/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * RDP Server Listener
 *
 * Copyright 2011 Vic Lee
 * Copyright 2021 David Fort <contact@hardening-consulting.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <freerdp/config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include <winpr/crt.h>
#include <winpr/windows.h>
#include <freerdp/log.h>

#ifndef _WIN32
#include <netdb.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#endif

#if defined(HAVE_AF_VSOCK_H)
#include <ctype.h>
#include <linux/vm_sockets.h>
#endif

#include <winpr/handle.h>

#include "settings.h"
#include "bio.h"
#include "listener.h"
#include "utils.h"
#include "udpchannel.h"

#define TAG FREERDP_TAG("core.listener")

static BOOL freerdp_listener_open_from_vsock(WINPR_ATTR_UNUSED freerdp_listener* instance,
                                             WINPR_ATTR_UNUSED const char* bind_address,
                                             WINPR_ATTR_UNUSED UINT16 port)
{
#if defined(HAVE_AF_VSOCK_H)
	rdpListener* listener = (rdpListener*)instance->listener;
	const int sockfd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (sockfd == -1)
	{
		char ebuffer[256] = { 0 };
		WLog_ERR(TAG, "Error creating socket: %s", winpr_strerror(errno, ebuffer, sizeof(ebuffer)));
		return FALSE;
	}
	const int flags = fcntl(sockfd, F_GETFL, 0);
	if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1)
	{
		char ebuffer[256] = { 0 };
		WLog_ERR(TAG, "Error making socket nonblocking: %s",
		         winpr_strerror(errno, ebuffer, sizeof(ebuffer)));
		close(sockfd);
		return FALSE;
	}
	struct sockaddr_vm addr = { 0 };

	addr.svm_family = AF_VSOCK;
	addr.svm_port = port;

	errno = 0;
	char* ptr = NULL;
	unsigned long val = strtoul(bind_address, &ptr, 10);
	if (errno || (val > UINT32_MAX))
	{
		/* handle VMADDR_CID_ANY (-1U) */
		if ((val == ULONG_MAX) && (errno == 0))
			val = UINT32_MAX;
		else
		{
			char ebuffer[256] = { 0 };
			WLog_ERR(TAG, "could not extract port from '%s', value=%ul, error=%s", bind_address,
			         val, winpr_strerror(errno, ebuffer, sizeof(ebuffer)));
			close(sockfd);
			return FALSE;
		}
	}
	addr.svm_cid = WINPR_ASSERTING_INT_CAST(unsigned int, val);
	if (bind(sockfd, (struct sockaddr*)&addr, sizeof(struct sockaddr_vm)) == -1)
	{
		char ebuffer[256] = { 0 };
		WLog_ERR(TAG, "Error binding vsock at cid %d port %d: %s", addr.svm_cid, port,
		         winpr_strerror(errno, ebuffer, sizeof(ebuffer)));
		close(sockfd);
		return FALSE;
	}

	if (listen(sockfd, 10) == -1)
	{
		char ebuffer[256] = { 0 };
		WLog_ERR(TAG, "Error listening to socket at cid %d port %d: %s", addr.svm_cid, port,
		         winpr_strerror(errno, ebuffer, sizeof(ebuffer)));
		close(sockfd);
		return FALSE;
	}
	listener->sockfds[listener->num_sockfds] = sockfd;
	listener->events[listener->num_sockfds] = WSACreateEvent();

	if (!listener->events[listener->num_sockfds])
	{
		listener->num_sockfds = 0;
	}

	WSAEventSelect((SOCKET)sockfd, listener->events[listener->num_sockfds],
	               FD_READ | FD_ACCEPT | FD_CLOSE);
	listener->num_sockfds++;

	WLog_INFO(TAG, "Listening on %s:%d", bind_address, port);
	return TRUE;
#else
	WLog_ERR(TAG, "compiled without AF_VSOCK, '%s' not supported", bind_address);
	return FALSE;
#endif
}

static BOOL listener_add_fd(freerdp_listener* instance, SOCKET fd, BOOL isUdp)
{
	rdpListener* listener = (rdpListener*)instance->listener;
	int* sockCounter = isUdp ? &listener->num_sockfds_udp : &listener->num_sockfds;
	HANDLE* eventsArray = isUdp ? listener->eventsUdp : listener->events;
	int* sockArray = isUdp ? listener->sockfdsUdp : listener->sockfds;

	if (*sockCounter == MAX_LISTENER_HANDLES)
	{
		WLog_ERR(TAG, "too many %s listening sockets", isUdp ? "UDP" : "TCP");
		return FALSE;
	}

#ifndef _WIN32
	{
		if (fcntl((int)fd, F_SETFL, O_NONBLOCK) < 0)
		{
			WLog_ERR(TAG, "error setting socket non-blocking");
			return FALSE;
		}
	}
#else
	{
		u_long arg = 1;
		ioctlsocket(sockfd, FIONBIO, &arg);
	}
#endif

	sockArray[*sockCounter] = (int)fd;
	HANDLE h = WSACreateEvent();
	if (!h)
	{
		WLog_ERR(TAG, "unable to create WSA event");
		return FALSE;
	}

	const LONG networkEvents = FD_READ | FD_ACCEPT | FD_CLOSE;
	WSAEventSelect(fd, h, networkEvents);

	eventsArray[*sockCounter] = h;
	++*sockCounter;
	return TRUE;
}

static BOOL freerdp_listener_open_ex(freerdp_listener* instance, const char* bind_address,
                                     UINT16 port, BOOL udp)
{
	int ai_flags = 0;
	int status = 0;
	int sockfd = 0;
	char addr[64];
	void* sin_addr = NULL;
	int option_value = 0;
	struct addrinfo* res = NULL;
	int sockType = udp ? SOCK_DGRAM : SOCK_STREAM;
	rdpListener* listener = (rdpListener*)instance->listener;
	int ret = 0;

	if (!bind_address)
		ai_flags = AI_PASSIVE;

	if (utils_is_vsock(bind_address))
	{
		bind_address = utils_is_vsock(bind_address);
		return freerdp_listener_open_from_vsock(instance, bind_address, port);
	}

	res = freerdp_resolve_host(bind_address, port, sockType, ai_flags);
	if (!res)
		return FALSE;

	for (struct addrinfo* ai = res; ai && (listener->num_sockfds < 5); ai = ai->ai_next)
	{
		if ((ai->ai_family != AF_INET) && (ai->ai_family != AF_INET6))
			continue;

		sockfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sockfd == -1)
		{
			WLog_ERR(TAG, "error creating listening socket");
			continue;
		}

		switch (ai->ai_family)
		{
			case AF_INET:
				sin_addr = &(((struct sockaddr_in*)ai->ai_addr)->sin_addr);
				break;
			case AF_INET6:
				sin_addr = &(((struct sockaddr_in6*)ai->ai_addr)->sin6_addr);
				option_value = 1;
				if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&option_value,
				               sizeof(option_value)) == -1)
					WLog_ERR(TAG, "setsockopt");
				break;
			default:
				WLog_ERR(TAG, "family %d not supported");
				closesocket((SOCKET)sockfd);
				continue;
		}

		inet_ntop(ai->ai_family, sin_addr, addr, sizeof(addr));

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void*)&option_value,
		               sizeof(option_value)) == -1)
			WLog_ERR(TAG, "setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR)");

#ifndef _WIN32
		if (fcntl(sockfd, F_SETFL, O_NONBLOCK) != 0)
			WLog_ERR(TAG, "fcntl(sockfd, F_SETFL, O_NONBLOCK)");
#else
		arg = 1;
		ioctlsocket(sockfd, FIONBIO, &arg);
#endif
		status = _bind((SOCKET)sockfd, ai->ai_addr, WINPR_ASSERTING_INT_CAST(int, ai->ai_addrlen));
		if (status != 0)
		{
			closesocket((SOCKET)sockfd);
			continue;
		}

		if (!udp)
		{
			status = _listen((SOCKET)sockfd, 10);
			if (status != 0)
			{
				WLog_ERR(TAG, "listen error");
				closesocket((SOCKET)sockfd);
				continue;
			}
		}

		if (!listener_add_fd(instance, (SOCKET)sockfd, udp))
		{
			closesocket((SOCKET)sockfd);
			continue;
		}

		WLog_INFO(TAG, "Listening on %s:[%s]:%d", udp ? "UDP" : "TCP", addr, port);
	}

	freeaddrinfo(res);
	return (ret >= 0);
}

static BOOL freerdp_listener_open(freerdp_listener* instance, const char* bind_address, UINT16 port)
{
	return freerdp_listener_open_ex(instance, bind_address, port, FALSE);
}

static BOOL freerdp_listener_open_local(freerdp_listener* instance, const char* path)
{
#ifndef _WIN32
	int status = 0;
	int sockfd = 0;
	struct sockaddr_un addr = { 0 };
	rdpListener* listener = (rdpListener*)instance->listener;

	if (listener->num_sockfds == MAX_LISTENER_HANDLES)
	{
		WLog_ERR(TAG, "too many listening sockets");
		return FALSE;
	}

	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd == -1)
	{
		WLog_ERR(TAG, "socket");
		return FALSE;
	}

	int rc = fcntl(sockfd, F_SETFL, O_NONBLOCK);
	if (rc != 0)
	{
		WLog_ERR(TAG, "fcntl(sockfd, F_SETFL, O_NONBLOCK)");
		closesocket((SOCKET)sockfd);
		return FALSE;
	}

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
	unlink(path);

	status = _bind((SOCKET)sockfd, (struct sockaddr*)&addr, sizeof(addr));
	if (status != 0)
	{
		WLog_ERR(TAG, "error binding unix socket %s", path);
		closesocket((SOCKET)sockfd);
		return FALSE;
	}

	status = _listen((SOCKET)sockfd, 10);
	if (status != 0)
	{
		WLog_ERR(TAG, "error listening on unix socket %s", path);
		closesocket((SOCKET)sockfd);
		return FALSE;
	}

	if (!listener_add_fd(instance, (SOCKET)sockfd, FALSE))
	{
		closesocket((SOCKET)sockfd);
		return FALSE;
	}

	WLog_INFO(TAG, "Listening on socket %s.", addr.sun_path);
	return TRUE;
#else
	return TRUE;
#endif
}

static BOOL freerdp_listener_open_from_socket(freerdp_listener* instance, int fd)
{
#ifndef _WIN32
	int sockType;
	socklen_t length = sizeof(sockType);

	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &sockType, &length) < 0)
	{
		WLog_ERR(TAG, "error retrieving socket type");
		return FALSE;
	}

	if (!listener_add_fd(instance, (SOCKET)fd, (sockType == SOCK_DGRAM)))
	{
		WLog_ERR(TAG, "error when adding fd %d to listener", fd);
		return FALSE;
	}

	WLog_INFO(TAG, "Listening on socket %d.", fd);
	return TRUE;
#else
	return FALSE;
#endif
}

static void freerdp_listener_close(freerdp_listener* instance)
{
	rdpListener* listener = (rdpListener*)instance->listener;

	for (int i = 0; i < listener->num_sockfds; i++)
	{
		closesocket((SOCKET)listener->sockfds[i]);
		(void)CloseHandle(listener->events[i]);
	}
	listener->num_sockfds = 0;

	for (int i = 0; i < listener->num_sockfds_udp; i++)
	{
		closesocket((SOCKET)listener->sockfdsUdp[i]);
		CloseHandle(listener->eventsUdp[i]);
	}
	listener->num_sockfds_udp = 0;

	// TODO: cleanup peers
}

#if defined(WITH_FREERDP_DEPRECATED)
static BOOL freerdp_listener_get_fds(freerdp_listener* instance, void** rfds, int* rcount)
{
	rdpListener* listener = (rdpListener*)instance->listener;

	if (listener->num_sockfds < 1)
		return FALSE;

	for (int index = 0; index < listener->num_sockfds; index++)
	{
		rfds[*rcount] = (void*)(long)(listener->sockfds[index]);
		(*rcount)++;
	}

	for (index = 0; index < listener->num_sockfds_udp; index++)
	{
		rfds[*rcount] = (void*)(long)(listener->sockfdsUdp[index]);
		(*rcount)++;
	}

	return TRUE;
}
#endif

static DWORD freerdp_listener_get_event_handles(freerdp_listener* instance, HANDLE* events,
                                                DWORD nCount)
{
	rdpListener* listener = (rdpListener*)instance->listener;
	int ret = 0;

	if (listener->num_sockfds < 1)
		return 0;

	if (listener->num_sockfds + listener->num_sockfds_udp > (int)nCount)
	{
		WLog_ERR(TAG, "not enough place in target array");
		return 0;
	}

	for (int i = 0; i < listener->num_sockfds; i++, ret++)
		events[ret] = listener->events[i];

	for (int i = 0; i < listener->num_sockfds_udp; i++, ret++)
		events[ret] = listener->eventsUdp[i];

	if (listener->udpPeers)
	{
		ULONG_PTR* keys = NULL;
		int nKeys = HashTable_GetKeys(listener->udpPeers, &keys);
		if (nKeys > 0)
		{
			for (int i = 0; i < nKeys; i++)
			{
				ListenerUdpPeer* peer = HashTable_GetItemValue(listener->udpPeers, (void*)keys[i]);
				if (peer && !peer->handledExternaly && ret < nCount)
				{
					events[ret] = Queue_Event(peer->packetQueue);
					ret++;
				}
			}
		}
		free(keys);
	}
	return ret;
}

void peer_addr_computation(const struct sockaddr_storage* peer_addr, BOOL* isLocal, char* str,
                           size_t strSz, BOOL withPort)
{
	static const BYTE localhost6_bytes[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
	struct sockaddr_in* sin;
	struct sockaddr_in6* sin6;
	void* sin_addr = NULL;
	int port;

	switch (peer_addr->ss_family)
	{
		case AF_INET:
			sin = (struct sockaddr_in*)peer_addr;
			sin_addr = &sin->sin_addr;
			port = sin->sin_port;
			*isLocal = ((*(UINT32*)sin_addr) == 0x0100007f);
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6*)peer_addr;
			sin_addr = &sin6->sin6_addr;
			port = sin6->sin6_port;
			*isLocal = (memcmp(sin_addr, localhost6_bytes, 16) == 0);
			break;
#ifdef HAVE_LINUX_VM_SOCKETS_H
		case AF_VSOCK:
		{
			struct sockaddr_vm* svm = (struct sockaddr_vm*)peer_addr;
			*isLocal = TRUE;
			if (withPort)
				snprintf(str, strSz, "CID(%d):%d", svm->svm_cid, svm->svm_port);
			else
				snprintf(str, strSz, "CID(%d)", svm->svm_cid);
			break;
		}
#endif
#ifndef _WIN32
		case AF_UNIX:
		{
			struct sockaddr_un* un = (struct sockaddr_un*)peer_addr;
			snprintf(str, strSz, "unix:%s", un->sun_path);
			*isLocal = TRUE;
			break;
		}
#endif
		default:
			break;
	}

	if (sin_addr)
	{
		inet_ntop(peer_addr->ss_family, sin_addr, str, strSz);
		if (withPort)
		{
			char tmpAddr[39 + 1];

			strcpy(tmpAddr, str);
			switch (peer_addr->ss_family)
			{
				case AF_INET:
					snprintf(str, strSz, "%s:%d", tmpAddr, port);
					break;
				case AF_INET6:
					snprintf(str, strSz, "[%s]:%d", tmpAddr, port);
					break;
			}
		}
	}
}

BOOL freerdp_peer_set_local_and_hostname(freerdp_peer* client,
                                         const struct sockaddr_storage* peer_addr)
{
	peer_addr_computation(peer_addr, &client->local, client->hostname, sizeof(client->hostname),
	                      FALSE);
	return TRUE;
}

static BOOL freerdp_check_and_create_client(freerdp_listener* instance, int peer_sockfd,
                                            const struct sockaddr_storage* peer_addr)
{
	WINPR_ASSERT(instance);
	WINPR_ASSERT(peer_sockfd >= 0);
	WINPR_ASSERT(peer_addr);

	const BOOL check = IFCALLRESULT(TRUE, instance->CheckPeerAcceptRestrictions, instance);
	if (!check)
	{
		closesocket((SOCKET)peer_sockfd);
		return TRUE;
	}

	freerdp_peer* client = freerdp_peer_new(peer_sockfd);
	if (!client)
	{
		closesocket((SOCKET)peer_sockfd);
		return FALSE;
	}

	if (!freerdp_peer_set_local_and_hostname(client, peer_addr))
	{
		freerdp_peer_free(client);
		return FALSE;
	}

	const BOOL peer_accepted = IFCALLRESULT(FALSE, instance->PeerAccepted, instance, client);
	if (!peer_accepted)
	{
		WLog_ERR(TAG, "PeerAccepted callback failed");
		freerdp_peer_free(client);
	}

	return TRUE;
}

static BOOL listenerPacketTreatment(freerdp_listener* instance, ListenerUdpPeer* peer)
{
	return peer->channel->handlePackets(peer->channel);
}

static ListenerUdpPeer* ListenerUdpPeer_new(freerdp_listener* listener, rdpSettings* settings,
                                            SOCKET sock, const PeerAddr* peerAddr)
{
	char hostKey[UDP_PEER_ADDR_LEN];
	BOOL isLocal = FALSE;
	ListenerUdpPeer* peer;
	BYTE cookie[16];

	if (winpr_RAND(cookie, sizeof(cookie)) < 0)
	{
		WLog_ERR(TAG, "unable to generate peer cookie");
		return FALSE;
	}

	peer_addr_computation(&peerAddr->addr, &isLocal, hostKey, sizeof(hostKey), TRUE);

	peer = calloc(1, sizeof(*peer));
	if (!peer)
	{
		WLog_ERR(TAG, "unable to allocate UDP peer");
		return FALSE;
	}
	peer->isLocal = isLocal;
	peer->sock = sock;
	peer->peerAddr = *peerAddr;
	peer->PacketTreatment = listenerPacketTreatment;

	peer->packetQueue = Queue_New(TRUE, 0, 0);
	if (!peer->packetQueue)
	{
		WLog_ERR(TAG, "unable to allocate packet list");
		free(peer);
		return FALSE;
	}

	memcpy(peer->peerAddrStr, hostKey, sizeof(hostKey));

	peer->channel = multitransportchannel_server_new(settings, peer);
	if (!peer->channel)
	{
		Queue_Free(peer->packetQueue);
		free(peer);
	}
	peer->channel->listener = listener;

	return peer;
}

static BOOL freerdp_listener_check_fds_ex(freerdp_listener* instance, DWORD waitResult)
{
	int i;
	rdpListener* listener = (rdpListener*)instance->listener;
	DWORD startIndex = waitResult - WAIT_OBJECT_0;
	DWORD currentBound = listener->num_sockfds;

	/* note: fail if we don't have any listening TCP sockets */
	if (listener->num_sockfds < 1)
		return FALSE;

	/* let's look if some TCP socket have accepted */
	if (startIndex < currentBound)
	{
		for (i = 0; i < listener->num_sockfds; i++)
		{
			struct sockaddr_storage addr;
			socklen_t addrLen;
			WSAResetEvent(listener->events[i]);
			addrLen = sizeof(addr);

			int peer_sockfd =
			    _accept((SOCKET)listener->sockfds[i], (struct sockaddr*)&addr, (int*)&addrLen);
			if (peer_sockfd == (SOCKET)-1)
			{
				char buffer[8192] = { 0 };
#ifdef _WIN32
				int wsa_error = WSAGetLastError();

				/* No data available */
				if (wsa_error == WSAEWOULDBLOCK)
					continue;
#else
				if (errno == EAGAIN || errno == EWOULDBLOCK)
					continue;

#endif
				WLog_WARN(TAG, "accept failed with %s",
				          winpr_strerror(errno, buffer, sizeof(buffer)));
				return FALSE;
			}

			if (!freerdp_check_and_create_client(instance, peer_sockfd, &addr))
				return FALSE;
		}
	}
	currentBound += listener->num_sockfds_udp;

	if (!instance->withUdp)
		return TRUE;

	/* treat listening UDP sockets */
	if (startIndex < currentBound)
	{
		for (i = 0; i < listener->num_sockfds_udp; i++)
		{
			if (WaitForSingleObject(listener->eventsUdp[i], 0) != WAIT_OBJECT_0)
				continue;
			WSAResetEvent(listener->eventsUdp[i]);

			ListenerUdpPeer* peer;
			ssize_t status;
			wStream* s = StreamPool_Take(listener->pool, 0x10000);
			if (!s)
				return FALSE;

			PeerAddr peer_addr;
			peer_addr.len = sizeof(peer_addr.addr);
			status = recvfrom(listener->sockfdsUdp[i], Stream_Buffer(s), 0x10000, 0,
			                  (struct sockaddr*)&peer_addr.addr, &peer_addr.len);
			if (status <= 0)
				continue;

			peer = (ListenerUdpPeer*)HashTable_GetItemValue(listener->udpPeers, &peer_addr);
			if (!peer)
			{
				peer = ListenerUdpPeer_new(instance, listener->udpSettings, listener->sockfdsUdp[i],
				                           &peer_addr);
				if (!peer)
				{
					WLog_ERR(TAG, "error creating new UdpListenerPeer");
					continue;
				}

				if (!HashTable_Insert(listener->udpPeers, &peer->peerAddr, peer))
				{
					multitransportchannel_free(&peer->channel);
					Queue_Free(peer->packetQueue);
					free(peer);
				}

				if (instance->NewUdpPeer)
					instance->NewUdpPeer(instance, peer);
			}

			Stream_SetLength(s, status);
			if (!Queue_Enqueue(peer->packetQueue, s))
			{
				WLog_ERR(TAG, "unable to push packet to UDP peer");
				Stream_Release(s);
				return FALSE;
			}

			while (Queue_Count(peer->packetQueue) > listener->udpSettings->MaxPendingUdpPackets)
			{
				/* don't accumulate too many packets, drop the exceeding ones */
				s = Queue_Dequeue(peer->packetQueue);
				if (s)
					Stream_Release(s);
			}
			peer->lastPacketDate = GetTickCount64();

			if (!peer->handledExternaly && peer->PacketTreatment)
			{
				peer->PacketTreatment(instance, peer);
			}
		}
	}

	if (instance->withUdp)
	{
		ULONG_PTR* keys = NULL;
		int nKeys = HashTable_GetKeys(listener->udpPeers, &keys);

		for (i = 0; i < nKeys; i++)
		{
			ListenerUdpPeer* peer = HashTable_GetItemValue(listener->udpPeers, (void*)keys[i]);
			if (peer && !peer->handledExternaly)
			{
				if (Queue_Count(peer->packetQueue) && peer->channel->handlePackets)
					peer->channel->handlePackets(peer->channel);
			}
		}

#if 0
		if (!freerdp_check_and_create_client(instance, (int)peer_sockfd, &peer_addr))
			return FALSE;
#endif
	}

	return TRUE;
}

static BOOL freerdp_listener_check_fds(freerdp_listener* instance)
{
	return freerdp_listener_check_fds_ex(instance, WAIT_OBJECT_0);
}

UINT32 udpPeers_hash(PeerAddr* key1)
{
	const BYTE* b;
	int i = 0;
	UINT32 ret = key1->len;

	for (b = (const BYTE*)&key1->addr; i < key1->len; i++, b++)
		ret += *b;

	return ret;
}

BOOL udpPeers_keyCompare(const PeerAddr* key1, const PeerAddr* key2)
{
	if (key1->len != key2->len)
		return FALSE;

	return memcmp(&key1->addr, &key2->addr, key1->len) == 0;
}

static rdpListener* rdpListener_init(BOOL isUdp, rdpSettings* settings)
{
	rdpListener* ret = calloc(1, sizeof(*ret));
	if (!ret)
		return NULL;

	ret->udpSettings = settings;

	if (isUdp)
	{
		wHashTable* h;
		wObject* obj;
		ret->pool = StreamPool_New(FALSE, 0x10000);
		if (!ret->pool)
			goto error_pool;

		ret->udpPeers = h = HashTable_New(FALSE);
		if (!h)
			goto error_peers;

		HashTable_SetHashFunction(h, (HASH_TABLE_HASH_FN)udpPeers_hash);
		obj = HashTable_KeyObject(h);
		obj->fnObjectEquals = (OBJECT_EQUALS_FN)udpPeers_keyCompare;
	}
	return ret;

error_peers:
	StreamPool_Free(ret->pool);
error_pool:
	free(ret);
	return NULL;
}

static void rdpListener_free(rdpListener* listener)
{
	StreamPool_Free(listener->pool);
	HashTable_Free(listener->udpPeers);
	free(listener);
}

BOOL freerdp_listener_init(freerdp_listener* l, BOOL isUdp, rdpSettings* settings)
{
	rdpListener* listener = rdpListener_init(isUdp, settings);
	if (!listener)
		return FALSE;

	listener->instance = l;
	l->listener = listener;
	return TRUE;
}

freerdp_listener* freerdp_listener_new(void)
{
	return freerdp_listener_new_ex(FALSE, NULL);
}

freerdp_listener* freerdp_listener_new_ex(BOOL allowUdp, rdpSettings* udpSettings)
{
	freerdp_listener* ret = (freerdp_listener*)calloc(1, sizeof(freerdp_listener));
	if (!ret)
		return NULL;

	if (!freerdp_listener_init(ret, allowUdp, udpSettings))
	{
		free(ret);
		return NULL;
	}

	ret->withUdp = allowUdp;
	ret->Open = freerdp_listener_open;
	ret->OpenLocal = freerdp_listener_open_local;
	ret->OpenFromSocket = freerdp_listener_open_from_socket;
#if defined(WITH_FREERDP_DEPRECATED)
	ret->GetFileDescriptor = freerdp_listener_get_fds;
#endif
	ret->GetEventHandles = freerdp_listener_get_event_handles;
	ret->CheckFileDescriptor = freerdp_listener_check_fds;
	ret->CheckFileDescriptorEx = freerdp_listener_check_fds_ex;
	ret->Close = freerdp_listener_close;
	ret->OpenEx = freerdp_listener_open_ex;
	return ret;
}

void freerdp_listener_free(freerdp_listener* instance)
{
	if (instance)
	{
		rdpListener_free(instance->listener);
		free(instance);
	}
}
