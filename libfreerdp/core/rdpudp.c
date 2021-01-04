/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * UDP
 *
 * Copyright 2020 David Fort <contact@hardening-consulting.com>
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
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>

#include <winpr/winsock.h>
#include <winpr/stream.h>
#include <winpr/wlog.h>
#include <winpr/print.h>
#include <winpr/sysinfo.h>
#include <winpr/crypto.h>

#include "settings.h"
#include "bio.h"
#include "tcp.h"
#include "udp.h"
#include "udp_bio.h"
#include "rdpudp.h"
#include "udp_priv.h"
#include "listener.h"

#define UDP_MTU 1232

#define TAG FREERDP_TAG("udp")

#define MIDDLE_SEQ_NUMBER 0x8000000
int seqNumberCompare(UINT32 sn1, UINT32 sn2)
{
	BOOL sn1AfterMiddle = (sn1 > MIDDLE_SEQ_NUMBER);
	BOOL sn2AfterMiddle = (sn2 > MIDDLE_SEQ_NUMBER);

	if (sn1AfterMiddle != sn2AfterMiddle)
	{
		sn1 += MIDDLE_SEQ_NUMBER;
		sn2 += MIDDLE_SEQ_NUMBER;
	}

	return sn2 - sn1;
}

BOOL checkMtu(UINT16 mtu)
{
	return (mtu <= 1232) && (mtu >= 1132);
}

BOOL udp12_packet_reader(rdpUdpTransport* udp, Udp12Context* udp12, wStream* s)
{
	Udp12Packet packet;
	BOOL ret = FALSE;
	UINT16 mask;
	int version;

	if (!udp12_parse_packet(s, &packet))
		return FALSE;

	if (!UdpWindowBuffer_ackPacket(udp12->outputBuffer, packet.snSourceAck))
	{
		WLog_INFO(TAG, "unable to ack packet 0x%x", packet.snSourceAck);
	}

	switch (udp->state)
	{
		case UDP_STATE_WAIT_SYN:
			if ((packet.uFlags & RDPUDP_FLAG_SYN) == 0)
			{
				WLog_ERR(TAG, "UDP_STATE_WAIT_SYN: expecting a SYN packet");
				goto out;
			}

			if (packet.uFlags & RDPUDP_FLAG_CORRELATION_ID)
				memcpy(udp->correlationId, packet.uCorrelationId, sizeof(udp->correlationId));

			version = 1;
			if (packet.uSynExFlags & RDPUDP_VERSION_INFO_VALID)
			{
				switch (packet.uUdpVer)
				{
					case RDPUDP_PROTOCOL_VERSION_1:
						version = 1;
						break;
					case RDPUDP_PROTOCOL_VERSION_2:
						version = 2;
						break;
					case RDPUDP_PROTOCOL_VERSION_3:
						version = 3;
						break;
				}
			}

			/* prepare answer packet */
			packet.uFlags = RDPUDP_FLAG_SYN | RDPUDP_FLAG_ACK | RDPUDP_FLAG_SYNEX;
			packet.snSourceAck = packet.snInitialSequenceNumber;
			packet.uDownStreamMtu = packet.uUpStreamMtu = 1232;
			packet.snInitialSequenceNumber = udp12->currentSeqNumber;

			WLog_DBG(TAG, "---> UDP syn+ack()");
			if (!udp12_send_packet(udp, udp12, &packet))
			{
				WLog_ERR(TAG, "UDP_STATE_WAIT_SYN: unable to send SYNACK response");
				goto out;
			}
			if (version == 3)
				rdpUdpTransport_switchToUdp2(udp);
			udp->state = UDP_STATE_ESTABLISHED;
			ret = TRUE;
			break;

		case UDP_STATE_WAIT_SYNACK:
			mask = (RDPUDP_FLAG_SYN | RDPUDP_FLAG_ACK);
			if ((packet.uFlags & mask) != mask)
			{
				WLog_ERR(TAG, "UDP_STATE_WAIT_SYNACK: expecting a SYN+ACK packet");
				goto out;
			}

			if (packet.snSourceAck != udp12->currentSeqNumber - 1)
			{
				WLog_ERR(TAG, "invalid ackPacket have 0x%" PRIx32 " expecting 0x%" PRIx32 "",
				         packet.snSourceAck, udp12->currentSeqNumber - 1);
				goto out;
			}

			/* check and adjust MTUs */
			if (!checkMtu(packet.uUpStreamMtu) || !checkMtu(packet.uDownStreamMtu))
			{
				WLog_ERR(TAG, "invalid MTUs sent back by the server");
				goto out;
			}

			udp->mtus.up = packet.uUpStreamMtu;
			udp->mtus.down = packet.uDownStreamMtu;
			udp12->lastReceivedPacket = packet.snInitialSequenceNumber;

			/* treat protocol version */
			version = 1;
			if (packet.uSynExFlags & RDPUDP_VERSION_INFO_VALID)
			{
				switch (packet.uUdpVer)
				{
					case RDPUDP_PROTOCOL_VERSION_1:
						version = 1;
						break;
					case RDPUDP_PROTOCOL_VERSION_2:
						version = 2;
						break;
					case RDPUDP_PROTOCOL_VERSION_3:
						/* switch to UDP2, so send a ACK packet */
						version = 3;
						rdpUdpTransport_switchToUdp2(udp);
						break;
					default:
						break;
				}
			}

			WLog_DBG(TAG, "udp12_packet_reader: UDP_STATE_WAIT_SYNACK -> UDP_STATE_ESTABLISHED");
			udp->state = UDP_STATE_ESTABLISHED;
			ret = TRUE;
			if (udp->pendingBuffer)
			{
				/* flush pending buffer */
				WLog_DBG(TAG, "flushing pending packet");
				Stream_SealLength(udp->pendingBuffer);
				// winpr_HexDump(TAG, WLOG_DEBUG, Stream_Buffer(udp->pendingBuffer),
				// Stream_Length(udp->pendingBuffer));

				ret = udp->lowLevelPacketWriter(udp, udp->currentContext, udp->pendingBuffer);

				Stream_Release(udp->pendingBuffer);
				udp->pendingBuffer = NULL;
			}
			break;
		default:
			ret = TRUE;
			break;
	}
out:
	return ret;
}

wStream* rdpUdpTransport_getPacket(rdpUdpTransport* udp)
{
	return StreamPool_Take(udp->packetPool, /*udp->mtus.up*/ 0xffff);
}

void rdpUdpTransport_discardPacket(rdpUdpTransport* udp, wStream* s)
{
	StreamPool_Return(udp->packetPool, s);
}

BOOL rdpUdpTransport_write(rdpUdpTransport* udp, wStream* s)
{
	switch (udp->state)
	{
		case UDP_STATE_INIT:
			if (!udp12_send_syn(udp, &udp->udp12, udp->lossy ? RDPUDP_FLAG_SYNLOSSY : 0))
				return FALSE;

			udp->state = UDP_STATE_WAIT_SYNACK;
			break;
		case UDP_STATE_WAIT_SYN:
		case UDP_STATE_WAIT_SYNACK:
		case UDP_STATE_WAIT_ACK:
			// TODO: handle these
			break;
		case UDP_STATE_ESTABLISHED:
			return udp->lowLevelPacketWriter(udp, udp->currentContext, s);
	}

	if (!udp->pendingBuffer)
	{
		udp->pendingBuffer = rdpUdpTransport_getPacket(udp);
		if (!udp->pendingBuffer)
			return FALSE;
	}

	if (!Stream_EnsureRemainingCapacity(udp->pendingBuffer, Stream_Length(s)))
		return FALSE;
	Stream_Write(udp->pendingBuffer, Stream_Buffer(s), Stream_Length(s));
	return TRUE;
}

BOOL rdpUdpTransport_bioSend(rdpUdpTransport* udp, wStream* s)
{
	int status;
	size_t len = Stream_Length(s);
	do {
		status = sendto(udp->fd, Stream_Buffer(s), len, 0, (struct sockaddr *)&udp->destAddr, udp->destAddrSz) >= 0;
	} while(status < 0 && errno == EINTR);

	return (status > 0);
}

UdpTransportState rdpUdpTransport_getState(const rdpUdpTransport* udp)
{
	return udp->state;
}

const UdpMtu* rdpUdpTransport_Mtus(const rdpUdpTransport* udp)
{
	return &udp->mtus;
}

BOOL rdpUdpTransport_isLossy(const rdpUdpTransport* udp)
{
	return udp->lossy;
}

void rdpUdpTransport_copyCorrelationId(const rdpUdpTransport* udp, BYTE* dest)
{
	memcpy(dest, udp->correlationId, sizeof(udp->correlationId));
}

void rdpUdpTransport_copyCookie(const rdpUdpTransport* udp, BYTE* dest)
{
	memcpy(dest, udp->cookieHash, sizeof(udp->cookieHash));
}

BOOL rdpUdpTransport_pushAvailableData(rdpUdpTransport* udp, wStream* s)
{
	EnterCriticalSection(&udp->recvLock);
	BOOL needToSetEvent = (ringbuffer_used(&udp->recvBuffer) == 0);
	BOOL ret = ringbuffer_write(&udp->recvBuffer, Stream_Buffer(s), Stream_Length(s));

	if (!ret)
		goto out;

	ret = !needToSetEvent || SetEvent(udp->recvEvent);
out:
	LeaveCriticalSection(&udp->recvLock);
	return ret;
}

void rdpUdpTransport_switchToUdp2(rdpUdpTransport* udp)
{
	WLog_DBG(TAG, "switching to UDP2");
	udp->currentContext = &udp->udp3;
	udp->lowLevelPacketReader = (UdpLowLevelHandler)udp3_low_level_reader;
	udp->lowLevelPacketWriter = (UdpLowLevelHandler)udp3_low_level_writer;
	udp->lowLevelTimer = (UdpLowLevelTimerHandler)udp3_low_level_timer;
}

static DWORD WINAPI client_polling_thread_func(LPVOID arg)
{
	rdpUdpTransport* ptr = (rdpUdpTransport*)arg;

	BYTE buf[0x10000];
	wStream staticS;
	wStream *s = Stream_StaticInit(&staticS, buf, sizeof(buf));

	ptr->pollRun = TRUE;
	while (ptr->pollRun)
	{
		UINT64 now = GetTickCount64();
		UINT64 delayToTimer = (ptr->nextTimer > now) ? (ptr->nextTimer - now) : 0;

		if (delayToTimer > 5)
		{
			int n = udp_doSelect(ptr->fd, delayToTimer);
			if (n > 0)
			{
				int res = recv(ptr->fd, buf, 0xffff, 0);
				UDP_DEBUG("recv(delay=%lu)=%d", delayToTimer, res);
				if (res >= 0) {
					Stream_SetLengthUnchecked(s, res);
					if (!ptr->lowLevelPacketReader(ptr, ptr->currentContext, s))
						WLog_ERR(TAG, "error treating packet");
				}
			}
		}

		now = GetTickCount64();
		if (now >= ptr->nextTimer)
		{
			if (ptr->lowLevelTimer && !ptr->lowLevelTimer(ptr, ptr->currentContext))
				WLog_ERR(TAG, "error treating timer");

			ptr->nextTimer = now + ptr->timerInterval;
		}
	}

	return 0;
}


rdpUdpTransport* rdpUdpTransport_new(SOCKET fd, const struct sockaddr *addr, socklen_t addrLen, rdpSettings* settings, BOOL lossy, BOOL server,
                                     const BYTE* correlationId, const BYTE* cookieHash)
{
	rdpUdpTransport* ret = calloc(1, sizeof(*ret));
	if (!ret)
		return NULL;

	InitializeCriticalSection(&ret->recvLock);
	ret->fd = fd;
	memcpy(&ret->destAddr, addr, addrLen);
	ret->destAddrSz = addrLen;

	ret->lossy = lossy;
	ret->timerInterval = 50;
	ret->nextTimer = GetTickCount64() + ret->timerInterval;
	ret->lowLevelPacketReader = (UdpLowLevelHandler)udp12_packet_reader;
	ret->lowLevelPacketWriter = (UdpLowLevelHandler)udp12_packet_writer;
	ret->lossy = FALSE;
	ret->state = server ? UDP_STATE_WAIT_SYN : UDP_STATE_INIT;
	ret->mtus.up = UDP_MTU;
	ret->mtus.down = UDP_MTU;
	ret->currentContext = &ret->udp12;

	if (correlationId)
		memcpy(ret->correlationId, correlationId, sizeof(ret->correlationId));

	if (cookieHash)
		memcpy(ret->cookieHash, cookieHash, sizeof(ret->cookieHash));

	if (!ringbuffer_init(&ret->recvBuffer, 0x10000))
		goto error_rb;

	ret->recvEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
	if (!ret->recvEvent)
		goto error_event;

	ret->packetPool = StreamPool_New(TRUE, 0x10000);
	if (!ret->packetPool)
		goto error_pool;

	if (!udp12_init(ret, &ret->udp12, server))
		goto error_udp12;

	if (!udp3_init(ret, &ret->udp3, server))
		goto error_udp3;

	ret->pollingThread = CreateThread(nullptr, 0, client_polling_thread_func, ret, 0, nullptr);
	if (!ret->pollingThread)
		goto error_thread;
	return ret;

error_thread:
	udp3_destroy(&ret->udp3);
error_udp3:
	udp12_destroy(&ret->udp12);
error_udp12:
	StreamPool_Free(ret->packetPool);
error_pool:
	CloseHandle(ret->recvEvent);
error_event:
	ringbuffer_destroy(&ret->recvBuffer);
error_rb:
	free(ret);
	return nullptr;
}

void rdpUdpTransport_free(rdpUdpTransport** pudp)
{
	rdpUdpTransport* udp;

	assert(pudp);
	udp = *pudp;
	if (!udp)
		return;

	udp->pollRun = FALSE;
	if (udp->pollingThread)
	{
		WaitForSingleObject(udp->pollingThread, INFINITE);
		CloseHandle(udp->pollingThread);
		udp->pollingThread = nullptr;
	}

	udp12_destroy(&udp->udp12);
	udp3_destroy(&udp->udp3);
	ringbuffer_destroy(&udp->recvBuffer);
	CloseHandle(udp->recvEvent);

	StreamPool_Free(udp->packetPool);
	free(udp);
	*pudp = NULL;
}

static int bio_rdpudp_write(BIO* bio, const char* buf, int size)
{
	// int error;
	int status = size;
	wStream s;
	rdpUdpTransport* udp = (rdpUdpTransport*)BIO_get_data(bio);

	if (!buf || !udp)
		return 0;

	UDP_DEBUG("bio_rdpudp_write(size=%d, thread=%x)", size, (int)pthread_self());
	// winpr_HexDump(TAG, WLOG_DEBUG, buf, size);

	BIO_clear_flags(bio, BIO_FLAGS_WRITE | BIO_FLAGS_READ | BIO_FLAGS_IO_SPECIAL);
	Stream_StaticInit(&s, (BYTE*)buf, size);
	if (!rdpUdpTransport_write(udp, &s))
		return -1;

	return status;
}

static int bio_rdpudp_read(BIO* bio, char* buf, int size)
{
	rdpUdpTransport* ptr = (rdpUdpTransport*)BIO_get_data(bio);
	WINPR_ASSERT(ptr);

	if (!buf || !ptr)
		return 0;

	BIO_clear_flags(bio, BIO_FLAGS_READ);
	ERR_clear_error();

	BOOL mustReset;
	int ret = -1;

	EnterCriticalSection(&ptr->recvLock);
	DataChunk chunks[2];
	size_t nchunks = ringbuffer_peek(&ptr->recvBuffer, chunks, size);
	if (!nchunks)
	{
		BIO_set_flags(bio, BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_READ);
		goto out;
	}

	ret = 0;
	for (size_t i = 0; i < nchunks; i++)
	{
		memcpy(buf, chunks[i].data, chunks[i].size);
		buf += chunks[i].size;
		ret += chunks[i].size;
	}

	ringbuffer_commit_read_bytes(&ptr->recvBuffer, ret);
out:
	/* read is supposed to be called when the event is set, so we reset it only when there's nothing
	 * to read */
	mustReset = (ringbuffer_used(&ptr->recvBuffer) == 0);

	if (mustReset && !ResetEvent(ptr->recvEvent))
	{
		WLog_ERR(TAG, "error resetting recvEvent");
		ret = -1;
	}
	LeaveCriticalSection(&ptr->recvLock);

	UDP_DEBUG("bio_rdpudp_read(size=%d, thread=%x)=%d", size, (int)pthread_self(), ret);
	return ret;
}

static long bio_rdpudp_ctrl(BIO* bio, int cmd, long arg1, void* arg2)
{
	rdpUdpTransport* udp = (rdpUdpTransport*)BIO_get_data(bio);
	WINPR_ASSERT(udp);

	if (!udp)
		return 0;

	/*WLog_DBG(TAG, "bio_rdpudp_ctrl(cmd=%d, num=0x%x)", cmd, num);*/
	switch (cmd)
	{
		case BIO_CTRL_PENDING:
			return 0;
		case BIO_CTRL_FLUSH:
			return 1;
		case BIO_C_GET_EVENT:
			EnterCriticalSection(&udp->recvLock);
			(*(HANDLE*)arg2) = udp->recvEvent;
			LeaveCriticalSection(&udp->recvLock);
			return 1;
		case BIO_C_GET_FD:
			EnterCriticalSection(&udp->recvLock);
			(*(SOCKET*)arg2) = GetEventFileDescriptor(udp->recvEvent);
			LeaveCriticalSection(&udp->recvLock);
			return 1;
		default:
			return -1;
	}
}

static int bio_rdpudp_free(BIO* bio)
{
	if (!bio)
		return 0;

	rdpUdpTransport* udp = (rdpUdpTransport*)BIO_get_data(bio);
	if (!udp)
		return 0;
	rdpUdpTransport_free(&udp);
	return 1;
}

#define BIO_TYPE_RDP_UDP 80

BIO_METHOD* BIO_s_rdpudp(void)
{
	static BIO_METHOD* bio_methods = NULL;

	if (bio_methods == NULL)
	{
		if (!(bio_methods = BIO_meth_new(BIO_TYPE_RDP_UDP, "RdpUdp")))
			return NULL;

		BIO_meth_set_write(bio_methods, bio_rdpudp_write);
		BIO_meth_set_read(bio_methods, bio_rdpudp_read);
		BIO_meth_set_puts(bio_methods, bio_generic_puts);
		BIO_meth_set_gets(bio_methods, bio_generic_gets);
		BIO_meth_set_ctrl(bio_methods, bio_rdpudp_ctrl);
		BIO_meth_set_create(bio_methods, bio_generic_new);
		BIO_meth_set_destroy(bio_methods, bio_rdpudp_free);
		BIO_meth_set_callback_ctrl(bio_methods, bio_generic_callback_ctrl);
	}

	return bio_methods;
}

BIO* rdpUdp_client_bio(rdpSettings* settings, SOCKET fd, struct sockaddr* addr, socklen_t addrLen, BOOL lossy,
                       const BYTE* cookie)
{

	BYTE cookieHashRaw[RDPUDP_COOKIE_HASHLEN];
	BYTE cookieHash[RDPUDP_COOKIE_HASHLEN];

	if (!winpr_Digest(WINPR_MD_SHA256, cookie, 16, cookieHashRaw, RDPUDP_COOKIE_HASHLEN))
		return NULL;

	UINT32* ptr = (UINT32*)&cookieHashRaw[0];
	wStream staticStream;
	wStream* s = Stream_StaticInit(&staticStream, cookieHash, RDPUDP_COOKIE_HASHLEN);

	/* needed hack or the server flags us as RDPUDPv1 */
	for (size_t i = 0; i < RDPUDP_COOKIE_HASHLEN; i += 4, ptr++)
		Stream_Write_UINT32_BE_unchecked(s, *ptr);

	BIO* rdpUdpBio = BIO_new(BIO_s_rdpudp());
	if (!rdpUdpBio)
		goto fail_rdpUdpBio;

	BYTE* correlationId = NULL;
	if (settings->UseCorrelationId)
		correlationId = settings->CorrelationId;

	rdpUdpTransport* udpTransport =
	    rdpUdpTransport_new(fd, addr, addrLen, settings, lossy, FALSE, correlationId, cookieHash);
	if (!udpTransport)
		goto fail_setup;

	BIO_set_data(rdpUdpBio, udpTransport);
	return rdpUdpBio;

fail_setup:
	BIO_free(rdpUdpBio);
fail_rdpUdpBio:
	return NULL;
}

BIO* rdpUdpTransport_init_client(rdpSettings* settings, rdpTls* tls, BOOL lossy, const BYTE* cookie,
                                 const char* hostname, int port, BOOL* completed,
                                 rdpUdpTransport** ptrans)
{
	WINPR_ASSERT(ptrans);

	struct sockaddr_storage addr = { 0 };
	socklen_t addrLen = 0;
	SOCKET sock = freerdp_udp_connect(settings, hostname, port, &addr, &addrLen);
	if (sock == INVALID_SOCKET)
		return NULL;

	BIO* bio = NULL;
	char* remoteHost = freerdp_tcp_get_peer_address(sock);
	if (!remoteHost)
		goto fail_bio;

	WLog_DBG(TAG, "UDP %s connected to %s", lossy ? "lossy" : "reliable", remoteHost);
	free(remoteHost);

	bio = rdpUdp_client_bio(settings, sock, (struct sockaddr*)&addr, addrLen, lossy, cookie);
	if (!bio)
		goto fail_bio;

	*ptrans = (rdpUdpTransport*)BIO_get_data(bio);

	const SSL_METHOD* method = freerdp_tls_get_ssl_method(lossy, TRUE);
	switch (freerdp_tls_connect_ex2(tls, bio, method, 200))
	{
		case TLS_HANDSHAKE_CONTINUE:
			*completed = FALSE;
			return tls->bio;
		case TLS_HANDSHAKE_SUCCESS:
			WLog_ERR(TAG, "not expecting successful handshake on first call");
			*completed = TRUE;
			return tls->bio;
		case TLS_HANDSHAKE_ERROR:
		case TLS_HANDSHAKE_VERIFY_ERROR:
			goto fail_bio;
	}

	return tls->bio;

fail_bio:
	BIO_free_all(bio);
	tls->bio = NULL;
	return NULL;
}
