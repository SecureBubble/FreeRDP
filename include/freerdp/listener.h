/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * RDP Server Listener
 *
 * Copyright 2011 Vic Lee
 * Copyright 2023 David Fort <contact@hardening-consulting.com>
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

#ifndef FREERDP_LISTENER_H
#define FREERDP_LISTENER_H

#include <freerdp/api.h>
#include <freerdp/types.h>
#include <freerdp/settings.h>
#include <freerdp/peer.h>

typedef struct rdp_freerdp_listener freerdp_listener;
typedef struct rdp_multitransport_channel multiTransportChannel;
typedef struct listener_udp_peer ListenerUdpPeer;


#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct rdp_freerdp_listener freerdp_listener;

	typedef BOOL (*psListenerOpen)(freerdp_listener* instance, const char* bind_address,
	                               UINT16 port);
	typedef BOOL (*psListenerOpenEx)(freerdp_listener* instance, const char* bind_address,
	                                 UINT16 port, BOOL udp);
	typedef BOOL (*psListenerOpenLocal)(freerdp_listener* instance, const char* path);
	typedef BOOL (*psListenerOpenFromSocket)(freerdp_listener* instance, int fd);
#if defined(WITH_FREERDP_DEPRECATED)
	WINPR_DEPRECATED_VAR("Use psListenerGetEventHandles instead",
	                     typedef BOOL (*psListenerGetFileDescriptor)(freerdp_listener* instance,
	                                                                 void** rfds, int* rcount);)
#endif
	typedef DWORD (*psListenerGetEventHandles)(freerdp_listener* instance, HANDLE* events,
	                                           DWORD nCount);
	typedef BOOL (*psListenerCheckFileDescriptor)(freerdp_listener* instance);
	typedef BOOL (*psListenerCheckFileDescriptorEx)(freerdp_listener* instance, DWORD waitResult);
	typedef void (*psListenerClose)(freerdp_listener* instance);
	typedef BOOL (*psPeerAccepted)(freerdp_listener* instance, freerdp_peer* client);
	typedef BOOL (*psNewUdpPeer)(freerdp_listener* instance, ListenerUdpPeer* peer);
	typedef INT32 (*psIdentifyUdpPeer)(freerdp_listener* instance, UINT32 reqId,
	                                   const BYTE* cookieHash, multiTransportChannel* channel);

	struct rdp_freerdp_listener
	{
		void* info;
		void* listener;
		void* param1;
		void* param2;
		void* param3;
		void* param4;

		psListenerOpen Open;
		psListenerOpenLocal OpenLocal;
#if defined(WITH_FREERDP_DEPRECATED)
		WINPR_DEPRECATED_VAR("Use rdp_freerdp_listener::GetEventHandles instead",
		                     psListenerGetFileDescriptor GetFileDescriptor;)
#else
	void* reserved;
#endif
		psListenerGetEventHandles GetEventHandles;
		psListenerCheckFileDescriptor CheckFileDescriptor;
		psListenerClose Close;

		psPeerAccepted PeerAccepted;
		psListenerOpenFromSocket OpenFromSocket;
		psListenerCheckFileDescriptor CheckPeerAcceptRestrictions;

		/* added in version 3.X */
		BOOL withUdp;
		psNewUdpPeer NewUdpPeer;
		psListenerOpenEx OpenEx;
		psListenerCheckFileDescriptorEx CheckFileDescriptorEx;
		psIdentifyUdpPeer IdentifyUdpPeer;
	};

	typedef struct
	{
		struct sockaddr_storage addr;
		socklen_t len;
	} PeerAddr;

	FREERDP_API freerdp_listener* freerdp_listener_new_ex(BOOL allowUdp, rdpSettings* udpSettings);
	FREERDP_API void freerdp_listener_free(freerdp_listener* instance);
	FREERDP_API void peer_addr_computation(const struct sockaddr_storage* addr, BOOL* isLocal,
			char* str, size_t strSz, BOOL withPort);

	WINPR_ATTR_MALLOC(freerdp_listener_free, 1)
	FREERDP_API freerdp_listener* freerdp_listener_new(void);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_LISTENER_H */
