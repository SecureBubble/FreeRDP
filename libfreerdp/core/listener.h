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

#ifndef FREERDP_LIB_CORE_LISTENER_H
#define FREERDP_LIB_CORE_LISTENER_H

typedef struct rdp_listener rdpListener;

#include "rdp.h"
#include "tcp.h"

#include <winpr/crt.h>
#include <winpr/synch.h>
#include <winpr/collections.h>

#include <freerdp/listener.h>

#define MAX_LISTENER_HANDLES 5
#define UDP_PEER_ADDR_LEN (1 + 39 + 1 + 1 + 5 + 1) /* [<ipv6 addr>]:<port>\0 */

struct rdp_listener
{
	freerdp_listener* instance;

	int num_sockfds;
	int sockfds[MAX_LISTENER_HANDLES];
	HANDLE events[MAX_LISTENER_HANDLES];

	rdpSettings* udpSettings;
	int num_sockfds_udp;
	int sockfdsUdp[MAX_LISTENER_HANDLES];
	HANDLE eventsUdp[MAX_LISTENER_HANDLES];

	wStreamPool* pool;
	wHashTable* udpPeers;
};

typedef BOOL (*psPacketTreatment)(freerdp_listener* instance, ListenerUdpPeer* peer);

struct listener_udp_peer
{
	char peerAddrStr[UDP_PEER_ADDR_LEN];
	PeerAddr peerAddr;
	SOCKET sock;
	BOOL isLocal;
	wQueue* packetQueue;
	UINT64 lastPacketDate;
	multiTransportChannel* channel;

	BOOL handledExternaly;
	psPacketTreatment PacketTreatment;
};
typedef struct listener_udp_peer ListenerUdpPeer;

#endif /* FREERDP_LIB_CORE_LISTENER_H */
