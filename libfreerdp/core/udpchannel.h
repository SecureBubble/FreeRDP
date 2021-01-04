/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * udpchannel
 *
 * Copyright 2022 David Fort <contact@hardening-consulting.com>
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
#ifndef LIBFREERDP_CORE_UDPCHANNEL_H_
#define LIBFREERDP_CORE_UDPCHANNEL_H_

#include <winpr/stream.h>

#include <freerdp/api.h>
#include "settings.h"
#include "../crypto/tls.h"

#include "multitransport.h"

/** @brief state of a multiTransport channel */
typedef enum
{
	MTCHANNEL_HANDSHAKING,
	MTCHANNEL_WAITING_REQUEST,
	MTCHANNEL_WAITING_RESPONSE,
	MTCHANNEL_RUNNING,
	MTCHANNEL_RESPONSE_ERROR
} MultiTransportChannelState;

typedef struct rdp_multitransport_channel multiTransportChannel;

typedef BOOL (*MultiTransportChannelCreateTunnelReq_fn)(multiTransportChannel* channel,
                                                        UINT32 reqId, const BYTE* cookie);
typedef BOOL (*MultiTransportChannelCreateTunnelResp_fn)(multiTransportChannel* channel,
                                                         INT32 hrResponse);
typedef BOOL (*MultiTransportChannelOnDataPduFn)(multiTransportChannel* channel, wStream* s);
typedef BOOL (*MultiTransportChannelSendPduFn)(multiTransportChannel* channel, wStream* headers,
                                               wStream* payload);
typedef BOOL (*MultiTransportChannelHandlePackets_fn)(multiTransportChannel* channel);

/** @brief */
struct rdp_multitransport_channel
{
	LONG volatile refCount;
	UINT32 reqId;
	BYTE cookie[16];
	BOOL lossy;
	BOOL isClient;
	char remoteAddr[50];

	rdpSettings* settings;
	rdpMultitransport* multiTransport;
	rdpTls* tls;
	BIO* bio;
	BIO* rdpUdpBio;
	HANDLE pollEvent;
	HANDLE timerEvent;
	MultiTransportChannelState state;
	RingBuffer inputBuffer;
	BOOL haveDynChannelId;
	UINT32 dynamicChannelId;

	freerdp_listener* listener;
	ListenerUdpPeer* peer;

	MultiTransportChannelCreateTunnelReq_fn createTunnelReq;
	MultiTransportChannelCreateTunnelResp_fn createTunnelResp;
	MultiTransportChannelOnDataPduFn onDataPdu;
	MultiTransportChannelSendPduFn SendPdu;
	MultiTransportChannelHandlePackets_fn handlePackets;
};

FREERDP_API void multitransportchannel_ref(multiTransportChannel* channel);
FREERDP_API void multitransportchannel_unref(multiTransportChannel** pchannel);

FREERDP_LOCAL multiTransportChannel* multitransportchannel_client_new(rdpMultitransport* multi,
                                                                      UINT32 reqId, BOOL lossy,
                                                                      const BYTE* cookie);
FREERDP_LOCAL multiTransportChannel* multitransportchannel_server_new(rdpSettings* settings,
                                                                      ListenerUdpPeer* peer);

FREERDP_LOCAL void multitransportchannel_free(multiTransportChannel** pchannel);

FREERDP_LOCAL BOOL multitransportchannel_handles(multiTransportChannel* channel, HANDLE* phandles,
                                                 DWORD* pcount);
FREERDP_LOCAL int multitransportchannel_checkfds(multiTransportChannel* channel);

#endif /* LIBFREERDP_CORE_UDPCHANNEL_H_ */
