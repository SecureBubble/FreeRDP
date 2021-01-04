/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Multitransport PDUs
 *
 * Copyright 2014 Dell Software <Mike.McDonald@software.dell.com>
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

#ifndef FREERDP_LIB_CORE_MULTITRANSPORT_H
#define FREERDP_LIB_CORE_MULTITRANSPORT_H


#include "rdp.h"
#include "state.h"

#include <winpr/stream.h>
#include <freerdp/freerdp.h>
#include <freerdp/api.h>
#include <freerdp/multitransport.h>
#include "../crypto/tls.h"
#include <freerdp/utils/ringbuffer.h>

/** @brief */
typedef enum
{
	INITIATE_REQUEST_PROTOCOL_UDPFECR = 0x01,
	INITIATE_REQUEST_PROTOCOL_UDPFECL = 0x02
} MultitransportRequestProtocol;


#define RDPUDP_COOKIE_HASHLEN 32

typedef struct rdp_multitransport rdpMultitransport;
typedef struct rdp_multitransport_channel multiTransportChannel;

typedef state_run_t (*MultiTransportRequestCb)(rdpMultitransport* multi, UINT32 reqId,
                                               UINT16 reqProto, const BYTE* cookie);
typedef state_run_t (*MultiTransportResponseCb)(rdpMultitransport* multi, UINT32 reqId,
                                                UINT32 hrResponse);

struct rdp_multitransport
{
	rdpRdp* rdp;

	MultiTransportRequestCb MtRequest;
	MultiTransportResponseCb MtResponse;

	/* server-side data */
	UINT32 reliableReqId;

	BYTE reliableCookie[RDPUDP_COOKIE_LEN];
	BYTE reliableCookieHash[RDPUDP_COOKIE_HASHLEN];

	multiTransportChannel* channels[2];
};



FREERDP_LOCAL state_run_t multitransport_recv_request(rdpMultitransport* multi, wStream* s);
FREERDP_LOCAL state_run_t multitransport_server_request(rdpMultitransport* multi, UINT16 reqProto);

FREERDP_LOCAL state_run_t multitransport_recv_response(rdpMultitransport* multi, wStream* s);
FREERDP_LOCAL BOOL multitransport_client_send_response(rdpMultitransport* multi, UINT32 reqId,
                                                       HRESULT hr);

FREERDP_LOCAL void multitransport_free(rdpMultitransport* multi);

WINPR_ATTR_MALLOC(multitransport_free, 1)
WINPR_ATTR_NODISCARD
FREERDP_LOCAL rdpMultitransport* multitransport_new(rdpRdp* rdp, UINT16 protocol);

typedef struct rdp_freerdp_listener freerdp_listener;
typedef struct listener_udp_peer ListenerUdpPeer;


FREERDP_LOCAL int multitransport_recv_req_packet(rdpMultitransport* multi, wStream* s);
FREERDP_LOCAL int multitransport_recv_resp_packet(rdpMultitransport* multi, wStream* s);

FREERDP_LOCAL int multitransport_send_request(rdpRdp* rdp, UINT32 reqId, UINT16 reqProto,
                                                  const BYTE* cookie);
FREERDP_LOCAL BOOL multitransport_send_response(rdpRdp* rdp, UINT32 reqId, UINT32 hrResponse);

FREERDP_LOCAL DWORD multitransport_get_event_handles(rdpMultitransport* multi, HANDLE* events,
                                                     DWORD count);
FREERDP_LOCAL int multitransport_check_fds(rdpMultitransport* multi);


#endif /* FREERDP_LIB_CORE_MULTITRANSPORT_H */
