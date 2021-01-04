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
#ifndef FREERDP_LIB_CORE_RDPUDP_H
#define FREERDP_LIB_CORE_RDPUDP_H

#include <winpr/winsock.h>
#include <winpr/stream.h>

#include <freerdp/types.h>
#include <freerdp/freerdp.h>
#include "../crypto/tls.h"

#include <openssl/bio.h>
#include "listener.h"

typedef struct rdpUdpTransport rdpUdpTransport;

// #define WITH_DEBUG_UDP

#ifdef WITH_DEBUG_UDP
#define UDP_DEBUG(...) WLog_DBG(TAG, __VA_ARGS__)
#else
#define UDP_DEBUG(...) \
	do                 \
	{                  \
	} while (0)
#endif

typedef struct
{
	UINT16 up;
	UINT16 down;
} UdpMtu;

typedef enum
{
	UDP_STATE_INIT,
	UDP_STATE_WAIT_SYN,
	UDP_STATE_WAIT_SYNACK,
	UDP_STATE_WAIT_ACK,
	UDP_STATE_ESTABLISHED
} UdpTransportState;

rdpUdpTransport* rdpUdpTransport_new(BIO* bio, rdpSettings* settings, BOOL lossy, BOOL server,
                                     const BYTE* cookie, const BYTE* correlationId);
void rdpUdpTransport_free(rdpUdpTransport** pudp);

BIO* rdpUdpTransport_init_client(rdpSettings* settings, rdpTls* tls, BOOL lossy, const BYTE* cookie,
                                 const char* hostname, int port, BOOL* completed);

wStream* rdpUdpTransport_getPacket(rdpUdpTransport* udp);
void rdpUdpTransport_discardPacket(rdpUdpTransport* udp, wStream* s);
BOOL rdpUdpTransport_bioSend(rdpUdpTransport* udp, wStream* s);
BOOL rdpUdpTransport_write(rdpUdpTransport* udp, wStream* s);

UdpTransportState rdpUdpTransport_getState(const rdpUdpTransport* udp);
const UdpMtu* rdpUdpTransport_Mtus(const rdpUdpTransport* udp);
BOOL rdpUdpTransport_isLossy(const rdpUdpTransport* udp);
void rdpUdpTransport_copyCorrelationId(const rdpUdpTransport* udp, BYTE* dest);
void rdpUdpTransport_copyCookie(const rdpUdpTransport* udp, BYTE* dest);
BOOL rdpUdpTransport_pushAvailableData(rdpUdpTransport* udp, wStream* s);
void rdpUdpTransport_switchToUdp2(rdpUdpTransport* udp);
BIO_METHOD* BIO_s_rdpudp(void);

#endif /* FREERDP_LIB_CORE_RDPUDP_H */
