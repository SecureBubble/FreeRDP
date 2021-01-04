/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * UDP peer for server-side UDP connections
 *
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
#ifndef UDP_PEER_H__
#define UDP_PEER_H__

#include <openssl/bio.h>
#include "../crypto/tls.h"

typedef struct listener_udp_peer ListenerUdpPeer;

BIO* rdpUdpTransport_init_server(rdpSettings* settings, rdpTls* tls, ListenerUdpPeer* peer);

#endif /* UDP_PEER_H__ */

