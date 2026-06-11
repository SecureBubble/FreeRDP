/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Websocket Transport - SERVER role (RD Gateway / MS-TSGU over WebSocket)
 *
 * Server-side counterpart to wst.c / rdg.c. Terminates a browser RDS HTML5
 * Web Client connection (wss:// + MS-TSGU PDUs) and exposes the inner RDP
 * byte stream as a BIO that a freerdp_peer transport can use as its frontBio,
 * symmetric to wst_get_front_bio_and_take_ownership() on the client side.
 *
 * Copyright 2026 Bubble
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef FREERDP_LIB_CORE_GATEWAY_WSTS_H
#define FREERDP_LIB_CORE_GATEWAY_WSTS_H

#include <winpr/wtypes.h>
#include <winpr/stream.h>
#include <winpr/winpr.h>

#include <freerdp/api.h>
#include <freerdp/types.h>

/* needed for BIO */
#include <openssl/ssl.h>

typedef struct rdp_wsts rdpWsts;

WINPR_ATTR_NODISCARD
FREERDP_LOCAL rdpWsts* wsts_new(rdpContext* context);

FREERDP_LOCAL void wsts_free(rdpWsts* wsts);

/**
 * Drive the full ingress handshake on an already-accepted TCP socket:
 *   outer TLS accept -> HTTP/1.1 websocket upgrade (101)
 *   -> MS-TSGU HANDSHAKE / EXTENDED_AUTH(NTLM) / TUNNEL_CREATE / TUNNEL_AUTH / CHANNEL_CREATE
 * Returns TRUE once the tunnel reaches the OPENED state (inner RDP can begin).
 * On success, wsts takes ownership of sockfd.
 */
WINPR_ATTR_NODISCARD
FREERDP_LOCAL BOOL wsts_accept(rdpWsts* wsts, int sockfd, DWORD timeout);

/**
 * Hand the inner-RDP front BIO to the caller (the peer transport).
 * Reads/writes on it are translated to/from MS-TSGU DATA PDUs inside
 * websocket binary frames. After this call wsts will not free the BIO.
 */
WINPR_ATTR_NODISCARD
FREERDP_LOCAL BIO* wsts_get_front_bio_and_take_ownership(rdpWsts* wsts);

/* Resolve which proxy session this connection belongs to: the RDS web client
 * carries CorId / ConId in the upgrade URL query string. Valid after wsts_accept. */
WINPR_ATTR_NODISCARD
FREERDP_LOCAL const char* wsts_get_query_param(rdpWsts* wsts, const char* name);

#endif /* FREERDP_LIB_CORE_GATEWAY_WSTS_H */
