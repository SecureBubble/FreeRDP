/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * RDCleanPath (Devolutions) PDU codec — server/proxy side.
 *
 * IronRDP's ironrdp-web browser client cannot do the inner RDP TLS itself, so it
 * uses RDCleanPath: it sends the X.224 Connection Request wrapped in a small DER
 * SEQUENCE and expects a response carrying the server's X.224 Connection Confirm
 * plus the TLS certificate chain. See draft-devolutions-rdcleanpath.
 *
 *   RDCleanPathPdu ::= SEQUENCE {                  -- fields EXPLICIT context-tagged
 *       version           [0] INTEGER (3390),
 *       error             [1] RDCleanPathErr OPTIONAL,
 *       destination       [2] UTF8String OPTIONAL,  -- request
 *       proxyAuth         [3] UTF8String OPTIONAL,  -- request (JWT)
 *       serverAuth        [4] UTF8String OPTIONAL,
 *       preconnectionBlob [5] UTF8String OPTIONAL,  -- request
 *       x224ConnectionPdu [6] OCTET STRING OPTIONAL, -- CR (req) / CC (resp)
 *       serverCertChain   [7] SEQUENCE OF OCTET STRING OPTIONAL, -- response
 *       serverAddr        [9] UTF8String OPTIONAL }  -- response
 *
 * Copyright 2026 Bubble
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef FREERDP_LIB_CORE_GATEWAY_RDCLEANPATH_H
#define FREERDP_LIB_CORE_GATEWAY_RDCLEANPATH_H

#include <winpr/wtypes.h>
#include <freerdp/api.h>

#define RDCLEANPATH_VERSION_1 3390

/**
 * Decode an RDCleanPath REQUEST (client -> proxy) and extract the inner X.224
 * Connection Request PDU (field [6]). On success returns TRUE and sets
 * *x224Cr/*x224CrLen to a malloc'd copy the caller must free. destination (field
 * [2]) is not needed by the proxy (it targets its own configured host) and is
 * ignored.
 */
WINPR_ATTR_NODISCARD
FREERDP_LOCAL BOOL rdcleanpath_read_request(const BYTE* der, size_t derLen, BYTE** x224Cr,
                                            size_t* x224CrLen);

/**
 * Build an RDCleanPath RESPONSE (proxy -> client): version [0] + the X.224
 * Connection Confirm [6] + serverCertChain [7] + serverAddr [9].
 *
 * serverAddr MUST be non-NULL: ironrdp-rdcleanpath classifies a PDU as a Response
 * purely by the presence of the [9] field (lib.rs into_enum); omit it and the
 * client rejects the reply as malformed and silently closes. The value itself is
 * ignored by the client (a placeholder host:port is fine).
 *
 * Returns a malloc'd DER buffer in *outDer/*outLen (caller frees).
 */
WINPR_ATTR_NODISCARD
FREERDP_LOCAL BOOL rdcleanpath_write_response(const BYTE* x224Cc, size_t ccLen,
                                              const BYTE* const* certDer, const size_t* certLen,
                                              size_t certCount, const char* serverAddr,
                                              BYTE** outDer, size_t* outLen);

#endif /* FREERDP_LIB_CORE_GATEWAY_RDCLEANPATH_H */
