/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Websocket Transport - SERVER role (RDCleanPath ingress for ironrdp-web)
 *
 * Copyright 2026 Bubble
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

#include <freerdp/config.h>

#include <winpr/assert.h>
#include <winpr/crt.h>
#include <winpr/synch.h>
#include <winpr/custom-crypto.h>
#include <winpr/stream.h>
#include <winpr/winsock.h>

#include <freerdp/log.h>
#include <freerdp/crypto/crypto.h>

#include <freerdp/settings.h>
#include <freerdp/crypto/certificate.h>

#include "wsts.h"
#include "rdcleanpath.h"
#include "websocket.h" /* WEBSOCKET_* opcodes / FIN / MASK bits */
#include "../tcp.h"
#include "../../crypto/tls.h"
#include "../../crypto/opensslcompat.h"

#define TAG FREERDP_TAG("core.gateway.wsts")

/* RFC 6455 GUID for Sec-WebSocket-Accept */
#define WS_ACCEPT_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

struct rdp_wsts
{
	rdpContext* context;
	wLog* log;
	BOOL attached;

	int sockfd;
	rdpTls* tls;   /* outer wss TLS */
	BIO* frontBio; /* inner-RDP facing BIO (BIO_s_wsts) */

	char* gwpath;  /* request-target incl. query string */
	char* gwquery; /* just the query part (after '?') */

	/* RDCleanPath (plain-WS) shim: the peer's X.224 CC is captured here until a full
	 * TPKT is buffered, then folded into the RDCleanPath response. The X.224 CR is
	 * replayed to the peer via dataResidual. */
	BOOL rdcpPending;    /* RDCleanPath request not yet read (unwrapped in wsts_bio_read) */
	BOOL rdcpAwaitingCc; /* capturing the peer's X.224 CC into the RDCleanPath response */
	BYTE* ccBuf;
	size_t ccLen;
	size_t ccCap;

	/* residual inner-RDP bytes decoded from a DATA frame not yet consumed by BIO_read */
	BYTE* dataResidual;
	size_t dataResidualLen;
	size_t dataResidualPos;

	/* non-blocking receive: raw bytes pulled from the outer TLS bio, awaiting
	 * assembly into complete (unmasked) websocket frames. */
	BYTE* rxbuf;
	size_t rxCap;
	size_t rxLen;
};

/* ----------------------------------------------------------------------------
 * Low-level blocking socket/TLS helpers (handshake phase)
 * ------------------------------------------------------------------------- */

static BOOL wsts_read_exact(rdpWsts* wsts, BYTE* buf, size_t len)
{
	size_t off = 0;
	while (off < len)
	{
		ERR_clear_error();
		const int rc = BIO_read(wsts->tls->bio, &buf[off], (int)(len - off));
		if (rc > 0)
			off += (size_t)rc;
		else if (!BIO_should_retry(wsts->tls->bio))
			return FALSE;
		else
			USleep(1000);
	}
	return TRUE;
}

static BOOL wsts_write_all(rdpWsts* wsts, const BYTE* buf, size_t len)
{
	size_t off = 0;
	while (off < len)
	{
		ERR_clear_error();
		const int rc = BIO_write(wsts->tls->bio, &buf[off], (int)(len - off));
		if (rc > 0)
			off += (size_t)rc;
		else if (!BIO_should_retry(wsts->tls->bio))
			return FALSE;
		else
			USleep(1000);
	}
	(void)BIO_flush(wsts->tls->bio);
	return TRUE;
}

/* ----------------------------------------------------------------------------
 * WebSocket framing (server perspective): emit UNMASKED, accept MASKED.
 * This is the inverse of websocket.c, which masks output and rejects masked
 * input. TODO(dedupe): fold a server flag into websocket.c and drop this.
 * ------------------------------------------------------------------------- */

static BOOL wsts_ws_send(rdpWsts* wsts, const BYTE* payload, size_t len, BYTE opcode)
{
	BYTE hdr[10];
	size_t hlen = 0;

	hdr[0] = (BYTE)(WEBSOCKET_FIN_BIT | (opcode & 0x0f));
	if (len < 126)
	{
		hdr[1] = (BYTE)len; /* no MASK bit: server->client is never masked */
		hlen = 2;
	}
	else if (len < 0x10000)
	{
		hdr[1] = 126;
		hdr[2] = (BYTE)(len >> 8);
		hdr[3] = (BYTE)(len & 0xff);
		hlen = 4;
	}
	else
	{
		hdr[1] = 127;
		for (int i = 0; i < 8; i++)
			hdr[2 + i] = (BYTE)((UINT64)len >> (56 - 8 * i));
		hlen = 10;
	}

	if (!wsts_write_all(wsts, hdr, hlen))
		return FALSE;
	if (len && !wsts_write_all(wsts, payload, len))
		return FALSE;
	return TRUE;
}

/* Read exactly one websocket frame's payload (unmasked) into *ppPayload/*pLen.
 * Control frames (ping/close) are handled inline and the function loops to the
 * next data frame. Blocking; used during the handshake phase. */
static BOOL wsts_ws_recv(rdpWsts* wsts, BYTE** ppPayload, size_t* pLen)
{
	for (;;)
	{
		BYTE b[2];
		if (!wsts_read_exact(wsts, b, 2))
			return FALSE;

		const BYTE opcode = b[0] & 0x0f;
		const BOOL masked = (b[1] & WEBSOCKET_MASK_BIT) != 0;
		size_t payloadLen = b[1] & 0x7f;

		if (payloadLen == 126)
		{
			BYTE ext[2];
			if (!wsts_read_exact(wsts, ext, 2))
				return FALSE;
			payloadLen = ((size_t)ext[0] << 8) | ext[1];
		}
		else if (payloadLen == 127)
		{
			BYTE ext[8];
			if (!wsts_read_exact(wsts, ext, 8))
				return FALSE;
			payloadLen = 0;
			for (int i = 0; i < 8; i++)
				payloadLen = (payloadLen << 8) | ext[i];
		}

		BYTE maskKey[4] = { 0 };
		if (masked && !wsts_read_exact(wsts, maskKey, 4))
			return FALSE;

		BYTE* payload = NULL;
		if (payloadLen)
		{
			payload = (BYTE*)malloc(payloadLen);
			if (!payload)
				return FALSE;
			if (!wsts_read_exact(wsts, payload, payloadLen))
			{
				free(payload);
				return FALSE;
			}
			if (masked)
			{
				for (size_t i = 0; i < payloadLen; i++)
					payload[i] ^= maskKey[i % 4];
			}
		}

		switch (opcode)
		{
			case WebsocketBinaryOpcode:
			case WebsocketContinuationOpcode:
				/* TODO: handle fragmentation (reassemble continuation frames).
				 * The RDS HTML5 client sends one PDU per unfragmented frame. */
				*ppPayload = payload;
				*pLen = payloadLen;
				return TRUE;
			case WebsocketPingOpcode:
				(void)wsts_ws_send(wsts, payload, payloadLen, WebsocketPongOpcode);
				free(payload);
				break;
			case WebsocketCloseOpcode:
				(void)wsts_ws_send(wsts, NULL, 0, WebsocketCloseOpcode);
				free(payload);
				return FALSE;
			default:
				free(payload);
				break;
		}
	}
}

/* ----------------------------------------------------------------------------
 * HTTP/1.1 -> WebSocket upgrade (anonymous; auth is in-band via EXTENDED_AUTH)
 * ------------------------------------------------------------------------- */

static char* wsts_header_value(const char* request, const char* name)
{
	/* case-insensitive header scan within the request head */
	const char* p = request;
	const size_t nlen = strlen(name);
	while (p && *p)
	{
		if (_strnicmp(p, name, nlen) == 0 && p[nlen] == ':')
		{
			const char* v = p + nlen + 1;
			while (*v == ' ' || *v == '\t')
				v++;
			const char* e = v;
			while (*e && *e != '\r' && *e != '\n')
				e++;
			return strndup(v, (size_t)(e - v));
		}
		p = strchr(p, '\n');
		if (p)
			p++;
	}
	return NULL;
}

/* base64(SHA1(key + GUID)) -> caller frees. NULL on failure. */
static char* wsts_compute_accept(const char* key)
{
	char concat[128] = { 0 };
	BYTE hash[WINPR_SHA1_DIGEST_LENGTH] = { 0 };
	(void)snprintf(concat, sizeof(concat), "%s%s", key, WS_ACCEPT_GUID);

	WINPR_DIGEST_CTX* ctx = winpr_Digest_New();
	if (!ctx)
		return NULL;
	BOOL ok = winpr_Digest_Init(ctx, WINPR_MD_SHA1) &&
	          winpr_Digest_Update(ctx, (const BYTE*)concat, strlen(concat)) &&
	          winpr_Digest_Final(ctx, hash, sizeof(hash));
	winpr_Digest_Free(ctx);
	if (!ok)
		return NULL;
	return crypto_base64_encode(hash, sizeof(hash));
}

static BOOL wsts_http_upgrade(rdpWsts* wsts)
{
	/* read request head up to CRLFCRLF */
	char buf[8192] = { 0 };
	size_t total = 0;
	char* key = NULL;
	char* upgrade = NULL;
	char* accept = NULL;
	char resp[256] = { 0 };
	BOOL ok = FALSE;

	BOOL headComplete = FALSE;
	while (total < sizeof(buf) - 1)
	{
		ERR_clear_error();
		const int rc = BIO_read(wsts->tls->bio, &buf[total], 1);
		if (rc > 0)
		{
			total += (size_t)rc;
			if (total >= 4 && memcmp(&buf[total - 4], "\r\n\r\n", 4) == 0)
			{
				headComplete = TRUE;
				break;
			}
		}
		else if (!BIO_should_retry(wsts->tls->bio))
		{
			WLog_Print(wsts->log, WLOG_ERROR,
			           "upgrade: read failed after %" PRIuz " bytes (peer closed?)", total);
			return FALSE;
		}
		else
			USleep(1000);
	}

	/* log the request line (up to first CRLF) for diagnosis */
	{
		size_t lineLen = 0;
		while (lineLen < total && buf[lineLen] != '\r' && buf[lineLen] != '\n')
			lineLen++;
		WLog_Print(wsts->log, WLOG_INFO, "upgrade: request-line [%" PRIuz " bytes head]: %.*s",
		           total, (int)lineLen, buf);
	}

	if (!headComplete)
	{
		WLog_Print(wsts->log, WLOG_ERROR, "upgrade: no CRLFCRLF in %" PRIuz " bytes", total);
		return FALSE;
	}

	/* request-target: "GET /<path>?... HTTP/1.1" — the ironrdp-web client opens a
	 * websocket via an HTTP GET upgrade; anything else is rejected. */
	if (_strnicmp(buf, "GET ", 4) != 0)
	{
		WLog_Print(wsts->log, WLOG_ERROR, "upgrade: not a GET request");
		return FALSE;
	}

	{
		const char* uriStart = buf + 4;
		const char* uriEnd = strchr(uriStart, ' ');
		if (!uriEnd)
			return FALSE;
		wsts->gwpath = strndup(uriStart, (size_t)(uriEnd - uriStart));
		if (wsts->gwpath)
		{
			const char* q = strchr(wsts->gwpath, '?');
			if (q)
				wsts->gwquery = _strdup(q + 1);
		}
	}

	WLog_Print(wsts->log, WLOG_INFO, "upgrade: path=%s", wsts->gwpath ? wsts->gwpath : "(none)");

	key = wsts_header_value(buf, "Sec-WebSocket-Key");
	upgrade = wsts_header_value(buf, "Upgrade");
	if (!key || !upgrade || (_stricmp(upgrade, "websocket") != 0))
	{
		WLog_Print(wsts->log, WLOG_ERROR,
		           "upgrade: missing/!= websocket (Upgrade=[%s], Sec-WebSocket-Key %s)",
		           upgrade ? upgrade : "(none)", key ? "present" : "MISSING");
		goto out;
	}

	accept = wsts_compute_accept(key);
	if (!accept)
		goto out;

	{
		/* deliberately NO Sec-WebSocket-Protocol and NO Sec-WebSocket-Extensions:
		 * decline permessage-deflate so the framing stays uncompressed. */
		const int rlen = snprintf(resp, sizeof(resp),
		                          "HTTP/1.1 101 Switching Protocols\r\n"
		                          "Upgrade: websocket\r\n"
		                          "Connection: Upgrade\r\n"
		                          "Sec-WebSocket-Accept: %s\r\n"
		                          "\r\n",
		                          accept);
		if (rlen > 0)
			ok = wsts_write_all(wsts, (const BYTE*)resp, (size_t)rlen);
	}

out:
	free(key);
	free(upgrade);
	free(accept);
	return ok;
}

/* ----------------------------------------------------------------------------
 * Inner-RDP front BIO: translate RDP byte stream <-> raw websocket binary frames
 * ------------------------------------------------------------------------- */

/* Send the RDCleanPath response: [0] version, [6] the peer's X.224 CC, [7] the
 * server cert chain (auth-irrelevant with CredSSP off, but populated). */
static BOOL wsts_rdcp_send_response(rdpWsts* wsts, const BYTE* cc, size_t ccLen)
{
	const BYTE* certs[1] = { 0 };
	size_t certLens[1] = { 0 };
	size_t certCount = 0;
	BYTE* certDer = NULL;

	const rdpCertificate* cert =
	    freerdp_settings_get_pointer(wsts->context->settings, FreeRDP_RdpServerCertificate);
	if (cert)
	{
		size_t len = 0;
		certDer = freerdp_certificate_get_der(cert, &len);
		if (certDer && len)
		{
			certs[0] = certDer;
			certLens[0] = len;
			certCount = 1;
		}
	}

	BYTE* der = NULL;
	size_t derLen = 0;
	/* [9] serverAddr must be present for the client to classify this as a Response; the
	 * value is ignored by ironrdp (destructured as _), so a placeholder host:port is
	 * fine. TODO: echo the request's [2] destination / the resolved target ip:port. */
	const BOOL built = rdcleanpath_write_response(cc, ccLen, certs, certLens, certCount,
	                                              "0.0.0.0:3389", &der, &derLen);
	free(certDer);
	if (!built)
		return FALSE;

	const BOOL sent = wsts_ws_send(wsts, der, derLen, WebsocketBinaryOpcode);
	free(der);
	WLog_Print(wsts->log, WLOG_INFO,
	           "RDCleanPath: response sent (CC %" PRIuz "B, certs %" PRIuz ", pdu %" PRIuz "B)",
	           ccLen, certCount, derLen);
	return sent;
}

/* Accumulate the peer's X.224 Connection Confirm; once a full TPKT is buffered,
 * fold it into the RDCleanPath response and leave the shim. */
static BOOL wsts_rdcp_capture_cc(rdpWsts* wsts, const BYTE* buf, size_t num)
{
	if (wsts->ccLen + num > wsts->ccCap)
	{
		size_t ncap = wsts->ccCap ? wsts->ccCap : 64;
		while (ncap < wsts->ccLen + num)
			ncap *= 2;
		BYTE* nb = (BYTE*)realloc(wsts->ccBuf, ncap);
		if (!nb)
			return FALSE;
		wsts->ccBuf = nb;
		wsts->ccCap = ncap;
	}
	memcpy(wsts->ccBuf + wsts->ccLen, buf, num);
	wsts->ccLen += num;

	if (wsts->ccLen >= 4) /* TPKT header present */
	{
		const size_t tpkt = ((size_t)wsts->ccBuf[2] << 8) | wsts->ccBuf[3];
		if ((tpkt >= 4) && (wsts->ccLen >= tpkt))
		{
			if (!wsts_rdcp_send_response(wsts, wsts->ccBuf, tpkt))
				return FALSE;
			wsts->rdcpAwaitingCc = FALSE;
			free(wsts->ccBuf);
			wsts->ccBuf = NULL;
			wsts->ccLen = wsts->ccCap = 0;
		}
	}
	return TRUE;
}

static int wsts_bio_write(BIO* bio, const char* buf, int num)
{
	rdpWsts* wsts = (rdpWsts*)BIO_get_data(bio);
	WINPR_ASSERT(wsts);
	BIO_clear_flags(bio, BIO_FLAGS_WRITE);

	if (num < 0)
		return -1;

	/* RDCleanPath: the peer's nego is writing the X.224 Connection Confirm; capture it
	 * into the RDCleanPath response instead of framing it raw over the websocket. */
	if (wsts->rdcpAwaitingCc)
	{
		if (!wsts_rdcp_capture_cc(wsts, (const BYTE*)buf, (size_t)num))
		{
			BIO_clear_flags(bio, BIO_FLAGS_SHOULD_RETRY);
			return -1;
		}
		BIO_set_flags(bio, BIO_FLAGS_WRITE);
		return num;
	}

	/* raw inner-RDP byte stream carried directly as a websocket binary frame */
	const BOOL ok = wsts_ws_send(wsts, (const BYTE*)buf, (size_t)num, WebsocketBinaryOpcode);

	if (!ok)
	{
		BIO_clear_flags(bio, BIO_FLAGS_SHOULD_RETRY);
		return -1;
	}
	BIO_set_flags(bio, BIO_FLAGS_WRITE);
	return num;
}

/* Non-blocking: append whatever the outer TLS bio has right now into rxbuf.
 * Returns >0 bytes read, 0 on would-block, <0 on hard error. */
static int wsts_pump(rdpWsts* wsts)
{
	if (wsts->rxLen + 4096 > wsts->rxCap)
	{
		size_t ncap = wsts->rxCap ? wsts->rxCap : 8192;
		while (ncap < wsts->rxLen + 4096)
			ncap *= 2;
		BYTE* nb = (BYTE*)realloc(wsts->rxbuf, ncap);
		if (!nb)
			return -1;
		wsts->rxbuf = nb;
		wsts->rxCap = ncap;
	}

	ERR_clear_error();
	const int n =
	    BIO_read(wsts->tls->bio, wsts->rxbuf + wsts->rxLen, (int)(wsts->rxCap - wsts->rxLen));
	if (n > 0)
	{
		wsts->rxLen += (size_t)n;
		return n;
	}
	if (BIO_should_retry(wsts->tls->bio))
		return 0;
	return -1;
}

/* Extract one complete, unmasked websocket frame payload from rxbuf. On success
 * fills *ppPayload (malloc'd)/*pLen/*pOpcode and consumes the frame. Returns
 * FALSE if rxbuf does not yet hold a full frame. */
static BOOL wsts_try_frame(rdpWsts* wsts, BYTE** ppPayload, size_t* pLen, BYTE* pOpcode)
{
	const BYTE* b = wsts->rxbuf;
	const size_t avail = wsts->rxLen;
	if (avail < 2)
		return FALSE;

	const BYTE opcode = b[0] & 0x0f;
	const BOOL masked = (b[1] & WEBSOCKET_MASK_BIT) != 0;
	size_t hdr = 2;
	size_t payloadLen = b[1] & 0x7f;

	if (payloadLen == 126)
	{
		if (avail < 4)
			return FALSE;
		payloadLen = ((size_t)b[2] << 8) | b[3];
		hdr = 4;
	}
	else if (payloadLen == 127)
	{
		if (avail < 10)
			return FALSE;
		payloadLen = 0;
		for (int i = 0; i < 8; i++)
			payloadLen = (payloadLen << 8) | b[2 + i];
		hdr = 10;
	}

	const size_t maskOff = hdr;
	if (masked)
		hdr += 4;

	if (avail < hdr + payloadLen)
		return FALSE; /* incomplete */

	BYTE* payload = NULL;
	if (payloadLen)
	{
		payload = (BYTE*)malloc(payloadLen);
		if (!payload)
			return FALSE;
		memcpy(payload, b + hdr, payloadLen);
		if (masked)
		{
			for (size_t i = 0; i < payloadLen; i++)
				payload[i] ^= b[maskOff + (i % 4)];
		}
	}

	const size_t frameTotal = hdr + payloadLen;
	memmove(wsts->rxbuf, wsts->rxbuf + frameTotal, wsts->rxLen - frameTotal);
	wsts->rxLen -= frameTotal;

	*ppPayload = payload;
	*pLen = payloadLen;
	*pOpcode = opcode;
	return TRUE;
}

static int wsts_bio_read(BIO* bio, char* buf, int size)
{
	rdpWsts* wsts = (rdpWsts*)BIO_get_data(bio);
	WINPR_ASSERT(wsts);
	if (size <= 0)
		return 0;

	for (;;)
	{
		/* 1) serve buffered inner-RDP bytes first */
		if (wsts->dataResidual && wsts->dataResidualPos < wsts->dataResidualLen)
		{
			const size_t availb = wsts->dataResidualLen - wsts->dataResidualPos;
			const size_t n = (availb < (size_t)size) ? availb : (size_t)size;
			memcpy(buf, wsts->dataResidual + wsts->dataResidualPos, n);
			wsts->dataResidualPos += n;
			if (wsts->dataResidualPos >= wsts->dataResidualLen)
			{
				free(wsts->dataResidual);
				wsts->dataResidual = NULL;
				wsts->dataResidualLen = wsts->dataResidualPos = 0;
			}
			BIO_set_flags(bio, BIO_FLAGS_READ);
			return (int)n;
		}

		/* 2) assemble a complete websocket frame from rxbuf, if present */
		BYTE* payload = NULL;
		size_t plen = 0;
		BYTE opcode = 0;
		if (wsts_try_frame(wsts, &payload, &plen, &opcode))
		{
			if ((opcode == WebsocketBinaryOpcode) || (opcode == WebsocketContinuationOpcode))
			{
				if (wsts->rdcpPending)
				{
					/* first plain-WS frame = DER RDCleanPath request. Unwrap the X.224
					 * CR and serve it to the peer's nego (its CC is captured in
					 * wsts_bio_write and folded into the RDCleanPath response). */
					BYTE* cr = NULL;
					size_t crLen = 0;
					const BOOL okReq = rdcleanpath_read_request(payload, plen, &cr, &crLen);
					free(payload);
					if (!okReq)
					{
						WLog_Print(wsts->log, WLOG_ERROR, "RDCleanPath: malformed request PDU");
						BIO_clear_flags(bio, BIO_FLAGS_SHOULD_RETRY);
						return -1;
					}
					wsts->rdcpPending = FALSE;
					wsts->rdcpAwaitingCc = TRUE;
					wsts->dataResidual = cr;
					wsts->dataResidualLen = crLen;
					wsts->dataResidualPos = 0;
					WLog_Print(wsts->log, WLOG_INFO,
					           "RDCleanPath: request parsed, X.224 CR = %" PRIuz " bytes", crLen);
					continue; /* serve the CR next loop */
				}

				/* the frame payload IS raw inner-RDP bytes; hand them straight to
				 * BIO_read via the residual buffer (take ownership, no copy). */
				if (plen)
				{
					wsts->dataResidual = payload;
					wsts->dataResidualLen = plen;
					wsts->dataResidualPos = 0;
					continue; /* serve residual next loop; do NOT free payload */
				}
				free(payload);
				continue;
			}
			else if (opcode == WebsocketPingOpcode)
			{
				(void)wsts_ws_send(wsts, payload, plen, WebsocketPongOpcode);
				free(payload);
				continue;
			}
			else if (opcode == WebsocketCloseOpcode)
			{
				(void)wsts_ws_send(wsts, NULL, 0, WebsocketCloseOpcode);
				free(payload);
				BIO_clear_flags(bio, BIO_FLAGS_SHOULD_RETRY);
				return -1; /* peer closed */
			}
			free(payload);
			continue;
		}

		/* 3) no complete frame: pull more raw bytes from the outer TLS bio */
		const int n = wsts_pump(wsts);
		if (n > 0)
			continue; /* try assembly again */
		if (n == 0)
		{
			/* would-block: tell the transport to wait for the next event */
			BIO_set_retry_read(bio);
			WSASetLastError(WSAEWOULDBLOCK);
			return -1;
		}
		BIO_clear_flags(bio, BIO_FLAGS_SHOULD_RETRY);
		return -1; /* hard error */
	}
}

static long wsts_bio_ctrl(BIO* bio, int cmd, long arg1, void* arg2)
{
	rdpWsts* wsts = (rdpWsts*)BIO_get_data(bio);
	WINPR_ASSERT(wsts);
	switch (cmd)
	{
		case BIO_CTRL_FLUSH:
			(void)BIO_flush(wsts->tls->bio);
			return 1;
		case BIO_C_SET_NONBLOCK:
			return 1;
		case BIO_C_GET_EVENT:
		case BIO_C_GET_FD:
			return BIO_ctrl(wsts->tls->bio, cmd, arg1, arg2);
		case BIO_C_READ_BLOCKED:
			return BIO_read_blocked(wsts->tls->bio);
		case BIO_C_WRITE_BLOCKED:
			return 0;
		case BIO_C_WAIT_READ:
			return BIO_wait_read(wsts->tls->bio, (int)arg1);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		case BIO_CTRL_GET_KTLS_SEND:
		case BIO_CTRL_GET_KTLS_RECV:
			return 0;
#endif
		default:
			return 0;
	}
}

static int wsts_bio_new(BIO* bio)
{
	BIO_set_init(bio, 1);
	BIO_set_flags(bio, BIO_FLAGS_SHOULD_RETRY);
	return 1;
}

static int wsts_bio_free(BIO* bio)
{
	WINPR_UNUSED(bio);
	return 1;
}

static BIO_METHOD* BIO_s_wsts(void)
{
	static BIO_METHOD* methods = NULL;
	if (!methods)
	{
		methods = BIO_meth_new(BIO_TYPE_TSG, "WSTSransport");
		if (!methods)
			return NULL;
		BIO_meth_set_write(methods, wsts_bio_write);
		BIO_meth_set_read(methods, wsts_bio_read);
		BIO_meth_set_ctrl(methods, wsts_bio_ctrl);
		BIO_meth_set_create(methods, wsts_bio_new);
		BIO_meth_set_destroy(methods, wsts_bio_free);
	}
	return methods;
}

/* ----------------------------------------------------------------------------
 * Outer TLS accept on the raw socket
 * ------------------------------------------------------------------------- */

static BOOL wsts_tls_accept(rdpWsts* wsts, int sockfd, DWORD timeout)
{
	WINPR_UNUSED(timeout);
	BIO* socketBio = BIO_new(BIO_s_simple_socket());
	if (!socketBio)
		return FALSE;
	BIO_set_fd(socketBio, sockfd, BIO_CLOSE);

	BIO* bufferedBio = BIO_new(BIO_s_buffered_socket());
	if (!bufferedBio)
	{
		BIO_free_all(socketBio);
		return FALSE;
	}
	bufferedBio = BIO_push(bufferedBio, socketBio);
	(void)BIO_set_nonblock(bufferedBio, 0); /* blocking during handshake */

	wsts->tls = freerdp_tls_new(wsts->context);
	if (!wsts->tls)
	{
		BIO_free_all(bufferedBio);
		return FALSE;
	}

	const int status = freerdp_tls_accept(wsts->tls, bufferedBio, wsts->context->settings);
	return (status >= 1);
}

/* ----------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

BOOL wsts_accept(rdpWsts* wsts, int sockfd, DWORD timeout)
{
	WINPR_ASSERT(wsts);
	wsts->sockfd = sockfd;

	if (!wsts_tls_accept(wsts, sockfd, timeout))
	{
		WLog_Print(wsts->log, WLOG_ERROR, "outer TLS accept failed");
		return FALSE;
	}
	if (!wsts_http_upgrade(wsts))
	{
		WLog_Print(wsts->log, WLOG_ERROR, "websocket upgrade failed");
		return FALSE;
	}
	/* ironrdp-web RDCleanPath: DEFER reading the DER request to the data phase.
	 * Consuming it here (blocking) and buffering the CR deadlocks: the peer's event loop
	 * waits on socket readability to drive its nego, but the CR would already be off the
	 * socket. So leave the request on the wire — wsts_bio_read unwraps the first frame
	 * into the X.224 CR when the peer's nego first reads, and wsts_bio_write folds the
	 * peer's CC into the RDCleanPath response. The inner RDP then runs plaintext over the
	 * websocket (rdp_server_accept_nego skips inner TLS, see
	 * transport_front_security_external). */
	wsts->rdcpPending = TRUE;
	WLog_Print(wsts->log, WLOG_INFO, "RDCleanPath: deferring request to data phase");

	/* The handshake ran with the outer TLS bio in blocking mode. The data phase is
	 * driven by the peer's non-blocking event loop (wsts_pump must see would-block),
	 * so switch the bio to non-blocking now. */
	BIO_set_nonblock(wsts->tls->bio, TRUE);
	return TRUE;
}

BIO* wsts_get_front_bio_and_take_ownership(rdpWsts* wsts)
{
	if (!wsts)
		return NULL;
	wsts->attached = TRUE;
	return wsts->frontBio;
}

WstsMode wsts_get_mode(rdpWsts* wsts)
{
	WINPR_UNUSED(wsts);
	/* ironrdp-only ingress: always plain RDP-over-WS + RDCleanPath (the MS-TSGU tunnel
	 * mode was removed). Kept so transport_front_security_external still skips inner TLS. */
	return WSTS_MODE_PLAIN_WS;
}

const char* wsts_get_query_param(rdpWsts* wsts, const char* name)
{
	/* NOTE: returns a pointer into a malloc'd scratch buffer cached on wsts.
	 * Minimal implementation: caller copies immediately. TODO: parse once into a map. */
	WINPR_UNUSED(wsts);
	WINPR_UNUSED(name);
	return NULL; /* TODO: implement query parsing over wsts->gwquery */
}

rdpWsts* wsts_new(rdpContext* context)
{
	if (!context)
		return NULL;

	rdpWsts* wsts = (rdpWsts*)calloc(1, sizeof(rdpWsts));
	if (!wsts)
		return NULL;

	wsts->context = context;
	wsts->log = WLog_Get(TAG);
	wsts->sockfd = -1;

	wsts->frontBio = BIO_new(BIO_s_wsts());
	if (!wsts->frontBio)
	{
		wsts_free(wsts);
		return NULL;
	}
	BIO_set_data(wsts->frontBio, wsts);
	return wsts;
}

void wsts_free(rdpWsts* wsts)
{
	if (!wsts)
		return;

	freerdp_tls_free(wsts->tls);
	free(wsts->gwpath);
	free(wsts->gwquery);
	free(wsts->dataResidual);
	free(wsts->ccBuf);
	free(wsts->rxbuf);

	if (!wsts->attached && wsts->frontBio)
		BIO_free_all(wsts->frontBio);

	free(wsts);
}
