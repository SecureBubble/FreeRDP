/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * RDCleanPath (Devolutions) PDU codec — server/proxy side.
 *
 * Copyright 2026 Bubble
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

#include <winpr/crt.h>
#include <winpr/asn1.h>
#include <winpr/stream.h>

#include <freerdp/log.h>

#include "rdcleanpath.h"

#define TAG FREERDP_TAG("core.gateway.rdcleanpath")

/* RDCleanPath field tags (context-specific, EXPLICIT). */
#define RDCP_TAG_VERSION 0
#define RDCP_TAG_DESTINATION 2
#define RDCP_TAG_X224 6
#define RDCP_TAG_CERT_CHAIN 7
#define RDCP_TAG_SERVER_ADDR 9

BOOL rdcleanpath_read_request(const BYTE* der, size_t derLen, BYTE** x224Cr, size_t* x224CrLen)
{
	if (!der || !x224Cr || !x224CrLen)
		return FALSE;

	*x224Cr = NULL;
	*x224CrLen = 0;

	WinPrAsn1Decoder dec = { 0 };
	WinPrAsn1Decoder seq = { 0 };
	WinPrAsn1Decoder_InitMem(&dec, WINPR_ASN1_DER, der, derLen);

	if (WinPrAsn1DecReadSequence(&dec, &seq) == 0)
	{
		WLog_ERR(TAG, "RDCleanPath request: not a SEQUENCE");
		return FALSE;
	}

	/* Fields are ordered by ascending context tag; iterate and pick [6]. Each
	 * ReadContextualTag reads one EXPLICIT [tag] element and advances seq past it,
	 * so tags we do not care about (version/destination/proxyAuth/...) are skipped
	 * simply by not reading their content. */
	for (;;)
	{
		WinPrAsn1_tagId tag = 0;
		WinPrAsn1Decoder ctx = { 0 };
		if (WinPrAsn1DecReadContextualTag(&seq, &tag, &ctx) == 0)
			break;

		if (tag == RDCP_TAG_X224)
		{
			WinPrAsn1_OctetString os = { 0 };
			if ((WinPrAsn1DecReadOctetString(&ctx, &os, TRUE) != 0) && os.len && os.data)
			{
				*x224Cr = (BYTE*)malloc(os.len);
				if (!*x224Cr)
				{
					free(os.data);
					return FALSE;
				}
				memcpy(*x224Cr, os.data, os.len);
				*x224CrLen = os.len;
			}
			free(os.data);
			break; /* got what we need */
		}
	}

	if (!*x224Cr)
	{
		WLog_ERR(TAG, "RDCleanPath request: missing x224ConnectionPdu [6]");
		return FALSE;
	}
	return TRUE;
}

BOOL rdcleanpath_write_response(const BYTE* x224Cc, size_t ccLen, const BYTE* const* certDer,
                                const size_t* certLen, size_t certCount, const char* serverAddr,
                                BYTE** outDer, size_t* outLen)
{
	if (!outDer || !outLen || !serverAddr)
		return FALSE;

	*outDer = NULL;
	*outLen = 0;

	BOOL ok = FALSE;
	wStream* s = NULL;
	WinPrAsn1Encoder* enc = WinPrAsn1Encoder_New(WINPR_ASN1_DER);
	if (!enc)
		return FALSE;

	if (!WinPrAsn1EncSeqContainer(enc)) /* SEQUENCE { */
		goto out;

	/* version [0] EXPLICIT INTEGER */
	if (!WinPrAsn1EncContextualContainer(enc, RDCP_TAG_VERSION))
		goto out;
	if (WinPrAsn1EncInteger(enc, RDCLEANPATH_VERSION_1) == 0)
		goto out;
	if (WinPrAsn1EncEndContainer(enc) == 0)
		goto out;

	/* x224ConnectionPdu [6] EXPLICIT OCTET STRING (the Connection Confirm) */
	if (x224Cc && ccLen)
	{
		const WinPrAsn1_OctetString os = { .len = ccLen, .data = (BYTE*)x224Cc };
		if (!WinPrAsn1EncContextualContainer(enc, RDCP_TAG_X224))
			goto out;
		if (WinPrAsn1EncOctetString(enc, &os) == 0)
			goto out;
		if (WinPrAsn1EncEndContainer(enc) == 0)
			goto out;
	}

	/* serverCertChain [7] EXPLICIT SEQUENCE OF OCTET STRING */
	if (certCount && certDer && certLen)
	{
		if (!WinPrAsn1EncContextualContainer(enc, RDCP_TAG_CERT_CHAIN))
			goto out;
		if (!WinPrAsn1EncSeqContainer(enc))
			goto out;
		for (size_t i = 0; i < certCount; i++)
		{
			const WinPrAsn1_OctetString os = { .len = certLen[i], .data = (BYTE*)certDer[i] };
			if (WinPrAsn1EncOctetString(enc, &os) == 0)
				goto out;
		}
		if (WinPrAsn1EncEndContainer(enc) == 0) /* end SEQUENCE OF */
			goto out;
		if (WinPrAsn1EncEndContainer(enc) == 0) /* end [7] */
			goto out;
	}

	/* serverAddr [9] EXPLICIT UTF8String — REQUIRED: ironrdp classifies the PDU as a
	 * Response by the presence of this field. winpr has no UTF8String encoder, so wrap
	 * a hand-built UTF8String primitive (tag 0x0C) in the explicit [9] container. */
	{
		const size_t alen = strlen(serverAddr);
		if (alen > 0x7f) /* keep DER length single-byte; serverAddr is host:port */
			goto out;
		BYTE prim[2 + 0x80];
		prim[0] = 0x0C; /* UTF8String */
		prim[1] = (BYTE)alen;
		memcpy(prim + 2, serverAddr, alen);
		const WinPrAsn1_MemoryChunk mc = { .len = 2 + alen, .data = prim };
		if (!WinPrAsn1EncContextualContainer(enc, RDCP_TAG_SERVER_ADDR))
			goto out;
		if (WinPrAsn1EncRawContent(enc, &mc) == 0)
			goto out;
		if (WinPrAsn1EncEndContainer(enc) == 0) /* end [9] */
			goto out;
	}

	if (WinPrAsn1EncEndContainer(enc) == 0) /* } SEQUENCE */
		goto out;

	size_t sz = 0;
	if (!WinPrAsn1EncStreamSize(enc, &sz) || (sz == 0))
		goto out;
	s = Stream_New(NULL, sz);
	if (!s)
		goto out;
	if (!WinPrAsn1EncToStream(enc, s))
		goto out;

	*outLen = Stream_GetPosition(s);
	*outDer = (BYTE*)malloc(*outLen ? *outLen : 1);
	if (!*outDer)
	{
		*outLen = 0;
		goto out;
	}
	memcpy(*outDer, Stream_Buffer(s), *outLen);
	ok = TRUE;

out:
	if (s)
		Stream_Free(s, TRUE);
	WinPrAsn1Encoder_Free(&enc);
	return ok;
}
