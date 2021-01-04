/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * UDP version 1 and 2 protocol
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
#include <winpr/sysinfo.h>
#include <winpr/print.h>
#include <winpr/crypto.h>

#include "rdpudp12.h"
#include "rdpudp.h"

#define TAG FREERDP_TAG("udp12")

UdpWindowBuffer* UdpWindowBuffer_new(rdpUdpTransport* udp, size_t windowSz)
{
	UdpWindowBuffer* ret = calloc(1, sizeof(*ret));
	if (!ret)
		return ret;

	ret->udp = udp;
	ret->windowSize = windowSz;
	ret->buffer = calloc(windowSz, sizeof(UdpBufferPacket));
	if (!ret->buffer)
	{
		free(ret);
		return NULL;
	}
	return ret;
}

void UdpWindowBuffer_free(UdpWindowBuffer** pbuf)
{
	UdpWindowBuffer* buf = *pbuf;

	free(buf->buffer);
	free(buf);
	*pbuf = NULL;
}

BOOL UdpWindowBuffer_push(UdpWindowBuffer* b, UINT32 seq, wStream* s)
{
	UdpBufferPacket* dest = &b->buffer[b->endPtr];
	dest->seq = seq;
	dest->acked = FALSE;
	dest->sendDate = GetTickCount64();
	dest->resendNb = 0;
	dest->packet = s;

	b->endPtr = (b->endPtr + 1) % b->windowSize;
	// TODO: check bounds
	return TRUE;
}

BOOL UdpWindowBuffer_ackPacket(UdpWindowBuffer* b, UINT32 seq)
{
	UINT16 ptrIdx = b->startPtr;
	UdpBufferPacket* dest;

	while (ptrIdx != b->endPtr && b->buffer[ptrIdx].seq != seq)
		ptrIdx = (ptrIdx + 1) % b->windowSize;

	if (ptrIdx == b->endPtr)
		return FALSE;

	dest = &b->buffer[ptrIdx];
	dest->acked = TRUE;
	rdpUdpTransport_discardPacket(b->udp, dest->packet);
	dest->packet = NULL;

	/** let's advance the inPtr until all packets have been acked */
	while ((b->startPtr == ptrIdx) && b->buffer[ptrIdx].acked && (b->startPtr != b->endPtr))
	{
		b->startPtr = ptrIdx = (ptrIdx + 1) % b->windowSize;
	}
	return TRUE;
}

BOOL write_fec_header(wStream* s, UINT32 snSourceAck, UINT16 uReceiveWindowSize, UINT16 uFlags)
{
	if (Stream_GetRemainingCapacity(s) < 8)
		return FALSE;

	Stream_Write_UINT32_BE(s, snSourceAck);
	Stream_Write_UINT16_BE(s, uReceiveWindowSize);
	Stream_Write_UINT16_BE(s, uFlags);
	return TRUE;
}

BOOL write_syndata_payload(wStream* s, UINT32 snIniSeqNumber, UINT16 uUpStreamMtu,
                           UINT16 uDownStreamMtu)
{
	if (Stream_GetRemainingCapacity(s) < 8)
		return FALSE;

	Stream_Write_UINT32_BE(s, snIniSeqNumber);
	Stream_Write_UINT16_BE(s, uUpStreamMtu);
	Stream_Write_UINT16_BE(s, uDownStreamMtu);
	return TRUE;
}

BOOL write_syndata_correlationId(wStream* s, const BYTE* uCorrelationId)
{
	if (Stream_GetRemainingCapacity(s) < 32)
		return FALSE;

	Stream_Write(s, uCorrelationId, 16);
	Stream_Zero(s, 16);
	return TRUE;
}

#ifdef WITH_DEBUG_UDP

static void flagsString(UINT16 flags, char* buffer)
{
	int i, match = 0;
	UINT16 mask = 0x01;
	char* targetBuf = buffer;
	const char* udp1FlagNames[] = { "SYN",         "FIN",      "ACK",        "DATA",
		                            "FEC",         "CN",       "CWR",        "SACK",
		                            "ACK_OF_ACKS", "SYNLOSSY", "ACKDELAYED", "CORRELATION_ID",
		                            "SYNEX" };

	*targetBuf = '\0';
	for (i = 0; i < sizeof(udp1FlagNames) / sizeof(udp1FlagNames[0]); i++, mask <<= 1)
	{
		if ((flags & mask) == 0)
			continue;

		if (match)
		{
			*targetBuf = ',';
			targetBuf++;
		}
		strcpy(targetBuf, udp1FlagNames[i]);
		targetBuf += strlen(udp1FlagNames[i]);
		match++;
	}
}

static void print_packet(Udp12Packet* p)
{
	char buffer[2048];
	int i;

	flagsString(p->uFlags, buffer);
	WLog_DBG(TAG, "============== UDP packet ==============");
	WLog_DBG(TAG, "flags=%s", buffer);
	WLog_DBG(TAG, "snSourceAcks=0x%" PRIx32 "", p->snSourceAck);
	WLog_DBG(TAG, "receiveWindowSize=%" PRIu16 "", p->uReceiveWindowSize);

	if (p->uFlags & RDPUDP_FLAG_SYN)
	{
		WLog_DBG(TAG, "snInitialSequenceNumber=0x%" PRIx32 "", p->snInitialSequenceNumber);
		WLog_DBG(TAG, "[up|down] MTU=(%" PRIu16 ",%" PRIu16 ")", p->uUpStreamMtu,
		         p->uDownStreamMtu);
	}

	if (p->uFlags & RDPUDP_FLAG_CORRELATION_ID)
	{
		char tmp[4];
		buffer[0] = '\0';
		for (i = 0; i < 16; i++)
		{
			snprintf(tmp, sizeof(tmp), "%02x ", p->uCorrelationId[i]);
			strcat(buffer, tmp);
		}
		WLog_DBG(TAG, "correlationId=%s", buffer);
	}

	if (p->uFlags & RDPUDP_FLAG_SYNEX)
	{
		WLog_DBG(TAG, "uSynExFlags=0x%" PRIx16 "", p->uSynExFlags);
		WLog_DBG(TAG, "uUdpVer=0x%" PRIx16 "", p->uUdpVer);
	}

	if ((p->uFlags & RDPUDP_FLAG_ACK) && !(p->uFlags & RDPUDP_FLAG_SYN))
	{
		snprintf(buffer, sizeof(buffer), "ackVector(%" PRIu16 ")=", p->uAckVectorSize);
		for (i = 0; i < p->uAckVectorSize; i++)
		{
			char tmp[1024];
			snprintf(tmp, sizeof(tmp), "(S=%d,L=%d)", p->AckVectorElements[i].state,
			         p->AckVectorElements[i].nb);
			strcat(buffer, tmp);
		}
		WLog_DBG(TAG, buffer);
	}

	if (p->uFlags & RDPUDP_FLAG_DATA)
	{
		WLog_DBG(TAG, "snCoded=0x%" PRIx32 " snSourceStart=0x%" PRIx32 " payload={",
		         p->sourceSnCoded, p->sourceSnSourceStart);
		winpr_HexDump(TAG, WLOG_DEBUG, p->payload, p->cbPayloadSize);
		WLog_DBG(TAG, "}");
	}

	WLog_DBG(TAG, "========================================");
}
#endif

static BOOL forge_packet(rdpUdpTransport* udp, wStream* s, Udp12Packet* p)
{
	BOOL haveSyn;
	const UdpMtu* mtus = rdpUdpTransport_Mtus(udp);

	if (!write_fec_header(s, p->snSourceAck, p->uReceiveWindowSize, p->uFlags))
		return FALSE;

	haveSyn = (p->uFlags & RDPUDP_FLAG_SYN) != 0;
	if (haveSyn &&
	    !write_syndata_payload(s, p->snInitialSequenceNumber, p->uUpStreamMtu, p->uDownStreamMtu))
		return FALSE;

	if ((p->uFlags & RDPUDP_FLAG_CORRELATION_ID) &&
	    !write_syndata_correlationId(s, p->uCorrelationId))
		return FALSE;

	if ((p->uFlags & RDPUDP_FLAG_SYNEX))
	{
		if (Stream_GetRemainingCapacity(s) < 4)
			return FALSE;

		Stream_Write_UINT16_BE(s, p->uSynExFlags);
		Stream_Write_UINT16_BE(s, p->uUdpVer);
		if (p->uUdpVer == RDPUDP_PROTOCOL_VERSION_3)
		{
			/* An optional 32-byte array that contains the SHA-256 hash of the data that
			    was transmitted from the server to the client in the securityCookie field of the
			   Initiate Multitransport Request PDU ([MS-RDPBCGR] section 2.2.15.1). The cookieHash
			   field MUST be present in a SYN datagram sent from the client to the server
			   (section 3.1.5.1.1) if uUdpVer
			    equals RDPUDP_PROTOCOL_VERSION_3 (0x0101). It MUST NOT be present in any other case.
			 */
			if (Stream_GetRemainingCapacity(s) < 32)
				return FALSE;

			Stream_Write(s, p->cookieHash, sizeof(p->cookieHash));
		}
	}

	if (!haveSyn && (p->uFlags & RDPUDP_FLAG_ACK))
	{
		UdpAck* acks = p->AckVectorElements;
		int i;

		if (Stream_GetRemainingCapacity(s) < 2 + p->uAckVectorSize)
			return FALSE;

		Stream_Write_UINT16_BE(s, p->uAckVectorSize);
		for (i = 0; i < p->uAckVectorSize; i++, acks++)
		{
			BYTE v = (acks->state << 6) | (acks->nb & 0x3f);
			Stream_Write_UINT8(s, v);
		}
	}

	if ((p->uFlags & RDPUDP_FLAG_ACK_OF_ACKS))
	{
		// TODO
	}

	Stream_Zero(s, mtus->up - Stream_GetPosition(s));
	Stream_SealLength(s);
	return TRUE;
}

void prepare_packet(Udp12Context* udp12, Udp12Packet* packet)
{
	packet->snSourceAck = udp12->lastReceivedPacket;
	packet->uReceiveWindowSize = udp12->receiveWindowSize;
}

void prepare_syn_packet(rdpUdpTransport* udp, Udp12Context* udp12, UINT16 flags,
                        Udp12Packet* packet)
{
	const UdpMtu* mtus = rdpUdpTransport_Mtus(udp);
	prepare_packet(udp12, packet);
	packet->uFlags = RDPUDP_FLAG_SYN | RDPUDP_FLAG_CORRELATION_ID | RDPUDP_FLAG_SYNEX | flags;
	if (rdpUdpTransport_isLossy(udp))
		packet->uFlags |= RDPUDP_FLAG_SYNLOSSY;

	packet->snInitialSequenceNumber = udp12->currentSeqNumber++;
	packet->uUpStreamMtu = mtus->up;
	packet->uDownStreamMtu = mtus->down;

	if (packet->uFlags & RDPUDP_FLAG_CORRELATION_ID)
		rdpUdpTransport_copyCorrelationId(udp, packet->uCorrelationId);

	packet->uSynExFlags = RDPUDP_VERSION_INFO_VALID;
	packet->uUdpVer =
	    rdpUdpTransport_isLossy(udp) ? RDPUDP_PROTOCOL_VERSION_2 : RDPUDP_PROTOCOL_VERSION_3;
	if (packet->uUdpVer == RDPUDP_PROTOCOL_VERSION_3)
		rdpUdpTransport_copyCookie(udp, packet->cookieHash);
}

BOOL udp12_send_packet(rdpUdpTransport* udp, Udp12Context* udp12, Udp12Packet* packet)
{
	wStream* s = rdpUdpTransport_getPacket(udp);
	if (!s)
		return FALSE;

	if (!forge_packet(udp, s, packet))
	{
		rdpUdpTransport_discardPacket(udp, s);
		return FALSE;
	}

	if (!rdpUdpTransport_bioSend(udp, s))
		return FALSE;

	return UdpWindowBuffer_push(udp12->outputBuffer, udp12->currentSeqNumber++, s);
}


BOOL udp12_send_syn(rdpUdpTransport* udp, Udp12Context* udp12, UINT16 flags)
{
	Udp12Packet packet;
	wStream* s = rdpUdpTransport_getPacket(udp);
	if (!s)
		return FALSE;

	WLog_DBG(TAG, "---> UDP syn(flags=0x%x)", flags);
	prepare_syn_packet(udp, udp12, 0, &packet);

	if (!forge_packet(udp, s, &packet))
	{
		rdpUdpTransport_discardPacket(udp, s);
		return FALSE;
	}

	Stream_SealLength(s);

	if (!rdpUdpTransport_bioSend(udp, s))
		return FALSE;

	return UdpWindowBuffer_push(udp12->outputBuffer, packet.snInitialSequenceNumber, s);
}


BOOL udp12_send_ack(rdpUdpTransport* udp, Udp12Context* udp12)
{
	Udp12Packet packet;
	UdpAck ack;

	wStream* s = rdpUdpTransport_getPacket(udp);
	if (!s)
		return FALSE;

	WLog_DBG(TAG, "---> UDP ack()");
	prepare_packet(udp12, &packet);
	packet.uFlags = RDPUDP_FLAG_ACK;
	packet.uAckVectorSize = 1;
	packet.AckVectorElements = &ack;
	ack.nb = 1;
	ack.state = DATAGRAM_RECEIVED;

	// TODO handle CN and ACKS_OF_ACKS
	if (!forge_packet(udp, s, &packet))
	{
		rdpUdpTransport_discardPacket(udp, s);
		return FALSE;
	}

	if (!rdpUdpTransport_bioSend(udp, s))
		return FALSE;

	return UdpWindowBuffer_push(udp12->outputBuffer, udp12->currentSeqNumber++, s);
}

#if 0
BOOL send_synack(rdpUdpTransport* udp, Udp12Context* udp12)
{
	Udp12Packet packet;

	wStream* s = rdpUdpTransport_getPacket(udp);
	if (!s)
		return FALSE;

	WLog_DBG(TAG, "---> UDP syn+ack()");
	prepare_syn_packet(udp, udp12, RDPUDP_FLAG_ACK, &packet);

	// TODO handle CN and ACKS_OF_ACKS

	if (!forge_packet(udp, s, &packet))
	{
		rdpUdpTransport_discardPacket(udp, s);
		return FALSE;
	}

	if (!rdpUdpTransport_bioSend(udp, s))
		return FALSE;

	return UdpWindowBuffer_push(udp12->outputBuffer, udp12->currentSeqNumber++, s);
}
#endif

BOOL udp12_init(rdpUdpTransport* udp, Udp12Context* udp12, BOOL server)
{
	udp12->lastReceivedPacket = 0xffffffff;
	udp12->receiveWindowSize = 64;

	if (winpr_RAND((BYTE*)&udp12->currentSeqNumber, sizeof(udp12->currentSeqNumber)) < 0)
		return FALSE;

	udp12->outputBuffer = UdpWindowBuffer_new(udp, udp12->receiveWindowSize);
	if (!udp12->outputBuffer)
		return FALSE;


	return TRUE;
}

void udp12_destroy(Udp12Context* udp12)
{
	UdpWindowBuffer_free(&udp12->outputBuffer);
}

BOOL udp12_parse_packet(wStream* s, Udp12Packet* packet)
{
	if (Stream_GetRemainingLength(s) < 8)
		return FALSE;

	Stream_Read_UINT32_BE(s, packet->snSourceAck);
	Stream_Read_UINT16_BE(s, packet->uReceiveWindowSize);
	Stream_Read_UINT16_BE(s, packet->uFlags);

	if (packet->uFlags & RDPUDP_FLAG_SYN)
	{
		if (Stream_GetRemainingLength(s) < 8)
			return FALSE;

		Stream_Read_UINT32_BE(s, packet->snInitialSequenceNumber);
		Stream_Read_UINT16_BE(s, packet->uUpStreamMtu);
		Stream_Read_UINT16_BE(s, packet->uDownStreamMtu);
	}

	if (packet->uFlags & RDPUDP_FLAG_CORRELATION_ID)
	{
		if (Stream_GetRemainingLength(s) < 32)
			return FALSE;

		Stream_Read(s, packet->uCorrelationId, 16);
		Stream_Seek(s, 16); /* reserved */
	}

	if (packet->uFlags & RDPUDP_FLAG_SYNEX)
	{
		if (Stream_GetRemainingLength(s) < 4)
			return FALSE;

		Stream_Read_UINT16_BE(s, packet->uSynExFlags);
		Stream_Read_UINT16_BE(s, packet->uUdpVer);
		if (packet->uUdpVer == RDPUDP_PROTOCOL_VERSION_3)
		{
			if (Stream_GetRemainingLength(s) < 32)
				return FALSE;

			Stream_Read(s, &packet->cookieHash, sizeof(packet->cookieHash));
		}
	}

	if ((packet->uFlags & RDPUDP_FLAG_ACK) && !(packet->uFlags & RDPUDP_FLAG_SYN))
	{
		UINT16 i;
		if (Stream_GetRemainingLength(s) < 2)
			return FALSE;

		Stream_Read_UINT16_BE(s, packet->uAckVectorSize);
		if (Stream_GetRemainingLength(s) < packet->uAckVectorSize)
			return FALSE;

		free(packet->AckVectorElements);
		packet->AckVectorElements = NULL;
		packet->AckVectorElements =
		    calloc(packet->uAckVectorSize, sizeof(*packet->AckVectorElements));
		if (!packet->AckVectorElements)
			return FALSE;

		for (i = 0; i < packet->uAckVectorSize; i++)
		{
			BYTE b;
			Stream_Read_UINT8(s, b);
			packet->AckVectorElements[i].nb = b & 0x3f;
			packet->AckVectorElements[i].state = (b >> 6) & 0x03;
		}

		if (packet->uAckVectorSize % 2)
			Stream_Seek(s, 1);
		else if (!packet->uAckVectorSize)
			Stream_Seek(s, 2);
	}

	if (packet->uFlags & RDPUDP_FLAG_FEC)
	{
		if (Stream_GetRemainingLength(s) < 12)
			return FALSE;

		Stream_Read_UINT32_BE(s, packet->snCoded);       // FEC snCoded
		Stream_Read_UINT32_BE(s, packet->snSourceStart); // FEC snSourceStart
		Stream_Read_UINT8(s, packet->uRange);
		Stream_Read_UINT8(s, packet->uFecIndex);
		Stream_Seek(s, 2);
	}

	if (packet->uFlags & RDPUDP_FLAG_ACK_OF_ACKS)
	{
		if (Stream_GetRemainingLength(s) < 4)
			return FALSE;
		Stream_Read_UINT32_BE(s, packet->snAckOfAcksSeqNum);
	}

	if (packet->uFlags & RDPUDP_FLAG_DATA)
	{
		if (Stream_GetRemainingLength(s) < 8)
			return FALSE;

		Stream_Read_UINT32_BE(s, packet->sourceSnCoded);
		Stream_Read_UINT32_BE(s, packet->sourceSnSourceStart);
		Stream_GetPointer(s, packet->payload);
		packet->cbPayloadSize = Stream_GetRemainingLength(s);
	}

#ifdef WITH_DEBUG_UDP
	print_packet(packet);
#endif
	return TRUE;
}

BOOL udp12_packet_writer(rdpUdpTransport* udp, Udp12Context* udp12, wStream* s)
{
	return TRUE;
}
