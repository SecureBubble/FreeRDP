/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * UDP version 3 implementation as specified in MS_RDPEUDP2
 *
 * Copyright 2025 David Fort <contact@hardening-consulting.com>
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
#include "rdpudp3.h"
#include "rdpudp.h"

#include <winpr/wlog.h>
#include <winpr/print.h>
#include <winpr/sysinfo.h>
#include <freerdp/log.h>

#define TAG FREERDP_TAG("udp3")

typedef enum
{
	UDPDATA_TYPE_NONE,
	UDPDATA_TYPE_DUMMY,
	UDPDATA_TYPE_DATA
} UdpDataType;

typedef enum
{
	PIGGYBACK_NONE,  /*!< don't try to append any ack data */
	PIGGYBACK_DATA,  /*!< piggy back for DATA packets: ACK but not ACKVEC */
	PIGGYBACK_TIMER, /*!< piggy back when running timers ACK or ACKVEC depending on the first entry
	                  */
} PiggyBackMode;

static void udp3_write_headers(wStream* s, Udp3Context* udp3, UdpDataType dataType, UINT16 dataSeq,
                               PiggyBackMode piggyBack);

UINT64 computeFullSeqNumber(UINT64 refNumber, UINT16 seqNumber)
{
	UINT64 cand = (refNumber & ~0xffff) | seqNumber;
	INT64 delta = (cand - refNumber);
	if (delta > 0x8000)
		cand -= 0x10000;
	else if (delta < -0x8000)
		cand += 0x10000;
	return cand;
}

UINT64 channelSeqNumberLinearToFullShort(UINT64 n)
{
	return 1 + n + (n / 0xffff);
}

UINT64 channelSeqNumberShort16ToLinear(UINT64 ref, UINT16 short16)
{
	UINT64 refShort = channelSeqNumberLinearToFullShort(ref);
	UINT64 base = refShort & ~0xffff;
	UINT64 shortN = short16 + base;

	/* now that we have a full short16 let's look if a wrap around was involved */
	if (shortN > refShort)
	{
		/* refShort v
		 *  [       x      x         ]
		 *                 ^ shortN
		 */
		if (shortN - refShort > 0x8000)
			shortN -= 0x10000;
	}
	else
	{
		/*   ShortN v
		 *  [       x      x         ]
		 *                 ^ refShort
		 */
		if (refShort - shortN > 0x8000)
			shortN += 0x10000;
	}

	return shortN - 1 - (shortN / 0x10000);
}

static void udp3_finalize_packet(wStream* s)
{
	/* swap byte 0 and 7 */
	BYTE* buffer;
	BYTE tmp;
	buffer = Stream_Buffer(s);
	tmp = buffer[7];
	buffer[7] = buffer[0];
	buffer[0] = tmp;
}

void Stream_Read_UINT24(wStream* s, UINT32* dest)
{
	BYTE hi;
	Stream_Read_UINT16(s, *dest);
	Stream_Read_UINT8(s, hi);
	*dest += (hi << 16);
}

void Stream_Write_UINT24(wStream* s, UINT32 v)
{
	Stream_Write_UINT16(s, (v & 0xffff));
	Stream_Write_UINT8(s, (v >> 16) & 0xff);
}

Udp3ReceiveWindow* Udp3ReceiveWindow_New(rdpUdpTransport* udp, size_t windowSz)
{
	size_t i;
	Udp3ReceiveWindow* ret = calloc(1, sizeof(*ret));
	if (!ret)
		return NULL;

	ret->udp = udp;
	ret->lowChannelWindow = ret->upChannelWindow = 0;
	ret->windowSize = windowSz;
	ret->window = calloc(windowSz, sizeof(*ret->window));
	if (!ret->window)
		goto error_window;
	for (i = 0; i < windowSz; i++)
		ret->window[i].state = UDP2_PACKET_PENDING;

	ret->channelWindow = calloc(windowSz, sizeof(ret->channelWindow[0]));
	if (!ret->channelWindow)
		goto error_channel;

	ret->lowIndex = ret->upIndex = 0x64;
	ret->ackableIndex = 0x63;
	return ret;

error_channel:
	free(ret->window);
error_window:
	free(ret);
	return NULL;
}

void Udp3ReceiveWindow_Destroy(Udp3ReceiveWindow** pwindow)
{
	Udp3ReceiveWindow* w = *pwindow;

	free(w->window);

	for (UINT64 i = w->lowChannelWindow; i < w->upChannelWindow; i++)
	{
		ChannelPacket* p = &w->channelWindow[i % w->windowSize];
		rdpUdpTransport_discardPacket(w->udp, p->s);
	}
	free(w->channelWindow);
	free(w);
	*pwindow = NULL;
}

UINT64 Udp3ReceiveWindow_nacks(Udp3ReceiveWindow* w)
{
	if (w->ackableIndex < w->lowIndex)
		return 0;

	return 1 + (w->ackableIndex - w->lowIndex);
}

wStream* Stream_Dup(rdpUdpTransport* udp, wStream* s)
{
	wStream* ret = rdpUdpTransport_getPacket(udp);
	if (!ret || !Stream_EnsureRemainingCapacity(ret, Stream_Length(s)))
		return NULL;

	Stream_Write(ret, Stream_Buffer(s), Stream_Length(s));
	Stream_SealLength(ret);
	return ret;
}

static inline UINT16 seqNext(UINT16 s, UINT16 windowSize)
{
	return (s + 1) % windowSize;
}

BOOL Udp3ReceiveWindow_updateAckable(Udp3ReceiveWindow* w)
{
	UINT64 newAckable = (w->lowIndex - 1);

	for (UINT64 seqIndex = w->lowIndex; seqIndex < w->upIndex; seqIndex++)
	{
		if (w->window[seqIndex % w->windowSize].state != UDP2_PACKET_RECEIVED)
			break;
		newAckable = seqIndex;
	}

	if (newAckable > w->ackableIndex)
	{
		UDP_DEBUG("new ackable seqId=0x%0.4x", newAckable);
		w->ackableIndex = newAckable;
		return TRUE;
	}
	return FALSE;
}

BOOL Udp3ReceiveWindow_recvDataPacket(Udp3ReceiveWindow* w, UINT16 seqNumber16,
                                      UINT16 channelSeqNumber16, wStream* payload)
{
	ReceivedPacket* rpacket;
	char payloadMsg[100];
	UINT64 seqNumber = computeFullSeqNumber(w->lowIndex, seqNumber16);
	UINT64 channelSeqNumber =
	    channelSeqNumberShort16ToLinear(w->lowChannelWindow, channelSeqNumber16);

	if (payload)
		snprintf(payloadMsg, sizeof(payloadMsg) - 1,
		         "channelSeqNumber=0x%lx(channelData16=0x%x) [%.8lx-%.8lx] payloadSz=%ld",
		         channelSeqNumber, channelSeqNumber16, w->lowChannelWindow, w->upChannelWindow,
		         Stream_Length(payload));
	else
		snprintf(payloadMsg, sizeof(payloadMsg) - 1, "dummy");

	UDP_DEBUG("%s: seqNumber=0x%x %s", __func__, seqNumber, payloadMsg);
	if (seqNumber < w->lowIndex)
	{
		WLog_INFO(TAG, "%s: packet is out-of-window, lowIndex=0x%x seqNumber=0x%x", __func__,
		          w->lowIndex, seqNumber);
		return FALSE;
	}

	while (w->upIndex < seqNumber)
	{
		rpacket = &w->window[w->upIndex % w->windowSize];
		rpacket->state = UDP2_PACKET_PENDING;
		w->upIndex++;
	}
	if (w->upIndex <= seqNumber)
		w->upIndex = seqNumber + 1;

	rpacket = &w->window[seqNumber % w->windowSize];
	rpacket->state = UDP2_PACKET_RECEIVED;
	rpacket->recvTimestamp = GetTickCount64();

	Udp3ReceiveWindow_updateAckable(w);

	if (!payload)
		return TRUE;

	if (channelSeqNumber < w->lowChannelWindow)
	{
		WLog_ERR(TAG,
		         "chunk 0x%.8x(channelSeqNumber16=0x%x) is out of channelWindow [0x%0.8x -> "
		         "0x%0.8x], retransmit ?",
		         channelSeqNumber, channelSeqNumber16, w->lowChannelWindow, w->upChannelWindow);
		return TRUE;
	}

	wStream* copy = Stream_Dup(w->udp, payload);
	if (!copy)
	{
		WLog_ERR(TAG, "error duplicating payload");
		return FALSE;
	}

	ChannelPacket* channelItem = &w->channelWindow[channelSeqNumber % w->windowSize];
	channelItem->s = copy;
	channelItem->recvSeqId = seqNumber;

	if (w->upChannelWindow < channelSeqNumber)
		w->upChannelWindow = channelSeqNumber;

	if (channelSeqNumber == w->lowChannelWindow)
	{
		for (; w->lowChannelWindow <= w->upChannelWindow; w->lowChannelWindow++)
		{
			ChannelPacket* channelItem = &w->channelWindow[w->lowChannelWindow % w->windowSize];
			if (!channelItem->s)
				break;

			UDP_DEBUG("pushing channelSeqId=0x%x recvseqId=0x%x", w->lowChannelWindow,
			          channelItem->recvSeqId);
			if (!rdpUdpTransport_pushAvailableData(w->udp, channelItem->s))
			{
				WLog_ERR(TAG, "unable to fill availableData buffer");
				return FALSE;
			}

			rdpUdpTransport_discardPacket(w->udp, channelItem->s);
			channelItem->s = NULL;
			channelItem->recvSeqId = 0;
		}

		if (w->upChannelWindow < w->lowChannelWindow)
			w->upChannelWindow = w->lowChannelWindow;
	}

	return TRUE;
}

BOOL Udp3ReceiveWindow_treatAoA(Udp3ReceiveWindow* w, UINT16 aoa16)
{
	UINT64 aoa = computeFullSeqNumber(w->lowIndex, aoa16);

	UDP_DEBUG("%s: aoa16=0x%x [0x%x - 0x%x]", __func__, aoa16, w->lowIndex, w->upIndex);
	if (aoa < w->lowIndex)
	{
		/*WLog_DBG(TAG, "%s: aoa(0x%x vs 0x%x) is out of sync with us taking lowIndex instead",
		   __func__, aoa, w->lowIndex);*/
		aoa = w->lowIndex;
	}
	else
	{
		w->lowIndex = aoa;
	}

	if (w->upIndex < w->lowIndex)
		w->upIndex = w->lowIndex;

	Udp3ReceiveWindow_updateAckable(w);
	return TRUE;
}

BOOL IntegrityManager_init(IntegrityManager* i, rdpUdpTransport* udp, size_t initialSz)
{
	i->reservedSize = initialSz;
	i->udp = udp;
	i->packets = calloc(initialSz, sizeof(*i->packets));
	if (!i->packets)
		return FALSE;
	return TRUE;
}

void IntegrityManager_Release(IntegrityManager* obj)
{
	for (int i = 0; i < obj->reservedSize; i++)
	{
		Udp3DataPacket* p = &obj->packets[i];
		if (p->used)
			rdpUdpTransport_discardPacket(obj->udp, p->payload);
	}
	free(obj->packets);
}

BOOL IntegrityManager_register(IntegrityManager* integrity, UINT16 seqId, UINT64 channelSeq,
                               wStream* payload)
{
	Udp3DataPacket* item = NULL;
	size_t i;

	/* find a free slot */
	for (i = 0; i < integrity->reservedSize; i++)
	{
		if (!integrity->packets[i].used)
		{
			item = &integrity->packets[i];
			break;
		}
	}

	if (!item)
	{
		/* no free slot, resize */
#define INTEGRITY_GROW_SZ 20
		size_t oldSize = integrity->reservedSize;
		item = realloc(integrity->packets, sizeof(*item) * (oldSize + INTEGRITY_GROW_SZ));
		if (!item)
			return FALSE;

		integrity->reservedSize = oldSize + INTEGRITY_GROW_SZ;
		integrity->packets = item;
		item += oldSize;
		memset(item, 0, sizeof(*item) * INTEGRITY_GROW_SZ);
	}

	item->used = TRUE;
	item->channelSeqId = channelSeq;
	item->seqId = seqId;
	item->payload = payload;
	return TRUE;
}

Udp3DataPacket* IntegrityManager_find(IntegrityManager* integrity, UINT16 seqId)
{
	Udp3DataPacket* item = integrity->packets;

	for (size_t i = 0; i < integrity->reservedSize; i++, item++)
		if (item->used && item->seqId == seqId)
			return item;

	return NULL;
}

BOOL IntegrityManager_dispose(IntegrityManager* integrity, UINT16 dataSeq)
{
	Udp3DataPacket* item = IntegrityManager_find(integrity, dataSeq);
	if (item)
	{
		item->used = FALSE;
		item->payload = NULL;
		rdpUdpTransport_discardPacket(integrity->udp, item->payload);
		return TRUE;
	}

	return FALSE;
}

BOOL Udp3SenderWindow_Init(Udp3SenderWindow* w, rdpUdpTransport* udp, size_t sz)
{
	w->windowSize = sz;
	w->channelSeqNumber = 0;
	w->pendingAoA = TRUE;
	w->lowIndex = w->upIndex = 0x64;
	w->range = calloc(w->windowSize, sizeof(*w->range));
	if (!w->range)
		goto error_range;

	if (!IntegrityManager_init(&w->integrity, udp, 20))
		goto out_integrity;

	return TRUE;

out_integrity:
	free(w->range);
error_range:
	return FALSE;
}

void Udp3SenderWindow_Release(Udp3SenderWindow* w)
{
	free(w->range);
	IntegrityManager_Release(&w->integrity);
}

UINT16 Udp3SenderWindow_reserveDataSeq(Udp3SenderWindow* w)
{
	return (w->upIndex++ & 0xffff);
}

UINT16 Udp3SenderWindow_reserveChannelSeq(Udp3SenderWindow* w)
{
	UINT64 ret = w->channelSeqNumber;
	w->channelSeqNumber++;

	return channelSeqNumberLinearToFullShort(ret) & 0xffff;
}

BOOL Udp3SenderWindow_Push(Udp3SenderWindow* w, UINT16 dataSeq, UINT16 channelSeq, wStream* payload)
{
	Udp3Node* node = &w->range[dataSeq % w->windowSize];

	node->state = UDP3_PACKET_PENDING;
	node->sendTimestamp = GetTickCount64();
	return IntegrityManager_register(&w->integrity, dataSeq, channelSeq, payload);
}

void Udp3SenderWindow_recomputeLowBound(Udp3SenderWindow* w)
{
	UINT64 newLowIndex;

	for (newLowIndex = w->lowIndex; newLowIndex != w->upIndex; newLowIndex++)
	{
		switch (w->range[newLowIndex % w->windowSize].state)
		{
			case UDP3_PACKET_RECEIVED:
				break;
			case UDP3_PACKET_LOST:
				/* if the packet is lost but we don't have any associated packet, it's a DUMMY
				 * packet sent by us, we don't care
				 */
				if (IntegrityManager_find(&w->integrity, (UINT16)(newLowIndex & 0xffff)) != NULL)
					goto outLoop;
				break;
			default:
				goto outLoop;
		}
	}

outLoop:
	if (newLowIndex != w->lowIndex)
	{
		UDP_DEBUG("%s: sender window updating lowIndex from 0x%0.8x to 0x%0.8x", __func__,
		          w->lowIndex, newLowIndex);
		w->pendingAoA = TRUE;
		w->lowIndex = newLowIndex;
	}
}

BOOL Udp3SenderWindow_treatAck(Udp3SenderWindow* w, Udp3Packet* p)
{
	UINT64 seqIndex;
	UINT64 now = GetTickCount64();
	UINT64 targetSeqNumber = computeFullSeqNumber(w->lowIndex, p->ackSeqNumber);

	UDP_DEBUG("Ack(base=0x%x down/up Index=[0x%x-0x%x])", targetSeqNumber, w->lowIndex, w->upIndex);
	if (targetSeqNumber < w->lowIndex || targetSeqNumber > w->upIndex)
	{
		UDP_DEBUG("%s: seqNumber 0x%x out of range (0x%x -> 0x%x)", __func__, targetSeqNumber,
		          w->lowIndex, w->upIndex);
		w->pendingAoA = TRUE;
		return FALSE;
	}

	for (seqIndex = targetSeqNumber; seqIndex >= w->lowIndex; seqIndex--)
	{
		Udp3Node* node = &w->range[seqIndex % w->windowSize];
		node->state = UDP3_PACKET_RECEIVED;
		node->ackTimestamp = now;

		if (!IntegrityManager_dispose(&w->integrity, seqIndex % w->windowSize))
		{
			// WLog_INFO(TAG, "%s: seq packet 0x%x not in integrity manager", __func__, seqIndex);
		}
	}

	Udp3SenderWindow_recomputeLowBound(w);
	return TRUE;
}

BOOL udp3_resend_packet(rdpUdpTransport* udp, Udp3Context* udp3, UINT64 seqId)
{
	Udp3SenderWindow* sendingWindow = &udp3->sendingWindow;
	Udp3DataPacket* packet = IntegrityManager_find(&sendingWindow->integrity, (seqId & 0xffff));
	if (!packet)
		return TRUE;

#ifdef WITH_DEBUG_UDP
	UINT16 origSeqId = packet->seqId;
#endif

	wStream* s = rdpUdpTransport_getPacket(udp);
	packet->seqId = Udp3SenderWindow_reserveDataSeq(&udp3->sendingWindow);

	UDP_DEBUG("resending channelDataSeq=0x%x origSeqId=0x%x newSeqId=0x%x", packet->channelSeqId,
	          origSeqId, packet->seqId);

	udp3_write_headers(s, udp3, UDPDATA_TYPE_DATA, packet->seqId, PIGGYBACK_NONE);

	Stream_Write(s, Stream_Buffer(packet->payload), Stream_GetPosition(packet->payload));
	Stream_SealLength(s);

	Udp3Node* newNode = &sendingWindow->range[packet->seqId % sendingWindow->windowSize];
	newNode->state = UDP3_PACKET_PENDING;
	newNode->sendTimestamp = GetTickCount64();

	udp3_finalize_packet(s);
	BOOL ret = rdpUdpTransport_bioSend(udp, s);
	rdpUdpTransport_discardPacket(udp, s);

	return ret;
}

BOOL Udp3SenderWindow_treatAckvec(rdpUdpTransport* udp, Udp3Context* udp3, Udp3Packet* p)
{
	BYTE i;
	UINT64 now = GetTickCount64();
	Udp3SenderWindow* w = &udp3->sendingWindow;
	UINT64 seq = computeFullSeqNumber(w->lowIndex, p->ackVecBaseSeqNum);

	UDP_DEBUG("AckVec(base=0x%x down/up Index=[0x%x-0x%x])", seq, w->lowIndex, w->upIndex);

	if (seq < w->lowIndex || w->upIndex < p->ackVecBaseSeqNum)
	{
		UDP_DEBUG("%s: seqNumber 0x%x out of range (0x%x -> 0x%x)", __func__, p->ackVecBaseSeqNum,
		          w->lowIndex, w->upIndex);
	}

	for (i = 0; i < p->codedAckVecSize; i++)
	{
		size_t j;
		Udp3Node* node;
		BOOL status, dropData;
		BYTE b = p->codedAckVector[i];

		if (b & 0x80)
		{
			/* ===== runlength mode ====== */
			status = (b & 0x40);
			size_t runLength = (b & 0x3f);

			for (j = 0; j < runLength; j++, seq++)
			{
				if (seq < w->lowIndex) /* lower than low limit */
					continue;

				if (seq > w->upIndex) /* upper than upper limit */
					break;

				node = &w->range[seq % w->windowSize];
				dropData = FALSE;
				switch (node->state)
				{
					case UDP3_PACKET_PENDING:
						node->state = status ? UDP3_PACKET_RECEIVED : UDP3_PACKET_LOST;
						dropData = status;
						if (status)
							node->ackTimestamp = now;
						break;
					case UDP3_PACKET_RECEIVED:
						if (!status)
							WLog_ERR(TAG, "Ignoring lost status for already acked packet 0x%x",
							         seq);
						break;
					case UDP3_PACKET_LOST:
						if (status)
						{
							node->state = UDP3_PACKET_RECEIVED;
							node->ackTimestamp = now;
						}
						dropData = status;
						break;
				}

				if (dropData && !IntegrityManager_dispose(&w->integrity, seq % w->windowSize))
				{
					UDP_DEBUG("%s: seq packet 0x%x not in integrity manager", __func__, seq);
				}
			}
		}
		else
		{
			/* bitmap mode */
			int j;
			BYTE mask = 1;
			for (j = 0; j < 7; j++, mask <<= 1, seq++)
			{
				status = (b & mask);
				node = &w->range[seq % w->windowSize];
				switch (node->state)
				{
					case UDP3_PACKET_PENDING:
						node->state = status ? UDP3_PACKET_RECEIVED : UDP3_PACKET_LOST;
						dropData = status;
						if (status)
							node->ackTimestamp = now;
						break;
					case UDP3_PACKET_RECEIVED:
						if (!status)
							WLog_DBG(TAG, "Ignoring lost status for already acked packet 0x%x",
							         seq);
						break;
					case UDP3_PACKET_LOST:
						if (status)
						{
							node->state = UDP3_PACKET_RECEIVED;
							node->ackTimestamp = now;
						}
						dropData = status;
						break;
				}

				if (dropData && !IntegrityManager_dispose(&w->integrity, seq % w->windowSize))
				{
					UDP_DEBUG("%s: seq packet 0x%x not in integrity manager", __func__, seq);
				}
			}
		}
	} /* for */

	Udp3SenderWindow_recomputeLowBound(w);

	for (UINT64 j = w->lowIndex; j != w->upIndex; j++)
	{
		Udp3Node* packet = &w->range[j % w->windowSize];
		switch (packet->state)
		{
			case UDP3_PACKET_LOST:
				break;
			default:
				continue;
		}

		if (!udp3_resend_packet(udp, udp3, j))
		{
			WLog_ERR(TAG, "error resending packet original seqId=0x%x", j);
		}
	}
	return TRUE;
}

BOOL udp3_init(rdpUdpTransport* udp, Udp3Context* udp3, BOOL server)
{
	memset(udp3, 0, sizeof(*udp3));
	udp3->pendingDelayInfo = TRUE;
	udp3->pendingOverheadSize = TRUE;
	udp3->logWindowSize = 12;
	udp3->localMaxDelayedAcks = 1;
	udp3->localDelayedAckTimeout = 20;
	udp3->timebase = GetTickCount64();
	udp3->nextLostCheck = udp3->timebase + 300;
	udp3->firstAckVec = TRUE;
	udp3->remoteMaxDelayedAcks = 8;
	udp3->remoteDelayedAckTimeout = 100;

	if (!Udp3SenderWindow_Init(&udp3->sendingWindow, udp, (1 << udp3->logWindowSize)))
		return FALSE;

	udp3->recvWindow = Udp3ReceiveWindow_New(udp, (1 << udp3->logWindowSize));
	if (!udp3->recvWindow)
	{
		// TODO: free udp3->sendingWindow
		return FALSE;
	}
	return TRUE;
}

void udp3_destroy(Udp3Context* udp3)
{
	Udp3ReceiveWindow_Destroy(&udp3->recvWindow);
	Udp3SenderWindow_Release(&udp3->sendingWindow);
}

BOOL doSendFastAckVec(Udp3Context* udp3)
{
	Udp3ReceiveWindow* w = udp3->recvWindow;

	/* we want at least the lowest packet lost, at least 7 non-acked, and the missing
	 * first channel data packet
	 */
	if (w->lowIndex >= w->upIndex)
		return FALSE;

	if (w->window[w->lowIndex % w->windowSize].state != UDP2_PACKET_PENDING)
		return FALSE;

	if (w->upIndex - w->lowIndex < 7)
		return FALSE;

	if (w->lowChannelWindow == w->upChannelWindow)
		return FALSE;

	return TRUE;
}

BOOL udp3_low_level_reader(rdpUdpTransport* udp, Udp3Context* udp3, wStream* s)
{
	Udp3Packet packet;

	Stream_SetPosition(s, 0);
	if (!udp3_parse_packet(s, &packet))
	{
		WLog_ERR(TAG, "error while parsing packet");
		winpr_HexDump(TAG, WLOG_DEBUG, Stream_Buffer(s), Stream_Length(s));
		return FALSE;
	}

	if (packet.flags & RDPUDP2_AOA)
	{
		Udp3ReceiveWindow_treatAoA(udp3->recvWindow, packet.ackOfAcksSeqNum);
	}

	if (packet.flags & RDPUDP2_DELAYACKINFO)
	{
		do
		{
			if (packet.maxDelayedAcks < 1 || packet.maxDelayedAcks > 15)
				break;

			if (packet.delayedAckTimeoutInMs == 0)
				packet.delayedAckTimeoutInMs = 10;

			udp3->remoteMaxDelayedAcks = packet.maxDelayedAcks;
			udp3->remoteDelayedAckTimeout = packet.delayedAckTimeoutInMs;
		} while (FALSE);
	}

	if (packet.flags & RDPUDP2_ACK)
	{
		if (!Udp3SenderWindow_treatAck(&udp3->sendingWindow, &packet))
		{
			// WLog_ERR(TAG, "error treating ACK");
		}
	}
	else if (packet.flags & RDPUDP2_ACKVEC)
	{
		if (!Udp3SenderWindow_treatAckvec(udp, udp3, &packet))
		{
			WLog_ERR(TAG, "error treating ACKVEC");
		}
	}

	if (packet.flags & RDPUDP2_DATA)
	{
		wStream staticDataPayload;
		wStream* dataPayload = &staticDataPayload;

		if (packet.isDummy)
			dataPayload = NULL;
		else
			Stream_StaticInit(&staticDataPayload, packet.data, packet.dataSz);

		Udp3ReceiveWindow_recvDataPacket(udp3->recvWindow, packet.dataSeqNum, packet.channelSeqNum,
		                                 dataPayload);
	}

	BOOL ret = TRUE;
	UINT64 nacks = Udp3ReceiveWindow_nacks(udp3->recvWindow);
	BOOL needAck = (nacks >= udp3->remoteMaxDelayedAcks);
	if (needAck)
	{
		UDP_DEBUG("acking some packets(nacks=%d)", nacks);
		ret = FALSE;
		wStream* s2 = rdpUdpTransport_getPacket(udp);
		if (!s2)
		{
			WLog_ERR(TAG, "unable to retrieve a packet");
			goto out;
		}

		udp3_write_headers(s2, udp3, UDPDATA_TYPE_NONE, 0, PIGGYBACK_DATA);
		udp3_finalize_packet(s2);
		Stream_SealLength(s2);
		ret = rdpUdpTransport_bioSend(udp, s2);
		rdpUdpTransport_discardPacket(udp, s2);
	}

	if (doSendFastAckVec(udp3))
	{
		UDP_DEBUG("doing a ACKVEC");
		ret = FALSE;
		wStream* s2 = rdpUdpTransport_getPacket(udp);
		if (!s2)
		{
			WLog_ERR(TAG, "unable to retrieve a packet");
			goto out;
		}

		udp3_write_headers(s2, udp3, UDPDATA_TYPE_NONE, 0, PIGGYBACK_TIMER);
		udp3_finalize_packet(s2);
		Stream_SealLength(s2);
		ret = rdpUdpTransport_bioSend(udp, s2);
		rdpUdpTransport_discardPacket(udp, s2);
	}

out:
	return ret;
}

static UINT16 scanAckFlags(Udp3Context* udp3, PiggyBackMode piggyBack, UINT64 now)
{
	Udp3ReceiveWindow* recvW = udp3->recvWindow;

	if (piggyBack == PIGGYBACK_NONE)
		return 0;

	if (recvW->lowIndex != recvW->upIndex)
	{
		/* the spec says that ACKVEC _should_ start with a non received packet */
		if (recvW->window[recvW->lowIndex % recvW->windowSize].state == UDP2_PACKET_PENDING)
		{
			/* don't send ACKVEC if we're in data piggy back mode */
			return (piggyBack == PIGGYBACK_TIMER) ? RDPUDP2_ACKVEC : 0;
		}

		return RDPUDP2_ACK;
	}

	if (udp3->recvWindow->lastAcks + 100 < now)
		return RDPUDP2_ACK;

	return 0;
}

static void pushAckVec(Udp3Context* udp3, wStream* s)
{
	Udp3ReceiveWindow* recvW = udp3->recvWindow;

	Stream_Write_UINT16(s, recvW->lowIndex & 0xffff);
	wStream nitemsStream = *s;
	Stream_Seek(s, 1); /* codedAckVecSize | TimeStampPresent */

	BOOL addTimestamp = (!udp3->firstAckVec /* && recvW->ackableIndex >= recvW->lowIndex*/);
	if (addTimestamp)
	{
		Stream_Seek(s, 3);           /* TimeStamp */
		Stream_Write_UINT8(s, 0xff); /* SendAckTimeGapInMs, 0xff = invalid */
	}

	UINT64 i = recvW->lowIndex;
	BYTE nAckItems = 0;

	while (i < recvW->upIndex && nAckItems < 127)
	{
		BOOL lastValue = (recvW->window[i % recvW->windowSize].state == UDP2_PACKET_RECEIVED);
		BYTE currentBitMask = lastValue;
		BYTE rleLen = 1;
		BOOL rleMode = TRUE;

		/* scan for the next 6 or 62 packets depending if we managed to stay in rleMode */
		int j;
		for (j = 1; j < 63 && i + j < recvW->upIndex; j++)
		{
			int idx = i + j;
			ReceivedPacket* recvP = &recvW->window[idx % recvW->windowSize];
			BOOL currentVal = (recvP->state == UDP2_PACKET_RECEIVED);

			currentBitMask |= (currentVal << j);
			if (rleMode)
			{
				if (currentVal == lastValue)
				{
					rleLen++;
					continue;
				}

				if (j < 6)
				{
					rleMode = FALSE;
					continue;
				}
				break;
			}
			else
			{
				if (j == 6)
					break;
			}
		}

		if (rleMode)
		{
			BYTE b = 0x80 + rleLen;
			if (lastValue)
				b |= 0x40;
			Stream_Write_UINT8(s, b);
			UDP_DEBUG(" * rle(%d) len=%d [0x%x -> 0x%x]", lastValue, rleLen, i, i + rleLen);
			i += rleLen;
		}
		else
		{
			UDP_DEBUG(" * bitmap=0x%x [0x%x -> 0x%x]", currentBitMask, i, i + 6);
			Stream_Write_UINT8(s, currentBitMask);
			i += 7;
		}

		nAckItems++;
	}

	BYTE nAckItemsflags = nAckItems;
	if (addTimestamp)
		nAckItemsflags |= 0x80;

	Stream_Write_UINT8(&nitemsStream, nAckItemsflags);
	if (addTimestamp)
	{
		Stream_Write_UINT24(&nitemsStream,
		                    recvW->window[recvW->ackableIndex % recvW->windowSize].recvTimestamp);
	}

	if (udp3->firstAckVec)
		udp3->firstAckVec = FALSE;
}

static void pushAck(Udp3Context* udp3, wStream* s, UINT64 now)
{
	Udp3ReceiveWindow* recvW = udp3->recvWindow;

	UINT64 ackTimeBase = (now - udp3->timebase);

	UINT64 nacks64 = Udp3ReceiveWindow_nacks(recvW);
	BYTE nacks = MIN(nacks64, 16);
	if (nacks)
	{
		UINT64 acked = (recvW->lowIndex + nacks - 1);
		UINT16 acked16 = acked & 0xffff;
		UDP_DEBUG("%s: range=[0x%0.6x -- 0x%0.6x] ackable=0x%0.6x acking16=0x%0.4x (%d acks)",
		          __func__, recvW->lowIndex, recvW->upIndex, recvW->ackableIndex, acked16, nacks);

		Stream_Write_UINT16(s, acked16);
		Stream_Write_UINT24(s, ackTimeBase * 250); /* in units of 4us */

		UINT64 sendAckTimeGap = (now - recvW->window[acked % recvW->windowSize].recvTimestamp);
		Stream_Write_UINT8(s, MIN(sendAckTimeGap, 255));
		Stream_Write_UINT8(s, nacks - 1);

		for (BYTE i = 0; i < nacks - 1; i++)
		{
			Stream_Write_UINT8(s, 0); // TODO: real computations
		}
	}
	else
	{
		Stream_Write_UINT16(s, recvW->ackableIndex & 0xffff);
		Stream_Write_UINT24(s, ackTimeBase * 250); /* in units of 4us */
		Stream_Write_UINT8(s, 0);                  /* sendAckTimeGap */
		Stream_Write_UINT8(s, 0);                  /* nacks */
	}

	recvW->lastAcks = now;
	recvW->lowIndex += nacks;
}

static void udp3_write_headers(wStream* s, Udp3Context* udp3, UdpDataType dataType, UINT16 dataSeq,
                               PiggyBackMode piggyBack)
{
	UINT16 flags = 0x0000;
	wStream startStream;
	UINT64 now = GetTickCount64();
	Udp3SenderWindow* sendingW = &udp3->sendingWindow;
	Udp3ReceiveWindow* recvW = udp3->recvWindow;
	BYTE packetType = (dataType == UDPDATA_TYPE_DATA) ? 0 : 8;

	/* PacketPrefixByte */
	Stream_Write_UINT8(s, (7 << 5) | (packetType << 1));

	startStream = *s;
	Stream_Seek(s, 2); /* skip header flags */

	if (dataType)
		flags |= RDPUDP2_DATA;

	flags |= scanAckFlags(udp3, piggyBack, now);

	if (flags & RDPUDP2_ACK)
	{
		pushAck(udp3, s, now);
	}

	if (udp3->pendingOverheadSize)
	{
		flags |= RDPUDP2_OVERHEADSIZE;
		Stream_Write_UINT8(s, 29); // TODO: hardcoded for now
		udp3->pendingOverheadSize = FALSE;
	}

	if (udp3->pendingDelayInfo)
	{
		flags |= RDPUDP2_DELAYACKINFO;
		Stream_Write_UINT8(s, udp3->localMaxDelayedAcks);     /* maxDelayedAcks */
		Stream_Write_UINT16(s, udp3->localDelayedAckTimeout); /* delayedAckTimeout */
		udp3->pendingDelayInfo = FALSE;
	}

	if (sendingW->pendingAoA)
	{
		flags |= RDPUDP2_AOA;
		Stream_Write_UINT16(s, (sendingW->lowIndex & 0xffff));

		sendingW->pendingAoA = FALSE;
		sendingW->lastAoA = now;
	}

	if (dataType != UDPDATA_TYPE_NONE)
		Stream_Write_UINT16(s, dataSeq);

	if (flags & RDPUDP2_ACKVEC)
	{
		UDP_DEBUG("adding ACKVEC");
		pushAckVec(udp3, s);
		recvW->lastAcks = now;
	}

	Stream_Write_UINT16(&startStream, flags | (udp3->logWindowSize << 12));
}

BOOL udp3_low_level_writer(rdpUdpTransport* udp, Udp3Context* udp3, wStream* s)
{
	BOOL ret = TRUE;

	wStream* packet = rdpUdpTransport_getPacket(udp);
	if (!packet)
		return FALSE;

	Stream_SetPosition(s, 0);
	while (Stream_GetRemainingLength(s))
	{
		UINT16 dataSeq = Udp3SenderWindow_reserveDataSeq(&udp3->sendingWindow);

		udp3_write_headers(packet, udp3, UDPDATA_TYPE_DATA, dataSeq, PIGGYBACK_DATA);

		size_t possiblePayload = Stream_GetRemainingCapacity(packet) - 2;
		size_t toTake = Stream_GetRemainingLength(s);
		if (toTake > possiblePayload)
			toTake = possiblePayload;

		/* === build payload === */
		wStream* dataPayload = rdpUdpTransport_getPacket(udp);
		if (!dataPayload)
		{
			WLog_ERR(TAG, "unable to create payload packet");
			return FALSE;
		}

		UINT16 channelSeq = Udp3SenderWindow_reserveChannelSeq(&udp3->sendingWindow);
		Stream_Write_UINT16(dataPayload, channelSeq);
		Stream_Write(dataPayload, Stream_Pointer(s), toTake);
		Stream_Seek(s, toTake);

		if (!Udp3SenderWindow_Push(&udp3->sendingWindow, dataSeq, channelSeq, dataPayload))
		{
			WLog_ERR(TAG, "unable to register payload against integrity manager");
			Stream_Release(dataPayload);
			return FALSE;
		}

		Stream_Write(packet, Stream_Buffer(dataPayload), Stream_GetPosition(dataPayload));
		Stream_SealLength(packet);
		udp3_finalize_packet(packet);
		if (!rdpUdpTransport_bioSend(udp, packet))
			goto out;

		Stream_SetPosition(packet, 0);
	}

out:
	rdpUdpTransport_discardPacket(udp, packet);
	return ret;
}

#define LOST_TIMEOUT 200

BOOL udp3_update_lost_packets(rdpUdpTransport* udp, Udp3Context* udp3, UINT64 now)
{
	Udp3SenderWindow* sendingWindow = &udp3->sendingWindow;

	UINT64 upBound = sendingWindow->upIndex;
	for (UINT64 i = sendingWindow->lowIndex; i < upBound; i++)
	{
		Udp3Node* node = &sendingWindow->range[i % sendingWindow->windowSize];
		if (node->state == UDP3_PACKET_PENDING && now > node->sendTimestamp + LOST_TIMEOUT)
		{
			UDP_DEBUG("packet 0x%x is lost", i);
			node->state = UDP3_PACKET_LOST;

			if (!udp3_resend_packet(udp, udp3, i))
			{
				WLog_ERR(TAG, "error resending packet seqId=0x%x", i);
				return FALSE;
			}
		}
	}

	Udp3SenderWindow_recomputeLowBound(sendingWindow);
	return TRUE;
}

BOOL udp3_low_level_timer(rdpUdpTransport* udp, Udp3Context* udp3)
{
	BOOL ret = FALSE;

	UDP_DEBUG("%s() low=0x%x up=0x%x ackable=0x%x", __FUNCTION__, udp3->recvWindow->lowIndex,
	          udp3->recvWindow->upIndex, udp3->recvWindow->ackableIndex);
	wStream* s = rdpUdpTransport_getPacket(udp);
	if (!s)
		return FALSE;

	/* let's force delayInfo and AoA for timer packet */
	UINT64 now = GetTickCount64();
	if (udp3->sendingWindow.lastAoA + 200 < now)
		udp3->sendingWindow.pendingAoA = TRUE;
	udp3->pendingDelayInfo = TRUE;

	UINT16 dataSeqNumber = Udp3SenderWindow_reserveDataSeq(&udp3->sendingWindow);
	UdpDataType dtype = UDPDATA_TYPE_DUMMY; // UDPDATA_TYPE_NONE;

	udp3_write_headers(s, udp3, dtype, dataSeqNumber, PIGGYBACK_TIMER);
	udp3_finalize_packet(s);
	Stream_SealLength(s);
	ret = rdpUdpTransport_bioSend(udp, s);
	rdpUdpTransport_discardPacket(udp, s);

	if (now > udp3->nextLostCheck)
	{
		udp3_update_lost_packets(udp, udp3, now);
		udp3->nextLostCheck = now + 500;
	}

	return ret;
}

static BOOL treat_PacketPrefixByte(wStream* s, BOOL* isDummy)
{
	BYTE packetPrefixByte;
	BYTE* buf = Stream_Buffer(s);
	BYTE shortLen, packetTypeIndex;

	if (Stream_GetRemainingLength(s) < 7)
	{
		return FALSE;
	}

	packetPrefixByte = buf[7];
	buf[7] = buf[0];

	packetTypeIndex = (packetPrefixByte >> 1) & 0x0f;
	if (packetTypeIndex != 0 && packetTypeIndex != 8)
	{
		return FALSE;
	}
	*isDummy = (packetTypeIndex == 8);

	Stream_Seek(s, 1);
	shortLen = (packetPrefixByte >> 5) & 0x7;
	if (shortLen != 7)
		Stream_SetLength(s, 1 + shortLen);
	return TRUE;
}

static void flagsString(UINT16 flags, char* buffer)
{
	int i, match = 0;
	UINT16 mask = 0x01;
	char* targetBuf = buffer;
	const char* udp3FlagNames[] = { "ACK",          NULL /*0x02*/, "DATA",
		                            "ACKVEC",       "AOA",         NULL /*0x20*/,
		                            "OVERHEADSIZE", NULL /*0x80*/, "DELAYACKINFO" };

	*targetBuf = '\0';
	for (i = 0; i < ARRAYSIZE(udp3FlagNames); i++, mask <<= 1)
	{
		if (!udp3FlagNames[i] || ((flags & mask) == 0))
			continue;

		if (match)
		{
			*targetBuf = ',';
			targetBuf++;
		}
		strcpy(targetBuf, udp3FlagNames[i]);
		targetBuf += strlen(udp3FlagNames[i]);
		match++;
	}
}

void udp3_print_packet(Udp3Packet* p)
{
	char flagsBuffer[2048];

	flagsString(p->flags, flagsBuffer);
	WLog_DBG(TAG, "==============================");
	WLog_DBG(TAG, "flags=0x%x(%s) logWindowSize=%d", p->flags, flagsBuffer, p->logWindowSize);
	if (p->flags & RDPUDP2_ACK)
	{
		WLog_DBG(TAG,
		         "ACK: seqNum=0x%x receivedTs=0x%x sendAckTimeGap=%d numDelayedAcks=%d "
		         "delayAckTimeScale=%d acks=",
		         p->ackSeqNumber, p->receivedTs, p->sendAckTimeGap, p->numDelayedAcks,
		         p->delayAckTimeScale);
		winpr_HexDump(TAG, WLOG_DEBUG, (const BYTE*)p->delayAckTimeAdditions, p->numDelayedAcks);
	}
	if (p->flags & RDPUDP2_OVERHEADSIZE)
		WLog_DBG(TAG, "overheadSize=%d", p->overheadSize);

	if (p->flags & RDPUDP2_DELAYACKINFO)
		WLog_DBG(TAG, "DELAYACKINFO: maxDelayedAcks=%d delayedAckTimeoutInMs=%d", p->maxDelayedAcks,
		         p->delayedAckTimeoutInMs);

	if (p->flags & RDPUDP2_AOA)
		WLog_DBG(TAG, "AOA: ackOfAcksSeqNum=0x%x", p->ackOfAcksSeqNum);

	if (p->flags & RDPUDP2_ACKVEC)
	{
		int i;
		UINT16 extra = 0;
		char timestampBuf[100] = { 0 };
		if (p->timeStampPresent)
		{
			snprintf(timestampBuf, sizeof(timestampBuf), "timestamp=0x%x sendAckTimeGap=%d ",
			         p->timestamp, p->sendAckVecTimeGap);
		}
		WLog_DBG(TAG, "ACKVEC: baseSeqNum=0x%x codedAckVecSize=%d %scodedAckVector=",
		         p->ackVecBaseSeqNum, p->codedAckVecSize, timestampBuf);
		winpr_HexDump(TAG, WLOG_DEBUG, (const BYTE*)p->codedAckVector, p->codedAckVecSize);

		for (i = 0; i < p->codedAckVecSize; i++)
		{
			if (p->codedAckVector[i] & 0x80)
			{
				/* run length mode */
				BOOL state = p->codedAckVector[i] & 0x40;
				UINT16 runLength = (p->codedAckVector[i] & ~0xc0);
				WLog_DBG(TAG, "  RunLength: 0x%x -> 0x%x: %s (len=%d)", p->ackVecBaseSeqNum + extra,
				         p->ackVecBaseSeqNum + extra + runLength, state ? "received" : "lost",
				         runLength);
				extra += runLength;
			}
			else
			{
				/* bitmap mode */
				int j;
				char bitmapStr[200] = { 0 }; /* 1 + 6*7*/
				BYTE b = p->codedAckVector[i];
				BYTE mask = 1;
				UINT16 seqNumber = p->ackVecBaseSeqNum + extra;
				for (j = 0; j < 7;
				     j++, mask <<= 1, seqNumber = seqNext(seqNumber, (1 << p->logWindowSize)))
				{
					char bitStr[100];
					snprintf(bitStr, sizeof(bitStr), "%s%.4x ", ((b & mask) ? "" : "!"), seqNumber);
					strcat(bitmapStr, bitStr);
				}
				WLog_DBG(TAG, "  bitmap: %s", bitmapStr);
				extra += 7;
			}
		}
	}

	if (p->flags & RDPUDP2_DATA)
	{
		if (p->isDummy)
		{
			WLog_DBG(TAG, "DATA: dummy dataSeqNum=0x%x", p->dataSeqNum);
		}
		else
		{
			WLog_DBG(TAG, "DATA: dataSeqNum=0x%x channelSeqNum=0x%x", p->dataSeqNum,
			         p->channelSeqNum);
			// winpr_HexDump(TAG, WLOG_DEBUG, p->data, p->dataSz);
		}
	}
	WLog_DBG(TAG, "==============================");
}

BOOL udp3_parse_packet(wStream* s, Udp3Packet* p)
{
	UINT16 flags, mask;

	if (!treat_PacketPrefixByte(s, &p->isDummy))
	{
		WLog_ERR(TAG, "%s: invalid packet prefix", __func__);
		return FALSE;
	}

	Stream_Read_UINT16(s, flags);

	p->flags = (flags & 0x0fff);
	p->logWindowSize = (flags >> 12) & 0xf;
	if (!p->flags)
	{
		/* In a packet, one or more of the flags MUST be specified in the Header field. */
		WLog_ERR(TAG, "%s: empty flags", __func__);
		return FALSE;
	}

	mask = (RDPUDP2_ACK | RDPUDP2_ACKVEC);
	if ((p->flags & mask) == mask)
	{
		/* The ACK flag and the ACKVEC flag are mutually exclusive and both MUST NOT be set to 1 in
		 *  the	Flags field of an RDP-UDP2 packet header. */
		WLog_ERR(TAG, "%s: ACK and ACKVEC are exclusive", __func__);
		return FALSE;
	}

	if (p->flags & RDPUDP2_ACK)
	{
		BYTE bc;

		if (Stream_GetRemainingLength(s) < 7)
		{
			WLog_ERR(TAG, "%s: invalid ACK field (remaining=%d)", __func__,
			         Stream_GetRemainingLength(s));
			return FALSE;
		}

		Stream_Read_UINT16(s, p->ackSeqNumber);
		Stream_Read_UINT24(s, &p->receivedTs);
		Stream_Read_UINT8(s, p->sendAckTimeGap);
		Stream_Read_UINT8(s, bc);
		p->numDelayedAcks = (bc & 0xf);
		p->delayAckTimeScale = (bc >> 4) & 0xff;

		if (Stream_GetRemainingLength(s) < p->numDelayedAcks)
		{
			WLog_ERR(TAG, "%s: invalid ACK field for delayed", __func__);
			return FALSE;
		}
		Stream_Read(s, p->delayAckTimeAdditions, p->numDelayedAcks);
	}

	if (p->flags & RDPUDP2_OVERHEADSIZE)
	{
		if (Stream_GetRemainingLength(s) < 1)
		{
			WLog_ERR(TAG, "%s: invalid OVERHEADSIZE field", __func__);
			return FALSE;
		}

		Stream_Read_UINT8(s, p->overheadSize);
	}

	if (p->flags & RDPUDP2_DELAYACKINFO)
	{
		if (Stream_GetRemainingLength(s) < 3)
		{
			WLog_ERR(TAG, "%s: invalid DELAYACKINFO field", __func__);
			return FALSE;
		}

		Stream_Read_UINT8(s, p->maxDelayedAcks);
		Stream_Read_UINT16(s, p->delayedAckTimeoutInMs);
	}

	if (p->flags & RDPUDP2_AOA)
	{
		if (Stream_GetRemainingLength(s) < 2)
		{
			WLog_ERR(TAG, "%s: invalid AOA field", __func__);
			return FALSE;
		}

		Stream_Read_UINT16(s, p->ackOfAcksSeqNum);
	}

	if (p->flags & RDPUDP2_DATA)
	{
		if (Stream_GetRemainingLength(s) < 2)
		{
			WLog_ERR(TAG, "%s: invalid DATA field", __func__);
			return FALSE;
		}

		Stream_Read_UINT16(s, p->dataSeqNum);
	}

	if (p->flags & RDPUDP2_ACKVEC)
	{
		BYTE codedAckPlusA;
		if (Stream_GetRemainingLength(s) < 3)
		{
			WLog_ERR(TAG, "%s: invalid ACKVEC field", __func__);
			return FALSE;
		}

		Stream_Read_UINT16(s, p->ackVecBaseSeqNum);
		Stream_Read_UINT8(s, codedAckPlusA);
		p->codedAckVecSize = (codedAckPlusA & 0x7f);
		p->timeStampPresent = (codedAckPlusA & 0x80) > 0;

		if (p->timeStampPresent)
		{
			if (Stream_GetRemainingLength(s) < 4)
			{
				WLog_ERR(TAG, "%s: invalid timestamp in ACKVEC field", __func__);
				return FALSE;
			}
			Stream_Read_UINT24(s, &p->timestamp);
			Stream_Read_UINT8(s, p->sendAckVecTimeGap);
		}

		if (Stream_GetRemainingLength(s) < p->codedAckVecSize)
		{
			WLog_ERR(TAG, "%s: invalid ACKVEC field", __func__);
			return FALSE;
		}
		Stream_Read(s, p->codedAckVector, p->codedAckVecSize);
	}

	if (p->flags & RDPUDP2_DATA)
	{
		if (!p->isDummy)
		{
			if (Stream_GetRemainingLength(s) < 2)
			{
				WLog_ERR(TAG, "%s: invalid DATA payload field", __func__);
				return FALSE;
			}

			Stream_Read_UINT16(s, p->channelSeqNum);
			p->data = Stream_Pointer(s);
			p->dataSz = Stream_GetRemainingLength(s);
		}
		else
		{
			p->channelSeqNum = 0;
			p->data = NULL;
			p->dataSz = 0;
		}
	}

#ifdef WITH_DEBUG_UDP
	// udp3_print_packet(p);
#endif
	return TRUE;
}
