/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * UDP version 3 as in MS-RDPEUDP2
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
#ifndef LIBFREERDP_CORE_UDP3_H_
#define LIBFREERDP_CORE_UDP3_H_

#include <winpr/wtypes.h>
#include <winpr/stream.h>
#include <freerdp/utils/ringbuffer.h>

typedef struct rdpUdpTransport rdpUdpTransport;

enum
{
	RDPUDP2_ACK = 0x001,
	RDPUDP2_DATA = 0x004,
	RDPUDP2_ACKVEC = 0x008,
	RDPUDP2_AOA = 0x010,
	RDPUDP2_OVERHEADSIZE = 0x040,
	RDPUDP2_DELAYACKINFO = 0x100,
};

typedef struct
{
	/* Packet headers */
	UINT16 flags;
	BYTE logWindowSize;
	BOOL isDummy;

	/* Acknowledgement Payload */
	UINT16 ackSeqNumber;
	UINT32 receivedTs;
	BYTE sendAckTimeGap;
	BYTE numDelayedAcks;
	BYTE delayAckTimeScale;
	UINT16 delayAckTimeAdditions[16];

	/* OverheadSize Payload */
	BYTE overheadSize;

	/* DelayAckInfo Payload */
	BYTE maxDelayedAcks;
	UINT16 delayedAckTimeoutInMs;

	/* AckOfAcks Payload */
	UINT16 ackOfAcksSeqNum;

	/* DataHeader Payload */
	UINT16 dataSeqNum;

	/* Acknowledgement Vector Payload */
	UINT16 ackVecBaseSeqNum;
	BYTE codedAckVecSize;
	BOOL timeStampPresent;
	UINT32 timestamp;
	BYTE sendAckVecTimeGap;
	BYTE codedAckVector[128];

	/* DataBody Payload */
	UINT16 channelSeqNum;
	BYTE* data;
	UINT16 dataSz;
} Udp3Packet;

typedef enum
{
	UDP3_PACKET_PENDING,
	UDP3_PACKET_RECEIVED,
	UDP3_PACKET_LOST
} Udp3NodeState;

typedef struct
{
	UINT64 sendTimestamp;
	UINT64 ackTimestamp;
	Udp3NodeState state;
} Udp3Node;

typedef struct
{
	BOOL used;
	UINT64 channelSeqId;
	UINT16 seqId;
	wStream* payload;
} Udp3DataPacket;

typedef struct
{
	size_t reservedSize;
	Udp3DataPacket* packets;
	rdpUdpTransport* udp;
} IntegrityManager;

typedef struct
{
	size_t windowSize;
	size_t rangeAllocated;
	Udp3Node* range;
	size_t lowIndex;
	size_t upIndex;

	UINT16 channelSeqNumber;
	IntegrityManager integrity;

	BOOL pendingAoA;
	UINT64 lastAoA;
} Udp3SenderWindow;

BOOL Udp3SenderWindow_Init(Udp3SenderWindow* w, rdpUdpTransport* udp, size_t sz);
BOOL Udp3SenderWindow_Resize(Udp3SenderWindow* w, size_t sz);
size_t Udp3SenderWindow_DetectLost(Udp3SenderWindow* w, UINT32 timeout);
BOOL Udp3SenderWindow_TreatAckRange(Udp3SenderWindow* w, UINT32 seqNumber, UINT32* ackOfAck);

typedef enum
{
	UDP2_PACKET_RECEIVED,
	UDP2_PACKET_PENDING
} ReceivedState;

typedef struct
{
	ReceivedState state;
	UINT64 recvTimestamp;
} ReceivedPacket;

typedef struct {
	wStream* s;
	UINT64 recvSeqId;
} ChannelPacket;

typedef struct
{
	rdpUdpTransport* udp;
	size_t windowSize;
	ReceivedPacket* window;
	UINT64 lowIndex, upIndex;
	UINT64 ackableIndex;

	ChannelPacket* channelWindow;
	UINT64 lowChannelWindow, upChannelWindow;
	UINT64 lastAcks;
} Udp3ReceiveWindow;

Udp3ReceiveWindow* Udp3ReceiveWindow_New(rdpUdpTransport* udp, size_t sz);
BOOL Udp3ReceiveWindow_recvDataPacket(Udp3ReceiveWindow* w, UINT16 seqNumber,
                                      UINT16 channelSeqNumber, wStream* payload);
BOOL Udp3ReceiveWindow_treatAoA(Udp3ReceiveWindow* w, UINT16 aoa);

typedef struct
{
	BOOL pendingDelayInfo;
	BOOL pendingOverheadSize;
	BOOL firstReceived;
	size_t logWindowSize;

	UINT16 localDelayedAckTimeout;
	BYTE localMaxDelayedAcks;

	UINT16 remoteDelayedAckTimeout;
	BYTE remoteMaxDelayedAcks;

	UINT64 timebase;
	Udp3SenderWindow sendingWindow;
	Udp3ReceiveWindow* recvWindow;
	UINT64 nextLostCheck;
	BOOL firstAckVec;
} Udp3Context;

BOOL udp3_init(rdpUdpTransport* udp, Udp3Context* udp3, BOOL server);
void udp3_destroy(Udp3Context* udp3);
BOOL udp3_low_level_reader(rdpUdpTransport* udp, Udp3Context* udp3, wStream* s);
BOOL udp3_low_level_writer(rdpUdpTransport* udp, Udp3Context* udp3, wStream* s);
BOOL udp3_low_level_need_timer(rdpUdpTransport* udp, Udp3Context* udp3);
BOOL udp3_low_level_timer(rdpUdpTransport* udp, Udp3Context* udp3);

FREERDP_LOCAL BOOL udp3_parse_packet(wStream* s, Udp3Packet* p);

FREERDP_LOCAL UINT64 computeFullSeqNumber(UINT64 refNumber, UINT16 seqNumber);

#endif /* LIBFREERDP_CORE_UDP3_H_ */
