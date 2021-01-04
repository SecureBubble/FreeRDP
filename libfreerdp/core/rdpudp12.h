/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * UDP version 1 and 2
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
#ifndef LIBFREERDP_CORE_RDPUDP12_H_
#define LIBFREERDP_CORE_RDPUDP12_H_

#include <winpr/wtypes.h>
#include <winpr/stream.h>

typedef struct rdpUdpTransport rdpUdpTransport;

enum
{
	/* */
	RDPUDP_FLAG_SYN = 0x0001,
	RDPUDP_FLAG_FIN = 0x0002,
	RDPUDP_FLAG_ACK = 0x0004,
	RDPUDP_FLAG_DATA = 0x0008,
	RDPUDP_FLAG_FEC = 0x0010,
	RDPUDP_FLAG_CN = 0x0020,
	RDPUDP_FLAG_CWR = 0x0040,
	RDPUDP_FLAG_SACK_OPTION = 0x0080,
	RDPUDP_FLAG_ACK_OF_ACKS = 0x0100,
	RDPUDP_FLAG_SYNLOSSY = 0x0200,
	RDPUDP_FLAG_ACKDELAYED = 0x0400,
	RDPUDP_FLAG_CORRELATION_ID = 0x0800,
	RDPUDP_FLAG_SYNEX = 0x1000,

	/* */
	RDPUDP_VERSION_INFO_VALID = 0x0001,
	RDPUDP_PROTOCOL_VERSION_1 = 0x0001,
	RDPUDP_PROTOCOL_VERSION_2 = 0x0002,
	RDPUDP_PROTOCOL_VERSION_3 = 0X0101,
};

typedef enum
{
	DATAGRAM_RECEIVED = 0,
	DATAGRAM_NOT_YET_RECEIVED = 3
} ElementState;

typedef struct
{
	ElementState state;
	BYTE nb;
} UdpAck;

typedef struct
{
	/* FEC Header */
	UINT32 snSourceAck;
	UINT16 uReceiveWindowSize;
	UINT16 uFlags;

	/* FEC PAYLOAD HEADER */
	UINT32 snCoded;
	UINT32 snSourceStart;
	BYTE uRange, uFecIndex;

	/* PAYLOAD PREFIX */
	UINT16 cbPayloadSize;

	/* SOURCE PAYLOAD HEADER */
	UINT32 sourceSnCoded;
	UINT32 sourceSnSourceStart;
	BYTE* payload;

	/* SYNDATA PAYLOAD */
	UINT32 snInitialSequenceNumber;
	UINT16 uUpStreamMtu, uDownStreamMtu;

	/* ACK OF ACKVECTOR */
	UINT32 snAckOfAcksSeqNum;

	/* ACK VECTOR */
	UINT16 uAckVectorSize;
	UdpAck* AckVectorElements;

	/* CORRELATION_ID_PAYLOAD */
	BYTE uCorrelationId[16];

	/* SYNDATAEX_PAYLOAD */
	UINT16 uSynExFlags;
	UINT16 uUdpVer;
	BYTE cookieHash[32];
} Udp12Packet;

typedef struct
{
	UINT32 seq;
	BOOL acked;
	UINT64 sendDate;
	BYTE resendNb;
	wStream* packet;
} UdpBufferPacket;

typedef struct
{
	rdpUdpTransport* udp;
	UINT16 windowSize;
	UINT16 startPtr;
	UINT16 endPtr;
	UdpBufferPacket* buffer;
} UdpWindowBuffer;

typedef struct
{
	UINT32 lastReceivedPacket;
	UINT16 receiveWindowSize;
	UINT32 currentSeqNumber;
	UdpWindowBuffer* outputBuffer;
} Udp12Context;

UdpWindowBuffer* UdpWindowBuffer_new(rdpUdpTransport* udp, size_t windowSz);
BOOL UdpWindowBuffer_push(UdpWindowBuffer* b, UINT32 seq, wStream* s);
BOOL UdpWindowBuffer_ackPacket(UdpWindowBuffer* b, UINT32 seq);
void UdpWindowBuffer_free(UdpWindowBuffer** pbuf);

BOOL udp12_init(rdpUdpTransport* udp, Udp12Context* udp12, BOOL server);
void udp12_destroy(Udp12Context* udp12);
BOOL udp12_parse_packet(wStream* s, Udp12Packet* packet);
BOOL udp12_send_syn(rdpUdpTransport* udp, Udp12Context* udp12, UINT16 flags);
BOOL udp12_send_ack(rdpUdpTransport* udp, Udp12Context* udp12);
BOOL udp12_send_packet(rdpUdpTransport* udp, Udp12Context* udp12, Udp12Packet* packet);

BOOL udp12_packet_writer(rdpUdpTransport* udp, Udp12Context* udp12, wStream* s);

#endif /* LIBFREERDP_CORE_RDPUDP12_H_ */
