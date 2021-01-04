/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * udp transport private definitions
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
#ifndef LIBFREERDP_CORE_UDP_PRIV_H_
#define LIBFREERDP_CORE_UDP_PRIV_H_

#include "rdpudp12.h"
#include "rdpudp3.h"

typedef BOOL (*UdpLowLevelHandler)(rdpUdpTransport* udp, void* context, wStream* packet);
typedef BOOL (*UdpLowLevelNeedTimerHandler)(rdpUdpTransport* udp, void* context);
typedef BOOL (*UdpLowLevelTimerHandler)(rdpUdpTransport* udp, void* context);

struct rdpUdpTransport
{
	BIO* bio;
	BOOL lossy;
	char* remoteHost;
	wStreamPool* packetPool;
	UdpTransportState state;
	BYTE correlationId[16];
	BYTE cookieHash[RDPUDP_COOKIE_HASHLEN];
	UdpMtu mtus;

	void* currentContext;
	Udp12Context udp12;
	Udp3Context udp3;
	wStream* pendingBuffer;
	RingBuffer availableData;

	UdpLowLevelHandler lowLevelPacketReader;
	UdpLowLevelHandler lowLevelPacketWriter;
	UdpLowLevelTimerHandler lowLevelTimer;
};

#endif /* LIBFREERDP_CORE_UDP_PRIV_H_ */
