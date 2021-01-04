/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * UDP
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
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>

#include <winpr/winsock.h>
#include <winpr/stream.h>
#include <winpr/wlog.h>
#include <winpr/print.h>
#include <winpr/sysinfo.h>
#include <winpr/crypto.h>

#include "settings.h"
#include "bio.h"
#include "tcp.h"
#include "udp.h"
#include "rdpudp.h"
#include "udp_priv.h"
#include "listener.h"

#define UDP_MTU 1232

#define TAG FREERDP_TAG("udp")

#define MIDDLE_SEQ_NUMBER 0x8000000
int seqNumberCompare(UINT32 sn1, UINT32 sn2)
{
	BOOL sn1AfterMiddle = (sn1 > MIDDLE_SEQ_NUMBER);
	BOOL sn2AfterMiddle = (sn2 > MIDDLE_SEQ_NUMBER);

	if (sn1AfterMiddle != sn2AfterMiddle)
	{
		sn1 += MIDDLE_SEQ_NUMBER;
		sn2 += MIDDLE_SEQ_NUMBER;
	}

	return sn2 - sn1;
}

BOOL checkMtu(UINT16 mtu)
{
	return (mtu <= 1232) && (mtu >= 1132);
}

BOOL udp12_packet_reader(rdpUdpTransport* udp, Udp12Context* udp12, wStream* s)
{
	Udp12Packet packet;
	BOOL ret = FALSE;
	UINT16 mask;
	int version;

	if (!udp12_parse_packet(s, &packet))
		return FALSE;

	if (!UdpWindowBuffer_ackPacket(udp12->outputBuffer, packet.snSourceAck))
	{
		WLog_INFO(TAG, "unable to ack packet 0x%x", packet.snSourceAck);
	}

	switch (udp->state)
	{
		case UDP_STATE_WAIT_SYN:
			if ((packet.uFlags & RDPUDP_FLAG_SYN) == 0)
			{
				WLog_ERR(TAG, "UDP_STATE_WAIT_SYN: expecting a SYN packet");
				goto out;
			}

			if (packet.uFlags & RDPUDP_FLAG_CORRELATION_ID)
				memcpy(udp->correlationId, packet.uCorrelationId, sizeof(udp->correlationId));

			version = 1;
			if (packet.uSynExFlags & RDPUDP_VERSION_INFO_VALID)
			{
				switch (packet.uUdpVer)
				{
					case RDPUDP_PROTOCOL_VERSION_1:
						version = 1;
						break;
					case RDPUDP_PROTOCOL_VERSION_2:
						version = 2;
						break;
					case RDPUDP_PROTOCOL_VERSION_3:
						version = 3;
						break;
				}
			}

			/* prepare answer packet */
			packet.uFlags = RDPUDP_FLAG_SYN | RDPUDP_FLAG_ACK | RDPUDP_FLAG_SYNEX;
			packet.snSourceAck = packet.snInitialSequenceNumber;
			packet.uDownStreamMtu = packet.uUpStreamMtu = 1232;
			packet.snInitialSequenceNumber = udp12->currentSeqNumber;

			WLog_DBG(TAG, "---> UDP syn+ack()");
			if (!udp12_send_packet(udp, udp12, &packet))
			{
				WLog_ERR(TAG, "UDP_STATE_WAIT_SYN: unable to send SYNACK response");
				goto out;
			}
			if (version == 3)
				rdpUdpTransport_switchToUdp2(udp);
			udp->state = UDP_STATE_ESTABLISHED;
			ret = TRUE;
			break;

		case UDP_STATE_WAIT_SYNACK:
			mask = (RDPUDP_FLAG_SYN | RDPUDP_FLAG_ACK);
			if ((packet.uFlags & mask) != mask)
			{
				WLog_ERR(TAG, "UDP_STATE_WAIT_SYNACK: expecting a SYN+ACK packet");
				goto out;
			}

			if (packet.snSourceAck != udp12->currentSeqNumber - 1)
			{
				WLog_ERR(TAG, "invalid ackPacket have 0x%" PRIx32 " expecting 0x%" PRIx32 "",
				         packet.snSourceAck, udp12->currentSeqNumber - 1);
				goto out;
			}

			/* check and adjust MTUs */
			if (!checkMtu(packet.uUpStreamMtu) || !checkMtu(packet.uDownStreamMtu))
			{
				WLog_ERR(TAG, "invalid MTUs sent back by the server");
				goto out;
			}

			udp->mtus.up = packet.uUpStreamMtu;
			udp->mtus.down = packet.uDownStreamMtu;
			udp12->lastReceivedPacket = packet.snInitialSequenceNumber;

			/* treat protocol version */
			version = 1;
			if (packet.uSynExFlags & RDPUDP_VERSION_INFO_VALID)
			{
				switch (packet.uUdpVer)
				{
					case RDPUDP_PROTOCOL_VERSION_1:
						version = 1;
						break;
					case RDPUDP_PROTOCOL_VERSION_2:
						version = 2;
						break;
					case RDPUDP_PROTOCOL_VERSION_3:
						/* switch to UDP2, so send a ACK packet */
						version = 3;
						rdpUdpTransport_switchToUdp2(udp);
						break;
					default:
						break;
				}
			}

			WLog_DBG(TAG, "udp12_packet_reader: UDP_STATE_WAIT_SYNACK -> UDP_STATE_ESTABLISHED");
			udp->state = UDP_STATE_ESTABLISHED;
			ret = TRUE;
			if (udp->pendingBuffer)
			{
				/* flush pending buffer */
				WLog_DBG(TAG, "flushing pending packet");
				Stream_SealLength(udp->pendingBuffer);
				// winpr_HexDump(TAG, WLOG_DEBUG, Stream_Buffer(udp->pendingBuffer),
				// Stream_Length(udp->pendingBuffer));

				ret = udp->lowLevelPacketWriter(udp, udp->currentContext, udp->pendingBuffer);

				Stream_Release(udp->pendingBuffer);
				udp->pendingBuffer = NULL;
			}
			break;
		default:
			ret = TRUE;
			break;
	}
out:
	return ret;
}

wStream* rdpUdpTransport_getPacket(rdpUdpTransport* udp)
{
	return StreamPool_Take(udp->packetPool, /*udp->mtus.up*/ 0xffff);
}

void rdpUdpTransport_discardPacket(rdpUdpTransport* udp, wStream* s)
{
	StreamPool_Return(udp->packetPool, s);
}

BOOL rdpUdpTransport_write(rdpUdpTransport* udp, wStream* s)
{
	switch (udp->state)
	{
		case UDP_STATE_INIT:
			if (!udp12_send_syn(udp, &udp->udp12, udp->lossy ? RDPUDP_FLAG_SYNLOSSY : 0))
				return FALSE;

			udp->state = UDP_STATE_WAIT_SYNACK;
			break;
		case UDP_STATE_WAIT_SYN:
		case UDP_STATE_WAIT_SYNACK:
		case UDP_STATE_WAIT_ACK:
			// TODO: handle these
			break;
		case UDP_STATE_ESTABLISHED:
			return udp->lowLevelPacketWriter(udp, udp->currentContext, s);
	}

	if (!udp->pendingBuffer)
	{
		udp->pendingBuffer = rdpUdpTransport_getPacket(udp);
		if (!udp->pendingBuffer)
			return FALSE;
	}

	if (!Stream_EnsureRemainingCapacity(udp->pendingBuffer, Stream_Length(s)))
		return FALSE;
	Stream_Write(udp->pendingBuffer, Stream_Buffer(s), Stream_Length(s));
	return TRUE;
}

BOOL rdpUdpTransport_bioSend(rdpUdpTransport* udp, wStream* s)
{
	return BIO_write(BIO_next(udp->bio), Stream_Buffer(s), Stream_Length(s));
}

UdpTransportState rdpUdpTransport_getState(const rdpUdpTransport* udp)
{
	return udp->state;
}

const UdpMtu* rdpUdpTransport_Mtus(const rdpUdpTransport* udp)
{
	return &udp->mtus;
}

BOOL rdpUdpTransport_isLossy(const rdpUdpTransport* udp)
{
	return udp->lossy;
}

void rdpUdpTransport_copyCorrelationId(const rdpUdpTransport* udp, BYTE* dest)
{
	memcpy(dest, udp->correlationId, sizeof(udp->correlationId));
}

void rdpUdpTransport_copyCookie(const rdpUdpTransport* udp, BYTE* dest)
{
	memcpy(dest, udp->cookieHash, sizeof(udp->cookieHash));
}

BOOL rdpUdpTransport_pushAvailableData(rdpUdpTransport* udp, wStream* s)
{
	//WLog_DBG(TAG, "");
	return ringbuffer_write(&udp->availableData, Stream_Buffer(s), Stream_Length(s));
}

void rdpUdpTransport_switchToUdp2(rdpUdpTransport* udp)
{
	WLog_DBG(TAG, "switching to UDP2");
	udp->currentContext = &udp->udp3;
	udp->lowLevelPacketReader = (UdpLowLevelHandler)udp3_low_level_reader;
	udp->lowLevelPacketWriter = (UdpLowLevelHandler)udp3_low_level_writer;
	udp->lowLevelTimer = (UdpLowLevelTimerHandler)udp3_low_level_timer;
}


rdpUdpTransport* rdpUdpTransport_new(BIO* bio, rdpSettings* settings, BOOL lossy, BOOL server,
                                     const BYTE* correlationId, const BYTE* cookieHash)
{
	rdpUdpTransport* ret = calloc(1, sizeof(*ret));
	if (!ret)
		return NULL;

	if (correlationId)
		memcpy(ret->correlationId, correlationId, sizeof(ret->correlationId));

	if (cookieHash)
		memcpy(ret->cookieHash, cookieHash, sizeof(ret->cookieHash));

	if (!ringbuffer_init(&ret->availableData, 4096))
		goto error_rb;

	ret->bio = bio;
	ret->lossy = lossy;
	ret->lowLevelPacketReader = (UdpLowLevelHandler)udp12_packet_reader;
	ret->lowLevelPacketWriter = (UdpLowLevelHandler)udp12_packet_writer;
	ret->lossy = FALSE;
	ret->state = server ? UDP_STATE_WAIT_SYN : UDP_STATE_INIT;
	ret->mtus.up = UDP_MTU;
	ret->mtus.down = UDP_MTU;
	ret->currentContext = &ret->udp12;

	ret->packetPool = StreamPool_New(TRUE, 0x10000);
	if (!ret->packetPool)
		goto error_pool;

	if (!udp12_init(ret, &ret->udp12, server))
		goto error_udp12;

	if (!udp3_init(ret, &ret->udp3, server))
		goto error_udp3;
	return ret;

error_udp3:
	udp12_destroy(&ret->udp12);
error_udp12:
	StreamPool_Free(ret->packetPool);
error_pool:
	ringbuffer_destroy(&ret->availableData);
error_rb:
	free(ret);
	return NULL;
}

void rdpUdpTransport_free(rdpUdpTransport** pudp)
{
	rdpUdpTransport* udp;

	assert(pudp);
	udp = *pudp;
	if (!udp)
		return;

	udp12_destroy(&udp->udp12);
	udp3_destroy(&udp->udp3);
	ringbuffer_destroy(&udp->availableData);

	StreamPool_Free(udp->packetPool);
	free(udp);
	*pudp = NULL;
}

static int bio_rdpudp_write(BIO* bio, const char* buf, int size)
{
	// int error;
	int status = size;
	wStream s;
	rdpUdpTransport* udp = (rdpUdpTransport*)BIO_get_data(bio);

	if (!buf || !udp)
		return 0;

	UDP_DEBUG("bio_rdpudp_write(size=%d, thread=%x)", size, (int)pthread_self());
	// winpr_HexDump(TAG, WLOG_DEBUG, buf, size);

	BIO_clear_flags(bio, BIO_FLAGS_WRITE | BIO_FLAGS_READ | BIO_FLAGS_IO_SPECIAL);
	Stream_StaticInit(&s, (BYTE*)buf, size);
	if (!rdpUdpTransport_write(udp, &s))
		return -1;

	return status;
}

static int bio_rdpudp_read(BIO* bio, char* buf, int size)
{
	int status;
	BIO* next_bio;
	const UdpMtu* mtus;
	rdpUdpTransport* udp = (rdpUdpTransport*)BIO_get_data(bio);

	if (!buf || !udp)
		return 0;

	mtus = rdpUdpTransport_Mtus(udp);

	next_bio = BIO_next(bio);

	int nreads = 0;
	BIO_clear_flags(bio, BIO_FLAGS_READ);

	wStream* s = rdpUdpTransport_getPacket(udp);
	if (!s)
		return 0;

	do
	{
		/* we should read mtus->down bytes but MS servers usually send dgram bigger than that */
		status = BIO_read(next_bio, Stream_Buffer(s), /*mtus->down + 0x100*/ 0xffff);
		UDP_DEBUG("bio_rdpudp_read next(downMtu=%d size=%d nreads=%d)=%d", mtus->down, size, nreads, status);
		/*if (status >= 0)
			winpr_HexDump(TAG, WLOG_DEBUG, Stream_Buffer(s), status);*/

		if (status <= 0)
		{
			if (!BIO_should_retry(next_bio))
			{
				rdpUdpTransport_discardPacket(udp, s);
				BIO_clear_flags(bio, BIO_FLAGS_SHOULD_RETRY);
				return status;
			}

			break;
		}

		Stream_SetLength(s, status);
		if (!udp->lowLevelPacketReader(udp, udp->currentContext, s))
			return -1;

		if (rdpUdpTransport_getState(udp) != UDP_STATE_ESTABLISHED)
		{
			rdpUdpTransport_discardPacket(udp, s);
			BIO_set_flags(bio, BIO_FLAGS_SHOULD_RETRY);
			status = 0;
			goto out;
		}
		Stream_SetPosition(s, 0);
		nreads++;
	} while (ringbuffer_used(&udp->availableData) < size && nreads < 20);

	rdpUdpTransport_discardPacket(udp, s);
	int nchunks, i;
	DataChunk chunks[2];

treat_data:
	status = 0;
	nchunks = ringbuffer_peek(&udp->availableData, chunks, size);
	if (nchunks)
	{
		BYTE* target = (BYTE*)buf;
		for (i = 0; i < nchunks; i++)
		{
			memcpy(target, chunks[i].data, chunks[i].size);
			target += chunks[i].size;
			status += chunks[i].size;
		}
		ringbuffer_commit_read_bytes(&udp->availableData, status);
		// WLog_DBG(TAG, "returned bio_rdpudp_read buf=");
		// winpr_HexDump(TAG, WLOG_DEBUG, buf, status);
	}
	else
	{
		BIO_set_flags(bio, BIO_FLAGS_READ | BIO_FLAGS_SHOULD_RETRY);
		status = -1;
	}
	//UDP_DEBUG("bio_rdpudp_read(size=%d) -> %d", size, status);
	/*if (status > 0)
	    winpr_HexDump(TAG,  WLOG_DEBUG, (const BYTE*)(buf-status), status);*/

out:
	return status;
}

static long bio_rdpudp_ctrl(BIO* bio, int cmd, long num, void* ptr)
{
	BIO* next_bio;
	int status = -1;
	rdpUdpTransport* udp = (rdpUdpTransport*)BIO_get_data(bio);

	if (!udp)
		return 0;

	/*WLog_DBG(TAG, "bio_rdpudp_ctrl(cmd=%d, num=0x%x)", cmd, num);*/
	next_bio = BIO_next(bio);

	switch (cmd)
	{
		case BIO_CTRL_PENDING:
			status = 0;
			break;

		case BIO_CTRL_FLUSH:
			status = 1;
			break;

		case BIO_C_TIMER_EXEC:
			if (udp->lowLevelTimer)
				status = udp->lowLevelTimer(udp, udp->currentContext);
			break;

		default:
			status = BIO_ctrl(next_bio, cmd, num, ptr);
			break;
	}

	return status;
}

static int bio_rdpudp_free(BIO* bio)
{
	if (!bio)
		return 0;

	rdpUdpTransport* udp = (rdpUdpTransport*)BIO_get_data(bio);
	if (!udp)
		return 0;
	rdpUdpTransport_free(&udp);
	return 1;
}

#define BIO_TYPE_RDP_UDP 80

BIO_METHOD* BIO_s_rdpudp(void)
{
	static BIO_METHOD* bio_methods = NULL;

	if (bio_methods == NULL)
	{
		if (!(bio_methods = BIO_meth_new(BIO_TYPE_RDP_UDP, "RdpUdp")))
			return NULL;

		BIO_meth_set_write(bio_methods, bio_rdpudp_write);
		BIO_meth_set_read(bio_methods, bio_rdpudp_read);
		BIO_meth_set_puts(bio_methods, bio_generic_puts);
		BIO_meth_set_gets(bio_methods, bio_generic_gets);
		BIO_meth_set_ctrl(bio_methods, bio_rdpudp_ctrl);
		BIO_meth_set_create(bio_methods, bio_generic_new);
		BIO_meth_set_destroy(bio_methods, bio_rdpudp_free);
		BIO_meth_set_callback_ctrl(bio_methods, bio_generic_callback_ctrl);
	}

	return bio_methods;
}

BIO* rdpUdp_client_bio(rdpSettings* settings, SOCKET fd, struct sockaddr* addr, BOOL lossy,
                       const BYTE* cookie)
{
	rdpUdpTransport* udp;
	BIO* udpBio;
	BIO* rdpUdpBio;
	BYTE cookieHashRaw[RDPUDP_COOKIE_HASHLEN];
	BYTE cookieHash[RDPUDP_COOKIE_HASHLEN];
	BYTE* correlationId = NULL;

	if (!winpr_Digest(WINPR_MD_SHA256, cookie, 16, cookieHashRaw, RDPUDP_COOKIE_HASHLEN))
		return NULL;

	UINT32 *ptr = (UINT32 *)&cookieHashRaw[0];
	wStream staticStream;
	wStream *s = Stream_StaticInit(&staticStream, cookieHash, RDPUDP_COOKIE_HASHLEN);

	for (size_t i = 0; i < RDPUDP_COOKIE_HASHLEN; i+= 4, ptr++)
		Stream_Write_UINT32_BE_unchecked(s, *ptr);

	if (settings->UseCorrelationId)
		correlationId = settings->CorrelationId;

	udpBio = BIO_new(BIO_s_simple_socket());
	if (!udpBio)
		goto fail_udp_BIO;
	BIO_set_fd(udpBio, fd, BIO_CLOSE);

	rdpUdpBio = BIO_new(BIO_s_rdpudp());
	if (!rdpUdpBio)
		goto fail_rdpUdpBio;

	udp = rdpUdpTransport_new(rdpUdpBio, settings, lossy, FALSE, correlationId, cookieHash);
	if (!udp)
		goto fail_setup;

	BIO_set_data(rdpUdpBio, udp);
	rdpUdpBio = BIO_push(rdpUdpBio, udpBio);

	return rdpUdpBio;

fail_setup:
	BIO_free(rdpUdpBio);
fail_rdpUdpBio:
	BIO_free(udpBio);
fail_udp_BIO:
	return NULL;
}

BIO* rdpUdpTransport_init_client(rdpSettings* settings, rdpTls* tls, BOOL lossy, const BYTE* cookie,
                                 const char* hostname, int port, BOOL* completed)
{
	char* remoteHost;
	BIO* bio;
	struct sockaddr_storage addr = { 0 };

	SOCKET sock = freerdp_udp_connect(settings, hostname, port, &addr);
	if (sock == INVALID_SOCKET)
		return NULL;

	remoteHost = freerdp_tcp_get_peer_address(sock);
	if (!remoteHost)
		goto fail_bio;

	WLog_DBG(TAG, "UDP %s connected to %s", lossy ? "lossy" : "reliable", remoteHost);
	free(remoteHost);

	bio = rdpUdp_client_bio(settings, sock, (struct sockaddr*)&addr, lossy, cookie);
	if (!bio)
		goto fail_bio;

	const SSL_METHOD* method = freerdp_tls_get_ssl_method(lossy, TRUE);
	switch (freerdp_tls_connect_ex2(tls, bio, method, 200))
	{
		case TLS_HANDSHAKE_CONTINUE:
			*completed = FALSE;
			return tls->bio;
		case TLS_HANDSHAKE_SUCCESS:
			WLog_ERR(TAG, "not expecting successful handshake on first call");
			*completed = TRUE;
			return tls->bio;
		case TLS_HANDSHAKE_ERROR:
		case TLS_HANDSHAKE_VERIFY_ERROR:
			goto fail_bio;
	}

	return tls->bio;

fail_bio:
	BIO_free_all(bio);
	tls->bio = NULL;
	return NULL;
}
