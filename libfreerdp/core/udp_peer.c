/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * udp_peer
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
#include <winpr/wlog.h>

#include "bio.h"
#include "rdpudp.h"
#include "udp_peer.h"
#include "tcp.h"
#include "listener.h"

#define TAG FREERDP_TAG("udp")

static int bio_rdpudp_peer_free(BIO* bio)
{
	ListenerUdpPeer* peer;

	if (!bio)
		return 0;

	peer = (ListenerUdpPeer*)BIO_get_data(bio);
	if (!peer)
		return 0;

	// TODO: do cleanup
	return 1;
}

static long bio_rdpudp_peer_ctrl(BIO* bio, int cmd, long num, void* ptr)
{
	BIO* next_bio;
	int status = -1;
	ListenerUdpPeer* peer = (ListenerUdpPeer*)BIO_get_data(bio);
	HANDLE h;

	if (!peer)
		return 0;

	// WLog_DBG(TAG, "bio_rdpudp_ctrl(cmd=%d, num=0x%x)", cmd, num);
	next_bio = BIO_next(bio);

	switch (cmd)
	{
		case BIO_CTRL_PENDING:
			status = 0;
			break;

		case BIO_CTRL_FLUSH:
			status = 1;
			break;
		case BIO_C_GET_EVENT:
			h = Queue_Event(peer->packetQueue);
			(*(HANDLE*)ptr) = h;
			status = 1;
			break;
		case BIO_C_GET_FD:
			h = Queue_Event(peer->packetQueue);
			(*(SOCKET*)ptr) = GetEventFileDescriptor(h);
			status = 1;
			break;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		case 72: /* BIO_CTRL_SET_KTLS_SEND */
		case 74: /* BIO_CTRL_SET_KTLS_SEND_CTRL_MSG */
		case 75: /* BIO_CTRL_CLEAR_KTLS_CTRL_MSG */
		case BIO_CTRL_GET_KTLS_SEND:
		case BIO_CTRL_GET_KTLS_RECV:
			/* WLog_DBG(TAG, "not supporting kTls commands %d", cmd); */
			status = 0;
			break;
#endif

		default:
			status = BIO_ctrl(next_bio, cmd, num, ptr);
			break;
	}

	return status;
}

static int bio_rdpudp_peer_write(BIO* bio, const char* buf, int size)
{
	int status = size;
	ListenerUdpPeer* peer = (ListenerUdpPeer*)BIO_get_data(bio);
	if (!peer)
		return -1;

	status = sendto(peer->sock, buf, size, MSG_NOSIGNAL,
	                (const struct sockaddr*)&peer->peerAddr.addr, peer->peerAddr.len);
	if (status < 0)
		WLog_ERR(TAG, "error sending UDP packet: %s", strerror(errno));

	// WLog_DBG(TAG, "bio_rdpudp_peer_write(%d) -> %d", size, status);

	return status;
}

static int bio_rdpudp_peer_read(BIO* bio, char* buf, int size)
{
	wStream* s;
	int ret;
	ListenerUdpPeer* peer = (ListenerUdpPeer*)BIO_get_data(bio);

	if (!buf || !peer)
	{
		WLog_ERR(TAG, "invalid peer or buf");
		return 0;
	}
	BIO_clear_flags(bio, BIO_FLAGS_READ);

	s = (wStream*)Queue_Dequeue(peer->packetQueue);
	if (!s)
	{
		BIO_set_flags(bio, BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_READ);
		return -1;
	}

	ret = Stream_Length(s);
	if (ret > size)
	{
		WLog_DBG(TAG, "capping popped packet from %d to %d", ret, size);
		ret = size;
	}

	WLog_DBG(TAG, "bio_rdpudp_peer_read(%d)->%d", size, ret);
	memcpy(buf, Stream_Buffer(s), ret);
	BIO_clear_flags(bio, BIO_FLAGS_SHOULD_RETRY);
	Stream_Free(s, TRUE);
	return ret;
}

#define BIO_TYPE_RDP_UDP_PEER 69

static BIO_METHOD* BIO_s_rdpudp_peer(void)
{
	static BIO_METHOD* bio_methods = NULL;

	if (bio_methods == NULL)
	{
		if (!(bio_methods = BIO_meth_new(BIO_TYPE_RDP_UDP_PEER, "RdpUdp_Peer")))
			return NULL;

		BIO_meth_set_write(bio_methods, bio_rdpudp_peer_write);
		BIO_meth_set_read(bio_methods, bio_rdpudp_peer_read);
		BIO_meth_set_puts(bio_methods, bio_generic_puts);
		BIO_meth_set_gets(bio_methods, bio_generic_gets);
		BIO_meth_set_ctrl(bio_methods, bio_rdpudp_peer_ctrl);
		BIO_meth_set_create(bio_methods, bio_generic_new);
		BIO_meth_set_destroy(bio_methods, bio_rdpudp_peer_free);
		BIO_meth_set_callback_ctrl(bio_methods, bio_generic_callback_ctrl);
	}

	return bio_methods;
}

BIO* rdpUdpTransport_init_server(rdpSettings* settings, rdpTls* tls, ListenerUdpPeer* peer)
{
	BIO* udpPeerBio;
	BIO* rdpUdpBio;
	rdpUdpTransport* rdpUdp;

	/* UDP peer layer */
	udpPeerBio = BIO_new(BIO_s_rdpudp_peer());
	if (!udpPeerBio)
		return NULL;
	BIO_set_data(udpPeerBio, peer);

	/* rdpUdp layer */
	rdpUdpBio = BIO_new(BIO_s_rdpudp());
	if (!rdpUdpBio)
		goto fail_rdpUdpBio;

	rdpUdp = rdpUdpTransport_new(rdpUdpBio, settings, FALSE, TRUE, NULL, NULL);
	if (!rdpUdp)
		goto fail_setup;
	BIO_set_data(rdpUdpBio, rdpUdp);

	rdpUdpBio = BIO_push(rdpUdpBio, udpPeerBio);
	return rdpUdpBio;

fail_rdpUdpBio:
	BIO_free(udpPeerBio);
fail_setup:
	return NULL;
}
