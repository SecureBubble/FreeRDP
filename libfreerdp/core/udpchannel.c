/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 *
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
#include "udpchannel.h"
#include "multitransport.h"
#include "rdpudp.h"
#include "udp_peer.h"

#define TAG FREERDP_TAG("udpchannel")

typedef enum
{
	RDPTUNNEL_ACTION_CREATEREQUEST = 0x00,
	RDPTUNNEL_ACTION_CREATERESPONSE = 0x01,
	RDPTUNNEL_ACTION_DATA = 0x02
} RdpTunnelAction;

static void ringbuffer_copyTo(const RingBuffer* rb, BYTE* target)
{
	DataChunk chunks[2];
	int nchunks = ringbuffer_peek(rb, chunks, ringbuffer_used(rb));
	int i;

	for (i = 0; i < nchunks; i++)
	{
		memcpy(target, chunks[i].data, chunks[i].size);
		target += chunks[i].size;
	}
}

static BOOL write_tunnel_header(wStream* s, BYTE action, UINT16 len, BYTE subHeaderLen)
{
	Stream_Write_UINT8(s, action);
	Stream_Write_UINT16(s, len);
	Stream_Write_UINT8(s, 4 + subHeaderLen);
	return TRUE;
}

static BOOL write_tunnel_create_request(wStream* s, UINT32 requestId, const BYTE* securityCookie)
{
	if (!write_tunnel_header(s, RDPTUNNEL_ACTION_CREATEREQUEST, 24, 0))
		return FALSE;

	if (Stream_GetRemainingCapacity(s) < 24)
		return FALSE;

	Stream_Write_UINT32(s, requestId);
	Stream_Zero(s, 4);
	Stream_Write(s, securityCookie, 16);
	Stream_SealLength(s);
	return TRUE;
}

static BOOL write_CreateTunnelReq(multiTransportChannel* channel, UINT32 reqId, const BYTE* cookie)
{
	BYTE buffer[256];
	wStream createTunnelPdu;
	wStream* s;
	int status;

	s = Stream_StaticInit(&createTunnelPdu, buffer, sizeof(buffer));
	if (!write_tunnel_create_request(s, reqId, cookie))
		return FALSE;

	/*WLog_DBG(TAG, "CreateTunnelReq packet=");
	winpr_HexDump(TAG, WLOG_DEBUG, buffer, Stream_Length(&createTunnelPdu));*/

	status = BIO_write(channel->bio, (const char*)buffer, Stream_GetPosition(s));
	return status >= 0;
}

static BOOL write_tunnel_create_response(wStream* s, INT32 hrResult)
{
	if (!write_tunnel_header(s, RDPTUNNEL_ACTION_CREATERESPONSE, 4, 0))
		return FALSE;

	if (Stream_GetRemainingCapacity(s) < 4)
		return FALSE;

	Stream_Write_UINT32(s, hrResult);
	Stream_SealLength(s);
	return TRUE;
}

static BOOL write_CreateTunnelResp(multiTransportChannel* channel, INT32 hrResult)
{
	BYTE buffer[256];
	wStream createTunnelPdu;
	wStream* s;
	int status;

	s = Stream_StaticInit(&createTunnelPdu, buffer, sizeof(buffer));
	if (!write_tunnel_create_response(s, hrResult))
		return FALSE;

	/*WLog_DBG(TAG, "CreateTunnelReq packet=");
	winpr_HexDump(TAG, WLOG_DEBUG, buffer, Stream_Length(&createTunnelPdu));*/

	status = BIO_write(channel->bio, (const char*)buffer, Stream_GetPosition(s));
	return status >= 0;
}

static BOOL server_channel_createTunnelReq(multiTransportChannel* channel, UINT32 reqId,
                                           const BYTE* cookie)
{
	freerdp_listener* listener = channel->listener;

	INT32 hrResponse = listener->IdentifyUdpPeer(listener, reqId, cookie, channel);

	return write_CreateTunnelResp(channel, hrResponse);
}

static BOOL server_channel_createTunnelResp(multiTransportChannel* channel, INT32 hrResponse)
{
	WLog_ERR(TAG, "should not receive a tunnelCreateResponse in server mode");
	return FALSE;
}

static BOOL client_channel_createTunnelReq(multiTransportChannel* channel, UINT32 reqId,
                                           const BYTE* cookie)
{
	WLog_ERR(TAG, "should not receive a tunnelCreateRequest in client mode");
	return FALSE;
}

static BOOL client_channel_createTunnelResp(multiTransportChannel* channel, INT32 hrResult)
{
	if (hrResult == ERROR_SUCCESS)
		channel->state = MTCHANNEL_RUNNING;
	else
		channel->state = MTCHANNEL_RESPONSE_ERROR;

	return multitransport_client_send_response(channel->multiTransport, channel->reqId, hrResult);
}

/** @brief multitransport parsing headers result */
typedef enum
{
	MT_PARSE_OK,
	MT_PARSE_FAIL,
	MT_PARSE_INCOMPLETE
} MtParseResult;

const char* multiTransportChannelStateToString(MultiTransportChannelState s)
{
	switch (s)
	{
		case MTCHANNEL_HANDSHAKING:
			return "HANDSHAKING";
		case MTCHANNEL_WAITING_REQUEST:
			return "WAITING_REQUEST";
		case MTCHANNEL_WAITING_RESPONSE:
			return "WAITING_RESPONSE";
		case MTCHANNEL_RUNNING:
			return "RUNNING";
		case MTCHANNEL_RESPONSE_ERROR:
			return "RESPONSE_ERROR";
		default:
			return "<unknown/error>";
	}
}

/** @brief result of MultiTransport read */
typedef enum
{
	MTREAD_PACKET_OK,
	MTREAD_PACKET_IO_ERROR,
	MTREAD_PACKET_OOM
} ReadPacketStatus;

static MtParseResult mt_tunnel_headers_parse(wStream* s, BYTE* action, UINT16* payloadLen,
                                             UINT16* subHeaderLen)
{
	BYTE headerLength;

	if (Stream_GetRemainingLength(s) < 4)
		return MT_PARSE_INCOMPLETE;

	Stream_Read_UINT8(s, *action);
	Stream_Read_UINT16(s, *payloadLen);
	Stream_Read_UINT8(s, headerLength);
	if (headerLength < 4)
	{
		WLog_ERR(TAG, "headerLength(%d) is too small", headerLength);
		return MT_PARSE_FAIL;
	}

	*subHeaderLen = headerLength - 4;
	if (Stream_GetRemainingLength(s) < *payloadLen + *subHeaderLen)
		return MT_PARSE_INCOMPLETE;

	return MT_PARSE_OK;
}

static BOOL mt_tunnel_subheaders_parse(multiTransportChannel* channel, wStream* s)
{
	BYTE subHeaderLength, subHeaderType;
	wStream savedStream = *s;
	RDP_TRANSPORT_TYPE transport = channel->lossy ? RDP_TRANSPORT_UDP_L : RDP_TRANSPORT_UDP_R;

	Stream_Read_UINT8(s, subHeaderLength);
	if (subHeaderLength < 2)
		return FALSE;

	Stream_Read_UINT8(s, subHeaderType);

	rdpAutoDetect* autodetect = channel->multiTransport->rdp->autodetect;
	switch (subHeaderType)
	{
		case TYPE_ID_AUTODETECT_REQUEST:
			return autodetect_recv_request_packet(autodetect, transport, &savedStream) == 0;

		case TYPE_ID_AUTODETECT_RESPONSE:
			return autodetect_recv_response_packet(autodetect, transport, &savedStream) == 0;

		default:
			WLog_ERR(TAG, "unhandled subHeaderType 0x%x", subHeaderType);
			break;
	}

	return TRUE;
}

void multitransportchannel_ref(multiTransportChannel* channel)
{
	InterlockedIncrement(&channel->refCount);
}

void multitransportchannel_unref(multiTransportChannel** pchannel)
{
	multiTransportChannel* channel = *pchannel;

	if (InterlockedDecrement(&channel->refCount) == 0)
		multitransportchannel_free(pchannel);
	else
		*pchannel = NULL;
}

void multitransportchannel_free(multiTransportChannel** pchannel)
{
	multiTransportChannel* channel = *pchannel;
	if (!channel)
		return;

	ringbuffer_destroy(&channel->inputBuffer);
	CloseHandle(channel->timerEvent);

	// TODO: BIO stuff ??
	freerdp_tls_free(channel->tls);
	free(channel);
	*pchannel = NULL;
}

wStream* multitransportchannel_readPacket(multiTransportChannel* channel, ReadPacketStatus* error)
{
#define MT_READ_CHUNKS 16 * 1024
	wStream* packet = NULL;
	BYTE* target = ringbuffer_ensure_linear_write(&channel->inputBuffer, MT_READ_CHUNKS);
	int status = BIO_read(channel->bio, target, MT_READ_CHUNKS);
	if (status < 0)
	{
		// WLog_ERR(TAG, "BIO_read error");
		*error = BIO_should_retry(channel->bio) ? MTREAD_PACKET_OK : MTREAD_PACKET_IO_ERROR;
		return NULL;
	}

#if 0
	winpr_HexDump(TAG, WLOG_DEBUG, target, status);
#endif

	if (status)
	{
		if (!ringbuffer_commit_written_bytes(&channel->inputBuffer, status))
		{
			*error = MTREAD_PACKET_OOM;
			return NULL;
		}

		packet = Stream_New(NULL, ringbuffer_used(&channel->inputBuffer));
		if (!packet)
		{
			*error = MTREAD_PACKET_OOM;
			return NULL;
		}

		ringbuffer_copyTo(&channel->inputBuffer, Stream_Buffer(packet));
	}
	*error = MTREAD_PACKET_OK;
	return packet;
}

static MtParseResult multitransport_parse_one_message(multiTransportChannel* channel, wStream* s)
{
	MtParseResult res;
	BYTE action;
	UINT16 payloadLen;
	UINT16 subHeaderLen;
	wStream payloadBuffer;
	wStream* payload;
	BOOL cbRet;

	res = mt_tunnel_headers_parse(s, &action, &payloadLen, &subHeaderLen);
	if (res != MT_PARSE_OK)
		return res;

	if (subHeaderLen)
	{
		wStream subHeaderStream;
		Stream_StaticInit(&subHeaderStream, Stream_Pointer(s), subHeaderLen);
		if (!mt_tunnel_subheaders_parse(channel, &subHeaderStream))
		{
			WLog_ERR(TAG, "error parsing subheaders");
			return MT_PARSE_FAIL;
		}
		Stream_Seek(s, subHeaderLen);
	}

	payload = Stream_StaticInit(&payloadBuffer, Stream_Pointer(s), payloadLen);
	Stream_Seek(s, payloadLen);

	switch (action)
	{
		case RDPTUNNEL_ACTION_CREATEREQUEST:
		{
			BYTE securityCookie[16];
			UINT32 reqId;

			if (Stream_GetRemainingLength(payload) < 24)
			{
				WLog_ERR(TAG, "stream too small for RDPTUNNEL_ACTION_CREATEREQUEST");
				return MT_PARSE_FAIL;
			}

			if (channel->isClient)
			{
				WLog_ERR(TAG, "not expecting a CREATEREQUEST on the client side");
				return MT_PARSE_FAIL;
			}
			Stream_Read_UINT32(payload, reqId);
			Stream_Seek(payload, 4);
			Stream_Read(payload, securityCookie, 16);

			WLog_DBG(TAG, "createTunnelRequest(reqId=0x%x)", reqId);
			cbRet = channel->createTunnelReq(channel, reqId, securityCookie);
			break;
		}

		case RDPTUNNEL_ACTION_CREATERESPONSE:
		{
			INT32 hrResult;
			if (Stream_GetRemainingLength(payload) < 4)
			{
				WLog_ERR(TAG, "stream too small for RDPTUNNEL_ACTION_CREATERESPONSE");
				return MT_PARSE_FAIL;
			}

			if (!channel->isClient)
			{
				WLog_ERR(TAG, "not expecting a CREATERESPONSE on the server side");
				return MT_PARSE_FAIL;
			}

			Stream_Read_INT32(payload, hrResult);
			WLog_DBG(TAG, "createTunnelResponse(hrResult=%d)", hrResult);

			cbRet = channel->createTunnelResp(channel, hrResult);
			if (cbRet)
			{
				freerdp* instance = channel->multiTransport->rdp->context->instance;
				if (instance->UdpChannelEstablished)
					cbRet = instance->UdpChannelEstablished(instance, channel);
			}
			break;
		}

		case RDPTUNNEL_ACTION_DATA:
			cbRet = (Stream_GetRemainingLength(payload) == 0) || !channel->onDataPdu ||
			        channel->onDataPdu(channel, payload);
			break;

		default:
			WLog_ERR(TAG, "unknown rdpTunnelAction 0x%x", action);
			cbRet = FALSE;
			break;
	}

	if (!cbRet)
		WLog_ERR(TAG, "error treating message 0x%x", action);

	return cbRet ? MT_PARSE_OK : MT_PARSE_FAIL;
}

static BOOL mtchannel_handlePackets(multiTransportChannel* channel)
{
	BOOL doLoop;
	wStream* packet = NULL;

	if (channel->state == MTCHANNEL_HANDSHAKING)
	{
		int status = BIO_do_handshake(channel->bio);
		if (status == 1)
		{
			WLog_DBG(TAG, "SSL handshake completed for %s", channel->remoteAddr);

			if (channel->isClient)
			{
				WLog_DBG(TAG, "sending CreateTunnelRequest");
				if (!write_CreateTunnelReq(channel, channel->reqId, channel->cookie))
				{
					channel->state = MTCHANNEL_RESPONSE_ERROR;
					return FALSE;
				}
				channel->state = MTCHANNEL_WAITING_RESPONSE;
				return TRUE;
			}
			else
			{
				channel->state = MTCHANNEL_WAITING_REQUEST;
			}
		}
		else
		{
			if (!BIO_should_retry(channel->bio))
			{
				WLog_ERR(TAG, "error while handshaking with %s, status=%d", channel->remoteAddr,
				         status);
				return FALSE;
			}
			return TRUE;
		}
	}

	ReadPacketStatus result;
	packet = multitransportchannel_readPacket(channel, &result);
	switch (result)
	{
		case MTREAD_PACKET_OK:
			break;
		case MTREAD_PACKET_IO_ERROR:
			WLog_ERR(TAG, "IO error while reading packet");
			return FALSE;
		case MTREAD_PACKET_OOM:
			WLog_ERR(TAG, "OOM while reading packet");
			return FALSE;
	}

	doLoop = TRUE;
	while (doLoop && packet && Stream_GetRemainingLength(packet))
	{
		switch (multitransport_parse_one_message(channel, packet))
		{
			case MT_PARSE_OK:
				break;
			case MT_PARSE_INCOMPLETE:
				doLoop = FALSE;
				break;
			case MT_PARSE_FAIL:
				// Perhaps we should deal with inputBuffer
				WLog_ERR(TAG, "parse error");
				Stream_Free(packet, TRUE);
				return FALSE;
		}
	}

	if (packet)
	{
		ringbuffer_commit_read_bytes(&channel->inputBuffer, Stream_GetPosition(packet));
		Stream_Free(packet, TRUE);
	}

	return TRUE;
}

static BOOL mt_treat_data(multiTransportChannel* channel, wStream* s)
{
	if (!Stream_GetRemainingLength(s))
		return TRUE;

#if 0
	winpr_HexDump(TAG, WLOG_DEBUG, (const BYTE*)Stream_Pointer(s), Stream_GetRemainingLength(s));
#endif

	if (!channel->haveDynChannelId)
	{
		UINT32 i;

		rdpMcs* mcs = channel->multiTransport->rdp->mcs;
		rdpMcsChannel* mcsChannel = mcs->channels;

		for (i = 0; i < mcs->channelCount; mcsChannel++)
		{
			if (strcasecmp(mcsChannel->Name, "drdynvc") == 0)
			{
				channel->haveDynChannelId = TRUE;
				channel->dynamicChannelId = mcsChannel->ChannelId;
				break;
			}
		}
	}

	if (!channel->haveDynChannelId)
	{
		WLog_ERR(TAG, "%s: unable to retrieve the dynamic channel id", __func__);
		return TRUE;
	}

	BOOL ret;
	if (channel->isClient)
	{
		freerdp* instance = channel->multiTransport->rdp->context->instance;
		ret = instance->ReceiveChannelData(
		    instance, channel->dynamicChannelId, Stream_Buffer(s), Stream_GetRemainingLength(s),
		    CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST, Stream_GetRemainingLength(s));
	}
	else
	{
		freerdp_peer* peer = channel->multiTransport->rdp->context->peer;
		ret = peer->ReceiveChannelData(
		    peer, channel->dynamicChannelId, Stream_Buffer(s), Stream_GetRemainingLength(s),
		    CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST, Stream_GetRemainingLength(s));
	}

	if (!ret)
		WLog_ERR(TAG, "error treating channel data");
	return ret;
}

BOOL mt_send_pdu(multiTransportChannel* channel, wStream* headers, wStream* payload)
{
	int status;
	wStream* s;
	UINT8 HeaderLength = 4 + (headers ? Stream_Length(headers) : 0);
	UINT16 PayloadLength = payload ? Stream_Length(payload) : 0;
	size_t totalLen = HeaderLength + PayloadLength;

	s = Stream_New(NULL, totalLen);
	if (!s)
		return FALSE;

	Stream_Write_UINT8(s, RDPTUNNEL_ACTION_DATA);
	Stream_Write_UINT16(s, PayloadLength);
	Stream_Write_UINT8(s, HeaderLength);
	if (headers)
		Stream_Write(s, Stream_Buffer(headers), Stream_Length(headers));

	if (payload)
		Stream_Write(s, Stream_Buffer(payload), Stream_Length(payload));
	Stream_SealLength(s);

	status = BIO_write(channel->bio, Stream_Buffer(s), Stream_Length(s));
	Stream_Free(s, TRUE);
	return status >= 0;
}

multiTransportChannel* multitransportchannel_new(rdpMultitransport* multi, rdpRdp* rdp)
{
	multiTransportChannel* ret = calloc(1, sizeof(*ret));
	if (!ret)
		return NULL;

	ret->refCount = 1;
	ret->multiTransport = multi;
	ret->settings = rdp->settings;
	if (!ringbuffer_init(&ret->inputBuffer, 4096))
		goto error_rb;

	ret->timerEvent = CreateWaitableTimerA(NULL, TRUE, NULL);
	if (!ret->timerEvent)
		goto error_timer_create;

	LARGE_INTEGER due = { 0 };
	// due.QuadPart = 0;
	if (!SetWaitableTimer(ret->timerEvent, &due, 50, NULL, NULL, FALSE))
		goto error_timer_schedule;

	/* establish transport */
	ret->tls = freerdp_tls_new(rdp->context);
	if (!ret->tls)
		goto error_tls;

	rdpSettings* settings = rdp->settings;
	ret->tls->hostname = settings->ServerHostname;

	// WLog_DBG(TAG, "reqId=0x%" PRIx32 " (D)TLS handshake completed", reqId);

	if (settings->ServerMode)
	{
		ret->state = MTCHANNEL_HANDSHAKING;
		ret->createTunnelReq = server_channel_createTunnelReq;
		ret->createTunnelResp = server_channel_createTunnelResp;
	}
	else
	{
		ret->state = MTCHANNEL_WAITING_RESPONSE;
		ret->createTunnelReq = client_channel_createTunnelReq;
		ret->createTunnelResp = client_channel_createTunnelResp;
	}
	ret->handlePackets = mtchannel_handlePackets;
	ret->onDataPdu = mt_treat_data;
	ret->SendPdu = mt_send_pdu;

	return ret;

error_tls:
error_timer_schedule:
	CloseHandle(ret->timerEvent);
error_timer_create:
	ringbuffer_destroy(&ret->inputBuffer);
error_rb:
	free(ret);
	return NULL;
}

multiTransportChannel* multitransportchannel_client_new(rdpMultitransport* multi, UINT32 reqId,
                                                        BOOL lossy, const BYTE* cookie)
{
	rdpRdp* rdp = multi->rdp;
	rdpSettings* settings = rdp->settings;
	multiTransportChannel* ret = multitransportchannel_new(multi, rdp);
	if (!ret)
	{
		WLog_ERR(TAG, "error initializing MultiTransport channel");
		return NULL;
	}

	ret->isClient = TRUE;
	ret->lossy = lossy;
	ret->reqId = reqId;
	memcpy(ret->cookie, cookie, sizeof(ret->cookie));

	BOOL completed;
	ret->bio =
	    rdpUdpTransport_init_client(settings, ret->tls, lossy, cookie, settings->ServerHostname,
	                                settings->ServerPort, &completed);

	if (!ret->bio)
	{
		WLog_ERR(TAG, "failed to initiate %s transport reqId=0x%" PRIx32 "",
		         (lossy ? "lossy" : "reliable"), reqId);
		goto error_bio;
	}

	if (completed)
	{
		/* This should never happen as the SSL handshake is composed of multiple packets,
		 * but just in case
		 */
		ret->state = MTCHANNEL_WAITING_RESPONSE;
		if (!write_CreateTunnelReq(ret, ret->reqId, ret->cookie))
		{
			ret->state = MTCHANNEL_RESPONSE_ERROR;
		}
	}
	else
	{
		ret->state = MTCHANNEL_HANDSHAKING;
	}
	return ret;

error_bio:
	multitransportchannel_free(&ret);
	return NULL;
}

typedef struct
{
	int mask;
	const char* str;
} WhereInfo;

void ssl_info_cb(const SSL* ssl, int where, int val)
{
	char whereBuffer[200];
	WhereInfo whereInfos[] = {
		{ SSL_CB_ACCEPT_LOOP, "acceptLoop" },
		{ SSL_CB_ACCEPT_EXIT, "acceptExit" },
		{ SSL_CB_HANDSHAKE_START, "handshake start" },
		{ SSL_CB_HANDSHAKE_DONE, "handshake done" },
		{ SSL_CB_LOOP, "loop" },
		{ SSL_CB_EXIT, "exit" },
		{ SSL_CB_READ, "read" },
		{ SSL_CB_WRITE, "write" },
		{ SSL_CB_ALERT, "alert" },
	};
	whereBuffer[0] = 0;

	for (size_t i = 0; i < ARRAYSIZE(whereInfos); i++)
	{
		if (whereInfos[i].mask & where)
		{
			winpr_str_append(whereInfos[i].str, whereBuffer, sizeof(whereBuffer), ",");
		}
	}

	WLog_ERR(TAG, "ssl_info_cb: where=%s val:0x%x state=%s", whereBuffer, val,
	         SSL_state_string_long(ssl));
}

multiTransportChannel* multitransportchannel_server_new(rdpSettings* settings,
                                                        ListenerUdpPeer* peer)
{
	multiTransportChannel* ret = multitransportchannel_new(NULL, NULL /*settings*/);
	if (!ret)
	{
		WLog_ERR(TAG, "error initializing MultiTransport channel");
		return NULL;
	}

	ret->lossy = FALSE;
	ret->peer = peer;
	memcpy(ret->remoteAddr, peer->peerAddrStr, sizeof(peer->peerAddrStr));
	ret->rdpUdpBio = rdpUdpTransport_init_server(/*settings*/ NULL, ret->tls, peer);
	if (!ret->rdpUdpBio)
	{
		WLog_ERR(TAG, "unable to initialize BIO for %s", peer->peerAddrStr);
		goto error_bio;
	}

	const SSL_METHOD* methods = freerdp_tls_get_ssl_method(ret->lossy, FALSE);
	switch (freerdp_tls_accept_ex(ret->tls, ret->rdpUdpBio, settings, methods))
	{
		case TLS_HANDSHAKE_SUCCESS:
			ret->state = MTCHANNEL_WAITING_REQUEST;
			break;
		case TLS_HANDSHAKE_CONTINUE:
			break;
		case TLS_HANDSHAKE_ERROR:
		case TLS_HANDSHAKE_VERIFY_ERROR:
		default:
			WLog_ERR(TAG, "error during accept with %s", peer->peerAddrStr);
			goto error_bio;
	}

	SSL_set_info_callback(ret->tls->ssl, ssl_info_cb);
	/*SSL_set_msg_callback_arg(ret->tls->ssl, SSL_trace);
	SSL_set_msg_callback_arg(ret->tls->ssl, BIO_new_fp(stdout,0));*/
	ret->bio = ret->tls->bio;
	return ret;

error_bio:
	multitransportchannel_free(&ret);
	return NULL;
}

BOOL multitransportchannel_handles(multiTransportChannel* channel, HANDLE* phandles, DWORD* pcount)
{
	if (!channel->pollEvent)
	{
		if (BIO_get_event(channel->bio, &channel->pollEvent) < 1)
			return FALSE;
	}

	*phandles = channel->pollEvent;
	phandles++;
	*pcount += 1;

	if (channel->timerEvent)
	{
		*phandles = channel->timerEvent;
		*pcount += 1;
	}
	return TRUE;
}

int multitransportchannel_checkfds(multiTransportChannel* channel)
{
	if (WaitForSingleObject(channel->timerEvent, 0) == WAIT_OBJECT_0)
	{
		BIO_handle_timer(channel->bio);

		/* reset and rearm the timer */
		LARGE_INTEGER due = { 0 };
		if (!SetWaitableTimer(channel->timerEvent, &due, 50, NULL, NULL, FALSE))
		{
			WLog_ERR(TAG, "error rearming the timer");
			return -1;
		}
	}

	if (!channel->pollEvent)
	{
		if (BIO_get_event(channel->bio, &channel->pollEvent) < 1)
			return 0;
	}

	if (WaitForSingleObject(channel->pollEvent, 0) == WAIT_OBJECT_0)
	{
		if (!channel->handlePackets(channel))
			return -1;
	}

	return 0;
}

void multitransportchannel_setExternalHandling(multiTransportChannel* channel, BOOL v)
{
	WINPR_ASSERT(channel && channel->peer);

	channel->peer->handledExternaly = v;
}

void multitransportchannel_setDataCallback(multiTransportChannel* channel,
                                           MultiTransportChannelOnDataPduFn fn)
{
	WINPR_ASSERT(channel);
	channel->onDataPdu = fn;
}

rdpContext* multitransportchannel_context(multiTransportChannel* channel)
{
	WINPR_ASSERT(channel);
	return channel->multiTransport->rdp->context;
}

BOOL multitransportchannel_send(multiTransportChannel* channel, wStream* headers, wStream* payload)
{
	WINPR_ASSERT(channel);
	return channel->SendPdu(channel, headers, payload);
}

BOOL freerdp_send_udp(rdpRdp* rdp, BOOL lossy, wStream* headers, wStream* payload)
{
	rdpMultitransport* multi = rdp->multitransport;
	multiTransportChannel* channel;
	int channelIndex = lossy ? 1 : 0;

	channel = multi->channels[channelIndex];
	if (!channel)
	{
		WLog_ERR(TAG, "%s UDP channel not established", lossy ? "lossy" : "reliable");
		return FALSE;
	}

	return channel->SendPdu(channel, headers, payload);
}
