/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * MULTITRANSPORT PDUs
 *
 * Copyright 2014 Dell Software <Mike.McDonald@software.dell.com>
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

#include <winpr/assert.h>
#include <freerdp/config.h>
#include <freerdp/log.h>

#include "settings.h"
#include "rdp.h"
#include "multitransport.h"
#include "udpchannel.h"

enum
{
	CHANNEL_INDEX_RELIABLE = 0,
	CHANNEL_INDEX_LOSSY = 1
};

#define TAG FREERDP_TAG("core.multitransport")

BOOL multitransport_match_reliable(rdpMultitransport* multi, UINT16 reqId, const BYTE* cookie)
{
	WINPR_ASSERT(multi);
	WINPR_ASSERT(cookie);

	return (multi->reliableReqId == reqId) &&
	       memcmp(cookie, multi->reliableCookie, RDPUDP_COOKIE_LEN) == 0;
}

state_run_t multitransport_recv_request(rdpMultitransport* multi, wStream* s)
{
	WINPR_ASSERT(multi);
	rdpSettings* settings = multi->rdp->settings;

	if (settings->ServerMode)
	{
		WLog_ERR(TAG, "not expecting a multi-transport request in server mode");
		return STATE_RUN_FAILED;
	}

	if (!Stream_CheckAndLogRequiredLength(TAG, s, 24))
		return STATE_RUN_FAILED;

	UINT32 requestId = 0;
	UINT16 requestedProto = 0;
	UINT16 reserved = 0;
	const BYTE* cookie = NULL;

	Stream_Read_UINT32(s, requestId);      /* requestId (4 bytes) */
	Stream_Read_UINT16(s, requestedProto); /* requestedProtocol (2 bytes) */
	Stream_Read_UINT16(s, reserved);       /* reserved (2 bytes) */
	cookie = Stream_ConstPointer(s);
	Stream_Seek(s, RDPUDP_COOKIE_LEN); /* securityCookie (16 bytes) */
	if (reserved != 0)
	{
		/*
		 * If the reserved filed is not 0 the request PDU seems to contain some extra data.
		 * If the reserved value is 1, then two bytes of 0 (probably a version field)
		 * are followed by a JSON payload (not null terminated, until the end of the packet.
		 * There seems to be no dedicated length field)
		 *
		 * for now just ignore all that
		 */
		WLog_WARN(TAG,
		          "reserved is %" PRIu16 " instead of 0, skipping %" PRIuz "bytes of unknown data",
		          reserved, Stream_GetRemainingLength(s));
		(void)Stream_SafeSeek(s, Stream_GetRemainingLength(s));
	}

	WINPR_ASSERT(multi->MtRequest);
	return multi->MtRequest(multi, requestId, requestedProto, cookie);
}

static BOOL multitransport_request_send(rdpMultitransport* multi, UINT32 reqId, UINT16 reqProto,
                                        const BYTE* cookie)
{
	WINPR_ASSERT(multi);
	UINT16 sec_flags = 0;
	wStream* s = rdp_message_channel_pdu_init(multi->rdp, &sec_flags);
	if (!s)
		return FALSE;

	if (!Stream_EnsureRemainingCapacity(s, 24))
	{
		Stream_Release(s);
		return FALSE;
	}

	Stream_Write_UINT32(s, reqId);              /* requestId (4 bytes) */
	Stream_Write_UINT16(s, reqProto);           /* requestedProtocol (2 bytes) */
	Stream_Zero(s, 2);                          /* reserved (2 bytes) */
	Stream_Write(s, cookie, RDPUDP_COOKIE_LEN); /* securityCookie (16 bytes) */

	return rdp_send_message_channel_pdu(multi->rdp, s, sec_flags | SEC_TRANSPORT_REQ);
}

state_run_t multitransport_server_request(rdpMultitransport* multi, UINT16 reqProto)
{
	WINPR_ASSERT(multi);

	/* TODO: move this static variable to the listener */
	static UINT32 reqId = 0;

	if (reqProto == INITIATE_REQUEST_PROTOCOL_UDPFECR)
	{
		multi->reliableReqId = reqId++;
		winpr_RAND(multi->reliableCookie, sizeof(multi->reliableCookie));

		return multitransport_request_send(multi, multi->reliableReqId, reqProto,
		                                   multi->reliableCookie)
		           ? STATE_RUN_SUCCESS
		           : STATE_RUN_FAILED;
	}

	WLog_ERR(TAG, "only reliable transport is supported");
	return STATE_RUN_CONTINUE;
}

BOOL multitransport_client_send_response(rdpMultitransport* multi, UINT32 reqId, HRESULT hr)
{
	WINPR_ASSERT(multi);

	UINT16 sec_flags = 0;
	wStream* s = rdp_message_channel_pdu_init(multi->rdp, &sec_flags);
	if (!s)
		return FALSE;

	if (!Stream_EnsureRemainingCapacity(s, 8))
	{
		Stream_Release(s);
		return FALSE;
	}

	Stream_Write_UINT32(s, reqId); /* requestId (4 bytes) */

	/* [MS-RDPBCGR] 2.2.15.2 Client Initiate Multitransport Response PDU defines this as 4byte
	 * UNSIGNED but https://learn.microsoft.com/en-us/windows/win32/learnwin32/error-codes-in-com
	 * defines this as signed... assume the spec is (implicitly) assuming twos complement. */
	Stream_Write_INT32(s, hr); /* HResult (4 bytes) */
	return rdp_send_message_channel_pdu(multi->rdp, s, sec_flags | SEC_TRANSPORT_RSP);
}

state_run_t multitransport_recv_response(rdpMultitransport* multi, wStream* s)
{
	WINPR_ASSERT(multi && multi->rdp);
	WINPR_ASSERT(s);

	rdpSettings* settings = multi->rdp->settings;
	WINPR_ASSERT(settings);

	if (!settings->ServerMode)
	{
		WLog_ERR(TAG, "client is not expecting a multi-transport resp packet");
		return STATE_RUN_FAILED;
	}

	if (!Stream_CheckAndLogRequiredLength(TAG, s, 8))
		return STATE_RUN_FAILED;

	UINT32 requestId = Stream_Get_UINT32(s); /* requestId (4 bytes) */
	UINT32 hr = Stream_Get_UINT32(s);        /* hrResponse (4 bytes) */

	state_run_t res = STATE_RUN_SUCCESS;
	IFCALLRET(multi->MtResponse, res, multi, requestId, hr);
	return res;
}

static state_run_t multitransport_udp(rdpMultitransport* multi, UINT32 reqId,
                                         UINT16 reqProto,
                                         const BYTE* cookie)
{
	int channelIndex;
	const char* channelTypeStr;

	if (reqProto & INITIATE_REQUEST_PROTOCOL_UDPFECR)
	{
		channelIndex = CHANNEL_INDEX_RELIABLE;
		channelTypeStr = "reliable";
	}
	else if (reqProto & INITIATE_REQUEST_PROTOCOL_UDPFECL)
	{
		channelIndex = CHANNEL_INDEX_LOSSY;
		channelTypeStr = "lossy";
	}
	else
	{
		WLog_ERR(TAG, "invalid requested proto");
		goto out_error;
	}

	if (multi->channels[channelIndex])
	{
		WLog_ERR(TAG, "error %s channel already set", channelTypeStr);
		goto out_error;
	}

	multiTransportChannel* channel = multitransportchannel_client_new(
	    multi, reqId, !!(reqProto & INITIATE_REQUEST_PROTOCOL_UDPFECL), cookie);
	if (!channel)
	{
		WLog_ERR(TAG, "error creating %s channel", channelTypeStr);
		goto out_error;
	}

	multi->channels[channelIndex] = channel;
	return STATE_RUN_SUCCESS;

out_error:
	return multitransport_client_send_response(multi, reqId, E_ABORT) ? STATE_RUN_SUCCESS
	                                                                  : STATE_RUN_FAILED;
}

static state_run_t multitransport_server_handle_response(rdpMultitransport* multi,
                                                         WINPR_ATTR_UNUSED UINT32 reqId,
                                                         WINPR_ATTR_UNUSED UINT32 hrResponse)
{
	rdpRdp* rdp = multi->rdp;

	if (!rdp_server_transition_to_state(rdp, CONNECTION_STATE_CAPABILITIES_EXCHANGE_DEMAND_ACTIVE))
		return STATE_RUN_FAILED;

	return STATE_RUN_CONTINUE;
}

rdpMultitransport* multitransport_new(rdpRdp* rdp, WINPR_ATTR_UNUSED UINT16 protocol)
{
	WINPR_ASSERT(rdp);

	rdpSettings* settings = rdp->settings;
	WINPR_ASSERT(settings);

	rdpMultitransport* multi = calloc(1, sizeof(rdpMultitransport));
	if (!multi)
		return NULL;

	if (settings->ServerMode)
	{
		multi->MtResponse = multitransport_server_handle_response;
	}
	else
	{
		multi->MtRequest = multitransport_udp;
	}

	multi->rdp = rdp;
	return multi;
}

void multitransport_free(rdpMultitransport* multi)
{
	for (int i = 0; i < 2; i++)
	{
		if (multi->channels[i])
			multitransportchannel_free(&multi->channels[i]);
	}
	free(multi);
}

DWORD multitransport_get_event_handles(rdpMultitransport* multi, HANDLE* events, DWORD count)
{
	DWORD ret = 0;
	int i;

	for (i = 0; (i < 2) && (ret <= count); i++)
	{
		multiTransportChannel* channel = multi->channels[i];
		if (!channel)
			continue;

		if (!multitransportchannel_handles(channel, &events[ret], &ret))
			return 0;
	}

	return ret;
}

int multitransport_check_fds(rdpMultitransport* multi)
{
	int status = 0;
	int i;

	for (i = 0; i < 2; i++)
	{
		multiTransportChannel* channel = multi->channels[i];
		if (!channel)
			continue;

		status = multitransportchannel_checkfds(channel);
	}

	return status;
}
