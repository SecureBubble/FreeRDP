/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * RAIL Virtual Channel Plugin
 *
 * Copyright 2019 Mati Shabtay <matishabtay@gmail.com>
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

#include <freerdp/types.h>
#include <freerdp/constants.h>

#include <freerdp/channels/log.h>
#include <freerdp/server/bubcli.h>
#include <freerdp/channels/bubcli.h>

#include <winpr/crt.h>
#include <winpr/synch.h>
#include <winpr/thread.h>
#include <winpr/stream.h>

#include "bubcli_main.h"

#define TAG CHANNELS_TAG("bubcli.server")

#define BUBCLI_PDU_HEADER_LENGTH 4

static UINT bubcli_server_handle_messages(BubcliServerContext* context);

static UINT bubcli_read_pdu_header(wStream* s, UINT16* orderType, UINT16* orderLength)
{
	if (!s || !orderType || !orderLength)
		return ERROR_INVALID_PARAMETER;

	if (Stream_GetRemainingLength(s) < 4)
		return ERROR_INVALID_DATA;

	Stream_Read_UINT16(s, *orderType);   /* orderType (2 bytes) */
	Stream_Read_UINT16(s, *orderLength); /* orderLength (2 bytes) */
	return CHANNEL_RC_OK;
}

static void bubcli_write_pdu_header(wStream* s, UINT16 orderType, UINT16 orderLength)
{
	Stream_Write_UINT16(s, orderType);   /* orderType (2 bytes) */
	Stream_Write_UINT16(s, orderLength); /* orderLength (2 bytes) */
}

static wStream* bubcli_pdu_init(size_t length)
{
	wStream* s;
	s = Stream_New(NULL, length + BUBCLI_PDU_HEADER_LENGTH);

	if (!s)
		return NULL;

	Stream_Seek(s, BUBCLI_PDU_HEADER_LENGTH);
	return s;
}

/**
 * Sends a single bubcli PDU on the channel
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT bubcli_send(BubcliServerContext* context, wStream* s, ULONG length)
{
	UINT status = CHANNEL_RC_OK;
	ULONG written;

	if (!context)
		return CHANNEL_RC_BAD_INIT_HANDLE;

	if (!WTSVirtualChannelWrite(context->priv->bubcli_channel, (PCHAR)Stream_Buffer(s), length,
	                            &written))
	{
		WLog_ERR(TAG, "WTSVirtualChannelWrite failed!");
		status = ERROR_INTERNAL_ERROR;
	}

	return status;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT bubcli_server_send_pdu(BubcliServerContext* context, wStream* s, UINT16 orderType)
{
	UINT16 orderLength;

	if (!context || !s)
		return ERROR_INVALID_PARAMETER;

	orderLength = (UINT16)Stream_GetPosition(s);
	Stream_SetPosition(s, 0);
	bubcli_write_pdu_header(s, orderType, orderLength);
	Stream_SetPosition(s, orderLength);
	WLog_DBG(TAG, "Sending %d PDU, length: %" PRIu16 "", orderType, orderLength);
	return bubcli_send(context, s, orderLength);
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error coie
 */
static UINT bubcli_send_message_pdu(BubcliServerContext* context, UINT32 messageType, UINT32 messageCode,
                                    const char* session_id)
{
	wStream* s;
	UINT error;

	if (!context)
		return ERROR_INVALID_PARAMETER;

	WLog_INFO(TAG, "bubble.cli: session_id %s [len=%d], messagecode: %d", session_id, strlen(session_id), messageCode);
	s = bubcli_pdu_init(4 + 2 + strlen(session_id));
	if (!s)
	{
		WLog_ERR(TAG, "bubcli_pdu_init failed!");
		return CHANNEL_RC_NO_MEMORY;
	}

	Stream_Write_UINT32(s, messageCode);
	Stream_Write_UINT16(s, strlen(session_id));
	Stream_Write(s, session_id, strlen(session_id));

	error = bubcli_server_send_pdu(context, s, messageType);
	Stream_Free(s, TRUE);
	return error;
}

static DWORD WINAPI bubcli_server_thread(LPVOID arg)
{
	BubcliServerContext* context = (BubcliServerContext*)arg;
	BubcliServerPrivate* priv = context->priv;
	DWORD status;
	DWORD nCount = 0;
	HANDLE events[8];
	UINT error = CHANNEL_RC_OK;
	events[nCount++] = priv->channelEvent;
	events[nCount++] = priv->stopEvent;

	while (TRUE)
	{
		status = WaitForMultipleObjects(nCount, events, FALSE, INFINITE);

		if (status == WAIT_FAILED)
		{
			error = GetLastError();
			WLog_ERR(TAG, "WaitForMultipleObjects failed with error %" PRIu32 "!", error);
			break;
		}

		status = WaitForSingleObject(context->priv->stopEvent, 0);

		if (status == WAIT_FAILED)
		{
			error = GetLastError();
			WLog_ERR(TAG, "WaitForSingleObject failed with error %" PRIu32 "!", error);
			break;
		}

		if (status == WAIT_OBJECT_0)
			break;

		status = WaitForSingleObject(context->priv->channelEvent, 0);

		if (status == WAIT_FAILED)
		{
			error = GetLastError();
			WLog_ERR(
			    TAG,
			    "WaitForSingleObject(context->priv->channelEvent, 0) failed with error %" PRIu32
			    "!",
			    error);
			break;
		}

		if (status == WAIT_OBJECT_0)
		{
			if ((error = bubcli_server_handle_messages(context)))
			{
				WLog_ERR(TAG, "bubcli_server_handle_messages failed with error %" PRIu32 "", error);
				break;
			}
		}
	}

	if (error && context->rdpcontext)
		setChannelError(context->rdpcontext, error, "bubcli_server_thread reported an error");

	ExitThread(error);
	return error;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT bubcli_server_start(BubcliServerContext* context)
{
	void* buffer = NULL;
	DWORD bytesReturned;
	BubcliServerPrivate* priv = context->priv;
	UINT error = ERROR_INTERNAL_ERROR;
	priv->bubcli_channel =
	    WTSVirtualChannelOpen(context->vcm, WTS_CURRENT_SESSION, BUBCLI_SVC_CHANNEL_NAME);

	if (!priv->bubcli_channel)
	{
		WLog_ERR(TAG, "WTSVirtualChannelOpen failed!");
		return error;
	}

	if (!WTSVirtualChannelQuery(priv->bubcli_channel, WTSVirtualEventHandle, &buffer,
	                            &bytesReturned) ||
	    (bytesReturned != sizeof(HANDLE)))
	{
		WLog_ERR(TAG,
		         "error during WTSVirtualChannelQuery(WTSVirtualEventHandle) or invalid returned "
		         "size(%" PRIu32 ")",
		         bytesReturned);

		if (buffer)
			WTSFreeMemory(buffer);

		goto out_close;
	}

	CopyMemory(&priv->channelEvent, buffer, sizeof(HANDLE));
	WTSFreeMemory(buffer);
	context->priv->stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	if (!context->priv->stopEvent)
	{
		WLog_ERR(TAG, "CreateEvent failed!");
		goto out_close;
	}

	context->priv->thread = CreateThread(NULL, 0, bubcli_server_thread, (void*)context, 0, NULL);

	if (!context->priv->thread)
	{
		WLog_ERR(TAG, "CreateThread failed!");
		goto out_stop_event;
	}

	return CHANNEL_RC_OK;
out_stop_event:
	CloseHandle(context->priv->stopEvent);
	context->priv->stopEvent = NULL;
out_close:
	WTSVirtualChannelClose(context->priv->bubcli_channel);
	context->priv->bubcli_channel = NULL;
	return error;
}

static BOOL bubcli_server_stop(BubcliServerContext* context)
{
	BubcliServerPrivate* priv = (BubcliServerPrivate*)context->priv;

	if (priv->thread)
	{
		SetEvent(priv->stopEvent);

		if (WaitForSingleObject(priv->thread, INFINITE) == WAIT_FAILED)
		{
			WLog_ERR(TAG, "WaitForSingleObject failed with error %" PRIu32 "", GetLastError());
			return FALSE;
		}

		CloseHandle(priv->thread);
		CloseHandle(priv->stopEvent);
		priv->thread = NULL;
		priv->stopEvent = NULL;
	}

	if (priv->bubcli_channel)
	{
		WTSVirtualChannelClose(priv->bubcli_channel);
		priv->bubcli_channel = NULL;
	}

	priv->channelEvent = NULL;
	return TRUE;
}

BubcliServerContext* bubcli_server_context_new(HANDLE vcm)
{
	BubcliServerContext* context;
	BubcliServerPrivate* priv;
	context = (BubcliServerContext*)calloc(1, sizeof(BubcliServerContext));

	if (!context)
	{
		WLog_ERR(TAG, "calloc failed!");
		return NULL;
	}

	context->vcm = vcm;
	context->Start = bubcli_server_start;
	context->Stop = bubcli_server_stop;
	context->MessageCodePdu = bubcli_send_message_pdu;
	context->priv = priv = (BubcliServerPrivate*)calloc(1, sizeof(BubcliServerPrivate));

	if (!priv)
	{
		WLog_ERR(TAG, "calloc failed!");
		goto out_free;
	}

	/* Create shared input stream */
	priv->input_stream = Stream_New(NULL, 4096);

	if (!priv->input_stream)
	{
		WLog_ERR(TAG, "Stream_New failed!");
		goto out_free_priv;
	}

	return context;
out_free_priv:
	free(context->priv);
out_free:
	free(context);
	return NULL;
}

void bubcli_server_context_free(BubcliServerContext* context)
{
	if (context->priv)
		Stream_Free(context->priv->input_stream, TRUE);

	free(context->priv);
	free(context);
}

static UINT bubcli_server_handle_messages(BubcliServerContext* context)
{
	UINT status = CHANNEL_RC_OK;
	DWORD bytesReturned;
	UINT16 orderType;
	UINT16 orderLength;
	BubcliServerPrivate* priv = context->priv;
	wStream* s = priv->input_stream;

	/* Read header */
	if (!Stream_EnsureRemainingCapacity(s, BUBCLI_PDU_HEADER_LENGTH))
	{
		WLog_ERR(TAG, "Stream_EnsureRemainingCapacity failed, BUBCLI_PDU_HEADER_LENGTH");
		return CHANNEL_RC_NO_MEMORY;
	}

	if (!WTSVirtualChannelRead(priv->bubcli_channel, 0, (PCHAR)Stream_Pointer(s),
	                           BUBCLI_PDU_HEADER_LENGTH, &bytesReturned))
	{
		if (GetLastError() == ERROR_NO_DATA)
			return ERROR_NO_DATA;

		WLog_ERR(TAG, "channel connection closed");
		return ERROR_INTERNAL_ERROR;
	}

	/* Parse header */
	if ((status = bubcli_read_pdu_header(s, &orderType, &orderLength)) != CHANNEL_RC_OK)
	{
		WLog_ERR(TAG, "bubcli_read_pdu_header failed with error %" PRIu32 "!", status);
		return status;
	}

	if (!Stream_EnsureRemainingCapacity(s, orderLength - BUBCLI_PDU_HEADER_LENGTH))
	{
		WLog_ERR(TAG,
		         "Stream_EnsureRemainingCapacity failed, orderLength - BUBCLI_PDU_HEADER_LENGTH");
		return CHANNEL_RC_NO_MEMORY;
	}

	/* Read body */
	if (!WTSVirtualChannelRead(priv->bubcli_channel, 0, (PCHAR)Stream_Pointer(s),
	                           orderLength - BUBCLI_PDU_HEADER_LENGTH, &bytesReturned))
	{
		if (GetLastError() == ERROR_NO_DATA)
			return ERROR_NO_DATA;

		WLog_ERR(TAG, "channel connection closed");
		return ERROR_INTERNAL_ERROR;
	}

	WLog_DBG(TAG, "Received %d PDU, length:%" PRIu16 "", orderType, orderLength);

	switch (orderType)
	{
		case 0:
		{
			// TODO: Add here messages that can be received from the client
			break;
		}

		default:
			WLog_ERR(TAG, "Unknown BUBCLI PDU order received.");
			return ERROR_INVALID_DATA;
	}

	Stream_SetPosition(s, 0);
	return status;
}
