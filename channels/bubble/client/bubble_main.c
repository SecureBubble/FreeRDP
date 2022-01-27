/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * RAIL Virtual Channel Plugin
 *
 * Copyright 2021 Kobi Mizrachi <kmizrachi18@gmail.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <winpr/crt.h>

#include <freerdp/types.h>
#include <freerdp/constants.h>

#include "bubble_main.h"
#include <freerdp/client/bubble.h>

#include "../../../channels/client/addin.h"

#define TAG "bubble.client"

BubbleClientContext* bubble_get_client_interface(bubblePlugin* bubble)
{
	BubbleClientContext* pInterface;

	if (!bubble)
		return NULL;

	pInterface = (BubbleClientContext*)bubble->channelEntryPoints.pInterface;
	return pInterface;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT bubble_send(bubblePlugin* bubble, wStream* s)
{
	UINT status;

	if (!bubble)
	{
		Stream_Free(s, TRUE);
		return CHANNEL_RC_BAD_INIT_HANDLE;
	}

	status = bubble->channelEntryPoints.pVirtualChannelWriteEx(
	    bubble->InitHandle, bubble->OpenHandle, Stream_Buffer(s), (UINT32)Stream_GetPosition(s), s);

	if (status != CHANNEL_RC_OK)
	{
		Stream_Free(s, TRUE);
		WLog_ERR(TAG, "pVirtualChannelWriteEx failed with %s [%08" PRIX32 "]",
		         WTSErrorToString(status), status);
	}

	return status;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
UINT bubble_send_channel_data(bubblePlugin* bubble, wStream* src)
{
	wStream* s;
	size_t length;

	if (!bubble || !src)
		return ERROR_INVALID_PARAMETER;

	length = Stream_GetPosition(src);
	s = Stream_New(NULL, length);

	if (!s)
	{
		WLog_ERR(TAG, "Stream_New failed!");
		return CHANNEL_RC_NO_MEMORY;
	}

	Stream_Write(s, Stream_Buffer(src), length);
	return bubble_send(bubble, s);
}

/**
 * Callback Interface
 */

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT bubble_on_open(BubbleClientContext* context)
{
	WLog_INFO(TAG, "sespobe on open");
	return CHANNEL_RC_OK;
}

static VOID VCAPITYPE bubble_virtual_channel_open_event_ex(LPVOID lpUserParam, DWORD openHandle,
                                                           UINT event, LPVOID pData,
                                                           UINT32 dataLength, UINT32 totalLength,
                                                           UINT32 dataFlags)
{
	UINT error = CHANNEL_RC_OK;
	bubblePlugin* bubble = (bubblePlugin*)lpUserParam;

	switch (event)
	{
		case CHANNEL_EVENT_DATA_RECEIVED:
			if (!bubble || (bubble->OpenHandle != openHandle))
			{
				WLog_ERR(TAG, "error no match");
				return;
			}

			if ((error = channel_client_post_message(bubble->MsgsHandle, pData, dataLength,
			                                         totalLength, dataFlags)))
			{
				WLog_ERR(TAG,
				         "bubble_virtual_channel_event_data_received"
				         " failed with error %" PRIu32 "!",
				         error);
			}
			break;

		case CHANNEL_EVENT_WRITE_CANCELLED:
		case CHANNEL_EVENT_WRITE_COMPLETE:
		{
			wStream* s = (wStream*)pData;
			Stream_Free(s, TRUE);
		}
		break;

		case CHANNEL_EVENT_USER:
			break;
	}

	if (error && bubble && bubble->rdpcontext)
		setChannelError(bubble->rdpcontext, error,
		                "bubble_virtual_channel_open_event reported an error");

	return;
}

static char* bubble_read_string(wStream* s)
{
	if (Stream_GetRemainingLength(s) < 4)
	{
		WLog_ERR(TAG, "not enough bytes");
		return NULL;
	}

	UINT32 length = 0;
	Stream_Read_UINT32_BE(s, length);
	if (Stream_GetRemainingLength(s) < length)
	{
		WLog_ERR(TAG, "not enough bytes2: have %d, expected %d", Stream_GetRemainingLength(s),
		         length);
		return NULL;
	}

	WLog_INFO(TAG, "got string of length %d", length);
	char* buffer = (char*)malloc(length + 1);
	if (!buffer)
	{
		return NULL;
	}

	Stream_Read(s, buffer, length);
	buffer[length] = '\0';
	return buffer;
}

static UINT bubble_handle_process_created(BubbleClientContext* context, wStream* s)
{
	UINT error = CHANNEL_RC_OK;
	UINT32 proc_id;
	UINT64 timestamp;

	if (Stream_GetRemainingLength(s) < 8 + 2)
		return ERROR_INTERNAL_ERROR;

	Stream_Read_UINT64_BE(s, timestamp); // 8 bytes
	Stream_Read_UINT32_BE(s, proc_id);   // 2 bytes

	char* proc_name = bubble_read_string(s);
	if (!proc_name)
		return ERROR_INTERNAL_ERROR;

	char* cmdline = bubble_read_string(s);
	if (!cmdline)
	{
		free(proc_name);
		return ERROR_INTERNAL_ERROR;
	}

	WLog_INFO(TAG, "new process: time=%d, proc_id=%d, proc_name=%s, cmdline=%s", timestamp, proc_id,
	          proc_name, cmdline);

	IFCALLRET(context->NewProcessCreated, error, context, proc_name, cmdline);

	free(proc_name);
	free(cmdline);
	return error;
}

static UINT bubble_handle_active_window_changed(BubbleClientContext* context, wStream* s)
{
	UINT64 timestamp;
	UINT error = CHANNEL_RC_OK;

	if (Stream_GetRemainingLength(s) < 8)
		return ERROR_INTERNAL_ERROR;

	Stream_Read_UINT64_BE(s, timestamp); // 8 bytes

	char* proc = bubble_read_string(s);
	if (!proc)
		return ERROR_INTERNAL_ERROR;

	char* window_title = bubble_read_string(s);
	if (!window_title)
	{
		free(proc);
		return ERROR_INTERNAL_ERROR;
	}

	WLog_INFO(TAG, "active window changed: time=%d, process name=%s, window title=%s", timestamp,
	          proc, window_title);

	IFCALLRET(context->ActiveWindowChanged, error, context, proc, window_title);

	free(proc);
	free(window_title);
	return error;
}

static UINT bubble_handle_keep_alive(BubbleClientContext* context, wStream* s)
{
	UINT64 timestamp;
	UINT error = CHANNEL_RC_OK;

	if (Stream_GetRemainingLength(s) < 8)
		return ERROR_INTERNAL_ERROR;

	Stream_Read_UINT64_BE(s, timestamp); // 8 bytes
	IFCALLRET(context->KeepAlive, error, context, timestamp);

	WLog_DBG(TAG, "received keep alive: time=%d", timestamp);
	return error;
}

static UINT bubble_handle_input_focus_change(BubbleClientContext* context, wStream* s)
{
	BOOL is_password;
	UINT error = CHANNEL_RC_OK;

	if (Stream_GetRemainingLength(s) < 1)
		return ERROR_INTERNAL_ERROR;

	Stream_Read_UINT8(s, is_password); // 8 bytes
	WLog_INFO(TAG, "current input is password=%d", is_password);

	IFCALLRET(context->InputFocusChanged, error, context, is_password);
	return error;
}

static UINT bubble_handle_uac_window_state(BubbleClientContext* context, wStream* s)
{
	BOOL is_uac_shown;
	UINT error = CHANNEL_RC_OK;

	if (Stream_GetRemainingLength(s) < 1)
		return ERROR_INTERNAL_ERROR;

	Stream_Read_UINT8(s, is_uac_shown); // 8 bytes
	WLog_DBG(TAG, "is uac shown=%d", is_uac_shown);
	IFCALLRET(context->UacWindowStateUpdate, error, context, is_uac_shown);
	return error;
}

static UINT bubble_request_exec_app(BubbleClientContext* context)
{
	bubblePlugin* plugin = (bubblePlugin*)context->handle;
	rdpSettings* settings = plugin->rdpcontext->settings;

	wStream* data_in = NULL;
	if (settings->RemoteApplicationMode)
	{
		if (settings->RemoteApplicationProgram == NULL ||
		    strlen(settings->RemoteApplicationProgram) <= 2)
		{
			WLog_ERR(TAG, "bubble: remote application is invalid");
			return ERROR_INTERNAL_ERROR;
		}

		const char* app_to_execute = (const char*)(settings->RemoteApplicationProgram + 2);

		WLog_INFO(TAG, "requesting agent to execute %s [len=%d]", app_to_execute,
		          strlen(app_to_execute));
		WLog_INFO(TAG, "lbinfolen=%d", settings->LoadBalanceInfoLength);

		data_in = Stream_New(NULL, 2 + 2 + strlen(app_to_execute) + 2 + strlen(settings->Username) +
		                               2 + settings->LoadBalanceInfoLength);
		Stream_Write_UINT16(data_in, settings->RemoteApplicationMode);
		Stream_Write_UINT16(data_in, strlen(app_to_execute));
		Stream_Write_UINT16(data_in, strlen(settings->Username));
		Stream_Write_UINT16(data_in, settings->LoadBalanceInfoLength);
		Stream_Write(data_in, app_to_execute, strlen(app_to_execute));
		Stream_Write(data_in, settings->Username, strlen(settings->Username));
		Stream_Write(data_in, settings->LoadBalanceInfo, settings->LoadBalanceInfoLength);
	}
	else
	{
		data_in = Stream_New(NULL, 4);
		Stream_Write_UINT16(data_in, settings->RemoteApplicationMode);
		Stream_Write_UINT16(data_in, 0); // padding
	}

	return bubble_send(plugin, data_in);
}

static UINT bubble_handle_query_mode(BubbleClientContext* context, wStream* s)
{
	UINT error = CHANNEL_RC_OK;
	WLog_INFO(TAG, "%s", __FUNCTION__);

	WLog_INFO(TAG, "before calling pre response callback");
	IFCALLRET(context->PreQueryModeResponse, error, context);
	WLog_INFO(TAG, "after calling pre response callback");

	bubble_request_exec_app(context);
	return error;
}

static UINT bubble_handle_disconnection_request(BubbleClientContext* context, wStream* s)
{
	UINT error = CHANNEL_RC_OK;
	WLog_INFO(TAG, "%s", __FUNCTION__);
	IFCALLRET(context->DisconnectRequested, error, context);
	return error;
}

static UINT bubble_handle_network_status(BubbleClientContext* context, wStream* s)
{
	UINT64 timestamp;
	UINT error = CHANNEL_RC_OK;

	if (Stream_GetRemainingLength(s) < 8)
		return ERROR_INTERNAL_ERROR;

	Stream_Read_UINT64_BE(s, timestamp); // 8 bytes

	char* netstat_data = bubble_read_string(s);
	if (!netstat_data)
		return ERROR_INTERNAL_ERROR;

	WLog_INFO(TAG, "%s", netstat_data);
	WLog_INFO(TAG, "%s", __FUNCTION__);

	IFCALLRET(context->OnNetstatData, error, context, timestamp, netstat_data);

	free(netstat_data);
	return error;
}
static UINT bubble_order_recv(LPVOID userdata, wStream* s)
{
	bubblePlugin* bubble = userdata;
	BubbleClientContext* context = bubble->context;
	UINT16 orderType;

	if (!bubble || !s)
		return ERROR_INVALID_PARAMETER;

	Stream_Read_UINT16_BE(s, orderType);

	switch (orderType)
	{
		case 0: // PROCESS_CREATED
			bubble_handle_process_created(context, s);
			break;
		case 1: // ACTIVE_WINDOW_CHANGED
			bubble_handle_active_window_changed(context, s);
			break;
		case 2: // KEEP_ALIVE
			bubble_handle_keep_alive(context, s);
			break;
		case 3: // KEEP_ALIVE
			bubble_handle_input_focus_change(context, s);
			break;
		case 4: // KEEP_ALIVE
			bubble_handle_uac_window_state(context, s);
			break;
		case 5:
			bubble_handle_query_mode(context, s);
			break;
		case 6:
			bubble_handle_disconnection_request(context, s);
			break;
		case 8: // NETWORK STATUS
			bubble_handle_network_status(context, s);
			break;

		default:
			WLog_ERR(TAG, "Unknown SEESPDU order 0x%08" PRIx32 " received.", orderType);
			return ERROR_INTERNAL_ERROR;
	}

	Stream_Free(s, TRUE);
	return CHANNEL_RC_OK;
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT bubble_virtual_channel_event_connected(bubblePlugin* bubble, LPVOID pData,
                                                   UINT32 dataLength)
{
	BubbleClientContext* context = bubble_get_client_interface(bubble);
	UINT status = CHANNEL_RC_OK;

	WINPR_ASSERT(bubble);

	if (context)
	{
		IFCALLRET(context->OnOpen, status, context);

		if (status != CHANNEL_RC_OK)
			WLog_ERR(TAG, "context->OnOpen failed with %s [%08" PRIX32 "]",
			         WTSErrorToString(status), status);
	}
	bubble->MsgsHandle =
	    channel_client_create_handler(bubble->rdpcontext, bubble, bubble_order_recv, "bubble");
	if (!bubble->MsgsHandle)
		return ERROR_INTERNAL_ERROR;

	return bubble->channelEntryPoints.pVirtualChannelOpenEx(bubble->InitHandle, &bubble->OpenHandle,
	                                                        bubble->channelDef.name,
	                                                        bubble_virtual_channel_open_event_ex);
}

/**
 * Function description
 *
 * @return 0 on success, otherwise a Win32 error code
 */
static UINT bubble_virtual_channel_event_disconnected(bubblePlugin* bubble)
{
	UINT rc;

	channel_client_quit_handler(bubble->MsgsHandle);
	if (bubble->OpenHandle == 0)
		return CHANNEL_RC_OK;

	WINPR_ASSERT(bubble->channelEntryPoints.pVirtualChannelCloseEx);
	rc = bubble->channelEntryPoints.pVirtualChannelCloseEx(bubble->InitHandle, bubble->OpenHandle);

	if (CHANNEL_RC_OK != rc)
	{
		WLog_ERR(TAG, "pVirtualChannelCloseEx failed with %s [%08" PRIX32 "]", WTSErrorToString(rc),
		         rc);
		return rc;
	}

	bubble->OpenHandle = 0;

	return CHANNEL_RC_OK;
}

static void bubble_virtual_channel_event_terminated(bubblePlugin* bubble)
{
	bubble->InitHandle = 0;
	free(bubble->context);
	free(bubble);
}

static VOID VCAPITYPE bubble_virtual_channel_init_event_ex(LPVOID lpUserParam, LPVOID pInitHandle,
                                                           UINT event, LPVOID pData,
                                                           UINT dataLength)
{
	UINT error = CHANNEL_RC_OK;
	bubblePlugin* bubble = (bubblePlugin*)lpUserParam;

	if (!bubble || (bubble->InitHandle != pInitHandle))
	{
		WLog_ERR(TAG, "error no match");
		return;
	}

	switch (event)
	{
		case CHANNEL_EVENT_CONNECTED:
			if ((error = bubble_virtual_channel_event_connected(bubble, pData, dataLength)))
				WLog_ERR(TAG,
				         "bubble_virtual_channel_event_connected failed with error %" PRIu32 "!",
				         error);

			break;

		case CHANNEL_EVENT_DISCONNECTED:
			if ((error = bubble_virtual_channel_event_disconnected(bubble)))
				WLog_ERR(TAG,
				         "bubble_virtual_channel_event_disconnected failed with error %" PRIu32 "!",
				         error);

			break;

		case CHANNEL_EVENT_TERMINATED:
			bubble_virtual_channel_event_terminated(bubble);
			break;

		case CHANNEL_EVENT_ATTACHED:
		case CHANNEL_EVENT_DETACHED:
		default:
			break;
	}

	if (error && bubble->rdpcontext)
		setChannelError(bubble->rdpcontext, error,
		                "bubble_virtual_channel_init_event_ex reported an error");
}

/* rail is always built-in */
#define VirtualChannelEntryEx bubble_VirtualChannelEntryEx

BOOL VCAPITYPE VirtualChannelEntryEx(PCHANNEL_ENTRY_POINTS pEntryPoints, PVOID pInitHandle)
{
	UINT rc;
	bubblePlugin* bubble;
	BubbleClientContext* context = NULL;
	CHANNEL_ENTRY_POINTS_FREERDP_EX* pEntryPointsEx;
	BOOL isFreerdp = FALSE;
	bubble = (bubblePlugin*)calloc(1, sizeof(bubblePlugin));

	if (!bubble)
	{
		WLog_ERR(TAG, "calloc failed!");
		return FALSE;
	}

	bubble->channelDef.options = CHANNEL_OPTION_INITIALIZED;
	sprintf_s(bubble->channelDef.name, ARRAYSIZE(bubble->channelDef.name), "bubble");
	pEntryPointsEx = (CHANNEL_ENTRY_POINTS_FREERDP_EX*)pEntryPoints;

	if ((pEntryPointsEx->cbSize >= sizeof(CHANNEL_ENTRY_POINTS_FREERDP_EX)) &&
	    (pEntryPointsEx->MagicNumber == FREERDP_CHANNEL_MAGIC_NUMBER))
	{
		context = (BubbleClientContext*)calloc(1, sizeof(BubbleClientContext));

		if (!context)
		{
			WLog_ERR(TAG, "calloc failed!");
			free(bubble);
			return FALSE;
		}

		context->handle = (void*)bubble;
		context->custom = NULL;
		context->OnOpen = bubble_on_open;
		context->ExecuteApp = bubble_request_exec_app;

		bubble->rdpcontext = pEntryPointsEx->context;
		bubble->context = context;
		isFreerdp = TRUE;
	}

	bubble->log = WLog_Get("com.freerdp.channels.bubble.client");
	WLog_Print(bubble->log, WLOG_DEBUG, "VirtualChannelEntryEx");
	CopyMemory(&(bubble->channelEntryPoints), pEntryPoints,
	           sizeof(CHANNEL_ENTRY_POINTS_FREERDP_EX));
	bubble->InitHandle = pInitHandle;
	rc = bubble->channelEntryPoints.pVirtualChannelInitEx(
	    bubble, context, pInitHandle, &bubble->channelDef, 1, VIRTUAL_CHANNEL_VERSION_WIN2000,
	    bubble_virtual_channel_init_event_ex);

	if (CHANNEL_RC_OK != rc)
	{
		WLog_ERR(TAG, "failed with %s [%08" PRIX32 "]", WTSErrorToString(rc), rc);
		goto error_out;
	}

	bubble->channelEntryPoints.pInterface = context;
	return TRUE;
error_out:

	if (isFreerdp)
		free(bubble->context);

	free(bubble);
	return FALSE;
}
