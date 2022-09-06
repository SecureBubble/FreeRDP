/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * BUBBLE RDP CHANNEL
 *
 * Copyright 2021 Kobi Mizrachi <kmizrachi18@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FREERDP_CHANNEL_BUBBLE_CLIENT_BUBBLE_H
#define FREERDP_CHANNEL_BUBBLE_CLIENT_BUBBLE_H

#include <freerdp/api.h>
#include <freerdp/types.h>

#include <freerdp/message.h>

/**
 * Client Interface
 */

typedef struct _bubble_client_context BubbleClientContext;

typedef UINT (*pcBubbleOnOpen)(BubbleClientContext* context);
typedef UINT (*pcBubbleActiveWindowChanged)(BubbleClientContext* context, UINT64 timestamp, const char* proc_name, 
						const char* window_title, const int keyboard_layout);
typedef UINT (*pcBubbleKeepAlive)(BubbleClientContext* context, UINT64 timestamp);
typedef UINT (*pcBubbleDisconnectRequest)(BubbleClientContext* context);
typedef UINT (*pcBubbleInputFocusChanged)(BubbleClientContext* context, BOOL is_password);
typedef UINT (*pcBubbleUacWindowState)(BubbleClientContext* context, BOOL is_shown);
typedef UINT (*pcBubbleNewProcessCreated)(BubbleClientContext* context, UINT64 timestamp, const char* process_name, const int process_id, 
						const char* cmdline, const char* process_hash);
typedef UINT (*pcBubblePreQueryModeResponse)(BubbleClientContext* context);
typedef UINT (*pcBubbleRequestAppExecute)(BubbleClientContext* context);
typedef UINT (*pcBubbleOnNetstatData)(BubbleClientContext* context, UINT64 timestamp, const char* netstat_data);

struct _bubble_client_context
{
	void* handle;
	void* custom;

	pcBubbleOnOpen OnOpen;
	pcBubbleOnNetstatData OnNetstatData;
	pcBubbleActiveWindowChanged ActiveWindowChanged;
	pcBubbleKeepAlive KeepAlive;
	pcBubbleDisconnectRequest DisconnectRequested;
	pcBubbleInputFocusChanged InputFocusChanged;
	pcBubbleUacWindowState UacWindowStateUpdate;
	pcBubbleNewProcessCreated NewProcessCreated;
	pcBubblePreQueryModeResponse PreQueryModeResponse;
	pcBubbleRequestAppExecute ExecuteApp;
};

#endif /* FREERDP_CHANNEL_BUBBLE_CLIENT_BUBBLE_H */

