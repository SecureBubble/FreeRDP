/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Proxy Session Probe Virtual Channel Plugin
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

#ifndef FREERDP_CHANNEL_BUBBLE_CLIENT_MAIN_H
#define FREERDP_CHANNEL_BUBBLE_CLIENT_MAIN_H

#include <freerdp/rail.h>
#include <freerdp/svc.h>
#include <freerdp/addin.h>
#include <freerdp/settings.h>
#include <freerdp/client/bubble.h>

#include <winpr/crt.h>
#include <winpr/wlog.h>
#include <winpr/stream.h>

#include "../bubble_common.h"

struct bubble_plugin
{
	CHANNEL_DEF channelDef;
	CHANNEL_ENTRY_POINTS_FREERDP_EX channelEntryPoints;

	BubbleClientContext* context;

	wLog* log;
	void* InitHandle;
	DWORD OpenHandle;
	void* MsgsHandle;
	rdpContext* rdpcontext;
	DWORD channelBuildNumber;
	DWORD channelFlags;
	RAIL_CLIENT_STATUS_ORDER clientStatus;
	BOOL sendHandshake;
};
typedef struct bubble_plugin bubblePlugin;

#endif /* FREERDP_CHANNEL_BUBBLE_CLIENT_MAIN_H */
