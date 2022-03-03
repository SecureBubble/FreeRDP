/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * BUBCLI Virtual Channel Plugin
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

#ifndef FREERDP_CHANNEL_BUBCLI_SERVER_MAIN_H
#define FREERDP_CHANNEL_BUBCLI_SERVER_MAIN_H

#include <freerdp/server/bubcli.h>

#include <winpr/crt.h>
#include <winpr/wlog.h>
#include <winpr/stream.h>

struct _bubcli_server_private
{
	HANDLE thread;
	HANDLE stopEvent;
	HANDLE channelEvent;
	void* bubcli_channel;

	wStream* input_stream;

	DWORD channelFlags;
};

#endif /* FREERDP_CHANNEL_BUBCLI_SERVER_MAIN_H */
