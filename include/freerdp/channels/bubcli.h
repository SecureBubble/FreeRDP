/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * Dynamic Virtual Channel Virtual Channel
 *
 * Copyright 2021 Armin Novak <anovak@thincast.com>
 * Copyright 2021 Thincast Technologies GmbH
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

#ifndef FREERDP_CHANNEL_BUBCLI_H
#define FREERDP_CHANNEL_BUBCLI_H

#include <freerdp/api.h>
#include <freerdp/types.h>

#define BUBCLI_SVC_CHANNEL_NAME "bubcli"

typedef enum
{
	BUBCLI_ERROR_CODE_PDU = 0,
	BUBCLI_INFO_CODE_PDU = 1
} BubcliChannelPDU;

#endif /* FREERDP_CHANNEL_BUBCLI_H */
