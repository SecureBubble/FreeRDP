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
AIL    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FREERDP_CHANNEL_BUBCLI_SERVER_BUBCLI_1_H
#define FREERDP_CHANNEL_BUBCLI_SERVER_BUBCLI_1_H

#include <freerdp/api.h>
#include <freerdp/types.h>
#include <freerdp/freerdp.h>

#include <freerdp/channels/bubcli.h>

typedef struct _bubcli_server_context BubcliServerContext;
typedef struct _bubcli_server_private BubcliServerPrivate;

typedef UINT (*psBubcliStart)(BubcliServerContext* context);
typedef BOOL (*psBubcliStop)(BubcliServerContext* context);

/* Server side messages sending methods */
typedef UINT (*psBubcliErrorCodePdu)(BubcliServerContext* context,
                                      UINT32 errorCode);

struct _bubcli_server_context
{
	HANDLE vcm;
	void* custom;

	psBubcliStart Start;
	psBubcliStop Stop;

	/* Methods for sending server side messages */
	psBubcliErrorCodePdu ErrorCodePdu;
	BubcliServerPrivate* priv;
	rdpContext* rdpcontext;
};

#ifdef __cplusplus
extern "C"
{
#endif

	FREERDP_API BubcliServerContext* bubcli_server_context_new(HANDLE vcm);
	FREERDP_API void bubcli_server_context_free(BubcliServerContext* context);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_CHANNEL_BUBCLI_SERVER_BUBCLI_H */

