/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * multitransport
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
#ifndef FREERDP_MULTITRANSPORT_H
#define FREERDP_MULTITRANSPORT_H

#include <winpr/wtypes.h>
#include <freerdp/api.h>

#define RDPUDP_COOKIE_LEN 16

typedef struct rdp_multitransport rdpMultitransport;
typedef struct rdp_multitransport_channel multiTransportChannel;

#ifdef __cplusplus
extern "C"
{
#endif
	typedef BOOL (*MultiTransportChannelOnDataPduFn)(multiTransportChannel* channel, wStream* s);
	typedef BOOL (*MultiTransportChannelSendPduFn)(multiTransportChannel* channel, wStream* headers,
	                                               wStream* payload);

	/**
	 * Returns the rdpContext associated with this UDP channel
	 * @param channel the UDP channel
	 * @return the rdpContext pointer
	 */
	FREERDP_API rdpContext* multitransportchannel_context(multiTransportChannel* channel);

	FREERDP_API BOOL multitransport_match_reliable(rdpMultitransport* multi, UINT16 reqId,
	                                               const BYTE* cookie);

	FREERDP_API void multitransportchannel_setExternalHandling(multiTransportChannel* channel,
	                                                           BOOL v);
	/** Sets the callback that is invoked when receiving data on the UDP channel (dynamic channel
	 * content)
	 *
	 * @param channel the UDP channel
	 * @param fn the callback
	 */
	FREERDP_API void multitransportchannel_setDataCallback(multiTransportChannel* channel,
	                                                       MultiTransportChannelOnDataPduFn fn);

	/**
	 * Sends data on a UDP channel forging a multi-transport packet with data and headers payload
	 *
	 * @param channel the UDP channel
	 * @param headers the headers payload, NULL if none
	 * @param payload the data payload, NULL if none
	 * @return if the operation was successful
	 */
	FREERDP_API BOOL multitransportchannel_send(multiTransportChannel* channel, wStream* headers,
	                                            wStream* payload);

#ifdef __cplusplus
}
#endif

#endif /* FREERDP_MULTITRANSPORT_H */
