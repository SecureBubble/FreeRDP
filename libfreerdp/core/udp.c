/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * UDP
 *
 * Copyright 2020 David Fort <contact@hardening-consulting.com>
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
#include "tcp.h"
#include "udp.h"

#ifndef _WIN32
#include <fcntl.h>
#endif

SOCKET freerdp_udp_connect(rdpSettings* settings, const char* hostname, int port,
                           struct sockaddr_storage* saddr)
{
	struct addrinfo* addr;
	SOCKET ret = INVALID_SOCKET;
	int r;
	struct addrinfo* result = addr = freerdp_resolve_host(hostname, port, SOCK_DGRAM, AI_PASSIVE);
	if (!result)
		return INVALID_SOCKET;

	if (!settings->PreferIPv6OverIPv4)
	{
		while (addr && addr->ai_family == AF_INET6)
			addr = addr->ai_next;
		if (!addr)
			goto out;
	}

	ret = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
	if (ret > 0)
	{
		memcpy(saddr, addr->ai_addr, addr->ai_addrlen);
		r = connect(ret, addr->ai_addr, addr->ai_addrlen);
		if (r < 0)
		{
			closesocket(ret);
			ret = INVALID_SOCKET;
			goto out;
		}

		int flags;
		if ((flags = fcntl(ret, F_GETFL)) < 0 || fcntl(ret, F_SETFL, flags | O_NONBLOCK))
		{
			closesocket(ret);
			ret = INVALID_SOCKET;
		}
	}
out:
	freeaddrinfo(result);
	return ret;
}

BIO* freerdp_udp_BIO(SOCKET sock, struct sockaddr* addr)
{
	WINPR_ASSERT(addr);

	BIO* udpBio = BIO_new_dgram(sock, BIO_NOCLOSE);
	if (!udpBio)
		return NULL;
	BIO_ctrl_dgram_connect(udpBio, addr);

	WINPR_BIO_SIMPLE_SOCKET* d = calloc(1, sizeof(*d));
	if (!d)
		goto fail_private;

	d->socket = sock;
	d->hEvent = WSACreateEvent();
	if (!d->hEvent)
		goto fail_event;
	if (WSAEventSelect(sock, d->hEvent, FD_READ | FD_ACCEPT | FD_CLOSE) != 0)
		goto fail_select;

	BIO_set_data(udpBio, d);
	return udpBio;

fail_select:
	WSACloseEvent(d->hEvent);
fail_event:
	free(d);
fail_private:
	BIO_free(udpBio);
	return NULL;
}
