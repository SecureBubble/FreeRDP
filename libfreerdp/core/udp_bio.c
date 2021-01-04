
#include <errno.h>

#include <winpr/file.h>
#include <winpr/thread.h>
#include <winpr/synch.h>
#include <winpr/collections.h>

#ifdef WINPR_HAVE_POLL_H
#include <poll.h>
#else
#include <time.h>
#include <sys/select.h>
#endif

#include "tcp.h"

int udp_doSelect(SOCKET sockfd, int timeout) {
	int status;
#ifdef WINPR_HAVE_POLL_H
	struct pollfd pollset;
	pollset.fd = sockfd;
	pollset.events = POLLIN;
	pollset.revents = 0;

	do
	{
		status = poll(&pollset, 1, timeout);
	} while ((status < 0) && (errno == EINTR));

#else
	fd_set rset = { 0 };
	struct timeval tv = { 0 };
	FD_ZERO(&rset);
	FD_SET(sockfd, &rset);

	if (timeout)
	{
		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;
	}

	do
	{
		status = select(sockfd + 1, &rset, nullptr, nullptr, timeout ? &tv : nullptr);
	} while ((status < 0) && (errno == EINTR));
#endif
	return status;
}

