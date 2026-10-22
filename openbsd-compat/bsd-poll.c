/*
 * Copyright (c) 2004, 2005, 2007 Darren Tucker (dtucker at zip com au).
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਜੇ !defined(HAVE_PPOLL) || !defined(HAVE_POLL) || defined(BROKEN_POLL)

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_PARAM_H
# include <sys/param.h>
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_SELECT_H
# include <sys/select.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ "bsd-poll.h"

#ਜੇ !defined(HAVE_PPOLL) || defined(BROKEN_POLL)
/*
 * A minimal implementation of ppoll(2), built on top of pselect(2).
 *
 * Only supports POLLIN, POLLOUT and POLLPRI flags in pfd.events and
 * revents. Notably POLLERR, POLLHUP and POLLNVAL are not supported.
 *
 * Supports pfd.fd = -1 meaning "unused" although it's not standard.
 */

ਪੂਰਨ
ppoll(ਬਣਤਰ pollfd *fds, nfds_t nfds, ਅਚਲ ਬਣਤਰ timespec *tmoutp,
    ਅਚਲ sigset_t *sigmask)
{
	nfds_t i;
	ਪੂਰਨ ret, fd, maxfd = 0;
	fd_set readfds, writefds, exceptfds;

	ਲਈ (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		ਜੇ (fd != -1 && fd >= FD_SETSIZE) {
			errno = EINVAL;
			ਵਾਪਸ -1;
		}
		maxfd = MAX(maxfd, fd);
	}

	/* populate event bit vectors for the events we're interested in */
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);
	ਲਈ (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		ਜੇ (fd == -1)
			ਜਾਰੀ;
		ਜੇ (fds[i].events & POLLIN)
			FD_SET(fd, &readfds);
		ਜੇ (fds[i].events & POLLOUT)
			FD_SET(fd, &writefds);
		ਜੇ (fds[i].events & POLLPRI)
			FD_SET(fd, &exceptfds);
	}

	ret = pselect(maxfd + 1, &readfds, &writefds, &exceptfds, tmoutp, sigmask);

	/* scan through select results and set poll() flags */
	ਲਈ (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		fds[i].revents = 0;
		ਜੇ (fd == -1)
			ਜਾਰੀ;
		ਜੇ ((fds[i].events & POLLIN) && FD_ISSET(fd, &readfds))
			fds[i].revents |= POLLIN;
		ਜੇ ((fds[i].events & POLLOUT) && FD_ISSET(fd, &writefds))
			fds[i].revents |= POLLOUT;
		ਜੇ ((fds[i].events & POLLPRI) && FD_ISSET(fd, &exceptfds))
			fds[i].revents |= POLLPRI;
	}

	ਵਾਪਸ ret;
}
#ਜੇ_ਅੰਤ /* !HAVE_PPOLL || BROKEN_POLL */

#ਜੇ !defined(HAVE_POLL) || defined(BROKEN_POLL)
ਪੂਰਨ
poll(ਬਣਤਰ pollfd *fds, nfds_t nfds, ਪੂਰਨ timeout)
{
	ਬਣਤਰ timespec ts, *tsp = ਨਿਰਾ;

	/* poll timeout is msec, ppoll is timespec (sec + nsec) */
	ਜੇ (timeout >= 0) {
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout % 1000) * 1000000;
		tsp = &ts;
	}

	ਵਾਪਸ ppoll(fds, nfds, tsp, ਨਿਰਾ);
}
#ਜੇ_ਅੰਤ /* !HAVE_POLL || BROKEN_POLL */

#ਜੇ_ਅੰਤ /* !HAVE_PPOLL || !HAVE_POLL || BROKEN_POLL */
