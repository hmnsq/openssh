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

#include "includes.h"
#nếu !defined(HAVE_PPOLL) || !defined(HAVE_POLL) || defined(BROKEN_POLL)

#include <sys/types.h>
#include <sys/time.h>
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "bsd-poll.h"

#nếu !defined(HAVE_PPOLL) || defined(BROKEN_POLL)
/*
 * A minimal implementation of ppoll(2), built on top of pselect(2).
 *
 * Only supports POLLIN, POLLOUT and POLLPRI flags in pfd.events and
 * revents. Notably POLLERR, POLLHUP and POLLNVAL are not supported.
 *
 * Supports pfd.fd = -1 meaning "unused" although it's not standard.
 */

số_nguyên
ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmoutp,
    const sigset_t *sigmask)
{
	nfds_t i;
	số_nguyên ret, fd, maxfd = 0;
	fd_set readfds, writefds, exceptfds;

	cho (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		nếu (fd != -1 && fd >= FD_SETSIZE) {
			errno = EINVAL;
			trả_về -1;
		}
		maxfd = MAX(maxfd, fd);
	}

	/* populate event bit vectors for the events we're interested in */
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);
	cho (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		nếu (fd == -1)
			continue;
		nếu (fds[i].events & POLLIN)
			FD_SET(fd, &readfds);
		nếu (fds[i].events & POLLOUT)
			FD_SET(fd, &writefds);
		nếu (fds[i].events & POLLPRI)
			FD_SET(fd, &exceptfds);
	}

	ret = pselect(maxfd + 1, &readfds, &writefds, &exceptfds, tmoutp, sigmask);

	/* scan through select results and set poll() flags */
	cho (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		fds[i].revents = 0;
		nếu (fd == -1)
			continue;
		nếu ((fds[i].events & POLLIN) && FD_ISSET(fd, &readfds))
			fds[i].revents |= POLLIN;
		nếu ((fds[i].events & POLLOUT) && FD_ISSET(fd, &writefds))
			fds[i].revents |= POLLOUT;
		nếu ((fds[i].events & POLLPRI) && FD_ISSET(fd, &exceptfds))
			fds[i].revents |= POLLPRI;
	}

	trả_về ret;
}
#endif /* !HAVE_PPOLL || BROKEN_POLL */

#nếu !defined(HAVE_POLL) || defined(BROKEN_POLL)
số_nguyên
poll(struct pollfd *fds, nfds_t nfds, số_nguyên timeout)
{
	struct timespec ts, *tsp = NULL;

	/* poll timeout is msec, ppoll is timespec (sec + nsec) */
	nếu (timeout >= 0) {
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout % 1000) * 1000000;
		tsp = &ts;
	}

	trả_về ppoll(fds, nfds, tsp, NULL);
}
#endif /* !HAVE_POLL || BROKEN_POLL */

#endif /* !HAVE_PPOLL || !HAVE_POLL || BROKEN_POLL */
