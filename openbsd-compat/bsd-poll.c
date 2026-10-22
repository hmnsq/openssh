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

#অন্তর্ভাৱ "includes.h"
#যদি !defined(HAVE_PPOLL) || !defined(HAVE_POLL) || defined(BROKEN_POLL)

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/time.h>
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <signal.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ "bsd-poll.h"

#যদি !defined(HAVE_PPOLL) || defined(BROKEN_POLL)
/*
 * A minimal implementation of ppoll(2), built on top of pselect(2).
 *
 * Only supports POLLIN, POLLOUT and POLLPRI flags in pfd.events and
 * revents. Notably POLLERR, POLLHUP and POLLNVAL are not supported.
 *
 * Supports pfd.fd = -1 meaning "unused" although it's not standard.
 */

পূর্ণাঙ্ক
ppoll(সংরচনা pollfd *fds, nfds_t nfds, ধ্রুৱ সংরচনা timespec *tmoutp,
    ধ্রুৱ sigset_t *sigmask)
{
	nfds_t i;
	পূর্ণাঙ্ক ret, fd, maxfd = 0;
	fd_set readfds, writefds, exceptfds;

	বাবে (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		যদি (fd != -1 && fd >= FD_SETSIZE) {
			errno = EINVAL;
			ঘূৰাই -1;
		}
		maxfd = MAX(maxfd, fd);
	}

	/* populate event bit vectors for the events we're interested in */
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);
	বাবে (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		যদি (fd == -1)
			অনুৱর্ত;
		যদি (fds[i].events & POLLIN)
			FD_SET(fd, &readfds);
		যদি (fds[i].events & POLLOUT)
			FD_SET(fd, &writefds);
		যদি (fds[i].events & POLLPRI)
			FD_SET(fd, &exceptfds);
	}

	ret = pselect(maxfd + 1, &readfds, &writefds, &exceptfds, tmoutp, sigmask);

	/* scan through select results and set poll() flags */
	বাবে (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		fds[i].revents = 0;
		যদি (fd == -1)
			অনুৱর্ত;
		যদি ((fds[i].events & POLLIN) && FD_ISSET(fd, &readfds))
			fds[i].revents |= POLLIN;
		যদি ((fds[i].events & POLLOUT) && FD_ISSET(fd, &writefds))
			fds[i].revents |= POLLOUT;
		যদি ((fds[i].events & POLLPRI) && FD_ISSET(fd, &exceptfds))
			fds[i].revents |= POLLPRI;
	}

	ঘূৰাই ret;
}
#endif /* !HAVE_PPOLL || BROKEN_POLL */

#যদি !defined(HAVE_POLL) || defined(BROKEN_POLL)
পূর্ণাঙ্ক
poll(সংরচনা pollfd *fds, nfds_t nfds, পূর্ণাঙ্ক timeout)
{
	সংরচনা timespec ts, *tsp = রিক্ত;

	/* poll timeout is msec, ppoll is timespec (sec + nsec) */
	যদি (timeout >= 0) {
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout % 1000) * 1000000;
		tsp = &ts;
	}

	ঘূৰাই ppoll(fds, nfds, tsp, রিক্ত);
}
#endif /* !HAVE_POLL || BROKEN_POLL */

#endif /* !HAVE_PPOLL || !HAVE_POLL || BROKEN_POLL */
