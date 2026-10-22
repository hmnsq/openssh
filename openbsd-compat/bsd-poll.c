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

#అన్తర్భావ "includes.h"
#ఒకవేళ !defined(HAVE_PPOLL) || !defined(HAVE_POLL) || defined(BROKEN_POLL)

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/time.h>
#నిర్వచితమైతే HAVE_SYS_PARAM_H
# include <sys/param.h>
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_SYS_SELECT_H
# include <sys/select.h>
#అయితే_ముగింపు

#అన్తర్భావ <errno.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ "bsd-poll.h"

#ఒకవేళ !defined(HAVE_PPOLL) || defined(BROKEN_POLL)
/*
 * A minimal implementation of ppoll(2), built on top of pselect(2).
 *
 * Only supports POLLIN, POLLOUT and POLLPRI flags in pfd.events and
 * revents. Notably POLLERR, POLLHUP and POLLNVAL are not supported.
 *
 * Supports pfd.fd = -1 meaning "unused" although it's not standard.
 */

పూర్ణాంకం
ppoll(నిర్మాణం pollfd *fds, nfds_t nfds, స్థిరరాశి నిర్మాణం timespec *tmoutp,
    స్థిరరాశి sigset_t *sigmask)
{
	nfds_t i;
	పూర్ణాంకం ret, fd, maxfd = 0;
	fd_set readfds, writefds, exceptfds;

	కొరకు (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		ఒకవేళ (fd != -1 && fd >= FD_SETSIZE) {
			errno = EINVAL;
			తిరిగి -1;
		}
		maxfd = MAX(maxfd, fd);
	}

	/* populate event bit vectors for the events we're interested in */
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);
	కొరకు (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		ఒకవేళ (fd == -1)
			కొనసాగు;
		ఒకవేళ (fds[i].events & POLLIN)
			FD_SET(fd, &readfds);
		ఒకవేళ (fds[i].events & POLLOUT)
			FD_SET(fd, &writefds);
		ఒకవేళ (fds[i].events & POLLPRI)
			FD_SET(fd, &exceptfds);
	}

	ret = pselect(maxfd + 1, &readfds, &writefds, &exceptfds, tmoutp, sigmask);

	/* scan through select results and set poll() flags */
	కొరకు (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		fds[i].revents = 0;
		ఒకవేళ (fd == -1)
			కొనసాగు;
		ఒకవేళ ((fds[i].events & POLLIN) && FD_ISSET(fd, &readfds))
			fds[i].revents |= POLLIN;
		ఒకవేళ ((fds[i].events & POLLOUT) && FD_ISSET(fd, &writefds))
			fds[i].revents |= POLLOUT;
		ఒకవేళ ((fds[i].events & POLLPRI) && FD_ISSET(fd, &exceptfds))
			fds[i].revents |= POLLPRI;
	}

	తిరిగి ret;
}
#అయితే_ముగింపు /* !HAVE_PPOLL || BROKEN_POLL */

#ఒకవేళ !defined(HAVE_POLL) || defined(BROKEN_POLL)
పూర్ణాంకం
poll(నిర్మాణం pollfd *fds, nfds_t nfds, పూర్ణాంకం timeout)
{
	నిర్మాణం timespec ts, *tsp = ఖాళీ;

	/* poll timeout is msec, ppoll is timespec (sec + nsec) */
	ఒకవేళ (timeout >= 0) {
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout % 1000) * 1000000;
		tsp = &ts;
	}

	తిరిగి ppoll(fds, nfds, tsp, ఖాళీ);
}
#అయితే_ముగింపు /* !HAVE_POLL || BROKEN_POLL */

#అయితే_ముగింపు /* !HAVE_PPOLL || !HAVE_POLL || BROKEN_POLL */
