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

#ଅନ୍ତର୍ଭାଵ "includes.h"
#ଯଦି !defined(HAVE_PPOLL) || !defined(HAVE_POLL) || defined(BROKEN_POLL)

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/time.h>
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ "bsd-poll.h"

#ଯଦି !defined(HAVE_PPOLL) || defined(BROKEN_POLL)
/*
 * A minimal implementation of ppoll(2), built on top of pselect(2).
 *
 * Only supports POLLIN, POLLOUT and POLLPRI flags in pfd.events and
 * revents. Notably POLLERR, POLLHUP and POLLNVAL are not supported.
 *
 * Supports pfd.fd = -1 meaning "unused" although it's not standard.
 */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ppoll(ସଂରଚନା pollfd *fds, nfds_t nfds, ଅଚଳ ସଂରଚନା timespec *tmoutp,
    ଅଚଳ sigset_t *sigmask)
{
	nfds_t i;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret, fd, maxfd = 0;
	fd_set readfds, writefds, exceptfds;

	ପାଇଁ (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		ଯଦି (fd != -1 && fd >= FD_SETSIZE) {
			errno = EINVAL;
			ଫେରନ୍ତୁ -1;
		}
		maxfd = MAX(maxfd, fd);
	}

	/* populate event bit vectors for the events we're interested in */
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);
	ପାଇଁ (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		ଯଦି (fd == -1)
			ଜାରି;
		ଯଦି (fds[i].events & POLLIN)
			FD_SET(fd, &readfds);
		ଯଦି (fds[i].events & POLLOUT)
			FD_SET(fd, &writefds);
		ଯଦି (fds[i].events & POLLPRI)
			FD_SET(fd, &exceptfds);
	}

	ret = pselect(maxfd + 1, &readfds, &writefds, &exceptfds, tmoutp, sigmask);

	/* scan through select results and set poll() flags */
	ପାଇଁ (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		fds[i].revents = 0;
		ଯଦି (fd == -1)
			ଜାରି;
		ଯଦି ((fds[i].events & POLLIN) && FD_ISSET(fd, &readfds))
			fds[i].revents |= POLLIN;
		ଯଦି ((fds[i].events & POLLOUT) && FD_ISSET(fd, &writefds))
			fds[i].revents |= POLLOUT;
		ଯଦି ((fds[i].events & POLLPRI) && FD_ISSET(fd, &exceptfds))
			fds[i].revents |= POLLPRI;
	}

	ଫେରନ୍ତୁ ret;
}
#endif /* !HAVE_PPOLL || BROKEN_POLL */

#ଯଦି !defined(HAVE_POLL) || defined(BROKEN_POLL)
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
poll(ସଂରଚନା pollfd *fds, nfds_t nfds, ପୂର୍ଣ୍ଣସଂଖ୍ୟା timeout)
{
	ସଂରଚନା timespec ts, *tsp = ଖାଲି;

	/* poll timeout is msec, ppoll is timespec (sec + nsec) */
	ଯଦି (timeout >= 0) {
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout % 1000) * 1000000;
		tsp = &ts;
	}

	ଫେରନ୍ତୁ ppoll(fds, nfds, tsp, ଖାଲି);
}
#endif /* !HAVE_POLL || BROKEN_POLL */

#endif /* !HAVE_PPOLL || !HAVE_POLL || BROKEN_POLL */
