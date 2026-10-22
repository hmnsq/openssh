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

#அந்தர்பாவ "includes.h"
#எனில் !defined(HAVE_PPOLL) || !defined(HAVE_POLL) || defined(BROKEN_POLL)

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/time.h>
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ "bsd-poll.h"

#எனில் !defined(HAVE_PPOLL) || defined(BROKEN_POLL)
/*
 * A minimal implementation of ppoll(2), built on top of pselect(2).
 *
 * Only supports POLLIN, POLLOUT and POLLPRI flags in pfd.events and
 * revents. Notably POLLERR, POLLHUP and POLLNVAL are not supported.
 *
 * Supports pfd.fd = -1 meaning "unused" although it's not standard.
 */

முழு
ppoll(கட்டமைப்பு pollfd *fds, nfds_t nfds, மாறிலி கட்டமைப்பு timespec *tmoutp,
    மாறிலி sigset_t *sigmask)
{
	nfds_t i;
	முழு ret, fd, maxfd = 0;
	fd_set readfds, writefds, exceptfds;

	க்கு (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		எனில் (fd != -1 && fd >= FD_SETSIZE) {
			errno = EINVAL;
			திரும்பு -1;
		}
		maxfd = MAX(maxfd, fd);
	}

	/* populate event bit vectors for the events we're interested in */
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);
	க்கு (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		எனில் (fd == -1)
			தொடர்;
		எனில் (fds[i].events & POLLIN)
			FD_SET(fd, &readfds);
		எனில் (fds[i].events & POLLOUT)
			FD_SET(fd, &writefds);
		எனில் (fds[i].events & POLLPRI)
			FD_SET(fd, &exceptfds);
	}

	ret = pselect(maxfd + 1, &readfds, &writefds, &exceptfds, tmoutp, sigmask);

	/* scan through select results and set poll() flags */
	க்கு (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		fds[i].revents = 0;
		எனில் (fd == -1)
			தொடர்;
		எனில் ((fds[i].events & POLLIN) && FD_ISSET(fd, &readfds))
			fds[i].revents |= POLLIN;
		எனில் ((fds[i].events & POLLOUT) && FD_ISSET(fd, &writefds))
			fds[i].revents |= POLLOUT;
		எனில் ((fds[i].events & POLLPRI) && FD_ISSET(fd, &exceptfds))
			fds[i].revents |= POLLPRI;
	}

	திரும்பு ret;
}
#endif /* !HAVE_PPOLL || BROKEN_POLL */

#எனில் !defined(HAVE_POLL) || defined(BROKEN_POLL)
முழு
poll(கட்டமைப்பு pollfd *fds, nfds_t nfds, முழு timeout)
{
	கட்டமைப்பு timespec ts, *tsp = வெற்று;

	/* poll timeout is msec, ppoll is timespec (sec + nsec) */
	எனில் (timeout >= 0) {
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout % 1000) * 1000000;
		tsp = &ts;
	}

	திரும்பு ppoll(fds, nfds, tsp, வெற்று);
}
#endif /* !HAVE_POLL || BROKEN_POLL */

#endif /* !HAVE_PPOLL || !HAVE_POLL || BROKEN_POLL */
