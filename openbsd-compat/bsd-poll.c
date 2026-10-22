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

#ಅನ್ತರ್ಭಾವ "includes.h"
#ಯದಿ !defined(HAVE_PPOLL) || !defined(HAVE_POLL) || defined(BROKEN_POLL)

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ "bsd-poll.h"

#ಯದಿ !defined(HAVE_PPOLL) || defined(BROKEN_POLL)
/*
 * A minimal implementation of ppoll(2), built on top of pselect(2).
 *
 * Only supports POLLIN, POLLOUT and POLLPRI flags in pfd.events and
 * revents. Notably POLLERR, POLLHUP and POLLNVAL are not supported.
 *
 * Supports pfd.fd = -1 meaning "unused" although it's not standard.
 */

ಪೂರ್ಣಾಙ್ಕ
ppoll(ಸಂರಚನಾ pollfd *fds, nfds_t nfds, ಧ್ರುವ ಸಂರಚನಾ timespec *tmoutp,
    ಧ್ರುವ sigset_t *sigmask)
{
	nfds_t i;
	ಪೂರ್ಣಾಙ್ಕ ret, fd, maxfd = 0;
	fd_set readfds, writefds, exceptfds;

	ಪ್ರತಿ (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		ಯದಿ (fd != -1 && fd >= FD_SETSIZE) {
			errno = EINVAL;
			ಪ್ರತ್ಯಾಗಮ -1;
		}
		maxfd = MAX(maxfd, fd);
	}

	/* populate event bit vectors for the events we're interested in */
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);
	ಪ್ರತಿ (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		ಯದಿ (fd == -1)
			ಅನುವರ್ತ;
		ಯದಿ (fds[i].events & POLLIN)
			FD_SET(fd, &readfds);
		ಯದಿ (fds[i].events & POLLOUT)
			FD_SET(fd, &writefds);
		ಯದಿ (fds[i].events & POLLPRI)
			FD_SET(fd, &exceptfds);
	}

	ret = pselect(maxfd + 1, &readfds, &writefds, &exceptfds, tmoutp, sigmask);

	/* scan through select results and set poll() flags */
	ಪ್ರತಿ (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		fds[i].revents = 0;
		ಯದಿ (fd == -1)
			ಅನುವರ್ತ;
		ಯದಿ ((fds[i].events & POLLIN) && FD_ISSET(fd, &readfds))
			fds[i].revents |= POLLIN;
		ಯದಿ ((fds[i].events & POLLOUT) && FD_ISSET(fd, &writefds))
			fds[i].revents |= POLLOUT;
		ಯದಿ ((fds[i].events & POLLPRI) && FD_ISSET(fd, &exceptfds))
			fds[i].revents |= POLLPRI;
	}

	ಪ್ರತ್ಯಾಗಮ ret;
}
#endif /* !HAVE_PPOLL || BROKEN_POLL */

#ಯದಿ !defined(HAVE_POLL) || defined(BROKEN_POLL)
ಪೂರ್ಣಾಙ್ಕ
poll(ಸಂರಚನಾ pollfd *fds, nfds_t nfds, ಪೂರ್ಣಾಙ್ಕ timeout)
{
	ಸಂರಚನಾ timespec ts, *tsp = ರಿಕ್ತ;

	/* poll timeout is msec, ppoll is timespec (sec + nsec) */
	ಯದಿ (timeout >= 0) {
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout % 1000) * 1000000;
		tsp = &ts;
	}

	ಪ್ರತ್ಯಾಗಮ ppoll(fds, nfds, tsp, ರಿಕ್ತ);
}
#endif /* !HAVE_POLL || BROKEN_POLL */

#endif /* !HAVE_PPOLL || !HAVE_POLL || BROKEN_POLL */
