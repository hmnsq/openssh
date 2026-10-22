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

#अन्तर्भाव "includes.h"
#जइ !defined(HAVE_PPOLL) || !defined(HAVE_POLL) || defined(BROKEN_POLL)

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/time.h>
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#अन्तर्भाव <errno.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव "bsd-poll.h"

#जइ !defined(HAVE_PPOLL) || defined(BROKEN_POLL)
/*
 * A minimal implementation of ppoll(2), built on top of pselect(2).
 *
 * Only supports POLLIN, POLLOUT and POLLPRI flags in pfd.events and
 * revents. Notably POLLERR, POLLHUP and POLLNVAL are not supported.
 *
 * Supports pfd.fd = -1 meaning "unused" although it's not standard.
 */

पूर्णाङ्क
ppoll(संरचना pollfd *fds, nfds_t nfds, ध्रुव संरचना timespec *tmoutp,
    ध्रुव sigset_t *sigmask)
{
	nfds_t i;
	पूर्णाङ्क ret, fd, maxfd = 0;
	fd_set readfds, writefds, exceptfds;

	प्रति (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		जइ (fd != -1 && fd >= FD_SETSIZE) {
			errno = EINVAL;
			प्रत्यागम -1;
		}
		maxfd = MAX(maxfd, fd);
	}

	/* populate event bit vectors for the events we're interested in */
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);
	प्रति (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		जइ (fd == -1)
			अनुवर्त;
		जइ (fds[i].events & POLLIN)
			FD_SET(fd, &readfds);
		जइ (fds[i].events & POLLOUT)
			FD_SET(fd, &writefds);
		जइ (fds[i].events & POLLPRI)
			FD_SET(fd, &exceptfds);
	}

	ret = pselect(maxfd + 1, &readfds, &writefds, &exceptfds, tmoutp, sigmask);

	/* scan through select results and set poll() flags */
	प्रति (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		fds[i].revents = 0;
		जइ (fd == -1)
			अनुवर्त;
		जइ ((fds[i].events & POLLIN) && FD_ISSET(fd, &readfds))
			fds[i].revents |= POLLIN;
		जइ ((fds[i].events & POLLOUT) && FD_ISSET(fd, &writefds))
			fds[i].revents |= POLLOUT;
		जइ ((fds[i].events & POLLPRI) && FD_ISSET(fd, &exceptfds))
			fds[i].revents |= POLLPRI;
	}

	प्रत्यागम ret;
}
#endif /* !HAVE_PPOLL || BROKEN_POLL */

#जइ !defined(HAVE_POLL) || defined(BROKEN_POLL)
पूर्णाङ्क
poll(संरचना pollfd *fds, nfds_t nfds, पूर्णाङ्क timeout)
{
	संरचना timespec ts, *tsp = रिक्त;

	/* poll timeout is msec, ppoll is timespec (sec + nsec) */
	जइ (timeout >= 0) {
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout % 1000) * 1000000;
		tsp = &ts;
	}

	प्रत्यागम ppoll(fds, nfds, tsp, रिक्त);
}
#endif /* !HAVE_POLL || BROKEN_POLL */

#endif /* !HAVE_PPOLL || !HAVE_POLL || BROKEN_POLL */
