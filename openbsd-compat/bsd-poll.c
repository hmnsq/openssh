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

#ضمن "includes.h"
#إذا !defined(HAVE_PPOLL) || !defined(HAVE_POLL) || defined(BROKEN_POLL)

#ضمن <sys/types.h>
#ضمن <sys/time.h>
#جيڪڏهن_وصف_ٿيل HAVE_SYS_PARAM_H
# include <sys/param.h>
#جيڪڏهن_پورو
#جيڪڏهن_وصف_ٿيل HAVE_SYS_SELECT_H
# include <sys/select.h>
#جيڪڏهن_پورو

#ضمن <errno.h>
#ضمن <signal.h>
#ضمن <stdlib.h>
#ضمن <unistd.h>
#ضمن "bsd-poll.h"

#إذا !defined(HAVE_PPOLL) || defined(BROKEN_POLL)
/*
 * A minimal implementation of ppoll(2), built on top of pselect(2).
 *
 * Only supports POLLIN, POLLOUT and POLLPRI flags in pfd.events and
 * revents. Notably POLLERR, POLLHUP and POLLNVAL are not supported.
 *
 * Supports pfd.fd = -1 meaning "unused" although it's not standard.
 */

صحيح
ppoll(بنية pollfd *fds, nfds_t nfds, ثابت بنية timespec *tmoutp,
    ثابت sigset_t *sigmask)
{
	nfds_t i;
	صحيح ret, fd, maxfd = 0;
	fd_set readfds, writefds, exceptfds;

	لكل (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		إذا (fd != -1 && fd >= FD_SETSIZE) {
			errno = EINVAL;
			أرجع -1;
		}
		maxfd = MAX(maxfd, fd);
	}

	/* populate event bit vectors for the events we're interested in */
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);
	لكل (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		إذا (fd == -1)
			استمر;
		إذا (fds[i].events & POLLIN)
			FD_SET(fd, &readfds);
		إذا (fds[i].events & POLLOUT)
			FD_SET(fd, &writefds);
		إذا (fds[i].events & POLLPRI)
			FD_SET(fd, &exceptfds);
	}

	ret = pselect(maxfd + 1, &readfds, &writefds, &exceptfds, tmoutp, sigmask);

	/* scan through select results and set poll() flags */
	لكل (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		fds[i].revents = 0;
		إذا (fd == -1)
			استمر;
		إذا ((fds[i].events & POLLIN) && FD_ISSET(fd, &readfds))
			fds[i].revents |= POLLIN;
		إذا ((fds[i].events & POLLOUT) && FD_ISSET(fd, &writefds))
			fds[i].revents |= POLLOUT;
		إذا ((fds[i].events & POLLPRI) && FD_ISSET(fd, &exceptfds))
			fds[i].revents |= POLLPRI;
	}

	أرجع ret;
}
#جيڪڏهن_پورو /* !HAVE_PPOLL || BROKEN_POLL */

#إذا !defined(HAVE_POLL) || defined(BROKEN_POLL)
صحيح
poll(بنية pollfd *fds, nfds_t nfds, صحيح timeout)
{
	بنية timespec ts, *tsp = عدم;

	/* poll timeout is msec, ppoll is timespec (sec + nsec) */
	إذا (timeout >= 0) {
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout % 1000) * 1000000;
		tsp = &ts;
	}

	أرجع ppoll(fds, nfds, tsp, عدم);
}
#جيڪڏهن_پورو /* !HAVE_POLL || BROKEN_POLL */

#جيڪڏهن_پورو /* !HAVE_PPOLL || !HAVE_POLL || BROKEN_POLL */
