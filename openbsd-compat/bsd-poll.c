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

#അന്തര്ഭാവ "includes.h"
#എങ്കിൽ !defined(HAVE_PPOLL) || !defined(HAVE_POLL) || defined(BROKEN_POLL)

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/time.h>
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ "bsd-poll.h"

#എങ്കിൽ !defined(HAVE_PPOLL) || defined(BROKEN_POLL)
/*
 * A minimal implementation of ppoll(2), built on top of pselect(2).
 *
 * Only supports POLLIN, POLLOUT and POLLPRI flags in pfd.events and
 * revents. Notably POLLERR, POLLHUP and POLLNVAL are not supported.
 *
 * Supports pfd.fd = -1 meaning "unused" although it's not standard.
 */

പൂർണ്ണസംഖ്യ
ppoll(ഘടന pollfd *fds, nfds_t nfds, സ്ഥിരം ഘടന timespec *tmoutp,
    സ്ഥിരം sigset_t *sigmask)
{
	nfds_t i;
	പൂർണ്ണസംഖ്യ ret, fd, maxfd = 0;
	fd_set readfds, writefds, exceptfds;

	വേണ്ടി (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		എങ്കിൽ (fd != -1 && fd >= FD_SETSIZE) {
			errno = EINVAL;
			തിരികെ -1;
		}
		maxfd = MAX(maxfd, fd);
	}

	/* populate event bit vectors for the events we're interested in */
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);
	വേണ്ടി (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		എങ്കിൽ (fd == -1)
			തുടരുക;
		എങ്കിൽ (fds[i].events & POLLIN)
			FD_SET(fd, &readfds);
		എങ്കിൽ (fds[i].events & POLLOUT)
			FD_SET(fd, &writefds);
		എങ്കിൽ (fds[i].events & POLLPRI)
			FD_SET(fd, &exceptfds);
	}

	ret = pselect(maxfd + 1, &readfds, &writefds, &exceptfds, tmoutp, sigmask);

	/* scan through select results and set poll() flags */
	വേണ്ടി (i = 0; i < nfds; i++) {
		fd = fds[i].fd;
		fds[i].revents = 0;
		എങ്കിൽ (fd == -1)
			തുടരുക;
		എങ്കിൽ ((fds[i].events & POLLIN) && FD_ISSET(fd, &readfds))
			fds[i].revents |= POLLIN;
		എങ്കിൽ ((fds[i].events & POLLOUT) && FD_ISSET(fd, &writefds))
			fds[i].revents |= POLLOUT;
		എങ്കിൽ ((fds[i].events & POLLPRI) && FD_ISSET(fd, &exceptfds))
			fds[i].revents |= POLLPRI;
	}

	തിരികെ ret;
}
#endif /* !HAVE_PPOLL || BROKEN_POLL */

#എങ്കിൽ !defined(HAVE_POLL) || defined(BROKEN_POLL)
പൂർണ്ണസംഖ്യ
poll(ഘടന pollfd *fds, nfds_t nfds, പൂർണ്ണസംഖ്യ timeout)
{
	ഘടന timespec ts, *tsp = ശൂന്യ;

	/* poll timeout is msec, ppoll is timespec (sec + nsec) */
	എങ്കിൽ (timeout >= 0) {
		ts.tv_sec = timeout / 1000;
		ts.tv_nsec = (timeout % 1000) * 1000000;
		tsp = &ts;
	}

	തിരികെ ppoll(fds, nfds, tsp, ശൂന്യ);
}
#endif /* !HAVE_POLL || BROKEN_POLL */

#endif /* !HAVE_PPOLL || !HAVE_POLL || BROKEN_POLL */
