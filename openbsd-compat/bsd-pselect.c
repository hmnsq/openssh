/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2021 Darren Tucker (dtucker at dtucker net).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"
#ifndef HAVE_PSELECT

#include <sys/types.h>
#include <sys/time.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"

#ifndef HAVE_SIGHANDLER_T
typedef void (*sighandler_t)(정수);
#endif

static sighandler_t saved_sighandler[_NSIG];
static 정수 notify_pipe[2];	/* 0 = read end, 1 = write end */

/*
 * Because the debugging for this is so noisy, we only output on the first
 * call, and suppress it thereafter.
 */
static 정수 suppress_debug;

static void
pselect_set_nonblock(정수 fd)
{
	정수 val;

	만약 ((val = fcntl(fd, F_GETFL)) == -1 ||
	     fcntl(fd, F_SETFL, val|O_NONBLOCK) == -1)
		error_f("fcntl: %s", strerror(errno));
}

/*
 * we write to this pipe if a SIGCHLD is caught in order to avoid
 * the race between select() and child_terminated.
 */
static 정수
pselect_notify_setup(void)
{
	만약 (pipe(notify_pipe) == -1) {
		error("pipe(notify_pipe) failed %s", strerror(errno));
		notify_pipe[0] = notify_pipe[1] = -1;
		반환 -1;
	}
	pselect_set_nonblock(notify_pipe[0]);
	pselect_set_nonblock(notify_pipe[1]);
	만약 (!suppress_debug)
		debug3_f("pipe0 %d pipe1 %d", notify_pipe[0], notify_pipe[1]);
	반환 0;
}
static void
pselect_notify_parent(void)
{
	만약 (notify_pipe[1] != -1)
		(void)write(notify_pipe[1], "", 1);
}
static void
pselect_notify_prepare(fd_set *readset)
{
	만약 (notify_pipe[0] != -1)
		FD_SET(notify_pipe[0], readset);
}
static void
pselect_notify_done(fd_set *readset)
{
	char c;

	만약 (notify_pipe[0] != -1 && FD_ISSET(notify_pipe[0], readset)) {
		동안 (read(notify_pipe[0], &c, 1) != -1)
			debug2_f("reading");
		FD_CLR(notify_pipe[0], readset);
	}
	(void)close(notify_pipe[0]);
	(void)close(notify_pipe[1]);
}

/*ARGSUSED*/
static void
pselect_sig_handler(정수 sig)
{
	정수 save_errno = errno;

	pselect_notify_parent();
	만약 (saved_sighandler[sig] != NULL)
		(*saved_sighandler[sig])(sig);  /* call original handler */
	errno = save_errno;
}

/*
 * A minimal implementation of pselect(2), built on top of select(2).
 */

정수
pselect(정수 nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    const struct timespec *timeout, const sigset_t *mask)
{
	정수 ret, sig, saved_errno, unmasked = 0;
	sigset_t osig;
	struct sigaction sa, osa;
	struct timeval tv, *tvp = NULL;

	만약 (timeout != NULL) {
		tv.tv_sec = timeout->tv_sec;
		tv.tv_usec = timeout->tv_nsec / 1000;
		tvp = &tv;
	}
	만약 (mask == NULL)  /* no signal mask, just call select */
		반환 select(nfds, readfds, writefds, exceptfds, tvp);

	/* For each signal unmasked, save old handler and install ours. */
	위해 (sig = 0; sig < _NSIG; sig++) {
		saved_sighandler[sig] = NULL;
		만약 (sig == SIGKILL || sig == SIGSTOP || sigismember(mask, sig))
			continue;
		만약 (sigaction(sig, NULL, &sa) == 0 &&
		    sa.sa_handler != SIG_IGN && sa.sa_handler != SIG_DFL) {
			unmasked = 1;
			sa.sa_handler = pselect_sig_handler;
			만약 (sigaction(sig, &sa, &osa) == 0) {
				만약 (!suppress_debug)
					debug3_f("installed signal handler for"
					    " %s, previous 0x%p",
					    strsignal(sig), osa.sa_handler);
				saved_sighandler[sig] = osa.sa_handler;
			}
		}
	}
	만약 (unmasked) {
		만약 ((ret = pselect_notify_setup()) == -1) {
			saved_errno = ENOMEM;
			goto out;
		}
		pselect_notify_prepare(readfds);
		nfds = MAX(nfds, notify_pipe[0] + 1);
	}

	/* Unmask signals, call select then restore signal mask. */
	sigprocmask(SIG_SETMASK, mask, &osig);
	ret = select(nfds, readfds, writefds, exceptfds, tvp);
	saved_errno = errno;
	sigprocmask(SIG_SETMASK, &osig, NULL);

	만약 (unmasked)
		pselect_notify_done(readfds);

 out:
	/* Restore signal handlers. */
	위해 (sig = 0; sig < _NSIG; sig++) {
		만약 (saved_sighandler[sig] == NULL)
			continue;
		만약 (sigaction(sig, NULL, &sa) == 0) {
			sa.sa_handler = saved_sighandler[sig];
			만약 (sigaction(sig, &sa, NULL) == 0) {
				만약 (!suppress_debug)
					debug3_f("restored signal handler for "
					    "%s", strsignal(sig));
			} 아니면 {
				error_f("failed to restore signal handler for "
				    "%s: %s", strsignal(sig), strerror(errno));
			}
		}
	}
	suppress_debug = 1;
	errno = saved_errno;
	반환 ret;
}
#endif
