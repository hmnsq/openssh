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

#ಅನ್ತರ್ಭಾವ "includes.h"
#ifndef HAVE_PSELECT

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "log.h"

#ifndef HAVE_SIGHANDLER_T
ಪ್ರಕಾರನಿರ್ದೇಶ ಶೂನ್ಯ (*sighandler_t)(ಪೂರ್ಣಾಙ್ಕ);
#endif

ಸ್ಥಿರ sighandler_t saved_sighandler[_NSIG];
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ notify_pipe[2];	/* 0 = read end, 1 = write end */

/*
 * Because the debugging for this is so noisy, we only output on the first
 * call, and suppress it thereafter.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ suppress_debug;

ಸ್ಥಿರ ಶೂನ್ಯ
pselect_set_nonblock(ಪೂರ್ಣಾಙ್ಕ fd)
{
	ಪೂರ್ಣಾಙ್ಕ val;

	ಯದಿ ((val = fcntl(fd, F_GETFL)) == -1 ||
	     fcntl(fd, F_SETFL, val|O_NONBLOCK) == -1)
		error_f("fcntl: %s", strerror(errno));
}

/*
 * we write to this pipe if a SIGCHLD is caught in order to avoid
 * the race between select() and child_terminated.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pselect_notify_setup(ಶೂನ್ಯ)
{
	ಯದಿ (pipe(notify_pipe) == -1) {
		error("pipe(notify_pipe) failed %s", strerror(errno));
		notify_pipe[0] = notify_pipe[1] = -1;
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	pselect_set_nonblock(notify_pipe[0]);
	pselect_set_nonblock(notify_pipe[1]);
	ಯದಿ (!suppress_debug)
		debug3_f("pipe0 %d pipe1 %d", notify_pipe[0], notify_pipe[1]);
	ಪ್ರತ್ಯಾಗಮ 0;
}
ಸ್ಥಿರ ಶೂನ್ಯ
pselect_notify_parent(ಶೂನ್ಯ)
{
	ಯದಿ (notify_pipe[1] != -1)
		(ಶೂನ್ಯ)ಲಿಖ(notify_pipe[1], "", 1);
}
ಸ್ಥಿರ ಶೂನ್ಯ
pselect_notify_prepare(fd_set *readset)
{
	ಯದಿ (notify_pipe[0] != -1)
		FD_SET(notify_pipe[0], readset);
}
ಸ್ಥಿರ ಶೂನ್ಯ
pselect_notify_done(fd_set *readset)
{
	ವರ್ಣ c;

	ಯದಿ (notify_pipe[0] != -1 && FD_ISSET(notify_pipe[0], readset)) {
		ಯಾವತ್ (ಪಠ(notify_pipe[0], &c, 1) != -1)
			debug2_f("reading");
		FD_CLR(notify_pipe[0], readset);
	}
	(ಶೂನ್ಯ)close(notify_pipe[0]);
	(ಶೂನ್ಯ)close(notify_pipe[1]);
}

/*ARGSUSED*/
ಸ್ಥಿರ ಶೂನ್ಯ
pselect_sig_handler(ಪೂರ್ಣಾಙ್ಕ sig)
{
	ಪೂರ್ಣಾಙ್ಕ save_errno = errno;

	pselect_notify_parent();
	ಯದಿ (saved_sighandler[sig] != ರಿಕ್ತ)
		(*saved_sighandler[sig])(sig);  /* call original handler */
	errno = save_errno;
}

/*
 * A minimal implementation of pselect(2), built on top of select(2).
 */

ಪೂರ್ಣಾಙ್ಕ
pselect(ಪೂರ್ಣಾಙ್ಕ nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    ಧ್ರುವ ಸಂರಚನಾ timespec *timeout, ಧ್ರುವ sigset_t *mask)
{
	ಪೂರ್ಣಾಙ್ಕ ret, sig, saved_errno, unmasked = 0;
	sigset_t osig;
	ಸಂರಚನಾ sigaction sa, osa;
	ಸಂರಚನಾ timeval tv, *tvp = ರಿಕ್ತ;

	ಯದಿ (timeout != ರಿಕ್ತ) {
		tv.tv_sec = timeout->tv_sec;
		tv.tv_usec = timeout->tv_nsec / 1000;
		tvp = &tv;
	}
	ಯದಿ (mask == ರಿಕ್ತ)  /* no signal mask, just call select */
		ಪ್ರತ್ಯಾಗಮ select(nfds, readfds, writefds, exceptfds, tvp);

	/* For each signal unmasked, save old handler and install ours. */
	ಪ್ರತಿ (sig = 0; sig < _NSIG; sig++) {
		saved_sighandler[sig] = ರಿಕ್ತ;
		ಯದಿ (sig == SIGKILL || sig == SIGSTOP || sigismember(mask, sig))
			ಅನುವರ್ತ;
		ಯದಿ (sigaction(sig, ರಿಕ್ತ, &sa) == 0 &&
		    sa.sa_handler != SIG_IGN && sa.sa_handler != SIG_DFL) {
			unmasked = 1;
			sa.sa_handler = pselect_sig_handler;
			ಯದಿ (sigaction(sig, &sa, &osa) == 0) {
				ಯದಿ (!suppress_debug)
					debug3_f("installed signal handler for"
					    " %s, previous 0x%p",
					    strsignal(sig), osa.sa_handler);
				saved_sighandler[sig] = osa.sa_handler;
			}
		}
	}
	ಯದಿ (unmasked) {
		ಯದಿ ((ret = pselect_notify_setup()) == -1) {
			saved_errno = ENOMEM;
			ಗಚ್ಛ out;
		}
		pselect_notify_prepare(readfds);
		nfds = MAX(nfds, notify_pipe[0] + 1);
	}

	/* Unmask signals, call select then restore signal mask. */
	sigprocmask(SIG_SETMASK, mask, &osig);
	ret = select(nfds, readfds, writefds, exceptfds, tvp);
	saved_errno = errno;
	sigprocmask(SIG_SETMASK, &osig, ರಿಕ್ತ);

	ಯದಿ (unmasked)
		pselect_notify_done(readfds);

 out:
	/* Restore signal handlers. */
	ಪ್ರತಿ (sig = 0; sig < _NSIG; sig++) {
		ಯದಿ (saved_sighandler[sig] == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		ಯದಿ (sigaction(sig, ರಿಕ್ತ, &sa) == 0) {
			sa.sa_handler = saved_sighandler[sig];
			ಯದಿ (sigaction(sig, &sa, ರಿಕ್ತ) == 0) {
				ಯದಿ (!suppress_debug)
					debug3_f("restored signal handler for "
					    "%s", strsignal(sig));
			} ಅನ್ಯಥಾ {
				error_f("failed to restore signal handler for "
				    "%s: %s", strsignal(sig), strerror(errno));
			}
		}
	}
	suppress_debug = 1;
	errno = saved_errno;
	ಪ್ರತ್ಯಾಗಮ ret;
}
#endif
