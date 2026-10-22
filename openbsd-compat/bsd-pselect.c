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
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_PSELECT

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/time.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SYS_SELECT_H
# include <sys/select.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "log.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SIGHANDLER_T
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಶೂನ್ಯ (*sighandler_t)(ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

ಸ್ಥಿರ sighandler_t saved_sighandler[_NSIG];
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ notify_pipe[2];	/* 0 = read end, 1 = write end */

/*
 * Because the debugging for this is so noisy, we only output on the first
 * call, and suppress it thereafter.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ suppress_debug;

ಸ್ಥಿರ ಶೂನ್ಯ
pselect_ಗಣ_nonblock(ಪೂರ್ಣಾಂಕ fd)
{
	ಪೂರ್ಣಾಂಕ val;

	ಆದರೆ ((val = fcntl(fd, F_GETFL)) == -1 ||
	     fcntl(fd, F_SETFL, val|O_NONBLOCK) == -1)
		error_f("fcntl: %s", strerror(errno));
}

/*
 * we write to this pipe if a SIGCHLD is caught in order to avoid
 * the race between select() and child_terminated.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pselect_notify_ಸಿದ್ಧತೆ(ಶೂನ್ಯ)
{
	ಆದರೆ (pipe(notify_pipe) == -1) {
		error("pipe(notify_pipe) failed %s", strerror(errno));
		notify_pipe[0] = notify_pipe[1] = -1;
		ಹಿಂತಿರುಗಿ -1;
	}
	pselect_ಗಣ_nonblock(notify_pipe[0]);
	pselect_ಗಣ_nonblock(notify_pipe[1]);
	ಆದರೆ (!suppress_debug)
		debug3_f("pipe0 %d pipe1 %d", notify_pipe[0], notify_pipe[1]);
	ಹಿಂತಿರುಗಿ 0;
}
ಸ್ಥಿರ ಶೂನ್ಯ
pselect_notify_ಪೋಷಕ(ಶೂನ್ಯ)
{
	ಆದರೆ (notify_pipe[1] != -1)
		(ಶೂನ್ಯ)ಲಿಖ(notify_pipe[1], "", 1);
}
ಸ್ಥಿರ ಶೂನ್ಯ
pselect_notify_prepare(fd_set *readset)
{
	ಆದರೆ (notify_pipe[0] != -1)
		FD_SET(notify_pipe[0], readset);
}
ಸ್ಥಿರ ಶೂನ್ಯ
pselect_notify_ಮುಗಿದ(fd_set *readset)
{
	ಅಕ್ಷರ c;

	ಆದರೆ (notify_pipe[0] != -1 && FD_ISSET(notify_pipe[0], readset)) {
		ಆಗ (ಪಠ(notify_pipe[0], &c, 1) != -1)
			debug2_f("reading");
		FD_CLR(notify_pipe[0], readset);
	}
	(ಶೂನ್ಯ)close(notify_pipe[0]);
	(ಶೂನ್ಯ)close(notify_pipe[1]);
}

/*ARGSUSED*/
ಸ್ಥಿರ ಶೂನ್ಯ
pselect_sig_handler(ಪೂರ್ಣಾಂಕ sig)
{
	ಪೂರ್ಣಾಂಕ save_errno = errno;

	pselect_notify_ಪೋಷಕ();
	ಆದರೆ (saved_sighandler[sig] != ಖಾಲಿ)
		(*saved_sighandler[sig])(sig);  /* call original handler */
	errno = save_errno;
}

/*
 * A minimal implementation of pselect(2), built on top of select(2).
 */

ಪೂರ್ಣಾಂಕ
pselect(ಪೂರ್ಣಾಂಕ nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    ಸ್ಥಿರಾಂಕ ರಚನೆ timespec *timeout, ಸ್ಥಿರಾಂಕ sigset_t *ಮುಖವಾಡ)
{
	ಪೂರ್ಣಾಂಕ ret, sig, saved_errno, unmasked = 0;
	sigset_t osig;
	ರಚನೆ sigaction sa, osa;
	ರಚನೆ timeval tv, *tvp = ಖಾಲಿ;

	ಆದರೆ (timeout != ಖಾಲಿ) {
		tv.tv_sec = timeout->tv_sec;
		tv.tv_usec = timeout->tv_nsec / 1000;
		tvp = &tv;
	}
	ಆದರೆ (ಮುಖವಾಡ == ಖಾಲಿ)  /* no signal mask, just call select */
		ಹಿಂತಿರುಗಿ select(nfds, readfds, writefds, exceptfds, tvp);

	/* For each signal unmasked, save old handler and install ours. */
	ಗಾಗಿ (sig = 0; sig < _NSIG; sig++) {
		saved_sighandler[sig] = ಖಾಲಿ;
		ಆದರೆ (sig == SIGKILL || sig == SIGSTOP || sigismember(ಮುಖವಾಡ, sig))
			ಮುಂದುವರಿ;
		ಆದರೆ (sigaction(sig, ಖಾಲಿ, &sa) == 0 &&
		    sa.sa_handler != SIG_IGN && sa.sa_handler != SIG_DFL) {
			unmasked = 1;
			sa.sa_handler = pselect_sig_handler;
			ಆದರೆ (sigaction(sig, &sa, &osa) == 0) {
				ಆದರೆ (!suppress_debug)
					debug3_f("installed signal handler for"
					    " %s, previous 0x%p",
					    strsignal(sig), osa.sa_handler);
				saved_sighandler[sig] = osa.sa_handler;
			}
		}
	}
	ಆದರೆ (unmasked) {
		ಆದರೆ ((ret = pselect_notify_ಸಿದ್ಧತೆ()) == -1) {
			saved_errno = ENOMEM;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		pselect_notify_prepare(readfds);
		nfds = MAX(nfds, notify_pipe[0] + 1);
	}

	/* Unmask signals, call select then restore signal mask. */
	sigprocmask(SIG_SETMASK, ಮುಖವಾಡ, &osig);
	ret = select(nfds, readfds, writefds, exceptfds, tvp);
	saved_errno = errno;
	sigprocmask(SIG_SETMASK, &osig, ಖಾಲಿ);

	ಆದರೆ (unmasked)
		pselect_notify_ಮುಗಿದ(readfds);

 ಹೊರಹೋಗು:
	/* Restore signal handlers. */
	ಗಾಗಿ (sig = 0; sig < _NSIG; sig++) {
		ಆದರೆ (saved_sighandler[sig] == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		ಆದರೆ (sigaction(sig, ಖಾಲಿ, &sa) == 0) {
			sa.sa_handler = saved_sighandler[sig];
			ಆದರೆ (sigaction(sig, &sa, ಖಾಲಿ) == 0) {
				ಆದರೆ (!suppress_debug)
					debug3_f("restored signal handler for "
					    "%s", strsignal(sig));
			} ಇಲ್ಲದಿದ್ದರೆ {
				error_f("failed to restore signal handler for "
				    "%s: %s", strsignal(sig), strerror(errno));
			}
		}
	}
	suppress_debug = 1;
	errno = saved_errno;
	ಹಿಂತಿರುಗಿ ret;
}
#ಆದರೆ_ಅಂತ್ಯ
