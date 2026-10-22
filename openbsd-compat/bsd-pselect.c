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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_PSELECT

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SYS_SELECT_H
# include <sys/select.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_SIGHANDLER_T
ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਖਾਲੀ (*sighandler_t)(ਪੂਰਨ);
#ਜੇ_ਅੰਤ

ਸਥਿਰ sighandler_t saved_sighandler[_NSIG];
ਸਥਿਰ ਪੂਰਨ notify_pipe[2];	/* 0 = read end, 1 = write end */

/*
 * Because the debugging for this is so noisy, we only output on the first
 * call, and suppress it thereafter.
 */
ਸਥਿਰ ਪੂਰਨ suppress_debug;

ਸਥਿਰ ਖਾਲੀ
pselect_ਸੈੱਟ_nonblock(ਪੂਰਨ fd)
{
	ਪੂਰਨ val;

	ਜੇ ((val = fcntl(fd, F_GETFL)) == -1 ||
	     fcntl(fd, F_SETFL, val|O_NONBLOCK) == -1)
		error_f("fcntl: %s", strerror(errno));
}

/*
 * we write to this pipe if a SIGCHLD is caught in order to avoid
 * the race between select() and child_terminated.
 */
ਸਥਿਰ ਪੂਰਨ
pselect_notify_ਤਿਆਰੀ(ਖਾਲੀ)
{
	ਜੇ (pipe(notify_pipe) == -1) {
		error("pipe(notify_pipe) failed %s", strerror(errno));
		notify_pipe[0] = notify_pipe[1] = -1;
		ਵਾਪਸ -1;
	}
	pselect_ਸੈੱਟ_nonblock(notify_pipe[0]);
	pselect_ਸੈੱਟ_nonblock(notify_pipe[1]);
	ਜੇ (!suppress_debug)
		debug3_f("pipe0 %d pipe1 %d", notify_pipe[0], notify_pipe[1]);
	ਵਾਪਸ 0;
}
ਸਥਿਰ ਖਾਲੀ
pselect_notify_ਮਾਪਾ(ਖਾਲੀ)
{
	ਜੇ (notify_pipe[1] != -1)
		(ਖਾਲੀ)ਲਿਖ(notify_pipe[1], "", 1);
}
ਸਥਿਰ ਖਾਲੀ
pselect_notify_prepare(fd_set *readset)
{
	ਜੇ (notify_pipe[0] != -1)
		FD_SET(notify_pipe[0], readset);
}
ਸਥਿਰ ਖਾਲੀ
pselect_notify_ਪੂਰਾ(fd_set *readset)
{
	ਅੱਖਰ c;

	ਜੇ (notify_pipe[0] != -1 && FD_ISSET(notify_pipe[0], readset)) {
		ਜਦੋਂ (ਪਠ(notify_pipe[0], &c, 1) != -1)
			debug2_f("reading");
		FD_CLR(notify_pipe[0], readset);
	}
	(ਖਾਲੀ)close(notify_pipe[0]);
	(ਖਾਲੀ)close(notify_pipe[1]);
}

/*ARGSUSED*/
ਸਥਿਰ ਖਾਲੀ
pselect_sig_handler(ਪੂਰਨ sig)
{
	ਪੂਰਨ save_errno = errno;

	pselect_notify_ਮਾਪਾ();
	ਜੇ (saved_sighandler[sig] != ਨਿਰਾ)
		(*saved_sighandler[sig])(sig);  /* call original handler */
	errno = save_errno;
}

/*
 * A minimal implementation of pselect(2), built on top of select(2).
 */

ਪੂਰਨ
pselect(ਪੂਰਨ nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    ਅਚਲ ਬਣਤਰ timespec *timeout, ਅਚਲ sigset_t *ਨਕਾਬ)
{
	ਪੂਰਨ ret, sig, saved_errno, unmasked = 0;
	sigset_t osig;
	ਬਣਤਰ sigaction sa, osa;
	ਬਣਤਰ timeval tv, *tvp = ਨਿਰਾ;

	ਜੇ (timeout != ਨਿਰਾ) {
		tv.tv_sec = timeout->tv_sec;
		tv.tv_usec = timeout->tv_nsec / 1000;
		tvp = &tv;
	}
	ਜੇ (ਨਕਾਬ == ਨਿਰਾ)  /* no signal mask, just call select */
		ਵਾਪਸ select(nfds, readfds, writefds, exceptfds, tvp);

	/* For each signal unmasked, save old handler and install ours. */
	ਲਈ (sig = 0; sig < _NSIG; sig++) {
		saved_sighandler[sig] = ਨਿਰਾ;
		ਜੇ (sig == SIGKILL || sig == SIGSTOP || sigismember(ਨਕਾਬ, sig))
			ਜਾਰੀ;
		ਜੇ (sigaction(sig, ਨਿਰਾ, &sa) == 0 &&
		    sa.sa_handler != SIG_IGN && sa.sa_handler != SIG_DFL) {
			unmasked = 1;
			sa.sa_handler = pselect_sig_handler;
			ਜੇ (sigaction(sig, &sa, &osa) == 0) {
				ਜੇ (!suppress_debug)
					debug3_f("installed signal handler for"
					    " %s, previous 0x%p",
					    strsignal(sig), osa.sa_handler);
				saved_sighandler[sig] = osa.sa_handler;
			}
		}
	}
	ਜੇ (unmasked) {
		ਜੇ ((ret = pselect_notify_ਤਿਆਰੀ()) == -1) {
			saved_errno = ENOMEM;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		pselect_notify_prepare(readfds);
		nfds = MAX(nfds, notify_pipe[0] + 1);
	}

	/* Unmask signals, call select then restore signal mask. */
	sigprocmask(SIG_SETMASK, ਨਕਾਬ, &osig);
	ret = select(nfds, readfds, writefds, exceptfds, tvp);
	saved_errno = errno;
	sigprocmask(SIG_SETMASK, &osig, ਨਿਰਾ);

	ਜੇ (unmasked)
		pselect_notify_ਪੂਰਾ(readfds);

 ਬਾਹਰਲਾ:
	/* Restore signal handlers. */
	ਲਈ (sig = 0; sig < _NSIG; sig++) {
		ਜੇ (saved_sighandler[sig] == ਨਿਰਾ)
			ਜਾਰੀ;
		ਜੇ (sigaction(sig, ਨਿਰਾ, &sa) == 0) {
			sa.sa_handler = saved_sighandler[sig];
			ਜੇ (sigaction(sig, &sa, ਨਿਰਾ) == 0) {
				ਜੇ (!suppress_debug)
					debug3_f("restored signal handler for "
					    "%s", strsignal(sig));
			} ਨਹੀਂਤਾਂ {
				error_f("failed to restore signal handler for "
				    "%s: %s", strsignal(sig), strerror(errno));
			}
		}
	}
	suppress_debug = 1;
	errno = saved_errno;
	ਵਾਪਸ ret;
}
#ਜੇ_ਅੰਤ
