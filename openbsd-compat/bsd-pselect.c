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

#அந்தர்பாவ "includes.h"
#ifndef HAVE_PSELECT

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/time.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "log.h"

#ifndef HAVE_SIGHANDLER_T
வகைவரை வெறுமை (*sighandler_t)(முழு);
#endif

நிலையான sighandler_t saved_sighandler[_NSIG];
நிலையான முழு notify_pipe[2];	/* 0 = read end, 1 = write end */

/*
 * Because the debugging for this is so noisy, we only output on the first
 * call, and suppress it thereafter.
 */
நிலையான முழு suppress_debug;

நிலையான வெறுமை
pselect_set_nonblock(முழு fd)
{
	முழு val;

	எனில் ((val = fcntl(fd, F_GETFL)) == -1 ||
	     fcntl(fd, F_SETFL, val|O_NONBLOCK) == -1)
		error_f("fcntl: %s", strerror(errno));
}

/*
 * we write to this pipe if a SIGCHLD is caught in order to avoid
 * the race between select() and child_terminated.
 */
நிலையான முழு
pselect_notify_setup(வெறுமை)
{
	எனில் (pipe(notify_pipe) == -1) {
		error("pipe(notify_pipe) failed %s", strerror(errno));
		notify_pipe[0] = notify_pipe[1] = -1;
		திரும்பு -1;
	}
	pselect_set_nonblock(notify_pipe[0]);
	pselect_set_nonblock(notify_pipe[1]);
	எனில் (!suppress_debug)
		debug3_f("pipe0 %d pipe1 %d", notify_pipe[0], notify_pipe[1]);
	திரும்பு 0;
}
நிலையான வெறுமை
pselect_notify_parent(வெறுமை)
{
	எனில் (notify_pipe[1] != -1)
		(வெறுமை)லிக(notify_pipe[1], "", 1);
}
நிலையான வெறுமை
pselect_notify_prepare(fd_set *readset)
{
	எனில் (notify_pipe[0] != -1)
		FD_SET(notify_pipe[0], readset);
}
நிலையான வெறுமை
pselect_notify_done(fd_set *readset)
{
	எழுத்து c;

	எனில் (notify_pipe[0] != -1 && FD_ISSET(notify_pipe[0], readset)) {
		போது (பட(notify_pipe[0], &c, 1) != -1)
			debug2_f("reading");
		FD_CLR(notify_pipe[0], readset);
	}
	(வெறுமை)close(notify_pipe[0]);
	(வெறுமை)close(notify_pipe[1]);
}

/*ARGSUSED*/
நிலையான வெறுமை
pselect_sig_handler(முழு sig)
{
	முழு save_errno = errno;

	pselect_notify_parent();
	எனில் (saved_sighandler[sig] != வெற்று)
		(*saved_sighandler[sig])(sig);  /* call original handler */
	errno = save_errno;
}

/*
 * A minimal implementation of pselect(2), built on top of select(2).
 */

முழு
pselect(முழு nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    மாறிலி கட்டமைப்பு timespec *timeout, மாறிலி sigset_t *mask)
{
	முழு ret, sig, saved_errno, unmasked = 0;
	sigset_t osig;
	கட்டமைப்பு sigaction sa, osa;
	கட்டமைப்பு timeval tv, *tvp = வெற்று;

	எனில் (timeout != வெற்று) {
		tv.tv_sec = timeout->tv_sec;
		tv.tv_usec = timeout->tv_nsec / 1000;
		tvp = &tv;
	}
	எனில் (mask == வெற்று)  /* no signal mask, just call select */
		திரும்பு select(nfds, readfds, writefds, exceptfds, tvp);

	/* For each signal unmasked, save old handler and install ours. */
	க்கு (sig = 0; sig < _NSIG; sig++) {
		saved_sighandler[sig] = வெற்று;
		எனில் (sig == SIGKILL || sig == SIGSTOP || sigismember(mask, sig))
			தொடர்;
		எனில் (sigaction(sig, வெற்று, &sa) == 0 &&
		    sa.sa_handler != SIG_IGN && sa.sa_handler != SIG_DFL) {
			unmasked = 1;
			sa.sa_handler = pselect_sig_handler;
			எனில் (sigaction(sig, &sa, &osa) == 0) {
				எனில் (!suppress_debug)
					debug3_f("installed signal handler for"
					    " %s, previous 0x%p",
					    strsignal(sig), osa.sa_handler);
				saved_sighandler[sig] = osa.sa_handler;
			}
		}
	}
	எனில் (unmasked) {
		எனில் ((ret = pselect_notify_setup()) == -1) {
			saved_errno = ENOMEM;
			செல் out;
		}
		pselect_notify_prepare(readfds);
		nfds = MAX(nfds, notify_pipe[0] + 1);
	}

	/* Unmask signals, call select then restore signal mask. */
	sigprocmask(SIG_SETMASK, mask, &osig);
	ret = select(nfds, readfds, writefds, exceptfds, tvp);
	saved_errno = errno;
	sigprocmask(SIG_SETMASK, &osig, வெற்று);

	எனில் (unmasked)
		pselect_notify_done(readfds);

 out:
	/* Restore signal handlers. */
	க்கு (sig = 0; sig < _NSIG; sig++) {
		எனில் (saved_sighandler[sig] == வெற்று)
			தொடர்;
		எனில் (sigaction(sig, வெற்று, &sa) == 0) {
			sa.sa_handler = saved_sighandler[sig];
			எனில் (sigaction(sig, &sa, வெற்று) == 0) {
				எனில் (!suppress_debug)
					debug3_f("restored signal handler for "
					    "%s", strsignal(sig));
			} இல்லையெனில் {
				error_f("failed to restore signal handler for "
				    "%s: %s", strsignal(sig), strerror(errno));
			}
		}
	}
	suppress_debug = 1;
	errno = saved_errno;
	திரும்பு ret;
}
#endif
