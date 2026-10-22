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

#అన్తర్భావ "includes.h"
#నిర్వచితం_కాకపోతే HAVE_PSELECT

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/time.h>
#నిర్వచితమైతే HAVE_SYS_SELECT_H
# include <sys/select.h>
#అయితే_ముగింపు

#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "log.h"

#నిర్వచితం_కాకపోతే HAVE_SIGHANDLER_T
రకనిర్వచనం శూన్య (*sighandler_t)(పూర్ణాంకం);
#అయితే_ముగింపు

స్థిర sighandler_t saved_sighandler[_NSIG];
స్థిర పూర్ణాంకం notify_pipe[2];	/* 0 = read end, 1 = write end */

/*
 * Because the debugging for this is so noisy, we only output on the first
 * call, and suppress it thereafter.
 */
స్థిర పూర్ణాంకం suppress_debug;

స్థిర శూన్య
pselect_సమితి_nonblock(పూర్ణాంకం fd)
{
	పూర్ణాంకం val;

	ఒకవేళ ((val = fcntl(fd, F_GETFL)) == -1 ||
	     fcntl(fd, F_SETFL, val|O_NONBLOCK) == -1)
		error_f("fcntl: %s", strerror(errno));
}

/*
 * we write to this pipe if a SIGCHLD is caught in order to avoid
 * the race between select() and child_terminated.
 */
స్థిర పూర్ణాంకం
pselect_notify_అమరిక(శూన్య)
{
	ఒకవేళ (pipe(notify_pipe) == -1) {
		error("pipe(notify_pipe) failed %s", strerror(errno));
		notify_pipe[0] = notify_pipe[1] = -1;
		తిరిగి -1;
	}
	pselect_సమితి_nonblock(notify_pipe[0]);
	pselect_సమితి_nonblock(notify_pipe[1]);
	ఒకవేళ (!suppress_debug)
		debug3_f("pipe0 %d pipe1 %d", notify_pipe[0], notify_pipe[1]);
	తిరిగి 0;
}
స్థిర శూన్య
pselect_notify_మాతృ(శూన్య)
{
	ఒకవేళ (notify_pipe[1] != -1)
		(శూన్య)లిఖ(notify_pipe[1], "", 1);
}
స్థిర శూన్య
pselect_notify_prepare(fd_set *readset)
{
	ఒకవేళ (notify_pipe[0] != -1)
		FD_SET(notify_pipe[0], readset);
}
స్థిర శూన్య
pselect_notify_పూర్తి(fd_set *readset)
{
	అక్షరం c;

	ఒకవేళ (notify_pipe[0] != -1 && FD_ISSET(notify_pipe[0], readset)) {
		అయితే (పఠ(notify_pipe[0], &c, 1) != -1)
			debug2_f("reading");
		FD_CLR(notify_pipe[0], readset);
	}
	(శూన్య)close(notify_pipe[0]);
	(శూన్య)close(notify_pipe[1]);
}

/*ARGSUSED*/
స్థిర శూన్య
pselect_sig_handler(పూర్ణాంకం sig)
{
	పూర్ణాంకం save_errno = errno;

	pselect_notify_మాతృ();
	ఒకవేళ (saved_sighandler[sig] != ఖాళీ)
		(*saved_sighandler[sig])(sig);  /* call original handler */
	errno = save_errno;
}

/*
 * A minimal implementation of pselect(2), built on top of select(2).
 */

పూర్ణాంకం
pselect(పూర్ణాంకం nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    స్థిరరాశి నిర్మాణం timespec *timeout, స్థిరరాశి sigset_t *ముసుగు)
{
	పూర్ణాంకం ret, sig, saved_errno, unmasked = 0;
	sigset_t osig;
	నిర్మాణం sigaction sa, osa;
	నిర్మాణం timeval tv, *tvp = ఖాళీ;

	ఒకవేళ (timeout != ఖాళీ) {
		tv.tv_sec = timeout->tv_sec;
		tv.tv_usec = timeout->tv_nsec / 1000;
		tvp = &tv;
	}
	ఒకవేళ (ముసుగు == ఖాళీ)  /* no signal mask, just call select */
		తిరిగి select(nfds, readfds, writefds, exceptfds, tvp);

	/* For each signal unmasked, save old handler and install ours. */
	కొరకు (sig = 0; sig < _NSIG; sig++) {
		saved_sighandler[sig] = ఖాళీ;
		ఒకవేళ (sig == SIGKILL || sig == SIGSTOP || sigismember(ముసుగు, sig))
			కొనసాగు;
		ఒకవేళ (sigaction(sig, ఖాళీ, &sa) == 0 &&
		    sa.sa_handler != SIG_IGN && sa.sa_handler != SIG_DFL) {
			unmasked = 1;
			sa.sa_handler = pselect_sig_handler;
			ఒకవేళ (sigaction(sig, &sa, &osa) == 0) {
				ఒకవేళ (!suppress_debug)
					debug3_f("installed signal handler for"
					    " %s, previous 0x%p",
					    strsignal(sig), osa.sa_handler);
				saved_sighandler[sig] = osa.sa_handler;
			}
		}
	}
	ఒకవేళ (unmasked) {
		ఒకవేళ ((ret = pselect_notify_అమరిక()) == -1) {
			saved_errno = ENOMEM;
			వెళ్ళు బహిర్గతం;
		}
		pselect_notify_prepare(readfds);
		nfds = MAX(nfds, notify_pipe[0] + 1);
	}

	/* Unmask signals, call select then restore signal mask. */
	sigprocmask(SIG_SETMASK, ముసుగు, &osig);
	ret = select(nfds, readfds, writefds, exceptfds, tvp);
	saved_errno = errno;
	sigprocmask(SIG_SETMASK, &osig, ఖాళీ);

	ఒకవేళ (unmasked)
		pselect_notify_పూర్తి(readfds);

 బహిర్గతం:
	/* Restore signal handlers. */
	కొరకు (sig = 0; sig < _NSIG; sig++) {
		ఒకవేళ (saved_sighandler[sig] == ఖాళీ)
			కొనసాగు;
		ఒకవేళ (sigaction(sig, ఖాళీ, &sa) == 0) {
			sa.sa_handler = saved_sighandler[sig];
			ఒకవేళ (sigaction(sig, &sa, ఖాళీ) == 0) {
				ఒకవేళ (!suppress_debug)
					debug3_f("restored signal handler for "
					    "%s", strsignal(sig));
			} లేకపోతే {
				error_f("failed to restore signal handler for "
				    "%s: %s", strsignal(sig), strerror(errno));
			}
		}
	}
	suppress_debug = 1;
	errno = saved_errno;
	తిరిగి ret;
}
#అయితే_ముగింపు
