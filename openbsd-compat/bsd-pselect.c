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

#ଅନ୍ତର୍ଭାଵ "includes.h"
#ifndef HAVE_PSELECT

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/time.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "log.h"

#ifndef HAVE_SIGHANDLER_T
ପ୍ରକାରବ୍ୟାଖ୍ୟା ଶୂନ୍ୟ (*sighandler_t)(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
#endif

ସ୍ଥିର sighandler_t saved_sighandler[_NSIG];
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା notify_pipe[2];	/* 0 = read end, 1 = write end */

/*
 * Because the debugging for this is so noisy, we only output on the first
 * call, and suppress it thereafter.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା suppress_debug;

ସ୍ଥିର ଶୂନ୍ୟ
pselect_set_nonblock(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା val;

	ଯଦି ((val = fcntl(fd, F_GETFL)) == -1 ||
	     fcntl(fd, F_SETFL, val|O_NONBLOCK) == -1)
		error_f("fcntl: %s", strerror(errno));
}

/*
 * we write to this pipe if a SIGCHLD is caught in order to avoid
 * the race between select() and child_terminated.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pselect_notify_setup(ଶୂନ୍ୟ)
{
	ଯଦି (pipe(notify_pipe) == -1) {
		error("pipe(notify_pipe) failed %s", strerror(errno));
		notify_pipe[0] = notify_pipe[1] = -1;
		ଫେରନ୍ତୁ -1;
	}
	pselect_set_nonblock(notify_pipe[0]);
	pselect_set_nonblock(notify_pipe[1]);
	ଯଦି (!suppress_debug)
		debug3_f("pipe0 %d pipe1 %d", notify_pipe[0], notify_pipe[1]);
	ଫେରନ୍ତୁ 0;
}
ସ୍ଥିର ଶୂନ୍ୟ
pselect_notify_parent(ଶୂନ୍ୟ)
{
	ଯଦି (notify_pipe[1] != -1)
		(ଶୂନ୍ୟ)ଲିଖ(notify_pipe[1], "", 1);
}
ସ୍ଥିର ଶୂନ୍ୟ
pselect_notify_prepare(fd_set *readset)
{
	ଯଦି (notify_pipe[0] != -1)
		FD_SET(notify_pipe[0], readset);
}
ସ୍ଥିର ଶୂନ୍ୟ
pselect_notify_done(fd_set *readset)
{
	ଅକ୍ଷର c;

	ଯଦି (notify_pipe[0] != -1 && FD_ISSET(notify_pipe[0], readset)) {
		ଯେତେବେଳେ (ପଠ(notify_pipe[0], &c, 1) != -1)
			debug2_f("reading");
		FD_CLR(notify_pipe[0], readset);
	}
	(ଶୂନ୍ୟ)close(notify_pipe[0]);
	(ଶୂନ୍ୟ)close(notify_pipe[1]);
}

/*ARGSUSED*/
ସ୍ଥିର ଶୂନ୍ୟ
pselect_sig_handler(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା save_errno = errno;

	pselect_notify_parent();
	ଯଦି (saved_sighandler[sig] != ଖାଲି)
		(*saved_sighandler[sig])(sig);  /* call original handler */
	errno = save_errno;
}

/*
 * A minimal implementation of pselect(2), built on top of select(2).
 */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pselect(ପୂର୍ଣ୍ଣସଂଖ୍ୟା nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    ଅଚଳ ସଂରଚନା timespec *timeout, ଅଚଳ sigset_t *mask)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret, sig, saved_errno, unmasked = 0;
	sigset_t osig;
	ସଂରଚନା sigaction sa, osa;
	ସଂରଚନା timeval tv, *tvp = ଖାଲି;

	ଯଦି (timeout != ଖାଲି) {
		tv.tv_sec = timeout->tv_sec;
		tv.tv_usec = timeout->tv_nsec / 1000;
		tvp = &tv;
	}
	ଯଦି (mask == ଖାଲି)  /* no signal mask, just call select */
		ଫେରନ୍ତୁ select(nfds, readfds, writefds, exceptfds, tvp);

	/* For each signal unmasked, save old handler and install ours. */
	ପାଇଁ (sig = 0; sig < _NSIG; sig++) {
		saved_sighandler[sig] = ଖାଲି;
		ଯଦି (sig == SIGKILL || sig == SIGSTOP || sigismember(mask, sig))
			ଜାରି;
		ଯଦି (sigaction(sig, ଖାଲି, &sa) == 0 &&
		    sa.sa_handler != SIG_IGN && sa.sa_handler != SIG_DFL) {
			unmasked = 1;
			sa.sa_handler = pselect_sig_handler;
			ଯଦି (sigaction(sig, &sa, &osa) == 0) {
				ଯଦି (!suppress_debug)
					debug3_f("installed signal handler for"
					    " %s, previous 0x%p",
					    strsignal(sig), osa.sa_handler);
				saved_sighandler[sig] = osa.sa_handler;
			}
		}
	}
	ଯଦି (unmasked) {
		ଯଦି ((ret = pselect_notify_setup()) == -1) {
			saved_errno = ENOMEM;
			ଯାଅ out;
		}
		pselect_notify_prepare(readfds);
		nfds = MAX(nfds, notify_pipe[0] + 1);
	}

	/* Unmask signals, call select then restore signal mask. */
	sigprocmask(SIG_SETMASK, mask, &osig);
	ret = select(nfds, readfds, writefds, exceptfds, tvp);
	saved_errno = errno;
	sigprocmask(SIG_SETMASK, &osig, ଖାଲି);

	ଯଦି (unmasked)
		pselect_notify_done(readfds);

 out:
	/* Restore signal handlers. */
	ପାଇଁ (sig = 0; sig < _NSIG; sig++) {
		ଯଦି (saved_sighandler[sig] == ଖାଲି)
			ଜାରି;
		ଯଦି (sigaction(sig, ଖାଲି, &sa) == 0) {
			sa.sa_handler = saved_sighandler[sig];
			ଯଦି (sigaction(sig, &sa, ଖାଲି) == 0) {
				ଯଦି (!suppress_debug)
					debug3_f("restored signal handler for "
					    "%s", strsignal(sig));
			} ଅନ୍ୟଥା {
				error_f("failed to restore signal handler for "
				    "%s: %s", strsignal(sig), strerror(errno));
			}
		}
	}
	suppress_debug = 1;
	errno = saved_errno;
	ଫେରନ୍ତୁ ret;
}
#endif
