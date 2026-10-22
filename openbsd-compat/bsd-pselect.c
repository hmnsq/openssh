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

#অন্তর্ভাব "includes.h"
#ifndef HAVE_PSELECT

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/time.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "log.h"

#ifndef HAVE_SIGHANDLER_T
প্রকারলেখ শূন্য (*sighandler_t)(পূর্ণসংখ্যা);
#endif

স্থির sighandler_t saved_sighandler[_NSIG];
স্থির পূর্ণসংখ্যা notify_pipe[2];	/* 0 = read end, 1 = write end */

/*
 * Because the debugging for this is so noisy, we only output on the first
 * call, and suppress it thereafter.
 */
স্থির পূর্ণসংখ্যা suppress_debug;

স্থির শূন্য
pselect_set_nonblock(পূর্ণসংখ্যা fd)
{
	পূর্ণসংখ্যা val;

	যদি ((val = fcntl(fd, F_GETFL)) == -1 ||
	     fcntl(fd, F_SETFL, val|O_NONBLOCK) == -1)
		error_f("fcntl: %s", strerror(errno));
}

/*
 * we write to this pipe if a SIGCHLD is caught in order to avoid
 * the race between select() and child_terminated.
 */
স্থির পূর্ণসংখ্যা
pselect_notify_setup(শূন্য)
{
	যদি (pipe(notify_pipe) == -1) {
		error("pipe(notify_pipe) failed %s", strerror(errno));
		notify_pipe[0] = notify_pipe[1] = -1;
		ফেরত -1;
	}
	pselect_set_nonblock(notify_pipe[0]);
	pselect_set_nonblock(notify_pipe[1]);
	যদি (!suppress_debug)
		debug3_f("pipe0 %d pipe1 %d", notify_pipe[0], notify_pipe[1]);
	ফেরত 0;
}
স্থির শূন্য
pselect_notify_parent(শূন্য)
{
	যদি (notify_pipe[1] != -1)
		(শূন্য)লিখ(notify_pipe[1], "", 1);
}
স্থির শূন্য
pselect_notify_prepare(fd_set *readset)
{
	যদি (notify_pipe[0] != -1)
		FD_SET(notify_pipe[0], readset);
}
স্থির শূন্য
pselect_notify_done(fd_set *readset)
{
	অক্ষর c;

	যদি (notify_pipe[0] != -1 && FD_ISSET(notify_pipe[0], readset)) {
		যখন (পঠ(notify_pipe[0], &c, 1) != -1)
			debug2_f("reading");
		FD_CLR(notify_pipe[0], readset);
	}
	(শূন্য)close(notify_pipe[0]);
	(শূন্য)close(notify_pipe[1]);
}

/*ARGSUSED*/
স্থির শূন্য
pselect_sig_handler(পূর্ণসংখ্যা sig)
{
	পূর্ণসংখ্যা save_errno = errno;

	pselect_notify_parent();
	যদি (saved_sighandler[sig] != ফাঁকা)
		(*saved_sighandler[sig])(sig);  /* call original handler */
	errno = save_errno;
}

/*
 * A minimal implementation of pselect(2), built on top of select(2).
 */

পূর্ণসংখ্যা
pselect(পূর্ণসংখ্যা nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    ধ্রুবক কাঠামো timespec *timeout, ধ্রুবক sigset_t *mask)
{
	পূর্ণসংখ্যা ret, sig, saved_errno, unmasked = 0;
	sigset_t osig;
	কাঠামো sigaction sa, osa;
	কাঠামো timeval tv, *tvp = ফাঁকা;

	যদি (timeout != ফাঁকা) {
		tv.tv_sec = timeout->tv_sec;
		tv.tv_usec = timeout->tv_nsec / 1000;
		tvp = &tv;
	}
	যদি (mask == ফাঁকা)  /* no signal mask, just call select */
		ফেরত select(nfds, readfds, writefds, exceptfds, tvp);

	/* For each signal unmasked, save old handler and install ours. */
	জন্য (sig = 0; sig < _NSIG; sig++) {
		saved_sighandler[sig] = ফাঁকা;
		যদি (sig == SIGKILL || sig == SIGSTOP || sigismember(mask, sig))
			চালু;
		যদি (sigaction(sig, ফাঁকা, &sa) == 0 &&
		    sa.sa_handler != SIG_IGN && sa.sa_handler != SIG_DFL) {
			unmasked = 1;
			sa.sa_handler = pselect_sig_handler;
			যদি (sigaction(sig, &sa, &osa) == 0) {
				যদি (!suppress_debug)
					debug3_f("installed signal handler for"
					    " %s, previous 0x%p",
					    strsignal(sig), osa.sa_handler);
				saved_sighandler[sig] = osa.sa_handler;
			}
		}
	}
	যদি (unmasked) {
		যদি ((ret = pselect_notify_setup()) == -1) {
			saved_errno = ENOMEM;
			যাও out;
		}
		pselect_notify_prepare(readfds);
		nfds = MAX(nfds, notify_pipe[0] + 1);
	}

	/* Unmask signals, call select then restore signal mask. */
	sigprocmask(SIG_SETMASK, mask, &osig);
	ret = select(nfds, readfds, writefds, exceptfds, tvp);
	saved_errno = errno;
	sigprocmask(SIG_SETMASK, &osig, ফাঁকা);

	যদি (unmasked)
		pselect_notify_done(readfds);

 out:
	/* Restore signal handlers. */
	জন্য (sig = 0; sig < _NSIG; sig++) {
		যদি (saved_sighandler[sig] == ফাঁকা)
			চালু;
		যদি (sigaction(sig, ফাঁকা, &sa) == 0) {
			sa.sa_handler = saved_sighandler[sig];
			যদি (sigaction(sig, &sa, ফাঁকা) == 0) {
				যদি (!suppress_debug)
					debug3_f("restored signal handler for "
					    "%s", strsignal(sig));
			} অন্যথা {
				error_f("failed to restore signal handler for "
				    "%s: %s", strsignal(sig), strerror(errno));
			}
		}
	}
	suppress_debug = 1;
	errno = saved_errno;
	ফেরত ret;
}
#endif
