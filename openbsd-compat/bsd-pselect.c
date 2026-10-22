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

#ضمن "includes.h"
#ifndef HAVE_PSELECT

#ضمن <sys/types.h>
#ضمن <sys/time.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <signal.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن "log.h"

#ifndef HAVE_SIGHANDLER_T
تعريفنوع فراغ (*sighandler_t)(صحيح);
#endif

ساكن sighandler_t saved_sighandler[_NSIG];
ساكن صحيح notify_pipe[2];	/* 0 = read end, 1 = write end */

/*
 * Because the debugging for this is so noisy, we only output on the first
 * call, and suppress it thereafter.
 */
ساكن صحيح suppress_debug;

ساكن فراغ
pselect_set_nonblock(صحيح fd)
{
	صحيح val;

	𐡄𐡍 ((val = fcntl(fd, F_GETFL)) == -1 ||
	     fcntl(fd, F_SETFL, val|O_NONBLOCK) == -1)
		error_f("fcntl: %s", strerror(errno));
}

/*
 * we write to this pipe if a SIGCHLD is caught in order to avoid
 * the race between select() and child_terminated.
 */
ساكن صحيح
pselect_notify_setup(فراغ)
{
	𐡄𐡍 (pipe(notify_pipe) == -1) {
		error("pipe(notify_pipe) failed %s", strerror(errno));
		notify_pipe[0] = notify_pipe[1] = -1;
		أرجع -1;
	}
	pselect_set_nonblock(notify_pipe[0]);
	pselect_set_nonblock(notify_pipe[1]);
	𐡄𐡍 (!suppress_debug)
		debug3_f("pipe0 %d pipe1 %d", notify_pipe[0], notify_pipe[1]);
	أرجع 0;
}
ساكن فراغ
pselect_notify_parent(فراغ)
{
	𐡄𐡍 (notify_pipe[1] != -1)
		(فراغ)اكتب(notify_pipe[1], "", 1);
}
ساكن فراغ
pselect_notify_prepare(fd_set *readset)
{
	𐡄𐡍 (notify_pipe[0] != -1)
		FD_SET(notify_pipe[0], readset);
}
ساكن فراغ
pselect_notify_done(fd_set *readset)
{
	حرف c;

	𐡄𐡍 (notify_pipe[0] != -1 && FD_ISSET(notify_pipe[0], readset)) {
		طالما (اقرأ(notify_pipe[0], &c, 1) != -1)
			debug2_f("reading");
		FD_CLR(notify_pipe[0], readset);
	}
	(فراغ)close(notify_pipe[0]);
	(فراغ)close(notify_pipe[1]);
}

/*ARGSUSED*/
ساكن فراغ
pselect_sig_handler(صحيح sig)
{
	صحيح save_errno = errno;

	pselect_notify_parent();
	𐡄𐡍 (saved_sighandler[sig] != عدم)
		(*saved_sighandler[sig])(sig);  /* call original handler */
	errno = save_errno;
}

/*
 * A minimal implementation of pselect(2), built on top of select(2).
 */

صحيح
pselect(صحيح nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    ثابت بنية timespec *timeout, ثابت sigset_t *mask)
{
	صحيح ret, sig, saved_errno, unmasked = 0;
	sigset_t osig;
	بنية sigaction sa, osa;
	بنية timeval tv, *tvp = عدم;

	𐡄𐡍 (timeout != عدم) {
		tv.tv_sec = timeout->tv_sec;
		tv.tv_usec = timeout->tv_nsec / 1000;
		tvp = &tv;
	}
	𐡄𐡍 (mask == عدم)  /* no signal mask, just call select */
		أرجع select(nfds, readfds, writefds, exceptfds, tvp);

	/* For each signal unmasked, save old handler and install ours. */
	لكل (sig = 0; sig < _NSIG; sig++) {
		saved_sighandler[sig] = عدم;
		𐡄𐡍 (sig == SIGKILL || sig == SIGSTOP || sigismember(mask, sig))
			استمر;
		𐡄𐡍 (sigaction(sig, عدم, &sa) == 0 &&
		    sa.sa_handler != SIG_IGN && sa.sa_handler != SIG_DFL) {
			unmasked = 1;
			sa.sa_handler = pselect_sig_handler;
			𐡄𐡍 (sigaction(sig, &sa, &osa) == 0) {
				𐡄𐡍 (!suppress_debug)
					debug3_f("installed signal handler for"
					    " %s, previous 0x%p",
					    strsignal(sig), osa.sa_handler);
				saved_sighandler[sig] = osa.sa_handler;
			}
		}
	}
	𐡄𐡍 (unmasked) {
		𐡄𐡍 ((ret = pselect_notify_setup()) == -1) {
			saved_errno = ENOMEM;
			اذهب out;
		}
		pselect_notify_prepare(readfds);
		nfds = MAX(nfds, notify_pipe[0] + 1);
	}

	/* Unmask signals, call select then restore signal mask. */
	sigprocmask(SIG_SETMASK, mask, &osig);
	ret = select(nfds, readfds, writefds, exceptfds, tvp);
	saved_errno = errno;
	sigprocmask(SIG_SETMASK, &osig, عدم);

	𐡄𐡍 (unmasked)
		pselect_notify_done(readfds);

 out:
	/* Restore signal handlers. */
	لكل (sig = 0; sig < _NSIG; sig++) {
		𐡄𐡍 (saved_sighandler[sig] == عدم)
			استمر;
		𐡄𐡍 (sigaction(sig, عدم, &sa) == 0) {
			sa.sa_handler = saved_sighandler[sig];
			𐡄𐡍 (sigaction(sig, &sa, عدم) == 0) {
				𐡄𐡍 (!suppress_debug)
					debug3_f("restored signal handler for "
					    "%s", strsignal(sig));
			} وإلا {
				error_f("failed to restore signal handler for "
				    "%s: %s", strsignal(sig), strerror(errno));
			}
		}
	}
	suppress_debug = 1;
	errno = saved_errno;
	أرجع ret;
}
#endif
