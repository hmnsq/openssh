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

#شامل "includes.h"
#اگر_غیر_تعریف_شدہ HAVE_PSELECT

#شامل <sys/types.h>
#شامل <sys/time.h>
#اگر_تعریف_شدہ HAVE_SYS_SELECT_H
# include <sys/select.h>
#اگر_ختم

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <signal.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل "log.h"

#اگر_غیر_تعریف_شدہ HAVE_SIGHANDLER_T
قسمتعریف خالی (*sighandler_t)(صحیح);
#اگر_ختم

ساکن sighandler_t saved_sighandler[_NSIG];
ساکن صحیح notify_pipe[2];	/* 0 = read end, 1 = write end */

/*
 * Because the debugging for this is so noisy, we only output on the first
 * call, and suppress it thereafter.
 */
ساکن صحیح suppress_debug;

ساکن خالی
pselect_سیٹ_nonblock(صحیح fd)
{
	صحیح val;

	اگر ((val = fcntl(fd, F_GETFL)) == -1 ||
	     fcntl(fd, F_SETFL, val|O_NONBLOCK) == -1)
		error_f("fcntl: %s", strerror(errno));
}

/*
 * we write to this pipe if a SIGCHLD is caught in order to avoid
 * the race between select() and child_terminated.
 */
ساکن صحیح
pselect_notify_تیاری(خالی)
{
	اگر (pipe(notify_pipe) == -1) {
		error("pipe(notify_pipe) failed %s", strerror(errno));
		notify_pipe[0] = notify_pipe[1] = -1;
		واپس -1;
	}
	pselect_سیٹ_nonblock(notify_pipe[0]);
	pselect_سیٹ_nonblock(notify_pipe[1]);
	اگر (!suppress_debug)
		debug3_f("pipe0 %d pipe1 %d", notify_pipe[0], notify_pipe[1]);
	واپس 0;
}
ساکن خالی
pselect_notify_والد(خالی)
{
	اگر (notify_pipe[1] != -1)
		(خالی)اكتب(notify_pipe[1], "", 1);
}
ساکن خالی
pselect_notify_prepare(fd_set *readset)
{
	اگر (notify_pipe[0] != -1)
		FD_SET(notify_pipe[0], readset);
}
ساکن خالی
pselect_notify_مکمل(fd_set *readset)
{
	حرف c;

	اگر (notify_pipe[0] != -1 && FD_ISSET(notify_pipe[0], readset)) {
		جب (اقرأ(notify_pipe[0], &c, 1) != -1)
			debug2_f("reading");
		FD_CLR(notify_pipe[0], readset);
	}
	(خالی)close(notify_pipe[0]);
	(خالی)close(notify_pipe[1]);
}

/*ARGSUSED*/
ساکن خالی
pselect_sig_handler(صحیح sig)
{
	صحیح save_errno = errno;

	pselect_notify_والد();
	اگر (saved_sighandler[sig] != تہی)
		(*saved_sighandler[sig])(sig);  /* call original handler */
	errno = save_errno;
}

/*
 * A minimal implementation of pselect(2), built on top of select(2).
 */

صحیح
pselect(صحیح nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    ثابت ساخت timespec *timeout, ثابت sigset_t *نقاب)
{
	صحیح ret, sig, saved_errno, unmasked = 0;
	sigset_t osig;
	ساخت sigaction sa, osa;
	ساخت timeval tv, *tvp = تہی;

	اگر (timeout != تہی) {
		tv.tv_sec = timeout->tv_sec;
		tv.tv_usec = timeout->tv_nsec / 1000;
		tvp = &tv;
	}
	اگر (نقاب == تہی)  /* no signal mask, just call select */
		واپس select(nfds, readfds, writefds, exceptfds, tvp);

	/* For each signal unmasked, save old handler and install ours. */
	برائے (sig = 0; sig < _NSIG; sig++) {
		saved_sighandler[sig] = تہی;
		اگر (sig == SIGKILL || sig == SIGSTOP || sigismember(نقاب, sig))
			جاری;
		اگر (sigaction(sig, تہی, &sa) == 0 &&
		    sa.sa_handler != SIG_IGN && sa.sa_handler != SIG_DFL) {
			unmasked = 1;
			sa.sa_handler = pselect_sig_handler;
			اگر (sigaction(sig, &sa, &osa) == 0) {
				اگر (!suppress_debug)
					debug3_f("installed signal handler for"
					    " %s, previous 0x%p",
					    strsignal(sig), osa.sa_handler);
				saved_sighandler[sig] = osa.sa_handler;
			}
		}
	}
	اگر (unmasked) {
		اگر ((ret = pselect_notify_تیاری()) == -1) {
			saved_errno = ENOMEM;
			جاؤ برآمد;
		}
		pselect_notify_prepare(readfds);
		nfds = MAX(nfds, notify_pipe[0] + 1);
	}

	/* Unmask signals, call select then restore signal mask. */
	sigprocmask(SIG_SETMASK, نقاب, &osig);
	ret = select(nfds, readfds, writefds, exceptfds, tvp);
	saved_errno = errno;
	sigprocmask(SIG_SETMASK, &osig, تہی);

	اگر (unmasked)
		pselect_notify_مکمل(readfds);

 برآمد:
	/* Restore signal handlers. */
	برائے (sig = 0; sig < _NSIG; sig++) {
		اگر (saved_sighandler[sig] == تہی)
			جاری;
		اگر (sigaction(sig, تہی, &sa) == 0) {
			sa.sa_handler = saved_sighandler[sig];
			اگر (sigaction(sig, &sa, تہی) == 0) {
				اگر (!suppress_debug)
					debug3_f("restored signal handler for "
					    "%s", strsignal(sig));
			} ورنہ {
				error_f("failed to restore signal handler for "
				    "%s: %s", strsignal(sig), strerror(errno));
			}
		}
	}
	suppress_debug = 1;
	errno = saved_errno;
	واپس ret;
}
#اگر_ختم
