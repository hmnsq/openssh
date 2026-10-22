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

#അന്തര്ഭാവ "includes.h"
#ifndef HAVE_PSELECT

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/time.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "log.h"

#ifndef HAVE_SIGHANDLER_T
തരനിർവചനം ശൂന്യം (*sighandler_t)(പൂർണ്ണസംഖ്യ);
#endif

സ്ഥിതം sighandler_t saved_sighandler[_NSIG];
സ്ഥിതം പൂർണ്ണസംഖ്യ notify_pipe[2];	/* 0 = read end, 1 = write end */

/*
 * Because the debugging for this is so noisy, we only output on the first
 * call, and suppress it thereafter.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ suppress_debug;

സ്ഥിതം ശൂന്യം
pselect_set_nonblock(പൂർണ്ണസംഖ്യ fd)
{
	പൂർണ്ണസംഖ്യ val;

	എങ്കിൽ ((val = fcntl(fd, F_GETFL)) == -1 ||
	     fcntl(fd, F_SETFL, val|O_NONBLOCK) == -1)
		error_f("fcntl: %s", strerror(errno));
}

/*
 * we write to this pipe if a SIGCHLD is caught in order to avoid
 * the race between select() and child_terminated.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
pselect_notify_setup(ശൂന്യം)
{
	എങ്കിൽ (pipe(notify_pipe) == -1) {
		error("pipe(notify_pipe) failed %s", strerror(errno));
		notify_pipe[0] = notify_pipe[1] = -1;
		തിരികെ -1;
	}
	pselect_set_nonblock(notify_pipe[0]);
	pselect_set_nonblock(notify_pipe[1]);
	എങ്കിൽ (!suppress_debug)
		debug3_f("pipe0 %d pipe1 %d", notify_pipe[0], notify_pipe[1]);
	തിരികെ 0;
}
സ്ഥിതം ശൂന്യം
pselect_notify_parent(ശൂന്യം)
{
	എങ്കിൽ (notify_pipe[1] != -1)
		(ശൂന്യം)ലിഖ(notify_pipe[1], "", 1);
}
സ്ഥിതം ശൂന്യം
pselect_notify_prepare(fd_set *readset)
{
	എങ്കിൽ (notify_pipe[0] != -1)
		FD_SET(notify_pipe[0], readset);
}
സ്ഥിതം ശൂന്യം
pselect_notify_done(fd_set *readset)
{
	അക്ഷരം c;

	എങ്കിൽ (notify_pipe[0] != -1 && FD_ISSET(notify_pipe[0], readset)) {
		ആകുമ്പോൾ (പഠ(notify_pipe[0], &c, 1) != -1)
			debug2_f("reading");
		FD_CLR(notify_pipe[0], readset);
	}
	(ശൂന്യം)close(notify_pipe[0]);
	(ശൂന്യം)close(notify_pipe[1]);
}

/*ARGSUSED*/
സ്ഥിതം ശൂന്യം
pselect_sig_handler(പൂർണ്ണസംഖ്യ sig)
{
	പൂർണ്ണസംഖ്യ save_errno = errno;

	pselect_notify_parent();
	എങ്കിൽ (saved_sighandler[sig] != ശൂന്യ)
		(*saved_sighandler[sig])(sig);  /* call original handler */
	errno = save_errno;
}

/*
 * A minimal implementation of pselect(2), built on top of select(2).
 */

പൂർണ്ണസംഖ്യ
pselect(പൂർണ്ണസംഖ്യ nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    സ്ഥിരം ഘടന timespec *timeout, സ്ഥിരം sigset_t *mask)
{
	പൂർണ്ണസംഖ്യ ret, sig, saved_errno, unmasked = 0;
	sigset_t osig;
	ഘടന sigaction sa, osa;
	ഘടന timeval tv, *tvp = ശൂന്യ;

	എങ്കിൽ (timeout != ശൂന്യ) {
		tv.tv_sec = timeout->tv_sec;
		tv.tv_usec = timeout->tv_nsec / 1000;
		tvp = &tv;
	}
	എങ്കിൽ (mask == ശൂന്യ)  /* no signal mask, just call select */
		തിരികെ select(nfds, readfds, writefds, exceptfds, tvp);

	/* For each signal unmasked, save old handler and install ours. */
	വേണ്ടി (sig = 0; sig < _NSIG; sig++) {
		saved_sighandler[sig] = ശൂന്യ;
		എങ്കിൽ (sig == SIGKILL || sig == SIGSTOP || sigismember(mask, sig))
			തുടരുക;
		എങ്കിൽ (sigaction(sig, ശൂന്യ, &sa) == 0 &&
		    sa.sa_handler != SIG_IGN && sa.sa_handler != SIG_DFL) {
			unmasked = 1;
			sa.sa_handler = pselect_sig_handler;
			എങ്കിൽ (sigaction(sig, &sa, &osa) == 0) {
				എങ്കിൽ (!suppress_debug)
					debug3_f("installed signal handler for"
					    " %s, previous 0x%p",
					    strsignal(sig), osa.sa_handler);
				saved_sighandler[sig] = osa.sa_handler;
			}
		}
	}
	എങ്കിൽ (unmasked) {
		എങ്കിൽ ((ret = pselect_notify_setup()) == -1) {
			saved_errno = ENOMEM;
			പോകുക out;
		}
		pselect_notify_prepare(readfds);
		nfds = MAX(nfds, notify_pipe[0] + 1);
	}

	/* Unmask signals, call select then restore signal mask. */
	sigprocmask(SIG_SETMASK, mask, &osig);
	ret = select(nfds, readfds, writefds, exceptfds, tvp);
	saved_errno = errno;
	sigprocmask(SIG_SETMASK, &osig, ശൂന്യ);

	എങ്കിൽ (unmasked)
		pselect_notify_done(readfds);

 out:
	/* Restore signal handlers. */
	വേണ്ടി (sig = 0; sig < _NSIG; sig++) {
		എങ്കിൽ (saved_sighandler[sig] == ശൂന്യ)
			തുടരുക;
		എങ്കിൽ (sigaction(sig, ശൂന്യ, &sa) == 0) {
			sa.sa_handler = saved_sighandler[sig];
			എങ്കിൽ (sigaction(sig, &sa, ശൂന്യ) == 0) {
				എങ്കിൽ (!suppress_debug)
					debug3_f("restored signal handler for "
					    "%s", strsignal(sig));
			} അല്ലെങ്കിൽ {
				error_f("failed to restore signal handler for "
				    "%s: %s", strsignal(sig), strerror(errno));
			}
		}
	}
	suppress_debug = 1;
	errno = saved_errno;
	തിരികെ ret;
}
#endif
