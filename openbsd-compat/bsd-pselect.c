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

#અન્તર્ભાવ "includes.h"
#ifndef HAVE_PSELECT

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/time.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "log.h"

#ifndef HAVE_SIGHANDLER_T
પ્રકારવ્યાખ્યા શૂન્ય (*sighandler_t)(પૂર્ણાંક);
#endif

સ્થિર sighandler_t saved_sighandler[_NSIG];
સ્થિર પૂર્ણાંક notify_pipe[2];	/* 0 = read end, 1 = write end */

/*
 * Because the debugging for this is so noisy, we only output on the first
 * call, and suppress it thereafter.
 */
સ્થિર પૂર્ણાંક suppress_debug;

સ્થિર શૂન્ય
pselect_set_nonblock(પૂર્ણાંક fd)
{
	પૂર્ણાંક val;

	જો ((val = fcntl(fd, F_GETFL)) == -1 ||
	     fcntl(fd, F_SETFL, val|O_NONBLOCK) == -1)
		error_f("fcntl: %s", strerror(errno));
}

/*
 * we write to this pipe if a SIGCHLD is caught in order to avoid
 * the race between select() and child_terminated.
 */
સ્થિર પૂર્ણાંક
pselect_notify_setup(શૂન્ય)
{
	જો (pipe(notify_pipe) == -1) {
		error("pipe(notify_pipe) failed %s", strerror(errno));
		notify_pipe[0] = notify_pipe[1] = -1;
		પાછા -1;
	}
	pselect_set_nonblock(notify_pipe[0]);
	pselect_set_nonblock(notify_pipe[1]);
	જો (!suppress_debug)
		debug3_f("pipe0 %d pipe1 %d", notify_pipe[0], notify_pipe[1]);
	પાછા 0;
}
સ્થિર શૂન્ય
pselect_notify_parent(શૂન્ય)
{
	જો (notify_pipe[1] != -1)
		(શૂન્ય)લિખ(notify_pipe[1], "", 1);
}
સ્થિર શૂન્ય
pselect_notify_prepare(fd_set *readset)
{
	જો (notify_pipe[0] != -1)
		FD_SET(notify_pipe[0], readset);
}
સ્થિર શૂન્ય
pselect_notify_done(fd_set *readset)
{
	અક્ષર c;

	જો (notify_pipe[0] != -1 && FD_ISSET(notify_pipe[0], readset)) {
		જ્યારે (પઠ(notify_pipe[0], &c, 1) != -1)
			debug2_f("reading");
		FD_CLR(notify_pipe[0], readset);
	}
	(શૂન્ય)close(notify_pipe[0]);
	(શૂન્ય)close(notify_pipe[1]);
}

/*ARGSUSED*/
સ્થિર શૂન્ય
pselect_sig_handler(પૂર્ણાંક sig)
{
	પૂર્ણાંક save_errno = errno;

	pselect_notify_parent();
	જો (saved_sighandler[sig] != ખાલી)
		(*saved_sighandler[sig])(sig);  /* call original handler */
	errno = save_errno;
}

/*
 * A minimal implementation of pselect(2), built on top of select(2).
 */

પૂર્ણાંક
pselect(પૂર્ણાંક nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    અચલ સંરચના timespec *timeout, અચલ sigset_t *mask)
{
	પૂર્ણાંક ret, sig, saved_errno, unmasked = 0;
	sigset_t osig;
	સંરચના sigaction sa, osa;
	સંરચના timeval tv, *tvp = ખાલી;

	જો (timeout != ખાલી) {
		tv.tv_sec = timeout->tv_sec;
		tv.tv_usec = timeout->tv_nsec / 1000;
		tvp = &tv;
	}
	જો (mask == ખાલી)  /* no signal mask, just call select */
		પાછા select(nfds, readfds, writefds, exceptfds, tvp);

	/* For each signal unmasked, save old handler and install ours. */
	માટે (sig = 0; sig < _NSIG; sig++) {
		saved_sighandler[sig] = ખાલી;
		જો (sig == SIGKILL || sig == SIGSTOP || sigismember(mask, sig))
			ચાલુ;
		જો (sigaction(sig, ખાલી, &sa) == 0 &&
		    sa.sa_handler != SIG_IGN && sa.sa_handler != SIG_DFL) {
			unmasked = 1;
			sa.sa_handler = pselect_sig_handler;
			જો (sigaction(sig, &sa, &osa) == 0) {
				જો (!suppress_debug)
					debug3_f("installed signal handler for"
					    " %s, previous 0x%p",
					    strsignal(sig), osa.sa_handler);
				saved_sighandler[sig] = osa.sa_handler;
			}
		}
	}
	જો (unmasked) {
		જો ((ret = pselect_notify_setup()) == -1) {
			saved_errno = ENOMEM;
			જાઓ out;
		}
		pselect_notify_prepare(readfds);
		nfds = MAX(nfds, notify_pipe[0] + 1);
	}

	/* Unmask signals, call select then restore signal mask. */
	sigprocmask(SIG_SETMASK, mask, &osig);
	ret = select(nfds, readfds, writefds, exceptfds, tvp);
	saved_errno = errno;
	sigprocmask(SIG_SETMASK, &osig, ખાલી);

	જો (unmasked)
		pselect_notify_done(readfds);

 out:
	/* Restore signal handlers. */
	માટે (sig = 0; sig < _NSIG; sig++) {
		જો (saved_sighandler[sig] == ખાલી)
			ચાલુ;
		જો (sigaction(sig, ખાલી, &sa) == 0) {
			sa.sa_handler = saved_sighandler[sig];
			જો (sigaction(sig, &sa, ખાલી) == 0) {
				જો (!suppress_debug)
					debug3_f("restored signal handler for "
					    "%s", strsignal(sig));
			} નહીંતર {
				error_f("failed to restore signal handler for "
				    "%s: %s", strsignal(sig), strerror(errno));
			}
		}
	}
	suppress_debug = 1;
	errno = saved_errno;
	પાછા ret;
}
#endif
