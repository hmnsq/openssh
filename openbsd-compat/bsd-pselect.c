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

#अन्तर्भाव "includes.h"
#ifndef HAVE_PSELECT

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/time.h>
#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "log.h"

#ifndef HAVE_SIGHANDLER_T
प्रकारनिर्देश शून्य (*sighandler_t)(पूर्णाङ्क);
#endif

स्थिर sighandler_t saved_sighandler[_NSIG];
स्थिर पूर्णाङ्क notify_pipe[2];	/* 0 = read end, 1 = write end */

/*
 * Because the debugging for this is so noisy, we only output on the first
 * call, and suppress it thereafter.
 */
स्थिर पूर्णाङ्क suppress_debug;

स्थिर शून्य
pselect_set_nonblock(पूर्णाङ्क fd)
{
	पूर्णाङ्क val;

	यदि ((val = fcntl(fd, F_GETFL)) == -1 ||
	     fcntl(fd, F_SETFL, val|O_NONBLOCK) == -1)
		error_f("fcntl: %s", म_त्रुटि(त्रुटि_सं));
}

/*
 * we write to this pipe if a SIGCHLD is caught in order to avoid
 * the race between select() and child_terminated.
 */
स्थिर पूर्णाङ्क
pselect_notify_setup(शून्य)
{
	यदि (pipe(notify_pipe) == -1) {
		error("pipe(notify_pipe) failed %s", म_त्रुटि(त्रुटि_सं));
		notify_pipe[0] = notify_pipe[1] = -1;
		प्रत्यागम -1;
	}
	pselect_set_nonblock(notify_pipe[0]);
	pselect_set_nonblock(notify_pipe[1]);
	यदि (!suppress_debug)
		debug3_f("pipe0 %d pipe1 %d", notify_pipe[0], notify_pipe[1]);
	प्रत्यागम 0;
}
स्थिर शून्य
pselect_notify_parent(शून्य)
{
	यदि (notify_pipe[1] != -1)
		(शून्य)लिख(notify_pipe[1], "", 1);
}
स्थिर शून्य
pselect_notify_prepare(fd_set *readset)
{
	यदि (notify_pipe[0] != -1)
		FD_SET(notify_pipe[0], readset);
}
स्थिर शून्य
pselect_notify_done(fd_set *readset)
{
	वर्ण c;

	यदि (notify_pipe[0] != -1 && FD_ISSET(notify_pipe[0], readset)) {
		यावत् (पठ(notify_pipe[0], &c, 1) != -1)
			debug2_f("reading");
		FD_CLR(notify_pipe[0], readset);
	}
	(शून्य)बंद(notify_pipe[0]);
	(शून्य)बंद(notify_pipe[1]);
}

/*ARGSUSED*/
स्थिर शून्य
pselect_sig_handler(पूर्णाङ्क sig)
{
	पूर्णाङ्क save_errno = त्रुटि_सं;

	pselect_notify_parent();
	यदि (saved_sighandler[sig] != रिक्त)
		(*saved_sighandler[sig])(sig);  /* call original handler */
	त्रुटि_सं = save_errno;
}

/*
 * A minimal implementation of pselect(2), built on top of select(2).
 */

पूर्णाङ्क
pselect(पूर्णाङ्क nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    ध्रुव संरचना timespec *timeout, ध्रुव sigset_t *mask)
{
	पूर्णाङ्क ret, sig, saved_errno, unmasked = 0;
	sigset_t osig;
	संरचना sigaction sa, osa;
	संरचना timeval tv, *tvp = रिक्त;

	यदि (timeout != रिक्त) {
		tv.tv_sec = timeout->tv_sec;
		tv.tv_usec = timeout->tv_nsec / 1000;
		tvp = &tv;
	}
	यदि (mask == रिक्त)  /* no signal mask, just call select */
		प्रत्यागम select(nfds, readfds, writefds, exceptfds, tvp);

	/* For each signal unmasked, save old handler and install ours. */
	प्रति (sig = 0; sig < _NSIG; sig++) {
		saved_sighandler[sig] = रिक्त;
		यदि (sig == SIGKILL || sig == SIGSTOP || sigismember(mask, sig))
			अनुवर्त;
		यदि (sigaction(sig, रिक्त, &sa) == 0 &&
		    sa.sa_handler != संक_छोड़ो && sa.sa_handler != संक_पूर्व) {
			unmasked = 1;
			sa.sa_handler = pselect_sig_handler;
			यदि (sigaction(sig, &sa, &osa) == 0) {
				यदि (!suppress_debug)
					debug3_f("installed signal handler for"
					    " %s, previous 0x%p",
					    strsignal(sig), osa.sa_handler);
				saved_sighandler[sig] = osa.sa_handler;
			}
		}
	}
	यदि (unmasked) {
		यदि ((ret = pselect_notify_setup()) == -1) {
			saved_errno = ENOMEM;
			गच्छ out;
		}
		pselect_notify_prepare(readfds);
		nfds = MAX(nfds, notify_pipe[0] + 1);
	}

	/* Unmask signals, call select then restore signal mask. */
	sigprocmask(SIG_SETMASK, mask, &osig);
	ret = select(nfds, readfds, writefds, exceptfds, tvp);
	saved_errno = त्रुटि_सं;
	sigprocmask(SIG_SETMASK, &osig, रिक्त);

	यदि (unmasked)
		pselect_notify_done(readfds);

 out:
	/* Restore signal handlers. */
	प्रति (sig = 0; sig < _NSIG; sig++) {
		यदि (saved_sighandler[sig] == रिक्त)
			अनुवर्त;
		यदि (sigaction(sig, रिक्त, &sa) == 0) {
			sa.sa_handler = saved_sighandler[sig];
			यदि (sigaction(sig, &sa, रिक्त) == 0) {
				यदि (!suppress_debug)
					debug3_f("restored signal handler for "
					    "%s", strsignal(sig));
			} अन्यथा {
				error_f("failed to restore signal handler for "
				    "%s: %s", strsignal(sig), म_त्रुटि(त्रुटि_सं));
			}
		}
	}
	suppress_debug = 1;
	त्रुटि_सं = saved_errno;
	प्रत्यागम ret;
}
#endif
