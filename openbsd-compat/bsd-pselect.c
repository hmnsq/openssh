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

#समावेश "includes.h"
#अगर_अघोषित HAVE_PSELECT

#समावेश <sys/types.h>
#समावेश <sys/time.h>
#अगर_घोषित HAVE_SYS_SELECT_H
# include <sys/select.h>
#पूर्ण_अगर

#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <signal.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>

#समावेश "log.h"

#अगर_अघोषित HAVE_SIGHANDLER_T
प्रकार व्योम (*sighandler_t)(पूर्णांक);
#पूर्ण_अगर

अटल sighandler_t saved_sighandler[_NSIG];
अटल पूर्णांक notify_pipe[2];	/* 0 = read end, 1 = write end */

/*
 * Because the debugging for this is so noisy, we only output on the first
 * call, and suppress it thereafter.
 */
अटल पूर्णांक suppress_debug;

अटल व्योम
pselect_set_nonblock(पूर्णांक fd)
{
	पूर्णांक val;

	अगर ((val = fcntl(fd, F_GETFL)) == -1 ||
	     fcntl(fd, F_SETFL, val|O_NONBLOCK) == -1)
		error_f("fcntl: %s", म_त्रुटि(त्रुटि_सं));
}

/*
 * we write to this pipe if a SIGCHLD is caught in order to avoid
 * the race between select() and child_terminated.
 */
अटल पूर्णांक
pselect_notify_setup(व्योम)
{
	अगर (pipe(notify_pipe) == -1) {
		error("pipe(notify_pipe) failed %s", म_त्रुटि(त्रुटि_सं));
		notify_pipe[0] = notify_pipe[1] = -1;
		वापस -1;
	}
	pselect_set_nonblock(notify_pipe[0]);
	pselect_set_nonblock(notify_pipe[1]);
	अगर (!suppress_debug)
		debug3_f("pipe0 %d pipe1 %d", notify_pipe[0], notify_pipe[1]);
	वापस 0;
}
अटल व्योम
pselect_notify_parent(व्योम)
{
	अगर (notify_pipe[1] != -1)
		(व्योम)ग_लिखो(notify_pipe[1], "", 1);
}
अटल व्योम
pselect_notify_prepare(fd_set *readset)
{
	अगर (notify_pipe[0] != -1)
		FD_SET(notify_pipe[0], readset);
}
अटल व्योम
pselect_notify_done(fd_set *readset)
{
	अक्षर c;

	अगर (notify_pipe[0] != -1 && FD_ISSET(notify_pipe[0], readset)) {
		जबतक (पढ़ो(notify_pipe[0], &c, 1) != -1)
			debug2_f("reading");
		FD_CLR(notify_pipe[0], readset);
	}
	(व्योम)बंद(notify_pipe[0]);
	(व्योम)बंद(notify_pipe[1]);
}

/*ARGSUSED*/
अटल व्योम
pselect_sig_handler(पूर्णांक sig)
{
	पूर्णांक save_errno = त्रुटि_सं;

	pselect_notify_parent();
	अगर (saved_sighandler[sig] != शून्य)
		(*saved_sighandler[sig])(sig);  /* call original handler */
	त्रुटि_सं = save_errno;
}

/*
 * A minimal implementation of pselect(2), built on top of select(2).
 */

पूर्णांक
pselect(पूर्णांक nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
    स्थिर काष्ठा timespec *timeout, स्थिर sigset_t *mask)
{
	पूर्णांक ret, sig, saved_errno, unmasked = 0;
	sigset_t osig;
	काष्ठा sigaction sa, osa;
	काष्ठा timeval tv, *tvp = शून्य;

	अगर (timeout != शून्य) {
		tv.tv_sec = timeout->tv_sec;
		tv.tv_usec = timeout->tv_nsec / 1000;
		tvp = &tv;
	}
	अगर (mask == शून्य)  /* no signal mask, just call select */
		वापस select(nfds, readfds, writefds, exceptfds, tvp);

	/* For each signal unmasked, save old handler and install ours. */
	क्रम (sig = 0; sig < _NSIG; sig++) {
		saved_sighandler[sig] = शून्य;
		अगर (sig == SIGKILL || sig == SIGSTOP || sigismember(mask, sig))
			जारी;
		अगर (sigaction(sig, शून्य, &sa) == 0 &&
		    sa.sa_handler != संक_छोड़ो && sa.sa_handler != संक_पूर्व) {
			unmasked = 1;
			sa.sa_handler = pselect_sig_handler;
			अगर (sigaction(sig, &sa, &osa) == 0) {
				अगर (!suppress_debug)
					debug3_f("installed signal handler for"
					    " %s, previous 0x%p",
					    strsignal(sig), osa.sa_handler);
				saved_sighandler[sig] = osa.sa_handler;
			}
		}
	}
	अगर (unmasked) {
		अगर ((ret = pselect_notify_setup()) == -1) {
			saved_errno = ENOMEM;
			जाओ out;
		}
		pselect_notify_prepare(readfds);
		nfds = MAX(nfds, notify_pipe[0] + 1);
	}

	/* Unmask signals, call select then restore signal mask. */
	sigprocmask(SIG_SETMASK, mask, &osig);
	ret = select(nfds, readfds, writefds, exceptfds, tvp);
	saved_errno = त्रुटि_सं;
	sigprocmask(SIG_SETMASK, &osig, शून्य);

	अगर (unmasked)
		pselect_notify_done(readfds);

 out:
	/* Restore signal handlers. */
	क्रम (sig = 0; sig < _NSIG; sig++) {
		अगर (saved_sighandler[sig] == शून्य)
			जारी;
		अगर (sigaction(sig, शून्य, &sa) == 0) {
			sa.sa_handler = saved_sighandler[sig];
			अगर (sigaction(sig, &sa, शून्य) == 0) {
				अगर (!suppress_debug)
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
	वापस ret;
}
#पूर्ण_अगर
