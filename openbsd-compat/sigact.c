/*	$OpenBSD: sigaction.c,v 1.4 2001/01/22 18:01:48 millert Exp $	*/

/****************************************************************************
 * Copyright (c) 1998,2000 Free Software Foundation, Inc.                   *
 *                                                                          *
 * Permission is hereby granted, free of charge, to any person obtaining a  *
 * copy of this software and associated documentation files (the            *
 * "Software"), to deal in the Software without restriction, including      *
 * without limitation the rights to use, copy, modify, merge, publish,      *
 * distribute, distribute with modifications, sublicense, and/or sell       *
 * copies of the Software, and to permit persons to whom the Software is    *
 * furnished to do so, subject to the following conditions:                 *
 *                                                                          *
 * The above copyright notice and this permission notice shall be included  *
 * in all copies or substantial portions of the Software.                   *
 *                                                                          *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS  *
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF               *
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.   *
 * IN NO EVENT SHALL THE ABOVE COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,   *
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR    *
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR    *
 * THE USE OR OTHER DEALINGS IN THE SOFTWARE.                               *
 *                                                                          *
 * Except as contained in this notice, the name(s) of the above copyright   *
 * holders shall not be used in advertising or otherwise to promote the     *
 * sale, use or other dealings in this Software without prior written       *
 * authorization.                                                           *
 ****************************************************************************/

/****************************************************************************
 *  Author: Zeyd M. Ben-Halim <zmbenhal@netcom.com> 1992,1995               *
 *     and: Eric S. Raymond <esr@snark.thyrsus.com>                         *
 ****************************************************************************/

/* OPENBSD ORIGINAL: lib/libcurses/base/sigaction.c */

#ଅନ୍ତର୍ଭାଵ "includes.h"
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ "sigact.h"

/* This file provides sigaction() emulation using sigvec() */
/* Use only if this is non POSIX system */

#ଯଦି !HAVE_SIGACTION && HAVE_SIGVEC

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sigaction(ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig, ସଂରଚନା sigaction *sigact, ସଂରଚନା sigaction *osigact)
{
	ଫେରନ୍ତୁ sigvec(sig, sigact ? &sigact->sv : ଖାଲି,
	    osigact ? &osigact->sv : ଖାଲି);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sigemptyset (sigset_t *mask)
{
	ଯଦି (!mask) {
		errno = EINVAL;
		ଫେରନ୍ତୁ -1;
	}
	*mask = 0;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sigprocmask (ପୂର୍ଣ୍ଣସଂଖ୍ୟା mode, sigset_t *mask, sigset_t *omask)
{
	sigset_t current = sigsetmask(0);

	ଯଦି (!mask) {
		errno = EINVAL;
		ଫେରନ୍ତୁ -1;
	}

	ଯଦି (omask)
		*omask = current;

	ଯଦି (mode == SIG_BLOCK)
		current |= *mask;
	ଅନ୍ୟଥା ଯଦି (mode == SIG_UNBLOCK)
		current &= ~*mask;
	ଅନ୍ୟଥା ଯଦି (mode == SIG_SETMASK)
	current = *mask;

	sigsetmask(current);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sigsuspend (sigset_t *mask)
{
	ଯଦି (!mask) {
		errno = EINVAL;
		ଫେରନ୍ତୁ -1;
	}
	ଫେରନ୍ତୁ sigpause(*mask);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sigdelset (sigset_t *mask, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig)
{
	ଯଦି (!mask) {
		errno = EINVAL;
		ଫେରନ୍ତୁ -1;
	}
	*mask &= ~sigmask(sig);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sigaddset (sigset_t *mask, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig)
{
	ଯଦି (!mask) {
		errno = EINVAL;
		ଫେରନ୍ତୁ -1;
	}
	*mask |= sigmask(sig);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sigismember (sigset_t *mask, ପୂର୍ଣ୍ଣସଂଖ୍ୟା sig)
{
	ଯଦି (!mask) {
		errno = EINVAL;
		ଫେରନ୍ତୁ -1;
	}
	ଫେରନ୍ତୁ (*mask & sigmask(sig)) != 0;
}

#endif
