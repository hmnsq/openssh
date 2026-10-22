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

#అన్తర్భావ "includes.h"
#అన్తర్భావ <errno.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ "sigact.h"

/* This file provides sigaction() emulation using sigvec() */
/* Use only if this is non POSIX system */

#ఒకవేళ !HAVE_SIGACTION && HAVE_SIGVEC

పూర్ణాంకం
sigaction(పూర్ణాంకం sig, నిర్మాణం sigaction *sigact, నిర్మాణం sigaction *osigact)
{
	తిరిగి sigvec(sig, sigact ? &sigact->sv : ఖాళీ,
	    osigact ? &osigact->sv : ఖాళీ);
}

పూర్ణాంకం
sigemptyset (sigset_t *ముసుగు)
{
	ఒకవేళ (!ముసుగు) {
		errno = EINVAL;
		తిరిగి -1;
	}
	*ముసుగు = 0;
	తిరిగి 0;
}

పూర్ణాంకం
sigprocmask (పూర్ణాంకం బహుళకం, sigset_t *ముసుగు, sigset_t *omask)
{
	sigset_t current = sigsetmask(0);

	ఒకవేళ (!ముసుగు) {
		errno = EINVAL;
		తిరిగి -1;
	}

	ఒకవేళ (omask)
		*omask = current;

	ఒకవేళ (బహుళకం == SIG_BLOCK)
		current |= *ముసుగు;
	లేకపోతే ఒకవేళ (బహుళకం == SIG_UNBLOCK)
		current &= ~*ముసుగు;
	లేకపోతే ఒకవేళ (బహుళకం == SIG_SETMASK)
	current = *ముసుగు;

	sigsetmask(current);
	తిరిగి 0;
}

పూర్ణాంకం
sigsuspend (sigset_t *ముసుగు)
{
	ఒకవేళ (!ముసుగు) {
		errno = EINVAL;
		తిరిగి -1;
	}
	తిరిగి sigpause(*ముసుగు);
}

పూర్ణాంకం
sigdelset (sigset_t *ముసుగు, పూర్ణాంకం sig)
{
	ఒకవేళ (!ముసుగు) {
		errno = EINVAL;
		తిరిగి -1;
	}
	*ముసుగు &= ~sigmask(sig);
	తిరిగి 0;
}

పూర్ణాంకం
sigaddset (sigset_t *ముసుగు, పూర్ణాంకం sig)
{
	ఒకవేళ (!ముసుగు) {
		errno = EINVAL;
		తిరిగి -1;
	}
	*ముసుగు |= sigmask(sig);
	తిరిగి 0;
}

పూర్ణాంకం
sigismember (sigset_t *ముసుగు, పూర్ణాంకం sig)
{
	ఒకవేళ (!ముసుగు) {
		errno = EINVAL;
		తిరిగి -1;
	}
	తిరిగి (*ముసుగు & sigmask(sig)) != 0;
}

#అయితే_ముగింపు
