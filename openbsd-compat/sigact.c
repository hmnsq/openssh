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

#অন্তর্ভাৱ "includes.h"
#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <signal.h>
#অন্তর্ভাৱ "sigact.h"

/* This file provides sigaction() emulation using sigvec() */
/* Use only if this is non POSIX system */

#যদি !HAVE_SIGACTION && HAVE_SIGVEC

পূর্ণাঙ্ক
sigaction(পূর্ণাঙ্ক sig, সংরচনা sigaction *sigact, সংরচনা sigaction *osigact)
{
	ঘূৰাই sigvec(sig, sigact ? &sigact->sv : রিক্ত,
	    osigact ? &osigact->sv : রিক্ত);
}

পূর্ণাঙ্ক
sigemptyset (sigset_t *mask)
{
	যদি (!mask) {
		errno = EINVAL;
		ঘূৰাই -1;
	}
	*mask = 0;
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sigprocmask (পূর্ণাঙ্ক mode, sigset_t *mask, sigset_t *omask)
{
	sigset_t current = sigsetmask(0);

	যদি (!mask) {
		errno = EINVAL;
		ঘূৰাই -1;
	}

	যদি (omask)
		*omask = current;

	যদি (mode == SIG_BLOCK)
		current |= *mask;
	অন্যথা যদি (mode == SIG_UNBLOCK)
		current &= ~*mask;
	অন্যথা যদি (mode == SIG_SETMASK)
	current = *mask;

	sigsetmask(current);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sigsuspend (sigset_t *mask)
{
	যদি (!mask) {
		errno = EINVAL;
		ঘূৰাই -1;
	}
	ঘূৰাই sigpause(*mask);
}

পূর্ণাঙ্ক
sigdelset (sigset_t *mask, পূর্ণাঙ্ক sig)
{
	যদি (!mask) {
		errno = EINVAL;
		ঘূৰাই -1;
	}
	*mask &= ~sigmask(sig);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sigaddset (sigset_t *mask, পূর্ণাঙ্ক sig)
{
	যদি (!mask) {
		errno = EINVAL;
		ঘূৰাই -1;
	}
	*mask |= sigmask(sig);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sigismember (sigset_t *mask, পূর্ণাঙ্ক sig)
{
	যদি (!mask) {
		errno = EINVAL;
		ঘূৰাই -1;
	}
	ঘূৰাই (*mask & sigmask(sig)) != 0;
}

#endif
