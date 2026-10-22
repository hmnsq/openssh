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

#ಅನ್ತರ್ಭಾವ "includes.h"
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ "sigact.h"

/* This file provides sigaction() emulation using sigvec() */
/* Use only if this is non POSIX system */

#ಯದಿ !HAVE_SIGACTION && HAVE_SIGVEC

ಪೂರ್ಣಾಙ್ಕ
sigaction(ಪೂರ್ಣಾಙ್ಕ sig, ಸಂರಚನಾ sigaction *sigact, ಸಂರಚನಾ sigaction *osigact)
{
	ಪ್ರತ್ಯಾಗಮ sigvec(sig, sigact ? &sigact->sv : ರಿಕ್ತ,
	    osigact ? &osigact->sv : ರಿಕ್ತ);
}

ಪೂರ್ಣಾಙ್ಕ
sigemptyset (sigset_t *mask)
{
	ಯದಿ (!mask) {
		errno = EINVAL;
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	*mask = 0;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sigprocmask (ಪೂರ್ಣಾಙ್ಕ mode, sigset_t *mask, sigset_t *omask)
{
	sigset_t current = sigsetmask(0);

	ಯದಿ (!mask) {
		errno = EINVAL;
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	ಯದಿ (omask)
		*omask = current;

	ಯದಿ (mode == SIG_BLOCK)
		current |= *mask;
	ಅನ್ಯಥಾ ಯದಿ (mode == SIG_UNBLOCK)
		current &= ~*mask;
	ಅನ್ಯಥಾ ಯದಿ (mode == SIG_SETMASK)
	current = *mask;

	sigsetmask(current);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sigsuspend (sigset_t *mask)
{
	ಯದಿ (!mask) {
		errno = EINVAL;
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತ್ಯಾಗಮ sigpause(*mask);
}

ಪೂರ್ಣಾಙ್ಕ
sigdelset (sigset_t *mask, ಪೂರ್ಣಾಙ್ಕ sig)
{
	ಯದಿ (!mask) {
		errno = EINVAL;
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	*mask &= ~sigmask(sig);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sigaddset (sigset_t *mask, ಪೂರ್ಣಾಙ್ಕ sig)
{
	ಯದಿ (!mask) {
		errno = EINVAL;
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	*mask |= sigmask(sig);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sigismember (sigset_t *mask, ಪೂರ್ಣಾಙ್ಕ sig)
{
	ಯದಿ (!mask) {
		errno = EINVAL;
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತ್ಯಾಗಮ (*mask & sigmask(sig)) != 0;
}

#endif
