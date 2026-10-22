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

#ಆದರೆ !HAVE_SIGACTION && HAVE_SIGVEC

ಪೂರ್ಣಾಂಕ
sigaction(ಪೂರ್ಣಾಂಕ sig, ರಚನೆ sigaction *sigact, ರಚನೆ sigaction *osigact)
{
	ಹಿಂತಿರುಗಿ sigvec(sig, sigact ? &sigact->sv : ಖಾಲಿ,
	    osigact ? &osigact->sv : ಖಾಲಿ);
}

ಪೂರ್ಣಾಂಕ
sigemptyset (sigset_t *ಮುಖವಾಡ)
{
	ಆದರೆ (!ಮುಖವಾಡ) {
		errno = EINVAL;
		ಹಿಂತಿರುಗಿ -1;
	}
	*ಮುಖವಾಡ = 0;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sigprocmask (ಪೂರ್ಣಾಂಕ ಬಹುಲಕ, sigset_t *ಮುಖವಾಡ, sigset_t *omask)
{
	sigset_t current = sigsetmask(0);

	ಆದರೆ (!ಮುಖವಾಡ) {
		errno = EINVAL;
		ಹಿಂತಿರುಗಿ -1;
	}

	ಆದರೆ (omask)
		*omask = current;

	ಆದರೆ (ಬಹುಲಕ == SIG_BLOCK)
		current |= *ಮುಖವಾಡ;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಬಹುಲಕ == SIG_UNBLOCK)
		current &= ~*ಮುಖವಾಡ;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಬಹುಲಕ == SIG_SETMASK)
	current = *ಮುಖವಾಡ;

	sigsetmask(current);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sigsuspend (sigset_t *ಮುಖವಾಡ)
{
	ಆದರೆ (!ಮುಖವಾಡ) {
		errno = EINVAL;
		ಹಿಂತಿರುಗಿ -1;
	}
	ಹಿಂತಿರುಗಿ sigpause(*ಮುಖವಾಡ);
}

ಪೂರ್ಣಾಂಕ
sigdelset (sigset_t *ಮುಖವಾಡ, ಪೂರ್ಣಾಂಕ sig)
{
	ಆದರೆ (!ಮುಖವಾಡ) {
		errno = EINVAL;
		ಹಿಂತಿರುಗಿ -1;
	}
	*ಮುಖವಾಡ &= ~sigmask(sig);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sigaddset (sigset_t *ಮುಖವಾಡ, ಪೂರ್ಣಾಂಕ sig)
{
	ಆದರೆ (!ಮುಖವಾಡ) {
		errno = EINVAL;
		ಹಿಂತಿರುಗಿ -1;
	}
	*ಮುಖವಾಡ |= sigmask(sig);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sigismember (sigset_t *ಮುಖವಾಡ, ಪೂರ್ಣಾಂಕ sig)
{
	ಆದರೆ (!ಮುಖವಾಡ) {
		errno = EINVAL;
		ಹಿಂತಿರುಗಿ -1;
	}
	ಹಿಂತಿರುಗಿ (*ಮುಖವಾಡ & sigmask(sig)) != 0;
}

#ಆದರೆ_ಅಂತ್ಯ
