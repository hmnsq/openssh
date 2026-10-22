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

#अन्तर्भाव "includes.h"
#अन्तर्भाव <errno.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव "sigact.h"

/* This file provides sigaction() emulation using sigvec() */
/* Use only if this is non POSIX system */

#यदि !HAVE_SIGACTION && HAVE_SIGVEC

पूर्णाङ्क
sigaction(पूर्णाङ्क sig, संरचना sigaction *sigact, संरचना sigaction *osigact)
{
	प्रत्यागम sigvec(sig, sigact ? &sigact->sv : रिक्त,
	    osigact ? &osigact->sv : रिक्त);
}

पूर्णाङ्क
sigemptyset (sigset_t *mask)
{
	यदि (!mask) {
		त्रुटि_सं = EINVAL;
		प्रत्यागम -1;
	}
	*mask = 0;
	प्रत्यागम 0;
}

पूर्णाङ्क
sigprocmask (पूर्णाङ्क mode, sigset_t *mask, sigset_t *omask)
{
	sigset_t current = sigsetmask(0);

	यदि (!mask) {
		त्रुटि_सं = EINVAL;
		प्रत्यागम -1;
	}

	यदि (omask)
		*omask = current;

	यदि (mode == SIG_BLOCK)
		current |= *mask;
	अन्यथा यदि (mode == SIG_UNBLOCK)
		current &= ~*mask;
	अन्यथा यदि (mode == SIG_SETMASK)
	current = *mask;

	sigsetmask(current);
	प्रत्यागम 0;
}

पूर्णाङ्क
संक_रोको (sigset_t *mask)
{
	यदि (!mask) {
		त्रुटि_सं = EINVAL;
		प्रत्यागम -1;
	}
	प्रत्यागम sigpause(*mask);
}

पूर्णाङ्क
sigdelset (sigset_t *mask, पूर्णाङ्क sig)
{
	यदि (!mask) {
		त्रुटि_सं = EINVAL;
		प्रत्यागम -1;
	}
	*mask &= ~sigmask(sig);
	प्रत्यागम 0;
}

पूर्णाङ्क
sigaddset (sigset_t *mask, पूर्णाङ्क sig)
{
	यदि (!mask) {
		त्रुटि_सं = EINVAL;
		प्रत्यागम -1;
	}
	*mask |= sigmask(sig);
	प्रत्यागम 0;
}

पूर्णाङ्क
sigismember (sigset_t *mask, पूर्णाङ्क sig)
{
	यदि (!mask) {
		त्रुटि_सं = EINVAL;
		प्रत्यागम -1;
	}
	प्रत्यागम (*mask & sigmask(sig)) != 0;
}

#endif
