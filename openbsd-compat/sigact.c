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

#include "includes.h"
#include <errno.h>
#include <signal.h>
#include "sigact.h"

/* This file provides sigaction() emulation using sigvec() */
/* Use only if this is non POSIX system */

#නම් !HAVE_SIGACTION && HAVE_SIGVEC

පූර්ණ_සංඛ්‍යා
sigaction(පූර්ණ_සංඛ්‍යා sig, sa_nracanaa sigaction *sigact, sa_nracanaa sigaction *osigact)
{
	ආපසු sigvec(sig, sigact ? &sigact->sv : NULL,
	    osigact ? &osigact->sv : NULL);
}

පූර්ණ_සංඛ්‍යා
sigemptyset (sigset_t *mask)
{
	නම් (!mask) {
		errno = EINVAL;
		ආපසු -1;
	}
	*mask = 0;
	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
sigprocmask (පූර්ණ_සංඛ්‍යා mode, sigset_t *mask, sigset_t *omask)
{
	sigset_t current = sigsetmask(0);

	නම් (!mask) {
		errno = EINVAL;
		ආපසු -1;
	}

	නම් (omask)
		*omask = current;

	නම් (mode == SIG_BLOCK)
		current |= *mask;
	නැතහොත් නම් (mode == SIG_UNBLOCK)
		current &= ~*mask;
	නැතහොත් නම් (mode == SIG_SETMASK)
	current = *mask;

	sigsetmask(current);
	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
sigsuspend (sigset_t *mask)
{
	නම් (!mask) {
		errno = EINVAL;
		ආපසු -1;
	}
	ආපසු sigpause(*mask);
}

පූර්ණ_සංඛ්‍යා
sigdelset (sigset_t *mask, පූර්ණ_සංඛ්‍යා sig)
{
	නම් (!mask) {
		errno = EINVAL;
		ආපසු -1;
	}
	*mask &= ~sigmask(sig);
	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
sigaddset (sigset_t *mask, පූර්ණ_සංඛ්‍යා sig)
{
	නම් (!mask) {
		errno = EINVAL;
		ආපසු -1;
	}
	*mask |= sigmask(sig);
	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
sigismember (sigset_t *mask, පූර්ණ_සංඛ්‍යා sig)
{
	නම් (!mask) {
		errno = EINVAL;
		ආපසු -1;
	}
	ආපසු (*mask & sigmask(sig)) != 0;
}

#endif
