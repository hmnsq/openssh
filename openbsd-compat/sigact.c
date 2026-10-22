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

#شامل "includes.h"
#شامل <errno.h>
#شامل <signal.h>
#شامل "sigact.h"

/* This file provides sigaction() emulation using sigvec() */
/* Use only if this is non POSIX system */

#اگر !HAVE_SIGACTION && HAVE_SIGVEC

صحیح
sigaction(صحیح sig, ساخت sigaction *sigact, ساخت sigaction *osigact)
{
	واپس sigvec(sig, sigact ? &sigact->sv : تہی,
	    osigact ? &osigact->sv : تہی);
}

صحیح
sigemptyset (sigset_t *نقاب)
{
	اگر (!نقاب) {
		errno = EINVAL;
		واپس -1;
	}
	*نقاب = 0;
	واپس 0;
}

صحیح
sigprocmask (صحیح منوال, sigset_t *نقاب, sigset_t *omask)
{
	sigset_t current = sigsetmask(0);

	اگر (!نقاب) {
		errno = EINVAL;
		واپس -1;
	}

	اگر (omask)
		*omask = current;

	اگر (منوال == SIG_BLOCK)
		current |= *نقاب;
	ورنہ اگر (منوال == SIG_UNBLOCK)
		current &= ~*نقاب;
	ورنہ اگر (منوال == SIG_SETMASK)
	current = *نقاب;

	sigsetmask(current);
	واپس 0;
}

صحیح
sigsuspend (sigset_t *نقاب)
{
	اگر (!نقاب) {
		errno = EINVAL;
		واپس -1;
	}
	واپس sigpause(*نقاب);
}

صحیح
sigdelset (sigset_t *نقاب, صحیح sig)
{
	اگر (!نقاب) {
		errno = EINVAL;
		واپس -1;
	}
	*نقاب &= ~sigmask(sig);
	واپس 0;
}

صحیح
sigaddset (sigset_t *نقاب, صحیح sig)
{
	اگر (!نقاب) {
		errno = EINVAL;
		واپس -1;
	}
	*نقاب |= sigmask(sig);
	واپس 0;
}

صحیح
sigismember (sigset_t *نقاب, صحیح sig)
{
	اگر (!نقاب) {
		errno = EINVAL;
		واپس -1;
	}
	واپس (*نقاب & sigmask(sig)) != 0;
}

#اگر_ختم
