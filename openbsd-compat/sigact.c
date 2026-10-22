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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ "sigact.h"

/* This file provides sigaction() emulation using sigvec() */
/* Use only if this is non POSIX system */

#ਜੇ !HAVE_SIGACTION && HAVE_SIGVEC

ਪੂਰਨ
sigaction(ਪੂਰਨ sig, ਬਣਤਰ sigaction *sigact, ਬਣਤਰ sigaction *osigact)
{
	ਵਾਪਸ sigvec(sig, sigact ? &sigact->sv : ਨਿਰਾ,
	    osigact ? &osigact->sv : ਨਿਰਾ);
}

ਪੂਰਨ
sigemptyset (sigset_t *ਨਕਾਬ)
{
	ਜੇ (!ਨਕਾਬ) {
		errno = EINVAL;
		ਵਾਪਸ -1;
	}
	*ਨਕਾਬ = 0;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sigprocmask (ਪੂਰਨ ਬਹੁਲਕ, sigset_t *ਨਕਾਬ, sigset_t *omask)
{
	sigset_t current = sigsetmask(0);

	ਜੇ (!ਨਕਾਬ) {
		errno = EINVAL;
		ਵਾਪਸ -1;
	}

	ਜੇ (omask)
		*omask = current;

	ਜੇ (ਬਹੁਲਕ == SIG_BLOCK)
		current |= *ਨਕਾਬ;
	ਨਹੀਂਤਾਂ ਜੇ (ਬਹੁਲਕ == SIG_UNBLOCK)
		current &= ~*ਨਕਾਬ;
	ਨਹੀਂਤਾਂ ਜੇ (ਬਹੁਲਕ == SIG_SETMASK)
	current = *ਨਕਾਬ;

	sigsetmask(current);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sigsuspend (sigset_t *ਨਕਾਬ)
{
	ਜੇ (!ਨਕਾਬ) {
		errno = EINVAL;
		ਵਾਪਸ -1;
	}
	ਵਾਪਸ sigpause(*ਨਕਾਬ);
}

ਪੂਰਨ
sigdelset (sigset_t *ਨਕਾਬ, ਪੂਰਨ sig)
{
	ਜੇ (!ਨਕਾਬ) {
		errno = EINVAL;
		ਵਾਪਸ -1;
	}
	*ਨਕਾਬ &= ~sigmask(sig);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sigaddset (sigset_t *ਨਕਾਬ, ਪੂਰਨ sig)
{
	ਜੇ (!ਨਕਾਬ) {
		errno = EINVAL;
		ਵਾਪਸ -1;
	}
	*ਨਕਾਬ |= sigmask(sig);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sigismember (sigset_t *ਨਕਾਬ, ਪੂਰਨ sig)
{
	ਜੇ (!ਨਕਾਬ) {
		errno = EINVAL;
		ਵਾਪਸ -1;
	}
	ਵਾਪਸ (*ਨਕਾਬ & sigmask(sig)) != 0;
}

#ਜੇ_ਅੰਤ
