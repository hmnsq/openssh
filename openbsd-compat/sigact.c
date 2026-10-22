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

#അന്തര്ഭാവ "includes.h"
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ "sigact.h"

/* This file provides sigaction() emulation using sigvec() */
/* Use only if this is non POSIX system */

#എങ്കിൽ !HAVE_SIGACTION && HAVE_SIGVEC

പൂർണ്ണസംഖ്യ
sigaction(പൂർണ്ണസംഖ്യ sig, ഘടന sigaction *sigact, ഘടന sigaction *osigact)
{
	തിരികെ sigvec(sig, sigact ? &sigact->sv : ശൂന്യ,
	    osigact ? &osigact->sv : ശൂന്യ);
}

പൂർണ്ണസംഖ്യ
sigemptyset (sigset_t *mask)
{
	എങ്കിൽ (!mask) {
		errno = EINVAL;
		തിരികെ -1;
	}
	*mask = 0;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sigprocmask (പൂർണ്ണസംഖ്യ mode, sigset_t *mask, sigset_t *omask)
{
	sigset_t current = sigsetmask(0);

	എങ്കിൽ (!mask) {
		errno = EINVAL;
		തിരികെ -1;
	}

	എങ്കിൽ (omask)
		*omask = current;

	എങ്കിൽ (mode == SIG_BLOCK)
		current |= *mask;
	അല്ലെങ്കിൽ എങ്കിൽ (mode == SIG_UNBLOCK)
		current &= ~*mask;
	അല്ലെങ്കിൽ എങ്കിൽ (mode == SIG_SETMASK)
	current = *mask;

	sigsetmask(current);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sigsuspend (sigset_t *mask)
{
	എങ്കിൽ (!mask) {
		errno = EINVAL;
		തിരികെ -1;
	}
	തിരികെ sigpause(*mask);
}

പൂർണ്ണസംഖ്യ
sigdelset (sigset_t *mask, പൂർണ്ണസംഖ്യ sig)
{
	എങ്കിൽ (!mask) {
		errno = EINVAL;
		തിരികെ -1;
	}
	*mask &= ~sigmask(sig);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sigaddset (sigset_t *mask, പൂർണ്ണസംഖ്യ sig)
{
	എങ്കിൽ (!mask) {
		errno = EINVAL;
		തിരികെ -1;
	}
	*mask |= sigmask(sig);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sigismember (sigset_t *mask, പൂർണ്ണസംഖ്യ sig)
{
	എങ്കിൽ (!mask) {
		errno = EINVAL;
		തിരികെ -1;
	}
	തിരികെ (*mask & sigmask(sig)) != 0;
}

#endif
