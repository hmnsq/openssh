/*	$OpenBSD: SigAction.h,v 1.3 2001/01/22 18:01:32 millert Exp $	*/

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

/*
 * $From: SigAction.h,v 1.6 2000/12/10 02:36:10 tom Exp $
 *
 * This file exists to handle non-POSIX systems which don't have <unistd.h>,
 * and usually no sigaction() nor <termios.h>
 */

/* OPENBSD ORIGINAL: lib/libcurses/SigAction.h */

#यदि_अपरिभाषितम् _SIGACTION_H
#परिभाषय _SIGACTION_H

#यदि !defined(HAVE_SIGACTION) && defined(HAVE_SIGVEC)

#अपरिभाषय  SIG_BLOCK
#परिभाषय SIG_BLOCK       00

#अपरिभाषय  SIG_UNBLOCK
#परिभाषय SIG_UNBLOCK     01

#अपरिभाषय  SIG_SETMASK
#परिभाषय SIG_SETMASK     02

/*
 * <bsd/signal.h> is in the Linux 1.2.8 + gcc 2.7.0 configuration,
 * and is useful for testing this header file.
 */
#यदि HAVE_BSD_SIGNAL_H
# include <bsd/signal.h>
#यदि_अन्तः

संरचना sigaction
{
	संरचना sigvec sv;
};

प्रकारनिर्देश अचिह्नित दीर्घ sigset_t;

#अपरिभाषय  sa_mask
#परिभाषय sa_mask sv.sv_आवरणम्
#अपरिभाषय  sa_handler
#परिभाषय sa_handler sv.sv_handler
#अपरिभाषय  sa_flags
#परिभाषय sa_flags sv.sv_flags

पूर्णाङ्क sigaction(पूर्णाङ्क sig, संरचना sigaction *sigact, संरचना sigaction *osigact);
पूर्णाङ्क sigprocmask (पूर्णाङ्क how, sigset_t *आवरणम्, sigset_t *omask);
पूर्णाङ्क sigemptyset (sigset_t *आवरणम्);
पूर्णाङ्क sigsuspend (sigset_t *आवरणम्);
पूर्णाङ्क sigdelset (sigset_t *आवरणम्, पूर्णाङ्क sig);
पूर्णाङ्क sigaddset (sigset_t *आवरणम्, पूर्णाङ्क sig);

#यदि_अन्तः /* !defined(HAVE_SIGACTION) && defined(HAVE_SIGVEC) */

#यदि_अन्तः /* !defined(_SIGACTION_H) */
