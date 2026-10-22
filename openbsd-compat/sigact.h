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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _SIGACTION_H
#ವ್ಯಾಖ್ಯಾನಿಸು _SIGACTION_H

#ಆದರೆ !defined(HAVE_SIGACTION) && defined(HAVE_SIGVEC)

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು  SIG_BLOCK
#ವ್ಯಾಖ್ಯಾನಿಸು SIG_BLOCK       00

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು  SIG_UNBLOCK
#ವ್ಯಾಖ್ಯಾನಿಸು SIG_UNBLOCK     01

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು  SIG_SETMASK
#ವ್ಯಾಖ್ಯಾನಿಸು SIG_SETMASK     02

/*
 * <bsd/signal.h> is in the Linux 1.2.8 + gcc 2.7.0 configuration,
 * and is useful for testing this header file.
 */
#ಆದರೆ HAVE_BSD_SIGNAL_H
# include <bsd/signal.h>
#ಆದರೆ_ಅಂತ್ಯ

ರಚನೆ sigaction
{
	ರಚನೆ sigvec sv;
};

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ sigset_t;

#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು  sa_mask
#ವ್ಯಾಖ್ಯಾನಿಸು sa_mask sv.sv_ಮುಖವಾಡ
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು  sa_handler
#ವ್ಯಾಖ್ಯಾನಿಸು sa_handler sv.sv_handler
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು  sa_flags
#ವ್ಯಾಖ್ಯಾನಿಸು sa_flags sv.sv_flags

ಪೂರ್ಣಾಂಕ sigaction(ಪೂರ್ಣಾಂಕ sig, ರಚನೆ sigaction *sigact, ರಚನೆ sigaction *osigact);
ಪೂರ್ಣಾಂಕ sigprocmask (ಪೂರ್ಣಾಂಕ how, sigset_t *ಮುಖವಾಡ, sigset_t *omask);
ಪೂರ್ಣಾಂಕ sigemptyset (sigset_t *ಮುಖವಾಡ);
ಪೂರ್ಣಾಂಕ sigsuspend (sigset_t *ಮುಖವಾಡ);
ಪೂರ್ಣಾಂಕ sigdelset (sigset_t *ಮುಖವಾಡ, ಪೂರ್ಣಾಂಕ sig);
ಪೂರ್ಣಾಂಕ sigaddset (sigset_t *ಮುಖವಾಡ, ಪೂರ್ಣಾಂಕ sig);

#ಆದರೆ_ಅಂತ್ಯ /* !defined(HAVE_SIGACTION) && defined(HAVE_SIGVEC) */

#ಆದರೆ_ಅಂತ್ಯ /* !defined(_SIGACTION_H) */
