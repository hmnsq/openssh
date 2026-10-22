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

#جيڪڏهن_وصف_نه_ٿيل _SIGACTION_H
#وصف_ڪريو _SIGACTION_H

#إذا !defined(HAVE_SIGACTION) && defined(HAVE_SIGVEC)

#وصف_رد  SIG_BLOCK
#وصف_ڪريو SIG_BLOCK       00

#وصف_رد  SIG_UNBLOCK
#وصف_ڪريو SIG_UNBLOCK     01

#وصف_رد  SIG_SETMASK
#وصف_ڪريو SIG_SETMASK     02

/*
 * <bsd/signal.h> is in the Linux 1.2.8 + gcc 2.7.0 configuration,
 * and is useful for testing this header file.
 */
#إذا HAVE_BSD_SIGNAL_H
# include <bsd/signal.h>
#جيڪڏهن_پورو

بنية sigaction
{
	بنية sigvec sv;
};

تعريفنوع بنانشان ڊگهو sigset_t;

#وصف_رد  sa_mask
#وصف_ڪريو sa_mask sv.sv_نقاب
#وصف_رد  sa_handler
#وصف_ڪريو sa_handler sv.sv_handler
#وصف_رد  sa_flags
#وصف_ڪريو sa_flags sv.sv_flags

صحيح sigaction(صحيح sig, بنية sigaction *sigact, بنية sigaction *osigact);
صحيح sigprocmask (صحيح how, sigset_t *نقاب, sigset_t *omask);
صحيح sigemptyset (sigset_t *نقاب);
صحيح sigsuspend (sigset_t *نقاب);
صحيح sigdelset (sigset_t *نقاب, صحيح sig);
صحيح sigaddset (sigset_t *نقاب, صحيح sig);

#جيڪڏهن_پورو /* !defined(HAVE_SIGACTION) && defined(HAVE_SIGVEC) */

#جيڪڏهن_پورو /* !defined(_SIGACTION_H) */
