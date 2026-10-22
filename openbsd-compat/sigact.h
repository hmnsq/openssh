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

#నిర్వచితం_కాకపోతే _SIGACTION_H
#నిర్వచించు _SIGACTION_H

#ఒకవేళ !defined(HAVE_SIGACTION) && defined(HAVE_SIGVEC)

#నిర్వచనం_రద్దు  SIG_BLOCK
#నిర్వచించు SIG_BLOCK       00

#నిర్వచనం_రద్దు  SIG_UNBLOCK
#నిర్వచించు SIG_UNBLOCK     01

#నిర్వచనం_రద్దు  SIG_SETMASK
#నిర్వచించు SIG_SETMASK     02

/*
 * <bsd/signal.h> is in the Linux 1.2.8 + gcc 2.7.0 configuration,
 * and is useful for testing this header file.
 */
#ఒకవేళ HAVE_BSD_SIGNAL_H
# include <bsd/signal.h>
#అయితే_ముగింపు

నిర్మాణం sigaction
{
	నిర్మాణం sigvec sv;
};

రకనిర్వచనం గుర్తులేని దీర్ఘ sigset_t;

#నిర్వచనం_రద్దు  sa_mask
#నిర్వచించు sa_mask sv.sv_ముసుగు
#నిర్వచనం_రద్దు  sa_handler
#నిర్వచించు sa_handler sv.sv_handler
#నిర్వచనం_రద్దు  sa_flags
#నిర్వచించు sa_flags sv.sv_flags

పూర్ణాంకం sigaction(పూర్ణాంకం sig, నిర్మాణం sigaction *sigact, నిర్మాణం sigaction *osigact);
పూర్ణాంకం sigprocmask (పూర్ణాంకం how, sigset_t *ముసుగు, sigset_t *omask);
పూర్ణాంకం sigemptyset (sigset_t *ముసుగు);
పూర్ణాంకం sigsuspend (sigset_t *ముసుగు);
పూర్ణాంకం sigdelset (sigset_t *ముసుగు, పూర్ణాంకం sig);
పూర్ణాంకం sigaddset (sigset_t *ముసుగు, పూర్ణాంకం sig);

#అయితే_ముగింపు /* !defined(HAVE_SIGACTION) && defined(HAVE_SIGVEC) */

#అయితే_ముగింపు /* !defined(_SIGACTION_H) */
