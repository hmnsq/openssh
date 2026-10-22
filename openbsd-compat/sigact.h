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

#अगर_अघोषित _SIGACTION_H
#घोषणा _SIGACTION_H

#अगर !defined(HAVE_SIGACTION) && defined(HAVE_SIGVEC)

#अघोषित  SIG_BLOCK
#घोषणा SIG_BLOCK       00

#अघोषित  SIG_UNBLOCK
#घोषणा SIG_UNBLOCK     01

#अघोषित  SIG_SETMASK
#घोषणा SIG_SETMASK     02

/*
 * <bsd/signal.h> is in the Linux 1.2.8 + gcc 2.7.0 configuration,
 * and is useful for testing this header file.
 */
#अगर HAVE_BSD_SIGNAL_H
# include <bsd/signal.h>
#पूर्ण_अगर

काष्ठा sigaction
{
	काष्ठा sigvec sv;
};

प्रकार अचिन्हित दीर्घ sigset_t;

#अघोषित  sa_mask
#घोषणा sa_mask sv.sv_mask
#अघोषित  sa_handler
#घोषणा sa_handler sv.sv_handler
#अघोषित  sa_flags
#घोषणा sa_flags sv.sv_flags

पूर्णांक sigaction(पूर्णांक sig, काष्ठा sigaction *sigact, काष्ठा sigaction *osigact);
पूर्णांक sigprocmask (पूर्णांक how, sigset_t *mask, sigset_t *omask);
पूर्णांक sigemptyset (sigset_t *mask);
पूर्णांक संक_रोको (sigset_t *mask);
पूर्णांक sigdelset (sigset_t *mask, पूर्णांक sig);
पूर्णांक sigaddset (sigset_t *mask, पूर्णांक sig);

#पूर्ण_अगर /* !defined(HAVE_SIGACTION) && defined(HAVE_SIGVEC) */

#पूर्ण_अगर /* !defined(_SIGACTION_H) */
