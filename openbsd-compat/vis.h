/*	$OpenBSD: vis.h,v 1.15 2015/07/20 01:52:27 millert Exp $	*/
/*	$NetBSD: vis.h,v 1.4 1994/10/26 00:56:41 cgd Exp $	*/

/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)vis.h	5.9 (Berkeley) 4/3/91
 */

/* OPENBSD ORIGINAL: include/vis.h */

#समावेश "includes.h"
#अगर !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#अगर_अघोषित _VIS_H_
#घोषणा	_VIS_H_

#समावेश <sys/types.h>
#समावेश <limits.h>

/*
 * to select alternate encoding format
 */
#घोषणा	VIS_OCTAL	0x01	/* use octal \ddd format */
#घोषणा	VIS_CSTYLE	0x02	/* use \[nrft0..] where appropriate */

/*
 * to alter set of characters encoded (default is to encode all
 * non-graphic except space, tab, and newline).
 */
#घोषणा	VIS_SP		0x04	/* also encode space */
#घोषणा	VIS_TAB		0x08	/* also encode tab */
#घोषणा	VIS_NL		0x10	/* also encode newline */
#घोषणा	VIS_WHITE	(VIS_SP | VIS_TAB | VIS_NL)
#घोषणा	VIS_SAFE	0x20	/* only encode "unsafe" characters */
#घोषणा	VIS_DQ		0x200	/* backslash-escape double quotes */
#घोषणा	VIS_ALL		0x400	/* encode all characters */

/*
 * other
 */
#घोषणा	VIS_NOSLASH	0x40	/* inhibit printing '\' */
#घोषणा	VIS_GLOB	0x100	/* encode glob(3) magics and '#' */

/*
 * unvis return codes
 */
#घोषणा	UNVIS_VALID	 1	/* character valid */
#घोषणा	UNVIS_VALIDPUSH	 2	/* character valid, push back passed char */
#घोषणा	UNVIS_NOCHAR	 3	/* valid sequence, no character produced */
#घोषणा	UNVIS_SYNBAD	-1	/* unrecognized escape sequence */
#घोषणा	UNVIS_ERROR	-2	/* decoder in unknown state (unrecoverable) */

/*
 * unvis flags
 */
#घोषणा	UNVIS_END	1	/* no more characters */

अक्षर	*vis(अक्षर *, पूर्णांक, पूर्णांक, पूर्णांक);
पूर्णांक	strvis(अक्षर *, स्थिर अक्षर *, पूर्णांक);
पूर्णांक	stravis(अक्षर **, स्थिर अक्षर *, पूर्णांक);
पूर्णांक	strnvis(अक्षर *, स्थिर अक्षर *, माप_प्रकार, पूर्णांक)
		__attribute__ ((__bounded__(__string__,1,3)));
पूर्णांक	strvisx(अक्षर *, स्थिर अक्षर *, माप_प्रकार, पूर्णांक)
		__attribute__ ((__bounded__(__string__,1,3)));
पूर्णांक	strunvis(अक्षर *, स्थिर अक्षर *);
पूर्णांक	unvis(अक्षर *, अक्षर, पूर्णांक *, पूर्णांक);
ssize_t strnunvis(अक्षर *, स्थिर अक्षर *, माप_प्रकार)
		__attribute__ ((__bounded__(__string__,1,3)));

#पूर्ण_अगर /* !_VIS_H_ */

#पूर्ण_अगर /* !HAVE_STRNVIS || BROKEN_STRNVIS */
