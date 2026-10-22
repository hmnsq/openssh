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

#ضمن "includes.h"
#إذا !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#اگر_تعریف_نشده _VIS_H_
#تعریف_کن	_VIS_H_

#ضمن <sys/types.h>
#ضمن <limits.h>

/*
 * to select alternate encoding format
 */
#تعریف_کن	VIS_OCTAL	0x01	/* use octal \ddd format */
#تعریف_کن	VIS_CSTYLE	0x02	/* use \[nrft0..] where appropriate */

/*
 * to alter set of characters encoded (default is to encode all
 * non-graphic except space, tab, and newline).
 */
#تعریف_کن	VIS_SP		0x04	/* also encode space */
#تعریف_کن	VIS_TAB		0x08	/* also encode tab */
#تعریف_کن	VIS_NL		0x10	/* also encode newline */
#تعریف_کن	VIS_WHITE	(VIS_SP | VIS_TAB | VIS_NL)
#تعریف_کن	VIS_امن	0x20	/* only encode "unsafe" characters */
#تعریف_کن	VIS_DQ		0x200	/* backslash-escape double quotes */
#تعریف_کن	VIS_ALL		0x400	/* encode all characters */

/*
 * other
 */
#تعریف_کن	VIS_NOSLASH	0x40	/* inhibit printing '\' */
#تعریف_کن	VIS_GLOB	0x100	/* encode glob(3) magics and '#' */

/*
 * unvis return codes
 */
#تعریف_کن	UNVIS_VALID	 1	/* character valid */
#تعریف_کن	UNVIS_VALIDPUSH	 2	/* character valid, push back passed char */
#تعریف_کن	UNVIS_NOCHAR	 3	/* valid sequence, no character produced */
#تعریف_کن	UNVIS_SYNBAD	-1	/* unrecognized escape sequence */
#تعریف_کن	UNVIS_ERROR	-2	/* decoder in unknown state (unrecoverable) */

/*
 * unvis flags
 */
#تعریف_کن	UNVIS_انتها	1	/* no more characters */

حرف	*vis(حرف *, صحيح, صحيح, صحيح);
صحيح	strvis(حرف *, ثابت حرف *, صحيح);
صحيح	stravis(حرف **, ثابت حرف *, صحيح);
صحيح	strnvis(حرف *, ثابت حرف *, اندازه_t, صحيح)
		__attribute__ ((__bounded__(__string__,1,3)));
صحيح	strvisx(حرف *, ثابت حرف *, اندازه_t, صحيح)
		__attribute__ ((__bounded__(__string__,1,3)));
صحيح	strunvis(حرف *, ثابت حرف *);
صحيح	unvis(حرف *, حرف, صحيح *, صحيح);
ssize_t strnunvis(حرف *, ثابت حرف *, اندازه_t)
		__attribute__ ((__bounded__(__string__,1,3)));

#پایان_اگر /* !_VIS_H_ */

#پایان_اگر /* !HAVE_STRNVIS || BROKEN_STRNVIS */
