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

#अन्तर्भाव "includes.h"
#यदि !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#यदि_अपरिभाषितम् _VIS_H_
#परिभाषय	_VIS_H_

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <limits.h>

/*
 * to select alternate encoding format
 */
#परिभाषय	VIS_OCTAL	0x01	/* use octal \ddd format */
#परिभाषय	VIS_CSTYLE	0x02	/* use \[nrft0..] where appropriate */

/*
 * to alter set of characters encoded (default is to encode all
 * non-graphic except space, tab, and newline).
 */
#परिभाषय	VIS_SP		0x04	/* also encode space */
#परिभाषय	VIS_TAB		0x08	/* also encode tab */
#परिभाषय	VIS_NL		0x10	/* also encode newline */
#परिभाषय	VIS_WHITE	(VIS_SP | VIS_TAB | VIS_NL)
#परिभाषय	VIS_SAFE	0x20	/* only encode "unsafe" characters */
#परिभाषय	VIS_DQ		0x200	/* backslash-escape double quotes */
#परिभाषय	VIS_ALL		0x400	/* encode all characters */

/*
 * other
 */
#परिभाषय	VIS_NOSLASH	0x40	/* inhibit printing '\' */
#परिभाषय	VIS_GLOB	0x100	/* encode glob(3) magics and '#' */

/*
 * unvis return codes
 */
#परिभाषय	UNVIS_VALID	 1	/* character valid */
#परिभाषय	UNVIS_VALIDPUSH	 2	/* character valid, push back passed char */
#परिभाषय	UNVIS_NOCHAR	 3	/* valid sequence, no character produced */
#परिभाषय	UNVIS_SYNBAD	-1	/* unrecognized escape sequence */
#परिभाषय	UNVIS_ERROR	-2	/* decoder in unknown state (unrecoverable) */

/*
 * unvis flags
 */
#परिभाषय	UNVIS_अन्तः	1	/* no more characters */

वर्ण	*vis(वर्ण *, पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क);
पूर्णाङ्क	strvis(वर्ण *, ध्रुव वर्ण *, पूर्णाङ्क);
पूर्णाङ्क	stravis(वर्ण **, ध्रुव वर्ण *, पूर्णाङ्क);
पूर्णाङ्क	strnvis(वर्ण *, ध्रुव वर्ण *, आकार_t, पूर्णाङ्क)
		__attribute__ ((__bounded__(__string__,1,3)));
पूर्णाङ्क	strvisx(वर्ण *, ध्रुव वर्ण *, आकार_t, पूर्णाङ्क)
		__attribute__ ((__bounded__(__string__,1,3)));
पूर्णाङ्क	strunvis(वर्ण *, ध्रुव वर्ण *);
पूर्णाङ्क	unvis(वर्ण *, वर्ण, पूर्णाङ्क *, पूर्णाङ्क);
ssize_t strnunvis(वर्ण *, ध्रुव वर्ण *, आकार_t)
		__attribute__ ((__bounded__(__string__,1,3)));

#यदि_अन्तः /* !_VIS_H_ */

#यदि_अन्तः /* !HAVE_STRNVIS || BROKEN_STRNVIS */
