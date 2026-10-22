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

#అన్తర్భావ "includes.h"
#ఒకవేళ !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#నిర్వచితం_కాకపోతే _VIS_H_
#నిర్వచించు	_VIS_H_

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <limits.h>

/*
 * to select alternate encoding format
 */
#నిర్వచించు	VIS_OCTAL	0x01	/* use octal \ddd format */
#నిర్వచించు	VIS_CSTYLE	0x02	/* use \[nrft0..] where appropriate */

/*
 * to alter set of characters encoded (default is to encode all
 * non-graphic except space, tab, and newline).
 */
#నిర్వచించు	VIS_SP		0x04	/* also encode space */
#నిర్వచించు	VIS_TAB		0x08	/* also encode tab */
#నిర్వచించు	VIS_NL		0x10	/* also encode newline */
#నిర్వచించు	VIS_WHITE	(VIS_SP | VIS_TAB | VIS_NL)
#నిర్వచించు	VIS_సురక్షిత	0x20	/* only encode "unsafe" characters */
#నిర్వచించు	VIS_DQ		0x200	/* backslash-escape double quotes */
#నిర్వచించు	VIS_ALL		0x400	/* encode all characters */

/*
 * other
 */
#నిర్వచించు	VIS_NOSLASH	0x40	/* inhibit printing '\' */
#నిర్వచించు	VIS_GLOB	0x100	/* encode glob(3) magics and '#' */

/*
 * unvis return codes
 */
#నిర్వచించు	UNVIS_VALID	 1	/* character valid */
#నిర్వచించు	UNVIS_VALIDPUSH	 2	/* character valid, push back passed char */
#నిర్వచించు	UNVIS_NOCHAR	 3	/* valid sequence, no character produced */
#నిర్వచించు	UNVIS_SYNBAD	-1	/* unrecognized escape sequence */
#నిర్వచించు	UNVIS_ERROR	-2	/* decoder in unknown state (unrecoverable) */

/*
 * unvis flags
 */
#నిర్వచించు	UNVIS_చివర	1	/* no more characters */

అక్షరం	*vis(అక్షరం *, పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం);
పూర్ణాంకం	strvis(అక్షరం *, స్థిరరాశి అక్షరం *, పూర్ణాంకం);
పూర్ణాంకం	stravis(అక్షరం **, స్థిరరాశి అక్షరం *, పూర్ణాంకం);
పూర్ణాంకం	strnvis(అక్షరం *, స్థిరరాశి అక్షరం *, కొలత_t, పూర్ణాంకం)
		__attribute__ ((__bounded__(__string__,1,3)));
పూర్ణాంకం	strvisx(అక్షరం *, స్థిరరాశి అక్షరం *, కొలత_t, పూర్ణాంకం)
		__attribute__ ((__bounded__(__string__,1,3)));
పూర్ణాంకం	strunvis(అక్షరం *, స్థిరరాశి అక్షరం *);
పూర్ణాంకం	unvis(అక్షరం *, అక్షరం, పూర్ణాంకం *, పూర్ణాంకం);
ssize_t strnunvis(అక్షరం *, స్థిరరాశి అక్షరం *, కొలత_t)
		__attribute__ ((__bounded__(__string__,1,3)));

#అయితే_ముగింపు /* !_VIS_H_ */

#అయితే_ముగింపు /* !HAVE_STRNVIS || BROKEN_STRNVIS */
