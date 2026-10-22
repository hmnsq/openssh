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

#ಅನ್ತರ್ಭಾವ "includes.h"
#ಆದರೆ !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _VIS_H_
#ವ್ಯಾಖ್ಯಾನಿಸು	_VIS_H_

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

/*
 * to select alternate encoding format
 */
#ವ್ಯಾಖ್ಯಾನಿಸು	VIS_OCTAL	0x01	/* use octal \ddd format */
#ವ್ಯಾಖ್ಯಾನಿಸು	VIS_CSTYLE	0x02	/* use \[nrft0..] where appropriate */

/*
 * to alter set of characters encoded (default is to encode all
 * non-graphic except space, tab, and newline).
 */
#ವ್ಯಾಖ್ಯಾನಿಸು	VIS_SP		0x04	/* also encode space */
#ವ್ಯಾಖ್ಯಾನಿಸು	VIS_TAB		0x08	/* also encode tab */
#ವ್ಯಾಖ್ಯಾನಿಸು	VIS_NL		0x10	/* also encode newline */
#ವ್ಯಾಖ್ಯಾನಿಸು	VIS_WHITE	(VIS_SP | VIS_TAB | VIS_NL)
#ವ್ಯಾಖ್ಯಾನಿಸು	VIS_ಸುರಕ್ಷಿತ	0x20	/* only encode "unsafe" characters */
#ವ್ಯಾಖ್ಯಾನಿಸು	VIS_DQ		0x200	/* backslash-escape double quotes */
#ವ್ಯಾಖ್ಯಾನಿಸು	VIS_ALL		0x400	/* encode all characters */

/*
 * other
 */
#ವ್ಯಾಖ್ಯಾನಿಸು	VIS_NOSLASH	0x40	/* inhibit printing '\' */
#ವ್ಯಾಖ್ಯಾನಿಸು	VIS_GLOB	0x100	/* encode glob(3) magics and '#' */

/*
 * unvis return codes
 */
#ವ್ಯಾಖ್ಯಾನಿಸು	UNVIS_VALID	 1	/* character valid */
#ವ್ಯಾಖ್ಯಾನಿಸು	UNVIS_VALIDPUSH	 2	/* character valid, push back passed char */
#ವ್ಯಾಖ್ಯಾನಿಸು	UNVIS_NOCHAR	 3	/* valid sequence, no character produced */
#ವ್ಯಾಖ್ಯಾನಿಸು	UNVIS_SYNBAD	-1	/* unrecognized escape sequence */
#ವ್ಯಾಖ್ಯಾನಿಸು	UNVIS_ERROR	-2	/* decoder in unknown state (unrecoverable) */

/*
 * unvis flags
 */
#ವ್ಯಾಖ್ಯಾನಿಸು	UNVIS_ಕೊನೆ	1	/* no more characters */

ಅಕ್ಷರ	*vis(ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	strvis(ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	stravis(ಅಕ್ಷರ **, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	strnvis(ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಗಾತ್ರ_t, ಪೂರ್ಣಾಂಕ)
		__attribute__ ((__bounded__(__string__,1,3)));
ಪೂರ್ಣಾಂಕ	strvisx(ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಗಾತ್ರ_t, ಪೂರ್ಣಾಂಕ)
		__attribute__ ((__bounded__(__string__,1,3)));
ಪೂರ್ಣಾಂಕ	strunvis(ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	unvis(ಅಕ್ಷರ *, ಅಕ್ಷರ, ಪೂರ್ಣಾಂಕ *, ಪೂರ್ಣಾಂಕ);
ssize_t strnunvis(ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಗಾತ್ರ_t)
		__attribute__ ((__bounded__(__string__,1,3)));

#ಆದರೆ_ಅಂತ್ಯ /* !_VIS_H_ */

#ಆದರೆ_ಅಂತ್ಯ /* !HAVE_STRNVIS || BROKEN_STRNVIS */
