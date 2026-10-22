/*	$OpenBSD: vis.c,v 1.25 2015/09/13 11:32:51 guenther Exp $ */
/*-
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 */

/* OPENBSD ORIGINAL: lib/libc/gen/vis.c */

#అన్తర్భావ "includes.h"
#ఒకవేళ !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <ctype.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdlib.h>

#అన్తర్భావ "vis.h"

#నిర్వచించు	isoctal(c)	(((u_char)(c)) >= '0' && ((u_char)(c)) <= '7')
#నిర్వచించు	isvisible(c,flag)						\
	(((c) == '\\' || (flag & VIS_ALL) == 0) &&			\
	(((u_int)(c) <= UCHAR_MAX && isascii((u_char)(c)) &&		\
	(((c) != '*' && (c) != '?' && (c) != '[' && (c) != '#') ||	\
		(flag & VIS_GLOB) == 0) && isgraph((u_char)(c))) ||	\
	((flag & VIS_SP) == 0 && (c) == ' ') ||				\
	((flag & VIS_TAB) == 0 && (c) == '\t') ||			\
	((flag & VIS_NL) == 0 && (c) == '\n') ||			\
	((flag & VIS_సురక్షిత) && ((c) == '\b' ||				\
		(c) == '\007' || (c) == '\r' ||				\
		isgraph((u_char)(c))))))

/*
 * vis - visually encode characters
 */
అక్షరం *
vis(అక్షరం *dst, పూర్ణాంకం c, పూర్ణాంకం flag, పూర్ణాంకం nextc)
{
	ఒకవేళ (isvisible(c, flag)) {
		ఒకవేళ ((c == '"' && (flag & VIS_DQ) != 0) ||
		    (c == '\\' && (flag & VIS_NOSLASH) == 0))
			*dst++ = '\\';
		*dst++ = c;
		*dst = '\0';
		తిరిగి (dst);
	}

	ఒకవేళ (flag & VIS_CSTYLE) {
		ఎంపిక(c) {
		స్థితి '\n':
			*dst++ = '\\';
			*dst++ = 'n';
			వెళ్ళు పూర్తి;
		స్థితి '\r':
			*dst++ = '\\';
			*dst++ = 'r';
			వెళ్ళు పూర్తి;
		స్థితి '\b':
			*dst++ = '\\';
			*dst++ = 'b';
			వెళ్ళు పూర్తి;
		స్థితి '\a':
			*dst++ = '\\';
			*dst++ = 'a';
			వెళ్ళు పూర్తి;
		స్థితి '\v':
			*dst++ = '\\';
			*dst++ = 'v';
			వెళ్ళు పూర్తి;
		స్థితి '\t':
			*dst++ = '\\';
			*dst++ = 't';
			వెళ్ళు పూర్తి;
		స్థితి '\f':
			*dst++ = '\\';
			*dst++ = 'f';
			వెళ్ళు పూర్తి;
		స్థితి ' ':
			*dst++ = '\\';
			*dst++ = 's';
			వెళ్ళు పూర్తి;
		స్థితి '\0':
			*dst++ = '\\';
			*dst++ = '0';
			ఒకవేళ (isoctal(nextc)) {
				*dst++ = '0';
				*dst++ = '0';
			}
			వెళ్ళు పూర్తి;
		}
	}
	ఒకవేళ (((c & 0177) == ' ') || (flag & VIS_OCTAL) ||
	    ((flag & VIS_GLOB) && (c == '*' || c == '?' || c == '[' || c == '#'))) {
		*dst++ = '\\';
		*dst++ = ((u_char)c >> 6 & 07) + '0';
		*dst++ = ((u_char)c >> 3 & 07) + '0';
		*dst++ = ((u_char)c & 07) + '0';
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ ((flag & VIS_NOSLASH) == 0)
		*dst++ = '\\';
	ఒకవేళ (c & 0200) {
		c &= 0177;
		*dst++ = 'M';
	}
	ఒకవేళ (iscntrl((u_char)c)) {
		*dst++ = '^';
		ఒకవేళ (c == 0177)
			*dst++ = '?';
		లేకపోతే
			*dst++ = c + '@';
	} లేకపోతే {
		*dst++ = '-';
		*dst++ = c;
	}
పూర్తి:
	*dst = '\0';
	తిరిగి (dst);
}
DEF_WEAK(vis);

/*
 * strvis, strnvis, strvisx - visually encode characters from src into dst
 *	
 *	Dst must be 4 times the size of src to account for possible
 *	expansion.  The length of dst, not including the trailing NULL,
 *	is returned. 
 *
 *	Strnvis will write no more than siz-1 bytes (and will NULL terminate).
 *	The number of bytes needed to fully encode the string is returned.
 *
 *	Strvisx encodes exactly len bytes from src into dst.
 *	This is useful for encoding a block of data.
 */
పూర్ణాంకం
strvis(అక్షరం *dst, స్థిరరాశి అక్షరం *src, పూర్ణాంకం flag)
{
	అక్షరం c;
	అక్షరం *ప్రారంభం;

	కొరకు (ప్రారంభం = dst; (c = *src);)
		dst = vis(dst, c, flag, *++src);
	*dst = '\0';
	తిరిగి (dst - ప్రారంభం);
}
DEF_WEAK(strvis);

పూర్ణాంకం
strnvis(అక్షరం *dst, స్థిరరాశి అక్షరం *src, కొలత_t siz, పూర్ణాంకం flag)
{
	అక్షరం *ప్రారంభం, *చివర;
	అక్షరం tbuf[5];
	పూర్ణాంకం c, i;

	i = 0;
	కొరకు (ప్రారంభం = dst, చివర = ప్రారంభం + siz - 1; (c = *src) && dst < చివర; ) {
		ఒకవేళ (isvisible(c, flag)) {
			ఒకవేళ ((c == '"' && (flag & VIS_DQ) != 0) ||
			    (c == '\\' && (flag & VIS_NOSLASH) == 0)) {
				/* need space for the extra '\\' */
				ఒకవేళ (dst + 1 >= చివర) {
					i = 2;
					ఆపు;
				}
				*dst++ = '\\';
			}
			i = 1;
			*dst++ = c;
			src++;
		} లేకపోతే {
			i = vis(tbuf, c, flag, *++src) - tbuf;
			ఒకవేళ (dst + i <= చివర) {
				జ్ఞాపకం_నకలు(dst, tbuf, i);
				dst += i;
			} లేకపోతే {
				src--;
				ఆపు;
			}
		}
	}
	ఒకవేళ (siz > 0)
		*dst = '\0';
	ఒకవేళ (dst + i > చివర) {
		/* adjust return value for truncation */
		అయితే ((c = *src))
			dst += vis(tbuf, c, flag, *++src) - tbuf;
	}
	తిరిగి (dst - ప్రారంభం);
}

#ఒకవేళ 0 /* unused in OpenSSH */
పూర్ణాంకం
stravis(అక్షరం **outp, స్థిరరాశి అక్షరం *src, పూర్ణాంకం flag)
{
	అక్షరం *buf;
	పూర్ణాంకం len, serrno;

	buf = reallocarray(ఖాళీ, 4, అక్షరశ్రేణి_పొడవు(src) + 1);
	ఒకవేళ (buf == ఖాళీ)
		తిరిగి -1;
	len = strvis(buf, src, flag);
	serrno = errno;
	*outp = realloc(buf, len + 1);
	ఒకవేళ (*outp == ఖాళీ) {
		*outp = buf;
		errno = serrno;
	}
	తిరిగి (len);
}

పూర్ణాంకం
strvisx(అక్షరం *dst, స్థిరరాశి అక్షరం *src, కొలత_t len, పూర్ణాంకం flag)
{
	అక్షరం c;
	అక్షరం *ప్రారంభం;

	కొరకు (ప్రారంభం = dst; len > 1; len--) {
		c = *src;
		dst = vis(dst, c, flag, *++src);
	}
	ఒకవేళ (len)
		dst = vis(dst, *src, flag, '\0');
	*dst = '\0';
	తిరిగి (dst - ప్రారంభం);
}
#అయితే_ముగింపు /*వాడని*/

#అయితే_ముగింపు
