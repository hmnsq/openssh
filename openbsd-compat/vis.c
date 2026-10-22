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

#अन्तर्भाव "includes.h"
#जर !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <ctype.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdlib.h>

#अन्तर्भाव "vis.h"

#define	isoctal(c)	(((u_char)(c)) >= '0' && ((u_char)(c)) <= '7')
#define	isvisible(c,flag)						\
	(((c) == '\\' || (flag & VIS_ALL) == 0) &&			\
	(((u_int)(c) <= अच_अक्षर_उच्च && isascii((u_char)(c)) &&		\
	(((c) != '*' && (c) != '?' && (c) != '[' && (c) != '#') ||	\
		(flag & VIS_GLOB) == 0) && है_चित्र((u_char)(c))) ||	\
	((flag & VIS_SP) == 0 && (c) == ' ') ||				\
	((flag & VIS_TAB) == 0 && (c) == '\t') ||			\
	((flag & VIS_NL) == 0 && (c) == '\n') ||			\
	((flag & VIS_SAFE) && ((c) == '\b' ||				\
		(c) == '\007' || (c) == '\r' ||				\
		है_चित्र((u_char)(c))))))

/*
 * vis - visually encode characters
 */
अक्षर *
vis(अक्षर *dst, पूर्णांक c, पूर्णांक flag, पूर्णांक nextc)
{
	जर (isvisible(c, flag)) {
		जर ((c == '"' && (flag & VIS_DQ) != 0) ||
		    (c == '\\' && (flag & VIS_NOSLASH) == 0))
			*dst++ = '\\';
		*dst++ = c;
		*dst = '\0';
		परत (dst);
	}

	जर (flag & VIS_CSTYLE) {
		निवड(c) {
		स्थिती '\n':
			*dst++ = '\\';
			*dst++ = 'n';
			जा done;
		स्थिती '\r':
			*dst++ = '\\';
			*dst++ = 'r';
			जा done;
		स्थिती '\b':
			*dst++ = '\\';
			*dst++ = 'b';
			जा done;
		स्थिती '\a':
			*dst++ = '\\';
			*dst++ = 'a';
			जा done;
		स्थिती '\v':
			*dst++ = '\\';
			*dst++ = 'v';
			जा done;
		स्थिती '\t':
			*dst++ = '\\';
			*dst++ = 't';
			जा done;
		स्थिती '\f':
			*dst++ = '\\';
			*dst++ = 'f';
			जा done;
		स्थिती ' ':
			*dst++ = '\\';
			*dst++ = 's';
			जा done;
		स्थिती '\0':
			*dst++ = '\\';
			*dst++ = '0';
			जर (isoctal(nextc)) {
				*dst++ = '0';
				*dst++ = '0';
			}
			जा done;
		}
	}
	जर (((c & 0177) == ' ') || (flag & VIS_OCTAL) ||
	    ((flag & VIS_GLOB) && (c == '*' || c == '?' || c == '[' || c == '#'))) {
		*dst++ = '\\';
		*dst++ = ((u_char)c >> 6 & 07) + '0';
		*dst++ = ((u_char)c >> 3 & 07) + '0';
		*dst++ = ((u_char)c & 07) + '0';
		जा done;
	}
	जर ((flag & VIS_NOSLASH) == 0)
		*dst++ = '\\';
	जर (c & 0200) {
		c &= 0177;
		*dst++ = 'M';
	}
	जर (है_नियंत्रण((u_char)c)) {
		*dst++ = '^';
		जर (c == 0177)
			*dst++ = '?';
		अन्यथा
			*dst++ = c + '@';
	} अन्यथा {
		*dst++ = '-';
		*dst++ = c;
	}
done:
	*dst = '\0';
	परत (dst);
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
पूर्णांक
strvis(अक्षर *dst, स्थिरांक अक्षर *src, पूर्णांक flag)
{
	अक्षर c;
	अक्षर *start;

	साठी (start = dst; (c = *src);)
		dst = vis(dst, c, flag, *++src);
	*dst = '\0';
	परत (dst - start);
}
DEF_WEAK(strvis);

पूर्णांक
strnvis(अक्षर *dst, स्थिरांक अक्षर *src, माप_प्रकार siz, पूर्णांक flag)
{
	अक्षर *start, *end;
	अक्षर tbuf[5];
	पूर्णांक c, i;

	i = 0;
	साठी (start = dst, end = start + siz - 1; (c = *src) && dst < end; ) {
		जर (isvisible(c, flag)) {
			जर ((c == '"' && (flag & VIS_DQ) != 0) ||
			    (c == '\\' && (flag & VIS_NOSLASH) == 0)) {
				/* need space for the extra '\\' */
				जर (dst + 1 >= end) {
					i = 2;
					थांबा;
				}
				*dst++ = '\\';
			}
			i = 1;
			*dst++ = c;
			src++;
		} अन्यथा {
			i = vis(tbuf, c, flag, *++src) - tbuf;
			जर (dst + i <= end) {
				स_नकल(dst, tbuf, i);
				dst += i;
			} अन्यथा {
				src--;
				थांबा;
			}
		}
	}
	जर (siz > 0)
		*dst = '\0';
	जर (dst + i > end) {
		/* adjust return value for truncation */
		पर्यंत ((c = *src))
			dst += vis(tbuf, c, flag, *++src) - tbuf;
	}
	परत (dst - start);
}

#जर 0 /* unused in OpenSSH */
पूर्णांक
stravis(अक्षर **outp, स्थिरांक अक्षर *src, पूर्णांक flag)
{
	अक्षर *buf;
	पूर्णांक len, serrno;

	buf = reallocarray(रिक्त, 4, म_माप(src) + 1);
	जर (buf == रिक्त)
		परत -1;
	len = strvis(buf, src, flag);
	serrno = त्रुटि_सं;
	*outp = पुनः_स्मृति(buf, len + 1);
	जर (*outp == रिक्त) {
		*outp = buf;
		त्रुटि_सं = serrno;
	}
	परत (len);
}

पूर्णांक
strvisx(अक्षर *dst, स्थिरांक अक्षर *src, माप_प्रकार len, पूर्णांक flag)
{
	अक्षर c;
	अक्षर *start;

	साठी (start = dst; len > 1; len--) {
		c = *src;
		dst = vis(dst, c, flag, *++src);
	}
	जर (len)
		dst = vis(dst, *src, flag, '\0');
	*dst = '\0';
	परत (dst - start);
}
#endif /* unused */

#endif
