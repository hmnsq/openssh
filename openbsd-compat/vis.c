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

#समावेश "includes.h"
#अगर !defined(HAVE_STRNVIS) || defined(BROKEN_STRNVIS)

#समावेश <sys/types.h>
#समावेश <errno.h>
#समावेश <ctype.h>
#समावेश <limits.h>
#समावेश <string.h>
#समावेश <stdlib.h>

#समावेश "vis.h"

#घोषणा	isoctal(c)	(((u_char)(c)) >= '0' && ((u_char)(c)) <= '7')
#घोषणा	isvisible(c,flag)						\
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
	अगर (isvisible(c, flag)) {
		अगर ((c == '"' && (flag & VIS_DQ) != 0) ||
		    (c == '\\' && (flag & VIS_NOSLASH) == 0))
			*dst++ = '\\';
		*dst++ = c;
		*dst = '\0';
		वापस (dst);
	}

	अगर (flag & VIS_CSTYLE) {
		चयन(c) {
		हाल '\n':
			*dst++ = '\\';
			*dst++ = 'n';
			जाओ done;
		हाल '\r':
			*dst++ = '\\';
			*dst++ = 'r';
			जाओ done;
		हाल '\b':
			*dst++ = '\\';
			*dst++ = 'b';
			जाओ done;
		हाल '\a':
			*dst++ = '\\';
			*dst++ = 'a';
			जाओ done;
		हाल '\v':
			*dst++ = '\\';
			*dst++ = 'v';
			जाओ done;
		हाल '\t':
			*dst++ = '\\';
			*dst++ = 't';
			जाओ done;
		हाल '\f':
			*dst++ = '\\';
			*dst++ = 'f';
			जाओ done;
		हाल ' ':
			*dst++ = '\\';
			*dst++ = 's';
			जाओ done;
		हाल '\0':
			*dst++ = '\\';
			*dst++ = '0';
			अगर (isoctal(nextc)) {
				*dst++ = '0';
				*dst++ = '0';
			}
			जाओ done;
		}
	}
	अगर (((c & 0177) == ' ') || (flag & VIS_OCTAL) ||
	    ((flag & VIS_GLOB) && (c == '*' || c == '?' || c == '[' || c == '#'))) {
		*dst++ = '\\';
		*dst++ = ((u_char)c >> 6 & 07) + '0';
		*dst++ = ((u_char)c >> 3 & 07) + '0';
		*dst++ = ((u_char)c & 07) + '0';
		जाओ done;
	}
	अगर ((flag & VIS_NOSLASH) == 0)
		*dst++ = '\\';
	अगर (c & 0200) {
		c &= 0177;
		*dst++ = 'M';
	}
	अगर (है_नियंत्रण((u_char)c)) {
		*dst++ = '^';
		अगर (c == 0177)
			*dst++ = '?';
		अन्यथा
			*dst++ = c + '@';
	} अन्यथा {
		*dst++ = '-';
		*dst++ = c;
	}
done:
	*dst = '\0';
	वापस (dst);
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
strvis(अक्षर *dst, स्थिर अक्षर *src, पूर्णांक flag)
{
	अक्षर c;
	अक्षर *start;

	क्रम (start = dst; (c = *src);)
		dst = vis(dst, c, flag, *++src);
	*dst = '\0';
	वापस (dst - start);
}
DEF_WEAK(strvis);

पूर्णांक
strnvis(अक्षर *dst, स्थिर अक्षर *src, माप_प्रकार siz, पूर्णांक flag)
{
	अक्षर *start, *end;
	अक्षर tbuf[5];
	पूर्णांक c, i;

	i = 0;
	क्रम (start = dst, end = start + siz - 1; (c = *src) && dst < end; ) {
		अगर (isvisible(c, flag)) {
			अगर ((c == '"' && (flag & VIS_DQ) != 0) ||
			    (c == '\\' && (flag & VIS_NOSLASH) == 0)) {
				/* need space for the extra '\\' */
				अगर (dst + 1 >= end) {
					i = 2;
					अवरोध;
				}
				*dst++ = '\\';
			}
			i = 1;
			*dst++ = c;
			src++;
		} अन्यथा {
			i = vis(tbuf, c, flag, *++src) - tbuf;
			अगर (dst + i <= end) {
				स_नकल(dst, tbuf, i);
				dst += i;
			} अन्यथा {
				src--;
				अवरोध;
			}
		}
	}
	अगर (siz > 0)
		*dst = '\0';
	अगर (dst + i > end) {
		/* adjust return value for truncation */
		जबतक ((c = *src))
			dst += vis(tbuf, c, flag, *++src) - tbuf;
	}
	वापस (dst - start);
}

#अगर 0 /* unused in OpenSSH */
पूर्णांक
stravis(अक्षर **outp, स्थिर अक्षर *src, पूर्णांक flag)
{
	अक्षर *buf;
	पूर्णांक len, serrno;

	buf = reallocarray(शून्य, 4, म_माप(src) + 1);
	अगर (buf == शून्य)
		वापस -1;
	len = strvis(buf, src, flag);
	serrno = त्रुटि_सं;
	*outp = पुनः_स्मृति(buf, len + 1);
	अगर (*outp == शून्य) {
		*outp = buf;
		त्रुटि_सं = serrno;
	}
	वापस (len);
}

पूर्णांक
strvisx(अक्षर *dst, स्थिर अक्षर *src, माप_प्रकार len, पूर्णांक flag)
{
	अक्षर c;
	अक्षर *start;

	क्रम (start = dst; len > 1; len--) {
		c = *src;
		dst = vis(dst, c, flag, *++src);
	}
	अगर (len)
		dst = vis(dst, *src, flag, '\0');
	*dst = '\0';
	वापस (dst - start);
}
#पूर्ण_अगर /* unused */

#पूर्ण_अगर
