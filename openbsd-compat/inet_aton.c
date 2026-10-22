/*	$OpenBSD: inet_addr.c,v 1.9 2005/08/06 20:30:03 espie Exp $	*/

/*
 * Copyright (c) 1983, 1990, 1993
 *    The Regents of the University of California.  All rights reserved.
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
 * -
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * -
 * --Copyright--
 */

/* OPENBSD ORIGINAL: lib/libc/net/inet_addr.c */

#समावेश "includes.h"

#अगर !defined(HAVE_INET_ATON)

#समावेश <sys/types.h>
#समावेश <netinet/in.h>
#समावेश <arpa/inet.h>
#समावेश <ctype.h>

#अगर 0
/*
 * Ascii internet address interpretation routine.
 * The value returned is in network order.
 */
in_addr_t
inet_addr(स्थिर अक्षर *cp)
{
	काष्ठा in_addr val;

	अगर (inet_aton(cp, &val))
		वापस (val.s_addr);
	वापस (INADDR_NONE);
}
#पूर्ण_अगर

/*
 * Check whether "cp" is a valid ascii representation
 * of an Internet address and convert to a binary address.
 * Returns 1 if the address is valid, 0 if not.
 * This replaces inet_addr, the return value from which
 * cannot distinguish between failure and a local broadcast address.
 */
पूर्णांक
inet_aton(स्थिर अक्षर *cp, काष्ठा in_addr *addr)
{
	u_int32_t val;
	पूर्णांक base, n;
	अक्षर c;
	u_int parts[4];
	u_int *pp = parts;

	c = *cp;
	क्रम (;;) {
		/*
		 * Collect number up to ``.''.
		 * Values are specified as for C:
		 * 0x=hex, 0=octal, isdigit=decimal.
		 */
		अगर (!है_अंक(c))
			वापस (0);
		val = 0; base = 10;
		अगर (c == '0') {
			c = *++cp;
			अगर (c == 'x' || c == 'X')
				base = 16, c = *++cp;
			अन्यथा
				base = 8;
		}
		क्रम (;;) {
			अगर (isascii(c) && है_अंक(c)) {
				val = (val * base) + (c - '0');
				c = *++cp;
			} अन्यथा अगर (base == 16 && isascii(c) && है_षष्ठादशक(c)) {
				val = (val << 4) |
					(c + 10 - (है_छोटा(c) ? 'a' : 'A'));
				c = *++cp;
			} अन्यथा
				अवरोध;
		}
		अगर (c == '.') {
			/*
			 * Internet format:
			 *	a.b.c.d
			 *	a.b.c	(with c treated as 16 bits)
			 *	a.b	(with b treated as 24 bits)
			 */
			अगर (pp >= parts + 3)
				वापस (0);
			*pp++ = val;
			c = *++cp;
		} अन्यथा
			अवरोध;
	}
	/*
	 * Check for trailing characters.
	 */
	अगर (c != '\0' && (!isascii(c) || !है_खाली(c)))
		वापस (0);
	/*
	 * Concoct the address according to
	 * the number of parts specified.
	 */
	n = pp - parts + 1;
	चयन (n) {

	हाल 0:
		वापस (0);		/* initial nondigit */

	हाल 1:				/* a -- 32 bits */
		अवरोध;

	हाल 2:				/* a.b -- 8.24 bits */
		अगर ((val > 0xffffff) || (parts[0] > 0xff))
			वापस (0);
		val |= parts[0] << 24;
		अवरोध;

	हाल 3:				/* a.b.c -- 8.8.16 bits */
		अगर ((val > 0xffff) || (parts[0] > 0xff) || (parts[1] > 0xff))
			वापस (0);
		val |= (parts[0] << 24) | (parts[1] << 16);
		अवरोध;

	हाल 4:				/* a.b.c.d -- 8.8.8.8 bits */
		अगर ((val > 0xff) || (parts[0] > 0xff) || (parts[1] > 0xff) || (parts[2] > 0xff))
			वापस (0);
		val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
		अवरोध;
	}
	अगर (addr)
		addr->s_addr = htonl(val);
	वापस (1);
}

#पूर्ण_अगर /* !defined(HAVE_INET_ATON) */
