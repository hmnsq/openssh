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

#অন্তর্ভাব "includes.h"

#যদি !defined(HAVE_INET_ATON)

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <netinet/in.h>
#অন্তর্ভাব <arpa/inet.h>
#অন্তর্ভাব <ctype.h>

#যদি 0
/*
 * Ascii internet address interpretation routine.
 * The value returned is in network order.
 */
in_addr_t
inet_addr(ধ্রুব বর্ণ *cp)
{
	সংরচনা in_addr val;

	যদি (inet_aton(cp, &val))
		প্রত্যাগম (val.s_addr);
	প্রত্যাগম (INADDR_NONE);
}
#endif

/*
 * Check whether "cp" is a valid ascii representation
 * of an Internet address and convert to a binary address.
 * Returns 1 if the address is valid, 0 if not.
 * This replaces inet_addr, the return value from which
 * cannot distinguish between failure and a local broadcast address.
 */
পূর্ণাঙ্ক
inet_aton(ধ্রুব বর্ণ *cp, সংরচনা in_addr *addr)
{
	u_int32_t val;
	পূর্ণাঙ্ক base, n;
	বর্ণ c;
	u_int parts[4];
	u_int *pp = parts;

	c = *cp;
	প্রতি (;;) {
		/*
		 * Collect number up to ``.''.
		 * Values are specified as for C:
		 * 0x=hex, 0=octal, isdigit=decimal.
		 */
		যদি (!isdigit(c))
			প্রত্যাগম (0);
		val = 0; base = 10;
		যদি (c == '0') {
			c = *++cp;
			যদি (c == 'x' || c == 'X')
				base = 16, c = *++cp;
			অন্যথা
				base = 8;
		}
		প্রতি (;;) {
			যদি (isascii(c) && isdigit(c)) {
				val = (val * base) + (c - '0');
				c = *++cp;
			} অন্যথা যদি (base == 16 && isascii(c) && isxdigit(c)) {
				val = (val << 4) |
					(c + 10 - (islower(c) ? 'a' : 'A'));
				c = *++cp;
			} অন্যথা
				ভঙ্গ;
		}
		যদি (c == '.') {
			/*
			 * Internet format:
			 *	a.b.c.d
			 *	a.b.c	(with c treated as 16 bits)
			 *	a.b	(with b treated as 24 bits)
			 */
			যদি (pp >= parts + 3)
				প্রত্যাগম (0);
			*pp++ = val;
			c = *++cp;
		} অন্যথা
			ভঙ্গ;
	}
	/*
	 * Check for trailing characters.
	 */
	যদি (c != '\0' && (!isascii(c) || !isspace(c)))
		প্রত্যাগম (0);
	/*
	 * Concoct the address according to
	 * the number of parts specified.
	 */
	n = pp - parts + 1;
	বিকল্প (n) {

	পক্ষ 0:
		প্রত্যাগম (0);		/* initial nondigit */

	পক্ষ 1:				/* a -- 32 bits */
		ভঙ্গ;

	পক্ষ 2:				/* a.b -- 8.24 bits */
		যদি ((val > 0xffffff) || (parts[0] > 0xff))
			প্রত্যাগম (0);
		val |= parts[0] << 24;
		ভঙ্গ;

	পক্ষ 3:				/* a.b.c -- 8.8.16 bits */
		যদি ((val > 0xffff) || (parts[0] > 0xff) || (parts[1] > 0xff))
			প্রত্যাগম (0);
		val |= (parts[0] << 24) | (parts[1] << 16);
		ভঙ্গ;

	পক্ষ 4:				/* a.b.c.d -- 8.8.8.8 bits */
		যদি ((val > 0xff) || (parts[0] > 0xff) || (parts[1] > 0xff) || (parts[2] > 0xff))
			প্রত্যাগম (0);
		val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
		ভঙ্গ;
	}
	যদি (addr)
		addr->s_addr = htonl(val);
	প্রত্যাগম (1);
}

#endif /* !defined(HAVE_INET_ATON) */
