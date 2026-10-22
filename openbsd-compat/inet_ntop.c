/*	$OpenBSD: inet_ntop.c,v 1.8 2008/12/09 19:38:38 otto Exp $	*/

/* Copyright (c) 1996 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/* OPENBSD ORIGINAL: lib/libc/net/inet_ntop.c */

#अन्तर्भाव "includes.h"

#यदि_अपरिभाषितम् HAVE_INET_NTOP

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <arpa/inet.h>
#अन्तर्भाव <arpa/nameser.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <stdio.h>

#यदि_अपरिभाषितम् IN6ADDRSZ
#परिभाषय IN6ADDRSZ   16   /* IPv6 T_AAAA */                 
#यदि_अन्तः

#यदि_अपरिभाषितम् INT16SZ
#परिभाषय INT16SZ     2    /* for systems without 16-bit ints */
#यदि_अन्तः

/*
 * WARNING: Don't even consider trying to compile this on a system where
 * sizeof(int) < 4.  sizeof(int) > 4 is fine; all the world's not a VAX.
 */

स्थिर ध्रुव वर्ण *inet_ntop4(ध्रुव u_char *src, वर्ण *dst, आकार_t आकार);
स्थिर ध्रुव वर्ण *inet_ntop6(ध्रुव u_char *src, वर्ण *dst, आकार_t आकार);

/* char *
 * inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
ध्रुव वर्ण *
inet_ntop(पूर्णाङ्क af, ध्रुव शून्य *src, वर्ण *dst, socklen_t आकार)
{
	विकल्प (af) {
	पक्ष AF_INET:
		प्रत्यागम (inet_ntop4(src, dst, (आकार_t)आकार));
	पक्ष AF_INET6:
		प्रत्यागम (inet_ntop6(src, dst, (आकार_t)आकार));
	स्वभाव:
		errno = EAFNOSUPPORT;
		प्रत्यागम (रिक्त);
	}
	/* NOTREACHED */
}

/* const char *
 * inet_ntop4(src, dst, size)
 *	format an IPv4 address, more or less like inet_ntoa()
 * return:
 *	`dst' (as a const)
 * notes:
 *	(1) uses no statics
 *	(2) takes a u_char* not an in_addr as input
 * author:
 *	Paul Vixie, 1996.
 */
स्थिर ध्रुव वर्ण *
inet_ntop4(ध्रुव u_char *src, वर्ण *dst, आकार_t आकार)
{
	स्थिर ध्रुव वर्ण fmt[] = "%u.%u.%u.%u";
	वर्ण tmp[परिमाण "255.255.255.255"];
	पूर्णाङ्क l;

	l = snprintf(tmp, आकार, fmt, src[0], src[1], src[2], src[3]);
	यदि (l <= 0 || l >= आकार) {
		errno = ENOSPC;
		प्रत्यागम (रिक्त);
	}
	strlcpy(dst, tmp, आकार);
	प्रत्यागम (dst);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
स्थिर ध्रुव वर्ण *
inet_ntop6(ध्रुव u_char *src, वर्ण *dst, आकार_t आकार)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	वर्ण tmp[परिमाण "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
	वर्ण *tp, *ep;
	संरचना { पूर्णाङ्क आधारः, len; } best, cur;
	u_int शब्दाः[IN6ADDRSZ / INT16SZ];
	पूर्णाङ्क i;
	पूर्णाङ्क advance;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	स्मृतिं_पूरय(शब्दाः, '\0', परिमाण शब्दाः);
	प्रति (i = 0; i < IN6ADDRSZ; i++)
		शब्दाः[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.आधारः = -1;
	cur.आधारः = -1;
	प्रति (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
		यदि (शब्दाः[i] == 0) {
			यदि (cur.आधारः == -1)
				cur.आधारः = i, cur.len = 1;
			अन्यथा
				cur.len++;
		} अन्यथा {
			यदि (cur.आधारः != -1) {
				यदि (best.आधारः == -1 || cur.len > best.len)
					best = cur;
				cur.आधारः = -1;
			}
		}
	}
	यदि (cur.आधारः != -1) {
		यदि (best.आधारः == -1 || cur.len > best.len)
			best = cur;
	}
	यदि (best.आधारः != -1 && best.len < 2)
		best.आधारः = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	ep = tmp + परिमाण(tmp);
	प्रति (i = 0; i < (IN6ADDRSZ / INT16SZ) && tp < ep; i++) {
		/* Are we inside the best run of 0x00's? */
		यदि (best.आधारः != -1 && i >= best.आधारः &&
		    i < (best.आधारः + best.len)) {
			यदि (i == best.आधारः) {
				यदि (tp + 1 >= ep)
					प्रत्यागम (रिक्त);
				*tp++ = ':';
			}
			अनुवर्त;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		यदि (i != 0) {
			यदि (tp + 1 >= ep)
				प्रत्यागम (रिक्त);
			*tp++ = ':';
		}
		/* Is this address an encapsulated IPv4? */
		यदि (i == 6 && best.आधारः == 0 &&
		    (best.len == 6 || (best.len == 5 && शब्दाः[5] == 0xffff))) {
			यदि (!inet_ntop4(src+12, tp, (आकार_t)(ep - tp)))
				प्रत्यागम (रिक्त);
			tp += वाक्यदैर्घ्यम्(tp);
			भङ्ग;
		}
		advance = snprintf(tp, ep - tp, "%x", शब्दाः[i]);
		यदि (advance <= 0 || advance >= ep - tp)
			प्रत्यागम (रिक्त);
		tp += advance;
	}
	/* Was it a trailing run of 0x00's? */
	यदि (best.आधारः != -1 && (best.आधारः + best.len) == (IN6ADDRSZ / INT16SZ)) {
		यदि (tp + 1 >= ep)
			प्रत्यागम (रिक्त);
		*tp++ = ':';
	}
	यदि (tp + 1 >= ep)
		प्रत्यागम (रिक्त);
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	यदि ((आकार_t)(tp - tmp) > आकार) {
		errno = ENOSPC;
		प्रत्यागम (रिक्त);
	}
	strlcpy(dst, tmp, आकार);
	प्रत्यागम (dst);
}

#यदि_अन्तः /* !HAVE_INET_NTOP */
