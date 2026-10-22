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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_INET_NTOP

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <arpa/inet.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <arpa/nameser.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ IN6ADDRSZ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ IN6ADDRSZ   16   /* IPv6 T_AAAA */                 
#ਜੇ_ਅੰਤ

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ INT16SZ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ INT16SZ     2    /* for systems without 16-bit ints */
#ਜੇ_ਅੰਤ

/*
 * WARNING: Don't even consider trying to compile this on a system where
 * sizeof(int) < 4.  sizeof(int) > 4 is fine; all the world's not a VAX.
 */

ਸਥਿਰ ਅਚਲ ਅੱਖਰ *inet_ntop4(ਅਚਲ u_char *src, ਅੱਖਰ *dst, ਮਾਪ_t ਮਾਪ);
ਸਥਿਰ ਅਚਲ ਅੱਖਰ *inet_ntop6(ਅਚਲ u_char *src, ਅੱਖਰ *dst, ਮਾਪ_t ਮਾਪ);

/* char *
 * inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
ਅਚਲ ਅੱਖਰ *
inet_ntop(ਪੂਰਨ af, ਅਚਲ ਖਾਲੀ *src, ਅੱਖਰ *dst, socklen_t ਮਾਪ)
{
	ਚੋਣ (af) {
	ਹਾਲਤ AF_INET:
		ਵਾਪਸ (inet_ntop4(src, dst, (ਮਾਪ_t)ਮਾਪ));
	ਹਾਲਤ AF_INET6:
		ਵਾਪਸ (inet_ntop6(src, dst, (ਮਾਪ_t)ਮਾਪ));
	ਮੂਲ:
		errno = EAFNOSUPPORT;
		ਵਾਪਸ (ਨਿਰਾ);
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
ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
inet_ntop4(ਅਚਲ u_char *src, ਅੱਖਰ *dst, ਮਾਪ_t ਮਾਪ)
{
	ਸਥਿਰ ਅਚਲ ਅੱਖਰ fmt[] = "%u.%u.%u.%u";
	ਅੱਖਰ tmp[ਆਕਾਰ "255.255.255.255"];
	ਪੂਰਨ l;

	l = snprintf(tmp, ਮਾਪ, fmt, src[0], src[1], src[2], src[3]);
	ਜੇ (l <= 0 || l >= ਮਾਪ) {
		errno = ENOSPC;
		ਵਾਪਸ (ਨਿਰਾ);
	}
	strlcpy(dst, tmp, ਮਾਪ);
	ਵਾਪਸ (dst);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
inet_ntop6(ਅਚਲ u_char *src, ਅੱਖਰ *dst, ਮਾਪ_t ਮਾਪ)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	ਅੱਖਰ tmp[ਆਕਾਰ "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
	ਅੱਖਰ *tp, *ep;
	ਬਣਤਰ { ਪੂਰਨ ਅਧਾਰ, len; } ਉੱਤਮ, cur;
	u_int ਸ਼ਬਦ[IN6ADDRSZ / INT16SZ];
	ਪੂਰਨ i;
	ਪੂਰਨ advance;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(ਸ਼ਬਦ, '\0', ਆਕਾਰ ਸ਼ਬਦ);
	ਲਈ (i = 0; i < IN6ADDRSZ; i++)
		ਸ਼ਬਦ[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	ਉੱਤਮ.ਅਧਾਰ = -1;
	cur.ਅਧਾਰ = -1;
	ਲਈ (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
		ਜੇ (ਸ਼ਬਦ[i] == 0) {
			ਜੇ (cur.ਅਧਾਰ == -1)
				cur.ਅਧਾਰ = i, cur.len = 1;
			ਨਹੀਂਤਾਂ
				cur.len++;
		} ਨਹੀਂਤਾਂ {
			ਜੇ (cur.ਅਧਾਰ != -1) {
				ਜੇ (ਉੱਤਮ.ਅਧਾਰ == -1 || cur.len > ਉੱਤਮ.len)
					ਉੱਤਮ = cur;
				cur.ਅਧਾਰ = -1;
			}
		}
	}
	ਜੇ (cur.ਅਧਾਰ != -1) {
		ਜੇ (ਉੱਤਮ.ਅਧਾਰ == -1 || cur.len > ਉੱਤਮ.len)
			ਉੱਤਮ = cur;
	}
	ਜੇ (ਉੱਤਮ.ਅਧਾਰ != -1 && ਉੱਤਮ.len < 2)
		ਉੱਤਮ.ਅਧਾਰ = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	ep = tmp + ਆਕਾਰ(tmp);
	ਲਈ (i = 0; i < (IN6ADDRSZ / INT16SZ) && tp < ep; i++) {
		/* Are we inside the best run of 0x00's? */
		ਜੇ (ਉੱਤਮ.ਅਧਾਰ != -1 && i >= ਉੱਤਮ.ਅਧਾਰ &&
		    i < (ਉੱਤਮ.ਅਧਾਰ + ਉੱਤਮ.len)) {
			ਜੇ (i == ਉੱਤਮ.ਅਧਾਰ) {
				ਜੇ (tp + 1 >= ep)
					ਵਾਪਸ (ਨਿਰਾ);
				*tp++ = ':';
			}
			ਜਾਰੀ;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		ਜੇ (i != 0) {
			ਜੇ (tp + 1 >= ep)
				ਵਾਪਸ (ਨਿਰਾ);
			*tp++ = ':';
		}
		/* Is this address an encapsulated IPv4? */
		ਜੇ (i == 6 && ਉੱਤਮ.ਅਧਾਰ == 0 &&
		    (ਉੱਤਮ.len == 6 || (ਉੱਤਮ.len == 5 && ਸ਼ਬਦ[5] == 0xffff))) {
			ਜੇ (!inet_ntop4(src+12, tp, (ਮਾਪ_t)(ep - tp)))
				ਵਾਪਸ (ਨਿਰਾ);
			tp += ਲੜੀ_ਲੰਬਾਈ(tp);
			ਰੋਕੋ;
		}
		advance = snprintf(tp, ep - tp, "%x", ਸ਼ਬਦ[i]);
		ਜੇ (advance <= 0 || advance >= ep - tp)
			ਵਾਪਸ (ਨਿਰਾ);
		tp += advance;
	}
	/* Was it a trailing run of 0x00's? */
	ਜੇ (ਉੱਤਮ.ਅਧਾਰ != -1 && (ਉੱਤਮ.ਅਧਾਰ + ਉੱਤਮ.len) == (IN6ADDRSZ / INT16SZ)) {
		ਜੇ (tp + 1 >= ep)
			ਵਾਪਸ (ਨਿਰਾ);
		*tp++ = ':';
	}
	ਜੇ (tp + 1 >= ep)
		ਵਾਪਸ (ਨਿਰਾ);
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	ਜੇ ((ਮਾਪ_t)(tp - tmp) > ਮਾਪ) {
		errno = ENOSPC;
		ਵਾਪਸ (ਨਿਰਾ);
	}
	strlcpy(dst, tmp, ਮਾਪ);
	ਵਾਪਸ (dst);
}

#ਜੇ_ਅੰਤ /* !HAVE_INET_NTOP */
