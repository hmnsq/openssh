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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_INET_NTOP

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>
#ಅನ್ತರ್ಭಾವ <arpa/nameser.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ IN6ADDRSZ
#ವ್ಯಾಖ್ಯಾನಿಸು IN6ADDRSZ   16   /* IPv6 T_AAAA */                 
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ INT16SZ
#ವ್ಯಾಖ್ಯಾನಿಸು INT16SZ     2    /* for systems without 16-bit ints */
#ಆದರೆ_ಅಂತ್ಯ

/*
 * WARNING: Don't even consider trying to compile this on a system where
 * sizeof(int) < 4.  sizeof(int) > 4 is fine; all the world's not a VAX.
 */

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *inet_ntop4(ಸ್ಥಿರಾಂಕ u_char *src, ಅಕ್ಷರ *dst, ಗಾತ್ರ_t ಗಾತ್ರ_2);
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *inet_ntop6(ಸ್ಥಿರಾಂಕ u_char *src, ಅಕ್ಷರ *dst, ಗಾತ್ರ_t ಗಾತ್ರ_2);

/* char *
 * inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
inet_ntop(ಪೂರ್ಣಾಂಕ af, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *src, ಅಕ್ಷರ *dst, socklen_t ಗಾತ್ರ_2)
{
	ಆಯ್ಕೆ (af) {
	ಸ್ಥಿತಿ AF_INET:
		ಹಿಂತಿರುಗಿ (inet_ntop4(src, dst, (ಗಾತ್ರ_t)ಗಾತ್ರ_2));
	ಸ್ಥಿತಿ AF_INET6:
		ಹಿಂತಿರುಗಿ (inet_ntop6(src, dst, (ಗಾತ್ರ_t)ಗಾತ್ರ_2));
	ಪೂರ್ವನಿಯೋಜಿತ:
		errno = EAFNOSUPPORT;
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
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
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
inet_ntop4(ಸ್ಥಿರಾಂಕ u_char *src, ಅಕ್ಷರ *dst, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ fmt[] = "%u.%u.%u.%u";
	ಅಕ್ಷರ tmp[ಗಾತ್ರ "255.255.255.255"];
	ಪೂರ್ಣಾಂಕ l;

	l = snprintf(tmp, ಗಾತ್ರ_2, fmt, src[0], src[1], src[2], src[3]);
	ಆದರೆ (l <= 0 || l >= ಗಾತ್ರ_2) {
		errno = ENOSPC;
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}
	strlcpy(dst, tmp, ಗಾತ್ರ_2);
	ಹಿಂತಿರುಗಿ (dst);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
inet_ntop6(ಸ್ಥಿರಾಂಕ u_char *src, ಅಕ್ಷರ *dst, ಗಾತ್ರ_t ಗಾತ್ರ_2)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	ಅಕ್ಷರ tmp[ಗಾತ್ರ "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
	ಅಕ್ಷರ *tp, *ep;
	ರಚನೆ { ಪೂರ್ಣಾಂಕ ತಳ, len; } ಉತ್ತಮ, cur;
	u_int ಪದಗಳು[IN6ADDRSZ / INT16SZ];
	ಪೂರ್ಣಾಂಕ i;
	ಪೂರ್ಣಾಂಕ advance;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(ಪದಗಳು, '\0', ಗಾತ್ರ ಪದಗಳು);
	ಗಾಗಿ (i = 0; i < IN6ADDRSZ; i++)
		ಪದಗಳು[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	ಉತ್ತಮ.ತಳ = -1;
	cur.ತಳ = -1;
	ಗಾಗಿ (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
		ಆದರೆ (ಪದಗಳು[i] == 0) {
			ಆದರೆ (cur.ತಳ == -1)
				cur.ತಳ = i, cur.len = 1;
			ಇಲ್ಲದಿದ್ದರೆ
				cur.len++;
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (cur.ತಳ != -1) {
				ಆದರೆ (ಉತ್ತಮ.ತಳ == -1 || cur.len > ಉತ್ತಮ.len)
					ಉತ್ತಮ = cur;
				cur.ತಳ = -1;
			}
		}
	}
	ಆದರೆ (cur.ತಳ != -1) {
		ಆದರೆ (ಉತ್ತಮ.ತಳ == -1 || cur.len > ಉತ್ತಮ.len)
			ಉತ್ತಮ = cur;
	}
	ಆದರೆ (ಉತ್ತಮ.ತಳ != -1 && ಉತ್ತಮ.len < 2)
		ಉತ್ತಮ.ತಳ = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	ep = tmp + ಗಾತ್ರ(tmp);
	ಗಾಗಿ (i = 0; i < (IN6ADDRSZ / INT16SZ) && tp < ep; i++) {
		/* Are we inside the best run of 0x00's? */
		ಆದರೆ (ಉತ್ತಮ.ತಳ != -1 && i >= ಉತ್ತಮ.ತಳ &&
		    i < (ಉತ್ತಮ.ತಳ + ಉತ್ತಮ.len)) {
			ಆದರೆ (i == ಉತ್ತಮ.ತಳ) {
				ಆದರೆ (tp + 1 >= ep)
					ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
				*tp++ = ':';
			}
			ಮುಂದುವರಿ;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		ಆದರೆ (i != 0) {
			ಆದರೆ (tp + 1 >= ep)
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			*tp++ = ':';
		}
		/* Is this address an encapsulated IPv4? */
		ಆದರೆ (i == 6 && ಉತ್ತಮ.ತಳ == 0 &&
		    (ಉತ್ತಮ.len == 6 || (ಉತ್ತಮ.len == 5 && ಪದಗಳು[5] == 0xffff))) {
			ಆದರೆ (!inet_ntop4(src+12, tp, (ಗಾತ್ರ_t)(ep - tp)))
				ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
			tp += ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(tp);
			ನಿಲ್ಲಿಸು;
		}
		advance = snprintf(tp, ep - tp, "%x", ಪದಗಳು[i]);
		ಆದರೆ (advance <= 0 || advance >= ep - tp)
			ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
		tp += advance;
	}
	/* Was it a trailing run of 0x00's? */
	ಆದರೆ (ಉತ್ತಮ.ತಳ != -1 && (ಉತ್ತಮ.ತಳ + ಉತ್ತಮ.len) == (IN6ADDRSZ / INT16SZ)) {
		ಆದರೆ (tp + 1 >= ep)
			ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
		*tp++ = ':';
	}
	ಆದರೆ (tp + 1 >= ep)
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	ಆದರೆ ((ಗಾತ್ರ_t)(tp - tmp) > ಗಾತ್ರ_2) {
		errno = ENOSPC;
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}
	strlcpy(dst, tmp, ಗಾತ್ರ_2);
	ಹಿಂತಿರುಗಿ (dst);
}

#ಆದರೆ_ಅಂತ್ಯ /* !HAVE_INET_NTOP */
