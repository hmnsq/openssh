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

#شامل "includes.h"

#اگر_غیر_تعریف_شدہ HAVE_INET_NTOP

#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <netinet/in.h>
#شامل <arpa/inet.h>
#شامل <arpa/nameser.h>
#شامل <string.h>
#شامل <errno.h>
#شامل <stdio.h>

#اگر_غیر_تعریف_شدہ IN6ADDRSZ
#تعریف_کرو IN6ADDRSZ   16   /* IPv6 T_AAAA */                 
#اگر_ختم

#اگر_غیر_تعریف_شدہ INT16SZ
#تعریف_کرو INT16SZ     2    /* for systems without 16-bit ints */
#اگر_ختم

/*
 * WARNING: Don't even consider trying to compile this on a system where
 * sizeof(int) < 4.  sizeof(int) > 4 is fine; all the world's not a VAX.
 */

ساکن ثابت حرف *inet_ntop4(ثابت u_char *src, حرف *dst, سائز_t سائز);
ساکن ثابت حرف *inet_ntop6(ثابت u_char *src, حرف *dst, سائز_t سائز);

/* char *
 * inet_ntop(af, src, dst, size)
 *	convert a network format address to presentation format.
 * return:
 *	pointer to presentation format address (`dst'), or NULL (see errno).
 * author:
 *	Paul Vixie, 1996.
 */
ثابت حرف *
inet_ntop(صحیح af, ثابت خالی *src, حرف *dst, socklen_t سائز)
{
	انتخاب (af) {
	حالت AF_INET:
		واپس (inet_ntop4(src, dst, (سائز_t)سائز));
	حالت AF_INET6:
		واپس (inet_ntop6(src, dst, (سائز_t)سائز));
	طےشدہ:
		errno = EAFNOSUPPORT;
		واپس (تہی);
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
ساکن ثابت حرف *
inet_ntop4(ثابت u_char *src, حرف *dst, سائز_t سائز)
{
	ساکن ثابت حرف fmt[] = "%u.%u.%u.%u";
	حرف tmp[حجم "255.255.255.255"];
	صحیح l;

	l = snprintf(tmp, سائز, fmt, src[0], src[1], src[2], src[3]);
	اگر (l <= 0 || l >= سائز) {
		errno = ENOSPC;
		واپس (تہی);
	}
	strlcpy(dst, tmp, سائز);
	واپس (dst);
}

/* const char *
 * inet_ntop6(src, dst, size)
 *	convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
ساکن ثابت حرف *
inet_ntop6(ثابت u_char *src, حرف *dst, سائز_t سائز)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	حرف tmp[حجم "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"];
	حرف *tp, *ep;
	ساخت { صحیح بنیاد, len; } بہترین, cur;
	u_int الفاظ[IN6ADDRSZ / INT16SZ];
	صحیح i;
	صحیح advance;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(الفاظ, '\0', حجم الفاظ);
	برائے (i = 0; i < IN6ADDRSZ; i++)
		الفاظ[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	بہترین.بنیاد = -1;
	cur.بنیاد = -1;
	برائے (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
		اگر (الفاظ[i] == 0) {
			اگر (cur.بنیاد == -1)
				cur.بنیاد = i, cur.len = 1;
			ورنہ
				cur.len++;
		} ورنہ {
			اگر (cur.بنیاد != -1) {
				اگر (بہترین.بنیاد == -1 || cur.len > بہترین.len)
					بہترین = cur;
				cur.بنیاد = -1;
			}
		}
	}
	اگر (cur.بنیاد != -1) {
		اگر (بہترین.بنیاد == -1 || cur.len > بہترین.len)
			بہترین = cur;
	}
	اگر (بہترین.بنیاد != -1 && بہترین.len < 2)
		بہترین.بنیاد = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	ep = tmp + حجم(tmp);
	برائے (i = 0; i < (IN6ADDRSZ / INT16SZ) && tp < ep; i++) {
		/* Are we inside the best run of 0x00's? */
		اگر (بہترین.بنیاد != -1 && i >= بہترین.بنیاد &&
		    i < (بہترین.بنیاد + بہترین.len)) {
			اگر (i == بہترین.بنیاد) {
				اگر (tp + 1 >= ep)
					واپس (تہی);
				*tp++ = ':';
			}
			جاری;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		اگر (i != 0) {
			اگر (tp + 1 >= ep)
				واپس (تہی);
			*tp++ = ':';
		}
		/* Is this address an encapsulated IPv4? */
		اگر (i == 6 && بہترین.بنیاد == 0 &&
		    (بہترین.len == 6 || (بہترین.len == 5 && الفاظ[5] == 0xffff))) {
			اگر (!inet_ntop4(src+12, tp, (سائز_t)(ep - tp)))
				واپس (تہی);
			tp += لڑی_لمبائی(tp);
			توڑو;
		}
		advance = snprintf(tp, ep - tp, "%x", الفاظ[i]);
		اگر (advance <= 0 || advance >= ep - tp)
			واپس (تہی);
		tp += advance;
	}
	/* Was it a trailing run of 0x00's? */
	اگر (بہترین.بنیاد != -1 && (بہترین.بنیاد + بہترین.len) == (IN6ADDRSZ / INT16SZ)) {
		اگر (tp + 1 >= ep)
			واپس (تہی);
		*tp++ = ':';
	}
	اگر (tp + 1 >= ep)
		واپس (تہی);
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	اگر ((سائز_t)(tp - tmp) > سائز) {
		errno = ENOSPC;
		واپس (تہی);
	}
	strlcpy(dst, tmp, سائز);
	واپس (dst);
}

#اگر_ختم /* !HAVE_INET_NTOP */
