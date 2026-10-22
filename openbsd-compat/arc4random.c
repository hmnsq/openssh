/*	$OpenBSD: arc4random.c,v 1.58 2022/07/31 13:41:45 tb Exp $	*/

/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 * Copyright (c) 2013, Markus Friedl <markus@openbsd.org>
 * Copyright (c) 2014, Theo de Raadt <deraadt@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * ChaCha based random number generator for OpenBSD.
 */

/* OPENBSD ORIGINAL: lib/libc/crypt/arc4random.c */

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <fcntl.h>
#شامل <limits.h>
#شامل <signal.h>
#شامل <stdint.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <sys/types.h>
#شامل <sys/time.h>

#اگر_غیر_تعریف_شدہ HAVE_ARC4RANDOM

/*
 * Always use the getentropy implementation from bsd-getentropy.c, which
 * will call a native getentropy if available then fall back as required.
 * We use a different name so that OpenSSL cannot call the wrong getentropy.
 */
صحیح _ssh_compat_getentropy(خالی *, سائز_t);
#اگر_تعریف_شدہ getentropy
# undef getentropy
#اگر_ختم
#تعریف_کرو getentropy(x, y) (_ssh_compat_getentropy((x), (y)))

#شامل "log.h"

#تعریف_کرو KEYSTREAM_ONLY
#شامل "chacha_private.h"

#تعریف_کرو minimum(a, b) ((a) < (b) ? (a) : (b))

#اگر defined(__GNUC__) || defined(_MSC_VER)
#تعریف_کرو اندرونی __inline
#ورنہ				/* __GNUC__ || _MSC_VER */
#تعریف_کرو اندرونی
#اگر_ختم				/* !__GNUC__ && !_MSC_VER */

#تعریف_کرو KEYSZ	32
#تعریف_کرو IVSZ	8
#تعریف_کرو BLOCKSZ	64
#تعریف_کرو RSBUFSZ	(16*BLOCKSZ)

#تعریف_کرو REKEY_بنیاد	(1024*1024) /* NB. should be a power of 2 */

/* Marked MAP_INHERIT_ZERO, so zero'd out in fork children. */
ساکن ساخت _rs {
	سائز_t		rs_have;	/* valid bytes at end of rs_buf */
	سائز_t		rs_گنتی;	/* bytes till reseed */
} *rs;

/* Maybe be preserved in fork children, if _rs_allocate() decides. */
ساکن ساخت _rsx {
	chacha_ctx	rs_chacha;	/* chacha context for random keystream */
	u_char		rs_buf[RSBUFSZ];	/* keystream blocks */
} *rsx;

ساکن اندرونی صحیح _rs_allocate(ساخت _rs **, ساخت _rsx **);
ساکن اندرونی خالی _rs_forkdetect(خالی);
#شامل "arc4random.h"

ساکن اندرونی خالی _rs_rekey(u_char *dat, سائز_t datlen);

ساکن اندرونی خالی
_rs_init(u_char *buf, سائز_t n)
{
	اگر (n < KEYSZ + IVSZ)
		واپس;

	اگر (rs == تہی) {
		اگر (_rs_allocate(&rs, &rsx) == -1)
			_exit(1);
	}

	chacha_keysetup(&rsx->rs_chacha, buf, KEYSZ * 8);
	chacha_ivsetup(&rsx->rs_chacha, buf + KEYSZ);
}

ساکن خالی
_rs_stir(خالی)
{
	u_char rnd[KEYSZ + IVSZ];
	uint32_t rekey_fuzz = 0;

	اگر (getentropy(rnd, حجم rnd) == -1)
		_getentropy_fail();

	اگر (!rs)
		_rs_init(rnd, حجم(rnd));
	ورنہ
		_rs_rekey(rnd, حجم(rnd));
	explicit_bzero(rnd, حجم(rnd));	/* discard source seed */

	/* invalidate rs_buf */
	rs->rs_have = 0;
	memset(rsx->rs_buf, 0, حجم(rsx->rs_buf));

	/* rekey interval should not be predictable */
	chacha_encrypt_بائٹیں(&rsx->rs_chacha, (uint8_t *)&rekey_fuzz,
	    (uint8_t *)&rekey_fuzz, حجم(rekey_fuzz));
	rs->rs_گنتی = REKEY_بنیاد + (rekey_fuzz % REKEY_بنیاد);
}

ساکن اندرونی خالی
_rs_stir_if_needed(سائز_t len)
{
	_rs_forkdetect();
	اگر (!rs || rs->rs_گنتی <= len)
		_rs_stir();
	اگر (rs->rs_گنتی <= len)
		rs->rs_گنتی = 0;
	ورنہ
		rs->rs_گنتی -= len;
}

ساکن اندرونی خالی
_rs_rekey(u_char *dat, سائز_t datlen)
{
#اگر_غیر_تعریف_شدہ KEYSTREAM_ONLY
	memset(rsx->rs_buf, 0, حجم(rsx->rs_buf));
#اگر_ختم
	/* fill rs_buf with the keystream */
	chacha_encrypt_بائٹیں(&rsx->rs_chacha, rsx->rs_buf,
	    rsx->rs_buf, حجم(rsx->rs_buf));
	/* mix in optional user provided data */
	اگر (dat) {
		سائز_t i, m;

		m = minimum(datlen, KEYSZ + IVSZ);
		برائے (i = 0; i < m; i++)
			rsx->rs_buf[i] ^= dat[i];
	}
	/* immediately reinit for backtracking resistance */
	_rs_init(rsx->rs_buf, KEYSZ + IVSZ);
	memset(rsx->rs_buf, 0, KEYSZ + IVSZ);
	rs->rs_have = حجم(rsx->rs_buf) - KEYSZ - IVSZ;
}

ساکن اندرونی خالی
_rs_random_buf(خالی *_buf, سائز_t n)
{
	u_char *buf = (u_char *)_buf;
	u_char *keystream;
	سائز_t m;

	_rs_stir_if_needed(n);
	جب (n > 0) {
		اگر (rs->rs_have > 0) {
			m = minimum(n, rs->rs_have);
			keystream = rsx->rs_buf + حجم(rsx->rs_buf)
			    - rs->rs_have;
			حافظہ_نقل(buf, keystream, m);
			memset(keystream, 0, m);
			buf += m;
			n -= m;
			rs->rs_have -= m;
		}
		اگر (rs->rs_have == 0)
			_rs_rekey(تہی, 0);
	}
}

ساکن اندرونی خالی
_rs_random_u32(uint32_t *val)
{
	u_char *keystream;

	_rs_stir_if_needed(حجم(*val));
	اگر (rs->rs_have < حجم(*val))
		_rs_rekey(تہی, 0);
	keystream = rsx->rs_buf + حجم(rsx->rs_buf) - rs->rs_have;
	حافظہ_نقل(val, keystream, حجم(*val));
	memset(keystream, 0, حجم(*val));
	rs->rs_have -= حجم(*val);
}

uint32_t
arc4random(خالی)
{
	uint32_t val;

	ARC4_تالا();
	_rs_random_u32(&val);
	_ARC4_UNLOCK();
	واپس val;
}
DEF_WEAK(arc4random);

/*
 * If we are providing arc4random, then we can provide a more efficient
 * arc4random_buf().
 */
# ifndef HAVE_ARC4RANDOM_BUF
خالی
arc4random_buf(خالی *buf, سائز_t n)
{
	ARC4_تالا();
	_rs_random_buf(buf, n);
	_ARC4_UNLOCK();
}
DEF_WEAK(arc4random_buf);
# endif /* !HAVE_ARC4RANDOM_BUF */
#اگر_ختم /* !HAVE_ARC4RANDOM */

/* arc4random_buf() that uses platform arc4random() */
#اگر !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM)
خالی
arc4random_buf(خالی *_buf, سائز_t n)
{
	سائز_t i;
	u_int32_t r = 0;
	حرف *buf = (حرف *)_buf;

	برائے (i = 0; i < n; i++) {
		اگر (i % 4 == 0)
			r = arc4random();
		buf[i] = r & 0xff;
		r >>= 8;
	}
	explicit_bzero(&r, حجم(r));
}
#اگر_ختم /* !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM) */

