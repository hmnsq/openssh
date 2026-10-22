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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <fcntl.h>
#ضمن <limits.h>
#ضمن <signal.h>
#ضمن <stdint.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <sys/types.h>
#ضمن <sys/time.h>

#جے_بنا_تعریف HAVE_ARC4RANDOM

/*
 * Always use the getentropy implementation from bsd-getentropy.c, which
 * will call a native getentropy if available then fall back as required.
 * We use a different name so that OpenSSL cannot call the wrong getentropy.
 */
صحيح _ssh_compat_getentropy(فراغ *, ناپ_t);
#جے_تعریف_شدہ getentropy
# undef getentropy
#جے_انت
#تعریف_کرو getentropy(x, y) (_ssh_compat_getentropy((x), (y)))

#ضمن "log.h"

#تعریف_کرو KEYSTREAM_ONLY
#ضمن "chacha_private.h"

#تعریف_کرو minimum(a, b) ((a) < (b) ? (a) : (b))

#إذا defined(__GNUC__) || defined(_MSC_VER)
#تعریف_کرو مضمن __inline
#وإلا				/* __GNUC__ || _MSC_VER */
#تعریف_کرو مضمن
#جے_انت				/* !__GNUC__ && !_MSC_VER */

#تعریف_کرو KEYSZ	32
#تعریف_کرو IVSZ	8
#تعریف_کرو BLOCKSZ	64
#تعریف_کرو RSBUFSZ	(16*BLOCKSZ)

#تعریف_کرو REKEY_ادھار	(1024*1024) /* NB. should be a power of 2 */

/* Marked MAP_INHERIT_ZERO, so zero'd out in fork children. */
ساكن بنية _rs {
	ناپ_t		rs_have;	/* valid bytes at end of rs_buf */
	ناپ_t		rs_گنتی;	/* bytes till reseed */
} *rs;

/* Maybe be preserved in fork children, if _rs_allocate() decides. */
ساكن بنية _rsx {
	chacha_ctx	rs_chacha;	/* chacha context for random keystream */
	u_char		rs_buf[RSBUFSZ];	/* keystream blocks */
} *rsx;

ساكن مضمن صحيح _rs_allocate(بنية _rs **, بنية _rsx **);
ساكن مضمن فراغ _rs_forkdetect(فراغ);
#ضمن "arc4random.h"

ساكن مضمن فراغ _rs_rekey(u_char *dat, ناپ_t datlen);

ساكن مضمن فراغ
_rs_init(u_char *buf, ناپ_t n)
{
	إذا (n < KEYSZ + IVSZ)
		أرجع;

	إذا (rs == عدم) {
		إذا (_rs_allocate(&rs, &rsx) == -1)
			_exit(1);
	}

	chacha_keysetup(&rsx->rs_chacha, buf, KEYSZ * 8);
	chacha_ivsetup(&rsx->rs_chacha, buf + KEYSZ);
}

ساكن فراغ
_rs_stir(فراغ)
{
	u_char rnd[KEYSZ + IVSZ];
	uint32_t rekey_fuzz = 0;

	إذا (getentropy(rnd, حجم rnd) == -1)
		_getentropy_fail();

	إذا (!rs)
		_rs_init(rnd, حجم(rnd));
	وإلا
		_rs_rekey(rnd, حجم(rnd));
	explicit_bzero(rnd, حجم(rnd));	/* discard source seed */

	/* invalidate rs_buf */
	rs->rs_have = 0;
	memset(rsx->rs_buf, 0, حجم(rsx->rs_buf));

	/* rekey interval should not be predictable */
	chacha_encrypt_بائٹاں(&rsx->rs_chacha, (uint8_t *)&rekey_fuzz,
	    (uint8_t *)&rekey_fuzz, حجم(rekey_fuzz));
	rs->rs_گنتی = REKEY_ادھار + (rekey_fuzz % REKEY_ادھار);
}

ساكن مضمن فراغ
_rs_stir_if_needed(ناپ_t len)
{
	_rs_forkdetect();
	إذا (!rs || rs->rs_گنتی <= len)
		_rs_stir();
	إذا (rs->rs_گنتی <= len)
		rs->rs_گنتی = 0;
	وإلا
		rs->rs_گنتی -= len;
}

ساكن مضمن فراغ
_rs_rekey(u_char *dat, ناپ_t datlen)
{
#جے_بنا_تعریف KEYSTREAM_ONLY
	memset(rsx->rs_buf, 0, حجم(rsx->rs_buf));
#جے_انت
	/* fill rs_buf with the keystream */
	chacha_encrypt_بائٹاں(&rsx->rs_chacha, rsx->rs_buf,
	    rsx->rs_buf, حجم(rsx->rs_buf));
	/* mix in optional user provided data */
	إذا (dat) {
		ناپ_t i, m;

		m = minimum(datlen, KEYSZ + IVSZ);
		لكل (i = 0; i < m; i++)
			rsx->rs_buf[i] ^= dat[i];
	}
	/* immediately reinit for backtracking resistance */
	_rs_init(rsx->rs_buf, KEYSZ + IVSZ);
	memset(rsx->rs_buf, 0, KEYSZ + IVSZ);
	rs->rs_have = حجم(rsx->rs_buf) - KEYSZ - IVSZ;
}

ساكن مضمن فراغ
_rs_random_buf(فراغ *_buf, ناپ_t n)
{
	u_char *buf = (u_char *)_buf;
	u_char *keystream;
	ناپ_t m;

	_rs_stir_if_needed(n);
	طالما (n > 0) {
		إذا (rs->rs_have > 0) {
			m = minimum(n, rs->rs_have);
			keystream = rsx->rs_buf + حجم(rsx->rs_buf)
			    - rs->rs_have;
			حافظہ_نقل(buf, keystream, m);
			memset(keystream, 0, m);
			buf += m;
			n -= m;
			rs->rs_have -= m;
		}
		إذا (rs->rs_have == 0)
			_rs_rekey(عدم, 0);
	}
}

ساكن مضمن فراغ
_rs_random_u32(uint32_t *val)
{
	u_char *keystream;

	_rs_stir_if_needed(حجم(*val));
	إذا (rs->rs_have < حجم(*val))
		_rs_rekey(عدم, 0);
	keystream = rsx->rs_buf + حجم(rsx->rs_buf) - rs->rs_have;
	حافظہ_نقل(val, keystream, حجم(*val));
	memset(keystream, 0, حجم(*val));
	rs->rs_have -= حجم(*val);
}

uint32_t
arc4random(فراغ)
{
	uint32_t val;

	ARC4_جندرا();
	_rs_random_u32(&val);
	_ARC4_UNLOCK();
	أرجع val;
}
DEF_WEAK(arc4random);

/*
 * If we are providing arc4random, then we can provide a more efficient
 * arc4random_buf().
 */
# ifndef HAVE_ARC4RANDOM_BUF
فراغ
arc4random_buf(فراغ *buf, ناپ_t n)
{
	ARC4_جندرا();
	_rs_random_buf(buf, n);
	_ARC4_UNLOCK();
}
DEF_WEAK(arc4random_buf);
# endif /* !HAVE_ARC4RANDOM_BUF */
#جے_انت /* !HAVE_ARC4RANDOM */

/* arc4random_buf() that uses platform arc4random() */
#إذا !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM)
فراغ
arc4random_buf(فراغ *_buf, ناپ_t n)
{
	ناپ_t i;
	u_int32_t r = 0;
	حرف *buf = (حرف *)_buf;

	لكل (i = 0; i < n; i++) {
		إذا (i % 4 == 0)
			r = arc4random();
		buf[i] = r & 0xff;
		r >>= 8;
	}
	explicit_bzero(&r, حجم(r));
}
#جے_انت /* !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM) */

