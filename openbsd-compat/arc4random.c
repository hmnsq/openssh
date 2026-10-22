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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/time.h>

#ifndef HAVE_ARC4RANDOM

/*
 * Always use the getentropy implementation from bsd-getentropy.c, which
 * will call a native getentropy if available then fall back as required.
 * We use a different name so that OpenSSL cannot call the wrong getentropy.
 */
முழு _ssh_compat_getentropy(வெறுமை *, size_t);
#ifdef getentropy
# undef getentropy
#endif
#define getentropy(x, y) (_ssh_compat_getentropy((x), (y)))

#அந்தர்பாவ "log.h"

#define KEYSTREAM_ONLY
#அந்தர்பாவ "chacha_private.h"

#define minimum(a, b) ((a) < (b) ? (a) : (b))

#எனில் defined(__GNUC__) || defined(_MSC_VER)
#define உள்வரி __inline
#இல்லையெனில்				/* __GNUC__ || _MSC_VER */
#define உள்வரி
#endif				/* !__GNUC__ && !_MSC_VER */

#define KEYSZ	32
#define IVSZ	8
#define BLOCKSZ	64
#define RSBUFSZ	(16*BLOCKSZ)

#define REKEY_BASE	(1024*1024) /* NB. should be a power of 2 */

/* Marked MAP_INHERIT_ZERO, so zero'd out in fork children. */
நிலையான கட்டமைப்பு _rs {
	size_t		rs_have;	/* valid bytes at end of rs_buf */
	size_t		rs_மொத்தம்;	/* bytes till reseed */
} *rs;

/* Maybe be preserved in fork children, if _rs_allocate() decides. */
நிலையான கட்டமைப்பு _rsx {
	chacha_ctx	rs_chacha;	/* chacha context for random keystream */
	u_char		rs_buf[RSBUFSZ];	/* keystream blocks */
} *rsx;

நிலையான உள்வரி முழு _rs_allocate(கட்டமைப்பு _rs **, கட்டமைப்பு _rsx **);
நிலையான உள்வரி வெறுமை _rs_forkdetect(வெறுமை);
#அந்தர்பாவ "arc4random.h"

நிலையான உள்வரி வெறுமை _rs_rekey(u_char *dat, size_t datlen);

நிலையான உள்வரி வெறுமை
_rs_init(u_char *buf, size_t n)
{
	எனில் (n < KEYSZ + IVSZ)
		திரும்பு;

	எனில் (rs == வெற்று) {
		எனில் (_rs_allocate(&rs, &rsx) == -1)
			_exit(1);
	}

	chacha_keysetup(&rsx->rs_chacha, buf, KEYSZ * 8);
	chacha_ivsetup(&rsx->rs_chacha, buf + KEYSZ);
}

நிலையான வெறுமை
_rs_stir(வெறுமை)
{
	u_char rnd[KEYSZ + IVSZ];
	uint32_t rekey_fuzz = 0;

	எனில் (getentropy(rnd, அளவு rnd) == -1)
		_getentropy_fail();

	எனில் (!rs)
		_rs_init(rnd, அளவு(rnd));
	இல்லையெனில்
		_rs_rekey(rnd, அளவு(rnd));
	explicit_bzero(rnd, அளவு(rnd));	/* discard source seed */

	/* invalidate rs_buf */
	rs->rs_have = 0;
	memset(rsx->rs_buf, 0, அளவு(rsx->rs_buf));

	/* rekey interval should not be predictable */
	chacha_encrypt_bytes(&rsx->rs_chacha, (uint8_t *)&rekey_fuzz,
	    (uint8_t *)&rekey_fuzz, அளவு(rekey_fuzz));
	rs->rs_மொத்தம் = REKEY_BASE + (rekey_fuzz % REKEY_BASE);
}

நிலையான உள்வரி வெறுமை
_rs_stir_if_needed(size_t len)
{
	_rs_forkdetect();
	எனில் (!rs || rs->rs_மொத்தம் <= len)
		_rs_stir();
	எனில் (rs->rs_மொத்தம் <= len)
		rs->rs_மொத்தம் = 0;
	இல்லையெனில்
		rs->rs_மொத்தம் -= len;
}

நிலையான உள்வரி வெறுமை
_rs_rekey(u_char *dat, size_t datlen)
{
#ifndef KEYSTREAM_ONLY
	memset(rsx->rs_buf, 0, அளவு(rsx->rs_buf));
#endif
	/* fill rs_buf with the keystream */
	chacha_encrypt_bytes(&rsx->rs_chacha, rsx->rs_buf,
	    rsx->rs_buf, அளவு(rsx->rs_buf));
	/* mix in optional user provided data */
	எனில் (dat) {
		size_t i, m;

		m = minimum(datlen, KEYSZ + IVSZ);
		க்கு (i = 0; i < m; i++)
			rsx->rs_buf[i] ^= dat[i];
	}
	/* immediately reinit for backtracking resistance */
	_rs_init(rsx->rs_buf, KEYSZ + IVSZ);
	memset(rsx->rs_buf, 0, KEYSZ + IVSZ);
	rs->rs_have = அளவு(rsx->rs_buf) - KEYSZ - IVSZ;
}

நிலையான உள்வரி வெறுமை
_rs_random_buf(வெறுமை *_buf, size_t n)
{
	u_char *buf = (u_char *)_buf;
	u_char *keystream;
	size_t m;

	_rs_stir_if_needed(n);
	போது (n > 0) {
		எனில் (rs->rs_have > 0) {
			m = minimum(n, rs->rs_have);
			keystream = rsx->rs_buf + அளவு(rsx->rs_buf)
			    - rs->rs_have;
			memcpy(buf, keystream, m);
			memset(keystream, 0, m);
			buf += m;
			n -= m;
			rs->rs_have -= m;
		}
		எனில் (rs->rs_have == 0)
			_rs_rekey(வெற்று, 0);
	}
}

நிலையான உள்வரி வெறுமை
_rs_random_u32(uint32_t *val)
{
	u_char *keystream;

	_rs_stir_if_needed(அளவு(*val));
	எனில் (rs->rs_have < அளவு(*val))
		_rs_rekey(வெற்று, 0);
	keystream = rsx->rs_buf + அளவு(rsx->rs_buf) - rs->rs_have;
	memcpy(val, keystream, அளவு(*val));
	memset(keystream, 0, அளவு(*val));
	rs->rs_have -= அளவு(*val);
}

uint32_t
arc4random(வெறுமை)
{
	uint32_t val;

	_ARC4_LOCK();
	_rs_random_u32(&val);
	_ARC4_UNLOCK();
	திரும்பு val;
}
DEF_WEAK(arc4random);

/*
 * If we are providing arc4random, then we can provide a more efficient
 * arc4random_buf().
 */
# ifndef HAVE_ARC4RANDOM_BUF
வெறுமை
arc4random_buf(வெறுமை *buf, size_t n)
{
	_ARC4_LOCK();
	_rs_random_buf(buf, n);
	_ARC4_UNLOCK();
}
DEF_WEAK(arc4random_buf);
# endif /* !HAVE_ARC4RANDOM_BUF */
#endif /* !HAVE_ARC4RANDOM */

/* arc4random_buf() that uses platform arc4random() */
#எனில் !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM)
வெறுமை
arc4random_buf(வெறுமை *_buf, size_t n)
{
	size_t i;
	u_int32_t r = 0;
	எழுத்து *buf = (எழுத்து *)_buf;

	க்கு (i = 0; i < n; i++) {
		எனில் (i % 4 == 0)
			r = arc4random();
		buf[i] = r & 0xff;
		r >>= 8;
	}
	explicit_bzero(&r, அளவு(r));
}
#endif /* !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM) */

