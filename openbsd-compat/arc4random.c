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

#ifndef HAVE_ARC4RANDOM

/*
 * Always use the getentropy implementation from bsd-getentropy.c, which
 * will call a native getentropy if available then fall back as required.
 * We use a different name so that OpenSSL cannot call the wrong getentropy.
 */
صحیح _ssh_compat_getentropy(تهی *, size_t);
#ifdef getentropy
# undef getentropy
#endif
#define getentropy(x, y) (_ssh_compat_getentropy((x), (y)))

#شامل "log.h"

#define KEYSTREAM_ONLY
#شامل "chacha_private.h"

#define minimum(a, b) ((a) < (b) ? (a) : (b))

#اگر defined(__GNUC__) || defined(_MSC_VER)
#define درونخطی __inline
#وگرنه				/* __GNUC__ || _MSC_VER */
#define درونخطی
#endif				/* !__GNUC__ && !_MSC_VER */

#define KEYSZ	32
#define IVSZ	8
#define BLOCKSZ	64
#define RSBUFSZ	(16*BLOCKSZ)

#define REKEY_BASE	(1024*1024) /* NB. should be a power of 2 */

/* Marked MAP_INHERIT_ZERO, so zero'd out in fork children. */
ایستا ساختار _rs {
	size_t		rs_have;	/* valid bytes at end of rs_buf */
	size_t		rs_شمار;	/* bytes till reseed */
} *rs;

/* Maybe be preserved in fork children, if _rs_allocate() decides. */
ایستا ساختار _rsx {
	chacha_ctx	rs_chacha;	/* chacha context for random keystream */
	u_char		rs_buf[RSBUFSZ];	/* keystream blocks */
} *rsx;

ایستا درونخطی صحیح _rs_allocate(ساختار _rs **, ساختار _rsx **);
ایستا درونخطی تهی _rs_forkdetect(تهی);
#شامل "arc4random.h"

ایستا درونخطی تهی _rs_rekey(u_char *dat, size_t datlen);

ایستا درونخطی تهی
_rs_init(u_char *buf, size_t n)
{
	اگر (n < KEYSZ + IVSZ)
		بازگشت;

	اگر (rs == پوچ) {
		اگر (_rs_allocate(&rs, &rsx) == -1)
			_exit(1);
	}

	chacha_keysetup(&rsx->rs_chacha, buf, KEYSZ * 8);
	chacha_ivsetup(&rsx->rs_chacha, buf + KEYSZ);
}

ایستا تهی
_rs_stir(تهی)
{
	u_char rnd[KEYSZ + IVSZ];
	uint32_t rekey_fuzz = 0;

	اگر (getentropy(rnd, اندازه rnd) == -1)
		_getentropy_fail();

	اگر (!rs)
		_rs_init(rnd, اندازه(rnd));
	وگرنه
		_rs_rekey(rnd, اندازه(rnd));
	explicit_bzero(rnd, اندازه(rnd));	/* discard source seed */

	/* invalidate rs_buf */
	rs->rs_have = 0;
	memset(rsx->rs_buf, 0, اندازه(rsx->rs_buf));

	/* rekey interval should not be predictable */
	chacha_encrypt_bytes(&rsx->rs_chacha, (uint8_t *)&rekey_fuzz,
	    (uint8_t *)&rekey_fuzz, اندازه(rekey_fuzz));
	rs->rs_شمار = REKEY_BASE + (rekey_fuzz % REKEY_BASE);
}

ایستا درونخطی تهی
_rs_stir_if_needed(size_t len)
{
	_rs_forkdetect();
	اگر (!rs || rs->rs_شمار <= len)
		_rs_stir();
	اگر (rs->rs_شمار <= len)
		rs->rs_شمار = 0;
	وگرنه
		rs->rs_شمار -= len;
}

ایستا درونخطی تهی
_rs_rekey(u_char *dat, size_t datlen)
{
#ifndef KEYSTREAM_ONLY
	memset(rsx->rs_buf, 0, اندازه(rsx->rs_buf));
#endif
	/* fill rs_buf with the keystream */
	chacha_encrypt_bytes(&rsx->rs_chacha, rsx->rs_buf,
	    rsx->rs_buf, اندازه(rsx->rs_buf));
	/* mix in optional user provided data */
	اگر (dat) {
		size_t i, m;

		m = minimum(datlen, KEYSZ + IVSZ);
		برای (i = 0; i < m; i++)
			rsx->rs_buf[i] ^= dat[i];
	}
	/* immediately reinit for backtracking resistance */
	_rs_init(rsx->rs_buf, KEYSZ + IVSZ);
	memset(rsx->rs_buf, 0, KEYSZ + IVSZ);
	rs->rs_have = اندازه(rsx->rs_buf) - KEYSZ - IVSZ;
}

ایستا درونخطی تهی
_rs_random_buf(تهی *_buf, size_t n)
{
	u_char *buf = (u_char *)_buf;
	u_char *keystream;
	size_t m;

	_rs_stir_if_needed(n);
	وقتی (n > 0) {
		اگر (rs->rs_have > 0) {
			m = minimum(n, rs->rs_have);
			keystream = rsx->rs_buf + اندازه(rsx->rs_buf)
			    - rs->rs_have;
			memcpy(buf, keystream, m);
			memset(keystream, 0, m);
			buf += m;
			n -= m;
			rs->rs_have -= m;
		}
		اگر (rs->rs_have == 0)
			_rs_rekey(پوچ, 0);
	}
}

ایستا درونخطی تهی
_rs_random_u32(uint32_t *val)
{
	u_char *keystream;

	_rs_stir_if_needed(اندازه(*val));
	اگر (rs->rs_have < اندازه(*val))
		_rs_rekey(پوچ, 0);
	keystream = rsx->rs_buf + اندازه(rsx->rs_buf) - rs->rs_have;
	memcpy(val, keystream, اندازه(*val));
	memset(keystream, 0, اندازه(*val));
	rs->rs_have -= اندازه(*val);
}

uint32_t
arc4random(تهی)
{
	uint32_t val;

	_ARC4_LOCK();
	_rs_random_u32(&val);
	_ARC4_UNLOCK();
	بازگشت val;
}
DEF_WEAK(arc4random);

/*
 * If we are providing arc4random, then we can provide a more efficient
 * arc4random_buf().
 */
# ifndef HAVE_ARC4RANDOM_BUF
تهی
arc4random_buf(تهی *buf, size_t n)
{
	_ARC4_LOCK();
	_rs_random_buf(buf, n);
	_ARC4_UNLOCK();
}
DEF_WEAK(arc4random_buf);
# endif /* !HAVE_ARC4RANDOM_BUF */
#endif /* !HAVE_ARC4RANDOM */

/* arc4random_buf() that uses platform arc4random() */
#اگر !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM)
تهی
arc4random_buf(تهی *_buf, size_t n)
{
	size_t i;
	u_int32_t r = 0;
	نویسه *buf = (نویسه *)_buf;

	برای (i = 0; i < n; i++) {
		اگر (i % 4 == 0)
			r = arc4random();
		buf[i] = r & 0xff;
		r >>= 8;
	}
	explicit_bzero(&r, اندازه(r));
}
#endif /* !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM) */

