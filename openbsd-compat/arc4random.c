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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/time.h>

#ifndef HAVE_ARC4RANDOM

/*
 * Always use the getentropy implementation from bsd-getentropy.c, which
 * will call a native getentropy if available then fall back as required.
 * We use a different name so that OpenSSL cannot call the wrong getentropy.
 */
পূর্ণসংখ্যা _ssh_compat_getentropy(শূন্য *, আকার_t);
#ifdef getentropy
# undef getentropy
#endif
#define getentropy(x, y) (_ssh_compat_getentropy((x), (y)))

#অন্তর্ভাব "log.h"

#define KEYSTREAM_ONLY
#অন্তর্ভাব "chacha_private.h"

#define minimum(a, b) ((a) < (b) ? (a) : (b))

#যদি defined(__GNUC__) || defined(_MSC_VER)
#define অন্তঃরেখ __inline
#অন্যথা				/* __GNUC__ || _MSC_VER */
#define অন্তঃরেখ
#endif				/* !__GNUC__ && !_MSC_VER */

#define KEYSZ	32
#define IVSZ	8
#define BLOCKSZ	64
#define RSBUFSZ	(16*BLOCKSZ)

#define REKEY_BASE	(1024*1024) /* NB. should be a power of 2 */

/* Marked MAP_INHERIT_ZERO, so zero'd out in fork children. */
স্থির কাঠামো _rs {
	আকার_t		rs_have;	/* valid bytes at end of rs_buf */
	আকার_t		rs_গুনতি;	/* bytes till reseed */
} *rs;

/* Maybe be preserved in fork children, if _rs_allocate() decides. */
স্থির কাঠামো _rsx {
	chacha_ctx	rs_chacha;	/* chacha context for random keystream */
	u_char		rs_buf[RSBUFSZ];	/* keystream blocks */
} *rsx;

স্থির অন্তঃরেখ পূর্ণসংখ্যা _rs_allocate(কাঠামো _rs **, কাঠামো _rsx **);
স্থির অন্তঃরেখ শূন্য _rs_forkdetect(শূন্য);
#অন্তর্ভাব "arc4random.h"

স্থির অন্তঃরেখ শূন্য _rs_rekey(u_char *dat, আকার_t datlen);

স্থির অন্তঃরেখ শূন্য
_rs_init(u_char *buf, আকার_t n)
{
	যদি (n < KEYSZ + IVSZ)
		ফেরত;

	যদি (rs == ফাঁকা) {
		যদি (_rs_allocate(&rs, &rsx) == -1)
			_exit(1);
	}

	chacha_keysetup(&rsx->rs_chacha, buf, KEYSZ * 8);
	chacha_ivsetup(&rsx->rs_chacha, buf + KEYSZ);
}

স্থির শূন্য
_rs_stir(শূন্য)
{
	u_char rnd[KEYSZ + IVSZ];
	uint32_t rekey_fuzz = 0;

	যদি (getentropy(rnd, আকার rnd) == -1)
		_getentropy_fail();

	যদি (!rs)
		_rs_init(rnd, আকার(rnd));
	অন্যথা
		_rs_rekey(rnd, আকার(rnd));
	explicit_bzero(rnd, আকার(rnd));	/* discard source seed */

	/* invalidate rs_buf */
	rs->rs_have = 0;
	memset(rsx->rs_buf, 0, আকার(rsx->rs_buf));

	/* rekey interval should not be predictable */
	chacha_encrypt_bytes(&rsx->rs_chacha, (uint8_t *)&rekey_fuzz,
	    (uint8_t *)&rekey_fuzz, আকার(rekey_fuzz));
	rs->rs_গুনতি = REKEY_BASE + (rekey_fuzz % REKEY_BASE);
}

স্থির অন্তঃরেখ শূন্য
_rs_stir_if_needed(আকার_t len)
{
	_rs_forkdetect();
	যদি (!rs || rs->rs_গুনতি <= len)
		_rs_stir();
	যদি (rs->rs_গুনতি <= len)
		rs->rs_গুনতি = 0;
	অন্যথা
		rs->rs_গুনতি -= len;
}

স্থির অন্তঃরেখ শূন্য
_rs_rekey(u_char *dat, আকার_t datlen)
{
#ifndef KEYSTREAM_ONLY
	memset(rsx->rs_buf, 0, আকার(rsx->rs_buf));
#endif
	/* fill rs_buf with the keystream */
	chacha_encrypt_bytes(&rsx->rs_chacha, rsx->rs_buf,
	    rsx->rs_buf, আকার(rsx->rs_buf));
	/* mix in optional user provided data */
	যদি (dat) {
		আকার_t i, m;

		m = minimum(datlen, KEYSZ + IVSZ);
		জন্য (i = 0; i < m; i++)
			rsx->rs_buf[i] ^= dat[i];
	}
	/* immediately reinit for backtracking resistance */
	_rs_init(rsx->rs_buf, KEYSZ + IVSZ);
	memset(rsx->rs_buf, 0, KEYSZ + IVSZ);
	rs->rs_have = আকার(rsx->rs_buf) - KEYSZ - IVSZ;
}

স্থির অন্তঃরেখ শূন্য
_rs_random_buf(শূন্য *_buf, আকার_t n)
{
	u_char *buf = (u_char *)_buf;
	u_char *keystream;
	আকার_t m;

	_rs_stir_if_needed(n);
	যখন (n > 0) {
		যদি (rs->rs_have > 0) {
			m = minimum(n, rs->rs_have);
			keystream = rsx->rs_buf + আকার(rsx->rs_buf)
			    - rs->rs_have;
			memcpy(buf, keystream, m);
			memset(keystream, 0, m);
			buf += m;
			n -= m;
			rs->rs_have -= m;
		}
		যদি (rs->rs_have == 0)
			_rs_rekey(ফাঁকা, 0);
	}
}

স্থির অন্তঃরেখ শূন্য
_rs_random_u32(uint32_t *val)
{
	u_char *keystream;

	_rs_stir_if_needed(আকার(*val));
	যদি (rs->rs_have < আকার(*val))
		_rs_rekey(ফাঁকা, 0);
	keystream = rsx->rs_buf + আকার(rsx->rs_buf) - rs->rs_have;
	memcpy(val, keystream, আকার(*val));
	memset(keystream, 0, আকার(*val));
	rs->rs_have -= আকার(*val);
}

uint32_t
arc4random(শূন্য)
{
	uint32_t val;

	_ARC4_LOCK();
	_rs_random_u32(&val);
	_ARC4_UNLOCK();
	ফেরত val;
}
DEF_WEAK(arc4random);

/*
 * If we are providing arc4random, then we can provide a more efficient
 * arc4random_buf().
 */
# ifndef HAVE_ARC4RANDOM_BUF
শূন্য
arc4random_buf(শূন্য *buf, আকার_t n)
{
	_ARC4_LOCK();
	_rs_random_buf(buf, n);
	_ARC4_UNLOCK();
}
DEF_WEAK(arc4random_buf);
# endif /* !HAVE_ARC4RANDOM_BUF */
#endif /* !HAVE_ARC4RANDOM */

/* arc4random_buf() that uses platform arc4random() */
#যদি !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM)
শূন্য
arc4random_buf(শূন্য *_buf, আকার_t n)
{
	আকার_t i;
	u_int32_t r = 0;
	অক্ষর *buf = (অক্ষর *)_buf;

	জন্য (i = 0; i < n; i++) {
		যদি (i % 4 == 0)
			r = arc4random();
		buf[i] = r & 0xff;
		r >>= 8;
	}
	explicit_bzero(&r, আকার(r));
}
#endif /* !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM) */

