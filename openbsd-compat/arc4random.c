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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/time.h>

#ifndef HAVE_ARC4RANDOM

/*
 * Always use the getentropy implementation from bsd-getentropy.c, which
 * will call a native getentropy if available then fall back as required.
 * We use a different name so that OpenSSL cannot call the wrong getentropy.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା _ssh_compat_getentropy(ଶୂନ୍ୟ *, size_t);
#ifdef getentropy
# undef getentropy
#endif
#define getentropy(x, y) (_ssh_compat_getentropy((x), (y)))

#ଅନ୍ତର୍ଭାଵ "log.h"

#define KEYSTREAM_ONLY
#ଅନ୍ତର୍ଭାଵ "chacha_private.h"

#define minimum(a, b) ((a) < (b) ? (a) : (b))

#ଯଦି defined(__GNUC__) || defined(_MSC_VER)
#define ଧାଡ଼ିଭିତରେ __inline
#ଅନ୍ୟଥା				/* __GNUC__ || _MSC_VER */
#define ଧାଡ଼ିଭିତରେ
#endif				/* !__GNUC__ && !_MSC_VER */

#define KEYSZ	32
#define IVSZ	8
#define BLOCKSZ	64
#define RSBUFSZ	(16*BLOCKSZ)

#define REKEY_BASE	(1024*1024) /* NB. should be a power of 2 */

/* Marked MAP_INHERIT_ZERO, so zero'd out in fork children. */
ସ୍ଥିର ସଂରଚନା _rs {
	size_t		rs_have;	/* valid bytes at end of rs_buf */
	size_t		rs_ଗଣନା;	/* bytes till reseed */
} *rs;

/* Maybe be preserved in fork children, if _rs_allocate() decides. */
ସ୍ଥିର ସଂରଚନା _rsx {
	chacha_ctx	rs_chacha;	/* chacha context for random keystream */
	u_char		rs_buf[RSBUFSZ];	/* keystream blocks */
} *rsx;

ସ୍ଥିର ଧାଡ଼ିଭିତରେ ପୂର୍ଣ୍ଣସଂଖ୍ୟା _rs_allocate(ସଂରଚନା _rs **, ସଂରଚନା _rsx **);
ସ୍ଥିର ଧାଡ଼ିଭିତରେ ଶୂନ୍ୟ _rs_forkdetect(ଶୂନ୍ୟ);
#ଅନ୍ତର୍ଭାଵ "arc4random.h"

ସ୍ଥିର ଧାଡ଼ିଭିତରେ ଶୂନ୍ୟ _rs_rekey(u_char *dat, size_t datlen);

ସ୍ଥିର ଧାଡ଼ିଭିତରେ ଶୂନ୍ୟ
_rs_init(u_char *buf, size_t n)
{
	ଯଦି (n < KEYSZ + IVSZ)
		ଫେରନ୍ତୁ;

	ଯଦି (rs == ଖାଲି) {
		ଯଦି (_rs_allocate(&rs, &rsx) == -1)
			_exit(1);
	}

	chacha_keysetup(&rsx->rs_chacha, buf, KEYSZ * 8);
	chacha_ivsetup(&rsx->rs_chacha, buf + KEYSZ);
}

ସ୍ଥିର ଶୂନ୍ୟ
_rs_stir(ଶୂନ୍ୟ)
{
	u_char rnd[KEYSZ + IVSZ];
	uint32_t rekey_fuzz = 0;

	ଯଦି (getentropy(rnd, ଆକାର rnd) == -1)
		_getentropy_fail();

	ଯଦି (!rs)
		_rs_init(rnd, ଆକାର(rnd));
	ଅନ୍ୟଥା
		_rs_rekey(rnd, ଆକାର(rnd));
	explicit_bzero(rnd, ଆକାର(rnd));	/* discard source seed */

	/* invalidate rs_buf */
	rs->rs_have = 0;
	memset(rsx->rs_buf, 0, ଆକାର(rsx->rs_buf));

	/* rekey interval should not be predictable */
	chacha_encrypt_bytes(&rsx->rs_chacha, (uint8_t *)&rekey_fuzz,
	    (uint8_t *)&rekey_fuzz, ଆକାର(rekey_fuzz));
	rs->rs_ଗଣନା = REKEY_BASE + (rekey_fuzz % REKEY_BASE);
}

ସ୍ଥିର ଧାଡ଼ିଭିତରେ ଶୂନ୍ୟ
_rs_stir_if_needed(size_t len)
{
	_rs_forkdetect();
	ଯଦି (!rs || rs->rs_ଗଣନା <= len)
		_rs_stir();
	ଯଦି (rs->rs_ଗଣନା <= len)
		rs->rs_ଗଣନା = 0;
	ଅନ୍ୟଥା
		rs->rs_ଗଣନା -= len;
}

ସ୍ଥିର ଧାଡ଼ିଭିତରେ ଶୂନ୍ୟ
_rs_rekey(u_char *dat, size_t datlen)
{
#ifndef KEYSTREAM_ONLY
	memset(rsx->rs_buf, 0, ଆକାର(rsx->rs_buf));
#endif
	/* fill rs_buf with the keystream */
	chacha_encrypt_bytes(&rsx->rs_chacha, rsx->rs_buf,
	    rsx->rs_buf, ଆକାର(rsx->rs_buf));
	/* mix in optional user provided data */
	ଯଦି (dat) {
		size_t i, m;

		m = minimum(datlen, KEYSZ + IVSZ);
		ପାଇଁ (i = 0; i < m; i++)
			rsx->rs_buf[i] ^= dat[i];
	}
	/* immediately reinit for backtracking resistance */
	_rs_init(rsx->rs_buf, KEYSZ + IVSZ);
	memset(rsx->rs_buf, 0, KEYSZ + IVSZ);
	rs->rs_have = ଆକାର(rsx->rs_buf) - KEYSZ - IVSZ;
}

ସ୍ଥିର ଧାଡ଼ିଭିତରେ ଶୂନ୍ୟ
_rs_random_buf(ଶୂନ୍ୟ *_buf, size_t n)
{
	u_char *buf = (u_char *)_buf;
	u_char *keystream;
	size_t m;

	_rs_stir_if_needed(n);
	ଯେତେବେଳେ (n > 0) {
		ଯଦି (rs->rs_have > 0) {
			m = minimum(n, rs->rs_have);
			keystream = rsx->rs_buf + ଆକାର(rsx->rs_buf)
			    - rs->rs_have;
			memcpy(buf, keystream, m);
			memset(keystream, 0, m);
			buf += m;
			n -= m;
			rs->rs_have -= m;
		}
		ଯଦି (rs->rs_have == 0)
			_rs_rekey(ଖାଲି, 0);
	}
}

ସ୍ଥିର ଧାଡ଼ିଭିତରେ ଶୂନ୍ୟ
_rs_random_u32(uint32_t *val)
{
	u_char *keystream;

	_rs_stir_if_needed(ଆକାର(*val));
	ଯଦି (rs->rs_have < ଆକାର(*val))
		_rs_rekey(ଖାଲି, 0);
	keystream = rsx->rs_buf + ଆକାର(rsx->rs_buf) - rs->rs_have;
	memcpy(val, keystream, ଆକାର(*val));
	memset(keystream, 0, ଆକାର(*val));
	rs->rs_have -= ଆକାର(*val);
}

uint32_t
arc4random(ଶୂନ୍ୟ)
{
	uint32_t val;

	_ARC4_LOCK();
	_rs_random_u32(&val);
	_ARC4_UNLOCK();
	ଫେରନ୍ତୁ val;
}
DEF_WEAK(arc4random);

/*
 * If we are providing arc4random, then we can provide a more efficient
 * arc4random_buf().
 */
# ifndef HAVE_ARC4RANDOM_BUF
ଶୂନ୍ୟ
arc4random_buf(ଶୂନ୍ୟ *buf, size_t n)
{
	_ARC4_LOCK();
	_rs_random_buf(buf, n);
	_ARC4_UNLOCK();
}
DEF_WEAK(arc4random_buf);
# endif /* !HAVE_ARC4RANDOM_BUF */
#endif /* !HAVE_ARC4RANDOM */

/* arc4random_buf() that uses platform arc4random() */
#ଯଦି !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM)
ଶୂନ୍ୟ
arc4random_buf(ଶୂନ୍ୟ *_buf, size_t n)
{
	size_t i;
	u_int32_t r = 0;
	ଅକ୍ଷର *buf = (ଅକ୍ଷର *)_buf;

	ପାଇଁ (i = 0; i < n; i++) {
		ଯଦି (i % 4 == 0)
			r = arc4random();
		buf[i] = r & 0xff;
		r >>= 8;
	}
	explicit_bzero(&r, ଆକାର(r));
}
#endif /* !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM) */

