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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/time.h>

#నిర్వచితం_కాకపోతే HAVE_ARC4RANDOM

/*
 * Always use the getentropy implementation from bsd-getentropy.c, which
 * will call a native getentropy if available then fall back as required.
 * We use a different name so that OpenSSL cannot call the wrong getentropy.
 */
పూర్ణాంకం _ssh_compat_getentropy(శూన్య *, కొలత_t);
#నిర్వచితమైతే getentropy
# undef getentropy
#అయితే_ముగింపు
#నిర్వచించు getentropy(x, y) (_ssh_compat_getentropy((x), (y)))

#అన్తర్భావ "log.h"

#నిర్వచించు KEYSTREAM_ONLY
#అన్తర్భావ "chacha_private.h"

#నిర్వచించు minimum(a, b) ((a) < (b) ? (a) : (b))

#ఒకవేళ defined(__GNUC__) || defined(_MSC_VER)
#నిర్వచించు అంతఃవరుస __inline
#లేకపోతే				/* __GNUC__ || _MSC_VER */
#నిర్వచించు అంతఃవరుస
#అయితే_ముగింపు				/* !__GNUC__ && !_MSC_VER */

#నిర్వచించు KEYSZ	32
#నిర్వచించు IVSZ	8
#నిర్వచించు BLOCKSZ	64
#నిర్వచించు RSBUFSZ	(16*BLOCKSZ)

#నిర్వచించు REKEY_పునాది	(1024*1024) /* NB. should be a power of 2 */

/* Marked MAP_INHERIT_ZERO, so zero'd out in fork children. */
స్థిర నిర్మాణం _rs {
	కొలత_t		rs_have;	/* valid bytes at end of rs_buf */
	కొలత_t		rs_లెక్క;	/* bytes till reseed */
} *rs;

/* Maybe be preserved in fork children, if _rs_allocate() decides. */
స్థిర నిర్మాణం _rsx {
	chacha_ctx	rs_chacha;	/* chacha context for random keystream */
	u_char		rs_buf[RSBUFSZ];	/* keystream blocks */
} *rsx;

స్థిర అంతఃవరుస పూర్ణాంకం _rs_allocate(నిర్మాణం _rs **, నిర్మాణం _rsx **);
స్థిర అంతఃవరుస శూన్య _rs_forkdetect(శూన్య);
#అన్తర్భావ "arc4random.h"

స్థిర అంతఃవరుస శూన్య _rs_rekey(u_char *dat, కొలత_t datlen);

స్థిర అంతఃవరుస శూన్య
_rs_init(u_char *buf, కొలత_t n)
{
	ఒకవేళ (n < KEYSZ + IVSZ)
		తిరిగి;

	ఒకవేళ (rs == ఖాళీ) {
		ఒకవేళ (_rs_allocate(&rs, &rsx) == -1)
			_exit(1);
	}

	chacha_keysetup(&rsx->rs_chacha, buf, KEYSZ * 8);
	chacha_ivsetup(&rsx->rs_chacha, buf + KEYSZ);
}

స్థిర శూన్య
_rs_stir(శూన్య)
{
	u_char rnd[KEYSZ + IVSZ];
	uint32_t rekey_fuzz = 0;

	ఒకవేళ (getentropy(rnd, పరిమాణం rnd) == -1)
		_getentropy_fail();

	ఒకవేళ (!rs)
		_rs_init(rnd, పరిమాణం(rnd));
	లేకపోతే
		_rs_rekey(rnd, పరిమాణం(rnd));
	explicit_bzero(rnd, పరిమాణం(rnd));	/* discard source seed */

	/* invalidate rs_buf */
	rs->rs_have = 0;
	memset(rsx->rs_buf, 0, పరిమాణం(rsx->rs_buf));

	/* rekey interval should not be predictable */
	chacha_encrypt_బైట్లు(&rsx->rs_chacha, (uint8_t *)&rekey_fuzz,
	    (uint8_t *)&rekey_fuzz, పరిమాణం(rekey_fuzz));
	rs->rs_లెక్క = REKEY_పునాది + (rekey_fuzz % REKEY_పునాది);
}

స్థిర అంతఃవరుస శూన్య
_rs_stir_if_needed(కొలత_t len)
{
	_rs_forkdetect();
	ఒకవేళ (!rs || rs->rs_లెక్క <= len)
		_rs_stir();
	ఒకవేళ (rs->rs_లెక్క <= len)
		rs->rs_లెక్క = 0;
	లేకపోతే
		rs->rs_లెక్క -= len;
}

స్థిర అంతఃవరుస శూన్య
_rs_rekey(u_char *dat, కొలత_t datlen)
{
#నిర్వచితం_కాకపోతే KEYSTREAM_ONLY
	memset(rsx->rs_buf, 0, పరిమాణం(rsx->rs_buf));
#అయితే_ముగింపు
	/* fill rs_buf with the keystream */
	chacha_encrypt_బైట్లు(&rsx->rs_chacha, rsx->rs_buf,
	    rsx->rs_buf, పరిమాణం(rsx->rs_buf));
	/* mix in optional user provided data */
	ఒకవేళ (dat) {
		కొలత_t i, m;

		m = minimum(datlen, KEYSZ + IVSZ);
		కొరకు (i = 0; i < m; i++)
			rsx->rs_buf[i] ^= dat[i];
	}
	/* immediately reinit for backtracking resistance */
	_rs_init(rsx->rs_buf, KEYSZ + IVSZ);
	memset(rsx->rs_buf, 0, KEYSZ + IVSZ);
	rs->rs_have = పరిమాణం(rsx->rs_buf) - KEYSZ - IVSZ;
}

స్థిర అంతఃవరుస శూన్య
_rs_random_buf(శూన్య *_buf, కొలత_t n)
{
	u_char *buf = (u_char *)_buf;
	u_char *keystream;
	కొలత_t m;

	_rs_stir_if_needed(n);
	అయితే (n > 0) {
		ఒకవేళ (rs->rs_have > 0) {
			m = minimum(n, rs->rs_have);
			keystream = rsx->rs_buf + పరిమాణం(rsx->rs_buf)
			    - rs->rs_have;
			జ్ఞాపకం_నకలు(buf, keystream, m);
			memset(keystream, 0, m);
			buf += m;
			n -= m;
			rs->rs_have -= m;
		}
		ఒకవేళ (rs->rs_have == 0)
			_rs_rekey(ఖాళీ, 0);
	}
}

స్థిర అంతఃవరుస శూన్య
_rs_random_u32(uint32_t *val)
{
	u_char *keystream;

	_rs_stir_if_needed(పరిమాణం(*val));
	ఒకవేళ (rs->rs_have < పరిమాణం(*val))
		_rs_rekey(ఖాళీ, 0);
	keystream = rsx->rs_buf + పరిమాణం(rsx->rs_buf) - rs->rs_have;
	జ్ఞాపకం_నకలు(val, keystream, పరిమాణం(*val));
	memset(keystream, 0, పరిమాణం(*val));
	rs->rs_have -= పరిమాణం(*val);
}

uint32_t
arc4random(శూన్య)
{
	uint32_t val;

	ARC4_తాళం();
	_rs_random_u32(&val);
	_ARC4_UNLOCK();
	తిరిగి val;
}
DEF_WEAK(arc4random);

/*
 * If we are providing arc4random, then we can provide a more efficient
 * arc4random_buf().
 */
# ifndef HAVE_ARC4RANDOM_BUF
శూన్య
arc4random_buf(శూన్య *buf, కొలత_t n)
{
	ARC4_తాళం();
	_rs_random_buf(buf, n);
	_ARC4_UNLOCK();
}
DEF_WEAK(arc4random_buf);
# endif /* !HAVE_ARC4RANDOM_BUF */
#అయితే_ముగింపు /* !HAVE_ARC4RANDOM */

/* arc4random_buf() that uses platform arc4random() */
#ఒకవేళ !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM)
శూన్య
arc4random_buf(శూన్య *_buf, కొలత_t n)
{
	కొలత_t i;
	u_int32_t r = 0;
	అక్షరం *buf = (అక్షరం *)_buf;

	కొరకు (i = 0; i < n; i++) {
		ఒకవేళ (i % 4 == 0)
			r = arc4random();
		buf[i] = r & 0xff;
		r >>= 8;
	}
	explicit_bzero(&r, పరిమాణం(r));
}
#అయితే_ముగింపు /* !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM) */

