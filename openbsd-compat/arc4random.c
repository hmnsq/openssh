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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/time.h>

#यदि_अपरिभाषितम् HAVE_ARC4RANDOM

/*
 * Always use the getentropy implementation from bsd-getentropy.c, which
 * will call a native getentropy if available then fall back as required.
 * We use a different name so that OpenSSL cannot call the wrong getentropy.
 */
पूर्णाङ्क _ssh_compat_getentropy(शून्य *, आकार_t);
#यदि_परिभाषितम् getentropy
# undef getentropy
#यदि_अन्तः
#परिभाषय getentropy(x, y) (_ssh_compat_getentropy((x), (y)))

#अन्तर्भाव "log.h"

#परिभाषय KEYSTREAM_ONLY
#अन्तर्भाव "chacha_private.h"

#परिभाषय minimum(a, b) ((a) < (b) ? (a) : (b))

#यदि defined(__GNUC__) || defined(_MSC_VER)
#परिभाषय अन्तःस्थ __inline
#अन्यथा				/* __GNUC__ || _MSC_VER */
#परिभाषय अन्तःस्थ
#यदि_अन्तः				/* !__GNUC__ && !_MSC_VER */

#परिभाषय KEYSZ	32
#परिभाषय IVSZ	8
#परिभाषय BLOCKSZ	64
#परिभाषय RSBUFSZ	(16*BLOCKSZ)

#परिभाषय REKEY_आधारः	(1024*1024) /* NB. should be a power of 2 */

/* Marked MAP_INHERIT_ZERO, so zero'd out in fork children. */
स्थिर संरचना _rs {
	आकार_t		rs_have;	/* valid bytes at end of rs_buf */
	आकार_t		rs_गणनम्;	/* bytes till reseed */
} *rs;

/* Maybe be preserved in fork children, if _rs_allocate() decides. */
स्थिर संरचना _rsx {
	chacha_ctx	rs_chacha;	/* chacha context for random keystream */
	u_char		rs_buf[RSBUFSZ];	/* keystream blocks */
} *rsx;

स्थिर अन्तःस्थ पूर्णाङ्क _rs_allocate(संरचना _rs **, संरचना _rsx **);
स्थिर अन्तःस्थ शून्य _rs_forkdetect(शून्य);
#अन्तर्भाव "arc4random.h"

स्थिर अन्तःस्थ शून्य _rs_rekey(u_char *dat, आकार_t datlen);

स्थिर अन्तःस्थ शून्य
_rs_init(u_char *buf, आकार_t n)
{
	यदि (n < KEYSZ + IVSZ)
		प्रत्यागम;

	यदि (rs == रिक्त) {
		यदि (_rs_allocate(&rs, &rsx) == -1)
			_exit(1);
	}

	chacha_keysetup(&rsx->rs_chacha, buf, KEYSZ * 8);
	chacha_ivsetup(&rsx->rs_chacha, buf + KEYSZ);
}

स्थिर शून्य
_rs_stir(शून्य)
{
	u_char rnd[KEYSZ + IVSZ];
	uint32_t rekey_fuzz = 0;

	यदि (getentropy(rnd, परिमाण rnd) == -1)
		_getentropy_fail();

	यदि (!rs)
		_rs_init(rnd, परिमाण(rnd));
	अन्यथा
		_rs_rekey(rnd, परिमाण(rnd));
	explicit_bzero(rnd, परिमाण(rnd));	/* discard source seed */

	/* invalidate rs_buf */
	rs->rs_have = 0;
	स्मृतिं_पूरय(rsx->rs_buf, 0, परिमाण(rsx->rs_buf));

	/* rekey interval should not be predictable */
	chacha_encrypt_अष्टकानि(&rsx->rs_chacha, (uint8_t *)&rekey_fuzz,
	    (uint8_t *)&rekey_fuzz, परिमाण(rekey_fuzz));
	rs->rs_गणनम् = REKEY_आधारः + (rekey_fuzz % REKEY_आधारः);
}

स्थिर अन्तःस्थ शून्य
_rs_stir_if_needed(आकार_t len)
{
	_rs_forkdetect();
	यदि (!rs || rs->rs_गणनम् <= len)
		_rs_stir();
	यदि (rs->rs_गणनम् <= len)
		rs->rs_गणनम् = 0;
	अन्यथा
		rs->rs_गणनम् -= len;
}

स्थिर अन्तःस्थ शून्य
_rs_rekey(u_char *dat, आकार_t datlen)
{
#यदि_अपरिभाषितम् KEYSTREAM_ONLY
	स्मृतिं_पूरय(rsx->rs_buf, 0, परिमाण(rsx->rs_buf));
#यदि_अन्तः
	/* fill rs_buf with the keystream */
	chacha_encrypt_अष्टकानि(&rsx->rs_chacha, rsx->rs_buf,
	    rsx->rs_buf, परिमाण(rsx->rs_buf));
	/* mix in optional user provided data */
	यदि (dat) {
		आकार_t i, m;

		m = minimum(datlen, KEYSZ + IVSZ);
		प्रति (i = 0; i < m; i++)
			rsx->rs_buf[i] ^= dat[i];
	}
	/* immediately reinit for backtracking resistance */
	_rs_init(rsx->rs_buf, KEYSZ + IVSZ);
	स्मृतिं_पूरय(rsx->rs_buf, 0, KEYSZ + IVSZ);
	rs->rs_have = परिमाण(rsx->rs_buf) - KEYSZ - IVSZ;
}

स्थिर अन्तःस्थ शून्य
_rs_random_buf(शून्य *_buf, आकार_t n)
{
	u_char *buf = (u_char *)_buf;
	u_char *keystream;
	आकार_t m;

	_rs_stir_if_needed(n);
	यावत् (n > 0) {
		यदि (rs->rs_have > 0) {
			m = minimum(n, rs->rs_have);
			keystream = rsx->rs_buf + परिमाण(rsx->rs_buf)
			    - rs->rs_have;
			स्मृतिं_प्रतिलिख(buf, keystream, m);
			स्मृतिं_पूरय(keystream, 0, m);
			buf += m;
			n -= m;
			rs->rs_have -= m;
		}
		यदि (rs->rs_have == 0)
			_rs_rekey(रिक्त, 0);
	}
}

स्थिर अन्तःस्थ शून्य
_rs_random_u32(uint32_t *val)
{
	u_char *keystream;

	_rs_stir_if_needed(परिमाण(*val));
	यदि (rs->rs_have < परिमाण(*val))
		_rs_rekey(रिक्त, 0);
	keystream = rsx->rs_buf + परिमाण(rsx->rs_buf) - rs->rs_have;
	स्मृतिं_प्रतिलिख(val, keystream, परिमाण(*val));
	स्मृतिं_पूरय(keystream, 0, परिमाण(*val));
	rs->rs_have -= परिमाण(*val);
}

uint32_t
arc4random(शून्य)
{
	uint32_t val;

	ARC4_तालकम्();
	_rs_random_u32(&val);
	_ARC4_UNLOCK();
	प्रत्यागम val;
}
DEF_WEAK(arc4random);

/*
 * If we are providing arc4random, then we can provide a more efficient
 * arc4random_buf().
 */
# ifndef HAVE_ARC4RANDOM_BUF
शून्य
arc4random_buf(शून्य *buf, आकार_t n)
{
	ARC4_तालकम्();
	_rs_random_buf(buf, n);
	_ARC4_UNLOCK();
}
DEF_WEAK(arc4random_buf);
# endif /* !HAVE_ARC4RANDOM_BUF */
#यदि_अन्तः /* !HAVE_ARC4RANDOM */

/* arc4random_buf() that uses platform arc4random() */
#यदि !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM)
शून्य
arc4random_buf(शून्य *_buf, आकार_t n)
{
	आकार_t i;
	u_int32_t r = 0;
	वर्ण *buf = (वर्ण *)_buf;

	प्रति (i = 0; i < n; i++) {
		यदि (i % 4 == 0)
			r = arc4random();
		buf[i] = r & 0xff;
		r >>= 8;
	}
	explicit_bzero(&r, परिमाण(r));
}
#यदि_अन्तः /* !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM) */

