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

#ifndef HAVE_ARC4RANDOM

/*
 * Always use the getentropy implementation from bsd-getentropy.c, which
 * will call a native getentropy if available then fall back as required.
 * We use a different name so that OpenSSL cannot call the wrong getentropy.
 */
पूर्णाङ्क _ssh_compat_getentropy(शून्य *, माप_प्रकार);
#ifdef getentropy
# undef getentropy
#endif
#define getentropy(x, y) (_ssh_compat_getentropy((x), (y)))

#अन्तर्भाव "log.h"

#define KEYSTREAM_ONLY
#अन्तर्भाव "chacha_private.h"

#define minimum(a, b) ((a) < (b) ? (a) : (b))

#यदि defined(__GNUC__) || defined(_MSC_VER)
#define अन्तःस्थ __inline
#अन्यथा				/* __GNUC__ || _MSC_VER */
#define अन्तःस्थ
#endif				/* !__GNUC__ && !_MSC_VER */

#define KEYSZ	32
#define IVSZ	8
#define BLOCKSZ	64
#define RSBUFSZ	(16*BLOCKSZ)

#define REKEY_BASE	(1024*1024) /* NB. should be a power of 2 */

/* Marked MAP_INHERIT_ZERO, so zero'd out in fork children. */
स्थिर संरचना _rs {
	माप_प्रकार		rs_have;	/* valid bytes at end of rs_buf */
	माप_प्रकार		rs_गिनती;	/* bytes till reseed */
} *rs;

/* Maybe be preserved in fork children, if _rs_allocate() decides. */
स्थिर संरचना _rsx {
	chacha_ctx	rs_chacha;	/* chacha context for random keystream */
	u_char		rs_buf[RSBUFSZ];	/* keystream blocks */
} *rsx;

स्थिर अन्तःस्थ पूर्णाङ्क _rs_allocate(संरचना _rs **, संरचना _rsx **);
स्थिर अन्तःस्थ शून्य _rs_forkdetect(शून्य);
#अन्तर्भाव "arc4random.h"

स्थिर अन्तःस्थ शून्य _rs_rekey(u_char *dat, माप_प्रकार datlen);

स्थिर अन्तःस्थ शून्य
_rs_init(u_char *buf, माप_प्रकार n)
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
	स_रखो(rsx->rs_buf, 0, परिमाण(rsx->rs_buf));

	/* rekey interval should not be predictable */
	chacha_encrypt_bytes(&rsx->rs_chacha, (uint8_t *)&rekey_fuzz,
	    (uint8_t *)&rekey_fuzz, परिमाण(rekey_fuzz));
	rs->rs_गिनती = REKEY_BASE + (rekey_fuzz % REKEY_BASE);
}

स्थिर अन्तःस्थ शून्य
_rs_stir_if_needed(माप_प्रकार len)
{
	_rs_forkdetect();
	यदि (!rs || rs->rs_गिनती <= len)
		_rs_stir();
	यदि (rs->rs_गिनती <= len)
		rs->rs_गिनती = 0;
	अन्यथा
		rs->rs_गिनती -= len;
}

स्थिर अन्तःस्थ शून्य
_rs_rekey(u_char *dat, माप_प्रकार datlen)
{
#ifndef KEYSTREAM_ONLY
	स_रखो(rsx->rs_buf, 0, परिमाण(rsx->rs_buf));
#endif
	/* fill rs_buf with the keystream */
	chacha_encrypt_bytes(&rsx->rs_chacha, rsx->rs_buf,
	    rsx->rs_buf, परिमाण(rsx->rs_buf));
	/* mix in optional user provided data */
	यदि (dat) {
		माप_प्रकार i, m;

		m = minimum(datlen, KEYSZ + IVSZ);
		प्रति (i = 0; i < m; i++)
			rsx->rs_buf[i] ^= dat[i];
	}
	/* immediately reinit for backtracking resistance */
	_rs_init(rsx->rs_buf, KEYSZ + IVSZ);
	स_रखो(rsx->rs_buf, 0, KEYSZ + IVSZ);
	rs->rs_have = परिमाण(rsx->rs_buf) - KEYSZ - IVSZ;
}

स्थिर अन्तःस्थ शून्य
_rs_random_buf(शून्य *_buf, माप_प्रकार n)
{
	u_char *buf = (u_char *)_buf;
	u_char *keystream;
	माप_प्रकार m;

	_rs_stir_if_needed(n);
	यावत् (n > 0) {
		यदि (rs->rs_have > 0) {
			m = minimum(n, rs->rs_have);
			keystream = rsx->rs_buf + परिमाण(rsx->rs_buf)
			    - rs->rs_have;
			स_नकल(buf, keystream, m);
			स_रखो(keystream, 0, m);
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
	स_नकल(val, keystream, परिमाण(*val));
	स_रखो(keystream, 0, परिमाण(*val));
	rs->rs_have -= परिमाण(*val);
}

uint32_t
arc4random(शून्य)
{
	uint32_t val;

	_ARC4_LOCK();
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
arc4random_buf(शून्य *buf, माप_प्रकार n)
{
	_ARC4_LOCK();
	_rs_random_buf(buf, n);
	_ARC4_UNLOCK();
}
DEF_WEAK(arc4random_buf);
# endif /* !HAVE_ARC4RANDOM_BUF */
#endif /* !HAVE_ARC4RANDOM */

/* arc4random_buf() that uses platform arc4random() */
#यदि !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM)
शून्य
arc4random_buf(शून्य *_buf, माप_प्रकार n)
{
	माप_प्रकार i;
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
#endif /* !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM) */

