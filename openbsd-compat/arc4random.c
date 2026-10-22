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

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <fcntl.h>
#समावेश <limits.h>
#समावेश <signal.h>
#समावेश <stdint.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <sys/types.h>
#समावेश <sys/time.h>

#अगर_अघोषित HAVE_ARC4RANDOM

/*
 * Always use the getentropy implementation from bsd-getentropy.c, which
 * will call a native getentropy if available then fall back as required.
 * We use a different name so that OpenSSL cannot call the wrong getentropy.
 */
पूर्णांक _ssh_compat_getentropy(व्योम *, माप_प्रकार);
#अगर_घोषित getentropy
# undef getentropy
#पूर्ण_अगर
#घोषणा getentropy(x, y) (_ssh_compat_getentropy((x), (y)))

#समावेश "log.h"

#घोषणा KEYSTREAM_ONLY
#समावेश "chacha_private.h"

#घोषणा minimum(a, b) ((a) < (b) ? (a) : (b))

#अगर defined(__GNUC__) || defined(_MSC_VER)
#घोषणा अंतरभूत __inline
#अन्यथा				/* __GNUC__ || _MSC_VER */
#घोषणा अंतरभूत
#पूर्ण_अगर				/* !__GNUC__ && !_MSC_VER */

#घोषणा KEYSZ	32
#घोषणा IVSZ	8
#घोषणा BLOCKSZ	64
#घोषणा RSBUFSZ	(16*BLOCKSZ)

#घोषणा REKEY_BASE	(1024*1024) /* NB. should be a power of 2 */

/* Marked MAP_INHERIT_ZERO, so zero'd out in fork children. */
अटल काष्ठा _rs {
	माप_प्रकार		rs_have;	/* valid bytes at end of rs_buf */
	माप_प्रकार		rs_गिनती;	/* bytes till reseed */
} *rs;

/* Maybe be preserved in fork children, if _rs_allocate() decides. */
अटल काष्ठा _rsx {
	chacha_ctx	rs_chacha;	/* chacha context for random keystream */
	u_char		rs_buf[RSBUFSZ];	/* keystream blocks */
} *rsx;

अटल अंतरभूत पूर्णांक _rs_allocate(काष्ठा _rs **, काष्ठा _rsx **);
अटल अंतरभूत व्योम _rs_forkdetect(व्योम);
#समावेश "arc4random.h"

अटल अंतरभूत व्योम _rs_rekey(u_char *dat, माप_प्रकार datlen);

अटल अंतरभूत व्योम
_rs_init(u_char *buf, माप_प्रकार n)
{
	अगर (n < KEYSZ + IVSZ)
		वापस;

	अगर (rs == शून्य) {
		अगर (_rs_allocate(&rs, &rsx) == -1)
			_निकास(1);
	}

	chacha_keysetup(&rsx->rs_chacha, buf, KEYSZ * 8);
	chacha_ivsetup(&rsx->rs_chacha, buf + KEYSZ);
}

अटल व्योम
_rs_stir(व्योम)
{
	u_char rnd[KEYSZ + IVSZ];
	uint32_t rekey_fuzz = 0;

	अगर (getentropy(rnd, माप rnd) == -1)
		_getentropy_fail();

	अगर (!rs)
		_rs_init(rnd, माप(rnd));
	अन्यथा
		_rs_rekey(rnd, माप(rnd));
	explicit_bzero(rnd, माप(rnd));	/* discard source seed */

	/* invalidate rs_buf */
	rs->rs_have = 0;
	स_रखो(rsx->rs_buf, 0, माप(rsx->rs_buf));

	/* rekey interval should not be predictable */
	chacha_encrypt_bytes(&rsx->rs_chacha, (uint8_t *)&rekey_fuzz,
	    (uint8_t *)&rekey_fuzz, माप(rekey_fuzz));
	rs->rs_गिनती = REKEY_BASE + (rekey_fuzz % REKEY_BASE);
}

अटल अंतरभूत व्योम
_rs_stir_if_needed(माप_प्रकार len)
{
	_rs_forkdetect();
	अगर (!rs || rs->rs_गिनती <= len)
		_rs_stir();
	अगर (rs->rs_गिनती <= len)
		rs->rs_गिनती = 0;
	अन्यथा
		rs->rs_गिनती -= len;
}

अटल अंतरभूत व्योम
_rs_rekey(u_char *dat, माप_प्रकार datlen)
{
#अगर_अघोषित KEYSTREAM_ONLY
	स_रखो(rsx->rs_buf, 0, माप(rsx->rs_buf));
#पूर्ण_अगर
	/* fill rs_buf with the keystream */
	chacha_encrypt_bytes(&rsx->rs_chacha, rsx->rs_buf,
	    rsx->rs_buf, माप(rsx->rs_buf));
	/* mix in optional user provided data */
	अगर (dat) {
		माप_प्रकार i, m;

		m = minimum(datlen, KEYSZ + IVSZ);
		क्रम (i = 0; i < m; i++)
			rsx->rs_buf[i] ^= dat[i];
	}
	/* immediately reinit for backtracking resistance */
	_rs_init(rsx->rs_buf, KEYSZ + IVSZ);
	स_रखो(rsx->rs_buf, 0, KEYSZ + IVSZ);
	rs->rs_have = माप(rsx->rs_buf) - KEYSZ - IVSZ;
}

अटल अंतरभूत व्योम
_rs_random_buf(व्योम *_buf, माप_प्रकार n)
{
	u_char *buf = (u_char *)_buf;
	u_char *keystream;
	माप_प्रकार m;

	_rs_stir_if_needed(n);
	जबतक (n > 0) {
		अगर (rs->rs_have > 0) {
			m = minimum(n, rs->rs_have);
			keystream = rsx->rs_buf + माप(rsx->rs_buf)
			    - rs->rs_have;
			स_नकल(buf, keystream, m);
			स_रखो(keystream, 0, m);
			buf += m;
			n -= m;
			rs->rs_have -= m;
		}
		अगर (rs->rs_have == 0)
			_rs_rekey(शून्य, 0);
	}
}

अटल अंतरभूत व्योम
_rs_random_u32(uint32_t *val)
{
	u_char *keystream;

	_rs_stir_if_needed(माप(*val));
	अगर (rs->rs_have < माप(*val))
		_rs_rekey(शून्य, 0);
	keystream = rsx->rs_buf + माप(rsx->rs_buf) - rs->rs_have;
	स_नकल(val, keystream, माप(*val));
	स_रखो(keystream, 0, माप(*val));
	rs->rs_have -= माप(*val);
}

uint32_t
arc4random(व्योम)
{
	uint32_t val;

	_ARC4_LOCK();
	_rs_random_u32(&val);
	_ARC4_UNLOCK();
	वापस val;
}
DEF_WEAK(arc4random);

/*
 * If we are providing arc4random, then we can provide a more efficient
 * arc4random_buf().
 */
# ifndef HAVE_ARC4RANDOM_BUF
व्योम
arc4random_buf(व्योम *buf, माप_प्रकार n)
{
	_ARC4_LOCK();
	_rs_random_buf(buf, n);
	_ARC4_UNLOCK();
}
DEF_WEAK(arc4random_buf);
# endif /* !HAVE_ARC4RANDOM_BUF */
#पूर्ण_अगर /* !HAVE_ARC4RANDOM */

/* arc4random_buf() that uses platform arc4random() */
#अगर !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM)
व्योम
arc4random_buf(व्योम *_buf, माप_प्रकार n)
{
	माप_प्रकार i;
	u_int32_t r = 0;
	अक्षर *buf = (अक्षर *)_buf;

	क्रम (i = 0; i < n; i++) {
		अगर (i % 4 == 0)
			r = arc4random();
		buf[i] = r & 0xff;
		r >>= 8;
	}
	explicit_bzero(&r, माप(r));
}
#पूर्ण_अगर /* !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM) */

