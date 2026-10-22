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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/time.h>

#ifndef HAVE_ARC4RANDOM

/*
 * Always use the getentropy implementation from bsd-getentropy.c, which
 * will call a native getentropy if available then fall back as required.
 * We use a different name so that OpenSSL cannot call the wrong getentropy.
 */
પૂર્ણાંક _ssh_compat_getentropy(શૂન્ય *, size_t);
#ifdef getentropy
# undef getentropy
#endif
#define getentropy(x, y) (_ssh_compat_getentropy((x), (y)))

#અન્તર્ભાવ "log.h"

#define KEYSTREAM_ONLY
#અન્તર્ભાવ "chacha_private.h"

#define minimum(a, b) ((a) < (b) ? (a) : (b))

#જો defined(__GNUC__) || defined(_MSC_VER)
#define અંતઃરેખ __inline
#નહીંતર				/* __GNUC__ || _MSC_VER */
#define અંતઃરેખ
#endif				/* !__GNUC__ && !_MSC_VER */

#define KEYSZ	32
#define IVSZ	8
#define BLOCKSZ	64
#define RSBUFSZ	(16*BLOCKSZ)

#define REKEY_BASE	(1024*1024) /* NB. should be a power of 2 */

/* Marked MAP_INHERIT_ZERO, so zero'd out in fork children. */
સ્થિર સંરચના _rs {
	size_t		rs_have;	/* valid bytes at end of rs_buf */
	size_t		rs_ગણતરી;	/* bytes till reseed */
} *rs;

/* Maybe be preserved in fork children, if _rs_allocate() decides. */
સ્થિર સંરચના _rsx {
	chacha_ctx	rs_chacha;	/* chacha context for random keystream */
	u_char		rs_buf[RSBUFSZ];	/* keystream blocks */
} *rsx;

સ્થિર અંતઃરેખ પૂર્ણાંક _rs_allocate(સંરચના _rs **, સંરચના _rsx **);
સ્થિર અંતઃરેખ શૂન્ય _rs_forkdetect(શૂન્ય);
#અન્તર્ભાવ "arc4random.h"

સ્થિર અંતઃરેખ શૂન્ય _rs_rekey(u_char *dat, size_t datlen);

સ્થિર અંતઃરેખ શૂન્ય
_rs_init(u_char *buf, size_t n)
{
	જો (n < KEYSZ + IVSZ)
		પાછા;

	જો (rs == ખાલી) {
		જો (_rs_allocate(&rs, &rsx) == -1)
			_exit(1);
	}

	chacha_keysetup(&rsx->rs_chacha, buf, KEYSZ * 8);
	chacha_ivsetup(&rsx->rs_chacha, buf + KEYSZ);
}

સ્થિર શૂન્ય
_rs_stir(શૂન્ય)
{
	u_char rnd[KEYSZ + IVSZ];
	uint32_t rekey_fuzz = 0;

	જો (getentropy(rnd, કદ rnd) == -1)
		_getentropy_fail();

	જો (!rs)
		_rs_init(rnd, કદ(rnd));
	નહીંતર
		_rs_rekey(rnd, કદ(rnd));
	explicit_bzero(rnd, કદ(rnd));	/* discard source seed */

	/* invalidate rs_buf */
	rs->rs_have = 0;
	memset(rsx->rs_buf, 0, કદ(rsx->rs_buf));

	/* rekey interval should not be predictable */
	chacha_encrypt_bytes(&rsx->rs_chacha, (uint8_t *)&rekey_fuzz,
	    (uint8_t *)&rekey_fuzz, કદ(rekey_fuzz));
	rs->rs_ગણતરી = REKEY_BASE + (rekey_fuzz % REKEY_BASE);
}

સ્થિર અંતઃરેખ શૂન્ય
_rs_stir_if_needed(size_t len)
{
	_rs_forkdetect();
	જો (!rs || rs->rs_ગણતરી <= len)
		_rs_stir();
	જો (rs->rs_ગણતરી <= len)
		rs->rs_ગણતરી = 0;
	નહીંતર
		rs->rs_ગણતરી -= len;
}

સ્થિર અંતઃરેખ શૂન્ય
_rs_rekey(u_char *dat, size_t datlen)
{
#ifndef KEYSTREAM_ONLY
	memset(rsx->rs_buf, 0, કદ(rsx->rs_buf));
#endif
	/* fill rs_buf with the keystream */
	chacha_encrypt_bytes(&rsx->rs_chacha, rsx->rs_buf,
	    rsx->rs_buf, કદ(rsx->rs_buf));
	/* mix in optional user provided data */
	જો (dat) {
		size_t i, m;

		m = minimum(datlen, KEYSZ + IVSZ);
		માટે (i = 0; i < m; i++)
			rsx->rs_buf[i] ^= dat[i];
	}
	/* immediately reinit for backtracking resistance */
	_rs_init(rsx->rs_buf, KEYSZ + IVSZ);
	memset(rsx->rs_buf, 0, KEYSZ + IVSZ);
	rs->rs_have = કદ(rsx->rs_buf) - KEYSZ - IVSZ;
}

સ્થિર અંતઃરેખ શૂન્ય
_rs_random_buf(શૂન્ય *_buf, size_t n)
{
	u_char *buf = (u_char *)_buf;
	u_char *keystream;
	size_t m;

	_rs_stir_if_needed(n);
	જ્યારે (n > 0) {
		જો (rs->rs_have > 0) {
			m = minimum(n, rs->rs_have);
			keystream = rsx->rs_buf + કદ(rsx->rs_buf)
			    - rs->rs_have;
			memcpy(buf, keystream, m);
			memset(keystream, 0, m);
			buf += m;
			n -= m;
			rs->rs_have -= m;
		}
		જો (rs->rs_have == 0)
			_rs_rekey(ખાલી, 0);
	}
}

સ્થિર અંતઃરેખ શૂન્ય
_rs_random_u32(uint32_t *val)
{
	u_char *keystream;

	_rs_stir_if_needed(કદ(*val));
	જો (rs->rs_have < કદ(*val))
		_rs_rekey(ખાલી, 0);
	keystream = rsx->rs_buf + કદ(rsx->rs_buf) - rs->rs_have;
	memcpy(val, keystream, કદ(*val));
	memset(keystream, 0, કદ(*val));
	rs->rs_have -= કદ(*val);
}

uint32_t
arc4random(શૂન્ય)
{
	uint32_t val;

	_ARC4_LOCK();
	_rs_random_u32(&val);
	_ARC4_UNLOCK();
	પાછા val;
}
DEF_WEAK(arc4random);

/*
 * If we are providing arc4random, then we can provide a more efficient
 * arc4random_buf().
 */
# ifndef HAVE_ARC4RANDOM_BUF
શૂન્ય
arc4random_buf(શૂન્ય *buf, size_t n)
{
	_ARC4_LOCK();
	_rs_random_buf(buf, n);
	_ARC4_UNLOCK();
}
DEF_WEAK(arc4random_buf);
# endif /* !HAVE_ARC4RANDOM_BUF */
#endif /* !HAVE_ARC4RANDOM */

/* arc4random_buf() that uses platform arc4random() */
#જો !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM)
શૂન્ય
arc4random_buf(શૂન્ય *_buf, size_t n)
{
	size_t i;
	u_int32_t r = 0;
	અક્ષર *buf = (અક્ષર *)_buf;

	માટે (i = 0; i < n; i++) {
		જો (i % 4 == 0)
			r = arc4random();
		buf[i] = r & 0xff;
		r >>= 8;
	}
	explicit_bzero(&r, કદ(r));
}
#endif /* !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM) */

