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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/time.h>

#ifndef HAVE_ARC4RANDOM

/*
 * Always use the getentropy implementation from bsd-getentropy.c, which
 * will call a native getentropy if available then fall back as required.
 * We use a different name so that OpenSSL cannot call the wrong getentropy.
 */
പൂർണ്ണസംഖ്യ _ssh_compat_getentropy(ശൂന്യം *, size_t);
#ifdef getentropy
# undef getentropy
#endif
#define getentropy(x, y) (_ssh_compat_getentropy((x), (y)))

#അന്തര്ഭാവ "log.h"

#define KEYSTREAM_ONLY
#അന്തര്ഭാവ "chacha_private.h"

#define minimum(a, b) ((a) < (b) ? (a) : (b))

#എങ്കിൽ defined(__GNUC__) || defined(_MSC_VER)
#define വരിയിൽ __inline
#അല്ലെങ്കിൽ				/* __GNUC__ || _MSC_VER */
#define വരിയിൽ
#endif				/* !__GNUC__ && !_MSC_VER */

#define KEYSZ	32
#define IVSZ	8
#define BLOCKSZ	64
#define RSBUFSZ	(16*BLOCKSZ)

#define REKEY_BASE	(1024*1024) /* NB. should be a power of 2 */

/* Marked MAP_INHERIT_ZERO, so zero'd out in fork children. */
സ്ഥിതം ഘടന _rs {
	size_t		rs_have;	/* valid bytes at end of rs_buf */
	size_t		rs_എണ്ണം;	/* bytes till reseed */
} *rs;

/* Maybe be preserved in fork children, if _rs_allocate() decides. */
സ്ഥിതം ഘടന _rsx {
	chacha_ctx	rs_chacha;	/* chacha context for random keystream */
	u_char		rs_buf[RSBUFSZ];	/* keystream blocks */
} *rsx;

സ്ഥിതം വരിയിൽ പൂർണ്ണസംഖ്യ _rs_allocate(ഘടന _rs **, ഘടന _rsx **);
സ്ഥിതം വരിയിൽ ശൂന്യം _rs_forkdetect(ശൂന്യം);
#അന്തര്ഭാവ "arc4random.h"

സ്ഥിതം വരിയിൽ ശൂന്യം _rs_rekey(u_char *dat, size_t datlen);

സ്ഥിതം വരിയിൽ ശൂന്യം
_rs_init(u_char *buf, size_t n)
{
	എങ്കിൽ (n < KEYSZ + IVSZ)
		തിരികെ;

	എങ്കിൽ (rs == ശൂന്യ) {
		എങ്കിൽ (_rs_allocate(&rs, &rsx) == -1)
			_exit(1);
	}

	chacha_keysetup(&rsx->rs_chacha, buf, KEYSZ * 8);
	chacha_ivsetup(&rsx->rs_chacha, buf + KEYSZ);
}

സ്ഥിതം ശൂന്യം
_rs_stir(ശൂന്യം)
{
	u_char rnd[KEYSZ + IVSZ];
	uint32_t rekey_fuzz = 0;

	എങ്കിൽ (getentropy(rnd, വലുപ്പം rnd) == -1)
		_getentropy_fail();

	എങ്കിൽ (!rs)
		_rs_init(rnd, വലുപ്പം(rnd));
	അല്ലെങ്കിൽ
		_rs_rekey(rnd, വലുപ്പം(rnd));
	explicit_bzero(rnd, വലുപ്പം(rnd));	/* discard source seed */

	/* invalidate rs_buf */
	rs->rs_have = 0;
	memset(rsx->rs_buf, 0, വലുപ്പം(rsx->rs_buf));

	/* rekey interval should not be predictable */
	chacha_encrypt_bytes(&rsx->rs_chacha, (uint8_t *)&rekey_fuzz,
	    (uint8_t *)&rekey_fuzz, വലുപ്പം(rekey_fuzz));
	rs->rs_എണ്ണം = REKEY_BASE + (rekey_fuzz % REKEY_BASE);
}

സ്ഥിതം വരിയിൽ ശൂന്യം
_rs_stir_if_needed(size_t len)
{
	_rs_forkdetect();
	എങ്കിൽ (!rs || rs->rs_എണ്ണം <= len)
		_rs_stir();
	എങ്കിൽ (rs->rs_എണ്ണം <= len)
		rs->rs_എണ്ണം = 0;
	അല്ലെങ്കിൽ
		rs->rs_എണ്ണം -= len;
}

സ്ഥിതം വരിയിൽ ശൂന്യം
_rs_rekey(u_char *dat, size_t datlen)
{
#ifndef KEYSTREAM_ONLY
	memset(rsx->rs_buf, 0, വലുപ്പം(rsx->rs_buf));
#endif
	/* fill rs_buf with the keystream */
	chacha_encrypt_bytes(&rsx->rs_chacha, rsx->rs_buf,
	    rsx->rs_buf, വലുപ്പം(rsx->rs_buf));
	/* mix in optional user provided data */
	എങ്കിൽ (dat) {
		size_t i, m;

		m = minimum(datlen, KEYSZ + IVSZ);
		വേണ്ടി (i = 0; i < m; i++)
			rsx->rs_buf[i] ^= dat[i];
	}
	/* immediately reinit for backtracking resistance */
	_rs_init(rsx->rs_buf, KEYSZ + IVSZ);
	memset(rsx->rs_buf, 0, KEYSZ + IVSZ);
	rs->rs_have = വലുപ്പം(rsx->rs_buf) - KEYSZ - IVSZ;
}

സ്ഥിതം വരിയിൽ ശൂന്യം
_rs_random_buf(ശൂന്യം *_buf, size_t n)
{
	u_char *buf = (u_char *)_buf;
	u_char *keystream;
	size_t m;

	_rs_stir_if_needed(n);
	ആകുമ്പോൾ (n > 0) {
		എങ്കിൽ (rs->rs_have > 0) {
			m = minimum(n, rs->rs_have);
			keystream = rsx->rs_buf + വലുപ്പം(rsx->rs_buf)
			    - rs->rs_have;
			memcpy(buf, keystream, m);
			memset(keystream, 0, m);
			buf += m;
			n -= m;
			rs->rs_have -= m;
		}
		എങ്കിൽ (rs->rs_have == 0)
			_rs_rekey(ശൂന്യ, 0);
	}
}

സ്ഥിതം വരിയിൽ ശൂന്യം
_rs_random_u32(uint32_t *val)
{
	u_char *keystream;

	_rs_stir_if_needed(വലുപ്പം(*val));
	എങ്കിൽ (rs->rs_have < വലുപ്പം(*val))
		_rs_rekey(ശൂന്യ, 0);
	keystream = rsx->rs_buf + വലുപ്പം(rsx->rs_buf) - rs->rs_have;
	memcpy(val, keystream, വലുപ്പം(*val));
	memset(keystream, 0, വലുപ്പം(*val));
	rs->rs_have -= വലുപ്പം(*val);
}

uint32_t
arc4random(ശൂന്യം)
{
	uint32_t val;

	_ARC4_LOCK();
	_rs_random_u32(&val);
	_ARC4_UNLOCK();
	തിരികെ val;
}
DEF_WEAK(arc4random);

/*
 * If we are providing arc4random, then we can provide a more efficient
 * arc4random_buf().
 */
# ifndef HAVE_ARC4RANDOM_BUF
ശൂന്യം
arc4random_buf(ശൂന്യം *buf, size_t n)
{
	_ARC4_LOCK();
	_rs_random_buf(buf, n);
	_ARC4_UNLOCK();
}
DEF_WEAK(arc4random_buf);
# endif /* !HAVE_ARC4RANDOM_BUF */
#endif /* !HAVE_ARC4RANDOM */

/* arc4random_buf() that uses platform arc4random() */
#എങ്കിൽ !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM)
ശൂന്യം
arc4random_buf(ശൂന്യം *_buf, size_t n)
{
	size_t i;
	u_int32_t r = 0;
	അക്ഷരം *buf = (അക്ഷരം *)_buf;

	വേണ്ടി (i = 0; i < n; i++) {
		എങ്കിൽ (i % 4 == 0)
			r = arc4random();
		buf[i] = r & 0xff;
		r >>= 8;
	}
	explicit_bzero(&r, വലുപ്പം(r));
}
#endif /* !defined(HAVE_ARC4RANDOM_BUF) && defined(HAVE_ARC4RANDOM) */

