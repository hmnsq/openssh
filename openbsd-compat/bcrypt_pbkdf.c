/* $OpenBSD: bcrypt_pbkdf.c,v 1.17 2022/12/27 17:10:08 jmc Exp $ */
/*
 * Copyright (c) 2013 Ted Unangst <tedu@openbsd.org>
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

/* OPENBSD ORIGINAL: lib/libutil/bcrypt_pbkdf.c */

/* This version has been modified to use SHA512 from SUPERCOP */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_BCRYPT_PBKDF

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_STDLIB_H
# include <stdlib.h>
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_BLF_H
# include <blf.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "crypto_api.h"
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SHA512_DIGEST_ਲੰਮਾਈ
# undef SHA512_DIGEST_ਲੰਮਾਈ
#ਜੇ_ਅੰਤ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SHA512_DIGEST_ਲੰਮਾਈ crypto_hash_sha512_ਬਾਈਟਾਂ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	MINIMUM(a,b) (((a) < (b)) ? (a) : (b))

/*
 * pkcs #5 pbkdf2 implementation using the "bcrypt" hash
 *
 * The bcrypt hash function is derived from the bcrypt password hashing
 * function with the following modifications:
 * 1. The input password and salt are preprocessed with SHA512.
 * 2. The output length is expanded to 256 bits.
 * 3. Subsequently the magic string to be encrypted is lengthened and modified
 *    to "OxychromaticBlowfishSwatDynamite"
 * 4. The hash function is defined to perform 64 rounds of initial state
 *    expansion. (More rounds are performed by iterating the hash.)
 *
 * Note that this implementation pulls the SHA512 operations into the caller
 * as a performance optimization.
 *
 * One modification from official pbkdf2. Instead of outputting key material
 * linearly, we mix it. pbkdf2 has a known weakness where if one uses it to
 * generate (e.g.) 512 bits of key material for use as two 256 bit keys, an
 * attacker can merely run once through the outer loop, but the user
 * always runs it twice. Shuffling output bytes requires computing the
 * entirety of the key material to assemble any subkey. This is something a
 * wise caller could do; we just do it for you.
 */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BCRYPT_ਸ਼ਬਦ 8
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BCRYPT_HASHSIZE (BCRYPT_ਸ਼ਬਦ * 4)

ਸਥਿਰ ਖਾਲੀ
bcrypt_hash(uint8_t *sha2pass, uint8_t *sha2salt, uint8_t *ਬਾਹਰਲਾ)
{
	blf_ctx state;
	uint8_t __attribute__ ((__nonstring__)) ciphertext[BCRYPT_HASHSIZE] =
	    "OxychromaticBlowfishSwatDynamite";
	uint32_t cdata[BCRYPT_ਸ਼ਬਦ];
	ਪੂਰਨ i;
	uint16_t j;
	ਮਾਪ_t shalen = SHA512_DIGEST_ਲੰਮਾਈ;

	/* key expansion */
	Blowfish_initstate(&state);
	Blowfish_expandstate(&state, sha2salt, shalen, sha2pass, shalen);
	ਲਈ (i = 0; i < 64; i++) {
		Blowfish_expand0state(&state, sha2salt, shalen);
		Blowfish_expand0state(&state, sha2pass, shalen);
	}

	/* encryption */
	j = 0;
	ਲਈ (i = 0; i < BCRYPT_ਸ਼ਬਦ; i++)
		cdata[i] = Blowfish_stream2word(ciphertext, ਆਕਾਰ(ciphertext),
		    &j);
	ਲਈ (i = 0; i < 64; i++)
		blf_enc(&state, cdata, BCRYPT_ਸ਼ਬਦ / 2);

	/* copy out */
	ਲਈ (i = 0; i < BCRYPT_ਸ਼ਬਦ; i++) {
		ਬਾਹਰਲਾ[4 * i + 3] = (cdata[i] >> 24) & 0xff;
		ਬਾਹਰਲਾ[4 * i + 2] = (cdata[i] >> 16) & 0xff;
		ਬਾਹਰਲਾ[4 * i + 1] = (cdata[i] >> 8) & 0xff;
		ਬਾਹਰਲਾ[4 * i + 0] = cdata[i] & 0xff;
	}

	/* zap */
	explicit_bzero(ciphertext, ਆਕਾਰ(ciphertext));
	explicit_bzero(cdata, ਆਕਾਰ(cdata));
	explicit_bzero(&state, ਆਕਾਰ(state));
}

ਪੂਰਨ
bcrypt_pbkdf(ਅਚਲ ਅੱਖਰ *pass, ਮਾਪ_t passlen, ਅਚਲ uint8_t *salt, ਮਾਪ_t saltlen,
    uint8_t *ਕੁੰਜੀ, ਮਾਪ_t keylen, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ ਗੇੜ)
{
	uint8_t sha2pass[SHA512_DIGEST_ਲੰਮਾਈ];
	uint8_t sha2salt[SHA512_DIGEST_ਲੰਮਾਈ];
	uint8_t ਬਾਹਰਲਾ[BCRYPT_HASHSIZE];
	uint8_t tmpout[BCRYPT_HASHSIZE];
	uint8_t *countsalt;
	ਮਾਪ_t i, j, amt, stride;
	uint32_t ਗਿਣਤੀ_2;
	ਮਾਪ_t origkeylen = keylen;

	/* nothing crazy */
	ਜੇ (ਗੇੜ < 1)
		ਜਾਓ bad;
	ਜੇ (passlen == 0 || saltlen == 0 || keylen == 0 ||
	    keylen > ਆਕਾਰ(ਬਾਹਰਲਾ) * ਆਕਾਰ(ਬਾਹਰਲਾ) || saltlen > 1<<20)
		ਜਾਓ bad;
	ਜੇ ((countsalt = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, saltlen + 4)) == ਨਿਰਾ)
		ਜਾਓ bad;
	stride = (keylen + ਆਕਾਰ(ਬਾਹਰਲਾ) - 1) / ਆਕਾਰ(ਬਾਹਰਲਾ);
	amt = (keylen + stride - 1) / stride;

	ਸਮ੍ਰਿਤੀ_ਨਕਲ(countsalt, salt, saltlen);

	/* collapse password */
	crypto_hash_sha512(sha2pass, pass, passlen);

	/* generate key, sizeof(out) at a time */
	ਲਈ (ਗਿਣਤੀ_2 = 1; keylen > 0; ਗਿਣਤੀ_2++) {
		countsalt[saltlen + 0] = (ਗਿਣਤੀ_2 >> 24) & 0xff;
		countsalt[saltlen + 1] = (ਗਿਣਤੀ_2 >> 16) & 0xff;
		countsalt[saltlen + 2] = (ਗਿਣਤੀ_2 >> 8) & 0xff;
		countsalt[saltlen + 3] = ਗਿਣਤੀ_2 & 0xff;

		/* first round, salt is salt */
		crypto_hash_sha512(sha2salt, countsalt, saltlen + 4);

		bcrypt_hash(sha2pass, sha2salt, tmpout);
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(ਬਾਹਰਲਾ, tmpout, ਆਕਾਰ(ਬਾਹਰਲਾ));

		ਲਈ (i = 1; i < ਗੇੜ; i++) {
			/* subsequent rounds, salt is previous output */
			crypto_hash_sha512(sha2salt, tmpout, ਆਕਾਰ(tmpout));
			bcrypt_hash(sha2pass, sha2salt, tmpout);
			ਲਈ (j = 0; j < ਆਕਾਰ(ਬਾਹਰਲਾ); j++)
				ਬਾਹਰਲਾ[j] ^= tmpout[j];
		}

		/*
		 * pbkdf2 deviation: output the key material non-linearly.
		 */
		amt = MINIMUM(amt, keylen);
		ਲਈ (i = 0; i < amt; i++) {
			ਮਾਪ_t dest = i * stride + (ਗਿਣਤੀ_2 - 1);
			ਜੇ (dest >= origkeylen)
				ਰੋਕੋ;
			ਕੁੰਜੀ[dest] = ਬਾਹਰਲਾ[i];
		}
		keylen -= i;
	}

	/* zap */
	freezero(countsalt, saltlen + 4);
	explicit_bzero(ਬਾਹਰਲਾ, ਆਕਾਰ(ਬਾਹਰਲਾ));
	explicit_bzero(tmpout, ਆਕਾਰ(tmpout));

	ਵਾਪਸ 0;

bad:
	/* overwrite with random in case caller doesn't check return code */
	arc4random_buf(ਕੁੰਜੀ, keylen);
	ਵਾਪਸ -1;
}
#ਜੇ_ਅੰਤ /* HAVE_BCRYPT_PBKDF */
