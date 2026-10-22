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

#شامل "includes.h"

#ifndef HAVE_BCRYPT_PBKDF

#شامل <sys/types.h>

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif
#شامل <string.h>

#ifdef HAVE_BLF_H
# include <blf.h>
#endif

#شامل "crypto_api.h"
#ifdef SHA512_DIGEST_LENGTH
# undef SHA512_DIGEST_LENGTH
#endif
#define SHA512_DIGEST_LENGTH crypto_hash_sha512_BYTES

#define	MINIMUM(a,b) (((a) < (b)) ? (a) : (b))

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

#define BCRYPT_واژگان 8
#define BCRYPT_HASHSIZE (BCRYPT_واژگان * 4)

ایستا تهی
bcrypt_hash(uint8_t *sha2pass, uint8_t *sha2salt, uint8_t *out)
{
	blf_ctx state;
	uint8_t __attribute__ ((__nonstring__)) ciphertext[BCRYPT_HASHSIZE] =
	    "OxychromaticBlowfishSwatDynamite";
	uint32_t cdata[BCRYPT_واژگان];
	صحیح i;
	uint16_t j;
	size_t shalen = SHA512_DIGEST_LENGTH;

	/* key expansion */
	Blowfish_initstate(&state);
	Blowfish_expandstate(&state, sha2salt, shalen, sha2pass, shalen);
	برای (i = 0; i < 64; i++) {
		Blowfish_expand0state(&state, sha2salt, shalen);
		Blowfish_expand0state(&state, sha2pass, shalen);
	}

	/* encryption */
	j = 0;
	برای (i = 0; i < BCRYPT_واژگان; i++)
		cdata[i] = Blowfish_stream2word(ciphertext, اندازه(ciphertext),
		    &j);
	برای (i = 0; i < 64; i++)
		blf_enc(&state, cdata, BCRYPT_واژگان / 2);

	/* copy out */
	برای (i = 0; i < BCRYPT_واژگان; i++) {
		out[4 * i + 3] = (cdata[i] >> 24) & 0xff;
		out[4 * i + 2] = (cdata[i] >> 16) & 0xff;
		out[4 * i + 1] = (cdata[i] >> 8) & 0xff;
		out[4 * i + 0] = cdata[i] & 0xff;
	}

	/* zap */
	explicit_bzero(ciphertext, اندازه(ciphertext));
	explicit_bzero(cdata, اندازه(cdata));
	explicit_bzero(&state, اندازه(state));
}

صحیح
bcrypt_pbkdf(ثابت نویسه *pass, size_t passlen, ثابت uint8_t *salt, size_t saltlen,
    uint8_t *کلید, size_t keylen, unsigned صحیح rounds)
{
	uint8_t sha2pass[SHA512_DIGEST_LENGTH];
	uint8_t sha2salt[SHA512_DIGEST_LENGTH];
	uint8_t out[BCRYPT_HASHSIZE];
	uint8_t tmpout[BCRYPT_HASHSIZE];
	uint8_t *countsalt;
	size_t i, j, amt, stride;
	uint32_t شمار;
	size_t origkeylen = keylen;

	/* nothing crazy */
	اگر (rounds < 1)
		برو bad;
	اگر (passlen == 0 || saltlen == 0 || keylen == 0 ||
	    keylen > اندازه(out) * اندازه(out) || saltlen > 1<<20)
		برو bad;
	اگر ((countsalt = calloc(1, saltlen + 4)) == پوچ)
		برو bad;
	stride = (keylen + اندازه(out) - 1) / اندازه(out);
	amt = (keylen + stride - 1) / stride;

	memcpy(countsalt, salt, saltlen);

	/* collapse password */
	crypto_hash_sha512(sha2pass, pass, passlen);

	/* generate key, sizeof(out) at a time */
	برای (شمار = 1; keylen > 0; شمار++) {
		countsalt[saltlen + 0] = (شمار >> 24) & 0xff;
		countsalt[saltlen + 1] = (شمار >> 16) & 0xff;
		countsalt[saltlen + 2] = (شمار >> 8) & 0xff;
		countsalt[saltlen + 3] = شمار & 0xff;

		/* first round, salt is salt */
		crypto_hash_sha512(sha2salt, countsalt, saltlen + 4);

		bcrypt_hash(sha2pass, sha2salt, tmpout);
		memcpy(out, tmpout, اندازه(out));

		برای (i = 1; i < rounds; i++) {
			/* subsequent rounds, salt is previous output */
			crypto_hash_sha512(sha2salt, tmpout, اندازه(tmpout));
			bcrypt_hash(sha2pass, sha2salt, tmpout);
			برای (j = 0; j < اندازه(out); j++)
				out[j] ^= tmpout[j];
		}

		/*
		 * pbkdf2 deviation: output the key material non-linearly.
		 */
		amt = MINIMUM(amt, keylen);
		برای (i = 0; i < amt; i++) {
			size_t dest = i * stride + (شمار - 1);
			اگر (dest >= origkeylen)
				بشکن;
			کلید[dest] = out[i];
		}
		keylen -= i;
	}

	/* zap */
	freezero(countsalt, saltlen + 4);
	explicit_bzero(out, اندازه(out));
	explicit_bzero(tmpout, اندازه(tmpout));

	بازگشت 0;

bad:
	/* overwrite with random in case caller doesn't check return code */
	arc4random_buf(کلید, keylen);
	بازگشت -1;
}
#endif /* HAVE_BCRYPT_PBKDF */
