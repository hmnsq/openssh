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

#অন্তর্ভাৱ "includes.h"

#ifndef HAVE_BCRYPT_PBKDF

#অন্তর্ভাৱ <sys/types.h>

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif
#অন্তর্ভাৱ <string.h>

#ifdef HAVE_BLF_H
# include <blf.h>
#endif

#অন্তর্ভাৱ "crypto_api.h"
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

#define BCRYPT_শব্দগুলি 8
#define BCRYPT_HASHSIZE (BCRYPT_শব্দগুলি * 4)

স্থির শূন্য
bcrypt_hash(uint8_t *sha2pass, uint8_t *sha2salt, uint8_t *out)
{
	blf_ctx state;
	uint8_t __attribute__ ((__nonstring__)) ciphertext[BCRYPT_HASHSIZE] =
	    "OxychromaticBlowfishSwatDynamite";
	uint32_t cdata[BCRYPT_শব্দগুলি];
	পূর্ণাঙ্ক i;
	uint16_t j;
	size_t shalen = SHA512_DIGEST_LENGTH;

	/* key expansion */
	Blowfish_initstate(&state);
	Blowfish_expandstate(&state, sha2salt, shalen, sha2pass, shalen);
	বাবে (i = 0; i < 64; i++) {
		Blowfish_expand0state(&state, sha2salt, shalen);
		Blowfish_expand0state(&state, sha2pass, shalen);
	}

	/* encryption */
	j = 0;
	বাবে (i = 0; i < BCRYPT_শব্দগুলি; i++)
		cdata[i] = Blowfish_stream2word(ciphertext, পরিমাণ(ciphertext),
		    &j);
	বাবে (i = 0; i < 64; i++)
		blf_enc(&state, cdata, BCRYPT_শব্দগুলি / 2);

	/* copy out */
	বাবে (i = 0; i < BCRYPT_শব্দগুলি; i++) {
		out[4 * i + 3] = (cdata[i] >> 24) & 0xff;
		out[4 * i + 2] = (cdata[i] >> 16) & 0xff;
		out[4 * i + 1] = (cdata[i] >> 8) & 0xff;
		out[4 * i + 0] = cdata[i] & 0xff;
	}

	/* zap */
	explicit_bzero(ciphertext, পরিমাণ(ciphertext));
	explicit_bzero(cdata, পরিমাণ(cdata));
	explicit_bzero(&state, পরিমাণ(state));
}

পূর্ণাঙ্ক
bcrypt_pbkdf(ধ্রুৱ ৱর্ণ *pass, size_t passlen, ধ্রুৱ uint8_t *salt, size_t saltlen,
    uint8_t *চাবি, size_t keylen, unsigned পূর্ণাঙ্ক rounds)
{
	uint8_t sha2pass[SHA512_DIGEST_LENGTH];
	uint8_t sha2salt[SHA512_DIGEST_LENGTH];
	uint8_t out[BCRYPT_HASHSIZE];
	uint8_t tmpout[BCRYPT_HASHSIZE];
	uint8_t *countsalt;
	size_t i, j, amt, stride;
	uint32_t গুনতি;
	size_t origkeylen = keylen;

	/* nothing crazy */
	যদি (rounds < 1)
		গচ্ছ bad;
	যদি (passlen == 0 || saltlen == 0 || keylen == 0 ||
	    keylen > পরিমাণ(out) * পরিমাণ(out) || saltlen > 1<<20)
		গচ্ছ bad;
	যদি ((countsalt = calloc(1, saltlen + 4)) == রিক্ত)
		গচ্ছ bad;
	stride = (keylen + পরিমাণ(out) - 1) / পরিমাণ(out);
	amt = (keylen + stride - 1) / stride;

	memcpy(countsalt, salt, saltlen);

	/* collapse password */
	crypto_hash_sha512(sha2pass, pass, passlen);

	/* generate key, sizeof(out) at a time */
	বাবে (গুনতি = 1; keylen > 0; গুনতি++) {
		countsalt[saltlen + 0] = (গুনতি >> 24) & 0xff;
		countsalt[saltlen + 1] = (গুনতি >> 16) & 0xff;
		countsalt[saltlen + 2] = (গুনতি >> 8) & 0xff;
		countsalt[saltlen + 3] = গুনতি & 0xff;

		/* first round, salt is salt */
		crypto_hash_sha512(sha2salt, countsalt, saltlen + 4);

		bcrypt_hash(sha2pass, sha2salt, tmpout);
		memcpy(out, tmpout, পরিমাণ(out));

		বাবে (i = 1; i < rounds; i++) {
			/* subsequent rounds, salt is previous output */
			crypto_hash_sha512(sha2salt, tmpout, পরিমাণ(tmpout));
			bcrypt_hash(sha2pass, sha2salt, tmpout);
			বাবে (j = 0; j < পরিমাণ(out); j++)
				out[j] ^= tmpout[j];
		}

		/*
		 * pbkdf2 deviation: output the key material non-linearly.
		 */
		amt = MINIMUM(amt, keylen);
		বাবে (i = 0; i < amt; i++) {
			size_t dest = i * stride + (গুনতি - 1);
			যদি (dest >= origkeylen)
				ভঙ্গ;
			চাবি[dest] = out[i];
		}
		keylen -= i;
	}

	/* zap */
	freezero(countsalt, saltlen + 4);
	explicit_bzero(out, পরিমাণ(out));
	explicit_bzero(tmpout, পরিমাণ(tmpout));

	ঘূৰাই 0;

bad:
	/* overwrite with random in case caller doesn't check return code */
	arc4random_buf(চাবি, keylen);
	ঘূৰাই -1;
}
#endif /* HAVE_BCRYPT_PBKDF */
