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

#समावेश "includes.h"

#अगर_अघोषित HAVE_BCRYPT_PBKDF

#समावेश <sys/types.h>

#अगर_घोषित HAVE_STDLIB_H
# include <stdlib.h>
#पूर्ण_अगर
#समावेश <string.h>

#अगर_घोषित HAVE_BLF_H
# include <blf.h>
#पूर्ण_अगर

#समावेश "crypto_api.h"
#अगर_घोषित SHA512_DIGEST_लंबाई
# undef SHA512_DIGEST_लंबाई
#पूर्ण_अगर
#घोषणा SHA512_DIGEST_लंबाई crypto_hash_sha512_BYTES

#घोषणा	MINIMUM(a,b) (((a) < (b)) ? (a) : (b))

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

#घोषणा BCRYPT_शब्दगण 8
#घोषणा BCRYPT_HASHSIZE (BCRYPT_शब्दगण * 4)

अटल व्योम
bcrypt_hash(uint8_t *sha2pass, uint8_t *sha2salt, uint8_t *out)
{
	blf_ctx state;
	uint8_t __attribute__ ((__nonstring__)) ciphertext[BCRYPT_HASHSIZE] =
	    "OxychromaticBlowfishSwatDynamite";
	uint32_t cdata[BCRYPT_शब्दगण];
	पूर्णांक i;
	uint16_t j;
	माप_प्रकार shalen = SHA512_DIGEST_लंबाई;

	/* key expansion */
	Blowfish_initstate(&state);
	Blowfish_expandstate(&state, sha2salt, shalen, sha2pass, shalen);
	क्रम (i = 0; i < 64; i++) {
		Blowfish_expand0state(&state, sha2salt, shalen);
		Blowfish_expand0state(&state, sha2pass, shalen);
	}

	/* encryption */
	j = 0;
	क्रम (i = 0; i < BCRYPT_शब्दगण; i++)
		cdata[i] = Blowfish_stream2word(ciphertext, माप(ciphertext),
		    &j);
	क्रम (i = 0; i < 64; i++)
		blf_enc(&state, cdata, BCRYPT_शब्दगण / 2);

	/* copy out */
	क्रम (i = 0; i < BCRYPT_शब्दगण; i++) {
		out[4 * i + 3] = (cdata[i] >> 24) & 0xff;
		out[4 * i + 2] = (cdata[i] >> 16) & 0xff;
		out[4 * i + 1] = (cdata[i] >> 8) & 0xff;
		out[4 * i + 0] = cdata[i] & 0xff;
	}

	/* zap */
	explicit_bzero(ciphertext, माप(ciphertext));
	explicit_bzero(cdata, माप(cdata));
	explicit_bzero(&state, माप(state));
}

पूर्णांक
bcrypt_pbkdf(स्थिर अक्षर *pass, माप_प्रकार passlen, स्थिर uint8_t *salt, माप_प्रकार saltlen,
    uint8_t *कुंजी, माप_प्रकार keylen, अचिन्हित पूर्णांक rounds)
{
	uint8_t sha2pass[SHA512_DIGEST_लंबाई];
	uint8_t sha2salt[SHA512_DIGEST_लंबाई];
	uint8_t out[BCRYPT_HASHSIZE];
	uint8_t tmpout[BCRYPT_HASHSIZE];
	uint8_t *countsalt;
	माप_प्रकार i, j, amt, stride;
	uint32_t गिनती;
	माप_प्रकार origkeylen = keylen;

	/* nothing crazy */
	अगर (rounds < 1)
		जाओ bad;
	अगर (passlen == 0 || saltlen == 0 || keylen == 0 ||
	    keylen > माप(out) * माप(out) || saltlen > 1<<20)
		जाओ bad;
	अगर ((countsalt = सुस्मृति(1, saltlen + 4)) == शून्य)
		जाओ bad;
	stride = (keylen + माप(out) - 1) / माप(out);
	amt = (keylen + stride - 1) / stride;

	स_नकल(countsalt, salt, saltlen);

	/* collapse password */
	crypto_hash_sha512(sha2pass, pass, passlen);

	/* generate key, sizeof(out) at a time */
	क्रम (गिनती = 1; keylen > 0; गिनती++) {
		countsalt[saltlen + 0] = (गिनती >> 24) & 0xff;
		countsalt[saltlen + 1] = (गिनती >> 16) & 0xff;
		countsalt[saltlen + 2] = (गिनती >> 8) & 0xff;
		countsalt[saltlen + 3] = गिनती & 0xff;

		/* first round, salt is salt */
		crypto_hash_sha512(sha2salt, countsalt, saltlen + 4);

		bcrypt_hash(sha2pass, sha2salt, tmpout);
		स_नकल(out, tmpout, माप(out));

		क्रम (i = 1; i < rounds; i++) {
			/* subsequent rounds, salt is previous output */
			crypto_hash_sha512(sha2salt, tmpout, माप(tmpout));
			bcrypt_hash(sha2pass, sha2salt, tmpout);
			क्रम (j = 0; j < माप(out); j++)
				out[j] ^= tmpout[j];
		}

		/*
		 * pbkdf2 deviation: output the key material non-linearly.
		 */
		amt = MINIMUM(amt, keylen);
		क्रम (i = 0; i < amt; i++) {
			माप_प्रकार dest = i * stride + (गिनती - 1);
			अगर (dest >= origkeylen)
				अवरोध;
			कुंजी[dest] = out[i];
		}
		keylen -= i;
	}

	/* zap */
	freezero(countsalt, saltlen + 4);
	explicit_bzero(out, माप(out));
	explicit_bzero(tmpout, माप(tmpout));

	वापस 0;

bad:
	/* overwrite with random in case caller doesn't check return code */
	arc4random_buf(कुंजी, keylen);
	वापस -1;
}
#पूर्ण_अगर /* HAVE_BCRYPT_PBKDF */
