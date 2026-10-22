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

#అన్తర్భావ "includes.h"

#నిర్వచితం_కాకపోతే HAVE_BCRYPT_PBKDF

#అన్తర్భావ <sys/types.h>

#నిర్వచితమైతే HAVE_STDLIB_H
# include <stdlib.h>
#అయితే_ముగింపు
#అన్తర్భావ <string.h>

#నిర్వచితమైతే HAVE_BLF_H
# include <blf.h>
#అయితే_ముగింపు

#అన్తర్భావ "crypto_api.h"
#నిర్వచితమైతే SHA512_DIGEST_నిడివి
# undef SHA512_DIGEST_నిడివి
#అయితే_ముగింపు
#నిర్వచించు SHA512_DIGEST_నిడివి crypto_hash_sha512_బైట్లు

#నిర్వచించు	MINIMUM(a,b) (((a) < (b)) ? (a) : (b))

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

#నిర్వచించు BCRYPT_పదాలు 8
#నిర్వచించు BCRYPT_HASHSIZE (BCRYPT_పదాలు * 4)

స్థిర శూన్య
bcrypt_hash(uint8_t *sha2pass, uint8_t *sha2salt, uint8_t *బహిర్గతం)
{
	blf_ctx state;
	uint8_t __attribute__ ((__nonstring__)) ciphertext[BCRYPT_HASHSIZE] =
	    "OxychromaticBlowfishSwatDynamite";
	uint32_t cdata[BCRYPT_పదాలు];
	పూర్ణాంకం i;
	uint16_t j;
	కొలత_t shalen = SHA512_DIGEST_నిడివి;

	/* key expansion */
	Blowfish_initstate(&state);
	Blowfish_expandstate(&state, sha2salt, shalen, sha2pass, shalen);
	కొరకు (i = 0; i < 64; i++) {
		Blowfish_expand0state(&state, sha2salt, shalen);
		Blowfish_expand0state(&state, sha2pass, shalen);
	}

	/* encryption */
	j = 0;
	కొరకు (i = 0; i < BCRYPT_పదాలు; i++)
		cdata[i] = Blowfish_stream2word(ciphertext, పరిమాణం(ciphertext),
		    &j);
	కొరకు (i = 0; i < 64; i++)
		blf_enc(&state, cdata, BCRYPT_పదాలు / 2);

	/* copy out */
	కొరకు (i = 0; i < BCRYPT_పదాలు; i++) {
		బహిర్గతం[4 * i + 3] = (cdata[i] >> 24) & 0xff;
		బహిర్గతం[4 * i + 2] = (cdata[i] >> 16) & 0xff;
		బహిర్గతం[4 * i + 1] = (cdata[i] >> 8) & 0xff;
		బహిర్గతం[4 * i + 0] = cdata[i] & 0xff;
	}

	/* zap */
	explicit_bzero(ciphertext, పరిమాణం(ciphertext));
	explicit_bzero(cdata, పరిమాణం(cdata));
	explicit_bzero(&state, పరిమాణం(state));
}

పూర్ణాంకం
bcrypt_pbkdf(స్థిరరాశి అక్షరం *pass, కొలత_t passlen, స్థిరరాశి uint8_t *salt, కొలత_t saltlen,
    uint8_t *కీలకం, కొలత_t keylen, గుర్తులేని పూర్ణాంకం విడతలు)
{
	uint8_t sha2pass[SHA512_DIGEST_నిడివి];
	uint8_t sha2salt[SHA512_DIGEST_నిడివి];
	uint8_t బహిర్గతం[BCRYPT_HASHSIZE];
	uint8_t tmpout[BCRYPT_HASHSIZE];
	uint8_t *countsalt;
	కొలత_t i, j, amt, stride;
	uint32_t లెక్క;
	కొలత_t origkeylen = keylen;

	/* nothing crazy */
	ఒకవేళ (విడతలు < 1)
		వెళ్ళు bad;
	ఒకవేళ (passlen == 0 || saltlen == 0 || keylen == 0 ||
	    keylen > పరిమాణం(బహిర్గతం) * పరిమాణం(బహిర్గతం) || saltlen > 1<<20)
		వెళ్ళు bad;
	ఒకవేళ ((countsalt = సున్నా_జ్ఞాపకం_ఇవ్వు(1, saltlen + 4)) == ఖాళీ)
		వెళ్ళు bad;
	stride = (keylen + పరిమాణం(బహిర్గతం) - 1) / పరిమాణం(బహిర్గతం);
	amt = (keylen + stride - 1) / stride;

	జ్ఞాపకం_నకలు(countsalt, salt, saltlen);

	/* collapse password */
	crypto_hash_sha512(sha2pass, pass, passlen);

	/* generate key, sizeof(out) at a time */
	కొరకు (లెక్క = 1; keylen > 0; లెక్క++) {
		countsalt[saltlen + 0] = (లెక్క >> 24) & 0xff;
		countsalt[saltlen + 1] = (లెక్క >> 16) & 0xff;
		countsalt[saltlen + 2] = (లెక్క >> 8) & 0xff;
		countsalt[saltlen + 3] = లెక్క & 0xff;

		/* first round, salt is salt */
		crypto_hash_sha512(sha2salt, countsalt, saltlen + 4);

		bcrypt_hash(sha2pass, sha2salt, tmpout);
		జ్ఞాపకం_నకలు(బహిర్గతం, tmpout, పరిమాణం(బహిర్గతం));

		కొరకు (i = 1; i < విడతలు; i++) {
			/* subsequent rounds, salt is previous output */
			crypto_hash_sha512(sha2salt, tmpout, పరిమాణం(tmpout));
			bcrypt_hash(sha2pass, sha2salt, tmpout);
			కొరకు (j = 0; j < పరిమాణం(బహిర్గతం); j++)
				బహిర్గతం[j] ^= tmpout[j];
		}

		/*
		 * pbkdf2 deviation: output the key material non-linearly.
		 */
		amt = MINIMUM(amt, keylen);
		కొరకు (i = 0; i < amt; i++) {
			కొలత_t dest = i * stride + (లెక్క - 1);
			ఒకవేళ (dest >= origkeylen)
				ఆపు;
			కీలకం[dest] = బహిర్గతం[i];
		}
		keylen -= i;
	}

	/* zap */
	freezero(countsalt, saltlen + 4);
	explicit_bzero(బహిర్గతం, పరిమాణం(బహిర్గతం));
	explicit_bzero(tmpout, పరిమాణం(tmpout));

	తిరిగి 0;

bad:
	/* overwrite with random in case caller doesn't check return code */
	arc4random_buf(కీలకం, keylen);
	తిరిగి -1;
}
#అయితే_ముగింపు /* HAVE_BCRYPT_PBKDF */
