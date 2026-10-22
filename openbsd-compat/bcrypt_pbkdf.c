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

#ضمن "includes.h"

#جے_بنا_تعریف HAVE_BCRYPT_PBKDF

#ضمن <sys/types.h>

#جے_تعریف_شدہ HAVE_STDLIB_H
# include <stdlib.h>
#جے_انت
#ضمن <string.h>

#جے_تعریف_شدہ HAVE_BLF_H
# include <blf.h>
#جے_انت

#ضمن "crypto_api.h"
#جے_تعریف_شدہ SHA512_DIGEST_لمائی
# undef SHA512_DIGEST_لمائی
#جے_انت
#تعریف_کرو SHA512_DIGEST_لمائی crypto_hash_sha512_بائٹاں

#تعریف_کرو	MINIMUM(a,b) (((a) < (b)) ? (a) : (b))

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

#تعریف_کرو BCRYPT_الفاظ 8
#تعریف_کرو BCRYPT_HASHSIZE (BCRYPT_الفاظ * 4)

ساكن فراغ
bcrypt_hash(uint8_t *sha2pass, uint8_t *sha2salt, uint8_t *باہرلا)
{
	blf_ctx state;
	uint8_t __attribute__ ((__nonstring__)) ciphertext[BCRYPT_HASHSIZE] =
	    "OxychromaticBlowfishSwatDynamite";
	uint32_t cdata[BCRYPT_الفاظ];
	صحيح i;
	uint16_t j;
	ناپ_t shalen = SHA512_DIGEST_لمائی;

	/* key expansion */
	Blowfish_initstate(&state);
	Blowfish_expandstate(&state, sha2salt, shalen, sha2pass, shalen);
	لكل (i = 0; i < 64; i++) {
		Blowfish_expand0state(&state, sha2salt, shalen);
		Blowfish_expand0state(&state, sha2pass, shalen);
	}

	/* encryption */
	j = 0;
	لكل (i = 0; i < BCRYPT_الفاظ; i++)
		cdata[i] = Blowfish_stream2word(ciphertext, حجم(ciphertext),
		    &j);
	لكل (i = 0; i < 64; i++)
		blf_enc(&state, cdata, BCRYPT_الفاظ / 2);

	/* copy out */
	لكل (i = 0; i < BCRYPT_الفاظ; i++) {
		باہرلا[4 * i + 3] = (cdata[i] >> 24) & 0xff;
		باہرلا[4 * i + 2] = (cdata[i] >> 16) & 0xff;
		باہرلا[4 * i + 1] = (cdata[i] >> 8) & 0xff;
		باہرلا[4 * i + 0] = cdata[i] & 0xff;
	}

	/* zap */
	explicit_bzero(ciphertext, حجم(ciphertext));
	explicit_bzero(cdata, حجم(cdata));
	explicit_bzero(&state, حجم(state));
}

صحيح
bcrypt_pbkdf(ثابت حرف *pass, ناپ_t passlen, ثابت uint8_t *salt, ناپ_t saltlen,
    uint8_t *کلید, ناپ_t keylen, بنانشانی صحيح گیڑ)
{
	uint8_t sha2pass[SHA512_DIGEST_لمائی];
	uint8_t sha2salt[SHA512_DIGEST_لمائی];
	uint8_t باہرلا[BCRYPT_HASHSIZE];
	uint8_t tmpout[BCRYPT_HASHSIZE];
	uint8_t *countsalt;
	ناپ_t i, j, amt, stride;
	uint32_t گنتی;
	ناپ_t origkeylen = keylen;

	/* nothing crazy */
	إذا (گیڑ < 1)
		اذهب bad;
	إذا (passlen == 0 || saltlen == 0 || keylen == 0 ||
	    keylen > حجم(باہرلا) * حجم(باہرلا) || saltlen > 1<<20)
		اذهب bad;
	إذا ((countsalt = صفر_حافظہ_دیو(1, saltlen + 4)) == عدم)
		اذهب bad;
	stride = (keylen + حجم(باہرلا) - 1) / حجم(باہرلا);
	amt = (keylen + stride - 1) / stride;

	حافظہ_نقل(countsalt, salt, saltlen);

	/* collapse password */
	crypto_hash_sha512(sha2pass, pass, passlen);

	/* generate key, sizeof(out) at a time */
	لكل (گنتی = 1; keylen > 0; گنتی++) {
		countsalt[saltlen + 0] = (گنتی >> 24) & 0xff;
		countsalt[saltlen + 1] = (گنتی >> 16) & 0xff;
		countsalt[saltlen + 2] = (گنتی >> 8) & 0xff;
		countsalt[saltlen + 3] = گنتی & 0xff;

		/* first round, salt is salt */
		crypto_hash_sha512(sha2salt, countsalt, saltlen + 4);

		bcrypt_hash(sha2pass, sha2salt, tmpout);
		حافظہ_نقل(باہرلا, tmpout, حجم(باہرلا));

		لكل (i = 1; i < گیڑ; i++) {
			/* subsequent rounds, salt is previous output */
			crypto_hash_sha512(sha2salt, tmpout, حجم(tmpout));
			bcrypt_hash(sha2pass, sha2salt, tmpout);
			لكل (j = 0; j < حجم(باہرلا); j++)
				باہرلا[j] ^= tmpout[j];
		}

		/*
		 * pbkdf2 deviation: output the key material non-linearly.
		 */
		amt = MINIMUM(amt, keylen);
		لكل (i = 0; i < amt; i++) {
			ناپ_t dest = i * stride + (گنتی - 1);
			إذا (dest >= origkeylen)
				اكسر;
			کلید[dest] = باہرلا[i];
		}
		keylen -= i;
	}

	/* zap */
	freezero(countsalt, saltlen + 4);
	explicit_bzero(باہرلا, حجم(باہرلا));
	explicit_bzero(tmpout, حجم(tmpout));

	أرجع 0;

bad:
	/* overwrite with random in case caller doesn't check return code */
	arc4random_buf(کلید, keylen);
	أرجع -1;
}
#جے_انت /* HAVE_BCRYPT_PBKDF */
