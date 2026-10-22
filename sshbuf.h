/*	$OpenBSD: sshbuf.h,v 1.36 2026/04/07 07:40:40 djm Exp $	*/
/*
 * Copyright (c) 2011 Damien Miller
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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _SSHBUF_H
#ವ್ಯಾಖ್ಯಾನಿಸು _SSHBUF_H

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/ecdsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಇಲ್ಲದಿದ್ದರೆ /* OPENSSL */
#ವ್ಯಾಖ್ಯಾನಿಸು BIGNUM		ಶೂನ್ಯ
#ವ್ಯಾಖ್ಯಾನಿಸು EC_ಕೀಲಿ		ಶೂನ್ಯ
#ವ್ಯಾಖ್ಯಾನಿಸು EC_ಗುಂಪು	ಶೂನ್ಯ
#ವ್ಯಾಖ್ಯಾನಿಸು EC_ಬಿಂದು	ಶೂನ್ಯ
#ವ್ಯಾಖ್ಯಾನಿಸು EVP_PKEY	ಶೂನ್ಯ
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

#ವ್ಯಾಖ್ಯಾನಿಸು SSHBUF_ಗಾತ್ರ_MAX		0x8000000	/* Hard maximum size */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHBUF_REFS_MAX		0x100000	/* Max child buffers */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHBUF_MAX_BIGNUM	(16384 / 8)	/* Max bignum *bytes* */
#ವ್ಯಾಖ್ಯಾನಿಸು SSHBUF_MAX_ECPOINT	((528 * 2 / 8) + 1) /* Max EC point *bytes* */

ರಚನೆ sshbuf;

/*
 * Create a new sshbuf buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
ರಚನೆ sshbuf *sshbuf_new(ಶೂನ್ಯ);

/*
 * Create a new, read-only sshbuf buffer from existing data.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
ರಚನೆ sshbuf *sshbuf_from(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *blob, ಗಾತ್ರ_t len);

/*
 * Create a new, read-only sshbuf buffer from the contents of an existing
 * buffer. The contents of "buf" must not change in the lifetime of the
 * resultant buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
ರಚನೆ sshbuf *sshbuf_fromb(ರಚನೆ sshbuf *buf);

/*
 * Create a new, read-only sshbuf buffer from the contents of a string in
 * an existing buffer (the string is consumed in the process).
 * The contents of "buf" must not change in the lifetime of the resultant
 * buffer.
 * On success, a pointer to the newly allocated buffer is placed in *bufp.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ಪೂರ್ಣಾಂಕ	sshbuf_froms(ರಚನೆ sshbuf *buf, ರಚನೆ sshbuf **bufp);

/*
 * Clear and free buf
 */
ಶೂನ್ಯ	sshbuf_free(ರಚನೆ sshbuf *buf);

/*
 * Reset buf, clearing its contents. NB. max_size is preserved.
 */
ಶೂನ್ಯ	sshbuf_reset(ರಚನೆ sshbuf *buf);

/*
 * Return the maximum size of buf
 */
ಗಾತ್ರ_t	sshbuf_max_ಗಾತ್ರ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf);

/*
 * Set the maximum size of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ಪೂರ್ಣಾಂಕ	sshbuf_ಗಣ_max_ಗಾತ್ರ(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t max_ಗಾತ್ರ);

/*
 * Returns the length of data in buf
 */
ಗಾತ್ರ_t	sshbuf_len(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf);

/*
 * Returns number of bytes left in buffer before hitting max_size.
 */
ಗಾತ್ರ_t	sshbuf_avail(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf);

/*
 * Returns a read-only pointer to the start of the data in buf
 */
ಸ್ಥಿರಾಂಕ u_char *sshbuf_ptr(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf);

/*
 * Returns a mutable pointer to the start of the data in buf, or
 * NULL if the buffer is read-only.
 */
u_char *sshbuf_mutable_ptr(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf);

/*
 * Check whether a reservation of size len will succeed in buf
 * Safer to use than direct comparisons again sshbuf_avail as it copes
 * with unsigned overflows correctly.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ಪೂರ್ಣಾಂಕ	sshbuf_check_reserve(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t len);

/*
 * Preallocates len additional bytes in buf.
 * Useful for cases where the caller knows how many bytes will ultimately be
 * required to avoid realloc in the buffer code.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ಪೂರ್ಣಾಂಕ	sshbuf_allocate(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t len);

/*
 * Reserve len bytes in buf.
 * Returns 0 on success and a pointer to the first reserved byte via the
 * optional dpp parameter or a negative SSH_ERR_* error code on failure.
 */
ಪೂರ್ಣಾಂಕ	sshbuf_reserve(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t len, u_char **dpp);

/*
 * Consume len bytes from the start of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ಪೂರ್ಣಾಂಕ	sshbuf_consume(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t len);

/*
 * Consume len bytes from the end of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ಪೂರ್ಣಾಂಕ	sshbuf_consume_ಕೊನೆ(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t len);

/*
 * Consume data from a parent buffer up to that of a child buffer (i.e.
 * one created by sshbuf_fromb()).
 *
 * Intended to be used in a pattern like:
 *
 *     b = sshbuf_fromb(parent);
 *     sshbuf_get_string(b, &foo, &foostr);
 *     sshbuf_get_u32(b, &bar);
 *     sshbuf_consume_upto_child(parent, b);
 *
 * After which, both "b" and "parent" will point to the same data.
 *
 * "child" must be a direct child of "buf" (i.e. neither an unrelated buffer
 * nor a grandchild) which has consumed data past that of "buf".
 */
ಪೂರ್ಣಾಂಕ	sshbuf_consume_upto_ಮಗು(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *ಮಗು);

/* Extract or deposit some bytes */
ಪೂರ್ಣಾಂಕ	sshbuf_get(ರಚನೆ sshbuf *buf, ಶೂನ್ಯ *v, ಗಾತ್ರ_t len);
ಪೂರ್ಣಾಂಕ	sshbuf_put(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *v, ಗಾತ್ರ_t len);
ಪೂರ್ಣಾಂಕ	sshbuf_putb(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *v);

/* Append using a printf(3) format */
ಪೂರ್ಣಾಂಕ	sshbuf_putf(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
	    __attribute__((format(ಬರೆ, 2, 3)));
ಪೂರ್ಣಾಂಕ	sshbuf_putfv(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, va_list ap);

/* Functions to extract or store big-endian words of various sizes */
ಪೂರ್ಣಾಂಕ	sshbuf_get_u64(ರಚನೆ sshbuf *buf, uint64_t *valp);
ಪೂರ್ಣಾಂಕ	sshbuf_get_u32(ರಚನೆ sshbuf *buf, uint32_t *valp);
ಪೂರ್ಣಾಂಕ	sshbuf_get_u16(ರಚನೆ sshbuf *buf, uint16_t *valp);
ಪೂರ್ಣಾಂಕ	sshbuf_get_u8(ರಚನೆ sshbuf *buf, u_char *valp);
ಪೂರ್ಣಾಂಕ	sshbuf_put_u64(ರಚನೆ sshbuf *buf, uint64_t val);
ಪೂರ್ಣಾಂಕ	sshbuf_put_u32(ರಚನೆ sshbuf *buf, uint32_t val);
ಪೂರ್ಣಾಂಕ	sshbuf_put_u16(ರಚನೆ sshbuf *buf, uint16_t val);
ಪೂರ್ಣಾಂಕ	sshbuf_put_u8(ರಚನೆ sshbuf *buf, u_char val);

/* Functions to peek at the contents of a buffer without modifying it. */
ಪೂರ್ಣಾಂಕ	sshbuf_peek_u64(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ,
    uint64_t *valp);
ಪೂರ್ಣಾಂಕ	sshbuf_peek_u32(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ,
    uint32_t *valp);
ಪೂರ್ಣಾಂಕ	sshbuf_peek_u16(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ,
    uint16_t *valp);
ಪೂರ್ಣಾಂಕ	sshbuf_peek_u8(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ,
    u_char *valp);

/*
 * Functions to poke values into an existing buffer (e.g. a length header
 * to a packet). The destination bytes must already exist in the buffer.
 */
ಪೂರ್ಣಾಂಕ sshbuf_poke_u64(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ, uint64_t val);
ಪೂರ್ಣಾಂಕ sshbuf_poke_u32(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ, uint32_t val);
ಪೂರ್ಣಾಂಕ sshbuf_poke_u16(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ, uint16_t val);
ಪೂರ್ಣಾಂಕ sshbuf_poke_u8(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ, u_char val);
ಪೂರ್ಣಾಂಕ sshbuf_poke(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ, ಶೂನ್ಯ *v, ಗಾತ್ರ_t len);

/*
 * Functions to extract or store SSH wire encoded strings (u32 len || data)
 * The "cstring" variants admit no \0 characters in the string contents.
 * Caller must free *valp.
 */
ಪೂರ್ಣಾಂಕ	sshbuf_get_string(ರಚನೆ sshbuf *buf, u_char **valp, ಗಾತ್ರ_t *lenp);
ಪೂರ್ಣಾಂಕ	sshbuf_get_cstring(ರಚನೆ sshbuf *buf, ಅಕ್ಷರ **valp, ಗಾತ್ರ_t *lenp);
ಪೂರ್ಣಾಂಕ	sshbuf_get_stringb(ರಚನೆ sshbuf *buf, ರಚನೆ sshbuf *v);
ಪೂರ್ಣಾಂಕ	sshbuf_put_string(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *v, ಗಾತ್ರ_t len);
ಪೂರ್ಣಾಂಕ	sshbuf_put_cstring(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *v);
ಪೂರ್ಣಾಂಕ	sshbuf_put_stringb(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *v);

/*
 * "Direct" variant of sshbuf_get_string, returns pointer into the sshbuf to
 * avoid an malloc+memcpy. The pointer is guaranteed to be valid until the
 * next sshbuf-modifying function call. Caller does not free.
 */
ಪೂರ್ಣಾಂಕ	sshbuf_get_string_ನೇರ(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ u_char **valp,
	    ಗಾತ್ರ_t *lenp);

/* Skip past a string */
#ವ್ಯಾಖ್ಯಾನಿಸು sshbuf_skip_string(buf) sshbuf_get_string_ನೇರ(buf, ಖಾಲಿ, ಖಾಲಿ)

/* Another variant: "peeks" into the buffer without modifying it */
ಪೂರ್ಣಾಂಕ	sshbuf_peek_string_ನೇರ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ u_char **valp,
	    ಗಾತ್ರ_t *lenp);

/*
 * Functions to extract or store SSH wire encoded bignums and elliptic
 * curve points.
 */
ಪೂರ್ಣಾಂಕ	sshbuf_get_bignum2(ರಚನೆ sshbuf *buf, BIGNUM **valp);
ಪೂರ್ಣಾಂಕ	sshbuf_get_bignum2_ಬೈಟುಗಳು_ನೇರ(ರಚನೆ sshbuf *buf,
	    ಸ್ಥಿರಾಂಕ u_char **valp, ಗಾತ್ರ_t *lenp);
ಪೂರ್ಣಾಂಕ	sshbuf_put_bignum2(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ BIGNUM *v);
ಪೂರ್ಣಾಂಕ	sshbuf_put_bignum2_ಬೈಟುಗಳು(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *v, ಗಾತ್ರ_t len);
ಪೂರ್ಣಾಂಕ	sshbuf_get_ec(ರಚನೆ sshbuf *buf, EC_ಬಿಂದು *v, ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *g);
ಪೂರ್ಣಾಂಕ	sshbuf_get_eckey(ರಚನೆ sshbuf *buf, EC_ಕೀಲಿ *v);
ಪೂರ್ಣಾಂಕ	sshbuf_put_ec(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ EC_ಬಿಂದು *v, ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *g);
ಪೂರ್ಣಾಂಕ	sshbuf_put_eckey(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ EC_ಕೀಲಿ *v);
ಪೂರ್ಣಾಂಕ	sshbuf_put_ec_pkey(ರಚನೆ sshbuf *buf, EVP_PKEY *pkey);

/* Functions to extract or store various non-SSH wire encoded values */
ಪೂರ್ಣಾಂಕ	sshbuf_get_nulterminated_string(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t maxlen,
	    ಅಕ್ಷರ **valp, ಗಾತ್ರ_t *lenp);

/* Dump the contents of the buffer in a human-readable format */
ಶೂನ್ಯ	sshbuf_dump(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf, FILE *f);

/* Dump specified memory in a human-readable format */
ಶೂನ್ಯ	sshbuf_dump_ದತ್ತಾಂಶ(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *s, ಗಾತ್ರ_t len, FILE *f);

/* Return the hexadecimal representation of the contents of the buffer */
ಅಕ್ಷರ	*sshbuf_dtob16(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf);
/* Make a sshbuf from a hex string */
ರಚನೆ sshbuf *sshbuf_b16tod(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *b16);

/* Encode the contents of the buffer as base64 */
ಅಕ್ಷರ	*sshbuf_dtob64_string(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf, ಪೂರ್ಣಾಂಕ wrap);
ಪೂರ್ಣಾಂಕ	sshbuf_dtob64(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *d, ರಚನೆ sshbuf *b64, ಪೂರ್ಣಾಂಕ wrap);
/* RFC4648 "base64url" encoding variant */
ಪೂರ್ಣಾಂಕ	sshbuf_dtourlb64(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *d, ರಚನೆ sshbuf *b64, ಪೂರ್ಣಾಂಕ wrap);

/* Decode base64 data and append it to the buffer */
ಪೂರ್ಣಾಂಕ	sshbuf_b64tod(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *b64);

/*
 * Tests whether the buffer contains the specified byte sequence at the
 * specified offset. Returns 0 on successful match, or a ssherr.h code
 * otherwise. SSH_ERR_INVALID_FORMAT indicates sufficient bytes were
 * present but the buffer contents did not match those supplied. Zero-
 * length comparisons are not allowed.
 *
 * If sufficient data is present to make a comparison, then it is
 * performed with timing independent of the value of the data. If
 * insufficient data is present then the comparison is not attempted at
 * all.
 */
ಪೂರ್ಣಾಂಕ	sshbuf_cmp(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *b, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ,
    ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *s, ಗಾತ್ರ_t len);

/*
 * Test whether two buffers have identical contents.
 * SSH_ERR_MESSAGE_INCOMPLETE indicates the buffers had differing size.
 * SSH_ERR_INVALID_FORMAT indicates the buffers were the same size but
 * had differing contents.
 * Returns 0 on successful compare (comparing two empty buffers returns 0).
 */
ಪೂರ್ಣಾಂಕ sshbuf_equals(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *a, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *b);

/*
 * Searches the buffer for the specified string. Returns 0 on success
 * and updates *offsetp with the offset of the first match, relative to
 * the start of the buffer. Otherwise sshbuf_find will return a ssherr.h
 * error code. SSH_ERR_INVALID_FORMAT indicates sufficient bytes were
 * present in the buffer for a match to be possible but none was found.
 * Searches for zero-length data are not allowed.
 */
ಪೂರ್ಣಾಂಕ
sshbuf_ಕಂಡುಹಿಡಿ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *b, ಗಾತ್ರ_t ಆರಂಭ_ಸ್ಥಾನಾಂತರ,
    ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *s, ಗಾತ್ರ_t len, ಗಾತ್ರ_t *offsetp);

/*
 * Duplicate the contents of a buffer to a string (caller to free).
 * Returns NULL on buffer error, or if the buffer contains a premature
 * nul character.
 */
ಅಕ್ಷರ *sshbuf_dup_string(ರಚನೆ sshbuf *buf);

/*
 * Fill a buffer from a file descriptor or filename. Both allocate the
 * buffer for the caller.
 */
ಪೂರ್ಣಾಂಕ sshbuf_ತುಂಬು_fd(ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf **)
    __attribute__((__nonnull__ (2)));
ಪೂರ್ಣಾಂಕ sshbuf_ತುಂಬು_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ರಚನೆ sshbuf **)
    __attribute__((__nonnull__ (2)));

/*
 * Write a buffer to a path, creating/truncating as needed (mode 0644,
 * subject to umask). The buffer contents are not modified.
 */
ಪೂರ್ಣಾಂಕ sshbuf_write_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ರಚನೆ sshbuf *buf)
    __attribute__((__nonnull__ (2)));

/* Read up to maxlen bytes from a fd directly to a buffer */
ಪೂರ್ಣಾಂಕ sshbuf_read(ಪೂರ್ಣಾಂಕ, ರಚನೆ sshbuf *, ಗಾತ್ರ_t, ಗಾತ್ರ_t *)
    __attribute__((__nonnull__ (2)));

/* Macros for decoding/encoding integers */
#ವ್ಯಾಖ್ಯಾನಿಸು PEEK_U64(p) \
	(((uint64_t)(((ಸ್ಥಿರಾಂಕ u_char *)(p))[0]) << 56) | \
	 ((uint64_t)(((ಸ್ಥಿರಾಂಕ u_char *)(p))[1]) << 48) | \
	 ((uint64_t)(((ಸ್ಥಿರಾಂಕ u_char *)(p))[2]) << 40) | \
	 ((uint64_t)(((ಸ್ಥಿರಾಂಕ u_char *)(p))[3]) << 32) | \
	 ((uint64_t)(((ಸ್ಥಿರಾಂಕ u_char *)(p))[4]) << 24) | \
	 ((uint64_t)(((ಸ್ಥಿರಾಂಕ u_char *)(p))[5]) << 16) | \
	 ((uint64_t)(((ಸ್ಥಿರಾಂಕ u_char *)(p))[6]) << 8) | \
	  (uint64_t)(((ಸ್ಥಿರಾಂಕ u_char *)(p))[7]))
#ವ್ಯಾಖ್ಯಾನಿಸು PEEK_U32(p) \
	(((uint32_t)(((ಸ್ಥಿರಾಂಕ u_char *)(p))[0]) << 24) | \
	 ((uint32_t)(((ಸ್ಥಿರಾಂಕ u_char *)(p))[1]) << 16) | \
	 ((uint32_t)(((ಸ್ಥಿರಾಂಕ u_char *)(p))[2]) << 8) | \
	  (uint32_t)(((ಸ್ಥಿರಾಂಕ u_char *)(p))[3]))
#ವ್ಯಾಖ್ಯಾನಿಸು PEEK_U16(p) \
	(((uint16_t)(((ಸ್ಥಿರಾಂಕ u_char *)(p))[0]) << 8) | \
	  (uint16_t)(((ಸ್ಥಿರಾಂಕ u_char *)(p))[1]))

#ವ್ಯಾಖ್ಯಾನಿಸು POKE_U64(p, v) \
	ಮಾಡು { \
		ಸ್ಥಿರಾಂಕ uint64_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 56) & 0xff; \
		((u_char *)(p))[1] = (__v >> 48) & 0xff; \
		((u_char *)(p))[2] = (__v >> 40) & 0xff; \
		((u_char *)(p))[3] = (__v >> 32) & 0xff; \
		((u_char *)(p))[4] = (__v >> 24) & 0xff; \
		((u_char *)(p))[5] = (__v >> 16) & 0xff; \
		((u_char *)(p))[6] = (__v >> 8) & 0xff; \
		((u_char *)(p))[7] = __v & 0xff; \
	} ಆಗ (0)
#ವ್ಯಾಖ್ಯಾನಿಸು POKE_U32(p, v) \
	ಮಾಡು { \
		ಸ್ಥಿರಾಂಕ uint32_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 24) & 0xff; \
		((u_char *)(p))[1] = (__v >> 16) & 0xff; \
		((u_char *)(p))[2] = (__v >> 8) & 0xff; \
		((u_char *)(p))[3] = __v & 0xff; \
	} ಆಗ (0)
#ವ್ಯಾಖ್ಯಾನಿಸು POKE_U16(p, v) \
	ಮಾಡು { \
		ಸ್ಥಿರಾಂಕ uint16_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 8) & 0xff; \
		((u_char *)(p))[1] = __v & 0xff; \
	} ಆಗ (0)

/* Internal definitions follow. Exposed for regress tests */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSHBUF_ಆಂತರಿಕ

/*
 * Return the allocation size of buf
 */
ಗಾತ್ರ_t	sshbuf_alloc(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf);

/*
 * Increment the reference count of buf.
 */
ಪೂರ್ಣಾಂಕ	sshbuf_ಗಣ_ಪೋಷಕ(ರಚನೆ sshbuf *ಮಗು, ರಚನೆ sshbuf *ಪೋಷಕ);

/*
 * Return the parent buffer of buf, or NULL if it has no parent.
 */
ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *sshbuf_ಪೋಷಕ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf);

/*
 * Return the reference count of buf
 */
u_int	sshbuf_refcount(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf);

# define SSHBUF_ಗಾತ್ರ_INIT	256		/* Initial allocation */
# define SSHBUF_ಗಾತ್ರ_INC	256		/* Preferred increment length */
# define SSHBUF_PACK_MIN	8192		/* Minimum packable offset */

/* # define SSHBUF_ABORT abort */
/* # define SSHBUF_DEBUG */

# ifndef SSHBUF_ABORT
#  define SSHBUF_ABORT()
# endif

# ifdef SSHBUF_DEBUG
#  define SSHBUF_DBG(x) ಮಾಡು { \
		ಬರೆ("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		ಬರೆ x; \
		ಬರೆ("\n"); \
		fflush(stdout); \
	} ಆಗ (0)
# ಇಲ್ಲದಿದ್ದರೆ
#  define SSHBUF_DBG(x)
# endif
#ಆದರೆ_ಅಂತ್ಯ /* SSHBUF_INTERNAL */

#ಆದರೆ_ಅಂತ್ಯ /* _SSHBUF_H */
