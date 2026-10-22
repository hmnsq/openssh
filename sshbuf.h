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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _SSHBUF_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _SSHBUF_H

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ec.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ecdsa.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
#ਨਹੀਂਤਾਂ /* OPENSSL */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BIGNUM		ਖਾਲੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ EC_ਕੁੰਜੀ		ਖਾਲੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ EC_ਸਮੂਹ	ਖਾਲੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ EC_ਬਿੰਦੂ	ਖਾਲੀ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ EVP_PKEY	ਖਾਲੀ
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHBUF_ਮਾਪ_MAX		0x8000000	/* Hard maximum size */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHBUF_REFS_MAX		0x100000	/* Max child buffers */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHBUF_MAX_BIGNUM	(16384 / 8)	/* Max bignum *bytes* */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHBUF_MAX_ECPOINT	((528 * 2 / 8) + 1) /* Max EC point *bytes* */

ਬਣਤਰ sshbuf;

/*
 * Create a new sshbuf buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
ਬਣਤਰ sshbuf *sshbuf_new(ਖਾਲੀ);

/*
 * Create a new, read-only sshbuf buffer from existing data.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
ਬਣਤਰ sshbuf *sshbuf_from(ਅਚਲ ਖਾਲੀ *blob, ਮਾਪ_t len);

/*
 * Create a new, read-only sshbuf buffer from the contents of an existing
 * buffer. The contents of "buf" must not change in the lifetime of the
 * resultant buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
ਬਣਤਰ sshbuf *sshbuf_fromb(ਬਣਤਰ sshbuf *buf);

/*
 * Create a new, read-only sshbuf buffer from the contents of a string in
 * an existing buffer (the string is consumed in the process).
 * The contents of "buf" must not change in the lifetime of the resultant
 * buffer.
 * On success, a pointer to the newly allocated buffer is placed in *bufp.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ਪੂਰਨ	sshbuf_froms(ਬਣਤਰ sshbuf *buf, ਬਣਤਰ sshbuf **bufp);

/*
 * Clear and free buf
 */
ਖਾਲੀ	sshbuf_free(ਬਣਤਰ sshbuf *buf);

/*
 * Reset buf, clearing its contents. NB. max_size is preserved.
 */
ਖਾਲੀ	sshbuf_reset(ਬਣਤਰ sshbuf *buf);

/*
 * Return the maximum size of buf
 */
ਮਾਪ_t	sshbuf_max_ਮਾਪ(ਅਚਲ ਬਣਤਰ sshbuf *buf);

/*
 * Set the maximum size of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ਪੂਰਨ	sshbuf_ਸੈੱਟ_max_ਮਾਪ(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t max_ਮਾਪ);

/*
 * Returns the length of data in buf
 */
ਮਾਪ_t	sshbuf_len(ਅਚਲ ਬਣਤਰ sshbuf *buf);

/*
 * Returns number of bytes left in buffer before hitting max_size.
 */
ਮਾਪ_t	sshbuf_avail(ਅਚਲ ਬਣਤਰ sshbuf *buf);

/*
 * Returns a read-only pointer to the start of the data in buf
 */
ਅਚਲ u_char *sshbuf_ptr(ਅਚਲ ਬਣਤਰ sshbuf *buf);

/*
 * Returns a mutable pointer to the start of the data in buf, or
 * NULL if the buffer is read-only.
 */
u_char *sshbuf_mutable_ptr(ਅਚਲ ਬਣਤਰ sshbuf *buf);

/*
 * Check whether a reservation of size len will succeed in buf
 * Safer to use than direct comparisons again sshbuf_avail as it copes
 * with unsigned overflows correctly.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ਪੂਰਨ	sshbuf_check_reserve(ਅਚਲ ਬਣਤਰ sshbuf *buf, ਮਾਪ_t len);

/*
 * Preallocates len additional bytes in buf.
 * Useful for cases where the caller knows how many bytes will ultimately be
 * required to avoid realloc in the buffer code.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ਪੂਰਨ	sshbuf_allocate(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t len);

/*
 * Reserve len bytes in buf.
 * Returns 0 on success and a pointer to the first reserved byte via the
 * optional dpp parameter or a negative SSH_ERR_* error code on failure.
 */
ਪੂਰਨ	sshbuf_reserve(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t len, u_char **dpp);

/*
 * Consume len bytes from the start of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ਪੂਰਨ	sshbuf_consume(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t len);

/*
 * Consume len bytes from the end of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ਪੂਰਨ	sshbuf_consume_ਸਿਰਾ(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t len);

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
ਪੂਰਨ	sshbuf_consume_upto_ਬੱਚਾ(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਬਣਤਰ sshbuf *ਬੱਚਾ);

/* Extract or deposit some bytes */
ਪੂਰਨ	sshbuf_get(ਬਣਤਰ sshbuf *buf, ਖਾਲੀ *v, ਮਾਪ_t len);
ਪੂਰਨ	sshbuf_put(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਖਾਲੀ *v, ਮਾਪ_t len);
ਪੂਰਨ	sshbuf_putb(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਬਣਤਰ sshbuf *v);

/* Append using a printf(3) format */
ਪੂਰਨ	sshbuf_putf(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਅੱਖਰ *fmt, ...)
	    __attribute__((format(ਲਿਖੋ, 2, 3)));
ਪੂਰਨ	sshbuf_putfv(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਅੱਖਰ *fmt, va_list ap);

/* Functions to extract or store big-endian words of various sizes */
ਪੂਰਨ	sshbuf_get_u64(ਬਣਤਰ sshbuf *buf, uint64_t *valp);
ਪੂਰਨ	sshbuf_get_u32(ਬਣਤਰ sshbuf *buf, uint32_t *valp);
ਪੂਰਨ	sshbuf_get_u16(ਬਣਤਰ sshbuf *buf, uint16_t *valp);
ਪੂਰਨ	sshbuf_get_u8(ਬਣਤਰ sshbuf *buf, u_char *valp);
ਪੂਰਨ	sshbuf_put_u64(ਬਣਤਰ sshbuf *buf, uint64_t val);
ਪੂਰਨ	sshbuf_put_u32(ਬਣਤਰ sshbuf *buf, uint32_t val);
ਪੂਰਨ	sshbuf_put_u16(ਬਣਤਰ sshbuf *buf, uint16_t val);
ਪੂਰਨ	sshbuf_put_u8(ਬਣਤਰ sshbuf *buf, u_char val);

/* Functions to peek at the contents of a buffer without modifying it. */
ਪੂਰਨ	sshbuf_peek_u64(ਅਚਲ ਬਣਤਰ sshbuf *buf, ਮਾਪ_t ਵਿੱਥ,
    uint64_t *valp);
ਪੂਰਨ	sshbuf_peek_u32(ਅਚਲ ਬਣਤਰ sshbuf *buf, ਮਾਪ_t ਵਿੱਥ,
    uint32_t *valp);
ਪੂਰਨ	sshbuf_peek_u16(ਅਚਲ ਬਣਤਰ sshbuf *buf, ਮਾਪ_t ਵਿੱਥ,
    uint16_t *valp);
ਪੂਰਨ	sshbuf_peek_u8(ਅਚਲ ਬਣਤਰ sshbuf *buf, ਮਾਪ_t ਵਿੱਥ,
    u_char *valp);

/*
 * Functions to poke values into an existing buffer (e.g. a length header
 * to a packet). The destination bytes must already exist in the buffer.
 */
ਪੂਰਨ sshbuf_poke_u64(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t ਵਿੱਥ, uint64_t val);
ਪੂਰਨ sshbuf_poke_u32(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t ਵਿੱਥ, uint32_t val);
ਪੂਰਨ sshbuf_poke_u16(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t ਵਿੱਥ, uint16_t val);
ਪੂਰਨ sshbuf_poke_u8(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t ਵਿੱਥ, u_char val);
ਪੂਰਨ sshbuf_poke(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t ਵਿੱਥ, ਖਾਲੀ *v, ਮਾਪ_t len);

/*
 * Functions to extract or store SSH wire encoded strings (u32 len || data)
 * The "cstring" variants admit no \0 characters in the string contents.
 * Caller must free *valp.
 */
ਪੂਰਨ	sshbuf_get_string(ਬਣਤਰ sshbuf *buf, u_char **valp, ਮਾਪ_t *lenp);
ਪੂਰਨ	sshbuf_get_cstring(ਬਣਤਰ sshbuf *buf, ਅੱਖਰ **valp, ਮਾਪ_t *lenp);
ਪੂਰਨ	sshbuf_get_stringb(ਬਣਤਰ sshbuf *buf, ਬਣਤਰ sshbuf *v);
ਪੂਰਨ	sshbuf_put_string(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਖਾਲੀ *v, ਮਾਪ_t len);
ਪੂਰਨ	sshbuf_put_cstring(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਅੱਖਰ *v);
ਪੂਰਨ	sshbuf_put_stringb(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਬਣਤਰ sshbuf *v);

/*
 * "Direct" variant of sshbuf_get_string, returns pointer into the sshbuf to
 * avoid an malloc+memcpy. The pointer is guaranteed to be valid until the
 * next sshbuf-modifying function call. Caller does not free.
 */
ਪੂਰਨ	sshbuf_get_string_ਸਿੱਧਾ(ਬਣਤਰ sshbuf *buf, ਅਚਲ u_char **valp,
	    ਮਾਪ_t *lenp);

/* Skip past a string */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ sshbuf_skip_string(buf) sshbuf_get_string_ਸਿੱਧਾ(buf, ਨਿਰਾ, ਨਿਰਾ)

/* Another variant: "peeks" into the buffer without modifying it */
ਪੂਰਨ	sshbuf_peek_string_ਸਿੱਧਾ(ਅਚਲ ਬਣਤਰ sshbuf *buf, ਅਚਲ u_char **valp,
	    ਮਾਪ_t *lenp);

/*
 * Functions to extract or store SSH wire encoded bignums and elliptic
 * curve points.
 */
ਪੂਰਨ	sshbuf_get_bignum2(ਬਣਤਰ sshbuf *buf, BIGNUM **valp);
ਪੂਰਨ	sshbuf_get_bignum2_ਬਾਈਟਾਂ_ਸਿੱਧਾ(ਬਣਤਰ sshbuf *buf,
	    ਅਚਲ u_char **valp, ਮਾਪ_t *lenp);
ਪੂਰਨ	sshbuf_put_bignum2(ਬਣਤਰ sshbuf *buf, ਅਚਲ BIGNUM *v);
ਪੂਰਨ	sshbuf_put_bignum2_ਬਾਈਟਾਂ(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਖਾਲੀ *v, ਮਾਪ_t len);
ਪੂਰਨ	sshbuf_get_ec(ਬਣਤਰ sshbuf *buf, EC_ਬਿੰਦੂ *v, ਅਚਲ EC_ਸਮੂਹ *g);
ਪੂਰਨ	sshbuf_get_eckey(ਬਣਤਰ sshbuf *buf, EC_ਕੁੰਜੀ *v);
ਪੂਰਨ	sshbuf_put_ec(ਬਣਤਰ sshbuf *buf, ਅਚਲ EC_ਬਿੰਦੂ *v, ਅਚਲ EC_ਸਮੂਹ *g);
ਪੂਰਨ	sshbuf_put_eckey(ਬਣਤਰ sshbuf *buf, ਅਚਲ EC_ਕੁੰਜੀ *v);
ਪੂਰਨ	sshbuf_put_ec_pkey(ਬਣਤਰ sshbuf *buf, EVP_PKEY *pkey);

/* Functions to extract or store various non-SSH wire encoded values */
ਪੂਰਨ	sshbuf_get_nulterminated_string(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t maxlen,
	    ਅੱਖਰ **valp, ਮਾਪ_t *lenp);

/* Dump the contents of the buffer in a human-readable format */
ਖਾਲੀ	sshbuf_dump(ਅਚਲ ਬਣਤਰ sshbuf *buf, FILE *f);

/* Dump specified memory in a human-readable format */
ਖਾਲੀ	sshbuf_dump_ਅੰਕੜੇ(ਅਚਲ ਖਾਲੀ *s, ਮਾਪ_t len, FILE *f);

/* Return the hexadecimal representation of the contents of the buffer */
ਅੱਖਰ	*sshbuf_dtob16(ਅਚਲ ਬਣਤਰ sshbuf *buf);
/* Make a sshbuf from a hex string */
ਬਣਤਰ sshbuf *sshbuf_b16tod(ਅਚਲ ਅੱਖਰ *b16);

/* Encode the contents of the buffer as base64 */
ਅੱਖਰ	*sshbuf_dtob64_string(ਅਚਲ ਬਣਤਰ sshbuf *buf, ਪੂਰਨ wrap);
ਪੂਰਨ	sshbuf_dtob64(ਅਚਲ ਬਣਤਰ sshbuf *d, ਬਣਤਰ sshbuf *b64, ਪੂਰਨ wrap);
/* RFC4648 "base64url" encoding variant */
ਪੂਰਨ	sshbuf_dtourlb64(ਅਚਲ ਬਣਤਰ sshbuf *d, ਬਣਤਰ sshbuf *b64, ਪੂਰਨ wrap);

/* Decode base64 data and append it to the buffer */
ਪੂਰਨ	sshbuf_b64tod(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਅੱਖਰ *b64);

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
ਪੂਰਨ	sshbuf_cmp(ਅਚਲ ਬਣਤਰ sshbuf *b, ਮਾਪ_t ਵਿੱਥ,
    ਅਚਲ ਖਾਲੀ *s, ਮਾਪ_t len);

/*
 * Test whether two buffers have identical contents.
 * SSH_ERR_MESSAGE_INCOMPLETE indicates the buffers had differing size.
 * SSH_ERR_INVALID_FORMAT indicates the buffers were the same size but
 * had differing contents.
 * Returns 0 on successful compare (comparing two empty buffers returns 0).
 */
ਪੂਰਨ sshbuf_equals(ਅਚਲ ਬਣਤਰ sshbuf *a, ਅਚਲ ਬਣਤਰ sshbuf *b);

/*
 * Searches the buffer for the specified string. Returns 0 on success
 * and updates *offsetp with the offset of the first match, relative to
 * the start of the buffer. Otherwise sshbuf_find will return a ssherr.h
 * error code. SSH_ERR_INVALID_FORMAT indicates sufficient bytes were
 * present in the buffer for a match to be possible but none was found.
 * Searches for zero-length data are not allowed.
 */
ਪੂਰਨ
sshbuf_ਲੱਭੋ(ਅਚਲ ਬਣਤਰ sshbuf *b, ਮਾਪ_t ਸ਼ੁਰੂ_ਵਿੱਥ,
    ਅਚਲ ਖਾਲੀ *s, ਮਾਪ_t len, ਮਾਪ_t *offsetp);

/*
 * Duplicate the contents of a buffer to a string (caller to free).
 * Returns NULL on buffer error, or if the buffer contains a premature
 * nul character.
 */
ਅੱਖਰ *sshbuf_dup_string(ਬਣਤਰ sshbuf *buf);

/*
 * Fill a buffer from a file descriptor or filename. Both allocate the
 * buffer for the caller.
 */
ਪੂਰਨ sshbuf_ਲੱਦੋ_fd(ਪੂਰਨ, ਬਣਤਰ sshbuf **)
    __attribute__((__nonnull__ (2)));
ਪੂਰਨ sshbuf_ਲੱਦੋ_file(ਅਚਲ ਅੱਖਰ *, ਬਣਤਰ sshbuf **)
    __attribute__((__nonnull__ (2)));

/*
 * Write a buffer to a path, creating/truncating as needed (mode 0644,
 * subject to umask). The buffer contents are not modified.
 */
ਪੂਰਨ sshbuf_write_file(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਬਣਤਰ sshbuf *buf)
    __attribute__((__nonnull__ (2)));

/* Read up to maxlen bytes from a fd directly to a buffer */
ਪੂਰਨ sshbuf_read(ਪੂਰਨ, ਬਣਤਰ sshbuf *, ਮਾਪ_t, ਮਾਪ_t *)
    __attribute__((__nonnull__ (2)));

/* Macros for decoding/encoding integers */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PEEK_U64(p) \
	(((uint64_t)(((ਅਚਲ u_char *)(p))[0]) << 56) | \
	 ((uint64_t)(((ਅਚਲ u_char *)(p))[1]) << 48) | \
	 ((uint64_t)(((ਅਚਲ u_char *)(p))[2]) << 40) | \
	 ((uint64_t)(((ਅਚਲ u_char *)(p))[3]) << 32) | \
	 ((uint64_t)(((ਅਚਲ u_char *)(p))[4]) << 24) | \
	 ((uint64_t)(((ਅਚਲ u_char *)(p))[5]) << 16) | \
	 ((uint64_t)(((ਅਚਲ u_char *)(p))[6]) << 8) | \
	  (uint64_t)(((ਅਚਲ u_char *)(p))[7]))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PEEK_U32(p) \
	(((uint32_t)(((ਅਚਲ u_char *)(p))[0]) << 24) | \
	 ((uint32_t)(((ਅਚਲ u_char *)(p))[1]) << 16) | \
	 ((uint32_t)(((ਅਚਲ u_char *)(p))[2]) << 8) | \
	  (uint32_t)(((ਅਚਲ u_char *)(p))[3]))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PEEK_U16(p) \
	(((uint16_t)(((ਅਚਲ u_char *)(p))[0]) << 8) | \
	  (uint16_t)(((ਅਚਲ u_char *)(p))[1]))

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ POKE_U64(p, v) \
	ਕਰੋ { \
		ਅਚਲ uint64_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 56) & 0xff; \
		((u_char *)(p))[1] = (__v >> 48) & 0xff; \
		((u_char *)(p))[2] = (__v >> 40) & 0xff; \
		((u_char *)(p))[3] = (__v >> 32) & 0xff; \
		((u_char *)(p))[4] = (__v >> 24) & 0xff; \
		((u_char *)(p))[5] = (__v >> 16) & 0xff; \
		((u_char *)(p))[6] = (__v >> 8) & 0xff; \
		((u_char *)(p))[7] = __v & 0xff; \
	} ਜਦੋਂ (0)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ POKE_U32(p, v) \
	ਕਰੋ { \
		ਅਚਲ uint32_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 24) & 0xff; \
		((u_char *)(p))[1] = (__v >> 16) & 0xff; \
		((u_char *)(p))[2] = (__v >> 8) & 0xff; \
		((u_char *)(p))[3] = __v & 0xff; \
	} ਜਦੋਂ (0)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ POKE_U16(p, v) \
	ਕਰੋ { \
		ਅਚਲ uint16_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 8) & 0xff; \
		((u_char *)(p))[1] = __v & 0xff; \
	} ਜਦੋਂ (0)

/* Internal definitions follow. Exposed for regress tests */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSHBUF_ਅੰਦਰੂਨੀ

/*
 * Return the allocation size of buf
 */
ਮਾਪ_t	sshbuf_alloc(ਅਚਲ ਬਣਤਰ sshbuf *buf);

/*
 * Increment the reference count of buf.
 */
ਪੂਰਨ	sshbuf_ਸੈੱਟ_ਮਾਪਾ(ਬਣਤਰ sshbuf *ਬੱਚਾ, ਬਣਤਰ sshbuf *ਮਾਪਾ);

/*
 * Return the parent buffer of buf, or NULL if it has no parent.
 */
ਅਚਲ ਬਣਤਰ sshbuf *sshbuf_ਮਾਪਾ(ਅਚਲ ਬਣਤਰ sshbuf *buf);

/*
 * Return the reference count of buf
 */
u_int	sshbuf_refcount(ਅਚਲ ਬਣਤਰ sshbuf *buf);

# define SSHBUF_ਮਾਪ_INIT	256		/* Initial allocation */
# define SSHBUF_ਮਾਪ_INC	256		/* Preferred increment length */
# define SSHBUF_PACK_MIN	8192		/* Minimum packable offset */

/* # define SSHBUF_ABORT abort */
/* # define SSHBUF_DEBUG */

# ifndef SSHBUF_ABORT
#  define SSHBUF_ABORT()
# endif

# ifdef SSHBUF_DEBUG
#  define SSHBUF_DBG(x) ਕਰੋ { \
		ਲਿਖੋ("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		ਲਿਖੋ x; \
		ਲਿਖੋ("\n"); \
		fflush(stdout); \
	} ਜਦੋਂ (0)
# ਨਹੀਂਤਾਂ
#  define SSHBUF_DBG(x)
# endif
#ਜੇ_ਅੰਤ /* SSHBUF_INTERNAL */

#ਜੇ_ਅੰਤ /* _SSHBUF_H */
