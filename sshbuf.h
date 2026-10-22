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

#ifndef _SSHBUF_H
#define _SSHBUF_H

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/ecdsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ಯಥಾ /* OPENSSL */
#define BIGNUM		ಶೂನ್ಯ
#define EC_ಕೀಲಿ		ಶೂನ್ಯ
#define EC_GROUP	ಶೂನ್ಯ
#define EC_POINT	ಶೂನ್ಯ
#define EVP_PKEY	ಶೂನ್ಯ
#endif /* WITH_OPENSSL */

#define SSHBUF_SIZE_MAX		0x8000000	/* Hard maximum size */
#define SSHBUF_REFS_MAX		0x100000	/* Max child buffers */
#define SSHBUF_MAX_BIGNUM	(16384 / 8)	/* Max bignum *bytes* */
#define SSHBUF_MAX_ECPOINT	((528 * 2 / 8) + 1) /* Max EC point *bytes* */

ಸಂರಚನಾ sshbuf;

/*
 * Create a new sshbuf buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
ಸಂರಚನಾ sshbuf *sshbuf_new(ಶೂನ್ಯ);

/*
 * Create a new, read-only sshbuf buffer from existing data.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
ಸಂರಚನಾ sshbuf *sshbuf_from(ಧ್ರುವ ಶೂನ್ಯ *blob, size_t len);

/*
 * Create a new, read-only sshbuf buffer from the contents of an existing
 * buffer. The contents of "buf" must not change in the lifetime of the
 * resultant buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
ಸಂರಚನಾ sshbuf *sshbuf_fromb(ಸಂರಚನಾ sshbuf *buf);

/*
 * Create a new, read-only sshbuf buffer from the contents of a string in
 * an existing buffer (the string is consumed in the process).
 * The contents of "buf" must not change in the lifetime of the resultant
 * buffer.
 * On success, a pointer to the newly allocated buffer is placed in *bufp.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ಪೂರ್ಣಾಙ್ಕ	sshbuf_froms(ಸಂರಚನಾ sshbuf *buf, ಸಂರಚನಾ sshbuf **bufp);

/*
 * Clear and free buf
 */
ಶೂನ್ಯ	sshbuf_free(ಸಂರಚನಾ sshbuf *buf);

/*
 * Reset buf, clearing its contents. NB. max_size is preserved.
 */
ಶೂನ್ಯ	sshbuf_reset(ಸಂರಚನಾ sshbuf *buf);

/*
 * Return the maximum size of buf
 */
size_t	sshbuf_max_size(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf);

/*
 * Set the maximum size of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ಪೂರ್ಣಾಙ್ಕ	sshbuf_set_max_size(ಸಂರಚನಾ sshbuf *buf, size_t max_size);

/*
 * Returns the length of data in buf
 */
size_t	sshbuf_len(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf);

/*
 * Returns number of bytes left in buffer before hitting max_size.
 */
size_t	sshbuf_avail(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf);

/*
 * Returns a read-only pointer to the start of the data in buf
 */
ಧ್ರುವ u_char *sshbuf_ptr(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf);

/*
 * Returns a mutable pointer to the start of the data in buf, or
 * NULL if the buffer is read-only.
 */
u_char *sshbuf_mutable_ptr(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf);

/*
 * Check whether a reservation of size len will succeed in buf
 * Safer to use than direct comparisons again sshbuf_avail as it copes
 * with unsigned overflows correctly.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ಪೂರ್ಣಾಙ್ಕ	sshbuf_check_reserve(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf, size_t len);

/*
 * Preallocates len additional bytes in buf.
 * Useful for cases where the caller knows how many bytes will ultimately be
 * required to avoid realloc in the buffer code.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ಪೂರ್ಣಾಙ್ಕ	sshbuf_allocate(ಸಂರಚನಾ sshbuf *buf, size_t len);

/*
 * Reserve len bytes in buf.
 * Returns 0 on success and a pointer to the first reserved byte via the
 * optional dpp parameter or a negative SSH_ERR_* error code on failure.
 */
ಪೂರ್ಣಾಙ್ಕ	sshbuf_reserve(ಸಂರಚನಾ sshbuf *buf, size_t len, u_char **dpp);

/*
 * Consume len bytes from the start of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ಪೂರ್ಣಾಙ್ಕ	sshbuf_consume(ಸಂರಚನಾ sshbuf *buf, size_t len);

/*
 * Consume len bytes from the end of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ಪೂರ್ಣಾಙ್ಕ	sshbuf_consume_end(ಸಂರಚನಾ sshbuf *buf, size_t len);

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
ಪೂರ್ಣಾಙ್ಕ	sshbuf_consume_upto_child(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ಸಂರಚನಾ sshbuf *child);

/* Extract or deposit some bytes */
ಪೂರ್ಣಾಙ್ಕ	sshbuf_get(ಸಂರಚನಾ sshbuf *buf, ಶೂನ್ಯ *v, size_t len);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_put(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ಶೂನ್ಯ *v, size_t len);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_putb(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ಸಂರಚನಾ sshbuf *v);

/* Append using a printf(3) format */
ಪೂರ್ಣಾಙ್ಕ	sshbuf_putf(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ವರ್ಣ *fmt, ...)
	    __attribute__((format(printf, 2, 3)));
ಪೂರ್ಣಾಙ್ಕ	sshbuf_putfv(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ವರ್ಣ *fmt, va_list ap);

/* Functions to extract or store big-endian words of various sizes */
ಪೂರ್ಣಾಙ್ಕ	sshbuf_get_u64(ಸಂರಚನಾ sshbuf *buf, uint64_t *valp);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_get_u32(ಸಂರಚನಾ sshbuf *buf, uint32_t *valp);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_get_u16(ಸಂರಚನಾ sshbuf *buf, uint16_t *valp);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_get_u8(ಸಂರಚನಾ sshbuf *buf, u_char *valp);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_put_u64(ಸಂರಚನಾ sshbuf *buf, uint64_t val);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_put_u32(ಸಂರಚನಾ sshbuf *buf, uint32_t val);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_put_u16(ಸಂರಚನಾ sshbuf *buf, uint16_t val);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_put_u8(ಸಂರಚನಾ sshbuf *buf, u_char val);

/* Functions to peek at the contents of a buffer without modifying it. */
ಪೂರ್ಣಾಙ್ಕ	sshbuf_peek_u64(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf, size_t offset,
    uint64_t *valp);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_peek_u32(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf, size_t offset,
    uint32_t *valp);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_peek_u16(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf, size_t offset,
    uint16_t *valp);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_peek_u8(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf, size_t offset,
    u_char *valp);

/*
 * Functions to poke values into an existing buffer (e.g. a length header
 * to a packet). The destination bytes must already exist in the buffer.
 */
ಪೂರ್ಣಾಙ್ಕ sshbuf_poke_u64(ಸಂರಚನಾ sshbuf *buf, size_t offset, uint64_t val);
ಪೂರ್ಣಾಙ್ಕ sshbuf_poke_u32(ಸಂರಚನಾ sshbuf *buf, size_t offset, uint32_t val);
ಪೂರ್ಣಾಙ್ಕ sshbuf_poke_u16(ಸಂರಚನಾ sshbuf *buf, size_t offset, uint16_t val);
ಪೂರ್ಣಾಙ್ಕ sshbuf_poke_u8(ಸಂರಚನಾ sshbuf *buf, size_t offset, u_char val);
ಪೂರ್ಣಾಙ್ಕ sshbuf_poke(ಸಂರಚನಾ sshbuf *buf, size_t offset, ಶೂನ್ಯ *v, size_t len);

/*
 * Functions to extract or store SSH wire encoded strings (u32 len || data)
 * The "cstring" variants admit no \0 characters in the string contents.
 * Caller must free *valp.
 */
ಪೂರ್ಣಾಙ್ಕ	sshbuf_get_string(ಸಂರಚನಾ sshbuf *buf, u_char **valp, size_t *lenp);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_get_cstring(ಸಂರಚನಾ sshbuf *buf, ವರ್ಣ **valp, size_t *lenp);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_get_stringb(ಸಂರಚನಾ sshbuf *buf, ಸಂರಚನಾ sshbuf *v);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_put_string(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ಶೂನ್ಯ *v, size_t len);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_put_cstring(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ವರ್ಣ *v);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_put_stringb(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ಸಂರಚನಾ sshbuf *v);

/*
 * "Direct" variant of sshbuf_get_string, returns pointer into the sshbuf to
 * avoid an malloc+memcpy. The pointer is guaranteed to be valid until the
 * next sshbuf-modifying function call. Caller does not free.
 */
ಪೂರ್ಣಾಙ್ಕ	sshbuf_get_string_direct(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ u_char **valp,
	    size_t *lenp);

/* Skip past a string */
#define sshbuf_skip_string(buf) sshbuf_get_string_direct(buf, ರಿಕ್ತ, ರಿಕ್ತ)

/* Another variant: "peeks" into the buffer without modifying it */
ಪೂರ್ಣಾಙ್ಕ	sshbuf_peek_string_direct(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ u_char **valp,
	    size_t *lenp);

/*
 * Functions to extract or store SSH wire encoded bignums and elliptic
 * curve points.
 */
ಪೂರ್ಣಾಙ್ಕ	sshbuf_get_bignum2(ಸಂರಚನಾ sshbuf *buf, BIGNUM **valp);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_get_bignum2_bytes_direct(ಸಂರಚನಾ sshbuf *buf,
	    ಧ್ರುವ u_char **valp, size_t *lenp);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_put_bignum2(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ BIGNUM *v);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_put_bignum2_bytes(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ಶೂನ್ಯ *v, size_t len);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_get_ec(ಸಂರಚನಾ sshbuf *buf, EC_POINT *v, ಧ್ರುವ EC_GROUP *g);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_get_eckey(ಸಂರಚನಾ sshbuf *buf, EC_ಕೀಲಿ *v);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_put_ec(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ EC_POINT *v, ಧ್ರುವ EC_GROUP *g);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_put_eckey(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ EC_ಕೀಲಿ *v);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_put_ec_pkey(ಸಂರಚನಾ sshbuf *buf, EVP_PKEY *pkey);

/* Functions to extract or store various non-SSH wire encoded values */
ಪೂರ್ಣಾಙ್ಕ	sshbuf_get_nulterminated_string(ಸಂರಚನಾ sshbuf *buf, size_t maxlen,
	    ವರ್ಣ **valp, size_t *lenp);

/* Dump the contents of the buffer in a human-readable format */
ಶೂನ್ಯ	sshbuf_dump(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf, FILE *f);

/* Dump specified memory in a human-readable format */
ಶೂನ್ಯ	sshbuf_dump_data(ಧ್ರುವ ಶೂನ್ಯ *s, size_t len, FILE *f);

/* Return the hexadecimal representation of the contents of the buffer */
ವರ್ಣ	*sshbuf_dtob16(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf);
/* Make a sshbuf from a hex string */
ಸಂರಚನಾ sshbuf *sshbuf_b16tod(ಧ್ರುವ ವರ್ಣ *b16);

/* Encode the contents of the buffer as base64 */
ವರ್ಣ	*sshbuf_dtob64_string(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf, ಪೂರ್ಣಾಙ್ಕ wrap);
ಪೂರ್ಣಾಙ್ಕ	sshbuf_dtob64(ಧ್ರುವ ಸಂರಚನಾ sshbuf *d, ಸಂರಚನಾ sshbuf *b64, ಪೂರ್ಣಾಙ್ಕ wrap);
/* RFC4648 "base64url" encoding variant */
ಪೂರ್ಣಾಙ್ಕ	sshbuf_dtourlb64(ಧ್ರುವ ಸಂರಚನಾ sshbuf *d, ಸಂರಚನಾ sshbuf *b64, ಪೂರ್ಣಾಙ್ಕ wrap);

/* Decode base64 data and append it to the buffer */
ಪೂರ್ಣಾಙ್ಕ	sshbuf_b64tod(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ವರ್ಣ *b64);

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
ಪೂರ್ಣಾಙ್ಕ	sshbuf_cmp(ಧ್ರುವ ಸಂರಚನಾ sshbuf *b, size_t offset,
    ಧ್ರುವ ಶೂನ್ಯ *s, size_t len);

/*
 * Test whether two buffers have identical contents.
 * SSH_ERR_MESSAGE_INCOMPLETE indicates the buffers had differing size.
 * SSH_ERR_INVALID_FORMAT indicates the buffers were the same size but
 * had differing contents.
 * Returns 0 on successful compare (comparing two empty buffers returns 0).
 */
ಪೂರ್ಣಾಙ್ಕ sshbuf_equals(ಧ್ರುವ ಸಂರಚನಾ sshbuf *a, ಧ್ರುವ ಸಂರಚನಾ sshbuf *b);

/*
 * Searches the buffer for the specified string. Returns 0 on success
 * and updates *offsetp with the offset of the first match, relative to
 * the start of the buffer. Otherwise sshbuf_find will return a ssherr.h
 * error code. SSH_ERR_INVALID_FORMAT indicates sufficient bytes were
 * present in the buffer for a match to be possible but none was found.
 * Searches for zero-length data are not allowed.
 */
ಪೂರ್ಣಾಙ್ಕ
sshbuf_find(ಧ್ರುವ ಸಂರಚನಾ sshbuf *b, size_t start_offset,
    ಧ್ರುವ ಶೂನ್ಯ *s, size_t len, size_t *offsetp);

/*
 * Duplicate the contents of a buffer to a string (caller to free).
 * Returns NULL on buffer error, or if the buffer contains a premature
 * nul character.
 */
ವರ್ಣ *sshbuf_dup_string(ಸಂರಚನಾ sshbuf *buf);

/*
 * Fill a buffer from a file descriptor or filename. Both allocate the
 * buffer for the caller.
 */
ಪೂರ್ಣಾಙ್ಕ sshbuf_load_fd(ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf **)
    __attribute__((__nonnull__ (2)));
ಪೂರ್ಣಾಙ್ಕ sshbuf_load_file(ಧ್ರುವ ವರ್ಣ *, ಸಂರಚನಾ sshbuf **)
    __attribute__((__nonnull__ (2)));

/*
 * Write a buffer to a path, creating/truncating as needed (mode 0644,
 * subject to umask). The buffer contents are not modified.
 */
ಪೂರ್ಣಾಙ್ಕ sshbuf_write_file(ಧ್ರುವ ವರ್ಣ *path, ಸಂರಚನಾ sshbuf *buf)
    __attribute__((__nonnull__ (2)));

/* Read up to maxlen bytes from a fd directly to a buffer */
ಪೂರ್ಣಾಙ್ಕ sshbuf_read(ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ sshbuf *, size_t, size_t *)
    __attribute__((__nonnull__ (2)));

/* Macros for decoding/encoding integers */
#define PEEK_U64(p) \
	(((uint64_t)(((ಧ್ರುವ u_char *)(p))[0]) << 56) | \
	 ((uint64_t)(((ಧ್ರುವ u_char *)(p))[1]) << 48) | \
	 ((uint64_t)(((ಧ್ರುವ u_char *)(p))[2]) << 40) | \
	 ((uint64_t)(((ಧ್ರುವ u_char *)(p))[3]) << 32) | \
	 ((uint64_t)(((ಧ್ರುವ u_char *)(p))[4]) << 24) | \
	 ((uint64_t)(((ಧ್ರುವ u_char *)(p))[5]) << 16) | \
	 ((uint64_t)(((ಧ್ರುವ u_char *)(p))[6]) << 8) | \
	  (uint64_t)(((ಧ್ರುವ u_char *)(p))[7]))
#define PEEK_U32(p) \
	(((uint32_t)(((ಧ್ರುವ u_char *)(p))[0]) << 24) | \
	 ((uint32_t)(((ಧ್ರುವ u_char *)(p))[1]) << 16) | \
	 ((uint32_t)(((ಧ್ರುವ u_char *)(p))[2]) << 8) | \
	  (uint32_t)(((ಧ್ರುವ u_char *)(p))[3]))
#define PEEK_U16(p) \
	(((uint16_t)(((ಧ್ರುವ u_char *)(p))[0]) << 8) | \
	  (uint16_t)(((ಧ್ರುವ u_char *)(p))[1]))

#define POKE_U64(p, v) \
	ಕುರು { \
		ಧ್ರುವ uint64_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 56) & 0xff; \
		((u_char *)(p))[1] = (__v >> 48) & 0xff; \
		((u_char *)(p))[2] = (__v >> 40) & 0xff; \
		((u_char *)(p))[3] = (__v >> 32) & 0xff; \
		((u_char *)(p))[4] = (__v >> 24) & 0xff; \
		((u_char *)(p))[5] = (__v >> 16) & 0xff; \
		((u_char *)(p))[6] = (__v >> 8) & 0xff; \
		((u_char *)(p))[7] = __v & 0xff; \
	} ಯಾವತ್ (0)
#define POKE_U32(p, v) \
	ಕುರು { \
		ಧ್ರುವ uint32_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 24) & 0xff; \
		((u_char *)(p))[1] = (__v >> 16) & 0xff; \
		((u_char *)(p))[2] = (__v >> 8) & 0xff; \
		((u_char *)(p))[3] = __v & 0xff; \
	} ಯಾವತ್ (0)
#define POKE_U16(p, v) \
	ಕುರು { \
		ಧ್ರುವ uint16_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 8) & 0xff; \
		((u_char *)(p))[1] = __v & 0xff; \
	} ಯಾವತ್ (0)

/* Internal definitions follow. Exposed for regress tests */
#ifdef SSHBUF_INTERNAL

/*
 * Return the allocation size of buf
 */
size_t	sshbuf_alloc(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf);

/*
 * Increment the reference count of buf.
 */
ಪೂರ್ಣಾಙ್ಕ	sshbuf_set_parent(ಸಂರಚನಾ sshbuf *child, ಸಂರಚನಾ sshbuf *parent);

/*
 * Return the parent buffer of buf, or NULL if it has no parent.
 */
ಧ್ರುವ ಸಂರಚನಾ sshbuf *sshbuf_parent(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf);

/*
 * Return the reference count of buf
 */
u_int	sshbuf_refcount(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf);

# define SSHBUF_SIZE_INIT	256		/* Initial allocation */
# define SSHBUF_SIZE_INC	256		/* Preferred increment length */
# define SSHBUF_PACK_MIN	8192		/* Minimum packable offset */

/* # define SSHBUF_ABORT abort */
/* # define SSHBUF_DEBUG */

# ifndef SSHBUF_ABORT
#  define SSHBUF_ABORT()
# endif

# ifdef SSHBUF_DEBUG
#  define SSHBUF_DBG(x) ಕುರು { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} ಯಾವತ್ (0)
# ಅನ್ಯಥಾ
#  define SSHBUF_DBG(x)
# endif
#endif /* SSHBUF_INTERNAL */

#endif /* _SSHBUF_H */
