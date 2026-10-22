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

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ec.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ecdsa.h>
#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>
#ଅନ୍ୟଥା /* OPENSSL */
#define BIGNUM		ଶୂନ୍ୟ
#define EC_ଚାବି		ଶୂନ୍ୟ
#define EC_GROUP	ଶୂନ୍ୟ
#define EC_POINT	ଶୂନ୍ୟ
#define EVP_PKEY	ଶୂନ୍ୟ
#endif /* WITH_OPENSSL */

#define SSHBUF_SIZE_MAX		0x8000000	/* Hard maximum size */
#define SSHBUF_REFS_MAX		0x100000	/* Max child buffers */
#define SSHBUF_MAX_BIGNUM	(16384 / 8)	/* Max bignum *bytes* */
#define SSHBUF_MAX_ECPOINT	((528 * 2 / 8) + 1) /* Max EC point *bytes* */

ସଂରଚନା sshbuf;

/*
 * Create a new sshbuf buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
ସଂରଚନା sshbuf *sshbuf_new(ଶୂନ୍ୟ);

/*
 * Create a new, read-only sshbuf buffer from existing data.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
ସଂରଚନା sshbuf *sshbuf_from(ଅଚଳ ଶୂନ୍ୟ *blob, size_t len);

/*
 * Create a new, read-only sshbuf buffer from the contents of an existing
 * buffer. The contents of "buf" must not change in the lifetime of the
 * resultant buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
ସଂରଚନା sshbuf *sshbuf_fromb(ସଂରଚନା sshbuf *buf);

/*
 * Create a new, read-only sshbuf buffer from the contents of a string in
 * an existing buffer (the string is consumed in the process).
 * The contents of "buf" must not change in the lifetime of the resultant
 * buffer.
 * On success, a pointer to the newly allocated buffer is placed in *bufp.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_froms(ସଂରଚନା sshbuf *buf, ସଂରଚନା sshbuf **bufp);

/*
 * Clear and free buf
 */
ଶୂନ୍ୟ	sshbuf_free(ସଂରଚନା sshbuf *buf);

/*
 * Reset buf, clearing its contents. NB. max_size is preserved.
 */
ଶୂନ୍ୟ	sshbuf_reset(ସଂରଚନା sshbuf *buf);

/*
 * Return the maximum size of buf
 */
size_t	sshbuf_max_size(ଅଚଳ ସଂରଚନା sshbuf *buf);

/*
 * Set the maximum size of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_set_max_size(ସଂରଚନା sshbuf *buf, size_t max_size);

/*
 * Returns the length of data in buf
 */
size_t	sshbuf_len(ଅଚଳ ସଂରଚନା sshbuf *buf);

/*
 * Returns number of bytes left in buffer before hitting max_size.
 */
size_t	sshbuf_avail(ଅଚଳ ସଂରଚନା sshbuf *buf);

/*
 * Returns a read-only pointer to the start of the data in buf
 */
ଅଚଳ u_char *sshbuf_ptr(ଅଚଳ ସଂରଚନା sshbuf *buf);

/*
 * Returns a mutable pointer to the start of the data in buf, or
 * NULL if the buffer is read-only.
 */
u_char *sshbuf_mutable_ptr(ଅଚଳ ସଂରଚନା sshbuf *buf);

/*
 * Check whether a reservation of size len will succeed in buf
 * Safer to use than direct comparisons again sshbuf_avail as it copes
 * with unsigned overflows correctly.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_check_reserve(ଅଚଳ ସଂରଚନା sshbuf *buf, size_t len);

/*
 * Preallocates len additional bytes in buf.
 * Useful for cases where the caller knows how many bytes will ultimately be
 * required to avoid realloc in the buffer code.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_allocate(ସଂରଚନା sshbuf *buf, size_t len);

/*
 * Reserve len bytes in buf.
 * Returns 0 on success and a pointer to the first reserved byte via the
 * optional dpp parameter or a negative SSH_ERR_* error code on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_reserve(ସଂରଚନା sshbuf *buf, size_t len, u_char **dpp);

/*
 * Consume len bytes from the start of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_consume(ସଂରଚନା sshbuf *buf, size_t len);

/*
 * Consume len bytes from the end of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_consume_end(ସଂରଚନା sshbuf *buf, size_t len);

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
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_consume_upto_child(ସଂରଚନା sshbuf *buf, ଅଚଳ ସଂରଚନା sshbuf *child);

/* Extract or deposit some bytes */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_get(ସଂରଚନା sshbuf *buf, ଶୂନ୍ୟ *v, size_t len);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_put(ସଂରଚନା sshbuf *buf, ଅଚଳ ଶୂନ୍ୟ *v, size_t len);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_putb(ସଂରଚନା sshbuf *buf, ଅଚଳ ସଂରଚନା sshbuf *v);

/* Append using a printf(3) format */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_putf(ସଂରଚନା sshbuf *buf, ଅଚଳ ଅକ୍ଷର *fmt, ...)
	    __attribute__((format(printf, 2, 3)));
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_putfv(ସଂରଚନା sshbuf *buf, ଅଚଳ ଅକ୍ଷର *fmt, va_list ap);

/* Functions to extract or store big-endian words of various sizes */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_get_u64(ସଂରଚନା sshbuf *buf, uint64_t *valp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_get_u32(ସଂରଚନା sshbuf *buf, uint32_t *valp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_get_u16(ସଂରଚନା sshbuf *buf, uint16_t *valp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_get_u8(ସଂରଚନା sshbuf *buf, u_char *valp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_put_u64(ସଂରଚନା sshbuf *buf, uint64_t val);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_put_u32(ସଂରଚନା sshbuf *buf, uint32_t val);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_put_u16(ସଂରଚନା sshbuf *buf, uint16_t val);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_put_u8(ସଂରଚନା sshbuf *buf, u_char val);

/* Functions to peek at the contents of a buffer without modifying it. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_peek_u64(ଅଚଳ ସଂରଚନା sshbuf *buf, size_t offset,
    uint64_t *valp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_peek_u32(ଅଚଳ ସଂରଚନା sshbuf *buf, size_t offset,
    uint32_t *valp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_peek_u16(ଅଚଳ ସଂରଚନା sshbuf *buf, size_t offset,
    uint16_t *valp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_peek_u8(ଅଚଳ ସଂରଚନା sshbuf *buf, size_t offset,
    u_char *valp);

/*
 * Functions to poke values into an existing buffer (e.g. a length header
 * to a packet). The destination bytes must already exist in the buffer.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshbuf_poke_u64(ସଂରଚନା sshbuf *buf, size_t offset, uint64_t val);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshbuf_poke_u32(ସଂରଚନା sshbuf *buf, size_t offset, uint32_t val);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshbuf_poke_u16(ସଂରଚନା sshbuf *buf, size_t offset, uint16_t val);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshbuf_poke_u8(ସଂରଚନା sshbuf *buf, size_t offset, u_char val);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshbuf_poke(ସଂରଚନା sshbuf *buf, size_t offset, ଶୂନ୍ୟ *v, size_t len);

/*
 * Functions to extract or store SSH wire encoded strings (u32 len || data)
 * The "cstring" variants admit no \0 characters in the string contents.
 * Caller must free *valp.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_get_string(ସଂରଚନା sshbuf *buf, u_char **valp, size_t *lenp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_get_cstring(ସଂରଚନା sshbuf *buf, ଅକ୍ଷର **valp, size_t *lenp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_get_stringb(ସଂରଚନା sshbuf *buf, ସଂରଚନା sshbuf *v);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_put_string(ସଂରଚନା sshbuf *buf, ଅଚଳ ଶୂନ୍ୟ *v, size_t len);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_put_cstring(ସଂରଚନା sshbuf *buf, ଅଚଳ ଅକ୍ଷର *v);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_put_stringb(ସଂରଚନା sshbuf *buf, ଅଚଳ ସଂରଚନା sshbuf *v);

/*
 * "Direct" variant of sshbuf_get_string, returns pointer into the sshbuf to
 * avoid an malloc+memcpy. The pointer is guaranteed to be valid until the
 * next sshbuf-modifying function call. Caller does not free.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_get_string_direct(ସଂରଚନା sshbuf *buf, ଅଚଳ u_char **valp,
	    size_t *lenp);

/* Skip past a string */
#define sshbuf_skip_string(buf) sshbuf_get_string_direct(buf, ଖାଲି, ଖାଲି)

/* Another variant: "peeks" into the buffer without modifying it */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_peek_string_direct(ଅଚଳ ସଂରଚନା sshbuf *buf, ଅଚଳ u_char **valp,
	    size_t *lenp);

/*
 * Functions to extract or store SSH wire encoded bignums and elliptic
 * curve points.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_get_bignum2(ସଂରଚନା sshbuf *buf, BIGNUM **valp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_get_bignum2_bytes_direct(ସଂରଚନା sshbuf *buf,
	    ଅଚଳ u_char **valp, size_t *lenp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_put_bignum2(ସଂରଚନା sshbuf *buf, ଅଚଳ BIGNUM *v);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_put_bignum2_bytes(ସଂରଚନା sshbuf *buf, ଅଚଳ ଶୂନ୍ୟ *v, size_t len);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_get_ec(ସଂରଚନା sshbuf *buf, EC_POINT *v, ଅଚଳ EC_GROUP *g);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_get_eckey(ସଂରଚନା sshbuf *buf, EC_ଚାବି *v);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_put_ec(ସଂରଚନା sshbuf *buf, ଅଚଳ EC_POINT *v, ଅଚଳ EC_GROUP *g);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_put_eckey(ସଂରଚନା sshbuf *buf, ଅଚଳ EC_ଚାବି *v);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_put_ec_pkey(ସଂରଚନା sshbuf *buf, EVP_PKEY *pkey);

/* Functions to extract or store various non-SSH wire encoded values */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_get_nulterminated_string(ସଂରଚନା sshbuf *buf, size_t maxlen,
	    ଅକ୍ଷର **valp, size_t *lenp);

/* Dump the contents of the buffer in a human-readable format */
ଶୂନ୍ୟ	sshbuf_dump(ଅଚଳ ସଂରଚନା sshbuf *buf, FILE *f);

/* Dump specified memory in a human-readable format */
ଶୂନ୍ୟ	sshbuf_dump_data(ଅଚଳ ଶୂନ୍ୟ *s, size_t len, FILE *f);

/* Return the hexadecimal representation of the contents of the buffer */
ଅକ୍ଷର	*sshbuf_dtob16(ଅଚଳ ସଂରଚନା sshbuf *buf);
/* Make a sshbuf from a hex string */
ସଂରଚନା sshbuf *sshbuf_b16tod(ଅଚଳ ଅକ୍ଷର *b16);

/* Encode the contents of the buffer as base64 */
ଅକ୍ଷର	*sshbuf_dtob64_string(ଅଚଳ ସଂରଚନା sshbuf *buf, ପୂର୍ଣ୍ଣସଂଖ୍ୟା wrap);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_dtob64(ଅଚଳ ସଂରଚନା sshbuf *d, ସଂରଚନା sshbuf *b64, ପୂର୍ଣ୍ଣସଂଖ୍ୟା wrap);
/* RFC4648 "base64url" encoding variant */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_dtourlb64(ଅଚଳ ସଂରଚନା sshbuf *d, ସଂରଚନା sshbuf *b64, ପୂର୍ଣ୍ଣସଂଖ୍ୟା wrap);

/* Decode base64 data and append it to the buffer */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_b64tod(ସଂରଚନା sshbuf *buf, ଅଚଳ ଅକ୍ଷର *b64);

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
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_cmp(ଅଚଳ ସଂରଚନା sshbuf *b, size_t offset,
    ଅଚଳ ଶୂନ୍ୟ *s, size_t len);

/*
 * Test whether two buffers have identical contents.
 * SSH_ERR_MESSAGE_INCOMPLETE indicates the buffers had differing size.
 * SSH_ERR_INVALID_FORMAT indicates the buffers were the same size but
 * had differing contents.
 * Returns 0 on successful compare (comparing two empty buffers returns 0).
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshbuf_equals(ଅଚଳ ସଂରଚନା sshbuf *a, ଅଚଳ ସଂରଚନା sshbuf *b);

/*
 * Searches the buffer for the specified string. Returns 0 on success
 * and updates *offsetp with the offset of the first match, relative to
 * the start of the buffer. Otherwise sshbuf_find will return a ssherr.h
 * error code. SSH_ERR_INVALID_FORMAT indicates sufficient bytes were
 * present in the buffer for a match to be possible but none was found.
 * Searches for zero-length data are not allowed.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_find(ଅଚଳ ସଂରଚନା sshbuf *b, size_t start_offset,
    ଅଚଳ ଶୂନ୍ୟ *s, size_t len, size_t *offsetp);

/*
 * Duplicate the contents of a buffer to a string (caller to free).
 * Returns NULL on buffer error, or if the buffer contains a premature
 * nul character.
 */
ଅକ୍ଷର *sshbuf_dup_string(ସଂରଚନା sshbuf *buf);

/*
 * Fill a buffer from a file descriptor or filename. Both allocate the
 * buffer for the caller.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshbuf_load_fd(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf **)
    __attribute__((__nonnull__ (2)));
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshbuf_load_file(ଅଚଳ ଅକ୍ଷର *, ସଂରଚନା sshbuf **)
    __attribute__((__nonnull__ (2)));

/*
 * Write a buffer to a path, creating/truncating as needed (mode 0644,
 * subject to umask). The buffer contents are not modified.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshbuf_write_file(ଅଚଳ ଅକ୍ଷର *path, ସଂରଚନା sshbuf *buf)
    __attribute__((__nonnull__ (2)));

/* Read up to maxlen bytes from a fd directly to a buffer */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshbuf_read(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା sshbuf *, size_t, size_t *)
    __attribute__((__nonnull__ (2)));

/* Macros for decoding/encoding integers */
#define PEEK_U64(p) \
	(((uint64_t)(((ଅଚଳ u_char *)(p))[0]) << 56) | \
	 ((uint64_t)(((ଅଚଳ u_char *)(p))[1]) << 48) | \
	 ((uint64_t)(((ଅଚଳ u_char *)(p))[2]) << 40) | \
	 ((uint64_t)(((ଅଚଳ u_char *)(p))[3]) << 32) | \
	 ((uint64_t)(((ଅଚଳ u_char *)(p))[4]) << 24) | \
	 ((uint64_t)(((ଅଚଳ u_char *)(p))[5]) << 16) | \
	 ((uint64_t)(((ଅଚଳ u_char *)(p))[6]) << 8) | \
	  (uint64_t)(((ଅଚଳ u_char *)(p))[7]))
#define PEEK_U32(p) \
	(((uint32_t)(((ଅଚଳ u_char *)(p))[0]) << 24) | \
	 ((uint32_t)(((ଅଚଳ u_char *)(p))[1]) << 16) | \
	 ((uint32_t)(((ଅଚଳ u_char *)(p))[2]) << 8) | \
	  (uint32_t)(((ଅଚଳ u_char *)(p))[3]))
#define PEEK_U16(p) \
	(((uint16_t)(((ଅଚଳ u_char *)(p))[0]) << 8) | \
	  (uint16_t)(((ଅଚଳ u_char *)(p))[1]))

#define POKE_U64(p, v) \
	କର { \
		ଅଚଳ uint64_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 56) & 0xff; \
		((u_char *)(p))[1] = (__v >> 48) & 0xff; \
		((u_char *)(p))[2] = (__v >> 40) & 0xff; \
		((u_char *)(p))[3] = (__v >> 32) & 0xff; \
		((u_char *)(p))[4] = (__v >> 24) & 0xff; \
		((u_char *)(p))[5] = (__v >> 16) & 0xff; \
		((u_char *)(p))[6] = (__v >> 8) & 0xff; \
		((u_char *)(p))[7] = __v & 0xff; \
	} ଯେତେବେଳେ (0)
#define POKE_U32(p, v) \
	କର { \
		ଅଚଳ uint32_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 24) & 0xff; \
		((u_char *)(p))[1] = (__v >> 16) & 0xff; \
		((u_char *)(p))[2] = (__v >> 8) & 0xff; \
		((u_char *)(p))[3] = __v & 0xff; \
	} ଯେତେବେଳେ (0)
#define POKE_U16(p, v) \
	କର { \
		ଅଚଳ uint16_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 8) & 0xff; \
		((u_char *)(p))[1] = __v & 0xff; \
	} ଯେତେବେଳେ (0)

/* Internal definitions follow. Exposed for regress tests */
#ifdef SSHBUF_INTERNAL

/*
 * Return the allocation size of buf
 */
size_t	sshbuf_alloc(ଅଚଳ ସଂରଚନା sshbuf *buf);

/*
 * Increment the reference count of buf.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshbuf_set_parent(ସଂରଚନା sshbuf *child, ସଂରଚନା sshbuf *parent);

/*
 * Return the parent buffer of buf, or NULL if it has no parent.
 */
ଅଚଳ ସଂରଚନା sshbuf *sshbuf_parent(ଅଚଳ ସଂରଚନା sshbuf *buf);

/*
 * Return the reference count of buf
 */
u_int	sshbuf_refcount(ଅଚଳ ସଂରଚନା sshbuf *buf);

# define SSHBUF_SIZE_INIT	256		/* Initial allocation */
# define SSHBUF_SIZE_INC	256		/* Preferred increment length */
# define SSHBUF_PACK_MIN	8192		/* Minimum packable offset */

/* # define SSHBUF_ABORT abort */
/* # define SSHBUF_DEBUG */

# ifndef SSHBUF_ABORT
#  define SSHBUF_ABORT()
# endif

# ifdef SSHBUF_DEBUG
#  define SSHBUF_DBG(x) କର { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} ଯେତେବେଳେ (0)
# ଅନ୍ୟଥା
#  define SSHBUF_DBG(x)
# endif
#endif /* SSHBUF_INTERNAL */

#endif /* _SSHBUF_H */
