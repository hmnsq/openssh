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

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdint.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাৱ <openssl/bn.h>
#অন্তর্ভাৱ <openssl/ec.h>
#অন্তর্ভাৱ <openssl/ecdsa.h>
#অন্তর্ভাৱ <openssl/evp.h>
#অন্যথা /* OPENSSL */
#define BIGNUM		শূন্য
#define EC_চাবি		শূন্য
#define EC_GROUP	শূন্য
#define EC_POINT	শূন্য
#define EVP_PKEY	শূন্য
#endif /* WITH_OPENSSL */

#define SSHBUF_SIZE_MAX		0x8000000	/* Hard maximum size */
#define SSHBUF_REFS_MAX		0x100000	/* Max child buffers */
#define SSHBUF_MAX_BIGNUM	(16384 / 8)	/* Max bignum *bytes* */
#define SSHBUF_MAX_ECPOINT	((528 * 2 / 8) + 1) /* Max EC point *bytes* */

সংরচনা sshbuf;

/*
 * Create a new sshbuf buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
সংরচনা sshbuf *sshbuf_new(শূন্য);

/*
 * Create a new, read-only sshbuf buffer from existing data.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
সংরচনা sshbuf *sshbuf_from(ধ্রুৱ শূন্য *blob, size_t len);

/*
 * Create a new, read-only sshbuf buffer from the contents of an existing
 * buffer. The contents of "buf" must not change in the lifetime of the
 * resultant buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
সংরচনা sshbuf *sshbuf_fromb(সংরচনা sshbuf *buf);

/*
 * Create a new, read-only sshbuf buffer from the contents of a string in
 * an existing buffer (the string is consumed in the process).
 * The contents of "buf" must not change in the lifetime of the resultant
 * buffer.
 * On success, a pointer to the newly allocated buffer is placed in *bufp.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
পূর্ণাঙ্ক	sshbuf_froms(সংরচনা sshbuf *buf, সংরচনা sshbuf **bufp);

/*
 * Clear and free buf
 */
শূন্য	sshbuf_free(সংরচনা sshbuf *buf);

/*
 * Reset buf, clearing its contents. NB. max_size is preserved.
 */
শূন্য	sshbuf_reset(সংরচনা sshbuf *buf);

/*
 * Return the maximum size of buf
 */
size_t	sshbuf_max_size(ধ্রুৱ সংরচনা sshbuf *buf);

/*
 * Set the maximum size of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
পূর্ণাঙ্ক	sshbuf_set_max_size(সংরচনা sshbuf *buf, size_t max_size);

/*
 * Returns the length of data in buf
 */
size_t	sshbuf_len(ধ্রুৱ সংরচনা sshbuf *buf);

/*
 * Returns number of bytes left in buffer before hitting max_size.
 */
size_t	sshbuf_avail(ধ্রুৱ সংরচনা sshbuf *buf);

/*
 * Returns a read-only pointer to the start of the data in buf
 */
ধ্রুৱ u_char *sshbuf_ptr(ধ্রুৱ সংরচনা sshbuf *buf);

/*
 * Returns a mutable pointer to the start of the data in buf, or
 * NULL if the buffer is read-only.
 */
u_char *sshbuf_mutable_ptr(ধ্রুৱ সংরচনা sshbuf *buf);

/*
 * Check whether a reservation of size len will succeed in buf
 * Safer to use than direct comparisons again sshbuf_avail as it copes
 * with unsigned overflows correctly.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
পূর্ণাঙ্ক	sshbuf_check_reserve(ধ্রুৱ সংরচনা sshbuf *buf, size_t len);

/*
 * Preallocates len additional bytes in buf.
 * Useful for cases where the caller knows how many bytes will ultimately be
 * required to avoid realloc in the buffer code.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
পূর্ণাঙ্ক	sshbuf_allocate(সংরচনা sshbuf *buf, size_t len);

/*
 * Reserve len bytes in buf.
 * Returns 0 on success and a pointer to the first reserved byte via the
 * optional dpp parameter or a negative SSH_ERR_* error code on failure.
 */
পূর্ণাঙ্ক	sshbuf_reserve(সংরচনা sshbuf *buf, size_t len, u_char **dpp);

/*
 * Consume len bytes from the start of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
পূর্ণাঙ্ক	sshbuf_consume(সংরচনা sshbuf *buf, size_t len);

/*
 * Consume len bytes from the end of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
পূর্ণাঙ্ক	sshbuf_consume_end(সংরচনা sshbuf *buf, size_t len);

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
পূর্ণাঙ্ক	sshbuf_consume_upto_child(সংরচনা sshbuf *buf, ধ্রুৱ সংরচনা sshbuf *child);

/* Extract or deposit some bytes */
পূর্ণাঙ্ক	sshbuf_get(সংরচনা sshbuf *buf, শূন্য *v, size_t len);
পূর্ণাঙ্ক	sshbuf_put(সংরচনা sshbuf *buf, ধ্রুৱ শূন্য *v, size_t len);
পূর্ণাঙ্ক	sshbuf_putb(সংরচনা sshbuf *buf, ধ্রুৱ সংরচনা sshbuf *v);

/* Append using a printf(3) format */
পূর্ণাঙ্ক	sshbuf_putf(সংরচনা sshbuf *buf, ধ্রুৱ ৱর্ণ *fmt, ...)
	    __attribute__((format(printf, 2, 3)));
পূর্ণাঙ্ক	sshbuf_putfv(সংরচনা sshbuf *buf, ধ্রুৱ ৱর্ণ *fmt, va_list ap);

/* Functions to extract or store big-endian words of various sizes */
পূর্ণাঙ্ক	sshbuf_get_u64(সংরচনা sshbuf *buf, uint64_t *valp);
পূর্ণাঙ্ক	sshbuf_get_u32(সংরচনা sshbuf *buf, uint32_t *valp);
পূর্ণাঙ্ক	sshbuf_get_u16(সংরচনা sshbuf *buf, uint16_t *valp);
পূর্ণাঙ্ক	sshbuf_get_u8(সংরচনা sshbuf *buf, u_char *valp);
পূর্ণাঙ্ক	sshbuf_put_u64(সংরচনা sshbuf *buf, uint64_t val);
পূর্ণাঙ্ক	sshbuf_put_u32(সংরচনা sshbuf *buf, uint32_t val);
পূর্ণাঙ্ক	sshbuf_put_u16(সংরচনা sshbuf *buf, uint16_t val);
পূর্ণাঙ্ক	sshbuf_put_u8(সংরচনা sshbuf *buf, u_char val);

/* Functions to peek at the contents of a buffer without modifying it. */
পূর্ণাঙ্ক	sshbuf_peek_u64(ধ্রুৱ সংরচনা sshbuf *buf, size_t offset,
    uint64_t *valp);
পূর্ণাঙ্ক	sshbuf_peek_u32(ধ্রুৱ সংরচনা sshbuf *buf, size_t offset,
    uint32_t *valp);
পূর্ণাঙ্ক	sshbuf_peek_u16(ধ্রুৱ সংরচনা sshbuf *buf, size_t offset,
    uint16_t *valp);
পূর্ণাঙ্ক	sshbuf_peek_u8(ধ্রুৱ সংরচনা sshbuf *buf, size_t offset,
    u_char *valp);

/*
 * Functions to poke values into an existing buffer (e.g. a length header
 * to a packet). The destination bytes must already exist in the buffer.
 */
পূর্ণাঙ্ক sshbuf_poke_u64(সংরচনা sshbuf *buf, size_t offset, uint64_t val);
পূর্ণাঙ্ক sshbuf_poke_u32(সংরচনা sshbuf *buf, size_t offset, uint32_t val);
পূর্ণাঙ্ক sshbuf_poke_u16(সংরচনা sshbuf *buf, size_t offset, uint16_t val);
পূর্ণাঙ্ক sshbuf_poke_u8(সংরচনা sshbuf *buf, size_t offset, u_char val);
পূর্ণাঙ্ক sshbuf_poke(সংরচনা sshbuf *buf, size_t offset, শূন্য *v, size_t len);

/*
 * Functions to extract or store SSH wire encoded strings (u32 len || data)
 * The "cstring" variants admit no \0 characters in the string contents.
 * Caller must free *valp.
 */
পূর্ণাঙ্ক	sshbuf_get_string(সংরচনা sshbuf *buf, u_char **valp, size_t *lenp);
পূর্ণাঙ্ক	sshbuf_get_cstring(সংরচনা sshbuf *buf, ৱর্ণ **valp, size_t *lenp);
পূর্ণাঙ্ক	sshbuf_get_stringb(সংরচনা sshbuf *buf, সংরচনা sshbuf *v);
পূর্ণাঙ্ক	sshbuf_put_string(সংরচনা sshbuf *buf, ধ্রুৱ শূন্য *v, size_t len);
পূর্ণাঙ্ক	sshbuf_put_cstring(সংরচনা sshbuf *buf, ধ্রুৱ ৱর্ণ *v);
পূর্ণাঙ্ক	sshbuf_put_stringb(সংরচনা sshbuf *buf, ধ্রুৱ সংরচনা sshbuf *v);

/*
 * "Direct" variant of sshbuf_get_string, returns pointer into the sshbuf to
 * avoid an malloc+memcpy. The pointer is guaranteed to be valid until the
 * next sshbuf-modifying function call. Caller does not free.
 */
পূর্ণাঙ্ক	sshbuf_get_string_direct(সংরচনা sshbuf *buf, ধ্রুৱ u_char **valp,
	    size_t *lenp);

/* Skip past a string */
#define sshbuf_skip_string(buf) sshbuf_get_string_direct(buf, রিক্ত, রিক্ত)

/* Another variant: "peeks" into the buffer without modifying it */
পূর্ণাঙ্ক	sshbuf_peek_string_direct(ধ্রুৱ সংরচনা sshbuf *buf, ধ্রুৱ u_char **valp,
	    size_t *lenp);

/*
 * Functions to extract or store SSH wire encoded bignums and elliptic
 * curve points.
 */
পূর্ণাঙ্ক	sshbuf_get_bignum2(সংরচনা sshbuf *buf, BIGNUM **valp);
পূর্ণাঙ্ক	sshbuf_get_bignum2_bytes_direct(সংরচনা sshbuf *buf,
	    ধ্রুৱ u_char **valp, size_t *lenp);
পূর্ণাঙ্ক	sshbuf_put_bignum2(সংরচনা sshbuf *buf, ধ্রুৱ BIGNUM *v);
পূর্ণাঙ্ক	sshbuf_put_bignum2_bytes(সংরচনা sshbuf *buf, ধ্রুৱ শূন্য *v, size_t len);
পূর্ণাঙ্ক	sshbuf_get_ec(সংরচনা sshbuf *buf, EC_POINT *v, ধ্রুৱ EC_GROUP *g);
পূর্ণাঙ্ক	sshbuf_get_eckey(সংরচনা sshbuf *buf, EC_চাবি *v);
পূর্ণাঙ্ক	sshbuf_put_ec(সংরচনা sshbuf *buf, ধ্রুৱ EC_POINT *v, ধ্রুৱ EC_GROUP *g);
পূর্ণাঙ্ক	sshbuf_put_eckey(সংরচনা sshbuf *buf, ধ্রুৱ EC_চাবি *v);
পূর্ণাঙ্ক	sshbuf_put_ec_pkey(সংরচনা sshbuf *buf, EVP_PKEY *pkey);

/* Functions to extract or store various non-SSH wire encoded values */
পূর্ণাঙ্ক	sshbuf_get_nulterminated_string(সংরচনা sshbuf *buf, size_t maxlen,
	    ৱর্ণ **valp, size_t *lenp);

/* Dump the contents of the buffer in a human-readable format */
শূন্য	sshbuf_dump(ধ্রুৱ সংরচনা sshbuf *buf, FILE *f);

/* Dump specified memory in a human-readable format */
শূন্য	sshbuf_dump_data(ধ্রুৱ শূন্য *s, size_t len, FILE *f);

/* Return the hexadecimal representation of the contents of the buffer */
ৱর্ণ	*sshbuf_dtob16(ধ্রুৱ সংরচনা sshbuf *buf);
/* Make a sshbuf from a hex string */
সংরচনা sshbuf *sshbuf_b16tod(ধ্রুৱ ৱর্ণ *b16);

/* Encode the contents of the buffer as base64 */
ৱর্ণ	*sshbuf_dtob64_string(ধ্রুৱ সংরচনা sshbuf *buf, পূর্ণাঙ্ক wrap);
পূর্ণাঙ্ক	sshbuf_dtob64(ধ্রুৱ সংরচনা sshbuf *d, সংরচনা sshbuf *b64, পূর্ণাঙ্ক wrap);
/* RFC4648 "base64url" encoding variant */
পূর্ণাঙ্ক	sshbuf_dtourlb64(ধ্রুৱ সংরচনা sshbuf *d, সংরচনা sshbuf *b64, পূর্ণাঙ্ক wrap);

/* Decode base64 data and append it to the buffer */
পূর্ণাঙ্ক	sshbuf_b64tod(সংরচনা sshbuf *buf, ধ্রুৱ ৱর্ণ *b64);

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
পূর্ণাঙ্ক	sshbuf_cmp(ধ্রুৱ সংরচনা sshbuf *b, size_t offset,
    ধ্রুৱ শূন্য *s, size_t len);

/*
 * Test whether two buffers have identical contents.
 * SSH_ERR_MESSAGE_INCOMPLETE indicates the buffers had differing size.
 * SSH_ERR_INVALID_FORMAT indicates the buffers were the same size but
 * had differing contents.
 * Returns 0 on successful compare (comparing two empty buffers returns 0).
 */
পূর্ণাঙ্ক sshbuf_equals(ধ্রুৱ সংরচনা sshbuf *a, ধ্রুৱ সংরচনা sshbuf *b);

/*
 * Searches the buffer for the specified string. Returns 0 on success
 * and updates *offsetp with the offset of the first match, relative to
 * the start of the buffer. Otherwise sshbuf_find will return a ssherr.h
 * error code. SSH_ERR_INVALID_FORMAT indicates sufficient bytes were
 * present in the buffer for a match to be possible but none was found.
 * Searches for zero-length data are not allowed.
 */
পূর্ণাঙ্ক
sshbuf_find(ধ্রুৱ সংরচনা sshbuf *b, size_t start_offset,
    ধ্রুৱ শূন্য *s, size_t len, size_t *offsetp);

/*
 * Duplicate the contents of a buffer to a string (caller to free).
 * Returns NULL on buffer error, or if the buffer contains a premature
 * nul character.
 */
ৱর্ণ *sshbuf_dup_string(সংরচনা sshbuf *buf);

/*
 * Fill a buffer from a file descriptor or filename. Both allocate the
 * buffer for the caller.
 */
পূর্ণাঙ্ক sshbuf_load_fd(পূর্ণাঙ্ক, সংরচনা sshbuf **)
    __attribute__((__nonnull__ (2)));
পূর্ণাঙ্ক sshbuf_load_file(ধ্রুৱ ৱর্ণ *, সংরচনা sshbuf **)
    __attribute__((__nonnull__ (2)));

/*
 * Write a buffer to a path, creating/truncating as needed (mode 0644,
 * subject to umask). The buffer contents are not modified.
 */
পূর্ণাঙ্ক sshbuf_write_file(ধ্রুৱ ৱর্ণ *path, সংরচনা sshbuf *buf)
    __attribute__((__nonnull__ (2)));

/* Read up to maxlen bytes from a fd directly to a buffer */
পূর্ণাঙ্ক sshbuf_read(পূর্ণাঙ্ক, সংরচনা sshbuf *, size_t, size_t *)
    __attribute__((__nonnull__ (2)));

/* Macros for decoding/encoding integers */
#define PEEK_U64(p) \
	(((uint64_t)(((ধ্রুৱ u_char *)(p))[0]) << 56) | \
	 ((uint64_t)(((ধ্রুৱ u_char *)(p))[1]) << 48) | \
	 ((uint64_t)(((ধ্রুৱ u_char *)(p))[2]) << 40) | \
	 ((uint64_t)(((ধ্রুৱ u_char *)(p))[3]) << 32) | \
	 ((uint64_t)(((ধ্রুৱ u_char *)(p))[4]) << 24) | \
	 ((uint64_t)(((ধ্রুৱ u_char *)(p))[5]) << 16) | \
	 ((uint64_t)(((ধ্রুৱ u_char *)(p))[6]) << 8) | \
	  (uint64_t)(((ধ্রুৱ u_char *)(p))[7]))
#define PEEK_U32(p) \
	(((uint32_t)(((ধ্রুৱ u_char *)(p))[0]) << 24) | \
	 ((uint32_t)(((ধ্রুৱ u_char *)(p))[1]) << 16) | \
	 ((uint32_t)(((ধ্রুৱ u_char *)(p))[2]) << 8) | \
	  (uint32_t)(((ধ্রুৱ u_char *)(p))[3]))
#define PEEK_U16(p) \
	(((uint16_t)(((ধ্রুৱ u_char *)(p))[0]) << 8) | \
	  (uint16_t)(((ধ্রুৱ u_char *)(p))[1]))

#define POKE_U64(p, v) \
	কৰা { \
		ধ্রুৱ uint64_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 56) & 0xff; \
		((u_char *)(p))[1] = (__v >> 48) & 0xff; \
		((u_char *)(p))[2] = (__v >> 40) & 0xff; \
		((u_char *)(p))[3] = (__v >> 32) & 0xff; \
		((u_char *)(p))[4] = (__v >> 24) & 0xff; \
		((u_char *)(p))[5] = (__v >> 16) & 0xff; \
		((u_char *)(p))[6] = (__v >> 8) & 0xff; \
		((u_char *)(p))[7] = __v & 0xff; \
	} যেতিয়ালৈ (0)
#define POKE_U32(p, v) \
	কৰা { \
		ধ্রুৱ uint32_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 24) & 0xff; \
		((u_char *)(p))[1] = (__v >> 16) & 0xff; \
		((u_char *)(p))[2] = (__v >> 8) & 0xff; \
		((u_char *)(p))[3] = __v & 0xff; \
	} যেতিয়ালৈ (0)
#define POKE_U16(p, v) \
	কৰা { \
		ধ্রুৱ uint16_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 8) & 0xff; \
		((u_char *)(p))[1] = __v & 0xff; \
	} যেতিয়ালৈ (0)

/* Internal definitions follow. Exposed for regress tests */
#ifdef SSHBUF_INTERNAL

/*
 * Return the allocation size of buf
 */
size_t	sshbuf_alloc(ধ্রুৱ সংরচনা sshbuf *buf);

/*
 * Increment the reference count of buf.
 */
পূর্ণাঙ্ক	sshbuf_set_parent(সংরচনা sshbuf *child, সংরচনা sshbuf *parent);

/*
 * Return the parent buffer of buf, or NULL if it has no parent.
 */
ধ্রুৱ সংরচনা sshbuf *sshbuf_parent(ধ্রুৱ সংরচনা sshbuf *buf);

/*
 * Return the reference count of buf
 */
u_int	sshbuf_refcount(ধ্রুৱ সংরচনা sshbuf *buf);

# define SSHBUF_SIZE_INIT	256		/* Initial allocation */
# define SSHBUF_SIZE_INC	256		/* Preferred increment length */
# define SSHBUF_PACK_MIN	8192		/* Minimum packable offset */

/* # define SSHBUF_ABORT abort */
/* # define SSHBUF_DEBUG */

# ifndef SSHBUF_ABORT
#  define SSHBUF_ABORT()
# endif

# ifdef SSHBUF_DEBUG
#  define SSHBUF_DBG(x) কৰা { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} যেতিয়ালৈ (0)
# অন্যথা
#  define SSHBUF_DBG(x)
# endif
#endif /* SSHBUF_INTERNAL */

#endif /* _SSHBUF_H */
