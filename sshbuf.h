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

#ضمن <sys/types.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdint.h>

#ifdef WITH_OPENSSL
#ضمن <openssl/bn.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/ecdsa.h>
#ضمن <openssl/evp.h>
#وإلا /* OPENSSL */
#define BIGNUM		فراغ
#define EC_KEY		فراغ
#define EC_GROUP	فراغ
#define EC_POINT	فراغ
#define EVP_PKEY	فراغ
#endif /* WITH_OPENSSL */

#define SSHBUF_SIZE_MAX		0x8000000	/* Hard maximum size */
#define SSHBUF_REFS_MAX		0x100000	/* Max child buffers */
#define SSHBUF_MAX_BIGNUM	(16384 / 8)	/* Max bignum *bytes* */
#define SSHBUF_MAX_ECPOINT	((528 * 2 / 8) + 1) /* Max EC point *bytes* */

بنية sshbuf;

/*
 * Create a new sshbuf buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
بنية sshbuf *sshbuf_new(فراغ);

/*
 * Create a new, read-only sshbuf buffer from existing data.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
بنية sshbuf *sshbuf_from(ثابت فراغ *blob, size_t len);

/*
 * Create a new, read-only sshbuf buffer from the contents of an existing
 * buffer. The contents of "buf" must not change in the lifetime of the
 * resultant buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
بنية sshbuf *sshbuf_fromb(بنية sshbuf *buf);

/*
 * Create a new, read-only sshbuf buffer from the contents of a string in
 * an existing buffer (the string is consumed in the process).
 * The contents of "buf" must not change in the lifetime of the resultant
 * buffer.
 * On success, a pointer to the newly allocated buffer is placed in *bufp.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
صحيح	sshbuf_froms(بنية sshbuf *buf, بنية sshbuf **bufp);

/*
 * Clear and free buf
 */
فراغ	sshbuf_free(بنية sshbuf *buf);

/*
 * Reset buf, clearing its contents. NB. max_size is preserved.
 */
فراغ	sshbuf_reset(بنية sshbuf *buf);

/*
 * Return the maximum size of buf
 */
size_t	sshbuf_max_size(ثابت بنية sshbuf *buf);

/*
 * Set the maximum size of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
صحيح	sshbuf_set_max_size(بنية sshbuf *buf, size_t max_size);

/*
 * Returns the length of data in buf
 */
size_t	sshbuf_len(ثابت بنية sshbuf *buf);

/*
 * Returns number of bytes left in buffer before hitting max_size.
 */
size_t	sshbuf_avail(ثابت بنية sshbuf *buf);

/*
 * Returns a read-only pointer to the start of the data in buf
 */
ثابت u_char *sshbuf_ptr(ثابت بنية sshbuf *buf);

/*
 * Returns a mutable pointer to the start of the data in buf, or
 * NULL if the buffer is read-only.
 */
u_char *sshbuf_mutable_ptr(ثابت بنية sshbuf *buf);

/*
 * Check whether a reservation of size len will succeed in buf
 * Safer to use than direct comparisons again sshbuf_avail as it copes
 * with unsigned overflows correctly.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
صحيح	sshbuf_check_reserve(ثابت بنية sshbuf *buf, size_t len);

/*
 * Preallocates len additional bytes in buf.
 * Useful for cases where the caller knows how many bytes will ultimately be
 * required to avoid realloc in the buffer code.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
صحيح	sshbuf_allocate(بنية sshbuf *buf, size_t len);

/*
 * Reserve len bytes in buf.
 * Returns 0 on success and a pointer to the first reserved byte via the
 * optional dpp parameter or a negative SSH_ERR_* error code on failure.
 */
صحيح	sshbuf_reserve(بنية sshbuf *buf, size_t len, u_char **dpp);

/*
 * Consume len bytes from the start of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
صحيح	sshbuf_consume(بنية sshbuf *buf, size_t len);

/*
 * Consume len bytes from the end of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
صحيح	sshbuf_consume_end(بنية sshbuf *buf, size_t len);

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
صحيح	sshbuf_consume_upto_child(بنية sshbuf *buf, ثابت بنية sshbuf *child);

/* Extract or deposit some bytes */
صحيح	sshbuf_get(بنية sshbuf *buf, فراغ *v, size_t len);
صحيح	sshbuf_put(بنية sshbuf *buf, ثابت فراغ *v, size_t len);
صحيح	sshbuf_putb(بنية sshbuf *buf, ثابت بنية sshbuf *v);

/* Append using a printf(3) format */
صحيح	sshbuf_putf(بنية sshbuf *buf, ثابت حرف *fmt, ...)
	    __attribute__((format(printf, 2, 3)));
صحيح	sshbuf_putfv(بنية sshbuf *buf, ثابت حرف *fmt, va_list ap);

/* Functions to extract or store big-endian words of various sizes */
صحيح	sshbuf_get_u64(بنية sshbuf *buf, uint64_t *valp);
صحيح	sshbuf_get_u32(بنية sshbuf *buf, uint32_t *valp);
صحيح	sshbuf_get_u16(بنية sshbuf *buf, uint16_t *valp);
صحيح	sshbuf_get_u8(بنية sshbuf *buf, u_char *valp);
صحيح	sshbuf_put_u64(بنية sshbuf *buf, uint64_t val);
صحيح	sshbuf_put_u32(بنية sshbuf *buf, uint32_t val);
صحيح	sshbuf_put_u16(بنية sshbuf *buf, uint16_t val);
صحيح	sshbuf_put_u8(بنية sshbuf *buf, u_char val);

/* Functions to peek at the contents of a buffer without modifying it. */
صحيح	sshbuf_peek_u64(ثابت بنية sshbuf *buf, size_t offset,
    uint64_t *valp);
صحيح	sshbuf_peek_u32(ثابت بنية sshbuf *buf, size_t offset,
    uint32_t *valp);
صحيح	sshbuf_peek_u16(ثابت بنية sshbuf *buf, size_t offset,
    uint16_t *valp);
صحيح	sshbuf_peek_u8(ثابت بنية sshbuf *buf, size_t offset,
    u_char *valp);

/*
 * Functions to poke values into an existing buffer (e.g. a length header
 * to a packet). The destination bytes must already exist in the buffer.
 */
صحيح sshbuf_poke_u64(بنية sshbuf *buf, size_t offset, uint64_t val);
صحيح sshbuf_poke_u32(بنية sshbuf *buf, size_t offset, uint32_t val);
صحيح sshbuf_poke_u16(بنية sshbuf *buf, size_t offset, uint16_t val);
صحيح sshbuf_poke_u8(بنية sshbuf *buf, size_t offset, u_char val);
صحيح sshbuf_poke(بنية sshbuf *buf, size_t offset, فراغ *v, size_t len);

/*
 * Functions to extract or store SSH wire encoded strings (u32 len || data)
 * The "cstring" variants admit no \0 characters in the string contents.
 * Caller must free *valp.
 */
صحيح	sshbuf_get_string(بنية sshbuf *buf, u_char **valp, size_t *lenp);
صحيح	sshbuf_get_cstring(بنية sshbuf *buf, حرف **valp, size_t *lenp);
صحيح	sshbuf_get_stringb(بنية sshbuf *buf, بنية sshbuf *v);
صحيح	sshbuf_put_string(بنية sshbuf *buf, ثابت فراغ *v, size_t len);
صحيح	sshbuf_put_cstring(بنية sshbuf *buf, ثابت حرف *v);
صحيح	sshbuf_put_stringb(بنية sshbuf *buf, ثابت بنية sshbuf *v);

/*
 * "Direct" variant of sshbuf_get_string, returns pointer into the sshbuf to
 * avoid an malloc+memcpy. The pointer is guaranteed to be valid until the
 * next sshbuf-modifying function call. Caller does not free.
 */
صحيح	sshbuf_get_string_direct(بنية sshbuf *buf, ثابت u_char **valp,
	    size_t *lenp);

/* Skip past a string */
#define sshbuf_skip_string(buf) sshbuf_get_string_direct(buf, عدم, عدم)

/* Another variant: "peeks" into the buffer without modifying it */
صحيح	sshbuf_peek_string_direct(ثابت بنية sshbuf *buf, ثابت u_char **valp,
	    size_t *lenp);

/*
 * Functions to extract or store SSH wire encoded bignums and elliptic
 * curve points.
 */
صحيح	sshbuf_get_bignum2(بنية sshbuf *buf, BIGNUM **valp);
صحيح	sshbuf_get_bignum2_bytes_direct(بنية sshbuf *buf,
	    ثابت u_char **valp, size_t *lenp);
صحيح	sshbuf_put_bignum2(بنية sshbuf *buf, ثابت BIGNUM *v);
صحيح	sshbuf_put_bignum2_bytes(بنية sshbuf *buf, ثابت فراغ *v, size_t len);
صحيح	sshbuf_get_ec(بنية sshbuf *buf, EC_POINT *v, ثابت EC_GROUP *g);
صحيح	sshbuf_get_eckey(بنية sshbuf *buf, EC_KEY *v);
صحيح	sshbuf_put_ec(بنية sshbuf *buf, ثابت EC_POINT *v, ثابت EC_GROUP *g);
صحيح	sshbuf_put_eckey(بنية sshbuf *buf, ثابت EC_KEY *v);
صحيح	sshbuf_put_ec_pkey(بنية sshbuf *buf, EVP_PKEY *pkey);

/* Functions to extract or store various non-SSH wire encoded values */
صحيح	sshbuf_get_nulterminated_string(بنية sshbuf *buf, size_t maxlen,
	    حرف **valp, size_t *lenp);

/* Dump the contents of the buffer in a human-readable format */
فراغ	sshbuf_dump(ثابت بنية sshbuf *buf, FILE *f);

/* Dump specified memory in a human-readable format */
فراغ	sshbuf_dump_data(ثابت فراغ *s, size_t len, FILE *f);

/* Return the hexadecimal representation of the contents of the buffer */
حرف	*sshbuf_dtob16(ثابت بنية sshbuf *buf);
/* Make a sshbuf from a hex string */
بنية sshbuf *sshbuf_b16tod(ثابت حرف *b16);

/* Encode the contents of the buffer as base64 */
حرف	*sshbuf_dtob64_string(ثابت بنية sshbuf *buf, صحيح wrap);
صحيح	sshbuf_dtob64(ثابت بنية sshbuf *d, بنية sshbuf *b64, صحيح wrap);
/* RFC4648 "base64url" encoding variant */
صحيح	sshbuf_dtourlb64(ثابت بنية sshbuf *d, بنية sshbuf *b64, صحيح wrap);

/* Decode base64 data and append it to the buffer */
صحيح	sshbuf_b64tod(بنية sshbuf *buf, ثابت حرف *b64);

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
صحيح	sshbuf_cmp(ثابت بنية sshbuf *b, size_t offset,
    ثابت فراغ *s, size_t len);

/*
 * Test whether two buffers have identical contents.
 * SSH_ERR_MESSAGE_INCOMPLETE indicates the buffers had differing size.
 * SSH_ERR_INVALID_FORMAT indicates the buffers were the same size but
 * had differing contents.
 * Returns 0 on successful compare (comparing two empty buffers returns 0).
 */
صحيح sshbuf_equals(ثابت بنية sshbuf *a, ثابت بنية sshbuf *b);

/*
 * Searches the buffer for the specified string. Returns 0 on success
 * and updates *offsetp with the offset of the first match, relative to
 * the start of the buffer. Otherwise sshbuf_find will return a ssherr.h
 * error code. SSH_ERR_INVALID_FORMAT indicates sufficient bytes were
 * present in the buffer for a match to be possible but none was found.
 * Searches for zero-length data are not allowed.
 */
صحيح
sshbuf_find(ثابت بنية sshbuf *b, size_t start_offset,
    ثابت فراغ *s, size_t len, size_t *offsetp);

/*
 * Duplicate the contents of a buffer to a string (caller to free).
 * Returns NULL on buffer error, or if the buffer contains a premature
 * nul character.
 */
حرف *sshbuf_dup_string(بنية sshbuf *buf);

/*
 * Fill a buffer from a file descriptor or filename. Both allocate the
 * buffer for the caller.
 */
صحيح sshbuf_load_fd(صحيح, بنية sshbuf **)
    __attribute__((__nonnull__ (2)));
صحيح sshbuf_load_file(ثابت حرف *, بنية sshbuf **)
    __attribute__((__nonnull__ (2)));

/*
 * Write a buffer to a path, creating/truncating as needed (mode 0644,
 * subject to umask). The buffer contents are not modified.
 */
صحيح sshbuf_write_file(ثابت حرف *path, بنية sshbuf *buf)
    __attribute__((__nonnull__ (2)));

/* Read up to maxlen bytes from a fd directly to a buffer */
صحيح sshbuf_read(صحيح, بنية sshbuf *, size_t, size_t *)
    __attribute__((__nonnull__ (2)));

/* Macros for decoding/encoding integers */
#define PEEK_U64(p) \
	(((uint64_t)(((ثابت u_char *)(p))[0]) << 56) | \
	 ((uint64_t)(((ثابت u_char *)(p))[1]) << 48) | \
	 ((uint64_t)(((ثابت u_char *)(p))[2]) << 40) | \
	 ((uint64_t)(((ثابت u_char *)(p))[3]) << 32) | \
	 ((uint64_t)(((ثابت u_char *)(p))[4]) << 24) | \
	 ((uint64_t)(((ثابت u_char *)(p))[5]) << 16) | \
	 ((uint64_t)(((ثابت u_char *)(p))[6]) << 8) | \
	  (uint64_t)(((ثابت u_char *)(p))[7]))
#define PEEK_U32(p) \
	(((uint32_t)(((ثابت u_char *)(p))[0]) << 24) | \
	 ((uint32_t)(((ثابت u_char *)(p))[1]) << 16) | \
	 ((uint32_t)(((ثابت u_char *)(p))[2]) << 8) | \
	  (uint32_t)(((ثابت u_char *)(p))[3]))
#define PEEK_U16(p) \
	(((uint16_t)(((ثابت u_char *)(p))[0]) << 8) | \
	  (uint16_t)(((ثابت u_char *)(p))[1]))

#define POKE_U64(p, v) \
	𐡏𐡁𐡃 { \
		ثابت uint64_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 56) & 0xff; \
		((u_char *)(p))[1] = (__v >> 48) & 0xff; \
		((u_char *)(p))[2] = (__v >> 40) & 0xff; \
		((u_char *)(p))[3] = (__v >> 32) & 0xff; \
		((u_char *)(p))[4] = (__v >> 24) & 0xff; \
		((u_char *)(p))[5] = (__v >> 16) & 0xff; \
		((u_char *)(p))[6] = (__v >> 8) & 0xff; \
		((u_char *)(p))[7] = __v & 0xff; \
	} طالما (0)
#define POKE_U32(p, v) \
	𐡏𐡁𐡃 { \
		ثابت uint32_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 24) & 0xff; \
		((u_char *)(p))[1] = (__v >> 16) & 0xff; \
		((u_char *)(p))[2] = (__v >> 8) & 0xff; \
		((u_char *)(p))[3] = __v & 0xff; \
	} طالما (0)
#define POKE_U16(p, v) \
	𐡏𐡁𐡃 { \
		ثابت uint16_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 8) & 0xff; \
		((u_char *)(p))[1] = __v & 0xff; \
	} طالما (0)

/* Internal definitions follow. Exposed for regress tests */
#ifdef SSHBUF_INTERNAL

/*
 * Return the allocation size of buf
 */
size_t	sshbuf_alloc(ثابت بنية sshbuf *buf);

/*
 * Increment the reference count of buf.
 */
صحيح	sshbuf_set_parent(بنية sshbuf *child, بنية sshbuf *parent);

/*
 * Return the parent buffer of buf, or NULL if it has no parent.
 */
ثابت بنية sshbuf *sshbuf_parent(ثابت بنية sshbuf *buf);

/*
 * Return the reference count of buf
 */
u_int	sshbuf_refcount(ثابت بنية sshbuf *buf);

# define SSHBUF_SIZE_INIT	256		/* Initial allocation */
# define SSHBUF_SIZE_INC	256		/* Preferred increment length */
# define SSHBUF_PACK_MIN	8192		/* Minimum packable offset */

/* # define SSHBUF_ABORT abort */
/* # define SSHBUF_DEBUG */

# ifndef SSHBUF_ABORT
#  define SSHBUF_ABORT()
# endif

# ifdef SSHBUF_DEBUG
#  define SSHBUF_DBG(x) 𐡏𐡁𐡃 { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} طالما (0)
# وإلا
#  define SSHBUF_DBG(x)
# endif
#endif /* SSHBUF_INTERNAL */

#endif /* _SSHBUF_H */
