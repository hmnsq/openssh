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

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdint.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/ec.h>
#அந்தர்பாவ <openssl/ecdsa.h>
#அந்தர்பாவ <openssl/evp.h>
#இல்லையெனில் /* OPENSSL */
#define BIGNUM		வெறுமை
#define EC_சாவி		வெறுமை
#define EC_GROUP	வெறுமை
#define EC_POINT	வெறுமை
#define EVP_PKEY	வெறுமை
#endif /* WITH_OPENSSL */

#define SSHBUF_SIZE_MAX		0x8000000	/* Hard maximum size */
#define SSHBUF_REFS_MAX		0x100000	/* Max child buffers */
#define SSHBUF_MAX_BIGNUM	(16384 / 8)	/* Max bignum *bytes* */
#define SSHBUF_MAX_ECPOINT	((528 * 2 / 8) + 1) /* Max EC point *bytes* */

கட்டமைப்பு sshbuf;

/*
 * Create a new sshbuf buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
கட்டமைப்பு sshbuf *sshbuf_new(வெறுமை);

/*
 * Create a new, read-only sshbuf buffer from existing data.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
கட்டமைப்பு sshbuf *sshbuf_from(மாறிலி வெறுமை *blob, size_t len);

/*
 * Create a new, read-only sshbuf buffer from the contents of an existing
 * buffer. The contents of "buf" must not change in the lifetime of the
 * resultant buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
கட்டமைப்பு sshbuf *sshbuf_fromb(கட்டமைப்பு sshbuf *buf);

/*
 * Create a new, read-only sshbuf buffer from the contents of a string in
 * an existing buffer (the string is consumed in the process).
 * The contents of "buf" must not change in the lifetime of the resultant
 * buffer.
 * On success, a pointer to the newly allocated buffer is placed in *bufp.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
முழு	sshbuf_froms(கட்டமைப்பு sshbuf *buf, கட்டமைப்பு sshbuf **bufp);

/*
 * Clear and free buf
 */
வெறுமை	sshbuf_free(கட்டமைப்பு sshbuf *buf);

/*
 * Reset buf, clearing its contents. NB. max_size is preserved.
 */
வெறுமை	sshbuf_reset(கட்டமைப்பு sshbuf *buf);

/*
 * Return the maximum size of buf
 */
size_t	sshbuf_max_size(மாறிலி கட்டமைப்பு sshbuf *buf);

/*
 * Set the maximum size of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
முழு	sshbuf_set_max_size(கட்டமைப்பு sshbuf *buf, size_t max_size);

/*
 * Returns the length of data in buf
 */
size_t	sshbuf_len(மாறிலி கட்டமைப்பு sshbuf *buf);

/*
 * Returns number of bytes left in buffer before hitting max_size.
 */
size_t	sshbuf_avail(மாறிலி கட்டமைப்பு sshbuf *buf);

/*
 * Returns a read-only pointer to the start of the data in buf
 */
மாறிலி u_char *sshbuf_ptr(மாறிலி கட்டமைப்பு sshbuf *buf);

/*
 * Returns a mutable pointer to the start of the data in buf, or
 * NULL if the buffer is read-only.
 */
u_char *sshbuf_mutable_ptr(மாறிலி கட்டமைப்பு sshbuf *buf);

/*
 * Check whether a reservation of size len will succeed in buf
 * Safer to use than direct comparisons again sshbuf_avail as it copes
 * with unsigned overflows correctly.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
முழு	sshbuf_check_reserve(மாறிலி கட்டமைப்பு sshbuf *buf, size_t len);

/*
 * Preallocates len additional bytes in buf.
 * Useful for cases where the caller knows how many bytes will ultimately be
 * required to avoid realloc in the buffer code.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
முழு	sshbuf_allocate(கட்டமைப்பு sshbuf *buf, size_t len);

/*
 * Reserve len bytes in buf.
 * Returns 0 on success and a pointer to the first reserved byte via the
 * optional dpp parameter or a negative SSH_ERR_* error code on failure.
 */
முழு	sshbuf_reserve(கட்டமைப்பு sshbuf *buf, size_t len, u_char **dpp);

/*
 * Consume len bytes from the start of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
முழு	sshbuf_consume(கட்டமைப்பு sshbuf *buf, size_t len);

/*
 * Consume len bytes from the end of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
முழு	sshbuf_consume_end(கட்டமைப்பு sshbuf *buf, size_t len);

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
முழு	sshbuf_consume_upto_child(கட்டமைப்பு sshbuf *buf, மாறிலி கட்டமைப்பு sshbuf *child);

/* Extract or deposit some bytes */
முழு	sshbuf_get(கட்டமைப்பு sshbuf *buf, வெறுமை *v, size_t len);
முழு	sshbuf_put(கட்டமைப்பு sshbuf *buf, மாறிலி வெறுமை *v, size_t len);
முழு	sshbuf_putb(கட்டமைப்பு sshbuf *buf, மாறிலி கட்டமைப்பு sshbuf *v);

/* Append using a printf(3) format */
முழு	sshbuf_putf(கட்டமைப்பு sshbuf *buf, மாறிலி எழுத்து *fmt, ...)
	    __attribute__((format(printf, 2, 3)));
முழு	sshbuf_putfv(கட்டமைப்பு sshbuf *buf, மாறிலி எழுத்து *fmt, va_list ap);

/* Functions to extract or store big-endian words of various sizes */
முழு	sshbuf_get_u64(கட்டமைப்பு sshbuf *buf, uint64_t *valp);
முழு	sshbuf_get_u32(கட்டமைப்பு sshbuf *buf, uint32_t *valp);
முழு	sshbuf_get_u16(கட்டமைப்பு sshbuf *buf, uint16_t *valp);
முழு	sshbuf_get_u8(கட்டமைப்பு sshbuf *buf, u_char *valp);
முழு	sshbuf_put_u64(கட்டமைப்பு sshbuf *buf, uint64_t val);
முழு	sshbuf_put_u32(கட்டமைப்பு sshbuf *buf, uint32_t val);
முழு	sshbuf_put_u16(கட்டமைப்பு sshbuf *buf, uint16_t val);
முழு	sshbuf_put_u8(கட்டமைப்பு sshbuf *buf, u_char val);

/* Functions to peek at the contents of a buffer without modifying it. */
முழு	sshbuf_peek_u64(மாறிலி கட்டமைப்பு sshbuf *buf, size_t offset,
    uint64_t *valp);
முழு	sshbuf_peek_u32(மாறிலி கட்டமைப்பு sshbuf *buf, size_t offset,
    uint32_t *valp);
முழு	sshbuf_peek_u16(மாறிலி கட்டமைப்பு sshbuf *buf, size_t offset,
    uint16_t *valp);
முழு	sshbuf_peek_u8(மாறிலி கட்டமைப்பு sshbuf *buf, size_t offset,
    u_char *valp);

/*
 * Functions to poke values into an existing buffer (e.g. a length header
 * to a packet). The destination bytes must already exist in the buffer.
 */
முழு sshbuf_poke_u64(கட்டமைப்பு sshbuf *buf, size_t offset, uint64_t val);
முழு sshbuf_poke_u32(கட்டமைப்பு sshbuf *buf, size_t offset, uint32_t val);
முழு sshbuf_poke_u16(கட்டமைப்பு sshbuf *buf, size_t offset, uint16_t val);
முழு sshbuf_poke_u8(கட்டமைப்பு sshbuf *buf, size_t offset, u_char val);
முழு sshbuf_poke(கட்டமைப்பு sshbuf *buf, size_t offset, வெறுமை *v, size_t len);

/*
 * Functions to extract or store SSH wire encoded strings (u32 len || data)
 * The "cstring" variants admit no \0 characters in the string contents.
 * Caller must free *valp.
 */
முழு	sshbuf_get_string(கட்டமைப்பு sshbuf *buf, u_char **valp, size_t *lenp);
முழு	sshbuf_get_cstring(கட்டமைப்பு sshbuf *buf, எழுத்து **valp, size_t *lenp);
முழு	sshbuf_get_stringb(கட்டமைப்பு sshbuf *buf, கட்டமைப்பு sshbuf *v);
முழு	sshbuf_put_string(கட்டமைப்பு sshbuf *buf, மாறிலி வெறுமை *v, size_t len);
முழு	sshbuf_put_cstring(கட்டமைப்பு sshbuf *buf, மாறிலி எழுத்து *v);
முழு	sshbuf_put_stringb(கட்டமைப்பு sshbuf *buf, மாறிலி கட்டமைப்பு sshbuf *v);

/*
 * "Direct" variant of sshbuf_get_string, returns pointer into the sshbuf to
 * avoid an malloc+memcpy. The pointer is guaranteed to be valid until the
 * next sshbuf-modifying function call. Caller does not free.
 */
முழு	sshbuf_get_string_direct(கட்டமைப்பு sshbuf *buf, மாறிலி u_char **valp,
	    size_t *lenp);

/* Skip past a string */
#define sshbuf_skip_string(buf) sshbuf_get_string_direct(buf, வெற்று, வெற்று)

/* Another variant: "peeks" into the buffer without modifying it */
முழு	sshbuf_peek_string_direct(மாறிலி கட்டமைப்பு sshbuf *buf, மாறிலி u_char **valp,
	    size_t *lenp);

/*
 * Functions to extract or store SSH wire encoded bignums and elliptic
 * curve points.
 */
முழு	sshbuf_get_bignum2(கட்டமைப்பு sshbuf *buf, BIGNUM **valp);
முழு	sshbuf_get_bignum2_bytes_direct(கட்டமைப்பு sshbuf *buf,
	    மாறிலி u_char **valp, size_t *lenp);
முழு	sshbuf_put_bignum2(கட்டமைப்பு sshbuf *buf, மாறிலி BIGNUM *v);
முழு	sshbuf_put_bignum2_bytes(கட்டமைப்பு sshbuf *buf, மாறிலி வெறுமை *v, size_t len);
முழு	sshbuf_get_ec(கட்டமைப்பு sshbuf *buf, EC_POINT *v, மாறிலி EC_GROUP *g);
முழு	sshbuf_get_eckey(கட்டமைப்பு sshbuf *buf, EC_சாவி *v);
முழு	sshbuf_put_ec(கட்டமைப்பு sshbuf *buf, மாறிலி EC_POINT *v, மாறிலி EC_GROUP *g);
முழு	sshbuf_put_eckey(கட்டமைப்பு sshbuf *buf, மாறிலி EC_சாவி *v);
முழு	sshbuf_put_ec_pkey(கட்டமைப்பு sshbuf *buf, EVP_PKEY *pkey);

/* Functions to extract or store various non-SSH wire encoded values */
முழு	sshbuf_get_nulterminated_string(கட்டமைப்பு sshbuf *buf, size_t maxlen,
	    எழுத்து **valp, size_t *lenp);

/* Dump the contents of the buffer in a human-readable format */
வெறுமை	sshbuf_dump(மாறிலி கட்டமைப்பு sshbuf *buf, FILE *f);

/* Dump specified memory in a human-readable format */
வெறுமை	sshbuf_dump_data(மாறிலி வெறுமை *s, size_t len, FILE *f);

/* Return the hexadecimal representation of the contents of the buffer */
எழுத்து	*sshbuf_dtob16(மாறிலி கட்டமைப்பு sshbuf *buf);
/* Make a sshbuf from a hex string */
கட்டமைப்பு sshbuf *sshbuf_b16tod(மாறிலி எழுத்து *b16);

/* Encode the contents of the buffer as base64 */
எழுத்து	*sshbuf_dtob64_string(மாறிலி கட்டமைப்பு sshbuf *buf, முழு wrap);
முழு	sshbuf_dtob64(மாறிலி கட்டமைப்பு sshbuf *d, கட்டமைப்பு sshbuf *b64, முழு wrap);
/* RFC4648 "base64url" encoding variant */
முழு	sshbuf_dtourlb64(மாறிலி கட்டமைப்பு sshbuf *d, கட்டமைப்பு sshbuf *b64, முழு wrap);

/* Decode base64 data and append it to the buffer */
முழு	sshbuf_b64tod(கட்டமைப்பு sshbuf *buf, மாறிலி எழுத்து *b64);

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
முழு	sshbuf_cmp(மாறிலி கட்டமைப்பு sshbuf *b, size_t offset,
    மாறிலி வெறுமை *s, size_t len);

/*
 * Test whether two buffers have identical contents.
 * SSH_ERR_MESSAGE_INCOMPLETE indicates the buffers had differing size.
 * SSH_ERR_INVALID_FORMAT indicates the buffers were the same size but
 * had differing contents.
 * Returns 0 on successful compare (comparing two empty buffers returns 0).
 */
முழு sshbuf_equals(மாறிலி கட்டமைப்பு sshbuf *a, மாறிலி கட்டமைப்பு sshbuf *b);

/*
 * Searches the buffer for the specified string. Returns 0 on success
 * and updates *offsetp with the offset of the first match, relative to
 * the start of the buffer. Otherwise sshbuf_find will return a ssherr.h
 * error code. SSH_ERR_INVALID_FORMAT indicates sufficient bytes were
 * present in the buffer for a match to be possible but none was found.
 * Searches for zero-length data are not allowed.
 */
முழு
sshbuf_find(மாறிலி கட்டமைப்பு sshbuf *b, size_t start_offset,
    மாறிலி வெறுமை *s, size_t len, size_t *offsetp);

/*
 * Duplicate the contents of a buffer to a string (caller to free).
 * Returns NULL on buffer error, or if the buffer contains a premature
 * nul character.
 */
எழுத்து *sshbuf_dup_string(கட்டமைப்பு sshbuf *buf);

/*
 * Fill a buffer from a file descriptor or filename. Both allocate the
 * buffer for the caller.
 */
முழு sshbuf_load_fd(முழு, கட்டமைப்பு sshbuf **)
    __attribute__((__nonnull__ (2)));
முழு sshbuf_load_file(மாறிலி எழுத்து *, கட்டமைப்பு sshbuf **)
    __attribute__((__nonnull__ (2)));

/*
 * Write a buffer to a path, creating/truncating as needed (mode 0644,
 * subject to umask). The buffer contents are not modified.
 */
முழு sshbuf_write_file(மாறிலி எழுத்து *path, கட்டமைப்பு sshbuf *buf)
    __attribute__((__nonnull__ (2)));

/* Read up to maxlen bytes from a fd directly to a buffer */
முழு sshbuf_read(முழு, கட்டமைப்பு sshbuf *, size_t, size_t *)
    __attribute__((__nonnull__ (2)));

/* Macros for decoding/encoding integers */
#define PEEK_U64(p) \
	(((uint64_t)(((மாறிலி u_char *)(p))[0]) << 56) | \
	 ((uint64_t)(((மாறிலி u_char *)(p))[1]) << 48) | \
	 ((uint64_t)(((மாறிலி u_char *)(p))[2]) << 40) | \
	 ((uint64_t)(((மாறிலி u_char *)(p))[3]) << 32) | \
	 ((uint64_t)(((மாறிலி u_char *)(p))[4]) << 24) | \
	 ((uint64_t)(((மாறிலி u_char *)(p))[5]) << 16) | \
	 ((uint64_t)(((மாறிலி u_char *)(p))[6]) << 8) | \
	  (uint64_t)(((மாறிலி u_char *)(p))[7]))
#define PEEK_U32(p) \
	(((uint32_t)(((மாறிலி u_char *)(p))[0]) << 24) | \
	 ((uint32_t)(((மாறிலி u_char *)(p))[1]) << 16) | \
	 ((uint32_t)(((மாறிலி u_char *)(p))[2]) << 8) | \
	  (uint32_t)(((மாறிலி u_char *)(p))[3]))
#define PEEK_U16(p) \
	(((uint16_t)(((மாறிலி u_char *)(p))[0]) << 8) | \
	  (uint16_t)(((மாறிலி u_char *)(p))[1]))

#define POKE_U64(p, v) \
	செய் { \
		மாறிலி uint64_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 56) & 0xff; \
		((u_char *)(p))[1] = (__v >> 48) & 0xff; \
		((u_char *)(p))[2] = (__v >> 40) & 0xff; \
		((u_char *)(p))[3] = (__v >> 32) & 0xff; \
		((u_char *)(p))[4] = (__v >> 24) & 0xff; \
		((u_char *)(p))[5] = (__v >> 16) & 0xff; \
		((u_char *)(p))[6] = (__v >> 8) & 0xff; \
		((u_char *)(p))[7] = __v & 0xff; \
	} போது (0)
#define POKE_U32(p, v) \
	செய் { \
		மாறிலி uint32_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 24) & 0xff; \
		((u_char *)(p))[1] = (__v >> 16) & 0xff; \
		((u_char *)(p))[2] = (__v >> 8) & 0xff; \
		((u_char *)(p))[3] = __v & 0xff; \
	} போது (0)
#define POKE_U16(p, v) \
	செய் { \
		மாறிலி uint16_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 8) & 0xff; \
		((u_char *)(p))[1] = __v & 0xff; \
	} போது (0)

/* Internal definitions follow. Exposed for regress tests */
#ifdef SSHBUF_INTERNAL

/*
 * Return the allocation size of buf
 */
size_t	sshbuf_alloc(மாறிலி கட்டமைப்பு sshbuf *buf);

/*
 * Increment the reference count of buf.
 */
முழு	sshbuf_set_parent(கட்டமைப்பு sshbuf *child, கட்டமைப்பு sshbuf *parent);

/*
 * Return the parent buffer of buf, or NULL if it has no parent.
 */
மாறிலி கட்டமைப்பு sshbuf *sshbuf_parent(மாறிலி கட்டமைப்பு sshbuf *buf);

/*
 * Return the reference count of buf
 */
u_int	sshbuf_refcount(மாறிலி கட்டமைப்பு sshbuf *buf);

# define SSHBUF_SIZE_INIT	256		/* Initial allocation */
# define SSHBUF_SIZE_INC	256		/* Preferred increment length */
# define SSHBUF_PACK_MIN	8192		/* Minimum packable offset */

/* # define SSHBUF_ABORT abort */
/* # define SSHBUF_DEBUG */

# ifndef SSHBUF_ABORT
#  define SSHBUF_ABORT()
# endif

# ifdef SSHBUF_DEBUG
#  define SSHBUF_DBG(x) செய் { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} போது (0)
# இல்லையெனில்
#  define SSHBUF_DBG(x)
# endif
#endif /* SSHBUF_INTERNAL */

#endif /* _SSHBUF_H */
