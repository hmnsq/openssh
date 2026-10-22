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

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdint.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/ec.h>
#અન્તર્ભાવ <openssl/ecdsa.h>
#અન્તર્ભાવ <openssl/evp.h>
#નહીંતર /* OPENSSL */
#define BIGNUM		શૂન્ય
#define EC_ચાવી		શૂન્ય
#define EC_GROUP	શૂન્ય
#define EC_POINT	શૂન્ય
#define EVP_PKEY	શૂન્ય
#endif /* WITH_OPENSSL */

#define SSHBUF_SIZE_MAX		0x8000000	/* Hard maximum size */
#define SSHBUF_REFS_MAX		0x100000	/* Max child buffers */
#define SSHBUF_MAX_BIGNUM	(16384 / 8)	/* Max bignum *bytes* */
#define SSHBUF_MAX_ECPOINT	((528 * 2 / 8) + 1) /* Max EC point *bytes* */

સંરચના sshbuf;

/*
 * Create a new sshbuf buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
સંરચના sshbuf *sshbuf_new(શૂન્ય);

/*
 * Create a new, read-only sshbuf buffer from existing data.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
સંરચના sshbuf *sshbuf_from(અચલ શૂન્ય *blob, size_t len);

/*
 * Create a new, read-only sshbuf buffer from the contents of an existing
 * buffer. The contents of "buf" must not change in the lifetime of the
 * resultant buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
સંરચના sshbuf *sshbuf_fromb(સંરચના sshbuf *buf);

/*
 * Create a new, read-only sshbuf buffer from the contents of a string in
 * an existing buffer (the string is consumed in the process).
 * The contents of "buf" must not change in the lifetime of the resultant
 * buffer.
 * On success, a pointer to the newly allocated buffer is placed in *bufp.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
પૂર્ણાંક	sshbuf_froms(સંરચના sshbuf *buf, સંરચના sshbuf **bufp);

/*
 * Clear and free buf
 */
શૂન્ય	sshbuf_free(સંરચના sshbuf *buf);

/*
 * Reset buf, clearing its contents. NB. max_size is preserved.
 */
શૂન્ય	sshbuf_reset(સંરચના sshbuf *buf);

/*
 * Return the maximum size of buf
 */
size_t	sshbuf_max_size(અચલ સંરચના sshbuf *buf);

/*
 * Set the maximum size of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
પૂર્ણાંક	sshbuf_set_max_size(સંરચના sshbuf *buf, size_t max_size);

/*
 * Returns the length of data in buf
 */
size_t	sshbuf_len(અચલ સંરચના sshbuf *buf);

/*
 * Returns number of bytes left in buffer before hitting max_size.
 */
size_t	sshbuf_avail(અચલ સંરચના sshbuf *buf);

/*
 * Returns a read-only pointer to the start of the data in buf
 */
અચલ u_char *sshbuf_ptr(અચલ સંરચના sshbuf *buf);

/*
 * Returns a mutable pointer to the start of the data in buf, or
 * NULL if the buffer is read-only.
 */
u_char *sshbuf_mutable_ptr(અચલ સંરચના sshbuf *buf);

/*
 * Check whether a reservation of size len will succeed in buf
 * Safer to use than direct comparisons again sshbuf_avail as it copes
 * with unsigned overflows correctly.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
પૂર્ણાંક	sshbuf_check_reserve(અચલ સંરચના sshbuf *buf, size_t len);

/*
 * Preallocates len additional bytes in buf.
 * Useful for cases where the caller knows how many bytes will ultimately be
 * required to avoid realloc in the buffer code.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
પૂર્ણાંક	sshbuf_allocate(સંરચના sshbuf *buf, size_t len);

/*
 * Reserve len bytes in buf.
 * Returns 0 on success and a pointer to the first reserved byte via the
 * optional dpp parameter or a negative SSH_ERR_* error code on failure.
 */
પૂર્ણાંક	sshbuf_reserve(સંરચના sshbuf *buf, size_t len, u_char **dpp);

/*
 * Consume len bytes from the start of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
પૂર્ણાંક	sshbuf_consume(સંરચના sshbuf *buf, size_t len);

/*
 * Consume len bytes from the end of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
પૂર્ણાંક	sshbuf_consume_end(સંરચના sshbuf *buf, size_t len);

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
પૂર્ણાંક	sshbuf_consume_upto_child(સંરચના sshbuf *buf, અચલ સંરચના sshbuf *child);

/* Extract or deposit some bytes */
પૂર્ણાંક	sshbuf_get(સંરચના sshbuf *buf, શૂન્ય *v, size_t len);
પૂર્ણાંક	sshbuf_put(સંરચના sshbuf *buf, અચલ શૂન્ય *v, size_t len);
પૂર્ણાંક	sshbuf_putb(સંરચના sshbuf *buf, અચલ સંરચના sshbuf *v);

/* Append using a printf(3) format */
પૂર્ણાંક	sshbuf_putf(સંરચના sshbuf *buf, અચલ અક્ષર *fmt, ...)
	    __attribute__((format(printf, 2, 3)));
પૂર્ણાંક	sshbuf_putfv(સંરચના sshbuf *buf, અચલ અક્ષર *fmt, va_list ap);

/* Functions to extract or store big-endian words of various sizes */
પૂર્ણાંક	sshbuf_get_u64(સંરચના sshbuf *buf, uint64_t *valp);
પૂર્ણાંક	sshbuf_get_u32(સંરચના sshbuf *buf, uint32_t *valp);
પૂર્ણાંક	sshbuf_get_u16(સંરચના sshbuf *buf, uint16_t *valp);
પૂર્ણાંક	sshbuf_get_u8(સંરચના sshbuf *buf, u_char *valp);
પૂર્ણાંક	sshbuf_put_u64(સંરચના sshbuf *buf, uint64_t val);
પૂર્ણાંક	sshbuf_put_u32(સંરચના sshbuf *buf, uint32_t val);
પૂર્ણાંક	sshbuf_put_u16(સંરચના sshbuf *buf, uint16_t val);
પૂર્ણાંક	sshbuf_put_u8(સંરચના sshbuf *buf, u_char val);

/* Functions to peek at the contents of a buffer without modifying it. */
પૂર્ણાંક	sshbuf_peek_u64(અચલ સંરચના sshbuf *buf, size_t offset,
    uint64_t *valp);
પૂર્ણાંક	sshbuf_peek_u32(અચલ સંરચના sshbuf *buf, size_t offset,
    uint32_t *valp);
પૂર્ણાંક	sshbuf_peek_u16(અચલ સંરચના sshbuf *buf, size_t offset,
    uint16_t *valp);
પૂર્ણાંક	sshbuf_peek_u8(અચલ સંરચના sshbuf *buf, size_t offset,
    u_char *valp);

/*
 * Functions to poke values into an existing buffer (e.g. a length header
 * to a packet). The destination bytes must already exist in the buffer.
 */
પૂર્ણાંક sshbuf_poke_u64(સંરચના sshbuf *buf, size_t offset, uint64_t val);
પૂર્ણાંક sshbuf_poke_u32(સંરચના sshbuf *buf, size_t offset, uint32_t val);
પૂર્ણાંક sshbuf_poke_u16(સંરચના sshbuf *buf, size_t offset, uint16_t val);
પૂર્ણાંક sshbuf_poke_u8(સંરચના sshbuf *buf, size_t offset, u_char val);
પૂર્ણાંક sshbuf_poke(સંરચના sshbuf *buf, size_t offset, શૂન્ય *v, size_t len);

/*
 * Functions to extract or store SSH wire encoded strings (u32 len || data)
 * The "cstring" variants admit no \0 characters in the string contents.
 * Caller must free *valp.
 */
પૂર્ણાંક	sshbuf_get_string(સંરચના sshbuf *buf, u_char **valp, size_t *lenp);
પૂર્ણાંક	sshbuf_get_cstring(સંરચના sshbuf *buf, અક્ષર **valp, size_t *lenp);
પૂર્ણાંક	sshbuf_get_stringb(સંરચના sshbuf *buf, સંરચના sshbuf *v);
પૂર્ણાંક	sshbuf_put_string(સંરચના sshbuf *buf, અચલ શૂન્ય *v, size_t len);
પૂર્ણાંક	sshbuf_put_cstring(સંરચના sshbuf *buf, અચલ અક્ષર *v);
પૂર્ણાંક	sshbuf_put_stringb(સંરચના sshbuf *buf, અચલ સંરચના sshbuf *v);

/*
 * "Direct" variant of sshbuf_get_string, returns pointer into the sshbuf to
 * avoid an malloc+memcpy. The pointer is guaranteed to be valid until the
 * next sshbuf-modifying function call. Caller does not free.
 */
પૂર્ણાંક	sshbuf_get_string_direct(સંરચના sshbuf *buf, અચલ u_char **valp,
	    size_t *lenp);

/* Skip past a string */
#define sshbuf_skip_string(buf) sshbuf_get_string_direct(buf, ખાલી, ખાલી)

/* Another variant: "peeks" into the buffer without modifying it */
પૂર્ણાંક	sshbuf_peek_string_direct(અચલ સંરચના sshbuf *buf, અચલ u_char **valp,
	    size_t *lenp);

/*
 * Functions to extract or store SSH wire encoded bignums and elliptic
 * curve points.
 */
પૂર્ણાંક	sshbuf_get_bignum2(સંરચના sshbuf *buf, BIGNUM **valp);
પૂર્ણાંક	sshbuf_get_bignum2_bytes_direct(સંરચના sshbuf *buf,
	    અચલ u_char **valp, size_t *lenp);
પૂર્ણાંક	sshbuf_put_bignum2(સંરચના sshbuf *buf, અચલ BIGNUM *v);
પૂર્ણાંક	sshbuf_put_bignum2_bytes(સંરચના sshbuf *buf, અચલ શૂન્ય *v, size_t len);
પૂર્ણાંક	sshbuf_get_ec(સંરચના sshbuf *buf, EC_POINT *v, અચલ EC_GROUP *g);
પૂર્ણાંક	sshbuf_get_eckey(સંરચના sshbuf *buf, EC_ચાવી *v);
પૂર્ણાંક	sshbuf_put_ec(સંરચના sshbuf *buf, અચલ EC_POINT *v, અચલ EC_GROUP *g);
પૂર્ણાંક	sshbuf_put_eckey(સંરચના sshbuf *buf, અચલ EC_ચાવી *v);
પૂર્ણાંક	sshbuf_put_ec_pkey(સંરચના sshbuf *buf, EVP_PKEY *pkey);

/* Functions to extract or store various non-SSH wire encoded values */
પૂર્ણાંક	sshbuf_get_nulterminated_string(સંરચના sshbuf *buf, size_t maxlen,
	    અક્ષર **valp, size_t *lenp);

/* Dump the contents of the buffer in a human-readable format */
શૂન્ય	sshbuf_dump(અચલ સંરચના sshbuf *buf, FILE *f);

/* Dump specified memory in a human-readable format */
શૂન્ય	sshbuf_dump_data(અચલ શૂન્ય *s, size_t len, FILE *f);

/* Return the hexadecimal representation of the contents of the buffer */
અક્ષર	*sshbuf_dtob16(અચલ સંરચના sshbuf *buf);
/* Make a sshbuf from a hex string */
સંરચના sshbuf *sshbuf_b16tod(અચલ અક્ષર *b16);

/* Encode the contents of the buffer as base64 */
અક્ષર	*sshbuf_dtob64_string(અચલ સંરચના sshbuf *buf, પૂર્ણાંક wrap);
પૂર્ણાંક	sshbuf_dtob64(અચલ સંરચના sshbuf *d, સંરચના sshbuf *b64, પૂર્ણાંક wrap);
/* RFC4648 "base64url" encoding variant */
પૂર્ણાંક	sshbuf_dtourlb64(અચલ સંરચના sshbuf *d, સંરચના sshbuf *b64, પૂર્ણાંક wrap);

/* Decode base64 data and append it to the buffer */
પૂર્ણાંક	sshbuf_b64tod(સંરચના sshbuf *buf, અચલ અક્ષર *b64);

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
પૂર્ણાંક	sshbuf_cmp(અચલ સંરચના sshbuf *b, size_t offset,
    અચલ શૂન્ય *s, size_t len);

/*
 * Test whether two buffers have identical contents.
 * SSH_ERR_MESSAGE_INCOMPLETE indicates the buffers had differing size.
 * SSH_ERR_INVALID_FORMAT indicates the buffers were the same size but
 * had differing contents.
 * Returns 0 on successful compare (comparing two empty buffers returns 0).
 */
પૂર્ણાંક sshbuf_equals(અચલ સંરચના sshbuf *a, અચલ સંરચના sshbuf *b);

/*
 * Searches the buffer for the specified string. Returns 0 on success
 * and updates *offsetp with the offset of the first match, relative to
 * the start of the buffer. Otherwise sshbuf_find will return a ssherr.h
 * error code. SSH_ERR_INVALID_FORMAT indicates sufficient bytes were
 * present in the buffer for a match to be possible but none was found.
 * Searches for zero-length data are not allowed.
 */
પૂર્ણાંક
sshbuf_find(અચલ સંરચના sshbuf *b, size_t start_offset,
    અચલ શૂન્ય *s, size_t len, size_t *offsetp);

/*
 * Duplicate the contents of a buffer to a string (caller to free).
 * Returns NULL on buffer error, or if the buffer contains a premature
 * nul character.
 */
અક્ષર *sshbuf_dup_string(સંરચના sshbuf *buf);

/*
 * Fill a buffer from a file descriptor or filename. Both allocate the
 * buffer for the caller.
 */
પૂર્ણાંક sshbuf_load_fd(પૂર્ણાંક, સંરચના sshbuf **)
    __attribute__((__nonnull__ (2)));
પૂર્ણાંક sshbuf_load_file(અચલ અક્ષર *, સંરચના sshbuf **)
    __attribute__((__nonnull__ (2)));

/*
 * Write a buffer to a path, creating/truncating as needed (mode 0644,
 * subject to umask). The buffer contents are not modified.
 */
પૂર્ણાંક sshbuf_write_file(અચલ અક્ષર *path, સંરચના sshbuf *buf)
    __attribute__((__nonnull__ (2)));

/* Read up to maxlen bytes from a fd directly to a buffer */
પૂર્ણાંક sshbuf_read(પૂર્ણાંક, સંરચના sshbuf *, size_t, size_t *)
    __attribute__((__nonnull__ (2)));

/* Macros for decoding/encoding integers */
#define PEEK_U64(p) \
	(((uint64_t)(((અચલ u_char *)(p))[0]) << 56) | \
	 ((uint64_t)(((અચલ u_char *)(p))[1]) << 48) | \
	 ((uint64_t)(((અચલ u_char *)(p))[2]) << 40) | \
	 ((uint64_t)(((અચલ u_char *)(p))[3]) << 32) | \
	 ((uint64_t)(((અચલ u_char *)(p))[4]) << 24) | \
	 ((uint64_t)(((અચલ u_char *)(p))[5]) << 16) | \
	 ((uint64_t)(((અચલ u_char *)(p))[6]) << 8) | \
	  (uint64_t)(((અચલ u_char *)(p))[7]))
#define PEEK_U32(p) \
	(((uint32_t)(((અચલ u_char *)(p))[0]) << 24) | \
	 ((uint32_t)(((અચલ u_char *)(p))[1]) << 16) | \
	 ((uint32_t)(((અચલ u_char *)(p))[2]) << 8) | \
	  (uint32_t)(((અચલ u_char *)(p))[3]))
#define PEEK_U16(p) \
	(((uint16_t)(((અચલ u_char *)(p))[0]) << 8) | \
	  (uint16_t)(((અચલ u_char *)(p))[1]))

#define POKE_U64(p, v) \
	કરો { \
		અચલ uint64_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 56) & 0xff; \
		((u_char *)(p))[1] = (__v >> 48) & 0xff; \
		((u_char *)(p))[2] = (__v >> 40) & 0xff; \
		((u_char *)(p))[3] = (__v >> 32) & 0xff; \
		((u_char *)(p))[4] = (__v >> 24) & 0xff; \
		((u_char *)(p))[5] = (__v >> 16) & 0xff; \
		((u_char *)(p))[6] = (__v >> 8) & 0xff; \
		((u_char *)(p))[7] = __v & 0xff; \
	} જ્યારે (0)
#define POKE_U32(p, v) \
	કરો { \
		અચલ uint32_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 24) & 0xff; \
		((u_char *)(p))[1] = (__v >> 16) & 0xff; \
		((u_char *)(p))[2] = (__v >> 8) & 0xff; \
		((u_char *)(p))[3] = __v & 0xff; \
	} જ્યારે (0)
#define POKE_U16(p, v) \
	કરો { \
		અચલ uint16_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 8) & 0xff; \
		((u_char *)(p))[1] = __v & 0xff; \
	} જ્યારે (0)

/* Internal definitions follow. Exposed for regress tests */
#ifdef SSHBUF_INTERNAL

/*
 * Return the allocation size of buf
 */
size_t	sshbuf_alloc(અચલ સંરચના sshbuf *buf);

/*
 * Increment the reference count of buf.
 */
પૂર્ણાંક	sshbuf_set_parent(સંરચના sshbuf *child, સંરચના sshbuf *parent);

/*
 * Return the parent buffer of buf, or NULL if it has no parent.
 */
અચલ સંરચના sshbuf *sshbuf_parent(અચલ સંરચના sshbuf *buf);

/*
 * Return the reference count of buf
 */
u_int	sshbuf_refcount(અચલ સંરચના sshbuf *buf);

# define SSHBUF_SIZE_INIT	256		/* Initial allocation */
# define SSHBUF_SIZE_INC	256		/* Preferred increment length */
# define SSHBUF_PACK_MIN	8192		/* Minimum packable offset */

/* # define SSHBUF_ABORT abort */
/* # define SSHBUF_DEBUG */

# ifndef SSHBUF_ABORT
#  define SSHBUF_ABORT()
# endif

# ifdef SSHBUF_DEBUG
#  define SSHBUF_DBG(x) કરો { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} જ્યારે (0)
# નહીંતર
#  define SSHBUF_DBG(x)
# endif
#endif /* SSHBUF_INTERNAL */

#endif /* _SSHBUF_H */
