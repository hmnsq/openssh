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

#నిర్వచితం_కాకపోతే _SSHBUF_H
#నిర్వచించు _SSHBUF_H

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdint.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/ec.h>
#అన్తర్భావ <openssl/ecdsa.h>
#అన్తర్భావ <openssl/evp.h>
#లేకపోతే /* OPENSSL */
#నిర్వచించు BIGNUM		శూన్య
#నిర్వచించు EC_కీలకం		శూన్య
#నిర్వచించు EC_సమూహం	శూన్య
#నిర్వచించు EC_బిందువు	శూన్య
#నిర్వచించు EVP_PKEY	శూన్య
#అయితే_ముగింపు /* WITH_OPENSSL */

#నిర్వచించు SSHBUF_కొలత_MAX		0x8000000	/* Hard maximum size */
#నిర్వచించు SSHBUF_REFS_MAX		0x100000	/* Max child buffers */
#నిర్వచించు SSHBUF_MAX_BIGNUM	(16384 / 8)	/* Max bignum *bytes* */
#నిర్వచించు SSHBUF_MAX_ECPOINT	((528 * 2 / 8) + 1) /* Max EC point *bytes* */

నిర్మాణం sshbuf;

/*
 * Create a new sshbuf buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
నిర్మాణం sshbuf *sshbuf_new(శూన్య);

/*
 * Create a new, read-only sshbuf buffer from existing data.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
నిర్మాణం sshbuf *sshbuf_from(స్థిరరాశి శూన్య *blob, కొలత_t len);

/*
 * Create a new, read-only sshbuf buffer from the contents of an existing
 * buffer. The contents of "buf" must not change in the lifetime of the
 * resultant buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
నిర్మాణం sshbuf *sshbuf_fromb(నిర్మాణం sshbuf *buf);

/*
 * Create a new, read-only sshbuf buffer from the contents of a string in
 * an existing buffer (the string is consumed in the process).
 * The contents of "buf" must not change in the lifetime of the resultant
 * buffer.
 * On success, a pointer to the newly allocated buffer is placed in *bufp.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
పూర్ణాంకం	sshbuf_froms(నిర్మాణం sshbuf *buf, నిర్మాణం sshbuf **bufp);

/*
 * Clear and free buf
 */
శూన్య	sshbuf_free(నిర్మాణం sshbuf *buf);

/*
 * Reset buf, clearing its contents. NB. max_size is preserved.
 */
శూన్య	sshbuf_reset(నిర్మాణం sshbuf *buf);

/*
 * Return the maximum size of buf
 */
కొలత_t	sshbuf_max_కొలత(స్థిరరాశి నిర్మాణం sshbuf *buf);

/*
 * Set the maximum size of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
పూర్ణాంకం	sshbuf_సమితి_max_కొలత(నిర్మాణం sshbuf *buf, కొలత_t max_కొలత);

/*
 * Returns the length of data in buf
 */
కొలత_t	sshbuf_len(స్థిరరాశి నిర్మాణం sshbuf *buf);

/*
 * Returns number of bytes left in buffer before hitting max_size.
 */
కొలత_t	sshbuf_avail(స్థిరరాశి నిర్మాణం sshbuf *buf);

/*
 * Returns a read-only pointer to the start of the data in buf
 */
స్థిరరాశి u_char *sshbuf_ptr(స్థిరరాశి నిర్మాణం sshbuf *buf);

/*
 * Returns a mutable pointer to the start of the data in buf, or
 * NULL if the buffer is read-only.
 */
u_char *sshbuf_mutable_ptr(స్థిరరాశి నిర్మాణం sshbuf *buf);

/*
 * Check whether a reservation of size len will succeed in buf
 * Safer to use than direct comparisons again sshbuf_avail as it copes
 * with unsigned overflows correctly.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
పూర్ణాంకం	sshbuf_check_reserve(స్థిరరాశి నిర్మాణం sshbuf *buf, కొలత_t len);

/*
 * Preallocates len additional bytes in buf.
 * Useful for cases where the caller knows how many bytes will ultimately be
 * required to avoid realloc in the buffer code.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
పూర్ణాంకం	sshbuf_allocate(నిర్మాణం sshbuf *buf, కొలత_t len);

/*
 * Reserve len bytes in buf.
 * Returns 0 on success and a pointer to the first reserved byte via the
 * optional dpp parameter or a negative SSH_ERR_* error code on failure.
 */
పూర్ణాంకం	sshbuf_reserve(నిర్మాణం sshbuf *buf, కొలత_t len, u_char **dpp);

/*
 * Consume len bytes from the start of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
పూర్ణాంకం	sshbuf_consume(నిర్మాణం sshbuf *buf, కొలత_t len);

/*
 * Consume len bytes from the end of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
పూర్ణాంకం	sshbuf_consume_చివర(నిర్మాణం sshbuf *buf, కొలత_t len);

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
పూర్ణాంకం	sshbuf_consume_upto_బిడ్డ(నిర్మాణం sshbuf *buf, స్థిరరాశి నిర్మాణం sshbuf *బిడ్డ);

/* Extract or deposit some bytes */
పూర్ణాంకం	sshbuf_get(నిర్మాణం sshbuf *buf, శూన్య *v, కొలత_t len);
పూర్ణాంకం	sshbuf_put(నిర్మాణం sshbuf *buf, స్థిరరాశి శూన్య *v, కొలత_t len);
పూర్ణాంకం	sshbuf_putb(నిర్మాణం sshbuf *buf, స్థిరరాశి నిర్మాణం sshbuf *v);

/* Append using a printf(3) format */
పూర్ణాంకం	sshbuf_putf(నిర్మాణం sshbuf *buf, స్థిరరాశి అక్షరం *fmt, ...)
	    __attribute__((format(రాయి, 2, 3)));
పూర్ణాంకం	sshbuf_putfv(నిర్మాణం sshbuf *buf, స్థిరరాశి అక్షరం *fmt, va_list ap);

/* Functions to extract or store big-endian words of various sizes */
పూర్ణాంకం	sshbuf_get_u64(నిర్మాణం sshbuf *buf, uint64_t *valp);
పూర్ణాంకం	sshbuf_get_u32(నిర్మాణం sshbuf *buf, uint32_t *valp);
పూర్ణాంకం	sshbuf_get_u16(నిర్మాణం sshbuf *buf, uint16_t *valp);
పూర్ణాంకం	sshbuf_get_u8(నిర్మాణం sshbuf *buf, u_char *valp);
పూర్ణాంకం	sshbuf_put_u64(నిర్మాణం sshbuf *buf, uint64_t val);
పూర్ణాంకం	sshbuf_put_u32(నిర్మాణం sshbuf *buf, uint32_t val);
పూర్ణాంకం	sshbuf_put_u16(నిర్మాణం sshbuf *buf, uint16_t val);
పూర్ణాంకం	sshbuf_put_u8(నిర్మాణం sshbuf *buf, u_char val);

/* Functions to peek at the contents of a buffer without modifying it. */
పూర్ణాంకం	sshbuf_peek_u64(స్థిరరాశి నిర్మాణం sshbuf *buf, కొలత_t స్థానభ్రంశం,
    uint64_t *valp);
పూర్ణాంకం	sshbuf_peek_u32(స్థిరరాశి నిర్మాణం sshbuf *buf, కొలత_t స్థానభ్రంశం,
    uint32_t *valp);
పూర్ణాంకం	sshbuf_peek_u16(స్థిరరాశి నిర్మాణం sshbuf *buf, కొలత_t స్థానభ్రంశం,
    uint16_t *valp);
పూర్ణాంకం	sshbuf_peek_u8(స్థిరరాశి నిర్మాణం sshbuf *buf, కొలత_t స్థానభ్రంశం,
    u_char *valp);

/*
 * Functions to poke values into an existing buffer (e.g. a length header
 * to a packet). The destination bytes must already exist in the buffer.
 */
పూర్ణాంకం sshbuf_poke_u64(నిర్మాణం sshbuf *buf, కొలత_t స్థానభ్రంశం, uint64_t val);
పూర్ణాంకం sshbuf_poke_u32(నిర్మాణం sshbuf *buf, కొలత_t స్థానభ్రంశం, uint32_t val);
పూర్ణాంకం sshbuf_poke_u16(నిర్మాణం sshbuf *buf, కొలత_t స్థానభ్రంశం, uint16_t val);
పూర్ణాంకం sshbuf_poke_u8(నిర్మాణం sshbuf *buf, కొలత_t స్థానభ్రంశం, u_char val);
పూర్ణాంకం sshbuf_poke(నిర్మాణం sshbuf *buf, కొలత_t స్థానభ్రంశం, శూన్య *v, కొలత_t len);

/*
 * Functions to extract or store SSH wire encoded strings (u32 len || data)
 * The "cstring" variants admit no \0 characters in the string contents.
 * Caller must free *valp.
 */
పూర్ణాంకం	sshbuf_get_string(నిర్మాణం sshbuf *buf, u_char **valp, కొలత_t *lenp);
పూర్ణాంకం	sshbuf_get_cstring(నిర్మాణం sshbuf *buf, అక్షరం **valp, కొలత_t *lenp);
పూర్ణాంకం	sshbuf_get_stringb(నిర్మాణం sshbuf *buf, నిర్మాణం sshbuf *v);
పూర్ణాంకం	sshbuf_put_string(నిర్మాణం sshbuf *buf, స్థిరరాశి శూన్య *v, కొలత_t len);
పూర్ణాంకం	sshbuf_put_cstring(నిర్మాణం sshbuf *buf, స్థిరరాశి అక్షరం *v);
పూర్ణాంకం	sshbuf_put_stringb(నిర్మాణం sshbuf *buf, స్థిరరాశి నిర్మాణం sshbuf *v);

/*
 * "Direct" variant of sshbuf_get_string, returns pointer into the sshbuf to
 * avoid an malloc+memcpy. The pointer is guaranteed to be valid until the
 * next sshbuf-modifying function call. Caller does not free.
 */
పూర్ణాంకం	sshbuf_get_string_ప్రత్యక్ష(నిర్మాణం sshbuf *buf, స్థిరరాశి u_char **valp,
	    కొలత_t *lenp);

/* Skip past a string */
#నిర్వచించు sshbuf_skip_string(buf) sshbuf_get_string_ప్రత్యక్ష(buf, ఖాళీ, ఖాళీ)

/* Another variant: "peeks" into the buffer without modifying it */
పూర్ణాంకం	sshbuf_peek_string_ప్రత్యక్ష(స్థిరరాశి నిర్మాణం sshbuf *buf, స్థిరరాశి u_char **valp,
	    కొలత_t *lenp);

/*
 * Functions to extract or store SSH wire encoded bignums and elliptic
 * curve points.
 */
పూర్ణాంకం	sshbuf_get_bignum2(నిర్మాణం sshbuf *buf, BIGNUM **valp);
పూర్ణాంకం	sshbuf_get_bignum2_బైట్లు_ప్రత్యక్ష(నిర్మాణం sshbuf *buf,
	    స్థిరరాశి u_char **valp, కొలత_t *lenp);
పూర్ణాంకం	sshbuf_put_bignum2(నిర్మాణం sshbuf *buf, స్థిరరాశి BIGNUM *v);
పూర్ణాంకం	sshbuf_put_bignum2_బైట్లు(నిర్మాణం sshbuf *buf, స్థిరరాశి శూన్య *v, కొలత_t len);
పూర్ణాంకం	sshbuf_get_ec(నిర్మాణం sshbuf *buf, EC_బిందువు *v, స్థిరరాశి EC_సమూహం *g);
పూర్ణాంకం	sshbuf_get_eckey(నిర్మాణం sshbuf *buf, EC_కీలకం *v);
పూర్ణాంకం	sshbuf_put_ec(నిర్మాణం sshbuf *buf, స్థిరరాశి EC_బిందువు *v, స్థిరరాశి EC_సమూహం *g);
పూర్ణాంకం	sshbuf_put_eckey(నిర్మాణం sshbuf *buf, స్థిరరాశి EC_కీలకం *v);
పూర్ణాంకం	sshbuf_put_ec_pkey(నిర్మాణం sshbuf *buf, EVP_PKEY *pkey);

/* Functions to extract or store various non-SSH wire encoded values */
పూర్ణాంకం	sshbuf_get_nulterminated_string(నిర్మాణం sshbuf *buf, కొలత_t maxlen,
	    అక్షరం **valp, కొలత_t *lenp);

/* Dump the contents of the buffer in a human-readable format */
శూన్య	sshbuf_dump(స్థిరరాశి నిర్మాణం sshbuf *buf, FILE *f);

/* Dump specified memory in a human-readable format */
శూన్య	sshbuf_dump_దత్తాంశం(స్థిరరాశి శూన్య *s, కొలత_t len, FILE *f);

/* Return the hexadecimal representation of the contents of the buffer */
అక్షరం	*sshbuf_dtob16(స్థిరరాశి నిర్మాణం sshbuf *buf);
/* Make a sshbuf from a hex string */
నిర్మాణం sshbuf *sshbuf_b16tod(స్థిరరాశి అక్షరం *b16);

/* Encode the contents of the buffer as base64 */
అక్షరం	*sshbuf_dtob64_string(స్థిరరాశి నిర్మాణం sshbuf *buf, పూర్ణాంకం wrap);
పూర్ణాంకం	sshbuf_dtob64(స్థిరరాశి నిర్మాణం sshbuf *d, నిర్మాణం sshbuf *b64, పూర్ణాంకం wrap);
/* RFC4648 "base64url" encoding variant */
పూర్ణాంకం	sshbuf_dtourlb64(స్థిరరాశి నిర్మాణం sshbuf *d, నిర్మాణం sshbuf *b64, పూర్ణాంకం wrap);

/* Decode base64 data and append it to the buffer */
పూర్ణాంకం	sshbuf_b64tod(నిర్మాణం sshbuf *buf, స్థిరరాశి అక్షరం *b64);

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
పూర్ణాంకం	sshbuf_cmp(స్థిరరాశి నిర్మాణం sshbuf *b, కొలత_t స్థానభ్రంశం,
    స్థిరరాశి శూన్య *s, కొలత_t len);

/*
 * Test whether two buffers have identical contents.
 * SSH_ERR_MESSAGE_INCOMPLETE indicates the buffers had differing size.
 * SSH_ERR_INVALID_FORMAT indicates the buffers were the same size but
 * had differing contents.
 * Returns 0 on successful compare (comparing two empty buffers returns 0).
 */
పూర్ణాంకం sshbuf_equals(స్థిరరాశి నిర్మాణం sshbuf *a, స్థిరరాశి నిర్మాణం sshbuf *b);

/*
 * Searches the buffer for the specified string. Returns 0 on success
 * and updates *offsetp with the offset of the first match, relative to
 * the start of the buffer. Otherwise sshbuf_find will return a ssherr.h
 * error code. SSH_ERR_INVALID_FORMAT indicates sufficient bytes were
 * present in the buffer for a match to be possible but none was found.
 * Searches for zero-length data are not allowed.
 */
పూర్ణాంకం
sshbuf_కనుగొను(స్థిరరాశి నిర్మాణం sshbuf *b, కొలత_t ప్రారంభం_స్థానభ్రంశం,
    స్థిరరాశి శూన్య *s, కొలత_t len, కొలత_t *offsetp);

/*
 * Duplicate the contents of a buffer to a string (caller to free).
 * Returns NULL on buffer error, or if the buffer contains a premature
 * nul character.
 */
అక్షరం *sshbuf_dup_string(నిర్మాణం sshbuf *buf);

/*
 * Fill a buffer from a file descriptor or filename. Both allocate the
 * buffer for the caller.
 */
పూర్ణాంకం sshbuf_ఎక్కించు_fd(పూర్ణాంకం, నిర్మాణం sshbuf **)
    __attribute__((__nonnull__ (2)));
పూర్ణాంకం sshbuf_ఎక్కించు_file(స్థిరరాశి అక్షరం *, నిర్మాణం sshbuf **)
    __attribute__((__nonnull__ (2)));

/*
 * Write a buffer to a path, creating/truncating as needed (mode 0644,
 * subject to umask). The buffer contents are not modified.
 */
పూర్ణాంకం sshbuf_write_file(స్థిరరాశి అక్షరం *మార్గం, నిర్మాణం sshbuf *buf)
    __attribute__((__nonnull__ (2)));

/* Read up to maxlen bytes from a fd directly to a buffer */
పూర్ణాంకం sshbuf_read(పూర్ణాంకం, నిర్మాణం sshbuf *, కొలత_t, కొలత_t *)
    __attribute__((__nonnull__ (2)));

/* Macros for decoding/encoding integers */
#నిర్వచించు PEEK_U64(p) \
	(((uint64_t)(((స్థిరరాశి u_char *)(p))[0]) << 56) | \
	 ((uint64_t)(((స్థిరరాశి u_char *)(p))[1]) << 48) | \
	 ((uint64_t)(((స్థిరరాశి u_char *)(p))[2]) << 40) | \
	 ((uint64_t)(((స్థిరరాశి u_char *)(p))[3]) << 32) | \
	 ((uint64_t)(((స్థిరరాశి u_char *)(p))[4]) << 24) | \
	 ((uint64_t)(((స్థిరరాశి u_char *)(p))[5]) << 16) | \
	 ((uint64_t)(((స్థిరరాశి u_char *)(p))[6]) << 8) | \
	  (uint64_t)(((స్థిరరాశి u_char *)(p))[7]))
#నిర్వచించు PEEK_U32(p) \
	(((uint32_t)(((స్థిరరాశి u_char *)(p))[0]) << 24) | \
	 ((uint32_t)(((స్థిరరాశి u_char *)(p))[1]) << 16) | \
	 ((uint32_t)(((స్థిరరాశి u_char *)(p))[2]) << 8) | \
	  (uint32_t)(((స్థిరరాశి u_char *)(p))[3]))
#నిర్వచించు PEEK_U16(p) \
	(((uint16_t)(((స్థిరరాశి u_char *)(p))[0]) << 8) | \
	  (uint16_t)(((స్థిరరాశి u_char *)(p))[1]))

#నిర్వచించు POKE_U64(p, v) \
	చేయి { \
		స్థిరరాశి uint64_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 56) & 0xff; \
		((u_char *)(p))[1] = (__v >> 48) & 0xff; \
		((u_char *)(p))[2] = (__v >> 40) & 0xff; \
		((u_char *)(p))[3] = (__v >> 32) & 0xff; \
		((u_char *)(p))[4] = (__v >> 24) & 0xff; \
		((u_char *)(p))[5] = (__v >> 16) & 0xff; \
		((u_char *)(p))[6] = (__v >> 8) & 0xff; \
		((u_char *)(p))[7] = __v & 0xff; \
	} అయితే (0)
#నిర్వచించు POKE_U32(p, v) \
	చేయి { \
		స్థిరరాశి uint32_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 24) & 0xff; \
		((u_char *)(p))[1] = (__v >> 16) & 0xff; \
		((u_char *)(p))[2] = (__v >> 8) & 0xff; \
		((u_char *)(p))[3] = __v & 0xff; \
	} అయితే (0)
#నిర్వచించు POKE_U16(p, v) \
	చేయి { \
		స్థిరరాశి uint16_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 8) & 0xff; \
		((u_char *)(p))[1] = __v & 0xff; \
	} అయితే (0)

/* Internal definitions follow. Exposed for regress tests */
#నిర్వచితమైతే SSHBUF_అంతర్గత

/*
 * Return the allocation size of buf
 */
కొలత_t	sshbuf_alloc(స్థిరరాశి నిర్మాణం sshbuf *buf);

/*
 * Increment the reference count of buf.
 */
పూర్ణాంకం	sshbuf_సమితి_మాతృ(నిర్మాణం sshbuf *బిడ్డ, నిర్మాణం sshbuf *మాతృ);

/*
 * Return the parent buffer of buf, or NULL if it has no parent.
 */
స్థిరరాశి నిర్మాణం sshbuf *sshbuf_మాతృ(స్థిరరాశి నిర్మాణం sshbuf *buf);

/*
 * Return the reference count of buf
 */
u_int	sshbuf_refcount(స్థిరరాశి నిర్మాణం sshbuf *buf);

# define SSHBUF_కొలత_INIT	256		/* Initial allocation */
# define SSHBUF_కొలత_INC	256		/* Preferred increment length */
# define SSHBUF_PACK_MIN	8192		/* Minimum packable offset */

/* # define SSHBUF_ABORT abort */
/* # define SSHBUF_DEBUG */

# ifndef SSHBUF_ABORT
#  define SSHBUF_ABORT()
# endif

# ifdef SSHBUF_DEBUG
#  define SSHBUF_DBG(x) చేయి { \
		రాయి("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		రాయి x; \
		రాయి("\n"); \
		fflush(stdout); \
	} అయితే (0)
# లేకపోతే
#  define SSHBUF_DBG(x)
# endif
#అయితే_ముగింపు /* SSHBUF_INTERNAL */

#అయితే_ముగింపు /* _SSHBUF_H */
