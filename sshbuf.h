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

#अगर_अघोषित _SSHBUF_H
#घोषणा _SSHBUF_H

#समावेश <sys/types.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdint.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/bn.h>
#समावेश <openssl/ec.h>
#समावेश <openssl/ecdsa.h>
#समावेश <openssl/evp.h>
#अन्यथा /* OPENSSL */
#घोषणा BIGNUM		व्योम
#घोषणा EC_कुंजी		व्योम
#घोषणा EC_GROUP	व्योम
#घोषणा EC_POINT	व्योम
#घोषणा EVP_PKEY	व्योम
#पूर्ण_अगर /* WITH_OPENSSL */

#घोषणा SSHBUF_आकार_MAX		0x8000000	/* Hard maximum size */
#घोषणा SSHBUF_REFS_MAX		0x100000	/* Max child buffers */
#घोषणा SSHBUF_MAX_BIGNUM	(16384 / 8)	/* Max bignum *bytes* */
#घोषणा SSHBUF_MAX_ECPOINT	((528 * 2 / 8) + 1) /* Max EC point *bytes* */

काष्ठा sshbuf;

/*
 * Create a new sshbuf buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
काष्ठा sshbuf *sshbuf_new(व्योम);

/*
 * Create a new, read-only sshbuf buffer from existing data.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
काष्ठा sshbuf *sshbuf_from(स्थिर व्योम *blob, माप_प्रकार len);

/*
 * Create a new, read-only sshbuf buffer from the contents of an existing
 * buffer. The contents of "buf" must not change in the lifetime of the
 * resultant buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
काष्ठा sshbuf *sshbuf_fromb(काष्ठा sshbuf *buf);

/*
 * Create a new, read-only sshbuf buffer from the contents of a string in
 * an existing buffer (the string is consumed in the process).
 * The contents of "buf" must not change in the lifetime of the resultant
 * buffer.
 * On success, a pointer to the newly allocated buffer is placed in *bufp.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
पूर्णांक	sshbuf_froms(काष्ठा sshbuf *buf, काष्ठा sshbuf **bufp);

/*
 * Clear and free buf
 */
व्योम	sshbuf_free(काष्ठा sshbuf *buf);

/*
 * Reset buf, clearing its contents. NB. max_size is preserved.
 */
व्योम	sshbuf_reset(काष्ठा sshbuf *buf);

/*
 * Return the maximum size of buf
 */
माप_प्रकार	sshbuf_max_आकार(स्थिर काष्ठा sshbuf *buf);

/*
 * Set the maximum size of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
पूर्णांक	sshbuf_set_max_आकार(काष्ठा sshbuf *buf, माप_प्रकार max_आकार);

/*
 * Returns the length of data in buf
 */
माप_प्रकार	sshbuf_len(स्थिर काष्ठा sshbuf *buf);

/*
 * Returns number of bytes left in buffer before hitting max_size.
 */
माप_प्रकार	sshbuf_avail(स्थिर काष्ठा sshbuf *buf);

/*
 * Returns a read-only pointer to the start of the data in buf
 */
स्थिर u_char *sshbuf_ptr(स्थिर काष्ठा sshbuf *buf);

/*
 * Returns a mutable pointer to the start of the data in buf, or
 * NULL if the buffer is read-only.
 */
u_char *sshbuf_mutable_ptr(स्थिर काष्ठा sshbuf *buf);

/*
 * Check whether a reservation of size len will succeed in buf
 * Safer to use than direct comparisons again sshbuf_avail as it copes
 * with unsigned overflows correctly.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
पूर्णांक	sshbuf_check_reserve(स्थिर काष्ठा sshbuf *buf, माप_प्रकार len);

/*
 * Preallocates len additional bytes in buf.
 * Useful for cases where the caller knows how many bytes will ultimately be
 * required to avoid realloc in the buffer code.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
पूर्णांक	sshbuf_allocate(काष्ठा sshbuf *buf, माप_प्रकार len);

/*
 * Reserve len bytes in buf.
 * Returns 0 on success and a pointer to the first reserved byte via the
 * optional dpp parameter or a negative SSH_ERR_* error code on failure.
 */
पूर्णांक	sshbuf_reserve(काष्ठा sshbuf *buf, माप_प्रकार len, u_char **dpp);

/*
 * Consume len bytes from the start of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
पूर्णांक	sshbuf_consume(काष्ठा sshbuf *buf, माप_प्रकार len);

/*
 * Consume len bytes from the end of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
पूर्णांक	sshbuf_consume_end(काष्ठा sshbuf *buf, माप_प्रकार len);

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
पूर्णांक	sshbuf_consume_upto_child(काष्ठा sshbuf *buf, स्थिर काष्ठा sshbuf *child);

/* Extract or deposit some bytes */
पूर्णांक	sshbuf_get(काष्ठा sshbuf *buf, व्योम *v, माप_प्रकार len);
पूर्णांक	sshbuf_put(काष्ठा sshbuf *buf, स्थिर व्योम *v, माप_प्रकार len);
पूर्णांक	sshbuf_putb(काष्ठा sshbuf *buf, स्थिर काष्ठा sshbuf *v);

/* Append using a printf(3) format */
पूर्णांक	sshbuf_putf(काष्ठा sshbuf *buf, स्थिर अक्षर *fmt, ...)
	    __attribute__((format(म_लिखो, 2, 3)));
पूर्णांक	sshbuf_putfv(काष्ठा sshbuf *buf, स्थिर अक्षर *fmt, बहु_सूची ap);

/* Functions to extract or store big-endian words of various sizes */
पूर्णांक	sshbuf_get_u64(काष्ठा sshbuf *buf, uint64_t *valp);
पूर्णांक	sshbuf_get_u32(काष्ठा sshbuf *buf, uint32_t *valp);
पूर्णांक	sshbuf_get_u16(काष्ठा sshbuf *buf, uint16_t *valp);
पूर्णांक	sshbuf_get_u8(काष्ठा sshbuf *buf, u_char *valp);
पूर्णांक	sshbuf_put_u64(काष्ठा sshbuf *buf, uint64_t val);
पूर्णांक	sshbuf_put_u32(काष्ठा sshbuf *buf, uint32_t val);
पूर्णांक	sshbuf_put_u16(काष्ठा sshbuf *buf, uint16_t val);
पूर्णांक	sshbuf_put_u8(काष्ठा sshbuf *buf, u_char val);

/* Functions to peek at the contents of a buffer without modifying it. */
पूर्णांक	sshbuf_peek_u64(स्थिर काष्ठा sshbuf *buf, माप_प्रकार offset,
    uint64_t *valp);
पूर्णांक	sshbuf_peek_u32(स्थिर काष्ठा sshbuf *buf, माप_प्रकार offset,
    uint32_t *valp);
पूर्णांक	sshbuf_peek_u16(स्थिर काष्ठा sshbuf *buf, माप_प्रकार offset,
    uint16_t *valp);
पूर्णांक	sshbuf_peek_u8(स्थिर काष्ठा sshbuf *buf, माप_प्रकार offset,
    u_char *valp);

/*
 * Functions to poke values into an existing buffer (e.g. a length header
 * to a packet). The destination bytes must already exist in the buffer.
 */
पूर्णांक sshbuf_poke_u64(काष्ठा sshbuf *buf, माप_प्रकार offset, uint64_t val);
पूर्णांक sshbuf_poke_u32(काष्ठा sshbuf *buf, माप_प्रकार offset, uint32_t val);
पूर्णांक sshbuf_poke_u16(काष्ठा sshbuf *buf, माप_प्रकार offset, uint16_t val);
पूर्णांक sshbuf_poke_u8(काष्ठा sshbuf *buf, माप_प्रकार offset, u_char val);
पूर्णांक sshbuf_poke(काष्ठा sshbuf *buf, माप_प्रकार offset, व्योम *v, माप_प्रकार len);

/*
 * Functions to extract or store SSH wire encoded strings (u32 len || data)
 * The "cstring" variants admit no \0 characters in the string contents.
 * Caller must free *valp.
 */
पूर्णांक	sshbuf_get_string(काष्ठा sshbuf *buf, u_char **valp, माप_प्रकार *lenp);
पूर्णांक	sshbuf_get_cstring(काष्ठा sshbuf *buf, अक्षर **valp, माप_प्रकार *lenp);
पूर्णांक	sshbuf_get_stringb(काष्ठा sshbuf *buf, काष्ठा sshbuf *v);
पूर्णांक	sshbuf_put_string(काष्ठा sshbuf *buf, स्थिर व्योम *v, माप_प्रकार len);
पूर्णांक	sshbuf_put_cstring(काष्ठा sshbuf *buf, स्थिर अक्षर *v);
पूर्णांक	sshbuf_put_stringb(काष्ठा sshbuf *buf, स्थिर काष्ठा sshbuf *v);

/*
 * "Direct" variant of sshbuf_get_string, returns pointer into the sshbuf to
 * avoid an malloc+memcpy. The pointer is guaranteed to be valid until the
 * next sshbuf-modifying function call. Caller does not free.
 */
पूर्णांक	sshbuf_get_string_direct(काष्ठा sshbuf *buf, स्थिर u_char **valp,
	    माप_प्रकार *lenp);

/* Skip past a string */
#घोषणा sshbuf_skip_string(buf) sshbuf_get_string_direct(buf, शून्य, शून्य)

/* Another variant: "peeks" into the buffer without modifying it */
पूर्णांक	sshbuf_peek_string_direct(स्थिर काष्ठा sshbuf *buf, स्थिर u_char **valp,
	    माप_प्रकार *lenp);

/*
 * Functions to extract or store SSH wire encoded bignums and elliptic
 * curve points.
 */
पूर्णांक	sshbuf_get_bignum2(काष्ठा sshbuf *buf, BIGNUM **valp);
पूर्णांक	sshbuf_get_bignum2_bytes_direct(काष्ठा sshbuf *buf,
	    स्थिर u_char **valp, माप_प्रकार *lenp);
पूर्णांक	sshbuf_put_bignum2(काष्ठा sshbuf *buf, स्थिर BIGNUM *v);
पूर्णांक	sshbuf_put_bignum2_bytes(काष्ठा sshbuf *buf, स्थिर व्योम *v, माप_प्रकार len);
पूर्णांक	sshbuf_get_ec(काष्ठा sshbuf *buf, EC_POINT *v, स्थिर EC_GROUP *g);
पूर्णांक	sshbuf_get_eckey(काष्ठा sshbuf *buf, EC_कुंजी *v);
पूर्णांक	sshbuf_put_ec(काष्ठा sshbuf *buf, स्थिर EC_POINT *v, स्थिर EC_GROUP *g);
पूर्णांक	sshbuf_put_eckey(काष्ठा sshbuf *buf, स्थिर EC_कुंजी *v);
पूर्णांक	sshbuf_put_ec_pkey(काष्ठा sshbuf *buf, EVP_PKEY *pkey);

/* Functions to extract or store various non-SSH wire encoded values */
पूर्णांक	sshbuf_get_nulterminated_string(काष्ठा sshbuf *buf, माप_प्रकार maxlen,
	    अक्षर **valp, माप_प्रकार *lenp);

/* Dump the contents of the buffer in a human-readable format */
व्योम	sshbuf_dump(स्थिर काष्ठा sshbuf *buf, खाता *f);

/* Dump specified memory in a human-readable format */
व्योम	sshbuf_dump_तथ्य(स्थिर व्योम *s, माप_प्रकार len, खाता *f);

/* Return the hexadecimal representation of the contents of the buffer */
अक्षर	*sshbuf_dtob16(स्थिर काष्ठा sshbuf *buf);
/* Make a sshbuf from a hex string */
काष्ठा sshbuf *sshbuf_b16tod(स्थिर अक्षर *b16);

/* Encode the contents of the buffer as base64 */
अक्षर	*sshbuf_dtob64_string(स्थिर काष्ठा sshbuf *buf, पूर्णांक wrap);
पूर्णांक	sshbuf_dtob64(स्थिर काष्ठा sshbuf *d, काष्ठा sshbuf *b64, पूर्णांक wrap);
/* RFC4648 "base64url" encoding variant */
पूर्णांक	sshbuf_dtourlb64(स्थिर काष्ठा sshbuf *d, काष्ठा sshbuf *b64, पूर्णांक wrap);

/* Decode base64 data and append it to the buffer */
पूर्णांक	sshbuf_b64tod(काष्ठा sshbuf *buf, स्थिर अक्षर *b64);

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
पूर्णांक	sshbuf_cmp(स्थिर काष्ठा sshbuf *b, माप_प्रकार offset,
    स्थिर व्योम *s, माप_प्रकार len);

/*
 * Test whether two buffers have identical contents.
 * SSH_ERR_MESSAGE_INCOMPLETE indicates the buffers had differing size.
 * SSH_ERR_INVALID_FORMAT indicates the buffers were the same size but
 * had differing contents.
 * Returns 0 on successful compare (comparing two empty buffers returns 0).
 */
पूर्णांक sshbuf_equals(स्थिर काष्ठा sshbuf *a, स्थिर काष्ठा sshbuf *b);

/*
 * Searches the buffer for the specified string. Returns 0 on success
 * and updates *offsetp with the offset of the first match, relative to
 * the start of the buffer. Otherwise sshbuf_find will return a ssherr.h
 * error code. SSH_ERR_INVALID_FORMAT indicates sufficient bytes were
 * present in the buffer for a match to be possible but none was found.
 * Searches for zero-length data are not allowed.
 */
पूर्णांक
sshbuf_find(स्थिर काष्ठा sshbuf *b, माप_प्रकार start_offset,
    स्थिर व्योम *s, माप_प्रकार len, माप_प्रकार *offsetp);

/*
 * Duplicate the contents of a buffer to a string (caller to free).
 * Returns NULL on buffer error, or if the buffer contains a premature
 * nul character.
 */
अक्षर *sshbuf_dup_string(काष्ठा sshbuf *buf);

/*
 * Fill a buffer from a file descriptor or filename. Both allocate the
 * buffer for the caller.
 */
पूर्णांक sshbuf_load_fd(पूर्णांक, काष्ठा sshbuf **)
    __attribute__((__nonnull__ (2)));
पूर्णांक sshbuf_load_file(स्थिर अक्षर *, काष्ठा sshbuf **)
    __attribute__((__nonnull__ (2)));

/*
 * Write a buffer to a path, creating/truncating as needed (mode 0644,
 * subject to umask). The buffer contents are not modified.
 */
पूर्णांक sshbuf_write_file(स्थिर अक्षर *path, काष्ठा sshbuf *buf)
    __attribute__((__nonnull__ (2)));

/* Read up to maxlen bytes from a fd directly to a buffer */
पूर्णांक sshbuf_read(पूर्णांक, काष्ठा sshbuf *, माप_प्रकार, माप_प्रकार *)
    __attribute__((__nonnull__ (2)));

/* Macros for decoding/encoding integers */
#घोषणा PEEK_U64(p) \
	(((uint64_t)(((स्थिर u_char *)(p))[0]) << 56) | \
	 ((uint64_t)(((स्थिर u_char *)(p))[1]) << 48) | \
	 ((uint64_t)(((स्थिर u_char *)(p))[2]) << 40) | \
	 ((uint64_t)(((स्थिर u_char *)(p))[3]) << 32) | \
	 ((uint64_t)(((स्थिर u_char *)(p))[4]) << 24) | \
	 ((uint64_t)(((स्थिर u_char *)(p))[5]) << 16) | \
	 ((uint64_t)(((स्थिर u_char *)(p))[6]) << 8) | \
	  (uint64_t)(((स्थिर u_char *)(p))[7]))
#घोषणा PEEK_U32(p) \
	(((uint32_t)(((स्थिर u_char *)(p))[0]) << 24) | \
	 ((uint32_t)(((स्थिर u_char *)(p))[1]) << 16) | \
	 ((uint32_t)(((स्थिर u_char *)(p))[2]) << 8) | \
	  (uint32_t)(((स्थिर u_char *)(p))[3]))
#घोषणा PEEK_U16(p) \
	(((uint16_t)(((स्थिर u_char *)(p))[0]) << 8) | \
	  (uint16_t)(((स्थिर u_char *)(p))[1]))

#घोषणा POKE_U64(p, v) \
	करो { \
		स्थिर uint64_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 56) & 0xff; \
		((u_char *)(p))[1] = (__v >> 48) & 0xff; \
		((u_char *)(p))[2] = (__v >> 40) & 0xff; \
		((u_char *)(p))[3] = (__v >> 32) & 0xff; \
		((u_char *)(p))[4] = (__v >> 24) & 0xff; \
		((u_char *)(p))[5] = (__v >> 16) & 0xff; \
		((u_char *)(p))[6] = (__v >> 8) & 0xff; \
		((u_char *)(p))[7] = __v & 0xff; \
	} जबतक (0)
#घोषणा POKE_U32(p, v) \
	करो { \
		स्थिर uint32_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 24) & 0xff; \
		((u_char *)(p))[1] = (__v >> 16) & 0xff; \
		((u_char *)(p))[2] = (__v >> 8) & 0xff; \
		((u_char *)(p))[3] = __v & 0xff; \
	} जबतक (0)
#घोषणा POKE_U16(p, v) \
	करो { \
		स्थिर uint16_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 8) & 0xff; \
		((u_char *)(p))[1] = __v & 0xff; \
	} जबतक (0)

/* Internal definitions follow. Exposed for regress tests */
#अगर_घोषित SSHBUF_INTERNAL

/*
 * Return the allocation size of buf
 */
माप_प्रकार	sshbuf_alloc(स्थिर काष्ठा sshbuf *buf);

/*
 * Increment the reference count of buf.
 */
पूर्णांक	sshbuf_set_parent(काष्ठा sshbuf *child, काष्ठा sshbuf *parent);

/*
 * Return the parent buffer of buf, or NULL if it has no parent.
 */
स्थिर काष्ठा sshbuf *sshbuf_parent(स्थिर काष्ठा sshbuf *buf);

/*
 * Return the reference count of buf
 */
u_int	sshbuf_refcount(स्थिर काष्ठा sshbuf *buf);

# define SSHBUF_आकार_INIT	256		/* Initial allocation */
# define SSHBUF_आकार_INC	256		/* Preferred increment length */
# define SSHBUF_PACK_MIN	8192		/* Minimum packable offset */

/* # define SSHBUF_ABORT abort */
/* # define SSHBUF_DEBUG */

# ifndef SSHBUF_ABORT
#  define SSHBUF_ABORT()
# endif

# ifdef SSHBUF_DEBUG
#  define SSHBUF_DBG(x) करो { \
		म_लिखो("%s:%d %s: ", __खाता__, __LINE__, __func__); \
		म_लिखो x; \
		म_लिखो("\n"); \
		ख_साफ(मानक_निकास); \
	} जबतक (0)
# अन्यथा
#  define SSHBUF_DBG(x)
# endif
#पूर्ण_अगर /* SSHBUF_INTERNAL */

#पूर्ण_अगर /* _SSHBUF_H */
