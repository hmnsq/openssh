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

#اگر_غیر_تعریف_شدہ _SSHBUF_H
#تعریف_کرو _SSHBUF_H

#شامل <sys/types.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdint.h>

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/bn.h>
#شامل <openssl/ec.h>
#شامل <openssl/ecdsa.h>
#شامل <openssl/evp.h>
#ورنہ /* OPENSSL */
#تعریف_کرو BIGNUM		خالی
#تعریف_کرو EC_کلید		خالی
#تعریف_کرو EC_گروہ	خالی
#تعریف_کرو EC_نقطہ	خالی
#تعریف_کرو EVP_PKEY	خالی
#اگر_ختم /* WITH_OPENSSL */

#تعریف_کرو SSHBUF_سائز_MAX		0x8000000	/* Hard maximum size */
#تعریف_کرو SSHBUF_REFS_MAX		0x100000	/* Max child buffers */
#تعریف_کرو SSHBUF_MAX_BIGNUM	(16384 / 8)	/* Max bignum *bytes* */
#تعریف_کرو SSHBUF_MAX_ECPOINT	((528 * 2 / 8) + 1) /* Max EC point *bytes* */

ساخت sshbuf;

/*
 * Create a new sshbuf buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
ساخت sshbuf *sshbuf_new(خالی);

/*
 * Create a new, read-only sshbuf buffer from existing data.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
ساخت sshbuf *sshbuf_from(ثابت خالی *blob, سائز_t len);

/*
 * Create a new, read-only sshbuf buffer from the contents of an existing
 * buffer. The contents of "buf" must not change in the lifetime of the
 * resultant buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
ساخت sshbuf *sshbuf_fromb(ساخت sshbuf *buf);

/*
 * Create a new, read-only sshbuf buffer from the contents of a string in
 * an existing buffer (the string is consumed in the process).
 * The contents of "buf" must not change in the lifetime of the resultant
 * buffer.
 * On success, a pointer to the newly allocated buffer is placed in *bufp.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
صحیح	sshbuf_froms(ساخت sshbuf *buf, ساخت sshbuf **bufp);

/*
 * Clear and free buf
 */
خالی	sshbuf_free(ساخت sshbuf *buf);

/*
 * Reset buf, clearing its contents. NB. max_size is preserved.
 */
خالی	sshbuf_reset(ساخت sshbuf *buf);

/*
 * Return the maximum size of buf
 */
سائز_t	sshbuf_max_سائز(ثابت ساخت sshbuf *buf);

/*
 * Set the maximum size of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
صحیح	sshbuf_سیٹ_max_سائز(ساخت sshbuf *buf, سائز_t max_سائز);

/*
 * Returns the length of data in buf
 */
سائز_t	sshbuf_len(ثابت ساخت sshbuf *buf);

/*
 * Returns number of bytes left in buffer before hitting max_size.
 */
سائز_t	sshbuf_avail(ثابت ساخت sshbuf *buf);

/*
 * Returns a read-only pointer to the start of the data in buf
 */
ثابت u_char *sshbuf_ptr(ثابت ساخت sshbuf *buf);

/*
 * Returns a mutable pointer to the start of the data in buf, or
 * NULL if the buffer is read-only.
 */
u_char *sshbuf_mutable_ptr(ثابت ساخت sshbuf *buf);

/*
 * Check whether a reservation of size len will succeed in buf
 * Safer to use than direct comparisons again sshbuf_avail as it copes
 * with unsigned overflows correctly.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
صحیح	sshbuf_check_reserve(ثابت ساخت sshbuf *buf, سائز_t len);

/*
 * Preallocates len additional bytes in buf.
 * Useful for cases where the caller knows how many bytes will ultimately be
 * required to avoid realloc in the buffer code.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
صحیح	sshbuf_allocate(ساخت sshbuf *buf, سائز_t len);

/*
 * Reserve len bytes in buf.
 * Returns 0 on success and a pointer to the first reserved byte via the
 * optional dpp parameter or a negative SSH_ERR_* error code on failure.
 */
صحیح	sshbuf_reserve(ساخت sshbuf *buf, سائز_t len, u_char **dpp);

/*
 * Consume len bytes from the start of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
صحیح	sshbuf_consume(ساخت sshbuf *buf, سائز_t len);

/*
 * Consume len bytes from the end of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
صحیح	sshbuf_consume_انتہا(ساخت sshbuf *buf, سائز_t len);

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
صحیح	sshbuf_consume_upto_بچہ(ساخت sshbuf *buf, ثابت ساخت sshbuf *بچہ);

/* Extract or deposit some bytes */
صحیح	sshbuf_get(ساخت sshbuf *buf, خالی *v, سائز_t len);
صحیح	sshbuf_put(ساخت sshbuf *buf, ثابت خالی *v, سائز_t len);
صحیح	sshbuf_putb(ساخت sshbuf *buf, ثابت ساخت sshbuf *v);

/* Append using a printf(3) format */
صحیح	sshbuf_putf(ساخت sshbuf *buf, ثابت حرف *fmt, ...)
	    __attribute__((format(لکھو, 2, 3)));
صحیح	sshbuf_putfv(ساخت sshbuf *buf, ثابت حرف *fmt, va_list ap);

/* Functions to extract or store big-endian words of various sizes */
صحیح	sshbuf_get_u64(ساخت sshbuf *buf, uint64_t *valp);
صحیح	sshbuf_get_u32(ساخت sshbuf *buf, uint32_t *valp);
صحیح	sshbuf_get_u16(ساخت sshbuf *buf, uint16_t *valp);
صحیح	sshbuf_get_u8(ساخت sshbuf *buf, u_char *valp);
صحیح	sshbuf_put_u64(ساخت sshbuf *buf, uint64_t val);
صحیح	sshbuf_put_u32(ساخت sshbuf *buf, uint32_t val);
صحیح	sshbuf_put_u16(ساخت sshbuf *buf, uint16_t val);
صحیح	sshbuf_put_u8(ساخت sshbuf *buf, u_char val);

/* Functions to peek at the contents of a buffer without modifying it. */
صحیح	sshbuf_peek_u64(ثابت ساخت sshbuf *buf, سائز_t انحراف,
    uint64_t *valp);
صحیح	sshbuf_peek_u32(ثابت ساخت sshbuf *buf, سائز_t انحراف,
    uint32_t *valp);
صحیح	sshbuf_peek_u16(ثابت ساخت sshbuf *buf, سائز_t انحراف,
    uint16_t *valp);
صحیح	sshbuf_peek_u8(ثابت ساخت sshbuf *buf, سائز_t انحراف,
    u_char *valp);

/*
 * Functions to poke values into an existing buffer (e.g. a length header
 * to a packet). The destination bytes must already exist in the buffer.
 */
صحیح sshbuf_poke_u64(ساخت sshbuf *buf, سائز_t انحراف, uint64_t val);
صحیح sshbuf_poke_u32(ساخت sshbuf *buf, سائز_t انحراف, uint32_t val);
صحیح sshbuf_poke_u16(ساخت sshbuf *buf, سائز_t انحراف, uint16_t val);
صحیح sshbuf_poke_u8(ساخت sshbuf *buf, سائز_t انحراف, u_char val);
صحیح sshbuf_poke(ساخت sshbuf *buf, سائز_t انحراف, خالی *v, سائز_t len);

/*
 * Functions to extract or store SSH wire encoded strings (u32 len || data)
 * The "cstring" variants admit no \0 characters in the string contents.
 * Caller must free *valp.
 */
صحیح	sshbuf_get_string(ساخت sshbuf *buf, u_char **valp, سائز_t *lenp);
صحیح	sshbuf_get_cstring(ساخت sshbuf *buf, حرف **valp, سائز_t *lenp);
صحیح	sshbuf_get_stringb(ساخت sshbuf *buf, ساخت sshbuf *v);
صحیح	sshbuf_put_string(ساخت sshbuf *buf, ثابت خالی *v, سائز_t len);
صحیح	sshbuf_put_cstring(ساخت sshbuf *buf, ثابت حرف *v);
صحیح	sshbuf_put_stringb(ساخت sshbuf *buf, ثابت ساخت sshbuf *v);

/*
 * "Direct" variant of sshbuf_get_string, returns pointer into the sshbuf to
 * avoid an malloc+memcpy. The pointer is guaranteed to be valid until the
 * next sshbuf-modifying function call. Caller does not free.
 */
صحیح	sshbuf_get_string_براہ_راست(ساخت sshbuf *buf, ثابت u_char **valp,
	    سائز_t *lenp);

/* Skip past a string */
#تعریف_کرو sshbuf_skip_string(buf) sshbuf_get_string_براہ_راست(buf, تہی, تہی)

/* Another variant: "peeks" into the buffer without modifying it */
صحیح	sshbuf_peek_string_براہ_راست(ثابت ساخت sshbuf *buf, ثابت u_char **valp,
	    سائز_t *lenp);

/*
 * Functions to extract or store SSH wire encoded bignums and elliptic
 * curve points.
 */
صحیح	sshbuf_get_bignum2(ساخت sshbuf *buf, BIGNUM **valp);
صحیح	sshbuf_get_bignum2_بائٹیں_براہ_راست(ساخت sshbuf *buf,
	    ثابت u_char **valp, سائز_t *lenp);
صحیح	sshbuf_put_bignum2(ساخت sshbuf *buf, ثابت BIGNUM *v);
صحیح	sshbuf_put_bignum2_بائٹیں(ساخت sshbuf *buf, ثابت خالی *v, سائز_t len);
صحیح	sshbuf_get_ec(ساخت sshbuf *buf, EC_نقطہ *v, ثابت EC_گروہ *g);
صحیح	sshbuf_get_eckey(ساخت sshbuf *buf, EC_کلید *v);
صحیح	sshbuf_put_ec(ساخت sshbuf *buf, ثابت EC_نقطہ *v, ثابت EC_گروہ *g);
صحیح	sshbuf_put_eckey(ساخت sshbuf *buf, ثابت EC_کلید *v);
صحیح	sshbuf_put_ec_pkey(ساخت sshbuf *buf, EVP_PKEY *pkey);

/* Functions to extract or store various non-SSH wire encoded values */
صحیح	sshbuf_get_nulterminated_string(ساخت sshbuf *buf, سائز_t maxlen,
	    حرف **valp, سائز_t *lenp);

/* Dump the contents of the buffer in a human-readable format */
خالی	sshbuf_dump(ثابت ساخت sshbuf *buf, FILE *f);

/* Dump specified memory in a human-readable format */
خالی	sshbuf_dump_ڈیٹا(ثابت خالی *s, سائز_t len, FILE *f);

/* Return the hexadecimal representation of the contents of the buffer */
حرف	*sshbuf_dtob16(ثابت ساخت sshbuf *buf);
/* Make a sshbuf from a hex string */
ساخت sshbuf *sshbuf_b16tod(ثابت حرف *b16);

/* Encode the contents of the buffer as base64 */
حرف	*sshbuf_dtob64_string(ثابت ساخت sshbuf *buf, صحیح wrap);
صحیح	sshbuf_dtob64(ثابت ساخت sshbuf *d, ساخت sshbuf *b64, صحیح wrap);
/* RFC4648 "base64url" encoding variant */
صحیح	sshbuf_dtourlb64(ثابت ساخت sshbuf *d, ساخت sshbuf *b64, صحیح wrap);

/* Decode base64 data and append it to the buffer */
صحیح	sshbuf_b64tod(ساخت sshbuf *buf, ثابت حرف *b64);

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
صحیح	sshbuf_cmp(ثابت ساخت sshbuf *b, سائز_t انحراف,
    ثابت خالی *s, سائز_t len);

/*
 * Test whether two buffers have identical contents.
 * SSH_ERR_MESSAGE_INCOMPLETE indicates the buffers had differing size.
 * SSH_ERR_INVALID_FORMAT indicates the buffers were the same size but
 * had differing contents.
 * Returns 0 on successful compare (comparing two empty buffers returns 0).
 */
صحیح sshbuf_equals(ثابت ساخت sshbuf *a, ثابت ساخت sshbuf *b);

/*
 * Searches the buffer for the specified string. Returns 0 on success
 * and updates *offsetp with the offset of the first match, relative to
 * the start of the buffer. Otherwise sshbuf_find will return a ssherr.h
 * error code. SSH_ERR_INVALID_FORMAT indicates sufficient bytes were
 * present in the buffer for a match to be possible but none was found.
 * Searches for zero-length data are not allowed.
 */
صحیح
sshbuf_ڈھونڈو(ثابت ساخت sshbuf *b, سائز_t آغاز_انحراف,
    ثابت خالی *s, سائز_t len, سائز_t *offsetp);

/*
 * Duplicate the contents of a buffer to a string (caller to free).
 * Returns NULL on buffer error, or if the buffer contains a premature
 * nul character.
 */
حرف *sshbuf_dup_string(ساخت sshbuf *buf);

/*
 * Fill a buffer from a file descriptor or filename. Both allocate the
 * buffer for the caller.
 */
صحیح sshbuf_بھرو_fd(صحیح, ساخت sshbuf **)
    __attribute__((__nonnull__ (2)));
صحیح sshbuf_بھرو_file(ثابت حرف *, ساخت sshbuf **)
    __attribute__((__nonnull__ (2)));

/*
 * Write a buffer to a path, creating/truncating as needed (mode 0644,
 * subject to umask). The buffer contents are not modified.
 */
صحیح sshbuf_write_file(ثابت حرف *راستہ, ساخت sshbuf *buf)
    __attribute__((__nonnull__ (2)));

/* Read up to maxlen bytes from a fd directly to a buffer */
صحیح sshbuf_read(صحیح, ساخت sshbuf *, سائز_t, سائز_t *)
    __attribute__((__nonnull__ (2)));

/* Macros for decoding/encoding integers */
#تعریف_کرو PEEK_U64(p) \
	(((uint64_t)(((ثابت u_char *)(p))[0]) << 56) | \
	 ((uint64_t)(((ثابت u_char *)(p))[1]) << 48) | \
	 ((uint64_t)(((ثابت u_char *)(p))[2]) << 40) | \
	 ((uint64_t)(((ثابت u_char *)(p))[3]) << 32) | \
	 ((uint64_t)(((ثابت u_char *)(p))[4]) << 24) | \
	 ((uint64_t)(((ثابت u_char *)(p))[5]) << 16) | \
	 ((uint64_t)(((ثابت u_char *)(p))[6]) << 8) | \
	  (uint64_t)(((ثابت u_char *)(p))[7]))
#تعریف_کرو PEEK_U32(p) \
	(((uint32_t)(((ثابت u_char *)(p))[0]) << 24) | \
	 ((uint32_t)(((ثابت u_char *)(p))[1]) << 16) | \
	 ((uint32_t)(((ثابت u_char *)(p))[2]) << 8) | \
	  (uint32_t)(((ثابت u_char *)(p))[3]))
#تعریف_کرو PEEK_U16(p) \
	(((uint16_t)(((ثابت u_char *)(p))[0]) << 8) | \
	  (uint16_t)(((ثابت u_char *)(p))[1]))

#تعریف_کرو POKE_U64(p, v) \
	کرو { \
		ثابت uint64_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 56) & 0xff; \
		((u_char *)(p))[1] = (__v >> 48) & 0xff; \
		((u_char *)(p))[2] = (__v >> 40) & 0xff; \
		((u_char *)(p))[3] = (__v >> 32) & 0xff; \
		((u_char *)(p))[4] = (__v >> 24) & 0xff; \
		((u_char *)(p))[5] = (__v >> 16) & 0xff; \
		((u_char *)(p))[6] = (__v >> 8) & 0xff; \
		((u_char *)(p))[7] = __v & 0xff; \
	} جب (0)
#تعریف_کرو POKE_U32(p, v) \
	کرو { \
		ثابت uint32_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 24) & 0xff; \
		((u_char *)(p))[1] = (__v >> 16) & 0xff; \
		((u_char *)(p))[2] = (__v >> 8) & 0xff; \
		((u_char *)(p))[3] = __v & 0xff; \
	} جب (0)
#تعریف_کرو POKE_U16(p, v) \
	کرو { \
		ثابت uint16_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 8) & 0xff; \
		((u_char *)(p))[1] = __v & 0xff; \
	} جب (0)

/* Internal definitions follow. Exposed for regress tests */
#اگر_تعریف_شدہ SSHBUF_اندرونی

/*
 * Return the allocation size of buf
 */
سائز_t	sshbuf_alloc(ثابت ساخت sshbuf *buf);

/*
 * Increment the reference count of buf.
 */
صحیح	sshbuf_سیٹ_والد(ساخت sshbuf *بچہ, ساخت sshbuf *والد);

/*
 * Return the parent buffer of buf, or NULL if it has no parent.
 */
ثابت ساخت sshbuf *sshbuf_والد(ثابت ساخت sshbuf *buf);

/*
 * Return the reference count of buf
 */
u_int	sshbuf_refcount(ثابت ساخت sshbuf *buf);

# define SSHBUF_سائز_INIT	256		/* Initial allocation */
# define SSHBUF_سائز_INC	256		/* Preferred increment length */
# define SSHBUF_PACK_MIN	8192		/* Minimum packable offset */

/* # define SSHBUF_ABORT abort */
/* # define SSHBUF_DEBUG */

# ifndef SSHBUF_ABORT
#  define SSHBUF_ABORT()
# endif

# ifdef SSHBUF_DEBUG
#  define SSHBUF_DBG(x) کرو { \
		لکھو("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		لکھو x; \
		لکھو("\n"); \
		fflush(stdout); \
	} جب (0)
# ورنہ
#  define SSHBUF_DBG(x)
# endif
#اگر_ختم /* SSHBUF_INTERNAL */

#اگر_ختم /* _SSHBUF_H */
