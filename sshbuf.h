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

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdint.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/ec.h>
#അന്തര്ഭാവ <openssl/ecdsa.h>
#അന്തര്ഭാവ <openssl/evp.h>
#അല്ലെങ്കിൽ /* OPENSSL */
#define BIGNUM		ശൂന്യം
#define EC_താക്കോൽ		ശൂന്യം
#define EC_GROUP	ശൂന്യം
#define EC_POINT	ശൂന്യം
#define EVP_PKEY	ശൂന്യം
#endif /* WITH_OPENSSL */

#define SSHBUF_SIZE_MAX		0x8000000	/* Hard maximum size */
#define SSHBUF_REFS_MAX		0x100000	/* Max child buffers */
#define SSHBUF_MAX_BIGNUM	(16384 / 8)	/* Max bignum *bytes* */
#define SSHBUF_MAX_ECPOINT	((528 * 2 / 8) + 1) /* Max EC point *bytes* */

ഘടന sshbuf;

/*
 * Create a new sshbuf buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
ഘടന sshbuf *sshbuf_new(ശൂന്യം);

/*
 * Create a new, read-only sshbuf buffer from existing data.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
ഘടന sshbuf *sshbuf_from(സ്ഥിരം ശൂന്യം *blob, size_t len);

/*
 * Create a new, read-only sshbuf buffer from the contents of an existing
 * buffer. The contents of "buf" must not change in the lifetime of the
 * resultant buffer.
 * Returns pointer to buffer on success, or NULL on allocation failure.
 */
ഘടന sshbuf *sshbuf_fromb(ഘടന sshbuf *buf);

/*
 * Create a new, read-only sshbuf buffer from the contents of a string in
 * an existing buffer (the string is consumed in the process).
 * The contents of "buf" must not change in the lifetime of the resultant
 * buffer.
 * On success, a pointer to the newly allocated buffer is placed in *bufp.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
പൂർണ്ണസംഖ്യ	sshbuf_froms(ഘടന sshbuf *buf, ഘടന sshbuf **bufp);

/*
 * Clear and free buf
 */
ശൂന്യം	sshbuf_free(ഘടന sshbuf *buf);

/*
 * Reset buf, clearing its contents. NB. max_size is preserved.
 */
ശൂന്യം	sshbuf_reset(ഘടന sshbuf *buf);

/*
 * Return the maximum size of buf
 */
size_t	sshbuf_max_size(സ്ഥിരം ഘടന sshbuf *buf);

/*
 * Set the maximum size of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
പൂർണ്ണസംഖ്യ	sshbuf_set_max_size(ഘടന sshbuf *buf, size_t max_size);

/*
 * Returns the length of data in buf
 */
size_t	sshbuf_len(സ്ഥിരം ഘടന sshbuf *buf);

/*
 * Returns number of bytes left in buffer before hitting max_size.
 */
size_t	sshbuf_avail(സ്ഥിരം ഘടന sshbuf *buf);

/*
 * Returns a read-only pointer to the start of the data in buf
 */
സ്ഥിരം u_char *sshbuf_ptr(സ്ഥിരം ഘടന sshbuf *buf);

/*
 * Returns a mutable pointer to the start of the data in buf, or
 * NULL if the buffer is read-only.
 */
u_char *sshbuf_mutable_ptr(സ്ഥിരം ഘടന sshbuf *buf);

/*
 * Check whether a reservation of size len will succeed in buf
 * Safer to use than direct comparisons again sshbuf_avail as it copes
 * with unsigned overflows correctly.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
പൂർണ്ണസംഖ്യ	sshbuf_check_reserve(സ്ഥിരം ഘടന sshbuf *buf, size_t len);

/*
 * Preallocates len additional bytes in buf.
 * Useful for cases where the caller knows how many bytes will ultimately be
 * required to avoid realloc in the buffer code.
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
പൂർണ്ണസംഖ്യ	sshbuf_allocate(ഘടന sshbuf *buf, size_t len);

/*
 * Reserve len bytes in buf.
 * Returns 0 on success and a pointer to the first reserved byte via the
 * optional dpp parameter or a negative SSH_ERR_* error code on failure.
 */
പൂർണ്ണസംഖ്യ	sshbuf_reserve(ഘടന sshbuf *buf, size_t len, u_char **dpp);

/*
 * Consume len bytes from the start of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
പൂർണ്ണസംഖ്യ	sshbuf_consume(ഘടന sshbuf *buf, size_t len);

/*
 * Consume len bytes from the end of buf
 * Returns 0 on success, or a negative SSH_ERR_* error code on failure.
 */
പൂർണ്ണസംഖ്യ	sshbuf_consume_end(ഘടന sshbuf *buf, size_t len);

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
പൂർണ്ണസംഖ്യ	sshbuf_consume_upto_child(ഘടന sshbuf *buf, സ്ഥിരം ഘടന sshbuf *child);

/* Extract or deposit some bytes */
പൂർണ്ണസംഖ്യ	sshbuf_get(ഘടന sshbuf *buf, ശൂന്യം *v, size_t len);
പൂർണ്ണസംഖ്യ	sshbuf_put(ഘടന sshbuf *buf, സ്ഥിരം ശൂന്യം *v, size_t len);
പൂർണ്ണസംഖ്യ	sshbuf_putb(ഘടന sshbuf *buf, സ്ഥിരം ഘടന sshbuf *v);

/* Append using a printf(3) format */
പൂർണ്ണസംഖ്യ	sshbuf_putf(ഘടന sshbuf *buf, സ്ഥിരം അക്ഷരം *fmt, ...)
	    __attribute__((format(printf, 2, 3)));
പൂർണ്ണസംഖ്യ	sshbuf_putfv(ഘടന sshbuf *buf, സ്ഥിരം അക്ഷരം *fmt, va_list ap);

/* Functions to extract or store big-endian words of various sizes */
പൂർണ്ണസംഖ്യ	sshbuf_get_u64(ഘടന sshbuf *buf, uint64_t *valp);
പൂർണ്ണസംഖ്യ	sshbuf_get_u32(ഘടന sshbuf *buf, uint32_t *valp);
പൂർണ്ണസംഖ്യ	sshbuf_get_u16(ഘടന sshbuf *buf, uint16_t *valp);
പൂർണ്ണസംഖ്യ	sshbuf_get_u8(ഘടന sshbuf *buf, u_char *valp);
പൂർണ്ണസംഖ്യ	sshbuf_put_u64(ഘടന sshbuf *buf, uint64_t val);
പൂർണ്ണസംഖ്യ	sshbuf_put_u32(ഘടന sshbuf *buf, uint32_t val);
പൂർണ്ണസംഖ്യ	sshbuf_put_u16(ഘടന sshbuf *buf, uint16_t val);
പൂർണ്ണസംഖ്യ	sshbuf_put_u8(ഘടന sshbuf *buf, u_char val);

/* Functions to peek at the contents of a buffer without modifying it. */
പൂർണ്ണസംഖ്യ	sshbuf_peek_u64(സ്ഥിരം ഘടന sshbuf *buf, size_t offset,
    uint64_t *valp);
പൂർണ്ണസംഖ്യ	sshbuf_peek_u32(സ്ഥിരം ഘടന sshbuf *buf, size_t offset,
    uint32_t *valp);
പൂർണ്ണസംഖ്യ	sshbuf_peek_u16(സ്ഥിരം ഘടന sshbuf *buf, size_t offset,
    uint16_t *valp);
പൂർണ്ണസംഖ്യ	sshbuf_peek_u8(സ്ഥിരം ഘടന sshbuf *buf, size_t offset,
    u_char *valp);

/*
 * Functions to poke values into an existing buffer (e.g. a length header
 * to a packet). The destination bytes must already exist in the buffer.
 */
പൂർണ്ണസംഖ്യ sshbuf_poke_u64(ഘടന sshbuf *buf, size_t offset, uint64_t val);
പൂർണ്ണസംഖ്യ sshbuf_poke_u32(ഘടന sshbuf *buf, size_t offset, uint32_t val);
പൂർണ്ണസംഖ്യ sshbuf_poke_u16(ഘടന sshbuf *buf, size_t offset, uint16_t val);
പൂർണ്ണസംഖ്യ sshbuf_poke_u8(ഘടന sshbuf *buf, size_t offset, u_char val);
പൂർണ്ണസംഖ്യ sshbuf_poke(ഘടന sshbuf *buf, size_t offset, ശൂന്യം *v, size_t len);

/*
 * Functions to extract or store SSH wire encoded strings (u32 len || data)
 * The "cstring" variants admit no \0 characters in the string contents.
 * Caller must free *valp.
 */
പൂർണ്ണസംഖ്യ	sshbuf_get_string(ഘടന sshbuf *buf, u_char **valp, size_t *lenp);
പൂർണ്ണസംഖ്യ	sshbuf_get_cstring(ഘടന sshbuf *buf, അക്ഷരം **valp, size_t *lenp);
പൂർണ്ണസംഖ്യ	sshbuf_get_stringb(ഘടന sshbuf *buf, ഘടന sshbuf *v);
പൂർണ്ണസംഖ്യ	sshbuf_put_string(ഘടന sshbuf *buf, സ്ഥിരം ശൂന്യം *v, size_t len);
പൂർണ്ണസംഖ്യ	sshbuf_put_cstring(ഘടന sshbuf *buf, സ്ഥിരം അക്ഷരം *v);
പൂർണ്ണസംഖ്യ	sshbuf_put_stringb(ഘടന sshbuf *buf, സ്ഥിരം ഘടന sshbuf *v);

/*
 * "Direct" variant of sshbuf_get_string, returns pointer into the sshbuf to
 * avoid an malloc+memcpy. The pointer is guaranteed to be valid until the
 * next sshbuf-modifying function call. Caller does not free.
 */
പൂർണ്ണസംഖ്യ	sshbuf_get_string_direct(ഘടന sshbuf *buf, സ്ഥിരം u_char **valp,
	    size_t *lenp);

/* Skip past a string */
#define sshbuf_skip_string(buf) sshbuf_get_string_direct(buf, ശൂന്യ, ശൂന്യ)

/* Another variant: "peeks" into the buffer without modifying it */
പൂർണ്ണസംഖ്യ	sshbuf_peek_string_direct(സ്ഥിരം ഘടന sshbuf *buf, സ്ഥിരം u_char **valp,
	    size_t *lenp);

/*
 * Functions to extract or store SSH wire encoded bignums and elliptic
 * curve points.
 */
പൂർണ്ണസംഖ്യ	sshbuf_get_bignum2(ഘടന sshbuf *buf, BIGNUM **valp);
പൂർണ്ണസംഖ്യ	sshbuf_get_bignum2_bytes_direct(ഘടന sshbuf *buf,
	    സ്ഥിരം u_char **valp, size_t *lenp);
പൂർണ്ണസംഖ്യ	sshbuf_put_bignum2(ഘടന sshbuf *buf, സ്ഥിരം BIGNUM *v);
പൂർണ്ണസംഖ്യ	sshbuf_put_bignum2_bytes(ഘടന sshbuf *buf, സ്ഥിരം ശൂന്യം *v, size_t len);
പൂർണ്ണസംഖ്യ	sshbuf_get_ec(ഘടന sshbuf *buf, EC_POINT *v, സ്ഥിരം EC_GROUP *g);
പൂർണ്ണസംഖ്യ	sshbuf_get_eckey(ഘടന sshbuf *buf, EC_താക്കോൽ *v);
പൂർണ്ണസംഖ്യ	sshbuf_put_ec(ഘടന sshbuf *buf, സ്ഥിരം EC_POINT *v, സ്ഥിരം EC_GROUP *g);
പൂർണ്ണസംഖ്യ	sshbuf_put_eckey(ഘടന sshbuf *buf, സ്ഥിരം EC_താക്കോൽ *v);
പൂർണ്ണസംഖ്യ	sshbuf_put_ec_pkey(ഘടന sshbuf *buf, EVP_PKEY *pkey);

/* Functions to extract or store various non-SSH wire encoded values */
പൂർണ്ണസംഖ്യ	sshbuf_get_nulterminated_string(ഘടന sshbuf *buf, size_t maxlen,
	    അക്ഷരം **valp, size_t *lenp);

/* Dump the contents of the buffer in a human-readable format */
ശൂന്യം	sshbuf_dump(സ്ഥിരം ഘടന sshbuf *buf, FILE *f);

/* Dump specified memory in a human-readable format */
ശൂന്യം	sshbuf_dump_data(സ്ഥിരം ശൂന്യം *s, size_t len, FILE *f);

/* Return the hexadecimal representation of the contents of the buffer */
അക്ഷരം	*sshbuf_dtob16(സ്ഥിരം ഘടന sshbuf *buf);
/* Make a sshbuf from a hex string */
ഘടന sshbuf *sshbuf_b16tod(സ്ഥിരം അക്ഷരം *b16);

/* Encode the contents of the buffer as base64 */
അക്ഷരം	*sshbuf_dtob64_string(സ്ഥിരം ഘടന sshbuf *buf, പൂർണ്ണസംഖ്യ wrap);
പൂർണ്ണസംഖ്യ	sshbuf_dtob64(സ്ഥിരം ഘടന sshbuf *d, ഘടന sshbuf *b64, പൂർണ്ണസംഖ്യ wrap);
/* RFC4648 "base64url" encoding variant */
പൂർണ്ണസംഖ്യ	sshbuf_dtourlb64(സ്ഥിരം ഘടന sshbuf *d, ഘടന sshbuf *b64, പൂർണ്ണസംഖ്യ wrap);

/* Decode base64 data and append it to the buffer */
പൂർണ്ണസംഖ്യ	sshbuf_b64tod(ഘടന sshbuf *buf, സ്ഥിരം അക്ഷരം *b64);

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
പൂർണ്ണസംഖ്യ	sshbuf_cmp(സ്ഥിരം ഘടന sshbuf *b, size_t offset,
    സ്ഥിരം ശൂന്യം *s, size_t len);

/*
 * Test whether two buffers have identical contents.
 * SSH_ERR_MESSAGE_INCOMPLETE indicates the buffers had differing size.
 * SSH_ERR_INVALID_FORMAT indicates the buffers were the same size but
 * had differing contents.
 * Returns 0 on successful compare (comparing two empty buffers returns 0).
 */
പൂർണ്ണസംഖ്യ sshbuf_equals(സ്ഥിരം ഘടന sshbuf *a, സ്ഥിരം ഘടന sshbuf *b);

/*
 * Searches the buffer for the specified string. Returns 0 on success
 * and updates *offsetp with the offset of the first match, relative to
 * the start of the buffer. Otherwise sshbuf_find will return a ssherr.h
 * error code. SSH_ERR_INVALID_FORMAT indicates sufficient bytes were
 * present in the buffer for a match to be possible but none was found.
 * Searches for zero-length data are not allowed.
 */
പൂർണ്ണസംഖ്യ
sshbuf_find(സ്ഥിരം ഘടന sshbuf *b, size_t start_offset,
    സ്ഥിരം ശൂന്യം *s, size_t len, size_t *offsetp);

/*
 * Duplicate the contents of a buffer to a string (caller to free).
 * Returns NULL on buffer error, or if the buffer contains a premature
 * nul character.
 */
അക്ഷരം *sshbuf_dup_string(ഘടന sshbuf *buf);

/*
 * Fill a buffer from a file descriptor or filename. Both allocate the
 * buffer for the caller.
 */
പൂർണ്ണസംഖ്യ sshbuf_load_fd(പൂർണ്ണസംഖ്യ, ഘടന sshbuf **)
    __attribute__((__nonnull__ (2)));
പൂർണ്ണസംഖ്യ sshbuf_load_file(സ്ഥിരം അക്ഷരം *, ഘടന sshbuf **)
    __attribute__((__nonnull__ (2)));

/*
 * Write a buffer to a path, creating/truncating as needed (mode 0644,
 * subject to umask). The buffer contents are not modified.
 */
പൂർണ്ണസംഖ്യ sshbuf_write_file(സ്ഥിരം അക്ഷരം *path, ഘടന sshbuf *buf)
    __attribute__((__nonnull__ (2)));

/* Read up to maxlen bytes from a fd directly to a buffer */
പൂർണ്ണസംഖ്യ sshbuf_read(പൂർണ്ണസംഖ്യ, ഘടന sshbuf *, size_t, size_t *)
    __attribute__((__nonnull__ (2)));

/* Macros for decoding/encoding integers */
#define PEEK_U64(p) \
	(((uint64_t)(((സ്ഥിരം u_char *)(p))[0]) << 56) | \
	 ((uint64_t)(((സ്ഥിരം u_char *)(p))[1]) << 48) | \
	 ((uint64_t)(((സ്ഥിരം u_char *)(p))[2]) << 40) | \
	 ((uint64_t)(((സ്ഥിരം u_char *)(p))[3]) << 32) | \
	 ((uint64_t)(((സ്ഥിരം u_char *)(p))[4]) << 24) | \
	 ((uint64_t)(((സ്ഥിരം u_char *)(p))[5]) << 16) | \
	 ((uint64_t)(((സ്ഥിരം u_char *)(p))[6]) << 8) | \
	  (uint64_t)(((സ്ഥിരം u_char *)(p))[7]))
#define PEEK_U32(p) \
	(((uint32_t)(((സ്ഥിരം u_char *)(p))[0]) << 24) | \
	 ((uint32_t)(((സ്ഥിരം u_char *)(p))[1]) << 16) | \
	 ((uint32_t)(((സ്ഥിരം u_char *)(p))[2]) << 8) | \
	  (uint32_t)(((സ്ഥിരം u_char *)(p))[3]))
#define PEEK_U16(p) \
	(((uint16_t)(((സ്ഥിരം u_char *)(p))[0]) << 8) | \
	  (uint16_t)(((സ്ഥിരം u_char *)(p))[1]))

#define POKE_U64(p, v) \
	ചെയ്യുക { \
		സ്ഥിരം uint64_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 56) & 0xff; \
		((u_char *)(p))[1] = (__v >> 48) & 0xff; \
		((u_char *)(p))[2] = (__v >> 40) & 0xff; \
		((u_char *)(p))[3] = (__v >> 32) & 0xff; \
		((u_char *)(p))[4] = (__v >> 24) & 0xff; \
		((u_char *)(p))[5] = (__v >> 16) & 0xff; \
		((u_char *)(p))[6] = (__v >> 8) & 0xff; \
		((u_char *)(p))[7] = __v & 0xff; \
	} ആകുമ്പോൾ (0)
#define POKE_U32(p, v) \
	ചെയ്യുക { \
		സ്ഥിരം uint32_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 24) & 0xff; \
		((u_char *)(p))[1] = (__v >> 16) & 0xff; \
		((u_char *)(p))[2] = (__v >> 8) & 0xff; \
		((u_char *)(p))[3] = __v & 0xff; \
	} ആകുമ്പോൾ (0)
#define POKE_U16(p, v) \
	ചെയ്യുക { \
		സ്ഥിരം uint16_t __v = (v); \
		((u_char *)(p))[0] = (__v >> 8) & 0xff; \
		((u_char *)(p))[1] = __v & 0xff; \
	} ആകുമ്പോൾ (0)

/* Internal definitions follow. Exposed for regress tests */
#ifdef SSHBUF_INTERNAL

/*
 * Return the allocation size of buf
 */
size_t	sshbuf_alloc(സ്ഥിരം ഘടന sshbuf *buf);

/*
 * Increment the reference count of buf.
 */
പൂർണ്ണസംഖ്യ	sshbuf_set_parent(ഘടന sshbuf *child, ഘടന sshbuf *parent);

/*
 * Return the parent buffer of buf, or NULL if it has no parent.
 */
സ്ഥിരം ഘടന sshbuf *sshbuf_parent(സ്ഥിരം ഘടന sshbuf *buf);

/*
 * Return the reference count of buf
 */
u_int	sshbuf_refcount(സ്ഥിരം ഘടന sshbuf *buf);

# define SSHBUF_SIZE_INIT	256		/* Initial allocation */
# define SSHBUF_SIZE_INC	256		/* Preferred increment length */
# define SSHBUF_PACK_MIN	8192		/* Minimum packable offset */

/* # define SSHBUF_ABORT abort */
/* # define SSHBUF_DEBUG */

# ifndef SSHBUF_ABORT
#  define SSHBUF_ABORT()
# endif

# ifdef SSHBUF_DEBUG
#  define SSHBUF_DBG(x) ചെയ്യുക { \
		printf("%s:%d %s: ", __FILE__, __LINE__, __func__); \
		printf x; \
		printf("\n"); \
		fflush(stdout); \
	} ആകുമ്പോൾ (0)
# അല്ലെങ്കിൽ
#  define SSHBUF_DBG(x)
# endif
#endif /* SSHBUF_INTERNAL */

#endif /* _SSHBUF_H */
