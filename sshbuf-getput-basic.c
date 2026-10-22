/*	$OpenBSD: sshbuf-getput-basic.c,v 1.15 2026/03/03 09:57:25 dtucker Exp $	*/
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

#include "includes.h"

#include <sys/types.h>

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "ssherr.h"
#define SSHBUF_INTERNAL
#include "sshbuf.h"

ціле
sshbuf_get(struct sshbuf *buf, void *v, size_t len)
{
	const u_char *p = sshbuf_ptr(buf);
	ціле r;

	якщо ((r = sshbuf_consume(buf, len)) < 0)
		повернути r;
	якщо (v != NULL && len != 0)
		memcpy(v, p, len);
	повернути 0;
}

ціле
sshbuf_get_u64(struct sshbuf *buf, uint64_t *valp)
{
	const u_char *p = sshbuf_ptr(buf);
	ціле r;

	якщо ((r = sshbuf_consume(buf, 8)) < 0)
		повернути r;
	якщо (valp != NULL)
		*valp = PEEK_U64(p);
	повернути 0;
}

ціле
sshbuf_get_u32(struct sshbuf *buf, uint32_t *valp)
{
	const u_char *p = sshbuf_ptr(buf);
	ціле r;

	якщо ((r = sshbuf_consume(buf, 4)) < 0)
		повернути r;
	якщо (valp != NULL)
		*valp = PEEK_U32(p);
	повернути 0;
}

ціле
sshbuf_get_u16(struct sshbuf *buf, uint16_t *valp)
{
	const u_char *p = sshbuf_ptr(buf);
	ціле r;

	якщо ((r = sshbuf_consume(buf, 2)) < 0)
		повернути r;
	якщо (valp != NULL)
		*valp = PEEK_U16(p);
	повернути 0;
}

ціле
sshbuf_get_u8(struct sshbuf *buf, u_char *valp)
{
	const u_char *p = sshbuf_ptr(buf);
	ціле r;

	якщо ((r = sshbuf_consume(buf, 1)) < 0)
		повернути r;
	якщо (valp != NULL)
		*valp = (uint8_t)*p;
	повернути 0;
}

static ціле
check_offset(const struct sshbuf *buf, ціле wr, size_t offset, size_t len)
{
	якщо (sshbuf_ptr(buf) == NULL) /* calls sshbuf_check_sanity() */
		повернути SSH_ERR_INTERNAL_ERROR;
	якщо (offset >= SIZE_MAX - len)
		повернути SSH_ERR_INVALID_ARGUMENT;
	якщо (offset + len > sshbuf_len(buf)) {
		повернути wr ?
		    SSH_ERR_NO_BUFFER_SPACE : SSH_ERR_MESSAGE_INCOMPLETE;
	}
	повернути 0;
}

static ціле
check_roffset(const struct sshbuf *buf, size_t offset, size_t len,
    const u_char **p)
{
	ціле r;

	*p = NULL;
	якщо ((r = check_offset(buf, 0, offset, len)) != 0)
		повернути r;
	*p = sshbuf_ptr(buf) + offset;
	повернути 0;
}

ціле
sshbuf_peek_u64(const struct sshbuf *buf, size_t offset, uint64_t *valp)
{
	const u_char *p = NULL;
	ціле r;

	якщо (valp != NULL)
		*valp = 0;
	якщо ((r = check_roffset(buf, offset, 8, &p)) != 0)
		повернути r;
	якщо (valp != NULL)
		*valp = PEEK_U64(p);
	повернути 0;
}

ціле
sshbuf_peek_u32(const struct sshbuf *buf, size_t offset, uint32_t *valp)
{
	const u_char *p = NULL;
	ціле r;

	якщо (valp != NULL)
		*valp = 0;
	якщо ((r = check_roffset(buf, offset, 4, &p)) != 0)
		повернути r;
	якщо (valp != NULL)
		*valp = PEEK_U32(p);
	повернути 0;
}

ціле
sshbuf_peek_u16(const struct sshbuf *buf, size_t offset, uint16_t *valp)
{
	const u_char *p = NULL;
	ціле r;

	якщо (valp != NULL)
		*valp = 0;
	якщо ((r = check_roffset(buf, offset, 2, &p)) != 0)
		повернути r;
	якщо (valp != NULL)
		*valp = PEEK_U16(p);
	повернути 0;
}

ціле
sshbuf_peek_u8(const struct sshbuf *buf, size_t offset, u_char *valp)
{
	const u_char *p = NULL;
	ціле r;

	якщо (valp != NULL)
		*valp = 0;
	якщо ((r = check_roffset(buf, offset, 1, &p)) != 0)
		повернути r;
	якщо (valp != NULL)
		*valp = *p;
	повернути 0;
}

ціле
sshbuf_get_string(struct sshbuf *buf, u_char **valp, size_t *lenp)
{
	const u_char *val;
	size_t len;
	ціле r;

	якщо (valp != NULL)
		*valp = NULL;
	якщо (lenp != NULL)
		*lenp = 0;
	якщо ((r = sshbuf_get_string_direct(buf, &val, &len)) < 0)
		повернути r;
	якщо (valp != NULL) {
		якщо ((*valp = malloc(len + 1)) == NULL) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			повернути SSH_ERR_ALLOC_FAIL;
		}
		якщо (len != 0)
			memcpy(*valp, val, len);
		(*valp)[len] = '\0';
	}
	якщо (lenp != NULL)
		*lenp = len;
	повернути 0;
}

ціле
sshbuf_get_string_direct(struct sshbuf *buf, const u_char **valp, size_t *lenp)
{
	size_t len;
	const u_char *p;
	ціле r;

	якщо (valp != NULL)
		*valp = NULL;
	якщо (lenp != NULL)
		*lenp = 0;
	якщо ((r = sshbuf_peek_string_direct(buf, &p, &len)) < 0)
		повернути r;
	якщо (valp != NULL)
		*valp = p;
	якщо (lenp != NULL)
		*lenp = len;
	якщо (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		повернути SSH_ERR_INTERNAL_ERROR;
	}
	повернути 0;
}

ціле
sshbuf_peek_string_direct(const struct sshbuf *buf, const u_char **valp,
    size_t *lenp)
{
	uint32_t len;
	const u_char *p = sshbuf_ptr(buf);

	якщо (valp != NULL)
		*valp = NULL;
	якщо (lenp != NULL)
		*lenp = 0;
	якщо (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		повернути SSH_ERR_MESSAGE_INCOMPLETE;
	}
	len = PEEK_U32(p);
	якщо (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		повернути SSH_ERR_STRING_TOO_LARGE;
	}
	якщо (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		повернути SSH_ERR_MESSAGE_INCOMPLETE;
	}
	якщо (valp != NULL)
		*valp = p + 4;
	якщо (lenp != NULL)
		*lenp = len;
	повернути 0;
}

ціле
sshbuf_get_cstring(struct sshbuf *buf, char **valp, size_t *lenp)
{
	size_t len;
	const u_char *p, *z;
	ціле r;

	якщо (valp != NULL)
		*valp = NULL;
	якщо (lenp != NULL)
		*lenp = 0;
	якщо ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		повернути r;
	/* Allow a \0 only at the end of the string */
	якщо (len > 0 &&
	    (z = memchr(p , '\0', len)) != NULL && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		повернути SSH_ERR_INVALID_FORMAT;
	}
	якщо ((r = sshbuf_skip_string(buf)) != 0)
		повернути -1;
	якщо (valp != NULL) {
		якщо ((*valp = malloc(len + 1)) == NULL) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			повернути SSH_ERR_ALLOC_FAIL;
		}
		якщо (len != 0)
			memcpy(*valp, p, len);
		(*valp)[len] = '\0';
	}
	якщо (lenp != NULL)
		*lenp = (size_t)len;
	повернути 0;
}

ціле
sshbuf_get_stringb(struct sshbuf *buf, struct sshbuf *v)
{
	uint32_t len;
	u_char *p;
	ціле r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	якщо ((r = sshbuf_peek_string_direct(buf, NULL, NULL)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		повернути r;
	повернути 0;
}

ціле
sshbuf_put(struct sshbuf *buf, const void *v, size_t len)
{
	u_char *p;
	ціле r;

	якщо ((r = sshbuf_reserve(buf, len, &p)) < 0)
		повернути r;
	якщо (len != 0)
		memcpy(p, v, len);
	повернути 0;
}

ціле
sshbuf_putb(struct sshbuf *buf, const struct sshbuf *v)
{
	якщо (v == NULL)
		повернути 0;
	повернути sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

ціле
sshbuf_putf(struct sshbuf *buf, const char *fmt, ...)
{
	va_list ap;
	ціле r;

	va_start(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	va_end(ap);
	повернути r;
}

ціле
sshbuf_putfv(struct sshbuf *buf, const char *fmt, va_list ap)
{
	va_list ap2;
	ціле r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	якщо ((len = vsnprintf(NULL, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	якщо (len == 0) {
		r = 0;
		goto out; /* Nothing to do */
	}
	va_end(ap2);
	VA_COPY(ap2, ap);
	якщо ((r = sshbuf_reserve(buf, (size_t)len + 1, &p)) < 0)
		goto out;
	якщо ((r = vsnprintf((char *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	якщо ((r = sshbuf_consume_end(buf, 1)) != 0)
		goto out;
	r = 0;
 out:
	va_end(ap2);
	повернути r;
}

ціле
sshbuf_put_u64(struct sshbuf *buf, uint64_t val)
{
	u_char *p;
	ціле r;

	якщо ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		повернути r;
	POKE_U64(p, val);
	повернути 0;
}

ціле
sshbuf_put_u32(struct sshbuf *buf, uint32_t val)
{
	u_char *p;
	ціле r;

	якщо ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		повернути r;
	POKE_U32(p, val);
	повернути 0;
}

ціле
sshbuf_put_u16(struct sshbuf *buf, uint16_t val)
{
	u_char *p;
	ціле r;

	якщо ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		повернути r;
	POKE_U16(p, val);
	повернути 0;
}

ціле
sshbuf_put_u8(struct sshbuf *buf, u_char val)
{
	u_char *p;
	ціле r;

	якщо ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		повернути r;
	p[0] = val;
	повернути 0;
}

static ціле
check_woffset(struct sshbuf *buf, size_t offset, size_t len, u_char **p)
{
	ціле r;

	*p = NULL;
	якщо ((r = check_offset(buf, 1, offset, len)) != 0)
		повернути r;
	якщо (sshbuf_mutable_ptr(buf) == NULL)
		повернути SSH_ERR_BUFFER_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + offset;
	повернути 0;
}

ціле
sshbuf_poke_u64(struct sshbuf *buf, size_t offset, uint64_t val)
{
	u_char *p = NULL;
	ціле r;

	якщо ((r = check_woffset(buf, offset, 8, &p)) != 0)
		повернути r;
	POKE_U64(p, val);
	повернути 0;
}

ціле
sshbuf_poke_u32(struct sshbuf *buf, size_t offset, uint32_t val)
{
	u_char *p = NULL;
	ціле r;

	якщо ((r = check_woffset(buf, offset, 4, &p)) != 0)
		повернути r;
	POKE_U32(p, val);
	повернути 0;
}

ціле
sshbuf_poke_u16(struct sshbuf *buf, size_t offset, uint16_t val)
{
	u_char *p = NULL;
	ціле r;

	якщо ((r = check_woffset(buf, offset, 2, &p)) != 0)
		повернути r;
	POKE_U16(p, val);
	повернути 0;
}

ціле
sshbuf_poke_u8(struct sshbuf *buf, size_t offset, u_char val)
{
	u_char *p = NULL;
	ціле r;

	якщо ((r = check_woffset(buf, offset, 1, &p)) != 0)
		повернути r;
	*p = val;
	повернути 0;
}

ціле
sshbuf_poke(struct sshbuf *buf, size_t offset, void *v, size_t len)
{
	u_char *p = NULL;
	ціле r;

	якщо ((r = check_woffset(buf, offset, len, &p)) != 0)
		повернути r;
	memcpy(p, v, len);
	повернути 0;
}

ціле
sshbuf_put_string(struct sshbuf *buf, const void *v, size_t len)
{
	u_char *d;
	ціле r;

	якщо (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		повернути SSH_ERR_NO_BUFFER_SPACE;
	}
	якщо ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		повернути r;
	POKE_U32(d, len);
	якщо (len != 0)
		memcpy(d + 4, v, len);
	повернути 0;
}

ціле
sshbuf_put_cstring(struct sshbuf *buf, const char *v)
{
	повернути sshbuf_put_string(buf, v, v == NULL ? 0 : strlen(v));
}

ціле
sshbuf_put_stringb(struct sshbuf *buf, const struct sshbuf *v)
{
	якщо (v == NULL)
		повернути sshbuf_put_string(buf, NULL, 0);

	повернути sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

ціле
sshbuf_froms(struct sshbuf *buf, struct sshbuf **bufp)
{
	const u_char *p;
	size_t len;
	struct sshbuf *ret;
	ціле r;

	якщо (buf == NULL || bufp == NULL)
		повернути SSH_ERR_INVALID_ARGUMENT;
	*bufp = NULL;
	якщо ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		повернути r;
	якщо ((ret = sshbuf_from(p, len)) == NULL)
		повернути SSH_ERR_ALLOC_FAIL;
	якщо ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_set_parent(ret, buf)) != 0) {
		sshbuf_free(ret);
		повернути r;
	}
	*bufp = ret;
	повернути 0;
}

ціле
sshbuf_put_bignum2_bytes(struct sshbuf *buf, const void *v, size_t len)
{
	u_char *d;
	const u_char *s = (const u_char *)v;
	ціле r, prepend;

	якщо (len > SSHBUF_SIZE_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		повернути SSH_ERR_NO_BUFFER_SPACE;
	}
	/* Skip leading zero bytes */
	для (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	якщо ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		повернути r;
	POKE_U32(d, len + prepend);
	якщо (prepend)
		d[4] = 0;
	якщо (len != 0)
		memcpy(d + 4 + prepend, s, len);
	повернути 0;
}

ціле
sshbuf_get_bignum2_bytes_direct(struct sshbuf *buf,
    const u_char **valp, size_t *lenp)
{
	const u_char *d;
	size_t len, olen;
	ціле r;

	якщо ((r = sshbuf_peek_string_direct(buf, &d, &olen)) < 0)
		повернути r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	якщо ((len != 0 && (*d & 0x80) != 0))
		повернути SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	якщо (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		повернути SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	поки (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	якщо (valp != NULL)
		*valp = d;
	якщо (lenp != NULL)
		*lenp = len;
	якщо (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		повернути SSH_ERR_INTERNAL_ERROR;
	}
	повернути 0;
}

ціле
sshbuf_get_nulterminated_string(struct sshbuf *buf, size_t maxlen,
    char **valp, size_t *lenp)
{
	const u_char zero = 0;
	char *val = NULL;
	size_t len = 0;
	ціле r;

	якщо (valp != NULL)
		*valp = NULL;
	якщо (lenp != NULL)
		*lenp = 0;
	якщо ((r = sshbuf_find(buf, 0, &zero, sizeof(zero), &len)) != 0) {
		якщо (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			повернути SSH_ERR_MESSAGE_INCOMPLETE;
		повернути r;
	}
	якщо (len > maxlen)
		повернути SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	якщо ((val = strdup(sshbuf_ptr(buf))) == NULL)
		повернути SSH_ERR_ALLOC_FAIL;
	якщо ((r = sshbuf_consume(buf, len + 1)) != 0)
		goto out;
	/* success */
	r = 0;
	якщо (valp != NULL) {
		*valp = val;
		val = NULL;
	}
	якщо (lenp != NULL)
		*lenp = len;
 out:
	free(val);
	повернути r;
}
