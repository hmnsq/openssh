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

ចំនួនគត់
sshbuf_get(sa_nracanaa sshbuf *buf, void *v, size_t len)
{
	const u_char *p = sshbuf_ptr(buf);
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = sshbuf_consume(buf, len)) < 0)
		ត្រឡប់ r;
	ប្រសិនបើ (v != NULL && len != 0)
		memcpy(v, p, len);
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_get_u64(sa_nracanaa sshbuf *buf, uint64_t *valp)
{
	const u_char *p = sshbuf_ptr(buf);
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = sshbuf_consume(buf, 8)) < 0)
		ត្រឡប់ r;
	ប្រសិនបើ (valp != NULL)
		*valp = PEEK_U64(p);
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_get_u32(sa_nracanaa sshbuf *buf, uint32_t *valp)
{
	const u_char *p = sshbuf_ptr(buf);
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = sshbuf_consume(buf, 4)) < 0)
		ត្រឡប់ r;
	ប្រសិនបើ (valp != NULL)
		*valp = PEEK_U32(p);
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_get_u16(sa_nracanaa sshbuf *buf, uint16_t *valp)
{
	const u_char *p = sshbuf_ptr(buf);
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = sshbuf_consume(buf, 2)) < 0)
		ត្រឡប់ r;
	ប្រសិនបើ (valp != NULL)
		*valp = PEEK_U16(p);
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_get_u8(sa_nracanaa sshbuf *buf, u_char *valp)
{
	const u_char *p = sshbuf_ptr(buf);
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = sshbuf_consume(buf, 1)) < 0)
		ត្រឡប់ r;
	ប្រសិនបើ (valp != NULL)
		*valp = (uint8_t)*p;
	ត្រឡប់ 0;
}

static ចំនួនគត់
check_offset(const sa_nracanaa sshbuf *buf, ចំនួនគត់ wr, size_t offset, size_t len)
{
	ប្រសិនបើ (sshbuf_ptr(buf) == NULL) /* calls sshbuf_check_sanity() */
		ត្រឡប់ SSH_ERR_INTERNAL_ERROR;
	ប្រសិនបើ (offset >= SIZE_MAX - len)
		ត្រឡប់ SSH_ERR_INVALID_ARGUMENT;
	ប្រសិនបើ (offset + len > sshbuf_len(buf)) {
		ត្រឡប់ wr ?
		    SSH_ERR_NO_BUFFER_SPACE : SSH_ERR_MESSAGE_INCOMPLETE;
	}
	ត្រឡប់ 0;
}

static ចំនួនគត់
check_roffset(const sa_nracanaa sshbuf *buf, size_t offset, size_t len,
    const u_char **p)
{
	ចំនួនគត់ r;

	*p = NULL;
	ប្រសិនបើ ((r = check_offset(buf, 0, offset, len)) != 0)
		ត្រឡប់ r;
	*p = sshbuf_ptr(buf) + offset;
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_peek_u64(const sa_nracanaa sshbuf *buf, size_t offset, uint64_t *valp)
{
	const u_char *p = NULL;
	ចំនួនគត់ r;

	ប្រសិនបើ (valp != NULL)
		*valp = 0;
	ប្រសិនបើ ((r = check_roffset(buf, offset, 8, &p)) != 0)
		ត្រឡប់ r;
	ប្រសិនបើ (valp != NULL)
		*valp = PEEK_U64(p);
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_peek_u32(const sa_nracanaa sshbuf *buf, size_t offset, uint32_t *valp)
{
	const u_char *p = NULL;
	ចំនួនគត់ r;

	ប្រសិនបើ (valp != NULL)
		*valp = 0;
	ប្រសិនបើ ((r = check_roffset(buf, offset, 4, &p)) != 0)
		ត្រឡប់ r;
	ប្រសិនបើ (valp != NULL)
		*valp = PEEK_U32(p);
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_peek_u16(const sa_nracanaa sshbuf *buf, size_t offset, uint16_t *valp)
{
	const u_char *p = NULL;
	ចំនួនគត់ r;

	ប្រសិនបើ (valp != NULL)
		*valp = 0;
	ប្រសិនបើ ((r = check_roffset(buf, offset, 2, &p)) != 0)
		ត្រឡប់ r;
	ប្រសិនបើ (valp != NULL)
		*valp = PEEK_U16(p);
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_peek_u8(const sa_nracanaa sshbuf *buf, size_t offset, u_char *valp)
{
	const u_char *p = NULL;
	ចំនួនគត់ r;

	ប្រសិនបើ (valp != NULL)
		*valp = 0;
	ប្រសិនបើ ((r = check_roffset(buf, offset, 1, &p)) != 0)
		ត្រឡប់ r;
	ប្រសិនបើ (valp != NULL)
		*valp = *p;
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_get_string(sa_nracanaa sshbuf *buf, u_char **valp, size_t *lenp)
{
	const u_char *val;
	size_t len;
	ចំនួនគត់ r;

	ប្រសិនបើ (valp != NULL)
		*valp = NULL;
	ប្រសិនបើ (lenp != NULL)
		*lenp = 0;
	ប្រសិនបើ ((r = sshbuf_get_string_direct(buf, &val, &len)) < 0)
		ត្រឡប់ r;
	ប្រសិនបើ (valp != NULL) {
		ប្រសិនបើ ((*valp = malloc(len + 1)) == NULL) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			ត្រឡប់ SSH_ERR_ALLOC_FAIL;
		}
		ប្រសិនបើ (len != 0)
			memcpy(*valp, val, len);
		(*valp)[len] = '\0';
	}
	ប្រសិនបើ (lenp != NULL)
		*lenp = len;
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_get_string_direct(sa_nracanaa sshbuf *buf, const u_char **valp, size_t *lenp)
{
	size_t len;
	const u_char *p;
	ចំនួនគត់ r;

	ប្រសិនបើ (valp != NULL)
		*valp = NULL;
	ប្រសិនបើ (lenp != NULL)
		*lenp = 0;
	ប្រសិនបើ ((r = sshbuf_peek_string_direct(buf, &p, &len)) < 0)
		ត្រឡប់ r;
	ប្រសិនបើ (valp != NULL)
		*valp = p;
	ប្រសិនបើ (lenp != NULL)
		*lenp = len;
	ប្រសិនបើ (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ត្រឡប់ SSH_ERR_INTERNAL_ERROR;
	}
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_peek_string_direct(const sa_nracanaa sshbuf *buf, const u_char **valp,
    size_t *lenp)
{
	uint32_t len;
	const u_char *p = sshbuf_ptr(buf);

	ប្រសិនបើ (valp != NULL)
		*valp = NULL;
	ប្រសិនបើ (lenp != NULL)
		*lenp = 0;
	ប្រសិនបើ (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		ត្រឡប់ SSH_ERR_MESSAGE_INCOMPLETE;
	}
	len = PEEK_U32(p);
	ប្រសិនបើ (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		ត្រឡប់ SSH_ERR_STRING_TOO_LARGE;
	}
	ប្រសិនបើ (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		ត្រឡប់ SSH_ERR_MESSAGE_INCOMPLETE;
	}
	ប្រសិនបើ (valp != NULL)
		*valp = p + 4;
	ប្រសិនបើ (lenp != NULL)
		*lenp = len;
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_get_cstring(sa_nracanaa sshbuf *buf, var_na **valp, size_t *lenp)
{
	size_t len;
	const u_char *p, *z;
	ចំនួនគត់ r;

	ប្រសិនបើ (valp != NULL)
		*valp = NULL;
	ប្រសិនបើ (lenp != NULL)
		*lenp = 0;
	ប្រសិនបើ ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		ត្រឡប់ r;
	/* Allow a \0 only at the end of the string */
	ប្រសិនបើ (len > 0 &&
	    (z = memchr(p , '\0', len)) != NULL && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		ត្រឡប់ SSH_ERR_INVALID_FORMAT;
	}
	ប្រសិនបើ ((r = sshbuf_skip_string(buf)) != 0)
		ត្រឡប់ -1;
	ប្រសិនបើ (valp != NULL) {
		ប្រសិនបើ ((*valp = malloc(len + 1)) == NULL) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			ត្រឡប់ SSH_ERR_ALLOC_FAIL;
		}
		ប្រសិនបើ (len != 0)
			memcpy(*valp, p, len);
		(*valp)[len] = '\0';
	}
	ប្រសិនបើ (lenp != NULL)
		*lenp = (size_t)len;
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_get_stringb(sa_nracanaa sshbuf *buf, sa_nracanaa sshbuf *v)
{
	uint32_t len;
	u_char *p;
	ចំនួនគត់ r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	ប្រសិនបើ ((r = sshbuf_peek_string_direct(buf, NULL, NULL)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		ត្រឡប់ r;
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_put(sa_nracanaa sshbuf *buf, const void *v, size_t len)
{
	u_char *p;
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = sshbuf_reserve(buf, len, &p)) < 0)
		ត្រឡប់ r;
	ប្រសិនបើ (len != 0)
		memcpy(p, v, len);
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_putb(sa_nracanaa sshbuf *buf, const sa_nracanaa sshbuf *v)
{
	ប្រសិនបើ (v == NULL)
		ត្រឡប់ 0;
	ត្រឡប់ sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

ចំនួនគត់
sshbuf_putf(sa_nracanaa sshbuf *buf, const var_na *fmt, ...)
{
	va_list ap;
	ចំនួនគត់ r;

	va_start(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	va_end(ap);
	ត្រឡប់ r;
}

ចំនួនគត់
sshbuf_putfv(sa_nracanaa sshbuf *buf, const var_na *fmt, va_list ap)
{
	va_list ap2;
	ចំនួនគត់ r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	ប្រសិនបើ ((len = vsnprintf(NULL, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	ប្រសិនបើ (len == 0) {
		r = 0;
		goto out; /* Nothing to do */
	}
	va_end(ap2);
	VA_COPY(ap2, ap);
	ប្រសិនបើ ((r = sshbuf_reserve(buf, (size_t)len + 1, &p)) < 0)
		goto out;
	ប្រសិនបើ ((r = vsnprintf((var_na *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	ប្រសិនបើ ((r = sshbuf_consume_end(buf, 1)) != 0)
		goto out;
	r = 0;
 out:
	va_end(ap2);
	ត្រឡប់ r;
}

ចំនួនគត់
sshbuf_put_u64(sa_nracanaa sshbuf *buf, uint64_t val)
{
	u_char *p;
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		ត្រឡប់ r;
	POKE_U64(p, val);
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_put_u32(sa_nracanaa sshbuf *buf, uint32_t val)
{
	u_char *p;
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		ត្រឡប់ r;
	POKE_U32(p, val);
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_put_u16(sa_nracanaa sshbuf *buf, uint16_t val)
{
	u_char *p;
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		ត្រឡប់ r;
	POKE_U16(p, val);
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_put_u8(sa_nracanaa sshbuf *buf, u_char val)
{
	u_char *p;
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		ត្រឡប់ r;
	p[0] = val;
	ត្រឡប់ 0;
}

static ចំនួនគត់
check_woffset(sa_nracanaa sshbuf *buf, size_t offset, size_t len, u_char **p)
{
	ចំនួនគត់ r;

	*p = NULL;
	ប្រសិនបើ ((r = check_offset(buf, 1, offset, len)) != 0)
		ត្រឡប់ r;
	ប្រសិនបើ (sshbuf_mutable_ptr(buf) == NULL)
		ត្រឡប់ SSH_ERR_BUFFER_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + offset;
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_poke_u64(sa_nracanaa sshbuf *buf, size_t offset, uint64_t val)
{
	u_char *p = NULL;
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = check_woffset(buf, offset, 8, &p)) != 0)
		ត្រឡប់ r;
	POKE_U64(p, val);
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_poke_u32(sa_nracanaa sshbuf *buf, size_t offset, uint32_t val)
{
	u_char *p = NULL;
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = check_woffset(buf, offset, 4, &p)) != 0)
		ត្រឡប់ r;
	POKE_U32(p, val);
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_poke_u16(sa_nracanaa sshbuf *buf, size_t offset, uint16_t val)
{
	u_char *p = NULL;
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = check_woffset(buf, offset, 2, &p)) != 0)
		ត្រឡប់ r;
	POKE_U16(p, val);
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_poke_u8(sa_nracanaa sshbuf *buf, size_t offset, u_char val)
{
	u_char *p = NULL;
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = check_woffset(buf, offset, 1, &p)) != 0)
		ត្រឡប់ r;
	*p = val;
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_poke(sa_nracanaa sshbuf *buf, size_t offset, void *v, size_t len)
{
	u_char *p = NULL;
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = check_woffset(buf, offset, len, &p)) != 0)
		ត្រឡប់ r;
	memcpy(p, v, len);
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_put_string(sa_nracanaa sshbuf *buf, const void *v, size_t len)
{
	u_char *d;
	ចំនួនគត់ r;

	ប្រសិនបើ (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		ត្រឡប់ SSH_ERR_NO_BUFFER_SPACE;
	}
	ប្រសិនបើ ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		ត្រឡប់ r;
	POKE_U32(d, len);
	ប្រសិនបើ (len != 0)
		memcpy(d + 4, v, len);
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_put_cstring(sa_nracanaa sshbuf *buf, const var_na *v)
{
	ត្រឡប់ sshbuf_put_string(buf, v, v == NULL ? 0 : strlen(v));
}

ចំនួនគត់
sshbuf_put_stringb(sa_nracanaa sshbuf *buf, const sa_nracanaa sshbuf *v)
{
	ប្រសិនបើ (v == NULL)
		ត្រឡប់ sshbuf_put_string(buf, NULL, 0);

	ត្រឡប់ sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

ចំនួនគត់
sshbuf_froms(sa_nracanaa sshbuf *buf, sa_nracanaa sshbuf **bufp)
{
	const u_char *p;
	size_t len;
	sa_nracanaa sshbuf *ret;
	ចំនួនគត់ r;

	ប្រសិនបើ (buf == NULL || bufp == NULL)
		ត្រឡប់ SSH_ERR_INVALID_ARGUMENT;
	*bufp = NULL;
	ប្រសិនបើ ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		ត្រឡប់ r;
	ប្រសិនបើ ((ret = sshbuf_from(p, len)) == NULL)
		ត្រឡប់ SSH_ERR_ALLOC_FAIL;
	ប្រសិនបើ ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_set_parent(ret, buf)) != 0) {
		sshbuf_free(ret);
		ត្រឡប់ r;
	}
	*bufp = ret;
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_put_bignum2_bytes(sa_nracanaa sshbuf *buf, const void *v, size_t len)
{
	u_char *d;
	const u_char *s = (const u_char *)v;
	ចំនួនគត់ r, prepend;

	ប្រសិនបើ (len > SSHBUF_SIZE_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		ត្រឡប់ SSH_ERR_NO_BUFFER_SPACE;
	}
	/* Skip leading zero bytes */
	សម្រាប់ (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	ប្រសិនបើ ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		ត្រឡប់ r;
	POKE_U32(d, len + prepend);
	ប្រសិនបើ (prepend)
		d[4] = 0;
	ប្រសិនបើ (len != 0)
		memcpy(d + 4 + prepend, s, len);
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_get_bignum2_bytes_direct(sa_nracanaa sshbuf *buf,
    const u_char **valp, size_t *lenp)
{
	const u_char *d;
	size_t len, olen;
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = sshbuf_peek_string_direct(buf, &d, &olen)) < 0)
		ត្រឡប់ r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	ប្រសិនបើ ((len != 0 && (*d & 0x80) != 0))
		ត្រឡប់ SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	ប្រសិនបើ (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		ត្រឡប់ SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	ខណៈពេល (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	ប្រសិនបើ (valp != NULL)
		*valp = d;
	ប្រសិនបើ (lenp != NULL)
		*lenp = len;
	ប្រសិនបើ (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ត្រឡប់ SSH_ERR_INTERNAL_ERROR;
	}
	ត្រឡប់ 0;
}

ចំនួនគត់
sshbuf_get_nulterminated_string(sa_nracanaa sshbuf *buf, size_t maxlen,
    var_na **valp, size_t *lenp)
{
	const u_char zero = 0;
	var_na *val = NULL;
	size_t len = 0;
	ចំនួនគត់ r;

	ប្រសិនបើ (valp != NULL)
		*valp = NULL;
	ប្រសិនបើ (lenp != NULL)
		*lenp = 0;
	ប្រសិនបើ ((r = sshbuf_find(buf, 0, &zero, parimaa_na(zero), &len)) != 0) {
		ប្រសិនបើ (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			ត្រឡប់ SSH_ERR_MESSAGE_INCOMPLETE;
		ត្រឡប់ r;
	}
	ប្រសិនបើ (len > maxlen)
		ត្រឡប់ SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	ប្រសិនបើ ((val = strdup(sshbuf_ptr(buf))) == NULL)
		ត្រឡប់ SSH_ERR_ALLOC_FAIL;
	ប្រសិនបើ ((r = sshbuf_consume(buf, len + 1)) != 0)
		goto out;
	/* success */
	r = 0;
	ប្រសិនបើ (valp != NULL) {
		*valp = val;
		val = NULL;
	}
	ប្រសិនបើ (lenp != NULL)
		*lenp = len;
 out:
	free(val);
	ត្រឡប់ r;
}
