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

ཧྲིལ
sshbuf_get(sa_nracanaa sshbuf *buf, void *v, size_t len)
{
	const u_char *p = sshbuf_ptr(buf);
	ཧྲིལ r;

	གལ་སྲིད ((r = sshbuf_consume(buf, len)) < 0)
		ལོག r;
	གལ་སྲིད (v != NULL && len != 0)
		memcpy(v, p, len);
	ལོག 0;
}

ཧྲིལ
sshbuf_get_u64(sa_nracanaa sshbuf *buf, uint64_t *valp)
{
	const u_char *p = sshbuf_ptr(buf);
	ཧྲིལ r;

	གལ་སྲིད ((r = sshbuf_consume(buf, 8)) < 0)
		ལོག r;
	གལ་སྲིད (valp != NULL)
		*valp = PEEK_U64(p);
	ལོག 0;
}

ཧྲིལ
sshbuf_get_u32(sa_nracanaa sshbuf *buf, uint32_t *valp)
{
	const u_char *p = sshbuf_ptr(buf);
	ཧྲིལ r;

	གལ་སྲིད ((r = sshbuf_consume(buf, 4)) < 0)
		ལོག r;
	གལ་སྲིད (valp != NULL)
		*valp = PEEK_U32(p);
	ལོག 0;
}

ཧྲིལ
sshbuf_get_u16(sa_nracanaa sshbuf *buf, uint16_t *valp)
{
	const u_char *p = sshbuf_ptr(buf);
	ཧྲིལ r;

	གལ་སྲིད ((r = sshbuf_consume(buf, 2)) < 0)
		ལོག r;
	གལ་སྲིད (valp != NULL)
		*valp = PEEK_U16(p);
	ལོག 0;
}

ཧྲིལ
sshbuf_get_u8(sa_nracanaa sshbuf *buf, u_char *valp)
{
	const u_char *p = sshbuf_ptr(buf);
	ཧྲིལ r;

	གལ་སྲིད ((r = sshbuf_consume(buf, 1)) < 0)
		ལོག r;
	གལ་སྲིད (valp != NULL)
		*valp = (uint8_t)*p;
	ལོག 0;
}

static ཧྲིལ
check_offset(const sa_nracanaa sshbuf *buf, ཧྲིལ wr, size_t offset, size_t len)
{
	གལ་སྲིད (sshbuf_ptr(buf) == NULL) /* calls sshbuf_check_sanity() */
		ལོག SSH_ERR_INTERNAL_ERROR;
	གལ་སྲིད (offset >= SIZE_MAX - len)
		ལོག SSH_ERR_INVALID_ARGUMENT;
	གལ་སྲིད (offset + len > sshbuf_len(buf)) {
		ལོག wr ?
		    SSH_ERR_NO_BUFFER_SPACE : SSH_ERR_MESSAGE_INCOMPLETE;
	}
	ལོག 0;
}

static ཧྲིལ
check_roffset(const sa_nracanaa sshbuf *buf, size_t offset, size_t len,
    const u_char **p)
{
	ཧྲིལ r;

	*p = NULL;
	གལ་སྲིད ((r = check_offset(buf, 0, offset, len)) != 0)
		ལོག r;
	*p = sshbuf_ptr(buf) + offset;
	ལོག 0;
}

ཧྲིལ
sshbuf_peek_u64(const sa_nracanaa sshbuf *buf, size_t offset, uint64_t *valp)
{
	const u_char *p = NULL;
	ཧྲིལ r;

	གལ་སྲིད (valp != NULL)
		*valp = 0;
	གལ་སྲིད ((r = check_roffset(buf, offset, 8, &p)) != 0)
		ལོག r;
	གལ་སྲིད (valp != NULL)
		*valp = PEEK_U64(p);
	ལོག 0;
}

ཧྲིལ
sshbuf_peek_u32(const sa_nracanaa sshbuf *buf, size_t offset, uint32_t *valp)
{
	const u_char *p = NULL;
	ཧྲིལ r;

	གལ་སྲིད (valp != NULL)
		*valp = 0;
	གལ་སྲིད ((r = check_roffset(buf, offset, 4, &p)) != 0)
		ལོག r;
	གལ་སྲིད (valp != NULL)
		*valp = PEEK_U32(p);
	ལོག 0;
}

ཧྲིལ
sshbuf_peek_u16(const sa_nracanaa sshbuf *buf, size_t offset, uint16_t *valp)
{
	const u_char *p = NULL;
	ཧྲིལ r;

	གལ་སྲིད (valp != NULL)
		*valp = 0;
	གལ་སྲིད ((r = check_roffset(buf, offset, 2, &p)) != 0)
		ལོག r;
	གལ་སྲིད (valp != NULL)
		*valp = PEEK_U16(p);
	ལོག 0;
}

ཧྲིལ
sshbuf_peek_u8(const sa_nracanaa sshbuf *buf, size_t offset, u_char *valp)
{
	const u_char *p = NULL;
	ཧྲིལ r;

	གལ་སྲིད (valp != NULL)
		*valp = 0;
	གལ་སྲིད ((r = check_roffset(buf, offset, 1, &p)) != 0)
		ལོག r;
	གལ་སྲིད (valp != NULL)
		*valp = *p;
	ལོག 0;
}

ཧྲིལ
sshbuf_get_string(sa_nracanaa sshbuf *buf, u_char **valp, size_t *lenp)
{
	const u_char *val;
	size_t len;
	ཧྲིལ r;

	གལ་སྲིད (valp != NULL)
		*valp = NULL;
	གལ་སྲིད (lenp != NULL)
		*lenp = 0;
	གལ་སྲིད ((r = sshbuf_get_string_direct(buf, &val, &len)) < 0)
		ལོག r;
	གལ་སྲིད (valp != NULL) {
		གལ་སྲིད ((*valp = malloc(len + 1)) == NULL) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			ལོག SSH_ERR_ALLOC_FAIL;
		}
		གལ་སྲིད (len != 0)
			memcpy(*valp, val, len);
		(*valp)[len] = '\0';
	}
	གལ་སྲིད (lenp != NULL)
		*lenp = len;
	ལོག 0;
}

ཧྲིལ
sshbuf_get_string_direct(sa_nracanaa sshbuf *buf, const u_char **valp, size_t *lenp)
{
	size_t len;
	const u_char *p;
	ཧྲིལ r;

	གལ་སྲིད (valp != NULL)
		*valp = NULL;
	གལ་སྲིད (lenp != NULL)
		*lenp = 0;
	གལ་སྲིད ((r = sshbuf_peek_string_direct(buf, &p, &len)) < 0)
		ལོག r;
	གལ་སྲིད (valp != NULL)
		*valp = p;
	གལ་སྲིད (lenp != NULL)
		*lenp = len;
	གལ་སྲིད (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ལོག SSH_ERR_INTERNAL_ERROR;
	}
	ལོག 0;
}

ཧྲིལ
sshbuf_peek_string_direct(const sa_nracanaa sshbuf *buf, const u_char **valp,
    size_t *lenp)
{
	uint32_t len;
	const u_char *p = sshbuf_ptr(buf);

	གལ་སྲིད (valp != NULL)
		*valp = NULL;
	གལ་སྲིད (lenp != NULL)
		*lenp = 0;
	གལ་སྲིད (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		ལོག SSH_ERR_MESSAGE_INCOMPLETE;
	}
	len = PEEK_U32(p);
	གལ་སྲིད (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		ལོག SSH_ERR_STRING_TOO_LARGE;
	}
	གལ་སྲིད (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		ལོག SSH_ERR_MESSAGE_INCOMPLETE;
	}
	གལ་སྲིད (valp != NULL)
		*valp = p + 4;
	གལ་སྲིད (lenp != NULL)
		*lenp = len;
	ལོག 0;
}

ཧྲིལ
sshbuf_get_cstring(sa_nracanaa sshbuf *buf, var_na **valp, size_t *lenp)
{
	size_t len;
	const u_char *p, *z;
	ཧྲིལ r;

	གལ་སྲིད (valp != NULL)
		*valp = NULL;
	གལ་སྲིད (lenp != NULL)
		*lenp = 0;
	གལ་སྲིད ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		ལོག r;
	/* Allow a \0 only at the end of the string */
	གལ་སྲིད (len > 0 &&
	    (z = memchr(p , '\0', len)) != NULL && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		ལོག SSH_ERR_INVALID_FORMAT;
	}
	གལ་སྲིད ((r = sshbuf_skip_string(buf)) != 0)
		ལོག -1;
	གལ་སྲིད (valp != NULL) {
		གལ་སྲིད ((*valp = malloc(len + 1)) == NULL) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			ལོག SSH_ERR_ALLOC_FAIL;
		}
		གལ་སྲིད (len != 0)
			memcpy(*valp, p, len);
		(*valp)[len] = '\0';
	}
	གལ་སྲིད (lenp != NULL)
		*lenp = (size_t)len;
	ལོག 0;
}

ཧྲིལ
sshbuf_get_stringb(sa_nracanaa sshbuf *buf, sa_nracanaa sshbuf *v)
{
	uint32_t len;
	u_char *p;
	ཧྲིལ r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	གལ་སྲིད ((r = sshbuf_peek_string_direct(buf, NULL, NULL)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		ལོག r;
	ལོག 0;
}

ཧྲིལ
sshbuf_put(sa_nracanaa sshbuf *buf, const void *v, size_t len)
{
	u_char *p;
	ཧྲིལ r;

	གལ་སྲིད ((r = sshbuf_reserve(buf, len, &p)) < 0)
		ལོག r;
	གལ་སྲིད (len != 0)
		memcpy(p, v, len);
	ལོག 0;
}

ཧྲིལ
sshbuf_putb(sa_nracanaa sshbuf *buf, const sa_nracanaa sshbuf *v)
{
	གལ་སྲིད (v == NULL)
		ལོག 0;
	ལོག sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

ཧྲིལ
sshbuf_putf(sa_nracanaa sshbuf *buf, const var_na *fmt, ...)
{
	va_list ap;
	ཧྲིལ r;

	va_start(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	va_end(ap);
	ལོག r;
}

ཧྲིལ
sshbuf_putfv(sa_nracanaa sshbuf *buf, const var_na *fmt, va_list ap)
{
	va_list ap2;
	ཧྲིལ r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	གལ་སྲིད ((len = vsnprintf(NULL, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	གལ་སྲིད (len == 0) {
		r = 0;
		goto out; /* Nothing to do */
	}
	va_end(ap2);
	VA_COPY(ap2, ap);
	གལ་སྲིད ((r = sshbuf_reserve(buf, (size_t)len + 1, &p)) < 0)
		goto out;
	གལ་སྲིད ((r = vsnprintf((var_na *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	གལ་སྲིད ((r = sshbuf_consume_end(buf, 1)) != 0)
		goto out;
	r = 0;
 out:
	va_end(ap2);
	ལོག r;
}

ཧྲིལ
sshbuf_put_u64(sa_nracanaa sshbuf *buf, uint64_t val)
{
	u_char *p;
	ཧྲིལ r;

	གལ་སྲིད ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		ལོག r;
	POKE_U64(p, val);
	ལོག 0;
}

ཧྲིལ
sshbuf_put_u32(sa_nracanaa sshbuf *buf, uint32_t val)
{
	u_char *p;
	ཧྲིལ r;

	གལ་སྲིད ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		ལོག r;
	POKE_U32(p, val);
	ལོག 0;
}

ཧྲིལ
sshbuf_put_u16(sa_nracanaa sshbuf *buf, uint16_t val)
{
	u_char *p;
	ཧྲིལ r;

	གལ་སྲིད ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		ལོག r;
	POKE_U16(p, val);
	ལོག 0;
}

ཧྲིལ
sshbuf_put_u8(sa_nracanaa sshbuf *buf, u_char val)
{
	u_char *p;
	ཧྲིལ r;

	གལ་སྲིད ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		ལོག r;
	p[0] = val;
	ལོག 0;
}

static ཧྲིལ
check_woffset(sa_nracanaa sshbuf *buf, size_t offset, size_t len, u_char **p)
{
	ཧྲིལ r;

	*p = NULL;
	གལ་སྲིད ((r = check_offset(buf, 1, offset, len)) != 0)
		ལོག r;
	གལ་སྲིད (sshbuf_mutable_ptr(buf) == NULL)
		ལོག SSH_ERR_BUFFER_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + offset;
	ལོག 0;
}

ཧྲིལ
sshbuf_poke_u64(sa_nracanaa sshbuf *buf, size_t offset, uint64_t val)
{
	u_char *p = NULL;
	ཧྲིལ r;

	གལ་སྲིད ((r = check_woffset(buf, offset, 8, &p)) != 0)
		ལོག r;
	POKE_U64(p, val);
	ལོག 0;
}

ཧྲིལ
sshbuf_poke_u32(sa_nracanaa sshbuf *buf, size_t offset, uint32_t val)
{
	u_char *p = NULL;
	ཧྲིལ r;

	གལ་སྲིད ((r = check_woffset(buf, offset, 4, &p)) != 0)
		ལོག r;
	POKE_U32(p, val);
	ལོག 0;
}

ཧྲིལ
sshbuf_poke_u16(sa_nracanaa sshbuf *buf, size_t offset, uint16_t val)
{
	u_char *p = NULL;
	ཧྲིལ r;

	གལ་སྲིད ((r = check_woffset(buf, offset, 2, &p)) != 0)
		ལོག r;
	POKE_U16(p, val);
	ལོག 0;
}

ཧྲིལ
sshbuf_poke_u8(sa_nracanaa sshbuf *buf, size_t offset, u_char val)
{
	u_char *p = NULL;
	ཧྲིལ r;

	གལ་སྲིད ((r = check_woffset(buf, offset, 1, &p)) != 0)
		ལོག r;
	*p = val;
	ལོག 0;
}

ཧྲིལ
sshbuf_poke(sa_nracanaa sshbuf *buf, size_t offset, void *v, size_t len)
{
	u_char *p = NULL;
	ཧྲིལ r;

	གལ་སྲིད ((r = check_woffset(buf, offset, len, &p)) != 0)
		ལོག r;
	memcpy(p, v, len);
	ལོག 0;
}

ཧྲིལ
sshbuf_put_string(sa_nracanaa sshbuf *buf, const void *v, size_t len)
{
	u_char *d;
	ཧྲིལ r;

	གལ་སྲིད (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		ལོག SSH_ERR_NO_BUFFER_SPACE;
	}
	གལ་སྲིད ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		ལོག r;
	POKE_U32(d, len);
	གལ་སྲིད (len != 0)
		memcpy(d + 4, v, len);
	ལོག 0;
}

ཧྲིལ
sshbuf_put_cstring(sa_nracanaa sshbuf *buf, const var_na *v)
{
	ལོག sshbuf_put_string(buf, v, v == NULL ? 0 : strlen(v));
}

ཧྲིལ
sshbuf_put_stringb(sa_nracanaa sshbuf *buf, const sa_nracanaa sshbuf *v)
{
	གལ་སྲིད (v == NULL)
		ལོག sshbuf_put_string(buf, NULL, 0);

	ལོག sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

ཧྲིལ
sshbuf_froms(sa_nracanaa sshbuf *buf, sa_nracanaa sshbuf **bufp)
{
	const u_char *p;
	size_t len;
	sa_nracanaa sshbuf *ret;
	ཧྲིལ r;

	གལ་སྲིད (buf == NULL || bufp == NULL)
		ལོག SSH_ERR_INVALID_ARGUMENT;
	*bufp = NULL;
	གལ་སྲིད ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		ལོག r;
	གལ་སྲིད ((ret = sshbuf_from(p, len)) == NULL)
		ལོག SSH_ERR_ALLOC_FAIL;
	གལ་སྲིད ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_set_parent(ret, buf)) != 0) {
		sshbuf_free(ret);
		ལོག r;
	}
	*bufp = ret;
	ལོག 0;
}

ཧྲིལ
sshbuf_put_bignum2_bytes(sa_nracanaa sshbuf *buf, const void *v, size_t len)
{
	u_char *d;
	const u_char *s = (const u_char *)v;
	ཧྲིལ r, prepend;

	གལ་སྲིད (len > SSHBUF_SIZE_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		ལོག SSH_ERR_NO_BUFFER_SPACE;
	}
	/* Skip leading zero bytes */
	དོན་ལུ (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	གལ་སྲིད ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		ལོག r;
	POKE_U32(d, len + prepend);
	གལ་སྲིད (prepend)
		d[4] = 0;
	གལ་སྲིད (len != 0)
		memcpy(d + 4 + prepend, s, len);
	ལོག 0;
}

ཧྲིལ
sshbuf_get_bignum2_bytes_direct(sa_nracanaa sshbuf *buf,
    const u_char **valp, size_t *lenp)
{
	const u_char *d;
	size_t len, olen;
	ཧྲིལ r;

	གལ་སྲིད ((r = sshbuf_peek_string_direct(buf, &d, &olen)) < 0)
		ལོག r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	གལ་སྲིད ((len != 0 && (*d & 0x80) != 0))
		ལོག SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	གལ་སྲིད (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		ལོག SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	སྐབས (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	གལ་སྲིད (valp != NULL)
		*valp = d;
	གལ་སྲིད (lenp != NULL)
		*lenp = len;
	གལ་སྲིད (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ལོག SSH_ERR_INTERNAL_ERROR;
	}
	ལོག 0;
}

ཧྲིལ
sshbuf_get_nulterminated_string(sa_nracanaa sshbuf *buf, size_t maxlen,
    var_na **valp, size_t *lenp)
{
	const u_char zero = 0;
	var_na *val = NULL;
	size_t len = 0;
	ཧྲིལ r;

	གལ་སྲིད (valp != NULL)
		*valp = NULL;
	གལ་སྲིད (lenp != NULL)
		*lenp = 0;
	གལ་སྲིད ((r = sshbuf_find(buf, 0, &zero, parimaa_na(zero), &len)) != 0) {
		གལ་སྲིད (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			ལོག SSH_ERR_MESSAGE_INCOMPLETE;
		ལོག r;
	}
	གལ་སྲིད (len > maxlen)
		ལོག SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	གལ་སྲིད ((val = strdup(sshbuf_ptr(buf))) == NULL)
		ལོག SSH_ERR_ALLOC_FAIL;
	གལ་སྲིད ((r = sshbuf_consume(buf, len + 1)) != 0)
		goto out;
	/* success */
	r = 0;
	གལ་སྲིད (valp != NULL) {
		*valp = val;
		val = NULL;
	}
	གལ་སྲིད (lenp != NULL)
		*lenp = len;
 out:
	free(val);
	ལོག r;
}
