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

puur_naa_nka
sshbuf_get(sa_nracanaa sshbuf *buf, void *v, size_t len)
{
	const u_char *p = sshbuf_ptr(buf);
	puur_naa_nka r;

	ᤀᤡ᤺ ((r = sshbuf_consume(buf, len)) < 0)
		ᤀᤡᤴ r;
	ᤀᤡ᤺ (v != NULL && len != 0)
		memcpy(v, p, len);
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_get_u64(sa_nracanaa sshbuf *buf, uint64_t *valp)
{
	const u_char *p = sshbuf_ptr(buf);
	puur_naa_nka r;

	ᤀᤡ᤺ ((r = sshbuf_consume(buf, 8)) < 0)
		ᤀᤡᤴ r;
	ᤀᤡ᤺ (valp != NULL)
		*valp = PEEK_U64(p);
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_get_u32(sa_nracanaa sshbuf *buf, uint32_t *valp)
{
	const u_char *p = sshbuf_ptr(buf);
	puur_naa_nka r;

	ᤀᤡ᤺ ((r = sshbuf_consume(buf, 4)) < 0)
		ᤀᤡᤴ r;
	ᤀᤡ᤺ (valp != NULL)
		*valp = PEEK_U32(p);
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_get_u16(sa_nracanaa sshbuf *buf, uint16_t *valp)
{
	const u_char *p = sshbuf_ptr(buf);
	puur_naa_nka r;

	ᤀᤡ᤺ ((r = sshbuf_consume(buf, 2)) < 0)
		ᤀᤡᤴ r;
	ᤀᤡ᤺ (valp != NULL)
		*valp = PEEK_U16(p);
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_get_u8(sa_nracanaa sshbuf *buf, u_char *valp)
{
	const u_char *p = sshbuf_ptr(buf);
	puur_naa_nka r;

	ᤀᤡ᤺ ((r = sshbuf_consume(buf, 1)) < 0)
		ᤀᤡᤴ r;
	ᤀᤡ᤺ (valp != NULL)
		*valp = (uint8_t)*p;
	ᤀᤡᤴ 0;
}

static puur_naa_nka
check_offset(const sa_nracanaa sshbuf *buf, puur_naa_nka wr, size_t offset, size_t len)
{
	ᤀᤡ᤺ (sshbuf_ptr(buf) == NULL) /* calls sshbuf_check_sanity() */
		ᤀᤡᤴ SSH_ERR_INTERNAL_ERROR;
	ᤀᤡ᤺ (offset >= SIZE_MAX - len)
		ᤀᤡᤴ SSH_ERR_INVALID_ARGUMENT;
	ᤀᤡ᤺ (offset + len > sshbuf_len(buf)) {
		ᤀᤡᤴ wr ?
		    SSH_ERR_NO_BUFFER_SPACE : SSH_ERR_MESSAGE_INCOMPLETE;
	}
	ᤀᤡᤴ 0;
}

static puur_naa_nka
check_roffset(const sa_nracanaa sshbuf *buf, size_t offset, size_t len,
    const u_char **p)
{
	puur_naa_nka r;

	*p = NULL;
	ᤀᤡ᤺ ((r = check_offset(buf, 0, offset, len)) != 0)
		ᤀᤡᤴ r;
	*p = sshbuf_ptr(buf) + offset;
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_peek_u64(const sa_nracanaa sshbuf *buf, size_t offset, uint64_t *valp)
{
	const u_char *p = NULL;
	puur_naa_nka r;

	ᤀᤡ᤺ (valp != NULL)
		*valp = 0;
	ᤀᤡ᤺ ((r = check_roffset(buf, offset, 8, &p)) != 0)
		ᤀᤡᤴ r;
	ᤀᤡ᤺ (valp != NULL)
		*valp = PEEK_U64(p);
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_peek_u32(const sa_nracanaa sshbuf *buf, size_t offset, uint32_t *valp)
{
	const u_char *p = NULL;
	puur_naa_nka r;

	ᤀᤡ᤺ (valp != NULL)
		*valp = 0;
	ᤀᤡ᤺ ((r = check_roffset(buf, offset, 4, &p)) != 0)
		ᤀᤡᤴ r;
	ᤀᤡ᤺ (valp != NULL)
		*valp = PEEK_U32(p);
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_peek_u16(const sa_nracanaa sshbuf *buf, size_t offset, uint16_t *valp)
{
	const u_char *p = NULL;
	puur_naa_nka r;

	ᤀᤡ᤺ (valp != NULL)
		*valp = 0;
	ᤀᤡ᤺ ((r = check_roffset(buf, offset, 2, &p)) != 0)
		ᤀᤡᤴ r;
	ᤀᤡ᤺ (valp != NULL)
		*valp = PEEK_U16(p);
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_peek_u8(const sa_nracanaa sshbuf *buf, size_t offset, u_char *valp)
{
	const u_char *p = NULL;
	puur_naa_nka r;

	ᤀᤡ᤺ (valp != NULL)
		*valp = 0;
	ᤀᤡ᤺ ((r = check_roffset(buf, offset, 1, &p)) != 0)
		ᤀᤡᤴ r;
	ᤀᤡ᤺ (valp != NULL)
		*valp = *p;
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_get_string(sa_nracanaa sshbuf *buf, u_char **valp, size_t *lenp)
{
	const u_char *val;
	size_t len;
	puur_naa_nka r;

	ᤀᤡ᤺ (valp != NULL)
		*valp = NULL;
	ᤀᤡ᤺ (lenp != NULL)
		*lenp = 0;
	ᤀᤡ᤺ ((r = sshbuf_get_string_direct(buf, &val, &len)) < 0)
		ᤀᤡᤴ r;
	ᤀᤡ᤺ (valp != NULL) {
		ᤀᤡ᤺ ((*valp = malloc(len + 1)) == NULL) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			ᤀᤡᤴ SSH_ERR_ALLOC_FAIL;
		}
		ᤀᤡ᤺ (len != 0)
			memcpy(*valp, val, len);
		(*valp)[len] = '\0';
	}
	ᤀᤡ᤺ (lenp != NULL)
		*lenp = len;
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_get_string_direct(sa_nracanaa sshbuf *buf, const u_char **valp, size_t *lenp)
{
	size_t len;
	const u_char *p;
	puur_naa_nka r;

	ᤀᤡ᤺ (valp != NULL)
		*valp = NULL;
	ᤀᤡ᤺ (lenp != NULL)
		*lenp = 0;
	ᤀᤡ᤺ ((r = sshbuf_peek_string_direct(buf, &p, &len)) < 0)
		ᤀᤡᤴ r;
	ᤀᤡ᤺ (valp != NULL)
		*valp = p;
	ᤀᤡ᤺ (lenp != NULL)
		*lenp = len;
	ᤀᤡ᤺ (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ᤀᤡᤴ SSH_ERR_INTERNAL_ERROR;
	}
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_peek_string_direct(const sa_nracanaa sshbuf *buf, const u_char **valp,
    size_t *lenp)
{
	uint32_t len;
	const u_char *p = sshbuf_ptr(buf);

	ᤀᤡ᤺ (valp != NULL)
		*valp = NULL;
	ᤀᤡ᤺ (lenp != NULL)
		*lenp = 0;
	ᤀᤡ᤺ (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		ᤀᤡᤴ SSH_ERR_MESSAGE_INCOMPLETE;
	}
	len = PEEK_U32(p);
	ᤀᤡ᤺ (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		ᤀᤡᤴ SSH_ERR_STRING_TOO_LARGE;
	}
	ᤀᤡ᤺ (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		ᤀᤡᤴ SSH_ERR_MESSAGE_INCOMPLETE;
	}
	ᤀᤡ᤺ (valp != NULL)
		*valp = p + 4;
	ᤀᤡ᤺ (lenp != NULL)
		*lenp = len;
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_get_cstring(sa_nracanaa sshbuf *buf, var_na **valp, size_t *lenp)
{
	size_t len;
	const u_char *p, *z;
	puur_naa_nka r;

	ᤀᤡ᤺ (valp != NULL)
		*valp = NULL;
	ᤀᤡ᤺ (lenp != NULL)
		*lenp = 0;
	ᤀᤡ᤺ ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		ᤀᤡᤴ r;
	/* Allow a \0 only at the end of the string */
	ᤀᤡ᤺ (len > 0 &&
	    (z = memchr(p , '\0', len)) != NULL && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		ᤀᤡᤴ SSH_ERR_INVALID_FORMAT;
	}
	ᤀᤡ᤺ ((r = sshbuf_skip_string(buf)) != 0)
		ᤀᤡᤴ -1;
	ᤀᤡ᤺ (valp != NULL) {
		ᤀᤡ᤺ ((*valp = malloc(len + 1)) == NULL) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			ᤀᤡᤴ SSH_ERR_ALLOC_FAIL;
		}
		ᤀᤡ᤺ (len != 0)
			memcpy(*valp, p, len);
		(*valp)[len] = '\0';
	}
	ᤀᤡ᤺ (lenp != NULL)
		*lenp = (size_t)len;
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_get_stringb(sa_nracanaa sshbuf *buf, sa_nracanaa sshbuf *v)
{
	uint32_t len;
	u_char *p;
	puur_naa_nka r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	ᤀᤡ᤺ ((r = sshbuf_peek_string_direct(buf, NULL, NULL)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		ᤀᤡᤴ r;
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_put(sa_nracanaa sshbuf *buf, const void *v, size_t len)
{
	u_char *p;
	puur_naa_nka r;

	ᤀᤡ᤺ ((r = sshbuf_reserve(buf, len, &p)) < 0)
		ᤀᤡᤴ r;
	ᤀᤡ᤺ (len != 0)
		memcpy(p, v, len);
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_putb(sa_nracanaa sshbuf *buf, const sa_nracanaa sshbuf *v)
{
	ᤀᤡ᤺ (v == NULL)
		ᤀᤡᤴ 0;
	ᤀᤡᤴ sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

puur_naa_nka
sshbuf_putf(sa_nracanaa sshbuf *buf, const var_na *fmt, ...)
{
	va_list ap;
	puur_naa_nka r;

	va_start(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	va_end(ap);
	ᤀᤡᤴ r;
}

puur_naa_nka
sshbuf_putfv(sa_nracanaa sshbuf *buf, const var_na *fmt, va_list ap)
{
	va_list ap2;
	puur_naa_nka r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	ᤀᤡ᤺ ((len = vsnprintf(NULL, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	ᤀᤡ᤺ (len == 0) {
		r = 0;
		goto out; /* Nothing to do */
	}
	va_end(ap2);
	VA_COPY(ap2, ap);
	ᤀᤡ᤺ ((r = sshbuf_reserve(buf, (size_t)len + 1, &p)) < 0)
		goto out;
	ᤀᤡ᤺ ((r = vsnprintf((var_na *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	ᤀᤡ᤺ ((r = sshbuf_consume_end(buf, 1)) != 0)
		goto out;
	r = 0;
 out:
	va_end(ap2);
	ᤀᤡᤴ r;
}

puur_naa_nka
sshbuf_put_u64(sa_nracanaa sshbuf *buf, uint64_t val)
{
	u_char *p;
	puur_naa_nka r;

	ᤀᤡ᤺ ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		ᤀᤡᤴ r;
	POKE_U64(p, val);
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_put_u32(sa_nracanaa sshbuf *buf, uint32_t val)
{
	u_char *p;
	puur_naa_nka r;

	ᤀᤡ᤺ ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		ᤀᤡᤴ r;
	POKE_U32(p, val);
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_put_u16(sa_nracanaa sshbuf *buf, uint16_t val)
{
	u_char *p;
	puur_naa_nka r;

	ᤀᤡ᤺ ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		ᤀᤡᤴ r;
	POKE_U16(p, val);
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_put_u8(sa_nracanaa sshbuf *buf, u_char val)
{
	u_char *p;
	puur_naa_nka r;

	ᤀᤡ᤺ ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		ᤀᤡᤴ r;
	p[0] = val;
	ᤀᤡᤴ 0;
}

static puur_naa_nka
check_woffset(sa_nracanaa sshbuf *buf, size_t offset, size_t len, u_char **p)
{
	puur_naa_nka r;

	*p = NULL;
	ᤀᤡ᤺ ((r = check_offset(buf, 1, offset, len)) != 0)
		ᤀᤡᤴ r;
	ᤀᤡ᤺ (sshbuf_mutable_ptr(buf) == NULL)
		ᤀᤡᤴ SSH_ERR_BUFFER_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + offset;
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_poke_u64(sa_nracanaa sshbuf *buf, size_t offset, uint64_t val)
{
	u_char *p = NULL;
	puur_naa_nka r;

	ᤀᤡ᤺ ((r = check_woffset(buf, offset, 8, &p)) != 0)
		ᤀᤡᤴ r;
	POKE_U64(p, val);
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_poke_u32(sa_nracanaa sshbuf *buf, size_t offset, uint32_t val)
{
	u_char *p = NULL;
	puur_naa_nka r;

	ᤀᤡ᤺ ((r = check_woffset(buf, offset, 4, &p)) != 0)
		ᤀᤡᤴ r;
	POKE_U32(p, val);
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_poke_u16(sa_nracanaa sshbuf *buf, size_t offset, uint16_t val)
{
	u_char *p = NULL;
	puur_naa_nka r;

	ᤀᤡ᤺ ((r = check_woffset(buf, offset, 2, &p)) != 0)
		ᤀᤡᤴ r;
	POKE_U16(p, val);
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_poke_u8(sa_nracanaa sshbuf *buf, size_t offset, u_char val)
{
	u_char *p = NULL;
	puur_naa_nka r;

	ᤀᤡ᤺ ((r = check_woffset(buf, offset, 1, &p)) != 0)
		ᤀᤡᤴ r;
	*p = val;
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_poke(sa_nracanaa sshbuf *buf, size_t offset, void *v, size_t len)
{
	u_char *p = NULL;
	puur_naa_nka r;

	ᤀᤡ᤺ ((r = check_woffset(buf, offset, len, &p)) != 0)
		ᤀᤡᤴ r;
	memcpy(p, v, len);
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_put_string(sa_nracanaa sshbuf *buf, const void *v, size_t len)
{
	u_char *d;
	puur_naa_nka r;

	ᤀᤡ᤺ (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		ᤀᤡᤴ SSH_ERR_NO_BUFFER_SPACE;
	}
	ᤀᤡ᤺ ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		ᤀᤡᤴ r;
	POKE_U32(d, len);
	ᤀᤡ᤺ (len != 0)
		memcpy(d + 4, v, len);
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_put_cstring(sa_nracanaa sshbuf *buf, const var_na *v)
{
	ᤀᤡᤴ sshbuf_put_string(buf, v, v == NULL ? 0 : strlen(v));
}

puur_naa_nka
sshbuf_put_stringb(sa_nracanaa sshbuf *buf, const sa_nracanaa sshbuf *v)
{
	ᤀᤡ᤺ (v == NULL)
		ᤀᤡᤴ sshbuf_put_string(buf, NULL, 0);

	ᤀᤡᤴ sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

puur_naa_nka
sshbuf_froms(sa_nracanaa sshbuf *buf, sa_nracanaa sshbuf **bufp)
{
	const u_char *p;
	size_t len;
	sa_nracanaa sshbuf *ret;
	puur_naa_nka r;

	ᤀᤡ᤺ (buf == NULL || bufp == NULL)
		ᤀᤡᤴ SSH_ERR_INVALID_ARGUMENT;
	*bufp = NULL;
	ᤀᤡ᤺ ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		ᤀᤡᤴ r;
	ᤀᤡ᤺ ((ret = sshbuf_from(p, len)) == NULL)
		ᤀᤡᤴ SSH_ERR_ALLOC_FAIL;
	ᤀᤡ᤺ ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_set_parent(ret, buf)) != 0) {
		sshbuf_free(ret);
		ᤀᤡᤴ r;
	}
	*bufp = ret;
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_put_bignum2_bytes(sa_nracanaa sshbuf *buf, const void *v, size_t len)
{
	u_char *d;
	const u_char *s = (const u_char *)v;
	puur_naa_nka r, prepend;

	ᤀᤡ᤺ (len > SSHBUF_SIZE_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		ᤀᤡᤴ SSH_ERR_NO_BUFFER_SPACE;
	}
	/* Skip leading zero bytes */
	for (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	ᤀᤡ᤺ ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		ᤀᤡᤴ r;
	POKE_U32(d, len + prepend);
	ᤀᤡ᤺ (prepend)
		d[4] = 0;
	ᤀᤡ᤺ (len != 0)
		memcpy(d + 4 + prepend, s, len);
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_get_bignum2_bytes_direct(sa_nracanaa sshbuf *buf,
    const u_char **valp, size_t *lenp)
{
	const u_char *d;
	size_t len, olen;
	puur_naa_nka r;

	ᤀᤡ᤺ ((r = sshbuf_peek_string_direct(buf, &d, &olen)) < 0)
		ᤀᤡᤴ r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	ᤀᤡ᤺ ((len != 0 && (*d & 0x80) != 0))
		ᤀᤡᤴ SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	ᤀᤡ᤺ (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		ᤀᤡᤴ SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	ᤀᤠ᤺ (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	ᤀᤡ᤺ (valp != NULL)
		*valp = d;
	ᤀᤡ᤺ (lenp != NULL)
		*lenp = len;
	ᤀᤡ᤺ (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ᤀᤡᤴ SSH_ERR_INTERNAL_ERROR;
	}
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_get_nulterminated_string(sa_nracanaa sshbuf *buf, size_t maxlen,
    var_na **valp, size_t *lenp)
{
	const u_char zero = 0;
	var_na *val = NULL;
	size_t len = 0;
	puur_naa_nka r;

	ᤀᤡ᤺ (valp != NULL)
		*valp = NULL;
	ᤀᤡ᤺ (lenp != NULL)
		*lenp = 0;
	ᤀᤡ᤺ ((r = sshbuf_find(buf, 0, &zero, parimaa_na(zero), &len)) != 0) {
		ᤀᤡ᤺ (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			ᤀᤡᤴ SSH_ERR_MESSAGE_INCOMPLETE;
		ᤀᤡᤴ r;
	}
	ᤀᤡ᤺ (len > maxlen)
		ᤀᤡᤴ SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	ᤀᤡ᤺ ((val = strdup(sshbuf_ptr(buf))) == NULL)
		ᤀᤡᤴ SSH_ERR_ALLOC_FAIL;
	ᤀᤡ᤺ ((r = sshbuf_consume(buf, len + 1)) != 0)
		goto out;
	/* success */
	r = 0;
	ᤀᤡ᤺ (valp != NULL) {
		*valp = val;
		val = NULL;
	}
	ᤀᤡ᤺ (lenp != NULL)
		*lenp = len;
 out:
	free(val);
	ᤀᤡᤴ r;
}
