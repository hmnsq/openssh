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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdint.h>

#अन्तर्भाव "ssherr.h"
#define SSHBUF_INTERNAL
#अन्तर्भाव "sshbuf.h"

पूर्णाङ्क
sshbuf_get(संरचना sshbuf *buf, शून्य *v, size_t len)
{
	ध्रुव u_char *p = sshbuf_ptr(buf);
	पूर्णाङ्क r;

	सचे ((r = sshbuf_consume(buf, len)) < 0)
		पटिनिवत्त r;
	सचे (v != रिक्त && len != 0)
		memcpy(v, p, len);
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_get_u64(संरचना sshbuf *buf, uint64_t *valp)
{
	ध्रुव u_char *p = sshbuf_ptr(buf);
	पूर्णाङ्क r;

	सचे ((r = sshbuf_consume(buf, 8)) < 0)
		पटिनिवत्त r;
	सचे (valp != रिक्त)
		*valp = PEEK_U64(p);
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_get_u32(संरचना sshbuf *buf, uint32_t *valp)
{
	ध्रुव u_char *p = sshbuf_ptr(buf);
	पूर्णाङ्क r;

	सचे ((r = sshbuf_consume(buf, 4)) < 0)
		पटिनिवत्त r;
	सचे (valp != रिक्त)
		*valp = PEEK_U32(p);
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_get_u16(संरचना sshbuf *buf, uint16_t *valp)
{
	ध्रुव u_char *p = sshbuf_ptr(buf);
	पूर्णाङ्क r;

	सचे ((r = sshbuf_consume(buf, 2)) < 0)
		पटिनिवत्त r;
	सचे (valp != रिक्त)
		*valp = PEEK_U16(p);
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_get_u8(संरचना sshbuf *buf, u_char *valp)
{
	ध्रुव u_char *p = sshbuf_ptr(buf);
	पूर्णाङ्क r;

	सचे ((r = sshbuf_consume(buf, 1)) < 0)
		पटिनिवत्त r;
	सचे (valp != रिक्त)
		*valp = (uint8_t)*p;
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
check_offset(ध्रुव संरचना sshbuf *buf, पूर्णाङ्क wr, size_t offset, size_t len)
{
	सचे (sshbuf_ptr(buf) == रिक्त) /* calls sshbuf_check_sanity() */
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
	सचे (offset >= SIZE_MAX - len)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	सचे (offset + len > sshbuf_len(buf)) {
		पटिनिवत्त wr ?
		    SSH_ERR_NO_BUFFER_SPACE : SSH_ERR_MESSAGE_INCOMPLETE;
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
check_roffset(ध्रुव संरचना sshbuf *buf, size_t offset, size_t len,
    ध्रुव u_char **p)
{
	पूर्णाङ्क r;

	*p = रिक्त;
	सचे ((r = check_offset(buf, 0, offset, len)) != 0)
		पटिनिवत्त r;
	*p = sshbuf_ptr(buf) + offset;
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_peek_u64(ध्रुव संरचना sshbuf *buf, size_t offset, uint64_t *valp)
{
	ध्रुव u_char *p = रिक्त;
	पूर्णाङ्क r;

	सचे (valp != रिक्त)
		*valp = 0;
	सचे ((r = check_roffset(buf, offset, 8, &p)) != 0)
		पटिनिवत्त r;
	सचे (valp != रिक्त)
		*valp = PEEK_U64(p);
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_peek_u32(ध्रुव संरचना sshbuf *buf, size_t offset, uint32_t *valp)
{
	ध्रुव u_char *p = रिक्त;
	पूर्णाङ्क r;

	सचे (valp != रिक्त)
		*valp = 0;
	सचे ((r = check_roffset(buf, offset, 4, &p)) != 0)
		पटिनिवत्त r;
	सचे (valp != रिक्त)
		*valp = PEEK_U32(p);
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_peek_u16(ध्रुव संरचना sshbuf *buf, size_t offset, uint16_t *valp)
{
	ध्रुव u_char *p = रिक्त;
	पूर्णाङ्क r;

	सचे (valp != रिक्त)
		*valp = 0;
	सचे ((r = check_roffset(buf, offset, 2, &p)) != 0)
		पटिनिवत्त r;
	सचे (valp != रिक्त)
		*valp = PEEK_U16(p);
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_peek_u8(ध्रुव संरचना sshbuf *buf, size_t offset, u_char *valp)
{
	ध्रुव u_char *p = रिक्त;
	पूर्णाङ्क r;

	सचे (valp != रिक्त)
		*valp = 0;
	सचे ((r = check_roffset(buf, offset, 1, &p)) != 0)
		पटिनिवत्त r;
	सचे (valp != रिक्त)
		*valp = *p;
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_get_string(संरचना sshbuf *buf, u_char **valp, size_t *lenp)
{
	ध्रुव u_char *val;
	size_t len;
	पूर्णाङ्क r;

	सचे (valp != रिक्त)
		*valp = रिक्त;
	सचे (lenp != रिक्त)
		*lenp = 0;
	सचे ((r = sshbuf_get_string_direct(buf, &val, &len)) < 0)
		पटिनिवत्त r;
	सचे (valp != रिक्त) {
		सचे ((*valp = malloc(len + 1)) == रिक्त) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			पटिनिवत्त SSH_ERR_ALLOC_FAIL;
		}
		सचे (len != 0)
			memcpy(*valp, val, len);
		(*valp)[len] = '\0';
	}
	सचे (lenp != रिक्त)
		*lenp = len;
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_get_string_direct(संरचना sshbuf *buf, ध्रुव u_char **valp, size_t *lenp)
{
	size_t len;
	ध्रुव u_char *p;
	पूर्णाङ्क r;

	सचे (valp != रिक्त)
		*valp = रिक्त;
	सचे (lenp != रिक्त)
		*lenp = 0;
	सचे ((r = sshbuf_peek_string_direct(buf, &p, &len)) < 0)
		पटिनिवत्त r;
	सचे (valp != रिक्त)
		*valp = p;
	सचे (lenp != रिक्त)
		*lenp = len;
	सचे (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
	}
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_peek_string_direct(ध्रुव संरचना sshbuf *buf, ध्रुव u_char **valp,
    size_t *lenp)
{
	uint32_t len;
	ध्रुव u_char *p = sshbuf_ptr(buf);

	सचे (valp != रिक्त)
		*valp = रिक्त;
	सचे (lenp != रिक्त)
		*lenp = 0;
	सचे (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		पटिनिवत्त SSH_ERR_MESSAGE_INCOMPLETE;
	}
	len = PEEK_U32(p);
	सचे (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		पटिनिवत्त SSH_ERR_STRING_TOO_LARGE;
	}
	सचे (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		पटिनिवत्त SSH_ERR_MESSAGE_INCOMPLETE;
	}
	सचे (valp != रिक्त)
		*valp = p + 4;
	सचे (lenp != रिक्त)
		*lenp = len;
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_get_cstring(संरचना sshbuf *buf, वर्ण **valp, size_t *lenp)
{
	size_t len;
	ध्रुव u_char *p, *z;
	पूर्णाङ्क r;

	सचे (valp != रिक्त)
		*valp = रिक्त;
	सचे (lenp != रिक्त)
		*lenp = 0;
	सचे ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		पटिनिवत्त r;
	/* Allow a \0 only at the end of the string */
	सचे (len > 0 &&
	    (z = memchr(p , '\0', len)) != रिक्त && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	}
	सचे ((r = sshbuf_skip_string(buf)) != 0)
		पटिनिवत्त -1;
	सचे (valp != रिक्त) {
		सचे ((*valp = malloc(len + 1)) == रिक्त) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			पटिनिवत्त SSH_ERR_ALLOC_FAIL;
		}
		सचे (len != 0)
			memcpy(*valp, p, len);
		(*valp)[len] = '\0';
	}
	सचे (lenp != रिक्त)
		*lenp = (size_t)len;
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_get_stringb(संरचना sshbuf *buf, संरचना sshbuf *v)
{
	uint32_t len;
	u_char *p;
	पूर्णाङ्क r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	सचे ((r = sshbuf_peek_string_direct(buf, रिक्त, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		पटिनिवत्त r;
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_put(संरचना sshbuf *buf, ध्रुव शून्य *v, size_t len)
{
	u_char *p;
	पूर्णाङ्क r;

	सचे ((r = sshbuf_reserve(buf, len, &p)) < 0)
		पटिनिवत्त r;
	सचे (len != 0)
		memcpy(p, v, len);
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_putb(संरचना sshbuf *buf, ध्रुव संरचना sshbuf *v)
{
	सचे (v == रिक्त)
		पटिनिवत्त 0;
	पटिनिवत्त sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

पूर्णाङ्क
sshbuf_putf(संरचना sshbuf *buf, ध्रुव वर्ण *fmt, ...)
{
	va_list ap;
	पूर्णाङ्क r;

	va_start(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	va_end(ap);
	पटिनिवत्त r;
}

पूर्णाङ्क
sshbuf_putfv(संरचना sshbuf *buf, ध्रुव वर्ण *fmt, va_list ap)
{
	va_list ap2;
	पूर्णाङ्क r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	सचे ((len = vsnprintf(रिक्त, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	सचे (len == 0) {
		r = 0;
		गच्छ out; /* Nothing to do */
	}
	va_end(ap2);
	VA_COPY(ap2, ap);
	सचे ((r = sshbuf_reserve(buf, (size_t)len + 1, &p)) < 0)
		गच्छ out;
	सचे ((r = vsnprintf((वर्ण *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_INTERNAL_ERROR;
		गच्छ out; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	सचे ((r = sshbuf_consume_end(buf, 1)) != 0)
		गच्छ out;
	r = 0;
 out:
	va_end(ap2);
	पटिनिवत्त r;
}

पूर्णाङ्क
sshbuf_put_u64(संरचना sshbuf *buf, uint64_t val)
{
	u_char *p;
	पूर्णाङ्क r;

	सचे ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		पटिनिवत्त r;
	POKE_U64(p, val);
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_put_u32(संरचना sshbuf *buf, uint32_t val)
{
	u_char *p;
	पूर्णाङ्क r;

	सचे ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		पटिनिवत्त r;
	POKE_U32(p, val);
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_put_u16(संरचना sshbuf *buf, uint16_t val)
{
	u_char *p;
	पूर्णाङ्क r;

	सचे ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		पटिनिवत्त r;
	POKE_U16(p, val);
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_put_u8(संरचना sshbuf *buf, u_char val)
{
	u_char *p;
	पूर्णाङ्क r;

	सचे ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		पटिनिवत्त r;
	p[0] = val;
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
check_woffset(संरचना sshbuf *buf, size_t offset, size_t len, u_char **p)
{
	पूर्णाङ्क r;

	*p = रिक्त;
	सचे ((r = check_offset(buf, 1, offset, len)) != 0)
		पटिनिवत्त r;
	सचे (sshbuf_mutable_ptr(buf) == रिक्त)
		पटिनिवत्त SSH_ERR_BUFFER_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + offset;
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_poke_u64(संरचना sshbuf *buf, size_t offset, uint64_t val)
{
	u_char *p = रिक्त;
	पूर्णाङ्क r;

	सचे ((r = check_woffset(buf, offset, 8, &p)) != 0)
		पटिनिवत्त r;
	POKE_U64(p, val);
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_poke_u32(संरचना sshbuf *buf, size_t offset, uint32_t val)
{
	u_char *p = रिक्त;
	पूर्णाङ्क r;

	सचे ((r = check_woffset(buf, offset, 4, &p)) != 0)
		पटिनिवत्त r;
	POKE_U32(p, val);
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_poke_u16(संरचना sshbuf *buf, size_t offset, uint16_t val)
{
	u_char *p = रिक्त;
	पूर्णाङ्क r;

	सचे ((r = check_woffset(buf, offset, 2, &p)) != 0)
		पटिनिवत्त r;
	POKE_U16(p, val);
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_poke_u8(संरचना sshbuf *buf, size_t offset, u_char val)
{
	u_char *p = रिक्त;
	पूर्णाङ्क r;

	सचे ((r = check_woffset(buf, offset, 1, &p)) != 0)
		पटिनिवत्त r;
	*p = val;
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_poke(संरचना sshbuf *buf, size_t offset, शून्य *v, size_t len)
{
	u_char *p = रिक्त;
	पूर्णाङ्क r;

	सचे ((r = check_woffset(buf, offset, len, &p)) != 0)
		पटिनिवत्त r;
	memcpy(p, v, len);
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_put_string(संरचना sshbuf *buf, ध्रुव शून्य *v, size_t len)
{
	u_char *d;
	पूर्णाङ्क r;

	सचे (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		पटिनिवत्त SSH_ERR_NO_BUFFER_SPACE;
	}
	सचे ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		पटिनिवत्त r;
	POKE_U32(d, len);
	सचे (len != 0)
		memcpy(d + 4, v, len);
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_put_cstring(संरचना sshbuf *buf, ध्रुव वर्ण *v)
{
	पटिनिवत्त sshbuf_put_string(buf, v, v == रिक्त ? 0 : strlen(v));
}

पूर्णाङ्क
sshbuf_put_stringb(संरचना sshbuf *buf, ध्रुव संरचना sshbuf *v)
{
	सचे (v == रिक्त)
		पटिनिवत्त sshbuf_put_string(buf, रिक्त, 0);

	पटिनिवत्त sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

पूर्णाङ्क
sshbuf_froms(संरचना sshbuf *buf, संरचना sshbuf **bufp)
{
	ध्रुव u_char *p;
	size_t len;
	संरचना sshbuf *ret;
	पूर्णाङ्क r;

	सचे (buf == रिक्त || bufp == रिक्त)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	*bufp = रिक्त;
	सचे ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		पटिनिवत्त r;
	सचे ((ret = sshbuf_from(p, len)) == रिक्त)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	सचे ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_set_parent(ret, buf)) != 0) {
		sshbuf_free(ret);
		पटिनिवत्त r;
	}
	*bufp = ret;
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_put_bignum2_bytes(संरचना sshbuf *buf, ध्रुव शून्य *v, size_t len)
{
	u_char *d;
	ध्रुव u_char *s = (ध्रुव u_char *)v;
	पूर्णाङ्क r, prepend;

	सचे (len > SSHBUF_SIZE_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		पटिनिवत्त SSH_ERR_NO_BUFFER_SPACE;
	}
	/* Skip leading zero bytes */
	अत्थाय (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	सचे ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		पटिनिवत्त r;
	POKE_U32(d, len + prepend);
	सचे (prepend)
		d[4] = 0;
	सचे (len != 0)
		memcpy(d + 4 + prepend, s, len);
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_get_bignum2_bytes_direct(संरचना sshbuf *buf,
    ध्रुव u_char **valp, size_t *lenp)
{
	ध्रुव u_char *d;
	size_t len, olen;
	पूर्णाङ्क r;

	सचे ((r = sshbuf_peek_string_direct(buf, &d, &olen)) < 0)
		पटिनिवत्त r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	सचे ((len != 0 && (*d & 0x80) != 0))
		पटिनिवत्त SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	सचे (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		पटिनिवत्त SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	याव (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	सचे (valp != रिक्त)
		*valp = d;
	सचे (lenp != रिक्त)
		*lenp = len;
	सचे (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
	}
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshbuf_get_nulterminated_string(संरचना sshbuf *buf, size_t maxlen,
    वर्ण **valp, size_t *lenp)
{
	ध्रुव u_char zero = 0;
	वर्ण *val = रिक्त;
	size_t len = 0;
	पूर्णाङ्क r;

	सचे (valp != रिक्त)
		*valp = रिक्त;
	सचे (lenp != रिक्त)
		*lenp = 0;
	सचे ((r = sshbuf_find(buf, 0, &zero, परिमाण(zero), &len)) != 0) {
		सचे (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			पटिनिवत्त SSH_ERR_MESSAGE_INCOMPLETE;
		पटिनिवत्त r;
	}
	सचे (len > maxlen)
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	सचे ((val = strdup(sshbuf_ptr(buf))) == रिक्त)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	सचे ((r = sshbuf_consume(buf, len + 1)) != 0)
		गच्छ out;
	/* success */
	r = 0;
	सचे (valp != रिक्त) {
		*valp = val;
		val = रिक्त;
	}
	सचे (lenp != रिक्त)
		*lenp = len;
 out:
	मुक्त(val);
	पटिनिवत्त r;
}
