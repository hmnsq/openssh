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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <stdarg.h>
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <stdint.h>

#شامل "ssherr.h"
#define SSHBUF_INTERNAL
#شامل "sshbuf.h"

صحیح
sshbuf_get(ساختار sshbuf *buf, تهی *v, size_t len)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحیح r;

	اگر ((r = sshbuf_consume(buf, len)) < 0)
		بازگشت r;
	اگر (v != پوچ && len != 0)
		memcpy(v, p, len);
	بازگشت 0;
}

صحیح
sshbuf_get_u64(ساختار sshbuf *buf, uint64_t *valp)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحیح r;

	اگر ((r = sshbuf_consume(buf, 8)) < 0)
		بازگشت r;
	اگر (valp != پوچ)
		*valp = PEEK_U64(p);
	بازگشت 0;
}

صحیح
sshbuf_get_u32(ساختار sshbuf *buf, uint32_t *valp)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحیح r;

	اگر ((r = sshbuf_consume(buf, 4)) < 0)
		بازگشت r;
	اگر (valp != پوچ)
		*valp = PEEK_U32(p);
	بازگشت 0;
}

صحیح
sshbuf_get_u16(ساختار sshbuf *buf, uint16_t *valp)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحیح r;

	اگر ((r = sshbuf_consume(buf, 2)) < 0)
		بازگشت r;
	اگر (valp != پوچ)
		*valp = PEEK_U16(p);
	بازگشت 0;
}

صحیح
sshbuf_get_u8(ساختار sshbuf *buf, u_char *valp)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحیح r;

	اگر ((r = sshbuf_consume(buf, 1)) < 0)
		بازگشت r;
	اگر (valp != پوچ)
		*valp = (uint8_t)*p;
	بازگشت 0;
}

ایستا صحیح
check_offset(ثابت ساختار sshbuf *buf, صحیح wr, size_t offset, size_t len)
{
	اگر (sshbuf_ptr(buf) == پوچ) /* calls sshbuf_check_sanity() */
		بازگشت SSH_ERR_INTERNAL_ERROR;
	اگر (offset >= SIZE_MAX - len)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر (offset + len > sshbuf_len(buf)) {
		بازگشت wr ?
		    SSH_ERR_NO_BUFFER_SPACE : SSH_ERR_MESSAGE_INCOMPLETE;
	}
	بازگشت 0;
}

ایستا صحیح
check_roffset(ثابت ساختار sshbuf *buf, size_t offset, size_t len,
    ثابت u_char **p)
{
	صحیح r;

	*p = پوچ;
	اگر ((r = check_offset(buf, 0, offset, len)) != 0)
		بازگشت r;
	*p = sshbuf_ptr(buf) + offset;
	بازگشت 0;
}

صحیح
sshbuf_peek_u64(ثابت ساختار sshbuf *buf, size_t offset, uint64_t *valp)
{
	ثابت u_char *p = پوچ;
	صحیح r;

	اگر (valp != پوچ)
		*valp = 0;
	اگر ((r = check_roffset(buf, offset, 8, &p)) != 0)
		بازگشت r;
	اگر (valp != پوچ)
		*valp = PEEK_U64(p);
	بازگشت 0;
}

صحیح
sshbuf_peek_u32(ثابت ساختار sshbuf *buf, size_t offset, uint32_t *valp)
{
	ثابت u_char *p = پوچ;
	صحیح r;

	اگر (valp != پوچ)
		*valp = 0;
	اگر ((r = check_roffset(buf, offset, 4, &p)) != 0)
		بازگشت r;
	اگر (valp != پوچ)
		*valp = PEEK_U32(p);
	بازگشت 0;
}

صحیح
sshbuf_peek_u16(ثابت ساختار sshbuf *buf, size_t offset, uint16_t *valp)
{
	ثابت u_char *p = پوچ;
	صحیح r;

	اگر (valp != پوچ)
		*valp = 0;
	اگر ((r = check_roffset(buf, offset, 2, &p)) != 0)
		بازگشت r;
	اگر (valp != پوچ)
		*valp = PEEK_U16(p);
	بازگشت 0;
}

صحیح
sshbuf_peek_u8(ثابت ساختار sshbuf *buf, size_t offset, u_char *valp)
{
	ثابت u_char *p = پوچ;
	صحیح r;

	اگر (valp != پوچ)
		*valp = 0;
	اگر ((r = check_roffset(buf, offset, 1, &p)) != 0)
		بازگشت r;
	اگر (valp != پوچ)
		*valp = *p;
	بازگشت 0;
}

صحیح
sshbuf_get_string(ساختار sshbuf *buf, u_char **valp, size_t *lenp)
{
	ثابت u_char *val;
	size_t len;
	صحیح r;

	اگر (valp != پوچ)
		*valp = پوچ;
	اگر (lenp != پوچ)
		*lenp = 0;
	اگر ((r = sshbuf_get_string_direct(buf, &val, &len)) < 0)
		بازگشت r;
	اگر (valp != پوچ) {
		اگر ((*valp = malloc(len + 1)) == پوچ) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			بازگشت SSH_ERR_ALLOC_FAIL;
		}
		اگر (len != 0)
			memcpy(*valp, val, len);
		(*valp)[len] = '\0';
	}
	اگر (lenp != پوچ)
		*lenp = len;
	بازگشت 0;
}

صحیح
sshbuf_get_string_direct(ساختار sshbuf *buf, ثابت u_char **valp, size_t *lenp)
{
	size_t len;
	ثابت u_char *p;
	صحیح r;

	اگر (valp != پوچ)
		*valp = پوچ;
	اگر (lenp != پوچ)
		*lenp = 0;
	اگر ((r = sshbuf_peek_string_direct(buf, &p, &len)) < 0)
		بازگشت r;
	اگر (valp != پوچ)
		*valp = p;
	اگر (lenp != پوچ)
		*lenp = len;
	اگر (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	بازگشت 0;
}

صحیح
sshbuf_peek_string_direct(ثابت ساختار sshbuf *buf, ثابت u_char **valp,
    size_t *lenp)
{
	uint32_t len;
	ثابت u_char *p = sshbuf_ptr(buf);

	اگر (valp != پوچ)
		*valp = پوچ;
	اگر (lenp != پوچ)
		*lenp = 0;
	اگر (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		بازگشت SSH_ERR_MESSAGE_INCOMPLETE;
	}
	len = PEEK_U32(p);
	اگر (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		بازگشت SSH_ERR_STRING_TOO_LARGE;
	}
	اگر (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		بازگشت SSH_ERR_MESSAGE_INCOMPLETE;
	}
	اگر (valp != پوچ)
		*valp = p + 4;
	اگر (lenp != پوچ)
		*lenp = len;
	بازگشت 0;
}

صحیح
sshbuf_get_cstring(ساختار sshbuf *buf, نویسه **valp, size_t *lenp)
{
	size_t len;
	ثابت u_char *p, *z;
	صحیح r;

	اگر (valp != پوچ)
		*valp = پوچ;
	اگر (lenp != پوچ)
		*lenp = 0;
	اگر ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		بازگشت r;
	/* Allow a \0 only at the end of the string */
	اگر (len > 0 &&
	    (z = memchr(p , '\0', len)) != پوچ && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		بازگشت SSH_ERR_INVALID_FORMAT;
	}
	اگر ((r = sshbuf_skip_string(buf)) != 0)
		بازگشت -1;
	اگر (valp != پوچ) {
		اگر ((*valp = malloc(len + 1)) == پوچ) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			بازگشت SSH_ERR_ALLOC_FAIL;
		}
		اگر (len != 0)
			memcpy(*valp, p, len);
		(*valp)[len] = '\0';
	}
	اگر (lenp != پوچ)
		*lenp = (size_t)len;
	بازگشت 0;
}

صحیح
sshbuf_get_stringb(ساختار sshbuf *buf, ساختار sshbuf *v)
{
	uint32_t len;
	u_char *p;
	صحیح r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	اگر ((r = sshbuf_peek_string_direct(buf, پوچ, پوچ)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		بازگشت r;
	بازگشت 0;
}

صحیح
sshbuf_put(ساختار sshbuf *buf, ثابت تهی *v, size_t len)
{
	u_char *p;
	صحیح r;

	اگر ((r = sshbuf_reserve(buf, len, &p)) < 0)
		بازگشت r;
	اگر (len != 0)
		memcpy(p, v, len);
	بازگشت 0;
}

صحیح
sshbuf_putb(ساختار sshbuf *buf, ثابت ساختار sshbuf *v)
{
	اگر (v == پوچ)
		بازگشت 0;
	بازگشت sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

صحیح
sshbuf_putf(ساختار sshbuf *buf, ثابت نویسه *fmt, ...)
{
	va_list ap;
	صحیح r;

	va_start(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	va_end(ap);
	بازگشت r;
}

صحیح
sshbuf_putfv(ساختار sshbuf *buf, ثابت نویسه *fmt, va_list ap)
{
	va_list ap2;
	صحیح r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	اگر ((len = vsnprintf(پوچ, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		برو out;
	}
	اگر (len == 0) {
		r = 0;
		برو out; /* Nothing to do */
	}
	va_end(ap2);
	VA_COPY(ap2, ap);
	اگر ((r = sshbuf_reserve(buf, (size_t)len + 1, &p)) < 0)
		برو out;
	اگر ((r = vsnprintf((نویسه *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_INTERNAL_ERROR;
		برو out; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	اگر ((r = sshbuf_consume_end(buf, 1)) != 0)
		برو out;
	r = 0;
 out:
	va_end(ap2);
	بازگشت r;
}

صحیح
sshbuf_put_u64(ساختار sshbuf *buf, uint64_t val)
{
	u_char *p;
	صحیح r;

	اگر ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		بازگشت r;
	POKE_U64(p, val);
	بازگشت 0;
}

صحیح
sshbuf_put_u32(ساختار sshbuf *buf, uint32_t val)
{
	u_char *p;
	صحیح r;

	اگر ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		بازگشت r;
	POKE_U32(p, val);
	بازگشت 0;
}

صحیح
sshbuf_put_u16(ساختار sshbuf *buf, uint16_t val)
{
	u_char *p;
	صحیح r;

	اگر ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		بازگشت r;
	POKE_U16(p, val);
	بازگشت 0;
}

صحیح
sshbuf_put_u8(ساختار sshbuf *buf, u_char val)
{
	u_char *p;
	صحیح r;

	اگر ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		بازگشت r;
	p[0] = val;
	بازگشت 0;
}

ایستا صحیح
check_woffset(ساختار sshbuf *buf, size_t offset, size_t len, u_char **p)
{
	صحیح r;

	*p = پوچ;
	اگر ((r = check_offset(buf, 1, offset, len)) != 0)
		بازگشت r;
	اگر (sshbuf_mutable_ptr(buf) == پوچ)
		بازگشت SSH_ERR_BUFFER_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + offset;
	بازگشت 0;
}

صحیح
sshbuf_poke_u64(ساختار sshbuf *buf, size_t offset, uint64_t val)
{
	u_char *p = پوچ;
	صحیح r;

	اگر ((r = check_woffset(buf, offset, 8, &p)) != 0)
		بازگشت r;
	POKE_U64(p, val);
	بازگشت 0;
}

صحیح
sshbuf_poke_u32(ساختار sshbuf *buf, size_t offset, uint32_t val)
{
	u_char *p = پوچ;
	صحیح r;

	اگر ((r = check_woffset(buf, offset, 4, &p)) != 0)
		بازگشت r;
	POKE_U32(p, val);
	بازگشت 0;
}

صحیح
sshbuf_poke_u16(ساختار sshbuf *buf, size_t offset, uint16_t val)
{
	u_char *p = پوچ;
	صحیح r;

	اگر ((r = check_woffset(buf, offset, 2, &p)) != 0)
		بازگشت r;
	POKE_U16(p, val);
	بازگشت 0;
}

صحیح
sshbuf_poke_u8(ساختار sshbuf *buf, size_t offset, u_char val)
{
	u_char *p = پوچ;
	صحیح r;

	اگر ((r = check_woffset(buf, offset, 1, &p)) != 0)
		بازگشت r;
	*p = val;
	بازگشت 0;
}

صحیح
sshbuf_poke(ساختار sshbuf *buf, size_t offset, تهی *v, size_t len)
{
	u_char *p = پوچ;
	صحیح r;

	اگر ((r = check_woffset(buf, offset, len, &p)) != 0)
		بازگشت r;
	memcpy(p, v, len);
	بازگشت 0;
}

صحیح
sshbuf_put_string(ساختار sshbuf *buf, ثابت تهی *v, size_t len)
{
	u_char *d;
	صحیح r;

	اگر (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		بازگشت SSH_ERR_NO_BUFFER_SPACE;
	}
	اگر ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		بازگشت r;
	POKE_U32(d, len);
	اگر (len != 0)
		memcpy(d + 4, v, len);
	بازگشت 0;
}

صحیح
sshbuf_put_cstring(ساختار sshbuf *buf, ثابت نویسه *v)
{
	بازگشت sshbuf_put_string(buf, v, v == پوچ ? 0 : strlen(v));
}

صحیح
sshbuf_put_stringb(ساختار sshbuf *buf, ثابت ساختار sshbuf *v)
{
	اگر (v == پوچ)
		بازگشت sshbuf_put_string(buf, پوچ, 0);

	بازگشت sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

صحیح
sshbuf_froms(ساختار sshbuf *buf, ساختار sshbuf **bufp)
{
	ثابت u_char *p;
	size_t len;
	ساختار sshbuf *ret;
	صحیح r;

	اگر (buf == پوچ || bufp == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	*bufp = پوچ;
	اگر ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		بازگشت r;
	اگر ((ret = sshbuf_from(p, len)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_set_parent(ret, buf)) != 0) {
		sshbuf_free(ret);
		بازگشت r;
	}
	*bufp = ret;
	بازگشت 0;
}

صحیح
sshbuf_put_bignum2_bytes(ساختار sshbuf *buf, ثابت تهی *v, size_t len)
{
	u_char *d;
	ثابت u_char *s = (ثابت u_char *)v;
	صحیح r, prepend;

	اگر (len > SSHBUF_SIZE_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		بازگشت SSH_ERR_NO_BUFFER_SPACE;
	}
	/* Skip leading zero bytes */
	برای (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	اگر ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		بازگشت r;
	POKE_U32(d, len + prepend);
	اگر (prepend)
		d[4] = 0;
	اگر (len != 0)
		memcpy(d + 4 + prepend, s, len);
	بازگشت 0;
}

صحیح
sshbuf_get_bignum2_bytes_direct(ساختار sshbuf *buf,
    ثابت u_char **valp, size_t *lenp)
{
	ثابت u_char *d;
	size_t len, olen;
	صحیح r;

	اگر ((r = sshbuf_peek_string_direct(buf, &d, &olen)) < 0)
		بازگشت r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	اگر ((len != 0 && (*d & 0x80) != 0))
		بازگشت SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	اگر (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		بازگشت SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	وقتی (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	اگر (valp != پوچ)
		*valp = d;
	اگر (lenp != پوچ)
		*lenp = len;
	اگر (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	بازگشت 0;
}

صحیح
sshbuf_get_nulterminated_string(ساختار sshbuf *buf, size_t maxlen,
    نویسه **valp, size_t *lenp)
{
	ثابت u_char zero = 0;
	نویسه *val = پوچ;
	size_t len = 0;
	صحیح r;

	اگر (valp != پوچ)
		*valp = پوچ;
	اگر (lenp != پوچ)
		*lenp = 0;
	اگر ((r = sshbuf_find(buf, 0, &zero, اندازه(zero), &len)) != 0) {
		اگر (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			بازگشت SSH_ERR_MESSAGE_INCOMPLETE;
		بازگشت r;
	}
	اگر (len > maxlen)
		بازگشت SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	اگر ((val = strdup(sshbuf_ptr(buf))) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_consume(buf, len + 1)) != 0)
		برو out;
	/* success */
	r = 0;
	اگر (valp != پوچ) {
		*valp = val;
		val = پوچ;
	}
	اگر (lenp != پوچ)
		*lenp = len;
 out:
	آزاد(val);
	بازگشت r;
}
