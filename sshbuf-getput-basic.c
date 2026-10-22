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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <stdarg.h>
#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <stdint.h>

#ضمن "ssherr.h"
#define SSHBUF_INTERNAL
#ضمن "sshbuf.h"

صحيح
sshbuf_get(بنية sshbuf *buf, فراغ *v, size_t len)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحيح r;

	إذا ((r = sshbuf_consume(buf, len)) < 0)
		إرجاع r;
	إذا (v != عدم && len != 0)
		memcpy(v, p, len);
	إرجاع 0;
}

صحيح
sshbuf_get_u64(بنية sshbuf *buf, uint64_t *valp)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحيح r;

	إذا ((r = sshbuf_consume(buf, 8)) < 0)
		إرجاع r;
	إذا (valp != عدم)
		*valp = PEEK_U64(p);
	إرجاع 0;
}

صحيح
sshbuf_get_u32(بنية sshbuf *buf, uint32_t *valp)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحيح r;

	إذا ((r = sshbuf_consume(buf, 4)) < 0)
		إرجاع r;
	إذا (valp != عدم)
		*valp = PEEK_U32(p);
	إرجاع 0;
}

صحيح
sshbuf_get_u16(بنية sshbuf *buf, uint16_t *valp)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحيح r;

	إذا ((r = sshbuf_consume(buf, 2)) < 0)
		إرجاع r;
	إذا (valp != عدم)
		*valp = PEEK_U16(p);
	إرجاع 0;
}

صحيح
sshbuf_get_u8(بنية sshbuf *buf, u_char *valp)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحيح r;

	إذا ((r = sshbuf_consume(buf, 1)) < 0)
		إرجاع r;
	إذا (valp != عدم)
		*valp = (uint8_t)*p;
	إرجاع 0;
}

ساكن صحيح
check_offset(ثابت بنية sshbuf *buf, صحيح wr, size_t offset, size_t len)
{
	إذا (sshbuf_ptr(buf) == عدم) /* calls sshbuf_check_sanity() */
		إرجاع SSH_ERR_INTERNAL_ERROR;
	إذا (offset >= SIZE_MAX - len)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	إذا (offset + len > sshbuf_len(buf)) {
		إرجاع wr ?
		    SSH_ERR_NO_BUFFER_SPACE : SSH_ERR_MESSAGE_INCOMPLETE;
	}
	إرجاع 0;
}

ساكن صحيح
check_roffset(ثابت بنية sshbuf *buf, size_t offset, size_t len,
    ثابت u_char **p)
{
	صحيح r;

	*p = عدم;
	إذا ((r = check_offset(buf, 0, offset, len)) != 0)
		إرجاع r;
	*p = sshbuf_ptr(buf) + offset;
	إرجاع 0;
}

صحيح
sshbuf_peek_u64(ثابت بنية sshbuf *buf, size_t offset, uint64_t *valp)
{
	ثابت u_char *p = عدم;
	صحيح r;

	إذا (valp != عدم)
		*valp = 0;
	إذا ((r = check_roffset(buf, offset, 8, &p)) != 0)
		إرجاع r;
	إذا (valp != عدم)
		*valp = PEEK_U64(p);
	إرجاع 0;
}

صحيح
sshbuf_peek_u32(ثابت بنية sshbuf *buf, size_t offset, uint32_t *valp)
{
	ثابت u_char *p = عدم;
	صحيح r;

	إذا (valp != عدم)
		*valp = 0;
	إذا ((r = check_roffset(buf, offset, 4, &p)) != 0)
		إرجاع r;
	إذا (valp != عدم)
		*valp = PEEK_U32(p);
	إرجاع 0;
}

صحيح
sshbuf_peek_u16(ثابت بنية sshbuf *buf, size_t offset, uint16_t *valp)
{
	ثابت u_char *p = عدم;
	صحيح r;

	إذا (valp != عدم)
		*valp = 0;
	إذا ((r = check_roffset(buf, offset, 2, &p)) != 0)
		إرجاع r;
	إذا (valp != عدم)
		*valp = PEEK_U16(p);
	إرجاع 0;
}

صحيح
sshbuf_peek_u8(ثابت بنية sshbuf *buf, size_t offset, u_char *valp)
{
	ثابت u_char *p = عدم;
	صحيح r;

	إذا (valp != عدم)
		*valp = 0;
	إذا ((r = check_roffset(buf, offset, 1, &p)) != 0)
		إرجاع r;
	إذا (valp != عدم)
		*valp = *p;
	إرجاع 0;
}

صحيح
sshbuf_get_string(بنية sshbuf *buf, u_char **valp, size_t *lenp)
{
	ثابت u_char *val;
	size_t len;
	صحيح r;

	إذا (valp != عدم)
		*valp = عدم;
	إذا (lenp != عدم)
		*lenp = 0;
	إذا ((r = sshbuf_get_string_direct(buf, &val, &len)) < 0)
		إرجاع r;
	إذا (valp != عدم) {
		إذا ((*valp = malloc(len + 1)) == عدم) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			إرجاع SSH_ERR_ALLOC_FAIL;
		}
		إذا (len != 0)
			memcpy(*valp, val, len);
		(*valp)[len] = '\0';
	}
	إذا (lenp != عدم)
		*lenp = len;
	إرجاع 0;
}

صحيح
sshbuf_get_string_direct(بنية sshbuf *buf, ثابت u_char **valp, size_t *lenp)
{
	size_t len;
	ثابت u_char *p;
	صحيح r;

	إذا (valp != عدم)
		*valp = عدم;
	إذا (lenp != عدم)
		*lenp = 0;
	إذا ((r = sshbuf_peek_string_direct(buf, &p, &len)) < 0)
		إرجاع r;
	إذا (valp != عدم)
		*valp = p;
	إذا (lenp != عدم)
		*lenp = len;
	إذا (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		إرجاع SSH_ERR_INTERNAL_ERROR;
	}
	إرجاع 0;
}

صحيح
sshbuf_peek_string_direct(ثابت بنية sshbuf *buf, ثابت u_char **valp,
    size_t *lenp)
{
	uint32_t len;
	ثابت u_char *p = sshbuf_ptr(buf);

	إذا (valp != عدم)
		*valp = عدم;
	إذا (lenp != عدم)
		*lenp = 0;
	إذا (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		إرجاع SSH_ERR_MESSAGE_INCOMPLETE;
	}
	len = PEEK_U32(p);
	إذا (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		إرجاع SSH_ERR_STRING_TOO_LARGE;
	}
	إذا (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		إرجاع SSH_ERR_MESSAGE_INCOMPLETE;
	}
	إذا (valp != عدم)
		*valp = p + 4;
	إذا (lenp != عدم)
		*lenp = len;
	إرجاع 0;
}

صحيح
sshbuf_get_cstring(بنية sshbuf *buf, حرف **valp, size_t *lenp)
{
	size_t len;
	ثابت u_char *p, *z;
	صحيح r;

	إذا (valp != عدم)
		*valp = عدم;
	إذا (lenp != عدم)
		*lenp = 0;
	إذا ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		إرجاع r;
	/* Allow a \0 only at the end of the string */
	إذا (len > 0 &&
	    (z = memchr(p , '\0', len)) != عدم && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		إرجاع SSH_ERR_INVALID_FORMAT;
	}
	إذا ((r = sshbuf_skip_string(buf)) != 0)
		إرجاع -1;
	إذا (valp != عدم) {
		إذا ((*valp = malloc(len + 1)) == عدم) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			إرجاع SSH_ERR_ALLOC_FAIL;
		}
		إذا (len != 0)
			memcpy(*valp, p, len);
		(*valp)[len] = '\0';
	}
	إذا (lenp != عدم)
		*lenp = (size_t)len;
	إرجاع 0;
}

صحيح
sshbuf_get_stringb(بنية sshbuf *buf, بنية sshbuf *v)
{
	uint32_t len;
	u_char *p;
	صحيح r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	إذا ((r = sshbuf_peek_string_direct(buf, عدم, عدم)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		إرجاع r;
	إرجاع 0;
}

صحيح
sshbuf_put(بنية sshbuf *buf, ثابت فراغ *v, size_t len)
{
	u_char *p;
	صحيح r;

	إذا ((r = sshbuf_reserve(buf, len, &p)) < 0)
		إرجاع r;
	إذا (len != 0)
		memcpy(p, v, len);
	إرجاع 0;
}

صحيح
sshbuf_putb(بنية sshbuf *buf, ثابت بنية sshbuf *v)
{
	إذا (v == عدم)
		إرجاع 0;
	إرجاع sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

صحيح
sshbuf_putf(بنية sshbuf *buf, ثابت حرف *fmt, ...)
{
	va_list ap;
	صحيح r;

	va_start(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	va_end(ap);
	إرجاع r;
}

صحيح
sshbuf_putfv(بنية sshbuf *buf, ثابت حرف *fmt, va_list ap)
{
	va_list ap2;
	صحيح r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	إذا ((len = vsnprintf(عدم, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	إذا (len == 0) {
		r = 0;
		اذهب out; /* Nothing to do */
	}
	va_end(ap2);
	VA_COPY(ap2, ap);
	إذا ((r = sshbuf_reserve(buf, (size_t)len + 1, &p)) < 0)
		اذهب out;
	إذا ((r = vsnprintf((حرف *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_INTERNAL_ERROR;
		اذهب out; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	إذا ((r = sshbuf_consume_end(buf, 1)) != 0)
		اذهب out;
	r = 0;
 out:
	va_end(ap2);
	إرجاع r;
}

صحيح
sshbuf_put_u64(بنية sshbuf *buf, uint64_t val)
{
	u_char *p;
	صحيح r;

	إذا ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		إرجاع r;
	POKE_U64(p, val);
	إرجاع 0;
}

صحيح
sshbuf_put_u32(بنية sshbuf *buf, uint32_t val)
{
	u_char *p;
	صحيح r;

	إذا ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		إرجاع r;
	POKE_U32(p, val);
	إرجاع 0;
}

صحيح
sshbuf_put_u16(بنية sshbuf *buf, uint16_t val)
{
	u_char *p;
	صحيح r;

	إذا ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		إرجاع r;
	POKE_U16(p, val);
	إرجاع 0;
}

صحيح
sshbuf_put_u8(بنية sshbuf *buf, u_char val)
{
	u_char *p;
	صحيح r;

	إذا ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		إرجاع r;
	p[0] = val;
	إرجاع 0;
}

ساكن صحيح
check_woffset(بنية sshbuf *buf, size_t offset, size_t len, u_char **p)
{
	صحيح r;

	*p = عدم;
	إذا ((r = check_offset(buf, 1, offset, len)) != 0)
		إرجاع r;
	إذا (sshbuf_mutable_ptr(buf) == عدم)
		إرجاع SSH_ERR_BUFFER_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + offset;
	إرجاع 0;
}

صحيح
sshbuf_poke_u64(بنية sshbuf *buf, size_t offset, uint64_t val)
{
	u_char *p = عدم;
	صحيح r;

	إذا ((r = check_woffset(buf, offset, 8, &p)) != 0)
		إرجاع r;
	POKE_U64(p, val);
	إرجاع 0;
}

صحيح
sshbuf_poke_u32(بنية sshbuf *buf, size_t offset, uint32_t val)
{
	u_char *p = عدم;
	صحيح r;

	إذا ((r = check_woffset(buf, offset, 4, &p)) != 0)
		إرجاع r;
	POKE_U32(p, val);
	إرجاع 0;
}

صحيح
sshbuf_poke_u16(بنية sshbuf *buf, size_t offset, uint16_t val)
{
	u_char *p = عدم;
	صحيح r;

	إذا ((r = check_woffset(buf, offset, 2, &p)) != 0)
		إرجاع r;
	POKE_U16(p, val);
	إرجاع 0;
}

صحيح
sshbuf_poke_u8(بنية sshbuf *buf, size_t offset, u_char val)
{
	u_char *p = عدم;
	صحيح r;

	إذا ((r = check_woffset(buf, offset, 1, &p)) != 0)
		إرجاع r;
	*p = val;
	إرجاع 0;
}

صحيح
sshbuf_poke(بنية sshbuf *buf, size_t offset, فراغ *v, size_t len)
{
	u_char *p = عدم;
	صحيح r;

	إذا ((r = check_woffset(buf, offset, len, &p)) != 0)
		إرجاع r;
	memcpy(p, v, len);
	إرجاع 0;
}

صحيح
sshbuf_put_string(بنية sshbuf *buf, ثابت فراغ *v, size_t len)
{
	u_char *d;
	صحيح r;

	إذا (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		إرجاع SSH_ERR_NO_BUFFER_SPACE;
	}
	إذا ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		إرجاع r;
	POKE_U32(d, len);
	إذا (len != 0)
		memcpy(d + 4, v, len);
	إرجاع 0;
}

صحيح
sshbuf_put_cstring(بنية sshbuf *buf, ثابت حرف *v)
{
	إرجاع sshbuf_put_string(buf, v, v == عدم ? 0 : strlen(v));
}

صحيح
sshbuf_put_stringb(بنية sshbuf *buf, ثابت بنية sshbuf *v)
{
	إذا (v == عدم)
		إرجاع sshbuf_put_string(buf, عدم, 0);

	إرجاع sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

صحيح
sshbuf_froms(بنية sshbuf *buf, بنية sshbuf **bufp)
{
	ثابت u_char *p;
	size_t len;
	بنية sshbuf *ret;
	صحيح r;

	إذا (buf == عدم || bufp == عدم)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	*bufp = عدم;
	إذا ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		إرجاع r;
	إذا ((ret = sshbuf_from(p, len)) == عدم)
		إرجاع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_set_parent(ret, buf)) != 0) {
		sshbuf_free(ret);
		إرجاع r;
	}
	*bufp = ret;
	إرجاع 0;
}

صحيح
sshbuf_put_bignum2_bytes(بنية sshbuf *buf, ثابت فراغ *v, size_t len)
{
	u_char *d;
	ثابت u_char *s = (ثابت u_char *)v;
	صحيح r, prepend;

	إذا (len > SSHBUF_SIZE_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		إرجاع SSH_ERR_NO_BUFFER_SPACE;
	}
	/* Skip leading zero bytes */
	لكل (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	إذا ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		إرجاع r;
	POKE_U32(d, len + prepend);
	إذا (prepend)
		d[4] = 0;
	إذا (len != 0)
		memcpy(d + 4 + prepend, s, len);
	إرجاع 0;
}

صحيح
sshbuf_get_bignum2_bytes_direct(بنية sshbuf *buf,
    ثابت u_char **valp, size_t *lenp)
{
	ثابت u_char *d;
	size_t len, olen;
	صحيح r;

	إذا ((r = sshbuf_peek_string_direct(buf, &d, &olen)) < 0)
		إرجاع r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	إذا ((len != 0 && (*d & 0x80) != 0))
		إرجاع SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	إذا (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		إرجاع SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	بينما (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	إذا (valp != عدم)
		*valp = d;
	إذا (lenp != عدم)
		*lenp = len;
	إذا (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		إرجاع SSH_ERR_INTERNAL_ERROR;
	}
	إرجاع 0;
}

صحيح
sshbuf_get_nulterminated_string(بنية sshbuf *buf, size_t maxlen,
    حرف **valp, size_t *lenp)
{
	ثابت u_char zero = 0;
	حرف *val = عدم;
	size_t len = 0;
	صحيح r;

	إذا (valp != عدم)
		*valp = عدم;
	إذا (lenp != عدم)
		*lenp = 0;
	إذا ((r = sshbuf_find(buf, 0, &zero, حجم(zero), &len)) != 0) {
		إذا (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			إرجاع SSH_ERR_MESSAGE_INCOMPLETE;
		إرجاع r;
	}
	إذا (len > maxlen)
		إرجاع SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	إذا ((val = strdup(sshbuf_ptr(buf))) == عدم)
		إرجاع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_consume(buf, len + 1)) != 0)
		اذهب out;
	/* success */
	r = 0;
	إذا (valp != عدم) {
		*valp = val;
		val = عدم;
	}
	إذا (lenp != عدم)
		*lenp = len;
 out:
	حرر(val);
	إرجاع r;
}
