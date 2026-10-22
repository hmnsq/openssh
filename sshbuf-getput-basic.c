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

	ܐܢ ((r = sshbuf_consume(buf, len)) < 0)
		ܦܢܐ r;
	ܐܢ (v != عدم && len != 0)
		memcpy(v, p, len);
	ܦܢܐ 0;
}

صحيح
sshbuf_get_u64(بنية sshbuf *buf, uint64_t *valp)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحيح r;

	ܐܢ ((r = sshbuf_consume(buf, 8)) < 0)
		ܦܢܐ r;
	ܐܢ (valp != عدم)
		*valp = PEEK_U64(p);
	ܦܢܐ 0;
}

صحيح
sshbuf_get_u32(بنية sshbuf *buf, uint32_t *valp)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحيح r;

	ܐܢ ((r = sshbuf_consume(buf, 4)) < 0)
		ܦܢܐ r;
	ܐܢ (valp != عدم)
		*valp = PEEK_U32(p);
	ܦܢܐ 0;
}

صحيح
sshbuf_get_u16(بنية sshbuf *buf, uint16_t *valp)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحيح r;

	ܐܢ ((r = sshbuf_consume(buf, 2)) < 0)
		ܦܢܐ r;
	ܐܢ (valp != عدم)
		*valp = PEEK_U16(p);
	ܦܢܐ 0;
}

صحيح
sshbuf_get_u8(بنية sshbuf *buf, u_char *valp)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحيح r;

	ܐܢ ((r = sshbuf_consume(buf, 1)) < 0)
		ܦܢܐ r;
	ܐܢ (valp != عدم)
		*valp = (uint8_t)*p;
	ܦܢܐ 0;
}

ساكن صحيح
check_offset(ثابت بنية sshbuf *buf, صحيح wr, size_t offset, size_t len)
{
	ܐܢ (sshbuf_ptr(buf) == عدم) /* calls sshbuf_check_sanity() */
		ܦܢܐ SSH_ERR_INTERNAL_ERROR;
	ܐܢ (offset >= SIZE_MAX - len)
		ܦܢܐ SSH_ERR_INVALID_ARGUMENT;
	ܐܢ (offset + len > sshbuf_len(buf)) {
		ܦܢܐ wr ?
		    SSH_ERR_NO_BUFFER_SPACE : SSH_ERR_MESSAGE_INCOMPLETE;
	}
	ܦܢܐ 0;
}

ساكن صحيح
check_roffset(ثابت بنية sshbuf *buf, size_t offset, size_t len,
    ثابت u_char **p)
{
	صحيح r;

	*p = عدم;
	ܐܢ ((r = check_offset(buf, 0, offset, len)) != 0)
		ܦܢܐ r;
	*p = sshbuf_ptr(buf) + offset;
	ܦܢܐ 0;
}

صحيح
sshbuf_peek_u64(ثابت بنية sshbuf *buf, size_t offset, uint64_t *valp)
{
	ثابت u_char *p = عدم;
	صحيح r;

	ܐܢ (valp != عدم)
		*valp = 0;
	ܐܢ ((r = check_roffset(buf, offset, 8, &p)) != 0)
		ܦܢܐ r;
	ܐܢ (valp != عدم)
		*valp = PEEK_U64(p);
	ܦܢܐ 0;
}

صحيح
sshbuf_peek_u32(ثابت بنية sshbuf *buf, size_t offset, uint32_t *valp)
{
	ثابت u_char *p = عدم;
	صحيح r;

	ܐܢ (valp != عدم)
		*valp = 0;
	ܐܢ ((r = check_roffset(buf, offset, 4, &p)) != 0)
		ܦܢܐ r;
	ܐܢ (valp != عدم)
		*valp = PEEK_U32(p);
	ܦܢܐ 0;
}

صحيح
sshbuf_peek_u16(ثابت بنية sshbuf *buf, size_t offset, uint16_t *valp)
{
	ثابت u_char *p = عدم;
	صحيح r;

	ܐܢ (valp != عدم)
		*valp = 0;
	ܐܢ ((r = check_roffset(buf, offset, 2, &p)) != 0)
		ܦܢܐ r;
	ܐܢ (valp != عدم)
		*valp = PEEK_U16(p);
	ܦܢܐ 0;
}

صحيح
sshbuf_peek_u8(ثابت بنية sshbuf *buf, size_t offset, u_char *valp)
{
	ثابت u_char *p = عدم;
	صحيح r;

	ܐܢ (valp != عدم)
		*valp = 0;
	ܐܢ ((r = check_roffset(buf, offset, 1, &p)) != 0)
		ܦܢܐ r;
	ܐܢ (valp != عدم)
		*valp = *p;
	ܦܢܐ 0;
}

صحيح
sshbuf_get_string(بنية sshbuf *buf, u_char **valp, size_t *lenp)
{
	ثابت u_char *val;
	size_t len;
	صحيح r;

	ܐܢ (valp != عدم)
		*valp = عدم;
	ܐܢ (lenp != عدم)
		*lenp = 0;
	ܐܢ ((r = sshbuf_get_string_direct(buf, &val, &len)) < 0)
		ܦܢܐ r;
	ܐܢ (valp != عدم) {
		ܐܢ ((*valp = malloc(len + 1)) == عدم) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			ܦܢܐ SSH_ERR_ALLOC_FAIL;
		}
		ܐܢ (len != 0)
			memcpy(*valp, val, len);
		(*valp)[len] = '\0';
	}
	ܐܢ (lenp != عدم)
		*lenp = len;
	ܦܢܐ 0;
}

صحيح
sshbuf_get_string_direct(بنية sshbuf *buf, ثابت u_char **valp, size_t *lenp)
{
	size_t len;
	ثابت u_char *p;
	صحيح r;

	ܐܢ (valp != عدم)
		*valp = عدم;
	ܐܢ (lenp != عدم)
		*lenp = 0;
	ܐܢ ((r = sshbuf_peek_string_direct(buf, &p, &len)) < 0)
		ܦܢܐ r;
	ܐܢ (valp != عدم)
		*valp = p;
	ܐܢ (lenp != عدم)
		*lenp = len;
	ܐܢ (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ܦܢܐ SSH_ERR_INTERNAL_ERROR;
	}
	ܦܢܐ 0;
}

صحيح
sshbuf_peek_string_direct(ثابت بنية sshbuf *buf, ثابت u_char **valp,
    size_t *lenp)
{
	uint32_t len;
	ثابت u_char *p = sshbuf_ptr(buf);

	ܐܢ (valp != عدم)
		*valp = عدم;
	ܐܢ (lenp != عدم)
		*lenp = 0;
	ܐܢ (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		ܦܢܐ SSH_ERR_MESSAGE_INCOMPLETE;
	}
	len = PEEK_U32(p);
	ܐܢ (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		ܦܢܐ SSH_ERR_STRING_TOO_LARGE;
	}
	ܐܢ (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		ܦܢܐ SSH_ERR_MESSAGE_INCOMPLETE;
	}
	ܐܢ (valp != عدم)
		*valp = p + 4;
	ܐܢ (lenp != عدم)
		*lenp = len;
	ܦܢܐ 0;
}

صحيح
sshbuf_get_cstring(بنية sshbuf *buf, حرف **valp, size_t *lenp)
{
	size_t len;
	ثابت u_char *p, *z;
	صحيح r;

	ܐܢ (valp != عدم)
		*valp = عدم;
	ܐܢ (lenp != عدم)
		*lenp = 0;
	ܐܢ ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		ܦܢܐ r;
	/* Allow a \0 only at the end of the string */
	ܐܢ (len > 0 &&
	    (z = memchr(p , '\0', len)) != عدم && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		ܦܢܐ SSH_ERR_INVALID_FORMAT;
	}
	ܐܢ ((r = sshbuf_skip_string(buf)) != 0)
		ܦܢܐ -1;
	ܐܢ (valp != عدم) {
		ܐܢ ((*valp = malloc(len + 1)) == عدم) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			ܦܢܐ SSH_ERR_ALLOC_FAIL;
		}
		ܐܢ (len != 0)
			memcpy(*valp, p, len);
		(*valp)[len] = '\0';
	}
	ܐܢ (lenp != عدم)
		*lenp = (size_t)len;
	ܦܢܐ 0;
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
	ܐܢ ((r = sshbuf_peek_string_direct(buf, عدم, عدم)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		ܦܢܐ r;
	ܦܢܐ 0;
}

صحيح
sshbuf_put(بنية sshbuf *buf, ثابت فراغ *v, size_t len)
{
	u_char *p;
	صحيح r;

	ܐܢ ((r = sshbuf_reserve(buf, len, &p)) < 0)
		ܦܢܐ r;
	ܐܢ (len != 0)
		memcpy(p, v, len);
	ܦܢܐ 0;
}

صحيح
sshbuf_putb(بنية sshbuf *buf, ثابت بنية sshbuf *v)
{
	ܐܢ (v == عدم)
		ܦܢܐ 0;
	ܦܢܐ sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

صحيح
sshbuf_putf(بنية sshbuf *buf, ثابت حرف *fmt, ...)
{
	va_list ap;
	صحيح r;

	va_start(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	va_end(ap);
	ܦܢܐ r;
}

صحيح
sshbuf_putfv(بنية sshbuf *buf, ثابت حرف *fmt, va_list ap)
{
	va_list ap2;
	صحيح r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	ܐܢ ((len = vsnprintf(عدم, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	ܐܢ (len == 0) {
		r = 0;
		اذهب out; /* Nothing to do */
	}
	va_end(ap2);
	VA_COPY(ap2, ap);
	ܐܢ ((r = sshbuf_reserve(buf, (size_t)len + 1, &p)) < 0)
		اذهب out;
	ܐܢ ((r = vsnprintf((حرف *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_INTERNAL_ERROR;
		اذهب out; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	ܐܢ ((r = sshbuf_consume_end(buf, 1)) != 0)
		اذهب out;
	r = 0;
 out:
	va_end(ap2);
	ܦܢܐ r;
}

صحيح
sshbuf_put_u64(بنية sshbuf *buf, uint64_t val)
{
	u_char *p;
	صحيح r;

	ܐܢ ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		ܦܢܐ r;
	POKE_U64(p, val);
	ܦܢܐ 0;
}

صحيح
sshbuf_put_u32(بنية sshbuf *buf, uint32_t val)
{
	u_char *p;
	صحيح r;

	ܐܢ ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		ܦܢܐ r;
	POKE_U32(p, val);
	ܦܢܐ 0;
}

صحيح
sshbuf_put_u16(بنية sshbuf *buf, uint16_t val)
{
	u_char *p;
	صحيح r;

	ܐܢ ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		ܦܢܐ r;
	POKE_U16(p, val);
	ܦܢܐ 0;
}

صحيح
sshbuf_put_u8(بنية sshbuf *buf, u_char val)
{
	u_char *p;
	صحيح r;

	ܐܢ ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		ܦܢܐ r;
	p[0] = val;
	ܦܢܐ 0;
}

ساكن صحيح
check_woffset(بنية sshbuf *buf, size_t offset, size_t len, u_char **p)
{
	صحيح r;

	*p = عدم;
	ܐܢ ((r = check_offset(buf, 1, offset, len)) != 0)
		ܦܢܐ r;
	ܐܢ (sshbuf_mutable_ptr(buf) == عدم)
		ܦܢܐ SSH_ERR_BUFFER_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + offset;
	ܦܢܐ 0;
}

صحيح
sshbuf_poke_u64(بنية sshbuf *buf, size_t offset, uint64_t val)
{
	u_char *p = عدم;
	صحيح r;

	ܐܢ ((r = check_woffset(buf, offset, 8, &p)) != 0)
		ܦܢܐ r;
	POKE_U64(p, val);
	ܦܢܐ 0;
}

صحيح
sshbuf_poke_u32(بنية sshbuf *buf, size_t offset, uint32_t val)
{
	u_char *p = عدم;
	صحيح r;

	ܐܢ ((r = check_woffset(buf, offset, 4, &p)) != 0)
		ܦܢܐ r;
	POKE_U32(p, val);
	ܦܢܐ 0;
}

صحيح
sshbuf_poke_u16(بنية sshbuf *buf, size_t offset, uint16_t val)
{
	u_char *p = عدم;
	صحيح r;

	ܐܢ ((r = check_woffset(buf, offset, 2, &p)) != 0)
		ܦܢܐ r;
	POKE_U16(p, val);
	ܦܢܐ 0;
}

صحيح
sshbuf_poke_u8(بنية sshbuf *buf, size_t offset, u_char val)
{
	u_char *p = عدم;
	صحيح r;

	ܐܢ ((r = check_woffset(buf, offset, 1, &p)) != 0)
		ܦܢܐ r;
	*p = val;
	ܦܢܐ 0;
}

صحيح
sshbuf_poke(بنية sshbuf *buf, size_t offset, فراغ *v, size_t len)
{
	u_char *p = عدم;
	صحيح r;

	ܐܢ ((r = check_woffset(buf, offset, len, &p)) != 0)
		ܦܢܐ r;
	memcpy(p, v, len);
	ܦܢܐ 0;
}

صحيح
sshbuf_put_string(بنية sshbuf *buf, ثابت فراغ *v, size_t len)
{
	u_char *d;
	صحيح r;

	ܐܢ (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		ܦܢܐ SSH_ERR_NO_BUFFER_SPACE;
	}
	ܐܢ ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		ܦܢܐ r;
	POKE_U32(d, len);
	ܐܢ (len != 0)
		memcpy(d + 4, v, len);
	ܦܢܐ 0;
}

صحيح
sshbuf_put_cstring(بنية sshbuf *buf, ثابت حرف *v)
{
	ܦܢܐ sshbuf_put_string(buf, v, v == عدم ? 0 : strlen(v));
}

صحيح
sshbuf_put_stringb(بنية sshbuf *buf, ثابت بنية sshbuf *v)
{
	ܐܢ (v == عدم)
		ܦܢܐ sshbuf_put_string(buf, عدم, 0);

	ܦܢܐ sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

صحيح
sshbuf_froms(بنية sshbuf *buf, بنية sshbuf **bufp)
{
	ثابت u_char *p;
	size_t len;
	بنية sshbuf *ret;
	صحيح r;

	ܐܢ (buf == عدم || bufp == عدم)
		ܦܢܐ SSH_ERR_INVALID_ARGUMENT;
	*bufp = عدم;
	ܐܢ ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		ܦܢܐ r;
	ܐܢ ((ret = sshbuf_from(p, len)) == عدم)
		ܦܢܐ SSH_ERR_ALLOC_FAIL;
	ܐܢ ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_set_parent(ret, buf)) != 0) {
		sshbuf_free(ret);
		ܦܢܐ r;
	}
	*bufp = ret;
	ܦܢܐ 0;
}

صحيح
sshbuf_put_bignum2_bytes(بنية sshbuf *buf, ثابت فراغ *v, size_t len)
{
	u_char *d;
	ثابت u_char *s = (ثابت u_char *)v;
	صحيح r, prepend;

	ܐܢ (len > SSHBUF_SIZE_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		ܦܢܐ SSH_ERR_NO_BUFFER_SPACE;
	}
	/* Skip leading zero bytes */
	لكل (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	ܐܢ ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		ܦܢܐ r;
	POKE_U32(d, len + prepend);
	ܐܢ (prepend)
		d[4] = 0;
	ܐܢ (len != 0)
		memcpy(d + 4 + prepend, s, len);
	ܦܢܐ 0;
}

صحيح
sshbuf_get_bignum2_bytes_direct(بنية sshbuf *buf,
    ثابت u_char **valp, size_t *lenp)
{
	ثابت u_char *d;
	size_t len, olen;
	صحيح r;

	ܐܢ ((r = sshbuf_peek_string_direct(buf, &d, &olen)) < 0)
		ܦܢܐ r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	ܐܢ ((len != 0 && (*d & 0x80) != 0))
		ܦܢܐ SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	ܐܢ (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		ܦܢܐ SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	ܟܡܐ (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	ܐܢ (valp != عدم)
		*valp = d;
	ܐܢ (lenp != عدم)
		*lenp = len;
	ܐܢ (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ܦܢܐ SSH_ERR_INTERNAL_ERROR;
	}
	ܦܢܐ 0;
}

صحيح
sshbuf_get_nulterminated_string(بنية sshbuf *buf, size_t maxlen,
    حرف **valp, size_t *lenp)
{
	ثابت u_char zero = 0;
	حرف *val = عدم;
	size_t len = 0;
	صحيح r;

	ܐܢ (valp != عدم)
		*valp = عدم;
	ܐܢ (lenp != عدم)
		*lenp = 0;
	ܐܢ ((r = sshbuf_find(buf, 0, &zero, حجم(zero), &len)) != 0) {
		ܐܢ (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			ܦܢܐ SSH_ERR_MESSAGE_INCOMPLETE;
		ܦܢܐ r;
	}
	ܐܢ (len > maxlen)
		ܦܢܐ SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	ܐܢ ((val = strdup(sshbuf_ptr(buf))) == عدم)
		ܦܢܐ SSH_ERR_ALLOC_FAIL;
	ܐܢ ((r = sshbuf_consume(buf, len + 1)) != 0)
		اذهب out;
	/* success */
	r = 0;
	ܐܢ (valp != عدم) {
		*valp = val;
		val = عدم;
	}
	ܐܢ (lenp != عدم)
		*lenp = len;
 out:
	حرر(val);
	ܦܢܐ r;
}
