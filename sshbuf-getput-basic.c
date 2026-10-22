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
#وصف_ڪريو SSHBUF_اندروني
#ضمن "sshbuf.h"

صحيح
sshbuf_get(بنية sshbuf *buf, فراغ *v, سائيز_t len)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحيح r;

	إذا ((r = sshbuf_consume(buf, len)) < 0)
		أرجع r;
	إذا (v != عدم && len != 0)
		يادگيري_نقل(v, p, len);
	أرجع 0;
}

صحيح
sshbuf_get_u64(بنية sshbuf *buf, uint64_t *valp)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحيح r;

	إذا ((r = sshbuf_consume(buf, 8)) < 0)
		أرجع r;
	إذا (valp != عدم)
		*valp = PEEK_U64(p);
	أرجع 0;
}

صحيح
sshbuf_get_u32(بنية sshbuf *buf, uint32_t *valp)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحيح r;

	إذا ((r = sshbuf_consume(buf, 4)) < 0)
		أرجع r;
	إذا (valp != عدم)
		*valp = PEEK_U32(p);
	أرجع 0;
}

صحيح
sshbuf_get_u16(بنية sshbuf *buf, uint16_t *valp)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحيح r;

	إذا ((r = sshbuf_consume(buf, 2)) < 0)
		أرجع r;
	إذا (valp != عدم)
		*valp = PEEK_U16(p);
	أرجع 0;
}

صحيح
sshbuf_get_u8(بنية sshbuf *buf, u_char *valp)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحيح r;

	إذا ((r = sshbuf_consume(buf, 1)) < 0)
		أرجع r;
	إذا (valp != عدم)
		*valp = (uint8_t)*p;
	أرجع 0;
}

ساكن صحيح
check_وٿي(ثابت بنية sshbuf *buf, صحيح wr, سائيز_t وٿي, سائيز_t len)
{
	إذا (sshbuf_ptr(buf) == عدم) /* calls sshbuf_check_sanity() */
		أرجع SSH_ERR_اندروني_ERROR;
	إذا (وٿي >= SIZE_MAX - len)
		أرجع SSH_ERR_INVALID_دليل;
	إذا (وٿي + len > sshbuf_len(buf)) {
		أرجع wr ?
		    SSH_ERR_NO_بفر_SPACE : SSH_ERR_پيغام_INCOMPLETE;
	}
	أرجع 0;
}

ساكن صحيح
check_roffset(ثابت بنية sshbuf *buf, سائيز_t وٿي, سائيز_t len,
    ثابت u_char **p)
{
	صحيح r;

	*p = عدم;
	إذا ((r = check_وٿي(buf, 0, وٿي, len)) != 0)
		أرجع r;
	*p = sshbuf_ptr(buf) + وٿي;
	أرجع 0;
}

صحيح
sshbuf_peek_u64(ثابت بنية sshbuf *buf, سائيز_t وٿي, uint64_t *valp)
{
	ثابت u_char *p = عدم;
	صحيح r;

	إذا (valp != عدم)
		*valp = 0;
	إذا ((r = check_roffset(buf, وٿي, 8, &p)) != 0)
		أرجع r;
	إذا (valp != عدم)
		*valp = PEEK_U64(p);
	أرجع 0;
}

صحيح
sshbuf_peek_u32(ثابت بنية sshbuf *buf, سائيز_t وٿي, uint32_t *valp)
{
	ثابت u_char *p = عدم;
	صحيح r;

	إذا (valp != عدم)
		*valp = 0;
	إذا ((r = check_roffset(buf, وٿي, 4, &p)) != 0)
		أرجع r;
	إذا (valp != عدم)
		*valp = PEEK_U32(p);
	أرجع 0;
}

صحيح
sshbuf_peek_u16(ثابت بنية sshbuf *buf, سائيز_t وٿي, uint16_t *valp)
{
	ثابت u_char *p = عدم;
	صحيح r;

	إذا (valp != عدم)
		*valp = 0;
	إذا ((r = check_roffset(buf, وٿي, 2, &p)) != 0)
		أرجع r;
	إذا (valp != عدم)
		*valp = PEEK_U16(p);
	أرجع 0;
}

صحيح
sshbuf_peek_u8(ثابت بنية sshbuf *buf, سائيز_t وٿي, u_char *valp)
{
	ثابت u_char *p = عدم;
	صحيح r;

	إذا (valp != عدم)
		*valp = 0;
	إذا ((r = check_roffset(buf, وٿي, 1, &p)) != 0)
		أرجع r;
	إذا (valp != عدم)
		*valp = *p;
	أرجع 0;
}

صحيح
sshbuf_get_string(بنية sshbuf *buf, u_char **valp, سائيز_t *lenp)
{
	ثابت u_char *val;
	سائيز_t len;
	صحيح r;

	إذا (valp != عدم)
		*valp = عدم;
	إذا (lenp != عدم)
		*lenp = 0;
	إذا ((r = sshbuf_get_string_سڌو(buf, &val, &len)) < 0)
		أرجع r;
	إذا (valp != عدم) {
		إذا ((*valp = يادگيري_ڏيو(len + 1)) == عدم) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			أرجع SSH_ERR_ALLOC_FAIL;
		}
		إذا (len != 0)
			يادگيري_نقل(*valp, val, len);
		(*valp)[len] = '\0';
	}
	إذا (lenp != عدم)
		*lenp = len;
	أرجع 0;
}

صحيح
sshbuf_get_string_سڌو(بنية sshbuf *buf, ثابت u_char **valp, سائيز_t *lenp)
{
	سائيز_t len;
	ثابت u_char *p;
	صحيح r;

	إذا (valp != عدم)
		*valp = عدم;
	إذا (lenp != عدم)
		*lenp = 0;
	إذا ((r = sshbuf_peek_string_سڌو(buf, &p, &len)) < 0)
		أرجع r;
	إذا (valp != عدم)
		*valp = p;
	إذا (lenp != عدم)
		*lenp = len;
	إذا (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		أرجع SSH_ERR_اندروني_ERROR;
	}
	أرجع 0;
}

صحيح
sshbuf_peek_string_سڌو(ثابت بنية sshbuf *buf, ثابت u_char **valp,
    سائيز_t *lenp)
{
	uint32_t len;
	ثابت u_char *p = sshbuf_ptr(buf);

	إذا (valp != عدم)
		*valp = عدم;
	إذا (lenp != عدم)
		*lenp = 0;
	إذا (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		أرجع SSH_ERR_پيغام_INCOMPLETE;
	}
	len = PEEK_U32(p);
	إذا (len > SSHBUF_سائيز_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		أرجع SSH_ERR_STRING_TOO_LARGE;
	}
	إذا (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		أرجع SSH_ERR_پيغام_INCOMPLETE;
	}
	إذا (valp != عدم)
		*valp = p + 4;
	إذا (lenp != عدم)
		*lenp = len;
	أرجع 0;
}

صحيح
sshbuf_get_cstring(بنية sshbuf *buf, حرف **valp, سائيز_t *lenp)
{
	سائيز_t len;
	ثابت u_char *p, *z;
	صحيح r;

	إذا (valp != عدم)
		*valp = عدم;
	إذا (lenp != عدم)
		*lenp = 0;
	إذا ((r = sshbuf_peek_string_سڌو(buf, &p, &len)) != 0)
		أرجع r;
	/* Allow a \0 only at the end of the string */
	إذا (len > 0 &&
	    (z = memchr(p , '\0', len)) != عدم && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	إذا ((r = sshbuf_skip_string(buf)) != 0)
		أرجع -1;
	إذا (valp != عدم) {
		إذا ((*valp = يادگيري_ڏيو(len + 1)) == عدم) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			أرجع SSH_ERR_ALLOC_FAIL;
		}
		إذا (len != 0)
			يادگيري_نقل(*valp, p, len);
		(*valp)[len] = '\0';
	}
	إذا (lenp != عدم)
		*lenp = (سائيز_t)len;
	أرجع 0;
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
	إذا ((r = sshbuf_peek_string_سڌو(buf, عدم, عدم)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		أرجع r;
	أرجع 0;
}

صحيح
sshbuf_put(بنية sshbuf *buf, ثابت فراغ *v, سائيز_t len)
{
	u_char *p;
	صحيح r;

	إذا ((r = sshbuf_reserve(buf, len, &p)) < 0)
		أرجع r;
	إذا (len != 0)
		يادگيري_نقل(p, v, len);
	أرجع 0;
}

صحيح
sshbuf_putb(بنية sshbuf *buf, ثابت بنية sshbuf *v)
{
	إذا (v == عدم)
		أرجع 0;
	أرجع sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

صحيح
sshbuf_putf(بنية sshbuf *buf, ثابت حرف *fmt, ...)
{
	va_list ap;
	صحيح r;

	va_start(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	va_end(ap);
	أرجع r;
}

صحيح
sshbuf_putfv(بنية sshbuf *buf, ثابت حرف *fmt, va_list ap)
{
	va_list ap2;
	صحيح r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	إذا ((len = vsnprintf(عدم, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_دليل;
		اذهب ٻاهريون;
	}
	إذا (len == 0) {
		r = 0;
		اذهب ٻاهريون; /* Nothing to do */
	}
	va_end(ap2);
	VA_COPY(ap2, ap);
	إذا ((r = sshbuf_reserve(buf, (سائيز_t)len + 1, &p)) < 0)
		اذهب ٻاهريون;
	إذا ((r = vsnprintf((حرف *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_اندروني_ERROR;
		اذهب ٻاهريون; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	إذا ((r = sshbuf_consume_پڇاڙي(buf, 1)) != 0)
		اذهب ٻاهريون;
	r = 0;
 ٻاهريون:
	va_end(ap2);
	أرجع r;
}

صحيح
sshbuf_put_u64(بنية sshbuf *buf, uint64_t val)
{
	u_char *p;
	صحيح r;

	إذا ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		أرجع r;
	POKE_U64(p, val);
	أرجع 0;
}

صحيح
sshbuf_put_u32(بنية sshbuf *buf, uint32_t val)
{
	u_char *p;
	صحيح r;

	إذا ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		أرجع r;
	POKE_U32(p, val);
	أرجع 0;
}

صحيح
sshbuf_put_u16(بنية sshbuf *buf, uint16_t val)
{
	u_char *p;
	صحيح r;

	إذا ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		أرجع r;
	POKE_U16(p, val);
	أرجع 0;
}

صحيح
sshbuf_put_u8(بنية sshbuf *buf, u_char val)
{
	u_char *p;
	صحيح r;

	إذا ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		أرجع r;
	p[0] = val;
	أرجع 0;
}

ساكن صحيح
check_woffset(بنية sshbuf *buf, سائيز_t وٿي, سائيز_t len, u_char **p)
{
	صحيح r;

	*p = عدم;
	إذا ((r = check_وٿي(buf, 1, وٿي, len)) != 0)
		أرجع r;
	إذا (sshbuf_mutable_ptr(buf) == عدم)
		أرجع SSH_ERR_بفر_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + وٿي;
	أرجع 0;
}

صحيح
sshbuf_poke_u64(بنية sshbuf *buf, سائيز_t وٿي, uint64_t val)
{
	u_char *p = عدم;
	صحيح r;

	إذا ((r = check_woffset(buf, وٿي, 8, &p)) != 0)
		أرجع r;
	POKE_U64(p, val);
	أرجع 0;
}

صحيح
sshbuf_poke_u32(بنية sshbuf *buf, سائيز_t وٿي, uint32_t val)
{
	u_char *p = عدم;
	صحيح r;

	إذا ((r = check_woffset(buf, وٿي, 4, &p)) != 0)
		أرجع r;
	POKE_U32(p, val);
	أرجع 0;
}

صحيح
sshbuf_poke_u16(بنية sshbuf *buf, سائيز_t وٿي, uint16_t val)
{
	u_char *p = عدم;
	صحيح r;

	إذا ((r = check_woffset(buf, وٿي, 2, &p)) != 0)
		أرجع r;
	POKE_U16(p, val);
	أرجع 0;
}

صحيح
sshbuf_poke_u8(بنية sshbuf *buf, سائيز_t وٿي, u_char val)
{
	u_char *p = عدم;
	صحيح r;

	إذا ((r = check_woffset(buf, وٿي, 1, &p)) != 0)
		أرجع r;
	*p = val;
	أرجع 0;
}

صحيح
sshbuf_poke(بنية sshbuf *buf, سائيز_t وٿي, فراغ *v, سائيز_t len)
{
	u_char *p = عدم;
	صحيح r;

	إذا ((r = check_woffset(buf, وٿي, len, &p)) != 0)
		أرجع r;
	يادگيري_نقل(p, v, len);
	أرجع 0;
}

صحيح
sshbuf_put_string(بنية sshbuf *buf, ثابت فراغ *v, سائيز_t len)
{
	u_char *d;
	صحيح r;

	إذا (len > SSHBUF_سائيز_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		أرجع SSH_ERR_NO_بفر_SPACE;
	}
	إذا ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		أرجع r;
	POKE_U32(d, len);
	إذا (len != 0)
		يادگيري_نقل(d + 4, v, len);
	أرجع 0;
}

صحيح
sshbuf_put_cstring(بنية sshbuf *buf, ثابت حرف *v)
{
	أرجع sshbuf_put_string(buf, v, v == عدم ? 0 : لڙي_ڊيگهه(v));
}

صحيح
sshbuf_put_stringb(بنية sshbuf *buf, ثابت بنية sshbuf *v)
{
	إذا (v == عدم)
		أرجع sshbuf_put_string(buf, عدم, 0);

	أرجع sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

صحيح
sshbuf_froms(بنية sshbuf *buf, بنية sshbuf **bufp)
{
	ثابت u_char *p;
	سائيز_t len;
	بنية sshbuf *ret;
	صحيح r;

	إذا (buf == عدم || bufp == عدم)
		أرجع SSH_ERR_INVALID_دليل;
	*bufp = عدم;
	إذا ((r = sshbuf_peek_string_سڌو(buf, &p, &len)) != 0)
		أرجع r;
	إذا ((ret = sshbuf_from(p, len)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_سيٽ_والد(ret, buf)) != 0) {
		sshbuf_free(ret);
		أرجع r;
	}
	*bufp = ret;
	أرجع 0;
}

صحيح
sshbuf_put_bignum2_بائيٽون(بنية sshbuf *buf, ثابت فراغ *v, سائيز_t len)
{
	u_char *d;
	ثابت u_char *s = (ثابت u_char *)v;
	صحيح r, prepend;

	إذا (len > SSHBUF_سائيز_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		أرجع SSH_ERR_NO_بفر_SPACE;
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
		أرجع r;
	POKE_U32(d, len + prepend);
	إذا (prepend)
		d[4] = 0;
	إذا (len != 0)
		يادگيري_نقل(d + 4 + prepend, s, len);
	أرجع 0;
}

صحيح
sshbuf_get_bignum2_بائيٽون_سڌو(بنية sshbuf *buf,
    ثابت u_char **valp, سائيز_t *lenp)
{
	ثابت u_char *d;
	سائيز_t len, olen;
	صحيح r;

	إذا ((r = sshbuf_peek_string_سڌو(buf, &d, &olen)) < 0)
		أرجع r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	إذا ((len != 0 && (*d & 0x80) != 0))
		أرجع SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	إذا (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		أرجع SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	طالما (len > 0 && *d == 0x00) {
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
		أرجع SSH_ERR_اندروني_ERROR;
	}
	أرجع 0;
}

صحيح
sshbuf_get_nulterminated_string(بنية sshbuf *buf, سائيز_t maxlen,
    حرف **valp, سائيز_t *lenp)
{
	ثابت u_char zero = 0;
	حرف *val = عدم;
	سائيز_t len = 0;
	صحيح r;

	إذا (valp != عدم)
		*valp = عدم;
	إذا (lenp != عدم)
		*lenp = 0;
	إذا ((r = sshbuf_ڳوليو(buf, 0, &zero, حجم(zero), &len)) != 0) {
		إذا (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			أرجع SSH_ERR_پيغام_INCOMPLETE;
		أرجع r;
	}
	إذا (len > maxlen)
		أرجع SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	إذا ((val = strdup(sshbuf_ptr(buf))) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_consume(buf, len + 1)) != 0)
		اذهب ٻاهريون;
	/* success */
	r = 0;
	إذا (valp != عدم) {
		*valp = val;
		val = عدم;
	}
	إذا (lenp != عدم)
		*lenp = len;
 ٻاهريون:
	حرر(val);
	أرجع r;
}
