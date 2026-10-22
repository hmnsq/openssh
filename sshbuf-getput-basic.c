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
#تعریف_کرو SSHBUF_اندرونی
#شامل "sshbuf.h"

صحیح
sshbuf_get(ساخت sshbuf *buf, خالی *v, سائز_t len)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحیح r;

	اگر ((r = sshbuf_consume(buf, len)) < 0)
		واپس r;
	اگر (v != تہی && len != 0)
		حافظہ_نقل(v, p, len);
	واپس 0;
}

صحیح
sshbuf_get_u64(ساخت sshbuf *buf, uint64_t *valp)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحیح r;

	اگر ((r = sshbuf_consume(buf, 8)) < 0)
		واپس r;
	اگر (valp != تہی)
		*valp = PEEK_U64(p);
	واپس 0;
}

صحیح
sshbuf_get_u32(ساخت sshbuf *buf, uint32_t *valp)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحیح r;

	اگر ((r = sshbuf_consume(buf, 4)) < 0)
		واپس r;
	اگر (valp != تہی)
		*valp = PEEK_U32(p);
	واپس 0;
}

صحیح
sshbuf_get_u16(ساخت sshbuf *buf, uint16_t *valp)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحیح r;

	اگر ((r = sshbuf_consume(buf, 2)) < 0)
		واپس r;
	اگر (valp != تہی)
		*valp = PEEK_U16(p);
	واپس 0;
}

صحیح
sshbuf_get_u8(ساخت sshbuf *buf, u_char *valp)
{
	ثابت u_char *p = sshbuf_ptr(buf);
	صحیح r;

	اگر ((r = sshbuf_consume(buf, 1)) < 0)
		واپس r;
	اگر (valp != تہی)
		*valp = (uint8_t)*p;
	واپس 0;
}

ساکن صحیح
check_انحراف(ثابت ساخت sshbuf *buf, صحیح wr, سائز_t انحراف, سائز_t len)
{
	اگر (sshbuf_ptr(buf) == تہی) /* calls sshbuf_check_sanity() */
		واپس SSH_ERR_اندرونی_ERROR;
	اگر (انحراف >= SIZE_MAX - len)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (انحراف + len > sshbuf_len(buf)) {
		واپس wr ?
		    SSH_ERR_NO_بفر_SPACE : SSH_ERR_پیغام_INCOMPLETE;
	}
	واپس 0;
}

ساکن صحیح
check_roffset(ثابت ساخت sshbuf *buf, سائز_t انحراف, سائز_t len,
    ثابت u_char **p)
{
	صحیح r;

	*p = تہی;
	اگر ((r = check_انحراف(buf, 0, انحراف, len)) != 0)
		واپس r;
	*p = sshbuf_ptr(buf) + انحراف;
	واپس 0;
}

صحیح
sshbuf_peek_u64(ثابت ساخت sshbuf *buf, سائز_t انحراف, uint64_t *valp)
{
	ثابت u_char *p = تہی;
	صحیح r;

	اگر (valp != تہی)
		*valp = 0;
	اگر ((r = check_roffset(buf, انحراف, 8, &p)) != 0)
		واپس r;
	اگر (valp != تہی)
		*valp = PEEK_U64(p);
	واپس 0;
}

صحیح
sshbuf_peek_u32(ثابت ساخت sshbuf *buf, سائز_t انحراف, uint32_t *valp)
{
	ثابت u_char *p = تہی;
	صحیح r;

	اگر (valp != تہی)
		*valp = 0;
	اگر ((r = check_roffset(buf, انحراف, 4, &p)) != 0)
		واپس r;
	اگر (valp != تہی)
		*valp = PEEK_U32(p);
	واپس 0;
}

صحیح
sshbuf_peek_u16(ثابت ساخت sshbuf *buf, سائز_t انحراف, uint16_t *valp)
{
	ثابت u_char *p = تہی;
	صحیح r;

	اگر (valp != تہی)
		*valp = 0;
	اگر ((r = check_roffset(buf, انحراف, 2, &p)) != 0)
		واپس r;
	اگر (valp != تہی)
		*valp = PEEK_U16(p);
	واپس 0;
}

صحیح
sshbuf_peek_u8(ثابت ساخت sshbuf *buf, سائز_t انحراف, u_char *valp)
{
	ثابت u_char *p = تہی;
	صحیح r;

	اگر (valp != تہی)
		*valp = 0;
	اگر ((r = check_roffset(buf, انحراف, 1, &p)) != 0)
		واپس r;
	اگر (valp != تہی)
		*valp = *p;
	واپس 0;
}

صحیح
sshbuf_get_string(ساخت sshbuf *buf, u_char **valp, سائز_t *lenp)
{
	ثابت u_char *val;
	سائز_t len;
	صحیح r;

	اگر (valp != تہی)
		*valp = تہی;
	اگر (lenp != تہی)
		*lenp = 0;
	اگر ((r = sshbuf_get_string_براہ_راست(buf, &val, &len)) < 0)
		واپس r;
	اگر (valp != تہی) {
		اگر ((*valp = حافظہ_دو(len + 1)) == تہی) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			واپس SSH_ERR_ALLOC_FAIL;
		}
		اگر (len != 0)
			حافظہ_نقل(*valp, val, len);
		(*valp)[len] = '\0';
	}
	اگر (lenp != تہی)
		*lenp = len;
	واپس 0;
}

صحیح
sshbuf_get_string_براہ_راست(ساخت sshbuf *buf, ثابت u_char **valp, سائز_t *lenp)
{
	سائز_t len;
	ثابت u_char *p;
	صحیح r;

	اگر (valp != تہی)
		*valp = تہی;
	اگر (lenp != تہی)
		*lenp = 0;
	اگر ((r = sshbuf_peek_string_براہ_راست(buf, &p, &len)) < 0)
		واپس r;
	اگر (valp != تہی)
		*valp = p;
	اگر (lenp != تہی)
		*lenp = len;
	اگر (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		واپس SSH_ERR_اندرونی_ERROR;
	}
	واپس 0;
}

صحیح
sshbuf_peek_string_براہ_راست(ثابت ساخت sshbuf *buf, ثابت u_char **valp,
    سائز_t *lenp)
{
	uint32_t len;
	ثابت u_char *p = sshbuf_ptr(buf);

	اگر (valp != تہی)
		*valp = تہی;
	اگر (lenp != تہی)
		*lenp = 0;
	اگر (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		واپس SSH_ERR_پیغام_INCOMPLETE;
	}
	len = PEEK_U32(p);
	اگر (len > SSHBUF_سائز_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		واپس SSH_ERR_STRING_TOO_LARGE;
	}
	اگر (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		واپس SSH_ERR_پیغام_INCOMPLETE;
	}
	اگر (valp != تہی)
		*valp = p + 4;
	اگر (lenp != تہی)
		*lenp = len;
	واپس 0;
}

صحیح
sshbuf_get_cstring(ساخت sshbuf *buf, حرف **valp, سائز_t *lenp)
{
	سائز_t len;
	ثابت u_char *p, *z;
	صحیح r;

	اگر (valp != تہی)
		*valp = تہی;
	اگر (lenp != تہی)
		*lenp = 0;
	اگر ((r = sshbuf_peek_string_براہ_راست(buf, &p, &len)) != 0)
		واپس r;
	/* Allow a \0 only at the end of the string */
	اگر (len > 0 &&
	    (z = memchr(p , '\0', len)) != تہی && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		واپس SSH_ERR_INVALID_FORMAT;
	}
	اگر ((r = sshbuf_skip_string(buf)) != 0)
		واپس -1;
	اگر (valp != تہی) {
		اگر ((*valp = حافظہ_دو(len + 1)) == تہی) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			واپس SSH_ERR_ALLOC_FAIL;
		}
		اگر (len != 0)
			حافظہ_نقل(*valp, p, len);
		(*valp)[len] = '\0';
	}
	اگر (lenp != تہی)
		*lenp = (سائز_t)len;
	واپس 0;
}

صحیح
sshbuf_get_stringb(ساخت sshbuf *buf, ساخت sshbuf *v)
{
	uint32_t len;
	u_char *p;
	صحیح r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	اگر ((r = sshbuf_peek_string_براہ_راست(buf, تہی, تہی)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		واپس r;
	واپس 0;
}

صحیح
sshbuf_put(ساخت sshbuf *buf, ثابت خالی *v, سائز_t len)
{
	u_char *p;
	صحیح r;

	اگر ((r = sshbuf_reserve(buf, len, &p)) < 0)
		واپس r;
	اگر (len != 0)
		حافظہ_نقل(p, v, len);
	واپس 0;
}

صحیح
sshbuf_putb(ساخت sshbuf *buf, ثابت ساخت sshbuf *v)
{
	اگر (v == تہی)
		واپس 0;
	واپس sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

صحیح
sshbuf_putf(ساخت sshbuf *buf, ثابت حرف *fmt, ...)
{
	va_list ap;
	صحیح r;

	va_start(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	va_end(ap);
	واپس r;
}

صحیح
sshbuf_putfv(ساخت sshbuf *buf, ثابت حرف *fmt, va_list ap)
{
	va_list ap2;
	صحیح r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	اگر ((len = vsnprintf(تہی, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	}
	اگر (len == 0) {
		r = 0;
		جاؤ برآمد; /* Nothing to do */
	}
	va_end(ap2);
	VA_COPY(ap2, ap);
	اگر ((r = sshbuf_reserve(buf, (سائز_t)len + 1, &p)) < 0)
		جاؤ برآمد;
	اگر ((r = vsnprintf((حرف *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_اندرونی_ERROR;
		جاؤ برآمد; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	اگر ((r = sshbuf_consume_انتہا(buf, 1)) != 0)
		جاؤ برآمد;
	r = 0;
 برآمد:
	va_end(ap2);
	واپس r;
}

صحیح
sshbuf_put_u64(ساخت sshbuf *buf, uint64_t val)
{
	u_char *p;
	صحیح r;

	اگر ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		واپس r;
	POKE_U64(p, val);
	واپس 0;
}

صحیح
sshbuf_put_u32(ساخت sshbuf *buf, uint32_t val)
{
	u_char *p;
	صحیح r;

	اگر ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		واپس r;
	POKE_U32(p, val);
	واپس 0;
}

صحیح
sshbuf_put_u16(ساخت sshbuf *buf, uint16_t val)
{
	u_char *p;
	صحیح r;

	اگر ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		واپس r;
	POKE_U16(p, val);
	واپس 0;
}

صحیح
sshbuf_put_u8(ساخت sshbuf *buf, u_char val)
{
	u_char *p;
	صحیح r;

	اگر ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		واپس r;
	p[0] = val;
	واپس 0;
}

ساکن صحیح
check_woffset(ساخت sshbuf *buf, سائز_t انحراف, سائز_t len, u_char **p)
{
	صحیح r;

	*p = تہی;
	اگر ((r = check_انحراف(buf, 1, انحراف, len)) != 0)
		واپس r;
	اگر (sshbuf_mutable_ptr(buf) == تہی)
		واپس SSH_ERR_بفر_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + انحراف;
	واپس 0;
}

صحیح
sshbuf_poke_u64(ساخت sshbuf *buf, سائز_t انحراف, uint64_t val)
{
	u_char *p = تہی;
	صحیح r;

	اگر ((r = check_woffset(buf, انحراف, 8, &p)) != 0)
		واپس r;
	POKE_U64(p, val);
	واپس 0;
}

صحیح
sshbuf_poke_u32(ساخت sshbuf *buf, سائز_t انحراف, uint32_t val)
{
	u_char *p = تہی;
	صحیح r;

	اگر ((r = check_woffset(buf, انحراف, 4, &p)) != 0)
		واپس r;
	POKE_U32(p, val);
	واپس 0;
}

صحیح
sshbuf_poke_u16(ساخت sshbuf *buf, سائز_t انحراف, uint16_t val)
{
	u_char *p = تہی;
	صحیح r;

	اگر ((r = check_woffset(buf, انحراف, 2, &p)) != 0)
		واپس r;
	POKE_U16(p, val);
	واپس 0;
}

صحیح
sshbuf_poke_u8(ساخت sshbuf *buf, سائز_t انحراف, u_char val)
{
	u_char *p = تہی;
	صحیح r;

	اگر ((r = check_woffset(buf, انحراف, 1, &p)) != 0)
		واپس r;
	*p = val;
	واپس 0;
}

صحیح
sshbuf_poke(ساخت sshbuf *buf, سائز_t انحراف, خالی *v, سائز_t len)
{
	u_char *p = تہی;
	صحیح r;

	اگر ((r = check_woffset(buf, انحراف, len, &p)) != 0)
		واپس r;
	حافظہ_نقل(p, v, len);
	واپس 0;
}

صحیح
sshbuf_put_string(ساخت sshbuf *buf, ثابت خالی *v, سائز_t len)
{
	u_char *d;
	صحیح r;

	اگر (len > SSHBUF_سائز_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		واپس SSH_ERR_NO_بفر_SPACE;
	}
	اگر ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		واپس r;
	POKE_U32(d, len);
	اگر (len != 0)
		حافظہ_نقل(d + 4, v, len);
	واپس 0;
}

صحیح
sshbuf_put_cstring(ساخت sshbuf *buf, ثابت حرف *v)
{
	واپس sshbuf_put_string(buf, v, v == تہی ? 0 : لڑی_لمبائی(v));
}

صحیح
sshbuf_put_stringb(ساخت sshbuf *buf, ثابت ساخت sshbuf *v)
{
	اگر (v == تہی)
		واپس sshbuf_put_string(buf, تہی, 0);

	واپس sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

صحیح
sshbuf_froms(ساخت sshbuf *buf, ساخت sshbuf **bufp)
{
	ثابت u_char *p;
	سائز_t len;
	ساخت sshbuf *ret;
	صحیح r;

	اگر (buf == تہی || bufp == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	*bufp = تہی;
	اگر ((r = sshbuf_peek_string_براہ_راست(buf, &p, &len)) != 0)
		واپس r;
	اگر ((ret = sshbuf_from(p, len)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_سیٹ_والد(ret, buf)) != 0) {
		sshbuf_free(ret);
		واپس r;
	}
	*bufp = ret;
	واپس 0;
}

صحیح
sshbuf_put_bignum2_بائٹیں(ساخت sshbuf *buf, ثابت خالی *v, سائز_t len)
{
	u_char *d;
	ثابت u_char *s = (ثابت u_char *)v;
	صحیح r, prepend;

	اگر (len > SSHBUF_سائز_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		واپس SSH_ERR_NO_بفر_SPACE;
	}
	/* Skip leading zero bytes */
	برائے (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	اگر ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		واپس r;
	POKE_U32(d, len + prepend);
	اگر (prepend)
		d[4] = 0;
	اگر (len != 0)
		حافظہ_نقل(d + 4 + prepend, s, len);
	واپس 0;
}

صحیح
sshbuf_get_bignum2_بائٹیں_براہ_راست(ساخت sshbuf *buf,
    ثابت u_char **valp, سائز_t *lenp)
{
	ثابت u_char *d;
	سائز_t len, olen;
	صحیح r;

	اگر ((r = sshbuf_peek_string_براہ_راست(buf, &d, &olen)) < 0)
		واپس r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	اگر ((len != 0 && (*d & 0x80) != 0))
		واپس SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	اگر (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		واپس SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	جب (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	اگر (valp != تہی)
		*valp = d;
	اگر (lenp != تہی)
		*lenp = len;
	اگر (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		واپس SSH_ERR_اندرونی_ERROR;
	}
	واپس 0;
}

صحیح
sshbuf_get_nulterminated_string(ساخت sshbuf *buf, سائز_t maxlen,
    حرف **valp, سائز_t *lenp)
{
	ثابت u_char zero = 0;
	حرف *val = تہی;
	سائز_t len = 0;
	صحیح r;

	اگر (valp != تہی)
		*valp = تہی;
	اگر (lenp != تہی)
		*lenp = 0;
	اگر ((r = sshbuf_ڈھونڈو(buf, 0, &zero, حجم(zero), &len)) != 0) {
		اگر (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			واپس SSH_ERR_پیغام_INCOMPLETE;
		واپس r;
	}
	اگر (len > maxlen)
		واپس SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	اگر ((val = strdup(sshbuf_ptr(buf))) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_consume(buf, len + 1)) != 0)
		جاؤ برآمد;
	/* success */
	r = 0;
	اگر (valp != تہی) {
		*valp = val;
		val = تہی;
	}
	اگر (lenp != تہی)
		*lenp = len;
 برآمد:
	آزاد(val);
	واپس r;
}
