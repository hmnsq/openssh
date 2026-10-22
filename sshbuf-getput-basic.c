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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdint.h>

#অন্তর্ভাব "ssherr.h"
#define SSHBUF_INTERNAL
#অন্তর্ভাব "sshbuf.h"

পূর্ণসংখ্যা
sshbuf_get(কাঠামো sshbuf *buf, শূন্য *v, আকার_t len)
{
	ধ্রুবক u_char *p = sshbuf_ptr(buf);
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_consume(buf, len)) < 0)
		ফেরত r;
	যদি (v != ফাঁকা && len != 0)
		memcpy(v, p, len);
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_get_u64(কাঠামো sshbuf *buf, uint64_t *valp)
{
	ধ্রুবক u_char *p = sshbuf_ptr(buf);
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_consume(buf, 8)) < 0)
		ফেরত r;
	যদি (valp != ফাঁকা)
		*valp = PEEK_U64(p);
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_get_u32(কাঠামো sshbuf *buf, uint32_t *valp)
{
	ধ্রুবক u_char *p = sshbuf_ptr(buf);
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_consume(buf, 4)) < 0)
		ফেরত r;
	যদি (valp != ফাঁকা)
		*valp = PEEK_U32(p);
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_get_u16(কাঠামো sshbuf *buf, uint16_t *valp)
{
	ধ্রুবক u_char *p = sshbuf_ptr(buf);
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_consume(buf, 2)) < 0)
		ফেরত r;
	যদি (valp != ফাঁকা)
		*valp = PEEK_U16(p);
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_get_u8(কাঠামো sshbuf *buf, u_char *valp)
{
	ধ্রুবক u_char *p = sshbuf_ptr(buf);
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_consume(buf, 1)) < 0)
		ফেরত r;
	যদি (valp != ফাঁকা)
		*valp = (uint8_t)*p;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
check_offset(ধ্রুবক কাঠামো sshbuf *buf, পূর্ণসংখ্যা wr, আকার_t offset, আকার_t len)
{
	যদি (sshbuf_ptr(buf) == ফাঁকা) /* calls sshbuf_check_sanity() */
		ফেরত SSH_ERR_INTERNAL_ERROR;
	যদি (offset >= SIZE_MAX - len)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (offset + len > sshbuf_len(buf)) {
		ফেরত wr ?
		    SSH_ERR_NO_বাফার_SPACE : SSH_ERR_MESSAGE_INCOMPLETE;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
check_roffset(ধ্রুবক কাঠামো sshbuf *buf, আকার_t offset, আকার_t len,
    ধ্রুবক u_char **p)
{
	পূর্ণসংখ্যা r;

	*p = ফাঁকা;
	যদি ((r = check_offset(buf, 0, offset, len)) != 0)
		ফেরত r;
	*p = sshbuf_ptr(buf) + offset;
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_peek_u64(ধ্রুবক কাঠামো sshbuf *buf, আকার_t offset, uint64_t *valp)
{
	ধ্রুবক u_char *p = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি (valp != ফাঁকা)
		*valp = 0;
	যদি ((r = check_roffset(buf, offset, 8, &p)) != 0)
		ফেরত r;
	যদি (valp != ফাঁকা)
		*valp = PEEK_U64(p);
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_peek_u32(ধ্রুবক কাঠামো sshbuf *buf, আকার_t offset, uint32_t *valp)
{
	ধ্রুবক u_char *p = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি (valp != ফাঁকা)
		*valp = 0;
	যদি ((r = check_roffset(buf, offset, 4, &p)) != 0)
		ফেরত r;
	যদি (valp != ফাঁকা)
		*valp = PEEK_U32(p);
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_peek_u16(ধ্রুবক কাঠামো sshbuf *buf, আকার_t offset, uint16_t *valp)
{
	ধ্রুবক u_char *p = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি (valp != ফাঁকা)
		*valp = 0;
	যদি ((r = check_roffset(buf, offset, 2, &p)) != 0)
		ফেরত r;
	যদি (valp != ফাঁকা)
		*valp = PEEK_U16(p);
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_peek_u8(ধ্রুবক কাঠামো sshbuf *buf, আকার_t offset, u_char *valp)
{
	ধ্রুবক u_char *p = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি (valp != ফাঁকা)
		*valp = 0;
	যদি ((r = check_roffset(buf, offset, 1, &p)) != 0)
		ফেরত r;
	যদি (valp != ফাঁকা)
		*valp = *p;
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_get_string(কাঠামো sshbuf *buf, u_char **valp, আকার_t *lenp)
{
	ধ্রুবক u_char *val;
	আকার_t len;
	পূর্ণসংখ্যা r;

	যদি (valp != ফাঁকা)
		*valp = ফাঁকা;
	যদি (lenp != ফাঁকা)
		*lenp = 0;
	যদি ((r = sshbuf_get_string_direct(buf, &val, &len)) < 0)
		ফেরত r;
	যদি (valp != ফাঁকা) {
		যদি ((*valp = malloc(len + 1)) == ফাঁকা) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			ফেরত SSH_ERR_ALLOC_FAIL;
		}
		যদি (len != 0)
			memcpy(*valp, val, len);
		(*valp)[len] = '\0';
	}
	যদি (lenp != ফাঁকা)
		*lenp = len;
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_get_string_direct(কাঠামো sshbuf *buf, ধ্রুবক u_char **valp, আকার_t *lenp)
{
	আকার_t len;
	ধ্রুবক u_char *p;
	পূর্ণসংখ্যা r;

	যদি (valp != ফাঁকা)
		*valp = ফাঁকা;
	যদি (lenp != ফাঁকা)
		*lenp = 0;
	যদি ((r = sshbuf_peek_string_direct(buf, &p, &len)) < 0)
		ফেরত r;
	যদি (valp != ফাঁকা)
		*valp = p;
	যদি (lenp != ফাঁকা)
		*lenp = len;
	যদি (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_peek_string_direct(ধ্রুবক কাঠামো sshbuf *buf, ধ্রুবক u_char **valp,
    আকার_t *lenp)
{
	uint32_t len;
	ধ্রুবক u_char *p = sshbuf_ptr(buf);

	যদি (valp != ফাঁকা)
		*valp = ফাঁকা;
	যদি (lenp != ফাঁকা)
		*lenp = 0;
	যদি (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		ফেরত SSH_ERR_MESSAGE_INCOMPLETE;
	}
	len = PEEK_U32(p);
	যদি (len > SSHBUF_আকার_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		ফেরত SSH_ERR_STRING_TOO_LARGE;
	}
	যদি (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		ফেরত SSH_ERR_MESSAGE_INCOMPLETE;
	}
	যদি (valp != ফাঁকা)
		*valp = p + 4;
	যদি (lenp != ফাঁকা)
		*lenp = len;
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_get_cstring(কাঠামো sshbuf *buf, অক্ষর **valp, আকার_t *lenp)
{
	আকার_t len;
	ধ্রুবক u_char *p, *z;
	পূর্ণসংখ্যা r;

	যদি (valp != ফাঁকা)
		*valp = ফাঁকা;
	যদি (lenp != ফাঁকা)
		*lenp = 0;
	যদি ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		ফেরত r;
	/* Allow a \0 only at the end of the string */
	যদি (len > 0 &&
	    (z = memchr(p , '\0', len)) != ফাঁকা && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		ফেরত SSH_ERR_INVALID_FORMAT;
	}
	যদি ((r = sshbuf_skip_string(buf)) != 0)
		ফেরত -1;
	যদি (valp != ফাঁকা) {
		যদি ((*valp = malloc(len + 1)) == ফাঁকা) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			ফেরত SSH_ERR_ALLOC_FAIL;
		}
		যদি (len != 0)
			memcpy(*valp, p, len);
		(*valp)[len] = '\0';
	}
	যদি (lenp != ফাঁকা)
		*lenp = (আকার_t)len;
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_get_stringb(কাঠামো sshbuf *buf, কাঠামো sshbuf *v)
{
	uint32_t len;
	u_char *p;
	পূর্ণসংখ্যা r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	যদি ((r = sshbuf_peek_string_direct(buf, ফাঁকা, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		ফেরত r;
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_put(কাঠামো sshbuf *buf, ধ্রুবক শূন্য *v, আকার_t len)
{
	u_char *p;
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_reserve(buf, len, &p)) < 0)
		ফেরত r;
	যদি (len != 0)
		memcpy(p, v, len);
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_putb(কাঠামো sshbuf *buf, ধ্রুবক কাঠামো sshbuf *v)
{
	যদি (v == ফাঁকা)
		ফেরত 0;
	ফেরত sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

পূর্ণসংখ্যা
sshbuf_putf(কাঠামো sshbuf *buf, ধ্রুবক অক্ষর *fmt, ...)
{
	va_list ap;
	পূর্ণসংখ্যা r;

	va_start(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	va_end(ap);
	ফেরত r;
}

পূর্ণসংখ্যা
sshbuf_putfv(কাঠামো sshbuf *buf, ধ্রুবক অক্ষর *fmt, va_list ap)
{
	va_list ap2;
	পূর্ণসংখ্যা r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	যদি ((len = vsnprintf(ফাঁকা, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		যাও out;
	}
	যদি (len == 0) {
		r = 0;
		যাও out; /* Nothing to do */
	}
	va_end(ap2);
	VA_COPY(ap2, ap);
	যদি ((r = sshbuf_reserve(buf, (আকার_t)len + 1, &p)) < 0)
		যাও out;
	যদি ((r = vsnprintf((অক্ষর *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_INTERNAL_ERROR;
		যাও out; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	যদি ((r = sshbuf_consume_end(buf, 1)) != 0)
		যাও out;
	r = 0;
 out:
	va_end(ap2);
	ফেরত r;
}

পূর্ণসংখ্যা
sshbuf_put_u64(কাঠামো sshbuf *buf, uint64_t val)
{
	u_char *p;
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		ফেরত r;
	POKE_U64(p, val);
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_put_u32(কাঠামো sshbuf *buf, uint32_t val)
{
	u_char *p;
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		ফেরত r;
	POKE_U32(p, val);
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_put_u16(কাঠামো sshbuf *buf, uint16_t val)
{
	u_char *p;
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		ফেরত r;
	POKE_U16(p, val);
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_put_u8(কাঠামো sshbuf *buf, u_char val)
{
	u_char *p;
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		ফেরত r;
	p[0] = val;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
check_woffset(কাঠামো sshbuf *buf, আকার_t offset, আকার_t len, u_char **p)
{
	পূর্ণসংখ্যা r;

	*p = ফাঁকা;
	যদি ((r = check_offset(buf, 1, offset, len)) != 0)
		ফেরত r;
	যদি (sshbuf_mutable_ptr(buf) == ফাঁকা)
		ফেরত SSH_ERR_বাফার_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + offset;
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_poke_u64(কাঠামো sshbuf *buf, আকার_t offset, uint64_t val)
{
	u_char *p = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি ((r = check_woffset(buf, offset, 8, &p)) != 0)
		ফেরত r;
	POKE_U64(p, val);
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_poke_u32(কাঠামো sshbuf *buf, আকার_t offset, uint32_t val)
{
	u_char *p = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি ((r = check_woffset(buf, offset, 4, &p)) != 0)
		ফেরত r;
	POKE_U32(p, val);
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_poke_u16(কাঠামো sshbuf *buf, আকার_t offset, uint16_t val)
{
	u_char *p = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি ((r = check_woffset(buf, offset, 2, &p)) != 0)
		ফেরত r;
	POKE_U16(p, val);
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_poke_u8(কাঠামো sshbuf *buf, আকার_t offset, u_char val)
{
	u_char *p = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি ((r = check_woffset(buf, offset, 1, &p)) != 0)
		ফেরত r;
	*p = val;
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_poke(কাঠামো sshbuf *buf, আকার_t offset, শূন্য *v, আকার_t len)
{
	u_char *p = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি ((r = check_woffset(buf, offset, len, &p)) != 0)
		ফেরত r;
	memcpy(p, v, len);
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_put_string(কাঠামো sshbuf *buf, ধ্রুবক শূন্য *v, আকার_t len)
{
	u_char *d;
	পূর্ণসংখ্যা r;

	যদি (len > SSHBUF_আকার_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		ফেরত SSH_ERR_NO_বাফার_SPACE;
	}
	যদি ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		ফেরত r;
	POKE_U32(d, len);
	যদি (len != 0)
		memcpy(d + 4, v, len);
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_put_cstring(কাঠামো sshbuf *buf, ধ্রুবক অক্ষর *v)
{
	ফেরত sshbuf_put_string(buf, v, v == ফাঁকা ? 0 : strlen(v));
}

পূর্ণসংখ্যা
sshbuf_put_stringb(কাঠামো sshbuf *buf, ধ্রুবক কাঠামো sshbuf *v)
{
	যদি (v == ফাঁকা)
		ফেরত sshbuf_put_string(buf, ফাঁকা, 0);

	ফেরত sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

পূর্ণসংখ্যা
sshbuf_froms(কাঠামো sshbuf *buf, কাঠামো sshbuf **bufp)
{
	ধ্রুবক u_char *p;
	আকার_t len;
	কাঠামো sshbuf *ret;
	পূর্ণসংখ্যা r;

	যদি (buf == ফাঁকা || bufp == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	*bufp = ফাঁকা;
	যদি ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		ফেরত r;
	যদি ((ret = sshbuf_from(p, len)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_set_parent(ret, buf)) != 0) {
		sshbuf_free(ret);
		ফেরত r;
	}
	*bufp = ret;
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_put_bignum2_bytes(কাঠামো sshbuf *buf, ধ্রুবক শূন্য *v, আকার_t len)
{
	u_char *d;
	ধ্রুবক u_char *s = (ধ্রুবক u_char *)v;
	পূর্ণসংখ্যা r, prepend;

	যদি (len > SSHBUF_আকার_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		ফেরত SSH_ERR_NO_বাফার_SPACE;
	}
	/* Skip leading zero bytes */
	জন্য (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	যদি ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		ফেরত r;
	POKE_U32(d, len + prepend);
	যদি (prepend)
		d[4] = 0;
	যদি (len != 0)
		memcpy(d + 4 + prepend, s, len);
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_get_bignum2_bytes_direct(কাঠামো sshbuf *buf,
    ধ্রুবক u_char **valp, আকার_t *lenp)
{
	ধ্রুবক u_char *d;
	আকার_t len, olen;
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_peek_string_direct(buf, &d, &olen)) < 0)
		ফেরত r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	যদি ((len != 0 && (*d & 0x80) != 0))
		ফেরত SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	যদি (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		ফেরত SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	যখন (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	যদি (valp != ফাঁকা)
		*valp = d;
	যদি (lenp != ফাঁকা)
		*lenp = len;
	যদি (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_get_nulterminated_string(কাঠামো sshbuf *buf, আকার_t maxlen,
    অক্ষর **valp, আকার_t *lenp)
{
	ধ্রুবক u_char zero = 0;
	অক্ষর *val = ফাঁকা;
	আকার_t len = 0;
	পূর্ণসংখ্যা r;

	যদি (valp != ফাঁকা)
		*valp = ফাঁকা;
	যদি (lenp != ফাঁকা)
		*lenp = 0;
	যদি ((r = sshbuf_find(buf, 0, &zero, আকার(zero), &len)) != 0) {
		যদি (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			ফেরত SSH_ERR_MESSAGE_INCOMPLETE;
		ফেরত r;
	}
	যদি (len > maxlen)
		ফেরত SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	যদি ((val = strdup(sshbuf_ptr(buf))) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_consume(buf, len + 1)) != 0)
		যাও out;
	/* success */
	r = 0;
	যদি (valp != ফাঁকা) {
		*valp = val;
		val = ফাঁকা;
	}
	যদি (lenp != ফাঁকা)
		*lenp = len;
 out:
	মুক্ত(val);
	ফেরত r;
}
