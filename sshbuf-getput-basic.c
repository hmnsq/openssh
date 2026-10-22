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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdint.h>

#அந்தர்பாவ "ssherr.h"
#define SSHBUF_INTERNAL
#அந்தர்பாவ "sshbuf.h"

முழு
sshbuf_get(கட்டமைப்பு sshbuf *buf, வெறுமை *v, size_t len)
{
	மாறிலி u_char *p = sshbuf_ptr(buf);
	முழு r;

	எனில் ((r = sshbuf_consume(buf, len)) < 0)
		திரும்பு r;
	எனில் (v != வெற்று && len != 0)
		memcpy(v, p, len);
	திரும்பு 0;
}

முழு
sshbuf_get_u64(கட்டமைப்பு sshbuf *buf, uint64_t *valp)
{
	மாறிலி u_char *p = sshbuf_ptr(buf);
	முழு r;

	எனில் ((r = sshbuf_consume(buf, 8)) < 0)
		திரும்பு r;
	எனில் (valp != வெற்று)
		*valp = PEEK_U64(p);
	திரும்பு 0;
}

முழு
sshbuf_get_u32(கட்டமைப்பு sshbuf *buf, uint32_t *valp)
{
	மாறிலி u_char *p = sshbuf_ptr(buf);
	முழு r;

	எனில் ((r = sshbuf_consume(buf, 4)) < 0)
		திரும்பு r;
	எனில் (valp != வெற்று)
		*valp = PEEK_U32(p);
	திரும்பு 0;
}

முழு
sshbuf_get_u16(கட்டமைப்பு sshbuf *buf, uint16_t *valp)
{
	மாறிலி u_char *p = sshbuf_ptr(buf);
	முழு r;

	எனில் ((r = sshbuf_consume(buf, 2)) < 0)
		திரும்பு r;
	எனில் (valp != வெற்று)
		*valp = PEEK_U16(p);
	திரும்பு 0;
}

முழு
sshbuf_get_u8(கட்டமைப்பு sshbuf *buf, u_char *valp)
{
	மாறிலி u_char *p = sshbuf_ptr(buf);
	முழு r;

	எனில் ((r = sshbuf_consume(buf, 1)) < 0)
		திரும்பு r;
	எனில் (valp != வெற்று)
		*valp = (uint8_t)*p;
	திரும்பு 0;
}

நிலையான முழு
check_offset(மாறிலி கட்டமைப்பு sshbuf *buf, முழு wr, size_t offset, size_t len)
{
	எனில் (sshbuf_ptr(buf) == வெற்று) /* calls sshbuf_check_sanity() */
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	எனில் (offset >= SIZE_MAX - len)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (offset + len > sshbuf_len(buf)) {
		திரும்பு wr ?
		    SSH_ERR_NO_BUFFER_SPACE : SSH_ERR_MESSAGE_INCOMPLETE;
	}
	திரும்பு 0;
}

நிலையான முழு
check_roffset(மாறிலி கட்டமைப்பு sshbuf *buf, size_t offset, size_t len,
    மாறிலி u_char **p)
{
	முழு r;

	*p = வெற்று;
	எனில் ((r = check_offset(buf, 0, offset, len)) != 0)
		திரும்பு r;
	*p = sshbuf_ptr(buf) + offset;
	திரும்பு 0;
}

முழு
sshbuf_peek_u64(மாறிலி கட்டமைப்பு sshbuf *buf, size_t offset, uint64_t *valp)
{
	மாறிலி u_char *p = வெற்று;
	முழு r;

	எனில் (valp != வெற்று)
		*valp = 0;
	எனில் ((r = check_roffset(buf, offset, 8, &p)) != 0)
		திரும்பு r;
	எனில் (valp != வெற்று)
		*valp = PEEK_U64(p);
	திரும்பு 0;
}

முழு
sshbuf_peek_u32(மாறிலி கட்டமைப்பு sshbuf *buf, size_t offset, uint32_t *valp)
{
	மாறிலி u_char *p = வெற்று;
	முழு r;

	எனில் (valp != வெற்று)
		*valp = 0;
	எனில் ((r = check_roffset(buf, offset, 4, &p)) != 0)
		திரும்பு r;
	எனில் (valp != வெற்று)
		*valp = PEEK_U32(p);
	திரும்பு 0;
}

முழு
sshbuf_peek_u16(மாறிலி கட்டமைப்பு sshbuf *buf, size_t offset, uint16_t *valp)
{
	மாறிலி u_char *p = வெற்று;
	முழு r;

	எனில் (valp != வெற்று)
		*valp = 0;
	எனில் ((r = check_roffset(buf, offset, 2, &p)) != 0)
		திரும்பு r;
	எனில் (valp != வெற்று)
		*valp = PEEK_U16(p);
	திரும்பு 0;
}

முழு
sshbuf_peek_u8(மாறிலி கட்டமைப்பு sshbuf *buf, size_t offset, u_char *valp)
{
	மாறிலி u_char *p = வெற்று;
	முழு r;

	எனில் (valp != வெற்று)
		*valp = 0;
	எனில் ((r = check_roffset(buf, offset, 1, &p)) != 0)
		திரும்பு r;
	எனில் (valp != வெற்று)
		*valp = *p;
	திரும்பு 0;
}

முழு
sshbuf_get_string(கட்டமைப்பு sshbuf *buf, u_char **valp, size_t *lenp)
{
	மாறிலி u_char *val;
	size_t len;
	முழு r;

	எனில் (valp != வெற்று)
		*valp = வெற்று;
	எனில் (lenp != வெற்று)
		*lenp = 0;
	எனில் ((r = sshbuf_get_string_direct(buf, &val, &len)) < 0)
		திரும்பு r;
	எனில் (valp != வெற்று) {
		எனில் ((*valp = malloc(len + 1)) == வெற்று) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			திரும்பு SSH_ERR_ALLOC_FAIL;
		}
		எனில் (len != 0)
			memcpy(*valp, val, len);
		(*valp)[len] = '\0';
	}
	எனில் (lenp != வெற்று)
		*lenp = len;
	திரும்பு 0;
}

முழு
sshbuf_get_string_direct(கட்டமைப்பு sshbuf *buf, மாறிலி u_char **valp, size_t *lenp)
{
	size_t len;
	மாறிலி u_char *p;
	முழு r;

	எனில் (valp != வெற்று)
		*valp = வெற்று;
	எனில் (lenp != வெற்று)
		*lenp = 0;
	எனில் ((r = sshbuf_peek_string_direct(buf, &p, &len)) < 0)
		திரும்பு r;
	எனில் (valp != வெற்று)
		*valp = p;
	எனில் (lenp != வெற்று)
		*lenp = len;
	எனில் (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	}
	திரும்பு 0;
}

முழு
sshbuf_peek_string_direct(மாறிலி கட்டமைப்பு sshbuf *buf, மாறிலி u_char **valp,
    size_t *lenp)
{
	uint32_t len;
	மாறிலி u_char *p = sshbuf_ptr(buf);

	எனில் (valp != வெற்று)
		*valp = வெற்று;
	எனில் (lenp != வெற்று)
		*lenp = 0;
	எனில் (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		திரும்பு SSH_ERR_MESSAGE_INCOMPLETE;
	}
	len = PEEK_U32(p);
	எனில் (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		திரும்பு SSH_ERR_STRING_TOO_LARGE;
	}
	எனில் (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		திரும்பு SSH_ERR_MESSAGE_INCOMPLETE;
	}
	எனில் (valp != வெற்று)
		*valp = p + 4;
	எனில் (lenp != வெற்று)
		*lenp = len;
	திரும்பு 0;
}

முழு
sshbuf_get_cstring(கட்டமைப்பு sshbuf *buf, எழுத்து **valp, size_t *lenp)
{
	size_t len;
	மாறிலி u_char *p, *z;
	முழு r;

	எனில் (valp != வெற்று)
		*valp = வெற்று;
	எனில் (lenp != வெற்று)
		*lenp = 0;
	எனில் ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		திரும்பு r;
	/* Allow a \0 only at the end of the string */
	எனில் (len > 0 &&
	    (z = memchr(p , '\0', len)) != வெற்று && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		திரும்பு SSH_ERR_INVALID_FORMAT;
	}
	எனில் ((r = sshbuf_skip_string(buf)) != 0)
		திரும்பு -1;
	எனில் (valp != வெற்று) {
		எனில் ((*valp = malloc(len + 1)) == வெற்று) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			திரும்பு SSH_ERR_ALLOC_FAIL;
		}
		எனில் (len != 0)
			memcpy(*valp, p, len);
		(*valp)[len] = '\0';
	}
	எனில் (lenp != வெற்று)
		*lenp = (size_t)len;
	திரும்பு 0;
}

முழு
sshbuf_get_stringb(கட்டமைப்பு sshbuf *buf, கட்டமைப்பு sshbuf *v)
{
	uint32_t len;
	u_char *p;
	முழு r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	எனில் ((r = sshbuf_peek_string_direct(buf, வெற்று, வெற்று)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		திரும்பு r;
	திரும்பு 0;
}

முழு
sshbuf_put(கட்டமைப்பு sshbuf *buf, மாறிலி வெறுமை *v, size_t len)
{
	u_char *p;
	முழு r;

	எனில் ((r = sshbuf_reserve(buf, len, &p)) < 0)
		திரும்பு r;
	எனில் (len != 0)
		memcpy(p, v, len);
	திரும்பு 0;
}

முழு
sshbuf_putb(கட்டமைப்பு sshbuf *buf, மாறிலி கட்டமைப்பு sshbuf *v)
{
	எனில் (v == வெற்று)
		திரும்பு 0;
	திரும்பு sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

முழு
sshbuf_putf(கட்டமைப்பு sshbuf *buf, மாறிலி எழுத்து *fmt, ...)
{
	va_list ap;
	முழு r;

	va_start(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	va_end(ap);
	திரும்பு r;
}

முழு
sshbuf_putfv(கட்டமைப்பு sshbuf *buf, மாறிலி எழுத்து *fmt, va_list ap)
{
	va_list ap2;
	முழு r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	எனில் ((len = vsnprintf(வெற்று, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	}
	எனில் (len == 0) {
		r = 0;
		செல் out; /* Nothing to do */
	}
	va_end(ap2);
	VA_COPY(ap2, ap);
	எனில் ((r = sshbuf_reserve(buf, (size_t)len + 1, &p)) < 0)
		செல் out;
	எனில் ((r = vsnprintf((எழுத்து *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_INTERNAL_ERROR;
		செல் out; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	எனில் ((r = sshbuf_consume_end(buf, 1)) != 0)
		செல் out;
	r = 0;
 out:
	va_end(ap2);
	திரும்பு r;
}

முழு
sshbuf_put_u64(கட்டமைப்பு sshbuf *buf, uint64_t val)
{
	u_char *p;
	முழு r;

	எனில் ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		திரும்பு r;
	POKE_U64(p, val);
	திரும்பு 0;
}

முழு
sshbuf_put_u32(கட்டமைப்பு sshbuf *buf, uint32_t val)
{
	u_char *p;
	முழு r;

	எனில் ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		திரும்பு r;
	POKE_U32(p, val);
	திரும்பு 0;
}

முழு
sshbuf_put_u16(கட்டமைப்பு sshbuf *buf, uint16_t val)
{
	u_char *p;
	முழு r;

	எனில் ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		திரும்பு r;
	POKE_U16(p, val);
	திரும்பு 0;
}

முழு
sshbuf_put_u8(கட்டமைப்பு sshbuf *buf, u_char val)
{
	u_char *p;
	முழு r;

	எனில் ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		திரும்பு r;
	p[0] = val;
	திரும்பு 0;
}

நிலையான முழு
check_woffset(கட்டமைப்பு sshbuf *buf, size_t offset, size_t len, u_char **p)
{
	முழு r;

	*p = வெற்று;
	எனில் ((r = check_offset(buf, 1, offset, len)) != 0)
		திரும்பு r;
	எனில் (sshbuf_mutable_ptr(buf) == வெற்று)
		திரும்பு SSH_ERR_BUFFER_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + offset;
	திரும்பு 0;
}

முழு
sshbuf_poke_u64(கட்டமைப்பு sshbuf *buf, size_t offset, uint64_t val)
{
	u_char *p = வெற்று;
	முழு r;

	எனில் ((r = check_woffset(buf, offset, 8, &p)) != 0)
		திரும்பு r;
	POKE_U64(p, val);
	திரும்பு 0;
}

முழு
sshbuf_poke_u32(கட்டமைப்பு sshbuf *buf, size_t offset, uint32_t val)
{
	u_char *p = வெற்று;
	முழு r;

	எனில் ((r = check_woffset(buf, offset, 4, &p)) != 0)
		திரும்பு r;
	POKE_U32(p, val);
	திரும்பு 0;
}

முழு
sshbuf_poke_u16(கட்டமைப்பு sshbuf *buf, size_t offset, uint16_t val)
{
	u_char *p = வெற்று;
	முழு r;

	எனில் ((r = check_woffset(buf, offset, 2, &p)) != 0)
		திரும்பு r;
	POKE_U16(p, val);
	திரும்பு 0;
}

முழு
sshbuf_poke_u8(கட்டமைப்பு sshbuf *buf, size_t offset, u_char val)
{
	u_char *p = வெற்று;
	முழு r;

	எனில் ((r = check_woffset(buf, offset, 1, &p)) != 0)
		திரும்பு r;
	*p = val;
	திரும்பு 0;
}

முழு
sshbuf_poke(கட்டமைப்பு sshbuf *buf, size_t offset, வெறுமை *v, size_t len)
{
	u_char *p = வெற்று;
	முழு r;

	எனில் ((r = check_woffset(buf, offset, len, &p)) != 0)
		திரும்பு r;
	memcpy(p, v, len);
	திரும்பு 0;
}

முழு
sshbuf_put_string(கட்டமைப்பு sshbuf *buf, மாறிலி வெறுமை *v, size_t len)
{
	u_char *d;
	முழு r;

	எனில் (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		திரும்பு SSH_ERR_NO_BUFFER_SPACE;
	}
	எனில் ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		திரும்பு r;
	POKE_U32(d, len);
	எனில் (len != 0)
		memcpy(d + 4, v, len);
	திரும்பு 0;
}

முழு
sshbuf_put_cstring(கட்டமைப்பு sshbuf *buf, மாறிலி எழுத்து *v)
{
	திரும்பு sshbuf_put_string(buf, v, v == வெற்று ? 0 : strlen(v));
}

முழு
sshbuf_put_stringb(கட்டமைப்பு sshbuf *buf, மாறிலி கட்டமைப்பு sshbuf *v)
{
	எனில் (v == வெற்று)
		திரும்பு sshbuf_put_string(buf, வெற்று, 0);

	திரும்பு sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

முழு
sshbuf_froms(கட்டமைப்பு sshbuf *buf, கட்டமைப்பு sshbuf **bufp)
{
	மாறிலி u_char *p;
	size_t len;
	கட்டமைப்பு sshbuf *ret;
	முழு r;

	எனில் (buf == வெற்று || bufp == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	*bufp = வெற்று;
	எனில் ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		திரும்பு r;
	எனில் ((ret = sshbuf_from(p, len)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_set_parent(ret, buf)) != 0) {
		sshbuf_free(ret);
		திரும்பு r;
	}
	*bufp = ret;
	திரும்பு 0;
}

முழு
sshbuf_put_bignum2_bytes(கட்டமைப்பு sshbuf *buf, மாறிலி வெறுமை *v, size_t len)
{
	u_char *d;
	மாறிலி u_char *s = (மாறிலி u_char *)v;
	முழு r, prepend;

	எனில் (len > SSHBUF_SIZE_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		திரும்பு SSH_ERR_NO_BUFFER_SPACE;
	}
	/* Skip leading zero bytes */
	க்கு (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	எனில் ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		திரும்பு r;
	POKE_U32(d, len + prepend);
	எனில் (prepend)
		d[4] = 0;
	எனில் (len != 0)
		memcpy(d + 4 + prepend, s, len);
	திரும்பு 0;
}

முழு
sshbuf_get_bignum2_bytes_direct(கட்டமைப்பு sshbuf *buf,
    மாறிலி u_char **valp, size_t *lenp)
{
	மாறிலி u_char *d;
	size_t len, olen;
	முழு r;

	எனில் ((r = sshbuf_peek_string_direct(buf, &d, &olen)) < 0)
		திரும்பு r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	எனில் ((len != 0 && (*d & 0x80) != 0))
		திரும்பு SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	எனில் (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		திரும்பு SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	போது (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	எனில் (valp != வெற்று)
		*valp = d;
	எனில் (lenp != வெற்று)
		*lenp = len;
	எனில் (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	}
	திரும்பு 0;
}

முழு
sshbuf_get_nulterminated_string(கட்டமைப்பு sshbuf *buf, size_t maxlen,
    எழுத்து **valp, size_t *lenp)
{
	மாறிலி u_char zero = 0;
	எழுத்து *val = வெற்று;
	size_t len = 0;
	முழு r;

	எனில் (valp != வெற்று)
		*valp = வெற்று;
	எனில் (lenp != வெற்று)
		*lenp = 0;
	எனில் ((r = sshbuf_find(buf, 0, &zero, அளவு(zero), &len)) != 0) {
		எனில் (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			திரும்பு SSH_ERR_MESSAGE_INCOMPLETE;
		திரும்பு r;
	}
	எனில் (len > maxlen)
		திரும்பு SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	எனில் ((val = strdup(sshbuf_ptr(buf))) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_consume(buf, len + 1)) != 0)
		செல் out;
	/* success */
	r = 0;
	எனில் (valp != வெற்று) {
		*valp = val;
		val = வெற்று;
	}
	எனில் (lenp != வெற்று)
		*lenp = len;
 out:
	விடுவி(val);
	திரும்பு r;
}
