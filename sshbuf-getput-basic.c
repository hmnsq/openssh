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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>

#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <stdint.h>

#অন্তর্ভাৱ "ssherr.h"
#define SSHBUF_INTERNAL
#অন্তর্ভাৱ "sshbuf.h"

পূর্ণাঙ্ক
sshbuf_get(সংরচনা sshbuf *buf, শূন্য *v, size_t len)
{
	ধ্রুৱ u_char *p = sshbuf_ptr(buf);
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_consume(buf, len)) < 0)
		ঘূৰাই r;
	যদি (v != রিক্ত && len != 0)
		memcpy(v, p, len);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_get_u64(সংরচনা sshbuf *buf, uint64_t *valp)
{
	ধ্রুৱ u_char *p = sshbuf_ptr(buf);
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_consume(buf, 8)) < 0)
		ঘূৰাই r;
	যদি (valp != রিক্ত)
		*valp = PEEK_U64(p);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_get_u32(সংরচনা sshbuf *buf, uint32_t *valp)
{
	ধ্রুৱ u_char *p = sshbuf_ptr(buf);
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_consume(buf, 4)) < 0)
		ঘূৰাই r;
	যদি (valp != রিক্ত)
		*valp = PEEK_U32(p);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_get_u16(সংরচনা sshbuf *buf, uint16_t *valp)
{
	ধ্রুৱ u_char *p = sshbuf_ptr(buf);
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_consume(buf, 2)) < 0)
		ঘূৰাই r;
	যদি (valp != রিক্ত)
		*valp = PEEK_U16(p);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_get_u8(সংরচনা sshbuf *buf, u_char *valp)
{
	ধ্রুৱ u_char *p = sshbuf_ptr(buf);
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_consume(buf, 1)) < 0)
		ঘূৰাই r;
	যদি (valp != রিক্ত)
		*valp = (uint8_t)*p;
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
check_offset(ধ্রুৱ সংরচনা sshbuf *buf, পূর্ণাঙ্ক wr, size_t offset, size_t len)
{
	যদি (sshbuf_ptr(buf) == রিক্ত) /* calls sshbuf_check_sanity() */
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;
	যদি (offset >= SIZE_MAX - len)
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;
	যদি (offset + len > sshbuf_len(buf)) {
		ঘূৰাই wr ?
		    SSH_ERR_NO_BUFFER_SPACE : SSH_ERR_MESSAGE_INCOMPLETE;
	}
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
check_roffset(ধ্রুৱ সংরচনা sshbuf *buf, size_t offset, size_t len,
    ধ্রুৱ u_char **p)
{
	পূর্ণাঙ্ক r;

	*p = রিক্ত;
	যদি ((r = check_offset(buf, 0, offset, len)) != 0)
		ঘূৰাই r;
	*p = sshbuf_ptr(buf) + offset;
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_peek_u64(ধ্রুৱ সংরচনা sshbuf *buf, size_t offset, uint64_t *valp)
{
	ধ্রুৱ u_char *p = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি (valp != রিক্ত)
		*valp = 0;
	যদি ((r = check_roffset(buf, offset, 8, &p)) != 0)
		ঘূৰাই r;
	যদি (valp != রিক্ত)
		*valp = PEEK_U64(p);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_peek_u32(ধ্রুৱ সংরচনা sshbuf *buf, size_t offset, uint32_t *valp)
{
	ধ্রুৱ u_char *p = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি (valp != রিক্ত)
		*valp = 0;
	যদি ((r = check_roffset(buf, offset, 4, &p)) != 0)
		ঘূৰাই r;
	যদি (valp != রিক্ত)
		*valp = PEEK_U32(p);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_peek_u16(ধ্রুৱ সংরচনা sshbuf *buf, size_t offset, uint16_t *valp)
{
	ধ্রুৱ u_char *p = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি (valp != রিক্ত)
		*valp = 0;
	যদি ((r = check_roffset(buf, offset, 2, &p)) != 0)
		ঘূৰাই r;
	যদি (valp != রিক্ত)
		*valp = PEEK_U16(p);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_peek_u8(ধ্রুৱ সংরচনা sshbuf *buf, size_t offset, u_char *valp)
{
	ধ্রুৱ u_char *p = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি (valp != রিক্ত)
		*valp = 0;
	যদি ((r = check_roffset(buf, offset, 1, &p)) != 0)
		ঘূৰাই r;
	যদি (valp != রিক্ত)
		*valp = *p;
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_get_string(সংরচনা sshbuf *buf, u_char **valp, size_t *lenp)
{
	ধ্রুৱ u_char *val;
	size_t len;
	পূর্ণাঙ্ক r;

	যদি (valp != রিক্ত)
		*valp = রিক্ত;
	যদি (lenp != রিক্ত)
		*lenp = 0;
	যদি ((r = sshbuf_get_string_direct(buf, &val, &len)) < 0)
		ঘূৰাই r;
	যদি (valp != রিক্ত) {
		যদি ((*valp = malloc(len + 1)) == রিক্ত) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			ঘূৰাই SSH_ERR_ALLOC_FAIL;
		}
		যদি (len != 0)
			memcpy(*valp, val, len);
		(*valp)[len] = '\0';
	}
	যদি (lenp != রিক্ত)
		*lenp = len;
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_get_string_direct(সংরচনা sshbuf *buf, ধ্রুৱ u_char **valp, size_t *lenp)
{
	size_t len;
	ধ্রুৱ u_char *p;
	পূর্ণাঙ্ক r;

	যদি (valp != রিক্ত)
		*valp = রিক্ত;
	যদি (lenp != রিক্ত)
		*lenp = 0;
	যদি ((r = sshbuf_peek_string_direct(buf, &p, &len)) < 0)
		ঘূৰাই r;
	যদি (valp != রিক্ত)
		*valp = p;
	যদি (lenp != রিক্ত)
		*lenp = len;
	যদি (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;
	}
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_peek_string_direct(ধ্রুৱ সংরচনা sshbuf *buf, ধ্রুৱ u_char **valp,
    size_t *lenp)
{
	uint32_t len;
	ধ্রুৱ u_char *p = sshbuf_ptr(buf);

	যদি (valp != রিক্ত)
		*valp = রিক্ত;
	যদি (lenp != রিক্ত)
		*lenp = 0;
	যদি (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		ঘূৰাই SSH_ERR_MESSAGE_INCOMPLETE;
	}
	len = PEEK_U32(p);
	যদি (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		ঘূৰাই SSH_ERR_STRING_TOO_LARGE;
	}
	যদি (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		ঘূৰাই SSH_ERR_MESSAGE_INCOMPLETE;
	}
	যদি (valp != রিক্ত)
		*valp = p + 4;
	যদি (lenp != রিক্ত)
		*lenp = len;
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_get_cstring(সংরচনা sshbuf *buf, ৱর্ণ **valp, size_t *lenp)
{
	size_t len;
	ধ্রুৱ u_char *p, *z;
	পূর্ণাঙ্ক r;

	যদি (valp != রিক্ত)
		*valp = রিক্ত;
	যদি (lenp != রিক্ত)
		*lenp = 0;
	যদি ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		ঘূৰাই r;
	/* Allow a \0 only at the end of the string */
	যদি (len > 0 &&
	    (z = memchr(p , '\0', len)) != রিক্ত && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		ঘূৰাই SSH_ERR_INVALID_FORMAT;
	}
	যদি ((r = sshbuf_skip_string(buf)) != 0)
		ঘূৰাই -1;
	যদি (valp != রিক্ত) {
		যদি ((*valp = malloc(len + 1)) == রিক্ত) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			ঘূৰাই SSH_ERR_ALLOC_FAIL;
		}
		যদি (len != 0)
			memcpy(*valp, p, len);
		(*valp)[len] = '\0';
	}
	যদি (lenp != রিক্ত)
		*lenp = (size_t)len;
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_get_stringb(সংরচনা sshbuf *buf, সংরচনা sshbuf *v)
{
	uint32_t len;
	u_char *p;
	পূর্ণাঙ্ক r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	যদি ((r = sshbuf_peek_string_direct(buf, রিক্ত, রিক্ত)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		ঘূৰাই r;
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_put(সংরচনা sshbuf *buf, ধ্রুৱ শূন্য *v, size_t len)
{
	u_char *p;
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_reserve(buf, len, &p)) < 0)
		ঘূৰাই r;
	যদি (len != 0)
		memcpy(p, v, len);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_putb(সংরচনা sshbuf *buf, ধ্রুৱ সংরচনা sshbuf *v)
{
	যদি (v == রিক্ত)
		ঘূৰাই 0;
	ঘূৰাই sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

পূর্ণাঙ্ক
sshbuf_putf(সংরচনা sshbuf *buf, ধ্রুৱ ৱর্ণ *fmt, ...)
{
	va_list ap;
	পূর্ণাঙ্ক r;

	va_start(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	va_end(ap);
	ঘূৰাই r;
}

পূর্ণাঙ্ক
sshbuf_putfv(সংরচনা sshbuf *buf, ধ্রুৱ ৱর্ণ *fmt, va_list ap)
{
	va_list ap2;
	পূর্ণাঙ্ক r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	যদি ((len = vsnprintf(রিক্ত, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		গচ্ছ out;
	}
	যদি (len == 0) {
		r = 0;
		গচ্ছ out; /* Nothing to do */
	}
	va_end(ap2);
	VA_COPY(ap2, ap);
	যদি ((r = sshbuf_reserve(buf, (size_t)len + 1, &p)) < 0)
		গচ্ছ out;
	যদি ((r = vsnprintf((ৱর্ণ *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_INTERNAL_ERROR;
		গচ্ছ out; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	যদি ((r = sshbuf_consume_end(buf, 1)) != 0)
		গচ্ছ out;
	r = 0;
 out:
	va_end(ap2);
	ঘূৰাই r;
}

পূর্ণাঙ্ক
sshbuf_put_u64(সংরচনা sshbuf *buf, uint64_t val)
{
	u_char *p;
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		ঘূৰাই r;
	POKE_U64(p, val);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_put_u32(সংরচনা sshbuf *buf, uint32_t val)
{
	u_char *p;
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		ঘূৰাই r;
	POKE_U32(p, val);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_put_u16(সংরচনা sshbuf *buf, uint16_t val)
{
	u_char *p;
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		ঘূৰাই r;
	POKE_U16(p, val);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_put_u8(সংরচনা sshbuf *buf, u_char val)
{
	u_char *p;
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		ঘূৰাই r;
	p[0] = val;
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
check_woffset(সংরচনা sshbuf *buf, size_t offset, size_t len, u_char **p)
{
	পূর্ণাঙ্ক r;

	*p = রিক্ত;
	যদি ((r = check_offset(buf, 1, offset, len)) != 0)
		ঘূৰাই r;
	যদি (sshbuf_mutable_ptr(buf) == রিক্ত)
		ঘূৰাই SSH_ERR_BUFFER_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + offset;
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_poke_u64(সংরচনা sshbuf *buf, size_t offset, uint64_t val)
{
	u_char *p = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি ((r = check_woffset(buf, offset, 8, &p)) != 0)
		ঘূৰাই r;
	POKE_U64(p, val);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_poke_u32(সংরচনা sshbuf *buf, size_t offset, uint32_t val)
{
	u_char *p = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি ((r = check_woffset(buf, offset, 4, &p)) != 0)
		ঘূৰাই r;
	POKE_U32(p, val);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_poke_u16(সংরচনা sshbuf *buf, size_t offset, uint16_t val)
{
	u_char *p = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি ((r = check_woffset(buf, offset, 2, &p)) != 0)
		ঘূৰাই r;
	POKE_U16(p, val);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_poke_u8(সংরচনা sshbuf *buf, size_t offset, u_char val)
{
	u_char *p = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি ((r = check_woffset(buf, offset, 1, &p)) != 0)
		ঘূৰাই r;
	*p = val;
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_poke(সংরচনা sshbuf *buf, size_t offset, শূন্য *v, size_t len)
{
	u_char *p = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি ((r = check_woffset(buf, offset, len, &p)) != 0)
		ঘূৰাই r;
	memcpy(p, v, len);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_put_string(সংরচনা sshbuf *buf, ধ্রুৱ শূন্য *v, size_t len)
{
	u_char *d;
	পূর্ণাঙ্ক r;

	যদি (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		ঘূৰাই SSH_ERR_NO_BUFFER_SPACE;
	}
	যদি ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		ঘূৰাই r;
	POKE_U32(d, len);
	যদি (len != 0)
		memcpy(d + 4, v, len);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_put_cstring(সংরচনা sshbuf *buf, ধ্রুৱ ৱর্ণ *v)
{
	ঘূৰাই sshbuf_put_string(buf, v, v == রিক্ত ? 0 : strlen(v));
}

পূর্ণাঙ্ক
sshbuf_put_stringb(সংরচনা sshbuf *buf, ধ্রুৱ সংরচনা sshbuf *v)
{
	যদি (v == রিক্ত)
		ঘূৰাই sshbuf_put_string(buf, রিক্ত, 0);

	ঘূৰাই sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

পূর্ণাঙ্ক
sshbuf_froms(সংরচনা sshbuf *buf, সংরচনা sshbuf **bufp)
{
	ধ্রুৱ u_char *p;
	size_t len;
	সংরচনা sshbuf *ret;
	পূর্ণাঙ্ক r;

	যদি (buf == রিক্ত || bufp == রিক্ত)
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;
	*bufp = রিক্ত;
	যদি ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		ঘূৰাই r;
	যদি ((ret = sshbuf_from(p, len)) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_set_parent(ret, buf)) != 0) {
		sshbuf_free(ret);
		ঘূৰাই r;
	}
	*bufp = ret;
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_put_bignum2_bytes(সংরচনা sshbuf *buf, ধ্রুৱ শূন্য *v, size_t len)
{
	u_char *d;
	ধ্রুৱ u_char *s = (ধ্রুৱ u_char *)v;
	পূর্ণাঙ্ক r, prepend;

	যদি (len > SSHBUF_SIZE_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		ঘূৰাই SSH_ERR_NO_BUFFER_SPACE;
	}
	/* Skip leading zero bytes */
	বাবে (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	যদি ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		ঘূৰাই r;
	POKE_U32(d, len + prepend);
	যদি (prepend)
		d[4] = 0;
	যদি (len != 0)
		memcpy(d + 4 + prepend, s, len);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_get_bignum2_bytes_direct(সংরচনা sshbuf *buf,
    ধ্রুৱ u_char **valp, size_t *lenp)
{
	ধ্রুৱ u_char *d;
	size_t len, olen;
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_peek_string_direct(buf, &d, &olen)) < 0)
		ঘূৰাই r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	যদি ((len != 0 && (*d & 0x80) != 0))
		ঘূৰাই SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	যদি (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		ঘূৰাই SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	যেতিয়ালৈ (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	যদি (valp != রিক্ত)
		*valp = d;
	যদি (lenp != রিক্ত)
		*lenp = len;
	যদি (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;
	}
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_get_nulterminated_string(সংরচনা sshbuf *buf, size_t maxlen,
    ৱর্ণ **valp, size_t *lenp)
{
	ধ্রুৱ u_char zero = 0;
	ৱর্ণ *val = রিক্ত;
	size_t len = 0;
	পূর্ণাঙ্ক r;

	যদি (valp != রিক্ত)
		*valp = রিক্ত;
	যদি (lenp != রিক্ত)
		*lenp = 0;
	যদি ((r = sshbuf_find(buf, 0, &zero, পরিমাণ(zero), &len)) != 0) {
		যদি (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			ঘূৰাই SSH_ERR_MESSAGE_INCOMPLETE;
		ঘূৰাই r;
	}
	যদি (len > maxlen)
		ঘূৰাই SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	যদি ((val = strdup(sshbuf_ptr(buf))) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_consume(buf, len + 1)) != 0)
		গচ্ছ out;
	/* success */
	r = 0;
	যদি (valp != রিক্ত) {
		*valp = val;
		val = রিক্ত;
	}
	যদি (lenp != রিক্ত)
		*lenp = len;
 out:
	মুক্ত(val);
	ঘূৰাই r;
}
