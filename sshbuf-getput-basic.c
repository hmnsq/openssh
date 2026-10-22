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
sshbuf_get(संरचना sshbuf *buf, शून्य *v, माप_प्रकार len)
{
	ध्रुव u_char *p = sshbuf_ptr(buf);
	पूर्णाङ्क r;

	यदि ((r = sshbuf_consume(buf, len)) < 0)
		प्रत्यागम r;
	यदि (v != रिक्त && len != 0)
		स_नकल(v, p, len);
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_get_u64(संरचना sshbuf *buf, uint64_t *valp)
{
	ध्रुव u_char *p = sshbuf_ptr(buf);
	पूर्णाङ्क r;

	यदि ((r = sshbuf_consume(buf, 8)) < 0)
		प्रत्यागम r;
	यदि (valp != रिक्त)
		*valp = PEEK_U64(p);
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_get_u32(संरचना sshbuf *buf, uint32_t *valp)
{
	ध्रुव u_char *p = sshbuf_ptr(buf);
	पूर्णाङ्क r;

	यदि ((r = sshbuf_consume(buf, 4)) < 0)
		प्रत्यागम r;
	यदि (valp != रिक्त)
		*valp = PEEK_U32(p);
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_get_u16(संरचना sshbuf *buf, uint16_t *valp)
{
	ध्रुव u_char *p = sshbuf_ptr(buf);
	पूर्णाङ्क r;

	यदि ((r = sshbuf_consume(buf, 2)) < 0)
		प्रत्यागम r;
	यदि (valp != रिक्त)
		*valp = PEEK_U16(p);
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_get_u8(संरचना sshbuf *buf, u_char *valp)
{
	ध्रुव u_char *p = sshbuf_ptr(buf);
	पूर्णाङ्क r;

	यदि ((r = sshbuf_consume(buf, 1)) < 0)
		प्रत्यागम r;
	यदि (valp != रिक्त)
		*valp = (uint8_t)*p;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
check_offset(ध्रुव संरचना sshbuf *buf, पूर्णाङ्क wr, माप_प्रकार offset, माप_प्रकार len)
{
	यदि (sshbuf_ptr(buf) == रिक्त) /* calls sshbuf_check_sanity() */
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	यदि (offset >= SIZE_MAX - len)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	यदि (offset + len > sshbuf_len(buf)) {
		प्रत्यागम wr ?
		    SSH_ERR_NO_BUFFER_SPACE : SSH_ERR_MESSAGE_INCOMPLETE;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
check_roffset(ध्रुव संरचना sshbuf *buf, माप_प्रकार offset, माप_प्रकार len,
    ध्रुव u_char **p)
{
	पूर्णाङ्क r;

	*p = रिक्त;
	यदि ((r = check_offset(buf, 0, offset, len)) != 0)
		प्रत्यागम r;
	*p = sshbuf_ptr(buf) + offset;
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_peek_u64(ध्रुव संरचना sshbuf *buf, माप_प्रकार offset, uint64_t *valp)
{
	ध्रुव u_char *p = रिक्त;
	पूर्णाङ्क r;

	यदि (valp != रिक्त)
		*valp = 0;
	यदि ((r = check_roffset(buf, offset, 8, &p)) != 0)
		प्रत्यागम r;
	यदि (valp != रिक्त)
		*valp = PEEK_U64(p);
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_peek_u32(ध्रुव संरचना sshbuf *buf, माप_प्रकार offset, uint32_t *valp)
{
	ध्रुव u_char *p = रिक्त;
	पूर्णाङ्क r;

	यदि (valp != रिक्त)
		*valp = 0;
	यदि ((r = check_roffset(buf, offset, 4, &p)) != 0)
		प्रत्यागम r;
	यदि (valp != रिक्त)
		*valp = PEEK_U32(p);
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_peek_u16(ध्रुव संरचना sshbuf *buf, माप_प्रकार offset, uint16_t *valp)
{
	ध्रुव u_char *p = रिक्त;
	पूर्णाङ्क r;

	यदि (valp != रिक्त)
		*valp = 0;
	यदि ((r = check_roffset(buf, offset, 2, &p)) != 0)
		प्रत्यागम r;
	यदि (valp != रिक्त)
		*valp = PEEK_U16(p);
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_peek_u8(ध्रुव संरचना sshbuf *buf, माप_प्रकार offset, u_char *valp)
{
	ध्रुव u_char *p = रिक्त;
	पूर्णाङ्क r;

	यदि (valp != रिक्त)
		*valp = 0;
	यदि ((r = check_roffset(buf, offset, 1, &p)) != 0)
		प्रत्यागम r;
	यदि (valp != रिक्त)
		*valp = *p;
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_get_string(संरचना sshbuf *buf, u_char **valp, माप_प्रकार *lenp)
{
	ध्रुव u_char *val;
	माप_प्रकार len;
	पूर्णाङ्क r;

	यदि (valp != रिक्त)
		*valp = रिक्त;
	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि ((r = sshbuf_get_string_direct(buf, &val, &len)) < 0)
		प्रत्यागम r;
	यदि (valp != रिक्त) {
		यदि ((*valp = दो_स्मृति(len + 1)) == रिक्त) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			प्रत्यागम SSH_ERR_ALLOC_FAIL;
		}
		यदि (len != 0)
			स_नकल(*valp, val, len);
		(*valp)[len] = '\0';
	}
	यदि (lenp != रिक्त)
		*lenp = len;
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_get_string_direct(संरचना sshbuf *buf, ध्रुव u_char **valp, माप_प्रकार *lenp)
{
	माप_प्रकार len;
	ध्रुव u_char *p;
	पूर्णाङ्क r;

	यदि (valp != रिक्त)
		*valp = रिक्त;
	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि ((r = sshbuf_peek_string_direct(buf, &p, &len)) < 0)
		प्रत्यागम r;
	यदि (valp != रिक्त)
		*valp = p;
	यदि (lenp != रिक्त)
		*lenp = len;
	यदि (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_peek_string_direct(ध्रुव संरचना sshbuf *buf, ध्रुव u_char **valp,
    माप_प्रकार *lenp)
{
	uint32_t len;
	ध्रुव u_char *p = sshbuf_ptr(buf);

	यदि (valp != रिक्त)
		*valp = रिक्त;
	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		प्रत्यागम SSH_ERR_MESSAGE_INCOMPLETE;
	}
	len = PEEK_U32(p);
	यदि (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		प्रत्यागम SSH_ERR_STRING_TOO_LARGE;
	}
	यदि (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		प्रत्यागम SSH_ERR_MESSAGE_INCOMPLETE;
	}
	यदि (valp != रिक्त)
		*valp = p + 4;
	यदि (lenp != रिक्त)
		*lenp = len;
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_get_cstring(संरचना sshbuf *buf, वर्ण **valp, माप_प्रकार *lenp)
{
	माप_प्रकार len;
	ध्रुव u_char *p, *z;
	पूर्णाङ्क r;

	यदि (valp != रिक्त)
		*valp = रिक्त;
	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		प्रत्यागम r;
	/* Allow a \0 only at the end of the string */
	यदि (len > 0 &&
	    (z = स_प्रथम(p , '\0', len)) != रिक्त && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	}
	यदि ((r = sshbuf_skip_string(buf)) != 0)
		प्रत्यागम -1;
	यदि (valp != रिक्त) {
		यदि ((*valp = दो_स्मृति(len + 1)) == रिक्त) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			प्रत्यागम SSH_ERR_ALLOC_FAIL;
		}
		यदि (len != 0)
			स_नकल(*valp, p, len);
		(*valp)[len] = '\0';
	}
	यदि (lenp != रिक्त)
		*lenp = (माप_प्रकार)len;
	प्रत्यागम 0;
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
	यदि ((r = sshbuf_peek_string_direct(buf, रिक्त, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		प्रत्यागम r;
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_put(संरचना sshbuf *buf, ध्रुव शून्य *v, माप_प्रकार len)
{
	u_char *p;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_reserve(buf, len, &p)) < 0)
		प्रत्यागम r;
	यदि (len != 0)
		स_नकल(p, v, len);
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_putb(संरचना sshbuf *buf, ध्रुव संरचना sshbuf *v)
{
	यदि (v == रिक्त)
		प्रत्यागम 0;
	प्रत्यागम sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

पूर्णाङ्क
sshbuf_putf(संरचना sshbuf *buf, ध्रुव वर्ण *fmt, ...)
{
	बहु_सूची ap;
	पूर्णाङ्क r;

	बहु_शुरू(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	बहु_पूर्ण(ap);
	प्रत्यागम r;
}

पूर्णाङ्क
sshbuf_putfv(संरचना sshbuf *buf, ध्रुव वर्ण *fmt, बहु_सूची ap)
{
	बहु_सूची ap2;
	पूर्णाङ्क r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	यदि ((len = vsnprintf(रिक्त, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	यदि (len == 0) {
		r = 0;
		गच्छ out; /* Nothing to do */
	}
	बहु_पूर्ण(ap2);
	VA_COPY(ap2, ap);
	यदि ((r = sshbuf_reserve(buf, (माप_प्रकार)len + 1, &p)) < 0)
		गच्छ out;
	यदि ((r = vsnprintf((वर्ण *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_INTERNAL_ERROR;
		गच्छ out; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	यदि ((r = sshbuf_consume_end(buf, 1)) != 0)
		गच्छ out;
	r = 0;
 out:
	बहु_पूर्ण(ap2);
	प्रत्यागम r;
}

पूर्णाङ्क
sshbuf_put_u64(संरचना sshbuf *buf, uint64_t val)
{
	u_char *p;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		प्रत्यागम r;
	POKE_U64(p, val);
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_put_u32(संरचना sshbuf *buf, uint32_t val)
{
	u_char *p;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		प्रत्यागम r;
	POKE_U32(p, val);
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_put_u16(संरचना sshbuf *buf, uint16_t val)
{
	u_char *p;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		प्रत्यागम r;
	POKE_U16(p, val);
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_put_u8(संरचना sshbuf *buf, u_char val)
{
	u_char *p;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		प्रत्यागम r;
	p[0] = val;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
check_woffset(संरचना sshbuf *buf, माप_प्रकार offset, माप_प्रकार len, u_char **p)
{
	पूर्णाङ्क r;

	*p = रिक्त;
	यदि ((r = check_offset(buf, 1, offset, len)) != 0)
		प्रत्यागम r;
	यदि (sshbuf_mutable_ptr(buf) == रिक्त)
		प्रत्यागम SSH_ERR_BUFFER_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + offset;
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_poke_u64(संरचना sshbuf *buf, माप_प्रकार offset, uint64_t val)
{
	u_char *p = रिक्त;
	पूर्णाङ्क r;

	यदि ((r = check_woffset(buf, offset, 8, &p)) != 0)
		प्रत्यागम r;
	POKE_U64(p, val);
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_poke_u32(संरचना sshbuf *buf, माप_प्रकार offset, uint32_t val)
{
	u_char *p = रिक्त;
	पूर्णाङ्क r;

	यदि ((r = check_woffset(buf, offset, 4, &p)) != 0)
		प्रत्यागम r;
	POKE_U32(p, val);
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_poke_u16(संरचना sshbuf *buf, माप_प्रकार offset, uint16_t val)
{
	u_char *p = रिक्त;
	पूर्णाङ्क r;

	यदि ((r = check_woffset(buf, offset, 2, &p)) != 0)
		प्रत्यागम r;
	POKE_U16(p, val);
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_poke_u8(संरचना sshbuf *buf, माप_प्रकार offset, u_char val)
{
	u_char *p = रिक्त;
	पूर्णाङ्क r;

	यदि ((r = check_woffset(buf, offset, 1, &p)) != 0)
		प्रत्यागम r;
	*p = val;
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_poke(संरचना sshbuf *buf, माप_प्रकार offset, शून्य *v, माप_प्रकार len)
{
	u_char *p = रिक्त;
	पूर्णाङ्क r;

	यदि ((r = check_woffset(buf, offset, len, &p)) != 0)
		प्रत्यागम r;
	स_नकल(p, v, len);
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_put_string(संरचना sshbuf *buf, ध्रुव शून्य *v, माप_प्रकार len)
{
	u_char *d;
	पूर्णाङ्क r;

	यदि (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		प्रत्यागम SSH_ERR_NO_BUFFER_SPACE;
	}
	यदि ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		प्रत्यागम r;
	POKE_U32(d, len);
	यदि (len != 0)
		स_नकल(d + 4, v, len);
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_put_cstring(संरचना sshbuf *buf, ध्रुव वर्ण *v)
{
	प्रत्यागम sshbuf_put_string(buf, v, v == रिक्त ? 0 : म_माप(v));
}

पूर्णाङ्क
sshbuf_put_stringb(संरचना sshbuf *buf, ध्रुव संरचना sshbuf *v)
{
	यदि (v == रिक्त)
		प्रत्यागम sshbuf_put_string(buf, रिक्त, 0);

	प्रत्यागम sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

पूर्णाङ्क
sshbuf_froms(संरचना sshbuf *buf, संरचना sshbuf **bufp)
{
	ध्रुव u_char *p;
	माप_प्रकार len;
	संरचना sshbuf *ret;
	पूर्णाङ्क r;

	यदि (buf == रिक्त || bufp == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	*bufp = रिक्त;
	यदि ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		प्रत्यागम r;
	यदि ((ret = sshbuf_from(p, len)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_set_parent(ret, buf)) != 0) {
		sshbuf_free(ret);
		प्रत्यागम r;
	}
	*bufp = ret;
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_put_bignum2_bytes(संरचना sshbuf *buf, ध्रुव शून्य *v, माप_प्रकार len)
{
	u_char *d;
	ध्रुव u_char *s = (ध्रुव u_char *)v;
	पूर्णाङ्क r, prepend;

	यदि (len > SSHBUF_SIZE_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		प्रत्यागम SSH_ERR_NO_BUFFER_SPACE;
	}
	/* Skip leading zero bytes */
	प्रति (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	यदि ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		प्रत्यागम r;
	POKE_U32(d, len + prepend);
	यदि (prepend)
		d[4] = 0;
	यदि (len != 0)
		स_नकल(d + 4 + prepend, s, len);
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_get_bignum2_bytes_direct(संरचना sshbuf *buf,
    ध्रुव u_char **valp, माप_प्रकार *lenp)
{
	ध्रुव u_char *d;
	माप_प्रकार len, olen;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_peek_string_direct(buf, &d, &olen)) < 0)
		प्रत्यागम r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	यदि ((len != 0 && (*d & 0x80) != 0))
		प्रत्यागम SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	यदि (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		प्रत्यागम SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	यावत् (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	यदि (valp != रिक्त)
		*valp = d;
	यदि (lenp != रिक्त)
		*lenp = len;
	यदि (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_get_nulterminated_string(संरचना sshbuf *buf, माप_प्रकार maxlen,
    वर्ण **valp, माप_प्रकार *lenp)
{
	ध्रुव u_char zero = 0;
	वर्ण *val = रिक्त;
	माप_प्रकार len = 0;
	पूर्णाङ्क r;

	यदि (valp != रिक्त)
		*valp = रिक्त;
	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि ((r = sshbuf_find(buf, 0, &zero, परिमाण(zero), &len)) != 0) {
		यदि (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			प्रत्यागम SSH_ERR_MESSAGE_INCOMPLETE;
		प्रत्यागम r;
	}
	यदि (len > maxlen)
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	यदि ((val = strdup(sshbuf_ptr(buf))) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_consume(buf, len + 1)) != 0)
		गच्छ out;
	/* success */
	r = 0;
	यदि (valp != रिक्त) {
		*valp = val;
		val = रिक्त;
	}
	यदि (lenp != रिक्त)
		*lenp = len;
 out:
	मुक्त(val);
	प्रत्यागम r;
}
