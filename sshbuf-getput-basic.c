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

पूर्णांक
sshbuf_get(संरचना sshbuf *buf, शून्य *v, माप_प्रकार len)
{
	स्थिरांक u_char *p = sshbuf_ptr(buf);
	पूर्णांक r;

	जर ((r = sshbuf_consume(buf, len)) < 0)
		परत r;
	जर (v != रिक्त && len != 0)
		स_नकल(v, p, len);
	परत 0;
}

पूर्णांक
sshbuf_get_u64(संरचना sshbuf *buf, uint64_t *valp)
{
	स्थिरांक u_char *p = sshbuf_ptr(buf);
	पूर्णांक r;

	जर ((r = sshbuf_consume(buf, 8)) < 0)
		परत r;
	जर (valp != रिक्त)
		*valp = PEEK_U64(p);
	परत 0;
}

पूर्णांक
sshbuf_get_u32(संरचना sshbuf *buf, uint32_t *valp)
{
	स्थिरांक u_char *p = sshbuf_ptr(buf);
	पूर्णांक r;

	जर ((r = sshbuf_consume(buf, 4)) < 0)
		परत r;
	जर (valp != रिक्त)
		*valp = PEEK_U32(p);
	परत 0;
}

पूर्णांक
sshbuf_get_u16(संरचना sshbuf *buf, uint16_t *valp)
{
	स्थिरांक u_char *p = sshbuf_ptr(buf);
	पूर्णांक r;

	जर ((r = sshbuf_consume(buf, 2)) < 0)
		परत r;
	जर (valp != रिक्त)
		*valp = PEEK_U16(p);
	परत 0;
}

पूर्णांक
sshbuf_get_u8(संरचना sshbuf *buf, u_char *valp)
{
	स्थिरांक u_char *p = sshbuf_ptr(buf);
	पूर्णांक r;

	जर ((r = sshbuf_consume(buf, 1)) < 0)
		परत r;
	जर (valp != रिक्त)
		*valp = (uint8_t)*p;
	परत 0;
}

स्थिर पूर्णांक
check_offset(स्थिरांक संरचना sshbuf *buf, पूर्णांक wr, माप_प्रकार offset, माप_प्रकार len)
{
	जर (sshbuf_ptr(buf) == रिक्त) /* calls sshbuf_check_sanity() */
		परत SSH_ERR_INTERNAL_ERROR;
	जर (offset >= SIZE_MAX - len)
		परत SSH_ERR_INVALID_ARGUMENT;
	जर (offset + len > sshbuf_len(buf)) {
		परत wr ?
		    SSH_ERR_NO_BUFFER_SPACE : SSH_ERR_MESSAGE_INCOMPLETE;
	}
	परत 0;
}

स्थिर पूर्णांक
check_roffset(स्थिरांक संरचना sshbuf *buf, माप_प्रकार offset, माप_प्रकार len,
    स्थिरांक u_char **p)
{
	पूर्णांक r;

	*p = रिक्त;
	जर ((r = check_offset(buf, 0, offset, len)) != 0)
		परत r;
	*p = sshbuf_ptr(buf) + offset;
	परत 0;
}

पूर्णांक
sshbuf_peek_u64(स्थिरांक संरचना sshbuf *buf, माप_प्रकार offset, uint64_t *valp)
{
	स्थिरांक u_char *p = रिक्त;
	पूर्णांक r;

	जर (valp != रिक्त)
		*valp = 0;
	जर ((r = check_roffset(buf, offset, 8, &p)) != 0)
		परत r;
	जर (valp != रिक्त)
		*valp = PEEK_U64(p);
	परत 0;
}

पूर्णांक
sshbuf_peek_u32(स्थिरांक संरचना sshbuf *buf, माप_प्रकार offset, uint32_t *valp)
{
	स्थिरांक u_char *p = रिक्त;
	पूर्णांक r;

	जर (valp != रिक्त)
		*valp = 0;
	जर ((r = check_roffset(buf, offset, 4, &p)) != 0)
		परत r;
	जर (valp != रिक्त)
		*valp = PEEK_U32(p);
	परत 0;
}

पूर्णांक
sshbuf_peek_u16(स्थिरांक संरचना sshbuf *buf, माप_प्रकार offset, uint16_t *valp)
{
	स्थिरांक u_char *p = रिक्त;
	पूर्णांक r;

	जर (valp != रिक्त)
		*valp = 0;
	जर ((r = check_roffset(buf, offset, 2, &p)) != 0)
		परत r;
	जर (valp != रिक्त)
		*valp = PEEK_U16(p);
	परत 0;
}

पूर्णांक
sshbuf_peek_u8(स्थिरांक संरचना sshbuf *buf, माप_प्रकार offset, u_char *valp)
{
	स्थिरांक u_char *p = रिक्त;
	पूर्णांक r;

	जर (valp != रिक्त)
		*valp = 0;
	जर ((r = check_roffset(buf, offset, 1, &p)) != 0)
		परत r;
	जर (valp != रिक्त)
		*valp = *p;
	परत 0;
}

पूर्णांक
sshbuf_get_string(संरचना sshbuf *buf, u_char **valp, माप_प्रकार *lenp)
{
	स्थिरांक u_char *val;
	माप_प्रकार len;
	पूर्णांक r;

	जर (valp != रिक्त)
		*valp = रिक्त;
	जर (lenp != रिक्त)
		*lenp = 0;
	जर ((r = sshbuf_get_string_direct(buf, &val, &len)) < 0)
		परत r;
	जर (valp != रिक्त) {
		जर ((*valp = दो_स्मृति(len + 1)) == रिक्त) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			परत SSH_ERR_ALLOC_FAIL;
		}
		जर (len != 0)
			स_नकल(*valp, val, len);
		(*valp)[len] = '\0';
	}
	जर (lenp != रिक्त)
		*lenp = len;
	परत 0;
}

पूर्णांक
sshbuf_get_string_direct(संरचना sshbuf *buf, स्थिरांक u_char **valp, माप_प्रकार *lenp)
{
	माप_प्रकार len;
	स्थिरांक u_char *p;
	पूर्णांक r;

	जर (valp != रिक्त)
		*valp = रिक्त;
	जर (lenp != रिक्त)
		*lenp = 0;
	जर ((r = sshbuf_peek_string_direct(buf, &p, &len)) < 0)
		परत r;
	जर (valp != रिक्त)
		*valp = p;
	जर (lenp != रिक्त)
		*lenp = len;
	जर (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		परत SSH_ERR_INTERNAL_ERROR;
	}
	परत 0;
}

पूर्णांक
sshbuf_peek_string_direct(स्थिरांक संरचना sshbuf *buf, स्थिरांक u_char **valp,
    माप_प्रकार *lenp)
{
	uint32_t len;
	स्थिरांक u_char *p = sshbuf_ptr(buf);

	जर (valp != रिक्त)
		*valp = रिक्त;
	जर (lenp != रिक्त)
		*lenp = 0;
	जर (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		परत SSH_ERR_MESSAGE_INCOMPLETE;
	}
	len = PEEK_U32(p);
	जर (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		परत SSH_ERR_STRING_TOO_LARGE;
	}
	जर (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		परत SSH_ERR_MESSAGE_INCOMPLETE;
	}
	जर (valp != रिक्त)
		*valp = p + 4;
	जर (lenp != रिक्त)
		*lenp = len;
	परत 0;
}

पूर्णांक
sshbuf_get_cstring(संरचना sshbuf *buf, अक्षर **valp, माप_प्रकार *lenp)
{
	माप_प्रकार len;
	स्थिरांक u_char *p, *z;
	पूर्णांक r;

	जर (valp != रिक्त)
		*valp = रिक्त;
	जर (lenp != रिक्त)
		*lenp = 0;
	जर ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		परत r;
	/* Allow a \0 only at the end of the string */
	जर (len > 0 &&
	    (z = स_प्रथम(p , '\0', len)) != रिक्त && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		परत SSH_ERR_INVALID_FORMAT;
	}
	जर ((r = sshbuf_skip_string(buf)) != 0)
		परत -1;
	जर (valp != रिक्त) {
		जर ((*valp = दो_स्मृति(len + 1)) == रिक्त) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			परत SSH_ERR_ALLOC_FAIL;
		}
		जर (len != 0)
			स_नकल(*valp, p, len);
		(*valp)[len] = '\0';
	}
	जर (lenp != रिक्त)
		*lenp = (माप_प्रकार)len;
	परत 0;
}

पूर्णांक
sshbuf_get_stringb(संरचना sshbuf *buf, संरचना sshbuf *v)
{
	uint32_t len;
	u_char *p;
	पूर्णांक r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	जर ((r = sshbuf_peek_string_direct(buf, रिक्त, रिक्त)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		परत r;
	परत 0;
}

पूर्णांक
sshbuf_put(संरचना sshbuf *buf, स्थिरांक शून्य *v, माप_प्रकार len)
{
	u_char *p;
	पूर्णांक r;

	जर ((r = sshbuf_reserve(buf, len, &p)) < 0)
		परत r;
	जर (len != 0)
		स_नकल(p, v, len);
	परत 0;
}

पूर्णांक
sshbuf_putb(संरचना sshbuf *buf, स्थिरांक संरचना sshbuf *v)
{
	जर (v == रिक्त)
		परत 0;
	परत sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

पूर्णांक
sshbuf_putf(संरचना sshbuf *buf, स्थिरांक अक्षर *fmt, ...)
{
	बहु_सूची ap;
	पूर्णांक r;

	बहु_शुरू(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	बहु_पूर्ण(ap);
	परत r;
}

पूर्णांक
sshbuf_putfv(संरचना sshbuf *buf, स्थिरांक अक्षर *fmt, बहु_सूची ap)
{
	बहु_सूची ap2;
	पूर्णांक r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	जर ((len = vsnprintf(रिक्त, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		जा out;
	}
	जर (len == 0) {
		r = 0;
		जा out; /* Nothing to do */
	}
	बहु_पूर्ण(ap2);
	VA_COPY(ap2, ap);
	जर ((r = sshbuf_reserve(buf, (माप_प्रकार)len + 1, &p)) < 0)
		जा out;
	जर ((r = vsnprintf((अक्षर *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_INTERNAL_ERROR;
		जा out; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	जर ((r = sshbuf_consume_end(buf, 1)) != 0)
		जा out;
	r = 0;
 out:
	बहु_पूर्ण(ap2);
	परत r;
}

पूर्णांक
sshbuf_put_u64(संरचना sshbuf *buf, uint64_t val)
{
	u_char *p;
	पूर्णांक r;

	जर ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		परत r;
	POKE_U64(p, val);
	परत 0;
}

पूर्णांक
sshbuf_put_u32(संरचना sshbuf *buf, uint32_t val)
{
	u_char *p;
	पूर्णांक r;

	जर ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		परत r;
	POKE_U32(p, val);
	परत 0;
}

पूर्णांक
sshbuf_put_u16(संरचना sshbuf *buf, uint16_t val)
{
	u_char *p;
	पूर्णांक r;

	जर ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		परत r;
	POKE_U16(p, val);
	परत 0;
}

पूर्णांक
sshbuf_put_u8(संरचना sshbuf *buf, u_char val)
{
	u_char *p;
	पूर्णांक r;

	जर ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		परत r;
	p[0] = val;
	परत 0;
}

स्थिर पूर्णांक
check_woffset(संरचना sshbuf *buf, माप_प्रकार offset, माप_प्रकार len, u_char **p)
{
	पूर्णांक r;

	*p = रिक्त;
	जर ((r = check_offset(buf, 1, offset, len)) != 0)
		परत r;
	जर (sshbuf_mutable_ptr(buf) == रिक्त)
		परत SSH_ERR_BUFFER_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + offset;
	परत 0;
}

पूर्णांक
sshbuf_poke_u64(संरचना sshbuf *buf, माप_प्रकार offset, uint64_t val)
{
	u_char *p = रिक्त;
	पूर्णांक r;

	जर ((r = check_woffset(buf, offset, 8, &p)) != 0)
		परत r;
	POKE_U64(p, val);
	परत 0;
}

पूर्णांक
sshbuf_poke_u32(संरचना sshbuf *buf, माप_प्रकार offset, uint32_t val)
{
	u_char *p = रिक्त;
	पूर्णांक r;

	जर ((r = check_woffset(buf, offset, 4, &p)) != 0)
		परत r;
	POKE_U32(p, val);
	परत 0;
}

पूर्णांक
sshbuf_poke_u16(संरचना sshbuf *buf, माप_प्रकार offset, uint16_t val)
{
	u_char *p = रिक्त;
	पूर्णांक r;

	जर ((r = check_woffset(buf, offset, 2, &p)) != 0)
		परत r;
	POKE_U16(p, val);
	परत 0;
}

पूर्णांक
sshbuf_poke_u8(संरचना sshbuf *buf, माप_प्रकार offset, u_char val)
{
	u_char *p = रिक्त;
	पूर्णांक r;

	जर ((r = check_woffset(buf, offset, 1, &p)) != 0)
		परत r;
	*p = val;
	परत 0;
}

पूर्णांक
sshbuf_poke(संरचना sshbuf *buf, माप_प्रकार offset, शून्य *v, माप_प्रकार len)
{
	u_char *p = रिक्त;
	पूर्णांक r;

	जर ((r = check_woffset(buf, offset, len, &p)) != 0)
		परत r;
	स_नकल(p, v, len);
	परत 0;
}

पूर्णांक
sshbuf_put_string(संरचना sshbuf *buf, स्थिरांक शून्य *v, माप_प्रकार len)
{
	u_char *d;
	पूर्णांक r;

	जर (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		परत SSH_ERR_NO_BUFFER_SPACE;
	}
	जर ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		परत r;
	POKE_U32(d, len);
	जर (len != 0)
		स_नकल(d + 4, v, len);
	परत 0;
}

पूर्णांक
sshbuf_put_cstring(संरचना sshbuf *buf, स्थिरांक अक्षर *v)
{
	परत sshbuf_put_string(buf, v, v == रिक्त ? 0 : म_माप(v));
}

पूर्णांक
sshbuf_put_stringb(संरचना sshbuf *buf, स्थिरांक संरचना sshbuf *v)
{
	जर (v == रिक्त)
		परत sshbuf_put_string(buf, रिक्त, 0);

	परत sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

पूर्णांक
sshbuf_froms(संरचना sshbuf *buf, संरचना sshbuf **bufp)
{
	स्थिरांक u_char *p;
	माप_प्रकार len;
	संरचना sshbuf *ret;
	पूर्णांक r;

	जर (buf == रिक्त || bufp == रिक्त)
		परत SSH_ERR_INVALID_ARGUMENT;
	*bufp = रिक्त;
	जर ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		परत r;
	जर ((ret = sshbuf_from(p, len)) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_set_parent(ret, buf)) != 0) {
		sshbuf_free(ret);
		परत r;
	}
	*bufp = ret;
	परत 0;
}

पूर्णांक
sshbuf_put_bignum2_bytes(संरचना sshbuf *buf, स्थिरांक शून्य *v, माप_प्रकार len)
{
	u_char *d;
	स्थिरांक u_char *s = (स्थिरांक u_char *)v;
	पूर्णांक r, prepend;

	जर (len > SSHBUF_SIZE_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		परत SSH_ERR_NO_BUFFER_SPACE;
	}
	/* Skip leading zero bytes */
	साठी (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	जर ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		परत r;
	POKE_U32(d, len + prepend);
	जर (prepend)
		d[4] = 0;
	जर (len != 0)
		स_नकल(d + 4 + prepend, s, len);
	परत 0;
}

पूर्णांक
sshbuf_get_bignum2_bytes_direct(संरचना sshbuf *buf,
    स्थिरांक u_char **valp, माप_प्रकार *lenp)
{
	स्थिरांक u_char *d;
	माप_प्रकार len, olen;
	पूर्णांक r;

	जर ((r = sshbuf_peek_string_direct(buf, &d, &olen)) < 0)
		परत r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	जर ((len != 0 && (*d & 0x80) != 0))
		परत SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	जर (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		परत SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	पर्यंत (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	जर (valp != रिक्त)
		*valp = d;
	जर (lenp != रिक्त)
		*lenp = len;
	जर (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		परत SSH_ERR_INTERNAL_ERROR;
	}
	परत 0;
}

पूर्णांक
sshbuf_get_nulterminated_string(संरचना sshbuf *buf, माप_प्रकार maxlen,
    अक्षर **valp, माप_प्रकार *lenp)
{
	स्थिरांक u_char zero = 0;
	अक्षर *val = रिक्त;
	माप_प्रकार len = 0;
	पूर्णांक r;

	जर (valp != रिक्त)
		*valp = रिक्त;
	जर (lenp != रिक्त)
		*lenp = 0;
	जर ((r = sshbuf_find(buf, 0, &zero, आकार(zero), &len)) != 0) {
		जर (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			परत SSH_ERR_MESSAGE_INCOMPLETE;
		परत r;
	}
	जर (len > maxlen)
		परत SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	जर ((val = strdup(sshbuf_ptr(buf))) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = sshbuf_consume(buf, len + 1)) != 0)
		जा out;
	/* success */
	r = 0;
	जर (valp != रिक्त) {
		*valp = val;
		val = रिक्त;
	}
	जर (lenp != रिक्त)
		*lenp = len;
 out:
	मुक्त(val);
	परत r;
}
