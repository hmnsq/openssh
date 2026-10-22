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

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <stdarg.h>
#समावेश <stdlib.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <stdint.h>

#समावेश "ssherr.h"
#घोषणा SSHBUF_INTERNAL
#समावेश "sshbuf.h"

पूर्णांक
sshbuf_get(काष्ठा sshbuf *buf, व्योम *v, माप_प्रकार len)
{
	स्थिर u_char *p = sshbuf_ptr(buf);
	पूर्णांक r;

	अगर ((r = sshbuf_consume(buf, len)) < 0)
		वापस r;
	अगर (v != शून्य && len != 0)
		स_नकल(v, p, len);
	वापस 0;
}

पूर्णांक
sshbuf_get_u64(काष्ठा sshbuf *buf, uint64_t *valp)
{
	स्थिर u_char *p = sshbuf_ptr(buf);
	पूर्णांक r;

	अगर ((r = sshbuf_consume(buf, 8)) < 0)
		वापस r;
	अगर (valp != शून्य)
		*valp = PEEK_U64(p);
	वापस 0;
}

पूर्णांक
sshbuf_get_u32(काष्ठा sshbuf *buf, uint32_t *valp)
{
	स्थिर u_char *p = sshbuf_ptr(buf);
	पूर्णांक r;

	अगर ((r = sshbuf_consume(buf, 4)) < 0)
		वापस r;
	अगर (valp != शून्य)
		*valp = PEEK_U32(p);
	वापस 0;
}

पूर्णांक
sshbuf_get_u16(काष्ठा sshbuf *buf, uint16_t *valp)
{
	स्थिर u_char *p = sshbuf_ptr(buf);
	पूर्णांक r;

	अगर ((r = sshbuf_consume(buf, 2)) < 0)
		वापस r;
	अगर (valp != शून्य)
		*valp = PEEK_U16(p);
	वापस 0;
}

पूर्णांक
sshbuf_get_u8(काष्ठा sshbuf *buf, u_char *valp)
{
	स्थिर u_char *p = sshbuf_ptr(buf);
	पूर्णांक r;

	अगर ((r = sshbuf_consume(buf, 1)) < 0)
		वापस r;
	अगर (valp != शून्य)
		*valp = (uint8_t)*p;
	वापस 0;
}

अटल पूर्णांक
check_offset(स्थिर काष्ठा sshbuf *buf, पूर्णांक wr, माप_प्रकार offset, माप_प्रकार len)
{
	अगर (sshbuf_ptr(buf) == शून्य) /* calls sshbuf_check_sanity() */
		वापस SSH_ERR_INTERNAL_ERROR;
	अगर (offset >= SIZE_MAX - len)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (offset + len > sshbuf_len(buf)) {
		वापस wr ?
		    SSH_ERR_NO_बफर_SPACE : SSH_ERR_MESSAGE_INCOMPLETE;
	}
	वापस 0;
}

अटल पूर्णांक
check_roffset(स्थिर काष्ठा sshbuf *buf, माप_प्रकार offset, माप_प्रकार len,
    स्थिर u_char **p)
{
	पूर्णांक r;

	*p = शून्य;
	अगर ((r = check_offset(buf, 0, offset, len)) != 0)
		वापस r;
	*p = sshbuf_ptr(buf) + offset;
	वापस 0;
}

पूर्णांक
sshbuf_peek_u64(स्थिर काष्ठा sshbuf *buf, माप_प्रकार offset, uint64_t *valp)
{
	स्थिर u_char *p = शून्य;
	पूर्णांक r;

	अगर (valp != शून्य)
		*valp = 0;
	अगर ((r = check_roffset(buf, offset, 8, &p)) != 0)
		वापस r;
	अगर (valp != शून्य)
		*valp = PEEK_U64(p);
	वापस 0;
}

पूर्णांक
sshbuf_peek_u32(स्थिर काष्ठा sshbuf *buf, माप_प्रकार offset, uint32_t *valp)
{
	स्थिर u_char *p = शून्य;
	पूर्णांक r;

	अगर (valp != शून्य)
		*valp = 0;
	अगर ((r = check_roffset(buf, offset, 4, &p)) != 0)
		वापस r;
	अगर (valp != शून्य)
		*valp = PEEK_U32(p);
	वापस 0;
}

पूर्णांक
sshbuf_peek_u16(स्थिर काष्ठा sshbuf *buf, माप_प्रकार offset, uint16_t *valp)
{
	स्थिर u_char *p = शून्य;
	पूर्णांक r;

	अगर (valp != शून्य)
		*valp = 0;
	अगर ((r = check_roffset(buf, offset, 2, &p)) != 0)
		वापस r;
	अगर (valp != शून्य)
		*valp = PEEK_U16(p);
	वापस 0;
}

पूर्णांक
sshbuf_peek_u8(स्थिर काष्ठा sshbuf *buf, माप_प्रकार offset, u_char *valp)
{
	स्थिर u_char *p = शून्य;
	पूर्णांक r;

	अगर (valp != शून्य)
		*valp = 0;
	अगर ((r = check_roffset(buf, offset, 1, &p)) != 0)
		वापस r;
	अगर (valp != शून्य)
		*valp = *p;
	वापस 0;
}

पूर्णांक
sshbuf_get_string(काष्ठा sshbuf *buf, u_char **valp, माप_प्रकार *lenp)
{
	स्थिर u_char *val;
	माप_प्रकार len;
	पूर्णांक r;

	अगर (valp != शून्य)
		*valp = शून्य;
	अगर (lenp != शून्य)
		*lenp = 0;
	अगर ((r = sshbuf_get_string_direct(buf, &val, &len)) < 0)
		वापस r;
	अगर (valp != शून्य) {
		अगर ((*valp = दो_स्मृति(len + 1)) == शून्य) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			वापस SSH_ERR_ALLOC_FAIL;
		}
		अगर (len != 0)
			स_नकल(*valp, val, len);
		(*valp)[len] = '\0';
	}
	अगर (lenp != शून्य)
		*lenp = len;
	वापस 0;
}

पूर्णांक
sshbuf_get_string_direct(काष्ठा sshbuf *buf, स्थिर u_char **valp, माप_प्रकार *lenp)
{
	माप_प्रकार len;
	स्थिर u_char *p;
	पूर्णांक r;

	अगर (valp != शून्य)
		*valp = शून्य;
	अगर (lenp != शून्य)
		*lenp = 0;
	अगर ((r = sshbuf_peek_string_direct(buf, &p, &len)) < 0)
		वापस r;
	अगर (valp != शून्य)
		*valp = p;
	अगर (lenp != शून्य)
		*lenp = len;
	अगर (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	वापस 0;
}

पूर्णांक
sshbuf_peek_string_direct(स्थिर काष्ठा sshbuf *buf, स्थिर u_char **valp,
    माप_प्रकार *lenp)
{
	uint32_t len;
	स्थिर u_char *p = sshbuf_ptr(buf);

	अगर (valp != शून्य)
		*valp = शून्य;
	अगर (lenp != शून्य)
		*lenp = 0;
	अगर (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		वापस SSH_ERR_MESSAGE_INCOMPLETE;
	}
	len = PEEK_U32(p);
	अगर (len > SSHBUF_आकार_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		वापस SSH_ERR_STRING_TOO_LARGE;
	}
	अगर (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		वापस SSH_ERR_MESSAGE_INCOMPLETE;
	}
	अगर (valp != शून्य)
		*valp = p + 4;
	अगर (lenp != शून्य)
		*lenp = len;
	वापस 0;
}

पूर्णांक
sshbuf_get_cstring(काष्ठा sshbuf *buf, अक्षर **valp, माप_प्रकार *lenp)
{
	माप_प्रकार len;
	स्थिर u_char *p, *z;
	पूर्णांक r;

	अगर (valp != शून्य)
		*valp = शून्य;
	अगर (lenp != शून्य)
		*lenp = 0;
	अगर ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		वापस r;
	/* Allow a \0 only at the end of the string */
	अगर (len > 0 &&
	    (z = स_प्रथम(p , '\0', len)) != शून्य && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		वापस SSH_ERR_INVALID_FORMAT;
	}
	अगर ((r = sshbuf_skip_string(buf)) != 0)
		वापस -1;
	अगर (valp != शून्य) {
		अगर ((*valp = दो_स्मृति(len + 1)) == शून्य) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			वापस SSH_ERR_ALLOC_FAIL;
		}
		अगर (len != 0)
			स_नकल(*valp, p, len);
		(*valp)[len] = '\0';
	}
	अगर (lenp != शून्य)
		*lenp = (माप_प्रकार)len;
	वापस 0;
}

पूर्णांक
sshbuf_get_stringb(काष्ठा sshbuf *buf, काष्ठा sshbuf *v)
{
	uint32_t len;
	u_char *p;
	पूर्णांक r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	अगर ((r = sshbuf_peek_string_direct(buf, शून्य, शून्य)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		वापस r;
	वापस 0;
}

पूर्णांक
sshbuf_put(काष्ठा sshbuf *buf, स्थिर व्योम *v, माप_प्रकार len)
{
	u_char *p;
	पूर्णांक r;

	अगर ((r = sshbuf_reserve(buf, len, &p)) < 0)
		वापस r;
	अगर (len != 0)
		स_नकल(p, v, len);
	वापस 0;
}

पूर्णांक
sshbuf_putb(काष्ठा sshbuf *buf, स्थिर काष्ठा sshbuf *v)
{
	अगर (v == शून्य)
		वापस 0;
	वापस sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

पूर्णांक
sshbuf_putf(काष्ठा sshbuf *buf, स्थिर अक्षर *fmt, ...)
{
	बहु_सूची ap;
	पूर्णांक r;

	बहु_शुरू(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	बहु_पूर्ण(ap);
	वापस r;
}

पूर्णांक
sshbuf_putfv(काष्ठा sshbuf *buf, स्थिर अक्षर *fmt, बहु_सूची ap)
{
	बहु_सूची ap2;
	पूर्णांक r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	अगर ((len = vsnprintf(शून्य, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	}
	अगर (len == 0) {
		r = 0;
		जाओ out; /* Nothing to do */
	}
	बहु_पूर्ण(ap2);
	VA_COPY(ap2, ap);
	अगर ((r = sshbuf_reserve(buf, (माप_प्रकार)len + 1, &p)) < 0)
		जाओ out;
	अगर ((r = vsnprintf((अक्षर *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_INTERNAL_ERROR;
		जाओ out; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	अगर ((r = sshbuf_consume_end(buf, 1)) != 0)
		जाओ out;
	r = 0;
 out:
	बहु_पूर्ण(ap2);
	वापस r;
}

पूर्णांक
sshbuf_put_u64(काष्ठा sshbuf *buf, uint64_t val)
{
	u_char *p;
	पूर्णांक r;

	अगर ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		वापस r;
	POKE_U64(p, val);
	वापस 0;
}

पूर्णांक
sshbuf_put_u32(काष्ठा sshbuf *buf, uint32_t val)
{
	u_char *p;
	पूर्णांक r;

	अगर ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		वापस r;
	POKE_U32(p, val);
	वापस 0;
}

पूर्णांक
sshbuf_put_u16(काष्ठा sshbuf *buf, uint16_t val)
{
	u_char *p;
	पूर्णांक r;

	अगर ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		वापस r;
	POKE_U16(p, val);
	वापस 0;
}

पूर्णांक
sshbuf_put_u8(काष्ठा sshbuf *buf, u_char val)
{
	u_char *p;
	पूर्णांक r;

	अगर ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		वापस r;
	p[0] = val;
	वापस 0;
}

अटल पूर्णांक
check_woffset(काष्ठा sshbuf *buf, माप_प्रकार offset, माप_प्रकार len, u_char **p)
{
	पूर्णांक r;

	*p = शून्य;
	अगर ((r = check_offset(buf, 1, offset, len)) != 0)
		वापस r;
	अगर (sshbuf_mutable_ptr(buf) == शून्य)
		वापस SSH_ERR_बफर_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + offset;
	वापस 0;
}

पूर्णांक
sshbuf_poke_u64(काष्ठा sshbuf *buf, माप_प्रकार offset, uint64_t val)
{
	u_char *p = शून्य;
	पूर्णांक r;

	अगर ((r = check_woffset(buf, offset, 8, &p)) != 0)
		वापस r;
	POKE_U64(p, val);
	वापस 0;
}

पूर्णांक
sshbuf_poke_u32(काष्ठा sshbuf *buf, माप_प्रकार offset, uint32_t val)
{
	u_char *p = शून्य;
	पूर्णांक r;

	अगर ((r = check_woffset(buf, offset, 4, &p)) != 0)
		वापस r;
	POKE_U32(p, val);
	वापस 0;
}

पूर्णांक
sshbuf_poke_u16(काष्ठा sshbuf *buf, माप_प्रकार offset, uint16_t val)
{
	u_char *p = शून्य;
	पूर्णांक r;

	अगर ((r = check_woffset(buf, offset, 2, &p)) != 0)
		वापस r;
	POKE_U16(p, val);
	वापस 0;
}

पूर्णांक
sshbuf_poke_u8(काष्ठा sshbuf *buf, माप_प्रकार offset, u_char val)
{
	u_char *p = शून्य;
	पूर्णांक r;

	अगर ((r = check_woffset(buf, offset, 1, &p)) != 0)
		वापस r;
	*p = val;
	वापस 0;
}

पूर्णांक
sshbuf_poke(काष्ठा sshbuf *buf, माप_प्रकार offset, व्योम *v, माप_प्रकार len)
{
	u_char *p = शून्य;
	पूर्णांक r;

	अगर ((r = check_woffset(buf, offset, len, &p)) != 0)
		वापस r;
	स_नकल(p, v, len);
	वापस 0;
}

पूर्णांक
sshbuf_put_string(काष्ठा sshbuf *buf, स्थिर व्योम *v, माप_प्रकार len)
{
	u_char *d;
	पूर्णांक r;

	अगर (len > SSHBUF_आकार_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		वापस SSH_ERR_NO_बफर_SPACE;
	}
	अगर ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		वापस r;
	POKE_U32(d, len);
	अगर (len != 0)
		स_नकल(d + 4, v, len);
	वापस 0;
}

पूर्णांक
sshbuf_put_cstring(काष्ठा sshbuf *buf, स्थिर अक्षर *v)
{
	वापस sshbuf_put_string(buf, v, v == शून्य ? 0 : म_माप(v));
}

पूर्णांक
sshbuf_put_stringb(काष्ठा sshbuf *buf, स्थिर काष्ठा sshbuf *v)
{
	अगर (v == शून्य)
		वापस sshbuf_put_string(buf, शून्य, 0);

	वापस sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

पूर्णांक
sshbuf_froms(काष्ठा sshbuf *buf, काष्ठा sshbuf **bufp)
{
	स्थिर u_char *p;
	माप_प्रकार len;
	काष्ठा sshbuf *ret;
	पूर्णांक r;

	अगर (buf == शून्य || bufp == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	*bufp = शून्य;
	अगर ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		वापस r;
	अगर ((ret = sshbuf_from(p, len)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_set_parent(ret, buf)) != 0) {
		sshbuf_free(ret);
		वापस r;
	}
	*bufp = ret;
	वापस 0;
}

पूर्णांक
sshbuf_put_bignum2_bytes(काष्ठा sshbuf *buf, स्थिर व्योम *v, माप_प्रकार len)
{
	u_char *d;
	स्थिर u_char *s = (स्थिर u_char *)v;
	पूर्णांक r, prepend;

	अगर (len > SSHBUF_आकार_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		वापस SSH_ERR_NO_बफर_SPACE;
	}
	/* Skip leading zero bytes */
	क्रम (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	अगर ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		वापस r;
	POKE_U32(d, len + prepend);
	अगर (prepend)
		d[4] = 0;
	अगर (len != 0)
		स_नकल(d + 4 + prepend, s, len);
	वापस 0;
}

पूर्णांक
sshbuf_get_bignum2_bytes_direct(काष्ठा sshbuf *buf,
    स्थिर u_char **valp, माप_प्रकार *lenp)
{
	स्थिर u_char *d;
	माप_प्रकार len, olen;
	पूर्णांक r;

	अगर ((r = sshbuf_peek_string_direct(buf, &d, &olen)) < 0)
		वापस r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	अगर ((len != 0 && (*d & 0x80) != 0))
		वापस SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	अगर (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		वापस SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	जबतक (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	अगर (valp != शून्य)
		*valp = d;
	अगर (lenp != शून्य)
		*lenp = len;
	अगर (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	वापस 0;
}

पूर्णांक
sshbuf_get_nulterminated_string(काष्ठा sshbuf *buf, माप_प्रकार maxlen,
    अक्षर **valp, माप_प्रकार *lenp)
{
	स्थिर u_char zero = 0;
	अक्षर *val = शून्य;
	माप_प्रकार len = 0;
	पूर्णांक r;

	अगर (valp != शून्य)
		*valp = शून्य;
	अगर (lenp != शून्य)
		*lenp = 0;
	अगर ((r = sshbuf_find(buf, 0, &zero, माप(zero), &len)) != 0) {
		अगर (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			वापस SSH_ERR_MESSAGE_INCOMPLETE;
		वापस r;
	}
	अगर (len > maxlen)
		वापस SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	अगर ((val = strdup(sshbuf_ptr(buf))) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_consume(buf, len + 1)) != 0)
		जाओ out;
	/* success */
	r = 0;
	अगर (valp != शून्य) {
		*valp = val;
		val = शून्य;
	}
	अगर (lenp != शून्य)
		*lenp = len;
 out:
	मुक्त(val);
	वापस r;
}
