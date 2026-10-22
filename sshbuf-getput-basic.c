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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdint.h>

#અન્તર્ભાવ "ssherr.h"
#define SSHBUF_INTERNAL
#અન્તર્ભાવ "sshbuf.h"

પૂર્ણાંક
sshbuf_get(સંરચના sshbuf *buf, શૂન્ય *v, size_t len)
{
	અચલ u_char *p = sshbuf_ptr(buf);
	પૂર્ણાંક r;

	જો ((r = sshbuf_consume(buf, len)) < 0)
		પાછા r;
	જો (v != ખાલી && len != 0)
		memcpy(v, p, len);
	પાછા 0;
}

પૂર્ણાંક
sshbuf_get_u64(સંરચના sshbuf *buf, uint64_t *valp)
{
	અચલ u_char *p = sshbuf_ptr(buf);
	પૂર્ણાંક r;

	જો ((r = sshbuf_consume(buf, 8)) < 0)
		પાછા r;
	જો (valp != ખાલી)
		*valp = PEEK_U64(p);
	પાછા 0;
}

પૂર્ણાંક
sshbuf_get_u32(સંરચના sshbuf *buf, uint32_t *valp)
{
	અચલ u_char *p = sshbuf_ptr(buf);
	પૂર્ણાંક r;

	જો ((r = sshbuf_consume(buf, 4)) < 0)
		પાછા r;
	જો (valp != ખાલી)
		*valp = PEEK_U32(p);
	પાછા 0;
}

પૂર્ણાંક
sshbuf_get_u16(સંરચના sshbuf *buf, uint16_t *valp)
{
	અચલ u_char *p = sshbuf_ptr(buf);
	પૂર્ણાંક r;

	જો ((r = sshbuf_consume(buf, 2)) < 0)
		પાછા r;
	જો (valp != ખાલી)
		*valp = PEEK_U16(p);
	પાછા 0;
}

પૂર્ણાંક
sshbuf_get_u8(સંરચના sshbuf *buf, u_char *valp)
{
	અચલ u_char *p = sshbuf_ptr(buf);
	પૂર્ણાંક r;

	જો ((r = sshbuf_consume(buf, 1)) < 0)
		પાછા r;
	જો (valp != ખાલી)
		*valp = (uint8_t)*p;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
check_offset(અચલ સંરચના sshbuf *buf, પૂર્ણાંક wr, size_t offset, size_t len)
{
	જો (sshbuf_ptr(buf) == ખાલી) /* calls sshbuf_check_sanity() */
		પાછા SSH_ERR_INTERNAL_ERROR;
	જો (offset >= SIZE_MAX - len)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (offset + len > sshbuf_len(buf)) {
		પાછા wr ?
		    SSH_ERR_NO_BUFFER_SPACE : SSH_ERR_MESSAGE_INCOMPLETE;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
check_roffset(અચલ સંરચના sshbuf *buf, size_t offset, size_t len,
    અચલ u_char **p)
{
	પૂર્ણાંક r;

	*p = ખાલી;
	જો ((r = check_offset(buf, 0, offset, len)) != 0)
		પાછા r;
	*p = sshbuf_ptr(buf) + offset;
	પાછા 0;
}

પૂર્ણાંક
sshbuf_peek_u64(અચલ સંરચના sshbuf *buf, size_t offset, uint64_t *valp)
{
	અચલ u_char *p = ખાલી;
	પૂર્ણાંક r;

	જો (valp != ખાલી)
		*valp = 0;
	જો ((r = check_roffset(buf, offset, 8, &p)) != 0)
		પાછા r;
	જો (valp != ખાલી)
		*valp = PEEK_U64(p);
	પાછા 0;
}

પૂર્ણાંક
sshbuf_peek_u32(અચલ સંરચના sshbuf *buf, size_t offset, uint32_t *valp)
{
	અચલ u_char *p = ખાલી;
	પૂર્ણાંક r;

	જો (valp != ખાલી)
		*valp = 0;
	જો ((r = check_roffset(buf, offset, 4, &p)) != 0)
		પાછા r;
	જો (valp != ખાલી)
		*valp = PEEK_U32(p);
	પાછા 0;
}

પૂર્ણાંક
sshbuf_peek_u16(અચલ સંરચના sshbuf *buf, size_t offset, uint16_t *valp)
{
	અચલ u_char *p = ખાલી;
	પૂર્ણાંક r;

	જો (valp != ખાલી)
		*valp = 0;
	જો ((r = check_roffset(buf, offset, 2, &p)) != 0)
		પાછા r;
	જો (valp != ખાલી)
		*valp = PEEK_U16(p);
	પાછા 0;
}

પૂર્ણાંક
sshbuf_peek_u8(અચલ સંરચના sshbuf *buf, size_t offset, u_char *valp)
{
	અચલ u_char *p = ખાલી;
	પૂર્ણાંક r;

	જો (valp != ખાલી)
		*valp = 0;
	જો ((r = check_roffset(buf, offset, 1, &p)) != 0)
		પાછા r;
	જો (valp != ખાલી)
		*valp = *p;
	પાછા 0;
}

પૂર્ણાંક
sshbuf_get_string(સંરચના sshbuf *buf, u_char **valp, size_t *lenp)
{
	અચલ u_char *val;
	size_t len;
	પૂર્ણાંક r;

	જો (valp != ખાલી)
		*valp = ખાલી;
	જો (lenp != ખાલી)
		*lenp = 0;
	જો ((r = sshbuf_get_string_direct(buf, &val, &len)) < 0)
		પાછા r;
	જો (valp != ખાલી) {
		જો ((*valp = malloc(len + 1)) == ખાલી) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			પાછા SSH_ERR_ALLOC_FAIL;
		}
		જો (len != 0)
			memcpy(*valp, val, len);
		(*valp)[len] = '\0';
	}
	જો (lenp != ખાલી)
		*lenp = len;
	પાછા 0;
}

પૂર્ણાંક
sshbuf_get_string_direct(સંરચના sshbuf *buf, અચલ u_char **valp, size_t *lenp)
{
	size_t len;
	અચલ u_char *p;
	પૂર્ણાંક r;

	જો (valp != ખાલી)
		*valp = ખાલી;
	જો (lenp != ખાલી)
		*lenp = 0;
	જો ((r = sshbuf_peek_string_direct(buf, &p, &len)) < 0)
		પાછા r;
	જો (valp != ખાલી)
		*valp = p;
	જો (lenp != ખાલી)
		*lenp = len;
	જો (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	પાછા 0;
}

પૂર્ણાંક
sshbuf_peek_string_direct(અચલ સંરચના sshbuf *buf, અચલ u_char **valp,
    size_t *lenp)
{
	uint32_t len;
	અચલ u_char *p = sshbuf_ptr(buf);

	જો (valp != ખાલી)
		*valp = ખાલી;
	જો (lenp != ખાલી)
		*lenp = 0;
	જો (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		પાછા SSH_ERR_MESSAGE_INCOMPLETE;
	}
	len = PEEK_U32(p);
	જો (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		પાછા SSH_ERR_STRING_TOO_LARGE;
	}
	જો (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		પાછા SSH_ERR_MESSAGE_INCOMPLETE;
	}
	જો (valp != ખાલી)
		*valp = p + 4;
	જો (lenp != ખાલી)
		*lenp = len;
	પાછા 0;
}

પૂર્ણાંક
sshbuf_get_cstring(સંરચના sshbuf *buf, અક્ષર **valp, size_t *lenp)
{
	size_t len;
	અચલ u_char *p, *z;
	પૂર્ણાંક r;

	જો (valp != ખાલી)
		*valp = ખાલી;
	જો (lenp != ખાલી)
		*lenp = 0;
	જો ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		પાછા r;
	/* Allow a \0 only at the end of the string */
	જો (len > 0 &&
	    (z = memchr(p , '\0', len)) != ખાલી && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		પાછા SSH_ERR_INVALID_FORMAT;
	}
	જો ((r = sshbuf_skip_string(buf)) != 0)
		પાછા -1;
	જો (valp != ખાલી) {
		જો ((*valp = malloc(len + 1)) == ખાલી) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			પાછા SSH_ERR_ALLOC_FAIL;
		}
		જો (len != 0)
			memcpy(*valp, p, len);
		(*valp)[len] = '\0';
	}
	જો (lenp != ખાલી)
		*lenp = (size_t)len;
	પાછા 0;
}

પૂર્ણાંક
sshbuf_get_stringb(સંરચના sshbuf *buf, સંરચના sshbuf *v)
{
	uint32_t len;
	u_char *p;
	પૂર્ણાંક r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	જો ((r = sshbuf_peek_string_direct(buf, ખાલી, ખાલી)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		પાછા r;
	પાછા 0;
}

પૂર્ણાંક
sshbuf_put(સંરચના sshbuf *buf, અચલ શૂન્ય *v, size_t len)
{
	u_char *p;
	પૂર્ણાંક r;

	જો ((r = sshbuf_reserve(buf, len, &p)) < 0)
		પાછા r;
	જો (len != 0)
		memcpy(p, v, len);
	પાછા 0;
}

પૂર્ણાંક
sshbuf_putb(સંરચના sshbuf *buf, અચલ સંરચના sshbuf *v)
{
	જો (v == ખાલી)
		પાછા 0;
	પાછા sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

પૂર્ણાંક
sshbuf_putf(સંરચના sshbuf *buf, અચલ અક્ષર *fmt, ...)
{
	va_list ap;
	પૂર્ણાંક r;

	va_start(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	va_end(ap);
	પાછા r;
}

પૂર્ણાંક
sshbuf_putfv(સંરચના sshbuf *buf, અચલ અક્ષર *fmt, va_list ap)
{
	va_list ap2;
	પૂર્ણાંક r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	જો ((len = vsnprintf(ખાલી, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	}
	જો (len == 0) {
		r = 0;
		જાઓ out; /* Nothing to do */
	}
	va_end(ap2);
	VA_COPY(ap2, ap);
	જો ((r = sshbuf_reserve(buf, (size_t)len + 1, &p)) < 0)
		જાઓ out;
	જો ((r = vsnprintf((અક્ષર *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_INTERNAL_ERROR;
		જાઓ out; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	જો ((r = sshbuf_consume_end(buf, 1)) != 0)
		જાઓ out;
	r = 0;
 out:
	va_end(ap2);
	પાછા r;
}

પૂર્ણાંક
sshbuf_put_u64(સંરચના sshbuf *buf, uint64_t val)
{
	u_char *p;
	પૂર્ણાંક r;

	જો ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		પાછા r;
	POKE_U64(p, val);
	પાછા 0;
}

પૂર્ણાંક
sshbuf_put_u32(સંરચના sshbuf *buf, uint32_t val)
{
	u_char *p;
	પૂર્ણાંક r;

	જો ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		પાછા r;
	POKE_U32(p, val);
	પાછા 0;
}

પૂર્ણાંક
sshbuf_put_u16(સંરચના sshbuf *buf, uint16_t val)
{
	u_char *p;
	પૂર્ણાંક r;

	જો ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		પાછા r;
	POKE_U16(p, val);
	પાછા 0;
}

પૂર્ણાંક
sshbuf_put_u8(સંરચના sshbuf *buf, u_char val)
{
	u_char *p;
	પૂર્ણાંક r;

	જો ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		પાછા r;
	p[0] = val;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
check_woffset(સંરચના sshbuf *buf, size_t offset, size_t len, u_char **p)
{
	પૂર્ણાંક r;

	*p = ખાલી;
	જો ((r = check_offset(buf, 1, offset, len)) != 0)
		પાછા r;
	જો (sshbuf_mutable_ptr(buf) == ખાલી)
		પાછા SSH_ERR_BUFFER_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + offset;
	પાછા 0;
}

પૂર્ણાંક
sshbuf_poke_u64(સંરચના sshbuf *buf, size_t offset, uint64_t val)
{
	u_char *p = ખાલી;
	પૂર્ણાંક r;

	જો ((r = check_woffset(buf, offset, 8, &p)) != 0)
		પાછા r;
	POKE_U64(p, val);
	પાછા 0;
}

પૂર્ણાંક
sshbuf_poke_u32(સંરચના sshbuf *buf, size_t offset, uint32_t val)
{
	u_char *p = ખાલી;
	પૂર્ણાંક r;

	જો ((r = check_woffset(buf, offset, 4, &p)) != 0)
		પાછા r;
	POKE_U32(p, val);
	પાછા 0;
}

પૂર્ણાંક
sshbuf_poke_u16(સંરચના sshbuf *buf, size_t offset, uint16_t val)
{
	u_char *p = ખાલી;
	પૂર્ણાંક r;

	જો ((r = check_woffset(buf, offset, 2, &p)) != 0)
		પાછા r;
	POKE_U16(p, val);
	પાછા 0;
}

પૂર્ણાંક
sshbuf_poke_u8(સંરચના sshbuf *buf, size_t offset, u_char val)
{
	u_char *p = ખાલી;
	પૂર્ણાંક r;

	જો ((r = check_woffset(buf, offset, 1, &p)) != 0)
		પાછા r;
	*p = val;
	પાછા 0;
}

પૂર્ણાંક
sshbuf_poke(સંરચના sshbuf *buf, size_t offset, શૂન્ય *v, size_t len)
{
	u_char *p = ખાલી;
	પૂર્ણાંક r;

	જો ((r = check_woffset(buf, offset, len, &p)) != 0)
		પાછા r;
	memcpy(p, v, len);
	પાછા 0;
}

પૂર્ણાંક
sshbuf_put_string(સંરચના sshbuf *buf, અચલ શૂન્ય *v, size_t len)
{
	u_char *d;
	પૂર્ણાંક r;

	જો (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		પાછા SSH_ERR_NO_BUFFER_SPACE;
	}
	જો ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		પાછા r;
	POKE_U32(d, len);
	જો (len != 0)
		memcpy(d + 4, v, len);
	પાછા 0;
}

પૂર્ણાંક
sshbuf_put_cstring(સંરચના sshbuf *buf, અચલ અક્ષર *v)
{
	પાછા sshbuf_put_string(buf, v, v == ખાલી ? 0 : strlen(v));
}

પૂર્ણાંક
sshbuf_put_stringb(સંરચના sshbuf *buf, અચલ સંરચના sshbuf *v)
{
	જો (v == ખાલી)
		પાછા sshbuf_put_string(buf, ખાલી, 0);

	પાછા sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

પૂર્ણાંક
sshbuf_froms(સંરચના sshbuf *buf, સંરચના sshbuf **bufp)
{
	અચલ u_char *p;
	size_t len;
	સંરચના sshbuf *ret;
	પૂર્ણાંક r;

	જો (buf == ખાલી || bufp == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	*bufp = ખાલી;
	જો ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		પાછા r;
	જો ((ret = sshbuf_from(p, len)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_set_parent(ret, buf)) != 0) {
		sshbuf_free(ret);
		પાછા r;
	}
	*bufp = ret;
	પાછા 0;
}

પૂર્ણાંક
sshbuf_put_bignum2_bytes(સંરચના sshbuf *buf, અચલ શૂન્ય *v, size_t len)
{
	u_char *d;
	અચલ u_char *s = (અચલ u_char *)v;
	પૂર્ણાંક r, prepend;

	જો (len > SSHBUF_SIZE_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		પાછા SSH_ERR_NO_BUFFER_SPACE;
	}
	/* Skip leading zero bytes */
	માટે (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	જો ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		પાછા r;
	POKE_U32(d, len + prepend);
	જો (prepend)
		d[4] = 0;
	જો (len != 0)
		memcpy(d + 4 + prepend, s, len);
	પાછા 0;
}

પૂર્ણાંક
sshbuf_get_bignum2_bytes_direct(સંરચના sshbuf *buf,
    અચલ u_char **valp, size_t *lenp)
{
	અચલ u_char *d;
	size_t len, olen;
	પૂર્ણાંક r;

	જો ((r = sshbuf_peek_string_direct(buf, &d, &olen)) < 0)
		પાછા r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	જો ((len != 0 && (*d & 0x80) != 0))
		પાછા SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	જો (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		પાછા SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	જ્યારે (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	જો (valp != ખાલી)
		*valp = d;
	જો (lenp != ખાલી)
		*lenp = len;
	જો (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	પાછા 0;
}

પૂર્ણાંક
sshbuf_get_nulterminated_string(સંરચના sshbuf *buf, size_t maxlen,
    અક્ષર **valp, size_t *lenp)
{
	અચલ u_char zero = 0;
	અક્ષર *val = ખાલી;
	size_t len = 0;
	પૂર્ણાંક r;

	જો (valp != ખાલી)
		*valp = ખાલી;
	જો (lenp != ખાલી)
		*lenp = 0;
	જો ((r = sshbuf_find(buf, 0, &zero, કદ(zero), &len)) != 0) {
		જો (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			પાછા SSH_ERR_MESSAGE_INCOMPLETE;
		પાછા r;
	}
	જો (len > maxlen)
		પાછા SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	જો ((val = strdup(sshbuf_ptr(buf))) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_consume(buf, len + 1)) != 0)
		જાઓ out;
	/* success */
	r = 0;
	જો (valp != ખાલી) {
		*valp = val;
		val = ખાલી;
	}
	જો (lenp != ખાલી)
		*lenp = len;
 out:
	મુક્ત(val);
	પાછા r;
}
