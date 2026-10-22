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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHBUF_ਅੰਦਰੂਨੀ
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"

ਪੂਰਨ
sshbuf_get(ਬਣਤਰ sshbuf *buf, ਖਾਲੀ *v, ਮਾਪ_t len)
{
	ਅਚਲ u_char *p = sshbuf_ptr(buf);
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_consume(buf, len)) < 0)
		ਵਾਪਸ r;
	ਜੇ (v != ਨਿਰਾ && len != 0)
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(v, p, len);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_get_u64(ਬਣਤਰ sshbuf *buf, uint64_t *valp)
{
	ਅਚਲ u_char *p = sshbuf_ptr(buf);
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_consume(buf, 8)) < 0)
		ਵਾਪਸ r;
	ਜੇ (valp != ਨਿਰਾ)
		*valp = PEEK_U64(p);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_get_u32(ਬਣਤਰ sshbuf *buf, uint32_t *valp)
{
	ਅਚਲ u_char *p = sshbuf_ptr(buf);
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_consume(buf, 4)) < 0)
		ਵਾਪਸ r;
	ਜੇ (valp != ਨਿਰਾ)
		*valp = PEEK_U32(p);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_get_u16(ਬਣਤਰ sshbuf *buf, uint16_t *valp)
{
	ਅਚਲ u_char *p = sshbuf_ptr(buf);
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_consume(buf, 2)) < 0)
		ਵਾਪਸ r;
	ਜੇ (valp != ਨਿਰਾ)
		*valp = PEEK_U16(p);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_get_u8(ਬਣਤਰ sshbuf *buf, u_char *valp)
{
	ਅਚਲ u_char *p = sshbuf_ptr(buf);
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_consume(buf, 1)) < 0)
		ਵਾਪਸ r;
	ਜੇ (valp != ਨਿਰਾ)
		*valp = (uint8_t)*p;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
check_ਵਿੱਥ(ਅਚਲ ਬਣਤਰ sshbuf *buf, ਪੂਰਨ wr, ਮਾਪ_t ਵਿੱਥ, ਮਾਪ_t len)
{
	ਜੇ (sshbuf_ptr(buf) == ਨਿਰਾ) /* calls sshbuf_check_sanity() */
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਜੇ (ਵਿੱਥ >= SIZE_MAX - len)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (ਵਿੱਥ + len > sshbuf_len(buf)) {
		ਵਾਪਸ wr ?
		    SSH_ERR_NO_ਬਫਰ_SPACE : SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
check_roffset(ਅਚਲ ਬਣਤਰ sshbuf *buf, ਮਾਪ_t ਵਿੱਥ, ਮਾਪ_t len,
    ਅਚਲ u_char **p)
{
	ਪੂਰਨ r;

	*p = ਨਿਰਾ;
	ਜੇ ((r = check_ਵਿੱਥ(buf, 0, ਵਿੱਥ, len)) != 0)
		ਵਾਪਸ r;
	*p = sshbuf_ptr(buf) + ਵਿੱਥ;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_peek_u64(ਅਚਲ ਬਣਤਰ sshbuf *buf, ਮਾਪ_t ਵਿੱਥ, uint64_t *valp)
{
	ਅਚਲ u_char *p = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ (valp != ਨਿਰਾ)
		*valp = 0;
	ਜੇ ((r = check_roffset(buf, ਵਿੱਥ, 8, &p)) != 0)
		ਵਾਪਸ r;
	ਜੇ (valp != ਨਿਰਾ)
		*valp = PEEK_U64(p);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_peek_u32(ਅਚਲ ਬਣਤਰ sshbuf *buf, ਮਾਪ_t ਵਿੱਥ, uint32_t *valp)
{
	ਅਚਲ u_char *p = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ (valp != ਨਿਰਾ)
		*valp = 0;
	ਜੇ ((r = check_roffset(buf, ਵਿੱਥ, 4, &p)) != 0)
		ਵਾਪਸ r;
	ਜੇ (valp != ਨਿਰਾ)
		*valp = PEEK_U32(p);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_peek_u16(ਅਚਲ ਬਣਤਰ sshbuf *buf, ਮਾਪ_t ਵਿੱਥ, uint16_t *valp)
{
	ਅਚਲ u_char *p = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ (valp != ਨਿਰਾ)
		*valp = 0;
	ਜੇ ((r = check_roffset(buf, ਵਿੱਥ, 2, &p)) != 0)
		ਵਾਪਸ r;
	ਜੇ (valp != ਨਿਰਾ)
		*valp = PEEK_U16(p);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_peek_u8(ਅਚਲ ਬਣਤਰ sshbuf *buf, ਮਾਪ_t ਵਿੱਥ, u_char *valp)
{
	ਅਚਲ u_char *p = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ (valp != ਨਿਰਾ)
		*valp = 0;
	ਜੇ ((r = check_roffset(buf, ਵਿੱਥ, 1, &p)) != 0)
		ਵਾਪਸ r;
	ਜੇ (valp != ਨਿਰਾ)
		*valp = *p;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_get_string(ਬਣਤਰ sshbuf *buf, u_char **valp, ਮਾਪ_t *lenp)
{
	ਅਚਲ u_char *val;
	ਮਾਪ_t len;
	ਪੂਰਨ r;

	ਜੇ (valp != ਨਿਰਾ)
		*valp = ਨਿਰਾ;
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = 0;
	ਜੇ ((r = sshbuf_get_string_ਸਿੱਧਾ(buf, &val, &len)) < 0)
		ਵਾਪਸ r;
	ਜੇ (valp != ਨਿਰਾ) {
		ਜੇ ((*valp = ਸਮ੍ਰਿਤੀ_ਦਿਓ(len + 1)) == ਨਿਰਾ) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
		}
		ਜੇ (len != 0)
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(*valp, val, len);
		(*valp)[len] = '\0';
	}
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = len;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_get_string_ਸਿੱਧਾ(ਬਣਤਰ sshbuf *buf, ਅਚਲ u_char **valp, ਮਾਪ_t *lenp)
{
	ਮਾਪ_t len;
	ਅਚਲ u_char *p;
	ਪੂਰਨ r;

	ਜੇ (valp != ਨਿਰਾ)
		*valp = ਨਿਰਾ;
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = 0;
	ਜੇ ((r = sshbuf_peek_string_ਸਿੱਧਾ(buf, &p, &len)) < 0)
		ਵਾਪਸ r;
	ਜੇ (valp != ਨਿਰਾ)
		*valp = p;
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = len;
	ਜੇ (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_peek_string_ਸਿੱਧਾ(ਅਚਲ ਬਣਤਰ sshbuf *buf, ਅਚਲ u_char **valp,
    ਮਾਪ_t *lenp)
{
	uint32_t len;
	ਅਚਲ u_char *p = sshbuf_ptr(buf);

	ਜੇ (valp != ਨਿਰਾ)
		*valp = ਨਿਰਾ;
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = 0;
	ਜੇ (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		ਵਾਪਸ SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE;
	}
	len = PEEK_U32(p);
	ਜੇ (len > SSHBUF_ਮਾਪ_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		ਵਾਪਸ SSH_ERR_STRING_TOO_LARGE;
	}
	ਜੇ (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		ਵਾਪਸ SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE;
	}
	ਜੇ (valp != ਨਿਰਾ)
		*valp = p + 4;
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = len;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_get_cstring(ਬਣਤਰ sshbuf *buf, ਅੱਖਰ **valp, ਮਾਪ_t *lenp)
{
	ਮਾਪ_t len;
	ਅਚਲ u_char *p, *z;
	ਪੂਰਨ r;

	ਜੇ (valp != ਨਿਰਾ)
		*valp = ਨਿਰਾ;
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = 0;
	ਜੇ ((r = sshbuf_peek_string_ਸਿੱਧਾ(buf, &p, &len)) != 0)
		ਵਾਪਸ r;
	/* Allow a \0 only at the end of the string */
	ਜੇ (len > 0 &&
	    (z = memchr(p , '\0', len)) != ਨਿਰਾ && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	}
	ਜੇ ((r = sshbuf_skip_string(buf)) != 0)
		ਵਾਪਸ -1;
	ਜੇ (valp != ਨਿਰਾ) {
		ਜੇ ((*valp = ਸਮ੍ਰਿਤੀ_ਦਿਓ(len + 1)) == ਨਿਰਾ) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
		}
		ਜੇ (len != 0)
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(*valp, p, len);
		(*valp)[len] = '\0';
	}
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = (ਮਾਪ_t)len;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_get_stringb(ਬਣਤਰ sshbuf *buf, ਬਣਤਰ sshbuf *v)
{
	uint32_t len;
	u_char *p;
	ਪੂਰਨ r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	ਜੇ ((r = sshbuf_peek_string_ਸਿੱਧਾ(buf, ਨਿਰਾ, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		ਵਾਪਸ r;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_put(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਖਾਲੀ *v, ਮਾਪ_t len)
{
	u_char *p;
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_reserve(buf, len, &p)) < 0)
		ਵਾਪਸ r;
	ਜੇ (len != 0)
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(p, v, len);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_putb(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਬਣਤਰ sshbuf *v)
{
	ਜੇ (v == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਵਾਪਸ sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

ਪੂਰਨ
sshbuf_putf(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list ap;
	ਪੂਰਨ r;

	va_start(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	va_end(ap);
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshbuf_putfv(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਅੱਖਰ *fmt, va_list ap)
{
	va_list ap2;
	ਪੂਰਨ r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	ਜੇ ((len = vsnprintf(ਨਿਰਾ, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (len == 0) {
		r = 0;
		ਜਾਓ ਬਾਹਰਲਾ; /* Nothing to do */
	}
	va_end(ap2);
	VA_COPY(ap2, ap);
	ਜੇ ((r = sshbuf_reserve(buf, (ਮਾਪ_t)len + 1, &p)) < 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = vsnprintf((ਅੱਖਰ *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	ਜੇ ((r = sshbuf_consume_ਸਿਰਾ(buf, 1)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	r = 0;
 ਬਾਹਰਲਾ:
	va_end(ap2);
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshbuf_put_u64(ਬਣਤਰ sshbuf *buf, uint64_t val)
{
	u_char *p;
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		ਵਾਪਸ r;
	POKE_U64(p, val);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_put_u32(ਬਣਤਰ sshbuf *buf, uint32_t val)
{
	u_char *p;
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		ਵਾਪਸ r;
	POKE_U32(p, val);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_put_u16(ਬਣਤਰ sshbuf *buf, uint16_t val)
{
	u_char *p;
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		ਵਾਪਸ r;
	POKE_U16(p, val);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_put_u8(ਬਣਤਰ sshbuf *buf, u_char val)
{
	u_char *p;
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		ਵਾਪਸ r;
	p[0] = val;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
check_woffset(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t ਵਿੱਥ, ਮਾਪ_t len, u_char **p)
{
	ਪੂਰਨ r;

	*p = ਨਿਰਾ;
	ਜੇ ((r = check_ਵਿੱਥ(buf, 1, ਵਿੱਥ, len)) != 0)
		ਵਾਪਸ r;
	ਜੇ (sshbuf_mutable_ptr(buf) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ਬਫਰ_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + ਵਿੱਥ;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_poke_u64(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t ਵਿੱਥ, uint64_t val)
{
	u_char *p = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ ((r = check_woffset(buf, ਵਿੱਥ, 8, &p)) != 0)
		ਵਾਪਸ r;
	POKE_U64(p, val);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_poke_u32(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t ਵਿੱਥ, uint32_t val)
{
	u_char *p = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ ((r = check_woffset(buf, ਵਿੱਥ, 4, &p)) != 0)
		ਵਾਪਸ r;
	POKE_U32(p, val);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_poke_u16(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t ਵਿੱਥ, uint16_t val)
{
	u_char *p = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ ((r = check_woffset(buf, ਵਿੱਥ, 2, &p)) != 0)
		ਵਾਪਸ r;
	POKE_U16(p, val);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_poke_u8(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t ਵਿੱਥ, u_char val)
{
	u_char *p = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ ((r = check_woffset(buf, ਵਿੱਥ, 1, &p)) != 0)
		ਵਾਪਸ r;
	*p = val;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_poke(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t ਵਿੱਥ, ਖਾਲੀ *v, ਮਾਪ_t len)
{
	u_char *p = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ ((r = check_woffset(buf, ਵਿੱਥ, len, &p)) != 0)
		ਵਾਪਸ r;
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(p, v, len);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_put_string(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਖਾਲੀ *v, ਮਾਪ_t len)
{
	u_char *d;
	ਪੂਰਨ r;

	ਜੇ (len > SSHBUF_ਮਾਪ_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		ਵਾਪਸ SSH_ERR_NO_ਬਫਰ_SPACE;
	}
	ਜੇ ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		ਵਾਪਸ r;
	POKE_U32(d, len);
	ਜੇ (len != 0)
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(d + 4, v, len);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_put_cstring(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਅੱਖਰ *v)
{
	ਵਾਪਸ sshbuf_put_string(buf, v, v == ਨਿਰਾ ? 0 : ਲੜੀ_ਲੰਬਾਈ(v));
}

ਪੂਰਨ
sshbuf_put_stringb(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਬਣਤਰ sshbuf *v)
{
	ਜੇ (v == ਨਿਰਾ)
		ਵਾਪਸ sshbuf_put_string(buf, ਨਿਰਾ, 0);

	ਵਾਪਸ sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

ਪੂਰਨ
sshbuf_froms(ਬਣਤਰ sshbuf *buf, ਬਣਤਰ sshbuf **bufp)
{
	ਅਚਲ u_char *p;
	ਮਾਪ_t len;
	ਬਣਤਰ sshbuf *ret;
	ਪੂਰਨ r;

	ਜੇ (buf == ਨਿਰਾ || bufp == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	*bufp = ਨਿਰਾ;
	ਜੇ ((r = sshbuf_peek_string_ਸਿੱਧਾ(buf, &p, &len)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((ret = sshbuf_from(p, len)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_ਸੈੱਟ_ਮਾਪਾ(ret, buf)) != 0) {
		sshbuf_free(ret);
		ਵਾਪਸ r;
	}
	*bufp = ret;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_put_bignum2_ਬਾਈਟਾਂ(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਖਾਲੀ *v, ਮਾਪ_t len)
{
	u_char *d;
	ਅਚਲ u_char *s = (ਅਚਲ u_char *)v;
	ਪੂਰਨ r, prepend;

	ਜੇ (len > SSHBUF_ਮਾਪ_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		ਵਾਪਸ SSH_ERR_NO_ਬਫਰ_SPACE;
	}
	/* Skip leading zero bytes */
	ਲਈ (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	ਜੇ ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		ਵਾਪਸ r;
	POKE_U32(d, len + prepend);
	ਜੇ (prepend)
		d[4] = 0;
	ਜੇ (len != 0)
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(d + 4 + prepend, s, len);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_get_bignum2_ਬਾਈਟਾਂ_ਸਿੱਧਾ(ਬਣਤਰ sshbuf *buf,
    ਅਚਲ u_char **valp, ਮਾਪ_t *lenp)
{
	ਅਚਲ u_char *d;
	ਮਾਪ_t len, olen;
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_peek_string_ਸਿੱਧਾ(buf, &d, &olen)) < 0)
		ਵਾਪਸ r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	ਜੇ ((len != 0 && (*d & 0x80) != 0))
		ਵਾਪਸ SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	ਜੇ (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		ਵਾਪਸ SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	ਜਦੋਂ (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	ਜੇ (valp != ਨਿਰਾ)
		*valp = d;
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = len;
	ਜੇ (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_get_nulterminated_string(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t maxlen,
    ਅੱਖਰ **valp, ਮਾਪ_t *lenp)
{
	ਅਚਲ u_char zero = 0;
	ਅੱਖਰ *val = ਨਿਰਾ;
	ਮਾਪ_t len = 0;
	ਪੂਰਨ r;

	ਜੇ (valp != ਨਿਰਾ)
		*valp = ਨਿਰਾ;
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = 0;
	ਜੇ ((r = sshbuf_ਲੱਭੋ(buf, 0, &zero, ਆਕਾਰ(zero), &len)) != 0) {
		ਜੇ (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			ਵਾਪਸ SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE;
		ਵਾਪਸ r;
	}
	ਜੇ (len > maxlen)
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	ਜੇ ((val = strdup(sshbuf_ptr(buf))) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_consume(buf, len + 1)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	r = 0;
	ਜੇ (valp != ਨਿਰਾ) {
		*valp = val;
		val = ਨਿਰਾ;
	}
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = len;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(val);
	ਵਾਪਸ r;
}
