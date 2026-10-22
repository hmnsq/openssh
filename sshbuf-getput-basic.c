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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdint.h>

#അന്തര്ഭാവ "ssherr.h"
#define SSHBUF_INTERNAL
#അന്തര്ഭാവ "sshbuf.h"

പൂർണ്ണസംഖ്യ
sshbuf_get(ഘടന sshbuf *buf, ശൂന്യം *v, size_t len)
{
	സ്ഥിരം u_char *p = sshbuf_ptr(buf);
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_consume(buf, len)) < 0)
		തിരികെ r;
	എങ്കിൽ (v != ശൂന്യ && len != 0)
		memcpy(v, p, len);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_get_u64(ഘടന sshbuf *buf, uint64_t *valp)
{
	സ്ഥിരം u_char *p = sshbuf_ptr(buf);
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_consume(buf, 8)) < 0)
		തിരികെ r;
	എങ്കിൽ (valp != ശൂന്യ)
		*valp = PEEK_U64(p);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_get_u32(ഘടന sshbuf *buf, uint32_t *valp)
{
	സ്ഥിരം u_char *p = sshbuf_ptr(buf);
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_consume(buf, 4)) < 0)
		തിരികെ r;
	എങ്കിൽ (valp != ശൂന്യ)
		*valp = PEEK_U32(p);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_get_u16(ഘടന sshbuf *buf, uint16_t *valp)
{
	സ്ഥിരം u_char *p = sshbuf_ptr(buf);
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_consume(buf, 2)) < 0)
		തിരികെ r;
	എങ്കിൽ (valp != ശൂന്യ)
		*valp = PEEK_U16(p);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_get_u8(ഘടന sshbuf *buf, u_char *valp)
{
	സ്ഥിരം u_char *p = sshbuf_ptr(buf);
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_consume(buf, 1)) < 0)
		തിരികെ r;
	എങ്കിൽ (valp != ശൂന്യ)
		*valp = (uint8_t)*p;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
check_offset(സ്ഥിരം ഘടന sshbuf *buf, പൂർണ്ണസംഖ്യ wr, size_t offset, size_t len)
{
	എങ്കിൽ (sshbuf_ptr(buf) == ശൂന്യ) /* calls sshbuf_check_sanity() */
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	എങ്കിൽ (offset >= SIZE_MAX - len)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (offset + len > sshbuf_len(buf)) {
		തിരികെ wr ?
		    SSH_ERR_NO_BUFFER_SPACE : SSH_ERR_MESSAGE_INCOMPLETE;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
check_roffset(സ്ഥിരം ഘടന sshbuf *buf, size_t offset, size_t len,
    സ്ഥിരം u_char **p)
{
	പൂർണ്ണസംഖ്യ r;

	*p = ശൂന്യ;
	എങ്കിൽ ((r = check_offset(buf, 0, offset, len)) != 0)
		തിരികെ r;
	*p = sshbuf_ptr(buf) + offset;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_peek_u64(സ്ഥിരം ഘടന sshbuf *buf, size_t offset, uint64_t *valp)
{
	സ്ഥിരം u_char *p = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (valp != ശൂന്യ)
		*valp = 0;
	എങ്കിൽ ((r = check_roffset(buf, offset, 8, &p)) != 0)
		തിരികെ r;
	എങ്കിൽ (valp != ശൂന്യ)
		*valp = PEEK_U64(p);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_peek_u32(സ്ഥിരം ഘടന sshbuf *buf, size_t offset, uint32_t *valp)
{
	സ്ഥിരം u_char *p = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (valp != ശൂന്യ)
		*valp = 0;
	എങ്കിൽ ((r = check_roffset(buf, offset, 4, &p)) != 0)
		തിരികെ r;
	എങ്കിൽ (valp != ശൂന്യ)
		*valp = PEEK_U32(p);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_peek_u16(സ്ഥിരം ഘടന sshbuf *buf, size_t offset, uint16_t *valp)
{
	സ്ഥിരം u_char *p = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (valp != ശൂന്യ)
		*valp = 0;
	എങ്കിൽ ((r = check_roffset(buf, offset, 2, &p)) != 0)
		തിരികെ r;
	എങ്കിൽ (valp != ശൂന്യ)
		*valp = PEEK_U16(p);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_peek_u8(സ്ഥിരം ഘടന sshbuf *buf, size_t offset, u_char *valp)
{
	സ്ഥിരം u_char *p = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (valp != ശൂന്യ)
		*valp = 0;
	എങ്കിൽ ((r = check_roffset(buf, offset, 1, &p)) != 0)
		തിരികെ r;
	എങ്കിൽ (valp != ശൂന്യ)
		*valp = *p;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_get_string(ഘടന sshbuf *buf, u_char **valp, size_t *lenp)
{
	സ്ഥിരം u_char *val;
	size_t len;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (valp != ശൂന്യ)
		*valp = ശൂന്യ;
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = 0;
	എങ്കിൽ ((r = sshbuf_get_string_direct(buf, &val, &len)) < 0)
		തിരികെ r;
	എങ്കിൽ (valp != ശൂന്യ) {
		എങ്കിൽ ((*valp = malloc(len + 1)) == ശൂന്യ) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			തിരികെ SSH_ERR_ALLOC_FAIL;
		}
		എങ്കിൽ (len != 0)
			memcpy(*valp, val, len);
		(*valp)[len] = '\0';
	}
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = len;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_get_string_direct(ഘടന sshbuf *buf, സ്ഥിരം u_char **valp, size_t *lenp)
{
	size_t len;
	സ്ഥിരം u_char *p;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (valp != ശൂന്യ)
		*valp = ശൂന്യ;
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = 0;
	എങ്കിൽ ((r = sshbuf_peek_string_direct(buf, &p, &len)) < 0)
		തിരികെ r;
	എങ്കിൽ (valp != ശൂന്യ)
		*valp = p;
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = len;
	എങ്കിൽ (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	}
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_peek_string_direct(സ്ഥിരം ഘടന sshbuf *buf, സ്ഥിരം u_char **valp,
    size_t *lenp)
{
	uint32_t len;
	സ്ഥിരം u_char *p = sshbuf_ptr(buf);

	എങ്കിൽ (valp != ശൂന്യ)
		*valp = ശൂന്യ;
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = 0;
	എങ്കിൽ (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		തിരികെ SSH_ERR_MESSAGE_INCOMPLETE;
	}
	len = PEEK_U32(p);
	എങ്കിൽ (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		തിരികെ SSH_ERR_STRING_TOO_LARGE;
	}
	എങ്കിൽ (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		തിരികെ SSH_ERR_MESSAGE_INCOMPLETE;
	}
	എങ്കിൽ (valp != ശൂന്യ)
		*valp = p + 4;
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = len;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_get_cstring(ഘടന sshbuf *buf, അക്ഷരം **valp, size_t *lenp)
{
	size_t len;
	സ്ഥിരം u_char *p, *z;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (valp != ശൂന്യ)
		*valp = ശൂന്യ;
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = 0;
	എങ്കിൽ ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		തിരികെ r;
	/* Allow a \0 only at the end of the string */
	എങ്കിൽ (len > 0 &&
	    (z = memchr(p , '\0', len)) != ശൂന്യ && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		തിരികെ SSH_ERR_INVALID_FORMAT;
	}
	എങ്കിൽ ((r = sshbuf_skip_string(buf)) != 0)
		തിരികെ -1;
	എങ്കിൽ (valp != ശൂന്യ) {
		എങ്കിൽ ((*valp = malloc(len + 1)) == ശൂന്യ) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			തിരികെ SSH_ERR_ALLOC_FAIL;
		}
		എങ്കിൽ (len != 0)
			memcpy(*valp, p, len);
		(*valp)[len] = '\0';
	}
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = (size_t)len;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_get_stringb(ഘടന sshbuf *buf, ഘടന sshbuf *v)
{
	uint32_t len;
	u_char *p;
	പൂർണ്ണസംഖ്യ r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	എങ്കിൽ ((r = sshbuf_peek_string_direct(buf, ശൂന്യ, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		തിരികെ r;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_put(ഘടന sshbuf *buf, സ്ഥിരം ശൂന്യം *v, size_t len)
{
	u_char *p;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_reserve(buf, len, &p)) < 0)
		തിരികെ r;
	എങ്കിൽ (len != 0)
		memcpy(p, v, len);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_putb(ഘടന sshbuf *buf, സ്ഥിരം ഘടന sshbuf *v)
{
	എങ്കിൽ (v == ശൂന്യ)
		തിരികെ 0;
	തിരികെ sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

പൂർണ്ണസംഖ്യ
sshbuf_putf(ഘടന sshbuf *buf, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	va_list ap;
	പൂർണ്ണസംഖ്യ r;

	va_start(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	va_end(ap);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshbuf_putfv(ഘടന sshbuf *buf, സ്ഥിരം അക്ഷരം *fmt, va_list ap)
{
	va_list ap2;
	പൂർണ്ണസംഖ്യ r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	എങ്കിൽ ((len = vsnprintf(ശൂന്യ, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	}
	എങ്കിൽ (len == 0) {
		r = 0;
		പോകുക out; /* Nothing to do */
	}
	va_end(ap2);
	VA_COPY(ap2, ap);
	എങ്കിൽ ((r = sshbuf_reserve(buf, (size_t)len + 1, &p)) < 0)
		പോകുക out;
	എങ്കിൽ ((r = vsnprintf((അക്ഷരം *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_INTERNAL_ERROR;
		പോകുക out; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	എങ്കിൽ ((r = sshbuf_consume_end(buf, 1)) != 0)
		പോകുക out;
	r = 0;
 out:
	va_end(ap2);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshbuf_put_u64(ഘടന sshbuf *buf, uint64_t val)
{
	u_char *p;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		തിരികെ r;
	POKE_U64(p, val);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_put_u32(ഘടന sshbuf *buf, uint32_t val)
{
	u_char *p;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		തിരികെ r;
	POKE_U32(p, val);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_put_u16(ഘടന sshbuf *buf, uint16_t val)
{
	u_char *p;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		തിരികെ r;
	POKE_U16(p, val);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_put_u8(ഘടന sshbuf *buf, u_char val)
{
	u_char *p;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		തിരികെ r;
	p[0] = val;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
check_woffset(ഘടന sshbuf *buf, size_t offset, size_t len, u_char **p)
{
	പൂർണ്ണസംഖ്യ r;

	*p = ശൂന്യ;
	എങ്കിൽ ((r = check_offset(buf, 1, offset, len)) != 0)
		തിരികെ r;
	എങ്കിൽ (sshbuf_mutable_ptr(buf) == ശൂന്യ)
		തിരികെ SSH_ERR_BUFFER_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + offset;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_poke_u64(ഘടന sshbuf *buf, size_t offset, uint64_t val)
{
	u_char *p = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = check_woffset(buf, offset, 8, &p)) != 0)
		തിരികെ r;
	POKE_U64(p, val);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_poke_u32(ഘടന sshbuf *buf, size_t offset, uint32_t val)
{
	u_char *p = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = check_woffset(buf, offset, 4, &p)) != 0)
		തിരികെ r;
	POKE_U32(p, val);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_poke_u16(ഘടന sshbuf *buf, size_t offset, uint16_t val)
{
	u_char *p = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = check_woffset(buf, offset, 2, &p)) != 0)
		തിരികെ r;
	POKE_U16(p, val);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_poke_u8(ഘടന sshbuf *buf, size_t offset, u_char val)
{
	u_char *p = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = check_woffset(buf, offset, 1, &p)) != 0)
		തിരികെ r;
	*p = val;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_poke(ഘടന sshbuf *buf, size_t offset, ശൂന്യം *v, size_t len)
{
	u_char *p = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = check_woffset(buf, offset, len, &p)) != 0)
		തിരികെ r;
	memcpy(p, v, len);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_put_string(ഘടന sshbuf *buf, സ്ഥിരം ശൂന്യം *v, size_t len)
{
	u_char *d;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		തിരികെ SSH_ERR_NO_BUFFER_SPACE;
	}
	എങ്കിൽ ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		തിരികെ r;
	POKE_U32(d, len);
	എങ്കിൽ (len != 0)
		memcpy(d + 4, v, len);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_put_cstring(ഘടന sshbuf *buf, സ്ഥിരം അക്ഷരം *v)
{
	തിരികെ sshbuf_put_string(buf, v, v == ശൂന്യ ? 0 : strlen(v));
}

പൂർണ്ണസംഖ്യ
sshbuf_put_stringb(ഘടന sshbuf *buf, സ്ഥിരം ഘടന sshbuf *v)
{
	എങ്കിൽ (v == ശൂന്യ)
		തിരികെ sshbuf_put_string(buf, ശൂന്യ, 0);

	തിരികെ sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

പൂർണ്ണസംഖ്യ
sshbuf_froms(ഘടന sshbuf *buf, ഘടന sshbuf **bufp)
{
	സ്ഥിരം u_char *p;
	size_t len;
	ഘടന sshbuf *ret;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (buf == ശൂന്യ || bufp == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	*bufp = ശൂന്യ;
	എങ്കിൽ ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		തിരികെ r;
	എങ്കിൽ ((ret = sshbuf_from(p, len)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_set_parent(ret, buf)) != 0) {
		sshbuf_free(ret);
		തിരികെ r;
	}
	*bufp = ret;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_put_bignum2_bytes(ഘടന sshbuf *buf, സ്ഥിരം ശൂന്യം *v, size_t len)
{
	u_char *d;
	സ്ഥിരം u_char *s = (സ്ഥിരം u_char *)v;
	പൂർണ്ണസംഖ്യ r, prepend;

	എങ്കിൽ (len > SSHBUF_SIZE_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		തിരികെ SSH_ERR_NO_BUFFER_SPACE;
	}
	/* Skip leading zero bytes */
	വേണ്ടി (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	എങ്കിൽ ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		തിരികെ r;
	POKE_U32(d, len + prepend);
	എങ്കിൽ (prepend)
		d[4] = 0;
	എങ്കിൽ (len != 0)
		memcpy(d + 4 + prepend, s, len);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_get_bignum2_bytes_direct(ഘടന sshbuf *buf,
    സ്ഥിരം u_char **valp, size_t *lenp)
{
	സ്ഥിരം u_char *d;
	size_t len, olen;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_peek_string_direct(buf, &d, &olen)) < 0)
		തിരികെ r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	എങ്കിൽ ((len != 0 && (*d & 0x80) != 0))
		തിരികെ SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	എങ്കിൽ (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		തിരികെ SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	ആകുമ്പോൾ (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	എങ്കിൽ (valp != ശൂന്യ)
		*valp = d;
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = len;
	എങ്കിൽ (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	}
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_get_nulterminated_string(ഘടന sshbuf *buf, size_t maxlen,
    അക്ഷരം **valp, size_t *lenp)
{
	സ്ഥിരം u_char zero = 0;
	അക്ഷരം *val = ശൂന്യ;
	size_t len = 0;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (valp != ശൂന്യ)
		*valp = ശൂന്യ;
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = 0;
	എങ്കിൽ ((r = sshbuf_find(buf, 0, &zero, വലുപ്പം(zero), &len)) != 0) {
		എങ്കിൽ (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			തിരികെ SSH_ERR_MESSAGE_INCOMPLETE;
		തിരികെ r;
	}
	എങ്കിൽ (len > maxlen)
		തിരികെ SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	എങ്കിൽ ((val = strdup(sshbuf_ptr(buf))) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_consume(buf, len + 1)) != 0)
		പോകുക out;
	/* success */
	r = 0;
	എങ്കിൽ (valp != ശൂന്യ) {
		*valp = val;
		val = ശൂന്യ;
	}
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = len;
 out:
	സ്വതന്ത്രം(val);
	തിരികെ r;
}
