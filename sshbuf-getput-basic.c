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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>

#ಅನ್ತರ್ಭಾವ "ssherr.h"
#define SSHBUF_INTERNAL
#ಅನ್ತರ್ಭಾವ "sshbuf.h"

ಪೂರ್ಣಾಙ್ಕ
sshbuf_get(ಸಂರಚನಾ sshbuf *buf, ಶೂನ್ಯ *v, size_t len)
{
	ಧ್ರುವ u_char *p = sshbuf_ptr(buf);
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_consume(buf, len)) < 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (v != ರಿಕ್ತ && len != 0)
		memcpy(v, p, len);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_get_u64(ಸಂರಚನಾ sshbuf *buf, uint64_t *valp)
{
	ಧ್ರುವ u_char *p = sshbuf_ptr(buf);
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_consume(buf, 8)) < 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = PEEK_U64(p);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_get_u32(ಸಂರಚನಾ sshbuf *buf, uint32_t *valp)
{
	ಧ್ರುವ u_char *p = sshbuf_ptr(buf);
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_consume(buf, 4)) < 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = PEEK_U32(p);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_get_u16(ಸಂರಚನಾ sshbuf *buf, uint16_t *valp)
{
	ಧ್ರುವ u_char *p = sshbuf_ptr(buf);
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_consume(buf, 2)) < 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = PEEK_U16(p);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_get_u8(ಸಂರಚನಾ sshbuf *buf, u_char *valp)
{
	ಧ್ರುವ u_char *p = sshbuf_ptr(buf);
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_consume(buf, 1)) < 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = (uint8_t)*p;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
check_offset(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf, ಪೂರ್ಣಾಙ್ಕ wr, size_t offset, size_t len)
{
	ಯದಿ (sshbuf_ptr(buf) == ರಿಕ್ತ) /* calls sshbuf_check_sanity() */
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	ಯದಿ (offset >= SIZE_MAX - len)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (offset + len > sshbuf_len(buf)) {
		ಪ್ರತ್ಯಾಗಮ wr ?
		    SSH_ERR_NO_BUFFER_SPACE : SSH_ERR_MESSAGE_INCOMPLETE;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
check_roffset(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf, size_t offset, size_t len,
    ಧ್ರುವ u_char **p)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	*p = ರಿಕ್ತ;
	ಯದಿ ((r = check_offset(buf, 0, offset, len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	*p = sshbuf_ptr(buf) + offset;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_peek_u64(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf, size_t offset, uint64_t *valp)
{
	ಧ್ರುವ u_char *p = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = 0;
	ಯದಿ ((r = check_roffset(buf, offset, 8, &p)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = PEEK_U64(p);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_peek_u32(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf, size_t offset, uint32_t *valp)
{
	ಧ್ರುವ u_char *p = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = 0;
	ಯದಿ ((r = check_roffset(buf, offset, 4, &p)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = PEEK_U32(p);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_peek_u16(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf, size_t offset, uint16_t *valp)
{
	ಧ್ರುವ u_char *p = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = 0;
	ಯದಿ ((r = check_roffset(buf, offset, 2, &p)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = PEEK_U16(p);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_peek_u8(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf, size_t offset, u_char *valp)
{
	ಧ್ರುವ u_char *p = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = 0;
	ಯದಿ ((r = check_roffset(buf, offset, 1, &p)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = *p;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_get_string(ಸಂರಚನಾ sshbuf *buf, u_char **valp, size_t *lenp)
{
	ಧ್ರುವ u_char *val;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = ರಿಕ್ತ;
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = 0;
	ಯದಿ ((r = sshbuf_get_string_direct(buf, &val, &len)) < 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (valp != ರಿಕ್ತ) {
		ಯದಿ ((*valp = malloc(len + 1)) == ರಿಕ್ತ) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
		}
		ಯದಿ (len != 0)
			memcpy(*valp, val, len);
		(*valp)[len] = '\0';
	}
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = len;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_get_string_direct(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ u_char **valp, size_t *lenp)
{
	size_t len;
	ಧ್ರುವ u_char *p;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = ರಿಕ್ತ;
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = 0;
	ಯದಿ ((r = sshbuf_peek_string_direct(buf, &p, &len)) < 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = p;
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = len;
	ಯದಿ (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_peek_string_direct(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ u_char **valp,
    size_t *lenp)
{
	uint32_t len;
	ಧ್ರುವ u_char *p = sshbuf_ptr(buf);

	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = ರಿಕ್ತ;
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = 0;
	ಯದಿ (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_MESSAGE_INCOMPLETE;
	}
	len = PEEK_U32(p);
	ಯದಿ (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_STRING_TOO_LARGE;
	}
	ಯದಿ (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_MESSAGE_INCOMPLETE;
	}
	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = p + 4;
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = len;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_get_cstring(ಸಂರಚನಾ sshbuf *buf, ವರ್ಣ **valp, size_t *lenp)
{
	size_t len;
	ಧ್ರುವ u_char *p, *z;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = ರಿಕ್ತ;
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = 0;
	ಯದಿ ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	/* Allow a \0 only at the end of the string */
	ಯದಿ (len > 0 &&
	    (z = memchr(p , '\0', len)) != ರಿಕ್ತ && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	}
	ಯದಿ ((r = sshbuf_skip_string(buf)) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಯದಿ (valp != ರಿಕ್ತ) {
		ಯದಿ ((*valp = malloc(len + 1)) == ರಿಕ್ತ) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
		}
		ಯದಿ (len != 0)
			memcpy(*valp, p, len);
		(*valp)[len] = '\0';
	}
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = (size_t)len;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_get_stringb(ಸಂರಚನಾ sshbuf *buf, ಸಂರಚನಾ sshbuf *v)
{
	uint32_t len;
	u_char *p;
	ಪೂರ್ಣಾಙ್ಕ r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	ಯದಿ ((r = sshbuf_peek_string_direct(buf, ರಿಕ್ತ, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_put(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ಶೂನ್ಯ *v, size_t len)
{
	u_char *p;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_reserve(buf, len, &p)) < 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (len != 0)
		memcpy(p, v, len);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_putb(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ಸಂರಚನಾ sshbuf *v)
{
	ಯದಿ (v == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_putf(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	va_list ap;
	ಪೂರ್ಣಾಙ್ಕ r;

	va_start(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	va_end(ap);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_putfv(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ವರ್ಣ *fmt, va_list ap)
{
	va_list ap2;
	ಪೂರ್ಣಾಙ್ಕ r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	ಯದಿ ((len = vsnprintf(ರಿಕ್ತ, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (len == 0) {
		r = 0;
		ಗಚ್ಛ out; /* Nothing to do */
	}
	va_end(ap2);
	VA_COPY(ap2, ap);
	ಯದಿ ((r = sshbuf_reserve(buf, (size_t)len + 1, &p)) < 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = vsnprintf((ವರ್ಣ *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_INTERNAL_ERROR;
		ಗಚ್ಛ out; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	ಯದಿ ((r = sshbuf_consume_end(buf, 1)) != 0)
		ಗಚ್ಛ out;
	r = 0;
 out:
	va_end(ap2);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_put_u64(ಸಂರಚನಾ sshbuf *buf, uint64_t val)
{
	u_char *p;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		ಪ್ರತ್ಯಾಗಮ r;
	POKE_U64(p, val);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_put_u32(ಸಂರಚನಾ sshbuf *buf, uint32_t val)
{
	u_char *p;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		ಪ್ರತ್ಯಾಗಮ r;
	POKE_U32(p, val);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_put_u16(ಸಂರಚನಾ sshbuf *buf, uint16_t val)
{
	u_char *p;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		ಪ್ರತ್ಯಾಗಮ r;
	POKE_U16(p, val);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_put_u8(ಸಂರಚನಾ sshbuf *buf, u_char val)
{
	u_char *p;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		ಪ್ರತ್ಯಾಗಮ r;
	p[0] = val;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
check_woffset(ಸಂರಚನಾ sshbuf *buf, size_t offset, size_t len, u_char **p)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	*p = ರಿಕ್ತ;
	ಯದಿ ((r = check_offset(buf, 1, offset, len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (sshbuf_mutable_ptr(buf) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_BUFFER_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + offset;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_poke_u64(ಸಂರಚನಾ sshbuf *buf, size_t offset, uint64_t val)
{
	u_char *p = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = check_woffset(buf, offset, 8, &p)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	POKE_U64(p, val);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_poke_u32(ಸಂರಚನಾ sshbuf *buf, size_t offset, uint32_t val)
{
	u_char *p = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = check_woffset(buf, offset, 4, &p)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	POKE_U32(p, val);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_poke_u16(ಸಂರಚನಾ sshbuf *buf, size_t offset, uint16_t val)
{
	u_char *p = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = check_woffset(buf, offset, 2, &p)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	POKE_U16(p, val);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_poke_u8(ಸಂರಚನಾ sshbuf *buf, size_t offset, u_char val)
{
	u_char *p = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = check_woffset(buf, offset, 1, &p)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	*p = val;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_poke(ಸಂರಚನಾ sshbuf *buf, size_t offset, ಶೂನ್ಯ *v, size_t len)
{
	u_char *p = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = check_woffset(buf, offset, len, &p)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	memcpy(p, v, len);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_put_string(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ಶೂನ್ಯ *v, size_t len)
{
	u_char *d;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_NO_BUFFER_SPACE;
	}
	ಯದಿ ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		ಪ್ರತ್ಯಾಗಮ r;
	POKE_U32(d, len);
	ಯದಿ (len != 0)
		memcpy(d + 4, v, len);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_put_cstring(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ವರ್ಣ *v)
{
	ಪ್ರತ್ಯಾಗಮ sshbuf_put_string(buf, v, v == ರಿಕ್ತ ? 0 : strlen(v));
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_put_stringb(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ಸಂರಚನಾ sshbuf *v)
{
	ಯದಿ (v == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ sshbuf_put_string(buf, ರಿಕ್ತ, 0);

	ಪ್ರತ್ಯಾಗಮ sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_froms(ಸಂರಚನಾ sshbuf *buf, ಸಂರಚನಾ sshbuf **bufp)
{
	ಧ್ರುವ u_char *p;
	size_t len;
	ಸಂರಚನಾ sshbuf *ret;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (buf == ರಿಕ್ತ || bufp == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	*bufp = ರಿಕ್ತ;
	ಯದಿ ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((ret = sshbuf_from(p, len)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_set_parent(ret, buf)) != 0) {
		sshbuf_free(ret);
		ಪ್ರತ್ಯಾಗಮ r;
	}
	*bufp = ret;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_put_bignum2_bytes(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ಶೂನ್ಯ *v, size_t len)
{
	u_char *d;
	ಧ್ರುವ u_char *s = (ಧ್ರುವ u_char *)v;
	ಪೂರ್ಣಾಙ್ಕ r, prepend;

	ಯದಿ (len > SSHBUF_SIZE_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_NO_BUFFER_SPACE;
	}
	/* Skip leading zero bytes */
	ಪ್ರತಿ (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	ಯದಿ ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		ಪ್ರತ್ಯಾಗಮ r;
	POKE_U32(d, len + prepend);
	ಯದಿ (prepend)
		d[4] = 0;
	ಯದಿ (len != 0)
		memcpy(d + 4 + prepend, s, len);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_get_bignum2_bytes_direct(ಸಂರಚನಾ sshbuf *buf,
    ಧ್ರುವ u_char **valp, size_t *lenp)
{
	ಧ್ರುವ u_char *d;
	size_t len, olen;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_peek_string_direct(buf, &d, &olen)) < 0)
		ಪ್ರತ್ಯಾಗಮ r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	ಯದಿ ((len != 0 && (*d & 0x80) != 0))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	ಯದಿ (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	ಯಾವತ್ (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = d;
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = len;
	ಯದಿ (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_get_nulterminated_string(ಸಂರಚನಾ sshbuf *buf, size_t maxlen,
    ವರ್ಣ **valp, size_t *lenp)
{
	ಧ್ರುವ u_char zero = 0;
	ವರ್ಣ *val = ರಿಕ್ತ;
	size_t len = 0;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (valp != ರಿಕ್ತ)
		*valp = ರಿಕ್ತ;
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = 0;
	ಯದಿ ((r = sshbuf_find(buf, 0, &zero, ಪರಿಮಾಣ(zero), &len)) != 0) {
		ಯದಿ (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_MESSAGE_INCOMPLETE;
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ (len > maxlen)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	ಯದಿ ((val = strdup(sshbuf_ptr(buf))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_consume(buf, len + 1)) != 0)
		ಗಚ್ಛ out;
	/* success */
	r = 0;
	ಯದಿ (valp != ರಿಕ್ತ) {
		*valp = val;
		val = ರಿಕ್ತ;
	}
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = len;
 out:
	ಮುಕ್ತ(val);
	ಪ್ರತ್ಯಾಗಮ r;
}
