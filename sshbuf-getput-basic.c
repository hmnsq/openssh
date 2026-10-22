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
#ವ್ಯಾಖ್ಯಾನಿಸು SSHBUF_ಆಂತರಿಕ
#ಅನ್ತರ್ಭಾವ "sshbuf.h"

ಪೂರ್ಣಾಂಕ
sshbuf_get(ರಚನೆ sshbuf *buf, ಶೂನ್ಯ *v, ಗಾತ್ರ_t len)
{
	ಸ್ಥಿರಾಂಕ u_char *p = sshbuf_ptr(buf);
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_consume(buf, len)) < 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (v != ಖಾಲಿ && len != 0)
		ಸ್ಮರಣೆ_ನಕಲು(v, p, len);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_get_u64(ರಚನೆ sshbuf *buf, uint64_t *valp)
{
	ಸ್ಥಿರಾಂಕ u_char *p = sshbuf_ptr(buf);
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_consume(buf, 8)) < 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = PEEK_U64(p);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_get_u32(ರಚನೆ sshbuf *buf, uint32_t *valp)
{
	ಸ್ಥಿರಾಂಕ u_char *p = sshbuf_ptr(buf);
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_consume(buf, 4)) < 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = PEEK_U32(p);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_get_u16(ರಚನೆ sshbuf *buf, uint16_t *valp)
{
	ಸ್ಥಿರಾಂಕ u_char *p = sshbuf_ptr(buf);
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_consume(buf, 2)) < 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = PEEK_U16(p);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_get_u8(ರಚನೆ sshbuf *buf, u_char *valp)
{
	ಸ್ಥಿರಾಂಕ u_char *p = sshbuf_ptr(buf);
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_consume(buf, 1)) < 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = (uint8_t)*p;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
check_ಸ್ಥಾನಾಂತರ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf, ಪೂರ್ಣಾಂಕ wr, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ, ಗಾತ್ರ_t len)
{
	ಆದರೆ (sshbuf_ptr(buf) == ಖಾಲಿ) /* calls sshbuf_check_sanity() */
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಆದರೆ (ಸ್ಥಾನಾಂತರ >= SIZE_MAX - len)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (ಸ್ಥಾನಾಂತರ + len > sshbuf_len(buf)) {
		ಹಿಂತಿರುಗಿ wr ?
		    SSH_ERR_NO_ಬಫರ್_SPACE : SSH_ERR_ಸಂದೇಶ_INCOMPLETE;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
check_roffset(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ, ಗಾತ್ರ_t len,
    ಸ್ಥಿರಾಂಕ u_char **p)
{
	ಪೂರ್ಣಾಂಕ r;

	*p = ಖಾಲಿ;
	ಆದರೆ ((r = check_ಸ್ಥಾನಾಂತರ(buf, 0, ಸ್ಥಾನಾಂತರ, len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	*p = sshbuf_ptr(buf) + ಸ್ಥಾನಾಂತರ;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_peek_u64(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ, uint64_t *valp)
{
	ಸ್ಥಿರಾಂಕ u_char *p = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = 0;
	ಆದರೆ ((r = check_roffset(buf, ಸ್ಥಾನಾಂತರ, 8, &p)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = PEEK_U64(p);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_peek_u32(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ, uint32_t *valp)
{
	ಸ್ಥಿರಾಂಕ u_char *p = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = 0;
	ಆದರೆ ((r = check_roffset(buf, ಸ್ಥಾನಾಂತರ, 4, &p)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = PEEK_U32(p);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_peek_u16(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ, uint16_t *valp)
{
	ಸ್ಥಿರಾಂಕ u_char *p = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = 0;
	ಆದರೆ ((r = check_roffset(buf, ಸ್ಥಾನಾಂತರ, 2, &p)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = PEEK_U16(p);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_peek_u8(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ, u_char *valp)
{
	ಸ್ಥಿರಾಂಕ u_char *p = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = 0;
	ಆದರೆ ((r = check_roffset(buf, ಸ್ಥಾನಾಂತರ, 1, &p)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = *p;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_get_string(ರಚನೆ sshbuf *buf, u_char **valp, ಗಾತ್ರ_t *lenp)
{
	ಸ್ಥಿರಾಂಕ u_char *val;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = ಖಾಲಿ;
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = 0;
	ಆದರೆ ((r = sshbuf_get_string_ನೇರ(buf, &val, &len)) < 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (valp != ಖಾಲಿ) {
		ಆದರೆ ((*valp = ಸ್ಮರಣೆ_ಕೊಡು(len + 1)) == ಖಾಲಿ) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
		}
		ಆದರೆ (len != 0)
			ಸ್ಮರಣೆ_ನಕಲು(*valp, val, len);
		(*valp)[len] = '\0';
	}
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = len;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_get_string_ನೇರ(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ u_char **valp, ಗಾತ್ರ_t *lenp)
{
	ಗಾತ್ರ_t len;
	ಸ್ಥಿರಾಂಕ u_char *p;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = ಖಾಲಿ;
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = 0;
	ಆದರೆ ((r = sshbuf_peek_string_ನೇರ(buf, &p, &len)) < 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = p;
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = len;
	ಆದರೆ (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_peek_string_ನೇರ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ u_char **valp,
    ಗಾತ್ರ_t *lenp)
{
	uint32_t len;
	ಸ್ಥಿರಾಂಕ u_char *p = sshbuf_ptr(buf);

	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = ಖಾಲಿ;
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = 0;
	ಆದರೆ (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		ಹಿಂತಿರುಗಿ SSH_ERR_ಸಂದೇಶ_INCOMPLETE;
	}
	len = PEEK_U32(p);
	ಆದರೆ (len > SSHBUF_ಗಾತ್ರ_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		ಹಿಂತಿರುಗಿ SSH_ERR_STRING_TOO_LARGE;
	}
	ಆದರೆ (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		ಹಿಂತಿರುಗಿ SSH_ERR_ಸಂದೇಶ_INCOMPLETE;
	}
	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = p + 4;
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = len;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_get_cstring(ರಚನೆ sshbuf *buf, ಅಕ್ಷರ **valp, ಗಾತ್ರ_t *lenp)
{
	ಗಾತ್ರ_t len;
	ಸ್ಥಿರಾಂಕ u_char *p, *z;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = ಖಾಲಿ;
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = 0;
	ಆದರೆ ((r = sshbuf_peek_string_ನೇರ(buf, &p, &len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	/* Allow a \0 only at the end of the string */
	ಆದರೆ (len > 0 &&
	    (z = memchr(p , '\0', len)) != ಖಾಲಿ && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	}
	ಆದರೆ ((r = sshbuf_skip_string(buf)) != 0)
		ಹಿಂತಿರುಗಿ -1;
	ಆದರೆ (valp != ಖಾಲಿ) {
		ಆದರೆ ((*valp = ಸ್ಮರಣೆ_ಕೊಡು(len + 1)) == ಖಾಲಿ) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
		}
		ಆದರೆ (len != 0)
			ಸ್ಮರಣೆ_ನಕಲು(*valp, p, len);
		(*valp)[len] = '\0';
	}
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = (ಗಾತ್ರ_t)len;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_get_stringb(ರಚನೆ sshbuf *buf, ರಚನೆ sshbuf *v)
{
	uint32_t len;
	u_char *p;
	ಪೂರ್ಣಾಂಕ r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	ಆದರೆ ((r = sshbuf_peek_string_ನೇರ(buf, ಖಾಲಿ, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_put(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *v, ಗಾತ್ರ_t len)
{
	u_char *p;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_reserve(buf, len, &p)) < 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (len != 0)
		ಸ್ಮರಣೆ_ನಕಲು(p, v, len);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_putb(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *v)
{
	ಆದರೆ (v == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

ಪೂರ್ಣಾಂಕ
sshbuf_putf(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	va_list ap;
	ಪೂರ್ಣಾಂಕ r;

	va_start(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	va_end(ap);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshbuf_putfv(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, va_list ap)
{
	va_list ap2;
	ಪೂರ್ಣಾಂಕ r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	ಆದರೆ ((len = vsnprintf(ಖಾಲಿ, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (len == 0) {
		r = 0;
		ಹೋಗು ಹೊರಹೋಗು; /* Nothing to do */
	}
	va_end(ap2);
	VA_COPY(ap2, ap);
	ಆದರೆ ((r = sshbuf_reserve(buf, (ಗಾತ್ರ_t)len + 1, &p)) < 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = vsnprintf((ಅಕ್ಷರ *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_ಆಂತರಿಕ_ERROR;
		ಹೋಗು ಹೊರಹೋಗು; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	ಆದರೆ ((r = sshbuf_consume_ಕೊನೆ(buf, 1)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	r = 0;
 ಹೊರಹೋಗು:
	va_end(ap2);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshbuf_put_u64(ರಚನೆ sshbuf *buf, uint64_t val)
{
	u_char *p;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		ಹಿಂತಿರುಗಿ r;
	POKE_U64(p, val);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_put_u32(ರಚನೆ sshbuf *buf, uint32_t val)
{
	u_char *p;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		ಹಿಂತಿರುಗಿ r;
	POKE_U32(p, val);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_put_u16(ರಚನೆ sshbuf *buf, uint16_t val)
{
	u_char *p;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		ಹಿಂತಿರುಗಿ r;
	POKE_U16(p, val);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_put_u8(ರಚನೆ sshbuf *buf, u_char val)
{
	u_char *p;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		ಹಿಂತಿರುಗಿ r;
	p[0] = val;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
check_woffset(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ, ಗಾತ್ರ_t len, u_char **p)
{
	ಪೂರ್ಣಾಂಕ r;

	*p = ಖಾಲಿ;
	ಆದರೆ ((r = check_ಸ್ಥಾನಾಂತರ(buf, 1, ಸ್ಥಾನಾಂತರ, len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (sshbuf_mutable_ptr(buf) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಬಫರ್_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + ಸ್ಥಾನಾಂತರ;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_poke_u64(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ, uint64_t val)
{
	u_char *p = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = check_woffset(buf, ಸ್ಥಾನಾಂತರ, 8, &p)) != 0)
		ಹಿಂತಿರುಗಿ r;
	POKE_U64(p, val);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_poke_u32(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ, uint32_t val)
{
	u_char *p = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = check_woffset(buf, ಸ್ಥಾನಾಂತರ, 4, &p)) != 0)
		ಹಿಂತಿರುಗಿ r;
	POKE_U32(p, val);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_poke_u16(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ, uint16_t val)
{
	u_char *p = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = check_woffset(buf, ಸ್ಥಾನಾಂತರ, 2, &p)) != 0)
		ಹಿಂತಿರುಗಿ r;
	POKE_U16(p, val);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_poke_u8(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ, u_char val)
{
	u_char *p = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = check_woffset(buf, ಸ್ಥಾನಾಂತರ, 1, &p)) != 0)
		ಹಿಂತಿರುಗಿ r;
	*p = val;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_poke(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ, ಶೂನ್ಯ *v, ಗಾತ್ರ_t len)
{
	u_char *p = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = check_woffset(buf, ಸ್ಥಾನಾಂತರ, len, &p)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಸ್ಮರಣೆ_ನಕಲು(p, v, len);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_put_string(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *v, ಗಾತ್ರ_t len)
{
	u_char *d;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (len > SSHBUF_ಗಾತ್ರ_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		ಹಿಂತಿರುಗಿ SSH_ERR_NO_ಬಫರ್_SPACE;
	}
	ಆದರೆ ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		ಹಿಂತಿರುಗಿ r;
	POKE_U32(d, len);
	ಆದರೆ (len != 0)
		ಸ್ಮರಣೆ_ನಕಲು(d + 4, v, len);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_put_cstring(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *v)
{
	ಹಿಂತಿರುಗಿ sshbuf_put_string(buf, v, v == ಖಾಲಿ ? 0 : ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(v));
}

ಪೂರ್ಣಾಂಕ
sshbuf_put_stringb(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *v)
{
	ಆದರೆ (v == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ sshbuf_put_string(buf, ಖಾಲಿ, 0);

	ಹಿಂತಿರುಗಿ sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

ಪೂರ್ಣಾಂಕ
sshbuf_froms(ರಚನೆ sshbuf *buf, ರಚನೆ sshbuf **bufp)
{
	ಸ್ಥಿರಾಂಕ u_char *p;
	ಗಾತ್ರ_t len;
	ರಚನೆ sshbuf *ret;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (buf == ಖಾಲಿ || bufp == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	*bufp = ಖಾಲಿ;
	ಆದರೆ ((r = sshbuf_peek_string_ನೇರ(buf, &p, &len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((ret = sshbuf_from(p, len)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_ಗಣ_ಪೋಷಕ(ret, buf)) != 0) {
		sshbuf_free(ret);
		ಹಿಂತಿರುಗಿ r;
	}
	*bufp = ret;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_put_bignum2_ಬೈಟುಗಳು(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *v, ಗಾತ್ರ_t len)
{
	u_char *d;
	ಸ್ಥಿರಾಂಕ u_char *s = (ಸ್ಥಿರಾಂಕ u_char *)v;
	ಪೂರ್ಣಾಂಕ r, prepend;

	ಆದರೆ (len > SSHBUF_ಗಾತ್ರ_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		ಹಿಂತಿರುಗಿ SSH_ERR_NO_ಬಫರ್_SPACE;
	}
	/* Skip leading zero bytes */
	ಗಾಗಿ (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	ಆದರೆ ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		ಹಿಂತಿರುಗಿ r;
	POKE_U32(d, len + prepend);
	ಆದರೆ (prepend)
		d[4] = 0;
	ಆದರೆ (len != 0)
		ಸ್ಮರಣೆ_ನಕಲು(d + 4 + prepend, s, len);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_get_bignum2_ಬೈಟುಗಳು_ನೇರ(ರಚನೆ sshbuf *buf,
    ಸ್ಥಿರಾಂಕ u_char **valp, ಗಾತ್ರ_t *lenp)
{
	ಸ್ಥಿರಾಂಕ u_char *d;
	ಗಾತ್ರ_t len, olen;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_peek_string_ನೇರ(buf, &d, &olen)) < 0)
		ಹಿಂತಿರುಗಿ r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	ಆದರೆ ((len != 0 && (*d & 0x80) != 0))
		ಹಿಂತಿರುಗಿ SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	ಆದರೆ (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		ಹಿಂತಿರುಗಿ SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	ಆಗ (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = d;
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = len;
	ಆದರೆ (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_get_nulterminated_string(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t maxlen,
    ಅಕ್ಷರ **valp, ಗಾತ್ರ_t *lenp)
{
	ಸ್ಥಿರಾಂಕ u_char zero = 0;
	ಅಕ್ಷರ *val = ಖಾಲಿ;
	ಗಾತ್ರ_t len = 0;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (valp != ಖಾಲಿ)
		*valp = ಖಾಲಿ;
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = 0;
	ಆದರೆ ((r = sshbuf_ಕಂಡುಹಿಡಿ(buf, 0, &zero, ಗಾತ್ರ(zero), &len)) != 0) {
		ಆದರೆ (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			ಹಿಂತಿರುಗಿ SSH_ERR_ಸಂದೇಶ_INCOMPLETE;
		ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ (len > maxlen)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	ಆದರೆ ((val = strdup(sshbuf_ptr(buf))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_consume(buf, len + 1)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	r = 0;
	ಆದರೆ (valp != ಖಾಲಿ) {
		*valp = val;
		val = ಖಾಲಿ;
	}
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = len;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(val);
	ಹಿಂತಿರುಗಿ r;
}
