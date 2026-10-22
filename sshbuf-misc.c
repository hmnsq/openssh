/*	$OpenBSD: sshbuf-misc.c,v 1.23 2026/03/28 05:10:25 djm Exp $	*/
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
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <resolv.h>
#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ವ್ಯಾಖ್ಯಾನಿಸು SSHBUF_ಆಂತರಿಕ
#ಅನ್ತರ್ಭಾವ "sshbuf.h"

ಶೂನ್ಯ
sshbuf_dump_ದತ್ತಾಂಶ(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *s, ಗಾತ್ರ_t len, FILE *f)
{
	ಗಾತ್ರ_t i, j;
	ಸ್ಥಿರಾಂಕ u_char *p = (ಸ್ಥಿರಾಂಕ u_char *)s;

	ಗಾಗಿ (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		ಗಾಗಿ (j = i; j < i + 16; j++) {
			ಆದರೆ (j < len)
				fprintf(f, "%02x ", p[j]);
			ಇಲ್ಲದಿದ್ದರೆ
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		ಗಾಗಿ (j = i; j < i + 16; j++) {
			ಆದರೆ (j < len) {
				ಆದರೆ  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				ಇಲ್ಲದಿದ್ದರೆ
					fprintf(f, ".");
			}
		}
		fprintf(f, "\n");
	}
}

ಶೂನ್ಯ
sshbuf_dump(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf, FILE *f)
{
	fprintf(f, "buffer len = %zu\n", sshbuf_len(buf));
	sshbuf_dump_ದತ್ತಾಂಶ(sshbuf_ptr(buf), sshbuf_len(buf), f);
}

ಅಕ್ಷರ *
sshbuf_dtob16(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf)
{
	ಗಾತ್ರ_t i, j, len = sshbuf_len(buf);
	ಸ್ಥಿರಾಂಕ u_char *p = sshbuf_ptr(buf);
	ಅಕ್ಷರ *ret;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ hex[] = "0123456789abcdef";

	ಆದರೆ (len == 0)
		ಹಿಂತಿರುಗಿ strdup("");
	ಆದರೆ (SIZE_MAX / 2 <= len || (ret = ಸ್ಮರಣೆ_ಕೊಡು(len * 2 + 1)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಗಾಗಿ (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
b16tod(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ v)
{
	ಆದರೆ (v >= '0' && v <= '9')
		ಹಿಂತಿರುಗಿ v - '0';
	ಆದರೆ (v >= 'a' && v <= 'f')
		ಹಿಂತಿರುಗಿ 10 + v - 'a';
	ಆದರೆ (v >= 'A' && v <= 'F')
		ಹಿಂತಿರುಗಿ 10 + v - 'A';
	ಹಿಂತಿರುಗಿ -1;
}

ರಚನೆ sshbuf *
sshbuf_b16tod(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *b16)
{
	ರಚನೆ sshbuf *ret;
	ಗಾತ್ರ_t o;
	ಪೂರ್ಣಾಂಕ r, v1, v2;

	ಆದರೆ ((ret = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಗಾಗಿ (o = 0; b16[o] != '\0'; o += 2) {
		ಆದರೆ ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			ಹಿಂತಿರುಗಿ ಖಾಲಿ;
		}
		ಆದರೆ ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			ಹಿಂತಿರುಗಿ ಖಾಲಿ;
		}
	}
	/* success */
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
sshbuf_dtob64(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *d, ರಚನೆ sshbuf *b64, ಪೂರ್ಣಾಂಕ wrap)
{
	ಗಾತ್ರ_t i, slen = 0;
	ಅಕ್ಷರ *s = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (d == ಖಾಲಿ || b64 == ಖಾಲಿ || sshbuf_len(d) >= SIZE_MAX / 2)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (sshbuf_len(d) == 0)
		ಹಿಂತಿರುಗಿ 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	ಆದರೆ ((s = ಸ್ಮರಣೆ_ಕೊಡು(slen)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_ಆಂತರಿಕ_ERROR;
		ಹೋಗು fail;
	}
	ಆದರೆ (wrap) {
		ಗಾಗಿ (i = 0; s[i] != '\0'; i++) {
			ಆದರೆ ((r = sshbuf_put_u8(b64, s[i])) != 0)
				ಹೋಗು fail;
			ಆದರೆ (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				ಹೋಗು fail;
		}
		ಆದರೆ ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			ಹೋಗು fail;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ ((r = sshbuf_put(b64, s, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(s))) != 0)
			ಹೋಗು fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	ಹಿಂತಿರುಗಿ r;
}

ಅಕ್ಷರ *
sshbuf_dtob64_string(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf, ಪೂರ್ಣಾಂಕ wrap)
{
	ರಚನೆ sshbuf *tmp;
	ಅಕ್ಷರ *ret;

	ಆದರೆ ((tmp = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಆದರೆ (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
sshbuf_b64tod(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *b64)
{
	ಗಾತ್ರ_t plen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(b64);
	ಪೂರ್ಣಾಂಕ nlen, r;
	u_char *p;

	ಆದರೆ (plen == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ ((p = ಸ್ಮರಣೆ_ಕೊಡು(plen)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	}
	ಆದರೆ ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		ಹಿಂತಿರುಗಿ r;
	}
	freezero(p, plen);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_dtourlb64(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *d, ರಚನೆ sshbuf *b64, ಪೂರ್ಣಾಂಕ wrap)
{
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	u_char *p;
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	ಗಾತ್ರ_t i, l;

	ಆದರೆ (sshbuf_len(d) == 0)
		ಹಿಂತಿರುಗಿ 0;

	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	ಆದರೆ ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* remove padding from end of encoded string*/
	ಗಾಗಿ (;;) {
		l = sshbuf_len(b);
		ಆದರೆ (l <= 1 || sshbuf_ptr(b) == ಖಾಲಿ) {
			r = SSH_ERR_ಆಂತರಿಕ_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (sshbuf_ptr(b)[l - 1] != '=')
			ನಿಲ್ಲಿಸು;
		ಆದರೆ ((r = sshbuf_consume_ಕೊನೆ(b, 1)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	ಆದರೆ ((p = sshbuf_mutable_ptr(b)) == ಖಾಲಿ) {
		r = SSH_ERR_ಆಂತರಿಕ_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಗಾಗಿ (i = 0; i < l; i++) {
		ಆದರೆ (p[i] == '+')
			p[i] = '-';
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ r;
}

ಅಕ್ಷರ *
sshbuf_dup_string(ರಚನೆ sshbuf *buf)
{
	ಸ್ಥಿರಾಂಕ u_char *p = ಖಾಲಿ, *s = sshbuf_ptr(buf);
	ಗಾತ್ರ_t l = sshbuf_len(buf);
	ಅಕ್ಷರ *r;

	ಆದರೆ (s == ಖಾಲಿ || l >= SIZE_MAX)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	/* accept a nul only as the last character in the buffer */
	ಆದರೆ (l > 0 && (p = memchr(s, '\0', l)) != ಖಾಲಿ) {
		ಆದರೆ (p != s + l - 1)
			ಹಿಂತಿರುಗಿ ಖಾಲಿ;
		l--; /* the nul is put back below */
	}
	ಆದರೆ ((r = ಸ್ಮರಣೆ_ಕೊಡು(l + 1)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಆದರೆ (l > 0)
		ಸ್ಮರಣೆ_ನಕಲು(r, s, l);
	r[l] = '\0';
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshbuf_cmp(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *b, ಗಾತ್ರ_t ಸ್ಥಾನಾಂತರ,
    ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *s, ಗಾತ್ರ_t len)
{
	ಆದರೆ (sshbuf_ptr(b) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಆದರೆ (ಸ್ಥಾನಾಂತರ > SSHBUF_ಗಾತ್ರ_MAX || len > SSHBUF_ಗಾತ್ರ_MAX || len == 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (ಸ್ಥಾನಾಂತರ + len > sshbuf_len(b))
		ಹಿಂತಿರುಗಿ SSH_ERR_ಸಂದೇಶ_INCOMPLETE;
	ಆದರೆ (timingsafe_bcmp(sshbuf_ptr(b) + ಸ್ಥಾನಾಂತರ, s, len) != 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_equals(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *a, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *b)
{
	ಆದರೆ (sshbuf_ptr(a) == ಖಾಲಿ || sshbuf_ptr(b) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಆದರೆ (sshbuf_len(a) != sshbuf_len(b))
		ಹಿಂತಿರುಗಿ SSH_ERR_ಸಂದೇಶ_INCOMPLETE;
	ಆದರೆ (sshbuf_len(a) == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_ಕಂಡುಹಿಡಿ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *b, ಗಾತ್ರ_t ಆರಂಭ_ಸ್ಥಾನಾಂತರ,
    ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *s, ಗಾತ್ರ_t len, ಗಾತ್ರ_t *offsetp)
{
	ಶೂನ್ಯ *p;

	ಆದರೆ (offsetp != ಖಾಲಿ)
		*offsetp = 0;
	ಆದರೆ (sshbuf_ptr(b) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಆದರೆ (ಆರಂಭ_ಸ್ಥಾನಾಂತರ > SSHBUF_ಗಾತ್ರ_MAX || len > SSHBUF_ಗಾತ್ರ_MAX || len == 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (ಆರಂಭ_ಸ್ಥಾನಾಂತರ > sshbuf_len(b) || ಆರಂಭ_ಸ್ಥಾನಾಂತರ + len > sshbuf_len(b))
		ಹಿಂತಿರುಗಿ SSH_ERR_ಸಂದೇಶ_INCOMPLETE;
	ಆದರೆ ((p = memmem(sshbuf_ptr(b) + ಆರಂಭ_ಸ್ಥಾನಾಂತರ,
	    sshbuf_len(b) - ಆರಂಭ_ಸ್ಥಾನಾಂತರ, s, len)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	ಆದರೆ (offsetp != ಖಾಲಿ)
		*offsetp = (ಸ್ಥಿರಾಂಕ u_char *)p - sshbuf_ptr(b);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_read(ಪೂರ್ಣಾಂಕ fd, ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t maxlen, ಗಾತ್ರ_t *rlen)
{
	ಪೂರ್ಣಾಂಕ r, oerrno;
	ಗಾತ್ರ_t adjust;
	ssize_t rr;
	u_char *d;

	ಆದರೆ (rlen != ಖಾಲಿ)
		*rlen = 0;
	ಆದರೆ ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		ಹಿಂತಿರುಗಿ r;
	rr = ಪಠ(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	ಆದರೆ ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		ಆದರೆ ((r = sshbuf_consume_ಕೊನೆ(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR; /* shouldn't happen */
		}
	}
	ಆದರೆ (rr < 0) {
		errno = oerrno;
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (rr == 0) {
		errno = EPIPE;
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	ಆದರೆ (rlen != ಖಾಲಿ)
		*rlen = (ಗಾತ್ರ_t)rr;
	ಹಿಂತಿರುಗಿ 0;
}
