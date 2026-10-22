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
#define SSHBUF_INTERNAL
#ಅನ್ತರ್ಭಾವ "sshbuf.h"

ಶೂನ್ಯ
sshbuf_dump_data(ಧ್ರುವ ಶೂನ್ಯ *s, size_t len, FILE *f)
{
	size_t i, j;
	ಧ್ರುವ u_char *p = (ಧ್ರುವ u_char *)s;

	ಪ್ರತಿ (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		ಪ್ರತಿ (j = i; j < i + 16; j++) {
			ಯದಿ (j < len)
				fprintf(f, "%02x ", p[j]);
			ಅನ್ಯಥಾ
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		ಪ್ರತಿ (j = i; j < i + 16; j++) {
			ಯದಿ (j < len) {
				ಯದಿ  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				ಅನ್ಯಥಾ
					fprintf(f, ".");
			}
		}
		fprintf(f, "\n");
	}
}

ಶೂನ್ಯ
sshbuf_dump(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf, FILE *f)
{
	fprintf(f, "buffer len = %zu\n", sshbuf_len(buf));
	sshbuf_dump_data(sshbuf_ptr(buf), sshbuf_len(buf), f);
}

ವರ್ಣ *
sshbuf_dtob16(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf)
{
	size_t i, j, len = sshbuf_len(buf);
	ಧ್ರುವ u_char *p = sshbuf_ptr(buf);
	ವರ್ಣ *ret;
	ಧ್ರುವ ವರ್ಣ hex[] = "0123456789abcdef";

	ಯದಿ (len == 0)
		ಪ್ರತ್ಯಾಗಮ strdup("");
	ಯದಿ (SIZE_MAX / 2 <= len || (ret = malloc(len * 2 + 1)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಪ್ರತಿ (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
b16tod(ಧ್ರುವ ವರ್ಣ v)
{
	ಯದಿ (v >= '0' && v <= '9')
		ಪ್ರತ್ಯಾಗಮ v - '0';
	ಯದಿ (v >= 'a' && v <= 'f')
		ಪ್ರತ್ಯಾಗಮ 10 + v - 'a';
	ಯದಿ (v >= 'A' && v <= 'F')
		ಪ್ರತ್ಯಾಗಮ 10 + v - 'A';
	ಪ್ರತ್ಯಾಗಮ -1;
}

ಸಂರಚನಾ sshbuf *
sshbuf_b16tod(ಧ್ರುವ ವರ್ಣ *b16)
{
	ಸಂರಚನಾ sshbuf *ret;
	size_t o;
	ಪೂರ್ಣಾಙ್ಕ r, v1, v2;

	ಯದಿ ((ret = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಪ್ರತಿ (o = 0; b16[o] != '\0'; o += 2) {
		ಯದಿ ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
		}
		ಯದಿ ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
		}
	}
	/* success */
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_dtob64(ಧ್ರುವ ಸಂರಚನಾ sshbuf *d, ಸಂರಚನಾ sshbuf *b64, ಪೂರ್ಣಾಙ್ಕ wrap)
{
	size_t i, slen = 0;
	ವರ್ಣ *s = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (d == ರಿಕ್ತ || b64 == ರಿಕ್ತ || sshbuf_len(d) >= SIZE_MAX / 2)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (sshbuf_len(d) == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	ಯದಿ ((s = malloc(slen)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_INTERNAL_ERROR;
		ಗಚ್ಛ fail;
	}
	ಯದಿ (wrap) {
		ಪ್ರತಿ (i = 0; s[i] != '\0'; i++) {
			ಯದಿ ((r = sshbuf_put_u8(b64, s[i])) != 0)
				ಗಚ್ಛ fail;
			ಯದಿ (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				ಗಚ್ಛ fail;
		}
		ಯದಿ ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			ಗಚ್ಛ fail;
	} ಅನ್ಯಥಾ {
		ಯದಿ ((r = sshbuf_put(b64, s, strlen(s))) != 0)
			ಗಚ್ಛ fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	ಪ್ರತ್ಯಾಗಮ r;
}

ವರ್ಣ *
sshbuf_dtob64_string(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf, ಪೂರ್ಣಾಙ್ಕ wrap)
{
	ಸಂರಚನಾ sshbuf *tmp;
	ವರ್ಣ *ret;

	ಯದಿ ((tmp = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಯದಿ (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_b64tod(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ವರ್ಣ *b64)
{
	size_t plen = strlen(b64);
	ಪೂರ್ಣಾಙ್ಕ nlen, r;
	u_char *p;

	ಯದಿ (plen == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ ((p = malloc(plen)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	}
	ಯದಿ ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		ಪ್ರತ್ಯಾಗಮ r;
	}
	freezero(p, plen);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_dtourlb64(ಧ್ರುವ ಸಂರಚನಾ sshbuf *d, ಸಂರಚನಾ sshbuf *b64, ಪೂರ್ಣಾಙ್ಕ wrap)
{
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	u_char *p;
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	size_t i, l;

	ಯದಿ (sshbuf_len(d) == 0)
		ಪ್ರತ್ಯಾಗಮ 0;

	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	ಯದಿ ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		ಗಚ್ಛ out;
	/* remove padding from end of encoded string*/
	ಪ್ರತಿ (;;) {
		l = sshbuf_len(b);
		ಯದಿ (l <= 1 || sshbuf_ptr(b) == ರಿಕ್ತ) {
			r = SSH_ERR_INTERNAL_ERROR;
			ಗಚ್ಛ out;
		}
		ಯದಿ (sshbuf_ptr(b)[l - 1] != '=')
			ಭಙ್ಗ;
		ಯದಿ ((r = sshbuf_consume_end(b, 1)) != 0)
			ಗಚ್ಛ out;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	ಯದಿ ((p = sshbuf_mutable_ptr(b)) == ರಿಕ್ತ) {
		r = SSH_ERR_INTERNAL_ERROR;
		ಗಚ್ಛ out;
	}
	ಪ್ರತಿ (i = 0; i < l; i++) {
		ಯದಿ (p[i] == '+')
			p[i] = '-';
		ಅನ್ಯಥಾ ಯದಿ (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 out:
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ r;
}

ವರ್ಣ *
sshbuf_dup_string(ಸಂರಚನಾ sshbuf *buf)
{
	ಧ್ರುವ u_char *p = ರಿಕ್ತ, *s = sshbuf_ptr(buf);
	size_t l = sshbuf_len(buf);
	ವರ್ಣ *r;

	ಯದಿ (s == ರಿಕ್ತ || l >= SIZE_MAX)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	/* accept a nul only as the last character in the buffer */
	ಯದಿ (l > 0 && (p = memchr(s, '\0', l)) != ರಿಕ್ತ) {
		ಯದಿ (p != s + l - 1)
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
		l--; /* the nul is put back below */
	}
	ಯದಿ ((r = malloc(l + 1)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಯದಿ (l > 0)
		memcpy(r, s, l);
	r[l] = '\0';
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_cmp(ಧ್ರುವ ಸಂರಚನಾ sshbuf *b, size_t offset,
    ಧ್ರುವ ಶೂನ್ಯ *s, size_t len)
{
	ಯದಿ (sshbuf_ptr(b) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	ಯದಿ (offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (offset + len > sshbuf_len(b))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_MESSAGE_INCOMPLETE;
	ಯದಿ (timingsafe_bcmp(sshbuf_ptr(b) + offset, s, len) != 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_equals(ಧ್ರುವ ಸಂರಚನಾ sshbuf *a, ಧ್ರುವ ಸಂರಚನಾ sshbuf *b)
{
	ಯದಿ (sshbuf_ptr(a) == ರಿಕ್ತ || sshbuf_ptr(b) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	ಯದಿ (sshbuf_len(a) != sshbuf_len(b))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_MESSAGE_INCOMPLETE;
	ಯದಿ (sshbuf_len(a) == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_find(ಧ್ರುವ ಸಂರಚನಾ sshbuf *b, size_t start_offset,
    ಧ್ರುವ ಶೂನ್ಯ *s, size_t len, size_t *offsetp)
{
	ಶೂನ್ಯ *p;

	ಯದಿ (offsetp != ರಿಕ್ತ)
		*offsetp = 0;
	ಯದಿ (sshbuf_ptr(b) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	ಯದಿ (start_offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (start_offset > sshbuf_len(b) || start_offset + len > sshbuf_len(b))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_MESSAGE_INCOMPLETE;
	ಯದಿ ((p = memmem(sshbuf_ptr(b) + start_offset,
	    sshbuf_len(b) - start_offset, s, len)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	ಯದಿ (offsetp != ರಿಕ್ತ)
		*offsetp = (ಧ್ರುವ u_char *)p - sshbuf_ptr(b);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_read(ಪೂರ್ಣಾಙ್ಕ fd, ಸಂರಚನಾ sshbuf *buf, size_t maxlen, size_t *rlen)
{
	ಪೂರ್ಣಾಙ್ಕ r, oerrno;
	size_t adjust;
	ssize_t rr;
	u_char *d;

	ಯದಿ (rlen != ರಿಕ್ತ)
		*rlen = 0;
	ಯದಿ ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	rr = ಪಠ(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	ಯದಿ ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		ಯದಿ ((r = sshbuf_consume_end(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR; /* shouldn't happen */
		}
	}
	ಯದಿ (rr < 0) {
		errno = oerrno;
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
	} ಅನ್ಯಥಾ ಯದಿ (rr == 0) {
		errno = EPIPE;
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	ಯದಿ (rlen != ರಿಕ್ತ)
		*rlen = (size_t)rr;
	ಪ್ರತ್ಯಾಗಮ 0;
}
