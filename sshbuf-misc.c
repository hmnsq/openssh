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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <resolv.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHBUF_ਅੰਦਰੂਨੀ
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"

ਖਾਲੀ
sshbuf_dump_ਅੰਕੜੇ(ਅਚਲ ਖਾਲੀ *s, ਮਾਪ_t len, FILE *f)
{
	ਮਾਪ_t i, j;
	ਅਚਲ u_char *p = (ਅਚਲ u_char *)s;

	ਲਈ (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		ਲਈ (j = i; j < i + 16; j++) {
			ਜੇ (j < len)
				fprintf(f, "%02x ", p[j]);
			ਨਹੀਂਤਾਂ
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		ਲਈ (j = i; j < i + 16; j++) {
			ਜੇ (j < len) {
				ਜੇ  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				ਨਹੀਂਤਾਂ
					fprintf(f, ".");
			}
		}
		fprintf(f, "\n");
	}
}

ਖਾਲੀ
sshbuf_dump(ਅਚਲ ਬਣਤਰ sshbuf *buf, FILE *f)
{
	fprintf(f, "buffer len = %zu\n", sshbuf_len(buf));
	sshbuf_dump_ਅੰਕੜੇ(sshbuf_ptr(buf), sshbuf_len(buf), f);
}

ਅੱਖਰ *
sshbuf_dtob16(ਅਚਲ ਬਣਤਰ sshbuf *buf)
{
	ਮਾਪ_t i, j, len = sshbuf_len(buf);
	ਅਚਲ u_char *p = sshbuf_ptr(buf);
	ਅੱਖਰ *ret;
	ਅਚਲ ਅੱਖਰ hex[] = "0123456789abcdef";

	ਜੇ (len == 0)
		ਵਾਪਸ strdup("");
	ਜੇ (SIZE_MAX / 2 <= len || (ret = ਸਮ੍ਰਿਤੀ_ਦਿਓ(len * 2 + 1)) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ਲਈ (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
b16tod(ਅਚਲ ਅੱਖਰ v)
{
	ਜੇ (v >= '0' && v <= '9')
		ਵਾਪਸ v - '0';
	ਜੇ (v >= 'a' && v <= 'f')
		ਵਾਪਸ 10 + v - 'a';
	ਜੇ (v >= 'A' && v <= 'F')
		ਵਾਪਸ 10 + v - 'A';
	ਵਾਪਸ -1;
}

ਬਣਤਰ sshbuf *
sshbuf_b16tod(ਅਚਲ ਅੱਖਰ *b16)
{
	ਬਣਤਰ sshbuf *ret;
	ਮਾਪ_t o;
	ਪੂਰਨ r, v1, v2;

	ਜੇ ((ret = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ਲਈ (o = 0; b16[o] != '\0'; o += 2) {
		ਜੇ ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			ਵਾਪਸ ਨਿਰਾ;
		}
		ਜੇ ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			ਵਾਪਸ ਨਿਰਾ;
		}
	}
	/* success */
	ਵਾਪਸ ret;
}

ਪੂਰਨ
sshbuf_dtob64(ਅਚਲ ਬਣਤਰ sshbuf *d, ਬਣਤਰ sshbuf *b64, ਪੂਰਨ wrap)
{
	ਮਾਪ_t i, slen = 0;
	ਅੱਖਰ *s = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ (d == ਨਿਰਾ || b64 == ਨਿਰਾ || sshbuf_len(d) >= SIZE_MAX / 2)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (sshbuf_len(d) == 0)
		ਵਾਪਸ 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	ਜੇ ((s = ਸਮ੍ਰਿਤੀ_ਦਿਓ(slen)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
		ਜਾਓ fail;
	}
	ਜੇ (wrap) {
		ਲਈ (i = 0; s[i] != '\0'; i++) {
			ਜੇ ((r = sshbuf_put_u8(b64, s[i])) != 0)
				ਜਾਓ fail;
			ਜੇ (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				ਜਾਓ fail;
		}
		ਜੇ ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			ਜਾਓ fail;
	} ਨਹੀਂਤਾਂ {
		ਜੇ ((r = sshbuf_put(b64, s, ਲੜੀ_ਲੰਬਾਈ(s))) != 0)
			ਜਾਓ fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	ਵਾਪਸ r;
}

ਅੱਖਰ *
sshbuf_dtob64_string(ਅਚਲ ਬਣਤਰ sshbuf *buf, ਪੂਰਨ wrap)
{
	ਬਣਤਰ sshbuf *tmp;
	ਅੱਖਰ *ret;

	ਜੇ ((tmp = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ਜੇ (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
sshbuf_b64tod(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਅੱਖਰ *b64)
{
	ਮਾਪ_t plen = ਲੜੀ_ਲੰਬਾਈ(b64);
	ਪੂਰਨ nlen, r;
	u_char *p;

	ਜੇ (plen == 0)
		ਵਾਪਸ 0;
	ਜੇ ((p = ਸਮ੍ਰਿਤੀ_ਦਿਓ(plen)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	}
	ਜੇ ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		ਵਾਪਸ r;
	}
	freezero(p, plen);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_dtourlb64(ਅਚਲ ਬਣਤਰ sshbuf *d, ਬਣਤਰ sshbuf *b64, ਪੂਰਨ wrap)
{
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	u_char *p;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	ਮਾਪ_t i, l;

	ਜੇ (sshbuf_len(d) == 0)
		ਵਾਪਸ 0;

	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	ਜੇ ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* remove padding from end of encoded string*/
	ਲਈ (;;) {
		l = sshbuf_len(b);
		ਜੇ (l <= 1 || sshbuf_ptr(b) == ਨਿਰਾ) {
			r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (sshbuf_ptr(b)[l - 1] != '=')
			ਰੋਕੋ;
		ਜੇ ((r = sshbuf_consume_ਸਿਰਾ(b, 1)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	ਜੇ ((p = sshbuf_mutable_ptr(b)) == ਨਿਰਾ) {
		r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਲਈ (i = 0; i < l; i++) {
		ਜੇ (p[i] == '+')
			p[i] = '-';
		ਨਹੀਂਤਾਂ ਜੇ (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਵਾਪਸ r;
}

ਅੱਖਰ *
sshbuf_dup_string(ਬਣਤਰ sshbuf *buf)
{
	ਅਚਲ u_char *p = ਨਿਰਾ, *s = sshbuf_ptr(buf);
	ਮਾਪ_t l = sshbuf_len(buf);
	ਅੱਖਰ *r;

	ਜੇ (s == ਨਿਰਾ || l >= SIZE_MAX)
		ਵਾਪਸ ਨਿਰਾ;
	/* accept a nul only as the last character in the buffer */
	ਜੇ (l > 0 && (p = memchr(s, '\0', l)) != ਨਿਰਾ) {
		ਜੇ (p != s + l - 1)
			ਵਾਪਸ ਨਿਰਾ;
		l--; /* the nul is put back below */
	}
	ਜੇ ((r = ਸਮ੍ਰਿਤੀ_ਦਿਓ(l + 1)) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ਜੇ (l > 0)
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(r, s, l);
	r[l] = '\0';
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshbuf_cmp(ਅਚਲ ਬਣਤਰ sshbuf *b, ਮਾਪ_t ਵਿੱਥ,
    ਅਚਲ ਖਾਲੀ *s, ਮਾਪ_t len)
{
	ਜੇ (sshbuf_ptr(b) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਜੇ (ਵਿੱਥ > SSHBUF_ਮਾਪ_MAX || len > SSHBUF_ਮਾਪ_MAX || len == 0)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (ਵਿੱਥ + len > sshbuf_len(b))
		ਵਾਪਸ SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE;
	ਜੇ (timingsafe_bcmp(sshbuf_ptr(b) + ਵਿੱਥ, s, len) != 0)
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_equals(ਅਚਲ ਬਣਤਰ sshbuf *a, ਅਚਲ ਬਣਤਰ sshbuf *b)
{
	ਜੇ (sshbuf_ptr(a) == ਨਿਰਾ || sshbuf_ptr(b) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਜੇ (sshbuf_len(a) != sshbuf_len(b))
		ਵਾਪਸ SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE;
	ਜੇ (sshbuf_len(a) == 0)
		ਵਾਪਸ 0;
	ਜੇ (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_ਲੱਭੋ(ਅਚਲ ਬਣਤਰ sshbuf *b, ਮਾਪ_t ਸ਼ੁਰੂ_ਵਿੱਥ,
    ਅਚਲ ਖਾਲੀ *s, ਮਾਪ_t len, ਮਾਪ_t *offsetp)
{
	ਖਾਲੀ *p;

	ਜੇ (offsetp != ਨਿਰਾ)
		*offsetp = 0;
	ਜੇ (sshbuf_ptr(b) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਜੇ (ਸ਼ੁਰੂ_ਵਿੱਥ > SSHBUF_ਮਾਪ_MAX || len > SSHBUF_ਮਾਪ_MAX || len == 0)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (ਸ਼ੁਰੂ_ਵਿੱਥ > sshbuf_len(b) || ਸ਼ੁਰੂ_ਵਿੱਥ + len > sshbuf_len(b))
		ਵਾਪਸ SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE;
	ਜੇ ((p = memmem(sshbuf_ptr(b) + ਸ਼ੁਰੂ_ਵਿੱਥ,
	    sshbuf_len(b) - ਸ਼ੁਰੂ_ਵਿੱਥ, s, len)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	ਜੇ (offsetp != ਨਿਰਾ)
		*offsetp = (ਅਚਲ u_char *)p - sshbuf_ptr(b);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_read(ਪੂਰਨ fd, ਬਣਤਰ sshbuf *buf, ਮਾਪ_t maxlen, ਮਾਪ_t *rlen)
{
	ਪੂਰਨ r, oerrno;
	ਮਾਪ_t adjust;
	ssize_t rr;
	u_char *d;

	ਜੇ (rlen != ਨਿਰਾ)
		*rlen = 0;
	ਜੇ ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		ਵਾਪਸ r;
	rr = ਪਠ(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	ਜੇ ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		ਜੇ ((r = sshbuf_consume_ਸਿਰਾ(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR; /* shouldn't happen */
		}
	}
	ਜੇ (rr < 0) {
		errno = oerrno;
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
	} ਨਹੀਂਤਾਂ ਜੇ (rr == 0) {
		errno = EPIPE;
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	ਜੇ (rlen != ਨਿਰਾ)
		*rlen = (ਮਾਪ_t)rr;
	ਵਾਪਸ 0;
}
