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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <netinet/in.h>
#شامل <errno.h>
#شامل <stdlib.h>
#شامل <stdint.h>
#شامل <stdio.h>
#شامل <limits.h>
#شامل <string.h>
#شامل <resolv.h>
#شامل <ctype.h>
#شامل <unistd.h>

#شامل "ssherr.h"
#define SSHBUF_INTERNAL
#شامل "sshbuf.h"

تهی
sshbuf_dump_data(ثابت تهی *s, size_t len, FILE *f)
{
	size_t i, j;
	ثابت u_char *p = (ثابت u_char *)s;

	برای (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		برای (j = i; j < i + 16; j++) {
			اگر (j < len)
				fprintf(f, "%02x ", p[j]);
			وگرنه
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		برای (j = i; j < i + 16; j++) {
			اگر (j < len) {
				اگر  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				وگرنه
					fprintf(f, ".");
			}
		}
		fprintf(f, "\n");
	}
}

تهی
sshbuf_dump(ثابت ساختار sshbuf *buf, FILE *f)
{
	fprintf(f, "buffer len = %zu\n", sshbuf_len(buf));
	sshbuf_dump_data(sshbuf_ptr(buf), sshbuf_len(buf), f);
}

نویسه *
sshbuf_dtob16(ثابت ساختار sshbuf *buf)
{
	size_t i, j, len = sshbuf_len(buf);
	ثابت u_char *p = sshbuf_ptr(buf);
	نویسه *ret;
	ثابت نویسه hex[] = "0123456789abcdef";

	اگر (len == 0)
		بازگشت strdup("");
	اگر (SIZE_MAX / 2 <= len || (ret = malloc(len * 2 + 1)) == پوچ)
		بازگشت پوچ;
	برای (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	بازگشت ret;
}

ایستا صحیح
b16tod(ثابت نویسه v)
{
	اگر (v >= '0' && v <= '9')
		بازگشت v - '0';
	اگر (v >= 'a' && v <= 'f')
		بازگشت 10 + v - 'a';
	اگر (v >= 'A' && v <= 'F')
		بازگشت 10 + v - 'A';
	بازگشت -1;
}

ساختار sshbuf *
sshbuf_b16tod(ثابت نویسه *b16)
{
	ساختار sshbuf *ret;
	size_t o;
	صحیح r, v1, v2;

	اگر ((ret = sshbuf_new()) == پوچ)
		بازگشت پوچ;
	برای (o = 0; b16[o] != '\0'; o += 2) {
		اگر ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			بازگشت پوچ;
		}
		اگر ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			بازگشت پوچ;
		}
	}
	/* success */
	بازگشت ret;
}

صحیح
sshbuf_dtob64(ثابت ساختار sshbuf *d, ساختار sshbuf *b64, صحیح wrap)
{
	size_t i, slen = 0;
	نویسه *s = پوچ;
	صحیح r;

	اگر (d == پوچ || b64 == پوچ || sshbuf_len(d) >= SIZE_MAX / 2)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر (sshbuf_len(d) == 0)
		بازگشت 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	اگر ((s = malloc(slen)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_INTERNAL_ERROR;
		برو fail;
	}
	اگر (wrap) {
		برای (i = 0; s[i] != '\0'; i++) {
			اگر ((r = sshbuf_put_u8(b64, s[i])) != 0)
				برو fail;
			اگر (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				برو fail;
		}
		اگر ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			برو fail;
	} وگرنه {
		اگر ((r = sshbuf_put(b64, s, strlen(s))) != 0)
			برو fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	بازگشت r;
}

نویسه *
sshbuf_dtob64_string(ثابت ساختار sshbuf *buf, صحیح wrap)
{
	ساختار sshbuf *tmp;
	نویسه *ret;

	اگر ((tmp = sshbuf_new()) == پوچ)
		بازگشت پوچ;
	اگر (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		بازگشت پوچ;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	بازگشت ret;
}

صحیح
sshbuf_b64tod(ساختار sshbuf *buf, ثابت نویسه *b64)
{
	size_t plen = strlen(b64);
	صحیح nlen, r;
	u_char *p;

	اگر (plen == 0)
		بازگشت 0;
	اگر ((p = malloc(plen)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		بازگشت SSH_ERR_INVALID_FORMAT;
	}
	اگر ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		بازگشت r;
	}
	freezero(p, plen);
	بازگشت 0;
}

صحیح
sshbuf_dtourlb64(ثابت ساختار sshbuf *d, ساختار sshbuf *b64, صحیح wrap)
{
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	u_char *p;
	ساختار sshbuf *b = پوچ;
	size_t i, l;

	اگر (sshbuf_len(d) == 0)
		بازگشت 0;

	اگر ((b = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	اگر ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		برو out;
	/* remove padding from end of encoded string*/
	برای (;;) {
		l = sshbuf_len(b);
		اگر (l <= 1 || sshbuf_ptr(b) == پوچ) {
			r = SSH_ERR_INTERNAL_ERROR;
			برو out;
		}
		اگر (sshbuf_ptr(b)[l - 1] != '=')
			بشکن;
		اگر ((r = sshbuf_consume_end(b, 1)) != 0)
			برو out;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	اگر ((p = sshbuf_mutable_ptr(b)) == پوچ) {
		r = SSH_ERR_INTERNAL_ERROR;
		برو out;
	}
	برای (i = 0; i < l; i++) {
		اگر (p[i] == '+')
			p[i] = '-';
		وگرنه اگر (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 out:
	sshbuf_free(b);
	بازگشت r;
}

نویسه *
sshbuf_dup_string(ساختار sshbuf *buf)
{
	ثابت u_char *p = پوچ, *s = sshbuf_ptr(buf);
	size_t l = sshbuf_len(buf);
	نویسه *r;

	اگر (s == پوچ || l >= SIZE_MAX)
		بازگشت پوچ;
	/* accept a nul only as the last character in the buffer */
	اگر (l > 0 && (p = memchr(s, '\0', l)) != پوچ) {
		اگر (p != s + l - 1)
			بازگشت پوچ;
		l--; /* the nul is put back below */
	}
	اگر ((r = malloc(l + 1)) == پوچ)
		بازگشت پوچ;
	اگر (l > 0)
		memcpy(r, s, l);
	r[l] = '\0';
	بازگشت r;
}

صحیح
sshbuf_cmp(ثابت ساختار sshbuf *b, size_t offset,
    ثابت تهی *s, size_t len)
{
	اگر (sshbuf_ptr(b) == پوچ)
		بازگشت SSH_ERR_INTERNAL_ERROR;
	اگر (offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر (offset + len > sshbuf_len(b))
		بازگشت SSH_ERR_MESSAGE_INCOMPLETE;
	اگر (timingsafe_bcmp(sshbuf_ptr(b) + offset, s, len) != 0)
		بازگشت SSH_ERR_INVALID_FORMAT;
	بازگشت 0;
}

صحیح
sshbuf_equals(ثابت ساختار sshbuf *a, ثابت ساختار sshbuf *b)
{
	اگر (sshbuf_ptr(a) == پوچ || sshbuf_ptr(b) == پوچ)
		بازگشت SSH_ERR_INTERNAL_ERROR;
	اگر (sshbuf_len(a) != sshbuf_len(b))
		بازگشت SSH_ERR_MESSAGE_INCOMPLETE;
	اگر (sshbuf_len(a) == 0)
		بازگشت 0;
	اگر (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		بازگشت SSH_ERR_INVALID_FORMAT;
	بازگشت 0;
}

صحیح
sshbuf_find(ثابت ساختار sshbuf *b, size_t start_offset,
    ثابت تهی *s, size_t len, size_t *offsetp)
{
	تهی *p;

	اگر (offsetp != پوچ)
		*offsetp = 0;
	اگر (sshbuf_ptr(b) == پوچ)
		بازگشت SSH_ERR_INTERNAL_ERROR;
	اگر (start_offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر (start_offset > sshbuf_len(b) || start_offset + len > sshbuf_len(b))
		بازگشت SSH_ERR_MESSAGE_INCOMPLETE;
	اگر ((p = memmem(sshbuf_ptr(b) + start_offset,
	    sshbuf_len(b) - start_offset, s, len)) == پوچ)
		بازگشت SSH_ERR_INVALID_FORMAT;
	اگر (offsetp != پوچ)
		*offsetp = (ثابت u_char *)p - sshbuf_ptr(b);
	بازگشت 0;
}

صحیح
sshbuf_read(صحیح fd, ساختار sshbuf *buf, size_t maxlen, size_t *rlen)
{
	صحیح r, oerrno;
	size_t adjust;
	ssize_t rr;
	u_char *d;

	اگر (rlen != پوچ)
		*rlen = 0;
	اگر ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		بازگشت r;
	rr = اقرأ(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	اگر ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		اگر ((r = sshbuf_consume_end(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			بازگشت SSH_ERR_INTERNAL_ERROR; /* shouldn't happen */
		}
	}
	اگر (rr < 0) {
		errno = oerrno;
		بازگشت SSH_ERR_SYSTEM_ERROR;
	} وگرنه اگر (rr == 0) {
		errno = EPIPE;
		بازگشت SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	اگر (rlen != پوچ)
		*rlen = (size_t)rr;
	بازگشت 0;
}
