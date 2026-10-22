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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/socket.h>
#ضمن <netinet/in.h>
#ضمن <errno.h>
#ضمن <stdlib.h>
#ضمن <stdint.h>
#ضمن <stdio.h>
#ضمن <limits.h>
#ضمن <string.h>
#ضمن <resolv.h>
#ضمن <ctype.h>
#ضمن <unistd.h>

#ضمن "ssherr.h"
#define SSHBUF_INTERNAL
#ضمن "sshbuf.h"

فراغ
sshbuf_dump_data(ثابت فراغ *s, size_t len, FILE *f)
{
	size_t i, j;
	ثابت u_char *p = (ثابت u_char *)s;

	עבור (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		עבור (j = i; j < i + 16; j++) {
			אם (j < len)
				fprintf(f, "%02x ", p[j]);
			אחרת
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		עבור (j = i; j < i + 16; j++) {
			אם (j < len) {
				אם  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				אחרת
					fprintf(f, ".");
			}
		}
		fprintf(f, "\n");
	}
}

فراغ
sshbuf_dump(ثابت بنية sshbuf *buf, FILE *f)
{
	fprintf(f, "buffer len = %zu\n", sshbuf_len(buf));
	sshbuf_dump_data(sshbuf_ptr(buf), sshbuf_len(buf), f);
}

حرف *
sshbuf_dtob16(ثابت بنية sshbuf *buf)
{
	size_t i, j, len = sshbuf_len(buf);
	ثابت u_char *p = sshbuf_ptr(buf);
	حرف *ret;
	ثابت حرف hex[] = "0123456789abcdef";

	אם (len == 0)
		החזר strdup("");
	אם (SIZE_MAX / 2 <= len || (ret = malloc(len * 2 + 1)) == عدم)
		החזר عدم;
	עבור (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	החזר ret;
}

ساكن صحيح
b16tod(ثابت حرف v)
{
	אם (v >= '0' && v <= '9')
		החזר v - '0';
	אם (v >= 'a' && v <= 'f')
		החזר 10 + v - 'a';
	אם (v >= 'A' && v <= 'F')
		החזר 10 + v - 'A';
	החזר -1;
}

بنية sshbuf *
sshbuf_b16tod(ثابت حرف *b16)
{
	بنية sshbuf *ret;
	size_t o;
	صحيح r, v1, v2;

	אם ((ret = sshbuf_new()) == عدم)
		החזר عدم;
	עבור (o = 0; b16[o] != '\0'; o += 2) {
		אם ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			החזר عدم;
		}
		אם ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			החזר عدم;
		}
	}
	/* success */
	החזר ret;
}

صحيح
sshbuf_dtob64(ثابت بنية sshbuf *d, بنية sshbuf *b64, صحيح wrap)
{
	size_t i, slen = 0;
	حرف *s = عدم;
	صحيح r;

	אם (d == عدم || b64 == عدم || sshbuf_len(d) >= SIZE_MAX / 2)
		החזר SSH_ERR_INVALID_ARGUMENT;
	אם (sshbuf_len(d) == 0)
		החזר 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	אם ((s = malloc(slen)) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_INTERNAL_ERROR;
		اذهب fail;
	}
	אם (wrap) {
		עבור (i = 0; s[i] != '\0'; i++) {
			אם ((r = sshbuf_put_u8(b64, s[i])) != 0)
				اذهب fail;
			אם (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				اذهب fail;
		}
		אם ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			اذهب fail;
	} אחרת {
		אם ((r = sshbuf_put(b64, s, strlen(s))) != 0)
			اذهب fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	החזר r;
}

حرف *
sshbuf_dtob64_string(ثابت بنية sshbuf *buf, صحيح wrap)
{
	بنية sshbuf *tmp;
	حرف *ret;

	אם ((tmp = sshbuf_new()) == عدم)
		החזר عدم;
	אם (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		החזר عدم;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	החזר ret;
}

صحيح
sshbuf_b64tod(بنية sshbuf *buf, ثابت حرف *b64)
{
	size_t plen = strlen(b64);
	صحيح nlen, r;
	u_char *p;

	אם (plen == 0)
		החזר 0;
	אם ((p = malloc(plen)) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		החזר SSH_ERR_INVALID_FORMAT;
	}
	אם ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		החזר r;
	}
	freezero(p, plen);
	החזר 0;
}

صحيح
sshbuf_dtourlb64(ثابت بنية sshbuf *d, بنية sshbuf *b64, صحيح wrap)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	u_char *p;
	بنية sshbuf *b = عدم;
	size_t i, l;

	אם (sshbuf_len(d) == 0)
		החזר 0;

	אם ((b = sshbuf_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	אם ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		اذهب out;
	/* remove padding from end of encoded string*/
	עבור (;;) {
		l = sshbuf_len(b);
		אם (l <= 1 || sshbuf_ptr(b) == عدم) {
			r = SSH_ERR_INTERNAL_ERROR;
			اذهب out;
		}
		אם (sshbuf_ptr(b)[l - 1] != '=')
			اكسر;
		אם ((r = sshbuf_consume_end(b, 1)) != 0)
			اذهب out;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	אם ((p = sshbuf_mutable_ptr(b)) == عدم) {
		r = SSH_ERR_INTERNAL_ERROR;
		اذهب out;
	}
	עבור (i = 0; i < l; i++) {
		אם (p[i] == '+')
			p[i] = '-';
		אחרת אם (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 out:
	sshbuf_free(b);
	החזר r;
}

حرف *
sshbuf_dup_string(بنية sshbuf *buf)
{
	ثابت u_char *p = عدم, *s = sshbuf_ptr(buf);
	size_t l = sshbuf_len(buf);
	حرف *r;

	אם (s == عدم || l >= SIZE_MAX)
		החזר عدم;
	/* accept a nul only as the last character in the buffer */
	אם (l > 0 && (p = memchr(s, '\0', l)) != عدم) {
		אם (p != s + l - 1)
			החזר عدم;
		l--; /* the nul is put back below */
	}
	אם ((r = malloc(l + 1)) == عدم)
		החזר عدم;
	אם (l > 0)
		memcpy(r, s, l);
	r[l] = '\0';
	החזר r;
}

صحيح
sshbuf_cmp(ثابت بنية sshbuf *b, size_t offset,
    ثابت فراغ *s, size_t len)
{
	אם (sshbuf_ptr(b) == عدم)
		החזר SSH_ERR_INTERNAL_ERROR;
	אם (offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		החזר SSH_ERR_INVALID_ARGUMENT;
	אם (offset + len > sshbuf_len(b))
		החזר SSH_ERR_MESSAGE_INCOMPLETE;
	אם (timingsafe_bcmp(sshbuf_ptr(b) + offset, s, len) != 0)
		החזר SSH_ERR_INVALID_FORMAT;
	החזר 0;
}

صحيح
sshbuf_equals(ثابت بنية sshbuf *a, ثابت بنية sshbuf *b)
{
	אם (sshbuf_ptr(a) == عدم || sshbuf_ptr(b) == عدم)
		החזר SSH_ERR_INTERNAL_ERROR;
	אם (sshbuf_len(a) != sshbuf_len(b))
		החזר SSH_ERR_MESSAGE_INCOMPLETE;
	אם (sshbuf_len(a) == 0)
		החזר 0;
	אם (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		החזר SSH_ERR_INVALID_FORMAT;
	החזר 0;
}

صحيح
sshbuf_find(ثابت بنية sshbuf *b, size_t start_offset,
    ثابت فراغ *s, size_t len, size_t *offsetp)
{
	فراغ *p;

	אם (offsetp != عدم)
		*offsetp = 0;
	אם (sshbuf_ptr(b) == عدم)
		החזר SSH_ERR_INTERNAL_ERROR;
	אם (start_offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		החזר SSH_ERR_INVALID_ARGUMENT;
	אם (start_offset > sshbuf_len(b) || start_offset + len > sshbuf_len(b))
		החזר SSH_ERR_MESSAGE_INCOMPLETE;
	אם ((p = memmem(sshbuf_ptr(b) + start_offset,
	    sshbuf_len(b) - start_offset, s, len)) == عدم)
		החזר SSH_ERR_INVALID_FORMAT;
	אם (offsetp != عدم)
		*offsetp = (ثابت u_char *)p - sshbuf_ptr(b);
	החזר 0;
}

صحيح
sshbuf_read(صحيح fd, بنية sshbuf *buf, size_t maxlen, size_t *rlen)
{
	صحيح r, oerrno;
	size_t adjust;
	ssize_t rr;
	u_char *d;

	אם (rlen != عدم)
		*rlen = 0;
	אם ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		החזר r;
	rr = اقرأ(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	אם ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		אם ((r = sshbuf_consume_end(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			החזר SSH_ERR_INTERNAL_ERROR; /* shouldn't happen */
		}
	}
	אם (rr < 0) {
		errno = oerrno;
		החזר SSH_ERR_SYSTEM_ERROR;
	} אחרת אם (rr == 0) {
		errno = EPIPE;
		החזר SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	אם (rlen != عدم)
		*rlen = (size_t)rr;
	החזר 0;
}
