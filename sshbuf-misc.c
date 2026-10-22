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
#تعریف_کرو SSHBUF_اندرونی
#شامل "sshbuf.h"

خالی
sshbuf_dump_ڈیٹا(ثابت خالی *s, سائز_t len, FILE *f)
{
	سائز_t i, j;
	ثابت u_char *p = (ثابت u_char *)s;

	برائے (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		برائے (j = i; j < i + 16; j++) {
			اگر (j < len)
				fprintf(f, "%02x ", p[j]);
			ورنہ
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		برائے (j = i; j < i + 16; j++) {
			اگر (j < len) {
				اگر  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				ورنہ
					fprintf(f, ".");
			}
		}
		fprintf(f, "\n");
	}
}

خالی
sshbuf_dump(ثابت ساخت sshbuf *buf, FILE *f)
{
	fprintf(f, "buffer len = %zu\n", sshbuf_len(buf));
	sshbuf_dump_ڈیٹا(sshbuf_ptr(buf), sshbuf_len(buf), f);
}

حرف *
sshbuf_dtob16(ثابت ساخت sshbuf *buf)
{
	سائز_t i, j, len = sshbuf_len(buf);
	ثابت u_char *p = sshbuf_ptr(buf);
	حرف *ret;
	ثابت حرف hex[] = "0123456789abcdef";

	اگر (len == 0)
		واپس strdup("");
	اگر (SIZE_MAX / 2 <= len || (ret = حافظہ_دو(len * 2 + 1)) == تہی)
		واپس تہی;
	برائے (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	واپس ret;
}

ساکن صحیح
b16tod(ثابت حرف v)
{
	اگر (v >= '0' && v <= '9')
		واپس v - '0';
	اگر (v >= 'a' && v <= 'f')
		واپس 10 + v - 'a';
	اگر (v >= 'A' && v <= 'F')
		واپس 10 + v - 'A';
	واپس -1;
}

ساخت sshbuf *
sshbuf_b16tod(ثابت حرف *b16)
{
	ساخت sshbuf *ret;
	سائز_t o;
	صحیح r, v1, v2;

	اگر ((ret = sshbuf_new()) == تہی)
		واپس تہی;
	برائے (o = 0; b16[o] != '\0'; o += 2) {
		اگر ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			واپس تہی;
		}
		اگر ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			واپس تہی;
		}
	}
	/* success */
	واپس ret;
}

صحیح
sshbuf_dtob64(ثابت ساخت sshbuf *d, ساخت sshbuf *b64, صحیح wrap)
{
	سائز_t i, slen = 0;
	حرف *s = تہی;
	صحیح r;

	اگر (d == تہی || b64 == تہی || sshbuf_len(d) >= SIZE_MAX / 2)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (sshbuf_len(d) == 0)
		واپس 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	اگر ((s = حافظہ_دو(slen)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_اندرونی_ERROR;
		جاؤ fail;
	}
	اگر (wrap) {
		برائے (i = 0; s[i] != '\0'; i++) {
			اگر ((r = sshbuf_put_u8(b64, s[i])) != 0)
				جاؤ fail;
			اگر (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				جاؤ fail;
		}
		اگر ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			جاؤ fail;
	} ورنہ {
		اگر ((r = sshbuf_put(b64, s, لڑی_لمبائی(s))) != 0)
			جاؤ fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	واپس r;
}

حرف *
sshbuf_dtob64_string(ثابت ساخت sshbuf *buf, صحیح wrap)
{
	ساخت sshbuf *tmp;
	حرف *ret;

	اگر ((tmp = sshbuf_new()) == تہی)
		واپس تہی;
	اگر (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		واپس تہی;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	واپس ret;
}

صحیح
sshbuf_b64tod(ساخت sshbuf *buf, ثابت حرف *b64)
{
	سائز_t plen = لڑی_لمبائی(b64);
	صحیح nlen, r;
	u_char *p;

	اگر (plen == 0)
		واپس 0;
	اگر ((p = حافظہ_دو(plen)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		واپس SSH_ERR_INVALID_FORMAT;
	}
	اگر ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		واپس r;
	}
	freezero(p, plen);
	واپس 0;
}

صحیح
sshbuf_dtourlb64(ثابت ساخت sshbuf *d, ساخت sshbuf *b64, صحیح wrap)
{
	صحیح r = SSH_ERR_اندرونی_ERROR;
	u_char *p;
	ساخت sshbuf *b = تہی;
	سائز_t i, l;

	اگر (sshbuf_len(d) == 0)
		واپس 0;

	اگر ((b = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	اگر ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		جاؤ برآمد;
	/* remove padding from end of encoded string*/
	برائے (;;) {
		l = sshbuf_len(b);
		اگر (l <= 1 || sshbuf_ptr(b) == تہی) {
			r = SSH_ERR_اندرونی_ERROR;
			جاؤ برآمد;
		}
		اگر (sshbuf_ptr(b)[l - 1] != '=')
			توڑو;
		اگر ((r = sshbuf_consume_انتہا(b, 1)) != 0)
			جاؤ برآمد;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	اگر ((p = sshbuf_mutable_ptr(b)) == تہی) {
		r = SSH_ERR_اندرونی_ERROR;
		جاؤ برآمد;
	}
	برائے (i = 0; i < l; i++) {
		اگر (p[i] == '+')
			p[i] = '-';
		ورنہ اگر (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 برآمد:
	sshbuf_free(b);
	واپس r;
}

حرف *
sshbuf_dup_string(ساخت sshbuf *buf)
{
	ثابت u_char *p = تہی, *s = sshbuf_ptr(buf);
	سائز_t l = sshbuf_len(buf);
	حرف *r;

	اگر (s == تہی || l >= SIZE_MAX)
		واپس تہی;
	/* accept a nul only as the last character in the buffer */
	اگر (l > 0 && (p = memchr(s, '\0', l)) != تہی) {
		اگر (p != s + l - 1)
			واپس تہی;
		l--; /* the nul is put back below */
	}
	اگر ((r = حافظہ_دو(l + 1)) == تہی)
		واپس تہی;
	اگر (l > 0)
		حافظہ_نقل(r, s, l);
	r[l] = '\0';
	واپس r;
}

صحیح
sshbuf_cmp(ثابت ساخت sshbuf *b, سائز_t انحراف,
    ثابت خالی *s, سائز_t len)
{
	اگر (sshbuf_ptr(b) == تہی)
		واپس SSH_ERR_اندرونی_ERROR;
	اگر (انحراف > SSHBUF_سائز_MAX || len > SSHBUF_سائز_MAX || len == 0)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (انحراف + len > sshbuf_len(b))
		واپس SSH_ERR_پیغام_INCOMPLETE;
	اگر (timingsafe_bcmp(sshbuf_ptr(b) + انحراف, s, len) != 0)
		واپس SSH_ERR_INVALID_FORMAT;
	واپس 0;
}

صحیح
sshbuf_equals(ثابت ساخت sshbuf *a, ثابت ساخت sshbuf *b)
{
	اگر (sshbuf_ptr(a) == تہی || sshbuf_ptr(b) == تہی)
		واپس SSH_ERR_اندرونی_ERROR;
	اگر (sshbuf_len(a) != sshbuf_len(b))
		واپس SSH_ERR_پیغام_INCOMPLETE;
	اگر (sshbuf_len(a) == 0)
		واپس 0;
	اگر (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		واپس SSH_ERR_INVALID_FORMAT;
	واپس 0;
}

صحیح
sshbuf_ڈھونڈو(ثابت ساخت sshbuf *b, سائز_t آغاز_انحراف,
    ثابت خالی *s, سائز_t len, سائز_t *offsetp)
{
	خالی *p;

	اگر (offsetp != تہی)
		*offsetp = 0;
	اگر (sshbuf_ptr(b) == تہی)
		واپس SSH_ERR_اندرونی_ERROR;
	اگر (آغاز_انحراف > SSHBUF_سائز_MAX || len > SSHBUF_سائز_MAX || len == 0)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (آغاز_انحراف > sshbuf_len(b) || آغاز_انحراف + len > sshbuf_len(b))
		واپس SSH_ERR_پیغام_INCOMPLETE;
	اگر ((p = memmem(sshbuf_ptr(b) + آغاز_انحراف,
	    sshbuf_len(b) - آغاز_انحراف, s, len)) == تہی)
		واپس SSH_ERR_INVALID_FORMAT;
	اگر (offsetp != تہی)
		*offsetp = (ثابت u_char *)p - sshbuf_ptr(b);
	واپس 0;
}

صحیح
sshbuf_read(صحیح fd, ساخت sshbuf *buf, سائز_t maxlen, سائز_t *rlen)
{
	صحیح r, oerrno;
	سائز_t adjust;
	ssize_t rr;
	u_char *d;

	اگر (rlen != تہی)
		*rlen = 0;
	اگر ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		واپس r;
	rr = اقرأ(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	اگر ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		اگر ((r = sshbuf_consume_انتہا(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			واپس SSH_ERR_اندرونی_ERROR; /* shouldn't happen */
		}
	}
	اگر (rr < 0) {
		errno = oerrno;
		واپس SSH_ERR_SYSTEM_ERROR;
	} ورنہ اگر (rr == 0) {
		errno = EPIPE;
		واپس SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	اگر (rlen != تہی)
		*rlen = (سائز_t)rr;
	واپس 0;
}
