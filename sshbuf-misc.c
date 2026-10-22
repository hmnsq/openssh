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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <netinet/in.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <resolv.h>
#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "ssherr.h"
#define SSHBUF_INTERNAL
#অন্তর্ভাব "sshbuf.h"

শূন্য
sshbuf_dump_তথ্য(ধ্রুবক শূন্য *s, আকার_t len, FILE *f)
{
	আকার_t i, j;
	ধ্রুবক u_char *p = (ধ্রুবক u_char *)s;

	জন্য (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		জন্য (j = i; j < i + 16; j++) {
			যদি (j < len)
				fprintf(f, "%02x ", p[j]);
			অন্যথা
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		জন্য (j = i; j < i + 16; j++) {
			যদি (j < len) {
				যদি  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				অন্যথা
					fprintf(f, ".");
			}
		}
		fprintf(f, "\n");
	}
}

শূন্য
sshbuf_dump(ধ্রুবক কাঠামো sshbuf *buf, FILE *f)
{
	fprintf(f, "buffer len = %zu\n", sshbuf_len(buf));
	sshbuf_dump_তথ্য(sshbuf_ptr(buf), sshbuf_len(buf), f);
}

অক্ষর *
sshbuf_dtob16(ধ্রুবক কাঠামো sshbuf *buf)
{
	আকার_t i, j, len = sshbuf_len(buf);
	ধ্রুবক u_char *p = sshbuf_ptr(buf);
	অক্ষর *ret;
	ধ্রুবক অক্ষর hex[] = "0123456789abcdef";

	যদি (len == 0)
		ফেরত strdup("");
	যদি (SIZE_MAX / 2 <= len || (ret = malloc(len * 2 + 1)) == ফাঁকা)
		ফেরত ফাঁকা;
	জন্য (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
b16tod(ধ্রুবক অক্ষর v)
{
	যদি (v >= '0' && v <= '9')
		ফেরত v - '0';
	যদি (v >= 'a' && v <= 'f')
		ফেরত 10 + v - 'a';
	যদি (v >= 'A' && v <= 'F')
		ফেরত 10 + v - 'A';
	ফেরত -1;
}

কাঠামো sshbuf *
sshbuf_b16tod(ধ্রুবক অক্ষর *b16)
{
	কাঠামো sshbuf *ret;
	আকার_t o;
	পূর্ণসংখ্যা r, v1, v2;

	যদি ((ret = sshbuf_new()) == ফাঁকা)
		ফেরত ফাঁকা;
	জন্য (o = 0; b16[o] != '\0'; o += 2) {
		যদি ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			ফেরত ফাঁকা;
		}
		যদি ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			ফেরত ফাঁকা;
		}
	}
	/* success */
	ফেরত ret;
}

পূর্ণসংখ্যা
sshbuf_dtob64(ধ্রুবক কাঠামো sshbuf *d, কাঠামো sshbuf *b64, পূর্ণসংখ্যা wrap)
{
	আকার_t i, slen = 0;
	অক্ষর *s = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি (d == ফাঁকা || b64 == ফাঁকা || sshbuf_len(d) >= SIZE_MAX / 2)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (sshbuf_len(d) == 0)
		ফেরত 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	যদি ((s = malloc(slen)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_INTERNAL_ERROR;
		যাও fail;
	}
	যদি (wrap) {
		জন্য (i = 0; s[i] != '\0'; i++) {
			যদি ((r = sshbuf_put_u8(b64, s[i])) != 0)
				যাও fail;
			যদি (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				যাও fail;
		}
		যদি ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			যাও fail;
	} অন্যথা {
		যদি ((r = sshbuf_put(b64, s, strlen(s))) != 0)
			যাও fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	ফেরত r;
}

অক্ষর *
sshbuf_dtob64_string(ধ্রুবক কাঠামো sshbuf *buf, পূর্ণসংখ্যা wrap)
{
	কাঠামো sshbuf *tmp;
	অক্ষর *ret;

	যদি ((tmp = sshbuf_new()) == ফাঁকা)
		ফেরত ফাঁকা;
	যদি (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		ফেরত ফাঁকা;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	ফেরত ret;
}

পূর্ণসংখ্যা
sshbuf_b64tod(কাঠামো sshbuf *buf, ধ্রুবক অক্ষর *b64)
{
	আকার_t plen = strlen(b64);
	পূর্ণসংখ্যা nlen, r;
	u_char *p;

	যদি (plen == 0)
		ফেরত 0;
	যদি ((p = malloc(plen)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		ফেরত SSH_ERR_INVALID_FORMAT;
	}
	যদি ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		ফেরত r;
	}
	freezero(p, plen);
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_dtourlb64(ধ্রুবক কাঠামো sshbuf *d, কাঠামো sshbuf *b64, পূর্ণসংখ্যা wrap)
{
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	u_char *p;
	কাঠামো sshbuf *b = ফাঁকা;
	আকার_t i, l;

	যদি (sshbuf_len(d) == 0)
		ফেরত 0;

	যদি ((b = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	যদি ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		যাও out;
	/* remove padding from end of encoded string*/
	জন্য (;;) {
		l = sshbuf_len(b);
		যদি (l <= 1 || sshbuf_ptr(b) == ফাঁকা) {
			r = SSH_ERR_INTERNAL_ERROR;
			যাও out;
		}
		যদি (sshbuf_ptr(b)[l - 1] != '=')
			বিরতি;
		যদি ((r = sshbuf_consume_end(b, 1)) != 0)
			যাও out;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	যদি ((p = sshbuf_mutable_ptr(b)) == ফাঁকা) {
		r = SSH_ERR_INTERNAL_ERROR;
		যাও out;
	}
	জন্য (i = 0; i < l; i++) {
		যদি (p[i] == '+')
			p[i] = '-';
		অন্যথা যদি (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 out:
	sshbuf_free(b);
	ফেরত r;
}

অক্ষর *
sshbuf_dup_string(কাঠামো sshbuf *buf)
{
	ধ্রুবক u_char *p = ফাঁকা, *s = sshbuf_ptr(buf);
	আকার_t l = sshbuf_len(buf);
	অক্ষর *r;

	যদি (s == ফাঁকা || l >= SIZE_MAX)
		ফেরত ফাঁকা;
	/* accept a nul only as the last character in the buffer */
	যদি (l > 0 && (p = memchr(s, '\0', l)) != ফাঁকা) {
		যদি (p != s + l - 1)
			ফেরত ফাঁকা;
		l--; /* the nul is put back below */
	}
	যদি ((r = malloc(l + 1)) == ফাঁকা)
		ফেরত ফাঁকা;
	যদি (l > 0)
		memcpy(r, s, l);
	r[l] = '\0';
	ফেরত r;
}

পূর্ণসংখ্যা
sshbuf_cmp(ধ্রুবক কাঠামো sshbuf *b, আকার_t offset,
    ধ্রুবক শূন্য *s, আকার_t len)
{
	যদি (sshbuf_ptr(b) == ফাঁকা)
		ফেরত SSH_ERR_INTERNAL_ERROR;
	যদি (offset > SSHBUF_আকার_MAX || len > SSHBUF_আকার_MAX || len == 0)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (offset + len > sshbuf_len(b))
		ফেরত SSH_ERR_MESSAGE_INCOMPLETE;
	যদি (timingsafe_bcmp(sshbuf_ptr(b) + offset, s, len) != 0)
		ফেরত SSH_ERR_INVALID_FORMAT;
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_equals(ধ্রুবক কাঠামো sshbuf *a, ধ্রুবক কাঠামো sshbuf *b)
{
	যদি (sshbuf_ptr(a) == ফাঁকা || sshbuf_ptr(b) == ফাঁকা)
		ফেরত SSH_ERR_INTERNAL_ERROR;
	যদি (sshbuf_len(a) != sshbuf_len(b))
		ফেরত SSH_ERR_MESSAGE_INCOMPLETE;
	যদি (sshbuf_len(a) == 0)
		ফেরত 0;
	যদি (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		ফেরত SSH_ERR_INVALID_FORMAT;
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_find(ধ্রুবক কাঠামো sshbuf *b, আকার_t start_offset,
    ধ্রুবক শূন্য *s, আকার_t len, আকার_t *offsetp)
{
	শূন্য *p;

	যদি (offsetp != ফাঁকা)
		*offsetp = 0;
	যদি (sshbuf_ptr(b) == ফাঁকা)
		ফেরত SSH_ERR_INTERNAL_ERROR;
	যদি (start_offset > SSHBUF_আকার_MAX || len > SSHBUF_আকার_MAX || len == 0)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (start_offset > sshbuf_len(b) || start_offset + len > sshbuf_len(b))
		ফেরত SSH_ERR_MESSAGE_INCOMPLETE;
	যদি ((p = memmem(sshbuf_ptr(b) + start_offset,
	    sshbuf_len(b) - start_offset, s, len)) == ফাঁকা)
		ফেরত SSH_ERR_INVALID_FORMAT;
	যদি (offsetp != ফাঁকা)
		*offsetp = (ধ্রুবক u_char *)p - sshbuf_ptr(b);
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_read(পূর্ণসংখ্যা fd, কাঠামো sshbuf *buf, আকার_t maxlen, আকার_t *rlen)
{
	পূর্ণসংখ্যা r, oerrno;
	আকার_t adjust;
	ssize_t rr;
	u_char *d;

	যদি (rlen != ফাঁকা)
		*rlen = 0;
	যদি ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		ফেরত r;
	rr = পঠ(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	যদি ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		যদি ((r = sshbuf_consume_end(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			ফেরত SSH_ERR_INTERNAL_ERROR; /* shouldn't happen */
		}
	}
	যদি (rr < 0) {
		errno = oerrno;
		ফেরত SSH_ERR_SYSTEM_ERROR;
	} অন্যথা যদি (rr == 0) {
		errno = EPIPE;
		ফেরত SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	যদি (rlen != ফাঁকা)
		*rlen = (আকার_t)rr;
	ফেরত 0;
}
