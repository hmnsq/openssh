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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/socket.h>
#অন্তর্ভাৱ <netinet/in.h>
#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <limits.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <resolv.h>
#অন্তর্ভাৱ <ctype.h>
#অন্তর্ভাৱ <unistd.h>

#অন্তর্ভাৱ "ssherr.h"
#define SSHBUF_INTERNAL
#অন্তর্ভাৱ "sshbuf.h"

শূন্য
sshbuf_dump_data(ধ্রুৱ শূন্য *s, size_t len, FILE *f)
{
	size_t i, j;
	ধ্রুৱ u_char *p = (ধ্রুৱ u_char *)s;

	বাবে (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		বাবে (j = i; j < i + 16; j++) {
			যদি (j < len)
				fprintf(f, "%02x ", p[j]);
			অন্যথা
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		বাবে (j = i; j < i + 16; j++) {
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
sshbuf_dump(ধ্রুৱ সংরচনা sshbuf *buf, FILE *f)
{
	fprintf(f, "buffer len = %zu\n", sshbuf_len(buf));
	sshbuf_dump_data(sshbuf_ptr(buf), sshbuf_len(buf), f);
}

ৱর্ণ *
sshbuf_dtob16(ধ্রুৱ সংরচনা sshbuf *buf)
{
	size_t i, j, len = sshbuf_len(buf);
	ধ্রুৱ u_char *p = sshbuf_ptr(buf);
	ৱর্ণ *ret;
	ধ্রুৱ ৱর্ণ hex[] = "0123456789abcdef";

	যদি (len == 0)
		ঘূৰাই strdup("");
	যদি (SIZE_MAX / 2 <= len || (ret = malloc(len * 2 + 1)) == রিক্ত)
		ঘূৰাই রিক্ত;
	বাবে (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	ঘূৰাই ret;
}

স্থির পূর্ণাঙ্ক
b16tod(ধ্রুৱ ৱর্ণ v)
{
	যদি (v >= '0' && v <= '9')
		ঘূৰাই v - '0';
	যদি (v >= 'a' && v <= 'f')
		ঘূৰাই 10 + v - 'a';
	যদি (v >= 'A' && v <= 'F')
		ঘূৰাই 10 + v - 'A';
	ঘূৰাই -1;
}

সংরচনা sshbuf *
sshbuf_b16tod(ধ্রুৱ ৱর্ণ *b16)
{
	সংরচনা sshbuf *ret;
	size_t o;
	পূর্ণাঙ্ক r, v1, v2;

	যদি ((ret = sshbuf_new()) == রিক্ত)
		ঘূৰাই রিক্ত;
	বাবে (o = 0; b16[o] != '\0'; o += 2) {
		যদি ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			ঘূৰাই রিক্ত;
		}
		যদি ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			ঘূৰাই রিক্ত;
		}
	}
	/* success */
	ঘূৰাই ret;
}

পূর্ণাঙ্ক
sshbuf_dtob64(ধ্রুৱ সংরচনা sshbuf *d, সংরচনা sshbuf *b64, পূর্ণাঙ্ক wrap)
{
	size_t i, slen = 0;
	ৱর্ণ *s = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি (d == রিক্ত || b64 == রিক্ত || sshbuf_len(d) >= SIZE_MAX / 2)
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;
	যদি (sshbuf_len(d) == 0)
		ঘূৰাই 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	যদি ((s = malloc(slen)) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	যদি (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_INTERNAL_ERROR;
		গচ্ছ fail;
	}
	যদি (wrap) {
		বাবে (i = 0; s[i] != '\0'; i++) {
			যদি ((r = sshbuf_put_u8(b64, s[i])) != 0)
				গচ্ছ fail;
			যদি (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				গচ্ছ fail;
		}
		যদি ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			গচ্ছ fail;
	} অন্যথা {
		যদি ((r = sshbuf_put(b64, s, strlen(s))) != 0)
			গচ্ছ fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	ঘূৰাই r;
}

ৱর্ণ *
sshbuf_dtob64_string(ধ্রুৱ সংরচনা sshbuf *buf, পূর্ণাঙ্ক wrap)
{
	সংরচনা sshbuf *tmp;
	ৱর্ণ *ret;

	যদি ((tmp = sshbuf_new()) == রিক্ত)
		ঘূৰাই রিক্ত;
	যদি (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		ঘূৰাই রিক্ত;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	ঘূৰাই ret;
}

পূর্ণাঙ্ক
sshbuf_b64tod(সংরচনা sshbuf *buf, ধ্রুৱ ৱর্ণ *b64)
{
	size_t plen = strlen(b64);
	পূর্ণাঙ্ক nlen, r;
	u_char *p;

	যদি (plen == 0)
		ঘূৰাই 0;
	যদি ((p = malloc(plen)) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	যদি ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		ঘূৰাই SSH_ERR_INVALID_FORMAT;
	}
	যদি ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		ঘূৰাই r;
	}
	freezero(p, plen);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_dtourlb64(ধ্রুৱ সংরচনা sshbuf *d, সংরচনা sshbuf *b64, পূর্ণাঙ্ক wrap)
{
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	u_char *p;
	সংরচনা sshbuf *b = রিক্ত;
	size_t i, l;

	যদি (sshbuf_len(d) == 0)
		ঘূৰাই 0;

	যদি ((b = sshbuf_new()) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	যদি ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		গচ্ছ out;
	/* remove padding from end of encoded string*/
	বাবে (;;) {
		l = sshbuf_len(b);
		যদি (l <= 1 || sshbuf_ptr(b) == রিক্ত) {
			r = SSH_ERR_INTERNAL_ERROR;
			গচ্ছ out;
		}
		যদি (sshbuf_ptr(b)[l - 1] != '=')
			ভঙ্গ;
		যদি ((r = sshbuf_consume_end(b, 1)) != 0)
			গচ্ছ out;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	যদি ((p = sshbuf_mutable_ptr(b)) == রিক্ত) {
		r = SSH_ERR_INTERNAL_ERROR;
		গচ্ছ out;
	}
	বাবে (i = 0; i < l; i++) {
		যদি (p[i] == '+')
			p[i] = '-';
		অন্যথা যদি (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 out:
	sshbuf_free(b);
	ঘূৰাই r;
}

ৱর্ণ *
sshbuf_dup_string(সংরচনা sshbuf *buf)
{
	ধ্রুৱ u_char *p = রিক্ত, *s = sshbuf_ptr(buf);
	size_t l = sshbuf_len(buf);
	ৱর্ণ *r;

	যদি (s == রিক্ত || l >= SIZE_MAX)
		ঘূৰাই রিক্ত;
	/* accept a nul only as the last character in the buffer */
	যদি (l > 0 && (p = memchr(s, '\0', l)) != রিক্ত) {
		যদি (p != s + l - 1)
			ঘূৰাই রিক্ত;
		l--; /* the nul is put back below */
	}
	যদি ((r = malloc(l + 1)) == রিক্ত)
		ঘূৰাই রিক্ত;
	যদি (l > 0)
		memcpy(r, s, l);
	r[l] = '\0';
	ঘূৰাই r;
}

পূর্ণাঙ্ক
sshbuf_cmp(ধ্রুৱ সংরচনা sshbuf *b, size_t offset,
    ধ্রুৱ শূন্য *s, size_t len)
{
	যদি (sshbuf_ptr(b) == রিক্ত)
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;
	যদি (offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;
	যদি (offset + len > sshbuf_len(b))
		ঘূৰাই SSH_ERR_MESSAGE_INCOMPLETE;
	যদি (timingsafe_bcmp(sshbuf_ptr(b) + offset, s, len) != 0)
		ঘূৰাই SSH_ERR_INVALID_FORMAT;
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_equals(ধ্রুৱ সংরচনা sshbuf *a, ধ্রুৱ সংরচনা sshbuf *b)
{
	যদি (sshbuf_ptr(a) == রিক্ত || sshbuf_ptr(b) == রিক্ত)
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;
	যদি (sshbuf_len(a) != sshbuf_len(b))
		ঘূৰাই SSH_ERR_MESSAGE_INCOMPLETE;
	যদি (sshbuf_len(a) == 0)
		ঘূৰাই 0;
	যদি (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		ঘূৰাই SSH_ERR_INVALID_FORMAT;
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_find(ধ্রুৱ সংরচনা sshbuf *b, size_t start_offset,
    ধ্রুৱ শূন্য *s, size_t len, size_t *offsetp)
{
	শূন্য *p;

	যদি (offsetp != রিক্ত)
		*offsetp = 0;
	যদি (sshbuf_ptr(b) == রিক্ত)
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;
	যদি (start_offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;
	যদি (start_offset > sshbuf_len(b) || start_offset + len > sshbuf_len(b))
		ঘূৰাই SSH_ERR_MESSAGE_INCOMPLETE;
	যদি ((p = memmem(sshbuf_ptr(b) + start_offset,
	    sshbuf_len(b) - start_offset, s, len)) == রিক্ত)
		ঘূৰাই SSH_ERR_INVALID_FORMAT;
	যদি (offsetp != রিক্ত)
		*offsetp = (ধ্রুৱ u_char *)p - sshbuf_ptr(b);
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
sshbuf_read(পূর্ণাঙ্ক fd, সংরচনা sshbuf *buf, size_t maxlen, size_t *rlen)
{
	পূর্ণাঙ্ক r, oerrno;
	size_t adjust;
	ssize_t rr;
	u_char *d;

	যদি (rlen != রিক্ত)
		*rlen = 0;
	যদি ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		ঘূৰাই r;
	rr = পঠ(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	যদি ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		যদি ((r = sshbuf_consume_end(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			ঘূৰাই SSH_ERR_INTERNAL_ERROR; /* shouldn't happen */
		}
	}
	যদি (rr < 0) {
		errno = oerrno;
		ঘূৰাই SSH_ERR_SYSTEM_ERROR;
	} অন্যথা যদি (rr == 0) {
		errno = EPIPE;
		ঘূৰাই SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	যদি (rlen != রিক্ত)
		*rlen = (size_t)rr;
	ঘূৰাই 0;
}
