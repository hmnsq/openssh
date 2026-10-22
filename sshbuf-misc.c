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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <netinet/in.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <resolv.h>
#ଅନ୍ତର୍ଭାଵ <ctype.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#define SSHBUF_INTERNAL
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"

ଶୂନ୍ୟ
sshbuf_dump_data(ଅଚଳ ଶୂନ୍ୟ *s, size_t len, FILE *f)
{
	size_t i, j;
	ଅଚଳ u_char *p = (ଅଚଳ u_char *)s;

	ପାଇଁ (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		ପାଇଁ (j = i; j < i + 16; j++) {
			ଯଦି (j < len)
				fprintf(f, "%02x ", p[j]);
			ଅନ୍ୟଥା
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		ପାଇଁ (j = i; j < i + 16; j++) {
			ଯଦି (j < len) {
				ଯଦି  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				ଅନ୍ୟଥା
					fprintf(f, ".");
			}
		}
		fprintf(f, "\n");
	}
}

ଶୂନ୍ୟ
sshbuf_dump(ଅଚଳ ସଂରଚନା sshbuf *buf, FILE *f)
{
	fprintf(f, "buffer len = %zu\n", sshbuf_len(buf));
	sshbuf_dump_data(sshbuf_ptr(buf), sshbuf_len(buf), f);
}

ଅକ୍ଷର *
sshbuf_dtob16(ଅଚଳ ସଂରଚନା sshbuf *buf)
{
	size_t i, j, len = sshbuf_len(buf);
	ଅଚଳ u_char *p = sshbuf_ptr(buf);
	ଅକ୍ଷର *ret;
	ଅଚଳ ଅକ୍ଷର hex[] = "0123456789abcdef";

	ଯଦି (len == 0)
		ଫେରନ୍ତୁ strdup("");
	ଯଦି (SIZE_MAX / 2 <= len || (ret = malloc(len * 2 + 1)) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	ପାଇଁ (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
b16tod(ଅଚଳ ଅକ୍ଷର v)
{
	ଯଦି (v >= '0' && v <= '9')
		ଫେରନ୍ତୁ v - '0';
	ଯଦି (v >= 'a' && v <= 'f')
		ଫେରନ୍ତୁ 10 + v - 'a';
	ଯଦି (v >= 'A' && v <= 'F')
		ଫେରନ୍ତୁ 10 + v - 'A';
	ଫେରନ୍ତୁ -1;
}

ସଂରଚନା sshbuf *
sshbuf_b16tod(ଅଚଳ ଅକ୍ଷର *b16)
{
	ସଂରଚନା sshbuf *ret;
	size_t o;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, v1, v2;

	ଯଦି ((ret = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	ପାଇଁ (o = 0; b16[o] != '\0'; o += 2) {
		ଯଦି ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			ଫେରନ୍ତୁ ଖାଲି;
		}
		ଯଦି ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			ଫେରନ୍ତୁ ଖାଲି;
		}
	}
	/* success */
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_dtob64(ଅଚଳ ସଂରଚନା sshbuf *d, ସଂରଚନା sshbuf *b64, ପୂର୍ଣ୍ଣସଂଖ୍ୟା wrap)
{
	size_t i, slen = 0;
	ଅକ୍ଷର *s = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (d == ଖାଲି || b64 == ଖାଲି || sshbuf_len(d) >= SIZE_MAX / 2)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (sshbuf_len(d) == 0)
		ଫେରନ୍ତୁ 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	ଯଦି ((s = malloc(slen)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_INTERNAL_ERROR;
		ଯାଅ fail;
	}
	ଯଦି (wrap) {
		ପାଇଁ (i = 0; s[i] != '\0'; i++) {
			ଯଦି ((r = sshbuf_put_u8(b64, s[i])) != 0)
				ଯାଅ fail;
			ଯଦି (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				ଯାଅ fail;
		}
		ଯଦି ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			ଯାଅ fail;
	} ଅନ୍ୟଥା {
		ଯଦି ((r = sshbuf_put(b64, s, strlen(s))) != 0)
			ଯାଅ fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	ଫେରନ୍ତୁ r;
}

ଅକ୍ଷର *
sshbuf_dtob64_string(ଅଚଳ ସଂରଚନା sshbuf *buf, ପୂର୍ଣ୍ଣସଂଖ୍ୟା wrap)
{
	ସଂରଚନା sshbuf *tmp;
	ଅକ୍ଷର *ret;

	ଯଦି ((tmp = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	ଯଦି (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_b64tod(ସଂରଚନା sshbuf *buf, ଅଚଳ ଅକ୍ଷର *b64)
{
	size_t plen = strlen(b64);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା nlen, r;
	u_char *p;

	ଯଦି (plen == 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି ((p = malloc(plen)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	}
	ଯଦି ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		ଫେରନ୍ତୁ r;
	}
	freezero(p, plen);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_dtourlb64(ଅଚଳ ସଂରଚନା sshbuf *d, ସଂରଚନା sshbuf *b64, ପୂର୍ଣ୍ଣସଂଖ୍ୟା wrap)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	u_char *p;
	ସଂରଚନା sshbuf *b = ଖାଲି;
	size_t i, l;

	ଯଦି (sshbuf_len(d) == 0)
		ଫେରନ୍ତୁ 0;

	ଯଦି ((b = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	ଯଦି ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		ଯାଅ out;
	/* remove padding from end of encoded string*/
	ପାଇଁ (;;) {
		l = sshbuf_len(b);
		ଯଦି (l <= 1 || sshbuf_ptr(b) == ଖାଲି) {
			r = SSH_ERR_INTERNAL_ERROR;
			ଯାଅ out;
		}
		ଯଦି (sshbuf_ptr(b)[l - 1] != '=')
			ଭାଙ୍ଗ;
		ଯଦି ((r = sshbuf_consume_end(b, 1)) != 0)
			ଯାଅ out;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	ଯଦି ((p = sshbuf_mutable_ptr(b)) == ଖାଲି) {
		r = SSH_ERR_INTERNAL_ERROR;
		ଯାଅ out;
	}
	ପାଇଁ (i = 0; i < l; i++) {
		ଯଦି (p[i] == '+')
			p[i] = '-';
		ଅନ୍ୟଥା ଯଦି (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 out:
	sshbuf_free(b);
	ଫେରନ୍ତୁ r;
}

ଅକ୍ଷର *
sshbuf_dup_string(ସଂରଚନା sshbuf *buf)
{
	ଅଚଳ u_char *p = ଖାଲି, *s = sshbuf_ptr(buf);
	size_t l = sshbuf_len(buf);
	ଅକ୍ଷର *r;

	ଯଦି (s == ଖାଲି || l >= SIZE_MAX)
		ଫେରନ୍ତୁ ଖାଲି;
	/* accept a nul only as the last character in the buffer */
	ଯଦି (l > 0 && (p = memchr(s, '\0', l)) != ଖାଲି) {
		ଯଦି (p != s + l - 1)
			ଫେରନ୍ତୁ ଖାଲି;
		l--; /* the nul is put back below */
	}
	ଯଦି ((r = malloc(l + 1)) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	ଯଦି (l > 0)
		memcpy(r, s, l);
	r[l] = '\0';
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_cmp(ଅଚଳ ସଂରଚନା sshbuf *b, size_t offset,
    ଅଚଳ ଶୂନ୍ୟ *s, size_t len)
{
	ଯଦି (sshbuf_ptr(b) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	ଯଦି (offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (offset + len > sshbuf_len(b))
		ଫେରନ୍ତୁ SSH_ERR_MESSAGE_INCOMPLETE;
	ଯଦି (timingsafe_bcmp(sshbuf_ptr(b) + offset, s, len) != 0)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_equals(ଅଚଳ ସଂରଚନା sshbuf *a, ଅଚଳ ସଂରଚନା sshbuf *b)
{
	ଯଦି (sshbuf_ptr(a) == ଖାଲି || sshbuf_ptr(b) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	ଯଦି (sshbuf_len(a) != sshbuf_len(b))
		ଫେରନ୍ତୁ SSH_ERR_MESSAGE_INCOMPLETE;
	ଯଦି (sshbuf_len(a) == 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_find(ଅଚଳ ସଂରଚନା sshbuf *b, size_t start_offset,
    ଅଚଳ ଶୂନ୍ୟ *s, size_t len, size_t *offsetp)
{
	ଶୂନ୍ୟ *p;

	ଯଦି (offsetp != ଖାଲି)
		*offsetp = 0;
	ଯଦି (sshbuf_ptr(b) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	ଯଦି (start_offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (start_offset > sshbuf_len(b) || start_offset + len > sshbuf_len(b))
		ଫେରନ୍ତୁ SSH_ERR_MESSAGE_INCOMPLETE;
	ଯଦି ((p = memmem(sshbuf_ptr(b) + start_offset,
	    sshbuf_len(b) - start_offset, s, len)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	ଯଦି (offsetp != ଖାଲି)
		*offsetp = (ଅଚଳ u_char *)p - sshbuf_ptr(b);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_read(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ସଂରଚନା sshbuf *buf, size_t maxlen, size_t *rlen)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, oerrno;
	size_t adjust;
	ssize_t rr;
	u_char *d;

	ଯଦି (rlen != ଖାଲି)
		*rlen = 0;
	ଯଦି ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		ଫେରନ୍ତୁ r;
	rr = ପଠ(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	ଯଦି ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		ଯଦି ((r = sshbuf_consume_end(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR; /* shouldn't happen */
		}
	}
	ଯଦି (rr < 0) {
		errno = oerrno;
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
	} ଅନ୍ୟଥା ଯଦି (rr == 0) {
		errno = EPIPE;
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	ଯଦି (rlen != ଖାଲି)
		*rlen = (size_t)rr;
	ଫେରନ୍ତୁ 0;
}
