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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <netinet/in.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <resolv.h>
#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "ssherr.h"
#define SSHBUF_INTERNAL
#அந்தர்பாவ "sshbuf.h"

வெறுமை
sshbuf_dump_data(மாறிலி வெறுமை *s, size_t len, FILE *f)
{
	size_t i, j;
	மாறிலி u_char *p = (மாறிலி u_char *)s;

	க்கு (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		க்கு (j = i; j < i + 16; j++) {
			எனில் (j < len)
				fprintf(f, "%02x ", p[j]);
			இல்லையெனில்
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		க்கு (j = i; j < i + 16; j++) {
			எனில் (j < len) {
				எனில்  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				இல்லையெனில்
					fprintf(f, ".");
			}
		}
		fprintf(f, "\n");
	}
}

வெறுமை
sshbuf_dump(மாறிலி கட்டமைப்பு sshbuf *buf, FILE *f)
{
	fprintf(f, "buffer len = %zu\n", sshbuf_len(buf));
	sshbuf_dump_data(sshbuf_ptr(buf), sshbuf_len(buf), f);
}

எழுத்து *
sshbuf_dtob16(மாறிலி கட்டமைப்பு sshbuf *buf)
{
	size_t i, j, len = sshbuf_len(buf);
	மாறிலி u_char *p = sshbuf_ptr(buf);
	எழுத்து *ret;
	மாறிலி எழுத்து hex[] = "0123456789abcdef";

	எனில் (len == 0)
		திரும்பு strdup("");
	எனில் (SIZE_MAX / 2 <= len || (ret = malloc(len * 2 + 1)) == வெற்று)
		திரும்பு வெற்று;
	க்கு (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	திரும்பு ret;
}

நிலையான முழு
b16tod(மாறிலி எழுத்து v)
{
	எனில் (v >= '0' && v <= '9')
		திரும்பு v - '0';
	எனில் (v >= 'a' && v <= 'f')
		திரும்பு 10 + v - 'a';
	எனில் (v >= 'A' && v <= 'F')
		திரும்பு 10 + v - 'A';
	திரும்பு -1;
}

கட்டமைப்பு sshbuf *
sshbuf_b16tod(மாறிலி எழுத்து *b16)
{
	கட்டமைப்பு sshbuf *ret;
	size_t o;
	முழு r, v1, v2;

	எனில் ((ret = sshbuf_new()) == வெற்று)
		திரும்பு வெற்று;
	க்கு (o = 0; b16[o] != '\0'; o += 2) {
		எனில் ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			திரும்பு வெற்று;
		}
		எனில் ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			திரும்பு வெற்று;
		}
	}
	/* success */
	திரும்பு ret;
}

முழு
sshbuf_dtob64(மாறிலி கட்டமைப்பு sshbuf *d, கட்டமைப்பு sshbuf *b64, முழு wrap)
{
	size_t i, slen = 0;
	எழுத்து *s = வெற்று;
	முழு r;

	எனில் (d == வெற்று || b64 == வெற்று || sshbuf_len(d) >= SIZE_MAX / 2)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (sshbuf_len(d) == 0)
		திரும்பு 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	எனில் ((s = malloc(slen)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_INTERNAL_ERROR;
		செல் fail;
	}
	எனில் (wrap) {
		க்கு (i = 0; s[i] != '\0'; i++) {
			எனில் ((r = sshbuf_put_u8(b64, s[i])) != 0)
				செல் fail;
			எனில் (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				செல் fail;
		}
		எனில் ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			செல் fail;
	} இல்லையெனில் {
		எனில் ((r = sshbuf_put(b64, s, strlen(s))) != 0)
			செல் fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	திரும்பு r;
}

எழுத்து *
sshbuf_dtob64_string(மாறிலி கட்டமைப்பு sshbuf *buf, முழு wrap)
{
	கட்டமைப்பு sshbuf *tmp;
	எழுத்து *ret;

	எனில் ((tmp = sshbuf_new()) == வெற்று)
		திரும்பு வெற்று;
	எனில் (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		திரும்பு வெற்று;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	திரும்பு ret;
}

முழு
sshbuf_b64tod(கட்டமைப்பு sshbuf *buf, மாறிலி எழுத்து *b64)
{
	size_t plen = strlen(b64);
	முழு nlen, r;
	u_char *p;

	எனில் (plen == 0)
		திரும்பு 0;
	எனில் ((p = malloc(plen)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		திரும்பு SSH_ERR_INVALID_FORMAT;
	}
	எனில் ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		திரும்பு r;
	}
	freezero(p, plen);
	திரும்பு 0;
}

முழு
sshbuf_dtourlb64(மாறிலி கட்டமைப்பு sshbuf *d, கட்டமைப்பு sshbuf *b64, முழு wrap)
{
	முழு r = SSH_ERR_INTERNAL_ERROR;
	u_char *p;
	கட்டமைப்பு sshbuf *b = வெற்று;
	size_t i, l;

	எனில் (sshbuf_len(d) == 0)
		திரும்பு 0;

	எனில் ((b = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	எனில் ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		செல் out;
	/* remove padding from end of encoded string*/
	க்கு (;;) {
		l = sshbuf_len(b);
		எனில் (l <= 1 || sshbuf_ptr(b) == வெற்று) {
			r = SSH_ERR_INTERNAL_ERROR;
			செல் out;
		}
		எனில் (sshbuf_ptr(b)[l - 1] != '=')
			நிறுத்து;
		எனில் ((r = sshbuf_consume_end(b, 1)) != 0)
			செல் out;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	எனில் ((p = sshbuf_mutable_ptr(b)) == வெற்று) {
		r = SSH_ERR_INTERNAL_ERROR;
		செல் out;
	}
	க்கு (i = 0; i < l; i++) {
		எனில் (p[i] == '+')
			p[i] = '-';
		இல்லையெனில் எனில் (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 out:
	sshbuf_free(b);
	திரும்பு r;
}

எழுத்து *
sshbuf_dup_string(கட்டமைப்பு sshbuf *buf)
{
	மாறிலி u_char *p = வெற்று, *s = sshbuf_ptr(buf);
	size_t l = sshbuf_len(buf);
	எழுத்து *r;

	எனில் (s == வெற்று || l >= SIZE_MAX)
		திரும்பு வெற்று;
	/* accept a nul only as the last character in the buffer */
	எனில் (l > 0 && (p = memchr(s, '\0', l)) != வெற்று) {
		எனில் (p != s + l - 1)
			திரும்பு வெற்று;
		l--; /* the nul is put back below */
	}
	எனில் ((r = malloc(l + 1)) == வெற்று)
		திரும்பு வெற்று;
	எனில் (l > 0)
		memcpy(r, s, l);
	r[l] = '\0';
	திரும்பு r;
}

முழு
sshbuf_cmp(மாறிலி கட்டமைப்பு sshbuf *b, size_t offset,
    மாறிலி வெறுமை *s, size_t len)
{
	எனில் (sshbuf_ptr(b) == வெற்று)
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	எனில் (offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (offset + len > sshbuf_len(b))
		திரும்பு SSH_ERR_MESSAGE_INCOMPLETE;
	எனில் (timingsafe_bcmp(sshbuf_ptr(b) + offset, s, len) != 0)
		திரும்பு SSH_ERR_INVALID_FORMAT;
	திரும்பு 0;
}

முழு
sshbuf_equals(மாறிலி கட்டமைப்பு sshbuf *a, மாறிலி கட்டமைப்பு sshbuf *b)
{
	எனில் (sshbuf_ptr(a) == வெற்று || sshbuf_ptr(b) == வெற்று)
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	எனில் (sshbuf_len(a) != sshbuf_len(b))
		திரும்பு SSH_ERR_MESSAGE_INCOMPLETE;
	எனில் (sshbuf_len(a) == 0)
		திரும்பு 0;
	எனில் (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		திரும்பு SSH_ERR_INVALID_FORMAT;
	திரும்பு 0;
}

முழு
sshbuf_find(மாறிலி கட்டமைப்பு sshbuf *b, size_t start_offset,
    மாறிலி வெறுமை *s, size_t len, size_t *offsetp)
{
	வெறுமை *p;

	எனில் (offsetp != வெற்று)
		*offsetp = 0;
	எனில் (sshbuf_ptr(b) == வெற்று)
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	எனில் (start_offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (start_offset > sshbuf_len(b) || start_offset + len > sshbuf_len(b))
		திரும்பு SSH_ERR_MESSAGE_INCOMPLETE;
	எனில் ((p = memmem(sshbuf_ptr(b) + start_offset,
	    sshbuf_len(b) - start_offset, s, len)) == வெற்று)
		திரும்பு SSH_ERR_INVALID_FORMAT;
	எனில் (offsetp != வெற்று)
		*offsetp = (மாறிலி u_char *)p - sshbuf_ptr(b);
	திரும்பு 0;
}

முழு
sshbuf_read(முழு fd, கட்டமைப்பு sshbuf *buf, size_t maxlen, size_t *rlen)
{
	முழு r, oerrno;
	size_t adjust;
	ssize_t rr;
	u_char *d;

	எனில் (rlen != வெற்று)
		*rlen = 0;
	எனில் ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		திரும்பு r;
	rr = பட(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	எனில் ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		எனில் ((r = sshbuf_consume_end(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			திரும்பு SSH_ERR_INTERNAL_ERROR; /* shouldn't happen */
		}
	}
	எனில் (rr < 0) {
		errno = oerrno;
		திரும்பு SSH_ERR_SYSTEM_ERROR;
	} இல்லையெனில் எனில் (rr == 0) {
		errno = EPIPE;
		திரும்பு SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	எனில் (rlen != வெற்று)
		*rlen = (size_t)rr;
	திரும்பு 0;
}
