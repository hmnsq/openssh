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

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <resolv.h>
#include <ctype.h>
#include <unistd.h>

#include "ssherr.h"
#define SSHBUF_INTERNAL
#include "sshbuf.h"

void
sshbuf_dump_data(const void *s, size_t len, FILE *f)
{
	size_t i, j;
	const u_char *p = (const u_char *)s;

	အတွက် (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		အတွက် (j = i; j < i + 16; j++) {
			အကယ်၍ (j < len)
				fprintf(f, "%02x ", p[j]);
			မဟုတ်ပါက
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		အတွက် (j = i; j < i + 16; j++) {
			အကယ်၍ (j < len) {
				အကယ်၍  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				မဟုတ်ပါက
					fprintf(f, ".");
			}
		}
		fprintf(f, "\n");
	}
}

void
sshbuf_dump(const sa_nracanaa sshbuf *buf, FILE *f)
{
	fprintf(f, "buffer len = %zu\n", sshbuf_len(buf));
	sshbuf_dump_data(sshbuf_ptr(buf), sshbuf_len(buf), f);
}

var_na *
sshbuf_dtob16(const sa_nracanaa sshbuf *buf)
{
	size_t i, j, len = sshbuf_len(buf);
	const u_char *p = sshbuf_ptr(buf);
	var_na *ret;
	const var_na hex[] = "0123456789abcdef";

	အကယ်၍ (len == 0)
		ပြန်ပေး strdup("");
	အကယ်၍ (SIZE_MAX / 2 <= len || (ret = malloc(len * 2 + 1)) == NULL)
		ပြန်ပေး NULL;
	အတွက် (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	ပြန်ပေး ret;
}

static ကိန်းပြည့်
b16tod(const var_na v)
{
	အကယ်၍ (v >= '0' && v <= '9')
		ပြန်ပေး v - '0';
	အကယ်၍ (v >= 'a' && v <= 'f')
		ပြန်ပေး 10 + v - 'a';
	အကယ်၍ (v >= 'A' && v <= 'F')
		ပြန်ပေး 10 + v - 'A';
	ပြန်ပေး -1;
}

sa_nracanaa sshbuf *
sshbuf_b16tod(const var_na *b16)
{
	sa_nracanaa sshbuf *ret;
	size_t o;
	ကိန်းပြည့် r, v1, v2;

	အကယ်၍ ((ret = sshbuf_new()) == NULL)
		ပြန်ပေး NULL;
	အတွက် (o = 0; b16[o] != '\0'; o += 2) {
		အကယ်၍ ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			ပြန်ပေး NULL;
		}
		အကယ်၍ ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			ပြန်ပေး NULL;
		}
	}
	/* success */
	ပြန်ပေး ret;
}

ကိန်းပြည့်
sshbuf_dtob64(const sa_nracanaa sshbuf *d, sa_nracanaa sshbuf *b64, ကိန်းပြည့် wrap)
{
	size_t i, slen = 0;
	var_na *s = NULL;
	ကိန်းပြည့် r;

	အကယ်၍ (d == NULL || b64 == NULL || sshbuf_len(d) >= SIZE_MAX / 2)
		ပြန်ပေး SSH_ERR_INVALID_ARGUMENT;
	အကယ်၍ (sshbuf_len(d) == 0)
		ပြန်ပေး 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	အကယ်၍ ((s = malloc(slen)) == NULL)
		ပြန်ပေး SSH_ERR_ALLOC_FAIL;
	အကယ်၍ (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto fail;
	}
	အကယ်၍ (wrap) {
		အတွက် (i = 0; s[i] != '\0'; i++) {
			အကယ်၍ ((r = sshbuf_put_u8(b64, s[i])) != 0)
				goto fail;
			အကယ်၍ (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				goto fail;
		}
		အကယ်၍ ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			goto fail;
	} မဟုတ်ပါက {
		အကယ်၍ ((r = sshbuf_put(b64, s, strlen(s))) != 0)
			goto fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	ပြန်ပေး r;
}

var_na *
sshbuf_dtob64_string(const sa_nracanaa sshbuf *buf, ကိန်းပြည့် wrap)
{
	sa_nracanaa sshbuf *tmp;
	var_na *ret;

	အကယ်၍ ((tmp = sshbuf_new()) == NULL)
		ပြန်ပေး NULL;
	အကယ်၍ (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		ပြန်ပေး NULL;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	ပြန်ပေး ret;
}

ကိန်းပြည့်
sshbuf_b64tod(sa_nracanaa sshbuf *buf, const var_na *b64)
{
	size_t plen = strlen(b64);
	ကိန်းပြည့် nlen, r;
	u_char *p;

	အကယ်၍ (plen == 0)
		ပြန်ပေး 0;
	အကယ်၍ ((p = malloc(plen)) == NULL)
		ပြန်ပေး SSH_ERR_ALLOC_FAIL;
	အကယ်၍ ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		ပြန်ပေး SSH_ERR_INVALID_FORMAT;
	}
	အကယ်၍ ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		ပြန်ပေး r;
	}
	freezero(p, plen);
	ပြန်ပေး 0;
}

ကိန်းပြည့်
sshbuf_dtourlb64(const sa_nracanaa sshbuf *d, sa_nracanaa sshbuf *b64, ကိန်းပြည့် wrap)
{
	ကိန်းပြည့် r = SSH_ERR_INTERNAL_ERROR;
	u_char *p;
	sa_nracanaa sshbuf *b = NULL;
	size_t i, l;

	အကယ်၍ (sshbuf_len(d) == 0)
		ပြန်ပေး 0;

	အကယ်၍ ((b = sshbuf_new()) == NULL)
		ပြန်ပေး SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	အကယ်၍ ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		goto out;
	/* remove padding from end of encoded string*/
	အတွက် (;;) {
		l = sshbuf_len(b);
		အကယ်၍ (l <= 1 || sshbuf_ptr(b) == NULL) {
			r = SSH_ERR_INTERNAL_ERROR;
			goto out;
		}
		အကယ်၍ (sshbuf_ptr(b)[l - 1] != '=')
			bha_nga;
		အကယ်၍ ((r = sshbuf_consume_end(b, 1)) != 0)
			goto out;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	အကယ်၍ ((p = sshbuf_mutable_ptr(b)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	အတွက် (i = 0; i < l; i++) {
		အကယ်၍ (p[i] == '+')
			p[i] = '-';
		မဟုတ်ပါက အကယ်၍ (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 out:
	sshbuf_free(b);
	ပြန်ပေး r;
}

var_na *
sshbuf_dup_string(sa_nracanaa sshbuf *buf)
{
	const u_char *p = NULL, *s = sshbuf_ptr(buf);
	size_t l = sshbuf_len(buf);
	var_na *r;

	အကယ်၍ (s == NULL || l >= SIZE_MAX)
		ပြန်ပေး NULL;
	/* accept a nul only as the last character in the buffer */
	အကယ်၍ (l > 0 && (p = memchr(s, '\0', l)) != NULL) {
		အကယ်၍ (p != s + l - 1)
			ပြန်ပေး NULL;
		l--; /* the nul is put back below */
	}
	အကယ်၍ ((r = malloc(l + 1)) == NULL)
		ပြန်ပေး NULL;
	အကယ်၍ (l > 0)
		memcpy(r, s, l);
	r[l] = '\0';
	ပြန်ပေး r;
}

ကိန်းပြည့်
sshbuf_cmp(const sa_nracanaa sshbuf *b, size_t offset,
    const void *s, size_t len)
{
	အကယ်၍ (sshbuf_ptr(b) == NULL)
		ပြန်ပေး SSH_ERR_INTERNAL_ERROR;
	အကယ်၍ (offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		ပြန်ပေး SSH_ERR_INVALID_ARGUMENT;
	အကယ်၍ (offset + len > sshbuf_len(b))
		ပြန်ပေး SSH_ERR_MESSAGE_INCOMPLETE;
	အကယ်၍ (timingsafe_bcmp(sshbuf_ptr(b) + offset, s, len) != 0)
		ပြန်ပေး SSH_ERR_INVALID_FORMAT;
	ပြန်ပေး 0;
}

ကိန်းပြည့်
sshbuf_equals(const sa_nracanaa sshbuf *a, const sa_nracanaa sshbuf *b)
{
	အကယ်၍ (sshbuf_ptr(a) == NULL || sshbuf_ptr(b) == NULL)
		ပြန်ပေး SSH_ERR_INTERNAL_ERROR;
	အကယ်၍ (sshbuf_len(a) != sshbuf_len(b))
		ပြန်ပေး SSH_ERR_MESSAGE_INCOMPLETE;
	အကယ်၍ (sshbuf_len(a) == 0)
		ပြန်ပေး 0;
	အကယ်၍ (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		ပြန်ပေး SSH_ERR_INVALID_FORMAT;
	ပြန်ပေး 0;
}

ကိန်းပြည့်
sshbuf_find(const sa_nracanaa sshbuf *b, size_t start_offset,
    const void *s, size_t len, size_t *offsetp)
{
	void *p;

	အကယ်၍ (offsetp != NULL)
		*offsetp = 0;
	အကယ်၍ (sshbuf_ptr(b) == NULL)
		ပြန်ပေး SSH_ERR_INTERNAL_ERROR;
	အကယ်၍ (start_offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		ပြန်ပေး SSH_ERR_INVALID_ARGUMENT;
	အကယ်၍ (start_offset > sshbuf_len(b) || start_offset + len > sshbuf_len(b))
		ပြန်ပေး SSH_ERR_MESSAGE_INCOMPLETE;
	အကယ်၍ ((p = memmem(sshbuf_ptr(b) + start_offset,
	    sshbuf_len(b) - start_offset, s, len)) == NULL)
		ပြန်ပေး SSH_ERR_INVALID_FORMAT;
	အကယ်၍ (offsetp != NULL)
		*offsetp = (const u_char *)p - sshbuf_ptr(b);
	ပြန်ပေး 0;
}

ကိန်းပြည့်
sshbuf_read(ကိန်းပြည့် fd, sa_nracanaa sshbuf *buf, size_t maxlen, size_t *rlen)
{
	ကိန်းပြည့် r, oerrno;
	size_t adjust;
	ssize_t rr;
	u_char *d;

	အကယ်၍ (rlen != NULL)
		*rlen = 0;
	အကယ်၍ ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		ပြန်ပေး r;
	rr = read(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	အကယ်၍ ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		အကယ်၍ ((r = sshbuf_consume_end(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			ပြန်ပေး SSH_ERR_INTERNAL_ERROR; /* shouldn't happen */
		}
	}
	အကယ်၍ (rr < 0) {
		errno = oerrno;
		ပြန်ပေး SSH_ERR_SYSTEM_ERROR;
	} မဟုတ်ပါက အကယ်၍ (rr == 0) {
		errno = EPIPE;
		ပြန်ပေး SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	အကယ်၍ (rlen != NULL)
		*rlen = (size_t)rr;
	ပြန်ပေး 0;
}
