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

	དོན་ལུ (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		དོན་ལུ (j = i; j < i + 16; j++) {
			གལ་སྲིད (j < len)
				fprintf(f, "%02x ", p[j]);
			དེ་མིན
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		དོན་ལུ (j = i; j < i + 16; j++) {
			གལ་སྲིད (j < len) {
				གལ་སྲིད  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				དེ་མིན
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

	གལ་སྲིད (len == 0)
		ལོག strdup("");
	གལ་སྲིད (SIZE_MAX / 2 <= len || (ret = malloc(len * 2 + 1)) == NULL)
		ལོག NULL;
	དོན་ལུ (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	ལོག ret;
}

static ཧྲིལ
b16tod(const var_na v)
{
	གལ་སྲིད (v >= '0' && v <= '9')
		ལོག v - '0';
	གལ་སྲིད (v >= 'a' && v <= 'f')
		ལོག 10 + v - 'a';
	གལ་སྲིད (v >= 'A' && v <= 'F')
		ལོག 10 + v - 'A';
	ལོག -1;
}

sa_nracanaa sshbuf *
sshbuf_b16tod(const var_na *b16)
{
	sa_nracanaa sshbuf *ret;
	size_t o;
	ཧྲིལ r, v1, v2;

	གལ་སྲིད ((ret = sshbuf_new()) == NULL)
		ལོག NULL;
	དོན་ལུ (o = 0; b16[o] != '\0'; o += 2) {
		གལ་སྲིད ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			ལོག NULL;
		}
		གལ་སྲིད ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			ལོག NULL;
		}
	}
	/* success */
	ལོག ret;
}

ཧྲིལ
sshbuf_dtob64(const sa_nracanaa sshbuf *d, sa_nracanaa sshbuf *b64, ཧྲིལ wrap)
{
	size_t i, slen = 0;
	var_na *s = NULL;
	ཧྲིལ r;

	གལ་སྲིད (d == NULL || b64 == NULL || sshbuf_len(d) >= SIZE_MAX / 2)
		ལོག SSH_ERR_INVALID_ARGUMENT;
	གལ་སྲིད (sshbuf_len(d) == 0)
		ལོག 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	གལ་སྲིད ((s = malloc(slen)) == NULL)
		ལོག SSH_ERR_ALLOC_FAIL;
	གལ་སྲིད (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto fail;
	}
	གལ་སྲིད (wrap) {
		དོན་ལུ (i = 0; s[i] != '\0'; i++) {
			གལ་སྲིད ((r = sshbuf_put_u8(b64, s[i])) != 0)
				goto fail;
			གལ་སྲིད (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				goto fail;
		}
		གལ་སྲིད ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			goto fail;
	} དེ་མིན {
		གལ་སྲིད ((r = sshbuf_put(b64, s, strlen(s))) != 0)
			goto fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	ལོག r;
}

var_na *
sshbuf_dtob64_string(const sa_nracanaa sshbuf *buf, ཧྲིལ wrap)
{
	sa_nracanaa sshbuf *tmp;
	var_na *ret;

	གལ་སྲིད ((tmp = sshbuf_new()) == NULL)
		ལོག NULL;
	གལ་སྲིད (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		ལོག NULL;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	ལོག ret;
}

ཧྲིལ
sshbuf_b64tod(sa_nracanaa sshbuf *buf, const var_na *b64)
{
	size_t plen = strlen(b64);
	ཧྲིལ nlen, r;
	u_char *p;

	གལ་སྲིད (plen == 0)
		ལོག 0;
	གལ་སྲིད ((p = malloc(plen)) == NULL)
		ལོག SSH_ERR_ALLOC_FAIL;
	གལ་སྲིད ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		ལོག SSH_ERR_INVALID_FORMAT;
	}
	གལ་སྲིད ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		ལོག r;
	}
	freezero(p, plen);
	ལོག 0;
}

ཧྲིལ
sshbuf_dtourlb64(const sa_nracanaa sshbuf *d, sa_nracanaa sshbuf *b64, ཧྲིལ wrap)
{
	ཧྲིལ r = SSH_ERR_INTERNAL_ERROR;
	u_char *p;
	sa_nracanaa sshbuf *b = NULL;
	size_t i, l;

	གལ་སྲིད (sshbuf_len(d) == 0)
		ལོག 0;

	གལ་སྲིད ((b = sshbuf_new()) == NULL)
		ལོག SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	གལ་སྲིད ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		goto out;
	/* remove padding from end of encoded string*/
	དོན་ལུ (;;) {
		l = sshbuf_len(b);
		གལ་སྲིད (l <= 1 || sshbuf_ptr(b) == NULL) {
			r = SSH_ERR_INTERNAL_ERROR;
			goto out;
		}
		གལ་སྲིད (sshbuf_ptr(b)[l - 1] != '=')
			bha_nga;
		གལ་སྲིད ((r = sshbuf_consume_end(b, 1)) != 0)
			goto out;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	གལ་སྲིད ((p = sshbuf_mutable_ptr(b)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	དོན་ལུ (i = 0; i < l; i++) {
		གལ་སྲིད (p[i] == '+')
			p[i] = '-';
		དེ་མིན གལ་སྲིད (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 out:
	sshbuf_free(b);
	ལོག r;
}

var_na *
sshbuf_dup_string(sa_nracanaa sshbuf *buf)
{
	const u_char *p = NULL, *s = sshbuf_ptr(buf);
	size_t l = sshbuf_len(buf);
	var_na *r;

	གལ་སྲིད (s == NULL || l >= SIZE_MAX)
		ལོག NULL;
	/* accept a nul only as the last character in the buffer */
	གལ་སྲིད (l > 0 && (p = memchr(s, '\0', l)) != NULL) {
		གལ་སྲིད (p != s + l - 1)
			ལོག NULL;
		l--; /* the nul is put back below */
	}
	གལ་སྲིད ((r = malloc(l + 1)) == NULL)
		ལོག NULL;
	གལ་སྲིད (l > 0)
		memcpy(r, s, l);
	r[l] = '\0';
	ལོག r;
}

ཧྲིལ
sshbuf_cmp(const sa_nracanaa sshbuf *b, size_t offset,
    const void *s, size_t len)
{
	གལ་སྲིད (sshbuf_ptr(b) == NULL)
		ལོག SSH_ERR_INTERNAL_ERROR;
	གལ་སྲིད (offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		ལོག SSH_ERR_INVALID_ARGUMENT;
	གལ་སྲིད (offset + len > sshbuf_len(b))
		ལོག SSH_ERR_MESSAGE_INCOMPLETE;
	གལ་སྲིད (timingsafe_bcmp(sshbuf_ptr(b) + offset, s, len) != 0)
		ལོག SSH_ERR_INVALID_FORMAT;
	ལོག 0;
}

ཧྲིལ
sshbuf_equals(const sa_nracanaa sshbuf *a, const sa_nracanaa sshbuf *b)
{
	གལ་སྲིད (sshbuf_ptr(a) == NULL || sshbuf_ptr(b) == NULL)
		ལོག SSH_ERR_INTERNAL_ERROR;
	གལ་སྲིད (sshbuf_len(a) != sshbuf_len(b))
		ལོག SSH_ERR_MESSAGE_INCOMPLETE;
	གལ་སྲིད (sshbuf_len(a) == 0)
		ལོག 0;
	གལ་སྲིད (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		ལོག SSH_ERR_INVALID_FORMAT;
	ལོག 0;
}

ཧྲིལ
sshbuf_find(const sa_nracanaa sshbuf *b, size_t start_offset,
    const void *s, size_t len, size_t *offsetp)
{
	void *p;

	གལ་སྲིད (offsetp != NULL)
		*offsetp = 0;
	གལ་སྲིད (sshbuf_ptr(b) == NULL)
		ལོག SSH_ERR_INTERNAL_ERROR;
	གལ་སྲིད (start_offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		ལོག SSH_ERR_INVALID_ARGUMENT;
	གལ་སྲིད (start_offset > sshbuf_len(b) || start_offset + len > sshbuf_len(b))
		ལོག SSH_ERR_MESSAGE_INCOMPLETE;
	གལ་སྲིད ((p = memmem(sshbuf_ptr(b) + start_offset,
	    sshbuf_len(b) - start_offset, s, len)) == NULL)
		ལོག SSH_ERR_INVALID_FORMAT;
	གལ་སྲིད (offsetp != NULL)
		*offsetp = (const u_char *)p - sshbuf_ptr(b);
	ལོག 0;
}

ཧྲིལ
sshbuf_read(ཧྲིལ fd, sa_nracanaa sshbuf *buf, size_t maxlen, size_t *rlen)
{
	ཧྲིལ r, oerrno;
	size_t adjust;
	ssize_t rr;
	u_char *d;

	གལ་སྲིད (rlen != NULL)
		*rlen = 0;
	གལ་སྲིད ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		ལོག r;
	rr = read(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	གལ་སྲིད ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		གལ་སྲིད ((r = sshbuf_consume_end(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			ལོག SSH_ERR_INTERNAL_ERROR; /* shouldn't happen */
		}
	}
	གལ་སྲིད (rr < 0) {
		errno = oerrno;
		ལོག SSH_ERR_SYSTEM_ERROR;
	} དེ་མིན གལ་སྲིད (rr == 0) {
		errno = EPIPE;
		ལོག SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	གལ་སྲིད (rlen != NULL)
		*rlen = (size_t)rr;
	ལོག 0;
}
