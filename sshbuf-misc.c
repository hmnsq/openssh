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

	为 (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		为 (j = i; j < i + 16; j++) {
			如果 (j < len)
				fprintf(f, "%02x ", p[j]);
			否则
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		为 (j = i; j < i + 16; j++) {
			如果 (j < len) {
				如果  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				否则
					fprintf(f, ".");
			}
		}
		fprintf(f, "\n");
	}
}

void
sshbuf_dump(const struct sshbuf *buf, FILE *f)
{
	fprintf(f, "buffer len = %zu\n", sshbuf_len(buf));
	sshbuf_dump_data(sshbuf_ptr(buf), sshbuf_len(buf), f);
}

char *
sshbuf_dtob16(const struct sshbuf *buf)
{
	size_t i, j, len = sshbuf_len(buf);
	const u_char *p = sshbuf_ptr(buf);
	char *ret;
	const char hex[] = "0123456789abcdef";

	如果 (len == 0)
		返回 strdup("");
	如果 (SIZE_MAX / 2 <= len || (ret = malloc(len * 2 + 1)) == NULL)
		返回 NULL;
	为 (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	返回 ret;
}

static 整数
b16tod(const char v)
{
	如果 (v >= '0' && v <= '9')
		返回 v - '0';
	如果 (v >= 'a' && v <= 'f')
		返回 10 + v - 'a';
	如果 (v >= 'A' && v <= 'F')
		返回 10 + v - 'A';
	返回 -1;
}

struct sshbuf *
sshbuf_b16tod(const char *b16)
{
	struct sshbuf *ret;
	size_t o;
	整数 r, v1, v2;

	如果 ((ret = sshbuf_new()) == NULL)
		返回 NULL;
	为 (o = 0; b16[o] != '\0'; o += 2) {
		如果 ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			返回 NULL;
		}
		如果 ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			返回 NULL;
		}
	}
	/* success */
	返回 ret;
}

整数
sshbuf_dtob64(const struct sshbuf *d, struct sshbuf *b64, 整数 wrap)
{
	size_t i, slen = 0;
	char *s = NULL;
	整数 r;

	如果 (d == NULL || b64 == NULL || sshbuf_len(d) >= SIZE_MAX / 2)
		返回 SSH_ERR_INVALID_ARGUMENT;
	如果 (sshbuf_len(d) == 0)
		返回 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	如果 ((s = malloc(slen)) == NULL)
		返回 SSH_ERR_ALLOC_FAIL;
	如果 (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto fail;
	}
	如果 (wrap) {
		为 (i = 0; s[i] != '\0'; i++) {
			如果 ((r = sshbuf_put_u8(b64, s[i])) != 0)
				goto fail;
			如果 (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				goto fail;
		}
		如果 ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			goto fail;
	} 否则 {
		如果 ((r = sshbuf_put(b64, s, strlen(s))) != 0)
			goto fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	返回 r;
}

char *
sshbuf_dtob64_string(const struct sshbuf *buf, 整数 wrap)
{
	struct sshbuf *tmp;
	char *ret;

	如果 ((tmp = sshbuf_new()) == NULL)
		返回 NULL;
	如果 (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		返回 NULL;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	返回 ret;
}

整数
sshbuf_b64tod(struct sshbuf *buf, const char *b64)
{
	size_t plen = strlen(b64);
	整数 nlen, r;
	u_char *p;

	如果 (plen == 0)
		返回 0;
	如果 ((p = malloc(plen)) == NULL)
		返回 SSH_ERR_ALLOC_FAIL;
	如果 ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		返回 SSH_ERR_INVALID_FORMAT;
	}
	如果 ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		返回 r;
	}
	freezero(p, plen);
	返回 0;
}

整数
sshbuf_dtourlb64(const struct sshbuf *d, struct sshbuf *b64, 整数 wrap)
{
	整数 r = SSH_ERR_INTERNAL_ERROR;
	u_char *p;
	struct sshbuf *b = NULL;
	size_t i, l;

	如果 (sshbuf_len(d) == 0)
		返回 0;

	如果 ((b = sshbuf_new()) == NULL)
		返回 SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	如果 ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		goto out;
	/* remove padding from end of encoded string*/
	为 (;;) {
		l = sshbuf_len(b);
		如果 (l <= 1 || sshbuf_ptr(b) == NULL) {
			r = SSH_ERR_INTERNAL_ERROR;
			goto out;
		}
		如果 (sshbuf_ptr(b)[l - 1] != '=')
			break;
		如果 ((r = sshbuf_consume_end(b, 1)) != 0)
			goto out;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	如果 ((p = sshbuf_mutable_ptr(b)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	为 (i = 0; i < l; i++) {
		如果 (p[i] == '+')
			p[i] = '-';
		否则 如果 (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 out:
	sshbuf_free(b);
	返回 r;
}

char *
sshbuf_dup_string(struct sshbuf *buf)
{
	const u_char *p = NULL, *s = sshbuf_ptr(buf);
	size_t l = sshbuf_len(buf);
	char *r;

	如果 (s == NULL || l >= SIZE_MAX)
		返回 NULL;
	/* accept a nul only as the last character in the buffer */
	如果 (l > 0 && (p = memchr(s, '\0', l)) != NULL) {
		如果 (p != s + l - 1)
			返回 NULL;
		l--; /* the nul is put back below */
	}
	如果 ((r = malloc(l + 1)) == NULL)
		返回 NULL;
	如果 (l > 0)
		memcpy(r, s, l);
	r[l] = '\0';
	返回 r;
}

整数
sshbuf_cmp(const struct sshbuf *b, size_t offset,
    const void *s, size_t len)
{
	如果 (sshbuf_ptr(b) == NULL)
		返回 SSH_ERR_INTERNAL_ERROR;
	如果 (offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		返回 SSH_ERR_INVALID_ARGUMENT;
	如果 (offset + len > sshbuf_len(b))
		返回 SSH_ERR_MESSAGE_INCOMPLETE;
	如果 (timingsafe_bcmp(sshbuf_ptr(b) + offset, s, len) != 0)
		返回 SSH_ERR_INVALID_FORMAT;
	返回 0;
}

整数
sshbuf_equals(const struct sshbuf *a, const struct sshbuf *b)
{
	如果 (sshbuf_ptr(a) == NULL || sshbuf_ptr(b) == NULL)
		返回 SSH_ERR_INTERNAL_ERROR;
	如果 (sshbuf_len(a) != sshbuf_len(b))
		返回 SSH_ERR_MESSAGE_INCOMPLETE;
	如果 (sshbuf_len(a) == 0)
		返回 0;
	如果 (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		返回 SSH_ERR_INVALID_FORMAT;
	返回 0;
}

整数
sshbuf_find(const struct sshbuf *b, size_t start_offset,
    const void *s, size_t len, size_t *offsetp)
{
	void *p;

	如果 (offsetp != NULL)
		*offsetp = 0;
	如果 (sshbuf_ptr(b) == NULL)
		返回 SSH_ERR_INTERNAL_ERROR;
	如果 (start_offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		返回 SSH_ERR_INVALID_ARGUMENT;
	如果 (start_offset > sshbuf_len(b) || start_offset + len > sshbuf_len(b))
		返回 SSH_ERR_MESSAGE_INCOMPLETE;
	如果 ((p = memmem(sshbuf_ptr(b) + start_offset,
	    sshbuf_len(b) - start_offset, s, len)) == NULL)
		返回 SSH_ERR_INVALID_FORMAT;
	如果 (offsetp != NULL)
		*offsetp = (const u_char *)p - sshbuf_ptr(b);
	返回 0;
}

整数
sshbuf_read(整数 fd, struct sshbuf *buf, size_t maxlen, size_t *rlen)
{
	整数 r, oerrno;
	size_t adjust;
	ssize_t rr;
	u_char *d;

	如果 (rlen != NULL)
		*rlen = 0;
	如果 ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		返回 r;
	rr = read(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	如果 ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		如果 ((r = sshbuf_consume_end(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			返回 SSH_ERR_INTERNAL_ERROR; /* shouldn't happen */
		}
	}
	如果 (rr < 0) {
		errno = oerrno;
		返回 SSH_ERR_SYSTEM_ERROR;
	} 否则 如果 (rr == 0) {
		errno = EPIPE;
		返回 SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	如果 (rlen != NULL)
		*rlen = (size_t)rr;
	返回 0;
}
