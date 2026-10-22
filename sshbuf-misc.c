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

	для (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		для (j = i; j < i + 16; j++) {
			якщо (j < len)
				fprintf(f, "%02x ", p[j]);
			інакше
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		для (j = i; j < i + 16; j++) {
			якщо (j < len) {
				якщо  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				інакше
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

	якщо (len == 0)
		повернути strdup("");
	якщо (SIZE_MAX / 2 <= len || (ret = malloc(len * 2 + 1)) == NULL)
		повернути NULL;
	для (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	повернути ret;
}

static ціле
b16tod(const char v)
{
	якщо (v >= '0' && v <= '9')
		повернути v - '0';
	якщо (v >= 'a' && v <= 'f')
		повернути 10 + v - 'a';
	якщо (v >= 'A' && v <= 'F')
		повернути 10 + v - 'A';
	повернути -1;
}

struct sshbuf *
sshbuf_b16tod(const char *b16)
{
	struct sshbuf *ret;
	size_t o;
	ціле r, v1, v2;

	якщо ((ret = sshbuf_new()) == NULL)
		повернути NULL;
	для (o = 0; b16[o] != '\0'; o += 2) {
		якщо ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			повернути NULL;
		}
		якщо ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			повернути NULL;
		}
	}
	/* success */
	повернути ret;
}

ціле
sshbuf_dtob64(const struct sshbuf *d, struct sshbuf *b64, ціле wrap)
{
	size_t i, slen = 0;
	char *s = NULL;
	ціле r;

	якщо (d == NULL || b64 == NULL || sshbuf_len(d) >= SIZE_MAX / 2)
		повернути SSH_ERR_INVALID_ARGUMENT;
	якщо (sshbuf_len(d) == 0)
		повернути 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	якщо ((s = malloc(slen)) == NULL)
		повернути SSH_ERR_ALLOC_FAIL;
	якщо (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto fail;
	}
	якщо (wrap) {
		для (i = 0; s[i] != '\0'; i++) {
			якщо ((r = sshbuf_put_u8(b64, s[i])) != 0)
				goto fail;
			якщо (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				goto fail;
		}
		якщо ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			goto fail;
	} інакше {
		якщо ((r = sshbuf_put(b64, s, strlen(s))) != 0)
			goto fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	повернути r;
}

char *
sshbuf_dtob64_string(const struct sshbuf *buf, ціле wrap)
{
	struct sshbuf *tmp;
	char *ret;

	якщо ((tmp = sshbuf_new()) == NULL)
		повернути NULL;
	якщо (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		повернути NULL;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	повернути ret;
}

ціле
sshbuf_b64tod(struct sshbuf *buf, const char *b64)
{
	size_t plen = strlen(b64);
	ціле nlen, r;
	u_char *p;

	якщо (plen == 0)
		повернути 0;
	якщо ((p = malloc(plen)) == NULL)
		повернути SSH_ERR_ALLOC_FAIL;
	якщо ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		повернути SSH_ERR_INVALID_FORMAT;
	}
	якщо ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		повернути r;
	}
	freezero(p, plen);
	повернути 0;
}

ціле
sshbuf_dtourlb64(const struct sshbuf *d, struct sshbuf *b64, ціле wrap)
{
	ціле r = SSH_ERR_INTERNAL_ERROR;
	u_char *p;
	struct sshbuf *b = NULL;
	size_t i, l;

	якщо (sshbuf_len(d) == 0)
		повернути 0;

	якщо ((b = sshbuf_new()) == NULL)
		повернути SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	якщо ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		goto out;
	/* remove padding from end of encoded string*/
	для (;;) {
		l = sshbuf_len(b);
		якщо (l <= 1 || sshbuf_ptr(b) == NULL) {
			r = SSH_ERR_INTERNAL_ERROR;
			goto out;
		}
		якщо (sshbuf_ptr(b)[l - 1] != '=')
			break;
		якщо ((r = sshbuf_consume_end(b, 1)) != 0)
			goto out;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	якщо ((p = sshbuf_mutable_ptr(b)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	для (i = 0; i < l; i++) {
		якщо (p[i] == '+')
			p[i] = '-';
		інакше якщо (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 out:
	sshbuf_free(b);
	повернути r;
}

char *
sshbuf_dup_string(struct sshbuf *buf)
{
	const u_char *p = NULL, *s = sshbuf_ptr(buf);
	size_t l = sshbuf_len(buf);
	char *r;

	якщо (s == NULL || l >= SIZE_MAX)
		повернути NULL;
	/* accept a nul only as the last character in the buffer */
	якщо (l > 0 && (p = memchr(s, '\0', l)) != NULL) {
		якщо (p != s + l - 1)
			повернути NULL;
		l--; /* the nul is put back below */
	}
	якщо ((r = malloc(l + 1)) == NULL)
		повернути NULL;
	якщо (l > 0)
		memcpy(r, s, l);
	r[l] = '\0';
	повернути r;
}

ціле
sshbuf_cmp(const struct sshbuf *b, size_t offset,
    const void *s, size_t len)
{
	якщо (sshbuf_ptr(b) == NULL)
		повернути SSH_ERR_INTERNAL_ERROR;
	якщо (offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		повернути SSH_ERR_INVALID_ARGUMENT;
	якщо (offset + len > sshbuf_len(b))
		повернути SSH_ERR_MESSAGE_INCOMPLETE;
	якщо (timingsafe_bcmp(sshbuf_ptr(b) + offset, s, len) != 0)
		повернути SSH_ERR_INVALID_FORMAT;
	повернути 0;
}

ціле
sshbuf_equals(const struct sshbuf *a, const struct sshbuf *b)
{
	якщо (sshbuf_ptr(a) == NULL || sshbuf_ptr(b) == NULL)
		повернути SSH_ERR_INTERNAL_ERROR;
	якщо (sshbuf_len(a) != sshbuf_len(b))
		повернути SSH_ERR_MESSAGE_INCOMPLETE;
	якщо (sshbuf_len(a) == 0)
		повернути 0;
	якщо (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		повернути SSH_ERR_INVALID_FORMAT;
	повернути 0;
}

ціле
sshbuf_find(const struct sshbuf *b, size_t start_offset,
    const void *s, size_t len, size_t *offsetp)
{
	void *p;

	якщо (offsetp != NULL)
		*offsetp = 0;
	якщо (sshbuf_ptr(b) == NULL)
		повернути SSH_ERR_INTERNAL_ERROR;
	якщо (start_offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		повернути SSH_ERR_INVALID_ARGUMENT;
	якщо (start_offset > sshbuf_len(b) || start_offset + len > sshbuf_len(b))
		повернути SSH_ERR_MESSAGE_INCOMPLETE;
	якщо ((p = memmem(sshbuf_ptr(b) + start_offset,
	    sshbuf_len(b) - start_offset, s, len)) == NULL)
		повернути SSH_ERR_INVALID_FORMAT;
	якщо (offsetp != NULL)
		*offsetp = (const u_char *)p - sshbuf_ptr(b);
	повернути 0;
}

ціле
sshbuf_read(ціле fd, struct sshbuf *buf, size_t maxlen, size_t *rlen)
{
	ціле r, oerrno;
	size_t adjust;
	ssize_t rr;
	u_char *d;

	якщо (rlen != NULL)
		*rlen = 0;
	якщо ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		повернути r;
	rr = read(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	якщо ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		якщо ((r = sshbuf_consume_end(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			повернути SSH_ERR_INTERNAL_ERROR; /* shouldn't happen */
		}
	}
	якщо (rr < 0) {
		errno = oerrno;
		повернути SSH_ERR_SYSTEM_ERROR;
	} інакше якщо (rr == 0) {
		errno = EPIPE;
		повернути SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	якщо (rlen != NULL)
		*rlen = (size_t)rr;
	повернути 0;
}
