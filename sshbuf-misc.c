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

	for (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		for (j = i; j < i + 16; j++) {
			ᱡᱩᱫᱤ (j < len)
				fprintf(f, "%02x ", p[j]);
			ᱵᱟᱝ
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		for (j = i; j < i + 16; j++) {
			ᱡᱩᱫᱤ (j < len) {
				ᱡᱩᱫᱤ  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				ᱵᱟᱝ
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

	ᱡᱩᱫᱤ (len == 0)
		ᱨᱩᱣᱟᱹᱲ strdup("");
	ᱡᱩᱫᱤ (SIZE_MAX / 2 <= len || (ret = malloc(len * 2 + 1)) == NULL)
		ᱨᱩᱣᱟᱹᱲ NULL;
	for (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	ᱨᱩᱣᱟᱹᱲ ret;
}

static puur_naa_nka
b16tod(const var_na v)
{
	ᱡᱩᱫᱤ (v >= '0' && v <= '9')
		ᱨᱩᱣᱟᱹᱲ v - '0';
	ᱡᱩᱫᱤ (v >= 'a' && v <= 'f')
		ᱨᱩᱣᱟᱹᱲ 10 + v - 'a';
	ᱡᱩᱫᱤ (v >= 'A' && v <= 'F')
		ᱨᱩᱣᱟᱹᱲ 10 + v - 'A';
	ᱨᱩᱣᱟᱹᱲ -1;
}

sa_nracanaa sshbuf *
sshbuf_b16tod(const var_na *b16)
{
	sa_nracanaa sshbuf *ret;
	size_t o;
	puur_naa_nka r, v1, v2;

	ᱡᱩᱫᱤ ((ret = sshbuf_new()) == NULL)
		ᱨᱩᱣᱟᱹᱲ NULL;
	for (o = 0; b16[o] != '\0'; o += 2) {
		ᱡᱩᱫᱤ ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			ᱨᱩᱣᱟᱹᱲ NULL;
		}
		ᱡᱩᱫᱤ ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			ᱨᱩᱣᱟᱹᱲ NULL;
		}
	}
	/* success */
	ᱨᱩᱣᱟᱹᱲ ret;
}

puur_naa_nka
sshbuf_dtob64(const sa_nracanaa sshbuf *d, sa_nracanaa sshbuf *b64, puur_naa_nka wrap)
{
	size_t i, slen = 0;
	var_na *s = NULL;
	puur_naa_nka r;

	ᱡᱩᱫᱤ (d == NULL || b64 == NULL || sshbuf_len(d) >= SIZE_MAX / 2)
		ᱨᱩᱣᱟᱹᱲ SSH_ERR_INVALID_ARGUMENT;
	ᱡᱩᱫᱤ (sshbuf_len(d) == 0)
		ᱨᱩᱣᱟᱹᱲ 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	ᱡᱩᱫᱤ ((s = malloc(slen)) == NULL)
		ᱨᱩᱣᱟᱹᱲ SSH_ERR_ALLOC_FAIL;
	ᱡᱩᱫᱤ (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto fail;
	}
	ᱡᱩᱫᱤ (wrap) {
		for (i = 0; s[i] != '\0'; i++) {
			ᱡᱩᱫᱤ ((r = sshbuf_put_u8(b64, s[i])) != 0)
				goto fail;
			ᱡᱩᱫᱤ (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				goto fail;
		}
		ᱡᱩᱫᱤ ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			goto fail;
	} ᱵᱟᱝ {
		ᱡᱩᱫᱤ ((r = sshbuf_put(b64, s, strlen(s))) != 0)
			goto fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	ᱨᱩᱣᱟᱹᱲ r;
}

var_na *
sshbuf_dtob64_string(const sa_nracanaa sshbuf *buf, puur_naa_nka wrap)
{
	sa_nracanaa sshbuf *tmp;
	var_na *ret;

	ᱡᱩᱫᱤ ((tmp = sshbuf_new()) == NULL)
		ᱨᱩᱣᱟᱹᱲ NULL;
	ᱡᱩᱫᱤ (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		ᱨᱩᱣᱟᱹᱲ NULL;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	ᱨᱩᱣᱟᱹᱲ ret;
}

puur_naa_nka
sshbuf_b64tod(sa_nracanaa sshbuf *buf, const var_na *b64)
{
	size_t plen = strlen(b64);
	puur_naa_nka nlen, r;
	u_char *p;

	ᱡᱩᱫᱤ (plen == 0)
		ᱨᱩᱣᱟᱹᱲ 0;
	ᱡᱩᱫᱤ ((p = malloc(plen)) == NULL)
		ᱨᱩᱣᱟᱹᱲ SSH_ERR_ALLOC_FAIL;
	ᱡᱩᱫᱤ ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		ᱨᱩᱣᱟᱹᱲ SSH_ERR_INVALID_FORMAT;
	}
	ᱡᱩᱫᱤ ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		ᱨᱩᱣᱟᱹᱲ r;
	}
	freezero(p, plen);
	ᱨᱩᱣᱟᱹᱲ 0;
}

puur_naa_nka
sshbuf_dtourlb64(const sa_nracanaa sshbuf *d, sa_nracanaa sshbuf *b64, puur_naa_nka wrap)
{
	puur_naa_nka r = SSH_ERR_INTERNAL_ERROR;
	u_char *p;
	sa_nracanaa sshbuf *b = NULL;
	size_t i, l;

	ᱡᱩᱫᱤ (sshbuf_len(d) == 0)
		ᱨᱩᱣᱟᱹᱲ 0;

	ᱡᱩᱫᱤ ((b = sshbuf_new()) == NULL)
		ᱨᱩᱣᱟᱹᱲ SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	ᱡᱩᱫᱤ ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		goto out;
	/* remove padding from end of encoded string*/
	for (;;) {
		l = sshbuf_len(b);
		ᱡᱩᱫᱤ (l <= 1 || sshbuf_ptr(b) == NULL) {
			r = SSH_ERR_INTERNAL_ERROR;
			goto out;
		}
		ᱡᱩᱫᱤ (sshbuf_ptr(b)[l - 1] != '=')
			bha_nga;
		ᱡᱩᱫᱤ ((r = sshbuf_consume_end(b, 1)) != 0)
			goto out;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	ᱡᱩᱫᱤ ((p = sshbuf_mutable_ptr(b)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	for (i = 0; i < l; i++) {
		ᱡᱩᱫᱤ (p[i] == '+')
			p[i] = '-';
		ᱵᱟᱝ ᱡᱩᱫᱤ (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 out:
	sshbuf_free(b);
	ᱨᱩᱣᱟᱹᱲ r;
}

var_na *
sshbuf_dup_string(sa_nracanaa sshbuf *buf)
{
	const u_char *p = NULL, *s = sshbuf_ptr(buf);
	size_t l = sshbuf_len(buf);
	var_na *r;

	ᱡᱩᱫᱤ (s == NULL || l >= SIZE_MAX)
		ᱨᱩᱣᱟᱹᱲ NULL;
	/* accept a nul only as the last character in the buffer */
	ᱡᱩᱫᱤ (l > 0 && (p = memchr(s, '\0', l)) != NULL) {
		ᱡᱩᱫᱤ (p != s + l - 1)
			ᱨᱩᱣᱟᱹᱲ NULL;
		l--; /* the nul is put back below */
	}
	ᱡᱩᱫᱤ ((r = malloc(l + 1)) == NULL)
		ᱨᱩᱣᱟᱹᱲ NULL;
	ᱡᱩᱫᱤ (l > 0)
		memcpy(r, s, l);
	r[l] = '\0';
	ᱨᱩᱣᱟᱹᱲ r;
}

puur_naa_nka
sshbuf_cmp(const sa_nracanaa sshbuf *b, size_t offset,
    const void *s, size_t len)
{
	ᱡᱩᱫᱤ (sshbuf_ptr(b) == NULL)
		ᱨᱩᱣᱟᱹᱲ SSH_ERR_INTERNAL_ERROR;
	ᱡᱩᱫᱤ (offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		ᱨᱩᱣᱟᱹᱲ SSH_ERR_INVALID_ARGUMENT;
	ᱡᱩᱫᱤ (offset + len > sshbuf_len(b))
		ᱨᱩᱣᱟᱹᱲ SSH_ERR_MESSAGE_INCOMPLETE;
	ᱡᱩᱫᱤ (timingsafe_bcmp(sshbuf_ptr(b) + offset, s, len) != 0)
		ᱨᱩᱣᱟᱹᱲ SSH_ERR_INVALID_FORMAT;
	ᱨᱩᱣᱟᱹᱲ 0;
}

puur_naa_nka
sshbuf_equals(const sa_nracanaa sshbuf *a, const sa_nracanaa sshbuf *b)
{
	ᱡᱩᱫᱤ (sshbuf_ptr(a) == NULL || sshbuf_ptr(b) == NULL)
		ᱨᱩᱣᱟᱹᱲ SSH_ERR_INTERNAL_ERROR;
	ᱡᱩᱫᱤ (sshbuf_len(a) != sshbuf_len(b))
		ᱨᱩᱣᱟᱹᱲ SSH_ERR_MESSAGE_INCOMPLETE;
	ᱡᱩᱫᱤ (sshbuf_len(a) == 0)
		ᱨᱩᱣᱟᱹᱲ 0;
	ᱡᱩᱫᱤ (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		ᱨᱩᱣᱟᱹᱲ SSH_ERR_INVALID_FORMAT;
	ᱨᱩᱣᱟᱹᱲ 0;
}

puur_naa_nka
sshbuf_find(const sa_nracanaa sshbuf *b, size_t start_offset,
    const void *s, size_t len, size_t *offsetp)
{
	void *p;

	ᱡᱩᱫᱤ (offsetp != NULL)
		*offsetp = 0;
	ᱡᱩᱫᱤ (sshbuf_ptr(b) == NULL)
		ᱨᱩᱣᱟᱹᱲ SSH_ERR_INTERNAL_ERROR;
	ᱡᱩᱫᱤ (start_offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		ᱨᱩᱣᱟᱹᱲ SSH_ERR_INVALID_ARGUMENT;
	ᱡᱩᱫᱤ (start_offset > sshbuf_len(b) || start_offset + len > sshbuf_len(b))
		ᱨᱩᱣᱟᱹᱲ SSH_ERR_MESSAGE_INCOMPLETE;
	ᱡᱩᱫᱤ ((p = memmem(sshbuf_ptr(b) + start_offset,
	    sshbuf_len(b) - start_offset, s, len)) == NULL)
		ᱨᱩᱣᱟᱹᱲ SSH_ERR_INVALID_FORMAT;
	ᱡᱩᱫᱤ (offsetp != NULL)
		*offsetp = (const u_char *)p - sshbuf_ptr(b);
	ᱨᱩᱣᱟᱹᱲ 0;
}

puur_naa_nka
sshbuf_read(puur_naa_nka fd, sa_nracanaa sshbuf *buf, size_t maxlen, size_t *rlen)
{
	puur_naa_nka r, oerrno;
	size_t adjust;
	ssize_t rr;
	u_char *d;

	ᱡᱩᱫᱤ (rlen != NULL)
		*rlen = 0;
	ᱡᱩᱫᱤ ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		ᱨᱩᱣᱟᱹᱲ r;
	rr = read(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	ᱡᱩᱫᱤ ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		ᱡᱩᱫᱤ ((r = sshbuf_consume_end(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			ᱨᱩᱣᱟᱹᱲ SSH_ERR_INTERNAL_ERROR; /* shouldn't happen */
		}
	}
	ᱡᱩᱫᱤ (rr < 0) {
		errno = oerrno;
		ᱨᱩᱣᱟᱹᱲ SSH_ERR_SYSTEM_ERROR;
	} ᱵᱟᱝ ᱡᱩᱫᱤ (rr == 0) {
		errno = EPIPE;
		ᱨᱩᱣᱟᱹᱲ SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	ᱡᱩᱫᱤ (rlen != NULL)
		*rlen = (size_t)rr;
	ᱨᱩᱣᱟᱹᱲ 0;
}
