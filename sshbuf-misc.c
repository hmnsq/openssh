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

	ສຳລັບ (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		ສຳລັບ (j = i; j < i + 16; j++) {
			ຖ້າ (j < len)
				fprintf(f, "%02x ", p[j]);
			ບໍ່ດັ່ງນັ້ນ
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		ສຳລັບ (j = i; j < i + 16; j++) {
			ຖ້າ (j < len) {
				ຖ້າ  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				ບໍ່ດັ່ງນັ້ນ
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

	ຖ້າ (len == 0)
		ສົ່ງຄືນ strdup("");
	ຖ້າ (SIZE_MAX / 2 <= len || (ret = malloc(len * 2 + 1)) == NULL)
		ສົ່ງຄືນ NULL;
	ສຳລັບ (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	ສົ່ງຄືນ ret;
}

static ຈຳນວນເຕັມ
b16tod(const var_na v)
{
	ຖ້າ (v >= '0' && v <= '9')
		ສົ່ງຄືນ v - '0';
	ຖ້າ (v >= 'a' && v <= 'f')
		ສົ່ງຄືນ 10 + v - 'a';
	ຖ້າ (v >= 'A' && v <= 'F')
		ສົ່ງຄືນ 10 + v - 'A';
	ສົ່ງຄືນ -1;
}

sa_nracanaa sshbuf *
sshbuf_b16tod(const var_na *b16)
{
	sa_nracanaa sshbuf *ret;
	size_t o;
	ຈຳນວນເຕັມ r, v1, v2;

	ຖ້າ ((ret = sshbuf_new()) == NULL)
		ສົ່ງຄືນ NULL;
	ສຳລັບ (o = 0; b16[o] != '\0'; o += 2) {
		ຖ້າ ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			ສົ່ງຄືນ NULL;
		}
		ຖ້າ ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			ສົ່ງຄືນ NULL;
		}
	}
	/* success */
	ສົ່ງຄືນ ret;
}

ຈຳນວນເຕັມ
sshbuf_dtob64(const sa_nracanaa sshbuf *d, sa_nracanaa sshbuf *b64, ຈຳນວນເຕັມ wrap)
{
	size_t i, slen = 0;
	var_na *s = NULL;
	ຈຳນວນເຕັມ r;

	ຖ້າ (d == NULL || b64 == NULL || sshbuf_len(d) >= SIZE_MAX / 2)
		ສົ່ງຄືນ SSH_ERR_INVALID_ARGUMENT;
	ຖ້າ (sshbuf_len(d) == 0)
		ສົ່ງຄືນ 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	ຖ້າ ((s = malloc(slen)) == NULL)
		ສົ່ງຄືນ SSH_ERR_ALLOC_FAIL;
	ຖ້າ (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto fail;
	}
	ຖ້າ (wrap) {
		ສຳລັບ (i = 0; s[i] != '\0'; i++) {
			ຖ້າ ((r = sshbuf_put_u8(b64, s[i])) != 0)
				goto fail;
			ຖ້າ (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				goto fail;
		}
		ຖ້າ ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			goto fail;
	} ບໍ່ດັ່ງນັ້ນ {
		ຖ້າ ((r = sshbuf_put(b64, s, strlen(s))) != 0)
			goto fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	ສົ່ງຄືນ r;
}

var_na *
sshbuf_dtob64_string(const sa_nracanaa sshbuf *buf, ຈຳນວນເຕັມ wrap)
{
	sa_nracanaa sshbuf *tmp;
	var_na *ret;

	ຖ້າ ((tmp = sshbuf_new()) == NULL)
		ສົ່ງຄືນ NULL;
	ຖ້າ (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		ສົ່ງຄືນ NULL;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	ສົ່ງຄືນ ret;
}

ຈຳນວນເຕັມ
sshbuf_b64tod(sa_nracanaa sshbuf *buf, const var_na *b64)
{
	size_t plen = strlen(b64);
	ຈຳນວນເຕັມ nlen, r;
	u_char *p;

	ຖ້າ (plen == 0)
		ສົ່ງຄືນ 0;
	ຖ້າ ((p = malloc(plen)) == NULL)
		ສົ່ງຄືນ SSH_ERR_ALLOC_FAIL;
	ຖ້າ ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		ສົ່ງຄືນ SSH_ERR_INVALID_FORMAT;
	}
	ຖ້າ ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		ສົ່ງຄືນ r;
	}
	freezero(p, plen);
	ສົ່ງຄືນ 0;
}

ຈຳນວນເຕັມ
sshbuf_dtourlb64(const sa_nracanaa sshbuf *d, sa_nracanaa sshbuf *b64, ຈຳນວນເຕັມ wrap)
{
	ຈຳນວນເຕັມ r = SSH_ERR_INTERNAL_ERROR;
	u_char *p;
	sa_nracanaa sshbuf *b = NULL;
	size_t i, l;

	ຖ້າ (sshbuf_len(d) == 0)
		ສົ່ງຄືນ 0;

	ຖ້າ ((b = sshbuf_new()) == NULL)
		ສົ່ງຄືນ SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	ຖ້າ ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		goto out;
	/* remove padding from end of encoded string*/
	ສຳລັບ (;;) {
		l = sshbuf_len(b);
		ຖ້າ (l <= 1 || sshbuf_ptr(b) == NULL) {
			r = SSH_ERR_INTERNAL_ERROR;
			goto out;
		}
		ຖ້າ (sshbuf_ptr(b)[l - 1] != '=')
			bha_nga;
		ຖ້າ ((r = sshbuf_consume_end(b, 1)) != 0)
			goto out;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	ຖ້າ ((p = sshbuf_mutable_ptr(b)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	ສຳລັບ (i = 0; i < l; i++) {
		ຖ້າ (p[i] == '+')
			p[i] = '-';
		ບໍ່ດັ່ງນັ້ນ ຖ້າ (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 out:
	sshbuf_free(b);
	ສົ່ງຄືນ r;
}

var_na *
sshbuf_dup_string(sa_nracanaa sshbuf *buf)
{
	const u_char *p = NULL, *s = sshbuf_ptr(buf);
	size_t l = sshbuf_len(buf);
	var_na *r;

	ຖ້າ (s == NULL || l >= SIZE_MAX)
		ສົ່ງຄືນ NULL;
	/* accept a nul only as the last character in the buffer */
	ຖ້າ (l > 0 && (p = memchr(s, '\0', l)) != NULL) {
		ຖ້າ (p != s + l - 1)
			ສົ່ງຄືນ NULL;
		l--; /* the nul is put back below */
	}
	ຖ້າ ((r = malloc(l + 1)) == NULL)
		ສົ່ງຄືນ NULL;
	ຖ້າ (l > 0)
		memcpy(r, s, l);
	r[l] = '\0';
	ສົ່ງຄືນ r;
}

ຈຳນວນເຕັມ
sshbuf_cmp(const sa_nracanaa sshbuf *b, size_t offset,
    const void *s, size_t len)
{
	ຖ້າ (sshbuf_ptr(b) == NULL)
		ສົ່ງຄືນ SSH_ERR_INTERNAL_ERROR;
	ຖ້າ (offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		ສົ່ງຄືນ SSH_ERR_INVALID_ARGUMENT;
	ຖ້າ (offset + len > sshbuf_len(b))
		ສົ່ງຄືນ SSH_ERR_MESSAGE_INCOMPLETE;
	ຖ້າ (timingsafe_bcmp(sshbuf_ptr(b) + offset, s, len) != 0)
		ສົ່ງຄືນ SSH_ERR_INVALID_FORMAT;
	ສົ່ງຄືນ 0;
}

ຈຳນວນເຕັມ
sshbuf_equals(const sa_nracanaa sshbuf *a, const sa_nracanaa sshbuf *b)
{
	ຖ້າ (sshbuf_ptr(a) == NULL || sshbuf_ptr(b) == NULL)
		ສົ່ງຄືນ SSH_ERR_INTERNAL_ERROR;
	ຖ້າ (sshbuf_len(a) != sshbuf_len(b))
		ສົ່ງຄືນ SSH_ERR_MESSAGE_INCOMPLETE;
	ຖ້າ (sshbuf_len(a) == 0)
		ສົ່ງຄືນ 0;
	ຖ້າ (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		ສົ່ງຄືນ SSH_ERR_INVALID_FORMAT;
	ສົ່ງຄືນ 0;
}

ຈຳນວນເຕັມ
sshbuf_find(const sa_nracanaa sshbuf *b, size_t start_offset,
    const void *s, size_t len, size_t *offsetp)
{
	void *p;

	ຖ້າ (offsetp != NULL)
		*offsetp = 0;
	ຖ້າ (sshbuf_ptr(b) == NULL)
		ສົ່ງຄືນ SSH_ERR_INTERNAL_ERROR;
	ຖ້າ (start_offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		ສົ່ງຄືນ SSH_ERR_INVALID_ARGUMENT;
	ຖ້າ (start_offset > sshbuf_len(b) || start_offset + len > sshbuf_len(b))
		ສົ່ງຄືນ SSH_ERR_MESSAGE_INCOMPLETE;
	ຖ້າ ((p = memmem(sshbuf_ptr(b) + start_offset,
	    sshbuf_len(b) - start_offset, s, len)) == NULL)
		ສົ່ງຄືນ SSH_ERR_INVALID_FORMAT;
	ຖ້າ (offsetp != NULL)
		*offsetp = (const u_char *)p - sshbuf_ptr(b);
	ສົ່ງຄືນ 0;
}

ຈຳນວນເຕັມ
sshbuf_read(ຈຳນວນເຕັມ fd, sa_nracanaa sshbuf *buf, size_t maxlen, size_t *rlen)
{
	ຈຳນວນເຕັມ r, oerrno;
	size_t adjust;
	ssize_t rr;
	u_char *d;

	ຖ້າ (rlen != NULL)
		*rlen = 0;
	ຖ້າ ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		ສົ່ງຄືນ r;
	rr = read(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	ຖ້າ ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		ຖ້າ ((r = sshbuf_consume_end(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			ສົ່ງຄືນ SSH_ERR_INTERNAL_ERROR; /* shouldn't happen */
		}
	}
	ຖ້າ (rr < 0) {
		errno = oerrno;
		ສົ່ງຄືນ SSH_ERR_SYSTEM_ERROR;
	} ບໍ່ດັ່ງນັ້ນ ຖ້າ (rr == 0) {
		errno = EPIPE;
		ສົ່ງຄືນ SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	ຖ້າ (rlen != NULL)
		*rlen = (size_t)rr;
	ສົ່ງຄືນ 0;
}
