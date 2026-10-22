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

	සඳහා (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		සඳහා (j = i; j < i + 16; j++) {
			නම් (j < len)
				fprintf(f, "%02x ", p[j]);
			නැතහොත්
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		සඳහා (j = i; j < i + 16; j++) {
			නම් (j < len) {
				නම්  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				නැතහොත්
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

	නම් (len == 0)
		ආපසු strdup("");
	නම් (SIZE_MAX / 2 <= len || (ret = malloc(len * 2 + 1)) == NULL)
		ආපසු NULL;
	සඳහා (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	ආපසු ret;
}

static පූර්ණ_සංඛ්‍යා
b16tod(const var_na v)
{
	නම් (v >= '0' && v <= '9')
		ආපසු v - '0';
	නම් (v >= 'a' && v <= 'f')
		ආපසු 10 + v - 'a';
	නම් (v >= 'A' && v <= 'F')
		ආපසු 10 + v - 'A';
	ආපසු -1;
}

sa_nracanaa sshbuf *
sshbuf_b16tod(const var_na *b16)
{
	sa_nracanaa sshbuf *ret;
	size_t o;
	පූර්ණ_සංඛ්‍යා r, v1, v2;

	නම් ((ret = sshbuf_new()) == NULL)
		ආපසු NULL;
	සඳහා (o = 0; b16[o] != '\0'; o += 2) {
		නම් ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			ආපසු NULL;
		}
		නම් ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			ආපසු NULL;
		}
	}
	/* success */
	ආපසු ret;
}

පූර්ණ_සංඛ්‍යා
sshbuf_dtob64(const sa_nracanaa sshbuf *d, sa_nracanaa sshbuf *b64, පූර්ණ_සංඛ්‍යා wrap)
{
	size_t i, slen = 0;
	var_na *s = NULL;
	පූර්ණ_සංඛ්‍යා r;

	නම් (d == NULL || b64 == NULL || sshbuf_len(d) >= SIZE_MAX / 2)
		ආපසු SSH_ERR_INVALID_ARGUMENT;
	නම් (sshbuf_len(d) == 0)
		ආපසු 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	නම් ((s = malloc(slen)) == NULL)
		ආපසු SSH_ERR_ALLOC_FAIL;
	නම් (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto fail;
	}
	නම් (wrap) {
		සඳහා (i = 0; s[i] != '\0'; i++) {
			නම් ((r = sshbuf_put_u8(b64, s[i])) != 0)
				goto fail;
			නම් (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				goto fail;
		}
		නම් ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			goto fail;
	} නැතහොත් {
		නම් ((r = sshbuf_put(b64, s, strlen(s))) != 0)
			goto fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	ආපසු r;
}

var_na *
sshbuf_dtob64_string(const sa_nracanaa sshbuf *buf, පූර්ණ_සංඛ්‍යා wrap)
{
	sa_nracanaa sshbuf *tmp;
	var_na *ret;

	නම් ((tmp = sshbuf_new()) == NULL)
		ආපසු NULL;
	නම් (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		ආපසු NULL;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	ආපසු ret;
}

පූර්ණ_සංඛ්‍යා
sshbuf_b64tod(sa_nracanaa sshbuf *buf, const var_na *b64)
{
	size_t plen = strlen(b64);
	පූර්ණ_සංඛ්‍යා nlen, r;
	u_char *p;

	නම් (plen == 0)
		ආපසු 0;
	නම් ((p = malloc(plen)) == NULL)
		ආපසු SSH_ERR_ALLOC_FAIL;
	නම් ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		ආපසු SSH_ERR_INVALID_FORMAT;
	}
	නම් ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		ආපසු r;
	}
	freezero(p, plen);
	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
sshbuf_dtourlb64(const sa_nracanaa sshbuf *d, sa_nracanaa sshbuf *b64, පූර්ණ_සංඛ්‍යා wrap)
{
	පූර්ණ_සංඛ්‍යා r = SSH_ERR_INTERNAL_ERROR;
	u_char *p;
	sa_nracanaa sshbuf *b = NULL;
	size_t i, l;

	නම් (sshbuf_len(d) == 0)
		ආපසු 0;

	නම් ((b = sshbuf_new()) == NULL)
		ආපසු SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	නම් ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		goto out;
	/* remove padding from end of encoded string*/
	සඳහා (;;) {
		l = sshbuf_len(b);
		නම් (l <= 1 || sshbuf_ptr(b) == NULL) {
			r = SSH_ERR_INTERNAL_ERROR;
			goto out;
		}
		නම් (sshbuf_ptr(b)[l - 1] != '=')
			bha_nga;
		නම් ((r = sshbuf_consume_end(b, 1)) != 0)
			goto out;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	නම් ((p = sshbuf_mutable_ptr(b)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	සඳහා (i = 0; i < l; i++) {
		නම් (p[i] == '+')
			p[i] = '-';
		නැතහොත් නම් (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 out:
	sshbuf_free(b);
	ආපසු r;
}

var_na *
sshbuf_dup_string(sa_nracanaa sshbuf *buf)
{
	const u_char *p = NULL, *s = sshbuf_ptr(buf);
	size_t l = sshbuf_len(buf);
	var_na *r;

	නම් (s == NULL || l >= SIZE_MAX)
		ආපසු NULL;
	/* accept a nul only as the last character in the buffer */
	නම් (l > 0 && (p = memchr(s, '\0', l)) != NULL) {
		නම් (p != s + l - 1)
			ආපසු NULL;
		l--; /* the nul is put back below */
	}
	නම් ((r = malloc(l + 1)) == NULL)
		ආපසු NULL;
	නම් (l > 0)
		memcpy(r, s, l);
	r[l] = '\0';
	ආපසු r;
}

පූර්ණ_සංඛ්‍යා
sshbuf_cmp(const sa_nracanaa sshbuf *b, size_t offset,
    const void *s, size_t len)
{
	නම් (sshbuf_ptr(b) == NULL)
		ආපසු SSH_ERR_INTERNAL_ERROR;
	නම් (offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		ආපසු SSH_ERR_INVALID_ARGUMENT;
	නම් (offset + len > sshbuf_len(b))
		ආපසු SSH_ERR_MESSAGE_INCOMPLETE;
	නම් (timingsafe_bcmp(sshbuf_ptr(b) + offset, s, len) != 0)
		ආපසු SSH_ERR_INVALID_FORMAT;
	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
sshbuf_equals(const sa_nracanaa sshbuf *a, const sa_nracanaa sshbuf *b)
{
	නම් (sshbuf_ptr(a) == NULL || sshbuf_ptr(b) == NULL)
		ආපසු SSH_ERR_INTERNAL_ERROR;
	නම් (sshbuf_len(a) != sshbuf_len(b))
		ආපසු SSH_ERR_MESSAGE_INCOMPLETE;
	නම් (sshbuf_len(a) == 0)
		ආපසු 0;
	නම් (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		ආපසු SSH_ERR_INVALID_FORMAT;
	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
sshbuf_find(const sa_nracanaa sshbuf *b, size_t start_offset,
    const void *s, size_t len, size_t *offsetp)
{
	void *p;

	නම් (offsetp != NULL)
		*offsetp = 0;
	නම් (sshbuf_ptr(b) == NULL)
		ආපසු SSH_ERR_INTERNAL_ERROR;
	නම් (start_offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		ආපසු SSH_ERR_INVALID_ARGUMENT;
	නම් (start_offset > sshbuf_len(b) || start_offset + len > sshbuf_len(b))
		ආපසු SSH_ERR_MESSAGE_INCOMPLETE;
	නම් ((p = memmem(sshbuf_ptr(b) + start_offset,
	    sshbuf_len(b) - start_offset, s, len)) == NULL)
		ආපසු SSH_ERR_INVALID_FORMAT;
	නම් (offsetp != NULL)
		*offsetp = (const u_char *)p - sshbuf_ptr(b);
	ආපසු 0;
}

පූර්ණ_සංඛ්‍යා
sshbuf_read(පූර්ණ_සංඛ්‍යා fd, sa_nracanaa sshbuf *buf, size_t maxlen, size_t *rlen)
{
	පූර්ණ_සංඛ්‍යා r, oerrno;
	size_t adjust;
	ssize_t rr;
	u_char *d;

	නම් (rlen != NULL)
		*rlen = 0;
	නම් ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		ආපසු r;
	rr = read(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	නම් ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		නම් ((r = sshbuf_consume_end(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			ආපසු SSH_ERR_INTERNAL_ERROR; /* shouldn't happen */
		}
	}
	නම් (rr < 0) {
		errno = oerrno;
		ආපසු SSH_ERR_SYSTEM_ERROR;
	} නැතහොත් නම් (rr == 0) {
		errno = EPIPE;
		ආපසු SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	නම් (rlen != NULL)
		*rlen = (size_t)rr;
	ආපසු 0;
}
