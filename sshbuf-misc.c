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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <netinet/in.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <resolv.h>
#અન્તર્ભાવ <ctype.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "ssherr.h"
#define SSHBUF_INTERNAL
#અન્તર્ભાવ "sshbuf.h"

શૂન્ય
sshbuf_dump_data(અચલ શૂન્ય *s, size_t len, FILE *f)
{
	size_t i, j;
	અચલ u_char *p = (અચલ u_char *)s;

	માટે (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		માટે (j = i; j < i + 16; j++) {
			જો (j < len)
				fprintf(f, "%02x ", p[j]);
			નહીંતર
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		માટે (j = i; j < i + 16; j++) {
			જો (j < len) {
				જો  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				નહીંતર
					fprintf(f, ".");
			}
		}
		fprintf(f, "\n");
	}
}

શૂન્ય
sshbuf_dump(અચલ સંરચના sshbuf *buf, FILE *f)
{
	fprintf(f, "buffer len = %zu\n", sshbuf_len(buf));
	sshbuf_dump_data(sshbuf_ptr(buf), sshbuf_len(buf), f);
}

અક્ષર *
sshbuf_dtob16(અચલ સંરચના sshbuf *buf)
{
	size_t i, j, len = sshbuf_len(buf);
	અચલ u_char *p = sshbuf_ptr(buf);
	અક્ષર *ret;
	અચલ અક્ષર hex[] = "0123456789abcdef";

	જો (len == 0)
		પાછા strdup("");
	જો (SIZE_MAX / 2 <= len || (ret = malloc(len * 2 + 1)) == ખાલી)
		પાછા ખાલી;
	માટે (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	પાછા ret;
}

સ્થિર પૂર્ણાંક
b16tod(અચલ અક્ષર v)
{
	જો (v >= '0' && v <= '9')
		પાછા v - '0';
	જો (v >= 'a' && v <= 'f')
		પાછા 10 + v - 'a';
	જો (v >= 'A' && v <= 'F')
		પાછા 10 + v - 'A';
	પાછા -1;
}

સંરચના sshbuf *
sshbuf_b16tod(અચલ અક્ષર *b16)
{
	સંરચના sshbuf *ret;
	size_t o;
	પૂર્ણાંક r, v1, v2;

	જો ((ret = sshbuf_new()) == ખાલી)
		પાછા ખાલી;
	માટે (o = 0; b16[o] != '\0'; o += 2) {
		જો ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			પાછા ખાલી;
		}
		જો ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			પાછા ખાલી;
		}
	}
	/* success */
	પાછા ret;
}

પૂર્ણાંક
sshbuf_dtob64(અચલ સંરચના sshbuf *d, સંરચના sshbuf *b64, પૂર્ણાંક wrap)
{
	size_t i, slen = 0;
	અક્ષર *s = ખાલી;
	પૂર્ણાંક r;

	જો (d == ખાલી || b64 == ખાલી || sshbuf_len(d) >= SIZE_MAX / 2)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (sshbuf_len(d) == 0)
		પાછા 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	જો ((s = malloc(slen)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_INTERNAL_ERROR;
		જાઓ fail;
	}
	જો (wrap) {
		માટે (i = 0; s[i] != '\0'; i++) {
			જો ((r = sshbuf_put_u8(b64, s[i])) != 0)
				જાઓ fail;
			જો (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				જાઓ fail;
		}
		જો ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			જાઓ fail;
	} નહીંતર {
		જો ((r = sshbuf_put(b64, s, strlen(s))) != 0)
			જાઓ fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	પાછા r;
}

અક્ષર *
sshbuf_dtob64_string(અચલ સંરચના sshbuf *buf, પૂર્ણાંક wrap)
{
	સંરચના sshbuf *tmp;
	અક્ષર *ret;

	જો ((tmp = sshbuf_new()) == ખાલી)
		પાછા ખાલી;
	જો (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		પાછા ખાલી;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	પાછા ret;
}

પૂર્ણાંક
sshbuf_b64tod(સંરચના sshbuf *buf, અચલ અક્ષર *b64)
{
	size_t plen = strlen(b64);
	પૂર્ણાંક nlen, r;
	u_char *p;

	જો (plen == 0)
		પાછા 0;
	જો ((p = malloc(plen)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		પાછા SSH_ERR_INVALID_FORMAT;
	}
	જો ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		પાછા r;
	}
	freezero(p, plen);
	પાછા 0;
}

પૂર્ણાંક
sshbuf_dtourlb64(અચલ સંરચના sshbuf *d, સંરચના sshbuf *b64, પૂર્ણાંક wrap)
{
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	u_char *p;
	સંરચના sshbuf *b = ખાલી;
	size_t i, l;

	જો (sshbuf_len(d) == 0)
		પાછા 0;

	જો ((b = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	જો ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		જાઓ out;
	/* remove padding from end of encoded string*/
	માટે (;;) {
		l = sshbuf_len(b);
		જો (l <= 1 || sshbuf_ptr(b) == ખાલી) {
			r = SSH_ERR_INTERNAL_ERROR;
			જાઓ out;
		}
		જો (sshbuf_ptr(b)[l - 1] != '=')
			તોડો;
		જો ((r = sshbuf_consume_end(b, 1)) != 0)
			જાઓ out;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	જો ((p = sshbuf_mutable_ptr(b)) == ખાલી) {
		r = SSH_ERR_INTERNAL_ERROR;
		જાઓ out;
	}
	માટે (i = 0; i < l; i++) {
		જો (p[i] == '+')
			p[i] = '-';
		નહીંતર જો (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 out:
	sshbuf_free(b);
	પાછા r;
}

અક્ષર *
sshbuf_dup_string(સંરચના sshbuf *buf)
{
	અચલ u_char *p = ખાલી, *s = sshbuf_ptr(buf);
	size_t l = sshbuf_len(buf);
	અક્ષર *r;

	જો (s == ખાલી || l >= SIZE_MAX)
		પાછા ખાલી;
	/* accept a nul only as the last character in the buffer */
	જો (l > 0 && (p = memchr(s, '\0', l)) != ખાલી) {
		જો (p != s + l - 1)
			પાછા ખાલી;
		l--; /* the nul is put back below */
	}
	જો ((r = malloc(l + 1)) == ખાલી)
		પાછા ખાલી;
	જો (l > 0)
		memcpy(r, s, l);
	r[l] = '\0';
	પાછા r;
}

પૂર્ણાંક
sshbuf_cmp(અચલ સંરચના sshbuf *b, size_t offset,
    અચલ શૂન્ય *s, size_t len)
{
	જો (sshbuf_ptr(b) == ખાલી)
		પાછા SSH_ERR_INTERNAL_ERROR;
	જો (offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (offset + len > sshbuf_len(b))
		પાછા SSH_ERR_MESSAGE_INCOMPLETE;
	જો (timingsafe_bcmp(sshbuf_ptr(b) + offset, s, len) != 0)
		પાછા SSH_ERR_INVALID_FORMAT;
	પાછા 0;
}

પૂર્ણાંક
sshbuf_equals(અચલ સંરચના sshbuf *a, અચલ સંરચના sshbuf *b)
{
	જો (sshbuf_ptr(a) == ખાલી || sshbuf_ptr(b) == ખાલી)
		પાછા SSH_ERR_INTERNAL_ERROR;
	જો (sshbuf_len(a) != sshbuf_len(b))
		પાછા SSH_ERR_MESSAGE_INCOMPLETE;
	જો (sshbuf_len(a) == 0)
		પાછા 0;
	જો (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		પાછા SSH_ERR_INVALID_FORMAT;
	પાછા 0;
}

પૂર્ણાંક
sshbuf_find(અચલ સંરચના sshbuf *b, size_t start_offset,
    અચલ શૂન્ય *s, size_t len, size_t *offsetp)
{
	શૂન્ય *p;

	જો (offsetp != ખાલી)
		*offsetp = 0;
	જો (sshbuf_ptr(b) == ખાલી)
		પાછા SSH_ERR_INTERNAL_ERROR;
	જો (start_offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (start_offset > sshbuf_len(b) || start_offset + len > sshbuf_len(b))
		પાછા SSH_ERR_MESSAGE_INCOMPLETE;
	જો ((p = memmem(sshbuf_ptr(b) + start_offset,
	    sshbuf_len(b) - start_offset, s, len)) == ખાલી)
		પાછા SSH_ERR_INVALID_FORMAT;
	જો (offsetp != ખાલી)
		*offsetp = (અચલ u_char *)p - sshbuf_ptr(b);
	પાછા 0;
}

પૂર્ણાંક
sshbuf_read(પૂર્ણાંક fd, સંરચના sshbuf *buf, size_t maxlen, size_t *rlen)
{
	પૂર્ણાંક r, oerrno;
	size_t adjust;
	ssize_t rr;
	u_char *d;

	જો (rlen != ખાલી)
		*rlen = 0;
	જો ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		પાછા r;
	rr = પઠ(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	જો ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		જો ((r = sshbuf_consume_end(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			પાછા SSH_ERR_INTERNAL_ERROR; /* shouldn't happen */
		}
	}
	જો (rr < 0) {
		errno = oerrno;
		પાછા SSH_ERR_SYSTEM_ERROR;
	} નહીંતર જો (rr == 0) {
		errno = EPIPE;
		પાછા SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	જો (rlen != ખાલી)
		*rlen = (size_t)rr;
	પાછા 0;
}
