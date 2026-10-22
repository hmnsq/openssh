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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <netinet/in.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <resolv.h>
#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "ssherr.h"
#define SSHBUF_INTERNAL
#അന്തര്ഭാവ "sshbuf.h"

ശൂന്യം
sshbuf_dump_data(സ്ഥിരം ശൂന്യം *s, size_t len, FILE *f)
{
	size_t i, j;
	സ്ഥിരം u_char *p = (സ്ഥിരം u_char *)s;

	വേണ്ടി (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		വേണ്ടി (j = i; j < i + 16; j++) {
			എങ്കിൽ (j < len)
				fprintf(f, "%02x ", p[j]);
			അല്ലെങ്കിൽ
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		വേണ്ടി (j = i; j < i + 16; j++) {
			എങ്കിൽ (j < len) {
				എങ്കിൽ  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				അല്ലെങ്കിൽ
					fprintf(f, ".");
			}
		}
		fprintf(f, "\n");
	}
}

ശൂന്യം
sshbuf_dump(സ്ഥിരം ഘടന sshbuf *buf, FILE *f)
{
	fprintf(f, "buffer len = %zu\n", sshbuf_len(buf));
	sshbuf_dump_data(sshbuf_ptr(buf), sshbuf_len(buf), f);
}

അക്ഷരം *
sshbuf_dtob16(സ്ഥിരം ഘടന sshbuf *buf)
{
	size_t i, j, len = sshbuf_len(buf);
	സ്ഥിരം u_char *p = sshbuf_ptr(buf);
	അക്ഷരം *ret;
	സ്ഥിരം അക്ഷരം hex[] = "0123456789abcdef";

	എങ്കിൽ (len == 0)
		തിരികെ strdup("");
	എങ്കിൽ (SIZE_MAX / 2 <= len || (ret = malloc(len * 2 + 1)) == ശൂന്യ)
		തിരികെ ശൂന്യ;
	വേണ്ടി (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
b16tod(സ്ഥിരം അക്ഷരം v)
{
	എങ്കിൽ (v >= '0' && v <= '9')
		തിരികെ v - '0';
	എങ്കിൽ (v >= 'a' && v <= 'f')
		തിരികെ 10 + v - 'a';
	എങ്കിൽ (v >= 'A' && v <= 'F')
		തിരികെ 10 + v - 'A';
	തിരികെ -1;
}

ഘടന sshbuf *
sshbuf_b16tod(സ്ഥിരം അക്ഷരം *b16)
{
	ഘടന sshbuf *ret;
	size_t o;
	പൂർണ്ണസംഖ്യ r, v1, v2;

	എങ്കിൽ ((ret = sshbuf_new()) == ശൂന്യ)
		തിരികെ ശൂന്യ;
	വേണ്ടി (o = 0; b16[o] != '\0'; o += 2) {
		എങ്കിൽ ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			തിരികെ ശൂന്യ;
		}
		എങ്കിൽ ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			തിരികെ ശൂന്യ;
		}
	}
	/* success */
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
sshbuf_dtob64(സ്ഥിരം ഘടന sshbuf *d, ഘടന sshbuf *b64, പൂർണ്ണസംഖ്യ wrap)
{
	size_t i, slen = 0;
	അക്ഷരം *s = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (d == ശൂന്യ || b64 == ശൂന്യ || sshbuf_len(d) >= SIZE_MAX / 2)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (sshbuf_len(d) == 0)
		തിരികെ 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	എങ്കിൽ ((s = malloc(slen)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_INTERNAL_ERROR;
		പോകുക fail;
	}
	എങ്കിൽ (wrap) {
		വേണ്ടി (i = 0; s[i] != '\0'; i++) {
			എങ്കിൽ ((r = sshbuf_put_u8(b64, s[i])) != 0)
				പോകുക fail;
			എങ്കിൽ (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				പോകുക fail;
		}
		എങ്കിൽ ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			പോകുക fail;
	} അല്ലെങ്കിൽ {
		എങ്കിൽ ((r = sshbuf_put(b64, s, strlen(s))) != 0)
			പോകുക fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	തിരികെ r;
}

അക്ഷരം *
sshbuf_dtob64_string(സ്ഥിരം ഘടന sshbuf *buf, പൂർണ്ണസംഖ്യ wrap)
{
	ഘടന sshbuf *tmp;
	അക്ഷരം *ret;

	എങ്കിൽ ((tmp = sshbuf_new()) == ശൂന്യ)
		തിരികെ ശൂന്യ;
	എങ്കിൽ (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		തിരികെ ശൂന്യ;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
sshbuf_b64tod(ഘടന sshbuf *buf, സ്ഥിരം അക്ഷരം *b64)
{
	size_t plen = strlen(b64);
	പൂർണ്ണസംഖ്യ nlen, r;
	u_char *p;

	എങ്കിൽ (plen == 0)
		തിരികെ 0;
	എങ്കിൽ ((p = malloc(plen)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		തിരികെ SSH_ERR_INVALID_FORMAT;
	}
	എങ്കിൽ ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		തിരികെ r;
	}
	freezero(p, plen);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_dtourlb64(സ്ഥിരം ഘടന sshbuf *d, ഘടന sshbuf *b64, പൂർണ്ണസംഖ്യ wrap)
{
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	u_char *p;
	ഘടന sshbuf *b = ശൂന്യ;
	size_t i, l;

	എങ്കിൽ (sshbuf_len(d) == 0)
		തിരികെ 0;

	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	എങ്കിൽ ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		പോകുക out;
	/* remove padding from end of encoded string*/
	വേണ്ടി (;;) {
		l = sshbuf_len(b);
		എങ്കിൽ (l <= 1 || sshbuf_ptr(b) == ശൂന്യ) {
			r = SSH_ERR_INTERNAL_ERROR;
			പോകുക out;
		}
		എങ്കിൽ (sshbuf_ptr(b)[l - 1] != '=')
			നിർത്തുക;
		എങ്കിൽ ((r = sshbuf_consume_end(b, 1)) != 0)
			പോകുക out;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	എങ്കിൽ ((p = sshbuf_mutable_ptr(b)) == ശൂന്യ) {
		r = SSH_ERR_INTERNAL_ERROR;
		പോകുക out;
	}
	വേണ്ടി (i = 0; i < l; i++) {
		എങ്കിൽ (p[i] == '+')
			p[i] = '-';
		അല്ലെങ്കിൽ എങ്കിൽ (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 out:
	sshbuf_free(b);
	തിരികെ r;
}

അക്ഷരം *
sshbuf_dup_string(ഘടന sshbuf *buf)
{
	സ്ഥിരം u_char *p = ശൂന്യ, *s = sshbuf_ptr(buf);
	size_t l = sshbuf_len(buf);
	അക്ഷരം *r;

	എങ്കിൽ (s == ശൂന്യ || l >= SIZE_MAX)
		തിരികെ ശൂന്യ;
	/* accept a nul only as the last character in the buffer */
	എങ്കിൽ (l > 0 && (p = memchr(s, '\0', l)) != ശൂന്യ) {
		എങ്കിൽ (p != s + l - 1)
			തിരികെ ശൂന്യ;
		l--; /* the nul is put back below */
	}
	എങ്കിൽ ((r = malloc(l + 1)) == ശൂന്യ)
		തിരികെ ശൂന്യ;
	എങ്കിൽ (l > 0)
		memcpy(r, s, l);
	r[l] = '\0';
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshbuf_cmp(സ്ഥിരം ഘടന sshbuf *b, size_t offset,
    സ്ഥിരം ശൂന്യം *s, size_t len)
{
	എങ്കിൽ (sshbuf_ptr(b) == ശൂന്യ)
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	എങ്കിൽ (offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (offset + len > sshbuf_len(b))
		തിരികെ SSH_ERR_MESSAGE_INCOMPLETE;
	എങ്കിൽ (timingsafe_bcmp(sshbuf_ptr(b) + offset, s, len) != 0)
		തിരികെ SSH_ERR_INVALID_FORMAT;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_equals(സ്ഥിരം ഘടന sshbuf *a, സ്ഥിരം ഘടന sshbuf *b)
{
	എങ്കിൽ (sshbuf_ptr(a) == ശൂന്യ || sshbuf_ptr(b) == ശൂന്യ)
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	എങ്കിൽ (sshbuf_len(a) != sshbuf_len(b))
		തിരികെ SSH_ERR_MESSAGE_INCOMPLETE;
	എങ്കിൽ (sshbuf_len(a) == 0)
		തിരികെ 0;
	എങ്കിൽ (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		തിരികെ SSH_ERR_INVALID_FORMAT;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_find(സ്ഥിരം ഘടന sshbuf *b, size_t start_offset,
    സ്ഥിരം ശൂന്യം *s, size_t len, size_t *offsetp)
{
	ശൂന്യം *p;

	എങ്കിൽ (offsetp != ശൂന്യ)
		*offsetp = 0;
	എങ്കിൽ (sshbuf_ptr(b) == ശൂന്യ)
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	എങ്കിൽ (start_offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (start_offset > sshbuf_len(b) || start_offset + len > sshbuf_len(b))
		തിരികെ SSH_ERR_MESSAGE_INCOMPLETE;
	എങ്കിൽ ((p = memmem(sshbuf_ptr(b) + start_offset,
	    sshbuf_len(b) - start_offset, s, len)) == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_FORMAT;
	എങ്കിൽ (offsetp != ശൂന്യ)
		*offsetp = (സ്ഥിരം u_char *)p - sshbuf_ptr(b);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_read(പൂർണ്ണസംഖ്യ fd, ഘടന sshbuf *buf, size_t maxlen, size_t *rlen)
{
	പൂർണ്ണസംഖ്യ r, oerrno;
	size_t adjust;
	ssize_t rr;
	u_char *d;

	എങ്കിൽ (rlen != ശൂന്യ)
		*rlen = 0;
	എങ്കിൽ ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		തിരികെ r;
	rr = പഠ(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	എങ്കിൽ ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		എങ്കിൽ ((r = sshbuf_consume_end(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			തിരികെ SSH_ERR_INTERNAL_ERROR; /* shouldn't happen */
		}
	}
	എങ്കിൽ (rr < 0) {
		errno = oerrno;
		തിരികെ SSH_ERR_SYSTEM_ERROR;
	} അല്ലെങ്കിൽ എങ്കിൽ (rr == 0) {
		errno = EPIPE;
		തിരികെ SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	എങ്കിൽ (rlen != ശൂന്യ)
		*rlen = (size_t)rr;
	തിരികെ 0;
}
