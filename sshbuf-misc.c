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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <resolv.h>
#అన్తర్భావ <ctype.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "ssherr.h"
#నిర్వచించు SSHBUF_అంతర్గత
#అన్తర్భావ "sshbuf.h"

శూన్య
sshbuf_dump_దత్తాంశం(స్థిరరాశి శూన్య *s, కొలత_t len, FILE *f)
{
	కొలత_t i, j;
	స్థిరరాశి u_char *p = (స్థిరరాశి u_char *)s;

	కొరకు (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		కొరకు (j = i; j < i + 16; j++) {
			ఒకవేళ (j < len)
				fprintf(f, "%02x ", p[j]);
			లేకపోతే
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		కొరకు (j = i; j < i + 16; j++) {
			ఒకవేళ (j < len) {
				ఒకవేళ  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				లేకపోతే
					fprintf(f, ".");
			}
		}
		fprintf(f, "\n");
	}
}

శూన్య
sshbuf_dump(స్థిరరాశి నిర్మాణం sshbuf *buf, FILE *f)
{
	fprintf(f, "buffer len = %zu\n", sshbuf_len(buf));
	sshbuf_dump_దత్తాంశం(sshbuf_ptr(buf), sshbuf_len(buf), f);
}

అక్షరం *
sshbuf_dtob16(స్థిరరాశి నిర్మాణం sshbuf *buf)
{
	కొలత_t i, j, len = sshbuf_len(buf);
	స్థిరరాశి u_char *p = sshbuf_ptr(buf);
	అక్షరం *ret;
	స్థిరరాశి అక్షరం hex[] = "0123456789abcdef";

	ఒకవేళ (len == 0)
		తిరిగి strdup("");
	ఒకవేళ (SIZE_MAX / 2 <= len || (ret = జ్ఞాపకం_ఇవ్వు(len * 2 + 1)) == ఖాళీ)
		తిరిగి ఖాళీ;
	కొరకు (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
b16tod(స్థిరరాశి అక్షరం v)
{
	ఒకవేళ (v >= '0' && v <= '9')
		తిరిగి v - '0';
	ఒకవేళ (v >= 'a' && v <= 'f')
		తిరిగి 10 + v - 'a';
	ఒకవేళ (v >= 'A' && v <= 'F')
		తిరిగి 10 + v - 'A';
	తిరిగి -1;
}

నిర్మాణం sshbuf *
sshbuf_b16tod(స్థిరరాశి అక్షరం *b16)
{
	నిర్మాణం sshbuf *ret;
	కొలత_t o;
	పూర్ణాంకం r, v1, v2;

	ఒకవేళ ((ret = sshbuf_new()) == ఖాళీ)
		తిరిగి ఖాళీ;
	కొరకు (o = 0; b16[o] != '\0'; o += 2) {
		ఒకవేళ ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			తిరిగి ఖాళీ;
		}
		ఒకవేళ ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			తిరిగి ఖాళీ;
		}
	}
	/* success */
	తిరిగి ret;
}

పూర్ణాంకం
sshbuf_dtob64(స్థిరరాశి నిర్మాణం sshbuf *d, నిర్మాణం sshbuf *b64, పూర్ణాంకం wrap)
{
	కొలత_t i, slen = 0;
	అక్షరం *s = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ (d == ఖాళీ || b64 == ఖాళీ || sshbuf_len(d) >= SIZE_MAX / 2)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (sshbuf_len(d) == 0)
		తిరిగి 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	ఒకవేళ ((s = జ్ఞాపకం_ఇవ్వు(slen)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_అంతర్గత_ERROR;
		వెళ్ళు fail;
	}
	ఒకవేళ (wrap) {
		కొరకు (i = 0; s[i] != '\0'; i++) {
			ఒకవేళ ((r = sshbuf_put_u8(b64, s[i])) != 0)
				వెళ్ళు fail;
			ఒకవేళ (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				వెళ్ళు fail;
		}
		ఒకవేళ ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			వెళ్ళు fail;
	} లేకపోతే {
		ఒకవేళ ((r = sshbuf_put(b64, s, అక్షరశ్రేణి_పొడవు(s))) != 0)
			వెళ్ళు fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	తిరిగి r;
}

అక్షరం *
sshbuf_dtob64_string(స్థిరరాశి నిర్మాణం sshbuf *buf, పూర్ణాంకం wrap)
{
	నిర్మాణం sshbuf *tmp;
	అక్షరం *ret;

	ఒకవేళ ((tmp = sshbuf_new()) == ఖాళీ)
		తిరిగి ఖాళీ;
	ఒకవేళ (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		తిరిగి ఖాళీ;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	తిరిగి ret;
}

పూర్ణాంకం
sshbuf_b64tod(నిర్మాణం sshbuf *buf, స్థిరరాశి అక్షరం *b64)
{
	కొలత_t plen = అక్షరశ్రేణి_పొడవు(b64);
	పూర్ణాంకం nlen, r;
	u_char *p;

	ఒకవేళ (plen == 0)
		తిరిగి 0;
	ఒకవేళ ((p = జ్ఞాపకం_ఇవ్వు(plen)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		తిరిగి SSH_ERR_INVALID_FORMAT;
	}
	ఒకవేళ ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		తిరిగి r;
	}
	freezero(p, plen);
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_dtourlb64(స్థిరరాశి నిర్మాణం sshbuf *d, నిర్మాణం sshbuf *b64, పూర్ణాంకం wrap)
{
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	u_char *p;
	నిర్మాణం sshbuf *b = ఖాళీ;
	కొలత_t i, l;

	ఒకవేళ (sshbuf_len(d) == 0)
		తిరిగి 0;

	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	ఒకవేళ ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		వెళ్ళు బహిర్గతం;
	/* remove padding from end of encoded string*/
	కొరకు (;;) {
		l = sshbuf_len(b);
		ఒకవేళ (l <= 1 || sshbuf_ptr(b) == ఖాళీ) {
			r = SSH_ERR_అంతర్గత_ERROR;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (sshbuf_ptr(b)[l - 1] != '=')
			ఆపు;
		ఒకవేళ ((r = sshbuf_consume_చివర(b, 1)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	ఒకవేళ ((p = sshbuf_mutable_ptr(b)) == ఖాళీ) {
		r = SSH_ERR_అంతర్గత_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	కొరకు (i = 0; i < l; i++) {
		ఒకవేళ (p[i] == '+')
			p[i] = '-';
		లేకపోతే ఒకవేళ (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 బహిర్గతం:
	sshbuf_free(b);
	తిరిగి r;
}

అక్షరం *
sshbuf_dup_string(నిర్మాణం sshbuf *buf)
{
	స్థిరరాశి u_char *p = ఖాళీ, *s = sshbuf_ptr(buf);
	కొలత_t l = sshbuf_len(buf);
	అక్షరం *r;

	ఒకవేళ (s == ఖాళీ || l >= SIZE_MAX)
		తిరిగి ఖాళీ;
	/* accept a nul only as the last character in the buffer */
	ఒకవేళ (l > 0 && (p = memchr(s, '\0', l)) != ఖాళీ) {
		ఒకవేళ (p != s + l - 1)
			తిరిగి ఖాళీ;
		l--; /* the nul is put back below */
	}
	ఒకవేళ ((r = జ్ఞాపకం_ఇవ్వు(l + 1)) == ఖాళీ)
		తిరిగి ఖాళీ;
	ఒకవేళ (l > 0)
		జ్ఞాపకం_నకలు(r, s, l);
	r[l] = '\0';
	తిరిగి r;
}

పూర్ణాంకం
sshbuf_cmp(స్థిరరాశి నిర్మాణం sshbuf *b, కొలత_t స్థానభ్రంశం,
    స్థిరరాశి శూన్య *s, కొలత_t len)
{
	ఒకవేళ (sshbuf_ptr(b) == ఖాళీ)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	ఒకవేళ (స్థానభ్రంశం > SSHBUF_కొలత_MAX || len > SSHBUF_కొలత_MAX || len == 0)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (స్థానభ్రంశం + len > sshbuf_len(b))
		తిరిగి SSH_ERR_సందేశం_INCOMPLETE;
	ఒకవేళ (timingsafe_bcmp(sshbuf_ptr(b) + స్థానభ్రంశం, s, len) != 0)
		తిరిగి SSH_ERR_INVALID_FORMAT;
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_equals(స్థిరరాశి నిర్మాణం sshbuf *a, స్థిరరాశి నిర్మాణం sshbuf *b)
{
	ఒకవేళ (sshbuf_ptr(a) == ఖాళీ || sshbuf_ptr(b) == ఖాళీ)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	ఒకవేళ (sshbuf_len(a) != sshbuf_len(b))
		తిరిగి SSH_ERR_సందేశం_INCOMPLETE;
	ఒకవేళ (sshbuf_len(a) == 0)
		తిరిగి 0;
	ఒకవేళ (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		తిరిగి SSH_ERR_INVALID_FORMAT;
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_కనుగొను(స్థిరరాశి నిర్మాణం sshbuf *b, కొలత_t ప్రారంభం_స్థానభ్రంశం,
    స్థిరరాశి శూన్య *s, కొలత_t len, కొలత_t *offsetp)
{
	శూన్య *p;

	ఒకవేళ (offsetp != ఖాళీ)
		*offsetp = 0;
	ఒకవేళ (sshbuf_ptr(b) == ఖాళీ)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	ఒకవేళ (ప్రారంభం_స్థానభ్రంశం > SSHBUF_కొలత_MAX || len > SSHBUF_కొలత_MAX || len == 0)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (ప్రారంభం_స్థానభ్రంశం > sshbuf_len(b) || ప్రారంభం_స్థానభ్రంశం + len > sshbuf_len(b))
		తిరిగి SSH_ERR_సందేశం_INCOMPLETE;
	ఒకవేళ ((p = memmem(sshbuf_ptr(b) + ప్రారంభం_స్థానభ్రంశం,
	    sshbuf_len(b) - ప్రారంభం_స్థానభ్రంశం, s, len)) == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_FORMAT;
	ఒకవేళ (offsetp != ఖాళీ)
		*offsetp = (స్థిరరాశి u_char *)p - sshbuf_ptr(b);
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_read(పూర్ణాంకం fd, నిర్మాణం sshbuf *buf, కొలత_t maxlen, కొలత_t *rlen)
{
	పూర్ణాంకం r, oerrno;
	కొలత_t adjust;
	ssize_t rr;
	u_char *d;

	ఒకవేళ (rlen != ఖాళీ)
		*rlen = 0;
	ఒకవేళ ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		తిరిగి r;
	rr = పఠ(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	ఒకవేళ ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		ఒకవేళ ((r = sshbuf_consume_చివర(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			memset(d + rr, '\0', adjust);
			తిరిగి SSH_ERR_అంతర్గత_ERROR; /* shouldn't happen */
		}
	}
	ఒకవేళ (rr < 0) {
		errno = oerrno;
		తిరిగి SSH_ERR_SYSTEM_ERROR;
	} లేకపోతే ఒకవేళ (rr == 0) {
		errno = EPIPE;
		తిరిగి SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	ఒకవేళ (rlen != ఖాళీ)
		*rlen = (కొలత_t)rr;
	తిరిగి 0;
}
