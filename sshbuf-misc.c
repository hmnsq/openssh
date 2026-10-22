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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <resolv.h>
#अन्तर्भाव <ctype.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "ssherr.h"
#परिभाषय SSHBUF_आन्तरिकम्
#अन्तर्भाव "sshbuf.h"

शून्य
sshbuf_dump_दत्त(ध्रुव शून्य *s, आकार_t len, FILE *f)
{
	आकार_t i, j;
	ध्रुव u_char *p = (ध्रुव u_char *)s;

	प्रति (i = 0; i < len; i += 16) {
		fprintf(f, "%.4zu: ", i);
		प्रति (j = i; j < i + 16; j++) {
			यदि (j < len)
				fprintf(f, "%02x ", p[j]);
			अन्यथा
				fprintf(f, "   ");
		}
		fprintf(f, " ");
		प्रति (j = i; j < i + 16; j++) {
			यदि (j < len) {
				यदि  (isascii(p[j]) && isprint(p[j]))
					fprintf(f, "%c", p[j]);
				अन्यथा
					fprintf(f, ".");
			}
		}
		fprintf(f, "\n");
	}
}

शून्य
sshbuf_dump(ध्रुव संरचना sshbuf *buf, FILE *f)
{
	fprintf(f, "buffer len = %zu\n", sshbuf_len(buf));
	sshbuf_dump_दत्त(sshbuf_ptr(buf), sshbuf_len(buf), f);
}

वर्ण *
sshbuf_dtob16(ध्रुव संरचना sshbuf *buf)
{
	आकार_t i, j, len = sshbuf_len(buf);
	ध्रुव u_char *p = sshbuf_ptr(buf);
	वर्ण *ret;
	ध्रुव वर्ण hex[] = "0123456789abcdef";

	यदि (len == 0)
		प्रत्यागम strdup("");
	यदि (SIZE_MAX / 2 <= len || (ret = स्मृतिं_देहि(len * 2 + 1)) == रिक्त)
		प्रत्यागम रिक्त;
	प्रति (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
b16tod(ध्रुव वर्ण v)
{
	यदि (v >= '0' && v <= '9')
		प्रत्यागम v - '0';
	यदि (v >= 'a' && v <= 'f')
		प्रत्यागम 10 + v - 'a';
	यदि (v >= 'A' && v <= 'F')
		प्रत्यागम 10 + v - 'A';
	प्रत्यागम -1;
}

संरचना sshbuf *
sshbuf_b16tod(ध्रुव वर्ण *b16)
{
	संरचना sshbuf *ret;
	आकार_t o;
	पूर्णाङ्क r, v1, v2;

	यदि ((ret = sshbuf_new()) == रिक्त)
		प्रत्यागम रिक्त;
	प्रति (o = 0; b16[o] != '\0'; o += 2) {
		यदि ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			प्रत्यागम रिक्त;
		}
		यदि ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			प्रत्यागम रिक्त;
		}
	}
	/* success */
	प्रत्यागम ret;
}

पूर्णाङ्क
sshbuf_dtob64(ध्रुव संरचना sshbuf *d, संरचना sshbuf *b64, पूर्णाङ्क wrap)
{
	आकार_t i, slen = 0;
	वर्ण *s = रिक्त;
	पूर्णाङ्क r;

	यदि (d == रिक्त || b64 == रिक्त || sshbuf_len(d) >= SIZE_MAX / 2)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	यदि (sshbuf_len(d) == 0)
		प्रत्यागम 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	यदि ((s = स्मृतिं_देहि(slen)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_आन्तरिकम्_ERROR;
		गच्छ fail;
	}
	यदि (wrap) {
		प्रति (i = 0; s[i] != '\0'; i++) {
			यदि ((r = sshbuf_put_u8(b64, s[i])) != 0)
				गच्छ fail;
			यदि (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				गच्छ fail;
		}
		यदि ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			गच्छ fail;
	} अन्यथा {
		यदि ((r = sshbuf_put(b64, s, वाक्यदैर्घ्यम्(s))) != 0)
			गच्छ fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	प्रत्यागम r;
}

वर्ण *
sshbuf_dtob64_string(ध्रुव संरचना sshbuf *buf, पूर्णाङ्क wrap)
{
	संरचना sshbuf *tmp;
	वर्ण *ret;

	यदि ((tmp = sshbuf_new()) == रिक्त)
		प्रत्यागम रिक्त;
	यदि (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		प्रत्यागम रिक्त;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	प्रत्यागम ret;
}

पूर्णाङ्क
sshbuf_b64tod(संरचना sshbuf *buf, ध्रुव वर्ण *b64)
{
	आकार_t plen = वाक्यदैर्घ्यम्(b64);
	पूर्णाङ्क nlen, r;
	u_char *p;

	यदि (plen == 0)
		प्रत्यागम 0;
	यदि ((p = स्मृतिं_देहि(plen)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	}
	यदि ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		प्रत्यागम r;
	}
	freezero(p, plen);
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_dtourlb64(ध्रुव संरचना sshbuf *d, संरचना sshbuf *b64, पूर्णाङ्क wrap)
{
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;
	u_char *p;
	संरचना sshbuf *b = रिक्त;
	आकार_t i, l;

	यदि (sshbuf_len(d) == 0)
		प्रत्यागम 0;

	यदि ((b = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	यदि ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		गच्छ बहिर्गमनम्;
	/* remove padding from end of encoded string*/
	प्रति (;;) {
		l = sshbuf_len(b);
		यदि (l <= 1 || sshbuf_ptr(b) == रिक्त) {
			r = SSH_ERR_आन्तरिकम्_ERROR;
			गच्छ बहिर्गमनम्;
		}
		यदि (sshbuf_ptr(b)[l - 1] != '=')
			भङ्ग;
		यदि ((r = sshbuf_consume_अन्तः(b, 1)) != 0)
			गच्छ बहिर्गमनम्;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	यदि ((p = sshbuf_mutable_ptr(b)) == रिक्त) {
		r = SSH_ERR_आन्तरिकम्_ERROR;
		गच्छ बहिर्गमनम्;
	}
	प्रति (i = 0; i < l; i++) {
		यदि (p[i] == '+')
			p[i] = '-';
		अन्यथा यदि (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 बहिर्गमनम्:
	sshbuf_free(b);
	प्रत्यागम r;
}

वर्ण *
sshbuf_dup_string(संरचना sshbuf *buf)
{
	ध्रुव u_char *p = रिक्त, *s = sshbuf_ptr(buf);
	आकार_t l = sshbuf_len(buf);
	वर्ण *r;

	यदि (s == रिक्त || l >= SIZE_MAX)
		प्रत्यागम रिक्त;
	/* accept a nul only as the last character in the buffer */
	यदि (l > 0 && (p = memchr(s, '\0', l)) != रिक्त) {
		यदि (p != s + l - 1)
			प्रत्यागम रिक्त;
		l--; /* the nul is put back below */
	}
	यदि ((r = स्मृतिं_देहि(l + 1)) == रिक्त)
		प्रत्यागम रिक्त;
	यदि (l > 0)
		स्मृतिं_प्रतिलिख(r, s, l);
	r[l] = '\0';
	प्रत्यागम r;
}

पूर्णाङ्क
sshbuf_cmp(ध्रुव संरचना sshbuf *b, आकार_t विस्थापनम्,
    ध्रुव शून्य *s, आकार_t len)
{
	यदि (sshbuf_ptr(b) == रिक्त)
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	यदि (विस्थापनम् > SSHBUF_आकार_MAX || len > SSHBUF_आकार_MAX || len == 0)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	यदि (विस्थापनम् + len > sshbuf_len(b))
		प्रत्यागम SSH_ERR_सन्देशः_INCOMPLETE;
	यदि (timingsafe_bcmp(sshbuf_ptr(b) + विस्थापनम्, s, len) != 0)
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_equals(ध्रुव संरचना sshbuf *a, ध्रुव संरचना sshbuf *b)
{
	यदि (sshbuf_ptr(a) == रिक्त || sshbuf_ptr(b) == रिक्त)
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	यदि (sshbuf_len(a) != sshbuf_len(b))
		प्रत्यागम SSH_ERR_सन्देशः_INCOMPLETE;
	यदि (sshbuf_len(a) == 0)
		प्रत्यागम 0;
	यदि (memcmp(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_find(ध्रुव संरचना sshbuf *b, आकार_t start_विस्थापनम्,
    ध्रुव शून्य *s, आकार_t len, आकार_t *offsetp)
{
	शून्य *p;

	यदि (offsetp != रिक्त)
		*offsetp = 0;
	यदि (sshbuf_ptr(b) == रिक्त)
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	यदि (start_विस्थापनम् > SSHBUF_आकार_MAX || len > SSHBUF_आकार_MAX || len == 0)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	यदि (start_विस्थापनम् > sshbuf_len(b) || start_विस्थापनम् + len > sshbuf_len(b))
		प्रत्यागम SSH_ERR_सन्देशः_INCOMPLETE;
	यदि ((p = memmem(sshbuf_ptr(b) + start_विस्थापनम्,
	    sshbuf_len(b) - start_विस्थापनम्, s, len)) == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	यदि (offsetp != रिक्त)
		*offsetp = (ध्रुव u_char *)p - sshbuf_ptr(b);
	प्रत्यागम 0;
}

पूर्णाङ्क
sshbuf_read(पूर्णाङ्क fd, संरचना sshbuf *buf, आकार_t maxlen, आकार_t *rlen)
{
	पूर्णाङ्क r, oerrno;
	आकार_t adjust;
	ssize_t rr;
	u_char *d;

	यदि (rlen != रिक्त)
		*rlen = 0;
	यदि ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		प्रत्यागम r;
	rr = पठ(fd, d, maxlen);
	oerrno = errno;

	/* Adjust the buffer to include only what was actually read */
	यदि ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		यदि ((r = sshbuf_consume_अन्तः(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			स्मृतिं_पूरय(d + rr, '\0', adjust);
			प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR; /* shouldn't happen */
		}
	}
	यदि (rr < 0) {
		errno = oerrno;
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	} अन्यथा यदि (rr == 0) {
		errno = EPIPE;
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	यदि (rlen != रिक्त)
		*rlen = (आकार_t)rr;
	प्रत्यागम 0;
}
