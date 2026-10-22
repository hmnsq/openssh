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
#define SSHBUF_INTERNAL
#अन्तर्भाव "sshbuf.h"

शून्य
sshbuf_dump_data(अचर शून्य *s, माप_प्रकार len, खाता *f)
{
	माप_प्रकार i, j;
	अचर u_char *p = (अचर u_char *)s;

	लागि (i = 0; i < len; i += 16) {
		ख_लिखो(f, "%.4zu: ", i);
		लागि (j = i; j < i + 16; j++) {
			यदि (j < len)
				ख_लिखो(f, "%02x ", p[j]);
			अन्यथा
				ख_लिखो(f, "   ");
		}
		ख_लिखो(f, " ");
		लागि (j = i; j < i + 16; j++) {
			यदि (j < len) {
				यदि  (isascii(p[j]) && है_छाप(p[j]))
					ख_लिखो(f, "%c", p[j]);
				अन्यथा
					ख_लिखो(f, ".");
			}
		}
		ख_लिखो(f, "\n");
	}
}

शून्य
sshbuf_dump(अचर संरचना sshbuf *buf, खाता *f)
{
	ख_लिखो(f, "buffer len = %zu\n", sshbuf_len(buf));
	sshbuf_dump_data(sshbuf_ptr(buf), sshbuf_len(buf), f);
}

वर्ण *
sshbuf_dtob16(अचर संरचना sshbuf *buf)
{
	माप_प्रकार i, j, len = sshbuf_len(buf);
	अचर u_char *p = sshbuf_ptr(buf);
	वर्ण *ret;
	अचर वर्ण hex[] = "0123456789abcdef";

	यदि (len == 0)
		फर्काऊ strdup("");
	यदि (SIZE_MAX / 2 <= len || (ret = दो_स्मृति(len * 2 + 1)) == रिक्त)
		फर्काऊ रिक्त;
	लागि (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	फर्काऊ ret;
}

स्थिर पूर्णाङ्क
b16tod(अचर वर्ण v)
{
	यदि (v >= '0' && v <= '9')
		फर्काऊ v - '0';
	यदि (v >= 'a' && v <= 'f')
		फर्काऊ 10 + v - 'a';
	यदि (v >= 'A' && v <= 'F')
		फर्काऊ 10 + v - 'A';
	फर्काऊ -1;
}

संरचना sshbuf *
sshbuf_b16tod(अचर वर्ण *b16)
{
	संरचना sshbuf *ret;
	माप_प्रकार o;
	पूर्णाङ्क r, v1, v2;

	यदि ((ret = sshbuf_new()) == रिक्त)
		फर्काऊ रिक्त;
	लागि (o = 0; b16[o] != '\0'; o += 2) {
		यदि ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			फर्काऊ रिक्त;
		}
		यदि ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			फर्काऊ रिक्त;
		}
	}
	/* success */
	फर्काऊ ret;
}

पूर्णाङ्क
sshbuf_dtob64(अचर संरचना sshbuf *d, संरचना sshbuf *b64, पूर्णाङ्क wrap)
{
	माप_प्रकार i, slen = 0;
	वर्ण *s = रिक्त;
	पूर्णाङ्क r;

	यदि (d == रिक्त || b64 == रिक्त || sshbuf_len(d) >= SIZE_MAX / 2)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि (sshbuf_len(d) == 0)
		फर्काऊ 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	यदि ((s = दो_स्मृति(slen)) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	यदि (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_INTERNAL_ERROR;
		गच्छ fail;
	}
	यदि (wrap) {
		लागि (i = 0; s[i] != '\0'; i++) {
			यदि ((r = sshbuf_put_u8(b64, s[i])) != 0)
				गच्छ fail;
			यदि (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				गच्छ fail;
		}
		यदि ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			गच्छ fail;
	} अन्यथा {
		यदि ((r = sshbuf_put(b64, s, म_माप(s))) != 0)
			गच्छ fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	फर्काऊ r;
}

वर्ण *
sshbuf_dtob64_string(अचर संरचना sshbuf *buf, पूर्णाङ्क wrap)
{
	संरचना sshbuf *tmp;
	वर्ण *ret;

	यदि ((tmp = sshbuf_new()) == रिक्त)
		फर्काऊ रिक्त;
	यदि (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		फर्काऊ रिक्त;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	फर्काऊ ret;
}

पूर्णाङ्क
sshbuf_b64tod(संरचना sshbuf *buf, अचर वर्ण *b64)
{
	माप_प्रकार plen = म_माप(b64);
	पूर्णाङ्क nlen, r;
	u_char *p;

	यदि (plen == 0)
		फर्काऊ 0;
	यदि ((p = दो_स्मृति(plen)) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	यदि ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		फर्काऊ SSH_ERR_INVALID_FORMAT;
	}
	यदि ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		फर्काऊ r;
	}
	freezero(p, plen);
	फर्काऊ 0;
}

पूर्णाङ्क
sshbuf_dtourlb64(अचर संरचना sshbuf *d, संरचना sshbuf *b64, पूर्णाङ्क wrap)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	u_char *p;
	संरचना sshbuf *b = रिक्त;
	माप_प्रकार i, l;

	यदि (sshbuf_len(d) == 0)
		फर्काऊ 0;

	यदि ((b = sshbuf_new()) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	यदि ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		गच्छ out;
	/* remove padding from end of encoded string*/
	लागि (;;) {
		l = sshbuf_len(b);
		यदि (l <= 1 || sshbuf_ptr(b) == रिक्त) {
			r = SSH_ERR_INTERNAL_ERROR;
			गच्छ out;
		}
		यदि (sshbuf_ptr(b)[l - 1] != '=')
			रोक;
		यदि ((r = sshbuf_consume_end(b, 1)) != 0)
			गच्छ out;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	यदि ((p = sshbuf_mutable_ptr(b)) == रिक्त) {
		r = SSH_ERR_INTERNAL_ERROR;
		गच्छ out;
	}
	लागि (i = 0; i < l; i++) {
		यदि (p[i] == '+')
			p[i] = '-';
		अन्यथा यदि (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 out:
	sshbuf_free(b);
	फर्काऊ r;
}

वर्ण *
sshbuf_dup_string(संरचना sshbuf *buf)
{
	अचर u_char *p = रिक्त, *s = sshbuf_ptr(buf);
	माप_प्रकार l = sshbuf_len(buf);
	वर्ण *r;

	यदि (s == रिक्त || l >= SIZE_MAX)
		फर्काऊ रिक्त;
	/* accept a nul only as the last character in the buffer */
	यदि (l > 0 && (p = स_प्रथम(s, '\0', l)) != रिक्त) {
		यदि (p != s + l - 1)
			फर्काऊ रिक्त;
		l--; /* the nul is put back below */
	}
	यदि ((r = दो_स्मृति(l + 1)) == रिक्त)
		फर्काऊ रिक्त;
	यदि (l > 0)
		स_नकल(r, s, l);
	r[l] = '\0';
	फर्काऊ r;
}

पूर्णाङ्क
sshbuf_cmp(अचर संरचना sshbuf *b, माप_प्रकार offset,
    अचर शून्य *s, माप_प्रकार len)
{
	यदि (sshbuf_ptr(b) == रिक्त)
		फर्काऊ SSH_ERR_INTERNAL_ERROR;
	यदि (offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि (offset + len > sshbuf_len(b))
		फर्काऊ SSH_ERR_MESSAGE_INCOMPLETE;
	यदि (timingsafe_bcmp(sshbuf_ptr(b) + offset, s, len) != 0)
		फर्काऊ SSH_ERR_INVALID_FORMAT;
	फर्काऊ 0;
}

पूर्णाङ्क
sshbuf_equals(अचर संरचना sshbuf *a, अचर संरचना sshbuf *b)
{
	यदि (sshbuf_ptr(a) == रिक्त || sshbuf_ptr(b) == रिक्त)
		फर्काऊ SSH_ERR_INTERNAL_ERROR;
	यदि (sshbuf_len(a) != sshbuf_len(b))
		फर्काऊ SSH_ERR_MESSAGE_INCOMPLETE;
	यदि (sshbuf_len(a) == 0)
		फर्काऊ 0;
	यदि (स_भेद(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		फर्काऊ SSH_ERR_INVALID_FORMAT;
	फर्काऊ 0;
}

पूर्णाङ्क
sshbuf_find(अचर संरचना sshbuf *b, माप_प्रकार start_offset,
    अचर शून्य *s, माप_प्रकार len, माप_प्रकार *offsetp)
{
	शून्य *p;

	यदि (offsetp != रिक्त)
		*offsetp = 0;
	यदि (sshbuf_ptr(b) == रिक्त)
		फर्काऊ SSH_ERR_INTERNAL_ERROR;
	यदि (start_offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि (start_offset > sshbuf_len(b) || start_offset + len > sshbuf_len(b))
		फर्काऊ SSH_ERR_MESSAGE_INCOMPLETE;
	यदि ((p = memmem(sshbuf_ptr(b) + start_offset,
	    sshbuf_len(b) - start_offset, s, len)) == रिक्त)
		फर्काऊ SSH_ERR_INVALID_FORMAT;
	यदि (offsetp != रिक्त)
		*offsetp = (अचर u_char *)p - sshbuf_ptr(b);
	फर्काऊ 0;
}

पूर्णाङ्क
sshbuf_read(पूर्णाङ्क fd, संरचना sshbuf *buf, माप_प्रकार maxlen, माप_प्रकार *rlen)
{
	पूर्णाङ्क r, oerrno;
	माप_प्रकार adjust;
	ssize_t rr;
	u_char *d;

	यदि (rlen != रिक्त)
		*rlen = 0;
	यदि ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		फर्काऊ r;
	rr = पठ(fd, d, maxlen);
	oerrno = त्रुटि_सं;

	/* Adjust the buffer to include only what was actually read */
	यदि ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		यदि ((r = sshbuf_consume_end(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			स_रखो(d + rr, '\0', adjust);
			फर्काऊ SSH_ERR_INTERNAL_ERROR; /* shouldn't happen */
		}
	}
	यदि (rr < 0) {
		त्रुटि_सं = oerrno;
		फर्काऊ SSH_ERR_SYSTEM_ERROR;
	} अन्यथा यदि (rr == 0) {
		त्रुटि_सं = EPIPE;
		फर्काऊ SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	यदि (rlen != रिक्त)
		*rlen = (माप_प्रकार)rr;
	फर्काऊ 0;
}
