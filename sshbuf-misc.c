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
sshbuf_dump_data(स्थिरांक शून्य *s, माप_प्रकार len, खाता *f)
{
	माप_प्रकार i, j;
	स्थिरांक u_char *p = (स्थिरांक u_char *)s;

	साठी (i = 0; i < len; i += 16) {
		ख_लिखो(f, "%.4zu: ", i);
		साठी (j = i; j < i + 16; j++) {
			जर (j < len)
				ख_लिखो(f, "%02x ", p[j]);
			अन्यथा
				ख_लिखो(f, "   ");
		}
		ख_लिखो(f, " ");
		साठी (j = i; j < i + 16; j++) {
			जर (j < len) {
				जर  (isascii(p[j]) && है_छाप(p[j]))
					ख_लिखो(f, "%c", p[j]);
				अन्यथा
					ख_लिखो(f, ".");
			}
		}
		ख_लिखो(f, "\n");
	}
}

शून्य
sshbuf_dump(स्थिरांक संरचना sshbuf *buf, खाता *f)
{
	ख_लिखो(f, "buffer len = %zu\n", sshbuf_len(buf));
	sshbuf_dump_data(sshbuf_ptr(buf), sshbuf_len(buf), f);
}

अक्षर *
sshbuf_dtob16(स्थिरांक संरचना sshbuf *buf)
{
	माप_प्रकार i, j, len = sshbuf_len(buf);
	स्थिरांक u_char *p = sshbuf_ptr(buf);
	अक्षर *ret;
	स्थिरांक अक्षर hex[] = "0123456789abcdef";

	जर (len == 0)
		परत strdup("");
	जर (SIZE_MAX / 2 <= len || (ret = दो_स्मृति(len * 2 + 1)) == रिक्त)
		परत रिक्त;
	साठी (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	परत ret;
}

स्थिर पूर्णांक
b16tod(स्थिरांक अक्षर v)
{
	जर (v >= '0' && v <= '9')
		परत v - '0';
	जर (v >= 'a' && v <= 'f')
		परत 10 + v - 'a';
	जर (v >= 'A' && v <= 'F')
		परत 10 + v - 'A';
	परत -1;
}

संरचना sshbuf *
sshbuf_b16tod(स्थिरांक अक्षर *b16)
{
	संरचना sshbuf *ret;
	माप_प्रकार o;
	पूर्णांक r, v1, v2;

	जर ((ret = sshbuf_new()) == रिक्त)
		परत रिक्त;
	साठी (o = 0; b16[o] != '\0'; o += 2) {
		जर ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			परत रिक्त;
		}
		जर ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			परत रिक्त;
		}
	}
	/* success */
	परत ret;
}

पूर्णांक
sshbuf_dtob64(स्थिरांक संरचना sshbuf *d, संरचना sshbuf *b64, पूर्णांक wrap)
{
	माप_प्रकार i, slen = 0;
	अक्षर *s = रिक्त;
	पूर्णांक r;

	जर (d == रिक्त || b64 == रिक्त || sshbuf_len(d) >= SIZE_MAX / 2)
		परत SSH_ERR_INVALID_ARGUMENT;
	जर (sshbuf_len(d) == 0)
		परत 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	जर ((s = दो_स्मृति(slen)) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_INTERNAL_ERROR;
		जा fail;
	}
	जर (wrap) {
		साठी (i = 0; s[i] != '\0'; i++) {
			जर ((r = sshbuf_put_u8(b64, s[i])) != 0)
				जा fail;
			जर (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				जा fail;
		}
		जर ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			जा fail;
	} अन्यथा {
		जर ((r = sshbuf_put(b64, s, म_माप(s))) != 0)
			जा fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	परत r;
}

अक्षर *
sshbuf_dtob64_string(स्थिरांक संरचना sshbuf *buf, पूर्णांक wrap)
{
	संरचना sshbuf *tmp;
	अक्षर *ret;

	जर ((tmp = sshbuf_new()) == रिक्त)
		परत रिक्त;
	जर (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		परत रिक्त;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	परत ret;
}

पूर्णांक
sshbuf_b64tod(संरचना sshbuf *buf, स्थिरांक अक्षर *b64)
{
	माप_प्रकार plen = म_माप(b64);
	पूर्णांक nlen, r;
	u_char *p;

	जर (plen == 0)
		परत 0;
	जर ((p = दो_स्मृति(plen)) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		परत SSH_ERR_INVALID_FORMAT;
	}
	जर ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		परत r;
	}
	freezero(p, plen);
	परत 0;
}

पूर्णांक
sshbuf_dtourlb64(स्थिरांक संरचना sshbuf *d, संरचना sshbuf *b64, पूर्णांक wrap)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	u_char *p;
	संरचना sshbuf *b = रिक्त;
	माप_प्रकार i, l;

	जर (sshbuf_len(d) == 0)
		परत 0;

	जर ((b = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	जर ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		जा out;
	/* remove padding from end of encoded string*/
	साठी (;;) {
		l = sshbuf_len(b);
		जर (l <= 1 || sshbuf_ptr(b) == रिक्त) {
			r = SSH_ERR_INTERNAL_ERROR;
			जा out;
		}
		जर (sshbuf_ptr(b)[l - 1] != '=')
			थांबा;
		जर ((r = sshbuf_consume_end(b, 1)) != 0)
			जा out;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	जर ((p = sshbuf_mutable_ptr(b)) == रिक्त) {
		r = SSH_ERR_INTERNAL_ERROR;
		जा out;
	}
	साठी (i = 0; i < l; i++) {
		जर (p[i] == '+')
			p[i] = '-';
		अन्यथा जर (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 out:
	sshbuf_free(b);
	परत r;
}

अक्षर *
sshbuf_dup_string(संरचना sshbuf *buf)
{
	स्थिरांक u_char *p = रिक्त, *s = sshbuf_ptr(buf);
	माप_प्रकार l = sshbuf_len(buf);
	अक्षर *r;

	जर (s == रिक्त || l >= SIZE_MAX)
		परत रिक्त;
	/* accept a nul only as the last character in the buffer */
	जर (l > 0 && (p = स_प्रथम(s, '\0', l)) != रिक्त) {
		जर (p != s + l - 1)
			परत रिक्त;
		l--; /* the nul is put back below */
	}
	जर ((r = दो_स्मृति(l + 1)) == रिक्त)
		परत रिक्त;
	जर (l > 0)
		स_नकल(r, s, l);
	r[l] = '\0';
	परत r;
}

पूर्णांक
sshbuf_cmp(स्थिरांक संरचना sshbuf *b, माप_प्रकार offset,
    स्थिरांक शून्य *s, माप_प्रकार len)
{
	जर (sshbuf_ptr(b) == रिक्त)
		परत SSH_ERR_INTERNAL_ERROR;
	जर (offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		परत SSH_ERR_INVALID_ARGUMENT;
	जर (offset + len > sshbuf_len(b))
		परत SSH_ERR_MESSAGE_INCOMPLETE;
	जर (timingsafe_bcmp(sshbuf_ptr(b) + offset, s, len) != 0)
		परत SSH_ERR_INVALID_FORMAT;
	परत 0;
}

पूर्णांक
sshbuf_equals(स्थिरांक संरचना sshbuf *a, स्थिरांक संरचना sshbuf *b)
{
	जर (sshbuf_ptr(a) == रिक्त || sshbuf_ptr(b) == रिक्त)
		परत SSH_ERR_INTERNAL_ERROR;
	जर (sshbuf_len(a) != sshbuf_len(b))
		परत SSH_ERR_MESSAGE_INCOMPLETE;
	जर (sshbuf_len(a) == 0)
		परत 0;
	जर (स_भेद(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		परत SSH_ERR_INVALID_FORMAT;
	परत 0;
}

पूर्णांक
sshbuf_find(स्थिरांक संरचना sshbuf *b, माप_प्रकार start_offset,
    स्थिरांक शून्य *s, माप_प्रकार len, माप_प्रकार *offsetp)
{
	शून्य *p;

	जर (offsetp != रिक्त)
		*offsetp = 0;
	जर (sshbuf_ptr(b) == रिक्त)
		परत SSH_ERR_INTERNAL_ERROR;
	जर (start_offset > SSHBUF_SIZE_MAX || len > SSHBUF_SIZE_MAX || len == 0)
		परत SSH_ERR_INVALID_ARGUMENT;
	जर (start_offset > sshbuf_len(b) || start_offset + len > sshbuf_len(b))
		परत SSH_ERR_MESSAGE_INCOMPLETE;
	जर ((p = memmem(sshbuf_ptr(b) + start_offset,
	    sshbuf_len(b) - start_offset, s, len)) == रिक्त)
		परत SSH_ERR_INVALID_FORMAT;
	जर (offsetp != रिक्त)
		*offsetp = (स्थिरांक u_char *)p - sshbuf_ptr(b);
	परत 0;
}

पूर्णांक
sshbuf_read(पूर्णांक fd, संरचना sshbuf *buf, माप_प्रकार maxlen, माप_प्रकार *rlen)
{
	पूर्णांक r, oerrno;
	माप_प्रकार adjust;
	ssize_t rr;
	u_char *d;

	जर (rlen != रिक्त)
		*rlen = 0;
	जर ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		परत r;
	rr = पठ(fd, d, maxlen);
	oerrno = त्रुटि_सं;

	/* Adjust the buffer to include only what was actually read */
	जर ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		जर ((r = sshbuf_consume_end(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			स_रखो(d + rr, '\0', adjust);
			परत SSH_ERR_INTERNAL_ERROR; /* shouldn't happen */
		}
	}
	जर (rr < 0) {
		त्रुटि_सं = oerrno;
		परत SSH_ERR_SYSTEM_ERROR;
	} अन्यथा जर (rr == 0) {
		त्रुटि_सं = EPIPE;
		परत SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	जर (rlen != रिक्त)
		*rlen = (माप_प्रकार)rr;
	परत 0;
}
