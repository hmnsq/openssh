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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/socket.h>
#समावेश <netinet/in.h>
#समावेश <errno.h>
#समावेश <stdlib.h>
#समावेश <stdint.h>
#समावेश <stdio.h>
#समावेश <limits.h>
#समावेश <string.h>
#समावेश <resolv.h>
#समावेश <ctype.h>
#समावेश <unistd.h>

#समावेश "ssherr.h"
#घोषणा SSHBUF_INTERNAL
#समावेश "sshbuf.h"

व्योम
sshbuf_dump_तथ्य(स्थिर व्योम *s, माप_प्रकार len, खाता *f)
{
	माप_प्रकार i, j;
	स्थिर u_char *p = (स्थिर u_char *)s;

	क्रम (i = 0; i < len; i += 16) {
		ख_लिखो(f, "%.4zu: ", i);
		क्रम (j = i; j < i + 16; j++) {
			अगर (j < len)
				ख_लिखो(f, "%02x ", p[j]);
			अन्यथा
				ख_लिखो(f, "   ");
		}
		ख_लिखो(f, " ");
		क्रम (j = i; j < i + 16; j++) {
			अगर (j < len) {
				अगर  (isascii(p[j]) && है_छाप(p[j]))
					ख_लिखो(f, "%c", p[j]);
				अन्यथा
					ख_लिखो(f, ".");
			}
		}
		ख_लिखो(f, "\n");
	}
}

व्योम
sshbuf_dump(स्थिर काष्ठा sshbuf *buf, खाता *f)
{
	ख_लिखो(f, "buffer len = %zu\n", sshbuf_len(buf));
	sshbuf_dump_तथ्य(sshbuf_ptr(buf), sshbuf_len(buf), f);
}

अक्षर *
sshbuf_dtob16(स्थिर काष्ठा sshbuf *buf)
{
	माप_प्रकार i, j, len = sshbuf_len(buf);
	स्थिर u_char *p = sshbuf_ptr(buf);
	अक्षर *ret;
	स्थिर अक्षर hex[] = "0123456789abcdef";

	अगर (len == 0)
		वापस strdup("");
	अगर (SIZE_MAX / 2 <= len || (ret = दो_स्मृति(len * 2 + 1)) == शून्य)
		वापस शून्य;
	क्रम (i = j = 0; i < len; i++) {
		ret[j++] = hex[(p[i] >> 4) & 0xf];
		ret[j++] = hex[p[i] & 0xf];
	}
	ret[j] = '\0';
	वापस ret;
}

अटल पूर्णांक
b16tod(स्थिर अक्षर v)
{
	अगर (v >= '0' && v <= '9')
		वापस v - '0';
	अगर (v >= 'a' && v <= 'f')
		वापस 10 + v - 'a';
	अगर (v >= 'A' && v <= 'F')
		वापस 10 + v - 'A';
	वापस -1;
}

काष्ठा sshbuf *
sshbuf_b16tod(स्थिर अक्षर *b16)
{
	काष्ठा sshbuf *ret;
	माप_प्रकार o;
	पूर्णांक r, v1, v2;

	अगर ((ret = sshbuf_new()) == शून्य)
		वापस शून्य;
	क्रम (o = 0; b16[o] != '\0'; o += 2) {
		अगर ((v1 = b16tod(b16[o])) == -1 ||
		    (v2 = b16tod(b16[o + 1])) == -1) {
			sshbuf_free(ret);
			वापस शून्य;
		}
		अगर ((r = sshbuf_put_u8(ret, (u_char)((v1 << 4) | v2))) != 0) {
			sshbuf_free(ret);
			वापस शून्य;
		}
	}
	/* success */
	वापस ret;
}

पूर्णांक
sshbuf_dtob64(स्थिर काष्ठा sshbuf *d, काष्ठा sshbuf *b64, पूर्णांक wrap)
{
	माप_प्रकार i, slen = 0;
	अक्षर *s = शून्य;
	पूर्णांक r;

	अगर (d == शून्य || b64 == शून्य || sshbuf_len(d) >= SIZE_MAX / 2)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (sshbuf_len(d) == 0)
		वापस 0;
	slen = ((sshbuf_len(d) + 2) / 3) * 4 + 1;
	अगर ((s = दो_स्मृति(slen)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर (b64_ntop(sshbuf_ptr(d), sshbuf_len(d), s, slen) == -1) {
		r = SSH_ERR_INTERNAL_ERROR;
		जाओ fail;
	}
	अगर (wrap) {
		क्रम (i = 0; s[i] != '\0'; i++) {
			अगर ((r = sshbuf_put_u8(b64, s[i])) != 0)
				जाओ fail;
			अगर (i % 70 == 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
				जाओ fail;
		}
		अगर ((i - 1) % 70 != 69 && (r = sshbuf_put_u8(b64, '\n')) != 0)
			जाओ fail;
	} अन्यथा {
		अगर ((r = sshbuf_put(b64, s, म_माप(s))) != 0)
			जाओ fail;
	}
	/* Success */
	r = 0;
 fail:
	freezero(s, slen);
	वापस r;
}

अक्षर *
sshbuf_dtob64_string(स्थिर काष्ठा sshbuf *buf, पूर्णांक wrap)
{
	काष्ठा sshbuf *tmp;
	अक्षर *ret;

	अगर ((tmp = sshbuf_new()) == शून्य)
		वापस शून्य;
	अगर (sshbuf_dtob64(buf, tmp, wrap) != 0) {
		sshbuf_free(tmp);
		वापस शून्य;
	}
	ret = sshbuf_dup_string(tmp);
	sshbuf_free(tmp);
	वापस ret;
}

पूर्णांक
sshbuf_b64tod(काष्ठा sshbuf *buf, स्थिर अक्षर *b64)
{
	माप_प्रकार plen = म_माप(b64);
	पूर्णांक nlen, r;
	u_char *p;

	अगर (plen == 0)
		वापस 0;
	अगर ((p = दो_स्मृति(plen)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((nlen = b64_pton(b64, p, plen)) < 0) {
		freezero(p, plen);
		वापस SSH_ERR_INVALID_FORMAT;
	}
	अगर ((r = sshbuf_put(buf, p, nlen)) < 0) {
		freezero(p, plen);
		वापस r;
	}
	freezero(p, plen);
	वापस 0;
}

पूर्णांक
sshbuf_dtourlb64(स्थिर काष्ठा sshbuf *d, काष्ठा sshbuf *b64, पूर्णांक wrap)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	u_char *p;
	काष्ठा sshbuf *b = शून्य;
	माप_प्रकार i, l;

	अगर (sshbuf_len(d) == 0)
		वापस 0;

	अगर ((b = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	/* Encode using regular base64; we'll transform it once done */
	अगर ((r = sshbuf_dtob64(d, b, wrap)) != 0)
		जाओ out;
	/* remove padding from end of encoded string*/
	क्रम (;;) {
		l = sshbuf_len(b);
		अगर (l <= 1 || sshbuf_ptr(b) == शून्य) {
			r = SSH_ERR_INTERNAL_ERROR;
			जाओ out;
		}
		अगर (sshbuf_ptr(b)[l - 1] != '=')
			अवरोध;
		अगर ((r = sshbuf_consume_end(b, 1)) != 0)
			जाओ out;
	}
	/* Replace characters with rfc4648 equivalents */
	l = sshbuf_len(b);
	अगर ((p = sshbuf_mutable_ptr(b)) == शून्य) {
		r = SSH_ERR_INTERNAL_ERROR;
		जाओ out;
	}
	क्रम (i = 0; i < l; i++) {
		अगर (p[i] == '+')
			p[i] = '-';
		अन्यथा अगर (p[i] == '/')
			p[i] = '_';
	}
	r = sshbuf_putb(b64, b);
 out:
	sshbuf_free(b);
	वापस r;
}

अक्षर *
sshbuf_dup_string(काष्ठा sshbuf *buf)
{
	स्थिर u_char *p = शून्य, *s = sshbuf_ptr(buf);
	माप_प्रकार l = sshbuf_len(buf);
	अक्षर *r;

	अगर (s == शून्य || l >= SIZE_MAX)
		वापस शून्य;
	/* accept a nul only as the last character in the buffer */
	अगर (l > 0 && (p = स_प्रथम(s, '\0', l)) != शून्य) {
		अगर (p != s + l - 1)
			वापस शून्य;
		l--; /* the nul is put back below */
	}
	अगर ((r = दो_स्मृति(l + 1)) == शून्य)
		वापस शून्य;
	अगर (l > 0)
		स_नकल(r, s, l);
	r[l] = '\0';
	वापस r;
}

पूर्णांक
sshbuf_cmp(स्थिर काष्ठा sshbuf *b, माप_प्रकार offset,
    स्थिर व्योम *s, माप_प्रकार len)
{
	अगर (sshbuf_ptr(b) == शून्य)
		वापस SSH_ERR_INTERNAL_ERROR;
	अगर (offset > SSHBUF_आकार_MAX || len > SSHBUF_आकार_MAX || len == 0)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (offset + len > sshbuf_len(b))
		वापस SSH_ERR_MESSAGE_INCOMPLETE;
	अगर (timingsafe_bcmp(sshbuf_ptr(b) + offset, s, len) != 0)
		वापस SSH_ERR_INVALID_FORMAT;
	वापस 0;
}

पूर्णांक
sshbuf_equals(स्थिर काष्ठा sshbuf *a, स्थिर काष्ठा sshbuf *b)
{
	अगर (sshbuf_ptr(a) == शून्य || sshbuf_ptr(b) == शून्य)
		वापस SSH_ERR_INTERNAL_ERROR;
	अगर (sshbuf_len(a) != sshbuf_len(b))
		वापस SSH_ERR_MESSAGE_INCOMPLETE;
	अगर (sshbuf_len(a) == 0)
		वापस 0;
	अगर (स_भेद(sshbuf_ptr(a), sshbuf_ptr(b), sshbuf_len(a)) != 0)
		वापस SSH_ERR_INVALID_FORMAT;
	वापस 0;
}

पूर्णांक
sshbuf_find(स्थिर काष्ठा sshbuf *b, माप_प्रकार start_offset,
    स्थिर व्योम *s, माप_प्रकार len, माप_प्रकार *offsetp)
{
	व्योम *p;

	अगर (offsetp != शून्य)
		*offsetp = 0;
	अगर (sshbuf_ptr(b) == शून्य)
		वापस SSH_ERR_INTERNAL_ERROR;
	अगर (start_offset > SSHBUF_आकार_MAX || len > SSHBUF_आकार_MAX || len == 0)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (start_offset > sshbuf_len(b) || start_offset + len > sshbuf_len(b))
		वापस SSH_ERR_MESSAGE_INCOMPLETE;
	अगर ((p = memmem(sshbuf_ptr(b) + start_offset,
	    sshbuf_len(b) - start_offset, s, len)) == शून्य)
		वापस SSH_ERR_INVALID_FORMAT;
	अगर (offsetp != शून्य)
		*offsetp = (स्थिर u_char *)p - sshbuf_ptr(b);
	वापस 0;
}

पूर्णांक
sshbuf_read(पूर्णांक fd, काष्ठा sshbuf *buf, माप_प्रकार maxlen, माप_प्रकार *rlen)
{
	पूर्णांक r, oerrno;
	माप_प्रकार adjust;
	ssize_t rr;
	u_char *d;

	अगर (rlen != शून्य)
		*rlen = 0;
	अगर ((r = sshbuf_reserve(buf, maxlen, &d)) != 0)
		वापस r;
	rr = पढ़ो(fd, d, maxlen);
	oerrno = त्रुटि_सं;

	/* Adjust the buffer to include only what was actually read */
	अगर ((adjust = maxlen - (rr > 0 ? rr : 0)) != 0) {
		अगर ((r = sshbuf_consume_end(buf, adjust)) != 0) {
			/* avoid returning uninitialised data to caller */
			स_रखो(d + rr, '\0', adjust);
			वापस SSH_ERR_INTERNAL_ERROR; /* shouldn't happen */
		}
	}
	अगर (rr < 0) {
		त्रुटि_सं = oerrno;
		वापस SSH_ERR_SYSTEM_ERROR;
	} अन्यथा अगर (rr == 0) {
		त्रुटि_सं = EPIPE;
		वापस SSH_ERR_SYSTEM_ERROR;
	}
	/* success */
	अगर (rlen != शून्य)
		*rlen = (माप_प्रकार)rr;
	वापस 0;
}
