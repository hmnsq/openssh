/*	$OpenBSD: sshbuf-getput-basic.c,v 1.15 2026/03/03 09:57:25 dtucker Exp $	*/
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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>

#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#define SSHBUF_INTERNAL
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_get(ସଂରଚନା sshbuf *buf, ଶୂନ୍ୟ *v, size_t len)
{
	ଅଚଳ u_char *p = sshbuf_ptr(buf);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_consume(buf, len)) < 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (v != ଖାଲି && len != 0)
		memcpy(v, p, len);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_get_u64(ସଂରଚନା sshbuf *buf, uint64_t *valp)
{
	ଅଚଳ u_char *p = sshbuf_ptr(buf);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_consume(buf, 8)) < 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (valp != ଖାଲି)
		*valp = PEEK_U64(p);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_get_u32(ସଂରଚନା sshbuf *buf, uint32_t *valp)
{
	ଅଚଳ u_char *p = sshbuf_ptr(buf);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_consume(buf, 4)) < 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (valp != ଖାଲି)
		*valp = PEEK_U32(p);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_get_u16(ସଂରଚନା sshbuf *buf, uint16_t *valp)
{
	ଅଚଳ u_char *p = sshbuf_ptr(buf);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_consume(buf, 2)) < 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (valp != ଖାଲି)
		*valp = PEEK_U16(p);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_get_u8(ସଂରଚନା sshbuf *buf, u_char *valp)
{
	ଅଚଳ u_char *p = sshbuf_ptr(buf);
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_consume(buf, 1)) < 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (valp != ଖାଲି)
		*valp = (uint8_t)*p;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check_offset(ଅଚଳ ସଂରଚନା sshbuf *buf, ପୂର୍ଣ୍ଣସଂଖ୍ୟା wr, size_t offset, size_t len)
{
	ଯଦି (sshbuf_ptr(buf) == ଖାଲି) /* calls sshbuf_check_sanity() */
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	ଯଦି (offset >= SIZE_MAX - len)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (offset + len > sshbuf_len(buf)) {
		ଫେରନ୍ତୁ wr ?
		    SSH_ERR_NO_BUFFER_SPACE : SSH_ERR_MESSAGE_INCOMPLETE;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check_roffset(ଅଚଳ ସଂରଚନା sshbuf *buf, size_t offset, size_t len,
    ଅଚଳ u_char **p)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	*p = ଖାଲି;
	ଯଦି ((r = check_offset(buf, 0, offset, len)) != 0)
		ଫେରନ୍ତୁ r;
	*p = sshbuf_ptr(buf) + offset;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_peek_u64(ଅଚଳ ସଂରଚନା sshbuf *buf, size_t offset, uint64_t *valp)
{
	ଅଚଳ u_char *p = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (valp != ଖାଲି)
		*valp = 0;
	ଯଦି ((r = check_roffset(buf, offset, 8, &p)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (valp != ଖାଲି)
		*valp = PEEK_U64(p);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_peek_u32(ଅଚଳ ସଂରଚନା sshbuf *buf, size_t offset, uint32_t *valp)
{
	ଅଚଳ u_char *p = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (valp != ଖାଲି)
		*valp = 0;
	ଯଦି ((r = check_roffset(buf, offset, 4, &p)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (valp != ଖାଲି)
		*valp = PEEK_U32(p);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_peek_u16(ଅଚଳ ସଂରଚନା sshbuf *buf, size_t offset, uint16_t *valp)
{
	ଅଚଳ u_char *p = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (valp != ଖାଲି)
		*valp = 0;
	ଯଦି ((r = check_roffset(buf, offset, 2, &p)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (valp != ଖାଲି)
		*valp = PEEK_U16(p);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_peek_u8(ଅଚଳ ସଂରଚନା sshbuf *buf, size_t offset, u_char *valp)
{
	ଅଚଳ u_char *p = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (valp != ଖାଲି)
		*valp = 0;
	ଯଦି ((r = check_roffset(buf, offset, 1, &p)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (valp != ଖାଲି)
		*valp = *p;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_get_string(ସଂରଚନା sshbuf *buf, u_char **valp, size_t *lenp)
{
	ଅଚଳ u_char *val;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (valp != ଖାଲି)
		*valp = ଖାଲି;
	ଯଦି (lenp != ଖାଲି)
		*lenp = 0;
	ଯଦି ((r = sshbuf_get_string_direct(buf, &val, &len)) < 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (valp != ଖାଲି) {
		ଯଦି ((*valp = malloc(len + 1)) == ଖାଲି) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
		}
		ଯଦି (len != 0)
			memcpy(*valp, val, len);
		(*valp)[len] = '\0';
	}
	ଯଦି (lenp != ଖାଲି)
		*lenp = len;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_get_string_direct(ସଂରଚନା sshbuf *buf, ଅଚଳ u_char **valp, size_t *lenp)
{
	size_t len;
	ଅଚଳ u_char *p;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (valp != ଖାଲି)
		*valp = ଖାଲି;
	ଯଦି (lenp != ଖାଲି)
		*lenp = 0;
	ଯଦି ((r = sshbuf_peek_string_direct(buf, &p, &len)) < 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (valp != ଖାଲି)
		*valp = p;
	ଯଦି (lenp != ଖାଲି)
		*lenp = len;
	ଯଦି (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_peek_string_direct(ଅଚଳ ସଂରଚନା sshbuf *buf, ଅଚଳ u_char **valp,
    size_t *lenp)
{
	uint32_t len;
	ଅଚଳ u_char *p = sshbuf_ptr(buf);

	ଯଦି (valp != ଖାଲି)
		*valp = ଖାଲି;
	ଯଦି (lenp != ଖାଲି)
		*lenp = 0;
	ଯଦି (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		ଫେରନ୍ତୁ SSH_ERR_MESSAGE_INCOMPLETE;
	}
	len = PEEK_U32(p);
	ଯଦି (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		ଫେରନ୍ତୁ SSH_ERR_STRING_TOO_LARGE;
	}
	ଯଦି (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		ଫେରନ୍ତୁ SSH_ERR_MESSAGE_INCOMPLETE;
	}
	ଯଦି (valp != ଖାଲି)
		*valp = p + 4;
	ଯଦି (lenp != ଖାଲି)
		*lenp = len;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_get_cstring(ସଂରଚନା sshbuf *buf, ଅକ୍ଷର **valp, size_t *lenp)
{
	size_t len;
	ଅଚଳ u_char *p, *z;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (valp != ଖାଲି)
		*valp = ଖାଲି;
	ଯଦି (lenp != ଖାଲି)
		*lenp = 0;
	ଯଦି ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		ଫେରନ୍ତୁ r;
	/* Allow a \0 only at the end of the string */
	ଯଦି (len > 0 &&
	    (z = memchr(p , '\0', len)) != ଖାଲି && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	}
	ଯଦି ((r = sshbuf_skip_string(buf)) != 0)
		ଫେରନ୍ତୁ -1;
	ଯଦି (valp != ଖାଲି) {
		ଯଦି ((*valp = malloc(len + 1)) == ଖାଲି) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
		}
		ଯଦି (len != 0)
			memcpy(*valp, p, len);
		(*valp)[len] = '\0';
	}
	ଯଦି (lenp != ଖାଲି)
		*lenp = (size_t)len;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_get_stringb(ସଂରଚନା sshbuf *buf, ସଂରଚନା sshbuf *v)
{
	uint32_t len;
	u_char *p;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	ଯଦି ((r = sshbuf_peek_string_direct(buf, ଖାଲି, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_put(ସଂରଚନା sshbuf *buf, ଅଚଳ ଶୂନ୍ୟ *v, size_t len)
{
	u_char *p;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_reserve(buf, len, &p)) < 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (len != 0)
		memcpy(p, v, len);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_putb(ସଂରଚନା sshbuf *buf, ଅଚଳ ସଂରଚନା sshbuf *v)
{
	ଯଦି (v == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_putf(ସଂରଚନା sshbuf *buf, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	va_list ap;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	va_start(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	va_end(ap);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_putfv(ସଂରଚନା sshbuf *buf, ଅଚଳ ଅକ୍ଷର *fmt, va_list ap)
{
	va_list ap2;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	ଯଦି ((len = vsnprintf(ଖାଲି, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	}
	ଯଦି (len == 0) {
		r = 0;
		ଯାଅ out; /* Nothing to do */
	}
	va_end(ap2);
	VA_COPY(ap2, ap);
	ଯଦି ((r = sshbuf_reserve(buf, (size_t)len + 1, &p)) < 0)
		ଯାଅ out;
	ଯଦି ((r = vsnprintf((ଅକ୍ଷର *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_INTERNAL_ERROR;
		ଯାଅ out; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	ଯଦି ((r = sshbuf_consume_end(buf, 1)) != 0)
		ଯାଅ out;
	r = 0;
 out:
	va_end(ap2);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_put_u64(ସଂରଚନା sshbuf *buf, uint64_t val)
{
	u_char *p;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		ଫେରନ୍ତୁ r;
	POKE_U64(p, val);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_put_u32(ସଂରଚନା sshbuf *buf, uint32_t val)
{
	u_char *p;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		ଫେରନ୍ତୁ r;
	POKE_U32(p, val);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_put_u16(ସଂରଚନା sshbuf *buf, uint16_t val)
{
	u_char *p;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		ଫେରନ୍ତୁ r;
	POKE_U16(p, val);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_put_u8(ସଂରଚନା sshbuf *buf, u_char val)
{
	u_char *p;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		ଫେରନ୍ତୁ r;
	p[0] = val;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check_woffset(ସଂରଚନା sshbuf *buf, size_t offset, size_t len, u_char **p)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	*p = ଖାଲି;
	ଯଦି ((r = check_offset(buf, 1, offset, len)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (sshbuf_mutable_ptr(buf) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_BUFFER_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + offset;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_poke_u64(ସଂରଚନା sshbuf *buf, size_t offset, uint64_t val)
{
	u_char *p = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = check_woffset(buf, offset, 8, &p)) != 0)
		ଫେରନ୍ତୁ r;
	POKE_U64(p, val);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_poke_u32(ସଂରଚନା sshbuf *buf, size_t offset, uint32_t val)
{
	u_char *p = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = check_woffset(buf, offset, 4, &p)) != 0)
		ଫେରନ୍ତୁ r;
	POKE_U32(p, val);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_poke_u16(ସଂରଚନା sshbuf *buf, size_t offset, uint16_t val)
{
	u_char *p = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = check_woffset(buf, offset, 2, &p)) != 0)
		ଫେରନ୍ତୁ r;
	POKE_U16(p, val);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_poke_u8(ସଂରଚନା sshbuf *buf, size_t offset, u_char val)
{
	u_char *p = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = check_woffset(buf, offset, 1, &p)) != 0)
		ଫେରନ୍ତୁ r;
	*p = val;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_poke(ସଂରଚନା sshbuf *buf, size_t offset, ଶୂନ୍ୟ *v, size_t len)
{
	u_char *p = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = check_woffset(buf, offset, len, &p)) != 0)
		ଫେରନ୍ତୁ r;
	memcpy(p, v, len);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_put_string(ସଂରଚନା sshbuf *buf, ଅଚଳ ଶୂନ୍ୟ *v, size_t len)
{
	u_char *d;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (len > SSHBUF_SIZE_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		ଫେରନ୍ତୁ SSH_ERR_NO_BUFFER_SPACE;
	}
	ଯଦି ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		ଫେରନ୍ତୁ r;
	POKE_U32(d, len);
	ଯଦି (len != 0)
		memcpy(d + 4, v, len);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_put_cstring(ସଂରଚନା sshbuf *buf, ଅଚଳ ଅକ୍ଷର *v)
{
	ଫେରନ୍ତୁ sshbuf_put_string(buf, v, v == ଖାଲି ? 0 : strlen(v));
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_put_stringb(ସଂରଚନା sshbuf *buf, ଅଚଳ ସଂରଚନା sshbuf *v)
{
	ଯଦି (v == ଖାଲି)
		ଫେରନ୍ତୁ sshbuf_put_string(buf, ଖାଲି, 0);

	ଫେରନ୍ତୁ sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_froms(ସଂରଚନା sshbuf *buf, ସଂରଚନା sshbuf **bufp)
{
	ଅଚଳ u_char *p;
	size_t len;
	ସଂରଚନା sshbuf *ret;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (buf == ଖାଲି || bufp == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	*bufp = ଖାଲି;
	ଯଦି ((r = sshbuf_peek_string_direct(buf, &p, &len)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((ret = sshbuf_from(p, len)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_set_parent(ret, buf)) != 0) {
		sshbuf_free(ret);
		ଫେରନ୍ତୁ r;
	}
	*bufp = ret;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_put_bignum2_bytes(ସଂରଚନା sshbuf *buf, ଅଚଳ ଶୂନ୍ୟ *v, size_t len)
{
	u_char *d;
	ଅଚଳ u_char *s = (ଅଚଳ u_char *)v;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, prepend;

	ଯଦି (len > SSHBUF_SIZE_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		ଫେରନ୍ତୁ SSH_ERR_NO_BUFFER_SPACE;
	}
	/* Skip leading zero bytes */
	ପାଇଁ (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	ଯଦି ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		ଫେରନ୍ତୁ r;
	POKE_U32(d, len + prepend);
	ଯଦି (prepend)
		d[4] = 0;
	ଯଦି (len != 0)
		memcpy(d + 4 + prepend, s, len);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_get_bignum2_bytes_direct(ସଂରଚନା sshbuf *buf,
    ଅଚଳ u_char **valp, size_t *lenp)
{
	ଅଚଳ u_char *d;
	size_t len, olen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_peek_string_direct(buf, &d, &olen)) < 0)
		ଫେରନ୍ତୁ r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	ଯଦି ((len != 0 && (*d & 0x80) != 0))
		ଫେରନ୍ତୁ SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	ଯଦି (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		ଫେରନ୍ତୁ SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	ଯେତେବେଳେ (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	ଯଦି (valp != ଖାଲି)
		*valp = d;
	ଯଦି (lenp != ଖାଲି)
		*lenp = len;
	ଯଦି (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_get_nulterminated_string(ସଂରଚନା sshbuf *buf, size_t maxlen,
    ଅକ୍ଷର **valp, size_t *lenp)
{
	ଅଚଳ u_char zero = 0;
	ଅକ୍ଷର *val = ଖାଲି;
	size_t len = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (valp != ଖାଲି)
		*valp = ଖାଲି;
	ଯଦି (lenp != ଖାଲି)
		*lenp = 0;
	ଯଦି ((r = sshbuf_find(buf, 0, &zero, ଆକାର(zero), &len)) != 0) {
		ଯଦି (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			ଫେରନ୍ତୁ SSH_ERR_MESSAGE_INCOMPLETE;
		ଫେରନ୍ତୁ r;
	}
	ଯଦି (len > maxlen)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	ଯଦି ((val = strdup(sshbuf_ptr(buf))) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_consume(buf, len + 1)) != 0)
		ଯାଅ out;
	/* success */
	r = 0;
	ଯଦି (valp != ଖାଲି) {
		*valp = val;
		val = ଖାଲି;
	}
	ଯଦି (lenp != ଖାଲି)
		*lenp = len;
 out:
	ମୁକ୍ତ(val);
	ଫେରନ୍ତୁ r;
}
