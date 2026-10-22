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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdint.h>

#అన్తర్భావ "ssherr.h"
#నిర్వచించు SSHBUF_అంతర్గత
#అన్తర్భావ "sshbuf.h"

పూర్ణాంకం
sshbuf_get(నిర్మాణం sshbuf *buf, శూన్య *v, కొలత_t len)
{
	స్థిరరాశి u_char *p = sshbuf_ptr(buf);
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_consume(buf, len)) < 0)
		తిరిగి r;
	ఒకవేళ (v != ఖాళీ && len != 0)
		జ్ఞాపకం_నకలు(v, p, len);
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_get_u64(నిర్మాణం sshbuf *buf, uint64_t *valp)
{
	స్థిరరాశి u_char *p = sshbuf_ptr(buf);
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_consume(buf, 8)) < 0)
		తిరిగి r;
	ఒకవేళ (valp != ఖాళీ)
		*valp = PEEK_U64(p);
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_get_u32(నిర్మాణం sshbuf *buf, uint32_t *valp)
{
	స్థిరరాశి u_char *p = sshbuf_ptr(buf);
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_consume(buf, 4)) < 0)
		తిరిగి r;
	ఒకవేళ (valp != ఖాళీ)
		*valp = PEEK_U32(p);
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_get_u16(నిర్మాణం sshbuf *buf, uint16_t *valp)
{
	స్థిరరాశి u_char *p = sshbuf_ptr(buf);
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_consume(buf, 2)) < 0)
		తిరిగి r;
	ఒకవేళ (valp != ఖాళీ)
		*valp = PEEK_U16(p);
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_get_u8(నిర్మాణం sshbuf *buf, u_char *valp)
{
	స్థిరరాశి u_char *p = sshbuf_ptr(buf);
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_consume(buf, 1)) < 0)
		తిరిగి r;
	ఒకవేళ (valp != ఖాళీ)
		*valp = (uint8_t)*p;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
check_స్థానభ్రంశం(స్థిరరాశి నిర్మాణం sshbuf *buf, పూర్ణాంకం wr, కొలత_t స్థానభ్రంశం, కొలత_t len)
{
	ఒకవేళ (sshbuf_ptr(buf) == ఖాళీ) /* calls sshbuf_check_sanity() */
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	ఒకవేళ (స్థానభ్రంశం >= SIZE_MAX - len)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (స్థానభ్రంశం + len > sshbuf_len(buf)) {
		తిరిగి wr ?
		    SSH_ERR_NO_బఫరు_SPACE : SSH_ERR_సందేశం_INCOMPLETE;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
check_roffset(స్థిరరాశి నిర్మాణం sshbuf *buf, కొలత_t స్థానభ్రంశం, కొలత_t len,
    స్థిరరాశి u_char **p)
{
	పూర్ణాంకం r;

	*p = ఖాళీ;
	ఒకవేళ ((r = check_స్థానభ్రంశం(buf, 0, స్థానభ్రంశం, len)) != 0)
		తిరిగి r;
	*p = sshbuf_ptr(buf) + స్థానభ్రంశం;
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_peek_u64(స్థిరరాశి నిర్మాణం sshbuf *buf, కొలత_t స్థానభ్రంశం, uint64_t *valp)
{
	స్థిరరాశి u_char *p = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ (valp != ఖాళీ)
		*valp = 0;
	ఒకవేళ ((r = check_roffset(buf, స్థానభ్రంశం, 8, &p)) != 0)
		తిరిగి r;
	ఒకవేళ (valp != ఖాళీ)
		*valp = PEEK_U64(p);
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_peek_u32(స్థిరరాశి నిర్మాణం sshbuf *buf, కొలత_t స్థానభ్రంశం, uint32_t *valp)
{
	స్థిరరాశి u_char *p = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ (valp != ఖాళీ)
		*valp = 0;
	ఒకవేళ ((r = check_roffset(buf, స్థానభ్రంశం, 4, &p)) != 0)
		తిరిగి r;
	ఒకవేళ (valp != ఖాళీ)
		*valp = PEEK_U32(p);
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_peek_u16(స్థిరరాశి నిర్మాణం sshbuf *buf, కొలత_t స్థానభ్రంశం, uint16_t *valp)
{
	స్థిరరాశి u_char *p = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ (valp != ఖాళీ)
		*valp = 0;
	ఒకవేళ ((r = check_roffset(buf, స్థానభ్రంశం, 2, &p)) != 0)
		తిరిగి r;
	ఒకవేళ (valp != ఖాళీ)
		*valp = PEEK_U16(p);
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_peek_u8(స్థిరరాశి నిర్మాణం sshbuf *buf, కొలత_t స్థానభ్రంశం, u_char *valp)
{
	స్థిరరాశి u_char *p = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ (valp != ఖాళీ)
		*valp = 0;
	ఒకవేళ ((r = check_roffset(buf, స్థానభ్రంశం, 1, &p)) != 0)
		తిరిగి r;
	ఒకవేళ (valp != ఖాళీ)
		*valp = *p;
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_get_string(నిర్మాణం sshbuf *buf, u_char **valp, కొలత_t *lenp)
{
	స్థిరరాశి u_char *val;
	కొలత_t len;
	పూర్ణాంకం r;

	ఒకవేళ (valp != ఖాళీ)
		*valp = ఖాళీ;
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = 0;
	ఒకవేళ ((r = sshbuf_get_string_ప్రత్యక్ష(buf, &val, &len)) < 0)
		తిరిగి r;
	ఒకవేళ (valp != ఖాళీ) {
		ఒకవేళ ((*valp = జ్ఞాపకం_ఇవ్వు(len + 1)) == ఖాళీ) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			తిరిగి SSH_ERR_ALLOC_FAIL;
		}
		ఒకవేళ (len != 0)
			జ్ఞాపకం_నకలు(*valp, val, len);
		(*valp)[len] = '\0';
	}
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = len;
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_get_string_ప్రత్యక్ష(నిర్మాణం sshbuf *buf, స్థిరరాశి u_char **valp, కొలత_t *lenp)
{
	కొలత_t len;
	స్థిరరాశి u_char *p;
	పూర్ణాంకం r;

	ఒకవేళ (valp != ఖాళీ)
		*valp = ఖాళీ;
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = 0;
	ఒకవేళ ((r = sshbuf_peek_string_ప్రత్యక్ష(buf, &p, &len)) < 0)
		తిరిగి r;
	ఒకవేళ (valp != ఖాళీ)
		*valp = p;
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = len;
	ఒకవేళ (sshbuf_consume(buf, len + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_peek_string_ప్రత్యక్ష(స్థిరరాశి నిర్మాణం sshbuf *buf, స్థిరరాశి u_char **valp,
    కొలత_t *lenp)
{
	uint32_t len;
	స్థిరరాశి u_char *p = sshbuf_ptr(buf);

	ఒకవేళ (valp != ఖాళీ)
		*valp = ఖాళీ;
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = 0;
	ఒకవేళ (sshbuf_len(buf) < 4) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		తిరిగి SSH_ERR_సందేశం_INCOMPLETE;
	}
	len = PEEK_U32(p);
	ఒకవేళ (len > SSHBUF_కొలత_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_STRING_TOO_LARGE"));
		తిరిగి SSH_ERR_STRING_TOO_LARGE;
	}
	ఒకవేళ (sshbuf_len(buf) - 4 < len) {
		SSHBUF_DBG(("SSH_ERR_MESSAGE_INCOMPLETE"));
		తిరిగి SSH_ERR_సందేశం_INCOMPLETE;
	}
	ఒకవేళ (valp != ఖాళీ)
		*valp = p + 4;
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = len;
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_get_cstring(నిర్మాణం sshbuf *buf, అక్షరం **valp, కొలత_t *lenp)
{
	కొలత_t len;
	స్థిరరాశి u_char *p, *z;
	పూర్ణాంకం r;

	ఒకవేళ (valp != ఖాళీ)
		*valp = ఖాళీ;
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = 0;
	ఒకవేళ ((r = sshbuf_peek_string_ప్రత్యక్ష(buf, &p, &len)) != 0)
		తిరిగి r;
	/* Allow a \0 only at the end of the string */
	ఒకవేళ (len > 0 &&
	    (z = memchr(p , '\0', len)) != ఖాళీ && z < p + len - 1) {
		SSHBUF_DBG(("SSH_ERR_INVALID_FORMAT"));
		తిరిగి SSH_ERR_INVALID_FORMAT;
	}
	ఒకవేళ ((r = sshbuf_skip_string(buf)) != 0)
		తిరిగి -1;
	ఒకవేళ (valp != ఖాళీ) {
		ఒకవేళ ((*valp = జ్ఞాపకం_ఇవ్వు(len + 1)) == ఖాళీ) {
			SSHBUF_DBG(("SSH_ERR_ALLOC_FAIL"));
			తిరిగి SSH_ERR_ALLOC_FAIL;
		}
		ఒకవేళ (len != 0)
			జ్ఞాపకం_నకలు(*valp, p, len);
		(*valp)[len] = '\0';
	}
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = (కొలత_t)len;
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_get_stringb(నిర్మాణం sshbuf *buf, నిర్మాణం sshbuf *v)
{
	uint32_t len;
	u_char *p;
	పూర్ణాంకం r;

	/*
	 * Use sshbuf_peek_string_direct() to figure out if there is
	 * a complete string in 'buf' and copy the string directly
	 * into 'v'.
	 */
	ఒకవేళ ((r = sshbuf_peek_string_ప్రత్యక్ష(buf, ఖాళీ, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_u32(buf, &len)) != 0 ||
	    (r = sshbuf_reserve(v, len, &p)) != 0 ||
	    (r = sshbuf_get(buf, p, len)) != 0)
		తిరిగి r;
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_put(నిర్మాణం sshbuf *buf, స్థిరరాశి శూన్య *v, కొలత_t len)
{
	u_char *p;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_reserve(buf, len, &p)) < 0)
		తిరిగి r;
	ఒకవేళ (len != 0)
		జ్ఞాపకం_నకలు(p, v, len);
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_putb(నిర్మాణం sshbuf *buf, స్థిరరాశి నిర్మాణం sshbuf *v)
{
	ఒకవేళ (v == ఖాళీ)
		తిరిగి 0;
	తిరిగి sshbuf_put(buf, sshbuf_ptr(v), sshbuf_len(v));
}

పూర్ణాంకం
sshbuf_putf(నిర్మాణం sshbuf *buf, స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list ap;
	పూర్ణాంకం r;

	va_start(ap, fmt);
	r = sshbuf_putfv(buf, fmt, ap);
	va_end(ap);
	తిరిగి r;
}

పూర్ణాంకం
sshbuf_putfv(నిర్మాణం sshbuf *buf, స్థిరరాశి అక్షరం *fmt, va_list ap)
{
	va_list ap2;
	పూర్ణాంకం r, len;
	u_char *p;

	VA_COPY(ap2, ap);
	ఒకవేళ ((len = vsnprintf(ఖాళీ, 0, fmt, ap2)) < 0) {
		r = SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (len == 0) {
		r = 0;
		వెళ్ళు బహిర్గతం; /* Nothing to do */
	}
	va_end(ap2);
	VA_COPY(ap2, ap);
	ఒకవేళ ((r = sshbuf_reserve(buf, (కొలత_t)len + 1, &p)) < 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = vsnprintf((అక్షరం *)p, len + 1, fmt, ap2)) != len) {
		r = SSH_ERR_అంతర్గత_ERROR;
		వెళ్ళు బహిర్గతం; /* Shouldn't happen */
	}
	/* Consume terminating \0 */
	ఒకవేళ ((r = sshbuf_consume_చివర(buf, 1)) != 0)
		వెళ్ళు బహిర్గతం;
	r = 0;
 బహిర్గతం:
	va_end(ap2);
	తిరిగి r;
}

పూర్ణాంకం
sshbuf_put_u64(నిర్మాణం sshbuf *buf, uint64_t val)
{
	u_char *p;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_reserve(buf, 8, &p)) < 0)
		తిరిగి r;
	POKE_U64(p, val);
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_put_u32(నిర్మాణం sshbuf *buf, uint32_t val)
{
	u_char *p;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_reserve(buf, 4, &p)) < 0)
		తిరిగి r;
	POKE_U32(p, val);
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_put_u16(నిర్మాణం sshbuf *buf, uint16_t val)
{
	u_char *p;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_reserve(buf, 2, &p)) < 0)
		తిరిగి r;
	POKE_U16(p, val);
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_put_u8(నిర్మాణం sshbuf *buf, u_char val)
{
	u_char *p;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_reserve(buf, 1, &p)) < 0)
		తిరిగి r;
	p[0] = val;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
check_woffset(నిర్మాణం sshbuf *buf, కొలత_t స్థానభ్రంశం, కొలత_t len, u_char **p)
{
	పూర్ణాంకం r;

	*p = ఖాళీ;
	ఒకవేళ ((r = check_స్థానభ్రంశం(buf, 1, స్థానభ్రంశం, len)) != 0)
		తిరిగి r;
	ఒకవేళ (sshbuf_mutable_ptr(buf) == ఖాళీ)
		తిరిగి SSH_ERR_బఫరు_READ_ONLY;
	*p = sshbuf_mutable_ptr(buf) + స్థానభ్రంశం;
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_poke_u64(నిర్మాణం sshbuf *buf, కొలత_t స్థానభ్రంశం, uint64_t val)
{
	u_char *p = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ ((r = check_woffset(buf, స్థానభ్రంశం, 8, &p)) != 0)
		తిరిగి r;
	POKE_U64(p, val);
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_poke_u32(నిర్మాణం sshbuf *buf, కొలత_t స్థానభ్రంశం, uint32_t val)
{
	u_char *p = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ ((r = check_woffset(buf, స్థానభ్రంశం, 4, &p)) != 0)
		తిరిగి r;
	POKE_U32(p, val);
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_poke_u16(నిర్మాణం sshbuf *buf, కొలత_t స్థానభ్రంశం, uint16_t val)
{
	u_char *p = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ ((r = check_woffset(buf, స్థానభ్రంశం, 2, &p)) != 0)
		తిరిగి r;
	POKE_U16(p, val);
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_poke_u8(నిర్మాణం sshbuf *buf, కొలత_t స్థానభ్రంశం, u_char val)
{
	u_char *p = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ ((r = check_woffset(buf, స్థానభ్రంశం, 1, &p)) != 0)
		తిరిగి r;
	*p = val;
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_poke(నిర్మాణం sshbuf *buf, కొలత_t స్థానభ్రంశం, శూన్య *v, కొలత_t len)
{
	u_char *p = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ ((r = check_woffset(buf, స్థానభ్రంశం, len, &p)) != 0)
		తిరిగి r;
	జ్ఞాపకం_నకలు(p, v, len);
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_put_string(నిర్మాణం sshbuf *buf, స్థిరరాశి శూన్య *v, కొలత_t len)
{
	u_char *d;
	పూర్ణాంకం r;

	ఒకవేళ (len > SSHBUF_కొలత_MAX - 4) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		తిరిగి SSH_ERR_NO_బఫరు_SPACE;
	}
	ఒకవేళ ((r = sshbuf_reserve(buf, len + 4, &d)) < 0)
		తిరిగి r;
	POKE_U32(d, len);
	ఒకవేళ (len != 0)
		జ్ఞాపకం_నకలు(d + 4, v, len);
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_put_cstring(నిర్మాణం sshbuf *buf, స్థిరరాశి అక్షరం *v)
{
	తిరిగి sshbuf_put_string(buf, v, v == ఖాళీ ? 0 : అక్షరశ్రేణి_పొడవు(v));
}

పూర్ణాంకం
sshbuf_put_stringb(నిర్మాణం sshbuf *buf, స్థిరరాశి నిర్మాణం sshbuf *v)
{
	ఒకవేళ (v == ఖాళీ)
		తిరిగి sshbuf_put_string(buf, ఖాళీ, 0);

	తిరిగి sshbuf_put_string(buf, sshbuf_ptr(v), sshbuf_len(v));
}

పూర్ణాంకం
sshbuf_froms(నిర్మాణం sshbuf *buf, నిర్మాణం sshbuf **bufp)
{
	స్థిరరాశి u_char *p;
	కొలత_t len;
	నిర్మాణం sshbuf *ret;
	పూర్ణాంకం r;

	ఒకవేళ (buf == ఖాళీ || bufp == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	*bufp = ఖాళీ;
	ఒకవేళ ((r = sshbuf_peek_string_ప్రత్యక్ష(buf, &p, &len)) != 0)
		తిరిగి r;
	ఒకవేళ ((ret = sshbuf_from(p, len)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_consume(buf, len + 4)) != 0 ||  /* Shouldn't happen */
	    (r = sshbuf_సమితి_మాతృ(ret, buf)) != 0) {
		sshbuf_free(ret);
		తిరిగి r;
	}
	*bufp = ret;
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_put_bignum2_బైట్లు(నిర్మాణం sshbuf *buf, స్థిరరాశి శూన్య *v, కొలత_t len)
{
	u_char *d;
	స్థిరరాశి u_char *s = (స్థిరరాశి u_char *)v;
	పూర్ణాంకం r, prepend;

	ఒకవేళ (len > SSHBUF_కొలత_MAX - 5) {
		SSHBUF_DBG(("SSH_ERR_NO_BUFFER_SPACE"));
		తిరిగి SSH_ERR_NO_బఫరు_SPACE;
	}
	/* Skip leading zero bytes */
	కొరకు (; len > 0 && *s == 0; len--, s++)
		;
	/*
	 * If most significant bit is set then prepend a zero byte to
	 * avoid interpretation as a negative number.
	 */
	prepend = len > 0 && (s[0] & 0x80) != 0;
	ఒకవేళ ((r = sshbuf_reserve(buf, len + 4 + prepend, &d)) < 0)
		తిరిగి r;
	POKE_U32(d, len + prepend);
	ఒకవేళ (prepend)
		d[4] = 0;
	ఒకవేళ (len != 0)
		జ్ఞాపకం_నకలు(d + 4 + prepend, s, len);
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_get_bignum2_బైట్లు_ప్రత్యక్ష(నిర్మాణం sshbuf *buf,
    స్థిరరాశి u_char **valp, కొలత_t *lenp)
{
	స్థిరరాశి u_char *d;
	కొలత_t len, olen;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_peek_string_ప్రత్యక్ష(buf, &d, &olen)) < 0)
		తిరిగి r;
	len = olen;
	/* Refuse negative (MSB set) bignums */
	ఒకవేళ ((len != 0 && (*d & 0x80) != 0))
		తిరిగి SSH_ERR_BIGNUM_IS_NEGATIVE;
	/* Refuse overlong bignums, allow prepended \0 to avoid MSB set */
	ఒకవేళ (len > SSHBUF_MAX_BIGNUM + 1 ||
	    (len == SSHBUF_MAX_BIGNUM + 1 && *d != 0))
		తిరిగి SSH_ERR_BIGNUM_TOO_LARGE;
	/* Trim leading zeros */
	అయితే (len > 0 && *d == 0x00) {
		d++;
		len--;
	}
	ఒకవేళ (valp != ఖాళీ)
		*valp = d;
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = len;
	ఒకవేళ (sshbuf_consume(buf, olen + 4) != 0) {
		/* Shouldn't happen */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		SSHBUF_ABORT();
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_get_nulterminated_string(నిర్మాణం sshbuf *buf, కొలత_t maxlen,
    అక్షరం **valp, కొలత_t *lenp)
{
	స్థిరరాశి u_char zero = 0;
	అక్షరం *val = ఖాళీ;
	కొలత_t len = 0;
	పూర్ణాంకం r;

	ఒకవేళ (valp != ఖాళీ)
		*valp = ఖాళీ;
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = 0;
	ఒకవేళ ((r = sshbuf_కనుగొను(buf, 0, &zero, పరిమాణం(zero), &len)) != 0) {
		ఒకవేళ (r == SSH_ERR_INVALID_FORMAT && sshbuf_len(buf) < maxlen)
			తిరిగి SSH_ERR_సందేశం_INCOMPLETE;
		తిరిగి r;
	}
	ఒకవేళ (len > maxlen)
		తిరిగి SSH_ERR_INVALID_FORMAT;
	/* can strdup() because it's definitely nul-terminated */
	ఒకవేళ ((val = strdup(sshbuf_ptr(buf))) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_consume(buf, len + 1)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	r = 0;
	ఒకవేళ (valp != ఖాళీ) {
		*valp = val;
		val = ఖాళీ;
	}
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = len;
 బహిర్గతం:
	విడుదల(val);
	తిరిగి r;
}
