/*	$OpenBSD: sshbuf.c,v 1.24 2025/12/29 23:52:09 djm Exp $	*/
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
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "ssherr.h"
#నిర్వచించు SSHBUF_అంతర్గత
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "misc.h"

#నిర్వచితమైతే SSHBUF_DEBUG
# define SSHBUF_TELL(what) చేయి { \
		రాయి("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __FILE__, __LINE__, __func__, what, \
		    buf->కొలత, buf->alloc, buf->off, buf->max_కొలత); \
		fflush(stdout); \
	} అయితే (0)
#లేకపోతే
# define SSHBUF_TELL(what)
#అయితే_ముగింపు

నిర్మాణం sshbuf {
	u_char *d;		/* Data */
	స్థిరరాశి u_char *cd;	/* Const data */
	కొలత_t off;		/* First available byte is buf->d + buf->off */
	కొలత_t కొలత;		/* Last byte is buf->d + buf->size - 1 */
	కొలత_t max_కొలత;	/* Maximum size of buffer */
	కొలత_t alloc;		/* Total bytes allocated to buf->d */
	పూర్ణాంకం readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	నిర్మాణం sshbuf *మాతృ;	/* If child, pointer to parent */
};

స్థిర అంతఃవరుస పూర్ణాంకం
sshbuf_check_sanity(స్థిరరాశి నిర్మాణం sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	ఒకవేళ (__predict_false(buf == ఖాళీ ||
	    (!buf->readonly && buf->d != buf->cd) ||
	    buf->మాతృ == buf ||
	    buf->refcount < 1 || buf->refcount > SSHBUF_REFS_MAX ||
	    buf->cd == ఖాళీ ||
	    buf->max_కొలత > SSHBUF_కొలత_MAX ||
	    buf->alloc > buf->max_కొలత ||
	    buf->కొలత > buf->alloc ||
	    buf->off > buf->కొలత)) {
		/* Do not try to recover from corrupted buffer internals */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		ssh_signal(SIGSEGV, SIG_DFL);
		లేపు(SIGSEGV);
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	తిరిగి 0;
}

స్థిర శూన్య
sshbuf_maybe_pack(నిర్మాణం sshbuf *buf, పూర్ణాంకం force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	ఒకవేళ (buf->off == 0 || buf->readonly || buf->refcount > 1)
		తిరిగి;
	ఒకవేళ (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->కొలత / 2)) {
		memmove(buf->d, buf->d + buf->off, buf->కొలత - buf->off);
		buf->కొలత -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

నిర్మాణం sshbuf *
sshbuf_new(శూన్య)
{
	నిర్మాణం sshbuf *ret;

	ఒకవేళ ((ret = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*ret))) == ఖాళీ)
		తిరిగి ఖాళీ;
	ret->alloc = SSHBUF_కొలత_INIT;
	ret->max_కొలత = SSHBUF_కొలత_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->మాతృ = ఖాళీ;
	ఒకవేళ ((ret->cd = ret->d = సున్నా_జ్ఞాపకం_ఇవ్వు(1, ret->alloc)) == ఖాళీ) {
		విడుదల(ret);
		తిరిగి ఖాళీ;
	}
	తిరిగి ret;
}

నిర్మాణం sshbuf *
sshbuf_from(స్థిరరాశి శూన్య *blob, కొలత_t len)
{
	నిర్మాణం sshbuf *ret;

	ఒకవేళ (blob == ఖాళీ || len > SSHBUF_కొలత_MAX ||
	    (ret = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*ret))) == ఖాళీ)
		తిరిగి ఖాళీ;
	ret->alloc = ret->కొలత = ret->max_కొలత = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->మాతృ = ఖాళీ;
	ret->cd = blob;
	ret->d = ఖాళీ;
	తిరిగి ret;
}

పూర్ణాంకం
sshbuf_సమితి_మాతృ(నిర్మాణం sshbuf *బిడ్డ, నిర్మాణం sshbuf *మాతృ)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_check_sanity(బిడ్డ)) != 0 ||
	    (r = sshbuf_check_sanity(మాతృ)) != 0)
		తిరిగి r;
	ఒకవేళ ((బిడ్డ->మాతృ != ఖాళీ && బిడ్డ->మాతృ != మాతృ) ||
	    బిడ్డ == మాతృ)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	బిడ్డ->మాతృ = మాతృ;
	బిడ్డ->మాతృ->refcount++;
	తిరిగి 0;
}

నిర్మాణం sshbuf *
sshbuf_fromb(నిర్మాణం sshbuf *buf)
{
	నిర్మాణం sshbuf *ret;

	ఒకవేళ (sshbuf_check_sanity(buf) != 0)
		తిరిగి ఖాళీ;
	ఒకవేళ ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == ఖాళీ)
		తిరిగి ఖాళీ;
	ఒకవేళ (sshbuf_సమితి_మాతృ(ret, buf) != 0) {
		sshbuf_free(ret);
		తిరిగి ఖాళీ;
	}
	తిరిగి ret;
}

శూన్య
sshbuf_free(నిర్మాణం sshbuf *buf)
{
	ఒకవేళ (buf == ఖాళీ)
		తిరిగి;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	ఒకవేళ (sshbuf_check_sanity(buf) != 0)
		తిరిగి;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	ఒకవేళ (buf->refcount > 0)
		తిరిగి;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->మాతృ);
	buf->మాతృ = ఖాళీ;

	ఒకవేళ (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, పరిమాణం(*buf));
}

శూన్య
sshbuf_reset(నిర్మాణం sshbuf *buf)
{
	u_char *d;

	ఒకవేళ (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->కొలత;
		తిరిగి;
	}
	ఒకవేళ (sshbuf_check_sanity(buf) != 0)
		తిరిగి;
	buf->off = buf->కొలత = 0;
	ఒకవేళ (buf->alloc != SSHBUF_కొలత_INIT) {
		ఒకవేళ ((d = recallocarray(buf->d, buf->alloc, SSHBUF_కొలత_INIT,
		    1)) != ఖాళీ) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_కొలత_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

కొలత_t
sshbuf_max_కొలత(స్థిరరాశి నిర్మాణం sshbuf *buf)
{
	తిరిగి buf->max_కొలత;
}

కొలత_t
sshbuf_alloc(స్థిరరాశి నిర్మాణం sshbuf *buf)
{
	తిరిగి buf->alloc;
}

స్థిరరాశి నిర్మాణం sshbuf *
sshbuf_మాతృ(స్థిరరాశి నిర్మాణం sshbuf *buf)
{
	తిరిగి buf->మాతృ;
}

u_int
sshbuf_refcount(స్థిరరాశి నిర్మాణం sshbuf *buf)
{
	తిరిగి buf->refcount;
}

పూర్ణాంకం
sshbuf_సమితి_max_కొలత(నిర్మాణం sshbuf *buf, కొలత_t max_కొలత)
{
	కొలత_t rlen;
	u_char *dp;
	పూర్ణాంకం r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_కొలత));
	ఒకవేళ ((r = sshbuf_check_sanity(buf)) != 0)
		తిరిగి r;
	ఒకవేళ (max_కొలత == buf->max_కొలత)
		తిరిగి 0;
	ఒకవేళ (buf->readonly || buf->refcount > 1)
		తిరిగి SSH_ERR_బఫరు_READ_ONLY;
	ఒకవేళ (max_కొలత > SSHBUF_కొలత_MAX)
		తిరిగి SSH_ERR_NO_బఫరు_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_కొలత < buf->కొలత);
	ఒకవేళ (max_కొలత < buf->alloc && max_కొలత > buf->కొలత) {
		ఒకవేళ (buf->కొలత < SSHBUF_కొలత_INIT)
			rlen = SSHBUF_కొలత_INIT;
		లేకపోతే
			rlen = ROUNDUP(buf->కొలత, SSHBUF_కొలత_INC);
		ఒకవేళ (rlen > max_కొలత)
			rlen = max_కొలత;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		ఒకవేళ ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == ఖాళీ)
			తిరిగి SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	ఒకవేళ (max_కొలత < buf->alloc)
		తిరిగి SSH_ERR_NO_బఫరు_SPACE;
	buf->max_కొలత = max_కొలత;
	తిరిగి 0;
}

కొలత_t
sshbuf_len(స్థిరరాశి నిర్మాణం sshbuf *buf)
{
	ఒకవేళ (sshbuf_check_sanity(buf) != 0)
		తిరిగి 0;
	తిరిగి buf->కొలత - buf->off;
}

కొలత_t
sshbuf_avail(స్థిరరాశి నిర్మాణం sshbuf *buf)
{
	ఒకవేళ (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		తిరిగి 0;
	తిరిగి buf->max_కొలత - (buf->కొలత - buf->off);
}

స్థిరరాశి u_char *
sshbuf_ptr(స్థిరరాశి నిర్మాణం sshbuf *buf)
{
	ఒకవేళ (sshbuf_check_sanity(buf) != 0)
		తిరిగి ఖాళీ;
	తిరిగి buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(స్థిరరాశి నిర్మాణం sshbuf *buf)
{
	ఒకవేళ (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		తిరిగి ఖాళీ;
	తిరిగి buf->d + buf->off;
}

పూర్ణాంకం
sshbuf_check_reserve(స్థిరరాశి నిర్మాణం sshbuf *buf, కొలత_t len)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_check_sanity(buf)) != 0)
		తిరిగి r;
	ఒకవేళ (buf->readonly || buf->refcount > 1)
		తిరిగి SSH_ERR_బఫరు_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	ఒకవేళ (len > buf->max_కొలత || buf->max_కొలత - len < buf->కొలత - buf->off)
		తిరిగి SSH_ERR_NO_బఫరు_SPACE;
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_allocate(నిర్మాణం sshbuf *buf, కొలత_t len)
{
	కొలత_t rlen, need;
	u_char *dp;
	పూర్ణాంకం r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	ఒకవేళ ((r = sshbuf_check_reserve(buf, len)) != 0)
		తిరిగి r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->కొలత + len > buf->max_కొలత);
	SSHBUF_TELL("allocate");
	ఒకవేళ (len + buf->కొలత <= buf->alloc)
		తిరిగి 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->కొలత - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_కొలత_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	ఒకవేళ (rlen > buf->max_కొలత)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	ఒకవేళ ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == ఖాళీ) {
		SSHBUF_DBG(("realloc fail"));
		తిరిగి SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	ఒకవేళ ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		తిరిగి r;
	}
	SSHBUF_TELL("done");
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_reserve(నిర్మాణం sshbuf *buf, కొలత_t len, u_char **dpp)
{
	u_char *dp;
	పూర్ణాంకం r;

	ఒకవేళ (dpp != ఖాళీ)
		*dpp = ఖాళీ;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	ఒకవేళ ((r = sshbuf_allocate(buf, len)) != 0)
		తిరిగి r;

	dp = buf->d + buf->కొలత;
	buf->కొలత += len;
	ఒకవేళ (dpp != ఖాళీ)
		*dpp = dp;
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_consume(నిర్మాణం sshbuf *buf, కొలత_t len)
{
	పూర్ణాంకం r;

	SSHBUF_DBG(("len = %zu", len));
	ఒకవేళ ((r = sshbuf_check_sanity(buf)) != 0)
		తిరిగి r;
	ఒకవేళ (len == 0)
		తిరిగి 0;
	ఒకవేళ (len > sshbuf_len(buf))
		తిరిగి SSH_ERR_సందేశం_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	ఒకవేళ (buf->off == buf->కొలత)
		buf->off = buf->కొలత = 0;
	SSHBUF_TELL("done");
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_consume_చివర(నిర్మాణం sshbuf *buf, కొలత_t len)
{
	పూర్ణాంకం r;

	SSHBUF_DBG(("len = %zu", len));
	ఒకవేళ ((r = sshbuf_check_sanity(buf)) != 0)
		తిరిగి r;
	ఒకవేళ (len == 0)
		తిరిగి 0;
	ఒకవేళ (len > sshbuf_len(buf))
		తిరిగి SSH_ERR_సందేశం_INCOMPLETE;
	buf->కొలత -= len;
	SSHBUF_TELL("done");
	తిరిగి 0;
}

పూర్ణాంకం
sshbuf_consume_upto_బిడ్డ(నిర్మాణం sshbuf *buf, స్థిరరాశి నిర్మాణం sshbuf *బిడ్డ)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(బిడ్డ)) != 0)
		తిరిగి r;
	/* This function is only used for parent/child buffers */
	ఒకవేళ (బిడ్డ->మాతృ != buf)
		తిరిగి SSH_ERR_INVALID_వాదం;
	/* Nonsensical if the parent has advanced past the child */
	ఒకవేళ (sshbuf_len(బిడ్డ) > sshbuf_len(buf))
		తిరిగి SSH_ERR_INVALID_వాదం;
	/* More paranoia, shouldn't happen */
	ఒకవేళ (బిడ్డ->cd < buf->cd)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	/* Advance */
	తిరిగి sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(బిడ్డ));
}
