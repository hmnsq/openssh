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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <signal.h>
#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <string.h>

#ضمن "ssherr.h"
#تعریف_کرو SSHBUF_اندرونی
#ضمن "sshbuf.h"
#ضمن "misc.h"

#جے_تعریف_شدہ SSHBUF_DEBUG
# define SSHBUF_TELL(what) افعل { \
		لکھو("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __FILE__, __LINE__, __func__, what, \
		    buf->ناپ, buf->alloc, buf->off, buf->max_ناپ); \
		fflush(stdout); \
	} طالما (0)
#وإلا
# define SSHBUF_TELL(what)
#جے_انت

بنية sshbuf {
	u_char *d;		/* Data */
	ثابت u_char *cd;	/* Const data */
	ناپ_t off;		/* First available byte is buf->d + buf->off */
	ناپ_t ناپ;		/* Last byte is buf->d + buf->size - 1 */
	ناپ_t max_ناپ;	/* Maximum size of buffer */
	ناپ_t alloc;		/* Total bytes allocated to buf->d */
	صحيح readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	بنية sshbuf *ماپا;	/* If child, pointer to parent */
};

ساكن مضمن صحيح
sshbuf_check_sanity(ثابت بنية sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	إذا (__predict_false(buf == عدم ||
	    (!buf->readonly && buf->d != buf->cd) ||
	    buf->ماپا == buf ||
	    buf->refcount < 1 || buf->refcount > SSHBUF_REFS_MAX ||
	    buf->cd == عدم ||
	    buf->max_ناپ > SSHBUF_ناپ_MAX ||
	    buf->alloc > buf->max_ناپ ||
	    buf->ناپ > buf->alloc ||
	    buf->off > buf->ناپ)) {
		/* Do not try to recover from corrupted buffer internals */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		ssh_signal(SIGSEGV, SIG_DFL);
		ارفع(SIGSEGV);
		أرجع SSH_ERR_اندرونی_ERROR;
	}
	أرجع 0;
}

ساكن فراغ
sshbuf_maybe_pack(بنية sshbuf *buf, صحيح force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	إذا (buf->off == 0 || buf->readonly || buf->refcount > 1)
		أرجع;
	إذا (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->ناپ / 2)) {
		memmove(buf->d, buf->d + buf->off, buf->ناپ - buf->off);
		buf->ناپ -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

بنية sshbuf *
sshbuf_new(فراغ)
{
	بنية sshbuf *ret;

	إذا ((ret = صفر_حافظہ_دیو(1, حجم(*ret))) == عدم)
		أرجع عدم;
	ret->alloc = SSHBUF_ناپ_INIT;
	ret->max_ناپ = SSHBUF_ناپ_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->ماپا = عدم;
	إذا ((ret->cd = ret->d = صفر_حافظہ_دیو(1, ret->alloc)) == عدم) {
		حرر(ret);
		أرجع عدم;
	}
	أرجع ret;
}

بنية sshbuf *
sshbuf_from(ثابت فراغ *blob, ناپ_t len)
{
	بنية sshbuf *ret;

	إذا (blob == عدم || len > SSHBUF_ناپ_MAX ||
	    (ret = صفر_حافظہ_دیو(1, حجم(*ret))) == عدم)
		أرجع عدم;
	ret->alloc = ret->ناپ = ret->max_ناپ = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->ماپا = عدم;
	ret->cd = blob;
	ret->d = عدم;
	أرجع ret;
}

صحيح
sshbuf_سیٹ_ماپا(بنية sshbuf *بچہ, بنية sshbuf *ماپا)
{
	صحيح r;

	إذا ((r = sshbuf_check_sanity(بچہ)) != 0 ||
	    (r = sshbuf_check_sanity(ماپا)) != 0)
		أرجع r;
	إذا ((بچہ->ماپا != عدم && بچہ->ماپا != ماپا) ||
	    بچہ == ماپا)
		أرجع SSH_ERR_اندرونی_ERROR;
	بچہ->ماپا = ماپا;
	بچہ->ماپا->refcount++;
	أرجع 0;
}

بنية sshbuf *
sshbuf_fromb(بنية sshbuf *buf)
{
	بنية sshbuf *ret;

	إذا (sshbuf_check_sanity(buf) != 0)
		أرجع عدم;
	إذا ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == عدم)
		أرجع عدم;
	إذا (sshbuf_سیٹ_ماپا(ret, buf) != 0) {
		sshbuf_free(ret);
		أرجع عدم;
	}
	أرجع ret;
}

فراغ
sshbuf_free(بنية sshbuf *buf)
{
	إذا (buf == عدم)
		أرجع;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	إذا (sshbuf_check_sanity(buf) != 0)
		أرجع;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	إذا (buf->refcount > 0)
		أرجع;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->ماپا);
	buf->ماپا = عدم;

	إذا (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, حجم(*buf));
}

فراغ
sshbuf_reset(بنية sshbuf *buf)
{
	u_char *d;

	إذا (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->ناپ;
		أرجع;
	}
	إذا (sshbuf_check_sanity(buf) != 0)
		أرجع;
	buf->off = buf->ناپ = 0;
	إذا (buf->alloc != SSHBUF_ناپ_INIT) {
		إذا ((d = recallocarray(buf->d, buf->alloc, SSHBUF_ناپ_INIT,
		    1)) != عدم) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_ناپ_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

ناپ_t
sshbuf_max_ناپ(ثابت بنية sshbuf *buf)
{
	أرجع buf->max_ناپ;
}

ناپ_t
sshbuf_alloc(ثابت بنية sshbuf *buf)
{
	أرجع buf->alloc;
}

ثابت بنية sshbuf *
sshbuf_ماپا(ثابت بنية sshbuf *buf)
{
	أرجع buf->ماپا;
}

u_int
sshbuf_refcount(ثابت بنية sshbuf *buf)
{
	أرجع buf->refcount;
}

صحيح
sshbuf_سیٹ_max_ناپ(بنية sshbuf *buf, ناپ_t max_ناپ)
{
	ناپ_t rlen;
	u_char *dp;
	صحيح r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_ناپ));
	إذا ((r = sshbuf_check_sanity(buf)) != 0)
		أرجع r;
	إذا (max_ناپ == buf->max_ناپ)
		أرجع 0;
	إذا (buf->readonly || buf->refcount > 1)
		أرجع SSH_ERR_بفر_READ_ONLY;
	إذا (max_ناپ > SSHBUF_ناپ_MAX)
		أرجع SSH_ERR_NO_بفر_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_ناپ < buf->ناپ);
	إذا (max_ناپ < buf->alloc && max_ناپ > buf->ناپ) {
		إذا (buf->ناپ < SSHBUF_ناپ_INIT)
			rlen = SSHBUF_ناپ_INIT;
		وإلا
			rlen = ROUNDUP(buf->ناپ, SSHBUF_ناپ_INC);
		إذا (rlen > max_ناپ)
			rlen = max_ناپ;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		إذا ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == عدم)
			أرجع SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	إذا (max_ناپ < buf->alloc)
		أرجع SSH_ERR_NO_بفر_SPACE;
	buf->max_ناپ = max_ناپ;
	أرجع 0;
}

ناپ_t
sshbuf_len(ثابت بنية sshbuf *buf)
{
	إذا (sshbuf_check_sanity(buf) != 0)
		أرجع 0;
	أرجع buf->ناپ - buf->off;
}

ناپ_t
sshbuf_avail(ثابت بنية sshbuf *buf)
{
	إذا (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		أرجع 0;
	أرجع buf->max_ناپ - (buf->ناپ - buf->off);
}

ثابت u_char *
sshbuf_ptr(ثابت بنية sshbuf *buf)
{
	إذا (sshbuf_check_sanity(buf) != 0)
		أرجع عدم;
	أرجع buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(ثابت بنية sshbuf *buf)
{
	إذا (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		أرجع عدم;
	أرجع buf->d + buf->off;
}

صحيح
sshbuf_check_reserve(ثابت بنية sshbuf *buf, ناپ_t len)
{
	صحيح r;

	إذا ((r = sshbuf_check_sanity(buf)) != 0)
		أرجع r;
	إذا (buf->readonly || buf->refcount > 1)
		أرجع SSH_ERR_بفر_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	إذا (len > buf->max_ناپ || buf->max_ناپ - len < buf->ناپ - buf->off)
		أرجع SSH_ERR_NO_بفر_SPACE;
	أرجع 0;
}

صحيح
sshbuf_allocate(بنية sshbuf *buf, ناپ_t len)
{
	ناپ_t rlen, need;
	u_char *dp;
	صحيح r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	إذا ((r = sshbuf_check_reserve(buf, len)) != 0)
		أرجع r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->ناپ + len > buf->max_ناپ);
	SSHBUF_TELL("allocate");
	إذا (len + buf->ناپ <= buf->alloc)
		أرجع 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->ناپ - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_ناپ_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	إذا (rlen > buf->max_ناپ)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	إذا ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == عدم) {
		SSHBUF_DBG(("realloc fail"));
		أرجع SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	إذا ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		أرجع r;
	}
	SSHBUF_TELL("done");
	أرجع 0;
}

صحيح
sshbuf_reserve(بنية sshbuf *buf, ناپ_t len, u_char **dpp)
{
	u_char *dp;
	صحيح r;

	إذا (dpp != عدم)
		*dpp = عدم;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	إذا ((r = sshbuf_allocate(buf, len)) != 0)
		أرجع r;

	dp = buf->d + buf->ناپ;
	buf->ناپ += len;
	إذا (dpp != عدم)
		*dpp = dp;
	أرجع 0;
}

صحيح
sshbuf_consume(بنية sshbuf *buf, ناپ_t len)
{
	صحيح r;

	SSHBUF_DBG(("len = %zu", len));
	إذا ((r = sshbuf_check_sanity(buf)) != 0)
		أرجع r;
	إذا (len == 0)
		أرجع 0;
	إذا (len > sshbuf_len(buf))
		أرجع SSH_ERR_سنیہا_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	إذا (buf->off == buf->ناپ)
		buf->off = buf->ناپ = 0;
	SSHBUF_TELL("done");
	أرجع 0;
}

صحيح
sshbuf_consume_سرا(بنية sshbuf *buf, ناپ_t len)
{
	صحيح r;

	SSHBUF_DBG(("len = %zu", len));
	إذا ((r = sshbuf_check_sanity(buf)) != 0)
		أرجع r;
	إذا (len == 0)
		أرجع 0;
	إذا (len > sshbuf_len(buf))
		أرجع SSH_ERR_سنیہا_INCOMPLETE;
	buf->ناپ -= len;
	SSHBUF_TELL("done");
	أرجع 0;
}

صحيح
sshbuf_consume_upto_بچہ(بنية sshbuf *buf, ثابت بنية sshbuf *بچہ)
{
	صحيح r;

	إذا ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(بچہ)) != 0)
		أرجع r;
	/* This function is only used for parent/child buffers */
	إذا (بچہ->ماپا != buf)
		أرجع SSH_ERR_INVALID_دلیل;
	/* Nonsensical if the parent has advanced past the child */
	إذا (sshbuf_len(بچہ) > sshbuf_len(buf))
		أرجع SSH_ERR_INVALID_دلیل;
	/* More paranoia, shouldn't happen */
	إذا (بچہ->cd < buf->cd)
		أرجع SSH_ERR_اندرونی_ERROR;
	/* Advance */
	أرجع sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(بچہ));
}
