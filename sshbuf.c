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
#تعریف_کړه SSHBUF_دننی
#ضمن "sshbuf.h"
#ضمن "misc.h"

#که_تعریف_شوی SSHBUF_DEBUG
# define SSHBUF_TELL(what) افعل { \
		چاپ_کړه("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __FILE__, __LINE__, __func__, what, \
		    buf->اندازه, buf->alloc, buf->off, buf->max_اندازه); \
		fflush(stdout); \
	} طالما (0)
#وإلا
# define SSHBUF_TELL(what)
#د_که_پای

بنية sshbuf {
	u_char *d;		/* Data */
	ثابت u_char *cd;	/* Const data */
	اندازه_t off;		/* First available byte is buf->d + buf->off */
	اندازه_t اندازه;		/* Last byte is buf->d + buf->size - 1 */
	اندازه_t max_اندازه;	/* Maximum size of buffer */
	اندازه_t alloc;		/* Total bytes allocated to buf->d */
	صحيح readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	بنية sshbuf *پلار;	/* If child, pointer to parent */
};

ساكن مضمن صحيح
sshbuf_check_sanity(ثابت بنية sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	إذا (__predict_false(buf == عدم ||
	    (!buf->readonly && buf->d != buf->cd) ||
	    buf->پلار == buf ||
	    buf->refcount < 1 || buf->refcount > SSHBUF_REFS_MAX ||
	    buf->cd == عدم ||
	    buf->max_اندازه > SSHBUF_اندازه_MAX ||
	    buf->alloc > buf->max_اندازه ||
	    buf->اندازه > buf->alloc ||
	    buf->off > buf->اندازه)) {
		/* Do not try to recover from corrupted buffer internals */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		ssh_signal(SIGSEGV, SIG_DFL);
		ارفع(SIGSEGV);
		أرجع SSH_ERR_دننی_ERROR;
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
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->اندازه / 2)) {
		memmove(buf->d, buf->d + buf->off, buf->اندازه - buf->off);
		buf->اندازه -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

بنية sshbuf *
sshbuf_new(فراغ)
{
	بنية sshbuf *ret;

	إذا ((ret = حافظه_صفر_ورکړه(1, حجم(*ret))) == عدم)
		أرجع عدم;
	ret->alloc = SSHBUF_اندازه_INIT;
	ret->max_اندازه = SSHBUF_اندازه_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->پلار = عدم;
	إذا ((ret->cd = ret->d = حافظه_صفر_ورکړه(1, ret->alloc)) == عدم) {
		حرر(ret);
		أرجع عدم;
	}
	أرجع ret;
}

بنية sshbuf *
sshbuf_from(ثابت فراغ *blob, اندازه_t len)
{
	بنية sshbuf *ret;

	إذا (blob == عدم || len > SSHBUF_اندازه_MAX ||
	    (ret = حافظه_صفر_ورکړه(1, حجم(*ret))) == عدم)
		أرجع عدم;
	ret->alloc = ret->اندازه = ret->max_اندازه = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->پلار = عدم;
	ret->cd = blob;
	ret->d = عدم;
	أرجع ret;
}

صحيح
sshbuf_سېټ_پلار(بنية sshbuf *ماشوم, بنية sshbuf *پلار)
{
	صحيح r;

	إذا ((r = sshbuf_check_sanity(ماشوم)) != 0 ||
	    (r = sshbuf_check_sanity(پلار)) != 0)
		أرجع r;
	إذا ((ماشوم->پلار != عدم && ماشوم->پلار != پلار) ||
	    ماشوم == پلار)
		أرجع SSH_ERR_دننی_ERROR;
	ماشوم->پلار = پلار;
	ماشوم->پلار->refcount++;
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
	إذا (sshbuf_سېټ_پلار(ret, buf) != 0) {
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
	sshbuf_free(buf->پلار);
	buf->پلار = عدم;

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
		buf->off = buf->اندازه;
		أرجع;
	}
	إذا (sshbuf_check_sanity(buf) != 0)
		أرجع;
	buf->off = buf->اندازه = 0;
	إذا (buf->alloc != SSHBUF_اندازه_INIT) {
		إذا ((d = recallocarray(buf->d, buf->alloc, SSHBUF_اندازه_INIT,
		    1)) != عدم) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_اندازه_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

اندازه_t
sshbuf_max_اندازه(ثابت بنية sshbuf *buf)
{
	أرجع buf->max_اندازه;
}

اندازه_t
sshbuf_alloc(ثابت بنية sshbuf *buf)
{
	أرجع buf->alloc;
}

ثابت بنية sshbuf *
sshbuf_پلار(ثابت بنية sshbuf *buf)
{
	أرجع buf->پلار;
}

u_int
sshbuf_refcount(ثابت بنية sshbuf *buf)
{
	أرجع buf->refcount;
}

صحيح
sshbuf_سېټ_max_اندازه(بنية sshbuf *buf, اندازه_t max_اندازه)
{
	اندازه_t rlen;
	u_char *dp;
	صحيح r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_اندازه));
	إذا ((r = sshbuf_check_sanity(buf)) != 0)
		أرجع r;
	إذا (max_اندازه == buf->max_اندازه)
		أرجع 0;
	إذا (buf->readonly || buf->refcount > 1)
		أرجع SSH_ERR_بفر_READ_ONLY;
	إذا (max_اندازه > SSHBUF_اندازه_MAX)
		أرجع SSH_ERR_NO_بفر_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_اندازه < buf->اندازه);
	إذا (max_اندازه < buf->alloc && max_اندازه > buf->اندازه) {
		إذا (buf->اندازه < SSHBUF_اندازه_INIT)
			rlen = SSHBUF_اندازه_INIT;
		وإلا
			rlen = ROUNDUP(buf->اندازه, SSHBUF_اندازه_INC);
		إذا (rlen > max_اندازه)
			rlen = max_اندازه;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		إذا ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == عدم)
			أرجع SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	إذا (max_اندازه < buf->alloc)
		أرجع SSH_ERR_NO_بفر_SPACE;
	buf->max_اندازه = max_اندازه;
	أرجع 0;
}

اندازه_t
sshbuf_len(ثابت بنية sshbuf *buf)
{
	إذا (sshbuf_check_sanity(buf) != 0)
		أرجع 0;
	أرجع buf->اندازه - buf->off;
}

اندازه_t
sshbuf_avail(ثابت بنية sshbuf *buf)
{
	إذا (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		أرجع 0;
	أرجع buf->max_اندازه - (buf->اندازه - buf->off);
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
sshbuf_check_reserve(ثابت بنية sshbuf *buf, اندازه_t len)
{
	صحيح r;

	إذا ((r = sshbuf_check_sanity(buf)) != 0)
		أرجع r;
	إذا (buf->readonly || buf->refcount > 1)
		أرجع SSH_ERR_بفر_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	إذا (len > buf->max_اندازه || buf->max_اندازه - len < buf->اندازه - buf->off)
		أرجع SSH_ERR_NO_بفر_SPACE;
	أرجع 0;
}

صحيح
sshbuf_allocate(بنية sshbuf *buf, اندازه_t len)
{
	اندازه_t rlen, need;
	u_char *dp;
	صحيح r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	إذا ((r = sshbuf_check_reserve(buf, len)) != 0)
		أرجع r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->اندازه + len > buf->max_اندازه);
	SSHBUF_TELL("allocate");
	إذا (len + buf->اندازه <= buf->alloc)
		أرجع 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->اندازه - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_اندازه_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	إذا (rlen > buf->max_اندازه)
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
sshbuf_reserve(بنية sshbuf *buf, اندازه_t len, u_char **dpp)
{
	u_char *dp;
	صحيح r;

	إذا (dpp != عدم)
		*dpp = عدم;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	إذا ((r = sshbuf_allocate(buf, len)) != 0)
		أرجع r;

	dp = buf->d + buf->اندازه;
	buf->اندازه += len;
	إذا (dpp != عدم)
		*dpp = dp;
	أرجع 0;
}

صحيح
sshbuf_consume(بنية sshbuf *buf, اندازه_t len)
{
	صحيح r;

	SSHBUF_DBG(("len = %zu", len));
	إذا ((r = sshbuf_check_sanity(buf)) != 0)
		أرجع r;
	إذا (len == 0)
		أرجع 0;
	إذا (len > sshbuf_len(buf))
		أرجع SSH_ERR_پیغام_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	إذا (buf->off == buf->اندازه)
		buf->off = buf->اندازه = 0;
	SSHBUF_TELL("done");
	أرجع 0;
}

صحيح
sshbuf_consume_پای_ټکی(بنية sshbuf *buf, اندازه_t len)
{
	صحيح r;

	SSHBUF_DBG(("len = %zu", len));
	إذا ((r = sshbuf_check_sanity(buf)) != 0)
		أرجع r;
	إذا (len == 0)
		أرجع 0;
	إذا (len > sshbuf_len(buf))
		أرجع SSH_ERR_پیغام_INCOMPLETE;
	buf->اندازه -= len;
	SSHBUF_TELL("done");
	أرجع 0;
}

صحيح
sshbuf_consume_upto_ماشوم(بنية sshbuf *buf, ثابت بنية sshbuf *ماشوم)
{
	صحيح r;

	إذا ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(ماشوم)) != 0)
		أرجع r;
	/* This function is only used for parent/child buffers */
	إذا (ماشوم->پلار != buf)
		أرجع SSH_ERR_INVALID_دلیل;
	/* Nonsensical if the parent has advanced past the child */
	إذا (sshbuf_len(ماشوم) > sshbuf_len(buf))
		أرجع SSH_ERR_INVALID_دلیل;
	/* More paranoia, shouldn't happen */
	إذا (ماشوم->cd < buf->cd)
		أرجع SSH_ERR_دننی_ERROR;
	/* Advance */
	أرجع sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(ماشوم));
}
