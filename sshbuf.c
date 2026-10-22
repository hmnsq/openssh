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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <signal.h>
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <string.h>

#شامل "ssherr.h"
#تعریف_کرو SSHBUF_اندرونی
#شامل "sshbuf.h"
#شامل "misc.h"

#اگر_تعریف_شدہ SSHBUF_DEBUG
# define SSHBUF_TELL(what) کرو { \
		لکھو("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __FILE__, __LINE__, __func__, what, \
		    buf->سائز, buf->alloc, buf->off, buf->max_سائز); \
		fflush(stdout); \
	} جب (0)
#ورنہ
# define SSHBUF_TELL(what)
#اگر_ختم

ساخت sshbuf {
	u_char *d;		/* Data */
	ثابت u_char *cd;	/* Const data */
	سائز_t off;		/* First available byte is buf->d + buf->off */
	سائز_t سائز;		/* Last byte is buf->d + buf->size - 1 */
	سائز_t max_سائز;	/* Maximum size of buffer */
	سائز_t alloc;		/* Total bytes allocated to buf->d */
	صحیح readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	ساخت sshbuf *والد;	/* If child, pointer to parent */
};

ساکن اندرونی صحیح
sshbuf_check_sanity(ثابت ساخت sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	اگر (__predict_false(buf == تہی ||
	    (!buf->readonly && buf->d != buf->cd) ||
	    buf->والد == buf ||
	    buf->refcount < 1 || buf->refcount > SSHBUF_REFS_MAX ||
	    buf->cd == تہی ||
	    buf->max_سائز > SSHBUF_سائز_MAX ||
	    buf->alloc > buf->max_سائز ||
	    buf->سائز > buf->alloc ||
	    buf->off > buf->سائز)) {
		/* Do not try to recover from corrupted buffer internals */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		ssh_signal(SIGSEGV, SIG_DFL);
		اٹھاؤ(SIGSEGV);
		واپس SSH_ERR_اندرونی_ERROR;
	}
	واپس 0;
}

ساکن خالی
sshbuf_maybe_pack(ساخت sshbuf *buf, صحیح force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	اگر (buf->off == 0 || buf->readonly || buf->refcount > 1)
		واپس;
	اگر (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->سائز / 2)) {
		memmove(buf->d, buf->d + buf->off, buf->سائز - buf->off);
		buf->سائز -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

ساخت sshbuf *
sshbuf_new(خالی)
{
	ساخت sshbuf *ret;

	اگر ((ret = صفر_حافظہ_دو(1, حجم(*ret))) == تہی)
		واپس تہی;
	ret->alloc = SSHBUF_سائز_INIT;
	ret->max_سائز = SSHBUF_سائز_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->والد = تہی;
	اگر ((ret->cd = ret->d = صفر_حافظہ_دو(1, ret->alloc)) == تہی) {
		آزاد(ret);
		واپس تہی;
	}
	واپس ret;
}

ساخت sshbuf *
sshbuf_from(ثابت خالی *blob, سائز_t len)
{
	ساخت sshbuf *ret;

	اگر (blob == تہی || len > SSHBUF_سائز_MAX ||
	    (ret = صفر_حافظہ_دو(1, حجم(*ret))) == تہی)
		واپس تہی;
	ret->alloc = ret->سائز = ret->max_سائز = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->والد = تہی;
	ret->cd = blob;
	ret->d = تہی;
	واپس ret;
}

صحیح
sshbuf_سیٹ_والد(ساخت sshbuf *بچہ, ساخت sshbuf *والد)
{
	صحیح r;

	اگر ((r = sshbuf_check_sanity(بچہ)) != 0 ||
	    (r = sshbuf_check_sanity(والد)) != 0)
		واپس r;
	اگر ((بچہ->والد != تہی && بچہ->والد != والد) ||
	    بچہ == والد)
		واپس SSH_ERR_اندرونی_ERROR;
	بچہ->والد = والد;
	بچہ->والد->refcount++;
	واپس 0;
}

ساخت sshbuf *
sshbuf_fromb(ساخت sshbuf *buf)
{
	ساخت sshbuf *ret;

	اگر (sshbuf_check_sanity(buf) != 0)
		واپس تہی;
	اگر ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == تہی)
		واپس تہی;
	اگر (sshbuf_سیٹ_والد(ret, buf) != 0) {
		sshbuf_free(ret);
		واپس تہی;
	}
	واپس ret;
}

خالی
sshbuf_free(ساخت sshbuf *buf)
{
	اگر (buf == تہی)
		واپس;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	اگر (sshbuf_check_sanity(buf) != 0)
		واپس;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	اگر (buf->refcount > 0)
		واپس;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->والد);
	buf->والد = تہی;

	اگر (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, حجم(*buf));
}

خالی
sshbuf_reset(ساخت sshbuf *buf)
{
	u_char *d;

	اگر (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->سائز;
		واپس;
	}
	اگر (sshbuf_check_sanity(buf) != 0)
		واپس;
	buf->off = buf->سائز = 0;
	اگر (buf->alloc != SSHBUF_سائز_INIT) {
		اگر ((d = recallocarray(buf->d, buf->alloc, SSHBUF_سائز_INIT,
		    1)) != تہی) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_سائز_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

سائز_t
sshbuf_max_سائز(ثابت ساخت sshbuf *buf)
{
	واپس buf->max_سائز;
}

سائز_t
sshbuf_alloc(ثابت ساخت sshbuf *buf)
{
	واپس buf->alloc;
}

ثابت ساخت sshbuf *
sshbuf_والد(ثابت ساخت sshbuf *buf)
{
	واپس buf->والد;
}

u_int
sshbuf_refcount(ثابت ساخت sshbuf *buf)
{
	واپس buf->refcount;
}

صحیح
sshbuf_سیٹ_max_سائز(ساخت sshbuf *buf, سائز_t max_سائز)
{
	سائز_t rlen;
	u_char *dp;
	صحیح r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_سائز));
	اگر ((r = sshbuf_check_sanity(buf)) != 0)
		واپس r;
	اگر (max_سائز == buf->max_سائز)
		واپس 0;
	اگر (buf->readonly || buf->refcount > 1)
		واپس SSH_ERR_بفر_READ_ONLY;
	اگر (max_سائز > SSHBUF_سائز_MAX)
		واپس SSH_ERR_NO_بفر_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_سائز < buf->سائز);
	اگر (max_سائز < buf->alloc && max_سائز > buf->سائز) {
		اگر (buf->سائز < SSHBUF_سائز_INIT)
			rlen = SSHBUF_سائز_INIT;
		ورنہ
			rlen = ROUNDUP(buf->سائز, SSHBUF_سائز_INC);
		اگر (rlen > max_سائز)
			rlen = max_سائز;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		اگر ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == تہی)
			واپس SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	اگر (max_سائز < buf->alloc)
		واپس SSH_ERR_NO_بفر_SPACE;
	buf->max_سائز = max_سائز;
	واپس 0;
}

سائز_t
sshbuf_len(ثابت ساخت sshbuf *buf)
{
	اگر (sshbuf_check_sanity(buf) != 0)
		واپس 0;
	واپس buf->سائز - buf->off;
}

سائز_t
sshbuf_avail(ثابت ساخت sshbuf *buf)
{
	اگر (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		واپس 0;
	واپس buf->max_سائز - (buf->سائز - buf->off);
}

ثابت u_char *
sshbuf_ptr(ثابت ساخت sshbuf *buf)
{
	اگر (sshbuf_check_sanity(buf) != 0)
		واپس تہی;
	واپس buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(ثابت ساخت sshbuf *buf)
{
	اگر (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		واپس تہی;
	واپس buf->d + buf->off;
}

صحیح
sshbuf_check_reserve(ثابت ساخت sshbuf *buf, سائز_t len)
{
	صحیح r;

	اگر ((r = sshbuf_check_sanity(buf)) != 0)
		واپس r;
	اگر (buf->readonly || buf->refcount > 1)
		واپس SSH_ERR_بفر_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	اگر (len > buf->max_سائز || buf->max_سائز - len < buf->سائز - buf->off)
		واپس SSH_ERR_NO_بفر_SPACE;
	واپس 0;
}

صحیح
sshbuf_allocate(ساخت sshbuf *buf, سائز_t len)
{
	سائز_t rlen, need;
	u_char *dp;
	صحیح r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	اگر ((r = sshbuf_check_reserve(buf, len)) != 0)
		واپس r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->سائز + len > buf->max_سائز);
	SSHBUF_TELL("allocate");
	اگر (len + buf->سائز <= buf->alloc)
		واپس 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->سائز - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_سائز_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	اگر (rlen > buf->max_سائز)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	اگر ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == تہی) {
		SSHBUF_DBG(("realloc fail"));
		واپس SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	اگر ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		واپس r;
	}
	SSHBUF_TELL("done");
	واپس 0;
}

صحیح
sshbuf_reserve(ساخت sshbuf *buf, سائز_t len, u_char **dpp)
{
	u_char *dp;
	صحیح r;

	اگر (dpp != تہی)
		*dpp = تہی;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	اگر ((r = sshbuf_allocate(buf, len)) != 0)
		واپس r;

	dp = buf->d + buf->سائز;
	buf->سائز += len;
	اگر (dpp != تہی)
		*dpp = dp;
	واپس 0;
}

صحیح
sshbuf_consume(ساخت sshbuf *buf, سائز_t len)
{
	صحیح r;

	SSHBUF_DBG(("len = %zu", len));
	اگر ((r = sshbuf_check_sanity(buf)) != 0)
		واپس r;
	اگر (len == 0)
		واپس 0;
	اگر (len > sshbuf_len(buf))
		واپس SSH_ERR_پیغام_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	اگر (buf->off == buf->سائز)
		buf->off = buf->سائز = 0;
	SSHBUF_TELL("done");
	واپس 0;
}

صحیح
sshbuf_consume_انتہا(ساخت sshbuf *buf, سائز_t len)
{
	صحیح r;

	SSHBUF_DBG(("len = %zu", len));
	اگر ((r = sshbuf_check_sanity(buf)) != 0)
		واپس r;
	اگر (len == 0)
		واپس 0;
	اگر (len > sshbuf_len(buf))
		واپس SSH_ERR_پیغام_INCOMPLETE;
	buf->سائز -= len;
	SSHBUF_TELL("done");
	واپس 0;
}

صحیح
sshbuf_consume_upto_بچہ(ساخت sshbuf *buf, ثابت ساخت sshbuf *بچہ)
{
	صحیح r;

	اگر ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(بچہ)) != 0)
		واپس r;
	/* This function is only used for parent/child buffers */
	اگر (بچہ->والد != buf)
		واپس SSH_ERR_INVALID_دلیل;
	/* Nonsensical if the parent has advanced past the child */
	اگر (sshbuf_len(بچہ) > sshbuf_len(buf))
		واپس SSH_ERR_INVALID_دلیل;
	/* More paranoia, shouldn't happen */
	اگر (بچہ->cd < buf->cd)
		واپس SSH_ERR_اندرونی_ERROR;
	/* Advance */
	واپس sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(بچہ));
}
