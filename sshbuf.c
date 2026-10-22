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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব "ssherr.h"
#define SSHBUF_INTERNAL
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "misc.h"

#ifdef SSHBUF_DEBUG
# define SSHBUF_TELL(what) করো { \
		printf("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __FILE__, __LINE__, __func__, what, \
		    buf->আকার_2, buf->alloc, buf->off, buf->max_আকার); \
		fflush(stdout); \
	} যখন (0)
#অন্যথা
# define SSHBUF_TELL(what)
#endif

কাঠামো sshbuf {
	u_char *d;		/* Data */
	ধ্রুবক u_char *cd;	/* Const data */
	আকার_t off;		/* First available byte is buf->d + buf->off */
	আকার_t আকার_2;		/* Last byte is buf->d + buf->size - 1 */
	আকার_t max_আকার;	/* Maximum size of buffer */
	আকার_t alloc;		/* Total bytes allocated to buf->d */
	পূর্ণসংখ্যা readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	কাঠামো sshbuf *parent;	/* If child, pointer to parent */
};

স্থির অন্তঃরেখ পূর্ণসংখ্যা
sshbuf_check_sanity(ধ্রুবক কাঠামো sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	যদি (__predict_false(buf == ফাঁকা ||
	    (!buf->readonly && buf->d != buf->cd) ||
	    buf->parent == buf ||
	    buf->refcount < 1 || buf->refcount > SSHBUF_REFS_MAX ||
	    buf->cd == ফাঁকা ||
	    buf->max_আকার > SSHBUF_আকার_MAX ||
	    buf->alloc > buf->max_আকার ||
	    buf->আকার_2 > buf->alloc ||
	    buf->off > buf->আকার_2)) {
		/* Do not try to recover from corrupted buffer internals */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		ssh_signal(SIGSEGV, SIG_DFL);
		তোলো(SIGSEGV);
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	ফেরত 0;
}

স্থির শূন্য
sshbuf_maybe_pack(কাঠামো sshbuf *buf, পূর্ণসংখ্যা force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	যদি (buf->off == 0 || buf->readonly || buf->refcount > 1)
		ফেরত;
	যদি (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->আকার_2 / 2)) {
		memmove(buf->d, buf->d + buf->off, buf->আকার_2 - buf->off);
		buf->আকার_2 -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

কাঠামো sshbuf *
sshbuf_new(শূন্য)
{
	কাঠামো sshbuf *ret;

	যদি ((ret = calloc(1, আকার(*ret))) == ফাঁকা)
		ফেরত ফাঁকা;
	ret->alloc = SSHBUF_আকার_INIT;
	ret->max_আকার = SSHBUF_আকার_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->parent = ফাঁকা;
	যদি ((ret->cd = ret->d = calloc(1, ret->alloc)) == ফাঁকা) {
		মুক্ত(ret);
		ফেরত ফাঁকা;
	}
	ফেরত ret;
}

কাঠামো sshbuf *
sshbuf_from(ধ্রুবক শূন্য *blob, আকার_t len)
{
	কাঠামো sshbuf *ret;

	যদি (blob == ফাঁকা || len > SSHBUF_আকার_MAX ||
	    (ret = calloc(1, আকার(*ret))) == ফাঁকা)
		ফেরত ফাঁকা;
	ret->alloc = ret->আকার_2 = ret->max_আকার = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->parent = ফাঁকা;
	ret->cd = blob;
	ret->d = ফাঁকা;
	ফেরত ret;
}

পূর্ণসংখ্যা
sshbuf_set_parent(কাঠামো sshbuf *child, কাঠামো sshbuf *parent)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_check_sanity(child)) != 0 ||
	    (r = sshbuf_check_sanity(parent)) != 0)
		ফেরত r;
	যদি ((child->parent != ফাঁকা && child->parent != parent) ||
	    child == parent)
		ফেরত SSH_ERR_INTERNAL_ERROR;
	child->parent = parent;
	child->parent->refcount++;
	ফেরত 0;
}

কাঠামো sshbuf *
sshbuf_fromb(কাঠামো sshbuf *buf)
{
	কাঠামো sshbuf *ret;

	যদি (sshbuf_check_sanity(buf) != 0)
		ফেরত ফাঁকা;
	যদি ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == ফাঁকা)
		ফেরত ফাঁকা;
	যদি (sshbuf_set_parent(ret, buf) != 0) {
		sshbuf_free(ret);
		ফেরত ফাঁকা;
	}
	ফেরত ret;
}

শূন্য
sshbuf_free(কাঠামো sshbuf *buf)
{
	যদি (buf == ফাঁকা)
		ফেরত;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	যদি (sshbuf_check_sanity(buf) != 0)
		ফেরত;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	যদি (buf->refcount > 0)
		ফেরত;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->parent);
	buf->parent = ফাঁকা;

	যদি (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, আকার(*buf));
}

শূন্য
sshbuf_reset(কাঠামো sshbuf *buf)
{
	u_char *d;

	যদি (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->আকার_2;
		ফেরত;
	}
	যদি (sshbuf_check_sanity(buf) != 0)
		ফেরত;
	buf->off = buf->আকার_2 = 0;
	যদি (buf->alloc != SSHBUF_আকার_INIT) {
		যদি ((d = recallocarray(buf->d, buf->alloc, SSHBUF_আকার_INIT,
		    1)) != ফাঁকা) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_আকার_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

আকার_t
sshbuf_max_আকার(ধ্রুবক কাঠামো sshbuf *buf)
{
	ফেরত buf->max_আকার;
}

আকার_t
sshbuf_alloc(ধ্রুবক কাঠামো sshbuf *buf)
{
	ফেরত buf->alloc;
}

ধ্রুবক কাঠামো sshbuf *
sshbuf_parent(ধ্রুবক কাঠামো sshbuf *buf)
{
	ফেরত buf->parent;
}

u_int
sshbuf_refcount(ধ্রুবক কাঠামো sshbuf *buf)
{
	ফেরত buf->refcount;
}

পূর্ণসংখ্যা
sshbuf_set_max_আকার(কাঠামো sshbuf *buf, আকার_t max_আকার)
{
	আকার_t rlen;
	u_char *dp;
	পূর্ণসংখ্যা r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_আকার));
	যদি ((r = sshbuf_check_sanity(buf)) != 0)
		ফেরত r;
	যদি (max_আকার == buf->max_আকার)
		ফেরত 0;
	যদি (buf->readonly || buf->refcount > 1)
		ফেরত SSH_ERR_বাফার_READ_ONLY;
	যদি (max_আকার > SSHBUF_আকার_MAX)
		ফেরত SSH_ERR_NO_বাফার_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_আকার < buf->আকার_2);
	যদি (max_আকার < buf->alloc && max_আকার > buf->আকার_2) {
		যদি (buf->আকার_2 < SSHBUF_আকার_INIT)
			rlen = SSHBUF_আকার_INIT;
		অন্যথা
			rlen = ROUNDUP(buf->আকার_2, SSHBUF_আকার_INC);
		যদি (rlen > max_আকার)
			rlen = max_আকার;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		যদি ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == ফাঁকা)
			ফেরত SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	যদি (max_আকার < buf->alloc)
		ফেরত SSH_ERR_NO_বাফার_SPACE;
	buf->max_আকার = max_আকার;
	ফেরত 0;
}

আকার_t
sshbuf_len(ধ্রুবক কাঠামো sshbuf *buf)
{
	যদি (sshbuf_check_sanity(buf) != 0)
		ফেরত 0;
	ফেরত buf->আকার_2 - buf->off;
}

আকার_t
sshbuf_avail(ধ্রুবক কাঠামো sshbuf *buf)
{
	যদি (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		ফেরত 0;
	ফেরত buf->max_আকার - (buf->আকার_2 - buf->off);
}

ধ্রুবক u_char *
sshbuf_ptr(ধ্রুবক কাঠামো sshbuf *buf)
{
	যদি (sshbuf_check_sanity(buf) != 0)
		ফেরত ফাঁকা;
	ফেরত buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(ধ্রুবক কাঠামো sshbuf *buf)
{
	যদি (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		ফেরত ফাঁকা;
	ফেরত buf->d + buf->off;
}

পূর্ণসংখ্যা
sshbuf_check_reserve(ধ্রুবক কাঠামো sshbuf *buf, আকার_t len)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_check_sanity(buf)) != 0)
		ফেরত r;
	যদি (buf->readonly || buf->refcount > 1)
		ফেরত SSH_ERR_বাফার_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	যদি (len > buf->max_আকার || buf->max_আকার - len < buf->আকার_2 - buf->off)
		ফেরত SSH_ERR_NO_বাফার_SPACE;
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_allocate(কাঠামো sshbuf *buf, আকার_t len)
{
	আকার_t rlen, need;
	u_char *dp;
	পূর্ণসংখ্যা r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	যদি ((r = sshbuf_check_reserve(buf, len)) != 0)
		ফেরত r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->আকার_2 + len > buf->max_আকার);
	SSHBUF_TELL("allocate");
	যদি (len + buf->আকার_2 <= buf->alloc)
		ফেরত 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->আকার_2 - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_আকার_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	যদি (rlen > buf->max_আকার)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	যদি ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == ফাঁকা) {
		SSHBUF_DBG(("realloc fail"));
		ফেরত SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	যদি ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		ফেরত r;
	}
	SSHBUF_TELL("done");
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_reserve(কাঠামো sshbuf *buf, আকার_t len, u_char **dpp)
{
	u_char *dp;
	পূর্ণসংখ্যা r;

	যদি (dpp != ফাঁকা)
		*dpp = ফাঁকা;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	যদি ((r = sshbuf_allocate(buf, len)) != 0)
		ফেরত r;

	dp = buf->d + buf->আকার_2;
	buf->আকার_2 += len;
	যদি (dpp != ফাঁকা)
		*dpp = dp;
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_consume(কাঠামো sshbuf *buf, আকার_t len)
{
	পূর্ণসংখ্যা r;

	SSHBUF_DBG(("len = %zu", len));
	যদি ((r = sshbuf_check_sanity(buf)) != 0)
		ফেরত r;
	যদি (len == 0)
		ফেরত 0;
	যদি (len > sshbuf_len(buf))
		ফেরত SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	যদি (buf->off == buf->আকার_2)
		buf->off = buf->আকার_2 = 0;
	SSHBUF_TELL("done");
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_consume_end(কাঠামো sshbuf *buf, আকার_t len)
{
	পূর্ণসংখ্যা r;

	SSHBUF_DBG(("len = %zu", len));
	যদি ((r = sshbuf_check_sanity(buf)) != 0)
		ফেরত r;
	যদি (len == 0)
		ফেরত 0;
	যদি (len > sshbuf_len(buf))
		ফেরত SSH_ERR_MESSAGE_INCOMPLETE;
	buf->আকার_2 -= len;
	SSHBUF_TELL("done");
	ফেরত 0;
}

পূর্ণসংখ্যা
sshbuf_consume_upto_child(কাঠামো sshbuf *buf, ধ্রুবক কাঠামো sshbuf *child)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(child)) != 0)
		ফেরত r;
	/* This function is only used for parent/child buffers */
	যদি (child->parent != buf)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	/* Nonsensical if the parent has advanced past the child */
	যদি (sshbuf_len(child) > sshbuf_len(buf))
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	/* More paranoia, shouldn't happen */
	যদি (child->cd < buf->cd)
		ফেরত SSH_ERR_INTERNAL_ERROR;
	/* Advance */
	ফেরত sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(child));
}
