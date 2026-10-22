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
#define SSHBUF_INTERNAL
#ضمن "sshbuf.h"
#ضمن "misc.h"

#ifdef SSHBUF_DEBUG
# define SSHBUF_TELL(what) افعل { \
		printf("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __FILE__, __LINE__, __func__, what, \
		    buf->size, buf->alloc, buf->off, buf->max_size); \
		fflush(stdout); \
	} بينما (0)
#وإلا
# define SSHBUF_TELL(what)
#endif

بنية sshbuf {
	u_char *d;		/* Data */
	ثابت u_char *cd;	/* Const data */
	size_t off;		/* First available byte is buf->d + buf->off */
	size_t size;		/* Last byte is buf->d + buf->size - 1 */
	size_t max_size;	/* Maximum size of buffer */
	size_t alloc;		/* Total bytes allocated to buf->d */
	صحيح readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	بنية sshbuf *parent;	/* If child, pointer to parent */
};

ساكن مضمن صحيح
sshbuf_check_sanity(ثابت بنية sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	إذا (__predict_false(buf == عدم ||
	    (!buf->readonly && buf->d != buf->cd) ||
	    buf->parent == buf ||
	    buf->refcount < 1 || buf->refcount > SSHBUF_REFS_MAX ||
	    buf->cd == عدم ||
	    buf->max_size > SSHBUF_SIZE_MAX ||
	    buf->alloc > buf->max_size ||
	    buf->size > buf->alloc ||
	    buf->off > buf->size)) {
		/* Do not try to recover from corrupted buffer internals */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		ssh_signal(SIGSEGV, SIG_DFL);
		ارفع(SIGSEGV);
		إرجاع SSH_ERR_INTERNAL_ERROR;
	}
	إرجاع 0;
}

ساكن فراغ
sshbuf_maybe_pack(بنية sshbuf *buf, صحيح force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	إذا (buf->off == 0 || buf->readonly || buf->refcount > 1)
		إرجاع;
	إذا (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->size / 2)) {
		memmove(buf->d, buf->d + buf->off, buf->size - buf->off);
		buf->size -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

بنية sshbuf *
sshbuf_new(فراغ)
{
	بنية sshbuf *ret;

	إذا ((ret = calloc(1, حجم(*ret))) == عدم)
		إرجاع عدم;
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_size = SSHBUF_SIZE_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->parent = عدم;
	إذا ((ret->cd = ret->d = calloc(1, ret->alloc)) == عدم) {
		حرر(ret);
		إرجاع عدم;
	}
	إرجاع ret;
}

بنية sshbuf *
sshbuf_from(ثابت فراغ *blob, size_t len)
{
	بنية sshbuf *ret;

	إذا (blob == عدم || len > SSHBUF_SIZE_MAX ||
	    (ret = calloc(1, حجم(*ret))) == عدم)
		إرجاع عدم;
	ret->alloc = ret->size = ret->max_size = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->parent = عدم;
	ret->cd = blob;
	ret->d = عدم;
	إرجاع ret;
}

صحيح
sshbuf_set_parent(بنية sshbuf *child, بنية sshbuf *parent)
{
	صحيح r;

	إذا ((r = sshbuf_check_sanity(child)) != 0 ||
	    (r = sshbuf_check_sanity(parent)) != 0)
		إرجاع r;
	إذا ((child->parent != عدم && child->parent != parent) ||
	    child == parent)
		إرجاع SSH_ERR_INTERNAL_ERROR;
	child->parent = parent;
	child->parent->refcount++;
	إرجاع 0;
}

بنية sshbuf *
sshbuf_fromb(بنية sshbuf *buf)
{
	بنية sshbuf *ret;

	إذا (sshbuf_check_sanity(buf) != 0)
		إرجاع عدم;
	إذا ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == عدم)
		إرجاع عدم;
	إذا (sshbuf_set_parent(ret, buf) != 0) {
		sshbuf_free(ret);
		إرجاع عدم;
	}
	إرجاع ret;
}

فراغ
sshbuf_free(بنية sshbuf *buf)
{
	إذا (buf == عدم)
		إرجاع;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	إذا (sshbuf_check_sanity(buf) != 0)
		إرجاع;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	إذا (buf->refcount > 0)
		إرجاع;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->parent);
	buf->parent = عدم;

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
		buf->off = buf->size;
		إرجاع;
	}
	إذا (sshbuf_check_sanity(buf) != 0)
		إرجاع;
	buf->off = buf->size = 0;
	إذا (buf->alloc != SSHBUF_SIZE_INIT) {
		إذا ((d = recallocarray(buf->d, buf->alloc, SSHBUF_SIZE_INIT,
		    1)) != عدم) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_SIZE_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

size_t
sshbuf_max_size(ثابت بنية sshbuf *buf)
{
	إرجاع buf->max_size;
}

size_t
sshbuf_alloc(ثابت بنية sshbuf *buf)
{
	إرجاع buf->alloc;
}

ثابت بنية sshbuf *
sshbuf_parent(ثابت بنية sshbuf *buf)
{
	إرجاع buf->parent;
}

u_int
sshbuf_refcount(ثابت بنية sshbuf *buf)
{
	إرجاع buf->refcount;
}

صحيح
sshbuf_set_max_size(بنية sshbuf *buf, size_t max_size)
{
	size_t rlen;
	u_char *dp;
	صحيح r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_size));
	إذا ((r = sshbuf_check_sanity(buf)) != 0)
		إرجاع r;
	إذا (max_size == buf->max_size)
		إرجاع 0;
	إذا (buf->readonly || buf->refcount > 1)
		إرجاع SSH_ERR_BUFFER_READ_ONLY;
	إذا (max_size > SSHBUF_SIZE_MAX)
		إرجاع SSH_ERR_NO_BUFFER_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_size < buf->size);
	إذا (max_size < buf->alloc && max_size > buf->size) {
		إذا (buf->size < SSHBUF_SIZE_INIT)
			rlen = SSHBUF_SIZE_INIT;
		وإلا
			rlen = ROUNDUP(buf->size, SSHBUF_SIZE_INC);
		إذا (rlen > max_size)
			rlen = max_size;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		إذا ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == عدم)
			إرجاع SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	إذا (max_size < buf->alloc)
		إرجاع SSH_ERR_NO_BUFFER_SPACE;
	buf->max_size = max_size;
	إرجاع 0;
}

size_t
sshbuf_len(ثابت بنية sshbuf *buf)
{
	إذا (sshbuf_check_sanity(buf) != 0)
		إرجاع 0;
	إرجاع buf->size - buf->off;
}

size_t
sshbuf_avail(ثابت بنية sshbuf *buf)
{
	إذا (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		إرجاع 0;
	إرجاع buf->max_size - (buf->size - buf->off);
}

ثابت u_char *
sshbuf_ptr(ثابت بنية sshbuf *buf)
{
	إذا (sshbuf_check_sanity(buf) != 0)
		إرجاع عدم;
	إرجاع buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(ثابت بنية sshbuf *buf)
{
	إذا (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		إرجاع عدم;
	إرجاع buf->d + buf->off;
}

صحيح
sshbuf_check_reserve(ثابت بنية sshbuf *buf, size_t len)
{
	صحيح r;

	إذا ((r = sshbuf_check_sanity(buf)) != 0)
		إرجاع r;
	إذا (buf->readonly || buf->refcount > 1)
		إرجاع SSH_ERR_BUFFER_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	إذا (len > buf->max_size || buf->max_size - len < buf->size - buf->off)
		إرجاع SSH_ERR_NO_BUFFER_SPACE;
	إرجاع 0;
}

صحيح
sshbuf_allocate(بنية sshbuf *buf, size_t len)
{
	size_t rlen, need;
	u_char *dp;
	صحيح r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	إذا ((r = sshbuf_check_reserve(buf, len)) != 0)
		إرجاع r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->size + len > buf->max_size);
	SSHBUF_TELL("allocate");
	إذا (len + buf->size <= buf->alloc)
		إرجاع 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->size - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_SIZE_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	إذا (rlen > buf->max_size)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	إذا ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == عدم) {
		SSHBUF_DBG(("realloc fail"));
		إرجاع SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	إذا ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		إرجاع r;
	}
	SSHBUF_TELL("done");
	إرجاع 0;
}

صحيح
sshbuf_reserve(بنية sshbuf *buf, size_t len, u_char **dpp)
{
	u_char *dp;
	صحيح r;

	إذا (dpp != عدم)
		*dpp = عدم;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	إذا ((r = sshbuf_allocate(buf, len)) != 0)
		إرجاع r;

	dp = buf->d + buf->size;
	buf->size += len;
	إذا (dpp != عدم)
		*dpp = dp;
	إرجاع 0;
}

صحيح
sshbuf_consume(بنية sshbuf *buf, size_t len)
{
	صحيح r;

	SSHBUF_DBG(("len = %zu", len));
	إذا ((r = sshbuf_check_sanity(buf)) != 0)
		إرجاع r;
	إذا (len == 0)
		إرجاع 0;
	إذا (len > sshbuf_len(buf))
		إرجاع SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	إذا (buf->off == buf->size)
		buf->off = buf->size = 0;
	SSHBUF_TELL("done");
	إرجاع 0;
}

صحيح
sshbuf_consume_end(بنية sshbuf *buf, size_t len)
{
	صحيح r;

	SSHBUF_DBG(("len = %zu", len));
	إذا ((r = sshbuf_check_sanity(buf)) != 0)
		إرجاع r;
	إذا (len == 0)
		إرجاع 0;
	إذا (len > sshbuf_len(buf))
		إرجاع SSH_ERR_MESSAGE_INCOMPLETE;
	buf->size -= len;
	SSHBUF_TELL("done");
	إرجاع 0;
}

صحيح
sshbuf_consume_upto_child(بنية sshbuf *buf, ثابت بنية sshbuf *child)
{
	صحيح r;

	إذا ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(child)) != 0)
		إرجاع r;
	/* This function is only used for parent/child buffers */
	إذا (child->parent != buf)
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	/* Nonsensical if the parent has advanced past the child */
	إذا (sshbuf_len(child) > sshbuf_len(buf))
		إرجاع SSH_ERR_INVALID_ARGUMENT;
	/* More paranoia, shouldn't happen */
	إذا (child->cd < buf->cd)
		إرجاع SSH_ERR_INTERNAL_ERROR;
	/* Advance */
	إرجاع sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(child));
}
