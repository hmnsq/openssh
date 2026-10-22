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
# define SSHBUF_TELL(what) 𐡏𐡁𐡃 { \
		printf("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __FILE__, __LINE__, __func__, what, \
		    buf->size, buf->alloc, buf->off, buf->max_size); \
		fflush(stdout); \
	} طالما (0)
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
	𐡄𐡍 (__predict_false(buf == عدم ||
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
		أرجع SSH_ERR_INTERNAL_ERROR;
	}
	أرجع 0;
}

ساكن فراغ
sshbuf_maybe_pack(بنية sshbuf *buf, صحيح force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	𐡄𐡍 (buf->off == 0 || buf->readonly || buf->refcount > 1)
		أرجع;
	𐡄𐡍 (force ||
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

	𐡄𐡍 ((ret = calloc(1, حجم(*ret))) == عدم)
		أرجع عدم;
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_size = SSHBUF_SIZE_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->parent = عدم;
	𐡄𐡍 ((ret->cd = ret->d = calloc(1, ret->alloc)) == عدم) {
		حرر(ret);
		أرجع عدم;
	}
	أرجع ret;
}

بنية sshbuf *
sshbuf_from(ثابت فراغ *blob, size_t len)
{
	بنية sshbuf *ret;

	𐡄𐡍 (blob == عدم || len > SSHBUF_SIZE_MAX ||
	    (ret = calloc(1, حجم(*ret))) == عدم)
		أرجع عدم;
	ret->alloc = ret->size = ret->max_size = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->parent = عدم;
	ret->cd = blob;
	ret->d = عدم;
	أرجع ret;
}

صحيح
sshbuf_set_parent(بنية sshbuf *child, بنية sshbuf *parent)
{
	صحيح r;

	𐡄𐡍 ((r = sshbuf_check_sanity(child)) != 0 ||
	    (r = sshbuf_check_sanity(parent)) != 0)
		أرجع r;
	𐡄𐡍 ((child->parent != عدم && child->parent != parent) ||
	    child == parent)
		أرجع SSH_ERR_INTERNAL_ERROR;
	child->parent = parent;
	child->parent->refcount++;
	أرجع 0;
}

بنية sshbuf *
sshbuf_fromb(بنية sshbuf *buf)
{
	بنية sshbuf *ret;

	𐡄𐡍 (sshbuf_check_sanity(buf) != 0)
		أرجع عدم;
	𐡄𐡍 ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == عدم)
		أرجع عدم;
	𐡄𐡍 (sshbuf_set_parent(ret, buf) != 0) {
		sshbuf_free(ret);
		أرجع عدم;
	}
	أرجع ret;
}

فراغ
sshbuf_free(بنية sshbuf *buf)
{
	𐡄𐡍 (buf == عدم)
		أرجع;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	𐡄𐡍 (sshbuf_check_sanity(buf) != 0)
		أرجع;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	𐡄𐡍 (buf->refcount > 0)
		أرجع;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->parent);
	buf->parent = عدم;

	𐡄𐡍 (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, حجم(*buf));
}

فراغ
sshbuf_reset(بنية sshbuf *buf)
{
	u_char *d;

	𐡄𐡍 (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->size;
		أرجع;
	}
	𐡄𐡍 (sshbuf_check_sanity(buf) != 0)
		أرجع;
	buf->off = buf->size = 0;
	𐡄𐡍 (buf->alloc != SSHBUF_SIZE_INIT) {
		𐡄𐡍 ((d = recallocarray(buf->d, buf->alloc, SSHBUF_SIZE_INIT,
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
	أرجع buf->max_size;
}

size_t
sshbuf_alloc(ثابت بنية sshbuf *buf)
{
	أرجع buf->alloc;
}

ثابت بنية sshbuf *
sshbuf_parent(ثابت بنية sshbuf *buf)
{
	أرجع buf->parent;
}

u_int
sshbuf_refcount(ثابت بنية sshbuf *buf)
{
	أرجع buf->refcount;
}

صحيح
sshbuf_set_max_size(بنية sshbuf *buf, size_t max_size)
{
	size_t rlen;
	u_char *dp;
	صحيح r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_size));
	𐡄𐡍 ((r = sshbuf_check_sanity(buf)) != 0)
		أرجع r;
	𐡄𐡍 (max_size == buf->max_size)
		أرجع 0;
	𐡄𐡍 (buf->readonly || buf->refcount > 1)
		أرجع SSH_ERR_BUFFER_READ_ONLY;
	𐡄𐡍 (max_size > SSHBUF_SIZE_MAX)
		أرجع SSH_ERR_NO_BUFFER_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_size < buf->size);
	𐡄𐡍 (max_size < buf->alloc && max_size > buf->size) {
		𐡄𐡍 (buf->size < SSHBUF_SIZE_INIT)
			rlen = SSHBUF_SIZE_INIT;
		وإلا
			rlen = ROUNDUP(buf->size, SSHBUF_SIZE_INC);
		𐡄𐡍 (rlen > max_size)
			rlen = max_size;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		𐡄𐡍 ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == عدم)
			أرجع SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	𐡄𐡍 (max_size < buf->alloc)
		أرجع SSH_ERR_NO_BUFFER_SPACE;
	buf->max_size = max_size;
	أرجع 0;
}

size_t
sshbuf_len(ثابت بنية sshbuf *buf)
{
	𐡄𐡍 (sshbuf_check_sanity(buf) != 0)
		أرجع 0;
	أرجع buf->size - buf->off;
}

size_t
sshbuf_avail(ثابت بنية sshbuf *buf)
{
	𐡄𐡍 (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		أرجع 0;
	أرجع buf->max_size - (buf->size - buf->off);
}

ثابت u_char *
sshbuf_ptr(ثابت بنية sshbuf *buf)
{
	𐡄𐡍 (sshbuf_check_sanity(buf) != 0)
		أرجع عدم;
	أرجع buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(ثابت بنية sshbuf *buf)
{
	𐡄𐡍 (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		أرجع عدم;
	أرجع buf->d + buf->off;
}

صحيح
sshbuf_check_reserve(ثابت بنية sshbuf *buf, size_t len)
{
	صحيح r;

	𐡄𐡍 ((r = sshbuf_check_sanity(buf)) != 0)
		أرجع r;
	𐡄𐡍 (buf->readonly || buf->refcount > 1)
		أرجع SSH_ERR_BUFFER_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	𐡄𐡍 (len > buf->max_size || buf->max_size - len < buf->size - buf->off)
		أرجع SSH_ERR_NO_BUFFER_SPACE;
	أرجع 0;
}

صحيح
sshbuf_allocate(بنية sshbuf *buf, size_t len)
{
	size_t rlen, need;
	u_char *dp;
	صحيح r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	𐡄𐡍 ((r = sshbuf_check_reserve(buf, len)) != 0)
		أرجع r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->size + len > buf->max_size);
	SSHBUF_TELL("allocate");
	𐡄𐡍 (len + buf->size <= buf->alloc)
		أرجع 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->size - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_SIZE_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	𐡄𐡍 (rlen > buf->max_size)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	𐡄𐡍 ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == عدم) {
		SSHBUF_DBG(("realloc fail"));
		أرجع SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	𐡄𐡍 ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		أرجع r;
	}
	SSHBUF_TELL("done");
	أرجع 0;
}

صحيح
sshbuf_reserve(بنية sshbuf *buf, size_t len, u_char **dpp)
{
	u_char *dp;
	صحيح r;

	𐡄𐡍 (dpp != عدم)
		*dpp = عدم;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	𐡄𐡍 ((r = sshbuf_allocate(buf, len)) != 0)
		أرجع r;

	dp = buf->d + buf->size;
	buf->size += len;
	𐡄𐡍 (dpp != عدم)
		*dpp = dp;
	أرجع 0;
}

صحيح
sshbuf_consume(بنية sshbuf *buf, size_t len)
{
	صحيح r;

	SSHBUF_DBG(("len = %zu", len));
	𐡄𐡍 ((r = sshbuf_check_sanity(buf)) != 0)
		أرجع r;
	𐡄𐡍 (len == 0)
		أرجع 0;
	𐡄𐡍 (len > sshbuf_len(buf))
		أرجع SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	𐡄𐡍 (buf->off == buf->size)
		buf->off = buf->size = 0;
	SSHBUF_TELL("done");
	أرجع 0;
}

صحيح
sshbuf_consume_end(بنية sshbuf *buf, size_t len)
{
	صحيح r;

	SSHBUF_DBG(("len = %zu", len));
	𐡄𐡍 ((r = sshbuf_check_sanity(buf)) != 0)
		أرجع r;
	𐡄𐡍 (len == 0)
		أرجع 0;
	𐡄𐡍 (len > sshbuf_len(buf))
		أرجع SSH_ERR_MESSAGE_INCOMPLETE;
	buf->size -= len;
	SSHBUF_TELL("done");
	أرجع 0;
}

صحيح
sshbuf_consume_upto_child(بنية sshbuf *buf, ثابت بنية sshbuf *child)
{
	صحيح r;

	𐡄𐡍 ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(child)) != 0)
		أرجع r;
	/* This function is only used for parent/child buffers */
	𐡄𐡍 (child->parent != buf)
		أرجع SSH_ERR_INVALID_ARGUMENT;
	/* Nonsensical if the parent has advanced past the child */
	𐡄𐡍 (sshbuf_len(child) > sshbuf_len(buf))
		أرجع SSH_ERR_INVALID_ARGUMENT;
	/* More paranoia, shouldn't happen */
	𐡄𐡍 (child->cd < buf->cd)
		أرجع SSH_ERR_INTERNAL_ERROR;
	/* Advance */
	أرجع sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(child));
}
