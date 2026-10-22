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
# define SSHBUF_TELL(what) কুরু { \
		printf("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __FILE__, __LINE__, __func__, what, \
		    buf->size, buf->alloc, buf->off, buf->max_size); \
		fflush(stdout); \
	} যাবত্ (0)
#অন্যথা
# define SSHBUF_TELL(what)
#endif

সংরচনা sshbuf {
	u_char *d;		/* Data */
	ধ্রুব u_char *cd;	/* Const data */
	size_t off;		/* First available byte is buf->d + buf->off */
	size_t size;		/* Last byte is buf->d + buf->size - 1 */
	size_t max_size;	/* Maximum size of buffer */
	size_t alloc;		/* Total bytes allocated to buf->d */
	পূর্ণাঙ্ক readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	সংরচনা sshbuf *parent;	/* If child, pointer to parent */
};

স্থির অন্তঃস্থ পূর্ণাঙ্ক
sshbuf_check_sanity(ধ্রুব সংরচনা sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	যদি (__predict_false(buf == রিক্ত ||
	    (!buf->readonly && buf->d != buf->cd) ||
	    buf->parent == buf ||
	    buf->refcount < 1 || buf->refcount > SSHBUF_REFS_MAX ||
	    buf->cd == রিক্ত ||
	    buf->max_size > SSHBUF_SIZE_MAX ||
	    buf->alloc > buf->max_size ||
	    buf->size > buf->alloc ||
	    buf->off > buf->size)) {
		/* Do not try to recover from corrupted buffer internals */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		ssh_signal(SIGSEGV, SIG_DFL);
		উত্থাপয(SIGSEGV);
		প্রত্যাগম SSH_ERR_INTERNAL_ERROR;
	}
	প্রত্যাগম 0;
}

স্থির শূন্য
sshbuf_maybe_pack(সংরচনা sshbuf *buf, পূর্ণাঙ্ক force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	যদি (buf->off == 0 || buf->readonly || buf->refcount > 1)
		প্রত্যাগম;
	যদি (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->size / 2)) {
		memmove(buf->d, buf->d + buf->off, buf->size - buf->off);
		buf->size -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

সংরচনা sshbuf *
sshbuf_new(শূন্য)
{
	সংরচনা sshbuf *ret;

	যদি ((ret = calloc(1, পরিমাণ(*ret))) == রিক্ত)
		প্রত্যাগম রিক্ত;
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_size = SSHBUF_SIZE_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->parent = রিক্ত;
	যদি ((ret->cd = ret->d = calloc(1, ret->alloc)) == রিক্ত) {
		মুক্ত(ret);
		প্রত্যাগম রিক্ত;
	}
	প্রত্যাগম ret;
}

সংরচনা sshbuf *
sshbuf_from(ধ্রুব শূন্য *blob, size_t len)
{
	সংরচনা sshbuf *ret;

	যদি (blob == রিক্ত || len > SSHBUF_SIZE_MAX ||
	    (ret = calloc(1, পরিমাণ(*ret))) == রিক্ত)
		প্রত্যাগম রিক্ত;
	ret->alloc = ret->size = ret->max_size = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->parent = রিক্ত;
	ret->cd = blob;
	ret->d = রিক্ত;
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
sshbuf_set_parent(সংরচনা sshbuf *child, সংরচনা sshbuf *parent)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_check_sanity(child)) != 0 ||
	    (r = sshbuf_check_sanity(parent)) != 0)
		প্রত্যাগম r;
	যদি ((child->parent != রিক্ত && child->parent != parent) ||
	    child == parent)
		প্রত্যাগম SSH_ERR_INTERNAL_ERROR;
	child->parent = parent;
	child->parent->refcount++;
	প্রত্যাগম 0;
}

সংরচনা sshbuf *
sshbuf_fromb(সংরচনা sshbuf *buf)
{
	সংরচনা sshbuf *ret;

	যদি (sshbuf_check_sanity(buf) != 0)
		প্রত্যাগম রিক্ত;
	যদি ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == রিক্ত)
		প্রত্যাগম রিক্ত;
	যদি (sshbuf_set_parent(ret, buf) != 0) {
		sshbuf_free(ret);
		প্রত্যাগম রিক্ত;
	}
	প্রত্যাগম ret;
}

শূন্য
sshbuf_free(সংরচনা sshbuf *buf)
{
	যদি (buf == রিক্ত)
		প্রত্যাগম;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	যদি (sshbuf_check_sanity(buf) != 0)
		প্রত্যাগম;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	যদি (buf->refcount > 0)
		প্রত্যাগম;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->parent);
	buf->parent = রিক্ত;

	যদি (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, পরিমাণ(*buf));
}

শূন্য
sshbuf_reset(সংরচনা sshbuf *buf)
{
	u_char *d;

	যদি (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->size;
		প্রত্যাগম;
	}
	যদি (sshbuf_check_sanity(buf) != 0)
		প্রত্যাগম;
	buf->off = buf->size = 0;
	যদি (buf->alloc != SSHBUF_SIZE_INIT) {
		যদি ((d = recallocarray(buf->d, buf->alloc, SSHBUF_SIZE_INIT,
		    1)) != রিক্ত) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_SIZE_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

size_t
sshbuf_max_size(ধ্রুব সংরচনা sshbuf *buf)
{
	প্রত্যাগম buf->max_size;
}

size_t
sshbuf_alloc(ধ্রুব সংরচনা sshbuf *buf)
{
	প্রত্যাগম buf->alloc;
}

ধ্রুব সংরচনা sshbuf *
sshbuf_parent(ধ্রুব সংরচনা sshbuf *buf)
{
	প্রত্যাগম buf->parent;
}

u_int
sshbuf_refcount(ধ্রুব সংরচনা sshbuf *buf)
{
	প্রত্যাগম buf->refcount;
}

পূর্ণাঙ্ক
sshbuf_set_max_size(সংরচনা sshbuf *buf, size_t max_size)
{
	size_t rlen;
	u_char *dp;
	পূর্ণাঙ্ক r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_size));
	যদি ((r = sshbuf_check_sanity(buf)) != 0)
		প্রত্যাগম r;
	যদি (max_size == buf->max_size)
		প্রত্যাগম 0;
	যদি (buf->readonly || buf->refcount > 1)
		প্রত্যাগম SSH_ERR_BUFFER_READ_ONLY;
	যদি (max_size > SSHBUF_SIZE_MAX)
		প্রত্যাগম SSH_ERR_NO_BUFFER_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_size < buf->size);
	যদি (max_size < buf->alloc && max_size > buf->size) {
		যদি (buf->size < SSHBUF_SIZE_INIT)
			rlen = SSHBUF_SIZE_INIT;
		অন্যথা
			rlen = ROUNDUP(buf->size, SSHBUF_SIZE_INC);
		যদি (rlen > max_size)
			rlen = max_size;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		যদি ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == রিক্ত)
			প্রত্যাগম SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	যদি (max_size < buf->alloc)
		প্রত্যাগম SSH_ERR_NO_BUFFER_SPACE;
	buf->max_size = max_size;
	প্রত্যাগম 0;
}

size_t
sshbuf_len(ধ্রুব সংরচনা sshbuf *buf)
{
	যদি (sshbuf_check_sanity(buf) != 0)
		প্রত্যাগম 0;
	প্রত্যাগম buf->size - buf->off;
}

size_t
sshbuf_avail(ধ্রুব সংরচনা sshbuf *buf)
{
	যদি (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		প্রত্যাগম 0;
	প্রত্যাগম buf->max_size - (buf->size - buf->off);
}

ধ্রুব u_char *
sshbuf_ptr(ধ্রুব সংরচনা sshbuf *buf)
{
	যদি (sshbuf_check_sanity(buf) != 0)
		প্রত্যাগম রিক্ত;
	প্রত্যাগম buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(ধ্রুব সংরচনা sshbuf *buf)
{
	যদি (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		প্রত্যাগম রিক্ত;
	প্রত্যাগম buf->d + buf->off;
}

পূর্ণাঙ্ক
sshbuf_check_reserve(ধ্রুব সংরচনা sshbuf *buf, size_t len)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_check_sanity(buf)) != 0)
		প্রত্যাগম r;
	যদি (buf->readonly || buf->refcount > 1)
		প্রত্যাগম SSH_ERR_BUFFER_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	যদি (len > buf->max_size || buf->max_size - len < buf->size - buf->off)
		প্রত্যাগম SSH_ERR_NO_BUFFER_SPACE;
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
sshbuf_allocate(সংরচনা sshbuf *buf, size_t len)
{
	size_t rlen, need;
	u_char *dp;
	পূর্ণাঙ্ক r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	যদি ((r = sshbuf_check_reserve(buf, len)) != 0)
		প্রত্যাগম r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->size + len > buf->max_size);
	SSHBUF_TELL("allocate");
	যদি (len + buf->size <= buf->alloc)
		প্রত্যাগম 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->size - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_SIZE_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	যদি (rlen > buf->max_size)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	যদি ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == রিক্ত) {
		SSHBUF_DBG(("realloc fail"));
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	যদি ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		প্রত্যাগম r;
	}
	SSHBUF_TELL("done");
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
sshbuf_reserve(সংরচনা sshbuf *buf, size_t len, u_char **dpp)
{
	u_char *dp;
	পূর্ণাঙ্ক r;

	যদি (dpp != রিক্ত)
		*dpp = রিক্ত;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	যদি ((r = sshbuf_allocate(buf, len)) != 0)
		প্রত্যাগম r;

	dp = buf->d + buf->size;
	buf->size += len;
	যদি (dpp != রিক্ত)
		*dpp = dp;
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
sshbuf_consume(সংরচনা sshbuf *buf, size_t len)
{
	পূর্ণাঙ্ক r;

	SSHBUF_DBG(("len = %zu", len));
	যদি ((r = sshbuf_check_sanity(buf)) != 0)
		প্রত্যাগম r;
	যদি (len == 0)
		প্রত্যাগম 0;
	যদি (len > sshbuf_len(buf))
		প্রত্যাগম SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	যদি (buf->off == buf->size)
		buf->off = buf->size = 0;
	SSHBUF_TELL("done");
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
sshbuf_consume_end(সংরচনা sshbuf *buf, size_t len)
{
	পূর্ণাঙ্ক r;

	SSHBUF_DBG(("len = %zu", len));
	যদি ((r = sshbuf_check_sanity(buf)) != 0)
		প্রত্যাগম r;
	যদি (len == 0)
		প্রত্যাগম 0;
	যদি (len > sshbuf_len(buf))
		প্রত্যাগম SSH_ERR_MESSAGE_INCOMPLETE;
	buf->size -= len;
	SSHBUF_TELL("done");
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
sshbuf_consume_upto_child(সংরচনা sshbuf *buf, ধ্রুব সংরচনা sshbuf *child)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(child)) != 0)
		প্রত্যাগম r;
	/* This function is only used for parent/child buffers */
	যদি (child->parent != buf)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	/* Nonsensical if the parent has advanced past the child */
	যদি (sshbuf_len(child) > sshbuf_len(buf))
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	/* More paranoia, shouldn't happen */
	যদি (child->cd < buf->cd)
		প্রত্যাগম SSH_ERR_INTERNAL_ERROR;
	/* Advance */
	প্রত্যাগম sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(child));
}
