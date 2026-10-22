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
#define SSHBUF_INTERNAL
#شامل "sshbuf.h"
#شامل "misc.h"

#ifdef SSHBUF_DEBUG
# define SSHBUF_TELL(what) انجامبده { \
		printf("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __FILE__, __LINE__, __func__, what, \
		    buf->size, buf->alloc, buf->off, buf->max_size); \
		fflush(stdout); \
	} وقتی (0)
#وگرنه
# define SSHBUF_TELL(what)
#endif

ساختار sshbuf {
	u_char *d;		/* Data */
	ثابت u_char *cd;	/* Const data */
	size_t off;		/* First available byte is buf->d + buf->off */
	size_t size;		/* Last byte is buf->d + buf->size - 1 */
	size_t max_size;	/* Maximum size of buffer */
	size_t alloc;		/* Total bytes allocated to buf->d */
	صحیح readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	ساختار sshbuf *parent;	/* If child, pointer to parent */
};

ایستا درونخطی صحیح
sshbuf_check_sanity(ثابت ساختار sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	اگر (__predict_false(buf == پوچ ||
	    (!buf->readonly && buf->d != buf->cd) ||
	    buf->parent == buf ||
	    buf->refcount < 1 || buf->refcount > SSHBUF_REFS_MAX ||
	    buf->cd == پوچ ||
	    buf->max_size > SSHBUF_SIZE_MAX ||
	    buf->alloc > buf->max_size ||
	    buf->size > buf->alloc ||
	    buf->off > buf->size)) {
		/* Do not try to recover from corrupted buffer internals */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		ssh_signal(SIGSEGV, SIG_DFL);
		بالاببر(SIGSEGV);
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	بازگشت 0;
}

ایستا تهی
sshbuf_maybe_pack(ساختار sshbuf *buf, صحیح force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	اگر (buf->off == 0 || buf->readonly || buf->refcount > 1)
		بازگشت;
	اگر (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->size / 2)) {
		memmove(buf->d, buf->d + buf->off, buf->size - buf->off);
		buf->size -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

ساختار sshbuf *
sshbuf_new(تهی)
{
	ساختار sshbuf *ret;

	اگر ((ret = calloc(1, اندازه(*ret))) == پوچ)
		بازگشت پوچ;
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_size = SSHBUF_SIZE_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->parent = پوچ;
	اگر ((ret->cd = ret->d = calloc(1, ret->alloc)) == پوچ) {
		آزاد(ret);
		بازگشت پوچ;
	}
	بازگشت ret;
}

ساختار sshbuf *
sshbuf_from(ثابت تهی *blob, size_t len)
{
	ساختار sshbuf *ret;

	اگر (blob == پوچ || len > SSHBUF_SIZE_MAX ||
	    (ret = calloc(1, اندازه(*ret))) == پوچ)
		بازگشت پوچ;
	ret->alloc = ret->size = ret->max_size = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->parent = پوچ;
	ret->cd = blob;
	ret->d = پوچ;
	بازگشت ret;
}

صحیح
sshbuf_set_parent(ساختار sshbuf *child, ساختار sshbuf *parent)
{
	صحیح r;

	اگر ((r = sshbuf_check_sanity(child)) != 0 ||
	    (r = sshbuf_check_sanity(parent)) != 0)
		بازگشت r;
	اگر ((child->parent != پوچ && child->parent != parent) ||
	    child == parent)
		بازگشت SSH_ERR_INTERNAL_ERROR;
	child->parent = parent;
	child->parent->refcount++;
	بازگشت 0;
}

ساختار sshbuf *
sshbuf_fromb(ساختار sshbuf *buf)
{
	ساختار sshbuf *ret;

	اگر (sshbuf_check_sanity(buf) != 0)
		بازگشت پوچ;
	اگر ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == پوچ)
		بازگشت پوچ;
	اگر (sshbuf_set_parent(ret, buf) != 0) {
		sshbuf_free(ret);
		بازگشت پوچ;
	}
	بازگشت ret;
}

تهی
sshbuf_free(ساختار sshbuf *buf)
{
	اگر (buf == پوچ)
		بازگشت;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	اگر (sshbuf_check_sanity(buf) != 0)
		بازگشت;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	اگر (buf->refcount > 0)
		بازگشت;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->parent);
	buf->parent = پوچ;

	اگر (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, اندازه(*buf));
}

تهی
sshbuf_reset(ساختار sshbuf *buf)
{
	u_char *d;

	اگر (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->size;
		بازگشت;
	}
	اگر (sshbuf_check_sanity(buf) != 0)
		بازگشت;
	buf->off = buf->size = 0;
	اگر (buf->alloc != SSHBUF_SIZE_INIT) {
		اگر ((d = recallocarray(buf->d, buf->alloc, SSHBUF_SIZE_INIT,
		    1)) != پوچ) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_SIZE_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

size_t
sshbuf_max_size(ثابت ساختار sshbuf *buf)
{
	بازگشت buf->max_size;
}

size_t
sshbuf_alloc(ثابت ساختار sshbuf *buf)
{
	بازگشت buf->alloc;
}

ثابت ساختار sshbuf *
sshbuf_parent(ثابت ساختار sshbuf *buf)
{
	بازگشت buf->parent;
}

u_int
sshbuf_refcount(ثابت ساختار sshbuf *buf)
{
	بازگشت buf->refcount;
}

صحیح
sshbuf_set_max_size(ساختار sshbuf *buf, size_t max_size)
{
	size_t rlen;
	u_char *dp;
	صحیح r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_size));
	اگر ((r = sshbuf_check_sanity(buf)) != 0)
		بازگشت r;
	اگر (max_size == buf->max_size)
		بازگشت 0;
	اگر (buf->readonly || buf->refcount > 1)
		بازگشت SSH_ERR_BUFFER_READ_ONLY;
	اگر (max_size > SSHBUF_SIZE_MAX)
		بازگشت SSH_ERR_NO_BUFFER_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_size < buf->size);
	اگر (max_size < buf->alloc && max_size > buf->size) {
		اگر (buf->size < SSHBUF_SIZE_INIT)
			rlen = SSHBUF_SIZE_INIT;
		وگرنه
			rlen = ROUNDUP(buf->size, SSHBUF_SIZE_INC);
		اگر (rlen > max_size)
			rlen = max_size;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		اگر ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == پوچ)
			بازگشت SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	اگر (max_size < buf->alloc)
		بازگشت SSH_ERR_NO_BUFFER_SPACE;
	buf->max_size = max_size;
	بازگشت 0;
}

size_t
sshbuf_len(ثابت ساختار sshbuf *buf)
{
	اگر (sshbuf_check_sanity(buf) != 0)
		بازگشت 0;
	بازگشت buf->size - buf->off;
}

size_t
sshbuf_avail(ثابت ساختار sshbuf *buf)
{
	اگر (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		بازگشت 0;
	بازگشت buf->max_size - (buf->size - buf->off);
}

ثابت u_char *
sshbuf_ptr(ثابت ساختار sshbuf *buf)
{
	اگر (sshbuf_check_sanity(buf) != 0)
		بازگشت پوچ;
	بازگشت buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(ثابت ساختار sshbuf *buf)
{
	اگر (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		بازگشت پوچ;
	بازگشت buf->d + buf->off;
}

صحیح
sshbuf_check_reserve(ثابت ساختار sshbuf *buf, size_t len)
{
	صحیح r;

	اگر ((r = sshbuf_check_sanity(buf)) != 0)
		بازگشت r;
	اگر (buf->readonly || buf->refcount > 1)
		بازگشت SSH_ERR_BUFFER_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	اگر (len > buf->max_size || buf->max_size - len < buf->size - buf->off)
		بازگشت SSH_ERR_NO_BUFFER_SPACE;
	بازگشت 0;
}

صحیح
sshbuf_allocate(ساختار sshbuf *buf, size_t len)
{
	size_t rlen, need;
	u_char *dp;
	صحیح r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	اگر ((r = sshbuf_check_reserve(buf, len)) != 0)
		بازگشت r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->size + len > buf->max_size);
	SSHBUF_TELL("allocate");
	اگر (len + buf->size <= buf->alloc)
		بازگشت 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->size - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_SIZE_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	اگر (rlen > buf->max_size)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	اگر ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == پوچ) {
		SSHBUF_DBG(("realloc fail"));
		بازگشت SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	اگر ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		بازگشت r;
	}
	SSHBUF_TELL("done");
	بازگشت 0;
}

صحیح
sshbuf_reserve(ساختار sshbuf *buf, size_t len, u_char **dpp)
{
	u_char *dp;
	صحیح r;

	اگر (dpp != پوچ)
		*dpp = پوچ;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	اگر ((r = sshbuf_allocate(buf, len)) != 0)
		بازگشت r;

	dp = buf->d + buf->size;
	buf->size += len;
	اگر (dpp != پوچ)
		*dpp = dp;
	بازگشت 0;
}

صحیح
sshbuf_consume(ساختار sshbuf *buf, size_t len)
{
	صحیح r;

	SSHBUF_DBG(("len = %zu", len));
	اگر ((r = sshbuf_check_sanity(buf)) != 0)
		بازگشت r;
	اگر (len == 0)
		بازگشت 0;
	اگر (len > sshbuf_len(buf))
		بازگشت SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	اگر (buf->off == buf->size)
		buf->off = buf->size = 0;
	SSHBUF_TELL("done");
	بازگشت 0;
}

صحیح
sshbuf_consume_end(ساختار sshbuf *buf, size_t len)
{
	صحیح r;

	SSHBUF_DBG(("len = %zu", len));
	اگر ((r = sshbuf_check_sanity(buf)) != 0)
		بازگشت r;
	اگر (len == 0)
		بازگشت 0;
	اگر (len > sshbuf_len(buf))
		بازگشت SSH_ERR_MESSAGE_INCOMPLETE;
	buf->size -= len;
	SSHBUF_TELL("done");
	بازگشت 0;
}

صحیح
sshbuf_consume_upto_child(ساختار sshbuf *buf, ثابت ساختار sshbuf *child)
{
	صحیح r;

	اگر ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(child)) != 0)
		بازگشت r;
	/* This function is only used for parent/child buffers */
	اگر (child->parent != buf)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	/* Nonsensical if the parent has advanced past the child */
	اگر (sshbuf_len(child) > sshbuf_len(buf))
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	/* More paranoia, shouldn't happen */
	اگر (child->cd < buf->cd)
		بازگشت SSH_ERR_INTERNAL_ERROR;
	/* Advance */
	بازگشت sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(child));
}
