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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "ssherr.h"
#define SSHBUF_INTERNAL
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "misc.h"

#ifdef SSHBUF_DEBUG
# define SSHBUF_TELL(what) செய் { \
		printf("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __FILE__, __LINE__, __func__, what, \
		    buf->size, buf->alloc, buf->off, buf->max_size); \
		fflush(stdout); \
	} போது (0)
#இல்லையெனில்
# define SSHBUF_TELL(what)
#endif

கட்டமைப்பு sshbuf {
	u_char *d;		/* Data */
	மாறிலி u_char *cd;	/* Const data */
	size_t off;		/* First available byte is buf->d + buf->off */
	size_t size;		/* Last byte is buf->d + buf->size - 1 */
	size_t max_size;	/* Maximum size of buffer */
	size_t alloc;		/* Total bytes allocated to buf->d */
	முழு readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	கட்டமைப்பு sshbuf *parent;	/* If child, pointer to parent */
};

நிலையான உள்வரி முழு
sshbuf_check_sanity(மாறிலி கட்டமைப்பு sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	எனில் (__predict_false(buf == வெற்று ||
	    (!buf->readonly && buf->d != buf->cd) ||
	    buf->parent == buf ||
	    buf->refcount < 1 || buf->refcount > SSHBUF_REFS_MAX ||
	    buf->cd == வெற்று ||
	    buf->max_size > SSHBUF_SIZE_MAX ||
	    buf->alloc > buf->max_size ||
	    buf->size > buf->alloc ||
	    buf->off > buf->size)) {
		/* Do not try to recover from corrupted buffer internals */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		ssh_signal(SIGSEGV, SIG_DFL);
		எழுப்பு(SIGSEGV);
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	}
	திரும்பு 0;
}

நிலையான வெறுமை
sshbuf_maybe_pack(கட்டமைப்பு sshbuf *buf, முழு force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	எனில் (buf->off == 0 || buf->readonly || buf->refcount > 1)
		திரும்பு;
	எனில் (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->size / 2)) {
		memmove(buf->d, buf->d + buf->off, buf->size - buf->off);
		buf->size -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

கட்டமைப்பு sshbuf *
sshbuf_new(வெறுமை)
{
	கட்டமைப்பு sshbuf *ret;

	எனில் ((ret = calloc(1, அளவு(*ret))) == வெற்று)
		திரும்பு வெற்று;
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_size = SSHBUF_SIZE_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->parent = வெற்று;
	எனில் ((ret->cd = ret->d = calloc(1, ret->alloc)) == வெற்று) {
		விடுவி(ret);
		திரும்பு வெற்று;
	}
	திரும்பு ret;
}

கட்டமைப்பு sshbuf *
sshbuf_from(மாறிலி வெறுமை *blob, size_t len)
{
	கட்டமைப்பு sshbuf *ret;

	எனில் (blob == வெற்று || len > SSHBUF_SIZE_MAX ||
	    (ret = calloc(1, அளவு(*ret))) == வெற்று)
		திரும்பு வெற்று;
	ret->alloc = ret->size = ret->max_size = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->parent = வெற்று;
	ret->cd = blob;
	ret->d = வெற்று;
	திரும்பு ret;
}

முழு
sshbuf_set_parent(கட்டமைப்பு sshbuf *child, கட்டமைப்பு sshbuf *parent)
{
	முழு r;

	எனில் ((r = sshbuf_check_sanity(child)) != 0 ||
	    (r = sshbuf_check_sanity(parent)) != 0)
		திரும்பு r;
	எனில் ((child->parent != வெற்று && child->parent != parent) ||
	    child == parent)
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	child->parent = parent;
	child->parent->refcount++;
	திரும்பு 0;
}

கட்டமைப்பு sshbuf *
sshbuf_fromb(கட்டமைப்பு sshbuf *buf)
{
	கட்டமைப்பு sshbuf *ret;

	எனில் (sshbuf_check_sanity(buf) != 0)
		திரும்பு வெற்று;
	எனில் ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == வெற்று)
		திரும்பு வெற்று;
	எனில் (sshbuf_set_parent(ret, buf) != 0) {
		sshbuf_free(ret);
		திரும்பு வெற்று;
	}
	திரும்பு ret;
}

வெறுமை
sshbuf_free(கட்டமைப்பு sshbuf *buf)
{
	எனில் (buf == வெற்று)
		திரும்பு;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	எனில் (sshbuf_check_sanity(buf) != 0)
		திரும்பு;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	எனில் (buf->refcount > 0)
		திரும்பு;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->parent);
	buf->parent = வெற்று;

	எனில் (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, அளவு(*buf));
}

வெறுமை
sshbuf_reset(கட்டமைப்பு sshbuf *buf)
{
	u_char *d;

	எனில் (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->size;
		திரும்பு;
	}
	எனில் (sshbuf_check_sanity(buf) != 0)
		திரும்பு;
	buf->off = buf->size = 0;
	எனில் (buf->alloc != SSHBUF_SIZE_INIT) {
		எனில் ((d = recallocarray(buf->d, buf->alloc, SSHBUF_SIZE_INIT,
		    1)) != வெற்று) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_SIZE_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

size_t
sshbuf_max_size(மாறிலி கட்டமைப்பு sshbuf *buf)
{
	திரும்பு buf->max_size;
}

size_t
sshbuf_alloc(மாறிலி கட்டமைப்பு sshbuf *buf)
{
	திரும்பு buf->alloc;
}

மாறிலி கட்டமைப்பு sshbuf *
sshbuf_parent(மாறிலி கட்டமைப்பு sshbuf *buf)
{
	திரும்பு buf->parent;
}

u_int
sshbuf_refcount(மாறிலி கட்டமைப்பு sshbuf *buf)
{
	திரும்பு buf->refcount;
}

முழு
sshbuf_set_max_size(கட்டமைப்பு sshbuf *buf, size_t max_size)
{
	size_t rlen;
	u_char *dp;
	முழு r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_size));
	எனில் ((r = sshbuf_check_sanity(buf)) != 0)
		திரும்பு r;
	எனில் (max_size == buf->max_size)
		திரும்பு 0;
	எனில் (buf->readonly || buf->refcount > 1)
		திரும்பு SSH_ERR_BUFFER_READ_ONLY;
	எனில் (max_size > SSHBUF_SIZE_MAX)
		திரும்பு SSH_ERR_NO_BUFFER_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_size < buf->size);
	எனில் (max_size < buf->alloc && max_size > buf->size) {
		எனில் (buf->size < SSHBUF_SIZE_INIT)
			rlen = SSHBUF_SIZE_INIT;
		இல்லையெனில்
			rlen = ROUNDUP(buf->size, SSHBUF_SIZE_INC);
		எனில் (rlen > max_size)
			rlen = max_size;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		எனில் ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == வெற்று)
			திரும்பு SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	எனில் (max_size < buf->alloc)
		திரும்பு SSH_ERR_NO_BUFFER_SPACE;
	buf->max_size = max_size;
	திரும்பு 0;
}

size_t
sshbuf_len(மாறிலி கட்டமைப்பு sshbuf *buf)
{
	எனில் (sshbuf_check_sanity(buf) != 0)
		திரும்பு 0;
	திரும்பு buf->size - buf->off;
}

size_t
sshbuf_avail(மாறிலி கட்டமைப்பு sshbuf *buf)
{
	எனில் (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		திரும்பு 0;
	திரும்பு buf->max_size - (buf->size - buf->off);
}

மாறிலி u_char *
sshbuf_ptr(மாறிலி கட்டமைப்பு sshbuf *buf)
{
	எனில் (sshbuf_check_sanity(buf) != 0)
		திரும்பு வெற்று;
	திரும்பு buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(மாறிலி கட்டமைப்பு sshbuf *buf)
{
	எனில் (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		திரும்பு வெற்று;
	திரும்பு buf->d + buf->off;
}

முழு
sshbuf_check_reserve(மாறிலி கட்டமைப்பு sshbuf *buf, size_t len)
{
	முழு r;

	எனில் ((r = sshbuf_check_sanity(buf)) != 0)
		திரும்பு r;
	எனில் (buf->readonly || buf->refcount > 1)
		திரும்பு SSH_ERR_BUFFER_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	எனில் (len > buf->max_size || buf->max_size - len < buf->size - buf->off)
		திரும்பு SSH_ERR_NO_BUFFER_SPACE;
	திரும்பு 0;
}

முழு
sshbuf_allocate(கட்டமைப்பு sshbuf *buf, size_t len)
{
	size_t rlen, need;
	u_char *dp;
	முழு r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	எனில் ((r = sshbuf_check_reserve(buf, len)) != 0)
		திரும்பு r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->size + len > buf->max_size);
	SSHBUF_TELL("allocate");
	எனில் (len + buf->size <= buf->alloc)
		திரும்பு 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->size - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_SIZE_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	எனில் (rlen > buf->max_size)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	எனில் ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == வெற்று) {
		SSHBUF_DBG(("realloc fail"));
		திரும்பு SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	எனில் ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		திரும்பு r;
	}
	SSHBUF_TELL("done");
	திரும்பு 0;
}

முழு
sshbuf_reserve(கட்டமைப்பு sshbuf *buf, size_t len, u_char **dpp)
{
	u_char *dp;
	முழு r;

	எனில் (dpp != வெற்று)
		*dpp = வெற்று;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	எனில் ((r = sshbuf_allocate(buf, len)) != 0)
		திரும்பு r;

	dp = buf->d + buf->size;
	buf->size += len;
	எனில் (dpp != வெற்று)
		*dpp = dp;
	திரும்பு 0;
}

முழு
sshbuf_consume(கட்டமைப்பு sshbuf *buf, size_t len)
{
	முழு r;

	SSHBUF_DBG(("len = %zu", len));
	எனில் ((r = sshbuf_check_sanity(buf)) != 0)
		திரும்பு r;
	எனில் (len == 0)
		திரும்பு 0;
	எனில் (len > sshbuf_len(buf))
		திரும்பு SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	எனில் (buf->off == buf->size)
		buf->off = buf->size = 0;
	SSHBUF_TELL("done");
	திரும்பு 0;
}

முழு
sshbuf_consume_end(கட்டமைப்பு sshbuf *buf, size_t len)
{
	முழு r;

	SSHBUF_DBG(("len = %zu", len));
	எனில் ((r = sshbuf_check_sanity(buf)) != 0)
		திரும்பு r;
	எனில் (len == 0)
		திரும்பு 0;
	எனில் (len > sshbuf_len(buf))
		திரும்பு SSH_ERR_MESSAGE_INCOMPLETE;
	buf->size -= len;
	SSHBUF_TELL("done");
	திரும்பு 0;
}

முழு
sshbuf_consume_upto_child(கட்டமைப்பு sshbuf *buf, மாறிலி கட்டமைப்பு sshbuf *child)
{
	முழு r;

	எனில் ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(child)) != 0)
		திரும்பு r;
	/* This function is only used for parent/child buffers */
	எனில் (child->parent != buf)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	/* Nonsensical if the parent has advanced past the child */
	எனில் (sshbuf_len(child) > sshbuf_len(buf))
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	/* More paranoia, shouldn't happen */
	எனில் (child->cd < buf->cd)
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	/* Advance */
	திரும்பு sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(child));
}
