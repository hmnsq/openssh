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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "ssherr.h"
#define SSHBUF_INTERNAL
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "misc.h"

#ifdef SSHBUF_DEBUG
# define SSHBUF_TELL(what) કરો { \
		printf("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __FILE__, __LINE__, __func__, what, \
		    buf->size, buf->alloc, buf->off, buf->max_size); \
		fflush(stdout); \
	} જ્યારે (0)
#નહીંતર
# define SSHBUF_TELL(what)
#endif

સંરચના sshbuf {
	u_char *d;		/* Data */
	અચલ u_char *cd;	/* Const data */
	size_t off;		/* First available byte is buf->d + buf->off */
	size_t size;		/* Last byte is buf->d + buf->size - 1 */
	size_t max_size;	/* Maximum size of buffer */
	size_t alloc;		/* Total bytes allocated to buf->d */
	પૂર્ણાંક readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	સંરચના sshbuf *parent;	/* If child, pointer to parent */
};

સ્થિર અંતઃરેખ પૂર્ણાંક
sshbuf_check_sanity(અચલ સંરચના sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	જો (__predict_false(buf == ખાલી ||
	    (!buf->readonly && buf->d != buf->cd) ||
	    buf->parent == buf ||
	    buf->refcount < 1 || buf->refcount > SSHBUF_REFS_MAX ||
	    buf->cd == ખાલી ||
	    buf->max_size > SSHBUF_SIZE_MAX ||
	    buf->alloc > buf->max_size ||
	    buf->size > buf->alloc ||
	    buf->off > buf->size)) {
		/* Do not try to recover from corrupted buffer internals */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		ssh_signal(SIGSEGV, SIG_DFL);
		ઉઠાવો(SIGSEGV);
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	પાછા 0;
}

સ્થિર શૂન્ય
sshbuf_maybe_pack(સંરચના sshbuf *buf, પૂર્ણાંક force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	જો (buf->off == 0 || buf->readonly || buf->refcount > 1)
		પાછા;
	જો (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->size / 2)) {
		memmove(buf->d, buf->d + buf->off, buf->size - buf->off);
		buf->size -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

સંરચના sshbuf *
sshbuf_new(શૂન્ય)
{
	સંરચના sshbuf *ret;

	જો ((ret = calloc(1, કદ(*ret))) == ખાલી)
		પાછા ખાલી;
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_size = SSHBUF_SIZE_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->parent = ખાલી;
	જો ((ret->cd = ret->d = calloc(1, ret->alloc)) == ખાલી) {
		મુક્ત(ret);
		પાછા ખાલી;
	}
	પાછા ret;
}

સંરચના sshbuf *
sshbuf_from(અચલ શૂન્ય *blob, size_t len)
{
	સંરચના sshbuf *ret;

	જો (blob == ખાલી || len > SSHBUF_SIZE_MAX ||
	    (ret = calloc(1, કદ(*ret))) == ખાલી)
		પાછા ખાલી;
	ret->alloc = ret->size = ret->max_size = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->parent = ખાલી;
	ret->cd = blob;
	ret->d = ખાલી;
	પાછા ret;
}

પૂર્ણાંક
sshbuf_set_parent(સંરચના sshbuf *child, સંરચના sshbuf *parent)
{
	પૂર્ણાંક r;

	જો ((r = sshbuf_check_sanity(child)) != 0 ||
	    (r = sshbuf_check_sanity(parent)) != 0)
		પાછા r;
	જો ((child->parent != ખાલી && child->parent != parent) ||
	    child == parent)
		પાછા SSH_ERR_INTERNAL_ERROR;
	child->parent = parent;
	child->parent->refcount++;
	પાછા 0;
}

સંરચના sshbuf *
sshbuf_fromb(સંરચના sshbuf *buf)
{
	સંરચના sshbuf *ret;

	જો (sshbuf_check_sanity(buf) != 0)
		પાછા ખાલી;
	જો ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == ખાલી)
		પાછા ખાલી;
	જો (sshbuf_set_parent(ret, buf) != 0) {
		sshbuf_free(ret);
		પાછા ખાલી;
	}
	પાછા ret;
}

શૂન્ય
sshbuf_free(સંરચના sshbuf *buf)
{
	જો (buf == ખાલી)
		પાછા;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	જો (sshbuf_check_sanity(buf) != 0)
		પાછા;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	જો (buf->refcount > 0)
		પાછા;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->parent);
	buf->parent = ખાલી;

	જો (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, કદ(*buf));
}

શૂન્ય
sshbuf_reset(સંરચના sshbuf *buf)
{
	u_char *d;

	જો (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->size;
		પાછા;
	}
	જો (sshbuf_check_sanity(buf) != 0)
		પાછા;
	buf->off = buf->size = 0;
	જો (buf->alloc != SSHBUF_SIZE_INIT) {
		જો ((d = recallocarray(buf->d, buf->alloc, SSHBUF_SIZE_INIT,
		    1)) != ખાલી) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_SIZE_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

size_t
sshbuf_max_size(અચલ સંરચના sshbuf *buf)
{
	પાછા buf->max_size;
}

size_t
sshbuf_alloc(અચલ સંરચના sshbuf *buf)
{
	પાછા buf->alloc;
}

અચલ સંરચના sshbuf *
sshbuf_parent(અચલ સંરચના sshbuf *buf)
{
	પાછા buf->parent;
}

u_int
sshbuf_refcount(અચલ સંરચના sshbuf *buf)
{
	પાછા buf->refcount;
}

પૂર્ણાંક
sshbuf_set_max_size(સંરચના sshbuf *buf, size_t max_size)
{
	size_t rlen;
	u_char *dp;
	પૂર્ણાંક r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_size));
	જો ((r = sshbuf_check_sanity(buf)) != 0)
		પાછા r;
	જો (max_size == buf->max_size)
		પાછા 0;
	જો (buf->readonly || buf->refcount > 1)
		પાછા SSH_ERR_BUFFER_READ_ONLY;
	જો (max_size > SSHBUF_SIZE_MAX)
		પાછા SSH_ERR_NO_BUFFER_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_size < buf->size);
	જો (max_size < buf->alloc && max_size > buf->size) {
		જો (buf->size < SSHBUF_SIZE_INIT)
			rlen = SSHBUF_SIZE_INIT;
		નહીંતર
			rlen = ROUNDUP(buf->size, SSHBUF_SIZE_INC);
		જો (rlen > max_size)
			rlen = max_size;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		જો ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == ખાલી)
			પાછા SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	જો (max_size < buf->alloc)
		પાછા SSH_ERR_NO_BUFFER_SPACE;
	buf->max_size = max_size;
	પાછા 0;
}

size_t
sshbuf_len(અચલ સંરચના sshbuf *buf)
{
	જો (sshbuf_check_sanity(buf) != 0)
		પાછા 0;
	પાછા buf->size - buf->off;
}

size_t
sshbuf_avail(અચલ સંરચના sshbuf *buf)
{
	જો (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		પાછા 0;
	પાછા buf->max_size - (buf->size - buf->off);
}

અચલ u_char *
sshbuf_ptr(અચલ સંરચના sshbuf *buf)
{
	જો (sshbuf_check_sanity(buf) != 0)
		પાછા ખાલી;
	પાછા buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(અચલ સંરચના sshbuf *buf)
{
	જો (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		પાછા ખાલી;
	પાછા buf->d + buf->off;
}

પૂર્ણાંક
sshbuf_check_reserve(અચલ સંરચના sshbuf *buf, size_t len)
{
	પૂર્ણાંક r;

	જો ((r = sshbuf_check_sanity(buf)) != 0)
		પાછા r;
	જો (buf->readonly || buf->refcount > 1)
		પાછા SSH_ERR_BUFFER_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	જો (len > buf->max_size || buf->max_size - len < buf->size - buf->off)
		પાછા SSH_ERR_NO_BUFFER_SPACE;
	પાછા 0;
}

પૂર્ણાંક
sshbuf_allocate(સંરચના sshbuf *buf, size_t len)
{
	size_t rlen, need;
	u_char *dp;
	પૂર્ણાંક r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	જો ((r = sshbuf_check_reserve(buf, len)) != 0)
		પાછા r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->size + len > buf->max_size);
	SSHBUF_TELL("allocate");
	જો (len + buf->size <= buf->alloc)
		પાછા 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->size - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_SIZE_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	જો (rlen > buf->max_size)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	જો ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == ખાલી) {
		SSHBUF_DBG(("realloc fail"));
		પાછા SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	જો ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		પાછા r;
	}
	SSHBUF_TELL("done");
	પાછા 0;
}

પૂર્ણાંક
sshbuf_reserve(સંરચના sshbuf *buf, size_t len, u_char **dpp)
{
	u_char *dp;
	પૂર્ણાંક r;

	જો (dpp != ખાલી)
		*dpp = ખાલી;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	જો ((r = sshbuf_allocate(buf, len)) != 0)
		પાછા r;

	dp = buf->d + buf->size;
	buf->size += len;
	જો (dpp != ખાલી)
		*dpp = dp;
	પાછા 0;
}

પૂર્ણાંક
sshbuf_consume(સંરચના sshbuf *buf, size_t len)
{
	પૂર્ણાંક r;

	SSHBUF_DBG(("len = %zu", len));
	જો ((r = sshbuf_check_sanity(buf)) != 0)
		પાછા r;
	જો (len == 0)
		પાછા 0;
	જો (len > sshbuf_len(buf))
		પાછા SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	જો (buf->off == buf->size)
		buf->off = buf->size = 0;
	SSHBUF_TELL("done");
	પાછા 0;
}

પૂર્ણાંક
sshbuf_consume_end(સંરચના sshbuf *buf, size_t len)
{
	પૂર્ણાંક r;

	SSHBUF_DBG(("len = %zu", len));
	જો ((r = sshbuf_check_sanity(buf)) != 0)
		પાછા r;
	જો (len == 0)
		પાછા 0;
	જો (len > sshbuf_len(buf))
		પાછા SSH_ERR_MESSAGE_INCOMPLETE;
	buf->size -= len;
	SSHBUF_TELL("done");
	પાછા 0;
}

પૂર્ણાંક
sshbuf_consume_upto_child(સંરચના sshbuf *buf, અચલ સંરચના sshbuf *child)
{
	પૂર્ણાંક r;

	જો ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(child)) != 0)
		પાછા r;
	/* This function is only used for parent/child buffers */
	જો (child->parent != buf)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	/* Nonsensical if the parent has advanced past the child */
	જો (sshbuf_len(child) > sshbuf_len(buf))
		પાછા SSH_ERR_INVALID_ARGUMENT;
	/* More paranoia, shouldn't happen */
	જો (child->cd < buf->cd)
		પાછા SSH_ERR_INTERNAL_ERROR;
	/* Advance */
	પાછા sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(child));
}
