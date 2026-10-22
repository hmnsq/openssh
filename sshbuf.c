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

#include "includes.h"

#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ssherr.h"
#define SSHBUF_INTERNAL
#include "sshbuf.h"
#include "misc.h"

#ifdef SSHBUF_DEBUG
# define SSHBUF_TELL(what) do { \
		printf("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __FILE__, __LINE__, __func__, what, \
		    buf->size, buf->alloc, buf->off, buf->max_size); \
		fflush(stdout); \
	} trong_khi (0)
#không_thì
# define SSHBUF_TELL(what)
#endif

struct sshbuf {
	u_char *d;		/* Data */
	const u_char *cd;	/* Const data */
	size_t off;		/* First available byte is buf->d + buf->off */
	size_t size;		/* Last byte is buf->d + buf->size - 1 */
	size_t max_size;	/* Maximum size of buffer */
	size_t alloc;		/* Total bytes allocated to buf->d */
	số_nguyên readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	struct sshbuf *parent;	/* If child, pointer to parent */
};

static inline số_nguyên
sshbuf_check_sanity(const struct sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	nếu (__predict_false(buf == NULL ||
	    (!buf->readonly && buf->d != buf->cd) ||
	    buf->parent == buf ||
	    buf->refcount < 1 || buf->refcount > SSHBUF_REFS_MAX ||
	    buf->cd == NULL ||
	    buf->max_size > SSHBUF_SIZE_MAX ||
	    buf->alloc > buf->max_size ||
	    buf->size > buf->alloc ||
	    buf->off > buf->size)) {
		/* Do not try to recover from corrupted buffer internals */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		ssh_signal(SIGSEGV, SIG_DFL);
		raise(SIGSEGV);
		trả_về SSH_ERR_INTERNAL_ERROR;
	}
	trả_về 0;
}

static void
sshbuf_maybe_pack(struct sshbuf *buf, số_nguyên force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	nếu (buf->off == 0 || buf->readonly || buf->refcount > 1)
		trả_về;
	nếu (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->size / 2)) {
		memmove(buf->d, buf->d + buf->off, buf->size - buf->off);
		buf->size -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

struct sshbuf *
sshbuf_new(void)
{
	struct sshbuf *ret;

	nếu ((ret = calloc(1, sizeof(*ret))) == NULL)
		trả_về NULL;
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_size = SSHBUF_SIZE_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->parent = NULL;
	nếu ((ret->cd = ret->d = calloc(1, ret->alloc)) == NULL) {
		free(ret);
		trả_về NULL;
	}
	trả_về ret;
}

struct sshbuf *
sshbuf_from(const void *blob, size_t len)
{
	struct sshbuf *ret;

	nếu (blob == NULL || len > SSHBUF_SIZE_MAX ||
	    (ret = calloc(1, sizeof(*ret))) == NULL)
		trả_về NULL;
	ret->alloc = ret->size = ret->max_size = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->parent = NULL;
	ret->cd = blob;
	ret->d = NULL;
	trả_về ret;
}

số_nguyên
sshbuf_set_parent(struct sshbuf *child, struct sshbuf *parent)
{
	số_nguyên r;

	nếu ((r = sshbuf_check_sanity(child)) != 0 ||
	    (r = sshbuf_check_sanity(parent)) != 0)
		trả_về r;
	nếu ((child->parent != NULL && child->parent != parent) ||
	    child == parent)
		trả_về SSH_ERR_INTERNAL_ERROR;
	child->parent = parent;
	child->parent->refcount++;
	trả_về 0;
}

struct sshbuf *
sshbuf_fromb(struct sshbuf *buf)
{
	struct sshbuf *ret;

	nếu (sshbuf_check_sanity(buf) != 0)
		trả_về NULL;
	nếu ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == NULL)
		trả_về NULL;
	nếu (sshbuf_set_parent(ret, buf) != 0) {
		sshbuf_free(ret);
		trả_về NULL;
	}
	trả_về ret;
}

void
sshbuf_free(struct sshbuf *buf)
{
	nếu (buf == NULL)
		trả_về;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	nếu (sshbuf_check_sanity(buf) != 0)
		trả_về;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	nếu (buf->refcount > 0)
		trả_về;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->parent);
	buf->parent = NULL;

	nếu (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, sizeof(*buf));
}

void
sshbuf_reset(struct sshbuf *buf)
{
	u_char *d;

	nếu (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->size;
		trả_về;
	}
	nếu (sshbuf_check_sanity(buf) != 0)
		trả_về;
	buf->off = buf->size = 0;
	nếu (buf->alloc != SSHBUF_SIZE_INIT) {
		nếu ((d = recallocarray(buf->d, buf->alloc, SSHBUF_SIZE_INIT,
		    1)) != NULL) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_SIZE_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

size_t
sshbuf_max_size(const struct sshbuf *buf)
{
	trả_về buf->max_size;
}

size_t
sshbuf_alloc(const struct sshbuf *buf)
{
	trả_về buf->alloc;
}

const struct sshbuf *
sshbuf_parent(const struct sshbuf *buf)
{
	trả_về buf->parent;
}

u_int
sshbuf_refcount(const struct sshbuf *buf)
{
	trả_về buf->refcount;
}

số_nguyên
sshbuf_set_max_size(struct sshbuf *buf, size_t max_size)
{
	size_t rlen;
	u_char *dp;
	số_nguyên r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_size));
	nếu ((r = sshbuf_check_sanity(buf)) != 0)
		trả_về r;
	nếu (max_size == buf->max_size)
		trả_về 0;
	nếu (buf->readonly || buf->refcount > 1)
		trả_về SSH_ERR_BUFFER_READ_ONLY;
	nếu (max_size > SSHBUF_SIZE_MAX)
		trả_về SSH_ERR_NO_BUFFER_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_size < buf->size);
	nếu (max_size < buf->alloc && max_size > buf->size) {
		nếu (buf->size < SSHBUF_SIZE_INIT)
			rlen = SSHBUF_SIZE_INIT;
		không_thì
			rlen = ROUNDUP(buf->size, SSHBUF_SIZE_INC);
		nếu (rlen > max_size)
			rlen = max_size;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		nếu ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == NULL)
			trả_về SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	nếu (max_size < buf->alloc)
		trả_về SSH_ERR_NO_BUFFER_SPACE;
	buf->max_size = max_size;
	trả_về 0;
}

size_t
sshbuf_len(const struct sshbuf *buf)
{
	nếu (sshbuf_check_sanity(buf) != 0)
		trả_về 0;
	trả_về buf->size - buf->off;
}

size_t
sshbuf_avail(const struct sshbuf *buf)
{
	nếu (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		trả_về 0;
	trả_về buf->max_size - (buf->size - buf->off);
}

const u_char *
sshbuf_ptr(const struct sshbuf *buf)
{
	nếu (sshbuf_check_sanity(buf) != 0)
		trả_về NULL;
	trả_về buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(const struct sshbuf *buf)
{
	nếu (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		trả_về NULL;
	trả_về buf->d + buf->off;
}

số_nguyên
sshbuf_check_reserve(const struct sshbuf *buf, size_t len)
{
	số_nguyên r;

	nếu ((r = sshbuf_check_sanity(buf)) != 0)
		trả_về r;
	nếu (buf->readonly || buf->refcount > 1)
		trả_về SSH_ERR_BUFFER_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	nếu (len > buf->max_size || buf->max_size - len < buf->size - buf->off)
		trả_về SSH_ERR_NO_BUFFER_SPACE;
	trả_về 0;
}

số_nguyên
sshbuf_allocate(struct sshbuf *buf, size_t len)
{
	size_t rlen, need;
	u_char *dp;
	số_nguyên r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	nếu ((r = sshbuf_check_reserve(buf, len)) != 0)
		trả_về r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->size + len > buf->max_size);
	SSHBUF_TELL("allocate");
	nếu (len + buf->size <= buf->alloc)
		trả_về 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->size - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_SIZE_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	nếu (rlen > buf->max_size)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	nếu ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == NULL) {
		SSHBUF_DBG(("realloc fail"));
		trả_về SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	nếu ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		trả_về r;
	}
	SSHBUF_TELL("done");
	trả_về 0;
}

số_nguyên
sshbuf_reserve(struct sshbuf *buf, size_t len, u_char **dpp)
{
	u_char *dp;
	số_nguyên r;

	nếu (dpp != NULL)
		*dpp = NULL;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	nếu ((r = sshbuf_allocate(buf, len)) != 0)
		trả_về r;

	dp = buf->d + buf->size;
	buf->size += len;
	nếu (dpp != NULL)
		*dpp = dp;
	trả_về 0;
}

số_nguyên
sshbuf_consume(struct sshbuf *buf, size_t len)
{
	số_nguyên r;

	SSHBUF_DBG(("len = %zu", len));
	nếu ((r = sshbuf_check_sanity(buf)) != 0)
		trả_về r;
	nếu (len == 0)
		trả_về 0;
	nếu (len > sshbuf_len(buf))
		trả_về SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	nếu (buf->off == buf->size)
		buf->off = buf->size = 0;
	SSHBUF_TELL("done");
	trả_về 0;
}

số_nguyên
sshbuf_consume_end(struct sshbuf *buf, size_t len)
{
	số_nguyên r;

	SSHBUF_DBG(("len = %zu", len));
	nếu ((r = sshbuf_check_sanity(buf)) != 0)
		trả_về r;
	nếu (len == 0)
		trả_về 0;
	nếu (len > sshbuf_len(buf))
		trả_về SSH_ERR_MESSAGE_INCOMPLETE;
	buf->size -= len;
	SSHBUF_TELL("done");
	trả_về 0;
}

số_nguyên
sshbuf_consume_upto_child(struct sshbuf *buf, const struct sshbuf *child)
{
	số_nguyên r;

	nếu ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(child)) != 0)
		trả_về r;
	/* This function is only used for parent/child buffers */
	nếu (child->parent != buf)
		trả_về SSH_ERR_INVALID_ARGUMENT;
	/* Nonsensical if the parent has advanced past the child */
	nếu (sshbuf_len(child) > sshbuf_len(buf))
		trả_về SSH_ERR_INVALID_ARGUMENT;
	/* More paranoia, shouldn't happen */
	nếu (child->cd < buf->cd)
		trả_về SSH_ERR_INTERNAL_ERROR;
	/* Advance */
	trả_về sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(child));
}
