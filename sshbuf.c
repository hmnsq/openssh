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
	} док (0)
#инако
# define SSHBUF_TELL(what)
#endif

struct sshbuf {
	u_char *d;		/* Data */
	const u_char *cd;	/* Const data */
	size_t off;		/* First available byte is buf->d + buf->off */
	size_t size;		/* Last byte is buf->d + buf->size - 1 */
	size_t max_size;	/* Maximum size of buffer */
	size_t alloc;		/* Total bytes allocated to buf->d */
	цео readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	struct sshbuf *parent;	/* If child, pointer to parent */
};

static inline цео
sshbuf_check_sanity(const struct sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	ако (__predict_false(buf == NULL ||
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
		врати SSH_ERR_INTERNAL_ERROR;
	}
	врати 0;
}

static void
sshbuf_maybe_pack(struct sshbuf *buf, цео force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	ако (buf->off == 0 || buf->readonly || buf->refcount > 1)
		врати;
	ако (force ||
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

	ако ((ret = calloc(1, sizeof(*ret))) == NULL)
		врати NULL;
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_size = SSHBUF_SIZE_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->parent = NULL;
	ако ((ret->cd = ret->d = calloc(1, ret->alloc)) == NULL) {
		free(ret);
		врати NULL;
	}
	врати ret;
}

struct sshbuf *
sshbuf_from(const void *blob, size_t len)
{
	struct sshbuf *ret;

	ако (blob == NULL || len > SSHBUF_SIZE_MAX ||
	    (ret = calloc(1, sizeof(*ret))) == NULL)
		врати NULL;
	ret->alloc = ret->size = ret->max_size = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->parent = NULL;
	ret->cd = blob;
	ret->d = NULL;
	врати ret;
}

цео
sshbuf_set_parent(struct sshbuf *child, struct sshbuf *parent)
{
	цео r;

	ако ((r = sshbuf_check_sanity(child)) != 0 ||
	    (r = sshbuf_check_sanity(parent)) != 0)
		врати r;
	ако ((child->parent != NULL && child->parent != parent) ||
	    child == parent)
		врати SSH_ERR_INTERNAL_ERROR;
	child->parent = parent;
	child->parent->refcount++;
	врати 0;
}

struct sshbuf *
sshbuf_fromb(struct sshbuf *buf)
{
	struct sshbuf *ret;

	ако (sshbuf_check_sanity(buf) != 0)
		врати NULL;
	ако ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == NULL)
		врати NULL;
	ако (sshbuf_set_parent(ret, buf) != 0) {
		sshbuf_free(ret);
		врати NULL;
	}
	врати ret;
}

void
sshbuf_free(struct sshbuf *buf)
{
	ако (buf == NULL)
		врати;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	ако (sshbuf_check_sanity(buf) != 0)
		врати;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	ако (buf->refcount > 0)
		врати;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->parent);
	buf->parent = NULL;

	ако (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, sizeof(*buf));
}

void
sshbuf_reset(struct sshbuf *buf)
{
	u_char *d;

	ако (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->size;
		врати;
	}
	ако (sshbuf_check_sanity(buf) != 0)
		врати;
	buf->off = buf->size = 0;
	ако (buf->alloc != SSHBUF_SIZE_INIT) {
		ако ((d = recallocarray(buf->d, buf->alloc, SSHBUF_SIZE_INIT,
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
	врати buf->max_size;
}

size_t
sshbuf_alloc(const struct sshbuf *buf)
{
	врати buf->alloc;
}

const struct sshbuf *
sshbuf_parent(const struct sshbuf *buf)
{
	врати buf->parent;
}

u_int
sshbuf_refcount(const struct sshbuf *buf)
{
	врати buf->refcount;
}

цео
sshbuf_set_max_size(struct sshbuf *buf, size_t max_size)
{
	size_t rlen;
	u_char *dp;
	цео r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_size));
	ако ((r = sshbuf_check_sanity(buf)) != 0)
		врати r;
	ако (max_size == buf->max_size)
		врати 0;
	ако (buf->readonly || buf->refcount > 1)
		врати SSH_ERR_BUFFER_READ_ONLY;
	ако (max_size > SSHBUF_SIZE_MAX)
		врати SSH_ERR_NO_BUFFER_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_size < buf->size);
	ако (max_size < buf->alloc && max_size > buf->size) {
		ако (buf->size < SSHBUF_SIZE_INIT)
			rlen = SSHBUF_SIZE_INIT;
		инако
			rlen = ROUNDUP(buf->size, SSHBUF_SIZE_INC);
		ако (rlen > max_size)
			rlen = max_size;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		ако ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == NULL)
			врати SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	ако (max_size < buf->alloc)
		врати SSH_ERR_NO_BUFFER_SPACE;
	buf->max_size = max_size;
	врати 0;
}

size_t
sshbuf_len(const struct sshbuf *buf)
{
	ако (sshbuf_check_sanity(buf) != 0)
		врати 0;
	врати buf->size - buf->off;
}

size_t
sshbuf_avail(const struct sshbuf *buf)
{
	ако (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		врати 0;
	врати buf->max_size - (buf->size - buf->off);
}

const u_char *
sshbuf_ptr(const struct sshbuf *buf)
{
	ако (sshbuf_check_sanity(buf) != 0)
		врати NULL;
	врати buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(const struct sshbuf *buf)
{
	ако (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		врати NULL;
	врати buf->d + buf->off;
}

цео
sshbuf_check_reserve(const struct sshbuf *buf, size_t len)
{
	цео r;

	ако ((r = sshbuf_check_sanity(buf)) != 0)
		врати r;
	ако (buf->readonly || buf->refcount > 1)
		врати SSH_ERR_BUFFER_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	ако (len > buf->max_size || buf->max_size - len < buf->size - buf->off)
		врати SSH_ERR_NO_BUFFER_SPACE;
	врати 0;
}

цео
sshbuf_allocate(struct sshbuf *buf, size_t len)
{
	size_t rlen, need;
	u_char *dp;
	цео r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	ако ((r = sshbuf_check_reserve(buf, len)) != 0)
		врати r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->size + len > buf->max_size);
	SSHBUF_TELL("allocate");
	ако (len + buf->size <= buf->alloc)
		врати 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->size - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_SIZE_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	ако (rlen > buf->max_size)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	ако ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == NULL) {
		SSHBUF_DBG(("realloc fail"));
		врати SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	ако ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		врати r;
	}
	SSHBUF_TELL("done");
	врати 0;
}

цео
sshbuf_reserve(struct sshbuf *buf, size_t len, u_char **dpp)
{
	u_char *dp;
	цео r;

	ако (dpp != NULL)
		*dpp = NULL;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	ако ((r = sshbuf_allocate(buf, len)) != 0)
		врати r;

	dp = buf->d + buf->size;
	buf->size += len;
	ако (dpp != NULL)
		*dpp = dp;
	врати 0;
}

цео
sshbuf_consume(struct sshbuf *buf, size_t len)
{
	цео r;

	SSHBUF_DBG(("len = %zu", len));
	ако ((r = sshbuf_check_sanity(buf)) != 0)
		врати r;
	ако (len == 0)
		врати 0;
	ако (len > sshbuf_len(buf))
		врати SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	ако (buf->off == buf->size)
		buf->off = buf->size = 0;
	SSHBUF_TELL("done");
	врати 0;
}

цео
sshbuf_consume_end(struct sshbuf *buf, size_t len)
{
	цео r;

	SSHBUF_DBG(("len = %zu", len));
	ако ((r = sshbuf_check_sanity(buf)) != 0)
		врати r;
	ако (len == 0)
		врати 0;
	ако (len > sshbuf_len(buf))
		врати SSH_ERR_MESSAGE_INCOMPLETE;
	buf->size -= len;
	SSHBUF_TELL("done");
	врати 0;
}

цео
sshbuf_consume_upto_child(struct sshbuf *buf, const struct sshbuf *child)
{
	цео r;

	ако ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(child)) != 0)
		врати r;
	/* This function is only used for parent/child buffers */
	ако (child->parent != buf)
		врати SSH_ERR_INVALID_ARGUMENT;
	/* Nonsensical if the parent has advanced past the child */
	ако (sshbuf_len(child) > sshbuf_len(buf))
		врати SSH_ERR_INVALID_ARGUMENT;
	/* More paranoia, shouldn't happen */
	ако (child->cd < buf->cd)
		врати SSH_ERR_INTERNAL_ERROR;
	/* Advance */
	врати sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(child));
}
