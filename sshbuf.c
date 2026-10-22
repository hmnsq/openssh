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
	} докато (0)
#иначе
# define SSHBUF_TELL(what)
#endif

struct sshbuf {
	u_char *d;		/* Data */
	const u_char *cd;	/* Const data */
	size_t off;		/* First available byte is buf->d + buf->off */
	size_t size;		/* Last byte is buf->d + buf->size - 1 */
	size_t max_size;	/* Maximum size of buffer */
	size_t alloc;		/* Total bytes allocated to buf->d */
	цяло readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	struct sshbuf *parent;	/* If child, pointer to parent */
};

static inline цяло
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
		върни SSH_ERR_INTERNAL_ERROR;
	}
	върни 0;
}

static void
sshbuf_maybe_pack(struct sshbuf *buf, цяло force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	ако (buf->off == 0 || buf->readonly || buf->refcount > 1)
		върни;
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
		върни NULL;
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_size = SSHBUF_SIZE_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->parent = NULL;
	ако ((ret->cd = ret->d = calloc(1, ret->alloc)) == NULL) {
		free(ret);
		върни NULL;
	}
	върни ret;
}

struct sshbuf *
sshbuf_from(const void *blob, size_t len)
{
	struct sshbuf *ret;

	ако (blob == NULL || len > SSHBUF_SIZE_MAX ||
	    (ret = calloc(1, sizeof(*ret))) == NULL)
		върни NULL;
	ret->alloc = ret->size = ret->max_size = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->parent = NULL;
	ret->cd = blob;
	ret->d = NULL;
	върни ret;
}

цяло
sshbuf_set_parent(struct sshbuf *child, struct sshbuf *parent)
{
	цяло r;

	ако ((r = sshbuf_check_sanity(child)) != 0 ||
	    (r = sshbuf_check_sanity(parent)) != 0)
		върни r;
	ако ((child->parent != NULL && child->parent != parent) ||
	    child == parent)
		върни SSH_ERR_INTERNAL_ERROR;
	child->parent = parent;
	child->parent->refcount++;
	върни 0;
}

struct sshbuf *
sshbuf_fromb(struct sshbuf *buf)
{
	struct sshbuf *ret;

	ако (sshbuf_check_sanity(buf) != 0)
		върни NULL;
	ако ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == NULL)
		върни NULL;
	ако (sshbuf_set_parent(ret, buf) != 0) {
		sshbuf_free(ret);
		върни NULL;
	}
	върни ret;
}

void
sshbuf_free(struct sshbuf *buf)
{
	ако (buf == NULL)
		върни;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	ако (sshbuf_check_sanity(buf) != 0)
		върни;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	ако (buf->refcount > 0)
		върни;

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
		върни;
	}
	ако (sshbuf_check_sanity(buf) != 0)
		върни;
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
	върни buf->max_size;
}

size_t
sshbuf_alloc(const struct sshbuf *buf)
{
	върни buf->alloc;
}

const struct sshbuf *
sshbuf_parent(const struct sshbuf *buf)
{
	върни buf->parent;
}

u_int
sshbuf_refcount(const struct sshbuf *buf)
{
	върни buf->refcount;
}

цяло
sshbuf_set_max_size(struct sshbuf *buf, size_t max_size)
{
	size_t rlen;
	u_char *dp;
	цяло r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_size));
	ако ((r = sshbuf_check_sanity(buf)) != 0)
		върни r;
	ако (max_size == buf->max_size)
		върни 0;
	ако (buf->readonly || buf->refcount > 1)
		върни SSH_ERR_BUFFER_READ_ONLY;
	ако (max_size > SSHBUF_SIZE_MAX)
		върни SSH_ERR_NO_BUFFER_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_size < buf->size);
	ако (max_size < buf->alloc && max_size > buf->size) {
		ако (buf->size < SSHBUF_SIZE_INIT)
			rlen = SSHBUF_SIZE_INIT;
		иначе
			rlen = ROUNDUP(buf->size, SSHBUF_SIZE_INC);
		ако (rlen > max_size)
			rlen = max_size;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		ако ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == NULL)
			върни SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	ако (max_size < buf->alloc)
		върни SSH_ERR_NO_BUFFER_SPACE;
	buf->max_size = max_size;
	върни 0;
}

size_t
sshbuf_len(const struct sshbuf *buf)
{
	ако (sshbuf_check_sanity(buf) != 0)
		върни 0;
	върни buf->size - buf->off;
}

size_t
sshbuf_avail(const struct sshbuf *buf)
{
	ако (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		върни 0;
	върни buf->max_size - (buf->size - buf->off);
}

const u_char *
sshbuf_ptr(const struct sshbuf *buf)
{
	ако (sshbuf_check_sanity(buf) != 0)
		върни NULL;
	върни buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(const struct sshbuf *buf)
{
	ако (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		върни NULL;
	върни buf->d + buf->off;
}

цяло
sshbuf_check_reserve(const struct sshbuf *buf, size_t len)
{
	цяло r;

	ако ((r = sshbuf_check_sanity(buf)) != 0)
		върни r;
	ако (buf->readonly || buf->refcount > 1)
		върни SSH_ERR_BUFFER_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	ако (len > buf->max_size || buf->max_size - len < buf->size - buf->off)
		върни SSH_ERR_NO_BUFFER_SPACE;
	върни 0;
}

цяло
sshbuf_allocate(struct sshbuf *buf, size_t len)
{
	size_t rlen, need;
	u_char *dp;
	цяло r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	ако ((r = sshbuf_check_reserve(buf, len)) != 0)
		върни r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->size + len > buf->max_size);
	SSHBUF_TELL("allocate");
	ако (len + buf->size <= buf->alloc)
		върни 0; /* already have it. */

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
		върни SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	ако ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		върни r;
	}
	SSHBUF_TELL("done");
	върни 0;
}

цяло
sshbuf_reserve(struct sshbuf *buf, size_t len, u_char **dpp)
{
	u_char *dp;
	цяло r;

	ако (dpp != NULL)
		*dpp = NULL;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	ако ((r = sshbuf_allocate(buf, len)) != 0)
		върни r;

	dp = buf->d + buf->size;
	buf->size += len;
	ако (dpp != NULL)
		*dpp = dp;
	върни 0;
}

цяло
sshbuf_consume(struct sshbuf *buf, size_t len)
{
	цяло r;

	SSHBUF_DBG(("len = %zu", len));
	ако ((r = sshbuf_check_sanity(buf)) != 0)
		върни r;
	ако (len == 0)
		върни 0;
	ако (len > sshbuf_len(buf))
		върни SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	ако (buf->off == buf->size)
		buf->off = buf->size = 0;
	SSHBUF_TELL("done");
	върни 0;
}

цяло
sshbuf_consume_end(struct sshbuf *buf, size_t len)
{
	цяло r;

	SSHBUF_DBG(("len = %zu", len));
	ако ((r = sshbuf_check_sanity(buf)) != 0)
		върни r;
	ако (len == 0)
		върни 0;
	ако (len > sshbuf_len(buf))
		върни SSH_ERR_MESSAGE_INCOMPLETE;
	buf->size -= len;
	SSHBUF_TELL("done");
	върни 0;
}

цяло
sshbuf_consume_upto_child(struct sshbuf *buf, const struct sshbuf *child)
{
	цяло r;

	ако ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(child)) != 0)
		върни r;
	/* This function is only used for parent/child buffers */
	ако (child->parent != buf)
		върни SSH_ERR_INVALID_ARGUMENT;
	/* Nonsensical if the parent has advanced past the child */
	ако (sshbuf_len(child) > sshbuf_len(buf))
		върни SSH_ERR_INVALID_ARGUMENT;
	/* More paranoia, shouldn't happen */
	ако (child->cd < buf->cd)
		върни SSH_ERR_INTERNAL_ERROR;
	/* Advance */
	върни sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(child));
}
