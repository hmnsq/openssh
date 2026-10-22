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
	} ᤀᤠ᤺ (0)
#ᤀᤡ᤺ᤆᤡ
# define SSHBUF_TELL(what)
#endif

sa_nracanaa sshbuf {
	u_char *d;		/* Data */
	const u_char *cd;	/* Const data */
	size_t off;		/* First available byte is buf->d + buf->off */
	size_t size;		/* Last byte is buf->d + buf->size - 1 */
	size_t max_size;	/* Maximum size of buffer */
	size_t alloc;		/* Total bytes allocated to buf->d */
	puur_naa_nka readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	sa_nracanaa sshbuf *parent;	/* If child, pointer to parent */
};

static anta_hstha puur_naa_nka
sshbuf_check_sanity(const sa_nracanaa sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	ᤀᤡ᤺ (__predict_false(buf == NULL ||
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
		ᤀᤡᤴ SSH_ERR_INTERNAL_ERROR;
	}
	ᤀᤡᤴ 0;
}

static void
sshbuf_maybe_pack(sa_nracanaa sshbuf *buf, puur_naa_nka force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	ᤀᤡ᤺ (buf->off == 0 || buf->readonly || buf->refcount > 1)
		ᤀᤡᤴ;
	ᤀᤡ᤺ (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->size / 2)) {
		memmove(buf->d, buf->d + buf->off, buf->size - buf->off);
		buf->size -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

sa_nracanaa sshbuf *
sshbuf_new(void)
{
	sa_nracanaa sshbuf *ret;

	ᤀᤡ᤺ ((ret = calloc(1, parimaa_na(*ret))) == NULL)
		ᤀᤡᤴ NULL;
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_size = SSHBUF_SIZE_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->parent = NULL;
	ᤀᤡ᤺ ((ret->cd = ret->d = calloc(1, ret->alloc)) == NULL) {
		free(ret);
		ᤀᤡᤴ NULL;
	}
	ᤀᤡᤴ ret;
}

sa_nracanaa sshbuf *
sshbuf_from(const void *blob, size_t len)
{
	sa_nracanaa sshbuf *ret;

	ᤀᤡ᤺ (blob == NULL || len > SSHBUF_SIZE_MAX ||
	    (ret = calloc(1, parimaa_na(*ret))) == NULL)
		ᤀᤡᤴ NULL;
	ret->alloc = ret->size = ret->max_size = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->parent = NULL;
	ret->cd = blob;
	ret->d = NULL;
	ᤀᤡᤴ ret;
}

puur_naa_nka
sshbuf_set_parent(sa_nracanaa sshbuf *child, sa_nracanaa sshbuf *parent)
{
	puur_naa_nka r;

	ᤀᤡ᤺ ((r = sshbuf_check_sanity(child)) != 0 ||
	    (r = sshbuf_check_sanity(parent)) != 0)
		ᤀᤡᤴ r;
	ᤀᤡ᤺ ((child->parent != NULL && child->parent != parent) ||
	    child == parent)
		ᤀᤡᤴ SSH_ERR_INTERNAL_ERROR;
	child->parent = parent;
	child->parent->refcount++;
	ᤀᤡᤴ 0;
}

sa_nracanaa sshbuf *
sshbuf_fromb(sa_nracanaa sshbuf *buf)
{
	sa_nracanaa sshbuf *ret;

	ᤀᤡ᤺ (sshbuf_check_sanity(buf) != 0)
		ᤀᤡᤴ NULL;
	ᤀᤡ᤺ ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == NULL)
		ᤀᤡᤴ NULL;
	ᤀᤡ᤺ (sshbuf_set_parent(ret, buf) != 0) {
		sshbuf_free(ret);
		ᤀᤡᤴ NULL;
	}
	ᤀᤡᤴ ret;
}

void
sshbuf_free(sa_nracanaa sshbuf *buf)
{
	ᤀᤡ᤺ (buf == NULL)
		ᤀᤡᤴ;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	ᤀᤡ᤺ (sshbuf_check_sanity(buf) != 0)
		ᤀᤡᤴ;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	ᤀᤡ᤺ (buf->refcount > 0)
		ᤀᤡᤴ;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->parent);
	buf->parent = NULL;

	ᤀᤡ᤺ (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, parimaa_na(*buf));
}

void
sshbuf_reset(sa_nracanaa sshbuf *buf)
{
	u_char *d;

	ᤀᤡ᤺ (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->size;
		ᤀᤡᤴ;
	}
	ᤀᤡ᤺ (sshbuf_check_sanity(buf) != 0)
		ᤀᤡᤴ;
	buf->off = buf->size = 0;
	ᤀᤡ᤺ (buf->alloc != SSHBUF_SIZE_INIT) {
		ᤀᤡ᤺ ((d = recallocarray(buf->d, buf->alloc, SSHBUF_SIZE_INIT,
		    1)) != NULL) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_SIZE_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

size_t
sshbuf_max_size(const sa_nracanaa sshbuf *buf)
{
	ᤀᤡᤴ buf->max_size;
}

size_t
sshbuf_alloc(const sa_nracanaa sshbuf *buf)
{
	ᤀᤡᤴ buf->alloc;
}

const sa_nracanaa sshbuf *
sshbuf_parent(const sa_nracanaa sshbuf *buf)
{
	ᤀᤡᤴ buf->parent;
}

u_int
sshbuf_refcount(const sa_nracanaa sshbuf *buf)
{
	ᤀᤡᤴ buf->refcount;
}

puur_naa_nka
sshbuf_set_max_size(sa_nracanaa sshbuf *buf, size_t max_size)
{
	size_t rlen;
	u_char *dp;
	puur_naa_nka r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_size));
	ᤀᤡ᤺ ((r = sshbuf_check_sanity(buf)) != 0)
		ᤀᤡᤴ r;
	ᤀᤡ᤺ (max_size == buf->max_size)
		ᤀᤡᤴ 0;
	ᤀᤡ᤺ (buf->readonly || buf->refcount > 1)
		ᤀᤡᤴ SSH_ERR_BUFFER_READ_ONLY;
	ᤀᤡ᤺ (max_size > SSHBUF_SIZE_MAX)
		ᤀᤡᤴ SSH_ERR_NO_BUFFER_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_size < buf->size);
	ᤀᤡ᤺ (max_size < buf->alloc && max_size > buf->size) {
		ᤀᤡ᤺ (buf->size < SSHBUF_SIZE_INIT)
			rlen = SSHBUF_SIZE_INIT;
		ᤀᤡ᤺ᤆᤡ
			rlen = ROUNDUP(buf->size, SSHBUF_SIZE_INC);
		ᤀᤡ᤺ (rlen > max_size)
			rlen = max_size;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		ᤀᤡ᤺ ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == NULL)
			ᤀᤡᤴ SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	ᤀᤡ᤺ (max_size < buf->alloc)
		ᤀᤡᤴ SSH_ERR_NO_BUFFER_SPACE;
	buf->max_size = max_size;
	ᤀᤡᤴ 0;
}

size_t
sshbuf_len(const sa_nracanaa sshbuf *buf)
{
	ᤀᤡ᤺ (sshbuf_check_sanity(buf) != 0)
		ᤀᤡᤴ 0;
	ᤀᤡᤴ buf->size - buf->off;
}

size_t
sshbuf_avail(const sa_nracanaa sshbuf *buf)
{
	ᤀᤡ᤺ (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		ᤀᤡᤴ 0;
	ᤀᤡᤴ buf->max_size - (buf->size - buf->off);
}

const u_char *
sshbuf_ptr(const sa_nracanaa sshbuf *buf)
{
	ᤀᤡ᤺ (sshbuf_check_sanity(buf) != 0)
		ᤀᤡᤴ NULL;
	ᤀᤡᤴ buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(const sa_nracanaa sshbuf *buf)
{
	ᤀᤡ᤺ (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		ᤀᤡᤴ NULL;
	ᤀᤡᤴ buf->d + buf->off;
}

puur_naa_nka
sshbuf_check_reserve(const sa_nracanaa sshbuf *buf, size_t len)
{
	puur_naa_nka r;

	ᤀᤡ᤺ ((r = sshbuf_check_sanity(buf)) != 0)
		ᤀᤡᤴ r;
	ᤀᤡ᤺ (buf->readonly || buf->refcount > 1)
		ᤀᤡᤴ SSH_ERR_BUFFER_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	ᤀᤡ᤺ (len > buf->max_size || buf->max_size - len < buf->size - buf->off)
		ᤀᤡᤴ SSH_ERR_NO_BUFFER_SPACE;
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_allocate(sa_nracanaa sshbuf *buf, size_t len)
{
	size_t rlen, need;
	u_char *dp;
	puur_naa_nka r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	ᤀᤡ᤺ ((r = sshbuf_check_reserve(buf, len)) != 0)
		ᤀᤡᤴ r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->size + len > buf->max_size);
	SSHBUF_TELL("allocate");
	ᤀᤡ᤺ (len + buf->size <= buf->alloc)
		ᤀᤡᤴ 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->size - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_SIZE_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	ᤀᤡ᤺ (rlen > buf->max_size)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	ᤀᤡ᤺ ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == NULL) {
		SSHBUF_DBG(("realloc fail"));
		ᤀᤡᤴ SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	ᤀᤡ᤺ ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		ᤀᤡᤴ r;
	}
	SSHBUF_TELL("done");
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_reserve(sa_nracanaa sshbuf *buf, size_t len, u_char **dpp)
{
	u_char *dp;
	puur_naa_nka r;

	ᤀᤡ᤺ (dpp != NULL)
		*dpp = NULL;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	ᤀᤡ᤺ ((r = sshbuf_allocate(buf, len)) != 0)
		ᤀᤡᤴ r;

	dp = buf->d + buf->size;
	buf->size += len;
	ᤀᤡ᤺ (dpp != NULL)
		*dpp = dp;
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_consume(sa_nracanaa sshbuf *buf, size_t len)
{
	puur_naa_nka r;

	SSHBUF_DBG(("len = %zu", len));
	ᤀᤡ᤺ ((r = sshbuf_check_sanity(buf)) != 0)
		ᤀᤡᤴ r;
	ᤀᤡ᤺ (len == 0)
		ᤀᤡᤴ 0;
	ᤀᤡ᤺ (len > sshbuf_len(buf))
		ᤀᤡᤴ SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	ᤀᤡ᤺ (buf->off == buf->size)
		buf->off = buf->size = 0;
	SSHBUF_TELL("done");
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_consume_end(sa_nracanaa sshbuf *buf, size_t len)
{
	puur_naa_nka r;

	SSHBUF_DBG(("len = %zu", len));
	ᤀᤡ᤺ ((r = sshbuf_check_sanity(buf)) != 0)
		ᤀᤡᤴ r;
	ᤀᤡ᤺ (len == 0)
		ᤀᤡᤴ 0;
	ᤀᤡ᤺ (len > sshbuf_len(buf))
		ᤀᤡᤴ SSH_ERR_MESSAGE_INCOMPLETE;
	buf->size -= len;
	SSHBUF_TELL("done");
	ᤀᤡᤴ 0;
}

puur_naa_nka
sshbuf_consume_upto_child(sa_nracanaa sshbuf *buf, const sa_nracanaa sshbuf *child)
{
	puur_naa_nka r;

	ᤀᤡ᤺ ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(child)) != 0)
		ᤀᤡᤴ r;
	/* This function is only used for parent/child buffers */
	ᤀᤡ᤺ (child->parent != buf)
		ᤀᤡᤴ SSH_ERR_INVALID_ARGUMENT;
	/* Nonsensical if the parent has advanced past the child */
	ᤀᤡ᤺ (sshbuf_len(child) > sshbuf_len(buf))
		ᤀᤡᤴ SSH_ERR_INVALID_ARGUMENT;
	/* More paranoia, shouldn't happen */
	ᤀᤡ᤺ (child->cd < buf->cd)
		ᤀᤡᤴ SSH_ERR_INTERNAL_ERROR;
	/* Advance */
	ᤀᤡᤴ sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(child));
}
