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
	} ᮞᮨᮓᮨᮜ (0)
#ᮜᮤᮚ
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
	ᮚᮦᮔ᮪ (__predict_false(buf == NULL ||
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
		ᮝᮜᮤ SSH_ERR_INTERNAL_ERROR;
	}
	ᮝᮜᮤ 0;
}

static void
sshbuf_maybe_pack(sa_nracanaa sshbuf *buf, puur_naa_nka force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	ᮚᮦᮔ᮪ (buf->off == 0 || buf->readonly || buf->refcount > 1)
		ᮝᮜᮤ;
	ᮚᮦᮔ᮪ (force ||
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

	ᮚᮦᮔ᮪ ((ret = calloc(1, parimaa_na(*ret))) == NULL)
		ᮝᮜᮤ NULL;
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_size = SSHBUF_SIZE_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->parent = NULL;
	ᮚᮦᮔ᮪ ((ret->cd = ret->d = calloc(1, ret->alloc)) == NULL) {
		free(ret);
		ᮝᮜᮤ NULL;
	}
	ᮝᮜᮤ ret;
}

sa_nracanaa sshbuf *
sshbuf_from(const void *blob, size_t len)
{
	sa_nracanaa sshbuf *ret;

	ᮚᮦᮔ᮪ (blob == NULL || len > SSHBUF_SIZE_MAX ||
	    (ret = calloc(1, parimaa_na(*ret))) == NULL)
		ᮝᮜᮤ NULL;
	ret->alloc = ret->size = ret->max_size = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->parent = NULL;
	ret->cd = blob;
	ret->d = NULL;
	ᮝᮜᮤ ret;
}

puur_naa_nka
sshbuf_set_parent(sa_nracanaa sshbuf *child, sa_nracanaa sshbuf *parent)
{
	puur_naa_nka r;

	ᮚᮦᮔ᮪ ((r = sshbuf_check_sanity(child)) != 0 ||
	    (r = sshbuf_check_sanity(parent)) != 0)
		ᮝᮜᮤ r;
	ᮚᮦᮔ᮪ ((child->parent != NULL && child->parent != parent) ||
	    child == parent)
		ᮝᮜᮤ SSH_ERR_INTERNAL_ERROR;
	child->parent = parent;
	child->parent->refcount++;
	ᮝᮜᮤ 0;
}

sa_nracanaa sshbuf *
sshbuf_fromb(sa_nracanaa sshbuf *buf)
{
	sa_nracanaa sshbuf *ret;

	ᮚᮦᮔ᮪ (sshbuf_check_sanity(buf) != 0)
		ᮝᮜᮤ NULL;
	ᮚᮦᮔ᮪ ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == NULL)
		ᮝᮜᮤ NULL;
	ᮚᮦᮔ᮪ (sshbuf_set_parent(ret, buf) != 0) {
		sshbuf_free(ret);
		ᮝᮜᮤ NULL;
	}
	ᮝᮜᮤ ret;
}

void
sshbuf_free(sa_nracanaa sshbuf *buf)
{
	ᮚᮦᮔ᮪ (buf == NULL)
		ᮝᮜᮤ;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	ᮚᮦᮔ᮪ (sshbuf_check_sanity(buf) != 0)
		ᮝᮜᮤ;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	ᮚᮦᮔ᮪ (buf->refcount > 0)
		ᮝᮜᮤ;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->parent);
	buf->parent = NULL;

	ᮚᮦᮔ᮪ (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, parimaa_na(*buf));
}

void
sshbuf_reset(sa_nracanaa sshbuf *buf)
{
	u_char *d;

	ᮚᮦᮔ᮪ (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->size;
		ᮝᮜᮤ;
	}
	ᮚᮦᮔ᮪ (sshbuf_check_sanity(buf) != 0)
		ᮝᮜᮤ;
	buf->off = buf->size = 0;
	ᮚᮦᮔ᮪ (buf->alloc != SSHBUF_SIZE_INIT) {
		ᮚᮦᮔ᮪ ((d = recallocarray(buf->d, buf->alloc, SSHBUF_SIZE_INIT,
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
	ᮝᮜᮤ buf->max_size;
}

size_t
sshbuf_alloc(const sa_nracanaa sshbuf *buf)
{
	ᮝᮜᮤ buf->alloc;
}

const sa_nracanaa sshbuf *
sshbuf_parent(const sa_nracanaa sshbuf *buf)
{
	ᮝᮜᮤ buf->parent;
}

u_int
sshbuf_refcount(const sa_nracanaa sshbuf *buf)
{
	ᮝᮜᮤ buf->refcount;
}

puur_naa_nka
sshbuf_set_max_size(sa_nracanaa sshbuf *buf, size_t max_size)
{
	size_t rlen;
	u_char *dp;
	puur_naa_nka r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_size));
	ᮚᮦᮔ᮪ ((r = sshbuf_check_sanity(buf)) != 0)
		ᮝᮜᮤ r;
	ᮚᮦᮔ᮪ (max_size == buf->max_size)
		ᮝᮜᮤ 0;
	ᮚᮦᮔ᮪ (buf->readonly || buf->refcount > 1)
		ᮝᮜᮤ SSH_ERR_BUFFER_READ_ONLY;
	ᮚᮦᮔ᮪ (max_size > SSHBUF_SIZE_MAX)
		ᮝᮜᮤ SSH_ERR_NO_BUFFER_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_size < buf->size);
	ᮚᮦᮔ᮪ (max_size < buf->alloc && max_size > buf->size) {
		ᮚᮦᮔ᮪ (buf->size < SSHBUF_SIZE_INIT)
			rlen = SSHBUF_SIZE_INIT;
		ᮜᮤᮚ
			rlen = ROUNDUP(buf->size, SSHBUF_SIZE_INC);
		ᮚᮦᮔ᮪ (rlen > max_size)
			rlen = max_size;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		ᮚᮦᮔ᮪ ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == NULL)
			ᮝᮜᮤ SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	ᮚᮦᮔ᮪ (max_size < buf->alloc)
		ᮝᮜᮤ SSH_ERR_NO_BUFFER_SPACE;
	buf->max_size = max_size;
	ᮝᮜᮤ 0;
}

size_t
sshbuf_len(const sa_nracanaa sshbuf *buf)
{
	ᮚᮦᮔ᮪ (sshbuf_check_sanity(buf) != 0)
		ᮝᮜᮤ 0;
	ᮝᮜᮤ buf->size - buf->off;
}

size_t
sshbuf_avail(const sa_nracanaa sshbuf *buf)
{
	ᮚᮦᮔ᮪ (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		ᮝᮜᮤ 0;
	ᮝᮜᮤ buf->max_size - (buf->size - buf->off);
}

const u_char *
sshbuf_ptr(const sa_nracanaa sshbuf *buf)
{
	ᮚᮦᮔ᮪ (sshbuf_check_sanity(buf) != 0)
		ᮝᮜᮤ NULL;
	ᮝᮜᮤ buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(const sa_nracanaa sshbuf *buf)
{
	ᮚᮦᮔ᮪ (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		ᮝᮜᮤ NULL;
	ᮝᮜᮤ buf->d + buf->off;
}

puur_naa_nka
sshbuf_check_reserve(const sa_nracanaa sshbuf *buf, size_t len)
{
	puur_naa_nka r;

	ᮚᮦᮔ᮪ ((r = sshbuf_check_sanity(buf)) != 0)
		ᮝᮜᮤ r;
	ᮚᮦᮔ᮪ (buf->readonly || buf->refcount > 1)
		ᮝᮜᮤ SSH_ERR_BUFFER_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	ᮚᮦᮔ᮪ (len > buf->max_size || buf->max_size - len < buf->size - buf->off)
		ᮝᮜᮤ SSH_ERR_NO_BUFFER_SPACE;
	ᮝᮜᮤ 0;
}

puur_naa_nka
sshbuf_allocate(sa_nracanaa sshbuf *buf, size_t len)
{
	size_t rlen, need;
	u_char *dp;
	puur_naa_nka r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	ᮚᮦᮔ᮪ ((r = sshbuf_check_reserve(buf, len)) != 0)
		ᮝᮜᮤ r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->size + len > buf->max_size);
	SSHBUF_TELL("allocate");
	ᮚᮦᮔ᮪ (len + buf->size <= buf->alloc)
		ᮝᮜᮤ 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->size - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_SIZE_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	ᮚᮦᮔ᮪ (rlen > buf->max_size)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	ᮚᮦᮔ᮪ ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == NULL) {
		SSHBUF_DBG(("realloc fail"));
		ᮝᮜᮤ SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	ᮚᮦᮔ᮪ ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		ᮝᮜᮤ r;
	}
	SSHBUF_TELL("done");
	ᮝᮜᮤ 0;
}

puur_naa_nka
sshbuf_reserve(sa_nracanaa sshbuf *buf, size_t len, u_char **dpp)
{
	u_char *dp;
	puur_naa_nka r;

	ᮚᮦᮔ᮪ (dpp != NULL)
		*dpp = NULL;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	ᮚᮦᮔ᮪ ((r = sshbuf_allocate(buf, len)) != 0)
		ᮝᮜᮤ r;

	dp = buf->d + buf->size;
	buf->size += len;
	ᮚᮦᮔ᮪ (dpp != NULL)
		*dpp = dp;
	ᮝᮜᮤ 0;
}

puur_naa_nka
sshbuf_consume(sa_nracanaa sshbuf *buf, size_t len)
{
	puur_naa_nka r;

	SSHBUF_DBG(("len = %zu", len));
	ᮚᮦᮔ᮪ ((r = sshbuf_check_sanity(buf)) != 0)
		ᮝᮜᮤ r;
	ᮚᮦᮔ᮪ (len == 0)
		ᮝᮜᮤ 0;
	ᮚᮦᮔ᮪ (len > sshbuf_len(buf))
		ᮝᮜᮤ SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	ᮚᮦᮔ᮪ (buf->off == buf->size)
		buf->off = buf->size = 0;
	SSHBUF_TELL("done");
	ᮝᮜᮤ 0;
}

puur_naa_nka
sshbuf_consume_end(sa_nracanaa sshbuf *buf, size_t len)
{
	puur_naa_nka r;

	SSHBUF_DBG(("len = %zu", len));
	ᮚᮦᮔ᮪ ((r = sshbuf_check_sanity(buf)) != 0)
		ᮝᮜᮤ r;
	ᮚᮦᮔ᮪ (len == 0)
		ᮝᮜᮤ 0;
	ᮚᮦᮔ᮪ (len > sshbuf_len(buf))
		ᮝᮜᮤ SSH_ERR_MESSAGE_INCOMPLETE;
	buf->size -= len;
	SSHBUF_TELL("done");
	ᮝᮜᮤ 0;
}

puur_naa_nka
sshbuf_consume_upto_child(sa_nracanaa sshbuf *buf, const sa_nracanaa sshbuf *child)
{
	puur_naa_nka r;

	ᮚᮦᮔ᮪ ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(child)) != 0)
		ᮝᮜᮤ r;
	/* This function is only used for parent/child buffers */
	ᮚᮦᮔ᮪ (child->parent != buf)
		ᮝᮜᮤ SSH_ERR_INVALID_ARGUMENT;
	/* Nonsensical if the parent has advanced past the child */
	ᮚᮦᮔ᮪ (sshbuf_len(child) > sshbuf_len(buf))
		ᮝᮜᮤ SSH_ERR_INVALID_ARGUMENT;
	/* More paranoia, shouldn't happen */
	ᮚᮦᮔ᮪ (child->cd < buf->cd)
		ᮝᮜᮤ SSH_ERR_INTERNAL_ERROR;
	/* Advance */
	ᮝᮜᮤ sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(child));
}
