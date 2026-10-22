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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "ssherr.h"
#define SSHBUF_INTERNAL
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

#ifdef SSHBUF_DEBUG
# define SSHBUF_TELL(what) ಕುರು { \
		printf("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __FILE__, __LINE__, __func__, what, \
		    buf->size, buf->alloc, buf->off, buf->max_size); \
		fflush(stdout); \
	} ಯಾವತ್ (0)
#ಅನ್ಯಥಾ
# define SSHBUF_TELL(what)
#endif

ಸಂರಚನಾ sshbuf {
	u_char *d;		/* Data */
	ಧ್ರುವ u_char *cd;	/* Const data */
	size_t off;		/* First available byte is buf->d + buf->off */
	size_t size;		/* Last byte is buf->d + buf->size - 1 */
	size_t max_size;	/* Maximum size of buffer */
	size_t alloc;		/* Total bytes allocated to buf->d */
	ಪೂರ್ಣಾಙ್ಕ readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	ಸಂರಚನಾ sshbuf *parent;	/* If child, pointer to parent */
};

ಸ್ಥಿರ ಅನ್ತಃಸ್ಥ ಪೂರ್ಣಾಙ್ಕ
sshbuf_check_sanity(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	ಯದಿ (__predict_false(buf == ರಿಕ್ತ ||
	    (!buf->readonly && buf->d != buf->cd) ||
	    buf->parent == buf ||
	    buf->refcount < 1 || buf->refcount > SSHBUF_REFS_MAX ||
	    buf->cd == ರಿಕ್ತ ||
	    buf->max_size > SSHBUF_SIZE_MAX ||
	    buf->alloc > buf->max_size ||
	    buf->size > buf->alloc ||
	    buf->off > buf->size)) {
		/* Do not try to recover from corrupted buffer internals */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		ssh_signal(SIGSEGV, SIG_DFL);
		ಉತ್ಥಾಪಯ(SIGSEGV);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
sshbuf_maybe_pack(ಸಂರಚನಾ sshbuf *buf, ಪೂರ್ಣಾಙ್ಕ force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	ಯದಿ (buf->off == 0 || buf->readonly || buf->refcount > 1)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->size / 2)) {
		memmove(buf->d, buf->d + buf->off, buf->size - buf->off);
		buf->size -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

ಸಂರಚನಾ sshbuf *
sshbuf_new(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ sshbuf *ret;

	ಯದಿ ((ret = calloc(1, ಪರಿಮಾಣ(*ret))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_size = SSHBUF_SIZE_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->parent = ರಿಕ್ತ;
	ಯದಿ ((ret->cd = ret->d = calloc(1, ret->alloc)) == ರಿಕ್ತ) {
		ಮುಕ್ತ(ret);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸಂರಚನಾ sshbuf *
sshbuf_from(ಧ್ರುವ ಶೂನ್ಯ *blob, size_t len)
{
	ಸಂರಚನಾ sshbuf *ret;

	ಯದಿ (blob == ರಿಕ್ತ || len > SSHBUF_SIZE_MAX ||
	    (ret = calloc(1, ಪರಿಮಾಣ(*ret))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ret->alloc = ret->size = ret->max_size = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->parent = ರಿಕ್ತ;
	ret->cd = blob;
	ret->d = ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_set_parent(ಸಂರಚನಾ sshbuf *child, ಸಂರಚನಾ sshbuf *parent)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_check_sanity(child)) != 0 ||
	    (r = sshbuf_check_sanity(parent)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((child->parent != ರಿಕ್ತ && child->parent != parent) ||
	    child == parent)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	child->parent = parent;
	child->parent->refcount++;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸಂರಚನಾ sshbuf *
sshbuf_fromb(ಸಂರಚನಾ sshbuf *buf)
{
	ಸಂರಚನಾ sshbuf *ret;

	ಯದಿ (sshbuf_check_sanity(buf) != 0)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಯದಿ ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಯದಿ (sshbuf_set_parent(ret, buf) != 0) {
		sshbuf_free(ret);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಶೂನ್ಯ
sshbuf_free(ಸಂರಚನಾ sshbuf *buf)
{
	ಯದಿ (buf == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	ಯದಿ (sshbuf_check_sanity(buf) != 0)
		ಪ್ರತ್ಯಾಗಮ;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	ಯದಿ (buf->refcount > 0)
		ಪ್ರತ್ಯಾಗಮ;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->parent);
	buf->parent = ರಿಕ್ತ;

	ಯದಿ (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, ಪರಿಮಾಣ(*buf));
}

ಶೂನ್ಯ
sshbuf_reset(ಸಂರಚನಾ sshbuf *buf)
{
	u_char *d;

	ಯದಿ (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->size;
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ (sshbuf_check_sanity(buf) != 0)
		ಪ್ರತ್ಯಾಗಮ;
	buf->off = buf->size = 0;
	ಯದಿ (buf->alloc != SSHBUF_SIZE_INIT) {
		ಯದಿ ((d = recallocarray(buf->d, buf->alloc, SSHBUF_SIZE_INIT,
		    1)) != ರಿಕ್ತ) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_SIZE_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

size_t
sshbuf_max_size(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf)
{
	ಪ್ರತ್ಯಾಗಮ buf->max_size;
}

size_t
sshbuf_alloc(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf)
{
	ಪ್ರತ್ಯಾಗಮ buf->alloc;
}

ಧ್ರುವ ಸಂರಚನಾ sshbuf *
sshbuf_parent(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf)
{
	ಪ್ರತ್ಯಾಗಮ buf->parent;
}

u_int
sshbuf_refcount(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf)
{
	ಪ್ರತ್ಯಾಗಮ buf->refcount;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_set_max_size(ಸಂರಚನಾ sshbuf *buf, size_t max_size)
{
	size_t rlen;
	u_char *dp;
	ಪೂರ್ಣಾಙ್ಕ r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_size));
	ಯದಿ ((r = sshbuf_check_sanity(buf)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (max_size == buf->max_size)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (buf->readonly || buf->refcount > 1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_BUFFER_READ_ONLY;
	ಯದಿ (max_size > SSHBUF_SIZE_MAX)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_NO_BUFFER_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_size < buf->size);
	ಯದಿ (max_size < buf->alloc && max_size > buf->size) {
		ಯದಿ (buf->size < SSHBUF_SIZE_INIT)
			rlen = SSHBUF_SIZE_INIT;
		ಅನ್ಯಥಾ
			rlen = ROUNDUP(buf->size, SSHBUF_SIZE_INC);
		ಯದಿ (rlen > max_size)
			rlen = max_size;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		ಯದಿ ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	ಯದಿ (max_size < buf->alloc)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_NO_BUFFER_SPACE;
	buf->max_size = max_size;
	ಪ್ರತ್ಯಾಗಮ 0;
}

size_t
sshbuf_len(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf)
{
	ಯದಿ (sshbuf_check_sanity(buf) != 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ buf->size - buf->off;
}

size_t
sshbuf_avail(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf)
{
	ಯದಿ (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ buf->max_size - (buf->size - buf->off);
}

ಧ್ರುವ u_char *
sshbuf_ptr(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf)
{
	ಯದಿ (sshbuf_check_sanity(buf) != 0)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf)
{
	ಯದಿ (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ buf->d + buf->off;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_check_reserve(ಧ್ರುವ ಸಂರಚನಾ sshbuf *buf, size_t len)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_check_sanity(buf)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (buf->readonly || buf->refcount > 1)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_BUFFER_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	ಯದಿ (len > buf->max_size || buf->max_size - len < buf->size - buf->off)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_NO_BUFFER_SPACE;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_allocate(ಸಂರಚನಾ sshbuf *buf, size_t len)
{
	size_t rlen, need;
	u_char *dp;
	ಪೂರ್ಣಾಙ್ಕ r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	ಯದಿ ((r = sshbuf_check_reserve(buf, len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->size + len > buf->max_size);
	SSHBUF_TELL("allocate");
	ಯದಿ (len + buf->size <= buf->alloc)
		ಪ್ರತ್ಯಾಗಮ 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->size - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_SIZE_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	ಯದಿ (rlen > buf->max_size)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	ಯದಿ ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == ರಿಕ್ತ) {
		SSHBUF_DBG(("realloc fail"));
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	ಯದಿ ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		ಪ್ರತ್ಯಾಗಮ r;
	}
	SSHBUF_TELL("done");
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_reserve(ಸಂರಚನಾ sshbuf *buf, size_t len, u_char **dpp)
{
	u_char *dp;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (dpp != ರಿಕ್ತ)
		*dpp = ರಿಕ್ತ;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	ಯದಿ ((r = sshbuf_allocate(buf, len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	dp = buf->d + buf->size;
	buf->size += len;
	ಯದಿ (dpp != ರಿಕ್ತ)
		*dpp = dp;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_consume(ಸಂರಚನಾ sshbuf *buf, size_t len)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	SSHBUF_DBG(("len = %zu", len));
	ಯದಿ ((r = sshbuf_check_sanity(buf)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (len == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (len > sshbuf_len(buf))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	ಯದಿ (buf->off == buf->size)
		buf->off = buf->size = 0;
	SSHBUF_TELL("done");
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_consume_end(ಸಂರಚನಾ sshbuf *buf, size_t len)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	SSHBUF_DBG(("len = %zu", len));
	ಯದಿ ((r = sshbuf_check_sanity(buf)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (len == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (len > sshbuf_len(buf))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_MESSAGE_INCOMPLETE;
	buf->size -= len;
	SSHBUF_TELL("done");
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshbuf_consume_upto_child(ಸಂರಚನಾ sshbuf *buf, ಧ್ರುವ ಸಂರಚನಾ sshbuf *child)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(child)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	/* This function is only used for parent/child buffers */
	ಯದಿ (child->parent != buf)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	/* Nonsensical if the parent has advanced past the child */
	ಯದಿ (sshbuf_len(child) > sshbuf_len(buf))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	/* More paranoia, shouldn't happen */
	ಯದಿ (child->cd < buf->cd)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	/* Advance */
	ಪ್ರತ್ಯಾಗಮ sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(child));
}
