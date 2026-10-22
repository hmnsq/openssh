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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#define SSHBUF_INTERNAL
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"

#ifdef SSHBUF_DEBUG
# define SSHBUF_TELL(what) କର { \
		printf("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __FILE__, __LINE__, __func__, what, \
		    buf->size, buf->alloc, buf->off, buf->max_size); \
		fflush(stdout); \
	} ଯେତେବେଳେ (0)
#ଅନ୍ୟଥା
# define SSHBUF_TELL(what)
#endif

ସଂରଚନା sshbuf {
	u_char *d;		/* Data */
	ଅଚଳ u_char *cd;	/* Const data */
	size_t off;		/* First available byte is buf->d + buf->off */
	size_t size;		/* Last byte is buf->d + buf->size - 1 */
	size_t max_size;	/* Maximum size of buffer */
	size_t alloc;		/* Total bytes allocated to buf->d */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	ସଂରଚନା sshbuf *parent;	/* If child, pointer to parent */
};

ସ୍ଥିର ଧାଡ଼ିଭିତରେ ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_check_sanity(ଅଚଳ ସଂରଚନା sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	ଯଦି (__predict_false(buf == ଖାଲି ||
	    (!buf->readonly && buf->d != buf->cd) ||
	    buf->parent == buf ||
	    buf->refcount < 1 || buf->refcount > SSHBUF_REFS_MAX ||
	    buf->cd == ଖାଲି ||
	    buf->max_size > SSHBUF_SIZE_MAX ||
	    buf->alloc > buf->max_size ||
	    buf->size > buf->alloc ||
	    buf->off > buf->size)) {
		/* Do not try to recover from corrupted buffer internals */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		ssh_signal(SIGSEGV, SIG_DFL);
		ଉଠାଅ(SIGSEGV);
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
sshbuf_maybe_pack(ସଂରଚନା sshbuf *buf, ପୂର୍ଣ୍ଣସଂଖ୍ୟା force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	ଯଦି (buf->off == 0 || buf->readonly || buf->refcount > 1)
		ଫେରନ୍ତୁ;
	ଯଦି (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->size / 2)) {
		memmove(buf->d, buf->d + buf->off, buf->size - buf->off);
		buf->size -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

ସଂରଚନା sshbuf *
sshbuf_new(ଶୂନ୍ୟ)
{
	ସଂରଚନା sshbuf *ret;

	ଯଦି ((ret = calloc(1, ଆକାର(*ret))) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_size = SSHBUF_SIZE_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->parent = ଖାଲି;
	ଯଦି ((ret->cd = ret->d = calloc(1, ret->alloc)) == ଖାଲି) {
		ମୁକ୍ତ(ret);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଫେରନ୍ତୁ ret;
}

ସଂରଚନା sshbuf *
sshbuf_from(ଅଚଳ ଶୂନ୍ୟ *blob, size_t len)
{
	ସଂରଚନା sshbuf *ret;

	ଯଦି (blob == ଖାଲି || len > SSHBUF_SIZE_MAX ||
	    (ret = calloc(1, ଆକାର(*ret))) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	ret->alloc = ret->size = ret->max_size = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->parent = ଖାଲି;
	ret->cd = blob;
	ret->d = ଖାଲି;
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_set_parent(ସଂରଚନା sshbuf *child, ସଂରଚନା sshbuf *parent)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_check_sanity(child)) != 0 ||
	    (r = sshbuf_check_sanity(parent)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((child->parent != ଖାଲି && child->parent != parent) ||
	    child == parent)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	child->parent = parent;
	child->parent->refcount++;
	ଫେରନ୍ତୁ 0;
}

ସଂରଚନା sshbuf *
sshbuf_fromb(ସଂରଚନା sshbuf *buf)
{
	ସଂରଚନା sshbuf *ret;

	ଯଦି (sshbuf_check_sanity(buf) != 0)
		ଫେରନ୍ତୁ ଖାଲି;
	ଯଦି ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	ଯଦି (sshbuf_set_parent(ret, buf) != 0) {
		sshbuf_free(ret);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଫେରନ୍ତୁ ret;
}

ଶୂନ୍ୟ
sshbuf_free(ସଂରଚନା sshbuf *buf)
{
	ଯଦି (buf == ଖାଲି)
		ଫେରନ୍ତୁ;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	ଯଦି (sshbuf_check_sanity(buf) != 0)
		ଫେରନ୍ତୁ;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	ଯଦି (buf->refcount > 0)
		ଫେରନ୍ତୁ;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->parent);
	buf->parent = ଖାଲି;

	ଯଦି (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, ଆକାର(*buf));
}

ଶୂନ୍ୟ
sshbuf_reset(ସଂରଚନା sshbuf *buf)
{
	u_char *d;

	ଯଦି (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->size;
		ଫେରନ୍ତୁ;
	}
	ଯଦି (sshbuf_check_sanity(buf) != 0)
		ଫେରନ୍ତୁ;
	buf->off = buf->size = 0;
	ଯଦି (buf->alloc != SSHBUF_SIZE_INIT) {
		ଯଦି ((d = recallocarray(buf->d, buf->alloc, SSHBUF_SIZE_INIT,
		    1)) != ଖାଲି) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_SIZE_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

size_t
sshbuf_max_size(ଅଚଳ ସଂରଚନା sshbuf *buf)
{
	ଫେରନ୍ତୁ buf->max_size;
}

size_t
sshbuf_alloc(ଅଚଳ ସଂରଚନା sshbuf *buf)
{
	ଫେରନ୍ତୁ buf->alloc;
}

ଅଚଳ ସଂରଚନା sshbuf *
sshbuf_parent(ଅଚଳ ସଂରଚନା sshbuf *buf)
{
	ଫେରନ୍ତୁ buf->parent;
}

u_int
sshbuf_refcount(ଅଚଳ ସଂରଚନା sshbuf *buf)
{
	ଫେରନ୍ତୁ buf->refcount;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_set_max_size(ସଂରଚନା sshbuf *buf, size_t max_size)
{
	size_t rlen;
	u_char *dp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_size));
	ଯଦି ((r = sshbuf_check_sanity(buf)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (max_size == buf->max_size)
		ଫେରନ୍ତୁ 0;
	ଯଦି (buf->readonly || buf->refcount > 1)
		ଫେରନ୍ତୁ SSH_ERR_BUFFER_READ_ONLY;
	ଯଦି (max_size > SSHBUF_SIZE_MAX)
		ଫେରନ୍ତୁ SSH_ERR_NO_BUFFER_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_size < buf->size);
	ଯଦି (max_size < buf->alloc && max_size > buf->size) {
		ଯଦି (buf->size < SSHBUF_SIZE_INIT)
			rlen = SSHBUF_SIZE_INIT;
		ଅନ୍ୟଥା
			rlen = ROUNDUP(buf->size, SSHBUF_SIZE_INC);
		ଯଦି (rlen > max_size)
			rlen = max_size;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		ଯଦି ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == ଖାଲି)
			ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	ଯଦି (max_size < buf->alloc)
		ଫେରନ୍ତୁ SSH_ERR_NO_BUFFER_SPACE;
	buf->max_size = max_size;
	ଫେରନ୍ତୁ 0;
}

size_t
sshbuf_len(ଅଚଳ ସଂରଚନା sshbuf *buf)
{
	ଯଦି (sshbuf_check_sanity(buf) != 0)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ buf->size - buf->off;
}

size_t
sshbuf_avail(ଅଚଳ ସଂରଚନା sshbuf *buf)
{
	ଯଦି (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ buf->max_size - (buf->size - buf->off);
}

ଅଚଳ u_char *
sshbuf_ptr(ଅଚଳ ସଂରଚନା sshbuf *buf)
{
	ଯଦି (sshbuf_check_sanity(buf) != 0)
		ଫେରନ୍ତୁ ଖାଲି;
	ଫେରନ୍ତୁ buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(ଅଚଳ ସଂରଚନା sshbuf *buf)
{
	ଯଦି (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		ଫେରନ୍ତୁ ଖାଲି;
	ଫେରନ୍ତୁ buf->d + buf->off;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_check_reserve(ଅଚଳ ସଂରଚନା sshbuf *buf, size_t len)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_check_sanity(buf)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (buf->readonly || buf->refcount > 1)
		ଫେରନ୍ତୁ SSH_ERR_BUFFER_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	ଯଦି (len > buf->max_size || buf->max_size - len < buf->size - buf->off)
		ଫେରନ୍ତୁ SSH_ERR_NO_BUFFER_SPACE;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_allocate(ସଂରଚନା sshbuf *buf, size_t len)
{
	size_t rlen, need;
	u_char *dp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	ଯଦି ((r = sshbuf_check_reserve(buf, len)) != 0)
		ଫେରନ୍ତୁ r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->size + len > buf->max_size);
	SSHBUF_TELL("allocate");
	ଯଦି (len + buf->size <= buf->alloc)
		ଫେରନ୍ତୁ 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->size - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_SIZE_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	ଯଦି (rlen > buf->max_size)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	ଯଦି ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == ଖାଲି) {
		SSHBUF_DBG(("realloc fail"));
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	ଯଦି ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		ଫେରନ୍ତୁ r;
	}
	SSHBUF_TELL("done");
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_reserve(ସଂରଚନା sshbuf *buf, size_t len, u_char **dpp)
{
	u_char *dp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (dpp != ଖାଲି)
		*dpp = ଖାଲି;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	ଯଦି ((r = sshbuf_allocate(buf, len)) != 0)
		ଫେରନ୍ତୁ r;

	dp = buf->d + buf->size;
	buf->size += len;
	ଯଦି (dpp != ଖାଲି)
		*dpp = dp;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_consume(ସଂରଚନା sshbuf *buf, size_t len)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	SSHBUF_DBG(("len = %zu", len));
	ଯଦି ((r = sshbuf_check_sanity(buf)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (len == 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି (len > sshbuf_len(buf))
		ଫେରନ୍ତୁ SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	ଯଦି (buf->off == buf->size)
		buf->off = buf->size = 0;
	SSHBUF_TELL("done");
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_consume_end(ସଂରଚନା sshbuf *buf, size_t len)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	SSHBUF_DBG(("len = %zu", len));
	ଯଦି ((r = sshbuf_check_sanity(buf)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (len == 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି (len > sshbuf_len(buf))
		ଫେରନ୍ତୁ SSH_ERR_MESSAGE_INCOMPLETE;
	buf->size -= len;
	SSHBUF_TELL("done");
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshbuf_consume_upto_child(ସଂରଚନା sshbuf *buf, ଅଚଳ ସଂରଚନା sshbuf *child)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(child)) != 0)
		ଫେରନ୍ତୁ r;
	/* This function is only used for parent/child buffers */
	ଯଦି (child->parent != buf)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	/* Nonsensical if the parent has advanced past the child */
	ଯଦି (sshbuf_len(child) > sshbuf_len(buf))
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	/* More paranoia, shouldn't happen */
	ଯଦି (child->cd < buf->cd)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	/* Advance */
	ଫେରନ୍ତୁ sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(child));
}
