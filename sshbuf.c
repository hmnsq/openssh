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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "ssherr.h"
#define SSHBUF_INTERNAL
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "misc.h"

#ifdef SSHBUF_DEBUG
# define SSHBUF_TELL(what) ചെയ്യുക { \
		printf("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __FILE__, __LINE__, __func__, what, \
		    buf->size, buf->alloc, buf->off, buf->max_size); \
		fflush(stdout); \
	} ആകുമ്പോൾ (0)
#അല്ലെങ്കിൽ
# define SSHBUF_TELL(what)
#endif

ഘടന sshbuf {
	u_char *d;		/* Data */
	സ്ഥിരം u_char *cd;	/* Const data */
	size_t off;		/* First available byte is buf->d + buf->off */
	size_t size;		/* Last byte is buf->d + buf->size - 1 */
	size_t max_size;	/* Maximum size of buffer */
	size_t alloc;		/* Total bytes allocated to buf->d */
	പൂർണ്ണസംഖ്യ readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	ഘടന sshbuf *parent;	/* If child, pointer to parent */
};

സ്ഥിതം വരിയിൽ പൂർണ്ണസംഖ്യ
sshbuf_check_sanity(സ്ഥിരം ഘടന sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	എങ്കിൽ (__predict_false(buf == ശൂന്യ ||
	    (!buf->readonly && buf->d != buf->cd) ||
	    buf->parent == buf ||
	    buf->refcount < 1 || buf->refcount > SSHBUF_REFS_MAX ||
	    buf->cd == ശൂന്യ ||
	    buf->max_size > SSHBUF_SIZE_MAX ||
	    buf->alloc > buf->max_size ||
	    buf->size > buf->alloc ||
	    buf->off > buf->size)) {
		/* Do not try to recover from corrupted buffer internals */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		ssh_signal(SIGSEGV, SIG_DFL);
		ഉയർത്തുക(SIGSEGV);
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	}
	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
sshbuf_maybe_pack(ഘടന sshbuf *buf, പൂർണ്ണസംഖ്യ force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	എങ്കിൽ (buf->off == 0 || buf->readonly || buf->refcount > 1)
		തിരികെ;
	എങ്കിൽ (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->size / 2)) {
		memmove(buf->d, buf->d + buf->off, buf->size - buf->off);
		buf->size -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

ഘടന sshbuf *
sshbuf_new(ശൂന്യം)
{
	ഘടന sshbuf *ret;

	എങ്കിൽ ((ret = calloc(1, വലുപ്പം(*ret))) == ശൂന്യ)
		തിരികെ ശൂന്യ;
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_size = SSHBUF_SIZE_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->parent = ശൂന്യ;
	എങ്കിൽ ((ret->cd = ret->d = calloc(1, ret->alloc)) == ശൂന്യ) {
		സ്വതന്ത്രം(ret);
		തിരികെ ശൂന്യ;
	}
	തിരികെ ret;
}

ഘടന sshbuf *
sshbuf_from(സ്ഥിരം ശൂന്യം *blob, size_t len)
{
	ഘടന sshbuf *ret;

	എങ്കിൽ (blob == ശൂന്യ || len > SSHBUF_SIZE_MAX ||
	    (ret = calloc(1, വലുപ്പം(*ret))) == ശൂന്യ)
		തിരികെ ശൂന്യ;
	ret->alloc = ret->size = ret->max_size = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->parent = ശൂന്യ;
	ret->cd = blob;
	ret->d = ശൂന്യ;
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
sshbuf_set_parent(ഘടന sshbuf *child, ഘടന sshbuf *parent)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_check_sanity(child)) != 0 ||
	    (r = sshbuf_check_sanity(parent)) != 0)
		തിരികെ r;
	എങ്കിൽ ((child->parent != ശൂന്യ && child->parent != parent) ||
	    child == parent)
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	child->parent = parent;
	child->parent->refcount++;
	തിരികെ 0;
}

ഘടന sshbuf *
sshbuf_fromb(ഘടന sshbuf *buf)
{
	ഘടന sshbuf *ret;

	എങ്കിൽ (sshbuf_check_sanity(buf) != 0)
		തിരികെ ശൂന്യ;
	എങ്കിൽ ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == ശൂന്യ)
		തിരികെ ശൂന്യ;
	എങ്കിൽ (sshbuf_set_parent(ret, buf) != 0) {
		sshbuf_free(ret);
		തിരികെ ശൂന്യ;
	}
	തിരികെ ret;
}

ശൂന്യം
sshbuf_free(ഘടന sshbuf *buf)
{
	എങ്കിൽ (buf == ശൂന്യ)
		തിരികെ;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	എങ്കിൽ (sshbuf_check_sanity(buf) != 0)
		തിരികെ;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	എങ്കിൽ (buf->refcount > 0)
		തിരികെ;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->parent);
	buf->parent = ശൂന്യ;

	എങ്കിൽ (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, വലുപ്പം(*buf));
}

ശൂന്യം
sshbuf_reset(ഘടന sshbuf *buf)
{
	u_char *d;

	എങ്കിൽ (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->size;
		തിരികെ;
	}
	എങ്കിൽ (sshbuf_check_sanity(buf) != 0)
		തിരികെ;
	buf->off = buf->size = 0;
	എങ്കിൽ (buf->alloc != SSHBUF_SIZE_INIT) {
		എങ്കിൽ ((d = recallocarray(buf->d, buf->alloc, SSHBUF_SIZE_INIT,
		    1)) != ശൂന്യ) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_SIZE_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

size_t
sshbuf_max_size(സ്ഥിരം ഘടന sshbuf *buf)
{
	തിരികെ buf->max_size;
}

size_t
sshbuf_alloc(സ്ഥിരം ഘടന sshbuf *buf)
{
	തിരികെ buf->alloc;
}

സ്ഥിരം ഘടന sshbuf *
sshbuf_parent(സ്ഥിരം ഘടന sshbuf *buf)
{
	തിരികെ buf->parent;
}

u_int
sshbuf_refcount(സ്ഥിരം ഘടന sshbuf *buf)
{
	തിരികെ buf->refcount;
}

പൂർണ്ണസംഖ്യ
sshbuf_set_max_size(ഘടന sshbuf *buf, size_t max_size)
{
	size_t rlen;
	u_char *dp;
	പൂർണ്ണസംഖ്യ r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_size));
	എങ്കിൽ ((r = sshbuf_check_sanity(buf)) != 0)
		തിരികെ r;
	എങ്കിൽ (max_size == buf->max_size)
		തിരികെ 0;
	എങ്കിൽ (buf->readonly || buf->refcount > 1)
		തിരികെ SSH_ERR_BUFFER_READ_ONLY;
	എങ്കിൽ (max_size > SSHBUF_SIZE_MAX)
		തിരികെ SSH_ERR_NO_BUFFER_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_size < buf->size);
	എങ്കിൽ (max_size < buf->alloc && max_size > buf->size) {
		എങ്കിൽ (buf->size < SSHBUF_SIZE_INIT)
			rlen = SSHBUF_SIZE_INIT;
		അല്ലെങ്കിൽ
			rlen = ROUNDUP(buf->size, SSHBUF_SIZE_INC);
		എങ്കിൽ (rlen > max_size)
			rlen = max_size;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		എങ്കിൽ ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == ശൂന്യ)
			തിരികെ SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	എങ്കിൽ (max_size < buf->alloc)
		തിരികെ SSH_ERR_NO_BUFFER_SPACE;
	buf->max_size = max_size;
	തിരികെ 0;
}

size_t
sshbuf_len(സ്ഥിരം ഘടന sshbuf *buf)
{
	എങ്കിൽ (sshbuf_check_sanity(buf) != 0)
		തിരികെ 0;
	തിരികെ buf->size - buf->off;
}

size_t
sshbuf_avail(സ്ഥിരം ഘടന sshbuf *buf)
{
	എങ്കിൽ (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		തിരികെ 0;
	തിരികെ buf->max_size - (buf->size - buf->off);
}

സ്ഥിരം u_char *
sshbuf_ptr(സ്ഥിരം ഘടന sshbuf *buf)
{
	എങ്കിൽ (sshbuf_check_sanity(buf) != 0)
		തിരികെ ശൂന്യ;
	തിരികെ buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(സ്ഥിരം ഘടന sshbuf *buf)
{
	എങ്കിൽ (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		തിരികെ ശൂന്യ;
	തിരികെ buf->d + buf->off;
}

പൂർണ്ണസംഖ്യ
sshbuf_check_reserve(സ്ഥിരം ഘടന sshbuf *buf, size_t len)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_check_sanity(buf)) != 0)
		തിരികെ r;
	എങ്കിൽ (buf->readonly || buf->refcount > 1)
		തിരികെ SSH_ERR_BUFFER_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	എങ്കിൽ (len > buf->max_size || buf->max_size - len < buf->size - buf->off)
		തിരികെ SSH_ERR_NO_BUFFER_SPACE;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_allocate(ഘടന sshbuf *buf, size_t len)
{
	size_t rlen, need;
	u_char *dp;
	പൂർണ്ണസംഖ്യ r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	എങ്കിൽ ((r = sshbuf_check_reserve(buf, len)) != 0)
		തിരികെ r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->size + len > buf->max_size);
	SSHBUF_TELL("allocate");
	എങ്കിൽ (len + buf->size <= buf->alloc)
		തിരികെ 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->size - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_SIZE_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	എങ്കിൽ (rlen > buf->max_size)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	എങ്കിൽ ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == ശൂന്യ) {
		SSHBUF_DBG(("realloc fail"));
		തിരികെ SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	എങ്കിൽ ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		തിരികെ r;
	}
	SSHBUF_TELL("done");
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_reserve(ഘടന sshbuf *buf, size_t len, u_char **dpp)
{
	u_char *dp;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (dpp != ശൂന്യ)
		*dpp = ശൂന്യ;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	എങ്കിൽ ((r = sshbuf_allocate(buf, len)) != 0)
		തിരികെ r;

	dp = buf->d + buf->size;
	buf->size += len;
	എങ്കിൽ (dpp != ശൂന്യ)
		*dpp = dp;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_consume(ഘടന sshbuf *buf, size_t len)
{
	പൂർണ്ണസംഖ്യ r;

	SSHBUF_DBG(("len = %zu", len));
	എങ്കിൽ ((r = sshbuf_check_sanity(buf)) != 0)
		തിരികെ r;
	എങ്കിൽ (len == 0)
		തിരികെ 0;
	എങ്കിൽ (len > sshbuf_len(buf))
		തിരികെ SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	എങ്കിൽ (buf->off == buf->size)
		buf->off = buf->size = 0;
	SSHBUF_TELL("done");
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_consume_end(ഘടന sshbuf *buf, size_t len)
{
	പൂർണ്ണസംഖ്യ r;

	SSHBUF_DBG(("len = %zu", len));
	എങ്കിൽ ((r = sshbuf_check_sanity(buf)) != 0)
		തിരികെ r;
	എങ്കിൽ (len == 0)
		തിരികെ 0;
	എങ്കിൽ (len > sshbuf_len(buf))
		തിരികെ SSH_ERR_MESSAGE_INCOMPLETE;
	buf->size -= len;
	SSHBUF_TELL("done");
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshbuf_consume_upto_child(ഘടന sshbuf *buf, സ്ഥിരം ഘടന sshbuf *child)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(child)) != 0)
		തിരികെ r;
	/* This function is only used for parent/child buffers */
	എങ്കിൽ (child->parent != buf)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	/* Nonsensical if the parent has advanced past the child */
	എങ്കിൽ (sshbuf_len(child) > sshbuf_len(buf))
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	/* More paranoia, shouldn't happen */
	എങ്കിൽ (child->cd < buf->cd)
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	/* Advance */
	തിരികെ sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(child));
}
