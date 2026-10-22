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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "ssherr.h"
#define SSHBUF_INTERNAL
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "misc.h"

#ifdef SSHBUF_DEBUG
# define SSHBUF_TELL(what) गर { \
		म_लिखो("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __FILE__, __LINE__, __func__, what, \
		    buf->size, buf->alloc, buf->off, buf->max_size); \
		ख_साफ(मानक_निकास); \
	} जबसम्म (0)
#अन्यथा
# define SSHBUF_TELL(what)
#endif

संरचना sshbuf {
	u_char *d;		/* Data */
	अचर u_char *cd;	/* Const data */
	माप_प्रकार off;		/* First available byte is buf->d + buf->off */
	माप_प्रकार size;		/* Last byte is buf->d + buf->size - 1 */
	माप_प्रकार max_size;	/* Maximum size of buffer */
	माप_प्रकार alloc;		/* Total bytes allocated to buf->d */
	पूर्णाङ्क readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	संरचना sshbuf *parent;	/* If child, pointer to parent */
};

स्थिर अन्तःस्थ पूर्णाङ्क
sshbuf_check_sanity(अचर संरचना sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	यदि (__predict_false(buf == रिक्त ||
	    (!buf->readonly && buf->d != buf->cd) ||
	    buf->parent == buf ||
	    buf->refcount < 1 || buf->refcount > SSHBUF_REFS_MAX ||
	    buf->cd == रिक्त ||
	    buf->max_size > SSHBUF_SIZE_MAX ||
	    buf->alloc > buf->max_size ||
	    buf->size > buf->alloc ||
	    buf->off > buf->size)) {
		/* Do not try to recover from corrupted buffer internals */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		ssh_signal(संक_अंश, संक_पूर्व);
		उत्थापय(संक_अंश);
		फर्काऊ SSH_ERR_INTERNAL_ERROR;
	}
	फर्काऊ 0;
}

स्थिर शून्य
sshbuf_maybe_pack(संरचना sshbuf *buf, पूर्णाङ्क force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	यदि (buf->off == 0 || buf->readonly || buf->refcount > 1)
		फर्काऊ;
	यदि (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->size / 2)) {
		स_हटाओ(buf->d, buf->d + buf->off, buf->size - buf->off);
		buf->size -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

संरचना sshbuf *
sshbuf_new(शून्य)
{
	संरचना sshbuf *ret;

	यदि ((ret = सुस्मृति(1, परिमाण(*ret))) == रिक्त)
		फर्काऊ रिक्त;
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_size = SSHBUF_SIZE_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->parent = रिक्त;
	यदि ((ret->cd = ret->d = सुस्मृति(1, ret->alloc)) == रिक्त) {
		मुक्त(ret);
		फर्काऊ रिक्त;
	}
	फर्काऊ ret;
}

संरचना sshbuf *
sshbuf_from(अचर शून्य *blob, माप_प्रकार len)
{
	संरचना sshbuf *ret;

	यदि (blob == रिक्त || len > SSHBUF_SIZE_MAX ||
	    (ret = सुस्मृति(1, परिमाण(*ret))) == रिक्त)
		फर्काऊ रिक्त;
	ret->alloc = ret->size = ret->max_size = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->parent = रिक्त;
	ret->cd = blob;
	ret->d = रिक्त;
	फर्काऊ ret;
}

पूर्णाङ्क
sshbuf_set_parent(संरचना sshbuf *child, संरचना sshbuf *parent)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_check_sanity(child)) != 0 ||
	    (r = sshbuf_check_sanity(parent)) != 0)
		फर्काऊ r;
	यदि ((child->parent != रिक्त && child->parent != parent) ||
	    child == parent)
		फर्काऊ SSH_ERR_INTERNAL_ERROR;
	child->parent = parent;
	child->parent->refcount++;
	फर्काऊ 0;
}

संरचना sshbuf *
sshbuf_fromb(संरचना sshbuf *buf)
{
	संरचना sshbuf *ret;

	यदि (sshbuf_check_sanity(buf) != 0)
		फर्काऊ रिक्त;
	यदि ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == रिक्त)
		फर्काऊ रिक्त;
	यदि (sshbuf_set_parent(ret, buf) != 0) {
		sshbuf_free(ret);
		फर्काऊ रिक्त;
	}
	फर्काऊ ret;
}

शून्य
sshbuf_free(संरचना sshbuf *buf)
{
	यदि (buf == रिक्त)
		फर्काऊ;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	यदि (sshbuf_check_sanity(buf) != 0)
		फर्काऊ;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	यदि (buf->refcount > 0)
		फर्काऊ;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->parent);
	buf->parent = रिक्त;

	यदि (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, परिमाण(*buf));
}

शून्य
sshbuf_reset(संरचना sshbuf *buf)
{
	u_char *d;

	यदि (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->size;
		फर्काऊ;
	}
	यदि (sshbuf_check_sanity(buf) != 0)
		फर्काऊ;
	buf->off = buf->size = 0;
	यदि (buf->alloc != SSHBUF_SIZE_INIT) {
		यदि ((d = recallocarray(buf->d, buf->alloc, SSHBUF_SIZE_INIT,
		    1)) != रिक्त) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_SIZE_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

माप_प्रकार
sshbuf_max_size(अचर संरचना sshbuf *buf)
{
	फर्काऊ buf->max_size;
}

माप_प्रकार
sshbuf_alloc(अचर संरचना sshbuf *buf)
{
	फर्काऊ buf->alloc;
}

अचर संरचना sshbuf *
sshbuf_parent(अचर संरचना sshbuf *buf)
{
	फर्काऊ buf->parent;
}

u_int
sshbuf_refcount(अचर संरचना sshbuf *buf)
{
	फर्काऊ buf->refcount;
}

पूर्णाङ्क
sshbuf_set_max_size(संरचना sshbuf *buf, माप_प्रकार max_size)
{
	माप_प्रकार rlen;
	u_char *dp;
	पूर्णाङ्क r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_size));
	यदि ((r = sshbuf_check_sanity(buf)) != 0)
		फर्काऊ r;
	यदि (max_size == buf->max_size)
		फर्काऊ 0;
	यदि (buf->readonly || buf->refcount > 1)
		फर्काऊ SSH_ERR_BUFFER_READ_ONLY;
	यदि (max_size > SSHBUF_SIZE_MAX)
		फर्काऊ SSH_ERR_NO_BUFFER_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_size < buf->size);
	यदि (max_size < buf->alloc && max_size > buf->size) {
		यदि (buf->size < SSHBUF_SIZE_INIT)
			rlen = SSHBUF_SIZE_INIT;
		अन्यथा
			rlen = ROUNDUP(buf->size, SSHBUF_SIZE_INC);
		यदि (rlen > max_size)
			rlen = max_size;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		यदि ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == रिक्त)
			फर्काऊ SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	यदि (max_size < buf->alloc)
		फर्काऊ SSH_ERR_NO_BUFFER_SPACE;
	buf->max_size = max_size;
	फर्काऊ 0;
}

माप_प्रकार
sshbuf_len(अचर संरचना sshbuf *buf)
{
	यदि (sshbuf_check_sanity(buf) != 0)
		फर्काऊ 0;
	फर्काऊ buf->size - buf->off;
}

माप_प्रकार
sshbuf_avail(अचर संरचना sshbuf *buf)
{
	यदि (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		फर्काऊ 0;
	फर्काऊ buf->max_size - (buf->size - buf->off);
}

अचर u_char *
sshbuf_ptr(अचर संरचना sshbuf *buf)
{
	यदि (sshbuf_check_sanity(buf) != 0)
		फर्काऊ रिक्त;
	फर्काऊ buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(अचर संरचना sshbuf *buf)
{
	यदि (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		फर्काऊ रिक्त;
	फर्काऊ buf->d + buf->off;
}

पूर्णाङ्क
sshbuf_check_reserve(अचर संरचना sshbuf *buf, माप_प्रकार len)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_check_sanity(buf)) != 0)
		फर्काऊ r;
	यदि (buf->readonly || buf->refcount > 1)
		फर्काऊ SSH_ERR_BUFFER_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	यदि (len > buf->max_size || buf->max_size - len < buf->size - buf->off)
		फर्काऊ SSH_ERR_NO_BUFFER_SPACE;
	फर्काऊ 0;
}

पूर्णाङ्क
sshbuf_allocate(संरचना sshbuf *buf, माप_प्रकार len)
{
	माप_प्रकार rlen, need;
	u_char *dp;
	पूर्णाङ्क r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	यदि ((r = sshbuf_check_reserve(buf, len)) != 0)
		फर्काऊ r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->size + len > buf->max_size);
	SSHBUF_TELL("allocate");
	यदि (len + buf->size <= buf->alloc)
		फर्काऊ 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->size - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_SIZE_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	यदि (rlen > buf->max_size)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	यदि ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == रिक्त) {
		SSHBUF_DBG(("realloc fail"));
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	यदि ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		फर्काऊ r;
	}
	SSHBUF_TELL("done");
	फर्काऊ 0;
}

पूर्णाङ्क
sshbuf_reserve(संरचना sshbuf *buf, माप_प्रकार len, u_char **dpp)
{
	u_char *dp;
	पूर्णाङ्क r;

	यदि (dpp != रिक्त)
		*dpp = रिक्त;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	यदि ((r = sshbuf_allocate(buf, len)) != 0)
		फर्काऊ r;

	dp = buf->d + buf->size;
	buf->size += len;
	यदि (dpp != रिक्त)
		*dpp = dp;
	फर्काऊ 0;
}

पूर्णाङ्क
sshbuf_consume(संरचना sshbuf *buf, माप_प्रकार len)
{
	पूर्णाङ्क r;

	SSHBUF_DBG(("len = %zu", len));
	यदि ((r = sshbuf_check_sanity(buf)) != 0)
		फर्काऊ r;
	यदि (len == 0)
		फर्काऊ 0;
	यदि (len > sshbuf_len(buf))
		फर्काऊ SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	यदि (buf->off == buf->size)
		buf->off = buf->size = 0;
	SSHBUF_TELL("done");
	फर्काऊ 0;
}

पूर्णाङ्क
sshbuf_consume_end(संरचना sshbuf *buf, माप_प्रकार len)
{
	पूर्णाङ्क r;

	SSHBUF_DBG(("len = %zu", len));
	यदि ((r = sshbuf_check_sanity(buf)) != 0)
		फर्काऊ r;
	यदि (len == 0)
		फर्काऊ 0;
	यदि (len > sshbuf_len(buf))
		फर्काऊ SSH_ERR_MESSAGE_INCOMPLETE;
	buf->size -= len;
	SSHBUF_TELL("done");
	फर्काऊ 0;
}

पूर्णाङ्क
sshbuf_consume_upto_child(संरचना sshbuf *buf, अचर संरचना sshbuf *child)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(child)) != 0)
		फर्काऊ r;
	/* This function is only used for parent/child buffers */
	यदि (child->parent != buf)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	/* Nonsensical if the parent has advanced past the child */
	यदि (sshbuf_len(child) > sshbuf_len(buf))
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	/* More paranoia, shouldn't happen */
	यदि (child->cd < buf->cd)
		फर्काऊ SSH_ERR_INTERNAL_ERROR;
	/* Advance */
	फर्काऊ sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(child));
}
