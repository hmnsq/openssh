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
# define SSHBUF_TELL(what) करा { \
		म_लिखो("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __FILE__, __LINE__, __func__, what, \
		    buf->size, buf->alloc, buf->off, buf->max_size); \
		ख_साफ(मानक_निकास); \
	} पर्यंत (0)
#अन्यथा
# define SSHBUF_TELL(what)
#endif

संरचना sshbuf {
	u_char *d;		/* Data */
	स्थिरांक u_char *cd;	/* Const data */
	माप_प्रकार off;		/* First available byte is buf->d + buf->off */
	माप_प्रकार size;		/* Last byte is buf->d + buf->size - 1 */
	माप_प्रकार max_size;	/* Maximum size of buffer */
	माप_प्रकार alloc;		/* Total bytes allocated to buf->d */
	पूर्णांक readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	संरचना sshbuf *parent;	/* If child, pointer to parent */
};

स्थिर ओळीत पूर्णांक
sshbuf_check_sanity(स्थिरांक संरचना sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	जर (__predict_false(buf == रिक्त ||
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
		उठवा(संक_अंश);
		परत SSH_ERR_INTERNAL_ERROR;
	}
	परत 0;
}

स्थिर शून्य
sshbuf_maybe_pack(संरचना sshbuf *buf, पूर्णांक force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	जर (buf->off == 0 || buf->readonly || buf->refcount > 1)
		परत;
	जर (force ||
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

	जर ((ret = सुस्मृति(1, आकार(*ret))) == रिक्त)
		परत रिक्त;
	ret->alloc = SSHBUF_SIZE_INIT;
	ret->max_size = SSHBUF_SIZE_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->parent = रिक्त;
	जर ((ret->cd = ret->d = सुस्मृति(1, ret->alloc)) == रिक्त) {
		मुक्त(ret);
		परत रिक्त;
	}
	परत ret;
}

संरचना sshbuf *
sshbuf_from(स्थिरांक शून्य *blob, माप_प्रकार len)
{
	संरचना sshbuf *ret;

	जर (blob == रिक्त || len > SSHBUF_SIZE_MAX ||
	    (ret = सुस्मृति(1, आकार(*ret))) == रिक्त)
		परत रिक्त;
	ret->alloc = ret->size = ret->max_size = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->parent = रिक्त;
	ret->cd = blob;
	ret->d = रिक्त;
	परत ret;
}

पूर्णांक
sshbuf_set_parent(संरचना sshbuf *child, संरचना sshbuf *parent)
{
	पूर्णांक r;

	जर ((r = sshbuf_check_sanity(child)) != 0 ||
	    (r = sshbuf_check_sanity(parent)) != 0)
		परत r;
	जर ((child->parent != रिक्त && child->parent != parent) ||
	    child == parent)
		परत SSH_ERR_INTERNAL_ERROR;
	child->parent = parent;
	child->parent->refcount++;
	परत 0;
}

संरचना sshbuf *
sshbuf_fromb(संरचना sshbuf *buf)
{
	संरचना sshbuf *ret;

	जर (sshbuf_check_sanity(buf) != 0)
		परत रिक्त;
	जर ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == रिक्त)
		परत रिक्त;
	जर (sshbuf_set_parent(ret, buf) != 0) {
		sshbuf_free(ret);
		परत रिक्त;
	}
	परत ret;
}

शून्य
sshbuf_free(संरचना sshbuf *buf)
{
	जर (buf == रिक्त)
		परत;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	जर (sshbuf_check_sanity(buf) != 0)
		परत;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	जर (buf->refcount > 0)
		परत;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->parent);
	buf->parent = रिक्त;

	जर (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, आकार(*buf));
}

शून्य
sshbuf_reset(संरचना sshbuf *buf)
{
	u_char *d;

	जर (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->size;
		परत;
	}
	जर (sshbuf_check_sanity(buf) != 0)
		परत;
	buf->off = buf->size = 0;
	जर (buf->alloc != SSHBUF_SIZE_INIT) {
		जर ((d = recallocarray(buf->d, buf->alloc, SSHBUF_SIZE_INIT,
		    1)) != रिक्त) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_SIZE_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

माप_प्रकार
sshbuf_max_size(स्थिरांक संरचना sshbuf *buf)
{
	परत buf->max_size;
}

माप_प्रकार
sshbuf_alloc(स्थिरांक संरचना sshbuf *buf)
{
	परत buf->alloc;
}

स्थिरांक संरचना sshbuf *
sshbuf_parent(स्थिरांक संरचना sshbuf *buf)
{
	परत buf->parent;
}

u_int
sshbuf_refcount(स्थिरांक संरचना sshbuf *buf)
{
	परत buf->refcount;
}

पूर्णांक
sshbuf_set_max_size(संरचना sshbuf *buf, माप_प्रकार max_size)
{
	माप_प्रकार rlen;
	u_char *dp;
	पूर्णांक r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_size));
	जर ((r = sshbuf_check_sanity(buf)) != 0)
		परत r;
	जर (max_size == buf->max_size)
		परत 0;
	जर (buf->readonly || buf->refcount > 1)
		परत SSH_ERR_BUFFER_READ_ONLY;
	जर (max_size > SSHBUF_SIZE_MAX)
		परत SSH_ERR_NO_BUFFER_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_size < buf->size);
	जर (max_size < buf->alloc && max_size > buf->size) {
		जर (buf->size < SSHBUF_SIZE_INIT)
			rlen = SSHBUF_SIZE_INIT;
		अन्यथा
			rlen = ROUNDUP(buf->size, SSHBUF_SIZE_INC);
		जर (rlen > max_size)
			rlen = max_size;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		जर ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == रिक्त)
			परत SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	जर (max_size < buf->alloc)
		परत SSH_ERR_NO_BUFFER_SPACE;
	buf->max_size = max_size;
	परत 0;
}

माप_प्रकार
sshbuf_len(स्थिरांक संरचना sshbuf *buf)
{
	जर (sshbuf_check_sanity(buf) != 0)
		परत 0;
	परत buf->size - buf->off;
}

माप_प्रकार
sshbuf_avail(स्थिरांक संरचना sshbuf *buf)
{
	जर (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		परत 0;
	परत buf->max_size - (buf->size - buf->off);
}

स्थिरांक u_char *
sshbuf_ptr(स्थिरांक संरचना sshbuf *buf)
{
	जर (sshbuf_check_sanity(buf) != 0)
		परत रिक्त;
	परत buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(स्थिरांक संरचना sshbuf *buf)
{
	जर (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		परत रिक्त;
	परत buf->d + buf->off;
}

पूर्णांक
sshbuf_check_reserve(स्थिरांक संरचना sshbuf *buf, माप_प्रकार len)
{
	पूर्णांक r;

	जर ((r = sshbuf_check_sanity(buf)) != 0)
		परत r;
	जर (buf->readonly || buf->refcount > 1)
		परत SSH_ERR_BUFFER_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	जर (len > buf->max_size || buf->max_size - len < buf->size - buf->off)
		परत SSH_ERR_NO_BUFFER_SPACE;
	परत 0;
}

पूर्णांक
sshbuf_allocate(संरचना sshbuf *buf, माप_प्रकार len)
{
	माप_प्रकार rlen, need;
	u_char *dp;
	पूर्णांक r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	जर ((r = sshbuf_check_reserve(buf, len)) != 0)
		परत r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->size + len > buf->max_size);
	SSHBUF_TELL("allocate");
	जर (len + buf->size <= buf->alloc)
		परत 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->size - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_SIZE_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	जर (rlen > buf->max_size)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	जर ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == रिक्त) {
		SSHBUF_DBG(("realloc fail"));
		परत SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	जर ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		परत r;
	}
	SSHBUF_TELL("done");
	परत 0;
}

पूर्णांक
sshbuf_reserve(संरचना sshbuf *buf, माप_प्रकार len, u_char **dpp)
{
	u_char *dp;
	पूर्णांक r;

	जर (dpp != रिक्त)
		*dpp = रिक्त;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	जर ((r = sshbuf_allocate(buf, len)) != 0)
		परत r;

	dp = buf->d + buf->size;
	buf->size += len;
	जर (dpp != रिक्त)
		*dpp = dp;
	परत 0;
}

पूर्णांक
sshbuf_consume(संरचना sshbuf *buf, माप_प्रकार len)
{
	पूर्णांक r;

	SSHBUF_DBG(("len = %zu", len));
	जर ((r = sshbuf_check_sanity(buf)) != 0)
		परत r;
	जर (len == 0)
		परत 0;
	जर (len > sshbuf_len(buf))
		परत SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	जर (buf->off == buf->size)
		buf->off = buf->size = 0;
	SSHBUF_TELL("done");
	परत 0;
}

पूर्णांक
sshbuf_consume_end(संरचना sshbuf *buf, माप_प्रकार len)
{
	पूर्णांक r;

	SSHBUF_DBG(("len = %zu", len));
	जर ((r = sshbuf_check_sanity(buf)) != 0)
		परत r;
	जर (len == 0)
		परत 0;
	जर (len > sshbuf_len(buf))
		परत SSH_ERR_MESSAGE_INCOMPLETE;
	buf->size -= len;
	SSHBUF_TELL("done");
	परत 0;
}

पूर्णांक
sshbuf_consume_upto_child(संरचना sshbuf *buf, स्थिरांक संरचना sshbuf *child)
{
	पूर्णांक r;

	जर ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(child)) != 0)
		परत r;
	/* This function is only used for parent/child buffers */
	जर (child->parent != buf)
		परत SSH_ERR_INVALID_ARGUMENT;
	/* Nonsensical if the parent has advanced past the child */
	जर (sshbuf_len(child) > sshbuf_len(buf))
		परत SSH_ERR_INVALID_ARGUMENT;
	/* More paranoia, shouldn't happen */
	जर (child->cd < buf->cd)
		परत SSH_ERR_INTERNAL_ERROR;
	/* Advance */
	परत sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(child));
}
