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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <signal.h>
#समावेश <stdlib.h>
#समावेश <stdio.h>
#समावेश <string.h>

#समावेश "ssherr.h"
#घोषणा SSHBUF_INTERNAL
#समावेश "sshbuf.h"
#समावेश "misc.h"

#अगर_घोषित SSHBUF_DEBUG
# define SSHBUF_TELL(what) करो { \
		म_लिखो("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __खाता__, __LINE__, __func__, what, \
		    buf->आकार, buf->alloc, buf->off, buf->max_आकार); \
		ख_साफ(मानक_निकास); \
	} जबतक (0)
#अन्यथा
# define SSHBUF_TELL(what)
#पूर्ण_अगर

काष्ठा sshbuf {
	u_char *d;		/* Data */
	स्थिर u_char *cd;	/* Const data */
	माप_प्रकार off;		/* First available byte is buf->d + buf->off */
	माप_प्रकार आकार;		/* Last byte is buf->d + buf->size - 1 */
	माप_प्रकार max_आकार;	/* Maximum size of buffer */
	माप_प्रकार alloc;		/* Total bytes allocated to buf->d */
	पूर्णांक readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	काष्ठा sshbuf *parent;	/* If child, pointer to parent */
};

अटल अंतरभूत पूर्णांक
sshbuf_check_sanity(स्थिर काष्ठा sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	अगर (__predict_false(buf == शून्य ||
	    (!buf->readonly && buf->d != buf->cd) ||
	    buf->parent == buf ||
	    buf->refcount < 1 || buf->refcount > SSHBUF_REFS_MAX ||
	    buf->cd == शून्य ||
	    buf->max_आकार > SSHBUF_आकार_MAX ||
	    buf->alloc > buf->max_आकार ||
	    buf->आकार > buf->alloc ||
	    buf->off > buf->आकार)) {
		/* Do not try to recover from corrupted buffer internals */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		ssh_signal(संक_अंश, संक_पूर्व);
		उठाओ(संक_अंश);
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	वापस 0;
}

अटल व्योम
sshbuf_maybe_pack(काष्ठा sshbuf *buf, पूर्णांक force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	अगर (buf->off == 0 || buf->readonly || buf->refcount > 1)
		वापस;
	अगर (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->आकार / 2)) {
		स_हटाओ(buf->d, buf->d + buf->off, buf->आकार - buf->off);
		buf->आकार -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

काष्ठा sshbuf *
sshbuf_new(व्योम)
{
	काष्ठा sshbuf *ret;

	अगर ((ret = सुस्मृति(1, माप(*ret))) == शून्य)
		वापस शून्य;
	ret->alloc = SSHBUF_आकार_INIT;
	ret->max_आकार = SSHBUF_आकार_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->parent = शून्य;
	अगर ((ret->cd = ret->d = सुस्मृति(1, ret->alloc)) == शून्य) {
		मुक्त(ret);
		वापस शून्य;
	}
	वापस ret;
}

काष्ठा sshbuf *
sshbuf_from(स्थिर व्योम *blob, माप_प्रकार len)
{
	काष्ठा sshbuf *ret;

	अगर (blob == शून्य || len > SSHBUF_आकार_MAX ||
	    (ret = सुस्मृति(1, माप(*ret))) == शून्य)
		वापस शून्य;
	ret->alloc = ret->आकार = ret->max_आकार = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->parent = शून्य;
	ret->cd = blob;
	ret->d = शून्य;
	वापस ret;
}

पूर्णांक
sshbuf_set_parent(काष्ठा sshbuf *child, काष्ठा sshbuf *parent)
{
	पूर्णांक r;

	अगर ((r = sshbuf_check_sanity(child)) != 0 ||
	    (r = sshbuf_check_sanity(parent)) != 0)
		वापस r;
	अगर ((child->parent != शून्य && child->parent != parent) ||
	    child == parent)
		वापस SSH_ERR_INTERNAL_ERROR;
	child->parent = parent;
	child->parent->refcount++;
	वापस 0;
}

काष्ठा sshbuf *
sshbuf_fromb(काष्ठा sshbuf *buf)
{
	काष्ठा sshbuf *ret;

	अगर (sshbuf_check_sanity(buf) != 0)
		वापस शून्य;
	अगर ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == शून्य)
		वापस शून्य;
	अगर (sshbuf_set_parent(ret, buf) != 0) {
		sshbuf_free(ret);
		वापस शून्य;
	}
	वापस ret;
}

व्योम
sshbuf_free(काष्ठा sshbuf *buf)
{
	अगर (buf == शून्य)
		वापस;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	अगर (sshbuf_check_sanity(buf) != 0)
		वापस;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	अगर (buf->refcount > 0)
		वापस;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->parent);
	buf->parent = शून्य;

	अगर (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, माप(*buf));
}

व्योम
sshbuf_reset(काष्ठा sshbuf *buf)
{
	u_char *d;

	अगर (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->आकार;
		वापस;
	}
	अगर (sshbuf_check_sanity(buf) != 0)
		वापस;
	buf->off = buf->आकार = 0;
	अगर (buf->alloc != SSHBUF_आकार_INIT) {
		अगर ((d = recallocarray(buf->d, buf->alloc, SSHBUF_आकार_INIT,
		    1)) != शून्य) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_आकार_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

माप_प्रकार
sshbuf_max_आकार(स्थिर काष्ठा sshbuf *buf)
{
	वापस buf->max_आकार;
}

माप_प्रकार
sshbuf_alloc(स्थिर काष्ठा sshbuf *buf)
{
	वापस buf->alloc;
}

स्थिर काष्ठा sshbuf *
sshbuf_parent(स्थिर काष्ठा sshbuf *buf)
{
	वापस buf->parent;
}

u_int
sshbuf_refcount(स्थिर काष्ठा sshbuf *buf)
{
	वापस buf->refcount;
}

पूर्णांक
sshbuf_set_max_आकार(काष्ठा sshbuf *buf, माप_प्रकार max_आकार)
{
	माप_प्रकार rlen;
	u_char *dp;
	पूर्णांक r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_आकार));
	अगर ((r = sshbuf_check_sanity(buf)) != 0)
		वापस r;
	अगर (max_आकार == buf->max_आकार)
		वापस 0;
	अगर (buf->readonly || buf->refcount > 1)
		वापस SSH_ERR_बफर_READ_ONLY;
	अगर (max_आकार > SSHBUF_आकार_MAX)
		वापस SSH_ERR_NO_बफर_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_आकार < buf->आकार);
	अगर (max_आकार < buf->alloc && max_आकार > buf->आकार) {
		अगर (buf->आकार < SSHBUF_आकार_INIT)
			rlen = SSHBUF_आकार_INIT;
		अन्यथा
			rlen = ROUNDUP(buf->आकार, SSHBUF_आकार_INC);
		अगर (rlen > max_आकार)
			rlen = max_आकार;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		अगर ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == शून्य)
			वापस SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	अगर (max_आकार < buf->alloc)
		वापस SSH_ERR_NO_बफर_SPACE;
	buf->max_आकार = max_आकार;
	वापस 0;
}

माप_प्रकार
sshbuf_len(स्थिर काष्ठा sshbuf *buf)
{
	अगर (sshbuf_check_sanity(buf) != 0)
		वापस 0;
	वापस buf->आकार - buf->off;
}

माप_प्रकार
sshbuf_avail(स्थिर काष्ठा sshbuf *buf)
{
	अगर (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		वापस 0;
	वापस buf->max_आकार - (buf->आकार - buf->off);
}

स्थिर u_char *
sshbuf_ptr(स्थिर काष्ठा sshbuf *buf)
{
	अगर (sshbuf_check_sanity(buf) != 0)
		वापस शून्य;
	वापस buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(स्थिर काष्ठा sshbuf *buf)
{
	अगर (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		वापस शून्य;
	वापस buf->d + buf->off;
}

पूर्णांक
sshbuf_check_reserve(स्थिर काष्ठा sshbuf *buf, माप_प्रकार len)
{
	पूर्णांक r;

	अगर ((r = sshbuf_check_sanity(buf)) != 0)
		वापस r;
	अगर (buf->readonly || buf->refcount > 1)
		वापस SSH_ERR_बफर_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	अगर (len > buf->max_आकार || buf->max_आकार - len < buf->आकार - buf->off)
		वापस SSH_ERR_NO_बफर_SPACE;
	वापस 0;
}

पूर्णांक
sshbuf_allocate(काष्ठा sshbuf *buf, माप_प्रकार len)
{
	माप_प्रकार rlen, need;
	u_char *dp;
	पूर्णांक r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	अगर ((r = sshbuf_check_reserve(buf, len)) != 0)
		वापस r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->आकार + len > buf->max_आकार);
	SSHBUF_TELL("allocate");
	अगर (len + buf->आकार <= buf->alloc)
		वापस 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->आकार - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_आकार_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	अगर (rlen > buf->max_आकार)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	अगर ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == शून्य) {
		SSHBUF_DBG(("realloc fail"));
		वापस SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	अगर ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		वापस r;
	}
	SSHBUF_TELL("done");
	वापस 0;
}

पूर्णांक
sshbuf_reserve(काष्ठा sshbuf *buf, माप_प्रकार len, u_char **dpp)
{
	u_char *dp;
	पूर्णांक r;

	अगर (dpp != शून्य)
		*dpp = शून्य;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	अगर ((r = sshbuf_allocate(buf, len)) != 0)
		वापस r;

	dp = buf->d + buf->आकार;
	buf->आकार += len;
	अगर (dpp != शून्य)
		*dpp = dp;
	वापस 0;
}

पूर्णांक
sshbuf_consume(काष्ठा sshbuf *buf, माप_प्रकार len)
{
	पूर्णांक r;

	SSHBUF_DBG(("len = %zu", len));
	अगर ((r = sshbuf_check_sanity(buf)) != 0)
		वापस r;
	अगर (len == 0)
		वापस 0;
	अगर (len > sshbuf_len(buf))
		वापस SSH_ERR_MESSAGE_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	अगर (buf->off == buf->आकार)
		buf->off = buf->आकार = 0;
	SSHBUF_TELL("done");
	वापस 0;
}

पूर्णांक
sshbuf_consume_end(काष्ठा sshbuf *buf, माप_प्रकार len)
{
	पूर्णांक r;

	SSHBUF_DBG(("len = %zu", len));
	अगर ((r = sshbuf_check_sanity(buf)) != 0)
		वापस r;
	अगर (len == 0)
		वापस 0;
	अगर (len > sshbuf_len(buf))
		वापस SSH_ERR_MESSAGE_INCOMPLETE;
	buf->आकार -= len;
	SSHBUF_TELL("done");
	वापस 0;
}

पूर्णांक
sshbuf_consume_upto_child(काष्ठा sshbuf *buf, स्थिर काष्ठा sshbuf *child)
{
	पूर्णांक r;

	अगर ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(child)) != 0)
		वापस r;
	/* This function is only used for parent/child buffers */
	अगर (child->parent != buf)
		वापस SSH_ERR_INVALID_ARGUMENT;
	/* Nonsensical if the parent has advanced past the child */
	अगर (sshbuf_len(child) > sshbuf_len(buf))
		वापस SSH_ERR_INVALID_ARGUMENT;
	/* More paranoia, shouldn't happen */
	अगर (child->cd < buf->cd)
		वापस SSH_ERR_INTERNAL_ERROR;
	/* Advance */
	वापस sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(child));
}
