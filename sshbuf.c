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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHBUF_ਅੰਦਰੂਨੀ
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ SSHBUF_DEBUG
# define SSHBUF_TELL(what) ਕਰੋ { \
		ਲਿਖੋ("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __FILE__, __LINE__, __func__, what, \
		    buf->ਮਾਪ, buf->alloc, buf->off, buf->max_ਮਾਪ); \
		fflush(stdout); \
	} ਜਦੋਂ (0)
#ਨਹੀਂਤਾਂ
# define SSHBUF_TELL(what)
#ਜੇ_ਅੰਤ

ਬਣਤਰ sshbuf {
	u_char *d;		/* Data */
	ਅਚਲ u_char *cd;	/* Const data */
	ਮਾਪ_t off;		/* First available byte is buf->d + buf->off */
	ਮਾਪ_t ਮਾਪ;		/* Last byte is buf->d + buf->size - 1 */
	ਮਾਪ_t max_ਮਾਪ;	/* Maximum size of buffer */
	ਮਾਪ_t alloc;		/* Total bytes allocated to buf->d */
	ਪੂਰਨ readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	ਬਣਤਰ sshbuf *ਮਾਪਾ;	/* If child, pointer to parent */
};

ਸਥਿਰ ਸਤਰਅੰਦਰ ਪੂਰਨ
sshbuf_check_sanity(ਅਚਲ ਬਣਤਰ sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	ਜੇ (__predict_false(buf == ਨਿਰਾ ||
	    (!buf->readonly && buf->d != buf->cd) ||
	    buf->ਮਾਪਾ == buf ||
	    buf->refcount < 1 || buf->refcount > SSHBUF_REFS_MAX ||
	    buf->cd == ਨਿਰਾ ||
	    buf->max_ਮਾਪ > SSHBUF_ਮਾਪ_MAX ||
	    buf->alloc > buf->max_ਮਾਪ ||
	    buf->ਮਾਪ > buf->alloc ||
	    buf->off > buf->ਮਾਪ)) {
		/* Do not try to recover from corrupted buffer internals */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		ssh_signal(SIGSEGV, SIG_DFL);
		ਉਠਾਓ(SIGSEGV);
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਖਾਲੀ
sshbuf_maybe_pack(ਬਣਤਰ sshbuf *buf, ਪੂਰਨ force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	ਜੇ (buf->off == 0 || buf->readonly || buf->refcount > 1)
		ਵਾਪਸ;
	ਜੇ (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->ਮਾਪ / 2)) {
		memmove(buf->d, buf->d + buf->off, buf->ਮਾਪ - buf->off);
		buf->ਮਾਪ -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

ਬਣਤਰ sshbuf *
sshbuf_new(ਖਾਲੀ)
{
	ਬਣਤਰ sshbuf *ret;

	ਜੇ ((ret = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*ret))) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ret->alloc = SSHBUF_ਮਾਪ_INIT;
	ret->max_ਮਾਪ = SSHBUF_ਮਾਪ_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->ਮਾਪਾ = ਨਿਰਾ;
	ਜੇ ((ret->cd = ret->d = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ret->alloc)) == ਨਿਰਾ) {
		ਮੁਕਤ(ret);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਵਾਪਸ ret;
}

ਬਣਤਰ sshbuf *
sshbuf_from(ਅਚਲ ਖਾਲੀ *blob, ਮਾਪ_t len)
{
	ਬਣਤਰ sshbuf *ret;

	ਜੇ (blob == ਨਿਰਾ || len > SSHBUF_ਮਾਪ_MAX ||
	    (ret = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*ret))) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ret->alloc = ret->ਮਾਪ = ret->max_ਮਾਪ = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->ਮਾਪਾ = ਨਿਰਾ;
	ret->cd = blob;
	ret->d = ਨਿਰਾ;
	ਵਾਪਸ ret;
}

ਪੂਰਨ
sshbuf_ਸੈੱਟ_ਮਾਪਾ(ਬਣਤਰ sshbuf *ਬੱਚਾ, ਬਣਤਰ sshbuf *ਮਾਪਾ)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_check_sanity(ਬੱਚਾ)) != 0 ||
	    (r = sshbuf_check_sanity(ਮਾਪਾ)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((ਬੱਚਾ->ਮਾਪਾ != ਨਿਰਾ && ਬੱਚਾ->ਮਾਪਾ != ਮਾਪਾ) ||
	    ਬੱਚਾ == ਮਾਪਾ)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਬੱਚਾ->ਮਾਪਾ = ਮਾਪਾ;
	ਬੱਚਾ->ਮਾਪਾ->refcount++;
	ਵਾਪਸ 0;
}

ਬਣਤਰ sshbuf *
sshbuf_fromb(ਬਣਤਰ sshbuf *buf)
{
	ਬਣਤਰ sshbuf *ret;

	ਜੇ (sshbuf_check_sanity(buf) != 0)
		ਵਾਪਸ ਨਿਰਾ;
	ਜੇ ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ਜੇ (sshbuf_ਸੈੱਟ_ਮਾਪਾ(ret, buf) != 0) {
		sshbuf_free(ret);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਵਾਪਸ ret;
}

ਖਾਲੀ
sshbuf_free(ਬਣਤਰ sshbuf *buf)
{
	ਜੇ (buf == ਨਿਰਾ)
		ਵਾਪਸ;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	ਜੇ (sshbuf_check_sanity(buf) != 0)
		ਵਾਪਸ;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	ਜੇ (buf->refcount > 0)
		ਵਾਪਸ;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->ਮਾਪਾ);
	buf->ਮਾਪਾ = ਨਿਰਾ;

	ਜੇ (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, ਆਕਾਰ(*buf));
}

ਖਾਲੀ
sshbuf_reset(ਬਣਤਰ sshbuf *buf)
{
	u_char *d;

	ਜੇ (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->ਮਾਪ;
		ਵਾਪਸ;
	}
	ਜੇ (sshbuf_check_sanity(buf) != 0)
		ਵਾਪਸ;
	buf->off = buf->ਮਾਪ = 0;
	ਜੇ (buf->alloc != SSHBUF_ਮਾਪ_INIT) {
		ਜੇ ((d = recallocarray(buf->d, buf->alloc, SSHBUF_ਮਾਪ_INIT,
		    1)) != ਨਿਰਾ) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_ਮਾਪ_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

ਮਾਪ_t
sshbuf_max_ਮਾਪ(ਅਚਲ ਬਣਤਰ sshbuf *buf)
{
	ਵਾਪਸ buf->max_ਮਾਪ;
}

ਮਾਪ_t
sshbuf_alloc(ਅਚਲ ਬਣਤਰ sshbuf *buf)
{
	ਵਾਪਸ buf->alloc;
}

ਅਚਲ ਬਣਤਰ sshbuf *
sshbuf_ਮਾਪਾ(ਅਚਲ ਬਣਤਰ sshbuf *buf)
{
	ਵਾਪਸ buf->ਮਾਪਾ;
}

u_int
sshbuf_refcount(ਅਚਲ ਬਣਤਰ sshbuf *buf)
{
	ਵਾਪਸ buf->refcount;
}

ਪੂਰਨ
sshbuf_ਸੈੱਟ_max_ਮਾਪ(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t max_ਮਾਪ)
{
	ਮਾਪ_t rlen;
	u_char *dp;
	ਪੂਰਨ r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_ਮਾਪ));
	ਜੇ ((r = sshbuf_check_sanity(buf)) != 0)
		ਵਾਪਸ r;
	ਜੇ (max_ਮਾਪ == buf->max_ਮਾਪ)
		ਵਾਪਸ 0;
	ਜੇ (buf->readonly || buf->refcount > 1)
		ਵਾਪਸ SSH_ERR_ਬਫਰ_READ_ONLY;
	ਜੇ (max_ਮਾਪ > SSHBUF_ਮਾਪ_MAX)
		ਵਾਪਸ SSH_ERR_NO_ਬਫਰ_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_ਮਾਪ < buf->ਮਾਪ);
	ਜੇ (max_ਮਾਪ < buf->alloc && max_ਮਾਪ > buf->ਮਾਪ) {
		ਜੇ (buf->ਮਾਪ < SSHBUF_ਮਾਪ_INIT)
			rlen = SSHBUF_ਮਾਪ_INIT;
		ਨਹੀਂਤਾਂ
			rlen = ROUNDUP(buf->ਮਾਪ, SSHBUF_ਮਾਪ_INC);
		ਜੇ (rlen > max_ਮਾਪ)
			rlen = max_ਮਾਪ;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		ਜੇ ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == ਨਿਰਾ)
			ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	ਜੇ (max_ਮਾਪ < buf->alloc)
		ਵਾਪਸ SSH_ERR_NO_ਬਫਰ_SPACE;
	buf->max_ਮਾਪ = max_ਮਾਪ;
	ਵਾਪਸ 0;
}

ਮਾਪ_t
sshbuf_len(ਅਚਲ ਬਣਤਰ sshbuf *buf)
{
	ਜੇ (sshbuf_check_sanity(buf) != 0)
		ਵਾਪਸ 0;
	ਵਾਪਸ buf->ਮਾਪ - buf->off;
}

ਮਾਪ_t
sshbuf_avail(ਅਚਲ ਬਣਤਰ sshbuf *buf)
{
	ਜੇ (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		ਵਾਪਸ 0;
	ਵਾਪਸ buf->max_ਮਾਪ - (buf->ਮਾਪ - buf->off);
}

ਅਚਲ u_char *
sshbuf_ptr(ਅਚਲ ਬਣਤਰ sshbuf *buf)
{
	ਜੇ (sshbuf_check_sanity(buf) != 0)
		ਵਾਪਸ ਨਿਰਾ;
	ਵਾਪਸ buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(ਅਚਲ ਬਣਤਰ sshbuf *buf)
{
	ਜੇ (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		ਵਾਪਸ ਨਿਰਾ;
	ਵਾਪਸ buf->d + buf->off;
}

ਪੂਰਨ
sshbuf_check_reserve(ਅਚਲ ਬਣਤਰ sshbuf *buf, ਮਾਪ_t len)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_check_sanity(buf)) != 0)
		ਵਾਪਸ r;
	ਜੇ (buf->readonly || buf->refcount > 1)
		ਵਾਪਸ SSH_ERR_ਬਫਰ_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	ਜੇ (len > buf->max_ਮਾਪ || buf->max_ਮਾਪ - len < buf->ਮਾਪ - buf->off)
		ਵਾਪਸ SSH_ERR_NO_ਬਫਰ_SPACE;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_allocate(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t len)
{
	ਮਾਪ_t rlen, need;
	u_char *dp;
	ਪੂਰਨ r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	ਜੇ ((r = sshbuf_check_reserve(buf, len)) != 0)
		ਵਾਪਸ r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->ਮਾਪ + len > buf->max_ਮਾਪ);
	SSHBUF_TELL("allocate");
	ਜੇ (len + buf->ਮਾਪ <= buf->alloc)
		ਵਾਪਸ 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->ਮਾਪ - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_ਮਾਪ_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	ਜੇ (rlen > buf->max_ਮਾਪ)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	ਜੇ ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == ਨਿਰਾ) {
		SSHBUF_DBG(("realloc fail"));
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	ਜੇ ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		ਵਾਪਸ r;
	}
	SSHBUF_TELL("done");
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_reserve(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t len, u_char **dpp)
{
	u_char *dp;
	ਪੂਰਨ r;

	ਜੇ (dpp != ਨਿਰਾ)
		*dpp = ਨਿਰਾ;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	ਜੇ ((r = sshbuf_allocate(buf, len)) != 0)
		ਵਾਪਸ r;

	dp = buf->d + buf->ਮਾਪ;
	buf->ਮਾਪ += len;
	ਜੇ (dpp != ਨਿਰਾ)
		*dpp = dp;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_consume(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t len)
{
	ਪੂਰਨ r;

	SSHBUF_DBG(("len = %zu", len));
	ਜੇ ((r = sshbuf_check_sanity(buf)) != 0)
		ਵਾਪਸ r;
	ਜੇ (len == 0)
		ਵਾਪਸ 0;
	ਜੇ (len > sshbuf_len(buf))
		ਵਾਪਸ SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	ਜੇ (buf->off == buf->ਮਾਪ)
		buf->off = buf->ਮਾਪ = 0;
	SSHBUF_TELL("done");
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_consume_ਸਿਰਾ(ਬਣਤਰ sshbuf *buf, ਮਾਪ_t len)
{
	ਪੂਰਨ r;

	SSHBUF_DBG(("len = %zu", len));
	ਜੇ ((r = sshbuf_check_sanity(buf)) != 0)
		ਵਾਪਸ r;
	ਜੇ (len == 0)
		ਵਾਪਸ 0;
	ਜੇ (len > sshbuf_len(buf))
		ਵਾਪਸ SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE;
	buf->ਮਾਪ -= len;
	SSHBUF_TELL("done");
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshbuf_consume_upto_ਬੱਚਾ(ਬਣਤਰ sshbuf *buf, ਅਚਲ ਬਣਤਰ sshbuf *ਬੱਚਾ)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(ਬੱਚਾ)) != 0)
		ਵਾਪਸ r;
	/* This function is only used for parent/child buffers */
	ਜੇ (ਬੱਚਾ->ਮਾਪਾ != buf)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	/* Nonsensical if the parent has advanced past the child */
	ਜੇ (sshbuf_len(ਬੱਚਾ) > sshbuf_len(buf))
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	/* More paranoia, shouldn't happen */
	ਜੇ (ਬੱਚਾ->cd < buf->cd)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	/* Advance */
	ਵਾਪਸ sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(ਬੱਚਾ));
}
