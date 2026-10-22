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
#ವ್ಯಾಖ್ಯಾನಿಸು SSHBUF_ಆಂತರಿಕ
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ SSHBUF_DEBUG
# define SSHBUF_TELL(what) ಮಾಡು { \
		ಬರೆ("%s:%d %s: %s size %zu alloc %zu off %zu max %zu\n", \
		    __FILE__, __LINE__, __func__, what, \
		    buf->ಗಾತ್ರ_2, buf->alloc, buf->off, buf->max_ಗಾತ್ರ); \
		fflush(stdout); \
	} ಆಗ (0)
#ಇಲ್ಲದಿದ್ದರೆ
# define SSHBUF_TELL(what)
#ಆದರೆ_ಅಂತ್ಯ

ರಚನೆ sshbuf {
	u_char *d;		/* Data */
	ಸ್ಥಿರಾಂಕ u_char *cd;	/* Const data */
	ಗಾತ್ರ_t off;		/* First available byte is buf->d + buf->off */
	ಗಾತ್ರ_t ಗಾತ್ರ_2;		/* Last byte is buf->d + buf->size - 1 */
	ಗಾತ್ರ_t max_ಗಾತ್ರ;	/* Maximum size of buffer */
	ಗಾತ್ರ_t alloc;		/* Total bytes allocated to buf->d */
	ಪೂರ್ಣಾಂಕ readonly;		/* Refers to external, const data */
	u_int refcount;		/* Tracks self and number of child buffers */
	ರಚನೆ sshbuf *ಪೋಷಕ;	/* If child, pointer to parent */
};

ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಪೂರ್ಣಾಂಕ
sshbuf_check_sanity(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf)
{
	SSHBUF_TELL("sanity");
	ಆದರೆ (__predict_false(buf == ಖಾಲಿ ||
	    (!buf->readonly && buf->d != buf->cd) ||
	    buf->ಪೋಷಕ == buf ||
	    buf->refcount < 1 || buf->refcount > SSHBUF_REFS_MAX ||
	    buf->cd == ಖಾಲಿ ||
	    buf->max_ಗಾತ್ರ > SSHBUF_ಗಾತ್ರ_MAX ||
	    buf->alloc > buf->max_ಗಾತ್ರ ||
	    buf->ಗಾತ್ರ_2 > buf->alloc ||
	    buf->off > buf->ಗಾತ್ರ_2)) {
		/* Do not try to recover from corrupted buffer internals */
		SSHBUF_DBG(("SSH_ERR_INTERNAL_ERROR"));
		ssh_signal(SIGSEGV, SIG_DFL);
		ಎತ್ತು(SIGSEGV);
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
sshbuf_maybe_pack(ರಚನೆ sshbuf *buf, ಪೂರ್ಣಾಂಕ force)
{
	SSHBUF_DBG(("force %d", force));
	SSHBUF_TELL("pre-pack");
	ಆದರೆ (buf->off == 0 || buf->readonly || buf->refcount > 1)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (force ||
	    (buf->off >= SSHBUF_PACK_MIN && buf->off >= buf->ಗಾತ್ರ_2 / 2)) {
		memmove(buf->d, buf->d + buf->off, buf->ಗಾತ್ರ_2 - buf->off);
		buf->ಗಾತ್ರ_2 -= buf->off;
		buf->off = 0;
		SSHBUF_TELL("packed");
	}
}

ರಚನೆ sshbuf *
sshbuf_new(ಶೂನ್ಯ)
{
	ರಚನೆ sshbuf *ret;

	ಆದರೆ ((ret = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*ret))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ret->alloc = SSHBUF_ಗಾತ್ರ_INIT;
	ret->max_ಗಾತ್ರ = SSHBUF_ಗಾತ್ರ_MAX;
	ret->readonly = 0;
	ret->refcount = 1;
	ret->ಪೋಷಕ = ಖಾಲಿ;
	ಆದರೆ ((ret->cd = ret->d = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ret->alloc)) == ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(ret);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ ret;
}

ರಚನೆ sshbuf *
sshbuf_from(ಸ್ಥಿರಾಂಕ ಶೂನ್ಯ *blob, ಗಾತ್ರ_t len)
{
	ರಚನೆ sshbuf *ret;

	ಆದರೆ (blob == ಖಾಲಿ || len > SSHBUF_ಗಾತ್ರ_MAX ||
	    (ret = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*ret))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ret->alloc = ret->ಗಾತ್ರ_2 = ret->max_ಗಾತ್ರ = len;
	ret->readonly = 1;
	ret->refcount = 1;
	ret->ಪೋಷಕ = ಖಾಲಿ;
	ret->cd = blob;
	ret->d = ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
sshbuf_ಗಣ_ಪೋಷಕ(ರಚನೆ sshbuf *ಮಗು, ರಚನೆ sshbuf *ಪೋಷಕ)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_check_sanity(ಮಗು)) != 0 ||
	    (r = sshbuf_check_sanity(ಪೋಷಕ)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((ಮಗು->ಪೋಷಕ != ಖಾಲಿ && ಮಗು->ಪೋಷಕ != ಪೋಷಕ) ||
	    ಮಗು == ಪೋಷಕ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಮಗು->ಪೋಷಕ = ಪೋಷಕ;
	ಮಗು->ಪೋಷಕ->refcount++;
	ಹಿಂತಿರುಗಿ 0;
}

ರಚನೆ sshbuf *
sshbuf_fromb(ರಚನೆ sshbuf *buf)
{
	ರಚನೆ sshbuf *ret;

	ಆದರೆ (sshbuf_check_sanity(buf) != 0)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಆದರೆ ((ret = sshbuf_from(sshbuf_ptr(buf), sshbuf_len(buf))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಆದರೆ (sshbuf_ಗಣ_ಪೋಷಕ(ret, buf) != 0) {
		sshbuf_free(ret);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ ret;
}

ಶೂನ್ಯ
sshbuf_free(ರಚನೆ sshbuf *buf)
{
	ಆದರೆ (buf == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	/*
	 * The following will leak on insane buffers, but this is the safest
	 * course of action - an invalid pointer or already-freed pointer may
	 * have been passed to us and continuing to scribble over memory would
	 * be bad.
	 */
	ಆದರೆ (sshbuf_check_sanity(buf) != 0)
		ಹಿಂತಿರುಗಿ;

	/*
	 * If we are a parent with still-extant children, then don't free just
	 * yet. The last child's call to sshbuf_free should decrement our
	 * refcount to 0 and trigger the actual free.
	 */
	buf->refcount--;
	ಆದರೆ (buf->refcount > 0)
		ಹಿಂತಿರುಗಿ;

	/*
	 * If we are a child, then free our parent to decrement its reference
	 * count and possibly free it.
	 */
	sshbuf_free(buf->ಪೋಷಕ);
	buf->ಪೋಷಕ = ಖಾಲಿ;

	ಆದರೆ (!buf->readonly)
		freezero(buf->d, buf->alloc);
	freezero(buf, ಗಾತ್ರ(*buf));
}

ಶೂನ್ಯ
sshbuf_reset(ರಚನೆ sshbuf *buf)
{
	u_char *d;

	ಆದರೆ (buf->readonly || buf->refcount > 1) {
		/* Nonsensical. Just make buffer appear empty */
		buf->off = buf->ಗಾತ್ರ_2;
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ (sshbuf_check_sanity(buf) != 0)
		ಹಿಂತಿರುಗಿ;
	buf->off = buf->ಗಾತ್ರ_2 = 0;
	ಆದರೆ (buf->alloc != SSHBUF_ಗಾತ್ರ_INIT) {
		ಆದರೆ ((d = recallocarray(buf->d, buf->alloc, SSHBUF_ಗಾತ್ರ_INIT,
		    1)) != ಖಾಲಿ) {
			buf->cd = buf->d = d;
			buf->alloc = SSHBUF_ಗಾತ್ರ_INIT;
		}
	}
	explicit_bzero(buf->d, buf->alloc);
}

ಗಾತ್ರ_t
sshbuf_max_ಗಾತ್ರ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf)
{
	ಹಿಂತಿರುಗಿ buf->max_ಗಾತ್ರ;
}

ಗಾತ್ರ_t
sshbuf_alloc(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf)
{
	ಹಿಂತಿರುಗಿ buf->alloc;
}

ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *
sshbuf_ಪೋಷಕ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf)
{
	ಹಿಂತಿರುಗಿ buf->ಪೋಷಕ;
}

u_int
sshbuf_refcount(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf)
{
	ಹಿಂತಿರುಗಿ buf->refcount;
}

ಪೂರ್ಣಾಂಕ
sshbuf_ಗಣ_max_ಗಾತ್ರ(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t max_ಗಾತ್ರ)
{
	ಗಾತ್ರ_t rlen;
	u_char *dp;
	ಪೂರ್ಣಾಂಕ r;

	SSHBUF_DBG(("set max buf = %p len = %zu", buf, max_ಗಾತ್ರ));
	ಆದರೆ ((r = sshbuf_check_sanity(buf)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (max_ಗಾತ್ರ == buf->max_ಗಾತ್ರ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (buf->readonly || buf->refcount > 1)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಬಫರ್_READ_ONLY;
	ಆದರೆ (max_ಗಾತ್ರ > SSHBUF_ಗಾತ್ರ_MAX)
		ಹಿಂತಿರುಗಿ SSH_ERR_NO_ಬಫರ್_SPACE;
	/* pack and realloc if necessary */
	sshbuf_maybe_pack(buf, max_ಗಾತ್ರ < buf->ಗಾತ್ರ_2);
	ಆದರೆ (max_ಗಾತ್ರ < buf->alloc && max_ಗಾತ್ರ > buf->ಗಾತ್ರ_2) {
		ಆದರೆ (buf->ಗಾತ್ರ_2 < SSHBUF_ಗಾತ್ರ_INIT)
			rlen = SSHBUF_ಗಾತ್ರ_INIT;
		ಇಲ್ಲದಿದ್ದರೆ
			rlen = ROUNDUP(buf->ಗಾತ್ರ_2, SSHBUF_ಗಾತ್ರ_INC);
		ಆದರೆ (rlen > max_ಗಾತ್ರ)
			rlen = max_ಗಾತ್ರ;
		SSHBUF_DBG(("new alloc = %zu", rlen));
		ಆದರೆ ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
		buf->cd = buf->d = dp;
		buf->alloc = rlen;
	}
	SSHBUF_TELL("new-max");
	ಆದರೆ (max_ಗಾತ್ರ < buf->alloc)
		ಹಿಂತಿರುಗಿ SSH_ERR_NO_ಬಫರ್_SPACE;
	buf->max_ಗಾತ್ರ = max_ಗಾತ್ರ;
	ಹಿಂತಿರುಗಿ 0;
}

ಗಾತ್ರ_t
sshbuf_len(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf)
{
	ಆದರೆ (sshbuf_check_sanity(buf) != 0)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ buf->ಗಾತ್ರ_2 - buf->off;
}

ಗಾತ್ರ_t
sshbuf_avail(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf)
{
	ಆದರೆ (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ buf->max_ಗಾತ್ರ - (buf->ಗಾತ್ರ_2 - buf->off);
}

ಸ್ಥಿರಾಂಕ u_char *
sshbuf_ptr(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf)
{
	ಆದರೆ (sshbuf_check_sanity(buf) != 0)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ buf->cd + buf->off;
}

u_char *
sshbuf_mutable_ptr(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf)
{
	ಆದರೆ (sshbuf_check_sanity(buf) != 0 || buf->readonly || buf->refcount > 1)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ buf->d + buf->off;
}

ಪೂರ್ಣಾಂಕ
sshbuf_check_reserve(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t len)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_check_sanity(buf)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (buf->readonly || buf->refcount > 1)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಬಫರ್_READ_ONLY;
	SSHBUF_TELL("check");
	/* Check that len is reasonable and that max_size + available < len */
	ಆದರೆ (len > buf->max_ಗಾತ್ರ || buf->max_ಗಾತ್ರ - len < buf->ಗಾತ್ರ_2 - buf->off)
		ಹಿಂತಿರುಗಿ SSH_ERR_NO_ಬಫರ್_SPACE;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_allocate(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t len)
{
	ಗಾತ್ರ_t rlen, need;
	u_char *dp;
	ಪೂರ್ಣಾಂಕ r;

	SSHBUF_DBG(("allocate buf = %p len = %zu", buf, len));
	ಆದರೆ ((r = sshbuf_check_reserve(buf, len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	/*
	 * If the requested allocation appended would push us past max_size
	 * then pack the buffer, zeroing buf->off.
	 */
	sshbuf_maybe_pack(buf, buf->ಗಾತ್ರ_2 + len > buf->max_ಗಾತ್ರ);
	SSHBUF_TELL("allocate");
	ಆದರೆ (len + buf->ಗಾತ್ರ_2 <= buf->alloc)
		ಹಿಂತಿರುಗಿ 0; /* already have it. */

	/*
	 * Prefer to alloc in SSHBUF_SIZE_INC units, but
	 * allocate less if doing so would overflow max_size.
	 */
	need = len + buf->ಗಾತ್ರ_2 - buf->alloc;
	rlen = ROUNDUP(buf->alloc + need, SSHBUF_ಗಾತ್ರ_INC);
	SSHBUF_DBG(("need %zu initial rlen %zu", need, rlen));
	ಆದರೆ (rlen > buf->max_ಗಾತ್ರ)
		rlen = buf->alloc + need;
	SSHBUF_DBG(("adjusted rlen %zu", rlen));
	ಆದರೆ ((dp = recallocarray(buf->d, buf->alloc, rlen, 1)) == ಖಾಲಿ) {
		SSHBUF_DBG(("realloc fail"));
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	}
	buf->alloc = rlen;
	buf->cd = buf->d = dp;
	ಆದರೆ ((r = sshbuf_check_reserve(buf, len)) < 0) {
		/* shouldn't fail */
		ಹಿಂತಿರುಗಿ r;
	}
	SSHBUF_TELL("done");
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_reserve(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t len, u_char **dpp)
{
	u_char *dp;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (dpp != ಖಾಲಿ)
		*dpp = ಖಾಲಿ;

	SSHBUF_DBG(("reserve buf = %p len = %zu", buf, len));
	ಆದರೆ ((r = sshbuf_allocate(buf, len)) != 0)
		ಹಿಂತಿರುಗಿ r;

	dp = buf->d + buf->ಗಾತ್ರ_2;
	buf->ಗಾತ್ರ_2 += len;
	ಆದರೆ (dpp != ಖಾಲಿ)
		*dpp = dp;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_consume(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t len)
{
	ಪೂರ್ಣಾಂಕ r;

	SSHBUF_DBG(("len = %zu", len));
	ಆದರೆ ((r = sshbuf_check_sanity(buf)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (len == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (len > sshbuf_len(buf))
		ಹಿಂತಿರುಗಿ SSH_ERR_ಸಂದೇಶ_INCOMPLETE;
	buf->off += len;
	/* deal with empty buffer */
	ಆದರೆ (buf->off == buf->ಗಾತ್ರ_2)
		buf->off = buf->ಗಾತ್ರ_2 = 0;
	SSHBUF_TELL("done");
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_consume_ಕೊನೆ(ರಚನೆ sshbuf *buf, ಗಾತ್ರ_t len)
{
	ಪೂರ್ಣಾಂಕ r;

	SSHBUF_DBG(("len = %zu", len));
	ಆದರೆ ((r = sshbuf_check_sanity(buf)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (len == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (len > sshbuf_len(buf))
		ಹಿಂತಿರುಗಿ SSH_ERR_ಸಂದೇಶ_INCOMPLETE;
	buf->ಗಾತ್ರ_2 -= len;
	SSHBUF_TELL("done");
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshbuf_consume_upto_ಮಗು(ರಚನೆ sshbuf *buf, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *ಮಗು)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_check_sanity(buf)) != 0 ||
	    (r = sshbuf_check_sanity(ಮಗು)) != 0)
		ಹಿಂತಿರುಗಿ r;
	/* This function is only used for parent/child buffers */
	ಆದರೆ (ಮಗು->ಪೋಷಕ != buf)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	/* Nonsensical if the parent has advanced past the child */
	ಆದರೆ (sshbuf_len(ಮಗು) > sshbuf_len(buf))
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	/* More paranoia, shouldn't happen */
	ಆದರೆ (ಮಗು->cd < buf->cd)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	/* Advance */
	ಹಿಂತಿರುಗಿ sshbuf_consume(buf, sshbuf_len(buf) - sshbuf_len(ಮಗು));
}
