/* $OpenBSD: krl.c,v 1.66 2026/10/17 11:47:42 djm Exp $ */
/*
 * Copyright (c) 2012 Damien Miller <djm@mindrot.org>
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
#ಅನ್ತರ್ಭಾವ <sys/tree.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <time.h>

#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "bitmap.h"
#ಅನ್ತರ್ಭಾವ "utf8.h"

#ಅನ್ತರ್ಭಾವ "krl.h"

/* #define DEBUG_KRL */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KRL
# define KRL_DBG(x) debug3_f x
#ಇಲ್ಲದಿದ್ದರೆ
# define KRL_DBG(x)
#ಆದರೆ_ಅಂತ್ಯ

/*
 * Trees of revoked serial numbers, key IDs and keys. This allows
 * quick searching, querying and producing lists in canonical order.
 */

/* Tree of serial numbers. XXX make smarter: really need a real sparse bitmap */
ರಚನೆ revoked_serial {
	uint64_t lo, hi;
	RB_ನಮೂದು(revoked_serial) ವೃಕ್ಷ_ನಮೂದು;
};
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ serial_cmp(ರಚನೆ revoked_serial *a, ರಚನೆ revoked_serial *b);
RB_ತಲೆ(revoked_serial_ವೃಕ್ಷ, revoked_serial);
RB_GENERATE_STATIC(revoked_serial_ವೃಕ್ಷ, revoked_serial, ವೃಕ್ಷ_ನಮೂದು, serial_cmp)

/* Tree of key IDs */
ರಚನೆ revoked_ಕೀಲಿ_id {
	ಅಕ್ಷರ *ಕೀಲಿ_id;
	RB_ನಮೂದು(revoked_ಕೀಲಿ_id) ವೃಕ್ಷ_ನಮೂದು;
};
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಕೀಲಿ_id_cmp(ರಚನೆ revoked_ಕೀಲಿ_id *a, ರಚನೆ revoked_ಕೀಲಿ_id *b);
RB_ತಲೆ(revoked_ಕೀಲಿ_id_ವೃಕ್ಷ, revoked_ಕೀಲಿ_id);
RB_GENERATE_STATIC(revoked_ಕೀಲಿ_id_ವೃಕ್ಷ, revoked_ಕೀಲಿ_id, ವೃಕ್ಷ_ನಮೂದು, ಕೀಲಿ_id_cmp)

/* Tree of blobs (used for keys and fingerprints) */
ರಚನೆ revoked_blob {
	u_char *blob;
	ಗಾತ್ರ_t len;
	RB_ನಮೂದು(revoked_blob) ವೃಕ್ಷ_ನಮೂದು;
};
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ blob_cmp(ರಚನೆ revoked_blob *a, ರಚನೆ revoked_blob *b);
RB_ತಲೆ(revoked_blob_ವೃಕ್ಷ, revoked_blob);
RB_GENERATE_STATIC(revoked_blob_ವೃಕ್ಷ, revoked_blob, ವೃಕ್ಷ_ನಮೂದು, blob_cmp)

/* Tracks revoked certs for a single CA */
ರಚನೆ revoked_certs {
	ರಚನೆ sshkey *ca_ಕೀಲಿ;
	ರಚನೆ revoked_serial_ವೃಕ್ಷ revoked_serials;
	ರಚನೆ revoked_ಕೀಲಿ_id_ವೃಕ್ಷ revoked_ಕೀಲಿ_ids;
	TAILQ_ENTRY(revoked_certs) ನಮೂದು;
};
TAILQ_HEAD(revoked_certs_list, revoked_certs);

ರಚನೆ ssh_krl {
	uint64_t krl_ಆವೃತ್ತಿ;
	uint64_t generated_date;
	uint64_t flags;
	ಅಕ್ಷರ *comment;
	ರಚನೆ revoked_blob_ವೃಕ್ಷ revoked_ಕೀಲಿಗಳು;
	ರಚನೆ revoked_blob_ವೃಕ್ಷ revoked_sha1s;
	ರಚನೆ revoked_blob_ವೃಕ್ಷ revoked_sha256s;
	ರಚನೆ revoked_certs_list revoked_certs;
};

/* Return equal if a and b overlap */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
serial_cmp(ರಚನೆ revoked_serial *a, ರಚನೆ revoked_serial *b)
{
	ಆದರೆ (a->hi >= b->lo && a->lo <= b->hi)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ a->lo < b->lo ? -1 : 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಕೀಲಿ_id_cmp(ರಚನೆ revoked_ಕೀಲಿ_id *a, ರಚನೆ revoked_ಕೀಲಿ_id *b)
{
	ಹಿಂತಿರುಗಿ strcmp(a->ಕೀಲಿ_id, b->ಕೀಲಿ_id);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
blob_cmp(ರಚನೆ revoked_blob *a, ರಚನೆ revoked_blob *b)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (a->len != b->len) {
		ಆದರೆ ((r = memcmp(a->blob, b->blob, MINIMUM(a->len, b->len))) != 0)
			ಹಿಂತಿರುಗಿ r;
		ಹಿಂತಿರುಗಿ a->len > b->len ? 1 : -1;
	} ಇಲ್ಲದಿದ್ದರೆ
		ಹಿಂತಿರುಗಿ memcmp(a->blob, b->blob, a->len);
}

ರಚನೆ ssh_krl *
ssh_krl_init(ಶೂನ್ಯ)
{
	ರಚನೆ ssh_krl *krl;

	ಆದರೆ ((krl = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*krl))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	RB_INIT(&krl->revoked_ಕೀಲಿಗಳು);
	RB_INIT(&krl->revoked_sha1s);
	RB_INIT(&krl->revoked_sha256s);
	TAILQ_INIT(&krl->revoked_certs);
	ಹಿಂತಿರುಗಿ krl;
}

ಸ್ಥಿರ ಶೂನ್ಯ
revoked_certs_free(ರಚನೆ revoked_certs *rc)
{
	ರಚನೆ revoked_serial *rs, *trs;
	ರಚನೆ revoked_ಕೀಲಿ_id *rki, *trki;

	ಆದರೆ (rc == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	RB_FOREACH_ಸುರಕ್ಷಿತ(rs, revoked_serial_ವೃಕ್ಷ, &rc->revoked_serials, trs) {
		RB_REMOVE(revoked_serial_ವೃಕ್ಷ, &rc->revoked_serials, rs);
		ಬಿಡುಗಡೆ(rs);
	}
	RB_FOREACH_ಸುರಕ್ಷಿತ(rki, revoked_ಕೀಲಿ_id_ವೃಕ್ಷ, &rc->revoked_ಕೀಲಿ_ids, trki) {
		RB_REMOVE(revoked_ಕೀಲಿ_id_ವೃಕ್ಷ, &rc->revoked_ಕೀಲಿ_ids, rki);
		ಬಿಡುಗಡೆ(rki->ಕೀಲಿ_id);
		ಬಿಡುಗಡೆ(rki);
	}
	sshkey_free(rc->ca_ಕೀಲಿ);
	freezero(rc, ಗಾತ್ರ(*rc));
}

ಶೂನ್ಯ
ssh_krl_free(ರಚನೆ ssh_krl *krl)
{
	ರಚನೆ revoked_blob *rb, *trb;
	ರಚನೆ revoked_certs *rc, *trc;

	ಆದರೆ (krl == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;

	ಬಿಡುಗಡೆ(krl->comment);
	RB_FOREACH_ಸುರಕ್ಷಿತ(rb, revoked_blob_ವೃಕ್ಷ, &krl->revoked_ಕೀಲಿಗಳು, trb) {
		RB_REMOVE(revoked_blob_ವೃಕ್ಷ, &krl->revoked_ಕೀಲಿಗಳು, rb);
		ಬಿಡುಗಡೆ(rb->blob);
		ಬಿಡುಗಡೆ(rb);
	}
	RB_FOREACH_ಸುರಕ್ಷಿತ(rb, revoked_blob_ವೃಕ್ಷ, &krl->revoked_sha1s, trb) {
		RB_REMOVE(revoked_blob_ವೃಕ್ಷ, &krl->revoked_sha1s, rb);
		ಬಿಡುಗಡೆ(rb->blob);
		ಬಿಡುಗಡೆ(rb);
	}
	RB_FOREACH_ಸುರಕ್ಷಿತ(rb, revoked_blob_ವೃಕ್ಷ, &krl->revoked_sha256s, trb) {
		RB_REMOVE(revoked_blob_ವೃಕ್ಷ, &krl->revoked_sha256s, rb);
		ಬಿಡುಗಡೆ(rb->blob);
		ಬಿಡುಗಡೆ(rb);
	}
	TAILQ_FOREACH_ಸುರಕ್ಷಿತ(rc, &krl->revoked_certs, ನಮೂದು, trc) {
		TAILQ_REMOVE(&krl->revoked_certs, rc, ನಮೂದು);
		revoked_certs_free(rc);
	}
	ಬಿಡುಗಡೆ(krl);
}

ಶೂನ್ಯ
ssh_krl_ಗಣ_ಆವೃತ್ತಿ(ರಚನೆ ssh_krl *krl, uint64_t ಆವೃತ್ತಿ)
{
	krl->krl_ಆವೃತ್ತಿ = ಆವೃತ್ತಿ;
}

ಪೂರ್ಣಾಂಕ
ssh_krl_ಗಣ_comment(ರಚನೆ ssh_krl *krl, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *comment)
{
	ಬಿಡುಗಡೆ(krl->comment);
	ಆದರೆ ((krl->comment = strdup(comment)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Find the revoked_certs struct for a CA key. If allow_create is set then
 * create a new one in the tree if one did not exist already.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
revoked_certs_for_ca_ಕೀಲಿ(ರಚನೆ ssh_krl *krl, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ca_ಕೀಲಿ,
    ರಚನೆ revoked_certs **rcp, ಪೂರ್ಣಾಂಕ allow_create)
{
	ರಚನೆ revoked_certs *rc;
	ಪೂರ್ಣಾಂಕ r;

	*rcp = ಖಾಲಿ;
	TAILQ_FOREACH(rc, &krl->revoked_certs, ನಮೂದು) {
		ಆದರೆ ((ca_ಕೀಲಿ == ಖಾಲಿ && rc->ca_ಕೀಲಿ == ಖಾಲಿ) ||
		    sshkey_equal(rc->ca_ಕೀಲಿ, ca_ಕೀಲಿ)) {
			*rcp = rc;
			ಹಿಂತಿರುಗಿ 0;
		}
	}
	ಆದರೆ (!allow_create)
		ಹಿಂತಿರುಗಿ 0;
	/* If this CA doesn't exist in the list then add it now */
	ಆದರೆ ((rc = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*rc))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ (ca_ಕೀಲಿ == ಖಾಲಿ)
		rc->ca_ಕೀಲಿ = ಖಾಲಿ;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = sshkey_from_ಖಾಸಗಿ(ca_ಕೀಲಿ, &rc->ca_ಕೀಲಿ)) != 0) {
		ಬಿಡುಗಡೆ(rc);
		ಹಿಂತಿರುಗಿ r;
	}
	RB_INIT(&rc->revoked_serials);
	RB_INIT(&rc->revoked_ಕೀಲಿ_ids);
	TAILQ_INSERT_TAIL(&krl->revoked_certs, rc, ನಮೂದು);
	KRL_DBG(("new CA %s", ca_ಕೀಲಿ == ಖಾಲಿ ? "*" : sshkey_type(ca_ಕೀಲಿ)));
	*rcp = rc;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಸೇರಿಸು_serial_range(ರಚನೆ revoked_serial_ವೃಕ್ಷ *rt, uint64_t lo, uint64_t hi)
{
	ರಚನೆ revoked_serial rs, *ers, *crs, *irs;

	KRL_DBG(("insert %llu:%llu",
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)lo, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)hi));
	memset(&rs, 0, ಗಾತ್ರ(rs));
	rs.lo = lo;
	rs.hi = hi;
	ers = RB_NFIND(revoked_serial_ವೃಕ್ಷ, rt, &rs);
	ಆದರೆ (ers == ಖಾಲಿ || serial_cmp(ers, &rs) != 0) {
		/* No entry matches. Just insert */
		ಆದರೆ ((irs = ಸ್ಮರಣೆ_ಕೊಡು(ಗಾತ್ರ(rs))) == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
		ಸ್ಮರಣೆ_ನಕಲು(irs, &rs, ಗಾತ್ರ(*irs));
		ers = RB_ಸೇರಿಸು(revoked_serial_ವೃಕ್ಷ, rt, irs);
		ಆದರೆ (ers != ಖಾಲಿ) {
			KRL_DBG(("bad: ers != NULL"));
			/* Shouldn't happen */
			ಬಿಡುಗಡೆ(irs);
			ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
		}
		ers = irs;
	} ಇಲ್ಲದಿದ್ದರೆ {
		KRL_DBG(("overlap found %llu:%llu",
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ers->lo, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ers->hi));
		/*
		 * The inserted entry overlaps an existing one. Grow the
		 * existing entry.
		 */
		ಆದರೆ (ers->lo > lo)
			ers->lo = lo;
		ಆದರೆ (ers->hi < hi)
			ers->hi = hi;
	}

	/*
	 * The inserted or revised range might overlap or abut adjacent ones;
	 * coalesce as necessary.
	 */

	/* Check predecessors */
	ಆಗ ((crs = RB_PREV(revoked_serial_ವೃಕ್ಷ, rt, ers)) != ಖಾಲಿ) {
		KRL_DBG(("pred %llu:%llu",
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)crs->lo, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)crs->hi));
		ಆದರೆ (ers->lo != 0 && crs->hi < ers->lo - 1)
			ನಿಲ್ಲಿಸು;
		/* This entry overlaps. */
		ಆದರೆ (crs->lo < ers->lo) {
			ers->lo = crs->lo;
			KRL_DBG(("pred extend %llu:%llu",
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ers->lo,
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ers->hi));
		}
		RB_REMOVE(revoked_serial_ವೃಕ್ಷ, rt, crs);
		ಬಿಡುಗಡೆ(crs);
	}
	/* Check successors */
	ಆಗ ((crs = RB_ಮುಂದಿನ(revoked_serial_ವೃಕ್ಷ, rt, ers)) != ಖಾಲಿ) {
		KRL_DBG(("succ %llu:%llu",
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)crs->lo, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)crs->hi));
		ಆದರೆ (ers->hi != (uint64_t)-1 && crs->lo > ers->hi + 1)
			ನಿಲ್ಲಿಸು;
		/* This entry overlaps. */
		ಆದರೆ (crs->hi > ers->hi) {
			ers->hi = crs->hi;
			KRL_DBG(("succ extend %llu:%llu",
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ers->lo,
			    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ers->hi));
		}
		RB_REMOVE(revoked_serial_ವೃಕ್ಷ, rt, crs);
		ಬಿಡುಗಡೆ(crs);
	}
	KRL_DBG(("done, final %llu:%llu",
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ers->lo, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ers->hi));
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
ssh_krl_revoke_cert_by_serial(ರಚನೆ ssh_krl *krl, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ca_ಕೀಲಿ,
    uint64_t serial)
{
	ಹಿಂತಿರುಗಿ ssh_krl_revoke_cert_by_serial_range(krl, ca_ಕೀಲಿ, serial, serial);
}

ಪೂರ್ಣಾಂಕ
ssh_krl_revoke_cert_by_serial_range(ರಚನೆ ssh_krl *krl,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ca_ಕೀಲಿ, uint64_t lo, uint64_t hi)
{
	ರಚನೆ revoked_certs *rc;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (lo > hi || lo == 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ ((r = revoked_certs_for_ca_ಕೀಲಿ(krl, ca_ಕೀಲಿ, &rc, 1)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ ಸೇರಿಸು_serial_range(&rc->revoked_serials, lo, hi);
}

ಪೂರ್ಣಾಂಕ
ssh_krl_revoke_cert_by_ಕೀಲಿ_id(ರಚನೆ ssh_krl *krl, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ca_ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಕೀಲಿ_id)
{
	ರಚನೆ revoked_ಕೀಲಿ_id *rki, *erki;
	ರಚನೆ revoked_certs *rc;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = revoked_certs_for_ca_ಕೀಲಿ(krl, ca_ಕೀಲಿ, &rc, 1)) != 0)
		ಹಿಂತಿರುಗಿ r;

	KRL_DBG(("revoke %s", ಕೀಲಿ_id));
	ಆದರೆ ((rki = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*rki))) == ಖಾಲಿ ||
	    (rki->ಕೀಲಿ_id = strdup(ಕೀಲಿ_id)) == ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(rki);
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	}
	erki = RB_ಸೇರಿಸು(revoked_ಕೀಲಿ_id_ವೃಕ್ಷ, &rc->revoked_ಕೀಲಿ_ids, rki);
	ಆದರೆ (erki != ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(rki->ಕೀಲಿ_id);
		ಬಿಡುಗಡೆ(rki);
	}
	ಹಿಂತಿರುಗಿ 0;
}

/* Convert "key" to a public key blob without any certificate information */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
plain_ಕೀಲಿ_blob(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, u_char **blob, ಗಾತ್ರ_t *blen)
{
	ರಚನೆ sshkey *kcopy;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshkey_from_ಖಾಸಗಿ(ಕೀಲಿ, &kcopy)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (sshkey_is_cert(kcopy)) {
		ಆದರೆ ((r = sshkey_drop_cert(kcopy)) != 0) {
			sshkey_free(kcopy);
			ಹಿಂತಿರುಗಿ r;
		}
	}
	r = sshkey_ಗಮ್ಯ_blob(kcopy, blob, blen);
	sshkey_free(kcopy);
	ಹಿಂತಿರುಗಿ r;
}

/* Revoke a key blob. Ownership of blob is transferred to the tree */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
revoke_blob(ರಚನೆ revoked_blob_ವೃಕ್ಷ *rbt, u_char *blob, ಗಾತ್ರ_t len)
{
	ರಚನೆ revoked_blob *rb, *erb;

	ಆದರೆ ((rb = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*rb))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	rb->blob = blob;
	rb->len = len;
	erb = RB_ಸೇರಿಸು(revoked_blob_ವೃಕ್ಷ, rbt, rb);
	ಆದರೆ (erb != ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(rb->blob);
		ಬಿಡುಗಡೆ(rb);
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
ssh_krl_revoke_ಕೀಲಿ_explicit(ರಚನೆ ssh_krl *krl, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ)
{
	u_char *blob;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("revoke type %s", sshkey_type(ಕೀಲಿ));
	ಆದರೆ ((r = plain_ಕೀಲಿ_blob(ಕೀಲಿ, &blob, &len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ revoke_blob(&krl->revoked_ಕೀಲಿಗಳು, blob, len);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
revoke_by_hash(ರಚನೆ revoked_blob_ವೃಕ್ಷ *ಗುರಿ, ಸ್ಥಿರಾಂಕ u_char *p, ಗಾತ್ರ_t len)
{
	u_char *blob;
	ಪೂರ್ಣಾಂಕ r;

	/* need to copy hash, as revoke_blob steals ownership */
	ಆದರೆ ((blob = ಸ್ಮರಣೆ_ಕೊಡು(len)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
	ಸ್ಮರಣೆ_ನಕಲು(blob, p, len);
	ಆದರೆ ((r = revoke_blob(ಗುರಿ, blob, len)) != 0) {
		ಬಿಡುಗಡೆ(blob);
		ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
ssh_krl_revoke_ಕೀಲಿ_sha1(ರಚನೆ ssh_krl *krl, ಸ್ಥಿರಾಂಕ u_char *p, ಗಾತ್ರ_t len)
{
	debug3_f("revoke by sha1");
	ಆದರೆ (len != 20)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	ಹಿಂತಿರುಗಿ revoke_by_hash(&krl->revoked_sha1s, p, len);
}

ಪೂರ್ಣಾಂಕ
ssh_krl_revoke_ಕೀಲಿ_sha256(ರಚನೆ ssh_krl *krl, ಸ್ಥಿರಾಂಕ u_char *p, ಗಾತ್ರ_t len)
{
	debug3_f("revoke by sha256");
	ಆದರೆ (len != 32)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	ಹಿಂತಿರುಗಿ revoke_by_hash(&krl->revoked_sha256s, p, len);
}

ಪೂರ್ಣಾಂಕ
ssh_krl_revoke_ಕೀಲಿ(ರಚನೆ ssh_krl *krl, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ)
{
	/* XXX replace with SHA256? */
	ಆದರೆ (!sshkey_is_cert(ಕೀಲಿ))
		ಹಿಂತಿರುಗಿ ssh_krl_revoke_ಕೀಲಿ_explicit(krl, ಕೀಲಿ);

	ಆದರೆ (ಕೀಲಿ->cert->serial == 0) {
		ಹಿಂತಿರುಗಿ ssh_krl_revoke_cert_by_ಕೀಲಿ_id(krl,
		    ಕೀಲಿ->cert->signature_ಕೀಲಿ,
		    ಕೀಲಿ->cert->ಕೀಲಿ_id);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಹಿಂತಿರುಗಿ ssh_krl_revoke_cert_by_serial(krl,
		    ಕೀಲಿ->cert->signature_ಕೀಲಿ,
		    ಕೀಲಿ->cert->serial);
	}
}

/*
 * Select the most compact section type to emit next in a KRL based on
 * the current section type, the run length of contiguous revoked serial
 * numbers and the gaps from the last and to the next revoked serial.
 * Applies a mostly-accurate bit cost model to select the section type
 * that will minimise the size of the resultant KRL.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಆರಿಸು_ಮುಂದಿನ_state(ಪೂರ್ಣಾಂಕ current_state, uint64_t contig, ಪೂರ್ಣಾಂಕ final,
    uint64_t ಕೊನೆಯ_gap, uint64_t ಮುಂದಿನ_gap, ಗಾತ್ರ_t bitmap_len,
    ಪೂರ್ಣಾಂಕ *force_new_section)
{
	ಪೂರ್ಣಾಂಕ new_state;
	uint64_t ವೆಚ್ಚ, ವೆಚ್ಚ_list, ವೆಚ್ಚ_range, ವೆಚ್ಚ_bitmap, ವೆಚ್ಚ_bitmap_restart;

	/*
	 * Avoid unsigned overflows.
	 * The limits are high enough to avoid confusing the calculations.
	 */
	contig = MINIMUM(contig, 1ULL<<31);
	ಕೊನೆಯ_gap = MINIMUM(ಕೊನೆಯ_gap, 1ULL<<31);
	ಮುಂದಿನ_gap = MINIMUM(ಮುಂದಿನ_gap, 1ULL<<31);

	/*
	 * Calculate the cost to switch from the current state to candidates.
	 * NB. range sections only ever contain a single range, so their
	 * switching cost is independent of the current_state.
	 */
	ವೆಚ್ಚ_list = ವೆಚ್ಚ_bitmap = ವೆಚ್ಚ_bitmap_restart = 0;
	ವೆಚ್ಚ_range = 8;
	ಆಯ್ಕೆ (current_state) {
	ಸ್ಥಿತಿ KRL_SECTION_CERT_SERIAL_LIST:
		ವೆಚ್ಚ_bitmap_restart = ವೆಚ್ಚ_bitmap = 8 + 64;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KRL_SECTION_CERT_SERIAL_BITMAP:
		ವೆಚ್ಚ_list = 8;
		ವೆಚ್ಚ_bitmap_restart = 8 + 64;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KRL_SECTION_CERT_SERIAL_RANGE:
	ಸ್ಥಿತಿ 0:
		ವೆಚ್ಚ_bitmap_restart = ವೆಚ್ಚ_bitmap = 8 + 64;
		ವೆಚ್ಚ_list = 8;
	}

	/* Estimate base cost in bits of each section type */
	ವೆಚ್ಚ_list += 64 * contig + (final ? 0 : 8+64);
	ವೆಚ್ಚ_range += (2 * 64) + (final ? 0 : 8+64);
	ವೆಚ್ಚ_bitmap += ಕೊನೆಯ_gap + contig + (final ? 0 : MINIMUM(ಮುಂದಿನ_gap, 8+64));
	ವೆಚ್ಚ_bitmap_restart += contig + (final ? 0 : MINIMUM(ಮುಂದಿನ_gap, 8+64));

	/* Convert to byte costs for actual comparison */
	ವೆಚ್ಚ_list = (ವೆಚ್ಚ_list + 7) / 8;
	ವೆಚ್ಚ_bitmap = (ವೆಚ್ಚ_bitmap + 7) / 8;
	ವೆಚ್ಚ_bitmap_restart = (ವೆಚ್ಚ_bitmap_restart + 7) / 8;
	ವೆಚ್ಚ_range = (ವೆಚ್ಚ_range + 7) / 8;

	/* Ensure that we never emit a bitmap larger than sshbuf can handle */
	ಆದರೆ (bitmap_len + ವೆಚ್ಚ_bitmap >= SSHBUF_MAX_BIGNUM) {
		KRL_DBG(("bitmap overfull len=%zu cost=%llu max=%u",
		    bitmap_len, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ವೆಚ್ಚ_bitmap,
		    SSHBUF_MAX_BIGNUM));
		ವೆಚ್ಚ_bitmap = (uint64_t)-1;
	}

	/* Now pick the best choice */
	*force_new_section = 0;
	new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
	ವೆಚ್ಚ = ವೆಚ್ಚ_bitmap;
	ಆದರೆ (ವೆಚ್ಚ_range < ವೆಚ್ಚ) {
		new_state = KRL_SECTION_CERT_SERIAL_RANGE;
		ವೆಚ್ಚ = ವೆಚ್ಚ_range;
	}
	ಆದರೆ (ವೆಚ್ಚ_list < ವೆಚ್ಚ) {
		new_state = KRL_SECTION_CERT_SERIAL_LIST;
		ವೆಚ್ಚ = ವೆಚ್ಚ_list;
	}
	ಆದರೆ (ವೆಚ್ಚ_bitmap_restart < ವೆಚ್ಚ) {
		new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
		*force_new_section = 1;
		ವೆಚ್ಚ = ವೆಚ್ಚ_bitmap_restart;
	}
	KRL_DBG(("contig %llu last_gap %llu next_gap %llu final %d, costs:"
	    "list %llu range %llu bitmap %llu new bitmap %llu, "
	    "selected 0x%02x%s", (ದೀರ್ಘ ದೀರ್ಘ ಚಿಹ್ನೆರಹಿತ)contig,
	    (ದೀರ್ಘ ದೀರ್ಘ ಚಿಹ್ನೆರಹಿತ)ಕೊನೆಯ_gap, (ದೀರ್ಘ ದೀರ್ಘ ಚಿಹ್ನೆರಹಿತ)ಮುಂದಿನ_gap, final,
	    (ದೀರ್ಘ ದೀರ್ಘ ಚಿಹ್ನೆರಹಿತ)ವೆಚ್ಚ_list, (ದೀರ್ಘ ದೀರ್ಘ ಚಿಹ್ನೆರಹಿತ)ವೆಚ್ಚ_range,
	    (ದೀರ್ಘ ದೀರ್ಘ ಚಿಹ್ನೆರಹಿತ)ವೆಚ್ಚ_bitmap,
	    (ದೀರ್ಘ ದೀರ್ಘ ಚಿಹ್ನೆರಹಿತ)ವೆಚ್ಚ_bitmap_restart, new_state,
	    *force_new_section ? " restart" : ""));
	ಹಿಂತಿರುಗಿ new_state;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
put_bitmap(ರಚನೆ sshbuf *buf, ರಚನೆ bitmap *bitmap)
{
	ಗಾತ್ರ_t len;
	u_char *blob;
	ಪೂರ್ಣಾಂಕ r;

	len = bitmap_nbytes(bitmap);
	ಆದರೆ ((blob = ಸ್ಮರಣೆ_ಕೊಡು(len)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ (bitmap_ಗಮ್ಯ_string(bitmap, blob, len) != 0) {
		ಬಿಡುಗಡೆ(blob);
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	r = sshbuf_put_bignum2_ಬೈಟುಗಳು(buf, blob, len);
	ಬಿಡುಗಡೆ(blob);
	ಹಿಂತಿರುಗಿ r;
}

/* Generate a KRL_SECTION_CERTIFICATES KRL section */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
revoked_certs_generate(ರಚನೆ revoked_certs *rc, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ final, force_new_sect, r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	uint64_t i, contig, gap, ಕೊನೆಯ = 0, bitmap_ಆರಂಭ = 0;
	ರಚನೆ revoked_serial *rs, *nrs;
	ರಚನೆ revoked_ಕೀಲಿ_id *rki;
	ಪೂರ್ಣಾಂಕ ಮುಂದಿನ_state, state = 0;
	ಗಾತ್ರ_t bitmap_len;
	ರಚನೆ sshbuf *sect;
	ರಚನೆ bitmap *bitmap = ಖಾಲಿ;

	ಆದರೆ ((sect = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;

	/* Store the header: optional CA scope key, reserved */
	ಆದರೆ (rc->ca_ಕೀಲಿ == ಖಾಲಿ) {
		ಆದರೆ ((r = sshbuf_put_string(buf, ಖಾಲಿ, 0)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ ((r = sshkey_puts(rc->ca_ಕೀಲಿ, buf)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put_string(buf, ಖಾಲಿ, 0)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Store the revoked serials.  */
	ಗಾಗಿ (rs = RB_MIN(revoked_serial_ವೃಕ್ಷ, &rc->revoked_serials);
	     rs != ಖಾಲಿ;
	     rs = RB_ಮುಂದಿನ(revoked_serial_ವೃಕ್ಷ, &rc->revoked_serials, rs)) {
		KRL_DBG(("serial %llu:%llu state 0x%02x",
		    (ದೀರ್ಘ ದೀರ್ಘ ಚಿಹ್ನೆರಹಿತ)rs->lo, (ದೀರ್ಘ ದೀರ್ಘ ಚಿಹ್ನೆರಹಿತ)rs->hi,
		    state));

		/* Check contiguous length and gap to next section (if any) */
		nrs = RB_ಮುಂದಿನ(revoked_serial_ವೃಕ್ಷ, &rc->revoked_serials, rs);
		final = nrs == ಖಾಲಿ;
		gap = nrs == ಖಾಲಿ ? 0 : nrs->lo - rs->hi;
		contig = 1 + (rs->hi - rs->lo);

		bitmap_len = state == KRL_SECTION_CERT_SERIAL_BITMAP ?
		    bitmap_nbytes(bitmap) : 0;

		/* Choose next state based on these */
		ಮುಂದಿನ_state = ಆರಿಸು_ಮುಂದಿನ_state(state, contig, final,
		    state == 0 ? 0 : rs->lo - ಕೊನೆಯ, gap, bitmap_len,
		    &force_new_sect);

		/*
		 * If the current section is a range section or has a different
		 * type to the next section, then finish it off now.
		 */
		ಆದರೆ (state != 0 && (force_new_sect || ಮುಂದಿನ_state != state ||
		    state == KRL_SECTION_CERT_SERIAL_RANGE)) {
			KRL_DBG(("finish state 0x%02x", state));
			ಆಯ್ಕೆ (state) {
			ಸ್ಥಿತಿ KRL_SECTION_CERT_SERIAL_LIST:
			ಸ್ಥಿತಿ KRL_SECTION_CERT_SERIAL_RANGE:
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ KRL_SECTION_CERT_SERIAL_BITMAP:
				ಆದರೆ ((r = put_bitmap(sect, bitmap)) != 0)
					ಹೋಗು ಹೊರಹೋಗು;
				bitmap_free(bitmap);
				bitmap = ಖಾಲಿ;
				ನಿಲ್ಲಿಸು;
			}
			ಆದರೆ ((r = sshbuf_put_u8(buf, state)) != 0 ||
			    (r = sshbuf_put_stringb(buf, sect)) != 0)
				ಹೋಗು ಹೊರಹೋಗು;
			sshbuf_reset(sect);
		}

		/* If we are starting a new section then prepare it now */
		ಆದರೆ (ಮುಂದಿನ_state != state || force_new_sect) {
			KRL_DBG(("start state 0x%02x",
			    ಮುಂದಿನ_state));
			state = ಮುಂದಿನ_state;
			sshbuf_reset(sect);
			ಆಯ್ಕೆ (state) {
			ಸ್ಥಿತಿ KRL_SECTION_CERT_SERIAL_LIST:
			ಸ್ಥಿತಿ KRL_SECTION_CERT_SERIAL_RANGE:
				ನಿಲ್ಲಿಸು;
			ಸ್ಥಿತಿ KRL_SECTION_CERT_SERIAL_BITMAP:
				ಆದರೆ ((bitmap = bitmap_new()) == ಖಾಲಿ) {
					r = SSH_ERR_ALLOC_FAIL;
					ಹೋಗು ಹೊರಹೋಗು;
				}
				bitmap_ಆರಂಭ = rs->lo;
				ಆದರೆ ((r = sshbuf_put_u64(sect,
				    bitmap_ಆರಂಭ)) != 0)
					ಹೋಗು ಹೊರಹೋಗು;
				ನಿಲ್ಲಿಸು;
			}
		}

		/* Perform section-specific processing */
		ಆಯ್ಕೆ (state) {
		ಸ್ಥಿತಿ KRL_SECTION_CERT_SERIAL_LIST:
			ಗಾಗಿ (i = 0; i < contig; i++) {
				ಆದರೆ ((r = sshbuf_put_u64(sect, rs->lo + i)) != 0)
					ಹೋಗು ಹೊರಹೋಗು;
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ KRL_SECTION_CERT_SERIAL_RANGE:
			ಆದರೆ ((r = sshbuf_put_u64(sect, rs->lo)) != 0 ||
			    (r = sshbuf_put_u64(sect, rs->hi)) != 0)
				ಹೋಗು ಹೊರಹೋಗು;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ KRL_SECTION_CERT_SERIAL_BITMAP:
			ಆದರೆ (rs->lo - bitmap_ಆರಂಭ > ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ) {
				r = SSH_ERR_INVALID_FORMAT;
				error_f("insane bitmap gap");
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಗಾಗಿ (i = 0; i < contig; i++) {
				ಆದರೆ (bitmap_ಗಣ_ಬಿಟ್(bitmap,
				    rs->lo + i - bitmap_ಆರಂಭ) != 0) {
					r = SSH_ERR_ALLOC_FAIL;
					ಹೋಗು ಹೊರಹೋಗು;
				}
			}
			ನಿಲ್ಲಿಸು;
		}
		ಕೊನೆಯ = rs->hi;
	}
	/* Flush the remaining section, if any */
	ಆದರೆ (state != 0) {
		KRL_DBG(("serial final flush for state 0x%02x", state));
		ಆಯ್ಕೆ (state) {
		ಸ್ಥಿತಿ KRL_SECTION_CERT_SERIAL_LIST:
		ಸ್ಥಿತಿ KRL_SECTION_CERT_SERIAL_RANGE:
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ KRL_SECTION_CERT_SERIAL_BITMAP:
			ಆದರೆ ((r = put_bitmap(sect, bitmap)) != 0)
				ಹೋಗು ಹೊರಹೋಗು;
			bitmap_free(bitmap);
			bitmap = ಖಾಲಿ;
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ ((r = sshbuf_put_u8(buf, state)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	KRL_DBG(("serial done "));

	/* Now output a section for any revocations by key ID */
	sshbuf_reset(sect);
	RB_FOREACH(rki, revoked_ಕೀಲಿ_id_ವೃಕ್ಷ, &rc->revoked_ಕೀಲಿ_ids) {
		KRL_DBG(("key ID %s", rki->ಕೀಲಿ_id));
		ಆದರೆ ((r = sshbuf_put_cstring(sect, rki->ಕೀಲಿ_id)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshbuf_len(sect) != 0) {
		ಆದರೆ ((r = sshbuf_put_u8(buf, KRL_SECTION_CERT_ಕೀಲಿ_ID)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	r = 0;
 ಹೊರಹೋಗು:
	bitmap_free(bitmap);
	sshbuf_free(sect);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
ssh_krl_ಗಮ್ಯ_blob(ರಚನೆ ssh_krl *krl, ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ರಚನೆ revoked_certs *rc;
	ರಚನೆ revoked_blob *rb;
	ರಚನೆ sshbuf *sect;
	u_char *sblob = ಖಾಲಿ;

	ಆದರೆ (krl->generated_date == 0)
		krl->generated_date = time(ಖಾಲಿ);

	ಆದರೆ ((sect = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;

	/* Store the header */
	ಆದರೆ ((r = sshbuf_put(buf, KRL_MAGIC, ಗಾತ್ರ(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_put_u32(buf, KRL_FORMAT_ಆವೃತ್ತಿ)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->krl_ಆವೃತ್ತಿ)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->generated_date)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->flags)) != 0 ||
	    (r = sshbuf_put_string(buf, ಖಾಲಿ, 0)) != 0 ||
	    (r = sshbuf_put_cstring(buf, krl->comment)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Store sections for revoked certificates */
	TAILQ_FOREACH(rc, &krl->revoked_certs, ನಮೂದು) {
		sshbuf_reset(sect);
		ಆದರೆ ((r = revoked_certs_generate(rc, sect)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ಆದರೆ ((r = sshbuf_put_u8(buf, KRL_SECTION_CERTIFICATES)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Finally, output sections for revocations by public key/hash */
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_ವೃಕ್ಷ, &krl->revoked_ಕೀಲಿಗಳು) {
		KRL_DBG(("key len %zu ", rb->len));
		ಆದರೆ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshbuf_len(sect) != 0) {
		ಆದರೆ ((r = sshbuf_put_u8(buf, KRL_SECTION_EXPLICIT_ಕೀಲಿ)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_ವೃಕ್ಷ, &krl->revoked_sha1s) {
		KRL_DBG(("hash len %zu ", rb->len));
		ಆದರೆ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshbuf_len(sect) != 0) {
		ಆದರೆ ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA1)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_ವೃಕ್ಷ, &krl->revoked_sha256s) {
		KRL_DBG(("hash len %zu ", rb->len));
		ಆದರೆ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshbuf_len(sect) != 0) {
		ಆದರೆ ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA256)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(sblob);
	sshbuf_free(sect);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಶೂನ್ಯ
format_timestamp(uint64_t timestamp, ಅಕ್ಷರ *ts, ಗಾತ್ರ_t nts)
{
	time_t t;
	ರಚನೆ tm *tm;

	t = timestamp;
	tm = localtime(&t);
	ಆದರೆ (tm == ಖಾಲಿ)
		strlcpy(ts, "<INVALID>", nts);
	ಇಲ್ಲದಿದ್ದರೆ {
		*ts = '\0';
		strftime(ts, nts, "%Y%m%dT%H%M%S", tm);
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
cert_extension_subsection(ರಚನೆ sshbuf *subsect, ರಚನೆ ssh_krl *krl)
{
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	u_char critical = 1;
	ರಚನೆ sshbuf *ಮೌಲ್ಯ = ಖಾಲಿ;
	ಅಕ್ಷರ *name = ಖಾಲಿ;

	ಆದರೆ ((r = sshbuf_get_cstring(subsect, &name, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_u8(subsect, &critical)) != 0 ||
	    (r = sshbuf_froms(subsect, &ಮೌಲ್ಯ)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid certificate extension subsection");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshbuf_len(subsect) != 0) {
		error("KRL has invalid certificate extension subsection: "
		    "trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	debug_f("cert extension %s critical %u len %zu",
	    name, critical, sshbuf_len(ಮೌಲ್ಯ));
	/* no extensions are currently supported */
	ಆದರೆ (critical) {
		error("KRL contains unsupported critical certificate "
		    "subsection \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(name);
	sshbuf_free(ಮೌಲ್ಯ);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_revoked_certs(ರಚನೆ sshbuf *buf, ರಚನೆ ssh_krl *krl)
{
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	u_char type;
	ಸ್ಥಿರಾಂಕ u_char *blob;
	ಗಾತ್ರ_t blen, nbits;
	ರಚನೆ sshbuf *subsect = ಖಾಲಿ;
	uint64_t serial, serial_lo, serial_hi;
	ರಚನೆ bitmap *bitmap = ಖಾಲಿ;
	ಅಕ್ಷರ *ಕೀಲಿ_id = ಖಾಲಿ;
	ರಚನೆ sshkey *ca_ಕೀಲಿ = ಖಾಲಿ;

	ಆದರೆ ((subsect = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;

	/* Header: key, reserved */
	ಆದರೆ ((r = sshbuf_get_string_ನೇರ(buf, &blob, &blen)) != 0 ||
	    (r = sshbuf_skip_string(buf)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (blen != 0 && (r = sshkey_from_blob(blob, blen, &ca_ಕೀಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆಗ (sshbuf_len(buf) > 0) {
		sshbuf_free(subsect);
		subsect = ಖಾಲಿ;
		ಆದರೆ ((r = sshbuf_get_u8(buf, &type)) != 0 ||
		    (r = sshbuf_froms(buf, &subsect)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		KRL_DBG(("subsection type 0x%02x", type));
		/* sshbuf_dump(subsect, stderr); */

		ಆಯ್ಕೆ (type) {
		ಸ್ಥಿತಿ KRL_SECTION_CERT_SERIAL_LIST:
			ಆಗ (sshbuf_len(subsect) > 0) {
				ಆದರೆ ((r = sshbuf_get_u64(subsect, &serial)) != 0)
					ಹೋಗು ಹೊರಹೋಗು;
				ಆದರೆ ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_ಕೀಲಿ, serial)) != 0)
					ಹೋಗು ಹೊರಹೋಗು;
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ KRL_SECTION_CERT_SERIAL_RANGE:
			ಆದರೆ ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_u64(subsect, &serial_hi)) != 0)
				ಹೋಗು ಹೊರಹೋಗು;
			ಆದರೆ ((r = ssh_krl_revoke_cert_by_serial_range(krl,
			    ca_ಕೀಲಿ, serial_lo, serial_hi)) != 0)
				ಹೋಗು ಹೊರಹೋಗು;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ KRL_SECTION_CERT_SERIAL_BITMAP:
			ಆದರೆ ((bitmap = bitmap_new()) == ಖಾಲಿ) {
				r = SSH_ERR_ALLOC_FAIL;
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಆದರೆ ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_bignum2_ಬೈಟುಗಳು_ನೇರ(subsect,
			    &blob, &blen)) != 0)
				ಹೋಗು ಹೊರಹೋಗು;
			ಆದರೆ (bitmap_from_string(bitmap, blob, blen) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				ಹೋಗು ಹೊರಹೋಗು;
			}
			nbits = bitmap_nbits(bitmap);
			ಗಾಗಿ (serial = 0; serial < (uint64_t)nbits; serial++) {
				ಆದರೆ (serial > 0 && serial_lo + serial == 0) {
					error_f("bitmap wraps u64");
					r = SSH_ERR_INVALID_FORMAT;
					ಹೋಗು ಹೊರಹೋಗು;
				}
				ಆದರೆ (!bitmap_test_ಬಿಟ್(bitmap, serial))
					ಮುಂದುವರಿ;
				ಆದರೆ ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_ಕೀಲಿ, serial_lo + serial)) != 0)
					ಹೋಗು ಹೊರಹೋಗು;
			}
			bitmap_free(bitmap);
			bitmap = ಖಾಲಿ;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ KRL_SECTION_CERT_ಕೀಲಿ_ID:
			ಆಗ (sshbuf_len(subsect) > 0) {
				ಆದರೆ ((r = sshbuf_get_cstring(subsect,
				    &ಕೀಲಿ_id, ಖಾಲಿ)) != 0)
					ಹೋಗು ಹೊರಹೋಗು;
				ಆದರೆ ((r = ssh_krl_revoke_cert_by_ಕೀಲಿ_id(krl,
				    ca_ಕೀಲಿ, ಕೀಲಿ_id)) != 0)
					ಹೋಗು ಹೊರಹೋಗು;
				ಬಿಡುಗಡೆ(ಕೀಲಿ_id);
				ಕೀಲಿ_id = ಖಾಲಿ;
			}
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ KRL_SECTION_CERT_EXTENSION:
			ಆದರೆ ((r = cert_extension_subsection(subsect, krl)) != 0)
				ಹೋಗು ಹೊರಹೋಗು;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			error("Unsupported KRL certificate section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (sshbuf_len(subsect) > 0) {
			error("KRL certificate section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}

	r = 0;
 ಹೊರಹೋಗು:
	ಆದರೆ (bitmap != ಖಾಲಿ)
		bitmap_free(bitmap);
	ಬಿಡುಗಡೆ(ಕೀಲಿ_id);
	sshkey_free(ca_ಕೀಲಿ);
	sshbuf_free(subsect);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
blob_section(ರಚನೆ sshbuf *sect, ರಚನೆ revoked_blob_ವೃಕ್ಷ *ಗುರಿ_ವೃಕ್ಷ,
    ಗಾತ್ರ_t expected_len)
{
	u_char *rdata = ಖಾಲಿ;
	ಗಾತ್ರ_t rlen = 0;
	ಪೂರ್ಣಾಂಕ r;

	ಆಗ (sshbuf_len(sect) > 0) {
		ಆದರೆ ((r = sshbuf_get_string(sect, &rdata, &rlen)) != 0)
			ಹಿಂತಿರುಗಿ r;
		ಆದರೆ (expected_len != 0 && rlen != expected_len) {
			error_f("bad length");
			ಬಿಡುಗಡೆ(rdata);
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
		}
		ಆದರೆ ((r = revoke_blob(ಗುರಿ_ವೃಕ್ಷ, rdata, rlen)) != 0) {
			ಬಿಡುಗಡೆ(rdata);
			ಹಿಂತಿರುಗಿ r;
		}
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
extension_section(ರಚನೆ sshbuf *sect, ರಚನೆ ssh_krl *krl)
{
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	u_char critical = 1;
	ರಚನೆ sshbuf *ಮೌಲ್ಯ = ಖಾಲಿ;
	ಅಕ್ಷರ *name = ಖಾಲಿ;

	ಆದರೆ ((r = sshbuf_get_cstring(sect, &name, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_u8(sect, &critical)) != 0 ||
	    (r = sshbuf_froms(sect, &ಮೌಲ್ಯ)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid extension section");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshbuf_len(sect) != 0) {
		error("KRL has invalid extension section: trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	debug_f("extension %s critical %u len %zu",
	    name, critical, sshbuf_len(ಮೌಲ್ಯ));
	/* no extensions are currently supported */
	ಆದರೆ (critical) {
		error("KRL contains unsupported critical section \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(name);
	sshbuf_free(ಮೌಲ್ಯ);
	ಹಿಂತಿರುಗಿ r;
}

/* Attempt to parse a KRL */
ಪೂರ್ಣಾಂಕ
ssh_krl_from_blob(ರಚನೆ sshbuf *buf, ರಚನೆ ssh_krl **krlp)
{
	ರಚನೆ sshbuf *copy = ಖಾಲಿ, *sect = ಖಾಲಿ;
	ರಚನೆ ssh_krl *krl = ಖಾಲಿ;
	ಅಕ್ಷರ timestamp[64];
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	u_char type;
	u_int format_ಆವೃತ್ತಿ;

	*krlp = ಖಾಲಿ;

	/* KRL must begin with magic string */
	ಆದರೆ ((r = sshbuf_cmp(buf, 0, KRL_MAGIC, ಗಾತ್ರ(KRL_MAGIC) - 1)) != 0) {
		debug2_f("bad KRL magic header");
		ಹಿಂತಿರುಗಿ SSH_ERR_KRL_BAD_MAGIC;
	}

	ಆದರೆ ((krl = ssh_krl_init()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		error_f("alloc failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* Don't modify buffer */
	ಆದರೆ ((copy = sshbuf_fromb(buf)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_consume(copy, ಗಾತ್ರ(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_get_u32(copy, &format_ಆವೃತ್ತಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (format_ಆವೃತ್ತಿ != KRL_FORMAT_ಆವೃತ್ತಿ) {
		error_f("unsupported KRL format version %u", format_ಆವೃತ್ತಿ);
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_get_u64(copy, &krl->krl_ಆವೃತ್ತಿ)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->generated_date)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->flags)) != 0 ||
	    (r = sshbuf_skip_string(copy)) != 0 ||
	    (r = sshbuf_get_cstring(copy, &krl->comment, ಖಾಲಿ)) != 0) {
		error_fr(r, "parse KRL header");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	format_timestamp(krl->generated_date, timestamp, ಗಾತ್ರ(timestamp));
	debug("KRL version %llu generated at %s%s%s",
	    (ದೀರ್ಘ ದೀರ್ಘ ಚಿಹ್ನೆರಹಿತ)krl->krl_ಆವೃತ್ತಿ, timestamp,
	    *krl->comment ? ": " : "", krl->comment);

	/* Parse and load the KRL sections. */
	ಆಗ (sshbuf_len(copy) > 0) {
		sshbuf_free(sect);
		sect = ಖಾಲಿ;
		ಆದರೆ ((r = sshbuf_get_u8(copy, &type)) != 0 ||
		    (r = sshbuf_froms(copy, &sect)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		KRL_DBG(("section 0x%02x", type));

		ಆಯ್ಕೆ (type) {
		ಸ್ಥಿತಿ KRL_SECTION_CERTIFICATES:
			ಆದರೆ ((r = parse_revoked_certs(sect, krl)) != 0)
				ಹೋಗು ಹೊರಹೋಗು;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ KRL_SECTION_EXPLICIT_ಕೀಲಿ:
			ಆದರೆ ((r = blob_section(sect,
			    &krl->revoked_ಕೀಲಿಗಳು, 0)) != 0)
				ಹೋಗು ಹೊರಹೋಗು;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ KRL_SECTION_FINGERPRINT_SHA1:
			ಆದರೆ ((r = blob_section(sect,
			    &krl->revoked_sha1s, 20)) != 0)
				ಹೋಗು ಹೊರಹೋಗು;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ KRL_SECTION_FINGERPRINT_SHA256:
			ಆದರೆ ((r = blob_section(sect,
			    &krl->revoked_sha256s, 32)) != 0)
				ಹೋಗು ಹೊರಹೋಗು;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ KRL_SECTION_EXTENSION:
			ಆದರೆ ((r = extension_section(sect, krl)) != 0)
				ಹೋಗು ಹೊರಹೋಗು;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ KRL_SECTION_SIGNATURE:
			/* Handled above, but still need to stay in synch */
			sshbuf_free(sect);
			sect = ಖಾಲಿ;
			ಆದರೆ ((r = sshbuf_skip_string(copy)) != 0)
				ಹೋಗು ಹೊರಹೋಗು;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			error("Unsupported KRL section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (sect != ಖಾಲಿ && sshbuf_len(sect) > 0) {
			error("KRL section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}

	/* Success */
	*krlp = krl;
	r = 0;
 ಹೊರಹೋಗು:
	ಆದರೆ (r != 0)
		ssh_krl_free(krl);
	sshbuf_free(copy);
	sshbuf_free(sect);
	ಹಿಂತಿರುಗಿ r;
}

/* Checks certificate serial number and key ID revocation */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
is_cert_revoked(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ revoked_certs *rc)
{
	ರಚನೆ revoked_serial rs, *ers;
	ರಚನೆ revoked_ಕೀಲಿ_id rki, *erki;

	/* Check revocation by cert key ID */
	memset(&rki, 0, ಗಾತ್ರ(rki));
	rki.ಕೀಲಿ_id = ಕೀಲಿ->cert->ಕೀಲಿ_id;
	erki = RB_ಕಂಡುಹಿಡಿ(revoked_ಕೀಲಿ_id_ವೃಕ್ಷ, &rc->revoked_ಕೀಲಿ_ids, &rki);
	ಆದರೆ (erki != ಖಾಲಿ) {
		KRL_DBG(("revoked by key ID"));
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_REVOKED;
	}

	/*
	 * Zero serials numbers are ignored (it's the default when the
	 * CA doesn't specify one).
	 */
	ಆದರೆ (ಕೀಲಿ->cert->serial == 0)
		ಹಿಂತಿರುಗಿ 0;

	memset(&rs, 0, ಗಾತ್ರ(rs));
	rs.lo = rs.hi = ಕೀಲಿ->cert->serial;
	ers = RB_ಕಂಡುಹಿಡಿ(revoked_serial_ವೃಕ್ಷ, &rc->revoked_serials, &rs);
	ಆದರೆ (ers != ಖಾಲಿ) {
		KRL_DBG(("revoked serial %llu matched %llu:%llu",
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಕೀಲಿ->cert->serial,
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ers->lo,
		    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ers->hi));
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_REVOKED;
	}
	ಹಿಂತಿರುಗಿ 0;
}

/* Checks whether a given key/cert is revoked. Does not check its CA */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
is_ಕೀಲಿ_revoked(ರಚನೆ ssh_krl *krl, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ)
{
	ರಚನೆ revoked_blob rb, *erb;
	ರಚನೆ revoked_certs *rc;
	ಪೂರ್ಣಾಂಕ r;

	/* Check explicitly revoked hashes first */
	memset(&rb, 0, ಗಾತ್ರ(rb));
	ಆದರೆ ((r = sshkey_fingerprint_raw(ಕೀಲಿ, SSH_DIGEST_SHA1,
	    &rb.blob, &rb.len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	erb = RB_ಕಂಡುಹಿಡಿ(revoked_blob_ವೃಕ್ಷ, &krl->revoked_sha1s, &rb);
	ಬಿಡುಗಡೆ(rb.blob);
	ಆದರೆ (erb != ಖಾಲಿ) {
		KRL_DBG(("revoked by key SHA1"));
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_REVOKED;
	}
	memset(&rb, 0, ಗಾತ್ರ(rb));
	ಆದರೆ ((r = sshkey_fingerprint_raw(ಕೀಲಿ, SSH_DIGEST_SHA256,
	    &rb.blob, &rb.len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	erb = RB_ಕಂಡುಹಿಡಿ(revoked_blob_ವೃಕ್ಷ, &krl->revoked_sha256s, &rb);
	ಬಿಡುಗಡೆ(rb.blob);
	ಆದರೆ (erb != ಖಾಲಿ) {
		KRL_DBG(("revoked by key SHA256"));
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_REVOKED;
	}

	/* Next, explicit keys */
	memset(&rb, 0, ಗಾತ್ರ(rb));
	ಆದರೆ ((r = plain_ಕೀಲಿ_blob(ಕೀಲಿ, &rb.blob, &rb.len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	erb = RB_ಕಂಡುಹಿಡಿ(revoked_blob_ವೃಕ್ಷ, &krl->revoked_ಕೀಲಿಗಳು, &rb);
	ಬಿಡುಗಡೆ(rb.blob);
	ಆದರೆ (erb != ಖಾಲಿ) {
		KRL_DBG(("revoked by explicit key"));
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_REVOKED;
	}

	ಆದರೆ (!sshkey_is_cert(ಕೀಲಿ))
		ಹಿಂತಿರುಗಿ 0;

	/* Check cert revocation for the specified CA */
	ಆದರೆ ((r = revoked_certs_for_ca_ಕೀಲಿ(krl, ಕೀಲಿ->cert->signature_ಕೀಲಿ,
	    &rc, 0)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (rc != ಖಾಲಿ) {
		ಆದರೆ ((r = is_cert_revoked(ಕೀಲಿ, rc)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	/* Check cert revocation for the wildcard CA */
	ಆದರೆ ((r = revoked_certs_for_ca_ಕೀಲಿ(krl, ಖಾಲಿ, &rc, 0)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (rc != ಖಾಲಿ) {
		ಆದರೆ ((r = is_cert_revoked(ಕೀಲಿ, rc)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}

	KRL_DBG(("%llu no match", (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)ಕೀಲಿ->cert->serial));
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
ssh_krl_check_ಕೀಲಿ(ರಚನೆ ssh_krl *krl, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಂಕ r;

	KRL_DBG(("checking key"));
	ಆದರೆ ((r = is_ಕೀಲಿ_revoked(krl, ಕೀಲಿ)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (sshkey_is_cert(ಕೀಲಿ)) {
		debug2_f("checking CA key");
		ಆದರೆ ((r = is_ಕೀಲಿ_revoked(krl, ಕೀಲಿ->cert->signature_ಕೀಲಿ)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	KRL_DBG(("key okay"));
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
ssh_krl_file_ಒಳಗೊಂಡಿದೆ_ಕೀಲಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ)
{
	ರಚನೆ sshbuf *krlbuf = ಖಾಲಿ;
	ರಚನೆ ssh_krl *krl = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ oerrno = 0, r;

	ಆದರೆ (ಮಾರ್ಗ == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ ((r = sshbuf_ತುಂಬು_file(ಮಾರ್ಗ, &krlbuf)) != 0) {
		oerrno = errno;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = ssh_krl_from_blob(krlbuf, &krl)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	debug2_f("checking KRL %s", ಮಾರ್ಗ);
	r = ssh_krl_check_ಕೀಲಿ(krl, ಕೀಲಿ);
 ಹೊರಹೋಗು:
	sshbuf_free(krlbuf);
	ssh_krl_free(krl);
	ಆದರೆ (r != 0)
		errno = oerrno;
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
krl_dump(ರಚನೆ ssh_krl *krl, FILE *f)
{
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ರಚನೆ revoked_blob *rb;
	ರಚನೆ revoked_certs *rc;
	ರಚನೆ revoked_serial *rs;
	ರಚನೆ revoked_ಕೀಲಿ_id *rki;
	ಪೂರ್ಣಾಂಕ r, ret = 0;
	ಅಕ್ಷರ *fp, timestamp[64];

	/* Try to print in a KRL spec-compatible format */
	format_timestamp(krl->generated_date, timestamp, ಗಾತ್ರ(timestamp));
	fprintf(f, "# KRL version %llu\n", (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)krl->krl_ಆವೃತ್ತಿ);
	fprintf(f, "# Generated at %s\n", timestamp);
	ಆದರೆ (krl->comment != ಖಾಲಿ && *krl->comment != '\0') {
		r = ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ;
		asmprintf(&fp, ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ, &r, "%s", krl->comment);
		fprintf(f, "# Comment: %s\n", fp);
		ಬಿಡುಗಡೆ(fp);
	}
	fputc('\n', f);

	RB_FOREACH(rb, revoked_blob_ವೃಕ್ಷ, &krl->revoked_ಕೀಲಿಗಳು) {
		ಆದರೆ ((r = sshkey_from_blob(rb->blob, rb->len, &ಕೀಲಿ)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			error_r(r, "parse KRL key");
			ಮುಂದುವರಿ;
		}
		ಆದರೆ ((fp = sshkey_fingerprint(ಕೀಲಿ, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ಖಾಲಿ) {
			ret = SSH_ERR_INVALID_FORMAT;
			error("sshkey_fingerprint failed");
			ಮುಂದುವರಿ;
		}
		fprintf(f, "hash: %s # %s\n", fp, sshkey_ssh_name(ಕೀಲಿ));
		ಬಿಡುಗಡೆ(fp);
		ಬಿಡುಗಡೆ(ಕೀಲಿ);
	}
	RB_FOREACH(rb, revoked_blob_ವೃಕ್ಷ, &krl->revoked_sha256s) {
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "hash: SHA256:%s\n", fp);
		ಬಿಡುಗಡೆ(fp);
	}
	RB_FOREACH(rb, revoked_blob_ವೃಕ್ಷ, &krl->revoked_sha1s) {
		/*
		 * There is not KRL spec keyword for raw SHA1 hashes, so
		 * print them as comments.
		 */
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "# hash SHA1:%s\n", fp);
		ಬಿಡುಗಡೆ(fp);
	}

	TAILQ_FOREACH(rc, &krl->revoked_certs, ನಮೂದು) {
		fputc('\n', f);
		ಆದರೆ (rc->ca_ಕೀಲಿ == ಖಾಲಿ)
			fprintf(f, "# Wildcard CA\n");
		ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ ((fp = sshkey_fingerprint(rc->ca_ಕೀಲಿ,
			    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ಖಾಲಿ) {
				ret = SSH_ERR_INVALID_FORMAT;
				error("sshkey_fingerprint failed");
				ಮುಂದುವರಿ;
			}
			fprintf(f, "# CA key %s %s\n",
			    sshkey_ssh_name(rc->ca_ಕೀಲಿ), fp);
			ಬಿಡುಗಡೆ(fp);
		}
		RB_FOREACH(rs, revoked_serial_ವೃಕ್ಷ, &rc->revoked_serials) {
			ಆದರೆ (rs->lo == rs->hi) {
				fprintf(f, "serial: %llu\n",
				    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)rs->lo);
			} ಇಲ್ಲದಿದ್ದರೆ {
				fprintf(f, "serial: %llu-%llu\n",
				    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)rs->lo,
				    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)rs->hi);
			}
		}
		RB_FOREACH(rki, revoked_ಕೀಲಿ_id_ವೃಕ್ಷ, &rc->revoked_ಕೀಲಿ_ids) {
			/*
			 * We don't want key IDs with embedded newlines to
			 * mess up the display.
			 */
			r = ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ;
			asmprintf(&fp, ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ, &r, "%s", rki->ಕೀಲಿ_id);
			fprintf(f, "id: %s\n", fp);
			ಬಿಡುಗಡೆ(fp);
		}
	}
	ಹಿಂತಿರುಗಿ ret;
}
