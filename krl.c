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
#ifdef DEBUG_KRL
# define KRL_DBG(x) debug3_f x
#ಅನ್ಯಥಾ
# define KRL_DBG(x)
#endif

/*
 * Trees of revoked serial numbers, key IDs and keys. This allows
 * quick searching, querying and producing lists in canonical order.
 */

/* Tree of serial numbers. XXX make smarter: really need a real sparse bitmap */
ಸಂರಚನಾ revoked_serial {
	uint64_t lo, hi;
	RB_ENTRY(revoked_serial) ವೃಕ್ಷ_entry;
};
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ serial_cmp(ಸಂರಚನಾ revoked_serial *a, ಸಂರಚನಾ revoked_serial *b);
RB_HEAD(revoked_serial_ವೃಕ್ಷ, revoked_serial);
RB_GENERATE_STATIC(revoked_serial_ವೃಕ್ಷ, revoked_serial, ವೃಕ್ಷ_entry, serial_cmp)

/* Tree of key IDs */
ಸಂರಚನಾ revoked_ಕೀಲಿ_id {
	ವರ್ಣ *ಕೀಲಿ_id;
	RB_ENTRY(revoked_ಕೀಲಿ_id) ವೃಕ್ಷ_entry;
};
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಕೀಲಿ_id_cmp(ಸಂರಚನಾ revoked_ಕೀಲಿ_id *a, ಸಂರಚನಾ revoked_ಕೀಲಿ_id *b);
RB_HEAD(revoked_ಕೀಲಿ_id_ವೃಕ್ಷ, revoked_ಕೀಲಿ_id);
RB_GENERATE_STATIC(revoked_ಕೀಲಿ_id_ವೃಕ್ಷ, revoked_ಕೀಲಿ_id, ವೃಕ್ಷ_entry, ಕೀಲಿ_id_cmp)

/* Tree of blobs (used for keys and fingerprints) */
ಸಂರಚನಾ revoked_blob {
	u_char *blob;
	size_t len;
	RB_ENTRY(revoked_blob) ವೃಕ್ಷ_entry;
};
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ blob_cmp(ಸಂರಚನಾ revoked_blob *a, ಸಂರಚನಾ revoked_blob *b);
RB_HEAD(revoked_blob_ವೃಕ್ಷ, revoked_blob);
RB_GENERATE_STATIC(revoked_blob_ವೃಕ್ಷ, revoked_blob, ವೃಕ್ಷ_entry, blob_cmp)

/* Tracks revoked certs for a single CA */
ಸಂರಚನಾ revoked_certs {
	ಸಂರಚನಾ sshkey *ca_ಕೀಲಿ;
	ಸಂರಚನಾ revoked_serial_ವೃಕ್ಷ revoked_serials;
	ಸಂರಚನಾ revoked_ಕೀಲಿ_id_ವೃಕ್ಷ revoked_ಕೀಲಿ_ids;
	TAILQ_ENTRY(revoked_certs) entry;
};
TAILQ_HEAD(revoked_certs_list, revoked_certs);

ಸಂರಚನಾ ssh_krl {
	uint64_t krl_version;
	uint64_t generated_date;
	uint64_t flags;
	ವರ್ಣ *comment;
	ಸಂರಚನಾ revoked_blob_ವೃಕ್ಷ revoked_ಕೀಲಿಗಳು;
	ಸಂರಚನಾ revoked_blob_ವೃಕ್ಷ revoked_sha1s;
	ಸಂರಚನಾ revoked_blob_ವೃಕ್ಷ revoked_sha256s;
	ಸಂರಚನಾ revoked_certs_list revoked_certs;
};

/* Return equal if a and b overlap */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
serial_cmp(ಸಂರಚನಾ revoked_serial *a, ಸಂರಚನಾ revoked_serial *b)
{
	ಯದಿ (a->hi >= b->lo && a->lo <= b->hi)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ a->lo < b->lo ? -1 : 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಕೀಲಿ_id_cmp(ಸಂರಚನಾ revoked_ಕೀಲಿ_id *a, ಸಂರಚನಾ revoked_ಕೀಲಿ_id *b)
{
	ಪ್ರತ್ಯಾಗಮ strcmp(a->ಕೀಲಿ_id, b->ಕೀಲಿ_id);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
blob_cmp(ಸಂರಚನಾ revoked_blob *a, ಸಂರಚನಾ revoked_blob *b)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (a->len != b->len) {
		ಯದಿ ((r = memcmp(a->blob, b->blob, MINIMUM(a->len, b->len))) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
		ಪ್ರತ್ಯಾಗಮ a->len > b->len ? 1 : -1;
	} ಅನ್ಯಥಾ
		ಪ್ರತ್ಯಾಗಮ memcmp(a->blob, b->blob, a->len);
}

ಸಂರಚನಾ ssh_krl *
ssh_krl_init(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ ssh_krl *krl;

	ಯದಿ ((krl = calloc(1, ಪರಿಮಾಣ(*krl))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	RB_INIT(&krl->revoked_ಕೀಲಿಗಳು);
	RB_INIT(&krl->revoked_sha1s);
	RB_INIT(&krl->revoked_sha256s);
	TAILQ_INIT(&krl->revoked_certs);
	ಪ್ರತ್ಯಾಗಮ krl;
}

ಸ್ಥಿರ ಶೂನ್ಯ
revoked_certs_free(ಸಂರಚನಾ revoked_certs *rc)
{
	ಸಂರಚನಾ revoked_serial *rs, *trs;
	ಸಂರಚನಾ revoked_ಕೀಲಿ_id *rki, *trki;

	ಯದಿ (rc == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	RB_FOREACH_SAFE(rs, revoked_serial_ವೃಕ್ಷ, &rc->revoked_serials, trs) {
		RB_REMOVE(revoked_serial_ವೃಕ್ಷ, &rc->revoked_serials, rs);
		ಮುಕ್ತ(rs);
	}
	RB_FOREACH_SAFE(rki, revoked_ಕೀಲಿ_id_ವೃಕ್ಷ, &rc->revoked_ಕೀಲಿ_ids, trki) {
		RB_REMOVE(revoked_ಕೀಲಿ_id_ವೃಕ್ಷ, &rc->revoked_ಕೀಲಿ_ids, rki);
		ಮುಕ್ತ(rki->ಕೀಲಿ_id);
		ಮುಕ್ತ(rki);
	}
	sshkey_free(rc->ca_ಕೀಲಿ);
	freezero(rc, ಪರಿಮಾಣ(*rc));
}

ಶೂನ್ಯ
ssh_krl_free(ಸಂರಚನಾ ssh_krl *krl)
{
	ಸಂರಚನಾ revoked_blob *rb, *trb;
	ಸಂರಚನಾ revoked_certs *rc, *trc;

	ಯದಿ (krl == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;

	ಮುಕ್ತ(krl->comment);
	RB_FOREACH_SAFE(rb, revoked_blob_ವೃಕ್ಷ, &krl->revoked_ಕೀಲಿಗಳು, trb) {
		RB_REMOVE(revoked_blob_ವೃಕ್ಷ, &krl->revoked_ಕೀಲಿಗಳು, rb);
		ಮುಕ್ತ(rb->blob);
		ಮುಕ್ತ(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_ವೃಕ್ಷ, &krl->revoked_sha1s, trb) {
		RB_REMOVE(revoked_blob_ವೃಕ್ಷ, &krl->revoked_sha1s, rb);
		ಮುಕ್ತ(rb->blob);
		ಮುಕ್ತ(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_ವೃಕ್ಷ, &krl->revoked_sha256s, trb) {
		RB_REMOVE(revoked_blob_ವೃಕ್ಷ, &krl->revoked_sha256s, rb);
		ಮುಕ್ತ(rb->blob);
		ಮುಕ್ತ(rb);
	}
	TAILQ_FOREACH_SAFE(rc, &krl->revoked_certs, entry, trc) {
		TAILQ_REMOVE(&krl->revoked_certs, rc, entry);
		revoked_certs_free(rc);
	}
	ಮುಕ್ತ(krl);
}

ಶೂನ್ಯ
ssh_krl_set_version(ಸಂರಚನಾ ssh_krl *krl, uint64_t version)
{
	krl->krl_version = version;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_krl_set_comment(ಸಂರಚನಾ ssh_krl *krl, ಧ್ರುವ ವರ್ಣ *comment)
{
	ಮುಕ್ತ(krl->comment);
	ಯದಿ ((krl->comment = strdup(comment)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Find the revoked_certs struct for a CA key. If allow_create is set then
 * create a new one in the tree if one did not exist already.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
revoked_certs_for_ca_ಕೀಲಿ(ಸಂರಚನಾ ssh_krl *krl, ಧ್ರುವ ಸಂರಚನಾ sshkey *ca_ಕೀಲಿ,
    ಸಂರಚನಾ revoked_certs **rcp, ಪೂರ್ಣಾಙ್ಕ allow_create)
{
	ಸಂರಚನಾ revoked_certs *rc;
	ಪೂರ್ಣಾಙ್ಕ r;

	*rcp = ರಿಕ್ತ;
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		ಯದಿ ((ca_ಕೀಲಿ == ರಿಕ್ತ && rc->ca_ಕೀಲಿ == ರಿಕ್ತ) ||
		    sshkey_equal(rc->ca_ಕೀಲಿ, ca_ಕೀಲಿ)) {
			*rcp = rc;
			ಪ್ರತ್ಯಾಗಮ 0;
		}
	}
	ಯದಿ (!allow_create)
		ಪ್ರತ್ಯಾಗಮ 0;
	/* If this CA doesn't exist in the list then add it now */
	ಯದಿ ((rc = calloc(1, ಪರಿಮಾಣ(*rc))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ (ca_ಕೀಲಿ == ರಿಕ್ತ)
		rc->ca_ಕೀಲಿ = ರಿಕ್ತ;
	ಅನ್ಯಥಾ ಯದಿ ((r = sshkey_from_private(ca_ಕೀಲಿ, &rc->ca_ಕೀಲಿ)) != 0) {
		ಮುಕ್ತ(rc);
		ಪ್ರತ್ಯಾಗಮ r;
	}
	RB_INIT(&rc->revoked_serials);
	RB_INIT(&rc->revoked_ಕೀಲಿ_ids);
	TAILQ_INSERT_TAIL(&krl->revoked_certs, rc, entry);
	KRL_DBG(("new CA %s", ca_ಕೀಲಿ == ರಿಕ್ತ ? "*" : sshkey_type(ca_ಕೀಲಿ)));
	*rcp = rc;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಸೇರಿಸು_serial_range(ಸಂರಚನಾ revoked_serial_ವೃಕ್ಷ *rt, uint64_t lo, uint64_t hi)
{
	ಸಂರಚನಾ revoked_serial rs, *ers, *crs, *irs;

	KRL_DBG(("insert %llu:%llu",
	    (unsigned long long)lo, (unsigned long long)hi));
	memset(&rs, 0, ಪರಿಮಾಣ(rs));
	rs.lo = lo;
	rs.hi = hi;
	ers = RB_NFIND(revoked_serial_ವೃಕ್ಷ, rt, &rs);
	ಯದಿ (ers == ರಿಕ್ತ || serial_cmp(ers, &rs) != 0) {
		/* No entry matches. Just insert */
		ಯದಿ ((irs = malloc(ಪರಿಮಾಣ(rs))) == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
		memcpy(irs, &rs, ಪರಿಮಾಣ(*irs));
		ers = RB_ಸೇರಿಸು(revoked_serial_ವೃಕ್ಷ, rt, irs);
		ಯದಿ (ers != ರಿಕ್ತ) {
			KRL_DBG(("bad: ers != NULL"));
			/* Shouldn't happen */
			ಮುಕ್ತ(irs);
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
		}
		ers = irs;
	} ಅನ್ಯಥಾ {
		KRL_DBG(("overlap found %llu:%llu",
		    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
		/*
		 * The inserted entry overlaps an existing one. Grow the
		 * existing entry.
		 */
		ಯದಿ (ers->lo > lo)
			ers->lo = lo;
		ಯದಿ (ers->hi < hi)
			ers->hi = hi;
	}

	/*
	 * The inserted or revised range might overlap or abut adjacent ones;
	 * coalesce as necessary.
	 */

	/* Check predecessors */
	ಯಾವತ್ ((crs = RB_PREV(revoked_serial_ವೃಕ್ಷ, rt, ers)) != ರಿಕ್ತ) {
		KRL_DBG(("pred %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		ಯದಿ (ers->lo != 0 && crs->hi < ers->lo - 1)
			ಭಙ್ಗ;
		/* This entry overlaps. */
		ಯದಿ (crs->lo < ers->lo) {
			ers->lo = crs->lo;
			KRL_DBG(("pred extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_ವೃಕ್ಷ, rt, crs);
		ಮುಕ್ತ(crs);
	}
	/* Check successors */
	ಯಾವತ್ ((crs = RB_NEXT(revoked_serial_ವೃಕ್ಷ, rt, ers)) != ರಿಕ್ತ) {
		KRL_DBG(("succ %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		ಯದಿ (ers->hi != (uint64_t)-1 && crs->lo > ers->hi + 1)
			ಭಙ್ಗ;
		/* This entry overlaps. */
		ಯದಿ (crs->hi > ers->hi) {
			ers->hi = crs->hi;
			KRL_DBG(("succ extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_ವೃಕ್ಷ, rt, crs);
		ಮುಕ್ತ(crs);
	}
	KRL_DBG(("done, final %llu:%llu",
	    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_krl_revoke_cert_by_serial(ಸಂರಚನಾ ssh_krl *krl, ಧ್ರುವ ಸಂರಚನಾ sshkey *ca_ಕೀಲಿ,
    uint64_t serial)
{
	ಪ್ರತ್ಯಾಗಮ ssh_krl_revoke_cert_by_serial_range(krl, ca_ಕೀಲಿ, serial, serial);
}

ಪೂರ್ಣಾಙ್ಕ
ssh_krl_revoke_cert_by_serial_range(ಸಂರಚನಾ ssh_krl *krl,
    ಧ್ರುವ ಸಂರಚನಾ sshkey *ca_ಕೀಲಿ, uint64_t lo, uint64_t hi)
{
	ಸಂರಚನಾ revoked_certs *rc;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (lo > hi || lo == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ ((r = revoked_certs_for_ca_ಕೀಲಿ(krl, ca_ಕೀಲಿ, &rc, 1)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಪ್ರತ್ಯಾಗಮ ಸೇರಿಸು_serial_range(&rc->revoked_serials, lo, hi);
}

ಪೂರ್ಣಾಙ್ಕ
ssh_krl_revoke_cert_by_ಕೀಲಿ_id(ಸಂರಚನಾ ssh_krl *krl, ಧ್ರುವ ಸಂರಚನಾ sshkey *ca_ಕೀಲಿ,
    ಧ್ರುವ ವರ್ಣ *ಕೀಲಿ_id)
{
	ಸಂರಚನಾ revoked_ಕೀಲಿ_id *rki, *erki;
	ಸಂರಚನಾ revoked_certs *rc;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = revoked_certs_for_ca_ಕೀಲಿ(krl, ca_ಕೀಲಿ, &rc, 1)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	KRL_DBG(("revoke %s", ಕೀಲಿ_id));
	ಯದಿ ((rki = calloc(1, ಪರಿಮಾಣ(*rki))) == ರಿಕ್ತ ||
	    (rki->ಕೀಲಿ_id = strdup(ಕೀಲಿ_id)) == ರಿಕ್ತ) {
		ಮುಕ್ತ(rki);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	}
	erki = RB_ಸೇರಿಸು(revoked_ಕೀಲಿ_id_ವೃಕ್ಷ, &rc->revoked_ಕೀಲಿ_ids, rki);
	ಯದಿ (erki != ರಿಕ್ತ) {
		ಮುಕ್ತ(rki->ಕೀಲಿ_id);
		ಮುಕ್ತ(rki);
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Convert "key" to a public key blob without any certificate information */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
plain_ಕೀಲಿ_blob(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, u_char **blob, size_t *blen)
{
	ಸಂರಚನಾ sshkey *kcopy;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshkey_from_private(ಕೀಲಿ, &kcopy)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (sshkey_is_cert(kcopy)) {
		ಯದಿ ((r = sshkey_drop_cert(kcopy)) != 0) {
			sshkey_free(kcopy);
			ಪ್ರತ್ಯಾಗಮ r;
		}
	}
	r = sshkey_to_blob(kcopy, blob, blen);
	sshkey_free(kcopy);
	ಪ್ರತ್ಯಾಗಮ r;
}

/* Revoke a key blob. Ownership of blob is transferred to the tree */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
revoke_blob(ಸಂರಚನಾ revoked_blob_ವೃಕ್ಷ *rbt, u_char *blob, size_t len)
{
	ಸಂರಚನಾ revoked_blob *rb, *erb;

	ಯದಿ ((rb = calloc(1, ಪರಿಮಾಣ(*rb))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	rb->blob = blob;
	rb->len = len;
	erb = RB_ಸೇರಿಸು(revoked_blob_ವೃಕ್ಷ, rbt, rb);
	ಯದಿ (erb != ರಿಕ್ತ) {
		ಮುಕ್ತ(rb->blob);
		ಮುಕ್ತ(rb);
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_krl_revoke_ಕೀಲಿ_explicit(ಸಂರಚನಾ ssh_krl *krl, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	u_char *blob;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("revoke type %s", sshkey_type(ಕೀಲಿ));
	ಯದಿ ((r = plain_ಕೀಲಿ_blob(ಕೀಲಿ, &blob, &len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಪ್ರತ್ಯಾಗಮ revoke_blob(&krl->revoked_ಕೀಲಿಗಳು, blob, len);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
revoke_by_hash(ಸಂರಚನಾ revoked_blob_ವೃಕ್ಷ *target, ಧ್ರುವ u_char *p, size_t len)
{
	u_char *blob;
	ಪೂರ್ಣಾಙ್ಕ r;

	/* need to copy hash, as revoke_blob steals ownership */
	ಯದಿ ((blob = malloc(len)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
	memcpy(blob, p, len);
	ಯದಿ ((r = revoke_blob(target, blob, len)) != 0) {
		ಮುಕ್ತ(blob);
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_krl_revoke_ಕೀಲಿ_sha1(ಸಂರಚನಾ ssh_krl *krl, ಧ್ರುವ u_char *p, size_t len)
{
	debug3_f("revoke by sha1");
	ಯದಿ (len != 20)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	ಪ್ರತ್ಯಾಗಮ revoke_by_hash(&krl->revoked_sha1s, p, len);
}

ಪೂರ್ಣಾಙ್ಕ
ssh_krl_revoke_ಕೀಲಿ_sha256(ಸಂರಚನಾ ssh_krl *krl, ಧ್ರುವ u_char *p, size_t len)
{
	debug3_f("revoke by sha256");
	ಯದಿ (len != 32)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	ಪ್ರತ್ಯಾಗಮ revoke_by_hash(&krl->revoked_sha256s, p, len);
}

ಪೂರ್ಣಾಙ್ಕ
ssh_krl_revoke_ಕೀಲಿ(ಸಂರಚನಾ ssh_krl *krl, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	/* XXX replace with SHA256? */
	ಯದಿ (!sshkey_is_cert(ಕೀಲಿ))
		ಪ್ರತ್ಯಾಗಮ ssh_krl_revoke_ಕೀಲಿ_explicit(krl, ಕೀಲಿ);

	ಯದಿ (ಕೀಲಿ->cert->serial == 0) {
		ಪ್ರತ್ಯಾಗಮ ssh_krl_revoke_cert_by_ಕೀಲಿ_id(krl,
		    ಕೀಲಿ->cert->signature_ಕೀಲಿ,
		    ಕೀಲಿ->cert->ಕೀಲಿ_id);
	} ಅನ್ಯಥಾ {
		ಪ್ರತ್ಯಾಗಮ ssh_krl_revoke_cert_by_serial(krl,
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
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
choose_next_state(ಪೂರ್ಣಾಙ್ಕ current_state, uint64_t contig, ಪೂರ್ಣಾಙ್ಕ final,
    uint64_t last_gap, uint64_t next_gap, size_t bitmap_len,
    ಪೂರ್ಣಾಙ್ಕ *force_new_section)
{
	ಪೂರ್ಣಾಙ್ಕ new_state;
	uint64_t cost, cost_list, cost_range, cost_bitmap, cost_bitmap_restart;

	/*
	 * Avoid unsigned overflows.
	 * The limits are high enough to avoid confusing the calculations.
	 */
	contig = MINIMUM(contig, 1ULL<<31);
	last_gap = MINIMUM(last_gap, 1ULL<<31);
	next_gap = MINIMUM(next_gap, 1ULL<<31);

	/*
	 * Calculate the cost to switch from the current state to candidates.
	 * NB. range sections only ever contain a single range, so their
	 * switching cost is independent of the current_state.
	 */
	cost_list = cost_bitmap = cost_bitmap_restart = 0;
	cost_range = 8;
	ವಿಕಲ್ಪ (current_state) {
	ಪಕ್ಷ KRL_SECTION_CERT_SERIAL_LIST:
		cost_bitmap_restart = cost_bitmap = 8 + 64;
		ಭಙ್ಗ;
	ಪಕ್ಷ KRL_SECTION_CERT_SERIAL_BITMAP:
		cost_list = 8;
		cost_bitmap_restart = 8 + 64;
		ಭಙ್ಗ;
	ಪಕ್ಷ KRL_SECTION_CERT_SERIAL_RANGE:
	ಪಕ್ಷ 0:
		cost_bitmap_restart = cost_bitmap = 8 + 64;
		cost_list = 8;
	}

	/* Estimate base cost in bits of each section type */
	cost_list += 64 * contig + (final ? 0 : 8+64);
	cost_range += (2 * 64) + (final ? 0 : 8+64);
	cost_bitmap += last_gap + contig + (final ? 0 : MINIMUM(next_gap, 8+64));
	cost_bitmap_restart += contig + (final ? 0 : MINIMUM(next_gap, 8+64));

	/* Convert to byte costs for actual comparison */
	cost_list = (cost_list + 7) / 8;
	cost_bitmap = (cost_bitmap + 7) / 8;
	cost_bitmap_restart = (cost_bitmap_restart + 7) / 8;
	cost_range = (cost_range + 7) / 8;

	/* Ensure that we never emit a bitmap larger than sshbuf can handle */
	ಯದಿ (bitmap_len + cost_bitmap >= SSHBUF_MAX_BIGNUM) {
		KRL_DBG(("bitmap overfull len=%zu cost=%llu max=%u",
		    bitmap_len, (unsigned long long)cost_bitmap,
		    SSHBUF_MAX_BIGNUM));
		cost_bitmap = (uint64_t)-1;
	}

	/* Now pick the best choice */
	*force_new_section = 0;
	new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
	cost = cost_bitmap;
	ಯದಿ (cost_range < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_RANGE;
		cost = cost_range;
	}
	ಯದಿ (cost_list < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_LIST;
		cost = cost_list;
	}
	ಯದಿ (cost_bitmap_restart < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
		*force_new_section = 1;
		cost = cost_bitmap_restart;
	}
	KRL_DBG(("contig %llu last_gap %llu next_gap %llu final %d, costs:"
	    "list %llu range %llu bitmap %llu new bitmap %llu, "
	    "selected 0x%02x%s", (long long unsigned)contig,
	    (long long unsigned)last_gap, (long long unsigned)next_gap, final,
	    (long long unsigned)cost_list, (long long unsigned)cost_range,
	    (long long unsigned)cost_bitmap,
	    (long long unsigned)cost_bitmap_restart, new_state,
	    *force_new_section ? " restart" : ""));
	ಪ್ರತ್ಯಾಗಮ new_state;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
put_bitmap(ಸಂರಚನಾ sshbuf *buf, ಸಂರಚನಾ bitmap *bitmap)
{
	size_t len;
	u_char *blob;
	ಪೂರ್ಣಾಙ್ಕ r;

	len = bitmap_nbytes(bitmap);
	ಯದಿ ((blob = malloc(len)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ (bitmap_to_string(bitmap, blob, len) != 0) {
		ಮುಕ್ತ(blob);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	}
	r = sshbuf_put_bignum2_bytes(buf, blob, len);
	ಮುಕ್ತ(blob);
	ಪ್ರತ್ಯಾಗಮ r;
}

/* Generate a KRL_SECTION_CERTIFICATES KRL section */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
revoked_certs_generate(ಸಂರಚನಾ revoked_certs *rc, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ final, force_new_sect, r = SSH_ERR_INTERNAL_ERROR;
	uint64_t i, contig, gap, last = 0, bitmap_start = 0;
	ಸಂರಚನಾ revoked_serial *rs, *nrs;
	ಸಂರಚನಾ revoked_ಕೀಲಿ_id *rki;
	ಪೂರ್ಣಾಙ್ಕ next_state, state = 0;
	size_t bitmap_len;
	ಸಂರಚನಾ sshbuf *sect;
	ಸಂರಚನಾ bitmap *bitmap = ರಿಕ್ತ;

	ಯದಿ ((sect = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;

	/* Store the header: optional CA scope key, reserved */
	ಯದಿ (rc->ca_ಕೀಲಿ == ರಿಕ್ತ) {
		ಯದಿ ((r = sshbuf_put_string(buf, ರಿಕ್ತ, 0)) != 0)
			ಗಚ್ಛ out;
	} ಅನ್ಯಥಾ {
		ಯದಿ ((r = sshkey_puts(rc->ca_ಕೀಲಿ, buf)) != 0)
			ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put_string(buf, ರಿಕ್ತ, 0)) != 0)
		ಗಚ್ಛ out;

	/* Store the revoked serials.  */
	ಪ್ರತಿ (rs = RB_MIN(revoked_serial_ವೃಕ್ಷ, &rc->revoked_serials);
	     rs != ರಿಕ್ತ;
	     rs = RB_NEXT(revoked_serial_ವೃಕ್ಷ, &rc->revoked_serials, rs)) {
		KRL_DBG(("serial %llu:%llu state 0x%02x",
		    (long long unsigned)rs->lo, (long long unsigned)rs->hi,
		    state));

		/* Check contiguous length and gap to next section (if any) */
		nrs = RB_NEXT(revoked_serial_ವೃಕ್ಷ, &rc->revoked_serials, rs);
		final = nrs == ರಿಕ್ತ;
		gap = nrs == ರಿಕ್ತ ? 0 : nrs->lo - rs->hi;
		contig = 1 + (rs->hi - rs->lo);

		bitmap_len = state == KRL_SECTION_CERT_SERIAL_BITMAP ?
		    bitmap_nbytes(bitmap) : 0;

		/* Choose next state based on these */
		next_state = choose_next_state(state, contig, final,
		    state == 0 ? 0 : rs->lo - last, gap, bitmap_len,
		    &force_new_sect);

		/*
		 * If the current section is a range section or has a different
		 * type to the next section, then finish it off now.
		 */
		ಯದಿ (state != 0 && (force_new_sect || next_state != state ||
		    state == KRL_SECTION_CERT_SERIAL_RANGE)) {
			KRL_DBG(("finish state 0x%02x", state));
			ವಿಕಲ್ಪ (state) {
			ಪಕ್ಷ KRL_SECTION_CERT_SERIAL_LIST:
			ಪಕ್ಷ KRL_SECTION_CERT_SERIAL_RANGE:
				ಭಙ್ಗ;
			ಪಕ್ಷ KRL_SECTION_CERT_SERIAL_BITMAP:
				ಯದಿ ((r = put_bitmap(sect, bitmap)) != 0)
					ಗಚ್ಛ out;
				bitmap_free(bitmap);
				bitmap = ರಿಕ್ತ;
				ಭಙ್ಗ;
			}
			ಯದಿ ((r = sshbuf_put_u8(buf, state)) != 0 ||
			    (r = sshbuf_put_stringb(buf, sect)) != 0)
				ಗಚ್ಛ out;
			sshbuf_reset(sect);
		}

		/* If we are starting a new section then prepare it now */
		ಯದಿ (next_state != state || force_new_sect) {
			KRL_DBG(("start state 0x%02x",
			    next_state));
			state = next_state;
			sshbuf_reset(sect);
			ವಿಕಲ್ಪ (state) {
			ಪಕ್ಷ KRL_SECTION_CERT_SERIAL_LIST:
			ಪಕ್ಷ KRL_SECTION_CERT_SERIAL_RANGE:
				ಭಙ್ಗ;
			ಪಕ್ಷ KRL_SECTION_CERT_SERIAL_BITMAP:
				ಯದಿ ((bitmap = bitmap_new()) == ರಿಕ್ತ) {
					r = SSH_ERR_ALLOC_FAIL;
					ಗಚ್ಛ out;
				}
				bitmap_start = rs->lo;
				ಯದಿ ((r = sshbuf_put_u64(sect,
				    bitmap_start)) != 0)
					ಗಚ್ಛ out;
				ಭಙ್ಗ;
			}
		}

		/* Perform section-specific processing */
		ವಿಕಲ್ಪ (state) {
		ಪಕ್ಷ KRL_SECTION_CERT_SERIAL_LIST:
			ಪ್ರತಿ (i = 0; i < contig; i++) {
				ಯದಿ ((r = sshbuf_put_u64(sect, rs->lo + i)) != 0)
					ಗಚ್ಛ out;
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ KRL_SECTION_CERT_SERIAL_RANGE:
			ಯದಿ ((r = sshbuf_put_u64(sect, rs->lo)) != 0 ||
			    (r = sshbuf_put_u64(sect, rs->hi)) != 0)
				ಗಚ್ಛ out;
			ಭಙ್ಗ;
		ಪಕ್ಷ KRL_SECTION_CERT_SERIAL_BITMAP:
			ಯದಿ (rs->lo - bitmap_start > INT_MAX) {
				r = SSH_ERR_INVALID_FORMAT;
				error_f("insane bitmap gap");
				ಗಚ್ಛ out;
			}
			ಪ್ರತಿ (i = 0; i < contig; i++) {
				ಯದಿ (bitmap_set_bit(bitmap,
				    rs->lo + i - bitmap_start) != 0) {
					r = SSH_ERR_ALLOC_FAIL;
					ಗಚ್ಛ out;
				}
			}
			ಭಙ್ಗ;
		}
		last = rs->hi;
	}
	/* Flush the remaining section, if any */
	ಯದಿ (state != 0) {
		KRL_DBG(("serial final flush for state 0x%02x", state));
		ವಿಕಲ್ಪ (state) {
		ಪಕ್ಷ KRL_SECTION_CERT_SERIAL_LIST:
		ಪಕ್ಷ KRL_SECTION_CERT_SERIAL_RANGE:
			ಭಙ್ಗ;
		ಪಕ್ಷ KRL_SECTION_CERT_SERIAL_BITMAP:
			ಯದಿ ((r = put_bitmap(sect, bitmap)) != 0)
				ಗಚ್ಛ out;
			bitmap_free(bitmap);
			bitmap = ರಿಕ್ತ;
			ಭಙ್ಗ;
		}
		ಯದಿ ((r = sshbuf_put_u8(buf, state)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ಗಚ್ಛ out;
	}
	KRL_DBG(("serial done "));

	/* Now output a section for any revocations by key ID */
	sshbuf_reset(sect);
	RB_FOREACH(rki, revoked_ಕೀಲಿ_id_ವೃಕ್ಷ, &rc->revoked_ಕೀಲಿ_ids) {
		KRL_DBG(("key ID %s", rki->ಕೀಲಿ_id));
		ಯದಿ ((r = sshbuf_put_cstring(sect, rki->ಕೀಲಿ_id)) != 0)
			ಗಚ್ಛ out;
	}
	ಯದಿ (sshbuf_len(sect) != 0) {
		ಯದಿ ((r = sshbuf_put_u8(buf, KRL_SECTION_CERT_ಕೀಲಿ_ID)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ಗಚ್ಛ out;
	}
	r = 0;
 out:
	bitmap_free(bitmap);
	sshbuf_free(sect);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_krl_to_blob(ಸಂರಚನಾ ssh_krl *krl, ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	ಸಂರಚನಾ revoked_certs *rc;
	ಸಂರಚನಾ revoked_blob *rb;
	ಸಂರಚನಾ sshbuf *sect;
	u_char *sblob = ರಿಕ್ತ;

	ಯದಿ (krl->generated_date == 0)
		krl->generated_date = time(ರಿಕ್ತ);

	ಯದಿ ((sect = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;

	/* Store the header */
	ಯದಿ ((r = sshbuf_put(buf, KRL_MAGIC, ಪರಿಮಾಣ(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_put_u32(buf, KRL_FORMAT_VERSION)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->krl_version)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->generated_date)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->flags)) != 0 ||
	    (r = sshbuf_put_string(buf, ರಿಕ್ತ, 0)) != 0 ||
	    (r = sshbuf_put_cstring(buf, krl->comment)) != 0)
		ಗಚ್ಛ out;

	/* Store sections for revoked certificates */
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		sshbuf_reset(sect);
		ಯದಿ ((r = revoked_certs_generate(rc, sect)) != 0)
			ಗಚ್ಛ out;
		ಯದಿ ((r = sshbuf_put_u8(buf, KRL_SECTION_CERTIFICATES)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ಗಚ್ಛ out;
	}

	/* Finally, output sections for revocations by public key/hash */
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_ವೃಕ್ಷ, &krl->revoked_ಕೀಲಿಗಳು) {
		KRL_DBG(("key len %zu ", rb->len));
		ಯದಿ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			ಗಚ್ಛ out;
	}
	ಯದಿ (sshbuf_len(sect) != 0) {
		ಯದಿ ((r = sshbuf_put_u8(buf, KRL_SECTION_EXPLICIT_ಕೀಲಿ)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ಗಚ್ಛ out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_ವೃಕ್ಷ, &krl->revoked_sha1s) {
		KRL_DBG(("hash len %zu ", rb->len));
		ಯದಿ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			ಗಚ್ಛ out;
	}
	ಯದಿ (sshbuf_len(sect) != 0) {
		ಯದಿ ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA1)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ಗಚ್ಛ out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_ವೃಕ್ಷ, &krl->revoked_sha256s) {
		KRL_DBG(("hash len %zu ", rb->len));
		ಯದಿ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			ಗಚ್ಛ out;
	}
	ಯದಿ (sshbuf_len(sect) != 0) {
		ಯದಿ ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA256)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ಗಚ್ಛ out;
	}
	/* success */
	r = 0;
 out:
	ಮುಕ್ತ(sblob);
	sshbuf_free(sect);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಶೂನ್ಯ
format_timestamp(uint64_t timestamp, ವರ್ಣ *ts, size_t nts)
{
	time_t t;
	ಸಂರಚನಾ tm *tm;

	t = timestamp;
	tm = localtime(&t);
	ಯದಿ (tm == ರಿಕ್ತ)
		strlcpy(ts, "<INVALID>", nts);
	ಅನ್ಯಥಾ {
		*ts = '\0';
		strftime(ts, nts, "%Y%m%dT%H%M%S", tm);
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
cert_extension_subsection(ಸಂರಚನಾ sshbuf *subsect, ಸಂರಚನಾ ssh_krl *krl)
{
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	ಸಂರಚನಾ sshbuf *ಮೌಲ್ಯ = ರಿಕ್ತ;
	ವರ್ಣ *name = ರಿಕ್ತ;

	ಯದಿ ((r = sshbuf_get_cstring(subsect, &name, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_u8(subsect, &critical)) != 0 ||
	    (r = sshbuf_froms(subsect, &ಮೌಲ್ಯ)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid certificate extension subsection");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (sshbuf_len(subsect) != 0) {
		error("KRL has invalid certificate extension subsection: "
		    "trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	debug_f("cert extension %s critical %u len %zu",
	    name, critical, sshbuf_len(ಮೌಲ್ಯ));
	/* no extensions are currently supported */
	ಯದಿ (critical) {
		error("KRL contains unsupported critical certificate "
		    "subsection \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		ಗಚ್ಛ out;
	}
	/* success */
	r = 0;
 out:
	ಮುಕ್ತ(name);
	sshbuf_free(ಮೌಲ್ಯ);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_revoked_certs(ಸಂರಚನಾ sshbuf *buf, ಸಂರಚನಾ ssh_krl *krl)
{
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	ಧ್ರುವ u_char *blob;
	size_t blen, nbits;
	ಸಂರಚನಾ sshbuf *subsect = ರಿಕ್ತ;
	uint64_t serial, serial_lo, serial_hi;
	ಸಂರಚನಾ bitmap *bitmap = ರಿಕ್ತ;
	ವರ್ಣ *ಕೀಲಿ_id = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *ca_ಕೀಲಿ = ರಿಕ್ತ;

	ಯದಿ ((subsect = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;

	/* Header: key, reserved */
	ಯದಿ ((r = sshbuf_get_string_direct(buf, &blob, &blen)) != 0 ||
	    (r = sshbuf_skip_string(buf)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (blen != 0 && (r = sshkey_from_blob(blob, blen, &ca_ಕೀಲಿ)) != 0)
		ಗಚ್ಛ out;

	ಯಾವತ್ (sshbuf_len(buf) > 0) {
		sshbuf_free(subsect);
		subsect = ರಿಕ್ತ;
		ಯದಿ ((r = sshbuf_get_u8(buf, &type)) != 0 ||
		    (r = sshbuf_froms(buf, &subsect)) != 0)
			ಗಚ್ಛ out;
		KRL_DBG(("subsection type 0x%02x", type));
		/* sshbuf_dump(subsect, stderr); */

		ವಿಕಲ್ಪ (type) {
		ಪಕ್ಷ KRL_SECTION_CERT_SERIAL_LIST:
			ಯಾವತ್ (sshbuf_len(subsect) > 0) {
				ಯದಿ ((r = sshbuf_get_u64(subsect, &serial)) != 0)
					ಗಚ್ಛ out;
				ಯದಿ ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_ಕೀಲಿ, serial)) != 0)
					ಗಚ್ಛ out;
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ KRL_SECTION_CERT_SERIAL_RANGE:
			ಯದಿ ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_u64(subsect, &serial_hi)) != 0)
				ಗಚ್ಛ out;
			ಯದಿ ((r = ssh_krl_revoke_cert_by_serial_range(krl,
			    ca_ಕೀಲಿ, serial_lo, serial_hi)) != 0)
				ಗಚ್ಛ out;
			ಭಙ್ಗ;
		ಪಕ್ಷ KRL_SECTION_CERT_SERIAL_BITMAP:
			ಯದಿ ((bitmap = bitmap_new()) == ರಿಕ್ತ) {
				r = SSH_ERR_ALLOC_FAIL;
				ಗಚ್ಛ out;
			}
			ಯದಿ ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_bignum2_bytes_direct(subsect,
			    &blob, &blen)) != 0)
				ಗಚ್ಛ out;
			ಯದಿ (bitmap_from_string(bitmap, blob, blen) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				ಗಚ್ಛ out;
			}
			nbits = bitmap_nbits(bitmap);
			ಪ್ರತಿ (serial = 0; serial < (uint64_t)nbits; serial++) {
				ಯದಿ (serial > 0 && serial_lo + serial == 0) {
					error_f("bitmap wraps u64");
					r = SSH_ERR_INVALID_FORMAT;
					ಗಚ್ಛ out;
				}
				ಯದಿ (!bitmap_test_bit(bitmap, serial))
					ಅನುವರ್ತ;
				ಯದಿ ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_ಕೀಲಿ, serial_lo + serial)) != 0)
					ಗಚ್ಛ out;
			}
			bitmap_free(bitmap);
			bitmap = ರಿಕ್ತ;
			ಭಙ್ಗ;
		ಪಕ್ಷ KRL_SECTION_CERT_ಕೀಲಿ_ID:
			ಯಾವತ್ (sshbuf_len(subsect) > 0) {
				ಯದಿ ((r = sshbuf_get_cstring(subsect,
				    &ಕೀಲಿ_id, ರಿಕ್ತ)) != 0)
					ಗಚ್ಛ out;
				ಯದಿ ((r = ssh_krl_revoke_cert_by_ಕೀಲಿ_id(krl,
				    ca_ಕೀಲಿ, ಕೀಲಿ_id)) != 0)
					ಗಚ್ಛ out;
				ಮುಕ್ತ(ಕೀಲಿ_id);
				ಕೀಲಿ_id = ರಿಕ್ತ;
			}
			ಭಙ್ಗ;
		ಪಕ್ಷ KRL_SECTION_CERT_EXTENSION:
			ಯದಿ ((r = cert_extension_subsection(subsect, krl)) != 0)
				ಗಚ್ಛ out;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			error("Unsupported KRL certificate section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
		ಯದಿ (sshbuf_len(subsect) > 0) {
			error("KRL certificate section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
	}

	r = 0;
 out:
	ಯದಿ (bitmap != ರಿಕ್ತ)
		bitmap_free(bitmap);
	ಮುಕ್ತ(ಕೀಲಿ_id);
	sshkey_free(ca_ಕೀಲಿ);
	sshbuf_free(subsect);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
blob_section(ಸಂರಚನಾ sshbuf *sect, ಸಂರಚನಾ revoked_blob_ವೃಕ್ಷ *target_ವೃಕ್ಷ,
    size_t expected_len)
{
	u_char *rdata = ರಿಕ್ತ;
	size_t rlen = 0;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯಾವತ್ (sshbuf_len(sect) > 0) {
		ಯದಿ ((r = sshbuf_get_string(sect, &rdata, &rlen)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
		ಯದಿ (expected_len != 0 && rlen != expected_len) {
			error_f("bad length");
			ಮುಕ್ತ(rdata);
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
		}
		ಯದಿ ((r = revoke_blob(target_ವೃಕ್ಷ, rdata, rlen)) != 0) {
			ಮುಕ್ತ(rdata);
			ಪ್ರತ್ಯಾಗಮ r;
		}
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
extension_section(ಸಂರಚನಾ sshbuf *sect, ಸಂರಚನಾ ssh_krl *krl)
{
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	ಸಂರಚನಾ sshbuf *ಮೌಲ್ಯ = ರಿಕ್ತ;
	ವರ್ಣ *name = ರಿಕ್ತ;

	ಯದಿ ((r = sshbuf_get_cstring(sect, &name, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_u8(sect, &critical)) != 0 ||
	    (r = sshbuf_froms(sect, &ಮೌಲ್ಯ)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid extension section");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (sshbuf_len(sect) != 0) {
		error("KRL has invalid extension section: trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	debug_f("extension %s critical %u len %zu",
	    name, critical, sshbuf_len(ಮೌಲ್ಯ));
	/* no extensions are currently supported */
	ಯದಿ (critical) {
		error("KRL contains unsupported critical section \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		ಗಚ್ಛ out;
	}
	/* success */
	r = 0;
 out:
	ಮುಕ್ತ(name);
	sshbuf_free(ಮೌಲ್ಯ);
	ಪ್ರತ್ಯಾಗಮ r;
}

/* Attempt to parse a KRL */
ಪೂರ್ಣಾಙ್ಕ
ssh_krl_from_blob(ಸಂರಚನಾ sshbuf *buf, ಸಂರಚನಾ ssh_krl **krlp)
{
	ಸಂರಚನಾ sshbuf *copy = ರಿಕ್ತ, *sect = ರಿಕ್ತ;
	ಸಂರಚನಾ ssh_krl *krl = ರಿಕ್ತ;
	ವರ್ಣ timestamp[64];
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	u_int format_version;

	*krlp = ರಿಕ್ತ;

	/* KRL must begin with magic string */
	ಯದಿ ((r = sshbuf_cmp(buf, 0, KRL_MAGIC, ಪರಿಮಾಣ(KRL_MAGIC) - 1)) != 0) {
		debug2_f("bad KRL magic header");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_KRL_BAD_MAGIC;
	}

	ಯದಿ ((krl = ssh_krl_init()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		error_f("alloc failed");
		ಗಚ್ಛ out;
	}
	/* Don't modify buffer */
	ಯದಿ ((copy = sshbuf_fromb(buf)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_consume(copy, ಪರಿಮಾಣ(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_get_u32(copy, &format_version)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (format_version != KRL_FORMAT_VERSION) {
		error_f("unsupported KRL format version %u", format_version);
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_get_u64(copy, &krl->krl_version)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->generated_date)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->flags)) != 0 ||
	    (r = sshbuf_skip_string(copy)) != 0 ||
	    (r = sshbuf_get_cstring(copy, &krl->comment, ರಿಕ್ತ)) != 0) {
		error_fr(r, "parse KRL header");
		ಗಚ್ಛ out;
	}
	format_timestamp(krl->generated_date, timestamp, ಪರಿಮಾಣ(timestamp));
	debug("KRL version %llu generated at %s%s%s",
	    (long long unsigned)krl->krl_version, timestamp,
	    *krl->comment ? ": " : "", krl->comment);

	/* Parse and load the KRL sections. */
	ಯಾವತ್ (sshbuf_len(copy) > 0) {
		sshbuf_free(sect);
		sect = ರಿಕ್ತ;
		ಯದಿ ((r = sshbuf_get_u8(copy, &type)) != 0 ||
		    (r = sshbuf_froms(copy, &sect)) != 0)
			ಗಚ್ಛ out;
		KRL_DBG(("section 0x%02x", type));

		ವಿಕಲ್ಪ (type) {
		ಪಕ್ಷ KRL_SECTION_CERTIFICATES:
			ಯದಿ ((r = parse_revoked_certs(sect, krl)) != 0)
				ಗಚ್ಛ out;
			ಭಙ್ಗ;
		ಪಕ್ಷ KRL_SECTION_EXPLICIT_ಕೀಲಿ:
			ಯದಿ ((r = blob_section(sect,
			    &krl->revoked_ಕೀಲಿಗಳು, 0)) != 0)
				ಗಚ್ಛ out;
			ಭಙ್ಗ;
		ಪಕ್ಷ KRL_SECTION_FINGERPRINT_SHA1:
			ಯದಿ ((r = blob_section(sect,
			    &krl->revoked_sha1s, 20)) != 0)
				ಗಚ್ಛ out;
			ಭಙ್ಗ;
		ಪಕ್ಷ KRL_SECTION_FINGERPRINT_SHA256:
			ಯದಿ ((r = blob_section(sect,
			    &krl->revoked_sha256s, 32)) != 0)
				ಗಚ್ಛ out;
			ಭಙ್ಗ;
		ಪಕ್ಷ KRL_SECTION_EXTENSION:
			ಯದಿ ((r = extension_section(sect, krl)) != 0)
				ಗಚ್ಛ out;
			ಭಙ್ಗ;
		ಪಕ್ಷ KRL_SECTION_SIGNATURE:
			/* Handled above, but still need to stay in synch */
			sshbuf_free(sect);
			sect = ರಿಕ್ತ;
			ಯದಿ ((r = sshbuf_skip_string(copy)) != 0)
				ಗಚ್ಛ out;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			error("Unsupported KRL section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
		ಯದಿ (sect != ರಿಕ್ತ && sshbuf_len(sect) > 0) {
			error("KRL section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
	}

	/* Success */
	*krlp = krl;
	r = 0;
 out:
	ಯದಿ (r != 0)
		ssh_krl_free(krl);
	sshbuf_free(copy);
	sshbuf_free(sect);
	ಪ್ರತ್ಯಾಗಮ r;
}

/* Checks certificate serial number and key ID revocation */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
is_cert_revoked(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ revoked_certs *rc)
{
	ಸಂರಚನಾ revoked_serial rs, *ers;
	ಸಂರಚನಾ revoked_ಕೀಲಿ_id rki, *erki;

	/* Check revocation by cert key ID */
	memset(&rki, 0, ಪರಿಮಾಣ(rki));
	rki.ಕೀಲಿ_id = ಕೀಲಿ->cert->ಕೀಲಿ_id;
	erki = RB_FIND(revoked_ಕೀಲಿ_id_ವೃಕ್ಷ, &rc->revoked_ಕೀಲಿ_ids, &rki);
	ಯದಿ (erki != ರಿಕ್ತ) {
		KRL_DBG(("revoked by key ID"));
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_REVOKED;
	}

	/*
	 * Zero serials numbers are ignored (it's the default when the
	 * CA doesn't specify one).
	 */
	ಯದಿ (ಕೀಲಿ->cert->serial == 0)
		ಪ್ರತ್ಯಾಗಮ 0;

	memset(&rs, 0, ಪರಿಮಾಣ(rs));
	rs.lo = rs.hi = ಕೀಲಿ->cert->serial;
	ers = RB_FIND(revoked_serial_ವೃಕ್ಷ, &rc->revoked_serials, &rs);
	ಯದಿ (ers != ರಿಕ್ತ) {
		KRL_DBG(("revoked serial %llu matched %llu:%llu",
		    (unsigned long long)ಕೀಲಿ->cert->serial,
		    (unsigned long long)ers->lo,
		    (unsigned long long)ers->hi));
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_REVOKED;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Checks whether a given key/cert is revoked. Does not check its CA */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
is_ಕೀಲಿ_revoked(ಸಂರಚನಾ ssh_krl *krl, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಸಂರಚನಾ revoked_blob rb, *erb;
	ಸಂರಚನಾ revoked_certs *rc;
	ಪೂರ್ಣಾಙ್ಕ r;

	/* Check explicitly revoked hashes first */
	memset(&rb, 0, ಪರಿಮಾಣ(rb));
	ಯದಿ ((r = sshkey_fingerprint_raw(ಕೀಲಿ, SSH_DIGEST_SHA1,
	    &rb.blob, &rb.len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	erb = RB_FIND(revoked_blob_ವೃಕ್ಷ, &krl->revoked_sha1s, &rb);
	ಮುಕ್ತ(rb.blob);
	ಯದಿ (erb != ರಿಕ್ತ) {
		KRL_DBG(("revoked by key SHA1"));
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_REVOKED;
	}
	memset(&rb, 0, ಪರಿಮಾಣ(rb));
	ಯದಿ ((r = sshkey_fingerprint_raw(ಕೀಲಿ, SSH_DIGEST_SHA256,
	    &rb.blob, &rb.len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	erb = RB_FIND(revoked_blob_ವೃಕ್ಷ, &krl->revoked_sha256s, &rb);
	ಮುಕ್ತ(rb.blob);
	ಯದಿ (erb != ರಿಕ್ತ) {
		KRL_DBG(("revoked by key SHA256"));
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_REVOKED;
	}

	/* Next, explicit keys */
	memset(&rb, 0, ಪರಿಮಾಣ(rb));
	ಯದಿ ((r = plain_ಕೀಲಿ_blob(ಕೀಲಿ, &rb.blob, &rb.len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	erb = RB_FIND(revoked_blob_ವೃಕ್ಷ, &krl->revoked_ಕೀಲಿಗಳು, &rb);
	ಮುಕ್ತ(rb.blob);
	ಯದಿ (erb != ರಿಕ್ತ) {
		KRL_DBG(("revoked by explicit key"));
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_REVOKED;
	}

	ಯದಿ (!sshkey_is_cert(ಕೀಲಿ))
		ಪ್ರತ್ಯಾಗಮ 0;

	/* Check cert revocation for the specified CA */
	ಯದಿ ((r = revoked_certs_for_ca_ಕೀಲಿ(krl, ಕೀಲಿ->cert->signature_ಕೀಲಿ,
	    &rc, 0)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (rc != ರಿಕ್ತ) {
		ಯದಿ ((r = is_cert_revoked(ಕೀಲಿ, rc)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}
	/* Check cert revocation for the wildcard CA */
	ಯದಿ ((r = revoked_certs_for_ca_ಕೀಲಿ(krl, ರಿಕ್ತ, &rc, 0)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (rc != ರಿಕ್ತ) {
		ಯದಿ ((r = is_cert_revoked(ಕೀಲಿ, rc)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}

	KRL_DBG(("%llu no match", (unsigned long long)ಕೀಲಿ->cert->serial));
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_krl_check_ಕೀಲಿ(ಸಂರಚನಾ ssh_krl *krl, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	KRL_DBG(("checking key"));
	ಯದಿ ((r = is_ಕೀಲಿ_revoked(krl, ಕೀಲಿ)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (sshkey_is_cert(ಕೀಲಿ)) {
		debug2_f("checking CA key");
		ಯದಿ ((r = is_ಕೀಲಿ_revoked(krl, ಕೀಲಿ->cert->signature_ಕೀಲಿ)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}
	KRL_DBG(("key okay"));
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_krl_file_contains_ಕೀಲಿ(ಧ್ರುವ ವರ್ಣ *path, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಸಂರಚನಾ sshbuf *krlbuf = ರಿಕ್ತ;
	ಸಂರಚನಾ ssh_krl *krl = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ oerrno = 0, r;

	ಯದಿ (path == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ ((r = sshbuf_load_file(path, &krlbuf)) != 0) {
		oerrno = errno;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = ssh_krl_from_blob(krlbuf, &krl)) != 0)
		ಗಚ್ಛ out;
	debug2_f("checking KRL %s", path);
	r = ssh_krl_check_ಕೀಲಿ(krl, ಕೀಲಿ);
 out:
	sshbuf_free(krlbuf);
	ssh_krl_free(krl);
	ಯದಿ (r != 0)
		errno = oerrno;
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
krl_dump(ಸಂರಚನಾ ssh_krl *krl, FILE *f)
{
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	ಸಂರಚನಾ revoked_blob *rb;
	ಸಂರಚನಾ revoked_certs *rc;
	ಸಂರಚನಾ revoked_serial *rs;
	ಸಂರಚನಾ revoked_ಕೀಲಿ_id *rki;
	ಪೂರ್ಣಾಙ್ಕ r, ret = 0;
	ವರ್ಣ *fp, timestamp[64];

	/* Try to print in a KRL spec-compatible format */
	format_timestamp(krl->generated_date, timestamp, ಪರಿಮಾಣ(timestamp));
	fprintf(f, "# KRL version %llu\n", (unsigned long long)krl->krl_version);
	fprintf(f, "# Generated at %s\n", timestamp);
	ಯದಿ (krl->comment != ರಿಕ್ತ && *krl->comment != '\0') {
		r = INT_MAX;
		asmprintf(&fp, INT_MAX, &r, "%s", krl->comment);
		fprintf(f, "# Comment: %s\n", fp);
		ಮುಕ್ತ(fp);
	}
	fputc('\n', f);

	RB_FOREACH(rb, revoked_blob_ವೃಕ್ಷ, &krl->revoked_ಕೀಲಿಗಳು) {
		ಯದಿ ((r = sshkey_from_blob(rb->blob, rb->len, &ಕೀಲಿ)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			error_r(r, "parse KRL key");
			ಅನುವರ್ತ;
		}
		ಯದಿ ((fp = sshkey_fingerprint(ಕೀಲಿ, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ರಿಕ್ತ) {
			ret = SSH_ERR_INVALID_FORMAT;
			error("sshkey_fingerprint failed");
			ಅನುವರ್ತ;
		}
		fprintf(f, "hash: %s # %s\n", fp, sshkey_ssh_name(ಕೀಲಿ));
		ಮುಕ್ತ(fp);
		ಮುಕ್ತ(ಕೀಲಿ);
	}
	RB_FOREACH(rb, revoked_blob_ವೃಕ್ಷ, &krl->revoked_sha256s) {
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "hash: SHA256:%s\n", fp);
		ಮುಕ್ತ(fp);
	}
	RB_FOREACH(rb, revoked_blob_ವೃಕ್ಷ, &krl->revoked_sha1s) {
		/*
		 * There is not KRL spec keyword for raw SHA1 hashes, so
		 * print them as comments.
		 */
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "# hash SHA1:%s\n", fp);
		ಮುಕ್ತ(fp);
	}

	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		fputc('\n', f);
		ಯದಿ (rc->ca_ಕೀಲಿ == ರಿಕ್ತ)
			fprintf(f, "# Wildcard CA\n");
		ಅನ್ಯಥಾ {
			ಯದಿ ((fp = sshkey_fingerprint(rc->ca_ಕೀಲಿ,
			    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ರಿಕ್ತ) {
				ret = SSH_ERR_INVALID_FORMAT;
				error("sshkey_fingerprint failed");
				ಅನುವರ್ತ;
			}
			fprintf(f, "# CA key %s %s\n",
			    sshkey_ssh_name(rc->ca_ಕೀಲಿ), fp);
			ಮುಕ್ತ(fp);
		}
		RB_FOREACH(rs, revoked_serial_ವೃಕ್ಷ, &rc->revoked_serials) {
			ಯದಿ (rs->lo == rs->hi) {
				fprintf(f, "serial: %llu\n",
				    (unsigned long long)rs->lo);
			} ಅನ್ಯಥಾ {
				fprintf(f, "serial: %llu-%llu\n",
				    (unsigned long long)rs->lo,
				    (unsigned long long)rs->hi);
			}
		}
		RB_FOREACH(rki, revoked_ಕೀಲಿ_id_ವೃಕ್ಷ, &rc->revoked_ಕೀಲಿ_ids) {
			/*
			 * We don't want key IDs with embedded newlines to
			 * mess up the display.
			 */
			r = INT_MAX;
			asmprintf(&fp, INT_MAX, &r, "%s", rki->ಕೀಲಿ_id);
			fprintf(f, "id: %s\n", fp);
			ಮುಕ್ತ(fp);
		}
	}
	ಪ್ರತ್ಯಾಗಮ ret;
}
