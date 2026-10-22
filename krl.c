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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/tree.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "bitmap.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "utf8.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "krl.h"

/* #define DEBUG_KRL */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KRL
# define KRL_DBG(x) debug3_f x
#ਨਹੀਂਤਾਂ
# define KRL_DBG(x)
#ਜੇ_ਅੰਤ

/*
 * Trees of revoked serial numbers, key IDs and keys. This allows
 * quick searching, querying and producing lists in canonical order.
 */

/* Tree of serial numbers. XXX make smarter: really need a real sparse bitmap */
ਬਣਤਰ revoked_serial {
	uint64_t lo, hi;
	RB_ਇੰਦਰਾਜ(revoked_serial) ਰੁੱਖ_ਇੰਦਰਾਜ;
};
ਸਥਿਰ ਪੂਰਨ serial_cmp(ਬਣਤਰ revoked_serial *a, ਬਣਤਰ revoked_serial *b);
RB_ਸਿਰ(revoked_serial_ਰੁੱਖ, revoked_serial);
RB_GENERATE_STATIC(revoked_serial_ਰੁੱਖ, revoked_serial, ਰੁੱਖ_ਇੰਦਰਾਜ, serial_cmp)

/* Tree of key IDs */
ਬਣਤਰ revoked_ਕੁੰਜੀ_id {
	ਅੱਖਰ *ਕੁੰਜੀ_id;
	RB_ਇੰਦਰਾਜ(revoked_ਕੁੰਜੀ_id) ਰੁੱਖ_ਇੰਦਰਾਜ;
};
ਸਥਿਰ ਪੂਰਨ ਕੁੰਜੀ_id_cmp(ਬਣਤਰ revoked_ਕੁੰਜੀ_id *a, ਬਣਤਰ revoked_ਕੁੰਜੀ_id *b);
RB_ਸਿਰ(revoked_ਕੁੰਜੀ_id_ਰੁੱਖ, revoked_ਕੁੰਜੀ_id);
RB_GENERATE_STATIC(revoked_ਕੁੰਜੀ_id_ਰੁੱਖ, revoked_ਕੁੰਜੀ_id, ਰੁੱਖ_ਇੰਦਰਾਜ, ਕੁੰਜੀ_id_cmp)

/* Tree of blobs (used for keys and fingerprints) */
ਬਣਤਰ revoked_blob {
	u_char *blob;
	ਮਾਪ_t len;
	RB_ਇੰਦਰਾਜ(revoked_blob) ਰੁੱਖ_ਇੰਦਰਾਜ;
};
ਸਥਿਰ ਪੂਰਨ blob_cmp(ਬਣਤਰ revoked_blob *a, ਬਣਤਰ revoked_blob *b);
RB_ਸਿਰ(revoked_blob_ਰੁੱਖ, revoked_blob);
RB_GENERATE_STATIC(revoked_blob_ਰੁੱਖ, revoked_blob, ਰੁੱਖ_ਇੰਦਰਾਜ, blob_cmp)

/* Tracks revoked certs for a single CA */
ਬਣਤਰ revoked_certs {
	ਬਣਤਰ sshkey *ca_ਕੁੰਜੀ;
	ਬਣਤਰ revoked_serial_ਰੁੱਖ revoked_serials;
	ਬਣਤਰ revoked_ਕੁੰਜੀ_id_ਰੁੱਖ revoked_ਕੁੰਜੀ_ids;
	TAILQ_ENTRY(revoked_certs) ਇੰਦਰਾਜ;
};
TAILQ_HEAD(revoked_certs_list, revoked_certs);

ਬਣਤਰ ssh_krl {
	uint64_t krl_ਸੰਸਕਰਣ;
	uint64_t generated_date;
	uint64_t flags;
	ਅੱਖਰ *comment;
	ਬਣਤਰ revoked_blob_ਰੁੱਖ revoked_ਕੁੰਜੀਆਂ;
	ਬਣਤਰ revoked_blob_ਰੁੱਖ revoked_sha1s;
	ਬਣਤਰ revoked_blob_ਰੁੱਖ revoked_sha256s;
	ਬਣਤਰ revoked_certs_list revoked_certs;
};

/* Return equal if a and b overlap */
ਸਥਿਰ ਪੂਰਨ
serial_cmp(ਬਣਤਰ revoked_serial *a, ਬਣਤਰ revoked_serial *b)
{
	ਜੇ (a->hi >= b->lo && a->lo <= b->hi)
		ਵਾਪਸ 0;
	ਵਾਪਸ a->lo < b->lo ? -1 : 1;
}

ਸਥਿਰ ਪੂਰਨ
ਕੁੰਜੀ_id_cmp(ਬਣਤਰ revoked_ਕੁੰਜੀ_id *a, ਬਣਤਰ revoked_ਕੁੰਜੀ_id *b)
{
	ਵਾਪਸ strcmp(a->ਕੁੰਜੀ_id, b->ਕੁੰਜੀ_id);
}

ਸਥਿਰ ਪੂਰਨ
blob_cmp(ਬਣਤਰ revoked_blob *a, ਬਣਤਰ revoked_blob *b)
{
	ਪੂਰਨ r;

	ਜੇ (a->len != b->len) {
		ਜੇ ((r = memcmp(a->blob, b->blob, MINIMUM(a->len, b->len))) != 0)
			ਵਾਪਸ r;
		ਵਾਪਸ a->len > b->len ? 1 : -1;
	} ਨਹੀਂਤਾਂ
		ਵਾਪਸ memcmp(a->blob, b->blob, a->len);
}

ਬਣਤਰ ssh_krl *
ssh_krl_init(ਖਾਲੀ)
{
	ਬਣਤਰ ssh_krl *krl;

	ਜੇ ((krl = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*krl))) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	RB_INIT(&krl->revoked_ਕੁੰਜੀਆਂ);
	RB_INIT(&krl->revoked_sha1s);
	RB_INIT(&krl->revoked_sha256s);
	TAILQ_INIT(&krl->revoked_certs);
	ਵਾਪਸ krl;
}

ਸਥਿਰ ਖਾਲੀ
revoked_certs_free(ਬਣਤਰ revoked_certs *rc)
{
	ਬਣਤਰ revoked_serial *rs, *trs;
	ਬਣਤਰ revoked_ਕੁੰਜੀ_id *rki, *trki;

	ਜੇ (rc == ਨਿਰਾ)
		ਵਾਪਸ;
	RB_FOREACH_ਸੁਰੱਖਿਅਤ(rs, revoked_serial_ਰੁੱਖ, &rc->revoked_serials, trs) {
		RB_REMOVE(revoked_serial_ਰੁੱਖ, &rc->revoked_serials, rs);
		ਮੁਕਤ(rs);
	}
	RB_FOREACH_ਸੁਰੱਖਿਅਤ(rki, revoked_ਕੁੰਜੀ_id_ਰੁੱਖ, &rc->revoked_ਕੁੰਜੀ_ids, trki) {
		RB_REMOVE(revoked_ਕੁੰਜੀ_id_ਰੁੱਖ, &rc->revoked_ਕੁੰਜੀ_ids, rki);
		ਮੁਕਤ(rki->ਕੁੰਜੀ_id);
		ਮੁਕਤ(rki);
	}
	sshkey_free(rc->ca_ਕੁੰਜੀ);
	freezero(rc, ਆਕਾਰ(*rc));
}

ਖਾਲੀ
ssh_krl_free(ਬਣਤਰ ssh_krl *krl)
{
	ਬਣਤਰ revoked_blob *rb, *trb;
	ਬਣਤਰ revoked_certs *rc, *trc;

	ਜੇ (krl == ਨਿਰਾ)
		ਵਾਪਸ;

	ਮੁਕਤ(krl->comment);
	RB_FOREACH_ਸੁਰੱਖਿਅਤ(rb, revoked_blob_ਰੁੱਖ, &krl->revoked_ਕੁੰਜੀਆਂ, trb) {
		RB_REMOVE(revoked_blob_ਰੁੱਖ, &krl->revoked_ਕੁੰਜੀਆਂ, rb);
		ਮੁਕਤ(rb->blob);
		ਮੁਕਤ(rb);
	}
	RB_FOREACH_ਸੁਰੱਖਿਅਤ(rb, revoked_blob_ਰੁੱਖ, &krl->revoked_sha1s, trb) {
		RB_REMOVE(revoked_blob_ਰੁੱਖ, &krl->revoked_sha1s, rb);
		ਮੁਕਤ(rb->blob);
		ਮੁਕਤ(rb);
	}
	RB_FOREACH_ਸੁਰੱਖਿਅਤ(rb, revoked_blob_ਰੁੱਖ, &krl->revoked_sha256s, trb) {
		RB_REMOVE(revoked_blob_ਰੁੱਖ, &krl->revoked_sha256s, rb);
		ਮੁਕਤ(rb->blob);
		ਮੁਕਤ(rb);
	}
	TAILQ_FOREACH_ਸੁਰੱਖਿਅਤ(rc, &krl->revoked_certs, ਇੰਦਰਾਜ, trc) {
		TAILQ_REMOVE(&krl->revoked_certs, rc, ਇੰਦਰਾਜ);
		revoked_certs_free(rc);
	}
	ਮੁਕਤ(krl);
}

ਖਾਲੀ
ssh_krl_ਸੈੱਟ_ਸੰਸਕਰਣ(ਬਣਤਰ ssh_krl *krl, uint64_t ਸੰਸਕਰਣ)
{
	krl->krl_ਸੰਸਕਰਣ = ਸੰਸਕਰਣ;
}

ਪੂਰਨ
ssh_krl_ਸੈੱਟ_comment(ਬਣਤਰ ssh_krl *krl, ਅਚਲ ਅੱਖਰ *comment)
{
	ਮੁਕਤ(krl->comment);
	ਜੇ ((krl->comment = strdup(comment)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਵਾਪਸ 0;
}

/*
 * Find the revoked_certs struct for a CA key. If allow_create is set then
 * create a new one in the tree if one did not exist already.
 */
ਸਥਿਰ ਪੂਰਨ
revoked_certs_for_ca_ਕੁੰਜੀ(ਬਣਤਰ ssh_krl *krl, ਅਚਲ ਬਣਤਰ sshkey *ca_ਕੁੰਜੀ,
    ਬਣਤਰ revoked_certs **rcp, ਪੂਰਨ allow_create)
{
	ਬਣਤਰ revoked_certs *rc;
	ਪੂਰਨ r;

	*rcp = ਨਿਰਾ;
	TAILQ_FOREACH(rc, &krl->revoked_certs, ਇੰਦਰਾਜ) {
		ਜੇ ((ca_ਕੁੰਜੀ == ਨਿਰਾ && rc->ca_ਕੁੰਜੀ == ਨਿਰਾ) ||
		    sshkey_equal(rc->ca_ਕੁੰਜੀ, ca_ਕੁੰਜੀ)) {
			*rcp = rc;
			ਵਾਪਸ 0;
		}
	}
	ਜੇ (!allow_create)
		ਵਾਪਸ 0;
	/* If this CA doesn't exist in the list then add it now */
	ਜੇ ((rc = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*rc))) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ (ca_ਕੁੰਜੀ == ਨਿਰਾ)
		rc->ca_ਕੁੰਜੀ = ਨਿਰਾ;
	ਨਹੀਂਤਾਂ ਜੇ ((r = sshkey_from_ਨਿੱਜੀ(ca_ਕੁੰਜੀ, &rc->ca_ਕੁੰਜੀ)) != 0) {
		ਮੁਕਤ(rc);
		ਵਾਪਸ r;
	}
	RB_INIT(&rc->revoked_serials);
	RB_INIT(&rc->revoked_ਕੁੰਜੀ_ids);
	TAILQ_INSERT_TAIL(&krl->revoked_certs, rc, ਇੰਦਰਾਜ);
	KRL_DBG(("new CA %s", ca_ਕੁੰਜੀ == ਨਿਰਾ ? "*" : sshkey_type(ca_ਕੁੰਜੀ)));
	*rcp = rc;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ਪਾਓ_serial_range(ਬਣਤਰ revoked_serial_ਰੁੱਖ *rt, uint64_t lo, uint64_t hi)
{
	ਬਣਤਰ revoked_serial rs, *ers, *crs, *irs;

	KRL_DBG(("insert %llu:%llu",
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)lo, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)hi));
	memset(&rs, 0, ਆਕਾਰ(rs));
	rs.lo = lo;
	rs.hi = hi;
	ers = RB_NFIND(revoked_serial_ਰੁੱਖ, rt, &rs);
	ਜੇ (ers == ਨਿਰਾ || serial_cmp(ers, &rs) != 0) {
		/* No entry matches. Just insert */
		ਜੇ ((irs = ਸਮ੍ਰਿਤੀ_ਦਿਓ(ਆਕਾਰ(rs))) == ਨਿਰਾ)
			ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(irs, &rs, ਆਕਾਰ(*irs));
		ers = RB_ਪਾਓ(revoked_serial_ਰੁੱਖ, rt, irs);
		ਜੇ (ers != ਨਿਰਾ) {
			KRL_DBG(("bad: ers != NULL"));
			/* Shouldn't happen */
			ਮੁਕਤ(irs);
			ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
		}
		ers = irs;
	} ਨਹੀਂਤਾਂ {
		KRL_DBG(("overlap found %llu:%llu",
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ers->lo, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ers->hi));
		/*
		 * The inserted entry overlaps an existing one. Grow the
		 * existing entry.
		 */
		ਜੇ (ers->lo > lo)
			ers->lo = lo;
		ਜੇ (ers->hi < hi)
			ers->hi = hi;
	}

	/*
	 * The inserted or revised range might overlap or abut adjacent ones;
	 * coalesce as necessary.
	 */

	/* Check predecessors */
	ਜਦੋਂ ((crs = RB_PREV(revoked_serial_ਰੁੱਖ, rt, ers)) != ਨਿਰਾ) {
		KRL_DBG(("pred %llu:%llu",
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)crs->lo, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)crs->hi));
		ਜੇ (ers->lo != 0 && crs->hi < ers->lo - 1)
			ਰੋਕੋ;
		/* This entry overlaps. */
		ਜੇ (crs->lo < ers->lo) {
			ers->lo = crs->lo;
			KRL_DBG(("pred extend %llu:%llu",
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ers->lo,
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ers->hi));
		}
		RB_REMOVE(revoked_serial_ਰੁੱਖ, rt, crs);
		ਮੁਕਤ(crs);
	}
	/* Check successors */
	ਜਦੋਂ ((crs = RB_ਅਗਲਾ(revoked_serial_ਰੁੱਖ, rt, ers)) != ਨਿਰਾ) {
		KRL_DBG(("succ %llu:%llu",
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)crs->lo, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)crs->hi));
		ਜੇ (ers->hi != (uint64_t)-1 && crs->lo > ers->hi + 1)
			ਰੋਕੋ;
		/* This entry overlaps. */
		ਜੇ (crs->hi > ers->hi) {
			ers->hi = crs->hi;
			KRL_DBG(("succ extend %llu:%llu",
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ers->lo,
			    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ers->hi));
		}
		RB_REMOVE(revoked_serial_ਰੁੱਖ, rt, crs);
		ਮੁਕਤ(crs);
	}
	KRL_DBG(("done, final %llu:%llu",
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ers->lo, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ers->hi));
	ਵਾਪਸ 0;
}

ਪੂਰਨ
ssh_krl_revoke_cert_by_serial(ਬਣਤਰ ssh_krl *krl, ਅਚਲ ਬਣਤਰ sshkey *ca_ਕੁੰਜੀ,
    uint64_t serial)
{
	ਵਾਪਸ ssh_krl_revoke_cert_by_serial_range(krl, ca_ਕੁੰਜੀ, serial, serial);
}

ਪੂਰਨ
ssh_krl_revoke_cert_by_serial_range(ਬਣਤਰ ssh_krl *krl,
    ਅਚਲ ਬਣਤਰ sshkey *ca_ਕੁੰਜੀ, uint64_t lo, uint64_t hi)
{
	ਬਣਤਰ revoked_certs *rc;
	ਪੂਰਨ r;

	ਜੇ (lo > hi || lo == 0)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ ((r = revoked_certs_for_ca_ਕੁੰਜੀ(krl, ca_ਕੁੰਜੀ, &rc, 1)) != 0)
		ਵਾਪਸ r;
	ਵਾਪਸ ਪਾਓ_serial_range(&rc->revoked_serials, lo, hi);
}

ਪੂਰਨ
ssh_krl_revoke_cert_by_ਕੁੰਜੀ_id(ਬਣਤਰ ssh_krl *krl, ਅਚਲ ਬਣਤਰ sshkey *ca_ਕੁੰਜੀ,
    ਅਚਲ ਅੱਖਰ *ਕੁੰਜੀ_id)
{
	ਬਣਤਰ revoked_ਕੁੰਜੀ_id *rki, *erki;
	ਬਣਤਰ revoked_certs *rc;
	ਪੂਰਨ r;

	ਜੇ ((r = revoked_certs_for_ca_ਕੁੰਜੀ(krl, ca_ਕੁੰਜੀ, &rc, 1)) != 0)
		ਵਾਪਸ r;

	KRL_DBG(("revoke %s", ਕੁੰਜੀ_id));
	ਜੇ ((rki = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*rki))) == ਨਿਰਾ ||
	    (rki->ਕੁੰਜੀ_id = strdup(ਕੁੰਜੀ_id)) == ਨਿਰਾ) {
		ਮੁਕਤ(rki);
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	}
	erki = RB_ਪਾਓ(revoked_ਕੁੰਜੀ_id_ਰੁੱਖ, &rc->revoked_ਕੁੰਜੀ_ids, rki);
	ਜੇ (erki != ਨਿਰਾ) {
		ਮੁਕਤ(rki->ਕੁੰਜੀ_id);
		ਮੁਕਤ(rki);
	}
	ਵਾਪਸ 0;
}

/* Convert "key" to a public key blob without any certificate information */
ਸਥਿਰ ਪੂਰਨ
plain_ਕੁੰਜੀ_blob(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, u_char **blob, ਮਾਪ_t *blen)
{
	ਬਣਤਰ sshkey *kcopy;
	ਪੂਰਨ r;

	ਜੇ ((r = sshkey_from_ਨਿੱਜੀ(ਕੁੰਜੀ, &kcopy)) != 0)
		ਵਾਪਸ r;
	ਜੇ (sshkey_is_cert(kcopy)) {
		ਜੇ ((r = sshkey_drop_cert(kcopy)) != 0) {
			sshkey_free(kcopy);
			ਵਾਪਸ r;
		}
	}
	r = sshkey_ਮੰਜ਼ਿਲ_blob(kcopy, blob, blen);
	sshkey_free(kcopy);
	ਵਾਪਸ r;
}

/* Revoke a key blob. Ownership of blob is transferred to the tree */
ਸਥਿਰ ਪੂਰਨ
revoke_blob(ਬਣਤਰ revoked_blob_ਰੁੱਖ *rbt, u_char *blob, ਮਾਪ_t len)
{
	ਬਣਤਰ revoked_blob *rb, *erb;

	ਜੇ ((rb = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*rb))) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	rb->blob = blob;
	rb->len = len;
	erb = RB_ਪਾਓ(revoked_blob_ਰੁੱਖ, rbt, rb);
	ਜੇ (erb != ਨਿਰਾ) {
		ਮੁਕਤ(rb->blob);
		ਮੁਕਤ(rb);
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
ssh_krl_revoke_ਕੁੰਜੀ_explicit(ਬਣਤਰ ssh_krl *krl, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	u_char *blob;
	ਮਾਪ_t len;
	ਪੂਰਨ r;

	debug3_f("revoke type %s", sshkey_type(ਕੁੰਜੀ));
	ਜੇ ((r = plain_ਕੁੰਜੀ_blob(ਕੁੰਜੀ, &blob, &len)) != 0)
		ਵਾਪਸ r;
	ਵਾਪਸ revoke_blob(&krl->revoked_ਕੁੰਜੀਆਂ, blob, len);
}

ਸਥਿਰ ਪੂਰਨ
revoke_by_hash(ਬਣਤਰ revoked_blob_ਰੁੱਖ *ਨਿਸ਼ਾਨਾ, ਅਚਲ u_char *p, ਮਾਪ_t len)
{
	u_char *blob;
	ਪੂਰਨ r;

	/* need to copy hash, as revoke_blob steals ownership */
	ਜੇ ((blob = ਸਮ੍ਰਿਤੀ_ਦਿਓ(len)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(blob, p, len);
	ਜੇ ((r = revoke_blob(ਨਿਸ਼ਾਨਾ, blob, len)) != 0) {
		ਮੁਕਤ(blob);
		ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
ssh_krl_revoke_ਕੁੰਜੀ_sha1(ਬਣਤਰ ssh_krl *krl, ਅਚਲ u_char *p, ਮਾਪ_t len)
{
	debug3_f("revoke by sha1");
	ਜੇ (len != 20)
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	ਵਾਪਸ revoke_by_hash(&krl->revoked_sha1s, p, len);
}

ਪੂਰਨ
ssh_krl_revoke_ਕੁੰਜੀ_sha256(ਬਣਤਰ ssh_krl *krl, ਅਚਲ u_char *p, ਮਾਪ_t len)
{
	debug3_f("revoke by sha256");
	ਜੇ (len != 32)
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	ਵਾਪਸ revoke_by_hash(&krl->revoked_sha256s, p, len);
}

ਪੂਰਨ
ssh_krl_revoke_ਕੁੰਜੀ(ਬਣਤਰ ssh_krl *krl, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	/* XXX replace with SHA256? */
	ਜੇ (!sshkey_is_cert(ਕੁੰਜੀ))
		ਵਾਪਸ ssh_krl_revoke_ਕੁੰਜੀ_explicit(krl, ਕੁੰਜੀ);

	ਜੇ (ਕੁੰਜੀ->cert->serial == 0) {
		ਵਾਪਸ ssh_krl_revoke_cert_by_ਕੁੰਜੀ_id(krl,
		    ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ,
		    ਕੁੰਜੀ->cert->ਕੁੰਜੀ_id);
	} ਨਹੀਂਤਾਂ {
		ਵਾਪਸ ssh_krl_revoke_cert_by_serial(krl,
		    ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ,
		    ਕੁੰਜੀ->cert->serial);
	}
}

/*
 * Select the most compact section type to emit next in a KRL based on
 * the current section type, the run length of contiguous revoked serial
 * numbers and the gaps from the last and to the next revoked serial.
 * Applies a mostly-accurate bit cost model to select the section type
 * that will minimise the size of the resultant KRL.
 */
ਸਥਿਰ ਪੂਰਨ
ਚੁਣੋ_ਅਗਲਾ_state(ਪੂਰਨ current_state, uint64_t contig, ਪੂਰਨ final,
    uint64_t ਆਖਰੀ_gap, uint64_t ਅਗਲਾ_gap, ਮਾਪ_t bitmap_len,
    ਪੂਰਨ *force_new_section)
{
	ਪੂਰਨ new_state;
	uint64_t ਲਾਗਤ, ਲਾਗਤ_list, ਲਾਗਤ_range, ਲਾਗਤ_bitmap, ਲਾਗਤ_bitmap_restart;

	/*
	 * Avoid unsigned overflows.
	 * The limits are high enough to avoid confusing the calculations.
	 */
	contig = MINIMUM(contig, 1ULL<<31);
	ਆਖਰੀ_gap = MINIMUM(ਆਖਰੀ_gap, 1ULL<<31);
	ਅਗਲਾ_gap = MINIMUM(ਅਗਲਾ_gap, 1ULL<<31);

	/*
	 * Calculate the cost to switch from the current state to candidates.
	 * NB. range sections only ever contain a single range, so their
	 * switching cost is independent of the current_state.
	 */
	ਲਾਗਤ_list = ਲਾਗਤ_bitmap = ਲਾਗਤ_bitmap_restart = 0;
	ਲਾਗਤ_range = 8;
	ਚੋਣ (current_state) {
	ਹਾਲਤ KRL_SECTION_CERT_SERIAL_LIST:
		ਲਾਗਤ_bitmap_restart = ਲਾਗਤ_bitmap = 8 + 64;
		ਰੋਕੋ;
	ਹਾਲਤ KRL_SECTION_CERT_SERIAL_BITMAP:
		ਲਾਗਤ_list = 8;
		ਲਾਗਤ_bitmap_restart = 8 + 64;
		ਰੋਕੋ;
	ਹਾਲਤ KRL_SECTION_CERT_SERIAL_RANGE:
	ਹਾਲਤ 0:
		ਲਾਗਤ_bitmap_restart = ਲਾਗਤ_bitmap = 8 + 64;
		ਲਾਗਤ_list = 8;
	}

	/* Estimate base cost in bits of each section type */
	ਲਾਗਤ_list += 64 * contig + (final ? 0 : 8+64);
	ਲਾਗਤ_range += (2 * 64) + (final ? 0 : 8+64);
	ਲਾਗਤ_bitmap += ਆਖਰੀ_gap + contig + (final ? 0 : MINIMUM(ਅਗਲਾ_gap, 8+64));
	ਲਾਗਤ_bitmap_restart += contig + (final ? 0 : MINIMUM(ਅਗਲਾ_gap, 8+64));

	/* Convert to byte costs for actual comparison */
	ਲਾਗਤ_list = (ਲਾਗਤ_list + 7) / 8;
	ਲਾਗਤ_bitmap = (ਲਾਗਤ_bitmap + 7) / 8;
	ਲਾਗਤ_bitmap_restart = (ਲਾਗਤ_bitmap_restart + 7) / 8;
	ਲਾਗਤ_range = (ਲਾਗਤ_range + 7) / 8;

	/* Ensure that we never emit a bitmap larger than sshbuf can handle */
	ਜੇ (bitmap_len + ਲਾਗਤ_bitmap >= SSHBUF_MAX_BIGNUM) {
		KRL_DBG(("bitmap overfull len=%zu cost=%llu max=%u",
		    bitmap_len, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਲਾਗਤ_bitmap,
		    SSHBUF_MAX_BIGNUM));
		ਲਾਗਤ_bitmap = (uint64_t)-1;
	}

	/* Now pick the best choice */
	*force_new_section = 0;
	new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
	ਲਾਗਤ = ਲਾਗਤ_bitmap;
	ਜੇ (ਲਾਗਤ_range < ਲਾਗਤ) {
		new_state = KRL_SECTION_CERT_SERIAL_RANGE;
		ਲਾਗਤ = ਲਾਗਤ_range;
	}
	ਜੇ (ਲਾਗਤ_list < ਲਾਗਤ) {
		new_state = KRL_SECTION_CERT_SERIAL_LIST;
		ਲਾਗਤ = ਲਾਗਤ_list;
	}
	ਜੇ (ਲਾਗਤ_bitmap_restart < ਲਾਗਤ) {
		new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
		*force_new_section = 1;
		ਲਾਗਤ = ਲਾਗਤ_bitmap_restart;
	}
	KRL_DBG(("contig %llu last_gap %llu next_gap %llu final %d, costs:"
	    "list %llu range %llu bitmap %llu new bitmap %llu, "
	    "selected 0x%02x%s", (ਲੰਮਾ ਲੰਮਾ ਬਿਨਾਨਿਸ਼ਾਨੀ)contig,
	    (ਲੰਮਾ ਲੰਮਾ ਬਿਨਾਨਿਸ਼ਾਨੀ)ਆਖਰੀ_gap, (ਲੰਮਾ ਲੰਮਾ ਬਿਨਾਨਿਸ਼ਾਨੀ)ਅਗਲਾ_gap, final,
	    (ਲੰਮਾ ਲੰਮਾ ਬਿਨਾਨਿਸ਼ਾਨੀ)ਲਾਗਤ_list, (ਲੰਮਾ ਲੰਮਾ ਬਿਨਾਨਿਸ਼ਾਨੀ)ਲਾਗਤ_range,
	    (ਲੰਮਾ ਲੰਮਾ ਬਿਨਾਨਿਸ਼ਾਨੀ)ਲਾਗਤ_bitmap,
	    (ਲੰਮਾ ਲੰਮਾ ਬਿਨਾਨਿਸ਼ਾਨੀ)ਲਾਗਤ_bitmap_restart, new_state,
	    *force_new_section ? " restart" : ""));
	ਵਾਪਸ new_state;
}

ਸਥਿਰ ਪੂਰਨ
put_bitmap(ਬਣਤਰ sshbuf *buf, ਬਣਤਰ bitmap *bitmap)
{
	ਮਾਪ_t len;
	u_char *blob;
	ਪੂਰਨ r;

	len = bitmap_nbytes(bitmap);
	ਜੇ ((blob = ਸਮ੍ਰਿਤੀ_ਦਿਓ(len)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ (bitmap_ਮੰਜ਼ਿਲ_string(bitmap, blob, len) != 0) {
		ਮੁਕਤ(blob);
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	r = sshbuf_put_bignum2_ਬਾਈਟਾਂ(buf, blob, len);
	ਮੁਕਤ(blob);
	ਵਾਪਸ r;
}

/* Generate a KRL_SECTION_CERTIFICATES KRL section */
ਸਥਿਰ ਪੂਰਨ
revoked_certs_generate(ਬਣਤਰ revoked_certs *rc, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ final, force_new_sect, r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	uint64_t i, contig, gap, ਆਖਰੀ = 0, bitmap_ਸ਼ੁਰੂ = 0;
	ਬਣਤਰ revoked_serial *rs, *nrs;
	ਬਣਤਰ revoked_ਕੁੰਜੀ_id *rki;
	ਪੂਰਨ ਅਗਲਾ_state, state = 0;
	ਮਾਪ_t bitmap_len;
	ਬਣਤਰ sshbuf *sect;
	ਬਣਤਰ bitmap *bitmap = ਨਿਰਾ;

	ਜੇ ((sect = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;

	/* Store the header: optional CA scope key, reserved */
	ਜੇ (rc->ca_ਕੁੰਜੀ == ਨਿਰਾ) {
		ਜੇ ((r = sshbuf_put_string(buf, ਨਿਰਾ, 0)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	} ਨਹੀਂਤਾਂ {
		ਜੇ ((r = sshkey_puts(rc->ca_ਕੁੰਜੀ, buf)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put_string(buf, ਨਿਰਾ, 0)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Store the revoked serials.  */
	ਲਈ (rs = RB_MIN(revoked_serial_ਰੁੱਖ, &rc->revoked_serials);
	     rs != ਨਿਰਾ;
	     rs = RB_ਅਗਲਾ(revoked_serial_ਰੁੱਖ, &rc->revoked_serials, rs)) {
		KRL_DBG(("serial %llu:%llu state 0x%02x",
		    (ਲੰਮਾ ਲੰਮਾ ਬਿਨਾਨਿਸ਼ਾਨੀ)rs->lo, (ਲੰਮਾ ਲੰਮਾ ਬਿਨਾਨਿਸ਼ਾਨੀ)rs->hi,
		    state));

		/* Check contiguous length and gap to next section (if any) */
		nrs = RB_ਅਗਲਾ(revoked_serial_ਰੁੱਖ, &rc->revoked_serials, rs);
		final = nrs == ਨਿਰਾ;
		gap = nrs == ਨਿਰਾ ? 0 : nrs->lo - rs->hi;
		contig = 1 + (rs->hi - rs->lo);

		bitmap_len = state == KRL_SECTION_CERT_SERIAL_BITMAP ?
		    bitmap_nbytes(bitmap) : 0;

		/* Choose next state based on these */
		ਅਗਲਾ_state = ਚੁਣੋ_ਅਗਲਾ_state(state, contig, final,
		    state == 0 ? 0 : rs->lo - ਆਖਰੀ, gap, bitmap_len,
		    &force_new_sect);

		/*
		 * If the current section is a range section or has a different
		 * type to the next section, then finish it off now.
		 */
		ਜੇ (state != 0 && (force_new_sect || ਅਗਲਾ_state != state ||
		    state == KRL_SECTION_CERT_SERIAL_RANGE)) {
			KRL_DBG(("finish state 0x%02x", state));
			ਚੋਣ (state) {
			ਹਾਲਤ KRL_SECTION_CERT_SERIAL_LIST:
			ਹਾਲਤ KRL_SECTION_CERT_SERIAL_RANGE:
				ਰੋਕੋ;
			ਹਾਲਤ KRL_SECTION_CERT_SERIAL_BITMAP:
				ਜੇ ((r = put_bitmap(sect, bitmap)) != 0)
					ਜਾਓ ਬਾਹਰਲਾ;
				bitmap_free(bitmap);
				bitmap = ਨਿਰਾ;
				ਰੋਕੋ;
			}
			ਜੇ ((r = sshbuf_put_u8(buf, state)) != 0 ||
			    (r = sshbuf_put_stringb(buf, sect)) != 0)
				ਜਾਓ ਬਾਹਰਲਾ;
			sshbuf_reset(sect);
		}

		/* If we are starting a new section then prepare it now */
		ਜੇ (ਅਗਲਾ_state != state || force_new_sect) {
			KRL_DBG(("start state 0x%02x",
			    ਅਗਲਾ_state));
			state = ਅਗਲਾ_state;
			sshbuf_reset(sect);
			ਚੋਣ (state) {
			ਹਾਲਤ KRL_SECTION_CERT_SERIAL_LIST:
			ਹਾਲਤ KRL_SECTION_CERT_SERIAL_RANGE:
				ਰੋਕੋ;
			ਹਾਲਤ KRL_SECTION_CERT_SERIAL_BITMAP:
				ਜੇ ((bitmap = bitmap_new()) == ਨਿਰਾ) {
					r = SSH_ERR_ALLOC_FAIL;
					ਜਾਓ ਬਾਹਰਲਾ;
				}
				bitmap_ਸ਼ੁਰੂ = rs->lo;
				ਜੇ ((r = sshbuf_put_u64(sect,
				    bitmap_ਸ਼ੁਰੂ)) != 0)
					ਜਾਓ ਬਾਹਰਲਾ;
				ਰੋਕੋ;
			}
		}

		/* Perform section-specific processing */
		ਚੋਣ (state) {
		ਹਾਲਤ KRL_SECTION_CERT_SERIAL_LIST:
			ਲਈ (i = 0; i < contig; i++) {
				ਜੇ ((r = sshbuf_put_u64(sect, rs->lo + i)) != 0)
					ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਰੋਕੋ;
		ਹਾਲਤ KRL_SECTION_CERT_SERIAL_RANGE:
			ਜੇ ((r = sshbuf_put_u64(sect, rs->lo)) != 0 ||
			    (r = sshbuf_put_u64(sect, rs->hi)) != 0)
				ਜਾਓ ਬਾਹਰਲਾ;
			ਰੋਕੋ;
		ਹਾਲਤ KRL_SECTION_CERT_SERIAL_BITMAP:
			ਜੇ (rs->lo - bitmap_ਸ਼ੁਰੂ > ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ) {
				r = SSH_ERR_INVALID_FORMAT;
				error_f("insane bitmap gap");
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਲਈ (i = 0; i < contig; i++) {
				ਜੇ (bitmap_ਸੈੱਟ_ਦੋਆਧਾਰੀ_ਅੰਕ(bitmap,
				    rs->lo + i - bitmap_ਸ਼ੁਰੂ) != 0) {
					r = SSH_ERR_ALLOC_FAIL;
					ਜਾਓ ਬਾਹਰਲਾ;
				}
			}
			ਰੋਕੋ;
		}
		ਆਖਰੀ = rs->hi;
	}
	/* Flush the remaining section, if any */
	ਜੇ (state != 0) {
		KRL_DBG(("serial final flush for state 0x%02x", state));
		ਚੋਣ (state) {
		ਹਾਲਤ KRL_SECTION_CERT_SERIAL_LIST:
		ਹਾਲਤ KRL_SECTION_CERT_SERIAL_RANGE:
			ਰੋਕੋ;
		ਹਾਲਤ KRL_SECTION_CERT_SERIAL_BITMAP:
			ਜੇ ((r = put_bitmap(sect, bitmap)) != 0)
				ਜਾਓ ਬਾਹਰਲਾ;
			bitmap_free(bitmap);
			bitmap = ਨਿਰਾ;
			ਰੋਕੋ;
		}
		ਜੇ ((r = sshbuf_put_u8(buf, state)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	KRL_DBG(("serial done "));

	/* Now output a section for any revocations by key ID */
	sshbuf_reset(sect);
	RB_FOREACH(rki, revoked_ਕੁੰਜੀ_id_ਰੁੱਖ, &rc->revoked_ਕੁੰਜੀ_ids) {
		KRL_DBG(("key ID %s", rki->ਕੁੰਜੀ_id));
		ਜੇ ((r = sshbuf_put_cstring(sect, rki->ਕੁੰਜੀ_id)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshbuf_len(sect) != 0) {
		ਜੇ ((r = sshbuf_put_u8(buf, KRL_SECTION_CERT_ਕੁੰਜੀ_ID)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	r = 0;
 ਬਾਹਰਲਾ:
	bitmap_free(bitmap);
	sshbuf_free(sect);
	ਵਾਪਸ r;
}

ਪੂਰਨ
ssh_krl_ਮੰਜ਼ਿਲ_blob(ਬਣਤਰ ssh_krl *krl, ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਬਣਤਰ revoked_certs *rc;
	ਬਣਤਰ revoked_blob *rb;
	ਬਣਤਰ sshbuf *sect;
	u_char *sblob = ਨਿਰਾ;

	ਜੇ (krl->generated_date == 0)
		krl->generated_date = time(ਨਿਰਾ);

	ਜੇ ((sect = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;

	/* Store the header */
	ਜੇ ((r = sshbuf_put(buf, KRL_MAGIC, ਆਕਾਰ(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_put_u32(buf, KRL_FORMAT_ਸੰਸਕਰਣ)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->krl_ਸੰਸਕਰਣ)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->generated_date)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->flags)) != 0 ||
	    (r = sshbuf_put_string(buf, ਨਿਰਾ, 0)) != 0 ||
	    (r = sshbuf_put_cstring(buf, krl->comment)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Store sections for revoked certificates */
	TAILQ_FOREACH(rc, &krl->revoked_certs, ਇੰਦਰਾਜ) {
		sshbuf_reset(sect);
		ਜੇ ((r = revoked_certs_generate(rc, sect)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਜੇ ((r = sshbuf_put_u8(buf, KRL_SECTION_CERTIFICATES)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Finally, output sections for revocations by public key/hash */
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_ਰੁੱਖ, &krl->revoked_ਕੁੰਜੀਆਂ) {
		KRL_DBG(("key len %zu ", rb->len));
		ਜੇ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshbuf_len(sect) != 0) {
		ਜੇ ((r = sshbuf_put_u8(buf, KRL_SECTION_EXPLICIT_ਕੁੰਜੀ)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_ਰੁੱਖ, &krl->revoked_sha1s) {
		KRL_DBG(("hash len %zu ", rb->len));
		ਜੇ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshbuf_len(sect) != 0) {
		ਜੇ ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA1)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_ਰੁੱਖ, &krl->revoked_sha256s) {
		KRL_DBG(("hash len %zu ", rb->len));
		ਜੇ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshbuf_len(sect) != 0) {
		ਜੇ ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA256)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(sblob);
	sshbuf_free(sect);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਖਾਲੀ
format_timestamp(uint64_t timestamp, ਅੱਖਰ *ts, ਮਾਪ_t nts)
{
	time_t t;
	ਬਣਤਰ tm *tm;

	t = timestamp;
	tm = localtime(&t);
	ਜੇ (tm == ਨਿਰਾ)
		strlcpy(ts, "<INVALID>", nts);
	ਨਹੀਂਤਾਂ {
		*ts = '\0';
		strftime(ts, nts, "%Y%m%dT%H%M%S", tm);
	}
}

ਸਥਿਰ ਪੂਰਨ
cert_extension_subsection(ਬਣਤਰ sshbuf *subsect, ਬਣਤਰ ssh_krl *krl)
{
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	u_char critical = 1;
	ਬਣਤਰ sshbuf *ਮੁੱਲ = ਨਿਰਾ;
	ਅੱਖਰ *name = ਨਿਰਾ;

	ਜੇ ((r = sshbuf_get_cstring(subsect, &name, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_u8(subsect, &critical)) != 0 ||
	    (r = sshbuf_froms(subsect, &ਮੁੱਲ)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid certificate extension subsection");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshbuf_len(subsect) != 0) {
		error("KRL has invalid certificate extension subsection: "
		    "trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	debug_f("cert extension %s critical %u len %zu",
	    name, critical, sshbuf_len(ਮੁੱਲ));
	/* no extensions are currently supported */
	ਜੇ (critical) {
		error("KRL contains unsupported critical certificate "
		    "subsection \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(name);
	sshbuf_free(ਮੁੱਲ);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
parse_revoked_certs(ਬਣਤਰ sshbuf *buf, ਬਣਤਰ ssh_krl *krl)
{
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	u_char type;
	ਅਚਲ u_char *blob;
	ਮਾਪ_t blen, nbits;
	ਬਣਤਰ sshbuf *subsect = ਨਿਰਾ;
	uint64_t serial, serial_lo, serial_hi;
	ਬਣਤਰ bitmap *bitmap = ਨਿਰਾ;
	ਅੱਖਰ *ਕੁੰਜੀ_id = ਨਿਰਾ;
	ਬਣਤਰ sshkey *ca_ਕੁੰਜੀ = ਨਿਰਾ;

	ਜੇ ((subsect = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;

	/* Header: key, reserved */
	ਜੇ ((r = sshbuf_get_string_ਸਿੱਧਾ(buf, &blob, &blen)) != 0 ||
	    (r = sshbuf_skip_string(buf)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (blen != 0 && (r = sshkey_from_blob(blob, blen, &ca_ਕੁੰਜੀ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜਦੋਂ (sshbuf_len(buf) > 0) {
		sshbuf_free(subsect);
		subsect = ਨਿਰਾ;
		ਜੇ ((r = sshbuf_get_u8(buf, &type)) != 0 ||
		    (r = sshbuf_froms(buf, &subsect)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		KRL_DBG(("subsection type 0x%02x", type));
		/* sshbuf_dump(subsect, stderr); */

		ਚੋਣ (type) {
		ਹਾਲਤ KRL_SECTION_CERT_SERIAL_LIST:
			ਜਦੋਂ (sshbuf_len(subsect) > 0) {
				ਜੇ ((r = sshbuf_get_u64(subsect, &serial)) != 0)
					ਜਾਓ ਬਾਹਰਲਾ;
				ਜੇ ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_ਕੁੰਜੀ, serial)) != 0)
					ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਰੋਕੋ;
		ਹਾਲਤ KRL_SECTION_CERT_SERIAL_RANGE:
			ਜੇ ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_u64(subsect, &serial_hi)) != 0)
				ਜਾਓ ਬਾਹਰਲਾ;
			ਜੇ ((r = ssh_krl_revoke_cert_by_serial_range(krl,
			    ca_ਕੁੰਜੀ, serial_lo, serial_hi)) != 0)
				ਜਾਓ ਬਾਹਰਲਾ;
			ਰੋਕੋ;
		ਹਾਲਤ KRL_SECTION_CERT_SERIAL_BITMAP:
			ਜੇ ((bitmap = bitmap_new()) == ਨਿਰਾ) {
				r = SSH_ERR_ALLOC_FAIL;
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਜੇ ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_bignum2_ਬਾਈਟਾਂ_ਸਿੱਧਾ(subsect,
			    &blob, &blen)) != 0)
				ਜਾਓ ਬਾਹਰਲਾ;
			ਜੇ (bitmap_from_string(bitmap, blob, blen) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			nbits = bitmap_nbits(bitmap);
			ਲਈ (serial = 0; serial < (uint64_t)nbits; serial++) {
				ਜੇ (serial > 0 && serial_lo + serial == 0) {
					error_f("bitmap wraps u64");
					r = SSH_ERR_INVALID_FORMAT;
					ਜਾਓ ਬਾਹਰਲਾ;
				}
				ਜੇ (!bitmap_test_ਦੋਆਧਾਰੀ_ਅੰਕ(bitmap, serial))
					ਜਾਰੀ;
				ਜੇ ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_ਕੁੰਜੀ, serial_lo + serial)) != 0)
					ਜਾਓ ਬਾਹਰਲਾ;
			}
			bitmap_free(bitmap);
			bitmap = ਨਿਰਾ;
			ਰੋਕੋ;
		ਹਾਲਤ KRL_SECTION_CERT_ਕੁੰਜੀ_ID:
			ਜਦੋਂ (sshbuf_len(subsect) > 0) {
				ਜੇ ((r = sshbuf_get_cstring(subsect,
				    &ਕੁੰਜੀ_id, ਨਿਰਾ)) != 0)
					ਜਾਓ ਬਾਹਰਲਾ;
				ਜੇ ((r = ssh_krl_revoke_cert_by_ਕੁੰਜੀ_id(krl,
				    ca_ਕੁੰਜੀ, ਕੁੰਜੀ_id)) != 0)
					ਜਾਓ ਬਾਹਰਲਾ;
				ਮੁਕਤ(ਕੁੰਜੀ_id);
				ਕੁੰਜੀ_id = ਨਿਰਾ;
			}
			ਰੋਕੋ;
		ਹਾਲਤ KRL_SECTION_CERT_EXTENSION:
			ਜੇ ((r = cert_extension_subsection(subsect, krl)) != 0)
				ਜਾਓ ਬਾਹਰਲਾ;
			ਰੋਕੋ;
		ਮੂਲ:
			error("Unsupported KRL certificate section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (sshbuf_len(subsect) > 0) {
			error("KRL certificate section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}

	r = 0;
 ਬਾਹਰਲਾ:
	ਜੇ (bitmap != ਨਿਰਾ)
		bitmap_free(bitmap);
	ਮੁਕਤ(ਕੁੰਜੀ_id);
	sshkey_free(ca_ਕੁੰਜੀ);
	sshbuf_free(subsect);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
blob_section(ਬਣਤਰ sshbuf *sect, ਬਣਤਰ revoked_blob_ਰੁੱਖ *ਨਿਸ਼ਾਨਾ_ਰੁੱਖ,
    ਮਾਪ_t expected_len)
{
	u_char *rdata = ਨਿਰਾ;
	ਮਾਪ_t rlen = 0;
	ਪੂਰਨ r;

	ਜਦੋਂ (sshbuf_len(sect) > 0) {
		ਜੇ ((r = sshbuf_get_string(sect, &rdata, &rlen)) != 0)
			ਵਾਪਸ r;
		ਜੇ (expected_len != 0 && rlen != expected_len) {
			error_f("bad length");
			ਮੁਕਤ(rdata);
			ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
		}
		ਜੇ ((r = revoke_blob(ਨਿਸ਼ਾਨਾ_ਰੁੱਖ, rdata, rlen)) != 0) {
			ਮੁਕਤ(rdata);
			ਵਾਪਸ r;
		}
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
extension_section(ਬਣਤਰ sshbuf *sect, ਬਣਤਰ ssh_krl *krl)
{
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	u_char critical = 1;
	ਬਣਤਰ sshbuf *ਮੁੱਲ = ਨਿਰਾ;
	ਅੱਖਰ *name = ਨਿਰਾ;

	ਜੇ ((r = sshbuf_get_cstring(sect, &name, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_u8(sect, &critical)) != 0 ||
	    (r = sshbuf_froms(sect, &ਮੁੱਲ)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid extension section");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshbuf_len(sect) != 0) {
		error("KRL has invalid extension section: trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	debug_f("extension %s critical %u len %zu",
	    name, critical, sshbuf_len(ਮੁੱਲ));
	/* no extensions are currently supported */
	ਜੇ (critical) {
		error("KRL contains unsupported critical section \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(name);
	sshbuf_free(ਮੁੱਲ);
	ਵਾਪਸ r;
}

/* Attempt to parse a KRL */
ਪੂਰਨ
ssh_krl_from_blob(ਬਣਤਰ sshbuf *buf, ਬਣਤਰ ssh_krl **krlp)
{
	ਬਣਤਰ sshbuf *copy = ਨਿਰਾ, *sect = ਨਿਰਾ;
	ਬਣਤਰ ssh_krl *krl = ਨਿਰਾ;
	ਅੱਖਰ timestamp[64];
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	u_char type;
	u_int format_ਸੰਸਕਰਣ;

	*krlp = ਨਿਰਾ;

	/* KRL must begin with magic string */
	ਜੇ ((r = sshbuf_cmp(buf, 0, KRL_MAGIC, ਆਕਾਰ(KRL_MAGIC) - 1)) != 0) {
		debug2_f("bad KRL magic header");
		ਵਾਪਸ SSH_ERR_KRL_BAD_MAGIC;
	}

	ਜੇ ((krl = ssh_krl_init()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		error_f("alloc failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* Don't modify buffer */
	ਜੇ ((copy = sshbuf_fromb(buf)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_consume(copy, ਆਕਾਰ(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_get_u32(copy, &format_ਸੰਸਕਰਣ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (format_ਸੰਸਕਰਣ != KRL_FORMAT_ਸੰਸਕਰਣ) {
		error_f("unsupported KRL format version %u", format_ਸੰਸਕਰਣ);
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_get_u64(copy, &krl->krl_ਸੰਸਕਰਣ)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->generated_date)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->flags)) != 0 ||
	    (r = sshbuf_skip_string(copy)) != 0 ||
	    (r = sshbuf_get_cstring(copy, &krl->comment, ਨਿਰਾ)) != 0) {
		error_fr(r, "parse KRL header");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	format_timestamp(krl->generated_date, timestamp, ਆਕਾਰ(timestamp));
	debug("KRL version %llu generated at %s%s%s",
	    (ਲੰਮਾ ਲੰਮਾ ਬਿਨਾਨਿਸ਼ਾਨੀ)krl->krl_ਸੰਸਕਰਣ, timestamp,
	    *krl->comment ? ": " : "", krl->comment);

	/* Parse and load the KRL sections. */
	ਜਦੋਂ (sshbuf_len(copy) > 0) {
		sshbuf_free(sect);
		sect = ਨਿਰਾ;
		ਜੇ ((r = sshbuf_get_u8(copy, &type)) != 0 ||
		    (r = sshbuf_froms(copy, &sect)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		KRL_DBG(("section 0x%02x", type));

		ਚੋਣ (type) {
		ਹਾਲਤ KRL_SECTION_CERTIFICATES:
			ਜੇ ((r = parse_revoked_certs(sect, krl)) != 0)
				ਜਾਓ ਬਾਹਰਲਾ;
			ਰੋਕੋ;
		ਹਾਲਤ KRL_SECTION_EXPLICIT_ਕੁੰਜੀ:
			ਜੇ ((r = blob_section(sect,
			    &krl->revoked_ਕੁੰਜੀਆਂ, 0)) != 0)
				ਜਾਓ ਬਾਹਰਲਾ;
			ਰੋਕੋ;
		ਹਾਲਤ KRL_SECTION_FINGERPRINT_SHA1:
			ਜੇ ((r = blob_section(sect,
			    &krl->revoked_sha1s, 20)) != 0)
				ਜਾਓ ਬਾਹਰਲਾ;
			ਰੋਕੋ;
		ਹਾਲਤ KRL_SECTION_FINGERPRINT_SHA256:
			ਜੇ ((r = blob_section(sect,
			    &krl->revoked_sha256s, 32)) != 0)
				ਜਾਓ ਬਾਹਰਲਾ;
			ਰੋਕੋ;
		ਹਾਲਤ KRL_SECTION_EXTENSION:
			ਜੇ ((r = extension_section(sect, krl)) != 0)
				ਜਾਓ ਬਾਹਰਲਾ;
			ਰੋਕੋ;
		ਹਾਲਤ KRL_SECTION_SIGNATURE:
			/* Handled above, but still need to stay in synch */
			sshbuf_free(sect);
			sect = ਨਿਰਾ;
			ਜੇ ((r = sshbuf_skip_string(copy)) != 0)
				ਜਾਓ ਬਾਹਰਲਾ;
			ਰੋਕੋ;
		ਮੂਲ:
			error("Unsupported KRL section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (sect != ਨਿਰਾ && sshbuf_len(sect) > 0) {
			error("KRL section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}

	/* Success */
	*krlp = krl;
	r = 0;
 ਬਾਹਰਲਾ:
	ਜੇ (r != 0)
		ssh_krl_free(krl);
	sshbuf_free(copy);
	sshbuf_free(sect);
	ਵਾਪਸ r;
}

/* Checks certificate serial number and key ID revocation */
ਸਥਿਰ ਪੂਰਨ
is_cert_revoked(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ revoked_certs *rc)
{
	ਬਣਤਰ revoked_serial rs, *ers;
	ਬਣਤਰ revoked_ਕੁੰਜੀ_id rki, *erki;

	/* Check revocation by cert key ID */
	memset(&rki, 0, ਆਕਾਰ(rki));
	rki.ਕੁੰਜੀ_id = ਕੁੰਜੀ->cert->ਕੁੰਜੀ_id;
	erki = RB_ਲੱਭੋ(revoked_ਕੁੰਜੀ_id_ਰੁੱਖ, &rc->revoked_ਕੁੰਜੀ_ids, &rki);
	ਜੇ (erki != ਨਿਰਾ) {
		KRL_DBG(("revoked by key ID"));
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_REVOKED;
	}

	/*
	 * Zero serials numbers are ignored (it's the default when the
	 * CA doesn't specify one).
	 */
	ਜੇ (ਕੁੰਜੀ->cert->serial == 0)
		ਵਾਪਸ 0;

	memset(&rs, 0, ਆਕਾਰ(rs));
	rs.lo = rs.hi = ਕੁੰਜੀ->cert->serial;
	ers = RB_ਲੱਭੋ(revoked_serial_ਰੁੱਖ, &rc->revoked_serials, &rs);
	ਜੇ (ers != ਨਿਰਾ) {
		KRL_DBG(("revoked serial %llu matched %llu:%llu",
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਕੁੰਜੀ->cert->serial,
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ers->lo,
		    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ers->hi));
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_REVOKED;
	}
	ਵਾਪਸ 0;
}

/* Checks whether a given key/cert is revoked. Does not check its CA */
ਸਥਿਰ ਪੂਰਨ
is_ਕੁੰਜੀ_revoked(ਬਣਤਰ ssh_krl *krl, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਬਣਤਰ revoked_blob rb, *erb;
	ਬਣਤਰ revoked_certs *rc;
	ਪੂਰਨ r;

	/* Check explicitly revoked hashes first */
	memset(&rb, 0, ਆਕਾਰ(rb));
	ਜੇ ((r = sshkey_fingerprint_raw(ਕੁੰਜੀ, SSH_DIGEST_SHA1,
	    &rb.blob, &rb.len)) != 0)
		ਵਾਪਸ r;
	erb = RB_ਲੱਭੋ(revoked_blob_ਰੁੱਖ, &krl->revoked_sha1s, &rb);
	ਮੁਕਤ(rb.blob);
	ਜੇ (erb != ਨਿਰਾ) {
		KRL_DBG(("revoked by key SHA1"));
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_REVOKED;
	}
	memset(&rb, 0, ਆਕਾਰ(rb));
	ਜੇ ((r = sshkey_fingerprint_raw(ਕੁੰਜੀ, SSH_DIGEST_SHA256,
	    &rb.blob, &rb.len)) != 0)
		ਵਾਪਸ r;
	erb = RB_ਲੱਭੋ(revoked_blob_ਰੁੱਖ, &krl->revoked_sha256s, &rb);
	ਮੁਕਤ(rb.blob);
	ਜੇ (erb != ਨਿਰਾ) {
		KRL_DBG(("revoked by key SHA256"));
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_REVOKED;
	}

	/* Next, explicit keys */
	memset(&rb, 0, ਆਕਾਰ(rb));
	ਜੇ ((r = plain_ਕੁੰਜੀ_blob(ਕੁੰਜੀ, &rb.blob, &rb.len)) != 0)
		ਵਾਪਸ r;
	erb = RB_ਲੱਭੋ(revoked_blob_ਰੁੱਖ, &krl->revoked_ਕੁੰਜੀਆਂ, &rb);
	ਮੁਕਤ(rb.blob);
	ਜੇ (erb != ਨਿਰਾ) {
		KRL_DBG(("revoked by explicit key"));
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_REVOKED;
	}

	ਜੇ (!sshkey_is_cert(ਕੁੰਜੀ))
		ਵਾਪਸ 0;

	/* Check cert revocation for the specified CA */
	ਜੇ ((r = revoked_certs_for_ca_ਕੁੰਜੀ(krl, ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ,
	    &rc, 0)) != 0)
		ਵਾਪਸ r;
	ਜੇ (rc != ਨਿਰਾ) {
		ਜੇ ((r = is_cert_revoked(ਕੁੰਜੀ, rc)) != 0)
			ਵਾਪਸ r;
	}
	/* Check cert revocation for the wildcard CA */
	ਜੇ ((r = revoked_certs_for_ca_ਕੁੰਜੀ(krl, ਨਿਰਾ, &rc, 0)) != 0)
		ਵਾਪਸ r;
	ਜੇ (rc != ਨਿਰਾ) {
		ਜੇ ((r = is_cert_revoked(ਕੁੰਜੀ, rc)) != 0)
			ਵਾਪਸ r;
	}

	KRL_DBG(("%llu no match", (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)ਕੁੰਜੀ->cert->serial));
	ਵਾਪਸ 0;
}

ਪੂਰਨ
ssh_krl_check_ਕੁੰਜੀ(ਬਣਤਰ ssh_krl *krl, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਪੂਰਨ r;

	KRL_DBG(("checking key"));
	ਜੇ ((r = is_ਕੁੰਜੀ_revoked(krl, ਕੁੰਜੀ)) != 0)
		ਵਾਪਸ r;
	ਜੇ (sshkey_is_cert(ਕੁੰਜੀ)) {
		debug2_f("checking CA key");
		ਜੇ ((r = is_ਕੁੰਜੀ_revoked(krl, ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ)) != 0)
			ਵਾਪਸ r;
	}
	KRL_DBG(("key okay"));
	ਵਾਪਸ 0;
}

ਪੂਰਨ
ssh_krl_file_ਸ਼ਾਮਲ_ਹੈ_ਕੁੰਜੀ(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਬਣਤਰ sshbuf *krlbuf = ਨਿਰਾ;
	ਬਣਤਰ ssh_krl *krl = ਨਿਰਾ;
	ਪੂਰਨ oerrno = 0, r;

	ਜੇ (ਰਸਤਾ == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ ((r = sshbuf_ਲੱਦੋ_file(ਰਸਤਾ, &krlbuf)) != 0) {
		oerrno = errno;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = ssh_krl_from_blob(krlbuf, &krl)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	debug2_f("checking KRL %s", ਰਸਤਾ);
	r = ssh_krl_check_ਕੁੰਜੀ(krl, ਕੁੰਜੀ);
 ਬਾਹਰਲਾ:
	sshbuf_free(krlbuf);
	ssh_krl_free(krl);
	ਜੇ (r != 0)
		errno = oerrno;
	ਵਾਪਸ r;
}

ਪੂਰਨ
krl_dump(ਬਣਤਰ ssh_krl *krl, FILE *f)
{
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਬਣਤਰ revoked_blob *rb;
	ਬਣਤਰ revoked_certs *rc;
	ਬਣਤਰ revoked_serial *rs;
	ਬਣਤਰ revoked_ਕੁੰਜੀ_id *rki;
	ਪੂਰਨ r, ret = 0;
	ਅੱਖਰ *fp, timestamp[64];

	/* Try to print in a KRL spec-compatible format */
	format_timestamp(krl->generated_date, timestamp, ਆਕਾਰ(timestamp));
	fprintf(f, "# KRL version %llu\n", (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)krl->krl_ਸੰਸਕਰਣ);
	fprintf(f, "# Generated at %s\n", timestamp);
	ਜੇ (krl->comment != ਨਿਰਾ && *krl->comment != '\0') {
		r = ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ;
		asmprintf(&fp, ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ, &r, "%s", krl->comment);
		fprintf(f, "# Comment: %s\n", fp);
		ਮੁਕਤ(fp);
	}
	fputc('\n', f);

	RB_FOREACH(rb, revoked_blob_ਰੁੱਖ, &krl->revoked_ਕੁੰਜੀਆਂ) {
		ਜੇ ((r = sshkey_from_blob(rb->blob, rb->len, &ਕੁੰਜੀ)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			error_r(r, "parse KRL key");
			ਜਾਰੀ;
		}
		ਜੇ ((fp = sshkey_fingerprint(ਕੁੰਜੀ, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ਨਿਰਾ) {
			ret = SSH_ERR_INVALID_FORMAT;
			error("sshkey_fingerprint failed");
			ਜਾਰੀ;
		}
		fprintf(f, "hash: %s # %s\n", fp, sshkey_ssh_name(ਕੁੰਜੀ));
		ਮੁਕਤ(fp);
		ਮੁਕਤ(ਕੁੰਜੀ);
	}
	RB_FOREACH(rb, revoked_blob_ਰੁੱਖ, &krl->revoked_sha256s) {
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "hash: SHA256:%s\n", fp);
		ਮੁਕਤ(fp);
	}
	RB_FOREACH(rb, revoked_blob_ਰੁੱਖ, &krl->revoked_sha1s) {
		/*
		 * There is not KRL spec keyword for raw SHA1 hashes, so
		 * print them as comments.
		 */
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "# hash SHA1:%s\n", fp);
		ਮੁਕਤ(fp);
	}

	TAILQ_FOREACH(rc, &krl->revoked_certs, ਇੰਦਰਾਜ) {
		fputc('\n', f);
		ਜੇ (rc->ca_ਕੁੰਜੀ == ਨਿਰਾ)
			fprintf(f, "# Wildcard CA\n");
		ਨਹੀਂਤਾਂ {
			ਜੇ ((fp = sshkey_fingerprint(rc->ca_ਕੁੰਜੀ,
			    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ਨਿਰਾ) {
				ret = SSH_ERR_INVALID_FORMAT;
				error("sshkey_fingerprint failed");
				ਜਾਰੀ;
			}
			fprintf(f, "# CA key %s %s\n",
			    sshkey_ssh_name(rc->ca_ਕੁੰਜੀ), fp);
			ਮੁਕਤ(fp);
		}
		RB_FOREACH(rs, revoked_serial_ਰੁੱਖ, &rc->revoked_serials) {
			ਜੇ (rs->lo == rs->hi) {
				fprintf(f, "serial: %llu\n",
				    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)rs->lo);
			} ਨਹੀਂਤਾਂ {
				fprintf(f, "serial: %llu-%llu\n",
				    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)rs->lo,
				    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)rs->hi);
			}
		}
		RB_FOREACH(rki, revoked_ਕੁੰਜੀ_id_ਰੁੱਖ, &rc->revoked_ਕੁੰਜੀ_ids) {
			/*
			 * We don't want key IDs with embedded newlines to
			 * mess up the display.
			 */
			r = ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ;
			asmprintf(&fp, ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ, &r, "%s", rki->ਕੁੰਜੀ_id);
			fprintf(f, "id: %s\n", fp);
			ਮੁਕਤ(fp);
		}
	}
	ਵਾਪਸ ret;
}
