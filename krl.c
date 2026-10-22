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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/tree.h>
#ଅନ୍ତର୍ଭାଵ <sys/queue.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <time.h>

#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "bitmap.h"
#ଅନ୍ତର୍ଭାଵ "utf8.h"

#ଅନ୍ତର୍ଭାଵ "krl.h"

/* #define DEBUG_KRL */
#ifdef DEBUG_KRL
# define KRL_DBG(x) debug3_f x
#ଅନ୍ୟଥା
# define KRL_DBG(x)
#endif

/*
 * Trees of revoked serial numbers, key IDs and keys. This allows
 * quick searching, querying and producing lists in canonical order.
 */

/* Tree of serial numbers. XXX make smarter: really need a real sparse bitmap */
ସଂରଚନା revoked_serial {
	uint64_t lo, hi;
	RB_ENTRY(revoked_serial) ବୃକ୍ଷ_entry;
};
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା serial_cmp(ସଂରଚନା revoked_serial *a, ସଂରଚନା revoked_serial *b);
RB_HEAD(revoked_serial_ବୃକ୍ଷ, revoked_serial);
RB_GENERATE_STATIC(revoked_serial_ବୃକ୍ଷ, revoked_serial, ବୃକ୍ଷ_entry, serial_cmp)

/* Tree of key IDs */
ସଂରଚନା revoked_ଚାବି_id {
	ଅକ୍ଷର *ଚାବି_id;
	RB_ENTRY(revoked_ଚାବି_id) ବୃକ୍ଷ_entry;
};
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା ଚାବି_id_cmp(ସଂରଚନା revoked_ଚାବି_id *a, ସଂରଚନା revoked_ଚାବି_id *b);
RB_HEAD(revoked_ଚାବି_id_ବୃକ୍ଷ, revoked_ଚାବି_id);
RB_GENERATE_STATIC(revoked_ଚାବି_id_ବୃକ୍ଷ, revoked_ଚାବି_id, ବୃକ୍ଷ_entry, ଚାବି_id_cmp)

/* Tree of blobs (used for keys and fingerprints) */
ସଂରଚନା revoked_blob {
	u_char *blob;
	size_t len;
	RB_ENTRY(revoked_blob) ବୃକ୍ଷ_entry;
};
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା blob_cmp(ସଂରଚନା revoked_blob *a, ସଂରଚନା revoked_blob *b);
RB_HEAD(revoked_blob_ବୃକ୍ଷ, revoked_blob);
RB_GENERATE_STATIC(revoked_blob_ବୃକ୍ଷ, revoked_blob, ବୃକ୍ଷ_entry, blob_cmp)

/* Tracks revoked certs for a single CA */
ସଂରଚନା revoked_certs {
	ସଂରଚନା sshkey *ca_ଚାବି;
	ସଂରଚନା revoked_serial_ବୃକ୍ଷ revoked_serials;
	ସଂରଚନା revoked_ଚାବି_id_ବୃକ୍ଷ revoked_ଚାବି_ids;
	TAILQ_ENTRY(revoked_certs) entry;
};
TAILQ_HEAD(revoked_certs_list, revoked_certs);

ସଂରଚନା ssh_krl {
	uint64_t krl_version;
	uint64_t generated_date;
	uint64_t flags;
	ଅକ୍ଷର *comment;
	ସଂରଚନା revoked_blob_ବୃକ୍ଷ revoked_ଚାବିଗୁଡ଼ିକ;
	ସଂରଚନା revoked_blob_ବୃକ୍ଷ revoked_sha1s;
	ସଂରଚନା revoked_blob_ବୃକ୍ଷ revoked_sha256s;
	ସଂରଚନା revoked_certs_list revoked_certs;
};

/* Return equal if a and b overlap */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
serial_cmp(ସଂରଚନା revoked_serial *a, ସଂରଚନା revoked_serial *b)
{
	ଯଦି (a->hi >= b->lo && a->lo <= b->hi)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ a->lo < b->lo ? -1 : 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ଚାବି_id_cmp(ସଂରଚନା revoked_ଚାବି_id *a, ସଂରଚନା revoked_ଚାବି_id *b)
{
	ଫେରନ୍ତୁ strcmp(a->ଚାବି_id, b->ଚାବି_id);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
blob_cmp(ସଂରଚନା revoked_blob *a, ସଂରଚନା revoked_blob *b)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (a->len != b->len) {
		ଯଦି ((r = memcmp(a->blob, b->blob, MINIMUM(a->len, b->len))) != 0)
			ଫେରନ୍ତୁ r;
		ଫେରନ୍ତୁ a->len > b->len ? 1 : -1;
	} ଅନ୍ୟଥା
		ଫେରନ୍ତୁ memcmp(a->blob, b->blob, a->len);
}

ସଂରଚନା ssh_krl *
ssh_krl_init(ଶୂନ୍ୟ)
{
	ସଂରଚନା ssh_krl *krl;

	ଯଦି ((krl = calloc(1, ଆକାର(*krl))) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	RB_INIT(&krl->revoked_ଚାବିଗୁଡ଼ିକ);
	RB_INIT(&krl->revoked_sha1s);
	RB_INIT(&krl->revoked_sha256s);
	TAILQ_INIT(&krl->revoked_certs);
	ଫେରନ୍ତୁ krl;
}

ସ୍ଥିର ଶୂନ୍ୟ
revoked_certs_free(ସଂରଚନା revoked_certs *rc)
{
	ସଂରଚନା revoked_serial *rs, *trs;
	ସଂରଚନା revoked_ଚାବି_id *rki, *trki;

	ଯଦି (rc == ଖାଲି)
		ଫେରନ୍ତୁ;
	RB_FOREACH_SAFE(rs, revoked_serial_ବୃକ୍ଷ, &rc->revoked_serials, trs) {
		RB_REMOVE(revoked_serial_ବୃକ୍ଷ, &rc->revoked_serials, rs);
		ମୁକ୍ତ(rs);
	}
	RB_FOREACH_SAFE(rki, revoked_ଚାବି_id_ବୃକ୍ଷ, &rc->revoked_ଚାବି_ids, trki) {
		RB_REMOVE(revoked_ଚାବି_id_ବୃକ୍ଷ, &rc->revoked_ଚାବି_ids, rki);
		ମୁକ୍ତ(rki->ଚାବି_id);
		ମୁକ୍ତ(rki);
	}
	sshkey_free(rc->ca_ଚାବି);
	freezero(rc, ଆକାର(*rc));
}

ଶୂନ୍ୟ
ssh_krl_free(ସଂରଚନା ssh_krl *krl)
{
	ସଂରଚନା revoked_blob *rb, *trb;
	ସଂରଚନା revoked_certs *rc, *trc;

	ଯଦି (krl == ଖାଲି)
		ଫେରନ୍ତୁ;

	ମୁକ୍ତ(krl->comment);
	RB_FOREACH_SAFE(rb, revoked_blob_ବୃକ୍ଷ, &krl->revoked_ଚାବିଗୁଡ଼ିକ, trb) {
		RB_REMOVE(revoked_blob_ବୃକ୍ଷ, &krl->revoked_ଚାବିଗୁଡ଼ିକ, rb);
		ମୁକ୍ତ(rb->blob);
		ମୁକ୍ତ(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_ବୃକ୍ଷ, &krl->revoked_sha1s, trb) {
		RB_REMOVE(revoked_blob_ବୃକ୍ଷ, &krl->revoked_sha1s, rb);
		ମୁକ୍ତ(rb->blob);
		ମୁକ୍ତ(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_ବୃକ୍ଷ, &krl->revoked_sha256s, trb) {
		RB_REMOVE(revoked_blob_ବୃକ୍ଷ, &krl->revoked_sha256s, rb);
		ମୁକ୍ତ(rb->blob);
		ମୁକ୍ତ(rb);
	}
	TAILQ_FOREACH_SAFE(rc, &krl->revoked_certs, entry, trc) {
		TAILQ_REMOVE(&krl->revoked_certs, rc, entry);
		revoked_certs_free(rc);
	}
	ମୁକ୍ତ(krl);
}

ଶୂନ୍ୟ
ssh_krl_set_version(ସଂରଚନା ssh_krl *krl, uint64_t version)
{
	krl->krl_version = version;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_krl_set_comment(ସଂରଚନା ssh_krl *krl, ଅଚଳ ଅକ୍ଷର *comment)
{
	ମୁକ୍ତ(krl->comment);
	ଯଦି ((krl->comment = strdup(comment)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଫେରନ୍ତୁ 0;
}

/*
 * Find the revoked_certs struct for a CA key. If allow_create is set then
 * create a new one in the tree if one did not exist already.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
revoked_certs_for_ca_ଚାବି(ସଂରଚନା ssh_krl *krl, ଅଚଳ ସଂରଚନା sshkey *ca_ଚାବି,
    ସଂରଚନା revoked_certs **rcp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା allow_create)
{
	ସଂରଚନା revoked_certs *rc;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	*rcp = ଖାଲି;
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		ଯଦି ((ca_ଚାବି == ଖାଲି && rc->ca_ଚାବି == ଖାଲି) ||
		    sshkey_equal(rc->ca_ଚାବି, ca_ଚାବି)) {
			*rcp = rc;
			ଫେରନ୍ତୁ 0;
		}
	}
	ଯଦି (!allow_create)
		ଫେରନ୍ତୁ 0;
	/* If this CA doesn't exist in the list then add it now */
	ଯଦି ((rc = calloc(1, ଆକାର(*rc))) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି (ca_ଚାବି == ଖାଲି)
		rc->ca_ଚାବି = ଖାଲି;
	ଅନ୍ୟଥା ଯଦି ((r = sshkey_from_private(ca_ଚାବି, &rc->ca_ଚାବି)) != 0) {
		ମୁକ୍ତ(rc);
		ଫେରନ୍ତୁ r;
	}
	RB_INIT(&rc->revoked_serials);
	RB_INIT(&rc->revoked_ଚାବି_ids);
	TAILQ_INSERT_TAIL(&krl->revoked_certs, rc, entry);
	KRL_DBG(("new CA %s", ca_ଚାବି == ଖାଲି ? "*" : sshkey_type(ca_ଚାବି)));
	*rcp = rc;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ଭର୍ତ୍ତି_serial_range(ସଂରଚନା revoked_serial_ବୃକ୍ଷ *rt, uint64_t lo, uint64_t hi)
{
	ସଂରଚନା revoked_serial rs, *ers, *crs, *irs;

	KRL_DBG(("insert %llu:%llu",
	    (unsigned long long)lo, (unsigned long long)hi));
	memset(&rs, 0, ଆକାର(rs));
	rs.lo = lo;
	rs.hi = hi;
	ers = RB_NFIND(revoked_serial_ବୃକ୍ଷ, rt, &rs);
	ଯଦି (ers == ଖାଲି || serial_cmp(ers, &rs) != 0) {
		/* No entry matches. Just insert */
		ଯଦି ((irs = malloc(ଆକାର(rs))) == ଖାଲି)
			ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
		memcpy(irs, &rs, ଆକାର(*irs));
		ers = RB_ଭର୍ତ୍ତି(revoked_serial_ବୃକ୍ଷ, rt, irs);
		ଯଦି (ers != ଖାଲି) {
			KRL_DBG(("bad: ers != NULL"));
			/* Shouldn't happen */
			ମୁକ୍ତ(irs);
			ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
		}
		ers = irs;
	} ଅନ୍ୟଥା {
		KRL_DBG(("overlap found %llu:%llu",
		    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
		/*
		 * The inserted entry overlaps an existing one. Grow the
		 * existing entry.
		 */
		ଯଦି (ers->lo > lo)
			ers->lo = lo;
		ଯଦି (ers->hi < hi)
			ers->hi = hi;
	}

	/*
	 * The inserted or revised range might overlap or abut adjacent ones;
	 * coalesce as necessary.
	 */

	/* Check predecessors */
	ଯେତେବେଳେ ((crs = RB_PREV(revoked_serial_ବୃକ୍ଷ, rt, ers)) != ଖାଲି) {
		KRL_DBG(("pred %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		ଯଦି (ers->lo != 0 && crs->hi < ers->lo - 1)
			ଭାଙ୍ଗ;
		/* This entry overlaps. */
		ଯଦି (crs->lo < ers->lo) {
			ers->lo = crs->lo;
			KRL_DBG(("pred extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_ବୃକ୍ଷ, rt, crs);
		ମୁକ୍ତ(crs);
	}
	/* Check successors */
	ଯେତେବେଳେ ((crs = RB_NEXT(revoked_serial_ବୃକ୍ଷ, rt, ers)) != ଖାଲି) {
		KRL_DBG(("succ %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		ଯଦି (ers->hi != (uint64_t)-1 && crs->lo > ers->hi + 1)
			ଭାଙ୍ଗ;
		/* This entry overlaps. */
		ଯଦି (crs->hi > ers->hi) {
			ers->hi = crs->hi;
			KRL_DBG(("succ extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_ବୃକ୍ଷ, rt, crs);
		ମୁକ୍ତ(crs);
	}
	KRL_DBG(("done, final %llu:%llu",
	    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_krl_revoke_cert_by_serial(ସଂରଚନା ssh_krl *krl, ଅଚଳ ସଂରଚନା sshkey *ca_ଚାବି,
    uint64_t serial)
{
	ଫେରନ୍ତୁ ssh_krl_revoke_cert_by_serial_range(krl, ca_ଚାବି, serial, serial);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_krl_revoke_cert_by_serial_range(ସଂରଚନା ssh_krl *krl,
    ଅଚଳ ସଂରଚନା sshkey *ca_ଚାବି, uint64_t lo, uint64_t hi)
{
	ସଂରଚନା revoked_certs *rc;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (lo > hi || lo == 0)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି ((r = revoked_certs_for_ca_ଚାବି(krl, ca_ଚାବି, &rc, 1)) != 0)
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ ଭର୍ତ୍ତି_serial_range(&rc->revoked_serials, lo, hi);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_krl_revoke_cert_by_ଚାବି_id(ସଂରଚନା ssh_krl *krl, ଅଚଳ ସଂରଚନା sshkey *ca_ଚାବି,
    ଅଚଳ ଅକ୍ଷର *ଚାବି_id)
{
	ସଂରଚନା revoked_ଚାବି_id *rki, *erki;
	ସଂରଚନା revoked_certs *rc;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = revoked_certs_for_ca_ଚାବି(krl, ca_ଚାବି, &rc, 1)) != 0)
		ଫେରନ୍ତୁ r;

	KRL_DBG(("revoke %s", ଚାବି_id));
	ଯଦି ((rki = calloc(1, ଆକାର(*rki))) == ଖାଲି ||
	    (rki->ଚାବି_id = strdup(ଚାବି_id)) == ଖାଲି) {
		ମୁକ୍ତ(rki);
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	}
	erki = RB_ଭର୍ତ୍ତି(revoked_ଚାବି_id_ବୃକ୍ଷ, &rc->revoked_ଚାବି_ids, rki);
	ଯଦି (erki != ଖାଲି) {
		ମୁକ୍ତ(rki->ଚାବି_id);
		ମୁକ୍ତ(rki);
	}
	ଫେରନ୍ତୁ 0;
}

/* Convert "key" to a public key blob without any certificate information */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
plain_ଚାବି_blob(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, u_char **blob, size_t *blen)
{
	ସଂରଚନା sshkey *kcopy;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshkey_from_private(ଚାବି, &kcopy)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (sshkey_is_cert(kcopy)) {
		ଯଦି ((r = sshkey_drop_cert(kcopy)) != 0) {
			sshkey_free(kcopy);
			ଫେରନ୍ତୁ r;
		}
	}
	r = sshkey_to_blob(kcopy, blob, blen);
	sshkey_free(kcopy);
	ଫେରନ୍ତୁ r;
}

/* Revoke a key blob. Ownership of blob is transferred to the tree */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
revoke_blob(ସଂରଚନା revoked_blob_ବୃକ୍ଷ *rbt, u_char *blob, size_t len)
{
	ସଂରଚନା revoked_blob *rb, *erb;

	ଯଦି ((rb = calloc(1, ଆକାର(*rb))) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	rb->blob = blob;
	rb->len = len;
	erb = RB_ଭର୍ତ୍ତି(revoked_blob_ବୃକ୍ଷ, rbt, rb);
	ଯଦି (erb != ଖାଲି) {
		ମୁକ୍ତ(rb->blob);
		ମୁକ୍ତ(rb);
	}
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_krl_revoke_ଚାବି_explicit(ସଂରଚନା ssh_krl *krl, ଅଚଳ ସଂରଚନା sshkey *ଚାବି)
{
	u_char *blob;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	debug3_f("revoke type %s", sshkey_type(ଚାବି));
	ଯଦି ((r = plain_ଚାବି_blob(ଚାବି, &blob, &len)) != 0)
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ revoke_blob(&krl->revoked_ଚାବିଗୁଡ଼ିକ, blob, len);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
revoke_by_hash(ସଂରଚନା revoked_blob_ବୃକ୍ଷ *target, ଅଚଳ u_char *p, size_t len)
{
	u_char *blob;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	/* need to copy hash, as revoke_blob steals ownership */
	ଯଦି ((blob = malloc(len)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
	memcpy(blob, p, len);
	ଯଦି ((r = revoke_blob(target, blob, len)) != 0) {
		ମୁକ୍ତ(blob);
		ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_krl_revoke_ଚାବି_sha1(ସଂରଚନା ssh_krl *krl, ଅଚଳ u_char *p, size_t len)
{
	debug3_f("revoke by sha1");
	ଯଦି (len != 20)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	ଫେରନ୍ତୁ revoke_by_hash(&krl->revoked_sha1s, p, len);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_krl_revoke_ଚାବି_sha256(ସଂରଚନା ssh_krl *krl, ଅଚଳ u_char *p, size_t len)
{
	debug3_f("revoke by sha256");
	ଯଦି (len != 32)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	ଫେରନ୍ତୁ revoke_by_hash(&krl->revoked_sha256s, p, len);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_krl_revoke_ଚାବି(ସଂରଚନା ssh_krl *krl, ଅଚଳ ସଂରଚନା sshkey *ଚାବି)
{
	/* XXX replace with SHA256? */
	ଯଦି (!sshkey_is_cert(ଚାବି))
		ଫେରନ୍ତୁ ssh_krl_revoke_ଚାବି_explicit(krl, ଚାବି);

	ଯଦି (ଚାବି->cert->serial == 0) {
		ଫେରନ୍ତୁ ssh_krl_revoke_cert_by_ଚାବି_id(krl,
		    ଚାବି->cert->signature_ଚାବି,
		    ଚାବି->cert->ଚାବି_id);
	} ଅନ୍ୟଥା {
		ଫେରନ୍ତୁ ssh_krl_revoke_cert_by_serial(krl,
		    ଚାବି->cert->signature_ଚାବି,
		    ଚାବି->cert->serial);
	}
}

/*
 * Select the most compact section type to emit next in a KRL based on
 * the current section type, the run length of contiguous revoked serial
 * numbers and the gaps from the last and to the next revoked serial.
 * Applies a mostly-accurate bit cost model to select the section type
 * that will minimise the size of the resultant KRL.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
choose_next_state(ପୂର୍ଣ୍ଣସଂଖ୍ୟା current_state, uint64_t contig, ପୂର୍ଣ୍ଣସଂଖ୍ୟା final,
    uint64_t last_gap, uint64_t next_gap, size_t bitmap_len,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା *force_new_section)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା new_state;
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
	ବାଛ (current_state) {
	ସ୍ଥିତି KRL_SECTION_CERT_SERIAL_LIST:
		cost_bitmap_restart = cost_bitmap = 8 + 64;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KRL_SECTION_CERT_SERIAL_BITMAP:
		cost_list = 8;
		cost_bitmap_restart = 8 + 64;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି KRL_SECTION_CERT_SERIAL_RANGE:
	ସ୍ଥିତି 0:
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
	ଯଦି (bitmap_len + cost_bitmap >= SSHBUF_MAX_BIGNUM) {
		KRL_DBG(("bitmap overfull len=%zu cost=%llu max=%u",
		    bitmap_len, (unsigned long long)cost_bitmap,
		    SSHBUF_MAX_BIGNUM));
		cost_bitmap = (uint64_t)-1;
	}

	/* Now pick the best choice */
	*force_new_section = 0;
	new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
	cost = cost_bitmap;
	ଯଦି (cost_range < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_RANGE;
		cost = cost_range;
	}
	ଯଦି (cost_list < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_LIST;
		cost = cost_list;
	}
	ଯଦି (cost_bitmap_restart < cost) {
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
	ଫେରନ୍ତୁ new_state;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
put_bitmap(ସଂରଚନା sshbuf *buf, ସଂରଚନା bitmap *bitmap)
{
	size_t len;
	u_char *blob;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	len = bitmap_nbytes(bitmap);
	ଯଦି ((blob = malloc(len)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି (bitmap_to_string(bitmap, blob, len) != 0) {
		ମୁକ୍ତ(blob);
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	r = sshbuf_put_bignum2_bytes(buf, blob, len);
	ମୁକ୍ତ(blob);
	ଫେରନ୍ତୁ r;
}

/* Generate a KRL_SECTION_CERTIFICATES KRL section */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
revoked_certs_generate(ସଂରଚନା revoked_certs *rc, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା final, force_new_sect, r = SSH_ERR_INTERNAL_ERROR;
	uint64_t i, contig, gap, last = 0, bitmap_start = 0;
	ସଂରଚନା revoked_serial *rs, *nrs;
	ସଂରଚନା revoked_ଚାବି_id *rki;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା next_state, state = 0;
	size_t bitmap_len;
	ସଂରଚନା sshbuf *sect;
	ସଂରଚନା bitmap *bitmap = ଖାଲି;

	ଯଦି ((sect = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;

	/* Store the header: optional CA scope key, reserved */
	ଯଦି (rc->ca_ଚାବି == ଖାଲି) {
		ଯଦି ((r = sshbuf_put_string(buf, ଖାଲି, 0)) != 0)
			ଯାଅ out;
	} ଅନ୍ୟଥା {
		ଯଦି ((r = sshkey_puts(rc->ca_ଚାବି, buf)) != 0)
			ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put_string(buf, ଖାଲି, 0)) != 0)
		ଯାଅ out;

	/* Store the revoked serials.  */
	ପାଇଁ (rs = RB_MIN(revoked_serial_ବୃକ୍ଷ, &rc->revoked_serials);
	     rs != ଖାଲି;
	     rs = RB_NEXT(revoked_serial_ବୃକ୍ଷ, &rc->revoked_serials, rs)) {
		KRL_DBG(("serial %llu:%llu state 0x%02x",
		    (long long unsigned)rs->lo, (long long unsigned)rs->hi,
		    state));

		/* Check contiguous length and gap to next section (if any) */
		nrs = RB_NEXT(revoked_serial_ବୃକ୍ଷ, &rc->revoked_serials, rs);
		final = nrs == ଖାଲି;
		gap = nrs == ଖାଲି ? 0 : nrs->lo - rs->hi;
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
		ଯଦି (state != 0 && (force_new_sect || next_state != state ||
		    state == KRL_SECTION_CERT_SERIAL_RANGE)) {
			KRL_DBG(("finish state 0x%02x", state));
			ବାଛ (state) {
			ସ୍ଥିତି KRL_SECTION_CERT_SERIAL_LIST:
			ସ୍ଥିତି KRL_SECTION_CERT_SERIAL_RANGE:
				ଭାଙ୍ଗ;
			ସ୍ଥିତି KRL_SECTION_CERT_SERIAL_BITMAP:
				ଯଦି ((r = put_bitmap(sect, bitmap)) != 0)
					ଯାଅ out;
				bitmap_free(bitmap);
				bitmap = ଖାଲି;
				ଭାଙ୍ଗ;
			}
			ଯଦି ((r = sshbuf_put_u8(buf, state)) != 0 ||
			    (r = sshbuf_put_stringb(buf, sect)) != 0)
				ଯାଅ out;
			sshbuf_reset(sect);
		}

		/* If we are starting a new section then prepare it now */
		ଯଦି (next_state != state || force_new_sect) {
			KRL_DBG(("start state 0x%02x",
			    next_state));
			state = next_state;
			sshbuf_reset(sect);
			ବାଛ (state) {
			ସ୍ଥିତି KRL_SECTION_CERT_SERIAL_LIST:
			ସ୍ଥିତି KRL_SECTION_CERT_SERIAL_RANGE:
				ଭାଙ୍ଗ;
			ସ୍ଥିତି KRL_SECTION_CERT_SERIAL_BITMAP:
				ଯଦି ((bitmap = bitmap_new()) == ଖାଲି) {
					r = SSH_ERR_ALLOC_FAIL;
					ଯାଅ out;
				}
				bitmap_start = rs->lo;
				ଯଦି ((r = sshbuf_put_u64(sect,
				    bitmap_start)) != 0)
					ଯାଅ out;
				ଭାଙ୍ଗ;
			}
		}

		/* Perform section-specific processing */
		ବାଛ (state) {
		ସ୍ଥିତି KRL_SECTION_CERT_SERIAL_LIST:
			ପାଇଁ (i = 0; i < contig; i++) {
				ଯଦି ((r = sshbuf_put_u64(sect, rs->lo + i)) != 0)
					ଯାଅ out;
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି KRL_SECTION_CERT_SERIAL_RANGE:
			ଯଦି ((r = sshbuf_put_u64(sect, rs->lo)) != 0 ||
			    (r = sshbuf_put_u64(sect, rs->hi)) != 0)
				ଯାଅ out;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି KRL_SECTION_CERT_SERIAL_BITMAP:
			ଯଦି (rs->lo - bitmap_start > INT_MAX) {
				r = SSH_ERR_INVALID_FORMAT;
				error_f("insane bitmap gap");
				ଯାଅ out;
			}
			ପାଇଁ (i = 0; i < contig; i++) {
				ଯଦି (bitmap_set_bit(bitmap,
				    rs->lo + i - bitmap_start) != 0) {
					r = SSH_ERR_ALLOC_FAIL;
					ଯାଅ out;
				}
			}
			ଭାଙ୍ଗ;
		}
		last = rs->hi;
	}
	/* Flush the remaining section, if any */
	ଯଦି (state != 0) {
		KRL_DBG(("serial final flush for state 0x%02x", state));
		ବାଛ (state) {
		ସ୍ଥିତି KRL_SECTION_CERT_SERIAL_LIST:
		ସ୍ଥିତି KRL_SECTION_CERT_SERIAL_RANGE:
			ଭାଙ୍ଗ;
		ସ୍ଥିତି KRL_SECTION_CERT_SERIAL_BITMAP:
			ଯଦି ((r = put_bitmap(sect, bitmap)) != 0)
				ଯାଅ out;
			bitmap_free(bitmap);
			bitmap = ଖାଲି;
			ଭାଙ୍ଗ;
		}
		ଯଦି ((r = sshbuf_put_u8(buf, state)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ଯାଅ out;
	}
	KRL_DBG(("serial done "));

	/* Now output a section for any revocations by key ID */
	sshbuf_reset(sect);
	RB_FOREACH(rki, revoked_ଚାବି_id_ବୃକ୍ଷ, &rc->revoked_ଚାବି_ids) {
		KRL_DBG(("key ID %s", rki->ଚାବି_id));
		ଯଦି ((r = sshbuf_put_cstring(sect, rki->ଚାବି_id)) != 0)
			ଯାଅ out;
	}
	ଯଦି (sshbuf_len(sect) != 0) {
		ଯଦି ((r = sshbuf_put_u8(buf, KRL_SECTION_CERT_ଚାବି_ID)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ଯାଅ out;
	}
	r = 0;
 out:
	bitmap_free(bitmap);
	sshbuf_free(sect);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_krl_to_blob(ସଂରଚନା ssh_krl *krl, ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	ସଂରଚନା revoked_certs *rc;
	ସଂରଚନା revoked_blob *rb;
	ସଂରଚନା sshbuf *sect;
	u_char *sblob = ଖାଲି;

	ଯଦି (krl->generated_date == 0)
		krl->generated_date = time(ଖାଲି);

	ଯଦି ((sect = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;

	/* Store the header */
	ଯଦି ((r = sshbuf_put(buf, KRL_MAGIC, ଆକାର(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_put_u32(buf, KRL_FORMAT_VERSION)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->krl_version)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->generated_date)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->flags)) != 0 ||
	    (r = sshbuf_put_string(buf, ଖାଲି, 0)) != 0 ||
	    (r = sshbuf_put_cstring(buf, krl->comment)) != 0)
		ଯାଅ out;

	/* Store sections for revoked certificates */
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		sshbuf_reset(sect);
		ଯଦି ((r = revoked_certs_generate(rc, sect)) != 0)
			ଯାଅ out;
		ଯଦି ((r = sshbuf_put_u8(buf, KRL_SECTION_CERTIFICATES)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ଯାଅ out;
	}

	/* Finally, output sections for revocations by public key/hash */
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_ବୃକ୍ଷ, &krl->revoked_ଚାବିଗୁଡ଼ିକ) {
		KRL_DBG(("key len %zu ", rb->len));
		ଯଦି ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			ଯାଅ out;
	}
	ଯଦି (sshbuf_len(sect) != 0) {
		ଯଦି ((r = sshbuf_put_u8(buf, KRL_SECTION_EXPLICIT_ଚାବି)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ଯାଅ out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_ବୃକ୍ଷ, &krl->revoked_sha1s) {
		KRL_DBG(("hash len %zu ", rb->len));
		ଯଦି ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			ଯାଅ out;
	}
	ଯଦି (sshbuf_len(sect) != 0) {
		ଯଦି ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA1)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ଯାଅ out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_ବୃକ୍ଷ, &krl->revoked_sha256s) {
		KRL_DBG(("hash len %zu ", rb->len));
		ଯଦି ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			ଯାଅ out;
	}
	ଯଦି (sshbuf_len(sect) != 0) {
		ଯଦି ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA256)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			ଯାଅ out;
	}
	/* success */
	r = 0;
 out:
	ମୁକ୍ତ(sblob);
	sshbuf_free(sect);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ଶୂନ୍ୟ
format_timestamp(uint64_t timestamp, ଅକ୍ଷର *ts, size_t nts)
{
	time_t t;
	ସଂରଚନା tm *tm;

	t = timestamp;
	tm = localtime(&t);
	ଯଦି (tm == ଖାଲି)
		strlcpy(ts, "<INVALID>", nts);
	ଅନ୍ୟଥା {
		*ts = '\0';
		strftime(ts, nts, "%Y%m%dT%H%M%S", tm);
	}
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
cert_extension_subsection(ସଂରଚନା sshbuf *subsect, ସଂରଚନା ssh_krl *krl)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	ସଂରଚନା sshbuf *ମୂଲ୍ୟ = ଖାଲି;
	ଅକ୍ଷର *name = ଖାଲି;

	ଯଦି ((r = sshbuf_get_cstring(subsect, &name, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_u8(subsect, &critical)) != 0 ||
	    (r = sshbuf_froms(subsect, &ମୂଲ୍ୟ)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid certificate extension subsection");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (sshbuf_len(subsect) != 0) {
		error("KRL has invalid certificate extension subsection: "
		    "trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	debug_f("cert extension %s critical %u len %zu",
	    name, critical, sshbuf_len(ମୂଲ୍ୟ));
	/* no extensions are currently supported */
	ଯଦି (critical) {
		error("KRL contains unsupported critical certificate "
		    "subsection \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		ଯାଅ out;
	}
	/* success */
	r = 0;
 out:
	ମୁକ୍ତ(name);
	sshbuf_free(ମୂଲ୍ୟ);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_revoked_certs(ସଂରଚନା sshbuf *buf, ସଂରଚନା ssh_krl *krl)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	ଅଚଳ u_char *blob;
	size_t blen, nbits;
	ସଂରଚନା sshbuf *subsect = ଖାଲି;
	uint64_t serial, serial_lo, serial_hi;
	ସଂରଚନା bitmap *bitmap = ଖାଲି;
	ଅକ୍ଷର *ଚାବି_id = ଖାଲି;
	ସଂରଚନା sshkey *ca_ଚାବି = ଖାଲି;

	ଯଦି ((subsect = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;

	/* Header: key, reserved */
	ଯଦି ((r = sshbuf_get_string_direct(buf, &blob, &blen)) != 0 ||
	    (r = sshbuf_skip_string(buf)) != 0)
		ଯାଅ out;
	ଯଦି (blen != 0 && (r = sshkey_from_blob(blob, blen, &ca_ଚାବି)) != 0)
		ଯାଅ out;

	ଯେତେବେଳେ (sshbuf_len(buf) > 0) {
		sshbuf_free(subsect);
		subsect = ଖାଲି;
		ଯଦି ((r = sshbuf_get_u8(buf, &type)) != 0 ||
		    (r = sshbuf_froms(buf, &subsect)) != 0)
			ଯାଅ out;
		KRL_DBG(("subsection type 0x%02x", type));
		/* sshbuf_dump(subsect, stderr); */

		ବାଛ (type) {
		ସ୍ଥିତି KRL_SECTION_CERT_SERIAL_LIST:
			ଯେତେବେଳେ (sshbuf_len(subsect) > 0) {
				ଯଦି ((r = sshbuf_get_u64(subsect, &serial)) != 0)
					ଯାଅ out;
				ଯଦି ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_ଚାବି, serial)) != 0)
					ଯାଅ out;
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି KRL_SECTION_CERT_SERIAL_RANGE:
			ଯଦି ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_u64(subsect, &serial_hi)) != 0)
				ଯାଅ out;
			ଯଦି ((r = ssh_krl_revoke_cert_by_serial_range(krl,
			    ca_ଚାବି, serial_lo, serial_hi)) != 0)
				ଯାଅ out;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି KRL_SECTION_CERT_SERIAL_BITMAP:
			ଯଦି ((bitmap = bitmap_new()) == ଖାଲି) {
				r = SSH_ERR_ALLOC_FAIL;
				ଯାଅ out;
			}
			ଯଦି ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_bignum2_bytes_direct(subsect,
			    &blob, &blen)) != 0)
				ଯାଅ out;
			ଯଦି (bitmap_from_string(bitmap, blob, blen) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				ଯାଅ out;
			}
			nbits = bitmap_nbits(bitmap);
			ପାଇଁ (serial = 0; serial < (uint64_t)nbits; serial++) {
				ଯଦି (serial > 0 && serial_lo + serial == 0) {
					error_f("bitmap wraps u64");
					r = SSH_ERR_INVALID_FORMAT;
					ଯାଅ out;
				}
				ଯଦି (!bitmap_test_bit(bitmap, serial))
					ଜାରି;
				ଯଦି ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_ଚାବି, serial_lo + serial)) != 0)
					ଯାଅ out;
			}
			bitmap_free(bitmap);
			bitmap = ଖାଲି;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି KRL_SECTION_CERT_ଚାବି_ID:
			ଯେତେବେଳେ (sshbuf_len(subsect) > 0) {
				ଯଦି ((r = sshbuf_get_cstring(subsect,
				    &ଚାବି_id, ଖାଲି)) != 0)
					ଯାଅ out;
				ଯଦି ((r = ssh_krl_revoke_cert_by_ଚାବି_id(krl,
				    ca_ଚାବି, ଚାବି_id)) != 0)
					ଯାଅ out;
				ମୁକ୍ତ(ଚାବି_id);
				ଚାବି_id = ଖାଲି;
			}
			ଭାଙ୍ଗ;
		ସ୍ଥିତି KRL_SECTION_CERT_EXTENSION:
			ଯଦି ((r = cert_extension_subsection(subsect, krl)) != 0)
				ଯାଅ out;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			error("Unsupported KRL certificate section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
		ଯଦି (sshbuf_len(subsect) > 0) {
			error("KRL certificate section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
	}

	r = 0;
 out:
	ଯଦି (bitmap != ଖାଲି)
		bitmap_free(bitmap);
	ମୁକ୍ତ(ଚାବି_id);
	sshkey_free(ca_ଚାବି);
	sshbuf_free(subsect);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
blob_section(ସଂରଚନା sshbuf *sect, ସଂରଚନା revoked_blob_ବୃକ୍ଷ *target_ବୃକ୍ଷ,
    size_t expected_len)
{
	u_char *rdata = ଖାଲି;
	size_t rlen = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯେତେବେଳେ (sshbuf_len(sect) > 0) {
		ଯଦି ((r = sshbuf_get_string(sect, &rdata, &rlen)) != 0)
			ଫେରନ୍ତୁ r;
		ଯଦି (expected_len != 0 && rlen != expected_len) {
			error_f("bad length");
			ମୁକ୍ତ(rdata);
			ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
		}
		ଯଦି ((r = revoke_blob(target_ବୃକ୍ଷ, rdata, rlen)) != 0) {
			ମୁକ୍ତ(rdata);
			ଫେରନ୍ତୁ r;
		}
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
extension_section(ସଂରଚନା sshbuf *sect, ସଂରଚନା ssh_krl *krl)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	ସଂରଚନା sshbuf *ମୂଲ୍ୟ = ଖାଲି;
	ଅକ୍ଷର *name = ଖାଲି;

	ଯଦି ((r = sshbuf_get_cstring(sect, &name, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_u8(sect, &critical)) != 0 ||
	    (r = sshbuf_froms(sect, &ମୂଲ୍ୟ)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid extension section");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (sshbuf_len(sect) != 0) {
		error("KRL has invalid extension section: trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	debug_f("extension %s critical %u len %zu",
	    name, critical, sshbuf_len(ମୂଲ୍ୟ));
	/* no extensions are currently supported */
	ଯଦି (critical) {
		error("KRL contains unsupported critical section \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		ଯାଅ out;
	}
	/* success */
	r = 0;
 out:
	ମୁକ୍ତ(name);
	sshbuf_free(ମୂଲ୍ୟ);
	ଫେରନ୍ତୁ r;
}

/* Attempt to parse a KRL */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_krl_from_blob(ସଂରଚନା sshbuf *buf, ସଂରଚନା ssh_krl **krlp)
{
	ସଂରଚନା sshbuf *copy = ଖାଲି, *sect = ଖାଲି;
	ସଂରଚନା ssh_krl *krl = ଖାଲି;
	ଅକ୍ଷର timestamp[64];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	u_int format_version;

	*krlp = ଖାଲି;

	/* KRL must begin with magic string */
	ଯଦି ((r = sshbuf_cmp(buf, 0, KRL_MAGIC, ଆକାର(KRL_MAGIC) - 1)) != 0) {
		debug2_f("bad KRL magic header");
		ଫେରନ୍ତୁ SSH_ERR_KRL_BAD_MAGIC;
	}

	ଯଦି ((krl = ssh_krl_init()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		error_f("alloc failed");
		ଯାଅ out;
	}
	/* Don't modify buffer */
	ଯଦି ((copy = sshbuf_fromb(buf)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_consume(copy, ଆକାର(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_get_u32(copy, &format_version)) != 0)
		ଯାଅ out;
	ଯଦି (format_version != KRL_FORMAT_VERSION) {
		error_f("unsupported KRL format version %u", format_version);
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_get_u64(copy, &krl->krl_version)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->generated_date)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->flags)) != 0 ||
	    (r = sshbuf_skip_string(copy)) != 0 ||
	    (r = sshbuf_get_cstring(copy, &krl->comment, ଖାଲି)) != 0) {
		error_fr(r, "parse KRL header");
		ଯାଅ out;
	}
	format_timestamp(krl->generated_date, timestamp, ଆକାର(timestamp));
	debug("KRL version %llu generated at %s%s%s",
	    (long long unsigned)krl->krl_version, timestamp,
	    *krl->comment ? ": " : "", krl->comment);

	/* Parse and load the KRL sections. */
	ଯେତେବେଳେ (sshbuf_len(copy) > 0) {
		sshbuf_free(sect);
		sect = ଖାଲି;
		ଯଦି ((r = sshbuf_get_u8(copy, &type)) != 0 ||
		    (r = sshbuf_froms(copy, &sect)) != 0)
			ଯାଅ out;
		KRL_DBG(("section 0x%02x", type));

		ବାଛ (type) {
		ସ୍ଥିତି KRL_SECTION_CERTIFICATES:
			ଯଦି ((r = parse_revoked_certs(sect, krl)) != 0)
				ଯାଅ out;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି KRL_SECTION_EXPLICIT_ଚାବି:
			ଯଦି ((r = blob_section(sect,
			    &krl->revoked_ଚାବିଗୁଡ଼ିକ, 0)) != 0)
				ଯାଅ out;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି KRL_SECTION_FINGERPRINT_SHA1:
			ଯଦି ((r = blob_section(sect,
			    &krl->revoked_sha1s, 20)) != 0)
				ଯାଅ out;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି KRL_SECTION_FINGERPRINT_SHA256:
			ଯଦି ((r = blob_section(sect,
			    &krl->revoked_sha256s, 32)) != 0)
				ଯାଅ out;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି KRL_SECTION_EXTENSION:
			ଯଦି ((r = extension_section(sect, krl)) != 0)
				ଯାଅ out;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି KRL_SECTION_SIGNATURE:
			/* Handled above, but still need to stay in synch */
			sshbuf_free(sect);
			sect = ଖାଲି;
			ଯଦି ((r = sshbuf_skip_string(copy)) != 0)
				ଯାଅ out;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			error("Unsupported KRL section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
		ଯଦି (sect != ଖାଲି && sshbuf_len(sect) > 0) {
			error("KRL section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
	}

	/* Success */
	*krlp = krl;
	r = 0;
 out:
	ଯଦି (r != 0)
		ssh_krl_free(krl);
	sshbuf_free(copy);
	sshbuf_free(sect);
	ଫେରନ୍ତୁ r;
}

/* Checks certificate serial number and key ID revocation */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
is_cert_revoked(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା revoked_certs *rc)
{
	ସଂରଚନା revoked_serial rs, *ers;
	ସଂରଚନା revoked_ଚାବି_id rki, *erki;

	/* Check revocation by cert key ID */
	memset(&rki, 0, ଆକାର(rki));
	rki.ଚାବି_id = ଚାବି->cert->ଚାବି_id;
	erki = RB_FIND(revoked_ଚାବି_id_ବୃକ୍ଷ, &rc->revoked_ଚାବି_ids, &rki);
	ଯଦି (erki != ଖାଲି) {
		KRL_DBG(("revoked by key ID"));
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_REVOKED;
	}

	/*
	 * Zero serials numbers are ignored (it's the default when the
	 * CA doesn't specify one).
	 */
	ଯଦି (ଚାବି->cert->serial == 0)
		ଫେରନ୍ତୁ 0;

	memset(&rs, 0, ଆକାର(rs));
	rs.lo = rs.hi = ଚାବି->cert->serial;
	ers = RB_FIND(revoked_serial_ବୃକ୍ଷ, &rc->revoked_serials, &rs);
	ଯଦି (ers != ଖାଲି) {
		KRL_DBG(("revoked serial %llu matched %llu:%llu",
		    (unsigned long long)ଚାବି->cert->serial,
		    (unsigned long long)ers->lo,
		    (unsigned long long)ers->hi));
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_REVOKED;
	}
	ଫେରନ୍ତୁ 0;
}

/* Checks whether a given key/cert is revoked. Does not check its CA */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
is_ଚାବି_revoked(ସଂରଚନା ssh_krl *krl, ଅଚଳ ସଂରଚନା sshkey *ଚାବି)
{
	ସଂରଚନା revoked_blob rb, *erb;
	ସଂରଚନା revoked_certs *rc;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	/* Check explicitly revoked hashes first */
	memset(&rb, 0, ଆକାର(rb));
	ଯଦି ((r = sshkey_fingerprint_raw(ଚାବି, SSH_DIGEST_SHA1,
	    &rb.blob, &rb.len)) != 0)
		ଫେରନ୍ତୁ r;
	erb = RB_FIND(revoked_blob_ବୃକ୍ଷ, &krl->revoked_sha1s, &rb);
	ମୁକ୍ତ(rb.blob);
	ଯଦି (erb != ଖାଲି) {
		KRL_DBG(("revoked by key SHA1"));
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_REVOKED;
	}
	memset(&rb, 0, ଆକାର(rb));
	ଯଦି ((r = sshkey_fingerprint_raw(ଚାବି, SSH_DIGEST_SHA256,
	    &rb.blob, &rb.len)) != 0)
		ଫେରନ୍ତୁ r;
	erb = RB_FIND(revoked_blob_ବୃକ୍ଷ, &krl->revoked_sha256s, &rb);
	ମୁକ୍ତ(rb.blob);
	ଯଦି (erb != ଖାଲି) {
		KRL_DBG(("revoked by key SHA256"));
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_REVOKED;
	}

	/* Next, explicit keys */
	memset(&rb, 0, ଆକାର(rb));
	ଯଦି ((r = plain_ଚାବି_blob(ଚାବି, &rb.blob, &rb.len)) != 0)
		ଫେରନ୍ତୁ r;
	erb = RB_FIND(revoked_blob_ବୃକ୍ଷ, &krl->revoked_ଚାବିଗୁଡ଼ିକ, &rb);
	ମୁକ୍ତ(rb.blob);
	ଯଦି (erb != ଖାଲି) {
		KRL_DBG(("revoked by explicit key"));
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_REVOKED;
	}

	ଯଦି (!sshkey_is_cert(ଚାବି))
		ଫେରନ୍ତୁ 0;

	/* Check cert revocation for the specified CA */
	ଯଦି ((r = revoked_certs_for_ca_ଚାବି(krl, ଚାବି->cert->signature_ଚାବି,
	    &rc, 0)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (rc != ଖାଲି) {
		ଯଦି ((r = is_cert_revoked(ଚାବି, rc)) != 0)
			ଫେରନ୍ତୁ r;
	}
	/* Check cert revocation for the wildcard CA */
	ଯଦି ((r = revoked_certs_for_ca_ଚାବି(krl, ଖାଲି, &rc, 0)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (rc != ଖାଲି) {
		ଯଦି ((r = is_cert_revoked(ଚାବି, rc)) != 0)
			ଫେରନ୍ତୁ r;
	}

	KRL_DBG(("%llu no match", (unsigned long long)ଚାବି->cert->serial));
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_krl_check_ଚାବି(ସଂରଚନା ssh_krl *krl, ଅଚଳ ସଂରଚନା sshkey *ଚାବି)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	KRL_DBG(("checking key"));
	ଯଦି ((r = is_ଚାବି_revoked(krl, ଚାବି)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (sshkey_is_cert(ଚାବି)) {
		debug2_f("checking CA key");
		ଯଦି ((r = is_ଚାବି_revoked(krl, ଚାବି->cert->signature_ଚାବି)) != 0)
			ଫେରନ୍ତୁ r;
	}
	KRL_DBG(("key okay"));
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_krl_file_contains_ଚାବି(ଅଚଳ ଅକ୍ଷର *path, ଅଚଳ ସଂରଚନା sshkey *ଚାବି)
{
	ସଂରଚନା sshbuf *krlbuf = ଖାଲି;
	ସଂରଚନା ssh_krl *krl = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା oerrno = 0, r;

	ଯଦି (path == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଯଦି ((r = sshbuf_load_file(path, &krlbuf)) != 0) {
		oerrno = errno;
		ଯାଅ out;
	}
	ଯଦି ((r = ssh_krl_from_blob(krlbuf, &krl)) != 0)
		ଯାଅ out;
	debug2_f("checking KRL %s", path);
	r = ssh_krl_check_ଚାବି(krl, ଚାବି);
 out:
	sshbuf_free(krlbuf);
	ssh_krl_free(krl);
	ଯଦି (r != 0)
		errno = oerrno;
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
krl_dump(ସଂରଚନା ssh_krl *krl, FILE *f)
{
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	ସଂରଚନା revoked_blob *rb;
	ସଂରଚନା revoked_certs *rc;
	ସଂରଚନା revoked_serial *rs;
	ସଂରଚନା revoked_ଚାବି_id *rki;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret = 0;
	ଅକ୍ଷର *fp, timestamp[64];

	/* Try to print in a KRL spec-compatible format */
	format_timestamp(krl->generated_date, timestamp, ଆକାର(timestamp));
	fprintf(f, "# KRL version %llu\n", (unsigned long long)krl->krl_version);
	fprintf(f, "# Generated at %s\n", timestamp);
	ଯଦି (krl->comment != ଖାଲି && *krl->comment != '\0') {
		r = INT_MAX;
		asmprintf(&fp, INT_MAX, &r, "%s", krl->comment);
		fprintf(f, "# Comment: %s\n", fp);
		ମୁକ୍ତ(fp);
	}
	fputc('\n', f);

	RB_FOREACH(rb, revoked_blob_ବୃକ୍ଷ, &krl->revoked_ଚାବିଗୁଡ଼ିକ) {
		ଯଦି ((r = sshkey_from_blob(rb->blob, rb->len, &ଚାବି)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			error_r(r, "parse KRL key");
			ଜାରି;
		}
		ଯଦି ((fp = sshkey_fingerprint(ଚାବି, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ଖାଲି) {
			ret = SSH_ERR_INVALID_FORMAT;
			error("sshkey_fingerprint failed");
			ଜାରି;
		}
		fprintf(f, "hash: %s # %s\n", fp, sshkey_ssh_name(ଚାବି));
		ମୁକ୍ତ(fp);
		ମୁକ୍ତ(ଚାବି);
	}
	RB_FOREACH(rb, revoked_blob_ବୃକ୍ଷ, &krl->revoked_sha256s) {
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "hash: SHA256:%s\n", fp);
		ମୁକ୍ତ(fp);
	}
	RB_FOREACH(rb, revoked_blob_ବୃକ୍ଷ, &krl->revoked_sha1s) {
		/*
		 * There is not KRL spec keyword for raw SHA1 hashes, so
		 * print them as comments.
		 */
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "# hash SHA1:%s\n", fp);
		ମୁକ୍ତ(fp);
	}

	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		fputc('\n', f);
		ଯଦି (rc->ca_ଚାବି == ଖାଲି)
			fprintf(f, "# Wildcard CA\n");
		ଅନ୍ୟଥା {
			ଯଦି ((fp = sshkey_fingerprint(rc->ca_ଚାବି,
			    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ଖାଲି) {
				ret = SSH_ERR_INVALID_FORMAT;
				error("sshkey_fingerprint failed");
				ଜାରି;
			}
			fprintf(f, "# CA key %s %s\n",
			    sshkey_ssh_name(rc->ca_ଚାବି), fp);
			ମୁକ୍ତ(fp);
		}
		RB_FOREACH(rs, revoked_serial_ବୃକ୍ଷ, &rc->revoked_serials) {
			ଯଦି (rs->lo == rs->hi) {
				fprintf(f, "serial: %llu\n",
				    (unsigned long long)rs->lo);
			} ଅନ୍ୟଥା {
				fprintf(f, "serial: %llu-%llu\n",
				    (unsigned long long)rs->lo,
				    (unsigned long long)rs->hi);
			}
		}
		RB_FOREACH(rki, revoked_ଚାବି_id_ବୃକ୍ଷ, &rc->revoked_ଚାବି_ids) {
			/*
			 * We don't want key IDs with embedded newlines to
			 * mess up the display.
			 */
			r = INT_MAX;
			asmprintf(&fp, INT_MAX, &r, "%s", rki->ଚାବି_id);
			fprintf(f, "id: %s\n", fp);
			ମୁକ୍ତ(fp);
		}
	}
	ଫେରନ୍ତୁ ret;
}
