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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/tree.h>
#అన్తర్భావ <sys/queue.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <time.h>

#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "bitmap.h"
#అన్తర్భావ "utf8.h"

#అన్తర్భావ "krl.h"

/* #define DEBUG_KRL */
#నిర్వచితమైతే DEBUG_KRL
# define KRL_DBG(x) debug3_f x
#లేకపోతే
# define KRL_DBG(x)
#అయితే_ముగింపు

/*
 * Trees of revoked serial numbers, key IDs and keys. This allows
 * quick searching, querying and producing lists in canonical order.
 */

/* Tree of serial numbers. XXX make smarter: really need a real sparse bitmap */
నిర్మాణం revoked_serial {
	uint64_t lo, hi;
	RB_నమోదు(revoked_serial) వృక్షం_నమోదు;
};
స్థిర పూర్ణాంకం serial_cmp(నిర్మాణం revoked_serial *a, నిర్మాణం revoked_serial *b);
RB_తల(revoked_serial_వృక్షం, revoked_serial);
RB_GENERATE_STATIC(revoked_serial_వృక్షం, revoked_serial, వృక్షం_నమోదు, serial_cmp)

/* Tree of key IDs */
నిర్మాణం revoked_కీలకం_id {
	అక్షరం *కీలకం_id;
	RB_నమోదు(revoked_కీలకం_id) వృక్షం_నమోదు;
};
స్థిర పూర్ణాంకం కీలకం_id_cmp(నిర్మాణం revoked_కీలకం_id *a, నిర్మాణం revoked_కీలకం_id *b);
RB_తల(revoked_కీలకం_id_వృక్షం, revoked_కీలకం_id);
RB_GENERATE_STATIC(revoked_కీలకం_id_వృక్షం, revoked_కీలకం_id, వృక్షం_నమోదు, కీలకం_id_cmp)

/* Tree of blobs (used for keys and fingerprints) */
నిర్మాణం revoked_blob {
	u_char *blob;
	కొలత_t len;
	RB_నమోదు(revoked_blob) వృక్షం_నమోదు;
};
స్థిర పూర్ణాంకం blob_cmp(నిర్మాణం revoked_blob *a, నిర్మాణం revoked_blob *b);
RB_తల(revoked_blob_వృక్షం, revoked_blob);
RB_GENERATE_STATIC(revoked_blob_వృక్షం, revoked_blob, వృక్షం_నమోదు, blob_cmp)

/* Tracks revoked certs for a single CA */
నిర్మాణం revoked_certs {
	నిర్మాణం sshkey *ca_కీలకం;
	నిర్మాణం revoked_serial_వృక్షం revoked_serials;
	నిర్మాణం revoked_కీలకం_id_వృక్షం revoked_కీలకం_ids;
	TAILQ_ENTRY(revoked_certs) నమోదు_2;
};
TAILQ_HEAD(revoked_certs_list, revoked_certs);

నిర్మాణం ssh_krl {
	uint64_t krl_సంస్కరణ;
	uint64_t generated_date;
	uint64_t flags;
	అక్షరం *comment;
	నిర్మాణం revoked_blob_వృక్షం revoked_కీలకాలు;
	నిర్మాణం revoked_blob_వృక్షం revoked_sha1s;
	నిర్మాణం revoked_blob_వృక్షం revoked_sha256s;
	నిర్మాణం revoked_certs_list revoked_certs;
};

/* Return equal if a and b overlap */
స్థిర పూర్ణాంకం
serial_cmp(నిర్మాణం revoked_serial *a, నిర్మాణం revoked_serial *b)
{
	ఒకవేళ (a->hi >= b->lo && a->lo <= b->hi)
		తిరిగి 0;
	తిరిగి a->lo < b->lo ? -1 : 1;
}

స్థిర పూర్ణాంకం
కీలకం_id_cmp(నిర్మాణం revoked_కీలకం_id *a, నిర్మాణం revoked_కీలకం_id *b)
{
	తిరిగి strcmp(a->కీలకం_id, b->కీలకం_id);
}

స్థిర పూర్ణాంకం
blob_cmp(నిర్మాణం revoked_blob *a, నిర్మాణం revoked_blob *b)
{
	పూర్ణాంకం r;

	ఒకవేళ (a->len != b->len) {
		ఒకవేళ ((r = memcmp(a->blob, b->blob, MINIMUM(a->len, b->len))) != 0)
			తిరిగి r;
		తిరిగి a->len > b->len ? 1 : -1;
	} లేకపోతే
		తిరిగి memcmp(a->blob, b->blob, a->len);
}

నిర్మాణం ssh_krl *
ssh_krl_init(శూన్య)
{
	నిర్మాణం ssh_krl *krl;

	ఒకవేళ ((krl = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*krl))) == ఖాళీ)
		తిరిగి ఖాళీ;
	RB_INIT(&krl->revoked_కీలకాలు);
	RB_INIT(&krl->revoked_sha1s);
	RB_INIT(&krl->revoked_sha256s);
	TAILQ_INIT(&krl->revoked_certs);
	తిరిగి krl;
}

స్థిర శూన్య
revoked_certs_free(నిర్మాణం revoked_certs *rc)
{
	నిర్మాణం revoked_serial *rs, *trs;
	నిర్మాణం revoked_కీలకం_id *rki, *trki;

	ఒకవేళ (rc == ఖాళీ)
		తిరిగి;
	RB_FOREACH_సురక్షిత(rs, revoked_serial_వృక్షం, &rc->revoked_serials, trs) {
		RB_REMOVE(revoked_serial_వృక్షం, &rc->revoked_serials, rs);
		విడుదల(rs);
	}
	RB_FOREACH_సురక్షిత(rki, revoked_కీలకం_id_వృక్షం, &rc->revoked_కీలకం_ids, trki) {
		RB_REMOVE(revoked_కీలకం_id_వృక్షం, &rc->revoked_కీలకం_ids, rki);
		విడుదల(rki->కీలకం_id);
		విడుదల(rki);
	}
	sshkey_free(rc->ca_కీలకం);
	freezero(rc, పరిమాణం(*rc));
}

శూన్య
ssh_krl_free(నిర్మాణం ssh_krl *krl)
{
	నిర్మాణం revoked_blob *rb, *trb;
	నిర్మాణం revoked_certs *rc, *trc;

	ఒకవేళ (krl == ఖాళీ)
		తిరిగి;

	విడుదల(krl->comment);
	RB_FOREACH_సురక్షిత(rb, revoked_blob_వృక్షం, &krl->revoked_కీలకాలు, trb) {
		RB_REMOVE(revoked_blob_వృక్షం, &krl->revoked_కీలకాలు, rb);
		విడుదల(rb->blob);
		విడుదల(rb);
	}
	RB_FOREACH_సురక్షిత(rb, revoked_blob_వృక్షం, &krl->revoked_sha1s, trb) {
		RB_REMOVE(revoked_blob_వృక్షం, &krl->revoked_sha1s, rb);
		విడుదల(rb->blob);
		విడుదల(rb);
	}
	RB_FOREACH_సురక్షిత(rb, revoked_blob_వృక్షం, &krl->revoked_sha256s, trb) {
		RB_REMOVE(revoked_blob_వృక్షం, &krl->revoked_sha256s, rb);
		విడుదల(rb->blob);
		విడుదల(rb);
	}
	TAILQ_FOREACH_సురక్షిత(rc, &krl->revoked_certs, నమోదు_2, trc) {
		TAILQ_REMOVE(&krl->revoked_certs, rc, నమోదు_2);
		revoked_certs_free(rc);
	}
	విడుదల(krl);
}

శూన్య
ssh_krl_సమితి_సంస్కరణ(నిర్మాణం ssh_krl *krl, uint64_t సంస్కరణ)
{
	krl->krl_సంస్కరణ = సంస్కరణ;
}

పూర్ణాంకం
ssh_krl_సమితి_comment(నిర్మాణం ssh_krl *krl, స్థిరరాశి అక్షరం *comment)
{
	విడుదల(krl->comment);
	ఒకవేళ ((krl->comment = strdup(comment)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	తిరిగి 0;
}

/*
 * Find the revoked_certs struct for a CA key. If allow_create is set then
 * create a new one in the tree if one did not exist already.
 */
స్థిర పూర్ణాంకం
revoked_certs_for_ca_కీలకం(నిర్మాణం ssh_krl *krl, స్థిరరాశి నిర్మాణం sshkey *ca_కీలకం,
    నిర్మాణం revoked_certs **rcp, పూర్ణాంకం allow_create)
{
	నిర్మాణం revoked_certs *rc;
	పూర్ణాంకం r;

	*rcp = ఖాళీ;
	TAILQ_FOREACH(rc, &krl->revoked_certs, నమోదు_2) {
		ఒకవేళ ((ca_కీలకం == ఖాళీ && rc->ca_కీలకం == ఖాళీ) ||
		    sshkey_equal(rc->ca_కీలకం, ca_కీలకం)) {
			*rcp = rc;
			తిరిగి 0;
		}
	}
	ఒకవేళ (!allow_create)
		తిరిగి 0;
	/* If this CA doesn't exist in the list then add it now */
	ఒకవేళ ((rc = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*rc))) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ (ca_కీలకం == ఖాళీ)
		rc->ca_కీలకం = ఖాళీ;
	లేకపోతే ఒకవేళ ((r = sshkey_from_వ్యక్తిగత(ca_కీలకం, &rc->ca_కీలకం)) != 0) {
		విడుదల(rc);
		తిరిగి r;
	}
	RB_INIT(&rc->revoked_serials);
	RB_INIT(&rc->revoked_కీలకం_ids);
	TAILQ_INSERT_TAIL(&krl->revoked_certs, rc, నమోదు_2);
	KRL_DBG(("new CA %s", ca_కీలకం == ఖాళీ ? "*" : sshkey_type(ca_కీలకం)));
	*rcp = rc;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
చొప్పించు_serial_range(నిర్మాణం revoked_serial_వృక్షం *rt, uint64_t lo, uint64_t hi)
{
	నిర్మాణం revoked_serial rs, *ers, *crs, *irs;

	KRL_DBG(("insert %llu:%llu",
	    (గుర్తులేని దీర్ఘ దీర్ఘ)lo, (గుర్తులేని దీర్ఘ దీర్ఘ)hi));
	memset(&rs, 0, పరిమాణం(rs));
	rs.lo = lo;
	rs.hi = hi;
	ers = RB_NFIND(revoked_serial_వృక్షం, rt, &rs);
	ఒకవేళ (ers == ఖాళీ || serial_cmp(ers, &rs) != 0) {
		/* No entry matches. Just insert */
		ఒకవేళ ((irs = జ్ఞాపకం_ఇవ్వు(పరిమాణం(rs))) == ఖాళీ)
			తిరిగి SSH_ERR_ALLOC_FAIL;
		జ్ఞాపకం_నకలు(irs, &rs, పరిమాణం(*irs));
		ers = RB_చొప్పించు(revoked_serial_వృక్షం, rt, irs);
		ఒకవేళ (ers != ఖాళీ) {
			KRL_DBG(("bad: ers != NULL"));
			/* Shouldn't happen */
			విడుదల(irs);
			తిరిగి SSH_ERR_అంతర్గత_ERROR;
		}
		ers = irs;
	} లేకపోతే {
		KRL_DBG(("overlap found %llu:%llu",
		    (గుర్తులేని దీర్ఘ దీర్ఘ)ers->lo, (గుర్తులేని దీర్ఘ దీర్ఘ)ers->hi));
		/*
		 * The inserted entry overlaps an existing one. Grow the
		 * existing entry.
		 */
		ఒకవేళ (ers->lo > lo)
			ers->lo = lo;
		ఒకవేళ (ers->hi < hi)
			ers->hi = hi;
	}

	/*
	 * The inserted or revised range might overlap or abut adjacent ones;
	 * coalesce as necessary.
	 */

	/* Check predecessors */
	అయితే ((crs = RB_PREV(revoked_serial_వృక్షం, rt, ers)) != ఖాళీ) {
		KRL_DBG(("pred %llu:%llu",
		    (గుర్తులేని దీర్ఘ దీర్ఘ)crs->lo, (గుర్తులేని దీర్ఘ దీర్ఘ)crs->hi));
		ఒకవేళ (ers->lo != 0 && crs->hi < ers->lo - 1)
			ఆపు;
		/* This entry overlaps. */
		ఒకవేళ (crs->lo < ers->lo) {
			ers->lo = crs->lo;
			KRL_DBG(("pred extend %llu:%llu",
			    (గుర్తులేని దీర్ఘ దీర్ఘ)ers->lo,
			    (గుర్తులేని దీర్ఘ దీర్ఘ)ers->hi));
		}
		RB_REMOVE(revoked_serial_వృక్షం, rt, crs);
		విడుదల(crs);
	}
	/* Check successors */
	అయితే ((crs = RB_తదుపరి(revoked_serial_వృక్షం, rt, ers)) != ఖాళీ) {
		KRL_DBG(("succ %llu:%llu",
		    (గుర్తులేని దీర్ఘ దీర్ఘ)crs->lo, (గుర్తులేని దీర్ఘ దీర్ఘ)crs->hi));
		ఒకవేళ (ers->hi != (uint64_t)-1 && crs->lo > ers->hi + 1)
			ఆపు;
		/* This entry overlaps. */
		ఒకవేళ (crs->hi > ers->hi) {
			ers->hi = crs->hi;
			KRL_DBG(("succ extend %llu:%llu",
			    (గుర్తులేని దీర్ఘ దీర్ఘ)ers->lo,
			    (గుర్తులేని దీర్ఘ దీర్ఘ)ers->hi));
		}
		RB_REMOVE(revoked_serial_వృక్షం, rt, crs);
		విడుదల(crs);
	}
	KRL_DBG(("done, final %llu:%llu",
	    (గుర్తులేని దీర్ఘ దీర్ఘ)ers->lo, (గుర్తులేని దీర్ఘ దీర్ఘ)ers->hi));
	తిరిగి 0;
}

పూర్ణాంకం
ssh_krl_revoke_cert_by_serial(నిర్మాణం ssh_krl *krl, స్థిరరాశి నిర్మాణం sshkey *ca_కీలకం,
    uint64_t serial)
{
	తిరిగి ssh_krl_revoke_cert_by_serial_range(krl, ca_కీలకం, serial, serial);
}

పూర్ణాంకం
ssh_krl_revoke_cert_by_serial_range(నిర్మాణం ssh_krl *krl,
    స్థిరరాశి నిర్మాణం sshkey *ca_కీలకం, uint64_t lo, uint64_t hi)
{
	నిర్మాణం revoked_certs *rc;
	పూర్ణాంకం r;

	ఒకవేళ (lo > hi || lo == 0)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ ((r = revoked_certs_for_ca_కీలకం(krl, ca_కీలకం, &rc, 1)) != 0)
		తిరిగి r;
	తిరిగి చొప్పించు_serial_range(&rc->revoked_serials, lo, hi);
}

పూర్ణాంకం
ssh_krl_revoke_cert_by_కీలకం_id(నిర్మాణం ssh_krl *krl, స్థిరరాశి నిర్మాణం sshkey *ca_కీలకం,
    స్థిరరాశి అక్షరం *కీలకం_id)
{
	నిర్మాణం revoked_కీలకం_id *rki, *erki;
	నిర్మాణం revoked_certs *rc;
	పూర్ణాంకం r;

	ఒకవేళ ((r = revoked_certs_for_ca_కీలకం(krl, ca_కీలకం, &rc, 1)) != 0)
		తిరిగి r;

	KRL_DBG(("revoke %s", కీలకం_id));
	ఒకవేళ ((rki = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*rki))) == ఖాళీ ||
	    (rki->కీలకం_id = strdup(కీలకం_id)) == ఖాళీ) {
		విడుదల(rki);
		తిరిగి SSH_ERR_ALLOC_FAIL;
	}
	erki = RB_చొప్పించు(revoked_కీలకం_id_వృక్షం, &rc->revoked_కీలకం_ids, rki);
	ఒకవేళ (erki != ఖాళీ) {
		విడుదల(rki->కీలకం_id);
		విడుదల(rki);
	}
	తిరిగి 0;
}

/* Convert "key" to a public key blob without any certificate information */
స్థిర పూర్ణాంకం
plain_కీలకం_blob(స్థిరరాశి నిర్మాణం sshkey *కీలకం, u_char **blob, కొలత_t *blen)
{
	నిర్మాణం sshkey *kcopy;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshkey_from_వ్యక్తిగత(కీలకం, &kcopy)) != 0)
		తిరిగి r;
	ఒకవేళ (sshkey_is_cert(kcopy)) {
		ఒకవేళ ((r = sshkey_drop_cert(kcopy)) != 0) {
			sshkey_free(kcopy);
			తిరిగి r;
		}
	}
	r = sshkey_గమ్యం_blob(kcopy, blob, blen);
	sshkey_free(kcopy);
	తిరిగి r;
}

/* Revoke a key blob. Ownership of blob is transferred to the tree */
స్థిర పూర్ణాంకం
revoke_blob(నిర్మాణం revoked_blob_వృక్షం *rbt, u_char *blob, కొలత_t len)
{
	నిర్మాణం revoked_blob *rb, *erb;

	ఒకవేళ ((rb = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*rb))) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	rb->blob = blob;
	rb->len = len;
	erb = RB_చొప్పించు(revoked_blob_వృక్షం, rbt, rb);
	ఒకవేళ (erb != ఖాళీ) {
		విడుదల(rb->blob);
		విడుదల(rb);
	}
	తిరిగి 0;
}

పూర్ణాంకం
ssh_krl_revoke_కీలకం_explicit(నిర్మాణం ssh_krl *krl, స్థిరరాశి నిర్మాణం sshkey *కీలకం)
{
	u_char *blob;
	కొలత_t len;
	పూర్ణాంకం r;

	debug3_f("revoke type %s", sshkey_type(కీలకం));
	ఒకవేళ ((r = plain_కీలకం_blob(కీలకం, &blob, &len)) != 0)
		తిరిగి r;
	తిరిగి revoke_blob(&krl->revoked_కీలకాలు, blob, len);
}

స్థిర పూర్ణాంకం
revoke_by_hash(నిర్మాణం revoked_blob_వృక్షం *లక్ష్యం, స్థిరరాశి u_char *p, కొలత_t len)
{
	u_char *blob;
	పూర్ణాంకం r;

	/* need to copy hash, as revoke_blob steals ownership */
	ఒకవేళ ((blob = జ్ఞాపకం_ఇవ్వు(len)) == ఖాళీ)
		తిరిగి SSH_ERR_SYSTEM_ERROR;
	జ్ఞాపకం_నకలు(blob, p, len);
	ఒకవేళ ((r = revoke_blob(లక్ష్యం, blob, len)) != 0) {
		విడుదల(blob);
		తిరిగి r;
	}
	తిరిగి 0;
}

పూర్ణాంకం
ssh_krl_revoke_కీలకం_sha1(నిర్మాణం ssh_krl *krl, స్థిరరాశి u_char *p, కొలత_t len)
{
	debug3_f("revoke by sha1");
	ఒకవేళ (len != 20)
		తిరిగి SSH_ERR_INVALID_FORMAT;
	తిరిగి revoke_by_hash(&krl->revoked_sha1s, p, len);
}

పూర్ణాంకం
ssh_krl_revoke_కీలకం_sha256(నిర్మాణం ssh_krl *krl, స్థిరరాశి u_char *p, కొలత_t len)
{
	debug3_f("revoke by sha256");
	ఒకవేళ (len != 32)
		తిరిగి SSH_ERR_INVALID_FORMAT;
	తిరిగి revoke_by_hash(&krl->revoked_sha256s, p, len);
}

పూర్ణాంకం
ssh_krl_revoke_కీలకం(నిర్మాణం ssh_krl *krl, స్థిరరాశి నిర్మాణం sshkey *కీలకం)
{
	/* XXX replace with SHA256? */
	ఒకవేళ (!sshkey_is_cert(కీలకం))
		తిరిగి ssh_krl_revoke_కీలకం_explicit(krl, కీలకం);

	ఒకవేళ (కీలకం->cert->serial == 0) {
		తిరిగి ssh_krl_revoke_cert_by_కీలకం_id(krl,
		    కీలకం->cert->signature_కీలకం,
		    కీలకం->cert->కీలకం_id);
	} లేకపోతే {
		తిరిగి ssh_krl_revoke_cert_by_serial(krl,
		    కీలకం->cert->signature_కీలకం,
		    కీలకం->cert->serial);
	}
}

/*
 * Select the most compact section type to emit next in a KRL based on
 * the current section type, the run length of contiguous revoked serial
 * numbers and the gaps from the last and to the next revoked serial.
 * Applies a mostly-accurate bit cost model to select the section type
 * that will minimise the size of the resultant KRL.
 */
స్థిర పూర్ణాంకం
ఎంచుకో_తదుపరి_state(పూర్ణాంకం current_state, uint64_t contig, పూర్ణాంకం final,
    uint64_t చివరి_gap, uint64_t తదుపరి_gap, కొలత_t bitmap_len,
    పూర్ణాంకం *force_new_section)
{
	పూర్ణాంకం new_state;
	uint64_t ఖర్చు, ఖర్చు_list, ఖర్చు_range, ఖర్చు_bitmap, ఖర్చు_bitmap_restart;

	/*
	 * Avoid unsigned overflows.
	 * The limits are high enough to avoid confusing the calculations.
	 */
	contig = MINIMUM(contig, 1ULL<<31);
	చివరి_gap = MINIMUM(చివరి_gap, 1ULL<<31);
	తదుపరి_gap = MINIMUM(తదుపరి_gap, 1ULL<<31);

	/*
	 * Calculate the cost to switch from the current state to candidates.
	 * NB. range sections only ever contain a single range, so their
	 * switching cost is independent of the current_state.
	 */
	ఖర్చు_list = ఖర్చు_bitmap = ఖర్చు_bitmap_restart = 0;
	ఖర్చు_range = 8;
	ఎంపిక (current_state) {
	స్థితి KRL_SECTION_CERT_SERIAL_LIST:
		ఖర్చు_bitmap_restart = ఖర్చు_bitmap = 8 + 64;
		ఆపు;
	స్థితి KRL_SECTION_CERT_SERIAL_BITMAP:
		ఖర్చు_list = 8;
		ఖర్చు_bitmap_restart = 8 + 64;
		ఆపు;
	స్థితి KRL_SECTION_CERT_SERIAL_RANGE:
	స్థితి 0:
		ఖర్చు_bitmap_restart = ఖర్చు_bitmap = 8 + 64;
		ఖర్చు_list = 8;
	}

	/* Estimate base cost in bits of each section type */
	ఖర్చు_list += 64 * contig + (final ? 0 : 8+64);
	ఖర్చు_range += (2 * 64) + (final ? 0 : 8+64);
	ఖర్చు_bitmap += చివరి_gap + contig + (final ? 0 : MINIMUM(తదుపరి_gap, 8+64));
	ఖర్చు_bitmap_restart += contig + (final ? 0 : MINIMUM(తదుపరి_gap, 8+64));

	/* Convert to byte costs for actual comparison */
	ఖర్చు_list = (ఖర్చు_list + 7) / 8;
	ఖర్చు_bitmap = (ఖర్చు_bitmap + 7) / 8;
	ఖర్చు_bitmap_restart = (ఖర్చు_bitmap_restart + 7) / 8;
	ఖర్చు_range = (ఖర్చు_range + 7) / 8;

	/* Ensure that we never emit a bitmap larger than sshbuf can handle */
	ఒకవేళ (bitmap_len + ఖర్చు_bitmap >= SSHBUF_MAX_BIGNUM) {
		KRL_DBG(("bitmap overfull len=%zu cost=%llu max=%u",
		    bitmap_len, (గుర్తులేని దీర్ఘ దీర్ఘ)ఖర్చు_bitmap,
		    SSHBUF_MAX_BIGNUM));
		ఖర్చు_bitmap = (uint64_t)-1;
	}

	/* Now pick the best choice */
	*force_new_section = 0;
	new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
	ఖర్చు = ఖర్చు_bitmap;
	ఒకవేళ (ఖర్చు_range < ఖర్చు) {
		new_state = KRL_SECTION_CERT_SERIAL_RANGE;
		ఖర్చు = ఖర్చు_range;
	}
	ఒకవేళ (ఖర్చు_list < ఖర్చు) {
		new_state = KRL_SECTION_CERT_SERIAL_LIST;
		ఖర్చు = ఖర్చు_list;
	}
	ఒకవేళ (ఖర్చు_bitmap_restart < ఖర్చు) {
		new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
		*force_new_section = 1;
		ఖర్చు = ఖర్చు_bitmap_restart;
	}
	KRL_DBG(("contig %llu last_gap %llu next_gap %llu final %d, costs:"
	    "list %llu range %llu bitmap %llu new bitmap %llu, "
	    "selected 0x%02x%s", (దీర్ఘ దీర్ఘ గుర్తులేని)contig,
	    (దీర్ఘ దీర్ఘ గుర్తులేని)చివరి_gap, (దీర్ఘ దీర్ఘ గుర్తులేని)తదుపరి_gap, final,
	    (దీర్ఘ దీర్ఘ గుర్తులేని)ఖర్చు_list, (దీర్ఘ దీర్ఘ గుర్తులేని)ఖర్చు_range,
	    (దీర్ఘ దీర్ఘ గుర్తులేని)ఖర్చు_bitmap,
	    (దీర్ఘ దీర్ఘ గుర్తులేని)ఖర్చు_bitmap_restart, new_state,
	    *force_new_section ? " restart" : ""));
	తిరిగి new_state;
}

స్థిర పూర్ణాంకం
put_bitmap(నిర్మాణం sshbuf *buf, నిర్మాణం bitmap *bitmap)
{
	కొలత_t len;
	u_char *blob;
	పూర్ణాంకం r;

	len = bitmap_nbytes(bitmap);
	ఒకవేళ ((blob = జ్ఞాపకం_ఇవ్వు(len)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ (bitmap_గమ్యం_string(bitmap, blob, len) != 0) {
		విడుదల(blob);
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	r = sshbuf_put_bignum2_బైట్లు(buf, blob, len);
	విడుదల(blob);
	తిరిగి r;
}

/* Generate a KRL_SECTION_CERTIFICATES KRL section */
స్థిర పూర్ణాంకం
revoked_certs_generate(నిర్మాణం revoked_certs *rc, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం final, force_new_sect, r = SSH_ERR_అంతర్గత_ERROR;
	uint64_t i, contig, gap, చివరి = 0, bitmap_ప్రారంభం = 0;
	నిర్మాణం revoked_serial *rs, *nrs;
	నిర్మాణం revoked_కీలకం_id *rki;
	పూర్ణాంకం తదుపరి_state, state = 0;
	కొలత_t bitmap_len;
	నిర్మాణం sshbuf *sect;
	నిర్మాణం bitmap *bitmap = ఖాళీ;

	ఒకవేళ ((sect = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;

	/* Store the header: optional CA scope key, reserved */
	ఒకవేళ (rc->ca_కీలకం == ఖాళీ) {
		ఒకవేళ ((r = sshbuf_put_string(buf, ఖాళీ, 0)) != 0)
			వెళ్ళు బహిర్గతం;
	} లేకపోతే {
		ఒకవేళ ((r = sshkey_puts(rc->ca_కీలకం, buf)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put_string(buf, ఖాళీ, 0)) != 0)
		వెళ్ళు బహిర్గతం;

	/* Store the revoked serials.  */
	కొరకు (rs = RB_MIN(revoked_serial_వృక్షం, &rc->revoked_serials);
	     rs != ఖాళీ;
	     rs = RB_తదుపరి(revoked_serial_వృక్షం, &rc->revoked_serials, rs)) {
		KRL_DBG(("serial %llu:%llu state 0x%02x",
		    (దీర్ఘ దీర్ఘ గుర్తులేని)rs->lo, (దీర్ఘ దీర్ఘ గుర్తులేని)rs->hi,
		    state));

		/* Check contiguous length and gap to next section (if any) */
		nrs = RB_తదుపరి(revoked_serial_వృక్షం, &rc->revoked_serials, rs);
		final = nrs == ఖాళీ;
		gap = nrs == ఖాళీ ? 0 : nrs->lo - rs->hi;
		contig = 1 + (rs->hi - rs->lo);

		bitmap_len = state == KRL_SECTION_CERT_SERIAL_BITMAP ?
		    bitmap_nbytes(bitmap) : 0;

		/* Choose next state based on these */
		తదుపరి_state = ఎంచుకో_తదుపరి_state(state, contig, final,
		    state == 0 ? 0 : rs->lo - చివరి, gap, bitmap_len,
		    &force_new_sect);

		/*
		 * If the current section is a range section or has a different
		 * type to the next section, then finish it off now.
		 */
		ఒకవేళ (state != 0 && (force_new_sect || తదుపరి_state != state ||
		    state == KRL_SECTION_CERT_SERIAL_RANGE)) {
			KRL_DBG(("finish state 0x%02x", state));
			ఎంపిక (state) {
			స్థితి KRL_SECTION_CERT_SERIAL_LIST:
			స్థితి KRL_SECTION_CERT_SERIAL_RANGE:
				ఆపు;
			స్థితి KRL_SECTION_CERT_SERIAL_BITMAP:
				ఒకవేళ ((r = put_bitmap(sect, bitmap)) != 0)
					వెళ్ళు బహిర్గతం;
				bitmap_free(bitmap);
				bitmap = ఖాళీ;
				ఆపు;
			}
			ఒకవేళ ((r = sshbuf_put_u8(buf, state)) != 0 ||
			    (r = sshbuf_put_stringb(buf, sect)) != 0)
				వెళ్ళు బహిర్గతం;
			sshbuf_reset(sect);
		}

		/* If we are starting a new section then prepare it now */
		ఒకవేళ (తదుపరి_state != state || force_new_sect) {
			KRL_DBG(("start state 0x%02x",
			    తదుపరి_state));
			state = తదుపరి_state;
			sshbuf_reset(sect);
			ఎంపిక (state) {
			స్థితి KRL_SECTION_CERT_SERIAL_LIST:
			స్థితి KRL_SECTION_CERT_SERIAL_RANGE:
				ఆపు;
			స్థితి KRL_SECTION_CERT_SERIAL_BITMAP:
				ఒకవేళ ((bitmap = bitmap_new()) == ఖాళీ) {
					r = SSH_ERR_ALLOC_FAIL;
					వెళ్ళు బహిర్గతం;
				}
				bitmap_ప్రారంభం = rs->lo;
				ఒకవేళ ((r = sshbuf_put_u64(sect,
				    bitmap_ప్రారంభం)) != 0)
					వెళ్ళు బహిర్గతం;
				ఆపు;
			}
		}

		/* Perform section-specific processing */
		ఎంపిక (state) {
		స్థితి KRL_SECTION_CERT_SERIAL_LIST:
			కొరకు (i = 0; i < contig; i++) {
				ఒకవేళ ((r = sshbuf_put_u64(sect, rs->lo + i)) != 0)
					వెళ్ళు బహిర్గతం;
			}
			ఆపు;
		స్థితి KRL_SECTION_CERT_SERIAL_RANGE:
			ఒకవేళ ((r = sshbuf_put_u64(sect, rs->lo)) != 0 ||
			    (r = sshbuf_put_u64(sect, rs->hi)) != 0)
				వెళ్ళు బహిర్గతం;
			ఆపు;
		స్థితి KRL_SECTION_CERT_SERIAL_BITMAP:
			ఒకవేళ (rs->lo - bitmap_ప్రారంభం > గరిష్ఠ_పూర్ణాంకం) {
				r = SSH_ERR_INVALID_FORMAT;
				error_f("insane bitmap gap");
				వెళ్ళు బహిర్గతం;
			}
			కొరకు (i = 0; i < contig; i++) {
				ఒకవేళ (bitmap_సమితి_బిట్టు(bitmap,
				    rs->lo + i - bitmap_ప్రారంభం) != 0) {
					r = SSH_ERR_ALLOC_FAIL;
					వెళ్ళు బహిర్గతం;
				}
			}
			ఆపు;
		}
		చివరి = rs->hi;
	}
	/* Flush the remaining section, if any */
	ఒకవేళ (state != 0) {
		KRL_DBG(("serial final flush for state 0x%02x", state));
		ఎంపిక (state) {
		స్థితి KRL_SECTION_CERT_SERIAL_LIST:
		స్థితి KRL_SECTION_CERT_SERIAL_RANGE:
			ఆపు;
		స్థితి KRL_SECTION_CERT_SERIAL_BITMAP:
			ఒకవేళ ((r = put_bitmap(sect, bitmap)) != 0)
				వెళ్ళు బహిర్గతం;
			bitmap_free(bitmap);
			bitmap = ఖాళీ;
			ఆపు;
		}
		ఒకవేళ ((r = sshbuf_put_u8(buf, state)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	KRL_DBG(("serial done "));

	/* Now output a section for any revocations by key ID */
	sshbuf_reset(sect);
	RB_FOREACH(rki, revoked_కీలకం_id_వృక్షం, &rc->revoked_కీలకం_ids) {
		KRL_DBG(("key ID %s", rki->కీలకం_id));
		ఒకవేళ ((r = sshbuf_put_cstring(sect, rki->కీలకం_id)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshbuf_len(sect) != 0) {
		ఒకవేళ ((r = sshbuf_put_u8(buf, KRL_SECTION_CERT_కీలకం_ID)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	r = 0;
 బహిర్గతం:
	bitmap_free(bitmap);
	sshbuf_free(sect);
	తిరిగి r;
}

పూర్ణాంకం
ssh_krl_గమ్యం_blob(నిర్మాణం ssh_krl *krl, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	నిర్మాణం revoked_certs *rc;
	నిర్మాణం revoked_blob *rb;
	నిర్మాణం sshbuf *sect;
	u_char *sblob = ఖాళీ;

	ఒకవేళ (krl->generated_date == 0)
		krl->generated_date = time(ఖాళీ);

	ఒకవేళ ((sect = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;

	/* Store the header */
	ఒకవేళ ((r = sshbuf_put(buf, KRL_MAGIC, పరిమాణం(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_put_u32(buf, KRL_FORMAT_సంస్కరణ)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->krl_సంస్కరణ)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->generated_date)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->flags)) != 0 ||
	    (r = sshbuf_put_string(buf, ఖాళీ, 0)) != 0 ||
	    (r = sshbuf_put_cstring(buf, krl->comment)) != 0)
		వెళ్ళు బహిర్గతం;

	/* Store sections for revoked certificates */
	TAILQ_FOREACH(rc, &krl->revoked_certs, నమోదు_2) {
		sshbuf_reset(sect);
		ఒకవేళ ((r = revoked_certs_generate(rc, sect)) != 0)
			వెళ్ళు బహిర్గతం;
		ఒకవేళ ((r = sshbuf_put_u8(buf, KRL_SECTION_CERTIFICATES)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			వెళ్ళు బహిర్గతం;
	}

	/* Finally, output sections for revocations by public key/hash */
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_వృక్షం, &krl->revoked_కీలకాలు) {
		KRL_DBG(("key len %zu ", rb->len));
		ఒకవేళ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshbuf_len(sect) != 0) {
		ఒకవేళ ((r = sshbuf_put_u8(buf, KRL_SECTION_EXPLICIT_కీలకం)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_వృక్షం, &krl->revoked_sha1s) {
		KRL_DBG(("hash len %zu ", rb->len));
		ఒకవేళ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshbuf_len(sect) != 0) {
		ఒకవేళ ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA1)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_వృక్షం, &krl->revoked_sha256s) {
		KRL_DBG(("hash len %zu ", rb->len));
		ఒకవేళ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshbuf_len(sect) != 0) {
		ఒకవేళ ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA256)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	/* success */
	r = 0;
 బహిర్గతం:
	విడుదల(sblob);
	sshbuf_free(sect);
	తిరిగి r;
}

స్థిర శూన్య
format_timestamp(uint64_t timestamp, అక్షరం *ts, కొలత_t nts)
{
	time_t t;
	నిర్మాణం tm *tm;

	t = timestamp;
	tm = localtime(&t);
	ఒకవేళ (tm == ఖాళీ)
		strlcpy(ts, "<INVALID>", nts);
	లేకపోతే {
		*ts = '\0';
		strftime(ts, nts, "%Y%m%dT%H%M%S", tm);
	}
}

స్థిర పూర్ణాంకం
cert_extension_subsection(నిర్మాణం sshbuf *subsect, నిర్మాణం ssh_krl *krl)
{
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	u_char critical = 1;
	నిర్మాణం sshbuf *విలువ = ఖాళీ;
	అక్షరం *name = ఖాళీ;

	ఒకవేళ ((r = sshbuf_get_cstring(subsect, &name, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_u8(subsect, &critical)) != 0 ||
	    (r = sshbuf_froms(subsect, &విలువ)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid certificate extension subsection");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshbuf_len(subsect) != 0) {
		error("KRL has invalid certificate extension subsection: "
		    "trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	debug_f("cert extension %s critical %u len %zu",
	    name, critical, sshbuf_len(విలువ));
	/* no extensions are currently supported */
	ఒకవేళ (critical) {
		error("KRL contains unsupported critical certificate "
		    "subsection \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	r = 0;
 బహిర్గతం:
	విడుదల(name);
	sshbuf_free(విలువ);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
parse_revoked_certs(నిర్మాణం sshbuf *buf, నిర్మాణం ssh_krl *krl)
{
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	u_char type;
	స్థిరరాశి u_char *blob;
	కొలత_t blen, nbits;
	నిర్మాణం sshbuf *subsect = ఖాళీ;
	uint64_t serial, serial_lo, serial_hi;
	నిర్మాణం bitmap *bitmap = ఖాళీ;
	అక్షరం *కీలకం_id = ఖాళీ;
	నిర్మాణం sshkey *ca_కీలకం = ఖాళీ;

	ఒకవేళ ((subsect = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;

	/* Header: key, reserved */
	ఒకవేళ ((r = sshbuf_get_string_ప్రత్యక్ష(buf, &blob, &blen)) != 0 ||
	    (r = sshbuf_skip_string(buf)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (blen != 0 && (r = sshkey_from_blob(blob, blen, &ca_కీలకం)) != 0)
		వెళ్ళు బహిర్గతం;

	అయితే (sshbuf_len(buf) > 0) {
		sshbuf_free(subsect);
		subsect = ఖాళీ;
		ఒకవేళ ((r = sshbuf_get_u8(buf, &type)) != 0 ||
		    (r = sshbuf_froms(buf, &subsect)) != 0)
			వెళ్ళు బహిర్గతం;
		KRL_DBG(("subsection type 0x%02x", type));
		/* sshbuf_dump(subsect, stderr); */

		ఎంపిక (type) {
		స్థితి KRL_SECTION_CERT_SERIAL_LIST:
			అయితే (sshbuf_len(subsect) > 0) {
				ఒకవేళ ((r = sshbuf_get_u64(subsect, &serial)) != 0)
					వెళ్ళు బహిర్గతం;
				ఒకవేళ ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_కీలకం, serial)) != 0)
					వెళ్ళు బహిర్గతం;
			}
			ఆపు;
		స్థితి KRL_SECTION_CERT_SERIAL_RANGE:
			ఒకవేళ ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_u64(subsect, &serial_hi)) != 0)
				వెళ్ళు బహిర్గతం;
			ఒకవేళ ((r = ssh_krl_revoke_cert_by_serial_range(krl,
			    ca_కీలకం, serial_lo, serial_hi)) != 0)
				వెళ్ళు బహిర్గతం;
			ఆపు;
		స్థితి KRL_SECTION_CERT_SERIAL_BITMAP:
			ఒకవేళ ((bitmap = bitmap_new()) == ఖాళీ) {
				r = SSH_ERR_ALLOC_FAIL;
				వెళ్ళు బహిర్గతం;
			}
			ఒకవేళ ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_bignum2_బైట్లు_ప్రత్యక్ష(subsect,
			    &blob, &blen)) != 0)
				వెళ్ళు బహిర్గతం;
			ఒకవేళ (bitmap_from_string(bitmap, blob, blen) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				వెళ్ళు బహిర్గతం;
			}
			nbits = bitmap_nbits(bitmap);
			కొరకు (serial = 0; serial < (uint64_t)nbits; serial++) {
				ఒకవేళ (serial > 0 && serial_lo + serial == 0) {
					error_f("bitmap wraps u64");
					r = SSH_ERR_INVALID_FORMAT;
					వెళ్ళు బహిర్గతం;
				}
				ఒకవేళ (!bitmap_test_బిట్టు(bitmap, serial))
					కొనసాగు;
				ఒకవేళ ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_కీలకం, serial_lo + serial)) != 0)
					వెళ్ళు బహిర్గతం;
			}
			bitmap_free(bitmap);
			bitmap = ఖాళీ;
			ఆపు;
		స్థితి KRL_SECTION_CERT_కీలకం_ID:
			అయితే (sshbuf_len(subsect) > 0) {
				ఒకవేళ ((r = sshbuf_get_cstring(subsect,
				    &కీలకం_id, ఖాళీ)) != 0)
					వెళ్ళు బహిర్గతం;
				ఒకవేళ ((r = ssh_krl_revoke_cert_by_కీలకం_id(krl,
				    ca_కీలకం, కీలకం_id)) != 0)
					వెళ్ళు బహిర్గతం;
				విడుదల(కీలకం_id);
				కీలకం_id = ఖాళీ;
			}
			ఆపు;
		స్థితి KRL_SECTION_CERT_EXTENSION:
			ఒకవేళ ((r = cert_extension_subsection(subsect, krl)) != 0)
				వెళ్ళు బహిర్గతం;
			ఆపు;
		అప్రమేయ:
			error("Unsupported KRL certificate section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (sshbuf_len(subsect) > 0) {
			error("KRL certificate section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
	}

	r = 0;
 బహిర్గతం:
	ఒకవేళ (bitmap != ఖాళీ)
		bitmap_free(bitmap);
	విడుదల(కీలకం_id);
	sshkey_free(ca_కీలకం);
	sshbuf_free(subsect);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
blob_section(నిర్మాణం sshbuf *sect, నిర్మాణం revoked_blob_వృక్షం *లక్ష్యం_వృక్షం,
    కొలత_t expected_len)
{
	u_char *rdata = ఖాళీ;
	కొలత_t rlen = 0;
	పూర్ణాంకం r;

	అయితే (sshbuf_len(sect) > 0) {
		ఒకవేళ ((r = sshbuf_get_string(sect, &rdata, &rlen)) != 0)
			తిరిగి r;
		ఒకవేళ (expected_len != 0 && rlen != expected_len) {
			error_f("bad length");
			విడుదల(rdata);
			తిరిగి SSH_ERR_INVALID_FORMAT;
		}
		ఒకవేళ ((r = revoke_blob(లక్ష్యం_వృక్షం, rdata, rlen)) != 0) {
			విడుదల(rdata);
			తిరిగి r;
		}
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
extension_section(నిర్మాణం sshbuf *sect, నిర్మాణం ssh_krl *krl)
{
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	u_char critical = 1;
	నిర్మాణం sshbuf *విలువ = ఖాళీ;
	అక్షరం *name = ఖాళీ;

	ఒకవేళ ((r = sshbuf_get_cstring(sect, &name, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_u8(sect, &critical)) != 0 ||
	    (r = sshbuf_froms(sect, &విలువ)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid extension section");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshbuf_len(sect) != 0) {
		error("KRL has invalid extension section: trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	debug_f("extension %s critical %u len %zu",
	    name, critical, sshbuf_len(విలువ));
	/* no extensions are currently supported */
	ఒకవేళ (critical) {
		error("KRL contains unsupported critical section \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	r = 0;
 బహిర్గతం:
	విడుదల(name);
	sshbuf_free(విలువ);
	తిరిగి r;
}

/* Attempt to parse a KRL */
పూర్ణాంకం
ssh_krl_from_blob(నిర్మాణం sshbuf *buf, నిర్మాణం ssh_krl **krlp)
{
	నిర్మాణం sshbuf *copy = ఖాళీ, *sect = ఖాళీ;
	నిర్మాణం ssh_krl *krl = ఖాళీ;
	అక్షరం timestamp[64];
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	u_char type;
	u_int format_సంస్కరణ;

	*krlp = ఖాళీ;

	/* KRL must begin with magic string */
	ఒకవేళ ((r = sshbuf_cmp(buf, 0, KRL_MAGIC, పరిమాణం(KRL_MAGIC) - 1)) != 0) {
		debug2_f("bad KRL magic header");
		తిరిగి SSH_ERR_KRL_BAD_MAGIC;
	}

	ఒకవేళ ((krl = ssh_krl_init()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		error_f("alloc failed");
		వెళ్ళు బహిర్గతం;
	}
	/* Don't modify buffer */
	ఒకవేళ ((copy = sshbuf_fromb(buf)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_consume(copy, పరిమాణం(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_get_u32(copy, &format_సంస్కరణ)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (format_సంస్కరణ != KRL_FORMAT_సంస్కరణ) {
		error_f("unsupported KRL format version %u", format_సంస్కరణ);
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_get_u64(copy, &krl->krl_సంస్కరణ)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->generated_date)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->flags)) != 0 ||
	    (r = sshbuf_skip_string(copy)) != 0 ||
	    (r = sshbuf_get_cstring(copy, &krl->comment, ఖాళీ)) != 0) {
		error_fr(r, "parse KRL header");
		వెళ్ళు బహిర్గతం;
	}
	format_timestamp(krl->generated_date, timestamp, పరిమాణం(timestamp));
	debug("KRL version %llu generated at %s%s%s",
	    (దీర్ఘ దీర్ఘ గుర్తులేని)krl->krl_సంస్కరణ, timestamp,
	    *krl->comment ? ": " : "", krl->comment);

	/* Parse and load the KRL sections. */
	అయితే (sshbuf_len(copy) > 0) {
		sshbuf_free(sect);
		sect = ఖాళీ;
		ఒకవేళ ((r = sshbuf_get_u8(copy, &type)) != 0 ||
		    (r = sshbuf_froms(copy, &sect)) != 0)
			వెళ్ళు బహిర్గతం;
		KRL_DBG(("section 0x%02x", type));

		ఎంపిక (type) {
		స్థితి KRL_SECTION_CERTIFICATES:
			ఒకవేళ ((r = parse_revoked_certs(sect, krl)) != 0)
				వెళ్ళు బహిర్గతం;
			ఆపు;
		స్థితి KRL_SECTION_EXPLICIT_కీలకం:
			ఒకవేళ ((r = blob_section(sect,
			    &krl->revoked_కీలకాలు, 0)) != 0)
				వెళ్ళు బహిర్గతం;
			ఆపు;
		స్థితి KRL_SECTION_FINGERPRINT_SHA1:
			ఒకవేళ ((r = blob_section(sect,
			    &krl->revoked_sha1s, 20)) != 0)
				వెళ్ళు బహిర్గతం;
			ఆపు;
		స్థితి KRL_SECTION_FINGERPRINT_SHA256:
			ఒకవేళ ((r = blob_section(sect,
			    &krl->revoked_sha256s, 32)) != 0)
				వెళ్ళు బహిర్గతం;
			ఆపు;
		స్థితి KRL_SECTION_EXTENSION:
			ఒకవేళ ((r = extension_section(sect, krl)) != 0)
				వెళ్ళు బహిర్గతం;
			ఆపు;
		స్థితి KRL_SECTION_SIGNATURE:
			/* Handled above, but still need to stay in synch */
			sshbuf_free(sect);
			sect = ఖాళీ;
			ఒకవేళ ((r = sshbuf_skip_string(copy)) != 0)
				వెళ్ళు బహిర్గతం;
			ఆపు;
		అప్రమేయ:
			error("Unsupported KRL section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (sect != ఖాళీ && sshbuf_len(sect) > 0) {
			error("KRL section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
	}

	/* Success */
	*krlp = krl;
	r = 0;
 బహిర్గతం:
	ఒకవేళ (r != 0)
		ssh_krl_free(krl);
	sshbuf_free(copy);
	sshbuf_free(sect);
	తిరిగి r;
}

/* Checks certificate serial number and key ID revocation */
స్థిర పూర్ణాంకం
is_cert_revoked(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం revoked_certs *rc)
{
	నిర్మాణం revoked_serial rs, *ers;
	నిర్మాణం revoked_కీలకం_id rki, *erki;

	/* Check revocation by cert key ID */
	memset(&rki, 0, పరిమాణం(rki));
	rki.కీలకం_id = కీలకం->cert->కీలకం_id;
	erki = RB_కనుగొను(revoked_కీలకం_id_వృక్షం, &rc->revoked_కీలకం_ids, &rki);
	ఒకవేళ (erki != ఖాళీ) {
		KRL_DBG(("revoked by key ID"));
		తిరిగి SSH_ERR_కీలకం_REVOKED;
	}

	/*
	 * Zero serials numbers are ignored (it's the default when the
	 * CA doesn't specify one).
	 */
	ఒకవేళ (కీలకం->cert->serial == 0)
		తిరిగి 0;

	memset(&rs, 0, పరిమాణం(rs));
	rs.lo = rs.hi = కీలకం->cert->serial;
	ers = RB_కనుగొను(revoked_serial_వృక్షం, &rc->revoked_serials, &rs);
	ఒకవేళ (ers != ఖాళీ) {
		KRL_DBG(("revoked serial %llu matched %llu:%llu",
		    (గుర్తులేని దీర్ఘ దీర్ఘ)కీలకం->cert->serial,
		    (గుర్తులేని దీర్ఘ దీర్ఘ)ers->lo,
		    (గుర్తులేని దీర్ఘ దీర్ఘ)ers->hi));
		తిరిగి SSH_ERR_కీలకం_REVOKED;
	}
	తిరిగి 0;
}

/* Checks whether a given key/cert is revoked. Does not check its CA */
స్థిర పూర్ణాంకం
is_కీలకం_revoked(నిర్మాణం ssh_krl *krl, స్థిరరాశి నిర్మాణం sshkey *కీలకం)
{
	నిర్మాణం revoked_blob rb, *erb;
	నిర్మాణం revoked_certs *rc;
	పూర్ణాంకం r;

	/* Check explicitly revoked hashes first */
	memset(&rb, 0, పరిమాణం(rb));
	ఒకవేళ ((r = sshkey_fingerprint_raw(కీలకం, SSH_DIGEST_SHA1,
	    &rb.blob, &rb.len)) != 0)
		తిరిగి r;
	erb = RB_కనుగొను(revoked_blob_వృక్షం, &krl->revoked_sha1s, &rb);
	విడుదల(rb.blob);
	ఒకవేళ (erb != ఖాళీ) {
		KRL_DBG(("revoked by key SHA1"));
		తిరిగి SSH_ERR_కీలకం_REVOKED;
	}
	memset(&rb, 0, పరిమాణం(rb));
	ఒకవేళ ((r = sshkey_fingerprint_raw(కీలకం, SSH_DIGEST_SHA256,
	    &rb.blob, &rb.len)) != 0)
		తిరిగి r;
	erb = RB_కనుగొను(revoked_blob_వృక్షం, &krl->revoked_sha256s, &rb);
	విడుదల(rb.blob);
	ఒకవేళ (erb != ఖాళీ) {
		KRL_DBG(("revoked by key SHA256"));
		తిరిగి SSH_ERR_కీలకం_REVOKED;
	}

	/* Next, explicit keys */
	memset(&rb, 0, పరిమాణం(rb));
	ఒకవేళ ((r = plain_కీలకం_blob(కీలకం, &rb.blob, &rb.len)) != 0)
		తిరిగి r;
	erb = RB_కనుగొను(revoked_blob_వృక్షం, &krl->revoked_కీలకాలు, &rb);
	విడుదల(rb.blob);
	ఒకవేళ (erb != ఖాళీ) {
		KRL_DBG(("revoked by explicit key"));
		తిరిగి SSH_ERR_కీలకం_REVOKED;
	}

	ఒకవేళ (!sshkey_is_cert(కీలకం))
		తిరిగి 0;

	/* Check cert revocation for the specified CA */
	ఒకవేళ ((r = revoked_certs_for_ca_కీలకం(krl, కీలకం->cert->signature_కీలకం,
	    &rc, 0)) != 0)
		తిరిగి r;
	ఒకవేళ (rc != ఖాళీ) {
		ఒకవేళ ((r = is_cert_revoked(కీలకం, rc)) != 0)
			తిరిగి r;
	}
	/* Check cert revocation for the wildcard CA */
	ఒకవేళ ((r = revoked_certs_for_ca_కీలకం(krl, ఖాళీ, &rc, 0)) != 0)
		తిరిగి r;
	ఒకవేళ (rc != ఖాళీ) {
		ఒకవేళ ((r = is_cert_revoked(కీలకం, rc)) != 0)
			తిరిగి r;
	}

	KRL_DBG(("%llu no match", (గుర్తులేని దీర్ఘ దీర్ఘ)కీలకం->cert->serial));
	తిరిగి 0;
}

పూర్ణాంకం
ssh_krl_check_కీలకం(నిర్మాణం ssh_krl *krl, స్థిరరాశి నిర్మాణం sshkey *కీలకం)
{
	పూర్ణాంకం r;

	KRL_DBG(("checking key"));
	ఒకవేళ ((r = is_కీలకం_revoked(krl, కీలకం)) != 0)
		తిరిగి r;
	ఒకవేళ (sshkey_is_cert(కీలకం)) {
		debug2_f("checking CA key");
		ఒకవేళ ((r = is_కీలకం_revoked(krl, కీలకం->cert->signature_కీలకం)) != 0)
			తిరిగి r;
	}
	KRL_DBG(("key okay"));
	తిరిగి 0;
}

పూర్ణాంకం
ssh_krl_file_కలిగియుంది_కీలకం(స్థిరరాశి అక్షరం *మార్గం, స్థిరరాశి నిర్మాణం sshkey *కీలకం)
{
	నిర్మాణం sshbuf *krlbuf = ఖాళీ;
	నిర్మాణం ssh_krl *krl = ఖాళీ;
	పూర్ణాంకం oerrno = 0, r;

	ఒకవేళ (మార్గం == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ ((r = sshbuf_ఎక్కించు_file(మార్గం, &krlbuf)) != 0) {
		oerrno = errno;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = ssh_krl_from_blob(krlbuf, &krl)) != 0)
		వెళ్ళు బహిర్గతం;
	debug2_f("checking KRL %s", మార్గం);
	r = ssh_krl_check_కీలకం(krl, కీలకం);
 బహిర్గతం:
	sshbuf_free(krlbuf);
	ssh_krl_free(krl);
	ఒకవేళ (r != 0)
		errno = oerrno;
	తిరిగి r;
}

పూర్ణాంకం
krl_dump(నిర్మాణం ssh_krl *krl, FILE *f)
{
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	నిర్మాణం revoked_blob *rb;
	నిర్మాణం revoked_certs *rc;
	నిర్మాణం revoked_serial *rs;
	నిర్మాణం revoked_కీలకం_id *rki;
	పూర్ణాంకం r, ret = 0;
	అక్షరం *fp, timestamp[64];

	/* Try to print in a KRL spec-compatible format */
	format_timestamp(krl->generated_date, timestamp, పరిమాణం(timestamp));
	fprintf(f, "# KRL version %llu\n", (గుర్తులేని దీర్ఘ దీర్ఘ)krl->krl_సంస్కరణ);
	fprintf(f, "# Generated at %s\n", timestamp);
	ఒకవేళ (krl->comment != ఖాళీ && *krl->comment != '\0') {
		r = గరిష్ఠ_పూర్ణాంకం;
		asmprintf(&fp, గరిష్ఠ_పూర్ణాంకం, &r, "%s", krl->comment);
		fprintf(f, "# Comment: %s\n", fp);
		విడుదల(fp);
	}
	fputc('\n', f);

	RB_FOREACH(rb, revoked_blob_వృక్షం, &krl->revoked_కీలకాలు) {
		ఒకవేళ ((r = sshkey_from_blob(rb->blob, rb->len, &కీలకం)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			error_r(r, "parse KRL key");
			కొనసాగు;
		}
		ఒకవేళ ((fp = sshkey_fingerprint(కీలకం, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ఖాళీ) {
			ret = SSH_ERR_INVALID_FORMAT;
			error("sshkey_fingerprint failed");
			కొనసాగు;
		}
		fprintf(f, "hash: %s # %s\n", fp, sshkey_ssh_name(కీలకం));
		విడుదల(fp);
		విడుదల(కీలకం);
	}
	RB_FOREACH(rb, revoked_blob_వృక్షం, &krl->revoked_sha256s) {
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "hash: SHA256:%s\n", fp);
		విడుదల(fp);
	}
	RB_FOREACH(rb, revoked_blob_వృక్షం, &krl->revoked_sha1s) {
		/*
		 * There is not KRL spec keyword for raw SHA1 hashes, so
		 * print them as comments.
		 */
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "# hash SHA1:%s\n", fp);
		విడుదల(fp);
	}

	TAILQ_FOREACH(rc, &krl->revoked_certs, నమోదు_2) {
		fputc('\n', f);
		ఒకవేళ (rc->ca_కీలకం == ఖాళీ)
			fprintf(f, "# Wildcard CA\n");
		లేకపోతే {
			ఒకవేళ ((fp = sshkey_fingerprint(rc->ca_కీలకం,
			    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ఖాళీ) {
				ret = SSH_ERR_INVALID_FORMAT;
				error("sshkey_fingerprint failed");
				కొనసాగు;
			}
			fprintf(f, "# CA key %s %s\n",
			    sshkey_ssh_name(rc->ca_కీలకం), fp);
			విడుదల(fp);
		}
		RB_FOREACH(rs, revoked_serial_వృక్షం, &rc->revoked_serials) {
			ఒకవేళ (rs->lo == rs->hi) {
				fprintf(f, "serial: %llu\n",
				    (గుర్తులేని దీర్ఘ దీర్ఘ)rs->lo);
			} లేకపోతే {
				fprintf(f, "serial: %llu-%llu\n",
				    (గుర్తులేని దీర్ఘ దీర్ఘ)rs->lo,
				    (గుర్తులేని దీర్ఘ దీర్ఘ)rs->hi);
			}
		}
		RB_FOREACH(rki, revoked_కీలకం_id_వృక్షం, &rc->revoked_కీలకం_ids) {
			/*
			 * We don't want key IDs with embedded newlines to
			 * mess up the display.
			 */
			r = గరిష్ఠ_పూర్ణాంకం;
			asmprintf(&fp, గరిష్ఠ_పూర్ణాంకం, &r, "%s", rki->కీలకం_id);
			fprintf(f, "id: %s\n", fp);
			విడుదల(fp);
		}
	}
	తిరిగి ret;
}
