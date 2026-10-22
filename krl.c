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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/tree.h>
#অন্তর্ভাব <sys/queue.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <time.h>

#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "bitmap.h"
#অন্তর্ভাব "utf8.h"

#অন্তর্ভাব "krl.h"

/* #define DEBUG_KRL */
#ifdef DEBUG_KRL
# define KRL_DBG(x) debug3_f x
#অন্যথা
# define KRL_DBG(x)
#endif

/*
 * Trees of revoked serial numbers, key IDs and keys. This allows
 * quick searching, querying and producing lists in canonical order.
 */

/* Tree of serial numbers. XXX make smarter: really need a real sparse bitmap */
কাঠামো revoked_serial {
	uint64_t lo, hi;
	RB_ENTRY(revoked_serial) বৃক্ষ_entry;
};
স্থির পূর্ণসংখ্যা serial_cmp(কাঠামো revoked_serial *a, কাঠামো revoked_serial *b);
RB_শীর্ষ(revoked_serial_বৃক্ষ, revoked_serial);
RB_GENERATE_STATIC(revoked_serial_বৃক্ষ, revoked_serial, বৃক্ষ_entry, serial_cmp)

/* Tree of key IDs */
কাঠামো revoked_চাবি_id {
	অক্ষর *চাবি_id;
	RB_ENTRY(revoked_চাবি_id) বৃক্ষ_entry;
};
স্থির পূর্ণসংখ্যা চাবি_id_cmp(কাঠামো revoked_চাবি_id *a, কাঠামো revoked_চাবি_id *b);
RB_শীর্ষ(revoked_চাবি_id_বৃক্ষ, revoked_চাবি_id);
RB_GENERATE_STATIC(revoked_চাবি_id_বৃক্ষ, revoked_চাবি_id, বৃক্ষ_entry, চাবি_id_cmp)

/* Tree of blobs (used for keys and fingerprints) */
কাঠামো revoked_blob {
	u_char *blob;
	আকার_t len;
	RB_ENTRY(revoked_blob) বৃক্ষ_entry;
};
স্থির পূর্ণসংখ্যা blob_cmp(কাঠামো revoked_blob *a, কাঠামো revoked_blob *b);
RB_শীর্ষ(revoked_blob_বৃক্ষ, revoked_blob);
RB_GENERATE_STATIC(revoked_blob_বৃক্ষ, revoked_blob, বৃক্ষ_entry, blob_cmp)

/* Tracks revoked certs for a single CA */
কাঠামো revoked_certs {
	কাঠামো sshkey *ca_চাবি;
	কাঠামো revoked_serial_বৃক্ষ revoked_serials;
	কাঠামো revoked_চাবি_id_বৃক্ষ revoked_চাবি_ids;
	TAILQ_ENTRY(revoked_certs) entry;
};
TAILQ_HEAD(revoked_certs_list, revoked_certs);

কাঠামো ssh_krl {
	uint64_t krl_version;
	uint64_t generated_date;
	uint64_t flags;
	অক্ষর *comment;
	কাঠামো revoked_blob_বৃক্ষ revoked_চাবিগুলি;
	কাঠামো revoked_blob_বৃক্ষ revoked_sha1s;
	কাঠামো revoked_blob_বৃক্ষ revoked_sha256s;
	কাঠামো revoked_certs_list revoked_certs;
};

/* Return equal if a and b overlap */
স্থির পূর্ণসংখ্যা
serial_cmp(কাঠামো revoked_serial *a, কাঠামো revoked_serial *b)
{
	যদি (a->hi >= b->lo && a->lo <= b->hi)
		ফেরত 0;
	ফেরত a->lo < b->lo ? -1 : 1;
}

স্থির পূর্ণসংখ্যা
চাবি_id_cmp(কাঠামো revoked_চাবি_id *a, কাঠামো revoked_চাবি_id *b)
{
	ফেরত strcmp(a->চাবি_id, b->চাবি_id);
}

স্থির পূর্ণসংখ্যা
blob_cmp(কাঠামো revoked_blob *a, কাঠামো revoked_blob *b)
{
	পূর্ণসংখ্যা r;

	যদি (a->len != b->len) {
		যদি ((r = memcmp(a->blob, b->blob, MINIMUM(a->len, b->len))) != 0)
			ফেরত r;
		ফেরত a->len > b->len ? 1 : -1;
	} অন্যথা
		ফেরত memcmp(a->blob, b->blob, a->len);
}

কাঠামো ssh_krl *
ssh_krl_init(শূন্য)
{
	কাঠামো ssh_krl *krl;

	যদি ((krl = calloc(1, আকার(*krl))) == ফাঁকা)
		ফেরত ফাঁকা;
	RB_INIT(&krl->revoked_চাবিগুলি);
	RB_INIT(&krl->revoked_sha1s);
	RB_INIT(&krl->revoked_sha256s);
	TAILQ_INIT(&krl->revoked_certs);
	ফেরত krl;
}

স্থির শূন্য
revoked_certs_free(কাঠামো revoked_certs *rc)
{
	কাঠামো revoked_serial *rs, *trs;
	কাঠামো revoked_চাবি_id *rki, *trki;

	যদি (rc == ফাঁকা)
		ফেরত;
	RB_FOREACH_SAFE(rs, revoked_serial_বৃক্ষ, &rc->revoked_serials, trs) {
		RB_REMOVE(revoked_serial_বৃক্ষ, &rc->revoked_serials, rs);
		মুক্ত(rs);
	}
	RB_FOREACH_SAFE(rki, revoked_চাবি_id_বৃক্ষ, &rc->revoked_চাবি_ids, trki) {
		RB_REMOVE(revoked_চাবি_id_বৃক্ষ, &rc->revoked_চাবি_ids, rki);
		মুক্ত(rki->চাবি_id);
		মুক্ত(rki);
	}
	sshkey_free(rc->ca_চাবি);
	freezero(rc, আকার(*rc));
}

শূন্য
ssh_krl_free(কাঠামো ssh_krl *krl)
{
	কাঠামো revoked_blob *rb, *trb;
	কাঠামো revoked_certs *rc, *trc;

	যদি (krl == ফাঁকা)
		ফেরত;

	মুক্ত(krl->comment);
	RB_FOREACH_SAFE(rb, revoked_blob_বৃক্ষ, &krl->revoked_চাবিগুলি, trb) {
		RB_REMOVE(revoked_blob_বৃক্ষ, &krl->revoked_চাবিগুলি, rb);
		মুক্ত(rb->blob);
		মুক্ত(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_বৃক্ষ, &krl->revoked_sha1s, trb) {
		RB_REMOVE(revoked_blob_বৃক্ষ, &krl->revoked_sha1s, rb);
		মুক্ত(rb->blob);
		মুক্ত(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_বৃক্ষ, &krl->revoked_sha256s, trb) {
		RB_REMOVE(revoked_blob_বৃক্ষ, &krl->revoked_sha256s, rb);
		মুক্ত(rb->blob);
		মুক্ত(rb);
	}
	TAILQ_FOREACH_SAFE(rc, &krl->revoked_certs, entry, trc) {
		TAILQ_REMOVE(&krl->revoked_certs, rc, entry);
		revoked_certs_free(rc);
	}
	মুক্ত(krl);
}

শূন্য
ssh_krl_set_version(কাঠামো ssh_krl *krl, uint64_t version)
{
	krl->krl_version = version;
}

পূর্ণসংখ্যা
ssh_krl_set_comment(কাঠামো ssh_krl *krl, ধ্রুবক অক্ষর *comment)
{
	মুক্ত(krl->comment);
	যদি ((krl->comment = strdup(comment)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	ফেরত 0;
}

/*
 * Find the revoked_certs struct for a CA key. If allow_create is set then
 * create a new one in the tree if one did not exist already.
 */
স্থির পূর্ণসংখ্যা
revoked_certs_for_ca_চাবি(কাঠামো ssh_krl *krl, ধ্রুবক কাঠামো sshkey *ca_চাবি,
    কাঠামো revoked_certs **rcp, পূর্ণসংখ্যা allow_create)
{
	কাঠামো revoked_certs *rc;
	পূর্ণসংখ্যা r;

	*rcp = ফাঁকা;
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		যদি ((ca_চাবি == ফাঁকা && rc->ca_চাবি == ফাঁকা) ||
		    sshkey_equal(rc->ca_চাবি, ca_চাবি)) {
			*rcp = rc;
			ফেরত 0;
		}
	}
	যদি (!allow_create)
		ফেরত 0;
	/* If this CA doesn't exist in the list then add it now */
	যদি ((rc = calloc(1, আকার(*rc))) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি (ca_চাবি == ফাঁকা)
		rc->ca_চাবি = ফাঁকা;
	অন্যথা যদি ((r = sshkey_from_private(ca_চাবি, &rc->ca_চাবি)) != 0) {
		মুক্ত(rc);
		ফেরত r;
	}
	RB_INIT(&rc->revoked_serials);
	RB_INIT(&rc->revoked_চাবি_ids);
	TAILQ_INSERT_TAIL(&krl->revoked_certs, rc, entry);
	KRL_DBG(("new CA %s", ca_চাবি == ফাঁকা ? "*" : sshkey_type(ca_চাবি)));
	*rcp = rc;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
ঢোকাও_serial_range(কাঠামো revoked_serial_বৃক্ষ *rt, uint64_t lo, uint64_t hi)
{
	কাঠামো revoked_serial rs, *ers, *crs, *irs;

	KRL_DBG(("insert %llu:%llu",
	    (unsigned long long)lo, (unsigned long long)hi));
	memset(&rs, 0, আকার(rs));
	rs.lo = lo;
	rs.hi = hi;
	ers = RB_NFIND(revoked_serial_বৃক্ষ, rt, &rs);
	যদি (ers == ফাঁকা || serial_cmp(ers, &rs) != 0) {
		/* No entry matches. Just insert */
		যদি ((irs = malloc(আকার(rs))) == ফাঁকা)
			ফেরত SSH_ERR_ALLOC_FAIL;
		memcpy(irs, &rs, আকার(*irs));
		ers = RB_ঢোকাও(revoked_serial_বৃক্ষ, rt, irs);
		যদি (ers != ফাঁকা) {
			KRL_DBG(("bad: ers != NULL"));
			/* Shouldn't happen */
			মুক্ত(irs);
			ফেরত SSH_ERR_INTERNAL_ERROR;
		}
		ers = irs;
	} অন্যথা {
		KRL_DBG(("overlap found %llu:%llu",
		    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
		/*
		 * The inserted entry overlaps an existing one. Grow the
		 * existing entry.
		 */
		যদি (ers->lo > lo)
			ers->lo = lo;
		যদি (ers->hi < hi)
			ers->hi = hi;
	}

	/*
	 * The inserted or revised range might overlap or abut adjacent ones;
	 * coalesce as necessary.
	 */

	/* Check predecessors */
	যখন ((crs = RB_পূর্ব(revoked_serial_বৃক্ষ, rt, ers)) != ফাঁকা) {
		KRL_DBG(("pred %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		যদি (ers->lo != 0 && crs->hi < ers->lo - 1)
			বিরতি;
		/* This entry overlaps. */
		যদি (crs->lo < ers->lo) {
			ers->lo = crs->lo;
			KRL_DBG(("pred extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_বৃক্ষ, rt, crs);
		মুক্ত(crs);
	}
	/* Check successors */
	যখন ((crs = RB_পরবর্তী(revoked_serial_বৃক্ষ, rt, ers)) != ফাঁকা) {
		KRL_DBG(("succ %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		যদি (ers->hi != (uint64_t)-1 && crs->lo > ers->hi + 1)
			বিরতি;
		/* This entry overlaps. */
		যদি (crs->hi > ers->hi) {
			ers->hi = crs->hi;
			KRL_DBG(("succ extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_বৃক্ষ, rt, crs);
		মুক্ত(crs);
	}
	KRL_DBG(("done, final %llu:%llu",
	    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
	ফেরত 0;
}

পূর্ণসংখ্যা
ssh_krl_revoke_cert_by_serial(কাঠামো ssh_krl *krl, ধ্রুবক কাঠামো sshkey *ca_চাবি,
    uint64_t serial)
{
	ফেরত ssh_krl_revoke_cert_by_serial_range(krl, ca_চাবি, serial, serial);
}

পূর্ণসংখ্যা
ssh_krl_revoke_cert_by_serial_range(কাঠামো ssh_krl *krl,
    ধ্রুবক কাঠামো sshkey *ca_চাবি, uint64_t lo, uint64_t hi)
{
	কাঠামো revoked_certs *rc;
	পূর্ণসংখ্যা r;

	যদি (lo > hi || lo == 0)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি ((r = revoked_certs_for_ca_চাবি(krl, ca_চাবি, &rc, 1)) != 0)
		ফেরত r;
	ফেরত ঢোকাও_serial_range(&rc->revoked_serials, lo, hi);
}

পূর্ণসংখ্যা
ssh_krl_revoke_cert_by_চাবি_id(কাঠামো ssh_krl *krl, ধ্রুবক কাঠামো sshkey *ca_চাবি,
    ধ্রুবক অক্ষর *চাবি_id)
{
	কাঠামো revoked_চাবি_id *rki, *erki;
	কাঠামো revoked_certs *rc;
	পূর্ণসংখ্যা r;

	যদি ((r = revoked_certs_for_ca_চাবি(krl, ca_চাবি, &rc, 1)) != 0)
		ফেরত r;

	KRL_DBG(("revoke %s", চাবি_id));
	যদি ((rki = calloc(1, আকার(*rki))) == ফাঁকা ||
	    (rki->চাবি_id = strdup(চাবি_id)) == ফাঁকা) {
		মুক্ত(rki);
		ফেরত SSH_ERR_ALLOC_FAIL;
	}
	erki = RB_ঢোকাও(revoked_চাবি_id_বৃক্ষ, &rc->revoked_চাবি_ids, rki);
	যদি (erki != ফাঁকা) {
		মুক্ত(rki->চাবি_id);
		মুক্ত(rki);
	}
	ফেরত 0;
}

/* Convert "key" to a public key blob without any certificate information */
স্থির পূর্ণসংখ্যা
plain_চাবি_blob(ধ্রুবক কাঠামো sshkey *চাবি, u_char **blob, আকার_t *blen)
{
	কাঠামো sshkey *kcopy;
	পূর্ণসংখ্যা r;

	যদি ((r = sshkey_from_private(চাবি, &kcopy)) != 0)
		ফেরত r;
	যদি (sshkey_is_cert(kcopy)) {
		যদি ((r = sshkey_drop_cert(kcopy)) != 0) {
			sshkey_free(kcopy);
			ফেরত r;
		}
	}
	r = sshkey_to_blob(kcopy, blob, blen);
	sshkey_free(kcopy);
	ফেরত r;
}

/* Revoke a key blob. Ownership of blob is transferred to the tree */
স্থির পূর্ণসংখ্যা
revoke_blob(কাঠামো revoked_blob_বৃক্ষ *rbt, u_char *blob, আকার_t len)
{
	কাঠামো revoked_blob *rb, *erb;

	যদি ((rb = calloc(1, আকার(*rb))) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	rb->blob = blob;
	rb->len = len;
	erb = RB_ঢোকাও(revoked_blob_বৃক্ষ, rbt, rb);
	যদি (erb != ফাঁকা) {
		মুক্ত(rb->blob);
		মুক্ত(rb);
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
ssh_krl_revoke_চাবি_explicit(কাঠামো ssh_krl *krl, ধ্রুবক কাঠামো sshkey *চাবি)
{
	u_char *blob;
	আকার_t len;
	পূর্ণসংখ্যা r;

	debug3_f("revoke type %s", sshkey_type(চাবি));
	যদি ((r = plain_চাবি_blob(চাবি, &blob, &len)) != 0)
		ফেরত r;
	ফেরত revoke_blob(&krl->revoked_চাবিগুলি, blob, len);
}

স্থির পূর্ণসংখ্যা
revoke_by_hash(কাঠামো revoked_blob_বৃক্ষ *target, ধ্রুবক u_char *p, আকার_t len)
{
	u_char *blob;
	পূর্ণসংখ্যা r;

	/* need to copy hash, as revoke_blob steals ownership */
	যদি ((blob = malloc(len)) == ফাঁকা)
		ফেরত SSH_ERR_SYSTEM_ERROR;
	memcpy(blob, p, len);
	যদি ((r = revoke_blob(target, blob, len)) != 0) {
		মুক্ত(blob);
		ফেরত r;
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
ssh_krl_revoke_চাবি_sha1(কাঠামো ssh_krl *krl, ধ্রুবক u_char *p, আকার_t len)
{
	debug3_f("revoke by sha1");
	যদি (len != 20)
		ফেরত SSH_ERR_INVALID_FORMAT;
	ফেরত revoke_by_hash(&krl->revoked_sha1s, p, len);
}

পূর্ণসংখ্যা
ssh_krl_revoke_চাবি_sha256(কাঠামো ssh_krl *krl, ধ্রুবক u_char *p, আকার_t len)
{
	debug3_f("revoke by sha256");
	যদি (len != 32)
		ফেরত SSH_ERR_INVALID_FORMAT;
	ফেরত revoke_by_hash(&krl->revoked_sha256s, p, len);
}

পূর্ণসংখ্যা
ssh_krl_revoke_চাবি(কাঠামো ssh_krl *krl, ধ্রুবক কাঠামো sshkey *চাবি)
{
	/* XXX replace with SHA256? */
	যদি (!sshkey_is_cert(চাবি))
		ফেরত ssh_krl_revoke_চাবি_explicit(krl, চাবি);

	যদি (চাবি->cert->serial == 0) {
		ফেরত ssh_krl_revoke_cert_by_চাবি_id(krl,
		    চাবি->cert->signature_চাবি,
		    চাবি->cert->চাবি_id);
	} অন্যথা {
		ফেরত ssh_krl_revoke_cert_by_serial(krl,
		    চাবি->cert->signature_চাবি,
		    চাবি->cert->serial);
	}
}

/*
 * Select the most compact section type to emit next in a KRL based on
 * the current section type, the run length of contiguous revoked serial
 * numbers and the gaps from the last and to the next revoked serial.
 * Applies a mostly-accurate bit cost model to select the section type
 * that will minimise the size of the resultant KRL.
 */
স্থির পূর্ণসংখ্যা
choose_পরবর্তী_state(পূর্ণসংখ্যা current_state, uint64_t contig, পূর্ণসংখ্যা final,
    uint64_t last_gap, uint64_t পরবর্তী_gap, আকার_t bitmap_len,
    পূর্ণসংখ্যা *force_new_section)
{
	পূর্ণসংখ্যা new_state;
	uint64_t cost, cost_list, cost_range, cost_bitmap, cost_bitmap_restart;

	/*
	 * Avoid unsigned overflows.
	 * The limits are high enough to avoid confusing the calculations.
	 */
	contig = MINIMUM(contig, 1ULL<<31);
	last_gap = MINIMUM(last_gap, 1ULL<<31);
	পরবর্তী_gap = MINIMUM(পরবর্তী_gap, 1ULL<<31);

	/*
	 * Calculate the cost to switch from the current state to candidates.
	 * NB. range sections only ever contain a single range, so their
	 * switching cost is independent of the current_state.
	 */
	cost_list = cost_bitmap = cost_bitmap_restart = 0;
	cost_range = 8;
	নির্বাচন (current_state) {
	ক্ষেত্র KRL_SECTION_CERT_SERIAL_LIST:
		cost_bitmap_restart = cost_bitmap = 8 + 64;
		বিরতি;
	ক্ষেত্র KRL_SECTION_CERT_SERIAL_BITMAP:
		cost_list = 8;
		cost_bitmap_restart = 8 + 64;
		বিরতি;
	ক্ষেত্র KRL_SECTION_CERT_SERIAL_RANGE:
	ক্ষেত্র 0:
		cost_bitmap_restart = cost_bitmap = 8 + 64;
		cost_list = 8;
	}

	/* Estimate base cost in bits of each section type */
	cost_list += 64 * contig + (final ? 0 : 8+64);
	cost_range += (2 * 64) + (final ? 0 : 8+64);
	cost_bitmap += last_gap + contig + (final ? 0 : MINIMUM(পরবর্তী_gap, 8+64));
	cost_bitmap_restart += contig + (final ? 0 : MINIMUM(পরবর্তী_gap, 8+64));

	/* Convert to byte costs for actual comparison */
	cost_list = (cost_list + 7) / 8;
	cost_bitmap = (cost_bitmap + 7) / 8;
	cost_bitmap_restart = (cost_bitmap_restart + 7) / 8;
	cost_range = (cost_range + 7) / 8;

	/* Ensure that we never emit a bitmap larger than sshbuf can handle */
	যদি (bitmap_len + cost_bitmap >= SSHBUF_MAX_BIGNUM) {
		KRL_DBG(("bitmap overfull len=%zu cost=%llu max=%u",
		    bitmap_len, (unsigned long long)cost_bitmap,
		    SSHBUF_MAX_BIGNUM));
		cost_bitmap = (uint64_t)-1;
	}

	/* Now pick the best choice */
	*force_new_section = 0;
	new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
	cost = cost_bitmap;
	যদি (cost_range < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_RANGE;
		cost = cost_range;
	}
	যদি (cost_list < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_LIST;
		cost = cost_list;
	}
	যদি (cost_bitmap_restart < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
		*force_new_section = 1;
		cost = cost_bitmap_restart;
	}
	KRL_DBG(("contig %llu last_gap %llu next_gap %llu final %d, costs:"
	    "list %llu range %llu bitmap %llu new bitmap %llu, "
	    "selected 0x%02x%s", (long long unsigned)contig,
	    (long long unsigned)last_gap, (long long unsigned)পরবর্তী_gap, final,
	    (long long unsigned)cost_list, (long long unsigned)cost_range,
	    (long long unsigned)cost_bitmap,
	    (long long unsigned)cost_bitmap_restart, new_state,
	    *force_new_section ? " restart" : ""));
	ফেরত new_state;
}

স্থির পূর্ণসংখ্যা
put_bitmap(কাঠামো sshbuf *buf, কাঠামো bitmap *bitmap)
{
	আকার_t len;
	u_char *blob;
	পূর্ণসংখ্যা r;

	len = bitmap_nbytes(bitmap);
	যদি ((blob = malloc(len)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি (bitmap_to_string(bitmap, blob, len) != 0) {
		মুক্ত(blob);
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	r = sshbuf_put_bignum2_bytes(buf, blob, len);
	মুক্ত(blob);
	ফেরত r;
}

/* Generate a KRL_SECTION_CERTIFICATES KRL section */
স্থির পূর্ণসংখ্যা
revoked_certs_generate(কাঠামো revoked_certs *rc, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা final, force_new_sect, r = SSH_ERR_INTERNAL_ERROR;
	uint64_t i, contig, gap, last = 0, bitmap_start = 0;
	কাঠামো revoked_serial *rs, *nrs;
	কাঠামো revoked_চাবি_id *rki;
	পূর্ণসংখ্যা পরবর্তী_state, state = 0;
	আকার_t bitmap_len;
	কাঠামো sshbuf *sect;
	কাঠামো bitmap *bitmap = ফাঁকা;

	যদি ((sect = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;

	/* Store the header: optional CA scope key, reserved */
	যদি (rc->ca_চাবি == ফাঁকা) {
		যদি ((r = sshbuf_put_string(buf, ফাঁকা, 0)) != 0)
			যাও out;
	} অন্যথা {
		যদি ((r = sshkey_puts(rc->ca_চাবি, buf)) != 0)
			যাও out;
	}
	যদি ((r = sshbuf_put_string(buf, ফাঁকা, 0)) != 0)
		যাও out;

	/* Store the revoked serials.  */
	জন্য (rs = RB_MIN(revoked_serial_বৃক্ষ, &rc->revoked_serials);
	     rs != ফাঁকা;
	     rs = RB_পরবর্তী(revoked_serial_বৃক্ষ, &rc->revoked_serials, rs)) {
		KRL_DBG(("serial %llu:%llu state 0x%02x",
		    (long long unsigned)rs->lo, (long long unsigned)rs->hi,
		    state));

		/* Check contiguous length and gap to next section (if any) */
		nrs = RB_পরবর্তী(revoked_serial_বৃক্ষ, &rc->revoked_serials, rs);
		final = nrs == ফাঁকা;
		gap = nrs == ফাঁকা ? 0 : nrs->lo - rs->hi;
		contig = 1 + (rs->hi - rs->lo);

		bitmap_len = state == KRL_SECTION_CERT_SERIAL_BITMAP ?
		    bitmap_nbytes(bitmap) : 0;

		/* Choose next state based on these */
		পরবর্তী_state = choose_পরবর্তী_state(state, contig, final,
		    state == 0 ? 0 : rs->lo - last, gap, bitmap_len,
		    &force_new_sect);

		/*
		 * If the current section is a range section or has a different
		 * type to the next section, then finish it off now.
		 */
		যদি (state != 0 && (force_new_sect || পরবর্তী_state != state ||
		    state == KRL_SECTION_CERT_SERIAL_RANGE)) {
			KRL_DBG(("finish state 0x%02x", state));
			নির্বাচন (state) {
			ক্ষেত্র KRL_SECTION_CERT_SERIAL_LIST:
			ক্ষেত্র KRL_SECTION_CERT_SERIAL_RANGE:
				বিরতি;
			ক্ষেত্র KRL_SECTION_CERT_SERIAL_BITMAP:
				যদি ((r = put_bitmap(sect, bitmap)) != 0)
					যাও out;
				bitmap_free(bitmap);
				bitmap = ফাঁকা;
				বিরতি;
			}
			যদি ((r = sshbuf_put_u8(buf, state)) != 0 ||
			    (r = sshbuf_put_stringb(buf, sect)) != 0)
				যাও out;
			sshbuf_reset(sect);
		}

		/* If we are starting a new section then prepare it now */
		যদি (পরবর্তী_state != state || force_new_sect) {
			KRL_DBG(("start state 0x%02x",
			    পরবর্তী_state));
			state = পরবর্তী_state;
			sshbuf_reset(sect);
			নির্বাচন (state) {
			ক্ষেত্র KRL_SECTION_CERT_SERIAL_LIST:
			ক্ষেত্র KRL_SECTION_CERT_SERIAL_RANGE:
				বিরতি;
			ক্ষেত্র KRL_SECTION_CERT_SERIAL_BITMAP:
				যদি ((bitmap = bitmap_new()) == ফাঁকা) {
					r = SSH_ERR_ALLOC_FAIL;
					যাও out;
				}
				bitmap_start = rs->lo;
				যদি ((r = sshbuf_put_u64(sect,
				    bitmap_start)) != 0)
					যাও out;
				বিরতি;
			}
		}

		/* Perform section-specific processing */
		নির্বাচন (state) {
		ক্ষেত্র KRL_SECTION_CERT_SERIAL_LIST:
			জন্য (i = 0; i < contig; i++) {
				যদি ((r = sshbuf_put_u64(sect, rs->lo + i)) != 0)
					যাও out;
			}
			বিরতি;
		ক্ষেত্র KRL_SECTION_CERT_SERIAL_RANGE:
			যদি ((r = sshbuf_put_u64(sect, rs->lo)) != 0 ||
			    (r = sshbuf_put_u64(sect, rs->hi)) != 0)
				যাও out;
			বিরতি;
		ক্ষেত্র KRL_SECTION_CERT_SERIAL_BITMAP:
			যদি (rs->lo - bitmap_start > INT_MAX) {
				r = SSH_ERR_INVALID_FORMAT;
				error_f("insane bitmap gap");
				যাও out;
			}
			জন্য (i = 0; i < contig; i++) {
				যদি (bitmap_set_bit(bitmap,
				    rs->lo + i - bitmap_start) != 0) {
					r = SSH_ERR_ALLOC_FAIL;
					যাও out;
				}
			}
			বিরতি;
		}
		last = rs->hi;
	}
	/* Flush the remaining section, if any */
	যদি (state != 0) {
		KRL_DBG(("serial final flush for state 0x%02x", state));
		নির্বাচন (state) {
		ক্ষেত্র KRL_SECTION_CERT_SERIAL_LIST:
		ক্ষেত্র KRL_SECTION_CERT_SERIAL_RANGE:
			বিরতি;
		ক্ষেত্র KRL_SECTION_CERT_SERIAL_BITMAP:
			যদি ((r = put_bitmap(sect, bitmap)) != 0)
				যাও out;
			bitmap_free(bitmap);
			bitmap = ফাঁকা;
			বিরতি;
		}
		যদি ((r = sshbuf_put_u8(buf, state)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			যাও out;
	}
	KRL_DBG(("serial done "));

	/* Now output a section for any revocations by key ID */
	sshbuf_reset(sect);
	RB_FOREACH(rki, revoked_চাবি_id_বৃক্ষ, &rc->revoked_চাবি_ids) {
		KRL_DBG(("key ID %s", rki->চাবি_id));
		যদি ((r = sshbuf_put_cstring(sect, rki->চাবি_id)) != 0)
			যাও out;
	}
	যদি (sshbuf_len(sect) != 0) {
		যদি ((r = sshbuf_put_u8(buf, KRL_SECTION_CERT_চাবি_ID)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			যাও out;
	}
	r = 0;
 out:
	bitmap_free(bitmap);
	sshbuf_free(sect);
	ফেরত r;
}

পূর্ণসংখ্যা
ssh_krl_to_blob(কাঠামো ssh_krl *krl, কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	কাঠামো revoked_certs *rc;
	কাঠামো revoked_blob *rb;
	কাঠামো sshbuf *sect;
	u_char *sblob = ফাঁকা;

	যদি (krl->generated_date == 0)
		krl->generated_date = time(ফাঁকা);

	যদি ((sect = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;

	/* Store the header */
	যদি ((r = sshbuf_put(buf, KRL_MAGIC, আকার(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_put_u32(buf, KRL_FORMAT_VERSION)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->krl_version)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->generated_date)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->flags)) != 0 ||
	    (r = sshbuf_put_string(buf, ফাঁকা, 0)) != 0 ||
	    (r = sshbuf_put_cstring(buf, krl->comment)) != 0)
		যাও out;

	/* Store sections for revoked certificates */
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		sshbuf_reset(sect);
		যদি ((r = revoked_certs_generate(rc, sect)) != 0)
			যাও out;
		যদি ((r = sshbuf_put_u8(buf, KRL_SECTION_CERTIFICATES)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			যাও out;
	}

	/* Finally, output sections for revocations by public key/hash */
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_বৃক্ষ, &krl->revoked_চাবিগুলি) {
		KRL_DBG(("key len %zu ", rb->len));
		যদি ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			যাও out;
	}
	যদি (sshbuf_len(sect) != 0) {
		যদি ((r = sshbuf_put_u8(buf, KRL_SECTION_EXPLICIT_চাবি)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			যাও out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_বৃক্ষ, &krl->revoked_sha1s) {
		KRL_DBG(("hash len %zu ", rb->len));
		যদি ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			যাও out;
	}
	যদি (sshbuf_len(sect) != 0) {
		যদি ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA1)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			যাও out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_বৃক্ষ, &krl->revoked_sha256s) {
		KRL_DBG(("hash len %zu ", rb->len));
		যদি ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			যাও out;
	}
	যদি (sshbuf_len(sect) != 0) {
		যদি ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA256)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			যাও out;
	}
	/* success */
	r = 0;
 out:
	মুক্ত(sblob);
	sshbuf_free(sect);
	ফেরত r;
}

স্থির শূন্য
format_timestamp(uint64_t timestamp, অক্ষর *ts, আকার_t nts)
{
	time_t t;
	কাঠামো tm *tm;

	t = timestamp;
	tm = localtime(&t);
	যদি (tm == ফাঁকা)
		strlcpy(ts, "<INVALID>", nts);
	অন্যথা {
		*ts = '\0';
		strftime(ts, nts, "%Y%m%dT%H%M%S", tm);
	}
}

স্থির পূর্ণসংখ্যা
cert_extension_subsection(কাঠামো sshbuf *subsect, কাঠামো ssh_krl *krl)
{
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	কাঠামো sshbuf *মান = ফাঁকা;
	অক্ষর *name = ফাঁকা;

	যদি ((r = sshbuf_get_cstring(subsect, &name, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_u8(subsect, &critical)) != 0 ||
	    (r = sshbuf_froms(subsect, &মান)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid certificate extension subsection");
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি (sshbuf_len(subsect) != 0) {
		error("KRL has invalid certificate extension subsection: "
		    "trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	debug_f("cert extension %s critical %u len %zu",
	    name, critical, sshbuf_len(মান));
	/* no extensions are currently supported */
	যদি (critical) {
		error("KRL contains unsupported critical certificate "
		    "subsection \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		যাও out;
	}
	/* success */
	r = 0;
 out:
	মুক্ত(name);
	sshbuf_free(মান);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
parse_revoked_certs(কাঠামো sshbuf *buf, কাঠামো ssh_krl *krl)
{
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	ধ্রুবক u_char *blob;
	আকার_t blen, nbits;
	কাঠামো sshbuf *subsect = ফাঁকা;
	uint64_t serial, serial_lo, serial_hi;
	কাঠামো bitmap *bitmap = ফাঁকা;
	অক্ষর *চাবি_id = ফাঁকা;
	কাঠামো sshkey *ca_চাবি = ফাঁকা;

	যদি ((subsect = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;

	/* Header: key, reserved */
	যদি ((r = sshbuf_get_string_direct(buf, &blob, &blen)) != 0 ||
	    (r = sshbuf_skip_string(buf)) != 0)
		যাও out;
	যদি (blen != 0 && (r = sshkey_from_blob(blob, blen, &ca_চাবি)) != 0)
		যাও out;

	যখন (sshbuf_len(buf) > 0) {
		sshbuf_free(subsect);
		subsect = ফাঁকা;
		যদি ((r = sshbuf_get_u8(buf, &type)) != 0 ||
		    (r = sshbuf_froms(buf, &subsect)) != 0)
			যাও out;
		KRL_DBG(("subsection type 0x%02x", type));
		/* sshbuf_dump(subsect, stderr); */

		নির্বাচন (type) {
		ক্ষেত্র KRL_SECTION_CERT_SERIAL_LIST:
			যখন (sshbuf_len(subsect) > 0) {
				যদি ((r = sshbuf_get_u64(subsect, &serial)) != 0)
					যাও out;
				যদি ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_চাবি, serial)) != 0)
					যাও out;
			}
			বিরতি;
		ক্ষেত্র KRL_SECTION_CERT_SERIAL_RANGE:
			যদি ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_u64(subsect, &serial_hi)) != 0)
				যাও out;
			যদি ((r = ssh_krl_revoke_cert_by_serial_range(krl,
			    ca_চাবি, serial_lo, serial_hi)) != 0)
				যাও out;
			বিরতি;
		ক্ষেত্র KRL_SECTION_CERT_SERIAL_BITMAP:
			যদি ((bitmap = bitmap_new()) == ফাঁকা) {
				r = SSH_ERR_ALLOC_FAIL;
				যাও out;
			}
			যদি ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_bignum2_bytes_direct(subsect,
			    &blob, &blen)) != 0)
				যাও out;
			যদি (bitmap_from_string(bitmap, blob, blen) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				যাও out;
			}
			nbits = bitmap_nbits(bitmap);
			জন্য (serial = 0; serial < (uint64_t)nbits; serial++) {
				যদি (serial > 0 && serial_lo + serial == 0) {
					error_f("bitmap wraps u64");
					r = SSH_ERR_INVALID_FORMAT;
					যাও out;
				}
				যদি (!bitmap_test_bit(bitmap, serial))
					চালু;
				যদি ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_চাবি, serial_lo + serial)) != 0)
					যাও out;
			}
			bitmap_free(bitmap);
			bitmap = ফাঁকা;
			বিরতি;
		ক্ষেত্র KRL_SECTION_CERT_চাবি_ID:
			যখন (sshbuf_len(subsect) > 0) {
				যদি ((r = sshbuf_get_cstring(subsect,
				    &চাবি_id, ফাঁকা)) != 0)
					যাও out;
				যদি ((r = ssh_krl_revoke_cert_by_চাবি_id(krl,
				    ca_চাবি, চাবি_id)) != 0)
					যাও out;
				মুক্ত(চাবি_id);
				চাবি_id = ফাঁকা;
			}
			বিরতি;
		ক্ষেত্র KRL_SECTION_CERT_EXTENSION:
			যদি ((r = cert_extension_subsection(subsect, krl)) != 0)
				যাও out;
			বিরতি;
		পূর্বনির্ধারিত:
			error("Unsupported KRL certificate section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
		যদি (sshbuf_len(subsect) > 0) {
			error("KRL certificate section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
	}

	r = 0;
 out:
	যদি (bitmap != ফাঁকা)
		bitmap_free(bitmap);
	মুক্ত(চাবি_id);
	sshkey_free(ca_চাবি);
	sshbuf_free(subsect);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
blob_section(কাঠামো sshbuf *sect, কাঠামো revoked_blob_বৃক্ষ *target_বৃক্ষ,
    আকার_t expected_len)
{
	u_char *rdata = ফাঁকা;
	আকার_t rlen = 0;
	পূর্ণসংখ্যা r;

	যখন (sshbuf_len(sect) > 0) {
		যদি ((r = sshbuf_get_string(sect, &rdata, &rlen)) != 0)
			ফেরত r;
		যদি (expected_len != 0 && rlen != expected_len) {
			error_f("bad length");
			মুক্ত(rdata);
			ফেরত SSH_ERR_INVALID_FORMAT;
		}
		যদি ((r = revoke_blob(target_বৃক্ষ, rdata, rlen)) != 0) {
			মুক্ত(rdata);
			ফেরত r;
		}
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
extension_section(কাঠামো sshbuf *sect, কাঠামো ssh_krl *krl)
{
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	কাঠামো sshbuf *মান = ফাঁকা;
	অক্ষর *name = ফাঁকা;

	যদি ((r = sshbuf_get_cstring(sect, &name, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_u8(sect, &critical)) != 0 ||
	    (r = sshbuf_froms(sect, &মান)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid extension section");
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি (sshbuf_len(sect) != 0) {
		error("KRL has invalid extension section: trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	debug_f("extension %s critical %u len %zu",
	    name, critical, sshbuf_len(মান));
	/* no extensions are currently supported */
	যদি (critical) {
		error("KRL contains unsupported critical section \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		যাও out;
	}
	/* success */
	r = 0;
 out:
	মুক্ত(name);
	sshbuf_free(মান);
	ফেরত r;
}

/* Attempt to parse a KRL */
পূর্ণসংখ্যা
ssh_krl_from_blob(কাঠামো sshbuf *buf, কাঠামো ssh_krl **krlp)
{
	কাঠামো sshbuf *copy = ফাঁকা, *sect = ফাঁকা;
	কাঠামো ssh_krl *krl = ফাঁকা;
	অক্ষর timestamp[64];
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	u_int format_version;

	*krlp = ফাঁকা;

	/* KRL must begin with magic string */
	যদি ((r = sshbuf_cmp(buf, 0, KRL_MAGIC, আকার(KRL_MAGIC) - 1)) != 0) {
		debug2_f("bad KRL magic header");
		ফেরত SSH_ERR_KRL_BAD_MAGIC;
	}

	যদি ((krl = ssh_krl_init()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		error_f("alloc failed");
		যাও out;
	}
	/* Don't modify buffer */
	যদি ((copy = sshbuf_fromb(buf)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_consume(copy, আকার(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_get_u32(copy, &format_version)) != 0)
		যাও out;
	যদি (format_version != KRL_FORMAT_VERSION) {
		error_f("unsupported KRL format version %u", format_version);
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি ((r = sshbuf_get_u64(copy, &krl->krl_version)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->generated_date)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->flags)) != 0 ||
	    (r = sshbuf_skip_string(copy)) != 0 ||
	    (r = sshbuf_get_cstring(copy, &krl->comment, ফাঁকা)) != 0) {
		error_fr(r, "parse KRL header");
		যাও out;
	}
	format_timestamp(krl->generated_date, timestamp, আকার(timestamp));
	debug("KRL version %llu generated at %s%s%s",
	    (long long unsigned)krl->krl_version, timestamp,
	    *krl->comment ? ": " : "", krl->comment);

	/* Parse and load the KRL sections. */
	যখন (sshbuf_len(copy) > 0) {
		sshbuf_free(sect);
		sect = ফাঁকা;
		যদি ((r = sshbuf_get_u8(copy, &type)) != 0 ||
		    (r = sshbuf_froms(copy, &sect)) != 0)
			যাও out;
		KRL_DBG(("section 0x%02x", type));

		নির্বাচন (type) {
		ক্ষেত্র KRL_SECTION_CERTIFICATES:
			যদি ((r = parse_revoked_certs(sect, krl)) != 0)
				যাও out;
			বিরতি;
		ক্ষেত্র KRL_SECTION_EXPLICIT_চাবি:
			যদি ((r = blob_section(sect,
			    &krl->revoked_চাবিগুলি, 0)) != 0)
				যাও out;
			বিরতি;
		ক্ষেত্র KRL_SECTION_FINGERPRINT_SHA1:
			যদি ((r = blob_section(sect,
			    &krl->revoked_sha1s, 20)) != 0)
				যাও out;
			বিরতি;
		ক্ষেত্র KRL_SECTION_FINGERPRINT_SHA256:
			যদি ((r = blob_section(sect,
			    &krl->revoked_sha256s, 32)) != 0)
				যাও out;
			বিরতি;
		ক্ষেত্র KRL_SECTION_EXTENSION:
			যদি ((r = extension_section(sect, krl)) != 0)
				যাও out;
			বিরতি;
		ক্ষেত্র KRL_SECTION_SIGNATURE:
			/* Handled above, but still need to stay in synch */
			sshbuf_free(sect);
			sect = ফাঁকা;
			যদি ((r = sshbuf_skip_string(copy)) != 0)
				যাও out;
			বিরতি;
		পূর্বনির্ধারিত:
			error("Unsupported KRL section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
		যদি (sect != ফাঁকা && sshbuf_len(sect) > 0) {
			error("KRL section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
	}

	/* Success */
	*krlp = krl;
	r = 0;
 out:
	যদি (r != 0)
		ssh_krl_free(krl);
	sshbuf_free(copy);
	sshbuf_free(sect);
	ফেরত r;
}

/* Checks certificate serial number and key ID revocation */
স্থির পূর্ণসংখ্যা
is_cert_revoked(ধ্রুবক কাঠামো sshkey *চাবি, কাঠামো revoked_certs *rc)
{
	কাঠামো revoked_serial rs, *ers;
	কাঠামো revoked_চাবি_id rki, *erki;

	/* Check revocation by cert key ID */
	memset(&rki, 0, আকার(rki));
	rki.চাবি_id = চাবি->cert->চাবি_id;
	erki = RB_FIND(revoked_চাবি_id_বৃক্ষ, &rc->revoked_চাবি_ids, &rki);
	যদি (erki != ফাঁকা) {
		KRL_DBG(("revoked by key ID"));
		ফেরত SSH_ERR_চাবি_REVOKED;
	}

	/*
	 * Zero serials numbers are ignored (it's the default when the
	 * CA doesn't specify one).
	 */
	যদি (চাবি->cert->serial == 0)
		ফেরত 0;

	memset(&rs, 0, আকার(rs));
	rs.lo = rs.hi = চাবি->cert->serial;
	ers = RB_FIND(revoked_serial_বৃক্ষ, &rc->revoked_serials, &rs);
	যদি (ers != ফাঁকা) {
		KRL_DBG(("revoked serial %llu matched %llu:%llu",
		    (unsigned long long)চাবি->cert->serial,
		    (unsigned long long)ers->lo,
		    (unsigned long long)ers->hi));
		ফেরত SSH_ERR_চাবি_REVOKED;
	}
	ফেরত 0;
}

/* Checks whether a given key/cert is revoked. Does not check its CA */
স্থির পূর্ণসংখ্যা
is_চাবি_revoked(কাঠামো ssh_krl *krl, ধ্রুবক কাঠামো sshkey *চাবি)
{
	কাঠামো revoked_blob rb, *erb;
	কাঠামো revoked_certs *rc;
	পূর্ণসংখ্যা r;

	/* Check explicitly revoked hashes first */
	memset(&rb, 0, আকার(rb));
	যদি ((r = sshkey_fingerprint_raw(চাবি, SSH_DIGEST_SHA1,
	    &rb.blob, &rb.len)) != 0)
		ফেরত r;
	erb = RB_FIND(revoked_blob_বৃক্ষ, &krl->revoked_sha1s, &rb);
	মুক্ত(rb.blob);
	যদি (erb != ফাঁকা) {
		KRL_DBG(("revoked by key SHA1"));
		ফেরত SSH_ERR_চাবি_REVOKED;
	}
	memset(&rb, 0, আকার(rb));
	যদি ((r = sshkey_fingerprint_raw(চাবি, SSH_DIGEST_SHA256,
	    &rb.blob, &rb.len)) != 0)
		ফেরত r;
	erb = RB_FIND(revoked_blob_বৃক্ষ, &krl->revoked_sha256s, &rb);
	মুক্ত(rb.blob);
	যদি (erb != ফাঁকা) {
		KRL_DBG(("revoked by key SHA256"));
		ফেরত SSH_ERR_চাবি_REVOKED;
	}

	/* Next, explicit keys */
	memset(&rb, 0, আকার(rb));
	যদি ((r = plain_চাবি_blob(চাবি, &rb.blob, &rb.len)) != 0)
		ফেরত r;
	erb = RB_FIND(revoked_blob_বৃক্ষ, &krl->revoked_চাবিগুলি, &rb);
	মুক্ত(rb.blob);
	যদি (erb != ফাঁকা) {
		KRL_DBG(("revoked by explicit key"));
		ফেরত SSH_ERR_চাবি_REVOKED;
	}

	যদি (!sshkey_is_cert(চাবি))
		ফেরত 0;

	/* Check cert revocation for the specified CA */
	যদি ((r = revoked_certs_for_ca_চাবি(krl, চাবি->cert->signature_চাবি,
	    &rc, 0)) != 0)
		ফেরত r;
	যদি (rc != ফাঁকা) {
		যদি ((r = is_cert_revoked(চাবি, rc)) != 0)
			ফেরত r;
	}
	/* Check cert revocation for the wildcard CA */
	যদি ((r = revoked_certs_for_ca_চাবি(krl, ফাঁকা, &rc, 0)) != 0)
		ফেরত r;
	যদি (rc != ফাঁকা) {
		যদি ((r = is_cert_revoked(চাবি, rc)) != 0)
			ফেরত r;
	}

	KRL_DBG(("%llu no match", (unsigned long long)চাবি->cert->serial));
	ফেরত 0;
}

পূর্ণসংখ্যা
ssh_krl_check_চাবি(কাঠামো ssh_krl *krl, ধ্রুবক কাঠামো sshkey *চাবি)
{
	পূর্ণসংখ্যা r;

	KRL_DBG(("checking key"));
	যদি ((r = is_চাবি_revoked(krl, চাবি)) != 0)
		ফেরত r;
	যদি (sshkey_is_cert(চাবি)) {
		debug2_f("checking CA key");
		যদি ((r = is_চাবি_revoked(krl, চাবি->cert->signature_চাবি)) != 0)
			ফেরত r;
	}
	KRL_DBG(("key okay"));
	ফেরত 0;
}

পূর্ণসংখ্যা
ssh_krl_file_contains_চাবি(ধ্রুবক অক্ষর *path, ধ্রুবক কাঠামো sshkey *চাবি)
{
	কাঠামো sshbuf *krlbuf = ফাঁকা;
	কাঠামো ssh_krl *krl = ফাঁকা;
	পূর্ণসংখ্যা oerrno = 0, r;

	যদি (path == ফাঁকা)
		ফেরত 0;
	যদি ((r = sshbuf_load_file(path, &krlbuf)) != 0) {
		oerrno = errno;
		যাও out;
	}
	যদি ((r = ssh_krl_from_blob(krlbuf, &krl)) != 0)
		যাও out;
	debug2_f("checking KRL %s", path);
	r = ssh_krl_check_চাবি(krl, চাবি);
 out:
	sshbuf_free(krlbuf);
	ssh_krl_free(krl);
	যদি (r != 0)
		errno = oerrno;
	ফেরত r;
}

পূর্ণসংখ্যা
krl_dump(কাঠামো ssh_krl *krl, FILE *f)
{
	কাঠামো sshkey *চাবি = ফাঁকা;
	কাঠামো revoked_blob *rb;
	কাঠামো revoked_certs *rc;
	কাঠামো revoked_serial *rs;
	কাঠামো revoked_চাবি_id *rki;
	পূর্ণসংখ্যা r, ret = 0;
	অক্ষর *fp, timestamp[64];

	/* Try to print in a KRL spec-compatible format */
	format_timestamp(krl->generated_date, timestamp, আকার(timestamp));
	fprintf(f, "# KRL version %llu\n", (unsigned long long)krl->krl_version);
	fprintf(f, "# Generated at %s\n", timestamp);
	যদি (krl->comment != ফাঁকা && *krl->comment != '\0') {
		r = INT_MAX;
		asmprintf(&fp, INT_MAX, &r, "%s", krl->comment);
		fprintf(f, "# Comment: %s\n", fp);
		মুক্ত(fp);
	}
	fputc('\n', f);

	RB_FOREACH(rb, revoked_blob_বৃক্ষ, &krl->revoked_চাবিগুলি) {
		যদি ((r = sshkey_from_blob(rb->blob, rb->len, &চাবি)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			error_r(r, "parse KRL key");
			চালু;
		}
		যদি ((fp = sshkey_fingerprint(চাবি, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ফাঁকা) {
			ret = SSH_ERR_INVALID_FORMAT;
			error("sshkey_fingerprint failed");
			চালু;
		}
		fprintf(f, "hash: %s # %s\n", fp, sshkey_ssh_name(চাবি));
		মুক্ত(fp);
		মুক্ত(চাবি);
	}
	RB_FOREACH(rb, revoked_blob_বৃক্ষ, &krl->revoked_sha256s) {
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "hash: SHA256:%s\n", fp);
		মুক্ত(fp);
	}
	RB_FOREACH(rb, revoked_blob_বৃক্ষ, &krl->revoked_sha1s) {
		/*
		 * There is not KRL spec keyword for raw SHA1 hashes, so
		 * print them as comments.
		 */
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "# hash SHA1:%s\n", fp);
		মুক্ত(fp);
	}

	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		fputc('\n', f);
		যদি (rc->ca_চাবি == ফাঁকা)
			fprintf(f, "# Wildcard CA\n");
		অন্যথা {
			যদি ((fp = sshkey_fingerprint(rc->ca_চাবি,
			    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ফাঁকা) {
				ret = SSH_ERR_INVALID_FORMAT;
				error("sshkey_fingerprint failed");
				চালু;
			}
			fprintf(f, "# CA key %s %s\n",
			    sshkey_ssh_name(rc->ca_চাবি), fp);
			মুক্ত(fp);
		}
		RB_FOREACH(rs, revoked_serial_বৃক্ষ, &rc->revoked_serials) {
			যদি (rs->lo == rs->hi) {
				fprintf(f, "serial: %llu\n",
				    (unsigned long long)rs->lo);
			} অন্যথা {
				fprintf(f, "serial: %llu-%llu\n",
				    (unsigned long long)rs->lo,
				    (unsigned long long)rs->hi);
			}
		}
		RB_FOREACH(rki, revoked_চাবি_id_বৃক্ষ, &rc->revoked_চাবি_ids) {
			/*
			 * We don't want key IDs with embedded newlines to
			 * mess up the display.
			 */
			r = INT_MAX;
			asmprintf(&fp, INT_MAX, &r, "%s", rki->চাবি_id);
			fprintf(f, "id: %s\n", fp);
			মুক্ত(fp);
		}
	}
	ফেরত ret;
}
