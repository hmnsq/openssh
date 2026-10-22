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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/tree.h>
#अन्तर्भाव <sys/queue.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <time.h>

#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "bitmap.h"
#अन्तर्भाव "utf8.h"

#अन्तर्भाव "krl.h"

/* #define DEBUG_KRL */
#ifdef DEBUG_KRL
# define KRL_DBG(x) debug3_f x
#अण्णहा
# define KRL_DBG(x)
#endif

/*
 * Trees of revoked serial numbers, key IDs and keys. This allows
 * quick searching, querying and producing lists in canonical order.
 */

/* Tree of serial numbers. XXX make smarter: really need a real sparse bitmap */
संरचना revoked_serial {
	uint64_t lo, hi;
	RB_ENTRY(revoked_serial) वृक्षः_entry;
};
स्थिर पूर्णाङ्क serial_cmp(संरचना revoked_serial *a, संरचना revoked_serial *b);
RB_HEAD(revoked_serial_वृक्षः, revoked_serial);
RB_GENERATE_STATIC(revoked_serial_वृक्षः, revoked_serial, वृक्षः_entry, serial_cmp)

/* Tree of key IDs */
संरचना revoked_कुञ्चिका_id {
	वर्ण *कुञ्चिका_id;
	RB_ENTRY(revoked_कुञ्चिका_id) वृक्षः_entry;
};
स्थिर पूर्णाङ्क कुञ्चिका_id_cmp(संरचना revoked_कुञ्चिका_id *a, संरचना revoked_कुञ्चिका_id *b);
RB_HEAD(revoked_कुञ्चिका_id_वृक्षः, revoked_कुञ्चिका_id);
RB_GENERATE_STATIC(revoked_कुञ्चिका_id_वृक्षः, revoked_कुञ्चिका_id, वृक्षः_entry, कुञ्चिका_id_cmp)

/* Tree of blobs (used for keys and fingerprints) */
संरचना revoked_blob {
	u_char *blob;
	size_t len;
	RB_ENTRY(revoked_blob) वृक्षः_entry;
};
स्थिर पूर्णाङ्क blob_cmp(संरचना revoked_blob *a, संरचना revoked_blob *b);
RB_HEAD(revoked_blob_वृक्षः, revoked_blob);
RB_GENERATE_STATIC(revoked_blob_वृक्षः, revoked_blob, वृक्षः_entry, blob_cmp)

/* Tracks revoked certs for a single CA */
संरचना revoked_certs {
	संरचना sshkey *ca_कुञ्चिका;
	संरचना revoked_serial_वृक्षः revoked_serials;
	संरचना revoked_कुञ्चिका_id_वृक्षः revoked_कुञ्चिका_ids;
	TAILQ_ENTRY(revoked_certs) entry;
};
TAILQ_HEAD(revoked_certs_list, revoked_certs);

संरचना ssh_krl {
	uint64_t krl_version;
	uint64_t generated_date;
	uint64_t flags;
	वर्ण *comment;
	संरचना revoked_blob_वृक्षः revoked_कुञ्चिकाः;
	संरचना revoked_blob_वृक्षः revoked_sha1s;
	संरचना revoked_blob_वृक्षः revoked_sha256s;
	संरचना revoked_certs_list revoked_certs;
};

/* Return equal if a and b overlap */
स्थिर पूर्णाङ्क
serial_cmp(संरचना revoked_serial *a, संरचना revoked_serial *b)
{
	जइ (a->hi >= b->lo && a->lo <= b->hi)
		प्रत्यागम 0;
	प्रत्यागम a->lo < b->lo ? -1 : 1;
}

स्थिर पूर्णाङ्क
कुञ्चिका_id_cmp(संरचना revoked_कुञ्चिका_id *a, संरचना revoked_कुञ्चिका_id *b)
{
	प्रत्यागम strcmp(a->कुञ्चिका_id, b->कुञ्चिका_id);
}

स्थिर पूर्णाङ्क
blob_cmp(संरचना revoked_blob *a, संरचना revoked_blob *b)
{
	पूर्णाङ्क r;

	जइ (a->len != b->len) {
		जइ ((r = memcmp(a->blob, b->blob, MINIMUM(a->len, b->len))) != 0)
			प्रत्यागम r;
		प्रत्यागम a->len > b->len ? 1 : -1;
	} अण्णहा
		प्रत्यागम memcmp(a->blob, b->blob, a->len);
}

संरचना ssh_krl *
ssh_krl_init(शून्य)
{
	संरचना ssh_krl *krl;

	जइ ((krl = calloc(1, परिमाण(*krl))) == रिक्त)
		प्रत्यागम रिक्त;
	RB_INIT(&krl->revoked_कुञ्चिकाः);
	RB_INIT(&krl->revoked_sha1s);
	RB_INIT(&krl->revoked_sha256s);
	TAILQ_INIT(&krl->revoked_certs);
	प्रत्यागम krl;
}

स्थिर शून्य
revoked_certs_free(संरचना revoked_certs *rc)
{
	संरचना revoked_serial *rs, *trs;
	संरचना revoked_कुञ्चिका_id *rki, *trki;

	जइ (rc == रिक्त)
		प्रत्यागम;
	RB_FOREACH_SAFE(rs, revoked_serial_वृक्षः, &rc->revoked_serials, trs) {
		RB_REMOVE(revoked_serial_वृक्षः, &rc->revoked_serials, rs);
		मुक्त(rs);
	}
	RB_FOREACH_SAFE(rki, revoked_कुञ्चिका_id_वृक्षः, &rc->revoked_कुञ्चिका_ids, trki) {
		RB_REMOVE(revoked_कुञ्चिका_id_वृक्षः, &rc->revoked_कुञ्चिका_ids, rki);
		मुक्त(rki->कुञ्चिका_id);
		मुक्त(rki);
	}
	sshkey_free(rc->ca_कुञ्चिका);
	freezero(rc, परिमाण(*rc));
}

शून्य
ssh_krl_free(संरचना ssh_krl *krl)
{
	संरचना revoked_blob *rb, *trb;
	संरचना revoked_certs *rc, *trc;

	जइ (krl == रिक्त)
		प्रत्यागम;

	मुक्त(krl->comment);
	RB_FOREACH_SAFE(rb, revoked_blob_वृक्षः, &krl->revoked_कुञ्चिकाः, trb) {
		RB_REMOVE(revoked_blob_वृक्षः, &krl->revoked_कुञ्चिकाः, rb);
		मुक्त(rb->blob);
		मुक्त(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_वृक्षः, &krl->revoked_sha1s, trb) {
		RB_REMOVE(revoked_blob_वृक्षः, &krl->revoked_sha1s, rb);
		मुक्त(rb->blob);
		मुक्त(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_वृक्षः, &krl->revoked_sha256s, trb) {
		RB_REMOVE(revoked_blob_वृक्षः, &krl->revoked_sha256s, rb);
		मुक्त(rb->blob);
		मुक्त(rb);
	}
	TAILQ_FOREACH_SAFE(rc, &krl->revoked_certs, entry, trc) {
		TAILQ_REMOVE(&krl->revoked_certs, rc, entry);
		revoked_certs_free(rc);
	}
	मुक्त(krl);
}

शून्य
ssh_krl_set_version(संरचना ssh_krl *krl, uint64_t version)
{
	krl->krl_version = version;
}

पूर्णाङ्क
ssh_krl_set_comment(संरचना ssh_krl *krl, ध्रुव वर्ण *comment)
{
	मुक्त(krl->comment);
	जइ ((krl->comment = strdup(comment)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	प्रत्यागम 0;
}

/*
 * Find the revoked_certs struct for a CA key. If allow_create is set then
 * create a new one in the tree if one did not exist already.
 */
स्थिर पूर्णाङ्क
revoked_certs_for_ca_कुञ्चिका(संरचना ssh_krl *krl, ध्रुव संरचना sshkey *ca_कुञ्चिका,
    संरचना revoked_certs **rcp, पूर्णाङ्क allow_create)
{
	संरचना revoked_certs *rc;
	पूर्णाङ्क r;

	*rcp = रिक्त;
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		जइ ((ca_कुञ्चिका == रिक्त && rc->ca_कुञ्चिका == रिक्त) ||
		    sshkey_equal(rc->ca_कुञ्चिका, ca_कुञ्चिका)) {
			*rcp = rc;
			प्रत्यागम 0;
		}
	}
	जइ (!allow_create)
		प्रत्यागम 0;
	/* If this CA doesn't exist in the list then add it now */
	जइ ((rc = calloc(1, परिमाण(*rc))) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	जइ (ca_कुञ्चिका == रिक्त)
		rc->ca_कुञ्चिका = रिक्त;
	अण्णहा जइ ((r = sshkey_from_private(ca_कुञ्चिका, &rc->ca_कुञ्चिका)) != 0) {
		मुक्त(rc);
		प्रत्यागम r;
	}
	RB_INIT(&rc->revoked_serials);
	RB_INIT(&rc->revoked_कुञ्चिका_ids);
	TAILQ_INSERT_TAIL(&krl->revoked_certs, rc, entry);
	KRL_DBG(("new CA %s", ca_कुञ्चिका == रिक्त ? "*" : sshkey_type(ca_कुञ्चिका)));
	*rcp = rc;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
निवेशय_serial_range(संरचना revoked_serial_वृक्षः *rt, uint64_t lo, uint64_t hi)
{
	संरचना revoked_serial rs, *ers, *crs, *irs;

	KRL_DBG(("insert %llu:%llu",
	    (unsigned long long)lo, (unsigned long long)hi));
	memset(&rs, 0, परिमाण(rs));
	rs.lo = lo;
	rs.hi = hi;
	ers = RB_NFIND(revoked_serial_वृक्षः, rt, &rs);
	जइ (ers == रिक्त || serial_cmp(ers, &rs) != 0) {
		/* No entry matches. Just insert */
		जइ ((irs = malloc(परिमाण(rs))) == रिक्त)
			प्रत्यागम SSH_ERR_ALLOC_FAIL;
		memcpy(irs, &rs, परिमाण(*irs));
		ers = RB_निवेशय(revoked_serial_वृक्षः, rt, irs);
		जइ (ers != रिक्त) {
			KRL_DBG(("bad: ers != NULL"));
			/* Shouldn't happen */
			मुक्त(irs);
			प्रत्यागम SSH_ERR_INTERNAL_ERROR;
		}
		ers = irs;
	} अण्णहा {
		KRL_DBG(("overlap found %llu:%llu",
		    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
		/*
		 * The inserted entry overlaps an existing one. Grow the
		 * existing entry.
		 */
		जइ (ers->lo > lo)
			ers->lo = lo;
		जइ (ers->hi < hi)
			ers->hi = hi;
	}

	/*
	 * The inserted or revised range might overlap or abut adjacent ones;
	 * coalesce as necessary.
	 */

	/* Check predecessors */
	जाव ((crs = RB_PREV(revoked_serial_वृक्षः, rt, ers)) != रिक्त) {
		KRL_DBG(("pred %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		जइ (ers->lo != 0 && crs->hi < ers->lo - 1)
			भङ्ग;
		/* This entry overlaps. */
		जइ (crs->lo < ers->lo) {
			ers->lo = crs->lo;
			KRL_DBG(("pred extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_वृक्षः, rt, crs);
		मुक्त(crs);
	}
	/* Check successors */
	जाव ((crs = RB_NEXT(revoked_serial_वृक्षः, rt, ers)) != रिक्त) {
		KRL_DBG(("succ %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		जइ (ers->hi != (uint64_t)-1 && crs->lo > ers->hi + 1)
			भङ्ग;
		/* This entry overlaps. */
		जइ (crs->hi > ers->hi) {
			ers->hi = crs->hi;
			KRL_DBG(("succ extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_वृक्षः, rt, crs);
		मुक्त(crs);
	}
	KRL_DBG(("done, final %llu:%llu",
	    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_krl_revoke_cert_by_serial(संरचना ssh_krl *krl, ध्रुव संरचना sshkey *ca_कुञ्चिका,
    uint64_t serial)
{
	प्रत्यागम ssh_krl_revoke_cert_by_serial_range(krl, ca_कुञ्चिका, serial, serial);
}

पूर्णाङ्क
ssh_krl_revoke_cert_by_serial_range(संरचना ssh_krl *krl,
    ध्रुव संरचना sshkey *ca_कुञ्चिका, uint64_t lo, uint64_t hi)
{
	संरचना revoked_certs *rc;
	पूर्णाङ्क r;

	जइ (lo > hi || lo == 0)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	जइ ((r = revoked_certs_for_ca_कुञ्चिका(krl, ca_कुञ्चिका, &rc, 1)) != 0)
		प्रत्यागम r;
	प्रत्यागम निवेशय_serial_range(&rc->revoked_serials, lo, hi);
}

पूर्णाङ्क
ssh_krl_revoke_cert_by_कुञ्चिका_id(संरचना ssh_krl *krl, ध्रुव संरचना sshkey *ca_कुञ्चिका,
    ध्रुव वर्ण *कुञ्चिका_id)
{
	संरचना revoked_कुञ्चिका_id *rki, *erki;
	संरचना revoked_certs *rc;
	पूर्णाङ्क r;

	जइ ((r = revoked_certs_for_ca_कुञ्चिका(krl, ca_कुञ्चिका, &rc, 1)) != 0)
		प्रत्यागम r;

	KRL_DBG(("revoke %s", कुञ्चिका_id));
	जइ ((rki = calloc(1, परिमाण(*rki))) == रिक्त ||
	    (rki->कुञ्चिका_id = strdup(कुञ्चिका_id)) == रिक्त) {
		मुक्त(rki);
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	}
	erki = RB_निवेशय(revoked_कुञ्चिका_id_वृक्षः, &rc->revoked_कुञ्चिका_ids, rki);
	जइ (erki != रिक्त) {
		मुक्त(rki->कुञ्चिका_id);
		मुक्त(rki);
	}
	प्रत्यागम 0;
}

/* Convert "key" to a public key blob without any certificate information */
स्थिर पूर्णाङ्क
plain_कुञ्चिका_blob(ध्रुव संरचना sshkey *कुञ्चिका, u_char **blob, size_t *blen)
{
	संरचना sshkey *kcopy;
	पूर्णाङ्क r;

	जइ ((r = sshkey_from_private(कुञ्चिका, &kcopy)) != 0)
		प्रत्यागम r;
	जइ (sshkey_is_cert(kcopy)) {
		जइ ((r = sshkey_drop_cert(kcopy)) != 0) {
			sshkey_free(kcopy);
			प्रत्यागम r;
		}
	}
	r = sshkey_to_blob(kcopy, blob, blen);
	sshkey_free(kcopy);
	प्रत्यागम r;
}

/* Revoke a key blob. Ownership of blob is transferred to the tree */
स्थिर पूर्णाङ्क
revoke_blob(संरचना revoked_blob_वृक्षः *rbt, u_char *blob, size_t len)
{
	संरचना revoked_blob *rb, *erb;

	जइ ((rb = calloc(1, परिमाण(*rb))) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	rb->blob = blob;
	rb->len = len;
	erb = RB_निवेशय(revoked_blob_वृक्षः, rbt, rb);
	जइ (erb != रिक्त) {
		मुक्त(rb->blob);
		मुक्त(rb);
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_krl_revoke_कुञ्चिका_explicit(संरचना ssh_krl *krl, ध्रुव संरचना sshkey *कुञ्चिका)
{
	u_char *blob;
	size_t len;
	पूर्णाङ्क r;

	debug3_f("revoke type %s", sshkey_type(कुञ्चिका));
	जइ ((r = plain_कुञ्चिका_blob(कुञ्चिका, &blob, &len)) != 0)
		प्रत्यागम r;
	प्रत्यागम revoke_blob(&krl->revoked_कुञ्चिकाः, blob, len);
}

स्थिर पूर्णाङ्क
revoke_by_hash(संरचना revoked_blob_वृक्षः *target, ध्रुव u_char *p, size_t len)
{
	u_char *blob;
	पूर्णाङ्क r;

	/* need to copy hash, as revoke_blob steals ownership */
	जइ ((blob = malloc(len)) == रिक्त)
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	memcpy(blob, p, len);
	जइ ((r = revoke_blob(target, blob, len)) != 0) {
		मुक्त(blob);
		प्रत्यागम r;
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_krl_revoke_कुञ्चिका_sha1(संरचना ssh_krl *krl, ध्रुव u_char *p, size_t len)
{
	debug3_f("revoke by sha1");
	जइ (len != 20)
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	प्रत्यागम revoke_by_hash(&krl->revoked_sha1s, p, len);
}

पूर्णाङ्क
ssh_krl_revoke_कुञ्चिका_sha256(संरचना ssh_krl *krl, ध्रुव u_char *p, size_t len)
{
	debug3_f("revoke by sha256");
	जइ (len != 32)
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	प्रत्यागम revoke_by_hash(&krl->revoked_sha256s, p, len);
}

पूर्णाङ्क
ssh_krl_revoke_कुञ्चिका(संरचना ssh_krl *krl, ध्रुव संरचना sshkey *कुञ्चिका)
{
	/* XXX replace with SHA256? */
	जइ (!sshkey_is_cert(कुञ्चिका))
		प्रत्यागम ssh_krl_revoke_कुञ्चिका_explicit(krl, कुञ्चिका);

	जइ (कुञ्चिका->cert->serial == 0) {
		प्रत्यागम ssh_krl_revoke_cert_by_कुञ्चिका_id(krl,
		    कुञ्चिका->cert->signature_कुञ्चिका,
		    कुञ्चिका->cert->कुञ्चिका_id);
	} अण्णहा {
		प्रत्यागम ssh_krl_revoke_cert_by_serial(krl,
		    कुञ्चिका->cert->signature_कुञ्चिका,
		    कुञ्चिका->cert->serial);
	}
}

/*
 * Select the most compact section type to emit next in a KRL based on
 * the current section type, the run length of contiguous revoked serial
 * numbers and the gaps from the last and to the next revoked serial.
 * Applies a mostly-accurate bit cost model to select the section type
 * that will minimise the size of the resultant KRL.
 */
स्थिर पूर्णाङ्क
choose_next_state(पूर्णाङ्क current_state, uint64_t contig, पूर्णाङ्क final,
    uint64_t last_gap, uint64_t next_gap, size_t bitmap_len,
    पूर्णाङ्क *force_new_section)
{
	पूर्णाङ्क new_state;
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
	विकल्प (current_state) {
	पक्ष KRL_SECTION_CERT_SERIAL_LIST:
		cost_bitmap_restart = cost_bitmap = 8 + 64;
		भङ्ग;
	पक्ष KRL_SECTION_CERT_SERIAL_BITMAP:
		cost_list = 8;
		cost_bitmap_restart = 8 + 64;
		भङ्ग;
	पक्ष KRL_SECTION_CERT_SERIAL_RANGE:
	पक्ष 0:
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
	जइ (bitmap_len + cost_bitmap >= SSHBUF_MAX_BIGNUM) {
		KRL_DBG(("bitmap overfull len=%zu cost=%llu max=%u",
		    bitmap_len, (unsigned long long)cost_bitmap,
		    SSHBUF_MAX_BIGNUM));
		cost_bitmap = (uint64_t)-1;
	}

	/* Now pick the best choice */
	*force_new_section = 0;
	new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
	cost = cost_bitmap;
	जइ (cost_range < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_RANGE;
		cost = cost_range;
	}
	जइ (cost_list < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_LIST;
		cost = cost_list;
	}
	जइ (cost_bitmap_restart < cost) {
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
	प्रत्यागम new_state;
}

स्थिर पूर्णाङ्क
put_bitmap(संरचना sshbuf *buf, संरचना bitmap *bitmap)
{
	size_t len;
	u_char *blob;
	पूर्णाङ्क r;

	len = bitmap_nbytes(bitmap);
	जइ ((blob = malloc(len)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	जइ (bitmap_to_string(bitmap, blob, len) != 0) {
		मुक्त(blob);
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	}
	r = sshbuf_put_bignum2_bytes(buf, blob, len);
	मुक्त(blob);
	प्रत्यागम r;
}

/* Generate a KRL_SECTION_CERTIFICATES KRL section */
स्थिर पूर्णाङ्क
revoked_certs_generate(संरचना revoked_certs *rc, संरचना sshbuf *buf)
{
	पूर्णाङ्क final, force_new_sect, r = SSH_ERR_INTERNAL_ERROR;
	uint64_t i, contig, gap, last = 0, bitmap_start = 0;
	संरचना revoked_serial *rs, *nrs;
	संरचना revoked_कुञ्चिका_id *rki;
	पूर्णाङ्क next_state, state = 0;
	size_t bitmap_len;
	संरचना sshbuf *sect;
	संरचना bitmap *bitmap = रिक्त;

	जइ ((sect = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;

	/* Store the header: optional CA scope key, reserved */
	जइ (rc->ca_कुञ्चिका == रिक्त) {
		जइ ((r = sshbuf_put_string(buf, रिक्त, 0)) != 0)
			गच्छ out;
	} अण्णहा {
		जइ ((r = sshkey_puts(rc->ca_कुञ्चिका, buf)) != 0)
			गच्छ out;
	}
	जइ ((r = sshbuf_put_string(buf, रिक्त, 0)) != 0)
		गच्छ out;

	/* Store the revoked serials.  */
	प्रति (rs = RB_MIN(revoked_serial_वृक्षः, &rc->revoked_serials);
	     rs != रिक्त;
	     rs = RB_NEXT(revoked_serial_वृक्षः, &rc->revoked_serials, rs)) {
		KRL_DBG(("serial %llu:%llu state 0x%02x",
		    (long long unsigned)rs->lo, (long long unsigned)rs->hi,
		    state));

		/* Check contiguous length and gap to next section (if any) */
		nrs = RB_NEXT(revoked_serial_वृक्षः, &rc->revoked_serials, rs);
		final = nrs == रिक्त;
		gap = nrs == रिक्त ? 0 : nrs->lo - rs->hi;
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
		जइ (state != 0 && (force_new_sect || next_state != state ||
		    state == KRL_SECTION_CERT_SERIAL_RANGE)) {
			KRL_DBG(("finish state 0x%02x", state));
			विकल्प (state) {
			पक्ष KRL_SECTION_CERT_SERIAL_LIST:
			पक्ष KRL_SECTION_CERT_SERIAL_RANGE:
				भङ्ग;
			पक्ष KRL_SECTION_CERT_SERIAL_BITMAP:
				जइ ((r = put_bitmap(sect, bitmap)) != 0)
					गच्छ out;
				bitmap_free(bitmap);
				bitmap = रिक्त;
				भङ्ग;
			}
			जइ ((r = sshbuf_put_u8(buf, state)) != 0 ||
			    (r = sshbuf_put_stringb(buf, sect)) != 0)
				गच्छ out;
			sshbuf_reset(sect);
		}

		/* If we are starting a new section then prepare it now */
		जइ (next_state != state || force_new_sect) {
			KRL_DBG(("start state 0x%02x",
			    next_state));
			state = next_state;
			sshbuf_reset(sect);
			विकल्प (state) {
			पक्ष KRL_SECTION_CERT_SERIAL_LIST:
			पक्ष KRL_SECTION_CERT_SERIAL_RANGE:
				भङ्ग;
			पक्ष KRL_SECTION_CERT_SERIAL_BITMAP:
				जइ ((bitmap = bitmap_new()) == रिक्त) {
					r = SSH_ERR_ALLOC_FAIL;
					गच्छ out;
				}
				bitmap_start = rs->lo;
				जइ ((r = sshbuf_put_u64(sect,
				    bitmap_start)) != 0)
					गच्छ out;
				भङ्ग;
			}
		}

		/* Perform section-specific processing */
		विकल्प (state) {
		पक्ष KRL_SECTION_CERT_SERIAL_LIST:
			प्रति (i = 0; i < contig; i++) {
				जइ ((r = sshbuf_put_u64(sect, rs->lo + i)) != 0)
					गच्छ out;
			}
			भङ्ग;
		पक्ष KRL_SECTION_CERT_SERIAL_RANGE:
			जइ ((r = sshbuf_put_u64(sect, rs->lo)) != 0 ||
			    (r = sshbuf_put_u64(sect, rs->hi)) != 0)
				गच्छ out;
			भङ्ग;
		पक्ष KRL_SECTION_CERT_SERIAL_BITMAP:
			जइ (rs->lo - bitmap_start > INT_MAX) {
				r = SSH_ERR_INVALID_FORMAT;
				error_f("insane bitmap gap");
				गच्छ out;
			}
			प्रति (i = 0; i < contig; i++) {
				जइ (bitmap_set_bit(bitmap,
				    rs->lo + i - bitmap_start) != 0) {
					r = SSH_ERR_ALLOC_FAIL;
					गच्छ out;
				}
			}
			भङ्ग;
		}
		last = rs->hi;
	}
	/* Flush the remaining section, if any */
	जइ (state != 0) {
		KRL_DBG(("serial final flush for state 0x%02x", state));
		विकल्प (state) {
		पक्ष KRL_SECTION_CERT_SERIAL_LIST:
		पक्ष KRL_SECTION_CERT_SERIAL_RANGE:
			भङ्ग;
		पक्ष KRL_SECTION_CERT_SERIAL_BITMAP:
			जइ ((r = put_bitmap(sect, bitmap)) != 0)
				गच्छ out;
			bitmap_free(bitmap);
			bitmap = रिक्त;
			भङ्ग;
		}
		जइ ((r = sshbuf_put_u8(buf, state)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			गच्छ out;
	}
	KRL_DBG(("serial done "));

	/* Now output a section for any revocations by key ID */
	sshbuf_reset(sect);
	RB_FOREACH(rki, revoked_कुञ्चिका_id_वृक्षः, &rc->revoked_कुञ्चिका_ids) {
		KRL_DBG(("key ID %s", rki->कुञ्चिका_id));
		जइ ((r = sshbuf_put_cstring(sect, rki->कुञ्चिका_id)) != 0)
			गच्छ out;
	}
	जइ (sshbuf_len(sect) != 0) {
		जइ ((r = sshbuf_put_u8(buf, KRL_SECTION_CERT_कुञ्चिका_ID)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			गच्छ out;
	}
	r = 0;
 out:
	bitmap_free(bitmap);
	sshbuf_free(sect);
	प्रत्यागम r;
}

पूर्णाङ्क
ssh_krl_to_blob(संरचना ssh_krl *krl, संरचना sshbuf *buf)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	संरचना revoked_certs *rc;
	संरचना revoked_blob *rb;
	संरचना sshbuf *sect;
	u_char *sblob = रिक्त;

	जइ (krl->generated_date == 0)
		krl->generated_date = time(रिक्त);

	जइ ((sect = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;

	/* Store the header */
	जइ ((r = sshbuf_put(buf, KRL_MAGIC, परिमाण(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_put_u32(buf, KRL_FORMAT_VERSION)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->krl_version)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->generated_date)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->flags)) != 0 ||
	    (r = sshbuf_put_string(buf, रिक्त, 0)) != 0 ||
	    (r = sshbuf_put_cstring(buf, krl->comment)) != 0)
		गच्छ out;

	/* Store sections for revoked certificates */
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		sshbuf_reset(sect);
		जइ ((r = revoked_certs_generate(rc, sect)) != 0)
			गच्छ out;
		जइ ((r = sshbuf_put_u8(buf, KRL_SECTION_CERTIFICATES)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			गच्छ out;
	}

	/* Finally, output sections for revocations by public key/hash */
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_वृक्षः, &krl->revoked_कुञ्चिकाः) {
		KRL_DBG(("key len %zu ", rb->len));
		जइ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			गच्छ out;
	}
	जइ (sshbuf_len(sect) != 0) {
		जइ ((r = sshbuf_put_u8(buf, KRL_SECTION_EXPLICIT_कुञ्चिका)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			गच्छ out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_वृक्षः, &krl->revoked_sha1s) {
		KRL_DBG(("hash len %zu ", rb->len));
		जइ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			गच्छ out;
	}
	जइ (sshbuf_len(sect) != 0) {
		जइ ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA1)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			गच्छ out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_वृक्षः, &krl->revoked_sha256s) {
		KRL_DBG(("hash len %zu ", rb->len));
		जइ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			गच्छ out;
	}
	जइ (sshbuf_len(sect) != 0) {
		जइ ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA256)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			गच्छ out;
	}
	/* success */
	r = 0;
 out:
	मुक्त(sblob);
	sshbuf_free(sect);
	प्रत्यागम r;
}

स्थिर शून्य
format_timestamp(uint64_t timestamp, वर्ण *ts, size_t nts)
{
	time_t t;
	संरचना tm *tm;

	t = timestamp;
	tm = localtime(&t);
	जइ (tm == रिक्त)
		strlcpy(ts, "<INVALID>", nts);
	अण्णहा {
		*ts = '\0';
		strftime(ts, nts, "%Y%m%dT%H%M%S", tm);
	}
}

स्थिर पूर्णाङ्क
cert_extension_subsection(संरचना sshbuf *subsect, संरचना ssh_krl *krl)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	संरचना sshbuf *मानम् = रिक्त;
	वर्ण *name = रिक्त;

	जइ ((r = sshbuf_get_cstring(subsect, &name, रिक्त)) != 0 ||
	    (r = sshbuf_get_u8(subsect, &critical)) != 0 ||
	    (r = sshbuf_froms(subsect, &मानम्)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid certificate extension subsection");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	जइ (sshbuf_len(subsect) != 0) {
		error("KRL has invalid certificate extension subsection: "
		    "trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	debug_f("cert extension %s critical %u len %zu",
	    name, critical, sshbuf_len(मानम्));
	/* no extensions are currently supported */
	जइ (critical) {
		error("KRL contains unsupported critical certificate "
		    "subsection \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		गच्छ out;
	}
	/* success */
	r = 0;
 out:
	मुक्त(name);
	sshbuf_free(मानम्);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
parse_revoked_certs(संरचना sshbuf *buf, संरचना ssh_krl *krl)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	ध्रुव u_char *blob;
	size_t blen, nbits;
	संरचना sshbuf *subsect = रिक्त;
	uint64_t serial, serial_lo, serial_hi;
	संरचना bitmap *bitmap = रिक्त;
	वर्ण *कुञ्चिका_id = रिक्त;
	संरचना sshkey *ca_कुञ्चिका = रिक्त;

	जइ ((subsect = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;

	/* Header: key, reserved */
	जइ ((r = sshbuf_get_string_direct(buf, &blob, &blen)) != 0 ||
	    (r = sshbuf_skip_string(buf)) != 0)
		गच्छ out;
	जइ (blen != 0 && (r = sshkey_from_blob(blob, blen, &ca_कुञ्चिका)) != 0)
		गच्छ out;

	जाव (sshbuf_len(buf) > 0) {
		sshbuf_free(subsect);
		subsect = रिक्त;
		जइ ((r = sshbuf_get_u8(buf, &type)) != 0 ||
		    (r = sshbuf_froms(buf, &subsect)) != 0)
			गच्छ out;
		KRL_DBG(("subsection type 0x%02x", type));
		/* sshbuf_dump(subsect, stderr); */

		विकल्प (type) {
		पक्ष KRL_SECTION_CERT_SERIAL_LIST:
			जाव (sshbuf_len(subsect) > 0) {
				जइ ((r = sshbuf_get_u64(subsect, &serial)) != 0)
					गच्छ out;
				जइ ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_कुञ्चिका, serial)) != 0)
					गच्छ out;
			}
			भङ्ग;
		पक्ष KRL_SECTION_CERT_SERIAL_RANGE:
			जइ ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_u64(subsect, &serial_hi)) != 0)
				गच्छ out;
			जइ ((r = ssh_krl_revoke_cert_by_serial_range(krl,
			    ca_कुञ्चिका, serial_lo, serial_hi)) != 0)
				गच्छ out;
			भङ्ग;
		पक्ष KRL_SECTION_CERT_SERIAL_BITMAP:
			जइ ((bitmap = bitmap_new()) == रिक्त) {
				r = SSH_ERR_ALLOC_FAIL;
				गच्छ out;
			}
			जइ ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_bignum2_bytes_direct(subsect,
			    &blob, &blen)) != 0)
				गच्छ out;
			जइ (bitmap_from_string(bitmap, blob, blen) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				गच्छ out;
			}
			nbits = bitmap_nbits(bitmap);
			प्रति (serial = 0; serial < (uint64_t)nbits; serial++) {
				जइ (serial > 0 && serial_lo + serial == 0) {
					error_f("bitmap wraps u64");
					r = SSH_ERR_INVALID_FORMAT;
					गच्छ out;
				}
				जइ (!bitmap_test_bit(bitmap, serial))
					अनुवर्त;
				जइ ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_कुञ्चिका, serial_lo + serial)) != 0)
					गच्छ out;
			}
			bitmap_free(bitmap);
			bitmap = रिक्त;
			भङ्ग;
		पक्ष KRL_SECTION_CERT_कुञ्चिका_ID:
			जाव (sshbuf_len(subsect) > 0) {
				जइ ((r = sshbuf_get_cstring(subsect,
				    &कुञ्चिका_id, रिक्त)) != 0)
					गच्छ out;
				जइ ((r = ssh_krl_revoke_cert_by_कुञ्चिका_id(krl,
				    ca_कुञ्चिका, कुञ्चिका_id)) != 0)
					गच्छ out;
				मुक्त(कुञ्चिका_id);
				कुञ्चिका_id = रिक्त;
			}
			भङ्ग;
		पक्ष KRL_SECTION_CERT_EXTENSION:
			जइ ((r = cert_extension_subsection(subsect, krl)) != 0)
				गच्छ out;
			भङ्ग;
		स्वभाव:
			error("Unsupported KRL certificate section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
		जइ (sshbuf_len(subsect) > 0) {
			error("KRL certificate section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
	}

	r = 0;
 out:
	जइ (bitmap != रिक्त)
		bitmap_free(bitmap);
	मुक्त(कुञ्चिका_id);
	sshkey_free(ca_कुञ्चिका);
	sshbuf_free(subsect);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
blob_section(संरचना sshbuf *sect, संरचना revoked_blob_वृक्षः *target_वृक्षः,
    size_t expected_len)
{
	u_char *rdata = रिक्त;
	size_t rlen = 0;
	पूर्णाङ्क r;

	जाव (sshbuf_len(sect) > 0) {
		जइ ((r = sshbuf_get_string(sect, &rdata, &rlen)) != 0)
			प्रत्यागम r;
		जइ (expected_len != 0 && rlen != expected_len) {
			error_f("bad length");
			मुक्त(rdata);
			प्रत्यागम SSH_ERR_INVALID_FORMAT;
		}
		जइ ((r = revoke_blob(target_वृक्षः, rdata, rlen)) != 0) {
			मुक्त(rdata);
			प्रत्यागम r;
		}
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
extension_section(संरचना sshbuf *sect, संरचना ssh_krl *krl)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	संरचना sshbuf *मानम् = रिक्त;
	वर्ण *name = रिक्त;

	जइ ((r = sshbuf_get_cstring(sect, &name, रिक्त)) != 0 ||
	    (r = sshbuf_get_u8(sect, &critical)) != 0 ||
	    (r = sshbuf_froms(sect, &मानम्)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid extension section");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	जइ (sshbuf_len(sect) != 0) {
		error("KRL has invalid extension section: trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	debug_f("extension %s critical %u len %zu",
	    name, critical, sshbuf_len(मानम्));
	/* no extensions are currently supported */
	जइ (critical) {
		error("KRL contains unsupported critical section \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		गच्छ out;
	}
	/* success */
	r = 0;
 out:
	मुक्त(name);
	sshbuf_free(मानम्);
	प्रत्यागम r;
}

/* Attempt to parse a KRL */
पूर्णाङ्क
ssh_krl_from_blob(संरचना sshbuf *buf, संरचना ssh_krl **krlp)
{
	संरचना sshbuf *copy = रिक्त, *sect = रिक्त;
	संरचना ssh_krl *krl = रिक्त;
	वर्ण timestamp[64];
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	u_int format_version;

	*krlp = रिक्त;

	/* KRL must begin with magic string */
	जइ ((r = sshbuf_cmp(buf, 0, KRL_MAGIC, परिमाण(KRL_MAGIC) - 1)) != 0) {
		debug2_f("bad KRL magic header");
		प्रत्यागम SSH_ERR_KRL_BAD_MAGIC;
	}

	जइ ((krl = ssh_krl_init()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		error_f("alloc failed");
		गच्छ out;
	}
	/* Don't modify buffer */
	जइ ((copy = sshbuf_fromb(buf)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	जइ ((r = sshbuf_consume(copy, परिमाण(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_get_u32(copy, &format_version)) != 0)
		गच्छ out;
	जइ (format_version != KRL_FORMAT_VERSION) {
		error_f("unsupported KRL format version %u", format_version);
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	जइ ((r = sshbuf_get_u64(copy, &krl->krl_version)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->generated_date)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->flags)) != 0 ||
	    (r = sshbuf_skip_string(copy)) != 0 ||
	    (r = sshbuf_get_cstring(copy, &krl->comment, रिक्त)) != 0) {
		error_fr(r, "parse KRL header");
		गच्छ out;
	}
	format_timestamp(krl->generated_date, timestamp, परिमाण(timestamp));
	debug("KRL version %llu generated at %s%s%s",
	    (long long unsigned)krl->krl_version, timestamp,
	    *krl->comment ? ": " : "", krl->comment);

	/* Parse and load the KRL sections. */
	जाव (sshbuf_len(copy) > 0) {
		sshbuf_free(sect);
		sect = रिक्त;
		जइ ((r = sshbuf_get_u8(copy, &type)) != 0 ||
		    (r = sshbuf_froms(copy, &sect)) != 0)
			गच्छ out;
		KRL_DBG(("section 0x%02x", type));

		विकल्प (type) {
		पक्ष KRL_SECTION_CERTIFICATES:
			जइ ((r = parse_revoked_certs(sect, krl)) != 0)
				गच्छ out;
			भङ्ग;
		पक्ष KRL_SECTION_EXPLICIT_कुञ्चिका:
			जइ ((r = blob_section(sect,
			    &krl->revoked_कुञ्चिकाः, 0)) != 0)
				गच्छ out;
			भङ्ग;
		पक्ष KRL_SECTION_FINGERPRINT_SHA1:
			जइ ((r = blob_section(sect,
			    &krl->revoked_sha1s, 20)) != 0)
				गच्छ out;
			भङ्ग;
		पक्ष KRL_SECTION_FINGERPRINT_SHA256:
			जइ ((r = blob_section(sect,
			    &krl->revoked_sha256s, 32)) != 0)
				गच्छ out;
			भङ्ग;
		पक्ष KRL_SECTION_EXTENSION:
			जइ ((r = extension_section(sect, krl)) != 0)
				गच्छ out;
			भङ्ग;
		पक्ष KRL_SECTION_SIGNATURE:
			/* Handled above, but still need to stay in synch */
			sshbuf_free(sect);
			sect = रिक्त;
			जइ ((r = sshbuf_skip_string(copy)) != 0)
				गच्छ out;
			भङ्ग;
		स्वभाव:
			error("Unsupported KRL section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
		जइ (sect != रिक्त && sshbuf_len(sect) > 0) {
			error("KRL section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
	}

	/* Success */
	*krlp = krl;
	r = 0;
 out:
	जइ (r != 0)
		ssh_krl_free(krl);
	sshbuf_free(copy);
	sshbuf_free(sect);
	प्रत्यागम r;
}

/* Checks certificate serial number and key ID revocation */
स्थिर पूर्णाङ्क
is_cert_revoked(ध्रुव संरचना sshkey *कुञ्चिका, संरचना revoked_certs *rc)
{
	संरचना revoked_serial rs, *ers;
	संरचना revoked_कुञ्चिका_id rki, *erki;

	/* Check revocation by cert key ID */
	memset(&rki, 0, परिमाण(rki));
	rki.कुञ्चिका_id = कुञ्चिका->cert->कुञ्चिका_id;
	erki = RB_FIND(revoked_कुञ्चिका_id_वृक्षः, &rc->revoked_कुञ्चिका_ids, &rki);
	जइ (erki != रिक्त) {
		KRL_DBG(("revoked by key ID"));
		प्रत्यागम SSH_ERR_कुञ्चिका_REVOKED;
	}

	/*
	 * Zero serials numbers are ignored (it's the default when the
	 * CA doesn't specify one).
	 */
	जइ (कुञ्चिका->cert->serial == 0)
		प्रत्यागम 0;

	memset(&rs, 0, परिमाण(rs));
	rs.lo = rs.hi = कुञ्चिका->cert->serial;
	ers = RB_FIND(revoked_serial_वृक्षः, &rc->revoked_serials, &rs);
	जइ (ers != रिक्त) {
		KRL_DBG(("revoked serial %llu matched %llu:%llu",
		    (unsigned long long)कुञ्चिका->cert->serial,
		    (unsigned long long)ers->lo,
		    (unsigned long long)ers->hi));
		प्रत्यागम SSH_ERR_कुञ्चिका_REVOKED;
	}
	प्रत्यागम 0;
}

/* Checks whether a given key/cert is revoked. Does not check its CA */
स्थिर पूर्णाङ्क
is_कुञ्चिका_revoked(संरचना ssh_krl *krl, ध्रुव संरचना sshkey *कुञ्चिका)
{
	संरचना revoked_blob rb, *erb;
	संरचना revoked_certs *rc;
	पूर्णाङ्क r;

	/* Check explicitly revoked hashes first */
	memset(&rb, 0, परिमाण(rb));
	जइ ((r = sshkey_fingerprint_raw(कुञ्चिका, SSH_DIGEST_SHA1,
	    &rb.blob, &rb.len)) != 0)
		प्रत्यागम r;
	erb = RB_FIND(revoked_blob_वृक्षः, &krl->revoked_sha1s, &rb);
	मुक्त(rb.blob);
	जइ (erb != रिक्त) {
		KRL_DBG(("revoked by key SHA1"));
		प्रत्यागम SSH_ERR_कुञ्चिका_REVOKED;
	}
	memset(&rb, 0, परिमाण(rb));
	जइ ((r = sshkey_fingerprint_raw(कुञ्चिका, SSH_DIGEST_SHA256,
	    &rb.blob, &rb.len)) != 0)
		प्रत्यागम r;
	erb = RB_FIND(revoked_blob_वृक्षः, &krl->revoked_sha256s, &rb);
	मुक्त(rb.blob);
	जइ (erb != रिक्त) {
		KRL_DBG(("revoked by key SHA256"));
		प्रत्यागम SSH_ERR_कुञ्चिका_REVOKED;
	}

	/* Next, explicit keys */
	memset(&rb, 0, परिमाण(rb));
	जइ ((r = plain_कुञ्चिका_blob(कुञ्चिका, &rb.blob, &rb.len)) != 0)
		प्रत्यागम r;
	erb = RB_FIND(revoked_blob_वृक्षः, &krl->revoked_कुञ्चिकाः, &rb);
	मुक्त(rb.blob);
	जइ (erb != रिक्त) {
		KRL_DBG(("revoked by explicit key"));
		प्रत्यागम SSH_ERR_कुञ्चिका_REVOKED;
	}

	जइ (!sshkey_is_cert(कुञ्चिका))
		प्रत्यागम 0;

	/* Check cert revocation for the specified CA */
	जइ ((r = revoked_certs_for_ca_कुञ्चिका(krl, कुञ्चिका->cert->signature_कुञ्चिका,
	    &rc, 0)) != 0)
		प्रत्यागम r;
	जइ (rc != रिक्त) {
		जइ ((r = is_cert_revoked(कुञ्चिका, rc)) != 0)
			प्रत्यागम r;
	}
	/* Check cert revocation for the wildcard CA */
	जइ ((r = revoked_certs_for_ca_कुञ्चिका(krl, रिक्त, &rc, 0)) != 0)
		प्रत्यागम r;
	जइ (rc != रिक्त) {
		जइ ((r = is_cert_revoked(कुञ्चिका, rc)) != 0)
			प्रत्यागम r;
	}

	KRL_DBG(("%llu no match", (unsigned long long)कुञ्चिका->cert->serial));
	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_krl_check_कुञ्चिका(संरचना ssh_krl *krl, ध्रुव संरचना sshkey *कुञ्चिका)
{
	पूर्णाङ्क r;

	KRL_DBG(("checking key"));
	जइ ((r = is_कुञ्चिका_revoked(krl, कुञ्चिका)) != 0)
		प्रत्यागम r;
	जइ (sshkey_is_cert(कुञ्चिका)) {
		debug2_f("checking CA key");
		जइ ((r = is_कुञ्चिका_revoked(krl, कुञ्चिका->cert->signature_कुञ्चिका)) != 0)
			प्रत्यागम r;
	}
	KRL_DBG(("key okay"));
	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_krl_file_contains_कुञ्चिका(ध्रुव वर्ण *path, ध्रुव संरचना sshkey *कुञ्चिका)
{
	संरचना sshbuf *krlbuf = रिक्त;
	संरचना ssh_krl *krl = रिक्त;
	पूर्णाङ्क oerrno = 0, r;

	जइ (path == रिक्त)
		प्रत्यागम 0;
	जइ ((r = sshbuf_load_file(path, &krlbuf)) != 0) {
		oerrno = errno;
		गच्छ out;
	}
	जइ ((r = ssh_krl_from_blob(krlbuf, &krl)) != 0)
		गच्छ out;
	debug2_f("checking KRL %s", path);
	r = ssh_krl_check_कुञ्चिका(krl, कुञ्चिका);
 out:
	sshbuf_free(krlbuf);
	ssh_krl_free(krl);
	जइ (r != 0)
		errno = oerrno;
	प्रत्यागम r;
}

पूर्णाङ्क
krl_dump(संरचना ssh_krl *krl, FILE *f)
{
	संरचना sshkey *कुञ्चिका = रिक्त;
	संरचना revoked_blob *rb;
	संरचना revoked_certs *rc;
	संरचना revoked_serial *rs;
	संरचना revoked_कुञ्चिका_id *rki;
	पूर्णाङ्क r, ret = 0;
	वर्ण *fp, timestamp[64];

	/* Try to print in a KRL spec-compatible format */
	format_timestamp(krl->generated_date, timestamp, परिमाण(timestamp));
	fprintf(f, "# KRL version %llu\n", (unsigned long long)krl->krl_version);
	fprintf(f, "# Generated at %s\n", timestamp);
	जइ (krl->comment != रिक्त && *krl->comment != '\0') {
		r = INT_MAX;
		asmprintf(&fp, INT_MAX, &r, "%s", krl->comment);
		fprintf(f, "# Comment: %s\n", fp);
		मुक्त(fp);
	}
	fputc('\n', f);

	RB_FOREACH(rb, revoked_blob_वृक्षः, &krl->revoked_कुञ्चिकाः) {
		जइ ((r = sshkey_from_blob(rb->blob, rb->len, &कुञ्चिका)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			error_r(r, "parse KRL key");
			अनुवर्त;
		}
		जइ ((fp = sshkey_fingerprint(कुञ्चिका, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == रिक्त) {
			ret = SSH_ERR_INVALID_FORMAT;
			error("sshkey_fingerprint failed");
			अनुवर्त;
		}
		fprintf(f, "hash: %s # %s\n", fp, sshkey_ssh_name(कुञ्चिका));
		मुक्त(fp);
		मुक्त(कुञ्चिका);
	}
	RB_FOREACH(rb, revoked_blob_वृक्षः, &krl->revoked_sha256s) {
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "hash: SHA256:%s\n", fp);
		मुक्त(fp);
	}
	RB_FOREACH(rb, revoked_blob_वृक्षः, &krl->revoked_sha1s) {
		/*
		 * There is not KRL spec keyword for raw SHA1 hashes, so
		 * print them as comments.
		 */
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "# hash SHA1:%s\n", fp);
		मुक्त(fp);
	}

	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		fputc('\n', f);
		जइ (rc->ca_कुञ्चिका == रिक्त)
			fprintf(f, "# Wildcard CA\n");
		अण्णहा {
			जइ ((fp = sshkey_fingerprint(rc->ca_कुञ्चिका,
			    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == रिक्त) {
				ret = SSH_ERR_INVALID_FORMAT;
				error("sshkey_fingerprint failed");
				अनुवर्त;
			}
			fprintf(f, "# CA key %s %s\n",
			    sshkey_ssh_name(rc->ca_कुञ्चिका), fp);
			मुक्त(fp);
		}
		RB_FOREACH(rs, revoked_serial_वृक्षः, &rc->revoked_serials) {
			जइ (rs->lo == rs->hi) {
				fprintf(f, "serial: %llu\n",
				    (unsigned long long)rs->lo);
			} अण्णहा {
				fprintf(f, "serial: %llu-%llu\n",
				    (unsigned long long)rs->lo,
				    (unsigned long long)rs->hi);
			}
		}
		RB_FOREACH(rki, revoked_कुञ्चिका_id_वृक्षः, &rc->revoked_कुञ्चिका_ids) {
			/*
			 * We don't want key IDs with embedded newlines to
			 * mess up the display.
			 */
			r = INT_MAX;
			asmprintf(&fp, INT_MAX, &r, "%s", rki->कुञ्चिका_id);
			fprintf(f, "id: %s\n", fp);
			मुक्त(fp);
		}
	}
	प्रत्यागम ret;
}
