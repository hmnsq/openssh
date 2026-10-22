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
#यदि_परिभाषितम् DEBUG_KRL
# define KRL_DBG(x) debug3_f x
#अन्यथा
# define KRL_DBG(x)
#यदि_अन्तः

/*
 * Trees of revoked serial numbers, key IDs and keys. This allows
 * quick searching, querying and producing lists in canonical order.
 */

/* Tree of serial numbers. XXX make smarter: really need a real sparse bitmap */
संरचना revoked_serial {
	uint64_t lo, hi;
	RB_प्रविष्टिः(revoked_serial) वृक्षः_प्रविष्टिः;
};
स्थिर पूर्णाङ्क serial_cmp(संरचना revoked_serial *a, संरचना revoked_serial *b);
RB_शीर्ष(revoked_serial_वृक्षः, revoked_serial);
RB_GENERATE_STATIC(revoked_serial_वृक्षः, revoked_serial, वृक्षः_प्रविष्टिः, serial_cmp)

/* Tree of key IDs */
संरचना revoked_कुञ्चिका_id {
	वर्ण *कुञ्चिका_id;
	RB_प्रविष्टिः(revoked_कुञ्चिका_id) वृक्षः_प्रविष्टिः;
};
स्थिर पूर्णाङ्क कुञ्चिका_id_cmp(संरचना revoked_कुञ्चिका_id *a, संरचना revoked_कुञ्चिका_id *b);
RB_शीर्ष(revoked_कुञ्चिका_id_वृक्षः, revoked_कुञ्चिका_id);
RB_GENERATE_STATIC(revoked_कुञ्चिका_id_वृक्षः, revoked_कुञ्चिका_id, वृक्षः_प्रविष्टिः, कुञ्चिका_id_cmp)

/* Tree of blobs (used for keys and fingerprints) */
संरचना revoked_blob {
	u_char *blob;
	आकार_t len;
	RB_प्रविष्टिः(revoked_blob) वृक्षः_प्रविष्टिः;
};
स्थिर पूर्णाङ्क blob_cmp(संरचना revoked_blob *a, संरचना revoked_blob *b);
RB_शीर्ष(revoked_blob_वृक्षः, revoked_blob);
RB_GENERATE_STATIC(revoked_blob_वृक्षः, revoked_blob, वृक्षः_प्रविष्टिः, blob_cmp)

/* Tracks revoked certs for a single CA */
संरचना revoked_certs {
	संरचना sshkey *ca_कुञ्चिका;
	संरचना revoked_serial_वृक्षः revoked_serials;
	संरचना revoked_कुञ्चिका_id_वृक्षः revoked_कुञ्चिका_ids;
	TAILQ_ENTRY(revoked_certs) प्रविष्टिः;
};
TAILQ_HEAD(revoked_certs_list, revoked_certs);

संरचना ssh_krl {
	uint64_t krl_संस्करणम्;
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
	यदि (a->hi >= b->lo && a->lo <= b->hi)
		प्रत्यागम 0;
	प्रत्यागम a->lo < b->lo ? -1 : 1;
}

स्थिर पूर्णाङ्क
कुञ्चिका_id_cmp(संरचना revoked_कुञ्चिका_id *a, संरचना revoked_कुञ्चिका_id *b)
{
	प्रत्यागम वाक्यं_तुलय(a->कुञ्चिका_id, b->कुञ्चिका_id);
}

स्थिर पूर्णाङ्क
blob_cmp(संरचना revoked_blob *a, संरचना revoked_blob *b)
{
	पूर्णाङ्क r;

	यदि (a->len != b->len) {
		यदि ((r = memcmp(a->blob, b->blob, MINIMUM(a->len, b->len))) != 0)
			प्रत्यागम r;
		प्रत्यागम a->len > b->len ? 1 : -1;
	} अन्यथा
		प्रत्यागम memcmp(a->blob, b->blob, a->len);
}

संरचना ssh_krl *
ssh_krl_init(शून्य)
{
	संरचना ssh_krl *krl;

	यदि ((krl = शून्यस्मृतिं_देहि(1, परिमाण(*krl))) == रिक्त)
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

	यदि (rc == रिक्त)
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

	यदि (krl == रिक्त)
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
	TAILQ_FOREACH_SAFE(rc, &krl->revoked_certs, प्रविष्टिः, trc) {
		TAILQ_REMOVE(&krl->revoked_certs, rc, प्रविष्टिः);
		revoked_certs_free(rc);
	}
	मुक्त(krl);
}

शून्य
ssh_krl_समुच्चयः_संस्करणम्(संरचना ssh_krl *krl, uint64_t संस्करणम्)
{
	krl->krl_संस्करणम् = संस्करणम्;
}

पूर्णाङ्क
ssh_krl_समुच्चयः_comment(संरचना ssh_krl *krl, ध्रुव वर्ण *comment)
{
	मुक्त(krl->comment);
	यदि ((krl->comment = strdup(comment)) == रिक्त)
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
	TAILQ_FOREACH(rc, &krl->revoked_certs, प्रविष्टिः) {
		यदि ((ca_कुञ्चिका == रिक्त && rc->ca_कुञ्चिका == रिक्त) ||
		    sshkey_equal(rc->ca_कुञ्चिका, ca_कुञ्चिका)) {
			*rcp = rc;
			प्रत्यागम 0;
		}
	}
	यदि (!allow_create)
		प्रत्यागम 0;
	/* If this CA doesn't exist in the list then add it now */
	यदि ((rc = शून्यस्मृतिं_देहि(1, परिमाण(*rc))) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि (ca_कुञ्चिका == रिक्त)
		rc->ca_कुञ्चिका = रिक्त;
	अन्यथा यदि ((r = sshkey_from_वैयक्तिकम्(ca_कुञ्चिका, &rc->ca_कुञ्चिका)) != 0) {
		मुक्त(rc);
		प्रत्यागम r;
	}
	RB_INIT(&rc->revoked_serials);
	RB_INIT(&rc->revoked_कुञ्चिका_ids);
	TAILQ_INSERT_TAIL(&krl->revoked_certs, rc, प्रविष्टिः);
	KRL_DBG(("new CA %s", ca_कुञ्चिका == रिक्त ? "*" : sshkey_type(ca_कुञ्चिका)));
	*rcp = rc;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
निवेशय_serial_range(संरचना revoked_serial_वृक्षः *rt, uint64_t lo, uint64_t hi)
{
	संरचना revoked_serial rs, *ers, *crs, *irs;

	KRL_DBG(("insert %llu:%llu",
	    (अचिह्नित दीर्घ दीर्घ)lo, (अचिह्नित दीर्घ दीर्घ)hi));
	स्मृतिं_पूरय(&rs, 0, परिमाण(rs));
	rs.lo = lo;
	rs.hi = hi;
	ers = RB_NFIND(revoked_serial_वृक्षः, rt, &rs);
	यदि (ers == रिक्त || serial_cmp(ers, &rs) != 0) {
		/* No entry matches. Just insert */
		यदि ((irs = स्मृतिं_देहि(परिमाण(rs))) == रिक्त)
			प्रत्यागम SSH_ERR_ALLOC_FAIL;
		स्मृतिं_प्रतिलिख(irs, &rs, परिमाण(*irs));
		ers = RB_निवेशय(revoked_serial_वृक्षः, rt, irs);
		यदि (ers != रिक्त) {
			KRL_DBG(("bad: ers != NULL"));
			/* Shouldn't happen */
			मुक्त(irs);
			प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
		}
		ers = irs;
	} अन्यथा {
		KRL_DBG(("overlap found %llu:%llu",
		    (अचिह्नित दीर्घ दीर्घ)ers->lo, (अचिह्नित दीर्घ दीर्घ)ers->hi));
		/*
		 * The inserted entry overlaps an existing one. Grow the
		 * existing entry.
		 */
		यदि (ers->lo > lo)
			ers->lo = lo;
		यदि (ers->hi < hi)
			ers->hi = hi;
	}

	/*
	 * The inserted or revised range might overlap or abut adjacent ones;
	 * coalesce as necessary.
	 */

	/* Check predecessors */
	यावत् ((crs = RB_पूर्व(revoked_serial_वृक्षः, rt, ers)) != रिक्त) {
		KRL_DBG(("pred %llu:%llu",
		    (अचिह्नित दीर्घ दीर्घ)crs->lo, (अचिह्नित दीर्घ दीर्घ)crs->hi));
		यदि (ers->lo != 0 && crs->hi < ers->lo - 1)
			भङ्ग;
		/* This entry overlaps. */
		यदि (crs->lo < ers->lo) {
			ers->lo = crs->lo;
			KRL_DBG(("pred extend %llu:%llu",
			    (अचिह्नित दीर्घ दीर्घ)ers->lo,
			    (अचिह्नित दीर्घ दीर्घ)ers->hi));
		}
		RB_REMOVE(revoked_serial_वृक्षः, rt, crs);
		मुक्त(crs);
	}
	/* Check successors */
	यावत् ((crs = RB_अग्र(revoked_serial_वृक्षः, rt, ers)) != रिक्त) {
		KRL_DBG(("succ %llu:%llu",
		    (अचिह्नित दीर्घ दीर्घ)crs->lo, (अचिह्नित दीर्घ दीर्घ)crs->hi));
		यदि (ers->hi != (uint64_t)-1 && crs->lo > ers->hi + 1)
			भङ्ग;
		/* This entry overlaps. */
		यदि (crs->hi > ers->hi) {
			ers->hi = crs->hi;
			KRL_DBG(("succ extend %llu:%llu",
			    (अचिह्नित दीर्घ दीर्घ)ers->lo,
			    (अचिह्नित दीर्घ दीर्घ)ers->hi));
		}
		RB_REMOVE(revoked_serial_वृक्षः, rt, crs);
		मुक्त(crs);
	}
	KRL_DBG(("done, final %llu:%llu",
	    (अचिह्नित दीर्घ दीर्घ)ers->lo, (अचिह्नित दीर्घ दीर्घ)ers->hi));
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

	यदि (lo > hi || lo == 0)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	यदि ((r = revoked_certs_for_ca_कुञ्चिका(krl, ca_कुञ्चिका, &rc, 1)) != 0)
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

	यदि ((r = revoked_certs_for_ca_कुञ्चिका(krl, ca_कुञ्चिका, &rc, 1)) != 0)
		प्रत्यागम r;

	KRL_DBG(("revoke %s", कुञ्चिका_id));
	यदि ((rki = शून्यस्मृतिं_देहि(1, परिमाण(*rki))) == रिक्त ||
	    (rki->कुञ्चिका_id = strdup(कुञ्चिका_id)) == रिक्त) {
		मुक्त(rki);
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	}
	erki = RB_निवेशय(revoked_कुञ्चिका_id_वृक्षः, &rc->revoked_कुञ्चिका_ids, rki);
	यदि (erki != रिक्त) {
		मुक्त(rki->कुञ्चिका_id);
		मुक्त(rki);
	}
	प्रत्यागम 0;
}

/* Convert "key" to a public key blob without any certificate information */
स्थिर पूर्णाङ्क
plain_कुञ्चिका_blob(ध्रुव संरचना sshkey *कुञ्चिका, u_char **blob, आकार_t *blen)
{
	संरचना sshkey *kcopy;
	पूर्णाङ्क r;

	यदि ((r = sshkey_from_वैयक्तिकम्(कुञ्चिका, &kcopy)) != 0)
		प्रत्यागम r;
	यदि (sshkey_is_cert(kcopy)) {
		यदि ((r = sshkey_drop_cert(kcopy)) != 0) {
			sshkey_free(kcopy);
			प्रत्यागम r;
		}
	}
	r = sshkey_गन्तव्यम्_blob(kcopy, blob, blen);
	sshkey_free(kcopy);
	प्रत्यागम r;
}

/* Revoke a key blob. Ownership of blob is transferred to the tree */
स्थिर पूर्णाङ्क
revoke_blob(संरचना revoked_blob_वृक्षः *rbt, u_char *blob, आकार_t len)
{
	संरचना revoked_blob *rb, *erb;

	यदि ((rb = शून्यस्मृतिं_देहि(1, परिमाण(*rb))) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	rb->blob = blob;
	rb->len = len;
	erb = RB_निवेशय(revoked_blob_वृक्षः, rbt, rb);
	यदि (erb != रिक्त) {
		मुक्त(rb->blob);
		मुक्त(rb);
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_krl_revoke_कुञ्चिका_explicit(संरचना ssh_krl *krl, ध्रुव संरचना sshkey *कुञ्चिका)
{
	u_char *blob;
	आकार_t len;
	पूर्णाङ्क r;

	debug3_f("revoke type %s", sshkey_type(कुञ्चिका));
	यदि ((r = plain_कुञ्चिका_blob(कुञ्चिका, &blob, &len)) != 0)
		प्रत्यागम r;
	प्रत्यागम revoke_blob(&krl->revoked_कुञ्चिकाः, blob, len);
}

स्थिर पूर्णाङ्क
revoke_by_hash(संरचना revoked_blob_वृक्षः *target, ध्रुव u_char *p, आकार_t len)
{
	u_char *blob;
	पूर्णाङ्क r;

	/* need to copy hash, as revoke_blob steals ownership */
	यदि ((blob = स्मृतिं_देहि(len)) == रिक्त)
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	स्मृतिं_प्रतिलिख(blob, p, len);
	यदि ((r = revoke_blob(target, blob, len)) != 0) {
		मुक्त(blob);
		प्रत्यागम r;
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_krl_revoke_कुञ्चिका_sha1(संरचना ssh_krl *krl, ध्रुव u_char *p, आकार_t len)
{
	debug3_f("revoke by sha1");
	यदि (len != 20)
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	प्रत्यागम revoke_by_hash(&krl->revoked_sha1s, p, len);
}

पूर्णाङ्क
ssh_krl_revoke_कुञ्चिका_sha256(संरचना ssh_krl *krl, ध्रुव u_char *p, आकार_t len)
{
	debug3_f("revoke by sha256");
	यदि (len != 32)
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	प्रत्यागम revoke_by_hash(&krl->revoked_sha256s, p, len);
}

पूर्णाङ्क
ssh_krl_revoke_कुञ्चिका(संरचना ssh_krl *krl, ध्रुव संरचना sshkey *कुञ्चिका)
{
	/* XXX replace with SHA256? */
	यदि (!sshkey_is_cert(कुञ्चिका))
		प्रत्यागम ssh_krl_revoke_कुञ्चिका_explicit(krl, कुञ्चिका);

	यदि (कुञ्चिका->cert->serial == 0) {
		प्रत्यागम ssh_krl_revoke_cert_by_कुञ्चिका_id(krl,
		    कुञ्चिका->cert->signature_कुञ्चिका,
		    कुञ्चिका->cert->कुञ्चिका_id);
	} अन्यथा {
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
वृणु_अग्र_state(पूर्णाङ्क current_state, uint64_t contig, पूर्णाङ्क final,
    uint64_t चरमः_gap, uint64_t अग्र_gap, आकार_t bitmap_len,
    पूर्णाङ्क *force_new_section)
{
	पूर्णाङ्क new_state;
	uint64_t cost, cost_list, cost_range, cost_bitmap, cost_bitmap_restart;

	/*
	 * Avoid unsigned overflows.
	 * The limits are high enough to avoid confusing the calculations.
	 */
	contig = MINIMUM(contig, 1ULL<<31);
	चरमः_gap = MINIMUM(चरमः_gap, 1ULL<<31);
	अग्र_gap = MINIMUM(अग्र_gap, 1ULL<<31);

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
	cost_bitmap += चरमः_gap + contig + (final ? 0 : MINIMUM(अग्र_gap, 8+64));
	cost_bitmap_restart += contig + (final ? 0 : MINIMUM(अग्र_gap, 8+64));

	/* Convert to byte costs for actual comparison */
	cost_list = (cost_list + 7) / 8;
	cost_bitmap = (cost_bitmap + 7) / 8;
	cost_bitmap_restart = (cost_bitmap_restart + 7) / 8;
	cost_range = (cost_range + 7) / 8;

	/* Ensure that we never emit a bitmap larger than sshbuf can handle */
	यदि (bitmap_len + cost_bitmap >= SSHBUF_MAX_BIGNUM) {
		KRL_DBG(("bitmap overfull len=%zu cost=%llu max=%u",
		    bitmap_len, (अचिह्नित दीर्घ दीर्घ)cost_bitmap,
		    SSHBUF_MAX_BIGNUM));
		cost_bitmap = (uint64_t)-1;
	}

	/* Now pick the best choice */
	*force_new_section = 0;
	new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
	cost = cost_bitmap;
	यदि (cost_range < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_RANGE;
		cost = cost_range;
	}
	यदि (cost_list < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_LIST;
		cost = cost_list;
	}
	यदि (cost_bitmap_restart < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
		*force_new_section = 1;
		cost = cost_bitmap_restart;
	}
	KRL_DBG(("contig %llu last_gap %llu next_gap %llu final %d, costs:"
	    "list %llu range %llu bitmap %llu new bitmap %llu, "
	    "selected 0x%02x%s", (दीर्घ दीर्घ अचिह्नित)contig,
	    (दीर्घ दीर्घ अचिह्नित)चरमः_gap, (दीर्घ दीर्घ अचिह्नित)अग्र_gap, final,
	    (दीर्घ दीर्घ अचिह्नित)cost_list, (दीर्घ दीर्घ अचिह्नित)cost_range,
	    (दीर्घ दीर्घ अचिह्नित)cost_bitmap,
	    (दीर्घ दीर्घ अचिह्नित)cost_bitmap_restart, new_state,
	    *force_new_section ? " restart" : ""));
	प्रत्यागम new_state;
}

स्थिर पूर्णाङ्क
put_bitmap(संरचना sshbuf *buf, संरचना bitmap *bitmap)
{
	आकार_t len;
	u_char *blob;
	पूर्णाङ्क r;

	len = bitmap_nbytes(bitmap);
	यदि ((blob = स्मृतिं_देहि(len)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि (bitmap_गन्तव्यम्_string(bitmap, blob, len) != 0) {
		मुक्त(blob);
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	}
	r = sshbuf_put_bignum2_अष्टकानि(buf, blob, len);
	मुक्त(blob);
	प्रत्यागम r;
}

/* Generate a KRL_SECTION_CERTIFICATES KRL section */
स्थिर पूर्णाङ्क
revoked_certs_generate(संरचना revoked_certs *rc, संरचना sshbuf *buf)
{
	पूर्णाङ्क final, force_new_sect, r = SSH_ERR_आन्तरिकम्_ERROR;
	uint64_t i, contig, gap, चरमः = 0, bitmap_start = 0;
	संरचना revoked_serial *rs, *nrs;
	संरचना revoked_कुञ्चिका_id *rki;
	पूर्णाङ्क अग्र_state, state = 0;
	आकार_t bitmap_len;
	संरचना sshbuf *sect;
	संरचना bitmap *bitmap = रिक्त;

	यदि ((sect = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;

	/* Store the header: optional CA scope key, reserved */
	यदि (rc->ca_कुञ्चिका == रिक्त) {
		यदि ((r = sshbuf_put_string(buf, रिक्त, 0)) != 0)
			गच्छ बहिर्गमनम्;
	} अन्यथा {
		यदि ((r = sshkey_puts(rc->ca_कुञ्चिका, buf)) != 0)
			गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_put_string(buf, रिक्त, 0)) != 0)
		गच्छ बहिर्गमनम्;

	/* Store the revoked serials.  */
	प्रति (rs = RB_MIN(revoked_serial_वृक्षः, &rc->revoked_serials);
	     rs != रिक्त;
	     rs = RB_अग्र(revoked_serial_वृक्षः, &rc->revoked_serials, rs)) {
		KRL_DBG(("serial %llu:%llu state 0x%02x",
		    (दीर्घ दीर्घ अचिह्नित)rs->lo, (दीर्घ दीर्घ अचिह्नित)rs->hi,
		    state));

		/* Check contiguous length and gap to next section (if any) */
		nrs = RB_अग्र(revoked_serial_वृक्षः, &rc->revoked_serials, rs);
		final = nrs == रिक्त;
		gap = nrs == रिक्त ? 0 : nrs->lo - rs->hi;
		contig = 1 + (rs->hi - rs->lo);

		bitmap_len = state == KRL_SECTION_CERT_SERIAL_BITMAP ?
		    bitmap_nbytes(bitmap) : 0;

		/* Choose next state based on these */
		अग्र_state = वृणु_अग्र_state(state, contig, final,
		    state == 0 ? 0 : rs->lo - चरमः, gap, bitmap_len,
		    &force_new_sect);

		/*
		 * If the current section is a range section or has a different
		 * type to the next section, then finish it off now.
		 */
		यदि (state != 0 && (force_new_sect || अग्र_state != state ||
		    state == KRL_SECTION_CERT_SERIAL_RANGE)) {
			KRL_DBG(("finish state 0x%02x", state));
			विकल्प (state) {
			पक्ष KRL_SECTION_CERT_SERIAL_LIST:
			पक्ष KRL_SECTION_CERT_SERIAL_RANGE:
				भङ्ग;
			पक्ष KRL_SECTION_CERT_SERIAL_BITMAP:
				यदि ((r = put_bitmap(sect, bitmap)) != 0)
					गच्छ बहिर्गमनम्;
				bitmap_free(bitmap);
				bitmap = रिक्त;
				भङ्ग;
			}
			यदि ((r = sshbuf_put_u8(buf, state)) != 0 ||
			    (r = sshbuf_put_stringb(buf, sect)) != 0)
				गच्छ बहिर्गमनम्;
			sshbuf_reset(sect);
		}

		/* If we are starting a new section then prepare it now */
		यदि (अग्र_state != state || force_new_sect) {
			KRL_DBG(("start state 0x%02x",
			    अग्र_state));
			state = अग्र_state;
			sshbuf_reset(sect);
			विकल्प (state) {
			पक्ष KRL_SECTION_CERT_SERIAL_LIST:
			पक्ष KRL_SECTION_CERT_SERIAL_RANGE:
				भङ्ग;
			पक्ष KRL_SECTION_CERT_SERIAL_BITMAP:
				यदि ((bitmap = bitmap_new()) == रिक्त) {
					r = SSH_ERR_ALLOC_FAIL;
					गच्छ बहिर्गमनम्;
				}
				bitmap_start = rs->lo;
				यदि ((r = sshbuf_put_u64(sect,
				    bitmap_start)) != 0)
					गच्छ बहिर्गमनम्;
				भङ्ग;
			}
		}

		/* Perform section-specific processing */
		विकल्प (state) {
		पक्ष KRL_SECTION_CERT_SERIAL_LIST:
			प्रति (i = 0; i < contig; i++) {
				यदि ((r = sshbuf_put_u64(sect, rs->lo + i)) != 0)
					गच्छ बहिर्गमनम्;
			}
			भङ्ग;
		पक्ष KRL_SECTION_CERT_SERIAL_RANGE:
			यदि ((r = sshbuf_put_u64(sect, rs->lo)) != 0 ||
			    (r = sshbuf_put_u64(sect, rs->hi)) != 0)
				गच्छ बहिर्गमनम्;
			भङ्ग;
		पक्ष KRL_SECTION_CERT_SERIAL_BITMAP:
			यदि (rs->lo - bitmap_start > अधिकतम_पूर्णाङ्कः) {
				r = SSH_ERR_INVALID_FORMAT;
				error_f("insane bitmap gap");
				गच्छ बहिर्गमनम्;
			}
			प्रति (i = 0; i < contig; i++) {
				यदि (bitmap_समुच्चयः_bit(bitmap,
				    rs->lo + i - bitmap_start) != 0) {
					r = SSH_ERR_ALLOC_FAIL;
					गच्छ बहिर्गमनम्;
				}
			}
			भङ्ग;
		}
		चरमः = rs->hi;
	}
	/* Flush the remaining section, if any */
	यदि (state != 0) {
		KRL_DBG(("serial final flush for state 0x%02x", state));
		विकल्प (state) {
		पक्ष KRL_SECTION_CERT_SERIAL_LIST:
		पक्ष KRL_SECTION_CERT_SERIAL_RANGE:
			भङ्ग;
		पक्ष KRL_SECTION_CERT_SERIAL_BITMAP:
			यदि ((r = put_bitmap(sect, bitmap)) != 0)
				गच्छ बहिर्गमनम्;
			bitmap_free(bitmap);
			bitmap = रिक्त;
			भङ्ग;
		}
		यदि ((r = sshbuf_put_u8(buf, state)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			गच्छ बहिर्गमनम्;
	}
	KRL_DBG(("serial done "));

	/* Now output a section for any revocations by key ID */
	sshbuf_reset(sect);
	RB_FOREACH(rki, revoked_कुञ्चिका_id_वृक्षः, &rc->revoked_कुञ्चिका_ids) {
		KRL_DBG(("key ID %s", rki->कुञ्चिका_id));
		यदि ((r = sshbuf_put_cstring(sect, rki->कुञ्चिका_id)) != 0)
			गच्छ बहिर्गमनम्;
	}
	यदि (sshbuf_len(sect) != 0) {
		यदि ((r = sshbuf_put_u8(buf, KRL_SECTION_CERT_कुञ्चिका_ID)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			गच्छ बहिर्गमनम्;
	}
	r = 0;
 बहिर्गमनम्:
	bitmap_free(bitmap);
	sshbuf_free(sect);
	प्रत्यागम r;
}

पूर्णाङ्क
ssh_krl_गन्तव्यम्_blob(संरचना ssh_krl *krl, संरचना sshbuf *buf)
{
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;
	संरचना revoked_certs *rc;
	संरचना revoked_blob *rb;
	संरचना sshbuf *sect;
	u_char *sblob = रिक्त;

	यदि (krl->generated_date == 0)
		krl->generated_date = time(रिक्त);

	यदि ((sect = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;

	/* Store the header */
	यदि ((r = sshbuf_put(buf, KRL_MAGIC, परिमाण(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_put_u32(buf, KRL_FORMAT_संस्करणम्)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->krl_संस्करणम्)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->generated_date)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->flags)) != 0 ||
	    (r = sshbuf_put_string(buf, रिक्त, 0)) != 0 ||
	    (r = sshbuf_put_cstring(buf, krl->comment)) != 0)
		गच्छ बहिर्गमनम्;

	/* Store sections for revoked certificates */
	TAILQ_FOREACH(rc, &krl->revoked_certs, प्रविष्टिः) {
		sshbuf_reset(sect);
		यदि ((r = revoked_certs_generate(rc, sect)) != 0)
			गच्छ बहिर्गमनम्;
		यदि ((r = sshbuf_put_u8(buf, KRL_SECTION_CERTIFICATES)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			गच्छ बहिर्गमनम्;
	}

	/* Finally, output sections for revocations by public key/hash */
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_वृक्षः, &krl->revoked_कुञ्चिकाः) {
		KRL_DBG(("key len %zu ", rb->len));
		यदि ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			गच्छ बहिर्गमनम्;
	}
	यदि (sshbuf_len(sect) != 0) {
		यदि ((r = sshbuf_put_u8(buf, KRL_SECTION_EXPLICIT_कुञ्चिका)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			गच्छ बहिर्गमनम्;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_वृक्षः, &krl->revoked_sha1s) {
		KRL_DBG(("hash len %zu ", rb->len));
		यदि ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			गच्छ बहिर्गमनम्;
	}
	यदि (sshbuf_len(sect) != 0) {
		यदि ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA1)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			गच्छ बहिर्गमनम्;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_वृक्षः, &krl->revoked_sha256s) {
		KRL_DBG(("hash len %zu ", rb->len));
		यदि ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			गच्छ बहिर्गमनम्;
	}
	यदि (sshbuf_len(sect) != 0) {
		यदि ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA256)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			गच्छ बहिर्गमनम्;
	}
	/* success */
	r = 0;
 बहिर्गमनम्:
	मुक्त(sblob);
	sshbuf_free(sect);
	प्रत्यागम r;
}

स्थिर शून्य
format_timestamp(uint64_t timestamp, वर्ण *ts, आकार_t nts)
{
	time_t t;
	संरचना tm *tm;

	t = timestamp;
	tm = localtime(&t);
	यदि (tm == रिक्त)
		strlcpy(ts, "<INVALID>", nts);
	अन्यथा {
		*ts = '\0';
		strftime(ts, nts, "%Y%m%dT%H%M%S", tm);
	}
}

स्थिर पूर्णाङ्क
cert_extension_subsection(संरचना sshbuf *subsect, संरचना ssh_krl *krl)
{
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;
	u_char critical = 1;
	संरचना sshbuf *मानम् = रिक्त;
	वर्ण *name = रिक्त;

	यदि ((r = sshbuf_get_cstring(subsect, &name, रिक्त)) != 0 ||
	    (r = sshbuf_get_u8(subsect, &critical)) != 0 ||
	    (r = sshbuf_froms(subsect, &मानम्)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid certificate extension subsection");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि (sshbuf_len(subsect) != 0) {
		error("KRL has invalid certificate extension subsection: "
		    "trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	debug_f("cert extension %s critical %u len %zu",
	    name, critical, sshbuf_len(मानम्));
	/* no extensions are currently supported */
	यदि (critical) {
		error("KRL contains unsupported critical certificate "
		    "subsection \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		गच्छ बहिर्गमनम्;
	}
	/* success */
	r = 0;
 बहिर्गमनम्:
	मुक्त(name);
	sshbuf_free(मानम्);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
parse_revoked_certs(संरचना sshbuf *buf, संरचना ssh_krl *krl)
{
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;
	u_char type;
	ध्रुव u_char *blob;
	आकार_t blen, nbits;
	संरचना sshbuf *subsect = रिक्त;
	uint64_t serial, serial_lo, serial_hi;
	संरचना bitmap *bitmap = रिक्त;
	वर्ण *कुञ्चिका_id = रिक्त;
	संरचना sshkey *ca_कुञ्चिका = रिक्त;

	यदि ((subsect = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;

	/* Header: key, reserved */
	यदि ((r = sshbuf_get_string_प्रत्यक्षम्(buf, &blob, &blen)) != 0 ||
	    (r = sshbuf_skip_string(buf)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (blen != 0 && (r = sshkey_from_blob(blob, blen, &ca_कुञ्चिका)) != 0)
		गच्छ बहिर्गमनम्;

	यावत् (sshbuf_len(buf) > 0) {
		sshbuf_free(subsect);
		subsect = रिक्त;
		यदि ((r = sshbuf_get_u8(buf, &type)) != 0 ||
		    (r = sshbuf_froms(buf, &subsect)) != 0)
			गच्छ बहिर्गमनम्;
		KRL_DBG(("subsection type 0x%02x", type));
		/* sshbuf_dump(subsect, stderr); */

		विकल्प (type) {
		पक्ष KRL_SECTION_CERT_SERIAL_LIST:
			यावत् (sshbuf_len(subsect) > 0) {
				यदि ((r = sshbuf_get_u64(subsect, &serial)) != 0)
					गच्छ बहिर्गमनम्;
				यदि ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_कुञ्चिका, serial)) != 0)
					गच्छ बहिर्गमनम्;
			}
			भङ्ग;
		पक्ष KRL_SECTION_CERT_SERIAL_RANGE:
			यदि ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_u64(subsect, &serial_hi)) != 0)
				गच्छ बहिर्गमनम्;
			यदि ((r = ssh_krl_revoke_cert_by_serial_range(krl,
			    ca_कुञ्चिका, serial_lo, serial_hi)) != 0)
				गच्छ बहिर्गमनम्;
			भङ्ग;
		पक्ष KRL_SECTION_CERT_SERIAL_BITMAP:
			यदि ((bitmap = bitmap_new()) == रिक्त) {
				r = SSH_ERR_ALLOC_FAIL;
				गच्छ बहिर्गमनम्;
			}
			यदि ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_bignum2_अष्टकानि_प्रत्यक्षम्(subsect,
			    &blob, &blen)) != 0)
				गच्छ बहिर्गमनम्;
			यदि (bitmap_from_string(bitmap, blob, blen) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				गच्छ बहिर्गमनम्;
			}
			nbits = bitmap_nbits(bitmap);
			प्रति (serial = 0; serial < (uint64_t)nbits; serial++) {
				यदि (serial > 0 && serial_lo + serial == 0) {
					error_f("bitmap wraps u64");
					r = SSH_ERR_INVALID_FORMAT;
					गच्छ बहिर्गमनम्;
				}
				यदि (!bitmap_test_bit(bitmap, serial))
					अनुवर्त;
				यदि ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_कुञ्चिका, serial_lo + serial)) != 0)
					गच्छ बहिर्गमनम्;
			}
			bitmap_free(bitmap);
			bitmap = रिक्त;
			भङ्ग;
		पक्ष KRL_SECTION_CERT_कुञ्चिका_ID:
			यावत् (sshbuf_len(subsect) > 0) {
				यदि ((r = sshbuf_get_cstring(subsect,
				    &कुञ्चिका_id, रिक्त)) != 0)
					गच्छ बहिर्गमनम्;
				यदि ((r = ssh_krl_revoke_cert_by_कुञ्चिका_id(krl,
				    ca_कुञ्चिका, कुञ्चिका_id)) != 0)
					गच्छ बहिर्गमनम्;
				मुक्त(कुञ्चिका_id);
				कुञ्चिका_id = रिक्त;
			}
			भङ्ग;
		पक्ष KRL_SECTION_CERT_EXTENSION:
			यदि ((r = cert_extension_subsection(subsect, krl)) != 0)
				गच्छ बहिर्गमनम्;
			भङ्ग;
		स्वभाव:
			error("Unsupported KRL certificate section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ बहिर्गमनम्;
		}
		यदि (sshbuf_len(subsect) > 0) {
			error("KRL certificate section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ बहिर्गमनम्;
		}
	}

	r = 0;
 बहिर्गमनम्:
	यदि (bitmap != रिक्त)
		bitmap_free(bitmap);
	मुक्त(कुञ्चिका_id);
	sshkey_free(ca_कुञ्चिका);
	sshbuf_free(subsect);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
blob_section(संरचना sshbuf *sect, संरचना revoked_blob_वृक्षः *target_वृक्षः,
    आकार_t expected_len)
{
	u_char *rdata = रिक्त;
	आकार_t rlen = 0;
	पूर्णाङ्क r;

	यावत् (sshbuf_len(sect) > 0) {
		यदि ((r = sshbuf_get_string(sect, &rdata, &rlen)) != 0)
			प्रत्यागम r;
		यदि (expected_len != 0 && rlen != expected_len) {
			error_f("bad length");
			मुक्त(rdata);
			प्रत्यागम SSH_ERR_INVALID_FORMAT;
		}
		यदि ((r = revoke_blob(target_वृक्षः, rdata, rlen)) != 0) {
			मुक्त(rdata);
			प्रत्यागम r;
		}
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
extension_section(संरचना sshbuf *sect, संरचना ssh_krl *krl)
{
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;
	u_char critical = 1;
	संरचना sshbuf *मानम् = रिक्त;
	वर्ण *name = रिक्त;

	यदि ((r = sshbuf_get_cstring(sect, &name, रिक्त)) != 0 ||
	    (r = sshbuf_get_u8(sect, &critical)) != 0 ||
	    (r = sshbuf_froms(sect, &मानम्)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid extension section");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि (sshbuf_len(sect) != 0) {
		error("KRL has invalid extension section: trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	debug_f("extension %s critical %u len %zu",
	    name, critical, sshbuf_len(मानम्));
	/* no extensions are currently supported */
	यदि (critical) {
		error("KRL contains unsupported critical section \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		गच्छ बहिर्गमनम्;
	}
	/* success */
	r = 0;
 बहिर्गमनम्:
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
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;
	u_char type;
	u_int format_संस्करणम्;

	*krlp = रिक्त;

	/* KRL must begin with magic string */
	यदि ((r = sshbuf_cmp(buf, 0, KRL_MAGIC, परिमाण(KRL_MAGIC) - 1)) != 0) {
		debug2_f("bad KRL magic header");
		प्रत्यागम SSH_ERR_KRL_BAD_MAGIC;
	}

	यदि ((krl = ssh_krl_init()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		error_f("alloc failed");
		गच्छ बहिर्गमनम्;
	}
	/* Don't modify buffer */
	यदि ((copy = sshbuf_fromb(buf)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_consume(copy, परिमाण(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_get_u32(copy, &format_संस्करणम्)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (format_संस्करणम् != KRL_FORMAT_संस्करणम्) {
		error_f("unsupported KRL format version %u", format_संस्करणम्);
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_get_u64(copy, &krl->krl_संस्करणम्)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->generated_date)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->flags)) != 0 ||
	    (r = sshbuf_skip_string(copy)) != 0 ||
	    (r = sshbuf_get_cstring(copy, &krl->comment, रिक्त)) != 0) {
		error_fr(r, "parse KRL header");
		गच्छ बहिर्गमनम्;
	}
	format_timestamp(krl->generated_date, timestamp, परिमाण(timestamp));
	debug("KRL version %llu generated at %s%s%s",
	    (दीर्घ दीर्घ अचिह्नित)krl->krl_संस्करणम्, timestamp,
	    *krl->comment ? ": " : "", krl->comment);

	/* Parse and load the KRL sections. */
	यावत् (sshbuf_len(copy) > 0) {
		sshbuf_free(sect);
		sect = रिक्त;
		यदि ((r = sshbuf_get_u8(copy, &type)) != 0 ||
		    (r = sshbuf_froms(copy, &sect)) != 0)
			गच्छ बहिर्गमनम्;
		KRL_DBG(("section 0x%02x", type));

		विकल्प (type) {
		पक्ष KRL_SECTION_CERTIFICATES:
			यदि ((r = parse_revoked_certs(sect, krl)) != 0)
				गच्छ बहिर्गमनम्;
			भङ्ग;
		पक्ष KRL_SECTION_EXPLICIT_कुञ्चिका:
			यदि ((r = blob_section(sect,
			    &krl->revoked_कुञ्चिकाः, 0)) != 0)
				गच्छ बहिर्गमनम्;
			भङ्ग;
		पक्ष KRL_SECTION_FINGERPRINT_SHA1:
			यदि ((r = blob_section(sect,
			    &krl->revoked_sha1s, 20)) != 0)
				गच्छ बहिर्गमनम्;
			भङ्ग;
		पक्ष KRL_SECTION_FINGERPRINT_SHA256:
			यदि ((r = blob_section(sect,
			    &krl->revoked_sha256s, 32)) != 0)
				गच्छ बहिर्गमनम्;
			भङ्ग;
		पक्ष KRL_SECTION_EXTENSION:
			यदि ((r = extension_section(sect, krl)) != 0)
				गच्छ बहिर्गमनम्;
			भङ्ग;
		पक्ष KRL_SECTION_SIGNATURE:
			/* Handled above, but still need to stay in synch */
			sshbuf_free(sect);
			sect = रिक्त;
			यदि ((r = sshbuf_skip_string(copy)) != 0)
				गच्छ बहिर्गमनम्;
			भङ्ग;
		स्वभाव:
			error("Unsupported KRL section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ बहिर्गमनम्;
		}
		यदि (sect != रिक्त && sshbuf_len(sect) > 0) {
			error("KRL section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ बहिर्गमनम्;
		}
	}

	/* Success */
	*krlp = krl;
	r = 0;
 बहिर्गमनम्:
	यदि (r != 0)
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
	स्मृतिं_पूरय(&rki, 0, परिमाण(rki));
	rki.कुञ्चिका_id = कुञ्चिका->cert->कुञ्चिका_id;
	erki = RB_FIND(revoked_कुञ्चिका_id_वृक्षः, &rc->revoked_कुञ्चिका_ids, &rki);
	यदि (erki != रिक्त) {
		KRL_DBG(("revoked by key ID"));
		प्रत्यागम SSH_ERR_कुञ्चिका_REVOKED;
	}

	/*
	 * Zero serials numbers are ignored (it's the default when the
	 * CA doesn't specify one).
	 */
	यदि (कुञ्चिका->cert->serial == 0)
		प्रत्यागम 0;

	स्मृतिं_पूरय(&rs, 0, परिमाण(rs));
	rs.lo = rs.hi = कुञ्चिका->cert->serial;
	ers = RB_FIND(revoked_serial_वृक्षः, &rc->revoked_serials, &rs);
	यदि (ers != रिक्त) {
		KRL_DBG(("revoked serial %llu matched %llu:%llu",
		    (अचिह्नित दीर्घ दीर्घ)कुञ्चिका->cert->serial,
		    (अचिह्नित दीर्घ दीर्घ)ers->lo,
		    (अचिह्नित दीर्घ दीर्घ)ers->hi));
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
	स्मृतिं_पूरय(&rb, 0, परिमाण(rb));
	यदि ((r = sshkey_fingerprint_raw(कुञ्चिका, SSH_DIGEST_SHA1,
	    &rb.blob, &rb.len)) != 0)
		प्रत्यागम r;
	erb = RB_FIND(revoked_blob_वृक्षः, &krl->revoked_sha1s, &rb);
	मुक्त(rb.blob);
	यदि (erb != रिक्त) {
		KRL_DBG(("revoked by key SHA1"));
		प्रत्यागम SSH_ERR_कुञ्चिका_REVOKED;
	}
	स्मृतिं_पूरय(&rb, 0, परिमाण(rb));
	यदि ((r = sshkey_fingerprint_raw(कुञ्चिका, SSH_DIGEST_SHA256,
	    &rb.blob, &rb.len)) != 0)
		प्रत्यागम r;
	erb = RB_FIND(revoked_blob_वृक्षः, &krl->revoked_sha256s, &rb);
	मुक्त(rb.blob);
	यदि (erb != रिक्त) {
		KRL_DBG(("revoked by key SHA256"));
		प्रत्यागम SSH_ERR_कुञ्चिका_REVOKED;
	}

	/* Next, explicit keys */
	स्मृतिं_पूरय(&rb, 0, परिमाण(rb));
	यदि ((r = plain_कुञ्चिका_blob(कुञ्चिका, &rb.blob, &rb.len)) != 0)
		प्रत्यागम r;
	erb = RB_FIND(revoked_blob_वृक्षः, &krl->revoked_कुञ्चिकाः, &rb);
	मुक्त(rb.blob);
	यदि (erb != रिक्त) {
		KRL_DBG(("revoked by explicit key"));
		प्रत्यागम SSH_ERR_कुञ्चिका_REVOKED;
	}

	यदि (!sshkey_is_cert(कुञ्चिका))
		प्रत्यागम 0;

	/* Check cert revocation for the specified CA */
	यदि ((r = revoked_certs_for_ca_कुञ्चिका(krl, कुञ्चिका->cert->signature_कुञ्चिका,
	    &rc, 0)) != 0)
		प्रत्यागम r;
	यदि (rc != रिक्त) {
		यदि ((r = is_cert_revoked(कुञ्चिका, rc)) != 0)
			प्रत्यागम r;
	}
	/* Check cert revocation for the wildcard CA */
	यदि ((r = revoked_certs_for_ca_कुञ्चिका(krl, रिक्त, &rc, 0)) != 0)
		प्रत्यागम r;
	यदि (rc != रिक्त) {
		यदि ((r = is_cert_revoked(कुञ्चिका, rc)) != 0)
			प्रत्यागम r;
	}

	KRL_DBG(("%llu no match", (अचिह्नित दीर्घ दीर्घ)कुञ्चिका->cert->serial));
	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_krl_check_कुञ्चिका(संरचना ssh_krl *krl, ध्रुव संरचना sshkey *कुञ्चिका)
{
	पूर्णाङ्क r;

	KRL_DBG(("checking key"));
	यदि ((r = is_कुञ्चिका_revoked(krl, कुञ्चिका)) != 0)
		प्रत्यागम r;
	यदि (sshkey_is_cert(कुञ्चिका)) {
		debug2_f("checking CA key");
		यदि ((r = is_कुञ्चिका_revoked(krl, कुञ्चिका->cert->signature_कुञ्चिका)) != 0)
			प्रत्यागम r;
	}
	KRL_DBG(("key okay"));
	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_krl_file_अन्तर्भवति_कुञ्चिका(ध्रुव वर्ण *मार्गः, ध्रुव संरचना sshkey *कुञ्चिका)
{
	संरचना sshbuf *krlbuf = रिक्त;
	संरचना ssh_krl *krl = रिक्त;
	पूर्णाङ्क oerrno = 0, r;

	यदि (मार्गः == रिक्त)
		प्रत्यागम 0;
	यदि ((r = sshbuf_आरोपय_file(मार्गः, &krlbuf)) != 0) {
		oerrno = errno;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = ssh_krl_from_blob(krlbuf, &krl)) != 0)
		गच्छ बहिर्गमनम्;
	debug2_f("checking KRL %s", मार्गः);
	r = ssh_krl_check_कुञ्चिका(krl, कुञ्चिका);
 बहिर्गमनम्:
	sshbuf_free(krlbuf);
	ssh_krl_free(krl);
	यदि (r != 0)
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
	fprintf(f, "# KRL version %llu\n", (अचिह्नित दीर्घ दीर्घ)krl->krl_संस्करणम्);
	fprintf(f, "# Generated at %s\n", timestamp);
	यदि (krl->comment != रिक्त && *krl->comment != '\0') {
		r = अधिकतम_पूर्णाङ्कः;
		asmprintf(&fp, अधिकतम_पूर्णाङ्कः, &r, "%s", krl->comment);
		fprintf(f, "# Comment: %s\n", fp);
		मुक्त(fp);
	}
	fputc('\n', f);

	RB_FOREACH(rb, revoked_blob_वृक्षः, &krl->revoked_कुञ्चिकाः) {
		यदि ((r = sshkey_from_blob(rb->blob, rb->len, &कुञ्चिका)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			error_r(r, "parse KRL key");
			अनुवर्त;
		}
		यदि ((fp = sshkey_fingerprint(कुञ्चिका, SSH_FP_HASH_DEFAULT,
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

	TAILQ_FOREACH(rc, &krl->revoked_certs, प्रविष्टिः) {
		fputc('\n', f);
		यदि (rc->ca_कुञ्चिका == रिक्त)
			fprintf(f, "# Wildcard CA\n");
		अन्यथा {
			यदि ((fp = sshkey_fingerprint(rc->ca_कुञ्चिका,
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
			यदि (rs->lo == rs->hi) {
				fprintf(f, "serial: %llu\n",
				    (अचिह्नित दीर्घ दीर्घ)rs->lo);
			} अन्यथा {
				fprintf(f, "serial: %llu-%llu\n",
				    (अचिह्नित दीर्घ दीर्घ)rs->lo,
				    (अचिह्नित दीर्घ दीर्घ)rs->hi);
			}
		}
		RB_FOREACH(rki, revoked_कुञ्चिका_id_वृक्षः, &rc->revoked_कुञ्चिका_ids) {
			/*
			 * We don't want key IDs with embedded newlines to
			 * mess up the display.
			 */
			r = अधिकतम_पूर्णाङ्कः;
			asmprintf(&fp, अधिकतम_पूर्णाङ्कः, &r, "%s", rki->कुञ्चिका_id);
			fprintf(f, "id: %s\n", fp);
			मुक्त(fp);
		}
	}
	प्रत्यागम ret;
}
