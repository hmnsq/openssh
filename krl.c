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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/tree.h>
#شامل <sys/queue.h>

#شامل <errno.h>
#شامل <limits.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <time.h>

#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "sshkey.h"
#شامل "misc.h"
#شامل "log.h"
#شامل "digest.h"
#شامل "bitmap.h"
#شامل "utf8.h"

#شامل "krl.h"

/* #define DEBUG_KRL */
#اگر_تعریف_شدہ DEBUG_KRL
# define KRL_DBG(x) debug3_f x
#ورنہ
# define KRL_DBG(x)
#اگر_ختم

/*
 * Trees of revoked serial numbers, key IDs and keys. This allows
 * quick searching, querying and producing lists in canonical order.
 */

/* Tree of serial numbers. XXX make smarter: really need a real sparse bitmap */
ساخت revoked_serial {
	uint64_t lo, hi;
	RB_اندراج(revoked_serial) درخت_اندراج;
};
ساکن صحیح serial_cmp(ساخت revoked_serial *a, ساخت revoked_serial *b);
RB_سر(revoked_serial_درخت, revoked_serial);
RB_GENERATE_STATIC(revoked_serial_درخت, revoked_serial, درخت_اندراج, serial_cmp)

/* Tree of key IDs */
ساخت revoked_کلید_id {
	حرف *کلید_id;
	RB_اندراج(revoked_کلید_id) درخت_اندراج;
};
ساکن صحیح کلید_id_cmp(ساخت revoked_کلید_id *a, ساخت revoked_کلید_id *b);
RB_سر(revoked_کلید_id_درخت, revoked_کلید_id);
RB_GENERATE_STATIC(revoked_کلید_id_درخت, revoked_کلید_id, درخت_اندراج, کلید_id_cmp)

/* Tree of blobs (used for keys and fingerprints) */
ساخت revoked_blob {
	u_char *blob;
	سائز_t len;
	RB_اندراج(revoked_blob) درخت_اندراج;
};
ساکن صحیح blob_cmp(ساخت revoked_blob *a, ساخت revoked_blob *b);
RB_سر(revoked_blob_درخت, revoked_blob);
RB_GENERATE_STATIC(revoked_blob_درخت, revoked_blob, درخت_اندراج, blob_cmp)

/* Tracks revoked certs for a single CA */
ساخت revoked_certs {
	ساخت sshkey *ca_کلید;
	ساخت revoked_serial_درخت revoked_serials;
	ساخت revoked_کلید_id_درخت revoked_کلید_ids;
	TAILQ_ENTRY(revoked_certs) اندراج_2;
};
TAILQ_HEAD(revoked_certs_list, revoked_certs);

ساخت ssh_krl {
	uint64_t krl_نسخہ;
	uint64_t generated_date;
	uint64_t flags;
	حرف *comment;
	ساخت revoked_blob_درخت revoked_کلیدیں;
	ساخت revoked_blob_درخت revoked_sha1s;
	ساخت revoked_blob_درخت revoked_sha256s;
	ساخت revoked_certs_list revoked_certs;
};

/* Return equal if a and b overlap */
ساکن صحیح
serial_cmp(ساخت revoked_serial *a, ساخت revoked_serial *b)
{
	اگر (a->hi >= b->lo && a->lo <= b->hi)
		واپس 0;
	واپس a->lo < b->lo ? -1 : 1;
}

ساکن صحیح
کلید_id_cmp(ساخت revoked_کلید_id *a, ساخت revoked_کلید_id *b)
{
	واپس strcmp(a->کلید_id, b->کلید_id);
}

ساکن صحیح
blob_cmp(ساخت revoked_blob *a, ساخت revoked_blob *b)
{
	صحیح r;

	اگر (a->len != b->len) {
		اگر ((r = memcmp(a->blob, b->blob, MINIMUM(a->len, b->len))) != 0)
			واپس r;
		واپس a->len > b->len ? 1 : -1;
	} ورنہ
		واپس memcmp(a->blob, b->blob, a->len);
}

ساخت ssh_krl *
ssh_krl_init(خالی)
{
	ساخت ssh_krl *krl;

	اگر ((krl = صفر_حافظہ_دو(1, حجم(*krl))) == تہی)
		واپس تہی;
	RB_INIT(&krl->revoked_کلیدیں);
	RB_INIT(&krl->revoked_sha1s);
	RB_INIT(&krl->revoked_sha256s);
	TAILQ_INIT(&krl->revoked_certs);
	واپس krl;
}

ساکن خالی
revoked_certs_free(ساخت revoked_certs *rc)
{
	ساخت revoked_serial *rs, *trs;
	ساخت revoked_کلید_id *rki, *trki;

	اگر (rc == تہی)
		واپس;
	RB_FOREACH_محفوظ(rs, revoked_serial_درخت, &rc->revoked_serials, trs) {
		RB_REMOVE(revoked_serial_درخت, &rc->revoked_serials, rs);
		آزاد(rs);
	}
	RB_FOREACH_محفوظ(rki, revoked_کلید_id_درخت, &rc->revoked_کلید_ids, trki) {
		RB_REMOVE(revoked_کلید_id_درخت, &rc->revoked_کلید_ids, rki);
		آزاد(rki->کلید_id);
		آزاد(rki);
	}
	sshkey_free(rc->ca_کلید);
	freezero(rc, حجم(*rc));
}

خالی
ssh_krl_free(ساخت ssh_krl *krl)
{
	ساخت revoked_blob *rb, *trb;
	ساخت revoked_certs *rc, *trc;

	اگر (krl == تہی)
		واپس;

	آزاد(krl->comment);
	RB_FOREACH_محفوظ(rb, revoked_blob_درخت, &krl->revoked_کلیدیں, trb) {
		RB_REMOVE(revoked_blob_درخت, &krl->revoked_کلیدیں, rb);
		آزاد(rb->blob);
		آزاد(rb);
	}
	RB_FOREACH_محفوظ(rb, revoked_blob_درخت, &krl->revoked_sha1s, trb) {
		RB_REMOVE(revoked_blob_درخت, &krl->revoked_sha1s, rb);
		آزاد(rb->blob);
		آزاد(rb);
	}
	RB_FOREACH_محفوظ(rb, revoked_blob_درخت, &krl->revoked_sha256s, trb) {
		RB_REMOVE(revoked_blob_درخت, &krl->revoked_sha256s, rb);
		آزاد(rb->blob);
		آزاد(rb);
	}
	TAILQ_FOREACH_محفوظ(rc, &krl->revoked_certs, اندراج_2, trc) {
		TAILQ_REMOVE(&krl->revoked_certs, rc, اندراج_2);
		revoked_certs_free(rc);
	}
	آزاد(krl);
}

خالی
ssh_krl_سیٹ_نسخہ(ساخت ssh_krl *krl, uint64_t نسخہ)
{
	krl->krl_نسخہ = نسخہ;
}

صحیح
ssh_krl_سیٹ_comment(ساخت ssh_krl *krl, ثابت حرف *comment)
{
	آزاد(krl->comment);
	اگر ((krl->comment = strdup(comment)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	واپس 0;
}

/*
 * Find the revoked_certs struct for a CA key. If allow_create is set then
 * create a new one in the tree if one did not exist already.
 */
ساکن صحیح
revoked_certs_for_ca_کلید(ساخت ssh_krl *krl, ثابت ساخت sshkey *ca_کلید,
    ساخت revoked_certs **rcp, صحیح allow_create)
{
	ساخت revoked_certs *rc;
	صحیح r;

	*rcp = تہی;
	TAILQ_FOREACH(rc, &krl->revoked_certs, اندراج_2) {
		اگر ((ca_کلید == تہی && rc->ca_کلید == تہی) ||
		    sshkey_equal(rc->ca_کلید, ca_کلید)) {
			*rcp = rc;
			واپس 0;
		}
	}
	اگر (!allow_create)
		واپس 0;
	/* If this CA doesn't exist in the list then add it now */
	اگر ((rc = صفر_حافظہ_دو(1, حجم(*rc))) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر (ca_کلید == تہی)
		rc->ca_کلید = تہی;
	ورنہ اگر ((r = sshkey_from_نجی(ca_کلید, &rc->ca_کلید)) != 0) {
		آزاد(rc);
		واپس r;
	}
	RB_INIT(&rc->revoked_serials);
	RB_INIT(&rc->revoked_کلید_ids);
	TAILQ_INSERT_TAIL(&krl->revoked_certs, rc, اندراج_2);
	KRL_DBG(("new CA %s", ca_کلید == تہی ? "*" : sshkey_type(ca_کلید)));
	*rcp = rc;
	واپس 0;
}

ساکن صحیح
داخل_کرو_serial_range(ساخت revoked_serial_درخت *rt, uint64_t lo, uint64_t hi)
{
	ساخت revoked_serial rs, *ers, *crs, *irs;

	KRL_DBG(("insert %llu:%llu",
	    (غیرعلامتی طویل طویل)lo, (غیرعلامتی طویل طویل)hi));
	memset(&rs, 0, حجم(rs));
	rs.lo = lo;
	rs.hi = hi;
	ers = RB_NFIND(revoked_serial_درخت, rt, &rs);
	اگر (ers == تہی || serial_cmp(ers, &rs) != 0) {
		/* No entry matches. Just insert */
		اگر ((irs = حافظہ_دو(حجم(rs))) == تہی)
			واپس SSH_ERR_ALLOC_FAIL;
		حافظہ_نقل(irs, &rs, حجم(*irs));
		ers = RB_داخل_کرو(revoked_serial_درخت, rt, irs);
		اگر (ers != تہی) {
			KRL_DBG(("bad: ers != NULL"));
			/* Shouldn't happen */
			آزاد(irs);
			واپس SSH_ERR_اندرونی_ERROR;
		}
		ers = irs;
	} ورنہ {
		KRL_DBG(("overlap found %llu:%llu",
		    (غیرعلامتی طویل طویل)ers->lo, (غیرعلامتی طویل طویل)ers->hi));
		/*
		 * The inserted entry overlaps an existing one. Grow the
		 * existing entry.
		 */
		اگر (ers->lo > lo)
			ers->lo = lo;
		اگر (ers->hi < hi)
			ers->hi = hi;
	}

	/*
	 * The inserted or revised range might overlap or abut adjacent ones;
	 * coalesce as necessary.
	 */

	/* Check predecessors */
	جب ((crs = RB_پچھلا(revoked_serial_درخت, rt, ers)) != تہی) {
		KRL_DBG(("pred %llu:%llu",
		    (غیرعلامتی طویل طویل)crs->lo, (غیرعلامتی طویل طویل)crs->hi));
		اگر (ers->lo != 0 && crs->hi < ers->lo - 1)
			توڑو;
		/* This entry overlaps. */
		اگر (crs->lo < ers->lo) {
			ers->lo = crs->lo;
			KRL_DBG(("pred extend %llu:%llu",
			    (غیرعلامتی طویل طویل)ers->lo,
			    (غیرعلامتی طویل طویل)ers->hi));
		}
		RB_REMOVE(revoked_serial_درخت, rt, crs);
		آزاد(crs);
	}
	/* Check successors */
	جب ((crs = RB_اگلا(revoked_serial_درخت, rt, ers)) != تہی) {
		KRL_DBG(("succ %llu:%llu",
		    (غیرعلامتی طویل طویل)crs->lo, (غیرعلامتی طویل طویل)crs->hi));
		اگر (ers->hi != (uint64_t)-1 && crs->lo > ers->hi + 1)
			توڑو;
		/* This entry overlaps. */
		اگر (crs->hi > ers->hi) {
			ers->hi = crs->hi;
			KRL_DBG(("succ extend %llu:%llu",
			    (غیرعلامتی طویل طویل)ers->lo,
			    (غیرعلامتی طویل طویل)ers->hi));
		}
		RB_REMOVE(revoked_serial_درخت, rt, crs);
		آزاد(crs);
	}
	KRL_DBG(("done, final %llu:%llu",
	    (غیرعلامتی طویل طویل)ers->lo, (غیرعلامتی طویل طویل)ers->hi));
	واپس 0;
}

صحیح
ssh_krl_revoke_cert_by_serial(ساخت ssh_krl *krl, ثابت ساخت sshkey *ca_کلید,
    uint64_t serial)
{
	واپس ssh_krl_revoke_cert_by_serial_range(krl, ca_کلید, serial, serial);
}

صحیح
ssh_krl_revoke_cert_by_serial_range(ساخت ssh_krl *krl,
    ثابت ساخت sshkey *ca_کلید, uint64_t lo, uint64_t hi)
{
	ساخت revoked_certs *rc;
	صحیح r;

	اگر (lo > hi || lo == 0)
		واپس SSH_ERR_INVALID_دلیل;
	اگر ((r = revoked_certs_for_ca_کلید(krl, ca_کلید, &rc, 1)) != 0)
		واپس r;
	واپس داخل_کرو_serial_range(&rc->revoked_serials, lo, hi);
}

صحیح
ssh_krl_revoke_cert_by_کلید_id(ساخت ssh_krl *krl, ثابت ساخت sshkey *ca_کلید,
    ثابت حرف *کلید_id)
{
	ساخت revoked_کلید_id *rki, *erki;
	ساخت revoked_certs *rc;
	صحیح r;

	اگر ((r = revoked_certs_for_ca_کلید(krl, ca_کلید, &rc, 1)) != 0)
		واپس r;

	KRL_DBG(("revoke %s", کلید_id));
	اگر ((rki = صفر_حافظہ_دو(1, حجم(*rki))) == تہی ||
	    (rki->کلید_id = strdup(کلید_id)) == تہی) {
		آزاد(rki);
		واپس SSH_ERR_ALLOC_FAIL;
	}
	erki = RB_داخل_کرو(revoked_کلید_id_درخت, &rc->revoked_کلید_ids, rki);
	اگر (erki != تہی) {
		آزاد(rki->کلید_id);
		آزاد(rki);
	}
	واپس 0;
}

/* Convert "key" to a public key blob without any certificate information */
ساکن صحیح
plain_کلید_blob(ثابت ساخت sshkey *کلید, u_char **blob, سائز_t *blen)
{
	ساخت sshkey *kcopy;
	صحیح r;

	اگر ((r = sshkey_from_نجی(کلید, &kcopy)) != 0)
		واپس r;
	اگر (sshkey_is_cert(kcopy)) {
		اگر ((r = sshkey_drop_cert(kcopy)) != 0) {
			sshkey_free(kcopy);
			واپس r;
		}
	}
	r = sshkey_مقصد_blob(kcopy, blob, blen);
	sshkey_free(kcopy);
	واپس r;
}

/* Revoke a key blob. Ownership of blob is transferred to the tree */
ساکن صحیح
revoke_blob(ساخت revoked_blob_درخت *rbt, u_char *blob, سائز_t len)
{
	ساخت revoked_blob *rb, *erb;

	اگر ((rb = صفر_حافظہ_دو(1, حجم(*rb))) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	rb->blob = blob;
	rb->len = len;
	erb = RB_داخل_کرو(revoked_blob_درخت, rbt, rb);
	اگر (erb != تہی) {
		آزاد(rb->blob);
		آزاد(rb);
	}
	واپس 0;
}

صحیح
ssh_krl_revoke_کلید_explicit(ساخت ssh_krl *krl, ثابت ساخت sshkey *کلید)
{
	u_char *blob;
	سائز_t len;
	صحیح r;

	debug3_f("revoke type %s", sshkey_type(کلید));
	اگر ((r = plain_کلید_blob(کلید, &blob, &len)) != 0)
		واپس r;
	واپس revoke_blob(&krl->revoked_کلیدیں, blob, len);
}

ساکن صحیح
revoke_by_hash(ساخت revoked_blob_درخت *ہدف, ثابت u_char *p, سائز_t len)
{
	u_char *blob;
	صحیح r;

	/* need to copy hash, as revoke_blob steals ownership */
	اگر ((blob = حافظہ_دو(len)) == تہی)
		واپس SSH_ERR_SYSTEM_ERROR;
	حافظہ_نقل(blob, p, len);
	اگر ((r = revoke_blob(ہدف, blob, len)) != 0) {
		آزاد(blob);
		واپس r;
	}
	واپس 0;
}

صحیح
ssh_krl_revoke_کلید_sha1(ساخت ssh_krl *krl, ثابت u_char *p, سائز_t len)
{
	debug3_f("revoke by sha1");
	اگر (len != 20)
		واپس SSH_ERR_INVALID_FORMAT;
	واپس revoke_by_hash(&krl->revoked_sha1s, p, len);
}

صحیح
ssh_krl_revoke_کلید_sha256(ساخت ssh_krl *krl, ثابت u_char *p, سائز_t len)
{
	debug3_f("revoke by sha256");
	اگر (len != 32)
		واپس SSH_ERR_INVALID_FORMAT;
	واپس revoke_by_hash(&krl->revoked_sha256s, p, len);
}

صحیح
ssh_krl_revoke_کلید(ساخت ssh_krl *krl, ثابت ساخت sshkey *کلید)
{
	/* XXX replace with SHA256? */
	اگر (!sshkey_is_cert(کلید))
		واپس ssh_krl_revoke_کلید_explicit(krl, کلید);

	اگر (کلید->cert->serial == 0) {
		واپس ssh_krl_revoke_cert_by_کلید_id(krl,
		    کلید->cert->signature_کلید,
		    کلید->cert->کلید_id);
	} ورنہ {
		واپس ssh_krl_revoke_cert_by_serial(krl,
		    کلید->cert->signature_کلید,
		    کلید->cert->serial);
	}
}

/*
 * Select the most compact section type to emit next in a KRL based on
 * the current section type, the run length of contiguous revoked serial
 * numbers and the gaps from the last and to the next revoked serial.
 * Applies a mostly-accurate bit cost model to select the section type
 * that will minimise the size of the resultant KRL.
 */
ساکن صحیح
انتخاب_اگلا_state(صحیح current_state, uint64_t contig, صحیح final,
    uint64_t آخری_gap, uint64_t اگلا_gap, سائز_t bitmap_len,
    صحیح *force_new_section)
{
	صحیح new_state;
	uint64_t لاگت, لاگت_list, لاگت_range, لاگت_bitmap, لاگت_bitmap_restart;

	/*
	 * Avoid unsigned overflows.
	 * The limits are high enough to avoid confusing the calculations.
	 */
	contig = MINIMUM(contig, 1ULL<<31);
	آخری_gap = MINIMUM(آخری_gap, 1ULL<<31);
	اگلا_gap = MINIMUM(اگلا_gap, 1ULL<<31);

	/*
	 * Calculate the cost to switch from the current state to candidates.
	 * NB. range sections only ever contain a single range, so their
	 * switching cost is independent of the current_state.
	 */
	لاگت_list = لاگت_bitmap = لاگت_bitmap_restart = 0;
	لاگت_range = 8;
	انتخاب (current_state) {
	حالت KRL_SECTION_CERT_SERIAL_LIST:
		لاگت_bitmap_restart = لاگت_bitmap = 8 + 64;
		توڑو;
	حالت KRL_SECTION_CERT_SERIAL_BITMAP:
		لاگت_list = 8;
		لاگت_bitmap_restart = 8 + 64;
		توڑو;
	حالت KRL_SECTION_CERT_SERIAL_RANGE:
	حالت 0:
		لاگت_bitmap_restart = لاگت_bitmap = 8 + 64;
		لاگت_list = 8;
	}

	/* Estimate base cost in bits of each section type */
	لاگت_list += 64 * contig + (final ? 0 : 8+64);
	لاگت_range += (2 * 64) + (final ? 0 : 8+64);
	لاگت_bitmap += آخری_gap + contig + (final ? 0 : MINIMUM(اگلا_gap, 8+64));
	لاگت_bitmap_restart += contig + (final ? 0 : MINIMUM(اگلا_gap, 8+64));

	/* Convert to byte costs for actual comparison */
	لاگت_list = (لاگت_list + 7) / 8;
	لاگت_bitmap = (لاگت_bitmap + 7) / 8;
	لاگت_bitmap_restart = (لاگت_bitmap_restart + 7) / 8;
	لاگت_range = (لاگت_range + 7) / 8;

	/* Ensure that we never emit a bitmap larger than sshbuf can handle */
	اگر (bitmap_len + لاگت_bitmap >= SSHBUF_MAX_BIGNUM) {
		KRL_DBG(("bitmap overfull len=%zu cost=%llu max=%u",
		    bitmap_len, (غیرعلامتی طویل طویل)لاگت_bitmap,
		    SSHBUF_MAX_BIGNUM));
		لاگت_bitmap = (uint64_t)-1;
	}

	/* Now pick the best choice */
	*force_new_section = 0;
	new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
	لاگت = لاگت_bitmap;
	اگر (لاگت_range < لاگت) {
		new_state = KRL_SECTION_CERT_SERIAL_RANGE;
		لاگت = لاگت_range;
	}
	اگر (لاگت_list < لاگت) {
		new_state = KRL_SECTION_CERT_SERIAL_LIST;
		لاگت = لاگت_list;
	}
	اگر (لاگت_bitmap_restart < لاگت) {
		new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
		*force_new_section = 1;
		لاگت = لاگت_bitmap_restart;
	}
	KRL_DBG(("contig %llu last_gap %llu next_gap %llu final %d, costs:"
	    "list %llu range %llu bitmap %llu new bitmap %llu, "
	    "selected 0x%02x%s", (طویل طویل غیرعلامتی)contig,
	    (طویل طویل غیرعلامتی)آخری_gap, (طویل طویل غیرعلامتی)اگلا_gap, final,
	    (طویل طویل غیرعلامتی)لاگت_list, (طویل طویل غیرعلامتی)لاگت_range,
	    (طویل طویل غیرعلامتی)لاگت_bitmap,
	    (طویل طویل غیرعلامتی)لاگت_bitmap_restart, new_state,
	    *force_new_section ? " restart" : ""));
	واپس new_state;
}

ساکن صحیح
put_bitmap(ساخت sshbuf *buf, ساخت bitmap *bitmap)
{
	سائز_t len;
	u_char *blob;
	صحیح r;

	len = bitmap_nbytes(bitmap);
	اگر ((blob = حافظہ_دو(len)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر (bitmap_مقصد_string(bitmap, blob, len) != 0) {
		آزاد(blob);
		واپس SSH_ERR_اندرونی_ERROR;
	}
	r = sshbuf_put_bignum2_بائٹیں(buf, blob, len);
	آزاد(blob);
	واپس r;
}

/* Generate a KRL_SECTION_CERTIFICATES KRL section */
ساکن صحیح
revoked_certs_generate(ساخت revoked_certs *rc, ساخت sshbuf *buf)
{
	صحیح final, force_new_sect, r = SSH_ERR_اندرونی_ERROR;
	uint64_t i, contig, gap, آخری = 0, bitmap_آغاز = 0;
	ساخت revoked_serial *rs, *nrs;
	ساخت revoked_کلید_id *rki;
	صحیح اگلا_state, state = 0;
	سائز_t bitmap_len;
	ساخت sshbuf *sect;
	ساخت bitmap *bitmap = تہی;

	اگر ((sect = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;

	/* Store the header: optional CA scope key, reserved */
	اگر (rc->ca_کلید == تہی) {
		اگر ((r = sshbuf_put_string(buf, تہی, 0)) != 0)
			جاؤ برآمد;
	} ورنہ {
		اگر ((r = sshkey_puts(rc->ca_کلید, buf)) != 0)
			جاؤ برآمد;
	}
	اگر ((r = sshbuf_put_string(buf, تہی, 0)) != 0)
		جاؤ برآمد;

	/* Store the revoked serials.  */
	برائے (rs = RB_MIN(revoked_serial_درخت, &rc->revoked_serials);
	     rs != تہی;
	     rs = RB_اگلا(revoked_serial_درخت, &rc->revoked_serials, rs)) {
		KRL_DBG(("serial %llu:%llu state 0x%02x",
		    (طویل طویل غیرعلامتی)rs->lo, (طویل طویل غیرعلامتی)rs->hi,
		    state));

		/* Check contiguous length and gap to next section (if any) */
		nrs = RB_اگلا(revoked_serial_درخت, &rc->revoked_serials, rs);
		final = nrs == تہی;
		gap = nrs == تہی ? 0 : nrs->lo - rs->hi;
		contig = 1 + (rs->hi - rs->lo);

		bitmap_len = state == KRL_SECTION_CERT_SERIAL_BITMAP ?
		    bitmap_nbytes(bitmap) : 0;

		/* Choose next state based on these */
		اگلا_state = انتخاب_اگلا_state(state, contig, final,
		    state == 0 ? 0 : rs->lo - آخری, gap, bitmap_len,
		    &force_new_sect);

		/*
		 * If the current section is a range section or has a different
		 * type to the next section, then finish it off now.
		 */
		اگر (state != 0 && (force_new_sect || اگلا_state != state ||
		    state == KRL_SECTION_CERT_SERIAL_RANGE)) {
			KRL_DBG(("finish state 0x%02x", state));
			انتخاب (state) {
			حالت KRL_SECTION_CERT_SERIAL_LIST:
			حالت KRL_SECTION_CERT_SERIAL_RANGE:
				توڑو;
			حالت KRL_SECTION_CERT_SERIAL_BITMAP:
				اگر ((r = put_bitmap(sect, bitmap)) != 0)
					جاؤ برآمد;
				bitmap_free(bitmap);
				bitmap = تہی;
				توڑو;
			}
			اگر ((r = sshbuf_put_u8(buf, state)) != 0 ||
			    (r = sshbuf_put_stringb(buf, sect)) != 0)
				جاؤ برآمد;
			sshbuf_reset(sect);
		}

		/* If we are starting a new section then prepare it now */
		اگر (اگلا_state != state || force_new_sect) {
			KRL_DBG(("start state 0x%02x",
			    اگلا_state));
			state = اگلا_state;
			sshbuf_reset(sect);
			انتخاب (state) {
			حالت KRL_SECTION_CERT_SERIAL_LIST:
			حالت KRL_SECTION_CERT_SERIAL_RANGE:
				توڑو;
			حالت KRL_SECTION_CERT_SERIAL_BITMAP:
				اگر ((bitmap = bitmap_new()) == تہی) {
					r = SSH_ERR_ALLOC_FAIL;
					جاؤ برآمد;
				}
				bitmap_آغاز = rs->lo;
				اگر ((r = sshbuf_put_u64(sect,
				    bitmap_آغاز)) != 0)
					جاؤ برآمد;
				توڑو;
			}
		}

		/* Perform section-specific processing */
		انتخاب (state) {
		حالت KRL_SECTION_CERT_SERIAL_LIST:
			برائے (i = 0; i < contig; i++) {
				اگر ((r = sshbuf_put_u64(sect, rs->lo + i)) != 0)
					جاؤ برآمد;
			}
			توڑو;
		حالت KRL_SECTION_CERT_SERIAL_RANGE:
			اگر ((r = sshbuf_put_u64(sect, rs->lo)) != 0 ||
			    (r = sshbuf_put_u64(sect, rs->hi)) != 0)
				جاؤ برآمد;
			توڑو;
		حالت KRL_SECTION_CERT_SERIAL_BITMAP:
			اگر (rs->lo - bitmap_آغاز > زیادہ_سے_زیادہ_عدد) {
				r = SSH_ERR_INVALID_FORMAT;
				error_f("insane bitmap gap");
				جاؤ برآمد;
			}
			برائے (i = 0; i < contig; i++) {
				اگر (bitmap_سیٹ_ثنائی_ہندسہ(bitmap,
				    rs->lo + i - bitmap_آغاز) != 0) {
					r = SSH_ERR_ALLOC_FAIL;
					جاؤ برآمد;
				}
			}
			توڑو;
		}
		آخری = rs->hi;
	}
	/* Flush the remaining section, if any */
	اگر (state != 0) {
		KRL_DBG(("serial final flush for state 0x%02x", state));
		انتخاب (state) {
		حالت KRL_SECTION_CERT_SERIAL_LIST:
		حالت KRL_SECTION_CERT_SERIAL_RANGE:
			توڑو;
		حالت KRL_SECTION_CERT_SERIAL_BITMAP:
			اگر ((r = put_bitmap(sect, bitmap)) != 0)
				جاؤ برآمد;
			bitmap_free(bitmap);
			bitmap = تہی;
			توڑو;
		}
		اگر ((r = sshbuf_put_u8(buf, state)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			جاؤ برآمد;
	}
	KRL_DBG(("serial done "));

	/* Now output a section for any revocations by key ID */
	sshbuf_reset(sect);
	RB_FOREACH(rki, revoked_کلید_id_درخت, &rc->revoked_کلید_ids) {
		KRL_DBG(("key ID %s", rki->کلید_id));
		اگر ((r = sshbuf_put_cstring(sect, rki->کلید_id)) != 0)
			جاؤ برآمد;
	}
	اگر (sshbuf_len(sect) != 0) {
		اگر ((r = sshbuf_put_u8(buf, KRL_SECTION_CERT_کلید_ID)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			جاؤ برآمد;
	}
	r = 0;
 برآمد:
	bitmap_free(bitmap);
	sshbuf_free(sect);
	واپس r;
}

صحیح
ssh_krl_مقصد_blob(ساخت ssh_krl *krl, ساخت sshbuf *buf)
{
	صحیح r = SSH_ERR_اندرونی_ERROR;
	ساخت revoked_certs *rc;
	ساخت revoked_blob *rb;
	ساخت sshbuf *sect;
	u_char *sblob = تہی;

	اگر (krl->generated_date == 0)
		krl->generated_date = time(تہی);

	اگر ((sect = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;

	/* Store the header */
	اگر ((r = sshbuf_put(buf, KRL_MAGIC, حجم(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_put_u32(buf, KRL_FORMAT_نسخہ)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->krl_نسخہ)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->generated_date)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->flags)) != 0 ||
	    (r = sshbuf_put_string(buf, تہی, 0)) != 0 ||
	    (r = sshbuf_put_cstring(buf, krl->comment)) != 0)
		جاؤ برآمد;

	/* Store sections for revoked certificates */
	TAILQ_FOREACH(rc, &krl->revoked_certs, اندراج_2) {
		sshbuf_reset(sect);
		اگر ((r = revoked_certs_generate(rc, sect)) != 0)
			جاؤ برآمد;
		اگر ((r = sshbuf_put_u8(buf, KRL_SECTION_CERTIFICATES)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			جاؤ برآمد;
	}

	/* Finally, output sections for revocations by public key/hash */
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_درخت, &krl->revoked_کلیدیں) {
		KRL_DBG(("key len %zu ", rb->len));
		اگر ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			جاؤ برآمد;
	}
	اگر (sshbuf_len(sect) != 0) {
		اگر ((r = sshbuf_put_u8(buf, KRL_SECTION_EXPLICIT_کلید)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			جاؤ برآمد;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_درخت, &krl->revoked_sha1s) {
		KRL_DBG(("hash len %zu ", rb->len));
		اگر ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			جاؤ برآمد;
	}
	اگر (sshbuf_len(sect) != 0) {
		اگر ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA1)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			جاؤ برآمد;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_درخت, &krl->revoked_sha256s) {
		KRL_DBG(("hash len %zu ", rb->len));
		اگر ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			جاؤ برآمد;
	}
	اگر (sshbuf_len(sect) != 0) {
		اگر ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA256)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			جاؤ برآمد;
	}
	/* success */
	r = 0;
 برآمد:
	آزاد(sblob);
	sshbuf_free(sect);
	واپس r;
}

ساکن خالی
format_timestamp(uint64_t timestamp, حرف *ts, سائز_t nts)
{
	time_t t;
	ساخت tm *tm;

	t = timestamp;
	tm = localtime(&t);
	اگر (tm == تہی)
		strlcpy(ts, "<INVALID>", nts);
	ورنہ {
		*ts = '\0';
		strftime(ts, nts, "%Y%m%dT%H%M%S", tm);
	}
}

ساکن صحیح
cert_extension_subsection(ساخت sshbuf *subsect, ساخت ssh_krl *krl)
{
	صحیح r = SSH_ERR_اندرونی_ERROR;
	u_char critical = 1;
	ساخت sshbuf *قدر = تہی;
	حرف *name = تہی;

	اگر ((r = sshbuf_get_cstring(subsect, &name, تہی)) != 0 ||
	    (r = sshbuf_get_u8(subsect, &critical)) != 0 ||
	    (r = sshbuf_froms(subsect, &قدر)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid certificate extension subsection");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (sshbuf_len(subsect) != 0) {
		error("KRL has invalid certificate extension subsection: "
		    "trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	debug_f("cert extension %s critical %u len %zu",
	    name, critical, sshbuf_len(قدر));
	/* no extensions are currently supported */
	اگر (critical) {
		error("KRL contains unsupported critical certificate "
		    "subsection \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		جاؤ برآمد;
	}
	/* success */
	r = 0;
 برآمد:
	آزاد(name);
	sshbuf_free(قدر);
	واپس r;
}

ساکن صحیح
parse_revoked_certs(ساخت sshbuf *buf, ساخت ssh_krl *krl)
{
	صحیح r = SSH_ERR_اندرونی_ERROR;
	u_char type;
	ثابت u_char *blob;
	سائز_t blen, nbits;
	ساخت sshbuf *subsect = تہی;
	uint64_t serial, serial_lo, serial_hi;
	ساخت bitmap *bitmap = تہی;
	حرف *کلید_id = تہی;
	ساخت sshkey *ca_کلید = تہی;

	اگر ((subsect = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;

	/* Header: key, reserved */
	اگر ((r = sshbuf_get_string_براہ_راست(buf, &blob, &blen)) != 0 ||
	    (r = sshbuf_skip_string(buf)) != 0)
		جاؤ برآمد;
	اگر (blen != 0 && (r = sshkey_from_blob(blob, blen, &ca_کلید)) != 0)
		جاؤ برآمد;

	جب (sshbuf_len(buf) > 0) {
		sshbuf_free(subsect);
		subsect = تہی;
		اگر ((r = sshbuf_get_u8(buf, &type)) != 0 ||
		    (r = sshbuf_froms(buf, &subsect)) != 0)
			جاؤ برآمد;
		KRL_DBG(("subsection type 0x%02x", type));
		/* sshbuf_dump(subsect, stderr); */

		انتخاب (type) {
		حالت KRL_SECTION_CERT_SERIAL_LIST:
			جب (sshbuf_len(subsect) > 0) {
				اگر ((r = sshbuf_get_u64(subsect, &serial)) != 0)
					جاؤ برآمد;
				اگر ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_کلید, serial)) != 0)
					جاؤ برآمد;
			}
			توڑو;
		حالت KRL_SECTION_CERT_SERIAL_RANGE:
			اگر ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_u64(subsect, &serial_hi)) != 0)
				جاؤ برآمد;
			اگر ((r = ssh_krl_revoke_cert_by_serial_range(krl,
			    ca_کلید, serial_lo, serial_hi)) != 0)
				جاؤ برآمد;
			توڑو;
		حالت KRL_SECTION_CERT_SERIAL_BITMAP:
			اگر ((bitmap = bitmap_new()) == تہی) {
				r = SSH_ERR_ALLOC_FAIL;
				جاؤ برآمد;
			}
			اگر ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_bignum2_بائٹیں_براہ_راست(subsect,
			    &blob, &blen)) != 0)
				جاؤ برآمد;
			اگر (bitmap_from_string(bitmap, blob, blen) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				جاؤ برآمد;
			}
			nbits = bitmap_nbits(bitmap);
			برائے (serial = 0; serial < (uint64_t)nbits; serial++) {
				اگر (serial > 0 && serial_lo + serial == 0) {
					error_f("bitmap wraps u64");
					r = SSH_ERR_INVALID_FORMAT;
					جاؤ برآمد;
				}
				اگر (!bitmap_test_ثنائی_ہندسہ(bitmap, serial))
					جاری;
				اگر ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_کلید, serial_lo + serial)) != 0)
					جاؤ برآمد;
			}
			bitmap_free(bitmap);
			bitmap = تہی;
			توڑو;
		حالت KRL_SECTION_CERT_کلید_ID:
			جب (sshbuf_len(subsect) > 0) {
				اگر ((r = sshbuf_get_cstring(subsect,
				    &کلید_id, تہی)) != 0)
					جاؤ برآمد;
				اگر ((r = ssh_krl_revoke_cert_by_کلید_id(krl,
				    ca_کلید, کلید_id)) != 0)
					جاؤ برآمد;
				آزاد(کلید_id);
				کلید_id = تہی;
			}
			توڑو;
		حالت KRL_SECTION_CERT_EXTENSION:
			اگر ((r = cert_extension_subsection(subsect, krl)) != 0)
				جاؤ برآمد;
			توڑو;
		طےشدہ:
			error("Unsupported KRL certificate section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
		اگر (sshbuf_len(subsect) > 0) {
			error("KRL certificate section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
	}

	r = 0;
 برآمد:
	اگر (bitmap != تہی)
		bitmap_free(bitmap);
	آزاد(کلید_id);
	sshkey_free(ca_کلید);
	sshbuf_free(subsect);
	واپس r;
}

ساکن صحیح
blob_section(ساخت sshbuf *sect, ساخت revoked_blob_درخت *ہدف_درخت,
    سائز_t expected_len)
{
	u_char *rdata = تہی;
	سائز_t rlen = 0;
	صحیح r;

	جب (sshbuf_len(sect) > 0) {
		اگر ((r = sshbuf_get_string(sect, &rdata, &rlen)) != 0)
			واپس r;
		اگر (expected_len != 0 && rlen != expected_len) {
			error_f("bad length");
			آزاد(rdata);
			واپس SSH_ERR_INVALID_FORMAT;
		}
		اگر ((r = revoke_blob(ہدف_درخت, rdata, rlen)) != 0) {
			آزاد(rdata);
			واپس r;
		}
	}
	واپس 0;
}

ساکن صحیح
extension_section(ساخت sshbuf *sect, ساخت ssh_krl *krl)
{
	صحیح r = SSH_ERR_اندرونی_ERROR;
	u_char critical = 1;
	ساخت sshbuf *قدر = تہی;
	حرف *name = تہی;

	اگر ((r = sshbuf_get_cstring(sect, &name, تہی)) != 0 ||
	    (r = sshbuf_get_u8(sect, &critical)) != 0 ||
	    (r = sshbuf_froms(sect, &قدر)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid extension section");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (sshbuf_len(sect) != 0) {
		error("KRL has invalid extension section: trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	debug_f("extension %s critical %u len %zu",
	    name, critical, sshbuf_len(قدر));
	/* no extensions are currently supported */
	اگر (critical) {
		error("KRL contains unsupported critical section \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		جاؤ برآمد;
	}
	/* success */
	r = 0;
 برآمد:
	آزاد(name);
	sshbuf_free(قدر);
	واپس r;
}

/* Attempt to parse a KRL */
صحیح
ssh_krl_from_blob(ساخت sshbuf *buf, ساخت ssh_krl **krlp)
{
	ساخت sshbuf *copy = تہی, *sect = تہی;
	ساخت ssh_krl *krl = تہی;
	حرف timestamp[64];
	صحیح r = SSH_ERR_اندرونی_ERROR;
	u_char type;
	u_int format_نسخہ;

	*krlp = تہی;

	/* KRL must begin with magic string */
	اگر ((r = sshbuf_cmp(buf, 0, KRL_MAGIC, حجم(KRL_MAGIC) - 1)) != 0) {
		debug2_f("bad KRL magic header");
		واپس SSH_ERR_KRL_BAD_MAGIC;
	}

	اگر ((krl = ssh_krl_init()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		error_f("alloc failed");
		جاؤ برآمد;
	}
	/* Don't modify buffer */
	اگر ((copy = sshbuf_fromb(buf)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_consume(copy, حجم(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_get_u32(copy, &format_نسخہ)) != 0)
		جاؤ برآمد;
	اگر (format_نسخہ != KRL_FORMAT_نسخہ) {
		error_f("unsupported KRL format version %u", format_نسخہ);
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_get_u64(copy, &krl->krl_نسخہ)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->generated_date)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->flags)) != 0 ||
	    (r = sshbuf_skip_string(copy)) != 0 ||
	    (r = sshbuf_get_cstring(copy, &krl->comment, تہی)) != 0) {
		error_fr(r, "parse KRL header");
		جاؤ برآمد;
	}
	format_timestamp(krl->generated_date, timestamp, حجم(timestamp));
	debug("KRL version %llu generated at %s%s%s",
	    (طویل طویل غیرعلامتی)krl->krl_نسخہ, timestamp,
	    *krl->comment ? ": " : "", krl->comment);

	/* Parse and load the KRL sections. */
	جب (sshbuf_len(copy) > 0) {
		sshbuf_free(sect);
		sect = تہی;
		اگر ((r = sshbuf_get_u8(copy, &type)) != 0 ||
		    (r = sshbuf_froms(copy, &sect)) != 0)
			جاؤ برآمد;
		KRL_DBG(("section 0x%02x", type));

		انتخاب (type) {
		حالت KRL_SECTION_CERTIFICATES:
			اگر ((r = parse_revoked_certs(sect, krl)) != 0)
				جاؤ برآمد;
			توڑو;
		حالت KRL_SECTION_EXPLICIT_کلید:
			اگر ((r = blob_section(sect,
			    &krl->revoked_کلیدیں, 0)) != 0)
				جاؤ برآمد;
			توڑو;
		حالت KRL_SECTION_FINGERPRINT_SHA1:
			اگر ((r = blob_section(sect,
			    &krl->revoked_sha1s, 20)) != 0)
				جاؤ برآمد;
			توڑو;
		حالت KRL_SECTION_FINGERPRINT_SHA256:
			اگر ((r = blob_section(sect,
			    &krl->revoked_sha256s, 32)) != 0)
				جاؤ برآمد;
			توڑو;
		حالت KRL_SECTION_EXTENSION:
			اگر ((r = extension_section(sect, krl)) != 0)
				جاؤ برآمد;
			توڑو;
		حالت KRL_SECTION_SIGNATURE:
			/* Handled above, but still need to stay in synch */
			sshbuf_free(sect);
			sect = تہی;
			اگر ((r = sshbuf_skip_string(copy)) != 0)
				جاؤ برآمد;
			توڑو;
		طےشدہ:
			error("Unsupported KRL section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
		اگر (sect != تہی && sshbuf_len(sect) > 0) {
			error("KRL section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
	}

	/* Success */
	*krlp = krl;
	r = 0;
 برآمد:
	اگر (r != 0)
		ssh_krl_free(krl);
	sshbuf_free(copy);
	sshbuf_free(sect);
	واپس r;
}

/* Checks certificate serial number and key ID revocation */
ساکن صحیح
is_cert_revoked(ثابت ساخت sshkey *کلید, ساخت revoked_certs *rc)
{
	ساخت revoked_serial rs, *ers;
	ساخت revoked_کلید_id rki, *erki;

	/* Check revocation by cert key ID */
	memset(&rki, 0, حجم(rki));
	rki.کلید_id = کلید->cert->کلید_id;
	erki = RB_ڈھونڈو(revoked_کلید_id_درخت, &rc->revoked_کلید_ids, &rki);
	اگر (erki != تہی) {
		KRL_DBG(("revoked by key ID"));
		واپس SSH_ERR_کلید_REVOKED;
	}

	/*
	 * Zero serials numbers are ignored (it's the default when the
	 * CA doesn't specify one).
	 */
	اگر (کلید->cert->serial == 0)
		واپس 0;

	memset(&rs, 0, حجم(rs));
	rs.lo = rs.hi = کلید->cert->serial;
	ers = RB_ڈھونڈو(revoked_serial_درخت, &rc->revoked_serials, &rs);
	اگر (ers != تہی) {
		KRL_DBG(("revoked serial %llu matched %llu:%llu",
		    (غیرعلامتی طویل طویل)کلید->cert->serial,
		    (غیرعلامتی طویل طویل)ers->lo,
		    (غیرعلامتی طویل طویل)ers->hi));
		واپس SSH_ERR_کلید_REVOKED;
	}
	واپس 0;
}

/* Checks whether a given key/cert is revoked. Does not check its CA */
ساکن صحیح
is_کلید_revoked(ساخت ssh_krl *krl, ثابت ساخت sshkey *کلید)
{
	ساخت revoked_blob rb, *erb;
	ساخت revoked_certs *rc;
	صحیح r;

	/* Check explicitly revoked hashes first */
	memset(&rb, 0, حجم(rb));
	اگر ((r = sshkey_fingerprint_raw(کلید, SSH_DIGEST_SHA1,
	    &rb.blob, &rb.len)) != 0)
		واپس r;
	erb = RB_ڈھونڈو(revoked_blob_درخت, &krl->revoked_sha1s, &rb);
	آزاد(rb.blob);
	اگر (erb != تہی) {
		KRL_DBG(("revoked by key SHA1"));
		واپس SSH_ERR_کلید_REVOKED;
	}
	memset(&rb, 0, حجم(rb));
	اگر ((r = sshkey_fingerprint_raw(کلید, SSH_DIGEST_SHA256,
	    &rb.blob, &rb.len)) != 0)
		واپس r;
	erb = RB_ڈھونڈو(revoked_blob_درخت, &krl->revoked_sha256s, &rb);
	آزاد(rb.blob);
	اگر (erb != تہی) {
		KRL_DBG(("revoked by key SHA256"));
		واپس SSH_ERR_کلید_REVOKED;
	}

	/* Next, explicit keys */
	memset(&rb, 0, حجم(rb));
	اگر ((r = plain_کلید_blob(کلید, &rb.blob, &rb.len)) != 0)
		واپس r;
	erb = RB_ڈھونڈو(revoked_blob_درخت, &krl->revoked_کلیدیں, &rb);
	آزاد(rb.blob);
	اگر (erb != تہی) {
		KRL_DBG(("revoked by explicit key"));
		واپس SSH_ERR_کلید_REVOKED;
	}

	اگر (!sshkey_is_cert(کلید))
		واپس 0;

	/* Check cert revocation for the specified CA */
	اگر ((r = revoked_certs_for_ca_کلید(krl, کلید->cert->signature_کلید,
	    &rc, 0)) != 0)
		واپس r;
	اگر (rc != تہی) {
		اگر ((r = is_cert_revoked(کلید, rc)) != 0)
			واپس r;
	}
	/* Check cert revocation for the wildcard CA */
	اگر ((r = revoked_certs_for_ca_کلید(krl, تہی, &rc, 0)) != 0)
		واپس r;
	اگر (rc != تہی) {
		اگر ((r = is_cert_revoked(کلید, rc)) != 0)
			واپس r;
	}

	KRL_DBG(("%llu no match", (غیرعلامتی طویل طویل)کلید->cert->serial));
	واپس 0;
}

صحیح
ssh_krl_check_کلید(ساخت ssh_krl *krl, ثابت ساخت sshkey *کلید)
{
	صحیح r;

	KRL_DBG(("checking key"));
	اگر ((r = is_کلید_revoked(krl, کلید)) != 0)
		واپس r;
	اگر (sshkey_is_cert(کلید)) {
		debug2_f("checking CA key");
		اگر ((r = is_کلید_revoked(krl, کلید->cert->signature_کلید)) != 0)
			واپس r;
	}
	KRL_DBG(("key okay"));
	واپس 0;
}

صحیح
ssh_krl_file_شامل_ہے_کلید(ثابت حرف *راستہ, ثابت ساخت sshkey *کلید)
{
	ساخت sshbuf *krlbuf = تہی;
	ساخت ssh_krl *krl = تہی;
	صحیح oerrno = 0, r;

	اگر (راستہ == تہی)
		واپس 0;
	اگر ((r = sshbuf_بھرو_file(راستہ, &krlbuf)) != 0) {
		oerrno = errno;
		جاؤ برآمد;
	}
	اگر ((r = ssh_krl_from_blob(krlbuf, &krl)) != 0)
		جاؤ برآمد;
	debug2_f("checking KRL %s", راستہ);
	r = ssh_krl_check_کلید(krl, کلید);
 برآمد:
	sshbuf_free(krlbuf);
	ssh_krl_free(krl);
	اگر (r != 0)
		errno = oerrno;
	واپس r;
}

صحیح
krl_dump(ساخت ssh_krl *krl, FILE *f)
{
	ساخت sshkey *کلید = تہی;
	ساخت revoked_blob *rb;
	ساخت revoked_certs *rc;
	ساخت revoked_serial *rs;
	ساخت revoked_کلید_id *rki;
	صحیح r, ret = 0;
	حرف *fp, timestamp[64];

	/* Try to print in a KRL spec-compatible format */
	format_timestamp(krl->generated_date, timestamp, حجم(timestamp));
	fprintf(f, "# KRL version %llu\n", (غیرعلامتی طویل طویل)krl->krl_نسخہ);
	fprintf(f, "# Generated at %s\n", timestamp);
	اگر (krl->comment != تہی && *krl->comment != '\0') {
		r = زیادہ_سے_زیادہ_عدد;
		asmprintf(&fp, زیادہ_سے_زیادہ_عدد, &r, "%s", krl->comment);
		fprintf(f, "# Comment: %s\n", fp);
		آزاد(fp);
	}
	fputc('\n', f);

	RB_FOREACH(rb, revoked_blob_درخت, &krl->revoked_کلیدیں) {
		اگر ((r = sshkey_from_blob(rb->blob, rb->len, &کلید)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			error_r(r, "parse KRL key");
			جاری;
		}
		اگر ((fp = sshkey_fingerprint(کلید, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == تہی) {
			ret = SSH_ERR_INVALID_FORMAT;
			error("sshkey_fingerprint failed");
			جاری;
		}
		fprintf(f, "hash: %s # %s\n", fp, sshkey_ssh_name(کلید));
		آزاد(fp);
		آزاد(کلید);
	}
	RB_FOREACH(rb, revoked_blob_درخت, &krl->revoked_sha256s) {
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "hash: SHA256:%s\n", fp);
		آزاد(fp);
	}
	RB_FOREACH(rb, revoked_blob_درخت, &krl->revoked_sha1s) {
		/*
		 * There is not KRL spec keyword for raw SHA1 hashes, so
		 * print them as comments.
		 */
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "# hash SHA1:%s\n", fp);
		آزاد(fp);
	}

	TAILQ_FOREACH(rc, &krl->revoked_certs, اندراج_2) {
		fputc('\n', f);
		اگر (rc->ca_کلید == تہی)
			fprintf(f, "# Wildcard CA\n");
		ورنہ {
			اگر ((fp = sshkey_fingerprint(rc->ca_کلید,
			    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == تہی) {
				ret = SSH_ERR_INVALID_FORMAT;
				error("sshkey_fingerprint failed");
				جاری;
			}
			fprintf(f, "# CA key %s %s\n",
			    sshkey_ssh_name(rc->ca_کلید), fp);
			آزاد(fp);
		}
		RB_FOREACH(rs, revoked_serial_درخت, &rc->revoked_serials) {
			اگر (rs->lo == rs->hi) {
				fprintf(f, "serial: %llu\n",
				    (غیرعلامتی طویل طویل)rs->lo);
			} ورنہ {
				fprintf(f, "serial: %llu-%llu\n",
				    (غیرعلامتی طویل طویل)rs->lo,
				    (غیرعلامتی طویل طویل)rs->hi);
			}
		}
		RB_FOREACH(rki, revoked_کلید_id_درخت, &rc->revoked_کلید_ids) {
			/*
			 * We don't want key IDs with embedded newlines to
			 * mess up the display.
			 */
			r = زیادہ_سے_زیادہ_عدد;
			asmprintf(&fp, زیادہ_سے_زیادہ_عدد, &r, "%s", rki->کلید_id);
			fprintf(f, "id: %s\n", fp);
			آزاد(fp);
		}
	}
	واپس ret;
}
