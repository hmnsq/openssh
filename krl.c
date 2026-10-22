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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/tree.h>
#ضمن <sys/queue.h>

#ضمن <errno.h>
#ضمن <limits.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <time.h>

#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "sshkey.h"
#ضمن "misc.h"
#ضمن "log.h"
#ضمن "digest.h"
#ضمن "bitmap.h"
#ضمن "utf8.h"

#ضمن "krl.h"

/* #define DEBUG_KRL */
#اگر_تعریف_شده DEBUG_KRL
# define KRL_DBG(x) debug3_f x
#وإلا
# define KRL_DBG(x)
#پایان_اگر

/*
 * Trees of revoked serial numbers, key IDs and keys. This allows
 * quick searching, querying and producing lists in canonical order.
 */

/* Tree of serial numbers. XXX make smarter: really need a real sparse bitmap */
بنية revoked_serial {
	uint64_t lo, hi;
	RB_مدخل(revoked_serial) درخت_مدخل;
};
ساكن صحيح serial_cmp(بنية revoked_serial *a, بنية revoked_serial *b);
RB_سر(revoked_serial_درخت, revoked_serial);
RB_GENERATE_STATIC(revoked_serial_درخت, revoked_serial, درخت_مدخل, serial_cmp)

/* Tree of key IDs */
بنية revoked_کلید_id {
	حرف *کلید_id;
	RB_مدخل(revoked_کلید_id) درخت_مدخل;
};
ساكن صحيح کلید_id_cmp(بنية revoked_کلید_id *a, بنية revoked_کلید_id *b);
RB_سر(revoked_کلید_id_درخت, revoked_کلید_id);
RB_GENERATE_STATIC(revoked_کلید_id_درخت, revoked_کلید_id, درخت_مدخل, کلید_id_cmp)

/* Tree of blobs (used for keys and fingerprints) */
بنية revoked_blob {
	u_char *blob;
	اندازه_t len;
	RB_مدخل(revoked_blob) درخت_مدخل;
};
ساكن صحيح blob_cmp(بنية revoked_blob *a, بنية revoked_blob *b);
RB_سر(revoked_blob_درخت, revoked_blob);
RB_GENERATE_STATIC(revoked_blob_درخت, revoked_blob, درخت_مدخل, blob_cmp)

/* Tracks revoked certs for a single CA */
بنية revoked_certs {
	بنية sshkey *ca_کلید;
	بنية revoked_serial_درخت revoked_serials;
	بنية revoked_کلید_id_درخت revoked_کلید_ids;
	TAILQ_ENTRY(revoked_certs) مدخل;
};
TAILQ_HEAD(revoked_certs_list, revoked_certs);

بنية ssh_krl {
	uint64_t krl_نسخه;
	uint64_t generated_date;
	uint64_t flags;
	حرف *comment;
	بنية revoked_blob_درخت revoked_کلیدها;
	بنية revoked_blob_درخت revoked_sha1s;
	بنية revoked_blob_درخت revoked_sha256s;
	بنية revoked_certs_list revoked_certs;
};

/* Return equal if a and b overlap */
ساكن صحيح
serial_cmp(بنية revoked_serial *a, بنية revoked_serial *b)
{
	إذا (a->hi >= b->lo && a->lo <= b->hi)
		أرجع 0;
	أرجع a->lo < b->lo ? -1 : 1;
}

ساكن صحيح
کلید_id_cmp(بنية revoked_کلید_id *a, بنية revoked_کلید_id *b)
{
	أرجع strcmp(a->کلید_id, b->کلید_id);
}

ساكن صحيح
blob_cmp(بنية revoked_blob *a, بنية revoked_blob *b)
{
	صحيح r;

	إذا (a->len != b->len) {
		إذا ((r = memcmp(a->blob, b->blob, MINIMUM(a->len, b->len))) != 0)
			أرجع r;
		أرجع a->len > b->len ? 1 : -1;
	} وإلا
		أرجع memcmp(a->blob, b->blob, a->len);
}

بنية ssh_krl *
ssh_krl_init(فراغ)
{
	بنية ssh_krl *krl;

	إذا ((krl = حافظه_صفر_بده(1, حجم(*krl))) == عدم)
		أرجع عدم;
	RB_INIT(&krl->revoked_کلیدها);
	RB_INIT(&krl->revoked_sha1s);
	RB_INIT(&krl->revoked_sha256s);
	TAILQ_INIT(&krl->revoked_certs);
	أرجع krl;
}

ساكن فراغ
revoked_certs_free(بنية revoked_certs *rc)
{
	بنية revoked_serial *rs, *trs;
	بنية revoked_کلید_id *rki, *trki;

	إذا (rc == عدم)
		أرجع;
	RB_FOREACH_امن(rs, revoked_serial_درخت, &rc->revoked_serials, trs) {
		RB_REMOVE(revoked_serial_درخت, &rc->revoked_serials, rs);
		حرر(rs);
	}
	RB_FOREACH_امن(rki, revoked_کلید_id_درخت, &rc->revoked_کلید_ids, trki) {
		RB_REMOVE(revoked_کلید_id_درخت, &rc->revoked_کلید_ids, rki);
		حرر(rki->کلید_id);
		حرر(rki);
	}
	sshkey_free(rc->ca_کلید);
	freezero(rc, حجم(*rc));
}

فراغ
ssh_krl_free(بنية ssh_krl *krl)
{
	بنية revoked_blob *rb, *trb;
	بنية revoked_certs *rc, *trc;

	إذا (krl == عدم)
		أرجع;

	حرر(krl->comment);
	RB_FOREACH_امن(rb, revoked_blob_درخت, &krl->revoked_کلیدها, trb) {
		RB_REMOVE(revoked_blob_درخت, &krl->revoked_کلیدها, rb);
		حرر(rb->blob);
		حرر(rb);
	}
	RB_FOREACH_امن(rb, revoked_blob_درخت, &krl->revoked_sha1s, trb) {
		RB_REMOVE(revoked_blob_درخت, &krl->revoked_sha1s, rb);
		حرر(rb->blob);
		حرر(rb);
	}
	RB_FOREACH_امن(rb, revoked_blob_درخت, &krl->revoked_sha256s, trb) {
		RB_REMOVE(revoked_blob_درخت, &krl->revoked_sha256s, rb);
		حرر(rb->blob);
		حرر(rb);
	}
	TAILQ_FOREACH_امن(rc, &krl->revoked_certs, مدخل, trc) {
		TAILQ_REMOVE(&krl->revoked_certs, rc, مدخل);
		revoked_certs_free(rc);
	}
	حرر(krl);
}

فراغ
ssh_krl_مجموعه_نسخه(بنية ssh_krl *krl, uint64_t نسخه)
{
	krl->krl_نسخه = نسخه;
}

صحيح
ssh_krl_مجموعه_comment(بنية ssh_krl *krl, ثابت حرف *comment)
{
	حرر(krl->comment);
	إذا ((krl->comment = strdup(comment)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	أرجع 0;
}

/*
 * Find the revoked_certs struct for a CA key. If allow_create is set then
 * create a new one in the tree if one did not exist already.
 */
ساكن صحيح
revoked_certs_for_ca_کلید(بنية ssh_krl *krl, ثابت بنية sshkey *ca_کلید,
    بنية revoked_certs **rcp, صحيح allow_create)
{
	بنية revoked_certs *rc;
	صحيح r;

	*rcp = عدم;
	TAILQ_FOREACH(rc, &krl->revoked_certs, مدخل) {
		إذا ((ca_کلید == عدم && rc->ca_کلید == عدم) ||
		    sshkey_equal(rc->ca_کلید, ca_کلید)) {
			*rcp = rc;
			أرجع 0;
		}
	}
	إذا (!allow_create)
		أرجع 0;
	/* If this CA doesn't exist in the list then add it now */
	إذا ((rc = حافظه_صفر_بده(1, حجم(*rc))) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا (ca_کلید == عدم)
		rc->ca_کلید = عدم;
	وإلا إذا ((r = sshkey_from_خصوصی(ca_کلید, &rc->ca_کلید)) != 0) {
		حرر(rc);
		أرجع r;
	}
	RB_INIT(&rc->revoked_serials);
	RB_INIT(&rc->revoked_کلید_ids);
	TAILQ_INSERT_TAIL(&krl->revoked_certs, rc, مدخل);
	KRL_DBG(("new CA %s", ca_کلید == عدم ? "*" : sshkey_type(ca_کلید)));
	*rcp = rc;
	أرجع 0;
}

ساكن صحيح
درج_serial_range(بنية revoked_serial_درخت *rt, uint64_t lo, uint64_t hi)
{
	بنية revoked_serial rs, *ers, *crs, *irs;

	KRL_DBG(("insert %llu:%llu",
	    (بیعلامت دراز دراز)lo, (بیعلامت دراز دراز)hi));
	memset(&rs, 0, حجم(rs));
	rs.lo = lo;
	rs.hi = hi;
	ers = RB_NFIND(revoked_serial_درخت, rt, &rs);
	إذا (ers == عدم || serial_cmp(ers, &rs) != 0) {
		/* No entry matches. Just insert */
		إذا ((irs = حافظه_بده(حجم(rs))) == عدم)
			أرجع SSH_ERR_ALLOC_FAIL;
		کپی_حافظه(irs, &rs, حجم(*irs));
		ers = RB_درج(revoked_serial_درخت, rt, irs);
		إذا (ers != عدم) {
			KRL_DBG(("bad: ers != NULL"));
			/* Shouldn't happen */
			حرر(irs);
			أرجع SSH_ERR_داخلی_ERROR;
		}
		ers = irs;
	} وإلا {
		KRL_DBG(("overlap found %llu:%llu",
		    (بیعلامت دراز دراز)ers->lo, (بیعلامت دراز دراز)ers->hi));
		/*
		 * The inserted entry overlaps an existing one. Grow the
		 * existing entry.
		 */
		إذا (ers->lo > lo)
			ers->lo = lo;
		إذا (ers->hi < hi)
			ers->hi = hi;
	}

	/*
	 * The inserted or revised range might overlap or abut adjacent ones;
	 * coalesce as necessary.
	 */

	/* Check predecessors */
	طالما ((crs = RB_PREV(revoked_serial_درخت, rt, ers)) != عدم) {
		KRL_DBG(("pred %llu:%llu",
		    (بیعلامت دراز دراز)crs->lo, (بیعلامت دراز دراز)crs->hi));
		إذا (ers->lo != 0 && crs->hi < ers->lo - 1)
			اكسر;
		/* This entry overlaps. */
		إذا (crs->lo < ers->lo) {
			ers->lo = crs->lo;
			KRL_DBG(("pred extend %llu:%llu",
			    (بیعلامت دراز دراز)ers->lo,
			    (بیعلامت دراز دراز)ers->hi));
		}
		RB_REMOVE(revoked_serial_درخت, rt, crs);
		حرر(crs);
	}
	/* Check successors */
	طالما ((crs = RB_بعدی(revoked_serial_درخت, rt, ers)) != عدم) {
		KRL_DBG(("succ %llu:%llu",
		    (بیعلامت دراز دراز)crs->lo, (بیعلامت دراز دراز)crs->hi));
		إذا (ers->hi != (uint64_t)-1 && crs->lo > ers->hi + 1)
			اكسر;
		/* This entry overlaps. */
		إذا (crs->hi > ers->hi) {
			ers->hi = crs->hi;
			KRL_DBG(("succ extend %llu:%llu",
			    (بیعلامت دراز دراز)ers->lo,
			    (بیعلامت دراز دراز)ers->hi));
		}
		RB_REMOVE(revoked_serial_درخت, rt, crs);
		حرر(crs);
	}
	KRL_DBG(("done, final %llu:%llu",
	    (بیعلامت دراز دراز)ers->lo, (بیعلامت دراز دراز)ers->hi));
	أرجع 0;
}

صحيح
ssh_krl_revoke_cert_by_serial(بنية ssh_krl *krl, ثابت بنية sshkey *ca_کلید,
    uint64_t serial)
{
	أرجع ssh_krl_revoke_cert_by_serial_range(krl, ca_کلید, serial, serial);
}

صحيح
ssh_krl_revoke_cert_by_serial_range(بنية ssh_krl *krl,
    ثابت بنية sshkey *ca_کلید, uint64_t lo, uint64_t hi)
{
	بنية revoked_certs *rc;
	صحيح r;

	إذا (lo > hi || lo == 0)
		أرجع SSH_ERR_INVALID_آرگومان;
	إذا ((r = revoked_certs_for_ca_کلید(krl, ca_کلید, &rc, 1)) != 0)
		أرجع r;
	أرجع درج_serial_range(&rc->revoked_serials, lo, hi);
}

صحيح
ssh_krl_revoke_cert_by_کلید_id(بنية ssh_krl *krl, ثابت بنية sshkey *ca_کلید,
    ثابت حرف *کلید_id)
{
	بنية revoked_کلید_id *rki, *erki;
	بنية revoked_certs *rc;
	صحيح r;

	إذا ((r = revoked_certs_for_ca_کلید(krl, ca_کلید, &rc, 1)) != 0)
		أرجع r;

	KRL_DBG(("revoke %s", کلید_id));
	إذا ((rki = حافظه_صفر_بده(1, حجم(*rki))) == عدم ||
	    (rki->کلید_id = strdup(کلید_id)) == عدم) {
		حرر(rki);
		أرجع SSH_ERR_ALLOC_FAIL;
	}
	erki = RB_درج(revoked_کلید_id_درخت, &rc->revoked_کلید_ids, rki);
	إذا (erki != عدم) {
		حرر(rki->کلید_id);
		حرر(rki);
	}
	أرجع 0;
}

/* Convert "key" to a public key blob without any certificate information */
ساكن صحيح
plain_کلید_blob(ثابت بنية sshkey *کلید, u_char **blob, اندازه_t *blen)
{
	بنية sshkey *kcopy;
	صحيح r;

	إذا ((r = sshkey_from_خصوصی(کلید, &kcopy)) != 0)
		أرجع r;
	إذا (sshkey_is_cert(kcopy)) {
		إذا ((r = sshkey_drop_cert(kcopy)) != 0) {
			sshkey_free(kcopy);
			أرجع r;
		}
	}
	r = sshkey_مقصد_blob(kcopy, blob, blen);
	sshkey_free(kcopy);
	أرجع r;
}

/* Revoke a key blob. Ownership of blob is transferred to the tree */
ساكن صحيح
revoke_blob(بنية revoked_blob_درخت *rbt, u_char *blob, اندازه_t len)
{
	بنية revoked_blob *rb, *erb;

	إذا ((rb = حافظه_صفر_بده(1, حجم(*rb))) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	rb->blob = blob;
	rb->len = len;
	erb = RB_درج(revoked_blob_درخت, rbt, rb);
	إذا (erb != عدم) {
		حرر(rb->blob);
		حرر(rb);
	}
	أرجع 0;
}

صحيح
ssh_krl_revoke_کلید_explicit(بنية ssh_krl *krl, ثابت بنية sshkey *کلید)
{
	u_char *blob;
	اندازه_t len;
	صحيح r;

	debug3_f("revoke type %s", sshkey_type(کلید));
	إذا ((r = plain_کلید_blob(کلید, &blob, &len)) != 0)
		أرجع r;
	أرجع revoke_blob(&krl->revoked_کلیدها, blob, len);
}

ساكن صحيح
revoke_by_hash(بنية revoked_blob_درخت *هدف, ثابت u_char *p, اندازه_t len)
{
	u_char *blob;
	صحيح r;

	/* need to copy hash, as revoke_blob steals ownership */
	إذا ((blob = حافظه_بده(len)) == عدم)
		أرجع SSH_ERR_SYSTEM_ERROR;
	کپی_حافظه(blob, p, len);
	إذا ((r = revoke_blob(هدف, blob, len)) != 0) {
		حرر(blob);
		أرجع r;
	}
	أرجع 0;
}

صحيح
ssh_krl_revoke_کلید_sha1(بنية ssh_krl *krl, ثابت u_char *p, اندازه_t len)
{
	debug3_f("revoke by sha1");
	إذا (len != 20)
		أرجع SSH_ERR_INVALID_FORMAT;
	أرجع revoke_by_hash(&krl->revoked_sha1s, p, len);
}

صحيح
ssh_krl_revoke_کلید_sha256(بنية ssh_krl *krl, ثابت u_char *p, اندازه_t len)
{
	debug3_f("revoke by sha256");
	إذا (len != 32)
		أرجع SSH_ERR_INVALID_FORMAT;
	أرجع revoke_by_hash(&krl->revoked_sha256s, p, len);
}

صحيح
ssh_krl_revoke_کلید(بنية ssh_krl *krl, ثابت بنية sshkey *کلید)
{
	/* XXX replace with SHA256? */
	إذا (!sshkey_is_cert(کلید))
		أرجع ssh_krl_revoke_کلید_explicit(krl, کلید);

	إذا (کلید->cert->serial == 0) {
		أرجع ssh_krl_revoke_cert_by_کلید_id(krl,
		    کلید->cert->signature_کلید,
		    کلید->cert->کلید_id);
	} وإلا {
		أرجع ssh_krl_revoke_cert_by_serial(krl,
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
ساكن صحيح
انتخاب_بعدی_state(صحيح current_state, uint64_t contig, صحيح final,
    uint64_t آخرین_gap, uint64_t بعدی_gap, اندازه_t bitmap_len,
    صحيح *force_new_section)
{
	صحيح new_state;
	uint64_t هزینه, هزینه_list, هزینه_range, هزینه_bitmap, هزینه_bitmap_restart;

	/*
	 * Avoid unsigned overflows.
	 * The limits are high enough to avoid confusing the calculations.
	 */
	contig = MINIMUM(contig, 1ULL<<31);
	آخرین_gap = MINIMUM(آخرین_gap, 1ULL<<31);
	بعدی_gap = MINIMUM(بعدی_gap, 1ULL<<31);

	/*
	 * Calculate the cost to switch from the current state to candidates.
	 * NB. range sections only ever contain a single range, so their
	 * switching cost is independent of the current_state.
	 */
	هزینه_list = هزینه_bitmap = هزینه_bitmap_restart = 0;
	هزینه_range = 8;
	بدل (current_state) {
	حالة KRL_SECTION_CERT_SERIAL_LIST:
		هزینه_bitmap_restart = هزینه_bitmap = 8 + 64;
		اكسر;
	حالة KRL_SECTION_CERT_SERIAL_BITMAP:
		هزینه_list = 8;
		هزینه_bitmap_restart = 8 + 64;
		اكسر;
	حالة KRL_SECTION_CERT_SERIAL_RANGE:
	حالة 0:
		هزینه_bitmap_restart = هزینه_bitmap = 8 + 64;
		هزینه_list = 8;
	}

	/* Estimate base cost in bits of each section type */
	هزینه_list += 64 * contig + (final ? 0 : 8+64);
	هزینه_range += (2 * 64) + (final ? 0 : 8+64);
	هزینه_bitmap += آخرین_gap + contig + (final ? 0 : MINIMUM(بعدی_gap, 8+64));
	هزینه_bitmap_restart += contig + (final ? 0 : MINIMUM(بعدی_gap, 8+64));

	/* Convert to byte costs for actual comparison */
	هزینه_list = (هزینه_list + 7) / 8;
	هزینه_bitmap = (هزینه_bitmap + 7) / 8;
	هزینه_bitmap_restart = (هزینه_bitmap_restart + 7) / 8;
	هزینه_range = (هزینه_range + 7) / 8;

	/* Ensure that we never emit a bitmap larger than sshbuf can handle */
	إذا (bitmap_len + هزینه_bitmap >= SSHBUF_MAX_BIGNUM) {
		KRL_DBG(("bitmap overfull len=%zu cost=%llu max=%u",
		    bitmap_len, (بیعلامت دراز دراز)هزینه_bitmap,
		    SSHBUF_MAX_BIGNUM));
		هزینه_bitmap = (uint64_t)-1;
	}

	/* Now pick the best choice */
	*force_new_section = 0;
	new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
	هزینه = هزینه_bitmap;
	إذا (هزینه_range < هزینه) {
		new_state = KRL_SECTION_CERT_SERIAL_RANGE;
		هزینه = هزینه_range;
	}
	إذا (هزینه_list < هزینه) {
		new_state = KRL_SECTION_CERT_SERIAL_LIST;
		هزینه = هزینه_list;
	}
	إذا (هزینه_bitmap_restart < هزینه) {
		new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
		*force_new_section = 1;
		هزینه = هزینه_bitmap_restart;
	}
	KRL_DBG(("contig %llu last_gap %llu next_gap %llu final %d, costs:"
	    "list %llu range %llu bitmap %llu new bitmap %llu, "
	    "selected 0x%02x%s", (دراز دراز بیعلامت)contig,
	    (دراز دراز بیعلامت)آخرین_gap, (دراز دراز بیعلامت)بعدی_gap, final,
	    (دراز دراز بیعلامت)هزینه_list, (دراز دراز بیعلامت)هزینه_range,
	    (دراز دراز بیعلامت)هزینه_bitmap,
	    (دراز دراز بیعلامت)هزینه_bitmap_restart, new_state,
	    *force_new_section ? " restart" : ""));
	أرجع new_state;
}

ساكن صحيح
put_bitmap(بنية sshbuf *buf, بنية bitmap *bitmap)
{
	اندازه_t len;
	u_char *blob;
	صحيح r;

	len = bitmap_nbytes(bitmap);
	إذا ((blob = حافظه_بده(len)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا (bitmap_مقصد_string(bitmap, blob, len) != 0) {
		حرر(blob);
		أرجع SSH_ERR_داخلی_ERROR;
	}
	r = sshbuf_put_bignum2_بایتها(buf, blob, len);
	حرر(blob);
	أرجع r;
}

/* Generate a KRL_SECTION_CERTIFICATES KRL section */
ساكن صحيح
revoked_certs_generate(بنية revoked_certs *rc, بنية sshbuf *buf)
{
	صحيح final, force_new_sect, r = SSH_ERR_داخلی_ERROR;
	uint64_t i, contig, gap, آخرین = 0, bitmap_شروع = 0;
	بنية revoked_serial *rs, *nrs;
	بنية revoked_کلید_id *rki;
	صحيح بعدی_state, state = 0;
	اندازه_t bitmap_len;
	بنية sshbuf *sect;
	بنية bitmap *bitmap = عدم;

	إذا ((sect = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;

	/* Store the header: optional CA scope key, reserved */
	إذا (rc->ca_کلید == عدم) {
		إذا ((r = sshbuf_put_string(buf, عدم, 0)) != 0)
			اذهب بیرون;
	} وإلا {
		إذا ((r = sshkey_puts(rc->ca_کلید, buf)) != 0)
			اذهب بیرون;
	}
	إذا ((r = sshbuf_put_string(buf, عدم, 0)) != 0)
		اذهب بیرون;

	/* Store the revoked serials.  */
	لكل (rs = RB_MIN(revoked_serial_درخت, &rc->revoked_serials);
	     rs != عدم;
	     rs = RB_بعدی(revoked_serial_درخت, &rc->revoked_serials, rs)) {
		KRL_DBG(("serial %llu:%llu state 0x%02x",
		    (دراز دراز بیعلامت)rs->lo, (دراز دراز بیعلامت)rs->hi,
		    state));

		/* Check contiguous length and gap to next section (if any) */
		nrs = RB_بعدی(revoked_serial_درخت, &rc->revoked_serials, rs);
		final = nrs == عدم;
		gap = nrs == عدم ? 0 : nrs->lo - rs->hi;
		contig = 1 + (rs->hi - rs->lo);

		bitmap_len = state == KRL_SECTION_CERT_SERIAL_BITMAP ?
		    bitmap_nbytes(bitmap) : 0;

		/* Choose next state based on these */
		بعدی_state = انتخاب_بعدی_state(state, contig, final,
		    state == 0 ? 0 : rs->lo - آخرین, gap, bitmap_len,
		    &force_new_sect);

		/*
		 * If the current section is a range section or has a different
		 * type to the next section, then finish it off now.
		 */
		إذا (state != 0 && (force_new_sect || بعدی_state != state ||
		    state == KRL_SECTION_CERT_SERIAL_RANGE)) {
			KRL_DBG(("finish state 0x%02x", state));
			بدل (state) {
			حالة KRL_SECTION_CERT_SERIAL_LIST:
			حالة KRL_SECTION_CERT_SERIAL_RANGE:
				اكسر;
			حالة KRL_SECTION_CERT_SERIAL_BITMAP:
				إذا ((r = put_bitmap(sect, bitmap)) != 0)
					اذهب بیرون;
				bitmap_free(bitmap);
				bitmap = عدم;
				اكسر;
			}
			إذا ((r = sshbuf_put_u8(buf, state)) != 0 ||
			    (r = sshbuf_put_stringb(buf, sect)) != 0)
				اذهب بیرون;
			sshbuf_reset(sect);
		}

		/* If we are starting a new section then prepare it now */
		إذا (بعدی_state != state || force_new_sect) {
			KRL_DBG(("start state 0x%02x",
			    بعدی_state));
			state = بعدی_state;
			sshbuf_reset(sect);
			بدل (state) {
			حالة KRL_SECTION_CERT_SERIAL_LIST:
			حالة KRL_SECTION_CERT_SERIAL_RANGE:
				اكسر;
			حالة KRL_SECTION_CERT_SERIAL_BITMAP:
				إذا ((bitmap = bitmap_new()) == عدم) {
					r = SSH_ERR_ALLOC_FAIL;
					اذهب بیرون;
				}
				bitmap_شروع = rs->lo;
				إذا ((r = sshbuf_put_u64(sect,
				    bitmap_شروع)) != 0)
					اذهب بیرون;
				اكسر;
			}
		}

		/* Perform section-specific processing */
		بدل (state) {
		حالة KRL_SECTION_CERT_SERIAL_LIST:
			لكل (i = 0; i < contig; i++) {
				إذا ((r = sshbuf_put_u64(sect, rs->lo + i)) != 0)
					اذهب بیرون;
			}
			اكسر;
		حالة KRL_SECTION_CERT_SERIAL_RANGE:
			إذا ((r = sshbuf_put_u64(sect, rs->lo)) != 0 ||
			    (r = sshbuf_put_u64(sect, rs->hi)) != 0)
				اذهب بیرون;
			اكسر;
		حالة KRL_SECTION_CERT_SERIAL_BITMAP:
			إذا (rs->lo - bitmap_شروع > بیشترین_صحیح) {
				r = SSH_ERR_INVALID_FORMAT;
				error_f("insane bitmap gap");
				اذهب بیرون;
			}
			لكل (i = 0; i < contig; i++) {
				إذا (bitmap_مجموعه_بیت(bitmap,
				    rs->lo + i - bitmap_شروع) != 0) {
					r = SSH_ERR_ALLOC_FAIL;
					اذهب بیرون;
				}
			}
			اكسر;
		}
		آخرین = rs->hi;
	}
	/* Flush the remaining section, if any */
	إذا (state != 0) {
		KRL_DBG(("serial final flush for state 0x%02x", state));
		بدل (state) {
		حالة KRL_SECTION_CERT_SERIAL_LIST:
		حالة KRL_SECTION_CERT_SERIAL_RANGE:
			اكسر;
		حالة KRL_SECTION_CERT_SERIAL_BITMAP:
			إذا ((r = put_bitmap(sect, bitmap)) != 0)
				اذهب بیرون;
			bitmap_free(bitmap);
			bitmap = عدم;
			اكسر;
		}
		إذا ((r = sshbuf_put_u8(buf, state)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب بیرون;
	}
	KRL_DBG(("serial done "));

	/* Now output a section for any revocations by key ID */
	sshbuf_reset(sect);
	RB_FOREACH(rki, revoked_کلید_id_درخت, &rc->revoked_کلید_ids) {
		KRL_DBG(("key ID %s", rki->کلید_id));
		إذا ((r = sshbuf_put_cstring(sect, rki->کلید_id)) != 0)
			اذهب بیرون;
	}
	إذا (sshbuf_len(sect) != 0) {
		إذا ((r = sshbuf_put_u8(buf, KRL_SECTION_CERT_کلید_ID)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب بیرون;
	}
	r = 0;
 بیرون:
	bitmap_free(bitmap);
	sshbuf_free(sect);
	أرجع r;
}

صحيح
ssh_krl_مقصد_blob(بنية ssh_krl *krl, بنية sshbuf *buf)
{
	صحيح r = SSH_ERR_داخلی_ERROR;
	بنية revoked_certs *rc;
	بنية revoked_blob *rb;
	بنية sshbuf *sect;
	u_char *sblob = عدم;

	إذا (krl->generated_date == 0)
		krl->generated_date = time(عدم);

	إذا ((sect = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;

	/* Store the header */
	إذا ((r = sshbuf_put(buf, KRL_MAGIC, حجم(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_put_u32(buf, KRL_FORMAT_نسخه)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->krl_نسخه)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->generated_date)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->flags)) != 0 ||
	    (r = sshbuf_put_string(buf, عدم, 0)) != 0 ||
	    (r = sshbuf_put_cstring(buf, krl->comment)) != 0)
		اذهب بیرون;

	/* Store sections for revoked certificates */
	TAILQ_FOREACH(rc, &krl->revoked_certs, مدخل) {
		sshbuf_reset(sect);
		إذا ((r = revoked_certs_generate(rc, sect)) != 0)
			اذهب بیرون;
		إذا ((r = sshbuf_put_u8(buf, KRL_SECTION_CERTIFICATES)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب بیرون;
	}

	/* Finally, output sections for revocations by public key/hash */
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_درخت, &krl->revoked_کلیدها) {
		KRL_DBG(("key len %zu ", rb->len));
		إذا ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			اذهب بیرون;
	}
	إذا (sshbuf_len(sect) != 0) {
		إذا ((r = sshbuf_put_u8(buf, KRL_SECTION_EXPLICIT_کلید)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب بیرون;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_درخت, &krl->revoked_sha1s) {
		KRL_DBG(("hash len %zu ", rb->len));
		إذا ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			اذهب بیرون;
	}
	إذا (sshbuf_len(sect) != 0) {
		إذا ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA1)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب بیرون;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_درخت, &krl->revoked_sha256s) {
		KRL_DBG(("hash len %zu ", rb->len));
		إذا ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			اذهب بیرون;
	}
	إذا (sshbuf_len(sect) != 0) {
		إذا ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA256)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب بیرون;
	}
	/* success */
	r = 0;
 بیرون:
	حرر(sblob);
	sshbuf_free(sect);
	أرجع r;
}

ساكن فراغ
format_timestamp(uint64_t timestamp, حرف *ts, اندازه_t nts)
{
	time_t t;
	بنية tm *tm;

	t = timestamp;
	tm = localtime(&t);
	إذا (tm == عدم)
		strlcpy(ts, "<INVALID>", nts);
	وإلا {
		*ts = '\0';
		strftime(ts, nts, "%Y%m%dT%H%M%S", tm);
	}
}

ساكن صحيح
cert_extension_subsection(بنية sshbuf *subsect, بنية ssh_krl *krl)
{
	صحيح r = SSH_ERR_داخلی_ERROR;
	u_char critical = 1;
	بنية sshbuf *مقدار = عدم;
	حرف *name = عدم;

	إذا ((r = sshbuf_get_cstring(subsect, &name, عدم)) != 0 ||
	    (r = sshbuf_get_u8(subsect, &critical)) != 0 ||
	    (r = sshbuf_froms(subsect, &مقدار)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid certificate extension subsection");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بیرون;
	}
	إذا (sshbuf_len(subsect) != 0) {
		error("KRL has invalid certificate extension subsection: "
		    "trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بیرون;
	}
	debug_f("cert extension %s critical %u len %zu",
	    name, critical, sshbuf_len(مقدار));
	/* no extensions are currently supported */
	إذا (critical) {
		error("KRL contains unsupported critical certificate "
		    "subsection \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		اذهب بیرون;
	}
	/* success */
	r = 0;
 بیرون:
	حرر(name);
	sshbuf_free(مقدار);
	أرجع r;
}

ساكن صحيح
parse_revoked_certs(بنية sshbuf *buf, بنية ssh_krl *krl)
{
	صحيح r = SSH_ERR_داخلی_ERROR;
	u_char type;
	ثابت u_char *blob;
	اندازه_t blen, nbits;
	بنية sshbuf *subsect = عدم;
	uint64_t serial, serial_lo, serial_hi;
	بنية bitmap *bitmap = عدم;
	حرف *کلید_id = عدم;
	بنية sshkey *ca_کلید = عدم;

	إذا ((subsect = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;

	/* Header: key, reserved */
	إذا ((r = sshbuf_get_string_مستقیم(buf, &blob, &blen)) != 0 ||
	    (r = sshbuf_skip_string(buf)) != 0)
		اذهب بیرون;
	إذا (blen != 0 && (r = sshkey_from_blob(blob, blen, &ca_کلید)) != 0)
		اذهب بیرون;

	طالما (sshbuf_len(buf) > 0) {
		sshbuf_free(subsect);
		subsect = عدم;
		إذا ((r = sshbuf_get_u8(buf, &type)) != 0 ||
		    (r = sshbuf_froms(buf, &subsect)) != 0)
			اذهب بیرون;
		KRL_DBG(("subsection type 0x%02x", type));
		/* sshbuf_dump(subsect, stderr); */

		بدل (type) {
		حالة KRL_SECTION_CERT_SERIAL_LIST:
			طالما (sshbuf_len(subsect) > 0) {
				إذا ((r = sshbuf_get_u64(subsect, &serial)) != 0)
					اذهب بیرون;
				إذا ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_کلید, serial)) != 0)
					اذهب بیرون;
			}
			اكسر;
		حالة KRL_SECTION_CERT_SERIAL_RANGE:
			إذا ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_u64(subsect, &serial_hi)) != 0)
				اذهب بیرون;
			إذا ((r = ssh_krl_revoke_cert_by_serial_range(krl,
			    ca_کلید, serial_lo, serial_hi)) != 0)
				اذهب بیرون;
			اكسر;
		حالة KRL_SECTION_CERT_SERIAL_BITMAP:
			إذا ((bitmap = bitmap_new()) == عدم) {
				r = SSH_ERR_ALLOC_FAIL;
				اذهب بیرون;
			}
			إذا ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_bignum2_بایتها_مستقیم(subsect,
			    &blob, &blen)) != 0)
				اذهب بیرون;
			إذا (bitmap_from_string(bitmap, blob, blen) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				اذهب بیرون;
			}
			nbits = bitmap_nbits(bitmap);
			لكل (serial = 0; serial < (uint64_t)nbits; serial++) {
				إذا (serial > 0 && serial_lo + serial == 0) {
					error_f("bitmap wraps u64");
					r = SSH_ERR_INVALID_FORMAT;
					اذهب بیرون;
				}
				إذا (!bitmap_test_بیت(bitmap, serial))
					استمر;
				إذا ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_کلید, serial_lo + serial)) != 0)
					اذهب بیرون;
			}
			bitmap_free(bitmap);
			bitmap = عدم;
			اكسر;
		حالة KRL_SECTION_CERT_کلید_ID:
			طالما (sshbuf_len(subsect) > 0) {
				إذا ((r = sshbuf_get_cstring(subsect,
				    &کلید_id, عدم)) != 0)
					اذهب بیرون;
				إذا ((r = ssh_krl_revoke_cert_by_کلید_id(krl,
				    ca_کلید, کلید_id)) != 0)
					اذهب بیرون;
				حرر(کلید_id);
				کلید_id = عدم;
			}
			اكسر;
		حالة KRL_SECTION_CERT_EXTENSION:
			إذا ((r = cert_extension_subsection(subsect, krl)) != 0)
				اذهب بیرون;
			اكسر;
		افتراضي:
			error("Unsupported KRL certificate section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بیرون;
		}
		إذا (sshbuf_len(subsect) > 0) {
			error("KRL certificate section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بیرون;
		}
	}

	r = 0;
 بیرون:
	إذا (bitmap != عدم)
		bitmap_free(bitmap);
	حرر(کلید_id);
	sshkey_free(ca_کلید);
	sshbuf_free(subsect);
	أرجع r;
}

ساكن صحيح
blob_section(بنية sshbuf *sect, بنية revoked_blob_درخت *هدف_درخت,
    اندازه_t expected_len)
{
	u_char *rdata = عدم;
	اندازه_t rlen = 0;
	صحيح r;

	طالما (sshbuf_len(sect) > 0) {
		إذا ((r = sshbuf_get_string(sect, &rdata, &rlen)) != 0)
			أرجع r;
		إذا (expected_len != 0 && rlen != expected_len) {
			error_f("bad length");
			حرر(rdata);
			أرجع SSH_ERR_INVALID_FORMAT;
		}
		إذا ((r = revoke_blob(هدف_درخت, rdata, rlen)) != 0) {
			حرر(rdata);
			أرجع r;
		}
	}
	أرجع 0;
}

ساكن صحيح
extension_section(بنية sshbuf *sect, بنية ssh_krl *krl)
{
	صحيح r = SSH_ERR_داخلی_ERROR;
	u_char critical = 1;
	بنية sshbuf *مقدار = عدم;
	حرف *name = عدم;

	إذا ((r = sshbuf_get_cstring(sect, &name, عدم)) != 0 ||
	    (r = sshbuf_get_u8(sect, &critical)) != 0 ||
	    (r = sshbuf_froms(sect, &مقدار)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid extension section");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بیرون;
	}
	إذا (sshbuf_len(sect) != 0) {
		error("KRL has invalid extension section: trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بیرون;
	}
	debug_f("extension %s critical %u len %zu",
	    name, critical, sshbuf_len(مقدار));
	/* no extensions are currently supported */
	إذا (critical) {
		error("KRL contains unsupported critical section \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		اذهب بیرون;
	}
	/* success */
	r = 0;
 بیرون:
	حرر(name);
	sshbuf_free(مقدار);
	أرجع r;
}

/* Attempt to parse a KRL */
صحيح
ssh_krl_from_blob(بنية sshbuf *buf, بنية ssh_krl **krlp)
{
	بنية sshbuf *copy = عدم, *sect = عدم;
	بنية ssh_krl *krl = عدم;
	حرف timestamp[64];
	صحيح r = SSH_ERR_داخلی_ERROR;
	u_char type;
	u_int format_نسخه;

	*krlp = عدم;

	/* KRL must begin with magic string */
	إذا ((r = sshbuf_cmp(buf, 0, KRL_MAGIC, حجم(KRL_MAGIC) - 1)) != 0) {
		debug2_f("bad KRL magic header");
		أرجع SSH_ERR_KRL_BAD_MAGIC;
	}

	إذا ((krl = ssh_krl_init()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		error_f("alloc failed");
		اذهب بیرون;
	}
	/* Don't modify buffer */
	إذا ((copy = sshbuf_fromb(buf)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	إذا ((r = sshbuf_consume(copy, حجم(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_get_u32(copy, &format_نسخه)) != 0)
		اذهب بیرون;
	إذا (format_نسخه != KRL_FORMAT_نسخه) {
		error_f("unsupported KRL format version %u", format_نسخه);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بیرون;
	}
	إذا ((r = sshbuf_get_u64(copy, &krl->krl_نسخه)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->generated_date)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->flags)) != 0 ||
	    (r = sshbuf_skip_string(copy)) != 0 ||
	    (r = sshbuf_get_cstring(copy, &krl->comment, عدم)) != 0) {
		error_fr(r, "parse KRL header");
		اذهب بیرون;
	}
	format_timestamp(krl->generated_date, timestamp, حجم(timestamp));
	debug("KRL version %llu generated at %s%s%s",
	    (دراز دراز بیعلامت)krl->krl_نسخه, timestamp,
	    *krl->comment ? ": " : "", krl->comment);

	/* Parse and load the KRL sections. */
	طالما (sshbuf_len(copy) > 0) {
		sshbuf_free(sect);
		sect = عدم;
		إذا ((r = sshbuf_get_u8(copy, &type)) != 0 ||
		    (r = sshbuf_froms(copy, &sect)) != 0)
			اذهب بیرون;
		KRL_DBG(("section 0x%02x", type));

		بدل (type) {
		حالة KRL_SECTION_CERTIFICATES:
			إذا ((r = parse_revoked_certs(sect, krl)) != 0)
				اذهب بیرون;
			اكسر;
		حالة KRL_SECTION_EXPLICIT_کلید:
			إذا ((r = blob_section(sect,
			    &krl->revoked_کلیدها, 0)) != 0)
				اذهب بیرون;
			اكسر;
		حالة KRL_SECTION_FINGERPRINT_SHA1:
			إذا ((r = blob_section(sect,
			    &krl->revoked_sha1s, 20)) != 0)
				اذهب بیرون;
			اكسر;
		حالة KRL_SECTION_FINGERPRINT_SHA256:
			إذا ((r = blob_section(sect,
			    &krl->revoked_sha256s, 32)) != 0)
				اذهب بیرون;
			اكسر;
		حالة KRL_SECTION_EXTENSION:
			إذا ((r = extension_section(sect, krl)) != 0)
				اذهب بیرون;
			اكسر;
		حالة KRL_SECTION_SIGNATURE:
			/* Handled above, but still need to stay in synch */
			sshbuf_free(sect);
			sect = عدم;
			إذا ((r = sshbuf_skip_string(copy)) != 0)
				اذهب بیرون;
			اكسر;
		افتراضي:
			error("Unsupported KRL section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بیرون;
		}
		إذا (sect != عدم && sshbuf_len(sect) > 0) {
			error("KRL section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بیرون;
		}
	}

	/* Success */
	*krlp = krl;
	r = 0;
 بیرون:
	إذا (r != 0)
		ssh_krl_free(krl);
	sshbuf_free(copy);
	sshbuf_free(sect);
	أرجع r;
}

/* Checks certificate serial number and key ID revocation */
ساكن صحيح
is_cert_revoked(ثابت بنية sshkey *کلید, بنية revoked_certs *rc)
{
	بنية revoked_serial rs, *ers;
	بنية revoked_کلید_id rki, *erki;

	/* Check revocation by cert key ID */
	memset(&rki, 0, حجم(rki));
	rki.کلید_id = کلید->cert->کلید_id;
	erki = RB_پیدا_کن(revoked_کلید_id_درخت, &rc->revoked_کلید_ids, &rki);
	إذا (erki != عدم) {
		KRL_DBG(("revoked by key ID"));
		أرجع SSH_ERR_کلید_REVOKED;
	}

	/*
	 * Zero serials numbers are ignored (it's the default when the
	 * CA doesn't specify one).
	 */
	إذا (کلید->cert->serial == 0)
		أرجع 0;

	memset(&rs, 0, حجم(rs));
	rs.lo = rs.hi = کلید->cert->serial;
	ers = RB_پیدا_کن(revoked_serial_درخت, &rc->revoked_serials, &rs);
	إذا (ers != عدم) {
		KRL_DBG(("revoked serial %llu matched %llu:%llu",
		    (بیعلامت دراز دراز)کلید->cert->serial,
		    (بیعلامت دراز دراز)ers->lo,
		    (بیعلامت دراز دراز)ers->hi));
		أرجع SSH_ERR_کلید_REVOKED;
	}
	أرجع 0;
}

/* Checks whether a given key/cert is revoked. Does not check its CA */
ساكن صحيح
is_کلید_revoked(بنية ssh_krl *krl, ثابت بنية sshkey *کلید)
{
	بنية revoked_blob rb, *erb;
	بنية revoked_certs *rc;
	صحيح r;

	/* Check explicitly revoked hashes first */
	memset(&rb, 0, حجم(rb));
	إذا ((r = sshkey_fingerprint_raw(کلید, SSH_DIGEST_SHA1,
	    &rb.blob, &rb.len)) != 0)
		أرجع r;
	erb = RB_پیدا_کن(revoked_blob_درخت, &krl->revoked_sha1s, &rb);
	حرر(rb.blob);
	إذا (erb != عدم) {
		KRL_DBG(("revoked by key SHA1"));
		أرجع SSH_ERR_کلید_REVOKED;
	}
	memset(&rb, 0, حجم(rb));
	إذا ((r = sshkey_fingerprint_raw(کلید, SSH_DIGEST_SHA256,
	    &rb.blob, &rb.len)) != 0)
		أرجع r;
	erb = RB_پیدا_کن(revoked_blob_درخت, &krl->revoked_sha256s, &rb);
	حرر(rb.blob);
	إذا (erb != عدم) {
		KRL_DBG(("revoked by key SHA256"));
		أرجع SSH_ERR_کلید_REVOKED;
	}

	/* Next, explicit keys */
	memset(&rb, 0, حجم(rb));
	إذا ((r = plain_کلید_blob(کلید, &rb.blob, &rb.len)) != 0)
		أرجع r;
	erb = RB_پیدا_کن(revoked_blob_درخت, &krl->revoked_کلیدها, &rb);
	حرر(rb.blob);
	إذا (erb != عدم) {
		KRL_DBG(("revoked by explicit key"));
		أرجع SSH_ERR_کلید_REVOKED;
	}

	إذا (!sshkey_is_cert(کلید))
		أرجع 0;

	/* Check cert revocation for the specified CA */
	إذا ((r = revoked_certs_for_ca_کلید(krl, کلید->cert->signature_کلید,
	    &rc, 0)) != 0)
		أرجع r;
	إذا (rc != عدم) {
		إذا ((r = is_cert_revoked(کلید, rc)) != 0)
			أرجع r;
	}
	/* Check cert revocation for the wildcard CA */
	إذا ((r = revoked_certs_for_ca_کلید(krl, عدم, &rc, 0)) != 0)
		أرجع r;
	إذا (rc != عدم) {
		إذا ((r = is_cert_revoked(کلید, rc)) != 0)
			أرجع r;
	}

	KRL_DBG(("%llu no match", (بیعلامت دراز دراز)کلید->cert->serial));
	أرجع 0;
}

صحيح
ssh_krl_check_کلید(بنية ssh_krl *krl, ثابت بنية sshkey *کلید)
{
	صحيح r;

	KRL_DBG(("checking key"));
	إذا ((r = is_کلید_revoked(krl, کلید)) != 0)
		أرجع r;
	إذا (sshkey_is_cert(کلید)) {
		debug2_f("checking CA key");
		إذا ((r = is_کلید_revoked(krl, کلید->cert->signature_کلید)) != 0)
			أرجع r;
	}
	KRL_DBG(("key okay"));
	أرجع 0;
}

صحيح
ssh_krl_file_شامل_است_کلید(ثابت حرف *مسیر, ثابت بنية sshkey *کلید)
{
	بنية sshbuf *krlbuf = عدم;
	بنية ssh_krl *krl = عدم;
	صحيح oerrno = 0, r;

	إذا (مسیر == عدم)
		أرجع 0;
	إذا ((r = sshbuf_بارگیری_file(مسیر, &krlbuf)) != 0) {
		oerrno = errno;
		اذهب بیرون;
	}
	إذا ((r = ssh_krl_from_blob(krlbuf, &krl)) != 0)
		اذهب بیرون;
	debug2_f("checking KRL %s", مسیر);
	r = ssh_krl_check_کلید(krl, کلید);
 بیرون:
	sshbuf_free(krlbuf);
	ssh_krl_free(krl);
	إذا (r != 0)
		errno = oerrno;
	أرجع r;
}

صحيح
krl_dump(بنية ssh_krl *krl, FILE *f)
{
	بنية sshkey *کلید = عدم;
	بنية revoked_blob *rb;
	بنية revoked_certs *rc;
	بنية revoked_serial *rs;
	بنية revoked_کلید_id *rki;
	صحيح r, ret = 0;
	حرف *fp, timestamp[64];

	/* Try to print in a KRL spec-compatible format */
	format_timestamp(krl->generated_date, timestamp, حجم(timestamp));
	fprintf(f, "# KRL version %llu\n", (بیعلامت دراز دراز)krl->krl_نسخه);
	fprintf(f, "# Generated at %s\n", timestamp);
	إذا (krl->comment != عدم && *krl->comment != '\0') {
		r = بیشترین_صحیح;
		asmprintf(&fp, بیشترین_صحیح, &r, "%s", krl->comment);
		fprintf(f, "# Comment: %s\n", fp);
		حرر(fp);
	}
	fputc('\n', f);

	RB_FOREACH(rb, revoked_blob_درخت, &krl->revoked_کلیدها) {
		إذا ((r = sshkey_from_blob(rb->blob, rb->len, &کلید)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			error_r(r, "parse KRL key");
			استمر;
		}
		إذا ((fp = sshkey_fingerprint(کلید, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == عدم) {
			ret = SSH_ERR_INVALID_FORMAT;
			error("sshkey_fingerprint failed");
			استمر;
		}
		fprintf(f, "hash: %s # %s\n", fp, sshkey_ssh_name(کلید));
		حرر(fp);
		حرر(کلید);
	}
	RB_FOREACH(rb, revoked_blob_درخت, &krl->revoked_sha256s) {
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "hash: SHA256:%s\n", fp);
		حرر(fp);
	}
	RB_FOREACH(rb, revoked_blob_درخت, &krl->revoked_sha1s) {
		/*
		 * There is not KRL spec keyword for raw SHA1 hashes, so
		 * print them as comments.
		 */
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "# hash SHA1:%s\n", fp);
		حرر(fp);
	}

	TAILQ_FOREACH(rc, &krl->revoked_certs, مدخل) {
		fputc('\n', f);
		إذا (rc->ca_کلید == عدم)
			fprintf(f, "# Wildcard CA\n");
		وإلا {
			إذا ((fp = sshkey_fingerprint(rc->ca_کلید,
			    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == عدم) {
				ret = SSH_ERR_INVALID_FORMAT;
				error("sshkey_fingerprint failed");
				استمر;
			}
			fprintf(f, "# CA key %s %s\n",
			    sshkey_ssh_name(rc->ca_کلید), fp);
			حرر(fp);
		}
		RB_FOREACH(rs, revoked_serial_درخت, &rc->revoked_serials) {
			إذا (rs->lo == rs->hi) {
				fprintf(f, "serial: %llu\n",
				    (بیعلامت دراز دراز)rs->lo);
			} وإلا {
				fprintf(f, "serial: %llu-%llu\n",
				    (بیعلامت دراز دراز)rs->lo,
				    (بیعلامت دراز دراز)rs->hi);
			}
		}
		RB_FOREACH(rki, revoked_کلید_id_درخت, &rc->revoked_کلید_ids) {
			/*
			 * We don't want key IDs with embedded newlines to
			 * mess up the display.
			 */
			r = بیشترین_صحیح;
			asmprintf(&fp, بیشترین_صحیح, &r, "%s", rki->کلید_id);
			fprintf(f, "id: %s\n", fp);
			حرر(fp);
		}
	}
	أرجع ret;
}
