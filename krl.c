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
#که_تعریف_شوی DEBUG_KRL
# define KRL_DBG(x) debug3_f x
#وإلا
# define KRL_DBG(x)
#د_که_پای

/*
 * Trees of revoked serial numbers, key IDs and keys. This allows
 * quick searching, querying and producing lists in canonical order.
 */

/* Tree of serial numbers. XXX make smarter: really need a real sparse bitmap */
بنية revoked_serial {
	uint64_t lo, hi;
	RB_ثبت(revoked_serial) ونه_ثبت;
};
ساكن صحيح serial_cmp(بنية revoked_serial *a, بنية revoked_serial *b);
RB_سر(revoked_serial_ونه, revoked_serial);
RB_GENERATE_STATIC(revoked_serial_ونه, revoked_serial, ونه_ثبت, serial_cmp)

/* Tree of key IDs */
بنية revoked_کلی_id {
	حرف *کلی_id;
	RB_ثبت(revoked_کلی_id) ونه_ثبت;
};
ساكن صحيح کلی_id_cmp(بنية revoked_کلی_id *a, بنية revoked_کلی_id *b);
RB_سر(revoked_کلی_id_ونه, revoked_کلی_id);
RB_GENERATE_STATIC(revoked_کلی_id_ونه, revoked_کلی_id, ونه_ثبت, کلی_id_cmp)

/* Tree of blobs (used for keys and fingerprints) */
بنية revoked_blob {
	u_char *blob;
	اندازه_t len;
	RB_ثبت(revoked_blob) ونه_ثبت;
};
ساكن صحيح blob_cmp(بنية revoked_blob *a, بنية revoked_blob *b);
RB_سر(revoked_blob_ونه, revoked_blob);
RB_GENERATE_STATIC(revoked_blob_ونه, revoked_blob, ونه_ثبت, blob_cmp)

/* Tracks revoked certs for a single CA */
بنية revoked_certs {
	بنية sshkey *ca_کلی;
	بنية revoked_serial_ونه revoked_serials;
	بنية revoked_کلی_id_ونه revoked_کلی_ids;
	TAILQ_ENTRY(revoked_certs) ثبت;
};
TAILQ_HEAD(revoked_certs_list, revoked_certs);

بنية ssh_krl {
	uint64_t krl_نسخه;
	uint64_t generated_date;
	uint64_t flags;
	حرف *comment;
	بنية revoked_blob_ونه revoked_کلیګانې;
	بنية revoked_blob_ونه revoked_sha1s;
	بنية revoked_blob_ونه revoked_sha256s;
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
کلی_id_cmp(بنية revoked_کلی_id *a, بنية revoked_کلی_id *b)
{
	أرجع strcmp(a->کلی_id, b->کلی_id);
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

	إذا ((krl = حافظه_صفر_ورکړه(1, حجم(*krl))) == عدم)
		أرجع عدم;
	RB_INIT(&krl->revoked_کلیګانې);
	RB_INIT(&krl->revoked_sha1s);
	RB_INIT(&krl->revoked_sha256s);
	TAILQ_INIT(&krl->revoked_certs);
	أرجع krl;
}

ساكن فراغ
revoked_certs_free(بنية revoked_certs *rc)
{
	بنية revoked_serial *rs, *trs;
	بنية revoked_کلی_id *rki, *trki;

	إذا (rc == عدم)
		أرجع;
	RB_FOREACH_خوندي(rs, revoked_serial_ونه, &rc->revoked_serials, trs) {
		RB_REMOVE(revoked_serial_ونه, &rc->revoked_serials, rs);
		حرر(rs);
	}
	RB_FOREACH_خوندي(rki, revoked_کلی_id_ونه, &rc->revoked_کلی_ids, trki) {
		RB_REMOVE(revoked_کلی_id_ونه, &rc->revoked_کلی_ids, rki);
		حرر(rki->کلی_id);
		حرر(rki);
	}
	sshkey_free(rc->ca_کلی);
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
	RB_FOREACH_خوندي(rb, revoked_blob_ونه, &krl->revoked_کلیګانې, trb) {
		RB_REMOVE(revoked_blob_ونه, &krl->revoked_کلیګانې, rb);
		حرر(rb->blob);
		حرر(rb);
	}
	RB_FOREACH_خوندي(rb, revoked_blob_ونه, &krl->revoked_sha1s, trb) {
		RB_REMOVE(revoked_blob_ونه, &krl->revoked_sha1s, rb);
		حرر(rb->blob);
		حرر(rb);
	}
	RB_FOREACH_خوندي(rb, revoked_blob_ونه, &krl->revoked_sha256s, trb) {
		RB_REMOVE(revoked_blob_ونه, &krl->revoked_sha256s, rb);
		حرر(rb->blob);
		حرر(rb);
	}
	TAILQ_FOREACH_خوندي(rc, &krl->revoked_certs, ثبت, trc) {
		TAILQ_REMOVE(&krl->revoked_certs, rc, ثبت);
		revoked_certs_free(rc);
	}
	حرر(krl);
}

فراغ
ssh_krl_سېټ_نسخه(بنية ssh_krl *krl, uint64_t نسخه)
{
	krl->krl_نسخه = نسخه;
}

صحيح
ssh_krl_سېټ_comment(بنية ssh_krl *krl, ثابت حرف *comment)
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
revoked_certs_for_ca_کلی(بنية ssh_krl *krl, ثابت بنية sshkey *ca_کلی,
    بنية revoked_certs **rcp, صحيح allow_create)
{
	بنية revoked_certs *rc;
	صحيح r;

	*rcp = عدم;
	TAILQ_FOREACH(rc, &krl->revoked_certs, ثبت) {
		إذا ((ca_کلی == عدم && rc->ca_کلی == عدم) ||
		    sshkey_equal(rc->ca_کلی, ca_کلی)) {
			*rcp = rc;
			أرجع 0;
		}
	}
	إذا (!allow_create)
		أرجع 0;
	/* If this CA doesn't exist in the list then add it now */
	إذا ((rc = حافظه_صفر_ورکړه(1, حجم(*rc))) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا (ca_کلی == عدم)
		rc->ca_کلی = عدم;
	وإلا إذا ((r = sshkey_from_شخصي(ca_کلی, &rc->ca_کلی)) != 0) {
		حرر(rc);
		أرجع r;
	}
	RB_INIT(&rc->revoked_serials);
	RB_INIT(&rc->revoked_کلی_ids);
	TAILQ_INSERT_TAIL(&krl->revoked_certs, rc, ثبت);
	KRL_DBG(("new CA %s", ca_کلی == عدم ? "*" : sshkey_type(ca_کلی)));
	*rcp = rc;
	أرجع 0;
}

ساكن صحيح
ورننباسه_serial_range(بنية revoked_serial_ونه *rt, uint64_t lo, uint64_t hi)
{
	بنية revoked_serial rs, *ers, *crs, *irs;

	KRL_DBG(("insert %llu:%llu",
	    (بینښه اوږد اوږد)lo, (بینښه اوږد اوږد)hi));
	memset(&rs, 0, حجم(rs));
	rs.lo = lo;
	rs.hi = hi;
	ers = RB_NFIND(revoked_serial_ونه, rt, &rs);
	إذا (ers == عدم || serial_cmp(ers, &rs) != 0) {
		/* No entry matches. Just insert */
		إذا ((irs = حافظه_ورکړه(حجم(rs))) == عدم)
			أرجع SSH_ERR_ALLOC_FAIL;
		حافظه_نقل(irs, &rs, حجم(*irs));
		ers = RB_ورننباسه(revoked_serial_ونه, rt, irs);
		إذا (ers != عدم) {
			KRL_DBG(("bad: ers != NULL"));
			/* Shouldn't happen */
			حرر(irs);
			أرجع SSH_ERR_دننی_ERROR;
		}
		ers = irs;
	} وإلا {
		KRL_DBG(("overlap found %llu:%llu",
		    (بینښه اوږد اوږد)ers->lo, (بینښه اوږد اوږد)ers->hi));
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
	طالما ((crs = RB_PREV(revoked_serial_ونه, rt, ers)) != عدم) {
		KRL_DBG(("pred %llu:%llu",
		    (بینښه اوږد اوږد)crs->lo, (بینښه اوږد اوږد)crs->hi));
		إذا (ers->lo != 0 && crs->hi < ers->lo - 1)
			اكسر;
		/* This entry overlaps. */
		إذا (crs->lo < ers->lo) {
			ers->lo = crs->lo;
			KRL_DBG(("pred extend %llu:%llu",
			    (بینښه اوږد اوږد)ers->lo,
			    (بینښه اوږد اوږد)ers->hi));
		}
		RB_REMOVE(revoked_serial_ونه, rt, crs);
		حرر(crs);
	}
	/* Check successors */
	طالما ((crs = RB_بل(revoked_serial_ونه, rt, ers)) != عدم) {
		KRL_DBG(("succ %llu:%llu",
		    (بینښه اوږد اوږد)crs->lo, (بینښه اوږد اوږد)crs->hi));
		إذا (ers->hi != (uint64_t)-1 && crs->lo > ers->hi + 1)
			اكسر;
		/* This entry overlaps. */
		إذا (crs->hi > ers->hi) {
			ers->hi = crs->hi;
			KRL_DBG(("succ extend %llu:%llu",
			    (بینښه اوږد اوږد)ers->lo,
			    (بینښه اوږد اوږد)ers->hi));
		}
		RB_REMOVE(revoked_serial_ونه, rt, crs);
		حرر(crs);
	}
	KRL_DBG(("done, final %llu:%llu",
	    (بینښه اوږد اوږد)ers->lo, (بینښه اوږد اوږد)ers->hi));
	أرجع 0;
}

صحيح
ssh_krl_revoke_cert_by_serial(بنية ssh_krl *krl, ثابت بنية sshkey *ca_کلی,
    uint64_t serial)
{
	أرجع ssh_krl_revoke_cert_by_serial_range(krl, ca_کلی, serial, serial);
}

صحيح
ssh_krl_revoke_cert_by_serial_range(بنية ssh_krl *krl,
    ثابت بنية sshkey *ca_کلی, uint64_t lo, uint64_t hi)
{
	بنية revoked_certs *rc;
	صحيح r;

	إذا (lo > hi || lo == 0)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا ((r = revoked_certs_for_ca_کلی(krl, ca_کلی, &rc, 1)) != 0)
		أرجع r;
	أرجع ورننباسه_serial_range(&rc->revoked_serials, lo, hi);
}

صحيح
ssh_krl_revoke_cert_by_کلی_id(بنية ssh_krl *krl, ثابت بنية sshkey *ca_کلی,
    ثابت حرف *کلی_id)
{
	بنية revoked_کلی_id *rki, *erki;
	بنية revoked_certs *rc;
	صحيح r;

	إذا ((r = revoked_certs_for_ca_کلی(krl, ca_کلی, &rc, 1)) != 0)
		أرجع r;

	KRL_DBG(("revoke %s", کلی_id));
	إذا ((rki = حافظه_صفر_ورکړه(1, حجم(*rki))) == عدم ||
	    (rki->کلی_id = strdup(کلی_id)) == عدم) {
		حرر(rki);
		أرجع SSH_ERR_ALLOC_FAIL;
	}
	erki = RB_ورننباسه(revoked_کلی_id_ونه, &rc->revoked_کلی_ids, rki);
	إذا (erki != عدم) {
		حرر(rki->کلی_id);
		حرر(rki);
	}
	أرجع 0;
}

/* Convert "key" to a public key blob without any certificate information */
ساكن صحيح
plain_کلی_blob(ثابت بنية sshkey *کلی, u_char **blob, اندازه_t *blen)
{
	بنية sshkey *kcopy;
	صحيح r;

	إذا ((r = sshkey_from_شخصي(کلی, &kcopy)) != 0)
		أرجع r;
	إذا (sshkey_is_cert(kcopy)) {
		إذا ((r = sshkey_drop_cert(kcopy)) != 0) {
			sshkey_free(kcopy);
			أرجع r;
		}
	}
	r = sshkey_منزل_blob(kcopy, blob, blen);
	sshkey_free(kcopy);
	أرجع r;
}

/* Revoke a key blob. Ownership of blob is transferred to the tree */
ساكن صحيح
revoke_blob(بنية revoked_blob_ونه *rbt, u_char *blob, اندازه_t len)
{
	بنية revoked_blob *rb, *erb;

	إذا ((rb = حافظه_صفر_ورکړه(1, حجم(*rb))) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	rb->blob = blob;
	rb->len = len;
	erb = RB_ورننباسه(revoked_blob_ونه, rbt, rb);
	إذا (erb != عدم) {
		حرر(rb->blob);
		حرر(rb);
	}
	أرجع 0;
}

صحيح
ssh_krl_revoke_کلی_explicit(بنية ssh_krl *krl, ثابت بنية sshkey *کلی)
{
	u_char *blob;
	اندازه_t len;
	صحيح r;

	debug3_f("revoke type %s", sshkey_type(کلی));
	إذا ((r = plain_کلی_blob(کلی, &blob, &len)) != 0)
		أرجع r;
	أرجع revoke_blob(&krl->revoked_کلیګانې, blob, len);
}

ساكن صحيح
revoke_by_hash(بنية revoked_blob_ونه *موخه, ثابت u_char *p, اندازه_t len)
{
	u_char *blob;
	صحيح r;

	/* need to copy hash, as revoke_blob steals ownership */
	إذا ((blob = حافظه_ورکړه(len)) == عدم)
		أرجع SSH_ERR_SYSTEM_ERROR;
	حافظه_نقل(blob, p, len);
	إذا ((r = revoke_blob(موخه, blob, len)) != 0) {
		حرر(blob);
		أرجع r;
	}
	أرجع 0;
}

صحيح
ssh_krl_revoke_کلی_sha1(بنية ssh_krl *krl, ثابت u_char *p, اندازه_t len)
{
	debug3_f("revoke by sha1");
	إذا (len != 20)
		أرجع SSH_ERR_INVALID_FORMAT;
	أرجع revoke_by_hash(&krl->revoked_sha1s, p, len);
}

صحيح
ssh_krl_revoke_کلی_sha256(بنية ssh_krl *krl, ثابت u_char *p, اندازه_t len)
{
	debug3_f("revoke by sha256");
	إذا (len != 32)
		أرجع SSH_ERR_INVALID_FORMAT;
	أرجع revoke_by_hash(&krl->revoked_sha256s, p, len);
}

صحيح
ssh_krl_revoke_کلی(بنية ssh_krl *krl, ثابت بنية sshkey *کلی)
{
	/* XXX replace with SHA256? */
	إذا (!sshkey_is_cert(کلی))
		أرجع ssh_krl_revoke_کلی_explicit(krl, کلی);

	إذا (کلی->cert->serial == 0) {
		أرجع ssh_krl_revoke_cert_by_کلی_id(krl,
		    کلی->cert->signature_کلی,
		    کلی->cert->کلی_id);
	} وإلا {
		أرجع ssh_krl_revoke_cert_by_serial(krl,
		    کلی->cert->signature_کلی,
		    کلی->cert->serial);
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
ټاکنه_بل_state(صحيح current_state, uint64_t contig, صحيح final,
    uint64_t وروستی_gap, uint64_t بل_gap, اندازه_t bitmap_len,
    صحيح *force_new_section)
{
	صحيح new_state;
	uint64_t لګښت, لګښت_list, لګښت_range, لګښت_bitmap, لګښت_bitmap_restart;

	/*
	 * Avoid unsigned overflows.
	 * The limits are high enough to avoid confusing the calculations.
	 */
	contig = MINIMUM(contig, 1ULL<<31);
	وروستی_gap = MINIMUM(وروستی_gap, 1ULL<<31);
	بل_gap = MINIMUM(بل_gap, 1ULL<<31);

	/*
	 * Calculate the cost to switch from the current state to candidates.
	 * NB. range sections only ever contain a single range, so their
	 * switching cost is independent of the current_state.
	 */
	لګښت_list = لګښت_bitmap = لګښت_bitmap_restart = 0;
	لګښت_range = 8;
	بدل (current_state) {
	حالة KRL_SECTION_CERT_SERIAL_LIST:
		لګښت_bitmap_restart = لګښت_bitmap = 8 + 64;
		اكسر;
	حالة KRL_SECTION_CERT_SERIAL_BITMAP:
		لګښت_list = 8;
		لګښت_bitmap_restart = 8 + 64;
		اكسر;
	حالة KRL_SECTION_CERT_SERIAL_RANGE:
	حالة 0:
		لګښت_bitmap_restart = لګښت_bitmap = 8 + 64;
		لګښت_list = 8;
	}

	/* Estimate base cost in bits of each section type */
	لګښت_list += 64 * contig + (final ? 0 : 8+64);
	لګښت_range += (2 * 64) + (final ? 0 : 8+64);
	لګښت_bitmap += وروستی_gap + contig + (final ? 0 : MINIMUM(بل_gap, 8+64));
	لګښت_bitmap_restart += contig + (final ? 0 : MINIMUM(بل_gap, 8+64));

	/* Convert to byte costs for actual comparison */
	لګښت_list = (لګښت_list + 7) / 8;
	لګښت_bitmap = (لګښت_bitmap + 7) / 8;
	لګښت_bitmap_restart = (لګښت_bitmap_restart + 7) / 8;
	لګښت_range = (لګښت_range + 7) / 8;

	/* Ensure that we never emit a bitmap larger than sshbuf can handle */
	إذا (bitmap_len + لګښت_bitmap >= SSHBUF_MAX_BIGNUM) {
		KRL_DBG(("bitmap overfull len=%zu cost=%llu max=%u",
		    bitmap_len, (بینښه اوږد اوږد)لګښت_bitmap,
		    SSHBUF_MAX_BIGNUM));
		لګښت_bitmap = (uint64_t)-1;
	}

	/* Now pick the best choice */
	*force_new_section = 0;
	new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
	لګښت = لګښت_bitmap;
	إذا (لګښت_range < لګښت) {
		new_state = KRL_SECTION_CERT_SERIAL_RANGE;
		لګښت = لګښت_range;
	}
	إذا (لګښت_list < لګښت) {
		new_state = KRL_SECTION_CERT_SERIAL_LIST;
		لګښت = لګښت_list;
	}
	إذا (لګښت_bitmap_restart < لګښت) {
		new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
		*force_new_section = 1;
		لګښت = لګښت_bitmap_restart;
	}
	KRL_DBG(("contig %llu last_gap %llu next_gap %llu final %d, costs:"
	    "list %llu range %llu bitmap %llu new bitmap %llu, "
	    "selected 0x%02x%s", (اوږد اوږد بینښه)contig,
	    (اوږد اوږد بینښه)وروستی_gap, (اوږد اوږد بینښه)بل_gap, final,
	    (اوږد اوږد بینښه)لګښت_list, (اوږد اوږد بینښه)لګښت_range,
	    (اوږد اوږد بینښه)لګښت_bitmap,
	    (اوږد اوږد بینښه)لګښت_bitmap_restart, new_state,
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
	إذا ((blob = حافظه_ورکړه(len)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا (bitmap_منزل_string(bitmap, blob, len) != 0) {
		حرر(blob);
		أرجع SSH_ERR_دننی_ERROR;
	}
	r = sshbuf_put_bignum2_بایټونه(buf, blob, len);
	حرر(blob);
	أرجع r;
}

/* Generate a KRL_SECTION_CERTIFICATES KRL section */
ساكن صحيح
revoked_certs_generate(بنية revoked_certs *rc, بنية sshbuf *buf)
{
	صحيح final, force_new_sect, r = SSH_ERR_دننی_ERROR;
	uint64_t i, contig, gap, وروستی = 0, bitmap_پیل = 0;
	بنية revoked_serial *rs, *nrs;
	بنية revoked_کلی_id *rki;
	صحيح بل_state, state = 0;
	اندازه_t bitmap_len;
	بنية sshbuf *sect;
	بنية bitmap *bitmap = عدم;

	إذا ((sect = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;

	/* Store the header: optional CA scope key, reserved */
	إذا (rc->ca_کلی == عدم) {
		إذا ((r = sshbuf_put_string(buf, عدم, 0)) != 0)
			اذهب بهر;
	} وإلا {
		إذا ((r = sshkey_puts(rc->ca_کلی, buf)) != 0)
			اذهب بهر;
	}
	إذا ((r = sshbuf_put_string(buf, عدم, 0)) != 0)
		اذهب بهر;

	/* Store the revoked serials.  */
	لكل (rs = RB_MIN(revoked_serial_ونه, &rc->revoked_serials);
	     rs != عدم;
	     rs = RB_بل(revoked_serial_ونه, &rc->revoked_serials, rs)) {
		KRL_DBG(("serial %llu:%llu state 0x%02x",
		    (اوږد اوږد بینښه)rs->lo, (اوږد اوږد بینښه)rs->hi,
		    state));

		/* Check contiguous length and gap to next section (if any) */
		nrs = RB_بل(revoked_serial_ونه, &rc->revoked_serials, rs);
		final = nrs == عدم;
		gap = nrs == عدم ? 0 : nrs->lo - rs->hi;
		contig = 1 + (rs->hi - rs->lo);

		bitmap_len = state == KRL_SECTION_CERT_SERIAL_BITMAP ?
		    bitmap_nbytes(bitmap) : 0;

		/* Choose next state based on these */
		بل_state = ټاکنه_بل_state(state, contig, final,
		    state == 0 ? 0 : rs->lo - وروستی, gap, bitmap_len,
		    &force_new_sect);

		/*
		 * If the current section is a range section or has a different
		 * type to the next section, then finish it off now.
		 */
		إذا (state != 0 && (force_new_sect || بل_state != state ||
		    state == KRL_SECTION_CERT_SERIAL_RANGE)) {
			KRL_DBG(("finish state 0x%02x", state));
			بدل (state) {
			حالة KRL_SECTION_CERT_SERIAL_LIST:
			حالة KRL_SECTION_CERT_SERIAL_RANGE:
				اكسر;
			حالة KRL_SECTION_CERT_SERIAL_BITMAP:
				إذا ((r = put_bitmap(sect, bitmap)) != 0)
					اذهب بهر;
				bitmap_free(bitmap);
				bitmap = عدم;
				اكسر;
			}
			إذا ((r = sshbuf_put_u8(buf, state)) != 0 ||
			    (r = sshbuf_put_stringb(buf, sect)) != 0)
				اذهب بهر;
			sshbuf_reset(sect);
		}

		/* If we are starting a new section then prepare it now */
		إذا (بل_state != state || force_new_sect) {
			KRL_DBG(("start state 0x%02x",
			    بل_state));
			state = بل_state;
			sshbuf_reset(sect);
			بدل (state) {
			حالة KRL_SECTION_CERT_SERIAL_LIST:
			حالة KRL_SECTION_CERT_SERIAL_RANGE:
				اكسر;
			حالة KRL_SECTION_CERT_SERIAL_BITMAP:
				إذا ((bitmap = bitmap_new()) == عدم) {
					r = SSH_ERR_ALLOC_FAIL;
					اذهب بهر;
				}
				bitmap_پیل = rs->lo;
				إذا ((r = sshbuf_put_u64(sect,
				    bitmap_پیل)) != 0)
					اذهب بهر;
				اكسر;
			}
		}

		/* Perform section-specific processing */
		بدل (state) {
		حالة KRL_SECTION_CERT_SERIAL_LIST:
			لكل (i = 0; i < contig; i++) {
				إذا ((r = sshbuf_put_u64(sect, rs->lo + i)) != 0)
					اذهب بهر;
			}
			اكسر;
		حالة KRL_SECTION_CERT_SERIAL_RANGE:
			إذا ((r = sshbuf_put_u64(sect, rs->lo)) != 0 ||
			    (r = sshbuf_put_u64(sect, rs->hi)) != 0)
				اذهب بهر;
			اكسر;
		حالة KRL_SECTION_CERT_SERIAL_BITMAP:
			إذا (rs->lo - bitmap_پیل > لوی_عدد) {
				r = SSH_ERR_INVALID_FORMAT;
				error_f("insane bitmap gap");
				اذهب بهر;
			}
			لكل (i = 0; i < contig; i++) {
				إذا (bitmap_سېټ_بټ(bitmap,
				    rs->lo + i - bitmap_پیل) != 0) {
					r = SSH_ERR_ALLOC_FAIL;
					اذهب بهر;
				}
			}
			اكسر;
		}
		وروستی = rs->hi;
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
				اذهب بهر;
			bitmap_free(bitmap);
			bitmap = عدم;
			اكسر;
		}
		إذا ((r = sshbuf_put_u8(buf, state)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب بهر;
	}
	KRL_DBG(("serial done "));

	/* Now output a section for any revocations by key ID */
	sshbuf_reset(sect);
	RB_FOREACH(rki, revoked_کلی_id_ونه, &rc->revoked_کلی_ids) {
		KRL_DBG(("key ID %s", rki->کلی_id));
		إذا ((r = sshbuf_put_cstring(sect, rki->کلی_id)) != 0)
			اذهب بهر;
	}
	إذا (sshbuf_len(sect) != 0) {
		إذا ((r = sshbuf_put_u8(buf, KRL_SECTION_CERT_کلی_ID)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب بهر;
	}
	r = 0;
 بهر:
	bitmap_free(bitmap);
	sshbuf_free(sect);
	أرجع r;
}

صحيح
ssh_krl_منزل_blob(بنية ssh_krl *krl, بنية sshbuf *buf)
{
	صحيح r = SSH_ERR_دننی_ERROR;
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
		اذهب بهر;

	/* Store sections for revoked certificates */
	TAILQ_FOREACH(rc, &krl->revoked_certs, ثبت) {
		sshbuf_reset(sect);
		إذا ((r = revoked_certs_generate(rc, sect)) != 0)
			اذهب بهر;
		إذا ((r = sshbuf_put_u8(buf, KRL_SECTION_CERTIFICATES)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب بهر;
	}

	/* Finally, output sections for revocations by public key/hash */
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_ونه, &krl->revoked_کلیګانې) {
		KRL_DBG(("key len %zu ", rb->len));
		إذا ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			اذهب بهر;
	}
	إذا (sshbuf_len(sect) != 0) {
		إذا ((r = sshbuf_put_u8(buf, KRL_SECTION_EXPLICIT_کلی)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب بهر;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_ونه, &krl->revoked_sha1s) {
		KRL_DBG(("hash len %zu ", rb->len));
		إذا ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			اذهب بهر;
	}
	إذا (sshbuf_len(sect) != 0) {
		إذا ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA1)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب بهر;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_ونه, &krl->revoked_sha256s) {
		KRL_DBG(("hash len %zu ", rb->len));
		إذا ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			اذهب بهر;
	}
	إذا (sshbuf_len(sect) != 0) {
		إذا ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA256)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب بهر;
	}
	/* success */
	r = 0;
 بهر:
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
	صحيح r = SSH_ERR_دننی_ERROR;
	u_char critical = 1;
	بنية sshbuf *ارزښت = عدم;
	حرف *name = عدم;

	إذا ((r = sshbuf_get_cstring(subsect, &name, عدم)) != 0 ||
	    (r = sshbuf_get_u8(subsect, &critical)) != 0 ||
	    (r = sshbuf_froms(subsect, &ارزښت)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid certificate extension subsection");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}
	إذا (sshbuf_len(subsect) != 0) {
		error("KRL has invalid certificate extension subsection: "
		    "trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}
	debug_f("cert extension %s critical %u len %zu",
	    name, critical, sshbuf_len(ارزښت));
	/* no extensions are currently supported */
	إذا (critical) {
		error("KRL contains unsupported critical certificate "
		    "subsection \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		اذهب بهر;
	}
	/* success */
	r = 0;
 بهر:
	حرر(name);
	sshbuf_free(ارزښت);
	أرجع r;
}

ساكن صحيح
parse_revoked_certs(بنية sshbuf *buf, بنية ssh_krl *krl)
{
	صحيح r = SSH_ERR_دننی_ERROR;
	u_char type;
	ثابت u_char *blob;
	اندازه_t blen, nbits;
	بنية sshbuf *subsect = عدم;
	uint64_t serial, serial_lo, serial_hi;
	بنية bitmap *bitmap = عدم;
	حرف *کلی_id = عدم;
	بنية sshkey *ca_کلی = عدم;

	إذا ((subsect = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;

	/* Header: key, reserved */
	إذا ((r = sshbuf_get_string_مستقیم(buf, &blob, &blen)) != 0 ||
	    (r = sshbuf_skip_string(buf)) != 0)
		اذهب بهر;
	إذا (blen != 0 && (r = sshkey_from_blob(blob, blen, &ca_کلی)) != 0)
		اذهب بهر;

	طالما (sshbuf_len(buf) > 0) {
		sshbuf_free(subsect);
		subsect = عدم;
		إذا ((r = sshbuf_get_u8(buf, &type)) != 0 ||
		    (r = sshbuf_froms(buf, &subsect)) != 0)
			اذهب بهر;
		KRL_DBG(("subsection type 0x%02x", type));
		/* sshbuf_dump(subsect, stderr); */

		بدل (type) {
		حالة KRL_SECTION_CERT_SERIAL_LIST:
			طالما (sshbuf_len(subsect) > 0) {
				إذا ((r = sshbuf_get_u64(subsect, &serial)) != 0)
					اذهب بهر;
				إذا ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_کلی, serial)) != 0)
					اذهب بهر;
			}
			اكسر;
		حالة KRL_SECTION_CERT_SERIAL_RANGE:
			إذا ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_u64(subsect, &serial_hi)) != 0)
				اذهب بهر;
			إذا ((r = ssh_krl_revoke_cert_by_serial_range(krl,
			    ca_کلی, serial_lo, serial_hi)) != 0)
				اذهب بهر;
			اكسر;
		حالة KRL_SECTION_CERT_SERIAL_BITMAP:
			إذا ((bitmap = bitmap_new()) == عدم) {
				r = SSH_ERR_ALLOC_FAIL;
				اذهب بهر;
			}
			إذا ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_bignum2_بایټونه_مستقیم(subsect,
			    &blob, &blen)) != 0)
				اذهب بهر;
			إذا (bitmap_from_string(bitmap, blob, blen) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				اذهب بهر;
			}
			nbits = bitmap_nbits(bitmap);
			لكل (serial = 0; serial < (uint64_t)nbits; serial++) {
				إذا (serial > 0 && serial_lo + serial == 0) {
					error_f("bitmap wraps u64");
					r = SSH_ERR_INVALID_FORMAT;
					اذهب بهر;
				}
				إذا (!bitmap_test_بټ(bitmap, serial))
					استمر;
				إذا ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_کلی, serial_lo + serial)) != 0)
					اذهب بهر;
			}
			bitmap_free(bitmap);
			bitmap = عدم;
			اكسر;
		حالة KRL_SECTION_CERT_کلی_ID:
			طالما (sshbuf_len(subsect) > 0) {
				إذا ((r = sshbuf_get_cstring(subsect,
				    &کلی_id, عدم)) != 0)
					اذهب بهر;
				إذا ((r = ssh_krl_revoke_cert_by_کلی_id(krl,
				    ca_کلی, کلی_id)) != 0)
					اذهب بهر;
				حرر(کلی_id);
				کلی_id = عدم;
			}
			اكسر;
		حالة KRL_SECTION_CERT_EXTENSION:
			إذا ((r = cert_extension_subsection(subsect, krl)) != 0)
				اذهب بهر;
			اكسر;
		افتراضي:
			error("Unsupported KRL certificate section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بهر;
		}
		إذا (sshbuf_len(subsect) > 0) {
			error("KRL certificate section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بهر;
		}
	}

	r = 0;
 بهر:
	إذا (bitmap != عدم)
		bitmap_free(bitmap);
	حرر(کلی_id);
	sshkey_free(ca_کلی);
	sshbuf_free(subsect);
	أرجع r;
}

ساكن صحيح
blob_section(بنية sshbuf *sect, بنية revoked_blob_ونه *موخه_ونه,
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
		إذا ((r = revoke_blob(موخه_ونه, rdata, rlen)) != 0) {
			حرر(rdata);
			أرجع r;
		}
	}
	أرجع 0;
}

ساكن صحيح
extension_section(بنية sshbuf *sect, بنية ssh_krl *krl)
{
	صحيح r = SSH_ERR_دننی_ERROR;
	u_char critical = 1;
	بنية sshbuf *ارزښت = عدم;
	حرف *name = عدم;

	إذا ((r = sshbuf_get_cstring(sect, &name, عدم)) != 0 ||
	    (r = sshbuf_get_u8(sect, &critical)) != 0 ||
	    (r = sshbuf_froms(sect, &ارزښت)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid extension section");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}
	إذا (sshbuf_len(sect) != 0) {
		error("KRL has invalid extension section: trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}
	debug_f("extension %s critical %u len %zu",
	    name, critical, sshbuf_len(ارزښت));
	/* no extensions are currently supported */
	إذا (critical) {
		error("KRL contains unsupported critical section \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		اذهب بهر;
	}
	/* success */
	r = 0;
 بهر:
	حرر(name);
	sshbuf_free(ارزښت);
	أرجع r;
}

/* Attempt to parse a KRL */
صحيح
ssh_krl_from_blob(بنية sshbuf *buf, بنية ssh_krl **krlp)
{
	بنية sshbuf *copy = عدم, *sect = عدم;
	بنية ssh_krl *krl = عدم;
	حرف timestamp[64];
	صحيح r = SSH_ERR_دننی_ERROR;
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
		اذهب بهر;
	}
	/* Don't modify buffer */
	إذا ((copy = sshbuf_fromb(buf)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = sshbuf_consume(copy, حجم(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_get_u32(copy, &format_نسخه)) != 0)
		اذهب بهر;
	إذا (format_نسخه != KRL_FORMAT_نسخه) {
		error_f("unsupported KRL format version %u", format_نسخه);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}
	إذا ((r = sshbuf_get_u64(copy, &krl->krl_نسخه)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->generated_date)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->flags)) != 0 ||
	    (r = sshbuf_skip_string(copy)) != 0 ||
	    (r = sshbuf_get_cstring(copy, &krl->comment, عدم)) != 0) {
		error_fr(r, "parse KRL header");
		اذهب بهر;
	}
	format_timestamp(krl->generated_date, timestamp, حجم(timestamp));
	debug("KRL version %llu generated at %s%s%s",
	    (اوږد اوږد بینښه)krl->krl_نسخه, timestamp,
	    *krl->comment ? ": " : "", krl->comment);

	/* Parse and load the KRL sections. */
	طالما (sshbuf_len(copy) > 0) {
		sshbuf_free(sect);
		sect = عدم;
		إذا ((r = sshbuf_get_u8(copy, &type)) != 0 ||
		    (r = sshbuf_froms(copy, &sect)) != 0)
			اذهب بهر;
		KRL_DBG(("section 0x%02x", type));

		بدل (type) {
		حالة KRL_SECTION_CERTIFICATES:
			إذا ((r = parse_revoked_certs(sect, krl)) != 0)
				اذهب بهر;
			اكسر;
		حالة KRL_SECTION_EXPLICIT_کلی:
			إذا ((r = blob_section(sect,
			    &krl->revoked_کلیګانې, 0)) != 0)
				اذهب بهر;
			اكسر;
		حالة KRL_SECTION_FINGERPRINT_SHA1:
			إذا ((r = blob_section(sect,
			    &krl->revoked_sha1s, 20)) != 0)
				اذهب بهر;
			اكسر;
		حالة KRL_SECTION_FINGERPRINT_SHA256:
			إذا ((r = blob_section(sect,
			    &krl->revoked_sha256s, 32)) != 0)
				اذهب بهر;
			اكسر;
		حالة KRL_SECTION_EXTENSION:
			إذا ((r = extension_section(sect, krl)) != 0)
				اذهب بهر;
			اكسر;
		حالة KRL_SECTION_SIGNATURE:
			/* Handled above, but still need to stay in synch */
			sshbuf_free(sect);
			sect = عدم;
			إذا ((r = sshbuf_skip_string(copy)) != 0)
				اذهب بهر;
			اكسر;
		افتراضي:
			error("Unsupported KRL section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بهر;
		}
		إذا (sect != عدم && sshbuf_len(sect) > 0) {
			error("KRL section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بهر;
		}
	}

	/* Success */
	*krlp = krl;
	r = 0;
 بهر:
	إذا (r != 0)
		ssh_krl_free(krl);
	sshbuf_free(copy);
	sshbuf_free(sect);
	أرجع r;
}

/* Checks certificate serial number and key ID revocation */
ساكن صحيح
is_cert_revoked(ثابت بنية sshkey *کلی, بنية revoked_certs *rc)
{
	بنية revoked_serial rs, *ers;
	بنية revoked_کلی_id rki, *erki;

	/* Check revocation by cert key ID */
	memset(&rki, 0, حجم(rki));
	rki.کلی_id = کلی->cert->کلی_id;
	erki = RB_پیدا_کړه(revoked_کلی_id_ونه, &rc->revoked_کلی_ids, &rki);
	إذا (erki != عدم) {
		KRL_DBG(("revoked by key ID"));
		أرجع SSH_ERR_کلی_REVOKED;
	}

	/*
	 * Zero serials numbers are ignored (it's the default when the
	 * CA doesn't specify one).
	 */
	إذا (کلی->cert->serial == 0)
		أرجع 0;

	memset(&rs, 0, حجم(rs));
	rs.lo = rs.hi = کلی->cert->serial;
	ers = RB_پیدا_کړه(revoked_serial_ونه, &rc->revoked_serials, &rs);
	إذا (ers != عدم) {
		KRL_DBG(("revoked serial %llu matched %llu:%llu",
		    (بینښه اوږد اوږد)کلی->cert->serial,
		    (بینښه اوږد اوږد)ers->lo,
		    (بینښه اوږد اوږد)ers->hi));
		أرجع SSH_ERR_کلی_REVOKED;
	}
	أرجع 0;
}

/* Checks whether a given key/cert is revoked. Does not check its CA */
ساكن صحيح
is_کلی_revoked(بنية ssh_krl *krl, ثابت بنية sshkey *کلی)
{
	بنية revoked_blob rb, *erb;
	بنية revoked_certs *rc;
	صحيح r;

	/* Check explicitly revoked hashes first */
	memset(&rb, 0, حجم(rb));
	إذا ((r = sshkey_fingerprint_raw(کلی, SSH_DIGEST_SHA1,
	    &rb.blob, &rb.len)) != 0)
		أرجع r;
	erb = RB_پیدا_کړه(revoked_blob_ونه, &krl->revoked_sha1s, &rb);
	حرر(rb.blob);
	إذا (erb != عدم) {
		KRL_DBG(("revoked by key SHA1"));
		أرجع SSH_ERR_کلی_REVOKED;
	}
	memset(&rb, 0, حجم(rb));
	إذا ((r = sshkey_fingerprint_raw(کلی, SSH_DIGEST_SHA256,
	    &rb.blob, &rb.len)) != 0)
		أرجع r;
	erb = RB_پیدا_کړه(revoked_blob_ونه, &krl->revoked_sha256s, &rb);
	حرر(rb.blob);
	إذا (erb != عدم) {
		KRL_DBG(("revoked by key SHA256"));
		أرجع SSH_ERR_کلی_REVOKED;
	}

	/* Next, explicit keys */
	memset(&rb, 0, حجم(rb));
	إذا ((r = plain_کلی_blob(کلی, &rb.blob, &rb.len)) != 0)
		أرجع r;
	erb = RB_پیدا_کړه(revoked_blob_ونه, &krl->revoked_کلیګانې, &rb);
	حرر(rb.blob);
	إذا (erb != عدم) {
		KRL_DBG(("revoked by explicit key"));
		أرجع SSH_ERR_کلی_REVOKED;
	}

	إذا (!sshkey_is_cert(کلی))
		أرجع 0;

	/* Check cert revocation for the specified CA */
	إذا ((r = revoked_certs_for_ca_کلی(krl, کلی->cert->signature_کلی,
	    &rc, 0)) != 0)
		أرجع r;
	إذا (rc != عدم) {
		إذا ((r = is_cert_revoked(کلی, rc)) != 0)
			أرجع r;
	}
	/* Check cert revocation for the wildcard CA */
	إذا ((r = revoked_certs_for_ca_کلی(krl, عدم, &rc, 0)) != 0)
		أرجع r;
	إذا (rc != عدم) {
		إذا ((r = is_cert_revoked(کلی, rc)) != 0)
			أرجع r;
	}

	KRL_DBG(("%llu no match", (بینښه اوږد اوږد)کلی->cert->serial));
	أرجع 0;
}

صحيح
ssh_krl_check_کلی(بنية ssh_krl *krl, ثابت بنية sshkey *کلی)
{
	صحيح r;

	KRL_DBG(("checking key"));
	إذا ((r = is_کلی_revoked(krl, کلی)) != 0)
		أرجع r;
	إذا (sshkey_is_cert(کلی)) {
		debug2_f("checking CA key");
		إذا ((r = is_کلی_revoked(krl, کلی->cert->signature_کلی)) != 0)
			أرجع r;
	}
	KRL_DBG(("key okay"));
	أرجع 0;
}

صحيح
ssh_krl_file_لري_کلی(ثابت حرف *لار, ثابت بنية sshkey *کلی)
{
	بنية sshbuf *krlbuf = عدم;
	بنية ssh_krl *krl = عدم;
	صحيح oerrno = 0, r;

	إذا (لار == عدم)
		أرجع 0;
	إذا ((r = sshbuf_بارول_file(لار, &krlbuf)) != 0) {
		oerrno = errno;
		اذهب بهر;
	}
	إذا ((r = ssh_krl_from_blob(krlbuf, &krl)) != 0)
		اذهب بهر;
	debug2_f("checking KRL %s", لار);
	r = ssh_krl_check_کلی(krl, کلی);
 بهر:
	sshbuf_free(krlbuf);
	ssh_krl_free(krl);
	إذا (r != 0)
		errno = oerrno;
	أرجع r;
}

صحيح
krl_dump(بنية ssh_krl *krl, FILE *f)
{
	بنية sshkey *کلی = عدم;
	بنية revoked_blob *rb;
	بنية revoked_certs *rc;
	بنية revoked_serial *rs;
	بنية revoked_کلی_id *rki;
	صحيح r, ret = 0;
	حرف *fp, timestamp[64];

	/* Try to print in a KRL spec-compatible format */
	format_timestamp(krl->generated_date, timestamp, حجم(timestamp));
	fprintf(f, "# KRL version %llu\n", (بینښه اوږد اوږد)krl->krl_نسخه);
	fprintf(f, "# Generated at %s\n", timestamp);
	إذا (krl->comment != عدم && *krl->comment != '\0') {
		r = لوی_عدد;
		asmprintf(&fp, لوی_عدد, &r, "%s", krl->comment);
		fprintf(f, "# Comment: %s\n", fp);
		حرر(fp);
	}
	fputc('\n', f);

	RB_FOREACH(rb, revoked_blob_ونه, &krl->revoked_کلیګانې) {
		إذا ((r = sshkey_from_blob(rb->blob, rb->len, &کلی)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			error_r(r, "parse KRL key");
			استمر;
		}
		إذا ((fp = sshkey_fingerprint(کلی, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == عدم) {
			ret = SSH_ERR_INVALID_FORMAT;
			error("sshkey_fingerprint failed");
			استمر;
		}
		fprintf(f, "hash: %s # %s\n", fp, sshkey_ssh_name(کلی));
		حرر(fp);
		حرر(کلی);
	}
	RB_FOREACH(rb, revoked_blob_ونه, &krl->revoked_sha256s) {
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "hash: SHA256:%s\n", fp);
		حرر(fp);
	}
	RB_FOREACH(rb, revoked_blob_ونه, &krl->revoked_sha1s) {
		/*
		 * There is not KRL spec keyword for raw SHA1 hashes, so
		 * print them as comments.
		 */
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "# hash SHA1:%s\n", fp);
		حرر(fp);
	}

	TAILQ_FOREACH(rc, &krl->revoked_certs, ثبت) {
		fputc('\n', f);
		إذا (rc->ca_کلی == عدم)
			fprintf(f, "# Wildcard CA\n");
		وإلا {
			إذا ((fp = sshkey_fingerprint(rc->ca_کلی,
			    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == عدم) {
				ret = SSH_ERR_INVALID_FORMAT;
				error("sshkey_fingerprint failed");
				استمر;
			}
			fprintf(f, "# CA key %s %s\n",
			    sshkey_ssh_name(rc->ca_کلی), fp);
			حرر(fp);
		}
		RB_FOREACH(rs, revoked_serial_ونه, &rc->revoked_serials) {
			إذا (rs->lo == rs->hi) {
				fprintf(f, "serial: %llu\n",
				    (بینښه اوږد اوږد)rs->lo);
			} وإلا {
				fprintf(f, "serial: %llu-%llu\n",
				    (بینښه اوږد اوږد)rs->lo,
				    (بینښه اوږد اوږد)rs->hi);
			}
		}
		RB_FOREACH(rki, revoked_کلی_id_ونه, &rc->revoked_کلی_ids) {
			/*
			 * We don't want key IDs with embedded newlines to
			 * mess up the display.
			 */
			r = لوی_عدد;
			asmprintf(&fp, لوی_عدد, &r, "%s", rki->کلی_id);
			fprintf(f, "id: %s\n", fp);
			حرر(fp);
		}
	}
	أرجع ret;
}
