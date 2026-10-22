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
#ifdef DEBUG_KRL
# define KRL_DBG(x) debug3_f x
#وإلا
# define KRL_DBG(x)
#endif

/*
 * Trees of revoked serial numbers, key IDs and keys. This allows
 * quick searching, querying and producing lists in canonical order.
 */

/* Tree of serial numbers. XXX make smarter: really need a real sparse bitmap */
بنية revoked_serial {
	uint64_t lo, hi;
	RB_ENTRY(revoked_serial) درەخت_entry;
};
ساكن صحيح serial_cmp(بنية revoked_serial *a, بنية revoked_serial *b);
RB_HEAD(revoked_serial_درەخت, revoked_serial);
RB_GENERATE_STATIC(revoked_serial_درەخت, revoked_serial, درەخت_entry, serial_cmp)

/* Tree of key IDs */
بنية revoked_کلیل_id {
	حرف *کلیل_id;
	RB_ENTRY(revoked_کلیل_id) درەخت_entry;
};
ساكن صحيح کلیل_id_cmp(بنية revoked_کلیل_id *a, بنية revoked_کلیل_id *b);
RB_HEAD(revoked_کلیل_id_درەخت, revoked_کلیل_id);
RB_GENERATE_STATIC(revoked_کلیل_id_درەخت, revoked_کلیل_id, درەخت_entry, کلیل_id_cmp)

/* Tree of blobs (used for keys and fingerprints) */
بنية revoked_blob {
	u_char *blob;
	size_t len;
	RB_ENTRY(revoked_blob) درەخت_entry;
};
ساكن صحيح blob_cmp(بنية revoked_blob *a, بنية revoked_blob *b);
RB_HEAD(revoked_blob_درەخت, revoked_blob);
RB_GENERATE_STATIC(revoked_blob_درەخت, revoked_blob, درەخت_entry, blob_cmp)

/* Tracks revoked certs for a single CA */
بنية revoked_certs {
	بنية sshkey *ca_کلیل;
	بنية revoked_serial_درەخت revoked_serials;
	بنية revoked_کلیل_id_درەخت revoked_کلیل_ids;
	TAILQ_ENTRY(revoked_certs) entry;
};
TAILQ_HEAD(revoked_certs_list, revoked_certs);

بنية ssh_krl {
	uint64_t krl_version;
	uint64_t generated_date;
	uint64_t flags;
	حرف *comment;
	بنية revoked_blob_درەخت revoked_کلیلەکان;
	بنية revoked_blob_درەخت revoked_sha1s;
	بنية revoked_blob_درەخت revoked_sha256s;
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
کلیل_id_cmp(بنية revoked_کلیل_id *a, بنية revoked_کلیل_id *b)
{
	أرجع strcmp(a->کلیل_id, b->کلیل_id);
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

	إذا ((krl = calloc(1, حجم(*krl))) == عدم)
		أرجع عدم;
	RB_INIT(&krl->revoked_کلیلەکان);
	RB_INIT(&krl->revoked_sha1s);
	RB_INIT(&krl->revoked_sha256s);
	TAILQ_INIT(&krl->revoked_certs);
	أرجع krl;
}

ساكن فراغ
revoked_certs_free(بنية revoked_certs *rc)
{
	بنية revoked_serial *rs, *trs;
	بنية revoked_کلیل_id *rki, *trki;

	إذا (rc == عدم)
		أرجع;
	RB_FOREACH_SAFE(rs, revoked_serial_درەخت, &rc->revoked_serials, trs) {
		RB_REMOVE(revoked_serial_درەخت, &rc->revoked_serials, rs);
		حرر(rs);
	}
	RB_FOREACH_SAFE(rki, revoked_کلیل_id_درەخت, &rc->revoked_کلیل_ids, trki) {
		RB_REMOVE(revoked_کلیل_id_درەخت, &rc->revoked_کلیل_ids, rki);
		حرر(rki->کلیل_id);
		حرر(rki);
	}
	sshkey_free(rc->ca_کلیل);
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
	RB_FOREACH_SAFE(rb, revoked_blob_درەخت, &krl->revoked_کلیلەکان, trb) {
		RB_REMOVE(revoked_blob_درەخت, &krl->revoked_کلیلەکان, rb);
		حرر(rb->blob);
		حرر(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_درەخت, &krl->revoked_sha1s, trb) {
		RB_REMOVE(revoked_blob_درەخت, &krl->revoked_sha1s, rb);
		حرر(rb->blob);
		حرر(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_درەخت, &krl->revoked_sha256s, trb) {
		RB_REMOVE(revoked_blob_درەخت, &krl->revoked_sha256s, rb);
		حرر(rb->blob);
		حرر(rb);
	}
	TAILQ_FOREACH_SAFE(rc, &krl->revoked_certs, entry, trc) {
		TAILQ_REMOVE(&krl->revoked_certs, rc, entry);
		revoked_certs_free(rc);
	}
	حرر(krl);
}

فراغ
ssh_krl_set_version(بنية ssh_krl *krl, uint64_t version)
{
	krl->krl_version = version;
}

صحيح
ssh_krl_set_comment(بنية ssh_krl *krl, ثابت حرف *comment)
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
revoked_certs_for_ca_کلیل(بنية ssh_krl *krl, ثابت بنية sshkey *ca_کلیل,
    بنية revoked_certs **rcp, صحيح allow_create)
{
	بنية revoked_certs *rc;
	صحيح r;

	*rcp = عدم;
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		إذا ((ca_کلیل == عدم && rc->ca_کلیل == عدم) ||
		    sshkey_equal(rc->ca_کلیل, ca_کلیل)) {
			*rcp = rc;
			أرجع 0;
		}
	}
	إذا (!allow_create)
		أرجع 0;
	/* If this CA doesn't exist in the list then add it now */
	إذا ((rc = calloc(1, حجم(*rc))) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا (ca_کلیل == عدم)
		rc->ca_کلیل = عدم;
	وإلا إذا ((r = sshkey_from_private(ca_کلیل, &rc->ca_کلیل)) != 0) {
		حرر(rc);
		أرجع r;
	}
	RB_INIT(&rc->revoked_serials);
	RB_INIT(&rc->revoked_کلیل_ids);
	TAILQ_INSERT_TAIL(&krl->revoked_certs, rc, entry);
	KRL_DBG(("new CA %s", ca_کلیل == عدم ? "*" : sshkey_type(ca_کلیل)));
	*rcp = rc;
	أرجع 0;
}

ساكن صحيح
زیادکردن_serial_range(بنية revoked_serial_درەخت *rt, uint64_t lo, uint64_t hi)
{
	بنية revoked_serial rs, *ers, *crs, *irs;

	KRL_DBG(("insert %llu:%llu",
	    (unsigned long long)lo, (unsigned long long)hi));
	memset(&rs, 0, حجم(rs));
	rs.lo = lo;
	rs.hi = hi;
	ers = RB_NFIND(revoked_serial_درەخت, rt, &rs);
	إذا (ers == عدم || serial_cmp(ers, &rs) != 0) {
		/* No entry matches. Just insert */
		إذا ((irs = malloc(حجم(rs))) == عدم)
			أرجع SSH_ERR_ALLOC_FAIL;
		memcpy(irs, &rs, حجم(*irs));
		ers = RB_زیادکردن(revoked_serial_درەخت, rt, irs);
		إذا (ers != عدم) {
			KRL_DBG(("bad: ers != NULL"));
			/* Shouldn't happen */
			حرر(irs);
			أرجع SSH_ERR_INTERNAL_ERROR;
		}
		ers = irs;
	} وإلا {
		KRL_DBG(("overlap found %llu:%llu",
		    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
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
	طالما ((crs = RB_PREV(revoked_serial_درەخت, rt, ers)) != عدم) {
		KRL_DBG(("pred %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		إذا (ers->lo != 0 && crs->hi < ers->lo - 1)
			اكسر;
		/* This entry overlaps. */
		إذا (crs->lo < ers->lo) {
			ers->lo = crs->lo;
			KRL_DBG(("pred extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_درەخت, rt, crs);
		حرر(crs);
	}
	/* Check successors */
	طالما ((crs = RB_NEXT(revoked_serial_درەخت, rt, ers)) != عدم) {
		KRL_DBG(("succ %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		إذا (ers->hi != (uint64_t)-1 && crs->lo > ers->hi + 1)
			اكسر;
		/* This entry overlaps. */
		إذا (crs->hi > ers->hi) {
			ers->hi = crs->hi;
			KRL_DBG(("succ extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_درەخت, rt, crs);
		حرر(crs);
	}
	KRL_DBG(("done, final %llu:%llu",
	    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
	أرجع 0;
}

صحيح
ssh_krl_revoke_cert_by_serial(بنية ssh_krl *krl, ثابت بنية sshkey *ca_کلیل,
    uint64_t serial)
{
	أرجع ssh_krl_revoke_cert_by_serial_range(krl, ca_کلیل, serial, serial);
}

صحيح
ssh_krl_revoke_cert_by_serial_range(بنية ssh_krl *krl,
    ثابت بنية sshkey *ca_کلیل, uint64_t lo, uint64_t hi)
{
	بنية revoked_certs *rc;
	صحيح r;

	إذا (lo > hi || lo == 0)
		أرجع SSH_ERR_INVALID_ARGUMENT;
	إذا ((r = revoked_certs_for_ca_کلیل(krl, ca_کلیل, &rc, 1)) != 0)
		أرجع r;
	أرجع زیادکردن_serial_range(&rc->revoked_serials, lo, hi);
}

صحيح
ssh_krl_revoke_cert_by_کلیل_id(بنية ssh_krl *krl, ثابت بنية sshkey *ca_کلیل,
    ثابت حرف *کلیل_id)
{
	بنية revoked_کلیل_id *rki, *erki;
	بنية revoked_certs *rc;
	صحيح r;

	إذا ((r = revoked_certs_for_ca_کلیل(krl, ca_کلیل, &rc, 1)) != 0)
		أرجع r;

	KRL_DBG(("revoke %s", کلیل_id));
	إذا ((rki = calloc(1, حجم(*rki))) == عدم ||
	    (rki->کلیل_id = strdup(کلیل_id)) == عدم) {
		حرر(rki);
		أرجع SSH_ERR_ALLOC_FAIL;
	}
	erki = RB_زیادکردن(revoked_کلیل_id_درەخت, &rc->revoked_کلیل_ids, rki);
	إذا (erki != عدم) {
		حرر(rki->کلیل_id);
		حرر(rki);
	}
	أرجع 0;
}

/* Convert "key" to a public key blob without any certificate information */
ساكن صحيح
plain_کلیل_blob(ثابت بنية sshkey *کلیل, u_char **blob, size_t *blen)
{
	بنية sshkey *kcopy;
	صحيح r;

	إذا ((r = sshkey_from_private(کلیل, &kcopy)) != 0)
		أرجع r;
	إذا (sshkey_is_cert(kcopy)) {
		إذا ((r = sshkey_drop_cert(kcopy)) != 0) {
			sshkey_free(kcopy);
			أرجع r;
		}
	}
	r = sshkey_to_blob(kcopy, blob, blen);
	sshkey_free(kcopy);
	أرجع r;
}

/* Revoke a key blob. Ownership of blob is transferred to the tree */
ساكن صحيح
revoke_blob(بنية revoked_blob_درەخت *rbt, u_char *blob, size_t len)
{
	بنية revoked_blob *rb, *erb;

	إذا ((rb = calloc(1, حجم(*rb))) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	rb->blob = blob;
	rb->len = len;
	erb = RB_زیادکردن(revoked_blob_درەخت, rbt, rb);
	إذا (erb != عدم) {
		حرر(rb->blob);
		حرر(rb);
	}
	أرجع 0;
}

صحيح
ssh_krl_revoke_کلیل_explicit(بنية ssh_krl *krl, ثابت بنية sshkey *کلیل)
{
	u_char *blob;
	size_t len;
	صحيح r;

	debug3_f("revoke type %s", sshkey_type(کلیل));
	إذا ((r = plain_کلیل_blob(کلیل, &blob, &len)) != 0)
		أرجع r;
	أرجع revoke_blob(&krl->revoked_کلیلەکان, blob, len);
}

ساكن صحيح
revoke_by_hash(بنية revoked_blob_درەخت *target, ثابت u_char *p, size_t len)
{
	u_char *blob;
	صحيح r;

	/* need to copy hash, as revoke_blob steals ownership */
	إذا ((blob = malloc(len)) == عدم)
		أرجع SSH_ERR_SYSTEM_ERROR;
	memcpy(blob, p, len);
	إذا ((r = revoke_blob(target, blob, len)) != 0) {
		حرر(blob);
		أرجع r;
	}
	أرجع 0;
}

صحيح
ssh_krl_revoke_کلیل_sha1(بنية ssh_krl *krl, ثابت u_char *p, size_t len)
{
	debug3_f("revoke by sha1");
	إذا (len != 20)
		أرجع SSH_ERR_INVALID_FORMAT;
	أرجع revoke_by_hash(&krl->revoked_sha1s, p, len);
}

صحيح
ssh_krl_revoke_کلیل_sha256(بنية ssh_krl *krl, ثابت u_char *p, size_t len)
{
	debug3_f("revoke by sha256");
	إذا (len != 32)
		أرجع SSH_ERR_INVALID_FORMAT;
	أرجع revoke_by_hash(&krl->revoked_sha256s, p, len);
}

صحيح
ssh_krl_revoke_کلیل(بنية ssh_krl *krl, ثابت بنية sshkey *کلیل)
{
	/* XXX replace with SHA256? */
	إذا (!sshkey_is_cert(کلیل))
		أرجع ssh_krl_revoke_کلیل_explicit(krl, کلیل);

	إذا (کلیل->cert->serial == 0) {
		أرجع ssh_krl_revoke_cert_by_کلیل_id(krl,
		    کلیل->cert->signature_کلیل,
		    کلیل->cert->کلیل_id);
	} وإلا {
		أرجع ssh_krl_revoke_cert_by_serial(krl,
		    کلیل->cert->signature_کلیل,
		    کلیل->cert->serial);
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
choose_next_state(صحيح current_state, uint64_t contig, صحيح final,
    uint64_t last_gap, uint64_t next_gap, size_t bitmap_len,
    صحيح *force_new_section)
{
	صحيح new_state;
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
	بدل (current_state) {
	حالة KRL_SECTION_CERT_SERIAL_LIST:
		cost_bitmap_restart = cost_bitmap = 8 + 64;
		اكسر;
	حالة KRL_SECTION_CERT_SERIAL_BITMAP:
		cost_list = 8;
		cost_bitmap_restart = 8 + 64;
		اكسر;
	حالة KRL_SECTION_CERT_SERIAL_RANGE:
	حالة 0:
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
	إذا (bitmap_len + cost_bitmap >= SSHBUF_MAX_BIGNUM) {
		KRL_DBG(("bitmap overfull len=%zu cost=%llu max=%u",
		    bitmap_len, (unsigned long long)cost_bitmap,
		    SSHBUF_MAX_BIGNUM));
		cost_bitmap = (uint64_t)-1;
	}

	/* Now pick the best choice */
	*force_new_section = 0;
	new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
	cost = cost_bitmap;
	إذا (cost_range < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_RANGE;
		cost = cost_range;
	}
	إذا (cost_list < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_LIST;
		cost = cost_list;
	}
	إذا (cost_bitmap_restart < cost) {
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
	أرجع new_state;
}

ساكن صحيح
put_bitmap(بنية sshbuf *buf, بنية bitmap *bitmap)
{
	size_t len;
	u_char *blob;
	صحيح r;

	len = bitmap_nbytes(bitmap);
	إذا ((blob = malloc(len)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا (bitmap_to_string(bitmap, blob, len) != 0) {
		حرر(blob);
		أرجع SSH_ERR_INTERNAL_ERROR;
	}
	r = sshbuf_put_bignum2_bytes(buf, blob, len);
	حرر(blob);
	أرجع r;
}

/* Generate a KRL_SECTION_CERTIFICATES KRL section */
ساكن صحيح
revoked_certs_generate(بنية revoked_certs *rc, بنية sshbuf *buf)
{
	صحيح final, force_new_sect, r = SSH_ERR_INTERNAL_ERROR;
	uint64_t i, contig, gap, last = 0, bitmap_start = 0;
	بنية revoked_serial *rs, *nrs;
	بنية revoked_کلیل_id *rki;
	صحيح next_state, state = 0;
	size_t bitmap_len;
	بنية sshbuf *sect;
	بنية bitmap *bitmap = عدم;

	إذا ((sect = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;

	/* Store the header: optional CA scope key, reserved */
	إذا (rc->ca_کلیل == عدم) {
		إذا ((r = sshbuf_put_string(buf, عدم, 0)) != 0)
			اذهب out;
	} وإلا {
		إذا ((r = sshkey_puts(rc->ca_کلیل, buf)) != 0)
			اذهب out;
	}
	إذا ((r = sshbuf_put_string(buf, عدم, 0)) != 0)
		اذهب out;

	/* Store the revoked serials.  */
	لكل (rs = RB_MIN(revoked_serial_درەخت, &rc->revoked_serials);
	     rs != عدم;
	     rs = RB_NEXT(revoked_serial_درەخت, &rc->revoked_serials, rs)) {
		KRL_DBG(("serial %llu:%llu state 0x%02x",
		    (long long unsigned)rs->lo, (long long unsigned)rs->hi,
		    state));

		/* Check contiguous length and gap to next section (if any) */
		nrs = RB_NEXT(revoked_serial_درەخت, &rc->revoked_serials, rs);
		final = nrs == عدم;
		gap = nrs == عدم ? 0 : nrs->lo - rs->hi;
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
		إذا (state != 0 && (force_new_sect || next_state != state ||
		    state == KRL_SECTION_CERT_SERIAL_RANGE)) {
			KRL_DBG(("finish state 0x%02x", state));
			بدل (state) {
			حالة KRL_SECTION_CERT_SERIAL_LIST:
			حالة KRL_SECTION_CERT_SERIAL_RANGE:
				اكسر;
			حالة KRL_SECTION_CERT_SERIAL_BITMAP:
				إذا ((r = put_bitmap(sect, bitmap)) != 0)
					اذهب out;
				bitmap_free(bitmap);
				bitmap = عدم;
				اكسر;
			}
			إذا ((r = sshbuf_put_u8(buf, state)) != 0 ||
			    (r = sshbuf_put_stringb(buf, sect)) != 0)
				اذهب out;
			sshbuf_reset(sect);
		}

		/* If we are starting a new section then prepare it now */
		إذا (next_state != state || force_new_sect) {
			KRL_DBG(("start state 0x%02x",
			    next_state));
			state = next_state;
			sshbuf_reset(sect);
			بدل (state) {
			حالة KRL_SECTION_CERT_SERIAL_LIST:
			حالة KRL_SECTION_CERT_SERIAL_RANGE:
				اكسر;
			حالة KRL_SECTION_CERT_SERIAL_BITMAP:
				إذا ((bitmap = bitmap_new()) == عدم) {
					r = SSH_ERR_ALLOC_FAIL;
					اذهب out;
				}
				bitmap_start = rs->lo;
				إذا ((r = sshbuf_put_u64(sect,
				    bitmap_start)) != 0)
					اذهب out;
				اكسر;
			}
		}

		/* Perform section-specific processing */
		بدل (state) {
		حالة KRL_SECTION_CERT_SERIAL_LIST:
			لكل (i = 0; i < contig; i++) {
				إذا ((r = sshbuf_put_u64(sect, rs->lo + i)) != 0)
					اذهب out;
			}
			اكسر;
		حالة KRL_SECTION_CERT_SERIAL_RANGE:
			إذا ((r = sshbuf_put_u64(sect, rs->lo)) != 0 ||
			    (r = sshbuf_put_u64(sect, rs->hi)) != 0)
				اذهب out;
			اكسر;
		حالة KRL_SECTION_CERT_SERIAL_BITMAP:
			إذا (rs->lo - bitmap_start > INT_MAX) {
				r = SSH_ERR_INVALID_FORMAT;
				error_f("insane bitmap gap");
				اذهب out;
			}
			لكل (i = 0; i < contig; i++) {
				إذا (bitmap_set_bit(bitmap,
				    rs->lo + i - bitmap_start) != 0) {
					r = SSH_ERR_ALLOC_FAIL;
					اذهب out;
				}
			}
			اكسر;
		}
		last = rs->hi;
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
				اذهب out;
			bitmap_free(bitmap);
			bitmap = عدم;
			اكسر;
		}
		إذا ((r = sshbuf_put_u8(buf, state)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب out;
	}
	KRL_DBG(("serial done "));

	/* Now output a section for any revocations by key ID */
	sshbuf_reset(sect);
	RB_FOREACH(rki, revoked_کلیل_id_درەخت, &rc->revoked_کلیل_ids) {
		KRL_DBG(("key ID %s", rki->کلیل_id));
		إذا ((r = sshbuf_put_cstring(sect, rki->کلیل_id)) != 0)
			اذهب out;
	}
	إذا (sshbuf_len(sect) != 0) {
		إذا ((r = sshbuf_put_u8(buf, KRL_SECTION_CERT_کلیل_ID)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب out;
	}
	r = 0;
 out:
	bitmap_free(bitmap);
	sshbuf_free(sect);
	أرجع r;
}

صحيح
ssh_krl_to_blob(بنية ssh_krl *krl, بنية sshbuf *buf)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;
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
	    (r = sshbuf_put_u32(buf, KRL_FORMAT_VERSION)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->krl_version)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->generated_date)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->flags)) != 0 ||
	    (r = sshbuf_put_string(buf, عدم, 0)) != 0 ||
	    (r = sshbuf_put_cstring(buf, krl->comment)) != 0)
		اذهب out;

	/* Store sections for revoked certificates */
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		sshbuf_reset(sect);
		إذا ((r = revoked_certs_generate(rc, sect)) != 0)
			اذهب out;
		إذا ((r = sshbuf_put_u8(buf, KRL_SECTION_CERTIFICATES)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب out;
	}

	/* Finally, output sections for revocations by public key/hash */
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_درەخت, &krl->revoked_کلیلەکان) {
		KRL_DBG(("key len %zu ", rb->len));
		إذا ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			اذهب out;
	}
	إذا (sshbuf_len(sect) != 0) {
		إذا ((r = sshbuf_put_u8(buf, KRL_SECTION_EXPLICIT_کلیل)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_درەخت, &krl->revoked_sha1s) {
		KRL_DBG(("hash len %zu ", rb->len));
		إذا ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			اذهب out;
	}
	إذا (sshbuf_len(sect) != 0) {
		إذا ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA1)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_درەخت, &krl->revoked_sha256s) {
		KRL_DBG(("hash len %zu ", rb->len));
		إذا ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			اذهب out;
	}
	إذا (sshbuf_len(sect) != 0) {
		إذا ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA256)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب out;
	}
	/* success */
	r = 0;
 out:
	حرر(sblob);
	sshbuf_free(sect);
	أرجع r;
}

ساكن فراغ
format_timestamp(uint64_t timestamp, حرف *ts, size_t nts)
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
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	بنية sshbuf *بەها = عدم;
	حرف *name = عدم;

	إذا ((r = sshbuf_get_cstring(subsect, &name, عدم)) != 0 ||
	    (r = sshbuf_get_u8(subsect, &critical)) != 0 ||
	    (r = sshbuf_froms(subsect, &بەها)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid certificate extension subsection");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	إذا (sshbuf_len(subsect) != 0) {
		error("KRL has invalid certificate extension subsection: "
		    "trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	debug_f("cert extension %s critical %u len %zu",
	    name, critical, sshbuf_len(بەها));
	/* no extensions are currently supported */
	إذا (critical) {
		error("KRL contains unsupported critical certificate "
		    "subsection \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		اذهب out;
	}
	/* success */
	r = 0;
 out:
	حرر(name);
	sshbuf_free(بەها);
	أرجع r;
}

ساكن صحيح
parse_revoked_certs(بنية sshbuf *buf, بنية ssh_krl *krl)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	ثابت u_char *blob;
	size_t blen, nbits;
	بنية sshbuf *subsect = عدم;
	uint64_t serial, serial_lo, serial_hi;
	بنية bitmap *bitmap = عدم;
	حرف *کلیل_id = عدم;
	بنية sshkey *ca_کلیل = عدم;

	إذا ((subsect = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;

	/* Header: key, reserved */
	إذا ((r = sshbuf_get_string_direct(buf, &blob, &blen)) != 0 ||
	    (r = sshbuf_skip_string(buf)) != 0)
		اذهب out;
	إذا (blen != 0 && (r = sshkey_from_blob(blob, blen, &ca_کلیل)) != 0)
		اذهب out;

	طالما (sshbuf_len(buf) > 0) {
		sshbuf_free(subsect);
		subsect = عدم;
		إذا ((r = sshbuf_get_u8(buf, &type)) != 0 ||
		    (r = sshbuf_froms(buf, &subsect)) != 0)
			اذهب out;
		KRL_DBG(("subsection type 0x%02x", type));
		/* sshbuf_dump(subsect, stderr); */

		بدل (type) {
		حالة KRL_SECTION_CERT_SERIAL_LIST:
			طالما (sshbuf_len(subsect) > 0) {
				إذا ((r = sshbuf_get_u64(subsect, &serial)) != 0)
					اذهب out;
				إذا ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_کلیل, serial)) != 0)
					اذهب out;
			}
			اكسر;
		حالة KRL_SECTION_CERT_SERIAL_RANGE:
			إذا ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_u64(subsect, &serial_hi)) != 0)
				اذهب out;
			إذا ((r = ssh_krl_revoke_cert_by_serial_range(krl,
			    ca_کلیل, serial_lo, serial_hi)) != 0)
				اذهب out;
			اكسر;
		حالة KRL_SECTION_CERT_SERIAL_BITMAP:
			إذا ((bitmap = bitmap_new()) == عدم) {
				r = SSH_ERR_ALLOC_FAIL;
				اذهب out;
			}
			إذا ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_bignum2_bytes_direct(subsect,
			    &blob, &blen)) != 0)
				اذهب out;
			إذا (bitmap_from_string(bitmap, blob, blen) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				اذهب out;
			}
			nbits = bitmap_nbits(bitmap);
			لكل (serial = 0; serial < (uint64_t)nbits; serial++) {
				إذا (serial > 0 && serial_lo + serial == 0) {
					error_f("bitmap wraps u64");
					r = SSH_ERR_INVALID_FORMAT;
					اذهب out;
				}
				إذا (!bitmap_test_bit(bitmap, serial))
					استمر;
				إذا ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_کلیل, serial_lo + serial)) != 0)
					اذهب out;
			}
			bitmap_free(bitmap);
			bitmap = عدم;
			اكسر;
		حالة KRL_SECTION_CERT_کلیل_ID:
			طالما (sshbuf_len(subsect) > 0) {
				إذا ((r = sshbuf_get_cstring(subsect,
				    &کلیل_id, عدم)) != 0)
					اذهب out;
				إذا ((r = ssh_krl_revoke_cert_by_کلیل_id(krl,
				    ca_کلیل, کلیل_id)) != 0)
					اذهب out;
				حرر(کلیل_id);
				کلیل_id = عدم;
			}
			اكسر;
		حالة KRL_SECTION_CERT_EXTENSION:
			إذا ((r = cert_extension_subsection(subsect, krl)) != 0)
				اذهب out;
			اكسر;
		افتراضي:
			error("Unsupported KRL certificate section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		إذا (sshbuf_len(subsect) > 0) {
			error("KRL certificate section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
	}

	r = 0;
 out:
	إذا (bitmap != عدم)
		bitmap_free(bitmap);
	حرر(کلیل_id);
	sshkey_free(ca_کلیل);
	sshbuf_free(subsect);
	أرجع r;
}

ساكن صحيح
blob_section(بنية sshbuf *sect, بنية revoked_blob_درەخت *target_درەخت,
    size_t expected_len)
{
	u_char *rdata = عدم;
	size_t rlen = 0;
	صحيح r;

	طالما (sshbuf_len(sect) > 0) {
		إذا ((r = sshbuf_get_string(sect, &rdata, &rlen)) != 0)
			أرجع r;
		إذا (expected_len != 0 && rlen != expected_len) {
			error_f("bad length");
			حرر(rdata);
			أرجع SSH_ERR_INVALID_FORMAT;
		}
		إذا ((r = revoke_blob(target_درەخت, rdata, rlen)) != 0) {
			حرر(rdata);
			أرجع r;
		}
	}
	أرجع 0;
}

ساكن صحيح
extension_section(بنية sshbuf *sect, بنية ssh_krl *krl)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	بنية sshbuf *بەها = عدم;
	حرف *name = عدم;

	إذا ((r = sshbuf_get_cstring(sect, &name, عدم)) != 0 ||
	    (r = sshbuf_get_u8(sect, &critical)) != 0 ||
	    (r = sshbuf_froms(sect, &بەها)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid extension section");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	إذا (sshbuf_len(sect) != 0) {
		error("KRL has invalid extension section: trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	debug_f("extension %s critical %u len %zu",
	    name, critical, sshbuf_len(بەها));
	/* no extensions are currently supported */
	إذا (critical) {
		error("KRL contains unsupported critical section \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		اذهب out;
	}
	/* success */
	r = 0;
 out:
	حرر(name);
	sshbuf_free(بەها);
	أرجع r;
}

/* Attempt to parse a KRL */
صحيح
ssh_krl_from_blob(بنية sshbuf *buf, بنية ssh_krl **krlp)
{
	بنية sshbuf *copy = عدم, *sect = عدم;
	بنية ssh_krl *krl = عدم;
	حرف timestamp[64];
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	u_int format_version;

	*krlp = عدم;

	/* KRL must begin with magic string */
	إذا ((r = sshbuf_cmp(buf, 0, KRL_MAGIC, حجم(KRL_MAGIC) - 1)) != 0) {
		debug2_f("bad KRL magic header");
		أرجع SSH_ERR_KRL_BAD_MAGIC;
	}

	إذا ((krl = ssh_krl_init()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		error_f("alloc failed");
		اذهب out;
	}
	/* Don't modify buffer */
	إذا ((copy = sshbuf_fromb(buf)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((r = sshbuf_consume(copy, حجم(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_get_u32(copy, &format_version)) != 0)
		اذهب out;
	إذا (format_version != KRL_FORMAT_VERSION) {
		error_f("unsupported KRL format version %u", format_version);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	إذا ((r = sshbuf_get_u64(copy, &krl->krl_version)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->generated_date)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->flags)) != 0 ||
	    (r = sshbuf_skip_string(copy)) != 0 ||
	    (r = sshbuf_get_cstring(copy, &krl->comment, عدم)) != 0) {
		error_fr(r, "parse KRL header");
		اذهب out;
	}
	format_timestamp(krl->generated_date, timestamp, حجم(timestamp));
	debug("KRL version %llu generated at %s%s%s",
	    (long long unsigned)krl->krl_version, timestamp,
	    *krl->comment ? ": " : "", krl->comment);

	/* Parse and load the KRL sections. */
	طالما (sshbuf_len(copy) > 0) {
		sshbuf_free(sect);
		sect = عدم;
		إذا ((r = sshbuf_get_u8(copy, &type)) != 0 ||
		    (r = sshbuf_froms(copy, &sect)) != 0)
			اذهب out;
		KRL_DBG(("section 0x%02x", type));

		بدل (type) {
		حالة KRL_SECTION_CERTIFICATES:
			إذا ((r = parse_revoked_certs(sect, krl)) != 0)
				اذهب out;
			اكسر;
		حالة KRL_SECTION_EXPLICIT_کلیل:
			إذا ((r = blob_section(sect,
			    &krl->revoked_کلیلەکان, 0)) != 0)
				اذهب out;
			اكسر;
		حالة KRL_SECTION_FINGERPRINT_SHA1:
			إذا ((r = blob_section(sect,
			    &krl->revoked_sha1s, 20)) != 0)
				اذهب out;
			اكسر;
		حالة KRL_SECTION_FINGERPRINT_SHA256:
			إذا ((r = blob_section(sect,
			    &krl->revoked_sha256s, 32)) != 0)
				اذهب out;
			اكسر;
		حالة KRL_SECTION_EXTENSION:
			إذا ((r = extension_section(sect, krl)) != 0)
				اذهب out;
			اكسر;
		حالة KRL_SECTION_SIGNATURE:
			/* Handled above, but still need to stay in synch */
			sshbuf_free(sect);
			sect = عدم;
			إذا ((r = sshbuf_skip_string(copy)) != 0)
				اذهب out;
			اكسر;
		افتراضي:
			error("Unsupported KRL section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		إذا (sect != عدم && sshbuf_len(sect) > 0) {
			error("KRL section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
	}

	/* Success */
	*krlp = krl;
	r = 0;
 out:
	إذا (r != 0)
		ssh_krl_free(krl);
	sshbuf_free(copy);
	sshbuf_free(sect);
	أرجع r;
}

/* Checks certificate serial number and key ID revocation */
ساكن صحيح
is_cert_revoked(ثابت بنية sshkey *کلیل, بنية revoked_certs *rc)
{
	بنية revoked_serial rs, *ers;
	بنية revoked_کلیل_id rki, *erki;

	/* Check revocation by cert key ID */
	memset(&rki, 0, حجم(rki));
	rki.کلیل_id = کلیل->cert->کلیل_id;
	erki = RB_FIND(revoked_کلیل_id_درەخت, &rc->revoked_کلیل_ids, &rki);
	إذا (erki != عدم) {
		KRL_DBG(("revoked by key ID"));
		أرجع SSH_ERR_کلیل_REVOKED;
	}

	/*
	 * Zero serials numbers are ignored (it's the default when the
	 * CA doesn't specify one).
	 */
	إذا (کلیل->cert->serial == 0)
		أرجع 0;

	memset(&rs, 0, حجم(rs));
	rs.lo = rs.hi = کلیل->cert->serial;
	ers = RB_FIND(revoked_serial_درەخت, &rc->revoked_serials, &rs);
	إذا (ers != عدم) {
		KRL_DBG(("revoked serial %llu matched %llu:%llu",
		    (unsigned long long)کلیل->cert->serial,
		    (unsigned long long)ers->lo,
		    (unsigned long long)ers->hi));
		أرجع SSH_ERR_کلیل_REVOKED;
	}
	أرجع 0;
}

/* Checks whether a given key/cert is revoked. Does not check its CA */
ساكن صحيح
is_کلیل_revoked(بنية ssh_krl *krl, ثابت بنية sshkey *کلیل)
{
	بنية revoked_blob rb, *erb;
	بنية revoked_certs *rc;
	صحيح r;

	/* Check explicitly revoked hashes first */
	memset(&rb, 0, حجم(rb));
	إذا ((r = sshkey_fingerprint_raw(کلیل, SSH_DIGEST_SHA1,
	    &rb.blob, &rb.len)) != 0)
		أرجع r;
	erb = RB_FIND(revoked_blob_درەخت, &krl->revoked_sha1s, &rb);
	حرر(rb.blob);
	إذا (erb != عدم) {
		KRL_DBG(("revoked by key SHA1"));
		أرجع SSH_ERR_کلیل_REVOKED;
	}
	memset(&rb, 0, حجم(rb));
	إذا ((r = sshkey_fingerprint_raw(کلیل, SSH_DIGEST_SHA256,
	    &rb.blob, &rb.len)) != 0)
		أرجع r;
	erb = RB_FIND(revoked_blob_درەخت, &krl->revoked_sha256s, &rb);
	حرر(rb.blob);
	إذا (erb != عدم) {
		KRL_DBG(("revoked by key SHA256"));
		أرجع SSH_ERR_کلیل_REVOKED;
	}

	/* Next, explicit keys */
	memset(&rb, 0, حجم(rb));
	إذا ((r = plain_کلیل_blob(کلیل, &rb.blob, &rb.len)) != 0)
		أرجع r;
	erb = RB_FIND(revoked_blob_درەخت, &krl->revoked_کلیلەکان, &rb);
	حرر(rb.blob);
	إذا (erb != عدم) {
		KRL_DBG(("revoked by explicit key"));
		أرجع SSH_ERR_کلیل_REVOKED;
	}

	إذا (!sshkey_is_cert(کلیل))
		أرجع 0;

	/* Check cert revocation for the specified CA */
	إذا ((r = revoked_certs_for_ca_کلیل(krl, کلیل->cert->signature_کلیل,
	    &rc, 0)) != 0)
		أرجع r;
	إذا (rc != عدم) {
		إذا ((r = is_cert_revoked(کلیل, rc)) != 0)
			أرجع r;
	}
	/* Check cert revocation for the wildcard CA */
	إذا ((r = revoked_certs_for_ca_کلیل(krl, عدم, &rc, 0)) != 0)
		أرجع r;
	إذا (rc != عدم) {
		إذا ((r = is_cert_revoked(کلیل, rc)) != 0)
			أرجع r;
	}

	KRL_DBG(("%llu no match", (unsigned long long)کلیل->cert->serial));
	أرجع 0;
}

صحيح
ssh_krl_check_کلیل(بنية ssh_krl *krl, ثابت بنية sshkey *کلیل)
{
	صحيح r;

	KRL_DBG(("checking key"));
	إذا ((r = is_کلیل_revoked(krl, کلیل)) != 0)
		أرجع r;
	إذا (sshkey_is_cert(کلیل)) {
		debug2_f("checking CA key");
		إذا ((r = is_کلیل_revoked(krl, کلیل->cert->signature_کلیل)) != 0)
			أرجع r;
	}
	KRL_DBG(("key okay"));
	أرجع 0;
}

صحيح
ssh_krl_file_contains_کلیل(ثابت حرف *path, ثابت بنية sshkey *کلیل)
{
	بنية sshbuf *krlbuf = عدم;
	بنية ssh_krl *krl = عدم;
	صحيح oerrno = 0, r;

	إذا (path == عدم)
		أرجع 0;
	إذا ((r = sshbuf_load_file(path, &krlbuf)) != 0) {
		oerrno = errno;
		اذهب out;
	}
	إذا ((r = ssh_krl_from_blob(krlbuf, &krl)) != 0)
		اذهب out;
	debug2_f("checking KRL %s", path);
	r = ssh_krl_check_کلیل(krl, کلیل);
 out:
	sshbuf_free(krlbuf);
	ssh_krl_free(krl);
	إذا (r != 0)
		errno = oerrno;
	أرجع r;
}

صحيح
krl_dump(بنية ssh_krl *krl, FILE *f)
{
	بنية sshkey *کلیل = عدم;
	بنية revoked_blob *rb;
	بنية revoked_certs *rc;
	بنية revoked_serial *rs;
	بنية revoked_کلیل_id *rki;
	صحيح r, ret = 0;
	حرف *fp, timestamp[64];

	/* Try to print in a KRL spec-compatible format */
	format_timestamp(krl->generated_date, timestamp, حجم(timestamp));
	fprintf(f, "# KRL version %llu\n", (unsigned long long)krl->krl_version);
	fprintf(f, "# Generated at %s\n", timestamp);
	إذا (krl->comment != عدم && *krl->comment != '\0') {
		r = INT_MAX;
		asmprintf(&fp, INT_MAX, &r, "%s", krl->comment);
		fprintf(f, "# Comment: %s\n", fp);
		حرر(fp);
	}
	fputc('\n', f);

	RB_FOREACH(rb, revoked_blob_درەخت, &krl->revoked_کلیلەکان) {
		إذا ((r = sshkey_from_blob(rb->blob, rb->len, &کلیل)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			error_r(r, "parse KRL key");
			استمر;
		}
		إذا ((fp = sshkey_fingerprint(کلیل, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == عدم) {
			ret = SSH_ERR_INVALID_FORMAT;
			error("sshkey_fingerprint failed");
			استمر;
		}
		fprintf(f, "hash: %s # %s\n", fp, sshkey_ssh_name(کلیل));
		حرر(fp);
		حرر(کلیل);
	}
	RB_FOREACH(rb, revoked_blob_درەخت, &krl->revoked_sha256s) {
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "hash: SHA256:%s\n", fp);
		حرر(fp);
	}
	RB_FOREACH(rb, revoked_blob_درەخت, &krl->revoked_sha1s) {
		/*
		 * There is not KRL spec keyword for raw SHA1 hashes, so
		 * print them as comments.
		 */
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "# hash SHA1:%s\n", fp);
		حرر(fp);
	}

	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		fputc('\n', f);
		إذا (rc->ca_کلیل == عدم)
			fprintf(f, "# Wildcard CA\n");
		وإلا {
			إذا ((fp = sshkey_fingerprint(rc->ca_کلیل,
			    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == عدم) {
				ret = SSH_ERR_INVALID_FORMAT;
				error("sshkey_fingerprint failed");
				استمر;
			}
			fprintf(f, "# CA key %s %s\n",
			    sshkey_ssh_name(rc->ca_کلیل), fp);
			حرر(fp);
		}
		RB_FOREACH(rs, revoked_serial_درەخت, &rc->revoked_serials) {
			إذا (rs->lo == rs->hi) {
				fprintf(f, "serial: %llu\n",
				    (unsigned long long)rs->lo);
			} وإلا {
				fprintf(f, "serial: %llu-%llu\n",
				    (unsigned long long)rs->lo,
				    (unsigned long long)rs->hi);
			}
		}
		RB_FOREACH(rki, revoked_کلیل_id_درەخت, &rc->revoked_کلیل_ids) {
			/*
			 * We don't want key IDs with embedded newlines to
			 * mess up the display.
			 */
			r = INT_MAX;
			asmprintf(&fp, INT_MAX, &r, "%s", rki->کلیل_id);
			fprintf(f, "id: %s\n", fp);
			حرر(fp);
		}
	}
	أرجع ret;
}
