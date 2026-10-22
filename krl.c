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
#ifdef DEBUG_KRL
# define KRL_DBG(x) debug3_f x
#وگرنه
# define KRL_DBG(x)
#endif

/*
 * Trees of revoked serial numbers, key IDs and keys. This allows
 * quick searching, querying and producing lists in canonical order.
 */

/* Tree of serial numbers. XXX make smarter: really need a real sparse bitmap */
ساختار revoked_serial {
	uint64_t lo, hi;
	RB_ENTRY(revoked_serial) درخت_entry;
};
ایستا صحیح serial_cmp(ساختار revoked_serial *a, ساختار revoked_serial *b);
RB_HEAD(revoked_serial_درخت, revoked_serial);
RB_GENERATE_STATIC(revoked_serial_درخت, revoked_serial, درخت_entry, serial_cmp)

/* Tree of key IDs */
ساختار revoked_کلید_id {
	نویسه *کلید_id;
	RB_ENTRY(revoked_کلید_id) درخت_entry;
};
ایستا صحیح کلید_id_cmp(ساختار revoked_کلید_id *a, ساختار revoked_کلید_id *b);
RB_HEAD(revoked_کلید_id_درخت, revoked_کلید_id);
RB_GENERATE_STATIC(revoked_کلید_id_درخت, revoked_کلید_id, درخت_entry, کلید_id_cmp)

/* Tree of blobs (used for keys and fingerprints) */
ساختار revoked_blob {
	u_char *blob;
	size_t len;
	RB_ENTRY(revoked_blob) درخت_entry;
};
ایستا صحیح blob_cmp(ساختار revoked_blob *a, ساختار revoked_blob *b);
RB_HEAD(revoked_blob_درخت, revoked_blob);
RB_GENERATE_STATIC(revoked_blob_درخت, revoked_blob, درخت_entry, blob_cmp)

/* Tracks revoked certs for a single CA */
ساختار revoked_certs {
	ساختار sshkey *ca_کلید;
	ساختار revoked_serial_درخت revoked_serials;
	ساختار revoked_کلید_id_درخت revoked_کلید_ids;
	TAILQ_ENTRY(revoked_certs) entry;
};
TAILQ_HEAD(revoked_certs_list, revoked_certs);

ساختار ssh_krl {
	uint64_t krl_version;
	uint64_t generated_date;
	uint64_t flags;
	نویسه *comment;
	ساختار revoked_blob_درخت revoked_کلیدها;
	ساختار revoked_blob_درخت revoked_sha1s;
	ساختار revoked_blob_درخت revoked_sha256s;
	ساختار revoked_certs_list revoked_certs;
};

/* Return equal if a and b overlap */
ایستا صحیح
serial_cmp(ساختار revoked_serial *a, ساختار revoked_serial *b)
{
	اگر (a->hi >= b->lo && a->lo <= b->hi)
		بازگشت 0;
	بازگشت a->lo < b->lo ? -1 : 1;
}

ایستا صحیح
کلید_id_cmp(ساختار revoked_کلید_id *a, ساختار revoked_کلید_id *b)
{
	بازگشت strcmp(a->کلید_id, b->کلید_id);
}

ایستا صحیح
blob_cmp(ساختار revoked_blob *a, ساختار revoked_blob *b)
{
	صحیح r;

	اگر (a->len != b->len) {
		اگر ((r = memcmp(a->blob, b->blob, MINIMUM(a->len, b->len))) != 0)
			بازگشت r;
		بازگشت a->len > b->len ? 1 : -1;
	} وگرنه
		بازگشت memcmp(a->blob, b->blob, a->len);
}

ساختار ssh_krl *
ssh_krl_init(تهی)
{
	ساختار ssh_krl *krl;

	اگر ((krl = calloc(1, اندازه(*krl))) == پوچ)
		بازگشت پوچ;
	RB_INIT(&krl->revoked_کلیدها);
	RB_INIT(&krl->revoked_sha1s);
	RB_INIT(&krl->revoked_sha256s);
	TAILQ_INIT(&krl->revoked_certs);
	بازگشت krl;
}

ایستا تهی
revoked_certs_free(ساختار revoked_certs *rc)
{
	ساختار revoked_serial *rs, *trs;
	ساختار revoked_کلید_id *rki, *trki;

	اگر (rc == پوچ)
		بازگشت;
	RB_FOREACH_SAFE(rs, revoked_serial_درخت, &rc->revoked_serials, trs) {
		RB_REMOVE(revoked_serial_درخت, &rc->revoked_serials, rs);
		آزاد(rs);
	}
	RB_FOREACH_SAFE(rki, revoked_کلید_id_درخت, &rc->revoked_کلید_ids, trki) {
		RB_REMOVE(revoked_کلید_id_درخت, &rc->revoked_کلید_ids, rki);
		آزاد(rki->کلید_id);
		آزاد(rki);
	}
	sshkey_free(rc->ca_کلید);
	freezero(rc, اندازه(*rc));
}

تهی
ssh_krl_free(ساختار ssh_krl *krl)
{
	ساختار revoked_blob *rb, *trb;
	ساختار revoked_certs *rc, *trc;

	اگر (krl == پوچ)
		بازگشت;

	آزاد(krl->comment);
	RB_FOREACH_SAFE(rb, revoked_blob_درخت, &krl->revoked_کلیدها, trb) {
		RB_REMOVE(revoked_blob_درخت, &krl->revoked_کلیدها, rb);
		آزاد(rb->blob);
		آزاد(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_درخت, &krl->revoked_sha1s, trb) {
		RB_REMOVE(revoked_blob_درخت, &krl->revoked_sha1s, rb);
		آزاد(rb->blob);
		آزاد(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_درخت, &krl->revoked_sha256s, trb) {
		RB_REMOVE(revoked_blob_درخت, &krl->revoked_sha256s, rb);
		آزاد(rb->blob);
		آزاد(rb);
	}
	TAILQ_FOREACH_SAFE(rc, &krl->revoked_certs, entry, trc) {
		TAILQ_REMOVE(&krl->revoked_certs, rc, entry);
		revoked_certs_free(rc);
	}
	آزاد(krl);
}

تهی
ssh_krl_set_version(ساختار ssh_krl *krl, uint64_t version)
{
	krl->krl_version = version;
}

صحیح
ssh_krl_set_comment(ساختار ssh_krl *krl, ثابت نویسه *comment)
{
	آزاد(krl->comment);
	اگر ((krl->comment = strdup(comment)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	بازگشت 0;
}

/*
 * Find the revoked_certs struct for a CA key. If allow_create is set then
 * create a new one in the tree if one did not exist already.
 */
ایستا صحیح
revoked_certs_for_ca_کلید(ساختار ssh_krl *krl, ثابت ساختار sshkey *ca_کلید,
    ساختار revoked_certs **rcp, صحیح allow_create)
{
	ساختار revoked_certs *rc;
	صحیح r;

	*rcp = پوچ;
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		اگر ((ca_کلید == پوچ && rc->ca_کلید == پوچ) ||
		    sshkey_equal(rc->ca_کلید, ca_کلید)) {
			*rcp = rc;
			بازگشت 0;
		}
	}
	اگر (!allow_create)
		بازگشت 0;
	/* If this CA doesn't exist in the list then add it now */
	اگر ((rc = calloc(1, اندازه(*rc))) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر (ca_کلید == پوچ)
		rc->ca_کلید = پوچ;
	وگرنه اگر ((r = sshkey_from_private(ca_کلید, &rc->ca_کلید)) != 0) {
		آزاد(rc);
		بازگشت r;
	}
	RB_INIT(&rc->revoked_serials);
	RB_INIT(&rc->revoked_کلید_ids);
	TAILQ_INSERT_TAIL(&krl->revoked_certs, rc, entry);
	KRL_DBG(("new CA %s", ca_کلید == پوچ ? "*" : sshkey_type(ca_کلید)));
	*rcp = rc;
	بازگشت 0;
}

ایستا صحیح
درج_serial_range(ساختار revoked_serial_درخت *rt, uint64_t lo, uint64_t hi)
{
	ساختار revoked_serial rs, *ers, *crs, *irs;

	KRL_DBG(("insert %llu:%llu",
	    (unsigned long long)lo, (unsigned long long)hi));
	memset(&rs, 0, اندازه(rs));
	rs.lo = lo;
	rs.hi = hi;
	ers = RB_NFIND(revoked_serial_درخت, rt, &rs);
	اگر (ers == پوچ || serial_cmp(ers, &rs) != 0) {
		/* No entry matches. Just insert */
		اگر ((irs = malloc(اندازه(rs))) == پوچ)
			بازگشت SSH_ERR_ALLOC_FAIL;
		memcpy(irs, &rs, اندازه(*irs));
		ers = RB_درج(revoked_serial_درخت, rt, irs);
		اگر (ers != پوچ) {
			KRL_DBG(("bad: ers != NULL"));
			/* Shouldn't happen */
			آزاد(irs);
			بازگشت SSH_ERR_INTERNAL_ERROR;
		}
		ers = irs;
	} وگرنه {
		KRL_DBG(("overlap found %llu:%llu",
		    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
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
	وقتی ((crs = RB_PREV(revoked_serial_درخت, rt, ers)) != پوچ) {
		KRL_DBG(("pred %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		اگر (ers->lo != 0 && crs->hi < ers->lo - 1)
			بشکن;
		/* This entry overlaps. */
		اگر (crs->lo < ers->lo) {
			ers->lo = crs->lo;
			KRL_DBG(("pred extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_درخت, rt, crs);
		آزاد(crs);
	}
	/* Check successors */
	وقتی ((crs = RB_NEXT(revoked_serial_درخت, rt, ers)) != پوچ) {
		KRL_DBG(("succ %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		اگر (ers->hi != (uint64_t)-1 && crs->lo > ers->hi + 1)
			بشکن;
		/* This entry overlaps. */
		اگر (crs->hi > ers->hi) {
			ers->hi = crs->hi;
			KRL_DBG(("succ extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_درخت, rt, crs);
		آزاد(crs);
	}
	KRL_DBG(("done, final %llu:%llu",
	    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
	بازگشت 0;
}

صحیح
ssh_krl_revoke_cert_by_serial(ساختار ssh_krl *krl, ثابت ساختار sshkey *ca_کلید,
    uint64_t serial)
{
	بازگشت ssh_krl_revoke_cert_by_serial_range(krl, ca_کلید, serial, serial);
}

صحیح
ssh_krl_revoke_cert_by_serial_range(ساختار ssh_krl *krl,
    ثابت ساختار sshkey *ca_کلید, uint64_t lo, uint64_t hi)
{
	ساختار revoked_certs *rc;
	صحیح r;

	اگر (lo > hi || lo == 0)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر ((r = revoked_certs_for_ca_کلید(krl, ca_کلید, &rc, 1)) != 0)
		بازگشت r;
	بازگشت درج_serial_range(&rc->revoked_serials, lo, hi);
}

صحیح
ssh_krl_revoke_cert_by_کلید_id(ساختار ssh_krl *krl, ثابت ساختار sshkey *ca_کلید,
    ثابت نویسه *کلید_id)
{
	ساختار revoked_کلید_id *rki, *erki;
	ساختار revoked_certs *rc;
	صحیح r;

	اگر ((r = revoked_certs_for_ca_کلید(krl, ca_کلید, &rc, 1)) != 0)
		بازگشت r;

	KRL_DBG(("revoke %s", کلید_id));
	اگر ((rki = calloc(1, اندازه(*rki))) == پوچ ||
	    (rki->کلید_id = strdup(کلید_id)) == پوچ) {
		آزاد(rki);
		بازگشت SSH_ERR_ALLOC_FAIL;
	}
	erki = RB_درج(revoked_کلید_id_درخت, &rc->revoked_کلید_ids, rki);
	اگر (erki != پوچ) {
		آزاد(rki->کلید_id);
		آزاد(rki);
	}
	بازگشت 0;
}

/* Convert "key" to a public key blob without any certificate information */
ایستا صحیح
plain_کلید_blob(ثابت ساختار sshkey *کلید, u_char **blob, size_t *blen)
{
	ساختار sshkey *kcopy;
	صحیح r;

	اگر ((r = sshkey_from_private(کلید, &kcopy)) != 0)
		بازگشت r;
	اگر (sshkey_is_cert(kcopy)) {
		اگر ((r = sshkey_drop_cert(kcopy)) != 0) {
			sshkey_free(kcopy);
			بازگشت r;
		}
	}
	r = sshkey_to_blob(kcopy, blob, blen);
	sshkey_free(kcopy);
	بازگشت r;
}

/* Revoke a key blob. Ownership of blob is transferred to the tree */
ایستا صحیح
revoke_blob(ساختار revoked_blob_درخت *rbt, u_char *blob, size_t len)
{
	ساختار revoked_blob *rb, *erb;

	اگر ((rb = calloc(1, اندازه(*rb))) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	rb->blob = blob;
	rb->len = len;
	erb = RB_درج(revoked_blob_درخت, rbt, rb);
	اگر (erb != پوچ) {
		آزاد(rb->blob);
		آزاد(rb);
	}
	بازگشت 0;
}

صحیح
ssh_krl_revoke_کلید_explicit(ساختار ssh_krl *krl, ثابت ساختار sshkey *کلید)
{
	u_char *blob;
	size_t len;
	صحیح r;

	debug3_f("revoke type %s", sshkey_type(کلید));
	اگر ((r = plain_کلید_blob(کلید, &blob, &len)) != 0)
		بازگشت r;
	بازگشت revoke_blob(&krl->revoked_کلیدها, blob, len);
}

ایستا صحیح
revoke_by_hash(ساختار revoked_blob_درخت *target, ثابت u_char *p, size_t len)
{
	u_char *blob;
	صحیح r;

	/* need to copy hash, as revoke_blob steals ownership */
	اگر ((blob = malloc(len)) == پوچ)
		بازگشت SSH_ERR_SYSTEM_ERROR;
	memcpy(blob, p, len);
	اگر ((r = revoke_blob(target, blob, len)) != 0) {
		آزاد(blob);
		بازگشت r;
	}
	بازگشت 0;
}

صحیح
ssh_krl_revoke_کلید_sha1(ساختار ssh_krl *krl, ثابت u_char *p, size_t len)
{
	debug3_f("revoke by sha1");
	اگر (len != 20)
		بازگشت SSH_ERR_INVALID_FORMAT;
	بازگشت revoke_by_hash(&krl->revoked_sha1s, p, len);
}

صحیح
ssh_krl_revoke_کلید_sha256(ساختار ssh_krl *krl, ثابت u_char *p, size_t len)
{
	debug3_f("revoke by sha256");
	اگر (len != 32)
		بازگشت SSH_ERR_INVALID_FORMAT;
	بازگشت revoke_by_hash(&krl->revoked_sha256s, p, len);
}

صحیح
ssh_krl_revoke_کلید(ساختار ssh_krl *krl, ثابت ساختار sshkey *کلید)
{
	/* XXX replace with SHA256? */
	اگر (!sshkey_is_cert(کلید))
		بازگشت ssh_krl_revoke_کلید_explicit(krl, کلید);

	اگر (کلید->cert->serial == 0) {
		بازگشت ssh_krl_revoke_cert_by_کلید_id(krl,
		    کلید->cert->signature_کلید,
		    کلید->cert->کلید_id);
	} وگرنه {
		بازگشت ssh_krl_revoke_cert_by_serial(krl,
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
ایستا صحیح
choose_next_state(صحیح current_state, uint64_t contig, صحیح final,
    uint64_t last_gap, uint64_t next_gap, size_t bitmap_len,
    صحیح *force_new_section)
{
	صحیح new_state;
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
	انتخاب (current_state) {
	حالت KRL_SECTION_CERT_SERIAL_LIST:
		cost_bitmap_restart = cost_bitmap = 8 + 64;
		بشکن;
	حالت KRL_SECTION_CERT_SERIAL_BITMAP:
		cost_list = 8;
		cost_bitmap_restart = 8 + 64;
		بشکن;
	حالت KRL_SECTION_CERT_SERIAL_RANGE:
	حالت 0:
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
	اگر (bitmap_len + cost_bitmap >= SSHBUF_MAX_BIGNUM) {
		KRL_DBG(("bitmap overfull len=%zu cost=%llu max=%u",
		    bitmap_len, (unsigned long long)cost_bitmap,
		    SSHBUF_MAX_BIGNUM));
		cost_bitmap = (uint64_t)-1;
	}

	/* Now pick the best choice */
	*force_new_section = 0;
	new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
	cost = cost_bitmap;
	اگر (cost_range < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_RANGE;
		cost = cost_range;
	}
	اگر (cost_list < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_LIST;
		cost = cost_list;
	}
	اگر (cost_bitmap_restart < cost) {
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
	بازگشت new_state;
}

ایستا صحیح
put_bitmap(ساختار sshbuf *buf, ساختار bitmap *bitmap)
{
	size_t len;
	u_char *blob;
	صحیح r;

	len = bitmap_nbytes(bitmap);
	اگر ((blob = malloc(len)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر (bitmap_to_string(bitmap, blob, len) != 0) {
		آزاد(blob);
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	r = sshbuf_put_bignum2_bytes(buf, blob, len);
	آزاد(blob);
	بازگشت r;
}

/* Generate a KRL_SECTION_CERTIFICATES KRL section */
ایستا صحیح
revoked_certs_generate(ساختار revoked_certs *rc, ساختار sshbuf *buf)
{
	صحیح final, force_new_sect, r = SSH_ERR_INTERNAL_ERROR;
	uint64_t i, contig, gap, last = 0, bitmap_start = 0;
	ساختار revoked_serial *rs, *nrs;
	ساختار revoked_کلید_id *rki;
	صحیح next_state, state = 0;
	size_t bitmap_len;
	ساختار sshbuf *sect;
	ساختار bitmap *bitmap = پوچ;

	اگر ((sect = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;

	/* Store the header: optional CA scope key, reserved */
	اگر (rc->ca_کلید == پوچ) {
		اگر ((r = sshbuf_put_string(buf, پوچ, 0)) != 0)
			برو out;
	} وگرنه {
		اگر ((r = sshkey_puts(rc->ca_کلید, buf)) != 0)
			برو out;
	}
	اگر ((r = sshbuf_put_string(buf, پوچ, 0)) != 0)
		برو out;

	/* Store the revoked serials.  */
	برای (rs = RB_MIN(revoked_serial_درخت, &rc->revoked_serials);
	     rs != پوچ;
	     rs = RB_NEXT(revoked_serial_درخت, &rc->revoked_serials, rs)) {
		KRL_DBG(("serial %llu:%llu state 0x%02x",
		    (long long unsigned)rs->lo, (long long unsigned)rs->hi,
		    state));

		/* Check contiguous length and gap to next section (if any) */
		nrs = RB_NEXT(revoked_serial_درخت, &rc->revoked_serials, rs);
		final = nrs == پوچ;
		gap = nrs == پوچ ? 0 : nrs->lo - rs->hi;
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
		اگر (state != 0 && (force_new_sect || next_state != state ||
		    state == KRL_SECTION_CERT_SERIAL_RANGE)) {
			KRL_DBG(("finish state 0x%02x", state));
			انتخاب (state) {
			حالت KRL_SECTION_CERT_SERIAL_LIST:
			حالت KRL_SECTION_CERT_SERIAL_RANGE:
				بشکن;
			حالت KRL_SECTION_CERT_SERIAL_BITMAP:
				اگر ((r = put_bitmap(sect, bitmap)) != 0)
					برو out;
				bitmap_free(bitmap);
				bitmap = پوچ;
				بشکن;
			}
			اگر ((r = sshbuf_put_u8(buf, state)) != 0 ||
			    (r = sshbuf_put_stringb(buf, sect)) != 0)
				برو out;
			sshbuf_reset(sect);
		}

		/* If we are starting a new section then prepare it now */
		اگر (next_state != state || force_new_sect) {
			KRL_DBG(("start state 0x%02x",
			    next_state));
			state = next_state;
			sshbuf_reset(sect);
			انتخاب (state) {
			حالت KRL_SECTION_CERT_SERIAL_LIST:
			حالت KRL_SECTION_CERT_SERIAL_RANGE:
				بشکن;
			حالت KRL_SECTION_CERT_SERIAL_BITMAP:
				اگر ((bitmap = bitmap_new()) == پوچ) {
					r = SSH_ERR_ALLOC_FAIL;
					برو out;
				}
				bitmap_start = rs->lo;
				اگر ((r = sshbuf_put_u64(sect,
				    bitmap_start)) != 0)
					برو out;
				بشکن;
			}
		}

		/* Perform section-specific processing */
		انتخاب (state) {
		حالت KRL_SECTION_CERT_SERIAL_LIST:
			برای (i = 0; i < contig; i++) {
				اگر ((r = sshbuf_put_u64(sect, rs->lo + i)) != 0)
					برو out;
			}
			بشکن;
		حالت KRL_SECTION_CERT_SERIAL_RANGE:
			اگر ((r = sshbuf_put_u64(sect, rs->lo)) != 0 ||
			    (r = sshbuf_put_u64(sect, rs->hi)) != 0)
				برو out;
			بشکن;
		حالت KRL_SECTION_CERT_SERIAL_BITMAP:
			اگر (rs->lo - bitmap_start > INT_MAX) {
				r = SSH_ERR_INVALID_FORMAT;
				error_f("insane bitmap gap");
				برو out;
			}
			برای (i = 0; i < contig; i++) {
				اگر (bitmap_set_bit(bitmap,
				    rs->lo + i - bitmap_start) != 0) {
					r = SSH_ERR_ALLOC_FAIL;
					برو out;
				}
			}
			بشکن;
		}
		last = rs->hi;
	}
	/* Flush the remaining section, if any */
	اگر (state != 0) {
		KRL_DBG(("serial final flush for state 0x%02x", state));
		انتخاب (state) {
		حالت KRL_SECTION_CERT_SERIAL_LIST:
		حالت KRL_SECTION_CERT_SERIAL_RANGE:
			بشکن;
		حالت KRL_SECTION_CERT_SERIAL_BITMAP:
			اگر ((r = put_bitmap(sect, bitmap)) != 0)
				برو out;
			bitmap_free(bitmap);
			bitmap = پوچ;
			بشکن;
		}
		اگر ((r = sshbuf_put_u8(buf, state)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			برو out;
	}
	KRL_DBG(("serial done "));

	/* Now output a section for any revocations by key ID */
	sshbuf_reset(sect);
	RB_FOREACH(rki, revoked_کلید_id_درخت, &rc->revoked_کلید_ids) {
		KRL_DBG(("key ID %s", rki->کلید_id));
		اگر ((r = sshbuf_put_cstring(sect, rki->کلید_id)) != 0)
			برو out;
	}
	اگر (sshbuf_len(sect) != 0) {
		اگر ((r = sshbuf_put_u8(buf, KRL_SECTION_CERT_کلید_ID)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			برو out;
	}
	r = 0;
 out:
	bitmap_free(bitmap);
	sshbuf_free(sect);
	بازگشت r;
}

صحیح
ssh_krl_to_blob(ساختار ssh_krl *krl, ساختار sshbuf *buf)
{
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	ساختار revoked_certs *rc;
	ساختار revoked_blob *rb;
	ساختار sshbuf *sect;
	u_char *sblob = پوچ;

	اگر (krl->generated_date == 0)
		krl->generated_date = time(پوچ);

	اگر ((sect = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;

	/* Store the header */
	اگر ((r = sshbuf_put(buf, KRL_MAGIC, اندازه(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_put_u32(buf, KRL_FORMAT_VERSION)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->krl_version)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->generated_date)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->flags)) != 0 ||
	    (r = sshbuf_put_string(buf, پوچ, 0)) != 0 ||
	    (r = sshbuf_put_cstring(buf, krl->comment)) != 0)
		برو out;

	/* Store sections for revoked certificates */
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		sshbuf_reset(sect);
		اگر ((r = revoked_certs_generate(rc, sect)) != 0)
			برو out;
		اگر ((r = sshbuf_put_u8(buf, KRL_SECTION_CERTIFICATES)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			برو out;
	}

	/* Finally, output sections for revocations by public key/hash */
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_درخت, &krl->revoked_کلیدها) {
		KRL_DBG(("key len %zu ", rb->len));
		اگر ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			برو out;
	}
	اگر (sshbuf_len(sect) != 0) {
		اگر ((r = sshbuf_put_u8(buf, KRL_SECTION_EXPLICIT_کلید)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			برو out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_درخت, &krl->revoked_sha1s) {
		KRL_DBG(("hash len %zu ", rb->len));
		اگر ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			برو out;
	}
	اگر (sshbuf_len(sect) != 0) {
		اگر ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA1)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			برو out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_درخت, &krl->revoked_sha256s) {
		KRL_DBG(("hash len %zu ", rb->len));
		اگر ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			برو out;
	}
	اگر (sshbuf_len(sect) != 0) {
		اگر ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA256)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			برو out;
	}
	/* success */
	r = 0;
 out:
	آزاد(sblob);
	sshbuf_free(sect);
	بازگشت r;
}

ایستا تهی
format_timestamp(uint64_t timestamp, نویسه *ts, size_t nts)
{
	time_t t;
	ساختار tm *tm;

	t = timestamp;
	tm = localtime(&t);
	اگر (tm == پوچ)
		strlcpy(ts, "<INVALID>", nts);
	وگرنه {
		*ts = '\0';
		strftime(ts, nts, "%Y%m%dT%H%M%S", tm);
	}
}

ایستا صحیح
cert_extension_subsection(ساختار sshbuf *subsect, ساختار ssh_krl *krl)
{
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	ساختار sshbuf *مقدار = پوچ;
	نویسه *name = پوچ;

	اگر ((r = sshbuf_get_cstring(subsect, &name, پوچ)) != 0 ||
	    (r = sshbuf_get_u8(subsect, &critical)) != 0 ||
	    (r = sshbuf_froms(subsect, &مقدار)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid certificate extension subsection");
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (sshbuf_len(subsect) != 0) {
		error("KRL has invalid certificate extension subsection: "
		    "trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	debug_f("cert extension %s critical %u len %zu",
	    name, critical, sshbuf_len(مقدار));
	/* no extensions are currently supported */
	اگر (critical) {
		error("KRL contains unsupported critical certificate "
		    "subsection \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		برو out;
	}
	/* success */
	r = 0;
 out:
	آزاد(name);
	sshbuf_free(مقدار);
	بازگشت r;
}

ایستا صحیح
parse_revoked_certs(ساختار sshbuf *buf, ساختار ssh_krl *krl)
{
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	ثابت u_char *blob;
	size_t blen, nbits;
	ساختار sshbuf *subsect = پوچ;
	uint64_t serial, serial_lo, serial_hi;
	ساختار bitmap *bitmap = پوچ;
	نویسه *کلید_id = پوچ;
	ساختار sshkey *ca_کلید = پوچ;

	اگر ((subsect = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;

	/* Header: key, reserved */
	اگر ((r = sshbuf_get_string_direct(buf, &blob, &blen)) != 0 ||
	    (r = sshbuf_skip_string(buf)) != 0)
		برو out;
	اگر (blen != 0 && (r = sshkey_from_blob(blob, blen, &ca_کلید)) != 0)
		برو out;

	وقتی (sshbuf_len(buf) > 0) {
		sshbuf_free(subsect);
		subsect = پوچ;
		اگر ((r = sshbuf_get_u8(buf, &type)) != 0 ||
		    (r = sshbuf_froms(buf, &subsect)) != 0)
			برو out;
		KRL_DBG(("subsection type 0x%02x", type));
		/* sshbuf_dump(subsect, stderr); */

		انتخاب (type) {
		حالت KRL_SECTION_CERT_SERIAL_LIST:
			وقتی (sshbuf_len(subsect) > 0) {
				اگر ((r = sshbuf_get_u64(subsect, &serial)) != 0)
					برو out;
				اگر ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_کلید, serial)) != 0)
					برو out;
			}
			بشکن;
		حالت KRL_SECTION_CERT_SERIAL_RANGE:
			اگر ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_u64(subsect, &serial_hi)) != 0)
				برو out;
			اگر ((r = ssh_krl_revoke_cert_by_serial_range(krl,
			    ca_کلید, serial_lo, serial_hi)) != 0)
				برو out;
			بشکن;
		حالت KRL_SECTION_CERT_SERIAL_BITMAP:
			اگر ((bitmap = bitmap_new()) == پوچ) {
				r = SSH_ERR_ALLOC_FAIL;
				برو out;
			}
			اگر ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_bignum2_bytes_direct(subsect,
			    &blob, &blen)) != 0)
				برو out;
			اگر (bitmap_from_string(bitmap, blob, blen) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				برو out;
			}
			nbits = bitmap_nbits(bitmap);
			برای (serial = 0; serial < (uint64_t)nbits; serial++) {
				اگر (serial > 0 && serial_lo + serial == 0) {
					error_f("bitmap wraps u64");
					r = SSH_ERR_INVALID_FORMAT;
					برو out;
				}
				اگر (!bitmap_test_bit(bitmap, serial))
					ادامه;
				اگر ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_کلید, serial_lo + serial)) != 0)
					برو out;
			}
			bitmap_free(bitmap);
			bitmap = پوچ;
			بشکن;
		حالت KRL_SECTION_CERT_کلید_ID:
			وقتی (sshbuf_len(subsect) > 0) {
				اگر ((r = sshbuf_get_cstring(subsect,
				    &کلید_id, پوچ)) != 0)
					برو out;
				اگر ((r = ssh_krl_revoke_cert_by_کلید_id(krl,
				    ca_کلید, کلید_id)) != 0)
					برو out;
				آزاد(کلید_id);
				کلید_id = پوچ;
			}
			بشکن;
		حالت KRL_SECTION_CERT_EXTENSION:
			اگر ((r = cert_extension_subsection(subsect, krl)) != 0)
				برو out;
			بشکن;
		پیشفرض:
			error("Unsupported KRL certificate section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
		اگر (sshbuf_len(subsect) > 0) {
			error("KRL certificate section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
	}

	r = 0;
 out:
	اگر (bitmap != پوچ)
		bitmap_free(bitmap);
	آزاد(کلید_id);
	sshkey_free(ca_کلید);
	sshbuf_free(subsect);
	بازگشت r;
}

ایستا صحیح
blob_section(ساختار sshbuf *sect, ساختار revoked_blob_درخت *target_درخت,
    size_t expected_len)
{
	u_char *rdata = پوچ;
	size_t rlen = 0;
	صحیح r;

	وقتی (sshbuf_len(sect) > 0) {
		اگر ((r = sshbuf_get_string(sect, &rdata, &rlen)) != 0)
			بازگشت r;
		اگر (expected_len != 0 && rlen != expected_len) {
			error_f("bad length");
			آزاد(rdata);
			بازگشت SSH_ERR_INVALID_FORMAT;
		}
		اگر ((r = revoke_blob(target_درخت, rdata, rlen)) != 0) {
			آزاد(rdata);
			بازگشت r;
		}
	}
	بازگشت 0;
}

ایستا صحیح
extension_section(ساختار sshbuf *sect, ساختار ssh_krl *krl)
{
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	ساختار sshbuf *مقدار = پوچ;
	نویسه *name = پوچ;

	اگر ((r = sshbuf_get_cstring(sect, &name, پوچ)) != 0 ||
	    (r = sshbuf_get_u8(sect, &critical)) != 0 ||
	    (r = sshbuf_froms(sect, &مقدار)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid extension section");
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (sshbuf_len(sect) != 0) {
		error("KRL has invalid extension section: trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	debug_f("extension %s critical %u len %zu",
	    name, critical, sshbuf_len(مقدار));
	/* no extensions are currently supported */
	اگر (critical) {
		error("KRL contains unsupported critical section \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		برو out;
	}
	/* success */
	r = 0;
 out:
	آزاد(name);
	sshbuf_free(مقدار);
	بازگشت r;
}

/* Attempt to parse a KRL */
صحیح
ssh_krl_from_blob(ساختار sshbuf *buf, ساختار ssh_krl **krlp)
{
	ساختار sshbuf *copy = پوچ, *sect = پوچ;
	ساختار ssh_krl *krl = پوچ;
	نویسه timestamp[64];
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	u_int format_version;

	*krlp = پوچ;

	/* KRL must begin with magic string */
	اگر ((r = sshbuf_cmp(buf, 0, KRL_MAGIC, اندازه(KRL_MAGIC) - 1)) != 0) {
		debug2_f("bad KRL magic header");
		بازگشت SSH_ERR_KRL_BAD_MAGIC;
	}

	اگر ((krl = ssh_krl_init()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		error_f("alloc failed");
		برو out;
	}
	/* Don't modify buffer */
	اگر ((copy = sshbuf_fromb(buf)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshbuf_consume(copy, اندازه(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_get_u32(copy, &format_version)) != 0)
		برو out;
	اگر (format_version != KRL_FORMAT_VERSION) {
		error_f("unsupported KRL format version %u", format_version);
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر ((r = sshbuf_get_u64(copy, &krl->krl_version)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->generated_date)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->flags)) != 0 ||
	    (r = sshbuf_skip_string(copy)) != 0 ||
	    (r = sshbuf_get_cstring(copy, &krl->comment, پوچ)) != 0) {
		error_fr(r, "parse KRL header");
		برو out;
	}
	format_timestamp(krl->generated_date, timestamp, اندازه(timestamp));
	debug("KRL version %llu generated at %s%s%s",
	    (long long unsigned)krl->krl_version, timestamp,
	    *krl->comment ? ": " : "", krl->comment);

	/* Parse and load the KRL sections. */
	وقتی (sshbuf_len(copy) > 0) {
		sshbuf_free(sect);
		sect = پوچ;
		اگر ((r = sshbuf_get_u8(copy, &type)) != 0 ||
		    (r = sshbuf_froms(copy, &sect)) != 0)
			برو out;
		KRL_DBG(("section 0x%02x", type));

		انتخاب (type) {
		حالت KRL_SECTION_CERTIFICATES:
			اگر ((r = parse_revoked_certs(sect, krl)) != 0)
				برو out;
			بشکن;
		حالت KRL_SECTION_EXPLICIT_کلید:
			اگر ((r = blob_section(sect,
			    &krl->revoked_کلیدها, 0)) != 0)
				برو out;
			بشکن;
		حالت KRL_SECTION_FINGERPRINT_SHA1:
			اگر ((r = blob_section(sect,
			    &krl->revoked_sha1s, 20)) != 0)
				برو out;
			بشکن;
		حالت KRL_SECTION_FINGERPRINT_SHA256:
			اگر ((r = blob_section(sect,
			    &krl->revoked_sha256s, 32)) != 0)
				برو out;
			بشکن;
		حالت KRL_SECTION_EXTENSION:
			اگر ((r = extension_section(sect, krl)) != 0)
				برو out;
			بشکن;
		حالت KRL_SECTION_SIGNATURE:
			/* Handled above, but still need to stay in synch */
			sshbuf_free(sect);
			sect = پوچ;
			اگر ((r = sshbuf_skip_string(copy)) != 0)
				برو out;
			بشکن;
		پیشفرض:
			error("Unsupported KRL section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
		اگر (sect != پوچ && sshbuf_len(sect) > 0) {
			error("KRL section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
	}

	/* Success */
	*krlp = krl;
	r = 0;
 out:
	اگر (r != 0)
		ssh_krl_free(krl);
	sshbuf_free(copy);
	sshbuf_free(sect);
	بازگشت r;
}

/* Checks certificate serial number and key ID revocation */
ایستا صحیح
is_cert_revoked(ثابت ساختار sshkey *کلید, ساختار revoked_certs *rc)
{
	ساختار revoked_serial rs, *ers;
	ساختار revoked_کلید_id rki, *erki;

	/* Check revocation by cert key ID */
	memset(&rki, 0, اندازه(rki));
	rki.کلید_id = کلید->cert->کلید_id;
	erki = RB_FIND(revoked_کلید_id_درخت, &rc->revoked_کلید_ids, &rki);
	اگر (erki != پوچ) {
		KRL_DBG(("revoked by key ID"));
		بازگشت SSH_ERR_کلید_REVOKED;
	}

	/*
	 * Zero serials numbers are ignored (it's the default when the
	 * CA doesn't specify one).
	 */
	اگر (کلید->cert->serial == 0)
		بازگشت 0;

	memset(&rs, 0, اندازه(rs));
	rs.lo = rs.hi = کلید->cert->serial;
	ers = RB_FIND(revoked_serial_درخت, &rc->revoked_serials, &rs);
	اگر (ers != پوچ) {
		KRL_DBG(("revoked serial %llu matched %llu:%llu",
		    (unsigned long long)کلید->cert->serial,
		    (unsigned long long)ers->lo,
		    (unsigned long long)ers->hi));
		بازگشت SSH_ERR_کلید_REVOKED;
	}
	بازگشت 0;
}

/* Checks whether a given key/cert is revoked. Does not check its CA */
ایستا صحیح
is_کلید_revoked(ساختار ssh_krl *krl, ثابت ساختار sshkey *کلید)
{
	ساختار revoked_blob rb, *erb;
	ساختار revoked_certs *rc;
	صحیح r;

	/* Check explicitly revoked hashes first */
	memset(&rb, 0, اندازه(rb));
	اگر ((r = sshkey_fingerprint_raw(کلید, SSH_DIGEST_SHA1,
	    &rb.blob, &rb.len)) != 0)
		بازگشت r;
	erb = RB_FIND(revoked_blob_درخت, &krl->revoked_sha1s, &rb);
	آزاد(rb.blob);
	اگر (erb != پوچ) {
		KRL_DBG(("revoked by key SHA1"));
		بازگشت SSH_ERR_کلید_REVOKED;
	}
	memset(&rb, 0, اندازه(rb));
	اگر ((r = sshkey_fingerprint_raw(کلید, SSH_DIGEST_SHA256,
	    &rb.blob, &rb.len)) != 0)
		بازگشت r;
	erb = RB_FIND(revoked_blob_درخت, &krl->revoked_sha256s, &rb);
	آزاد(rb.blob);
	اگر (erb != پوچ) {
		KRL_DBG(("revoked by key SHA256"));
		بازگشت SSH_ERR_کلید_REVOKED;
	}

	/* Next, explicit keys */
	memset(&rb, 0, اندازه(rb));
	اگر ((r = plain_کلید_blob(کلید, &rb.blob, &rb.len)) != 0)
		بازگشت r;
	erb = RB_FIND(revoked_blob_درخت, &krl->revoked_کلیدها, &rb);
	آزاد(rb.blob);
	اگر (erb != پوچ) {
		KRL_DBG(("revoked by explicit key"));
		بازگشت SSH_ERR_کلید_REVOKED;
	}

	اگر (!sshkey_is_cert(کلید))
		بازگشت 0;

	/* Check cert revocation for the specified CA */
	اگر ((r = revoked_certs_for_ca_کلید(krl, کلید->cert->signature_کلید,
	    &rc, 0)) != 0)
		بازگشت r;
	اگر (rc != پوچ) {
		اگر ((r = is_cert_revoked(کلید, rc)) != 0)
			بازگشت r;
	}
	/* Check cert revocation for the wildcard CA */
	اگر ((r = revoked_certs_for_ca_کلید(krl, پوچ, &rc, 0)) != 0)
		بازگشت r;
	اگر (rc != پوچ) {
		اگر ((r = is_cert_revoked(کلید, rc)) != 0)
			بازگشت r;
	}

	KRL_DBG(("%llu no match", (unsigned long long)کلید->cert->serial));
	بازگشت 0;
}

صحیح
ssh_krl_check_کلید(ساختار ssh_krl *krl, ثابت ساختار sshkey *کلید)
{
	صحیح r;

	KRL_DBG(("checking key"));
	اگر ((r = is_کلید_revoked(krl, کلید)) != 0)
		بازگشت r;
	اگر (sshkey_is_cert(کلید)) {
		debug2_f("checking CA key");
		اگر ((r = is_کلید_revoked(krl, کلید->cert->signature_کلید)) != 0)
			بازگشت r;
	}
	KRL_DBG(("key okay"));
	بازگشت 0;
}

صحیح
ssh_krl_file_contains_کلید(ثابت نویسه *path, ثابت ساختار sshkey *کلید)
{
	ساختار sshbuf *krlbuf = پوچ;
	ساختار ssh_krl *krl = پوچ;
	صحیح oerrno = 0, r;

	اگر (path == پوچ)
		بازگشت 0;
	اگر ((r = sshbuf_load_file(path, &krlbuf)) != 0) {
		oerrno = errno;
		برو out;
	}
	اگر ((r = ssh_krl_from_blob(krlbuf, &krl)) != 0)
		برو out;
	debug2_f("checking KRL %s", path);
	r = ssh_krl_check_کلید(krl, کلید);
 out:
	sshbuf_free(krlbuf);
	ssh_krl_free(krl);
	اگر (r != 0)
		errno = oerrno;
	بازگشت r;
}

صحیح
krl_dump(ساختار ssh_krl *krl, FILE *f)
{
	ساختار sshkey *کلید = پوچ;
	ساختار revoked_blob *rb;
	ساختار revoked_certs *rc;
	ساختار revoked_serial *rs;
	ساختار revoked_کلید_id *rki;
	صحیح r, ret = 0;
	نویسه *fp, timestamp[64];

	/* Try to print in a KRL spec-compatible format */
	format_timestamp(krl->generated_date, timestamp, اندازه(timestamp));
	fprintf(f, "# KRL version %llu\n", (unsigned long long)krl->krl_version);
	fprintf(f, "# Generated at %s\n", timestamp);
	اگر (krl->comment != پوچ && *krl->comment != '\0') {
		r = INT_MAX;
		asmprintf(&fp, INT_MAX, &r, "%s", krl->comment);
		fprintf(f, "# Comment: %s\n", fp);
		آزاد(fp);
	}
	fputc('\n', f);

	RB_FOREACH(rb, revoked_blob_درخت, &krl->revoked_کلیدها) {
		اگر ((r = sshkey_from_blob(rb->blob, rb->len, &کلید)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			error_r(r, "parse KRL key");
			ادامه;
		}
		اگر ((fp = sshkey_fingerprint(کلید, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == پوچ) {
			ret = SSH_ERR_INVALID_FORMAT;
			error("sshkey_fingerprint failed");
			ادامه;
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

	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		fputc('\n', f);
		اگر (rc->ca_کلید == پوچ)
			fprintf(f, "# Wildcard CA\n");
		وگرنه {
			اگر ((fp = sshkey_fingerprint(rc->ca_کلید,
			    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == پوچ) {
				ret = SSH_ERR_INVALID_FORMAT;
				error("sshkey_fingerprint failed");
				ادامه;
			}
			fprintf(f, "# CA key %s %s\n",
			    sshkey_ssh_name(rc->ca_کلید), fp);
			آزاد(fp);
		}
		RB_FOREACH(rs, revoked_serial_درخت, &rc->revoked_serials) {
			اگر (rs->lo == rs->hi) {
				fprintf(f, "serial: %llu\n",
				    (unsigned long long)rs->lo);
			} وگرنه {
				fprintf(f, "serial: %llu-%llu\n",
				    (unsigned long long)rs->lo,
				    (unsigned long long)rs->hi);
			}
		}
		RB_FOREACH(rki, revoked_کلید_id_درخت, &rc->revoked_کلید_ids) {
			/*
			 * We don't want key IDs with embedded newlines to
			 * mess up the display.
			 */
			r = INT_MAX;
			asmprintf(&fp, INT_MAX, &r, "%s", rki->کلید_id);
			fprintf(f, "id: %s\n", fp);
			آزاد(fp);
		}
	}
	بازگشت ret;
}
