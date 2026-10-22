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
#אחרת
# define KRL_DBG(x)
#endif

/*
 * Trees of revoked serial numbers, key IDs and keys. This allows
 * quick searching, querying and producing lists in canonical order.
 */

/* Tree of serial numbers. XXX make smarter: really need a real sparse bitmap */
بنية revoked_serial {
	uint64_t lo, hi;
	RB_ENTRY(revoked_serial) tree_entry;
};
ساكن صحيح serial_cmp(بنية revoked_serial *a, بنية revoked_serial *b);
RB_HEAD(revoked_serial_tree, revoked_serial);
RB_GENERATE_STATIC(revoked_serial_tree, revoked_serial, tree_entry, serial_cmp)

/* Tree of key IDs */
بنية revoked_key_id {
	حرف *key_id;
	RB_ENTRY(revoked_key_id) tree_entry;
};
ساكن صحيح key_id_cmp(بنية revoked_key_id *a, بنية revoked_key_id *b);
RB_HEAD(revoked_key_id_tree, revoked_key_id);
RB_GENERATE_STATIC(revoked_key_id_tree, revoked_key_id, tree_entry, key_id_cmp)

/* Tree of blobs (used for keys and fingerprints) */
بنية revoked_blob {
	u_char *blob;
	size_t len;
	RB_ENTRY(revoked_blob) tree_entry;
};
ساكن صحيح blob_cmp(بنية revoked_blob *a, بنية revoked_blob *b);
RB_HEAD(revoked_blob_tree, revoked_blob);
RB_GENERATE_STATIC(revoked_blob_tree, revoked_blob, tree_entry, blob_cmp)

/* Tracks revoked certs for a single CA */
بنية revoked_certs {
	بنية sshkey *ca_key;
	بنية revoked_serial_tree revoked_serials;
	بنية revoked_key_id_tree revoked_key_ids;
	TAILQ_ENTRY(revoked_certs) entry;
};
TAILQ_HEAD(revoked_certs_list, revoked_certs);

بنية ssh_krl {
	uint64_t krl_version;
	uint64_t generated_date;
	uint64_t flags;
	حرف *comment;
	بنية revoked_blob_tree revoked_keys;
	بنية revoked_blob_tree revoked_sha1s;
	بنية revoked_blob_tree revoked_sha256s;
	بنية revoked_certs_list revoked_certs;
};

/* Return equal if a and b overlap */
ساكن صحيح
serial_cmp(بنية revoked_serial *a, بنية revoked_serial *b)
{
	אם (a->hi >= b->lo && a->lo <= b->hi)
		החזר 0;
	החזר a->lo < b->lo ? -1 : 1;
}

ساكن صحيح
key_id_cmp(بنية revoked_key_id *a, بنية revoked_key_id *b)
{
	החזר strcmp(a->key_id, b->key_id);
}

ساكن صحيح
blob_cmp(بنية revoked_blob *a, بنية revoked_blob *b)
{
	صحيح r;

	אם (a->len != b->len) {
		אם ((r = memcmp(a->blob, b->blob, MINIMUM(a->len, b->len))) != 0)
			החזר r;
		החזר a->len > b->len ? 1 : -1;
	} אחרת
		החזר memcmp(a->blob, b->blob, a->len);
}

بنية ssh_krl *
ssh_krl_init(فراغ)
{
	بنية ssh_krl *krl;

	אם ((krl = calloc(1, حجم(*krl))) == عدم)
		החזר عدم;
	RB_INIT(&krl->revoked_keys);
	RB_INIT(&krl->revoked_sha1s);
	RB_INIT(&krl->revoked_sha256s);
	TAILQ_INIT(&krl->revoked_certs);
	החזר krl;
}

ساكن فراغ
revoked_certs_free(بنية revoked_certs *rc)
{
	بنية revoked_serial *rs, *trs;
	بنية revoked_key_id *rki, *trki;

	אם (rc == عدم)
		החזר;
	RB_FOREACH_SAFE(rs, revoked_serial_tree, &rc->revoked_serials, trs) {
		RB_REMOVE(revoked_serial_tree, &rc->revoked_serials, rs);
		حرر(rs);
	}
	RB_FOREACH_SAFE(rki, revoked_key_id_tree, &rc->revoked_key_ids, trki) {
		RB_REMOVE(revoked_key_id_tree, &rc->revoked_key_ids, rki);
		حرر(rki->key_id);
		حرر(rki);
	}
	sshkey_free(rc->ca_key);
	freezero(rc, حجم(*rc));
}

فراغ
ssh_krl_free(بنية ssh_krl *krl)
{
	بنية revoked_blob *rb, *trb;
	بنية revoked_certs *rc, *trc;

	אם (krl == عدم)
		החזר;

	حرر(krl->comment);
	RB_FOREACH_SAFE(rb, revoked_blob_tree, &krl->revoked_keys, trb) {
		RB_REMOVE(revoked_blob_tree, &krl->revoked_keys, rb);
		حرر(rb->blob);
		حرر(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_tree, &krl->revoked_sha1s, trb) {
		RB_REMOVE(revoked_blob_tree, &krl->revoked_sha1s, rb);
		حرر(rb->blob);
		حرر(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_tree, &krl->revoked_sha256s, trb) {
		RB_REMOVE(revoked_blob_tree, &krl->revoked_sha256s, rb);
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
	אם ((krl->comment = strdup(comment)) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	החזר 0;
}

/*
 * Find the revoked_certs struct for a CA key. If allow_create is set then
 * create a new one in the tree if one did not exist already.
 */
ساكن صحيح
revoked_certs_for_ca_key(بنية ssh_krl *krl, ثابت بنية sshkey *ca_key,
    بنية revoked_certs **rcp, صحيح allow_create)
{
	بنية revoked_certs *rc;
	صحيح r;

	*rcp = عدم;
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		אם ((ca_key == عدم && rc->ca_key == عدم) ||
		    sshkey_equal(rc->ca_key, ca_key)) {
			*rcp = rc;
			החזר 0;
		}
	}
	אם (!allow_create)
		החזר 0;
	/* If this CA doesn't exist in the list then add it now */
	אם ((rc = calloc(1, حجم(*rc))) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם (ca_key == عدم)
		rc->ca_key = عدم;
	אחרת אם ((r = sshkey_from_private(ca_key, &rc->ca_key)) != 0) {
		حرر(rc);
		החזר r;
	}
	RB_INIT(&rc->revoked_serials);
	RB_INIT(&rc->revoked_key_ids);
	TAILQ_INSERT_TAIL(&krl->revoked_certs, rc, entry);
	KRL_DBG(("new CA %s", ca_key == عدم ? "*" : sshkey_type(ca_key)));
	*rcp = rc;
	החזר 0;
}

ساكن صحيح
insert_serial_range(بنية revoked_serial_tree *rt, uint64_t lo, uint64_t hi)
{
	بنية revoked_serial rs, *ers, *crs, *irs;

	KRL_DBG(("insert %llu:%llu",
	    (unsigned long long)lo, (unsigned long long)hi));
	memset(&rs, 0, حجم(rs));
	rs.lo = lo;
	rs.hi = hi;
	ers = RB_NFIND(revoked_serial_tree, rt, &rs);
	אם (ers == عدم || serial_cmp(ers, &rs) != 0) {
		/* No entry matches. Just insert */
		אם ((irs = malloc(حجم(rs))) == عدم)
			החזר SSH_ERR_ALLOC_FAIL;
		memcpy(irs, &rs, حجم(*irs));
		ers = RB_INSERT(revoked_serial_tree, rt, irs);
		אם (ers != عدم) {
			KRL_DBG(("bad: ers != NULL"));
			/* Shouldn't happen */
			حرر(irs);
			החזר SSH_ERR_INTERNAL_ERROR;
		}
		ers = irs;
	} אחרת {
		KRL_DBG(("overlap found %llu:%llu",
		    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
		/*
		 * The inserted entry overlaps an existing one. Grow the
		 * existing entry.
		 */
		אם (ers->lo > lo)
			ers->lo = lo;
		אם (ers->hi < hi)
			ers->hi = hi;
	}

	/*
	 * The inserted or revised range might overlap or abut adjacent ones;
	 * coalesce as necessary.
	 */

	/* Check predecessors */
	כלעוד ((crs = RB_PREV(revoked_serial_tree, rt, ers)) != عدم) {
		KRL_DBG(("pred %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		אם (ers->lo != 0 && crs->hi < ers->lo - 1)
			اكسر;
		/* This entry overlaps. */
		אם (crs->lo < ers->lo) {
			ers->lo = crs->lo;
			KRL_DBG(("pred extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_tree, rt, crs);
		حرر(crs);
	}
	/* Check successors */
	כלעוד ((crs = RB_NEXT(revoked_serial_tree, rt, ers)) != عدم) {
		KRL_DBG(("succ %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		אם (ers->hi != (uint64_t)-1 && crs->lo > ers->hi + 1)
			اكسر;
		/* This entry overlaps. */
		אם (crs->hi > ers->hi) {
			ers->hi = crs->hi;
			KRL_DBG(("succ extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_tree, rt, crs);
		حرر(crs);
	}
	KRL_DBG(("done, final %llu:%llu",
	    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
	החזר 0;
}

صحيح
ssh_krl_revoke_cert_by_serial(بنية ssh_krl *krl, ثابت بنية sshkey *ca_key,
    uint64_t serial)
{
	החזר ssh_krl_revoke_cert_by_serial_range(krl, ca_key, serial, serial);
}

صحيح
ssh_krl_revoke_cert_by_serial_range(بنية ssh_krl *krl,
    ثابت بنية sshkey *ca_key, uint64_t lo, uint64_t hi)
{
	بنية revoked_certs *rc;
	صحيح r;

	אם (lo > hi || lo == 0)
		החזר SSH_ERR_INVALID_ARGUMENT;
	אם ((r = revoked_certs_for_ca_key(krl, ca_key, &rc, 1)) != 0)
		החזר r;
	החזר insert_serial_range(&rc->revoked_serials, lo, hi);
}

صحيح
ssh_krl_revoke_cert_by_key_id(بنية ssh_krl *krl, ثابت بنية sshkey *ca_key,
    ثابت حرف *key_id)
{
	بنية revoked_key_id *rki, *erki;
	بنية revoked_certs *rc;
	صحيح r;

	אם ((r = revoked_certs_for_ca_key(krl, ca_key, &rc, 1)) != 0)
		החזר r;

	KRL_DBG(("revoke %s", key_id));
	אם ((rki = calloc(1, حجم(*rki))) == عدم ||
	    (rki->key_id = strdup(key_id)) == عدم) {
		حرر(rki);
		החזר SSH_ERR_ALLOC_FAIL;
	}
	erki = RB_INSERT(revoked_key_id_tree, &rc->revoked_key_ids, rki);
	אם (erki != عدم) {
		حرر(rki->key_id);
		حرر(rki);
	}
	החזר 0;
}

/* Convert "key" to a public key blob without any certificate information */
ساكن صحيح
plain_key_blob(ثابت بنية sshkey *key, u_char **blob, size_t *blen)
{
	بنية sshkey *kcopy;
	صحيح r;

	אם ((r = sshkey_from_private(key, &kcopy)) != 0)
		החזר r;
	אם (sshkey_is_cert(kcopy)) {
		אם ((r = sshkey_drop_cert(kcopy)) != 0) {
			sshkey_free(kcopy);
			החזר r;
		}
	}
	r = sshkey_to_blob(kcopy, blob, blen);
	sshkey_free(kcopy);
	החזר r;
}

/* Revoke a key blob. Ownership of blob is transferred to the tree */
ساكن صحيح
revoke_blob(بنية revoked_blob_tree *rbt, u_char *blob, size_t len)
{
	بنية revoked_blob *rb, *erb;

	אם ((rb = calloc(1, حجم(*rb))) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	rb->blob = blob;
	rb->len = len;
	erb = RB_INSERT(revoked_blob_tree, rbt, rb);
	אם (erb != عدم) {
		حرر(rb->blob);
		حرر(rb);
	}
	החזר 0;
}

صحيح
ssh_krl_revoke_key_explicit(بنية ssh_krl *krl, ثابت بنية sshkey *key)
{
	u_char *blob;
	size_t len;
	صحيح r;

	debug3_f("revoke type %s", sshkey_type(key));
	אם ((r = plain_key_blob(key, &blob, &len)) != 0)
		החזר r;
	החזר revoke_blob(&krl->revoked_keys, blob, len);
}

ساكن صحيح
revoke_by_hash(بنية revoked_blob_tree *target, ثابت u_char *p, size_t len)
{
	u_char *blob;
	صحيح r;

	/* need to copy hash, as revoke_blob steals ownership */
	אם ((blob = malloc(len)) == عدم)
		החזר SSH_ERR_SYSTEM_ERROR;
	memcpy(blob, p, len);
	אם ((r = revoke_blob(target, blob, len)) != 0) {
		حرر(blob);
		החזר r;
	}
	החזר 0;
}

صحيح
ssh_krl_revoke_key_sha1(بنية ssh_krl *krl, ثابت u_char *p, size_t len)
{
	debug3_f("revoke by sha1");
	אם (len != 20)
		החזר SSH_ERR_INVALID_FORMAT;
	החזר revoke_by_hash(&krl->revoked_sha1s, p, len);
}

صحيح
ssh_krl_revoke_key_sha256(بنية ssh_krl *krl, ثابت u_char *p, size_t len)
{
	debug3_f("revoke by sha256");
	אם (len != 32)
		החזר SSH_ERR_INVALID_FORMAT;
	החזר revoke_by_hash(&krl->revoked_sha256s, p, len);
}

صحيح
ssh_krl_revoke_key(بنية ssh_krl *krl, ثابت بنية sshkey *key)
{
	/* XXX replace with SHA256? */
	אם (!sshkey_is_cert(key))
		החזר ssh_krl_revoke_key_explicit(krl, key);

	אם (key->cert->serial == 0) {
		החזר ssh_krl_revoke_cert_by_key_id(krl,
		    key->cert->signature_key,
		    key->cert->key_id);
	} אחרת {
		החזר ssh_krl_revoke_cert_by_serial(krl,
		    key->cert->signature_key,
		    key->cert->serial);
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
	אם (bitmap_len + cost_bitmap >= SSHBUF_MAX_BIGNUM) {
		KRL_DBG(("bitmap overfull len=%zu cost=%llu max=%u",
		    bitmap_len, (unsigned long long)cost_bitmap,
		    SSHBUF_MAX_BIGNUM));
		cost_bitmap = (uint64_t)-1;
	}

	/* Now pick the best choice */
	*force_new_section = 0;
	new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
	cost = cost_bitmap;
	אם (cost_range < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_RANGE;
		cost = cost_range;
	}
	אם (cost_list < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_LIST;
		cost = cost_list;
	}
	אם (cost_bitmap_restart < cost) {
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
	החזר new_state;
}

ساكن صحيح
put_bitmap(بنية sshbuf *buf, بنية bitmap *bitmap)
{
	size_t len;
	u_char *blob;
	صحيح r;

	len = bitmap_nbytes(bitmap);
	אם ((blob = malloc(len)) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם (bitmap_to_string(bitmap, blob, len) != 0) {
		حرر(blob);
		החזר SSH_ERR_INTERNAL_ERROR;
	}
	r = sshbuf_put_bignum2_bytes(buf, blob, len);
	حرر(blob);
	החזר r;
}

/* Generate a KRL_SECTION_CERTIFICATES KRL section */
ساكن صحيح
revoked_certs_generate(بنية revoked_certs *rc, بنية sshbuf *buf)
{
	صحيح final, force_new_sect, r = SSH_ERR_INTERNAL_ERROR;
	uint64_t i, contig, gap, last = 0, bitmap_start = 0;
	بنية revoked_serial *rs, *nrs;
	بنية revoked_key_id *rki;
	صحيح next_state, state = 0;
	size_t bitmap_len;
	بنية sshbuf *sect;
	بنية bitmap *bitmap = عدم;

	אם ((sect = sshbuf_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;

	/* Store the header: optional CA scope key, reserved */
	אם (rc->ca_key == عدم) {
		אם ((r = sshbuf_put_string(buf, عدم, 0)) != 0)
			اذهب out;
	} אחרת {
		אם ((r = sshkey_puts(rc->ca_key, buf)) != 0)
			اذهب out;
	}
	אם ((r = sshbuf_put_string(buf, عدم, 0)) != 0)
		اذهب out;

	/* Store the revoked serials.  */
	עבור (rs = RB_MIN(revoked_serial_tree, &rc->revoked_serials);
	     rs != عدم;
	     rs = RB_NEXT(revoked_serial_tree, &rc->revoked_serials, rs)) {
		KRL_DBG(("serial %llu:%llu state 0x%02x",
		    (long long unsigned)rs->lo, (long long unsigned)rs->hi,
		    state));

		/* Check contiguous length and gap to next section (if any) */
		nrs = RB_NEXT(revoked_serial_tree, &rc->revoked_serials, rs);
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
		אם (state != 0 && (force_new_sect || next_state != state ||
		    state == KRL_SECTION_CERT_SERIAL_RANGE)) {
			KRL_DBG(("finish state 0x%02x", state));
			بدل (state) {
			حالة KRL_SECTION_CERT_SERIAL_LIST:
			حالة KRL_SECTION_CERT_SERIAL_RANGE:
				اكسر;
			حالة KRL_SECTION_CERT_SERIAL_BITMAP:
				אם ((r = put_bitmap(sect, bitmap)) != 0)
					اذهب out;
				bitmap_free(bitmap);
				bitmap = عدم;
				اكسر;
			}
			אם ((r = sshbuf_put_u8(buf, state)) != 0 ||
			    (r = sshbuf_put_stringb(buf, sect)) != 0)
				اذهب out;
			sshbuf_reset(sect);
		}

		/* If we are starting a new section then prepare it now */
		אם (next_state != state || force_new_sect) {
			KRL_DBG(("start state 0x%02x",
			    next_state));
			state = next_state;
			sshbuf_reset(sect);
			بدل (state) {
			حالة KRL_SECTION_CERT_SERIAL_LIST:
			حالة KRL_SECTION_CERT_SERIAL_RANGE:
				اكسر;
			حالة KRL_SECTION_CERT_SERIAL_BITMAP:
				אם ((bitmap = bitmap_new()) == عدم) {
					r = SSH_ERR_ALLOC_FAIL;
					اذهب out;
				}
				bitmap_start = rs->lo;
				אם ((r = sshbuf_put_u64(sect,
				    bitmap_start)) != 0)
					اذهب out;
				اكسر;
			}
		}

		/* Perform section-specific processing */
		بدل (state) {
		حالة KRL_SECTION_CERT_SERIAL_LIST:
			עבור (i = 0; i < contig; i++) {
				אם ((r = sshbuf_put_u64(sect, rs->lo + i)) != 0)
					اذهب out;
			}
			اكسر;
		حالة KRL_SECTION_CERT_SERIAL_RANGE:
			אם ((r = sshbuf_put_u64(sect, rs->lo)) != 0 ||
			    (r = sshbuf_put_u64(sect, rs->hi)) != 0)
				اذهب out;
			اكسر;
		حالة KRL_SECTION_CERT_SERIAL_BITMAP:
			אם (rs->lo - bitmap_start > INT_MAX) {
				r = SSH_ERR_INVALID_FORMAT;
				error_f("insane bitmap gap");
				اذهب out;
			}
			עבור (i = 0; i < contig; i++) {
				אם (bitmap_set_bit(bitmap,
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
	אם (state != 0) {
		KRL_DBG(("serial final flush for state 0x%02x", state));
		بدل (state) {
		حالة KRL_SECTION_CERT_SERIAL_LIST:
		حالة KRL_SECTION_CERT_SERIAL_RANGE:
			اكسر;
		حالة KRL_SECTION_CERT_SERIAL_BITMAP:
			אם ((r = put_bitmap(sect, bitmap)) != 0)
				اذهب out;
			bitmap_free(bitmap);
			bitmap = عدم;
			اكسر;
		}
		אם ((r = sshbuf_put_u8(buf, state)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب out;
	}
	KRL_DBG(("serial done "));

	/* Now output a section for any revocations by key ID */
	sshbuf_reset(sect);
	RB_FOREACH(rki, revoked_key_id_tree, &rc->revoked_key_ids) {
		KRL_DBG(("key ID %s", rki->key_id));
		אם ((r = sshbuf_put_cstring(sect, rki->key_id)) != 0)
			اذهب out;
	}
	אם (sshbuf_len(sect) != 0) {
		אם ((r = sshbuf_put_u8(buf, KRL_SECTION_CERT_KEY_ID)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب out;
	}
	r = 0;
 out:
	bitmap_free(bitmap);
	sshbuf_free(sect);
	החזר r;
}

صحيح
ssh_krl_to_blob(بنية ssh_krl *krl, بنية sshbuf *buf)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	بنية revoked_certs *rc;
	بنية revoked_blob *rb;
	بنية sshbuf *sect;
	u_char *sblob = عدم;

	אם (krl->generated_date == 0)
		krl->generated_date = time(عدم);

	אם ((sect = sshbuf_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;

	/* Store the header */
	אם ((r = sshbuf_put(buf, KRL_MAGIC, حجم(KRL_MAGIC) - 1)) != 0 ||
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
		אם ((r = revoked_certs_generate(rc, sect)) != 0)
			اذهب out;
		אם ((r = sshbuf_put_u8(buf, KRL_SECTION_CERTIFICATES)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب out;
	}

	/* Finally, output sections for revocations by public key/hash */
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_tree, &krl->revoked_keys) {
		KRL_DBG(("key len %zu ", rb->len));
		אם ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			اذهب out;
	}
	אם (sshbuf_len(sect) != 0) {
		אם ((r = sshbuf_put_u8(buf, KRL_SECTION_EXPLICIT_KEY)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_tree, &krl->revoked_sha1s) {
		KRL_DBG(("hash len %zu ", rb->len));
		אם ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			اذهب out;
	}
	אם (sshbuf_len(sect) != 0) {
		אם ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA1)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_tree, &krl->revoked_sha256s) {
		KRL_DBG(("hash len %zu ", rb->len));
		אם ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			اذهب out;
	}
	אם (sshbuf_len(sect) != 0) {
		אם ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA256)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			اذهب out;
	}
	/* success */
	r = 0;
 out:
	حرر(sblob);
	sshbuf_free(sect);
	החזר r;
}

ساكن فراغ
format_timestamp(uint64_t timestamp, حرف *ts, size_t nts)
{
	time_t t;
	بنية tm *tm;

	t = timestamp;
	tm = localtime(&t);
	אם (tm == عدم)
		strlcpy(ts, "<INVALID>", nts);
	אחרת {
		*ts = '\0';
		strftime(ts, nts, "%Y%m%dT%H%M%S", tm);
	}
}

ساكن صحيح
cert_extension_subsection(بنية sshbuf *subsect, بنية ssh_krl *krl)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	بنية sshbuf *value = عدم;
	حرف *name = عدم;

	אם ((r = sshbuf_get_cstring(subsect, &name, عدم)) != 0 ||
	    (r = sshbuf_get_u8(subsect, &critical)) != 0 ||
	    (r = sshbuf_froms(subsect, &value)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid certificate extension subsection");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	אם (sshbuf_len(subsect) != 0) {
		error("KRL has invalid certificate extension subsection: "
		    "trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	debug_f("cert extension %s critical %u len %zu",
	    name, critical, sshbuf_len(value));
	/* no extensions are currently supported */
	אם (critical) {
		error("KRL contains unsupported critical certificate "
		    "subsection \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		اذهب out;
	}
	/* success */
	r = 0;
 out:
	حرر(name);
	sshbuf_free(value);
	החזר r;
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
	حرف *key_id = عدم;
	بنية sshkey *ca_key = عدم;

	אם ((subsect = sshbuf_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;

	/* Header: key, reserved */
	אם ((r = sshbuf_get_string_direct(buf, &blob, &blen)) != 0 ||
	    (r = sshbuf_skip_string(buf)) != 0)
		اذهب out;
	אם (blen != 0 && (r = sshkey_from_blob(blob, blen, &ca_key)) != 0)
		اذهب out;

	כלעוד (sshbuf_len(buf) > 0) {
		sshbuf_free(subsect);
		subsect = عدم;
		אם ((r = sshbuf_get_u8(buf, &type)) != 0 ||
		    (r = sshbuf_froms(buf, &subsect)) != 0)
			اذهب out;
		KRL_DBG(("subsection type 0x%02x", type));
		/* sshbuf_dump(subsect, stderr); */

		بدل (type) {
		حالة KRL_SECTION_CERT_SERIAL_LIST:
			כלעוד (sshbuf_len(subsect) > 0) {
				אם ((r = sshbuf_get_u64(subsect, &serial)) != 0)
					اذهب out;
				אם ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_key, serial)) != 0)
					اذهب out;
			}
			اكسر;
		حالة KRL_SECTION_CERT_SERIAL_RANGE:
			אם ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_u64(subsect, &serial_hi)) != 0)
				اذهب out;
			אם ((r = ssh_krl_revoke_cert_by_serial_range(krl,
			    ca_key, serial_lo, serial_hi)) != 0)
				اذهب out;
			اكسر;
		حالة KRL_SECTION_CERT_SERIAL_BITMAP:
			אם ((bitmap = bitmap_new()) == عدم) {
				r = SSH_ERR_ALLOC_FAIL;
				اذهب out;
			}
			אם ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_bignum2_bytes_direct(subsect,
			    &blob, &blen)) != 0)
				اذهب out;
			אם (bitmap_from_string(bitmap, blob, blen) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				اذهب out;
			}
			nbits = bitmap_nbits(bitmap);
			עבור (serial = 0; serial < (uint64_t)nbits; serial++) {
				אם (serial > 0 && serial_lo + serial == 0) {
					error_f("bitmap wraps u64");
					r = SSH_ERR_INVALID_FORMAT;
					اذهب out;
				}
				אם (!bitmap_test_bit(bitmap, serial))
					استمر;
				אם ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_key, serial_lo + serial)) != 0)
					اذهب out;
			}
			bitmap_free(bitmap);
			bitmap = عدم;
			اكسر;
		حالة KRL_SECTION_CERT_KEY_ID:
			כלעוד (sshbuf_len(subsect) > 0) {
				אם ((r = sshbuf_get_cstring(subsect,
				    &key_id, عدم)) != 0)
					اذهب out;
				אם ((r = ssh_krl_revoke_cert_by_key_id(krl,
				    ca_key, key_id)) != 0)
					اذهب out;
				حرر(key_id);
				key_id = عدم;
			}
			اكسر;
		حالة KRL_SECTION_CERT_EXTENSION:
			אם ((r = cert_extension_subsection(subsect, krl)) != 0)
				اذهب out;
			اكسر;
		افتراضي:
			error("Unsupported KRL certificate section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		אם (sshbuf_len(subsect) > 0) {
			error("KRL certificate section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
	}

	r = 0;
 out:
	אם (bitmap != عدم)
		bitmap_free(bitmap);
	حرر(key_id);
	sshkey_free(ca_key);
	sshbuf_free(subsect);
	החזר r;
}

ساكن صحيح
blob_section(بنية sshbuf *sect, بنية revoked_blob_tree *target_tree,
    size_t expected_len)
{
	u_char *rdata = عدم;
	size_t rlen = 0;
	صحيح r;

	כלעוד (sshbuf_len(sect) > 0) {
		אם ((r = sshbuf_get_string(sect, &rdata, &rlen)) != 0)
			החזר r;
		אם (expected_len != 0 && rlen != expected_len) {
			error_f("bad length");
			حرر(rdata);
			החזר SSH_ERR_INVALID_FORMAT;
		}
		אם ((r = revoke_blob(target_tree, rdata, rlen)) != 0) {
			حرر(rdata);
			החזר r;
		}
	}
	החזר 0;
}

ساكن صحيح
extension_section(بنية sshbuf *sect, بنية ssh_krl *krl)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	بنية sshbuf *value = عدم;
	حرف *name = عدم;

	אם ((r = sshbuf_get_cstring(sect, &name, عدم)) != 0 ||
	    (r = sshbuf_get_u8(sect, &critical)) != 0 ||
	    (r = sshbuf_froms(sect, &value)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid extension section");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	אם (sshbuf_len(sect) != 0) {
		error("KRL has invalid extension section: trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	debug_f("extension %s critical %u len %zu",
	    name, critical, sshbuf_len(value));
	/* no extensions are currently supported */
	אם (critical) {
		error("KRL contains unsupported critical section \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		اذهب out;
	}
	/* success */
	r = 0;
 out:
	حرر(name);
	sshbuf_free(value);
	החזר r;
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
	אם ((r = sshbuf_cmp(buf, 0, KRL_MAGIC, حجم(KRL_MAGIC) - 1)) != 0) {
		debug2_f("bad KRL magic header");
		החזר SSH_ERR_KRL_BAD_MAGIC;
	}

	אם ((krl = ssh_krl_init()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		error_f("alloc failed");
		اذهب out;
	}
	/* Don't modify buffer */
	אם ((copy = sshbuf_fromb(buf)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם ((r = sshbuf_consume(copy, حجم(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_get_u32(copy, &format_version)) != 0)
		اذهب out;
	אם (format_version != KRL_FORMAT_VERSION) {
		error_f("unsupported KRL format version %u", format_version);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	אם ((r = sshbuf_get_u64(copy, &krl->krl_version)) != 0 ||
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
	כלעוד (sshbuf_len(copy) > 0) {
		sshbuf_free(sect);
		sect = عدم;
		אם ((r = sshbuf_get_u8(copy, &type)) != 0 ||
		    (r = sshbuf_froms(copy, &sect)) != 0)
			اذهب out;
		KRL_DBG(("section 0x%02x", type));

		بدل (type) {
		حالة KRL_SECTION_CERTIFICATES:
			אם ((r = parse_revoked_certs(sect, krl)) != 0)
				اذهب out;
			اكسر;
		حالة KRL_SECTION_EXPLICIT_KEY:
			אם ((r = blob_section(sect,
			    &krl->revoked_keys, 0)) != 0)
				اذهب out;
			اكسر;
		حالة KRL_SECTION_FINGERPRINT_SHA1:
			אם ((r = blob_section(sect,
			    &krl->revoked_sha1s, 20)) != 0)
				اذهب out;
			اكسر;
		حالة KRL_SECTION_FINGERPRINT_SHA256:
			אם ((r = blob_section(sect,
			    &krl->revoked_sha256s, 32)) != 0)
				اذهب out;
			اكسر;
		حالة KRL_SECTION_EXTENSION:
			אם ((r = extension_section(sect, krl)) != 0)
				اذهب out;
			اكسر;
		حالة KRL_SECTION_SIGNATURE:
			/* Handled above, but still need to stay in synch */
			sshbuf_free(sect);
			sect = عدم;
			אם ((r = sshbuf_skip_string(copy)) != 0)
				اذهب out;
			اكسر;
		افتراضي:
			error("Unsupported KRL section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		אם (sect != عدم && sshbuf_len(sect) > 0) {
			error("KRL section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
	}

	/* Success */
	*krlp = krl;
	r = 0;
 out:
	אם (r != 0)
		ssh_krl_free(krl);
	sshbuf_free(copy);
	sshbuf_free(sect);
	החזר r;
}

/* Checks certificate serial number and key ID revocation */
ساكن صحيح
is_cert_revoked(ثابت بنية sshkey *key, بنية revoked_certs *rc)
{
	بنية revoked_serial rs, *ers;
	بنية revoked_key_id rki, *erki;

	/* Check revocation by cert key ID */
	memset(&rki, 0, حجم(rki));
	rki.key_id = key->cert->key_id;
	erki = RB_FIND(revoked_key_id_tree, &rc->revoked_key_ids, &rki);
	אם (erki != عدم) {
		KRL_DBG(("revoked by key ID"));
		החזר SSH_ERR_KEY_REVOKED;
	}

	/*
	 * Zero serials numbers are ignored (it's the default when the
	 * CA doesn't specify one).
	 */
	אם (key->cert->serial == 0)
		החזר 0;

	memset(&rs, 0, حجم(rs));
	rs.lo = rs.hi = key->cert->serial;
	ers = RB_FIND(revoked_serial_tree, &rc->revoked_serials, &rs);
	אם (ers != عدم) {
		KRL_DBG(("revoked serial %llu matched %llu:%llu",
		    (unsigned long long)key->cert->serial,
		    (unsigned long long)ers->lo,
		    (unsigned long long)ers->hi));
		החזר SSH_ERR_KEY_REVOKED;
	}
	החזר 0;
}

/* Checks whether a given key/cert is revoked. Does not check its CA */
ساكن صحيح
is_key_revoked(بنية ssh_krl *krl, ثابت بنية sshkey *key)
{
	بنية revoked_blob rb, *erb;
	بنية revoked_certs *rc;
	صحيح r;

	/* Check explicitly revoked hashes first */
	memset(&rb, 0, حجم(rb));
	אם ((r = sshkey_fingerprint_raw(key, SSH_DIGEST_SHA1,
	    &rb.blob, &rb.len)) != 0)
		החזר r;
	erb = RB_FIND(revoked_blob_tree, &krl->revoked_sha1s, &rb);
	حرر(rb.blob);
	אם (erb != عدم) {
		KRL_DBG(("revoked by key SHA1"));
		החזר SSH_ERR_KEY_REVOKED;
	}
	memset(&rb, 0, حجم(rb));
	אם ((r = sshkey_fingerprint_raw(key, SSH_DIGEST_SHA256,
	    &rb.blob, &rb.len)) != 0)
		החזר r;
	erb = RB_FIND(revoked_blob_tree, &krl->revoked_sha256s, &rb);
	حرر(rb.blob);
	אם (erb != عدم) {
		KRL_DBG(("revoked by key SHA256"));
		החזר SSH_ERR_KEY_REVOKED;
	}

	/* Next, explicit keys */
	memset(&rb, 0, حجم(rb));
	אם ((r = plain_key_blob(key, &rb.blob, &rb.len)) != 0)
		החזר r;
	erb = RB_FIND(revoked_blob_tree, &krl->revoked_keys, &rb);
	حرر(rb.blob);
	אם (erb != عدم) {
		KRL_DBG(("revoked by explicit key"));
		החזר SSH_ERR_KEY_REVOKED;
	}

	אם (!sshkey_is_cert(key))
		החזר 0;

	/* Check cert revocation for the specified CA */
	אם ((r = revoked_certs_for_ca_key(krl, key->cert->signature_key,
	    &rc, 0)) != 0)
		החזר r;
	אם (rc != عدم) {
		אם ((r = is_cert_revoked(key, rc)) != 0)
			החזר r;
	}
	/* Check cert revocation for the wildcard CA */
	אם ((r = revoked_certs_for_ca_key(krl, عدم, &rc, 0)) != 0)
		החזר r;
	אם (rc != عدم) {
		אם ((r = is_cert_revoked(key, rc)) != 0)
			החזר r;
	}

	KRL_DBG(("%llu no match", (unsigned long long)key->cert->serial));
	החזר 0;
}

صحيح
ssh_krl_check_key(بنية ssh_krl *krl, ثابت بنية sshkey *key)
{
	صحيح r;

	KRL_DBG(("checking key"));
	אם ((r = is_key_revoked(krl, key)) != 0)
		החזר r;
	אם (sshkey_is_cert(key)) {
		debug2_f("checking CA key");
		אם ((r = is_key_revoked(krl, key->cert->signature_key)) != 0)
			החזר r;
	}
	KRL_DBG(("key okay"));
	החזר 0;
}

صحيح
ssh_krl_file_contains_key(ثابت حرف *path, ثابت بنية sshkey *key)
{
	بنية sshbuf *krlbuf = عدم;
	بنية ssh_krl *krl = عدم;
	صحيح oerrno = 0, r;

	אם (path == عدم)
		החזר 0;
	אם ((r = sshbuf_load_file(path, &krlbuf)) != 0) {
		oerrno = errno;
		اذهب out;
	}
	אם ((r = ssh_krl_from_blob(krlbuf, &krl)) != 0)
		اذهب out;
	debug2_f("checking KRL %s", path);
	r = ssh_krl_check_key(krl, key);
 out:
	sshbuf_free(krlbuf);
	ssh_krl_free(krl);
	אם (r != 0)
		errno = oerrno;
	החזר r;
}

صحيح
krl_dump(بنية ssh_krl *krl, FILE *f)
{
	بنية sshkey *key = عدم;
	بنية revoked_blob *rb;
	بنية revoked_certs *rc;
	بنية revoked_serial *rs;
	بنية revoked_key_id *rki;
	صحيح r, ret = 0;
	حرف *fp, timestamp[64];

	/* Try to print in a KRL spec-compatible format */
	format_timestamp(krl->generated_date, timestamp, حجم(timestamp));
	fprintf(f, "# KRL version %llu\n", (unsigned long long)krl->krl_version);
	fprintf(f, "# Generated at %s\n", timestamp);
	אם (krl->comment != عدم && *krl->comment != '\0') {
		r = INT_MAX;
		asmprintf(&fp, INT_MAX, &r, "%s", krl->comment);
		fprintf(f, "# Comment: %s\n", fp);
		حرر(fp);
	}
	fputc('\n', f);

	RB_FOREACH(rb, revoked_blob_tree, &krl->revoked_keys) {
		אם ((r = sshkey_from_blob(rb->blob, rb->len, &key)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			error_r(r, "parse KRL key");
			استمر;
		}
		אם ((fp = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == عدم) {
			ret = SSH_ERR_INVALID_FORMAT;
			error("sshkey_fingerprint failed");
			استمر;
		}
		fprintf(f, "hash: %s # %s\n", fp, sshkey_ssh_name(key));
		حرر(fp);
		حرر(key);
	}
	RB_FOREACH(rb, revoked_blob_tree, &krl->revoked_sha256s) {
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "hash: SHA256:%s\n", fp);
		حرر(fp);
	}
	RB_FOREACH(rb, revoked_blob_tree, &krl->revoked_sha1s) {
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
		אם (rc->ca_key == عدم)
			fprintf(f, "# Wildcard CA\n");
		אחרת {
			אם ((fp = sshkey_fingerprint(rc->ca_key,
			    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == عدم) {
				ret = SSH_ERR_INVALID_FORMAT;
				error("sshkey_fingerprint failed");
				استمر;
			}
			fprintf(f, "# CA key %s %s\n",
			    sshkey_ssh_name(rc->ca_key), fp);
			حرر(fp);
		}
		RB_FOREACH(rs, revoked_serial_tree, &rc->revoked_serials) {
			אם (rs->lo == rs->hi) {
				fprintf(f, "serial: %llu\n",
				    (unsigned long long)rs->lo);
			} אחרת {
				fprintf(f, "serial: %llu-%llu\n",
				    (unsigned long long)rs->lo,
				    (unsigned long long)rs->hi);
			}
		}
		RB_FOREACH(rki, revoked_key_id_tree, &rc->revoked_key_ids) {
			/*
			 * We don't want key IDs with embedded newlines to
			 * mess up the display.
			 */
			r = INT_MAX;
			asmprintf(&fp, INT_MAX, &r, "%s", rki->key_id);
			fprintf(f, "id: %s\n", fp);
			حرر(fp);
		}
	}
	החזר ret;
}
