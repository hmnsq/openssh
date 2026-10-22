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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/tree.h>
#அந்தர்பாவ <sys/queue.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <time.h>

#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "bitmap.h"
#அந்தர்பாவ "utf8.h"

#அந்தர்பாவ "krl.h"

/* #define DEBUG_KRL */
#ifdef DEBUG_KRL
# define KRL_DBG(x) debug3_f x
#இல்லையெனில்
# define KRL_DBG(x)
#endif

/*
 * Trees of revoked serial numbers, key IDs and keys. This allows
 * quick searching, querying and producing lists in canonical order.
 */

/* Tree of serial numbers. XXX make smarter: really need a real sparse bitmap */
கட்டமைப்பு revoked_serial {
	uint64_t lo, hi;
	RB_ENTRY(revoked_serial) மரம்_entry;
};
நிலையான முழு serial_cmp(கட்டமைப்பு revoked_serial *a, கட்டமைப்பு revoked_serial *b);
RB_HEAD(revoked_serial_மரம், revoked_serial);
RB_GENERATE_STATIC(revoked_serial_மரம், revoked_serial, மரம்_entry, serial_cmp)

/* Tree of key IDs */
கட்டமைப்பு revoked_சாவி_id {
	எழுத்து *சாவி_id;
	RB_ENTRY(revoked_சாவி_id) மரம்_entry;
};
நிலையான முழு சாவி_id_cmp(கட்டமைப்பு revoked_சாவி_id *a, கட்டமைப்பு revoked_சாவி_id *b);
RB_HEAD(revoked_சாவி_id_மரம், revoked_சாவி_id);
RB_GENERATE_STATIC(revoked_சாவி_id_மரம், revoked_சாவி_id, மரம்_entry, சாவி_id_cmp)

/* Tree of blobs (used for keys and fingerprints) */
கட்டமைப்பு revoked_blob {
	u_char *blob;
	size_t len;
	RB_ENTRY(revoked_blob) மரம்_entry;
};
நிலையான முழு blob_cmp(கட்டமைப்பு revoked_blob *a, கட்டமைப்பு revoked_blob *b);
RB_HEAD(revoked_blob_மரம், revoked_blob);
RB_GENERATE_STATIC(revoked_blob_மரம், revoked_blob, மரம்_entry, blob_cmp)

/* Tracks revoked certs for a single CA */
கட்டமைப்பு revoked_certs {
	கட்டமைப்பு sshkey *ca_சாவி;
	கட்டமைப்பு revoked_serial_மரம் revoked_serials;
	கட்டமைப்பு revoked_சாவி_id_மரம் revoked_சாவி_ids;
	TAILQ_ENTRY(revoked_certs) entry;
};
TAILQ_HEAD(revoked_certs_list, revoked_certs);

கட்டமைப்பு ssh_krl {
	uint64_t krl_version;
	uint64_t generated_date;
	uint64_t flags;
	எழுத்து *comment;
	கட்டமைப்பு revoked_blob_மரம் revoked_சாவிகள்;
	கட்டமைப்பு revoked_blob_மரம் revoked_sha1s;
	கட்டமைப்பு revoked_blob_மரம் revoked_sha256s;
	கட்டமைப்பு revoked_certs_list revoked_certs;
};

/* Return equal if a and b overlap */
நிலையான முழு
serial_cmp(கட்டமைப்பு revoked_serial *a, கட்டமைப்பு revoked_serial *b)
{
	எனில் (a->hi >= b->lo && a->lo <= b->hi)
		திரும்பு 0;
	திரும்பு a->lo < b->lo ? -1 : 1;
}

நிலையான முழு
சாவி_id_cmp(கட்டமைப்பு revoked_சாவி_id *a, கட்டமைப்பு revoked_சாவி_id *b)
{
	திரும்பு strcmp(a->சாவி_id, b->சாவி_id);
}

நிலையான முழு
blob_cmp(கட்டமைப்பு revoked_blob *a, கட்டமைப்பு revoked_blob *b)
{
	முழு r;

	எனில் (a->len != b->len) {
		எனில் ((r = memcmp(a->blob, b->blob, MINIMUM(a->len, b->len))) != 0)
			திரும்பு r;
		திரும்பு a->len > b->len ? 1 : -1;
	} இல்லையெனில்
		திரும்பு memcmp(a->blob, b->blob, a->len);
}

கட்டமைப்பு ssh_krl *
ssh_krl_init(வெறுமை)
{
	கட்டமைப்பு ssh_krl *krl;

	எனில் ((krl = calloc(1, அளவு(*krl))) == வெற்று)
		திரும்பு வெற்று;
	RB_INIT(&krl->revoked_சாவிகள்);
	RB_INIT(&krl->revoked_sha1s);
	RB_INIT(&krl->revoked_sha256s);
	TAILQ_INIT(&krl->revoked_certs);
	திரும்பு krl;
}

நிலையான வெறுமை
revoked_certs_free(கட்டமைப்பு revoked_certs *rc)
{
	கட்டமைப்பு revoked_serial *rs, *trs;
	கட்டமைப்பு revoked_சாவி_id *rki, *trki;

	எனில் (rc == வெற்று)
		திரும்பு;
	RB_FOREACH_SAFE(rs, revoked_serial_மரம், &rc->revoked_serials, trs) {
		RB_REMOVE(revoked_serial_மரம், &rc->revoked_serials, rs);
		விடுவி(rs);
	}
	RB_FOREACH_SAFE(rki, revoked_சாவி_id_மரம், &rc->revoked_சாவி_ids, trki) {
		RB_REMOVE(revoked_சாவி_id_மரம், &rc->revoked_சாவி_ids, rki);
		விடுவி(rki->சாவி_id);
		விடுவி(rki);
	}
	sshkey_free(rc->ca_சாவி);
	freezero(rc, அளவு(*rc));
}

வெறுமை
ssh_krl_free(கட்டமைப்பு ssh_krl *krl)
{
	கட்டமைப்பு revoked_blob *rb, *trb;
	கட்டமைப்பு revoked_certs *rc, *trc;

	எனில் (krl == வெற்று)
		திரும்பு;

	விடுவி(krl->comment);
	RB_FOREACH_SAFE(rb, revoked_blob_மரம், &krl->revoked_சாவிகள், trb) {
		RB_REMOVE(revoked_blob_மரம், &krl->revoked_சாவிகள், rb);
		விடுவி(rb->blob);
		விடுவி(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_மரம், &krl->revoked_sha1s, trb) {
		RB_REMOVE(revoked_blob_மரம், &krl->revoked_sha1s, rb);
		விடுவி(rb->blob);
		விடுவி(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_மரம், &krl->revoked_sha256s, trb) {
		RB_REMOVE(revoked_blob_மரம், &krl->revoked_sha256s, rb);
		விடுவி(rb->blob);
		விடுவி(rb);
	}
	TAILQ_FOREACH_SAFE(rc, &krl->revoked_certs, entry, trc) {
		TAILQ_REMOVE(&krl->revoked_certs, rc, entry);
		revoked_certs_free(rc);
	}
	விடுவி(krl);
}

வெறுமை
ssh_krl_set_version(கட்டமைப்பு ssh_krl *krl, uint64_t version)
{
	krl->krl_version = version;
}

முழு
ssh_krl_set_comment(கட்டமைப்பு ssh_krl *krl, மாறிலி எழுத்து *comment)
{
	விடுவி(krl->comment);
	எனில் ((krl->comment = strdup(comment)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	திரும்பு 0;
}

/*
 * Find the revoked_certs struct for a CA key. If allow_create is set then
 * create a new one in the tree if one did not exist already.
 */
நிலையான முழு
revoked_certs_for_ca_சாவி(கட்டமைப்பு ssh_krl *krl, மாறிலி கட்டமைப்பு sshkey *ca_சாவி,
    கட்டமைப்பு revoked_certs **rcp, முழு allow_create)
{
	கட்டமைப்பு revoked_certs *rc;
	முழு r;

	*rcp = வெற்று;
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		எனில் ((ca_சாவி == வெற்று && rc->ca_சாவி == வெற்று) ||
		    sshkey_equal(rc->ca_சாவி, ca_சாவி)) {
			*rcp = rc;
			திரும்பு 0;
		}
	}
	எனில் (!allow_create)
		திரும்பு 0;
	/* If this CA doesn't exist in the list then add it now */
	எனில் ((rc = calloc(1, அளவு(*rc))) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் (ca_சாவி == வெற்று)
		rc->ca_சாவி = வெற்று;
	இல்லையெனில் எனில் ((r = sshkey_from_private(ca_சாவி, &rc->ca_சாவி)) != 0) {
		விடுவி(rc);
		திரும்பு r;
	}
	RB_INIT(&rc->revoked_serials);
	RB_INIT(&rc->revoked_சாவி_ids);
	TAILQ_INSERT_TAIL(&krl->revoked_certs, rc, entry);
	KRL_DBG(("new CA %s", ca_சாவி == வெற்று ? "*" : sshkey_type(ca_சாவி)));
	*rcp = rc;
	திரும்பு 0;
}

நிலையான முழு
செருகு_serial_range(கட்டமைப்பு revoked_serial_மரம் *rt, uint64_t lo, uint64_t hi)
{
	கட்டமைப்பு revoked_serial rs, *ers, *crs, *irs;

	KRL_DBG(("insert %llu:%llu",
	    (unsigned long long)lo, (unsigned long long)hi));
	memset(&rs, 0, அளவு(rs));
	rs.lo = lo;
	rs.hi = hi;
	ers = RB_NFIND(revoked_serial_மரம், rt, &rs);
	எனில் (ers == வெற்று || serial_cmp(ers, &rs) != 0) {
		/* No entry matches. Just insert */
		எனில் ((irs = malloc(அளவு(rs))) == வெற்று)
			திரும்பு SSH_ERR_ALLOC_FAIL;
		memcpy(irs, &rs, அளவு(*irs));
		ers = RB_செருகு(revoked_serial_மரம், rt, irs);
		எனில் (ers != வெற்று) {
			KRL_DBG(("bad: ers != NULL"));
			/* Shouldn't happen */
			விடுவி(irs);
			திரும்பு SSH_ERR_INTERNAL_ERROR;
		}
		ers = irs;
	} இல்லையெனில் {
		KRL_DBG(("overlap found %llu:%llu",
		    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
		/*
		 * The inserted entry overlaps an existing one. Grow the
		 * existing entry.
		 */
		எனில் (ers->lo > lo)
			ers->lo = lo;
		எனில் (ers->hi < hi)
			ers->hi = hi;
	}

	/*
	 * The inserted or revised range might overlap or abut adjacent ones;
	 * coalesce as necessary.
	 */

	/* Check predecessors */
	போது ((crs = RB_PREV(revoked_serial_மரம், rt, ers)) != வெற்று) {
		KRL_DBG(("pred %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		எனில் (ers->lo != 0 && crs->hi < ers->lo - 1)
			நிறுத்து;
		/* This entry overlaps. */
		எனில் (crs->lo < ers->lo) {
			ers->lo = crs->lo;
			KRL_DBG(("pred extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_மரம், rt, crs);
		விடுவி(crs);
	}
	/* Check successors */
	போது ((crs = RB_NEXT(revoked_serial_மரம், rt, ers)) != வெற்று) {
		KRL_DBG(("succ %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		எனில் (ers->hi != (uint64_t)-1 && crs->lo > ers->hi + 1)
			நிறுத்து;
		/* This entry overlaps. */
		எனில் (crs->hi > ers->hi) {
			ers->hi = crs->hi;
			KRL_DBG(("succ extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_மரம், rt, crs);
		விடுவி(crs);
	}
	KRL_DBG(("done, final %llu:%llu",
	    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
	திரும்பு 0;
}

முழு
ssh_krl_revoke_cert_by_serial(கட்டமைப்பு ssh_krl *krl, மாறிலி கட்டமைப்பு sshkey *ca_சாவி,
    uint64_t serial)
{
	திரும்பு ssh_krl_revoke_cert_by_serial_range(krl, ca_சாவி, serial, serial);
}

முழு
ssh_krl_revoke_cert_by_serial_range(கட்டமைப்பு ssh_krl *krl,
    மாறிலி கட்டமைப்பு sshkey *ca_சாவி, uint64_t lo, uint64_t hi)
{
	கட்டமைப்பு revoked_certs *rc;
	முழு r;

	எனில் (lo > hi || lo == 0)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் ((r = revoked_certs_for_ca_சாவி(krl, ca_சாவி, &rc, 1)) != 0)
		திரும்பு r;
	திரும்பு செருகு_serial_range(&rc->revoked_serials, lo, hi);
}

முழு
ssh_krl_revoke_cert_by_சாவி_id(கட்டமைப்பு ssh_krl *krl, மாறிலி கட்டமைப்பு sshkey *ca_சாவி,
    மாறிலி எழுத்து *சாவி_id)
{
	கட்டமைப்பு revoked_சாவி_id *rki, *erki;
	கட்டமைப்பு revoked_certs *rc;
	முழு r;

	எனில் ((r = revoked_certs_for_ca_சாவி(krl, ca_சாவி, &rc, 1)) != 0)
		திரும்பு r;

	KRL_DBG(("revoke %s", சாவி_id));
	எனில் ((rki = calloc(1, அளவு(*rki))) == வெற்று ||
	    (rki->சாவி_id = strdup(சாவி_id)) == வெற்று) {
		விடுவி(rki);
		திரும்பு SSH_ERR_ALLOC_FAIL;
	}
	erki = RB_செருகு(revoked_சாவி_id_மரம், &rc->revoked_சாவி_ids, rki);
	எனில் (erki != வெற்று) {
		விடுவி(rki->சாவி_id);
		விடுவி(rki);
	}
	திரும்பு 0;
}

/* Convert "key" to a public key blob without any certificate information */
நிலையான முழு
plain_சாவி_blob(மாறிலி கட்டமைப்பு sshkey *சாவி, u_char **blob, size_t *blen)
{
	கட்டமைப்பு sshkey *kcopy;
	முழு r;

	எனில் ((r = sshkey_from_private(சாவி, &kcopy)) != 0)
		திரும்பு r;
	எனில் (sshkey_is_cert(kcopy)) {
		எனில் ((r = sshkey_drop_cert(kcopy)) != 0) {
			sshkey_free(kcopy);
			திரும்பு r;
		}
	}
	r = sshkey_to_blob(kcopy, blob, blen);
	sshkey_free(kcopy);
	திரும்பு r;
}

/* Revoke a key blob. Ownership of blob is transferred to the tree */
நிலையான முழு
revoke_blob(கட்டமைப்பு revoked_blob_மரம் *rbt, u_char *blob, size_t len)
{
	கட்டமைப்பு revoked_blob *rb, *erb;

	எனில் ((rb = calloc(1, அளவு(*rb))) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	rb->blob = blob;
	rb->len = len;
	erb = RB_செருகு(revoked_blob_மரம், rbt, rb);
	எனில் (erb != வெற்று) {
		விடுவி(rb->blob);
		விடுவி(rb);
	}
	திரும்பு 0;
}

முழு
ssh_krl_revoke_சாவி_explicit(கட்டமைப்பு ssh_krl *krl, மாறிலி கட்டமைப்பு sshkey *சாவி)
{
	u_char *blob;
	size_t len;
	முழு r;

	debug3_f("revoke type %s", sshkey_type(சாவி));
	எனில் ((r = plain_சாவி_blob(சாவி, &blob, &len)) != 0)
		திரும்பு r;
	திரும்பு revoke_blob(&krl->revoked_சாவிகள், blob, len);
}

நிலையான முழு
revoke_by_hash(கட்டமைப்பு revoked_blob_மரம் *target, மாறிலி u_char *p, size_t len)
{
	u_char *blob;
	முழு r;

	/* need to copy hash, as revoke_blob steals ownership */
	எனில் ((blob = malloc(len)) == வெற்று)
		திரும்பு SSH_ERR_SYSTEM_ERROR;
	memcpy(blob, p, len);
	எனில் ((r = revoke_blob(target, blob, len)) != 0) {
		விடுவி(blob);
		திரும்பு r;
	}
	திரும்பு 0;
}

முழு
ssh_krl_revoke_சாவி_sha1(கட்டமைப்பு ssh_krl *krl, மாறிலி u_char *p, size_t len)
{
	debug3_f("revoke by sha1");
	எனில் (len != 20)
		திரும்பு SSH_ERR_INVALID_FORMAT;
	திரும்பு revoke_by_hash(&krl->revoked_sha1s, p, len);
}

முழு
ssh_krl_revoke_சாவி_sha256(கட்டமைப்பு ssh_krl *krl, மாறிலி u_char *p, size_t len)
{
	debug3_f("revoke by sha256");
	எனில் (len != 32)
		திரும்பு SSH_ERR_INVALID_FORMAT;
	திரும்பு revoke_by_hash(&krl->revoked_sha256s, p, len);
}

முழு
ssh_krl_revoke_சாவி(கட்டமைப்பு ssh_krl *krl, மாறிலி கட்டமைப்பு sshkey *சாவி)
{
	/* XXX replace with SHA256? */
	எனில் (!sshkey_is_cert(சாவி))
		திரும்பு ssh_krl_revoke_சாவி_explicit(krl, சாவி);

	எனில் (சாவி->cert->serial == 0) {
		திரும்பு ssh_krl_revoke_cert_by_சாவி_id(krl,
		    சாவி->cert->signature_சாவி,
		    சாவி->cert->சாவி_id);
	} இல்லையெனில் {
		திரும்பு ssh_krl_revoke_cert_by_serial(krl,
		    சாவி->cert->signature_சாவி,
		    சாவி->cert->serial);
	}
}

/*
 * Select the most compact section type to emit next in a KRL based on
 * the current section type, the run length of contiguous revoked serial
 * numbers and the gaps from the last and to the next revoked serial.
 * Applies a mostly-accurate bit cost model to select the section type
 * that will minimise the size of the resultant KRL.
 */
நிலையான முழு
choose_next_state(முழு current_state, uint64_t contig, முழு final,
    uint64_t last_gap, uint64_t next_gap, size_t bitmap_len,
    முழு *force_new_section)
{
	முழு new_state;
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
	தேர்வு (current_state) {
	நிலை KRL_SECTION_CERT_SERIAL_LIST:
		cost_bitmap_restart = cost_bitmap = 8 + 64;
		நிறுத்து;
	நிலை KRL_SECTION_CERT_SERIAL_BITMAP:
		cost_list = 8;
		cost_bitmap_restart = 8 + 64;
		நிறுத்து;
	நிலை KRL_SECTION_CERT_SERIAL_RANGE:
	நிலை 0:
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
	எனில் (bitmap_len + cost_bitmap >= SSHBUF_MAX_BIGNUM) {
		KRL_DBG(("bitmap overfull len=%zu cost=%llu max=%u",
		    bitmap_len, (unsigned long long)cost_bitmap,
		    SSHBUF_MAX_BIGNUM));
		cost_bitmap = (uint64_t)-1;
	}

	/* Now pick the best choice */
	*force_new_section = 0;
	new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
	cost = cost_bitmap;
	எனில் (cost_range < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_RANGE;
		cost = cost_range;
	}
	எனில் (cost_list < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_LIST;
		cost = cost_list;
	}
	எனில் (cost_bitmap_restart < cost) {
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
	திரும்பு new_state;
}

நிலையான முழு
put_bitmap(கட்டமைப்பு sshbuf *buf, கட்டமைப்பு bitmap *bitmap)
{
	size_t len;
	u_char *blob;
	முழு r;

	len = bitmap_nbytes(bitmap);
	எனில் ((blob = malloc(len)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் (bitmap_to_string(bitmap, blob, len) != 0) {
		விடுவி(blob);
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	}
	r = sshbuf_put_bignum2_bytes(buf, blob, len);
	விடுவி(blob);
	திரும்பு r;
}

/* Generate a KRL_SECTION_CERTIFICATES KRL section */
நிலையான முழு
revoked_certs_generate(கட்டமைப்பு revoked_certs *rc, கட்டமைப்பு sshbuf *buf)
{
	முழு final, force_new_sect, r = SSH_ERR_INTERNAL_ERROR;
	uint64_t i, contig, gap, last = 0, bitmap_start = 0;
	கட்டமைப்பு revoked_serial *rs, *nrs;
	கட்டமைப்பு revoked_சாவி_id *rki;
	முழு next_state, state = 0;
	size_t bitmap_len;
	கட்டமைப்பு sshbuf *sect;
	கட்டமைப்பு bitmap *bitmap = வெற்று;

	எனில் ((sect = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;

	/* Store the header: optional CA scope key, reserved */
	எனில் (rc->ca_சாவி == வெற்று) {
		எனில் ((r = sshbuf_put_string(buf, வெற்று, 0)) != 0)
			செல் out;
	} இல்லையெனில் {
		எனில் ((r = sshkey_puts(rc->ca_சாவி, buf)) != 0)
			செல் out;
	}
	எனில் ((r = sshbuf_put_string(buf, வெற்று, 0)) != 0)
		செல் out;

	/* Store the revoked serials.  */
	க்கு (rs = RB_MIN(revoked_serial_மரம், &rc->revoked_serials);
	     rs != வெற்று;
	     rs = RB_NEXT(revoked_serial_மரம், &rc->revoked_serials, rs)) {
		KRL_DBG(("serial %llu:%llu state 0x%02x",
		    (long long unsigned)rs->lo, (long long unsigned)rs->hi,
		    state));

		/* Check contiguous length and gap to next section (if any) */
		nrs = RB_NEXT(revoked_serial_மரம், &rc->revoked_serials, rs);
		final = nrs == வெற்று;
		gap = nrs == வெற்று ? 0 : nrs->lo - rs->hi;
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
		எனில் (state != 0 && (force_new_sect || next_state != state ||
		    state == KRL_SECTION_CERT_SERIAL_RANGE)) {
			KRL_DBG(("finish state 0x%02x", state));
			தேர்வு (state) {
			நிலை KRL_SECTION_CERT_SERIAL_LIST:
			நிலை KRL_SECTION_CERT_SERIAL_RANGE:
				நிறுத்து;
			நிலை KRL_SECTION_CERT_SERIAL_BITMAP:
				எனில் ((r = put_bitmap(sect, bitmap)) != 0)
					செல் out;
				bitmap_free(bitmap);
				bitmap = வெற்று;
				நிறுத்து;
			}
			எனில் ((r = sshbuf_put_u8(buf, state)) != 0 ||
			    (r = sshbuf_put_stringb(buf, sect)) != 0)
				செல் out;
			sshbuf_reset(sect);
		}

		/* If we are starting a new section then prepare it now */
		எனில் (next_state != state || force_new_sect) {
			KRL_DBG(("start state 0x%02x",
			    next_state));
			state = next_state;
			sshbuf_reset(sect);
			தேர்வு (state) {
			நிலை KRL_SECTION_CERT_SERIAL_LIST:
			நிலை KRL_SECTION_CERT_SERIAL_RANGE:
				நிறுத்து;
			நிலை KRL_SECTION_CERT_SERIAL_BITMAP:
				எனில் ((bitmap = bitmap_new()) == வெற்று) {
					r = SSH_ERR_ALLOC_FAIL;
					செல் out;
				}
				bitmap_start = rs->lo;
				எனில் ((r = sshbuf_put_u64(sect,
				    bitmap_start)) != 0)
					செல் out;
				நிறுத்து;
			}
		}

		/* Perform section-specific processing */
		தேர்வு (state) {
		நிலை KRL_SECTION_CERT_SERIAL_LIST:
			க்கு (i = 0; i < contig; i++) {
				எனில் ((r = sshbuf_put_u64(sect, rs->lo + i)) != 0)
					செல் out;
			}
			நிறுத்து;
		நிலை KRL_SECTION_CERT_SERIAL_RANGE:
			எனில் ((r = sshbuf_put_u64(sect, rs->lo)) != 0 ||
			    (r = sshbuf_put_u64(sect, rs->hi)) != 0)
				செல் out;
			நிறுத்து;
		நிலை KRL_SECTION_CERT_SERIAL_BITMAP:
			எனில் (rs->lo - bitmap_start > INT_MAX) {
				r = SSH_ERR_INVALID_FORMAT;
				error_f("insane bitmap gap");
				செல் out;
			}
			க்கு (i = 0; i < contig; i++) {
				எனில் (bitmap_set_bit(bitmap,
				    rs->lo + i - bitmap_start) != 0) {
					r = SSH_ERR_ALLOC_FAIL;
					செல் out;
				}
			}
			நிறுத்து;
		}
		last = rs->hi;
	}
	/* Flush the remaining section, if any */
	எனில் (state != 0) {
		KRL_DBG(("serial final flush for state 0x%02x", state));
		தேர்வு (state) {
		நிலை KRL_SECTION_CERT_SERIAL_LIST:
		நிலை KRL_SECTION_CERT_SERIAL_RANGE:
			நிறுத்து;
		நிலை KRL_SECTION_CERT_SERIAL_BITMAP:
			எனில் ((r = put_bitmap(sect, bitmap)) != 0)
				செல் out;
			bitmap_free(bitmap);
			bitmap = வெற்று;
			நிறுத்து;
		}
		எனில் ((r = sshbuf_put_u8(buf, state)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			செல் out;
	}
	KRL_DBG(("serial done "));

	/* Now output a section for any revocations by key ID */
	sshbuf_reset(sect);
	RB_FOREACH(rki, revoked_சாவி_id_மரம், &rc->revoked_சாவி_ids) {
		KRL_DBG(("key ID %s", rki->சாவி_id));
		எனில் ((r = sshbuf_put_cstring(sect, rki->சாவி_id)) != 0)
			செல் out;
	}
	எனில் (sshbuf_len(sect) != 0) {
		எனில் ((r = sshbuf_put_u8(buf, KRL_SECTION_CERT_சாவி_ID)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			செல் out;
	}
	r = 0;
 out:
	bitmap_free(bitmap);
	sshbuf_free(sect);
	திரும்பு r;
}

முழு
ssh_krl_to_blob(கட்டமைப்பு ssh_krl *krl, கட்டமைப்பு sshbuf *buf)
{
	முழு r = SSH_ERR_INTERNAL_ERROR;
	கட்டமைப்பு revoked_certs *rc;
	கட்டமைப்பு revoked_blob *rb;
	கட்டமைப்பு sshbuf *sect;
	u_char *sblob = வெற்று;

	எனில் (krl->generated_date == 0)
		krl->generated_date = time(வெற்று);

	எனில் ((sect = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;

	/* Store the header */
	எனில் ((r = sshbuf_put(buf, KRL_MAGIC, அளவு(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_put_u32(buf, KRL_FORMAT_VERSION)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->krl_version)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->generated_date)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->flags)) != 0 ||
	    (r = sshbuf_put_string(buf, வெற்று, 0)) != 0 ||
	    (r = sshbuf_put_cstring(buf, krl->comment)) != 0)
		செல் out;

	/* Store sections for revoked certificates */
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		sshbuf_reset(sect);
		எனில் ((r = revoked_certs_generate(rc, sect)) != 0)
			செல் out;
		எனில் ((r = sshbuf_put_u8(buf, KRL_SECTION_CERTIFICATES)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			செல் out;
	}

	/* Finally, output sections for revocations by public key/hash */
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_மரம், &krl->revoked_சாவிகள்) {
		KRL_DBG(("key len %zu ", rb->len));
		எனில் ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			செல் out;
	}
	எனில் (sshbuf_len(sect) != 0) {
		எனில் ((r = sshbuf_put_u8(buf, KRL_SECTION_EXPLICIT_சாவி)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			செல் out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_மரம், &krl->revoked_sha1s) {
		KRL_DBG(("hash len %zu ", rb->len));
		எனில் ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			செல் out;
	}
	எனில் (sshbuf_len(sect) != 0) {
		எனில் ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA1)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			செல் out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_மரம், &krl->revoked_sha256s) {
		KRL_DBG(("hash len %zu ", rb->len));
		எனில் ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			செல் out;
	}
	எனில் (sshbuf_len(sect) != 0) {
		எனில் ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA256)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			செல் out;
	}
	/* success */
	r = 0;
 out:
	விடுவி(sblob);
	sshbuf_free(sect);
	திரும்பு r;
}

நிலையான வெறுமை
format_timestamp(uint64_t timestamp, எழுத்து *ts, size_t nts)
{
	time_t t;
	கட்டமைப்பு tm *tm;

	t = timestamp;
	tm = localtime(&t);
	எனில் (tm == வெற்று)
		strlcpy(ts, "<INVALID>", nts);
	இல்லையெனில் {
		*ts = '\0';
		strftime(ts, nts, "%Y%m%dT%H%M%S", tm);
	}
}

நிலையான முழு
cert_extension_subsection(கட்டமைப்பு sshbuf *subsect, கட்டமைப்பு ssh_krl *krl)
{
	முழு r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	கட்டமைப்பு sshbuf *மதிப்பு = வெற்று;
	எழுத்து *name = வெற்று;

	எனில் ((r = sshbuf_get_cstring(subsect, &name, வெற்று)) != 0 ||
	    (r = sshbuf_get_u8(subsect, &critical)) != 0 ||
	    (r = sshbuf_froms(subsect, &மதிப்பு)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid certificate extension subsection");
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் (sshbuf_len(subsect) != 0) {
		error("KRL has invalid certificate extension subsection: "
		    "trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	debug_f("cert extension %s critical %u len %zu",
	    name, critical, sshbuf_len(மதிப்பு));
	/* no extensions are currently supported */
	எனில் (critical) {
		error("KRL contains unsupported critical certificate "
		    "subsection \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		செல் out;
	}
	/* success */
	r = 0;
 out:
	விடுவி(name);
	sshbuf_free(மதிப்பு);
	திரும்பு r;
}

நிலையான முழு
parse_revoked_certs(கட்டமைப்பு sshbuf *buf, கட்டமைப்பு ssh_krl *krl)
{
	முழு r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	மாறிலி u_char *blob;
	size_t blen, nbits;
	கட்டமைப்பு sshbuf *subsect = வெற்று;
	uint64_t serial, serial_lo, serial_hi;
	கட்டமைப்பு bitmap *bitmap = வெற்று;
	எழுத்து *சாவி_id = வெற்று;
	கட்டமைப்பு sshkey *ca_சாவி = வெற்று;

	எனில் ((subsect = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;

	/* Header: key, reserved */
	எனில் ((r = sshbuf_get_string_direct(buf, &blob, &blen)) != 0 ||
	    (r = sshbuf_skip_string(buf)) != 0)
		செல் out;
	எனில் (blen != 0 && (r = sshkey_from_blob(blob, blen, &ca_சாவி)) != 0)
		செல் out;

	போது (sshbuf_len(buf) > 0) {
		sshbuf_free(subsect);
		subsect = வெற்று;
		எனில் ((r = sshbuf_get_u8(buf, &type)) != 0 ||
		    (r = sshbuf_froms(buf, &subsect)) != 0)
			செல் out;
		KRL_DBG(("subsection type 0x%02x", type));
		/* sshbuf_dump(subsect, stderr); */

		தேர்வு (type) {
		நிலை KRL_SECTION_CERT_SERIAL_LIST:
			போது (sshbuf_len(subsect) > 0) {
				எனில் ((r = sshbuf_get_u64(subsect, &serial)) != 0)
					செல் out;
				எனில் ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_சாவி, serial)) != 0)
					செல் out;
			}
			நிறுத்து;
		நிலை KRL_SECTION_CERT_SERIAL_RANGE:
			எனில் ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_u64(subsect, &serial_hi)) != 0)
				செல் out;
			எனில் ((r = ssh_krl_revoke_cert_by_serial_range(krl,
			    ca_சாவி, serial_lo, serial_hi)) != 0)
				செல் out;
			நிறுத்து;
		நிலை KRL_SECTION_CERT_SERIAL_BITMAP:
			எனில் ((bitmap = bitmap_new()) == வெற்று) {
				r = SSH_ERR_ALLOC_FAIL;
				செல் out;
			}
			எனில் ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_bignum2_bytes_direct(subsect,
			    &blob, &blen)) != 0)
				செல் out;
			எனில் (bitmap_from_string(bitmap, blob, blen) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				செல் out;
			}
			nbits = bitmap_nbits(bitmap);
			க்கு (serial = 0; serial < (uint64_t)nbits; serial++) {
				எனில் (serial > 0 && serial_lo + serial == 0) {
					error_f("bitmap wraps u64");
					r = SSH_ERR_INVALID_FORMAT;
					செல் out;
				}
				எனில் (!bitmap_test_bit(bitmap, serial))
					தொடர்;
				எனில் ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_சாவி, serial_lo + serial)) != 0)
					செல் out;
			}
			bitmap_free(bitmap);
			bitmap = வெற்று;
			நிறுத்து;
		நிலை KRL_SECTION_CERT_சாவி_ID:
			போது (sshbuf_len(subsect) > 0) {
				எனில் ((r = sshbuf_get_cstring(subsect,
				    &சாவி_id, வெற்று)) != 0)
					செல் out;
				எனில் ((r = ssh_krl_revoke_cert_by_சாவி_id(krl,
				    ca_சாவி, சாவி_id)) != 0)
					செல் out;
				விடுவி(சாவி_id);
				சாவி_id = வெற்று;
			}
			நிறுத்து;
		நிலை KRL_SECTION_CERT_EXTENSION:
			எனில் ((r = cert_extension_subsection(subsect, krl)) != 0)
				செல் out;
			நிறுத்து;
		இயல்பு:
			error("Unsupported KRL certificate section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
		எனில் (sshbuf_len(subsect) > 0) {
			error("KRL certificate section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
	}

	r = 0;
 out:
	எனில் (bitmap != வெற்று)
		bitmap_free(bitmap);
	விடுவி(சாவி_id);
	sshkey_free(ca_சாவி);
	sshbuf_free(subsect);
	திரும்பு r;
}

நிலையான முழு
blob_section(கட்டமைப்பு sshbuf *sect, கட்டமைப்பு revoked_blob_மரம் *target_மரம்,
    size_t expected_len)
{
	u_char *rdata = வெற்று;
	size_t rlen = 0;
	முழு r;

	போது (sshbuf_len(sect) > 0) {
		எனில் ((r = sshbuf_get_string(sect, &rdata, &rlen)) != 0)
			திரும்பு r;
		எனில் (expected_len != 0 && rlen != expected_len) {
			error_f("bad length");
			விடுவி(rdata);
			திரும்பு SSH_ERR_INVALID_FORMAT;
		}
		எனில் ((r = revoke_blob(target_மரம், rdata, rlen)) != 0) {
			விடுவி(rdata);
			திரும்பு r;
		}
	}
	திரும்பு 0;
}

நிலையான முழு
extension_section(கட்டமைப்பு sshbuf *sect, கட்டமைப்பு ssh_krl *krl)
{
	முழு r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	கட்டமைப்பு sshbuf *மதிப்பு = வெற்று;
	எழுத்து *name = வெற்று;

	எனில் ((r = sshbuf_get_cstring(sect, &name, வெற்று)) != 0 ||
	    (r = sshbuf_get_u8(sect, &critical)) != 0 ||
	    (r = sshbuf_froms(sect, &மதிப்பு)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid extension section");
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் (sshbuf_len(sect) != 0) {
		error("KRL has invalid extension section: trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	debug_f("extension %s critical %u len %zu",
	    name, critical, sshbuf_len(மதிப்பு));
	/* no extensions are currently supported */
	எனில் (critical) {
		error("KRL contains unsupported critical section \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		செல் out;
	}
	/* success */
	r = 0;
 out:
	விடுவி(name);
	sshbuf_free(மதிப்பு);
	திரும்பு r;
}

/* Attempt to parse a KRL */
முழு
ssh_krl_from_blob(கட்டமைப்பு sshbuf *buf, கட்டமைப்பு ssh_krl **krlp)
{
	கட்டமைப்பு sshbuf *copy = வெற்று, *sect = வெற்று;
	கட்டமைப்பு ssh_krl *krl = வெற்று;
	எழுத்து timestamp[64];
	முழு r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	u_int format_version;

	*krlp = வெற்று;

	/* KRL must begin with magic string */
	எனில் ((r = sshbuf_cmp(buf, 0, KRL_MAGIC, அளவு(KRL_MAGIC) - 1)) != 0) {
		debug2_f("bad KRL magic header");
		திரும்பு SSH_ERR_KRL_BAD_MAGIC;
	}

	எனில் ((krl = ssh_krl_init()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		error_f("alloc failed");
		செல் out;
	}
	/* Don't modify buffer */
	எனில் ((copy = sshbuf_fromb(buf)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_consume(copy, அளவு(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_get_u32(copy, &format_version)) != 0)
		செல் out;
	எனில் (format_version != KRL_FORMAT_VERSION) {
		error_f("unsupported KRL format version %u", format_version);
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் ((r = sshbuf_get_u64(copy, &krl->krl_version)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->generated_date)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->flags)) != 0 ||
	    (r = sshbuf_skip_string(copy)) != 0 ||
	    (r = sshbuf_get_cstring(copy, &krl->comment, வெற்று)) != 0) {
		error_fr(r, "parse KRL header");
		செல் out;
	}
	format_timestamp(krl->generated_date, timestamp, அளவு(timestamp));
	debug("KRL version %llu generated at %s%s%s",
	    (long long unsigned)krl->krl_version, timestamp,
	    *krl->comment ? ": " : "", krl->comment);

	/* Parse and load the KRL sections. */
	போது (sshbuf_len(copy) > 0) {
		sshbuf_free(sect);
		sect = வெற்று;
		எனில் ((r = sshbuf_get_u8(copy, &type)) != 0 ||
		    (r = sshbuf_froms(copy, &sect)) != 0)
			செல் out;
		KRL_DBG(("section 0x%02x", type));

		தேர்வு (type) {
		நிலை KRL_SECTION_CERTIFICATES:
			எனில் ((r = parse_revoked_certs(sect, krl)) != 0)
				செல் out;
			நிறுத்து;
		நிலை KRL_SECTION_EXPLICIT_சாவி:
			எனில் ((r = blob_section(sect,
			    &krl->revoked_சாவிகள், 0)) != 0)
				செல் out;
			நிறுத்து;
		நிலை KRL_SECTION_FINGERPRINT_SHA1:
			எனில் ((r = blob_section(sect,
			    &krl->revoked_sha1s, 20)) != 0)
				செல் out;
			நிறுத்து;
		நிலை KRL_SECTION_FINGERPRINT_SHA256:
			எனில் ((r = blob_section(sect,
			    &krl->revoked_sha256s, 32)) != 0)
				செல் out;
			நிறுத்து;
		நிலை KRL_SECTION_EXTENSION:
			எனில் ((r = extension_section(sect, krl)) != 0)
				செல் out;
			நிறுத்து;
		நிலை KRL_SECTION_SIGNATURE:
			/* Handled above, but still need to stay in synch */
			sshbuf_free(sect);
			sect = வெற்று;
			எனில் ((r = sshbuf_skip_string(copy)) != 0)
				செல் out;
			நிறுத்து;
		இயல்பு:
			error("Unsupported KRL section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
		எனில் (sect != வெற்று && sshbuf_len(sect) > 0) {
			error("KRL section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
	}

	/* Success */
	*krlp = krl;
	r = 0;
 out:
	எனில் (r != 0)
		ssh_krl_free(krl);
	sshbuf_free(copy);
	sshbuf_free(sect);
	திரும்பு r;
}

/* Checks certificate serial number and key ID revocation */
நிலையான முழு
is_cert_revoked(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு revoked_certs *rc)
{
	கட்டமைப்பு revoked_serial rs, *ers;
	கட்டமைப்பு revoked_சாவி_id rki, *erki;

	/* Check revocation by cert key ID */
	memset(&rki, 0, அளவு(rki));
	rki.சாவி_id = சாவி->cert->சாவி_id;
	erki = RB_FIND(revoked_சாவி_id_மரம், &rc->revoked_சாவி_ids, &rki);
	எனில் (erki != வெற்று) {
		KRL_DBG(("revoked by key ID"));
		திரும்பு SSH_ERR_சாவி_REVOKED;
	}

	/*
	 * Zero serials numbers are ignored (it's the default when the
	 * CA doesn't specify one).
	 */
	எனில் (சாவி->cert->serial == 0)
		திரும்பு 0;

	memset(&rs, 0, அளவு(rs));
	rs.lo = rs.hi = சாவி->cert->serial;
	ers = RB_FIND(revoked_serial_மரம், &rc->revoked_serials, &rs);
	எனில் (ers != வெற்று) {
		KRL_DBG(("revoked serial %llu matched %llu:%llu",
		    (unsigned long long)சாவி->cert->serial,
		    (unsigned long long)ers->lo,
		    (unsigned long long)ers->hi));
		திரும்பு SSH_ERR_சாவி_REVOKED;
	}
	திரும்பு 0;
}

/* Checks whether a given key/cert is revoked. Does not check its CA */
நிலையான முழு
is_சாவி_revoked(கட்டமைப்பு ssh_krl *krl, மாறிலி கட்டமைப்பு sshkey *சாவி)
{
	கட்டமைப்பு revoked_blob rb, *erb;
	கட்டமைப்பு revoked_certs *rc;
	முழு r;

	/* Check explicitly revoked hashes first */
	memset(&rb, 0, அளவு(rb));
	எனில் ((r = sshkey_fingerprint_raw(சாவி, SSH_DIGEST_SHA1,
	    &rb.blob, &rb.len)) != 0)
		திரும்பு r;
	erb = RB_FIND(revoked_blob_மரம், &krl->revoked_sha1s, &rb);
	விடுவி(rb.blob);
	எனில் (erb != வெற்று) {
		KRL_DBG(("revoked by key SHA1"));
		திரும்பு SSH_ERR_சாவி_REVOKED;
	}
	memset(&rb, 0, அளவு(rb));
	எனில் ((r = sshkey_fingerprint_raw(சாவி, SSH_DIGEST_SHA256,
	    &rb.blob, &rb.len)) != 0)
		திரும்பு r;
	erb = RB_FIND(revoked_blob_மரம், &krl->revoked_sha256s, &rb);
	விடுவி(rb.blob);
	எனில் (erb != வெற்று) {
		KRL_DBG(("revoked by key SHA256"));
		திரும்பு SSH_ERR_சாவி_REVOKED;
	}

	/* Next, explicit keys */
	memset(&rb, 0, அளவு(rb));
	எனில் ((r = plain_சாவி_blob(சாவி, &rb.blob, &rb.len)) != 0)
		திரும்பு r;
	erb = RB_FIND(revoked_blob_மரம், &krl->revoked_சாவிகள், &rb);
	விடுவி(rb.blob);
	எனில் (erb != வெற்று) {
		KRL_DBG(("revoked by explicit key"));
		திரும்பு SSH_ERR_சாவி_REVOKED;
	}

	எனில் (!sshkey_is_cert(சாவி))
		திரும்பு 0;

	/* Check cert revocation for the specified CA */
	எனில் ((r = revoked_certs_for_ca_சாவி(krl, சாவி->cert->signature_சாவி,
	    &rc, 0)) != 0)
		திரும்பு r;
	எனில் (rc != வெற்று) {
		எனில் ((r = is_cert_revoked(சாவி, rc)) != 0)
			திரும்பு r;
	}
	/* Check cert revocation for the wildcard CA */
	எனில் ((r = revoked_certs_for_ca_சாவி(krl, வெற்று, &rc, 0)) != 0)
		திரும்பு r;
	எனில் (rc != வெற்று) {
		எனில் ((r = is_cert_revoked(சாவி, rc)) != 0)
			திரும்பு r;
	}

	KRL_DBG(("%llu no match", (unsigned long long)சாவி->cert->serial));
	திரும்பு 0;
}

முழு
ssh_krl_check_சாவி(கட்டமைப்பு ssh_krl *krl, மாறிலி கட்டமைப்பு sshkey *சாவி)
{
	முழு r;

	KRL_DBG(("checking key"));
	எனில் ((r = is_சாவி_revoked(krl, சாவி)) != 0)
		திரும்பு r;
	எனில் (sshkey_is_cert(சாவி)) {
		debug2_f("checking CA key");
		எனில் ((r = is_சாவி_revoked(krl, சாவி->cert->signature_சாவி)) != 0)
			திரும்பு r;
	}
	KRL_DBG(("key okay"));
	திரும்பு 0;
}

முழு
ssh_krl_file_contains_சாவி(மாறிலி எழுத்து *path, மாறிலி கட்டமைப்பு sshkey *சாவி)
{
	கட்டமைப்பு sshbuf *krlbuf = வெற்று;
	கட்டமைப்பு ssh_krl *krl = வெற்று;
	முழு oerrno = 0, r;

	எனில் (path == வெற்று)
		திரும்பு 0;
	எனில் ((r = sshbuf_load_file(path, &krlbuf)) != 0) {
		oerrno = errno;
		செல் out;
	}
	எனில் ((r = ssh_krl_from_blob(krlbuf, &krl)) != 0)
		செல் out;
	debug2_f("checking KRL %s", path);
	r = ssh_krl_check_சாவி(krl, சாவி);
 out:
	sshbuf_free(krlbuf);
	ssh_krl_free(krl);
	எனில் (r != 0)
		errno = oerrno;
	திரும்பு r;
}

முழு
krl_dump(கட்டமைப்பு ssh_krl *krl, FILE *f)
{
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	கட்டமைப்பு revoked_blob *rb;
	கட்டமைப்பு revoked_certs *rc;
	கட்டமைப்பு revoked_serial *rs;
	கட்டமைப்பு revoked_சாவி_id *rki;
	முழு r, ret = 0;
	எழுத்து *fp, timestamp[64];

	/* Try to print in a KRL spec-compatible format */
	format_timestamp(krl->generated_date, timestamp, அளவு(timestamp));
	fprintf(f, "# KRL version %llu\n", (unsigned long long)krl->krl_version);
	fprintf(f, "# Generated at %s\n", timestamp);
	எனில் (krl->comment != வெற்று && *krl->comment != '\0') {
		r = INT_MAX;
		asmprintf(&fp, INT_MAX, &r, "%s", krl->comment);
		fprintf(f, "# Comment: %s\n", fp);
		விடுவி(fp);
	}
	fputc('\n', f);

	RB_FOREACH(rb, revoked_blob_மரம், &krl->revoked_சாவிகள்) {
		எனில் ((r = sshkey_from_blob(rb->blob, rb->len, &சாவி)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			error_r(r, "parse KRL key");
			தொடர்;
		}
		எனில் ((fp = sshkey_fingerprint(சாவி, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == வெற்று) {
			ret = SSH_ERR_INVALID_FORMAT;
			error("sshkey_fingerprint failed");
			தொடர்;
		}
		fprintf(f, "hash: %s # %s\n", fp, sshkey_ssh_name(சாவி));
		விடுவி(fp);
		விடுவி(சாவி);
	}
	RB_FOREACH(rb, revoked_blob_மரம், &krl->revoked_sha256s) {
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "hash: SHA256:%s\n", fp);
		விடுவி(fp);
	}
	RB_FOREACH(rb, revoked_blob_மரம், &krl->revoked_sha1s) {
		/*
		 * There is not KRL spec keyword for raw SHA1 hashes, so
		 * print them as comments.
		 */
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "# hash SHA1:%s\n", fp);
		விடுவி(fp);
	}

	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		fputc('\n', f);
		எனில் (rc->ca_சாவி == வெற்று)
			fprintf(f, "# Wildcard CA\n");
		இல்லையெனில் {
			எனில் ((fp = sshkey_fingerprint(rc->ca_சாவி,
			    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == வெற்று) {
				ret = SSH_ERR_INVALID_FORMAT;
				error("sshkey_fingerprint failed");
				தொடர்;
			}
			fprintf(f, "# CA key %s %s\n",
			    sshkey_ssh_name(rc->ca_சாவி), fp);
			விடுவி(fp);
		}
		RB_FOREACH(rs, revoked_serial_மரம், &rc->revoked_serials) {
			எனில் (rs->lo == rs->hi) {
				fprintf(f, "serial: %llu\n",
				    (unsigned long long)rs->lo);
			} இல்லையெனில் {
				fprintf(f, "serial: %llu-%llu\n",
				    (unsigned long long)rs->lo,
				    (unsigned long long)rs->hi);
			}
		}
		RB_FOREACH(rki, revoked_சாவி_id_மரம், &rc->revoked_சாவி_ids) {
			/*
			 * We don't want key IDs with embedded newlines to
			 * mess up the display.
			 */
			r = INT_MAX;
			asmprintf(&fp, INT_MAX, &r, "%s", rki->சாவி_id);
			fprintf(f, "id: %s\n", fp);
			விடுவி(fp);
		}
	}
	திரும்பு ret;
}
