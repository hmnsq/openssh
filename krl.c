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

#include "includes.h"

#include <sys/types.h>
#include <sys/tree.h>
#include <sys/queue.h>

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "sshkey.h"
#include "misc.h"
#include "log.h"
#include "digest.h"
#include "bitmap.h"
#include "utf8.h"

#include "krl.h"

/* #define DEBUG_KRL */
#ifdef DEBUG_KRL
# define KRL_DBG(x) debug3_f x
#ບໍ່ດັ່ງນັ້ນ
# define KRL_DBG(x)
#endif

/*
 * Trees of revoked serial numbers, key IDs and keys. This allows
 * quick searching, querying and producing lists in canonical order.
 */

/* Tree of serial numbers. XXX make smarter: really need a real sparse bitmap */
sa_nracanaa revoked_serial {
	uint64_t lo, hi;
	RB_ENTRY(revoked_serial) tree_entry;
};
static ຈຳນວນເຕັມ serial_cmp(sa_nracanaa revoked_serial *a, sa_nracanaa revoked_serial *b);
RB_HEAD(revoked_serial_tree, revoked_serial);
RB_GENERATE_STATIC(revoked_serial_tree, revoked_serial, tree_entry, serial_cmp)

/* Tree of key IDs */
sa_nracanaa revoked_key_id {
	var_na *key_id;
	RB_ENTRY(revoked_key_id) tree_entry;
};
static ຈຳນວນເຕັມ key_id_cmp(sa_nracanaa revoked_key_id *a, sa_nracanaa revoked_key_id *b);
RB_HEAD(revoked_key_id_tree, revoked_key_id);
RB_GENERATE_STATIC(revoked_key_id_tree, revoked_key_id, tree_entry, key_id_cmp)

/* Tree of blobs (used for keys and fingerprints) */
sa_nracanaa revoked_blob {
	u_char *blob;
	size_t len;
	RB_ENTRY(revoked_blob) tree_entry;
};
static ຈຳນວນເຕັມ blob_cmp(sa_nracanaa revoked_blob *a, sa_nracanaa revoked_blob *b);
RB_HEAD(revoked_blob_tree, revoked_blob);
RB_GENERATE_STATIC(revoked_blob_tree, revoked_blob, tree_entry, blob_cmp)

/* Tracks revoked certs for a single CA */
sa_nracanaa revoked_certs {
	sa_nracanaa sshkey *ca_key;
	sa_nracanaa revoked_serial_tree revoked_serials;
	sa_nracanaa revoked_key_id_tree revoked_key_ids;
	TAILQ_ENTRY(revoked_certs) entry;
};
TAILQ_HEAD(revoked_certs_list, revoked_certs);

sa_nracanaa ssh_krl {
	uint64_t krl_version;
	uint64_t generated_date;
	uint64_t flags;
	var_na *comment;
	sa_nracanaa revoked_blob_tree revoked_keys;
	sa_nracanaa revoked_blob_tree revoked_sha1s;
	sa_nracanaa revoked_blob_tree revoked_sha256s;
	sa_nracanaa revoked_certs_list revoked_certs;
};

/* Return equal if a and b overlap */
static ຈຳນວນເຕັມ
serial_cmp(sa_nracanaa revoked_serial *a, sa_nracanaa revoked_serial *b)
{
	ຖ້າ (a->hi >= b->lo && a->lo <= b->hi)
		ສົ່ງຄືນ 0;
	ສົ່ງຄືນ a->lo < b->lo ? -1 : 1;
}

static ຈຳນວນເຕັມ
key_id_cmp(sa_nracanaa revoked_key_id *a, sa_nracanaa revoked_key_id *b)
{
	ສົ່ງຄືນ strcmp(a->key_id, b->key_id);
}

static ຈຳນວນເຕັມ
blob_cmp(sa_nracanaa revoked_blob *a, sa_nracanaa revoked_blob *b)
{
	ຈຳນວນເຕັມ r;

	ຖ້າ (a->len != b->len) {
		ຖ້າ ((r = memcmp(a->blob, b->blob, MINIMUM(a->len, b->len))) != 0)
			ສົ່ງຄືນ r;
		ສົ່ງຄືນ a->len > b->len ? 1 : -1;
	} ບໍ່ດັ່ງນັ້ນ
		ສົ່ງຄືນ memcmp(a->blob, b->blob, a->len);
}

sa_nracanaa ssh_krl *
ssh_krl_init(void)
{
	sa_nracanaa ssh_krl *krl;

	ຖ້າ ((krl = calloc(1, parimaa_na(*krl))) == NULL)
		ສົ່ງຄືນ NULL;
	RB_INIT(&krl->revoked_keys);
	RB_INIT(&krl->revoked_sha1s);
	RB_INIT(&krl->revoked_sha256s);
	TAILQ_INIT(&krl->revoked_certs);
	ສົ່ງຄືນ krl;
}

static void
revoked_certs_free(sa_nracanaa revoked_certs *rc)
{
	sa_nracanaa revoked_serial *rs, *trs;
	sa_nracanaa revoked_key_id *rki, *trki;

	ຖ້າ (rc == NULL)
		ສົ່ງຄືນ;
	RB_FOREACH_SAFE(rs, revoked_serial_tree, &rc->revoked_serials, trs) {
		RB_REMOVE(revoked_serial_tree, &rc->revoked_serials, rs);
		free(rs);
	}
	RB_FOREACH_SAFE(rki, revoked_key_id_tree, &rc->revoked_key_ids, trki) {
		RB_REMOVE(revoked_key_id_tree, &rc->revoked_key_ids, rki);
		free(rki->key_id);
		free(rki);
	}
	sshkey_free(rc->ca_key);
	freezero(rc, parimaa_na(*rc));
}

void
ssh_krl_free(sa_nracanaa ssh_krl *krl)
{
	sa_nracanaa revoked_blob *rb, *trb;
	sa_nracanaa revoked_certs *rc, *trc;

	ຖ້າ (krl == NULL)
		ສົ່ງຄືນ;

	free(krl->comment);
	RB_FOREACH_SAFE(rb, revoked_blob_tree, &krl->revoked_keys, trb) {
		RB_REMOVE(revoked_blob_tree, &krl->revoked_keys, rb);
		free(rb->blob);
		free(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_tree, &krl->revoked_sha1s, trb) {
		RB_REMOVE(revoked_blob_tree, &krl->revoked_sha1s, rb);
		free(rb->blob);
		free(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_tree, &krl->revoked_sha256s, trb) {
		RB_REMOVE(revoked_blob_tree, &krl->revoked_sha256s, rb);
		free(rb->blob);
		free(rb);
	}
	TAILQ_FOREACH_SAFE(rc, &krl->revoked_certs, entry, trc) {
		TAILQ_REMOVE(&krl->revoked_certs, rc, entry);
		revoked_certs_free(rc);
	}
	free(krl);
}

void
ssh_krl_set_version(sa_nracanaa ssh_krl *krl, uint64_t version)
{
	krl->krl_version = version;
}

ຈຳນວນເຕັມ
ssh_krl_set_comment(sa_nracanaa ssh_krl *krl, const var_na *comment)
{
	free(krl->comment);
	ຖ້າ ((krl->comment = strdup(comment)) == NULL)
		ສົ່ງຄືນ SSH_ERR_ALLOC_FAIL;
	ສົ່ງຄືນ 0;
}

/*
 * Find the revoked_certs struct for a CA key. If allow_create is set then
 * create a new one in the tree if one did not exist already.
 */
static ຈຳນວນເຕັມ
revoked_certs_for_ca_key(sa_nracanaa ssh_krl *krl, const sa_nracanaa sshkey *ca_key,
    sa_nracanaa revoked_certs **rcp, ຈຳນວນເຕັມ allow_create)
{
	sa_nracanaa revoked_certs *rc;
	ຈຳນວນເຕັມ r;

	*rcp = NULL;
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		ຖ້າ ((ca_key == NULL && rc->ca_key == NULL) ||
		    sshkey_equal(rc->ca_key, ca_key)) {
			*rcp = rc;
			ສົ່ງຄືນ 0;
		}
	}
	ຖ້າ (!allow_create)
		ສົ່ງຄືນ 0;
	/* If this CA doesn't exist in the list then add it now */
	ຖ້າ ((rc = calloc(1, parimaa_na(*rc))) == NULL)
		ສົ່ງຄືນ SSH_ERR_ALLOC_FAIL;
	ຖ້າ (ca_key == NULL)
		rc->ca_key = NULL;
	ບໍ່ດັ່ງນັ້ນ ຖ້າ ((r = sshkey_from_private(ca_key, &rc->ca_key)) != 0) {
		free(rc);
		ສົ່ງຄືນ r;
	}
	RB_INIT(&rc->revoked_serials);
	RB_INIT(&rc->revoked_key_ids);
	TAILQ_INSERT_TAIL(&krl->revoked_certs, rc, entry);
	KRL_DBG(("new CA %s", ca_key == NULL ? "*" : sshkey_type(ca_key)));
	*rcp = rc;
	ສົ່ງຄືນ 0;
}

static ຈຳນວນເຕັມ
insert_serial_range(sa_nracanaa revoked_serial_tree *rt, uint64_t lo, uint64_t hi)
{
	sa_nracanaa revoked_serial rs, *ers, *crs, *irs;

	KRL_DBG(("insert %llu:%llu",
	    (unsigned long long)lo, (unsigned long long)hi));
	memset(&rs, 0, parimaa_na(rs));
	rs.lo = lo;
	rs.hi = hi;
	ers = RB_NFIND(revoked_serial_tree, rt, &rs);
	ຖ້າ (ers == NULL || serial_cmp(ers, &rs) != 0) {
		/* No entry matches. Just insert */
		ຖ້າ ((irs = malloc(parimaa_na(rs))) == NULL)
			ສົ່ງຄືນ SSH_ERR_ALLOC_FAIL;
		memcpy(irs, &rs, parimaa_na(*irs));
		ers = RB_INSERT(revoked_serial_tree, rt, irs);
		ຖ້າ (ers != NULL) {
			KRL_DBG(("bad: ers != NULL"));
			/* Shouldn't happen */
			free(irs);
			ສົ່ງຄືນ SSH_ERR_INTERNAL_ERROR;
		}
		ers = irs;
	} ບໍ່ດັ່ງນັ້ນ {
		KRL_DBG(("overlap found %llu:%llu",
		    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
		/*
		 * The inserted entry overlaps an existing one. Grow the
		 * existing entry.
		 */
		ຖ້າ (ers->lo > lo)
			ers->lo = lo;
		ຖ້າ (ers->hi < hi)
			ers->hi = hi;
	}

	/*
	 * The inserted or revised range might overlap or abut adjacent ones;
	 * coalesce as necessary.
	 */

	/* Check predecessors */
	ໃນຂະນະທີ່ ((crs = RB_PREV(revoked_serial_tree, rt, ers)) != NULL) {
		KRL_DBG(("pred %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		ຖ້າ (ers->lo != 0 && crs->hi < ers->lo - 1)
			bha_nga;
		/* This entry overlaps. */
		ຖ້າ (crs->lo < ers->lo) {
			ers->lo = crs->lo;
			KRL_DBG(("pred extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_tree, rt, crs);
		free(crs);
	}
	/* Check successors */
	ໃນຂະນະທີ່ ((crs = RB_NEXT(revoked_serial_tree, rt, ers)) != NULL) {
		KRL_DBG(("succ %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		ຖ້າ (ers->hi != (uint64_t)-1 && crs->lo > ers->hi + 1)
			bha_nga;
		/* This entry overlaps. */
		ຖ້າ (crs->hi > ers->hi) {
			ers->hi = crs->hi;
			KRL_DBG(("succ extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_tree, rt, crs);
		free(crs);
	}
	KRL_DBG(("done, final %llu:%llu",
	    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
	ສົ່ງຄືນ 0;
}

ຈຳນວນເຕັມ
ssh_krl_revoke_cert_by_serial(sa_nracanaa ssh_krl *krl, const sa_nracanaa sshkey *ca_key,
    uint64_t serial)
{
	ສົ່ງຄືນ ssh_krl_revoke_cert_by_serial_range(krl, ca_key, serial, serial);
}

ຈຳນວນເຕັມ
ssh_krl_revoke_cert_by_serial_range(sa_nracanaa ssh_krl *krl,
    const sa_nracanaa sshkey *ca_key, uint64_t lo, uint64_t hi)
{
	sa_nracanaa revoked_certs *rc;
	ຈຳນວນເຕັມ r;

	ຖ້າ (lo > hi || lo == 0)
		ສົ່ງຄືນ SSH_ERR_INVALID_ARGUMENT;
	ຖ້າ ((r = revoked_certs_for_ca_key(krl, ca_key, &rc, 1)) != 0)
		ສົ່ງຄືນ r;
	ສົ່ງຄືນ insert_serial_range(&rc->revoked_serials, lo, hi);
}

ຈຳນວນເຕັມ
ssh_krl_revoke_cert_by_key_id(sa_nracanaa ssh_krl *krl, const sa_nracanaa sshkey *ca_key,
    const var_na *key_id)
{
	sa_nracanaa revoked_key_id *rki, *erki;
	sa_nracanaa revoked_certs *rc;
	ຈຳນວນເຕັມ r;

	ຖ້າ ((r = revoked_certs_for_ca_key(krl, ca_key, &rc, 1)) != 0)
		ສົ່ງຄືນ r;

	KRL_DBG(("revoke %s", key_id));
	ຖ້າ ((rki = calloc(1, parimaa_na(*rki))) == NULL ||
	    (rki->key_id = strdup(key_id)) == NULL) {
		free(rki);
		ສົ່ງຄືນ SSH_ERR_ALLOC_FAIL;
	}
	erki = RB_INSERT(revoked_key_id_tree, &rc->revoked_key_ids, rki);
	ຖ້າ (erki != NULL) {
		free(rki->key_id);
		free(rki);
	}
	ສົ່ງຄືນ 0;
}

/* Convert "key" to a public key blob without any certificate information */
static ຈຳນວນເຕັມ
plain_key_blob(const sa_nracanaa sshkey *key, u_char **blob, size_t *blen)
{
	sa_nracanaa sshkey *kcopy;
	ຈຳນວນເຕັມ r;

	ຖ້າ ((r = sshkey_from_private(key, &kcopy)) != 0)
		ສົ່ງຄືນ r;
	ຖ້າ (sshkey_is_cert(kcopy)) {
		ຖ້າ ((r = sshkey_drop_cert(kcopy)) != 0) {
			sshkey_free(kcopy);
			ສົ່ງຄືນ r;
		}
	}
	r = sshkey_to_blob(kcopy, blob, blen);
	sshkey_free(kcopy);
	ສົ່ງຄືນ r;
}

/* Revoke a key blob. Ownership of blob is transferred to the tree */
static ຈຳນວນເຕັມ
revoke_blob(sa_nracanaa revoked_blob_tree *rbt, u_char *blob, size_t len)
{
	sa_nracanaa revoked_blob *rb, *erb;

	ຖ້າ ((rb = calloc(1, parimaa_na(*rb))) == NULL)
		ສົ່ງຄືນ SSH_ERR_ALLOC_FAIL;
	rb->blob = blob;
	rb->len = len;
	erb = RB_INSERT(revoked_blob_tree, rbt, rb);
	ຖ້າ (erb != NULL) {
		free(rb->blob);
		free(rb);
	}
	ສົ່ງຄືນ 0;
}

ຈຳນວນເຕັມ
ssh_krl_revoke_key_explicit(sa_nracanaa ssh_krl *krl, const sa_nracanaa sshkey *key)
{
	u_char *blob;
	size_t len;
	ຈຳນວນເຕັມ r;

	debug3_f("revoke type %s", sshkey_type(key));
	ຖ້າ ((r = plain_key_blob(key, &blob, &len)) != 0)
		ສົ່ງຄືນ r;
	ສົ່ງຄືນ revoke_blob(&krl->revoked_keys, blob, len);
}

static ຈຳນວນເຕັມ
revoke_by_hash(sa_nracanaa revoked_blob_tree *target, const u_char *p, size_t len)
{
	u_char *blob;
	ຈຳນວນເຕັມ r;

	/* need to copy hash, as revoke_blob steals ownership */
	ຖ້າ ((blob = malloc(len)) == NULL)
		ສົ່ງຄືນ SSH_ERR_SYSTEM_ERROR;
	memcpy(blob, p, len);
	ຖ້າ ((r = revoke_blob(target, blob, len)) != 0) {
		free(blob);
		ສົ່ງຄືນ r;
	}
	ສົ່ງຄືນ 0;
}

ຈຳນວນເຕັມ
ssh_krl_revoke_key_sha1(sa_nracanaa ssh_krl *krl, const u_char *p, size_t len)
{
	debug3_f("revoke by sha1");
	ຖ້າ (len != 20)
		ສົ່ງຄືນ SSH_ERR_INVALID_FORMAT;
	ສົ່ງຄືນ revoke_by_hash(&krl->revoked_sha1s, p, len);
}

ຈຳນວນເຕັມ
ssh_krl_revoke_key_sha256(sa_nracanaa ssh_krl *krl, const u_char *p, size_t len)
{
	debug3_f("revoke by sha256");
	ຖ້າ (len != 32)
		ສົ່ງຄືນ SSH_ERR_INVALID_FORMAT;
	ສົ່ງຄືນ revoke_by_hash(&krl->revoked_sha256s, p, len);
}

ຈຳນວນເຕັມ
ssh_krl_revoke_key(sa_nracanaa ssh_krl *krl, const sa_nracanaa sshkey *key)
{
	/* XXX replace with SHA256? */
	ຖ້າ (!sshkey_is_cert(key))
		ສົ່ງຄືນ ssh_krl_revoke_key_explicit(krl, key);

	ຖ້າ (key->cert->serial == 0) {
		ສົ່ງຄືນ ssh_krl_revoke_cert_by_key_id(krl,
		    key->cert->signature_key,
		    key->cert->key_id);
	} ບໍ່ດັ່ງນັ້ນ {
		ສົ່ງຄືນ ssh_krl_revoke_cert_by_serial(krl,
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
static ຈຳນວນເຕັມ
choose_next_state(ຈຳນວນເຕັມ current_state, uint64_t contig, ຈຳນວນເຕັມ final,
    uint64_t last_gap, uint64_t next_gap, size_t bitmap_len,
    ຈຳນວນເຕັມ *force_new_section)
{
	ຈຳນວນເຕັມ new_state;
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
	switch (current_state) {
	pak_sa KRL_SECTION_CERT_SERIAL_LIST:
		cost_bitmap_restart = cost_bitmap = 8 + 64;
		bha_nga;
	pak_sa KRL_SECTION_CERT_SERIAL_BITMAP:
		cost_list = 8;
		cost_bitmap_restart = 8 + 64;
		bha_nga;
	pak_sa KRL_SECTION_CERT_SERIAL_RANGE:
	pak_sa 0:
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
	ຖ້າ (bitmap_len + cost_bitmap >= SSHBUF_MAX_BIGNUM) {
		KRL_DBG(("bitmap overfull len=%zu cost=%llu max=%u",
		    bitmap_len, (unsigned long long)cost_bitmap,
		    SSHBUF_MAX_BIGNUM));
		cost_bitmap = (uint64_t)-1;
	}

	/* Now pick the best choice */
	*force_new_section = 0;
	new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
	cost = cost_bitmap;
	ຖ້າ (cost_range < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_RANGE;
		cost = cost_range;
	}
	ຖ້າ (cost_list < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_LIST;
		cost = cost_list;
	}
	ຖ້າ (cost_bitmap_restart < cost) {
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
	ສົ່ງຄືນ new_state;
}

static ຈຳນວນເຕັມ
put_bitmap(sa_nracanaa sshbuf *buf, sa_nracanaa bitmap *bitmap)
{
	size_t len;
	u_char *blob;
	ຈຳນວນເຕັມ r;

	len = bitmap_nbytes(bitmap);
	ຖ້າ ((blob = malloc(len)) == NULL)
		ສົ່ງຄືນ SSH_ERR_ALLOC_FAIL;
	ຖ້າ (bitmap_to_string(bitmap, blob, len) != 0) {
		free(blob);
		ສົ່ງຄືນ SSH_ERR_INTERNAL_ERROR;
	}
	r = sshbuf_put_bignum2_bytes(buf, blob, len);
	free(blob);
	ສົ່ງຄືນ r;
}

/* Generate a KRL_SECTION_CERTIFICATES KRL section */
static ຈຳນວນເຕັມ
revoked_certs_generate(sa_nracanaa revoked_certs *rc, sa_nracanaa sshbuf *buf)
{
	ຈຳນວນເຕັມ final, force_new_sect, r = SSH_ERR_INTERNAL_ERROR;
	uint64_t i, contig, gap, last = 0, bitmap_start = 0;
	sa_nracanaa revoked_serial *rs, *nrs;
	sa_nracanaa revoked_key_id *rki;
	ຈຳນວນເຕັມ next_state, state = 0;
	size_t bitmap_len;
	sa_nracanaa sshbuf *sect;
	sa_nracanaa bitmap *bitmap = NULL;

	ຖ້າ ((sect = sshbuf_new()) == NULL)
		ສົ່ງຄືນ SSH_ERR_ALLOC_FAIL;

	/* Store the header: optional CA scope key, reserved */
	ຖ້າ (rc->ca_key == NULL) {
		ຖ້າ ((r = sshbuf_put_string(buf, NULL, 0)) != 0)
			goto out;
	} ບໍ່ດັ່ງນັ້ນ {
		ຖ້າ ((r = sshkey_puts(rc->ca_key, buf)) != 0)
			goto out;
	}
	ຖ້າ ((r = sshbuf_put_string(buf, NULL, 0)) != 0)
		goto out;

	/* Store the revoked serials.  */
	ສຳລັບ (rs = RB_MIN(revoked_serial_tree, &rc->revoked_serials);
	     rs != NULL;
	     rs = RB_NEXT(revoked_serial_tree, &rc->revoked_serials, rs)) {
		KRL_DBG(("serial %llu:%llu state 0x%02x",
		    (long long unsigned)rs->lo, (long long unsigned)rs->hi,
		    state));

		/* Check contiguous length and gap to next section (if any) */
		nrs = RB_NEXT(revoked_serial_tree, &rc->revoked_serials, rs);
		final = nrs == NULL;
		gap = nrs == NULL ? 0 : nrs->lo - rs->hi;
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
		ຖ້າ (state != 0 && (force_new_sect || next_state != state ||
		    state == KRL_SECTION_CERT_SERIAL_RANGE)) {
			KRL_DBG(("finish state 0x%02x", state));
			switch (state) {
			pak_sa KRL_SECTION_CERT_SERIAL_LIST:
			pak_sa KRL_SECTION_CERT_SERIAL_RANGE:
				bha_nga;
			pak_sa KRL_SECTION_CERT_SERIAL_BITMAP:
				ຖ້າ ((r = put_bitmap(sect, bitmap)) != 0)
					goto out;
				bitmap_free(bitmap);
				bitmap = NULL;
				bha_nga;
			}
			ຖ້າ ((r = sshbuf_put_u8(buf, state)) != 0 ||
			    (r = sshbuf_put_stringb(buf, sect)) != 0)
				goto out;
			sshbuf_reset(sect);
		}

		/* If we are starting a new section then prepare it now */
		ຖ້າ (next_state != state || force_new_sect) {
			KRL_DBG(("start state 0x%02x",
			    next_state));
			state = next_state;
			sshbuf_reset(sect);
			switch (state) {
			pak_sa KRL_SECTION_CERT_SERIAL_LIST:
			pak_sa KRL_SECTION_CERT_SERIAL_RANGE:
				bha_nga;
			pak_sa KRL_SECTION_CERT_SERIAL_BITMAP:
				ຖ້າ ((bitmap = bitmap_new()) == NULL) {
					r = SSH_ERR_ALLOC_FAIL;
					goto out;
				}
				bitmap_start = rs->lo;
				ຖ້າ ((r = sshbuf_put_u64(sect,
				    bitmap_start)) != 0)
					goto out;
				bha_nga;
			}
		}

		/* Perform section-specific processing */
		switch (state) {
		pak_sa KRL_SECTION_CERT_SERIAL_LIST:
			ສຳລັບ (i = 0; i < contig; i++) {
				ຖ້າ ((r = sshbuf_put_u64(sect, rs->lo + i)) != 0)
					goto out;
			}
			bha_nga;
		pak_sa KRL_SECTION_CERT_SERIAL_RANGE:
			ຖ້າ ((r = sshbuf_put_u64(sect, rs->lo)) != 0 ||
			    (r = sshbuf_put_u64(sect, rs->hi)) != 0)
				goto out;
			bha_nga;
		pak_sa KRL_SECTION_CERT_SERIAL_BITMAP:
			ຖ້າ (rs->lo - bitmap_start > INT_MAX) {
				r = SSH_ERR_INVALID_FORMAT;
				error_f("insane bitmap gap");
				goto out;
			}
			ສຳລັບ (i = 0; i < contig; i++) {
				ຖ້າ (bitmap_set_bit(bitmap,
				    rs->lo + i - bitmap_start) != 0) {
					r = SSH_ERR_ALLOC_FAIL;
					goto out;
				}
			}
			bha_nga;
		}
		last = rs->hi;
	}
	/* Flush the remaining section, if any */
	ຖ້າ (state != 0) {
		KRL_DBG(("serial final flush for state 0x%02x", state));
		switch (state) {
		pak_sa KRL_SECTION_CERT_SERIAL_LIST:
		pak_sa KRL_SECTION_CERT_SERIAL_RANGE:
			bha_nga;
		pak_sa KRL_SECTION_CERT_SERIAL_BITMAP:
			ຖ້າ ((r = put_bitmap(sect, bitmap)) != 0)
				goto out;
			bitmap_free(bitmap);
			bitmap = NULL;
			bha_nga;
		}
		ຖ້າ ((r = sshbuf_put_u8(buf, state)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			goto out;
	}
	KRL_DBG(("serial done "));

	/* Now output a section for any revocations by key ID */
	sshbuf_reset(sect);
	RB_FOREACH(rki, revoked_key_id_tree, &rc->revoked_key_ids) {
		KRL_DBG(("key ID %s", rki->key_id));
		ຖ້າ ((r = sshbuf_put_cstring(sect, rki->key_id)) != 0)
			goto out;
	}
	ຖ້າ (sshbuf_len(sect) != 0) {
		ຖ້າ ((r = sshbuf_put_u8(buf, KRL_SECTION_CERT_KEY_ID)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			goto out;
	}
	r = 0;
 out:
	bitmap_free(bitmap);
	sshbuf_free(sect);
	ສົ່ງຄືນ r;
}

ຈຳນວນເຕັມ
ssh_krl_to_blob(sa_nracanaa ssh_krl *krl, sa_nracanaa sshbuf *buf)
{
	ຈຳນວນເຕັມ r = SSH_ERR_INTERNAL_ERROR;
	sa_nracanaa revoked_certs *rc;
	sa_nracanaa revoked_blob *rb;
	sa_nracanaa sshbuf *sect;
	u_char *sblob = NULL;

	ຖ້າ (krl->generated_date == 0)
		krl->generated_date = time(NULL);

	ຖ້າ ((sect = sshbuf_new()) == NULL)
		ສົ່ງຄືນ SSH_ERR_ALLOC_FAIL;

	/* Store the header */
	ຖ້າ ((r = sshbuf_put(buf, KRL_MAGIC, parimaa_na(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_put_u32(buf, KRL_FORMAT_VERSION)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->krl_version)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->generated_date)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->flags)) != 0 ||
	    (r = sshbuf_put_string(buf, NULL, 0)) != 0 ||
	    (r = sshbuf_put_cstring(buf, krl->comment)) != 0)
		goto out;

	/* Store sections for revoked certificates */
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		sshbuf_reset(sect);
		ຖ້າ ((r = revoked_certs_generate(rc, sect)) != 0)
			goto out;
		ຖ້າ ((r = sshbuf_put_u8(buf, KRL_SECTION_CERTIFICATES)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			goto out;
	}

	/* Finally, output sections for revocations by public key/hash */
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_tree, &krl->revoked_keys) {
		KRL_DBG(("key len %zu ", rb->len));
		ຖ້າ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			goto out;
	}
	ຖ້າ (sshbuf_len(sect) != 0) {
		ຖ້າ ((r = sshbuf_put_u8(buf, KRL_SECTION_EXPLICIT_KEY)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			goto out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_tree, &krl->revoked_sha1s) {
		KRL_DBG(("hash len %zu ", rb->len));
		ຖ້າ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			goto out;
	}
	ຖ້າ (sshbuf_len(sect) != 0) {
		ຖ້າ ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA1)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			goto out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_tree, &krl->revoked_sha256s) {
		KRL_DBG(("hash len %zu ", rb->len));
		ຖ້າ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			goto out;
	}
	ຖ້າ (sshbuf_len(sect) != 0) {
		ຖ້າ ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA256)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			goto out;
	}
	/* success */
	r = 0;
 out:
	free(sblob);
	sshbuf_free(sect);
	ສົ່ງຄືນ r;
}

static void
format_timestamp(uint64_t timestamp, var_na *ts, size_t nts)
{
	time_t t;
	sa_nracanaa tm *tm;

	t = timestamp;
	tm = localtime(&t);
	ຖ້າ (tm == NULL)
		strlcpy(ts, "<INVALID>", nts);
	ບໍ່ດັ່ງນັ້ນ {
		*ts = '\0';
		strftime(ts, nts, "%Y%m%dT%H%M%S", tm);
	}
}

static ຈຳນວນເຕັມ
cert_extension_subsection(sa_nracanaa sshbuf *subsect, sa_nracanaa ssh_krl *krl)
{
	ຈຳນວນເຕັມ r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	sa_nracanaa sshbuf *value = NULL;
	var_na *name = NULL;

	ຖ້າ ((r = sshbuf_get_cstring(subsect, &name, NULL)) != 0 ||
	    (r = sshbuf_get_u8(subsect, &critical)) != 0 ||
	    (r = sshbuf_froms(subsect, &value)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid certificate extension subsection");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ຖ້າ (sshbuf_len(subsect) != 0) {
		error("KRL has invalid certificate extension subsection: "
		    "trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	debug_f("cert extension %s critical %u len %zu",
	    name, critical, sshbuf_len(value));
	/* no extensions are currently supported */
	ຖ້າ (critical) {
		error("KRL contains unsupported critical certificate "
		    "subsection \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		goto out;
	}
	/* success */
	r = 0;
 out:
	free(name);
	sshbuf_free(value);
	ສົ່ງຄືນ r;
}

static ຈຳນວນເຕັມ
parse_revoked_certs(sa_nracanaa sshbuf *buf, sa_nracanaa ssh_krl *krl)
{
	ຈຳນວນເຕັມ r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	const u_char *blob;
	size_t blen, nbits;
	sa_nracanaa sshbuf *subsect = NULL;
	uint64_t serial, serial_lo, serial_hi;
	sa_nracanaa bitmap *bitmap = NULL;
	var_na *key_id = NULL;
	sa_nracanaa sshkey *ca_key = NULL;

	ຖ້າ ((subsect = sshbuf_new()) == NULL)
		ສົ່ງຄືນ SSH_ERR_ALLOC_FAIL;

	/* Header: key, reserved */
	ຖ້າ ((r = sshbuf_get_string_direct(buf, &blob, &blen)) != 0 ||
	    (r = sshbuf_skip_string(buf)) != 0)
		goto out;
	ຖ້າ (blen != 0 && (r = sshkey_from_blob(blob, blen, &ca_key)) != 0)
		goto out;

	ໃນຂະນະທີ່ (sshbuf_len(buf) > 0) {
		sshbuf_free(subsect);
		subsect = NULL;
		ຖ້າ ((r = sshbuf_get_u8(buf, &type)) != 0 ||
		    (r = sshbuf_froms(buf, &subsect)) != 0)
			goto out;
		KRL_DBG(("subsection type 0x%02x", type));
		/* sshbuf_dump(subsect, stderr); */

		switch (type) {
		pak_sa KRL_SECTION_CERT_SERIAL_LIST:
			ໃນຂະນະທີ່ (sshbuf_len(subsect) > 0) {
				ຖ້າ ((r = sshbuf_get_u64(subsect, &serial)) != 0)
					goto out;
				ຖ້າ ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_key, serial)) != 0)
					goto out;
			}
			bha_nga;
		pak_sa KRL_SECTION_CERT_SERIAL_RANGE:
			ຖ້າ ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_u64(subsect, &serial_hi)) != 0)
				goto out;
			ຖ້າ ((r = ssh_krl_revoke_cert_by_serial_range(krl,
			    ca_key, serial_lo, serial_hi)) != 0)
				goto out;
			bha_nga;
		pak_sa KRL_SECTION_CERT_SERIAL_BITMAP:
			ຖ້າ ((bitmap = bitmap_new()) == NULL) {
				r = SSH_ERR_ALLOC_FAIL;
				goto out;
			}
			ຖ້າ ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_bignum2_bytes_direct(subsect,
			    &blob, &blen)) != 0)
				goto out;
			ຖ້າ (bitmap_from_string(bitmap, blob, blen) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				goto out;
			}
			nbits = bitmap_nbits(bitmap);
			ສຳລັບ (serial = 0; serial < (uint64_t)nbits; serial++) {
				ຖ້າ (serial > 0 && serial_lo + serial == 0) {
					error_f("bitmap wraps u64");
					r = SSH_ERR_INVALID_FORMAT;
					goto out;
				}
				ຖ້າ (!bitmap_test_bit(bitmap, serial))
					continue;
				ຖ້າ ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_key, serial_lo + serial)) != 0)
					goto out;
			}
			bitmap_free(bitmap);
			bitmap = NULL;
			bha_nga;
		pak_sa KRL_SECTION_CERT_KEY_ID:
			ໃນຂະນະທີ່ (sshbuf_len(subsect) > 0) {
				ຖ້າ ((r = sshbuf_get_cstring(subsect,
				    &key_id, NULL)) != 0)
					goto out;
				ຖ້າ ((r = ssh_krl_revoke_cert_by_key_id(krl,
				    ca_key, key_id)) != 0)
					goto out;
				free(key_id);
				key_id = NULL;
			}
			bha_nga;
		pak_sa KRL_SECTION_CERT_EXTENSION:
			ຖ້າ ((r = cert_extension_subsection(subsect, krl)) != 0)
				goto out;
			bha_nga;
		default:
			error("Unsupported KRL certificate section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		ຖ້າ (sshbuf_len(subsect) > 0) {
			error("KRL certificate section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}

	r = 0;
 out:
	ຖ້າ (bitmap != NULL)
		bitmap_free(bitmap);
	free(key_id);
	sshkey_free(ca_key);
	sshbuf_free(subsect);
	ສົ່ງຄືນ r;
}

static ຈຳນວນເຕັມ
blob_section(sa_nracanaa sshbuf *sect, sa_nracanaa revoked_blob_tree *target_tree,
    size_t expected_len)
{
	u_char *rdata = NULL;
	size_t rlen = 0;
	ຈຳນວນເຕັມ r;

	ໃນຂະນະທີ່ (sshbuf_len(sect) > 0) {
		ຖ້າ ((r = sshbuf_get_string(sect, &rdata, &rlen)) != 0)
			ສົ່ງຄືນ r;
		ຖ້າ (expected_len != 0 && rlen != expected_len) {
			error_f("bad length");
			free(rdata);
			ສົ່ງຄືນ SSH_ERR_INVALID_FORMAT;
		}
		ຖ້າ ((r = revoke_blob(target_tree, rdata, rlen)) != 0) {
			free(rdata);
			ສົ່ງຄືນ r;
		}
	}
	ສົ່ງຄືນ 0;
}

static ຈຳນວນເຕັມ
extension_section(sa_nracanaa sshbuf *sect, sa_nracanaa ssh_krl *krl)
{
	ຈຳນວນເຕັມ r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	sa_nracanaa sshbuf *value = NULL;
	var_na *name = NULL;

	ຖ້າ ((r = sshbuf_get_cstring(sect, &name, NULL)) != 0 ||
	    (r = sshbuf_get_u8(sect, &critical)) != 0 ||
	    (r = sshbuf_froms(sect, &value)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid extension section");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ຖ້າ (sshbuf_len(sect) != 0) {
		error("KRL has invalid extension section: trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	debug_f("extension %s critical %u len %zu",
	    name, critical, sshbuf_len(value));
	/* no extensions are currently supported */
	ຖ້າ (critical) {
		error("KRL contains unsupported critical section \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		goto out;
	}
	/* success */
	r = 0;
 out:
	free(name);
	sshbuf_free(value);
	ສົ່ງຄືນ r;
}

/* Attempt to parse a KRL */
ຈຳນວນເຕັມ
ssh_krl_from_blob(sa_nracanaa sshbuf *buf, sa_nracanaa ssh_krl **krlp)
{
	sa_nracanaa sshbuf *copy = NULL, *sect = NULL;
	sa_nracanaa ssh_krl *krl = NULL;
	var_na timestamp[64];
	ຈຳນວນເຕັມ r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	u_int format_version;

	*krlp = NULL;

	/* KRL must begin with magic string */
	ຖ້າ ((r = sshbuf_cmp(buf, 0, KRL_MAGIC, parimaa_na(KRL_MAGIC) - 1)) != 0) {
		debug2_f("bad KRL magic header");
		ສົ່ງຄືນ SSH_ERR_KRL_BAD_MAGIC;
	}

	ຖ້າ ((krl = ssh_krl_init()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		error_f("alloc failed");
		goto out;
	}
	/* Don't modify buffer */
	ຖ້າ ((copy = sshbuf_fromb(buf)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ຖ້າ ((r = sshbuf_consume(copy, parimaa_na(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_get_u32(copy, &format_version)) != 0)
		goto out;
	ຖ້າ (format_version != KRL_FORMAT_VERSION) {
		error_f("unsupported KRL format version %u", format_version);
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ຖ້າ ((r = sshbuf_get_u64(copy, &krl->krl_version)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->generated_date)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->flags)) != 0 ||
	    (r = sshbuf_skip_string(copy)) != 0 ||
	    (r = sshbuf_get_cstring(copy, &krl->comment, NULL)) != 0) {
		error_fr(r, "parse KRL header");
		goto out;
	}
	format_timestamp(krl->generated_date, timestamp, parimaa_na(timestamp));
	debug("KRL version %llu generated at %s%s%s",
	    (long long unsigned)krl->krl_version, timestamp,
	    *krl->comment ? ": " : "", krl->comment);

	/* Parse and load the KRL sections. */
	ໃນຂະນະທີ່ (sshbuf_len(copy) > 0) {
		sshbuf_free(sect);
		sect = NULL;
		ຖ້າ ((r = sshbuf_get_u8(copy, &type)) != 0 ||
		    (r = sshbuf_froms(copy, &sect)) != 0)
			goto out;
		KRL_DBG(("section 0x%02x", type));

		switch (type) {
		pak_sa KRL_SECTION_CERTIFICATES:
			ຖ້າ ((r = parse_revoked_certs(sect, krl)) != 0)
				goto out;
			bha_nga;
		pak_sa KRL_SECTION_EXPLICIT_KEY:
			ຖ້າ ((r = blob_section(sect,
			    &krl->revoked_keys, 0)) != 0)
				goto out;
			bha_nga;
		pak_sa KRL_SECTION_FINGERPRINT_SHA1:
			ຖ້າ ((r = blob_section(sect,
			    &krl->revoked_sha1s, 20)) != 0)
				goto out;
			bha_nga;
		pak_sa KRL_SECTION_FINGERPRINT_SHA256:
			ຖ້າ ((r = blob_section(sect,
			    &krl->revoked_sha256s, 32)) != 0)
				goto out;
			bha_nga;
		pak_sa KRL_SECTION_EXTENSION:
			ຖ້າ ((r = extension_section(sect, krl)) != 0)
				goto out;
			bha_nga;
		pak_sa KRL_SECTION_SIGNATURE:
			/* Handled above, but still need to stay in synch */
			sshbuf_free(sect);
			sect = NULL;
			ຖ້າ ((r = sshbuf_skip_string(copy)) != 0)
				goto out;
			bha_nga;
		default:
			error("Unsupported KRL section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		ຖ້າ (sect != NULL && sshbuf_len(sect) > 0) {
			error("KRL section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}

	/* Success */
	*krlp = krl;
	r = 0;
 out:
	ຖ້າ (r != 0)
		ssh_krl_free(krl);
	sshbuf_free(copy);
	sshbuf_free(sect);
	ສົ່ງຄືນ r;
}

/* Checks certificate serial number and key ID revocation */
static ຈຳນວນເຕັມ
is_cert_revoked(const sa_nracanaa sshkey *key, sa_nracanaa revoked_certs *rc)
{
	sa_nracanaa revoked_serial rs, *ers;
	sa_nracanaa revoked_key_id rki, *erki;

	/* Check revocation by cert key ID */
	memset(&rki, 0, parimaa_na(rki));
	rki.key_id = key->cert->key_id;
	erki = RB_FIND(revoked_key_id_tree, &rc->revoked_key_ids, &rki);
	ຖ້າ (erki != NULL) {
		KRL_DBG(("revoked by key ID"));
		ສົ່ງຄືນ SSH_ERR_KEY_REVOKED;
	}

	/*
	 * Zero serials numbers are ignored (it's the default when the
	 * CA doesn't specify one).
	 */
	ຖ້າ (key->cert->serial == 0)
		ສົ່ງຄືນ 0;

	memset(&rs, 0, parimaa_na(rs));
	rs.lo = rs.hi = key->cert->serial;
	ers = RB_FIND(revoked_serial_tree, &rc->revoked_serials, &rs);
	ຖ້າ (ers != NULL) {
		KRL_DBG(("revoked serial %llu matched %llu:%llu",
		    (unsigned long long)key->cert->serial,
		    (unsigned long long)ers->lo,
		    (unsigned long long)ers->hi));
		ສົ່ງຄືນ SSH_ERR_KEY_REVOKED;
	}
	ສົ່ງຄືນ 0;
}

/* Checks whether a given key/cert is revoked. Does not check its CA */
static ຈຳນວນເຕັມ
is_key_revoked(sa_nracanaa ssh_krl *krl, const sa_nracanaa sshkey *key)
{
	sa_nracanaa revoked_blob rb, *erb;
	sa_nracanaa revoked_certs *rc;
	ຈຳນວນເຕັມ r;

	/* Check explicitly revoked hashes first */
	memset(&rb, 0, parimaa_na(rb));
	ຖ້າ ((r = sshkey_fingerprint_raw(key, SSH_DIGEST_SHA1,
	    &rb.blob, &rb.len)) != 0)
		ສົ່ງຄືນ r;
	erb = RB_FIND(revoked_blob_tree, &krl->revoked_sha1s, &rb);
	free(rb.blob);
	ຖ້າ (erb != NULL) {
		KRL_DBG(("revoked by key SHA1"));
		ສົ່ງຄືນ SSH_ERR_KEY_REVOKED;
	}
	memset(&rb, 0, parimaa_na(rb));
	ຖ້າ ((r = sshkey_fingerprint_raw(key, SSH_DIGEST_SHA256,
	    &rb.blob, &rb.len)) != 0)
		ສົ່ງຄືນ r;
	erb = RB_FIND(revoked_blob_tree, &krl->revoked_sha256s, &rb);
	free(rb.blob);
	ຖ້າ (erb != NULL) {
		KRL_DBG(("revoked by key SHA256"));
		ສົ່ງຄືນ SSH_ERR_KEY_REVOKED;
	}

	/* Next, explicit keys */
	memset(&rb, 0, parimaa_na(rb));
	ຖ້າ ((r = plain_key_blob(key, &rb.blob, &rb.len)) != 0)
		ສົ່ງຄືນ r;
	erb = RB_FIND(revoked_blob_tree, &krl->revoked_keys, &rb);
	free(rb.blob);
	ຖ້າ (erb != NULL) {
		KRL_DBG(("revoked by explicit key"));
		ສົ່ງຄືນ SSH_ERR_KEY_REVOKED;
	}

	ຖ້າ (!sshkey_is_cert(key))
		ສົ່ງຄືນ 0;

	/* Check cert revocation for the specified CA */
	ຖ້າ ((r = revoked_certs_for_ca_key(krl, key->cert->signature_key,
	    &rc, 0)) != 0)
		ສົ່ງຄືນ r;
	ຖ້າ (rc != NULL) {
		ຖ້າ ((r = is_cert_revoked(key, rc)) != 0)
			ສົ່ງຄືນ r;
	}
	/* Check cert revocation for the wildcard CA */
	ຖ້າ ((r = revoked_certs_for_ca_key(krl, NULL, &rc, 0)) != 0)
		ສົ່ງຄືນ r;
	ຖ້າ (rc != NULL) {
		ຖ້າ ((r = is_cert_revoked(key, rc)) != 0)
			ສົ່ງຄືນ r;
	}

	KRL_DBG(("%llu no match", (unsigned long long)key->cert->serial));
	ສົ່ງຄືນ 0;
}

ຈຳນວນເຕັມ
ssh_krl_check_key(sa_nracanaa ssh_krl *krl, const sa_nracanaa sshkey *key)
{
	ຈຳນວນເຕັມ r;

	KRL_DBG(("checking key"));
	ຖ້າ ((r = is_key_revoked(krl, key)) != 0)
		ສົ່ງຄືນ r;
	ຖ້າ (sshkey_is_cert(key)) {
		debug2_f("checking CA key");
		ຖ້າ ((r = is_key_revoked(krl, key->cert->signature_key)) != 0)
			ສົ່ງຄືນ r;
	}
	KRL_DBG(("key okay"));
	ສົ່ງຄືນ 0;
}

ຈຳນວນເຕັມ
ssh_krl_file_contains_key(const var_na *path, const sa_nracanaa sshkey *key)
{
	sa_nracanaa sshbuf *krlbuf = NULL;
	sa_nracanaa ssh_krl *krl = NULL;
	ຈຳນວນເຕັມ oerrno = 0, r;

	ຖ້າ (path == NULL)
		ສົ່ງຄືນ 0;
	ຖ້າ ((r = sshbuf_load_file(path, &krlbuf)) != 0) {
		oerrno = errno;
		goto out;
	}
	ຖ້າ ((r = ssh_krl_from_blob(krlbuf, &krl)) != 0)
		goto out;
	debug2_f("checking KRL %s", path);
	r = ssh_krl_check_key(krl, key);
 out:
	sshbuf_free(krlbuf);
	ssh_krl_free(krl);
	ຖ້າ (r != 0)
		errno = oerrno;
	ສົ່ງຄືນ r;
}

ຈຳນວນເຕັມ
krl_dump(sa_nracanaa ssh_krl *krl, FILE *f)
{
	sa_nracanaa sshkey *key = NULL;
	sa_nracanaa revoked_blob *rb;
	sa_nracanaa revoked_certs *rc;
	sa_nracanaa revoked_serial *rs;
	sa_nracanaa revoked_key_id *rki;
	ຈຳນວນເຕັມ r, ret = 0;
	var_na *fp, timestamp[64];

	/* Try to print in a KRL spec-compatible format */
	format_timestamp(krl->generated_date, timestamp, parimaa_na(timestamp));
	fprintf(f, "# KRL version %llu\n", (unsigned long long)krl->krl_version);
	fprintf(f, "# Generated at %s\n", timestamp);
	ຖ້າ (krl->comment != NULL && *krl->comment != '\0') {
		r = INT_MAX;
		asmprintf(&fp, INT_MAX, &r, "%s", krl->comment);
		fprintf(f, "# Comment: %s\n", fp);
		free(fp);
	}
	fputc('\n', f);

	RB_FOREACH(rb, revoked_blob_tree, &krl->revoked_keys) {
		ຖ້າ ((r = sshkey_from_blob(rb->blob, rb->len, &key)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			error_r(r, "parse KRL key");
			continue;
		}
		ຖ້າ ((fp = sshkey_fingerprint(key, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == NULL) {
			ret = SSH_ERR_INVALID_FORMAT;
			error("sshkey_fingerprint failed");
			continue;
		}
		fprintf(f, "hash: %s # %s\n", fp, sshkey_ssh_name(key));
		free(fp);
		free(key);
	}
	RB_FOREACH(rb, revoked_blob_tree, &krl->revoked_sha256s) {
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "hash: SHA256:%s\n", fp);
		free(fp);
	}
	RB_FOREACH(rb, revoked_blob_tree, &krl->revoked_sha1s) {
		/*
		 * There is not KRL spec keyword for raw SHA1 hashes, so
		 * print them as comments.
		 */
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "# hash SHA1:%s\n", fp);
		free(fp);
	}

	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		fputc('\n', f);
		ຖ້າ (rc->ca_key == NULL)
			fprintf(f, "# Wildcard CA\n");
		ບໍ່ດັ່ງນັ້ນ {
			ຖ້າ ((fp = sshkey_fingerprint(rc->ca_key,
			    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == NULL) {
				ret = SSH_ERR_INVALID_FORMAT;
				error("sshkey_fingerprint failed");
				continue;
			}
			fprintf(f, "# CA key %s %s\n",
			    sshkey_ssh_name(rc->ca_key), fp);
			free(fp);
		}
		RB_FOREACH(rs, revoked_serial_tree, &rc->revoked_serials) {
			ຖ້າ (rs->lo == rs->hi) {
				fprintf(f, "serial: %llu\n",
				    (unsigned long long)rs->lo);
			} ບໍ່ດັ່ງນັ້ນ {
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
			free(fp);
		}
	}
	ສົ່ງຄືນ ret;
}
