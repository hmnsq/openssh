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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/tree.h>
#અન્તર્ભાવ <sys/queue.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <limits.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <time.h>

#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "bitmap.h"
#અન્તર્ભાવ "utf8.h"

#અન્તર્ભાવ "krl.h"

/* #define DEBUG_KRL */
#ifdef DEBUG_KRL
# define KRL_DBG(x) debug3_f x
#નહીંતર
# define KRL_DBG(x)
#endif

/*
 * Trees of revoked serial numbers, key IDs and keys. This allows
 * quick searching, querying and producing lists in canonical order.
 */

/* Tree of serial numbers. XXX make smarter: really need a real sparse bitmap */
સંરચના revoked_serial {
	uint64_t lo, hi;
	RB_ENTRY(revoked_serial) વૃક્ષ_entry;
};
સ્થિર પૂર્ણાંક serial_cmp(સંરચના revoked_serial *a, સંરચના revoked_serial *b);
RB_HEAD(revoked_serial_વૃક્ષ, revoked_serial);
RB_GENERATE_STATIC(revoked_serial_વૃક્ષ, revoked_serial, વૃક્ષ_entry, serial_cmp)

/* Tree of key IDs */
સંરચના revoked_ચાવી_id {
	અક્ષર *ચાવી_id;
	RB_ENTRY(revoked_ચાવી_id) વૃક્ષ_entry;
};
સ્થિર પૂર્ણાંક ચાવી_id_cmp(સંરચના revoked_ચાવી_id *a, સંરચના revoked_ચાવી_id *b);
RB_HEAD(revoked_ચાવી_id_વૃક્ષ, revoked_ચાવી_id);
RB_GENERATE_STATIC(revoked_ચાવી_id_વૃક્ષ, revoked_ચાવી_id, વૃક્ષ_entry, ચાવી_id_cmp)

/* Tree of blobs (used for keys and fingerprints) */
સંરચના revoked_blob {
	u_char *blob;
	size_t len;
	RB_ENTRY(revoked_blob) વૃક્ષ_entry;
};
સ્થિર પૂર્ણાંક blob_cmp(સંરચના revoked_blob *a, સંરચના revoked_blob *b);
RB_HEAD(revoked_blob_વૃક્ષ, revoked_blob);
RB_GENERATE_STATIC(revoked_blob_વૃક્ષ, revoked_blob, વૃક્ષ_entry, blob_cmp)

/* Tracks revoked certs for a single CA */
સંરચના revoked_certs {
	સંરચના sshkey *ca_ચાવી;
	સંરચના revoked_serial_વૃક્ષ revoked_serials;
	સંરચના revoked_ચાવી_id_વૃક્ષ revoked_ચાવી_ids;
	TAILQ_ENTRY(revoked_certs) entry;
};
TAILQ_HEAD(revoked_certs_list, revoked_certs);

સંરચના ssh_krl {
	uint64_t krl_version;
	uint64_t generated_date;
	uint64_t flags;
	અક્ષર *comment;
	સંરચના revoked_blob_વૃક્ષ revoked_ચાવીઓ;
	સંરચના revoked_blob_વૃક્ષ revoked_sha1s;
	સંરચના revoked_blob_વૃક્ષ revoked_sha256s;
	સંરચના revoked_certs_list revoked_certs;
};

/* Return equal if a and b overlap */
સ્થિર પૂર્ણાંક
serial_cmp(સંરચના revoked_serial *a, સંરચના revoked_serial *b)
{
	જો (a->hi >= b->lo && a->lo <= b->hi)
		પાછા 0;
	પાછા a->lo < b->lo ? -1 : 1;
}

સ્થિર પૂર્ણાંક
ચાવી_id_cmp(સંરચના revoked_ચાવી_id *a, સંરચના revoked_ચાવી_id *b)
{
	પાછા strcmp(a->ચાવી_id, b->ચાવી_id);
}

સ્થિર પૂર્ણાંક
blob_cmp(સંરચના revoked_blob *a, સંરચના revoked_blob *b)
{
	પૂર્ણાંક r;

	જો (a->len != b->len) {
		જો ((r = memcmp(a->blob, b->blob, MINIMUM(a->len, b->len))) != 0)
			પાછા r;
		પાછા a->len > b->len ? 1 : -1;
	} નહીંતર
		પાછા memcmp(a->blob, b->blob, a->len);
}

સંરચના ssh_krl *
ssh_krl_init(શૂન્ય)
{
	સંરચના ssh_krl *krl;

	જો ((krl = calloc(1, કદ(*krl))) == ખાલી)
		પાછા ખાલી;
	RB_INIT(&krl->revoked_ચાવીઓ);
	RB_INIT(&krl->revoked_sha1s);
	RB_INIT(&krl->revoked_sha256s);
	TAILQ_INIT(&krl->revoked_certs);
	પાછા krl;
}

સ્થિર શૂન્ય
revoked_certs_free(સંરચના revoked_certs *rc)
{
	સંરચના revoked_serial *rs, *trs;
	સંરચના revoked_ચાવી_id *rki, *trki;

	જો (rc == ખાલી)
		પાછા;
	RB_FOREACH_SAFE(rs, revoked_serial_વૃક્ષ, &rc->revoked_serials, trs) {
		RB_REMOVE(revoked_serial_વૃક્ષ, &rc->revoked_serials, rs);
		મુક્ત(rs);
	}
	RB_FOREACH_SAFE(rki, revoked_ચાવી_id_વૃક્ષ, &rc->revoked_ચાવી_ids, trki) {
		RB_REMOVE(revoked_ચાવી_id_વૃક્ષ, &rc->revoked_ચાવી_ids, rki);
		મુક્ત(rki->ચાવી_id);
		મુક્ત(rki);
	}
	sshkey_free(rc->ca_ચાવી);
	freezero(rc, કદ(*rc));
}

શૂન્ય
ssh_krl_free(સંરચના ssh_krl *krl)
{
	સંરચના revoked_blob *rb, *trb;
	સંરચના revoked_certs *rc, *trc;

	જો (krl == ખાલી)
		પાછા;

	મુક્ત(krl->comment);
	RB_FOREACH_SAFE(rb, revoked_blob_વૃક્ષ, &krl->revoked_ચાવીઓ, trb) {
		RB_REMOVE(revoked_blob_વૃક્ષ, &krl->revoked_ચાવીઓ, rb);
		મુક્ત(rb->blob);
		મુક્ત(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_વૃક્ષ, &krl->revoked_sha1s, trb) {
		RB_REMOVE(revoked_blob_વૃક્ષ, &krl->revoked_sha1s, rb);
		મુક્ત(rb->blob);
		મુક્ત(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_વૃક્ષ, &krl->revoked_sha256s, trb) {
		RB_REMOVE(revoked_blob_વૃક્ષ, &krl->revoked_sha256s, rb);
		મુક્ત(rb->blob);
		મુક્ત(rb);
	}
	TAILQ_FOREACH_SAFE(rc, &krl->revoked_certs, entry, trc) {
		TAILQ_REMOVE(&krl->revoked_certs, rc, entry);
		revoked_certs_free(rc);
	}
	મુક્ત(krl);
}

શૂન્ય
ssh_krl_set_version(સંરચના ssh_krl *krl, uint64_t version)
{
	krl->krl_version = version;
}

પૂર્ણાંક
ssh_krl_set_comment(સંરચના ssh_krl *krl, અચલ અક્ષર *comment)
{
	મુક્ત(krl->comment);
	જો ((krl->comment = strdup(comment)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	પાછા 0;
}

/*
 * Find the revoked_certs struct for a CA key. If allow_create is set then
 * create a new one in the tree if one did not exist already.
 */
સ્થિર પૂર્ણાંક
revoked_certs_for_ca_ચાવી(સંરચના ssh_krl *krl, અચલ સંરચના sshkey *ca_ચાવી,
    સંરચના revoked_certs **rcp, પૂર્ણાંક allow_create)
{
	સંરચના revoked_certs *rc;
	પૂર્ણાંક r;

	*rcp = ખાલી;
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		જો ((ca_ચાવી == ખાલી && rc->ca_ચાવી == ખાલી) ||
		    sshkey_equal(rc->ca_ચાવી, ca_ચાવી)) {
			*rcp = rc;
			પાછા 0;
		}
	}
	જો (!allow_create)
		પાછા 0;
	/* If this CA doesn't exist in the list then add it now */
	જો ((rc = calloc(1, કદ(*rc))) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો (ca_ચાવી == ખાલી)
		rc->ca_ચાવી = ખાલી;
	નહીંતર જો ((r = sshkey_from_private(ca_ચાવી, &rc->ca_ચાવી)) != 0) {
		મુક્ત(rc);
		પાછા r;
	}
	RB_INIT(&rc->revoked_serials);
	RB_INIT(&rc->revoked_ચાવી_ids);
	TAILQ_INSERT_TAIL(&krl->revoked_certs, rc, entry);
	KRL_DBG(("new CA %s", ca_ચાવી == ખાલી ? "*" : sshkey_type(ca_ચાવી)));
	*rcp = rc;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
ઉમેરો_serial_range(સંરચના revoked_serial_વૃક્ષ *rt, uint64_t lo, uint64_t hi)
{
	સંરચના revoked_serial rs, *ers, *crs, *irs;

	KRL_DBG(("insert %llu:%llu",
	    (unsigned long long)lo, (unsigned long long)hi));
	memset(&rs, 0, કદ(rs));
	rs.lo = lo;
	rs.hi = hi;
	ers = RB_NFIND(revoked_serial_વૃક્ષ, rt, &rs);
	જો (ers == ખાલી || serial_cmp(ers, &rs) != 0) {
		/* No entry matches. Just insert */
		જો ((irs = malloc(કદ(rs))) == ખાલી)
			પાછા SSH_ERR_ALLOC_FAIL;
		memcpy(irs, &rs, કદ(*irs));
		ers = RB_ઉમેરો(revoked_serial_વૃક્ષ, rt, irs);
		જો (ers != ખાલી) {
			KRL_DBG(("bad: ers != NULL"));
			/* Shouldn't happen */
			મુક્ત(irs);
			પાછા SSH_ERR_INTERNAL_ERROR;
		}
		ers = irs;
	} નહીંતર {
		KRL_DBG(("overlap found %llu:%llu",
		    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
		/*
		 * The inserted entry overlaps an existing one. Grow the
		 * existing entry.
		 */
		જો (ers->lo > lo)
			ers->lo = lo;
		જો (ers->hi < hi)
			ers->hi = hi;
	}

	/*
	 * The inserted or revised range might overlap or abut adjacent ones;
	 * coalesce as necessary.
	 */

	/* Check predecessors */
	જ્યારે ((crs = RB_PREV(revoked_serial_વૃક્ષ, rt, ers)) != ખાલી) {
		KRL_DBG(("pred %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		જો (ers->lo != 0 && crs->hi < ers->lo - 1)
			તોડો;
		/* This entry overlaps. */
		જો (crs->lo < ers->lo) {
			ers->lo = crs->lo;
			KRL_DBG(("pred extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_વૃક્ષ, rt, crs);
		મુક્ત(crs);
	}
	/* Check successors */
	જ્યારે ((crs = RB_NEXT(revoked_serial_વૃક્ષ, rt, ers)) != ખાલી) {
		KRL_DBG(("succ %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		જો (ers->hi != (uint64_t)-1 && crs->lo > ers->hi + 1)
			તોડો;
		/* This entry overlaps. */
		જો (crs->hi > ers->hi) {
			ers->hi = crs->hi;
			KRL_DBG(("succ extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_વૃક્ષ, rt, crs);
		મુક્ત(crs);
	}
	KRL_DBG(("done, final %llu:%llu",
	    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
	પાછા 0;
}

પૂર્ણાંક
ssh_krl_revoke_cert_by_serial(સંરચના ssh_krl *krl, અચલ સંરચના sshkey *ca_ચાવી,
    uint64_t serial)
{
	પાછા ssh_krl_revoke_cert_by_serial_range(krl, ca_ચાવી, serial, serial);
}

પૂર્ણાંક
ssh_krl_revoke_cert_by_serial_range(સંરચના ssh_krl *krl,
    અચલ સંરચના sshkey *ca_ચાવી, uint64_t lo, uint64_t hi)
{
	સંરચના revoked_certs *rc;
	પૂર્ણાંક r;

	જો (lo > hi || lo == 0)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો ((r = revoked_certs_for_ca_ચાવી(krl, ca_ચાવી, &rc, 1)) != 0)
		પાછા r;
	પાછા ઉમેરો_serial_range(&rc->revoked_serials, lo, hi);
}

પૂર્ણાંક
ssh_krl_revoke_cert_by_ચાવી_id(સંરચના ssh_krl *krl, અચલ સંરચના sshkey *ca_ચાવી,
    અચલ અક્ષર *ચાવી_id)
{
	સંરચના revoked_ચાવી_id *rki, *erki;
	સંરચના revoked_certs *rc;
	પૂર્ણાંક r;

	જો ((r = revoked_certs_for_ca_ચાવી(krl, ca_ચાવી, &rc, 1)) != 0)
		પાછા r;

	KRL_DBG(("revoke %s", ચાવી_id));
	જો ((rki = calloc(1, કદ(*rki))) == ખાલી ||
	    (rki->ચાવી_id = strdup(ચાવી_id)) == ખાલી) {
		મુક્ત(rki);
		પાછા SSH_ERR_ALLOC_FAIL;
	}
	erki = RB_ઉમેરો(revoked_ચાવી_id_વૃક્ષ, &rc->revoked_ચાવી_ids, rki);
	જો (erki != ખાલી) {
		મુક્ત(rki->ચાવી_id);
		મુક્ત(rki);
	}
	પાછા 0;
}

/* Convert "key" to a public key blob without any certificate information */
સ્થિર પૂર્ણાંક
plain_ચાવી_blob(અચલ સંરચના sshkey *ચાવી, u_char **blob, size_t *blen)
{
	સંરચના sshkey *kcopy;
	પૂર્ણાંક r;

	જો ((r = sshkey_from_private(ચાવી, &kcopy)) != 0)
		પાછા r;
	જો (sshkey_is_cert(kcopy)) {
		જો ((r = sshkey_drop_cert(kcopy)) != 0) {
			sshkey_free(kcopy);
			પાછા r;
		}
	}
	r = sshkey_to_blob(kcopy, blob, blen);
	sshkey_free(kcopy);
	પાછા r;
}

/* Revoke a key blob. Ownership of blob is transferred to the tree */
સ્થિર પૂર્ણાંક
revoke_blob(સંરચના revoked_blob_વૃક્ષ *rbt, u_char *blob, size_t len)
{
	સંરચના revoked_blob *rb, *erb;

	જો ((rb = calloc(1, કદ(*rb))) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	rb->blob = blob;
	rb->len = len;
	erb = RB_ઉમેરો(revoked_blob_વૃક્ષ, rbt, rb);
	જો (erb != ખાલી) {
		મુક્ત(rb->blob);
		મુક્ત(rb);
	}
	પાછા 0;
}

પૂર્ણાંક
ssh_krl_revoke_ચાવી_explicit(સંરચના ssh_krl *krl, અચલ સંરચના sshkey *ચાવી)
{
	u_char *blob;
	size_t len;
	પૂર્ણાંક r;

	debug3_f("revoke type %s", sshkey_type(ચાવી));
	જો ((r = plain_ચાવી_blob(ચાવી, &blob, &len)) != 0)
		પાછા r;
	પાછા revoke_blob(&krl->revoked_ચાવીઓ, blob, len);
}

સ્થિર પૂર્ણાંક
revoke_by_hash(સંરચના revoked_blob_વૃક્ષ *target, અચલ u_char *p, size_t len)
{
	u_char *blob;
	પૂર્ણાંક r;

	/* need to copy hash, as revoke_blob steals ownership */
	જો ((blob = malloc(len)) == ખાલી)
		પાછા SSH_ERR_SYSTEM_ERROR;
	memcpy(blob, p, len);
	જો ((r = revoke_blob(target, blob, len)) != 0) {
		મુક્ત(blob);
		પાછા r;
	}
	પાછા 0;
}

પૂર્ણાંક
ssh_krl_revoke_ચાવી_sha1(સંરચના ssh_krl *krl, અચલ u_char *p, size_t len)
{
	debug3_f("revoke by sha1");
	જો (len != 20)
		પાછા SSH_ERR_INVALID_FORMAT;
	પાછા revoke_by_hash(&krl->revoked_sha1s, p, len);
}

પૂર્ણાંક
ssh_krl_revoke_ચાવી_sha256(સંરચના ssh_krl *krl, અચલ u_char *p, size_t len)
{
	debug3_f("revoke by sha256");
	જો (len != 32)
		પાછા SSH_ERR_INVALID_FORMAT;
	પાછા revoke_by_hash(&krl->revoked_sha256s, p, len);
}

પૂર્ણાંક
ssh_krl_revoke_ચાવી(સંરચના ssh_krl *krl, અચલ સંરચના sshkey *ચાવી)
{
	/* XXX replace with SHA256? */
	જો (!sshkey_is_cert(ચાવી))
		પાછા ssh_krl_revoke_ચાવી_explicit(krl, ચાવી);

	જો (ચાવી->cert->serial == 0) {
		પાછા ssh_krl_revoke_cert_by_ચાવી_id(krl,
		    ચાવી->cert->signature_ચાવી,
		    ચાવી->cert->ચાવી_id);
	} નહીંતર {
		પાછા ssh_krl_revoke_cert_by_serial(krl,
		    ચાવી->cert->signature_ચાવી,
		    ચાવી->cert->serial);
	}
}

/*
 * Select the most compact section type to emit next in a KRL based on
 * the current section type, the run length of contiguous revoked serial
 * numbers and the gaps from the last and to the next revoked serial.
 * Applies a mostly-accurate bit cost model to select the section type
 * that will minimise the size of the resultant KRL.
 */
સ્થિર પૂર્ણાંક
choose_next_state(પૂર્ણાંક current_state, uint64_t contig, પૂર્ણાંક final,
    uint64_t last_gap, uint64_t next_gap, size_t bitmap_len,
    પૂર્ણાંક *force_new_section)
{
	પૂર્ણાંક new_state;
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
	પસંદગી (current_state) {
	સ્થિતિ KRL_SECTION_CERT_SERIAL_LIST:
		cost_bitmap_restart = cost_bitmap = 8 + 64;
		તોડો;
	સ્થિતિ KRL_SECTION_CERT_SERIAL_BITMAP:
		cost_list = 8;
		cost_bitmap_restart = 8 + 64;
		તોડો;
	સ્થિતિ KRL_SECTION_CERT_SERIAL_RANGE:
	સ્થિતિ 0:
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
	જો (bitmap_len + cost_bitmap >= SSHBUF_MAX_BIGNUM) {
		KRL_DBG(("bitmap overfull len=%zu cost=%llu max=%u",
		    bitmap_len, (unsigned long long)cost_bitmap,
		    SSHBUF_MAX_BIGNUM));
		cost_bitmap = (uint64_t)-1;
	}

	/* Now pick the best choice */
	*force_new_section = 0;
	new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
	cost = cost_bitmap;
	જો (cost_range < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_RANGE;
		cost = cost_range;
	}
	જો (cost_list < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_LIST;
		cost = cost_list;
	}
	જો (cost_bitmap_restart < cost) {
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
	પાછા new_state;
}

સ્થિર પૂર્ણાંક
put_bitmap(સંરચના sshbuf *buf, સંરચના bitmap *bitmap)
{
	size_t len;
	u_char *blob;
	પૂર્ણાંક r;

	len = bitmap_nbytes(bitmap);
	જો ((blob = malloc(len)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો (bitmap_to_string(bitmap, blob, len) != 0) {
		મુક્ત(blob);
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	r = sshbuf_put_bignum2_bytes(buf, blob, len);
	મુક્ત(blob);
	પાછા r;
}

/* Generate a KRL_SECTION_CERTIFICATES KRL section */
સ્થિર પૂર્ણાંક
revoked_certs_generate(સંરચના revoked_certs *rc, સંરચના sshbuf *buf)
{
	પૂર્ણાંક final, force_new_sect, r = SSH_ERR_INTERNAL_ERROR;
	uint64_t i, contig, gap, last = 0, bitmap_start = 0;
	સંરચના revoked_serial *rs, *nrs;
	સંરચના revoked_ચાવી_id *rki;
	પૂર્ણાંક next_state, state = 0;
	size_t bitmap_len;
	સંરચના sshbuf *sect;
	સંરચના bitmap *bitmap = ખાલી;

	જો ((sect = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;

	/* Store the header: optional CA scope key, reserved */
	જો (rc->ca_ચાવી == ખાલી) {
		જો ((r = sshbuf_put_string(buf, ખાલી, 0)) != 0)
			જાઓ out;
	} નહીંતર {
		જો ((r = sshkey_puts(rc->ca_ચાવી, buf)) != 0)
			જાઓ out;
	}
	જો ((r = sshbuf_put_string(buf, ખાલી, 0)) != 0)
		જાઓ out;

	/* Store the revoked serials.  */
	માટે (rs = RB_MIN(revoked_serial_વૃક્ષ, &rc->revoked_serials);
	     rs != ખાલી;
	     rs = RB_NEXT(revoked_serial_વૃક્ષ, &rc->revoked_serials, rs)) {
		KRL_DBG(("serial %llu:%llu state 0x%02x",
		    (long long unsigned)rs->lo, (long long unsigned)rs->hi,
		    state));

		/* Check contiguous length and gap to next section (if any) */
		nrs = RB_NEXT(revoked_serial_વૃક્ષ, &rc->revoked_serials, rs);
		final = nrs == ખાલી;
		gap = nrs == ખાલી ? 0 : nrs->lo - rs->hi;
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
		જો (state != 0 && (force_new_sect || next_state != state ||
		    state == KRL_SECTION_CERT_SERIAL_RANGE)) {
			KRL_DBG(("finish state 0x%02x", state));
			પસંદગી (state) {
			સ્થિતિ KRL_SECTION_CERT_SERIAL_LIST:
			સ્થિતિ KRL_SECTION_CERT_SERIAL_RANGE:
				તોડો;
			સ્થિતિ KRL_SECTION_CERT_SERIAL_BITMAP:
				જો ((r = put_bitmap(sect, bitmap)) != 0)
					જાઓ out;
				bitmap_free(bitmap);
				bitmap = ખાલી;
				તોડો;
			}
			જો ((r = sshbuf_put_u8(buf, state)) != 0 ||
			    (r = sshbuf_put_stringb(buf, sect)) != 0)
				જાઓ out;
			sshbuf_reset(sect);
		}

		/* If we are starting a new section then prepare it now */
		જો (next_state != state || force_new_sect) {
			KRL_DBG(("start state 0x%02x",
			    next_state));
			state = next_state;
			sshbuf_reset(sect);
			પસંદગી (state) {
			સ્થિતિ KRL_SECTION_CERT_SERIAL_LIST:
			સ્થિતિ KRL_SECTION_CERT_SERIAL_RANGE:
				તોડો;
			સ્થિતિ KRL_SECTION_CERT_SERIAL_BITMAP:
				જો ((bitmap = bitmap_new()) == ખાલી) {
					r = SSH_ERR_ALLOC_FAIL;
					જાઓ out;
				}
				bitmap_start = rs->lo;
				જો ((r = sshbuf_put_u64(sect,
				    bitmap_start)) != 0)
					જાઓ out;
				તોડો;
			}
		}

		/* Perform section-specific processing */
		પસંદગી (state) {
		સ્થિતિ KRL_SECTION_CERT_SERIAL_LIST:
			માટે (i = 0; i < contig; i++) {
				જો ((r = sshbuf_put_u64(sect, rs->lo + i)) != 0)
					જાઓ out;
			}
			તોડો;
		સ્થિતિ KRL_SECTION_CERT_SERIAL_RANGE:
			જો ((r = sshbuf_put_u64(sect, rs->lo)) != 0 ||
			    (r = sshbuf_put_u64(sect, rs->hi)) != 0)
				જાઓ out;
			તોડો;
		સ્થિતિ KRL_SECTION_CERT_SERIAL_BITMAP:
			જો (rs->lo - bitmap_start > INT_MAX) {
				r = SSH_ERR_INVALID_FORMAT;
				error_f("insane bitmap gap");
				જાઓ out;
			}
			માટે (i = 0; i < contig; i++) {
				જો (bitmap_set_bit(bitmap,
				    rs->lo + i - bitmap_start) != 0) {
					r = SSH_ERR_ALLOC_FAIL;
					જાઓ out;
				}
			}
			તોડો;
		}
		last = rs->hi;
	}
	/* Flush the remaining section, if any */
	જો (state != 0) {
		KRL_DBG(("serial final flush for state 0x%02x", state));
		પસંદગી (state) {
		સ્થિતિ KRL_SECTION_CERT_SERIAL_LIST:
		સ્થિતિ KRL_SECTION_CERT_SERIAL_RANGE:
			તોડો;
		સ્થિતિ KRL_SECTION_CERT_SERIAL_BITMAP:
			જો ((r = put_bitmap(sect, bitmap)) != 0)
				જાઓ out;
			bitmap_free(bitmap);
			bitmap = ખાલી;
			તોડો;
		}
		જો ((r = sshbuf_put_u8(buf, state)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			જાઓ out;
	}
	KRL_DBG(("serial done "));

	/* Now output a section for any revocations by key ID */
	sshbuf_reset(sect);
	RB_FOREACH(rki, revoked_ચાવી_id_વૃક્ષ, &rc->revoked_ચાવી_ids) {
		KRL_DBG(("key ID %s", rki->ચાવી_id));
		જો ((r = sshbuf_put_cstring(sect, rki->ચાવી_id)) != 0)
			જાઓ out;
	}
	જો (sshbuf_len(sect) != 0) {
		જો ((r = sshbuf_put_u8(buf, KRL_SECTION_CERT_ચાવી_ID)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			જાઓ out;
	}
	r = 0;
 out:
	bitmap_free(bitmap);
	sshbuf_free(sect);
	પાછા r;
}

પૂર્ણાંક
ssh_krl_to_blob(સંરચના ssh_krl *krl, સંરચના sshbuf *buf)
{
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	સંરચના revoked_certs *rc;
	સંરચના revoked_blob *rb;
	સંરચના sshbuf *sect;
	u_char *sblob = ખાલી;

	જો (krl->generated_date == 0)
		krl->generated_date = time(ખાલી);

	જો ((sect = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;

	/* Store the header */
	જો ((r = sshbuf_put(buf, KRL_MAGIC, કદ(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_put_u32(buf, KRL_FORMAT_VERSION)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->krl_version)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->generated_date)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->flags)) != 0 ||
	    (r = sshbuf_put_string(buf, ખાલી, 0)) != 0 ||
	    (r = sshbuf_put_cstring(buf, krl->comment)) != 0)
		જાઓ out;

	/* Store sections for revoked certificates */
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		sshbuf_reset(sect);
		જો ((r = revoked_certs_generate(rc, sect)) != 0)
			જાઓ out;
		જો ((r = sshbuf_put_u8(buf, KRL_SECTION_CERTIFICATES)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			જાઓ out;
	}

	/* Finally, output sections for revocations by public key/hash */
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_વૃક્ષ, &krl->revoked_ચાવીઓ) {
		KRL_DBG(("key len %zu ", rb->len));
		જો ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			જાઓ out;
	}
	જો (sshbuf_len(sect) != 0) {
		જો ((r = sshbuf_put_u8(buf, KRL_SECTION_EXPLICIT_ચાવી)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			જાઓ out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_વૃક્ષ, &krl->revoked_sha1s) {
		KRL_DBG(("hash len %zu ", rb->len));
		જો ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			જાઓ out;
	}
	જો (sshbuf_len(sect) != 0) {
		જો ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA1)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			જાઓ out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_વૃક્ષ, &krl->revoked_sha256s) {
		KRL_DBG(("hash len %zu ", rb->len));
		જો ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			જાઓ out;
	}
	જો (sshbuf_len(sect) != 0) {
		જો ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA256)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			જાઓ out;
	}
	/* success */
	r = 0;
 out:
	મુક્ત(sblob);
	sshbuf_free(sect);
	પાછા r;
}

સ્થિર શૂન્ય
format_timestamp(uint64_t timestamp, અક્ષર *ts, size_t nts)
{
	time_t t;
	સંરચના tm *tm;

	t = timestamp;
	tm = localtime(&t);
	જો (tm == ખાલી)
		strlcpy(ts, "<INVALID>", nts);
	નહીંતર {
		*ts = '\0';
		strftime(ts, nts, "%Y%m%dT%H%M%S", tm);
	}
}

સ્થિર પૂર્ણાંક
cert_extension_subsection(સંરચના sshbuf *subsect, સંરચના ssh_krl *krl)
{
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	સંરચના sshbuf *કિંમત = ખાલી;
	અક્ષર *name = ખાલી;

	જો ((r = sshbuf_get_cstring(subsect, &name, ખાલી)) != 0 ||
	    (r = sshbuf_get_u8(subsect, &critical)) != 0 ||
	    (r = sshbuf_froms(subsect, &કિંમત)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid certificate extension subsection");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (sshbuf_len(subsect) != 0) {
		error("KRL has invalid certificate extension subsection: "
		    "trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	debug_f("cert extension %s critical %u len %zu",
	    name, critical, sshbuf_len(કિંમત));
	/* no extensions are currently supported */
	જો (critical) {
		error("KRL contains unsupported critical certificate "
		    "subsection \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		જાઓ out;
	}
	/* success */
	r = 0;
 out:
	મુક્ત(name);
	sshbuf_free(કિંમત);
	પાછા r;
}

સ્થિર પૂર્ણાંક
parse_revoked_certs(સંરચના sshbuf *buf, સંરચના ssh_krl *krl)
{
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	અચલ u_char *blob;
	size_t blen, nbits;
	સંરચના sshbuf *subsect = ખાલી;
	uint64_t serial, serial_lo, serial_hi;
	સંરચના bitmap *bitmap = ખાલી;
	અક્ષર *ચાવી_id = ખાલી;
	સંરચના sshkey *ca_ચાવી = ખાલી;

	જો ((subsect = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;

	/* Header: key, reserved */
	જો ((r = sshbuf_get_string_direct(buf, &blob, &blen)) != 0 ||
	    (r = sshbuf_skip_string(buf)) != 0)
		જાઓ out;
	જો (blen != 0 && (r = sshkey_from_blob(blob, blen, &ca_ચાવી)) != 0)
		જાઓ out;

	જ્યારે (sshbuf_len(buf) > 0) {
		sshbuf_free(subsect);
		subsect = ખાલી;
		જો ((r = sshbuf_get_u8(buf, &type)) != 0 ||
		    (r = sshbuf_froms(buf, &subsect)) != 0)
			જાઓ out;
		KRL_DBG(("subsection type 0x%02x", type));
		/* sshbuf_dump(subsect, stderr); */

		પસંદગી (type) {
		સ્થિતિ KRL_SECTION_CERT_SERIAL_LIST:
			જ્યારે (sshbuf_len(subsect) > 0) {
				જો ((r = sshbuf_get_u64(subsect, &serial)) != 0)
					જાઓ out;
				જો ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_ચાવી, serial)) != 0)
					જાઓ out;
			}
			તોડો;
		સ્થિતિ KRL_SECTION_CERT_SERIAL_RANGE:
			જો ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_u64(subsect, &serial_hi)) != 0)
				જાઓ out;
			જો ((r = ssh_krl_revoke_cert_by_serial_range(krl,
			    ca_ચાવી, serial_lo, serial_hi)) != 0)
				જાઓ out;
			તોડો;
		સ્થિતિ KRL_SECTION_CERT_SERIAL_BITMAP:
			જો ((bitmap = bitmap_new()) == ખાલી) {
				r = SSH_ERR_ALLOC_FAIL;
				જાઓ out;
			}
			જો ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_bignum2_bytes_direct(subsect,
			    &blob, &blen)) != 0)
				જાઓ out;
			જો (bitmap_from_string(bitmap, blob, blen) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				જાઓ out;
			}
			nbits = bitmap_nbits(bitmap);
			માટે (serial = 0; serial < (uint64_t)nbits; serial++) {
				જો (serial > 0 && serial_lo + serial == 0) {
					error_f("bitmap wraps u64");
					r = SSH_ERR_INVALID_FORMAT;
					જાઓ out;
				}
				જો (!bitmap_test_bit(bitmap, serial))
					ચાલુ;
				જો ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_ચાવી, serial_lo + serial)) != 0)
					જાઓ out;
			}
			bitmap_free(bitmap);
			bitmap = ખાલી;
			તોડો;
		સ્થિતિ KRL_SECTION_CERT_ચાવી_ID:
			જ્યારે (sshbuf_len(subsect) > 0) {
				જો ((r = sshbuf_get_cstring(subsect,
				    &ચાવી_id, ખાલી)) != 0)
					જાઓ out;
				જો ((r = ssh_krl_revoke_cert_by_ચાવી_id(krl,
				    ca_ચાવી, ચાવી_id)) != 0)
					જાઓ out;
				મુક્ત(ચાવી_id);
				ચાવી_id = ખાલી;
			}
			તોડો;
		સ્થિતિ KRL_SECTION_CERT_EXTENSION:
			જો ((r = cert_extension_subsection(subsect, krl)) != 0)
				જાઓ out;
			તોડો;
		મૂળભૂત:
			error("Unsupported KRL certificate section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
		જો (sshbuf_len(subsect) > 0) {
			error("KRL certificate section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
	}

	r = 0;
 out:
	જો (bitmap != ખાલી)
		bitmap_free(bitmap);
	મુક્ત(ચાવી_id);
	sshkey_free(ca_ચાવી);
	sshbuf_free(subsect);
	પાછા r;
}

સ્થિર પૂર્ણાંક
blob_section(સંરચના sshbuf *sect, સંરચના revoked_blob_વૃક્ષ *target_વૃક્ષ,
    size_t expected_len)
{
	u_char *rdata = ખાલી;
	size_t rlen = 0;
	પૂર્ણાંક r;

	જ્યારે (sshbuf_len(sect) > 0) {
		જો ((r = sshbuf_get_string(sect, &rdata, &rlen)) != 0)
			પાછા r;
		જો (expected_len != 0 && rlen != expected_len) {
			error_f("bad length");
			મુક્ત(rdata);
			પાછા SSH_ERR_INVALID_FORMAT;
		}
		જો ((r = revoke_blob(target_વૃક્ષ, rdata, rlen)) != 0) {
			મુક્ત(rdata);
			પાછા r;
		}
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
extension_section(સંરચના sshbuf *sect, સંરચના ssh_krl *krl)
{
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	સંરચના sshbuf *કિંમત = ખાલી;
	અક્ષર *name = ખાલી;

	જો ((r = sshbuf_get_cstring(sect, &name, ખાલી)) != 0 ||
	    (r = sshbuf_get_u8(sect, &critical)) != 0 ||
	    (r = sshbuf_froms(sect, &કિંમત)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid extension section");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (sshbuf_len(sect) != 0) {
		error("KRL has invalid extension section: trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	debug_f("extension %s critical %u len %zu",
	    name, critical, sshbuf_len(કિંમત));
	/* no extensions are currently supported */
	જો (critical) {
		error("KRL contains unsupported critical section \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		જાઓ out;
	}
	/* success */
	r = 0;
 out:
	મુક્ત(name);
	sshbuf_free(કિંમત);
	પાછા r;
}

/* Attempt to parse a KRL */
પૂર્ણાંક
ssh_krl_from_blob(સંરચના sshbuf *buf, સંરચના ssh_krl **krlp)
{
	સંરચના sshbuf *copy = ખાલી, *sect = ખાલી;
	સંરચના ssh_krl *krl = ખાલી;
	અક્ષર timestamp[64];
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	u_int format_version;

	*krlp = ખાલી;

	/* KRL must begin with magic string */
	જો ((r = sshbuf_cmp(buf, 0, KRL_MAGIC, કદ(KRL_MAGIC) - 1)) != 0) {
		debug2_f("bad KRL magic header");
		પાછા SSH_ERR_KRL_BAD_MAGIC;
	}

	જો ((krl = ssh_krl_init()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		error_f("alloc failed");
		જાઓ out;
	}
	/* Don't modify buffer */
	જો ((copy = sshbuf_fromb(buf)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshbuf_consume(copy, કદ(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_get_u32(copy, &format_version)) != 0)
		જાઓ out;
	જો (format_version != KRL_FORMAT_VERSION) {
		error_f("unsupported KRL format version %u", format_version);
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો ((r = sshbuf_get_u64(copy, &krl->krl_version)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->generated_date)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->flags)) != 0 ||
	    (r = sshbuf_skip_string(copy)) != 0 ||
	    (r = sshbuf_get_cstring(copy, &krl->comment, ખાલી)) != 0) {
		error_fr(r, "parse KRL header");
		જાઓ out;
	}
	format_timestamp(krl->generated_date, timestamp, કદ(timestamp));
	debug("KRL version %llu generated at %s%s%s",
	    (long long unsigned)krl->krl_version, timestamp,
	    *krl->comment ? ": " : "", krl->comment);

	/* Parse and load the KRL sections. */
	જ્યારે (sshbuf_len(copy) > 0) {
		sshbuf_free(sect);
		sect = ખાલી;
		જો ((r = sshbuf_get_u8(copy, &type)) != 0 ||
		    (r = sshbuf_froms(copy, &sect)) != 0)
			જાઓ out;
		KRL_DBG(("section 0x%02x", type));

		પસંદગી (type) {
		સ્થિતિ KRL_SECTION_CERTIFICATES:
			જો ((r = parse_revoked_certs(sect, krl)) != 0)
				જાઓ out;
			તોડો;
		સ્થિતિ KRL_SECTION_EXPLICIT_ચાવી:
			જો ((r = blob_section(sect,
			    &krl->revoked_ચાવીઓ, 0)) != 0)
				જાઓ out;
			તોડો;
		સ્થિતિ KRL_SECTION_FINGERPRINT_SHA1:
			જો ((r = blob_section(sect,
			    &krl->revoked_sha1s, 20)) != 0)
				જાઓ out;
			તોડો;
		સ્થિતિ KRL_SECTION_FINGERPRINT_SHA256:
			જો ((r = blob_section(sect,
			    &krl->revoked_sha256s, 32)) != 0)
				જાઓ out;
			તોડો;
		સ્થિતિ KRL_SECTION_EXTENSION:
			જો ((r = extension_section(sect, krl)) != 0)
				જાઓ out;
			તોડો;
		સ્થિતિ KRL_SECTION_SIGNATURE:
			/* Handled above, but still need to stay in synch */
			sshbuf_free(sect);
			sect = ખાલી;
			જો ((r = sshbuf_skip_string(copy)) != 0)
				જાઓ out;
			તોડો;
		મૂળભૂત:
			error("Unsupported KRL section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
		જો (sect != ખાલી && sshbuf_len(sect) > 0) {
			error("KRL section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
	}

	/* Success */
	*krlp = krl;
	r = 0;
 out:
	જો (r != 0)
		ssh_krl_free(krl);
	sshbuf_free(copy);
	sshbuf_free(sect);
	પાછા r;
}

/* Checks certificate serial number and key ID revocation */
સ્થિર પૂર્ણાંક
is_cert_revoked(અચલ સંરચના sshkey *ચાવી, સંરચના revoked_certs *rc)
{
	સંરચના revoked_serial rs, *ers;
	સંરચના revoked_ચાવી_id rki, *erki;

	/* Check revocation by cert key ID */
	memset(&rki, 0, કદ(rki));
	rki.ચાવી_id = ચાવી->cert->ચાવી_id;
	erki = RB_FIND(revoked_ચાવી_id_વૃક્ષ, &rc->revoked_ચાવી_ids, &rki);
	જો (erki != ખાલી) {
		KRL_DBG(("revoked by key ID"));
		પાછા SSH_ERR_ચાવી_REVOKED;
	}

	/*
	 * Zero serials numbers are ignored (it's the default when the
	 * CA doesn't specify one).
	 */
	જો (ચાવી->cert->serial == 0)
		પાછા 0;

	memset(&rs, 0, કદ(rs));
	rs.lo = rs.hi = ચાવી->cert->serial;
	ers = RB_FIND(revoked_serial_વૃક્ષ, &rc->revoked_serials, &rs);
	જો (ers != ખાલી) {
		KRL_DBG(("revoked serial %llu matched %llu:%llu",
		    (unsigned long long)ચાવી->cert->serial,
		    (unsigned long long)ers->lo,
		    (unsigned long long)ers->hi));
		પાછા SSH_ERR_ચાવી_REVOKED;
	}
	પાછા 0;
}

/* Checks whether a given key/cert is revoked. Does not check its CA */
સ્થિર પૂર્ણાંક
is_ચાવી_revoked(સંરચના ssh_krl *krl, અચલ સંરચના sshkey *ચાવી)
{
	સંરચના revoked_blob rb, *erb;
	સંરચના revoked_certs *rc;
	પૂર્ણાંક r;

	/* Check explicitly revoked hashes first */
	memset(&rb, 0, કદ(rb));
	જો ((r = sshkey_fingerprint_raw(ચાવી, SSH_DIGEST_SHA1,
	    &rb.blob, &rb.len)) != 0)
		પાછા r;
	erb = RB_FIND(revoked_blob_વૃક્ષ, &krl->revoked_sha1s, &rb);
	મુક્ત(rb.blob);
	જો (erb != ખાલી) {
		KRL_DBG(("revoked by key SHA1"));
		પાછા SSH_ERR_ચાવી_REVOKED;
	}
	memset(&rb, 0, કદ(rb));
	જો ((r = sshkey_fingerprint_raw(ચાવી, SSH_DIGEST_SHA256,
	    &rb.blob, &rb.len)) != 0)
		પાછા r;
	erb = RB_FIND(revoked_blob_વૃક્ષ, &krl->revoked_sha256s, &rb);
	મુક્ત(rb.blob);
	જો (erb != ખાલી) {
		KRL_DBG(("revoked by key SHA256"));
		પાછા SSH_ERR_ચાવી_REVOKED;
	}

	/* Next, explicit keys */
	memset(&rb, 0, કદ(rb));
	જો ((r = plain_ચાવી_blob(ચાવી, &rb.blob, &rb.len)) != 0)
		પાછા r;
	erb = RB_FIND(revoked_blob_વૃક્ષ, &krl->revoked_ચાવીઓ, &rb);
	મુક્ત(rb.blob);
	જો (erb != ખાલી) {
		KRL_DBG(("revoked by explicit key"));
		પાછા SSH_ERR_ચાવી_REVOKED;
	}

	જો (!sshkey_is_cert(ચાવી))
		પાછા 0;

	/* Check cert revocation for the specified CA */
	જો ((r = revoked_certs_for_ca_ચાવી(krl, ચાવી->cert->signature_ચાવી,
	    &rc, 0)) != 0)
		પાછા r;
	જો (rc != ખાલી) {
		જો ((r = is_cert_revoked(ચાવી, rc)) != 0)
			પાછા r;
	}
	/* Check cert revocation for the wildcard CA */
	જો ((r = revoked_certs_for_ca_ચાવી(krl, ખાલી, &rc, 0)) != 0)
		પાછા r;
	જો (rc != ખાલી) {
		જો ((r = is_cert_revoked(ચાવી, rc)) != 0)
			પાછા r;
	}

	KRL_DBG(("%llu no match", (unsigned long long)ચાવી->cert->serial));
	પાછા 0;
}

પૂર્ણાંક
ssh_krl_check_ચાવી(સંરચના ssh_krl *krl, અચલ સંરચના sshkey *ચાવી)
{
	પૂર્ણાંક r;

	KRL_DBG(("checking key"));
	જો ((r = is_ચાવી_revoked(krl, ચાવી)) != 0)
		પાછા r;
	જો (sshkey_is_cert(ચાવી)) {
		debug2_f("checking CA key");
		જો ((r = is_ચાવી_revoked(krl, ચાવી->cert->signature_ચાવી)) != 0)
			પાછા r;
	}
	KRL_DBG(("key okay"));
	પાછા 0;
}

પૂર્ણાંક
ssh_krl_file_contains_ચાવી(અચલ અક્ષર *path, અચલ સંરચના sshkey *ચાવી)
{
	સંરચના sshbuf *krlbuf = ખાલી;
	સંરચના ssh_krl *krl = ખાલી;
	પૂર્ણાંક oerrno = 0, r;

	જો (path == ખાલી)
		પાછા 0;
	જો ((r = sshbuf_load_file(path, &krlbuf)) != 0) {
		oerrno = errno;
		જાઓ out;
	}
	જો ((r = ssh_krl_from_blob(krlbuf, &krl)) != 0)
		જાઓ out;
	debug2_f("checking KRL %s", path);
	r = ssh_krl_check_ચાવી(krl, ચાવી);
 out:
	sshbuf_free(krlbuf);
	ssh_krl_free(krl);
	જો (r != 0)
		errno = oerrno;
	પાછા r;
}

પૂર્ણાંક
krl_dump(સંરચના ssh_krl *krl, FILE *f)
{
	સંરચના sshkey *ચાવી = ખાલી;
	સંરચના revoked_blob *rb;
	સંરચના revoked_certs *rc;
	સંરચના revoked_serial *rs;
	સંરચના revoked_ચાવી_id *rki;
	પૂર્ણાંક r, ret = 0;
	અક્ષર *fp, timestamp[64];

	/* Try to print in a KRL spec-compatible format */
	format_timestamp(krl->generated_date, timestamp, કદ(timestamp));
	fprintf(f, "# KRL version %llu\n", (unsigned long long)krl->krl_version);
	fprintf(f, "# Generated at %s\n", timestamp);
	જો (krl->comment != ખાલી && *krl->comment != '\0') {
		r = INT_MAX;
		asmprintf(&fp, INT_MAX, &r, "%s", krl->comment);
		fprintf(f, "# Comment: %s\n", fp);
		મુક્ત(fp);
	}
	fputc('\n', f);

	RB_FOREACH(rb, revoked_blob_વૃક્ષ, &krl->revoked_ચાવીઓ) {
		જો ((r = sshkey_from_blob(rb->blob, rb->len, &ચાવી)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			error_r(r, "parse KRL key");
			ચાલુ;
		}
		જો ((fp = sshkey_fingerprint(ચાવી, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ખાલી) {
			ret = SSH_ERR_INVALID_FORMAT;
			error("sshkey_fingerprint failed");
			ચાલુ;
		}
		fprintf(f, "hash: %s # %s\n", fp, sshkey_ssh_name(ચાવી));
		મુક્ત(fp);
		મુક્ત(ચાવી);
	}
	RB_FOREACH(rb, revoked_blob_વૃક્ષ, &krl->revoked_sha256s) {
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "hash: SHA256:%s\n", fp);
		મુક્ત(fp);
	}
	RB_FOREACH(rb, revoked_blob_વૃક્ષ, &krl->revoked_sha1s) {
		/*
		 * There is not KRL spec keyword for raw SHA1 hashes, so
		 * print them as comments.
		 */
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "# hash SHA1:%s\n", fp);
		મુક્ત(fp);
	}

	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		fputc('\n', f);
		જો (rc->ca_ચાવી == ખાલી)
			fprintf(f, "# Wildcard CA\n");
		નહીંતર {
			જો ((fp = sshkey_fingerprint(rc->ca_ચાવી,
			    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ખાલી) {
				ret = SSH_ERR_INVALID_FORMAT;
				error("sshkey_fingerprint failed");
				ચાલુ;
			}
			fprintf(f, "# CA key %s %s\n",
			    sshkey_ssh_name(rc->ca_ચાવી), fp);
			મુક્ત(fp);
		}
		RB_FOREACH(rs, revoked_serial_વૃક્ષ, &rc->revoked_serials) {
			જો (rs->lo == rs->hi) {
				fprintf(f, "serial: %llu\n",
				    (unsigned long long)rs->lo);
			} નહીંતર {
				fprintf(f, "serial: %llu-%llu\n",
				    (unsigned long long)rs->lo,
				    (unsigned long long)rs->hi);
			}
		}
		RB_FOREACH(rki, revoked_ચાવી_id_વૃક્ષ, &rc->revoked_ચાવી_ids) {
			/*
			 * We don't want key IDs with embedded newlines to
			 * mess up the display.
			 */
			r = INT_MAX;
			asmprintf(&fp, INT_MAX, &r, "%s", rki->ચાવી_id);
			fprintf(f, "id: %s\n", fp);
			મુક્ત(fp);
		}
	}
	પાછા ret;
}
