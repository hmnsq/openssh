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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/tree.h>
#അന്തര്ഭാവ <sys/queue.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <time.h>

#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "bitmap.h"
#അന്തര്ഭാവ "utf8.h"

#അന്തര്ഭാവ "krl.h"

/* #define DEBUG_KRL */
#ifdef DEBUG_KRL
# define KRL_DBG(x) debug3_f x
#അല്ലെങ്കിൽ
# define KRL_DBG(x)
#endif

/*
 * Trees of revoked serial numbers, key IDs and keys. This allows
 * quick searching, querying and producing lists in canonical order.
 */

/* Tree of serial numbers. XXX make smarter: really need a real sparse bitmap */
ഘടന revoked_serial {
	uint64_t lo, hi;
	RB_ENTRY(revoked_serial) വൃക്ഷം_entry;
};
സ്ഥിതം പൂർണ്ണസംഖ്യ serial_cmp(ഘടന revoked_serial *a, ഘടന revoked_serial *b);
RB_HEAD(revoked_serial_വൃക്ഷം, revoked_serial);
RB_GENERATE_STATIC(revoked_serial_വൃക്ഷം, revoked_serial, വൃക്ഷം_entry, serial_cmp)

/* Tree of key IDs */
ഘടന revoked_താക്കോൽ_id {
	അക്ഷരം *താക്കോൽ_id;
	RB_ENTRY(revoked_താക്കോൽ_id) വൃക്ഷം_entry;
};
സ്ഥിതം പൂർണ്ണസംഖ്യ താക്കോൽ_id_cmp(ഘടന revoked_താക്കോൽ_id *a, ഘടന revoked_താക്കോൽ_id *b);
RB_HEAD(revoked_താക്കോൽ_id_വൃക്ഷം, revoked_താക്കോൽ_id);
RB_GENERATE_STATIC(revoked_താക്കോൽ_id_വൃക്ഷം, revoked_താക്കോൽ_id, വൃക്ഷം_entry, താക്കോൽ_id_cmp)

/* Tree of blobs (used for keys and fingerprints) */
ഘടന revoked_blob {
	u_char *blob;
	size_t len;
	RB_ENTRY(revoked_blob) വൃക്ഷം_entry;
};
സ്ഥിതം പൂർണ്ണസംഖ്യ blob_cmp(ഘടന revoked_blob *a, ഘടന revoked_blob *b);
RB_HEAD(revoked_blob_വൃക്ഷം, revoked_blob);
RB_GENERATE_STATIC(revoked_blob_വൃക്ഷം, revoked_blob, വൃക്ഷം_entry, blob_cmp)

/* Tracks revoked certs for a single CA */
ഘടന revoked_certs {
	ഘടന sshkey *ca_താക്കോൽ;
	ഘടന revoked_serial_വൃക്ഷം revoked_serials;
	ഘടന revoked_താക്കോൽ_id_വൃക്ഷം revoked_താക്കോൽ_ids;
	TAILQ_ENTRY(revoked_certs) entry;
};
TAILQ_HEAD(revoked_certs_list, revoked_certs);

ഘടന ssh_krl {
	uint64_t krl_version;
	uint64_t generated_date;
	uint64_t flags;
	അക്ഷരം *comment;
	ഘടന revoked_blob_വൃക്ഷം revoked_താക്കോലുകൾ;
	ഘടന revoked_blob_വൃക്ഷം revoked_sha1s;
	ഘടന revoked_blob_വൃക്ഷം revoked_sha256s;
	ഘടന revoked_certs_list revoked_certs;
};

/* Return equal if a and b overlap */
സ്ഥിതം പൂർണ്ണസംഖ്യ
serial_cmp(ഘടന revoked_serial *a, ഘടന revoked_serial *b)
{
	എങ്കിൽ (a->hi >= b->lo && a->lo <= b->hi)
		തിരികെ 0;
	തിരികെ a->lo < b->lo ? -1 : 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
താക്കോൽ_id_cmp(ഘടന revoked_താക്കോൽ_id *a, ഘടന revoked_താക്കോൽ_id *b)
{
	തിരികെ strcmp(a->താക്കോൽ_id, b->താക്കോൽ_id);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
blob_cmp(ഘടന revoked_blob *a, ഘടന revoked_blob *b)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (a->len != b->len) {
		എങ്കിൽ ((r = memcmp(a->blob, b->blob, MINIMUM(a->len, b->len))) != 0)
			തിരികെ r;
		തിരികെ a->len > b->len ? 1 : -1;
	} അല്ലെങ്കിൽ
		തിരികെ memcmp(a->blob, b->blob, a->len);
}

ഘടന ssh_krl *
ssh_krl_init(ശൂന്യം)
{
	ഘടന ssh_krl *krl;

	എങ്കിൽ ((krl = calloc(1, വലുപ്പം(*krl))) == ശൂന്യ)
		തിരികെ ശൂന്യ;
	RB_INIT(&krl->revoked_താക്കോലുകൾ);
	RB_INIT(&krl->revoked_sha1s);
	RB_INIT(&krl->revoked_sha256s);
	TAILQ_INIT(&krl->revoked_certs);
	തിരികെ krl;
}

സ്ഥിതം ശൂന്യം
revoked_certs_free(ഘടന revoked_certs *rc)
{
	ഘടന revoked_serial *rs, *trs;
	ഘടന revoked_താക്കോൽ_id *rki, *trki;

	എങ്കിൽ (rc == ശൂന്യ)
		തിരികെ;
	RB_FOREACH_SAFE(rs, revoked_serial_വൃക്ഷം, &rc->revoked_serials, trs) {
		RB_REMOVE(revoked_serial_വൃക്ഷം, &rc->revoked_serials, rs);
		സ്വതന്ത്രം(rs);
	}
	RB_FOREACH_SAFE(rki, revoked_താക്കോൽ_id_വൃക്ഷം, &rc->revoked_താക്കോൽ_ids, trki) {
		RB_REMOVE(revoked_താക്കോൽ_id_വൃക്ഷം, &rc->revoked_താക്കോൽ_ids, rki);
		സ്വതന്ത്രം(rki->താക്കോൽ_id);
		സ്വതന്ത്രം(rki);
	}
	sshkey_free(rc->ca_താക്കോൽ);
	freezero(rc, വലുപ്പം(*rc));
}

ശൂന്യം
ssh_krl_free(ഘടന ssh_krl *krl)
{
	ഘടന revoked_blob *rb, *trb;
	ഘടന revoked_certs *rc, *trc;

	എങ്കിൽ (krl == ശൂന്യ)
		തിരികെ;

	സ്വതന്ത്രം(krl->comment);
	RB_FOREACH_SAFE(rb, revoked_blob_വൃക്ഷം, &krl->revoked_താക്കോലുകൾ, trb) {
		RB_REMOVE(revoked_blob_വൃക്ഷം, &krl->revoked_താക്കോലുകൾ, rb);
		സ്വതന്ത്രം(rb->blob);
		സ്വതന്ത്രം(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_വൃക്ഷം, &krl->revoked_sha1s, trb) {
		RB_REMOVE(revoked_blob_വൃക്ഷം, &krl->revoked_sha1s, rb);
		സ്വതന്ത്രം(rb->blob);
		സ്വതന്ത്രം(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_വൃക്ഷം, &krl->revoked_sha256s, trb) {
		RB_REMOVE(revoked_blob_വൃക്ഷം, &krl->revoked_sha256s, rb);
		സ്വതന്ത്രം(rb->blob);
		സ്വതന്ത്രം(rb);
	}
	TAILQ_FOREACH_SAFE(rc, &krl->revoked_certs, entry, trc) {
		TAILQ_REMOVE(&krl->revoked_certs, rc, entry);
		revoked_certs_free(rc);
	}
	സ്വതന്ത്രം(krl);
}

ശൂന്യം
ssh_krl_set_version(ഘടന ssh_krl *krl, uint64_t version)
{
	krl->krl_version = version;
}

പൂർണ്ണസംഖ്യ
ssh_krl_set_comment(ഘടന ssh_krl *krl, സ്ഥിരം അക്ഷരം *comment)
{
	സ്വതന്ത്രം(krl->comment);
	എങ്കിൽ ((krl->comment = strdup(comment)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	തിരികെ 0;
}

/*
 * Find the revoked_certs struct for a CA key. If allow_create is set then
 * create a new one in the tree if one did not exist already.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
revoked_certs_for_ca_താക്കോൽ(ഘടന ssh_krl *krl, സ്ഥിരം ഘടന sshkey *ca_താക്കോൽ,
    ഘടന revoked_certs **rcp, പൂർണ്ണസംഖ്യ allow_create)
{
	ഘടന revoked_certs *rc;
	പൂർണ്ണസംഖ്യ r;

	*rcp = ശൂന്യ;
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		എങ്കിൽ ((ca_താക്കോൽ == ശൂന്യ && rc->ca_താക്കോൽ == ശൂന്യ) ||
		    sshkey_equal(rc->ca_താക്കോൽ, ca_താക്കോൽ)) {
			*rcp = rc;
			തിരികെ 0;
		}
	}
	എങ്കിൽ (!allow_create)
		തിരികെ 0;
	/* If this CA doesn't exist in the list then add it now */
	എങ്കിൽ ((rc = calloc(1, വലുപ്പം(*rc))) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ (ca_താക്കോൽ == ശൂന്യ)
		rc->ca_താക്കോൽ = ശൂന്യ;
	അല്ലെങ്കിൽ എങ്കിൽ ((r = sshkey_from_private(ca_താക്കോൽ, &rc->ca_താക്കോൽ)) != 0) {
		സ്വതന്ത്രം(rc);
		തിരികെ r;
	}
	RB_INIT(&rc->revoked_serials);
	RB_INIT(&rc->revoked_താക്കോൽ_ids);
	TAILQ_INSERT_TAIL(&krl->revoked_certs, rc, entry);
	KRL_DBG(("new CA %s", ca_താക്കോൽ == ശൂന്യ ? "*" : sshkey_type(ca_താക്കോൽ)));
	*rcp = rc;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
തിരുകുക_serial_range(ഘടന revoked_serial_വൃക്ഷം *rt, uint64_t lo, uint64_t hi)
{
	ഘടന revoked_serial rs, *ers, *crs, *irs;

	KRL_DBG(("insert %llu:%llu",
	    (unsigned long long)lo, (unsigned long long)hi));
	memset(&rs, 0, വലുപ്പം(rs));
	rs.lo = lo;
	rs.hi = hi;
	ers = RB_NFIND(revoked_serial_വൃക്ഷം, rt, &rs);
	എങ്കിൽ (ers == ശൂന്യ || serial_cmp(ers, &rs) != 0) {
		/* No entry matches. Just insert */
		എങ്കിൽ ((irs = malloc(വലുപ്പം(rs))) == ശൂന്യ)
			തിരികെ SSH_ERR_ALLOC_FAIL;
		memcpy(irs, &rs, വലുപ്പം(*irs));
		ers = RB_തിരുകുക(revoked_serial_വൃക്ഷം, rt, irs);
		എങ്കിൽ (ers != ശൂന്യ) {
			KRL_DBG(("bad: ers != NULL"));
			/* Shouldn't happen */
			സ്വതന്ത്രം(irs);
			തിരികെ SSH_ERR_INTERNAL_ERROR;
		}
		ers = irs;
	} അല്ലെങ്കിൽ {
		KRL_DBG(("overlap found %llu:%llu",
		    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
		/*
		 * The inserted entry overlaps an existing one. Grow the
		 * existing entry.
		 */
		എങ്കിൽ (ers->lo > lo)
			ers->lo = lo;
		എങ്കിൽ (ers->hi < hi)
			ers->hi = hi;
	}

	/*
	 * The inserted or revised range might overlap or abut adjacent ones;
	 * coalesce as necessary.
	 */

	/* Check predecessors */
	ആകുമ്പോൾ ((crs = RB_PREV(revoked_serial_വൃക്ഷം, rt, ers)) != ശൂന്യ) {
		KRL_DBG(("pred %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		എങ്കിൽ (ers->lo != 0 && crs->hi < ers->lo - 1)
			നിർത്തുക;
		/* This entry overlaps. */
		എങ്കിൽ (crs->lo < ers->lo) {
			ers->lo = crs->lo;
			KRL_DBG(("pred extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_വൃക്ഷം, rt, crs);
		സ്വതന്ത്രം(crs);
	}
	/* Check successors */
	ആകുമ്പോൾ ((crs = RB_NEXT(revoked_serial_വൃക്ഷം, rt, ers)) != ശൂന്യ) {
		KRL_DBG(("succ %llu:%llu",
		    (unsigned long long)crs->lo, (unsigned long long)crs->hi));
		എങ്കിൽ (ers->hi != (uint64_t)-1 && crs->lo > ers->hi + 1)
			നിർത്തുക;
		/* This entry overlaps. */
		എങ്കിൽ (crs->hi > ers->hi) {
			ers->hi = crs->hi;
			KRL_DBG(("succ extend %llu:%llu",
			    (unsigned long long)ers->lo,
			    (unsigned long long)ers->hi));
		}
		RB_REMOVE(revoked_serial_വൃക്ഷം, rt, crs);
		സ്വതന്ത്രം(crs);
	}
	KRL_DBG(("done, final %llu:%llu",
	    (unsigned long long)ers->lo, (unsigned long long)ers->hi));
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
ssh_krl_revoke_cert_by_serial(ഘടന ssh_krl *krl, സ്ഥിരം ഘടന sshkey *ca_താക്കോൽ,
    uint64_t serial)
{
	തിരികെ ssh_krl_revoke_cert_by_serial_range(krl, ca_താക്കോൽ, serial, serial);
}

പൂർണ്ണസംഖ്യ
ssh_krl_revoke_cert_by_serial_range(ഘടന ssh_krl *krl,
    സ്ഥിരം ഘടന sshkey *ca_താക്കോൽ, uint64_t lo, uint64_t hi)
{
	ഘടന revoked_certs *rc;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (lo > hi || lo == 0)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ ((r = revoked_certs_for_ca_താക്കോൽ(krl, ca_താക്കോൽ, &rc, 1)) != 0)
		തിരികെ r;
	തിരികെ തിരുകുക_serial_range(&rc->revoked_serials, lo, hi);
}

പൂർണ്ണസംഖ്യ
ssh_krl_revoke_cert_by_താക്കോൽ_id(ഘടന ssh_krl *krl, സ്ഥിരം ഘടന sshkey *ca_താക്കോൽ,
    സ്ഥിരം അക്ഷരം *താക്കോൽ_id)
{
	ഘടന revoked_താക്കോൽ_id *rki, *erki;
	ഘടന revoked_certs *rc;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = revoked_certs_for_ca_താക്കോൽ(krl, ca_താക്കോൽ, &rc, 1)) != 0)
		തിരികെ r;

	KRL_DBG(("revoke %s", താക്കോൽ_id));
	എങ്കിൽ ((rki = calloc(1, വലുപ്പം(*rki))) == ശൂന്യ ||
	    (rki->താക്കോൽ_id = strdup(താക്കോൽ_id)) == ശൂന്യ) {
		സ്വതന്ത്രം(rki);
		തിരികെ SSH_ERR_ALLOC_FAIL;
	}
	erki = RB_തിരുകുക(revoked_താക്കോൽ_id_വൃക്ഷം, &rc->revoked_താക്കോൽ_ids, rki);
	എങ്കിൽ (erki != ശൂന്യ) {
		സ്വതന്ത്രം(rki->താക്കോൽ_id);
		സ്വതന്ത്രം(rki);
	}
	തിരികെ 0;
}

/* Convert "key" to a public key blob without any certificate information */
സ്ഥിതം പൂർണ്ണസംഖ്യ
plain_താക്കോൽ_blob(സ്ഥിരം ഘടന sshkey *താക്കോൽ, u_char **blob, size_t *blen)
{
	ഘടന sshkey *kcopy;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshkey_from_private(താക്കോൽ, &kcopy)) != 0)
		തിരികെ r;
	എങ്കിൽ (sshkey_is_cert(kcopy)) {
		എങ്കിൽ ((r = sshkey_drop_cert(kcopy)) != 0) {
			sshkey_free(kcopy);
			തിരികെ r;
		}
	}
	r = sshkey_to_blob(kcopy, blob, blen);
	sshkey_free(kcopy);
	തിരികെ r;
}

/* Revoke a key blob. Ownership of blob is transferred to the tree */
സ്ഥിതം പൂർണ്ണസംഖ്യ
revoke_blob(ഘടന revoked_blob_വൃക്ഷം *rbt, u_char *blob, size_t len)
{
	ഘടന revoked_blob *rb, *erb;

	എങ്കിൽ ((rb = calloc(1, വലുപ്പം(*rb))) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	rb->blob = blob;
	rb->len = len;
	erb = RB_തിരുകുക(revoked_blob_വൃക്ഷം, rbt, rb);
	എങ്കിൽ (erb != ശൂന്യ) {
		സ്വതന്ത്രം(rb->blob);
		സ്വതന്ത്രം(rb);
	}
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
ssh_krl_revoke_താക്കോൽ_explicit(ഘടന ssh_krl *krl, സ്ഥിരം ഘടന sshkey *താക്കോൽ)
{
	u_char *blob;
	size_t len;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("revoke type %s", sshkey_type(താക്കോൽ));
	എങ്കിൽ ((r = plain_താക്കോൽ_blob(താക്കോൽ, &blob, &len)) != 0)
		തിരികെ r;
	തിരികെ revoke_blob(&krl->revoked_താക്കോലുകൾ, blob, len);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
revoke_by_hash(ഘടന revoked_blob_വൃക്ഷം *target, സ്ഥിരം u_char *p, size_t len)
{
	u_char *blob;
	പൂർണ്ണസംഖ്യ r;

	/* need to copy hash, as revoke_blob steals ownership */
	എങ്കിൽ ((blob = malloc(len)) == ശൂന്യ)
		തിരികെ SSH_ERR_SYSTEM_ERROR;
	memcpy(blob, p, len);
	എങ്കിൽ ((r = revoke_blob(target, blob, len)) != 0) {
		സ്വതന്ത്രം(blob);
		തിരികെ r;
	}
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
ssh_krl_revoke_താക്കോൽ_sha1(ഘടന ssh_krl *krl, സ്ഥിരം u_char *p, size_t len)
{
	debug3_f("revoke by sha1");
	എങ്കിൽ (len != 20)
		തിരികെ SSH_ERR_INVALID_FORMAT;
	തിരികെ revoke_by_hash(&krl->revoked_sha1s, p, len);
}

പൂർണ്ണസംഖ്യ
ssh_krl_revoke_താക്കോൽ_sha256(ഘടന ssh_krl *krl, സ്ഥിരം u_char *p, size_t len)
{
	debug3_f("revoke by sha256");
	എങ്കിൽ (len != 32)
		തിരികെ SSH_ERR_INVALID_FORMAT;
	തിരികെ revoke_by_hash(&krl->revoked_sha256s, p, len);
}

പൂർണ്ണസംഖ്യ
ssh_krl_revoke_താക്കോൽ(ഘടന ssh_krl *krl, സ്ഥിരം ഘടന sshkey *താക്കോൽ)
{
	/* XXX replace with SHA256? */
	എങ്കിൽ (!sshkey_is_cert(താക്കോൽ))
		തിരികെ ssh_krl_revoke_താക്കോൽ_explicit(krl, താക്കോൽ);

	എങ്കിൽ (താക്കോൽ->cert->serial == 0) {
		തിരികെ ssh_krl_revoke_cert_by_താക്കോൽ_id(krl,
		    താക്കോൽ->cert->signature_താക്കോൽ,
		    താക്കോൽ->cert->താക്കോൽ_id);
	} അല്ലെങ്കിൽ {
		തിരികെ ssh_krl_revoke_cert_by_serial(krl,
		    താക്കോൽ->cert->signature_താക്കോൽ,
		    താക്കോൽ->cert->serial);
	}
}

/*
 * Select the most compact section type to emit next in a KRL based on
 * the current section type, the run length of contiguous revoked serial
 * numbers and the gaps from the last and to the next revoked serial.
 * Applies a mostly-accurate bit cost model to select the section type
 * that will minimise the size of the resultant KRL.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
choose_next_state(പൂർണ്ണസംഖ്യ current_state, uint64_t contig, പൂർണ്ണസംഖ്യ final,
    uint64_t last_gap, uint64_t next_gap, size_t bitmap_len,
    പൂർണ്ണസംഖ്യ *force_new_section)
{
	പൂർണ്ണസംഖ്യ new_state;
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
	തിരഞ്ഞെടുപ്പ് (current_state) {
	അവസ്ഥ KRL_SECTION_CERT_SERIAL_LIST:
		cost_bitmap_restart = cost_bitmap = 8 + 64;
		നിർത്തുക;
	അവസ്ഥ KRL_SECTION_CERT_SERIAL_BITMAP:
		cost_list = 8;
		cost_bitmap_restart = 8 + 64;
		നിർത്തുക;
	അവസ്ഥ KRL_SECTION_CERT_SERIAL_RANGE:
	അവസ്ഥ 0:
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
	എങ്കിൽ (bitmap_len + cost_bitmap >= SSHBUF_MAX_BIGNUM) {
		KRL_DBG(("bitmap overfull len=%zu cost=%llu max=%u",
		    bitmap_len, (unsigned long long)cost_bitmap,
		    SSHBUF_MAX_BIGNUM));
		cost_bitmap = (uint64_t)-1;
	}

	/* Now pick the best choice */
	*force_new_section = 0;
	new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
	cost = cost_bitmap;
	എങ്കിൽ (cost_range < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_RANGE;
		cost = cost_range;
	}
	എങ്കിൽ (cost_list < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_LIST;
		cost = cost_list;
	}
	എങ്കിൽ (cost_bitmap_restart < cost) {
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
	തിരികെ new_state;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
put_bitmap(ഘടന sshbuf *buf, ഘടന bitmap *bitmap)
{
	size_t len;
	u_char *blob;
	പൂർണ്ണസംഖ്യ r;

	len = bitmap_nbytes(bitmap);
	എങ്കിൽ ((blob = malloc(len)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ (bitmap_to_string(bitmap, blob, len) != 0) {
		സ്വതന്ത്രം(blob);
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	}
	r = sshbuf_put_bignum2_bytes(buf, blob, len);
	സ്വതന്ത്രം(blob);
	തിരികെ r;
}

/* Generate a KRL_SECTION_CERTIFICATES KRL section */
സ്ഥിതം പൂർണ്ണസംഖ്യ
revoked_certs_generate(ഘടന revoked_certs *rc, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ final, force_new_sect, r = SSH_ERR_INTERNAL_ERROR;
	uint64_t i, contig, gap, last = 0, bitmap_start = 0;
	ഘടന revoked_serial *rs, *nrs;
	ഘടന revoked_താക്കോൽ_id *rki;
	പൂർണ്ണസംഖ്യ next_state, state = 0;
	size_t bitmap_len;
	ഘടന sshbuf *sect;
	ഘടന bitmap *bitmap = ശൂന്യ;

	എങ്കിൽ ((sect = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;

	/* Store the header: optional CA scope key, reserved */
	എങ്കിൽ (rc->ca_താക്കോൽ == ശൂന്യ) {
		എങ്കിൽ ((r = sshbuf_put_string(buf, ശൂന്യ, 0)) != 0)
			പോകുക out;
	} അല്ലെങ്കിൽ {
		എങ്കിൽ ((r = sshkey_puts(rc->ca_താക്കോൽ, buf)) != 0)
			പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put_string(buf, ശൂന്യ, 0)) != 0)
		പോകുക out;

	/* Store the revoked serials.  */
	വേണ്ടി (rs = RB_MIN(revoked_serial_വൃക്ഷം, &rc->revoked_serials);
	     rs != ശൂന്യ;
	     rs = RB_NEXT(revoked_serial_വൃക്ഷം, &rc->revoked_serials, rs)) {
		KRL_DBG(("serial %llu:%llu state 0x%02x",
		    (long long unsigned)rs->lo, (long long unsigned)rs->hi,
		    state));

		/* Check contiguous length and gap to next section (if any) */
		nrs = RB_NEXT(revoked_serial_വൃക്ഷം, &rc->revoked_serials, rs);
		final = nrs == ശൂന്യ;
		gap = nrs == ശൂന്യ ? 0 : nrs->lo - rs->hi;
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
		എങ്കിൽ (state != 0 && (force_new_sect || next_state != state ||
		    state == KRL_SECTION_CERT_SERIAL_RANGE)) {
			KRL_DBG(("finish state 0x%02x", state));
			തിരഞ്ഞെടുപ്പ് (state) {
			അവസ്ഥ KRL_SECTION_CERT_SERIAL_LIST:
			അവസ്ഥ KRL_SECTION_CERT_SERIAL_RANGE:
				നിർത്തുക;
			അവസ്ഥ KRL_SECTION_CERT_SERIAL_BITMAP:
				എങ്കിൽ ((r = put_bitmap(sect, bitmap)) != 0)
					പോകുക out;
				bitmap_free(bitmap);
				bitmap = ശൂന്യ;
				നിർത്തുക;
			}
			എങ്കിൽ ((r = sshbuf_put_u8(buf, state)) != 0 ||
			    (r = sshbuf_put_stringb(buf, sect)) != 0)
				പോകുക out;
			sshbuf_reset(sect);
		}

		/* If we are starting a new section then prepare it now */
		എങ്കിൽ (next_state != state || force_new_sect) {
			KRL_DBG(("start state 0x%02x",
			    next_state));
			state = next_state;
			sshbuf_reset(sect);
			തിരഞ്ഞെടുപ്പ് (state) {
			അവസ്ഥ KRL_SECTION_CERT_SERIAL_LIST:
			അവസ്ഥ KRL_SECTION_CERT_SERIAL_RANGE:
				നിർത്തുക;
			അവസ്ഥ KRL_SECTION_CERT_SERIAL_BITMAP:
				എങ്കിൽ ((bitmap = bitmap_new()) == ശൂന്യ) {
					r = SSH_ERR_ALLOC_FAIL;
					പോകുക out;
				}
				bitmap_start = rs->lo;
				എങ്കിൽ ((r = sshbuf_put_u64(sect,
				    bitmap_start)) != 0)
					പോകുക out;
				നിർത്തുക;
			}
		}

		/* Perform section-specific processing */
		തിരഞ്ഞെടുപ്പ് (state) {
		അവസ്ഥ KRL_SECTION_CERT_SERIAL_LIST:
			വേണ്ടി (i = 0; i < contig; i++) {
				എങ്കിൽ ((r = sshbuf_put_u64(sect, rs->lo + i)) != 0)
					പോകുക out;
			}
			നിർത്തുക;
		അവസ്ഥ KRL_SECTION_CERT_SERIAL_RANGE:
			എങ്കിൽ ((r = sshbuf_put_u64(sect, rs->lo)) != 0 ||
			    (r = sshbuf_put_u64(sect, rs->hi)) != 0)
				പോകുക out;
			നിർത്തുക;
		അവസ്ഥ KRL_SECTION_CERT_SERIAL_BITMAP:
			എങ്കിൽ (rs->lo - bitmap_start > INT_MAX) {
				r = SSH_ERR_INVALID_FORMAT;
				error_f("insane bitmap gap");
				പോകുക out;
			}
			വേണ്ടി (i = 0; i < contig; i++) {
				എങ്കിൽ (bitmap_set_bit(bitmap,
				    rs->lo + i - bitmap_start) != 0) {
					r = SSH_ERR_ALLOC_FAIL;
					പോകുക out;
				}
			}
			നിർത്തുക;
		}
		last = rs->hi;
	}
	/* Flush the remaining section, if any */
	എങ്കിൽ (state != 0) {
		KRL_DBG(("serial final flush for state 0x%02x", state));
		തിരഞ്ഞെടുപ്പ് (state) {
		അവസ്ഥ KRL_SECTION_CERT_SERIAL_LIST:
		അവസ്ഥ KRL_SECTION_CERT_SERIAL_RANGE:
			നിർത്തുക;
		അവസ്ഥ KRL_SECTION_CERT_SERIAL_BITMAP:
			എങ്കിൽ ((r = put_bitmap(sect, bitmap)) != 0)
				പോകുക out;
			bitmap_free(bitmap);
			bitmap = ശൂന്യ;
			നിർത്തുക;
		}
		എങ്കിൽ ((r = sshbuf_put_u8(buf, state)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			പോകുക out;
	}
	KRL_DBG(("serial done "));

	/* Now output a section for any revocations by key ID */
	sshbuf_reset(sect);
	RB_FOREACH(rki, revoked_താക്കോൽ_id_വൃക്ഷം, &rc->revoked_താക്കോൽ_ids) {
		KRL_DBG(("key ID %s", rki->താക്കോൽ_id));
		എങ്കിൽ ((r = sshbuf_put_cstring(sect, rki->താക്കോൽ_id)) != 0)
			പോകുക out;
	}
	എങ്കിൽ (sshbuf_len(sect) != 0) {
		എങ്കിൽ ((r = sshbuf_put_u8(buf, KRL_SECTION_CERT_താക്കോൽ_ID)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			പോകുക out;
	}
	r = 0;
 out:
	bitmap_free(bitmap);
	sshbuf_free(sect);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
ssh_krl_to_blob(ഘടന ssh_krl *krl, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	ഘടന revoked_certs *rc;
	ഘടന revoked_blob *rb;
	ഘടന sshbuf *sect;
	u_char *sblob = ശൂന്യ;

	എങ്കിൽ (krl->generated_date == 0)
		krl->generated_date = time(ശൂന്യ);

	എങ്കിൽ ((sect = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;

	/* Store the header */
	എങ്കിൽ ((r = sshbuf_put(buf, KRL_MAGIC, വലുപ്പം(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_put_u32(buf, KRL_FORMAT_VERSION)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->krl_version)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->generated_date)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->flags)) != 0 ||
	    (r = sshbuf_put_string(buf, ശൂന്യ, 0)) != 0 ||
	    (r = sshbuf_put_cstring(buf, krl->comment)) != 0)
		പോകുക out;

	/* Store sections for revoked certificates */
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		sshbuf_reset(sect);
		എങ്കിൽ ((r = revoked_certs_generate(rc, sect)) != 0)
			പോകുക out;
		എങ്കിൽ ((r = sshbuf_put_u8(buf, KRL_SECTION_CERTIFICATES)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			പോകുക out;
	}

	/* Finally, output sections for revocations by public key/hash */
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_വൃക്ഷം, &krl->revoked_താക്കോലുകൾ) {
		KRL_DBG(("key len %zu ", rb->len));
		എങ്കിൽ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			പോകുക out;
	}
	എങ്കിൽ (sshbuf_len(sect) != 0) {
		എങ്കിൽ ((r = sshbuf_put_u8(buf, KRL_SECTION_EXPLICIT_താക്കോൽ)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			പോകുക out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_വൃക്ഷം, &krl->revoked_sha1s) {
		KRL_DBG(("hash len %zu ", rb->len));
		എങ്കിൽ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			പോകുക out;
	}
	എങ്കിൽ (sshbuf_len(sect) != 0) {
		എങ്കിൽ ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA1)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			പോകുക out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_വൃക്ഷം, &krl->revoked_sha256s) {
		KRL_DBG(("hash len %zu ", rb->len));
		എങ്കിൽ ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			പോകുക out;
	}
	എങ്കിൽ (sshbuf_len(sect) != 0) {
		എങ്കിൽ ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA256)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			പോകുക out;
	}
	/* success */
	r = 0;
 out:
	സ്വതന്ത്രം(sblob);
	sshbuf_free(sect);
	തിരികെ r;
}

സ്ഥിതം ശൂന്യം
format_timestamp(uint64_t timestamp, അക്ഷരം *ts, size_t nts)
{
	time_t t;
	ഘടന tm *tm;

	t = timestamp;
	tm = localtime(&t);
	എങ്കിൽ (tm == ശൂന്യ)
		strlcpy(ts, "<INVALID>", nts);
	അല്ലെങ്കിൽ {
		*ts = '\0';
		strftime(ts, nts, "%Y%m%dT%H%M%S", tm);
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
cert_extension_subsection(ഘടന sshbuf *subsect, ഘടന ssh_krl *krl)
{
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	ഘടന sshbuf *മൂല്യം = ശൂന്യ;
	അക്ഷരം *name = ശൂന്യ;

	എങ്കിൽ ((r = sshbuf_get_cstring(subsect, &name, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_u8(subsect, &critical)) != 0 ||
	    (r = sshbuf_froms(subsect, &മൂല്യം)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid certificate extension subsection");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ (sshbuf_len(subsect) != 0) {
		error("KRL has invalid certificate extension subsection: "
		    "trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	debug_f("cert extension %s critical %u len %zu",
	    name, critical, sshbuf_len(മൂല്യം));
	/* no extensions are currently supported */
	എങ്കിൽ (critical) {
		error("KRL contains unsupported critical certificate "
		    "subsection \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		പോകുക out;
	}
	/* success */
	r = 0;
 out:
	സ്വതന്ത്രം(name);
	sshbuf_free(മൂല്യം);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_revoked_certs(ഘടന sshbuf *buf, ഘടന ssh_krl *krl)
{
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	സ്ഥിരം u_char *blob;
	size_t blen, nbits;
	ഘടന sshbuf *subsect = ശൂന്യ;
	uint64_t serial, serial_lo, serial_hi;
	ഘടന bitmap *bitmap = ശൂന്യ;
	അക്ഷരം *താക്കോൽ_id = ശൂന്യ;
	ഘടന sshkey *ca_താക്കോൽ = ശൂന്യ;

	എങ്കിൽ ((subsect = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;

	/* Header: key, reserved */
	എങ്കിൽ ((r = sshbuf_get_string_direct(buf, &blob, &blen)) != 0 ||
	    (r = sshbuf_skip_string(buf)) != 0)
		പോകുക out;
	എങ്കിൽ (blen != 0 && (r = sshkey_from_blob(blob, blen, &ca_താക്കോൽ)) != 0)
		പോകുക out;

	ആകുമ്പോൾ (sshbuf_len(buf) > 0) {
		sshbuf_free(subsect);
		subsect = ശൂന്യ;
		എങ്കിൽ ((r = sshbuf_get_u8(buf, &type)) != 0 ||
		    (r = sshbuf_froms(buf, &subsect)) != 0)
			പോകുക out;
		KRL_DBG(("subsection type 0x%02x", type));
		/* sshbuf_dump(subsect, stderr); */

		തിരഞ്ഞെടുപ്പ് (type) {
		അവസ്ഥ KRL_SECTION_CERT_SERIAL_LIST:
			ആകുമ്പോൾ (sshbuf_len(subsect) > 0) {
				എങ്കിൽ ((r = sshbuf_get_u64(subsect, &serial)) != 0)
					പോകുക out;
				എങ്കിൽ ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_താക്കോൽ, serial)) != 0)
					പോകുക out;
			}
			നിർത്തുക;
		അവസ്ഥ KRL_SECTION_CERT_SERIAL_RANGE:
			എങ്കിൽ ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_u64(subsect, &serial_hi)) != 0)
				പോകുക out;
			എങ്കിൽ ((r = ssh_krl_revoke_cert_by_serial_range(krl,
			    ca_താക്കോൽ, serial_lo, serial_hi)) != 0)
				പോകുക out;
			നിർത്തുക;
		അവസ്ഥ KRL_SECTION_CERT_SERIAL_BITMAP:
			എങ്കിൽ ((bitmap = bitmap_new()) == ശൂന്യ) {
				r = SSH_ERR_ALLOC_FAIL;
				പോകുക out;
			}
			എങ്കിൽ ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_bignum2_bytes_direct(subsect,
			    &blob, &blen)) != 0)
				പോകുക out;
			എങ്കിൽ (bitmap_from_string(bitmap, blob, blen) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				പോകുക out;
			}
			nbits = bitmap_nbits(bitmap);
			വേണ്ടി (serial = 0; serial < (uint64_t)nbits; serial++) {
				എങ്കിൽ (serial > 0 && serial_lo + serial == 0) {
					error_f("bitmap wraps u64");
					r = SSH_ERR_INVALID_FORMAT;
					പോകുക out;
				}
				എങ്കിൽ (!bitmap_test_bit(bitmap, serial))
					തുടരുക;
				എങ്കിൽ ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_താക്കോൽ, serial_lo + serial)) != 0)
					പോകുക out;
			}
			bitmap_free(bitmap);
			bitmap = ശൂന്യ;
			നിർത്തുക;
		അവസ്ഥ KRL_SECTION_CERT_താക്കോൽ_ID:
			ആകുമ്പോൾ (sshbuf_len(subsect) > 0) {
				എങ്കിൽ ((r = sshbuf_get_cstring(subsect,
				    &താക്കോൽ_id, ശൂന്യ)) != 0)
					പോകുക out;
				എങ്കിൽ ((r = ssh_krl_revoke_cert_by_താക്കോൽ_id(krl,
				    ca_താക്കോൽ, താക്കോൽ_id)) != 0)
					പോകുക out;
				സ്വതന്ത്രം(താക്കോൽ_id);
				താക്കോൽ_id = ശൂന്യ;
			}
			നിർത്തുക;
		അവസ്ഥ KRL_SECTION_CERT_EXTENSION:
			എങ്കിൽ ((r = cert_extension_subsection(subsect, krl)) != 0)
				പോകുക out;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			error("Unsupported KRL certificate section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
		എങ്കിൽ (sshbuf_len(subsect) > 0) {
			error("KRL certificate section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
	}

	r = 0;
 out:
	എങ്കിൽ (bitmap != ശൂന്യ)
		bitmap_free(bitmap);
	സ്വതന്ത്രം(താക്കോൽ_id);
	sshkey_free(ca_താക്കോൽ);
	sshbuf_free(subsect);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
blob_section(ഘടന sshbuf *sect, ഘടന revoked_blob_വൃക്ഷം *target_വൃക്ഷം,
    size_t expected_len)
{
	u_char *rdata = ശൂന്യ;
	size_t rlen = 0;
	പൂർണ്ണസംഖ്യ r;

	ആകുമ്പോൾ (sshbuf_len(sect) > 0) {
		എങ്കിൽ ((r = sshbuf_get_string(sect, &rdata, &rlen)) != 0)
			തിരികെ r;
		എങ്കിൽ (expected_len != 0 && rlen != expected_len) {
			error_f("bad length");
			സ്വതന്ത്രം(rdata);
			തിരികെ SSH_ERR_INVALID_FORMAT;
		}
		എങ്കിൽ ((r = revoke_blob(target_വൃക്ഷം, rdata, rlen)) != 0) {
			സ്വതന്ത്രം(rdata);
			തിരികെ r;
		}
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
extension_section(ഘടന sshbuf *sect, ഘടന ssh_krl *krl)
{
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	ഘടന sshbuf *മൂല്യം = ശൂന്യ;
	അക്ഷരം *name = ശൂന്യ;

	എങ്കിൽ ((r = sshbuf_get_cstring(sect, &name, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_u8(sect, &critical)) != 0 ||
	    (r = sshbuf_froms(sect, &മൂല്യം)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid extension section");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ (sshbuf_len(sect) != 0) {
		error("KRL has invalid extension section: trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	debug_f("extension %s critical %u len %zu",
	    name, critical, sshbuf_len(മൂല്യം));
	/* no extensions are currently supported */
	എങ്കിൽ (critical) {
		error("KRL contains unsupported critical section \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		പോകുക out;
	}
	/* success */
	r = 0;
 out:
	സ്വതന്ത്രം(name);
	sshbuf_free(മൂല്യം);
	തിരികെ r;
}

/* Attempt to parse a KRL */
പൂർണ്ണസംഖ്യ
ssh_krl_from_blob(ഘടന sshbuf *buf, ഘടന ssh_krl **krlp)
{
	ഘടന sshbuf *copy = ശൂന്യ, *sect = ശൂന്യ;
	ഘടന ssh_krl *krl = ശൂന്യ;
	അക്ഷരം timestamp[64];
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	u_int format_version;

	*krlp = ശൂന്യ;

	/* KRL must begin with magic string */
	എങ്കിൽ ((r = sshbuf_cmp(buf, 0, KRL_MAGIC, വലുപ്പം(KRL_MAGIC) - 1)) != 0) {
		debug2_f("bad KRL magic header");
		തിരികെ SSH_ERR_KRL_BAD_MAGIC;
	}

	എങ്കിൽ ((krl = ssh_krl_init()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		error_f("alloc failed");
		പോകുക out;
	}
	/* Don't modify buffer */
	എങ്കിൽ ((copy = sshbuf_fromb(buf)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_consume(copy, വലുപ്പം(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_get_u32(copy, &format_version)) != 0)
		പോകുക out;
	എങ്കിൽ (format_version != KRL_FORMAT_VERSION) {
		error_f("unsupported KRL format version %u", format_version);
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_get_u64(copy, &krl->krl_version)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->generated_date)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->flags)) != 0 ||
	    (r = sshbuf_skip_string(copy)) != 0 ||
	    (r = sshbuf_get_cstring(copy, &krl->comment, ശൂന്യ)) != 0) {
		error_fr(r, "parse KRL header");
		പോകുക out;
	}
	format_timestamp(krl->generated_date, timestamp, വലുപ്പം(timestamp));
	debug("KRL version %llu generated at %s%s%s",
	    (long long unsigned)krl->krl_version, timestamp,
	    *krl->comment ? ": " : "", krl->comment);

	/* Parse and load the KRL sections. */
	ആകുമ്പോൾ (sshbuf_len(copy) > 0) {
		sshbuf_free(sect);
		sect = ശൂന്യ;
		എങ്കിൽ ((r = sshbuf_get_u8(copy, &type)) != 0 ||
		    (r = sshbuf_froms(copy, &sect)) != 0)
			പോകുക out;
		KRL_DBG(("section 0x%02x", type));

		തിരഞ്ഞെടുപ്പ് (type) {
		അവസ്ഥ KRL_SECTION_CERTIFICATES:
			എങ്കിൽ ((r = parse_revoked_certs(sect, krl)) != 0)
				പോകുക out;
			നിർത്തുക;
		അവസ്ഥ KRL_SECTION_EXPLICIT_താക്കോൽ:
			എങ്കിൽ ((r = blob_section(sect,
			    &krl->revoked_താക്കോലുകൾ, 0)) != 0)
				പോകുക out;
			നിർത്തുക;
		അവസ്ഥ KRL_SECTION_FINGERPRINT_SHA1:
			എങ്കിൽ ((r = blob_section(sect,
			    &krl->revoked_sha1s, 20)) != 0)
				പോകുക out;
			നിർത്തുക;
		അവസ്ഥ KRL_SECTION_FINGERPRINT_SHA256:
			എങ്കിൽ ((r = blob_section(sect,
			    &krl->revoked_sha256s, 32)) != 0)
				പോകുക out;
			നിർത്തുക;
		അവസ്ഥ KRL_SECTION_EXTENSION:
			എങ്കിൽ ((r = extension_section(sect, krl)) != 0)
				പോകുക out;
			നിർത്തുക;
		അവസ്ഥ KRL_SECTION_SIGNATURE:
			/* Handled above, but still need to stay in synch */
			sshbuf_free(sect);
			sect = ശൂന്യ;
			എങ്കിൽ ((r = sshbuf_skip_string(copy)) != 0)
				പോകുക out;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			error("Unsupported KRL section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
		എങ്കിൽ (sect != ശൂന്യ && sshbuf_len(sect) > 0) {
			error("KRL section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
	}

	/* Success */
	*krlp = krl;
	r = 0;
 out:
	എങ്കിൽ (r != 0)
		ssh_krl_free(krl);
	sshbuf_free(copy);
	sshbuf_free(sect);
	തിരികെ r;
}

/* Checks certificate serial number and key ID revocation */
സ്ഥിതം പൂർണ്ണസംഖ്യ
is_cert_revoked(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന revoked_certs *rc)
{
	ഘടന revoked_serial rs, *ers;
	ഘടന revoked_താക്കോൽ_id rki, *erki;

	/* Check revocation by cert key ID */
	memset(&rki, 0, വലുപ്പം(rki));
	rki.താക്കോൽ_id = താക്കോൽ->cert->താക്കോൽ_id;
	erki = RB_FIND(revoked_താക്കോൽ_id_വൃക്ഷം, &rc->revoked_താക്കോൽ_ids, &rki);
	എങ്കിൽ (erki != ശൂന്യ) {
		KRL_DBG(("revoked by key ID"));
		തിരികെ SSH_ERR_താക്കോൽ_REVOKED;
	}

	/*
	 * Zero serials numbers are ignored (it's the default when the
	 * CA doesn't specify one).
	 */
	എങ്കിൽ (താക്കോൽ->cert->serial == 0)
		തിരികെ 0;

	memset(&rs, 0, വലുപ്പം(rs));
	rs.lo = rs.hi = താക്കോൽ->cert->serial;
	ers = RB_FIND(revoked_serial_വൃക്ഷം, &rc->revoked_serials, &rs);
	എങ്കിൽ (ers != ശൂന്യ) {
		KRL_DBG(("revoked serial %llu matched %llu:%llu",
		    (unsigned long long)താക്കോൽ->cert->serial,
		    (unsigned long long)ers->lo,
		    (unsigned long long)ers->hi));
		തിരികെ SSH_ERR_താക്കോൽ_REVOKED;
	}
	തിരികെ 0;
}

/* Checks whether a given key/cert is revoked. Does not check its CA */
സ്ഥിതം പൂർണ്ണസംഖ്യ
is_താക്കോൽ_revoked(ഘടന ssh_krl *krl, സ്ഥിരം ഘടന sshkey *താക്കോൽ)
{
	ഘടന revoked_blob rb, *erb;
	ഘടന revoked_certs *rc;
	പൂർണ്ണസംഖ്യ r;

	/* Check explicitly revoked hashes first */
	memset(&rb, 0, വലുപ്പം(rb));
	എങ്കിൽ ((r = sshkey_fingerprint_raw(താക്കോൽ, SSH_DIGEST_SHA1,
	    &rb.blob, &rb.len)) != 0)
		തിരികെ r;
	erb = RB_FIND(revoked_blob_വൃക്ഷം, &krl->revoked_sha1s, &rb);
	സ്വതന്ത്രം(rb.blob);
	എങ്കിൽ (erb != ശൂന്യ) {
		KRL_DBG(("revoked by key SHA1"));
		തിരികെ SSH_ERR_താക്കോൽ_REVOKED;
	}
	memset(&rb, 0, വലുപ്പം(rb));
	എങ്കിൽ ((r = sshkey_fingerprint_raw(താക്കോൽ, SSH_DIGEST_SHA256,
	    &rb.blob, &rb.len)) != 0)
		തിരികെ r;
	erb = RB_FIND(revoked_blob_വൃക്ഷം, &krl->revoked_sha256s, &rb);
	സ്വതന്ത്രം(rb.blob);
	എങ്കിൽ (erb != ശൂന്യ) {
		KRL_DBG(("revoked by key SHA256"));
		തിരികെ SSH_ERR_താക്കോൽ_REVOKED;
	}

	/* Next, explicit keys */
	memset(&rb, 0, വലുപ്പം(rb));
	എങ്കിൽ ((r = plain_താക്കോൽ_blob(താക്കോൽ, &rb.blob, &rb.len)) != 0)
		തിരികെ r;
	erb = RB_FIND(revoked_blob_വൃക്ഷം, &krl->revoked_താക്കോലുകൾ, &rb);
	സ്വതന്ത്രം(rb.blob);
	എങ്കിൽ (erb != ശൂന്യ) {
		KRL_DBG(("revoked by explicit key"));
		തിരികെ SSH_ERR_താക്കോൽ_REVOKED;
	}

	എങ്കിൽ (!sshkey_is_cert(താക്കോൽ))
		തിരികെ 0;

	/* Check cert revocation for the specified CA */
	എങ്കിൽ ((r = revoked_certs_for_ca_താക്കോൽ(krl, താക്കോൽ->cert->signature_താക്കോൽ,
	    &rc, 0)) != 0)
		തിരികെ r;
	എങ്കിൽ (rc != ശൂന്യ) {
		എങ്കിൽ ((r = is_cert_revoked(താക്കോൽ, rc)) != 0)
			തിരികെ r;
	}
	/* Check cert revocation for the wildcard CA */
	എങ്കിൽ ((r = revoked_certs_for_ca_താക്കോൽ(krl, ശൂന്യ, &rc, 0)) != 0)
		തിരികെ r;
	എങ്കിൽ (rc != ശൂന്യ) {
		എങ്കിൽ ((r = is_cert_revoked(താക്കോൽ, rc)) != 0)
			തിരികെ r;
	}

	KRL_DBG(("%llu no match", (unsigned long long)താക്കോൽ->cert->serial));
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
ssh_krl_check_താക്കോൽ(ഘടന ssh_krl *krl, സ്ഥിരം ഘടന sshkey *താക്കോൽ)
{
	പൂർണ്ണസംഖ്യ r;

	KRL_DBG(("checking key"));
	എങ്കിൽ ((r = is_താക്കോൽ_revoked(krl, താക്കോൽ)) != 0)
		തിരികെ r;
	എങ്കിൽ (sshkey_is_cert(താക്കോൽ)) {
		debug2_f("checking CA key");
		എങ്കിൽ ((r = is_താക്കോൽ_revoked(krl, താക്കോൽ->cert->signature_താക്കോൽ)) != 0)
			തിരികെ r;
	}
	KRL_DBG(("key okay"));
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
ssh_krl_file_contains_താക്കോൽ(സ്ഥിരം അക്ഷരം *path, സ്ഥിരം ഘടന sshkey *താക്കോൽ)
{
	ഘടന sshbuf *krlbuf = ശൂന്യ;
	ഘടന ssh_krl *krl = ശൂന്യ;
	പൂർണ്ണസംഖ്യ oerrno = 0, r;

	എങ്കിൽ (path == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ ((r = sshbuf_load_file(path, &krlbuf)) != 0) {
		oerrno = errno;
		പോകുക out;
	}
	എങ്കിൽ ((r = ssh_krl_from_blob(krlbuf, &krl)) != 0)
		പോകുക out;
	debug2_f("checking KRL %s", path);
	r = ssh_krl_check_താക്കോൽ(krl, താക്കോൽ);
 out:
	sshbuf_free(krlbuf);
	ssh_krl_free(krl);
	എങ്കിൽ (r != 0)
		errno = oerrno;
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
krl_dump(ഘടന ssh_krl *krl, FILE *f)
{
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	ഘടന revoked_blob *rb;
	ഘടന revoked_certs *rc;
	ഘടന revoked_serial *rs;
	ഘടന revoked_താക്കോൽ_id *rki;
	പൂർണ്ണസംഖ്യ r, ret = 0;
	അക്ഷരം *fp, timestamp[64];

	/* Try to print in a KRL spec-compatible format */
	format_timestamp(krl->generated_date, timestamp, വലുപ്പം(timestamp));
	fprintf(f, "# KRL version %llu\n", (unsigned long long)krl->krl_version);
	fprintf(f, "# Generated at %s\n", timestamp);
	എങ്കിൽ (krl->comment != ശൂന്യ && *krl->comment != '\0') {
		r = INT_MAX;
		asmprintf(&fp, INT_MAX, &r, "%s", krl->comment);
		fprintf(f, "# Comment: %s\n", fp);
		സ്വതന്ത്രം(fp);
	}
	fputc('\n', f);

	RB_FOREACH(rb, revoked_blob_വൃക്ഷം, &krl->revoked_താക്കോലുകൾ) {
		എങ്കിൽ ((r = sshkey_from_blob(rb->blob, rb->len, &താക്കോൽ)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			error_r(r, "parse KRL key");
			തുടരുക;
		}
		എങ്കിൽ ((fp = sshkey_fingerprint(താക്കോൽ, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == ശൂന്യ) {
			ret = SSH_ERR_INVALID_FORMAT;
			error("sshkey_fingerprint failed");
			തുടരുക;
		}
		fprintf(f, "hash: %s # %s\n", fp, sshkey_ssh_name(താക്കോൽ));
		സ്വതന്ത്രം(fp);
		സ്വതന്ത്രം(താക്കോൽ);
	}
	RB_FOREACH(rb, revoked_blob_വൃക്ഷം, &krl->revoked_sha256s) {
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "hash: SHA256:%s\n", fp);
		സ്വതന്ത്രം(fp);
	}
	RB_FOREACH(rb, revoked_blob_വൃക്ഷം, &krl->revoked_sha1s) {
		/*
		 * There is not KRL spec keyword for raw SHA1 hashes, so
		 * print them as comments.
		 */
		fp = tohex(rb->blob, rb->len);
		fprintf(f, "# hash SHA1:%s\n", fp);
		സ്വതന്ത്രം(fp);
	}

	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		fputc('\n', f);
		എങ്കിൽ (rc->ca_താക്കോൽ == ശൂന്യ)
			fprintf(f, "# Wildcard CA\n");
		അല്ലെങ്കിൽ {
			എങ്കിൽ ((fp = sshkey_fingerprint(rc->ca_താക്കോൽ,
			    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == ശൂന്യ) {
				ret = SSH_ERR_INVALID_FORMAT;
				error("sshkey_fingerprint failed");
				തുടരുക;
			}
			fprintf(f, "# CA key %s %s\n",
			    sshkey_ssh_name(rc->ca_താക്കോൽ), fp);
			സ്വതന്ത്രം(fp);
		}
		RB_FOREACH(rs, revoked_serial_വൃക്ഷം, &rc->revoked_serials) {
			എങ്കിൽ (rs->lo == rs->hi) {
				fprintf(f, "serial: %llu\n",
				    (unsigned long long)rs->lo);
			} അല്ലെങ്കിൽ {
				fprintf(f, "serial: %llu-%llu\n",
				    (unsigned long long)rs->lo,
				    (unsigned long long)rs->hi);
			}
		}
		RB_FOREACH(rki, revoked_താക്കോൽ_id_വൃക്ഷം, &rc->revoked_താക്കോൽ_ids) {
			/*
			 * We don't want key IDs with embedded newlines to
			 * mess up the display.
			 */
			r = INT_MAX;
			asmprintf(&fp, INT_MAX, &r, "%s", rki->താക്കോൽ_id);
			fprintf(f, "id: %s\n", fp);
			സ്വതന്ത്രം(fp);
		}
	}
	തിരികെ ret;
}
