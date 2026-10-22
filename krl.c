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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/tree.h>
#समावेश <sys/queue.h>

#समावेश <errno.h>
#समावेश <limits.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <time.h>

#समावेश "sshbuf.h"
#समावेश "ssherr.h"
#समावेश "sshkey.h"
#समावेश "misc.h"
#समावेश "log.h"
#समावेश "digest.h"
#समावेश "bitmap.h"
#समावेश "utf8.h"

#समावेश "krl.h"

/* #define DEBUG_KRL */
#अगर_घोषित DEBUG_KRL
# define KRL_DBG(x) debug3_f x
#अन्यथा
# define KRL_DBG(x)
#पूर्ण_अगर

/*
 * Trees of revoked serial numbers, key IDs and keys. This allows
 * quick searching, querying and producing lists in canonical order.
 */

/* Tree of serial numbers. XXX make smarter: really need a real sparse bitmap */
काष्ठा revoked_serial {
	uint64_t lo, hi;
	RB_ENTRY(revoked_serial) वृक्ष_entry;
};
अटल पूर्णांक serial_cmp(काष्ठा revoked_serial *a, काष्ठा revoked_serial *b);
RB_शीर्ष(revoked_serial_वृक्ष, revoked_serial);
RB_GENERATE_STATIC(revoked_serial_वृक्ष, revoked_serial, वृक्ष_entry, serial_cmp)

/* Tree of key IDs */
काष्ठा revoked_कुंजी_id {
	अक्षर *कुंजी_id;
	RB_ENTRY(revoked_कुंजी_id) वृक्ष_entry;
};
अटल पूर्णांक कुंजी_id_cmp(काष्ठा revoked_कुंजी_id *a, काष्ठा revoked_कुंजी_id *b);
RB_शीर्ष(revoked_कुंजी_id_वृक्ष, revoked_कुंजी_id);
RB_GENERATE_STATIC(revoked_कुंजी_id_वृक्ष, revoked_कुंजी_id, वृक्ष_entry, कुंजी_id_cmp)

/* Tree of blobs (used for keys and fingerprints) */
काष्ठा revoked_blob {
	u_char *blob;
	माप_प्रकार len;
	RB_ENTRY(revoked_blob) वृक्ष_entry;
};
अटल पूर्णांक blob_cmp(काष्ठा revoked_blob *a, काष्ठा revoked_blob *b);
RB_शीर्ष(revoked_blob_वृक्ष, revoked_blob);
RB_GENERATE_STATIC(revoked_blob_वृक्ष, revoked_blob, वृक्ष_entry, blob_cmp)

/* Tracks revoked certs for a single CA */
काष्ठा revoked_certs {
	काष्ठा sshkey *ca_कुंजी;
	काष्ठा revoked_serial_वृक्ष revoked_serials;
	काष्ठा revoked_कुंजी_id_वृक्ष revoked_कुंजी_ids;
	TAILQ_ENTRY(revoked_certs) entry;
};
TAILQ_HEAD(revoked_certs_list, revoked_certs);

काष्ठा ssh_krl {
	uint64_t krl_version;
	uint64_t generated_date;
	uint64_t flags;
	अक्षर *comment;
	काष्ठा revoked_blob_वृक्ष revoked_कुंजियाँ;
	काष्ठा revoked_blob_वृक्ष revoked_sha1s;
	काष्ठा revoked_blob_वृक्ष revoked_sha256s;
	काष्ठा revoked_certs_list revoked_certs;
};

/* Return equal if a and b overlap */
अटल पूर्णांक
serial_cmp(काष्ठा revoked_serial *a, काष्ठा revoked_serial *b)
{
	अगर (a->hi >= b->lo && a->lo <= b->hi)
		वापस 0;
	वापस a->lo < b->lo ? -1 : 1;
}

अटल पूर्णांक
कुंजी_id_cmp(काष्ठा revoked_कुंजी_id *a, काष्ठा revoked_कुंजी_id *b)
{
	वापस म_भेद(a->कुंजी_id, b->कुंजी_id);
}

अटल पूर्णांक
blob_cmp(काष्ठा revoked_blob *a, काष्ठा revoked_blob *b)
{
	पूर्णांक r;

	अगर (a->len != b->len) {
		अगर ((r = स_भेद(a->blob, b->blob, MINIMUM(a->len, b->len))) != 0)
			वापस r;
		वापस a->len > b->len ? 1 : -1;
	} अन्यथा
		वापस स_भेद(a->blob, b->blob, a->len);
}

काष्ठा ssh_krl *
ssh_krl_init(व्योम)
{
	काष्ठा ssh_krl *krl;

	अगर ((krl = सुस्मृति(1, माप(*krl))) == शून्य)
		वापस शून्य;
	RB_INIT(&krl->revoked_कुंजियाँ);
	RB_INIT(&krl->revoked_sha1s);
	RB_INIT(&krl->revoked_sha256s);
	TAILQ_INIT(&krl->revoked_certs);
	वापस krl;
}

अटल व्योम
revoked_certs_free(काष्ठा revoked_certs *rc)
{
	काष्ठा revoked_serial *rs, *trs;
	काष्ठा revoked_कुंजी_id *rki, *trki;

	अगर (rc == शून्य)
		वापस;
	RB_FOREACH_SAFE(rs, revoked_serial_वृक्ष, &rc->revoked_serials, trs) {
		RB_REMOVE(revoked_serial_वृक्ष, &rc->revoked_serials, rs);
		मुक्त(rs);
	}
	RB_FOREACH_SAFE(rki, revoked_कुंजी_id_वृक्ष, &rc->revoked_कुंजी_ids, trki) {
		RB_REMOVE(revoked_कुंजी_id_वृक्ष, &rc->revoked_कुंजी_ids, rki);
		मुक्त(rki->कुंजी_id);
		मुक्त(rki);
	}
	sshkey_free(rc->ca_कुंजी);
	freezero(rc, माप(*rc));
}

व्योम
ssh_krl_free(काष्ठा ssh_krl *krl)
{
	काष्ठा revoked_blob *rb, *trb;
	काष्ठा revoked_certs *rc, *trc;

	अगर (krl == शून्य)
		वापस;

	मुक्त(krl->comment);
	RB_FOREACH_SAFE(rb, revoked_blob_वृक्ष, &krl->revoked_कुंजियाँ, trb) {
		RB_REMOVE(revoked_blob_वृक्ष, &krl->revoked_कुंजियाँ, rb);
		मुक्त(rb->blob);
		मुक्त(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_वृक्ष, &krl->revoked_sha1s, trb) {
		RB_REMOVE(revoked_blob_वृक्ष, &krl->revoked_sha1s, rb);
		मुक्त(rb->blob);
		मुक्त(rb);
	}
	RB_FOREACH_SAFE(rb, revoked_blob_वृक्ष, &krl->revoked_sha256s, trb) {
		RB_REMOVE(revoked_blob_वृक्ष, &krl->revoked_sha256s, rb);
		मुक्त(rb->blob);
		मुक्त(rb);
	}
	TAILQ_FOREACH_SAFE(rc, &krl->revoked_certs, entry, trc) {
		TAILQ_REMOVE(&krl->revoked_certs, rc, entry);
		revoked_certs_free(rc);
	}
	मुक्त(krl);
}

व्योम
ssh_krl_set_version(काष्ठा ssh_krl *krl, uint64_t version)
{
	krl->krl_version = version;
}

पूर्णांक
ssh_krl_set_comment(काष्ठा ssh_krl *krl, स्थिर अक्षर *comment)
{
	मुक्त(krl->comment);
	अगर ((krl->comment = strdup(comment)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	वापस 0;
}

/*
 * Find the revoked_certs struct for a CA key. If allow_create is set then
 * create a new one in the tree if one did not exist already.
 */
अटल पूर्णांक
revoked_certs_for_ca_कुंजी(काष्ठा ssh_krl *krl, स्थिर काष्ठा sshkey *ca_कुंजी,
    काष्ठा revoked_certs **rcp, पूर्णांक allow_create)
{
	काष्ठा revoked_certs *rc;
	पूर्णांक r;

	*rcp = शून्य;
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		अगर ((ca_कुंजी == शून्य && rc->ca_कुंजी == शून्य) ||
		    sshkey_equal(rc->ca_कुंजी, ca_कुंजी)) {
			*rcp = rc;
			वापस 0;
		}
	}
	अगर (!allow_create)
		वापस 0;
	/* If this CA doesn't exist in the list then add it now */
	अगर ((rc = सुस्मृति(1, माप(*rc))) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर (ca_कुंजी == शून्य)
		rc->ca_कुंजी = शून्य;
	अन्यथा अगर ((r = sshkey_from_private(ca_कुंजी, &rc->ca_कुंजी)) != 0) {
		मुक्त(rc);
		वापस r;
	}
	RB_INIT(&rc->revoked_serials);
	RB_INIT(&rc->revoked_कुंजी_ids);
	TAILQ_INSERT_TAIL(&krl->revoked_certs, rc, entry);
	KRL_DBG(("new CA %s", ca_कुंजी == शून्य ? "*" : sshkey_type(ca_कुंजी)));
	*rcp = rc;
	वापस 0;
}

अटल पूर्णांक
जोड़ो_serial_range(काष्ठा revoked_serial_वृक्ष *rt, uint64_t lo, uint64_t hi)
{
	काष्ठा revoked_serial rs, *ers, *crs, *irs;

	KRL_DBG(("insert %llu:%llu",
	    (अचिन्हित दीर्घ दीर्घ)lo, (अचिन्हित दीर्घ दीर्घ)hi));
	स_रखो(&rs, 0, माप(rs));
	rs.lo = lo;
	rs.hi = hi;
	ers = RB_NFIND(revoked_serial_वृक्ष, rt, &rs);
	अगर (ers == शून्य || serial_cmp(ers, &rs) != 0) {
		/* No entry matches. Just insert */
		अगर ((irs = दो_स्मृति(माप(rs))) == शून्य)
			वापस SSH_ERR_ALLOC_FAIL;
		स_नकल(irs, &rs, माप(*irs));
		ers = RB_जोड़ो(revoked_serial_वृक्ष, rt, irs);
		अगर (ers != शून्य) {
			KRL_DBG(("bad: ers != NULL"));
			/* Shouldn't happen */
			मुक्त(irs);
			वापस SSH_ERR_INTERNAL_ERROR;
		}
		ers = irs;
	} अन्यथा {
		KRL_DBG(("overlap found %llu:%llu",
		    (अचिन्हित दीर्घ दीर्घ)ers->lo, (अचिन्हित दीर्घ दीर्घ)ers->hi));
		/*
		 * The inserted entry overlaps an existing one. Grow the
		 * existing entry.
		 */
		अगर (ers->lo > lo)
			ers->lo = lo;
		अगर (ers->hi < hi)
			ers->hi = hi;
	}

	/*
	 * The inserted or revised range might overlap or abut adjacent ones;
	 * coalesce as necessary.
	 */

	/* Check predecessors */
	जबतक ((crs = RB_पूर्व(revoked_serial_वृक्ष, rt, ers)) != शून्य) {
		KRL_DBG(("pred %llu:%llu",
		    (अचिन्हित दीर्घ दीर्घ)crs->lo, (अचिन्हित दीर्घ दीर्घ)crs->hi));
		अगर (ers->lo != 0 && crs->hi < ers->lo - 1)
			अवरोध;
		/* This entry overlaps. */
		अगर (crs->lo < ers->lo) {
			ers->lo = crs->lo;
			KRL_DBG(("pred extend %llu:%llu",
			    (अचिन्हित दीर्घ दीर्घ)ers->lo,
			    (अचिन्हित दीर्घ दीर्घ)ers->hi));
		}
		RB_REMOVE(revoked_serial_वृक्ष, rt, crs);
		मुक्त(crs);
	}
	/* Check successors */
	जबतक ((crs = RB_अग्र(revoked_serial_वृक्ष, rt, ers)) != शून्य) {
		KRL_DBG(("succ %llu:%llu",
		    (अचिन्हित दीर्घ दीर्घ)crs->lo, (अचिन्हित दीर्घ दीर्घ)crs->hi));
		अगर (ers->hi != (uint64_t)-1 && crs->lo > ers->hi + 1)
			अवरोध;
		/* This entry overlaps. */
		अगर (crs->hi > ers->hi) {
			ers->hi = crs->hi;
			KRL_DBG(("succ extend %llu:%llu",
			    (अचिन्हित दीर्घ दीर्घ)ers->lo,
			    (अचिन्हित दीर्घ दीर्घ)ers->hi));
		}
		RB_REMOVE(revoked_serial_वृक्ष, rt, crs);
		मुक्त(crs);
	}
	KRL_DBG(("done, final %llu:%llu",
	    (अचिन्हित दीर्घ दीर्घ)ers->lo, (अचिन्हित दीर्घ दीर्घ)ers->hi));
	वापस 0;
}

पूर्णांक
ssh_krl_revoke_cert_by_serial(काष्ठा ssh_krl *krl, स्थिर काष्ठा sshkey *ca_कुंजी,
    uint64_t serial)
{
	वापस ssh_krl_revoke_cert_by_serial_range(krl, ca_कुंजी, serial, serial);
}

पूर्णांक
ssh_krl_revoke_cert_by_serial_range(काष्ठा ssh_krl *krl,
    स्थिर काष्ठा sshkey *ca_कुंजी, uint64_t lo, uint64_t hi)
{
	काष्ठा revoked_certs *rc;
	पूर्णांक r;

	अगर (lo > hi || lo == 0)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर ((r = revoked_certs_for_ca_कुंजी(krl, ca_कुंजी, &rc, 1)) != 0)
		वापस r;
	वापस जोड़ो_serial_range(&rc->revoked_serials, lo, hi);
}

पूर्णांक
ssh_krl_revoke_cert_by_कुंजी_id(काष्ठा ssh_krl *krl, स्थिर काष्ठा sshkey *ca_कुंजी,
    स्थिर अक्षर *कुंजी_id)
{
	काष्ठा revoked_कुंजी_id *rki, *erki;
	काष्ठा revoked_certs *rc;
	पूर्णांक r;

	अगर ((r = revoked_certs_for_ca_कुंजी(krl, ca_कुंजी, &rc, 1)) != 0)
		वापस r;

	KRL_DBG(("revoke %s", कुंजी_id));
	अगर ((rki = सुस्मृति(1, माप(*rki))) == शून्य ||
	    (rki->कुंजी_id = strdup(कुंजी_id)) == शून्य) {
		मुक्त(rki);
		वापस SSH_ERR_ALLOC_FAIL;
	}
	erki = RB_जोड़ो(revoked_कुंजी_id_वृक्ष, &rc->revoked_कुंजी_ids, rki);
	अगर (erki != शून्य) {
		मुक्त(rki->कुंजी_id);
		मुक्त(rki);
	}
	वापस 0;
}

/* Convert "key" to a public key blob without any certificate information */
अटल पूर्णांक
plain_कुंजी_blob(स्थिर काष्ठा sshkey *कुंजी, u_char **blob, माप_प्रकार *blen)
{
	काष्ठा sshkey *kcopy;
	पूर्णांक r;

	अगर ((r = sshkey_from_private(कुंजी, &kcopy)) != 0)
		वापस r;
	अगर (sshkey_is_cert(kcopy)) {
		अगर ((r = sshkey_drop_cert(kcopy)) != 0) {
			sshkey_free(kcopy);
			वापस r;
		}
	}
	r = sshkey_to_blob(kcopy, blob, blen);
	sshkey_free(kcopy);
	वापस r;
}

/* Revoke a key blob. Ownership of blob is transferred to the tree */
अटल पूर्णांक
revoke_blob(काष्ठा revoked_blob_वृक्ष *rbt, u_char *blob, माप_प्रकार len)
{
	काष्ठा revoked_blob *rb, *erb;

	अगर ((rb = सुस्मृति(1, माप(*rb))) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	rb->blob = blob;
	rb->len = len;
	erb = RB_जोड़ो(revoked_blob_वृक्ष, rbt, rb);
	अगर (erb != शून्य) {
		मुक्त(rb->blob);
		मुक्त(rb);
	}
	वापस 0;
}

पूर्णांक
ssh_krl_revoke_कुंजी_explicit(काष्ठा ssh_krl *krl, स्थिर काष्ठा sshkey *कुंजी)
{
	u_char *blob;
	माप_प्रकार len;
	पूर्णांक r;

	debug3_f("revoke type %s", sshkey_type(कुंजी));
	अगर ((r = plain_कुंजी_blob(कुंजी, &blob, &len)) != 0)
		वापस r;
	वापस revoke_blob(&krl->revoked_कुंजियाँ, blob, len);
}

अटल पूर्णांक
revoke_by_hash(काष्ठा revoked_blob_वृक्ष *target, स्थिर u_char *p, माप_प्रकार len)
{
	u_char *blob;
	पूर्णांक r;

	/* need to copy hash, as revoke_blob steals ownership */
	अगर ((blob = दो_स्मृति(len)) == शून्य)
		वापस SSH_ERR_SYSTEM_ERROR;
	स_नकल(blob, p, len);
	अगर ((r = revoke_blob(target, blob, len)) != 0) {
		मुक्त(blob);
		वापस r;
	}
	वापस 0;
}

पूर्णांक
ssh_krl_revoke_कुंजी_sha1(काष्ठा ssh_krl *krl, स्थिर u_char *p, माप_प्रकार len)
{
	debug3_f("revoke by sha1");
	अगर (len != 20)
		वापस SSH_ERR_INVALID_FORMAT;
	वापस revoke_by_hash(&krl->revoked_sha1s, p, len);
}

पूर्णांक
ssh_krl_revoke_कुंजी_sha256(काष्ठा ssh_krl *krl, स्थिर u_char *p, माप_प्रकार len)
{
	debug3_f("revoke by sha256");
	अगर (len != 32)
		वापस SSH_ERR_INVALID_FORMAT;
	वापस revoke_by_hash(&krl->revoked_sha256s, p, len);
}

पूर्णांक
ssh_krl_revoke_कुंजी(काष्ठा ssh_krl *krl, स्थिर काष्ठा sshkey *कुंजी)
{
	/* XXX replace with SHA256? */
	अगर (!sshkey_is_cert(कुंजी))
		वापस ssh_krl_revoke_कुंजी_explicit(krl, कुंजी);

	अगर (कुंजी->cert->serial == 0) {
		वापस ssh_krl_revoke_cert_by_कुंजी_id(krl,
		    कुंजी->cert->signature_कुंजी,
		    कुंजी->cert->कुंजी_id);
	} अन्यथा {
		वापस ssh_krl_revoke_cert_by_serial(krl,
		    कुंजी->cert->signature_कुंजी,
		    कुंजी->cert->serial);
	}
}

/*
 * Select the most compact section type to emit next in a KRL based on
 * the current section type, the run length of contiguous revoked serial
 * numbers and the gaps from the last and to the next revoked serial.
 * Applies a mostly-accurate bit cost model to select the section type
 * that will minimise the size of the resultant KRL.
 */
अटल पूर्णांक
choose_अग्र_state(पूर्णांक current_state, uint64_t contig, पूर्णांक final,
    uint64_t last_gap, uint64_t अग्र_gap, माप_प्रकार bitmap_len,
    पूर्णांक *force_new_section)
{
	पूर्णांक new_state;
	uint64_t cost, cost_list, cost_range, cost_bitmap, cost_bitmap_restart;

	/*
	 * Avoid unsigned overflows.
	 * The limits are high enough to avoid confusing the calculations.
	 */
	contig = MINIMUM(contig, 1ULL<<31);
	last_gap = MINIMUM(last_gap, 1ULL<<31);
	अग्र_gap = MINIMUM(अग्र_gap, 1ULL<<31);

	/*
	 * Calculate the cost to switch from the current state to candidates.
	 * NB. range sections only ever contain a single range, so their
	 * switching cost is independent of the current_state.
	 */
	cost_list = cost_bitmap = cost_bitmap_restart = 0;
	cost_range = 8;
	चयन (current_state) {
	हाल KRL_SECTION_CERT_SERIAL_LIST:
		cost_bitmap_restart = cost_bitmap = 8 + 64;
		अवरोध;
	हाल KRL_SECTION_CERT_SERIAL_BITMAP:
		cost_list = 8;
		cost_bitmap_restart = 8 + 64;
		अवरोध;
	हाल KRL_SECTION_CERT_SERIAL_RANGE:
	हाल 0:
		cost_bitmap_restart = cost_bitmap = 8 + 64;
		cost_list = 8;
	}

	/* Estimate base cost in bits of each section type */
	cost_list += 64 * contig + (final ? 0 : 8+64);
	cost_range += (2 * 64) + (final ? 0 : 8+64);
	cost_bitmap += last_gap + contig + (final ? 0 : MINIMUM(अग्र_gap, 8+64));
	cost_bitmap_restart += contig + (final ? 0 : MINIMUM(अग्र_gap, 8+64));

	/* Convert to byte costs for actual comparison */
	cost_list = (cost_list + 7) / 8;
	cost_bitmap = (cost_bitmap + 7) / 8;
	cost_bitmap_restart = (cost_bitmap_restart + 7) / 8;
	cost_range = (cost_range + 7) / 8;

	/* Ensure that we never emit a bitmap larger than sshbuf can handle */
	अगर (bitmap_len + cost_bitmap >= SSHBUF_MAX_BIGNUM) {
		KRL_DBG(("bitmap overfull len=%zu cost=%llu max=%u",
		    bitmap_len, (अचिन्हित दीर्घ दीर्घ)cost_bitmap,
		    SSHBUF_MAX_BIGNUM));
		cost_bitmap = (uint64_t)-1;
	}

	/* Now pick the best choice */
	*force_new_section = 0;
	new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
	cost = cost_bitmap;
	अगर (cost_range < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_RANGE;
		cost = cost_range;
	}
	अगर (cost_list < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_LIST;
		cost = cost_list;
	}
	अगर (cost_bitmap_restart < cost) {
		new_state = KRL_SECTION_CERT_SERIAL_BITMAP;
		*force_new_section = 1;
		cost = cost_bitmap_restart;
	}
	KRL_DBG(("contig %llu last_gap %llu next_gap %llu final %d, costs:"
	    "list %llu range %llu bitmap %llu new bitmap %llu, "
	    "selected 0x%02x%s", (दीर्घ दीर्घ अचिन्हित)contig,
	    (दीर्घ दीर्घ अचिन्हित)last_gap, (दीर्घ दीर्घ अचिन्हित)अग्र_gap, final,
	    (दीर्घ दीर्घ अचिन्हित)cost_list, (दीर्घ दीर्घ अचिन्हित)cost_range,
	    (दीर्घ दीर्घ अचिन्हित)cost_bitmap,
	    (दीर्घ दीर्घ अचिन्हित)cost_bitmap_restart, new_state,
	    *force_new_section ? " restart" : ""));
	वापस new_state;
}

अटल पूर्णांक
put_bitmap(काष्ठा sshbuf *buf, काष्ठा bitmap *bitmap)
{
	माप_प्रकार len;
	u_char *blob;
	पूर्णांक r;

	len = bitmap_nbytes(bitmap);
	अगर ((blob = दो_स्मृति(len)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर (bitmap_to_string(bitmap, blob, len) != 0) {
		मुक्त(blob);
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	r = sshbuf_put_bignum2_bytes(buf, blob, len);
	मुक्त(blob);
	वापस r;
}

/* Generate a KRL_SECTION_CERTIFICATES KRL section */
अटल पूर्णांक
revoked_certs_generate(काष्ठा revoked_certs *rc, काष्ठा sshbuf *buf)
{
	पूर्णांक final, force_new_sect, r = SSH_ERR_INTERNAL_ERROR;
	uint64_t i, contig, gap, last = 0, bitmap_start = 0;
	काष्ठा revoked_serial *rs, *nrs;
	काष्ठा revoked_कुंजी_id *rki;
	पूर्णांक अग्र_state, state = 0;
	माप_प्रकार bitmap_len;
	काष्ठा sshbuf *sect;
	काष्ठा bitmap *bitmap = शून्य;

	अगर ((sect = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;

	/* Store the header: optional CA scope key, reserved */
	अगर (rc->ca_कुंजी == शून्य) {
		अगर ((r = sshbuf_put_string(buf, शून्य, 0)) != 0)
			जाओ out;
	} अन्यथा {
		अगर ((r = sshkey_puts(rc->ca_कुंजी, buf)) != 0)
			जाओ out;
	}
	अगर ((r = sshbuf_put_string(buf, शून्य, 0)) != 0)
		जाओ out;

	/* Store the revoked serials.  */
	क्रम (rs = RB_MIN(revoked_serial_वृक्ष, &rc->revoked_serials);
	     rs != शून्य;
	     rs = RB_अग्र(revoked_serial_वृक्ष, &rc->revoked_serials, rs)) {
		KRL_DBG(("serial %llu:%llu state 0x%02x",
		    (दीर्घ दीर्घ अचिन्हित)rs->lo, (दीर्घ दीर्घ अचिन्हित)rs->hi,
		    state));

		/* Check contiguous length and gap to next section (if any) */
		nrs = RB_अग्र(revoked_serial_वृक्ष, &rc->revoked_serials, rs);
		final = nrs == शून्य;
		gap = nrs == शून्य ? 0 : nrs->lo - rs->hi;
		contig = 1 + (rs->hi - rs->lo);

		bitmap_len = state == KRL_SECTION_CERT_SERIAL_BITMAP ?
		    bitmap_nbytes(bitmap) : 0;

		/* Choose next state based on these */
		अग्र_state = choose_अग्र_state(state, contig, final,
		    state == 0 ? 0 : rs->lo - last, gap, bitmap_len,
		    &force_new_sect);

		/*
		 * If the current section is a range section or has a different
		 * type to the next section, then finish it off now.
		 */
		अगर (state != 0 && (force_new_sect || अग्र_state != state ||
		    state == KRL_SECTION_CERT_SERIAL_RANGE)) {
			KRL_DBG(("finish state 0x%02x", state));
			चयन (state) {
			हाल KRL_SECTION_CERT_SERIAL_LIST:
			हाल KRL_SECTION_CERT_SERIAL_RANGE:
				अवरोध;
			हाल KRL_SECTION_CERT_SERIAL_BITMAP:
				अगर ((r = put_bitmap(sect, bitmap)) != 0)
					जाओ out;
				bitmap_free(bitmap);
				bitmap = शून्य;
				अवरोध;
			}
			अगर ((r = sshbuf_put_u8(buf, state)) != 0 ||
			    (r = sshbuf_put_stringb(buf, sect)) != 0)
				जाओ out;
			sshbuf_reset(sect);
		}

		/* If we are starting a new section then prepare it now */
		अगर (अग्र_state != state || force_new_sect) {
			KRL_DBG(("start state 0x%02x",
			    अग्र_state));
			state = अग्र_state;
			sshbuf_reset(sect);
			चयन (state) {
			हाल KRL_SECTION_CERT_SERIAL_LIST:
			हाल KRL_SECTION_CERT_SERIAL_RANGE:
				अवरोध;
			हाल KRL_SECTION_CERT_SERIAL_BITMAP:
				अगर ((bitmap = bitmap_new()) == शून्य) {
					r = SSH_ERR_ALLOC_FAIL;
					जाओ out;
				}
				bitmap_start = rs->lo;
				अगर ((r = sshbuf_put_u64(sect,
				    bitmap_start)) != 0)
					जाओ out;
				अवरोध;
			}
		}

		/* Perform section-specific processing */
		चयन (state) {
		हाल KRL_SECTION_CERT_SERIAL_LIST:
			क्रम (i = 0; i < contig; i++) {
				अगर ((r = sshbuf_put_u64(sect, rs->lo + i)) != 0)
					जाओ out;
			}
			अवरोध;
		हाल KRL_SECTION_CERT_SERIAL_RANGE:
			अगर ((r = sshbuf_put_u64(sect, rs->lo)) != 0 ||
			    (r = sshbuf_put_u64(sect, rs->hi)) != 0)
				जाओ out;
			अवरोध;
		हाल KRL_SECTION_CERT_SERIAL_BITMAP:
			अगर (rs->lo - bitmap_start > पूर्णांक_उच्च) {
				r = SSH_ERR_INVALID_FORMAT;
				error_f("insane bitmap gap");
				जाओ out;
			}
			क्रम (i = 0; i < contig; i++) {
				अगर (bitmap_set_bit(bitmap,
				    rs->lo + i - bitmap_start) != 0) {
					r = SSH_ERR_ALLOC_FAIL;
					जाओ out;
				}
			}
			अवरोध;
		}
		last = rs->hi;
	}
	/* Flush the remaining section, if any */
	अगर (state != 0) {
		KRL_DBG(("serial final flush for state 0x%02x", state));
		चयन (state) {
		हाल KRL_SECTION_CERT_SERIAL_LIST:
		हाल KRL_SECTION_CERT_SERIAL_RANGE:
			अवरोध;
		हाल KRL_SECTION_CERT_SERIAL_BITMAP:
			अगर ((r = put_bitmap(sect, bitmap)) != 0)
				जाओ out;
			bitmap_free(bitmap);
			bitmap = शून्य;
			अवरोध;
		}
		अगर ((r = sshbuf_put_u8(buf, state)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			जाओ out;
	}
	KRL_DBG(("serial done "));

	/* Now output a section for any revocations by key ID */
	sshbuf_reset(sect);
	RB_FOREACH(rki, revoked_कुंजी_id_वृक्ष, &rc->revoked_कुंजी_ids) {
		KRL_DBG(("key ID %s", rki->कुंजी_id));
		अगर ((r = sshbuf_put_cstring(sect, rki->कुंजी_id)) != 0)
			जाओ out;
	}
	अगर (sshbuf_len(sect) != 0) {
		अगर ((r = sshbuf_put_u8(buf, KRL_SECTION_CERT_कुंजी_ID)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			जाओ out;
	}
	r = 0;
 out:
	bitmap_free(bitmap);
	sshbuf_free(sect);
	वापस r;
}

पूर्णांक
ssh_krl_to_blob(काष्ठा ssh_krl *krl, काष्ठा sshbuf *buf)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	काष्ठा revoked_certs *rc;
	काष्ठा revoked_blob *rb;
	काष्ठा sshbuf *sect;
	u_char *sblob = शून्य;

	अगर (krl->generated_date == 0)
		krl->generated_date = समय(शून्य);

	अगर ((sect = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;

	/* Store the header */
	अगर ((r = sshbuf_put(buf, KRL_MAGIC, माप(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_put_u32(buf, KRL_FORMAT_VERSION)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->krl_version)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->generated_date)) != 0 ||
	    (r = sshbuf_put_u64(buf, krl->flags)) != 0 ||
	    (r = sshbuf_put_string(buf, शून्य, 0)) != 0 ||
	    (r = sshbuf_put_cstring(buf, krl->comment)) != 0)
		जाओ out;

	/* Store sections for revoked certificates */
	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		sshbuf_reset(sect);
		अगर ((r = revoked_certs_generate(rc, sect)) != 0)
			जाओ out;
		अगर ((r = sshbuf_put_u8(buf, KRL_SECTION_CERTIFICATES)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			जाओ out;
	}

	/* Finally, output sections for revocations by public key/hash */
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_वृक्ष, &krl->revoked_कुंजियाँ) {
		KRL_DBG(("key len %zu ", rb->len));
		अगर ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			जाओ out;
	}
	अगर (sshbuf_len(sect) != 0) {
		अगर ((r = sshbuf_put_u8(buf, KRL_SECTION_EXPLICIT_कुंजी)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			जाओ out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_वृक्ष, &krl->revoked_sha1s) {
		KRL_DBG(("hash len %zu ", rb->len));
		अगर ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			जाओ out;
	}
	अगर (sshbuf_len(sect) != 0) {
		अगर ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA1)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			जाओ out;
	}
	sshbuf_reset(sect);
	RB_FOREACH(rb, revoked_blob_वृक्ष, &krl->revoked_sha256s) {
		KRL_DBG(("hash len %zu ", rb->len));
		अगर ((r = sshbuf_put_string(sect, rb->blob, rb->len)) != 0)
			जाओ out;
	}
	अगर (sshbuf_len(sect) != 0) {
		अगर ((r = sshbuf_put_u8(buf,
		    KRL_SECTION_FINGERPRINT_SHA256)) != 0 ||
		    (r = sshbuf_put_stringb(buf, sect)) != 0)
			जाओ out;
	}
	/* success */
	r = 0;
 out:
	मुक्त(sblob);
	sshbuf_free(sect);
	वापस r;
}

अटल व्योम
format_timestamp(uint64_t timestamp, अक्षर *ts, माप_प्रकार nts)
{
	समय_प्रकार t;
	काष्ठा पंचांग *पंचांग;

	t = timestamp;
	पंचांग = स_स्थानीय(&t);
	अगर (पंचांग == शून्य)
		strlcpy(ts, "<INVALID>", nts);
	अन्यथा {
		*ts = '\0';
		स_माला(ts, nts, "%Y%m%dT%H%M%S", पंचांग);
	}
}

अटल पूर्णांक
cert_extension_subsection(काष्ठा sshbuf *subsect, काष्ठा ssh_krl *krl)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	काष्ठा sshbuf *मूल्य = शून्य;
	अक्षर *name = शून्य;

	अगर ((r = sshbuf_get_cstring(subsect, &name, शून्य)) != 0 ||
	    (r = sshbuf_get_u8(subsect, &critical)) != 0 ||
	    (r = sshbuf_froms(subsect, &मूल्य)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid certificate extension subsection");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर (sshbuf_len(subsect) != 0) {
		error("KRL has invalid certificate extension subsection: "
		    "trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	debug_f("cert extension %s critical %u len %zu",
	    name, critical, sshbuf_len(मूल्य));
	/* no extensions are currently supported */
	अगर (critical) {
		error("KRL contains unsupported critical certificate "
		    "subsection \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		जाओ out;
	}
	/* success */
	r = 0;
 out:
	मुक्त(name);
	sshbuf_free(मूल्य);
	वापस r;
}

अटल पूर्णांक
parse_revoked_certs(काष्ठा sshbuf *buf, काष्ठा ssh_krl *krl)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	स्थिर u_char *blob;
	माप_प्रकार blen, nbits;
	काष्ठा sshbuf *subsect = शून्य;
	uint64_t serial, serial_lo, serial_hi;
	काष्ठा bitmap *bitmap = शून्य;
	अक्षर *कुंजी_id = शून्य;
	काष्ठा sshkey *ca_कुंजी = शून्य;

	अगर ((subsect = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;

	/* Header: key, reserved */
	अगर ((r = sshbuf_get_string_direct(buf, &blob, &blen)) != 0 ||
	    (r = sshbuf_skip_string(buf)) != 0)
		जाओ out;
	अगर (blen != 0 && (r = sshkey_from_blob(blob, blen, &ca_कुंजी)) != 0)
		जाओ out;

	जबतक (sshbuf_len(buf) > 0) {
		sshbuf_free(subsect);
		subsect = शून्य;
		अगर ((r = sshbuf_get_u8(buf, &type)) != 0 ||
		    (r = sshbuf_froms(buf, &subsect)) != 0)
			जाओ out;
		KRL_DBG(("subsection type 0x%02x", type));
		/* sshbuf_dump(subsect, stderr); */

		चयन (type) {
		हाल KRL_SECTION_CERT_SERIAL_LIST:
			जबतक (sshbuf_len(subsect) > 0) {
				अगर ((r = sshbuf_get_u64(subsect, &serial)) != 0)
					जाओ out;
				अगर ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_कुंजी, serial)) != 0)
					जाओ out;
			}
			अवरोध;
		हाल KRL_SECTION_CERT_SERIAL_RANGE:
			अगर ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_u64(subsect, &serial_hi)) != 0)
				जाओ out;
			अगर ((r = ssh_krl_revoke_cert_by_serial_range(krl,
			    ca_कुंजी, serial_lo, serial_hi)) != 0)
				जाओ out;
			अवरोध;
		हाल KRL_SECTION_CERT_SERIAL_BITMAP:
			अगर ((bitmap = bitmap_new()) == शून्य) {
				r = SSH_ERR_ALLOC_FAIL;
				जाओ out;
			}
			अगर ((r = sshbuf_get_u64(subsect, &serial_lo)) != 0 ||
			    (r = sshbuf_get_bignum2_bytes_direct(subsect,
			    &blob, &blen)) != 0)
				जाओ out;
			अगर (bitmap_from_string(bitmap, blob, blen) != 0) {
				r = SSH_ERR_INVALID_FORMAT;
				जाओ out;
			}
			nbits = bitmap_nbits(bitmap);
			क्रम (serial = 0; serial < (uint64_t)nbits; serial++) {
				अगर (serial > 0 && serial_lo + serial == 0) {
					error_f("bitmap wraps u64");
					r = SSH_ERR_INVALID_FORMAT;
					जाओ out;
				}
				अगर (!bitmap_test_bit(bitmap, serial))
					जारी;
				अगर ((r = ssh_krl_revoke_cert_by_serial(krl,
				    ca_कुंजी, serial_lo + serial)) != 0)
					जाओ out;
			}
			bitmap_free(bitmap);
			bitmap = शून्य;
			अवरोध;
		हाल KRL_SECTION_CERT_कुंजी_ID:
			जबतक (sshbuf_len(subsect) > 0) {
				अगर ((r = sshbuf_get_cstring(subsect,
				    &कुंजी_id, शून्य)) != 0)
					जाओ out;
				अगर ((r = ssh_krl_revoke_cert_by_कुंजी_id(krl,
				    ca_कुंजी, कुंजी_id)) != 0)
					जाओ out;
				मुक्त(कुंजी_id);
				कुंजी_id = शून्य;
			}
			अवरोध;
		हाल KRL_SECTION_CERT_EXTENSION:
			अगर ((r = cert_extension_subsection(subsect, krl)) != 0)
				जाओ out;
			अवरोध;
		शेष:
			error("Unsupported KRL certificate section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
		अगर (sshbuf_len(subsect) > 0) {
			error("KRL certificate section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
	}

	r = 0;
 out:
	अगर (bitmap != शून्य)
		bitmap_free(bitmap);
	मुक्त(कुंजी_id);
	sshkey_free(ca_कुंजी);
	sshbuf_free(subsect);
	वापस r;
}

अटल पूर्णांक
blob_section(काष्ठा sshbuf *sect, काष्ठा revoked_blob_वृक्ष *target_वृक्ष,
    माप_प्रकार expected_len)
{
	u_char *rdata = शून्य;
	माप_प्रकार rlen = 0;
	पूर्णांक r;

	जबतक (sshbuf_len(sect) > 0) {
		अगर ((r = sshbuf_get_string(sect, &rdata, &rlen)) != 0)
			वापस r;
		अगर (expected_len != 0 && rlen != expected_len) {
			error_f("bad length");
			मुक्त(rdata);
			वापस SSH_ERR_INVALID_FORMAT;
		}
		अगर ((r = revoke_blob(target_वृक्ष, rdata, rlen)) != 0) {
			मुक्त(rdata);
			वापस r;
		}
	}
	वापस 0;
}

अटल पूर्णांक
extension_section(काष्ठा sshbuf *sect, काष्ठा ssh_krl *krl)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	u_char critical = 1;
	काष्ठा sshbuf *मूल्य = शून्य;
	अक्षर *name = शून्य;

	अगर ((r = sshbuf_get_cstring(sect, &name, शून्य)) != 0 ||
	    (r = sshbuf_get_u8(sect, &critical)) != 0 ||
	    (r = sshbuf_froms(sect, &मूल्य)) != 0) {
		debug_fr(r, "parse");
		error("KRL has invalid extension section");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर (sshbuf_len(sect) != 0) {
		error("KRL has invalid extension section: trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	debug_f("extension %s critical %u len %zu",
	    name, critical, sshbuf_len(मूल्य));
	/* no extensions are currently supported */
	अगर (critical) {
		error("KRL contains unsupported critical section \"%s\"", name);
		r = SSH_ERR_FEATURE_UNSUPPORTED;
		जाओ out;
	}
	/* success */
	r = 0;
 out:
	मुक्त(name);
	sshbuf_free(मूल्य);
	वापस r;
}

/* Attempt to parse a KRL */
पूर्णांक
ssh_krl_from_blob(काष्ठा sshbuf *buf, काष्ठा ssh_krl **krlp)
{
	काष्ठा sshbuf *copy = शून्य, *sect = शून्य;
	काष्ठा ssh_krl *krl = शून्य;
	अक्षर timestamp[64];
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	u_char type;
	u_int format_version;

	*krlp = शून्य;

	/* KRL must begin with magic string */
	अगर ((r = sshbuf_cmp(buf, 0, KRL_MAGIC, माप(KRL_MAGIC) - 1)) != 0) {
		debug2_f("bad KRL magic header");
		वापस SSH_ERR_KRL_BAD_MAGIC;
	}

	अगर ((krl = ssh_krl_init()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		error_f("alloc failed");
		जाओ out;
	}
	/* Don't modify buffer */
	अगर ((copy = sshbuf_fromb(buf)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_consume(copy, माप(KRL_MAGIC) - 1)) != 0 ||
	    (r = sshbuf_get_u32(copy, &format_version)) != 0)
		जाओ out;
	अगर (format_version != KRL_FORMAT_VERSION) {
		error_f("unsupported KRL format version %u", format_version);
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर ((r = sshbuf_get_u64(copy, &krl->krl_version)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->generated_date)) != 0 ||
	    (r = sshbuf_get_u64(copy, &krl->flags)) != 0 ||
	    (r = sshbuf_skip_string(copy)) != 0 ||
	    (r = sshbuf_get_cstring(copy, &krl->comment, शून्य)) != 0) {
		error_fr(r, "parse KRL header");
		जाओ out;
	}
	format_timestamp(krl->generated_date, timestamp, माप(timestamp));
	debug("KRL version %llu generated at %s%s%s",
	    (दीर्घ दीर्घ अचिन्हित)krl->krl_version, timestamp,
	    *krl->comment ? ": " : "", krl->comment);

	/* Parse and load the KRL sections. */
	जबतक (sshbuf_len(copy) > 0) {
		sshbuf_free(sect);
		sect = शून्य;
		अगर ((r = sshbuf_get_u8(copy, &type)) != 0 ||
		    (r = sshbuf_froms(copy, &sect)) != 0)
			जाओ out;
		KRL_DBG(("section 0x%02x", type));

		चयन (type) {
		हाल KRL_SECTION_CERTIFICATES:
			अगर ((r = parse_revoked_certs(sect, krl)) != 0)
				जाओ out;
			अवरोध;
		हाल KRL_SECTION_EXPLICIT_कुंजी:
			अगर ((r = blob_section(sect,
			    &krl->revoked_कुंजियाँ, 0)) != 0)
				जाओ out;
			अवरोध;
		हाल KRL_SECTION_FINGERPRINT_SHA1:
			अगर ((r = blob_section(sect,
			    &krl->revoked_sha1s, 20)) != 0)
				जाओ out;
			अवरोध;
		हाल KRL_SECTION_FINGERPRINT_SHA256:
			अगर ((r = blob_section(sect,
			    &krl->revoked_sha256s, 32)) != 0)
				जाओ out;
			अवरोध;
		हाल KRL_SECTION_EXTENSION:
			अगर ((r = extension_section(sect, krl)) != 0)
				जाओ out;
			अवरोध;
		हाल KRL_SECTION_SIGNATURE:
			/* Handled above, but still need to stay in synch */
			sshbuf_free(sect);
			sect = शून्य;
			अगर ((r = sshbuf_skip_string(copy)) != 0)
				जाओ out;
			अवरोध;
		शेष:
			error("Unsupported KRL section %u", type);
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
		अगर (sect != शून्य && sshbuf_len(sect) > 0) {
			error("KRL section contains unparsed data");
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
	}

	/* Success */
	*krlp = krl;
	r = 0;
 out:
	अगर (r != 0)
		ssh_krl_free(krl);
	sshbuf_free(copy);
	sshbuf_free(sect);
	वापस r;
}

/* Checks certificate serial number and key ID revocation */
अटल पूर्णांक
is_cert_revoked(स्थिर काष्ठा sshkey *कुंजी, काष्ठा revoked_certs *rc)
{
	काष्ठा revoked_serial rs, *ers;
	काष्ठा revoked_कुंजी_id rki, *erki;

	/* Check revocation by cert key ID */
	स_रखो(&rki, 0, माप(rki));
	rki.कुंजी_id = कुंजी->cert->कुंजी_id;
	erki = RB_FIND(revoked_कुंजी_id_वृक्ष, &rc->revoked_कुंजी_ids, &rki);
	अगर (erki != शून्य) {
		KRL_DBG(("revoked by key ID"));
		वापस SSH_ERR_कुंजी_REVOKED;
	}

	/*
	 * Zero serials numbers are ignored (it's the default when the
	 * CA doesn't specify one).
	 */
	अगर (कुंजी->cert->serial == 0)
		वापस 0;

	स_रखो(&rs, 0, माप(rs));
	rs.lo = rs.hi = कुंजी->cert->serial;
	ers = RB_FIND(revoked_serial_वृक्ष, &rc->revoked_serials, &rs);
	अगर (ers != शून्य) {
		KRL_DBG(("revoked serial %llu matched %llu:%llu",
		    (अचिन्हित दीर्घ दीर्घ)कुंजी->cert->serial,
		    (अचिन्हित दीर्घ दीर्घ)ers->lo,
		    (अचिन्हित दीर्घ दीर्घ)ers->hi));
		वापस SSH_ERR_कुंजी_REVOKED;
	}
	वापस 0;
}

/* Checks whether a given key/cert is revoked. Does not check its CA */
अटल पूर्णांक
is_कुंजी_revoked(काष्ठा ssh_krl *krl, स्थिर काष्ठा sshkey *कुंजी)
{
	काष्ठा revoked_blob rb, *erb;
	काष्ठा revoked_certs *rc;
	पूर्णांक r;

	/* Check explicitly revoked hashes first */
	स_रखो(&rb, 0, माप(rb));
	अगर ((r = sshkey_fingerprint_raw(कुंजी, SSH_DIGEST_SHA1,
	    &rb.blob, &rb.len)) != 0)
		वापस r;
	erb = RB_FIND(revoked_blob_वृक्ष, &krl->revoked_sha1s, &rb);
	मुक्त(rb.blob);
	अगर (erb != शून्य) {
		KRL_DBG(("revoked by key SHA1"));
		वापस SSH_ERR_कुंजी_REVOKED;
	}
	स_रखो(&rb, 0, माप(rb));
	अगर ((r = sshkey_fingerprint_raw(कुंजी, SSH_DIGEST_SHA256,
	    &rb.blob, &rb.len)) != 0)
		वापस r;
	erb = RB_FIND(revoked_blob_वृक्ष, &krl->revoked_sha256s, &rb);
	मुक्त(rb.blob);
	अगर (erb != शून्य) {
		KRL_DBG(("revoked by key SHA256"));
		वापस SSH_ERR_कुंजी_REVOKED;
	}

	/* Next, explicit keys */
	स_रखो(&rb, 0, माप(rb));
	अगर ((r = plain_कुंजी_blob(कुंजी, &rb.blob, &rb.len)) != 0)
		वापस r;
	erb = RB_FIND(revoked_blob_वृक्ष, &krl->revoked_कुंजियाँ, &rb);
	मुक्त(rb.blob);
	अगर (erb != शून्य) {
		KRL_DBG(("revoked by explicit key"));
		वापस SSH_ERR_कुंजी_REVOKED;
	}

	अगर (!sshkey_is_cert(कुंजी))
		वापस 0;

	/* Check cert revocation for the specified CA */
	अगर ((r = revoked_certs_for_ca_कुंजी(krl, कुंजी->cert->signature_कुंजी,
	    &rc, 0)) != 0)
		वापस r;
	अगर (rc != शून्य) {
		अगर ((r = is_cert_revoked(कुंजी, rc)) != 0)
			वापस r;
	}
	/* Check cert revocation for the wildcard CA */
	अगर ((r = revoked_certs_for_ca_कुंजी(krl, शून्य, &rc, 0)) != 0)
		वापस r;
	अगर (rc != शून्य) {
		अगर ((r = is_cert_revoked(कुंजी, rc)) != 0)
			वापस r;
	}

	KRL_DBG(("%llu no match", (अचिन्हित दीर्घ दीर्घ)कुंजी->cert->serial));
	वापस 0;
}

पूर्णांक
ssh_krl_check_कुंजी(काष्ठा ssh_krl *krl, स्थिर काष्ठा sshkey *कुंजी)
{
	पूर्णांक r;

	KRL_DBG(("checking key"));
	अगर ((r = is_कुंजी_revoked(krl, कुंजी)) != 0)
		वापस r;
	अगर (sshkey_is_cert(कुंजी)) {
		debug2_f("checking CA key");
		अगर ((r = is_कुंजी_revoked(krl, कुंजी->cert->signature_कुंजी)) != 0)
			वापस r;
	}
	KRL_DBG(("key okay"));
	वापस 0;
}

पूर्णांक
ssh_krl_file_contains_कुंजी(स्थिर अक्षर *path, स्थिर काष्ठा sshkey *कुंजी)
{
	काष्ठा sshbuf *krlbuf = शून्य;
	काष्ठा ssh_krl *krl = शून्य;
	पूर्णांक oerrno = 0, r;

	अगर (path == शून्य)
		वापस 0;
	अगर ((r = sshbuf_load_file(path, &krlbuf)) != 0) {
		oerrno = त्रुटि_सं;
		जाओ out;
	}
	अगर ((r = ssh_krl_from_blob(krlbuf, &krl)) != 0)
		जाओ out;
	debug2_f("checking KRL %s", path);
	r = ssh_krl_check_कुंजी(krl, कुंजी);
 out:
	sshbuf_free(krlbuf);
	ssh_krl_free(krl);
	अगर (r != 0)
		त्रुटि_सं = oerrno;
	वापस r;
}

पूर्णांक
krl_dump(काष्ठा ssh_krl *krl, खाता *f)
{
	काष्ठा sshkey *कुंजी = शून्य;
	काष्ठा revoked_blob *rb;
	काष्ठा revoked_certs *rc;
	काष्ठा revoked_serial *rs;
	काष्ठा revoked_कुंजी_id *rki;
	पूर्णांक r, ret = 0;
	अक्षर *fp, timestamp[64];

	/* Try to print in a KRL spec-compatible format */
	format_timestamp(krl->generated_date, timestamp, माप(timestamp));
	ख_लिखो(f, "# KRL version %llu\n", (अचिन्हित दीर्घ दीर्घ)krl->krl_version);
	ख_लिखो(f, "# Generated at %s\n", timestamp);
	अगर (krl->comment != शून्य && *krl->comment != '\0') {
		r = पूर्णांक_उच्च;
		asmprintf(&fp, पूर्णांक_उच्च, &r, "%s", krl->comment);
		ख_लिखो(f, "# Comment: %s\n", fp);
		मुक्त(fp);
	}
	ख_अक्षर_दो('\n', f);

	RB_FOREACH(rb, revoked_blob_वृक्ष, &krl->revoked_कुंजियाँ) {
		अगर ((r = sshkey_from_blob(rb->blob, rb->len, &कुंजी)) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			error_r(r, "parse KRL key");
			जारी;
		}
		अगर ((fp = sshkey_fingerprint(कुंजी, SSH_FP_HASH_DEFAULT,
		    SSH_FP_DEFAULT)) == शून्य) {
			ret = SSH_ERR_INVALID_FORMAT;
			error("sshkey_fingerprint failed");
			जारी;
		}
		ख_लिखो(f, "hash: %s # %s\n", fp, sshkey_ssh_name(कुंजी));
		मुक्त(fp);
		मुक्त(कुंजी);
	}
	RB_FOREACH(rb, revoked_blob_वृक्ष, &krl->revoked_sha256s) {
		fp = tohex(rb->blob, rb->len);
		ख_लिखो(f, "hash: SHA256:%s\n", fp);
		मुक्त(fp);
	}
	RB_FOREACH(rb, revoked_blob_वृक्ष, &krl->revoked_sha1s) {
		/*
		 * There is not KRL spec keyword for raw SHA1 hashes, so
		 * print them as comments.
		 */
		fp = tohex(rb->blob, rb->len);
		ख_लिखो(f, "# hash SHA1:%s\n", fp);
		मुक्त(fp);
	}

	TAILQ_FOREACH(rc, &krl->revoked_certs, entry) {
		ख_अक्षर_दो('\n', f);
		अगर (rc->ca_कुंजी == शून्य)
			ख_लिखो(f, "# Wildcard CA\n");
		अन्यथा {
			अगर ((fp = sshkey_fingerprint(rc->ca_कुंजी,
			    SSH_FP_HASH_DEFAULT, SSH_FP_DEFAULT)) == शून्य) {
				ret = SSH_ERR_INVALID_FORMAT;
				error("sshkey_fingerprint failed");
				जारी;
			}
			ख_लिखो(f, "# CA key %s %s\n",
			    sshkey_ssh_name(rc->ca_कुंजी), fp);
			मुक्त(fp);
		}
		RB_FOREACH(rs, revoked_serial_वृक्ष, &rc->revoked_serials) {
			अगर (rs->lo == rs->hi) {
				ख_लिखो(f, "serial: %llu\n",
				    (अचिन्हित दीर्घ दीर्घ)rs->lo);
			} अन्यथा {
				ख_लिखो(f, "serial: %llu-%llu\n",
				    (अचिन्हित दीर्घ दीर्घ)rs->lo,
				    (अचिन्हित दीर्घ दीर्घ)rs->hi);
			}
		}
		RB_FOREACH(rki, revoked_कुंजी_id_वृक्ष, &rc->revoked_कुंजी_ids) {
			/*
			 * We don't want key IDs with embedded newlines to
			 * mess up the display.
			 */
			r = पूर्णांक_उच्च;
			asmprintf(&fp, पूर्णांक_उच्च, &r, "%s", rki->कुंजी_id);
			ख_लिखो(f, "id: %s\n", fp);
			मुक्त(fp);
		}
	}
	वापस ret;
}
