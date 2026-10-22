/* $OpenBSD: kex-names.c,v 1.10 2026/08/08 07:27:54 djm Exp $ */
/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <signal.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/crypto.h>
#అన్తర్భావ <openssl/evp.h>
#అయితే_ముగింపు

#అన్తర్భావ "kex.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "misc.h"

#అన్తర్భావ "ssherr.h"

నిర్మాణం kexalg {
	అక్షరం *name;
	u_int type;
	పూర్ణాంకం ec_nid;
	పూర్ణాంకం hash_alg;
	పూర్ణాంకం pq_alg;
};
స్థిర స్థిరరాశి నిర్మాణం kexalg kexalgs[] = {
#నిర్వచితమైతే WITH_OPENSSL
	{ KEX_DH1, KEX_DH_GRP1_SHA1, 0, SSH_DIGEST_SHA1, KEX_NOT_PQ },
	{ KEX_DH14_SHA1, KEX_DH_GRP14_SHA1, 0, SSH_DIGEST_SHA1, KEX_NOT_PQ },
	{ KEX_DH14_SHA256, KEX_DH_GRP14_SHA256, 0, SSH_DIGEST_SHA256, KEX_NOT_PQ },
	{ KEX_DH16_SHA512, KEX_DH_GRP16_SHA512, 0, SSH_DIGEST_SHA512, KEX_NOT_PQ },
	{ KEX_DH18_SHA512, KEX_DH_GRP18_SHA512, 0, SSH_DIGEST_SHA512, KEX_NOT_PQ },
	{ KEX_DHGEX_SHA1, KEX_DH_GEX_SHA1, 0, SSH_DIGEST_SHA1, KEX_NOT_PQ },
# ifdef HAVE_EVP_SHA256
	{ KEX_DHGEX_SHA256, KEX_DH_GEX_SHA256, 0, SSH_DIGEST_SHA256, KEX_NOT_PQ },
# endif /* HAVE_EVP_SHA256 */
	{ KEX_ECDH_SHA2_NISTP256, KEX_ECDH_SHA2,
	    NID_X9_62_prime256v1, SSH_DIGEST_SHA256, KEX_NOT_PQ },
	{ KEX_ECDH_SHA2_NISTP384, KEX_ECDH_SHA2, NID_secp384r1,
	    SSH_DIGEST_SHA384, KEX_NOT_PQ },
	{ KEX_ECDH_SHA2_NISTP521, KEX_ECDH_SHA2, NID_secp521r1,
	    SSH_DIGEST_SHA512, KEX_NOT_PQ },
	{ KEX_MLKEM768NISTP256_SHA256, KEX_KEM_MLKEM768ECDH_SHA256,
	    NID_X9_62_prime256v1, SSH_DIGEST_SHA256, KEX_IS_PQ },
#అయితే_ముగింపు /* WITH_OPENSSL */
#ఒకవేళ defined(HAVE_EVP_SHA256) || !defined(WITH_OPENSSL)
	{ KEX_CURVE25519_SHA256, KEX_C25519_SHA256, 0, SSH_DIGEST_SHA256, KEX_NOT_PQ },
	{ KEX_CURVE25519_SHA256_OLD, KEX_C25519_SHA256, 0, SSH_DIGEST_SHA256, KEX_NOT_PQ },
#నిర్వచితమైతే USE_SNTRUP761X25519
	{ KEX_SNTRUP761X25519_SHA512, KEX_KEM_SNTRUP761X25519_SHA512, 0,
	    SSH_DIGEST_SHA512, KEX_IS_PQ },
	{ KEX_SNTRUP761X25519_SHA512_OLD, KEX_KEM_SNTRUP761X25519_SHA512, 0,
	    SSH_DIGEST_SHA512, KEX_IS_PQ },
#అయితే_ముగింపు
#నిర్వచితమైతే USE_MLKEM768X25519
	{ KEX_MLKEM768X25519_SHA256, KEX_KEM_MLKEM768X25519_SHA256, 0,
	    SSH_DIGEST_SHA256, KEX_IS_PQ },
#అయితే_ముగింపు
#అయితే_ముగింపు /* HAVE_EVP_SHA256 || !WITH_OPENSSL */
	{ ఖాళీ, 0, -1, -1, 0 },
};

అక్షరం *
kex_alg_list(అక్షరం sep)
{
	అక్షరం *ret = ఖాళీ;
	స్థిరరాశి నిర్మాణం kexalg *k;
	అక్షరం sep_str[2] = {sep, '\0'};

	కొరకు (k = kexalgs; k->name != ఖాళీ; k++)
		xextendf(&ret, sep_str, "%s", k->name);

	తిరిగి ret;
}

స్థిర స్థిరరాశి నిర్మాణం kexalg *
kex_alg_by_name(స్థిరరాశి అక్షరం *name)
{
	స్థిరరాశి నిర్మాణం kexalg *k;

	కొరకు (k = kexalgs; k->name != ఖాళీ; k++) {
		ఒకవేళ (strcmp(k->name, name) == 0)
			తిరిగి k;
	}
	తిరిగి ఖాళీ;
}

పూర్ణాంకం
kex_name_valid(స్థిరరాశి అక్షరం *name)
{
	తిరిగి kex_alg_by_name(name) != ఖాళీ;
}

పూర్ణాంకం
kex_is_pq_from_name(స్థిరరాశి అక్షరం *name)
{
	స్థిరరాశి నిర్మాణం kexalg *k;

	ఒకవేళ ((k = kex_alg_by_name(name)) == ఖాళీ)
		తిరిగి 0;
	తిరిగి k->pq_alg == KEX_IS_PQ;
}

u_int
kex_type_from_name(స్థిరరాశి అక్షరం *name)
{
	స్థిరరాశి నిర్మాణం kexalg *k;

	ఒకవేళ ((k = kex_alg_by_name(name)) == ఖాళీ)
		తిరిగి 0;
	తిరిగి k->type;
}

పూర్ణాంకం
kex_hash_from_name(స్థిరరాశి అక్షరం *name)
{
	స్థిరరాశి నిర్మాణం kexalg *k;

	ఒకవేళ ((k = kex_alg_by_name(name)) == ఖాళీ)
		తిరిగి -1;
	తిరిగి k->hash_alg;
}

పూర్ణాంకం
kex_nid_from_name(స్థిరరాశి అక్షరం *name)
{
	స్థిరరాశి నిర్మాణం kexalg *k;

	ఒకవేళ ((k = kex_alg_by_name(name)) == ఖాళీ)
		తిరిగి -1;
	తిరిగి k->ec_nid;
}

/* Validate KEX method name list */
పూర్ణాంకం
kex_పేర్లు_valid(స్థిరరాశి అక్షరం *పేర్లు)
{
	అక్షరం *s, *cp, *p;

	ఒకవేళ (పేర్లు == ఖాళీ || strcmp(పేర్లు, "") == 0)
		తిరిగి 0;
	ఒకవేళ ((s = cp = strdup(పేర్లు)) == ఖాళీ)
		తిరిగి 0;
	కొరకు ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		ఒకవేళ (kex_alg_by_name(p) == ఖాళీ) {
			error("Unsupported KEX algorithm \"%.100s\"", p);
			విడుదల(s);
			తిరిగి 0;
		}
	}
	debug3("kex names ok: [%s]", పేర్లు);
	విడుదల(s);
	తిరిగి 1;
}

/* returns non-zero if proposal contains any algorithm from algs */
పూర్ణాంకం
kex_has_any_alg(స్థిరరాశి అక్షరం *proposal, స్థిరరాశి అక్షరం *algs)
{
	అక్షరం *cp;

	ఒకవేళ ((cp = సరిపోలిక_list(proposal, algs, ఖాళీ)) == ఖాళీ)
		తిరిగి 0;
	విడుదల(cp);
	తిరిగి 1;
}

/*
 * Concatenate algorithm names, avoiding duplicates in the process.
 * Caller must free returned string.
 */
అక్షరం *
kex_పేర్లు_cat(స్థిరరాశి అక్షరం *a, స్థిరరాశి అక్షరం *b)
{
	అక్షరం *ret = ఖాళీ, *tmp = ఖాళీ, *cp, *p;
	కొలత_t len;

	ఒకవేళ (a == ఖాళీ || *a == '\0')
		తిరిగి strdup(b);
	ఒకవేళ (b == ఖాళీ || *b == '\0')
		తిరిగి strdup(a);
	ఒకవేళ (అక్షరశ్రేణి_పొడవు(b) > 1024*1024)
		తిరిగి ఖాళీ;
	len = అక్షరశ్రేణి_పొడవు(a) + అక్షరశ్రేణి_పొడవు(b) + 2;
	ఒకవేళ ((tmp = cp = strdup(b)) == ఖాళీ ||
	    (ret = సున్నా_జ్ఞాపకం_ఇవ్వు(1, len)) == ఖాళీ) {
		విడుదల(tmp);
		తిరిగి ఖాళీ;
	}
	strlcpy(ret, a, len);
	కొరకు ((p = strsep(&cp, ",")); p && *p != '\0'; (p = strsep(&cp, ","))) {
		ఒకవేళ (kex_has_any_alg(ret, p))
			కొనసాగు; /* Algorithm already present */
		ఒకవేళ (strlcat(ret, ",", len) >= len ||
		    strlcat(ret, p, len) >= len) {
			విడుదల(tmp);
			విడుదల(ret);
			తిరిగి ఖాళీ; /* Shouldn't happen */
		}
	}
	విడుదల(tmp);
	తిరిగి ret;
}

/*
 * Assemble a list of algorithms from a default list and a string from a
 * configuration file. The user-provided string may begin with '+' to
 * indicate that it should be appended to the default, '-' that the
 * specified names should be removed, or '^' that they should be placed
 * at the head.
 */
పూర్ణాంకం
kex_assemble_పేర్లు(అక్షరం **listp, స్థిరరాశి అక్షరం *def, స్థిరరాశి అక్షరం *all)
{
	అక్షరం *cp, *tmp, *patterns;
	అక్షరం *list = ఖాళీ, *ret = ఖాళీ, *matching = ఖాళీ, *opatterns = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ (listp == ఖాళీ || def == ఖాళీ || all == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;

	ఒకవేళ (*listp == ఖాళీ || **listp == '\0') {
		ఒకవేళ ((*listp = strdup(def)) == ఖాళీ)
			తిరిగి SSH_ERR_ALLOC_FAIL;
		తిరిగి 0;
	}

	list = *listp;
	*listp = ఖాళీ;
	ఒకవేళ (*list == '+') {
		/* Append names to default list */
		ఒకవేళ ((tmp = kex_పేర్లు_cat(def, list + 1)) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు fail;
		}
		విడుదల(list);
		list = tmp;
	} లేకపోతే ఒకవేళ (*list == '-') {
		/* Remove names from default list */
		ఒకవేళ ((*listp = సరిపోలిక_filter_denylist(def, list + 1)) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు fail;
		}
		విడుదల(list);
		/* filtering has already been done */
		తిరిగి 0;
	} లేకపోతే ఒకవేళ (*list == '^') {
		/* Place names at head of default list */
		ఒకవేళ ((tmp = kex_పేర్లు_cat(list + 1, def)) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు fail;
		}
		విడుదల(list);
		list = tmp;
	} లేకపోతే {
		/* Explicit list, overrides default - just use "list" as is */
	}

	/*
	 * The supplied names may be a pattern-list. For the -list case,
	 * the patterns are applied above. For the +list and explicit list
	 * cases we need to do it now.
	 */
	ret = ఖాళీ;
	ఒకవేళ ((patterns = opatterns = strdup(list)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు fail;
	}
	/* Apply positive (i.e. non-negated) patterns from the list */
	అయితే ((cp = strsep(&patterns, ",")) != ఖాళీ) {
		ఒకవేళ (*cp == '!') {
			/* negated matches are not supported here */
			r = SSH_ERR_INVALID_వాదం;
			వెళ్ళు fail;
		}
		విడుదల(matching);
		ఒకవేళ ((matching = సరిపోలిక_filter_allowlist(all, cp)) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు fail;
		}
		ఒకవేళ ((tmp = kex_పేర్లు_cat(ret, matching)) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు fail;
		}
		విడుదల(ret);
		ret = tmp;
	}
	ఒకవేళ (ret == ఖాళీ || *ret == '\0') {
		/* An empty name-list is an error */
		/* XXX better error code? */
		r = SSH_ERR_INVALID_వాదం;
		వెళ్ళు fail;
	}

	/* success */
	*listp = ret;
	ret = ఖాళీ;
	r = 0;

 fail:
	విడుదల(matching);
	విడుదల(opatterns);
	విడుదల(list);
	విడుదల(ret);
	తిరిగి r;
}
