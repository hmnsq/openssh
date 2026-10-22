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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <signal.h>

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/crypto.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#endif

#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

#ಅನ್ತರ್ಭಾವ "ssherr.h"

ಸಂರಚನಾ kexalg {
	ವರ್ಣ *name;
	u_int type;
	ಪೂರ್ಣಾಙ್ಕ ec_nid;
	ಪೂರ್ಣಾಙ್ಕ hash_alg;
	ಪೂರ್ಣಾಙ್ಕ pq_alg;
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ kexalg kexalgs[] = {
#ifdef WITH_OPENSSL
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
#endif /* WITH_OPENSSL */
#ಯದಿ defined(HAVE_EVP_SHA256) || !defined(WITH_OPENSSL)
	{ KEX_CURVE25519_SHA256, KEX_C25519_SHA256, 0, SSH_DIGEST_SHA256, KEX_NOT_PQ },
	{ KEX_CURVE25519_SHA256_OLD, KEX_C25519_SHA256, 0, SSH_DIGEST_SHA256, KEX_NOT_PQ },
#ifdef USE_SNTRUP761X25519
	{ KEX_SNTRUP761X25519_SHA512, KEX_KEM_SNTRUP761X25519_SHA512, 0,
	    SSH_DIGEST_SHA512, KEX_IS_PQ },
	{ KEX_SNTRUP761X25519_SHA512_OLD, KEX_KEM_SNTRUP761X25519_SHA512, 0,
	    SSH_DIGEST_SHA512, KEX_IS_PQ },
#endif
#ifdef USE_MLKEM768X25519
	{ KEX_MLKEM768X25519_SHA256, KEX_KEM_MLKEM768X25519_SHA256, 0,
	    SSH_DIGEST_SHA256, KEX_IS_PQ },
#endif
#endif /* HAVE_EVP_SHA256 || !WITH_OPENSSL */
	{ ರಿಕ್ತ, 0, -1, -1, 0 },
};

ವರ್ಣ *
kex_alg_list(ವರ್ಣ sep)
{
	ವರ್ಣ *ret = ರಿಕ್ತ;
	ಧ್ರುವ ಸಂರಚನಾ kexalg *k;
	ವರ್ಣ sep_str[2] = {sep, '\0'};

	ಪ್ರತಿ (k = kexalgs; k->name != ರಿಕ್ತ; k++)
		xextendf(&ret, sep_str, "%s", k->name);

	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ kexalg *
kex_alg_by_name(ಧ್ರುವ ವರ್ಣ *name)
{
	ಧ್ರುವ ಸಂರಚನಾ kexalg *k;

	ಪ್ರತಿ (k = kexalgs; k->name != ರಿಕ್ತ; k++) {
		ಯದಿ (strcmp(k->name, name) == 0)
			ಪ್ರತ್ಯಾಗಮ k;
	}
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಪೂರ್ಣಾಙ್ಕ
kex_name_valid(ಧ್ರುವ ವರ್ಣ *name)
{
	ಪ್ರತ್ಯಾಗಮ kex_alg_by_name(name) != ರಿಕ್ತ;
}

ಪೂರ್ಣಾಙ್ಕ
kex_is_pq_from_name(ಧ್ರುವ ವರ್ಣ *name)
{
	ಧ್ರುವ ಸಂರಚನಾ kexalg *k;

	ಯದಿ ((k = kex_alg_by_name(name)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ k->pq_alg == KEX_IS_PQ;
}

u_int
kex_type_from_name(ಧ್ರುವ ವರ್ಣ *name)
{
	ಧ್ರುವ ಸಂರಚನಾ kexalg *k;

	ಯದಿ ((k = kex_alg_by_name(name)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ k->type;
}

ಪೂರ್ಣಾಙ್ಕ
kex_hash_from_name(ಧ್ರುವ ವರ್ಣ *name)
{
	ಧ್ರುವ ಸಂರಚನಾ kexalg *k;

	ಯದಿ ((k = kex_alg_by_name(name)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪ್ರತ್ಯಾಗಮ k->hash_alg;
}

ಪೂರ್ಣಾಙ್ಕ
kex_nid_from_name(ಧ್ರುವ ವರ್ಣ *name)
{
	ಧ್ರುವ ಸಂರಚನಾ kexalg *k;

	ಯದಿ ((k = kex_alg_by_name(name)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪ್ರತ್ಯಾಗಮ k->ec_nid;
}

/* Validate KEX method name list */
ಪೂರ್ಣಾಙ್ಕ
kex_names_valid(ಧ್ರುವ ವರ್ಣ *names)
{
	ವರ್ಣ *s, *cp, *p;

	ಯದಿ (names == ರಿಕ್ತ || strcmp(names, "") == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ ((s = cp = strdup(names)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತಿ ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		ಯದಿ (kex_alg_by_name(p) == ರಿಕ್ತ) {
			error("Unsupported KEX algorithm \"%.100s\"", p);
			ಮುಕ್ತ(s);
			ಪ್ರತ್ಯಾಗಮ 0;
		}
	}
	debug3("kex names ok: [%s]", names);
	ಮುಕ್ತ(s);
	ಪ್ರತ್ಯಾಗಮ 1;
}

/* returns non-zero if proposal contains any algorithm from algs */
ಪೂರ್ಣಾಙ್ಕ
kex_has_any_alg(ಧ್ರುವ ವರ್ಣ *proposal, ಧ್ರುವ ವರ್ಣ *algs)
{
	ವರ್ಣ *cp;

	ಯದಿ ((cp = match_list(proposal, algs, ರಿಕ್ತ)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಮುಕ್ತ(cp);
	ಪ್ರತ್ಯಾಗಮ 1;
}

/*
 * Concatenate algorithm names, avoiding duplicates in the process.
 * Caller must free returned string.
 */
ವರ್ಣ *
kex_names_cat(ಧ್ರುವ ವರ್ಣ *a, ಧ್ರುವ ವರ್ಣ *b)
{
	ವರ್ಣ *ret = ರಿಕ್ತ, *tmp = ರಿಕ್ತ, *cp, *p;
	size_t len;

	ಯದಿ (a == ರಿಕ್ತ || *a == '\0')
		ಪ್ರತ್ಯಾಗಮ strdup(b);
	ಯದಿ (b == ರಿಕ್ತ || *b == '\0')
		ಪ್ರತ್ಯಾಗಮ strdup(a);
	ಯದಿ (strlen(b) > 1024*1024)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	len = strlen(a) + strlen(b) + 2;
	ಯದಿ ((tmp = cp = strdup(b)) == ರಿಕ್ತ ||
	    (ret = calloc(1, len)) == ರಿಕ್ತ) {
		ಮುಕ್ತ(tmp);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	strlcpy(ret, a, len);
	ಪ್ರತಿ ((p = strsep(&cp, ",")); p && *p != '\0'; (p = strsep(&cp, ","))) {
		ಯದಿ (kex_has_any_alg(ret, p))
			ಅನುವರ್ತ; /* Algorithm already present */
		ಯದಿ (strlcat(ret, ",", len) >= len ||
		    strlcat(ret, p, len) >= len) {
			ಮುಕ್ತ(tmp);
			ಮುಕ್ತ(ret);
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ; /* Shouldn't happen */
		}
	}
	ಮುಕ್ತ(tmp);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Assemble a list of algorithms from a default list and a string from a
 * configuration file. The user-provided string may begin with '+' to
 * indicate that it should be appended to the default, '-' that the
 * specified names should be removed, or '^' that they should be placed
 * at the head.
 */
ಪೂರ್ಣಾಙ್ಕ
kex_assemble_names(ವರ್ಣ **listp, ಧ್ರುವ ವರ್ಣ *def, ಧ್ರುವ ವರ್ಣ *all)
{
	ವರ್ಣ *cp, *tmp, *patterns;
	ವರ್ಣ *list = ರಿಕ್ತ, *ret = ರಿಕ್ತ, *matching = ರಿಕ್ತ, *opatterns = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ (listp == ರಿಕ್ತ || def == ರಿಕ್ತ || all == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;

	ಯದಿ (*listp == ರಿಕ್ತ || **listp == '\0') {
		ಯದಿ ((*listp = strdup(def)) == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	list = *listp;
	*listp = ರಿಕ್ತ;
	ಯದಿ (*list == '+') {
		/* Append names to default list */
		ಯದಿ ((tmp = kex_names_cat(def, list + 1)) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ fail;
		}
		ಮುಕ್ತ(list);
		list = tmp;
	} ಅನ್ಯಥಾ ಯದಿ (*list == '-') {
		/* Remove names from default list */
		ಯದಿ ((*listp = match_filter_denylist(def, list + 1)) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ fail;
		}
		ಮುಕ್ತ(list);
		/* filtering has already been done */
		ಪ್ರತ್ಯಾಗಮ 0;
	} ಅನ್ಯಥಾ ಯದಿ (*list == '^') {
		/* Place names at head of default list */
		ಯದಿ ((tmp = kex_names_cat(list + 1, def)) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ fail;
		}
		ಮುಕ್ತ(list);
		list = tmp;
	} ಅನ್ಯಥಾ {
		/* Explicit list, overrides default - just use "list" as is */
	}

	/*
	 * The supplied names may be a pattern-list. For the -list case,
	 * the patterns are applied above. For the +list and explicit list
	 * cases we need to do it now.
	 */
	ret = ರಿಕ್ತ;
	ಯದಿ ((patterns = opatterns = strdup(list)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ fail;
	}
	/* Apply positive (i.e. non-negated) patterns from the list */
	ಯಾವತ್ ((cp = strsep(&patterns, ",")) != ರಿಕ್ತ) {
		ಯದಿ (*cp == '!') {
			/* negated matches are not supported here */
			r = SSH_ERR_INVALID_ARGUMENT;
			ಗಚ್ಛ fail;
		}
		ಮುಕ್ತ(matching);
		ಯದಿ ((matching = match_filter_allowlist(all, cp)) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ fail;
		}
		ಯದಿ ((tmp = kex_names_cat(ret, matching)) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ fail;
		}
		ಮುಕ್ತ(ret);
		ret = tmp;
	}
	ಯದಿ (ret == ರಿಕ್ತ || *ret == '\0') {
		/* An empty name-list is an error */
		/* XXX better error code? */
		r = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ fail;
	}

	/* success */
	*listp = ret;
	ret = ರಿಕ್ತ;
	r = 0;

 fail:
	ಮುಕ್ತ(matching);
	ಮುಕ್ತ(opatterns);
	ಮುಕ್ತ(list);
	ಮುಕ್ತ(ret);
	ಪ್ರತ್ಯಾಗಮ r;
}
