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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/crypto.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

#ಅನ್ತರ್ಭಾವ "ssherr.h"

ರಚನೆ kexalg {
	ಅಕ್ಷರ *name;
	u_int type;
	ಪೂರ್ಣಾಂಕ ec_nid;
	ಪೂರ್ಣಾಂಕ hash_alg;
	ಪೂರ್ಣಾಂಕ pq_alg;
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ kexalg kexalgs[] = {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
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
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
#ಆದರೆ defined(HAVE_EVP_SHA256) || !defined(WITH_OPENSSL)
	{ KEX_CURVE25519_SHA256, KEX_C25519_SHA256, 0, SSH_DIGEST_SHA256, KEX_NOT_PQ },
	{ KEX_CURVE25519_SHA256_OLD, KEX_C25519_SHA256, 0, SSH_DIGEST_SHA256, KEX_NOT_PQ },
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_SNTRUP761X25519
	{ KEX_SNTRUP761X25519_SHA512, KEX_KEM_SNTRUP761X25519_SHA512, 0,
	    SSH_DIGEST_SHA512, KEX_IS_PQ },
	{ KEX_SNTRUP761X25519_SHA512_OLD, KEX_KEM_SNTRUP761X25519_SHA512, 0,
	    SSH_DIGEST_SHA512, KEX_IS_PQ },
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_MLKEM768X25519
	{ KEX_MLKEM768X25519_SHA256, KEX_KEM_MLKEM768X25519_SHA256, 0,
	    SSH_DIGEST_SHA256, KEX_IS_PQ },
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_EVP_SHA256 || !WITH_OPENSSL */
	{ ಖಾಲಿ, 0, -1, -1, 0 },
};

ಅಕ್ಷರ *
kex_alg_list(ಅಕ್ಷರ sep)
{
	ಅಕ್ಷರ *ret = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ರಚನೆ kexalg *k;
	ಅಕ್ಷರ sep_str[2] = {sep, '\0'};

	ಗಾಗಿ (k = kexalgs; k->name != ಖಾಲಿ; k++)
		xextendf(&ret, sep_str, "%s", k->name);

	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ kexalg *
kex_alg_by_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ kexalg *k;

	ಗಾಗಿ (k = kexalgs; k->name != ಖಾಲಿ; k++) {
		ಆದರೆ (strcmp(k->name, name) == 0)
			ಹಿಂತಿರುಗಿ k;
	}
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಪೂರ್ಣಾಂಕ
kex_name_valid(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಹಿಂತಿರುಗಿ kex_alg_by_name(name) != ಖಾಲಿ;
}

ಪೂರ್ಣಾಂಕ
kex_is_pq_from_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ kexalg *k;

	ಆದರೆ ((k = kex_alg_by_name(name)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ k->pq_alg == KEX_IS_PQ;
}

u_int
kex_type_from_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ kexalg *k;

	ಆದರೆ ((k = kex_alg_by_name(name)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ k->type;
}

ಪೂರ್ಣಾಂಕ
kex_hash_from_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ kexalg *k;

	ಆದರೆ ((k = kex_alg_by_name(name)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;
	ಹಿಂತಿರುಗಿ k->hash_alg;
}

ಪೂರ್ಣಾಂಕ
kex_nid_from_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ kexalg *k;

	ಆದರೆ ((k = kex_alg_by_name(name)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;
	ಹಿಂತಿರುಗಿ k->ec_nid;
}

/* Validate KEX method name list */
ಪೂರ್ಣಾಂಕ
kex_ಹೆಸರುಗಳು_valid(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಹೆಸರುಗಳು)
{
	ಅಕ್ಷರ *s, *cp, *p;

	ಆದರೆ (ಹೆಸರುಗಳು == ಖಾಲಿ || strcmp(ಹೆಸರುಗಳು, "") == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ ((s = cp = strdup(ಹೆಸರುಗಳು)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಗಾಗಿ ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		ಆದರೆ (kex_alg_by_name(p) == ಖಾಲಿ) {
			error("Unsupported KEX algorithm \"%.100s\"", p);
			ಬಿಡುಗಡೆ(s);
			ಹಿಂತಿರುಗಿ 0;
		}
	}
	debug3("kex names ok: [%s]", ಹೆಸರುಗಳು);
	ಬಿಡುಗಡೆ(s);
	ಹಿಂತಿರುಗಿ 1;
}

/* returns non-zero if proposal contains any algorithm from algs */
ಪೂರ್ಣಾಂಕ
kex_has_any_alg(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *proposal, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *algs)
{
	ಅಕ್ಷರ *cp;

	ಆದರೆ ((cp = ಹೊಂದಿಕೆ_list(proposal, algs, ಖಾಲಿ)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಬಿಡುಗಡೆ(cp);
	ಹಿಂತಿರುಗಿ 1;
}

/*
 * Concatenate algorithm names, avoiding duplicates in the process.
 * Caller must free returned string.
 */
ಅಕ್ಷರ *
kex_ಹೆಸರುಗಳು_cat(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *a, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *b)
{
	ಅಕ್ಷರ *ret = ಖಾಲಿ, *tmp = ಖಾಲಿ, *cp, *p;
	ಗಾತ್ರ_t len;

	ಆದರೆ (a == ಖಾಲಿ || *a == '\0')
		ಹಿಂತಿರುಗಿ strdup(b);
	ಆದರೆ (b == ಖಾಲಿ || *b == '\0')
		ಹಿಂತಿರುಗಿ strdup(a);
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(b) > 1024*1024)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(a) + ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(b) + 2;
	ಆದರೆ ((tmp = cp = strdup(b)) == ಖಾಲಿ ||
	    (ret = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, len)) == ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(tmp);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	strlcpy(ret, a, len);
	ಗಾಗಿ ((p = strsep(&cp, ",")); p && *p != '\0'; (p = strsep(&cp, ","))) {
		ಆದರೆ (kex_has_any_alg(ret, p))
			ಮುಂದುವರಿ; /* Algorithm already present */
		ಆದರೆ (strlcat(ret, ",", len) >= len ||
		    strlcat(ret, p, len) >= len) {
			ಬಿಡುಗಡೆ(tmp);
			ಬಿಡುಗಡೆ(ret);
			ಹಿಂತಿರುಗಿ ಖಾಲಿ; /* Shouldn't happen */
		}
	}
	ಬಿಡುಗಡೆ(tmp);
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Assemble a list of algorithms from a default list and a string from a
 * configuration file. The user-provided string may begin with '+' to
 * indicate that it should be appended to the default, '-' that the
 * specified names should be removed, or '^' that they should be placed
 * at the head.
 */
ಪೂರ್ಣಾಂಕ
kex_assemble_ಹೆಸರುಗಳು(ಅಕ್ಷರ **listp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *def, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *all)
{
	ಅಕ್ಷರ *cp, *tmp, *patterns;
	ಅಕ್ಷರ *list = ಖಾಲಿ, *ret = ಖಾಲಿ, *matching = ಖಾಲಿ, *opatterns = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ (listp == ಖಾಲಿ || def == ಖಾಲಿ || all == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;

	ಆದರೆ (*listp == ಖಾಲಿ || **listp == '\0') {
		ಆದರೆ ((*listp = strdup(def)) == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
		ಹಿಂತಿರುಗಿ 0;
	}

	list = *listp;
	*listp = ಖಾಲಿ;
	ಆದರೆ (*list == '+') {
		/* Append names to default list */
		ಆದರೆ ((tmp = kex_ಹೆಸರುಗಳು_cat(def, list + 1)) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು fail;
		}
		ಬಿಡುಗಡೆ(list);
		list = tmp;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*list == '-') {
		/* Remove names from default list */
		ಆದರೆ ((*listp = ಹೊಂದಿಕೆ_filter_denylist(def, list + 1)) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು fail;
		}
		ಬಿಡುಗಡೆ(list);
		/* filtering has already been done */
		ಹಿಂತಿರುಗಿ 0;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (*list == '^') {
		/* Place names at head of default list */
		ಆದರೆ ((tmp = kex_ಹೆಸರುಗಳು_cat(list + 1, def)) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು fail;
		}
		ಬಿಡುಗಡೆ(list);
		list = tmp;
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* Explicit list, overrides default - just use "list" as is */
	}

	/*
	 * The supplied names may be a pattern-list. For the -list case,
	 * the patterns are applied above. For the +list and explicit list
	 * cases we need to do it now.
	 */
	ret = ಖಾಲಿ;
	ಆದರೆ ((patterns = opatterns = strdup(list)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು fail;
	}
	/* Apply positive (i.e. non-negated) patterns from the list */
	ಆಗ ((cp = strsep(&patterns, ",")) != ಖಾಲಿ) {
		ಆದರೆ (*cp == '!') {
			/* negated matches are not supported here */
			r = SSH_ERR_INVALID_ವಾದ;
			ಹೋಗು fail;
		}
		ಬಿಡುಗಡೆ(matching);
		ಆದರೆ ((matching = ಹೊಂದಿಕೆ_filter_allowlist(all, cp)) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು fail;
		}
		ಆದರೆ ((tmp = kex_ಹೆಸರುಗಳು_cat(ret, matching)) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು fail;
		}
		ಬಿಡುಗಡೆ(ret);
		ret = tmp;
	}
	ಆದರೆ (ret == ಖಾಲಿ || *ret == '\0') {
		/* An empty name-list is an error */
		/* XXX better error code? */
		r = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು fail;
	}

	/* success */
	*listp = ret;
	ret = ಖಾಲಿ;
	r = 0;

 fail:
	ಬಿಡುಗಡೆ(matching);
	ಬಿಡುಗಡೆ(opatterns);
	ಬಿಡುಗಡೆ(list);
	ಬಿಡುಗಡೆ(ret);
	ಹಿಂತಿರುಗಿ r;
}
