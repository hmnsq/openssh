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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <signal.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/crypto.h>
#அந்தர்பாவ <openssl/evp.h>
#endif

#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "misc.h"

#அந்தர்பாவ "ssherr.h"

கட்டமைப்பு kexalg {
	எழுத்து *name;
	u_int type;
	முழு ec_nid;
	முழு hash_alg;
	முழு pq_alg;
};
நிலையான மாறிலி கட்டமைப்பு kexalg kexalgs[] = {
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
#எனில் defined(HAVE_EVP_SHA256) || !defined(WITH_OPENSSL)
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
	{ வெற்று, 0, -1, -1, 0 },
};

எழுத்து *
kex_alg_list(எழுத்து sep)
{
	எழுத்து *ret = வெற்று;
	மாறிலி கட்டமைப்பு kexalg *k;
	எழுத்து sep_str[2] = {sep, '\0'};

	க்கு (k = kexalgs; k->name != வெற்று; k++)
		xextendf(&ret, sep_str, "%s", k->name);

	திரும்பு ret;
}

நிலையான மாறிலி கட்டமைப்பு kexalg *
kex_alg_by_name(மாறிலி எழுத்து *name)
{
	மாறிலி கட்டமைப்பு kexalg *k;

	க்கு (k = kexalgs; k->name != வெற்று; k++) {
		எனில் (strcmp(k->name, name) == 0)
			திரும்பு k;
	}
	திரும்பு வெற்று;
}

முழு
kex_name_valid(மாறிலி எழுத்து *name)
{
	திரும்பு kex_alg_by_name(name) != வெற்று;
}

முழு
kex_is_pq_from_name(மாறிலி எழுத்து *name)
{
	மாறிலி கட்டமைப்பு kexalg *k;

	எனில் ((k = kex_alg_by_name(name)) == வெற்று)
		திரும்பு 0;
	திரும்பு k->pq_alg == KEX_IS_PQ;
}

u_int
kex_type_from_name(மாறிலி எழுத்து *name)
{
	மாறிலி கட்டமைப்பு kexalg *k;

	எனில் ((k = kex_alg_by_name(name)) == வெற்று)
		திரும்பு 0;
	திரும்பு k->type;
}

முழு
kex_hash_from_name(மாறிலி எழுத்து *name)
{
	மாறிலி கட்டமைப்பு kexalg *k;

	எனில் ((k = kex_alg_by_name(name)) == வெற்று)
		திரும்பு -1;
	திரும்பு k->hash_alg;
}

முழு
kex_nid_from_name(மாறிலி எழுத்து *name)
{
	மாறிலி கட்டமைப்பு kexalg *k;

	எனில் ((k = kex_alg_by_name(name)) == வெற்று)
		திரும்பு -1;
	திரும்பு k->ec_nid;
}

/* Validate KEX method name list */
முழு
kex_names_valid(மாறிலி எழுத்து *names)
{
	எழுத்து *s, *cp, *p;

	எனில் (names == வெற்று || strcmp(names, "") == 0)
		திரும்பு 0;
	எனில் ((s = cp = strdup(names)) == வெற்று)
		திரும்பு 0;
	க்கு ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		எனில் (kex_alg_by_name(p) == வெற்று) {
			error("Unsupported KEX algorithm \"%.100s\"", p);
			விடுவி(s);
			திரும்பு 0;
		}
	}
	debug3("kex names ok: [%s]", names);
	விடுவி(s);
	திரும்பு 1;
}

/* returns non-zero if proposal contains any algorithm from algs */
முழு
kex_has_any_alg(மாறிலி எழுத்து *proposal, மாறிலி எழுத்து *algs)
{
	எழுத்து *cp;

	எனில் ((cp = match_list(proposal, algs, வெற்று)) == வெற்று)
		திரும்பு 0;
	விடுவி(cp);
	திரும்பு 1;
}

/*
 * Concatenate algorithm names, avoiding duplicates in the process.
 * Caller must free returned string.
 */
எழுத்து *
kex_names_cat(மாறிலி எழுத்து *a, மாறிலி எழுத்து *b)
{
	எழுத்து *ret = வெற்று, *tmp = வெற்று, *cp, *p;
	size_t len;

	எனில் (a == வெற்று || *a == '\0')
		திரும்பு strdup(b);
	எனில் (b == வெற்று || *b == '\0')
		திரும்பு strdup(a);
	எனில் (strlen(b) > 1024*1024)
		திரும்பு வெற்று;
	len = strlen(a) + strlen(b) + 2;
	எனில் ((tmp = cp = strdup(b)) == வெற்று ||
	    (ret = calloc(1, len)) == வெற்று) {
		விடுவி(tmp);
		திரும்பு வெற்று;
	}
	strlcpy(ret, a, len);
	க்கு ((p = strsep(&cp, ",")); p && *p != '\0'; (p = strsep(&cp, ","))) {
		எனில் (kex_has_any_alg(ret, p))
			தொடர்; /* Algorithm already present */
		எனில் (strlcat(ret, ",", len) >= len ||
		    strlcat(ret, p, len) >= len) {
			விடுவி(tmp);
			விடுவி(ret);
			திரும்பு வெற்று; /* Shouldn't happen */
		}
	}
	விடுவி(tmp);
	திரும்பு ret;
}

/*
 * Assemble a list of algorithms from a default list and a string from a
 * configuration file. The user-provided string may begin with '+' to
 * indicate that it should be appended to the default, '-' that the
 * specified names should be removed, or '^' that they should be placed
 * at the head.
 */
முழு
kex_assemble_names(எழுத்து **listp, மாறிலி எழுத்து *def, மாறிலி எழுத்து *all)
{
	எழுத்து *cp, *tmp, *patterns;
	எழுத்து *list = வெற்று, *ret = வெற்று, *matching = வெற்று, *opatterns = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	எனில் (listp == வெற்று || def == வெற்று || all == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;

	எனில் (*listp == வெற்று || **listp == '\0') {
		எனில் ((*listp = strdup(def)) == வெற்று)
			திரும்பு SSH_ERR_ALLOC_FAIL;
		திரும்பு 0;
	}

	list = *listp;
	*listp = வெற்று;
	எனில் (*list == '+') {
		/* Append names to default list */
		எனில் ((tmp = kex_names_cat(def, list + 1)) == வெற்று) {
			r = SSH_ERR_ALLOC_FAIL;
			செல் fail;
		}
		விடுவி(list);
		list = tmp;
	} இல்லையெனில் எனில் (*list == '-') {
		/* Remove names from default list */
		எனில் ((*listp = match_filter_denylist(def, list + 1)) == வெற்று) {
			r = SSH_ERR_ALLOC_FAIL;
			செல் fail;
		}
		விடுவி(list);
		/* filtering has already been done */
		திரும்பு 0;
	} இல்லையெனில் எனில் (*list == '^') {
		/* Place names at head of default list */
		எனில் ((tmp = kex_names_cat(list + 1, def)) == வெற்று) {
			r = SSH_ERR_ALLOC_FAIL;
			செல் fail;
		}
		விடுவி(list);
		list = tmp;
	} இல்லையெனில் {
		/* Explicit list, overrides default - just use "list" as is */
	}

	/*
	 * The supplied names may be a pattern-list. For the -list case,
	 * the patterns are applied above. For the +list and explicit list
	 * cases we need to do it now.
	 */
	ret = வெற்று;
	எனில் ((patterns = opatterns = strdup(list)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் fail;
	}
	/* Apply positive (i.e. non-negated) patterns from the list */
	போது ((cp = strsep(&patterns, ",")) != வெற்று) {
		எனில் (*cp == '!') {
			/* negated matches are not supported here */
			r = SSH_ERR_INVALID_ARGUMENT;
			செல் fail;
		}
		விடுவி(matching);
		எனில் ((matching = match_filter_allowlist(all, cp)) == வெற்று) {
			r = SSH_ERR_ALLOC_FAIL;
			செல் fail;
		}
		எனில் ((tmp = kex_names_cat(ret, matching)) == வெற்று) {
			r = SSH_ERR_ALLOC_FAIL;
			செல் fail;
		}
		விடுவி(ret);
		ret = tmp;
	}
	எனில் (ret == வெற்று || *ret == '\0') {
		/* An empty name-list is an error */
		/* XXX better error code? */
		r = SSH_ERR_INVALID_ARGUMENT;
		செல் fail;
	}

	/* success */
	*listp = ret;
	ret = வெற்று;
	r = 0;

 fail:
	விடுவி(matching);
	விடுவி(opatterns);
	விடுவி(list);
	விடுவி(ret);
	திரும்பு r;
}
