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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <signal.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাৱ <openssl/crypto.h>
#অন্তর্ভাৱ <openssl/evp.h>
#endif

#অন্তর্ভাৱ "kex.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "match.h"
#অন্তর্ভাৱ "digest.h"
#অন্তর্ভাৱ "misc.h"

#অন্তর্ভাৱ "ssherr.h"

সংরচনা kexalg {
	ৱর্ণ *name;
	u_int type;
	পূর্ণাঙ্ক ec_nid;
	পূর্ণাঙ্ক hash_alg;
	পূর্ণাঙ্ক pq_alg;
};
স্থির ধ্রুৱ সংরচনা kexalg kexalgs[] = {
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
#যদি defined(HAVE_EVP_SHA256) || !defined(WITH_OPENSSL)
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
	{ রিক্ত, 0, -1, -1, 0 },
};

ৱর্ণ *
kex_alg_list(ৱর্ণ sep)
{
	ৱর্ণ *ret = রিক্ত;
	ধ্রুৱ সংরচনা kexalg *k;
	ৱর্ণ sep_str[2] = {sep, '\0'};

	বাবে (k = kexalgs; k->name != রিক্ত; k++)
		xextendf(&ret, sep_str, "%s", k->name);

	ঘূৰাই ret;
}

স্থির ধ্রুৱ সংরচনা kexalg *
kex_alg_by_name(ধ্রুৱ ৱর্ণ *name)
{
	ধ্রুৱ সংরচনা kexalg *k;

	বাবে (k = kexalgs; k->name != রিক্ত; k++) {
		যদি (strcmp(k->name, name) == 0)
			ঘূৰাই k;
	}
	ঘূৰাই রিক্ত;
}

পূর্ণাঙ্ক
kex_name_valid(ধ্রুৱ ৱর্ণ *name)
{
	ঘূৰাই kex_alg_by_name(name) != রিক্ত;
}

পূর্ণাঙ্ক
kex_is_pq_from_name(ধ্রুৱ ৱর্ণ *name)
{
	ধ্রুৱ সংরচনা kexalg *k;

	যদি ((k = kex_alg_by_name(name)) == রিক্ত)
		ঘূৰাই 0;
	ঘূৰাই k->pq_alg == KEX_IS_PQ;
}

u_int
kex_type_from_name(ধ্রুৱ ৱর্ণ *name)
{
	ধ্রুৱ সংরচনা kexalg *k;

	যদি ((k = kex_alg_by_name(name)) == রিক্ত)
		ঘূৰাই 0;
	ঘূৰাই k->type;
}

পূর্ণাঙ্ক
kex_hash_from_name(ধ্রুৱ ৱর্ণ *name)
{
	ধ্রুৱ সংরচনা kexalg *k;

	যদি ((k = kex_alg_by_name(name)) == রিক্ত)
		ঘূৰাই -1;
	ঘূৰাই k->hash_alg;
}

পূর্ণাঙ্ক
kex_nid_from_name(ধ্রুৱ ৱর্ণ *name)
{
	ধ্রুৱ সংরচনা kexalg *k;

	যদি ((k = kex_alg_by_name(name)) == রিক্ত)
		ঘূৰাই -1;
	ঘূৰাই k->ec_nid;
}

/* Validate KEX method name list */
পূর্ণাঙ্ক
kex_names_valid(ধ্রুৱ ৱর্ণ *names)
{
	ৱর্ণ *s, *cp, *p;

	যদি (names == রিক্ত || strcmp(names, "") == 0)
		ঘূৰাই 0;
	যদি ((s = cp = strdup(names)) == রিক্ত)
		ঘূৰাই 0;
	বাবে ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		যদি (kex_alg_by_name(p) == রিক্ত) {
			error("Unsupported KEX algorithm \"%.100s\"", p);
			মুক্ত(s);
			ঘূৰাই 0;
		}
	}
	debug3("kex names ok: [%s]", names);
	মুক্ত(s);
	ঘূৰাই 1;
}

/* returns non-zero if proposal contains any algorithm from algs */
পূর্ণাঙ্ক
kex_has_any_alg(ধ্রুৱ ৱর্ণ *proposal, ধ্রুৱ ৱর্ণ *algs)
{
	ৱর্ণ *cp;

	যদি ((cp = match_list(proposal, algs, রিক্ত)) == রিক্ত)
		ঘূৰাই 0;
	মুক্ত(cp);
	ঘূৰাই 1;
}

/*
 * Concatenate algorithm names, avoiding duplicates in the process.
 * Caller must free returned string.
 */
ৱর্ণ *
kex_names_cat(ধ্রুৱ ৱর্ণ *a, ধ্রুৱ ৱর্ণ *b)
{
	ৱর্ণ *ret = রিক্ত, *tmp = রিক্ত, *cp, *p;
	size_t len;

	যদি (a == রিক্ত || *a == '\0')
		ঘূৰাই strdup(b);
	যদি (b == রিক্ত || *b == '\0')
		ঘূৰাই strdup(a);
	যদি (strlen(b) > 1024*1024)
		ঘূৰাই রিক্ত;
	len = strlen(a) + strlen(b) + 2;
	যদি ((tmp = cp = strdup(b)) == রিক্ত ||
	    (ret = calloc(1, len)) == রিক্ত) {
		মুক্ত(tmp);
		ঘূৰাই রিক্ত;
	}
	strlcpy(ret, a, len);
	বাবে ((p = strsep(&cp, ",")); p && *p != '\0'; (p = strsep(&cp, ","))) {
		যদি (kex_has_any_alg(ret, p))
			অনুৱর্ত; /* Algorithm already present */
		যদি (strlcat(ret, ",", len) >= len ||
		    strlcat(ret, p, len) >= len) {
			মুক্ত(tmp);
			মুক্ত(ret);
			ঘূৰাই রিক্ত; /* Shouldn't happen */
		}
	}
	মুক্ত(tmp);
	ঘূৰাই ret;
}

/*
 * Assemble a list of algorithms from a default list and a string from a
 * configuration file. The user-provided string may begin with '+' to
 * indicate that it should be appended to the default, '-' that the
 * specified names should be removed, or '^' that they should be placed
 * at the head.
 */
পূর্ণাঙ্ক
kex_assemble_names(ৱর্ণ **listp, ধ্রুৱ ৱর্ণ *def, ধ্রুৱ ৱর্ণ *all)
{
	ৱর্ণ *cp, *tmp, *patterns;
	ৱর্ণ *list = রিক্ত, *ret = রিক্ত, *matching = রিক্ত, *opatterns = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	যদি (listp == রিক্ত || def == রিক্ত || all == রিক্ত)
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;

	যদি (*listp == রিক্ত || **listp == '\0') {
		যদি ((*listp = strdup(def)) == রিক্ত)
			ঘূৰাই SSH_ERR_ALLOC_FAIL;
		ঘূৰাই 0;
	}

	list = *listp;
	*listp = রিক্ত;
	যদি (*list == '+') {
		/* Append names to default list */
		যদি ((tmp = kex_names_cat(def, list + 1)) == রিক্ত) {
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ fail;
		}
		মুক্ত(list);
		list = tmp;
	} অন্যথা যদি (*list == '-') {
		/* Remove names from default list */
		যদি ((*listp = match_filter_denylist(def, list + 1)) == রিক্ত) {
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ fail;
		}
		মুক্ত(list);
		/* filtering has already been done */
		ঘূৰাই 0;
	} অন্যথা যদি (*list == '^') {
		/* Place names at head of default list */
		যদি ((tmp = kex_names_cat(list + 1, def)) == রিক্ত) {
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ fail;
		}
		মুক্ত(list);
		list = tmp;
	} অন্যথা {
		/* Explicit list, overrides default - just use "list" as is */
	}

	/*
	 * The supplied names may be a pattern-list. For the -list case,
	 * the patterns are applied above. For the +list and explicit list
	 * cases we need to do it now.
	 */
	ret = রিক্ত;
	যদি ((patterns = opatterns = strdup(list)) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ fail;
	}
	/* Apply positive (i.e. non-negated) patterns from the list */
	যেতিয়ালৈ ((cp = strsep(&patterns, ",")) != রিক্ত) {
		যদি (*cp == '!') {
			/* negated matches are not supported here */
			r = SSH_ERR_INVALID_ARGUMENT;
			গচ্ছ fail;
		}
		মুক্ত(matching);
		যদি ((matching = match_filter_allowlist(all, cp)) == রিক্ত) {
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ fail;
		}
		যদি ((tmp = kex_names_cat(ret, matching)) == রিক্ত) {
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ fail;
		}
		মুক্ত(ret);
		ret = tmp;
	}
	যদি (ret == রিক্ত || *ret == '\0') {
		/* An empty name-list is an error */
		/* XXX better error code? */
		r = SSH_ERR_INVALID_ARGUMENT;
		গচ্ছ fail;
	}

	/* success */
	*listp = ret;
	ret = রিক্ত;
	r = 0;

 fail:
	মুক্ত(matching);
	মুক্ত(opatterns);
	মুক্ত(list);
	মুক্ত(ret);
	ঘূৰাই r;
}
