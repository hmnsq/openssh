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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <signal.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/crypto.h>
#অন্তর্ভাব <openssl/evp.h>
#endif

#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "misc.h"

#অন্তর্ভাব "ssherr.h"

কাঠামো kexalg {
	অক্ষর *name;
	u_int type;
	পূর্ণসংখ্যা ec_nid;
	পূর্ণসংখ্যা hash_alg;
	পূর্ণসংখ্যা pq_alg;
};
স্থির ধ্রুবক কাঠামো kexalg kexalgs[] = {
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
	{ ফাঁকা, 0, -1, -1, 0 },
};

অক্ষর *
kex_alg_list(অক্ষর sep)
{
	অক্ষর *ret = ফাঁকা;
	ধ্রুবক কাঠামো kexalg *k;
	অক্ষর sep_str[2] = {sep, '\0'};

	জন্য (k = kexalgs; k->name != ফাঁকা; k++)
		xextendf(&ret, sep_str, "%s", k->name);

	ফেরত ret;
}

স্থির ধ্রুবক কাঠামো kexalg *
kex_alg_by_name(ধ্রুবক অক্ষর *name)
{
	ধ্রুবক কাঠামো kexalg *k;

	জন্য (k = kexalgs; k->name != ফাঁকা; k++) {
		যদি (strcmp(k->name, name) == 0)
			ফেরত k;
	}
	ফেরত ফাঁকা;
}

পূর্ণসংখ্যা
kex_name_valid(ধ্রুবক অক্ষর *name)
{
	ফেরত kex_alg_by_name(name) != ফাঁকা;
}

পূর্ণসংখ্যা
kex_is_pq_from_name(ধ্রুবক অক্ষর *name)
{
	ধ্রুবক কাঠামো kexalg *k;

	যদি ((k = kex_alg_by_name(name)) == ফাঁকা)
		ফেরত 0;
	ফেরত k->pq_alg == KEX_IS_PQ;
}

u_int
kex_type_from_name(ধ্রুবক অক্ষর *name)
{
	ধ্রুবক কাঠামো kexalg *k;

	যদি ((k = kex_alg_by_name(name)) == ফাঁকা)
		ফেরত 0;
	ফেরত k->type;
}

পূর্ণসংখ্যা
kex_hash_from_name(ধ্রুবক অক্ষর *name)
{
	ধ্রুবক কাঠামো kexalg *k;

	যদি ((k = kex_alg_by_name(name)) == ফাঁকা)
		ফেরত -1;
	ফেরত k->hash_alg;
}

পূর্ণসংখ্যা
kex_nid_from_name(ধ্রুবক অক্ষর *name)
{
	ধ্রুবক কাঠামো kexalg *k;

	যদি ((k = kex_alg_by_name(name)) == ফাঁকা)
		ফেরত -1;
	ফেরত k->ec_nid;
}

/* Validate KEX method name list */
পূর্ণসংখ্যা
kex_names_valid(ধ্রুবক অক্ষর *names)
{
	অক্ষর *s, *cp, *p;

	যদি (names == ফাঁকা || strcmp(names, "") == 0)
		ফেরত 0;
	যদি ((s = cp = strdup(names)) == ফাঁকা)
		ফেরত 0;
	জন্য ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		যদি (kex_alg_by_name(p) == ফাঁকা) {
			error("Unsupported KEX algorithm \"%.100s\"", p);
			মুক্ত(s);
			ফেরত 0;
		}
	}
	debug3("kex names ok: [%s]", names);
	মুক্ত(s);
	ফেরত 1;
}

/* returns non-zero if proposal contains any algorithm from algs */
পূর্ণসংখ্যা
kex_has_any_alg(ধ্রুবক অক্ষর *proposal, ধ্রুবক অক্ষর *algs)
{
	অক্ষর *cp;

	যদি ((cp = match_list(proposal, algs, ফাঁকা)) == ফাঁকা)
		ফেরত 0;
	মুক্ত(cp);
	ফেরত 1;
}

/*
 * Concatenate algorithm names, avoiding duplicates in the process.
 * Caller must free returned string.
 */
অক্ষর *
kex_names_cat(ধ্রুবক অক্ষর *a, ধ্রুবক অক্ষর *b)
{
	অক্ষর *ret = ফাঁকা, *tmp = ফাঁকা, *cp, *p;
	আকার_t len;

	যদি (a == ফাঁকা || *a == '\0')
		ফেরত strdup(b);
	যদি (b == ফাঁকা || *b == '\0')
		ফেরত strdup(a);
	যদি (strlen(b) > 1024*1024)
		ফেরত ফাঁকা;
	len = strlen(a) + strlen(b) + 2;
	যদি ((tmp = cp = strdup(b)) == ফাঁকা ||
	    (ret = calloc(1, len)) == ফাঁকা) {
		মুক্ত(tmp);
		ফেরত ফাঁকা;
	}
	strlcpy(ret, a, len);
	জন্য ((p = strsep(&cp, ",")); p && *p != '\0'; (p = strsep(&cp, ","))) {
		যদি (kex_has_any_alg(ret, p))
			চালু; /* Algorithm already present */
		যদি (strlcat(ret, ",", len) >= len ||
		    strlcat(ret, p, len) >= len) {
			মুক্ত(tmp);
			মুক্ত(ret);
			ফেরত ফাঁকা; /* Shouldn't happen */
		}
	}
	মুক্ত(tmp);
	ফেরত ret;
}

/*
 * Assemble a list of algorithms from a default list and a string from a
 * configuration file. The user-provided string may begin with '+' to
 * indicate that it should be appended to the default, '-' that the
 * specified names should be removed, or '^' that they should be placed
 * at the head.
 */
পূর্ণসংখ্যা
kex_assemble_names(অক্ষর **listp, ধ্রুবক অক্ষর *def, ধ্রুবক অক্ষর *all)
{
	অক্ষর *cp, *tmp, *patterns;
	অক্ষর *list = ফাঁকা, *ret = ফাঁকা, *matching = ফাঁকা, *opatterns = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	যদি (listp == ফাঁকা || def == ফাঁকা || all == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;

	যদি (*listp == ফাঁকা || **listp == '\0') {
		যদি ((*listp = strdup(def)) == ফাঁকা)
			ফেরত SSH_ERR_ALLOC_FAIL;
		ফেরত 0;
	}

	list = *listp;
	*listp = ফাঁকা;
	যদি (*list == '+') {
		/* Append names to default list */
		যদি ((tmp = kex_names_cat(def, list + 1)) == ফাঁকা) {
			r = SSH_ERR_ALLOC_FAIL;
			যাও fail;
		}
		মুক্ত(list);
		list = tmp;
	} অন্যথা যদি (*list == '-') {
		/* Remove names from default list */
		যদি ((*listp = match_filter_denylist(def, list + 1)) == ফাঁকা) {
			r = SSH_ERR_ALLOC_FAIL;
			যাও fail;
		}
		মুক্ত(list);
		/* filtering has already been done */
		ফেরত 0;
	} অন্যথা যদি (*list == '^') {
		/* Place names at head of default list */
		যদি ((tmp = kex_names_cat(list + 1, def)) == ফাঁকা) {
			r = SSH_ERR_ALLOC_FAIL;
			যাও fail;
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
	ret = ফাঁকা;
	যদি ((patterns = opatterns = strdup(list)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও fail;
	}
	/* Apply positive (i.e. non-negated) patterns from the list */
	যখন ((cp = strsep(&patterns, ",")) != ফাঁকা) {
		যদি (*cp == '!') {
			/* negated matches are not supported here */
			r = SSH_ERR_INVALID_ARGUMENT;
			যাও fail;
		}
		মুক্ত(matching);
		যদি ((matching = match_filter_allowlist(all, cp)) == ফাঁকা) {
			r = SSH_ERR_ALLOC_FAIL;
			যাও fail;
		}
		যদি ((tmp = kex_names_cat(ret, matching)) == ফাঁকা) {
			r = SSH_ERR_ALLOC_FAIL;
			যাও fail;
		}
		মুক্ত(ret);
		ret = tmp;
	}
	যদি (ret == ফাঁকা || *ret == '\0') {
		/* An empty name-list is an error */
		/* XXX better error code? */
		r = SSH_ERR_INVALID_ARGUMENT;
		যাও fail;
	}

	/* success */
	*listp = ret;
	ret = ফাঁকা;
	r = 0;

 fail:
	মুক্ত(matching);
	মুক্ত(opatterns);
	মুক্ত(list);
	মুক্ত(ret);
	ফেরত r;
}
