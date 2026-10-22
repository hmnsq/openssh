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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/crypto.h>
#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>
#endif

#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"

#ଅନ୍ତର୍ଭାଵ "ssherr.h"

ସଂରଚନା kexalg {
	ଅକ୍ଷର *name;
	u_int type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ec_nid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା hash_alg;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା pq_alg;
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା kexalg kexalgs[] = {
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
#ଯଦି defined(HAVE_EVP_SHA256) || !defined(WITH_OPENSSL)
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
	{ ଖାଲି, 0, -1, -1, 0 },
};

ଅକ୍ଷର *
kex_alg_list(ଅକ୍ଷର sep)
{
	ଅକ୍ଷର *ret = ଖାଲି;
	ଅଚଳ ସଂରଚନା kexalg *k;
	ଅକ୍ଷର sep_str[2] = {sep, '\0'};

	ପାଇଁ (k = kexalgs; k->name != ଖାଲି; k++)
		xextendf(&ret, sep_str, "%s", k->name);

	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ଅଚଳ ସଂରଚନା kexalg *
kex_alg_by_name(ଅଚଳ ଅକ୍ଷର *name)
{
	ଅଚଳ ସଂରଚନା kexalg *k;

	ପାଇଁ (k = kexalgs; k->name != ଖାଲି; k++) {
		ଯଦି (strcmp(k->name, name) == 0)
			ଫେରନ୍ତୁ k;
	}
	ଫେରନ୍ତୁ ଖାଲି;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_name_valid(ଅଚଳ ଅକ୍ଷର *name)
{
	ଫେରନ୍ତୁ kex_alg_by_name(name) != ଖାଲି;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_is_pq_from_name(ଅଚଳ ଅକ୍ଷର *name)
{
	ଅଚଳ ସଂରଚନା kexalg *k;

	ଯଦି ((k = kex_alg_by_name(name)) == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ k->pq_alg == KEX_IS_PQ;
}

u_int
kex_type_from_name(ଅଚଳ ଅକ୍ଷର *name)
{
	ଅଚଳ ସଂରଚନା kexalg *k;

	ଯଦି ((k = kex_alg_by_name(name)) == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ k->type;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_hash_from_name(ଅଚଳ ଅକ୍ଷର *name)
{
	ଅଚଳ ସଂରଚନା kexalg *k;

	ଯଦି ((k = kex_alg_by_name(name)) == ଖାଲି)
		ଫେରନ୍ତୁ -1;
	ଫେରନ୍ତୁ k->hash_alg;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_nid_from_name(ଅଚଳ ଅକ୍ଷର *name)
{
	ଅଚଳ ସଂରଚନା kexalg *k;

	ଯଦି ((k = kex_alg_by_name(name)) == ଖାଲି)
		ଫେରନ୍ତୁ -1;
	ଫେରନ୍ତୁ k->ec_nid;
}

/* Validate KEX method name list */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_names_valid(ଅଚଳ ଅକ୍ଷର *names)
{
	ଅକ୍ଷର *s, *cp, *p;

	ଯଦି (names == ଖାଲି || strcmp(names, "") == 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି ((s = cp = strdup(names)) == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ପାଇଁ ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		ଯଦି (kex_alg_by_name(p) == ଖାଲି) {
			error("Unsupported KEX algorithm \"%.100s\"", p);
			ମୁକ୍ତ(s);
			ଫେରନ୍ତୁ 0;
		}
	}
	debug3("kex names ok: [%s]", names);
	ମୁକ୍ତ(s);
	ଫେରନ୍ତୁ 1;
}

/* returns non-zero if proposal contains any algorithm from algs */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_has_any_alg(ଅଚଳ ଅକ୍ଷର *proposal, ଅଚଳ ଅକ୍ଷର *algs)
{
	ଅକ୍ଷର *cp;

	ଯଦି ((cp = match_list(proposal, algs, ଖାଲି)) == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ମୁକ୍ତ(cp);
	ଫେରନ୍ତୁ 1;
}

/*
 * Concatenate algorithm names, avoiding duplicates in the process.
 * Caller must free returned string.
 */
ଅକ୍ଷର *
kex_names_cat(ଅଚଳ ଅକ୍ଷର *a, ଅଚଳ ଅକ୍ଷର *b)
{
	ଅକ୍ଷର *ret = ଖାଲି, *tmp = ଖାଲି, *cp, *p;
	size_t len;

	ଯଦି (a == ଖାଲି || *a == '\0')
		ଫେରନ୍ତୁ strdup(b);
	ଯଦି (b == ଖାଲି || *b == '\0')
		ଫେରନ୍ତୁ strdup(a);
	ଯଦି (strlen(b) > 1024*1024)
		ଫେରନ୍ତୁ ଖାଲି;
	len = strlen(a) + strlen(b) + 2;
	ଯଦି ((tmp = cp = strdup(b)) == ଖାଲି ||
	    (ret = calloc(1, len)) == ଖାଲି) {
		ମୁକ୍ତ(tmp);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	strlcpy(ret, a, len);
	ପାଇଁ ((p = strsep(&cp, ",")); p && *p != '\0'; (p = strsep(&cp, ","))) {
		ଯଦି (kex_has_any_alg(ret, p))
			ଜାରି; /* Algorithm already present */
		ଯଦି (strlcat(ret, ",", len) >= len ||
		    strlcat(ret, p, len) >= len) {
			ମୁକ୍ତ(tmp);
			ମୁକ୍ତ(ret);
			ଫେରନ୍ତୁ ଖାଲି; /* Shouldn't happen */
		}
	}
	ମୁକ୍ତ(tmp);
	ଫେରନ୍ତୁ ret;
}

/*
 * Assemble a list of algorithms from a default list and a string from a
 * configuration file. The user-provided string may begin with '+' to
 * indicate that it should be appended to the default, '-' that the
 * specified names should be removed, or '^' that they should be placed
 * at the head.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_assemble_names(ଅକ୍ଷର **listp, ଅଚଳ ଅକ୍ଷର *def, ଅଚଳ ଅକ୍ଷର *all)
{
	ଅକ୍ଷର *cp, *tmp, *patterns;
	ଅକ୍ଷର *list = ଖାଲି, *ret = ଖାଲି, *matching = ଖାଲି, *opatterns = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	ଯଦି (listp == ଖାଲି || def == ଖାଲି || all == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;

	ଯଦି (*listp == ଖାଲି || **listp == '\0') {
		ଯଦି ((*listp = strdup(def)) == ଖାଲି)
			ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
		ଫେରନ୍ତୁ 0;
	}

	list = *listp;
	*listp = ଖାଲି;
	ଯଦି (*list == '+') {
		/* Append names to default list */
		ଯଦି ((tmp = kex_names_cat(def, list + 1)) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ fail;
		}
		ମୁକ୍ତ(list);
		list = tmp;
	} ଅନ୍ୟଥା ଯଦି (*list == '-') {
		/* Remove names from default list */
		ଯଦି ((*listp = match_filter_denylist(def, list + 1)) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ fail;
		}
		ମୁକ୍ତ(list);
		/* filtering has already been done */
		ଫେରନ୍ତୁ 0;
	} ଅନ୍ୟଥା ଯଦି (*list == '^') {
		/* Place names at head of default list */
		ଯଦି ((tmp = kex_names_cat(list + 1, def)) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ fail;
		}
		ମୁକ୍ତ(list);
		list = tmp;
	} ଅନ୍ୟଥା {
		/* Explicit list, overrides default - just use "list" as is */
	}

	/*
	 * The supplied names may be a pattern-list. For the -list case,
	 * the patterns are applied above. For the +list and explicit list
	 * cases we need to do it now.
	 */
	ret = ଖାଲି;
	ଯଦି ((patterns = opatterns = strdup(list)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ fail;
	}
	/* Apply positive (i.e. non-negated) patterns from the list */
	ଯେତେବେଳେ ((cp = strsep(&patterns, ",")) != ଖାଲି) {
		ଯଦି (*cp == '!') {
			/* negated matches are not supported here */
			r = SSH_ERR_INVALID_ARGUMENT;
			ଯାଅ fail;
		}
		ମୁକ୍ତ(matching);
		ଯଦି ((matching = match_filter_allowlist(all, cp)) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ fail;
		}
		ଯଦି ((tmp = kex_names_cat(ret, matching)) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ fail;
		}
		ମୁକ୍ତ(ret);
		ret = tmp;
	}
	ଯଦି (ret == ଖାଲି || *ret == '\0') {
		/* An empty name-list is an error */
		/* XXX better error code? */
		r = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ fail;
	}

	/* success */
	*listp = ret;
	ret = ଖାଲି;
	r = 0;

 fail:
	ମୁକ୍ତ(matching);
	ମୁକ୍ତ(opatterns);
	ମୁକ୍ତ(list);
	ମୁକ୍ତ(ret);
	ଫେରନ୍ତୁ r;
}
