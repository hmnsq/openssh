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

#include "includes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#ifdef WITH_OPENSSL
#include <openssl/crypto.h>
#include <openssl/evp.h>
#endif

#include "kex.h"
#include "log.h"
#include "match.h"
#include "digest.h"
#include "misc.h"

#include "ssherr.h"

sa_nracanaa kexalg {
	var_na *name;
	u_int type;
	ကိန်းပြည့် ec_nid;
	ကိန်းပြည့် hash_alg;
	ကိန်းပြည့် pq_alg;
};
static const sa_nracanaa kexalg kexalgs[] = {
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
#အကယ်၍ defined(HAVE_EVP_SHA256) || !defined(WITH_OPENSSL)
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
	{ NULL, 0, -1, -1, 0 },
};

var_na *
kex_alg_list(var_na sep)
{
	var_na *ret = NULL;
	const sa_nracanaa kexalg *k;
	var_na sep_str[2] = {sep, '\0'};

	အတွက် (k = kexalgs; k->name != NULL; k++)
		xextendf(&ret, sep_str, "%s", k->name);

	ပြန်ပေး ret;
}

static const sa_nracanaa kexalg *
kex_alg_by_name(const var_na *name)
{
	const sa_nracanaa kexalg *k;

	အတွက် (k = kexalgs; k->name != NULL; k++) {
		အကယ်၍ (strcmp(k->name, name) == 0)
			ပြန်ပေး k;
	}
	ပြန်ပေး NULL;
}

ကိန်းပြည့်
kex_name_valid(const var_na *name)
{
	ပြန်ပေး kex_alg_by_name(name) != NULL;
}

ကိန်းပြည့်
kex_is_pq_from_name(const var_na *name)
{
	const sa_nracanaa kexalg *k;

	အကယ်၍ ((k = kex_alg_by_name(name)) == NULL)
		ပြန်ပေး 0;
	ပြန်ပေး k->pq_alg == KEX_IS_PQ;
}

u_int
kex_type_from_name(const var_na *name)
{
	const sa_nracanaa kexalg *k;

	အကယ်၍ ((k = kex_alg_by_name(name)) == NULL)
		ပြန်ပေး 0;
	ပြန်ပေး k->type;
}

ကိန်းပြည့်
kex_hash_from_name(const var_na *name)
{
	const sa_nracanaa kexalg *k;

	အကယ်၍ ((k = kex_alg_by_name(name)) == NULL)
		ပြန်ပေး -1;
	ပြန်ပေး k->hash_alg;
}

ကိန်းပြည့်
kex_nid_from_name(const var_na *name)
{
	const sa_nracanaa kexalg *k;

	အကယ်၍ ((k = kex_alg_by_name(name)) == NULL)
		ပြန်ပေး -1;
	ပြန်ပေး k->ec_nid;
}

/* Validate KEX method name list */
ကိန်းပြည့်
kex_names_valid(const var_na *names)
{
	var_na *s, *cp, *p;

	အကယ်၍ (names == NULL || strcmp(names, "") == 0)
		ပြန်ပေး 0;
	အကယ်၍ ((s = cp = strdup(names)) == NULL)
		ပြန်ပေး 0;
	အတွက် ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		အကယ်၍ (kex_alg_by_name(p) == NULL) {
			error("Unsupported KEX algorithm \"%.100s\"", p);
			free(s);
			ပြန်ပေး 0;
		}
	}
	debug3("kex names ok: [%s]", names);
	free(s);
	ပြန်ပေး 1;
}

/* returns non-zero if proposal contains any algorithm from algs */
ကိန်းပြည့်
kex_has_any_alg(const var_na *proposal, const var_na *algs)
{
	var_na *cp;

	အကယ်၍ ((cp = match_list(proposal, algs, NULL)) == NULL)
		ပြန်ပေး 0;
	free(cp);
	ပြန်ပေး 1;
}

/*
 * Concatenate algorithm names, avoiding duplicates in the process.
 * Caller must free returned string.
 */
var_na *
kex_names_cat(const var_na *a, const var_na *b)
{
	var_na *ret = NULL, *tmp = NULL, *cp, *p;
	size_t len;

	အကယ်၍ (a == NULL || *a == '\0')
		ပြန်ပေး strdup(b);
	အကယ်၍ (b == NULL || *b == '\0')
		ပြန်ပေး strdup(a);
	အကယ်၍ (strlen(b) > 1024*1024)
		ပြန်ပေး NULL;
	len = strlen(a) + strlen(b) + 2;
	အကယ်၍ ((tmp = cp = strdup(b)) == NULL ||
	    (ret = calloc(1, len)) == NULL) {
		free(tmp);
		ပြန်ပေး NULL;
	}
	strlcpy(ret, a, len);
	အတွက် ((p = strsep(&cp, ",")); p && *p != '\0'; (p = strsep(&cp, ","))) {
		အကယ်၍ (kex_has_any_alg(ret, p))
			continue; /* Algorithm already present */
		အကယ်၍ (strlcat(ret, ",", len) >= len ||
		    strlcat(ret, p, len) >= len) {
			free(tmp);
			free(ret);
			ပြန်ပေး NULL; /* Shouldn't happen */
		}
	}
	free(tmp);
	ပြန်ပေး ret;
}

/*
 * Assemble a list of algorithms from a default list and a string from a
 * configuration file. The user-provided string may begin with '+' to
 * indicate that it should be appended to the default, '-' that the
 * specified names should be removed, or '^' that they should be placed
 * at the head.
 */
ကိန်းပြည့်
kex_assemble_names(var_na **listp, const var_na *def, const var_na *all)
{
	var_na *cp, *tmp, *patterns;
	var_na *list = NULL, *ret = NULL, *matching = NULL, *opatterns = NULL;
	ကိန်းပြည့် r = SSH_ERR_INTERNAL_ERROR;

	အကယ်၍ (listp == NULL || def == NULL || all == NULL)
		ပြန်ပေး SSH_ERR_INVALID_ARGUMENT;

	အကယ်၍ (*listp == NULL || **listp == '\0') {
		အကယ်၍ ((*listp = strdup(def)) == NULL)
			ပြန်ပေး SSH_ERR_ALLOC_FAIL;
		ပြန်ပေး 0;
	}

	list = *listp;
	*listp = NULL;
	အကယ်၍ (*list == '+') {
		/* Append names to default list */
		အကယ်၍ ((tmp = kex_names_cat(def, list + 1)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		free(list);
		list = tmp;
	} မဟုတ်ပါက အကယ်၍ (*list == '-') {
		/* Remove names from default list */
		အကယ်၍ ((*listp = match_filter_denylist(def, list + 1)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		free(list);
		/* filtering has already been done */
		ပြန်ပေး 0;
	} မဟုတ်ပါက အကယ်၍ (*list == '^') {
		/* Place names at head of default list */
		အကယ်၍ ((tmp = kex_names_cat(list + 1, def)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		free(list);
		list = tmp;
	} မဟုတ်ပါက {
		/* Explicit list, overrides default - just use "list" as is */
	}

	/*
	 * The supplied names may be a pattern-list. For the -list case,
	 * the patterns are applied above. For the +list and explicit list
	 * cases we need to do it now.
	 */
	ret = NULL;
	အကယ်၍ ((patterns = opatterns = strdup(list)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto fail;
	}
	/* Apply positive (i.e. non-negated) patterns from the list */
	နေစဉ် ((cp = strsep(&patterns, ",")) != NULL) {
		အကယ်၍ (*cp == '!') {
			/* negated matches are not supported here */
			r = SSH_ERR_INVALID_ARGUMENT;
			goto fail;
		}
		free(matching);
		အကယ်၍ ((matching = match_filter_allowlist(all, cp)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		အကယ်၍ ((tmp = kex_names_cat(ret, matching)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		free(ret);
		ret = tmp;
	}
	အကယ်၍ (ret == NULL || *ret == '\0') {
		/* An empty name-list is an error */
		/* XXX better error code? */
		r = SSH_ERR_INVALID_ARGUMENT;
		goto fail;
	}

	/* success */
	*listp = ret;
	ret = NULL;
	r = 0;

 fail:
	free(matching);
	free(opatterns);
	free(list);
	free(ret);
	ပြန်ပေး r;
}
