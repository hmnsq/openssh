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
	ཧྲིལ ec_nid;
	ཧྲིལ hash_alg;
	ཧྲིལ pq_alg;
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
#གལ་ཏེ defined(HAVE_EVP_SHA256) || !defined(WITH_OPENSSL)
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

	ཆེད་དུ (k = kexalgs; k->name != NULL; k++)
		xextendf(&ret, sep_str, "%s", k->name);

	ཕྱིར ret;
}

static const sa_nracanaa kexalg *
kex_alg_by_name(const var_na *name)
{
	const sa_nracanaa kexalg *k;

	ཆེད་དུ (k = kexalgs; k->name != NULL; k++) {
		གལ་ཏེ (strcmp(k->name, name) == 0)
			ཕྱིར k;
	}
	ཕྱིར NULL;
}

ཧྲིལ
kex_name_valid(const var_na *name)
{
	ཕྱིར kex_alg_by_name(name) != NULL;
}

ཧྲིལ
kex_is_pq_from_name(const var_na *name)
{
	const sa_nracanaa kexalg *k;

	གལ་ཏེ ((k = kex_alg_by_name(name)) == NULL)
		ཕྱིར 0;
	ཕྱིར k->pq_alg == KEX_IS_PQ;
}

u_int
kex_type_from_name(const var_na *name)
{
	const sa_nracanaa kexalg *k;

	གལ་ཏེ ((k = kex_alg_by_name(name)) == NULL)
		ཕྱིར 0;
	ཕྱིར k->type;
}

ཧྲིལ
kex_hash_from_name(const var_na *name)
{
	const sa_nracanaa kexalg *k;

	གལ་ཏེ ((k = kex_alg_by_name(name)) == NULL)
		ཕྱིར -1;
	ཕྱིར k->hash_alg;
}

ཧྲིལ
kex_nid_from_name(const var_na *name)
{
	const sa_nracanaa kexalg *k;

	གལ་ཏེ ((k = kex_alg_by_name(name)) == NULL)
		ཕྱིར -1;
	ཕྱིར k->ec_nid;
}

/* Validate KEX method name list */
ཧྲིལ
kex_names_valid(const var_na *names)
{
	var_na *s, *cp, *p;

	གལ་ཏེ (names == NULL || strcmp(names, "") == 0)
		ཕྱིར 0;
	གལ་ཏེ ((s = cp = strdup(names)) == NULL)
		ཕྱིར 0;
	ཆེད་དུ ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		གལ་ཏེ (kex_alg_by_name(p) == NULL) {
			error("Unsupported KEX algorithm \"%.100s\"", p);
			free(s);
			ཕྱིར 0;
		}
	}
	debug3("kex names ok: [%s]", names);
	free(s);
	ཕྱིར 1;
}

/* returns non-zero if proposal contains any algorithm from algs */
ཧྲིལ
kex_has_any_alg(const var_na *proposal, const var_na *algs)
{
	var_na *cp;

	གལ་ཏེ ((cp = match_list(proposal, algs, NULL)) == NULL)
		ཕྱིར 0;
	free(cp);
	ཕྱིར 1;
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

	གལ་ཏེ (a == NULL || *a == '\0')
		ཕྱིར strdup(b);
	གལ་ཏེ (b == NULL || *b == '\0')
		ཕྱིར strdup(a);
	གལ་ཏེ (strlen(b) > 1024*1024)
		ཕྱིར NULL;
	len = strlen(a) + strlen(b) + 2;
	གལ་ཏེ ((tmp = cp = strdup(b)) == NULL ||
	    (ret = calloc(1, len)) == NULL) {
		free(tmp);
		ཕྱིར NULL;
	}
	strlcpy(ret, a, len);
	ཆེད་དུ ((p = strsep(&cp, ",")); p && *p != '\0'; (p = strsep(&cp, ","))) {
		གལ་ཏེ (kex_has_any_alg(ret, p))
			continue; /* Algorithm already present */
		གལ་ཏེ (strlcat(ret, ",", len) >= len ||
		    strlcat(ret, p, len) >= len) {
			free(tmp);
			free(ret);
			ཕྱིར NULL; /* Shouldn't happen */
		}
	}
	free(tmp);
	ཕྱིར ret;
}

/*
 * Assemble a list of algorithms from a default list and a string from a
 * configuration file. The user-provided string may begin with '+' to
 * indicate that it should be appended to the default, '-' that the
 * specified names should be removed, or '^' that they should be placed
 * at the head.
 */
ཧྲིལ
kex_assemble_names(var_na **listp, const var_na *def, const var_na *all)
{
	var_na *cp, *tmp, *patterns;
	var_na *list = NULL, *ret = NULL, *matching = NULL, *opatterns = NULL;
	ཧྲིལ r = SSH_ERR_INTERNAL_ERROR;

	གལ་ཏེ (listp == NULL || def == NULL || all == NULL)
		ཕྱིར SSH_ERR_INVALID_ARGUMENT;

	གལ་ཏེ (*listp == NULL || **listp == '\0') {
		གལ་ཏེ ((*listp = strdup(def)) == NULL)
			ཕྱིར SSH_ERR_ALLOC_FAIL;
		ཕྱིར 0;
	}

	list = *listp;
	*listp = NULL;
	གལ་ཏེ (*list == '+') {
		/* Append names to default list */
		གལ་ཏེ ((tmp = kex_names_cat(def, list + 1)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		free(list);
		list = tmp;
	} དེ་མིན གལ་ཏེ (*list == '-') {
		/* Remove names from default list */
		གལ་ཏེ ((*listp = match_filter_denylist(def, list + 1)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		free(list);
		/* filtering has already been done */
		ཕྱིར 0;
	} དེ་མིན གལ་ཏེ (*list == '^') {
		/* Place names at head of default list */
		གལ་ཏེ ((tmp = kex_names_cat(list + 1, def)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		free(list);
		list = tmp;
	} དེ་མིན {
		/* Explicit list, overrides default - just use "list" as is */
	}

	/*
	 * The supplied names may be a pattern-list. For the -list case,
	 * the patterns are applied above. For the +list and explicit list
	 * cases we need to do it now.
	 */
	ret = NULL;
	གལ་ཏེ ((patterns = opatterns = strdup(list)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto fail;
	}
	/* Apply positive (i.e. non-negated) patterns from the list */
	སྐབས ((cp = strsep(&patterns, ",")) != NULL) {
		གལ་ཏེ (*cp == '!') {
			/* negated matches are not supported here */
			r = SSH_ERR_INVALID_ARGUMENT;
			goto fail;
		}
		free(matching);
		གལ་ཏེ ((matching = match_filter_allowlist(all, cp)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		གལ་ཏེ ((tmp = kex_names_cat(ret, matching)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		free(ret);
		ret = tmp;
	}
	གལ་ཏེ (ret == NULL || *ret == '\0') {
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
	ཕྱིར r;
}
