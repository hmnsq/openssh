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
	පූර්ණ_සංඛ්‍යා ec_nid;
	පූර්ණ_සංඛ්‍යා hash_alg;
	පූර්ණ_සංඛ්‍යා pq_alg;
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
#නම් defined(HAVE_EVP_SHA256) || !defined(WITH_OPENSSL)
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

	සඳහා (k = kexalgs; k->name != NULL; k++)
		xextendf(&ret, sep_str, "%s", k->name);

	ආපසු ret;
}

static const sa_nracanaa kexalg *
kex_alg_by_name(const var_na *name)
{
	const sa_nracanaa kexalg *k;

	සඳහා (k = kexalgs; k->name != NULL; k++) {
		නම් (strcmp(k->name, name) == 0)
			ආපසු k;
	}
	ආපසු NULL;
}

පූර්ණ_සංඛ්‍යා
kex_name_valid(const var_na *name)
{
	ආපසු kex_alg_by_name(name) != NULL;
}

පූර්ණ_සංඛ්‍යා
kex_is_pq_from_name(const var_na *name)
{
	const sa_nracanaa kexalg *k;

	නම් ((k = kex_alg_by_name(name)) == NULL)
		ආපසු 0;
	ආපසු k->pq_alg == KEX_IS_PQ;
}

u_int
kex_type_from_name(const var_na *name)
{
	const sa_nracanaa kexalg *k;

	නම් ((k = kex_alg_by_name(name)) == NULL)
		ආපසු 0;
	ආපසු k->type;
}

පූර්ණ_සංඛ්‍යා
kex_hash_from_name(const var_na *name)
{
	const sa_nracanaa kexalg *k;

	නම් ((k = kex_alg_by_name(name)) == NULL)
		ආපසු -1;
	ආපසු k->hash_alg;
}

පූර්ණ_සංඛ්‍යා
kex_nid_from_name(const var_na *name)
{
	const sa_nracanaa kexalg *k;

	නම් ((k = kex_alg_by_name(name)) == NULL)
		ආපසු -1;
	ආපසු k->ec_nid;
}

/* Validate KEX method name list */
පූර්ණ_සංඛ්‍යා
kex_names_valid(const var_na *names)
{
	var_na *s, *cp, *p;

	නම් (names == NULL || strcmp(names, "") == 0)
		ආපසු 0;
	නම් ((s = cp = strdup(names)) == NULL)
		ආපසු 0;
	සඳහා ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		නම් (kex_alg_by_name(p) == NULL) {
			error("Unsupported KEX algorithm \"%.100s\"", p);
			free(s);
			ආපසු 0;
		}
	}
	debug3("kex names ok: [%s]", names);
	free(s);
	ආපසු 1;
}

/* returns non-zero if proposal contains any algorithm from algs */
පූර්ණ_සංඛ්‍යා
kex_has_any_alg(const var_na *proposal, const var_na *algs)
{
	var_na *cp;

	නම් ((cp = match_list(proposal, algs, NULL)) == NULL)
		ආපසු 0;
	free(cp);
	ආපසු 1;
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

	නම් (a == NULL || *a == '\0')
		ආපසු strdup(b);
	නම් (b == NULL || *b == '\0')
		ආපසු strdup(a);
	නම් (strlen(b) > 1024*1024)
		ආපසු NULL;
	len = strlen(a) + strlen(b) + 2;
	නම් ((tmp = cp = strdup(b)) == NULL ||
	    (ret = calloc(1, len)) == NULL) {
		free(tmp);
		ආපසු NULL;
	}
	strlcpy(ret, a, len);
	සඳහා ((p = strsep(&cp, ",")); p && *p != '\0'; (p = strsep(&cp, ","))) {
		නම් (kex_has_any_alg(ret, p))
			continue; /* Algorithm already present */
		නම් (strlcat(ret, ",", len) >= len ||
		    strlcat(ret, p, len) >= len) {
			free(tmp);
			free(ret);
			ආපසු NULL; /* Shouldn't happen */
		}
	}
	free(tmp);
	ආපසු ret;
}

/*
 * Assemble a list of algorithms from a default list and a string from a
 * configuration file. The user-provided string may begin with '+' to
 * indicate that it should be appended to the default, '-' that the
 * specified names should be removed, or '^' that they should be placed
 * at the head.
 */
පූර්ණ_සංඛ්‍යා
kex_assemble_names(var_na **listp, const var_na *def, const var_na *all)
{
	var_na *cp, *tmp, *patterns;
	var_na *list = NULL, *ret = NULL, *matching = NULL, *opatterns = NULL;
	පූර්ණ_සංඛ්‍යා r = SSH_ERR_INTERNAL_ERROR;

	නම් (listp == NULL || def == NULL || all == NULL)
		ආපසු SSH_ERR_INVALID_ARGUMENT;

	නම් (*listp == NULL || **listp == '\0') {
		නම් ((*listp = strdup(def)) == NULL)
			ආපසු SSH_ERR_ALLOC_FAIL;
		ආපසු 0;
	}

	list = *listp;
	*listp = NULL;
	නම් (*list == '+') {
		/* Append names to default list */
		නම් ((tmp = kex_names_cat(def, list + 1)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		free(list);
		list = tmp;
	} නැතහොත් නම් (*list == '-') {
		/* Remove names from default list */
		නම් ((*listp = match_filter_denylist(def, list + 1)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		free(list);
		/* filtering has already been done */
		ආපසු 0;
	} නැතහොත් නම් (*list == '^') {
		/* Place names at head of default list */
		නම් ((tmp = kex_names_cat(list + 1, def)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		free(list);
		list = tmp;
	} නැතහොත් {
		/* Explicit list, overrides default - just use "list" as is */
	}

	/*
	 * The supplied names may be a pattern-list. For the -list case,
	 * the patterns are applied above. For the +list and explicit list
	 * cases we need to do it now.
	 */
	ret = NULL;
	නම් ((patterns = opatterns = strdup(list)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto fail;
	}
	/* Apply positive (i.e. non-negated) patterns from the list */
	අතරතුර ((cp = strsep(&patterns, ",")) != NULL) {
		නම් (*cp == '!') {
			/* negated matches are not supported here */
			r = SSH_ERR_INVALID_ARGUMENT;
			goto fail;
		}
		free(matching);
		නම් ((matching = match_filter_allowlist(all, cp)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		නම් ((tmp = kex_names_cat(ret, matching)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		free(ret);
		ret = tmp;
	}
	නම් (ret == NULL || *ret == '\0') {
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
	ආපසු r;
}
