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

struct kexalg {
	char *name;
	u_int type;
	정수 ec_nid;
	정수 hash_alg;
	정수 pq_alg;
};
static const struct kexalg kexalgs[] = {
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
#만약 defined(HAVE_EVP_SHA256) || !defined(WITH_OPENSSL)
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

char *
kex_alg_list(char sep)
{
	char *ret = NULL;
	const struct kexalg *k;
	char sep_str[2] = {sep, '\0'};

	위해 (k = kexalgs; k->name != NULL; k++)
		xextendf(&ret, sep_str, "%s", k->name);

	반환 ret;
}

static const struct kexalg *
kex_alg_by_name(const char *name)
{
	const struct kexalg *k;

	위해 (k = kexalgs; k->name != NULL; k++) {
		만약 (strcmp(k->name, name) == 0)
			반환 k;
	}
	반환 NULL;
}

정수
kex_name_valid(const char *name)
{
	반환 kex_alg_by_name(name) != NULL;
}

정수
kex_is_pq_from_name(const char *name)
{
	const struct kexalg *k;

	만약 ((k = kex_alg_by_name(name)) == NULL)
		반환 0;
	반환 k->pq_alg == KEX_IS_PQ;
}

u_int
kex_type_from_name(const char *name)
{
	const struct kexalg *k;

	만약 ((k = kex_alg_by_name(name)) == NULL)
		반환 0;
	반환 k->type;
}

정수
kex_hash_from_name(const char *name)
{
	const struct kexalg *k;

	만약 ((k = kex_alg_by_name(name)) == NULL)
		반환 -1;
	반환 k->hash_alg;
}

정수
kex_nid_from_name(const char *name)
{
	const struct kexalg *k;

	만약 ((k = kex_alg_by_name(name)) == NULL)
		반환 -1;
	반환 k->ec_nid;
}

/* Validate KEX method name list */
정수
kex_names_valid(const char *names)
{
	char *s, *cp, *p;

	만약 (names == NULL || strcmp(names, "") == 0)
		반환 0;
	만약 ((s = cp = strdup(names)) == NULL)
		반환 0;
	위해 ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		만약 (kex_alg_by_name(p) == NULL) {
			error("Unsupported KEX algorithm \"%.100s\"", p);
			free(s);
			반환 0;
		}
	}
	debug3("kex names ok: [%s]", names);
	free(s);
	반환 1;
}

/* returns non-zero if proposal contains any algorithm from algs */
정수
kex_has_any_alg(const char *proposal, const char *algs)
{
	char *cp;

	만약 ((cp = match_list(proposal, algs, NULL)) == NULL)
		반환 0;
	free(cp);
	반환 1;
}

/*
 * Concatenate algorithm names, avoiding duplicates in the process.
 * Caller must free returned string.
 */
char *
kex_names_cat(const char *a, const char *b)
{
	char *ret = NULL, *tmp = NULL, *cp, *p;
	size_t len;

	만약 (a == NULL || *a == '\0')
		반환 strdup(b);
	만약 (b == NULL || *b == '\0')
		반환 strdup(a);
	만약 (strlen(b) > 1024*1024)
		반환 NULL;
	len = strlen(a) + strlen(b) + 2;
	만약 ((tmp = cp = strdup(b)) == NULL ||
	    (ret = calloc(1, len)) == NULL) {
		free(tmp);
		반환 NULL;
	}
	strlcpy(ret, a, len);
	위해 ((p = strsep(&cp, ",")); p && *p != '\0'; (p = strsep(&cp, ","))) {
		만약 (kex_has_any_alg(ret, p))
			continue; /* Algorithm already present */
		만약 (strlcat(ret, ",", len) >= len ||
		    strlcat(ret, p, len) >= len) {
			free(tmp);
			free(ret);
			반환 NULL; /* Shouldn't happen */
		}
	}
	free(tmp);
	반환 ret;
}

/*
 * Assemble a list of algorithms from a default list and a string from a
 * configuration file. The user-provided string may begin with '+' to
 * indicate that it should be appended to the default, '-' that the
 * specified names should be removed, or '^' that they should be placed
 * at the head.
 */
정수
kex_assemble_names(char **listp, const char *def, const char *all)
{
	char *cp, *tmp, *patterns;
	char *list = NULL, *ret = NULL, *matching = NULL, *opatterns = NULL;
	정수 r = SSH_ERR_INTERNAL_ERROR;

	만약 (listp == NULL || def == NULL || all == NULL)
		반환 SSH_ERR_INVALID_ARGUMENT;

	만약 (*listp == NULL || **listp == '\0') {
		만약 ((*listp = strdup(def)) == NULL)
			반환 SSH_ERR_ALLOC_FAIL;
		반환 0;
	}

	list = *listp;
	*listp = NULL;
	만약 (*list == '+') {
		/* Append names to default list */
		만약 ((tmp = kex_names_cat(def, list + 1)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		free(list);
		list = tmp;
	} 아니면 만약 (*list == '-') {
		/* Remove names from default list */
		만약 ((*listp = match_filter_denylist(def, list + 1)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		free(list);
		/* filtering has already been done */
		반환 0;
	} 아니면 만약 (*list == '^') {
		/* Place names at head of default list */
		만약 ((tmp = kex_names_cat(list + 1, def)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		free(list);
		list = tmp;
	} 아니면 {
		/* Explicit list, overrides default - just use "list" as is */
	}

	/*
	 * The supplied names may be a pattern-list. For the -list case,
	 * the patterns are applied above. For the +list and explicit list
	 * cases we need to do it now.
	 */
	ret = NULL;
	만약 ((patterns = opatterns = strdup(list)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto fail;
	}
	/* Apply positive (i.e. non-negated) patterns from the list */
	동안 ((cp = strsep(&patterns, ",")) != NULL) {
		만약 (*cp == '!') {
			/* negated matches are not supported here */
			r = SSH_ERR_INVALID_ARGUMENT;
			goto fail;
		}
		free(matching);
		만약 ((matching = match_filter_allowlist(all, cp)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		만약 ((tmp = kex_names_cat(ret, matching)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto fail;
		}
		free(ret);
		ret = tmp;
	}
	만약 (ret == NULL || *ret == '\0') {
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
	반환 r;
}
