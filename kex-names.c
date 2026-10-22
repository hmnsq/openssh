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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <signal.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/crypto.h>
#അന്തര്ഭാവ <openssl/evp.h>
#endif

#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "misc.h"

#അന്തര്ഭാവ "ssherr.h"

ഘടന kexalg {
	അക്ഷരം *name;
	u_int type;
	പൂർണ്ണസംഖ്യ ec_nid;
	പൂർണ്ണസംഖ്യ hash_alg;
	പൂർണ്ണസംഖ്യ pq_alg;
};
സ്ഥിതം സ്ഥിരം ഘടന kexalg kexalgs[] = {
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
#എങ്കിൽ defined(HAVE_EVP_SHA256) || !defined(WITH_OPENSSL)
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
	{ ശൂന്യ, 0, -1, -1, 0 },
};

അക്ഷരം *
kex_alg_list(അക്ഷരം sep)
{
	അക്ഷരം *ret = ശൂന്യ;
	സ്ഥിരം ഘടന kexalg *k;
	അക്ഷരം sep_str[2] = {sep, '\0'};

	വേണ്ടി (k = kexalgs; k->name != ശൂന്യ; k++)
		xextendf(&ret, sep_str, "%s", k->name);

	തിരികെ ret;
}

സ്ഥിതം സ്ഥിരം ഘടന kexalg *
kex_alg_by_name(സ്ഥിരം അക്ഷരം *name)
{
	സ്ഥിരം ഘടന kexalg *k;

	വേണ്ടി (k = kexalgs; k->name != ശൂന്യ; k++) {
		എങ്കിൽ (strcmp(k->name, name) == 0)
			തിരികെ k;
	}
	തിരികെ ശൂന്യ;
}

പൂർണ്ണസംഖ്യ
kex_name_valid(സ്ഥിരം അക്ഷരം *name)
{
	തിരികെ kex_alg_by_name(name) != ശൂന്യ;
}

പൂർണ്ണസംഖ്യ
kex_is_pq_from_name(സ്ഥിരം അക്ഷരം *name)
{
	സ്ഥിരം ഘടന kexalg *k;

	എങ്കിൽ ((k = kex_alg_by_name(name)) == ശൂന്യ)
		തിരികെ 0;
	തിരികെ k->pq_alg == KEX_IS_PQ;
}

u_int
kex_type_from_name(സ്ഥിരം അക്ഷരം *name)
{
	സ്ഥിരം ഘടന kexalg *k;

	എങ്കിൽ ((k = kex_alg_by_name(name)) == ശൂന്യ)
		തിരികെ 0;
	തിരികെ k->type;
}

പൂർണ്ണസംഖ്യ
kex_hash_from_name(സ്ഥിരം അക്ഷരം *name)
{
	സ്ഥിരം ഘടന kexalg *k;

	എങ്കിൽ ((k = kex_alg_by_name(name)) == ശൂന്യ)
		തിരികെ -1;
	തിരികെ k->hash_alg;
}

പൂർണ്ണസംഖ്യ
kex_nid_from_name(സ്ഥിരം അക്ഷരം *name)
{
	സ്ഥിരം ഘടന kexalg *k;

	എങ്കിൽ ((k = kex_alg_by_name(name)) == ശൂന്യ)
		തിരികെ -1;
	തിരികെ k->ec_nid;
}

/* Validate KEX method name list */
പൂർണ്ണസംഖ്യ
kex_names_valid(സ്ഥിരം അക്ഷരം *names)
{
	അക്ഷരം *s, *cp, *p;

	എങ്കിൽ (names == ശൂന്യ || strcmp(names, "") == 0)
		തിരികെ 0;
	എങ്കിൽ ((s = cp = strdup(names)) == ശൂന്യ)
		തിരികെ 0;
	വേണ്ടി ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		എങ്കിൽ (kex_alg_by_name(p) == ശൂന്യ) {
			error("Unsupported KEX algorithm \"%.100s\"", p);
			സ്വതന്ത്രം(s);
			തിരികെ 0;
		}
	}
	debug3("kex names ok: [%s]", names);
	സ്വതന്ത്രം(s);
	തിരികെ 1;
}

/* returns non-zero if proposal contains any algorithm from algs */
പൂർണ്ണസംഖ്യ
kex_has_any_alg(സ്ഥിരം അക്ഷരം *proposal, സ്ഥിരം അക്ഷരം *algs)
{
	അക്ഷരം *cp;

	എങ്കിൽ ((cp = match_list(proposal, algs, ശൂന്യ)) == ശൂന്യ)
		തിരികെ 0;
	സ്വതന്ത്രം(cp);
	തിരികെ 1;
}

/*
 * Concatenate algorithm names, avoiding duplicates in the process.
 * Caller must free returned string.
 */
അക്ഷരം *
kex_names_cat(സ്ഥിരം അക്ഷരം *a, സ്ഥിരം അക്ഷരം *b)
{
	അക്ഷരം *ret = ശൂന്യ, *tmp = ശൂന്യ, *cp, *p;
	size_t len;

	എങ്കിൽ (a == ശൂന്യ || *a == '\0')
		തിരികെ strdup(b);
	എങ്കിൽ (b == ശൂന്യ || *b == '\0')
		തിരികെ strdup(a);
	എങ്കിൽ (strlen(b) > 1024*1024)
		തിരികെ ശൂന്യ;
	len = strlen(a) + strlen(b) + 2;
	എങ്കിൽ ((tmp = cp = strdup(b)) == ശൂന്യ ||
	    (ret = calloc(1, len)) == ശൂന്യ) {
		സ്വതന്ത്രം(tmp);
		തിരികെ ശൂന്യ;
	}
	strlcpy(ret, a, len);
	വേണ്ടി ((p = strsep(&cp, ",")); p && *p != '\0'; (p = strsep(&cp, ","))) {
		എങ്കിൽ (kex_has_any_alg(ret, p))
			തുടരുക; /* Algorithm already present */
		എങ്കിൽ (strlcat(ret, ",", len) >= len ||
		    strlcat(ret, p, len) >= len) {
			സ്വതന്ത്രം(tmp);
			സ്വതന്ത്രം(ret);
			തിരികെ ശൂന്യ; /* Shouldn't happen */
		}
	}
	സ്വതന്ത്രം(tmp);
	തിരികെ ret;
}

/*
 * Assemble a list of algorithms from a default list and a string from a
 * configuration file. The user-provided string may begin with '+' to
 * indicate that it should be appended to the default, '-' that the
 * specified names should be removed, or '^' that they should be placed
 * at the head.
 */
പൂർണ്ണസംഖ്യ
kex_assemble_names(അക്ഷരം **listp, സ്ഥിരം അക്ഷരം *def, സ്ഥിരം അക്ഷരം *all)
{
	അക്ഷരം *cp, *tmp, *patterns;
	അക്ഷരം *list = ശൂന്യ, *ret = ശൂന്യ, *matching = ശൂന്യ, *opatterns = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ (listp == ശൂന്യ || def == ശൂന്യ || all == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;

	എങ്കിൽ (*listp == ശൂന്യ || **listp == '\0') {
		എങ്കിൽ ((*listp = strdup(def)) == ശൂന്യ)
			തിരികെ SSH_ERR_ALLOC_FAIL;
		തിരികെ 0;
	}

	list = *listp;
	*listp = ശൂന്യ;
	എങ്കിൽ (*list == '+') {
		/* Append names to default list */
		എങ്കിൽ ((tmp = kex_names_cat(def, list + 1)) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക fail;
		}
		സ്വതന്ത്രം(list);
		list = tmp;
	} അല്ലെങ്കിൽ എങ്കിൽ (*list == '-') {
		/* Remove names from default list */
		എങ്കിൽ ((*listp = match_filter_denylist(def, list + 1)) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക fail;
		}
		സ്വതന്ത്രം(list);
		/* filtering has already been done */
		തിരികെ 0;
	} അല്ലെങ്കിൽ എങ്കിൽ (*list == '^') {
		/* Place names at head of default list */
		എങ്കിൽ ((tmp = kex_names_cat(list + 1, def)) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക fail;
		}
		സ്വതന്ത്രം(list);
		list = tmp;
	} അല്ലെങ്കിൽ {
		/* Explicit list, overrides default - just use "list" as is */
	}

	/*
	 * The supplied names may be a pattern-list. For the -list case,
	 * the patterns are applied above. For the +list and explicit list
	 * cases we need to do it now.
	 */
	ret = ശൂന്യ;
	എങ്കിൽ ((patterns = opatterns = strdup(list)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക fail;
	}
	/* Apply positive (i.e. non-negated) patterns from the list */
	ആകുമ്പോൾ ((cp = strsep(&patterns, ",")) != ശൂന്യ) {
		എങ്കിൽ (*cp == '!') {
			/* negated matches are not supported here */
			r = SSH_ERR_INVALID_ARGUMENT;
			പോകുക fail;
		}
		സ്വതന്ത്രം(matching);
		എങ്കിൽ ((matching = match_filter_allowlist(all, cp)) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക fail;
		}
		എങ്കിൽ ((tmp = kex_names_cat(ret, matching)) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക fail;
		}
		സ്വതന്ത്രം(ret);
		ret = tmp;
	}
	എങ്കിൽ (ret == ശൂന്യ || *ret == '\0') {
		/* An empty name-list is an error */
		/* XXX better error code? */
		r = SSH_ERR_INVALID_ARGUMENT;
		പോകുക fail;
	}

	/* success */
	*listp = ret;
	ret = ശൂന്യ;
	r = 0;

 fail:
	സ്വതന്ത്രം(matching);
	സ്വതന്ത്രം(opatterns);
	സ്വതന്ത്രം(list);
	സ്വതന്ത്രം(ret);
	തിരികെ r;
}
