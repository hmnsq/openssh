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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/crypto.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

ਬਣਤਰ kexalg {
	ਅੱਖਰ *name;
	u_int type;
	ਪੂਰਨ ec_nid;
	ਪੂਰਨ hash_alg;
	ਪੂਰਨ pq_alg;
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ kexalg kexalgs[] = {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
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
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
#ਜੇ defined(HAVE_EVP_SHA256) || !defined(WITH_OPENSSL)
	{ KEX_CURVE25519_SHA256, KEX_C25519_SHA256, 0, SSH_DIGEST_SHA256, KEX_NOT_PQ },
	{ KEX_CURVE25519_SHA256_OLD, KEX_C25519_SHA256, 0, SSH_DIGEST_SHA256, KEX_NOT_PQ },
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_SNTRUP761X25519
	{ KEX_SNTRUP761X25519_SHA512, KEX_KEM_SNTRUP761X25519_SHA512, 0,
	    SSH_DIGEST_SHA512, KEX_IS_PQ },
	{ KEX_SNTRUP761X25519_SHA512_OLD, KEX_KEM_SNTRUP761X25519_SHA512, 0,
	    SSH_DIGEST_SHA512, KEX_IS_PQ },
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_MLKEM768X25519
	{ KEX_MLKEM768X25519_SHA256, KEX_KEM_MLKEM768X25519_SHA256, 0,
	    SSH_DIGEST_SHA256, KEX_IS_PQ },
#ਜੇ_ਅੰਤ
#ਜੇ_ਅੰਤ /* HAVE_EVP_SHA256 || !WITH_OPENSSL */
	{ ਨਿਰਾ, 0, -1, -1, 0 },
};

ਅੱਖਰ *
kex_alg_list(ਅੱਖਰ sep)
{
	ਅੱਖਰ *ret = ਨਿਰਾ;
	ਅਚਲ ਬਣਤਰ kexalg *k;
	ਅੱਖਰ sep_str[2] = {sep, '\0'};

	ਲਈ (k = kexalgs; k->name != ਨਿਰਾ; k++)
		xextendf(&ret, sep_str, "%s", k->name);

	ਵਾਪਸ ret;
}

ਸਥਿਰ ਅਚਲ ਬਣਤਰ kexalg *
kex_alg_by_name(ਅਚਲ ਅੱਖਰ *name)
{
	ਅਚਲ ਬਣਤਰ kexalg *k;

	ਲਈ (k = kexalgs; k->name != ਨਿਰਾ; k++) {
		ਜੇ (strcmp(k->name, name) == 0)
			ਵਾਪਸ k;
	}
	ਵਾਪਸ ਨਿਰਾ;
}

ਪੂਰਨ
kex_name_valid(ਅਚਲ ਅੱਖਰ *name)
{
	ਵਾਪਸ kex_alg_by_name(name) != ਨਿਰਾ;
}

ਪੂਰਨ
kex_is_pq_from_name(ਅਚਲ ਅੱਖਰ *name)
{
	ਅਚਲ ਬਣਤਰ kexalg *k;

	ਜੇ ((k = kex_alg_by_name(name)) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਵਾਪਸ k->pq_alg == KEX_IS_PQ;
}

u_int
kex_type_from_name(ਅਚਲ ਅੱਖਰ *name)
{
	ਅਚਲ ਬਣਤਰ kexalg *k;

	ਜੇ ((k = kex_alg_by_name(name)) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਵਾਪਸ k->type;
}

ਪੂਰਨ
kex_hash_from_name(ਅਚਲ ਅੱਖਰ *name)
{
	ਅਚਲ ਬਣਤਰ kexalg *k;

	ਜੇ ((k = kex_alg_by_name(name)) == ਨਿਰਾ)
		ਵਾਪਸ -1;
	ਵਾਪਸ k->hash_alg;
}

ਪੂਰਨ
kex_nid_from_name(ਅਚਲ ਅੱਖਰ *name)
{
	ਅਚਲ ਬਣਤਰ kexalg *k;

	ਜੇ ((k = kex_alg_by_name(name)) == ਨਿਰਾ)
		ਵਾਪਸ -1;
	ਵਾਪਸ k->ec_nid;
}

/* Validate KEX method name list */
ਪੂਰਨ
kex_ਨਾਂ_valid(ਅਚਲ ਅੱਖਰ *ਨਾਂ)
{
	ਅੱਖਰ *s, *cp, *p;

	ਜੇ (ਨਾਂ == ਨਿਰਾ || strcmp(ਨਾਂ, "") == 0)
		ਵਾਪਸ 0;
	ਜੇ ((s = cp = strdup(ਨਾਂ)) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਲਈ ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		ਜੇ (kex_alg_by_name(p) == ਨਿਰਾ) {
			error("Unsupported KEX algorithm \"%.100s\"", p);
			ਮੁਕਤ(s);
			ਵਾਪਸ 0;
		}
	}
	debug3("kex names ok: [%s]", ਨਾਂ);
	ਮੁਕਤ(s);
	ਵਾਪਸ 1;
}

/* returns non-zero if proposal contains any algorithm from algs */
ਪੂਰਨ
kex_has_any_alg(ਅਚਲ ਅੱਖਰ *proposal, ਅਚਲ ਅੱਖਰ *algs)
{
	ਅੱਖਰ *cp;

	ਜੇ ((cp = ਮੇਲ_list(proposal, algs, ਨਿਰਾ)) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਮੁਕਤ(cp);
	ਵਾਪਸ 1;
}

/*
 * Concatenate algorithm names, avoiding duplicates in the process.
 * Caller must free returned string.
 */
ਅੱਖਰ *
kex_ਨਾਂ_cat(ਅਚਲ ਅੱਖਰ *a, ਅਚਲ ਅੱਖਰ *b)
{
	ਅੱਖਰ *ret = ਨਿਰਾ, *tmp = ਨਿਰਾ, *cp, *p;
	ਮਾਪ_t len;

	ਜੇ (a == ਨਿਰਾ || *a == '\0')
		ਵਾਪਸ strdup(b);
	ਜੇ (b == ਨਿਰਾ || *b == '\0')
		ਵਾਪਸ strdup(a);
	ਜੇ (ਲੜੀ_ਲੰਬਾਈ(b) > 1024*1024)
		ਵਾਪਸ ਨਿਰਾ;
	len = ਲੜੀ_ਲੰਬਾਈ(a) + ਲੜੀ_ਲੰਬਾਈ(b) + 2;
	ਜੇ ((tmp = cp = strdup(b)) == ਨਿਰਾ ||
	    (ret = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, len)) == ਨਿਰਾ) {
		ਮੁਕਤ(tmp);
		ਵਾਪਸ ਨਿਰਾ;
	}
	strlcpy(ret, a, len);
	ਲਈ ((p = strsep(&cp, ",")); p && *p != '\0'; (p = strsep(&cp, ","))) {
		ਜੇ (kex_has_any_alg(ret, p))
			ਜਾਰੀ; /* Algorithm already present */
		ਜੇ (strlcat(ret, ",", len) >= len ||
		    strlcat(ret, p, len) >= len) {
			ਮੁਕਤ(tmp);
			ਮੁਕਤ(ret);
			ਵਾਪਸ ਨਿਰਾ; /* Shouldn't happen */
		}
	}
	ਮੁਕਤ(tmp);
	ਵਾਪਸ ret;
}

/*
 * Assemble a list of algorithms from a default list and a string from a
 * configuration file. The user-provided string may begin with '+' to
 * indicate that it should be appended to the default, '-' that the
 * specified names should be removed, or '^' that they should be placed
 * at the head.
 */
ਪੂਰਨ
kex_assemble_ਨਾਂ(ਅੱਖਰ **listp, ਅਚਲ ਅੱਖਰ *def, ਅਚਲ ਅੱਖਰ *all)
{
	ਅੱਖਰ *cp, *tmp, *patterns;
	ਅੱਖਰ *list = ਨਿਰਾ, *ret = ਨਿਰਾ, *matching = ਨਿਰਾ, *opatterns = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ (listp == ਨਿਰਾ || def == ਨਿਰਾ || all == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;

	ਜੇ (*listp == ਨਿਰਾ || **listp == '\0') {
		ਜੇ ((*listp = strdup(def)) == ਨਿਰਾ)
			ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
		ਵਾਪਸ 0;
	}

	list = *listp;
	*listp = ਨਿਰਾ;
	ਜੇ (*list == '+') {
		/* Append names to default list */
		ਜੇ ((tmp = kex_ਨਾਂ_cat(def, list + 1)) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ fail;
		}
		ਮੁਕਤ(list);
		list = tmp;
	} ਨਹੀਂਤਾਂ ਜੇ (*list == '-') {
		/* Remove names from default list */
		ਜੇ ((*listp = ਮੇਲ_filter_denylist(def, list + 1)) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ fail;
		}
		ਮੁਕਤ(list);
		/* filtering has already been done */
		ਵਾਪਸ 0;
	} ਨਹੀਂਤਾਂ ਜੇ (*list == '^') {
		/* Place names at head of default list */
		ਜੇ ((tmp = kex_ਨਾਂ_cat(list + 1, def)) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ fail;
		}
		ਮੁਕਤ(list);
		list = tmp;
	} ਨਹੀਂਤਾਂ {
		/* Explicit list, overrides default - just use "list" as is */
	}

	/*
	 * The supplied names may be a pattern-list. For the -list case,
	 * the patterns are applied above. For the +list and explicit list
	 * cases we need to do it now.
	 */
	ret = ਨਿਰਾ;
	ਜੇ ((patterns = opatterns = strdup(list)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ fail;
	}
	/* Apply positive (i.e. non-negated) patterns from the list */
	ਜਦੋਂ ((cp = strsep(&patterns, ",")) != ਨਿਰਾ) {
		ਜੇ (*cp == '!') {
			/* negated matches are not supported here */
			r = SSH_ERR_INVALID_ਦਲੀਲ;
			ਜਾਓ fail;
		}
		ਮੁਕਤ(matching);
		ਜੇ ((matching = ਮੇਲ_filter_allowlist(all, cp)) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ fail;
		}
		ਜੇ ((tmp = kex_ਨਾਂ_cat(ret, matching)) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ fail;
		}
		ਮੁਕਤ(ret);
		ret = tmp;
	}
	ਜੇ (ret == ਨਿਰਾ || *ret == '\0') {
		/* An empty name-list is an error */
		/* XXX better error code? */
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ fail;
	}

	/* success */
	*listp = ret;
	ret = ਨਿਰਾ;
	r = 0;

 fail:
	ਮੁਕਤ(matching);
	ਮੁਕਤ(opatterns);
	ਮੁਕਤ(list);
	ਮੁਕਤ(ret);
	ਵਾਪਸ r;
}
