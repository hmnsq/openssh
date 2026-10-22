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

#ضمن "includes.h"

#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <signal.h>

#ifdef WITH_OPENSSL
#ضمن <openssl/crypto.h>
#ضمن <openssl/evp.h>
#endif

#ضمن "kex.h"
#ضمن "log.h"
#ضمن "match.h"
#ضمن "digest.h"
#ضمن "misc.h"

#ضمن "ssherr.h"

بنية kexalg {
	حرف *name;
	u_int type;
	صحيح ec_nid;
	صحيح hash_alg;
	صحيح pq_alg;
};
ساكن ثابت بنية kexalg kexalgs[] = {
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
#𐡄𐡍 defined(HAVE_EVP_SHA256) || !defined(WITH_OPENSSL)
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
	{ عدم, 0, -1, -1, 0 },
};

حرف *
kex_alg_list(حرف sep)
{
	حرف *ret = عدم;
	ثابت بنية kexalg *k;
	حرف sep_str[2] = {sep, '\0'};

	لكل (k = kexalgs; k->name != عدم; k++)
		xextendf(&ret, sep_str, "%s", k->name);

	أرجع ret;
}

ساكن ثابت بنية kexalg *
kex_alg_by_name(ثابت حرف *name)
{
	ثابت بنية kexalg *k;

	لكل (k = kexalgs; k->name != عدم; k++) {
		𐡄𐡍 (strcmp(k->name, name) == 0)
			أرجع k;
	}
	أرجع عدم;
}

صحيح
kex_name_valid(ثابت حرف *name)
{
	أرجع kex_alg_by_name(name) != عدم;
}

صحيح
kex_is_pq_from_name(ثابت حرف *name)
{
	ثابت بنية kexalg *k;

	𐡄𐡍 ((k = kex_alg_by_name(name)) == عدم)
		أرجع 0;
	أرجع k->pq_alg == KEX_IS_PQ;
}

u_int
kex_type_from_name(ثابت حرف *name)
{
	ثابت بنية kexalg *k;

	𐡄𐡍 ((k = kex_alg_by_name(name)) == عدم)
		أرجع 0;
	أرجع k->type;
}

صحيح
kex_hash_from_name(ثابت حرف *name)
{
	ثابت بنية kexalg *k;

	𐡄𐡍 ((k = kex_alg_by_name(name)) == عدم)
		أرجع -1;
	أرجع k->hash_alg;
}

صحيح
kex_nid_from_name(ثابت حرف *name)
{
	ثابت بنية kexalg *k;

	𐡄𐡍 ((k = kex_alg_by_name(name)) == عدم)
		أرجع -1;
	أرجع k->ec_nid;
}

/* Validate KEX method name list */
صحيح
kex_names_valid(ثابت حرف *names)
{
	حرف *s, *cp, *p;

	𐡄𐡍 (names == عدم || strcmp(names, "") == 0)
		أرجع 0;
	𐡄𐡍 ((s = cp = strdup(names)) == عدم)
		أرجع 0;
	لكل ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		𐡄𐡍 (kex_alg_by_name(p) == عدم) {
			error("Unsupported KEX algorithm \"%.100s\"", p);
			حرر(s);
			أرجع 0;
		}
	}
	debug3("kex names ok: [%s]", names);
	حرر(s);
	أرجع 1;
}

/* returns non-zero if proposal contains any algorithm from algs */
صحيح
kex_has_any_alg(ثابت حرف *proposal, ثابت حرف *algs)
{
	حرف *cp;

	𐡄𐡍 ((cp = match_list(proposal, algs, عدم)) == عدم)
		أرجع 0;
	حرر(cp);
	أرجع 1;
}

/*
 * Concatenate algorithm names, avoiding duplicates in the process.
 * Caller must free returned string.
 */
حرف *
kex_names_cat(ثابت حرف *a, ثابت حرف *b)
{
	حرف *ret = عدم, *tmp = عدم, *cp, *p;
	size_t len;

	𐡄𐡍 (a == عدم || *a == '\0')
		أرجع strdup(b);
	𐡄𐡍 (b == عدم || *b == '\0')
		أرجع strdup(a);
	𐡄𐡍 (strlen(b) > 1024*1024)
		أرجع عدم;
	len = strlen(a) + strlen(b) + 2;
	𐡄𐡍 ((tmp = cp = strdup(b)) == عدم ||
	    (ret = calloc(1, len)) == عدم) {
		حرر(tmp);
		أرجع عدم;
	}
	strlcpy(ret, a, len);
	لكل ((p = strsep(&cp, ",")); p && *p != '\0'; (p = strsep(&cp, ","))) {
		𐡄𐡍 (kex_has_any_alg(ret, p))
			استمر; /* Algorithm already present */
		𐡄𐡍 (strlcat(ret, ",", len) >= len ||
		    strlcat(ret, p, len) >= len) {
			حرر(tmp);
			حرر(ret);
			أرجع عدم; /* Shouldn't happen */
		}
	}
	حرر(tmp);
	أرجع ret;
}

/*
 * Assemble a list of algorithms from a default list and a string from a
 * configuration file. The user-provided string may begin with '+' to
 * indicate that it should be appended to the default, '-' that the
 * specified names should be removed, or '^' that they should be placed
 * at the head.
 */
صحيح
kex_assemble_names(حرف **listp, ثابت حرف *def, ثابت حرف *all)
{
	حرف *cp, *tmp, *patterns;
	حرف *list = عدم, *ret = عدم, *matching = عدم, *opatterns = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	𐡄𐡍 (listp == عدم || def == عدم || all == عدم)
		أرجع SSH_ERR_INVALID_ARGUMENT;

	𐡄𐡍 (*listp == عدم || **listp == '\0') {
		𐡄𐡍 ((*listp = strdup(def)) == عدم)
			أرجع SSH_ERR_ALLOC_FAIL;
		أرجع 0;
	}

	list = *listp;
	*listp = عدم;
	𐡄𐡍 (*list == '+') {
		/* Append names to default list */
		𐡄𐡍 ((tmp = kex_names_cat(def, list + 1)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب fail;
		}
		حرر(list);
		list = tmp;
	} وإلا 𐡄𐡍 (*list == '-') {
		/* Remove names from default list */
		𐡄𐡍 ((*listp = match_filter_denylist(def, list + 1)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب fail;
		}
		حرر(list);
		/* filtering has already been done */
		أرجع 0;
	} وإلا 𐡄𐡍 (*list == '^') {
		/* Place names at head of default list */
		𐡄𐡍 ((tmp = kex_names_cat(list + 1, def)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب fail;
		}
		حرر(list);
		list = tmp;
	} وإلا {
		/* Explicit list, overrides default - just use "list" as is */
	}

	/*
	 * The supplied names may be a pattern-list. For the -list case,
	 * the patterns are applied above. For the +list and explicit list
	 * cases we need to do it now.
	 */
	ret = عدم;
	𐡄𐡍 ((patterns = opatterns = strdup(list)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب fail;
	}
	/* Apply positive (i.e. non-negated) patterns from the list */
	طالما ((cp = strsep(&patterns, ",")) != عدم) {
		𐡄𐡍 (*cp == '!') {
			/* negated matches are not supported here */
			r = SSH_ERR_INVALID_ARGUMENT;
			اذهب fail;
		}
		حرر(matching);
		𐡄𐡍 ((matching = match_filter_allowlist(all, cp)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب fail;
		}
		𐡄𐡍 ((tmp = kex_names_cat(ret, matching)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب fail;
		}
		حرر(ret);
		ret = tmp;
	}
	𐡄𐡍 (ret == عدم || *ret == '\0') {
		/* An empty name-list is an error */
		/* XXX better error code? */
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب fail;
	}

	/* success */
	*listp = ret;
	ret = عدم;
	r = 0;

 fail:
	حرر(matching);
	حرر(opatterns);
	حرر(list);
	حرر(ret);
	أرجع r;
}
