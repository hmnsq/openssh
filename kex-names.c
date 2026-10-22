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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <signal.h>

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/crypto.h>
#अन्तर्भाव <openssl/evp.h>
#endif

#अन्तर्भाव "kex.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "misc.h"

#अन्तर्भाव "ssherr.h"

संरचना kexalg {
	वर्ण *name;
	u_int type;
	पूर्णाङ्क ec_nid;
	पूर्णाङ्क hash_alg;
	पूर्णाङ्क pq_alg;
};
स्थिर ध्रुव संरचना kexalg kexalgs[] = {
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
#यदि defined(HAVE_EVP_SHA256) || !defined(WITH_OPENSSL)
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
	{ रिक्त, 0, -1, -1, 0 },
};

वर्ण *
kex_alg_list(वर्ण sep)
{
	वर्ण *ret = रिक्त;
	ध्रुव संरचना kexalg *k;
	वर्ण sep_str[2] = {sep, '\0'};

	प्रति (k = kexalgs; k->name != रिक्त; k++)
		xextendf(&ret, sep_str, "%s", k->name);

	प्रत्यागम ret;
}

स्थिर ध्रुव संरचना kexalg *
kex_alg_by_name(ध्रुव वर्ण *name)
{
	ध्रुव संरचना kexalg *k;

	प्रति (k = kexalgs; k->name != रिक्त; k++) {
		यदि (म_भेद(k->name, name) == 0)
			प्रत्यागम k;
	}
	प्रत्यागम रिक्त;
}

पूर्णाङ्क
kex_name_valid(ध्रुव वर्ण *name)
{
	प्रत्यागम kex_alg_by_name(name) != रिक्त;
}

पूर्णाङ्क
kex_is_pq_from_name(ध्रुव वर्ण *name)
{
	ध्रुव संरचना kexalg *k;

	यदि ((k = kex_alg_by_name(name)) == रिक्त)
		प्रत्यागम 0;
	प्रत्यागम k->pq_alg == KEX_IS_PQ;
}

u_int
kex_type_from_name(ध्रुव वर्ण *name)
{
	ध्रुव संरचना kexalg *k;

	यदि ((k = kex_alg_by_name(name)) == रिक्त)
		प्रत्यागम 0;
	प्रत्यागम k->type;
}

पूर्णाङ्क
kex_hash_from_name(ध्रुव वर्ण *name)
{
	ध्रुव संरचना kexalg *k;

	यदि ((k = kex_alg_by_name(name)) == रिक्त)
		प्रत्यागम -1;
	प्रत्यागम k->hash_alg;
}

पूर्णाङ्क
kex_nid_from_name(ध्रुव वर्ण *name)
{
	ध्रुव संरचना kexalg *k;

	यदि ((k = kex_alg_by_name(name)) == रिक्त)
		प्रत्यागम -1;
	प्रत्यागम k->ec_nid;
}

/* Validate KEX method name list */
पूर्णाङ्क
kex_names_valid(ध्रुव वर्ण *names)
{
	वर्ण *s, *cp, *p;

	यदि (names == रिक्त || म_भेद(names, "") == 0)
		प्रत्यागम 0;
	यदि ((s = cp = strdup(names)) == रिक्त)
		प्रत्यागम 0;
	प्रति ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		यदि (kex_alg_by_name(p) == रिक्त) {
			error("Unsupported KEX algorithm \"%.100s\"", p);
			मुक्त(s);
			प्रत्यागम 0;
		}
	}
	debug3("kex names ok: [%s]", names);
	मुक्त(s);
	प्रत्यागम 1;
}

/* returns non-zero if proposal contains any algorithm from algs */
पूर्णाङ्क
kex_has_any_alg(ध्रुव वर्ण *proposal, ध्रुव वर्ण *algs)
{
	वर्ण *cp;

	यदि ((cp = match_list(proposal, algs, रिक्त)) == रिक्त)
		प्रत्यागम 0;
	मुक्त(cp);
	प्रत्यागम 1;
}

/*
 * Concatenate algorithm names, avoiding duplicates in the process.
 * Caller must free returned string.
 */
वर्ण *
kex_names_cat(ध्रुव वर्ण *a, ध्रुव वर्ण *b)
{
	वर्ण *ret = रिक्त, *tmp = रिक्त, *cp, *p;
	माप_प्रकार len;

	यदि (a == रिक्त || *a == '\0')
		प्रत्यागम strdup(b);
	यदि (b == रिक्त || *b == '\0')
		प्रत्यागम strdup(a);
	यदि (म_माप(b) > 1024*1024)
		प्रत्यागम रिक्त;
	len = म_माप(a) + म_माप(b) + 2;
	यदि ((tmp = cp = strdup(b)) == रिक्त ||
	    (ret = सुस्मृति(1, len)) == रिक्त) {
		मुक्त(tmp);
		प्रत्यागम रिक्त;
	}
	strlcpy(ret, a, len);
	प्रति ((p = strsep(&cp, ",")); p && *p != '\0'; (p = strsep(&cp, ","))) {
		यदि (kex_has_any_alg(ret, p))
			अनुवर्त; /* Algorithm already present */
		यदि (strlcat(ret, ",", len) >= len ||
		    strlcat(ret, p, len) >= len) {
			मुक्त(tmp);
			मुक्त(ret);
			प्रत्यागम रिक्त; /* Shouldn't happen */
		}
	}
	मुक्त(tmp);
	प्रत्यागम ret;
}

/*
 * Assemble a list of algorithms from a default list and a string from a
 * configuration file. The user-provided string may begin with '+' to
 * indicate that it should be appended to the default, '-' that the
 * specified names should be removed, or '^' that they should be placed
 * at the head.
 */
पूर्णाङ्क
kex_assemble_names(वर्ण **listp, ध्रुव वर्ण *def, ध्रुव वर्ण *all)
{
	वर्ण *cp, *tmp, *patterns;
	वर्ण *list = रिक्त, *ret = रिक्त, *matching = रिक्त, *opatterns = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	यदि (listp == रिक्त || def == रिक्त || all == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;

	यदि (*listp == रिक्त || **listp == '\0') {
		यदि ((*listp = strdup(def)) == रिक्त)
			प्रत्यागम SSH_ERR_ALLOC_FAIL;
		प्रत्यागम 0;
	}

	list = *listp;
	*listp = रिक्त;
	यदि (*list == '+') {
		/* Append names to default list */
		यदि ((tmp = kex_names_cat(def, list + 1)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ fail;
		}
		मुक्त(list);
		list = tmp;
	} अन्यथा यदि (*list == '-') {
		/* Remove names from default list */
		यदि ((*listp = match_filter_denylist(def, list + 1)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ fail;
		}
		मुक्त(list);
		/* filtering has already been done */
		प्रत्यागम 0;
	} अन्यथा यदि (*list == '^') {
		/* Place names at head of default list */
		यदि ((tmp = kex_names_cat(list + 1, def)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ fail;
		}
		मुक्त(list);
		list = tmp;
	} अन्यथा {
		/* Explicit list, overrides default - just use "list" as is */
	}

	/*
	 * The supplied names may be a pattern-list. For the -list case,
	 * the patterns are applied above. For the +list and explicit list
	 * cases we need to do it now.
	 */
	ret = रिक्त;
	यदि ((patterns = opatterns = strdup(list)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ fail;
	}
	/* Apply positive (i.e. non-negated) patterns from the list */
	यावत् ((cp = strsep(&patterns, ",")) != रिक्त) {
		यदि (*cp == '!') {
			/* negated matches are not supported here */
			r = SSH_ERR_INVALID_ARGUMENT;
			गच्छ fail;
		}
		मुक्त(matching);
		यदि ((matching = match_filter_allowlist(all, cp)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ fail;
		}
		यदि ((tmp = kex_names_cat(ret, matching)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ fail;
		}
		मुक्त(ret);
		ret = tmp;
	}
	यदि (ret == रिक्त || *ret == '\0') {
		/* An empty name-list is an error */
		/* XXX better error code? */
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ fail;
	}

	/* success */
	*listp = ret;
	ret = रिक्त;
	r = 0;

 fail:
	मुक्त(matching);
	मुक्त(opatterns);
	मुक्त(list);
	मुक्त(ret);
	प्रत्यागम r;
}
