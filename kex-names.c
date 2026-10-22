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
	अक्षर *name;
	u_int type;
	पूर्णांक ec_nid;
	पूर्णांक hash_alg;
	पूर्णांक pq_alg;
};
स्थिर स्थिरांक संरचना kexalg kexalgs[] = {
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
#जर defined(HAVE_EVP_SHA256) || !defined(WITH_OPENSSL)
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

अक्षर *
kex_alg_list(अक्षर sep)
{
	अक्षर *ret = रिक्त;
	स्थिरांक संरचना kexalg *k;
	अक्षर sep_str[2] = {sep, '\0'};

	साठी (k = kexalgs; k->name != रिक्त; k++)
		xextendf(&ret, sep_str, "%s", k->name);

	परत ret;
}

स्थिर स्थिरांक संरचना kexalg *
kex_alg_by_name(स्थिरांक अक्षर *name)
{
	स्थिरांक संरचना kexalg *k;

	साठी (k = kexalgs; k->name != रिक्त; k++) {
		जर (म_भेद(k->name, name) == 0)
			परत k;
	}
	परत रिक्त;
}

पूर्णांक
kex_name_valid(स्थिरांक अक्षर *name)
{
	परत kex_alg_by_name(name) != रिक्त;
}

पूर्णांक
kex_is_pq_from_name(स्थिरांक अक्षर *name)
{
	स्थिरांक संरचना kexalg *k;

	जर ((k = kex_alg_by_name(name)) == रिक्त)
		परत 0;
	परत k->pq_alg == KEX_IS_PQ;
}

u_int
kex_type_from_name(स्थिरांक अक्षर *name)
{
	स्थिरांक संरचना kexalg *k;

	जर ((k = kex_alg_by_name(name)) == रिक्त)
		परत 0;
	परत k->type;
}

पूर्णांक
kex_hash_from_name(स्थिरांक अक्षर *name)
{
	स्थिरांक संरचना kexalg *k;

	जर ((k = kex_alg_by_name(name)) == रिक्त)
		परत -1;
	परत k->hash_alg;
}

पूर्णांक
kex_nid_from_name(स्थिरांक अक्षर *name)
{
	स्थिरांक संरचना kexalg *k;

	जर ((k = kex_alg_by_name(name)) == रिक्त)
		परत -1;
	परत k->ec_nid;
}

/* Validate KEX method name list */
पूर्णांक
kex_names_valid(स्थिरांक अक्षर *names)
{
	अक्षर *s, *cp, *p;

	जर (names == रिक्त || म_भेद(names, "") == 0)
		परत 0;
	जर ((s = cp = strdup(names)) == रिक्त)
		परत 0;
	साठी ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		जर (kex_alg_by_name(p) == रिक्त) {
			error("Unsupported KEX algorithm \"%.100s\"", p);
			मुक्त(s);
			परत 0;
		}
	}
	debug3("kex names ok: [%s]", names);
	मुक्त(s);
	परत 1;
}

/* returns non-zero if proposal contains any algorithm from algs */
पूर्णांक
kex_has_any_alg(स्थिरांक अक्षर *proposal, स्थिरांक अक्षर *algs)
{
	अक्षर *cp;

	जर ((cp = match_list(proposal, algs, रिक्त)) == रिक्त)
		परत 0;
	मुक्त(cp);
	परत 1;
}

/*
 * Concatenate algorithm names, avoiding duplicates in the process.
 * Caller must free returned string.
 */
अक्षर *
kex_names_cat(स्थिरांक अक्षर *a, स्थिरांक अक्षर *b)
{
	अक्षर *ret = रिक्त, *tmp = रिक्त, *cp, *p;
	माप_प्रकार len;

	जर (a == रिक्त || *a == '\0')
		परत strdup(b);
	जर (b == रिक्त || *b == '\0')
		परत strdup(a);
	जर (म_माप(b) > 1024*1024)
		परत रिक्त;
	len = म_माप(a) + म_माप(b) + 2;
	जर ((tmp = cp = strdup(b)) == रिक्त ||
	    (ret = सुस्मृति(1, len)) == रिक्त) {
		मुक्त(tmp);
		परत रिक्त;
	}
	strlcpy(ret, a, len);
	साठी ((p = strsep(&cp, ",")); p && *p != '\0'; (p = strsep(&cp, ","))) {
		जर (kex_has_any_alg(ret, p))
			सुरूठेवा; /* Algorithm already present */
		जर (strlcat(ret, ",", len) >= len ||
		    strlcat(ret, p, len) >= len) {
			मुक्त(tmp);
			मुक्त(ret);
			परत रिक्त; /* Shouldn't happen */
		}
	}
	मुक्त(tmp);
	परत ret;
}

/*
 * Assemble a list of algorithms from a default list and a string from a
 * configuration file. The user-provided string may begin with '+' to
 * indicate that it should be appended to the default, '-' that the
 * specified names should be removed, or '^' that they should be placed
 * at the head.
 */
पूर्णांक
kex_assemble_names(अक्षर **listp, स्थिरांक अक्षर *def, स्थिरांक अक्षर *all)
{
	अक्षर *cp, *tmp, *patterns;
	अक्षर *list = रिक्त, *ret = रिक्त, *matching = रिक्त, *opatterns = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	जर (listp == रिक्त || def == रिक्त || all == रिक्त)
		परत SSH_ERR_INVALID_ARGUMENT;

	जर (*listp == रिक्त || **listp == '\0') {
		जर ((*listp = strdup(def)) == रिक्त)
			परत SSH_ERR_ALLOC_FAIL;
		परत 0;
	}

	list = *listp;
	*listp = रिक्त;
	जर (*list == '+') {
		/* Append names to default list */
		जर ((tmp = kex_names_cat(def, list + 1)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			जा fail;
		}
		मुक्त(list);
		list = tmp;
	} अन्यथा जर (*list == '-') {
		/* Remove names from default list */
		जर ((*listp = match_filter_denylist(def, list + 1)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			जा fail;
		}
		मुक्त(list);
		/* filtering has already been done */
		परत 0;
	} अन्यथा जर (*list == '^') {
		/* Place names at head of default list */
		जर ((tmp = kex_names_cat(list + 1, def)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			जा fail;
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
	जर ((patterns = opatterns = strdup(list)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा fail;
	}
	/* Apply positive (i.e. non-negated) patterns from the list */
	पर्यंत ((cp = strsep(&patterns, ",")) != रिक्त) {
		जर (*cp == '!') {
			/* negated matches are not supported here */
			r = SSH_ERR_INVALID_ARGUMENT;
			जा fail;
		}
		मुक्त(matching);
		जर ((matching = match_filter_allowlist(all, cp)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			जा fail;
		}
		जर ((tmp = kex_names_cat(ret, matching)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			जा fail;
		}
		मुक्त(ret);
		ret = tmp;
	}
	जर (ret == रिक्त || *ret == '\0') {
		/* An empty name-list is an error */
		/* XXX better error code? */
		r = SSH_ERR_INVALID_ARGUMENT;
		जा fail;
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
	परत r;
}
