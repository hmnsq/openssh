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

#समावेश "includes.h"

#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <signal.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/crypto.h>
#समावेश <openssl/evp.h>
#पूर्ण_अगर

#समावेश "kex.h"
#समावेश "log.h"
#समावेश "match.h"
#समावेश "digest.h"
#समावेश "misc.h"

#समावेश "ssherr.h"

काष्ठा kexalg {
	अक्षर *name;
	u_int type;
	पूर्णांक ec_nid;
	पूर्णांक hash_alg;
	पूर्णांक pq_alg;
};
अटल स्थिर काष्ठा kexalg kexalgs[] = {
#अगर_घोषित WITH_OPENSSL
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
#पूर्ण_अगर /* WITH_OPENSSL */
#अगर defined(HAVE_EVP_SHA256) || !defined(WITH_OPENSSL)
	{ KEX_CURVE25519_SHA256, KEX_C25519_SHA256, 0, SSH_DIGEST_SHA256, KEX_NOT_PQ },
	{ KEX_CURVE25519_SHA256_OLD, KEX_C25519_SHA256, 0, SSH_DIGEST_SHA256, KEX_NOT_PQ },
#अगर_घोषित USE_SNTRUP761X25519
	{ KEX_SNTRUP761X25519_SHA512, KEX_KEM_SNTRUP761X25519_SHA512, 0,
	    SSH_DIGEST_SHA512, KEX_IS_PQ },
	{ KEX_SNTRUP761X25519_SHA512_OLD, KEX_KEM_SNTRUP761X25519_SHA512, 0,
	    SSH_DIGEST_SHA512, KEX_IS_PQ },
#पूर्ण_अगर
#अगर_घोषित USE_MLKEM768X25519
	{ KEX_MLKEM768X25519_SHA256, KEX_KEM_MLKEM768X25519_SHA256, 0,
	    SSH_DIGEST_SHA256, KEX_IS_PQ },
#पूर्ण_अगर
#पूर्ण_अगर /* HAVE_EVP_SHA256 || !WITH_OPENSSL */
	{ शून्य, 0, -1, -1, 0 },
};

अक्षर *
kex_alg_list(अक्षर sep)
{
	अक्षर *ret = शून्य;
	स्थिर काष्ठा kexalg *k;
	अक्षर sep_str[2] = {sep, '\0'};

	क्रम (k = kexalgs; k->name != शून्य; k++)
		xextendf(&ret, sep_str, "%s", k->name);

	वापस ret;
}

अटल स्थिर काष्ठा kexalg *
kex_alg_by_name(स्थिर अक्षर *name)
{
	स्थिर काष्ठा kexalg *k;

	क्रम (k = kexalgs; k->name != शून्य; k++) {
		अगर (म_भेद(k->name, name) == 0)
			वापस k;
	}
	वापस शून्य;
}

पूर्णांक
kex_name_valid(स्थिर अक्षर *name)
{
	वापस kex_alg_by_name(name) != शून्य;
}

पूर्णांक
kex_is_pq_from_name(स्थिर अक्षर *name)
{
	स्थिर काष्ठा kexalg *k;

	अगर ((k = kex_alg_by_name(name)) == शून्य)
		वापस 0;
	वापस k->pq_alg == KEX_IS_PQ;
}

u_int
kex_type_from_name(स्थिर अक्षर *name)
{
	स्थिर काष्ठा kexalg *k;

	अगर ((k = kex_alg_by_name(name)) == शून्य)
		वापस 0;
	वापस k->type;
}

पूर्णांक
kex_hash_from_name(स्थिर अक्षर *name)
{
	स्थिर काष्ठा kexalg *k;

	अगर ((k = kex_alg_by_name(name)) == शून्य)
		वापस -1;
	वापस k->hash_alg;
}

पूर्णांक
kex_nid_from_name(स्थिर अक्षर *name)
{
	स्थिर काष्ठा kexalg *k;

	अगर ((k = kex_alg_by_name(name)) == शून्य)
		वापस -1;
	वापस k->ec_nid;
}

/* Validate KEX method name list */
पूर्णांक
kex_names_valid(स्थिर अक्षर *names)
{
	अक्षर *s, *cp, *p;

	अगर (names == शून्य || म_भेद(names, "") == 0)
		वापस 0;
	अगर ((s = cp = strdup(names)) == शून्य)
		वापस 0;
	क्रम ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		अगर (kex_alg_by_name(p) == शून्य) {
			error("Unsupported KEX algorithm \"%.100s\"", p);
			मुक्त(s);
			वापस 0;
		}
	}
	debug3("kex names ok: [%s]", names);
	मुक्त(s);
	वापस 1;
}

/* returns non-zero if proposal contains any algorithm from algs */
पूर्णांक
kex_has_any_alg(स्थिर अक्षर *proposal, स्थिर अक्षर *algs)
{
	अक्षर *cp;

	अगर ((cp = match_list(proposal, algs, शून्य)) == शून्य)
		वापस 0;
	मुक्त(cp);
	वापस 1;
}

/*
 * Concatenate algorithm names, avoiding duplicates in the process.
 * Caller must free returned string.
 */
अक्षर *
kex_names_cat(स्थिर अक्षर *a, स्थिर अक्षर *b)
{
	अक्षर *ret = शून्य, *tmp = शून्य, *cp, *p;
	माप_प्रकार len;

	अगर (a == शून्य || *a == '\0')
		वापस strdup(b);
	अगर (b == शून्य || *b == '\0')
		वापस strdup(a);
	अगर (म_माप(b) > 1024*1024)
		वापस शून्य;
	len = म_माप(a) + म_माप(b) + 2;
	अगर ((tmp = cp = strdup(b)) == शून्य ||
	    (ret = सुस्मृति(1, len)) == शून्य) {
		मुक्त(tmp);
		वापस शून्य;
	}
	strlcpy(ret, a, len);
	क्रम ((p = strsep(&cp, ",")); p && *p != '\0'; (p = strsep(&cp, ","))) {
		अगर (kex_has_any_alg(ret, p))
			जारी; /* Algorithm already present */
		अगर (strlcat(ret, ",", len) >= len ||
		    strlcat(ret, p, len) >= len) {
			मुक्त(tmp);
			मुक्त(ret);
			वापस शून्य; /* Shouldn't happen */
		}
	}
	मुक्त(tmp);
	वापस ret;
}

/*
 * Assemble a list of algorithms from a default list and a string from a
 * configuration file. The user-provided string may begin with '+' to
 * indicate that it should be appended to the default, '-' that the
 * specified names should be removed, or '^' that they should be placed
 * at the head.
 */
पूर्णांक
kex_assemble_names(अक्षर **listp, स्थिर अक्षर *def, स्थिर अक्षर *all)
{
	अक्षर *cp, *tmp, *patterns;
	अक्षर *list = शून्य, *ret = शून्य, *matching = शून्य, *opatterns = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	अगर (listp == शून्य || def == शून्य || all == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;

	अगर (*listp == शून्य || **listp == '\0') {
		अगर ((*listp = strdup(def)) == शून्य)
			वापस SSH_ERR_ALLOC_FAIL;
		वापस 0;
	}

	list = *listp;
	*listp = शून्य;
	अगर (*list == '+') {
		/* Append names to default list */
		अगर ((tmp = kex_names_cat(def, list + 1)) == शून्य) {
			r = SSH_ERR_ALLOC_FAIL;
			जाओ fail;
		}
		मुक्त(list);
		list = tmp;
	} अन्यथा अगर (*list == '-') {
		/* Remove names from default list */
		अगर ((*listp = match_filter_denylist(def, list + 1)) == शून्य) {
			r = SSH_ERR_ALLOC_FAIL;
			जाओ fail;
		}
		मुक्त(list);
		/* filtering has already been done */
		वापस 0;
	} अन्यथा अगर (*list == '^') {
		/* Place names at head of default list */
		अगर ((tmp = kex_names_cat(list + 1, def)) == शून्य) {
			r = SSH_ERR_ALLOC_FAIL;
			जाओ fail;
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
	ret = शून्य;
	अगर ((patterns = opatterns = strdup(list)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ fail;
	}
	/* Apply positive (i.e. non-negated) patterns from the list */
	जबतक ((cp = strsep(&patterns, ",")) != शून्य) {
		अगर (*cp == '!') {
			/* negated matches are not supported here */
			r = SSH_ERR_INVALID_ARGUMENT;
			जाओ fail;
		}
		मुक्त(matching);
		अगर ((matching = match_filter_allowlist(all, cp)) == शून्य) {
			r = SSH_ERR_ALLOC_FAIL;
			जाओ fail;
		}
		अगर ((tmp = kex_names_cat(ret, matching)) == शून्य) {
			r = SSH_ERR_ALLOC_FAIL;
			जाओ fail;
		}
		मुक्त(ret);
		ret = tmp;
	}
	अगर (ret == शून्य || *ret == '\0') {
		/* An empty name-list is an error */
		/* XXX better error code? */
		r = SSH_ERR_INVALID_ARGUMENT;
		जाओ fail;
	}

	/* success */
	*listp = ret;
	ret = शून्य;
	r = 0;

 fail:
	मुक्त(matching);
	मुक्त(opatterns);
	मुक्त(list);
	मुक्त(ret);
	वापस r;
}
