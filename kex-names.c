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

#شامل "includes.h"

#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <signal.h>

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/crypto.h>
#شامل <openssl/evp.h>
#اگر_ختم

#شامل "kex.h"
#شامل "log.h"
#شامل "match.h"
#شامل "digest.h"
#شامل "misc.h"

#شامل "ssherr.h"

ساخت kexalg {
	حرف *name;
	u_int type;
	صحیح ec_nid;
	صحیح hash_alg;
	صحیح pq_alg;
};
ساکن ثابت ساخت kexalg kexalgs[] = {
#اگر_تعریف_شدہ WITH_OPENSSL
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
#اگر_ختم /* WITH_OPENSSL */
#اگر defined(HAVE_EVP_SHA256) || !defined(WITH_OPENSSL)
	{ KEX_CURVE25519_SHA256, KEX_C25519_SHA256, 0, SSH_DIGEST_SHA256, KEX_NOT_PQ },
	{ KEX_CURVE25519_SHA256_OLD, KEX_C25519_SHA256, 0, SSH_DIGEST_SHA256, KEX_NOT_PQ },
#اگر_تعریف_شدہ USE_SNTRUP761X25519
	{ KEX_SNTRUP761X25519_SHA512, KEX_KEM_SNTRUP761X25519_SHA512, 0,
	    SSH_DIGEST_SHA512, KEX_IS_PQ },
	{ KEX_SNTRUP761X25519_SHA512_OLD, KEX_KEM_SNTRUP761X25519_SHA512, 0,
	    SSH_DIGEST_SHA512, KEX_IS_PQ },
#اگر_ختم
#اگر_تعریف_شدہ USE_MLKEM768X25519
	{ KEX_MLKEM768X25519_SHA256, KEX_KEM_MLKEM768X25519_SHA256, 0,
	    SSH_DIGEST_SHA256, KEX_IS_PQ },
#اگر_ختم
#اگر_ختم /* HAVE_EVP_SHA256 || !WITH_OPENSSL */
	{ تہی, 0, -1, -1, 0 },
};

حرف *
kex_alg_list(حرف sep)
{
	حرف *ret = تہی;
	ثابت ساخت kexalg *k;
	حرف sep_str[2] = {sep, '\0'};

	برائے (k = kexalgs; k->name != تہی; k++)
		xextendf(&ret, sep_str, "%s", k->name);

	واپس ret;
}

ساکن ثابت ساخت kexalg *
kex_alg_by_name(ثابت حرف *name)
{
	ثابت ساخت kexalg *k;

	برائے (k = kexalgs; k->name != تہی; k++) {
		اگر (strcmp(k->name, name) == 0)
			واپس k;
	}
	واپس تہی;
}

صحیح
kex_name_valid(ثابت حرف *name)
{
	واپس kex_alg_by_name(name) != تہی;
}

صحیح
kex_is_pq_from_name(ثابت حرف *name)
{
	ثابت ساخت kexalg *k;

	اگر ((k = kex_alg_by_name(name)) == تہی)
		واپس 0;
	واپس k->pq_alg == KEX_IS_PQ;
}

u_int
kex_type_from_name(ثابت حرف *name)
{
	ثابت ساخت kexalg *k;

	اگر ((k = kex_alg_by_name(name)) == تہی)
		واپس 0;
	واپس k->type;
}

صحیح
kex_hash_from_name(ثابت حرف *name)
{
	ثابت ساخت kexalg *k;

	اگر ((k = kex_alg_by_name(name)) == تہی)
		واپس -1;
	واپس k->hash_alg;
}

صحیح
kex_nid_from_name(ثابت حرف *name)
{
	ثابت ساخت kexalg *k;

	اگر ((k = kex_alg_by_name(name)) == تہی)
		واپس -1;
	واپس k->ec_nid;
}

/* Validate KEX method name list */
صحیح
kex_نام_valid(ثابت حرف *نام)
{
	حرف *s, *cp, *p;

	اگر (نام == تہی || strcmp(نام, "") == 0)
		واپس 0;
	اگر ((s = cp = strdup(نام)) == تہی)
		واپس 0;
	برائے ((p = strsep(&cp, ",")); p && *p != '\0';
	    (p = strsep(&cp, ","))) {
		اگر (kex_alg_by_name(p) == تہی) {
			error("Unsupported KEX algorithm \"%.100s\"", p);
			آزاد(s);
			واپس 0;
		}
	}
	debug3("kex names ok: [%s]", نام);
	آزاد(s);
	واپس 1;
}

/* returns non-zero if proposal contains any algorithm from algs */
صحیح
kex_has_any_alg(ثابت حرف *proposal, ثابت حرف *algs)
{
	حرف *cp;

	اگر ((cp = مطابقت_list(proposal, algs, تہی)) == تہی)
		واپس 0;
	آزاد(cp);
	واپس 1;
}

/*
 * Concatenate algorithm names, avoiding duplicates in the process.
 * Caller must free returned string.
 */
حرف *
kex_نام_cat(ثابت حرف *a, ثابت حرف *b)
{
	حرف *ret = تہی, *tmp = تہی, *cp, *p;
	سائز_t len;

	اگر (a == تہی || *a == '\0')
		واپس strdup(b);
	اگر (b == تہی || *b == '\0')
		واپس strdup(a);
	اگر (لڑی_لمبائی(b) > 1024*1024)
		واپس تہی;
	len = لڑی_لمبائی(a) + لڑی_لمبائی(b) + 2;
	اگر ((tmp = cp = strdup(b)) == تہی ||
	    (ret = صفر_حافظہ_دو(1, len)) == تہی) {
		آزاد(tmp);
		واپس تہی;
	}
	strlcpy(ret, a, len);
	برائے ((p = strsep(&cp, ",")); p && *p != '\0'; (p = strsep(&cp, ","))) {
		اگر (kex_has_any_alg(ret, p))
			جاری; /* Algorithm already present */
		اگر (strlcat(ret, ",", len) >= len ||
		    strlcat(ret, p, len) >= len) {
			آزاد(tmp);
			آزاد(ret);
			واپس تہی; /* Shouldn't happen */
		}
	}
	آزاد(tmp);
	واپس ret;
}

/*
 * Assemble a list of algorithms from a default list and a string from a
 * configuration file. The user-provided string may begin with '+' to
 * indicate that it should be appended to the default, '-' that the
 * specified names should be removed, or '^' that they should be placed
 * at the head.
 */
صحیح
kex_assemble_نام(حرف **listp, ثابت حرف *def, ثابت حرف *all)
{
	حرف *cp, *tmp, *patterns;
	حرف *list = تہی, *ret = تہی, *matching = تہی, *opatterns = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;

	اگر (listp == تہی || def == تہی || all == تہی)
		واپس SSH_ERR_INVALID_دلیل;

	اگر (*listp == تہی || **listp == '\0') {
		اگر ((*listp = strdup(def)) == تہی)
			واپس SSH_ERR_ALLOC_FAIL;
		واپس 0;
	}

	list = *listp;
	*listp = تہی;
	اگر (*list == '+') {
		/* Append names to default list */
		اگر ((tmp = kex_نام_cat(def, list + 1)) == تہی) {
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ fail;
		}
		آزاد(list);
		list = tmp;
	} ورنہ اگر (*list == '-') {
		/* Remove names from default list */
		اگر ((*listp = مطابقت_filter_denylist(def, list + 1)) == تہی) {
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ fail;
		}
		آزاد(list);
		/* filtering has already been done */
		واپس 0;
	} ورنہ اگر (*list == '^') {
		/* Place names at head of default list */
		اگر ((tmp = kex_نام_cat(list + 1, def)) == تہی) {
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ fail;
		}
		آزاد(list);
		list = tmp;
	} ورنہ {
		/* Explicit list, overrides default - just use "list" as is */
	}

	/*
	 * The supplied names may be a pattern-list. For the -list case,
	 * the patterns are applied above. For the +list and explicit list
	 * cases we need to do it now.
	 */
	ret = تہی;
	اگر ((patterns = opatterns = strdup(list)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ fail;
	}
	/* Apply positive (i.e. non-negated) patterns from the list */
	جب ((cp = strsep(&patterns, ",")) != تہی) {
		اگر (*cp == '!') {
			/* negated matches are not supported here */
			r = SSH_ERR_INVALID_دلیل;
			جاؤ fail;
		}
		آزاد(matching);
		اگر ((matching = مطابقت_filter_allowlist(all, cp)) == تہی) {
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ fail;
		}
		اگر ((tmp = kex_نام_cat(ret, matching)) == تہی) {
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ fail;
		}
		آزاد(ret);
		ret = tmp;
	}
	اگر (ret == تہی || *ret == '\0') {
		/* An empty name-list is an error */
		/* XXX better error code? */
		r = SSH_ERR_INVALID_دلیل;
		جاؤ fail;
	}

	/* success */
	*listp = ret;
	ret = تہی;
	r = 0;

 fail:
	آزاد(matching);
	آزاد(opatterns);
	آزاد(list);
	آزاد(ret);
	واپس r;
}
