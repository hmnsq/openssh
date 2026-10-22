/* $OpenBSD: ssh-pkcs11.c,v 1.78 2026/03/03 09:57:25 dtucker Exp $ */
/*
 * Copyright (c) 2010 Markus Friedl.  All rights reserved.
 * Copyright (c) 2014 Pedro Martelletto. All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#अन्तर्भाव "includes.h"

#यदि_परिभाषितम् ENABLE_PKCS11

#अन्तर्भाव <sys/time.h>

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/queue.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>

#अन्तर्भाव <string.h>
#अन्तर्भाव <dlfcn.h>

#यदि_परिभाषितम् WITH_OPENSSL
#अन्तर्भाव "openbsd-compat/openssl-compat.h"
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/ecdsa.h>
#अन्तर्भाव <openssl/x509.h>
#अन्तर्भाव <openssl/err.h>
#यदि_अन्तः

#परिभाषय CRYPTOKI_COMPAT
#अन्तर्भाव "pkcs11.h"

#परिभाषय SSHKEY_आन्तरिकम्
#अन्तर्भाव "sshkey.h"

#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssh-pkcs11.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "crypto_api.h"

संरचना pkcs11_slotinfo {
	CK_TOKEN_INFO		token;
	CK_SESSION_HANDLE	session;
	पूर्णाङ्क			logged_अन्तर्;
};

संरचना pkcs11_provider {
	वर्ण			*name;
	शून्य			*handle;
	CK_FUNCTION_LIST	*function_list;
	CK_INFO			info;
	CK_ULONG		nslots;
	CK_SLOT_ID		*slotlist;
	संरचना pkcs11_slotinfo	*slotinfo;
	पूर्णाङ्क			valid;
	पूर्णाङ्क			refcount;
	TAILQ_ENTRY(pkcs11_provider) अग्र;
};

TAILQ_HEAD(, pkcs11_provider) pkcs11_providers;

संरचना pkcs11_कुञ्चिका {
	संरचना sshbuf		*keyblob;
	संरचना pkcs11_provider	*provider;
	CK_ULONG		slotidx;
	वर्ण			*keyid;
	पूर्णाङ्क			keyid_len;
	TAILQ_ENTRY(pkcs11_कुञ्चिका)	अग्र;
};

TAILQ_HEAD(, pkcs11_कुञ्चिका) pkcs11_कुञ्चिकाः; /* XXX a tree would be better */

पूर्णाङ्क pkcs11_interactive = 0;

#यदि_परिभाषितम् WITH_OPENSSL
स्थिर शून्य
ossl_error(ध्रुव वर्ण *सन्देशः)
{
	अचिह्नित दीर्घ    e;

	error_f("%s", सन्देशः);
	यावत् ((e = ERR_get_error()) != 0)
		error_f("libcrypto error: %s", ERR_error_string(e, रिक्त));
}
#यदि_अन्तः

/*
 * finalize a provider shared library, it's no longer usable.
 * however, there might still be keys referencing this provider,
 * so the actual freeing of memory is handled by pkcs11_provider_unref().
 * this is called when a provider gets unregistered.
 */
स्थिर शून्य
pkcs11_provider_finalize(संरचना pkcs11_provider *p)
{
	CK_RV rv;
	CK_ULONG i;

	debug_f("provider \"%s\" refcount %d valid %d",
	    p->name, p->refcount, p->valid);
	यदि (!p->valid)
		प्रत्यागम;
	प्रति (i = 0; i < p->nslots; i++) {
		यदि (p->slotinfo[i].session &&
		    (rv = p->function_list->C_CloseSession(
		    p->slotinfo[i].session)) != CKR_OK)
			error("C_CloseSession failed: %lu", rv);
	}
	यदि ((rv = p->function_list->C_Finalize(रिक्त)) != CKR_OK)
		error("C_Finalize failed: %lu", rv);
	p->valid = 0;
	p->function_list = रिक्त;
	dlclose(p->handle);
}

/*
 * remove a reference to the provider.
 * called when a key gets destroyed or when the provider is unregistered.
 */
स्थिर शून्य
pkcs11_provider_unref(संरचना pkcs11_provider *p)
{
	debug_f("provider \"%s\" refcount %d", p->name, p->refcount);
	यदि (--p->refcount <= 0) {
		यदि (p->valid)
			error_f("provider \"%s\" still valid", p->name);
		मुक्त(p->name);
		मुक्त(p->slotlist);
		मुक्त(p->slotinfo);
		मुक्त(p);
	}
}

/* lookup provider by name */
स्थिर संरचना pkcs11_provider *
pkcs11_provider_lookup(वर्ण *provider_id)
{
	संरचना pkcs11_provider *p;

	TAILQ_FOREACH(p, &pkcs11_providers, अग्र) {
		debug("check provider \"%s\"", p->name);
		यदि (!वाक्यं_तुलय(provider_id, p->name))
			प्रत्यागम (p);
	}
	प्रत्यागम (रिक्त);
}

/* unregister provider by name */
पूर्णाङ्क
pkcs11_del_provider(वर्ण *provider_id)
{
	संरचना pkcs11_provider *p;

	यदि ((p = pkcs11_provider_lookup(provider_id)) != रिक्त) {
		TAILQ_REMOVE(&pkcs11_providers, p, अग्र);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
		प्रत्यागम (0);
	}
	प्रत्यागम (-1);
}

/* release a wrapped object */
स्थिर शून्य
pkcs11_k11_free(संरचना pkcs11_कुञ्चिका *k11)
{
	यदि (k11 == रिक्त)
		प्रत्यागम;
	यदि (k11->provider)
		pkcs11_provider_unref(k11->provider);
	मुक्त(k11->keyid);
	sshbuf_free(k11->keyblob);
	मुक्त(k11);
}

/* find a single 'obj' for given attributes */
स्थिर पूर्णाङ्क
pkcs11_find(संरचना pkcs11_provider *p, CK_ULONG slotidx, CK_ATTRIBUTE *attr,
    CK_ULONG nattr, CK_OBJECT_HANDLE *obj)
{
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	session;
	CK_ULONG		nfound = 0;
	CK_RV			rv;
	पूर्णाङ्क			ret = -1;

	f = p->function_list;
	session = p->slotinfo[slotidx].session;
	यदि ((rv = f->C_FindObjectsInit(session, attr, nattr)) != CKR_OK) {
		error("C_FindObjectsInit failed (nattr %lu): %lu", nattr, rv);
		प्रत्यागम (-1);
	}
	यदि ((rv = f->C_FindObjects(session, obj, 1, &nfound)) != CKR_OK ||
	    nfound != 1) {
		debug("C_FindObjects failed (nfound %lu nattr %lu): %lu",
		    nfound, nattr, rv);
	} अन्यथा
		ret = 0;
	यदि ((rv = f->C_FindObjectsFinal(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	प्रत्यागम (ret);
}

स्थिर पूर्णाङ्क
pkcs11_login_slot(संरचना pkcs11_provider *provider, संरचना pkcs11_slotinfo *si,
    CK_USER_TYPE type)
{
	वर्ण			*pin = रिक्त, prompt[1024];
	CK_RV			 rv;

	यदि (provider == रिक्त || si == रिक्त || !provider->valid) {
		error("no pkcs11 (valid) provider found");
		प्रत्यागम (-1);
	}

	यदि (!pkcs11_interactive) {
		error("need pin entry%s",
		    (si->token.flags & CKF_PROTECTED_AUTHENTICATION_मार्गः) ?
		    " on reader keypad" : "");
		प्रत्यागम (-1);
	}
	यदि (si->token.flags & CKF_PROTECTED_AUTHENTICATION_मार्गः)
		verbose("Deferring PIN entry to reader keypad.");
	अन्यथा {
		snprintf(prompt, परिमाण(prompt), "Enter PIN for '%s': ",
		    si->token.label);
		यदि ((pin = read_passphrase(prompt, RP_ALLOW_EOF)) == रिक्त) {
			debug_f("no pin specified");
			प्रत्यागम (-1);	/* bail out */
		}
	}
	rv = provider->function_list->C_Login(si->session, type, (u_char *)pin,
	    (pin != रिक्त) ? वाक्यदैर्घ्यम्(pin) : 0);
	यदि (pin != रिक्त)
		freezero(pin, वाक्यदैर्घ्यम्(pin));

	विकल्प (rv) {
	पक्ष CKR_OK:
	पक्ष CKR_USER_ALREADY_LOGGED_अन्तर्:
		/* success */
		भङ्ग;
	पक्ष CKR_PIN_LEN_RANGE:
		error("PKCS#11 login failed: PIN length out of range");
		प्रत्यागम -1;
	पक्ष CKR_PIN_INCORRECT:
		error("PKCS#11 login failed: PIN incorrect");
		प्रत्यागम -1;
	पक्ष CKR_PIN_LOCKED:
		error("PKCS#11 login failed: PIN locked");
		प्रत्यागम -1;
	स्वभाव:
		error("PKCS#11 login failed: error %lu", rv);
		प्रत्यागम -1;
	}
	si->logged_अन्तर् = 1;
	प्रत्यागम (0);
}

स्थिर पूर्णाङ्क
pkcs11_login(संरचना pkcs11_कुञ्चिका *k11, CK_USER_TYPE type)
{
	यदि (k11 == रिक्त || k11->provider == रिक्त || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		प्रत्यागम (-1);
	}

	प्रत्यागम pkcs11_login_slot(k11->provider,
	    &k11->provider->slotinfo[k11->slotidx], type);
}


स्थिर पूर्णाङ्क
pkcs11_check_obj_bool_attrib(संरचना pkcs11_कुञ्चिका *k11, CK_OBJECT_HANDLE obj,
    CK_ATTRIBUTE_TYPE type, पूर्णाङ्क *val)
{
	संरचना pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_BBOOL		flag = 0;
	CK_ATTRIBUTE		attr;
	CK_RV			 rv;

	*val = 0;

	यदि (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		प्रत्यागम (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	attr.type = type;
	attr.p_मानम् = &flag;
	attr.ul_मानम्_Len = परिमाण(flag);

	rv = f->C_Get_Attribute_मानम्(si->session, obj, &attr, 1);
	यदि (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		प्रत्यागम (-1);
	}
	*val = flag != 0;
	debug_f("provider \"%s\" slot %lu object %lu: attrib %lu = %d",
	    k11->provider->name, k11->slotidx, obj, type, *val);
	प्रत्यागम (0);
}

स्थिर पूर्णाङ्क
pkcs11_get_कुञ्चिका(संरचना pkcs11_कुञ्चिका *k11, CK_MECHANISM_TYPE mech_type)
{
	संरचना pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	 obj;
	CK_RV			 rv;
	CK_OBJECT_CLASS		 वैयक्तिकम्_कुञ्चिका_class;
	CK_BBOOL		 true_val;
	CK_MECHANISM		 mech;
	CK_ATTRIBUTE		 कुञ्चिका_filter[3];
	पूर्णाङ्क			 always_auth = 0;
	पूर्णाङ्क			 did_login = 0;

	यदि (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		प्रत्यागम (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	यदि ((si->token.flags & CKF_LOGIN_REQUIRED) && !si->logged_अन्तर्) {
		यदि (pkcs11_login(k11, CKU_USER) < 0) {
			error("login failed");
			प्रत्यागम (-1);
		}
		did_login = 1;
	}

	स्मृतिं_पूरय(&कुञ्चिका_filter, 0, परिमाण(कुञ्चिका_filter));
	वैयक्तिकम्_कुञ्चिका_class = CKO_वैयक्तिकम्_कुञ्चिका;
	कुञ्चिका_filter[0].type = CKA_CLASS;
	कुञ्चिका_filter[0].p_मानम् = &वैयक्तिकम्_कुञ्चिका_class;
	कुञ्चिका_filter[0].ul_मानम्_Len = परिमाण(वैयक्तिकम्_कुञ्चिका_class);

	कुञ्चिका_filter[1].type = CKA_ID;
	कुञ्चिका_filter[1].p_मानम् = k11->keyid;
	कुञ्चिका_filter[1].ul_मानम्_Len = k11->keyid_len;

	true_val = CK_TRUE;
	कुञ्चिका_filter[2].type = CKA_SIGN;
	कुञ्चिका_filter[2].p_मानम् = &true_val;
	कुञ्चिका_filter[2].ul_मानम्_Len = परिमाण(true_val);

	/* try to find object w/CKA_SIGN first, retry w/o */
	यदि (pkcs11_find(k11->provider, k11->slotidx, कुञ्चिका_filter, 3, &obj) < 0 &&
	    pkcs11_find(k11->provider, k11->slotidx, कुञ्चिका_filter, 2, &obj) < 0) {
		error("cannot find private key");
		प्रत्यागम (-1);
	}

	स्मृतिं_पूरय(&mech, 0, परिमाण(mech));
	mech.mechanism = mech_type;
	mech.pParameter = NULL_PTR;
	mech.ulParameterLen = 0;

	यदि ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
		प्रत्यागम (-1);
	}

	pkcs11_check_obj_bool_attrib(k11, obj, CKA_ALWAYS_AUTHENTICATE,
	    &always_auth); /* ignore errors here */
	यदि (always_auth && !did_login) {
		debug_f("always-auth key");
		यदि (pkcs11_login(k11, CKU_CONTEXT_SPECIFIC) < 0) {
			error("login failed for always-auth key");
			प्रत्यागम (-1);
		}
	}

	प्रत्यागम (0);
}

/* record the key information later use lookup by keyblob */
स्थिर पूर्णाङ्क
pkcs11_लेखः_कुञ्चिका(संरचना pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, संरचना sshkey *कुञ्चिका)
{
	संरचना sshbuf *keyblob;
	संरचना pkcs11_कुञ्चिका *k11;
	पूर्णाङ्क r;
	वर्ण *hex;

	hex = tohex(keyid_attrib->p_मानम्, keyid_attrib->ul_मानम्_Len);
	debug_f("%s key: provider %s slot %lu keyid %s",
	    sshkey_type(कुञ्चिका), provider->name, (u_long)slotidx, hex);
	मुक्त(hex);

	यदि ((keyblob = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshkey_putb(कुञ्चिका, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");

	/* Check if we've already recorded this key in a different slot */
	TAILQ_FOREACH(k11, &pkcs11_कुञ्चिकाः, अग्र) {
		यदि (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			hex = tohex(k11->keyid, k11->keyid_len);
			debug_f("Already seen this key at "
			    "provider %s slot %lu keyid %s",
			    k11->provider->name, k11->slotidx, hex);
			मुक्त(hex);
			sshbuf_free(keyblob);
			प्रत्यागम -1;
		}
	}

	k11 = xcalloc(1, परिमाण(*k11));
	k11->provider = provider;
	k11->keyblob = keyblob;
	provider->refcount++;	/* provider referenced by RSA key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ul_मानम्_Len;
	यदि (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len);
		स्मृतिं_प्रतिलिख(k11->keyid, keyid_attrib->p_मानम्, k11->keyid_len);
	}
	TAILQ_INSERT_TAIL(&pkcs11_कुञ्चिकाः, k11, अग्र);

	प्रत्यागम 0;
}

/* retrieve the key information by keyblob */
स्थिर संरचना pkcs11_कुञ्चिका *
pkcs11_lookup_कुञ्चिका(संरचना sshkey *कुञ्चिका)
{
	संरचना pkcs11_कुञ्चिका *k11, *प्राप्तम् = रिक्त;
	संरचना sshbuf *keyblob;
	पूर्णाङ्क r;

	यदि ((keyblob = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshkey_putb(कुञ्चिका, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");
	TAILQ_FOREACH(k11, &pkcs11_कुञ्चिकाः, अग्र) {
		यदि (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			प्राप्तम् = k11;
			भङ्ग;
		}
	}
	sshbuf_free(keyblob);
	प्रत्यागम प्राप्तम्;
}

#यदि_परिभाषितम् WITH_OPENSSL
/*
 * See:
 * https://datatracker.ietf.org/doc/html/rfc8017#section-9.2
 */

/*
 * id-sha1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
 *	oiw(14) secsig(3) algorithms(2) 26 }
 */
स्थिर ध्रुव u_char id_sha1[] = {
	0x30, 0x21, /* type Sequence, length 0x21 (33) */
	0x30, 0x09, /* type Sequence, length 0x09 */
	0x06, 0x05, /* type OID, length 0x05 */
	0x2b, 0x0e, 0x03, 0x02, 0x1a, /* id-sha1 OID */
	0x05, 0x00, /* NULL */
	0x04, 0x14  /* Octet string, length 0x14 (20), followed by sha1 hash */
};

/*
 * id-sha256 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840)
 *      organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2)
 *      id-sha256(1) }
 */
स्थिर ध्रुव u_char id_sha256[] = {
	0x30, 0x31, /* type Sequence, length 0x31 (49) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, /* id-sha256 */
	0x05, 0x00, /* NULL */
	0x04, 0x20  /* Octet string, length 0x20 (32), followed by sha256 hash */
};

/*
 * id-sha512 OBJECT IDENTIFIER ::= { joint-iso-itu-t(2) country(16) us(840)
 *      organization(1) gov(101) csor(3) nistAlgorithm(4) hashAlgs(2)
 *      id-sha256(3) }
 */
स्थिर ध्रुव u_char id_sha512[] = {
	0x30, 0x51, /* type Sequence, length 0x51 (81) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, /* id-sha512 */
	0x05, 0x00, /* NULL */
	0x04, 0x40  /* Octet string, length 0x40 (64), followed by sha512 hash */
};

स्थिर पूर्णाङ्क
rsa_hash_alg_oid(पूर्णाङ्क hash_alg, ध्रुव u_char **oidp, आकार_t *oidlenp)
{
	विकल्प (hash_alg) {
	पक्ष SSH_DIGEST_SHA1:
		*oidp = id_sha1;
		*oidlenp = परिमाण(id_sha1);
		भङ्ग;
	पक्ष SSH_DIGEST_SHA256:
		*oidp = id_sha256;
		*oidlenp = परिमाण(id_sha256);
		भङ्ग;
	पक्ष SSH_DIGEST_SHA512:
		*oidp = id_sha512;
		*oidlenp = परिमाण(id_sha512);
		भङ्ग;
	स्वभाव:
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
pkcs11_sign_rsa(संरचना sshkey *कुञ्चिका,
    u_char **sigp, आकार_t *lenp,
    ध्रुव u_char *दत्त, आकार_t datalen,
    ध्रुव वर्ण *alg, ध्रुव वर्ण *sk_provider,
    ध्रुव वर्ण *sk_pin, u_int compat)
{
	संरचना pkcs11_कुञ्चिका	*k11;
	संरचना pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	पूर्णाङ्क			hashalg, r, diff, siglen, ret = -1;
	u_char			*oid_dgst = रिक्त, *sig = रिक्त;
	आकार_t			dgst_len, oid_len, oid_dgst_len = 0;
	ध्रुव u_char		*oid;

	यदि (sigp != रिक्त)
		*sigp = रिक्त;
	यदि (lenp != रिक्त)
		*lenp = 0;

	यदि ((k11 = pkcs11_lookup_कुञ्चिका(कुञ्चिका)) == रिक्त) {
		error_f("no key found");
		प्रत्यागम SSH_ERR_कुञ्चिका_NOT_प्राप्तम्;
	}

	debug3_f("sign with alg \"%s\" using provider %s slotidx %lu",
	    alg == रिक्त ? "" : alg, k11->provider->name, (u_long)k11->slotidx);

	यदि (pkcs11_get_कुञ्चिका(k11, CKM_RSA_PKCS) == -1) {
		error("pkcs11_get_key failed");
		प्रत्यागम SSH_ERR_AGENT_FAILURE;
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	यदि ((siglen = EVP_PKEY_आकार(कुञ्चिका->pkey)) <= 0)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* Determine hash algorithm and OID for signature */
	यदि (alg == रिक्त || *alg == '\0')
		hashalg = SSH_DIGEST_SHA1;
	अन्यथा यदि ((hashalg = ssh_rsa_hash_id_from_keyname(alg)) == -1)
		fatal_f("couldn't determine RSA hash alg \"%s\"", alg);
	यदि ((r = rsa_hash_alg_oid(hashalg, &oid, &oid_len)) != 0)
		fatal_fr(r, "rsa_hash_alg_oid failed");
	यदि ((dgst_len = ssh_digest_अष्टकानि(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);

	/* Prepare { oid || digest } */
	oid_dgst_len = oid_len + dgst_len;
	oid_dgst = xcalloc(1, oid_dgst_len);
	स्मृतिं_प्रतिलिख(oid_dgst, oid, oid_len);
	यदि ((r = ssh_digest_स्मृतिः(hashalg, दत्त, datalen,
	    oid_dgst + oid_len, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	यदि ((rv = f->C_Sign(si->session, (CK_BYTE *)oid_dgst,
	    oid_dgst_len, sig, &slen)) != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		गच्छ समाप्तम्;
	}

	यदि (slen < (CK_ULONG)siglen) {
		diff = siglen - slen;
		debug3_f("repack %lu < %d (diff %d)",
		    (u_long)slen, siglen, diff);
		memmove(sig + diff, sig, slen);
		explicit_bzero(sig, diff);
	} अन्यथा यदि (slen > (आकार_t)siglen)
		fatal_f("bad C_Sign length");

	यदि ((ret = ssh_rsa_encode_store_sig(hashalg, sig, siglen,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 समाप्तम्:
	freezero(oid_dgst, oid_dgst_len);
	मुक्त(sig);
	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
pkcs11_sign_ecdsa(संरचना sshkey *कुञ्चिका,
    u_char **sigp, आकार_t *lenp,
    ध्रुव u_char *दत्त, आकार_t datalen,
    ध्रुव वर्ण *alg, ध्रुव वर्ण *sk_provider,
    ध्रुव वर्ण *sk_pin, u_int compat)
{
	संरचना pkcs11_कुञ्चिका	*k11;
	संरचना pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0, bnlen;
	CK_RV			rv;
	BIGNUM			*sig_r = रिक्त, *sig_s = रिक्त;
	u_char			*sig = रिक्त, *dgst = रिक्त;
	आकार_t			dgst_len = 0;
	पूर्णाङ्क			hashalg, ret = -1, r, siglen;

	यदि (sigp != रिक्त)
		*sigp = रिक्त;
	यदि (lenp != रिक्त)
		*lenp = 0;

	यदि ((k11 = pkcs11_lookup_कुञ्चिका(कुञ्चिका)) == रिक्त) {
		error_f("no key found");
		प्रत्यागम SSH_ERR_कुञ्चिका_NOT_प्राप्तम्;
	}

	यदि (pkcs11_get_कुञ्चिका(k11, CKM_ECDSA) == -1) {
		error("pkcs11_get_key failed");
		प्रत्यागम SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	/* Prepare digest to be signed */
	यदि ((hashalg = sshkey_ec_nid_गन्तव्यम्_hash_alg(कुञ्चिका->ecdsa_nid)) == -1)
		fatal_f("couldn't determine ECDSA hash alg");
	यदि ((dgst_len = ssh_digest_अष्टकानि(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);
	dgst = xcalloc(1, dgst_len);
	यदि ((r = ssh_digest_स्मृतिः(hashalg, दत्त, datalen,
	    dgst, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	यदि ((siglen = EVP_PKEY_आकार(कुञ्चिका->pkey)) <= 0)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dgst_len, sig, &slen);
	यदि (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		गच्छ समाप्तम्;
	}
	यदि (slen < 64 || slen > 132 || slen % 2) {
		error_f("bad signature length: %lu", (u_long)slen);
		गच्छ समाप्तम्;
	}
	bnlen = slen/2;
	यदि ((sig_r = BN_bin2bn(sig, bnlen, रिक्त)) == रिक्त ||
	    (sig_s = BN_bin2bn(sig+bnlen, bnlen, रिक्त)) == रिक्त) {
		ossl_error("BN_bin2bn failed");
		गच्छ समाप्तम्;
	}

	यदि ((ret = ssh_ecdsa_encode_store_sig(कुञ्चिका, sig_r, sig_s,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 समाप्तम्:
	freezero(dgst, dgst_len);
	BN_free(sig_r);
	BN_free(sig_s);
	मुक्त(sig);
	प्रत्यागम ret;
}
#यदि_अन्तः /* WITH_OPENSSL */

स्थिर पूर्णाङ्क
pkcs11_sign_ed25519(संरचना sshkey *कुञ्चिका,
    u_char **sigp, आकार_t *lenp,
    ध्रुव u_char *दत्त, आकार_t datalen,
    ध्रुव वर्ण *alg, ध्रुव वर्ण *sk_provider,
    ध्रुव वर्ण *sk_pin, u_int compat)
{
	संरचना pkcs11_कुञ्चिका	*k11;
	संरचना pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	u_char			*sig = रिक्त;
	CK_BYTE			*xdata = रिक्त;
	पूर्णाङ्क			ret = -1;

	यदि (sigp != रिक्त)
		*sigp = रिक्त;
	यदि (lenp != रिक्त)
		*lenp = 0;

	यदि ((k11 = pkcs11_lookup_कुञ्चिका(कुञ्चिका)) == रिक्त) {
		error_f("no key found");
		प्रत्यागम SSH_ERR_कुञ्चिका_NOT_प्राप्तम्;
	}

	यदि (pkcs11_get_कुञ्चिका(k11, CKM_EDDSA) == -1) {
		error("pkcs11_get_key failed");
		प्रत्यागम SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	xdata = xmalloc(datalen);
	स्मृतिं_प्रतिलिख(xdata, दत्त, datalen);
	sig = xmalloc(crypto_sign_ed25519_अष्टकानि);
	slen = crypto_sign_ed25519_अष्टकानि;

	rv = f->C_Sign(si->session, xdata, datalen, sig, &slen);
	यदि (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		गच्छ समाप्तम्;
	}
	यदि (slen != crypto_sign_ed25519_अष्टकानि) {
		error_f("bad signature length: %lu", (u_long)slen);
		गच्छ समाप्तम्;
	}
	यदि ((ret = ssh_ed25519_encode_store_sig(sig, slen, sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 समाप्तम्:
	यदि (xdata != रिक्त)
		freezero(xdata, datalen);
	मुक्त(sig);
	प्रत्यागम ret;
}

/* remove trailing spaces */
स्थिर वर्ण *
rmspace(u_char *buf, आकार_t len)
{
	आकार_t i;

	यदि (len == 0)
		प्रत्यागम buf;
	प्रति (i = len - 1; i > 0; i--)
		यदि (buf[i] == ' ')
			buf[i] = '\0';
		अन्यथा
			भङ्ग;
	प्रत्यागम buf;
}
/* Used to printf fixed-width, space-padded, unterminated strings using %.*s */
#परिभाषय RMSPACE(s) (पूर्णाङ्क)परिमाण(s), rmspace(s, परिमाण(s))

/*
 * open a pkcs11 session and login if required.
 * if pin == NULL we delay login until key use
 */
स्थिर पूर्णाङ्क
pkcs11_open_session(संरचना pkcs11_provider *p, CK_ULONG slotidx, वर्ण *pin,
    CK_ULONG user)
{
	संरचना pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_RV			rv;
	CK_SESSION_HANDLE	session;
	पूर्णाङ्क			login_required, ret;

	f = p->function_list;
	si = &p->slotinfo[slotidx];

	login_required = si->token.flags & CKF_LOGIN_REQUIRED;

	/* fail early before opening session */
	यदि (login_required && !pkcs11_interactive &&
	    (pin == रिक्त || वाक्यदैर्घ्यम्(pin) == 0)) {
		error("pin required");
		प्रत्यागम (-SSH_PKCS11_ERR_PIN_REQUIRED);
	}
	यदि ((rv = f->C_OpenSession(p->slotlist[slotidx], CKF_RW_SESSION|
	    CKF_SERIAL_SESSION, रिक्त, रिक्त, &session)) != CKR_OK) {
		error("C_OpenSession failed: %lu", rv);
		प्रत्यागम (-1);
	}
	यदि (login_required && pin != रिक्त && वाक्यदैर्घ्यम्(pin) != 0) {
		rv = f->C_Login(session, user, (u_char *)pin, वाक्यदैर्घ्यम्(pin));
		यदि (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_अन्तर्) {
			error("C_Login failed: %lu", rv);
			ret = (rv == CKR_PIN_LOCKED) ?
			    -SSH_PKCS11_ERR_PIN_LOCKED :
			    -SSH_PKCS11_ERR_LOGIN_FAIL;
			यदि ((rv = f->C_CloseSession(session)) != CKR_OK)
				error("C_CloseSession failed: %lu", rv);
			प्रत्यागम (ret);
		}
		si->logged_अन्तर् = 1;
	}
	si->session = session;
	प्रत्यागम (0);
}

स्थिर पूर्णाङ्क
pkcs11_कुञ्चिका_included(संरचना sshkey ***keysp, पूर्णाङ्क *nkeys, संरचना sshkey *कुञ्चिका)
{
	पूर्णाङ्क i;

	प्रति (i = 0; i < *nkeys; i++)
		यदि (sshkey_equal(कुञ्चिका, (*keysp)[i]))
			प्रत्यागम (1);
	प्रत्यागम (0);
}

#यदि_परिभाषितम् WITH_OPENSSL
स्थिर संरचना sshkey *
pkcs11_fetch_ecdsa_pubkey(संरचना pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 कुञ्चिका_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = रिक्त;
	CK_RV			 rv;
	ASN1_OCTET_STRING	*octet = रिक्त;
	EC_कुञ्चिका			*ec = रिक्त;
	EC_गणः		*गणः = रिक्त;
	संरचना sshkey		*कुञ्चिका = रिक्त;
	ध्रुव अचिह्नित वर्ण	*attrp = रिक्त;
	पूर्णाङ्क			 success = -1, r, i, nid;

	स्मृतिं_पूरय(&कुञ्चिका_attr, 0, परिमाण(कुञ्चिका_attr));
	कुञ्चिका_attr[0].type = CKA_ID;
	कुञ्चिका_attr[1].type = CKA_EC_POINT;
	कुञ्चिका_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_मानम्(session, *obj, कुञ्चिका_attr, 3);
	यदि (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		प्रत्यागम (रिक्त);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	यदि (कुञ्चिका_attr[1].ul_मानम्_Len == 0 ||
	    कुञ्चिका_attr[2].ul_मानम्_Len == 0) {
		error("invalid attribute length");
		प्रत्यागम (रिक्त);
	}

	/* allocate buffers for attributes */
	प्रति (i = 0; i < 3; i++)
		यदि (कुञ्चिका_attr[i].ul_मानम्_Len > 0)
			कुञ्चिका_attr[i].p_मानम् = xcalloc(1, कुञ्चिका_attr[i].ul_मानम्_Len);

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_मानम्(session, *obj, कुञ्चिका_attr, 3);
	यदि (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		गच्छ fail;
	}

	ec = EC_कुञ्चिका_new();
	यदि (ec == रिक्त) {
		error("EC_KEY_new failed");
		गच्छ fail;
	}

	attrp = कुञ्चिका_attr[2].p_मानम्;
	गणः = d2i_ECPKParameters(रिक्त, &attrp, कुञ्चिका_attr[2].ul_मानम्_Len);
	यदि (गणः == रिक्त) {
		ossl_error("d2i_ECPKParameters failed");
		गच्छ fail;
	}

	यदि (EC_कुञ्चिका_समुच्चयः_गणः(ec, गणः) == 0) {
		ossl_error("EC_KEY_set_group failed");
		गच्छ fail;
	}

	यदि (कुञ्चिका_attr[1].ul_मानम्_Len <= 2) {
		error("CKA_EC_POINT too small");
		गच्छ fail;
	}

	attrp = कुञ्चिका_attr[1].p_मानम्;
	octet = d2i_ASN1_OCTET_STRING(रिक्त, &attrp, कुञ्चिका_attr[1].ul_मानम्_Len);
	यदि (octet == रिक्त) {
		ossl_error("d2i_ASN1_OCTET_STRING failed");
		गच्छ fail;
	}
	attrp = ASN1_STRING_get0_दत्त(octet);
	यदि (o2i_ECPublic_कुञ्चिका(&ec, &attrp, ASN1_STRING_दीर्घता(octet)) == रिक्त) {
		ossl_error("o2i_ECPublicKey failed");
		गच्छ fail;
	}
	यदि ((r = sshkey_ec_validate_लौकिकम्(EC_कुञ्चिका_get0_गणः(ec),
	    EC_कुञ्चिका_get0_लौकिकम्_कुञ्चिका(ec))) != 0) {
		error_fr(r, "invalid EC key");
		गच्छ fail;
	}

	nid = sshkey_ecdsa_कुञ्चिका_गन्तव्यम्_nid(ec);
	यदि (nid < 0) {
		error("couldn't get curve nid");
		गच्छ fail;
	}

	कुञ्चिका = sshkey_new(कुञ्चिका_UNSPEC);
	यदि (कुञ्चिका == रिक्त) {
		error("sshkey_new failed");
		गच्छ fail;
	}

	EVP_PKEY_free(कुञ्चिका->pkey);
	यदि ((कुञ्चिका->pkey = EVP_PKEY_new()) == रिक्त)
		fatal("EVP_PKEY_new failed");
	यदि (EVP_PKEY_set1_EC_कुञ्चिका(कुञ्चिका->pkey, ec) != 1)
		fatal("EVP_PKEY_set1_EC_KEY failed");
	कुञ्चिका->ecdsa_nid = nid;
	कुञ्चिका->type = कुञ्चिका_ECDSA;
	कुञ्चिका->flags |= SSHKEY_FLAG_EXT;
	यदि (pkcs11_लेखः_कुञ्चिका(p, slotidx, &कुञ्चिका_attr[0], कुञ्चिका))
		गच्छ fail;
	/* success */
	success = 0;
fail:
	यदि (success != 0) {
		sshkey_free(कुञ्चिका);
		कुञ्चिका = रिक्त;
	}
	प्रति (i = 0; i < 3; i++)
		मुक्त(कुञ्चिका_attr[i].p_मानम्);
	यदि (ec)
		EC_कुञ्चिका_free(ec);
	यदि (गणः)
		EC_गणः_free(गणः);
	यदि (octet)
		ASN1_OCTET_STRING_free(octet);

	प्रत्यागम (कुञ्चिका);
}

स्थिर संरचना sshkey *
pkcs11_fetch_rsa_pubkey(संरचना pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 कुञ्चिका_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = रिक्त;
	CK_RV			 rv;
	RSA			*rsa = रिक्त;
	BIGNUM			*rsa_n, *rsa_e;
	संरचना sshkey		*कुञ्चिका = रिक्त;
	पूर्णाङ्क			 i, success = -1;

	स्मृतिं_पूरय(&कुञ्चिका_attr, 0, परिमाण(कुञ्चिका_attr));
	कुञ्चिका_attr[0].type = CKA_ID;
	कुञ्चिका_attr[1].type = CKA_MODULUS;
	कुञ्चिका_attr[2].type = CKA_लौकिकम्_EXPONENT;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_मानम्(session, *obj, कुञ्चिका_attr, 3);
	यदि (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		प्रत्यागम (रिक्त);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	यदि (कुञ्चिका_attr[1].ul_मानम्_Len == 0 ||
	    कुञ्चिका_attr[2].ul_मानम्_Len == 0) {
		error("invalid attribute length");
		प्रत्यागम (रिक्त);
	}

	/* allocate buffers for attributes */
	प्रति (i = 0; i < 3; i++)
		यदि (कुञ्चिका_attr[i].ul_मानम्_Len > 0)
			कुञ्चिका_attr[i].p_मानम् = xcalloc(1, कुञ्चिका_attr[i].ul_मानम्_Len);

	/* retrieve ID, modulus and public exponent of RSA key */
	rv = f->C_Get_Attribute_मानम्(session, *obj, कुञ्चिका_attr, 3);
	यदि (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		गच्छ fail;
	}

	rsa = RSA_new();
	यदि (rsa == रिक्त) {
		error("RSA_new failed");
		गच्छ fail;
	}

	rsa_n = BN_bin2bn(कुञ्चिका_attr[1].p_मानम्, कुञ्चिका_attr[1].ul_मानम्_Len, रिक्त);
	rsa_e = BN_bin2bn(कुञ्चिका_attr[2].p_मानम्, कुञ्चिका_attr[2].ul_मानम्_Len, रिक्त);
	यदि (rsa_n == रिक्त || rsa_e == रिक्त) {
		error("BN_bin2bn failed");
		गच्छ fail;
	}
	यदि (!RSA_set0_कुञ्चिका(rsa, rsa_n, rsa_e, रिक्त))
		fatal_f("set key");
	rsa_n = rsa_e = रिक्त; /* transferred */

	कुञ्चिका = sshkey_new(कुञ्चिका_UNSPEC);
	यदि (कुञ्चिका == रिक्त) {
		error("sshkey_new failed");
		गच्छ fail;
	}

	EVP_PKEY_free(कुञ्चिका->pkey);
	यदि ((कुञ्चिका->pkey = EVP_PKEY_new()) == रिक्त)
		fatal("EVP_PKEY_new failed");
	यदि (EVP_PKEY_set1_RSA(कुञ्चिका->pkey, rsa) != 1)
		fatal("EVP_PKEY_set1_RSA failed");
	कुञ्चिका->type = कुञ्चिका_RSA;
	कुञ्चिका->flags |= SSHKEY_FLAG_EXT;
	यदि (EVP_PKEY_द्वयङ्काः(कुञ्चिका->pkey) < SSH_RSA_MINIMUM_MODULUS_आकार) {
		error_f("RSA key too small %d < minimum %d",
		    EVP_PKEY_द्वयङ्काः(कुञ्चिका->pkey), SSH_RSA_MINIMUM_MODULUS_आकार);
		गच्छ fail;
	}
	यदि (pkcs11_लेखः_कुञ्चिका(p, slotidx, &कुञ्चिका_attr[0], कुञ्चिका))
		गच्छ fail;
	/* success */
	success = 0;
fail:
	प्रति (i = 0; i < 3; i++)
		मुक्त(कुञ्चिका_attr[i].p_मानम्);
	RSA_free(rsa);
	यदि (success != 0) {
		sshkey_free(कुञ्चिका);
		कुञ्चिका = रिक्त;
	}
	प्रत्यागम कुञ्चिका;
}
#यदि_अन्तः /* WITH_OPENSSL */

स्थिर संरचना sshkey *
pkcs11_fetch_ed25519_pubkey(संरचना pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 कुञ्चिका_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = रिक्त;
	CK_RV			 rv;
	संरचना sshkey		*कुञ्चिका = रिक्त;
	ध्रुव अचिह्नित वर्ण	*d = रिक्त;
	आकार_t			len;
	वर्ण			*hex = रिक्त;
	पूर्णाङ्क			 success = -1, i;
	/* https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061180 */
	ध्रुव u_char		 id1[14] = {
		0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64,
		0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
	}; /* PrintableString { "edwards25519" } */
	ध्रुव u_char		 id2[5] = {
		0x06, 0x03, 0x2b, 0x65, 0x70,
	}; /* OBJECT_IDENTIFIER { 1.3.101.112 } */

	स्मृतिं_पूरय(&कुञ्चिका_attr, 0, परिमाण(कुञ्चिका_attr));
	कुञ्चिका_attr[0].type = CKA_ID;
	कुञ्चिका_attr[1].type = CKA_EC_POINT; /* XXX or CKA_VALUE ? */
	कुञ्चिका_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_मानम्(session, *obj, कुञ्चिका_attr, 3);
	यदि (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		प्रत्यागम (रिक्त);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	यदि (कुञ्चिका_attr[1].ul_मानम्_Len == 0 ||
	    कुञ्चिका_attr[2].ul_मानम्_Len == 0) {
		error("invalid attribute length");
		प्रत्यागम (रिक्त);
	}

	/* allocate buffers for attributes */
	प्रति (i = 0; i < 3; i++) {
		यदि (कुञ्चिका_attr[i].ul_मानम्_Len > 0)
			कुञ्चिका_attr[i].p_मानम् = xcalloc(1, कुञ्चिका_attr[i].ul_मानम्_Len);
	}

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_मानम्(session, *obj, कुञ्चिका_attr, 3);
	यदि (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		गच्छ fail;
	}

	/* Expect one of the supported identifiers in CKA_EC_PARAMS */
	d = (u_char *)कुञ्चिका_attr[2].p_मानम्;
	len = कुञ्चिका_attr[2].ul_मानम्_Len;
	यदि ((len != परिमाण(id1) || memcmp(d, id1, परिमाण(id1)) != 0) &&
	    (len != परिमाण(id2) || memcmp(d, id2, परिमाण(id2)) != 0)) {
		hex = tohex(d, len);
		logit_f("unsupported CKA_EC_PARAMS: %s (len %zu)", hex, len);
		गच्छ fail;
	}

	/*
	 * Expect either a raw 32 byte pubkey or an OCTET STRING with
	 * a 32 byte pubkey in CKA_VALUE
	 */
	d = (u_char *)कुञ्चिका_attr[1].p_मानम्;
	len = कुञ्चिका_attr[1].ul_मानम्_Len;
	यदि (len == ED25519_PK_SZ + 2 && d[0] == 0x04 && d[1] == ED25519_PK_SZ) {
		d += 2;
		len -= 2;
	}
	यदि (len != ED25519_PK_SZ) {
		hex = tohex(कुञ्चिका_attr[1].p_मानम्, कुञ्चिका_attr[1].ul_मानम्_Len);
		logit_f("CKA_EC_POINT invalid octet str: %s (len %lu)",
		    hex, (u_long)कुञ्चिका_attr[1].ul_मानम्_Len);
		गच्छ fail;
	}

	यदि ((कुञ्चिका = sshkey_new(कुञ्चिका_UNSPEC)) == रिक्त)
		fatal_f("sshkey_new failed");
	कुञ्चिका->ed25519_pk = xmalloc(ED25519_PK_SZ);
	स्मृतिं_प्रतिलिख(कुञ्चिका->ed25519_pk, d, ED25519_PK_SZ);
	कुञ्चिका->type = कुञ्चिका_ED25519;
	कुञ्चिका->flags |= SSHKEY_FLAG_EXT;
	यदि (pkcs11_लेखः_कुञ्चिका(p, slotidx, &कुञ्चिका_attr[0], कुञ्चिका))
		गच्छ fail;
	/* success */
	success = 0;
 fail:
	यदि (success != 0) {
		sshkey_free(कुञ्चिका);
		कुञ्चिका = रिक्त;
	}
	मुक्त(hex);
	प्रति (i = 0; i < 3; i++)
		मुक्त(कुञ्चिका_attr[i].p_मानम्);
	प्रत्यागम कुञ्चिका;
}

#यदि_परिभाषितम् WITH_OPENSSL
स्थिर पूर्णाङ्क
pkcs11_fetch_x509_pubkey(संरचना pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj, संरचना sshkey **keyp, वर्ण **labelp)
{
	CK_ATTRIBUTE		 cert_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = रिक्त;
	CK_RV			 rv;
	X509			*x509 = रिक्त;
	X509_NAME		*x509_name = रिक्त;
	EVP_PKEY		*evp;
	RSA			*rsa = रिक्त;
	EC_कुञ्चिका			*ec = रिक्त;
	संरचना sshkey		*कुञ्चिका = रिक्त;
	पूर्णाङ्क			 r, i, nid, success = -1;
	ध्रुव u_char		*cp;
	वर्ण			*subject = रिक्त;
#यदि_परिभाषितम् OPENSSL_HAS_ED25519
	आकार_t			len;
#यदि_अन्तः /* OPENSSL_HAS_ED25519 */

	*keyp = रिक्त;
	*labelp = रिक्त;

	स्मृतिं_पूरय(&cert_attr, 0, परिमाण(cert_attr));
	cert_attr[0].type = CKA_ID;
	cert_attr[1].type = CKA_SUBJECT;
	cert_attr[2].type = CKA_मानम्;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_मानम्(session, *obj, cert_attr, 3);
	यदि (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		प्रत्यागम -1;
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	यदि (cert_attr[1].ul_मानम्_Len == 0 ||
	    cert_attr[2].ul_मानम्_Len == 0) {
		error("invalid attribute length");
		प्रत्यागम -1;
	}

	/* allocate buffers for attributes */
	प्रति (i = 0; i < 3; i++)
		यदि (cert_attr[i].ul_मानम्_Len > 0)
			cert_attr[i].p_मानम् = xcalloc(1, cert_attr[i].ul_मानम्_Len);

	/* retrieve ID, subject and value of certificate */
	rv = f->C_Get_Attribute_मानम्(session, *obj, cert_attr, 3);
	यदि (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		गच्छ बहिर्गमनम्;
	}

	/* Decode DER-encoded cert subject */
	cp = cert_attr[1].p_मानम्;
	यदि ((x509_name = d2i_X509_NAME(रिक्त, &cp,
	    cert_attr[1].ul_मानम्_Len)) == रिक्त ||
	    (subject = X509_NAME_oneline(x509_name, रिक्त, 0)) == रिक्त)
		subject = xstrdup("invalid subject");
	X509_NAME_free(x509_name);

	cp = cert_attr[2].p_मानम्;
	यदि ((x509 = d2i_X509(रिक्त, &cp, cert_attr[2].ul_मानम्_Len)) == रिक्त) {
		error("d2i_x509 failed");
		गच्छ बहिर्गमनम्;
	}

	यदि ((evp = X509_get_pubkey(x509)) == रिक्त) {
		error("X509_get_pubkey failed");
		गच्छ बहिर्गमनम्;
	}

	यदि (EVP_PKEY_आधारः_id(evp) == EVP_PKEY_RSA) {
		यदि (EVP_PKEY_get0_RSA(evp) == रिक्त) {
			error("invalid x509; no rsa key");
			गच्छ बहिर्गमनम्;
		}
		यदि ((rsa = RSAPublic_कुञ्चिका_dup(EVP_PKEY_get0_RSA(evp))) == रिक्त) {
			error("RSAPublicKey_dup failed");
			गच्छ बहिर्गमनम्;
		}

		कुञ्चिका = sshkey_new(कुञ्चिका_UNSPEC);
		यदि (कुञ्चिका == रिक्त) {
			error("sshkey_new failed");
			गच्छ बहिर्गमनम्;
		}

		EVP_PKEY_free(कुञ्चिका->pkey);
		यदि ((कुञ्चिका->pkey = EVP_PKEY_new()) == रिक्त)
			fatal("EVP_PKEY_new failed");
		यदि (EVP_PKEY_set1_RSA(कुञ्चिका->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		कुञ्चिका->type = कुञ्चिका_RSA;
		कुञ्चिका->flags |= SSHKEY_FLAG_EXT;
		यदि (EVP_PKEY_द्वयङ्काः(कुञ्चिका->pkey) < SSH_RSA_MINIMUM_MODULUS_आकार) {
			error_f("RSA key too small %d < minimum %d",
			    EVP_PKEY_द्वयङ्काः(कुञ्चिका->pkey),
			    SSH_RSA_MINIMUM_MODULUS_आकार);
			गच्छ बहिर्गमनम्;
		}
		यदि (pkcs11_लेखः_कुञ्चिका(p, slotidx, &cert_attr[0], कुञ्चिका))
			गच्छ बहिर्गमनम्;
		/* success */
		success = 0;
	} अन्यथा यदि (EVP_PKEY_आधारः_id(evp) == EVP_PKEY_EC) {
		यदि (EVP_PKEY_get0_EC_कुञ्चिका(evp) == रिक्त) {
			error("invalid x509; no ec key");
			गच्छ बहिर्गमनम्;
		}
		यदि ((ec = EC_कुञ्चिका_dup(EVP_PKEY_get0_EC_कुञ्चिका(evp))) == रिक्त) {
			error("EC_KEY_dup failed");
			गच्छ बहिर्गमनम्;
		}
		यदि ((r = sshkey_ec_validate_लौकिकम्(EC_कुञ्चिका_get0_गणः(ec),
		    EC_कुञ्चिका_get0_लौकिकम्_कुञ्चिका(ec))) != 0) {
			error_fr(r, "invalid EC key");
			गच्छ बहिर्गमनम्;
		}
		nid = sshkey_ecdsa_कुञ्चिका_गन्तव्यम्_nid(ec);
		यदि (nid < 0) {
			error("couldn't get curve nid");
			गच्छ बहिर्गमनम्;
		}

		कुञ्चिका = sshkey_new(कुञ्चिका_UNSPEC);
		यदि (कुञ्चिका == रिक्त) {
			error("sshkey_new failed");
			गच्छ बहिर्गमनम्;
		}

		EVP_PKEY_free(कुञ्चिका->pkey);
		यदि ((कुञ्चिका->pkey = EVP_PKEY_new()) == रिक्त)
			fatal("EVP_PKEY_new failed");
		यदि (EVP_PKEY_set1_EC_कुञ्चिका(कुञ्चिका->pkey, ec) != 1)
			fatal("EVP_PKEY_set1_EC_KEY failed");
		कुञ्चिका->ecdsa_nid = nid;
		कुञ्चिका->type = कुञ्चिका_ECDSA;
		कुञ्चिका->flags |= SSHKEY_FLAG_EXT;
		यदि (pkcs11_लेखः_कुञ्चिका(p, slotidx, &cert_attr[0], कुञ्चिका))
			गच्छ बहिर्गमनम्;
		/* success */
		success = 0;
#यदि_परिभाषितम् OPENSSL_HAS_ED25519
	} अन्यथा यदि (EVP_PKEY_आधारः_id(evp) == EVP_PKEY_ED25519) {
		यदि ((कुञ्चिका = sshkey_new(कुञ्चिका_UNSPEC)) == रिक्त ||
		    (कुञ्चिका->ed25519_pk = शून्यस्मृतिं_देहि(1, ED25519_PK_SZ)) == रिक्त)
			fatal_f("allocation failed");
		len = ED25519_PK_SZ;
		यदि (!EVP_PKEY_get_raw_लौकिकम्_कुञ्चिका(evp, कुञ्चिका->ed25519_pk, &len)) {
			ossl_error("EVP_PKEY_get_raw_public_key failed");
			गच्छ बहिर्गमनम्;
		}
		यदि (len != ED25519_PK_SZ) {
			error_f("incorrect returned public key "
			    "length for ed25519");
			गच्छ बहिर्गमनम्;
		}
		कुञ्चिका->type = कुञ्चिका_ED25519;
		कुञ्चिका->flags |= SSHKEY_FLAG_EXT;
		यदि (pkcs11_लेखः_कुञ्चिका(p, slotidx, &cert_attr[0], कुञ्चिका))
			गच्छ बहिर्गमनम्;
		/* success */
		success = 0;
#यदि_अन्तः /* OPENSSL_HAS_ED25519 */
	} अन्यथा {
		error("unknown certificate key type");
		गच्छ बहिर्गमनम्;
	}
 बहिर्गमनम्:
	प्रति (i = 0; i < 3; i++)
		मुक्त(cert_attr[i].p_मानम्);
	X509_free(x509);
	RSA_free(rsa);
	EC_कुञ्चिका_free(ec);
	यदि (success != 0 || कुञ्चिका == रिक्त) {
		sshkey_free(कुञ्चिका);
		मुक्त(subject);
		प्रत्यागम -1;
	}
	/* success */
	*keyp = कुञ्चिका;
	*labelp = subject;
	प्रत्यागम 0;
}
#यदि_अन्तः /* WITH_OPENSSL */

स्थिर शून्य
note_कुञ्चिका(संरचना pkcs11_provider *p, CK_ULONG slotidx, ध्रुव वर्ण *context,
    संरचना sshkey *कुञ्चिका)
{
	वर्ण *fp;

	यदि ((fp = sshkey_fingerprint(कुञ्चिका, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == रिक्त) {
		error_f("sshkey_fingerprint failed");
		प्रत्यागम;
	}
	debug2("%s: provider %s slot %lu: %s %s", context, p->name,
	    (u_long)slotidx, sshkey_type(कुञ्चिका), fp);
	मुक्त(fp);
}

#यदि_परिभाषितम् WITH_OPENSSL /* libcrypto needed for certificate parsing */
/*
 * lookup certificates for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
स्थिर पूर्णाङ्क
pkcs11_fetch_certs(संरचना pkcs11_provider *p, CK_ULONG slotidx,
    संरचना sshkey ***keysp, वर्ण ***labelsp, पूर्णाङ्क *nkeys)
{
	संरचना sshkey		*कुञ्चिका = रिक्त;
	CK_OBJECT_CLASS		 कुञ्चिका_class;
	CK_ATTRIBUTE		 कुञ्चिका_attr[1];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = रिक्त;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	पूर्णाङ्क			 ret = -1;
	वर्ण			*label;

	स्मृतिं_पूरय(&कुञ्चिका_attr, 0, परिमाण(कुञ्चिका_attr));
	स्मृतिं_पूरय(&obj, 0, परिमाण(obj));

	कुञ्चिका_class = CKO_CERTIFICATE;
	कुञ्चिका_attr[0].type = CKA_CLASS;
	कुञ्चिका_attr[0].p_मानम् = &कुञ्चिका_class;
	कुञ्चिका_attr[0].ul_मानम्_Len = परिमाण(कुञ्चिका_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, कुञ्चिका_attr, 1);
	यदि (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		गच्छ fail;
	}

	यावत् (1) {
		CK_CERTIFICATE_TYPE	ck_cert_type;

		rv = f->C_FindObjects(session, &obj, 1, &n);
		यदि (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			गच्छ fail;
		}
		यदि (n == 0)
			भङ्ग;

		स्मृतिं_पूरय(&ck_cert_type, 0, परिमाण(ck_cert_type));
		स्मृतिं_पूरय(&कुञ्चिका_attr, 0, परिमाण(कुञ्चिका_attr));
		कुञ्चिका_attr[0].type = CKA_CERTIFICATE_TYPE;
		कुञ्चिका_attr[0].p_मानम् = &ck_cert_type;
		कुञ्चिका_attr[0].ul_मानम्_Len = परिमाण(ck_cert_type);

		rv = f->C_Get_Attribute_मानम्(session, obj, कुञ्चिका_attr, 1);
		यदि (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			गच्छ fail;
		}

		कुञ्चिका = रिक्त;
		label = रिक्त;
		विकल्प (ck_cert_type) {
		पक्ष CKC_X_509:
			यदि (pkcs11_fetch_x509_pubkey(p, slotidx, &obj,
			    &कुञ्चिका, &label) != 0) {
				debug_f("failed to fetch key");
				अनुवर्त;
			}
			भङ्ग;
		स्वभाव:
			error("skipping unsupported certificate type %lu",
			    ck_cert_type);
			अनुवर्त;
		}
		note_कुञ्चिका(p, slotidx, __func__, कुञ्चिका);
		यदि (pkcs11_कुञ्चिका_included(keysp, nkeys, कुञ्चिका)) {
			debug2_f("key already included");
			sshkey_free(कुञ्चिका);
		} अन्यथा {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, परिमाण(संरचना sshkey *));
			(*keysp)[*nkeys] = कुञ्चिका;
			यदि (labelsp != रिक्त) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, परिमाण(वर्ण *));
				(*labelsp)[*nkeys] = xstrdup((वर्ण *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_FindObjectsFinal(session);
	यदि (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	प्रत्यागम (ret);
}
#यदि_अन्तः /* WITH_OPENSSL */

/*
 * lookup public keys for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
स्थिर पूर्णाङ्क
pkcs11_fetch_कुञ्चिकाः(संरचना pkcs11_provider *p, CK_ULONG slotidx,
    संरचना sshkey ***keysp, वर्ण ***labelsp, पूर्णाङ्क *nkeys)
{
	संरचना sshkey		*कुञ्चिका = रिक्त;
	CK_OBJECT_CLASS		 कुञ्चिका_class;
	CK_ATTRIBUTE		 कुञ्चिका_attr[2];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = रिक्त;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	पूर्णाङ्क			 ret = -1;

	स्मृतिं_पूरय(&कुञ्चिका_attr, 0, परिमाण(कुञ्चिका_attr));
	स्मृतिं_पूरय(&obj, 0, परिमाण(obj));

	कुञ्चिका_class = CKO_लौकिकम्_कुञ्चिका;
	कुञ्चिका_attr[0].type = CKA_CLASS;
	कुञ्चिका_attr[0].p_मानम् = &कुञ्चिका_class;
	कुञ्चिका_attr[0].ul_मानम्_Len = परिमाण(कुञ्चिका_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, कुञ्चिका_attr, 1);
	यदि (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		गच्छ fail;
	}

	यावत् (1) {
		CK_कुञ्चिका_TYPE	ck_कुञ्चिका_type;
		CK_UTF8CHAR	label[256];

		rv = f->C_FindObjects(session, &obj, 1, &n);
		यदि (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			गच्छ fail;
		}
		यदि (n == 0)
			भङ्ग;

		स्मृतिं_पूरय(&ck_कुञ्चिका_type, 0, परिमाण(ck_कुञ्चिका_type));
		स्मृतिं_पूरय(&कुञ्चिका_attr, 0, परिमाण(कुञ्चिका_attr));
		कुञ्चिका_attr[0].type = CKA_कुञ्चिका_TYPE;
		कुञ्चिका_attr[0].p_मानम् = &ck_कुञ्चिका_type;
		कुञ्चिका_attr[0].ul_मानम्_Len = परिमाण(ck_कुञ्चिका_type);
		कुञ्चिका_attr[1].type = CKA_LABEL;
		कुञ्चिका_attr[1].p_मानम् = &label;
		कुञ्चिका_attr[1].ul_मानम्_Len = परिमाण(label) - 1;

		rv = f->C_Get_Attribute_मानम्(session, obj, कुञ्चिका_attr, 2);
		यदि (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			गच्छ fail;
		}

		label[कुञ्चिका_attr[1].ul_मानम्_Len] = '\0';

		विकल्प (ck_कुञ्चिका_type) {
#यदि_परिभाषितम् WITH_OPENSSL
		पक्ष CKK_RSA:
			कुञ्चिका = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			भङ्ग;
		पक्ष CKK_ECDSA:
			कुञ्चिका = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			भङ्ग;
#यदि_अन्तः /* WITH_OPENSSL */
		पक्ष CKK_EC_EDWARDS:
			कुञ्चिका = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			भङ्ग;
		स्वभाव:
			/* XXX print key type? */
			कुञ्चिका = रिक्त;
			error("skipping unsupported key type 0x%lx",
			    (u_long)ck_कुञ्चिका_type);
		}

		यदि (कुञ्चिका == रिक्त) {
			debug_f("failed to fetch key");
			अनुवर्त;
		}
		note_कुञ्चिका(p, slotidx, __func__, कुञ्चिका);
		यदि (pkcs11_कुञ्चिका_included(keysp, nkeys, कुञ्चिका)) {
			debug2_f("key already included");
			sshkey_free(कुञ्चिका);
		} अन्यथा {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, परिमाण(संरचना sshkey *));
			(*keysp)[*nkeys] = कुञ्चिका;
			यदि (labelsp != रिक्त) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, परिमाण(वर्ण *));
				(*labelsp)[*nkeys] = xstrdup((वर्ण *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_FindObjectsFinal(session);
	यदि (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	प्रत्यागम (ret);
}

#यदि_परिभाषितम् WITH_PKCS11_KEYGEN
#परिभाषय FILL_ATTR(attr, idx, typ, val, len) \
	{ (attr[idx]).type=(typ); (attr[idx]).p_मानम्=(val); (attr[idx]).ul_मानम्_Len=len; idx++; }

स्थिर संरचना sshkey *
pkcs11_rsa_generate_वैयक्तिकम्_कुञ्चिका(संरचना pkcs11_provider *p, CK_ULONG slotidx,
    वर्ण *label, CK_ULONG द्वयङ्काः, CK_BYTE keyid, uint32_t *err)
{
	संरचना pkcs11_slotinfo	*si;
	वर्ण			*plabel = label ? label : "";
	पूर्णाङ्क			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_कुञ्चिका_2, priv_कुञ्चिका;
	CK_ATTRIBUTE		 tpub[16], tpriv[16];
	CK_MECHANISM		 mech = {
	    CKM_RSA_PKCS_कुञ्चिका_PAIR_GEN, NULL_PTR, 0
	};
	CK_BYTE			 pubExponent[] = {
	    0x01, 0x00, 0x01 /* RSA_F4 in bytes */
	};
	pubkey_filter[0].p_मानम् = &pubkey_class;
	cert_filter[0].p_मानम् = &cert_class;

	*err = 0;

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, परिमाण(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, वाक्यदैर्घ्यम्(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, परिमाण(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, परिमाण(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    परिमाण(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, परिमाण(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, परिमाण(false_val));
	FILL_ATTR(tpub, npub, CKA_MODULUS_द्वयङ्काः, &द्वयङ्काः, परिमाण(द्वयङ्काः));
	FILL_ATTR(tpub, npub, CKA_लौकिकम्_EXPONENT, pubExponent,
	    परिमाण(pubExponent));
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, परिमाण(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN,  &true_val, परिमाण(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL,  plabel, वाक्यदैर्घ्यम्(plabel));
	FILL_ATTR(tpriv, npriv, CKA_वैयक्तिकम्,  &true_val, परिमाण(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE,  &true_val, परिमाण(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT,  &false_val, परिमाण(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN,  &true_val, परिमाण(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER,  &false_val,
	    परिमाण(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP,  &false_val, परिमाण(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE,  &false_val, परिमाण(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, परिमाण(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	यदि ((rv = f->C_Generate_कुञ्चिका_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_कुञ्चिका_2, &priv_कुञ्चिका)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		प्रत्यागम रिक्त;
	}

	प्रत्यागम pkcs11_fetch_rsa_pubkey(p, slotidx, &pub_कुञ्चिका_2);
}

स्थिर पूर्णाङ्क
h2i(वर्ण c)
{
	यदि (c >= '0' && c <= '9')
		प्रत्यागम c - '0';
	अन्यथा यदि (c >= 'a' && c <= 'f')
		प्रत्यागम c - 'a' + 10;
	अन्यथा यदि (c >= 'A' && c <= 'F')
		प्रत्यागम c - 'A' + 10;
	अन्यथा
		प्रत्यागम -1;
}

स्थिर पूर्णाङ्क
pkcs11_decode_hex(ध्रुव वर्ण *hex, अचिह्नित वर्ण **dest, आकार_t *rlen)
{
	आकार_t	i, len;

	यदि (dest)
		*dest = रिक्त;
	यदि (rlen)
		*rlen = 0;

	यदि ((len = वाक्यदैर्घ्यम्(hex)) % 2)
		प्रत्यागम -1;
	len /= 2;

	*dest = xmalloc(len);

	प्रति (i = 0; i < len; i++) {
		पूर्णाङ्क hi, lo;

		hi = h2i(hex[2 * i]);
		lo = h2i(hex[(2 * i) + 1]);
		यदि (hi == -1 || lo == -1)
			प्रत्यागम -1;
		(*dest)[i] = (hi << 4) | lo;
	}

	यदि (rlen)
		*rlen = len;

	प्रत्यागम 0;
}

स्थिर संरचना ec_वक्रम्_info {
	ध्रुव वर्ण	*name;
	ध्रुव वर्ण	*oid;
	ध्रुव वर्ण	*oid_encoded;
	आकार_t		 आकार;
} ec_वक्रम्_infos[] = {
	{"prime256v1",	"1.2.840.10045.3.1.7",	"06082A8648CE3D030107", 256},
	{"secp384r1",	"1.3.132.0.34",		"06052B81040022",	384},
	{"secp521r1",	"1.3.132.0.35",		"06052B81040023",	521},
	{रिक्त,		रिक्त,			रिक्त,			0},
};

स्थिर संरचना sshkey *
pkcs11_ecdsa_generate_वैयक्तिकम्_कुञ्चिका(संरचना pkcs11_provider *p, CK_ULONG slotidx,
    वर्ण *label, CK_ULONG द्वयङ्काः, CK_BYTE keyid, uint32_t *err)
{
	संरचना pkcs11_slotinfo	*si;
	वर्ण			*plabel = label ? label : "";
	पूर्णाङ्क			 i;
	आकार_t			 ecparams_आकार;
	अचिह्नित वर्ण		*ecparams = रिक्त;
	पूर्णाङ्क			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_कुञ्चिका_2, priv_कुञ्चिका;
	CK_MECHANISM		 mech = {
	    CKM_EC_कुञ्चिका_PAIR_GEN, NULL_PTR, 0
	};
	CK_ATTRIBUTE		 tpub[16], tpriv[16];

	*err = 0;

	प्रति (i = 0; ec_वक्रम्_infos[i].name; i++) {
		यदि (ec_वक्रम्_infos[i].आकार == द्वयङ्काः)
			भङ्ग;
	}
	यदि (!ec_वक्रम्_infos[i].name) {
		error_f("invalid key size %lu", द्वयङ्काः);
		प्रत्यागम रिक्त;
	}
	यदि (pkcs11_decode_hex(ec_वक्रम्_infos[i].oid_encoded, &ecparams,
	    &ecparams_आकार) == -1) {
		error_f("invalid oid");
		प्रत्यागम रिक्त;
	}

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, परिमाण(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, वाक्यदैर्घ्यम्(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, परिमाण(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, परिमाण(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    परिमाण(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, परिमाण(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, परिमाण(false_val));
	FILL_ATTR(tpub, npub, CKA_EC_PARAMS, ecparams, ecparams_आकार);
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, परिमाण(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN, &true_val, परिमाण(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL, plabel, वाक्यदैर्घ्यम्(plabel));
	FILL_ATTR(tpriv, npriv, CKA_वैयक्तिकम्, &true_val, परिमाण(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE, &true_val, परिमाण(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT, &false_val, परिमाण(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN, &true_val, परिमाण(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER, &false_val,
	    परिमाण(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP, &false_val, परिमाण(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE, &false_val, परिमाण(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, परिमाण(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	यदि ((rv = f->C_Generate_कुञ्चिका_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_कुञ्चिका_2, &priv_कुञ्चिका)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		प्रत्यागम रिक्त;
	}

	प्रत्यागम pkcs11_fetch_ecdsa_pubkey(p, slotidx, &pub_कुञ्चिका_2);
}
#यदि_अन्तः /* WITH_PKCS11_KEYGEN */

/*
 * register a new provider, fails if provider already exists. if
 * keyp is provided, fetch keys.
 */
स्थिर पूर्णाङ्क
pkcs11_पञ्जिकाकोशः_provider(वर्ण *provider_id, वर्ण *pin,
    संरचना sshkey ***keyp, वर्ण ***labelsp,
    संरचना pkcs11_provider **providerp, CK_ULONG user)
{
	पूर्णाङ्क nkeys, need_finalize = 0;
	पूर्णाङ्क ret = -1;
	संरचना pkcs11_provider *p = रिक्त;
	शून्य *handle = रिक्त;
	CK_RV (*getfunctionlist)(CK_FUNCTION_LIST **);
	CK_RV rv;
	CK_FUNCTION_LIST *f = रिक्त;
	CK_TOKEN_INFO *token;
	CK_ULONG i;

	यदि (providerp == रिक्त)
		गच्छ fail;
	*providerp = रिक्त;

	यदि (keyp != रिक्त)
		*keyp = रिक्त;
	यदि (labelsp != रिक्त)
		*labelsp = रिक्त;

	यदि (pkcs11_provider_lookup(provider_id) != रिक्त) {
		debug_f("provider already registered: %s", provider_id);
		गच्छ fail;
	}
	यदि (lib_अन्तर्भवति_चिह्नम्(provider_id, "C_GetFunctionList") != 0) {
		error("provider %s is not a PKCS11 library", provider_id);
		गच्छ fail;
	}
	/* open shared pkcs11-library */
	यदि ((handle = dlopen(provider_id, RTLD_NOW)) == रिक्त) {
		error("dlopen %s failed: %s", provider_id, dlerror());
		गच्छ fail;
	}
	यदि ((getfunctionlist = dlsym(handle, "C_GetFunctionList")) == रिक्त)
		fatal("dlsym(C_GetFunctionList) failed: %s", dlerror());
	p = xcalloc(1, परिमाण(*p));
	p->name = xstrdup(provider_id);
	p->handle = handle;
	/* set up the pkcs11 callbacks */
	यदि ((rv = (*getfunctionlist)(&f)) != CKR_OK) {
		error("C_GetFunctionList for provider %s failed: %lu",
		    provider_id, rv);
		गच्छ fail;
	}
	p->function_list = f;
	यदि ((rv = f->C_Initialize(रिक्त)) != CKR_OK) {
		error("C_Initialize for provider %s failed: %lu",
		    provider_id, rv);
		गच्छ fail;
	}
	need_finalize = 1;
	यदि ((rv = f->C_GetInfo(&p->info)) != CKR_OK) {
		error("C_GetInfo for provider %s failed: %lu",
		    provider_id, rv);
		गच्छ fail;
	}
	debug("provider %s: manufacturerID <%.*s> cryptokiVersion %d.%d"
	    " libraryDescription <%.*s> libraryVersion %d.%d",
	    provider_id,
	    RMSPACE(p->info.manufacturerID),
	    p->info.cryptoki_संस्करणम्_2.major,
	    p->info.cryptoki_संस्करणम्_2.minor,
	    RMSPACE(p->info.libraryDescription),
	    p->info.library_संस्करणम्_2.major,
	    p->info.library_संस्करणम्_2.minor);
	यदि ((rv = f->C_GetSlotList(CK_TRUE, रिक्त, &p->nslots)) != CKR_OK) {
		error("C_GetSlotList failed: %lu", rv);
		गच्छ fail;
	}
	यदि (p->nslots == 0) {
		debug_f("provider %s returned no slots", provider_id);
		ret = -SSH_PKCS11_ERR_NO_SLOTS;
		गच्छ fail;
	}
	p->slotlist = xcalloc(p->nslots, परिमाण(CK_SLOT_ID));
	यदि ((rv = f->C_GetSlotList(CK_TRUE, p->slotlist, &p->nslots))
	    != CKR_OK) {
		error("C_GetSlotList for provider %s failed: %lu",
		    provider_id, rv);
		गच्छ fail;
	}
	p->slotinfo = xcalloc(p->nslots, परिमाण(संरचना pkcs11_slotinfo));
	p->valid = 1;
	nkeys = 0;
	प्रति (i = 0; i < p->nslots; i++) {
		token = &p->slotinfo[i].token;
		यदि ((rv = f->C_GetTokenInfo(p->slotlist[i], token))
		    != CKR_OK) {
			error("C_GetTokenInfo for provider %s slot %lu "
			    "failed: %lu", provider_id, (u_long)i, rv);
			अनुवर्त;
		}
		यदि ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
			debug2_f("ignoring uninitialised token in "
			    "provider %s slot %lu", provider_id, (u_long)i);
			अनुवर्त;
		}
		debug("provider %s slot %lu: label <%.*s> "
		    "manufacturerID <%.*s> model <%.*s> serial <%.*s> "
		    "flags 0x%lx",
		    provider_id, (अचिह्नित दीर्घ)i,
		    RMSPACE(token->label), RMSPACE(token->manufacturerID),
		    RMSPACE(token->model), RMSPACE(token->serial_सङ्ख्या_2),
		    token->flags);
		/*
		 * open session, login with pin and retrieve public
		 * keys (if keyp is provided)
		 */
		यदि ((ret = pkcs11_open_session(p, i, pin, user)) != 0 ||
		    keyp == रिक्त)
			अनुवर्त;
		pkcs11_fetch_कुञ्चिकाः(p, i, keyp, labelsp, &nkeys);
#यदि_परिभाषितम् WITH_OPENSSL
		pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#यदि_अन्तः
		यदि (nkeys == 0 && !p->slotinfo[i].logged_अन्तर् &&
		    pkcs11_interactive) {
			/*
			 * Some tokens require login before they will
			 * expose keys.
			 */
			यदि (pkcs11_login_slot(p, &p->slotinfo[i],
			    CKU_USER) < 0) {
				error("login failed");
				अनुवर्त;
			}
			pkcs11_fetch_कुञ्चिकाः(p, i, keyp, labelsp, &nkeys);
#यदि_परिभाषितम् WITH_OPENSSL
			pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#यदि_अन्तः
		}
	}

	/* now owned by caller */
	*providerp = p;

	TAILQ_INSERT_TAIL(&pkcs11_providers, p, अग्र);
	p->refcount++;	/* add to provider list */

	प्रत्यागम (nkeys);
fail:
	यदि (need_finalize && (rv = f->C_Finalize(रिक्त)) != CKR_OK)
		error("C_Finalize for provider %s failed: %lu",
		    provider_id, rv);
	यदि (p) {
		मुक्त(p->name);
		मुक्त(p->slotlist);
		मुक्त(p->slotinfo);
		मुक्त(p);
	}
	यदि (handle)
		dlclose(handle);
	यदि (ret > 0)
		ret = -1;
	प्रत्यागम (ret);
}

पूर्णाङ्क
pkcs11_init(पूर्णाङ्क interactive)
{
	debug3_f("called, interactive = %d", interactive);

	pkcs11_interactive = interactive;
	TAILQ_INIT(&pkcs11_providers);
	TAILQ_INIT(&pkcs11_कुञ्चिकाः);
	प्रत्यागम (0);
}

/* unregister all providers, keys might still point to the providers */
शून्य
pkcs11_terminate(शून्य)
{
	संरचना pkcs11_provider *p;
	संरचना pkcs11_कुञ्चिका *k11;

	debug3_f("called");

	यावत् ((k11 = TAILQ_FIRST(&pkcs11_कुञ्चिकाः)) != रिक्त) {
		TAILQ_REMOVE(&pkcs11_कुञ्चिकाः, k11, अग्र);
		pkcs11_k11_free(k11);
	}
	यावत् ((p = TAILQ_FIRST(&pkcs11_providers)) != रिक्त) {
		TAILQ_REMOVE(&pkcs11_providers, p, अग्र);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
}

/*
 * register a new provider and get number of keys hold by the token,
 * fails if provider already exists
 */
पूर्णाङ्क
pkcs11_सङ्कलय_provider(वर्ण *provider_id, वर्ण *pin, संरचना sshkey ***keyp,
    वर्ण ***labelsp)
{
	संरचना pkcs11_provider *p = रिक्त;
	पूर्णाङ्क nkeys;

	nkeys = pkcs11_पञ्जिकाकोशः_provider(provider_id, pin, keyp, labelsp,
	    &p, CKU_USER);

	/* no keys found or some other error, de-register provider */
	यदि (nkeys <= 0 && p != रिक्त) {
		TAILQ_REMOVE(&pkcs11_providers, p, अग्र);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
	यदि (nkeys == 0)
		debug_f("provider %s returned no keys", provider_id);

	प्रत्यागम (nkeys);
}

पूर्णाङ्क
pkcs11_sign(संरचना sshkey *कुञ्चिका,
    u_char **sigp, आकार_t *lenp,
    ध्रुव u_char *दत्त, आकार_t datalen,
    ध्रुव वर्ण *alg, ध्रुव वर्ण *sk_provider,
    ध्रुव वर्ण *sk_pin, u_int compat)
{
	विकल्प (कुञ्चिका->type) {
#यदि_परिभाषितम् WITH_OPENSSL
	पक्ष कुञ्चिका_RSA:
	पक्ष कुञ्चिका_RSA_CERT:
		प्रत्यागम pkcs11_sign_rsa(कुञ्चिका, sigp, lenp, दत्त, datalen,
		    alg, sk_provider, sk_pin, compat);
	पक्ष कुञ्चिका_ECDSA:
	पक्ष कुञ्चिका_ECDSA_CERT:
		प्रत्यागम pkcs11_sign_ecdsa(कुञ्चिका, sigp, lenp, दत्त, datalen,
		    alg, sk_provider, sk_pin, compat);
#यदि_अन्तः /* WITH_OPENSSL */
	पक्ष कुञ्चिका_ED25519:
	पक्ष कुञ्चिका_ED25519_CERT:
		प्रत्यागम pkcs11_sign_ed25519(कुञ्चिका, sigp, lenp, दत्त, datalen,
		    alg, sk_provider, sk_pin, compat);
	स्वभाव:
		प्रत्यागम SSH_ERR_कुञ्चिका_TYPE_UNKNOWN;
	}
}

शून्य
pkcs11_कुञ्चिका_free(संरचना sshkey *कुञ्चिका)
{
	/* never called */
}

#यदि_परिभाषितम् WITH_PKCS11_KEYGEN
संरचना sshkey *
pkcs11_gakp(वर्ण *provider_id, वर्ण *pin, अचिह्नित पूर्णाङ्क slotidx, वर्ण *label,
    अचिह्नित पूर्णाङ्क type, अचिह्नित पूर्णाङ्क द्वयङ्काः, अचिह्नित वर्ण keyid, uint32_t *err)
{
	संरचना pkcs11_provider	*p = रिक्त;
	संरचना pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	संरचना sshkey		*k = रिक्त;
	पूर्णाङ्क			 ret = -1, reset_pin = 0, reset_provider = 0;
	CK_RV			 rv;

	*err = 0;

	यदि ((p = pkcs11_provider_lookup(provider_id)) != रिक्त)
		debug_f("provider \"%s\" available", provider_id);
	अन्यथा यदि ((ret = pkcs11_पञ्जिकाकोशः_provider(provider_id, pin, रिक्त, रिक्त,
	    &p, CKU_SO)) < 0) {
		debug_f("could not register provider %s", provider_id);
		गच्छ बहिर्गमनम्;
	} अन्यथा
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	यदि ((rv = f->C_समुच्चयः_Operation_State(session , pin, वाक्यदैर्घ्यम्(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} अन्यथा
		reset_pin = 1;

	विकल्प (type) {
	पक्ष कुञ्चिका_RSA:
		यदि ((k = pkcs11_rsa_generate_वैयक्तिकम्_कुञ्चिका(p, slotidx, label,
		    द्वयङ्काः, keyid, err)) == रिक्त) {
			debug_f("failed to generate RSA key");
			गच्छ बहिर्गमनम्;
		}
		भङ्ग;
	पक्ष कुञ्चिका_ECDSA:
		यदि ((k = pkcs11_ecdsa_generate_वैयक्तिकम्_कुञ्चिका(p, slotidx, label,
		    द्वयङ्काः, keyid, err)) == रिक्त) {
			debug_f("failed to generate ECDSA key");
			गच्छ बहिर्गमनम्;
		}
		भङ्ग;
	स्वभाव:
		*err = SSH_PKCS11_ERR_GENERIC;
		debug_f("unknown type %d", type);
		गच्छ बहिर्गमनम्;
	}

बहिर्गमनम्:
	यदि (reset_pin)
		f->C_समुच्चयः_Operation_State(session , रिक्त, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	यदि (reset_provider)
		pkcs11_del_provider(provider_id);

	प्रत्यागम (k);
}

संरचना sshkey *
pkcs11_destroy_keypair(वर्ण *provider_id, वर्ण *pin, अचिह्नित दीर्घ slotidx,
    अचिह्नित वर्ण keyid, uint32_t *err)
{
	संरचना pkcs11_provider	*p = रिक्त;
	संरचना pkcs11_slotinfo	*si;
	संरचना sshkey		*k = रिक्त;
	पूर्णाङ्क			 reset_pin = 0, reset_provider = 0;
	CK_ULONG		 nattrs;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_ATTRIBUTE		 attrs[16];
	CK_OBJECT_CLASS		 कुञ्चिका_class;
	CK_कुञ्चिका_TYPE		 कुञ्चिका_type;
	CK_OBJECT_HANDLE	 obj = CK_INVALID_HANDLE;
	CK_RV			 rv;

	*err = 0;

	यदि ((p = pkcs11_provider_lookup(provider_id)) != रिक्त) {
		debug_f("using provider \"%s\"", provider_id);
	} अन्यथा यदि (pkcs11_पञ्जिकाकोशः_provider(provider_id, pin, रिक्त, रिक्त, &p,
	    CKU_SO) < 0) {
		debug_f("could not register provider %s",
		    provider_id);
		गच्छ बहिर्गमनम्;
	} अन्यथा
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	यदि ((rv = f->C_समुच्चयः_Operation_State(session , pin, वाक्यदैर्घ्यम्(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} अन्यथा
		reset_pin = 1;

	/* private key */
	nattrs = 0;
	कुञ्चिका_class = CKO_वैयक्तिकम्_कुञ्चिका;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &कुञ्चिका_class, परिमाण(कुञ्चिका_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, परिमाण(keyid));

	यदि (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {
		यदि ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy private key 0x%hhx",
			    keyid);
			*err = rv;
			गच्छ बहिर्गमनम्;
		}
	}

	/* public key */
	nattrs = 0;
	कुञ्चिका_class = CKO_लौकिकम्_कुञ्चिका;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &कुञ्चिका_class, परिमाण(कुञ्चिका_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, परिमाण(keyid));

	यदि (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {

		/* get key type */
		nattrs = 0;
		FILL_ATTR(attrs, nattrs, CKA_कुञ्चिका_TYPE, &कुञ्चिका_type,
		    परिमाण(कुञ्चिका_type));
		rv = f->C_Get_Attribute_मानम्(session, obj, attrs, nattrs);
		यदि (rv != CKR_OK) {
			debug_f("could not get key type of public key 0x%hhx",
			    keyid);
			*err = rv;
			कुञ्चिका_type = -1;
		}
		विकल्प (कुञ्चिका_type) {
#यदि_परिभाषितम् WITH_OPENSSL
		पक्ष CKK_RSA:
			k = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			भङ्ग;
		पक्ष CKK_ECDSA:
			k = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			भङ्ग;
#यदि_अन्तः /* WITH_OPENSSL */
		पक्ष CKK_EC_EDWARDS:
			k = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			भङ्ग;
		स्वभाव:
			debug_f("unsupported key type %lu", (u_long)कुञ्चिका_type);
			भङ्ग;
		}

		यदि ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy public key 0x%hhx", keyid);
			*err = rv;
			गच्छ बहिर्गमनम्;
		}
	}

बहिर्गमनम्:
	यदि (reset_pin)
		f->C_समुच्चयः_Operation_State(session , रिक्त, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	यदि (reset_provider)
		pkcs11_del_provider(provider_id);

	प्रत्यागम (k);
}
#यदि_अन्तः /* WITH_PKCS11_KEYGEN */
#अन्यथा /* ENABLE_PKCS11 */

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "ssh-pkcs11.h"

पूर्णाङ्क
pkcs11_init(पूर्णाङ्क interactive)
{
	error_f("PKCS#11 not supported");
	प्रत्यागम (-1);
}

पूर्णाङ्क
pkcs11_सङ्कलय_provider(वर्ण *provider_id, वर्ण *pin, संरचना sshkey ***keyp,
    वर्ण ***labelsp)
{
	error_f("PKCS#11 not supported");
	प्रत्यागम (-1);
}

शून्य
pkcs11_कुञ्चिका_free(संरचना sshkey *कुञ्चिका)
{
	error_f("PKCS#11 not supported");
}

पूर्णाङ्क
pkcs11_sign(संरचना sshkey *कुञ्चिका,
    u_char **sigp, आकार_t *lenp,
    ध्रुव u_char *दत्त, आकार_t datalen,
    ध्रुव वर्ण *alg, ध्रुव वर्ण *sk_provider,
    ध्रुव वर्ण *sk_pin, u_int compat)
{
	error_f("PKCS#11 not supported");
	प्रत्यागम SSH_ERR_FEATURE_UNSUPPORTED;
}

शून्य
pkcs11_terminate(शून्य)
{
	error_f("PKCS#11 not supported");
}
#यदि_अन्तः /* ENABLE_PKCS11 */
