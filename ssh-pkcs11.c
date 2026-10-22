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

#ifdef ENABLE_PKCS11

#अन्तर्भाव <sys/time.h>

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/queue.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>

#अन्तर्भाव <string.h>
#अन्तर्भाव <dlfcn.h>

#ifdef WITH_OPENSSL
#अन्तर्भाव "openbsd-compat/openssl-compat.h"
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/ecdsa.h>
#अन्तर्भाव <openssl/x509.h>
#अन्तर्भाव <openssl/err.h>
#endif

#define CRYPTOKI_COMPAT
#अन्तर्भाव "pkcs11.h"

#define SSHKEY_INTERNAL
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
	पूर्णाङ्क			logged_in;
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
	TAILQ_ENTRY(pkcs11_provider) next;
};

TAILQ_HEAD(, pkcs11_provider) pkcs11_providers;

संरचना pkcs11_साँचो {
	संरचना sshbuf		*keyblob;
	संरचना pkcs11_provider	*provider;
	CK_ULONG		slotidx;
	वर्ण			*keyid;
	पूर्णाङ्क			keyid_len;
	TAILQ_ENTRY(pkcs11_साँचो)	next;
};

TAILQ_HEAD(, pkcs11_साँचो) pkcs11_साँचोहरू; /* XXX a tree would be better */

पूर्णाङ्क pkcs11_interactive = 0;

#ifdef WITH_OPENSSL
स्थिर शून्य
ossl_error(अचर वर्ण *सन्देश)
{
	अचिन्हित दीर्घ    e;

	error_f("%s", सन्देश);
	जबसम्म ((e = ERR_get_error()) != 0)
		error_f("libcrypto error: %s", ERR_error_string(e, रिक्त));
}
#endif

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
		फर्काऊ;
	लागि (i = 0; i < p->nslots; i++) {
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

	TAILQ_FOREACH(p, &pkcs11_providers, next) {
		debug("check provider \"%s\"", p->name);
		यदि (!म_भेद(provider_id, p->name))
			फर्काऊ (p);
	}
	फर्काऊ (रिक्त);
}

/* unregister provider by name */
पूर्णाङ्क
pkcs11_del_provider(वर्ण *provider_id)
{
	संरचना pkcs11_provider *p;

	यदि ((p = pkcs11_provider_lookup(provider_id)) != रिक्त) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
		फर्काऊ (0);
	}
	फर्काऊ (-1);
}

/* release a wrapped object */
स्थिर शून्य
pkcs11_k11_free(संरचना pkcs11_साँचो *k11)
{
	यदि (k11 == रिक्त)
		फर्काऊ;
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
		फर्काऊ (-1);
	}
	यदि ((rv = f->C_FindObjects(session, obj, 1, &nfound)) != CKR_OK ||
	    nfound != 1) {
		debug("C_FindObjects failed (nfound %lu nattr %lu): %lu",
		    nfound, nattr, rv);
	} अन्यथा
		ret = 0;
	यदि ((rv = f->C_FindObjectsFinal(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	फर्काऊ (ret);
}

स्थिर पूर्णाङ्क
pkcs11_login_slot(संरचना pkcs11_provider *provider, संरचना pkcs11_slotinfo *si,
    CK_USER_TYPE type)
{
	वर्ण			*pin = रिक्त, prompt[1024];
	CK_RV			 rv;

	यदि (provider == रिक्त || si == रिक्त || !provider->valid) {
		error("no pkcs11 (valid) provider found");
		फर्काऊ (-1);
	}

	यदि (!pkcs11_interactive) {
		error("need pin entry%s",
		    (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH) ?
		    " on reader keypad" : "");
		फर्काऊ (-1);
	}
	यदि (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
		verbose("Deferring PIN entry to reader keypad.");
	अन्यथा {
		snprintf(prompt, परिमाण(prompt), "Enter PIN for '%s': ",
		    si->token.label);
		यदि ((pin = read_passphrase(prompt, RP_ALLOW_EOF)) == रिक्त) {
			debug_f("no pin specified");
			फर्काऊ (-1);	/* bail out */
		}
	}
	rv = provider->function_list->C_Login(si->session, type, (u_char *)pin,
	    (pin != रिक्त) ? म_माप(pin) : 0);
	यदि (pin != रिक्त)
		freezero(pin, म_माप(pin));

	विकल्प (rv) {
	पक्ष CKR_OK:
	पक्ष CKR_USER_ALREADY_LOGGED_IN:
		/* success */
		रोक;
	पक्ष CKR_PIN_LEN_RANGE:
		error("PKCS#11 login failed: PIN length out of range");
		फर्काऊ -1;
	पक्ष CKR_PIN_INCORRECT:
		error("PKCS#11 login failed: PIN incorrect");
		फर्काऊ -1;
	पक्ष CKR_PIN_LOCKED:
		error("PKCS#11 login failed: PIN locked");
		फर्काऊ -1;
	स्वभाव:
		error("PKCS#11 login failed: error %lu", rv);
		फर्काऊ -1;
	}
	si->logged_in = 1;
	फर्काऊ (0);
}

स्थिर पूर्णाङ्क
pkcs11_login(संरचना pkcs11_साँचो *k11, CK_USER_TYPE type)
{
	यदि (k11 == रिक्त || k11->provider == रिक्त || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		फर्काऊ (-1);
	}

	फर्काऊ pkcs11_login_slot(k11->provider,
	    &k11->provider->slotinfo[k11->slotidx], type);
}


स्थिर पूर्णाङ्क
pkcs11_check_obj_bool_attrib(संरचना pkcs11_साँचो *k11, CK_OBJECT_HANDLE obj,
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
		फर्काऊ (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	attr.type = type;
	attr.p_मान = &flag;
	attr.ul_मान_Len = परिमाण(flag);

	rv = f->C_Get_Attribute_मान(si->session, obj, &attr, 1);
	यदि (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		फर्काऊ (-1);
	}
	*val = flag != 0;
	debug_f("provider \"%s\" slot %lu object %lu: attrib %lu = %d",
	    k11->provider->name, k11->slotidx, obj, type, *val);
	फर्काऊ (0);
}

स्थिर पूर्णाङ्क
pkcs11_get_साँचो(संरचना pkcs11_साँचो *k11, CK_MECHANISM_TYPE mech_type)
{
	संरचना pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	 obj;
	CK_RV			 rv;
	CK_OBJECT_CLASS		 private_साँचो_class;
	CK_BBOOL		 true_val;
	CK_MECHANISM		 mech;
	CK_ATTRIBUTE		 साँचो_filter[3];
	पूर्णाङ्क			 always_auth = 0;
	पूर्णाङ्क			 did_login = 0;

	यदि (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		फर्काऊ (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	यदि ((si->token.flags & CKF_LOGIN_REQUIRED) && !si->logged_in) {
		यदि (pkcs11_login(k11, CKU_USER) < 0) {
			error("login failed");
			फर्काऊ (-1);
		}
		did_login = 1;
	}

	स_रखो(&साँचो_filter, 0, परिमाण(साँचो_filter));
	private_साँचो_class = CKO_PRIVATE_साँचो;
	साँचो_filter[0].type = CKA_CLASS;
	साँचो_filter[0].p_मान = &private_साँचो_class;
	साँचो_filter[0].ul_मान_Len = परिमाण(private_साँचो_class);

	साँचो_filter[1].type = CKA_ID;
	साँचो_filter[1].p_मान = k11->keyid;
	साँचो_filter[1].ul_मान_Len = k11->keyid_len;

	true_val = CK_TRUE;
	साँचो_filter[2].type = CKA_SIGN;
	साँचो_filter[2].p_मान = &true_val;
	साँचो_filter[2].ul_मान_Len = परिमाण(true_val);

	/* try to find object w/CKA_SIGN first, retry w/o */
	यदि (pkcs11_find(k11->provider, k11->slotidx, साँचो_filter, 3, &obj) < 0 &&
	    pkcs11_find(k11->provider, k11->slotidx, साँचो_filter, 2, &obj) < 0) {
		error("cannot find private key");
		फर्काऊ (-1);
	}

	स_रखो(&mech, 0, परिमाण(mech));
	mech.mechanism = mech_type;
	mech.pParameter = NULL_PTR;
	mech.ulParameterLen = 0;

	यदि ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
		फर्काऊ (-1);
	}

	pkcs11_check_obj_bool_attrib(k11, obj, CKA_ALWAYS_AUTHENTICATE,
	    &always_auth); /* ignore errors here */
	यदि (always_auth && !did_login) {
		debug_f("always-auth key");
		यदि (pkcs11_login(k11, CKU_CONTEXT_SPECIFIC) < 0) {
			error("login failed for always-auth key");
			फर्काऊ (-1);
		}
	}

	फर्काऊ (0);
}

/* record the key information later use lookup by keyblob */
स्थिर पूर्णाङ्क
pkcs11_record_साँचो(संरचना pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, संरचना sshkey *साँचो)
{
	संरचना sshbuf *keyblob;
	संरचना pkcs11_साँचो *k11;
	पूर्णाङ्क r;
	वर्ण *hex;

	hex = tohex(keyid_attrib->p_मान, keyid_attrib->ul_मान_Len);
	debug_f("%s key: provider %s slot %lu keyid %s",
	    sshkey_type(साँचो), provider->name, (u_long)slotidx, hex);
	मुक्त(hex);

	यदि ((keyblob = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshkey_putb(साँचो, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");

	/* Check if we've already recorded this key in a different slot */
	TAILQ_FOREACH(k11, &pkcs11_साँचोहरू, next) {
		यदि (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			hex = tohex(k11->keyid, k11->keyid_len);
			debug_f("Already seen this key at "
			    "provider %s slot %lu keyid %s",
			    k11->provider->name, k11->slotidx, hex);
			मुक्त(hex);
			sshbuf_free(keyblob);
			फर्काऊ -1;
		}
	}

	k11 = xcalloc(1, परिमाण(*k11));
	k11->provider = provider;
	k11->keyblob = keyblob;
	provider->refcount++;	/* provider referenced by RSA key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ul_मान_Len;
	यदि (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len);
		स_नकल(k11->keyid, keyid_attrib->p_मान, k11->keyid_len);
	}
	TAILQ_INSERT_TAIL(&pkcs11_साँचोहरू, k11, next);

	फर्काऊ 0;
}

/* retrieve the key information by keyblob */
स्थिर संरचना pkcs11_साँचो *
pkcs11_lookup_साँचो(संरचना sshkey *साँचो)
{
	संरचना pkcs11_साँचो *k11, *found = रिक्त;
	संरचना sshbuf *keyblob;
	पूर्णाङ्क r;

	यदि ((keyblob = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि ((r = sshkey_putb(साँचो, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");
	TAILQ_FOREACH(k11, &pkcs11_साँचोहरू, next) {
		यदि (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			found = k11;
			रोक;
		}
	}
	sshbuf_free(keyblob);
	फर्काऊ found;
}

#ifdef WITH_OPENSSL
/*
 * See:
 * https://datatracker.ietf.org/doc/html/rfc8017#section-9.2
 */

/*
 * id-sha1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
 *	oiw(14) secsig(3) algorithms(2) 26 }
 */
स्थिर अचर u_char id_sha1[] = {
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
स्थिर अचर u_char id_sha256[] = {
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
स्थिर अचर u_char id_sha512[] = {
	0x30, 0x51, /* type Sequence, length 0x51 (81) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, /* id-sha512 */
	0x05, 0x00, /* NULL */
	0x04, 0x40  /* Octet string, length 0x40 (64), followed by sha512 hash */
};

स्थिर पूर्णाङ्क
rsa_hash_alg_oid(पूर्णाङ्क hash_alg, अचर u_char **oidp, माप_प्रकार *oidlenp)
{
	विकल्प (hash_alg) {
	पक्ष SSH_DIGEST_SHA1:
		*oidp = id_sha1;
		*oidlenp = परिमाण(id_sha1);
		रोक;
	पक्ष SSH_DIGEST_SHA256:
		*oidp = id_sha256;
		*oidlenp = परिमाण(id_sha256);
		रोक;
	पक्ष SSH_DIGEST_SHA512:
		*oidp = id_sha512;
		*oidlenp = परिमाण(id_sha512);
		रोक;
	स्वभाव:
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
pkcs11_sign_rsa(संरचना sshkey *साँचो,
    u_char **sigp, माप_प्रकार *lenp,
    अचर u_char *data, माप_प्रकार datalen,
    अचर वर्ण *alg, अचर वर्ण *sk_provider,
    अचर वर्ण *sk_pin, u_int compat)
{
	संरचना pkcs11_साँचो	*k11;
	संरचना pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	पूर्णाङ्क			hashalg, r, diff, siglen, ret = -1;
	u_char			*oid_dgst = रिक्त, *sig = रिक्त;
	माप_प्रकार			dgst_len, oid_len, oid_dgst_len = 0;
	अचर u_char		*oid;

	यदि (sigp != रिक्त)
		*sigp = रिक्त;
	यदि (lenp != रिक्त)
		*lenp = 0;

	यदि ((k11 = pkcs11_lookup_साँचो(साँचो)) == रिक्त) {
		error_f("no key found");
		फर्काऊ SSH_ERR_साँचो_NOT_FOUND;
	}

	debug3_f("sign with alg \"%s\" using provider %s slotidx %lu",
	    alg == रिक्त ? "" : alg, k11->provider->name, (u_long)k11->slotidx);

	यदि (pkcs11_get_साँचो(k11, CKM_RSA_PKCS) == -1) {
		error("pkcs11_get_key failed");
		फर्काऊ SSH_ERR_AGENT_FAILURE;
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	यदि ((siglen = EVP_PKEY_size(साँचो->pkey)) <= 0)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* Determine hash algorithm and OID for signature */
	यदि (alg == रिक्त || *alg == '\0')
		hashalg = SSH_DIGEST_SHA1;
	अन्यथा यदि ((hashalg = ssh_rsa_hash_id_from_keyname(alg)) == -1)
		fatal_f("couldn't determine RSA hash alg \"%s\"", alg);
	यदि ((r = rsa_hash_alg_oid(hashalg, &oid, &oid_len)) != 0)
		fatal_fr(r, "rsa_hash_alg_oid failed");
	यदि ((dgst_len = ssh_digest_bytes(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);

	/* Prepare { oid || digest } */
	oid_dgst_len = oid_len + dgst_len;
	oid_dgst = xcalloc(1, oid_dgst_len);
	स_नकल(oid_dgst, oid, oid_len);
	यदि ((r = ssh_digest_memory(hashalg, data, datalen,
	    oid_dgst + oid_len, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	यदि ((rv = f->C_Sign(si->session, (CK_BYTE *)oid_dgst,
	    oid_dgst_len, sig, &slen)) != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		गच्छ done;
	}

	यदि (slen < (CK_ULONG)siglen) {
		diff = siglen - slen;
		debug3_f("repack %lu < %d (diff %d)",
		    (u_long)slen, siglen, diff);
		स_हटाओ(sig + diff, sig, slen);
		explicit_bzero(sig, diff);
	} अन्यथा यदि (slen > (माप_प्रकार)siglen)
		fatal_f("bad C_Sign length");

	यदि ((ret = ssh_rsa_encode_store_sig(hashalg, sig, siglen,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	freezero(oid_dgst, oid_dgst_len);
	मुक्त(sig);
	फर्काऊ ret;
}

स्थिर पूर्णाङ्क
pkcs11_sign_ecdsa(संरचना sshkey *साँचो,
    u_char **sigp, माप_प्रकार *lenp,
    अचर u_char *data, माप_प्रकार datalen,
    अचर वर्ण *alg, अचर वर्ण *sk_provider,
    अचर वर्ण *sk_pin, u_int compat)
{
	संरचना pkcs11_साँचो	*k11;
	संरचना pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0, bnlen;
	CK_RV			rv;
	BIGNUM			*sig_r = रिक्त, *sig_s = रिक्त;
	u_char			*sig = रिक्त, *dgst = रिक्त;
	माप_प्रकार			dgst_len = 0;
	पूर्णाङ्क			hashalg, ret = -1, r, siglen;

	यदि (sigp != रिक्त)
		*sigp = रिक्त;
	यदि (lenp != रिक्त)
		*lenp = 0;

	यदि ((k11 = pkcs11_lookup_साँचो(साँचो)) == रिक्त) {
		error_f("no key found");
		फर्काऊ SSH_ERR_साँचो_NOT_FOUND;
	}

	यदि (pkcs11_get_साँचो(k11, CKM_ECDSA) == -1) {
		error("pkcs11_get_key failed");
		फर्काऊ SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	/* Prepare digest to be signed */
	यदि ((hashalg = sshkey_ec_nid_to_hash_alg(साँचो->ecdsa_nid)) == -1)
		fatal_f("couldn't determine ECDSA hash alg");
	यदि ((dgst_len = ssh_digest_bytes(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);
	dgst = xcalloc(1, dgst_len);
	यदि ((r = ssh_digest_memory(hashalg, data, datalen,
	    dgst, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	यदि ((siglen = EVP_PKEY_size(साँचो->pkey)) <= 0)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dgst_len, sig, &slen);
	यदि (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		गच्छ done;
	}
	यदि (slen < 64 || slen > 132 || slen % 2) {
		error_f("bad signature length: %lu", (u_long)slen);
		गच्छ done;
	}
	bnlen = slen/2;
	यदि ((sig_r = BN_bin2bn(sig, bnlen, रिक्त)) == रिक्त ||
	    (sig_s = BN_bin2bn(sig+bnlen, bnlen, रिक्त)) == रिक्त) {
		ossl_error("BN_bin2bn failed");
		गच्छ done;
	}

	यदि ((ret = ssh_ecdsa_encode_store_sig(साँचो, sig_r, sig_s,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	freezero(dgst, dgst_len);
	BN_free(sig_r);
	BN_free(sig_s);
	मुक्त(sig);
	फर्काऊ ret;
}
#endif /* WITH_OPENSSL */

स्थिर पूर्णाङ्क
pkcs11_sign_ed25519(संरचना sshkey *साँचो,
    u_char **sigp, माप_प्रकार *lenp,
    अचर u_char *data, माप_प्रकार datalen,
    अचर वर्ण *alg, अचर वर्ण *sk_provider,
    अचर वर्ण *sk_pin, u_int compat)
{
	संरचना pkcs11_साँचो	*k11;
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

	यदि ((k11 = pkcs11_lookup_साँचो(साँचो)) == रिक्त) {
		error_f("no key found");
		फर्काऊ SSH_ERR_साँचो_NOT_FOUND;
	}

	यदि (pkcs11_get_साँचो(k11, CKM_EDDSA) == -1) {
		error("pkcs11_get_key failed");
		फर्काऊ SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	xdata = xmalloc(datalen);
	स_नकल(xdata, data, datalen);
	sig = xmalloc(crypto_sign_ed25519_BYTES);
	slen = crypto_sign_ed25519_BYTES;

	rv = f->C_Sign(si->session, xdata, datalen, sig, &slen);
	यदि (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		गच्छ done;
	}
	यदि (slen != crypto_sign_ed25519_BYTES) {
		error_f("bad signature length: %lu", (u_long)slen);
		गच्छ done;
	}
	यदि ((ret = ssh_ed25519_encode_store_sig(sig, slen, sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	यदि (xdata != रिक्त)
		freezero(xdata, datalen);
	मुक्त(sig);
	फर्काऊ ret;
}

/* remove trailing spaces */
स्थिर वर्ण *
rmspace(u_char *buf, माप_प्रकार len)
{
	माप_प्रकार i;

	यदि (len == 0)
		फर्काऊ buf;
	लागि (i = len - 1; i > 0; i--)
		यदि (buf[i] == ' ')
			buf[i] = '\0';
		अन्यथा
			रोक;
	फर्काऊ buf;
}
/* Used to printf fixed-width, space-padded, unterminated strings using %.*s */
#define RMSPACE(s) (पूर्णाङ्क)परिमाण(s), rmspace(s, परिमाण(s))

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
	    (pin == रिक्त || म_माप(pin) == 0)) {
		error("pin required");
		फर्काऊ (-SSH_PKCS11_ERR_PIN_REQUIRED);
	}
	यदि ((rv = f->C_OpenSession(p->slotlist[slotidx], CKF_RW_SESSION|
	    CKF_SERIAL_SESSION, रिक्त, रिक्त, &session)) != CKR_OK) {
		error("C_OpenSession failed: %lu", rv);
		फर्काऊ (-1);
	}
	यदि (login_required && pin != रिक्त && म_माप(pin) != 0) {
		rv = f->C_Login(session, user, (u_char *)pin, म_माप(pin));
		यदि (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
			error("C_Login failed: %lu", rv);
			ret = (rv == CKR_PIN_LOCKED) ?
			    -SSH_PKCS11_ERR_PIN_LOCKED :
			    -SSH_PKCS11_ERR_LOGIN_FAIL;
			यदि ((rv = f->C_CloseSession(session)) != CKR_OK)
				error("C_CloseSession failed: %lu", rv);
			फर्काऊ (ret);
		}
		si->logged_in = 1;
	}
	si->session = session;
	फर्काऊ (0);
}

स्थिर पूर्णाङ्क
pkcs11_साँचो_included(संरचना sshkey ***keysp, पूर्णाङ्क *nkeys, संरचना sshkey *साँचो)
{
	पूर्णाङ्क i;

	लागि (i = 0; i < *nkeys; i++)
		यदि (sshkey_equal(साँचो, (*keysp)[i]))
			फर्काऊ (1);
	फर्काऊ (0);
}

#ifdef WITH_OPENSSL
स्थिर संरचना sshkey *
pkcs11_fetch_ecdsa_pubkey(संरचना pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 साँचो_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = रिक्त;
	CK_RV			 rv;
	ASN1_OCTET_STRING	*octet = रिक्त;
	EC_साँचो			*ec = रिक्त;
	EC_GROUP		*group = रिक्त;
	संरचना sshkey		*साँचो = रिक्त;
	अचर अचिन्हित वर्ण	*attrp = रिक्त;
	पूर्णाङ्क			 success = -1, r, i, nid;

	स_रखो(&साँचो_attr, 0, परिमाण(साँचो_attr));
	साँचो_attr[0].type = CKA_ID;
	साँचो_attr[1].type = CKA_EC_POINT;
	साँचो_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_मान(session, *obj, साँचो_attr, 3);
	यदि (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		फर्काऊ (रिक्त);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	यदि (साँचो_attr[1].ul_मान_Len == 0 ||
	    साँचो_attr[2].ul_मान_Len == 0) {
		error("invalid attribute length");
		फर्काऊ (रिक्त);
	}

	/* allocate buffers for attributes */
	लागि (i = 0; i < 3; i++)
		यदि (साँचो_attr[i].ul_मान_Len > 0)
			साँचो_attr[i].p_मान = xcalloc(1, साँचो_attr[i].ul_मान_Len);

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_मान(session, *obj, साँचो_attr, 3);
	यदि (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		गच्छ fail;
	}

	ec = EC_साँचो_new();
	यदि (ec == रिक्त) {
		error("EC_KEY_new failed");
		गच्छ fail;
	}

	attrp = साँचो_attr[2].p_मान;
	group = d2i_ECPKParameters(रिक्त, &attrp, साँचो_attr[2].ul_मान_Len);
	यदि (group == रिक्त) {
		ossl_error("d2i_ECPKParameters failed");
		गच्छ fail;
	}

	यदि (EC_साँचो_set_group(ec, group) == 0) {
		ossl_error("EC_KEY_set_group failed");
		गच्छ fail;
	}

	यदि (साँचो_attr[1].ul_मान_Len <= 2) {
		error("CKA_EC_POINT too small");
		गच्छ fail;
	}

	attrp = साँचो_attr[1].p_मान;
	octet = d2i_ASN1_OCTET_STRING(रिक्त, &attrp, साँचो_attr[1].ul_मान_Len);
	यदि (octet == रिक्त) {
		ossl_error("d2i_ASN1_OCTET_STRING failed");
		गच्छ fail;
	}
	attrp = ASN1_STRING_get0_data(octet);
	यदि (o2i_ECPublic_साँचो(&ec, &attrp, ASN1_STRING_length(octet)) == रिक्त) {
		ossl_error("o2i_ECPublicKey failed");
		गच्छ fail;
	}
	यदि ((r = sshkey_ec_validate_public(EC_साँचो_get0_group(ec),
	    EC_साँचो_get0_public_साँचो(ec))) != 0) {
		error_fr(r, "invalid EC key");
		गच्छ fail;
	}

	nid = sshkey_ecdsa_साँचो_to_nid(ec);
	यदि (nid < 0) {
		error("couldn't get curve nid");
		गच्छ fail;
	}

	साँचो = sshkey_new(साँचो_UNSPEC);
	यदि (साँचो == रिक्त) {
		error("sshkey_new failed");
		गच्छ fail;
	}

	EVP_PKEY_free(साँचो->pkey);
	यदि ((साँचो->pkey = EVP_PKEY_new()) == रिक्त)
		fatal("EVP_PKEY_new failed");
	यदि (EVP_PKEY_set1_EC_साँचो(साँचो->pkey, ec) != 1)
		fatal("EVP_PKEY_set1_EC_KEY failed");
	साँचो->ecdsa_nid = nid;
	साँचो->type = साँचो_ECDSA;
	साँचो->flags |= SSHKEY_FLAG_EXT;
	यदि (pkcs11_record_साँचो(p, slotidx, &साँचो_attr[0], साँचो))
		गच्छ fail;
	/* success */
	success = 0;
fail:
	यदि (success != 0) {
		sshkey_free(साँचो);
		साँचो = रिक्त;
	}
	लागि (i = 0; i < 3; i++)
		मुक्त(साँचो_attr[i].p_मान);
	यदि (ec)
		EC_साँचो_free(ec);
	यदि (group)
		EC_GROUP_free(group);
	यदि (octet)
		ASN1_OCTET_STRING_free(octet);

	फर्काऊ (साँचो);
}

स्थिर संरचना sshkey *
pkcs11_fetch_rsa_pubkey(संरचना pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 साँचो_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = रिक्त;
	CK_RV			 rv;
	RSA			*rsa = रिक्त;
	BIGNUM			*rsa_n, *rsa_e;
	संरचना sshkey		*साँचो = रिक्त;
	पूर्णाङ्क			 i, success = -1;

	स_रखो(&साँचो_attr, 0, परिमाण(साँचो_attr));
	साँचो_attr[0].type = CKA_ID;
	साँचो_attr[1].type = CKA_MODULUS;
	साँचो_attr[2].type = CKA_PUBLIC_EXPONENT;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_मान(session, *obj, साँचो_attr, 3);
	यदि (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		फर्काऊ (रिक्त);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	यदि (साँचो_attr[1].ul_मान_Len == 0 ||
	    साँचो_attr[2].ul_मान_Len == 0) {
		error("invalid attribute length");
		फर्काऊ (रिक्त);
	}

	/* allocate buffers for attributes */
	लागि (i = 0; i < 3; i++)
		यदि (साँचो_attr[i].ul_मान_Len > 0)
			साँचो_attr[i].p_मान = xcalloc(1, साँचो_attr[i].ul_मान_Len);

	/* retrieve ID, modulus and public exponent of RSA key */
	rv = f->C_Get_Attribute_मान(session, *obj, साँचो_attr, 3);
	यदि (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		गच्छ fail;
	}

	rsa = RSA_new();
	यदि (rsa == रिक्त) {
		error("RSA_new failed");
		गच्छ fail;
	}

	rsa_n = BN_bin2bn(साँचो_attr[1].p_मान, साँचो_attr[1].ul_मान_Len, रिक्त);
	rsa_e = BN_bin2bn(साँचो_attr[2].p_मान, साँचो_attr[2].ul_मान_Len, रिक्त);
	यदि (rsa_n == रिक्त || rsa_e == रिक्त) {
		error("BN_bin2bn failed");
		गच्छ fail;
	}
	यदि (!RSA_set0_साँचो(rsa, rsa_n, rsa_e, रिक्त))
		fatal_f("set key");
	rsa_n = rsa_e = रिक्त; /* transferred */

	साँचो = sshkey_new(साँचो_UNSPEC);
	यदि (साँचो == रिक्त) {
		error("sshkey_new failed");
		गच्छ fail;
	}

	EVP_PKEY_free(साँचो->pkey);
	यदि ((साँचो->pkey = EVP_PKEY_new()) == रिक्त)
		fatal("EVP_PKEY_new failed");
	यदि (EVP_PKEY_set1_RSA(साँचो->pkey, rsa) != 1)
		fatal("EVP_PKEY_set1_RSA failed");
	साँचो->type = साँचो_RSA;
	साँचो->flags |= SSHKEY_FLAG_EXT;
	यदि (EVP_PKEY_bits(साँचो->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE) {
		error_f("RSA key too small %d < minimum %d",
		    EVP_PKEY_bits(साँचो->pkey), SSH_RSA_MINIMUM_MODULUS_SIZE);
		गच्छ fail;
	}
	यदि (pkcs11_record_साँचो(p, slotidx, &साँचो_attr[0], साँचो))
		गच्छ fail;
	/* success */
	success = 0;
fail:
	लागि (i = 0; i < 3; i++)
		मुक्त(साँचो_attr[i].p_मान);
	RSA_free(rsa);
	यदि (success != 0) {
		sshkey_free(साँचो);
		साँचो = रिक्त;
	}
	फर्काऊ साँचो;
}
#endif /* WITH_OPENSSL */

स्थिर संरचना sshkey *
pkcs11_fetch_ed25519_pubkey(संरचना pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 साँचो_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = रिक्त;
	CK_RV			 rv;
	संरचना sshkey		*साँचो = रिक्त;
	अचर अचिन्हित वर्ण	*d = रिक्त;
	माप_प्रकार			len;
	वर्ण			*hex = रिक्त;
	पूर्णाङ्क			 success = -1, i;
	/* https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061180 */
	अचर u_char		 id1[14] = {
		0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64,
		0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
	}; /* PrintableString { "edwards25519" } */
	अचर u_char		 id2[5] = {
		0x06, 0x03, 0x2b, 0x65, 0x70,
	}; /* OBJECT_IDENTIFIER { 1.3.101.112 } */

	स_रखो(&साँचो_attr, 0, परिमाण(साँचो_attr));
	साँचो_attr[0].type = CKA_ID;
	साँचो_attr[1].type = CKA_EC_POINT; /* XXX or CKA_VALUE ? */
	साँचो_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_मान(session, *obj, साँचो_attr, 3);
	यदि (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		फर्काऊ (रिक्त);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	यदि (साँचो_attr[1].ul_मान_Len == 0 ||
	    साँचो_attr[2].ul_मान_Len == 0) {
		error("invalid attribute length");
		फर्काऊ (रिक्त);
	}

	/* allocate buffers for attributes */
	लागि (i = 0; i < 3; i++) {
		यदि (साँचो_attr[i].ul_मान_Len > 0)
			साँचो_attr[i].p_मान = xcalloc(1, साँचो_attr[i].ul_मान_Len);
	}

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_मान(session, *obj, साँचो_attr, 3);
	यदि (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		गच्छ fail;
	}

	/* Expect one of the supported identifiers in CKA_EC_PARAMS */
	d = (u_char *)साँचो_attr[2].p_मान;
	len = साँचो_attr[2].ul_मान_Len;
	यदि ((len != परिमाण(id1) || स_भेद(d, id1, परिमाण(id1)) != 0) &&
	    (len != परिमाण(id2) || स_भेद(d, id2, परिमाण(id2)) != 0)) {
		hex = tohex(d, len);
		logit_f("unsupported CKA_EC_PARAMS: %s (len %zu)", hex, len);
		गच्छ fail;
	}

	/*
	 * Expect either a raw 32 byte pubkey or an OCTET STRING with
	 * a 32 byte pubkey in CKA_VALUE
	 */
	d = (u_char *)साँचो_attr[1].p_मान;
	len = साँचो_attr[1].ul_मान_Len;
	यदि (len == ED25519_PK_SZ + 2 && d[0] == 0x04 && d[1] == ED25519_PK_SZ) {
		d += 2;
		len -= 2;
	}
	यदि (len != ED25519_PK_SZ) {
		hex = tohex(साँचो_attr[1].p_मान, साँचो_attr[1].ul_मान_Len);
		logit_f("CKA_EC_POINT invalid octet str: %s (len %lu)",
		    hex, (u_long)साँचो_attr[1].ul_मान_Len);
		गच्छ fail;
	}

	यदि ((साँचो = sshkey_new(साँचो_UNSPEC)) == रिक्त)
		fatal_f("sshkey_new failed");
	साँचो->ed25519_pk = xmalloc(ED25519_PK_SZ);
	स_नकल(साँचो->ed25519_pk, d, ED25519_PK_SZ);
	साँचो->type = साँचो_ED25519;
	साँचो->flags |= SSHKEY_FLAG_EXT;
	यदि (pkcs11_record_साँचो(p, slotidx, &साँचो_attr[0], साँचो))
		गच्छ fail;
	/* success */
	success = 0;
 fail:
	यदि (success != 0) {
		sshkey_free(साँचो);
		साँचो = रिक्त;
	}
	मुक्त(hex);
	लागि (i = 0; i < 3; i++)
		मुक्त(साँचो_attr[i].p_मान);
	फर्काऊ साँचो;
}

#ifdef WITH_OPENSSL
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
	EC_साँचो			*ec = रिक्त;
	संरचना sshkey		*साँचो = रिक्त;
	पूर्णाङ्क			 r, i, nid, success = -1;
	अचर u_char		*cp;
	वर्ण			*subject = रिक्त;
#ifdef OPENSSL_HAS_ED25519
	माप_प्रकार			len;
#endif /* OPENSSL_HAS_ED25519 */

	*keyp = रिक्त;
	*labelp = रिक्त;

	स_रखो(&cert_attr, 0, परिमाण(cert_attr));
	cert_attr[0].type = CKA_ID;
	cert_attr[1].type = CKA_SUBJECT;
	cert_attr[2].type = CKA_मान;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_मान(session, *obj, cert_attr, 3);
	यदि (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		फर्काऊ -1;
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	यदि (cert_attr[1].ul_मान_Len == 0 ||
	    cert_attr[2].ul_मान_Len == 0) {
		error("invalid attribute length");
		फर्काऊ -1;
	}

	/* allocate buffers for attributes */
	लागि (i = 0; i < 3; i++)
		यदि (cert_attr[i].ul_मान_Len > 0)
			cert_attr[i].p_मान = xcalloc(1, cert_attr[i].ul_मान_Len);

	/* retrieve ID, subject and value of certificate */
	rv = f->C_Get_Attribute_मान(session, *obj, cert_attr, 3);
	यदि (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		गच्छ out;
	}

	/* Decode DER-encoded cert subject */
	cp = cert_attr[1].p_मान;
	यदि ((x509_name = d2i_X509_NAME(रिक्त, &cp,
	    cert_attr[1].ul_मान_Len)) == रिक्त ||
	    (subject = X509_NAME_oneline(x509_name, रिक्त, 0)) == रिक्त)
		subject = xstrdup("invalid subject");
	X509_NAME_free(x509_name);

	cp = cert_attr[2].p_मान;
	यदि ((x509 = d2i_X509(रिक्त, &cp, cert_attr[2].ul_मान_Len)) == रिक्त) {
		error("d2i_x509 failed");
		गच्छ out;
	}

	यदि ((evp = X509_get_pubkey(x509)) == रिक्त) {
		error("X509_get_pubkey failed");
		गच्छ out;
	}

	यदि (EVP_PKEY_base_id(evp) == EVP_PKEY_RSA) {
		यदि (EVP_PKEY_get0_RSA(evp) == रिक्त) {
			error("invalid x509; no rsa key");
			गच्छ out;
		}
		यदि ((rsa = RSAPublic_साँचो_dup(EVP_PKEY_get0_RSA(evp))) == रिक्त) {
			error("RSAPublicKey_dup failed");
			गच्छ out;
		}

		साँचो = sshkey_new(साँचो_UNSPEC);
		यदि (साँचो == रिक्त) {
			error("sshkey_new failed");
			गच्छ out;
		}

		EVP_PKEY_free(साँचो->pkey);
		यदि ((साँचो->pkey = EVP_PKEY_new()) == रिक्त)
			fatal("EVP_PKEY_new failed");
		यदि (EVP_PKEY_set1_RSA(साँचो->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		साँचो->type = साँचो_RSA;
		साँचो->flags |= SSHKEY_FLAG_EXT;
		यदि (EVP_PKEY_bits(साँचो->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE) {
			error_f("RSA key too small %d < minimum %d",
			    EVP_PKEY_bits(साँचो->pkey),
			    SSH_RSA_MINIMUM_MODULUS_SIZE);
			गच्छ out;
		}
		यदि (pkcs11_record_साँचो(p, slotidx, &cert_attr[0], साँचो))
			गच्छ out;
		/* success */
		success = 0;
	} अन्यथा यदि (EVP_PKEY_base_id(evp) == EVP_PKEY_EC) {
		यदि (EVP_PKEY_get0_EC_साँचो(evp) == रिक्त) {
			error("invalid x509; no ec key");
			गच्छ out;
		}
		यदि ((ec = EC_साँचो_dup(EVP_PKEY_get0_EC_साँचो(evp))) == रिक्त) {
			error("EC_KEY_dup failed");
			गच्छ out;
		}
		यदि ((r = sshkey_ec_validate_public(EC_साँचो_get0_group(ec),
		    EC_साँचो_get0_public_साँचो(ec))) != 0) {
			error_fr(r, "invalid EC key");
			गच्छ out;
		}
		nid = sshkey_ecdsa_साँचो_to_nid(ec);
		यदि (nid < 0) {
			error("couldn't get curve nid");
			गच्छ out;
		}

		साँचो = sshkey_new(साँचो_UNSPEC);
		यदि (साँचो == रिक्त) {
			error("sshkey_new failed");
			गच्छ out;
		}

		EVP_PKEY_free(साँचो->pkey);
		यदि ((साँचो->pkey = EVP_PKEY_new()) == रिक्त)
			fatal("EVP_PKEY_new failed");
		यदि (EVP_PKEY_set1_EC_साँचो(साँचो->pkey, ec) != 1)
			fatal("EVP_PKEY_set1_EC_KEY failed");
		साँचो->ecdsa_nid = nid;
		साँचो->type = साँचो_ECDSA;
		साँचो->flags |= SSHKEY_FLAG_EXT;
		यदि (pkcs11_record_साँचो(p, slotidx, &cert_attr[0], साँचो))
			गच्छ out;
		/* success */
		success = 0;
#ifdef OPENSSL_HAS_ED25519
	} अन्यथा यदि (EVP_PKEY_base_id(evp) == EVP_PKEY_ED25519) {
		यदि ((साँचो = sshkey_new(साँचो_UNSPEC)) == रिक्त ||
		    (साँचो->ed25519_pk = सुस्मृति(1, ED25519_PK_SZ)) == रिक्त)
			fatal_f("allocation failed");
		len = ED25519_PK_SZ;
		यदि (!EVP_PKEY_get_raw_public_साँचो(evp, साँचो->ed25519_pk, &len)) {
			ossl_error("EVP_PKEY_get_raw_public_key failed");
			गच्छ out;
		}
		यदि (len != ED25519_PK_SZ) {
			error_f("incorrect returned public key "
			    "length for ed25519");
			गच्छ out;
		}
		साँचो->type = साँचो_ED25519;
		साँचो->flags |= SSHKEY_FLAG_EXT;
		यदि (pkcs11_record_साँचो(p, slotidx, &cert_attr[0], साँचो))
			गच्छ out;
		/* success */
		success = 0;
#endif /* OPENSSL_HAS_ED25519 */
	} अन्यथा {
		error("unknown certificate key type");
		गच्छ out;
	}
 out:
	लागि (i = 0; i < 3; i++)
		मुक्त(cert_attr[i].p_मान);
	X509_free(x509);
	RSA_free(rsa);
	EC_साँचो_free(ec);
	यदि (success != 0 || साँचो == रिक्त) {
		sshkey_free(साँचो);
		मुक्त(subject);
		फर्काऊ -1;
	}
	/* success */
	*keyp = साँचो;
	*labelp = subject;
	फर्काऊ 0;
}
#endif /* WITH_OPENSSL */

स्थिर शून्य
note_साँचो(संरचना pkcs11_provider *p, CK_ULONG slotidx, अचर वर्ण *context,
    संरचना sshkey *साँचो)
{
	वर्ण *fp;

	यदि ((fp = sshkey_fingerprint(साँचो, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == रिक्त) {
		error_f("sshkey_fingerprint failed");
		फर्काऊ;
	}
	debug2("%s: provider %s slot %lu: %s %s", context, p->name,
	    (u_long)slotidx, sshkey_type(साँचो), fp);
	मुक्त(fp);
}

#ifdef WITH_OPENSSL /* libcrypto needed for certificate parsing */
/*
 * lookup certificates for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
स्थिर पूर्णाङ्क
pkcs11_fetch_certs(संरचना pkcs11_provider *p, CK_ULONG slotidx,
    संरचना sshkey ***keysp, वर्ण ***labelsp, पूर्णाङ्क *nkeys)
{
	संरचना sshkey		*साँचो = रिक्त;
	CK_OBJECT_CLASS		 साँचो_class;
	CK_ATTRIBUTE		 साँचो_attr[1];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = रिक्त;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	पूर्णाङ्क			 ret = -1;
	वर्ण			*label;

	स_रखो(&साँचो_attr, 0, परिमाण(साँचो_attr));
	स_रखो(&obj, 0, परिमाण(obj));

	साँचो_class = CKO_CERTIFICATE;
	साँचो_attr[0].type = CKA_CLASS;
	साँचो_attr[0].p_मान = &साँचो_class;
	साँचो_attr[0].ul_मान_Len = परिमाण(साँचो_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, साँचो_attr, 1);
	यदि (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		गच्छ fail;
	}

	जबसम्म (1) {
		CK_CERTIFICATE_TYPE	ck_cert_type;

		rv = f->C_FindObjects(session, &obj, 1, &n);
		यदि (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			गच्छ fail;
		}
		यदि (n == 0)
			रोक;

		स_रखो(&ck_cert_type, 0, परिमाण(ck_cert_type));
		स_रखो(&साँचो_attr, 0, परिमाण(साँचो_attr));
		साँचो_attr[0].type = CKA_CERTIFICATE_TYPE;
		साँचो_attr[0].p_मान = &ck_cert_type;
		साँचो_attr[0].ul_मान_Len = परिमाण(ck_cert_type);

		rv = f->C_Get_Attribute_मान(session, obj, साँचो_attr, 1);
		यदि (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			गच्छ fail;
		}

		साँचो = रिक्त;
		label = रिक्त;
		विकल्प (ck_cert_type) {
		पक्ष CKC_X_509:
			यदि (pkcs11_fetch_x509_pubkey(p, slotidx, &obj,
			    &साँचो, &label) != 0) {
				debug_f("failed to fetch key");
				जारी;
			}
			रोक;
		स्वभाव:
			error("skipping unsupported certificate type %lu",
			    ck_cert_type);
			जारी;
		}
		note_साँचो(p, slotidx, __func__, साँचो);
		यदि (pkcs11_साँचो_included(keysp, nkeys, साँचो)) {
			debug2_f("key already included");
			sshkey_free(साँचो);
		} अन्यथा {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, परिमाण(संरचना sshkey *));
			(*keysp)[*nkeys] = साँचो;
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

	फर्काऊ (ret);
}
#endif /* WITH_OPENSSL */

/*
 * lookup public keys for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
स्थिर पूर्णाङ्क
pkcs11_fetch_साँचोहरू(संरचना pkcs11_provider *p, CK_ULONG slotidx,
    संरचना sshkey ***keysp, वर्ण ***labelsp, पूर्णाङ्क *nkeys)
{
	संरचना sshkey		*साँचो = रिक्त;
	CK_OBJECT_CLASS		 साँचो_class;
	CK_ATTRIBUTE		 साँचो_attr[2];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = रिक्त;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	पूर्णाङ्क			 ret = -1;

	स_रखो(&साँचो_attr, 0, परिमाण(साँचो_attr));
	स_रखो(&obj, 0, परिमाण(obj));

	साँचो_class = CKO_PUBLIC_साँचो;
	साँचो_attr[0].type = CKA_CLASS;
	साँचो_attr[0].p_मान = &साँचो_class;
	साँचो_attr[0].ul_मान_Len = परिमाण(साँचो_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, साँचो_attr, 1);
	यदि (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		गच्छ fail;
	}

	जबसम्म (1) {
		CK_साँचो_TYPE	ck_साँचो_type;
		CK_UTF8CHAR	label[256];

		rv = f->C_FindObjects(session, &obj, 1, &n);
		यदि (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			गच्छ fail;
		}
		यदि (n == 0)
			रोक;

		स_रखो(&ck_साँचो_type, 0, परिमाण(ck_साँचो_type));
		स_रखो(&साँचो_attr, 0, परिमाण(साँचो_attr));
		साँचो_attr[0].type = CKA_साँचो_TYPE;
		साँचो_attr[0].p_मान = &ck_साँचो_type;
		साँचो_attr[0].ul_मान_Len = परिमाण(ck_साँचो_type);
		साँचो_attr[1].type = CKA_LABEL;
		साँचो_attr[1].p_मान = &label;
		साँचो_attr[1].ul_मान_Len = परिमाण(label) - 1;

		rv = f->C_Get_Attribute_मान(session, obj, साँचो_attr, 2);
		यदि (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			गच्छ fail;
		}

		label[साँचो_attr[1].ul_मान_Len] = '\0';

		विकल्प (ck_साँचो_type) {
#ifdef WITH_OPENSSL
		पक्ष CKK_RSA:
			साँचो = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			रोक;
		पक्ष CKK_ECDSA:
			साँचो = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			रोक;
#endif /* WITH_OPENSSL */
		पक्ष CKK_EC_EDWARDS:
			साँचो = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			रोक;
		स्वभाव:
			/* XXX print key type? */
			साँचो = रिक्त;
			error("skipping unsupported key type 0x%lx",
			    (u_long)ck_साँचो_type);
		}

		यदि (साँचो == रिक्त) {
			debug_f("failed to fetch key");
			जारी;
		}
		note_साँचो(p, slotidx, __func__, साँचो);
		यदि (pkcs11_साँचो_included(keysp, nkeys, साँचो)) {
			debug2_f("key already included");
			sshkey_free(साँचो);
		} अन्यथा {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, परिमाण(संरचना sshkey *));
			(*keysp)[*nkeys] = साँचो;
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

	फर्काऊ (ret);
}

#ifdef WITH_PKCS11_KEYGEN
#define FILL_ATTR(attr, idx, typ, val, len) \
	{ (attr[idx]).type=(typ); (attr[idx]).p_मान=(val); (attr[idx]).ul_मान_Len=len; idx++; }

स्थिर संरचना sshkey *
pkcs11_rsa_generate_private_साँचो(संरचना pkcs11_provider *p, CK_ULONG slotidx,
    वर्ण *label, CK_ULONG bits, CK_BYTE keyid, uint32_t *err)
{
	संरचना pkcs11_slotinfo	*si;
	वर्ण			*plabel = label ? label : "";
	पूर्णाङ्क			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_साँचो_2, priv_साँचो;
	CK_ATTRIBUTE		 tpub[16], tpriv[16];
	CK_MECHANISM		 mech = {
	    CKM_RSA_PKCS_साँचो_PAIR_GEN, NULL_PTR, 0
	};
	CK_BYTE			 pubExponent[] = {
	    0x01, 0x00, 0x01 /* RSA_F4 in bytes */
	};
	pubkey_filter[0].p_मान = &pubkey_class;
	cert_filter[0].p_मान = &cert_class;

	*err = 0;

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, परिमाण(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, म_माप(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, परिमाण(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, परिमाण(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    परिमाण(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, परिमाण(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, परिमाण(false_val));
	FILL_ATTR(tpub, npub, CKA_MODULUS_BITS, &bits, परिमाण(bits));
	FILL_ATTR(tpub, npub, CKA_PUBLIC_EXPONENT, pubExponent,
	    परिमाण(pubExponent));
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, परिमाण(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN,  &true_val, परिमाण(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL,  plabel, म_माप(plabel));
	FILL_ATTR(tpriv, npriv, CKA_PRIVATE,  &true_val, परिमाण(true_val));
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

	यदि ((rv = f->C_Generate_साँचो_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_साँचो_2, &priv_साँचो)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		फर्काऊ रिक्त;
	}

	फर्काऊ pkcs11_fetch_rsa_pubkey(p, slotidx, &pub_साँचो_2);
}

स्थिर पूर्णाङ्क
h2i(वर्ण c)
{
	यदि (c >= '0' && c <= '9')
		फर्काऊ c - '0';
	अन्यथा यदि (c >= 'a' && c <= 'f')
		फर्काऊ c - 'a' + 10;
	अन्यथा यदि (c >= 'A' && c <= 'F')
		फर्काऊ c - 'A' + 10;
	अन्यथा
		फर्काऊ -1;
}

स्थिर पूर्णाङ्क
pkcs11_decode_hex(अचर वर्ण *hex, अचिन्हित वर्ण **dest, माप_प्रकार *rlen)
{
	माप_प्रकार	i, len;

	यदि (dest)
		*dest = रिक्त;
	यदि (rlen)
		*rlen = 0;

	यदि ((len = म_माप(hex)) % 2)
		फर्काऊ -1;
	len /= 2;

	*dest = xmalloc(len);

	लागि (i = 0; i < len; i++) {
		पूर्णाङ्क hi, lo;

		hi = h2i(hex[2 * i]);
		lo = h2i(hex[(2 * i) + 1]);
		यदि (hi == -1 || lo == -1)
			फर्काऊ -1;
		(*dest)[i] = (hi << 4) | lo;
	}

	यदि (rlen)
		*rlen = len;

	फर्काऊ 0;
}

स्थिर संरचना ec_curve_info {
	अचर वर्ण	*name;
	अचर वर्ण	*oid;
	अचर वर्ण	*oid_encoded;
	माप_प्रकार		 size;
} ec_curve_infos[] = {
	{"prime256v1",	"1.2.840.10045.3.1.7",	"06082A8648CE3D030107", 256},
	{"secp384r1",	"1.3.132.0.34",		"06052B81040022",	384},
	{"secp521r1",	"1.3.132.0.35",		"06052B81040023",	521},
	{रिक्त,		रिक्त,			रिक्त,			0},
};

स्थिर संरचना sshkey *
pkcs11_ecdsa_generate_private_साँचो(संरचना pkcs11_provider *p, CK_ULONG slotidx,
    वर्ण *label, CK_ULONG bits, CK_BYTE keyid, uint32_t *err)
{
	संरचना pkcs11_slotinfo	*si;
	वर्ण			*plabel = label ? label : "";
	पूर्णाङ्क			 i;
	माप_प्रकार			 ecparams_size;
	अचिन्हित वर्ण		*ecparams = रिक्त;
	पूर्णाङ्क			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_साँचो_2, priv_साँचो;
	CK_MECHANISM		 mech = {
	    CKM_EC_साँचो_PAIR_GEN, NULL_PTR, 0
	};
	CK_ATTRIBUTE		 tpub[16], tpriv[16];

	*err = 0;

	लागि (i = 0; ec_curve_infos[i].name; i++) {
		यदि (ec_curve_infos[i].size == bits)
			रोक;
	}
	यदि (!ec_curve_infos[i].name) {
		error_f("invalid key size %lu", bits);
		फर्काऊ रिक्त;
	}
	यदि (pkcs11_decode_hex(ec_curve_infos[i].oid_encoded, &ecparams,
	    &ecparams_size) == -1) {
		error_f("invalid oid");
		फर्काऊ रिक्त;
	}

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, परिमाण(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, म_माप(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, परिमाण(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, परिमाण(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    परिमाण(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, परिमाण(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, परिमाण(false_val));
	FILL_ATTR(tpub, npub, CKA_EC_PARAMS, ecparams, ecparams_size);
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, परिमाण(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN, &true_val, परिमाण(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL, plabel, म_माप(plabel));
	FILL_ATTR(tpriv, npriv, CKA_PRIVATE, &true_val, परिमाण(true_val));
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

	यदि ((rv = f->C_Generate_साँचो_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_साँचो_2, &priv_साँचो)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		फर्काऊ रिक्त;
	}

	फर्काऊ pkcs11_fetch_ecdsa_pubkey(p, slotidx, &pub_साँचो_2);
}
#endif /* WITH_PKCS11_KEYGEN */

/*
 * register a new provider, fails if provider already exists. if
 * keyp is provided, fetch keys.
 */
स्थिर पूर्णाङ्क
pkcs11_register_provider(वर्ण *provider_id, वर्ण *pin,
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
	यदि (lib_contains_चिह्न(provider_id, "C_GetFunctionList") != 0) {
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
	    p->info.cryptokiVersion.major,
	    p->info.cryptokiVersion.minor,
	    RMSPACE(p->info.libraryDescription),
	    p->info.libraryVersion.major,
	    p->info.libraryVersion.minor);
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
	लागि (i = 0; i < p->nslots; i++) {
		token = &p->slotinfo[i].token;
		यदि ((rv = f->C_GetTokenInfo(p->slotlist[i], token))
		    != CKR_OK) {
			error("C_GetTokenInfo for provider %s slot %lu "
			    "failed: %lu", provider_id, (u_long)i, rv);
			जारी;
		}
		यदि ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
			debug2_f("ignoring uninitialised token in "
			    "provider %s slot %lu", provider_id, (u_long)i);
			जारी;
		}
		debug("provider %s slot %lu: label <%.*s> "
		    "manufacturerID <%.*s> model <%.*s> serial <%.*s> "
		    "flags 0x%lx",
		    provider_id, (अचिन्हित दीर्घ)i,
		    RMSPACE(token->label), RMSPACE(token->manufacturerID),
		    RMSPACE(token->model), RMSPACE(token->serial_सङ्ख्या_2),
		    token->flags);
		/*
		 * open session, login with pin and retrieve public
		 * keys (if keyp is provided)
		 */
		यदि ((ret = pkcs11_open_session(p, i, pin, user)) != 0 ||
		    keyp == रिक्त)
			जारी;
		pkcs11_fetch_साँचोहरू(p, i, keyp, labelsp, &nkeys);
#ifdef WITH_OPENSSL
		pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#endif
		यदि (nkeys == 0 && !p->slotinfo[i].logged_in &&
		    pkcs11_interactive) {
			/*
			 * Some tokens require login before they will
			 * expose keys.
			 */
			यदि (pkcs11_login_slot(p, &p->slotinfo[i],
			    CKU_USER) < 0) {
				error("login failed");
				जारी;
			}
			pkcs11_fetch_साँचोहरू(p, i, keyp, labelsp, &nkeys);
#ifdef WITH_OPENSSL
			pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#endif
		}
	}

	/* now owned by caller */
	*providerp = p;

	TAILQ_INSERT_TAIL(&pkcs11_providers, p, next);
	p->refcount++;	/* add to provider list */

	फर्काऊ (nkeys);
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
	फर्काऊ (ret);
}

पूर्णाङ्क
pkcs11_init(पूर्णाङ्क interactive)
{
	debug3_f("called, interactive = %d", interactive);

	pkcs11_interactive = interactive;
	TAILQ_INIT(&pkcs11_providers);
	TAILQ_INIT(&pkcs11_साँचोहरू);
	फर्काऊ (0);
}

/* unregister all providers, keys might still point to the providers */
शून्य
pkcs11_terminate(शून्य)
{
	संरचना pkcs11_provider *p;
	संरचना pkcs11_साँचो *k11;

	debug3_f("called");

	जबसम्म ((k11 = TAILQ_FIRST(&pkcs11_साँचोहरू)) != रिक्त) {
		TAILQ_REMOVE(&pkcs11_साँचोहरू, k11, next);
		pkcs11_k11_free(k11);
	}
	जबसम्म ((p = TAILQ_FIRST(&pkcs11_providers)) != रिक्त) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
}

/*
 * register a new provider and get number of keys hold by the token,
 * fails if provider already exists
 */
पूर्णाङ्क
pkcs11_add_provider(वर्ण *provider_id, वर्ण *pin, संरचना sshkey ***keyp,
    वर्ण ***labelsp)
{
	संरचना pkcs11_provider *p = रिक्त;
	पूर्णाङ्क nkeys;

	nkeys = pkcs11_register_provider(provider_id, pin, keyp, labelsp,
	    &p, CKU_USER);

	/* no keys found or some other error, de-register provider */
	यदि (nkeys <= 0 && p != रिक्त) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
	यदि (nkeys == 0)
		debug_f("provider %s returned no keys", provider_id);

	फर्काऊ (nkeys);
}

पूर्णाङ्क
pkcs11_sign(संरचना sshkey *साँचो,
    u_char **sigp, माप_प्रकार *lenp,
    अचर u_char *data, माप_प्रकार datalen,
    अचर वर्ण *alg, अचर वर्ण *sk_provider,
    अचर वर्ण *sk_pin, u_int compat)
{
	विकल्प (साँचो->type) {
#ifdef WITH_OPENSSL
	पक्ष साँचो_RSA:
	पक्ष साँचो_RSA_CERT:
		फर्काऊ pkcs11_sign_rsa(साँचो, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	पक्ष साँचो_ECDSA:
	पक्ष साँचो_ECDSA_CERT:
		फर्काऊ pkcs11_sign_ecdsa(साँचो, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
#endif /* WITH_OPENSSL */
	पक्ष साँचो_ED25519:
	पक्ष साँचो_ED25519_CERT:
		फर्काऊ pkcs11_sign_ed25519(साँचो, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	स्वभाव:
		फर्काऊ SSH_ERR_साँचो_TYPE_UNKNOWN;
	}
}

शून्य
pkcs11_साँचो_free(संरचना sshkey *साँचो)
{
	/* never called */
}

#ifdef WITH_PKCS11_KEYGEN
संरचना sshkey *
pkcs11_gakp(वर्ण *provider_id, वर्ण *pin, अचिन्हित पूर्णाङ्क slotidx, वर्ण *label,
    अचिन्हित पूर्णाङ्क type, अचिन्हित पूर्णाङ्क bits, अचिन्हित वर्ण keyid, uint32_t *err)
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
	अन्यथा यदि ((ret = pkcs11_register_provider(provider_id, pin, रिक्त, रिक्त,
	    &p, CKU_SO)) < 0) {
		debug_f("could not register provider %s", provider_id);
		गच्छ out;
	} अन्यथा
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	यदि ((rv = f->C_SetOperationState(session , pin, म_माप(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} अन्यथा
		reset_pin = 1;

	विकल्प (type) {
	पक्ष साँचो_RSA:
		यदि ((k = pkcs11_rsa_generate_private_साँचो(p, slotidx, label,
		    bits, keyid, err)) == रिक्त) {
			debug_f("failed to generate RSA key");
			गच्छ out;
		}
		रोक;
	पक्ष साँचो_ECDSA:
		यदि ((k = pkcs11_ecdsa_generate_private_साँचो(p, slotidx, label,
		    bits, keyid, err)) == रिक्त) {
			debug_f("failed to generate ECDSA key");
			गच्छ out;
		}
		रोक;
	स्वभाव:
		*err = SSH_PKCS11_ERR_GENERIC;
		debug_f("unknown type %d", type);
		गच्छ out;
	}

out:
	यदि (reset_pin)
		f->C_SetOperationState(session , रिक्त, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	यदि (reset_provider)
		pkcs11_del_provider(provider_id);

	फर्काऊ (k);
}

संरचना sshkey *
pkcs11_destroy_keypair(वर्ण *provider_id, वर्ण *pin, अचिन्हित दीर्घ slotidx,
    अचिन्हित वर्ण keyid, uint32_t *err)
{
	संरचना pkcs11_provider	*p = रिक्त;
	संरचना pkcs11_slotinfo	*si;
	संरचना sshkey		*k = रिक्त;
	पूर्णाङ्क			 reset_pin = 0, reset_provider = 0;
	CK_ULONG		 nattrs;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_ATTRIBUTE		 attrs[16];
	CK_OBJECT_CLASS		 साँचो_class;
	CK_साँचो_TYPE		 साँचो_type;
	CK_OBJECT_HANDLE	 obj = CK_INVALID_HANDLE;
	CK_RV			 rv;

	*err = 0;

	यदि ((p = pkcs11_provider_lookup(provider_id)) != रिक्त) {
		debug_f("using provider \"%s\"", provider_id);
	} अन्यथा यदि (pkcs11_register_provider(provider_id, pin, रिक्त, रिक्त, &p,
	    CKU_SO) < 0) {
		debug_f("could not register provider %s",
		    provider_id);
		गच्छ out;
	} अन्यथा
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	यदि ((rv = f->C_SetOperationState(session , pin, म_माप(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} अन्यथा
		reset_pin = 1;

	/* private key */
	nattrs = 0;
	साँचो_class = CKO_PRIVATE_साँचो;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &साँचो_class, परिमाण(साँचो_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, परिमाण(keyid));

	यदि (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {
		यदि ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy private key 0x%hhx",
			    keyid);
			*err = rv;
			गच्छ out;
		}
	}

	/* public key */
	nattrs = 0;
	साँचो_class = CKO_PUBLIC_साँचो;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &साँचो_class, परिमाण(साँचो_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, परिमाण(keyid));

	यदि (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {

		/* get key type */
		nattrs = 0;
		FILL_ATTR(attrs, nattrs, CKA_साँचो_TYPE, &साँचो_type,
		    परिमाण(साँचो_type));
		rv = f->C_Get_Attribute_मान(session, obj, attrs, nattrs);
		यदि (rv != CKR_OK) {
			debug_f("could not get key type of public key 0x%hhx",
			    keyid);
			*err = rv;
			साँचो_type = -1;
		}
		विकल्प (साँचो_type) {
#ifdef WITH_OPENSSL
		पक्ष CKK_RSA:
			k = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			रोक;
		पक्ष CKK_ECDSA:
			k = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			रोक;
#endif /* WITH_OPENSSL */
		पक्ष CKK_EC_EDWARDS:
			k = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			रोक;
		स्वभाव:
			debug_f("unsupported key type %lu", (u_long)साँचो_type);
			रोक;
		}

		यदि ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy public key 0x%hhx", keyid);
			*err = rv;
			गच्छ out;
		}
	}

out:
	यदि (reset_pin)
		f->C_SetOperationState(session , रिक्त, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	यदि (reset_provider)
		pkcs11_del_provider(provider_id);

	फर्काऊ (k);
}
#endif /* WITH_PKCS11_KEYGEN */
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
	फर्काऊ (-1);
}

पूर्णाङ्क
pkcs11_add_provider(वर्ण *provider_id, वर्ण *pin, संरचना sshkey ***keyp,
    वर्ण ***labelsp)
{
	error_f("PKCS#11 not supported");
	फर्काऊ (-1);
}

शून्य
pkcs11_साँचो_free(संरचना sshkey *साँचो)
{
	error_f("PKCS#11 not supported");
}

पूर्णाङ्क
pkcs11_sign(संरचना sshkey *साँचो,
    u_char **sigp, माप_प्रकार *lenp,
    अचर u_char *data, माप_प्रकार datalen,
    अचर वर्ण *alg, अचर वर्ण *sk_provider,
    अचर वर्ण *sk_pin, u_int compat)
{
	error_f("PKCS#11 not supported");
	फर्काऊ SSH_ERR_FEATURE_UNSUPPORTED;
}

शून्य
pkcs11_terminate(शून्य)
{
	error_f("PKCS#11 not supported");
}
#endif /* ENABLE_PKCS11 */
