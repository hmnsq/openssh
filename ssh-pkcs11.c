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

#समावेश "includes.h"

#अगर_घोषित ENABLE_PKCS11

#समावेश <sys/time.h>

#समावेश <sys/types.h>
#समावेश <sys/queue.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>

#समावेश <string.h>
#समावेश <dlfcn.h>

#अगर_घोषित WITH_OPENSSL
#समावेश "openbsd-compat/openssl-compat.h"
#समावेश <openssl/bn.h>
#समावेश <openssl/ecdsa.h>
#समावेश <openssl/x509.h>
#समावेश <openssl/err.h>
#पूर्ण_अगर

#घोषणा CRYPTOKI_COMPAT
#समावेश "pkcs11.h"

#घोषणा SSHKEY_INTERNAL
#समावेश "sshkey.h"

#समावेश "log.h"
#समावेश "misc.h"
#समावेश "sshbuf.h"
#समावेश "ssh-pkcs11.h"
#समावेश "digest.h"
#समावेश "xmalloc.h"
#समावेश "crypto_api.h"

काष्ठा pkcs11_slotinfo {
	CK_TOKEN_INFO		token;
	CK_SESSION_HANDLE	session;
	पूर्णांक			logged_in;
};

काष्ठा pkcs11_provider {
	अक्षर			*name;
	व्योम			*handle;
	CK_FUNCTION_LIST	*function_list;
	CK_INFO			info;
	CK_ULONG		nslots;
	CK_SLOT_ID		*slotlist;
	काष्ठा pkcs11_slotinfo	*slotinfo;
	पूर्णांक			valid;
	पूर्णांक			refcount;
	TAILQ_ENTRY(pkcs11_provider) अग्र;
};

TAILQ_HEAD(, pkcs11_provider) pkcs11_providers;

काष्ठा pkcs11_कुंजी {
	काष्ठा sshbuf		*keyblob;
	काष्ठा pkcs11_provider	*provider;
	CK_ULONG		slotidx;
	अक्षर			*keyid;
	पूर्णांक			keyid_len;
	TAILQ_ENTRY(pkcs11_कुंजी)	अग्र;
};

TAILQ_HEAD(, pkcs11_कुंजी) pkcs11_कुंजियाँ; /* XXX a tree would be better */

पूर्णांक pkcs11_interactive = 0;

#अगर_घोषित WITH_OPENSSL
अटल व्योम
ossl_error(स्थिर अक्षर *संदेश)
{
	अचिन्हित दीर्घ    e;

	error_f("%s", संदेश);
	जबतक ((e = ERR_get_error()) != 0)
		error_f("libcrypto error: %s", ERR_error_string(e, शून्य));
}
#पूर्ण_अगर

/*
 * finalize a provider shared library, it's no longer usable.
 * however, there might still be keys referencing this provider,
 * so the actual freeing of memory is handled by pkcs11_provider_unref().
 * this is called when a provider gets unregistered.
 */
अटल व्योम
pkcs11_provider_finalize(काष्ठा pkcs11_provider *p)
{
	CK_RV rv;
	CK_ULONG i;

	debug_f("provider \"%s\" refcount %d valid %d",
	    p->name, p->refcount, p->valid);
	अगर (!p->valid)
		वापस;
	क्रम (i = 0; i < p->nslots; i++) {
		अगर (p->slotinfo[i].session &&
		    (rv = p->function_list->C_CloseSession(
		    p->slotinfo[i].session)) != CKR_OK)
			error("C_CloseSession failed: %lu", rv);
	}
	अगर ((rv = p->function_list->C_Finalize(शून्य)) != CKR_OK)
		error("C_Finalize failed: %lu", rv);
	p->valid = 0;
	p->function_list = शून्य;
	dlclose(p->handle);
}

/*
 * remove a reference to the provider.
 * called when a key gets destroyed or when the provider is unregistered.
 */
अटल व्योम
pkcs11_provider_unref(काष्ठा pkcs11_provider *p)
{
	debug_f("provider \"%s\" refcount %d", p->name, p->refcount);
	अगर (--p->refcount <= 0) {
		अगर (p->valid)
			error_f("provider \"%s\" still valid", p->name);
		मुक्त(p->name);
		मुक्त(p->slotlist);
		मुक्त(p->slotinfo);
		मुक्त(p);
	}
}

/* lookup provider by name */
अटल काष्ठा pkcs11_provider *
pkcs11_provider_lookup(अक्षर *provider_id)
{
	काष्ठा pkcs11_provider *p;

	TAILQ_FOREACH(p, &pkcs11_providers, अग्र) {
		debug("check provider \"%s\"", p->name);
		अगर (!म_भेद(provider_id, p->name))
			वापस (p);
	}
	वापस (शून्य);
}

/* unregister provider by name */
पूर्णांक
pkcs11_del_provider(अक्षर *provider_id)
{
	काष्ठा pkcs11_provider *p;

	अगर ((p = pkcs11_provider_lookup(provider_id)) != शून्य) {
		TAILQ_REMOVE(&pkcs11_providers, p, अग्र);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
		वापस (0);
	}
	वापस (-1);
}

/* release a wrapped object */
अटल व्योम
pkcs11_k11_free(काष्ठा pkcs11_कुंजी *k11)
{
	अगर (k11 == शून्य)
		वापस;
	अगर (k11->provider)
		pkcs11_provider_unref(k11->provider);
	मुक्त(k11->keyid);
	sshbuf_free(k11->keyblob);
	मुक्त(k11);
}

/* find a single 'obj' for given attributes */
अटल पूर्णांक
pkcs11_find(काष्ठा pkcs11_provider *p, CK_ULONG slotidx, CK_ATTRIBUTE *attr,
    CK_ULONG nattr, CK_OBJECT_HANDLE *obj)
{
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	session;
	CK_ULONG		nfound = 0;
	CK_RV			rv;
	पूर्णांक			ret = -1;

	f = p->function_list;
	session = p->slotinfo[slotidx].session;
	अगर ((rv = f->C_FindObjectsInit(session, attr, nattr)) != CKR_OK) {
		error("C_FindObjectsInit failed (nattr %lu): %lu", nattr, rv);
		वापस (-1);
	}
	अगर ((rv = f->C_FindObjects(session, obj, 1, &nfound)) != CKR_OK ||
	    nfound != 1) {
		debug("C_FindObjects failed (nfound %lu nattr %lu): %lu",
		    nfound, nattr, rv);
	} अन्यथा
		ret = 0;
	अगर ((rv = f->C_FindObjectsFinal(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	वापस (ret);
}

अटल पूर्णांक
pkcs11_login_slot(काष्ठा pkcs11_provider *provider, काष्ठा pkcs11_slotinfo *si,
    CK_USER_TYPE type)
{
	अक्षर			*pin = शून्य, prompt[1024];
	CK_RV			 rv;

	अगर (provider == शून्य || si == शून्य || !provider->valid) {
		error("no pkcs11 (valid) provider found");
		वापस (-1);
	}

	अगर (!pkcs11_interactive) {
		error("need pin entry%s",
		    (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH) ?
		    " on reader keypad" : "");
		वापस (-1);
	}
	अगर (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
		verbose("Deferring PIN entry to reader keypad.");
	अन्यथा {
		snprintf(prompt, माप(prompt), "Enter PIN for '%s': ",
		    si->token.label);
		अगर ((pin = read_passphrase(prompt, RP_ALLOW_EOF)) == शून्य) {
			debug_f("no pin specified");
			वापस (-1);	/* bail out */
		}
	}
	rv = provider->function_list->C_Login(si->session, type, (u_char *)pin,
	    (pin != शून्य) ? म_माप(pin) : 0);
	अगर (pin != शून्य)
		freezero(pin, म_माप(pin));

	चयन (rv) {
	हाल CKR_OK:
	हाल CKR_USER_ALREADY_LOGGED_IN:
		/* success */
		अवरोध;
	हाल CKR_PIN_LEN_RANGE:
		error("PKCS#11 login failed: PIN length out of range");
		वापस -1;
	हाल CKR_PIN_INCORRECT:
		error("PKCS#11 login failed: PIN incorrect");
		वापस -1;
	हाल CKR_PIN_LOCKED:
		error("PKCS#11 login failed: PIN locked");
		वापस -1;
	शेष:
		error("PKCS#11 login failed: error %lu", rv);
		वापस -1;
	}
	si->logged_in = 1;
	वापस (0);
}

अटल पूर्णांक
pkcs11_login(काष्ठा pkcs11_कुंजी *k11, CK_USER_TYPE type)
{
	अगर (k11 == शून्य || k11->provider == शून्य || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		वापस (-1);
	}

	वापस pkcs11_login_slot(k11->provider,
	    &k11->provider->slotinfo[k11->slotidx], type);
}


अटल पूर्णांक
pkcs11_check_obj_bool_attrib(काष्ठा pkcs11_कुंजी *k11, CK_OBJECT_HANDLE obj,
    CK_ATTRIBUTE_TYPE type, पूर्णांक *val)
{
	काष्ठा pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_BBOOL		flag = 0;
	CK_ATTRIBUTE		attr;
	CK_RV			 rv;

	*val = 0;

	अगर (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		वापस (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	attr.type = type;
	attr.p_मूल्य = &flag;
	attr.ul_मूल्य_Len = माप(flag);

	rv = f->C_Get_Attribute_मूल्य(si->session, obj, &attr, 1);
	अगर (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		वापस (-1);
	}
	*val = flag != 0;
	debug_f("provider \"%s\" slot %lu object %lu: attrib %lu = %d",
	    k11->provider->name, k11->slotidx, obj, type, *val);
	वापस (0);
}

अटल पूर्णांक
pkcs11_get_कुंजी(काष्ठा pkcs11_कुंजी *k11, CK_MECHANISM_TYPE mech_type)
{
	काष्ठा pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	 obj;
	CK_RV			 rv;
	CK_OBJECT_CLASS		 private_कुंजी_class;
	CK_BBOOL		 true_val;
	CK_MECHANISM		 mech;
	CK_ATTRIBUTE		 कुंजी_filter[3];
	पूर्णांक			 always_auth = 0;
	पूर्णांक			 did_login = 0;

	अगर (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		वापस (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	अगर ((si->token.flags & CKF_LOGIN_REQUIRED) && !si->logged_in) {
		अगर (pkcs11_login(k11, CKU_USER) < 0) {
			error("login failed");
			वापस (-1);
		}
		did_login = 1;
	}

	स_रखो(&कुंजी_filter, 0, माप(कुंजी_filter));
	private_कुंजी_class = CKO_PRIVATE_कुंजी;
	कुंजी_filter[0].type = CKA_CLASS;
	कुंजी_filter[0].p_मूल्य = &private_कुंजी_class;
	कुंजी_filter[0].ul_मूल्य_Len = माप(private_कुंजी_class);

	कुंजी_filter[1].type = CKA_ID;
	कुंजी_filter[1].p_मूल्य = k11->keyid;
	कुंजी_filter[1].ul_मूल्य_Len = k11->keyid_len;

	true_val = CK_TRUE;
	कुंजी_filter[2].type = CKA_SIGN;
	कुंजी_filter[2].p_मूल्य = &true_val;
	कुंजी_filter[2].ul_मूल्य_Len = माप(true_val);

	/* try to find object w/CKA_SIGN first, retry w/o */
	अगर (pkcs11_find(k11->provider, k11->slotidx, कुंजी_filter, 3, &obj) < 0 &&
	    pkcs11_find(k11->provider, k11->slotidx, कुंजी_filter, 2, &obj) < 0) {
		error("cannot find private key");
		वापस (-1);
	}

	स_रखो(&mech, 0, माप(mech));
	mech.mechanism = mech_type;
	mech.pParameter = NULL_PTR;
	mech.ulParameterLen = 0;

	अगर ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
		वापस (-1);
	}

	pkcs11_check_obj_bool_attrib(k11, obj, CKA_ALWAYS_AUTHENTICATE,
	    &always_auth); /* ignore errors here */
	अगर (always_auth && !did_login) {
		debug_f("always-auth key");
		अगर (pkcs11_login(k11, CKU_CONTEXT_SPECIFIC) < 0) {
			error("login failed for always-auth key");
			वापस (-1);
		}
	}

	वापस (0);
}

/* record the key information later use lookup by keyblob */
अटल पूर्णांक
pkcs11_record_कुंजी(काष्ठा pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, काष्ठा sshkey *कुंजी)
{
	काष्ठा sshbuf *keyblob;
	काष्ठा pkcs11_कुंजी *k11;
	पूर्णांक r;
	अक्षर *hex;

	hex = tohex(keyid_attrib->p_मूल्य, keyid_attrib->ul_मूल्य_Len);
	debug_f("%s key: provider %s slot %lu keyid %s",
	    sshkey_type(कुंजी), provider->name, (u_long)slotidx, hex);
	मुक्त(hex);

	अगर ((keyblob = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshkey_putb(कुंजी, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");

	/* Check if we've already recorded this key in a different slot */
	TAILQ_FOREACH(k11, &pkcs11_कुंजियाँ, अग्र) {
		अगर (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			hex = tohex(k11->keyid, k11->keyid_len);
			debug_f("Already seen this key at "
			    "provider %s slot %lu keyid %s",
			    k11->provider->name, k11->slotidx, hex);
			मुक्त(hex);
			sshbuf_free(keyblob);
			वापस -1;
		}
	}

	k11 = xcalloc(1, माप(*k11));
	k11->provider = provider;
	k11->keyblob = keyblob;
	provider->refcount++;	/* provider referenced by RSA key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ul_मूल्य_Len;
	अगर (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len);
		स_नकल(k11->keyid, keyid_attrib->p_मूल्य, k11->keyid_len);
	}
	TAILQ_INSERT_TAIL(&pkcs11_कुंजियाँ, k11, अग्र);

	वापस 0;
}

/* retrieve the key information by keyblob */
अटल काष्ठा pkcs11_कुंजी *
pkcs11_lookup_कुंजी(काष्ठा sshkey *कुंजी)
{
	काष्ठा pkcs11_कुंजी *k11, *found = शून्य;
	काष्ठा sshbuf *keyblob;
	पूर्णांक r;

	अगर ((keyblob = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर ((r = sshkey_putb(कुंजी, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");
	TAILQ_FOREACH(k11, &pkcs11_कुंजियाँ, अग्र) {
		अगर (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			found = k11;
			अवरोध;
		}
	}
	sshbuf_free(keyblob);
	वापस found;
}

#अगर_घोषित WITH_OPENSSL
/*
 * See:
 * https://datatracker.ietf.org/doc/html/rfc8017#section-9.2
 */

/*
 * id-sha1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
 *	oiw(14) secsig(3) algorithms(2) 26 }
 */
अटल स्थिर u_char id_sha1[] = {
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
अटल स्थिर u_char id_sha256[] = {
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
अटल स्थिर u_char id_sha512[] = {
	0x30, 0x51, /* type Sequence, length 0x51 (81) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, /* id-sha512 */
	0x05, 0x00, /* NULL */
	0x04, 0x40  /* Octet string, length 0x40 (64), followed by sha512 hash */
};

अटल पूर्णांक
rsa_hash_alg_oid(पूर्णांक hash_alg, स्थिर u_char **oidp, माप_प्रकार *oidlenp)
{
	चयन (hash_alg) {
	हाल SSH_DIGEST_SHA1:
		*oidp = id_sha1;
		*oidlenp = माप(id_sha1);
		अवरोध;
	हाल SSH_DIGEST_SHA256:
		*oidp = id_sha256;
		*oidlenp = माप(id_sha256);
		अवरोध;
	हाल SSH_DIGEST_SHA512:
		*oidp = id_sha512;
		*oidlenp = माप(id_sha512);
		अवरोध;
	शेष:
		वापस SSH_ERR_INVALID_ARGUMENT;
	}
	वापस 0;
}

अटल पूर्णांक
pkcs11_sign_rsa(काष्ठा sshkey *कुंजी,
    u_char **sigp, माप_प्रकार *lenp,
    स्थिर u_char *तथ्य, माप_प्रकार datalen,
    स्थिर अक्षर *alg, स्थिर अक्षर *sk_provider,
    स्थिर अक्षर *sk_pin, u_int compat)
{
	काष्ठा pkcs11_कुंजी	*k11;
	काष्ठा pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	पूर्णांक			hashalg, r, diff, siglen, ret = -1;
	u_char			*oid_dgst = शून्य, *sig = शून्य;
	माप_प्रकार			dgst_len, oid_len, oid_dgst_len = 0;
	स्थिर u_char		*oid;

	अगर (sigp != शून्य)
		*sigp = शून्य;
	अगर (lenp != शून्य)
		*lenp = 0;

	अगर ((k11 = pkcs11_lookup_कुंजी(कुंजी)) == शून्य) {
		error_f("no key found");
		वापस SSH_ERR_कुंजी_NOT_FOUND;
	}

	debug3_f("sign with alg \"%s\" using provider %s slotidx %lu",
	    alg == शून्य ? "" : alg, k11->provider->name, (u_long)k11->slotidx);

	अगर (pkcs11_get_कुंजी(k11, CKM_RSA_PKCS) == -1) {
		error("pkcs11_get_key failed");
		वापस SSH_ERR_AGENT_FAILURE;
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	अगर ((siglen = EVP_PKEY_आकार(कुंजी->pkey)) <= 0)
		वापस SSH_ERR_INVALID_ARGUMENT;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* Determine hash algorithm and OID for signature */
	अगर (alg == शून्य || *alg == '\0')
		hashalg = SSH_DIGEST_SHA1;
	अन्यथा अगर ((hashalg = ssh_rsa_hash_id_from_keyname(alg)) == -1)
		fatal_f("couldn't determine RSA hash alg \"%s\"", alg);
	अगर ((r = rsa_hash_alg_oid(hashalg, &oid, &oid_len)) != 0)
		fatal_fr(r, "rsa_hash_alg_oid failed");
	अगर ((dgst_len = ssh_digest_bytes(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);

	/* Prepare { oid || digest } */
	oid_dgst_len = oid_len + dgst_len;
	oid_dgst = xcalloc(1, oid_dgst_len);
	स_नकल(oid_dgst, oid, oid_len);
	अगर ((r = ssh_digest_memory(hashalg, तथ्य, datalen,
	    oid_dgst + oid_len, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	अगर ((rv = f->C_Sign(si->session, (CK_BYTE *)oid_dgst,
	    oid_dgst_len, sig, &slen)) != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		जाओ done;
	}

	अगर (slen < (CK_ULONG)siglen) {
		diff = siglen - slen;
		debug3_f("repack %lu < %d (diff %d)",
		    (u_long)slen, siglen, diff);
		स_हटाओ(sig + diff, sig, slen);
		explicit_bzero(sig, diff);
	} अन्यथा अगर (slen > (माप_प्रकार)siglen)
		fatal_f("bad C_Sign length");

	अगर ((ret = ssh_rsa_encode_store_sig(hashalg, sig, siglen,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	freezero(oid_dgst, oid_dgst_len);
	मुक्त(sig);
	वापस ret;
}

अटल पूर्णांक
pkcs11_sign_ecdsa(काष्ठा sshkey *कुंजी,
    u_char **sigp, माप_प्रकार *lenp,
    स्थिर u_char *तथ्य, माप_प्रकार datalen,
    स्थिर अक्षर *alg, स्थिर अक्षर *sk_provider,
    स्थिर अक्षर *sk_pin, u_int compat)
{
	काष्ठा pkcs11_कुंजी	*k11;
	काष्ठा pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0, bnlen;
	CK_RV			rv;
	BIGNUM			*sig_r = शून्य, *sig_s = शून्य;
	u_char			*sig = शून्य, *dgst = शून्य;
	माप_प्रकार			dgst_len = 0;
	पूर्णांक			hashalg, ret = -1, r, siglen;

	अगर (sigp != शून्य)
		*sigp = शून्य;
	अगर (lenp != शून्य)
		*lenp = 0;

	अगर ((k11 = pkcs11_lookup_कुंजी(कुंजी)) == शून्य) {
		error_f("no key found");
		वापस SSH_ERR_कुंजी_NOT_FOUND;
	}

	अगर (pkcs11_get_कुंजी(k11, CKM_ECDSA) == -1) {
		error("pkcs11_get_key failed");
		वापस SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	/* Prepare digest to be signed */
	अगर ((hashalg = sshkey_ec_nid_to_hash_alg(कुंजी->ecdsa_nid)) == -1)
		fatal_f("couldn't determine ECDSA hash alg");
	अगर ((dgst_len = ssh_digest_bytes(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);
	dgst = xcalloc(1, dgst_len);
	अगर ((r = ssh_digest_memory(hashalg, तथ्य, datalen,
	    dgst, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	अगर ((siglen = EVP_PKEY_आकार(कुंजी->pkey)) <= 0)
		वापस SSH_ERR_INVALID_ARGUMENT;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dgst_len, sig, &slen);
	अगर (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		जाओ done;
	}
	अगर (slen < 64 || slen > 132 || slen % 2) {
		error_f("bad signature length: %lu", (u_long)slen);
		जाओ done;
	}
	bnlen = slen/2;
	अगर ((sig_r = BN_bin2bn(sig, bnlen, शून्य)) == शून्य ||
	    (sig_s = BN_bin2bn(sig+bnlen, bnlen, शून्य)) == शून्य) {
		ossl_error("BN_bin2bn failed");
		जाओ done;
	}

	अगर ((ret = ssh_ecdsa_encode_store_sig(कुंजी, sig_r, sig_s,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	freezero(dgst, dgst_len);
	BN_free(sig_r);
	BN_free(sig_s);
	मुक्त(sig);
	वापस ret;
}
#पूर्ण_अगर /* WITH_OPENSSL */

अटल पूर्णांक
pkcs11_sign_ed25519(काष्ठा sshkey *कुंजी,
    u_char **sigp, माप_प्रकार *lenp,
    स्थिर u_char *तथ्य, माप_प्रकार datalen,
    स्थिर अक्षर *alg, स्थिर अक्षर *sk_provider,
    स्थिर अक्षर *sk_pin, u_int compat)
{
	काष्ठा pkcs11_कुंजी	*k11;
	काष्ठा pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	u_char			*sig = शून्य;
	CK_BYTE			*xdata = शून्य;
	पूर्णांक			ret = -1;

	अगर (sigp != शून्य)
		*sigp = शून्य;
	अगर (lenp != शून्य)
		*lenp = 0;

	अगर ((k11 = pkcs11_lookup_कुंजी(कुंजी)) == शून्य) {
		error_f("no key found");
		वापस SSH_ERR_कुंजी_NOT_FOUND;
	}

	अगर (pkcs11_get_कुंजी(k11, CKM_EDDSA) == -1) {
		error("pkcs11_get_key failed");
		वापस SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	xdata = xmalloc(datalen);
	स_नकल(xdata, तथ्य, datalen);
	sig = xmalloc(crypto_sign_ed25519_BYTES);
	slen = crypto_sign_ed25519_BYTES;

	rv = f->C_Sign(si->session, xdata, datalen, sig, &slen);
	अगर (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		जाओ done;
	}
	अगर (slen != crypto_sign_ed25519_BYTES) {
		error_f("bad signature length: %lu", (u_long)slen);
		जाओ done;
	}
	अगर ((ret = ssh_ed25519_encode_store_sig(sig, slen, sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	अगर (xdata != शून्य)
		freezero(xdata, datalen);
	मुक्त(sig);
	वापस ret;
}

/* remove trailing spaces */
अटल अक्षर *
rmspace(u_char *buf, माप_प्रकार len)
{
	माप_प्रकार i;

	अगर (len == 0)
		वापस buf;
	क्रम (i = len - 1; i > 0; i--)
		अगर (buf[i] == ' ')
			buf[i] = '\0';
		अन्यथा
			अवरोध;
	वापस buf;
}
/* Used to printf fixed-width, space-padded, unterminated strings using %.*s */
#घोषणा RMSPACE(s) (पूर्णांक)माप(s), rmspace(s, माप(s))

/*
 * open a pkcs11 session and login if required.
 * if pin == NULL we delay login until key use
 */
अटल पूर्णांक
pkcs11_open_session(काष्ठा pkcs11_provider *p, CK_ULONG slotidx, अक्षर *pin,
    CK_ULONG user)
{
	काष्ठा pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_RV			rv;
	CK_SESSION_HANDLE	session;
	पूर्णांक			login_required, ret;

	f = p->function_list;
	si = &p->slotinfo[slotidx];

	login_required = si->token.flags & CKF_LOGIN_REQUIRED;

	/* fail early before opening session */
	अगर (login_required && !pkcs11_interactive &&
	    (pin == शून्य || म_माप(pin) == 0)) {
		error("pin required");
		वापस (-SSH_PKCS11_ERR_PIN_REQUIRED);
	}
	अगर ((rv = f->C_OpenSession(p->slotlist[slotidx], CKF_RW_SESSION|
	    CKF_SERIAL_SESSION, शून्य, शून्य, &session)) != CKR_OK) {
		error("C_OpenSession failed: %lu", rv);
		वापस (-1);
	}
	अगर (login_required && pin != शून्य && म_माप(pin) != 0) {
		rv = f->C_Login(session, user, (u_char *)pin, म_माप(pin));
		अगर (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
			error("C_Login failed: %lu", rv);
			ret = (rv == CKR_PIN_LOCKED) ?
			    -SSH_PKCS11_ERR_PIN_LOCKED :
			    -SSH_PKCS11_ERR_LOGIN_FAIL;
			अगर ((rv = f->C_CloseSession(session)) != CKR_OK)
				error("C_CloseSession failed: %lu", rv);
			वापस (ret);
		}
		si->logged_in = 1;
	}
	si->session = session;
	वापस (0);
}

अटल पूर्णांक
pkcs11_कुंजी_included(काष्ठा sshkey ***keysp, पूर्णांक *nkeys, काष्ठा sshkey *कुंजी)
{
	पूर्णांक i;

	क्रम (i = 0; i < *nkeys; i++)
		अगर (sshkey_equal(कुंजी, (*keysp)[i]))
			वापस (1);
	वापस (0);
}

#अगर_घोषित WITH_OPENSSL
अटल काष्ठा sshkey *
pkcs11_fetch_ecdsa_pubkey(काष्ठा pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 कुंजी_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = शून्य;
	CK_RV			 rv;
	ASN1_OCTET_STRING	*octet = शून्य;
	EC_कुंजी			*ec = शून्य;
	EC_GROUP		*group = शून्य;
	काष्ठा sshkey		*कुंजी = शून्य;
	स्थिर अचिन्हित अक्षर	*attrp = शून्य;
	पूर्णांक			 success = -1, r, i, nid;

	स_रखो(&कुंजी_attr, 0, माप(कुंजी_attr));
	कुंजी_attr[0].type = CKA_ID;
	कुंजी_attr[1].type = CKA_EC_POINT;
	कुंजी_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_मूल्य(session, *obj, कुंजी_attr, 3);
	अगर (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		वापस (शून्य);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	अगर (कुंजी_attr[1].ul_मूल्य_Len == 0 ||
	    कुंजी_attr[2].ul_मूल्य_Len == 0) {
		error("invalid attribute length");
		वापस (शून्य);
	}

	/* allocate buffers for attributes */
	क्रम (i = 0; i < 3; i++)
		अगर (कुंजी_attr[i].ul_मूल्य_Len > 0)
			कुंजी_attr[i].p_मूल्य = xcalloc(1, कुंजी_attr[i].ul_मूल्य_Len);

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_मूल्य(session, *obj, कुंजी_attr, 3);
	अगर (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		जाओ fail;
	}

	ec = EC_कुंजी_new();
	अगर (ec == शून्य) {
		error("EC_KEY_new failed");
		जाओ fail;
	}

	attrp = कुंजी_attr[2].p_मूल्य;
	group = d2i_ECPKParameters(शून्य, &attrp, कुंजी_attr[2].ul_मूल्य_Len);
	अगर (group == शून्य) {
		ossl_error("d2i_ECPKParameters failed");
		जाओ fail;
	}

	अगर (EC_कुंजी_set_group(ec, group) == 0) {
		ossl_error("EC_KEY_set_group failed");
		जाओ fail;
	}

	अगर (कुंजी_attr[1].ul_मूल्य_Len <= 2) {
		error("CKA_EC_POINT too small");
		जाओ fail;
	}

	attrp = कुंजी_attr[1].p_मूल्य;
	octet = d2i_ASN1_OCTET_STRING(शून्य, &attrp, कुंजी_attr[1].ul_मूल्य_Len);
	अगर (octet == शून्य) {
		ossl_error("d2i_ASN1_OCTET_STRING failed");
		जाओ fail;
	}
	attrp = ASN1_STRING_get0_तथ्य(octet);
	अगर (o2i_ECPublic_कुंजी(&ec, &attrp, ASN1_STRING_लंबाई(octet)) == शून्य) {
		ossl_error("o2i_ECPublicKey failed");
		जाओ fail;
	}
	अगर ((r = sshkey_ec_validate_public(EC_कुंजी_get0_group(ec),
	    EC_कुंजी_get0_public_कुंजी(ec))) != 0) {
		error_fr(r, "invalid EC key");
		जाओ fail;
	}

	nid = sshkey_ecdsa_कुंजी_to_nid(ec);
	अगर (nid < 0) {
		error("couldn't get curve nid");
		जाओ fail;
	}

	कुंजी = sshkey_new(कुंजी_UNSPEC);
	अगर (कुंजी == शून्य) {
		error("sshkey_new failed");
		जाओ fail;
	}

	EVP_PKEY_free(कुंजी->pkey);
	अगर ((कुंजी->pkey = EVP_PKEY_new()) == शून्य)
		fatal("EVP_PKEY_new failed");
	अगर (EVP_PKEY_set1_EC_कुंजी(कुंजी->pkey, ec) != 1)
		fatal("EVP_PKEY_set1_EC_KEY failed");
	कुंजी->ecdsa_nid = nid;
	कुंजी->type = कुंजी_ECDSA;
	कुंजी->flags |= SSHKEY_FLAG_EXT;
	अगर (pkcs11_record_कुंजी(p, slotidx, &कुंजी_attr[0], कुंजी))
		जाओ fail;
	/* success */
	success = 0;
fail:
	अगर (success != 0) {
		sshkey_free(कुंजी);
		कुंजी = शून्य;
	}
	क्रम (i = 0; i < 3; i++)
		मुक्त(कुंजी_attr[i].p_मूल्य);
	अगर (ec)
		EC_कुंजी_free(ec);
	अगर (group)
		EC_GROUP_free(group);
	अगर (octet)
		ASN1_OCTET_STRING_free(octet);

	वापस (कुंजी);
}

अटल काष्ठा sshkey *
pkcs11_fetch_rsa_pubkey(काष्ठा pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 कुंजी_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = शून्य;
	CK_RV			 rv;
	RSA			*rsa = शून्य;
	BIGNUM			*rsa_n, *rsa_e;
	काष्ठा sshkey		*कुंजी = शून्य;
	पूर्णांक			 i, success = -1;

	स_रखो(&कुंजी_attr, 0, माप(कुंजी_attr));
	कुंजी_attr[0].type = CKA_ID;
	कुंजी_attr[1].type = CKA_MODULUS;
	कुंजी_attr[2].type = CKA_PUBLIC_EXPONENT;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_मूल्य(session, *obj, कुंजी_attr, 3);
	अगर (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		वापस (शून्य);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	अगर (कुंजी_attr[1].ul_मूल्य_Len == 0 ||
	    कुंजी_attr[2].ul_मूल्य_Len == 0) {
		error("invalid attribute length");
		वापस (शून्य);
	}

	/* allocate buffers for attributes */
	क्रम (i = 0; i < 3; i++)
		अगर (कुंजी_attr[i].ul_मूल्य_Len > 0)
			कुंजी_attr[i].p_मूल्य = xcalloc(1, कुंजी_attr[i].ul_मूल्य_Len);

	/* retrieve ID, modulus and public exponent of RSA key */
	rv = f->C_Get_Attribute_मूल्य(session, *obj, कुंजी_attr, 3);
	अगर (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		जाओ fail;
	}

	rsa = RSA_new();
	अगर (rsa == शून्य) {
		error("RSA_new failed");
		जाओ fail;
	}

	rsa_n = BN_bin2bn(कुंजी_attr[1].p_मूल्य, कुंजी_attr[1].ul_मूल्य_Len, शून्य);
	rsa_e = BN_bin2bn(कुंजी_attr[2].p_मूल्य, कुंजी_attr[2].ul_मूल्य_Len, शून्य);
	अगर (rsa_n == शून्य || rsa_e == शून्य) {
		error("BN_bin2bn failed");
		जाओ fail;
	}
	अगर (!RSA_set0_कुंजी(rsa, rsa_n, rsa_e, शून्य))
		fatal_f("set key");
	rsa_n = rsa_e = शून्य; /* transferred */

	कुंजी = sshkey_new(कुंजी_UNSPEC);
	अगर (कुंजी == शून्य) {
		error("sshkey_new failed");
		जाओ fail;
	}

	EVP_PKEY_free(कुंजी->pkey);
	अगर ((कुंजी->pkey = EVP_PKEY_new()) == शून्य)
		fatal("EVP_PKEY_new failed");
	अगर (EVP_PKEY_set1_RSA(कुंजी->pkey, rsa) != 1)
		fatal("EVP_PKEY_set1_RSA failed");
	कुंजी->type = कुंजी_RSA;
	कुंजी->flags |= SSHKEY_FLAG_EXT;
	अगर (EVP_PKEY_bits(कुंजी->pkey) < SSH_RSA_MINIMUM_MODULUS_आकार) {
		error_f("RSA key too small %d < minimum %d",
		    EVP_PKEY_bits(कुंजी->pkey), SSH_RSA_MINIMUM_MODULUS_आकार);
		जाओ fail;
	}
	अगर (pkcs11_record_कुंजी(p, slotidx, &कुंजी_attr[0], कुंजी))
		जाओ fail;
	/* success */
	success = 0;
fail:
	क्रम (i = 0; i < 3; i++)
		मुक्त(कुंजी_attr[i].p_मूल्य);
	RSA_free(rsa);
	अगर (success != 0) {
		sshkey_free(कुंजी);
		कुंजी = शून्य;
	}
	वापस कुंजी;
}
#पूर्ण_अगर /* WITH_OPENSSL */

अटल काष्ठा sshkey *
pkcs11_fetch_ed25519_pubkey(काष्ठा pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 कुंजी_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = शून्य;
	CK_RV			 rv;
	काष्ठा sshkey		*कुंजी = शून्य;
	स्थिर अचिन्हित अक्षर	*d = शून्य;
	माप_प्रकार			len;
	अक्षर			*hex = शून्य;
	पूर्णांक			 success = -1, i;
	/* https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061180 */
	स्थिर u_char		 id1[14] = {
		0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64,
		0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
	}; /* PrintableString { "edwards25519" } */
	स्थिर u_char		 id2[5] = {
		0x06, 0x03, 0x2b, 0x65, 0x70,
	}; /* OBJECT_IDENTIFIER { 1.3.101.112 } */

	स_रखो(&कुंजी_attr, 0, माप(कुंजी_attr));
	कुंजी_attr[0].type = CKA_ID;
	कुंजी_attr[1].type = CKA_EC_POINT; /* XXX or CKA_VALUE ? */
	कुंजी_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_मूल्य(session, *obj, कुंजी_attr, 3);
	अगर (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		वापस (शून्य);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	अगर (कुंजी_attr[1].ul_मूल्य_Len == 0 ||
	    कुंजी_attr[2].ul_मूल्य_Len == 0) {
		error("invalid attribute length");
		वापस (शून्य);
	}

	/* allocate buffers for attributes */
	क्रम (i = 0; i < 3; i++) {
		अगर (कुंजी_attr[i].ul_मूल्य_Len > 0)
			कुंजी_attr[i].p_मूल्य = xcalloc(1, कुंजी_attr[i].ul_मूल्य_Len);
	}

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_मूल्य(session, *obj, कुंजी_attr, 3);
	अगर (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		जाओ fail;
	}

	/* Expect one of the supported identifiers in CKA_EC_PARAMS */
	d = (u_char *)कुंजी_attr[2].p_मूल्य;
	len = कुंजी_attr[2].ul_मूल्य_Len;
	अगर ((len != माप(id1) || स_भेद(d, id1, माप(id1)) != 0) &&
	    (len != माप(id2) || स_भेद(d, id2, माप(id2)) != 0)) {
		hex = tohex(d, len);
		logit_f("unsupported CKA_EC_PARAMS: %s (len %zu)", hex, len);
		जाओ fail;
	}

	/*
	 * Expect either a raw 32 byte pubkey or an OCTET STRING with
	 * a 32 byte pubkey in CKA_VALUE
	 */
	d = (u_char *)कुंजी_attr[1].p_मूल्य;
	len = कुंजी_attr[1].ul_मूल्य_Len;
	अगर (len == ED25519_PK_SZ + 2 && d[0] == 0x04 && d[1] == ED25519_PK_SZ) {
		d += 2;
		len -= 2;
	}
	अगर (len != ED25519_PK_SZ) {
		hex = tohex(कुंजी_attr[1].p_मूल्य, कुंजी_attr[1].ul_मूल्य_Len);
		logit_f("CKA_EC_POINT invalid octet str: %s (len %lu)",
		    hex, (u_long)कुंजी_attr[1].ul_मूल्य_Len);
		जाओ fail;
	}

	अगर ((कुंजी = sshkey_new(कुंजी_UNSPEC)) == शून्य)
		fatal_f("sshkey_new failed");
	कुंजी->ed25519_pk = xmalloc(ED25519_PK_SZ);
	स_नकल(कुंजी->ed25519_pk, d, ED25519_PK_SZ);
	कुंजी->type = कुंजी_ED25519;
	कुंजी->flags |= SSHKEY_FLAG_EXT;
	अगर (pkcs11_record_कुंजी(p, slotidx, &कुंजी_attr[0], कुंजी))
		जाओ fail;
	/* success */
	success = 0;
 fail:
	अगर (success != 0) {
		sshkey_free(कुंजी);
		कुंजी = शून्य;
	}
	मुक्त(hex);
	क्रम (i = 0; i < 3; i++)
		मुक्त(कुंजी_attr[i].p_मूल्य);
	वापस कुंजी;
}

#अगर_घोषित WITH_OPENSSL
अटल पूर्णांक
pkcs11_fetch_x509_pubkey(काष्ठा pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj, काष्ठा sshkey **keyp, अक्षर **labelp)
{
	CK_ATTRIBUTE		 cert_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = शून्य;
	CK_RV			 rv;
	X509			*x509 = शून्य;
	X509_NAME		*x509_name = शून्य;
	EVP_PKEY		*evp;
	RSA			*rsa = शून्य;
	EC_कुंजी			*ec = शून्य;
	काष्ठा sshkey		*कुंजी = शून्य;
	पूर्णांक			 r, i, nid, success = -1;
	स्थिर u_char		*cp;
	अक्षर			*subject = शून्य;
#अगर_घोषित OPENSSL_HAS_ED25519
	माप_प्रकार			len;
#पूर्ण_अगर /* OPENSSL_HAS_ED25519 */

	*keyp = शून्य;
	*labelp = शून्य;

	स_रखो(&cert_attr, 0, माप(cert_attr));
	cert_attr[0].type = CKA_ID;
	cert_attr[1].type = CKA_SUBJECT;
	cert_attr[2].type = CKA_मूल्य;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_मूल्य(session, *obj, cert_attr, 3);
	अगर (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		वापस -1;
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	अगर (cert_attr[1].ul_मूल्य_Len == 0 ||
	    cert_attr[2].ul_मूल्य_Len == 0) {
		error("invalid attribute length");
		वापस -1;
	}

	/* allocate buffers for attributes */
	क्रम (i = 0; i < 3; i++)
		अगर (cert_attr[i].ul_मूल्य_Len > 0)
			cert_attr[i].p_मूल्य = xcalloc(1, cert_attr[i].ul_मूल्य_Len);

	/* retrieve ID, subject and value of certificate */
	rv = f->C_Get_Attribute_मूल्य(session, *obj, cert_attr, 3);
	अगर (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		जाओ out;
	}

	/* Decode DER-encoded cert subject */
	cp = cert_attr[1].p_मूल्य;
	अगर ((x509_name = d2i_X509_NAME(शून्य, &cp,
	    cert_attr[1].ul_मूल्य_Len)) == शून्य ||
	    (subject = X509_NAME_oneline(x509_name, शून्य, 0)) == शून्य)
		subject = xstrdup("invalid subject");
	X509_NAME_free(x509_name);

	cp = cert_attr[2].p_मूल्य;
	अगर ((x509 = d2i_X509(शून्य, &cp, cert_attr[2].ul_मूल्य_Len)) == शून्य) {
		error("d2i_x509 failed");
		जाओ out;
	}

	अगर ((evp = X509_get_pubkey(x509)) == शून्य) {
		error("X509_get_pubkey failed");
		जाओ out;
	}

	अगर (EVP_PKEY_base_id(evp) == EVP_PKEY_RSA) {
		अगर (EVP_PKEY_get0_RSA(evp) == शून्य) {
			error("invalid x509; no rsa key");
			जाओ out;
		}
		अगर ((rsa = RSAPublic_कुंजी_dup(EVP_PKEY_get0_RSA(evp))) == शून्य) {
			error("RSAPublicKey_dup failed");
			जाओ out;
		}

		कुंजी = sshkey_new(कुंजी_UNSPEC);
		अगर (कुंजी == शून्य) {
			error("sshkey_new failed");
			जाओ out;
		}

		EVP_PKEY_free(कुंजी->pkey);
		अगर ((कुंजी->pkey = EVP_PKEY_new()) == शून्य)
			fatal("EVP_PKEY_new failed");
		अगर (EVP_PKEY_set1_RSA(कुंजी->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		कुंजी->type = कुंजी_RSA;
		कुंजी->flags |= SSHKEY_FLAG_EXT;
		अगर (EVP_PKEY_bits(कुंजी->pkey) < SSH_RSA_MINIMUM_MODULUS_आकार) {
			error_f("RSA key too small %d < minimum %d",
			    EVP_PKEY_bits(कुंजी->pkey),
			    SSH_RSA_MINIMUM_MODULUS_आकार);
			जाओ out;
		}
		अगर (pkcs11_record_कुंजी(p, slotidx, &cert_attr[0], कुंजी))
			जाओ out;
		/* success */
		success = 0;
	} अन्यथा अगर (EVP_PKEY_base_id(evp) == EVP_PKEY_EC) {
		अगर (EVP_PKEY_get0_EC_कुंजी(evp) == शून्य) {
			error("invalid x509; no ec key");
			जाओ out;
		}
		अगर ((ec = EC_कुंजी_dup(EVP_PKEY_get0_EC_कुंजी(evp))) == शून्य) {
			error("EC_KEY_dup failed");
			जाओ out;
		}
		अगर ((r = sshkey_ec_validate_public(EC_कुंजी_get0_group(ec),
		    EC_कुंजी_get0_public_कुंजी(ec))) != 0) {
			error_fr(r, "invalid EC key");
			जाओ out;
		}
		nid = sshkey_ecdsa_कुंजी_to_nid(ec);
		अगर (nid < 0) {
			error("couldn't get curve nid");
			जाओ out;
		}

		कुंजी = sshkey_new(कुंजी_UNSPEC);
		अगर (कुंजी == शून्य) {
			error("sshkey_new failed");
			जाओ out;
		}

		EVP_PKEY_free(कुंजी->pkey);
		अगर ((कुंजी->pkey = EVP_PKEY_new()) == शून्य)
			fatal("EVP_PKEY_new failed");
		अगर (EVP_PKEY_set1_EC_कुंजी(कुंजी->pkey, ec) != 1)
			fatal("EVP_PKEY_set1_EC_KEY failed");
		कुंजी->ecdsa_nid = nid;
		कुंजी->type = कुंजी_ECDSA;
		कुंजी->flags |= SSHKEY_FLAG_EXT;
		अगर (pkcs11_record_कुंजी(p, slotidx, &cert_attr[0], कुंजी))
			जाओ out;
		/* success */
		success = 0;
#अगर_घोषित OPENSSL_HAS_ED25519
	} अन्यथा अगर (EVP_PKEY_base_id(evp) == EVP_PKEY_ED25519) {
		अगर ((कुंजी = sshkey_new(कुंजी_UNSPEC)) == शून्य ||
		    (कुंजी->ed25519_pk = सुस्मृति(1, ED25519_PK_SZ)) == शून्य)
			fatal_f("allocation failed");
		len = ED25519_PK_SZ;
		अगर (!EVP_PKEY_get_raw_public_कुंजी(evp, कुंजी->ed25519_pk, &len)) {
			ossl_error("EVP_PKEY_get_raw_public_key failed");
			जाओ out;
		}
		अगर (len != ED25519_PK_SZ) {
			error_f("incorrect returned public key "
			    "length for ed25519");
			जाओ out;
		}
		कुंजी->type = कुंजी_ED25519;
		कुंजी->flags |= SSHKEY_FLAG_EXT;
		अगर (pkcs11_record_कुंजी(p, slotidx, &cert_attr[0], कुंजी))
			जाओ out;
		/* success */
		success = 0;
#पूर्ण_अगर /* OPENSSL_HAS_ED25519 */
	} अन्यथा {
		error("unknown certificate key type");
		जाओ out;
	}
 out:
	क्रम (i = 0; i < 3; i++)
		मुक्त(cert_attr[i].p_मूल्य);
	X509_free(x509);
	RSA_free(rsa);
	EC_कुंजी_free(ec);
	अगर (success != 0 || कुंजी == शून्य) {
		sshkey_free(कुंजी);
		मुक्त(subject);
		वापस -1;
	}
	/* success */
	*keyp = कुंजी;
	*labelp = subject;
	वापस 0;
}
#पूर्ण_अगर /* WITH_OPENSSL */

अटल व्योम
note_कुंजी(काष्ठा pkcs11_provider *p, CK_ULONG slotidx, स्थिर अक्षर *context,
    काष्ठा sshkey *कुंजी)
{
	अक्षर *fp;

	अगर ((fp = sshkey_fingerprint(कुंजी, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == शून्य) {
		error_f("sshkey_fingerprint failed");
		वापस;
	}
	debug2("%s: provider %s slot %lu: %s %s", context, p->name,
	    (u_long)slotidx, sshkey_type(कुंजी), fp);
	मुक्त(fp);
}

#अगर_घोषित WITH_OPENSSL /* libcrypto needed for certificate parsing */
/*
 * lookup certificates for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
अटल पूर्णांक
pkcs11_fetch_certs(काष्ठा pkcs11_provider *p, CK_ULONG slotidx,
    काष्ठा sshkey ***keysp, अक्षर ***labelsp, पूर्णांक *nkeys)
{
	काष्ठा sshkey		*कुंजी = शून्य;
	CK_OBJECT_CLASS		 कुंजी_class;
	CK_ATTRIBUTE		 कुंजी_attr[1];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = शून्य;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	पूर्णांक			 ret = -1;
	अक्षर			*label;

	स_रखो(&कुंजी_attr, 0, माप(कुंजी_attr));
	स_रखो(&obj, 0, माप(obj));

	कुंजी_class = CKO_CERTIFICATE;
	कुंजी_attr[0].type = CKA_CLASS;
	कुंजी_attr[0].p_मूल्य = &कुंजी_class;
	कुंजी_attr[0].ul_मूल्य_Len = माप(कुंजी_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, कुंजी_attr, 1);
	अगर (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		जाओ fail;
	}

	जबतक (1) {
		CK_CERTIFICATE_TYPE	ck_cert_type;

		rv = f->C_FindObjects(session, &obj, 1, &n);
		अगर (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			जाओ fail;
		}
		अगर (n == 0)
			अवरोध;

		स_रखो(&ck_cert_type, 0, माप(ck_cert_type));
		स_रखो(&कुंजी_attr, 0, माप(कुंजी_attr));
		कुंजी_attr[0].type = CKA_CERTIFICATE_TYPE;
		कुंजी_attr[0].p_मूल्य = &ck_cert_type;
		कुंजी_attr[0].ul_मूल्य_Len = माप(ck_cert_type);

		rv = f->C_Get_Attribute_मूल्य(session, obj, कुंजी_attr, 1);
		अगर (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			जाओ fail;
		}

		कुंजी = शून्य;
		label = शून्य;
		चयन (ck_cert_type) {
		हाल CKC_X_509:
			अगर (pkcs11_fetch_x509_pubkey(p, slotidx, &obj,
			    &कुंजी, &label) != 0) {
				debug_f("failed to fetch key");
				जारी;
			}
			अवरोध;
		शेष:
			error("skipping unsupported certificate type %lu",
			    ck_cert_type);
			जारी;
		}
		note_कुंजी(p, slotidx, __func__, कुंजी);
		अगर (pkcs11_कुंजी_included(keysp, nkeys, कुंजी)) {
			debug2_f("key already included");
			sshkey_free(कुंजी);
		} अन्यथा {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, माप(काष्ठा sshkey *));
			(*keysp)[*nkeys] = कुंजी;
			अगर (labelsp != शून्य) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, माप(अक्षर *));
				(*labelsp)[*nkeys] = xstrdup((अक्षर *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_FindObjectsFinal(session);
	अगर (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	वापस (ret);
}
#पूर्ण_अगर /* WITH_OPENSSL */

/*
 * lookup public keys for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
अटल पूर्णांक
pkcs11_fetch_कुंजियाँ(काष्ठा pkcs11_provider *p, CK_ULONG slotidx,
    काष्ठा sshkey ***keysp, अक्षर ***labelsp, पूर्णांक *nkeys)
{
	काष्ठा sshkey		*कुंजी = शून्य;
	CK_OBJECT_CLASS		 कुंजी_class;
	CK_ATTRIBUTE		 कुंजी_attr[2];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = शून्य;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	पूर्णांक			 ret = -1;

	स_रखो(&कुंजी_attr, 0, माप(कुंजी_attr));
	स_रखो(&obj, 0, माप(obj));

	कुंजी_class = CKO_PUBLIC_कुंजी;
	कुंजी_attr[0].type = CKA_CLASS;
	कुंजी_attr[0].p_मूल्य = &कुंजी_class;
	कुंजी_attr[0].ul_मूल्य_Len = माप(कुंजी_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, कुंजी_attr, 1);
	अगर (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		जाओ fail;
	}

	जबतक (1) {
		CK_कुंजी_TYPE	ck_कुंजी_type;
		CK_UTF8CHAR	label[256];

		rv = f->C_FindObjects(session, &obj, 1, &n);
		अगर (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			जाओ fail;
		}
		अगर (n == 0)
			अवरोध;

		स_रखो(&ck_कुंजी_type, 0, माप(ck_कुंजी_type));
		स_रखो(&कुंजी_attr, 0, माप(कुंजी_attr));
		कुंजी_attr[0].type = CKA_कुंजी_TYPE;
		कुंजी_attr[0].p_मूल्य = &ck_कुंजी_type;
		कुंजी_attr[0].ul_मूल्य_Len = माप(ck_कुंजी_type);
		कुंजी_attr[1].type = CKA_LABEL;
		कुंजी_attr[1].p_मूल्य = &label;
		कुंजी_attr[1].ul_मूल्य_Len = माप(label) - 1;

		rv = f->C_Get_Attribute_मूल्य(session, obj, कुंजी_attr, 2);
		अगर (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			जाओ fail;
		}

		label[कुंजी_attr[1].ul_मूल्य_Len] = '\0';

		चयन (ck_कुंजी_type) {
#अगर_घोषित WITH_OPENSSL
		हाल CKK_RSA:
			कुंजी = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			अवरोध;
		हाल CKK_ECDSA:
			कुंजी = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			अवरोध;
#पूर्ण_अगर /* WITH_OPENSSL */
		हाल CKK_EC_EDWARDS:
			कुंजी = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			अवरोध;
		शेष:
			/* XXX print key type? */
			कुंजी = शून्य;
			error("skipping unsupported key type 0x%lx",
			    (u_long)ck_कुंजी_type);
		}

		अगर (कुंजी == शून्य) {
			debug_f("failed to fetch key");
			जारी;
		}
		note_कुंजी(p, slotidx, __func__, कुंजी);
		अगर (pkcs11_कुंजी_included(keysp, nkeys, कुंजी)) {
			debug2_f("key already included");
			sshkey_free(कुंजी);
		} अन्यथा {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, माप(काष्ठा sshkey *));
			(*keysp)[*nkeys] = कुंजी;
			अगर (labelsp != शून्य) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, माप(अक्षर *));
				(*labelsp)[*nkeys] = xstrdup((अक्षर *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_FindObjectsFinal(session);
	अगर (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	वापस (ret);
}

#अगर_घोषित WITH_PKCS11_KEYGEN
#घोषणा FILL_ATTR(attr, idx, typ, val, len) \
	{ (attr[idx]).type=(typ); (attr[idx]).p_मूल्य=(val); (attr[idx]).ul_मूल्य_Len=len; idx++; }

अटल काष्ठा sshkey *
pkcs11_rsa_generate_private_कुंजी(काष्ठा pkcs11_provider *p, CK_ULONG slotidx,
    अक्षर *label, CK_ULONG bits, CK_BYTE keyid, uint32_t *err)
{
	काष्ठा pkcs11_slotinfo	*si;
	अक्षर			*plabel = label ? label : "";
	पूर्णांक			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_कुंजी_2, priv_कुंजी;
	CK_ATTRIBUTE		 tpub[16], tpriv[16];
	CK_MECHANISM		 mech = {
	    CKM_RSA_PKCS_कुंजी_PAIR_GEN, NULL_PTR, 0
	};
	CK_BYTE			 pubExponent[] = {
	    0x01, 0x00, 0x01 /* RSA_F4 in bytes */
	};
	pubkey_filter[0].p_मूल्य = &pubkey_class;
	cert_filter[0].p_मूल्य = &cert_class;

	*err = 0;

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, माप(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, म_माप(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, माप(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, माप(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    माप(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, माप(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, माप(false_val));
	FILL_ATTR(tpub, npub, CKA_MODULUS_BITS, &bits, माप(bits));
	FILL_ATTR(tpub, npub, CKA_PUBLIC_EXPONENT, pubExponent,
	    माप(pubExponent));
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, माप(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN,  &true_val, माप(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL,  plabel, म_माप(plabel));
	FILL_ATTR(tpriv, npriv, CKA_PRIVATE,  &true_val, माप(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE,  &true_val, माप(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT,  &false_val, माप(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN,  &true_val, माप(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER,  &false_val,
	    माप(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP,  &false_val, माप(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE,  &false_val, माप(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, माप(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	अगर ((rv = f->C_Generate_कुंजी_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_कुंजी_2, &priv_कुंजी)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		वापस शून्य;
	}

	वापस pkcs11_fetch_rsa_pubkey(p, slotidx, &pub_कुंजी_2);
}

अटल पूर्णांक
h2i(अक्षर c)
{
	अगर (c >= '0' && c <= '9')
		वापस c - '0';
	अन्यथा अगर (c >= 'a' && c <= 'f')
		वापस c - 'a' + 10;
	अन्यथा अगर (c >= 'A' && c <= 'F')
		वापस c - 'A' + 10;
	अन्यथा
		वापस -1;
}

अटल पूर्णांक
pkcs11_decode_hex(स्थिर अक्षर *hex, अचिन्हित अक्षर **dest, माप_प्रकार *rlen)
{
	माप_प्रकार	i, len;

	अगर (dest)
		*dest = शून्य;
	अगर (rlen)
		*rlen = 0;

	अगर ((len = म_माप(hex)) % 2)
		वापस -1;
	len /= 2;

	*dest = xmalloc(len);

	क्रम (i = 0; i < len; i++) {
		पूर्णांक hi, lo;

		hi = h2i(hex[2 * i]);
		lo = h2i(hex[(2 * i) + 1]);
		अगर (hi == -1 || lo == -1)
			वापस -1;
		(*dest)[i] = (hi << 4) | lo;
	}

	अगर (rlen)
		*rlen = len;

	वापस 0;
}

अटल काष्ठा ec_curve_info {
	स्थिर अक्षर	*name;
	स्थिर अक्षर	*oid;
	स्थिर अक्षर	*oid_encoded;
	माप_प्रकार		 आकार;
} ec_curve_infos[] = {
	{"prime256v1",	"1.2.840.10045.3.1.7",	"06082A8648CE3D030107", 256},
	{"secp384r1",	"1.3.132.0.34",		"06052B81040022",	384},
	{"secp521r1",	"1.3.132.0.35",		"06052B81040023",	521},
	{शून्य,		शून्य,			शून्य,			0},
};

अटल काष्ठा sshkey *
pkcs11_ecdsa_generate_private_कुंजी(काष्ठा pkcs11_provider *p, CK_ULONG slotidx,
    अक्षर *label, CK_ULONG bits, CK_BYTE keyid, uint32_t *err)
{
	काष्ठा pkcs11_slotinfo	*si;
	अक्षर			*plabel = label ? label : "";
	पूर्णांक			 i;
	माप_प्रकार			 ecparams_आकार;
	अचिन्हित अक्षर		*ecparams = शून्य;
	पूर्णांक			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_कुंजी_2, priv_कुंजी;
	CK_MECHANISM		 mech = {
	    CKM_EC_कुंजी_PAIR_GEN, NULL_PTR, 0
	};
	CK_ATTRIBUTE		 tpub[16], tpriv[16];

	*err = 0;

	क्रम (i = 0; ec_curve_infos[i].name; i++) {
		अगर (ec_curve_infos[i].आकार == bits)
			अवरोध;
	}
	अगर (!ec_curve_infos[i].name) {
		error_f("invalid key size %lu", bits);
		वापस शून्य;
	}
	अगर (pkcs11_decode_hex(ec_curve_infos[i].oid_encoded, &ecparams,
	    &ecparams_आकार) == -1) {
		error_f("invalid oid");
		वापस शून्य;
	}

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, माप(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, म_माप(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, माप(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, माप(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    माप(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, माप(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, माप(false_val));
	FILL_ATTR(tpub, npub, CKA_EC_PARAMS, ecparams, ecparams_आकार);
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, माप(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN, &true_val, माप(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL, plabel, म_माप(plabel));
	FILL_ATTR(tpriv, npriv, CKA_PRIVATE, &true_val, माप(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE, &true_val, माप(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT, &false_val, माप(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN, &true_val, माप(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER, &false_val,
	    माप(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP, &false_val, माप(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE, &false_val, माप(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, माप(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	अगर ((rv = f->C_Generate_कुंजी_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_कुंजी_2, &priv_कुंजी)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		वापस शून्य;
	}

	वापस pkcs11_fetch_ecdsa_pubkey(p, slotidx, &pub_कुंजी_2);
}
#पूर्ण_अगर /* WITH_PKCS11_KEYGEN */

/*
 * register a new provider, fails if provider already exists. if
 * keyp is provided, fetch keys.
 */
अटल पूर्णांक
pkcs11_register_provider(अक्षर *provider_id, अक्षर *pin,
    काष्ठा sshkey ***keyp, अक्षर ***labelsp,
    काष्ठा pkcs11_provider **providerp, CK_ULONG user)
{
	पूर्णांक nkeys, need_finalize = 0;
	पूर्णांक ret = -1;
	काष्ठा pkcs11_provider *p = शून्य;
	व्योम *handle = शून्य;
	CK_RV (*getfunctionlist)(CK_FUNCTION_LIST **);
	CK_RV rv;
	CK_FUNCTION_LIST *f = शून्य;
	CK_TOKEN_INFO *token;
	CK_ULONG i;

	अगर (providerp == शून्य)
		जाओ fail;
	*providerp = शून्य;

	अगर (keyp != शून्य)
		*keyp = शून्य;
	अगर (labelsp != शून्य)
		*labelsp = शून्य;

	अगर (pkcs11_provider_lookup(provider_id) != शून्य) {
		debug_f("provider already registered: %s", provider_id);
		जाओ fail;
	}
	अगर (lib_contains_प्रतीक(provider_id, "C_GetFunctionList") != 0) {
		error("provider %s is not a PKCS11 library", provider_id);
		जाओ fail;
	}
	/* open shared pkcs11-library */
	अगर ((handle = dlopen(provider_id, RTLD_NOW)) == शून्य) {
		error("dlopen %s failed: %s", provider_id, dlerror());
		जाओ fail;
	}
	अगर ((getfunctionlist = dlsym(handle, "C_GetFunctionList")) == शून्य)
		fatal("dlsym(C_GetFunctionList) failed: %s", dlerror());
	p = xcalloc(1, माप(*p));
	p->name = xstrdup(provider_id);
	p->handle = handle;
	/* set up the pkcs11 callbacks */
	अगर ((rv = (*getfunctionlist)(&f)) != CKR_OK) {
		error("C_GetFunctionList for provider %s failed: %lu",
		    provider_id, rv);
		जाओ fail;
	}
	p->function_list = f;
	अगर ((rv = f->C_Initialize(शून्य)) != CKR_OK) {
		error("C_Initialize for provider %s failed: %lu",
		    provider_id, rv);
		जाओ fail;
	}
	need_finalize = 1;
	अगर ((rv = f->C_GetInfo(&p->info)) != CKR_OK) {
		error("C_GetInfo for provider %s failed: %lu",
		    provider_id, rv);
		जाओ fail;
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
	अगर ((rv = f->C_GetSlotList(CK_TRUE, शून्य, &p->nslots)) != CKR_OK) {
		error("C_GetSlotList failed: %lu", rv);
		जाओ fail;
	}
	अगर (p->nslots == 0) {
		debug_f("provider %s returned no slots", provider_id);
		ret = -SSH_PKCS11_ERR_NO_SLOTS;
		जाओ fail;
	}
	p->slotlist = xcalloc(p->nslots, माप(CK_SLOT_ID));
	अगर ((rv = f->C_GetSlotList(CK_TRUE, p->slotlist, &p->nslots))
	    != CKR_OK) {
		error("C_GetSlotList for provider %s failed: %lu",
		    provider_id, rv);
		जाओ fail;
	}
	p->slotinfo = xcalloc(p->nslots, माप(काष्ठा pkcs11_slotinfo));
	p->valid = 1;
	nkeys = 0;
	क्रम (i = 0; i < p->nslots; i++) {
		token = &p->slotinfo[i].token;
		अगर ((rv = f->C_GetTokenInfo(p->slotlist[i], token))
		    != CKR_OK) {
			error("C_GetTokenInfo for provider %s slot %lu "
			    "failed: %lu", provider_id, (u_long)i, rv);
			जारी;
		}
		अगर ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
			debug2_f("ignoring uninitialised token in "
			    "provider %s slot %lu", provider_id, (u_long)i);
			जारी;
		}
		debug("provider %s slot %lu: label <%.*s> "
		    "manufacturerID <%.*s> model <%.*s> serial <%.*s> "
		    "flags 0x%lx",
		    provider_id, (अचिन्हित दीर्घ)i,
		    RMSPACE(token->label), RMSPACE(token->manufacturerID),
		    RMSPACE(token->model), RMSPACE(token->serial_संख्या_2),
		    token->flags);
		/*
		 * open session, login with pin and retrieve public
		 * keys (if keyp is provided)
		 */
		अगर ((ret = pkcs11_open_session(p, i, pin, user)) != 0 ||
		    keyp == शून्य)
			जारी;
		pkcs11_fetch_कुंजियाँ(p, i, keyp, labelsp, &nkeys);
#अगर_घोषित WITH_OPENSSL
		pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#पूर्ण_अगर
		अगर (nkeys == 0 && !p->slotinfo[i].logged_in &&
		    pkcs11_interactive) {
			/*
			 * Some tokens require login before they will
			 * expose keys.
			 */
			अगर (pkcs11_login_slot(p, &p->slotinfo[i],
			    CKU_USER) < 0) {
				error("login failed");
				जारी;
			}
			pkcs11_fetch_कुंजियाँ(p, i, keyp, labelsp, &nkeys);
#अगर_घोषित WITH_OPENSSL
			pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#पूर्ण_अगर
		}
	}

	/* now owned by caller */
	*providerp = p;

	TAILQ_INSERT_TAIL(&pkcs11_providers, p, अग्र);
	p->refcount++;	/* add to provider list */

	वापस (nkeys);
fail:
	अगर (need_finalize && (rv = f->C_Finalize(शून्य)) != CKR_OK)
		error("C_Finalize for provider %s failed: %lu",
		    provider_id, rv);
	अगर (p) {
		मुक्त(p->name);
		मुक्त(p->slotlist);
		मुक्त(p->slotinfo);
		मुक्त(p);
	}
	अगर (handle)
		dlclose(handle);
	अगर (ret > 0)
		ret = -1;
	वापस (ret);
}

पूर्णांक
pkcs11_init(पूर्णांक interactive)
{
	debug3_f("called, interactive = %d", interactive);

	pkcs11_interactive = interactive;
	TAILQ_INIT(&pkcs11_providers);
	TAILQ_INIT(&pkcs11_कुंजियाँ);
	वापस (0);
}

/* unregister all providers, keys might still point to the providers */
व्योम
pkcs11_terminate(व्योम)
{
	काष्ठा pkcs11_provider *p;
	काष्ठा pkcs11_कुंजी *k11;

	debug3_f("called");

	जबतक ((k11 = TAILQ_FIRST(&pkcs11_कुंजियाँ)) != शून्य) {
		TAILQ_REMOVE(&pkcs11_कुंजियाँ, k11, अग्र);
		pkcs11_k11_free(k11);
	}
	जबतक ((p = TAILQ_FIRST(&pkcs11_providers)) != शून्य) {
		TAILQ_REMOVE(&pkcs11_providers, p, अग्र);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
}

/*
 * register a new provider and get number of keys hold by the token,
 * fails if provider already exists
 */
पूर्णांक
pkcs11_add_provider(अक्षर *provider_id, अक्षर *pin, काष्ठा sshkey ***keyp,
    अक्षर ***labelsp)
{
	काष्ठा pkcs11_provider *p = शून्य;
	पूर्णांक nkeys;

	nkeys = pkcs11_register_provider(provider_id, pin, keyp, labelsp,
	    &p, CKU_USER);

	/* no keys found or some other error, de-register provider */
	अगर (nkeys <= 0 && p != शून्य) {
		TAILQ_REMOVE(&pkcs11_providers, p, अग्र);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
	अगर (nkeys == 0)
		debug_f("provider %s returned no keys", provider_id);

	वापस (nkeys);
}

पूर्णांक
pkcs11_sign(काष्ठा sshkey *कुंजी,
    u_char **sigp, माप_प्रकार *lenp,
    स्थिर u_char *तथ्य, माप_प्रकार datalen,
    स्थिर अक्षर *alg, स्थिर अक्षर *sk_provider,
    स्थिर अक्षर *sk_pin, u_int compat)
{
	चयन (कुंजी->type) {
#अगर_घोषित WITH_OPENSSL
	हाल कुंजी_RSA:
	हाल कुंजी_RSA_CERT:
		वापस pkcs11_sign_rsa(कुंजी, sigp, lenp, तथ्य, datalen,
		    alg, sk_provider, sk_pin, compat);
	हाल कुंजी_ECDSA:
	हाल कुंजी_ECDSA_CERT:
		वापस pkcs11_sign_ecdsa(कुंजी, sigp, lenp, तथ्य, datalen,
		    alg, sk_provider, sk_pin, compat);
#पूर्ण_अगर /* WITH_OPENSSL */
	हाल कुंजी_ED25519:
	हाल कुंजी_ED25519_CERT:
		वापस pkcs11_sign_ed25519(कुंजी, sigp, lenp, तथ्य, datalen,
		    alg, sk_provider, sk_pin, compat);
	शेष:
		वापस SSH_ERR_कुंजी_TYPE_UNKNOWN;
	}
}

व्योम
pkcs11_कुंजी_free(काष्ठा sshkey *कुंजी)
{
	/* never called */
}

#अगर_घोषित WITH_PKCS11_KEYGEN
काष्ठा sshkey *
pkcs11_gakp(अक्षर *provider_id, अक्षर *pin, अचिन्हित पूर्णांक slotidx, अक्षर *label,
    अचिन्हित पूर्णांक type, अचिन्हित पूर्णांक bits, अचिन्हित अक्षर keyid, uint32_t *err)
{
	काष्ठा pkcs11_provider	*p = शून्य;
	काष्ठा pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	काष्ठा sshkey		*k = शून्य;
	पूर्णांक			 ret = -1, reset_pin = 0, reset_provider = 0;
	CK_RV			 rv;

	*err = 0;

	अगर ((p = pkcs11_provider_lookup(provider_id)) != शून्य)
		debug_f("provider \"%s\" available", provider_id);
	अन्यथा अगर ((ret = pkcs11_register_provider(provider_id, pin, शून्य, शून्य,
	    &p, CKU_SO)) < 0) {
		debug_f("could not register provider %s", provider_id);
		जाओ out;
	} अन्यथा
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	अगर ((rv = f->C_SetOperationState(session , pin, म_माप(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} अन्यथा
		reset_pin = 1;

	चयन (type) {
	हाल कुंजी_RSA:
		अगर ((k = pkcs11_rsa_generate_private_कुंजी(p, slotidx, label,
		    bits, keyid, err)) == शून्य) {
			debug_f("failed to generate RSA key");
			जाओ out;
		}
		अवरोध;
	हाल कुंजी_ECDSA:
		अगर ((k = pkcs11_ecdsa_generate_private_कुंजी(p, slotidx, label,
		    bits, keyid, err)) == शून्य) {
			debug_f("failed to generate ECDSA key");
			जाओ out;
		}
		अवरोध;
	शेष:
		*err = SSH_PKCS11_ERR_GENERIC;
		debug_f("unknown type %d", type);
		जाओ out;
	}

out:
	अगर (reset_pin)
		f->C_SetOperationState(session , शून्य, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	अगर (reset_provider)
		pkcs11_del_provider(provider_id);

	वापस (k);
}

काष्ठा sshkey *
pkcs11_destroy_keypair(अक्षर *provider_id, अक्षर *pin, अचिन्हित दीर्घ slotidx,
    अचिन्हित अक्षर keyid, uint32_t *err)
{
	काष्ठा pkcs11_provider	*p = शून्य;
	काष्ठा pkcs11_slotinfo	*si;
	काष्ठा sshkey		*k = शून्य;
	पूर्णांक			 reset_pin = 0, reset_provider = 0;
	CK_ULONG		 nattrs;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_ATTRIBUTE		 attrs[16];
	CK_OBJECT_CLASS		 कुंजी_class;
	CK_कुंजी_TYPE		 कुंजी_type;
	CK_OBJECT_HANDLE	 obj = CK_INVALID_HANDLE;
	CK_RV			 rv;

	*err = 0;

	अगर ((p = pkcs11_provider_lookup(provider_id)) != शून्य) {
		debug_f("using provider \"%s\"", provider_id);
	} अन्यथा अगर (pkcs11_register_provider(provider_id, pin, शून्य, शून्य, &p,
	    CKU_SO) < 0) {
		debug_f("could not register provider %s",
		    provider_id);
		जाओ out;
	} अन्यथा
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	अगर ((rv = f->C_SetOperationState(session , pin, म_माप(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} अन्यथा
		reset_pin = 1;

	/* private key */
	nattrs = 0;
	कुंजी_class = CKO_PRIVATE_कुंजी;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &कुंजी_class, माप(कुंजी_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, माप(keyid));

	अगर (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {
		अगर ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy private key 0x%hhx",
			    keyid);
			*err = rv;
			जाओ out;
		}
	}

	/* public key */
	nattrs = 0;
	कुंजी_class = CKO_PUBLIC_कुंजी;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &कुंजी_class, माप(कुंजी_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, माप(keyid));

	अगर (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {

		/* get key type */
		nattrs = 0;
		FILL_ATTR(attrs, nattrs, CKA_कुंजी_TYPE, &कुंजी_type,
		    माप(कुंजी_type));
		rv = f->C_Get_Attribute_मूल्य(session, obj, attrs, nattrs);
		अगर (rv != CKR_OK) {
			debug_f("could not get key type of public key 0x%hhx",
			    keyid);
			*err = rv;
			कुंजी_type = -1;
		}
		चयन (कुंजी_type) {
#अगर_घोषित WITH_OPENSSL
		हाल CKK_RSA:
			k = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			अवरोध;
		हाल CKK_ECDSA:
			k = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			अवरोध;
#पूर्ण_अगर /* WITH_OPENSSL */
		हाल CKK_EC_EDWARDS:
			k = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			अवरोध;
		शेष:
			debug_f("unsupported key type %lu", (u_long)कुंजी_type);
			अवरोध;
		}

		अगर ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy public key 0x%hhx", keyid);
			*err = rv;
			जाओ out;
		}
	}

out:
	अगर (reset_pin)
		f->C_SetOperationState(session , शून्य, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	अगर (reset_provider)
		pkcs11_del_provider(provider_id);

	वापस (k);
}
#पूर्ण_अगर /* WITH_PKCS11_KEYGEN */
#अन्यथा /* ENABLE_PKCS11 */

#समावेश <sys/types.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>

#समावेश "log.h"
#समावेश "sshkey.h"
#समावेश "ssherr.h"
#समावेश "ssh-pkcs11.h"

पूर्णांक
pkcs11_init(पूर्णांक interactive)
{
	error_f("PKCS#11 not supported");
	वापस (-1);
}

पूर्णांक
pkcs11_add_provider(अक्षर *provider_id, अक्षर *pin, काष्ठा sshkey ***keyp,
    अक्षर ***labelsp)
{
	error_f("PKCS#11 not supported");
	वापस (-1);
}

व्योम
pkcs11_कुंजी_free(काष्ठा sshkey *कुंजी)
{
	error_f("PKCS#11 not supported");
}

पूर्णांक
pkcs11_sign(काष्ठा sshkey *कुंजी,
    u_char **sigp, माप_प्रकार *lenp,
    स्थिर u_char *तथ्य, माप_प्रकार datalen,
    स्थिर अक्षर *alg, स्थिर अक्षर *sk_provider,
    स्थिर अक्षर *sk_pin, u_int compat)
{
	error_f("PKCS#11 not supported");
	वापस SSH_ERR_FEATURE_UNSUPPORTED;
}

व्योम
pkcs11_terminate(व्योम)
{
	error_f("PKCS#11 not supported");
}
#पूर्ण_अगर /* ENABLE_PKCS11 */
