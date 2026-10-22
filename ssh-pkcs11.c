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

#அந்தர்பாவ "includes.h"

#ifdef ENABLE_PKCS11

#அந்தர்பாவ <sys/time.h>

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/queue.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>

#அந்தர்பாவ <string.h>
#அந்தர்பாவ <dlfcn.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ "openbsd-compat/openssl-compat.h"
#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/ecdsa.h>
#அந்தர்பாவ <openssl/x509.h>
#அந்தர்பாவ <openssl/err.h>
#endif

#define CRYPTOKI_COMPAT
#அந்தர்பாவ "pkcs11.h"

#define SSHKEY_INTERNAL
#அந்தர்பாவ "sshkey.h"

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssh-pkcs11.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "crypto_api.h"

கட்டமைப்பு pkcs11_slotinfo {
	CK_TOKEN_INFO		token;
	CK_SESSION_HANDLE	session;
	முழு			logged_in;
};

கட்டமைப்பு pkcs11_provider {
	எழுத்து			*name;
	வெறுமை			*handle;
	CK_FUNCTION_LIST	*function_list;
	CK_INFO			info;
	CK_ULONG		nslots;
	CK_SLOT_ID		*slotlist;
	கட்டமைப்பு pkcs11_slotinfo	*slotinfo;
	முழு			valid;
	முழு			refcount;
	TAILQ_ENTRY(pkcs11_provider) next;
};

TAILQ_HEAD(, pkcs11_provider) pkcs11_providers;

கட்டமைப்பு pkcs11_சாவி {
	கட்டமைப்பு sshbuf		*keyblob;
	கட்டமைப்பு pkcs11_provider	*provider;
	CK_ULONG		slotidx;
	எழுத்து			*keyid;
	முழு			keyid_len;
	TAILQ_ENTRY(pkcs11_சாவி)	next;
};

TAILQ_HEAD(, pkcs11_சாவி) pkcs11_சாவிகள்; /* XXX a tree would be better */

முழு pkcs11_interactive = 0;

#ifdef WITH_OPENSSL
நிலையான வெறுமை
ossl_error(மாறிலி எழுத்து *செய்தி)
{
	unsigned long    e;

	error_f("%s", செய்தி);
	போது ((e = ERR_get_error()) != 0)
		error_f("libcrypto error: %s", ERR_error_string(e, வெற்று));
}
#endif

/*
 * finalize a provider shared library, it's no longer usable.
 * however, there might still be keys referencing this provider,
 * so the actual freeing of memory is handled by pkcs11_provider_unref().
 * this is called when a provider gets unregistered.
 */
நிலையான வெறுமை
pkcs11_provider_finalize(கட்டமைப்பு pkcs11_provider *p)
{
	CK_RV rv;
	CK_ULONG i;

	debug_f("provider \"%s\" refcount %d valid %d",
	    p->name, p->refcount, p->valid);
	எனில் (!p->valid)
		திரும்பு;
	க்கு (i = 0; i < p->nslots; i++) {
		எனில் (p->slotinfo[i].session &&
		    (rv = p->function_list->C_CloseSession(
		    p->slotinfo[i].session)) != CKR_OK)
			error("C_CloseSession failed: %lu", rv);
	}
	எனில் ((rv = p->function_list->C_Finalize(வெற்று)) != CKR_OK)
		error("C_Finalize failed: %lu", rv);
	p->valid = 0;
	p->function_list = வெற்று;
	dlclose(p->handle);
}

/*
 * remove a reference to the provider.
 * called when a key gets destroyed or when the provider is unregistered.
 */
நிலையான வெறுமை
pkcs11_provider_unref(கட்டமைப்பு pkcs11_provider *p)
{
	debug_f("provider \"%s\" refcount %d", p->name, p->refcount);
	எனில் (--p->refcount <= 0) {
		எனில் (p->valid)
			error_f("provider \"%s\" still valid", p->name);
		விடுவி(p->name);
		விடுவி(p->slotlist);
		விடுவி(p->slotinfo);
		விடுவி(p);
	}
}

/* lookup provider by name */
நிலையான கட்டமைப்பு pkcs11_provider *
pkcs11_provider_lookup(எழுத்து *provider_id)
{
	கட்டமைப்பு pkcs11_provider *p;

	TAILQ_FOREACH(p, &pkcs11_providers, next) {
		debug("check provider \"%s\"", p->name);
		எனில் (!strcmp(provider_id, p->name))
			திரும்பு (p);
	}
	திரும்பு (வெற்று);
}

/* unregister provider by name */
முழு
pkcs11_del_provider(எழுத்து *provider_id)
{
	கட்டமைப்பு pkcs11_provider *p;

	எனில் ((p = pkcs11_provider_lookup(provider_id)) != வெற்று) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
		திரும்பு (0);
	}
	திரும்பு (-1);
}

/* release a wrapped object */
நிலையான வெறுமை
pkcs11_k11_free(கட்டமைப்பு pkcs11_சாவி *k11)
{
	எனில் (k11 == வெற்று)
		திரும்பு;
	எனில் (k11->provider)
		pkcs11_provider_unref(k11->provider);
	விடுவி(k11->keyid);
	sshbuf_free(k11->keyblob);
	விடுவி(k11);
}

/* find a single 'obj' for given attributes */
நிலையான முழு
pkcs11_find(கட்டமைப்பு pkcs11_provider *p, CK_ULONG slotidx, CK_ATTRIBUTE *attr,
    CK_ULONG nattr, CK_OBJECT_HANDLE *obj)
{
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	session;
	CK_ULONG		nfound = 0;
	CK_RV			rv;
	முழு			ret = -1;

	f = p->function_list;
	session = p->slotinfo[slotidx].session;
	எனில் ((rv = f->C_FindObjectsInit(session, attr, nattr)) != CKR_OK) {
		error("C_FindObjectsInit failed (nattr %lu): %lu", nattr, rv);
		திரும்பு (-1);
	}
	எனில் ((rv = f->C_FindObjects(session, obj, 1, &nfound)) != CKR_OK ||
	    nfound != 1) {
		debug("C_FindObjects failed (nfound %lu nattr %lu): %lu",
		    nfound, nattr, rv);
	} இல்லையெனில்
		ret = 0;
	எனில் ((rv = f->C_FindObjectsFinal(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	திரும்பு (ret);
}

நிலையான முழு
pkcs11_login_slot(கட்டமைப்பு pkcs11_provider *provider, கட்டமைப்பு pkcs11_slotinfo *si,
    CK_USER_TYPE type)
{
	எழுத்து			*pin = வெற்று, prompt[1024];
	CK_RV			 rv;

	எனில் (provider == வெற்று || si == வெற்று || !provider->valid) {
		error("no pkcs11 (valid) provider found");
		திரும்பு (-1);
	}

	எனில் (!pkcs11_interactive) {
		error("need pin entry%s",
		    (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH) ?
		    " on reader keypad" : "");
		திரும்பு (-1);
	}
	எனில் (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
		verbose("Deferring PIN entry to reader keypad.");
	இல்லையெனில் {
		snprintf(prompt, அளவு(prompt), "Enter PIN for '%s': ",
		    si->token.label);
		எனில் ((pin = read_passphrase(prompt, RP_ALLOW_EOF)) == வெற்று) {
			debug_f("no pin specified");
			திரும்பு (-1);	/* bail out */
		}
	}
	rv = provider->function_list->C_Login(si->session, type, (u_char *)pin,
	    (pin != வெற்று) ? strlen(pin) : 0);
	எனில் (pin != வெற்று)
		freezero(pin, strlen(pin));

	தேர்வு (rv) {
	நிலை CKR_OK:
	நிலை CKR_USER_ALREADY_LOGGED_IN:
		/* success */
		நிறுத்து;
	நிலை CKR_PIN_LEN_RANGE:
		error("PKCS#11 login failed: PIN length out of range");
		திரும்பு -1;
	நிலை CKR_PIN_INCORRECT:
		error("PKCS#11 login failed: PIN incorrect");
		திரும்பு -1;
	நிலை CKR_PIN_LOCKED:
		error("PKCS#11 login failed: PIN locked");
		திரும்பு -1;
	இயல்பு:
		error("PKCS#11 login failed: error %lu", rv);
		திரும்பு -1;
	}
	si->logged_in = 1;
	திரும்பு (0);
}

நிலையான முழு
pkcs11_login(கட்டமைப்பு pkcs11_சாவி *k11, CK_USER_TYPE type)
{
	எனில் (k11 == வெற்று || k11->provider == வெற்று || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		திரும்பு (-1);
	}

	திரும்பு pkcs11_login_slot(k11->provider,
	    &k11->provider->slotinfo[k11->slotidx], type);
}


நிலையான முழு
pkcs11_check_obj_bool_attrib(கட்டமைப்பு pkcs11_சாவி *k11, CK_OBJECT_HANDLE obj,
    CK_ATTRIBUTE_TYPE type, முழு *val)
{
	கட்டமைப்பு pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_BBOOL		flag = 0;
	CK_ATTRIBUTE		attr;
	CK_RV			 rv;

	*val = 0;

	எனில் (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		திரும்பு (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	attr.type = type;
	attr.p_மதிப்பு = &flag;
	attr.ul_மதிப்பு_Len = அளவு(flag);

	rv = f->C_Get_Attribute_மதிப்பு(si->session, obj, &attr, 1);
	எனில் (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		திரும்பு (-1);
	}
	*val = flag != 0;
	debug_f("provider \"%s\" slot %lu object %lu: attrib %lu = %d",
	    k11->provider->name, k11->slotidx, obj, type, *val);
	திரும்பு (0);
}

நிலையான முழு
pkcs11_get_சாவி(கட்டமைப்பு pkcs11_சாவி *k11, CK_MECHANISM_TYPE mech_type)
{
	கட்டமைப்பு pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	 obj;
	CK_RV			 rv;
	CK_OBJECT_CLASS		 private_சாவி_class;
	CK_BBOOL		 true_val;
	CK_MECHANISM		 mech;
	CK_ATTRIBUTE		 சாவி_filter[3];
	முழு			 always_auth = 0;
	முழு			 did_login = 0;

	எனில் (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		திரும்பு (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	எனில் ((si->token.flags & CKF_LOGIN_REQUIRED) && !si->logged_in) {
		எனில் (pkcs11_login(k11, CKU_USER) < 0) {
			error("login failed");
			திரும்பு (-1);
		}
		did_login = 1;
	}

	memset(&சாவி_filter, 0, அளவு(சாவி_filter));
	private_சாவி_class = CKO_PRIVATE_சாவி;
	சாவி_filter[0].type = CKA_CLASS;
	சாவி_filter[0].p_மதிப்பு = &private_சாவி_class;
	சாவி_filter[0].ul_மதிப்பு_Len = அளவு(private_சாவி_class);

	சாவி_filter[1].type = CKA_ID;
	சாவி_filter[1].p_மதிப்பு = k11->keyid;
	சாவி_filter[1].ul_மதிப்பு_Len = k11->keyid_len;

	true_val = CK_TRUE;
	சாவி_filter[2].type = CKA_SIGN;
	சாவி_filter[2].p_மதிப்பு = &true_val;
	சாவி_filter[2].ul_மதிப்பு_Len = அளவு(true_val);

	/* try to find object w/CKA_SIGN first, retry w/o */
	எனில் (pkcs11_find(k11->provider, k11->slotidx, சாவி_filter, 3, &obj) < 0 &&
	    pkcs11_find(k11->provider, k11->slotidx, சாவி_filter, 2, &obj) < 0) {
		error("cannot find private key");
		திரும்பு (-1);
	}

	memset(&mech, 0, அளவு(mech));
	mech.mechanism = mech_type;
	mech.pParameter = NULL_PTR;
	mech.ulParameterLen = 0;

	எனில் ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
		திரும்பு (-1);
	}

	pkcs11_check_obj_bool_attrib(k11, obj, CKA_ALWAYS_AUTHENTICATE,
	    &always_auth); /* ignore errors here */
	எனில் (always_auth && !did_login) {
		debug_f("always-auth key");
		எனில் (pkcs11_login(k11, CKU_CONTEXT_SPECIFIC) < 0) {
			error("login failed for always-auth key");
			திரும்பு (-1);
		}
	}

	திரும்பு (0);
}

/* record the key information later use lookup by keyblob */
நிலையான முழு
pkcs11_record_சாவி(கட்டமைப்பு pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, கட்டமைப்பு sshkey *சாவி)
{
	கட்டமைப்பு sshbuf *keyblob;
	கட்டமைப்பு pkcs11_சாவி *k11;
	முழு r;
	எழுத்து *hex;

	hex = tohex(keyid_attrib->p_மதிப்பு, keyid_attrib->ul_மதிப்பு_Len);
	debug_f("%s key: provider %s slot %lu keyid %s",
	    sshkey_type(சாவி), provider->name, (u_long)slotidx, hex);
	விடுவி(hex);

	எனில் ((keyblob = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshkey_putb(சாவி, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");

	/* Check if we've already recorded this key in a different slot */
	TAILQ_FOREACH(k11, &pkcs11_சாவிகள், next) {
		எனில் (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			hex = tohex(k11->keyid, k11->keyid_len);
			debug_f("Already seen this key at "
			    "provider %s slot %lu keyid %s",
			    k11->provider->name, k11->slotidx, hex);
			விடுவி(hex);
			sshbuf_free(keyblob);
			திரும்பு -1;
		}
	}

	k11 = xcalloc(1, அளவு(*k11));
	k11->provider = provider;
	k11->keyblob = keyblob;
	provider->refcount++;	/* provider referenced by RSA key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ul_மதிப்பு_Len;
	எனில் (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len);
		memcpy(k11->keyid, keyid_attrib->p_மதிப்பு, k11->keyid_len);
	}
	TAILQ_INSERT_TAIL(&pkcs11_சாவிகள், k11, next);

	திரும்பு 0;
}

/* retrieve the key information by keyblob */
நிலையான கட்டமைப்பு pkcs11_சாவி *
pkcs11_lookup_சாவி(கட்டமைப்பு sshkey *சாவி)
{
	கட்டமைப்பு pkcs11_சாவி *k11, *found = வெற்று;
	கட்டமைப்பு sshbuf *keyblob;
	முழு r;

	எனில் ((keyblob = sshbuf_new()) == வெற்று)
		fatal_f("sshbuf_new failed");
	எனில் ((r = sshkey_putb(சாவி, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");
	TAILQ_FOREACH(k11, &pkcs11_சாவிகள், next) {
		எனில் (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			found = k11;
			நிறுத்து;
		}
	}
	sshbuf_free(keyblob);
	திரும்பு found;
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
நிலையான மாறிலி u_char id_sha1[] = {
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
நிலையான மாறிலி u_char id_sha256[] = {
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
நிலையான மாறிலி u_char id_sha512[] = {
	0x30, 0x51, /* type Sequence, length 0x51 (81) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, /* id-sha512 */
	0x05, 0x00, /* NULL */
	0x04, 0x40  /* Octet string, length 0x40 (64), followed by sha512 hash */
};

நிலையான முழு
rsa_hash_alg_oid(முழு hash_alg, மாறிலி u_char **oidp, size_t *oidlenp)
{
	தேர்வு (hash_alg) {
	நிலை SSH_DIGEST_SHA1:
		*oidp = id_sha1;
		*oidlenp = அளவு(id_sha1);
		நிறுத்து;
	நிலை SSH_DIGEST_SHA256:
		*oidp = id_sha256;
		*oidlenp = அளவு(id_sha256);
		நிறுத்து;
	நிலை SSH_DIGEST_SHA512:
		*oidp = id_sha512;
		*oidlenp = அளவு(id_sha512);
		நிறுத்து;
	இயல்பு:
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	}
	திரும்பு 0;
}

நிலையான முழு
pkcs11_sign_rsa(கட்டமைப்பு sshkey *சாவி,
    u_char **sigp, size_t *lenp,
    மாறிலி u_char *data, size_t datalen,
    மாறிலி எழுத்து *alg, மாறிலி எழுத்து *sk_provider,
    மாறிலி எழுத்து *sk_pin, u_int compat)
{
	கட்டமைப்பு pkcs11_சாவி	*k11;
	கட்டமைப்பு pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	முழு			hashalg, r, diff, siglen, ret = -1;
	u_char			*oid_dgst = வெற்று, *sig = வெற்று;
	size_t			dgst_len, oid_len, oid_dgst_len = 0;
	மாறிலி u_char		*oid;

	எனில் (sigp != வெற்று)
		*sigp = வெற்று;
	எனில் (lenp != வெற்று)
		*lenp = 0;

	எனில் ((k11 = pkcs11_lookup_சாவி(சாவி)) == வெற்று) {
		error_f("no key found");
		திரும்பு SSH_ERR_சாவி_NOT_FOUND;
	}

	debug3_f("sign with alg \"%s\" using provider %s slotidx %lu",
	    alg == வெற்று ? "" : alg, k11->provider->name, (u_long)k11->slotidx);

	எனில் (pkcs11_get_சாவி(k11, CKM_RSA_PKCS) == -1) {
		error("pkcs11_get_key failed");
		திரும்பு SSH_ERR_AGENT_FAILURE;
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	எனில் ((siglen = EVP_PKEY_size(சாவி->pkey)) <= 0)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* Determine hash algorithm and OID for signature */
	எனில் (alg == வெற்று || *alg == '\0')
		hashalg = SSH_DIGEST_SHA1;
	இல்லையெனில் எனில் ((hashalg = ssh_rsa_hash_id_from_keyname(alg)) == -1)
		fatal_f("couldn't determine RSA hash alg \"%s\"", alg);
	எனில் ((r = rsa_hash_alg_oid(hashalg, &oid, &oid_len)) != 0)
		fatal_fr(r, "rsa_hash_alg_oid failed");
	எனில் ((dgst_len = ssh_digest_bytes(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);

	/* Prepare { oid || digest } */
	oid_dgst_len = oid_len + dgst_len;
	oid_dgst = xcalloc(1, oid_dgst_len);
	memcpy(oid_dgst, oid, oid_len);
	எனில் ((r = ssh_digest_memory(hashalg, data, datalen,
	    oid_dgst + oid_len, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	எனில் ((rv = f->C_Sign(si->session, (CK_BYTE *)oid_dgst,
	    oid_dgst_len, sig, &slen)) != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		செல் done;
	}

	எனில் (slen < (CK_ULONG)siglen) {
		diff = siglen - slen;
		debug3_f("repack %lu < %d (diff %d)",
		    (u_long)slen, siglen, diff);
		memmove(sig + diff, sig, slen);
		explicit_bzero(sig, diff);
	} இல்லையெனில் எனில் (slen > (size_t)siglen)
		fatal_f("bad C_Sign length");

	எனில் ((ret = ssh_rsa_encode_store_sig(hashalg, sig, siglen,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	freezero(oid_dgst, oid_dgst_len);
	விடுவி(sig);
	திரும்பு ret;
}

நிலையான முழு
pkcs11_sign_ecdsa(கட்டமைப்பு sshkey *சாவி,
    u_char **sigp, size_t *lenp,
    மாறிலி u_char *data, size_t datalen,
    மாறிலி எழுத்து *alg, மாறிலி எழுத்து *sk_provider,
    மாறிலி எழுத்து *sk_pin, u_int compat)
{
	கட்டமைப்பு pkcs11_சாவி	*k11;
	கட்டமைப்பு pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0, bnlen;
	CK_RV			rv;
	BIGNUM			*sig_r = வெற்று, *sig_s = வெற்று;
	u_char			*sig = வெற்று, *dgst = வெற்று;
	size_t			dgst_len = 0;
	முழு			hashalg, ret = -1, r, siglen;

	எனில் (sigp != வெற்று)
		*sigp = வெற்று;
	எனில் (lenp != வெற்று)
		*lenp = 0;

	எனில் ((k11 = pkcs11_lookup_சாவி(சாவி)) == வெற்று) {
		error_f("no key found");
		திரும்பு SSH_ERR_சாவி_NOT_FOUND;
	}

	எனில் (pkcs11_get_சாவி(k11, CKM_ECDSA) == -1) {
		error("pkcs11_get_key failed");
		திரும்பு SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	/* Prepare digest to be signed */
	எனில் ((hashalg = sshkey_ec_nid_to_hash_alg(சாவி->ecdsa_nid)) == -1)
		fatal_f("couldn't determine ECDSA hash alg");
	எனில் ((dgst_len = ssh_digest_bytes(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);
	dgst = xcalloc(1, dgst_len);
	எனில் ((r = ssh_digest_memory(hashalg, data, datalen,
	    dgst, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	எனில் ((siglen = EVP_PKEY_size(சாவி->pkey)) <= 0)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dgst_len, sig, &slen);
	எனில் (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		செல் done;
	}
	எனில் (slen < 64 || slen > 132 || slen % 2) {
		error_f("bad signature length: %lu", (u_long)slen);
		செல் done;
	}
	bnlen = slen/2;
	எனில் ((sig_r = BN_bin2bn(sig, bnlen, வெற்று)) == வெற்று ||
	    (sig_s = BN_bin2bn(sig+bnlen, bnlen, வெற்று)) == வெற்று) {
		ossl_error("BN_bin2bn failed");
		செல் done;
	}

	எனில் ((ret = ssh_ecdsa_encode_store_sig(சாவி, sig_r, sig_s,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	freezero(dgst, dgst_len);
	BN_free(sig_r);
	BN_free(sig_s);
	விடுவி(sig);
	திரும்பு ret;
}
#endif /* WITH_OPENSSL */

நிலையான முழு
pkcs11_sign_ed25519(கட்டமைப்பு sshkey *சாவி,
    u_char **sigp, size_t *lenp,
    மாறிலி u_char *data, size_t datalen,
    மாறிலி எழுத்து *alg, மாறிலி எழுத்து *sk_provider,
    மாறிலி எழுத்து *sk_pin, u_int compat)
{
	கட்டமைப்பு pkcs11_சாவி	*k11;
	கட்டமைப்பு pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	u_char			*sig = வெற்று;
	CK_BYTE			*xdata = வெற்று;
	முழு			ret = -1;

	எனில் (sigp != வெற்று)
		*sigp = வெற்று;
	எனில் (lenp != வெற்று)
		*lenp = 0;

	எனில் ((k11 = pkcs11_lookup_சாவி(சாவி)) == வெற்று) {
		error_f("no key found");
		திரும்பு SSH_ERR_சாவி_NOT_FOUND;
	}

	எனில் (pkcs11_get_சாவி(k11, CKM_EDDSA) == -1) {
		error("pkcs11_get_key failed");
		திரும்பு SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	xdata = xmalloc(datalen);
	memcpy(xdata, data, datalen);
	sig = xmalloc(crypto_sign_ed25519_BYTES);
	slen = crypto_sign_ed25519_BYTES;

	rv = f->C_Sign(si->session, xdata, datalen, sig, &slen);
	எனில் (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		செல் done;
	}
	எனில் (slen != crypto_sign_ed25519_BYTES) {
		error_f("bad signature length: %lu", (u_long)slen);
		செல் done;
	}
	எனில் ((ret = ssh_ed25519_encode_store_sig(sig, slen, sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	எனில் (xdata != வெற்று)
		freezero(xdata, datalen);
	விடுவி(sig);
	திரும்பு ret;
}

/* remove trailing spaces */
நிலையான எழுத்து *
rmspace(u_char *buf, size_t len)
{
	size_t i;

	எனில் (len == 0)
		திரும்பு buf;
	க்கு (i = len - 1; i > 0; i--)
		எனில் (buf[i] == ' ')
			buf[i] = '\0';
		இல்லையெனில்
			நிறுத்து;
	திரும்பு buf;
}
/* Used to printf fixed-width, space-padded, unterminated strings using %.*s */
#define RMSPACE(s) (முழு)அளவு(s), rmspace(s, அளவு(s))

/*
 * open a pkcs11 session and login if required.
 * if pin == NULL we delay login until key use
 */
நிலையான முழு
pkcs11_open_session(கட்டமைப்பு pkcs11_provider *p, CK_ULONG slotidx, எழுத்து *pin,
    CK_ULONG user)
{
	கட்டமைப்பு pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_RV			rv;
	CK_SESSION_HANDLE	session;
	முழு			login_required, ret;

	f = p->function_list;
	si = &p->slotinfo[slotidx];

	login_required = si->token.flags & CKF_LOGIN_REQUIRED;

	/* fail early before opening session */
	எனில் (login_required && !pkcs11_interactive &&
	    (pin == வெற்று || strlen(pin) == 0)) {
		error("pin required");
		திரும்பு (-SSH_PKCS11_ERR_PIN_REQUIRED);
	}
	எனில் ((rv = f->C_OpenSession(p->slotlist[slotidx], CKF_RW_SESSION|
	    CKF_SERIAL_SESSION, வெற்று, வெற்று, &session)) != CKR_OK) {
		error("C_OpenSession failed: %lu", rv);
		திரும்பு (-1);
	}
	எனில் (login_required && pin != வெற்று && strlen(pin) != 0) {
		rv = f->C_Login(session, user, (u_char *)pin, strlen(pin));
		எனில் (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
			error("C_Login failed: %lu", rv);
			ret = (rv == CKR_PIN_LOCKED) ?
			    -SSH_PKCS11_ERR_PIN_LOCKED :
			    -SSH_PKCS11_ERR_LOGIN_FAIL;
			எனில் ((rv = f->C_CloseSession(session)) != CKR_OK)
				error("C_CloseSession failed: %lu", rv);
			திரும்பு (ret);
		}
		si->logged_in = 1;
	}
	si->session = session;
	திரும்பு (0);
}

நிலையான முழு
pkcs11_சாவி_included(கட்டமைப்பு sshkey ***keysp, முழு *nkeys, கட்டமைப்பு sshkey *சாவி)
{
	முழு i;

	க்கு (i = 0; i < *nkeys; i++)
		எனில் (sshkey_equal(சாவி, (*keysp)[i]))
			திரும்பு (1);
	திரும்பு (0);
}

#ifdef WITH_OPENSSL
நிலையான கட்டமைப்பு sshkey *
pkcs11_fetch_ecdsa_pubkey(கட்டமைப்பு pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 சாவி_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = வெற்று;
	CK_RV			 rv;
	ASN1_OCTET_STRING	*octet = வெற்று;
	EC_சாவி			*ec = வெற்று;
	EC_GROUP		*group = வெற்று;
	கட்டமைப்பு sshkey		*சாவி = வெற்று;
	மாறிலி unsigned எழுத்து	*attrp = வெற்று;
	முழு			 success = -1, r, i, nid;

	memset(&சாவி_attr, 0, அளவு(சாவி_attr));
	சாவி_attr[0].type = CKA_ID;
	சாவி_attr[1].type = CKA_EC_POINT;
	சாவி_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_மதிப்பு(session, *obj, சாவி_attr, 3);
	எனில் (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		திரும்பு (வெற்று);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	எனில் (சாவி_attr[1].ul_மதிப்பு_Len == 0 ||
	    சாவி_attr[2].ul_மதிப்பு_Len == 0) {
		error("invalid attribute length");
		திரும்பு (வெற்று);
	}

	/* allocate buffers for attributes */
	க்கு (i = 0; i < 3; i++)
		எனில் (சாவி_attr[i].ul_மதிப்பு_Len > 0)
			சாவி_attr[i].p_மதிப்பு = xcalloc(1, சாவி_attr[i].ul_மதிப்பு_Len);

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_மதிப்பு(session, *obj, சாவி_attr, 3);
	எனில் (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		செல் fail;
	}

	ec = EC_சாவி_new();
	எனில் (ec == வெற்று) {
		error("EC_KEY_new failed");
		செல் fail;
	}

	attrp = சாவி_attr[2].p_மதிப்பு;
	group = d2i_ECPKParameters(வெற்று, &attrp, சாவி_attr[2].ul_மதிப்பு_Len);
	எனில் (group == வெற்று) {
		ossl_error("d2i_ECPKParameters failed");
		செல் fail;
	}

	எனில் (EC_சாவி_set_group(ec, group) == 0) {
		ossl_error("EC_KEY_set_group failed");
		செல் fail;
	}

	எனில் (சாவி_attr[1].ul_மதிப்பு_Len <= 2) {
		error("CKA_EC_POINT too small");
		செல் fail;
	}

	attrp = சாவி_attr[1].p_மதிப்பு;
	octet = d2i_ASN1_OCTET_STRING(வெற்று, &attrp, சாவி_attr[1].ul_மதிப்பு_Len);
	எனில் (octet == வெற்று) {
		ossl_error("d2i_ASN1_OCTET_STRING failed");
		செல் fail;
	}
	attrp = ASN1_STRING_get0_data(octet);
	எனில் (o2i_ECPublic_சாவி(&ec, &attrp, ASN1_STRING_length(octet)) == வெற்று) {
		ossl_error("o2i_ECPublicKey failed");
		செல் fail;
	}
	எனில் ((r = sshkey_ec_validate_public(EC_சாவி_get0_group(ec),
	    EC_சாவி_get0_public_சாவி(ec))) != 0) {
		error_fr(r, "invalid EC key");
		செல் fail;
	}

	nid = sshkey_ecdsa_சாவி_to_nid(ec);
	எனில் (nid < 0) {
		error("couldn't get curve nid");
		செல் fail;
	}

	சாவி = sshkey_new(சாவி_UNSPEC);
	எனில் (சாவி == வெற்று) {
		error("sshkey_new failed");
		செல் fail;
	}

	EVP_PKEY_free(சாவி->pkey);
	எனில் ((சாவி->pkey = EVP_PKEY_new()) == வெற்று)
		fatal("EVP_PKEY_new failed");
	எனில் (EVP_PKEY_set1_EC_சாவி(சாவி->pkey, ec) != 1)
		fatal("EVP_PKEY_set1_EC_KEY failed");
	சாவி->ecdsa_nid = nid;
	சாவி->type = சாவி_ECDSA;
	சாவி->flags |= SSHKEY_FLAG_EXT;
	எனில் (pkcs11_record_சாவி(p, slotidx, &சாவி_attr[0], சாவி))
		செல் fail;
	/* success */
	success = 0;
fail:
	எனில் (success != 0) {
		sshkey_free(சாவி);
		சாவி = வெற்று;
	}
	க்கு (i = 0; i < 3; i++)
		விடுவி(சாவி_attr[i].p_மதிப்பு);
	எனில் (ec)
		EC_சாவி_free(ec);
	எனில் (group)
		EC_GROUP_free(group);
	எனில் (octet)
		ASN1_OCTET_STRING_free(octet);

	திரும்பு (சாவி);
}

நிலையான கட்டமைப்பு sshkey *
pkcs11_fetch_rsa_pubkey(கட்டமைப்பு pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 சாவி_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = வெற்று;
	CK_RV			 rv;
	RSA			*rsa = வெற்று;
	BIGNUM			*rsa_n, *rsa_e;
	கட்டமைப்பு sshkey		*சாவி = வெற்று;
	முழு			 i, success = -1;

	memset(&சாவி_attr, 0, அளவு(சாவி_attr));
	சாவி_attr[0].type = CKA_ID;
	சாவி_attr[1].type = CKA_MODULUS;
	சாவி_attr[2].type = CKA_PUBLIC_EXPONENT;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_மதிப்பு(session, *obj, சாவி_attr, 3);
	எனில் (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		திரும்பு (வெற்று);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	எனில் (சாவி_attr[1].ul_மதிப்பு_Len == 0 ||
	    சாவி_attr[2].ul_மதிப்பு_Len == 0) {
		error("invalid attribute length");
		திரும்பு (வெற்று);
	}

	/* allocate buffers for attributes */
	க்கு (i = 0; i < 3; i++)
		எனில் (சாவி_attr[i].ul_மதிப்பு_Len > 0)
			சாவி_attr[i].p_மதிப்பு = xcalloc(1, சாவி_attr[i].ul_மதிப்பு_Len);

	/* retrieve ID, modulus and public exponent of RSA key */
	rv = f->C_Get_Attribute_மதிப்பு(session, *obj, சாவி_attr, 3);
	எனில் (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		செல் fail;
	}

	rsa = RSA_new();
	எனில் (rsa == வெற்று) {
		error("RSA_new failed");
		செல் fail;
	}

	rsa_n = BN_bin2bn(சாவி_attr[1].p_மதிப்பு, சாவி_attr[1].ul_மதிப்பு_Len, வெற்று);
	rsa_e = BN_bin2bn(சாவி_attr[2].p_மதிப்பு, சாவி_attr[2].ul_மதிப்பு_Len, வெற்று);
	எனில் (rsa_n == வெற்று || rsa_e == வெற்று) {
		error("BN_bin2bn failed");
		செல் fail;
	}
	எனில் (!RSA_set0_சாவி(rsa, rsa_n, rsa_e, வெற்று))
		fatal_f("set key");
	rsa_n = rsa_e = வெற்று; /* transferred */

	சாவி = sshkey_new(சாவி_UNSPEC);
	எனில் (சாவி == வெற்று) {
		error("sshkey_new failed");
		செல் fail;
	}

	EVP_PKEY_free(சாவி->pkey);
	எனில் ((சாவி->pkey = EVP_PKEY_new()) == வெற்று)
		fatal("EVP_PKEY_new failed");
	எனில் (EVP_PKEY_set1_RSA(சாவி->pkey, rsa) != 1)
		fatal("EVP_PKEY_set1_RSA failed");
	சாவி->type = சாவி_RSA;
	சாவி->flags |= SSHKEY_FLAG_EXT;
	எனில் (EVP_PKEY_bits(சாவி->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE) {
		error_f("RSA key too small %d < minimum %d",
		    EVP_PKEY_bits(சாவி->pkey), SSH_RSA_MINIMUM_MODULUS_SIZE);
		செல் fail;
	}
	எனில் (pkcs11_record_சாவி(p, slotidx, &சாவி_attr[0], சாவி))
		செல் fail;
	/* success */
	success = 0;
fail:
	க்கு (i = 0; i < 3; i++)
		விடுவி(சாவி_attr[i].p_மதிப்பு);
	RSA_free(rsa);
	எனில் (success != 0) {
		sshkey_free(சாவி);
		சாவி = வெற்று;
	}
	திரும்பு சாவி;
}
#endif /* WITH_OPENSSL */

நிலையான கட்டமைப்பு sshkey *
pkcs11_fetch_ed25519_pubkey(கட்டமைப்பு pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 சாவி_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = வெற்று;
	CK_RV			 rv;
	கட்டமைப்பு sshkey		*சாவி = வெற்று;
	மாறிலி unsigned எழுத்து	*d = வெற்று;
	size_t			len;
	எழுத்து			*hex = வெற்று;
	முழு			 success = -1, i;
	/* https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061180 */
	மாறிலி u_char		 id1[14] = {
		0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64,
		0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
	}; /* PrintableString { "edwards25519" } */
	மாறிலி u_char		 id2[5] = {
		0x06, 0x03, 0x2b, 0x65, 0x70,
	}; /* OBJECT_IDENTIFIER { 1.3.101.112 } */

	memset(&சாவி_attr, 0, அளவு(சாவி_attr));
	சாவி_attr[0].type = CKA_ID;
	சாவி_attr[1].type = CKA_EC_POINT; /* XXX or CKA_VALUE ? */
	சாவி_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_மதிப்பு(session, *obj, சாவி_attr, 3);
	எனில் (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		திரும்பு (வெற்று);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	எனில் (சாவி_attr[1].ul_மதிப்பு_Len == 0 ||
	    சாவி_attr[2].ul_மதிப்பு_Len == 0) {
		error("invalid attribute length");
		திரும்பு (வெற்று);
	}

	/* allocate buffers for attributes */
	க்கு (i = 0; i < 3; i++) {
		எனில் (சாவி_attr[i].ul_மதிப்பு_Len > 0)
			சாவி_attr[i].p_மதிப்பு = xcalloc(1, சாவி_attr[i].ul_மதிப்பு_Len);
	}

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_மதிப்பு(session, *obj, சாவி_attr, 3);
	எனில் (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		செல் fail;
	}

	/* Expect one of the supported identifiers in CKA_EC_PARAMS */
	d = (u_char *)சாவி_attr[2].p_மதிப்பு;
	len = சாவி_attr[2].ul_மதிப்பு_Len;
	எனில் ((len != அளவு(id1) || memcmp(d, id1, அளவு(id1)) != 0) &&
	    (len != அளவு(id2) || memcmp(d, id2, அளவு(id2)) != 0)) {
		hex = tohex(d, len);
		logit_f("unsupported CKA_EC_PARAMS: %s (len %zu)", hex, len);
		செல் fail;
	}

	/*
	 * Expect either a raw 32 byte pubkey or an OCTET STRING with
	 * a 32 byte pubkey in CKA_VALUE
	 */
	d = (u_char *)சாவி_attr[1].p_மதிப்பு;
	len = சாவி_attr[1].ul_மதிப்பு_Len;
	எனில் (len == ED25519_PK_SZ + 2 && d[0] == 0x04 && d[1] == ED25519_PK_SZ) {
		d += 2;
		len -= 2;
	}
	எனில் (len != ED25519_PK_SZ) {
		hex = tohex(சாவி_attr[1].p_மதிப்பு, சாவி_attr[1].ul_மதிப்பு_Len);
		logit_f("CKA_EC_POINT invalid octet str: %s (len %lu)",
		    hex, (u_long)சாவி_attr[1].ul_மதிப்பு_Len);
		செல் fail;
	}

	எனில் ((சாவி = sshkey_new(சாவி_UNSPEC)) == வெற்று)
		fatal_f("sshkey_new failed");
	சாவி->ed25519_pk = xmalloc(ED25519_PK_SZ);
	memcpy(சாவி->ed25519_pk, d, ED25519_PK_SZ);
	சாவி->type = சாவி_ED25519;
	சாவி->flags |= SSHKEY_FLAG_EXT;
	எனில் (pkcs11_record_சாவி(p, slotidx, &சாவி_attr[0], சாவி))
		செல் fail;
	/* success */
	success = 0;
 fail:
	எனில் (success != 0) {
		sshkey_free(சாவி);
		சாவி = வெற்று;
	}
	விடுவி(hex);
	க்கு (i = 0; i < 3; i++)
		விடுவி(சாவி_attr[i].p_மதிப்பு);
	திரும்பு சாவி;
}

#ifdef WITH_OPENSSL
நிலையான முழு
pkcs11_fetch_x509_pubkey(கட்டமைப்பு pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj, கட்டமைப்பு sshkey **keyp, எழுத்து **labelp)
{
	CK_ATTRIBUTE		 cert_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = வெற்று;
	CK_RV			 rv;
	X509			*x509 = வெற்று;
	X509_NAME		*x509_name = வெற்று;
	EVP_PKEY		*evp;
	RSA			*rsa = வெற்று;
	EC_சாவி			*ec = வெற்று;
	கட்டமைப்பு sshkey		*சாவி = வெற்று;
	முழு			 r, i, nid, success = -1;
	மாறிலி u_char		*cp;
	எழுத்து			*subject = வெற்று;
#ifdef OPENSSL_HAS_ED25519
	size_t			len;
#endif /* OPENSSL_HAS_ED25519 */

	*keyp = வெற்று;
	*labelp = வெற்று;

	memset(&cert_attr, 0, அளவு(cert_attr));
	cert_attr[0].type = CKA_ID;
	cert_attr[1].type = CKA_SUBJECT;
	cert_attr[2].type = CKA_மதிப்பு;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_மதிப்பு(session, *obj, cert_attr, 3);
	எனில் (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		திரும்பு -1;
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	எனில் (cert_attr[1].ul_மதிப்பு_Len == 0 ||
	    cert_attr[2].ul_மதிப்பு_Len == 0) {
		error("invalid attribute length");
		திரும்பு -1;
	}

	/* allocate buffers for attributes */
	க்கு (i = 0; i < 3; i++)
		எனில் (cert_attr[i].ul_மதிப்பு_Len > 0)
			cert_attr[i].p_மதிப்பு = xcalloc(1, cert_attr[i].ul_மதிப்பு_Len);

	/* retrieve ID, subject and value of certificate */
	rv = f->C_Get_Attribute_மதிப்பு(session, *obj, cert_attr, 3);
	எனில் (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		செல் out;
	}

	/* Decode DER-encoded cert subject */
	cp = cert_attr[1].p_மதிப்பு;
	எனில் ((x509_name = d2i_X509_NAME(வெற்று, &cp,
	    cert_attr[1].ul_மதிப்பு_Len)) == வெற்று ||
	    (subject = X509_NAME_oneline(x509_name, வெற்று, 0)) == வெற்று)
		subject = xstrdup("invalid subject");
	X509_NAME_free(x509_name);

	cp = cert_attr[2].p_மதிப்பு;
	எனில் ((x509 = d2i_X509(வெற்று, &cp, cert_attr[2].ul_மதிப்பு_Len)) == வெற்று) {
		error("d2i_x509 failed");
		செல் out;
	}

	எனில் ((evp = X509_get_pubkey(x509)) == வெற்று) {
		error("X509_get_pubkey failed");
		செல் out;
	}

	எனில் (EVP_PKEY_base_id(evp) == EVP_PKEY_RSA) {
		எனில் (EVP_PKEY_get0_RSA(evp) == வெற்று) {
			error("invalid x509; no rsa key");
			செல் out;
		}
		எனில் ((rsa = RSAPublic_சாவி_dup(EVP_PKEY_get0_RSA(evp))) == வெற்று) {
			error("RSAPublicKey_dup failed");
			செல் out;
		}

		சாவி = sshkey_new(சாவி_UNSPEC);
		எனில் (சாவி == வெற்று) {
			error("sshkey_new failed");
			செல் out;
		}

		EVP_PKEY_free(சாவி->pkey);
		எனில் ((சாவி->pkey = EVP_PKEY_new()) == வெற்று)
			fatal("EVP_PKEY_new failed");
		எனில் (EVP_PKEY_set1_RSA(சாவி->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		சாவி->type = சாவி_RSA;
		சாவி->flags |= SSHKEY_FLAG_EXT;
		எனில் (EVP_PKEY_bits(சாவி->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE) {
			error_f("RSA key too small %d < minimum %d",
			    EVP_PKEY_bits(சாவி->pkey),
			    SSH_RSA_MINIMUM_MODULUS_SIZE);
			செல் out;
		}
		எனில் (pkcs11_record_சாவி(p, slotidx, &cert_attr[0], சாவி))
			செல் out;
		/* success */
		success = 0;
	} இல்லையெனில் எனில் (EVP_PKEY_base_id(evp) == EVP_PKEY_EC) {
		எனில் (EVP_PKEY_get0_EC_சாவி(evp) == வெற்று) {
			error("invalid x509; no ec key");
			செல் out;
		}
		எனில் ((ec = EC_சாவி_dup(EVP_PKEY_get0_EC_சாவி(evp))) == வெற்று) {
			error("EC_KEY_dup failed");
			செல் out;
		}
		எனில் ((r = sshkey_ec_validate_public(EC_சாவி_get0_group(ec),
		    EC_சாவி_get0_public_சாவி(ec))) != 0) {
			error_fr(r, "invalid EC key");
			செல் out;
		}
		nid = sshkey_ecdsa_சாவி_to_nid(ec);
		எனில் (nid < 0) {
			error("couldn't get curve nid");
			செல் out;
		}

		சாவி = sshkey_new(சாவி_UNSPEC);
		எனில் (சாவி == வெற்று) {
			error("sshkey_new failed");
			செல் out;
		}

		EVP_PKEY_free(சாவி->pkey);
		எனில் ((சாவி->pkey = EVP_PKEY_new()) == வெற்று)
			fatal("EVP_PKEY_new failed");
		எனில் (EVP_PKEY_set1_EC_சாவி(சாவி->pkey, ec) != 1)
			fatal("EVP_PKEY_set1_EC_KEY failed");
		சாவி->ecdsa_nid = nid;
		சாவி->type = சாவி_ECDSA;
		சாவி->flags |= SSHKEY_FLAG_EXT;
		எனில் (pkcs11_record_சாவி(p, slotidx, &cert_attr[0], சாவி))
			செல் out;
		/* success */
		success = 0;
#ifdef OPENSSL_HAS_ED25519
	} இல்லையெனில் எனில் (EVP_PKEY_base_id(evp) == EVP_PKEY_ED25519) {
		எனில் ((சாவி = sshkey_new(சாவி_UNSPEC)) == வெற்று ||
		    (சாவி->ed25519_pk = calloc(1, ED25519_PK_SZ)) == வெற்று)
			fatal_f("allocation failed");
		len = ED25519_PK_SZ;
		எனில் (!EVP_PKEY_get_raw_public_சாவி(evp, சாவி->ed25519_pk, &len)) {
			ossl_error("EVP_PKEY_get_raw_public_key failed");
			செல் out;
		}
		எனில் (len != ED25519_PK_SZ) {
			error_f("incorrect returned public key "
			    "length for ed25519");
			செல் out;
		}
		சாவி->type = சாவி_ED25519;
		சாவி->flags |= SSHKEY_FLAG_EXT;
		எனில் (pkcs11_record_சாவி(p, slotidx, &cert_attr[0], சாவி))
			செல் out;
		/* success */
		success = 0;
#endif /* OPENSSL_HAS_ED25519 */
	} இல்லையெனில் {
		error("unknown certificate key type");
		செல் out;
	}
 out:
	க்கு (i = 0; i < 3; i++)
		விடுவி(cert_attr[i].p_மதிப்பு);
	X509_free(x509);
	RSA_free(rsa);
	EC_சாவி_free(ec);
	எனில் (success != 0 || சாவி == வெற்று) {
		sshkey_free(சாவி);
		விடுவி(subject);
		திரும்பு -1;
	}
	/* success */
	*keyp = சாவி;
	*labelp = subject;
	திரும்பு 0;
}
#endif /* WITH_OPENSSL */

நிலையான வெறுமை
note_சாவி(கட்டமைப்பு pkcs11_provider *p, CK_ULONG slotidx, மாறிலி எழுத்து *context,
    கட்டமைப்பு sshkey *சாவி)
{
	எழுத்து *fp;

	எனில் ((fp = sshkey_fingerprint(சாவி, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == வெற்று) {
		error_f("sshkey_fingerprint failed");
		திரும்பு;
	}
	debug2("%s: provider %s slot %lu: %s %s", context, p->name,
	    (u_long)slotidx, sshkey_type(சாவி), fp);
	விடுவி(fp);
}

#ifdef WITH_OPENSSL /* libcrypto needed for certificate parsing */
/*
 * lookup certificates for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
நிலையான முழு
pkcs11_fetch_certs(கட்டமைப்பு pkcs11_provider *p, CK_ULONG slotidx,
    கட்டமைப்பு sshkey ***keysp, எழுத்து ***labelsp, முழு *nkeys)
{
	கட்டமைப்பு sshkey		*சாவி = வெற்று;
	CK_OBJECT_CLASS		 சாவி_class;
	CK_ATTRIBUTE		 சாவி_attr[1];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = வெற்று;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	முழு			 ret = -1;
	எழுத்து			*label;

	memset(&சாவி_attr, 0, அளவு(சாவி_attr));
	memset(&obj, 0, அளவு(obj));

	சாவி_class = CKO_CERTIFICATE;
	சாவி_attr[0].type = CKA_CLASS;
	சாவி_attr[0].p_மதிப்பு = &சாவி_class;
	சாவி_attr[0].ul_மதிப்பு_Len = அளவு(சாவி_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, சாவி_attr, 1);
	எனில் (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		செல் fail;
	}

	போது (1) {
		CK_CERTIFICATE_TYPE	ck_cert_type;

		rv = f->C_FindObjects(session, &obj, 1, &n);
		எனில் (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			செல் fail;
		}
		எனில் (n == 0)
			நிறுத்து;

		memset(&ck_cert_type, 0, அளவு(ck_cert_type));
		memset(&சாவி_attr, 0, அளவு(சாவி_attr));
		சாவி_attr[0].type = CKA_CERTIFICATE_TYPE;
		சாவி_attr[0].p_மதிப்பு = &ck_cert_type;
		சாவி_attr[0].ul_மதிப்பு_Len = அளவு(ck_cert_type);

		rv = f->C_Get_Attribute_மதிப்பு(session, obj, சாவி_attr, 1);
		எனில் (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			செல் fail;
		}

		சாவி = வெற்று;
		label = வெற்று;
		தேர்வு (ck_cert_type) {
		நிலை CKC_X_509:
			எனில் (pkcs11_fetch_x509_pubkey(p, slotidx, &obj,
			    &சாவி, &label) != 0) {
				debug_f("failed to fetch key");
				தொடர்;
			}
			நிறுத்து;
		இயல்பு:
			error("skipping unsupported certificate type %lu",
			    ck_cert_type);
			தொடர்;
		}
		note_சாவி(p, slotidx, __func__, சாவி);
		எனில் (pkcs11_சாவி_included(keysp, nkeys, சாவி)) {
			debug2_f("key already included");
			sshkey_free(சாவி);
		} இல்லையெனில் {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, அளவு(கட்டமைப்பு sshkey *));
			(*keysp)[*nkeys] = சாவி;
			எனில் (labelsp != வெற்று) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, அளவு(எழுத்து *));
				(*labelsp)[*nkeys] = xstrdup((எழுத்து *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_FindObjectsFinal(session);
	எனில் (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	திரும்பு (ret);
}
#endif /* WITH_OPENSSL */

/*
 * lookup public keys for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
நிலையான முழு
pkcs11_fetch_சாவிகள்(கட்டமைப்பு pkcs11_provider *p, CK_ULONG slotidx,
    கட்டமைப்பு sshkey ***keysp, எழுத்து ***labelsp, முழு *nkeys)
{
	கட்டமைப்பு sshkey		*சாவி = வெற்று;
	CK_OBJECT_CLASS		 சாவி_class;
	CK_ATTRIBUTE		 சாவி_attr[2];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = வெற்று;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	முழு			 ret = -1;

	memset(&சாவி_attr, 0, அளவு(சாவி_attr));
	memset(&obj, 0, அளவு(obj));

	சாவி_class = CKO_PUBLIC_சாவி;
	சாவி_attr[0].type = CKA_CLASS;
	சாவி_attr[0].p_மதிப்பு = &சாவி_class;
	சாவி_attr[0].ul_மதிப்பு_Len = அளவு(சாவி_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, சாவி_attr, 1);
	எனில் (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		செல் fail;
	}

	போது (1) {
		CK_சாவி_TYPE	ck_சாவி_type;
		CK_UTF8CHAR	label[256];

		rv = f->C_FindObjects(session, &obj, 1, &n);
		எனில் (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			செல் fail;
		}
		எனில் (n == 0)
			நிறுத்து;

		memset(&ck_சாவி_type, 0, அளவு(ck_சாவி_type));
		memset(&சாவி_attr, 0, அளவு(சாவி_attr));
		சாவி_attr[0].type = CKA_சாவி_TYPE;
		சாவி_attr[0].p_மதிப்பு = &ck_சாவி_type;
		சாவி_attr[0].ul_மதிப்பு_Len = அளவு(ck_சாவி_type);
		சாவி_attr[1].type = CKA_LABEL;
		சாவி_attr[1].p_மதிப்பு = &label;
		சாவி_attr[1].ul_மதிப்பு_Len = அளவு(label) - 1;

		rv = f->C_Get_Attribute_மதிப்பு(session, obj, சாவி_attr, 2);
		எனில் (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			செல் fail;
		}

		label[சாவி_attr[1].ul_மதிப்பு_Len] = '\0';

		தேர்வு (ck_சாவி_type) {
#ifdef WITH_OPENSSL
		நிலை CKK_RSA:
			சாவி = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			நிறுத்து;
		நிலை CKK_ECDSA:
			சாவி = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			நிறுத்து;
#endif /* WITH_OPENSSL */
		நிலை CKK_EC_EDWARDS:
			சாவி = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			நிறுத்து;
		இயல்பு:
			/* XXX print key type? */
			சாவி = வெற்று;
			error("skipping unsupported key type 0x%lx",
			    (u_long)ck_சாவி_type);
		}

		எனில் (சாவி == வெற்று) {
			debug_f("failed to fetch key");
			தொடர்;
		}
		note_சாவி(p, slotidx, __func__, சாவி);
		எனில் (pkcs11_சாவி_included(keysp, nkeys, சாவி)) {
			debug2_f("key already included");
			sshkey_free(சாவி);
		} இல்லையெனில் {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, அளவு(கட்டமைப்பு sshkey *));
			(*keysp)[*nkeys] = சாவி;
			எனில் (labelsp != வெற்று) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, அளவு(எழுத்து *));
				(*labelsp)[*nkeys] = xstrdup((எழுத்து *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_FindObjectsFinal(session);
	எனில் (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	திரும்பு (ret);
}

#ifdef WITH_PKCS11_KEYGEN
#define FILL_ATTR(attr, idx, typ, val, len) \
	{ (attr[idx]).type=(typ); (attr[idx]).p_மதிப்பு=(val); (attr[idx]).ul_மதிப்பு_Len=len; idx++; }

நிலையான கட்டமைப்பு sshkey *
pkcs11_rsa_generate_private_சாவி(கட்டமைப்பு pkcs11_provider *p, CK_ULONG slotidx,
    எழுத்து *label, CK_ULONG bits, CK_BYTE keyid, uint32_t *err)
{
	கட்டமைப்பு pkcs11_slotinfo	*si;
	எழுத்து			*plabel = label ? label : "";
	முழு			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_சாவி_2, priv_சாவி;
	CK_ATTRIBUTE		 tpub[16], tpriv[16];
	CK_MECHANISM		 mech = {
	    CKM_RSA_PKCS_சாவி_PAIR_GEN, NULL_PTR, 0
	};
	CK_BYTE			 pubExponent[] = {
	    0x01, 0x00, 0x01 /* RSA_F4 in bytes */
	};
	pubkey_filter[0].p_மதிப்பு = &pubkey_class;
	cert_filter[0].p_மதிப்பு = &cert_class;

	*err = 0;

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, அளவு(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, அளவு(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, அளவு(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    அளவு(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, அளவு(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, அளவு(false_val));
	FILL_ATTR(tpub, npub, CKA_MODULUS_BITS, &bits, அளவு(bits));
	FILL_ATTR(tpub, npub, CKA_PUBLIC_EXPONENT, pubExponent,
	    அளவு(pubExponent));
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, அளவு(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN,  &true_val, அளவு(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL,  plabel, strlen(plabel));
	FILL_ATTR(tpriv, npriv, CKA_PRIVATE,  &true_val, அளவு(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE,  &true_val, அளவு(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT,  &false_val, அளவு(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN,  &true_val, அளவு(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER,  &false_val,
	    அளவு(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP,  &false_val, அளவு(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE,  &false_val, அளவு(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, அளவு(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	எனில் ((rv = f->C_Generate_சாவி_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_சாவி_2, &priv_சாவி)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		திரும்பு வெற்று;
	}

	திரும்பு pkcs11_fetch_rsa_pubkey(p, slotidx, &pub_சாவி_2);
}

நிலையான முழு
h2i(எழுத்து c)
{
	எனில் (c >= '0' && c <= '9')
		திரும்பு c - '0';
	இல்லையெனில் எனில் (c >= 'a' && c <= 'f')
		திரும்பு c - 'a' + 10;
	இல்லையெனில் எனில் (c >= 'A' && c <= 'F')
		திரும்பு c - 'A' + 10;
	இல்லையெனில்
		திரும்பு -1;
}

நிலையான முழு
pkcs11_decode_hex(மாறிலி எழுத்து *hex, unsigned எழுத்து **dest, size_t *rlen)
{
	size_t	i, len;

	எனில் (dest)
		*dest = வெற்று;
	எனில் (rlen)
		*rlen = 0;

	எனில் ((len = strlen(hex)) % 2)
		திரும்பு -1;
	len /= 2;

	*dest = xmalloc(len);

	க்கு (i = 0; i < len; i++) {
		முழு hi, lo;

		hi = h2i(hex[2 * i]);
		lo = h2i(hex[(2 * i) + 1]);
		எனில் (hi == -1 || lo == -1)
			திரும்பு -1;
		(*dest)[i] = (hi << 4) | lo;
	}

	எனில் (rlen)
		*rlen = len;

	திரும்பு 0;
}

நிலையான கட்டமைப்பு ec_curve_info {
	மாறிலி எழுத்து	*name;
	மாறிலி எழுத்து	*oid;
	மாறிலி எழுத்து	*oid_encoded;
	size_t		 size;
} ec_curve_infos[] = {
	{"prime256v1",	"1.2.840.10045.3.1.7",	"06082A8648CE3D030107", 256},
	{"secp384r1",	"1.3.132.0.34",		"06052B81040022",	384},
	{"secp521r1",	"1.3.132.0.35",		"06052B81040023",	521},
	{வெற்று,		வெற்று,			வெற்று,			0},
};

நிலையான கட்டமைப்பு sshkey *
pkcs11_ecdsa_generate_private_சாவி(கட்டமைப்பு pkcs11_provider *p, CK_ULONG slotidx,
    எழுத்து *label, CK_ULONG bits, CK_BYTE keyid, uint32_t *err)
{
	கட்டமைப்பு pkcs11_slotinfo	*si;
	எழுத்து			*plabel = label ? label : "";
	முழு			 i;
	size_t			 ecparams_size;
	unsigned எழுத்து		*ecparams = வெற்று;
	முழு			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_சாவி_2, priv_சாவி;
	CK_MECHANISM		 mech = {
	    CKM_EC_சாவி_PAIR_GEN, NULL_PTR, 0
	};
	CK_ATTRIBUTE		 tpub[16], tpriv[16];

	*err = 0;

	க்கு (i = 0; ec_curve_infos[i].name; i++) {
		எனில் (ec_curve_infos[i].size == bits)
			நிறுத்து;
	}
	எனில் (!ec_curve_infos[i].name) {
		error_f("invalid key size %lu", bits);
		திரும்பு வெற்று;
	}
	எனில் (pkcs11_decode_hex(ec_curve_infos[i].oid_encoded, &ecparams,
	    &ecparams_size) == -1) {
		error_f("invalid oid");
		திரும்பு வெற்று;
	}

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, அளவு(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, அளவு(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, அளவு(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    அளவு(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, அளவு(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, அளவு(false_val));
	FILL_ATTR(tpub, npub, CKA_EC_PARAMS, ecparams, ecparams_size);
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, அளவு(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN, &true_val, அளவு(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpriv, npriv, CKA_PRIVATE, &true_val, அளவு(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE, &true_val, அளவு(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT, &false_val, அளவு(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN, &true_val, அளவு(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER, &false_val,
	    அளவு(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP, &false_val, அளவு(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE, &false_val, அளவு(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, அளவு(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	எனில் ((rv = f->C_Generate_சாவி_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_சாவி_2, &priv_சாவி)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		திரும்பு வெற்று;
	}

	திரும்பு pkcs11_fetch_ecdsa_pubkey(p, slotidx, &pub_சாவி_2);
}
#endif /* WITH_PKCS11_KEYGEN */

/*
 * register a new provider, fails if provider already exists. if
 * keyp is provided, fetch keys.
 */
நிலையான முழு
pkcs11_register_provider(எழுத்து *provider_id, எழுத்து *pin,
    கட்டமைப்பு sshkey ***keyp, எழுத்து ***labelsp,
    கட்டமைப்பு pkcs11_provider **providerp, CK_ULONG user)
{
	முழு nkeys, need_finalize = 0;
	முழு ret = -1;
	கட்டமைப்பு pkcs11_provider *p = வெற்று;
	வெறுமை *handle = வெற்று;
	CK_RV (*getfunctionlist)(CK_FUNCTION_LIST **);
	CK_RV rv;
	CK_FUNCTION_LIST *f = வெற்று;
	CK_TOKEN_INFO *token;
	CK_ULONG i;

	எனில் (providerp == வெற்று)
		செல் fail;
	*providerp = வெற்று;

	எனில் (keyp != வெற்று)
		*keyp = வெற்று;
	எனில் (labelsp != வெற்று)
		*labelsp = வெற்று;

	எனில் (pkcs11_provider_lookup(provider_id) != வெற்று) {
		debug_f("provider already registered: %s", provider_id);
		செல் fail;
	}
	எனில் (lib_contains_குறியீடு(provider_id, "C_GetFunctionList") != 0) {
		error("provider %s is not a PKCS11 library", provider_id);
		செல் fail;
	}
	/* open shared pkcs11-library */
	எனில் ((handle = dlopen(provider_id, RTLD_NOW)) == வெற்று) {
		error("dlopen %s failed: %s", provider_id, dlerror());
		செல் fail;
	}
	எனில் ((getfunctionlist = dlsym(handle, "C_GetFunctionList")) == வெற்று)
		fatal("dlsym(C_GetFunctionList) failed: %s", dlerror());
	p = xcalloc(1, அளவு(*p));
	p->name = xstrdup(provider_id);
	p->handle = handle;
	/* set up the pkcs11 callbacks */
	எனில் ((rv = (*getfunctionlist)(&f)) != CKR_OK) {
		error("C_GetFunctionList for provider %s failed: %lu",
		    provider_id, rv);
		செல் fail;
	}
	p->function_list = f;
	எனில் ((rv = f->C_Initialize(வெற்று)) != CKR_OK) {
		error("C_Initialize for provider %s failed: %lu",
		    provider_id, rv);
		செல் fail;
	}
	need_finalize = 1;
	எனில் ((rv = f->C_GetInfo(&p->info)) != CKR_OK) {
		error("C_GetInfo for provider %s failed: %lu",
		    provider_id, rv);
		செல் fail;
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
	எனில் ((rv = f->C_GetSlotList(CK_TRUE, வெற்று, &p->nslots)) != CKR_OK) {
		error("C_GetSlotList failed: %lu", rv);
		செல் fail;
	}
	எனில் (p->nslots == 0) {
		debug_f("provider %s returned no slots", provider_id);
		ret = -SSH_PKCS11_ERR_NO_SLOTS;
		செல் fail;
	}
	p->slotlist = xcalloc(p->nslots, அளவு(CK_SLOT_ID));
	எனில் ((rv = f->C_GetSlotList(CK_TRUE, p->slotlist, &p->nslots))
	    != CKR_OK) {
		error("C_GetSlotList for provider %s failed: %lu",
		    provider_id, rv);
		செல் fail;
	}
	p->slotinfo = xcalloc(p->nslots, அளவு(கட்டமைப்பு pkcs11_slotinfo));
	p->valid = 1;
	nkeys = 0;
	க்கு (i = 0; i < p->nslots; i++) {
		token = &p->slotinfo[i].token;
		எனில் ((rv = f->C_GetTokenInfo(p->slotlist[i], token))
		    != CKR_OK) {
			error("C_GetTokenInfo for provider %s slot %lu "
			    "failed: %lu", provider_id, (u_long)i, rv);
			தொடர்;
		}
		எனில் ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
			debug2_f("ignoring uninitialised token in "
			    "provider %s slot %lu", provider_id, (u_long)i);
			தொடர்;
		}
		debug("provider %s slot %lu: label <%.*s> "
		    "manufacturerID <%.*s> model <%.*s> serial <%.*s> "
		    "flags 0x%lx",
		    provider_id, (unsigned long)i,
		    RMSPACE(token->label), RMSPACE(token->manufacturerID),
		    RMSPACE(token->model), RMSPACE(token->serial_எண்_2),
		    token->flags);
		/*
		 * open session, login with pin and retrieve public
		 * keys (if keyp is provided)
		 */
		எனில் ((ret = pkcs11_open_session(p, i, pin, user)) != 0 ||
		    keyp == வெற்று)
			தொடர்;
		pkcs11_fetch_சாவிகள்(p, i, keyp, labelsp, &nkeys);
#ifdef WITH_OPENSSL
		pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#endif
		எனில் (nkeys == 0 && !p->slotinfo[i].logged_in &&
		    pkcs11_interactive) {
			/*
			 * Some tokens require login before they will
			 * expose keys.
			 */
			எனில் (pkcs11_login_slot(p, &p->slotinfo[i],
			    CKU_USER) < 0) {
				error("login failed");
				தொடர்;
			}
			pkcs11_fetch_சாவிகள்(p, i, keyp, labelsp, &nkeys);
#ifdef WITH_OPENSSL
			pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#endif
		}
	}

	/* now owned by caller */
	*providerp = p;

	TAILQ_INSERT_TAIL(&pkcs11_providers, p, next);
	p->refcount++;	/* add to provider list */

	திரும்பு (nkeys);
fail:
	எனில் (need_finalize && (rv = f->C_Finalize(வெற்று)) != CKR_OK)
		error("C_Finalize for provider %s failed: %lu",
		    provider_id, rv);
	எனில் (p) {
		விடுவி(p->name);
		விடுவி(p->slotlist);
		விடுவி(p->slotinfo);
		விடுவி(p);
	}
	எனில் (handle)
		dlclose(handle);
	எனில் (ret > 0)
		ret = -1;
	திரும்பு (ret);
}

முழு
pkcs11_init(முழு interactive)
{
	debug3_f("called, interactive = %d", interactive);

	pkcs11_interactive = interactive;
	TAILQ_INIT(&pkcs11_providers);
	TAILQ_INIT(&pkcs11_சாவிகள்);
	திரும்பு (0);
}

/* unregister all providers, keys might still point to the providers */
வெறுமை
pkcs11_terminate(வெறுமை)
{
	கட்டமைப்பு pkcs11_provider *p;
	கட்டமைப்பு pkcs11_சாவி *k11;

	debug3_f("called");

	போது ((k11 = TAILQ_FIRST(&pkcs11_சாவிகள்)) != வெற்று) {
		TAILQ_REMOVE(&pkcs11_சாவிகள், k11, next);
		pkcs11_k11_free(k11);
	}
	போது ((p = TAILQ_FIRST(&pkcs11_providers)) != வெற்று) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
}

/*
 * register a new provider and get number of keys hold by the token,
 * fails if provider already exists
 */
முழு
pkcs11_add_provider(எழுத்து *provider_id, எழுத்து *pin, கட்டமைப்பு sshkey ***keyp,
    எழுத்து ***labelsp)
{
	கட்டமைப்பு pkcs11_provider *p = வெற்று;
	முழு nkeys;

	nkeys = pkcs11_register_provider(provider_id, pin, keyp, labelsp,
	    &p, CKU_USER);

	/* no keys found or some other error, de-register provider */
	எனில் (nkeys <= 0 && p != வெற்று) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
	எனில் (nkeys == 0)
		debug_f("provider %s returned no keys", provider_id);

	திரும்பு (nkeys);
}

முழு
pkcs11_sign(கட்டமைப்பு sshkey *சாவி,
    u_char **sigp, size_t *lenp,
    மாறிலி u_char *data, size_t datalen,
    மாறிலி எழுத்து *alg, மாறிலி எழுத்து *sk_provider,
    மாறிலி எழுத்து *sk_pin, u_int compat)
{
	தேர்வு (சாவி->type) {
#ifdef WITH_OPENSSL
	நிலை சாவி_RSA:
	நிலை சாவி_RSA_CERT:
		திரும்பு pkcs11_sign_rsa(சாவி, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	நிலை சாவி_ECDSA:
	நிலை சாவி_ECDSA_CERT:
		திரும்பு pkcs11_sign_ecdsa(சாவி, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
#endif /* WITH_OPENSSL */
	நிலை சாவி_ED25519:
	நிலை சாவி_ED25519_CERT:
		திரும்பு pkcs11_sign_ed25519(சாவி, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	இயல்பு:
		திரும்பு SSH_ERR_சாவி_TYPE_UNKNOWN;
	}
}

வெறுமை
pkcs11_சாவி_free(கட்டமைப்பு sshkey *சாவி)
{
	/* never called */
}

#ifdef WITH_PKCS11_KEYGEN
கட்டமைப்பு sshkey *
pkcs11_gakp(எழுத்து *provider_id, எழுத்து *pin, unsigned முழு slotidx, எழுத்து *label,
    unsigned முழு type, unsigned முழு bits, unsigned எழுத்து keyid, uint32_t *err)
{
	கட்டமைப்பு pkcs11_provider	*p = வெற்று;
	கட்டமைப்பு pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	கட்டமைப்பு sshkey		*k = வெற்று;
	முழு			 ret = -1, reset_pin = 0, reset_provider = 0;
	CK_RV			 rv;

	*err = 0;

	எனில் ((p = pkcs11_provider_lookup(provider_id)) != வெற்று)
		debug_f("provider \"%s\" available", provider_id);
	இல்லையெனில் எனில் ((ret = pkcs11_register_provider(provider_id, pin, வெற்று, வெற்று,
	    &p, CKU_SO)) < 0) {
		debug_f("could not register provider %s", provider_id);
		செல் out;
	} இல்லையெனில்
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	எனில் ((rv = f->C_SetOperationState(session , pin, strlen(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} இல்லையெனில்
		reset_pin = 1;

	தேர்வு (type) {
	நிலை சாவி_RSA:
		எனில் ((k = pkcs11_rsa_generate_private_சாவி(p, slotidx, label,
		    bits, keyid, err)) == வெற்று) {
			debug_f("failed to generate RSA key");
			செல் out;
		}
		நிறுத்து;
	நிலை சாவி_ECDSA:
		எனில் ((k = pkcs11_ecdsa_generate_private_சாவி(p, slotidx, label,
		    bits, keyid, err)) == வெற்று) {
			debug_f("failed to generate ECDSA key");
			செல் out;
		}
		நிறுத்து;
	இயல்பு:
		*err = SSH_PKCS11_ERR_GENERIC;
		debug_f("unknown type %d", type);
		செல் out;
	}

out:
	எனில் (reset_pin)
		f->C_SetOperationState(session , வெற்று, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	எனில் (reset_provider)
		pkcs11_del_provider(provider_id);

	திரும்பு (k);
}

கட்டமைப்பு sshkey *
pkcs11_destroy_keypair(எழுத்து *provider_id, எழுத்து *pin, unsigned long slotidx,
    unsigned எழுத்து keyid, uint32_t *err)
{
	கட்டமைப்பு pkcs11_provider	*p = வெற்று;
	கட்டமைப்பு pkcs11_slotinfo	*si;
	கட்டமைப்பு sshkey		*k = வெற்று;
	முழு			 reset_pin = 0, reset_provider = 0;
	CK_ULONG		 nattrs;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_ATTRIBUTE		 attrs[16];
	CK_OBJECT_CLASS		 சாவி_class;
	CK_சாவி_TYPE		 சாவி_type;
	CK_OBJECT_HANDLE	 obj = CK_INVALID_HANDLE;
	CK_RV			 rv;

	*err = 0;

	எனில் ((p = pkcs11_provider_lookup(provider_id)) != வெற்று) {
		debug_f("using provider \"%s\"", provider_id);
	} இல்லையெனில் எனில் (pkcs11_register_provider(provider_id, pin, வெற்று, வெற்று, &p,
	    CKU_SO) < 0) {
		debug_f("could not register provider %s",
		    provider_id);
		செல் out;
	} இல்லையெனில்
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	எனில் ((rv = f->C_SetOperationState(session , pin, strlen(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} இல்லையெனில்
		reset_pin = 1;

	/* private key */
	nattrs = 0;
	சாவி_class = CKO_PRIVATE_சாவி;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &சாவி_class, அளவு(சாவி_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, அளவு(keyid));

	எனில் (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {
		எனில் ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy private key 0x%hhx",
			    keyid);
			*err = rv;
			செல் out;
		}
	}

	/* public key */
	nattrs = 0;
	சாவி_class = CKO_PUBLIC_சாவி;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &சாவி_class, அளவு(சாவி_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, அளவு(keyid));

	எனில் (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {

		/* get key type */
		nattrs = 0;
		FILL_ATTR(attrs, nattrs, CKA_சாவி_TYPE, &சாவி_type,
		    அளவு(சாவி_type));
		rv = f->C_Get_Attribute_மதிப்பு(session, obj, attrs, nattrs);
		எனில் (rv != CKR_OK) {
			debug_f("could not get key type of public key 0x%hhx",
			    keyid);
			*err = rv;
			சாவி_type = -1;
		}
		தேர்வு (சாவி_type) {
#ifdef WITH_OPENSSL
		நிலை CKK_RSA:
			k = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			நிறுத்து;
		நிலை CKK_ECDSA:
			k = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			நிறுத்து;
#endif /* WITH_OPENSSL */
		நிலை CKK_EC_EDWARDS:
			k = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			நிறுத்து;
		இயல்பு:
			debug_f("unsupported key type %lu", (u_long)சாவி_type);
			நிறுத்து;
		}

		எனில் ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy public key 0x%hhx", keyid);
			*err = rv;
			செல் out;
		}
	}

out:
	எனில் (reset_pin)
		f->C_SetOperationState(session , வெற்று, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	எனில் (reset_provider)
		pkcs11_del_provider(provider_id);

	திரும்பு (k);
}
#endif /* WITH_PKCS11_KEYGEN */
#இல்லையெனில் /* ENABLE_PKCS11 */

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "ssh-pkcs11.h"

முழு
pkcs11_init(முழு interactive)
{
	error_f("PKCS#11 not supported");
	திரும்பு (-1);
}

முழு
pkcs11_add_provider(எழுத்து *provider_id, எழுத்து *pin, கட்டமைப்பு sshkey ***keyp,
    எழுத்து ***labelsp)
{
	error_f("PKCS#11 not supported");
	திரும்பு (-1);
}

வெறுமை
pkcs11_சாவி_free(கட்டமைப்பு sshkey *சாவி)
{
	error_f("PKCS#11 not supported");
}

முழு
pkcs11_sign(கட்டமைப்பு sshkey *சாவி,
    u_char **sigp, size_t *lenp,
    மாறிலி u_char *data, size_t datalen,
    மாறிலி எழுத்து *alg, மாறிலி எழுத்து *sk_provider,
    மாறிலி எழுத்து *sk_pin, u_int compat)
{
	error_f("PKCS#11 not supported");
	திரும்பு SSH_ERR_FEATURE_UNSUPPORTED;
}

வெறுமை
pkcs11_terminate(வெறுமை)
{
	error_f("PKCS#11 not supported");
}
#endif /* ENABLE_PKCS11 */
