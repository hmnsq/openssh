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

#അന്തര്ഭാവ "includes.h"

#ifdef ENABLE_PKCS11

#അന്തര്ഭാവ <sys/time.h>

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/queue.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>

#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <dlfcn.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"
#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/ecdsa.h>
#അന്തര്ഭാവ <openssl/x509.h>
#അന്തര്ഭാവ <openssl/err.h>
#endif

#define CRYPTOKI_COMPAT
#അന്തര്ഭാവ "pkcs11.h"

#define SSHKEY_INTERNAL
#അന്തര്ഭാവ "sshkey.h"

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssh-pkcs11.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "crypto_api.h"

ഘടന pkcs11_slotinfo {
	CK_TOKEN_INFO		token;
	CK_SESSION_HANDLE	session;
	പൂർണ്ണസംഖ്യ			logged_in;
};

ഘടന pkcs11_provider {
	അക്ഷരം			*name;
	ശൂന്യം			*handle;
	CK_FUNCTION_LIST	*function_list;
	CK_INFO			info;
	CK_ULONG		nslots;
	CK_SLOT_ID		*slotlist;
	ഘടന pkcs11_slotinfo	*slotinfo;
	പൂർണ്ണസംഖ്യ			valid;
	പൂർണ്ണസംഖ്യ			refcount;
	TAILQ_ENTRY(pkcs11_provider) next;
};

TAILQ_HEAD(, pkcs11_provider) pkcs11_providers;

ഘടന pkcs11_താക്കോൽ {
	ഘടന sshbuf		*keyblob;
	ഘടന pkcs11_provider	*provider;
	CK_ULONG		slotidx;
	അക്ഷരം			*keyid;
	പൂർണ്ണസംഖ്യ			keyid_len;
	TAILQ_ENTRY(pkcs11_താക്കോൽ)	next;
};

TAILQ_HEAD(, pkcs11_താക്കോൽ) pkcs11_താക്കോലുകൾ; /* XXX a tree would be better */

പൂർണ്ണസംഖ്യ pkcs11_interactive = 0;

#ifdef WITH_OPENSSL
സ്ഥിതം ശൂന്യം
ossl_error(സ്ഥിരം അക്ഷരം *സന്ദേശം)
{
	unsigned long    e;

	error_f("%s", സന്ദേശം);
	ആകുമ്പോൾ ((e = ERR_get_error()) != 0)
		error_f("libcrypto error: %s", ERR_error_string(e, ശൂന്യ));
}
#endif

/*
 * finalize a provider shared library, it's no longer usable.
 * however, there might still be keys referencing this provider,
 * so the actual freeing of memory is handled by pkcs11_provider_unref().
 * this is called when a provider gets unregistered.
 */
സ്ഥിതം ശൂന്യം
pkcs11_provider_finalize(ഘടന pkcs11_provider *p)
{
	CK_RV rv;
	CK_ULONG i;

	debug_f("provider \"%s\" refcount %d valid %d",
	    p->name, p->refcount, p->valid);
	എങ്കിൽ (!p->valid)
		തിരികെ;
	വേണ്ടി (i = 0; i < p->nslots; i++) {
		എങ്കിൽ (p->slotinfo[i].session &&
		    (rv = p->function_list->C_CloseSession(
		    p->slotinfo[i].session)) != CKR_OK)
			error("C_CloseSession failed: %lu", rv);
	}
	എങ്കിൽ ((rv = p->function_list->C_Finalize(ശൂന്യ)) != CKR_OK)
		error("C_Finalize failed: %lu", rv);
	p->valid = 0;
	p->function_list = ശൂന്യ;
	dlclose(p->handle);
}

/*
 * remove a reference to the provider.
 * called when a key gets destroyed or when the provider is unregistered.
 */
സ്ഥിതം ശൂന്യം
pkcs11_provider_unref(ഘടന pkcs11_provider *p)
{
	debug_f("provider \"%s\" refcount %d", p->name, p->refcount);
	എങ്കിൽ (--p->refcount <= 0) {
		എങ്കിൽ (p->valid)
			error_f("provider \"%s\" still valid", p->name);
		സ്വതന്ത്രം(p->name);
		സ്വതന്ത്രം(p->slotlist);
		സ്വതന്ത്രം(p->slotinfo);
		സ്വതന്ത്രം(p);
	}
}

/* lookup provider by name */
സ്ഥിതം ഘടന pkcs11_provider *
pkcs11_provider_lookup(അക്ഷരം *provider_id)
{
	ഘടന pkcs11_provider *p;

	TAILQ_FOREACH(p, &pkcs11_providers, next) {
		debug("check provider \"%s\"", p->name);
		എങ്കിൽ (!strcmp(provider_id, p->name))
			തിരികെ (p);
	}
	തിരികെ (ശൂന്യ);
}

/* unregister provider by name */
പൂർണ്ണസംഖ്യ
pkcs11_del_provider(അക്ഷരം *provider_id)
{
	ഘടന pkcs11_provider *p;

	എങ്കിൽ ((p = pkcs11_provider_lookup(provider_id)) != ശൂന്യ) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
		തിരികെ (0);
	}
	തിരികെ (-1);
}

/* release a wrapped object */
സ്ഥിതം ശൂന്യം
pkcs11_k11_free(ഘടന pkcs11_താക്കോൽ *k11)
{
	എങ്കിൽ (k11 == ശൂന്യ)
		തിരികെ;
	എങ്കിൽ (k11->provider)
		pkcs11_provider_unref(k11->provider);
	സ്വതന്ത്രം(k11->keyid);
	sshbuf_free(k11->keyblob);
	സ്വതന്ത്രം(k11);
}

/* find a single 'obj' for given attributes */
സ്ഥിതം പൂർണ്ണസംഖ്യ
pkcs11_find(ഘടന pkcs11_provider *p, CK_ULONG slotidx, CK_ATTRIBUTE *attr,
    CK_ULONG nattr, CK_OBJECT_HANDLE *obj)
{
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	session;
	CK_ULONG		nfound = 0;
	CK_RV			rv;
	പൂർണ്ണസംഖ്യ			ret = -1;

	f = p->function_list;
	session = p->slotinfo[slotidx].session;
	എങ്കിൽ ((rv = f->C_FindObjectsInit(session, attr, nattr)) != CKR_OK) {
		error("C_FindObjectsInit failed (nattr %lu): %lu", nattr, rv);
		തിരികെ (-1);
	}
	എങ്കിൽ ((rv = f->C_FindObjects(session, obj, 1, &nfound)) != CKR_OK ||
	    nfound != 1) {
		debug("C_FindObjects failed (nfound %lu nattr %lu): %lu",
		    nfound, nattr, rv);
	} അല്ലെങ്കിൽ
		ret = 0;
	എങ്കിൽ ((rv = f->C_FindObjectsFinal(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	തിരികെ (ret);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
pkcs11_login_slot(ഘടന pkcs11_provider *provider, ഘടന pkcs11_slotinfo *si,
    CK_USER_TYPE type)
{
	അക്ഷരം			*pin = ശൂന്യ, prompt[1024];
	CK_RV			 rv;

	എങ്കിൽ (provider == ശൂന്യ || si == ശൂന്യ || !provider->valid) {
		error("no pkcs11 (valid) provider found");
		തിരികെ (-1);
	}

	എങ്കിൽ (!pkcs11_interactive) {
		error("need pin entry%s",
		    (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH) ?
		    " on reader keypad" : "");
		തിരികെ (-1);
	}
	എങ്കിൽ (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
		verbose("Deferring PIN entry to reader keypad.");
	അല്ലെങ്കിൽ {
		snprintf(prompt, വലുപ്പം(prompt), "Enter PIN for '%s': ",
		    si->token.label);
		എങ്കിൽ ((pin = read_passphrase(prompt, RP_ALLOW_EOF)) == ശൂന്യ) {
			debug_f("no pin specified");
			തിരികെ (-1);	/* bail out */
		}
	}
	rv = provider->function_list->C_Login(si->session, type, (u_char *)pin,
	    (pin != ശൂന്യ) ? strlen(pin) : 0);
	എങ്കിൽ (pin != ശൂന്യ)
		freezero(pin, strlen(pin));

	തിരഞ്ഞെടുപ്പ് (rv) {
	അവസ്ഥ CKR_OK:
	അവസ്ഥ CKR_USER_ALREADY_LOGGED_IN:
		/* success */
		നിർത്തുക;
	അവസ്ഥ CKR_PIN_LEN_RANGE:
		error("PKCS#11 login failed: PIN length out of range");
		തിരികെ -1;
	അവസ്ഥ CKR_PIN_INCORRECT:
		error("PKCS#11 login failed: PIN incorrect");
		തിരികെ -1;
	അവസ്ഥ CKR_PIN_LOCKED:
		error("PKCS#11 login failed: PIN locked");
		തിരികെ -1;
	സ്ഥിരസ്ഥിതി:
		error("PKCS#11 login failed: error %lu", rv);
		തിരികെ -1;
	}
	si->logged_in = 1;
	തിരികെ (0);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
pkcs11_login(ഘടന pkcs11_താക്കോൽ *k11, CK_USER_TYPE type)
{
	എങ്കിൽ (k11 == ശൂന്യ || k11->provider == ശൂന്യ || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		തിരികെ (-1);
	}

	തിരികെ pkcs11_login_slot(k11->provider,
	    &k11->provider->slotinfo[k11->slotidx], type);
}


സ്ഥിതം പൂർണ്ണസംഖ്യ
pkcs11_check_obj_bool_attrib(ഘടന pkcs11_താക്കോൽ *k11, CK_OBJECT_HANDLE obj,
    CK_ATTRIBUTE_TYPE type, പൂർണ്ണസംഖ്യ *val)
{
	ഘടന pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_BBOOL		flag = 0;
	CK_ATTRIBUTE		attr;
	CK_RV			 rv;

	*val = 0;

	എങ്കിൽ (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		തിരികെ (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	attr.type = type;
	attr.p_മൂല്യം = &flag;
	attr.ul_മൂല്യം_Len = വലുപ്പം(flag);

	rv = f->C_Get_Attribute_മൂല്യം(si->session, obj, &attr, 1);
	എങ്കിൽ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		തിരികെ (-1);
	}
	*val = flag != 0;
	debug_f("provider \"%s\" slot %lu object %lu: attrib %lu = %d",
	    k11->provider->name, k11->slotidx, obj, type, *val);
	തിരികെ (0);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
pkcs11_get_താക്കോൽ(ഘടന pkcs11_താക്കോൽ *k11, CK_MECHANISM_TYPE mech_type)
{
	ഘടന pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	 obj;
	CK_RV			 rv;
	CK_OBJECT_CLASS		 private_താക്കോൽ_class;
	CK_BBOOL		 true_val;
	CK_MECHANISM		 mech;
	CK_ATTRIBUTE		 താക്കോൽ_filter[3];
	പൂർണ്ണസംഖ്യ			 always_auth = 0;
	പൂർണ്ണസംഖ്യ			 did_login = 0;

	എങ്കിൽ (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		തിരികെ (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	എങ്കിൽ ((si->token.flags & CKF_LOGIN_REQUIRED) && !si->logged_in) {
		എങ്കിൽ (pkcs11_login(k11, CKU_USER) < 0) {
			error("login failed");
			തിരികെ (-1);
		}
		did_login = 1;
	}

	memset(&താക്കോൽ_filter, 0, വലുപ്പം(താക്കോൽ_filter));
	private_താക്കോൽ_class = CKO_PRIVATE_താക്കോൽ;
	താക്കോൽ_filter[0].type = CKA_CLASS;
	താക്കോൽ_filter[0].p_മൂല്യം = &private_താക്കോൽ_class;
	താക്കോൽ_filter[0].ul_മൂല്യം_Len = വലുപ്പം(private_താക്കോൽ_class);

	താക്കോൽ_filter[1].type = CKA_ID;
	താക്കോൽ_filter[1].p_മൂല്യം = k11->keyid;
	താക്കോൽ_filter[1].ul_മൂല്യം_Len = k11->keyid_len;

	true_val = CK_TRUE;
	താക്കോൽ_filter[2].type = CKA_SIGN;
	താക്കോൽ_filter[2].p_മൂല്യം = &true_val;
	താക്കോൽ_filter[2].ul_മൂല്യം_Len = വലുപ്പം(true_val);

	/* try to find object w/CKA_SIGN first, retry w/o */
	എങ്കിൽ (pkcs11_find(k11->provider, k11->slotidx, താക്കോൽ_filter, 3, &obj) < 0 &&
	    pkcs11_find(k11->provider, k11->slotidx, താക്കോൽ_filter, 2, &obj) < 0) {
		error("cannot find private key");
		തിരികെ (-1);
	}

	memset(&mech, 0, വലുപ്പം(mech));
	mech.mechanism = mech_type;
	mech.pParameter = NULL_PTR;
	mech.ulParameterLen = 0;

	എങ്കിൽ ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
		തിരികെ (-1);
	}

	pkcs11_check_obj_bool_attrib(k11, obj, CKA_ALWAYS_AUTHENTICATE,
	    &always_auth); /* ignore errors here */
	എങ്കിൽ (always_auth && !did_login) {
		debug_f("always-auth key");
		എങ്കിൽ (pkcs11_login(k11, CKU_CONTEXT_SPECIFIC) < 0) {
			error("login failed for always-auth key");
			തിരികെ (-1);
		}
	}

	തിരികെ (0);
}

/* record the key information later use lookup by keyblob */
സ്ഥിതം പൂർണ്ണസംഖ്യ
pkcs11_record_താക്കോൽ(ഘടന pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, ഘടന sshkey *താക്കോൽ)
{
	ഘടന sshbuf *keyblob;
	ഘടന pkcs11_താക്കോൽ *k11;
	പൂർണ്ണസംഖ്യ r;
	അക്ഷരം *hex;

	hex = tohex(keyid_attrib->p_മൂല്യം, keyid_attrib->ul_മൂല്യം_Len);
	debug_f("%s key: provider %s slot %lu keyid %s",
	    sshkey_type(താക്കോൽ), provider->name, (u_long)slotidx, hex);
	സ്വതന്ത്രം(hex);

	എങ്കിൽ ((keyblob = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshkey_putb(താക്കോൽ, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");

	/* Check if we've already recorded this key in a different slot */
	TAILQ_FOREACH(k11, &pkcs11_താക്കോലുകൾ, next) {
		എങ്കിൽ (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			hex = tohex(k11->keyid, k11->keyid_len);
			debug_f("Already seen this key at "
			    "provider %s slot %lu keyid %s",
			    k11->provider->name, k11->slotidx, hex);
			സ്വതന്ത്രം(hex);
			sshbuf_free(keyblob);
			തിരികെ -1;
		}
	}

	k11 = xcalloc(1, വലുപ്പം(*k11));
	k11->provider = provider;
	k11->keyblob = keyblob;
	provider->refcount++;	/* provider referenced by RSA key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ul_മൂല്യം_Len;
	എങ്കിൽ (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len);
		memcpy(k11->keyid, keyid_attrib->p_മൂല്യം, k11->keyid_len);
	}
	TAILQ_INSERT_TAIL(&pkcs11_താക്കോലുകൾ, k11, next);

	തിരികെ 0;
}

/* retrieve the key information by keyblob */
സ്ഥിതം ഘടന pkcs11_താക്കോൽ *
pkcs11_lookup_താക്കോൽ(ഘടന sshkey *താക്കോൽ)
{
	ഘടന pkcs11_താക്കോൽ *k11, *found = ശൂന്യ;
	ഘടന sshbuf *keyblob;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((keyblob = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	എങ്കിൽ ((r = sshkey_putb(താക്കോൽ, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");
	TAILQ_FOREACH(k11, &pkcs11_താക്കോലുകൾ, next) {
		എങ്കിൽ (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			found = k11;
			നിർത്തുക;
		}
	}
	sshbuf_free(keyblob);
	തിരികെ found;
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
സ്ഥിതം സ്ഥിരം u_char id_sha1[] = {
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
സ്ഥിതം സ്ഥിരം u_char id_sha256[] = {
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
സ്ഥിതം സ്ഥിരം u_char id_sha512[] = {
	0x30, 0x51, /* type Sequence, length 0x51 (81) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, /* id-sha512 */
	0x05, 0x00, /* NULL */
	0x04, 0x40  /* Octet string, length 0x40 (64), followed by sha512 hash */
};

സ്ഥിതം പൂർണ്ണസംഖ്യ
rsa_hash_alg_oid(പൂർണ്ണസംഖ്യ hash_alg, സ്ഥിരം u_char **oidp, size_t *oidlenp)
{
	തിരഞ്ഞെടുപ്പ് (hash_alg) {
	അവസ്ഥ SSH_DIGEST_SHA1:
		*oidp = id_sha1;
		*oidlenp = വലുപ്പം(id_sha1);
		നിർത്തുക;
	അവസ്ഥ SSH_DIGEST_SHA256:
		*oidp = id_sha256;
		*oidlenp = വലുപ്പം(id_sha256);
		നിർത്തുക;
	അവസ്ഥ SSH_DIGEST_SHA512:
		*oidp = id_sha512;
		*oidlenp = വലുപ്പം(id_sha512);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
pkcs11_sign_rsa(ഘടന sshkey *താക്കോൽ,
    u_char **sigp, size_t *lenp,
    സ്ഥിരം u_char *data, size_t datalen,
    സ്ഥിരം അക്ഷരം *alg, സ്ഥിരം അക്ഷരം *sk_provider,
    സ്ഥിരം അക്ഷരം *sk_pin, u_int compat)
{
	ഘടന pkcs11_താക്കോൽ	*k11;
	ഘടന pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	പൂർണ്ണസംഖ്യ			hashalg, r, diff, siglen, ret = -1;
	u_char			*oid_dgst = ശൂന്യ, *sig = ശൂന്യ;
	size_t			dgst_len, oid_len, oid_dgst_len = 0;
	സ്ഥിരം u_char		*oid;

	എങ്കിൽ (sigp != ശൂന്യ)
		*sigp = ശൂന്യ;
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = 0;

	എങ്കിൽ ((k11 = pkcs11_lookup_താക്കോൽ(താക്കോൽ)) == ശൂന്യ) {
		error_f("no key found");
		തിരികെ SSH_ERR_താക്കോൽ_NOT_FOUND;
	}

	debug3_f("sign with alg \"%s\" using provider %s slotidx %lu",
	    alg == ശൂന്യ ? "" : alg, k11->provider->name, (u_long)k11->slotidx);

	എങ്കിൽ (pkcs11_get_താക്കോൽ(k11, CKM_RSA_PKCS) == -1) {
		error("pkcs11_get_key failed");
		തിരികെ SSH_ERR_AGENT_FAILURE;
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	എങ്കിൽ ((siglen = EVP_PKEY_size(താക്കോൽ->pkey)) <= 0)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* Determine hash algorithm and OID for signature */
	എങ്കിൽ (alg == ശൂന്യ || *alg == '\0')
		hashalg = SSH_DIGEST_SHA1;
	അല്ലെങ്കിൽ എങ്കിൽ ((hashalg = ssh_rsa_hash_id_from_keyname(alg)) == -1)
		fatal_f("couldn't determine RSA hash alg \"%s\"", alg);
	എങ്കിൽ ((r = rsa_hash_alg_oid(hashalg, &oid, &oid_len)) != 0)
		fatal_fr(r, "rsa_hash_alg_oid failed");
	എങ്കിൽ ((dgst_len = ssh_digest_bytes(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);

	/* Prepare { oid || digest } */
	oid_dgst_len = oid_len + dgst_len;
	oid_dgst = xcalloc(1, oid_dgst_len);
	memcpy(oid_dgst, oid, oid_len);
	എങ്കിൽ ((r = ssh_digest_memory(hashalg, data, datalen,
	    oid_dgst + oid_len, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	എങ്കിൽ ((rv = f->C_Sign(si->session, (CK_BYTE *)oid_dgst,
	    oid_dgst_len, sig, &slen)) != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		പോകുക done;
	}

	എങ്കിൽ (slen < (CK_ULONG)siglen) {
		diff = siglen - slen;
		debug3_f("repack %lu < %d (diff %d)",
		    (u_long)slen, siglen, diff);
		memmove(sig + diff, sig, slen);
		explicit_bzero(sig, diff);
	} അല്ലെങ്കിൽ എങ്കിൽ (slen > (size_t)siglen)
		fatal_f("bad C_Sign length");

	എങ്കിൽ ((ret = ssh_rsa_encode_store_sig(hashalg, sig, siglen,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	freezero(oid_dgst, oid_dgst_len);
	സ്വതന്ത്രം(sig);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
pkcs11_sign_ecdsa(ഘടന sshkey *താക്കോൽ,
    u_char **sigp, size_t *lenp,
    സ്ഥിരം u_char *data, size_t datalen,
    സ്ഥിരം അക്ഷരം *alg, സ്ഥിരം അക്ഷരം *sk_provider,
    സ്ഥിരം അക്ഷരം *sk_pin, u_int compat)
{
	ഘടന pkcs11_താക്കോൽ	*k11;
	ഘടന pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0, bnlen;
	CK_RV			rv;
	BIGNUM			*sig_r = ശൂന്യ, *sig_s = ശൂന്യ;
	u_char			*sig = ശൂന്യ, *dgst = ശൂന്യ;
	size_t			dgst_len = 0;
	പൂർണ്ണസംഖ്യ			hashalg, ret = -1, r, siglen;

	എങ്കിൽ (sigp != ശൂന്യ)
		*sigp = ശൂന്യ;
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = 0;

	എങ്കിൽ ((k11 = pkcs11_lookup_താക്കോൽ(താക്കോൽ)) == ശൂന്യ) {
		error_f("no key found");
		തിരികെ SSH_ERR_താക്കോൽ_NOT_FOUND;
	}

	എങ്കിൽ (pkcs11_get_താക്കോൽ(k11, CKM_ECDSA) == -1) {
		error("pkcs11_get_key failed");
		തിരികെ SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	/* Prepare digest to be signed */
	എങ്കിൽ ((hashalg = sshkey_ec_nid_to_hash_alg(താക്കോൽ->ecdsa_nid)) == -1)
		fatal_f("couldn't determine ECDSA hash alg");
	എങ്കിൽ ((dgst_len = ssh_digest_bytes(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);
	dgst = xcalloc(1, dgst_len);
	എങ്കിൽ ((r = ssh_digest_memory(hashalg, data, datalen,
	    dgst, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	എങ്കിൽ ((siglen = EVP_PKEY_size(താക്കോൽ->pkey)) <= 0)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dgst_len, sig, &slen);
	എങ്കിൽ (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		പോകുക done;
	}
	എങ്കിൽ (slen < 64 || slen > 132 || slen % 2) {
		error_f("bad signature length: %lu", (u_long)slen);
		പോകുക done;
	}
	bnlen = slen/2;
	എങ്കിൽ ((sig_r = BN_bin2bn(sig, bnlen, ശൂന്യ)) == ശൂന്യ ||
	    (sig_s = BN_bin2bn(sig+bnlen, bnlen, ശൂന്യ)) == ശൂന്യ) {
		ossl_error("BN_bin2bn failed");
		പോകുക done;
	}

	എങ്കിൽ ((ret = ssh_ecdsa_encode_store_sig(താക്കോൽ, sig_r, sig_s,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	freezero(dgst, dgst_len);
	BN_free(sig_r);
	BN_free(sig_s);
	സ്വതന്ത്രം(sig);
	തിരികെ ret;
}
#endif /* WITH_OPENSSL */

സ്ഥിതം പൂർണ്ണസംഖ്യ
pkcs11_sign_ed25519(ഘടന sshkey *താക്കോൽ,
    u_char **sigp, size_t *lenp,
    സ്ഥിരം u_char *data, size_t datalen,
    സ്ഥിരം അക്ഷരം *alg, സ്ഥിരം അക്ഷരം *sk_provider,
    സ്ഥിരം അക്ഷരം *sk_pin, u_int compat)
{
	ഘടന pkcs11_താക്കോൽ	*k11;
	ഘടന pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	u_char			*sig = ശൂന്യ;
	CK_BYTE			*xdata = ശൂന്യ;
	പൂർണ്ണസംഖ്യ			ret = -1;

	എങ്കിൽ (sigp != ശൂന്യ)
		*sigp = ശൂന്യ;
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = 0;

	എങ്കിൽ ((k11 = pkcs11_lookup_താക്കോൽ(താക്കോൽ)) == ശൂന്യ) {
		error_f("no key found");
		തിരികെ SSH_ERR_താക്കോൽ_NOT_FOUND;
	}

	എങ്കിൽ (pkcs11_get_താക്കോൽ(k11, CKM_EDDSA) == -1) {
		error("pkcs11_get_key failed");
		തിരികെ SSH_ERR_AGENT_FAILURE;
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
	എങ്കിൽ (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		പോകുക done;
	}
	എങ്കിൽ (slen != crypto_sign_ed25519_BYTES) {
		error_f("bad signature length: %lu", (u_long)slen);
		പോകുക done;
	}
	എങ്കിൽ ((ret = ssh_ed25519_encode_store_sig(sig, slen, sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	എങ്കിൽ (xdata != ശൂന്യ)
		freezero(xdata, datalen);
	സ്വതന്ത്രം(sig);
	തിരികെ ret;
}

/* remove trailing spaces */
സ്ഥിതം അക്ഷരം *
rmspace(u_char *buf, size_t len)
{
	size_t i;

	എങ്കിൽ (len == 0)
		തിരികെ buf;
	വേണ്ടി (i = len - 1; i > 0; i--)
		എങ്കിൽ (buf[i] == ' ')
			buf[i] = '\0';
		അല്ലെങ്കിൽ
			നിർത്തുക;
	തിരികെ buf;
}
/* Used to printf fixed-width, space-padded, unterminated strings using %.*s */
#define RMSPACE(s) (പൂർണ്ണസംഖ്യ)വലുപ്പം(s), rmspace(s, വലുപ്പം(s))

/*
 * open a pkcs11 session and login if required.
 * if pin == NULL we delay login until key use
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
pkcs11_open_session(ഘടന pkcs11_provider *p, CK_ULONG slotidx, അക്ഷരം *pin,
    CK_ULONG user)
{
	ഘടന pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_RV			rv;
	CK_SESSION_HANDLE	session;
	പൂർണ്ണസംഖ്യ			login_required, ret;

	f = p->function_list;
	si = &p->slotinfo[slotidx];

	login_required = si->token.flags & CKF_LOGIN_REQUIRED;

	/* fail early before opening session */
	എങ്കിൽ (login_required && !pkcs11_interactive &&
	    (pin == ശൂന്യ || strlen(pin) == 0)) {
		error("pin required");
		തിരികെ (-SSH_PKCS11_ERR_PIN_REQUIRED);
	}
	എങ്കിൽ ((rv = f->C_OpenSession(p->slotlist[slotidx], CKF_RW_SESSION|
	    CKF_SERIAL_SESSION, ശൂന്യ, ശൂന്യ, &session)) != CKR_OK) {
		error("C_OpenSession failed: %lu", rv);
		തിരികെ (-1);
	}
	എങ്കിൽ (login_required && pin != ശൂന്യ && strlen(pin) != 0) {
		rv = f->C_Login(session, user, (u_char *)pin, strlen(pin));
		എങ്കിൽ (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
			error("C_Login failed: %lu", rv);
			ret = (rv == CKR_PIN_LOCKED) ?
			    -SSH_PKCS11_ERR_PIN_LOCKED :
			    -SSH_PKCS11_ERR_LOGIN_FAIL;
			എങ്കിൽ ((rv = f->C_CloseSession(session)) != CKR_OK)
				error("C_CloseSession failed: %lu", rv);
			തിരികെ (ret);
		}
		si->logged_in = 1;
	}
	si->session = session;
	തിരികെ (0);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
pkcs11_താക്കോൽ_included(ഘടന sshkey ***keysp, പൂർണ്ണസംഖ്യ *nkeys, ഘടന sshkey *താക്കോൽ)
{
	പൂർണ്ണസംഖ്യ i;

	വേണ്ടി (i = 0; i < *nkeys; i++)
		എങ്കിൽ (sshkey_equal(താക്കോൽ, (*keysp)[i]))
			തിരികെ (1);
	തിരികെ (0);
}

#ifdef WITH_OPENSSL
സ്ഥിതം ഘടന sshkey *
pkcs11_fetch_ecdsa_pubkey(ഘടന pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 താക്കോൽ_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ശൂന്യ;
	CK_RV			 rv;
	ASN1_OCTET_STRING	*octet = ശൂന്യ;
	EC_താക്കോൽ			*ec = ശൂന്യ;
	EC_GROUP		*group = ശൂന്യ;
	ഘടന sshkey		*താക്കോൽ = ശൂന്യ;
	സ്ഥിരം unsigned അക്ഷരം	*attrp = ശൂന്യ;
	പൂർണ്ണസംഖ്യ			 success = -1, r, i, nid;

	memset(&താക്കോൽ_attr, 0, വലുപ്പം(താക്കോൽ_attr));
	താക്കോൽ_attr[0].type = CKA_ID;
	താക്കോൽ_attr[1].type = CKA_EC_POINT;
	താക്കോൽ_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_മൂല്യം(session, *obj, താക്കോൽ_attr, 3);
	എങ്കിൽ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		തിരികെ (ശൂന്യ);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	എങ്കിൽ (താക്കോൽ_attr[1].ul_മൂല്യം_Len == 0 ||
	    താക്കോൽ_attr[2].ul_മൂല്യം_Len == 0) {
		error("invalid attribute length");
		തിരികെ (ശൂന്യ);
	}

	/* allocate buffers for attributes */
	വേണ്ടി (i = 0; i < 3; i++)
		എങ്കിൽ (താക്കോൽ_attr[i].ul_മൂല്യം_Len > 0)
			താക്കോൽ_attr[i].p_മൂല്യം = xcalloc(1, താക്കോൽ_attr[i].ul_മൂല്യം_Len);

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_മൂല്യം(session, *obj, താക്കോൽ_attr, 3);
	എങ്കിൽ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		പോകുക fail;
	}

	ec = EC_താക്കോൽ_new();
	എങ്കിൽ (ec == ശൂന്യ) {
		error("EC_KEY_new failed");
		പോകുക fail;
	}

	attrp = താക്കോൽ_attr[2].p_മൂല്യം;
	group = d2i_ECPKParameters(ശൂന്യ, &attrp, താക്കോൽ_attr[2].ul_മൂല്യം_Len);
	എങ്കിൽ (group == ശൂന്യ) {
		ossl_error("d2i_ECPKParameters failed");
		പോകുക fail;
	}

	എങ്കിൽ (EC_താക്കോൽ_set_group(ec, group) == 0) {
		ossl_error("EC_KEY_set_group failed");
		പോകുക fail;
	}

	എങ്കിൽ (താക്കോൽ_attr[1].ul_മൂല്യം_Len <= 2) {
		error("CKA_EC_POINT too small");
		പോകുക fail;
	}

	attrp = താക്കോൽ_attr[1].p_മൂല്യം;
	octet = d2i_ASN1_OCTET_STRING(ശൂന്യ, &attrp, താക്കോൽ_attr[1].ul_മൂല്യം_Len);
	എങ്കിൽ (octet == ശൂന്യ) {
		ossl_error("d2i_ASN1_OCTET_STRING failed");
		പോകുക fail;
	}
	attrp = ASN1_STRING_get0_data(octet);
	എങ്കിൽ (o2i_ECPublic_താക്കോൽ(&ec, &attrp, ASN1_STRING_length(octet)) == ശൂന്യ) {
		ossl_error("o2i_ECPublicKey failed");
		പോകുക fail;
	}
	എങ്കിൽ ((r = sshkey_ec_validate_public(EC_താക്കോൽ_get0_group(ec),
	    EC_താക്കോൽ_get0_public_താക്കോൽ(ec))) != 0) {
		error_fr(r, "invalid EC key");
		പോകുക fail;
	}

	nid = sshkey_ecdsa_താക്കോൽ_to_nid(ec);
	എങ്കിൽ (nid < 0) {
		error("couldn't get curve nid");
		പോകുക fail;
	}

	താക്കോൽ = sshkey_new(താക്കോൽ_UNSPEC);
	എങ്കിൽ (താക്കോൽ == ശൂന്യ) {
		error("sshkey_new failed");
		പോകുക fail;
	}

	EVP_PKEY_free(താക്കോൽ->pkey);
	എങ്കിൽ ((താക്കോൽ->pkey = EVP_PKEY_new()) == ശൂന്യ)
		fatal("EVP_PKEY_new failed");
	എങ്കിൽ (EVP_PKEY_set1_EC_താക്കോൽ(താക്കോൽ->pkey, ec) != 1)
		fatal("EVP_PKEY_set1_EC_KEY failed");
	താക്കോൽ->ecdsa_nid = nid;
	താക്കോൽ->type = താക്കോൽ_ECDSA;
	താക്കോൽ->flags |= SSHKEY_FLAG_EXT;
	എങ്കിൽ (pkcs11_record_താക്കോൽ(p, slotidx, &താക്കോൽ_attr[0], താക്കോൽ))
		പോകുക fail;
	/* success */
	success = 0;
fail:
	എങ്കിൽ (success != 0) {
		sshkey_free(താക്കോൽ);
		താക്കോൽ = ശൂന്യ;
	}
	വേണ്ടി (i = 0; i < 3; i++)
		സ്വതന്ത്രം(താക്കോൽ_attr[i].p_മൂല്യം);
	എങ്കിൽ (ec)
		EC_താക്കോൽ_free(ec);
	എങ്കിൽ (group)
		EC_GROUP_free(group);
	എങ്കിൽ (octet)
		ASN1_OCTET_STRING_free(octet);

	തിരികെ (താക്കോൽ);
}

സ്ഥിതം ഘടന sshkey *
pkcs11_fetch_rsa_pubkey(ഘടന pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 താക്കോൽ_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ശൂന്യ;
	CK_RV			 rv;
	RSA			*rsa = ശൂന്യ;
	BIGNUM			*rsa_n, *rsa_e;
	ഘടന sshkey		*താക്കോൽ = ശൂന്യ;
	പൂർണ്ണസംഖ്യ			 i, success = -1;

	memset(&താക്കോൽ_attr, 0, വലുപ്പം(താക്കോൽ_attr));
	താക്കോൽ_attr[0].type = CKA_ID;
	താക്കോൽ_attr[1].type = CKA_MODULUS;
	താക്കോൽ_attr[2].type = CKA_PUBLIC_EXPONENT;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_മൂല്യം(session, *obj, താക്കോൽ_attr, 3);
	എങ്കിൽ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		തിരികെ (ശൂന്യ);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	എങ്കിൽ (താക്കോൽ_attr[1].ul_മൂല്യം_Len == 0 ||
	    താക്കോൽ_attr[2].ul_മൂല്യം_Len == 0) {
		error("invalid attribute length");
		തിരികെ (ശൂന്യ);
	}

	/* allocate buffers for attributes */
	വേണ്ടി (i = 0; i < 3; i++)
		എങ്കിൽ (താക്കോൽ_attr[i].ul_മൂല്യം_Len > 0)
			താക്കോൽ_attr[i].p_മൂല്യം = xcalloc(1, താക്കോൽ_attr[i].ul_മൂല്യം_Len);

	/* retrieve ID, modulus and public exponent of RSA key */
	rv = f->C_Get_Attribute_മൂല്യം(session, *obj, താക്കോൽ_attr, 3);
	എങ്കിൽ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		പോകുക fail;
	}

	rsa = RSA_new();
	എങ്കിൽ (rsa == ശൂന്യ) {
		error("RSA_new failed");
		പോകുക fail;
	}

	rsa_n = BN_bin2bn(താക്കോൽ_attr[1].p_മൂല്യം, താക്കോൽ_attr[1].ul_മൂല്യം_Len, ശൂന്യ);
	rsa_e = BN_bin2bn(താക്കോൽ_attr[2].p_മൂല്യം, താക്കോൽ_attr[2].ul_മൂല്യം_Len, ശൂന്യ);
	എങ്കിൽ (rsa_n == ശൂന്യ || rsa_e == ശൂന്യ) {
		error("BN_bin2bn failed");
		പോകുക fail;
	}
	എങ്കിൽ (!RSA_set0_താക്കോൽ(rsa, rsa_n, rsa_e, ശൂന്യ))
		fatal_f("set key");
	rsa_n = rsa_e = ശൂന്യ; /* transferred */

	താക്കോൽ = sshkey_new(താക്കോൽ_UNSPEC);
	എങ്കിൽ (താക്കോൽ == ശൂന്യ) {
		error("sshkey_new failed");
		പോകുക fail;
	}

	EVP_PKEY_free(താക്കോൽ->pkey);
	എങ്കിൽ ((താക്കോൽ->pkey = EVP_PKEY_new()) == ശൂന്യ)
		fatal("EVP_PKEY_new failed");
	എങ്കിൽ (EVP_PKEY_set1_RSA(താക്കോൽ->pkey, rsa) != 1)
		fatal("EVP_PKEY_set1_RSA failed");
	താക്കോൽ->type = താക്കോൽ_RSA;
	താക്കോൽ->flags |= SSHKEY_FLAG_EXT;
	എങ്കിൽ (EVP_PKEY_bits(താക്കോൽ->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE) {
		error_f("RSA key too small %d < minimum %d",
		    EVP_PKEY_bits(താക്കോൽ->pkey), SSH_RSA_MINIMUM_MODULUS_SIZE);
		പോകുക fail;
	}
	എങ്കിൽ (pkcs11_record_താക്കോൽ(p, slotidx, &താക്കോൽ_attr[0], താക്കോൽ))
		പോകുക fail;
	/* success */
	success = 0;
fail:
	വേണ്ടി (i = 0; i < 3; i++)
		സ്വതന്ത്രം(താക്കോൽ_attr[i].p_മൂല്യം);
	RSA_free(rsa);
	എങ്കിൽ (success != 0) {
		sshkey_free(താക്കോൽ);
		താക്കോൽ = ശൂന്യ;
	}
	തിരികെ താക്കോൽ;
}
#endif /* WITH_OPENSSL */

സ്ഥിതം ഘടന sshkey *
pkcs11_fetch_ed25519_pubkey(ഘടന pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 താക്കോൽ_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ശൂന്യ;
	CK_RV			 rv;
	ഘടന sshkey		*താക്കോൽ = ശൂന്യ;
	സ്ഥിരം unsigned അക്ഷരം	*d = ശൂന്യ;
	size_t			len;
	അക്ഷരം			*hex = ശൂന്യ;
	പൂർണ്ണസംഖ്യ			 success = -1, i;
	/* https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061180 */
	സ്ഥിരം u_char		 id1[14] = {
		0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64,
		0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
	}; /* PrintableString { "edwards25519" } */
	സ്ഥിരം u_char		 id2[5] = {
		0x06, 0x03, 0x2b, 0x65, 0x70,
	}; /* OBJECT_IDENTIFIER { 1.3.101.112 } */

	memset(&താക്കോൽ_attr, 0, വലുപ്പം(താക്കോൽ_attr));
	താക്കോൽ_attr[0].type = CKA_ID;
	താക്കോൽ_attr[1].type = CKA_EC_POINT; /* XXX or CKA_VALUE ? */
	താക്കോൽ_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_മൂല്യം(session, *obj, താക്കോൽ_attr, 3);
	എങ്കിൽ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		തിരികെ (ശൂന്യ);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	എങ്കിൽ (താക്കോൽ_attr[1].ul_മൂല്യം_Len == 0 ||
	    താക്കോൽ_attr[2].ul_മൂല്യം_Len == 0) {
		error("invalid attribute length");
		തിരികെ (ശൂന്യ);
	}

	/* allocate buffers for attributes */
	വേണ്ടി (i = 0; i < 3; i++) {
		എങ്കിൽ (താക്കോൽ_attr[i].ul_മൂല്യം_Len > 0)
			താക്കോൽ_attr[i].p_മൂല്യം = xcalloc(1, താക്കോൽ_attr[i].ul_മൂല്യം_Len);
	}

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_മൂല്യം(session, *obj, താക്കോൽ_attr, 3);
	എങ്കിൽ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		പോകുക fail;
	}

	/* Expect one of the supported identifiers in CKA_EC_PARAMS */
	d = (u_char *)താക്കോൽ_attr[2].p_മൂല്യം;
	len = താക്കോൽ_attr[2].ul_മൂല്യം_Len;
	എങ്കിൽ ((len != വലുപ്പം(id1) || memcmp(d, id1, വലുപ്പം(id1)) != 0) &&
	    (len != വലുപ്പം(id2) || memcmp(d, id2, വലുപ്പം(id2)) != 0)) {
		hex = tohex(d, len);
		logit_f("unsupported CKA_EC_PARAMS: %s (len %zu)", hex, len);
		പോകുക fail;
	}

	/*
	 * Expect either a raw 32 byte pubkey or an OCTET STRING with
	 * a 32 byte pubkey in CKA_VALUE
	 */
	d = (u_char *)താക്കോൽ_attr[1].p_മൂല്യം;
	len = താക്കോൽ_attr[1].ul_മൂല്യം_Len;
	എങ്കിൽ (len == ED25519_PK_SZ + 2 && d[0] == 0x04 && d[1] == ED25519_PK_SZ) {
		d += 2;
		len -= 2;
	}
	എങ്കിൽ (len != ED25519_PK_SZ) {
		hex = tohex(താക്കോൽ_attr[1].p_മൂല്യം, താക്കോൽ_attr[1].ul_മൂല്യം_Len);
		logit_f("CKA_EC_POINT invalid octet str: %s (len %lu)",
		    hex, (u_long)താക്കോൽ_attr[1].ul_മൂല്യം_Len);
		പോകുക fail;
	}

	എങ്കിൽ ((താക്കോൽ = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ)
		fatal_f("sshkey_new failed");
	താക്കോൽ->ed25519_pk = xmalloc(ED25519_PK_SZ);
	memcpy(താക്കോൽ->ed25519_pk, d, ED25519_PK_SZ);
	താക്കോൽ->type = താക്കോൽ_ED25519;
	താക്കോൽ->flags |= SSHKEY_FLAG_EXT;
	എങ്കിൽ (pkcs11_record_താക്കോൽ(p, slotidx, &താക്കോൽ_attr[0], താക്കോൽ))
		പോകുക fail;
	/* success */
	success = 0;
 fail:
	എങ്കിൽ (success != 0) {
		sshkey_free(താക്കോൽ);
		താക്കോൽ = ശൂന്യ;
	}
	സ്വതന്ത്രം(hex);
	വേണ്ടി (i = 0; i < 3; i++)
		സ്വതന്ത്രം(താക്കോൽ_attr[i].p_മൂല്യം);
	തിരികെ താക്കോൽ;
}

#ifdef WITH_OPENSSL
സ്ഥിതം പൂർണ്ണസംഖ്യ
pkcs11_fetch_x509_pubkey(ഘടന pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj, ഘടന sshkey **keyp, അക്ഷരം **labelp)
{
	CK_ATTRIBUTE		 cert_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ശൂന്യ;
	CK_RV			 rv;
	X509			*x509 = ശൂന്യ;
	X509_NAME		*x509_name = ശൂന്യ;
	EVP_PKEY		*evp;
	RSA			*rsa = ശൂന്യ;
	EC_താക്കോൽ			*ec = ശൂന്യ;
	ഘടന sshkey		*താക്കോൽ = ശൂന്യ;
	പൂർണ്ണസംഖ്യ			 r, i, nid, success = -1;
	സ്ഥിരം u_char		*cp;
	അക്ഷരം			*subject = ശൂന്യ;
#ifdef OPENSSL_HAS_ED25519
	size_t			len;
#endif /* OPENSSL_HAS_ED25519 */

	*keyp = ശൂന്യ;
	*labelp = ശൂന്യ;

	memset(&cert_attr, 0, വലുപ്പം(cert_attr));
	cert_attr[0].type = CKA_ID;
	cert_attr[1].type = CKA_SUBJECT;
	cert_attr[2].type = CKA_മൂല്യം;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_മൂല്യം(session, *obj, cert_attr, 3);
	എങ്കിൽ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		തിരികെ -1;
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	എങ്കിൽ (cert_attr[1].ul_മൂല്യം_Len == 0 ||
	    cert_attr[2].ul_മൂല്യം_Len == 0) {
		error("invalid attribute length");
		തിരികെ -1;
	}

	/* allocate buffers for attributes */
	വേണ്ടി (i = 0; i < 3; i++)
		എങ്കിൽ (cert_attr[i].ul_മൂല്യം_Len > 0)
			cert_attr[i].p_മൂല്യം = xcalloc(1, cert_attr[i].ul_മൂല്യം_Len);

	/* retrieve ID, subject and value of certificate */
	rv = f->C_Get_Attribute_മൂല്യം(session, *obj, cert_attr, 3);
	എങ്കിൽ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		പോകുക out;
	}

	/* Decode DER-encoded cert subject */
	cp = cert_attr[1].p_മൂല്യം;
	എങ്കിൽ ((x509_name = d2i_X509_NAME(ശൂന്യ, &cp,
	    cert_attr[1].ul_മൂല്യം_Len)) == ശൂന്യ ||
	    (subject = X509_NAME_oneline(x509_name, ശൂന്യ, 0)) == ശൂന്യ)
		subject = xstrdup("invalid subject");
	X509_NAME_free(x509_name);

	cp = cert_attr[2].p_മൂല്യം;
	എങ്കിൽ ((x509 = d2i_X509(ശൂന്യ, &cp, cert_attr[2].ul_മൂല്യം_Len)) == ശൂന്യ) {
		error("d2i_x509 failed");
		പോകുക out;
	}

	എങ്കിൽ ((evp = X509_get_pubkey(x509)) == ശൂന്യ) {
		error("X509_get_pubkey failed");
		പോകുക out;
	}

	എങ്കിൽ (EVP_PKEY_base_id(evp) == EVP_PKEY_RSA) {
		എങ്കിൽ (EVP_PKEY_get0_RSA(evp) == ശൂന്യ) {
			error("invalid x509; no rsa key");
			പോകുക out;
		}
		എങ്കിൽ ((rsa = RSAPublic_താക്കോൽ_dup(EVP_PKEY_get0_RSA(evp))) == ശൂന്യ) {
			error("RSAPublicKey_dup failed");
			പോകുക out;
		}

		താക്കോൽ = sshkey_new(താക്കോൽ_UNSPEC);
		എങ്കിൽ (താക്കോൽ == ശൂന്യ) {
			error("sshkey_new failed");
			പോകുക out;
		}

		EVP_PKEY_free(താക്കോൽ->pkey);
		എങ്കിൽ ((താക്കോൽ->pkey = EVP_PKEY_new()) == ശൂന്യ)
			fatal("EVP_PKEY_new failed");
		എങ്കിൽ (EVP_PKEY_set1_RSA(താക്കോൽ->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		താക്കോൽ->type = താക്കോൽ_RSA;
		താക്കോൽ->flags |= SSHKEY_FLAG_EXT;
		എങ്കിൽ (EVP_PKEY_bits(താക്കോൽ->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE) {
			error_f("RSA key too small %d < minimum %d",
			    EVP_PKEY_bits(താക്കോൽ->pkey),
			    SSH_RSA_MINIMUM_MODULUS_SIZE);
			പോകുക out;
		}
		എങ്കിൽ (pkcs11_record_താക്കോൽ(p, slotidx, &cert_attr[0], താക്കോൽ))
			പോകുക out;
		/* success */
		success = 0;
	} അല്ലെങ്കിൽ എങ്കിൽ (EVP_PKEY_base_id(evp) == EVP_PKEY_EC) {
		എങ്കിൽ (EVP_PKEY_get0_EC_താക്കോൽ(evp) == ശൂന്യ) {
			error("invalid x509; no ec key");
			പോകുക out;
		}
		എങ്കിൽ ((ec = EC_താക്കോൽ_dup(EVP_PKEY_get0_EC_താക്കോൽ(evp))) == ശൂന്യ) {
			error("EC_KEY_dup failed");
			പോകുക out;
		}
		എങ്കിൽ ((r = sshkey_ec_validate_public(EC_താക്കോൽ_get0_group(ec),
		    EC_താക്കോൽ_get0_public_താക്കോൽ(ec))) != 0) {
			error_fr(r, "invalid EC key");
			പോകുക out;
		}
		nid = sshkey_ecdsa_താക്കോൽ_to_nid(ec);
		എങ്കിൽ (nid < 0) {
			error("couldn't get curve nid");
			പോകുക out;
		}

		താക്കോൽ = sshkey_new(താക്കോൽ_UNSPEC);
		എങ്കിൽ (താക്കോൽ == ശൂന്യ) {
			error("sshkey_new failed");
			പോകുക out;
		}

		EVP_PKEY_free(താക്കോൽ->pkey);
		എങ്കിൽ ((താക്കോൽ->pkey = EVP_PKEY_new()) == ശൂന്യ)
			fatal("EVP_PKEY_new failed");
		എങ്കിൽ (EVP_PKEY_set1_EC_താക്കോൽ(താക്കോൽ->pkey, ec) != 1)
			fatal("EVP_PKEY_set1_EC_KEY failed");
		താക്കോൽ->ecdsa_nid = nid;
		താക്കോൽ->type = താക്കോൽ_ECDSA;
		താക്കോൽ->flags |= SSHKEY_FLAG_EXT;
		എങ്കിൽ (pkcs11_record_താക്കോൽ(p, slotidx, &cert_attr[0], താക്കോൽ))
			പോകുക out;
		/* success */
		success = 0;
#ifdef OPENSSL_HAS_ED25519
	} അല്ലെങ്കിൽ എങ്കിൽ (EVP_PKEY_base_id(evp) == EVP_PKEY_ED25519) {
		എങ്കിൽ ((താക്കോൽ = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ ||
		    (താക്കോൽ->ed25519_pk = calloc(1, ED25519_PK_SZ)) == ശൂന്യ)
			fatal_f("allocation failed");
		len = ED25519_PK_SZ;
		എങ്കിൽ (!EVP_PKEY_get_raw_public_താക്കോൽ(evp, താക്കോൽ->ed25519_pk, &len)) {
			ossl_error("EVP_PKEY_get_raw_public_key failed");
			പോകുക out;
		}
		എങ്കിൽ (len != ED25519_PK_SZ) {
			error_f("incorrect returned public key "
			    "length for ed25519");
			പോകുക out;
		}
		താക്കോൽ->type = താക്കോൽ_ED25519;
		താക്കോൽ->flags |= SSHKEY_FLAG_EXT;
		എങ്കിൽ (pkcs11_record_താക്കോൽ(p, slotidx, &cert_attr[0], താക്കോൽ))
			പോകുക out;
		/* success */
		success = 0;
#endif /* OPENSSL_HAS_ED25519 */
	} അല്ലെങ്കിൽ {
		error("unknown certificate key type");
		പോകുക out;
	}
 out:
	വേണ്ടി (i = 0; i < 3; i++)
		സ്വതന്ത്രം(cert_attr[i].p_മൂല്യം);
	X509_free(x509);
	RSA_free(rsa);
	EC_താക്കോൽ_free(ec);
	എങ്കിൽ (success != 0 || താക്കോൽ == ശൂന്യ) {
		sshkey_free(താക്കോൽ);
		സ്വതന്ത്രം(subject);
		തിരികെ -1;
	}
	/* success */
	*keyp = താക്കോൽ;
	*labelp = subject;
	തിരികെ 0;
}
#endif /* WITH_OPENSSL */

സ്ഥിതം ശൂന്യം
note_താക്കോൽ(ഘടന pkcs11_provider *p, CK_ULONG slotidx, സ്ഥിരം അക്ഷരം *context,
    ഘടന sshkey *താക്കോൽ)
{
	അക്ഷരം *fp;

	എങ്കിൽ ((fp = sshkey_fingerprint(താക്കോൽ, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ശൂന്യ) {
		error_f("sshkey_fingerprint failed");
		തിരികെ;
	}
	debug2("%s: provider %s slot %lu: %s %s", context, p->name,
	    (u_long)slotidx, sshkey_type(താക്കോൽ), fp);
	സ്വതന്ത്രം(fp);
}

#ifdef WITH_OPENSSL /* libcrypto needed for certificate parsing */
/*
 * lookup certificates for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
pkcs11_fetch_certs(ഘടന pkcs11_provider *p, CK_ULONG slotidx,
    ഘടന sshkey ***keysp, അക്ഷരം ***labelsp, പൂർണ്ണസംഖ്യ *nkeys)
{
	ഘടന sshkey		*താക്കോൽ = ശൂന്യ;
	CK_OBJECT_CLASS		 താക്കോൽ_class;
	CK_ATTRIBUTE		 താക്കോൽ_attr[1];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ശൂന്യ;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	പൂർണ്ണസംഖ്യ			 ret = -1;
	അക്ഷരം			*label;

	memset(&താക്കോൽ_attr, 0, വലുപ്പം(താക്കോൽ_attr));
	memset(&obj, 0, വലുപ്പം(obj));

	താക്കോൽ_class = CKO_CERTIFICATE;
	താക്കോൽ_attr[0].type = CKA_CLASS;
	താക്കോൽ_attr[0].p_മൂല്യം = &താക്കോൽ_class;
	താക്കോൽ_attr[0].ul_മൂല്യം_Len = വലുപ്പം(താക്കോൽ_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, താക്കോൽ_attr, 1);
	എങ്കിൽ (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		പോകുക fail;
	}

	ആകുമ്പോൾ (1) {
		CK_CERTIFICATE_TYPE	ck_cert_type;

		rv = f->C_FindObjects(session, &obj, 1, &n);
		എങ്കിൽ (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			പോകുക fail;
		}
		എങ്കിൽ (n == 0)
			നിർത്തുക;

		memset(&ck_cert_type, 0, വലുപ്പം(ck_cert_type));
		memset(&താക്കോൽ_attr, 0, വലുപ്പം(താക്കോൽ_attr));
		താക്കോൽ_attr[0].type = CKA_CERTIFICATE_TYPE;
		താക്കോൽ_attr[0].p_മൂല്യം = &ck_cert_type;
		താക്കോൽ_attr[0].ul_മൂല്യം_Len = വലുപ്പം(ck_cert_type);

		rv = f->C_Get_Attribute_മൂല്യം(session, obj, താക്കോൽ_attr, 1);
		എങ്കിൽ (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			പോകുക fail;
		}

		താക്കോൽ = ശൂന്യ;
		label = ശൂന്യ;
		തിരഞ്ഞെടുപ്പ് (ck_cert_type) {
		അവസ്ഥ CKC_X_509:
			എങ്കിൽ (pkcs11_fetch_x509_pubkey(p, slotidx, &obj,
			    &താക്കോൽ, &label) != 0) {
				debug_f("failed to fetch key");
				തുടരുക;
			}
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			error("skipping unsupported certificate type %lu",
			    ck_cert_type);
			തുടരുക;
		}
		note_താക്കോൽ(p, slotidx, __func__, താക്കോൽ);
		എങ്കിൽ (pkcs11_താക്കോൽ_included(keysp, nkeys, താക്കോൽ)) {
			debug2_f("key already included");
			sshkey_free(താക്കോൽ);
		} അല്ലെങ്കിൽ {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, വലുപ്പം(ഘടന sshkey *));
			(*keysp)[*nkeys] = താക്കോൽ;
			എങ്കിൽ (labelsp != ശൂന്യ) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, വലുപ്പം(അക്ഷരം *));
				(*labelsp)[*nkeys] = xstrdup((അക്ഷരം *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_FindObjectsFinal(session);
	എങ്കിൽ (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	തിരികെ (ret);
}
#endif /* WITH_OPENSSL */

/*
 * lookup public keys for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
pkcs11_fetch_താക്കോലുകൾ(ഘടന pkcs11_provider *p, CK_ULONG slotidx,
    ഘടന sshkey ***keysp, അക്ഷരം ***labelsp, പൂർണ്ണസംഖ്യ *nkeys)
{
	ഘടന sshkey		*താക്കോൽ = ശൂന്യ;
	CK_OBJECT_CLASS		 താക്കോൽ_class;
	CK_ATTRIBUTE		 താക്കോൽ_attr[2];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ശൂന്യ;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	പൂർണ്ണസംഖ്യ			 ret = -1;

	memset(&താക്കോൽ_attr, 0, വലുപ്പം(താക്കോൽ_attr));
	memset(&obj, 0, വലുപ്പം(obj));

	താക്കോൽ_class = CKO_PUBLIC_താക്കോൽ;
	താക്കോൽ_attr[0].type = CKA_CLASS;
	താക്കോൽ_attr[0].p_മൂല്യം = &താക്കോൽ_class;
	താക്കോൽ_attr[0].ul_മൂല്യം_Len = വലുപ്പം(താക്കോൽ_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, താക്കോൽ_attr, 1);
	എങ്കിൽ (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		പോകുക fail;
	}

	ആകുമ്പോൾ (1) {
		CK_താക്കോൽ_TYPE	ck_താക്കോൽ_type;
		CK_UTF8CHAR	label[256];

		rv = f->C_FindObjects(session, &obj, 1, &n);
		എങ്കിൽ (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			പോകുക fail;
		}
		എങ്കിൽ (n == 0)
			നിർത്തുക;

		memset(&ck_താക്കോൽ_type, 0, വലുപ്പം(ck_താക്കോൽ_type));
		memset(&താക്കോൽ_attr, 0, വലുപ്പം(താക്കോൽ_attr));
		താക്കോൽ_attr[0].type = CKA_താക്കോൽ_TYPE;
		താക്കോൽ_attr[0].p_മൂല്യം = &ck_താക്കോൽ_type;
		താക്കോൽ_attr[0].ul_മൂല്യം_Len = വലുപ്പം(ck_താക്കോൽ_type);
		താക്കോൽ_attr[1].type = CKA_LABEL;
		താക്കോൽ_attr[1].p_മൂല്യം = &label;
		താക്കോൽ_attr[1].ul_മൂല്യം_Len = വലുപ്പം(label) - 1;

		rv = f->C_Get_Attribute_മൂല്യം(session, obj, താക്കോൽ_attr, 2);
		എങ്കിൽ (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			പോകുക fail;
		}

		label[താക്കോൽ_attr[1].ul_മൂല്യം_Len] = '\0';

		തിരഞ്ഞെടുപ്പ് (ck_താക്കോൽ_type) {
#ifdef WITH_OPENSSL
		അവസ്ഥ CKK_RSA:
			താക്കോൽ = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			നിർത്തുക;
		അവസ്ഥ CKK_ECDSA:
			താക്കോൽ = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			നിർത്തുക;
#endif /* WITH_OPENSSL */
		അവസ്ഥ CKK_EC_EDWARDS:
			താക്കോൽ = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			/* XXX print key type? */
			താക്കോൽ = ശൂന്യ;
			error("skipping unsupported key type 0x%lx",
			    (u_long)ck_താക്കോൽ_type);
		}

		എങ്കിൽ (താക്കോൽ == ശൂന്യ) {
			debug_f("failed to fetch key");
			തുടരുക;
		}
		note_താക്കോൽ(p, slotidx, __func__, താക്കോൽ);
		എങ്കിൽ (pkcs11_താക്കോൽ_included(keysp, nkeys, താക്കോൽ)) {
			debug2_f("key already included");
			sshkey_free(താക്കോൽ);
		} അല്ലെങ്കിൽ {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, വലുപ്പം(ഘടന sshkey *));
			(*keysp)[*nkeys] = താക്കോൽ;
			എങ്കിൽ (labelsp != ശൂന്യ) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, വലുപ്പം(അക്ഷരം *));
				(*labelsp)[*nkeys] = xstrdup((അക്ഷരം *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_FindObjectsFinal(session);
	എങ്കിൽ (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	തിരികെ (ret);
}

#ifdef WITH_PKCS11_KEYGEN
#define FILL_ATTR(attr, idx, typ, val, len) \
	{ (attr[idx]).type=(typ); (attr[idx]).p_മൂല്യം=(val); (attr[idx]).ul_മൂല്യം_Len=len; idx++; }

സ്ഥിതം ഘടന sshkey *
pkcs11_rsa_generate_private_താക്കോൽ(ഘടന pkcs11_provider *p, CK_ULONG slotidx,
    അക്ഷരം *label, CK_ULONG bits, CK_BYTE keyid, uint32_t *err)
{
	ഘടന pkcs11_slotinfo	*si;
	അക്ഷരം			*plabel = label ? label : "";
	പൂർണ്ണസംഖ്യ			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_താക്കോൽ_2, priv_താക്കോൽ;
	CK_ATTRIBUTE		 tpub[16], tpriv[16];
	CK_MECHANISM		 mech = {
	    CKM_RSA_PKCS_താക്കോൽ_PAIR_GEN, NULL_PTR, 0
	};
	CK_BYTE			 pubExponent[] = {
	    0x01, 0x00, 0x01 /* RSA_F4 in bytes */
	};
	pubkey_filter[0].p_മൂല്യം = &pubkey_class;
	cert_filter[0].p_മൂല്യം = &cert_class;

	*err = 0;

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, വലുപ്പം(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, വലുപ്പം(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, വലുപ്പം(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    വലുപ്പം(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, വലുപ്പം(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, വലുപ്പം(false_val));
	FILL_ATTR(tpub, npub, CKA_MODULUS_BITS, &bits, വലുപ്പം(bits));
	FILL_ATTR(tpub, npub, CKA_PUBLIC_EXPONENT, pubExponent,
	    വലുപ്പം(pubExponent));
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, വലുപ്പം(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN,  &true_val, വലുപ്പം(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL,  plabel, strlen(plabel));
	FILL_ATTR(tpriv, npriv, CKA_PRIVATE,  &true_val, വലുപ്പം(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE,  &true_val, വലുപ്പം(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT,  &false_val, വലുപ്പം(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN,  &true_val, വലുപ്പം(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER,  &false_val,
	    വലുപ്പം(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP,  &false_val, വലുപ്പം(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE,  &false_val, വലുപ്പം(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, വലുപ്പം(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	എങ്കിൽ ((rv = f->C_Generate_താക്കോൽ_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_താക്കോൽ_2, &priv_താക്കോൽ)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		തിരികെ ശൂന്യ;
	}

	തിരികെ pkcs11_fetch_rsa_pubkey(p, slotidx, &pub_താക്കോൽ_2);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
h2i(അക്ഷരം c)
{
	എങ്കിൽ (c >= '0' && c <= '9')
		തിരികെ c - '0';
	അല്ലെങ്കിൽ എങ്കിൽ (c >= 'a' && c <= 'f')
		തിരികെ c - 'a' + 10;
	അല്ലെങ്കിൽ എങ്കിൽ (c >= 'A' && c <= 'F')
		തിരികെ c - 'A' + 10;
	അല്ലെങ്കിൽ
		തിരികെ -1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
pkcs11_decode_hex(സ്ഥിരം അക്ഷരം *hex, unsigned അക്ഷരം **dest, size_t *rlen)
{
	size_t	i, len;

	എങ്കിൽ (dest)
		*dest = ശൂന്യ;
	എങ്കിൽ (rlen)
		*rlen = 0;

	എങ്കിൽ ((len = strlen(hex)) % 2)
		തിരികെ -1;
	len /= 2;

	*dest = xmalloc(len);

	വേണ്ടി (i = 0; i < len; i++) {
		പൂർണ്ണസംഖ്യ hi, lo;

		hi = h2i(hex[2 * i]);
		lo = h2i(hex[(2 * i) + 1]);
		എങ്കിൽ (hi == -1 || lo == -1)
			തിരികെ -1;
		(*dest)[i] = (hi << 4) | lo;
	}

	എങ്കിൽ (rlen)
		*rlen = len;

	തിരികെ 0;
}

സ്ഥിതം ഘടന ec_curve_info {
	സ്ഥിരം അക്ഷരം	*name;
	സ്ഥിരം അക്ഷരം	*oid;
	സ്ഥിരം അക്ഷരം	*oid_encoded;
	size_t		 size;
} ec_curve_infos[] = {
	{"prime256v1",	"1.2.840.10045.3.1.7",	"06082A8648CE3D030107", 256},
	{"secp384r1",	"1.3.132.0.34",		"06052B81040022",	384},
	{"secp521r1",	"1.3.132.0.35",		"06052B81040023",	521},
	{ശൂന്യ,		ശൂന്യ,			ശൂന്യ,			0},
};

സ്ഥിതം ഘടന sshkey *
pkcs11_ecdsa_generate_private_താക്കോൽ(ഘടന pkcs11_provider *p, CK_ULONG slotidx,
    അക്ഷരം *label, CK_ULONG bits, CK_BYTE keyid, uint32_t *err)
{
	ഘടന pkcs11_slotinfo	*si;
	അക്ഷരം			*plabel = label ? label : "";
	പൂർണ്ണസംഖ്യ			 i;
	size_t			 ecparams_size;
	unsigned അക്ഷരം		*ecparams = ശൂന്യ;
	പൂർണ്ണസംഖ്യ			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_താക്കോൽ_2, priv_താക്കോൽ;
	CK_MECHANISM		 mech = {
	    CKM_EC_താക്കോൽ_PAIR_GEN, NULL_PTR, 0
	};
	CK_ATTRIBUTE		 tpub[16], tpriv[16];

	*err = 0;

	വേണ്ടി (i = 0; ec_curve_infos[i].name; i++) {
		എങ്കിൽ (ec_curve_infos[i].size == bits)
			നിർത്തുക;
	}
	എങ്കിൽ (!ec_curve_infos[i].name) {
		error_f("invalid key size %lu", bits);
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ (pkcs11_decode_hex(ec_curve_infos[i].oid_encoded, &ecparams,
	    &ecparams_size) == -1) {
		error_f("invalid oid");
		തിരികെ ശൂന്യ;
	}

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, വലുപ്പം(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, വലുപ്പം(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, വലുപ്പം(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    വലുപ്പം(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, വലുപ്പം(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, വലുപ്പം(false_val));
	FILL_ATTR(tpub, npub, CKA_EC_PARAMS, ecparams, ecparams_size);
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, വലുപ്പം(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN, &true_val, വലുപ്പം(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpriv, npriv, CKA_PRIVATE, &true_val, വലുപ്പം(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE, &true_val, വലുപ്പം(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT, &false_val, വലുപ്പം(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN, &true_val, വലുപ്പം(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER, &false_val,
	    വലുപ്പം(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP, &false_val, വലുപ്പം(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE, &false_val, വലുപ്പം(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, വലുപ്പം(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	എങ്കിൽ ((rv = f->C_Generate_താക്കോൽ_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_താക്കോൽ_2, &priv_താക്കോൽ)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		തിരികെ ശൂന്യ;
	}

	തിരികെ pkcs11_fetch_ecdsa_pubkey(p, slotidx, &pub_താക്കോൽ_2);
}
#endif /* WITH_PKCS11_KEYGEN */

/*
 * register a new provider, fails if provider already exists. if
 * keyp is provided, fetch keys.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
pkcs11_register_provider(അക്ഷരം *provider_id, അക്ഷരം *pin,
    ഘടന sshkey ***keyp, അക്ഷരം ***labelsp,
    ഘടന pkcs11_provider **providerp, CK_ULONG user)
{
	പൂർണ്ണസംഖ്യ nkeys, need_finalize = 0;
	പൂർണ്ണസംഖ്യ ret = -1;
	ഘടന pkcs11_provider *p = ശൂന്യ;
	ശൂന്യം *handle = ശൂന്യ;
	CK_RV (*getfunctionlist)(CK_FUNCTION_LIST **);
	CK_RV rv;
	CK_FUNCTION_LIST *f = ശൂന്യ;
	CK_TOKEN_INFO *token;
	CK_ULONG i;

	എങ്കിൽ (providerp == ശൂന്യ)
		പോകുക fail;
	*providerp = ശൂന്യ;

	എങ്കിൽ (keyp != ശൂന്യ)
		*keyp = ശൂന്യ;
	എങ്കിൽ (labelsp != ശൂന്യ)
		*labelsp = ശൂന്യ;

	എങ്കിൽ (pkcs11_provider_lookup(provider_id) != ശൂന്യ) {
		debug_f("provider already registered: %s", provider_id);
		പോകുക fail;
	}
	എങ്കിൽ (lib_contains_ചിഹ്നം(provider_id, "C_GetFunctionList") != 0) {
		error("provider %s is not a PKCS11 library", provider_id);
		പോകുക fail;
	}
	/* open shared pkcs11-library */
	എങ്കിൽ ((handle = dlopen(provider_id, RTLD_NOW)) == ശൂന്യ) {
		error("dlopen %s failed: %s", provider_id, dlerror());
		പോകുക fail;
	}
	എങ്കിൽ ((getfunctionlist = dlsym(handle, "C_GetFunctionList")) == ശൂന്യ)
		fatal("dlsym(C_GetFunctionList) failed: %s", dlerror());
	p = xcalloc(1, വലുപ്പം(*p));
	p->name = xstrdup(provider_id);
	p->handle = handle;
	/* set up the pkcs11 callbacks */
	എങ്കിൽ ((rv = (*getfunctionlist)(&f)) != CKR_OK) {
		error("C_GetFunctionList for provider %s failed: %lu",
		    provider_id, rv);
		പോകുക fail;
	}
	p->function_list = f;
	എങ്കിൽ ((rv = f->C_Initialize(ശൂന്യ)) != CKR_OK) {
		error("C_Initialize for provider %s failed: %lu",
		    provider_id, rv);
		പോകുക fail;
	}
	need_finalize = 1;
	എങ്കിൽ ((rv = f->C_GetInfo(&p->info)) != CKR_OK) {
		error("C_GetInfo for provider %s failed: %lu",
		    provider_id, rv);
		പോകുക fail;
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
	എങ്കിൽ ((rv = f->C_GetSlotList(CK_TRUE, ശൂന്യ, &p->nslots)) != CKR_OK) {
		error("C_GetSlotList failed: %lu", rv);
		പോകുക fail;
	}
	എങ്കിൽ (p->nslots == 0) {
		debug_f("provider %s returned no slots", provider_id);
		ret = -SSH_PKCS11_ERR_NO_SLOTS;
		പോകുക fail;
	}
	p->slotlist = xcalloc(p->nslots, വലുപ്പം(CK_SLOT_ID));
	എങ്കിൽ ((rv = f->C_GetSlotList(CK_TRUE, p->slotlist, &p->nslots))
	    != CKR_OK) {
		error("C_GetSlotList for provider %s failed: %lu",
		    provider_id, rv);
		പോകുക fail;
	}
	p->slotinfo = xcalloc(p->nslots, വലുപ്പം(ഘടന pkcs11_slotinfo));
	p->valid = 1;
	nkeys = 0;
	വേണ്ടി (i = 0; i < p->nslots; i++) {
		token = &p->slotinfo[i].token;
		എങ്കിൽ ((rv = f->C_GetTokenInfo(p->slotlist[i], token))
		    != CKR_OK) {
			error("C_GetTokenInfo for provider %s slot %lu "
			    "failed: %lu", provider_id, (u_long)i, rv);
			തുടരുക;
		}
		എങ്കിൽ ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
			debug2_f("ignoring uninitialised token in "
			    "provider %s slot %lu", provider_id, (u_long)i);
			തുടരുക;
		}
		debug("provider %s slot %lu: label <%.*s> "
		    "manufacturerID <%.*s> model <%.*s> serial <%.*s> "
		    "flags 0x%lx",
		    provider_id, (unsigned long)i,
		    RMSPACE(token->label), RMSPACE(token->manufacturerID),
		    RMSPACE(token->model), RMSPACE(token->serial_സംഖ്യ_2),
		    token->flags);
		/*
		 * open session, login with pin and retrieve public
		 * keys (if keyp is provided)
		 */
		എങ്കിൽ ((ret = pkcs11_open_session(p, i, pin, user)) != 0 ||
		    keyp == ശൂന്യ)
			തുടരുക;
		pkcs11_fetch_താക്കോലുകൾ(p, i, keyp, labelsp, &nkeys);
#ifdef WITH_OPENSSL
		pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#endif
		എങ്കിൽ (nkeys == 0 && !p->slotinfo[i].logged_in &&
		    pkcs11_interactive) {
			/*
			 * Some tokens require login before they will
			 * expose keys.
			 */
			എങ്കിൽ (pkcs11_login_slot(p, &p->slotinfo[i],
			    CKU_USER) < 0) {
				error("login failed");
				തുടരുക;
			}
			pkcs11_fetch_താക്കോലുകൾ(p, i, keyp, labelsp, &nkeys);
#ifdef WITH_OPENSSL
			pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#endif
		}
	}

	/* now owned by caller */
	*providerp = p;

	TAILQ_INSERT_TAIL(&pkcs11_providers, p, next);
	p->refcount++;	/* add to provider list */

	തിരികെ (nkeys);
fail:
	എങ്കിൽ (need_finalize && (rv = f->C_Finalize(ശൂന്യ)) != CKR_OK)
		error("C_Finalize for provider %s failed: %lu",
		    provider_id, rv);
	എങ്കിൽ (p) {
		സ്വതന്ത്രം(p->name);
		സ്വതന്ത്രം(p->slotlist);
		സ്വതന്ത്രം(p->slotinfo);
		സ്വതന്ത്രം(p);
	}
	എങ്കിൽ (handle)
		dlclose(handle);
	എങ്കിൽ (ret > 0)
		ret = -1;
	തിരികെ (ret);
}

പൂർണ്ണസംഖ്യ
pkcs11_init(പൂർണ്ണസംഖ്യ interactive)
{
	debug3_f("called, interactive = %d", interactive);

	pkcs11_interactive = interactive;
	TAILQ_INIT(&pkcs11_providers);
	TAILQ_INIT(&pkcs11_താക്കോലുകൾ);
	തിരികെ (0);
}

/* unregister all providers, keys might still point to the providers */
ശൂന്യം
pkcs11_terminate(ശൂന്യം)
{
	ഘടന pkcs11_provider *p;
	ഘടന pkcs11_താക്കോൽ *k11;

	debug3_f("called");

	ആകുമ്പോൾ ((k11 = TAILQ_FIRST(&pkcs11_താക്കോലുകൾ)) != ശൂന്യ) {
		TAILQ_REMOVE(&pkcs11_താക്കോലുകൾ, k11, next);
		pkcs11_k11_free(k11);
	}
	ആകുമ്പോൾ ((p = TAILQ_FIRST(&pkcs11_providers)) != ശൂന്യ) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
}

/*
 * register a new provider and get number of keys hold by the token,
 * fails if provider already exists
 */
പൂർണ്ണസംഖ്യ
pkcs11_add_provider(അക്ഷരം *provider_id, അക്ഷരം *pin, ഘടന sshkey ***keyp,
    അക്ഷരം ***labelsp)
{
	ഘടന pkcs11_provider *p = ശൂന്യ;
	പൂർണ്ണസംഖ്യ nkeys;

	nkeys = pkcs11_register_provider(provider_id, pin, keyp, labelsp,
	    &p, CKU_USER);

	/* no keys found or some other error, de-register provider */
	എങ്കിൽ (nkeys <= 0 && p != ശൂന്യ) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
	എങ്കിൽ (nkeys == 0)
		debug_f("provider %s returned no keys", provider_id);

	തിരികെ (nkeys);
}

പൂർണ്ണസംഖ്യ
pkcs11_sign(ഘടന sshkey *താക്കോൽ,
    u_char **sigp, size_t *lenp,
    സ്ഥിരം u_char *data, size_t datalen,
    സ്ഥിരം അക്ഷരം *alg, സ്ഥിരം അക്ഷരം *sk_provider,
    സ്ഥിരം അക്ഷരം *sk_pin, u_int compat)
{
	തിരഞ്ഞെടുപ്പ് (താക്കോൽ->type) {
#ifdef WITH_OPENSSL
	അവസ്ഥ താക്കോൽ_RSA:
	അവസ്ഥ താക്കോൽ_RSA_CERT:
		തിരികെ pkcs11_sign_rsa(താക്കോൽ, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	അവസ്ഥ താക്കോൽ_ECDSA:
	അവസ്ഥ താക്കോൽ_ECDSA_CERT:
		തിരികെ pkcs11_sign_ecdsa(താക്കോൽ, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
#endif /* WITH_OPENSSL */
	അവസ്ഥ താക്കോൽ_ED25519:
	അവസ്ഥ താക്കോൽ_ED25519_CERT:
		തിരികെ pkcs11_sign_ed25519(താക്കോൽ, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	സ്ഥിരസ്ഥിതി:
		തിരികെ SSH_ERR_താക്കോൽ_TYPE_UNKNOWN;
	}
}

ശൂന്യം
pkcs11_താക്കോൽ_free(ഘടന sshkey *താക്കോൽ)
{
	/* never called */
}

#ifdef WITH_PKCS11_KEYGEN
ഘടന sshkey *
pkcs11_gakp(അക്ഷരം *provider_id, അക്ഷരം *pin, unsigned പൂർണ്ണസംഖ്യ slotidx, അക്ഷരം *label,
    unsigned പൂർണ്ണസംഖ്യ type, unsigned പൂർണ്ണസംഖ്യ bits, unsigned അക്ഷരം keyid, uint32_t *err)
{
	ഘടന pkcs11_provider	*p = ശൂന്യ;
	ഘടന pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	ഘടന sshkey		*k = ശൂന്യ;
	പൂർണ്ണസംഖ്യ			 ret = -1, reset_pin = 0, reset_provider = 0;
	CK_RV			 rv;

	*err = 0;

	എങ്കിൽ ((p = pkcs11_provider_lookup(provider_id)) != ശൂന്യ)
		debug_f("provider \"%s\" available", provider_id);
	അല്ലെങ്കിൽ എങ്കിൽ ((ret = pkcs11_register_provider(provider_id, pin, ശൂന്യ, ശൂന്യ,
	    &p, CKU_SO)) < 0) {
		debug_f("could not register provider %s", provider_id);
		പോകുക out;
	} അല്ലെങ്കിൽ
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	എങ്കിൽ ((rv = f->C_SetOperationState(session , pin, strlen(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} അല്ലെങ്കിൽ
		reset_pin = 1;

	തിരഞ്ഞെടുപ്പ് (type) {
	അവസ്ഥ താക്കോൽ_RSA:
		എങ്കിൽ ((k = pkcs11_rsa_generate_private_താക്കോൽ(p, slotidx, label,
		    bits, keyid, err)) == ശൂന്യ) {
			debug_f("failed to generate RSA key");
			പോകുക out;
		}
		നിർത്തുക;
	അവസ്ഥ താക്കോൽ_ECDSA:
		എങ്കിൽ ((k = pkcs11_ecdsa_generate_private_താക്കോൽ(p, slotidx, label,
		    bits, keyid, err)) == ശൂന്യ) {
			debug_f("failed to generate ECDSA key");
			പോകുക out;
		}
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		*err = SSH_PKCS11_ERR_GENERIC;
		debug_f("unknown type %d", type);
		പോകുക out;
	}

out:
	എങ്കിൽ (reset_pin)
		f->C_SetOperationState(session , ശൂന്യ, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	എങ്കിൽ (reset_provider)
		pkcs11_del_provider(provider_id);

	തിരികെ (k);
}

ഘടന sshkey *
pkcs11_destroy_keypair(അക്ഷരം *provider_id, അക്ഷരം *pin, unsigned long slotidx,
    unsigned അക്ഷരം keyid, uint32_t *err)
{
	ഘടന pkcs11_provider	*p = ശൂന്യ;
	ഘടന pkcs11_slotinfo	*si;
	ഘടന sshkey		*k = ശൂന്യ;
	പൂർണ്ണസംഖ്യ			 reset_pin = 0, reset_provider = 0;
	CK_ULONG		 nattrs;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_ATTRIBUTE		 attrs[16];
	CK_OBJECT_CLASS		 താക്കോൽ_class;
	CK_താക്കോൽ_TYPE		 താക്കോൽ_type;
	CK_OBJECT_HANDLE	 obj = CK_INVALID_HANDLE;
	CK_RV			 rv;

	*err = 0;

	എങ്കിൽ ((p = pkcs11_provider_lookup(provider_id)) != ശൂന്യ) {
		debug_f("using provider \"%s\"", provider_id);
	} അല്ലെങ്കിൽ എങ്കിൽ (pkcs11_register_provider(provider_id, pin, ശൂന്യ, ശൂന്യ, &p,
	    CKU_SO) < 0) {
		debug_f("could not register provider %s",
		    provider_id);
		പോകുക out;
	} അല്ലെങ്കിൽ
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	എങ്കിൽ ((rv = f->C_SetOperationState(session , pin, strlen(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} അല്ലെങ്കിൽ
		reset_pin = 1;

	/* private key */
	nattrs = 0;
	താക്കോൽ_class = CKO_PRIVATE_താക്കോൽ;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &താക്കോൽ_class, വലുപ്പം(താക്കോൽ_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, വലുപ്പം(keyid));

	എങ്കിൽ (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {
		എങ്കിൽ ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy private key 0x%hhx",
			    keyid);
			*err = rv;
			പോകുക out;
		}
	}

	/* public key */
	nattrs = 0;
	താക്കോൽ_class = CKO_PUBLIC_താക്കോൽ;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &താക്കോൽ_class, വലുപ്പം(താക്കോൽ_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, വലുപ്പം(keyid));

	എങ്കിൽ (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {

		/* get key type */
		nattrs = 0;
		FILL_ATTR(attrs, nattrs, CKA_താക്കോൽ_TYPE, &താക്കോൽ_type,
		    വലുപ്പം(താക്കോൽ_type));
		rv = f->C_Get_Attribute_മൂല്യം(session, obj, attrs, nattrs);
		എങ്കിൽ (rv != CKR_OK) {
			debug_f("could not get key type of public key 0x%hhx",
			    keyid);
			*err = rv;
			താക്കോൽ_type = -1;
		}
		തിരഞ്ഞെടുപ്പ് (താക്കോൽ_type) {
#ifdef WITH_OPENSSL
		അവസ്ഥ CKK_RSA:
			k = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			നിർത്തുക;
		അവസ്ഥ CKK_ECDSA:
			k = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			നിർത്തുക;
#endif /* WITH_OPENSSL */
		അവസ്ഥ CKK_EC_EDWARDS:
			k = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			debug_f("unsupported key type %lu", (u_long)താക്കോൽ_type);
			നിർത്തുക;
		}

		എങ്കിൽ ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy public key 0x%hhx", keyid);
			*err = rv;
			പോകുക out;
		}
	}

out:
	എങ്കിൽ (reset_pin)
		f->C_SetOperationState(session , ശൂന്യ, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	എങ്കിൽ (reset_provider)
		pkcs11_del_provider(provider_id);

	തിരികെ (k);
}
#endif /* WITH_PKCS11_KEYGEN */
#അല്ലെങ്കിൽ /* ENABLE_PKCS11 */

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "ssh-pkcs11.h"

പൂർണ്ണസംഖ്യ
pkcs11_init(പൂർണ്ണസംഖ്യ interactive)
{
	error_f("PKCS#11 not supported");
	തിരികെ (-1);
}

പൂർണ്ണസംഖ്യ
pkcs11_add_provider(അക്ഷരം *provider_id, അക്ഷരം *pin, ഘടന sshkey ***keyp,
    അക്ഷരം ***labelsp)
{
	error_f("PKCS#11 not supported");
	തിരികെ (-1);
}

ശൂന്യം
pkcs11_താക്കോൽ_free(ഘടന sshkey *താക്കോൽ)
{
	error_f("PKCS#11 not supported");
}

പൂർണ്ണസംഖ്യ
pkcs11_sign(ഘടന sshkey *താക്കോൽ,
    u_char **sigp, size_t *lenp,
    സ്ഥിരം u_char *data, size_t datalen,
    സ്ഥിരം അക്ഷരം *alg, സ്ഥിരം അക്ഷരം *sk_provider,
    സ്ഥിരം അക്ഷരം *sk_pin, u_int compat)
{
	error_f("PKCS#11 not supported");
	തിരികെ SSH_ERR_FEATURE_UNSUPPORTED;
}

ശൂന്യം
pkcs11_terminate(ശൂന്യം)
{
	error_f("PKCS#11 not supported");
}
#endif /* ENABLE_PKCS11 */
