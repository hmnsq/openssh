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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_PKCS11

#ಅನ್ತರ್ಭಾವ <sys/time.h>

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>

#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <dlfcn.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ecdsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/x509.h>
#ಅನ್ತರ್ಭಾವ <openssl/err.h>
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿಸು CRYPTOKI_COMPAT
#ಅನ್ತರ್ಭಾವ "pkcs11.h"

#ವ್ಯಾಖ್ಯಾನಿಸು SSHKEY_ಆಂತರಿಕ
#ಅನ್ತರ್ಭಾವ "sshkey.h"

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssh-pkcs11.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "crypto_api.h"

ರಚನೆ pkcs11_slotinfo {
	CK_TOKEN_INFO		token;
	CK_SESSION_HANDLE	session;
	ಪೂರ್ಣಾಂಕ			logged_ಒಳ;
};

ರಚನೆ pkcs11_provider {
	ಅಕ್ಷರ			*name;
	ಶೂನ್ಯ			*handle;
	CK_FUNCTION_LIST	*function_list;
	CK_INFO			info;
	CK_ULONG		nslots;
	CK_ಸ್ಥಾನ_ID		*slotlist;
	ರಚನೆ pkcs11_slotinfo	*slotinfo;
	ಪೂರ್ಣಾಂಕ			valid;
	ಪೂರ್ಣಾಂಕ			refcount;
	TAILQ_ENTRY(pkcs11_provider) ಮುಂದಿನ;
};

TAILQ_HEAD(, pkcs11_provider) pkcs11_providers;

ರಚನೆ pkcs11_ಕೀಲಿ {
	ರಚನೆ sshbuf		*keyblob;
	ರಚನೆ pkcs11_provider	*provider;
	CK_ULONG		slotidx;
	ಅಕ್ಷರ			*keyid;
	ಪೂರ್ಣಾಂಕ			keyid_len;
	TAILQ_ENTRY(pkcs11_ಕೀಲಿ)	ಮುಂದಿನ;
};

TAILQ_HEAD(, pkcs11_ಕೀಲಿ) pkcs11_ಕೀಲಿಗಳು; /* XXX a tree would be better */

ಪೂರ್ಣಾಂಕ pkcs11_interactive = 0;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
ಸ್ಥಿರ ಶೂನ್ಯ
ossl_error(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಸಂದೇಶ)
{
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ    e;

	error_f("%s", ಸಂದೇಶ);
	ಆಗ ((e = ERR_get_error()) != 0)
		error_f("libcrypto error: %s", ERR_error_string(e, ಖಾಲಿ));
}
#ಆದರೆ_ಅಂತ್ಯ

/*
 * finalize a provider shared library, it's no longer usable.
 * however, there might still be keys referencing this provider,
 * so the actual freeing of memory is handled by pkcs11_provider_unref().
 * this is called when a provider gets unregistered.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
pkcs11_provider_finalize(ರಚನೆ pkcs11_provider *p)
{
	CK_RV rv;
	CK_ULONG i;

	debug_f("provider \"%s\" refcount %d valid %d",
	    p->name, p->refcount, p->valid);
	ಆದರೆ (!p->valid)
		ಹಿಂತಿರುಗಿ;
	ಗಾಗಿ (i = 0; i < p->nslots; i++) {
		ಆದರೆ (p->slotinfo[i].session &&
		    (rv = p->function_list->C_CloseSession(
		    p->slotinfo[i].session)) != CKR_OK)
			error("C_CloseSession failed: %lu", rv);
	}
	ಆದರೆ ((rv = p->function_list->C_Finalize(ಖಾಲಿ)) != CKR_OK)
		error("C_Finalize failed: %lu", rv);
	p->valid = 0;
	p->function_list = ಖಾಲಿ;
	dlclose(p->handle);
}

/*
 * remove a reference to the provider.
 * called when a key gets destroyed or when the provider is unregistered.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
pkcs11_provider_unref(ರಚನೆ pkcs11_provider *p)
{
	debug_f("provider \"%s\" refcount %d", p->name, p->refcount);
	ಆದರೆ (--p->refcount <= 0) {
		ಆದರೆ (p->valid)
			error_f("provider \"%s\" still valid", p->name);
		ಬಿಡುಗಡೆ(p->name);
		ಬಿಡುಗಡೆ(p->slotlist);
		ಬಿಡುಗಡೆ(p->slotinfo);
		ಬಿಡುಗಡೆ(p);
	}
}

/* lookup provider by name */
ಸ್ಥಿರ ರಚನೆ pkcs11_provider *
pkcs11_provider_lookup(ಅಕ್ಷರ *provider_id)
{
	ರಚನೆ pkcs11_provider *p;

	TAILQ_FOREACH(p, &pkcs11_providers, ಮುಂದಿನ) {
		debug("check provider \"%s\"", p->name);
		ಆದರೆ (!strcmp(provider_id, p->name))
			ಹಿಂತಿರುಗಿ (p);
	}
	ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
}

/* unregister provider by name */
ಪೂರ್ಣಾಂಕ
pkcs11_del_provider(ಅಕ್ಷರ *provider_id)
{
	ರಚನೆ pkcs11_provider *p;

	ಆದರೆ ((p = pkcs11_provider_lookup(provider_id)) != ಖಾಲಿ) {
		TAILQ_REMOVE(&pkcs11_providers, p, ಮುಂದಿನ);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
		ಹಿಂತಿರುಗಿ (0);
	}
	ಹಿಂತಿರುಗಿ (-1);
}

/* release a wrapped object */
ಸ್ಥಿರ ಶೂನ್ಯ
pkcs11_k11_free(ರಚನೆ pkcs11_ಕೀಲಿ *k11)
{
	ಆದರೆ (k11 == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (k11->provider)
		pkcs11_provider_unref(k11->provider);
	ಬಿಡುಗಡೆ(k11->keyid);
	sshbuf_free(k11->keyblob);
	ಬಿಡುಗಡೆ(k11);
}

/* find a single 'obj' for given attributes */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pkcs11_ಕಂಡುಹಿಡಿ(ರಚನೆ pkcs11_provider *p, CK_ULONG slotidx, CK_ATTRIBUTE *attr,
    CK_ULONG nattr, CK_OBJECT_HANDLE *obj)
{
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	session;
	CK_ULONG		nfound = 0;
	CK_RV			rv;
	ಪೂರ್ಣಾಂಕ			ret = -1;

	f = p->function_list;
	session = p->slotinfo[slotidx].session;
	ಆದರೆ ((rv = f->C_ಕಂಡುಹಿಡಿ_Objects_Init(session, attr, nattr)) != CKR_OK) {
		error("C_FindObjectsInit failed (nattr %lu): %lu", nattr, rv);
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಆದರೆ ((rv = f->C_ಕಂಡುಹಿಡಿ_Objects(session, obj, 1, &nfound)) != CKR_OK ||
	    nfound != 1) {
		debug("C_FindObjects failed (nfound %lu nattr %lu): %lu",
		    nfound, nattr, rv);
	} ಇಲ್ಲದಿದ್ದರೆ
		ret = 0;
	ಆದರೆ ((rv = f->C_ಕಂಡುಹಿಡಿ_Objects_Final(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	ಹಿಂತಿರುಗಿ (ret);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pkcs11_login_ಸ್ಥಾನ(ರಚನೆ pkcs11_provider *provider, ರಚನೆ pkcs11_slotinfo *si,
    CK_USER_TYPE type)
{
	ಅಕ್ಷರ			*pin = ಖಾಲಿ, prompt[1024];
	CK_RV			 rv;

	ಆದರೆ (provider == ಖಾಲಿ || si == ಖಾಲಿ || !provider->valid) {
		error("no pkcs11 (valid) provider found");
		ಹಿಂತಿರುಗಿ (-1);
	}

	ಆದರೆ (!pkcs11_interactive) {
		error("need pin entry%s",
		    (si->token.flags & CKF_PROTECTED_AUTHENTICATION_ಮಾರ್ಗ) ?
		    " on reader keypad" : "");
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಆದರೆ (si->token.flags & CKF_PROTECTED_AUTHENTICATION_ಮಾರ್ಗ)
		verbose("Deferring PIN entry to reader keypad.");
	ಇಲ್ಲದಿದ್ದರೆ {
		snprintf(prompt, ಗಾತ್ರ(prompt), "Enter PIN for '%s': ",
		    si->token.label);
		ಆದರೆ ((pin = read_passphrase(prompt, RP_ALLOW_EOF)) == ಖಾಲಿ) {
			debug_f("no pin specified");
			ಹಿಂತಿರುಗಿ (-1);	/* bail out */
		}
	}
	rv = provider->function_list->C_Login(si->session, type, (u_char *)pin,
	    (pin != ಖಾಲಿ) ? ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pin) : 0);
	ಆದರೆ (pin != ಖಾಲಿ)
		freezero(pin, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pin));

	ಆಯ್ಕೆ (rv) {
	ಸ್ಥಿತಿ CKR_OK:
	ಸ್ಥಿತಿ CKR_USER_ALREADY_LOGGED_ಒಳ:
		/* success */
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ CKR_PIN_LEN_RANGE:
		error("PKCS#11 login failed: PIN length out of range");
		ಹಿಂತಿರುಗಿ -1;
	ಸ್ಥಿತಿ CKR_PIN_INCORRECT:
		error("PKCS#11 login failed: PIN incorrect");
		ಹಿಂತಿರುಗಿ -1;
	ಸ್ಥಿತಿ CKR_PIN_LOCKED:
		error("PKCS#11 login failed: PIN locked");
		ಹಿಂತಿರುಗಿ -1;
	ಪೂರ್ವನಿಯೋಜಿತ:
		error("PKCS#11 login failed: error %lu", rv);
		ಹಿಂತಿರುಗಿ -1;
	}
	si->logged_ಒಳ = 1;
	ಹಿಂತಿರುಗಿ (0);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pkcs11_login(ರಚನೆ pkcs11_ಕೀಲಿ *k11, CK_USER_TYPE type)
{
	ಆದರೆ (k11 == ಖಾಲಿ || k11->provider == ಖಾಲಿ || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		ಹಿಂತಿರುಗಿ (-1);
	}

	ಹಿಂತಿರುಗಿ pkcs11_login_ಸ್ಥಾನ(k11->provider,
	    &k11->provider->slotinfo[k11->slotidx], type);
}


ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pkcs11_check_obj_bool_attrib(ರಚನೆ pkcs11_ಕೀಲಿ *k11, CK_OBJECT_HANDLE obj,
    CK_ATTRIBUTE_TYPE type, ಪೂರ್ಣಾಂಕ *val)
{
	ರಚನೆ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_BBOOL		flag = 0;
	CK_ATTRIBUTE		attr;
	CK_RV			 rv;

	*val = 0;

	ಆದರೆ (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		ಹಿಂತಿರುಗಿ (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	attr.type = type;
	attr.p_ಮೌಲ್ಯ = &flag;
	attr.ul_ಮೌಲ್ಯ_Len = ಗಾತ್ರ(flag);

	rv = f->C_Get_Attribute_ಮೌಲ್ಯ(si->session, obj, &attr, 1);
	ಆದರೆ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ಹಿಂತಿರುಗಿ (-1);
	}
	*val = flag != 0;
	debug_f("provider \"%s\" slot %lu object %lu: attrib %lu = %d",
	    k11->provider->name, k11->slotidx, obj, type, *val);
	ಹಿಂತಿರುಗಿ (0);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pkcs11_get_ಕೀಲಿ(ರಚನೆ pkcs11_ಕೀಲಿ *k11, CK_MECHANISM_TYPE mech_type)
{
	ರಚನೆ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	 obj;
	CK_RV			 rv;
	CK_OBJECT_CLASS		 ಖಾಸಗಿ_ಕೀಲಿ_class;
	CK_BBOOL		 true_val;
	CK_MECHANISM		 mech;
	CK_ATTRIBUTE		 ಕೀಲಿ_filter[3];
	ಪೂರ್ಣಾಂಕ			 always_auth = 0;
	ಪೂರ್ಣಾಂಕ			 did_login = 0;

	ಆದರೆ (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		ಹಿಂತಿರುಗಿ (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	ಆದರೆ ((si->token.flags & CKF_LOGIN_REQUIRED) && !si->logged_ಒಳ) {
		ಆದರೆ (pkcs11_login(k11, CKU_USER) < 0) {
			error("login failed");
			ಹಿಂತಿರುಗಿ (-1);
		}
		did_login = 1;
	}

	memset(&ಕೀಲಿ_filter, 0, ಗಾತ್ರ(ಕೀಲಿ_filter));
	ಖಾಸಗಿ_ಕೀಲಿ_class = CKO_ಖಾಸಗಿ_ಕೀಲಿ;
	ಕೀಲಿ_filter[0].type = CKA_CLASS;
	ಕೀಲಿ_filter[0].p_ಮೌಲ್ಯ = &ಖಾಸಗಿ_ಕೀಲಿ_class;
	ಕೀಲಿ_filter[0].ul_ಮೌಲ್ಯ_Len = ಗಾತ್ರ(ಖಾಸಗಿ_ಕೀಲಿ_class);

	ಕೀಲಿ_filter[1].type = CKA_ID;
	ಕೀಲಿ_filter[1].p_ಮೌಲ್ಯ = k11->keyid;
	ಕೀಲಿ_filter[1].ul_ಮೌಲ್ಯ_Len = k11->keyid_len;

	true_val = CK_TRUE;
	ಕೀಲಿ_filter[2].type = CKA_SIGN;
	ಕೀಲಿ_filter[2].p_ಮೌಲ್ಯ = &true_val;
	ಕೀಲಿ_filter[2].ul_ಮೌಲ್ಯ_Len = ಗಾತ್ರ(true_val);

	/* try to find object w/CKA_SIGN first, retry w/o */
	ಆದರೆ (pkcs11_ಕಂಡುಹಿಡಿ(k11->provider, k11->slotidx, ಕೀಲಿ_filter, 3, &obj) < 0 &&
	    pkcs11_ಕಂಡುಹಿಡಿ(k11->provider, k11->slotidx, ಕೀಲಿ_filter, 2, &obj) < 0) {
		error("cannot find private key");
		ಹಿಂತಿರುಗಿ (-1);
	}

	memset(&mech, 0, ಗಾತ್ರ(mech));
	mech.mechanism = mech_type;
	mech.pParameter = NULL_PTR;
	mech.ulParameterLen = 0;

	ಆದರೆ ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
		ಹಿಂತಿರುಗಿ (-1);
	}

	pkcs11_check_obj_bool_attrib(k11, obj, CKA_ALWAYS_AUTHENTICATE,
	    &always_auth); /* ignore errors here */
	ಆದರೆ (always_auth && !did_login) {
		debug_f("always-auth key");
		ಆದರೆ (pkcs11_login(k11, CKU_CONTEXT_SPECIFIC) < 0) {
			error("login failed for always-auth key");
			ಹಿಂತಿರುಗಿ (-1);
		}
	}

	ಹಿಂತಿರುಗಿ (0);
}

/* record the key information later use lookup by keyblob */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pkcs11_ದಾಖಲೆ_ಕೀಲಿ(ರಚನೆ pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, ರಚನೆ sshkey *ಕೀಲಿ)
{
	ರಚನೆ sshbuf *keyblob;
	ರಚನೆ pkcs11_ಕೀಲಿ *k11;
	ಪೂರ್ಣಾಂಕ r;
	ಅಕ್ಷರ *hex;

	hex = tohex(keyid_attrib->p_ಮೌಲ್ಯ, keyid_attrib->ul_ಮೌಲ್ಯ_Len);
	debug_f("%s key: provider %s slot %lu keyid %s",
	    sshkey_type(ಕೀಲಿ), provider->name, (u_long)slotidx, hex);
	ಬಿಡುಗಡೆ(hex);

	ಆದರೆ ((keyblob = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshkey_putb(ಕೀಲಿ, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");

	/* Check if we've already recorded this key in a different slot */
	TAILQ_FOREACH(k11, &pkcs11_ಕೀಲಿಗಳು, ಮುಂದಿನ) {
		ಆದರೆ (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			hex = tohex(k11->keyid, k11->keyid_len);
			debug_f("Already seen this key at "
			    "provider %s slot %lu keyid %s",
			    k11->provider->name, k11->slotidx, hex);
			ಬಿಡುಗಡೆ(hex);
			sshbuf_free(keyblob);
			ಹಿಂತಿರುಗಿ -1;
		}
	}

	k11 = xcalloc(1, ಗಾತ್ರ(*k11));
	k11->provider = provider;
	k11->keyblob = keyblob;
	provider->refcount++;	/* provider referenced by RSA key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ul_ಮೌಲ್ಯ_Len;
	ಆದರೆ (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len);
		ಸ್ಮರಣೆ_ನಕಲು(k11->keyid, keyid_attrib->p_ಮೌಲ್ಯ, k11->keyid_len);
	}
	TAILQ_INSERT_TAIL(&pkcs11_ಕೀಲಿಗಳು, k11, ಮುಂದಿನ);

	ಹಿಂತಿರುಗಿ 0;
}

/* retrieve the key information by keyblob */
ಸ್ಥಿರ ರಚನೆ pkcs11_ಕೀಲಿ *
pkcs11_lookup_ಕೀಲಿ(ರಚನೆ sshkey *ಕೀಲಿ)
{
	ರಚನೆ pkcs11_ಕೀಲಿ *k11, *ಸಿಕ್ಕಿತು = ಖಾಲಿ;
	ರಚನೆ sshbuf *keyblob;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((keyblob = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಆದರೆ ((r = sshkey_putb(ಕೀಲಿ, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");
	TAILQ_FOREACH(k11, &pkcs11_ಕೀಲಿಗಳು, ಮುಂದಿನ) {
		ಆದರೆ (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			ಸಿಕ್ಕಿತು = k11;
			ನಿಲ್ಲಿಸು;
		}
	}
	sshbuf_free(keyblob);
	ಹಿಂತಿರುಗಿ ಸಿಕ್ಕಿತು;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
/*
 * See:
 * https://datatracker.ietf.org/doc/html/rfc8017#section-9.2
 */

/*
 * id-sha1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
 *	oiw(14) secsig(3) algorithms(2) 26 }
 */
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ u_char id_sha1[] = {
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
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ u_char id_sha256[] = {
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
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ u_char id_sha512[] = {
	0x30, 0x51, /* type Sequence, length 0x51 (81) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, /* id-sha512 */
	0x05, 0x00, /* NULL */
	0x04, 0x40  /* Octet string, length 0x40 (64), followed by sha512 hash */
};

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
rsa_hash_alg_oid(ಪೂರ್ಣಾಂಕ hash_alg, ಸ್ಥಿರಾಂಕ u_char **oidp, ಗಾತ್ರ_t *oidlenp)
{
	ಆಯ್ಕೆ (hash_alg) {
	ಸ್ಥಿತಿ SSH_DIGEST_SHA1:
		*oidp = id_sha1;
		*oidlenp = ಗಾತ್ರ(id_sha1);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_DIGEST_SHA256:
		*oidp = id_sha256;
		*oidlenp = ಗಾತ್ರ(id_sha256);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_DIGEST_SHA512:
		*oidp = id_sha512;
		*oidlenp = ಗಾತ್ರ(id_sha512);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pkcs11_sign_rsa(ರಚನೆ sshkey *ಕೀಲಿ,
    u_char **sigp, ಗಾತ್ರ_t *lenp,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin, u_int compat)
{
	ರಚನೆ pkcs11_ಕೀಲಿ	*k11;
	ರಚನೆ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	ಪೂರ್ಣಾಂಕ			hashalg, r, diff, siglen, ret = -1;
	u_char			*oid_dgst = ಖಾಲಿ, *sig = ಖಾಲಿ;
	ಗಾತ್ರ_t			dgst_len, oid_len, oid_dgst_len = 0;
	ಸ್ಥಿರಾಂಕ u_char		*oid;

	ಆದರೆ (sigp != ಖಾಲಿ)
		*sigp = ಖಾಲಿ;
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = 0;

	ಆದರೆ ((k11 = pkcs11_lookup_ಕೀಲಿ(ಕೀಲಿ)) == ಖಾಲಿ) {
		error_f("no key found");
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು;
	}

	debug3_f("sign with alg \"%s\" using provider %s slotidx %lu",
	    alg == ಖಾಲಿ ? "" : alg, k11->provider->name, (u_long)k11->slotidx);

	ಆದರೆ (pkcs11_get_ಕೀಲಿ(k11, CKM_RSA_PKCS) == -1) {
		error("pkcs11_get_key failed");
		ಹಿಂತಿರುಗಿ SSH_ERR_AGENT_FAILURE;
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	ಆದರೆ ((siglen = EVP_PKEY_ಗಾತ್ರ(ಕೀಲಿ->pkey)) <= 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* Determine hash algorithm and OID for signature */
	ಆದರೆ (alg == ಖಾಲಿ || *alg == '\0')
		hashalg = SSH_DIGEST_SHA1;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((hashalg = ssh_rsa_hash_id_from_keyname(alg)) == -1)
		fatal_f("couldn't determine RSA hash alg \"%s\"", alg);
	ಆದರೆ ((r = rsa_hash_alg_oid(hashalg, &oid, &oid_len)) != 0)
		fatal_fr(r, "rsa_hash_alg_oid failed");
	ಆದರೆ ((dgst_len = ssh_digest_ಬೈಟುಗಳು(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);

	/* Prepare { oid || digest } */
	oid_dgst_len = oid_len + dgst_len;
	oid_dgst = xcalloc(1, oid_dgst_len);
	ಸ್ಮರಣೆ_ನಕಲು(oid_dgst, oid, oid_len);
	ಆದರೆ ((r = ssh_digest_ಸ್ಮರಣೆ(hashalg, ದತ್ತಾಂಶ, datalen,
	    oid_dgst + oid_len, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	ಆದರೆ ((rv = f->C_Sign(si->session, (CK_BYTE *)oid_dgst,
	    oid_dgst_len, sig, &slen)) != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		ಹೋಗು ಮುಗಿದ;
	}

	ಆದರೆ (slen < (CK_ULONG)siglen) {
		diff = siglen - slen;
		debug3_f("repack %lu < %d (diff %d)",
		    (u_long)slen, siglen, diff);
		memmove(sig + diff, sig, slen);
		explicit_bzero(sig, diff);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (slen > (ಗಾತ್ರ_t)siglen)
		fatal_f("bad C_Sign length");

	ಆದರೆ ((ret = ssh_rsa_encode_store_sig(hashalg, sig, siglen,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 ಮುಗಿದ:
	freezero(oid_dgst, oid_dgst_len);
	ಬಿಡುಗಡೆ(sig);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pkcs11_sign_ecdsa(ರಚನೆ sshkey *ಕೀಲಿ,
    u_char **sigp, ಗಾತ್ರ_t *lenp,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin, u_int compat)
{
	ರಚನೆ pkcs11_ಕೀಲಿ	*k11;
	ರಚನೆ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0, bnlen;
	CK_RV			rv;
	BIGNUM			*sig_r = ಖಾಲಿ, *sig_s = ಖಾಲಿ;
	u_char			*sig = ಖಾಲಿ, *dgst = ಖಾಲಿ;
	ಗಾತ್ರ_t			dgst_len = 0;
	ಪೂರ್ಣಾಂಕ			hashalg, ret = -1, r, siglen;

	ಆದರೆ (sigp != ಖಾಲಿ)
		*sigp = ಖಾಲಿ;
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = 0;

	ಆದರೆ ((k11 = pkcs11_lookup_ಕೀಲಿ(ಕೀಲಿ)) == ಖಾಲಿ) {
		error_f("no key found");
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು;
	}

	ಆದರೆ (pkcs11_get_ಕೀಲಿ(k11, CKM_ECDSA) == -1) {
		error("pkcs11_get_key failed");
		ಹಿಂತಿರುಗಿ SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	/* Prepare digest to be signed */
	ಆದರೆ ((hashalg = sshkey_ec_nid_ಗಮ್ಯ_hash_alg(ಕೀಲಿ->ecdsa_nid)) == -1)
		fatal_f("couldn't determine ECDSA hash alg");
	ಆದರೆ ((dgst_len = ssh_digest_ಬೈಟುಗಳು(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);
	dgst = xcalloc(1, dgst_len);
	ಆದರೆ ((r = ssh_digest_ಸ್ಮರಣೆ(hashalg, ದತ್ತಾಂಶ, datalen,
	    dgst, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	ಆದರೆ ((siglen = EVP_PKEY_ಗಾತ್ರ(ಕೀಲಿ->pkey)) <= 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dgst_len, sig, &slen);
	ಆದರೆ (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ (slen < 64 || slen > 132 || slen % 2) {
		error_f("bad signature length: %lu", (u_long)slen);
		ಹೋಗು ಮುಗಿದ;
	}
	bnlen = slen/2;
	ಆದರೆ ((sig_r = BN_bin2bn(sig, bnlen, ಖಾಲಿ)) == ಖಾಲಿ ||
	    (sig_s = BN_bin2bn(sig+bnlen, bnlen, ಖಾಲಿ)) == ಖಾಲಿ) {
		ossl_error("BN_bin2bn failed");
		ಹೋಗು ಮುಗಿದ;
	}

	ಆದರೆ ((ret = ssh_ecdsa_encode_store_sig(ಕೀಲಿ, sig_r, sig_s,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 ಮುಗಿದ:
	freezero(dgst, dgst_len);
	BN_free(sig_r);
	BN_free(sig_s);
	ಬಿಡುಗಡೆ(sig);
	ಹಿಂತಿರುಗಿ ret;
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pkcs11_sign_ed25519(ರಚನೆ sshkey *ಕೀಲಿ,
    u_char **sigp, ಗಾತ್ರ_t *lenp,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin, u_int compat)
{
	ರಚನೆ pkcs11_ಕೀಲಿ	*k11;
	ರಚನೆ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	u_char			*sig = ಖಾಲಿ;
	CK_BYTE			*xdata = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ			ret = -1;

	ಆದರೆ (sigp != ಖಾಲಿ)
		*sigp = ಖಾಲಿ;
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = 0;

	ಆದರೆ ((k11 = pkcs11_lookup_ಕೀಲಿ(ಕೀಲಿ)) == ಖಾಲಿ) {
		error_f("no key found");
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು;
	}

	ಆದರೆ (pkcs11_get_ಕೀಲಿ(k11, CKM_EDDSA) == -1) {
		error("pkcs11_get_key failed");
		ಹಿಂತಿರುಗಿ SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	xdata = xmalloc(datalen);
	ಸ್ಮರಣೆ_ನಕಲು(xdata, ದತ್ತಾಂಶ, datalen);
	sig = xmalloc(crypto_sign_ed25519_ಬೈಟುಗಳು);
	slen = crypto_sign_ed25519_ಬೈಟುಗಳು;

	rv = f->C_Sign(si->session, xdata, datalen, sig, &slen);
	ಆದರೆ (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ (slen != crypto_sign_ed25519_ಬೈಟುಗಳು) {
		error_f("bad signature length: %lu", (u_long)slen);
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ ((ret = ssh_ed25519_encode_store_sig(sig, slen, sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 ಮುಗಿದ:
	ಆದರೆ (xdata != ಖಾಲಿ)
		freezero(xdata, datalen);
	ಬಿಡುಗಡೆ(sig);
	ಹಿಂತಿರುಗಿ ret;
}

/* remove trailing spaces */
ಸ್ಥಿರ ಅಕ್ಷರ *
rmspace(u_char *buf, ಗಾತ್ರ_t len)
{
	ಗಾತ್ರ_t i;

	ಆದರೆ (len == 0)
		ಹಿಂತಿರುಗಿ buf;
	ಗಾಗಿ (i = len - 1; i > 0; i--)
		ಆದರೆ (buf[i] == ' ')
			buf[i] = '\0';
		ಇಲ್ಲದಿದ್ದರೆ
			ನಿಲ್ಲಿಸು;
	ಹಿಂತಿರುಗಿ buf;
}
/* Used to printf fixed-width, space-padded, unterminated strings using %.*s */
#ವ್ಯಾಖ್ಯಾನಿಸು RMSPACE(s) (ಪೂರ್ಣಾಂಕ)ಗಾತ್ರ(s), rmspace(s, ಗಾತ್ರ(s))

/*
 * open a pkcs11 session and login if required.
 * if pin == NULL we delay login until key use
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pkcs11_open_session(ರಚನೆ pkcs11_provider *p, CK_ULONG slotidx, ಅಕ್ಷರ *pin,
    CK_ULONG user)
{
	ರಚನೆ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_RV			rv;
	CK_SESSION_HANDLE	session;
	ಪೂರ್ಣಾಂಕ			login_required, ret;

	f = p->function_list;
	si = &p->slotinfo[slotidx];

	login_required = si->token.flags & CKF_LOGIN_REQUIRED;

	/* fail early before opening session */
	ಆದರೆ (login_required && !pkcs11_interactive &&
	    (pin == ಖಾಲಿ || ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pin) == 0)) {
		error("pin required");
		ಹಿಂತಿರುಗಿ (-SSH_PKCS11_ERR_PIN_REQUIRED);
	}
	ಆದರೆ ((rv = f->C_OpenSession(p->slotlist[slotidx], CKF_RW_SESSION|
	    CKF_SERIAL_SESSION, ಖಾಲಿ, ಖಾಲಿ, &session)) != CKR_OK) {
		error("C_OpenSession failed: %lu", rv);
		ಹಿಂತಿರುಗಿ (-1);
	}
	ಆದರೆ (login_required && pin != ಖಾಲಿ && ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pin) != 0) {
		rv = f->C_Login(session, user, (u_char *)pin, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pin));
		ಆದರೆ (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_ಒಳ) {
			error("C_Login failed: %lu", rv);
			ret = (rv == CKR_PIN_LOCKED) ?
			    -SSH_PKCS11_ERR_PIN_LOCKED :
			    -SSH_PKCS11_ERR_LOGIN_FAIL;
			ಆದರೆ ((rv = f->C_CloseSession(session)) != CKR_OK)
				error("C_CloseSession failed: %lu", rv);
			ಹಿಂತಿರುಗಿ (ret);
		}
		si->logged_ಒಳ = 1;
	}
	si->session = session;
	ಹಿಂತಿರುಗಿ (0);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pkcs11_ಕೀಲಿ_included(ರಚನೆ sshkey ***keysp, ಪೂರ್ಣಾಂಕ *nkeys, ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಂಕ i;

	ಗಾಗಿ (i = 0; i < *nkeys; i++)
		ಆದರೆ (sshkey_equal(ಕೀಲಿ, (*keysp)[i]))
			ಹಿಂತಿರುಗಿ (1);
	ಹಿಂತಿರುಗಿ (0);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
ಸ್ಥಿರ ರಚನೆ sshkey *
pkcs11_fetch_ecdsa_pubkey(ರಚನೆ pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 ಕೀಲಿ_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ಖಾಲಿ;
	CK_RV			 rv;
	ASN1_OCTET_STRING	*octet = ಖಾಲಿ;
	EC_ಕೀಲಿ			*ec = ಖಾಲಿ;
	EC_ಗುಂಪು		*ಗುಂಪು = ಖಾಲಿ;
	ರಚನೆ sshkey		*ಕೀಲಿ = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ	*attrp = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ			 success = -1, r, i, nid;

	memset(&ಕೀಲಿ_attr, 0, ಗಾತ್ರ(ಕೀಲಿ_attr));
	ಕೀಲಿ_attr[0].type = CKA_ID;
	ಕೀಲಿ_attr[1].type = CKA_EC_ಬಿಂದು;
	ಕೀಲಿ_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, *obj, ಕೀಲಿ_attr, 3);
	ಆದರೆ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	ಆದರೆ (ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len == 0 ||
	    ಕೀಲಿ_attr[2].ul_ಮೌಲ್ಯ_Len == 0) {
		error("invalid attribute length");
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}

	/* allocate buffers for attributes */
	ಗಾಗಿ (i = 0; i < 3; i++)
		ಆದರೆ (ಕೀಲಿ_attr[i].ul_ಮೌಲ್ಯ_Len > 0)
			ಕೀಲಿ_attr[i].p_ಮೌಲ್ಯ = xcalloc(1, ಕೀಲಿ_attr[i].ul_ಮೌಲ್ಯ_Len);

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, *obj, ಕೀಲಿ_attr, 3);
	ಆದರೆ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ಹೋಗು fail;
	}

	ec = EC_ಕೀಲಿ_new();
	ಆದರೆ (ec == ಖಾಲಿ) {
		error("EC_KEY_new failed");
		ಹೋಗು fail;
	}

	attrp = ಕೀಲಿ_attr[2].p_ಮೌಲ್ಯ;
	ಗುಂಪು = d2i_ECPKParameters(ಖಾಲಿ, &attrp, ಕೀಲಿ_attr[2].ul_ಮೌಲ್ಯ_Len);
	ಆದರೆ (ಗುಂಪು == ಖಾಲಿ) {
		ossl_error("d2i_ECPKParameters failed");
		ಹೋಗು fail;
	}

	ಆದರೆ (EC_ಕೀಲಿ_ಗಣ_ಗುಂಪು(ec, ಗುಂಪು) == 0) {
		ossl_error("EC_KEY_set_group failed");
		ಹೋಗು fail;
	}

	ಆದರೆ (ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len <= 2) {
		error("CKA_EC_POINT too small");
		ಹೋಗು fail;
	}

	attrp = ಕೀಲಿ_attr[1].p_ಮೌಲ್ಯ;
	octet = d2i_ASN1_OCTET_STRING(ಖಾಲಿ, &attrp, ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len);
	ಆದರೆ (octet == ಖಾಲಿ) {
		ossl_error("d2i_ASN1_OCTET_STRING failed");
		ಹೋಗು fail;
	}
	attrp = ASN1_STRING_get0_ದತ್ತಾಂಶ(octet);
	ಆದರೆ (o2i_ECPublic_ಕೀಲಿ(&ec, &attrp, ASN1_STRING_ಉದ್ದಳತೆ(octet)) == ಖಾಲಿ) {
		ossl_error("o2i_ECPublicKey failed");
		ಹೋಗು fail;
	}
	ಆದರೆ ((r = sshkey_ec_validate_ಬಹಿರಂಗ(EC_ಕೀಲಿ_get0_ಗುಂಪು(ec),
	    EC_ಕೀಲಿ_get0_ಬಹಿರಂಗ_ಕೀಲಿ(ec))) != 0) {
		error_fr(r, "invalid EC key");
		ಹೋಗು fail;
	}

	nid = sshkey_ecdsa_ಕೀಲಿ_ಗಮ್ಯ_nid(ec);
	ಆದರೆ (nid < 0) {
		error("couldn't get curve nid");
		ಹೋಗು fail;
	}

	ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC);
	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ) {
		error("sshkey_new failed");
		ಹೋಗು fail;
	}

	EVP_PKEY_free(ಕೀಲಿ->pkey);
	ಆದರೆ ((ಕೀಲಿ->pkey = EVP_PKEY_new()) == ಖಾಲಿ)
		fatal("EVP_PKEY_new failed");
	ಆದರೆ (EVP_PKEY_set1_EC_ಕೀಲಿ(ಕೀಲಿ->pkey, ec) != 1)
		fatal("EVP_PKEY_set1_EC_KEY failed");
	ಕೀಲಿ->ecdsa_nid = nid;
	ಕೀಲಿ->type = ಕೀಲಿ_ECDSA;
	ಕೀಲಿ->flags |= SSHKEY_FLAG_EXT;
	ಆದರೆ (pkcs11_ದಾಖಲೆ_ಕೀಲಿ(p, slotidx, &ಕೀಲಿ_attr[0], ಕೀಲಿ))
		ಹೋಗು fail;
	/* success */
	success = 0;
fail:
	ಆದರೆ (success != 0) {
		sshkey_free(ಕೀಲಿ);
		ಕೀಲಿ = ಖಾಲಿ;
	}
	ಗಾಗಿ (i = 0; i < 3; i++)
		ಬಿಡುಗಡೆ(ಕೀಲಿ_attr[i].p_ಮೌಲ್ಯ);
	ಆದರೆ (ec)
		EC_ಕೀಲಿ_free(ec);
	ಆದರೆ (ಗುಂಪು)
		EC_ಗುಂಪು_free(ಗುಂಪು);
	ಆದರೆ (octet)
		ASN1_OCTET_STRING_free(octet);

	ಹಿಂತಿರುಗಿ (ಕೀಲಿ);
}

ಸ್ಥಿರ ರಚನೆ sshkey *
pkcs11_fetch_rsa_pubkey(ರಚನೆ pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 ಕೀಲಿ_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ಖಾಲಿ;
	CK_RV			 rv;
	RSA			*rsa = ಖಾಲಿ;
	BIGNUM			*rsa_n, *rsa_e;
	ರಚನೆ sshkey		*ಕೀಲಿ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ			 i, success = -1;

	memset(&ಕೀಲಿ_attr, 0, ಗಾತ್ರ(ಕೀಲಿ_attr));
	ಕೀಲಿ_attr[0].type = CKA_ID;
	ಕೀಲಿ_attr[1].type = CKA_MODULUS;
	ಕೀಲಿ_attr[2].type = CKA_ಬಹಿರಂಗ_EXPONENT;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, *obj, ಕೀಲಿ_attr, 3);
	ಆದರೆ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	ಆದರೆ (ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len == 0 ||
	    ಕೀಲಿ_attr[2].ul_ಮೌಲ್ಯ_Len == 0) {
		error("invalid attribute length");
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}

	/* allocate buffers for attributes */
	ಗಾಗಿ (i = 0; i < 3; i++)
		ಆದರೆ (ಕೀಲಿ_attr[i].ul_ಮೌಲ್ಯ_Len > 0)
			ಕೀಲಿ_attr[i].p_ಮೌಲ್ಯ = xcalloc(1, ಕೀಲಿ_attr[i].ul_ಮೌಲ್ಯ_Len);

	/* retrieve ID, modulus and public exponent of RSA key */
	rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, *obj, ಕೀಲಿ_attr, 3);
	ಆದರೆ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ಹೋಗು fail;
	}

	rsa = RSA_new();
	ಆದರೆ (rsa == ಖಾಲಿ) {
		error("RSA_new failed");
		ಹೋಗು fail;
	}

	rsa_n = BN_bin2bn(ಕೀಲಿ_attr[1].p_ಮೌಲ್ಯ, ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len, ಖಾಲಿ);
	rsa_e = BN_bin2bn(ಕೀಲಿ_attr[2].p_ಮೌಲ್ಯ, ಕೀಲಿ_attr[2].ul_ಮೌಲ್ಯ_Len, ಖಾಲಿ);
	ಆದರೆ (rsa_n == ಖಾಲಿ || rsa_e == ಖಾಲಿ) {
		error("BN_bin2bn failed");
		ಹೋಗು fail;
	}
	ಆದರೆ (!RSA_set0_ಕೀಲಿ(rsa, rsa_n, rsa_e, ಖಾಲಿ))
		fatal_f("set key");
	rsa_n = rsa_e = ಖಾಲಿ; /* transferred */

	ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC);
	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ) {
		error("sshkey_new failed");
		ಹೋಗು fail;
	}

	EVP_PKEY_free(ಕೀಲಿ->pkey);
	ಆದರೆ ((ಕೀಲಿ->pkey = EVP_PKEY_new()) == ಖಾಲಿ)
		fatal("EVP_PKEY_new failed");
	ಆದರೆ (EVP_PKEY_set1_RSA(ಕೀಲಿ->pkey, rsa) != 1)
		fatal("EVP_PKEY_set1_RSA failed");
	ಕೀಲಿ->type = ಕೀಲಿ_RSA;
	ಕೀಲಿ->flags |= SSHKEY_FLAG_EXT;
	ಆದರೆ (EVP_PKEY_ಬಿಟ್ಟುಗಳು(ಕೀಲಿ->pkey) < SSH_RSA_MINIMUM_MODULUS_ಗಾತ್ರ) {
		error_f("RSA key too small %d < minimum %d",
		    EVP_PKEY_ಬಿಟ್ಟುಗಳು(ಕೀಲಿ->pkey), SSH_RSA_MINIMUM_MODULUS_ಗಾತ್ರ);
		ಹೋಗು fail;
	}
	ಆದರೆ (pkcs11_ದಾಖಲೆ_ಕೀಲಿ(p, slotidx, &ಕೀಲಿ_attr[0], ಕೀಲಿ))
		ಹೋಗು fail;
	/* success */
	success = 0;
fail:
	ಗಾಗಿ (i = 0; i < 3; i++)
		ಬಿಡುಗಡೆ(ಕೀಲಿ_attr[i].p_ಮೌಲ್ಯ);
	RSA_free(rsa);
	ಆದರೆ (success != 0) {
		sshkey_free(ಕೀಲಿ);
		ಕೀಲಿ = ಖಾಲಿ;
	}
	ಹಿಂತಿರುಗಿ ಕೀಲಿ;
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

ಸ್ಥಿರ ರಚನೆ sshkey *
pkcs11_fetch_ed25519_pubkey(ರಚನೆ pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 ಕೀಲಿ_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ಖಾಲಿ;
	CK_RV			 rv;
	ರಚನೆ sshkey		*ಕೀಲಿ = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ	*d = ಖಾಲಿ;
	ಗಾತ್ರ_t			len;
	ಅಕ್ಷರ			*hex = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ			 success = -1, i;
	/* https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061180 */
	ಸ್ಥಿರಾಂಕ u_char		 id1[14] = {
		0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64,
		0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
	}; /* PrintableString { "edwards25519" } */
	ಸ್ಥಿರಾಂಕ u_char		 id2[5] = {
		0x06, 0x03, 0x2b, 0x65, 0x70,
	}; /* OBJECT_IDENTIFIER { 1.3.101.112 } */

	memset(&ಕೀಲಿ_attr, 0, ಗಾತ್ರ(ಕೀಲಿ_attr));
	ಕೀಲಿ_attr[0].type = CKA_ID;
	ಕೀಲಿ_attr[1].type = CKA_EC_ಬಿಂದು; /* XXX or CKA_VALUE ? */
	ಕೀಲಿ_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, *obj, ಕೀಲಿ_attr, 3);
	ಆದರೆ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	ಆದರೆ (ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len == 0 ||
	    ಕೀಲಿ_attr[2].ul_ಮೌಲ್ಯ_Len == 0) {
		error("invalid attribute length");
		ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
	}

	/* allocate buffers for attributes */
	ಗಾಗಿ (i = 0; i < 3; i++) {
		ಆದರೆ (ಕೀಲಿ_attr[i].ul_ಮೌಲ್ಯ_Len > 0)
			ಕೀಲಿ_attr[i].p_ಮೌಲ್ಯ = xcalloc(1, ಕೀಲಿ_attr[i].ul_ಮೌಲ್ಯ_Len);
	}

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, *obj, ಕೀಲಿ_attr, 3);
	ಆದರೆ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ಹೋಗು fail;
	}

	/* Expect one of the supported identifiers in CKA_EC_PARAMS */
	d = (u_char *)ಕೀಲಿ_attr[2].p_ಮೌಲ್ಯ;
	len = ಕೀಲಿ_attr[2].ul_ಮೌಲ್ಯ_Len;
	ಆದರೆ ((len != ಗಾತ್ರ(id1) || memcmp(d, id1, ಗಾತ್ರ(id1)) != 0) &&
	    (len != ಗಾತ್ರ(id2) || memcmp(d, id2, ಗಾತ್ರ(id2)) != 0)) {
		hex = tohex(d, len);
		logit_f("unsupported CKA_EC_PARAMS: %s (len %zu)", hex, len);
		ಹೋಗು fail;
	}

	/*
	 * Expect either a raw 32 byte pubkey or an OCTET STRING with
	 * a 32 byte pubkey in CKA_VALUE
	 */
	d = (u_char *)ಕೀಲಿ_attr[1].p_ಮೌಲ್ಯ;
	len = ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len;
	ಆದರೆ (len == ED25519_PK_SZ + 2 && d[0] == 0x04 && d[1] == ED25519_PK_SZ) {
		d += 2;
		len -= 2;
	}
	ಆದರೆ (len != ED25519_PK_SZ) {
		hex = tohex(ಕೀಲಿ_attr[1].p_ಮೌಲ್ಯ, ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len);
		logit_f("CKA_EC_POINT invalid octet str: %s (len %lu)",
		    hex, (u_long)ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len);
		ಹೋಗು fail;
	}

	ಆದರೆ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ)
		fatal_f("sshkey_new failed");
	ಕೀಲಿ->ed25519_pk = xmalloc(ED25519_PK_SZ);
	ಸ್ಮರಣೆ_ನಕಲು(ಕೀಲಿ->ed25519_pk, d, ED25519_PK_SZ);
	ಕೀಲಿ->type = ಕೀಲಿ_ED25519;
	ಕೀಲಿ->flags |= SSHKEY_FLAG_EXT;
	ಆದರೆ (pkcs11_ದಾಖಲೆ_ಕೀಲಿ(p, slotidx, &ಕೀಲಿ_attr[0], ಕೀಲಿ))
		ಹೋಗು fail;
	/* success */
	success = 0;
 fail:
	ಆದರೆ (success != 0) {
		sshkey_free(ಕೀಲಿ);
		ಕೀಲಿ = ಖಾಲಿ;
	}
	ಬಿಡುಗಡೆ(hex);
	ಗಾಗಿ (i = 0; i < 3; i++)
		ಬಿಡುಗಡೆ(ಕೀಲಿ_attr[i].p_ಮೌಲ್ಯ);
	ಹಿಂತಿರುಗಿ ಕೀಲಿ;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pkcs11_fetch_x509_pubkey(ರಚನೆ pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj, ರಚನೆ sshkey **keyp, ಅಕ್ಷರ **labelp)
{
	CK_ATTRIBUTE		 cert_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ಖಾಲಿ;
	CK_RV			 rv;
	X509			*x509 = ಖಾಲಿ;
	X509_NAME		*x509_name = ಖಾಲಿ;
	EVP_PKEY		*evp;
	RSA			*rsa = ಖಾಲಿ;
	EC_ಕೀಲಿ			*ec = ಖಾಲಿ;
	ರಚನೆ sshkey		*ಕೀಲಿ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ			 r, i, nid, success = -1;
	ಸ್ಥಿರಾಂಕ u_char		*cp;
	ಅಕ್ಷರ			*subject = ಖಾಲಿ;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ OPENSSL_HAS_ED25519
	ಗಾತ್ರ_t			len;
#ಆದರೆ_ಅಂತ್ಯ /* OPENSSL_HAS_ED25519 */

	*keyp = ಖಾಲಿ;
	*labelp = ಖಾಲಿ;

	memset(&cert_attr, 0, ಗಾತ್ರ(cert_attr));
	cert_attr[0].type = CKA_ID;
	cert_attr[1].type = CKA_SUBJECT;
	cert_attr[2].type = CKA_ಮೌಲ್ಯ;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, *obj, cert_attr, 3);
	ಆದರೆ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ಹಿಂತಿರುಗಿ -1;
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	ಆದರೆ (cert_attr[1].ul_ಮೌಲ್ಯ_Len == 0 ||
	    cert_attr[2].ul_ಮೌಲ್ಯ_Len == 0) {
		error("invalid attribute length");
		ಹಿಂತಿರುಗಿ -1;
	}

	/* allocate buffers for attributes */
	ಗಾಗಿ (i = 0; i < 3; i++)
		ಆದರೆ (cert_attr[i].ul_ಮೌಲ್ಯ_Len > 0)
			cert_attr[i].p_ಮೌಲ್ಯ = xcalloc(1, cert_attr[i].ul_ಮೌಲ್ಯ_Len);

	/* retrieve ID, subject and value of certificate */
	rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, *obj, cert_attr, 3);
	ಆದರೆ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Decode DER-encoded cert subject */
	cp = cert_attr[1].p_ಮೌಲ್ಯ;
	ಆದರೆ ((x509_name = d2i_X509_NAME(ಖಾಲಿ, &cp,
	    cert_attr[1].ul_ಮೌಲ್ಯ_Len)) == ಖಾಲಿ ||
	    (subject = X509_NAME_oneline(x509_name, ಖಾಲಿ, 0)) == ಖಾಲಿ)
		subject = xstrdup("invalid subject");
	X509_NAME_free(x509_name);

	cp = cert_attr[2].p_ಮೌಲ್ಯ;
	ಆದರೆ ((x509 = d2i_X509(ಖಾಲಿ, &cp, cert_attr[2].ul_ಮೌಲ್ಯ_Len)) == ಖಾಲಿ) {
		error("d2i_x509 failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((evp = X509_get_pubkey(x509)) == ಖಾಲಿ) {
		error("X509_get_pubkey failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (EVP_PKEY_ತಳ_id(evp) == EVP_PKEY_RSA) {
		ಆದರೆ (EVP_PKEY_get0_RSA(evp) == ಖಾಲಿ) {
			error("invalid x509; no rsa key");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((rsa = RSAPublic_ಕೀಲಿ_dup(EVP_PKEY_get0_RSA(evp))) == ಖಾಲಿ) {
			error("RSAPublicKey_dup failed");
			ಹೋಗು ಹೊರಹೋಗು;
		}

		ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC);
		ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ) {
			error("sshkey_new failed");
			ಹೋಗು ಹೊರಹೋಗು;
		}

		EVP_PKEY_free(ಕೀಲಿ->pkey);
		ಆದರೆ ((ಕೀಲಿ->pkey = EVP_PKEY_new()) == ಖಾಲಿ)
			fatal("EVP_PKEY_new failed");
		ಆದರೆ (EVP_PKEY_set1_RSA(ಕೀಲಿ->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		ಕೀಲಿ->type = ಕೀಲಿ_RSA;
		ಕೀಲಿ->flags |= SSHKEY_FLAG_EXT;
		ಆದರೆ (EVP_PKEY_ಬಿಟ್ಟುಗಳು(ಕೀಲಿ->pkey) < SSH_RSA_MINIMUM_MODULUS_ಗಾತ್ರ) {
			error_f("RSA key too small %d < minimum %d",
			    EVP_PKEY_ಬಿಟ್ಟುಗಳು(ಕೀಲಿ->pkey),
			    SSH_RSA_MINIMUM_MODULUS_ಗಾತ್ರ);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (pkcs11_ದಾಖಲೆ_ಕೀಲಿ(p, slotidx, &cert_attr[0], ಕೀಲಿ))
			ಹೋಗು ಹೊರಹೋಗು;
		/* success */
		success = 0;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (EVP_PKEY_ತಳ_id(evp) == EVP_PKEY_EC) {
		ಆದರೆ (EVP_PKEY_get0_EC_ಕೀಲಿ(evp) == ಖಾಲಿ) {
			error("invalid x509; no ec key");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((ec = EC_ಕೀಲಿ_dup(EVP_PKEY_get0_EC_ಕೀಲಿ(evp))) == ಖಾಲಿ) {
			error("EC_KEY_dup failed");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = sshkey_ec_validate_ಬಹಿರಂಗ(EC_ಕೀಲಿ_get0_ಗುಂಪು(ec),
		    EC_ಕೀಲಿ_get0_ಬಹಿರಂಗ_ಕೀಲಿ(ec))) != 0) {
			error_fr(r, "invalid EC key");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		nid = sshkey_ecdsa_ಕೀಲಿ_ಗಮ್ಯ_nid(ec);
		ಆದರೆ (nid < 0) {
			error("couldn't get curve nid");
			ಹೋಗು ಹೊರಹೋಗು;
		}

		ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC);
		ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ) {
			error("sshkey_new failed");
			ಹೋಗು ಹೊರಹೋಗು;
		}

		EVP_PKEY_free(ಕೀಲಿ->pkey);
		ಆದರೆ ((ಕೀಲಿ->pkey = EVP_PKEY_new()) == ಖಾಲಿ)
			fatal("EVP_PKEY_new failed");
		ಆದರೆ (EVP_PKEY_set1_EC_ಕೀಲಿ(ಕೀಲಿ->pkey, ec) != 1)
			fatal("EVP_PKEY_set1_EC_KEY failed");
		ಕೀಲಿ->ecdsa_nid = nid;
		ಕೀಲಿ->type = ಕೀಲಿ_ECDSA;
		ಕೀಲಿ->flags |= SSHKEY_FLAG_EXT;
		ಆದರೆ (pkcs11_ದಾಖಲೆ_ಕೀಲಿ(p, slotidx, &cert_attr[0], ಕೀಲಿ))
			ಹೋಗು ಹೊರಹೋಗು;
		/* success */
		success = 0;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ OPENSSL_HAS_ED25519
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (EVP_PKEY_ತಳ_id(evp) == EVP_PKEY_ED25519) {
		ಆದರೆ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ ||
		    (ಕೀಲಿ->ed25519_pk = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ED25519_PK_SZ)) == ಖಾಲಿ)
			fatal_f("allocation failed");
		len = ED25519_PK_SZ;
		ಆದರೆ (!EVP_PKEY_get_raw_ಬಹಿರಂಗ_ಕೀಲಿ(evp, ಕೀಲಿ->ed25519_pk, &len)) {
			ossl_error("EVP_PKEY_get_raw_public_key failed");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (len != ED25519_PK_SZ) {
			error_f("incorrect returned public key "
			    "length for ed25519");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಕೀಲಿ->type = ಕೀಲಿ_ED25519;
		ಕೀಲಿ->flags |= SSHKEY_FLAG_EXT;
		ಆದರೆ (pkcs11_ದಾಖಲೆ_ಕೀಲಿ(p, slotidx, &cert_attr[0], ಕೀಲಿ))
			ಹೋಗು ಹೊರಹೋಗು;
		/* success */
		success = 0;
#ಆದರೆ_ಅಂತ್ಯ /* OPENSSL_HAS_ED25519 */
	} ಇಲ್ಲದಿದ್ದರೆ {
		error("unknown certificate key type");
		ಹೋಗು ಹೊರಹೋಗು;
	}
 ಹೊರಹೋಗು:
	ಗಾಗಿ (i = 0; i < 3; i++)
		ಬಿಡುಗಡೆ(cert_attr[i].p_ಮೌಲ್ಯ);
	X509_free(x509);
	RSA_free(rsa);
	EC_ಕೀಲಿ_free(ec);
	ಆದರೆ (success != 0 || ಕೀಲಿ == ಖಾಲಿ) {
		sshkey_free(ಕೀಲಿ);
		ಬಿಡುಗಡೆ(subject);
		ಹಿಂತಿರುಗಿ -1;
	}
	/* success */
	*keyp = ಕೀಲಿ;
	*labelp = subject;
	ಹಿಂತಿರುಗಿ 0;
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

ಸ್ಥಿರ ಶೂನ್ಯ
note_ಕೀಲಿ(ರಚನೆ pkcs11_provider *p, CK_ULONG slotidx, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *context,
    ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಅಕ್ಷರ *fp;

	ಆದರೆ ((fp = sshkey_fingerprint(ಕೀಲಿ, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ಖಾಲಿ) {
		error_f("sshkey_fingerprint failed");
		ಹಿಂತಿರುಗಿ;
	}
	debug2("%s: provider %s slot %lu: %s %s", context, p->name,
	    (u_long)slotidx, sshkey_type(ಕೀಲಿ), fp);
	ಬಿಡುಗಡೆ(fp);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL /* libcrypto needed for certificate parsing */
/*
 * lookup certificates for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pkcs11_fetch_certs(ರಚನೆ pkcs11_provider *p, CK_ULONG slotidx,
    ರಚನೆ sshkey ***keysp, ಅಕ್ಷರ ***labelsp, ಪೂರ್ಣಾಂಕ *nkeys)
{
	ರಚನೆ sshkey		*ಕೀಲಿ = ಖಾಲಿ;
	CK_OBJECT_CLASS		 ಕೀಲಿ_class;
	CK_ATTRIBUTE		 ಕೀಲಿ_attr[1];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ಖಾಲಿ;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	ಪೂರ್ಣಾಂಕ			 ret = -1;
	ಅಕ್ಷರ			*label;

	memset(&ಕೀಲಿ_attr, 0, ಗಾತ್ರ(ಕೀಲಿ_attr));
	memset(&obj, 0, ಗಾತ್ರ(obj));

	ಕೀಲಿ_class = CKO_CERTIFICATE;
	ಕೀಲಿ_attr[0].type = CKA_CLASS;
	ಕೀಲಿ_attr[0].p_ಮೌಲ್ಯ = &ಕೀಲಿ_class;
	ಕೀಲಿ_attr[0].ul_ಮೌಲ್ಯ_Len = ಗಾತ್ರ(ಕೀಲಿ_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_ಕಂಡುಹಿಡಿ_Objects_Init(session, ಕೀಲಿ_attr, 1);
	ಆದರೆ (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		ಹೋಗು fail;
	}

	ಆಗ (1) {
		CK_CERTIFICATE_TYPE	ck_cert_type;

		rv = f->C_ಕಂಡುಹಿಡಿ_Objects(session, &obj, 1, &n);
		ಆದರೆ (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			ಹೋಗು fail;
		}
		ಆದರೆ (n == 0)
			ನಿಲ್ಲಿಸು;

		memset(&ck_cert_type, 0, ಗಾತ್ರ(ck_cert_type));
		memset(&ಕೀಲಿ_attr, 0, ಗಾತ್ರ(ಕೀಲಿ_attr));
		ಕೀಲಿ_attr[0].type = CKA_CERTIFICATE_TYPE;
		ಕೀಲಿ_attr[0].p_ಮೌಲ್ಯ = &ck_cert_type;
		ಕೀಲಿ_attr[0].ul_ಮೌಲ್ಯ_Len = ಗಾತ್ರ(ck_cert_type);

		rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, obj, ಕೀಲಿ_attr, 1);
		ಆದರೆ (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			ಹೋಗು fail;
		}

		ಕೀಲಿ = ಖಾಲಿ;
		label = ಖಾಲಿ;
		ಆಯ್ಕೆ (ck_cert_type) {
		ಸ್ಥಿತಿ CKC_X_509:
			ಆದರೆ (pkcs11_fetch_x509_pubkey(p, slotidx, &obj,
			    &ಕೀಲಿ, &label) != 0) {
				debug_f("failed to fetch key");
				ಮುಂದುವರಿ;
			}
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			error("skipping unsupported certificate type %lu",
			    ck_cert_type);
			ಮುಂದುವರಿ;
		}
		note_ಕೀಲಿ(p, slotidx, __func__, ಕೀಲಿ);
		ಆದರೆ (pkcs11_ಕೀಲಿ_included(keysp, nkeys, ಕೀಲಿ)) {
			debug2_f("key already included");
			sshkey_free(ಕೀಲಿ);
		} ಇಲ್ಲದಿದ್ದರೆ {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, ಗಾತ್ರ(ರಚನೆ sshkey *));
			(*keysp)[*nkeys] = ಕೀಲಿ;
			ಆದರೆ (labelsp != ಖಾಲಿ) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, ಗಾತ್ರ(ಅಕ್ಷರ *));
				(*labelsp)[*nkeys] = xstrdup((ಅಕ್ಷರ *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_ಕಂಡುಹಿಡಿ_Objects_Final(session);
	ಆದರೆ (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	ಹಿಂತಿರುಗಿ (ret);
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

/*
 * lookup public keys for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pkcs11_fetch_ಕೀಲಿಗಳು(ರಚನೆ pkcs11_provider *p, CK_ULONG slotidx,
    ರಚನೆ sshkey ***keysp, ಅಕ್ಷರ ***labelsp, ಪೂರ್ಣಾಂಕ *nkeys)
{
	ರಚನೆ sshkey		*ಕೀಲಿ = ಖಾಲಿ;
	CK_OBJECT_CLASS		 ಕೀಲಿ_class;
	CK_ATTRIBUTE		 ಕೀಲಿ_attr[2];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ಖಾಲಿ;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	ಪೂರ್ಣಾಂಕ			 ret = -1;

	memset(&ಕೀಲಿ_attr, 0, ಗಾತ್ರ(ಕೀಲಿ_attr));
	memset(&obj, 0, ಗಾತ್ರ(obj));

	ಕೀಲಿ_class = CKO_ಬಹಿರಂಗ_ಕೀಲಿ;
	ಕೀಲಿ_attr[0].type = CKA_CLASS;
	ಕೀಲಿ_attr[0].p_ಮೌಲ್ಯ = &ಕೀಲಿ_class;
	ಕೀಲಿ_attr[0].ul_ಮೌಲ್ಯ_Len = ಗಾತ್ರ(ಕೀಲಿ_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_ಕಂಡುಹಿಡಿ_Objects_Init(session, ಕೀಲಿ_attr, 1);
	ಆದರೆ (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		ಹೋಗು fail;
	}

	ಆಗ (1) {
		CK_ಕೀಲಿ_TYPE	ck_ಕೀಲಿ_type;
		CK_UTF8CHAR	label[256];

		rv = f->C_ಕಂಡುಹಿಡಿ_Objects(session, &obj, 1, &n);
		ಆದರೆ (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			ಹೋಗು fail;
		}
		ಆದರೆ (n == 0)
			ನಿಲ್ಲಿಸು;

		memset(&ck_ಕೀಲಿ_type, 0, ಗಾತ್ರ(ck_ಕೀಲಿ_type));
		memset(&ಕೀಲಿ_attr, 0, ಗಾತ್ರ(ಕೀಲಿ_attr));
		ಕೀಲಿ_attr[0].type = CKA_ಕೀಲಿ_TYPE;
		ಕೀಲಿ_attr[0].p_ಮೌಲ್ಯ = &ck_ಕೀಲಿ_type;
		ಕೀಲಿ_attr[0].ul_ಮೌಲ್ಯ_Len = ಗಾತ್ರ(ck_ಕೀಲಿ_type);
		ಕೀಲಿ_attr[1].type = CKA_LABEL;
		ಕೀಲಿ_attr[1].p_ಮೌಲ್ಯ = &label;
		ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len = ಗಾತ್ರ(label) - 1;

		rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, obj, ಕೀಲಿ_attr, 2);
		ಆದರೆ (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			ಹೋಗು fail;
		}

		label[ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len] = '\0';

		ಆಯ್ಕೆ (ck_ಕೀಲಿ_type) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
		ಸ್ಥಿತಿ CKK_RSA:
			ಕೀಲಿ = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ CKK_ECDSA:
			ಕೀಲಿ = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
		ಸ್ಥಿತಿ CKK_EC_EDWARDS:
			ಕೀಲಿ = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			/* XXX print key type? */
			ಕೀಲಿ = ಖಾಲಿ;
			error("skipping unsupported key type 0x%lx",
			    (u_long)ck_ಕೀಲಿ_type);
		}

		ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ) {
			debug_f("failed to fetch key");
			ಮುಂದುವರಿ;
		}
		note_ಕೀಲಿ(p, slotidx, __func__, ಕೀಲಿ);
		ಆದರೆ (pkcs11_ಕೀಲಿ_included(keysp, nkeys, ಕೀಲಿ)) {
			debug2_f("key already included");
			sshkey_free(ಕೀಲಿ);
		} ಇಲ್ಲದಿದ್ದರೆ {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, ಗಾತ್ರ(ರಚನೆ sshkey *));
			(*keysp)[*nkeys] = ಕೀಲಿ;
			ಆದರೆ (labelsp != ಖಾಲಿ) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, ಗಾತ್ರ(ಅಕ್ಷರ *));
				(*labelsp)[*nkeys] = xstrdup((ಅಕ್ಷರ *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_ಕಂಡುಹಿಡಿ_Objects_Final(session);
	ಆದರೆ (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	ಹಿಂತಿರುಗಿ (ret);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_PKCS11_KEYGEN
#ವ್ಯಾಖ್ಯಾನಿಸು FILL_ATTR(attr, idx, typ, val, len) \
	{ (attr[idx]).type=(typ); (attr[idx]).p_ಮೌಲ್ಯ=(val); (attr[idx]).ul_ಮೌಲ್ಯ_Len=len; idx++; }

ಸ್ಥಿರ ರಚನೆ sshkey *
pkcs11_rsa_generate_ಖಾಸಗಿ_ಕೀಲಿ(ರಚನೆ pkcs11_provider *p, CK_ULONG slotidx,
    ಅಕ್ಷರ *label, CK_ULONG ಬಿಟ್ಟುಗಳು, CK_BYTE keyid, uint32_t *err)
{
	ರಚನೆ pkcs11_slotinfo	*si;
	ಅಕ್ಷರ			*plabel = label ? label : "";
	ಪೂರ್ಣಾಂಕ			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_ಕೀಲಿ_2, priv_ಕೀಲಿ;
	CK_ATTRIBUTE		 tpub[16], tpriv[16];
	CK_MECHANISM		 mech = {
	    CKM_RSA_PKCS_ಕೀಲಿ_PAIR_GEN, NULL_PTR, 0
	};
	CK_BYTE			 pubExponent[] = {
	    0x01, 0x00, 0x01 /* RSA_F4 in bytes */
	};
	pubkey_filter[0].p_ಮೌಲ್ಯ = &pubkey_class;
	cert_filter[0].p_ಮೌಲ್ಯ = &cert_class;

	*err = 0;

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, ಗಾತ್ರ(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, ಗಾತ್ರ(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, ಗಾತ್ರ(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    ಗಾತ್ರ(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, ಗಾತ್ರ(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, ಗಾತ್ರ(false_val));
	FILL_ATTR(tpub, npub, CKA_MODULUS_ಬಿಟ್ಟುಗಳು, &ಬಿಟ್ಟುಗಳು, ಗಾತ್ರ(ಬಿಟ್ಟುಗಳು));
	FILL_ATTR(tpub, npub, CKA_ಬಹಿರಂಗ_EXPONENT, pubExponent,
	    ಗಾತ್ರ(pubExponent));
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, ಗಾತ್ರ(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN,  &true_val, ಗಾತ್ರ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL,  plabel, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(plabel));
	FILL_ATTR(tpriv, npriv, CKA_ಖಾಸಗಿ,  &true_val, ಗಾತ್ರ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE,  &true_val, ಗಾತ್ರ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT,  &false_val, ಗಾತ್ರ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN,  &true_val, ಗಾತ್ರ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER,  &false_val,
	    ಗಾತ್ರ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP,  &false_val, ಗಾತ್ರ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE,  &false_val, ಗಾತ್ರ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, ಗಾತ್ರ(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	ಆದರೆ ((rv = f->C_Generate_ಕೀಲಿ_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_ಕೀಲಿ_2, &priv_ಕೀಲಿ)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}

	ಹಿಂತಿರುಗಿ pkcs11_fetch_rsa_pubkey(p, slotidx, &pub_ಕೀಲಿ_2);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
h2i(ಅಕ್ಷರ c)
{
	ಆದರೆ (c >= '0' && c <= '9')
		ಹಿಂತಿರುಗಿ c - '0';
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (c >= 'a' && c <= 'f')
		ಹಿಂತಿರುಗಿ c - 'a' + 10;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (c >= 'A' && c <= 'F')
		ಹಿಂತಿರುಗಿ c - 'A' + 10;
	ಇಲ್ಲದಿದ್ದರೆ
		ಹಿಂತಿರುಗಿ -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pkcs11_decode_hex(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hex, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ **dest, ಗಾತ್ರ_t *rlen)
{
	ಗಾತ್ರ_t	i, len;

	ಆದರೆ (dest)
		*dest = ಖಾಲಿ;
	ಆದರೆ (rlen)
		*rlen = 0;

	ಆದರೆ ((len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(hex)) % 2)
		ಹಿಂತಿರುಗಿ -1;
	len /= 2;

	*dest = xmalloc(len);

	ಗಾಗಿ (i = 0; i < len; i++) {
		ಪೂರ್ಣಾಂಕ hi, lo;

		hi = h2i(hex[2 * i]);
		lo = h2i(hex[(2 * i) + 1]);
		ಆದರೆ (hi == -1 || lo == -1)
			ಹಿಂತಿರುಗಿ -1;
		(*dest)[i] = (hi << 4) | lo;
	}

	ಆದರೆ (rlen)
		*rlen = len;

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ರಚನೆ ec_ವಕ್ರ_info {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ	*name;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ	*oid;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ	*oid_encoded;
	ಗಾತ್ರ_t		 ಗಾತ್ರ_2;
} ec_ವಕ್ರ_infos[] = {
	{"prime256v1",	"1.2.840.10045.3.1.7",	"06082A8648CE3D030107", 256},
	{"secp384r1",	"1.3.132.0.34",		"06052B81040022",	384},
	{"secp521r1",	"1.3.132.0.35",		"06052B81040023",	521},
	{ಖಾಲಿ,		ಖಾಲಿ,			ಖಾಲಿ,			0},
};

ಸ್ಥಿರ ರಚನೆ sshkey *
pkcs11_ecdsa_generate_ಖಾಸಗಿ_ಕೀಲಿ(ರಚನೆ pkcs11_provider *p, CK_ULONG slotidx,
    ಅಕ್ಷರ *label, CK_ULONG ಬಿಟ್ಟುಗಳು, CK_BYTE keyid, uint32_t *err)
{
	ರಚನೆ pkcs11_slotinfo	*si;
	ಅಕ್ಷರ			*plabel = label ? label : "";
	ಪೂರ್ಣಾಂಕ			 i;
	ಗಾತ್ರ_t			 ecparams_ಗಾತ್ರ;
	ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ		*ecparams = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_ಕೀಲಿ_2, priv_ಕೀಲಿ;
	CK_MECHANISM		 mech = {
	    CKM_EC_ಕೀಲಿ_PAIR_GEN, NULL_PTR, 0
	};
	CK_ATTRIBUTE		 tpub[16], tpriv[16];

	*err = 0;

	ಗಾಗಿ (i = 0; ec_ವಕ್ರ_infos[i].name; i++) {
		ಆದರೆ (ec_ವಕ್ರ_infos[i].ಗಾತ್ರ_2 == ಬಿಟ್ಟುಗಳು)
			ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ (!ec_ವಕ್ರ_infos[i].name) {
		error_f("invalid key size %lu", ಬಿಟ್ಟುಗಳು);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ (pkcs11_decode_hex(ec_ವಕ್ರ_infos[i].oid_encoded, &ecparams,
	    &ecparams_ಗಾತ್ರ) == -1) {
		error_f("invalid oid");
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, ಗಾತ್ರ(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, ಗಾತ್ರ(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, ಗಾತ್ರ(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    ಗಾತ್ರ(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, ಗಾತ್ರ(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, ಗಾತ್ರ(false_val));
	FILL_ATTR(tpub, npub, CKA_EC_PARAMS, ecparams, ecparams_ಗಾತ್ರ);
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, ಗಾತ್ರ(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN, &true_val, ಗಾತ್ರ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL, plabel, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(plabel));
	FILL_ATTR(tpriv, npriv, CKA_ಖಾಸಗಿ, &true_val, ಗಾತ್ರ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE, &true_val, ಗಾತ್ರ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT, &false_val, ಗಾತ್ರ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN, &true_val, ಗಾತ್ರ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER, &false_val,
	    ಗಾತ್ರ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP, &false_val, ಗಾತ್ರ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE, &false_val, ಗಾತ್ರ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, ಗಾತ್ರ(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	ಆದರೆ ((rv = f->C_Generate_ಕೀಲಿ_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_ಕೀಲಿ_2, &priv_ಕೀಲಿ)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}

	ಹಿಂತಿರುಗಿ pkcs11_fetch_ecdsa_pubkey(p, slotidx, &pub_ಕೀಲಿ_2);
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_PKCS11_KEYGEN */

/*
 * register a new provider, fails if provider already exists. if
 * keyp is provided, fetch keys.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
pkcs11_ರಿಜಿಸ್ಟರ್_provider(ಅಕ್ಷರ *provider_id, ಅಕ್ಷರ *pin,
    ರಚನೆ sshkey ***keyp, ಅಕ್ಷರ ***labelsp,
    ರಚನೆ pkcs11_provider **providerp, CK_ULONG user)
{
	ಪೂರ್ಣಾಂಕ nkeys, need_finalize = 0;
	ಪೂರ್ಣಾಂಕ ret = -1;
	ರಚನೆ pkcs11_provider *p = ಖಾಲಿ;
	ಶೂನ್ಯ *handle = ಖಾಲಿ;
	CK_RV (*getfunctionlist)(CK_FUNCTION_LIST **);
	CK_RV rv;
	CK_FUNCTION_LIST *f = ಖಾಲಿ;
	CK_TOKEN_INFO *token;
	CK_ULONG i;

	ಆದರೆ (providerp == ಖಾಲಿ)
		ಹೋಗು fail;
	*providerp = ಖಾಲಿ;

	ಆದರೆ (keyp != ಖಾಲಿ)
		*keyp = ಖಾಲಿ;
	ಆದರೆ (labelsp != ಖಾಲಿ)
		*labelsp = ಖಾಲಿ;

	ಆದರೆ (pkcs11_provider_lookup(provider_id) != ಖಾಲಿ) {
		debug_f("provider already registered: %s", provider_id);
		ಹೋಗು fail;
	}
	ಆದರೆ (lib_ಒಳಗೊಂಡಿದೆ_ಚಿಹ್ನೆ(provider_id, "C_GetFunctionList") != 0) {
		error("provider %s is not a PKCS11 library", provider_id);
		ಹೋಗು fail;
	}
	/* open shared pkcs11-library */
	ಆದರೆ ((handle = dlopen(provider_id, RTLD_NOW)) == ಖಾಲಿ) {
		error("dlopen %s failed: %s", provider_id, dlerror());
		ಹೋಗು fail;
	}
	ಆದರೆ ((getfunctionlist = dlsym(handle, "C_GetFunctionList")) == ಖಾಲಿ)
		fatal("dlsym(C_GetFunctionList) failed: %s", dlerror());
	p = xcalloc(1, ಗಾತ್ರ(*p));
	p->name = xstrdup(provider_id);
	p->handle = handle;
	/* set up the pkcs11 callbacks */
	ಆದರೆ ((rv = (*getfunctionlist)(&f)) != CKR_OK) {
		error("C_GetFunctionList for provider %s failed: %lu",
		    provider_id, rv);
		ಹೋಗು fail;
	}
	p->function_list = f;
	ಆದರೆ ((rv = f->C_Initialize(ಖಾಲಿ)) != CKR_OK) {
		error("C_Initialize for provider %s failed: %lu",
		    provider_id, rv);
		ಹೋಗು fail;
	}
	need_finalize = 1;
	ಆದರೆ ((rv = f->C_GetInfo(&p->info)) != CKR_OK) {
		error("C_GetInfo for provider %s failed: %lu",
		    provider_id, rv);
		ಹೋಗು fail;
	}
	debug("provider %s: manufacturerID <%.*s> cryptokiVersion %d.%d"
	    " libraryDescription <%.*s> libraryVersion %d.%d",
	    provider_id,
	    RMSPACE(p->info.manufacturerID),
	    p->info.cryptoki_ಆವೃತ್ತಿ_2.major,
	    p->info.cryptoki_ಆವೃತ್ತಿ_2.minor,
	    RMSPACE(p->info.libraryDescription),
	    p->info.library_ಆವೃತ್ತಿ_2.major,
	    p->info.library_ಆವೃತ್ತಿ_2.minor);
	ಆದರೆ ((rv = f->C_Get_ಸ್ಥಾನ_List(CK_TRUE, ಖಾಲಿ, &p->nslots)) != CKR_OK) {
		error("C_GetSlotList failed: %lu", rv);
		ಹೋಗು fail;
	}
	ಆದರೆ (p->nslots == 0) {
		debug_f("provider %s returned no slots", provider_id);
		ret = -SSH_PKCS11_ERR_NO_SLOTS;
		ಹೋಗು fail;
	}
	p->slotlist = xcalloc(p->nslots, ಗಾತ್ರ(CK_ಸ್ಥಾನ_ID));
	ಆದರೆ ((rv = f->C_Get_ಸ್ಥಾನ_List(CK_TRUE, p->slotlist, &p->nslots))
	    != CKR_OK) {
		error("C_GetSlotList for provider %s failed: %lu",
		    provider_id, rv);
		ಹೋಗು fail;
	}
	p->slotinfo = xcalloc(p->nslots, ಗಾತ್ರ(ರಚನೆ pkcs11_slotinfo));
	p->valid = 1;
	nkeys = 0;
	ಗಾಗಿ (i = 0; i < p->nslots; i++) {
		token = &p->slotinfo[i].token;
		ಆದರೆ ((rv = f->C_GetTokenInfo(p->slotlist[i], token))
		    != CKR_OK) {
			error("C_GetTokenInfo for provider %s slot %lu "
			    "failed: %lu", provider_id, (u_long)i, rv);
			ಮುಂದುವರಿ;
		}
		ಆದರೆ ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
			debug2_f("ignoring uninitialised token in "
			    "provider %s slot %lu", provider_id, (u_long)i);
			ಮುಂದುವರಿ;
		}
		debug("provider %s slot %lu: label <%.*s> "
		    "manufacturerID <%.*s> model <%.*s> serial <%.*s> "
		    "flags 0x%lx",
		    provider_id, (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ)i,
		    RMSPACE(token->label), RMSPACE(token->manufacturerID),
		    RMSPACE(token->model), RMSPACE(token->serial_ಸಂಖ್ಯೆ_2),
		    token->flags);
		/*
		 * open session, login with pin and retrieve public
		 * keys (if keyp is provided)
		 */
		ಆದರೆ ((ret = pkcs11_open_session(p, i, pin, user)) != 0 ||
		    keyp == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		pkcs11_fetch_ಕೀಲಿಗಳು(p, i, keyp, labelsp, &nkeys);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
		pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#ಆದರೆ_ಅಂತ್ಯ
		ಆದರೆ (nkeys == 0 && !p->slotinfo[i].logged_ಒಳ &&
		    pkcs11_interactive) {
			/*
			 * Some tokens require login before they will
			 * expose keys.
			 */
			ಆದರೆ (pkcs11_login_ಸ್ಥಾನ(p, &p->slotinfo[i],
			    CKU_USER) < 0) {
				error("login failed");
				ಮುಂದುವರಿ;
			}
			pkcs11_fetch_ಕೀಲಿಗಳು(p, i, keyp, labelsp, &nkeys);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
			pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#ಆದರೆ_ಅಂತ್ಯ
		}
	}

	/* now owned by caller */
	*providerp = p;

	TAILQ_INSERT_TAIL(&pkcs11_providers, p, ಮುಂದಿನ);
	p->refcount++;	/* add to provider list */

	ಹಿಂತಿರುಗಿ (nkeys);
fail:
	ಆದರೆ (need_finalize && (rv = f->C_Finalize(ಖಾಲಿ)) != CKR_OK)
		error("C_Finalize for provider %s failed: %lu",
		    provider_id, rv);
	ಆದರೆ (p) {
		ಬಿಡುಗಡೆ(p->name);
		ಬಿಡುಗಡೆ(p->slotlist);
		ಬಿಡುಗಡೆ(p->slotinfo);
		ಬಿಡುಗಡೆ(p);
	}
	ಆದರೆ (handle)
		dlclose(handle);
	ಆದರೆ (ret > 0)
		ret = -1;
	ಹಿಂತಿರುಗಿ (ret);
}

ಪೂರ್ಣಾಂಕ
pkcs11_init(ಪೂರ್ಣಾಂಕ interactive)
{
	debug3_f("called, interactive = %d", interactive);

	pkcs11_interactive = interactive;
	TAILQ_INIT(&pkcs11_providers);
	TAILQ_INIT(&pkcs11_ಕೀಲಿಗಳು);
	ಹಿಂತಿರುಗಿ (0);
}

/* unregister all providers, keys might still point to the providers */
ಶೂನ್ಯ
pkcs11_terminate(ಶೂನ್ಯ)
{
	ರಚನೆ pkcs11_provider *p;
	ರಚನೆ pkcs11_ಕೀಲಿ *k11;

	debug3_f("called");

	ಆಗ ((k11 = TAILQ_FIRST(&pkcs11_ಕೀಲಿಗಳು)) != ಖಾಲಿ) {
		TAILQ_REMOVE(&pkcs11_ಕೀಲಿಗಳು, k11, ಮುಂದಿನ);
		pkcs11_k11_free(k11);
	}
	ಆಗ ((p = TAILQ_FIRST(&pkcs11_providers)) != ಖಾಲಿ) {
		TAILQ_REMOVE(&pkcs11_providers, p, ಮುಂದಿನ);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
}

/*
 * register a new provider and get number of keys hold by the token,
 * fails if provider already exists
 */
ಪೂರ್ಣಾಂಕ
pkcs11_ಕೂಡಿಸು_provider(ಅಕ್ಷರ *provider_id, ಅಕ್ಷರ *pin, ರಚನೆ sshkey ***keyp,
    ಅಕ್ಷರ ***labelsp)
{
	ರಚನೆ pkcs11_provider *p = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ nkeys;

	nkeys = pkcs11_ರಿಜಿಸ್ಟರ್_provider(provider_id, pin, keyp, labelsp,
	    &p, CKU_USER);

	/* no keys found or some other error, de-register provider */
	ಆದರೆ (nkeys <= 0 && p != ಖಾಲಿ) {
		TAILQ_REMOVE(&pkcs11_providers, p, ಮುಂದಿನ);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
	ಆದರೆ (nkeys == 0)
		debug_f("provider %s returned no keys", provider_id);

	ಹಿಂತಿರುಗಿ (nkeys);
}

ಪೂರ್ಣಾಂಕ
pkcs11_sign(ರಚನೆ sshkey *ಕೀಲಿ,
    u_char **sigp, ಗಾತ್ರ_t *lenp,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin, u_int compat)
{
	ಆಯ್ಕೆ (ಕೀಲಿ->type) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
	ಸ್ಥಿತಿ ಕೀಲಿ_RSA_CERT:
		ಹಿಂತಿರುಗಿ pkcs11_sign_rsa(ಕೀಲಿ, sigp, lenp, ದತ್ತಾಂಶ, datalen,
		    alg, sk_provider, sk_pin, compat);
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_CERT:
		ಹಿಂತಿರುಗಿ pkcs11_sign_ecdsa(ಕೀಲಿ, sigp, lenp, ದತ್ತಾಂಶ, datalen,
		    alg, sk_provider, sk_pin, compat);
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519:
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_CERT:
		ಹಿಂತಿರುಗಿ pkcs11_sign_ed25519(ಕೀಲಿ, sigp, lenp, ದತ್ತಾಂಶ, datalen,
		    alg, sk_provider, sk_pin, compat);
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
	}
}

ಶೂನ್ಯ
pkcs11_ಕೀಲಿ_free(ರಚನೆ sshkey *ಕೀಲಿ)
{
	/* never called */
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_PKCS11_KEYGEN
ರಚನೆ sshkey *
pkcs11_gakp(ಅಕ್ಷರ *provider_id, ಅಕ್ಷರ *pin, ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ slotidx, ಅಕ್ಷರ *label,
    ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ type, ಚಿಹ್ನೆರಹಿತ ಪೂರ್ಣಾಂಕ ಬಿಟ್ಟುಗಳು, ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ keyid, uint32_t *err)
{
	ರಚನೆ pkcs11_provider	*p = ಖಾಲಿ;
	ರಚನೆ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	ರಚನೆ sshkey		*k = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ			 ret = -1, reset_pin = 0, reset_provider = 0;
	CK_RV			 rv;

	*err = 0;

	ಆದರೆ ((p = pkcs11_provider_lookup(provider_id)) != ಖಾಲಿ)
		debug_f("provider \"%s\" available", provider_id);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((ret = pkcs11_ರಿಜಿಸ್ಟರ್_provider(provider_id, pin, ಖಾಲಿ, ಖಾಲಿ,
	    &p, CKU_SO)) < 0) {
		debug_f("could not register provider %s", provider_id);
		ಹೋಗು ಹೊರಹೋಗು;
	} ಇಲ್ಲದಿದ್ದರೆ
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	ಆದರೆ ((rv = f->C_ಗಣ_Operation_State(session , pin, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} ಇಲ್ಲದಿದ್ದರೆ
		reset_pin = 1;

	ಆಯ್ಕೆ (type) {
	ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
		ಆದರೆ ((k = pkcs11_rsa_generate_ಖಾಸಗಿ_ಕೀಲಿ(p, slotidx, label,
		    ಬಿಟ್ಟುಗಳು, keyid, err)) == ಖಾಲಿ) {
			debug_f("failed to generate RSA key");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA:
		ಆದರೆ ((k = pkcs11_ecdsa_generate_ಖಾಸಗಿ_ಕೀಲಿ(p, slotidx, label,
		    ಬಿಟ್ಟುಗಳು, keyid, err)) == ಖಾಲಿ) {
			debug_f("failed to generate ECDSA key");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		*err = SSH_PKCS11_ERR_GENERIC;
		debug_f("unknown type %d", type);
		ಹೋಗು ಹೊರಹೋಗು;
	}

ಹೊರಹೋಗು:
	ಆದರೆ (reset_pin)
		f->C_ಗಣ_Operation_State(session , ಖಾಲಿ, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	ಆದರೆ (reset_provider)
		pkcs11_del_provider(provider_id);

	ಹಿಂತಿರುಗಿ (k);
}

ರಚನೆ sshkey *
pkcs11_destroy_keypair(ಅಕ್ಷರ *provider_id, ಅಕ್ಷರ *pin, ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ slotidx,
    ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ keyid, uint32_t *err)
{
	ರಚನೆ pkcs11_provider	*p = ಖಾಲಿ;
	ರಚನೆ pkcs11_slotinfo	*si;
	ರಚನೆ sshkey		*k = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ			 reset_pin = 0, reset_provider = 0;
	CK_ULONG		 nattrs;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_ATTRIBUTE		 attrs[16];
	CK_OBJECT_CLASS		 ಕೀಲಿ_class;
	CK_ಕೀಲಿ_TYPE		 ಕೀಲಿ_type;
	CK_OBJECT_HANDLE	 obj = CK_INVALID_HANDLE;
	CK_RV			 rv;

	*err = 0;

	ಆದರೆ ((p = pkcs11_provider_lookup(provider_id)) != ಖಾಲಿ) {
		debug_f("using provider \"%s\"", provider_id);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (pkcs11_ರಿಜಿಸ್ಟರ್_provider(provider_id, pin, ಖಾಲಿ, ಖಾಲಿ, &p,
	    CKU_SO) < 0) {
		debug_f("could not register provider %s",
		    provider_id);
		ಹೋಗು ಹೊರಹೋಗು;
	} ಇಲ್ಲದಿದ್ದರೆ
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	ಆದರೆ ((rv = f->C_ಗಣ_Operation_State(session , pin, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} ಇಲ್ಲದಿದ್ದರೆ
		reset_pin = 1;

	/* private key */
	nattrs = 0;
	ಕೀಲಿ_class = CKO_ಖಾಸಗಿ_ಕೀಲಿ;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &ಕೀಲಿ_class, ಗಾತ್ರ(ಕೀಲಿ_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, ಗಾತ್ರ(keyid));

	ಆದರೆ (pkcs11_ಕಂಡುಹಿಡಿ(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {
		ಆದರೆ ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy private key 0x%hhx",
			    keyid);
			*err = rv;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}

	/* public key */
	nattrs = 0;
	ಕೀಲಿ_class = CKO_ಬಹಿರಂಗ_ಕೀಲಿ;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &ಕೀಲಿ_class, ಗಾತ್ರ(ಕೀಲಿ_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, ಗಾತ್ರ(keyid));

	ಆದರೆ (pkcs11_ಕಂಡುಹಿಡಿ(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {

		/* get key type */
		nattrs = 0;
		FILL_ATTR(attrs, nattrs, CKA_ಕೀಲಿ_TYPE, &ಕೀಲಿ_type,
		    ಗಾತ್ರ(ಕೀಲಿ_type));
		rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, obj, attrs, nattrs);
		ಆದರೆ (rv != CKR_OK) {
			debug_f("could not get key type of public key 0x%hhx",
			    keyid);
			*err = rv;
			ಕೀಲಿ_type = -1;
		}
		ಆಯ್ಕೆ (ಕೀಲಿ_type) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
		ಸ್ಥಿತಿ CKK_RSA:
			k = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ CKK_ECDSA:
			k = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
		ಸ್ಥಿತಿ CKK_EC_EDWARDS:
			k = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			debug_f("unsupported key type %lu", (u_long)ಕೀಲಿ_type);
			ನಿಲ್ಲಿಸು;
		}

		ಆದರೆ ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy public key 0x%hhx", keyid);
			*err = rv;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}

ಹೊರಹೋಗು:
	ಆದರೆ (reset_pin)
		f->C_ಗಣ_Operation_State(session , ಖಾಲಿ, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	ಆದರೆ (reset_provider)
		pkcs11_del_provider(provider_id);

	ಹಿಂತಿರುಗಿ (k);
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_PKCS11_KEYGEN */
#ಇಲ್ಲದಿದ್ದರೆ /* ENABLE_PKCS11 */

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "ssh-pkcs11.h"

ಪೂರ್ಣಾಂಕ
pkcs11_init(ಪೂರ್ಣಾಂಕ interactive)
{
	error_f("PKCS#11 not supported");
	ಹಿಂತಿರುಗಿ (-1);
}

ಪೂರ್ಣಾಂಕ
pkcs11_ಕೂಡಿಸು_provider(ಅಕ್ಷರ *provider_id, ಅಕ್ಷರ *pin, ರಚನೆ sshkey ***keyp,
    ಅಕ್ಷರ ***labelsp)
{
	error_f("PKCS#11 not supported");
	ಹಿಂತಿರುಗಿ (-1);
}

ಶೂನ್ಯ
pkcs11_ಕೀಲಿ_free(ರಚನೆ sshkey *ಕೀಲಿ)
{
	error_f("PKCS#11 not supported");
}

ಪೂರ್ಣಾಂಕ
pkcs11_sign(ರಚನೆ sshkey *ಕೀಲಿ,
    u_char **sigp, ಗಾತ್ರ_t *lenp,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin, u_int compat)
{
	error_f("PKCS#11 not supported");
	ಹಿಂತಿರುಗಿ SSH_ERR_FEATURE_UNSUPPORTED;
}

ಶೂನ್ಯ
pkcs11_terminate(ಶೂನ್ಯ)
{
	error_f("PKCS#11 not supported");
}
#ಆದರೆ_ಅಂತ್ಯ /* ENABLE_PKCS11 */
