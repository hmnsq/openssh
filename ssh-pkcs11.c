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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_PKCS11

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/time.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/queue.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <dlfcn.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ecdsa.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/x509.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/err.h>
#ਜੇ_ਅੰਤ

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CRYPTOKI_COMPAT
#ਅਨ੍ਤਰ੍ਭਾਵ "pkcs11.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHKEY_ਅੰਦਰੂਨੀ
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-pkcs11.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "crypto_api.h"

ਬਣਤਰ pkcs11_slotinfo {
	CK_TOKEN_INFO		token;
	CK_SESSION_HANDLE	session;
	ਪੂਰਨ			logged_ਵਿੱਚ;
};

ਬਣਤਰ pkcs11_provider {
	ਅੱਖਰ			*name;
	ਖਾਲੀ			*handle;
	CK_FUNCTION_LIST	*function_list;
	CK_INFO			info;
	CK_ULONG		nslots;
	CK_ਥਾਂ_ID		*slotlist;
	ਬਣਤਰ pkcs11_slotinfo	*slotinfo;
	ਪੂਰਨ			valid;
	ਪੂਰਨ			refcount;
	TAILQ_ENTRY(pkcs11_provider) ਅਗਲਾ;
};

TAILQ_HEAD(, pkcs11_provider) pkcs11_providers;

ਬਣਤਰ pkcs11_ਕੁੰਜੀ {
	ਬਣਤਰ sshbuf		*keyblob;
	ਬਣਤਰ pkcs11_provider	*provider;
	CK_ULONG		slotidx;
	ਅੱਖਰ			*keyid;
	ਪੂਰਨ			keyid_len;
	TAILQ_ENTRY(pkcs11_ਕੁੰਜੀ)	ਅਗਲਾ;
};

TAILQ_HEAD(, pkcs11_ਕੁੰਜੀ) pkcs11_ਕੁੰਜੀਆਂ; /* XXX a tree would be better */

ਪੂਰਨ pkcs11_interactive = 0;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
ਸਥਿਰ ਖਾਲੀ
ossl_error(ਅਚਲ ਅੱਖਰ *ਸੁਨੇਹਾ)
{
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ    e;

	error_f("%s", ਸੁਨੇਹਾ);
	ਜਦੋਂ ((e = ERR_get_error()) != 0)
		error_f("libcrypto error: %s", ERR_error_string(e, ਨਿਰਾ));
}
#ਜੇ_ਅੰਤ

/*
 * finalize a provider shared library, it's no longer usable.
 * however, there might still be keys referencing this provider,
 * so the actual freeing of memory is handled by pkcs11_provider_unref().
 * this is called when a provider gets unregistered.
 */
ਸਥਿਰ ਖਾਲੀ
pkcs11_provider_finalize(ਬਣਤਰ pkcs11_provider *p)
{
	CK_RV rv;
	CK_ULONG i;

	debug_f("provider \"%s\" refcount %d valid %d",
	    p->name, p->refcount, p->valid);
	ਜੇ (!p->valid)
		ਵਾਪਸ;
	ਲਈ (i = 0; i < p->nslots; i++) {
		ਜੇ (p->slotinfo[i].session &&
		    (rv = p->function_list->C_CloseSession(
		    p->slotinfo[i].session)) != CKR_OK)
			error("C_CloseSession failed: %lu", rv);
	}
	ਜੇ ((rv = p->function_list->C_Finalize(ਨਿਰਾ)) != CKR_OK)
		error("C_Finalize failed: %lu", rv);
	p->valid = 0;
	p->function_list = ਨਿਰਾ;
	dlclose(p->handle);
}

/*
 * remove a reference to the provider.
 * called when a key gets destroyed or when the provider is unregistered.
 */
ਸਥਿਰ ਖਾਲੀ
pkcs11_provider_unref(ਬਣਤਰ pkcs11_provider *p)
{
	debug_f("provider \"%s\" refcount %d", p->name, p->refcount);
	ਜੇ (--p->refcount <= 0) {
		ਜੇ (p->valid)
			error_f("provider \"%s\" still valid", p->name);
		ਮੁਕਤ(p->name);
		ਮੁਕਤ(p->slotlist);
		ਮੁਕਤ(p->slotinfo);
		ਮੁਕਤ(p);
	}
}

/* lookup provider by name */
ਸਥਿਰ ਬਣਤਰ pkcs11_provider *
pkcs11_provider_lookup(ਅੱਖਰ *provider_id)
{
	ਬਣਤਰ pkcs11_provider *p;

	TAILQ_FOREACH(p, &pkcs11_providers, ਅਗਲਾ) {
		debug("check provider \"%s\"", p->name);
		ਜੇ (!strcmp(provider_id, p->name))
			ਵਾਪਸ (p);
	}
	ਵਾਪਸ (ਨਿਰਾ);
}

/* unregister provider by name */
ਪੂਰਨ
pkcs11_del_provider(ਅੱਖਰ *provider_id)
{
	ਬਣਤਰ pkcs11_provider *p;

	ਜੇ ((p = pkcs11_provider_lookup(provider_id)) != ਨਿਰਾ) {
		TAILQ_REMOVE(&pkcs11_providers, p, ਅਗਲਾ);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
		ਵਾਪਸ (0);
	}
	ਵਾਪਸ (-1);
}

/* release a wrapped object */
ਸਥਿਰ ਖਾਲੀ
pkcs11_k11_free(ਬਣਤਰ pkcs11_ਕੁੰਜੀ *k11)
{
	ਜੇ (k11 == ਨਿਰਾ)
		ਵਾਪਸ;
	ਜੇ (k11->provider)
		pkcs11_provider_unref(k11->provider);
	ਮੁਕਤ(k11->keyid);
	sshbuf_free(k11->keyblob);
	ਮੁਕਤ(k11);
}

/* find a single 'obj' for given attributes */
ਸਥਿਰ ਪੂਰਨ
pkcs11_ਲੱਭੋ(ਬਣਤਰ pkcs11_provider *p, CK_ULONG slotidx, CK_ATTRIBUTE *attr,
    CK_ULONG nattr, CK_OBJECT_HANDLE *obj)
{
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	session;
	CK_ULONG		nfound = 0;
	CK_RV			rv;
	ਪੂਰਨ			ret = -1;

	f = p->function_list;
	session = p->slotinfo[slotidx].session;
	ਜੇ ((rv = f->C_ਲੱਭੋ_Objects_Init(session, attr, nattr)) != CKR_OK) {
		error("C_FindObjectsInit failed (nattr %lu): %lu", nattr, rv);
		ਵਾਪਸ (-1);
	}
	ਜੇ ((rv = f->C_ਲੱਭੋ_Objects(session, obj, 1, &nfound)) != CKR_OK ||
	    nfound != 1) {
		debug("C_FindObjects failed (nfound %lu nattr %lu): %lu",
		    nfound, nattr, rv);
	} ਨਹੀਂਤਾਂ
		ret = 0;
	ਜੇ ((rv = f->C_ਲੱਭੋ_Objects_Final(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	ਵਾਪਸ (ret);
}

ਸਥਿਰ ਪੂਰਨ
pkcs11_login_ਥਾਂ(ਬਣਤਰ pkcs11_provider *provider, ਬਣਤਰ pkcs11_slotinfo *si,
    CK_USER_TYPE type)
{
	ਅੱਖਰ			*pin = ਨਿਰਾ, prompt[1024];
	CK_RV			 rv;

	ਜੇ (provider == ਨਿਰਾ || si == ਨਿਰਾ || !provider->valid) {
		error("no pkcs11 (valid) provider found");
		ਵਾਪਸ (-1);
	}

	ਜੇ (!pkcs11_interactive) {
		error("need pin entry%s",
		    (si->token.flags & CKF_PROTECTED_AUTHENTICATION_ਰਸਤਾ) ?
		    " on reader keypad" : "");
		ਵਾਪਸ (-1);
	}
	ਜੇ (si->token.flags & CKF_PROTECTED_AUTHENTICATION_ਰਸਤਾ)
		verbose("Deferring PIN entry to reader keypad.");
	ਨਹੀਂਤਾਂ {
		snprintf(prompt, ਆਕਾਰ(prompt), "Enter PIN for '%s': ",
		    si->token.label);
		ਜੇ ((pin = read_passphrase(prompt, RP_ALLOW_EOF)) == ਨਿਰਾ) {
			debug_f("no pin specified");
			ਵਾਪਸ (-1);	/* bail out */
		}
	}
	rv = provider->function_list->C_Login(si->session, type, (u_char *)pin,
	    (pin != ਨਿਰਾ) ? ਲੜੀ_ਲੰਬਾਈ(pin) : 0);
	ਜੇ (pin != ਨਿਰਾ)
		freezero(pin, ਲੜੀ_ਲੰਬਾਈ(pin));

	ਚੋਣ (rv) {
	ਹਾਲਤ CKR_OK:
	ਹਾਲਤ CKR_USER_ALREADY_LOGGED_ਵਿੱਚ:
		/* success */
		ਰੋਕੋ;
	ਹਾਲਤ CKR_PIN_LEN_RANGE:
		error("PKCS#11 login failed: PIN length out of range");
		ਵਾਪਸ -1;
	ਹਾਲਤ CKR_PIN_INCORRECT:
		error("PKCS#11 login failed: PIN incorrect");
		ਵਾਪਸ -1;
	ਹਾਲਤ CKR_PIN_LOCKED:
		error("PKCS#11 login failed: PIN locked");
		ਵਾਪਸ -1;
	ਮੂਲ:
		error("PKCS#11 login failed: error %lu", rv);
		ਵਾਪਸ -1;
	}
	si->logged_ਵਿੱਚ = 1;
	ਵਾਪਸ (0);
}

ਸਥਿਰ ਪੂਰਨ
pkcs11_login(ਬਣਤਰ pkcs11_ਕੁੰਜੀ *k11, CK_USER_TYPE type)
{
	ਜੇ (k11 == ਨਿਰਾ || k11->provider == ਨਿਰਾ || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		ਵਾਪਸ (-1);
	}

	ਵਾਪਸ pkcs11_login_ਥਾਂ(k11->provider,
	    &k11->provider->slotinfo[k11->slotidx], type);
}


ਸਥਿਰ ਪੂਰਨ
pkcs11_check_obj_bool_attrib(ਬਣਤਰ pkcs11_ਕੁੰਜੀ *k11, CK_OBJECT_HANDLE obj,
    CK_ATTRIBUTE_TYPE type, ਪੂਰਨ *val)
{
	ਬਣਤਰ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_BBOOL		flag = 0;
	CK_ATTRIBUTE		attr;
	CK_RV			 rv;

	*val = 0;

	ਜੇ (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		ਵਾਪਸ (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	attr.type = type;
	attr.p_ਮੁੱਲ = &flag;
	attr.ul_ਮੁੱਲ_Len = ਆਕਾਰ(flag);

	rv = f->C_Get_Attribute_ਮੁੱਲ(si->session, obj, &attr, 1);
	ਜੇ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ਵਾਪਸ (-1);
	}
	*val = flag != 0;
	debug_f("provider \"%s\" slot %lu object %lu: attrib %lu = %d",
	    k11->provider->name, k11->slotidx, obj, type, *val);
	ਵਾਪਸ (0);
}

ਸਥਿਰ ਪੂਰਨ
pkcs11_get_ਕੁੰਜੀ(ਬਣਤਰ pkcs11_ਕੁੰਜੀ *k11, CK_MECHANISM_TYPE mech_type)
{
	ਬਣਤਰ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	 obj;
	CK_RV			 rv;
	CK_OBJECT_CLASS		 ਨਿੱਜੀ_ਕੁੰਜੀ_class;
	CK_BBOOL		 true_val;
	CK_MECHANISM		 mech;
	CK_ATTRIBUTE		 ਕੁੰਜੀ_filter[3];
	ਪੂਰਨ			 always_auth = 0;
	ਪੂਰਨ			 did_login = 0;

	ਜੇ (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		ਵਾਪਸ (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	ਜੇ ((si->token.flags & CKF_LOGIN_REQUIRED) && !si->logged_ਵਿੱਚ) {
		ਜੇ (pkcs11_login(k11, CKU_USER) < 0) {
			error("login failed");
			ਵਾਪਸ (-1);
		}
		did_login = 1;
	}

	memset(&ਕੁੰਜੀ_filter, 0, ਆਕਾਰ(ਕੁੰਜੀ_filter));
	ਨਿੱਜੀ_ਕੁੰਜੀ_class = CKO_ਨਿੱਜੀ_ਕੁੰਜੀ;
	ਕੁੰਜੀ_filter[0].type = CKA_CLASS;
	ਕੁੰਜੀ_filter[0].p_ਮੁੱਲ = &ਨਿੱਜੀ_ਕੁੰਜੀ_class;
	ਕੁੰਜੀ_filter[0].ul_ਮੁੱਲ_Len = ਆਕਾਰ(ਨਿੱਜੀ_ਕੁੰਜੀ_class);

	ਕੁੰਜੀ_filter[1].type = CKA_ID;
	ਕੁੰਜੀ_filter[1].p_ਮੁੱਲ = k11->keyid;
	ਕੁੰਜੀ_filter[1].ul_ਮੁੱਲ_Len = k11->keyid_len;

	true_val = CK_TRUE;
	ਕੁੰਜੀ_filter[2].type = CKA_SIGN;
	ਕੁੰਜੀ_filter[2].p_ਮੁੱਲ = &true_val;
	ਕੁੰਜੀ_filter[2].ul_ਮੁੱਲ_Len = ਆਕਾਰ(true_val);

	/* try to find object w/CKA_SIGN first, retry w/o */
	ਜੇ (pkcs11_ਲੱਭੋ(k11->provider, k11->slotidx, ਕੁੰਜੀ_filter, 3, &obj) < 0 &&
	    pkcs11_ਲੱਭੋ(k11->provider, k11->slotidx, ਕੁੰਜੀ_filter, 2, &obj) < 0) {
		error("cannot find private key");
		ਵਾਪਸ (-1);
	}

	memset(&mech, 0, ਆਕਾਰ(mech));
	mech.mechanism = mech_type;
	mech.pParameter = NULL_PTR;
	mech.ulParameterLen = 0;

	ਜੇ ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
		ਵਾਪਸ (-1);
	}

	pkcs11_check_obj_bool_attrib(k11, obj, CKA_ALWAYS_AUTHENTICATE,
	    &always_auth); /* ignore errors here */
	ਜੇ (always_auth && !did_login) {
		debug_f("always-auth key");
		ਜੇ (pkcs11_login(k11, CKU_CONTEXT_SPECIFIC) < 0) {
			error("login failed for always-auth key");
			ਵਾਪਸ (-1);
		}
	}

	ਵਾਪਸ (0);
}

/* record the key information later use lookup by keyblob */
ਸਥਿਰ ਪੂਰਨ
pkcs11_ਰਿਕਾਰਡ_ਕੁੰਜੀ(ਬਣਤਰ pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਬਣਤਰ sshbuf *keyblob;
	ਬਣਤਰ pkcs11_ਕੁੰਜੀ *k11;
	ਪੂਰਨ r;
	ਅੱਖਰ *hex;

	hex = tohex(keyid_attrib->p_ਮੁੱਲ, keyid_attrib->ul_ਮੁੱਲ_Len);
	debug_f("%s key: provider %s slot %lu keyid %s",
	    sshkey_type(ਕੁੰਜੀ), provider->name, (u_long)slotidx, hex);
	ਮੁਕਤ(hex);

	ਜੇ ((keyblob = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshkey_putb(ਕੁੰਜੀ, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");

	/* Check if we've already recorded this key in a different slot */
	TAILQ_FOREACH(k11, &pkcs11_ਕੁੰਜੀਆਂ, ਅਗਲਾ) {
		ਜੇ (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			hex = tohex(k11->keyid, k11->keyid_len);
			debug_f("Already seen this key at "
			    "provider %s slot %lu keyid %s",
			    k11->provider->name, k11->slotidx, hex);
			ਮੁਕਤ(hex);
			sshbuf_free(keyblob);
			ਵਾਪਸ -1;
		}
	}

	k11 = xcalloc(1, ਆਕਾਰ(*k11));
	k11->provider = provider;
	k11->keyblob = keyblob;
	provider->refcount++;	/* provider referenced by RSA key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ul_ਮੁੱਲ_Len;
	ਜੇ (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len);
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(k11->keyid, keyid_attrib->p_ਮੁੱਲ, k11->keyid_len);
	}
	TAILQ_INSERT_TAIL(&pkcs11_ਕੁੰਜੀਆਂ, k11, ਅਗਲਾ);

	ਵਾਪਸ 0;
}

/* retrieve the key information by keyblob */
ਸਥਿਰ ਬਣਤਰ pkcs11_ਕੁੰਜੀ *
pkcs11_lookup_ਕੁੰਜੀ(ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਬਣਤਰ pkcs11_ਕੁੰਜੀ *k11, *ਮਿਲਿਆ = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *keyblob;
	ਪੂਰਨ r;

	ਜੇ ((keyblob = sshbuf_new()) == ਨਿਰਾ)
		fatal_f("sshbuf_new failed");
	ਜੇ ((r = sshkey_putb(ਕੁੰਜੀ, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");
	TAILQ_FOREACH(k11, &pkcs11_ਕੁੰਜੀਆਂ, ਅਗਲਾ) {
		ਜੇ (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			ਮਿਲਿਆ = k11;
			ਰੋਕੋ;
		}
	}
	sshbuf_free(keyblob);
	ਵਾਪਸ ਮਿਲਿਆ;
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
/*
 * See:
 * https://datatracker.ietf.org/doc/html/rfc8017#section-9.2
 */

/*
 * id-sha1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
 *	oiw(14) secsig(3) algorithms(2) 26 }
 */
ਸਥਿਰ ਅਚਲ u_char id_sha1[] = {
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
ਸਥਿਰ ਅਚਲ u_char id_sha256[] = {
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
ਸਥਿਰ ਅਚਲ u_char id_sha512[] = {
	0x30, 0x51, /* type Sequence, length 0x51 (81) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, /* id-sha512 */
	0x05, 0x00, /* NULL */
	0x04, 0x40  /* Octet string, length 0x40 (64), followed by sha512 hash */
};

ਸਥਿਰ ਪੂਰਨ
rsa_hash_alg_oid(ਪੂਰਨ hash_alg, ਅਚਲ u_char **oidp, ਮਾਪ_t *oidlenp)
{
	ਚੋਣ (hash_alg) {
	ਹਾਲਤ SSH_DIGEST_SHA1:
		*oidp = id_sha1;
		*oidlenp = ਆਕਾਰ(id_sha1);
		ਰੋਕੋ;
	ਹਾਲਤ SSH_DIGEST_SHA256:
		*oidp = id_sha256;
		*oidlenp = ਆਕਾਰ(id_sha256);
		ਰੋਕੋ;
	ਹਾਲਤ SSH_DIGEST_SHA512:
		*oidp = id_sha512;
		*oidlenp = ਆਕਾਰ(id_sha512);
		ਰੋਕੋ;
	ਮੂਲ:
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
pkcs11_sign_rsa(ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    u_char **sigp, ਮਾਪ_t *lenp,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen,
    ਅਚਲ ਅੱਖਰ *alg, ਅਚਲ ਅੱਖਰ *sk_provider,
    ਅਚਲ ਅੱਖਰ *sk_pin, u_int compat)
{
	ਬਣਤਰ pkcs11_ਕੁੰਜੀ	*k11;
	ਬਣਤਰ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	ਪੂਰਨ			hashalg, r, diff, siglen, ret = -1;
	u_char			*oid_dgst = ਨਿਰਾ, *sig = ਨਿਰਾ;
	ਮਾਪ_t			dgst_len, oid_len, oid_dgst_len = 0;
	ਅਚਲ u_char		*oid;

	ਜੇ (sigp != ਨਿਰਾ)
		*sigp = ਨਿਰਾ;
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = 0;

	ਜੇ ((k11 = pkcs11_lookup_ਕੁੰਜੀ(ਕੁੰਜੀ)) == ਨਿਰਾ) {
		error_f("no key found");
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ;
	}

	debug3_f("sign with alg \"%s\" using provider %s slotidx %lu",
	    alg == ਨਿਰਾ ? "" : alg, k11->provider->name, (u_long)k11->slotidx);

	ਜੇ (pkcs11_get_ਕੁੰਜੀ(k11, CKM_RSA_PKCS) == -1) {
		error("pkcs11_get_key failed");
		ਵਾਪਸ SSH_ERR_AGENT_FAILURE;
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	ਜੇ ((siglen = EVP_PKEY_ਮਾਪ(ਕੁੰਜੀ->pkey)) <= 0)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* Determine hash algorithm and OID for signature */
	ਜੇ (alg == ਨਿਰਾ || *alg == '\0')
		hashalg = SSH_DIGEST_SHA1;
	ਨਹੀਂਤਾਂ ਜੇ ((hashalg = ssh_rsa_hash_id_from_keyname(alg)) == -1)
		fatal_f("couldn't determine RSA hash alg \"%s\"", alg);
	ਜੇ ((r = rsa_hash_alg_oid(hashalg, &oid, &oid_len)) != 0)
		fatal_fr(r, "rsa_hash_alg_oid failed");
	ਜੇ ((dgst_len = ssh_digest_ਬਾਈਟਾਂ(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);

	/* Prepare { oid || digest } */
	oid_dgst_len = oid_len + dgst_len;
	oid_dgst = xcalloc(1, oid_dgst_len);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(oid_dgst, oid, oid_len);
	ਜੇ ((r = ssh_digest_ਸਮ੍ਰਿਤੀ(hashalg, ਅੰਕੜੇ, datalen,
	    oid_dgst + oid_len, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	ਜੇ ((rv = f->C_Sign(si->session, (CK_BYTE *)oid_dgst,
	    oid_dgst_len, sig, &slen)) != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		ਜਾਓ ਪੂਰਾ;
	}

	ਜੇ (slen < (CK_ULONG)siglen) {
		diff = siglen - slen;
		debug3_f("repack %lu < %d (diff %d)",
		    (u_long)slen, siglen, diff);
		memmove(sig + diff, sig, slen);
		explicit_bzero(sig, diff);
	} ਨਹੀਂਤਾਂ ਜੇ (slen > (ਮਾਪ_t)siglen)
		fatal_f("bad C_Sign length");

	ਜੇ ((ret = ssh_rsa_encode_store_sig(hashalg, sig, siglen,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 ਪੂਰਾ:
	freezero(oid_dgst, oid_dgst_len);
	ਮੁਕਤ(sig);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
pkcs11_sign_ecdsa(ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    u_char **sigp, ਮਾਪ_t *lenp,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen,
    ਅਚਲ ਅੱਖਰ *alg, ਅਚਲ ਅੱਖਰ *sk_provider,
    ਅਚਲ ਅੱਖਰ *sk_pin, u_int compat)
{
	ਬਣਤਰ pkcs11_ਕੁੰਜੀ	*k11;
	ਬਣਤਰ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0, bnlen;
	CK_RV			rv;
	BIGNUM			*sig_r = ਨਿਰਾ, *sig_s = ਨਿਰਾ;
	u_char			*sig = ਨਿਰਾ, *dgst = ਨਿਰਾ;
	ਮਾਪ_t			dgst_len = 0;
	ਪੂਰਨ			hashalg, ret = -1, r, siglen;

	ਜੇ (sigp != ਨਿਰਾ)
		*sigp = ਨਿਰਾ;
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = 0;

	ਜੇ ((k11 = pkcs11_lookup_ਕੁੰਜੀ(ਕੁੰਜੀ)) == ਨਿਰਾ) {
		error_f("no key found");
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ;
	}

	ਜੇ (pkcs11_get_ਕੁੰਜੀ(k11, CKM_ECDSA) == -1) {
		error("pkcs11_get_key failed");
		ਵਾਪਸ SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	/* Prepare digest to be signed */
	ਜੇ ((hashalg = sshkey_ec_nid_ਮੰਜ਼ਿਲ_hash_alg(ਕੁੰਜੀ->ecdsa_nid)) == -1)
		fatal_f("couldn't determine ECDSA hash alg");
	ਜੇ ((dgst_len = ssh_digest_ਬਾਈਟਾਂ(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);
	dgst = xcalloc(1, dgst_len);
	ਜੇ ((r = ssh_digest_ਸਮ੍ਰਿਤੀ(hashalg, ਅੰਕੜੇ, datalen,
	    dgst, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	ਜੇ ((siglen = EVP_PKEY_ਮਾਪ(ਕੁੰਜੀ->pkey)) <= 0)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dgst_len, sig, &slen);
	ਜੇ (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ (slen < 64 || slen > 132 || slen % 2) {
		error_f("bad signature length: %lu", (u_long)slen);
		ਜਾਓ ਪੂਰਾ;
	}
	bnlen = slen/2;
	ਜੇ ((sig_r = BN_bin2bn(sig, bnlen, ਨਿਰਾ)) == ਨਿਰਾ ||
	    (sig_s = BN_bin2bn(sig+bnlen, bnlen, ਨਿਰਾ)) == ਨਿਰਾ) {
		ossl_error("BN_bin2bn failed");
		ਜਾਓ ਪੂਰਾ;
	}

	ਜੇ ((ret = ssh_ecdsa_encode_store_sig(ਕੁੰਜੀ, sig_r, sig_s,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 ਪੂਰਾ:
	freezero(dgst, dgst_len);
	BN_free(sig_r);
	BN_free(sig_s);
	ਮੁਕਤ(sig);
	ਵਾਪਸ ret;
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

ਸਥਿਰ ਪੂਰਨ
pkcs11_sign_ed25519(ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    u_char **sigp, ਮਾਪ_t *lenp,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen,
    ਅਚਲ ਅੱਖਰ *alg, ਅਚਲ ਅੱਖਰ *sk_provider,
    ਅਚਲ ਅੱਖਰ *sk_pin, u_int compat)
{
	ਬਣਤਰ pkcs11_ਕੁੰਜੀ	*k11;
	ਬਣਤਰ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	u_char			*sig = ਨਿਰਾ;
	CK_BYTE			*xdata = ਨਿਰਾ;
	ਪੂਰਨ			ret = -1;

	ਜੇ (sigp != ਨਿਰਾ)
		*sigp = ਨਿਰਾ;
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = 0;

	ਜੇ ((k11 = pkcs11_lookup_ਕੁੰਜੀ(ਕੁੰਜੀ)) == ਨਿਰਾ) {
		error_f("no key found");
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ;
	}

	ਜੇ (pkcs11_get_ਕੁੰਜੀ(k11, CKM_EDDSA) == -1) {
		error("pkcs11_get_key failed");
		ਵਾਪਸ SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	xdata = xmalloc(datalen);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(xdata, ਅੰਕੜੇ, datalen);
	sig = xmalloc(crypto_sign_ed25519_ਬਾਈਟਾਂ);
	slen = crypto_sign_ed25519_ਬਾਈਟਾਂ;

	rv = f->C_Sign(si->session, xdata, datalen, sig, &slen);
	ਜੇ (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ (slen != crypto_sign_ed25519_ਬਾਈਟਾਂ) {
		error_f("bad signature length: %lu", (u_long)slen);
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ ((ret = ssh_ed25519_encode_store_sig(sig, slen, sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 ਪੂਰਾ:
	ਜੇ (xdata != ਨਿਰਾ)
		freezero(xdata, datalen);
	ਮੁਕਤ(sig);
	ਵਾਪਸ ret;
}

/* remove trailing spaces */
ਸਥਿਰ ਅੱਖਰ *
rmspace(u_char *buf, ਮਾਪ_t len)
{
	ਮਾਪ_t i;

	ਜੇ (len == 0)
		ਵਾਪਸ buf;
	ਲਈ (i = len - 1; i > 0; i--)
		ਜੇ (buf[i] == ' ')
			buf[i] = '\0';
		ਨਹੀਂਤਾਂ
			ਰੋਕੋ;
	ਵਾਪਸ buf;
}
/* Used to printf fixed-width, space-padded, unterminated strings using %.*s */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RMSPACE(s) (ਪੂਰਨ)ਆਕਾਰ(s), rmspace(s, ਆਕਾਰ(s))

/*
 * open a pkcs11 session and login if required.
 * if pin == NULL we delay login until key use
 */
ਸਥਿਰ ਪੂਰਨ
pkcs11_open_session(ਬਣਤਰ pkcs11_provider *p, CK_ULONG slotidx, ਅੱਖਰ *pin,
    CK_ULONG user)
{
	ਬਣਤਰ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_RV			rv;
	CK_SESSION_HANDLE	session;
	ਪੂਰਨ			login_required, ret;

	f = p->function_list;
	si = &p->slotinfo[slotidx];

	login_required = si->token.flags & CKF_LOGIN_REQUIRED;

	/* fail early before opening session */
	ਜੇ (login_required && !pkcs11_interactive &&
	    (pin == ਨਿਰਾ || ਲੜੀ_ਲੰਬਾਈ(pin) == 0)) {
		error("pin required");
		ਵਾਪਸ (-SSH_PKCS11_ERR_PIN_REQUIRED);
	}
	ਜੇ ((rv = f->C_OpenSession(p->slotlist[slotidx], CKF_RW_SESSION|
	    CKF_SERIAL_SESSION, ਨਿਰਾ, ਨਿਰਾ, &session)) != CKR_OK) {
		error("C_OpenSession failed: %lu", rv);
		ਵਾਪਸ (-1);
	}
	ਜੇ (login_required && pin != ਨਿਰਾ && ਲੜੀ_ਲੰਬਾਈ(pin) != 0) {
		rv = f->C_Login(session, user, (u_char *)pin, ਲੜੀ_ਲੰਬਾਈ(pin));
		ਜੇ (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_ਵਿੱਚ) {
			error("C_Login failed: %lu", rv);
			ret = (rv == CKR_PIN_LOCKED) ?
			    -SSH_PKCS11_ERR_PIN_LOCKED :
			    -SSH_PKCS11_ERR_LOGIN_FAIL;
			ਜੇ ((rv = f->C_CloseSession(session)) != CKR_OK)
				error("C_CloseSession failed: %lu", rv);
			ਵਾਪਸ (ret);
		}
		si->logged_ਵਿੱਚ = 1;
	}
	si->session = session;
	ਵਾਪਸ (0);
}

ਸਥਿਰ ਪੂਰਨ
pkcs11_ਕੁੰਜੀ_included(ਬਣਤਰ sshkey ***keysp, ਪੂਰਨ *nkeys, ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਪੂਰਨ i;

	ਲਈ (i = 0; i < *nkeys; i++)
		ਜੇ (sshkey_equal(ਕੁੰਜੀ, (*keysp)[i]))
			ਵਾਪਸ (1);
	ਵਾਪਸ (0);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
ਸਥਿਰ ਬਣਤਰ sshkey *
pkcs11_fetch_ecdsa_pubkey(ਬਣਤਰ pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 ਕੁੰਜੀ_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ਨਿਰਾ;
	CK_RV			 rv;
	ASN1_OCTET_STRING	*octet = ਨਿਰਾ;
	EC_ਕੁੰਜੀ			*ec = ਨਿਰਾ;
	EC_ਸਮੂਹ		*ਸਮੂਹ = ਨਿਰਾ;
	ਬਣਤਰ sshkey		*ਕੁੰਜੀ = ਨਿਰਾ;
	ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ	*attrp = ਨਿਰਾ;
	ਪੂਰਨ			 success = -1, r, i, nid;

	memset(&ਕੁੰਜੀ_attr, 0, ਆਕਾਰ(ਕੁੰਜੀ_attr));
	ਕੁੰਜੀ_attr[0].type = CKA_ID;
	ਕੁੰਜੀ_attr[1].type = CKA_EC_ਬਿੰਦੂ;
	ਕੁੰਜੀ_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_ਮੁੱਲ(session, *obj, ਕੁੰਜੀ_attr, 3);
	ਜੇ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ਵਾਪਸ (ਨਿਰਾ);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	ਜੇ (ਕੁੰਜੀ_attr[1].ul_ਮੁੱਲ_Len == 0 ||
	    ਕੁੰਜੀ_attr[2].ul_ਮੁੱਲ_Len == 0) {
		error("invalid attribute length");
		ਵਾਪਸ (ਨਿਰਾ);
	}

	/* allocate buffers for attributes */
	ਲਈ (i = 0; i < 3; i++)
		ਜੇ (ਕੁੰਜੀ_attr[i].ul_ਮੁੱਲ_Len > 0)
			ਕੁੰਜੀ_attr[i].p_ਮੁੱਲ = xcalloc(1, ਕੁੰਜੀ_attr[i].ul_ਮੁੱਲ_Len);

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_ਮੁੱਲ(session, *obj, ਕੁੰਜੀ_attr, 3);
	ਜੇ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ਜਾਓ fail;
	}

	ec = EC_ਕੁੰਜੀ_new();
	ਜੇ (ec == ਨਿਰਾ) {
		error("EC_KEY_new failed");
		ਜਾਓ fail;
	}

	attrp = ਕੁੰਜੀ_attr[2].p_ਮੁੱਲ;
	ਸਮੂਹ = d2i_ECPKParameters(ਨਿਰਾ, &attrp, ਕੁੰਜੀ_attr[2].ul_ਮੁੱਲ_Len);
	ਜੇ (ਸਮੂਹ == ਨਿਰਾ) {
		ossl_error("d2i_ECPKParameters failed");
		ਜਾਓ fail;
	}

	ਜੇ (EC_ਕੁੰਜੀ_ਸੈੱਟ_ਸਮੂਹ(ec, ਸਮੂਹ) == 0) {
		ossl_error("EC_KEY_set_group failed");
		ਜਾਓ fail;
	}

	ਜੇ (ਕੁੰਜੀ_attr[1].ul_ਮੁੱਲ_Len <= 2) {
		error("CKA_EC_POINT too small");
		ਜਾਓ fail;
	}

	attrp = ਕੁੰਜੀ_attr[1].p_ਮੁੱਲ;
	octet = d2i_ASN1_OCTET_STRING(ਨਿਰਾ, &attrp, ਕੁੰਜੀ_attr[1].ul_ਮੁੱਲ_Len);
	ਜੇ (octet == ਨਿਰਾ) {
		ossl_error("d2i_ASN1_OCTET_STRING failed");
		ਜਾਓ fail;
	}
	attrp = ASN1_STRING_get0_ਅੰਕੜੇ(octet);
	ਜੇ (o2i_ECPublic_ਕੁੰਜੀ(&ec, &attrp, ASN1_STRING_ਲੰਮਾਈ(octet)) == ਨਿਰਾ) {
		ossl_error("o2i_ECPublicKey failed");
		ਜਾਓ fail;
	}
	ਜੇ ((r = sshkey_ec_validate_ਜਨਤਕ(EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(ec),
	    EC_ਕੁੰਜੀ_get0_ਜਨਤਕ_ਕੁੰਜੀ(ec))) != 0) {
		error_fr(r, "invalid EC key");
		ਜਾਓ fail;
	}

	nid = sshkey_ecdsa_ਕੁੰਜੀ_ਮੰਜ਼ਿਲ_nid(ec);
	ਜੇ (nid < 0) {
		error("couldn't get curve nid");
		ਜਾਓ fail;
	}

	ਕੁੰਜੀ = sshkey_new(ਕੁੰਜੀ_UNSPEC);
	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ) {
		error("sshkey_new failed");
		ਜਾਓ fail;
	}

	EVP_PKEY_free(ਕੁੰਜੀ->pkey);
	ਜੇ ((ਕੁੰਜੀ->pkey = EVP_PKEY_new()) == ਨਿਰਾ)
		fatal("EVP_PKEY_new failed");
	ਜੇ (EVP_PKEY_set1_EC_ਕੁੰਜੀ(ਕੁੰਜੀ->pkey, ec) != 1)
		fatal("EVP_PKEY_set1_EC_KEY failed");
	ਕੁੰਜੀ->ecdsa_nid = nid;
	ਕੁੰਜੀ->type = ਕੁੰਜੀ_ECDSA;
	ਕੁੰਜੀ->flags |= SSHKEY_FLAG_EXT;
	ਜੇ (pkcs11_ਰਿਕਾਰਡ_ਕੁੰਜੀ(p, slotidx, &ਕੁੰਜੀ_attr[0], ਕੁੰਜੀ))
		ਜਾਓ fail;
	/* success */
	success = 0;
fail:
	ਜੇ (success != 0) {
		sshkey_free(ਕੁੰਜੀ);
		ਕੁੰਜੀ = ਨਿਰਾ;
	}
	ਲਈ (i = 0; i < 3; i++)
		ਮੁਕਤ(ਕੁੰਜੀ_attr[i].p_ਮੁੱਲ);
	ਜੇ (ec)
		EC_ਕੁੰਜੀ_free(ec);
	ਜੇ (ਸਮੂਹ)
		EC_ਸਮੂਹ_free(ਸਮੂਹ);
	ਜੇ (octet)
		ASN1_OCTET_STRING_free(octet);

	ਵਾਪਸ (ਕੁੰਜੀ);
}

ਸਥਿਰ ਬਣਤਰ sshkey *
pkcs11_fetch_rsa_pubkey(ਬਣਤਰ pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 ਕੁੰਜੀ_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ਨਿਰਾ;
	CK_RV			 rv;
	RSA			*rsa = ਨਿਰਾ;
	BIGNUM			*rsa_n, *rsa_e;
	ਬਣਤਰ sshkey		*ਕੁੰਜੀ = ਨਿਰਾ;
	ਪੂਰਨ			 i, success = -1;

	memset(&ਕੁੰਜੀ_attr, 0, ਆਕਾਰ(ਕੁੰਜੀ_attr));
	ਕੁੰਜੀ_attr[0].type = CKA_ID;
	ਕੁੰਜੀ_attr[1].type = CKA_MODULUS;
	ਕੁੰਜੀ_attr[2].type = CKA_ਜਨਤਕ_EXPONENT;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_ਮੁੱਲ(session, *obj, ਕੁੰਜੀ_attr, 3);
	ਜੇ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ਵਾਪਸ (ਨਿਰਾ);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	ਜੇ (ਕੁੰਜੀ_attr[1].ul_ਮੁੱਲ_Len == 0 ||
	    ਕੁੰਜੀ_attr[2].ul_ਮੁੱਲ_Len == 0) {
		error("invalid attribute length");
		ਵਾਪਸ (ਨਿਰਾ);
	}

	/* allocate buffers for attributes */
	ਲਈ (i = 0; i < 3; i++)
		ਜੇ (ਕੁੰਜੀ_attr[i].ul_ਮੁੱਲ_Len > 0)
			ਕੁੰਜੀ_attr[i].p_ਮੁੱਲ = xcalloc(1, ਕੁੰਜੀ_attr[i].ul_ਮੁੱਲ_Len);

	/* retrieve ID, modulus and public exponent of RSA key */
	rv = f->C_Get_Attribute_ਮੁੱਲ(session, *obj, ਕੁੰਜੀ_attr, 3);
	ਜੇ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ਜਾਓ fail;
	}

	rsa = RSA_new();
	ਜੇ (rsa == ਨਿਰਾ) {
		error("RSA_new failed");
		ਜਾਓ fail;
	}

	rsa_n = BN_bin2bn(ਕੁੰਜੀ_attr[1].p_ਮੁੱਲ, ਕੁੰਜੀ_attr[1].ul_ਮੁੱਲ_Len, ਨਿਰਾ);
	rsa_e = BN_bin2bn(ਕੁੰਜੀ_attr[2].p_ਮੁੱਲ, ਕੁੰਜੀ_attr[2].ul_ਮੁੱਲ_Len, ਨਿਰਾ);
	ਜੇ (rsa_n == ਨਿਰਾ || rsa_e == ਨਿਰਾ) {
		error("BN_bin2bn failed");
		ਜਾਓ fail;
	}
	ਜੇ (!RSA_set0_ਕੁੰਜੀ(rsa, rsa_n, rsa_e, ਨਿਰਾ))
		fatal_f("set key");
	rsa_n = rsa_e = ਨਿਰਾ; /* transferred */

	ਕੁੰਜੀ = sshkey_new(ਕੁੰਜੀ_UNSPEC);
	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ) {
		error("sshkey_new failed");
		ਜਾਓ fail;
	}

	EVP_PKEY_free(ਕੁੰਜੀ->pkey);
	ਜੇ ((ਕੁੰਜੀ->pkey = EVP_PKEY_new()) == ਨਿਰਾ)
		fatal("EVP_PKEY_new failed");
	ਜੇ (EVP_PKEY_set1_RSA(ਕੁੰਜੀ->pkey, rsa) != 1)
		fatal("EVP_PKEY_set1_RSA failed");
	ਕੁੰਜੀ->type = ਕੁੰਜੀ_RSA;
	ਕੁੰਜੀ->flags |= SSHKEY_FLAG_EXT;
	ਜੇ (EVP_PKEY_ਬਿੱਟ(ਕੁੰਜੀ->pkey) < SSH_RSA_MINIMUM_MODULUS_ਮਾਪ) {
		error_f("RSA key too small %d < minimum %d",
		    EVP_PKEY_ਬਿੱਟ(ਕੁੰਜੀ->pkey), SSH_RSA_MINIMUM_MODULUS_ਮਾਪ);
		ਜਾਓ fail;
	}
	ਜੇ (pkcs11_ਰਿਕਾਰਡ_ਕੁੰਜੀ(p, slotidx, &ਕੁੰਜੀ_attr[0], ਕੁੰਜੀ))
		ਜਾਓ fail;
	/* success */
	success = 0;
fail:
	ਲਈ (i = 0; i < 3; i++)
		ਮੁਕਤ(ਕੁੰਜੀ_attr[i].p_ਮੁੱਲ);
	RSA_free(rsa);
	ਜੇ (success != 0) {
		sshkey_free(ਕੁੰਜੀ);
		ਕੁੰਜੀ = ਨਿਰਾ;
	}
	ਵਾਪਸ ਕੁੰਜੀ;
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

ਸਥਿਰ ਬਣਤਰ sshkey *
pkcs11_fetch_ed25519_pubkey(ਬਣਤਰ pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 ਕੁੰਜੀ_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ਨਿਰਾ;
	CK_RV			 rv;
	ਬਣਤਰ sshkey		*ਕੁੰਜੀ = ਨਿਰਾ;
	ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ	*d = ਨਿਰਾ;
	ਮਾਪ_t			len;
	ਅੱਖਰ			*hex = ਨਿਰਾ;
	ਪੂਰਨ			 success = -1, i;
	/* https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061180 */
	ਅਚਲ u_char		 id1[14] = {
		0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64,
		0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
	}; /* PrintableString { "edwards25519" } */
	ਅਚਲ u_char		 id2[5] = {
		0x06, 0x03, 0x2b, 0x65, 0x70,
	}; /* OBJECT_IDENTIFIER { 1.3.101.112 } */

	memset(&ਕੁੰਜੀ_attr, 0, ਆਕਾਰ(ਕੁੰਜੀ_attr));
	ਕੁੰਜੀ_attr[0].type = CKA_ID;
	ਕੁੰਜੀ_attr[1].type = CKA_EC_ਬਿੰਦੂ; /* XXX or CKA_VALUE ? */
	ਕੁੰਜੀ_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_ਮੁੱਲ(session, *obj, ਕੁੰਜੀ_attr, 3);
	ਜੇ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ਵਾਪਸ (ਨਿਰਾ);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	ਜੇ (ਕੁੰਜੀ_attr[1].ul_ਮੁੱਲ_Len == 0 ||
	    ਕੁੰਜੀ_attr[2].ul_ਮੁੱਲ_Len == 0) {
		error("invalid attribute length");
		ਵਾਪਸ (ਨਿਰਾ);
	}

	/* allocate buffers for attributes */
	ਲਈ (i = 0; i < 3; i++) {
		ਜੇ (ਕੁੰਜੀ_attr[i].ul_ਮੁੱਲ_Len > 0)
			ਕੁੰਜੀ_attr[i].p_ਮੁੱਲ = xcalloc(1, ਕੁੰਜੀ_attr[i].ul_ਮੁੱਲ_Len);
	}

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_ਮੁੱਲ(session, *obj, ਕੁੰਜੀ_attr, 3);
	ਜੇ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ਜਾਓ fail;
	}

	/* Expect one of the supported identifiers in CKA_EC_PARAMS */
	d = (u_char *)ਕੁੰਜੀ_attr[2].p_ਮੁੱਲ;
	len = ਕੁੰਜੀ_attr[2].ul_ਮੁੱਲ_Len;
	ਜੇ ((len != ਆਕਾਰ(id1) || memcmp(d, id1, ਆਕਾਰ(id1)) != 0) &&
	    (len != ਆਕਾਰ(id2) || memcmp(d, id2, ਆਕਾਰ(id2)) != 0)) {
		hex = tohex(d, len);
		logit_f("unsupported CKA_EC_PARAMS: %s (len %zu)", hex, len);
		ਜਾਓ fail;
	}

	/*
	 * Expect either a raw 32 byte pubkey or an OCTET STRING with
	 * a 32 byte pubkey in CKA_VALUE
	 */
	d = (u_char *)ਕੁੰਜੀ_attr[1].p_ਮੁੱਲ;
	len = ਕੁੰਜੀ_attr[1].ul_ਮੁੱਲ_Len;
	ਜੇ (len == ED25519_PK_SZ + 2 && d[0] == 0x04 && d[1] == ED25519_PK_SZ) {
		d += 2;
		len -= 2;
	}
	ਜੇ (len != ED25519_PK_SZ) {
		hex = tohex(ਕੁੰਜੀ_attr[1].p_ਮੁੱਲ, ਕੁੰਜੀ_attr[1].ul_ਮੁੱਲ_Len);
		logit_f("CKA_EC_POINT invalid octet str: %s (len %lu)",
		    hex, (u_long)ਕੁੰਜੀ_attr[1].ul_ਮੁੱਲ_Len);
		ਜਾਓ fail;
	}

	ਜੇ ((ਕੁੰਜੀ = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ)
		fatal_f("sshkey_new failed");
	ਕੁੰਜੀ->ed25519_pk = xmalloc(ED25519_PK_SZ);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(ਕੁੰਜੀ->ed25519_pk, d, ED25519_PK_SZ);
	ਕੁੰਜੀ->type = ਕੁੰਜੀ_ED25519;
	ਕੁੰਜੀ->flags |= SSHKEY_FLAG_EXT;
	ਜੇ (pkcs11_ਰਿਕਾਰਡ_ਕੁੰਜੀ(p, slotidx, &ਕੁੰਜੀ_attr[0], ਕੁੰਜੀ))
		ਜਾਓ fail;
	/* success */
	success = 0;
 fail:
	ਜੇ (success != 0) {
		sshkey_free(ਕੁੰਜੀ);
		ਕੁੰਜੀ = ਨਿਰਾ;
	}
	ਮੁਕਤ(hex);
	ਲਈ (i = 0; i < 3; i++)
		ਮੁਕਤ(ਕੁੰਜੀ_attr[i].p_ਮੁੱਲ);
	ਵਾਪਸ ਕੁੰਜੀ;
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
ਸਥਿਰ ਪੂਰਨ
pkcs11_fetch_x509_pubkey(ਬਣਤਰ pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj, ਬਣਤਰ sshkey **keyp, ਅੱਖਰ **labelp)
{
	CK_ATTRIBUTE		 cert_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ਨਿਰਾ;
	CK_RV			 rv;
	X509			*x509 = ਨਿਰਾ;
	X509_NAME		*x509_name = ਨਿਰਾ;
	EVP_PKEY		*evp;
	RSA			*rsa = ਨਿਰਾ;
	EC_ਕੁੰਜੀ			*ec = ਨਿਰਾ;
	ਬਣਤਰ sshkey		*ਕੁੰਜੀ = ਨਿਰਾ;
	ਪੂਰਨ			 r, i, nid, success = -1;
	ਅਚਲ u_char		*cp;
	ਅੱਖਰ			*subject = ਨਿਰਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ OPENSSL_HAS_ED25519
	ਮਾਪ_t			len;
#ਜੇ_ਅੰਤ /* OPENSSL_HAS_ED25519 */

	*keyp = ਨਿਰਾ;
	*labelp = ਨਿਰਾ;

	memset(&cert_attr, 0, ਆਕਾਰ(cert_attr));
	cert_attr[0].type = CKA_ID;
	cert_attr[1].type = CKA_SUBJECT;
	cert_attr[2].type = CKA_ਮੁੱਲ;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_ਮੁੱਲ(session, *obj, cert_attr, 3);
	ਜੇ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ਵਾਪਸ -1;
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	ਜੇ (cert_attr[1].ul_ਮੁੱਲ_Len == 0 ||
	    cert_attr[2].ul_ਮੁੱਲ_Len == 0) {
		error("invalid attribute length");
		ਵਾਪਸ -1;
	}

	/* allocate buffers for attributes */
	ਲਈ (i = 0; i < 3; i++)
		ਜੇ (cert_attr[i].ul_ਮੁੱਲ_Len > 0)
			cert_attr[i].p_ਮੁੱਲ = xcalloc(1, cert_attr[i].ul_ਮੁੱਲ_Len);

	/* retrieve ID, subject and value of certificate */
	rv = f->C_Get_Attribute_ਮੁੱਲ(session, *obj, cert_attr, 3);
	ਜੇ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Decode DER-encoded cert subject */
	cp = cert_attr[1].p_ਮੁੱਲ;
	ਜੇ ((x509_name = d2i_X509_NAME(ਨਿਰਾ, &cp,
	    cert_attr[1].ul_ਮੁੱਲ_Len)) == ਨਿਰਾ ||
	    (subject = X509_NAME_oneline(x509_name, ਨਿਰਾ, 0)) == ਨਿਰਾ)
		subject = xstrdup("invalid subject");
	X509_NAME_free(x509_name);

	cp = cert_attr[2].p_ਮੁੱਲ;
	ਜੇ ((x509 = d2i_X509(ਨਿਰਾ, &cp, cert_attr[2].ul_ਮੁੱਲ_Len)) == ਨਿਰਾ) {
		error("d2i_x509 failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((evp = X509_get_pubkey(x509)) == ਨਿਰਾ) {
		error("X509_get_pubkey failed");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (EVP_PKEY_ਅਧਾਰ_id(evp) == EVP_PKEY_RSA) {
		ਜੇ (EVP_PKEY_get0_RSA(evp) == ਨਿਰਾ) {
			error("invalid x509; no rsa key");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((rsa = RSAPublic_ਕੁੰਜੀ_dup(EVP_PKEY_get0_RSA(evp))) == ਨਿਰਾ) {
			error("RSAPublicKey_dup failed");
			ਜਾਓ ਬਾਹਰਲਾ;
		}

		ਕੁੰਜੀ = sshkey_new(ਕੁੰਜੀ_UNSPEC);
		ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ) {
			error("sshkey_new failed");
			ਜਾਓ ਬਾਹਰਲਾ;
		}

		EVP_PKEY_free(ਕੁੰਜੀ->pkey);
		ਜੇ ((ਕੁੰਜੀ->pkey = EVP_PKEY_new()) == ਨਿਰਾ)
			fatal("EVP_PKEY_new failed");
		ਜੇ (EVP_PKEY_set1_RSA(ਕੁੰਜੀ->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		ਕੁੰਜੀ->type = ਕੁੰਜੀ_RSA;
		ਕੁੰਜੀ->flags |= SSHKEY_FLAG_EXT;
		ਜੇ (EVP_PKEY_ਬਿੱਟ(ਕੁੰਜੀ->pkey) < SSH_RSA_MINIMUM_MODULUS_ਮਾਪ) {
			error_f("RSA key too small %d < minimum %d",
			    EVP_PKEY_ਬਿੱਟ(ਕੁੰਜੀ->pkey),
			    SSH_RSA_MINIMUM_MODULUS_ਮਾਪ);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (pkcs11_ਰਿਕਾਰਡ_ਕੁੰਜੀ(p, slotidx, &cert_attr[0], ਕੁੰਜੀ))
			ਜਾਓ ਬਾਹਰਲਾ;
		/* success */
		success = 0;
	} ਨਹੀਂਤਾਂ ਜੇ (EVP_PKEY_ਅਧਾਰ_id(evp) == EVP_PKEY_EC) {
		ਜੇ (EVP_PKEY_get0_EC_ਕੁੰਜੀ(evp) == ਨਿਰਾ) {
			error("invalid x509; no ec key");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((ec = EC_ਕੁੰਜੀ_dup(EVP_PKEY_get0_EC_ਕੁੰਜੀ(evp))) == ਨਿਰਾ) {
			error("EC_KEY_dup failed");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((r = sshkey_ec_validate_ਜਨਤਕ(EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(ec),
		    EC_ਕੁੰਜੀ_get0_ਜਨਤਕ_ਕੁੰਜੀ(ec))) != 0) {
			error_fr(r, "invalid EC key");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		nid = sshkey_ecdsa_ਕੁੰਜੀ_ਮੰਜ਼ਿਲ_nid(ec);
		ਜੇ (nid < 0) {
			error("couldn't get curve nid");
			ਜਾਓ ਬਾਹਰਲਾ;
		}

		ਕੁੰਜੀ = sshkey_new(ਕੁੰਜੀ_UNSPEC);
		ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ) {
			error("sshkey_new failed");
			ਜਾਓ ਬਾਹਰਲਾ;
		}

		EVP_PKEY_free(ਕੁੰਜੀ->pkey);
		ਜੇ ((ਕੁੰਜੀ->pkey = EVP_PKEY_new()) == ਨਿਰਾ)
			fatal("EVP_PKEY_new failed");
		ਜੇ (EVP_PKEY_set1_EC_ਕੁੰਜੀ(ਕੁੰਜੀ->pkey, ec) != 1)
			fatal("EVP_PKEY_set1_EC_KEY failed");
		ਕੁੰਜੀ->ecdsa_nid = nid;
		ਕੁੰਜੀ->type = ਕੁੰਜੀ_ECDSA;
		ਕੁੰਜੀ->flags |= SSHKEY_FLAG_EXT;
		ਜੇ (pkcs11_ਰਿਕਾਰਡ_ਕੁੰਜੀ(p, slotidx, &cert_attr[0], ਕੁੰਜੀ))
			ਜਾਓ ਬਾਹਰਲਾ;
		/* success */
		success = 0;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ OPENSSL_HAS_ED25519
	} ਨਹੀਂਤਾਂ ਜੇ (EVP_PKEY_ਅਧਾਰ_id(evp) == EVP_PKEY_ED25519) {
		ਜੇ ((ਕੁੰਜੀ = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ ||
		    (ਕੁੰਜੀ->ed25519_pk = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ED25519_PK_SZ)) == ਨਿਰਾ)
			fatal_f("allocation failed");
		len = ED25519_PK_SZ;
		ਜੇ (!EVP_PKEY_get_raw_ਜਨਤਕ_ਕੁੰਜੀ(evp, ਕੁੰਜੀ->ed25519_pk, &len)) {
			ossl_error("EVP_PKEY_get_raw_public_key failed");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (len != ED25519_PK_SZ) {
			error_f("incorrect returned public key "
			    "length for ed25519");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਕੁੰਜੀ->type = ਕੁੰਜੀ_ED25519;
		ਕੁੰਜੀ->flags |= SSHKEY_FLAG_EXT;
		ਜੇ (pkcs11_ਰਿਕਾਰਡ_ਕੁੰਜੀ(p, slotidx, &cert_attr[0], ਕੁੰਜੀ))
			ਜਾਓ ਬਾਹਰਲਾ;
		/* success */
		success = 0;
#ਜੇ_ਅੰਤ /* OPENSSL_HAS_ED25519 */
	} ਨਹੀਂਤਾਂ {
		error("unknown certificate key type");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
 ਬਾਹਰਲਾ:
	ਲਈ (i = 0; i < 3; i++)
		ਮੁਕਤ(cert_attr[i].p_ਮੁੱਲ);
	X509_free(x509);
	RSA_free(rsa);
	EC_ਕੁੰਜੀ_free(ec);
	ਜੇ (success != 0 || ਕੁੰਜੀ == ਨਿਰਾ) {
		sshkey_free(ਕੁੰਜੀ);
		ਮੁਕਤ(subject);
		ਵਾਪਸ -1;
	}
	/* success */
	*keyp = ਕੁੰਜੀ;
	*labelp = subject;
	ਵਾਪਸ 0;
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

ਸਥਿਰ ਖਾਲੀ
note_ਕੁੰਜੀ(ਬਣਤਰ pkcs11_provider *p, CK_ULONG slotidx, ਅਚਲ ਅੱਖਰ *context,
    ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਅੱਖਰ *fp;

	ਜੇ ((fp = sshkey_fingerprint(ਕੁੰਜੀ, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ਨਿਰਾ) {
		error_f("sshkey_fingerprint failed");
		ਵਾਪਸ;
	}
	debug2("%s: provider %s slot %lu: %s %s", context, p->name,
	    (u_long)slotidx, sshkey_type(ਕੁੰਜੀ), fp);
	ਮੁਕਤ(fp);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL /* libcrypto needed for certificate parsing */
/*
 * lookup certificates for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
ਸਥਿਰ ਪੂਰਨ
pkcs11_fetch_certs(ਬਣਤਰ pkcs11_provider *p, CK_ULONG slotidx,
    ਬਣਤਰ sshkey ***keysp, ਅੱਖਰ ***labelsp, ਪੂਰਨ *nkeys)
{
	ਬਣਤਰ sshkey		*ਕੁੰਜੀ = ਨਿਰਾ;
	CK_OBJECT_CLASS		 ਕੁੰਜੀ_class;
	CK_ATTRIBUTE		 ਕੁੰਜੀ_attr[1];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ਨਿਰਾ;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	ਪੂਰਨ			 ret = -1;
	ਅੱਖਰ			*label;

	memset(&ਕੁੰਜੀ_attr, 0, ਆਕਾਰ(ਕੁੰਜੀ_attr));
	memset(&obj, 0, ਆਕਾਰ(obj));

	ਕੁੰਜੀ_class = CKO_CERTIFICATE;
	ਕੁੰਜੀ_attr[0].type = CKA_CLASS;
	ਕੁੰਜੀ_attr[0].p_ਮੁੱਲ = &ਕੁੰਜੀ_class;
	ਕੁੰਜੀ_attr[0].ul_ਮੁੱਲ_Len = ਆਕਾਰ(ਕੁੰਜੀ_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_ਲੱਭੋ_Objects_Init(session, ਕੁੰਜੀ_attr, 1);
	ਜੇ (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		ਜਾਓ fail;
	}

	ਜਦੋਂ (1) {
		CK_CERTIFICATE_TYPE	ck_cert_type;

		rv = f->C_ਲੱਭੋ_Objects(session, &obj, 1, &n);
		ਜੇ (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			ਜਾਓ fail;
		}
		ਜੇ (n == 0)
			ਰੋਕੋ;

		memset(&ck_cert_type, 0, ਆਕਾਰ(ck_cert_type));
		memset(&ਕੁੰਜੀ_attr, 0, ਆਕਾਰ(ਕੁੰਜੀ_attr));
		ਕੁੰਜੀ_attr[0].type = CKA_CERTIFICATE_TYPE;
		ਕੁੰਜੀ_attr[0].p_ਮੁੱਲ = &ck_cert_type;
		ਕੁੰਜੀ_attr[0].ul_ਮੁੱਲ_Len = ਆਕਾਰ(ck_cert_type);

		rv = f->C_Get_Attribute_ਮੁੱਲ(session, obj, ਕੁੰਜੀ_attr, 1);
		ਜੇ (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			ਜਾਓ fail;
		}

		ਕੁੰਜੀ = ਨਿਰਾ;
		label = ਨਿਰਾ;
		ਚੋਣ (ck_cert_type) {
		ਹਾਲਤ CKC_X_509:
			ਜੇ (pkcs11_fetch_x509_pubkey(p, slotidx, &obj,
			    &ਕੁੰਜੀ, &label) != 0) {
				debug_f("failed to fetch key");
				ਜਾਰੀ;
			}
			ਰੋਕੋ;
		ਮੂਲ:
			error("skipping unsupported certificate type %lu",
			    ck_cert_type);
			ਜਾਰੀ;
		}
		note_ਕੁੰਜੀ(p, slotidx, __func__, ਕੁੰਜੀ);
		ਜੇ (pkcs11_ਕੁੰਜੀ_included(keysp, nkeys, ਕੁੰਜੀ)) {
			debug2_f("key already included");
			sshkey_free(ਕੁੰਜੀ);
		} ਨਹੀਂਤਾਂ {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, ਆਕਾਰ(ਬਣਤਰ sshkey *));
			(*keysp)[*nkeys] = ਕੁੰਜੀ;
			ਜੇ (labelsp != ਨਿਰਾ) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, ਆਕਾਰ(ਅੱਖਰ *));
				(*labelsp)[*nkeys] = xstrdup((ਅੱਖਰ *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_ਲੱਭੋ_Objects_Final(session);
	ਜੇ (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	ਵਾਪਸ (ret);
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

/*
 * lookup public keys for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
ਸਥਿਰ ਪੂਰਨ
pkcs11_fetch_ਕੁੰਜੀਆਂ(ਬਣਤਰ pkcs11_provider *p, CK_ULONG slotidx,
    ਬਣਤਰ sshkey ***keysp, ਅੱਖਰ ***labelsp, ਪੂਰਨ *nkeys)
{
	ਬਣਤਰ sshkey		*ਕੁੰਜੀ = ਨਿਰਾ;
	CK_OBJECT_CLASS		 ਕੁੰਜੀ_class;
	CK_ATTRIBUTE		 ਕੁੰਜੀ_attr[2];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ਨਿਰਾ;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	ਪੂਰਨ			 ret = -1;

	memset(&ਕੁੰਜੀ_attr, 0, ਆਕਾਰ(ਕੁੰਜੀ_attr));
	memset(&obj, 0, ਆਕਾਰ(obj));

	ਕੁੰਜੀ_class = CKO_ਜਨਤਕ_ਕੁੰਜੀ;
	ਕੁੰਜੀ_attr[0].type = CKA_CLASS;
	ਕੁੰਜੀ_attr[0].p_ਮੁੱਲ = &ਕੁੰਜੀ_class;
	ਕੁੰਜੀ_attr[0].ul_ਮੁੱਲ_Len = ਆਕਾਰ(ਕੁੰਜੀ_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_ਲੱਭੋ_Objects_Init(session, ਕੁੰਜੀ_attr, 1);
	ਜੇ (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		ਜਾਓ fail;
	}

	ਜਦੋਂ (1) {
		CK_ਕੁੰਜੀ_TYPE	ck_ਕੁੰਜੀ_type;
		CK_UTF8CHAR	label[256];

		rv = f->C_ਲੱਭੋ_Objects(session, &obj, 1, &n);
		ਜੇ (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			ਜਾਓ fail;
		}
		ਜੇ (n == 0)
			ਰੋਕੋ;

		memset(&ck_ਕੁੰਜੀ_type, 0, ਆਕਾਰ(ck_ਕੁੰਜੀ_type));
		memset(&ਕੁੰਜੀ_attr, 0, ਆਕਾਰ(ਕੁੰਜੀ_attr));
		ਕੁੰਜੀ_attr[0].type = CKA_ਕੁੰਜੀ_TYPE;
		ਕੁੰਜੀ_attr[0].p_ਮੁੱਲ = &ck_ਕੁੰਜੀ_type;
		ਕੁੰਜੀ_attr[0].ul_ਮੁੱਲ_Len = ਆਕਾਰ(ck_ਕੁੰਜੀ_type);
		ਕੁੰਜੀ_attr[1].type = CKA_LABEL;
		ਕੁੰਜੀ_attr[1].p_ਮੁੱਲ = &label;
		ਕੁੰਜੀ_attr[1].ul_ਮੁੱਲ_Len = ਆਕਾਰ(label) - 1;

		rv = f->C_Get_Attribute_ਮੁੱਲ(session, obj, ਕੁੰਜੀ_attr, 2);
		ਜੇ (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			ਜਾਓ fail;
		}

		label[ਕੁੰਜੀ_attr[1].ul_ਮੁੱਲ_Len] = '\0';

		ਚੋਣ (ck_ਕੁੰਜੀ_type) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
		ਹਾਲਤ CKK_RSA:
			ਕੁੰਜੀ = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			ਰੋਕੋ;
		ਹਾਲਤ CKK_ECDSA:
			ਕੁੰਜੀ = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			ਰੋਕੋ;
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
		ਹਾਲਤ CKK_EC_EDWARDS:
			ਕੁੰਜੀ = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			ਰੋਕੋ;
		ਮੂਲ:
			/* XXX print key type? */
			ਕੁੰਜੀ = ਨਿਰਾ;
			error("skipping unsupported key type 0x%lx",
			    (u_long)ck_ਕੁੰਜੀ_type);
		}

		ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ) {
			debug_f("failed to fetch key");
			ਜਾਰੀ;
		}
		note_ਕੁੰਜੀ(p, slotidx, __func__, ਕੁੰਜੀ);
		ਜੇ (pkcs11_ਕੁੰਜੀ_included(keysp, nkeys, ਕੁੰਜੀ)) {
			debug2_f("key already included");
			sshkey_free(ਕੁੰਜੀ);
		} ਨਹੀਂਤਾਂ {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, ਆਕਾਰ(ਬਣਤਰ sshkey *));
			(*keysp)[*nkeys] = ਕੁੰਜੀ;
			ਜੇ (labelsp != ਨਿਰਾ) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, ਆਕਾਰ(ਅੱਖਰ *));
				(*labelsp)[*nkeys] = xstrdup((ਅੱਖਰ *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_ਲੱਭੋ_Objects_Final(session);
	ਜੇ (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	ਵਾਪਸ (ret);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_PKCS11_KEYGEN
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FILL_ATTR(attr, idx, typ, val, len) \
	{ (attr[idx]).type=(typ); (attr[idx]).p_ਮੁੱਲ=(val); (attr[idx]).ul_ਮੁੱਲ_Len=len; idx++; }

ਸਥਿਰ ਬਣਤਰ sshkey *
pkcs11_rsa_generate_ਨਿੱਜੀ_ਕੁੰਜੀ(ਬਣਤਰ pkcs11_provider *p, CK_ULONG slotidx,
    ਅੱਖਰ *label, CK_ULONG ਬਿੱਟ, CK_BYTE keyid, uint32_t *err)
{
	ਬਣਤਰ pkcs11_slotinfo	*si;
	ਅੱਖਰ			*plabel = label ? label : "";
	ਪੂਰਨ			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_ਕੁੰਜੀ_2, priv_ਕੁੰਜੀ;
	CK_ATTRIBUTE		 tpub[16], tpriv[16];
	CK_MECHANISM		 mech = {
	    CKM_RSA_PKCS_ਕੁੰਜੀ_PAIR_GEN, NULL_PTR, 0
	};
	CK_BYTE			 pubExponent[] = {
	    0x01, 0x00, 0x01 /* RSA_F4 in bytes */
	};
	pubkey_filter[0].p_ਮੁੱਲ = &pubkey_class;
	cert_filter[0].p_ਮੁੱਲ = &cert_class;

	*err = 0;

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, ਆਕਾਰ(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, ਲੜੀ_ਲੰਬਾਈ(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, ਆਕਾਰ(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, ਆਕਾਰ(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    ਆਕਾਰ(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, ਆਕਾਰ(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, ਆਕਾਰ(false_val));
	FILL_ATTR(tpub, npub, CKA_MODULUS_ਬਿੱਟ, &ਬਿੱਟ, ਆਕਾਰ(ਬਿੱਟ));
	FILL_ATTR(tpub, npub, CKA_ਜਨਤਕ_EXPONENT, pubExponent,
	    ਆਕਾਰ(pubExponent));
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, ਆਕਾਰ(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN,  &true_val, ਆਕਾਰ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL,  plabel, ਲੜੀ_ਲੰਬਾਈ(plabel));
	FILL_ATTR(tpriv, npriv, CKA_ਨਿੱਜੀ,  &true_val, ਆਕਾਰ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE,  &true_val, ਆਕਾਰ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT,  &false_val, ਆਕਾਰ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN,  &true_val, ਆਕਾਰ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER,  &false_val,
	    ਆਕਾਰ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP,  &false_val, ਆਕਾਰ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE,  &false_val, ਆਕਾਰ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, ਆਕਾਰ(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	ਜੇ ((rv = f->C_Generate_ਕੁੰਜੀ_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_ਕੁੰਜੀ_2, &priv_ਕੁੰਜੀ)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		ਵਾਪਸ ਨਿਰਾ;
	}

	ਵਾਪਸ pkcs11_fetch_rsa_pubkey(p, slotidx, &pub_ਕੁੰਜੀ_2);
}

ਸਥਿਰ ਪੂਰਨ
h2i(ਅੱਖਰ c)
{
	ਜੇ (c >= '0' && c <= '9')
		ਵਾਪਸ c - '0';
	ਨਹੀਂਤਾਂ ਜੇ (c >= 'a' && c <= 'f')
		ਵਾਪਸ c - 'a' + 10;
	ਨਹੀਂਤਾਂ ਜੇ (c >= 'A' && c <= 'F')
		ਵਾਪਸ c - 'A' + 10;
	ਨਹੀਂਤਾਂ
		ਵਾਪਸ -1;
}

ਸਥਿਰ ਪੂਰਨ
pkcs11_decode_hex(ਅਚਲ ਅੱਖਰ *hex, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ **dest, ਮਾਪ_t *rlen)
{
	ਮਾਪ_t	i, len;

	ਜੇ (dest)
		*dest = ਨਿਰਾ;
	ਜੇ (rlen)
		*rlen = 0;

	ਜੇ ((len = ਲੜੀ_ਲੰਬਾਈ(hex)) % 2)
		ਵਾਪਸ -1;
	len /= 2;

	*dest = xmalloc(len);

	ਲਈ (i = 0; i < len; i++) {
		ਪੂਰਨ hi, lo;

		hi = h2i(hex[2 * i]);
		lo = h2i(hex[(2 * i) + 1]);
		ਜੇ (hi == -1 || lo == -1)
			ਵਾਪਸ -1;
		(*dest)[i] = (hi << 4) | lo;
	}

	ਜੇ (rlen)
		*rlen = len;

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਬਣਤਰ ec_ਵਕਰ_info {
	ਅਚਲ ਅੱਖਰ	*name;
	ਅਚਲ ਅੱਖਰ	*oid;
	ਅਚਲ ਅੱਖਰ	*oid_encoded;
	ਮਾਪ_t		 ਮਾਪ;
} ec_ਵਕਰ_infos[] = {
	{"prime256v1",	"1.2.840.10045.3.1.7",	"06082A8648CE3D030107", 256},
	{"secp384r1",	"1.3.132.0.34",		"06052B81040022",	384},
	{"secp521r1",	"1.3.132.0.35",		"06052B81040023",	521},
	{ਨਿਰਾ,		ਨਿਰਾ,			ਨਿਰਾ,			0},
};

ਸਥਿਰ ਬਣਤਰ sshkey *
pkcs11_ecdsa_generate_ਨਿੱਜੀ_ਕੁੰਜੀ(ਬਣਤਰ pkcs11_provider *p, CK_ULONG slotidx,
    ਅੱਖਰ *label, CK_ULONG ਬਿੱਟ, CK_BYTE keyid, uint32_t *err)
{
	ਬਣਤਰ pkcs11_slotinfo	*si;
	ਅੱਖਰ			*plabel = label ? label : "";
	ਪੂਰਨ			 i;
	ਮਾਪ_t			 ecparams_ਮਾਪ;
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ		*ecparams = ਨਿਰਾ;
	ਪੂਰਨ			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_ਕੁੰਜੀ_2, priv_ਕੁੰਜੀ;
	CK_MECHANISM		 mech = {
	    CKM_EC_ਕੁੰਜੀ_PAIR_GEN, NULL_PTR, 0
	};
	CK_ATTRIBUTE		 tpub[16], tpriv[16];

	*err = 0;

	ਲਈ (i = 0; ec_ਵਕਰ_infos[i].name; i++) {
		ਜੇ (ec_ਵਕਰ_infos[i].ਮਾਪ == ਬਿੱਟ)
			ਰੋਕੋ;
	}
	ਜੇ (!ec_ਵਕਰ_infos[i].name) {
		error_f("invalid key size %lu", ਬਿੱਟ);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ (pkcs11_decode_hex(ec_ਵਕਰ_infos[i].oid_encoded, &ecparams,
	    &ecparams_ਮਾਪ) == -1) {
		error_f("invalid oid");
		ਵਾਪਸ ਨਿਰਾ;
	}

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, ਆਕਾਰ(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, ਲੜੀ_ਲੰਬਾਈ(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, ਆਕਾਰ(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, ਆਕਾਰ(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    ਆਕਾਰ(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, ਆਕਾਰ(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, ਆਕਾਰ(false_val));
	FILL_ATTR(tpub, npub, CKA_EC_PARAMS, ecparams, ecparams_ਮਾਪ);
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, ਆਕਾਰ(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN, &true_val, ਆਕਾਰ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL, plabel, ਲੜੀ_ਲੰਬਾਈ(plabel));
	FILL_ATTR(tpriv, npriv, CKA_ਨਿੱਜੀ, &true_val, ਆਕਾਰ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE, &true_val, ਆਕਾਰ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT, &false_val, ਆਕਾਰ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN, &true_val, ਆਕਾਰ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER, &false_val,
	    ਆਕਾਰ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP, &false_val, ਆਕਾਰ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE, &false_val, ਆਕਾਰ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, ਆਕਾਰ(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	ਜੇ ((rv = f->C_Generate_ਕੁੰਜੀ_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_ਕੁੰਜੀ_2, &priv_ਕੁੰਜੀ)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		ਵਾਪਸ ਨਿਰਾ;
	}

	ਵਾਪਸ pkcs11_fetch_ecdsa_pubkey(p, slotidx, &pub_ਕੁੰਜੀ_2);
}
#ਜੇ_ਅੰਤ /* WITH_PKCS11_KEYGEN */

/*
 * register a new provider, fails if provider already exists. if
 * keyp is provided, fetch keys.
 */
ਸਥਿਰ ਪੂਰਨ
pkcs11_ਰਜਿਸਟਰ_provider(ਅੱਖਰ *provider_id, ਅੱਖਰ *pin,
    ਬਣਤਰ sshkey ***keyp, ਅੱਖਰ ***labelsp,
    ਬਣਤਰ pkcs11_provider **providerp, CK_ULONG user)
{
	ਪੂਰਨ nkeys, need_finalize = 0;
	ਪੂਰਨ ret = -1;
	ਬਣਤਰ pkcs11_provider *p = ਨਿਰਾ;
	ਖਾਲੀ *handle = ਨਿਰਾ;
	CK_RV (*getfunctionlist)(CK_FUNCTION_LIST **);
	CK_RV rv;
	CK_FUNCTION_LIST *f = ਨਿਰਾ;
	CK_TOKEN_INFO *token;
	CK_ULONG i;

	ਜੇ (providerp == ਨਿਰਾ)
		ਜਾਓ fail;
	*providerp = ਨਿਰਾ;

	ਜੇ (keyp != ਨਿਰਾ)
		*keyp = ਨਿਰਾ;
	ਜੇ (labelsp != ਨਿਰਾ)
		*labelsp = ਨਿਰਾ;

	ਜੇ (pkcs11_provider_lookup(provider_id) != ਨਿਰਾ) {
		debug_f("provider already registered: %s", provider_id);
		ਜਾਓ fail;
	}
	ਜੇ (lib_ਸ਼ਾਮਲ_ਹੈ_ਚਿੰਨ੍ਹ(provider_id, "C_GetFunctionList") != 0) {
		error("provider %s is not a PKCS11 library", provider_id);
		ਜਾਓ fail;
	}
	/* open shared pkcs11-library */
	ਜੇ ((handle = dlopen(provider_id, RTLD_NOW)) == ਨਿਰਾ) {
		error("dlopen %s failed: %s", provider_id, dlerror());
		ਜਾਓ fail;
	}
	ਜੇ ((getfunctionlist = dlsym(handle, "C_GetFunctionList")) == ਨਿਰਾ)
		fatal("dlsym(C_GetFunctionList) failed: %s", dlerror());
	p = xcalloc(1, ਆਕਾਰ(*p));
	p->name = xstrdup(provider_id);
	p->handle = handle;
	/* set up the pkcs11 callbacks */
	ਜੇ ((rv = (*getfunctionlist)(&f)) != CKR_OK) {
		error("C_GetFunctionList for provider %s failed: %lu",
		    provider_id, rv);
		ਜਾਓ fail;
	}
	p->function_list = f;
	ਜੇ ((rv = f->C_Initialize(ਨਿਰਾ)) != CKR_OK) {
		error("C_Initialize for provider %s failed: %lu",
		    provider_id, rv);
		ਜਾਓ fail;
	}
	need_finalize = 1;
	ਜੇ ((rv = f->C_GetInfo(&p->info)) != CKR_OK) {
		error("C_GetInfo for provider %s failed: %lu",
		    provider_id, rv);
		ਜਾਓ fail;
	}
	debug("provider %s: manufacturerID <%.*s> cryptokiVersion %d.%d"
	    " libraryDescription <%.*s> libraryVersion %d.%d",
	    provider_id,
	    RMSPACE(p->info.manufacturerID),
	    p->info.cryptoki_ਸੰਸਕਰਣ_2.major,
	    p->info.cryptoki_ਸੰਸਕਰਣ_2.minor,
	    RMSPACE(p->info.libraryDescription),
	    p->info.library_ਸੰਸਕਰਣ_2.major,
	    p->info.library_ਸੰਸਕਰਣ_2.minor);
	ਜੇ ((rv = f->C_Get_ਥਾਂ_List(CK_TRUE, ਨਿਰਾ, &p->nslots)) != CKR_OK) {
		error("C_GetSlotList failed: %lu", rv);
		ਜਾਓ fail;
	}
	ਜੇ (p->nslots == 0) {
		debug_f("provider %s returned no slots", provider_id);
		ret = -SSH_PKCS11_ERR_NO_SLOTS;
		ਜਾਓ fail;
	}
	p->slotlist = xcalloc(p->nslots, ਆਕਾਰ(CK_ਥਾਂ_ID));
	ਜੇ ((rv = f->C_Get_ਥਾਂ_List(CK_TRUE, p->slotlist, &p->nslots))
	    != CKR_OK) {
		error("C_GetSlotList for provider %s failed: %lu",
		    provider_id, rv);
		ਜਾਓ fail;
	}
	p->slotinfo = xcalloc(p->nslots, ਆਕਾਰ(ਬਣਤਰ pkcs11_slotinfo));
	p->valid = 1;
	nkeys = 0;
	ਲਈ (i = 0; i < p->nslots; i++) {
		token = &p->slotinfo[i].token;
		ਜੇ ((rv = f->C_GetTokenInfo(p->slotlist[i], token))
		    != CKR_OK) {
			error("C_GetTokenInfo for provider %s slot %lu "
			    "failed: %lu", provider_id, (u_long)i, rv);
			ਜਾਰੀ;
		}
		ਜੇ ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
			debug2_f("ignoring uninitialised token in "
			    "provider %s slot %lu", provider_id, (u_long)i);
			ਜਾਰੀ;
		}
		debug("provider %s slot %lu: label <%.*s> "
		    "manufacturerID <%.*s> model <%.*s> serial <%.*s> "
		    "flags 0x%lx",
		    provider_id, (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ)i,
		    RMSPACE(token->label), RMSPACE(token->manufacturerID),
		    RMSPACE(token->model), RMSPACE(token->serial_ਸੰਖਿਆ_2),
		    token->flags);
		/*
		 * open session, login with pin and retrieve public
		 * keys (if keyp is provided)
		 */
		ਜੇ ((ret = pkcs11_open_session(p, i, pin, user)) != 0 ||
		    keyp == ਨਿਰਾ)
			ਜਾਰੀ;
		pkcs11_fetch_ਕੁੰਜੀਆਂ(p, i, keyp, labelsp, &nkeys);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
		pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#ਜੇ_ਅੰਤ
		ਜੇ (nkeys == 0 && !p->slotinfo[i].logged_ਵਿੱਚ &&
		    pkcs11_interactive) {
			/*
			 * Some tokens require login before they will
			 * expose keys.
			 */
			ਜੇ (pkcs11_login_ਥਾਂ(p, &p->slotinfo[i],
			    CKU_USER) < 0) {
				error("login failed");
				ਜਾਰੀ;
			}
			pkcs11_fetch_ਕੁੰਜੀਆਂ(p, i, keyp, labelsp, &nkeys);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
			pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#ਜੇ_ਅੰਤ
		}
	}

	/* now owned by caller */
	*providerp = p;

	TAILQ_INSERT_TAIL(&pkcs11_providers, p, ਅਗਲਾ);
	p->refcount++;	/* add to provider list */

	ਵਾਪਸ (nkeys);
fail:
	ਜੇ (need_finalize && (rv = f->C_Finalize(ਨਿਰਾ)) != CKR_OK)
		error("C_Finalize for provider %s failed: %lu",
		    provider_id, rv);
	ਜੇ (p) {
		ਮੁਕਤ(p->name);
		ਮੁਕਤ(p->slotlist);
		ਮੁਕਤ(p->slotinfo);
		ਮੁਕਤ(p);
	}
	ਜੇ (handle)
		dlclose(handle);
	ਜੇ (ret > 0)
		ret = -1;
	ਵਾਪਸ (ret);
}

ਪੂਰਨ
pkcs11_init(ਪੂਰਨ interactive)
{
	debug3_f("called, interactive = %d", interactive);

	pkcs11_interactive = interactive;
	TAILQ_INIT(&pkcs11_providers);
	TAILQ_INIT(&pkcs11_ਕੁੰਜੀਆਂ);
	ਵਾਪਸ (0);
}

/* unregister all providers, keys might still point to the providers */
ਖਾਲੀ
pkcs11_terminate(ਖਾਲੀ)
{
	ਬਣਤਰ pkcs11_provider *p;
	ਬਣਤਰ pkcs11_ਕੁੰਜੀ *k11;

	debug3_f("called");

	ਜਦੋਂ ((k11 = TAILQ_FIRST(&pkcs11_ਕੁੰਜੀਆਂ)) != ਨਿਰਾ) {
		TAILQ_REMOVE(&pkcs11_ਕੁੰਜੀਆਂ, k11, ਅਗਲਾ);
		pkcs11_k11_free(k11);
	}
	ਜਦੋਂ ((p = TAILQ_FIRST(&pkcs11_providers)) != ਨਿਰਾ) {
		TAILQ_REMOVE(&pkcs11_providers, p, ਅਗਲਾ);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
}

/*
 * register a new provider and get number of keys hold by the token,
 * fails if provider already exists
 */
ਪੂਰਨ
pkcs11_ਜੋੜੋ_provider(ਅੱਖਰ *provider_id, ਅੱਖਰ *pin, ਬਣਤਰ sshkey ***keyp,
    ਅੱਖਰ ***labelsp)
{
	ਬਣਤਰ pkcs11_provider *p = ਨਿਰਾ;
	ਪੂਰਨ nkeys;

	nkeys = pkcs11_ਰਜਿਸਟਰ_provider(provider_id, pin, keyp, labelsp,
	    &p, CKU_USER);

	/* no keys found or some other error, de-register provider */
	ਜੇ (nkeys <= 0 && p != ਨਿਰਾ) {
		TAILQ_REMOVE(&pkcs11_providers, p, ਅਗਲਾ);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
	ਜੇ (nkeys == 0)
		debug_f("provider %s returned no keys", provider_id);

	ਵਾਪਸ (nkeys);
}

ਪੂਰਨ
pkcs11_sign(ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    u_char **sigp, ਮਾਪ_t *lenp,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen,
    ਅਚਲ ਅੱਖਰ *alg, ਅਚਲ ਅੱਖਰ *sk_provider,
    ਅਚਲ ਅੱਖਰ *sk_pin, u_int compat)
{
	ਚੋਣ (ਕੁੰਜੀ->type) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਹਾਲਤ ਕੁੰਜੀ_RSA:
	ਹਾਲਤ ਕੁੰਜੀ_RSA_CERT:
		ਵਾਪਸ pkcs11_sign_rsa(ਕੁੰਜੀ, sigp, lenp, ਅੰਕੜੇ, datalen,
		    alg, sk_provider, sk_pin, compat);
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA_CERT:
		ਵਾਪਸ pkcs11_sign_ecdsa(ਕੁੰਜੀ, sigp, lenp, ਅੰਕੜੇ, datalen,
		    alg, sk_provider, sk_pin, compat);
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	ਹਾਲਤ ਕੁੰਜੀ_ED25519:
	ਹਾਲਤ ਕੁੰਜੀ_ED25519_CERT:
		ਵਾਪਸ pkcs11_sign_ed25519(ਕੁੰਜੀ, sigp, lenp, ਅੰਕੜੇ, datalen,
		    alg, sk_provider, sk_pin, compat);
	ਮੂਲ:
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_TYPE_UNKNOWN;
	}
}

ਖਾਲੀ
pkcs11_ਕੁੰਜੀ_free(ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	/* never called */
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_PKCS11_KEYGEN
ਬਣਤਰ sshkey *
pkcs11_gakp(ਅੱਖਰ *provider_id, ਅੱਖਰ *pin, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ slotidx, ਅੱਖਰ *label,
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ type, ਬਿਨਾਨਿਸ਼ਾਨੀ ਪੂਰਨ ਬਿੱਟ, ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ keyid, uint32_t *err)
{
	ਬਣਤਰ pkcs11_provider	*p = ਨਿਰਾ;
	ਬਣਤਰ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	ਬਣਤਰ sshkey		*k = ਨਿਰਾ;
	ਪੂਰਨ			 ret = -1, reset_pin = 0, reset_provider = 0;
	CK_RV			 rv;

	*err = 0;

	ਜੇ ((p = pkcs11_provider_lookup(provider_id)) != ਨਿਰਾ)
		debug_f("provider \"%s\" available", provider_id);
	ਨਹੀਂਤਾਂ ਜੇ ((ret = pkcs11_ਰਜਿਸਟਰ_provider(provider_id, pin, ਨਿਰਾ, ਨਿਰਾ,
	    &p, CKU_SO)) < 0) {
		debug_f("could not register provider %s", provider_id);
		ਜਾਓ ਬਾਹਰਲਾ;
	} ਨਹੀਂਤਾਂ
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	ਜੇ ((rv = f->C_ਸੈੱਟ_Operation_State(session , pin, ਲੜੀ_ਲੰਬਾਈ(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} ਨਹੀਂਤਾਂ
		reset_pin = 1;

	ਚੋਣ (type) {
	ਹਾਲਤ ਕੁੰਜੀ_RSA:
		ਜੇ ((k = pkcs11_rsa_generate_ਨਿੱਜੀ_ਕੁੰਜੀ(p, slotidx, label,
		    ਬਿੱਟ, keyid, err)) == ਨਿਰਾ) {
			debug_f("failed to generate RSA key");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਰੋਕੋ;
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA:
		ਜੇ ((k = pkcs11_ecdsa_generate_ਨਿੱਜੀ_ਕੁੰਜੀ(p, slotidx, label,
		    ਬਿੱਟ, keyid, err)) == ਨਿਰਾ) {
			debug_f("failed to generate ECDSA key");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਰੋਕੋ;
	ਮੂਲ:
		*err = SSH_PKCS11_ERR_GENERIC;
		debug_f("unknown type %d", type);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

ਬਾਹਰਲਾ:
	ਜੇ (reset_pin)
		f->C_ਸੈੱਟ_Operation_State(session , ਨਿਰਾ, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	ਜੇ (reset_provider)
		pkcs11_del_provider(provider_id);

	ਵਾਪਸ (k);
}

ਬਣਤਰ sshkey *
pkcs11_destroy_keypair(ਅੱਖਰ *provider_id, ਅੱਖਰ *pin, ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ slotidx,
    ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ keyid, uint32_t *err)
{
	ਬਣਤਰ pkcs11_provider	*p = ਨਿਰਾ;
	ਬਣਤਰ pkcs11_slotinfo	*si;
	ਬਣਤਰ sshkey		*k = ਨਿਰਾ;
	ਪੂਰਨ			 reset_pin = 0, reset_provider = 0;
	CK_ULONG		 nattrs;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_ATTRIBUTE		 attrs[16];
	CK_OBJECT_CLASS		 ਕੁੰਜੀ_class;
	CK_ਕੁੰਜੀ_TYPE		 ਕੁੰਜੀ_type;
	CK_OBJECT_HANDLE	 obj = CK_INVALID_HANDLE;
	CK_RV			 rv;

	*err = 0;

	ਜੇ ((p = pkcs11_provider_lookup(provider_id)) != ਨਿਰਾ) {
		debug_f("using provider \"%s\"", provider_id);
	} ਨਹੀਂਤਾਂ ਜੇ (pkcs11_ਰਜਿਸਟਰ_provider(provider_id, pin, ਨਿਰਾ, ਨਿਰਾ, &p,
	    CKU_SO) < 0) {
		debug_f("could not register provider %s",
		    provider_id);
		ਜਾਓ ਬਾਹਰਲਾ;
	} ਨਹੀਂਤਾਂ
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	ਜੇ ((rv = f->C_ਸੈੱਟ_Operation_State(session , pin, ਲੜੀ_ਲੰਬਾਈ(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} ਨਹੀਂਤਾਂ
		reset_pin = 1;

	/* private key */
	nattrs = 0;
	ਕੁੰਜੀ_class = CKO_ਨਿੱਜੀ_ਕੁੰਜੀ;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &ਕੁੰਜੀ_class, ਆਕਾਰ(ਕੁੰਜੀ_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, ਆਕਾਰ(keyid));

	ਜੇ (pkcs11_ਲੱਭੋ(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {
		ਜੇ ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy private key 0x%hhx",
			    keyid);
			*err = rv;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}

	/* public key */
	nattrs = 0;
	ਕੁੰਜੀ_class = CKO_ਜਨਤਕ_ਕੁੰਜੀ;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &ਕੁੰਜੀ_class, ਆਕਾਰ(ਕੁੰਜੀ_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, ਆਕਾਰ(keyid));

	ਜੇ (pkcs11_ਲੱਭੋ(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {

		/* get key type */
		nattrs = 0;
		FILL_ATTR(attrs, nattrs, CKA_ਕੁੰਜੀ_TYPE, &ਕੁੰਜੀ_type,
		    ਆਕਾਰ(ਕੁੰਜੀ_type));
		rv = f->C_Get_Attribute_ਮੁੱਲ(session, obj, attrs, nattrs);
		ਜੇ (rv != CKR_OK) {
			debug_f("could not get key type of public key 0x%hhx",
			    keyid);
			*err = rv;
			ਕੁੰਜੀ_type = -1;
		}
		ਚੋਣ (ਕੁੰਜੀ_type) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
		ਹਾਲਤ CKK_RSA:
			k = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			ਰੋਕੋ;
		ਹਾਲਤ CKK_ECDSA:
			k = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			ਰੋਕੋ;
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
		ਹਾਲਤ CKK_EC_EDWARDS:
			k = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			ਰੋਕੋ;
		ਮੂਲ:
			debug_f("unsupported key type %lu", (u_long)ਕੁੰਜੀ_type);
			ਰੋਕੋ;
		}

		ਜੇ ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy public key 0x%hhx", keyid);
			*err = rv;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}

ਬਾਹਰਲਾ:
	ਜੇ (reset_pin)
		f->C_ਸੈੱਟ_Operation_State(session , ਨਿਰਾ, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	ਜੇ (reset_provider)
		pkcs11_del_provider(provider_id);

	ਵਾਪਸ (k);
}
#ਜੇ_ਅੰਤ /* WITH_PKCS11_KEYGEN */
#ਨਹੀਂਤਾਂ /* ENABLE_PKCS11 */

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-pkcs11.h"

ਪੂਰਨ
pkcs11_init(ਪੂਰਨ interactive)
{
	error_f("PKCS#11 not supported");
	ਵਾਪਸ (-1);
}

ਪੂਰਨ
pkcs11_ਜੋੜੋ_provider(ਅੱਖਰ *provider_id, ਅੱਖਰ *pin, ਬਣਤਰ sshkey ***keyp,
    ਅੱਖਰ ***labelsp)
{
	error_f("PKCS#11 not supported");
	ਵਾਪਸ (-1);
}

ਖਾਲੀ
pkcs11_ਕੁੰਜੀ_free(ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	error_f("PKCS#11 not supported");
}

ਪੂਰਨ
pkcs11_sign(ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    u_char **sigp, ਮਾਪ_t *lenp,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen,
    ਅਚਲ ਅੱਖਰ *alg, ਅਚਲ ਅੱਖਰ *sk_provider,
    ਅਚਲ ਅੱਖਰ *sk_pin, u_int compat)
{
	error_f("PKCS#11 not supported");
	ਵਾਪਸ SSH_ERR_FEATURE_UNSUPPORTED;
}

ਖਾਲੀ
pkcs11_terminate(ਖਾਲੀ)
{
	error_f("PKCS#11 not supported");
}
#ਜੇ_ਅੰਤ /* ENABLE_PKCS11 */
