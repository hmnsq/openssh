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

#ifdef ENABLE_PKCS11

#ಅನ್ತರ್ಭಾವ <sys/time.h>

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>

#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <dlfcn.h>

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ecdsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/x509.h>
#ಅನ್ತರ್ಭಾವ <openssl/err.h>
#endif

#define CRYPTOKI_COMPAT
#ಅನ್ತರ್ಭಾವ "pkcs11.h"

#define SSHKEY_INTERNAL
#ಅನ್ತರ್ಭಾವ "sshkey.h"

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssh-pkcs11.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "crypto_api.h"

ಸಂರಚನಾ pkcs11_slotinfo {
	CK_TOKEN_INFO		token;
	CK_SESSION_HANDLE	session;
	ಪೂರ್ಣಾಙ್ಕ			logged_in;
};

ಸಂರಚನಾ pkcs11_provider {
	ವರ್ಣ			*name;
	ಶೂನ್ಯ			*handle;
	CK_FUNCTION_LIST	*function_list;
	CK_INFO			info;
	CK_ULONG		nslots;
	CK_SLOT_ID		*slotlist;
	ಸಂರಚನಾ pkcs11_slotinfo	*slotinfo;
	ಪೂರ್ಣಾಙ್ಕ			valid;
	ಪೂರ್ಣಾಙ್ಕ			refcount;
	TAILQ_ENTRY(pkcs11_provider) next;
};

TAILQ_HEAD(, pkcs11_provider) pkcs11_providers;

ಸಂರಚನಾ pkcs11_ಕೀಲಿ {
	ಸಂರಚನಾ sshbuf		*keyblob;
	ಸಂರಚನಾ pkcs11_provider	*provider;
	CK_ULONG		slotidx;
	ವರ್ಣ			*keyid;
	ಪೂರ್ಣಾಙ್ಕ			keyid_len;
	TAILQ_ENTRY(pkcs11_ಕೀಲಿ)	next;
};

TAILQ_HEAD(, pkcs11_ಕೀಲಿ) pkcs11_ಕೀಲಿಗಳು; /* XXX a tree would be better */

ಪೂರ್ಣಾಙ್ಕ pkcs11_interactive = 0;

#ifdef WITH_OPENSSL
ಸ್ಥಿರ ಶೂನ್ಯ
ossl_error(ಧ್ರುವ ವರ್ಣ *ಸಂದೇಶ)
{
	unsigned long    e;

	error_f("%s", ಸಂದೇಶ);
	ಯಾವತ್ ((e = ERR_get_error()) != 0)
		error_f("libcrypto error: %s", ERR_error_string(e, ರಿಕ್ತ));
}
#endif

/*
 * finalize a provider shared library, it's no longer usable.
 * however, there might still be keys referencing this provider,
 * so the actual freeing of memory is handled by pkcs11_provider_unref().
 * this is called when a provider gets unregistered.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
pkcs11_provider_finalize(ಸಂರಚನಾ pkcs11_provider *p)
{
	CK_RV rv;
	CK_ULONG i;

	debug_f("provider \"%s\" refcount %d valid %d",
	    p->name, p->refcount, p->valid);
	ಯದಿ (!p->valid)
		ಪ್ರತ್ಯಾಗಮ;
	ಪ್ರತಿ (i = 0; i < p->nslots; i++) {
		ಯದಿ (p->slotinfo[i].session &&
		    (rv = p->function_list->C_CloseSession(
		    p->slotinfo[i].session)) != CKR_OK)
			error("C_CloseSession failed: %lu", rv);
	}
	ಯದಿ ((rv = p->function_list->C_Finalize(ರಿಕ್ತ)) != CKR_OK)
		error("C_Finalize failed: %lu", rv);
	p->valid = 0;
	p->function_list = ರಿಕ್ತ;
	dlclose(p->handle);
}

/*
 * remove a reference to the provider.
 * called when a key gets destroyed or when the provider is unregistered.
 */
ಸ್ಥಿರ ಶೂನ್ಯ
pkcs11_provider_unref(ಸಂರಚನಾ pkcs11_provider *p)
{
	debug_f("provider \"%s\" refcount %d", p->name, p->refcount);
	ಯದಿ (--p->refcount <= 0) {
		ಯದಿ (p->valid)
			error_f("provider \"%s\" still valid", p->name);
		ಮುಕ್ತ(p->name);
		ಮುಕ್ತ(p->slotlist);
		ಮುಕ್ತ(p->slotinfo);
		ಮುಕ್ತ(p);
	}
}

/* lookup provider by name */
ಸ್ಥಿರ ಸಂರಚನಾ pkcs11_provider *
pkcs11_provider_lookup(ವರ್ಣ *provider_id)
{
	ಸಂರಚನಾ pkcs11_provider *p;

	TAILQ_FOREACH(p, &pkcs11_providers, next) {
		debug("check provider \"%s\"", p->name);
		ಯದಿ (!strcmp(provider_id, p->name))
			ಪ್ರತ್ಯಾಗಮ (p);
	}
	ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
}

/* unregister provider by name */
ಪೂರ್ಣಾಙ್ಕ
pkcs11_del_provider(ವರ್ಣ *provider_id)
{
	ಸಂರಚನಾ pkcs11_provider *p;

	ಯದಿ ((p = pkcs11_provider_lookup(provider_id)) != ರಿಕ್ತ) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
		ಪ್ರತ್ಯಾಗಮ (0);
	}
	ಪ್ರತ್ಯಾಗಮ (-1);
}

/* release a wrapped object */
ಸ್ಥಿರ ಶೂನ್ಯ
pkcs11_k11_free(ಸಂರಚನಾ pkcs11_ಕೀಲಿ *k11)
{
	ಯದಿ (k11 == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (k11->provider)
		pkcs11_provider_unref(k11->provider);
	ಮುಕ್ತ(k11->keyid);
	sshbuf_free(k11->keyblob);
	ಮುಕ್ತ(k11);
}

/* find a single 'obj' for given attributes */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pkcs11_find(ಸಂರಚನಾ pkcs11_provider *p, CK_ULONG slotidx, CK_ATTRIBUTE *attr,
    CK_ULONG nattr, CK_OBJECT_HANDLE *obj)
{
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	session;
	CK_ULONG		nfound = 0;
	CK_RV			rv;
	ಪೂರ್ಣಾಙ್ಕ			ret = -1;

	f = p->function_list;
	session = p->slotinfo[slotidx].session;
	ಯದಿ ((rv = f->C_FindObjectsInit(session, attr, nattr)) != CKR_OK) {
		error("C_FindObjectsInit failed (nattr %lu): %lu", nattr, rv);
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	ಯದಿ ((rv = f->C_FindObjects(session, obj, 1, &nfound)) != CKR_OK ||
	    nfound != 1) {
		debug("C_FindObjects failed (nfound %lu nattr %lu): %lu",
		    nfound, nattr, rv);
	} ಅನ್ಯಥಾ
		ret = 0;
	ಯದಿ ((rv = f->C_FindObjectsFinal(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	ಪ್ರತ್ಯಾಗಮ (ret);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pkcs11_login_slot(ಸಂರಚನಾ pkcs11_provider *provider, ಸಂರಚನಾ pkcs11_slotinfo *si,
    CK_USER_TYPE type)
{
	ವರ್ಣ			*pin = ರಿಕ್ತ, prompt[1024];
	CK_RV			 rv;

	ಯದಿ (provider == ರಿಕ್ತ || si == ರಿಕ್ತ || !provider->valid) {
		error("no pkcs11 (valid) provider found");
		ಪ್ರತ್ಯಾಗಮ (-1);
	}

	ಯದಿ (!pkcs11_interactive) {
		error("need pin entry%s",
		    (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH) ?
		    " on reader keypad" : "");
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	ಯದಿ (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
		verbose("Deferring PIN entry to reader keypad.");
	ಅನ್ಯಥಾ {
		snprintf(prompt, ಪರಿಮಾಣ(prompt), "Enter PIN for '%s': ",
		    si->token.label);
		ಯದಿ ((pin = read_passphrase(prompt, RP_ALLOW_EOF)) == ರಿಕ್ತ) {
			debug_f("no pin specified");
			ಪ್ರತ್ಯಾಗಮ (-1);	/* bail out */
		}
	}
	rv = provider->function_list->C_Login(si->session, type, (u_char *)pin,
	    (pin != ರಿಕ್ತ) ? strlen(pin) : 0);
	ಯದಿ (pin != ರಿಕ್ತ)
		freezero(pin, strlen(pin));

	ವಿಕಲ್ಪ (rv) {
	ಪಕ್ಷ CKR_OK:
	ಪಕ್ಷ CKR_USER_ALREADY_LOGGED_IN:
		/* success */
		ಭಙ್ಗ;
	ಪಕ್ಷ CKR_PIN_LEN_RANGE:
		error("PKCS#11 login failed: PIN length out of range");
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪಕ್ಷ CKR_PIN_INCORRECT:
		error("PKCS#11 login failed: PIN incorrect");
		ಪ್ರತ್ಯಾಗಮ -1;
	ಪಕ್ಷ CKR_PIN_LOCKED:
		error("PKCS#11 login failed: PIN locked");
		ಪ್ರತ್ಯಾಗಮ -1;
	ಸ್ವಭಾವ:
		error("PKCS#11 login failed: error %lu", rv);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	si->logged_in = 1;
	ಪ್ರತ್ಯಾಗಮ (0);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pkcs11_login(ಸಂರಚನಾ pkcs11_ಕೀಲಿ *k11, CK_USER_TYPE type)
{
	ಯದಿ (k11 == ರಿಕ್ತ || k11->provider == ರಿಕ್ತ || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		ಪ್ರತ್ಯಾಗಮ (-1);
	}

	ಪ್ರತ್ಯಾಗಮ pkcs11_login_slot(k11->provider,
	    &k11->provider->slotinfo[k11->slotidx], type);
}


ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pkcs11_check_obj_bool_attrib(ಸಂರಚನಾ pkcs11_ಕೀಲಿ *k11, CK_OBJECT_HANDLE obj,
    CK_ATTRIBUTE_TYPE type, ಪೂರ್ಣಾಙ್ಕ *val)
{
	ಸಂರಚನಾ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_BBOOL		flag = 0;
	CK_ATTRIBUTE		attr;
	CK_RV			 rv;

	*val = 0;

	ಯದಿ (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		ಪ್ರತ್ಯಾಗಮ (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	attr.type = type;
	attr.p_ಮೌಲ್ಯ = &flag;
	attr.ul_ಮೌಲ್ಯ_Len = ಪರಿಮಾಣ(flag);

	rv = f->C_Get_Attribute_ಮೌಲ್ಯ(si->session, obj, &attr, 1);
	ಯದಿ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	*val = flag != 0;
	debug_f("provider \"%s\" slot %lu object %lu: attrib %lu = %d",
	    k11->provider->name, k11->slotidx, obj, type, *val);
	ಪ್ರತ್ಯಾಗಮ (0);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pkcs11_get_ಕೀಲಿ(ಸಂರಚನಾ pkcs11_ಕೀಲಿ *k11, CK_MECHANISM_TYPE mech_type)
{
	ಸಂರಚನಾ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	 obj;
	CK_RV			 rv;
	CK_OBJECT_CLASS		 private_ಕೀಲಿ_class;
	CK_BBOOL		 true_val;
	CK_MECHANISM		 mech;
	CK_ATTRIBUTE		 ಕೀಲಿ_filter[3];
	ಪೂರ್ಣಾಙ್ಕ			 always_auth = 0;
	ಪೂರ್ಣಾಙ್ಕ			 did_login = 0;

	ಯದಿ (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		ಪ್ರತ್ಯಾಗಮ (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	ಯದಿ ((si->token.flags & CKF_LOGIN_REQUIRED) && !si->logged_in) {
		ಯದಿ (pkcs11_login(k11, CKU_USER) < 0) {
			error("login failed");
			ಪ್ರತ್ಯಾಗಮ (-1);
		}
		did_login = 1;
	}

	memset(&ಕೀಲಿ_filter, 0, ಪರಿಮಾಣ(ಕೀಲಿ_filter));
	private_ಕೀಲಿ_class = CKO_PRIVATE_ಕೀಲಿ;
	ಕೀಲಿ_filter[0].type = CKA_CLASS;
	ಕೀಲಿ_filter[0].p_ಮೌಲ್ಯ = &private_ಕೀಲಿ_class;
	ಕೀಲಿ_filter[0].ul_ಮೌಲ್ಯ_Len = ಪರಿಮಾಣ(private_ಕೀಲಿ_class);

	ಕೀಲಿ_filter[1].type = CKA_ID;
	ಕೀಲಿ_filter[1].p_ಮೌಲ್ಯ = k11->keyid;
	ಕೀಲಿ_filter[1].ul_ಮೌಲ್ಯ_Len = k11->keyid_len;

	true_val = CK_TRUE;
	ಕೀಲಿ_filter[2].type = CKA_SIGN;
	ಕೀಲಿ_filter[2].p_ಮೌಲ್ಯ = &true_val;
	ಕೀಲಿ_filter[2].ul_ಮೌಲ್ಯ_Len = ಪರಿಮಾಣ(true_val);

	/* try to find object w/CKA_SIGN first, retry w/o */
	ಯದಿ (pkcs11_find(k11->provider, k11->slotidx, ಕೀಲಿ_filter, 3, &obj) < 0 &&
	    pkcs11_find(k11->provider, k11->slotidx, ಕೀಲಿ_filter, 2, &obj) < 0) {
		error("cannot find private key");
		ಪ್ರತ್ಯಾಗಮ (-1);
	}

	memset(&mech, 0, ಪರಿಮಾಣ(mech));
	mech.mechanism = mech_type;
	mech.pParameter = NULL_PTR;
	mech.ulParameterLen = 0;

	ಯದಿ ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
		ಪ್ರತ್ಯಾಗಮ (-1);
	}

	pkcs11_check_obj_bool_attrib(k11, obj, CKA_ALWAYS_AUTHENTICATE,
	    &always_auth); /* ignore errors here */
	ಯದಿ (always_auth && !did_login) {
		debug_f("always-auth key");
		ಯದಿ (pkcs11_login(k11, CKU_CONTEXT_SPECIFIC) < 0) {
			error("login failed for always-auth key");
			ಪ್ರತ್ಯಾಗಮ (-1);
		}
	}

	ಪ್ರತ್ಯಾಗಮ (0);
}

/* record the key information later use lookup by keyblob */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pkcs11_record_ಕೀಲಿ(ಸಂರಚನಾ pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಸಂರಚನಾ sshbuf *keyblob;
	ಸಂರಚನಾ pkcs11_ಕೀಲಿ *k11;
	ಪೂರ್ಣಾಙ್ಕ r;
	ವರ್ಣ *hex;

	hex = tohex(keyid_attrib->p_ಮೌಲ್ಯ, keyid_attrib->ul_ಮೌಲ್ಯ_Len);
	debug_f("%s key: provider %s slot %lu keyid %s",
	    sshkey_type(ಕೀಲಿ), provider->name, (u_long)slotidx, hex);
	ಮುಕ್ತ(hex);

	ಯದಿ ((keyblob = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshkey_putb(ಕೀಲಿ, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");

	/* Check if we've already recorded this key in a different slot */
	TAILQ_FOREACH(k11, &pkcs11_ಕೀಲಿಗಳು, next) {
		ಯದಿ (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			hex = tohex(k11->keyid, k11->keyid_len);
			debug_f("Already seen this key at "
			    "provider %s slot %lu keyid %s",
			    k11->provider->name, k11->slotidx, hex);
			ಮುಕ್ತ(hex);
			sshbuf_free(keyblob);
			ಪ್ರತ್ಯಾಗಮ -1;
		}
	}

	k11 = xcalloc(1, ಪರಿಮಾಣ(*k11));
	k11->provider = provider;
	k11->keyblob = keyblob;
	provider->refcount++;	/* provider referenced by RSA key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ul_ಮೌಲ್ಯ_Len;
	ಯದಿ (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len);
		memcpy(k11->keyid, keyid_attrib->p_ಮೌಲ್ಯ, k11->keyid_len);
	}
	TAILQ_INSERT_TAIL(&pkcs11_ಕೀಲಿಗಳು, k11, next);

	ಪ್ರತ್ಯಾಗಮ 0;
}

/* retrieve the key information by keyblob */
ಸ್ಥಿರ ಸಂರಚನಾ pkcs11_ಕೀಲಿ *
pkcs11_lookup_ಕೀಲಿ(ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಸಂರಚನಾ pkcs11_ಕೀಲಿ *k11, *found = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *keyblob;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((keyblob = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಯದಿ ((r = sshkey_putb(ಕೀಲಿ, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");
	TAILQ_FOREACH(k11, &pkcs11_ಕೀಲಿಗಳು, next) {
		ಯದಿ (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			found = k11;
			ಭಙ್ಗ;
		}
	}
	sshbuf_free(keyblob);
	ಪ್ರತ್ಯಾಗಮ found;
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
ಸ್ಥಿರ ಧ್ರುವ u_char id_sha1[] = {
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
ಸ್ಥಿರ ಧ್ರುವ u_char id_sha256[] = {
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
ಸ್ಥಿರ ಧ್ರುವ u_char id_sha512[] = {
	0x30, 0x51, /* type Sequence, length 0x51 (81) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, /* id-sha512 */
	0x05, 0x00, /* NULL */
	0x04, 0x40  /* Octet string, length 0x40 (64), followed by sha512 hash */
};

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
rsa_hash_alg_oid(ಪೂರ್ಣಾಙ್ಕ hash_alg, ಧ್ರುವ u_char **oidp, size_t *oidlenp)
{
	ವಿಕಲ್ಪ (hash_alg) {
	ಪಕ್ಷ SSH_DIGEST_SHA1:
		*oidp = id_sha1;
		*oidlenp = ಪರಿಮಾಣ(id_sha1);
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_DIGEST_SHA256:
		*oidp = id_sha256;
		*oidlenp = ಪರಿಮಾಣ(id_sha256);
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_DIGEST_SHA512:
		*oidp = id_sha512;
		*oidlenp = ಪರಿಮಾಣ(id_sha512);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pkcs11_sign_rsa(ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    u_char **sigp, size_t *lenp,
    ಧ್ರುವ u_char *data, size_t datalen,
    ಧ್ರುವ ವರ್ಣ *alg, ಧ್ರುವ ವರ್ಣ *sk_provider,
    ಧ್ರುವ ವರ್ಣ *sk_pin, u_int compat)
{
	ಸಂರಚನಾ pkcs11_ಕೀಲಿ	*k11;
	ಸಂರಚನಾ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	ಪೂರ್ಣಾಙ್ಕ			hashalg, r, diff, siglen, ret = -1;
	u_char			*oid_dgst = ರಿಕ್ತ, *sig = ರಿಕ್ತ;
	size_t			dgst_len, oid_len, oid_dgst_len = 0;
	ಧ್ರುವ u_char		*oid;

	ಯದಿ (sigp != ರಿಕ್ತ)
		*sigp = ರಿಕ್ತ;
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = 0;

	ಯದಿ ((k11 = pkcs11_lookup_ಕೀಲಿ(ಕೀಲಿ)) == ರಿಕ್ತ) {
		error_f("no key found");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_NOT_FOUND;
	}

	debug3_f("sign with alg \"%s\" using provider %s slotidx %lu",
	    alg == ರಿಕ್ತ ? "" : alg, k11->provider->name, (u_long)k11->slotidx);

	ಯದಿ (pkcs11_get_ಕೀಲಿ(k11, CKM_RSA_PKCS) == -1) {
		error("pkcs11_get_key failed");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_AGENT_FAILURE;
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	ಯದಿ ((siglen = EVP_PKEY_size(ಕೀಲಿ->pkey)) <= 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* Determine hash algorithm and OID for signature */
	ಯದಿ (alg == ರಿಕ್ತ || *alg == '\0')
		hashalg = SSH_DIGEST_SHA1;
	ಅನ್ಯಥಾ ಯದಿ ((hashalg = ssh_rsa_hash_id_from_keyname(alg)) == -1)
		fatal_f("couldn't determine RSA hash alg \"%s\"", alg);
	ಯದಿ ((r = rsa_hash_alg_oid(hashalg, &oid, &oid_len)) != 0)
		fatal_fr(r, "rsa_hash_alg_oid failed");
	ಯದಿ ((dgst_len = ssh_digest_bytes(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);

	/* Prepare { oid || digest } */
	oid_dgst_len = oid_len + dgst_len;
	oid_dgst = xcalloc(1, oid_dgst_len);
	memcpy(oid_dgst, oid, oid_len);
	ಯದಿ ((r = ssh_digest_memory(hashalg, data, datalen,
	    oid_dgst + oid_len, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	ಯದಿ ((rv = f->C_Sign(si->session, (CK_BYTE *)oid_dgst,
	    oid_dgst_len, sig, &slen)) != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		ಗಚ್ಛ done;
	}

	ಯದಿ (slen < (CK_ULONG)siglen) {
		diff = siglen - slen;
		debug3_f("repack %lu < %d (diff %d)",
		    (u_long)slen, siglen, diff);
		memmove(sig + diff, sig, slen);
		explicit_bzero(sig, diff);
	} ಅನ್ಯಥಾ ಯದಿ (slen > (size_t)siglen)
		fatal_f("bad C_Sign length");

	ಯದಿ ((ret = ssh_rsa_encode_store_sig(hashalg, sig, siglen,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	freezero(oid_dgst, oid_dgst_len);
	ಮುಕ್ತ(sig);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pkcs11_sign_ecdsa(ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    u_char **sigp, size_t *lenp,
    ಧ್ರುವ u_char *data, size_t datalen,
    ಧ್ರುವ ವರ್ಣ *alg, ಧ್ರುವ ವರ್ಣ *sk_provider,
    ಧ್ರುವ ವರ್ಣ *sk_pin, u_int compat)
{
	ಸಂರಚನಾ pkcs11_ಕೀಲಿ	*k11;
	ಸಂರಚನಾ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0, bnlen;
	CK_RV			rv;
	BIGNUM			*sig_r = ರಿಕ್ತ, *sig_s = ರಿಕ್ತ;
	u_char			*sig = ರಿಕ್ತ, *dgst = ರಿಕ್ತ;
	size_t			dgst_len = 0;
	ಪೂರ್ಣಾಙ್ಕ			hashalg, ret = -1, r, siglen;

	ಯದಿ (sigp != ರಿಕ್ತ)
		*sigp = ರಿಕ್ತ;
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = 0;

	ಯದಿ ((k11 = pkcs11_lookup_ಕೀಲಿ(ಕೀಲಿ)) == ರಿಕ್ತ) {
		error_f("no key found");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_NOT_FOUND;
	}

	ಯದಿ (pkcs11_get_ಕೀಲಿ(k11, CKM_ECDSA) == -1) {
		error("pkcs11_get_key failed");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	/* Prepare digest to be signed */
	ಯದಿ ((hashalg = sshkey_ec_nid_to_hash_alg(ಕೀಲಿ->ecdsa_nid)) == -1)
		fatal_f("couldn't determine ECDSA hash alg");
	ಯದಿ ((dgst_len = ssh_digest_bytes(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);
	dgst = xcalloc(1, dgst_len);
	ಯದಿ ((r = ssh_digest_memory(hashalg, data, datalen,
	    dgst, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	ಯದಿ ((siglen = EVP_PKEY_size(ಕೀಲಿ->pkey)) <= 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dgst_len, sig, &slen);
	ಯದಿ (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		ಗಚ್ಛ done;
	}
	ಯದಿ (slen < 64 || slen > 132 || slen % 2) {
		error_f("bad signature length: %lu", (u_long)slen);
		ಗಚ್ಛ done;
	}
	bnlen = slen/2;
	ಯದಿ ((sig_r = BN_bin2bn(sig, bnlen, ರಿಕ್ತ)) == ರಿಕ್ತ ||
	    (sig_s = BN_bin2bn(sig+bnlen, bnlen, ರಿಕ್ತ)) == ರಿಕ್ತ) {
		ossl_error("BN_bin2bn failed");
		ಗಚ್ಛ done;
	}

	ಯದಿ ((ret = ssh_ecdsa_encode_store_sig(ಕೀಲಿ, sig_r, sig_s,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	freezero(dgst, dgst_len);
	BN_free(sig_r);
	BN_free(sig_s);
	ಮುಕ್ತ(sig);
	ಪ್ರತ್ಯಾಗಮ ret;
}
#endif /* WITH_OPENSSL */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pkcs11_sign_ed25519(ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    u_char **sigp, size_t *lenp,
    ಧ್ರುವ u_char *data, size_t datalen,
    ಧ್ರುವ ವರ್ಣ *alg, ಧ್ರುವ ವರ್ಣ *sk_provider,
    ಧ್ರುವ ವರ್ಣ *sk_pin, u_int compat)
{
	ಸಂರಚನಾ pkcs11_ಕೀಲಿ	*k11;
	ಸಂರಚನಾ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	u_char			*sig = ರಿಕ್ತ;
	CK_BYTE			*xdata = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ			ret = -1;

	ಯದಿ (sigp != ರಿಕ್ತ)
		*sigp = ರಿಕ್ತ;
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = 0;

	ಯದಿ ((k11 = pkcs11_lookup_ಕೀಲಿ(ಕೀಲಿ)) == ರಿಕ್ತ) {
		error_f("no key found");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_NOT_FOUND;
	}

	ಯದಿ (pkcs11_get_ಕೀಲಿ(k11, CKM_EDDSA) == -1) {
		error("pkcs11_get_key failed");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_AGENT_FAILURE;
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
	ಯದಿ (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		ಗಚ್ಛ done;
	}
	ಯದಿ (slen != crypto_sign_ed25519_BYTES) {
		error_f("bad signature length: %lu", (u_long)slen);
		ಗಚ್ಛ done;
	}
	ಯದಿ ((ret = ssh_ed25519_encode_store_sig(sig, slen, sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	ಯದಿ (xdata != ರಿಕ್ತ)
		freezero(xdata, datalen);
	ಮುಕ್ತ(sig);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/* remove trailing spaces */
ಸ್ಥಿರ ವರ್ಣ *
rmspace(u_char *buf, size_t len)
{
	size_t i;

	ಯದಿ (len == 0)
		ಪ್ರತ್ಯಾಗಮ buf;
	ಪ್ರತಿ (i = len - 1; i > 0; i--)
		ಯದಿ (buf[i] == ' ')
			buf[i] = '\0';
		ಅನ್ಯಥಾ
			ಭಙ್ಗ;
	ಪ್ರತ್ಯಾಗಮ buf;
}
/* Used to printf fixed-width, space-padded, unterminated strings using %.*s */
#define RMSPACE(s) (ಪೂರ್ಣಾಙ್ಕ)ಪರಿಮಾಣ(s), rmspace(s, ಪರಿಮಾಣ(s))

/*
 * open a pkcs11 session and login if required.
 * if pin == NULL we delay login until key use
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pkcs11_open_session(ಸಂರಚನಾ pkcs11_provider *p, CK_ULONG slotidx, ವರ್ಣ *pin,
    CK_ULONG user)
{
	ಸಂರಚನಾ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_RV			rv;
	CK_SESSION_HANDLE	session;
	ಪೂರ್ಣಾಙ್ಕ			login_required, ret;

	f = p->function_list;
	si = &p->slotinfo[slotidx];

	login_required = si->token.flags & CKF_LOGIN_REQUIRED;

	/* fail early before opening session */
	ಯದಿ (login_required && !pkcs11_interactive &&
	    (pin == ರಿಕ್ತ || strlen(pin) == 0)) {
		error("pin required");
		ಪ್ರತ್ಯಾಗಮ (-SSH_PKCS11_ERR_PIN_REQUIRED);
	}
	ಯದಿ ((rv = f->C_OpenSession(p->slotlist[slotidx], CKF_RW_SESSION|
	    CKF_SERIAL_SESSION, ರಿಕ್ತ, ರಿಕ್ತ, &session)) != CKR_OK) {
		error("C_OpenSession failed: %lu", rv);
		ಪ್ರತ್ಯಾಗಮ (-1);
	}
	ಯದಿ (login_required && pin != ರಿಕ್ತ && strlen(pin) != 0) {
		rv = f->C_Login(session, user, (u_char *)pin, strlen(pin));
		ಯದಿ (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
			error("C_Login failed: %lu", rv);
			ret = (rv == CKR_PIN_LOCKED) ?
			    -SSH_PKCS11_ERR_PIN_LOCKED :
			    -SSH_PKCS11_ERR_LOGIN_FAIL;
			ಯದಿ ((rv = f->C_CloseSession(session)) != CKR_OK)
				error("C_CloseSession failed: %lu", rv);
			ಪ್ರತ್ಯಾಗಮ (ret);
		}
		si->logged_in = 1;
	}
	si->session = session;
	ಪ್ರತ್ಯಾಗಮ (0);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pkcs11_ಕೀಲಿ_included(ಸಂರಚನಾ sshkey ***keysp, ಪೂರ್ಣಾಙ್ಕ *nkeys, ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಪ್ರತಿ (i = 0; i < *nkeys; i++)
		ಯದಿ (sshkey_equal(ಕೀಲಿ, (*keysp)[i]))
			ಪ್ರತ್ಯಾಗಮ (1);
	ಪ್ರತ್ಯಾಗಮ (0);
}

#ifdef WITH_OPENSSL
ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
pkcs11_fetch_ecdsa_pubkey(ಸಂರಚನಾ pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 ಕೀಲಿ_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ರಿಕ್ತ;
	CK_RV			 rv;
	ASN1_OCTET_STRING	*octet = ರಿಕ್ತ;
	EC_ಕೀಲಿ			*ec = ರಿಕ್ತ;
	EC_GROUP		*group = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey		*ಕೀಲಿ = ರಿಕ್ತ;
	ಧ್ರುವ unsigned ವರ್ಣ	*attrp = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ			 success = -1, r, i, nid;

	memset(&ಕೀಲಿ_attr, 0, ಪರಿಮಾಣ(ಕೀಲಿ_attr));
	ಕೀಲಿ_attr[0].type = CKA_ID;
	ಕೀಲಿ_attr[1].type = CKA_EC_POINT;
	ಕೀಲಿ_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, *obj, ಕೀಲಿ_attr, 3);
	ಯದಿ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	ಯದಿ (ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len == 0 ||
	    ಕೀಲಿ_attr[2].ul_ಮೌಲ್ಯ_Len == 0) {
		error("invalid attribute length");
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}

	/* allocate buffers for attributes */
	ಪ್ರತಿ (i = 0; i < 3; i++)
		ಯದಿ (ಕೀಲಿ_attr[i].ul_ಮೌಲ್ಯ_Len > 0)
			ಕೀಲಿ_attr[i].p_ಮೌಲ್ಯ = xcalloc(1, ಕೀಲಿ_attr[i].ul_ಮೌಲ್ಯ_Len);

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, *obj, ಕೀಲಿ_attr, 3);
	ಯದಿ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ಗಚ್ಛ fail;
	}

	ec = EC_ಕೀಲಿ_new();
	ಯದಿ (ec == ರಿಕ್ತ) {
		error("EC_KEY_new failed");
		ಗಚ್ಛ fail;
	}

	attrp = ಕೀಲಿ_attr[2].p_ಮೌಲ್ಯ;
	group = d2i_ECPKParameters(ರಿಕ್ತ, &attrp, ಕೀಲಿ_attr[2].ul_ಮೌಲ್ಯ_Len);
	ಯದಿ (group == ರಿಕ್ತ) {
		ossl_error("d2i_ECPKParameters failed");
		ಗಚ್ಛ fail;
	}

	ಯದಿ (EC_ಕೀಲಿ_set_group(ec, group) == 0) {
		ossl_error("EC_KEY_set_group failed");
		ಗಚ್ಛ fail;
	}

	ಯದಿ (ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len <= 2) {
		error("CKA_EC_POINT too small");
		ಗಚ್ಛ fail;
	}

	attrp = ಕೀಲಿ_attr[1].p_ಮೌಲ್ಯ;
	octet = d2i_ASN1_OCTET_STRING(ರಿಕ್ತ, &attrp, ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len);
	ಯದಿ (octet == ರಿಕ್ತ) {
		ossl_error("d2i_ASN1_OCTET_STRING failed");
		ಗಚ್ಛ fail;
	}
	attrp = ASN1_STRING_get0_data(octet);
	ಯದಿ (o2i_ECPublic_ಕೀಲಿ(&ec, &attrp, ASN1_STRING_length(octet)) == ರಿಕ್ತ) {
		ossl_error("o2i_ECPublicKey failed");
		ಗಚ್ಛ fail;
	}
	ಯದಿ ((r = sshkey_ec_validate_public(EC_ಕೀಲಿ_get0_group(ec),
	    EC_ಕೀಲಿ_get0_public_ಕೀಲಿ(ec))) != 0) {
		error_fr(r, "invalid EC key");
		ಗಚ್ಛ fail;
	}

	nid = sshkey_ecdsa_ಕೀಲಿ_to_nid(ec);
	ಯದಿ (nid < 0) {
		error("couldn't get curve nid");
		ಗಚ್ಛ fail;
	}

	ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC);
	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ) {
		error("sshkey_new failed");
		ಗಚ್ಛ fail;
	}

	EVP_PKEY_free(ಕೀಲಿ->pkey);
	ಯದಿ ((ಕೀಲಿ->pkey = EVP_PKEY_new()) == ರಿಕ್ತ)
		fatal("EVP_PKEY_new failed");
	ಯದಿ (EVP_PKEY_set1_EC_ಕೀಲಿ(ಕೀಲಿ->pkey, ec) != 1)
		fatal("EVP_PKEY_set1_EC_KEY failed");
	ಕೀಲಿ->ecdsa_nid = nid;
	ಕೀಲಿ->type = ಕೀಲಿ_ECDSA;
	ಕೀಲಿ->flags |= SSHKEY_FLAG_EXT;
	ಯದಿ (pkcs11_record_ಕೀಲಿ(p, slotidx, &ಕೀಲಿ_attr[0], ಕೀಲಿ))
		ಗಚ್ಛ fail;
	/* success */
	success = 0;
fail:
	ಯದಿ (success != 0) {
		sshkey_free(ಕೀಲಿ);
		ಕೀಲಿ = ರಿಕ್ತ;
	}
	ಪ್ರತಿ (i = 0; i < 3; i++)
		ಮುಕ್ತ(ಕೀಲಿ_attr[i].p_ಮೌಲ್ಯ);
	ಯದಿ (ec)
		EC_ಕೀಲಿ_free(ec);
	ಯದಿ (group)
		EC_GROUP_free(group);
	ಯದಿ (octet)
		ASN1_OCTET_STRING_free(octet);

	ಪ್ರತ್ಯಾಗಮ (ಕೀಲಿ);
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
pkcs11_fetch_rsa_pubkey(ಸಂರಚನಾ pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 ಕೀಲಿ_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ರಿಕ್ತ;
	CK_RV			 rv;
	RSA			*rsa = ರಿಕ್ತ;
	BIGNUM			*rsa_n, *rsa_e;
	ಸಂರಚನಾ sshkey		*ಕೀಲಿ = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ			 i, success = -1;

	memset(&ಕೀಲಿ_attr, 0, ಪರಿಮಾಣ(ಕೀಲಿ_attr));
	ಕೀಲಿ_attr[0].type = CKA_ID;
	ಕೀಲಿ_attr[1].type = CKA_MODULUS;
	ಕೀಲಿ_attr[2].type = CKA_PUBLIC_EXPONENT;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, *obj, ಕೀಲಿ_attr, 3);
	ಯದಿ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	ಯದಿ (ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len == 0 ||
	    ಕೀಲಿ_attr[2].ul_ಮೌಲ್ಯ_Len == 0) {
		error("invalid attribute length");
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}

	/* allocate buffers for attributes */
	ಪ್ರತಿ (i = 0; i < 3; i++)
		ಯದಿ (ಕೀಲಿ_attr[i].ul_ಮೌಲ್ಯ_Len > 0)
			ಕೀಲಿ_attr[i].p_ಮೌಲ್ಯ = xcalloc(1, ಕೀಲಿ_attr[i].ul_ಮೌಲ್ಯ_Len);

	/* retrieve ID, modulus and public exponent of RSA key */
	rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, *obj, ಕೀಲಿ_attr, 3);
	ಯದಿ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ಗಚ್ಛ fail;
	}

	rsa = RSA_new();
	ಯದಿ (rsa == ರಿಕ್ತ) {
		error("RSA_new failed");
		ಗಚ್ಛ fail;
	}

	rsa_n = BN_bin2bn(ಕೀಲಿ_attr[1].p_ಮೌಲ್ಯ, ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len, ರಿಕ್ತ);
	rsa_e = BN_bin2bn(ಕೀಲಿ_attr[2].p_ಮೌಲ್ಯ, ಕೀಲಿ_attr[2].ul_ಮೌಲ್ಯ_Len, ರಿಕ್ತ);
	ಯದಿ (rsa_n == ರಿಕ್ತ || rsa_e == ರಿಕ್ತ) {
		error("BN_bin2bn failed");
		ಗಚ್ಛ fail;
	}
	ಯದಿ (!RSA_set0_ಕೀಲಿ(rsa, rsa_n, rsa_e, ರಿಕ್ತ))
		fatal_f("set key");
	rsa_n = rsa_e = ರಿಕ್ತ; /* transferred */

	ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC);
	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ) {
		error("sshkey_new failed");
		ಗಚ್ಛ fail;
	}

	EVP_PKEY_free(ಕೀಲಿ->pkey);
	ಯದಿ ((ಕೀಲಿ->pkey = EVP_PKEY_new()) == ರಿಕ್ತ)
		fatal("EVP_PKEY_new failed");
	ಯದಿ (EVP_PKEY_set1_RSA(ಕೀಲಿ->pkey, rsa) != 1)
		fatal("EVP_PKEY_set1_RSA failed");
	ಕೀಲಿ->type = ಕೀಲಿ_RSA;
	ಕೀಲಿ->flags |= SSHKEY_FLAG_EXT;
	ಯದಿ (EVP_PKEY_bits(ಕೀಲಿ->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE) {
		error_f("RSA key too small %d < minimum %d",
		    EVP_PKEY_bits(ಕೀಲಿ->pkey), SSH_RSA_MINIMUM_MODULUS_SIZE);
		ಗಚ್ಛ fail;
	}
	ಯದಿ (pkcs11_record_ಕೀಲಿ(p, slotidx, &ಕೀಲಿ_attr[0], ಕೀಲಿ))
		ಗಚ್ಛ fail;
	/* success */
	success = 0;
fail:
	ಪ್ರತಿ (i = 0; i < 3; i++)
		ಮುಕ್ತ(ಕೀಲಿ_attr[i].p_ಮೌಲ್ಯ);
	RSA_free(rsa);
	ಯದಿ (success != 0) {
		sshkey_free(ಕೀಲಿ);
		ಕೀಲಿ = ರಿಕ್ತ;
	}
	ಪ್ರತ್ಯಾಗಮ ಕೀಲಿ;
}
#endif /* WITH_OPENSSL */

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
pkcs11_fetch_ed25519_pubkey(ಸಂರಚನಾ pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 ಕೀಲಿ_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ರಿಕ್ತ;
	CK_RV			 rv;
	ಸಂರಚನಾ sshkey		*ಕೀಲಿ = ರಿಕ್ತ;
	ಧ್ರುವ unsigned ವರ್ಣ	*d = ರಿಕ್ತ;
	size_t			len;
	ವರ್ಣ			*hex = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ			 success = -1, i;
	/* https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061180 */
	ಧ್ರುವ u_char		 id1[14] = {
		0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64,
		0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
	}; /* PrintableString { "edwards25519" } */
	ಧ್ರುವ u_char		 id2[5] = {
		0x06, 0x03, 0x2b, 0x65, 0x70,
	}; /* OBJECT_IDENTIFIER { 1.3.101.112 } */

	memset(&ಕೀಲಿ_attr, 0, ಪರಿಮಾಣ(ಕೀಲಿ_attr));
	ಕೀಲಿ_attr[0].type = CKA_ID;
	ಕೀಲಿ_attr[1].type = CKA_EC_POINT; /* XXX or CKA_VALUE ? */
	ಕೀಲಿ_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, *obj, ಕೀಲಿ_attr, 3);
	ಯದಿ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	ಯದಿ (ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len == 0 ||
	    ಕೀಲಿ_attr[2].ul_ಮೌಲ್ಯ_Len == 0) {
		error("invalid attribute length");
		ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
	}

	/* allocate buffers for attributes */
	ಪ್ರತಿ (i = 0; i < 3; i++) {
		ಯದಿ (ಕೀಲಿ_attr[i].ul_ಮೌಲ್ಯ_Len > 0)
			ಕೀಲಿ_attr[i].p_ಮೌಲ್ಯ = xcalloc(1, ಕೀಲಿ_attr[i].ul_ಮೌಲ್ಯ_Len);
	}

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, *obj, ಕೀಲಿ_attr, 3);
	ಯದಿ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ಗಚ್ಛ fail;
	}

	/* Expect one of the supported identifiers in CKA_EC_PARAMS */
	d = (u_char *)ಕೀಲಿ_attr[2].p_ಮೌಲ್ಯ;
	len = ಕೀಲಿ_attr[2].ul_ಮೌಲ್ಯ_Len;
	ಯದಿ ((len != ಪರಿಮಾಣ(id1) || memcmp(d, id1, ಪರಿಮಾಣ(id1)) != 0) &&
	    (len != ಪರಿಮಾಣ(id2) || memcmp(d, id2, ಪರಿಮಾಣ(id2)) != 0)) {
		hex = tohex(d, len);
		logit_f("unsupported CKA_EC_PARAMS: %s (len %zu)", hex, len);
		ಗಚ್ಛ fail;
	}

	/*
	 * Expect either a raw 32 byte pubkey or an OCTET STRING with
	 * a 32 byte pubkey in CKA_VALUE
	 */
	d = (u_char *)ಕೀಲಿ_attr[1].p_ಮೌಲ್ಯ;
	len = ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len;
	ಯದಿ (len == ED25519_PK_SZ + 2 && d[0] == 0x04 && d[1] == ED25519_PK_SZ) {
		d += 2;
		len -= 2;
	}
	ಯದಿ (len != ED25519_PK_SZ) {
		hex = tohex(ಕೀಲಿ_attr[1].p_ಮೌಲ್ಯ, ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len);
		logit_f("CKA_EC_POINT invalid octet str: %s (len %lu)",
		    hex, (u_long)ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len);
		ಗಚ್ಛ fail;
	}

	ಯದಿ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ)
		fatal_f("sshkey_new failed");
	ಕೀಲಿ->ed25519_pk = xmalloc(ED25519_PK_SZ);
	memcpy(ಕೀಲಿ->ed25519_pk, d, ED25519_PK_SZ);
	ಕೀಲಿ->type = ಕೀಲಿ_ED25519;
	ಕೀಲಿ->flags |= SSHKEY_FLAG_EXT;
	ಯದಿ (pkcs11_record_ಕೀಲಿ(p, slotidx, &ಕೀಲಿ_attr[0], ಕೀಲಿ))
		ಗಚ್ಛ fail;
	/* success */
	success = 0;
 fail:
	ಯದಿ (success != 0) {
		sshkey_free(ಕೀಲಿ);
		ಕೀಲಿ = ರಿಕ್ತ;
	}
	ಮುಕ್ತ(hex);
	ಪ್ರತಿ (i = 0; i < 3; i++)
		ಮುಕ್ತ(ಕೀಲಿ_attr[i].p_ಮೌಲ್ಯ);
	ಪ್ರತ್ಯಾಗಮ ಕೀಲಿ;
}

#ifdef WITH_OPENSSL
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pkcs11_fetch_x509_pubkey(ಸಂರಚನಾ pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj, ಸಂರಚನಾ sshkey **keyp, ವರ್ಣ **labelp)
{
	CK_ATTRIBUTE		 cert_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ರಿಕ್ತ;
	CK_RV			 rv;
	X509			*x509 = ರಿಕ್ತ;
	X509_NAME		*x509_name = ರಿಕ್ತ;
	EVP_PKEY		*evp;
	RSA			*rsa = ರಿಕ್ತ;
	EC_ಕೀಲಿ			*ec = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey		*ಕೀಲಿ = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ			 r, i, nid, success = -1;
	ಧ್ರುವ u_char		*cp;
	ವರ್ಣ			*subject = ರಿಕ್ತ;
#ifdef OPENSSL_HAS_ED25519
	size_t			len;
#endif /* OPENSSL_HAS_ED25519 */

	*keyp = ರಿಕ್ತ;
	*labelp = ರಿಕ್ತ;

	memset(&cert_attr, 0, ಪರಿಮಾಣ(cert_attr));
	cert_attr[0].type = CKA_ID;
	cert_attr[1].type = CKA_SUBJECT;
	cert_attr[2].type = CKA_ಮೌಲ್ಯ;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, *obj, cert_attr, 3);
	ಯದಿ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	ಯದಿ (cert_attr[1].ul_ಮೌಲ್ಯ_Len == 0 ||
	    cert_attr[2].ul_ಮೌಲ್ಯ_Len == 0) {
		error("invalid attribute length");
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	/* allocate buffers for attributes */
	ಪ್ರತಿ (i = 0; i < 3; i++)
		ಯದಿ (cert_attr[i].ul_ಮೌಲ್ಯ_Len > 0)
			cert_attr[i].p_ಮೌಲ್ಯ = xcalloc(1, cert_attr[i].ul_ಮೌಲ್ಯ_Len);

	/* retrieve ID, subject and value of certificate */
	rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, *obj, cert_attr, 3);
	ಯದಿ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ಗಚ್ಛ out;
	}

	/* Decode DER-encoded cert subject */
	cp = cert_attr[1].p_ಮೌಲ್ಯ;
	ಯದಿ ((x509_name = d2i_X509_NAME(ರಿಕ್ತ, &cp,
	    cert_attr[1].ul_ಮೌಲ್ಯ_Len)) == ರಿಕ್ತ ||
	    (subject = X509_NAME_oneline(x509_name, ರಿಕ್ತ, 0)) == ರಿಕ್ತ)
		subject = xstrdup("invalid subject");
	X509_NAME_free(x509_name);

	cp = cert_attr[2].p_ಮೌಲ್ಯ;
	ಯದಿ ((x509 = d2i_X509(ರಿಕ್ತ, &cp, cert_attr[2].ul_ಮೌಲ್ಯ_Len)) == ರಿಕ್ತ) {
		error("d2i_x509 failed");
		ಗಚ್ಛ out;
	}

	ಯದಿ ((evp = X509_get_pubkey(x509)) == ರಿಕ್ತ) {
		error("X509_get_pubkey failed");
		ಗಚ್ಛ out;
	}

	ಯದಿ (EVP_PKEY_base_id(evp) == EVP_PKEY_RSA) {
		ಯದಿ (EVP_PKEY_get0_RSA(evp) == ರಿಕ್ತ) {
			error("invalid x509; no rsa key");
			ಗಚ್ಛ out;
		}
		ಯದಿ ((rsa = RSAPublic_ಕೀಲಿ_dup(EVP_PKEY_get0_RSA(evp))) == ರಿಕ್ತ) {
			error("RSAPublicKey_dup failed");
			ಗಚ್ಛ out;
		}

		ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC);
		ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ) {
			error("sshkey_new failed");
			ಗಚ್ಛ out;
		}

		EVP_PKEY_free(ಕೀಲಿ->pkey);
		ಯದಿ ((ಕೀಲಿ->pkey = EVP_PKEY_new()) == ರಿಕ್ತ)
			fatal("EVP_PKEY_new failed");
		ಯದಿ (EVP_PKEY_set1_RSA(ಕೀಲಿ->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		ಕೀಲಿ->type = ಕೀಲಿ_RSA;
		ಕೀಲಿ->flags |= SSHKEY_FLAG_EXT;
		ಯದಿ (EVP_PKEY_bits(ಕೀಲಿ->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE) {
			error_f("RSA key too small %d < minimum %d",
			    EVP_PKEY_bits(ಕೀಲಿ->pkey),
			    SSH_RSA_MINIMUM_MODULUS_SIZE);
			ಗಚ್ಛ out;
		}
		ಯದಿ (pkcs11_record_ಕೀಲಿ(p, slotidx, &cert_attr[0], ಕೀಲಿ))
			ಗಚ್ಛ out;
		/* success */
		success = 0;
	} ಅನ್ಯಥಾ ಯದಿ (EVP_PKEY_base_id(evp) == EVP_PKEY_EC) {
		ಯದಿ (EVP_PKEY_get0_EC_ಕೀಲಿ(evp) == ರಿಕ್ತ) {
			error("invalid x509; no ec key");
			ಗಚ್ಛ out;
		}
		ಯದಿ ((ec = EC_ಕೀಲಿ_dup(EVP_PKEY_get0_EC_ಕೀಲಿ(evp))) == ರಿಕ್ತ) {
			error("EC_KEY_dup failed");
			ಗಚ್ಛ out;
		}
		ಯದಿ ((r = sshkey_ec_validate_public(EC_ಕೀಲಿ_get0_group(ec),
		    EC_ಕೀಲಿ_get0_public_ಕೀಲಿ(ec))) != 0) {
			error_fr(r, "invalid EC key");
			ಗಚ್ಛ out;
		}
		nid = sshkey_ecdsa_ಕೀಲಿ_to_nid(ec);
		ಯದಿ (nid < 0) {
			error("couldn't get curve nid");
			ಗಚ್ಛ out;
		}

		ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC);
		ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ) {
			error("sshkey_new failed");
			ಗಚ್ಛ out;
		}

		EVP_PKEY_free(ಕೀಲಿ->pkey);
		ಯದಿ ((ಕೀಲಿ->pkey = EVP_PKEY_new()) == ರಿಕ್ತ)
			fatal("EVP_PKEY_new failed");
		ಯದಿ (EVP_PKEY_set1_EC_ಕೀಲಿ(ಕೀಲಿ->pkey, ec) != 1)
			fatal("EVP_PKEY_set1_EC_KEY failed");
		ಕೀಲಿ->ecdsa_nid = nid;
		ಕೀಲಿ->type = ಕೀಲಿ_ECDSA;
		ಕೀಲಿ->flags |= SSHKEY_FLAG_EXT;
		ಯದಿ (pkcs11_record_ಕೀಲಿ(p, slotidx, &cert_attr[0], ಕೀಲಿ))
			ಗಚ್ಛ out;
		/* success */
		success = 0;
#ifdef OPENSSL_HAS_ED25519
	} ಅನ್ಯಥಾ ಯದಿ (EVP_PKEY_base_id(evp) == EVP_PKEY_ED25519) {
		ಯದಿ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ ||
		    (ಕೀಲಿ->ed25519_pk = calloc(1, ED25519_PK_SZ)) == ರಿಕ್ತ)
			fatal_f("allocation failed");
		len = ED25519_PK_SZ;
		ಯದಿ (!EVP_PKEY_get_raw_public_ಕೀಲಿ(evp, ಕೀಲಿ->ed25519_pk, &len)) {
			ossl_error("EVP_PKEY_get_raw_public_key failed");
			ಗಚ್ಛ out;
		}
		ಯದಿ (len != ED25519_PK_SZ) {
			error_f("incorrect returned public key "
			    "length for ed25519");
			ಗಚ್ಛ out;
		}
		ಕೀಲಿ->type = ಕೀಲಿ_ED25519;
		ಕೀಲಿ->flags |= SSHKEY_FLAG_EXT;
		ಯದಿ (pkcs11_record_ಕೀಲಿ(p, slotidx, &cert_attr[0], ಕೀಲಿ))
			ಗಚ್ಛ out;
		/* success */
		success = 0;
#endif /* OPENSSL_HAS_ED25519 */
	} ಅನ್ಯಥಾ {
		error("unknown certificate key type");
		ಗಚ್ಛ out;
	}
 out:
	ಪ್ರತಿ (i = 0; i < 3; i++)
		ಮುಕ್ತ(cert_attr[i].p_ಮೌಲ್ಯ);
	X509_free(x509);
	RSA_free(rsa);
	EC_ಕೀಲಿ_free(ec);
	ಯದಿ (success != 0 || ಕೀಲಿ == ರಿಕ್ತ) {
		sshkey_free(ಕೀಲಿ);
		ಮುಕ್ತ(subject);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	/* success */
	*keyp = ಕೀಲಿ;
	*labelp = subject;
	ಪ್ರತ್ಯಾಗಮ 0;
}
#endif /* WITH_OPENSSL */

ಸ್ಥಿರ ಶೂನ್ಯ
note_ಕೀಲಿ(ಸಂರಚನಾ pkcs11_provider *p, CK_ULONG slotidx, ಧ್ರುವ ವರ್ಣ *context,
    ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ವರ್ಣ *fp;

	ಯದಿ ((fp = sshkey_fingerprint(ಕೀಲಿ, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ರಿಕ್ತ) {
		error_f("sshkey_fingerprint failed");
		ಪ್ರತ್ಯಾಗಮ;
	}
	debug2("%s: provider %s slot %lu: %s %s", context, p->name,
	    (u_long)slotidx, sshkey_type(ಕೀಲಿ), fp);
	ಮುಕ್ತ(fp);
}

#ifdef WITH_OPENSSL /* libcrypto needed for certificate parsing */
/*
 * lookup certificates for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pkcs11_fetch_certs(ಸಂರಚನಾ pkcs11_provider *p, CK_ULONG slotidx,
    ಸಂರಚನಾ sshkey ***keysp, ವರ್ಣ ***labelsp, ಪೂರ್ಣಾಙ್ಕ *nkeys)
{
	ಸಂರಚನಾ sshkey		*ಕೀಲಿ = ರಿಕ್ತ;
	CK_OBJECT_CLASS		 ಕೀಲಿ_class;
	CK_ATTRIBUTE		 ಕೀಲಿ_attr[1];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ರಿಕ್ತ;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	ಪೂರ್ಣಾಙ್ಕ			 ret = -1;
	ವರ್ಣ			*label;

	memset(&ಕೀಲಿ_attr, 0, ಪರಿಮಾಣ(ಕೀಲಿ_attr));
	memset(&obj, 0, ಪರಿಮಾಣ(obj));

	ಕೀಲಿ_class = CKO_CERTIFICATE;
	ಕೀಲಿ_attr[0].type = CKA_CLASS;
	ಕೀಲಿ_attr[0].p_ಮೌಲ್ಯ = &ಕೀಲಿ_class;
	ಕೀಲಿ_attr[0].ul_ಮೌಲ್ಯ_Len = ಪರಿಮಾಣ(ಕೀಲಿ_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, ಕೀಲಿ_attr, 1);
	ಯದಿ (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		ಗಚ್ಛ fail;
	}

	ಯಾವತ್ (1) {
		CK_CERTIFICATE_TYPE	ck_cert_type;

		rv = f->C_FindObjects(session, &obj, 1, &n);
		ಯದಿ (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			ಗಚ್ಛ fail;
		}
		ಯದಿ (n == 0)
			ಭಙ್ಗ;

		memset(&ck_cert_type, 0, ಪರಿಮಾಣ(ck_cert_type));
		memset(&ಕೀಲಿ_attr, 0, ಪರಿಮಾಣ(ಕೀಲಿ_attr));
		ಕೀಲಿ_attr[0].type = CKA_CERTIFICATE_TYPE;
		ಕೀಲಿ_attr[0].p_ಮೌಲ್ಯ = &ck_cert_type;
		ಕೀಲಿ_attr[0].ul_ಮೌಲ್ಯ_Len = ಪರಿಮಾಣ(ck_cert_type);

		rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, obj, ಕೀಲಿ_attr, 1);
		ಯದಿ (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			ಗಚ್ಛ fail;
		}

		ಕೀಲಿ = ರಿಕ್ತ;
		label = ರಿಕ್ತ;
		ವಿಕಲ್ಪ (ck_cert_type) {
		ಪಕ್ಷ CKC_X_509:
			ಯದಿ (pkcs11_fetch_x509_pubkey(p, slotidx, &obj,
			    &ಕೀಲಿ, &label) != 0) {
				debug_f("failed to fetch key");
				ಅನುವರ್ತ;
			}
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			error("skipping unsupported certificate type %lu",
			    ck_cert_type);
			ಅನುವರ್ತ;
		}
		note_ಕೀಲಿ(p, slotidx, __func__, ಕೀಲಿ);
		ಯದಿ (pkcs11_ಕೀಲಿ_included(keysp, nkeys, ಕೀಲಿ)) {
			debug2_f("key already included");
			sshkey_free(ಕೀಲಿ);
		} ಅನ್ಯಥಾ {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, ಪರಿಮಾಣ(ಸಂರಚನಾ sshkey *));
			(*keysp)[*nkeys] = ಕೀಲಿ;
			ಯದಿ (labelsp != ರಿಕ್ತ) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, ಪರಿಮಾಣ(ವರ್ಣ *));
				(*labelsp)[*nkeys] = xstrdup((ವರ್ಣ *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_FindObjectsFinal(session);
	ಯದಿ (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	ಪ್ರತ್ಯಾಗಮ (ret);
}
#endif /* WITH_OPENSSL */

/*
 * lookup public keys for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pkcs11_fetch_ಕೀಲಿಗಳು(ಸಂರಚನಾ pkcs11_provider *p, CK_ULONG slotidx,
    ಸಂರಚನಾ sshkey ***keysp, ವರ್ಣ ***labelsp, ಪೂರ್ಣಾಙ್ಕ *nkeys)
{
	ಸಂರಚನಾ sshkey		*ಕೀಲಿ = ರಿಕ್ತ;
	CK_OBJECT_CLASS		 ಕೀಲಿ_class;
	CK_ATTRIBUTE		 ಕೀಲಿ_attr[2];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ರಿಕ್ತ;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	ಪೂರ್ಣಾಙ್ಕ			 ret = -1;

	memset(&ಕೀಲಿ_attr, 0, ಪರಿಮಾಣ(ಕೀಲಿ_attr));
	memset(&obj, 0, ಪರಿಮಾಣ(obj));

	ಕೀಲಿ_class = CKO_PUBLIC_ಕೀಲಿ;
	ಕೀಲಿ_attr[0].type = CKA_CLASS;
	ಕೀಲಿ_attr[0].p_ಮೌಲ್ಯ = &ಕೀಲಿ_class;
	ಕೀಲಿ_attr[0].ul_ಮೌಲ್ಯ_Len = ಪರಿಮಾಣ(ಕೀಲಿ_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, ಕೀಲಿ_attr, 1);
	ಯದಿ (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		ಗಚ್ಛ fail;
	}

	ಯಾವತ್ (1) {
		CK_ಕೀಲಿ_TYPE	ck_ಕೀಲಿ_type;
		CK_UTF8CHAR	label[256];

		rv = f->C_FindObjects(session, &obj, 1, &n);
		ಯದಿ (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			ಗಚ್ಛ fail;
		}
		ಯದಿ (n == 0)
			ಭಙ್ಗ;

		memset(&ck_ಕೀಲಿ_type, 0, ಪರಿಮಾಣ(ck_ಕೀಲಿ_type));
		memset(&ಕೀಲಿ_attr, 0, ಪರಿಮಾಣ(ಕೀಲಿ_attr));
		ಕೀಲಿ_attr[0].type = CKA_ಕೀಲಿ_TYPE;
		ಕೀಲಿ_attr[0].p_ಮೌಲ್ಯ = &ck_ಕೀಲಿ_type;
		ಕೀಲಿ_attr[0].ul_ಮೌಲ್ಯ_Len = ಪರಿಮಾಣ(ck_ಕೀಲಿ_type);
		ಕೀಲಿ_attr[1].type = CKA_LABEL;
		ಕೀಲಿ_attr[1].p_ಮೌಲ್ಯ = &label;
		ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len = ಪರಿಮಾಣ(label) - 1;

		rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, obj, ಕೀಲಿ_attr, 2);
		ಯದಿ (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			ಗಚ್ಛ fail;
		}

		label[ಕೀಲಿ_attr[1].ul_ಮೌಲ್ಯ_Len] = '\0';

		ವಿಕಲ್ಪ (ck_ಕೀಲಿ_type) {
#ifdef WITH_OPENSSL
		ಪಕ್ಷ CKK_RSA:
			ಕೀಲಿ = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			ಭಙ್ಗ;
		ಪಕ್ಷ CKK_ECDSA:
			ಕೀಲಿ = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			ಭಙ್ಗ;
#endif /* WITH_OPENSSL */
		ಪಕ್ಷ CKK_EC_EDWARDS:
			ಕೀಲಿ = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			/* XXX print key type? */
			ಕೀಲಿ = ರಿಕ್ತ;
			error("skipping unsupported key type 0x%lx",
			    (u_long)ck_ಕೀಲಿ_type);
		}

		ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ) {
			debug_f("failed to fetch key");
			ಅನುವರ್ತ;
		}
		note_ಕೀಲಿ(p, slotidx, __func__, ಕೀಲಿ);
		ಯದಿ (pkcs11_ಕೀಲಿ_included(keysp, nkeys, ಕೀಲಿ)) {
			debug2_f("key already included");
			sshkey_free(ಕೀಲಿ);
		} ಅನ್ಯಥಾ {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, ಪರಿಮಾಣ(ಸಂರಚನಾ sshkey *));
			(*keysp)[*nkeys] = ಕೀಲಿ;
			ಯದಿ (labelsp != ರಿಕ್ತ) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, ಪರಿಮಾಣ(ವರ್ಣ *));
				(*labelsp)[*nkeys] = xstrdup((ವರ್ಣ *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_FindObjectsFinal(session);
	ಯದಿ (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	ಪ್ರತ್ಯಾಗಮ (ret);
}

#ifdef WITH_PKCS11_KEYGEN
#define FILL_ATTR(attr, idx, typ, val, len) \
	{ (attr[idx]).type=(typ); (attr[idx]).p_ಮೌಲ್ಯ=(val); (attr[idx]).ul_ಮೌಲ್ಯ_Len=len; idx++; }

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
pkcs11_rsa_generate_private_ಕೀಲಿ(ಸಂರಚನಾ pkcs11_provider *p, CK_ULONG slotidx,
    ವರ್ಣ *label, CK_ULONG bits, CK_BYTE keyid, uint32_t *err)
{
	ಸಂರಚನಾ pkcs11_slotinfo	*si;
	ವರ್ಣ			*plabel = label ? label : "";
	ಪೂರ್ಣಾಙ್ಕ			 npub = 0, npriv = 0;
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

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, ಪರಿಮಾಣ(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, ಪರಿಮಾಣ(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, ಪರಿಮಾಣ(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    ಪರಿಮಾಣ(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, ಪರಿಮಾಣ(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, ಪರಿಮಾಣ(false_val));
	FILL_ATTR(tpub, npub, CKA_MODULUS_BITS, &bits, ಪರಿಮಾಣ(bits));
	FILL_ATTR(tpub, npub, CKA_PUBLIC_EXPONENT, pubExponent,
	    ಪರಿಮಾಣ(pubExponent));
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, ಪರಿಮಾಣ(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN,  &true_val, ಪರಿಮಾಣ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL,  plabel, strlen(plabel));
	FILL_ATTR(tpriv, npriv, CKA_PRIVATE,  &true_val, ಪರಿಮಾಣ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE,  &true_val, ಪರಿಮಾಣ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT,  &false_val, ಪರಿಮಾಣ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN,  &true_val, ಪರಿಮಾಣ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER,  &false_val,
	    ಪರಿಮಾಣ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP,  &false_val, ಪರಿಮಾಣ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE,  &false_val, ಪರಿಮಾಣ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, ಪರಿಮಾಣ(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	ಯದಿ ((rv = f->C_Generate_ಕೀಲಿ_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_ಕೀಲಿ_2, &priv_ಕೀಲಿ)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}

	ಪ್ರತ್ಯಾಗಮ pkcs11_fetch_rsa_pubkey(p, slotidx, &pub_ಕೀಲಿ_2);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
h2i(ವರ್ಣ c)
{
	ಯದಿ (c >= '0' && c <= '9')
		ಪ್ರತ್ಯಾಗಮ c - '0';
	ಅನ್ಯಥಾ ಯದಿ (c >= 'a' && c <= 'f')
		ಪ್ರತ್ಯಾಗಮ c - 'a' + 10;
	ಅನ್ಯಥಾ ಯದಿ (c >= 'A' && c <= 'F')
		ಪ್ರತ್ಯಾಗಮ c - 'A' + 10;
	ಅನ್ಯಥಾ
		ಪ್ರತ್ಯಾಗಮ -1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pkcs11_decode_hex(ಧ್ರುವ ವರ್ಣ *hex, unsigned ವರ್ಣ **dest, size_t *rlen)
{
	size_t	i, len;

	ಯದಿ (dest)
		*dest = ರಿಕ್ತ;
	ಯದಿ (rlen)
		*rlen = 0;

	ಯದಿ ((len = strlen(hex)) % 2)
		ಪ್ರತ್ಯಾಗಮ -1;
	len /= 2;

	*dest = xmalloc(len);

	ಪ್ರತಿ (i = 0; i < len; i++) {
		ಪೂರ್ಣಾಙ್ಕ hi, lo;

		hi = h2i(hex[2 * i]);
		lo = h2i(hex[(2 * i) + 1]);
		ಯದಿ (hi == -1 || lo == -1)
			ಪ್ರತ್ಯಾಗಮ -1;
		(*dest)[i] = (hi << 4) | lo;
	}

	ಯದಿ (rlen)
		*rlen = len;

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಸಂರಚನಾ ec_curve_info {
	ಧ್ರುವ ವರ್ಣ	*name;
	ಧ್ರುವ ವರ್ಣ	*oid;
	ಧ್ರುವ ವರ್ಣ	*oid_encoded;
	size_t		 size;
} ec_curve_infos[] = {
	{"prime256v1",	"1.2.840.10045.3.1.7",	"06082A8648CE3D030107", 256},
	{"secp384r1",	"1.3.132.0.34",		"06052B81040022",	384},
	{"secp521r1",	"1.3.132.0.35",		"06052B81040023",	521},
	{ರಿಕ್ತ,		ರಿಕ್ತ,			ರಿಕ್ತ,			0},
};

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
pkcs11_ecdsa_generate_private_ಕೀಲಿ(ಸಂರಚನಾ pkcs11_provider *p, CK_ULONG slotidx,
    ವರ್ಣ *label, CK_ULONG bits, CK_BYTE keyid, uint32_t *err)
{
	ಸಂರಚನಾ pkcs11_slotinfo	*si;
	ವರ್ಣ			*plabel = label ? label : "";
	ಪೂರ್ಣಾಙ್ಕ			 i;
	size_t			 ecparams_size;
	unsigned ವರ್ಣ		*ecparams = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ			 npub = 0, npriv = 0;
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

	ಪ್ರತಿ (i = 0; ec_curve_infos[i].name; i++) {
		ಯದಿ (ec_curve_infos[i].size == bits)
			ಭಙ್ಗ;
	}
	ಯದಿ (!ec_curve_infos[i].name) {
		error_f("invalid key size %lu", bits);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ (pkcs11_decode_hex(ec_curve_infos[i].oid_encoded, &ecparams,
	    &ecparams_size) == -1) {
		error_f("invalid oid");
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, ಪರಿಮಾಣ(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, ಪರಿಮಾಣ(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, ಪರಿಮಾಣ(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    ಪರಿಮಾಣ(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, ಪರಿಮಾಣ(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, ಪರಿಮಾಣ(false_val));
	FILL_ATTR(tpub, npub, CKA_EC_PARAMS, ecparams, ecparams_size);
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, ಪರಿಮಾಣ(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN, &true_val, ಪರಿಮಾಣ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpriv, npriv, CKA_PRIVATE, &true_val, ಪರಿಮಾಣ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE, &true_val, ಪರಿಮಾಣ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT, &false_val, ಪರಿಮಾಣ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN, &true_val, ಪರಿಮಾಣ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER, &false_val,
	    ಪರಿಮಾಣ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP, &false_val, ಪರಿಮಾಣ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE, &false_val, ಪರಿಮಾಣ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, ಪರಿಮಾಣ(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	ಯದಿ ((rv = f->C_Generate_ಕೀಲಿ_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_ಕೀಲಿ_2, &priv_ಕೀಲಿ)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}

	ಪ್ರತ್ಯಾಗಮ pkcs11_fetch_ecdsa_pubkey(p, slotidx, &pub_ಕೀಲಿ_2);
}
#endif /* WITH_PKCS11_KEYGEN */

/*
 * register a new provider, fails if provider already exists. if
 * keyp is provided, fetch keys.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
pkcs11_register_provider(ವರ್ಣ *provider_id, ವರ್ಣ *pin,
    ಸಂರಚನಾ sshkey ***keyp, ವರ್ಣ ***labelsp,
    ಸಂರಚನಾ pkcs11_provider **providerp, CK_ULONG user)
{
	ಪೂರ್ಣಾಙ್ಕ nkeys, need_finalize = 0;
	ಪೂರ್ಣಾಙ್ಕ ret = -1;
	ಸಂರಚನಾ pkcs11_provider *p = ರಿಕ್ತ;
	ಶೂನ್ಯ *handle = ರಿಕ್ತ;
	CK_RV (*getfunctionlist)(CK_FUNCTION_LIST **);
	CK_RV rv;
	CK_FUNCTION_LIST *f = ರಿಕ್ತ;
	CK_TOKEN_INFO *token;
	CK_ULONG i;

	ಯದಿ (providerp == ರಿಕ್ತ)
		ಗಚ್ಛ fail;
	*providerp = ರಿಕ್ತ;

	ಯದಿ (keyp != ರಿಕ್ತ)
		*keyp = ರಿಕ್ತ;
	ಯದಿ (labelsp != ರಿಕ್ತ)
		*labelsp = ರಿಕ್ತ;

	ಯದಿ (pkcs11_provider_lookup(provider_id) != ರಿಕ್ತ) {
		debug_f("provider already registered: %s", provider_id);
		ಗಚ್ಛ fail;
	}
	ಯದಿ (lib_contains_ಚಿಹ್ನೆ(provider_id, "C_GetFunctionList") != 0) {
		error("provider %s is not a PKCS11 library", provider_id);
		ಗಚ್ಛ fail;
	}
	/* open shared pkcs11-library */
	ಯದಿ ((handle = dlopen(provider_id, RTLD_NOW)) == ರಿಕ್ತ) {
		error("dlopen %s failed: %s", provider_id, dlerror());
		ಗಚ್ಛ fail;
	}
	ಯದಿ ((getfunctionlist = dlsym(handle, "C_GetFunctionList")) == ರಿಕ್ತ)
		fatal("dlsym(C_GetFunctionList) failed: %s", dlerror());
	p = xcalloc(1, ಪರಿಮಾಣ(*p));
	p->name = xstrdup(provider_id);
	p->handle = handle;
	/* set up the pkcs11 callbacks */
	ಯದಿ ((rv = (*getfunctionlist)(&f)) != CKR_OK) {
		error("C_GetFunctionList for provider %s failed: %lu",
		    provider_id, rv);
		ಗಚ್ಛ fail;
	}
	p->function_list = f;
	ಯದಿ ((rv = f->C_Initialize(ರಿಕ್ತ)) != CKR_OK) {
		error("C_Initialize for provider %s failed: %lu",
		    provider_id, rv);
		ಗಚ್ಛ fail;
	}
	need_finalize = 1;
	ಯದಿ ((rv = f->C_GetInfo(&p->info)) != CKR_OK) {
		error("C_GetInfo for provider %s failed: %lu",
		    provider_id, rv);
		ಗಚ್ಛ fail;
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
	ಯದಿ ((rv = f->C_GetSlotList(CK_TRUE, ರಿಕ್ತ, &p->nslots)) != CKR_OK) {
		error("C_GetSlotList failed: %lu", rv);
		ಗಚ್ಛ fail;
	}
	ಯದಿ (p->nslots == 0) {
		debug_f("provider %s returned no slots", provider_id);
		ret = -SSH_PKCS11_ERR_NO_SLOTS;
		ಗಚ್ಛ fail;
	}
	p->slotlist = xcalloc(p->nslots, ಪರಿಮಾಣ(CK_SLOT_ID));
	ಯದಿ ((rv = f->C_GetSlotList(CK_TRUE, p->slotlist, &p->nslots))
	    != CKR_OK) {
		error("C_GetSlotList for provider %s failed: %lu",
		    provider_id, rv);
		ಗಚ್ಛ fail;
	}
	p->slotinfo = xcalloc(p->nslots, ಪರಿಮಾಣ(ಸಂರಚನಾ pkcs11_slotinfo));
	p->valid = 1;
	nkeys = 0;
	ಪ್ರತಿ (i = 0; i < p->nslots; i++) {
		token = &p->slotinfo[i].token;
		ಯದಿ ((rv = f->C_GetTokenInfo(p->slotlist[i], token))
		    != CKR_OK) {
			error("C_GetTokenInfo for provider %s slot %lu "
			    "failed: %lu", provider_id, (u_long)i, rv);
			ಅನುವರ್ತ;
		}
		ಯದಿ ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
			debug2_f("ignoring uninitialised token in "
			    "provider %s slot %lu", provider_id, (u_long)i);
			ಅನುವರ್ತ;
		}
		debug("provider %s slot %lu: label <%.*s> "
		    "manufacturerID <%.*s> model <%.*s> serial <%.*s> "
		    "flags 0x%lx",
		    provider_id, (unsigned long)i,
		    RMSPACE(token->label), RMSPACE(token->manufacturerID),
		    RMSPACE(token->model), RMSPACE(token->serial_ಸಂಖ್ಯೆ_2),
		    token->flags);
		/*
		 * open session, login with pin and retrieve public
		 * keys (if keyp is provided)
		 */
		ಯದಿ ((ret = pkcs11_open_session(p, i, pin, user)) != 0 ||
		    keyp == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		pkcs11_fetch_ಕೀಲಿಗಳು(p, i, keyp, labelsp, &nkeys);
#ifdef WITH_OPENSSL
		pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#endif
		ಯದಿ (nkeys == 0 && !p->slotinfo[i].logged_in &&
		    pkcs11_interactive) {
			/*
			 * Some tokens require login before they will
			 * expose keys.
			 */
			ಯದಿ (pkcs11_login_slot(p, &p->slotinfo[i],
			    CKU_USER) < 0) {
				error("login failed");
				ಅನುವರ್ತ;
			}
			pkcs11_fetch_ಕೀಲಿಗಳು(p, i, keyp, labelsp, &nkeys);
#ifdef WITH_OPENSSL
			pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#endif
		}
	}

	/* now owned by caller */
	*providerp = p;

	TAILQ_INSERT_TAIL(&pkcs11_providers, p, next);
	p->refcount++;	/* add to provider list */

	ಪ್ರತ್ಯಾಗಮ (nkeys);
fail:
	ಯದಿ (need_finalize && (rv = f->C_Finalize(ರಿಕ್ತ)) != CKR_OK)
		error("C_Finalize for provider %s failed: %lu",
		    provider_id, rv);
	ಯದಿ (p) {
		ಮುಕ್ತ(p->name);
		ಮುಕ್ತ(p->slotlist);
		ಮುಕ್ತ(p->slotinfo);
		ಮುಕ್ತ(p);
	}
	ಯದಿ (handle)
		dlclose(handle);
	ಯದಿ (ret > 0)
		ret = -1;
	ಪ್ರತ್ಯಾಗಮ (ret);
}

ಪೂರ್ಣಾಙ್ಕ
pkcs11_init(ಪೂರ್ಣಾಙ್ಕ interactive)
{
	debug3_f("called, interactive = %d", interactive);

	pkcs11_interactive = interactive;
	TAILQ_INIT(&pkcs11_providers);
	TAILQ_INIT(&pkcs11_ಕೀಲಿಗಳು);
	ಪ್ರತ್ಯಾಗಮ (0);
}

/* unregister all providers, keys might still point to the providers */
ಶೂನ್ಯ
pkcs11_terminate(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ pkcs11_provider *p;
	ಸಂರಚನಾ pkcs11_ಕೀಲಿ *k11;

	debug3_f("called");

	ಯಾವತ್ ((k11 = TAILQ_FIRST(&pkcs11_ಕೀಲಿಗಳು)) != ರಿಕ್ತ) {
		TAILQ_REMOVE(&pkcs11_ಕೀಲಿಗಳು, k11, next);
		pkcs11_k11_free(k11);
	}
	ಯಾವತ್ ((p = TAILQ_FIRST(&pkcs11_providers)) != ರಿಕ್ತ) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
}

/*
 * register a new provider and get number of keys hold by the token,
 * fails if provider already exists
 */
ಪೂರ್ಣಾಙ್ಕ
pkcs11_add_provider(ವರ್ಣ *provider_id, ವರ್ಣ *pin, ಸಂರಚನಾ sshkey ***keyp,
    ವರ್ಣ ***labelsp)
{
	ಸಂರಚನಾ pkcs11_provider *p = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ nkeys;

	nkeys = pkcs11_register_provider(provider_id, pin, keyp, labelsp,
	    &p, CKU_USER);

	/* no keys found or some other error, de-register provider */
	ಯದಿ (nkeys <= 0 && p != ರಿಕ್ತ) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
	ಯದಿ (nkeys == 0)
		debug_f("provider %s returned no keys", provider_id);

	ಪ್ರತ್ಯಾಗಮ (nkeys);
}

ಪೂರ್ಣಾಙ್ಕ
pkcs11_sign(ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    u_char **sigp, size_t *lenp,
    ಧ್ರುವ u_char *data, size_t datalen,
    ಧ್ರುವ ವರ್ಣ *alg, ಧ್ರುವ ವರ್ಣ *sk_provider,
    ಧ್ರುವ ವರ್ಣ *sk_pin, u_int compat)
{
	ವಿಕಲ್ಪ (ಕೀಲಿ->type) {
#ifdef WITH_OPENSSL
	ಪಕ್ಷ ಕೀಲಿ_RSA:
	ಪಕ್ಷ ಕೀಲಿ_RSA_CERT:
		ಪ್ರತ್ಯಾಗಮ pkcs11_sign_rsa(ಕೀಲಿ, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	ಪಕ್ಷ ಕೀಲಿ_ECDSA:
	ಪಕ್ಷ ಕೀಲಿ_ECDSA_CERT:
		ಪ್ರತ್ಯಾಗಮ pkcs11_sign_ecdsa(ಕೀಲಿ, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
#endif /* WITH_OPENSSL */
	ಪಕ್ಷ ಕೀಲಿ_ED25519:
	ಪಕ್ಷ ಕೀಲಿ_ED25519_CERT:
		ಪ್ರತ್ಯಾಗಮ pkcs11_sign_ed25519(ಕೀಲಿ, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_TYPE_UNKNOWN;
	}
}

ಶೂನ್ಯ
pkcs11_ಕೀಲಿ_free(ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	/* never called */
}

#ifdef WITH_PKCS11_KEYGEN
ಸಂರಚನಾ sshkey *
pkcs11_gakp(ವರ್ಣ *provider_id, ವರ್ಣ *pin, unsigned ಪೂರ್ಣಾಙ್ಕ slotidx, ವರ್ಣ *label,
    unsigned ಪೂರ್ಣಾಙ್ಕ type, unsigned ಪೂರ್ಣಾಙ್ಕ bits, unsigned ವರ್ಣ keyid, uint32_t *err)
{
	ಸಂರಚನಾ pkcs11_provider	*p = ರಿಕ್ತ;
	ಸಂರಚನಾ pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	ಸಂರಚನಾ sshkey		*k = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ			 ret = -1, reset_pin = 0, reset_provider = 0;
	CK_RV			 rv;

	*err = 0;

	ಯದಿ ((p = pkcs11_provider_lookup(provider_id)) != ರಿಕ್ತ)
		debug_f("provider \"%s\" available", provider_id);
	ಅನ್ಯಥಾ ಯದಿ ((ret = pkcs11_register_provider(provider_id, pin, ರಿಕ್ತ, ರಿಕ್ತ,
	    &p, CKU_SO)) < 0) {
		debug_f("could not register provider %s", provider_id);
		ಗಚ್ಛ out;
	} ಅನ್ಯಥಾ
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	ಯದಿ ((rv = f->C_SetOperationState(session , pin, strlen(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} ಅನ್ಯಥಾ
		reset_pin = 1;

	ವಿಕಲ್ಪ (type) {
	ಪಕ್ಷ ಕೀಲಿ_RSA:
		ಯದಿ ((k = pkcs11_rsa_generate_private_ಕೀಲಿ(p, slotidx, label,
		    bits, keyid, err)) == ರಿಕ್ತ) {
			debug_f("failed to generate RSA key");
			ಗಚ್ಛ out;
		}
		ಭಙ್ಗ;
	ಪಕ್ಷ ಕೀಲಿ_ECDSA:
		ಯದಿ ((k = pkcs11_ecdsa_generate_private_ಕೀಲಿ(p, slotidx, label,
		    bits, keyid, err)) == ರಿಕ್ತ) {
			debug_f("failed to generate ECDSA key");
			ಗಚ್ಛ out;
		}
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		*err = SSH_PKCS11_ERR_GENERIC;
		debug_f("unknown type %d", type);
		ಗಚ್ಛ out;
	}

out:
	ಯದಿ (reset_pin)
		f->C_SetOperationState(session , ರಿಕ್ತ, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	ಯದಿ (reset_provider)
		pkcs11_del_provider(provider_id);

	ಪ್ರತ್ಯಾಗಮ (k);
}

ಸಂರಚನಾ sshkey *
pkcs11_destroy_keypair(ವರ್ಣ *provider_id, ವರ್ಣ *pin, unsigned long slotidx,
    unsigned ವರ್ಣ keyid, uint32_t *err)
{
	ಸಂರಚನಾ pkcs11_provider	*p = ರಿಕ್ತ;
	ಸಂರಚನಾ pkcs11_slotinfo	*si;
	ಸಂರಚನಾ sshkey		*k = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ			 reset_pin = 0, reset_provider = 0;
	CK_ULONG		 nattrs;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_ATTRIBUTE		 attrs[16];
	CK_OBJECT_CLASS		 ಕೀಲಿ_class;
	CK_ಕೀಲಿ_TYPE		 ಕೀಲಿ_type;
	CK_OBJECT_HANDLE	 obj = CK_INVALID_HANDLE;
	CK_RV			 rv;

	*err = 0;

	ಯದಿ ((p = pkcs11_provider_lookup(provider_id)) != ರಿಕ್ತ) {
		debug_f("using provider \"%s\"", provider_id);
	} ಅನ್ಯಥಾ ಯದಿ (pkcs11_register_provider(provider_id, pin, ರಿಕ್ತ, ರಿಕ್ತ, &p,
	    CKU_SO) < 0) {
		debug_f("could not register provider %s",
		    provider_id);
		ಗಚ್ಛ out;
	} ಅನ್ಯಥಾ
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	ಯದಿ ((rv = f->C_SetOperationState(session , pin, strlen(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} ಅನ್ಯಥಾ
		reset_pin = 1;

	/* private key */
	nattrs = 0;
	ಕೀಲಿ_class = CKO_PRIVATE_ಕೀಲಿ;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &ಕೀಲಿ_class, ಪರಿಮಾಣ(ಕೀಲಿ_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, ಪರಿಮಾಣ(keyid));

	ಯದಿ (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {
		ಯದಿ ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy private key 0x%hhx",
			    keyid);
			*err = rv;
			ಗಚ್ಛ out;
		}
	}

	/* public key */
	nattrs = 0;
	ಕೀಲಿ_class = CKO_PUBLIC_ಕೀಲಿ;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &ಕೀಲಿ_class, ಪರಿಮಾಣ(ಕೀಲಿ_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, ಪರಿಮಾಣ(keyid));

	ಯದಿ (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {

		/* get key type */
		nattrs = 0;
		FILL_ATTR(attrs, nattrs, CKA_ಕೀಲಿ_TYPE, &ಕೀಲಿ_type,
		    ಪರಿಮಾಣ(ಕೀಲಿ_type));
		rv = f->C_Get_Attribute_ಮೌಲ್ಯ(session, obj, attrs, nattrs);
		ಯದಿ (rv != CKR_OK) {
			debug_f("could not get key type of public key 0x%hhx",
			    keyid);
			*err = rv;
			ಕೀಲಿ_type = -1;
		}
		ವಿಕಲ್ಪ (ಕೀಲಿ_type) {
#ifdef WITH_OPENSSL
		ಪಕ್ಷ CKK_RSA:
			k = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			ಭಙ್ಗ;
		ಪಕ್ಷ CKK_ECDSA:
			k = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			ಭಙ್ಗ;
#endif /* WITH_OPENSSL */
		ಪಕ್ಷ CKK_EC_EDWARDS:
			k = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			debug_f("unsupported key type %lu", (u_long)ಕೀಲಿ_type);
			ಭಙ್ಗ;
		}

		ಯದಿ ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy public key 0x%hhx", keyid);
			*err = rv;
			ಗಚ್ಛ out;
		}
	}

out:
	ಯದಿ (reset_pin)
		f->C_SetOperationState(session , ರಿಕ್ತ, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	ಯದಿ (reset_provider)
		pkcs11_del_provider(provider_id);

	ಪ್ರತ್ಯಾಗಮ (k);
}
#endif /* WITH_PKCS11_KEYGEN */
#ಅನ್ಯಥಾ /* ENABLE_PKCS11 */

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "ssh-pkcs11.h"

ಪೂರ್ಣಾಙ್ಕ
pkcs11_init(ಪೂರ್ಣಾಙ್ಕ interactive)
{
	error_f("PKCS#11 not supported");
	ಪ್ರತ್ಯಾಗಮ (-1);
}

ಪೂರ್ಣಾಙ್ಕ
pkcs11_add_provider(ವರ್ಣ *provider_id, ವರ್ಣ *pin, ಸಂರಚನಾ sshkey ***keyp,
    ವರ್ಣ ***labelsp)
{
	error_f("PKCS#11 not supported");
	ಪ್ರತ್ಯಾಗಮ (-1);
}

ಶೂನ್ಯ
pkcs11_ಕೀಲಿ_free(ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	error_f("PKCS#11 not supported");
}

ಪೂರ್ಣಾಙ್ಕ
pkcs11_sign(ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    u_char **sigp, size_t *lenp,
    ಧ್ರುವ u_char *data, size_t datalen,
    ಧ್ರುವ ವರ್ಣ *alg, ಧ್ರುವ ವರ್ಣ *sk_provider,
    ಧ್ರುವ ವರ್ಣ *sk_pin, u_int compat)
{
	error_f("PKCS#11 not supported");
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_FEATURE_UNSUPPORTED;
}

ಶೂನ್ಯ
pkcs11_terminate(ಶೂನ್ಯ)
{
	error_f("PKCS#11 not supported");
}
#endif /* ENABLE_PKCS11 */
