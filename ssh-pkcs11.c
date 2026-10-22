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

#અન્તર્ભાવ "includes.h"

#ifdef ENABLE_PKCS11

#અન્તર્ભાવ <sys/time.h>

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/queue.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>

#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <dlfcn.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"
#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/ecdsa.h>
#અન્તર્ભાવ <openssl/x509.h>
#અન્તર્ભાવ <openssl/err.h>
#endif

#define CRYPTOKI_COMPAT
#અન્તર્ભાવ "pkcs11.h"

#define SSHKEY_INTERNAL
#અન્તર્ભાવ "sshkey.h"

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssh-pkcs11.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "crypto_api.h"

સંરચના pkcs11_slotinfo {
	CK_TOKEN_INFO		token;
	CK_SESSION_HANDLE	session;
	પૂર્ણાંક			logged_in;
};

સંરચના pkcs11_provider {
	અક્ષર			*name;
	શૂન્ય			*handle;
	CK_FUNCTION_LIST	*function_list;
	CK_INFO			info;
	CK_ULONG		nslots;
	CK_SLOT_ID		*slotlist;
	સંરચના pkcs11_slotinfo	*slotinfo;
	પૂર્ણાંક			valid;
	પૂર્ણાંક			refcount;
	TAILQ_ENTRY(pkcs11_provider) next;
};

TAILQ_HEAD(, pkcs11_provider) pkcs11_providers;

સંરચના pkcs11_ચાવી {
	સંરચના sshbuf		*keyblob;
	સંરચના pkcs11_provider	*provider;
	CK_ULONG		slotidx;
	અક્ષર			*keyid;
	પૂર્ણાંક			keyid_len;
	TAILQ_ENTRY(pkcs11_ચાવી)	next;
};

TAILQ_HEAD(, pkcs11_ચાવી) pkcs11_ચાવીઓ; /* XXX a tree would be better */

પૂર્ણાંક pkcs11_interactive = 0;

#ifdef WITH_OPENSSL
સ્થિર શૂન્ય
ossl_error(અચલ અક્ષર *સંદેશ)
{
	unsigned long    e;

	error_f("%s", સંદેશ);
	જ્યારે ((e = ERR_get_error()) != 0)
		error_f("libcrypto error: %s", ERR_error_string(e, ખાલી));
}
#endif

/*
 * finalize a provider shared library, it's no longer usable.
 * however, there might still be keys referencing this provider,
 * so the actual freeing of memory is handled by pkcs11_provider_unref().
 * this is called when a provider gets unregistered.
 */
સ્થિર શૂન્ય
pkcs11_provider_finalize(સંરચના pkcs11_provider *p)
{
	CK_RV rv;
	CK_ULONG i;

	debug_f("provider \"%s\" refcount %d valid %d",
	    p->name, p->refcount, p->valid);
	જો (!p->valid)
		પાછા;
	માટે (i = 0; i < p->nslots; i++) {
		જો (p->slotinfo[i].session &&
		    (rv = p->function_list->C_CloseSession(
		    p->slotinfo[i].session)) != CKR_OK)
			error("C_CloseSession failed: %lu", rv);
	}
	જો ((rv = p->function_list->C_Finalize(ખાલી)) != CKR_OK)
		error("C_Finalize failed: %lu", rv);
	p->valid = 0;
	p->function_list = ખાલી;
	dlclose(p->handle);
}

/*
 * remove a reference to the provider.
 * called when a key gets destroyed or when the provider is unregistered.
 */
સ્થિર શૂન્ય
pkcs11_provider_unref(સંરચના pkcs11_provider *p)
{
	debug_f("provider \"%s\" refcount %d", p->name, p->refcount);
	જો (--p->refcount <= 0) {
		જો (p->valid)
			error_f("provider \"%s\" still valid", p->name);
		મુક્ત(p->name);
		મુક્ત(p->slotlist);
		મુક્ત(p->slotinfo);
		મુક્ત(p);
	}
}

/* lookup provider by name */
સ્થિર સંરચના pkcs11_provider *
pkcs11_provider_lookup(અક્ષર *provider_id)
{
	સંરચના pkcs11_provider *p;

	TAILQ_FOREACH(p, &pkcs11_providers, next) {
		debug("check provider \"%s\"", p->name);
		જો (!strcmp(provider_id, p->name))
			પાછા (p);
	}
	પાછા (ખાલી);
}

/* unregister provider by name */
પૂર્ણાંક
pkcs11_del_provider(અક્ષર *provider_id)
{
	સંરચના pkcs11_provider *p;

	જો ((p = pkcs11_provider_lookup(provider_id)) != ખાલી) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
		પાછા (0);
	}
	પાછા (-1);
}

/* release a wrapped object */
સ્થિર શૂન્ય
pkcs11_k11_free(સંરચના pkcs11_ચાવી *k11)
{
	જો (k11 == ખાલી)
		પાછા;
	જો (k11->provider)
		pkcs11_provider_unref(k11->provider);
	મુક્ત(k11->keyid);
	sshbuf_free(k11->keyblob);
	મુક્ત(k11);
}

/* find a single 'obj' for given attributes */
સ્થિર પૂર્ણાંક
pkcs11_find(સંરચના pkcs11_provider *p, CK_ULONG slotidx, CK_ATTRIBUTE *attr,
    CK_ULONG nattr, CK_OBJECT_HANDLE *obj)
{
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	session;
	CK_ULONG		nfound = 0;
	CK_RV			rv;
	પૂર્ણાંક			ret = -1;

	f = p->function_list;
	session = p->slotinfo[slotidx].session;
	જો ((rv = f->C_FindObjectsInit(session, attr, nattr)) != CKR_OK) {
		error("C_FindObjectsInit failed (nattr %lu): %lu", nattr, rv);
		પાછા (-1);
	}
	જો ((rv = f->C_FindObjects(session, obj, 1, &nfound)) != CKR_OK ||
	    nfound != 1) {
		debug("C_FindObjects failed (nfound %lu nattr %lu): %lu",
		    nfound, nattr, rv);
	} નહીંતર
		ret = 0;
	જો ((rv = f->C_FindObjectsFinal(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	પાછા (ret);
}

સ્થિર પૂર્ણાંક
pkcs11_login_slot(સંરચના pkcs11_provider *provider, સંરચના pkcs11_slotinfo *si,
    CK_USER_TYPE type)
{
	અક્ષર			*pin = ખાલી, prompt[1024];
	CK_RV			 rv;

	જો (provider == ખાલી || si == ખાલી || !provider->valid) {
		error("no pkcs11 (valid) provider found");
		પાછા (-1);
	}

	જો (!pkcs11_interactive) {
		error("need pin entry%s",
		    (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH) ?
		    " on reader keypad" : "");
		પાછા (-1);
	}
	જો (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
		verbose("Deferring PIN entry to reader keypad.");
	નહીંતર {
		snprintf(prompt, કદ(prompt), "Enter PIN for '%s': ",
		    si->token.label);
		જો ((pin = read_passphrase(prompt, RP_ALLOW_EOF)) == ખાલી) {
			debug_f("no pin specified");
			પાછા (-1);	/* bail out */
		}
	}
	rv = provider->function_list->C_Login(si->session, type, (u_char *)pin,
	    (pin != ખાલી) ? strlen(pin) : 0);
	જો (pin != ખાલી)
		freezero(pin, strlen(pin));

	પસંદગી (rv) {
	સ્થિતિ CKR_OK:
	સ્થિતિ CKR_USER_ALREADY_LOGGED_IN:
		/* success */
		તોડો;
	સ્થિતિ CKR_PIN_LEN_RANGE:
		error("PKCS#11 login failed: PIN length out of range");
		પાછા -1;
	સ્થિતિ CKR_PIN_INCORRECT:
		error("PKCS#11 login failed: PIN incorrect");
		પાછા -1;
	સ્થિતિ CKR_PIN_LOCKED:
		error("PKCS#11 login failed: PIN locked");
		પાછા -1;
	મૂળભૂત:
		error("PKCS#11 login failed: error %lu", rv);
		પાછા -1;
	}
	si->logged_in = 1;
	પાછા (0);
}

સ્થિર પૂર્ણાંક
pkcs11_login(સંરચના pkcs11_ચાવી *k11, CK_USER_TYPE type)
{
	જો (k11 == ખાલી || k11->provider == ખાલી || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		પાછા (-1);
	}

	પાછા pkcs11_login_slot(k11->provider,
	    &k11->provider->slotinfo[k11->slotidx], type);
}


સ્થિર પૂર્ણાંક
pkcs11_check_obj_bool_attrib(સંરચના pkcs11_ચાવી *k11, CK_OBJECT_HANDLE obj,
    CK_ATTRIBUTE_TYPE type, પૂર્ણાંક *val)
{
	સંરચના pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_BBOOL		flag = 0;
	CK_ATTRIBUTE		attr;
	CK_RV			 rv;

	*val = 0;

	જો (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		પાછા (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	attr.type = type;
	attr.p_કિંમત = &flag;
	attr.ul_કિંમત_Len = કદ(flag);

	rv = f->C_Get_Attribute_કિંમત(si->session, obj, &attr, 1);
	જો (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		પાછા (-1);
	}
	*val = flag != 0;
	debug_f("provider \"%s\" slot %lu object %lu: attrib %lu = %d",
	    k11->provider->name, k11->slotidx, obj, type, *val);
	પાછા (0);
}

સ્થિર પૂર્ણાંક
pkcs11_get_ચાવી(સંરચના pkcs11_ચાવી *k11, CK_MECHANISM_TYPE mech_type)
{
	સંરચના pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	 obj;
	CK_RV			 rv;
	CK_OBJECT_CLASS		 private_ચાવી_class;
	CK_BBOOL		 true_val;
	CK_MECHANISM		 mech;
	CK_ATTRIBUTE		 ચાવી_filter[3];
	પૂર્ણાંક			 always_auth = 0;
	પૂર્ણાંક			 did_login = 0;

	જો (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		પાછા (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	જો ((si->token.flags & CKF_LOGIN_REQUIRED) && !si->logged_in) {
		જો (pkcs11_login(k11, CKU_USER) < 0) {
			error("login failed");
			પાછા (-1);
		}
		did_login = 1;
	}

	memset(&ચાવી_filter, 0, કદ(ચાવી_filter));
	private_ચાવી_class = CKO_PRIVATE_ચાવી;
	ચાવી_filter[0].type = CKA_CLASS;
	ચાવી_filter[0].p_કિંમત = &private_ચાવી_class;
	ચાવી_filter[0].ul_કિંમત_Len = કદ(private_ચાવી_class);

	ચાવી_filter[1].type = CKA_ID;
	ચાવી_filter[1].p_કિંમત = k11->keyid;
	ચાવી_filter[1].ul_કિંમત_Len = k11->keyid_len;

	true_val = CK_TRUE;
	ચાવી_filter[2].type = CKA_SIGN;
	ચાવી_filter[2].p_કિંમત = &true_val;
	ચાવી_filter[2].ul_કિંમત_Len = કદ(true_val);

	/* try to find object w/CKA_SIGN first, retry w/o */
	જો (pkcs11_find(k11->provider, k11->slotidx, ચાવી_filter, 3, &obj) < 0 &&
	    pkcs11_find(k11->provider, k11->slotidx, ચાવી_filter, 2, &obj) < 0) {
		error("cannot find private key");
		પાછા (-1);
	}

	memset(&mech, 0, કદ(mech));
	mech.mechanism = mech_type;
	mech.pParameter = NULL_PTR;
	mech.ulParameterLen = 0;

	જો ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
		પાછા (-1);
	}

	pkcs11_check_obj_bool_attrib(k11, obj, CKA_ALWAYS_AUTHENTICATE,
	    &always_auth); /* ignore errors here */
	જો (always_auth && !did_login) {
		debug_f("always-auth key");
		જો (pkcs11_login(k11, CKU_CONTEXT_SPECIFIC) < 0) {
			error("login failed for always-auth key");
			પાછા (-1);
		}
	}

	પાછા (0);
}

/* record the key information later use lookup by keyblob */
સ્થિર પૂર્ણાંક
pkcs11_record_ચાવી(સંરચના pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, સંરચના sshkey *ચાવી)
{
	સંરચના sshbuf *keyblob;
	સંરચના pkcs11_ચાવી *k11;
	પૂર્ણાંક r;
	અક્ષર *hex;

	hex = tohex(keyid_attrib->p_કિંમત, keyid_attrib->ul_કિંમત_Len);
	debug_f("%s key: provider %s slot %lu keyid %s",
	    sshkey_type(ચાવી), provider->name, (u_long)slotidx, hex);
	મુક્ત(hex);

	જો ((keyblob = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshkey_putb(ચાવી, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");

	/* Check if we've already recorded this key in a different slot */
	TAILQ_FOREACH(k11, &pkcs11_ચાવીઓ, next) {
		જો (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			hex = tohex(k11->keyid, k11->keyid_len);
			debug_f("Already seen this key at "
			    "provider %s slot %lu keyid %s",
			    k11->provider->name, k11->slotidx, hex);
			મુક્ત(hex);
			sshbuf_free(keyblob);
			પાછા -1;
		}
	}

	k11 = xcalloc(1, કદ(*k11));
	k11->provider = provider;
	k11->keyblob = keyblob;
	provider->refcount++;	/* provider referenced by RSA key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ul_કિંમત_Len;
	જો (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len);
		memcpy(k11->keyid, keyid_attrib->p_કિંમત, k11->keyid_len);
	}
	TAILQ_INSERT_TAIL(&pkcs11_ચાવીઓ, k11, next);

	પાછા 0;
}

/* retrieve the key information by keyblob */
સ્થિર સંરચના pkcs11_ચાવી *
pkcs11_lookup_ચાવી(સંરચના sshkey *ચાવી)
{
	સંરચના pkcs11_ચાવી *k11, *found = ખાલી;
	સંરચના sshbuf *keyblob;
	પૂર્ણાંક r;

	જો ((keyblob = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો ((r = sshkey_putb(ચાવી, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");
	TAILQ_FOREACH(k11, &pkcs11_ચાવીઓ, next) {
		જો (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			found = k11;
			તોડો;
		}
	}
	sshbuf_free(keyblob);
	પાછા found;
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
સ્થિર અચલ u_char id_sha1[] = {
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
સ્થિર અચલ u_char id_sha256[] = {
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
સ્થિર અચલ u_char id_sha512[] = {
	0x30, 0x51, /* type Sequence, length 0x51 (81) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, /* id-sha512 */
	0x05, 0x00, /* NULL */
	0x04, 0x40  /* Octet string, length 0x40 (64), followed by sha512 hash */
};

સ્થિર પૂર્ણાંક
rsa_hash_alg_oid(પૂર્ણાંક hash_alg, અચલ u_char **oidp, size_t *oidlenp)
{
	પસંદગી (hash_alg) {
	સ્થિતિ SSH_DIGEST_SHA1:
		*oidp = id_sha1;
		*oidlenp = કદ(id_sha1);
		તોડો;
	સ્થિતિ SSH_DIGEST_SHA256:
		*oidp = id_sha256;
		*oidlenp = કદ(id_sha256);
		તોડો;
	સ્થિતિ SSH_DIGEST_SHA512:
		*oidp = id_sha512;
		*oidlenp = કદ(id_sha512);
		તોડો;
	મૂળભૂત:
		પાછા SSH_ERR_INVALID_ARGUMENT;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
pkcs11_sign_rsa(સંરચના sshkey *ચાવી,
    u_char **sigp, size_t *lenp,
    અચલ u_char *data, size_t datalen,
    અચલ અક્ષર *alg, અચલ અક્ષર *sk_provider,
    અચલ અક્ષર *sk_pin, u_int compat)
{
	સંરચના pkcs11_ચાવી	*k11;
	સંરચના pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	પૂર્ણાંક			hashalg, r, diff, siglen, ret = -1;
	u_char			*oid_dgst = ખાલી, *sig = ખાલી;
	size_t			dgst_len, oid_len, oid_dgst_len = 0;
	અચલ u_char		*oid;

	જો (sigp != ખાલી)
		*sigp = ખાલી;
	જો (lenp != ખાલી)
		*lenp = 0;

	જો ((k11 = pkcs11_lookup_ચાવી(ચાવી)) == ખાલી) {
		error_f("no key found");
		પાછા SSH_ERR_ચાવી_NOT_FOUND;
	}

	debug3_f("sign with alg \"%s\" using provider %s slotidx %lu",
	    alg == ખાલી ? "" : alg, k11->provider->name, (u_long)k11->slotidx);

	જો (pkcs11_get_ચાવી(k11, CKM_RSA_PKCS) == -1) {
		error("pkcs11_get_key failed");
		પાછા SSH_ERR_AGENT_FAILURE;
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	જો ((siglen = EVP_PKEY_size(ચાવી->pkey)) <= 0)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* Determine hash algorithm and OID for signature */
	જો (alg == ખાલી || *alg == '\0')
		hashalg = SSH_DIGEST_SHA1;
	નહીંતર જો ((hashalg = ssh_rsa_hash_id_from_keyname(alg)) == -1)
		fatal_f("couldn't determine RSA hash alg \"%s\"", alg);
	જો ((r = rsa_hash_alg_oid(hashalg, &oid, &oid_len)) != 0)
		fatal_fr(r, "rsa_hash_alg_oid failed");
	જો ((dgst_len = ssh_digest_bytes(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);

	/* Prepare { oid || digest } */
	oid_dgst_len = oid_len + dgst_len;
	oid_dgst = xcalloc(1, oid_dgst_len);
	memcpy(oid_dgst, oid, oid_len);
	જો ((r = ssh_digest_memory(hashalg, data, datalen,
	    oid_dgst + oid_len, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	જો ((rv = f->C_Sign(si->session, (CK_BYTE *)oid_dgst,
	    oid_dgst_len, sig, &slen)) != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		જાઓ done;
	}

	જો (slen < (CK_ULONG)siglen) {
		diff = siglen - slen;
		debug3_f("repack %lu < %d (diff %d)",
		    (u_long)slen, siglen, diff);
		memmove(sig + diff, sig, slen);
		explicit_bzero(sig, diff);
	} નહીંતર જો (slen > (size_t)siglen)
		fatal_f("bad C_Sign length");

	જો ((ret = ssh_rsa_encode_store_sig(hashalg, sig, siglen,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	freezero(oid_dgst, oid_dgst_len);
	મુક્ત(sig);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
pkcs11_sign_ecdsa(સંરચના sshkey *ચાવી,
    u_char **sigp, size_t *lenp,
    અચલ u_char *data, size_t datalen,
    અચલ અક્ષર *alg, અચલ અક્ષર *sk_provider,
    અચલ અક્ષર *sk_pin, u_int compat)
{
	સંરચના pkcs11_ચાવી	*k11;
	સંરચના pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0, bnlen;
	CK_RV			rv;
	BIGNUM			*sig_r = ખાલી, *sig_s = ખાલી;
	u_char			*sig = ખાલી, *dgst = ખાલી;
	size_t			dgst_len = 0;
	પૂર્ણાંક			hashalg, ret = -1, r, siglen;

	જો (sigp != ખાલી)
		*sigp = ખાલી;
	જો (lenp != ખાલી)
		*lenp = 0;

	જો ((k11 = pkcs11_lookup_ચાવી(ચાવી)) == ખાલી) {
		error_f("no key found");
		પાછા SSH_ERR_ચાવી_NOT_FOUND;
	}

	જો (pkcs11_get_ચાવી(k11, CKM_ECDSA) == -1) {
		error("pkcs11_get_key failed");
		પાછા SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	/* Prepare digest to be signed */
	જો ((hashalg = sshkey_ec_nid_to_hash_alg(ચાવી->ecdsa_nid)) == -1)
		fatal_f("couldn't determine ECDSA hash alg");
	જો ((dgst_len = ssh_digest_bytes(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);
	dgst = xcalloc(1, dgst_len);
	જો ((r = ssh_digest_memory(hashalg, data, datalen,
	    dgst, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	જો ((siglen = EVP_PKEY_size(ચાવી->pkey)) <= 0)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dgst_len, sig, &slen);
	જો (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		જાઓ done;
	}
	જો (slen < 64 || slen > 132 || slen % 2) {
		error_f("bad signature length: %lu", (u_long)slen);
		જાઓ done;
	}
	bnlen = slen/2;
	જો ((sig_r = BN_bin2bn(sig, bnlen, ખાલી)) == ખાલી ||
	    (sig_s = BN_bin2bn(sig+bnlen, bnlen, ખાલી)) == ખાલી) {
		ossl_error("BN_bin2bn failed");
		જાઓ done;
	}

	જો ((ret = ssh_ecdsa_encode_store_sig(ચાવી, sig_r, sig_s,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	freezero(dgst, dgst_len);
	BN_free(sig_r);
	BN_free(sig_s);
	મુક્ત(sig);
	પાછા ret;
}
#endif /* WITH_OPENSSL */

સ્થિર પૂર્ણાંક
pkcs11_sign_ed25519(સંરચના sshkey *ચાવી,
    u_char **sigp, size_t *lenp,
    અચલ u_char *data, size_t datalen,
    અચલ અક્ષર *alg, અચલ અક્ષર *sk_provider,
    અચલ અક્ષર *sk_pin, u_int compat)
{
	સંરચના pkcs11_ચાવી	*k11;
	સંરચના pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	u_char			*sig = ખાલી;
	CK_BYTE			*xdata = ખાલી;
	પૂર્ણાંક			ret = -1;

	જો (sigp != ખાલી)
		*sigp = ખાલી;
	જો (lenp != ખાલી)
		*lenp = 0;

	જો ((k11 = pkcs11_lookup_ચાવી(ચાવી)) == ખાલી) {
		error_f("no key found");
		પાછા SSH_ERR_ચાવી_NOT_FOUND;
	}

	જો (pkcs11_get_ચાવી(k11, CKM_EDDSA) == -1) {
		error("pkcs11_get_key failed");
		પાછા SSH_ERR_AGENT_FAILURE;
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
	જો (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		જાઓ done;
	}
	જો (slen != crypto_sign_ed25519_BYTES) {
		error_f("bad signature length: %lu", (u_long)slen);
		જાઓ done;
	}
	જો ((ret = ssh_ed25519_encode_store_sig(sig, slen, sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	જો (xdata != ખાલી)
		freezero(xdata, datalen);
	મુક્ત(sig);
	પાછા ret;
}

/* remove trailing spaces */
સ્થિર અક્ષર *
rmspace(u_char *buf, size_t len)
{
	size_t i;

	જો (len == 0)
		પાછા buf;
	માટે (i = len - 1; i > 0; i--)
		જો (buf[i] == ' ')
			buf[i] = '\0';
		નહીંતર
			તોડો;
	પાછા buf;
}
/* Used to printf fixed-width, space-padded, unterminated strings using %.*s */
#define RMSPACE(s) (પૂર્ણાંક)કદ(s), rmspace(s, કદ(s))

/*
 * open a pkcs11 session and login if required.
 * if pin == NULL we delay login until key use
 */
સ્થિર પૂર્ણાંક
pkcs11_open_session(સંરચના pkcs11_provider *p, CK_ULONG slotidx, અક્ષર *pin,
    CK_ULONG user)
{
	સંરચના pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_RV			rv;
	CK_SESSION_HANDLE	session;
	પૂર્ણાંક			login_required, ret;

	f = p->function_list;
	si = &p->slotinfo[slotidx];

	login_required = si->token.flags & CKF_LOGIN_REQUIRED;

	/* fail early before opening session */
	જો (login_required && !pkcs11_interactive &&
	    (pin == ખાલી || strlen(pin) == 0)) {
		error("pin required");
		પાછા (-SSH_PKCS11_ERR_PIN_REQUIRED);
	}
	જો ((rv = f->C_OpenSession(p->slotlist[slotidx], CKF_RW_SESSION|
	    CKF_SERIAL_SESSION, ખાલી, ખાલી, &session)) != CKR_OK) {
		error("C_OpenSession failed: %lu", rv);
		પાછા (-1);
	}
	જો (login_required && pin != ખાલી && strlen(pin) != 0) {
		rv = f->C_Login(session, user, (u_char *)pin, strlen(pin));
		જો (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
			error("C_Login failed: %lu", rv);
			ret = (rv == CKR_PIN_LOCKED) ?
			    -SSH_PKCS11_ERR_PIN_LOCKED :
			    -SSH_PKCS11_ERR_LOGIN_FAIL;
			જો ((rv = f->C_CloseSession(session)) != CKR_OK)
				error("C_CloseSession failed: %lu", rv);
			પાછા (ret);
		}
		si->logged_in = 1;
	}
	si->session = session;
	પાછા (0);
}

સ્થિર પૂર્ણાંક
pkcs11_ચાવી_included(સંરચના sshkey ***keysp, પૂર્ણાંક *nkeys, સંરચના sshkey *ચાવી)
{
	પૂર્ણાંક i;

	માટે (i = 0; i < *nkeys; i++)
		જો (sshkey_equal(ચાવી, (*keysp)[i]))
			પાછા (1);
	પાછા (0);
}

#ifdef WITH_OPENSSL
સ્થિર સંરચના sshkey *
pkcs11_fetch_ecdsa_pubkey(સંરચના pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 ચાવી_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ખાલી;
	CK_RV			 rv;
	ASN1_OCTET_STRING	*octet = ખાલી;
	EC_ચાવી			*ec = ખાલી;
	EC_GROUP		*group = ખાલી;
	સંરચના sshkey		*ચાવી = ખાલી;
	અચલ unsigned અક્ષર	*attrp = ખાલી;
	પૂર્ણાંક			 success = -1, r, i, nid;

	memset(&ચાવી_attr, 0, કદ(ચાવી_attr));
	ચાવી_attr[0].type = CKA_ID;
	ચાવી_attr[1].type = CKA_EC_POINT;
	ચાવી_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_કિંમત(session, *obj, ચાવી_attr, 3);
	જો (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		પાછા (ખાલી);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	જો (ચાવી_attr[1].ul_કિંમત_Len == 0 ||
	    ચાવી_attr[2].ul_કિંમત_Len == 0) {
		error("invalid attribute length");
		પાછા (ખાલી);
	}

	/* allocate buffers for attributes */
	માટે (i = 0; i < 3; i++)
		જો (ચાવી_attr[i].ul_કિંમત_Len > 0)
			ચાવી_attr[i].p_કિંમત = xcalloc(1, ચાવી_attr[i].ul_કિંમત_Len);

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_કિંમત(session, *obj, ચાવી_attr, 3);
	જો (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		જાઓ fail;
	}

	ec = EC_ચાવી_new();
	જો (ec == ખાલી) {
		error("EC_KEY_new failed");
		જાઓ fail;
	}

	attrp = ચાવી_attr[2].p_કિંમત;
	group = d2i_ECPKParameters(ખાલી, &attrp, ચાવી_attr[2].ul_કિંમત_Len);
	જો (group == ખાલી) {
		ossl_error("d2i_ECPKParameters failed");
		જાઓ fail;
	}

	જો (EC_ચાવી_set_group(ec, group) == 0) {
		ossl_error("EC_KEY_set_group failed");
		જાઓ fail;
	}

	જો (ચાવી_attr[1].ul_કિંમત_Len <= 2) {
		error("CKA_EC_POINT too small");
		જાઓ fail;
	}

	attrp = ચાવી_attr[1].p_કિંમત;
	octet = d2i_ASN1_OCTET_STRING(ખાલી, &attrp, ચાવી_attr[1].ul_કિંમત_Len);
	જો (octet == ખાલી) {
		ossl_error("d2i_ASN1_OCTET_STRING failed");
		જાઓ fail;
	}
	attrp = ASN1_STRING_get0_data(octet);
	જો (o2i_ECPublic_ચાવી(&ec, &attrp, ASN1_STRING_length(octet)) == ખાલી) {
		ossl_error("o2i_ECPublicKey failed");
		જાઓ fail;
	}
	જો ((r = sshkey_ec_validate_public(EC_ચાવી_get0_group(ec),
	    EC_ચાવી_get0_public_ચાવી(ec))) != 0) {
		error_fr(r, "invalid EC key");
		જાઓ fail;
	}

	nid = sshkey_ecdsa_ચાવી_to_nid(ec);
	જો (nid < 0) {
		error("couldn't get curve nid");
		જાઓ fail;
	}

	ચાવી = sshkey_new(ચાવી_UNSPEC);
	જો (ચાવી == ખાલી) {
		error("sshkey_new failed");
		જાઓ fail;
	}

	EVP_PKEY_free(ચાવી->pkey);
	જો ((ચાવી->pkey = EVP_PKEY_new()) == ખાલી)
		fatal("EVP_PKEY_new failed");
	જો (EVP_PKEY_set1_EC_ચાવી(ચાવી->pkey, ec) != 1)
		fatal("EVP_PKEY_set1_EC_KEY failed");
	ચાવી->ecdsa_nid = nid;
	ચાવી->type = ચાવી_ECDSA;
	ચાવી->flags |= SSHKEY_FLAG_EXT;
	જો (pkcs11_record_ચાવી(p, slotidx, &ચાવી_attr[0], ચાવી))
		જાઓ fail;
	/* success */
	success = 0;
fail:
	જો (success != 0) {
		sshkey_free(ચાવી);
		ચાવી = ખાલી;
	}
	માટે (i = 0; i < 3; i++)
		મુક્ત(ચાવી_attr[i].p_કિંમત);
	જો (ec)
		EC_ચાવી_free(ec);
	જો (group)
		EC_GROUP_free(group);
	જો (octet)
		ASN1_OCTET_STRING_free(octet);

	પાછા (ચાવી);
}

સ્થિર સંરચના sshkey *
pkcs11_fetch_rsa_pubkey(સંરચના pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 ચાવી_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ખાલી;
	CK_RV			 rv;
	RSA			*rsa = ખાલી;
	BIGNUM			*rsa_n, *rsa_e;
	સંરચના sshkey		*ચાવી = ખાલી;
	પૂર્ણાંક			 i, success = -1;

	memset(&ચાવી_attr, 0, કદ(ચાવી_attr));
	ચાવી_attr[0].type = CKA_ID;
	ચાવી_attr[1].type = CKA_MODULUS;
	ચાવી_attr[2].type = CKA_PUBLIC_EXPONENT;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_કિંમત(session, *obj, ચાવી_attr, 3);
	જો (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		પાછા (ખાલી);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	જો (ચાવી_attr[1].ul_કિંમત_Len == 0 ||
	    ચાવી_attr[2].ul_કિંમત_Len == 0) {
		error("invalid attribute length");
		પાછા (ખાલી);
	}

	/* allocate buffers for attributes */
	માટે (i = 0; i < 3; i++)
		જો (ચાવી_attr[i].ul_કિંમત_Len > 0)
			ચાવી_attr[i].p_કિંમત = xcalloc(1, ચાવી_attr[i].ul_કિંમત_Len);

	/* retrieve ID, modulus and public exponent of RSA key */
	rv = f->C_Get_Attribute_કિંમત(session, *obj, ચાવી_attr, 3);
	જો (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		જાઓ fail;
	}

	rsa = RSA_new();
	જો (rsa == ખાલી) {
		error("RSA_new failed");
		જાઓ fail;
	}

	rsa_n = BN_bin2bn(ચાવી_attr[1].p_કિંમત, ચાવી_attr[1].ul_કિંમત_Len, ખાલી);
	rsa_e = BN_bin2bn(ચાવી_attr[2].p_કિંમત, ચાવી_attr[2].ul_કિંમત_Len, ખાલી);
	જો (rsa_n == ખાલી || rsa_e == ખાલી) {
		error("BN_bin2bn failed");
		જાઓ fail;
	}
	જો (!RSA_set0_ચાવી(rsa, rsa_n, rsa_e, ખાલી))
		fatal_f("set key");
	rsa_n = rsa_e = ખાલી; /* transferred */

	ચાવી = sshkey_new(ચાવી_UNSPEC);
	જો (ચાવી == ખાલી) {
		error("sshkey_new failed");
		જાઓ fail;
	}

	EVP_PKEY_free(ચાવી->pkey);
	જો ((ચાવી->pkey = EVP_PKEY_new()) == ખાલી)
		fatal("EVP_PKEY_new failed");
	જો (EVP_PKEY_set1_RSA(ચાવી->pkey, rsa) != 1)
		fatal("EVP_PKEY_set1_RSA failed");
	ચાવી->type = ચાવી_RSA;
	ચાવી->flags |= SSHKEY_FLAG_EXT;
	જો (EVP_PKEY_bits(ચાવી->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE) {
		error_f("RSA key too small %d < minimum %d",
		    EVP_PKEY_bits(ચાવી->pkey), SSH_RSA_MINIMUM_MODULUS_SIZE);
		જાઓ fail;
	}
	જો (pkcs11_record_ચાવી(p, slotidx, &ચાવી_attr[0], ચાવી))
		જાઓ fail;
	/* success */
	success = 0;
fail:
	માટે (i = 0; i < 3; i++)
		મુક્ત(ચાવી_attr[i].p_કિંમત);
	RSA_free(rsa);
	જો (success != 0) {
		sshkey_free(ચાવી);
		ચાવી = ખાલી;
	}
	પાછા ચાવી;
}
#endif /* WITH_OPENSSL */

સ્થિર સંરચના sshkey *
pkcs11_fetch_ed25519_pubkey(સંરચના pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 ચાવી_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ખાલી;
	CK_RV			 rv;
	સંરચના sshkey		*ચાવી = ખાલી;
	અચલ unsigned અક્ષર	*d = ખાલી;
	size_t			len;
	અક્ષર			*hex = ખાલી;
	પૂર્ણાંક			 success = -1, i;
	/* https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061180 */
	અચલ u_char		 id1[14] = {
		0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64,
		0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
	}; /* PrintableString { "edwards25519" } */
	અચલ u_char		 id2[5] = {
		0x06, 0x03, 0x2b, 0x65, 0x70,
	}; /* OBJECT_IDENTIFIER { 1.3.101.112 } */

	memset(&ચાવી_attr, 0, કદ(ચાવી_attr));
	ચાવી_attr[0].type = CKA_ID;
	ચાવી_attr[1].type = CKA_EC_POINT; /* XXX or CKA_VALUE ? */
	ચાવી_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_કિંમત(session, *obj, ચાવી_attr, 3);
	જો (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		પાછા (ખાલી);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	જો (ચાવી_attr[1].ul_કિંમત_Len == 0 ||
	    ચાવી_attr[2].ul_કિંમત_Len == 0) {
		error("invalid attribute length");
		પાછા (ખાલી);
	}

	/* allocate buffers for attributes */
	માટે (i = 0; i < 3; i++) {
		જો (ચાવી_attr[i].ul_કિંમત_Len > 0)
			ચાવી_attr[i].p_કિંમત = xcalloc(1, ચાવી_attr[i].ul_કિંમત_Len);
	}

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_કિંમત(session, *obj, ચાવી_attr, 3);
	જો (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		જાઓ fail;
	}

	/* Expect one of the supported identifiers in CKA_EC_PARAMS */
	d = (u_char *)ચાવી_attr[2].p_કિંમત;
	len = ચાવી_attr[2].ul_કિંમત_Len;
	જો ((len != કદ(id1) || memcmp(d, id1, કદ(id1)) != 0) &&
	    (len != કદ(id2) || memcmp(d, id2, કદ(id2)) != 0)) {
		hex = tohex(d, len);
		logit_f("unsupported CKA_EC_PARAMS: %s (len %zu)", hex, len);
		જાઓ fail;
	}

	/*
	 * Expect either a raw 32 byte pubkey or an OCTET STRING with
	 * a 32 byte pubkey in CKA_VALUE
	 */
	d = (u_char *)ચાવી_attr[1].p_કિંમત;
	len = ચાવી_attr[1].ul_કિંમત_Len;
	જો (len == ED25519_PK_SZ + 2 && d[0] == 0x04 && d[1] == ED25519_PK_SZ) {
		d += 2;
		len -= 2;
	}
	જો (len != ED25519_PK_SZ) {
		hex = tohex(ચાવી_attr[1].p_કિંમત, ચાવી_attr[1].ul_કિંમત_Len);
		logit_f("CKA_EC_POINT invalid octet str: %s (len %lu)",
		    hex, (u_long)ચાવી_attr[1].ul_કિંમત_Len);
		જાઓ fail;
	}

	જો ((ચાવી = sshkey_new(ચાવી_UNSPEC)) == ખાલી)
		fatal_f("sshkey_new failed");
	ચાવી->ed25519_pk = xmalloc(ED25519_PK_SZ);
	memcpy(ચાવી->ed25519_pk, d, ED25519_PK_SZ);
	ચાવી->type = ચાવી_ED25519;
	ચાવી->flags |= SSHKEY_FLAG_EXT;
	જો (pkcs11_record_ચાવી(p, slotidx, &ચાવી_attr[0], ચાવી))
		જાઓ fail;
	/* success */
	success = 0;
 fail:
	જો (success != 0) {
		sshkey_free(ચાવી);
		ચાવી = ખાલી;
	}
	મુક્ત(hex);
	માટે (i = 0; i < 3; i++)
		મુક્ત(ચાવી_attr[i].p_કિંમત);
	પાછા ચાવી;
}

#ifdef WITH_OPENSSL
સ્થિર પૂર્ણાંક
pkcs11_fetch_x509_pubkey(સંરચના pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj, સંરચના sshkey **keyp, અક્ષર **labelp)
{
	CK_ATTRIBUTE		 cert_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ખાલી;
	CK_RV			 rv;
	X509			*x509 = ખાલી;
	X509_NAME		*x509_name = ખાલી;
	EVP_PKEY		*evp;
	RSA			*rsa = ખાલી;
	EC_ચાવી			*ec = ખાલી;
	સંરચના sshkey		*ચાવી = ખાલી;
	પૂર્ણાંક			 r, i, nid, success = -1;
	અચલ u_char		*cp;
	અક્ષર			*subject = ખાલી;
#ifdef OPENSSL_HAS_ED25519
	size_t			len;
#endif /* OPENSSL_HAS_ED25519 */

	*keyp = ખાલી;
	*labelp = ખાલી;

	memset(&cert_attr, 0, કદ(cert_attr));
	cert_attr[0].type = CKA_ID;
	cert_attr[1].type = CKA_SUBJECT;
	cert_attr[2].type = CKA_કિંમત;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_કિંમત(session, *obj, cert_attr, 3);
	જો (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		પાછા -1;
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	જો (cert_attr[1].ul_કિંમત_Len == 0 ||
	    cert_attr[2].ul_કિંમત_Len == 0) {
		error("invalid attribute length");
		પાછા -1;
	}

	/* allocate buffers for attributes */
	માટે (i = 0; i < 3; i++)
		જો (cert_attr[i].ul_કિંમત_Len > 0)
			cert_attr[i].p_કિંમત = xcalloc(1, cert_attr[i].ul_કિંમત_Len);

	/* retrieve ID, subject and value of certificate */
	rv = f->C_Get_Attribute_કિંમત(session, *obj, cert_attr, 3);
	જો (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		જાઓ out;
	}

	/* Decode DER-encoded cert subject */
	cp = cert_attr[1].p_કિંમત;
	જો ((x509_name = d2i_X509_NAME(ખાલી, &cp,
	    cert_attr[1].ul_કિંમત_Len)) == ખાલી ||
	    (subject = X509_NAME_oneline(x509_name, ખાલી, 0)) == ખાલી)
		subject = xstrdup("invalid subject");
	X509_NAME_free(x509_name);

	cp = cert_attr[2].p_કિંમત;
	જો ((x509 = d2i_X509(ખાલી, &cp, cert_attr[2].ul_કિંમત_Len)) == ખાલી) {
		error("d2i_x509 failed");
		જાઓ out;
	}

	જો ((evp = X509_get_pubkey(x509)) == ખાલી) {
		error("X509_get_pubkey failed");
		જાઓ out;
	}

	જો (EVP_PKEY_base_id(evp) == EVP_PKEY_RSA) {
		જો (EVP_PKEY_get0_RSA(evp) == ખાલી) {
			error("invalid x509; no rsa key");
			જાઓ out;
		}
		જો ((rsa = RSAPublic_ચાવી_dup(EVP_PKEY_get0_RSA(evp))) == ખાલી) {
			error("RSAPublicKey_dup failed");
			જાઓ out;
		}

		ચાવી = sshkey_new(ચાવી_UNSPEC);
		જો (ચાવી == ખાલી) {
			error("sshkey_new failed");
			જાઓ out;
		}

		EVP_PKEY_free(ચાવી->pkey);
		જો ((ચાવી->pkey = EVP_PKEY_new()) == ખાલી)
			fatal("EVP_PKEY_new failed");
		જો (EVP_PKEY_set1_RSA(ચાવી->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		ચાવી->type = ચાવી_RSA;
		ચાવી->flags |= SSHKEY_FLAG_EXT;
		જો (EVP_PKEY_bits(ચાવી->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE) {
			error_f("RSA key too small %d < minimum %d",
			    EVP_PKEY_bits(ચાવી->pkey),
			    SSH_RSA_MINIMUM_MODULUS_SIZE);
			જાઓ out;
		}
		જો (pkcs11_record_ચાવી(p, slotidx, &cert_attr[0], ચાવી))
			જાઓ out;
		/* success */
		success = 0;
	} નહીંતર જો (EVP_PKEY_base_id(evp) == EVP_PKEY_EC) {
		જો (EVP_PKEY_get0_EC_ચાવી(evp) == ખાલી) {
			error("invalid x509; no ec key");
			જાઓ out;
		}
		જો ((ec = EC_ચાવી_dup(EVP_PKEY_get0_EC_ચાવી(evp))) == ખાલી) {
			error("EC_KEY_dup failed");
			જાઓ out;
		}
		જો ((r = sshkey_ec_validate_public(EC_ચાવી_get0_group(ec),
		    EC_ચાવી_get0_public_ચાવી(ec))) != 0) {
			error_fr(r, "invalid EC key");
			જાઓ out;
		}
		nid = sshkey_ecdsa_ચાવી_to_nid(ec);
		જો (nid < 0) {
			error("couldn't get curve nid");
			જાઓ out;
		}

		ચાવી = sshkey_new(ચાવી_UNSPEC);
		જો (ચાવી == ખાલી) {
			error("sshkey_new failed");
			જાઓ out;
		}

		EVP_PKEY_free(ચાવી->pkey);
		જો ((ચાવી->pkey = EVP_PKEY_new()) == ખાલી)
			fatal("EVP_PKEY_new failed");
		જો (EVP_PKEY_set1_EC_ચાવી(ચાવી->pkey, ec) != 1)
			fatal("EVP_PKEY_set1_EC_KEY failed");
		ચાવી->ecdsa_nid = nid;
		ચાવી->type = ચાવી_ECDSA;
		ચાવી->flags |= SSHKEY_FLAG_EXT;
		જો (pkcs11_record_ચાવી(p, slotidx, &cert_attr[0], ચાવી))
			જાઓ out;
		/* success */
		success = 0;
#ifdef OPENSSL_HAS_ED25519
	} નહીંતર જો (EVP_PKEY_base_id(evp) == EVP_PKEY_ED25519) {
		જો ((ચાવી = sshkey_new(ચાવી_UNSPEC)) == ખાલી ||
		    (ચાવી->ed25519_pk = calloc(1, ED25519_PK_SZ)) == ખાલી)
			fatal_f("allocation failed");
		len = ED25519_PK_SZ;
		જો (!EVP_PKEY_get_raw_public_ચાવી(evp, ચાવી->ed25519_pk, &len)) {
			ossl_error("EVP_PKEY_get_raw_public_key failed");
			જાઓ out;
		}
		જો (len != ED25519_PK_SZ) {
			error_f("incorrect returned public key "
			    "length for ed25519");
			જાઓ out;
		}
		ચાવી->type = ચાવી_ED25519;
		ચાવી->flags |= SSHKEY_FLAG_EXT;
		જો (pkcs11_record_ચાવી(p, slotidx, &cert_attr[0], ચાવી))
			જાઓ out;
		/* success */
		success = 0;
#endif /* OPENSSL_HAS_ED25519 */
	} નહીંતર {
		error("unknown certificate key type");
		જાઓ out;
	}
 out:
	માટે (i = 0; i < 3; i++)
		મુક્ત(cert_attr[i].p_કિંમત);
	X509_free(x509);
	RSA_free(rsa);
	EC_ચાવી_free(ec);
	જો (success != 0 || ચાવી == ખાલી) {
		sshkey_free(ચાવી);
		મુક્ત(subject);
		પાછા -1;
	}
	/* success */
	*keyp = ચાવી;
	*labelp = subject;
	પાછા 0;
}
#endif /* WITH_OPENSSL */

સ્થિર શૂન્ય
note_ચાવી(સંરચના pkcs11_provider *p, CK_ULONG slotidx, અચલ અક્ષર *context,
    સંરચના sshkey *ચાવી)
{
	અક્ષર *fp;

	જો ((fp = sshkey_fingerprint(ચાવી, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ખાલી) {
		error_f("sshkey_fingerprint failed");
		પાછા;
	}
	debug2("%s: provider %s slot %lu: %s %s", context, p->name,
	    (u_long)slotidx, sshkey_type(ચાવી), fp);
	મુક્ત(fp);
}

#ifdef WITH_OPENSSL /* libcrypto needed for certificate parsing */
/*
 * lookup certificates for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
સ્થિર પૂર્ણાંક
pkcs11_fetch_certs(સંરચના pkcs11_provider *p, CK_ULONG slotidx,
    સંરચના sshkey ***keysp, અક્ષર ***labelsp, પૂર્ણાંક *nkeys)
{
	સંરચના sshkey		*ચાવી = ખાલી;
	CK_OBJECT_CLASS		 ચાવી_class;
	CK_ATTRIBUTE		 ચાવી_attr[1];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ખાલી;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	પૂર્ણાંક			 ret = -1;
	અક્ષર			*label;

	memset(&ચાવી_attr, 0, કદ(ચાવી_attr));
	memset(&obj, 0, કદ(obj));

	ચાવી_class = CKO_CERTIFICATE;
	ચાવી_attr[0].type = CKA_CLASS;
	ચાવી_attr[0].p_કિંમત = &ચાવી_class;
	ચાવી_attr[0].ul_કિંમત_Len = કદ(ચાવી_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, ચાવી_attr, 1);
	જો (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		જાઓ fail;
	}

	જ્યારે (1) {
		CK_CERTIFICATE_TYPE	ck_cert_type;

		rv = f->C_FindObjects(session, &obj, 1, &n);
		જો (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			જાઓ fail;
		}
		જો (n == 0)
			તોડો;

		memset(&ck_cert_type, 0, કદ(ck_cert_type));
		memset(&ચાવી_attr, 0, કદ(ચાવી_attr));
		ચાવી_attr[0].type = CKA_CERTIFICATE_TYPE;
		ચાવી_attr[0].p_કિંમત = &ck_cert_type;
		ચાવી_attr[0].ul_કિંમત_Len = કદ(ck_cert_type);

		rv = f->C_Get_Attribute_કિંમત(session, obj, ચાવી_attr, 1);
		જો (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			જાઓ fail;
		}

		ચાવી = ખાલી;
		label = ખાલી;
		પસંદગી (ck_cert_type) {
		સ્થિતિ CKC_X_509:
			જો (pkcs11_fetch_x509_pubkey(p, slotidx, &obj,
			    &ચાવી, &label) != 0) {
				debug_f("failed to fetch key");
				ચાલુ;
			}
			તોડો;
		મૂળભૂત:
			error("skipping unsupported certificate type %lu",
			    ck_cert_type);
			ચાલુ;
		}
		note_ચાવી(p, slotidx, __func__, ચાવી);
		જો (pkcs11_ચાવી_included(keysp, nkeys, ચાવી)) {
			debug2_f("key already included");
			sshkey_free(ચાવી);
		} નહીંતર {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, કદ(સંરચના sshkey *));
			(*keysp)[*nkeys] = ચાવી;
			જો (labelsp != ખાલી) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, કદ(અક્ષર *));
				(*labelsp)[*nkeys] = xstrdup((અક્ષર *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_FindObjectsFinal(session);
	જો (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	પાછા (ret);
}
#endif /* WITH_OPENSSL */

/*
 * lookup public keys for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
સ્થિર પૂર્ણાંક
pkcs11_fetch_ચાવીઓ(સંરચના pkcs11_provider *p, CK_ULONG slotidx,
    સંરચના sshkey ***keysp, અક્ષર ***labelsp, પૂર્ણાંક *nkeys)
{
	સંરચના sshkey		*ચાવી = ખાલી;
	CK_OBJECT_CLASS		 ચાવી_class;
	CK_ATTRIBUTE		 ચાવી_attr[2];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ખાલી;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	પૂર્ણાંક			 ret = -1;

	memset(&ચાવી_attr, 0, કદ(ચાવી_attr));
	memset(&obj, 0, કદ(obj));

	ચાવી_class = CKO_PUBLIC_ચાવી;
	ચાવી_attr[0].type = CKA_CLASS;
	ચાવી_attr[0].p_કિંમત = &ચાવી_class;
	ચાવી_attr[0].ul_કિંમત_Len = કદ(ચાવી_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, ચાવી_attr, 1);
	જો (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		જાઓ fail;
	}

	જ્યારે (1) {
		CK_ચાવી_TYPE	ck_ચાવી_type;
		CK_UTF8CHAR	label[256];

		rv = f->C_FindObjects(session, &obj, 1, &n);
		જો (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			જાઓ fail;
		}
		જો (n == 0)
			તોડો;

		memset(&ck_ચાવી_type, 0, કદ(ck_ચાવી_type));
		memset(&ચાવી_attr, 0, કદ(ચાવી_attr));
		ચાવી_attr[0].type = CKA_ચાવી_TYPE;
		ચાવી_attr[0].p_કિંમત = &ck_ચાવી_type;
		ચાવી_attr[0].ul_કિંમત_Len = કદ(ck_ચાવી_type);
		ચાવી_attr[1].type = CKA_LABEL;
		ચાવી_attr[1].p_કિંમત = &label;
		ચાવી_attr[1].ul_કિંમત_Len = કદ(label) - 1;

		rv = f->C_Get_Attribute_કિંમત(session, obj, ચાવી_attr, 2);
		જો (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			જાઓ fail;
		}

		label[ચાવી_attr[1].ul_કિંમત_Len] = '\0';

		પસંદગી (ck_ચાવી_type) {
#ifdef WITH_OPENSSL
		સ્થિતિ CKK_RSA:
			ચાવી = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			તોડો;
		સ્થિતિ CKK_ECDSA:
			ચાવી = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			તોડો;
#endif /* WITH_OPENSSL */
		સ્થિતિ CKK_EC_EDWARDS:
			ચાવી = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			તોડો;
		મૂળભૂત:
			/* XXX print key type? */
			ચાવી = ખાલી;
			error("skipping unsupported key type 0x%lx",
			    (u_long)ck_ચાવી_type);
		}

		જો (ચાવી == ખાલી) {
			debug_f("failed to fetch key");
			ચાલુ;
		}
		note_ચાવી(p, slotidx, __func__, ચાવી);
		જો (pkcs11_ચાવી_included(keysp, nkeys, ચાવી)) {
			debug2_f("key already included");
			sshkey_free(ચાવી);
		} નહીંતર {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, કદ(સંરચના sshkey *));
			(*keysp)[*nkeys] = ચાવી;
			જો (labelsp != ખાલી) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, કદ(અક્ષર *));
				(*labelsp)[*nkeys] = xstrdup((અક્ષર *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_FindObjectsFinal(session);
	જો (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	પાછા (ret);
}

#ifdef WITH_PKCS11_KEYGEN
#define FILL_ATTR(attr, idx, typ, val, len) \
	{ (attr[idx]).type=(typ); (attr[idx]).p_કિંમત=(val); (attr[idx]).ul_કિંમત_Len=len; idx++; }

સ્થિર સંરચના sshkey *
pkcs11_rsa_generate_private_ચાવી(સંરચના pkcs11_provider *p, CK_ULONG slotidx,
    અક્ષર *label, CK_ULONG bits, CK_BYTE keyid, uint32_t *err)
{
	સંરચના pkcs11_slotinfo	*si;
	અક્ષર			*plabel = label ? label : "";
	પૂર્ણાંક			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_ચાવી_2, priv_ચાવી;
	CK_ATTRIBUTE		 tpub[16], tpriv[16];
	CK_MECHANISM		 mech = {
	    CKM_RSA_PKCS_ચાવી_PAIR_GEN, NULL_PTR, 0
	};
	CK_BYTE			 pubExponent[] = {
	    0x01, 0x00, 0x01 /* RSA_F4 in bytes */
	};
	pubkey_filter[0].p_કિંમત = &pubkey_class;
	cert_filter[0].p_કિંમત = &cert_class;

	*err = 0;

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, કદ(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, કદ(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, કદ(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    કદ(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, કદ(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, કદ(false_val));
	FILL_ATTR(tpub, npub, CKA_MODULUS_BITS, &bits, કદ(bits));
	FILL_ATTR(tpub, npub, CKA_PUBLIC_EXPONENT, pubExponent,
	    કદ(pubExponent));
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, કદ(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN,  &true_val, કદ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL,  plabel, strlen(plabel));
	FILL_ATTR(tpriv, npriv, CKA_PRIVATE,  &true_val, કદ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE,  &true_val, કદ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT,  &false_val, કદ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN,  &true_val, કદ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER,  &false_val,
	    કદ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP,  &false_val, કદ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE,  &false_val, કદ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, કદ(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	જો ((rv = f->C_Generate_ચાવી_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_ચાવી_2, &priv_ચાવી)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		પાછા ખાલી;
	}

	પાછા pkcs11_fetch_rsa_pubkey(p, slotidx, &pub_ચાવી_2);
}

સ્થિર પૂર્ણાંક
h2i(અક્ષર c)
{
	જો (c >= '0' && c <= '9')
		પાછા c - '0';
	નહીંતર જો (c >= 'a' && c <= 'f')
		પાછા c - 'a' + 10;
	નહીંતર જો (c >= 'A' && c <= 'F')
		પાછા c - 'A' + 10;
	નહીંતર
		પાછા -1;
}

સ્થિર પૂર્ણાંક
pkcs11_decode_hex(અચલ અક્ષર *hex, unsigned અક્ષર **dest, size_t *rlen)
{
	size_t	i, len;

	જો (dest)
		*dest = ખાલી;
	જો (rlen)
		*rlen = 0;

	જો ((len = strlen(hex)) % 2)
		પાછા -1;
	len /= 2;

	*dest = xmalloc(len);

	માટે (i = 0; i < len; i++) {
		પૂર્ણાંક hi, lo;

		hi = h2i(hex[2 * i]);
		lo = h2i(hex[(2 * i) + 1]);
		જો (hi == -1 || lo == -1)
			પાછા -1;
		(*dest)[i] = (hi << 4) | lo;
	}

	જો (rlen)
		*rlen = len;

	પાછા 0;
}

સ્થિર સંરચના ec_curve_info {
	અચલ અક્ષર	*name;
	અચલ અક્ષર	*oid;
	અચલ અક્ષર	*oid_encoded;
	size_t		 size;
} ec_curve_infos[] = {
	{"prime256v1",	"1.2.840.10045.3.1.7",	"06082A8648CE3D030107", 256},
	{"secp384r1",	"1.3.132.0.34",		"06052B81040022",	384},
	{"secp521r1",	"1.3.132.0.35",		"06052B81040023",	521},
	{ખાલી,		ખાલી,			ખાલી,			0},
};

સ્થિર સંરચના sshkey *
pkcs11_ecdsa_generate_private_ચાવી(સંરચના pkcs11_provider *p, CK_ULONG slotidx,
    અક્ષર *label, CK_ULONG bits, CK_BYTE keyid, uint32_t *err)
{
	સંરચના pkcs11_slotinfo	*si;
	અક્ષર			*plabel = label ? label : "";
	પૂર્ણાંક			 i;
	size_t			 ecparams_size;
	unsigned અક્ષર		*ecparams = ખાલી;
	પૂર્ણાંક			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_ચાવી_2, priv_ચાવી;
	CK_MECHANISM		 mech = {
	    CKM_EC_ચાવી_PAIR_GEN, NULL_PTR, 0
	};
	CK_ATTRIBUTE		 tpub[16], tpriv[16];

	*err = 0;

	માટે (i = 0; ec_curve_infos[i].name; i++) {
		જો (ec_curve_infos[i].size == bits)
			તોડો;
	}
	જો (!ec_curve_infos[i].name) {
		error_f("invalid key size %lu", bits);
		પાછા ખાલી;
	}
	જો (pkcs11_decode_hex(ec_curve_infos[i].oid_encoded, &ecparams,
	    &ecparams_size) == -1) {
		error_f("invalid oid");
		પાછા ખાલી;
	}

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, કદ(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, કદ(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, કદ(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    કદ(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, કદ(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, કદ(false_val));
	FILL_ATTR(tpub, npub, CKA_EC_PARAMS, ecparams, ecparams_size);
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, કદ(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN, &true_val, કદ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpriv, npriv, CKA_PRIVATE, &true_val, કદ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE, &true_val, કદ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT, &false_val, કદ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN, &true_val, કદ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER, &false_val,
	    કદ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP, &false_val, કદ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE, &false_val, કદ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, કદ(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	જો ((rv = f->C_Generate_ચાવી_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_ચાવી_2, &priv_ચાવી)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		પાછા ખાલી;
	}

	પાછા pkcs11_fetch_ecdsa_pubkey(p, slotidx, &pub_ચાવી_2);
}
#endif /* WITH_PKCS11_KEYGEN */

/*
 * register a new provider, fails if provider already exists. if
 * keyp is provided, fetch keys.
 */
સ્થિર પૂર્ણાંક
pkcs11_register_provider(અક્ષર *provider_id, અક્ષર *pin,
    સંરચના sshkey ***keyp, અક્ષર ***labelsp,
    સંરચના pkcs11_provider **providerp, CK_ULONG user)
{
	પૂર્ણાંક nkeys, need_finalize = 0;
	પૂર્ણાંક ret = -1;
	સંરચના pkcs11_provider *p = ખાલી;
	શૂન્ય *handle = ખાલી;
	CK_RV (*getfunctionlist)(CK_FUNCTION_LIST **);
	CK_RV rv;
	CK_FUNCTION_LIST *f = ખાલી;
	CK_TOKEN_INFO *token;
	CK_ULONG i;

	જો (providerp == ખાલી)
		જાઓ fail;
	*providerp = ખાલી;

	જો (keyp != ખાલી)
		*keyp = ખાલી;
	જો (labelsp != ખાલી)
		*labelsp = ખાલી;

	જો (pkcs11_provider_lookup(provider_id) != ખાલી) {
		debug_f("provider already registered: %s", provider_id);
		જાઓ fail;
	}
	જો (lib_contains_પ્રતીક(provider_id, "C_GetFunctionList") != 0) {
		error("provider %s is not a PKCS11 library", provider_id);
		જાઓ fail;
	}
	/* open shared pkcs11-library */
	જો ((handle = dlopen(provider_id, RTLD_NOW)) == ખાલી) {
		error("dlopen %s failed: %s", provider_id, dlerror());
		જાઓ fail;
	}
	જો ((getfunctionlist = dlsym(handle, "C_GetFunctionList")) == ખાલી)
		fatal("dlsym(C_GetFunctionList) failed: %s", dlerror());
	p = xcalloc(1, કદ(*p));
	p->name = xstrdup(provider_id);
	p->handle = handle;
	/* set up the pkcs11 callbacks */
	જો ((rv = (*getfunctionlist)(&f)) != CKR_OK) {
		error("C_GetFunctionList for provider %s failed: %lu",
		    provider_id, rv);
		જાઓ fail;
	}
	p->function_list = f;
	જો ((rv = f->C_Initialize(ખાલી)) != CKR_OK) {
		error("C_Initialize for provider %s failed: %lu",
		    provider_id, rv);
		જાઓ fail;
	}
	need_finalize = 1;
	જો ((rv = f->C_GetInfo(&p->info)) != CKR_OK) {
		error("C_GetInfo for provider %s failed: %lu",
		    provider_id, rv);
		જાઓ fail;
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
	જો ((rv = f->C_GetSlotList(CK_TRUE, ખાલી, &p->nslots)) != CKR_OK) {
		error("C_GetSlotList failed: %lu", rv);
		જાઓ fail;
	}
	જો (p->nslots == 0) {
		debug_f("provider %s returned no slots", provider_id);
		ret = -SSH_PKCS11_ERR_NO_SLOTS;
		જાઓ fail;
	}
	p->slotlist = xcalloc(p->nslots, કદ(CK_SLOT_ID));
	જો ((rv = f->C_GetSlotList(CK_TRUE, p->slotlist, &p->nslots))
	    != CKR_OK) {
		error("C_GetSlotList for provider %s failed: %lu",
		    provider_id, rv);
		જાઓ fail;
	}
	p->slotinfo = xcalloc(p->nslots, કદ(સંરચના pkcs11_slotinfo));
	p->valid = 1;
	nkeys = 0;
	માટે (i = 0; i < p->nslots; i++) {
		token = &p->slotinfo[i].token;
		જો ((rv = f->C_GetTokenInfo(p->slotlist[i], token))
		    != CKR_OK) {
			error("C_GetTokenInfo for provider %s slot %lu "
			    "failed: %lu", provider_id, (u_long)i, rv);
			ચાલુ;
		}
		જો ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
			debug2_f("ignoring uninitialised token in "
			    "provider %s slot %lu", provider_id, (u_long)i);
			ચાલુ;
		}
		debug("provider %s slot %lu: label <%.*s> "
		    "manufacturerID <%.*s> model <%.*s> serial <%.*s> "
		    "flags 0x%lx",
		    provider_id, (unsigned long)i,
		    RMSPACE(token->label), RMSPACE(token->manufacturerID),
		    RMSPACE(token->model), RMSPACE(token->serial_સંખ્યા_2),
		    token->flags);
		/*
		 * open session, login with pin and retrieve public
		 * keys (if keyp is provided)
		 */
		જો ((ret = pkcs11_open_session(p, i, pin, user)) != 0 ||
		    keyp == ખાલી)
			ચાલુ;
		pkcs11_fetch_ચાવીઓ(p, i, keyp, labelsp, &nkeys);
#ifdef WITH_OPENSSL
		pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#endif
		જો (nkeys == 0 && !p->slotinfo[i].logged_in &&
		    pkcs11_interactive) {
			/*
			 * Some tokens require login before they will
			 * expose keys.
			 */
			જો (pkcs11_login_slot(p, &p->slotinfo[i],
			    CKU_USER) < 0) {
				error("login failed");
				ચાલુ;
			}
			pkcs11_fetch_ચાવીઓ(p, i, keyp, labelsp, &nkeys);
#ifdef WITH_OPENSSL
			pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#endif
		}
	}

	/* now owned by caller */
	*providerp = p;

	TAILQ_INSERT_TAIL(&pkcs11_providers, p, next);
	p->refcount++;	/* add to provider list */

	પાછા (nkeys);
fail:
	જો (need_finalize && (rv = f->C_Finalize(ખાલી)) != CKR_OK)
		error("C_Finalize for provider %s failed: %lu",
		    provider_id, rv);
	જો (p) {
		મુક્ત(p->name);
		મુક્ત(p->slotlist);
		મુક્ત(p->slotinfo);
		મુક્ત(p);
	}
	જો (handle)
		dlclose(handle);
	જો (ret > 0)
		ret = -1;
	પાછા (ret);
}

પૂર્ણાંક
pkcs11_init(પૂર્ણાંક interactive)
{
	debug3_f("called, interactive = %d", interactive);

	pkcs11_interactive = interactive;
	TAILQ_INIT(&pkcs11_providers);
	TAILQ_INIT(&pkcs11_ચાવીઓ);
	પાછા (0);
}

/* unregister all providers, keys might still point to the providers */
શૂન્ય
pkcs11_terminate(શૂન્ય)
{
	સંરચના pkcs11_provider *p;
	સંરચના pkcs11_ચાવી *k11;

	debug3_f("called");

	જ્યારે ((k11 = TAILQ_FIRST(&pkcs11_ચાવીઓ)) != ખાલી) {
		TAILQ_REMOVE(&pkcs11_ચાવીઓ, k11, next);
		pkcs11_k11_free(k11);
	}
	જ્યારે ((p = TAILQ_FIRST(&pkcs11_providers)) != ખાલી) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
}

/*
 * register a new provider and get number of keys hold by the token,
 * fails if provider already exists
 */
પૂર્ણાંક
pkcs11_add_provider(અક્ષર *provider_id, અક્ષર *pin, સંરચના sshkey ***keyp,
    અક્ષર ***labelsp)
{
	સંરચના pkcs11_provider *p = ખાલી;
	પૂર્ણાંક nkeys;

	nkeys = pkcs11_register_provider(provider_id, pin, keyp, labelsp,
	    &p, CKU_USER);

	/* no keys found or some other error, de-register provider */
	જો (nkeys <= 0 && p != ખાલી) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
	જો (nkeys == 0)
		debug_f("provider %s returned no keys", provider_id);

	પાછા (nkeys);
}

પૂર્ણાંક
pkcs11_sign(સંરચના sshkey *ચાવી,
    u_char **sigp, size_t *lenp,
    અચલ u_char *data, size_t datalen,
    અચલ અક્ષર *alg, અચલ અક્ષર *sk_provider,
    અચલ અક્ષર *sk_pin, u_int compat)
{
	પસંદગી (ચાવી->type) {
#ifdef WITH_OPENSSL
	સ્થિતિ ચાવી_RSA:
	સ્થિતિ ચાવી_RSA_CERT:
		પાછા pkcs11_sign_rsa(ચાવી, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	સ્થિતિ ચાવી_ECDSA:
	સ્થિતિ ચાવી_ECDSA_CERT:
		પાછા pkcs11_sign_ecdsa(ચાવી, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
#endif /* WITH_OPENSSL */
	સ્થિતિ ચાવી_ED25519:
	સ્થિતિ ચાવી_ED25519_CERT:
		પાછા pkcs11_sign_ed25519(ચાવી, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	મૂળભૂત:
		પાછા SSH_ERR_ચાવી_TYPE_UNKNOWN;
	}
}

શૂન્ય
pkcs11_ચાવી_free(સંરચના sshkey *ચાવી)
{
	/* never called */
}

#ifdef WITH_PKCS11_KEYGEN
સંરચના sshkey *
pkcs11_gakp(અક્ષર *provider_id, અક્ષર *pin, unsigned પૂર્ણાંક slotidx, અક્ષર *label,
    unsigned પૂર્ણાંક type, unsigned પૂર્ણાંક bits, unsigned અક્ષર keyid, uint32_t *err)
{
	સંરચના pkcs11_provider	*p = ખાલી;
	સંરચના pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	સંરચના sshkey		*k = ખાલી;
	પૂર્ણાંક			 ret = -1, reset_pin = 0, reset_provider = 0;
	CK_RV			 rv;

	*err = 0;

	જો ((p = pkcs11_provider_lookup(provider_id)) != ખાલી)
		debug_f("provider \"%s\" available", provider_id);
	નહીંતર જો ((ret = pkcs11_register_provider(provider_id, pin, ખાલી, ખાલી,
	    &p, CKU_SO)) < 0) {
		debug_f("could not register provider %s", provider_id);
		જાઓ out;
	} નહીંતર
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	જો ((rv = f->C_SetOperationState(session , pin, strlen(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} નહીંતર
		reset_pin = 1;

	પસંદગી (type) {
	સ્થિતિ ચાવી_RSA:
		જો ((k = pkcs11_rsa_generate_private_ચાવી(p, slotidx, label,
		    bits, keyid, err)) == ખાલી) {
			debug_f("failed to generate RSA key");
			જાઓ out;
		}
		તોડો;
	સ્થિતિ ચાવી_ECDSA:
		જો ((k = pkcs11_ecdsa_generate_private_ચાવી(p, slotidx, label,
		    bits, keyid, err)) == ખાલી) {
			debug_f("failed to generate ECDSA key");
			જાઓ out;
		}
		તોડો;
	મૂળભૂત:
		*err = SSH_PKCS11_ERR_GENERIC;
		debug_f("unknown type %d", type);
		જાઓ out;
	}

out:
	જો (reset_pin)
		f->C_SetOperationState(session , ખાલી, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	જો (reset_provider)
		pkcs11_del_provider(provider_id);

	પાછા (k);
}

સંરચના sshkey *
pkcs11_destroy_keypair(અક્ષર *provider_id, અક્ષર *pin, unsigned long slotidx,
    unsigned અક્ષર keyid, uint32_t *err)
{
	સંરચના pkcs11_provider	*p = ખાલી;
	સંરચના pkcs11_slotinfo	*si;
	સંરચના sshkey		*k = ખાલી;
	પૂર્ણાંક			 reset_pin = 0, reset_provider = 0;
	CK_ULONG		 nattrs;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_ATTRIBUTE		 attrs[16];
	CK_OBJECT_CLASS		 ચાવી_class;
	CK_ચાવી_TYPE		 ચાવી_type;
	CK_OBJECT_HANDLE	 obj = CK_INVALID_HANDLE;
	CK_RV			 rv;

	*err = 0;

	જો ((p = pkcs11_provider_lookup(provider_id)) != ખાલી) {
		debug_f("using provider \"%s\"", provider_id);
	} નહીંતર જો (pkcs11_register_provider(provider_id, pin, ખાલી, ખાલી, &p,
	    CKU_SO) < 0) {
		debug_f("could not register provider %s",
		    provider_id);
		જાઓ out;
	} નહીંતર
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	જો ((rv = f->C_SetOperationState(session , pin, strlen(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} નહીંતર
		reset_pin = 1;

	/* private key */
	nattrs = 0;
	ચાવી_class = CKO_PRIVATE_ચાવી;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &ચાવી_class, કદ(ચાવી_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, કદ(keyid));

	જો (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {
		જો ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy private key 0x%hhx",
			    keyid);
			*err = rv;
			જાઓ out;
		}
	}

	/* public key */
	nattrs = 0;
	ચાવી_class = CKO_PUBLIC_ચાવી;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &ચાવી_class, કદ(ચાવી_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, કદ(keyid));

	જો (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {

		/* get key type */
		nattrs = 0;
		FILL_ATTR(attrs, nattrs, CKA_ચાવી_TYPE, &ચાવી_type,
		    કદ(ચાવી_type));
		rv = f->C_Get_Attribute_કિંમત(session, obj, attrs, nattrs);
		જો (rv != CKR_OK) {
			debug_f("could not get key type of public key 0x%hhx",
			    keyid);
			*err = rv;
			ચાવી_type = -1;
		}
		પસંદગી (ચાવી_type) {
#ifdef WITH_OPENSSL
		સ્થિતિ CKK_RSA:
			k = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			તોડો;
		સ્થિતિ CKK_ECDSA:
			k = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			તોડો;
#endif /* WITH_OPENSSL */
		સ્થિતિ CKK_EC_EDWARDS:
			k = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			તોડો;
		મૂળભૂત:
			debug_f("unsupported key type %lu", (u_long)ચાવી_type);
			તોડો;
		}

		જો ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy public key 0x%hhx", keyid);
			*err = rv;
			જાઓ out;
		}
	}

out:
	જો (reset_pin)
		f->C_SetOperationState(session , ખાલી, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	જો (reset_provider)
		pkcs11_del_provider(provider_id);

	પાછા (k);
}
#endif /* WITH_PKCS11_KEYGEN */
#નહીંતર /* ENABLE_PKCS11 */

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "ssh-pkcs11.h"

પૂર્ણાંક
pkcs11_init(પૂર્ણાંક interactive)
{
	error_f("PKCS#11 not supported");
	પાછા (-1);
}

પૂર્ણાંક
pkcs11_add_provider(અક્ષર *provider_id, અક્ષર *pin, સંરચના sshkey ***keyp,
    અક્ષર ***labelsp)
{
	error_f("PKCS#11 not supported");
	પાછા (-1);
}

શૂન્ય
pkcs11_ચાવી_free(સંરચના sshkey *ચાવી)
{
	error_f("PKCS#11 not supported");
}

પૂર્ણાંક
pkcs11_sign(સંરચના sshkey *ચાવી,
    u_char **sigp, size_t *lenp,
    અચલ u_char *data, size_t datalen,
    અચલ અક્ષર *alg, અચલ અક્ષર *sk_provider,
    અચલ અક્ષર *sk_pin, u_int compat)
{
	error_f("PKCS#11 not supported");
	પાછા SSH_ERR_FEATURE_UNSUPPORTED;
}

શૂન્ય
pkcs11_terminate(શૂન્ય)
{
	error_f("PKCS#11 not supported");
}
#endif /* ENABLE_PKCS11 */
