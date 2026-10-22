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

#অন্তর্ভাব "includes.h"

#ifdef ENABLE_PKCS11

#অন্তর্ভাব <sys/time.h>

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/queue.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>

#অন্তর্ভাব <string.h>
#অন্তর্ভাব <dlfcn.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব "openbsd-compat/openssl-compat.h"
#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/ecdsa.h>
#অন্তর্ভাব <openssl/x509.h>
#অন্তর্ভাব <openssl/err.h>
#endif

#define CRYPTOKI_COMPAT
#অন্তর্ভাব "pkcs11.h"

#define SSHKEY_INTERNAL
#অন্তর্ভাব "sshkey.h"

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssh-pkcs11.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "crypto_api.h"

সংরচনা pkcs11_slotinfo {
	CK_TOKEN_INFO		token;
	CK_SESSION_HANDLE	session;
	পূর্ণাঙ্ক			logged_in;
};

সংরচনা pkcs11_provider {
	বর্ণ			*name;
	শূন্য			*handle;
	CK_FUNCTION_LIST	*function_list;
	CK_INFO			info;
	CK_ULONG		nslots;
	CK_SLOT_ID		*slotlist;
	সংরচনা pkcs11_slotinfo	*slotinfo;
	পূর্ণাঙ্ক			valid;
	পূর্ণাঙ্ক			refcount;
	TAILQ_ENTRY(pkcs11_provider) next;
};

TAILQ_HEAD(, pkcs11_provider) pkcs11_providers;

সংরচনা pkcs11_চাবি {
	সংরচনা sshbuf		*keyblob;
	সংরচনা pkcs11_provider	*provider;
	CK_ULONG		slotidx;
	বর্ণ			*keyid;
	পূর্ণাঙ্ক			keyid_len;
	TAILQ_ENTRY(pkcs11_চাবি)	next;
};

TAILQ_HEAD(, pkcs11_চাবি) pkcs11_চাবিগুলি; /* XXX a tree would be better */

পূর্ণাঙ্ক pkcs11_interactive = 0;

#ifdef WITH_OPENSSL
স্থির শূন্য
ossl_error(ধ্রুব বর্ণ *বার্তা)
{
	unsigned long    e;

	error_f("%s", বার্তা);
	যাবত্ ((e = ERR_get_error()) != 0)
		error_f("libcrypto error: %s", ERR_error_string(e, রিক্ত));
}
#endif

/*
 * finalize a provider shared library, it's no longer usable.
 * however, there might still be keys referencing this provider,
 * so the actual freeing of memory is handled by pkcs11_provider_unref().
 * this is called when a provider gets unregistered.
 */
স্থির শূন্য
pkcs11_provider_finalize(সংরচনা pkcs11_provider *p)
{
	CK_RV rv;
	CK_ULONG i;

	debug_f("provider \"%s\" refcount %d valid %d",
	    p->name, p->refcount, p->valid);
	যদি (!p->valid)
		প্রত্যাগম;
	প্রতি (i = 0; i < p->nslots; i++) {
		যদি (p->slotinfo[i].session &&
		    (rv = p->function_list->C_CloseSession(
		    p->slotinfo[i].session)) != CKR_OK)
			error("C_CloseSession failed: %lu", rv);
	}
	যদি ((rv = p->function_list->C_Finalize(রিক্ত)) != CKR_OK)
		error("C_Finalize failed: %lu", rv);
	p->valid = 0;
	p->function_list = রিক্ত;
	dlclose(p->handle);
}

/*
 * remove a reference to the provider.
 * called when a key gets destroyed or when the provider is unregistered.
 */
স্থির শূন্য
pkcs11_provider_unref(সংরচনা pkcs11_provider *p)
{
	debug_f("provider \"%s\" refcount %d", p->name, p->refcount);
	যদি (--p->refcount <= 0) {
		যদি (p->valid)
			error_f("provider \"%s\" still valid", p->name);
		মুক্ত(p->name);
		মুক্ত(p->slotlist);
		মুক্ত(p->slotinfo);
		মুক্ত(p);
	}
}

/* lookup provider by name */
স্থির সংরচনা pkcs11_provider *
pkcs11_provider_lookup(বর্ণ *provider_id)
{
	সংরচনা pkcs11_provider *p;

	TAILQ_FOREACH(p, &pkcs11_providers, next) {
		debug("check provider \"%s\"", p->name);
		যদি (!strcmp(provider_id, p->name))
			প্রত্যাগম (p);
	}
	প্রত্যাগম (রিক্ত);
}

/* unregister provider by name */
পূর্ণাঙ্ক
pkcs11_del_provider(বর্ণ *provider_id)
{
	সংরচনা pkcs11_provider *p;

	যদি ((p = pkcs11_provider_lookup(provider_id)) != রিক্ত) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
		প্রত্যাগম (0);
	}
	প্রত্যাগম (-1);
}

/* release a wrapped object */
স্থির শূন্য
pkcs11_k11_free(সংরচনা pkcs11_চাবি *k11)
{
	যদি (k11 == রিক্ত)
		প্রত্যাগম;
	যদি (k11->provider)
		pkcs11_provider_unref(k11->provider);
	মুক্ত(k11->keyid);
	sshbuf_free(k11->keyblob);
	মুক্ত(k11);
}

/* find a single 'obj' for given attributes */
স্থির পূর্ণাঙ্ক
pkcs11_find(সংরচনা pkcs11_provider *p, CK_ULONG slotidx, CK_ATTRIBUTE *attr,
    CK_ULONG nattr, CK_OBJECT_HANDLE *obj)
{
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	session;
	CK_ULONG		nfound = 0;
	CK_RV			rv;
	পূর্ণাঙ্ক			ret = -1;

	f = p->function_list;
	session = p->slotinfo[slotidx].session;
	যদি ((rv = f->C_FindObjectsInit(session, attr, nattr)) != CKR_OK) {
		error("C_FindObjectsInit failed (nattr %lu): %lu", nattr, rv);
		প্রত্যাগম (-1);
	}
	যদি ((rv = f->C_FindObjects(session, obj, 1, &nfound)) != CKR_OK ||
	    nfound != 1) {
		debug("C_FindObjects failed (nfound %lu nattr %lu): %lu",
		    nfound, nattr, rv);
	} অন্যথা
		ret = 0;
	যদি ((rv = f->C_FindObjectsFinal(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	প্রত্যাগম (ret);
}

স্থির পূর্ণাঙ্ক
pkcs11_login_slot(সংরচনা pkcs11_provider *provider, সংরচনা pkcs11_slotinfo *si,
    CK_USER_TYPE type)
{
	বর্ণ			*pin = রিক্ত, prompt[1024];
	CK_RV			 rv;

	যদি (provider == রিক্ত || si == রিক্ত || !provider->valid) {
		error("no pkcs11 (valid) provider found");
		প্রত্যাগম (-1);
	}

	যদি (!pkcs11_interactive) {
		error("need pin entry%s",
		    (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH) ?
		    " on reader keypad" : "");
		প্রত্যাগম (-1);
	}
	যদি (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
		verbose("Deferring PIN entry to reader keypad.");
	অন্যথা {
		snprintf(prompt, পরিমাণ(prompt), "Enter PIN for '%s': ",
		    si->token.label);
		যদি ((pin = read_passphrase(prompt, RP_ALLOW_EOF)) == রিক্ত) {
			debug_f("no pin specified");
			প্রত্যাগম (-1);	/* bail out */
		}
	}
	rv = provider->function_list->C_Login(si->session, type, (u_char *)pin,
	    (pin != রিক্ত) ? strlen(pin) : 0);
	যদি (pin != রিক্ত)
		freezero(pin, strlen(pin));

	বিকল্প (rv) {
	পক্ষ CKR_OK:
	পক্ষ CKR_USER_ALREADY_LOGGED_IN:
		/* success */
		ভঙ্গ;
	পক্ষ CKR_PIN_LEN_RANGE:
		error("PKCS#11 login failed: PIN length out of range");
		প্রত্যাগম -1;
	পক্ষ CKR_PIN_INCORRECT:
		error("PKCS#11 login failed: PIN incorrect");
		প্রত্যাগম -1;
	পক্ষ CKR_PIN_LOCKED:
		error("PKCS#11 login failed: PIN locked");
		প্রত্যাগম -1;
	স্বভাব:
		error("PKCS#11 login failed: error %lu", rv);
		প্রত্যাগম -1;
	}
	si->logged_in = 1;
	প্রত্যাগম (0);
}

স্থির পূর্ণাঙ্ক
pkcs11_login(সংরচনা pkcs11_চাবি *k11, CK_USER_TYPE type)
{
	যদি (k11 == রিক্ত || k11->provider == রিক্ত || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		প্রত্যাগম (-1);
	}

	প্রত্যাগম pkcs11_login_slot(k11->provider,
	    &k11->provider->slotinfo[k11->slotidx], type);
}


স্থির পূর্ণাঙ্ক
pkcs11_check_obj_bool_attrib(সংরচনা pkcs11_চাবি *k11, CK_OBJECT_HANDLE obj,
    CK_ATTRIBUTE_TYPE type, পূর্ণাঙ্ক *val)
{
	সংরচনা pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_BBOOL		flag = 0;
	CK_ATTRIBUTE		attr;
	CK_RV			 rv;

	*val = 0;

	যদি (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		প্রত্যাগম (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	attr.type = type;
	attr.p_মান = &flag;
	attr.ul_মান_Len = পরিমাণ(flag);

	rv = f->C_Get_Attribute_মান(si->session, obj, &attr, 1);
	যদি (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		প্রত্যাগম (-1);
	}
	*val = flag != 0;
	debug_f("provider \"%s\" slot %lu object %lu: attrib %lu = %d",
	    k11->provider->name, k11->slotidx, obj, type, *val);
	প্রত্যাগম (0);
}

স্থির পূর্ণাঙ্ক
pkcs11_get_চাবি(সংরচনা pkcs11_চাবি *k11, CK_MECHANISM_TYPE mech_type)
{
	সংরচনা pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	 obj;
	CK_RV			 rv;
	CK_OBJECT_CLASS		 private_চাবি_class;
	CK_BBOOL		 true_val;
	CK_MECHANISM		 mech;
	CK_ATTRIBUTE		 চাবি_filter[3];
	পূর্ণাঙ্ক			 always_auth = 0;
	পূর্ণাঙ্ক			 did_login = 0;

	যদি (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		প্রত্যাগম (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	যদি ((si->token.flags & CKF_LOGIN_REQUIRED) && !si->logged_in) {
		যদি (pkcs11_login(k11, CKU_USER) < 0) {
			error("login failed");
			প্রত্যাগম (-1);
		}
		did_login = 1;
	}

	memset(&চাবি_filter, 0, পরিমাণ(চাবি_filter));
	private_চাবি_class = CKO_PRIVATE_চাবি;
	চাবি_filter[0].type = CKA_CLASS;
	চাবি_filter[0].p_মান = &private_চাবি_class;
	চাবি_filter[0].ul_মান_Len = পরিমাণ(private_চাবি_class);

	চাবি_filter[1].type = CKA_ID;
	চাবি_filter[1].p_মান = k11->keyid;
	চাবি_filter[1].ul_মান_Len = k11->keyid_len;

	true_val = CK_TRUE;
	চাবি_filter[2].type = CKA_SIGN;
	চাবি_filter[2].p_মান = &true_val;
	চাবি_filter[2].ul_মান_Len = পরিমাণ(true_val);

	/* try to find object w/CKA_SIGN first, retry w/o */
	যদি (pkcs11_find(k11->provider, k11->slotidx, চাবি_filter, 3, &obj) < 0 &&
	    pkcs11_find(k11->provider, k11->slotidx, চাবি_filter, 2, &obj) < 0) {
		error("cannot find private key");
		প্রত্যাগম (-1);
	}

	memset(&mech, 0, পরিমাণ(mech));
	mech.mechanism = mech_type;
	mech.pParameter = NULL_PTR;
	mech.ulParameterLen = 0;

	যদি ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
		প্রত্যাগম (-1);
	}

	pkcs11_check_obj_bool_attrib(k11, obj, CKA_ALWAYS_AUTHENTICATE,
	    &always_auth); /* ignore errors here */
	যদি (always_auth && !did_login) {
		debug_f("always-auth key");
		যদি (pkcs11_login(k11, CKU_CONTEXT_SPECIFIC) < 0) {
			error("login failed for always-auth key");
			প্রত্যাগম (-1);
		}
	}

	প্রত্যাগম (0);
}

/* record the key information later use lookup by keyblob */
স্থির পূর্ণাঙ্ক
pkcs11_record_চাবি(সংরচনা pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, সংরচনা sshkey *চাবি)
{
	সংরচনা sshbuf *keyblob;
	সংরচনা pkcs11_চাবি *k11;
	পূর্ণাঙ্ক r;
	বর্ণ *hex;

	hex = tohex(keyid_attrib->p_মান, keyid_attrib->ul_মান_Len);
	debug_f("%s key: provider %s slot %lu keyid %s",
	    sshkey_type(চাবি), provider->name, (u_long)slotidx, hex);
	মুক্ত(hex);

	যদি ((keyblob = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshkey_putb(চাবি, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");

	/* Check if we've already recorded this key in a different slot */
	TAILQ_FOREACH(k11, &pkcs11_চাবিগুলি, next) {
		যদি (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			hex = tohex(k11->keyid, k11->keyid_len);
			debug_f("Already seen this key at "
			    "provider %s slot %lu keyid %s",
			    k11->provider->name, k11->slotidx, hex);
			মুক্ত(hex);
			sshbuf_free(keyblob);
			প্রত্যাগম -1;
		}
	}

	k11 = xcalloc(1, পরিমাণ(*k11));
	k11->provider = provider;
	k11->keyblob = keyblob;
	provider->refcount++;	/* provider referenced by RSA key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ul_মান_Len;
	যদি (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len);
		memcpy(k11->keyid, keyid_attrib->p_মান, k11->keyid_len);
	}
	TAILQ_INSERT_TAIL(&pkcs11_চাবিগুলি, k11, next);

	প্রত্যাগম 0;
}

/* retrieve the key information by keyblob */
স্থির সংরচনা pkcs11_চাবি *
pkcs11_lookup_চাবি(সংরচনা sshkey *চাবি)
{
	সংরচনা pkcs11_চাবি *k11, *found = রিক্ত;
	সংরচনা sshbuf *keyblob;
	পূর্ণাঙ্ক r;

	যদি ((keyblob = sshbuf_new()) == রিক্ত)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshkey_putb(চাবি, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");
	TAILQ_FOREACH(k11, &pkcs11_চাবিগুলি, next) {
		যদি (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			found = k11;
			ভঙ্গ;
		}
	}
	sshbuf_free(keyblob);
	প্রত্যাগম found;
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
স্থির ধ্রুব u_char id_sha1[] = {
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
স্থির ধ্রুব u_char id_sha256[] = {
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
স্থির ধ্রুব u_char id_sha512[] = {
	0x30, 0x51, /* type Sequence, length 0x51 (81) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, /* id-sha512 */
	0x05, 0x00, /* NULL */
	0x04, 0x40  /* Octet string, length 0x40 (64), followed by sha512 hash */
};

স্থির পূর্ণাঙ্ক
rsa_hash_alg_oid(পূর্ণাঙ্ক hash_alg, ধ্রুব u_char **oidp, size_t *oidlenp)
{
	বিকল্প (hash_alg) {
	পক্ষ SSH_DIGEST_SHA1:
		*oidp = id_sha1;
		*oidlenp = পরিমাণ(id_sha1);
		ভঙ্গ;
	পক্ষ SSH_DIGEST_SHA256:
		*oidp = id_sha256;
		*oidlenp = পরিমাণ(id_sha256);
		ভঙ্গ;
	পক্ষ SSH_DIGEST_SHA512:
		*oidp = id_sha512;
		*oidlenp = পরিমাণ(id_sha512);
		ভঙ্গ;
	স্বভাব:
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
pkcs11_sign_rsa(সংরচনা sshkey *চাবি,
    u_char **sigp, size_t *lenp,
    ধ্রুব u_char *data, size_t datalen,
    ধ্রুব বর্ণ *alg, ধ্রুব বর্ণ *sk_provider,
    ধ্রুব বর্ণ *sk_pin, u_int compat)
{
	সংরচনা pkcs11_চাবি	*k11;
	সংরচনা pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	পূর্ণাঙ্ক			hashalg, r, diff, siglen, ret = -1;
	u_char			*oid_dgst = রিক্ত, *sig = রিক্ত;
	size_t			dgst_len, oid_len, oid_dgst_len = 0;
	ধ্রুব u_char		*oid;

	যদি (sigp != রিক্ত)
		*sigp = রিক্ত;
	যদি (lenp != রিক্ত)
		*lenp = 0;

	যদি ((k11 = pkcs11_lookup_চাবি(চাবি)) == রিক্ত) {
		error_f("no key found");
		প্রত্যাগম SSH_ERR_চাবি_NOT_FOUND;
	}

	debug3_f("sign with alg \"%s\" using provider %s slotidx %lu",
	    alg == রিক্ত ? "" : alg, k11->provider->name, (u_long)k11->slotidx);

	যদি (pkcs11_get_চাবি(k11, CKM_RSA_PKCS) == -1) {
		error("pkcs11_get_key failed");
		প্রত্যাগম SSH_ERR_AGENT_FAILURE;
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	যদি ((siglen = EVP_PKEY_size(চাবি->pkey)) <= 0)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* Determine hash algorithm and OID for signature */
	যদি (alg == রিক্ত || *alg == '\0')
		hashalg = SSH_DIGEST_SHA1;
	অন্যথা যদি ((hashalg = ssh_rsa_hash_id_from_keyname(alg)) == -1)
		fatal_f("couldn't determine RSA hash alg \"%s\"", alg);
	যদি ((r = rsa_hash_alg_oid(hashalg, &oid, &oid_len)) != 0)
		fatal_fr(r, "rsa_hash_alg_oid failed");
	যদি ((dgst_len = ssh_digest_bytes(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);

	/* Prepare { oid || digest } */
	oid_dgst_len = oid_len + dgst_len;
	oid_dgst = xcalloc(1, oid_dgst_len);
	memcpy(oid_dgst, oid, oid_len);
	যদি ((r = ssh_digest_memory(hashalg, data, datalen,
	    oid_dgst + oid_len, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	যদি ((rv = f->C_Sign(si->session, (CK_BYTE *)oid_dgst,
	    oid_dgst_len, sig, &slen)) != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		গচ্ছ done;
	}

	যদি (slen < (CK_ULONG)siglen) {
		diff = siglen - slen;
		debug3_f("repack %lu < %d (diff %d)",
		    (u_long)slen, siglen, diff);
		memmove(sig + diff, sig, slen);
		explicit_bzero(sig, diff);
	} অন্যথা যদি (slen > (size_t)siglen)
		fatal_f("bad C_Sign length");

	যদি ((ret = ssh_rsa_encode_store_sig(hashalg, sig, siglen,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	freezero(oid_dgst, oid_dgst_len);
	মুক্ত(sig);
	প্রত্যাগম ret;
}

স্থির পূর্ণাঙ্ক
pkcs11_sign_ecdsa(সংরচনা sshkey *চাবি,
    u_char **sigp, size_t *lenp,
    ধ্রুব u_char *data, size_t datalen,
    ধ্রুব বর্ণ *alg, ধ্রুব বর্ণ *sk_provider,
    ধ্রুব বর্ণ *sk_pin, u_int compat)
{
	সংরচনা pkcs11_চাবি	*k11;
	সংরচনা pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0, bnlen;
	CK_RV			rv;
	BIGNUM			*sig_r = রিক্ত, *sig_s = রিক্ত;
	u_char			*sig = রিক্ত, *dgst = রিক্ত;
	size_t			dgst_len = 0;
	পূর্ণাঙ্ক			hashalg, ret = -1, r, siglen;

	যদি (sigp != রিক্ত)
		*sigp = রিক্ত;
	যদি (lenp != রিক্ত)
		*lenp = 0;

	যদি ((k11 = pkcs11_lookup_চাবি(চাবি)) == রিক্ত) {
		error_f("no key found");
		প্রত্যাগম SSH_ERR_চাবি_NOT_FOUND;
	}

	যদি (pkcs11_get_চাবি(k11, CKM_ECDSA) == -1) {
		error("pkcs11_get_key failed");
		প্রত্যাগম SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	/* Prepare digest to be signed */
	যদি ((hashalg = sshkey_ec_nid_to_hash_alg(চাবি->ecdsa_nid)) == -1)
		fatal_f("couldn't determine ECDSA hash alg");
	যদি ((dgst_len = ssh_digest_bytes(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);
	dgst = xcalloc(1, dgst_len);
	যদি ((r = ssh_digest_memory(hashalg, data, datalen,
	    dgst, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	যদি ((siglen = EVP_PKEY_size(চাবি->pkey)) <= 0)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dgst_len, sig, &slen);
	যদি (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		গচ্ছ done;
	}
	যদি (slen < 64 || slen > 132 || slen % 2) {
		error_f("bad signature length: %lu", (u_long)slen);
		গচ্ছ done;
	}
	bnlen = slen/2;
	যদি ((sig_r = BN_bin2bn(sig, bnlen, রিক্ত)) == রিক্ত ||
	    (sig_s = BN_bin2bn(sig+bnlen, bnlen, রিক্ত)) == রিক্ত) {
		ossl_error("BN_bin2bn failed");
		গচ্ছ done;
	}

	যদি ((ret = ssh_ecdsa_encode_store_sig(চাবি, sig_r, sig_s,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	freezero(dgst, dgst_len);
	BN_free(sig_r);
	BN_free(sig_s);
	মুক্ত(sig);
	প্রত্যাগম ret;
}
#endif /* WITH_OPENSSL */

স্থির পূর্ণাঙ্ক
pkcs11_sign_ed25519(সংরচনা sshkey *চাবি,
    u_char **sigp, size_t *lenp,
    ধ্রুব u_char *data, size_t datalen,
    ধ্রুব বর্ণ *alg, ধ্রুব বর্ণ *sk_provider,
    ধ্রুব বর্ণ *sk_pin, u_int compat)
{
	সংরচনা pkcs11_চাবি	*k11;
	সংরচনা pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	u_char			*sig = রিক্ত;
	CK_BYTE			*xdata = রিক্ত;
	পূর্ণাঙ্ক			ret = -1;

	যদি (sigp != রিক্ত)
		*sigp = রিক্ত;
	যদি (lenp != রিক্ত)
		*lenp = 0;

	যদি ((k11 = pkcs11_lookup_চাবি(চাবি)) == রিক্ত) {
		error_f("no key found");
		প্রত্যাগম SSH_ERR_চাবি_NOT_FOUND;
	}

	যদি (pkcs11_get_চাবি(k11, CKM_EDDSA) == -1) {
		error("pkcs11_get_key failed");
		প্রত্যাগম SSH_ERR_AGENT_FAILURE;
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
	যদি (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		গচ্ছ done;
	}
	যদি (slen != crypto_sign_ed25519_BYTES) {
		error_f("bad signature length: %lu", (u_long)slen);
		গচ্ছ done;
	}
	যদি ((ret = ssh_ed25519_encode_store_sig(sig, slen, sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	যদি (xdata != রিক্ত)
		freezero(xdata, datalen);
	মুক্ত(sig);
	প্রত্যাগম ret;
}

/* remove trailing spaces */
স্থির বর্ণ *
rmspace(u_char *buf, size_t len)
{
	size_t i;

	যদি (len == 0)
		প্রত্যাগম buf;
	প্রতি (i = len - 1; i > 0; i--)
		যদি (buf[i] == ' ')
			buf[i] = '\0';
		অন্যথা
			ভঙ্গ;
	প্রত্যাগম buf;
}
/* Used to printf fixed-width, space-padded, unterminated strings using %.*s */
#define RMSPACE(s) (পূর্ণাঙ্ক)পরিমাণ(s), rmspace(s, পরিমাণ(s))

/*
 * open a pkcs11 session and login if required.
 * if pin == NULL we delay login until key use
 */
স্থির পূর্ণাঙ্ক
pkcs11_open_session(সংরচনা pkcs11_provider *p, CK_ULONG slotidx, বর্ণ *pin,
    CK_ULONG user)
{
	সংরচনা pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_RV			rv;
	CK_SESSION_HANDLE	session;
	পূর্ণাঙ্ক			login_required, ret;

	f = p->function_list;
	si = &p->slotinfo[slotidx];

	login_required = si->token.flags & CKF_LOGIN_REQUIRED;

	/* fail early before opening session */
	যদি (login_required && !pkcs11_interactive &&
	    (pin == রিক্ত || strlen(pin) == 0)) {
		error("pin required");
		প্রত্যাগম (-SSH_PKCS11_ERR_PIN_REQUIRED);
	}
	যদি ((rv = f->C_OpenSession(p->slotlist[slotidx], CKF_RW_SESSION|
	    CKF_SERIAL_SESSION, রিক্ত, রিক্ত, &session)) != CKR_OK) {
		error("C_OpenSession failed: %lu", rv);
		প্রত্যাগম (-1);
	}
	যদি (login_required && pin != রিক্ত && strlen(pin) != 0) {
		rv = f->C_Login(session, user, (u_char *)pin, strlen(pin));
		যদি (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
			error("C_Login failed: %lu", rv);
			ret = (rv == CKR_PIN_LOCKED) ?
			    -SSH_PKCS11_ERR_PIN_LOCKED :
			    -SSH_PKCS11_ERR_LOGIN_FAIL;
			যদি ((rv = f->C_CloseSession(session)) != CKR_OK)
				error("C_CloseSession failed: %lu", rv);
			প্রত্যাগম (ret);
		}
		si->logged_in = 1;
	}
	si->session = session;
	প্রত্যাগম (0);
}

স্থির পূর্ণাঙ্ক
pkcs11_চাবি_included(সংরচনা sshkey ***keysp, পূর্ণাঙ্ক *nkeys, সংরচনা sshkey *চাবি)
{
	পূর্ণাঙ্ক i;

	প্রতি (i = 0; i < *nkeys; i++)
		যদি (sshkey_equal(চাবি, (*keysp)[i]))
			প্রত্যাগম (1);
	প্রত্যাগম (0);
}

#ifdef WITH_OPENSSL
স্থির সংরচনা sshkey *
pkcs11_fetch_ecdsa_pubkey(সংরচনা pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 চাবি_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = রিক্ত;
	CK_RV			 rv;
	ASN1_OCTET_STRING	*octet = রিক্ত;
	EC_চাবি			*ec = রিক্ত;
	EC_GROUP		*group = রিক্ত;
	সংরচনা sshkey		*চাবি = রিক্ত;
	ধ্রুব unsigned বর্ণ	*attrp = রিক্ত;
	পূর্ণাঙ্ক			 success = -1, r, i, nid;

	memset(&চাবি_attr, 0, পরিমাণ(চাবি_attr));
	চাবি_attr[0].type = CKA_ID;
	চাবি_attr[1].type = CKA_EC_POINT;
	চাবি_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_মান(session, *obj, চাবি_attr, 3);
	যদি (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		প্রত্যাগম (রিক্ত);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	যদি (চাবি_attr[1].ul_মান_Len == 0 ||
	    চাবি_attr[2].ul_মান_Len == 0) {
		error("invalid attribute length");
		প্রত্যাগম (রিক্ত);
	}

	/* allocate buffers for attributes */
	প্রতি (i = 0; i < 3; i++)
		যদি (চাবি_attr[i].ul_মান_Len > 0)
			চাবি_attr[i].p_মান = xcalloc(1, চাবি_attr[i].ul_মান_Len);

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_মান(session, *obj, চাবি_attr, 3);
	যদি (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		গচ্ছ fail;
	}

	ec = EC_চাবি_new();
	যদি (ec == রিক্ত) {
		error("EC_KEY_new failed");
		গচ্ছ fail;
	}

	attrp = চাবি_attr[2].p_মান;
	group = d2i_ECPKParameters(রিক্ত, &attrp, চাবি_attr[2].ul_মান_Len);
	যদি (group == রিক্ত) {
		ossl_error("d2i_ECPKParameters failed");
		গচ্ছ fail;
	}

	যদি (EC_চাবি_set_group(ec, group) == 0) {
		ossl_error("EC_KEY_set_group failed");
		গচ্ছ fail;
	}

	যদি (চাবি_attr[1].ul_মান_Len <= 2) {
		error("CKA_EC_POINT too small");
		গচ্ছ fail;
	}

	attrp = চাবি_attr[1].p_মান;
	octet = d2i_ASN1_OCTET_STRING(রিক্ত, &attrp, চাবি_attr[1].ul_মান_Len);
	যদি (octet == রিক্ত) {
		ossl_error("d2i_ASN1_OCTET_STRING failed");
		গচ্ছ fail;
	}
	attrp = ASN1_STRING_get0_data(octet);
	যদি (o2i_ECPublic_চাবি(&ec, &attrp, ASN1_STRING_length(octet)) == রিক্ত) {
		ossl_error("o2i_ECPublicKey failed");
		গচ্ছ fail;
	}
	যদি ((r = sshkey_ec_validate_public(EC_চাবি_get0_group(ec),
	    EC_চাবি_get0_public_চাবি(ec))) != 0) {
		error_fr(r, "invalid EC key");
		গচ্ছ fail;
	}

	nid = sshkey_ecdsa_চাবি_to_nid(ec);
	যদি (nid < 0) {
		error("couldn't get curve nid");
		গচ্ছ fail;
	}

	চাবি = sshkey_new(চাবি_UNSPEC);
	যদি (চাবি == রিক্ত) {
		error("sshkey_new failed");
		গচ্ছ fail;
	}

	EVP_PKEY_free(চাবি->pkey);
	যদি ((চাবি->pkey = EVP_PKEY_new()) == রিক্ত)
		fatal("EVP_PKEY_new failed");
	যদি (EVP_PKEY_set1_EC_চাবি(চাবি->pkey, ec) != 1)
		fatal("EVP_PKEY_set1_EC_KEY failed");
	চাবি->ecdsa_nid = nid;
	চাবি->type = চাবি_ECDSA;
	চাবি->flags |= SSHKEY_FLAG_EXT;
	যদি (pkcs11_record_চাবি(p, slotidx, &চাবি_attr[0], চাবি))
		গচ্ছ fail;
	/* success */
	success = 0;
fail:
	যদি (success != 0) {
		sshkey_free(চাবি);
		চাবি = রিক্ত;
	}
	প্রতি (i = 0; i < 3; i++)
		মুক্ত(চাবি_attr[i].p_মান);
	যদি (ec)
		EC_চাবি_free(ec);
	যদি (group)
		EC_GROUP_free(group);
	যদি (octet)
		ASN1_OCTET_STRING_free(octet);

	প্রত্যাগম (চাবি);
}

স্থির সংরচনা sshkey *
pkcs11_fetch_rsa_pubkey(সংরচনা pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 চাবি_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = রিক্ত;
	CK_RV			 rv;
	RSA			*rsa = রিক্ত;
	BIGNUM			*rsa_n, *rsa_e;
	সংরচনা sshkey		*চাবি = রিক্ত;
	পূর্ণাঙ্ক			 i, success = -1;

	memset(&চাবি_attr, 0, পরিমাণ(চাবি_attr));
	চাবি_attr[0].type = CKA_ID;
	চাবি_attr[1].type = CKA_MODULUS;
	চাবি_attr[2].type = CKA_PUBLIC_EXPONENT;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_মান(session, *obj, চাবি_attr, 3);
	যদি (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		প্রত্যাগম (রিক্ত);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	যদি (চাবি_attr[1].ul_মান_Len == 0 ||
	    চাবি_attr[2].ul_মান_Len == 0) {
		error("invalid attribute length");
		প্রত্যাগম (রিক্ত);
	}

	/* allocate buffers for attributes */
	প্রতি (i = 0; i < 3; i++)
		যদি (চাবি_attr[i].ul_মান_Len > 0)
			চাবি_attr[i].p_মান = xcalloc(1, চাবি_attr[i].ul_মান_Len);

	/* retrieve ID, modulus and public exponent of RSA key */
	rv = f->C_Get_Attribute_মান(session, *obj, চাবি_attr, 3);
	যদি (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		গচ্ছ fail;
	}

	rsa = RSA_new();
	যদি (rsa == রিক্ত) {
		error("RSA_new failed");
		গচ্ছ fail;
	}

	rsa_n = BN_bin2bn(চাবি_attr[1].p_মান, চাবি_attr[1].ul_মান_Len, রিক্ত);
	rsa_e = BN_bin2bn(চাবি_attr[2].p_মান, চাবি_attr[2].ul_মান_Len, রিক্ত);
	যদি (rsa_n == রিক্ত || rsa_e == রিক্ত) {
		error("BN_bin2bn failed");
		গচ্ছ fail;
	}
	যদি (!RSA_set0_চাবি(rsa, rsa_n, rsa_e, রিক্ত))
		fatal_f("set key");
	rsa_n = rsa_e = রিক্ত; /* transferred */

	চাবি = sshkey_new(চাবি_UNSPEC);
	যদি (চাবি == রিক্ত) {
		error("sshkey_new failed");
		গচ্ছ fail;
	}

	EVP_PKEY_free(চাবি->pkey);
	যদি ((চাবি->pkey = EVP_PKEY_new()) == রিক্ত)
		fatal("EVP_PKEY_new failed");
	যদি (EVP_PKEY_set1_RSA(চাবি->pkey, rsa) != 1)
		fatal("EVP_PKEY_set1_RSA failed");
	চাবি->type = চাবি_RSA;
	চাবি->flags |= SSHKEY_FLAG_EXT;
	যদি (EVP_PKEY_bits(চাবি->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE) {
		error_f("RSA key too small %d < minimum %d",
		    EVP_PKEY_bits(চাবি->pkey), SSH_RSA_MINIMUM_MODULUS_SIZE);
		গচ্ছ fail;
	}
	যদি (pkcs11_record_চাবি(p, slotidx, &চাবি_attr[0], চাবি))
		গচ্ছ fail;
	/* success */
	success = 0;
fail:
	প্রতি (i = 0; i < 3; i++)
		মুক্ত(চাবি_attr[i].p_মান);
	RSA_free(rsa);
	যদি (success != 0) {
		sshkey_free(চাবি);
		চাবি = রিক্ত;
	}
	প্রত্যাগম চাবি;
}
#endif /* WITH_OPENSSL */

স্থির সংরচনা sshkey *
pkcs11_fetch_ed25519_pubkey(সংরচনা pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 চাবি_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = রিক্ত;
	CK_RV			 rv;
	সংরচনা sshkey		*চাবি = রিক্ত;
	ধ্রুব unsigned বর্ণ	*d = রিক্ত;
	size_t			len;
	বর্ণ			*hex = রিক্ত;
	পূর্ণাঙ্ক			 success = -1, i;
	/* https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061180 */
	ধ্রুব u_char		 id1[14] = {
		0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64,
		0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
	}; /* PrintableString { "edwards25519" } */
	ধ্রুব u_char		 id2[5] = {
		0x06, 0x03, 0x2b, 0x65, 0x70,
	}; /* OBJECT_IDENTIFIER { 1.3.101.112 } */

	memset(&চাবি_attr, 0, পরিমাণ(চাবি_attr));
	চাবি_attr[0].type = CKA_ID;
	চাবি_attr[1].type = CKA_EC_POINT; /* XXX or CKA_VALUE ? */
	চাবি_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_মান(session, *obj, চাবি_attr, 3);
	যদি (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		প্রত্যাগম (রিক্ত);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	যদি (চাবি_attr[1].ul_মান_Len == 0 ||
	    চাবি_attr[2].ul_মান_Len == 0) {
		error("invalid attribute length");
		প্রত্যাগম (রিক্ত);
	}

	/* allocate buffers for attributes */
	প্রতি (i = 0; i < 3; i++) {
		যদি (চাবি_attr[i].ul_মান_Len > 0)
			চাবি_attr[i].p_মান = xcalloc(1, চাবি_attr[i].ul_মান_Len);
	}

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_মান(session, *obj, চাবি_attr, 3);
	যদি (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		গচ্ছ fail;
	}

	/* Expect one of the supported identifiers in CKA_EC_PARAMS */
	d = (u_char *)চাবি_attr[2].p_মান;
	len = চাবি_attr[2].ul_মান_Len;
	যদি ((len != পরিমাণ(id1) || memcmp(d, id1, পরিমাণ(id1)) != 0) &&
	    (len != পরিমাণ(id2) || memcmp(d, id2, পরিমাণ(id2)) != 0)) {
		hex = tohex(d, len);
		logit_f("unsupported CKA_EC_PARAMS: %s (len %zu)", hex, len);
		গচ্ছ fail;
	}

	/*
	 * Expect either a raw 32 byte pubkey or an OCTET STRING with
	 * a 32 byte pubkey in CKA_VALUE
	 */
	d = (u_char *)চাবি_attr[1].p_মান;
	len = চাবি_attr[1].ul_মান_Len;
	যদি (len == ED25519_PK_SZ + 2 && d[0] == 0x04 && d[1] == ED25519_PK_SZ) {
		d += 2;
		len -= 2;
	}
	যদি (len != ED25519_PK_SZ) {
		hex = tohex(চাবি_attr[1].p_মান, চাবি_attr[1].ul_মান_Len);
		logit_f("CKA_EC_POINT invalid octet str: %s (len %lu)",
		    hex, (u_long)চাবি_attr[1].ul_মান_Len);
		গচ্ছ fail;
	}

	যদি ((চাবি = sshkey_new(চাবি_UNSPEC)) == রিক্ত)
		fatal_f("sshkey_new failed");
	চাবি->ed25519_pk = xmalloc(ED25519_PK_SZ);
	memcpy(চাবি->ed25519_pk, d, ED25519_PK_SZ);
	চাবি->type = চাবি_ED25519;
	চাবি->flags |= SSHKEY_FLAG_EXT;
	যদি (pkcs11_record_চাবি(p, slotidx, &চাবি_attr[0], চাবি))
		গচ্ছ fail;
	/* success */
	success = 0;
 fail:
	যদি (success != 0) {
		sshkey_free(চাবি);
		চাবি = রিক্ত;
	}
	মুক্ত(hex);
	প্রতি (i = 0; i < 3; i++)
		মুক্ত(চাবি_attr[i].p_মান);
	প্রত্যাগম চাবি;
}

#ifdef WITH_OPENSSL
স্থির পূর্ণাঙ্ক
pkcs11_fetch_x509_pubkey(সংরচনা pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj, সংরচনা sshkey **keyp, বর্ণ **labelp)
{
	CK_ATTRIBUTE		 cert_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = রিক্ত;
	CK_RV			 rv;
	X509			*x509 = রিক্ত;
	X509_NAME		*x509_name = রিক্ত;
	EVP_PKEY		*evp;
	RSA			*rsa = রিক্ত;
	EC_চাবি			*ec = রিক্ত;
	সংরচনা sshkey		*চাবি = রিক্ত;
	পূর্ণাঙ্ক			 r, i, nid, success = -1;
	ধ্রুব u_char		*cp;
	বর্ণ			*subject = রিক্ত;
#ifdef OPENSSL_HAS_ED25519
	size_t			len;
#endif /* OPENSSL_HAS_ED25519 */

	*keyp = রিক্ত;
	*labelp = রিক্ত;

	memset(&cert_attr, 0, পরিমাণ(cert_attr));
	cert_attr[0].type = CKA_ID;
	cert_attr[1].type = CKA_SUBJECT;
	cert_attr[2].type = CKA_মান;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_মান(session, *obj, cert_attr, 3);
	যদি (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		প্রত্যাগম -1;
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	যদি (cert_attr[1].ul_মান_Len == 0 ||
	    cert_attr[2].ul_মান_Len == 0) {
		error("invalid attribute length");
		প্রত্যাগম -1;
	}

	/* allocate buffers for attributes */
	প্রতি (i = 0; i < 3; i++)
		যদি (cert_attr[i].ul_মান_Len > 0)
			cert_attr[i].p_মান = xcalloc(1, cert_attr[i].ul_মান_Len);

	/* retrieve ID, subject and value of certificate */
	rv = f->C_Get_Attribute_মান(session, *obj, cert_attr, 3);
	যদি (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		গচ্ছ out;
	}

	/* Decode DER-encoded cert subject */
	cp = cert_attr[1].p_মান;
	যদি ((x509_name = d2i_X509_NAME(রিক্ত, &cp,
	    cert_attr[1].ul_মান_Len)) == রিক্ত ||
	    (subject = X509_NAME_oneline(x509_name, রিক্ত, 0)) == রিক্ত)
		subject = xstrdup("invalid subject");
	X509_NAME_free(x509_name);

	cp = cert_attr[2].p_মান;
	যদি ((x509 = d2i_X509(রিক্ত, &cp, cert_attr[2].ul_মান_Len)) == রিক্ত) {
		error("d2i_x509 failed");
		গচ্ছ out;
	}

	যদি ((evp = X509_get_pubkey(x509)) == রিক্ত) {
		error("X509_get_pubkey failed");
		গচ্ছ out;
	}

	যদি (EVP_PKEY_base_id(evp) == EVP_PKEY_RSA) {
		যদি (EVP_PKEY_get0_RSA(evp) == রিক্ত) {
			error("invalid x509; no rsa key");
			গচ্ছ out;
		}
		যদি ((rsa = RSAPublic_চাবি_dup(EVP_PKEY_get0_RSA(evp))) == রিক্ত) {
			error("RSAPublicKey_dup failed");
			গচ্ছ out;
		}

		চাবি = sshkey_new(চাবি_UNSPEC);
		যদি (চাবি == রিক্ত) {
			error("sshkey_new failed");
			গচ্ছ out;
		}

		EVP_PKEY_free(চাবি->pkey);
		যদি ((চাবি->pkey = EVP_PKEY_new()) == রিক্ত)
			fatal("EVP_PKEY_new failed");
		যদি (EVP_PKEY_set1_RSA(চাবি->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		চাবি->type = চাবি_RSA;
		চাবি->flags |= SSHKEY_FLAG_EXT;
		যদি (EVP_PKEY_bits(চাবি->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE) {
			error_f("RSA key too small %d < minimum %d",
			    EVP_PKEY_bits(চাবি->pkey),
			    SSH_RSA_MINIMUM_MODULUS_SIZE);
			গচ্ছ out;
		}
		যদি (pkcs11_record_চাবি(p, slotidx, &cert_attr[0], চাবি))
			গচ্ছ out;
		/* success */
		success = 0;
	} অন্যথা যদি (EVP_PKEY_base_id(evp) == EVP_PKEY_EC) {
		যদি (EVP_PKEY_get0_EC_চাবি(evp) == রিক্ত) {
			error("invalid x509; no ec key");
			গচ্ছ out;
		}
		যদি ((ec = EC_চাবি_dup(EVP_PKEY_get0_EC_চাবি(evp))) == রিক্ত) {
			error("EC_KEY_dup failed");
			গচ্ছ out;
		}
		যদি ((r = sshkey_ec_validate_public(EC_চাবি_get0_group(ec),
		    EC_চাবি_get0_public_চাবি(ec))) != 0) {
			error_fr(r, "invalid EC key");
			গচ্ছ out;
		}
		nid = sshkey_ecdsa_চাবি_to_nid(ec);
		যদি (nid < 0) {
			error("couldn't get curve nid");
			গচ্ছ out;
		}

		চাবি = sshkey_new(চাবি_UNSPEC);
		যদি (চাবি == রিক্ত) {
			error("sshkey_new failed");
			গচ্ছ out;
		}

		EVP_PKEY_free(চাবি->pkey);
		যদি ((চাবি->pkey = EVP_PKEY_new()) == রিক্ত)
			fatal("EVP_PKEY_new failed");
		যদি (EVP_PKEY_set1_EC_চাবি(চাবি->pkey, ec) != 1)
			fatal("EVP_PKEY_set1_EC_KEY failed");
		চাবি->ecdsa_nid = nid;
		চাবি->type = চাবি_ECDSA;
		চাবি->flags |= SSHKEY_FLAG_EXT;
		যদি (pkcs11_record_চাবি(p, slotidx, &cert_attr[0], চাবি))
			গচ্ছ out;
		/* success */
		success = 0;
#ifdef OPENSSL_HAS_ED25519
	} অন্যথা যদি (EVP_PKEY_base_id(evp) == EVP_PKEY_ED25519) {
		যদি ((চাবি = sshkey_new(চাবি_UNSPEC)) == রিক্ত ||
		    (চাবি->ed25519_pk = calloc(1, ED25519_PK_SZ)) == রিক্ত)
			fatal_f("allocation failed");
		len = ED25519_PK_SZ;
		যদি (!EVP_PKEY_get_raw_public_চাবি(evp, চাবি->ed25519_pk, &len)) {
			ossl_error("EVP_PKEY_get_raw_public_key failed");
			গচ্ছ out;
		}
		যদি (len != ED25519_PK_SZ) {
			error_f("incorrect returned public key "
			    "length for ed25519");
			গচ্ছ out;
		}
		চাবি->type = চাবি_ED25519;
		চাবি->flags |= SSHKEY_FLAG_EXT;
		যদি (pkcs11_record_চাবি(p, slotidx, &cert_attr[0], চাবি))
			গচ্ছ out;
		/* success */
		success = 0;
#endif /* OPENSSL_HAS_ED25519 */
	} অন্যথা {
		error("unknown certificate key type");
		গচ্ছ out;
	}
 out:
	প্রতি (i = 0; i < 3; i++)
		মুক্ত(cert_attr[i].p_মান);
	X509_free(x509);
	RSA_free(rsa);
	EC_চাবি_free(ec);
	যদি (success != 0 || চাবি == রিক্ত) {
		sshkey_free(চাবি);
		মুক্ত(subject);
		প্রত্যাগম -1;
	}
	/* success */
	*keyp = চাবি;
	*labelp = subject;
	প্রত্যাগম 0;
}
#endif /* WITH_OPENSSL */

স্থির শূন্য
note_চাবি(সংরচনা pkcs11_provider *p, CK_ULONG slotidx, ধ্রুব বর্ণ *context,
    সংরচনা sshkey *চাবি)
{
	বর্ণ *fp;

	যদি ((fp = sshkey_fingerprint(চাবি, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == রিক্ত) {
		error_f("sshkey_fingerprint failed");
		প্রত্যাগম;
	}
	debug2("%s: provider %s slot %lu: %s %s", context, p->name,
	    (u_long)slotidx, sshkey_type(চাবি), fp);
	মুক্ত(fp);
}

#ifdef WITH_OPENSSL /* libcrypto needed for certificate parsing */
/*
 * lookup certificates for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
স্থির পূর্ণাঙ্ক
pkcs11_fetch_certs(সংরচনা pkcs11_provider *p, CK_ULONG slotidx,
    সংরচনা sshkey ***keysp, বর্ণ ***labelsp, পূর্ণাঙ্ক *nkeys)
{
	সংরচনা sshkey		*চাবি = রিক্ত;
	CK_OBJECT_CLASS		 চাবি_class;
	CK_ATTRIBUTE		 চাবি_attr[1];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = রিক্ত;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	পূর্ণাঙ্ক			 ret = -1;
	বর্ণ			*label;

	memset(&চাবি_attr, 0, পরিমাণ(চাবি_attr));
	memset(&obj, 0, পরিমাণ(obj));

	চাবি_class = CKO_CERTIFICATE;
	চাবি_attr[0].type = CKA_CLASS;
	চাবি_attr[0].p_মান = &চাবি_class;
	চাবি_attr[0].ul_মান_Len = পরিমাণ(চাবি_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, চাবি_attr, 1);
	যদি (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		গচ্ছ fail;
	}

	যাবত্ (1) {
		CK_CERTIFICATE_TYPE	ck_cert_type;

		rv = f->C_FindObjects(session, &obj, 1, &n);
		যদি (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			গচ্ছ fail;
		}
		যদি (n == 0)
			ভঙ্গ;

		memset(&ck_cert_type, 0, পরিমাণ(ck_cert_type));
		memset(&চাবি_attr, 0, পরিমাণ(চাবি_attr));
		চাবি_attr[0].type = CKA_CERTIFICATE_TYPE;
		চাবি_attr[0].p_মান = &ck_cert_type;
		চাবি_attr[0].ul_মান_Len = পরিমাণ(ck_cert_type);

		rv = f->C_Get_Attribute_মান(session, obj, চাবি_attr, 1);
		যদি (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			গচ্ছ fail;
		}

		চাবি = রিক্ত;
		label = রিক্ত;
		বিকল্প (ck_cert_type) {
		পক্ষ CKC_X_509:
			যদি (pkcs11_fetch_x509_pubkey(p, slotidx, &obj,
			    &চাবি, &label) != 0) {
				debug_f("failed to fetch key");
				অনুবর্ত;
			}
			ভঙ্গ;
		স্বভাব:
			error("skipping unsupported certificate type %lu",
			    ck_cert_type);
			অনুবর্ত;
		}
		note_চাবি(p, slotidx, __func__, চাবি);
		যদি (pkcs11_চাবি_included(keysp, nkeys, চাবি)) {
			debug2_f("key already included");
			sshkey_free(চাবি);
		} অন্যথা {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, পরিমাণ(সংরচনা sshkey *));
			(*keysp)[*nkeys] = চাবি;
			যদি (labelsp != রিক্ত) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, পরিমাণ(বর্ণ *));
				(*labelsp)[*nkeys] = xstrdup((বর্ণ *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_FindObjectsFinal(session);
	যদি (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	প্রত্যাগম (ret);
}
#endif /* WITH_OPENSSL */

/*
 * lookup public keys for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
স্থির পূর্ণাঙ্ক
pkcs11_fetch_চাবিগুলি(সংরচনা pkcs11_provider *p, CK_ULONG slotidx,
    সংরচনা sshkey ***keysp, বর্ণ ***labelsp, পূর্ণাঙ্ক *nkeys)
{
	সংরচনা sshkey		*চাবি = রিক্ত;
	CK_OBJECT_CLASS		 চাবি_class;
	CK_ATTRIBUTE		 চাবি_attr[2];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = রিক্ত;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	পূর্ণাঙ্ক			 ret = -1;

	memset(&চাবি_attr, 0, পরিমাণ(চাবি_attr));
	memset(&obj, 0, পরিমাণ(obj));

	চাবি_class = CKO_PUBLIC_চাবি;
	চাবি_attr[0].type = CKA_CLASS;
	চাবি_attr[0].p_মান = &চাবি_class;
	চাবি_attr[0].ul_মান_Len = পরিমাণ(চাবি_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, চাবি_attr, 1);
	যদি (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		গচ্ছ fail;
	}

	যাবত্ (1) {
		CK_চাবি_TYPE	ck_চাবি_type;
		CK_UTF8CHAR	label[256];

		rv = f->C_FindObjects(session, &obj, 1, &n);
		যদি (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			গচ্ছ fail;
		}
		যদি (n == 0)
			ভঙ্গ;

		memset(&ck_চাবি_type, 0, পরিমাণ(ck_চাবি_type));
		memset(&চাবি_attr, 0, পরিমাণ(চাবি_attr));
		চাবি_attr[0].type = CKA_চাবি_TYPE;
		চাবি_attr[0].p_মান = &ck_চাবি_type;
		চাবি_attr[0].ul_মান_Len = পরিমাণ(ck_চাবি_type);
		চাবি_attr[1].type = CKA_LABEL;
		চাবি_attr[1].p_মান = &label;
		চাবি_attr[1].ul_মান_Len = পরিমাণ(label) - 1;

		rv = f->C_Get_Attribute_মান(session, obj, চাবি_attr, 2);
		যদি (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			গচ্ছ fail;
		}

		label[চাবি_attr[1].ul_মান_Len] = '\0';

		বিকল্প (ck_চাবি_type) {
#ifdef WITH_OPENSSL
		পক্ষ CKK_RSA:
			চাবি = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			ভঙ্গ;
		পক্ষ CKK_ECDSA:
			চাবি = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			ভঙ্গ;
#endif /* WITH_OPENSSL */
		পক্ষ CKK_EC_EDWARDS:
			চাবি = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			ভঙ্গ;
		স্বভাব:
			/* XXX print key type? */
			চাবি = রিক্ত;
			error("skipping unsupported key type 0x%lx",
			    (u_long)ck_চাবি_type);
		}

		যদি (চাবি == রিক্ত) {
			debug_f("failed to fetch key");
			অনুবর্ত;
		}
		note_চাবি(p, slotidx, __func__, চাবি);
		যদি (pkcs11_চাবি_included(keysp, nkeys, চাবি)) {
			debug2_f("key already included");
			sshkey_free(চাবি);
		} অন্যথা {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, পরিমাণ(সংরচনা sshkey *));
			(*keysp)[*nkeys] = চাবি;
			যদি (labelsp != রিক্ত) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, পরিমাণ(বর্ণ *));
				(*labelsp)[*nkeys] = xstrdup((বর্ণ *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_FindObjectsFinal(session);
	যদি (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	প্রত্যাগম (ret);
}

#ifdef WITH_PKCS11_KEYGEN
#define FILL_ATTR(attr, idx, typ, val, len) \
	{ (attr[idx]).type=(typ); (attr[idx]).p_মান=(val); (attr[idx]).ul_মান_Len=len; idx++; }

স্থির সংরচনা sshkey *
pkcs11_rsa_generate_private_চাবি(সংরচনা pkcs11_provider *p, CK_ULONG slotidx,
    বর্ণ *label, CK_ULONG bits, CK_BYTE keyid, uint32_t *err)
{
	সংরচনা pkcs11_slotinfo	*si;
	বর্ণ			*plabel = label ? label : "";
	পূর্ণাঙ্ক			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_চাবি_2, priv_চাবি;
	CK_ATTRIBUTE		 tpub[16], tpriv[16];
	CK_MECHANISM		 mech = {
	    CKM_RSA_PKCS_চাবি_PAIR_GEN, NULL_PTR, 0
	};
	CK_BYTE			 pubExponent[] = {
	    0x01, 0x00, 0x01 /* RSA_F4 in bytes */
	};
	pubkey_filter[0].p_মান = &pubkey_class;
	cert_filter[0].p_মান = &cert_class;

	*err = 0;

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, পরিমাণ(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, পরিমাণ(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, পরিমাণ(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    পরিমাণ(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, পরিমাণ(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, পরিমাণ(false_val));
	FILL_ATTR(tpub, npub, CKA_MODULUS_BITS, &bits, পরিমাণ(bits));
	FILL_ATTR(tpub, npub, CKA_PUBLIC_EXPONENT, pubExponent,
	    পরিমাণ(pubExponent));
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, পরিমাণ(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN,  &true_val, পরিমাণ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL,  plabel, strlen(plabel));
	FILL_ATTR(tpriv, npriv, CKA_PRIVATE,  &true_val, পরিমাণ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE,  &true_val, পরিমাণ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT,  &false_val, পরিমাণ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN,  &true_val, পরিমাণ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER,  &false_val,
	    পরিমাণ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP,  &false_val, পরিমাণ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE,  &false_val, পরিমাণ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, পরিমাণ(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	যদি ((rv = f->C_Generate_চাবি_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_চাবি_2, &priv_চাবি)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		প্রত্যাগম রিক্ত;
	}

	প্রত্যাগম pkcs11_fetch_rsa_pubkey(p, slotidx, &pub_চাবি_2);
}

স্থির পূর্ণাঙ্ক
h2i(বর্ণ c)
{
	যদি (c >= '0' && c <= '9')
		প্রত্যাগম c - '0';
	অন্যথা যদি (c >= 'a' && c <= 'f')
		প্রত্যাগম c - 'a' + 10;
	অন্যথা যদি (c >= 'A' && c <= 'F')
		প্রত্যাগম c - 'A' + 10;
	অন্যথা
		প্রত্যাগম -1;
}

স্থির পূর্ণাঙ্ক
pkcs11_decode_hex(ধ্রুব বর্ণ *hex, unsigned বর্ণ **dest, size_t *rlen)
{
	size_t	i, len;

	যদি (dest)
		*dest = রিক্ত;
	যদি (rlen)
		*rlen = 0;

	যদি ((len = strlen(hex)) % 2)
		প্রত্যাগম -1;
	len /= 2;

	*dest = xmalloc(len);

	প্রতি (i = 0; i < len; i++) {
		পূর্ণাঙ্ক hi, lo;

		hi = h2i(hex[2 * i]);
		lo = h2i(hex[(2 * i) + 1]);
		যদি (hi == -1 || lo == -1)
			প্রত্যাগম -1;
		(*dest)[i] = (hi << 4) | lo;
	}

	যদি (rlen)
		*rlen = len;

	প্রত্যাগম 0;
}

স্থির সংরচনা ec_curve_info {
	ধ্রুব বর্ণ	*name;
	ধ্রুব বর্ণ	*oid;
	ধ্রুব বর্ণ	*oid_encoded;
	size_t		 size;
} ec_curve_infos[] = {
	{"prime256v1",	"1.2.840.10045.3.1.7",	"06082A8648CE3D030107", 256},
	{"secp384r1",	"1.3.132.0.34",		"06052B81040022",	384},
	{"secp521r1",	"1.3.132.0.35",		"06052B81040023",	521},
	{রিক্ত,		রিক্ত,			রিক্ত,			0},
};

স্থির সংরচনা sshkey *
pkcs11_ecdsa_generate_private_চাবি(সংরচনা pkcs11_provider *p, CK_ULONG slotidx,
    বর্ণ *label, CK_ULONG bits, CK_BYTE keyid, uint32_t *err)
{
	সংরচনা pkcs11_slotinfo	*si;
	বর্ণ			*plabel = label ? label : "";
	পূর্ণাঙ্ক			 i;
	size_t			 ecparams_size;
	unsigned বর্ণ		*ecparams = রিক্ত;
	পূর্ণাঙ্ক			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_চাবি_2, priv_চাবি;
	CK_MECHANISM		 mech = {
	    CKM_EC_চাবি_PAIR_GEN, NULL_PTR, 0
	};
	CK_ATTRIBUTE		 tpub[16], tpriv[16];

	*err = 0;

	প্রতি (i = 0; ec_curve_infos[i].name; i++) {
		যদি (ec_curve_infos[i].size == bits)
			ভঙ্গ;
	}
	যদি (!ec_curve_infos[i].name) {
		error_f("invalid key size %lu", bits);
		প্রত্যাগম রিক্ত;
	}
	যদি (pkcs11_decode_hex(ec_curve_infos[i].oid_encoded, &ecparams,
	    &ecparams_size) == -1) {
		error_f("invalid oid");
		প্রত্যাগম রিক্ত;
	}

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, পরিমাণ(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, পরিমাণ(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, পরিমাণ(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    পরিমাণ(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, পরিমাণ(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, পরিমাণ(false_val));
	FILL_ATTR(tpub, npub, CKA_EC_PARAMS, ecparams, ecparams_size);
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, পরিমাণ(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN, &true_val, পরিমাণ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpriv, npriv, CKA_PRIVATE, &true_val, পরিমাণ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE, &true_val, পরিমাণ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT, &false_val, পরিমাণ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN, &true_val, পরিমাণ(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER, &false_val,
	    পরিমাণ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP, &false_val, পরিমাণ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE, &false_val, পরিমাণ(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, পরিমাণ(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	যদি ((rv = f->C_Generate_চাবি_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_চাবি_2, &priv_চাবি)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		প্রত্যাগম রিক্ত;
	}

	প্রত্যাগম pkcs11_fetch_ecdsa_pubkey(p, slotidx, &pub_চাবি_2);
}
#endif /* WITH_PKCS11_KEYGEN */

/*
 * register a new provider, fails if provider already exists. if
 * keyp is provided, fetch keys.
 */
স্থির পূর্ণাঙ্ক
pkcs11_register_provider(বর্ণ *provider_id, বর্ণ *pin,
    সংরচনা sshkey ***keyp, বর্ণ ***labelsp,
    সংরচনা pkcs11_provider **providerp, CK_ULONG user)
{
	পূর্ণাঙ্ক nkeys, need_finalize = 0;
	পূর্ণাঙ্ক ret = -1;
	সংরচনা pkcs11_provider *p = রিক্ত;
	শূন্য *handle = রিক্ত;
	CK_RV (*getfunctionlist)(CK_FUNCTION_LIST **);
	CK_RV rv;
	CK_FUNCTION_LIST *f = রিক্ত;
	CK_TOKEN_INFO *token;
	CK_ULONG i;

	যদি (providerp == রিক্ত)
		গচ্ছ fail;
	*providerp = রিক্ত;

	যদি (keyp != রিক্ত)
		*keyp = রিক্ত;
	যদি (labelsp != রিক্ত)
		*labelsp = রিক্ত;

	যদি (pkcs11_provider_lookup(provider_id) != রিক্ত) {
		debug_f("provider already registered: %s", provider_id);
		গচ্ছ fail;
	}
	যদি (lib_contains_প্রতীক(provider_id, "C_GetFunctionList") != 0) {
		error("provider %s is not a PKCS11 library", provider_id);
		গচ্ছ fail;
	}
	/* open shared pkcs11-library */
	যদি ((handle = dlopen(provider_id, RTLD_NOW)) == রিক্ত) {
		error("dlopen %s failed: %s", provider_id, dlerror());
		গচ্ছ fail;
	}
	যদি ((getfunctionlist = dlsym(handle, "C_GetFunctionList")) == রিক্ত)
		fatal("dlsym(C_GetFunctionList) failed: %s", dlerror());
	p = xcalloc(1, পরিমাণ(*p));
	p->name = xstrdup(provider_id);
	p->handle = handle;
	/* set up the pkcs11 callbacks */
	যদি ((rv = (*getfunctionlist)(&f)) != CKR_OK) {
		error("C_GetFunctionList for provider %s failed: %lu",
		    provider_id, rv);
		গচ্ছ fail;
	}
	p->function_list = f;
	যদি ((rv = f->C_Initialize(রিক্ত)) != CKR_OK) {
		error("C_Initialize for provider %s failed: %lu",
		    provider_id, rv);
		গচ্ছ fail;
	}
	need_finalize = 1;
	যদি ((rv = f->C_GetInfo(&p->info)) != CKR_OK) {
		error("C_GetInfo for provider %s failed: %lu",
		    provider_id, rv);
		গচ্ছ fail;
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
	যদি ((rv = f->C_GetSlotList(CK_TRUE, রিক্ত, &p->nslots)) != CKR_OK) {
		error("C_GetSlotList failed: %lu", rv);
		গচ্ছ fail;
	}
	যদি (p->nslots == 0) {
		debug_f("provider %s returned no slots", provider_id);
		ret = -SSH_PKCS11_ERR_NO_SLOTS;
		গচ্ছ fail;
	}
	p->slotlist = xcalloc(p->nslots, পরিমাণ(CK_SLOT_ID));
	যদি ((rv = f->C_GetSlotList(CK_TRUE, p->slotlist, &p->nslots))
	    != CKR_OK) {
		error("C_GetSlotList for provider %s failed: %lu",
		    provider_id, rv);
		গচ্ছ fail;
	}
	p->slotinfo = xcalloc(p->nslots, পরিমাণ(সংরচনা pkcs11_slotinfo));
	p->valid = 1;
	nkeys = 0;
	প্রতি (i = 0; i < p->nslots; i++) {
		token = &p->slotinfo[i].token;
		যদি ((rv = f->C_GetTokenInfo(p->slotlist[i], token))
		    != CKR_OK) {
			error("C_GetTokenInfo for provider %s slot %lu "
			    "failed: %lu", provider_id, (u_long)i, rv);
			অনুবর্ত;
		}
		যদি ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
			debug2_f("ignoring uninitialised token in "
			    "provider %s slot %lu", provider_id, (u_long)i);
			অনুবর্ত;
		}
		debug("provider %s slot %lu: label <%.*s> "
		    "manufacturerID <%.*s> model <%.*s> serial <%.*s> "
		    "flags 0x%lx",
		    provider_id, (unsigned long)i,
		    RMSPACE(token->label), RMSPACE(token->manufacturerID),
		    RMSPACE(token->model), RMSPACE(token->serial_সংখ্যা_2),
		    token->flags);
		/*
		 * open session, login with pin and retrieve public
		 * keys (if keyp is provided)
		 */
		যদি ((ret = pkcs11_open_session(p, i, pin, user)) != 0 ||
		    keyp == রিক্ত)
			অনুবর্ত;
		pkcs11_fetch_চাবিগুলি(p, i, keyp, labelsp, &nkeys);
#ifdef WITH_OPENSSL
		pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#endif
		যদি (nkeys == 0 && !p->slotinfo[i].logged_in &&
		    pkcs11_interactive) {
			/*
			 * Some tokens require login before they will
			 * expose keys.
			 */
			যদি (pkcs11_login_slot(p, &p->slotinfo[i],
			    CKU_USER) < 0) {
				error("login failed");
				অনুবর্ত;
			}
			pkcs11_fetch_চাবিগুলি(p, i, keyp, labelsp, &nkeys);
#ifdef WITH_OPENSSL
			pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#endif
		}
	}

	/* now owned by caller */
	*providerp = p;

	TAILQ_INSERT_TAIL(&pkcs11_providers, p, next);
	p->refcount++;	/* add to provider list */

	প্রত্যাগম (nkeys);
fail:
	যদি (need_finalize && (rv = f->C_Finalize(রিক্ত)) != CKR_OK)
		error("C_Finalize for provider %s failed: %lu",
		    provider_id, rv);
	যদি (p) {
		মুক্ত(p->name);
		মুক্ত(p->slotlist);
		মুক্ত(p->slotinfo);
		মুক্ত(p);
	}
	যদি (handle)
		dlclose(handle);
	যদি (ret > 0)
		ret = -1;
	প্রত্যাগম (ret);
}

পূর্ণাঙ্ক
pkcs11_init(পূর্ণাঙ্ক interactive)
{
	debug3_f("called, interactive = %d", interactive);

	pkcs11_interactive = interactive;
	TAILQ_INIT(&pkcs11_providers);
	TAILQ_INIT(&pkcs11_চাবিগুলি);
	প্রত্যাগম (0);
}

/* unregister all providers, keys might still point to the providers */
শূন্য
pkcs11_terminate(শূন্য)
{
	সংরচনা pkcs11_provider *p;
	সংরচনা pkcs11_চাবি *k11;

	debug3_f("called");

	যাবত্ ((k11 = TAILQ_FIRST(&pkcs11_চাবিগুলি)) != রিক্ত) {
		TAILQ_REMOVE(&pkcs11_চাবিগুলি, k11, next);
		pkcs11_k11_free(k11);
	}
	যাবত্ ((p = TAILQ_FIRST(&pkcs11_providers)) != রিক্ত) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
}

/*
 * register a new provider and get number of keys hold by the token,
 * fails if provider already exists
 */
পূর্ণাঙ্ক
pkcs11_add_provider(বর্ণ *provider_id, বর্ণ *pin, সংরচনা sshkey ***keyp,
    বর্ণ ***labelsp)
{
	সংরচনা pkcs11_provider *p = রিক্ত;
	পূর্ণাঙ্ক nkeys;

	nkeys = pkcs11_register_provider(provider_id, pin, keyp, labelsp,
	    &p, CKU_USER);

	/* no keys found or some other error, de-register provider */
	যদি (nkeys <= 0 && p != রিক্ত) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
	যদি (nkeys == 0)
		debug_f("provider %s returned no keys", provider_id);

	প্রত্যাগম (nkeys);
}

পূর্ণাঙ্ক
pkcs11_sign(সংরচনা sshkey *চাবি,
    u_char **sigp, size_t *lenp,
    ধ্রুব u_char *data, size_t datalen,
    ধ্রুব বর্ণ *alg, ধ্রুব বর্ণ *sk_provider,
    ধ্রুব বর্ণ *sk_pin, u_int compat)
{
	বিকল্প (চাবি->type) {
#ifdef WITH_OPENSSL
	পক্ষ চাবি_RSA:
	পক্ষ চাবি_RSA_CERT:
		প্রত্যাগম pkcs11_sign_rsa(চাবি, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	পক্ষ চাবি_ECDSA:
	পক্ষ চাবি_ECDSA_CERT:
		প্রত্যাগম pkcs11_sign_ecdsa(চাবি, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
#endif /* WITH_OPENSSL */
	পক্ষ চাবি_ED25519:
	পক্ষ চাবি_ED25519_CERT:
		প্রত্যাগম pkcs11_sign_ed25519(চাবি, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	স্বভাব:
		প্রত্যাগম SSH_ERR_চাবি_TYPE_UNKNOWN;
	}
}

শূন্য
pkcs11_চাবি_free(সংরচনা sshkey *চাবি)
{
	/* never called */
}

#ifdef WITH_PKCS11_KEYGEN
সংরচনা sshkey *
pkcs11_gakp(বর্ণ *provider_id, বর্ণ *pin, unsigned পূর্ণাঙ্ক slotidx, বর্ণ *label,
    unsigned পূর্ণাঙ্ক type, unsigned পূর্ণাঙ্ক bits, unsigned বর্ণ keyid, uint32_t *err)
{
	সংরচনা pkcs11_provider	*p = রিক্ত;
	সংরচনা pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	সংরচনা sshkey		*k = রিক্ত;
	পূর্ণাঙ্ক			 ret = -1, reset_pin = 0, reset_provider = 0;
	CK_RV			 rv;

	*err = 0;

	যদি ((p = pkcs11_provider_lookup(provider_id)) != রিক্ত)
		debug_f("provider \"%s\" available", provider_id);
	অন্যথা যদি ((ret = pkcs11_register_provider(provider_id, pin, রিক্ত, রিক্ত,
	    &p, CKU_SO)) < 0) {
		debug_f("could not register provider %s", provider_id);
		গচ্ছ out;
	} অন্যথা
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	যদি ((rv = f->C_SetOperationState(session , pin, strlen(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} অন্যথা
		reset_pin = 1;

	বিকল্প (type) {
	পক্ষ চাবি_RSA:
		যদি ((k = pkcs11_rsa_generate_private_চাবি(p, slotidx, label,
		    bits, keyid, err)) == রিক্ত) {
			debug_f("failed to generate RSA key");
			গচ্ছ out;
		}
		ভঙ্গ;
	পক্ষ চাবি_ECDSA:
		যদি ((k = pkcs11_ecdsa_generate_private_চাবি(p, slotidx, label,
		    bits, keyid, err)) == রিক্ত) {
			debug_f("failed to generate ECDSA key");
			গচ্ছ out;
		}
		ভঙ্গ;
	স্বভাব:
		*err = SSH_PKCS11_ERR_GENERIC;
		debug_f("unknown type %d", type);
		গচ্ছ out;
	}

out:
	যদি (reset_pin)
		f->C_SetOperationState(session , রিক্ত, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	যদি (reset_provider)
		pkcs11_del_provider(provider_id);

	প্রত্যাগম (k);
}

সংরচনা sshkey *
pkcs11_destroy_keypair(বর্ণ *provider_id, বর্ণ *pin, unsigned long slotidx,
    unsigned বর্ণ keyid, uint32_t *err)
{
	সংরচনা pkcs11_provider	*p = রিক্ত;
	সংরচনা pkcs11_slotinfo	*si;
	সংরচনা sshkey		*k = রিক্ত;
	পূর্ণাঙ্ক			 reset_pin = 0, reset_provider = 0;
	CK_ULONG		 nattrs;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_ATTRIBUTE		 attrs[16];
	CK_OBJECT_CLASS		 চাবি_class;
	CK_চাবি_TYPE		 চাবি_type;
	CK_OBJECT_HANDLE	 obj = CK_INVALID_HANDLE;
	CK_RV			 rv;

	*err = 0;

	যদি ((p = pkcs11_provider_lookup(provider_id)) != রিক্ত) {
		debug_f("using provider \"%s\"", provider_id);
	} অন্যথা যদি (pkcs11_register_provider(provider_id, pin, রিক্ত, রিক্ত, &p,
	    CKU_SO) < 0) {
		debug_f("could not register provider %s",
		    provider_id);
		গচ্ছ out;
	} অন্যথা
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	যদি ((rv = f->C_SetOperationState(session , pin, strlen(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} অন্যথা
		reset_pin = 1;

	/* private key */
	nattrs = 0;
	চাবি_class = CKO_PRIVATE_চাবি;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &চাবি_class, পরিমাণ(চাবি_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, পরিমাণ(keyid));

	যদি (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {
		যদি ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy private key 0x%hhx",
			    keyid);
			*err = rv;
			গচ্ছ out;
		}
	}

	/* public key */
	nattrs = 0;
	চাবি_class = CKO_PUBLIC_চাবি;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &চাবি_class, পরিমাণ(চাবি_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, পরিমাণ(keyid));

	যদি (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {

		/* get key type */
		nattrs = 0;
		FILL_ATTR(attrs, nattrs, CKA_চাবি_TYPE, &চাবি_type,
		    পরিমাণ(চাবি_type));
		rv = f->C_Get_Attribute_মান(session, obj, attrs, nattrs);
		যদি (rv != CKR_OK) {
			debug_f("could not get key type of public key 0x%hhx",
			    keyid);
			*err = rv;
			চাবি_type = -1;
		}
		বিকল্প (চাবি_type) {
#ifdef WITH_OPENSSL
		পক্ষ CKK_RSA:
			k = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			ভঙ্গ;
		পক্ষ CKK_ECDSA:
			k = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			ভঙ্গ;
#endif /* WITH_OPENSSL */
		পক্ষ CKK_EC_EDWARDS:
			k = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			ভঙ্গ;
		স্বভাব:
			debug_f("unsupported key type %lu", (u_long)চাবি_type);
			ভঙ্গ;
		}

		যদি ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy public key 0x%hhx", keyid);
			*err = rv;
			গচ্ছ out;
		}
	}

out:
	যদি (reset_pin)
		f->C_SetOperationState(session , রিক্ত, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	যদি (reset_provider)
		pkcs11_del_provider(provider_id);

	প্রত্যাগম (k);
}
#endif /* WITH_PKCS11_KEYGEN */
#অন্যথা /* ENABLE_PKCS11 */

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "ssh-pkcs11.h"

পূর্ণাঙ্ক
pkcs11_init(পূর্ণাঙ্ক interactive)
{
	error_f("PKCS#11 not supported");
	প্রত্যাগম (-1);
}

পূর্ণাঙ্ক
pkcs11_add_provider(বর্ণ *provider_id, বর্ণ *pin, সংরচনা sshkey ***keyp,
    বর্ণ ***labelsp)
{
	error_f("PKCS#11 not supported");
	প্রত্যাগম (-1);
}

শূন্য
pkcs11_চাবি_free(সংরচনা sshkey *চাবি)
{
	error_f("PKCS#11 not supported");
}

পূর্ণাঙ্ক
pkcs11_sign(সংরচনা sshkey *চাবি,
    u_char **sigp, size_t *lenp,
    ধ্রুব u_char *data, size_t datalen,
    ধ্রুব বর্ণ *alg, ধ্রুব বর্ণ *sk_provider,
    ধ্রুব বর্ণ *sk_pin, u_int compat)
{
	error_f("PKCS#11 not supported");
	প্রত্যাগম SSH_ERR_FEATURE_UNSUPPORTED;
}

শূন্য
pkcs11_terminate(শূন্য)
{
	error_f("PKCS#11 not supported");
}
#endif /* ENABLE_PKCS11 */
