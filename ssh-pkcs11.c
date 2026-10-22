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

কাঠামো pkcs11_slotinfo {
	CK_TOKEN_INFO		token;
	CK_SESSION_HANDLE	session;
	পূর্ণসংখ্যা			logged_in;
};

কাঠামো pkcs11_provider {
	অক্ষর			*name;
	শূন্য			*handle;
	CK_FUNCTION_LIST	*function_list;
	CK_INFO			info;
	CK_ULONG		nslots;
	CK_SLOT_ID		*slotlist;
	কাঠামো pkcs11_slotinfo	*slotinfo;
	পূর্ণসংখ্যা			valid;
	পূর্ণসংখ্যা			refcount;
	TAILQ_ENTRY(pkcs11_provider) পরবর্তী;
};

TAILQ_HEAD(, pkcs11_provider) pkcs11_providers;

কাঠামো pkcs11_চাবি {
	কাঠামো sshbuf		*keyblob;
	কাঠামো pkcs11_provider	*provider;
	CK_ULONG		slotidx;
	অক্ষর			*keyid;
	পূর্ণসংখ্যা			keyid_len;
	TAILQ_ENTRY(pkcs11_চাবি)	পরবর্তী;
};

TAILQ_HEAD(, pkcs11_চাবি) pkcs11_চাবিগুলি; /* XXX a tree would be better */

পূর্ণসংখ্যা pkcs11_interactive = 0;

#ifdef WITH_OPENSSL
স্থির শূন্য
ossl_error(ধ্রুবক অক্ষর *বার্তা)
{
	unsigned long    e;

	error_f("%s", বার্তা);
	যখন ((e = ERR_get_error()) != 0)
		error_f("libcrypto error: %s", ERR_error_string(e, ফাঁকা));
}
#endif

/*
 * finalize a provider shared library, it's no longer usable.
 * however, there might still be keys referencing this provider,
 * so the actual freeing of memory is handled by pkcs11_provider_unref().
 * this is called when a provider gets unregistered.
 */
স্থির শূন্য
pkcs11_provider_finalize(কাঠামো pkcs11_provider *p)
{
	CK_RV rv;
	CK_ULONG i;

	debug_f("provider \"%s\" refcount %d valid %d",
	    p->name, p->refcount, p->valid);
	যদি (!p->valid)
		ফেরত;
	জন্য (i = 0; i < p->nslots; i++) {
		যদি (p->slotinfo[i].session &&
		    (rv = p->function_list->C_CloseSession(
		    p->slotinfo[i].session)) != CKR_OK)
			error("C_CloseSession failed: %lu", rv);
	}
	যদি ((rv = p->function_list->C_Finalize(ফাঁকা)) != CKR_OK)
		error("C_Finalize failed: %lu", rv);
	p->valid = 0;
	p->function_list = ফাঁকা;
	dlclose(p->handle);
}

/*
 * remove a reference to the provider.
 * called when a key gets destroyed or when the provider is unregistered.
 */
স্থির শূন্য
pkcs11_provider_unref(কাঠামো pkcs11_provider *p)
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
স্থির কাঠামো pkcs11_provider *
pkcs11_provider_lookup(অক্ষর *provider_id)
{
	কাঠামো pkcs11_provider *p;

	TAILQ_FOREACH(p, &pkcs11_providers, পরবর্তী) {
		debug("check provider \"%s\"", p->name);
		যদি (!strcmp(provider_id, p->name))
			ফেরত (p);
	}
	ফেরত (ফাঁকা);
}

/* unregister provider by name */
পূর্ণসংখ্যা
pkcs11_del_provider(অক্ষর *provider_id)
{
	কাঠামো pkcs11_provider *p;

	যদি ((p = pkcs11_provider_lookup(provider_id)) != ফাঁকা) {
		TAILQ_REMOVE(&pkcs11_providers, p, পরবর্তী);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
		ফেরত (0);
	}
	ফেরত (-1);
}

/* release a wrapped object */
স্থির শূন্য
pkcs11_k11_free(কাঠামো pkcs11_চাবি *k11)
{
	যদি (k11 == ফাঁকা)
		ফেরত;
	যদি (k11->provider)
		pkcs11_provider_unref(k11->provider);
	মুক্ত(k11->keyid);
	sshbuf_free(k11->keyblob);
	মুক্ত(k11);
}

/* find a single 'obj' for given attributes */
স্থির পূর্ণসংখ্যা
pkcs11_find(কাঠামো pkcs11_provider *p, CK_ULONG slotidx, CK_ATTRIBUTE *attr,
    CK_ULONG nattr, CK_OBJECT_HANDLE *obj)
{
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	session;
	CK_ULONG		nfound = 0;
	CK_RV			rv;
	পূর্ণসংখ্যা			ret = -1;

	f = p->function_list;
	session = p->slotinfo[slotidx].session;
	যদি ((rv = f->C_FindObjectsInit(session, attr, nattr)) != CKR_OK) {
		error("C_FindObjectsInit failed (nattr %lu): %lu", nattr, rv);
		ফেরত (-1);
	}
	যদি ((rv = f->C_FindObjects(session, obj, 1, &nfound)) != CKR_OK ||
	    nfound != 1) {
		debug("C_FindObjects failed (nfound %lu nattr %lu): %lu",
		    nfound, nattr, rv);
	} অন্যথা
		ret = 0;
	যদি ((rv = f->C_FindObjectsFinal(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	ফেরত (ret);
}

স্থির পূর্ণসংখ্যা
pkcs11_login_slot(কাঠামো pkcs11_provider *provider, কাঠামো pkcs11_slotinfo *si,
    CK_USER_TYPE type)
{
	অক্ষর			*pin = ফাঁকা, prompt[1024];
	CK_RV			 rv;

	যদি (provider == ফাঁকা || si == ফাঁকা || !provider->valid) {
		error("no pkcs11 (valid) provider found");
		ফেরত (-1);
	}

	যদি (!pkcs11_interactive) {
		error("need pin entry%s",
		    (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH) ?
		    " on reader keypad" : "");
		ফেরত (-1);
	}
	যদি (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
		verbose("Deferring PIN entry to reader keypad.");
	অন্যথা {
		snprintf(prompt, আকার(prompt), "Enter PIN for '%s': ",
		    si->token.label);
		যদি ((pin = read_passphrase(prompt, RP_ALLOW_EOF)) == ফাঁকা) {
			debug_f("no pin specified");
			ফেরত (-1);	/* bail out */
		}
	}
	rv = provider->function_list->C_Login(si->session, type, (u_char *)pin,
	    (pin != ফাঁকা) ? strlen(pin) : 0);
	যদি (pin != ফাঁকা)
		freezero(pin, strlen(pin));

	নির্বাচন (rv) {
	ক্ষেত্র CKR_OK:
	ক্ষেত্র CKR_USER_ALREADY_LOGGED_IN:
		/* success */
		বিরতি;
	ক্ষেত্র CKR_PIN_LEN_RANGE:
		error("PKCS#11 login failed: PIN length out of range");
		ফেরত -1;
	ক্ষেত্র CKR_PIN_INCORRECT:
		error("PKCS#11 login failed: PIN incorrect");
		ফেরত -1;
	ক্ষেত্র CKR_PIN_LOCKED:
		error("PKCS#11 login failed: PIN locked");
		ফেরত -1;
	পূর্বনির্ধারিত:
		error("PKCS#11 login failed: error %lu", rv);
		ফেরত -1;
	}
	si->logged_in = 1;
	ফেরত (0);
}

স্থির পূর্ণসংখ্যা
pkcs11_login(কাঠামো pkcs11_চাবি *k11, CK_USER_TYPE type)
{
	যদি (k11 == ফাঁকা || k11->provider == ফাঁকা || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		ফেরত (-1);
	}

	ফেরত pkcs11_login_slot(k11->provider,
	    &k11->provider->slotinfo[k11->slotidx], type);
}


স্থির পূর্ণসংখ্যা
pkcs11_check_obj_bool_attrib(কাঠামো pkcs11_চাবি *k11, CK_OBJECT_HANDLE obj,
    CK_ATTRIBUTE_TYPE type, পূর্ণসংখ্যা *val)
{
	কাঠামো pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_BBOOL		flag = 0;
	CK_ATTRIBUTE		attr;
	CK_RV			 rv;

	*val = 0;

	যদি (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		ফেরত (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	attr.type = type;
	attr.p_মান = &flag;
	attr.ul_মান_Len = আকার(flag);

	rv = f->C_Get_Attribute_মান(si->session, obj, &attr, 1);
	যদি (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ফেরত (-1);
	}
	*val = flag != 0;
	debug_f("provider \"%s\" slot %lu object %lu: attrib %lu = %d",
	    k11->provider->name, k11->slotidx, obj, type, *val);
	ফেরত (0);
}

স্থির পূর্ণসংখ্যা
pkcs11_get_চাবি(কাঠামো pkcs11_চাবি *k11, CK_MECHANISM_TYPE mech_type)
{
	কাঠামো pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	 obj;
	CK_RV			 rv;
	CK_OBJECT_CLASS		 private_চাবি_class;
	CK_BBOOL		 true_val;
	CK_MECHANISM		 mech;
	CK_ATTRIBUTE		 চাবি_filter[3];
	পূর্ণসংখ্যা			 always_auth = 0;
	পূর্ণসংখ্যা			 did_login = 0;

	যদি (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		ফেরত (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	যদি ((si->token.flags & CKF_LOGIN_REQUIRED) && !si->logged_in) {
		যদি (pkcs11_login(k11, CKU_USER) < 0) {
			error("login failed");
			ফেরত (-1);
		}
		did_login = 1;
	}

	memset(&চাবি_filter, 0, আকার(চাবি_filter));
	private_চাবি_class = CKO_PRIVATE_চাবি;
	চাবি_filter[0].type = CKA_CLASS;
	চাবি_filter[0].p_মান = &private_চাবি_class;
	চাবি_filter[0].ul_মান_Len = আকার(private_চাবি_class);

	চাবি_filter[1].type = CKA_ID;
	চাবি_filter[1].p_মান = k11->keyid;
	চাবি_filter[1].ul_মান_Len = k11->keyid_len;

	true_val = CK_TRUE;
	চাবি_filter[2].type = CKA_SIGN;
	চাবি_filter[2].p_মান = &true_val;
	চাবি_filter[2].ul_মান_Len = আকার(true_val);

	/* try to find object w/CKA_SIGN first, retry w/o */
	যদি (pkcs11_find(k11->provider, k11->slotidx, চাবি_filter, 3, &obj) < 0 &&
	    pkcs11_find(k11->provider, k11->slotidx, চাবি_filter, 2, &obj) < 0) {
		error("cannot find private key");
		ফেরত (-1);
	}

	memset(&mech, 0, আকার(mech));
	mech.mechanism = mech_type;
	mech.pParameter = NULL_PTR;
	mech.ulParameterLen = 0;

	যদি ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
		ফেরত (-1);
	}

	pkcs11_check_obj_bool_attrib(k11, obj, CKA_ALWAYS_AUTHENTICATE,
	    &always_auth); /* ignore errors here */
	যদি (always_auth && !did_login) {
		debug_f("always-auth key");
		যদি (pkcs11_login(k11, CKU_CONTEXT_SPECIFIC) < 0) {
			error("login failed for always-auth key");
			ফেরত (-1);
		}
	}

	ফেরত (0);
}

/* record the key information later use lookup by keyblob */
স্থির পূর্ণসংখ্যা
pkcs11_record_চাবি(কাঠামো pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, কাঠামো sshkey *চাবি)
{
	কাঠামো sshbuf *keyblob;
	কাঠামো pkcs11_চাবি *k11;
	পূর্ণসংখ্যা r;
	অক্ষর *hex;

	hex = tohex(keyid_attrib->p_মান, keyid_attrib->ul_মান_Len);
	debug_f("%s key: provider %s slot %lu keyid %s",
	    sshkey_type(চাবি), provider->name, (u_long)slotidx, hex);
	মুক্ত(hex);

	যদি ((keyblob = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshkey_putb(চাবি, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");

	/* Check if we've already recorded this key in a different slot */
	TAILQ_FOREACH(k11, &pkcs11_চাবিগুলি, পরবর্তী) {
		যদি (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			hex = tohex(k11->keyid, k11->keyid_len);
			debug_f("Already seen this key at "
			    "provider %s slot %lu keyid %s",
			    k11->provider->name, k11->slotidx, hex);
			মুক্ত(hex);
			sshbuf_free(keyblob);
			ফেরত -1;
		}
	}

	k11 = xcalloc(1, আকার(*k11));
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
	TAILQ_INSERT_TAIL(&pkcs11_চাবিগুলি, k11, পরবর্তী);

	ফেরত 0;
}

/* retrieve the key information by keyblob */
স্থির কাঠামো pkcs11_চাবি *
pkcs11_lookup_চাবি(কাঠামো sshkey *চাবি)
{
	কাঠামো pkcs11_চাবি *k11, *found = ফাঁকা;
	কাঠামো sshbuf *keyblob;
	পূর্ণসংখ্যা r;

	যদি ((keyblob = sshbuf_new()) == ফাঁকা)
		fatal_f("sshbuf_new failed");
	যদি ((r = sshkey_putb(চাবি, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");
	TAILQ_FOREACH(k11, &pkcs11_চাবিগুলি, পরবর্তী) {
		যদি (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			found = k11;
			বিরতি;
		}
	}
	sshbuf_free(keyblob);
	ফেরত found;
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
স্থির ধ্রুবক u_char id_sha1[] = {
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
স্থির ধ্রুবক u_char id_sha256[] = {
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
স্থির ধ্রুবক u_char id_sha512[] = {
	0x30, 0x51, /* type Sequence, length 0x51 (81) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, /* id-sha512 */
	0x05, 0x00, /* NULL */
	0x04, 0x40  /* Octet string, length 0x40 (64), followed by sha512 hash */
};

স্থির পূর্ণসংখ্যা
rsa_hash_alg_oid(পূর্ণসংখ্যা hash_alg, ধ্রুবক u_char **oidp, আকার_t *oidlenp)
{
	নির্বাচন (hash_alg) {
	ক্ষেত্র SSH_DIGEST_SHA1:
		*oidp = id_sha1;
		*oidlenp = আকার(id_sha1);
		বিরতি;
	ক্ষেত্র SSH_DIGEST_SHA256:
		*oidp = id_sha256;
		*oidlenp = আকার(id_sha256);
		বিরতি;
	ক্ষেত্র SSH_DIGEST_SHA512:
		*oidp = id_sha512;
		*oidlenp = আকার(id_sha512);
		বিরতি;
	পূর্বনির্ধারিত:
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
pkcs11_sign_rsa(কাঠামো sshkey *চাবি,
    u_char **sigp, আকার_t *lenp,
    ধ্রুবক u_char *তথ্য, আকার_t datalen,
    ধ্রুবক অক্ষর *alg, ধ্রুবক অক্ষর *sk_provider,
    ধ্রুবক অক্ষর *sk_pin, u_int compat)
{
	কাঠামো pkcs11_চাবি	*k11;
	কাঠামো pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	পূর্ণসংখ্যা			hashalg, r, diff, siglen, ret = -1;
	u_char			*oid_dgst = ফাঁকা, *sig = ফাঁকা;
	আকার_t			dgst_len, oid_len, oid_dgst_len = 0;
	ধ্রুবক u_char		*oid;

	যদি (sigp != ফাঁকা)
		*sigp = ফাঁকা;
	যদি (lenp != ফাঁকা)
		*lenp = 0;

	যদি ((k11 = pkcs11_lookup_চাবি(চাবি)) == ফাঁকা) {
		error_f("no key found");
		ফেরত SSH_ERR_চাবি_NOT_FOUND;
	}

	debug3_f("sign with alg \"%s\" using provider %s slotidx %lu",
	    alg == ফাঁকা ? "" : alg, k11->provider->name, (u_long)k11->slotidx);

	যদি (pkcs11_get_চাবি(k11, CKM_RSA_PKCS) == -1) {
		error("pkcs11_get_key failed");
		ফেরত SSH_ERR_AGENT_FAILURE;
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	যদি ((siglen = EVP_PKEY_আকার(চাবি->pkey)) <= 0)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* Determine hash algorithm and OID for signature */
	যদি (alg == ফাঁকা || *alg == '\0')
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
	যদি ((r = ssh_digest_memory(hashalg, তথ্য, datalen,
	    oid_dgst + oid_len, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	যদি ((rv = f->C_Sign(si->session, (CK_BYTE *)oid_dgst,
	    oid_dgst_len, sig, &slen)) != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		যাও done;
	}

	যদি (slen < (CK_ULONG)siglen) {
		diff = siglen - slen;
		debug3_f("repack %lu < %d (diff %d)",
		    (u_long)slen, siglen, diff);
		memmove(sig + diff, sig, slen);
		explicit_bzero(sig, diff);
	} অন্যথা যদি (slen > (আকার_t)siglen)
		fatal_f("bad C_Sign length");

	যদি ((ret = ssh_rsa_encode_store_sig(hashalg, sig, siglen,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	freezero(oid_dgst, oid_dgst_len);
	মুক্ত(sig);
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
pkcs11_sign_ecdsa(কাঠামো sshkey *চাবি,
    u_char **sigp, আকার_t *lenp,
    ধ্রুবক u_char *তথ্য, আকার_t datalen,
    ধ্রুবক অক্ষর *alg, ধ্রুবক অক্ষর *sk_provider,
    ধ্রুবক অক্ষর *sk_pin, u_int compat)
{
	কাঠামো pkcs11_চাবি	*k11;
	কাঠামো pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0, bnlen;
	CK_RV			rv;
	BIGNUM			*sig_r = ফাঁকা, *sig_s = ফাঁকা;
	u_char			*sig = ফাঁকা, *dgst = ফাঁকা;
	আকার_t			dgst_len = 0;
	পূর্ণসংখ্যা			hashalg, ret = -1, r, siglen;

	যদি (sigp != ফাঁকা)
		*sigp = ফাঁকা;
	যদি (lenp != ফাঁকা)
		*lenp = 0;

	যদি ((k11 = pkcs11_lookup_চাবি(চাবি)) == ফাঁকা) {
		error_f("no key found");
		ফেরত SSH_ERR_চাবি_NOT_FOUND;
	}

	যদি (pkcs11_get_চাবি(k11, CKM_ECDSA) == -1) {
		error("pkcs11_get_key failed");
		ফেরত SSH_ERR_AGENT_FAILURE;
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
	যদি ((r = ssh_digest_memory(hashalg, তথ্য, datalen,
	    dgst, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	যদি ((siglen = EVP_PKEY_আকার(চাবি->pkey)) <= 0)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dgst_len, sig, &slen);
	যদি (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		যাও done;
	}
	যদি (slen < 64 || slen > 132 || slen % 2) {
		error_f("bad signature length: %lu", (u_long)slen);
		যাও done;
	}
	bnlen = slen/2;
	যদি ((sig_r = BN_bin2bn(sig, bnlen, ফাঁকা)) == ফাঁকা ||
	    (sig_s = BN_bin2bn(sig+bnlen, bnlen, ফাঁকা)) == ফাঁকা) {
		ossl_error("BN_bin2bn failed");
		যাও done;
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
	ফেরত ret;
}
#endif /* WITH_OPENSSL */

স্থির পূর্ণসংখ্যা
pkcs11_sign_ed25519(কাঠামো sshkey *চাবি,
    u_char **sigp, আকার_t *lenp,
    ধ্রুবক u_char *তথ্য, আকার_t datalen,
    ধ্রুবক অক্ষর *alg, ধ্রুবক অক্ষর *sk_provider,
    ধ্রুবক অক্ষর *sk_pin, u_int compat)
{
	কাঠামো pkcs11_চাবি	*k11;
	কাঠামো pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	u_char			*sig = ফাঁকা;
	CK_BYTE			*xdata = ফাঁকা;
	পূর্ণসংখ্যা			ret = -1;

	যদি (sigp != ফাঁকা)
		*sigp = ফাঁকা;
	যদি (lenp != ফাঁকা)
		*lenp = 0;

	যদি ((k11 = pkcs11_lookup_চাবি(চাবি)) == ফাঁকা) {
		error_f("no key found");
		ফেরত SSH_ERR_চাবি_NOT_FOUND;
	}

	যদি (pkcs11_get_চাবি(k11, CKM_EDDSA) == -1) {
		error("pkcs11_get_key failed");
		ফেরত SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	xdata = xmalloc(datalen);
	memcpy(xdata, তথ্য, datalen);
	sig = xmalloc(crypto_sign_ed25519_BYTES);
	slen = crypto_sign_ed25519_BYTES;

	rv = f->C_Sign(si->session, xdata, datalen, sig, &slen);
	যদি (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		যাও done;
	}
	যদি (slen != crypto_sign_ed25519_BYTES) {
		error_f("bad signature length: %lu", (u_long)slen);
		যাও done;
	}
	যদি ((ret = ssh_ed25519_encode_store_sig(sig, slen, sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	যদি (xdata != ফাঁকা)
		freezero(xdata, datalen);
	মুক্ত(sig);
	ফেরত ret;
}

/* remove trailing spaces */
স্থির অক্ষর *
rmspace(u_char *buf, আকার_t len)
{
	আকার_t i;

	যদি (len == 0)
		ফেরত buf;
	জন্য (i = len - 1; i > 0; i--)
		যদি (buf[i] == ' ')
			buf[i] = '\0';
		অন্যথা
			বিরতি;
	ফেরত buf;
}
/* Used to printf fixed-width, space-padded, unterminated strings using %.*s */
#define RMSPACE(s) (পূর্ণসংখ্যা)আকার(s), rmspace(s, আকার(s))

/*
 * open a pkcs11 session and login if required.
 * if pin == NULL we delay login until key use
 */
স্থির পূর্ণসংখ্যা
pkcs11_open_session(কাঠামো pkcs11_provider *p, CK_ULONG slotidx, অক্ষর *pin,
    CK_ULONG user)
{
	কাঠামো pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_RV			rv;
	CK_SESSION_HANDLE	session;
	পূর্ণসংখ্যা			login_required, ret;

	f = p->function_list;
	si = &p->slotinfo[slotidx];

	login_required = si->token.flags & CKF_LOGIN_REQUIRED;

	/* fail early before opening session */
	যদি (login_required && !pkcs11_interactive &&
	    (pin == ফাঁকা || strlen(pin) == 0)) {
		error("pin required");
		ফেরত (-SSH_PKCS11_ERR_PIN_REQUIRED);
	}
	যদি ((rv = f->C_OpenSession(p->slotlist[slotidx], CKF_RW_SESSION|
	    CKF_SERIAL_SESSION, ফাঁকা, ফাঁকা, &session)) != CKR_OK) {
		error("C_OpenSession failed: %lu", rv);
		ফেরত (-1);
	}
	যদি (login_required && pin != ফাঁকা && strlen(pin) != 0) {
		rv = f->C_Login(session, user, (u_char *)pin, strlen(pin));
		যদি (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
			error("C_Login failed: %lu", rv);
			ret = (rv == CKR_PIN_LOCKED) ?
			    -SSH_PKCS11_ERR_PIN_LOCKED :
			    -SSH_PKCS11_ERR_LOGIN_FAIL;
			যদি ((rv = f->C_CloseSession(session)) != CKR_OK)
				error("C_CloseSession failed: %lu", rv);
			ফেরত (ret);
		}
		si->logged_in = 1;
	}
	si->session = session;
	ফেরত (0);
}

স্থির পূর্ণসংখ্যা
pkcs11_চাবি_included(কাঠামো sshkey ***keysp, পূর্ণসংখ্যা *nkeys, কাঠামো sshkey *চাবি)
{
	পূর্ণসংখ্যা i;

	জন্য (i = 0; i < *nkeys; i++)
		যদি (sshkey_equal(চাবি, (*keysp)[i]))
			ফেরত (1);
	ফেরত (0);
}

#ifdef WITH_OPENSSL
স্থির কাঠামো sshkey *
pkcs11_fetch_ecdsa_pubkey(কাঠামো pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 চাবি_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ফাঁকা;
	CK_RV			 rv;
	ASN1_OCTET_STRING	*octet = ফাঁকা;
	EC_চাবি			*ec = ফাঁকা;
	EC_GROUP		*group = ফাঁকা;
	কাঠামো sshkey		*চাবি = ফাঁকা;
	ধ্রুবক unsigned অক্ষর	*attrp = ফাঁকা;
	পূর্ণসংখ্যা			 success = -1, r, i, nid;

	memset(&চাবি_attr, 0, আকার(চাবি_attr));
	চাবি_attr[0].type = CKA_ID;
	চাবি_attr[1].type = CKA_EC_POINT;
	চাবি_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_মান(session, *obj, চাবি_attr, 3);
	যদি (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ফেরত (ফাঁকা);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	যদি (চাবি_attr[1].ul_মান_Len == 0 ||
	    চাবি_attr[2].ul_মান_Len == 0) {
		error("invalid attribute length");
		ফেরত (ফাঁকা);
	}

	/* allocate buffers for attributes */
	জন্য (i = 0; i < 3; i++)
		যদি (চাবি_attr[i].ul_মান_Len > 0)
			চাবি_attr[i].p_মান = xcalloc(1, চাবি_attr[i].ul_মান_Len);

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_মান(session, *obj, চাবি_attr, 3);
	যদি (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		যাও fail;
	}

	ec = EC_চাবি_new();
	যদি (ec == ফাঁকা) {
		error("EC_KEY_new failed");
		যাও fail;
	}

	attrp = চাবি_attr[2].p_মান;
	group = d2i_ECPKParameters(ফাঁকা, &attrp, চাবি_attr[2].ul_মান_Len);
	যদি (group == ফাঁকা) {
		ossl_error("d2i_ECPKParameters failed");
		যাও fail;
	}

	যদি (EC_চাবি_set_group(ec, group) == 0) {
		ossl_error("EC_KEY_set_group failed");
		যাও fail;
	}

	যদি (চাবি_attr[1].ul_মান_Len <= 2) {
		error("CKA_EC_POINT too small");
		যাও fail;
	}

	attrp = চাবি_attr[1].p_মান;
	octet = d2i_ASN1_OCTET_STRING(ফাঁকা, &attrp, চাবি_attr[1].ul_মান_Len);
	যদি (octet == ফাঁকা) {
		ossl_error("d2i_ASN1_OCTET_STRING failed");
		যাও fail;
	}
	attrp = ASN1_STRING_get0_তথ্য(octet);
	যদি (o2i_ECPublic_চাবি(&ec, &attrp, ASN1_STRING_দৈর্ঘ্য(octet)) == ফাঁকা) {
		ossl_error("o2i_ECPublicKey failed");
		যাও fail;
	}
	যদি ((r = sshkey_ec_validate_public(EC_চাবি_get0_group(ec),
	    EC_চাবি_get0_public_চাবি(ec))) != 0) {
		error_fr(r, "invalid EC key");
		যাও fail;
	}

	nid = sshkey_ecdsa_চাবি_to_nid(ec);
	যদি (nid < 0) {
		error("couldn't get curve nid");
		যাও fail;
	}

	চাবি = sshkey_new(চাবি_UNSPEC);
	যদি (চাবি == ফাঁকা) {
		error("sshkey_new failed");
		যাও fail;
	}

	EVP_PKEY_free(চাবি->pkey);
	যদি ((চাবি->pkey = EVP_PKEY_new()) == ফাঁকা)
		fatal("EVP_PKEY_new failed");
	যদি (EVP_PKEY_set1_EC_চাবি(চাবি->pkey, ec) != 1)
		fatal("EVP_PKEY_set1_EC_KEY failed");
	চাবি->ecdsa_nid = nid;
	চাবি->type = চাবি_ECDSA;
	চাবি->flags |= SSHKEY_FLAG_EXT;
	যদি (pkcs11_record_চাবি(p, slotidx, &চাবি_attr[0], চাবি))
		যাও fail;
	/* success */
	success = 0;
fail:
	যদি (success != 0) {
		sshkey_free(চাবি);
		চাবি = ফাঁকা;
	}
	জন্য (i = 0; i < 3; i++)
		মুক্ত(চাবি_attr[i].p_মান);
	যদি (ec)
		EC_চাবি_free(ec);
	যদি (group)
		EC_GROUP_free(group);
	যদি (octet)
		ASN1_OCTET_STRING_free(octet);

	ফেরত (চাবি);
}

স্থির কাঠামো sshkey *
pkcs11_fetch_rsa_pubkey(কাঠামো pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 চাবি_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ফাঁকা;
	CK_RV			 rv;
	RSA			*rsa = ফাঁকা;
	BIGNUM			*rsa_n, *rsa_e;
	কাঠামো sshkey		*চাবি = ফাঁকা;
	পূর্ণসংখ্যা			 i, success = -1;

	memset(&চাবি_attr, 0, আকার(চাবি_attr));
	চাবি_attr[0].type = CKA_ID;
	চাবি_attr[1].type = CKA_MODULUS;
	চাবি_attr[2].type = CKA_PUBLIC_EXPONENT;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_মান(session, *obj, চাবি_attr, 3);
	যদি (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ফেরত (ফাঁকা);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	যদি (চাবি_attr[1].ul_মান_Len == 0 ||
	    চাবি_attr[2].ul_মান_Len == 0) {
		error("invalid attribute length");
		ফেরত (ফাঁকা);
	}

	/* allocate buffers for attributes */
	জন্য (i = 0; i < 3; i++)
		যদি (চাবি_attr[i].ul_মান_Len > 0)
			চাবি_attr[i].p_মান = xcalloc(1, চাবি_attr[i].ul_মান_Len);

	/* retrieve ID, modulus and public exponent of RSA key */
	rv = f->C_Get_Attribute_মান(session, *obj, চাবি_attr, 3);
	যদি (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		যাও fail;
	}

	rsa = RSA_new();
	যদি (rsa == ফাঁকা) {
		error("RSA_new failed");
		যাও fail;
	}

	rsa_n = BN_bin2bn(চাবি_attr[1].p_মান, চাবি_attr[1].ul_মান_Len, ফাঁকা);
	rsa_e = BN_bin2bn(চাবি_attr[2].p_মান, চাবি_attr[2].ul_মান_Len, ফাঁকা);
	যদি (rsa_n == ফাঁকা || rsa_e == ফাঁকা) {
		error("BN_bin2bn failed");
		যাও fail;
	}
	যদি (!RSA_set0_চাবি(rsa, rsa_n, rsa_e, ফাঁকা))
		fatal_f("set key");
	rsa_n = rsa_e = ফাঁকা; /* transferred */

	চাবি = sshkey_new(চাবি_UNSPEC);
	যদি (চাবি == ফাঁকা) {
		error("sshkey_new failed");
		যাও fail;
	}

	EVP_PKEY_free(চাবি->pkey);
	যদি ((চাবি->pkey = EVP_PKEY_new()) == ফাঁকা)
		fatal("EVP_PKEY_new failed");
	যদি (EVP_PKEY_set1_RSA(চাবি->pkey, rsa) != 1)
		fatal("EVP_PKEY_set1_RSA failed");
	চাবি->type = চাবি_RSA;
	চাবি->flags |= SSHKEY_FLAG_EXT;
	যদি (EVP_PKEY_bits(চাবি->pkey) < SSH_RSA_MINIMUM_MODULUS_আকার) {
		error_f("RSA key too small %d < minimum %d",
		    EVP_PKEY_bits(চাবি->pkey), SSH_RSA_MINIMUM_MODULUS_আকার);
		যাও fail;
	}
	যদি (pkcs11_record_চাবি(p, slotidx, &চাবি_attr[0], চাবি))
		যাও fail;
	/* success */
	success = 0;
fail:
	জন্য (i = 0; i < 3; i++)
		মুক্ত(চাবি_attr[i].p_মান);
	RSA_free(rsa);
	যদি (success != 0) {
		sshkey_free(চাবি);
		চাবি = ফাঁকা;
	}
	ফেরত চাবি;
}
#endif /* WITH_OPENSSL */

স্থির কাঠামো sshkey *
pkcs11_fetch_ed25519_pubkey(কাঠামো pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 চাবি_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ফাঁকা;
	CK_RV			 rv;
	কাঠামো sshkey		*চাবি = ফাঁকা;
	ধ্রুবক unsigned অক্ষর	*d = ফাঁকা;
	আকার_t			len;
	অক্ষর			*hex = ফাঁকা;
	পূর্ণসংখ্যা			 success = -1, i;
	/* https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061180 */
	ধ্রুবক u_char		 id1[14] = {
		0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64,
		0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
	}; /* PrintableString { "edwards25519" } */
	ধ্রুবক u_char		 id2[5] = {
		0x06, 0x03, 0x2b, 0x65, 0x70,
	}; /* OBJECT_IDENTIFIER { 1.3.101.112 } */

	memset(&চাবি_attr, 0, আকার(চাবি_attr));
	চাবি_attr[0].type = CKA_ID;
	চাবি_attr[1].type = CKA_EC_POINT; /* XXX or CKA_VALUE ? */
	চাবি_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_মান(session, *obj, চাবি_attr, 3);
	যদি (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ফেরত (ফাঁকা);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	যদি (চাবি_attr[1].ul_মান_Len == 0 ||
	    চাবি_attr[2].ul_মান_Len == 0) {
		error("invalid attribute length");
		ফেরত (ফাঁকা);
	}

	/* allocate buffers for attributes */
	জন্য (i = 0; i < 3; i++) {
		যদি (চাবি_attr[i].ul_মান_Len > 0)
			চাবি_attr[i].p_মান = xcalloc(1, চাবি_attr[i].ul_মান_Len);
	}

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_মান(session, *obj, চাবি_attr, 3);
	যদি (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		যাও fail;
	}

	/* Expect one of the supported identifiers in CKA_EC_PARAMS */
	d = (u_char *)চাবি_attr[2].p_মান;
	len = চাবি_attr[2].ul_মান_Len;
	যদি ((len != আকার(id1) || memcmp(d, id1, আকার(id1)) != 0) &&
	    (len != আকার(id2) || memcmp(d, id2, আকার(id2)) != 0)) {
		hex = tohex(d, len);
		logit_f("unsupported CKA_EC_PARAMS: %s (len %zu)", hex, len);
		যাও fail;
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
		যাও fail;
	}

	যদি ((চাবি = sshkey_new(চাবি_UNSPEC)) == ফাঁকা)
		fatal_f("sshkey_new failed");
	চাবি->ed25519_pk = xmalloc(ED25519_PK_SZ);
	memcpy(চাবি->ed25519_pk, d, ED25519_PK_SZ);
	চাবি->type = চাবি_ED25519;
	চাবি->flags |= SSHKEY_FLAG_EXT;
	যদি (pkcs11_record_চাবি(p, slotidx, &চাবি_attr[0], চাবি))
		যাও fail;
	/* success */
	success = 0;
 fail:
	যদি (success != 0) {
		sshkey_free(চাবি);
		চাবি = ফাঁকা;
	}
	মুক্ত(hex);
	জন্য (i = 0; i < 3; i++)
		মুক্ত(চাবি_attr[i].p_মান);
	ফেরত চাবি;
}

#ifdef WITH_OPENSSL
স্থির পূর্ণসংখ্যা
pkcs11_fetch_x509_pubkey(কাঠামো pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj, কাঠামো sshkey **keyp, অক্ষর **labelp)
{
	CK_ATTRIBUTE		 cert_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ফাঁকা;
	CK_RV			 rv;
	X509			*x509 = ফাঁকা;
	X509_NAME		*x509_name = ফাঁকা;
	EVP_PKEY		*evp;
	RSA			*rsa = ফাঁকা;
	EC_চাবি			*ec = ফাঁকা;
	কাঠামো sshkey		*চাবি = ফাঁকা;
	পূর্ণসংখ্যা			 r, i, nid, success = -1;
	ধ্রুবক u_char		*cp;
	অক্ষর			*subject = ফাঁকা;
#ifdef OPENSSL_HAS_ED25519
	আকার_t			len;
#endif /* OPENSSL_HAS_ED25519 */

	*keyp = ফাঁকা;
	*labelp = ফাঁকা;

	memset(&cert_attr, 0, আকার(cert_attr));
	cert_attr[0].type = CKA_ID;
	cert_attr[1].type = CKA_SUBJECT;
	cert_attr[2].type = CKA_মান;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_মান(session, *obj, cert_attr, 3);
	যদি (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ফেরত -1;
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	যদি (cert_attr[1].ul_মান_Len == 0 ||
	    cert_attr[2].ul_মান_Len == 0) {
		error("invalid attribute length");
		ফেরত -1;
	}

	/* allocate buffers for attributes */
	জন্য (i = 0; i < 3; i++)
		যদি (cert_attr[i].ul_মান_Len > 0)
			cert_attr[i].p_মান = xcalloc(1, cert_attr[i].ul_মান_Len);

	/* retrieve ID, subject and value of certificate */
	rv = f->C_Get_Attribute_মান(session, *obj, cert_attr, 3);
	যদি (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		যাও out;
	}

	/* Decode DER-encoded cert subject */
	cp = cert_attr[1].p_মান;
	যদি ((x509_name = d2i_X509_NAME(ফাঁকা, &cp,
	    cert_attr[1].ul_মান_Len)) == ফাঁকা ||
	    (subject = X509_NAME_oneline(x509_name, ফাঁকা, 0)) == ফাঁকা)
		subject = xstrdup("invalid subject");
	X509_NAME_free(x509_name);

	cp = cert_attr[2].p_মান;
	যদি ((x509 = d2i_X509(ফাঁকা, &cp, cert_attr[2].ul_মান_Len)) == ফাঁকা) {
		error("d2i_x509 failed");
		যাও out;
	}

	যদি ((evp = X509_get_pubkey(x509)) == ফাঁকা) {
		error("X509_get_pubkey failed");
		যাও out;
	}

	যদি (EVP_PKEY_base_id(evp) == EVP_PKEY_RSA) {
		যদি (EVP_PKEY_get0_RSA(evp) == ফাঁকা) {
			error("invalid x509; no rsa key");
			যাও out;
		}
		যদি ((rsa = RSAPublic_চাবি_dup(EVP_PKEY_get0_RSA(evp))) == ফাঁকা) {
			error("RSAPublicKey_dup failed");
			যাও out;
		}

		চাবি = sshkey_new(চাবি_UNSPEC);
		যদি (চাবি == ফাঁকা) {
			error("sshkey_new failed");
			যাও out;
		}

		EVP_PKEY_free(চাবি->pkey);
		যদি ((চাবি->pkey = EVP_PKEY_new()) == ফাঁকা)
			fatal("EVP_PKEY_new failed");
		যদি (EVP_PKEY_set1_RSA(চাবি->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		চাবি->type = চাবি_RSA;
		চাবি->flags |= SSHKEY_FLAG_EXT;
		যদি (EVP_PKEY_bits(চাবি->pkey) < SSH_RSA_MINIMUM_MODULUS_আকার) {
			error_f("RSA key too small %d < minimum %d",
			    EVP_PKEY_bits(চাবি->pkey),
			    SSH_RSA_MINIMUM_MODULUS_আকার);
			যাও out;
		}
		যদি (pkcs11_record_চাবি(p, slotidx, &cert_attr[0], চাবি))
			যাও out;
		/* success */
		success = 0;
	} অন্যথা যদি (EVP_PKEY_base_id(evp) == EVP_PKEY_EC) {
		যদি (EVP_PKEY_get0_EC_চাবি(evp) == ফাঁকা) {
			error("invalid x509; no ec key");
			যাও out;
		}
		যদি ((ec = EC_চাবি_dup(EVP_PKEY_get0_EC_চাবি(evp))) == ফাঁকা) {
			error("EC_KEY_dup failed");
			যাও out;
		}
		যদি ((r = sshkey_ec_validate_public(EC_চাবি_get0_group(ec),
		    EC_চাবি_get0_public_চাবি(ec))) != 0) {
			error_fr(r, "invalid EC key");
			যাও out;
		}
		nid = sshkey_ecdsa_চাবি_to_nid(ec);
		যদি (nid < 0) {
			error("couldn't get curve nid");
			যাও out;
		}

		চাবি = sshkey_new(চাবি_UNSPEC);
		যদি (চাবি == ফাঁকা) {
			error("sshkey_new failed");
			যাও out;
		}

		EVP_PKEY_free(চাবি->pkey);
		যদি ((চাবি->pkey = EVP_PKEY_new()) == ফাঁকা)
			fatal("EVP_PKEY_new failed");
		যদি (EVP_PKEY_set1_EC_চাবি(চাবি->pkey, ec) != 1)
			fatal("EVP_PKEY_set1_EC_KEY failed");
		চাবি->ecdsa_nid = nid;
		চাবি->type = চাবি_ECDSA;
		চাবি->flags |= SSHKEY_FLAG_EXT;
		যদি (pkcs11_record_চাবি(p, slotidx, &cert_attr[0], চাবি))
			যাও out;
		/* success */
		success = 0;
#ifdef OPENSSL_HAS_ED25519
	} অন্যথা যদি (EVP_PKEY_base_id(evp) == EVP_PKEY_ED25519) {
		যদি ((চাবি = sshkey_new(চাবি_UNSPEC)) == ফাঁকা ||
		    (চাবি->ed25519_pk = calloc(1, ED25519_PK_SZ)) == ফাঁকা)
			fatal_f("allocation failed");
		len = ED25519_PK_SZ;
		যদি (!EVP_PKEY_get_raw_public_চাবি(evp, চাবি->ed25519_pk, &len)) {
			ossl_error("EVP_PKEY_get_raw_public_key failed");
			যাও out;
		}
		যদি (len != ED25519_PK_SZ) {
			error_f("incorrect returned public key "
			    "length for ed25519");
			যাও out;
		}
		চাবি->type = চাবি_ED25519;
		চাবি->flags |= SSHKEY_FLAG_EXT;
		যদি (pkcs11_record_চাবি(p, slotidx, &cert_attr[0], চাবি))
			যাও out;
		/* success */
		success = 0;
#endif /* OPENSSL_HAS_ED25519 */
	} অন্যথা {
		error("unknown certificate key type");
		যাও out;
	}
 out:
	জন্য (i = 0; i < 3; i++)
		মুক্ত(cert_attr[i].p_মান);
	X509_free(x509);
	RSA_free(rsa);
	EC_চাবি_free(ec);
	যদি (success != 0 || চাবি == ফাঁকা) {
		sshkey_free(চাবি);
		মুক্ত(subject);
		ফেরত -1;
	}
	/* success */
	*keyp = চাবি;
	*labelp = subject;
	ফেরত 0;
}
#endif /* WITH_OPENSSL */

স্থির শূন্য
note_চাবি(কাঠামো pkcs11_provider *p, CK_ULONG slotidx, ধ্রুবক অক্ষর *context,
    কাঠামো sshkey *চাবি)
{
	অক্ষর *fp;

	যদি ((fp = sshkey_fingerprint(চাবি, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ফাঁকা) {
		error_f("sshkey_fingerprint failed");
		ফেরত;
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
স্থির পূর্ণসংখ্যা
pkcs11_fetch_certs(কাঠামো pkcs11_provider *p, CK_ULONG slotidx,
    কাঠামো sshkey ***keysp, অক্ষর ***labelsp, পূর্ণসংখ্যা *nkeys)
{
	কাঠামো sshkey		*চাবি = ফাঁকা;
	CK_OBJECT_CLASS		 চাবি_class;
	CK_ATTRIBUTE		 চাবি_attr[1];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ফাঁকা;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	পূর্ণসংখ্যা			 ret = -1;
	অক্ষর			*label;

	memset(&চাবি_attr, 0, আকার(চাবি_attr));
	memset(&obj, 0, আকার(obj));

	চাবি_class = CKO_CERTIFICATE;
	চাবি_attr[0].type = CKA_CLASS;
	চাবি_attr[0].p_মান = &চাবি_class;
	চাবি_attr[0].ul_মান_Len = আকার(চাবি_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, চাবি_attr, 1);
	যদি (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		যাও fail;
	}

	যখন (1) {
		CK_CERTIFICATE_TYPE	ck_cert_type;

		rv = f->C_FindObjects(session, &obj, 1, &n);
		যদি (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			যাও fail;
		}
		যদি (n == 0)
			বিরতি;

		memset(&ck_cert_type, 0, আকার(ck_cert_type));
		memset(&চাবি_attr, 0, আকার(চাবি_attr));
		চাবি_attr[0].type = CKA_CERTIFICATE_TYPE;
		চাবি_attr[0].p_মান = &ck_cert_type;
		চাবি_attr[0].ul_মান_Len = আকার(ck_cert_type);

		rv = f->C_Get_Attribute_মান(session, obj, চাবি_attr, 1);
		যদি (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			যাও fail;
		}

		চাবি = ফাঁকা;
		label = ফাঁকা;
		নির্বাচন (ck_cert_type) {
		ক্ষেত্র CKC_X_509:
			যদি (pkcs11_fetch_x509_pubkey(p, slotidx, &obj,
			    &চাবি, &label) != 0) {
				debug_f("failed to fetch key");
				চালু;
			}
			বিরতি;
		পূর্বনির্ধারিত:
			error("skipping unsupported certificate type %lu",
			    ck_cert_type);
			চালু;
		}
		note_চাবি(p, slotidx, __func__, চাবি);
		যদি (pkcs11_চাবি_included(keysp, nkeys, চাবি)) {
			debug2_f("key already included");
			sshkey_free(চাবি);
		} অন্যথা {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, আকার(কাঠামো sshkey *));
			(*keysp)[*nkeys] = চাবি;
			যদি (labelsp != ফাঁকা) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, আকার(অক্ষর *));
				(*labelsp)[*nkeys] = xstrdup((অক্ষর *)label);
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

	ফেরত (ret);
}
#endif /* WITH_OPENSSL */

/*
 * lookup public keys for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
স্থির পূর্ণসংখ্যা
pkcs11_fetch_চাবিগুলি(কাঠামো pkcs11_provider *p, CK_ULONG slotidx,
    কাঠামো sshkey ***keysp, অক্ষর ***labelsp, পূর্ণসংখ্যা *nkeys)
{
	কাঠামো sshkey		*চাবি = ফাঁকা;
	CK_OBJECT_CLASS		 চাবি_class;
	CK_ATTRIBUTE		 চাবি_attr[2];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ফাঁকা;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	পূর্ণসংখ্যা			 ret = -1;

	memset(&চাবি_attr, 0, আকার(চাবি_attr));
	memset(&obj, 0, আকার(obj));

	চাবি_class = CKO_PUBLIC_চাবি;
	চাবি_attr[0].type = CKA_CLASS;
	চাবি_attr[0].p_মান = &চাবি_class;
	চাবি_attr[0].ul_মান_Len = আকার(চাবি_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, চাবি_attr, 1);
	যদি (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		যাও fail;
	}

	যখন (1) {
		CK_চাবি_TYPE	ck_চাবি_type;
		CK_UTF8CHAR	label[256];

		rv = f->C_FindObjects(session, &obj, 1, &n);
		যদি (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			যাও fail;
		}
		যদি (n == 0)
			বিরতি;

		memset(&ck_চাবি_type, 0, আকার(ck_চাবি_type));
		memset(&চাবি_attr, 0, আকার(চাবি_attr));
		চাবি_attr[0].type = CKA_চাবি_TYPE;
		চাবি_attr[0].p_মান = &ck_চাবি_type;
		চাবি_attr[0].ul_মান_Len = আকার(ck_চাবি_type);
		চাবি_attr[1].type = CKA_LABEL;
		চাবি_attr[1].p_মান = &label;
		চাবি_attr[1].ul_মান_Len = আকার(label) - 1;

		rv = f->C_Get_Attribute_মান(session, obj, চাবি_attr, 2);
		যদি (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			যাও fail;
		}

		label[চাবি_attr[1].ul_মান_Len] = '\0';

		নির্বাচন (ck_চাবি_type) {
#ifdef WITH_OPENSSL
		ক্ষেত্র CKK_RSA:
			চাবি = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			বিরতি;
		ক্ষেত্র CKK_ECDSA:
			চাবি = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			বিরতি;
#endif /* WITH_OPENSSL */
		ক্ষেত্র CKK_EC_EDWARDS:
			চাবি = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			বিরতি;
		পূর্বনির্ধারিত:
			/* XXX print key type? */
			চাবি = ফাঁকা;
			error("skipping unsupported key type 0x%lx",
			    (u_long)ck_চাবি_type);
		}

		যদি (চাবি == ফাঁকা) {
			debug_f("failed to fetch key");
			চালু;
		}
		note_চাবি(p, slotidx, __func__, চাবি);
		যদি (pkcs11_চাবি_included(keysp, nkeys, চাবি)) {
			debug2_f("key already included");
			sshkey_free(চাবি);
		} অন্যথা {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, আকার(কাঠামো sshkey *));
			(*keysp)[*nkeys] = চাবি;
			যদি (labelsp != ফাঁকা) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, আকার(অক্ষর *));
				(*labelsp)[*nkeys] = xstrdup((অক্ষর *)label);
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

	ফেরত (ret);
}

#ifdef WITH_PKCS11_KEYGEN
#define FILL_ATTR(attr, idx, typ, val, len) \
	{ (attr[idx]).type=(typ); (attr[idx]).p_মান=(val); (attr[idx]).ul_মান_Len=len; idx++; }

স্থির কাঠামো sshkey *
pkcs11_rsa_generate_private_চাবি(কাঠামো pkcs11_provider *p, CK_ULONG slotidx,
    অক্ষর *label, CK_ULONG bits, CK_BYTE keyid, uint32_t *err)
{
	কাঠামো pkcs11_slotinfo	*si;
	অক্ষর			*plabel = label ? label : "";
	পূর্ণসংখ্যা			 npub = 0, npriv = 0;
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

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, আকার(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, আকার(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, আকার(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    আকার(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, আকার(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, আকার(false_val));
	FILL_ATTR(tpub, npub, CKA_MODULUS_BITS, &bits, আকার(bits));
	FILL_ATTR(tpub, npub, CKA_PUBLIC_EXPONENT, pubExponent,
	    আকার(pubExponent));
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, আকার(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN,  &true_val, আকার(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL,  plabel, strlen(plabel));
	FILL_ATTR(tpriv, npriv, CKA_PRIVATE,  &true_val, আকার(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE,  &true_val, আকার(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT,  &false_val, আকার(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN,  &true_val, আকার(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER,  &false_val,
	    আকার(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP,  &false_val, আকার(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE,  &false_val, আকার(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, আকার(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	যদি ((rv = f->C_Generate_চাবি_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_চাবি_2, &priv_চাবি)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		ফেরত ফাঁকা;
	}

	ফেরত pkcs11_fetch_rsa_pubkey(p, slotidx, &pub_চাবি_2);
}

স্থির পূর্ণসংখ্যা
h2i(অক্ষর c)
{
	যদি (c >= '0' && c <= '9')
		ফেরত c - '0';
	অন্যথা যদি (c >= 'a' && c <= 'f')
		ফেরত c - 'a' + 10;
	অন্যথা যদি (c >= 'A' && c <= 'F')
		ফেরত c - 'A' + 10;
	অন্যথা
		ফেরত -1;
}

স্থির পূর্ণসংখ্যা
pkcs11_decode_hex(ধ্রুবক অক্ষর *hex, unsigned অক্ষর **dest, আকার_t *rlen)
{
	আকার_t	i, len;

	যদি (dest)
		*dest = ফাঁকা;
	যদি (rlen)
		*rlen = 0;

	যদি ((len = strlen(hex)) % 2)
		ফেরত -1;
	len /= 2;

	*dest = xmalloc(len);

	জন্য (i = 0; i < len; i++) {
		পূর্ণসংখ্যা hi, lo;

		hi = h2i(hex[2 * i]);
		lo = h2i(hex[(2 * i) + 1]);
		যদি (hi == -1 || lo == -1)
			ফেরত -1;
		(*dest)[i] = (hi << 4) | lo;
	}

	যদি (rlen)
		*rlen = len;

	ফেরত 0;
}

স্থির কাঠামো ec_curve_info {
	ধ্রুবক অক্ষর	*name;
	ধ্রুবক অক্ষর	*oid;
	ধ্রুবক অক্ষর	*oid_encoded;
	আকার_t		 আকার_2;
} ec_curve_infos[] = {
	{"prime256v1",	"1.2.840.10045.3.1.7",	"06082A8648CE3D030107", 256},
	{"secp384r1",	"1.3.132.0.34",		"06052B81040022",	384},
	{"secp521r1",	"1.3.132.0.35",		"06052B81040023",	521},
	{ফাঁকা,		ফাঁকা,			ফাঁকা,			0},
};

স্থির কাঠামো sshkey *
pkcs11_ecdsa_generate_private_চাবি(কাঠামো pkcs11_provider *p, CK_ULONG slotidx,
    অক্ষর *label, CK_ULONG bits, CK_BYTE keyid, uint32_t *err)
{
	কাঠামো pkcs11_slotinfo	*si;
	অক্ষর			*plabel = label ? label : "";
	পূর্ণসংখ্যা			 i;
	আকার_t			 ecparams_আকার;
	unsigned অক্ষর		*ecparams = ফাঁকা;
	পূর্ণসংখ্যা			 npub = 0, npriv = 0;
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

	জন্য (i = 0; ec_curve_infos[i].name; i++) {
		যদি (ec_curve_infos[i].আকার_2 == bits)
			বিরতি;
	}
	যদি (!ec_curve_infos[i].name) {
		error_f("invalid key size %lu", bits);
		ফেরত ফাঁকা;
	}
	যদি (pkcs11_decode_hex(ec_curve_infos[i].oid_encoded, &ecparams,
	    &ecparams_আকার) == -1) {
		error_f("invalid oid");
		ফেরত ফাঁকা;
	}

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, আকার(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, আকার(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, আকার(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    আকার(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, আকার(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, আকার(false_val));
	FILL_ATTR(tpub, npub, CKA_EC_PARAMS, ecparams, ecparams_আকার);
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, আকার(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN, &true_val, আকার(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpriv, npriv, CKA_PRIVATE, &true_val, আকার(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE, &true_val, আকার(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT, &false_val, আকার(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN, &true_val, আকার(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER, &false_val,
	    আকার(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP, &false_val, আকার(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE, &false_val, আকার(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, আকার(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	যদি ((rv = f->C_Generate_চাবি_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_চাবি_2, &priv_চাবি)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		ফেরত ফাঁকা;
	}

	ফেরত pkcs11_fetch_ecdsa_pubkey(p, slotidx, &pub_চাবি_2);
}
#endif /* WITH_PKCS11_KEYGEN */

/*
 * register a new provider, fails if provider already exists. if
 * keyp is provided, fetch keys.
 */
স্থির পূর্ণসংখ্যা
pkcs11_register_provider(অক্ষর *provider_id, অক্ষর *pin,
    কাঠামো sshkey ***keyp, অক্ষর ***labelsp,
    কাঠামো pkcs11_provider **providerp, CK_ULONG user)
{
	পূর্ণসংখ্যা nkeys, need_finalize = 0;
	পূর্ণসংখ্যা ret = -1;
	কাঠামো pkcs11_provider *p = ফাঁকা;
	শূন্য *handle = ফাঁকা;
	CK_RV (*getfunctionlist)(CK_FUNCTION_LIST **);
	CK_RV rv;
	CK_FUNCTION_LIST *f = ফাঁকা;
	CK_TOKEN_INFO *token;
	CK_ULONG i;

	যদি (providerp == ফাঁকা)
		যাও fail;
	*providerp = ফাঁকা;

	যদি (keyp != ফাঁকা)
		*keyp = ফাঁকা;
	যদি (labelsp != ফাঁকা)
		*labelsp = ফাঁকা;

	যদি (pkcs11_provider_lookup(provider_id) != ফাঁকা) {
		debug_f("provider already registered: %s", provider_id);
		যাও fail;
	}
	যদি (lib_contains_প্রতীক(provider_id, "C_GetFunctionList") != 0) {
		error("provider %s is not a PKCS11 library", provider_id);
		যাও fail;
	}
	/* open shared pkcs11-library */
	যদি ((handle = dlopen(provider_id, RTLD_NOW)) == ফাঁকা) {
		error("dlopen %s failed: %s", provider_id, dlerror());
		যাও fail;
	}
	যদি ((getfunctionlist = dlsym(handle, "C_GetFunctionList")) == ফাঁকা)
		fatal("dlsym(C_GetFunctionList) failed: %s", dlerror());
	p = xcalloc(1, আকার(*p));
	p->name = xstrdup(provider_id);
	p->handle = handle;
	/* set up the pkcs11 callbacks */
	যদি ((rv = (*getfunctionlist)(&f)) != CKR_OK) {
		error("C_GetFunctionList for provider %s failed: %lu",
		    provider_id, rv);
		যাও fail;
	}
	p->function_list = f;
	যদি ((rv = f->C_Initialize(ফাঁকা)) != CKR_OK) {
		error("C_Initialize for provider %s failed: %lu",
		    provider_id, rv);
		যাও fail;
	}
	need_finalize = 1;
	যদি ((rv = f->C_GetInfo(&p->info)) != CKR_OK) {
		error("C_GetInfo for provider %s failed: %lu",
		    provider_id, rv);
		যাও fail;
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
	যদি ((rv = f->C_GetSlotList(CK_TRUE, ফাঁকা, &p->nslots)) != CKR_OK) {
		error("C_GetSlotList failed: %lu", rv);
		যাও fail;
	}
	যদি (p->nslots == 0) {
		debug_f("provider %s returned no slots", provider_id);
		ret = -SSH_PKCS11_ERR_NO_SLOTS;
		যাও fail;
	}
	p->slotlist = xcalloc(p->nslots, আকার(CK_SLOT_ID));
	যদি ((rv = f->C_GetSlotList(CK_TRUE, p->slotlist, &p->nslots))
	    != CKR_OK) {
		error("C_GetSlotList for provider %s failed: %lu",
		    provider_id, rv);
		যাও fail;
	}
	p->slotinfo = xcalloc(p->nslots, আকার(কাঠামো pkcs11_slotinfo));
	p->valid = 1;
	nkeys = 0;
	জন্য (i = 0; i < p->nslots; i++) {
		token = &p->slotinfo[i].token;
		যদি ((rv = f->C_GetTokenInfo(p->slotlist[i], token))
		    != CKR_OK) {
			error("C_GetTokenInfo for provider %s slot %lu "
			    "failed: %lu", provider_id, (u_long)i, rv);
			চালু;
		}
		যদি ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
			debug2_f("ignoring uninitialised token in "
			    "provider %s slot %lu", provider_id, (u_long)i);
			চালু;
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
		    keyp == ফাঁকা)
			চালু;
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
				চালু;
			}
			pkcs11_fetch_চাবিগুলি(p, i, keyp, labelsp, &nkeys);
#ifdef WITH_OPENSSL
			pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#endif
		}
	}

	/* now owned by caller */
	*providerp = p;

	TAILQ_INSERT_TAIL(&pkcs11_providers, p, পরবর্তী);
	p->refcount++;	/* add to provider list */

	ফেরত (nkeys);
fail:
	যদি (need_finalize && (rv = f->C_Finalize(ফাঁকা)) != CKR_OK)
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
	ফেরত (ret);
}

পূর্ণসংখ্যা
pkcs11_init(পূর্ণসংখ্যা interactive)
{
	debug3_f("called, interactive = %d", interactive);

	pkcs11_interactive = interactive;
	TAILQ_INIT(&pkcs11_providers);
	TAILQ_INIT(&pkcs11_চাবিগুলি);
	ফেরত (0);
}

/* unregister all providers, keys might still point to the providers */
শূন্য
pkcs11_terminate(শূন্য)
{
	কাঠামো pkcs11_provider *p;
	কাঠামো pkcs11_চাবি *k11;

	debug3_f("called");

	যখন ((k11 = TAILQ_FIRST(&pkcs11_চাবিগুলি)) != ফাঁকা) {
		TAILQ_REMOVE(&pkcs11_চাবিগুলি, k11, পরবর্তী);
		pkcs11_k11_free(k11);
	}
	যখন ((p = TAILQ_FIRST(&pkcs11_providers)) != ফাঁকা) {
		TAILQ_REMOVE(&pkcs11_providers, p, পরবর্তী);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
}

/*
 * register a new provider and get number of keys hold by the token,
 * fails if provider already exists
 */
পূর্ণসংখ্যা
pkcs11_add_provider(অক্ষর *provider_id, অক্ষর *pin, কাঠামো sshkey ***keyp,
    অক্ষর ***labelsp)
{
	কাঠামো pkcs11_provider *p = ফাঁকা;
	পূর্ণসংখ্যা nkeys;

	nkeys = pkcs11_register_provider(provider_id, pin, keyp, labelsp,
	    &p, CKU_USER);

	/* no keys found or some other error, de-register provider */
	যদি (nkeys <= 0 && p != ফাঁকা) {
		TAILQ_REMOVE(&pkcs11_providers, p, পরবর্তী);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
	যদি (nkeys == 0)
		debug_f("provider %s returned no keys", provider_id);

	ফেরত (nkeys);
}

পূর্ণসংখ্যা
pkcs11_sign(কাঠামো sshkey *চাবি,
    u_char **sigp, আকার_t *lenp,
    ধ্রুবক u_char *তথ্য, আকার_t datalen,
    ধ্রুবক অক্ষর *alg, ধ্রুবক অক্ষর *sk_provider,
    ধ্রুবক অক্ষর *sk_pin, u_int compat)
{
	নির্বাচন (চাবি->type) {
#ifdef WITH_OPENSSL
	ক্ষেত্র চাবি_RSA:
	ক্ষেত্র চাবি_RSA_CERT:
		ফেরত pkcs11_sign_rsa(চাবি, sigp, lenp, তথ্য, datalen,
		    alg, sk_provider, sk_pin, compat);
	ক্ষেত্র চাবি_ECDSA:
	ক্ষেত্র চাবি_ECDSA_CERT:
		ফেরত pkcs11_sign_ecdsa(চাবি, sigp, lenp, তথ্য, datalen,
		    alg, sk_provider, sk_pin, compat);
#endif /* WITH_OPENSSL */
	ক্ষেত্র চাবি_ED25519:
	ক্ষেত্র চাবি_ED25519_CERT:
		ফেরত pkcs11_sign_ed25519(চাবি, sigp, lenp, তথ্য, datalen,
		    alg, sk_provider, sk_pin, compat);
	পূর্বনির্ধারিত:
		ফেরত SSH_ERR_চাবি_TYPE_UNKNOWN;
	}
}

শূন্য
pkcs11_চাবি_free(কাঠামো sshkey *চাবি)
{
	/* never called */
}

#ifdef WITH_PKCS11_KEYGEN
কাঠামো sshkey *
pkcs11_gakp(অক্ষর *provider_id, অক্ষর *pin, unsigned পূর্ণসংখ্যা slotidx, অক্ষর *label,
    unsigned পূর্ণসংখ্যা type, unsigned পূর্ণসংখ্যা bits, unsigned অক্ষর keyid, uint32_t *err)
{
	কাঠামো pkcs11_provider	*p = ফাঁকা;
	কাঠামো pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	কাঠামো sshkey		*k = ফাঁকা;
	পূর্ণসংখ্যা			 ret = -1, reset_pin = 0, reset_provider = 0;
	CK_RV			 rv;

	*err = 0;

	যদি ((p = pkcs11_provider_lookup(provider_id)) != ফাঁকা)
		debug_f("provider \"%s\" available", provider_id);
	অন্যথা যদি ((ret = pkcs11_register_provider(provider_id, pin, ফাঁকা, ফাঁকা,
	    &p, CKU_SO)) < 0) {
		debug_f("could not register provider %s", provider_id);
		যাও out;
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

	নির্বাচন (type) {
	ক্ষেত্র চাবি_RSA:
		যদি ((k = pkcs11_rsa_generate_private_চাবি(p, slotidx, label,
		    bits, keyid, err)) == ফাঁকা) {
			debug_f("failed to generate RSA key");
			যাও out;
		}
		বিরতি;
	ক্ষেত্র চাবি_ECDSA:
		যদি ((k = pkcs11_ecdsa_generate_private_চাবি(p, slotidx, label,
		    bits, keyid, err)) == ফাঁকা) {
			debug_f("failed to generate ECDSA key");
			যাও out;
		}
		বিরতি;
	পূর্বনির্ধারিত:
		*err = SSH_PKCS11_ERR_GENERIC;
		debug_f("unknown type %d", type);
		যাও out;
	}

out:
	যদি (reset_pin)
		f->C_SetOperationState(session , ফাঁকা, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	যদি (reset_provider)
		pkcs11_del_provider(provider_id);

	ফেরত (k);
}

কাঠামো sshkey *
pkcs11_destroy_keypair(অক্ষর *provider_id, অক্ষর *pin, unsigned long slotidx,
    unsigned অক্ষর keyid, uint32_t *err)
{
	কাঠামো pkcs11_provider	*p = ফাঁকা;
	কাঠামো pkcs11_slotinfo	*si;
	কাঠামো sshkey		*k = ফাঁকা;
	পূর্ণসংখ্যা			 reset_pin = 0, reset_provider = 0;
	CK_ULONG		 nattrs;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_ATTRIBUTE		 attrs[16];
	CK_OBJECT_CLASS		 চাবি_class;
	CK_চাবি_TYPE		 চাবি_type;
	CK_OBJECT_HANDLE	 obj = CK_INVALID_HANDLE;
	CK_RV			 rv;

	*err = 0;

	যদি ((p = pkcs11_provider_lookup(provider_id)) != ফাঁকা) {
		debug_f("using provider \"%s\"", provider_id);
	} অন্যথা যদি (pkcs11_register_provider(provider_id, pin, ফাঁকা, ফাঁকা, &p,
	    CKU_SO) < 0) {
		debug_f("could not register provider %s",
		    provider_id);
		যাও out;
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
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &চাবি_class, আকার(চাবি_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, আকার(keyid));

	যদি (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {
		যদি ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy private key 0x%hhx",
			    keyid);
			*err = rv;
			যাও out;
		}
	}

	/* public key */
	nattrs = 0;
	চাবি_class = CKO_PUBLIC_চাবি;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &চাবি_class, আকার(চাবি_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, আকার(keyid));

	যদি (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {

		/* get key type */
		nattrs = 0;
		FILL_ATTR(attrs, nattrs, CKA_চাবি_TYPE, &চাবি_type,
		    আকার(চাবি_type));
		rv = f->C_Get_Attribute_মান(session, obj, attrs, nattrs);
		যদি (rv != CKR_OK) {
			debug_f("could not get key type of public key 0x%hhx",
			    keyid);
			*err = rv;
			চাবি_type = -1;
		}
		নির্বাচন (চাবি_type) {
#ifdef WITH_OPENSSL
		ক্ষেত্র CKK_RSA:
			k = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			বিরতি;
		ক্ষেত্র CKK_ECDSA:
			k = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			বিরতি;
#endif /* WITH_OPENSSL */
		ক্ষেত্র CKK_EC_EDWARDS:
			k = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			বিরতি;
		পূর্বনির্ধারিত:
			debug_f("unsupported key type %lu", (u_long)চাবি_type);
			বিরতি;
		}

		যদি ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy public key 0x%hhx", keyid);
			*err = rv;
			যাও out;
		}
	}

out:
	যদি (reset_pin)
		f->C_SetOperationState(session , ফাঁকা, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	যদি (reset_provider)
		pkcs11_del_provider(provider_id);

	ফেরত (k);
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

পূর্ণসংখ্যা
pkcs11_init(পূর্ণসংখ্যা interactive)
{
	error_f("PKCS#11 not supported");
	ফেরত (-1);
}

পূর্ণসংখ্যা
pkcs11_add_provider(অক্ষর *provider_id, অক্ষর *pin, কাঠামো sshkey ***keyp,
    অক্ষর ***labelsp)
{
	error_f("PKCS#11 not supported");
	ফেরত (-1);
}

শূন্য
pkcs11_চাবি_free(কাঠামো sshkey *চাবি)
{
	error_f("PKCS#11 not supported");
}

পূর্ণসংখ্যা
pkcs11_sign(কাঠামো sshkey *চাবি,
    u_char **sigp, আকার_t *lenp,
    ধ্রুবক u_char *তথ্য, আকার_t datalen,
    ধ্রুবক অক্ষর *alg, ধ্রুবক অক্ষর *sk_provider,
    ধ্রুবক অক্ষর *sk_pin, u_int compat)
{
	error_f("PKCS#11 not supported");
	ফেরত SSH_ERR_FEATURE_UNSUPPORTED;
}

শূন্য
pkcs11_terminate(শূন্য)
{
	error_f("PKCS#11 not supported");
}
#endif /* ENABLE_PKCS11 */
