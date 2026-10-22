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

#شامل "includes.h"

#اگر_تعریف_شدہ ENABLE_PKCS11

#شامل <sys/time.h>

#شامل <sys/types.h>
#شامل <sys/queue.h>
#شامل <stdarg.h>
#شامل <stdio.h>

#شامل <string.h>
#شامل <dlfcn.h>

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل "openbsd-compat/openssl-compat.h"
#شامل <openssl/bn.h>
#شامل <openssl/ecdsa.h>
#شامل <openssl/x509.h>
#شامل <openssl/err.h>
#اگر_ختم

#تعریف_کرو CRYPTOKI_COMPAT
#شامل "pkcs11.h"

#تعریف_کرو SSHKEY_اندرونی
#شامل "sshkey.h"

#شامل "log.h"
#شامل "misc.h"
#شامل "sshbuf.h"
#شامل "ssh-pkcs11.h"
#شامل "digest.h"
#شامل "xmalloc.h"
#شامل "crypto_api.h"

ساخت pkcs11_slotinfo {
	CK_TOKEN_INFO		token;
	CK_SESSION_HANDLE	session;
	صحیح			logged_اندر;
};

ساخت pkcs11_provider {
	حرف			*name;
	خالی			*handle;
	CK_FUNCTION_LIST	*function_list;
	CK_INFO			info;
	CK_ULONG		nslots;
	CK_خانہ_ID		*slotlist;
	ساخت pkcs11_slotinfo	*slotinfo;
	صحیح			valid;
	صحیح			refcount;
	TAILQ_ENTRY(pkcs11_provider) اگلا;
};

TAILQ_HEAD(, pkcs11_provider) pkcs11_providers;

ساخت pkcs11_کلید {
	ساخت sshbuf		*keyblob;
	ساخت pkcs11_provider	*provider;
	CK_ULONG		slotidx;
	حرف			*keyid;
	صحیح			keyid_len;
	TAILQ_ENTRY(pkcs11_کلید)	اگلا;
};

TAILQ_HEAD(, pkcs11_کلید) pkcs11_کلیدیں; /* XXX a tree would be better */

صحیح pkcs11_interactive = 0;

#اگر_تعریف_شدہ WITH_OPENSSL
ساکن خالی
ossl_error(ثابت حرف *پیغام)
{
	غیرعلامتی طویل    e;

	error_f("%s", پیغام);
	جب ((e = ERR_get_error()) != 0)
		error_f("libcrypto error: %s", ERR_error_string(e, تہی));
}
#اگر_ختم

/*
 * finalize a provider shared library, it's no longer usable.
 * however, there might still be keys referencing this provider,
 * so the actual freeing of memory is handled by pkcs11_provider_unref().
 * this is called when a provider gets unregistered.
 */
ساکن خالی
pkcs11_provider_finalize(ساخت pkcs11_provider *p)
{
	CK_RV rv;
	CK_ULONG i;

	debug_f("provider \"%s\" refcount %d valid %d",
	    p->name, p->refcount, p->valid);
	اگر (!p->valid)
		واپس;
	برائے (i = 0; i < p->nslots; i++) {
		اگر (p->slotinfo[i].session &&
		    (rv = p->function_list->C_CloseSession(
		    p->slotinfo[i].session)) != CKR_OK)
			error("C_CloseSession failed: %lu", rv);
	}
	اگر ((rv = p->function_list->C_Finalize(تہی)) != CKR_OK)
		error("C_Finalize failed: %lu", rv);
	p->valid = 0;
	p->function_list = تہی;
	dlclose(p->handle);
}

/*
 * remove a reference to the provider.
 * called when a key gets destroyed or when the provider is unregistered.
 */
ساکن خالی
pkcs11_provider_unref(ساخت pkcs11_provider *p)
{
	debug_f("provider \"%s\" refcount %d", p->name, p->refcount);
	اگر (--p->refcount <= 0) {
		اگر (p->valid)
			error_f("provider \"%s\" still valid", p->name);
		آزاد(p->name);
		آزاد(p->slotlist);
		آزاد(p->slotinfo);
		آزاد(p);
	}
}

/* lookup provider by name */
ساکن ساخت pkcs11_provider *
pkcs11_provider_lookup(حرف *provider_id)
{
	ساخت pkcs11_provider *p;

	TAILQ_FOREACH(p, &pkcs11_providers, اگلا) {
		debug("check provider \"%s\"", p->name);
		اگر (!strcmp(provider_id, p->name))
			واپس (p);
	}
	واپس (تہی);
}

/* unregister provider by name */
صحیح
pkcs11_del_provider(حرف *provider_id)
{
	ساخت pkcs11_provider *p;

	اگر ((p = pkcs11_provider_lookup(provider_id)) != تہی) {
		TAILQ_REMOVE(&pkcs11_providers, p, اگلا);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
		واپس (0);
	}
	واپس (-1);
}

/* release a wrapped object */
ساکن خالی
pkcs11_k11_free(ساخت pkcs11_کلید *k11)
{
	اگر (k11 == تہی)
		واپس;
	اگر (k11->provider)
		pkcs11_provider_unref(k11->provider);
	آزاد(k11->keyid);
	sshbuf_free(k11->keyblob);
	آزاد(k11);
}

/* find a single 'obj' for given attributes */
ساکن صحیح
pkcs11_ڈھونڈو(ساخت pkcs11_provider *p, CK_ULONG slotidx, CK_ATTRIBUTE *attr,
    CK_ULONG nattr, CK_OBJECT_HANDLE *obj)
{
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	session;
	CK_ULONG		nfound = 0;
	CK_RV			rv;
	صحیح			ret = -1;

	f = p->function_list;
	session = p->slotinfo[slotidx].session;
	اگر ((rv = f->C_ڈھونڈو_Objects_Init(session, attr, nattr)) != CKR_OK) {
		error("C_FindObjectsInit failed (nattr %lu): %lu", nattr, rv);
		واپس (-1);
	}
	اگر ((rv = f->C_ڈھونڈو_Objects(session, obj, 1, &nfound)) != CKR_OK ||
	    nfound != 1) {
		debug("C_FindObjects failed (nfound %lu nattr %lu): %lu",
		    nfound, nattr, rv);
	} ورنہ
		ret = 0;
	اگر ((rv = f->C_ڈھونڈو_Objects_Final(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	واپس (ret);
}

ساکن صحیح
pkcs11_login_خانہ(ساخت pkcs11_provider *provider, ساخت pkcs11_slotinfo *si,
    CK_USER_TYPE type)
{
	حرف			*pin = تہی, prompt[1024];
	CK_RV			 rv;

	اگر (provider == تہی || si == تہی || !provider->valid) {
		error("no pkcs11 (valid) provider found");
		واپس (-1);
	}

	اگر (!pkcs11_interactive) {
		error("need pin entry%s",
		    (si->token.flags & CKF_PROTECTED_AUTHENTICATION_راستہ) ?
		    " on reader keypad" : "");
		واپس (-1);
	}
	اگر (si->token.flags & CKF_PROTECTED_AUTHENTICATION_راستہ)
		verbose("Deferring PIN entry to reader keypad.");
	ورنہ {
		snprintf(prompt, حجم(prompt), "Enter PIN for '%s': ",
		    si->token.label);
		اگر ((pin = read_passphrase(prompt, RP_ALLOW_EOF)) == تہی) {
			debug_f("no pin specified");
			واپس (-1);	/* bail out */
		}
	}
	rv = provider->function_list->C_Login(si->session, type, (u_char *)pin,
	    (pin != تہی) ? لڑی_لمبائی(pin) : 0);
	اگر (pin != تہی)
		freezero(pin, لڑی_لمبائی(pin));

	انتخاب (rv) {
	حالت CKR_OK:
	حالت CKR_USER_ALREADY_LOGGED_اندر:
		/* success */
		توڑو;
	حالت CKR_PIN_LEN_RANGE:
		error("PKCS#11 login failed: PIN length out of range");
		واپس -1;
	حالت CKR_PIN_INCORRECT:
		error("PKCS#11 login failed: PIN incorrect");
		واپس -1;
	حالت CKR_PIN_LOCKED:
		error("PKCS#11 login failed: PIN locked");
		واپس -1;
	طےشدہ:
		error("PKCS#11 login failed: error %lu", rv);
		واپس -1;
	}
	si->logged_اندر = 1;
	واپس (0);
}

ساکن صحیح
pkcs11_login(ساخت pkcs11_کلید *k11, CK_USER_TYPE type)
{
	اگر (k11 == تہی || k11->provider == تہی || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		واپس (-1);
	}

	واپس pkcs11_login_خانہ(k11->provider,
	    &k11->provider->slotinfo[k11->slotidx], type);
}


ساکن صحیح
pkcs11_check_obj_bool_attrib(ساخت pkcs11_کلید *k11, CK_OBJECT_HANDLE obj,
    CK_ATTRIBUTE_TYPE type, صحیح *val)
{
	ساخت pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_BBOOL		flag = 0;
	CK_ATTRIBUTE		attr;
	CK_RV			 rv;

	*val = 0;

	اگر (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		واپس (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	attr.type = type;
	attr.p_قدر = &flag;
	attr.ul_قدر_Len = حجم(flag);

	rv = f->C_Get_Attribute_قدر(si->session, obj, &attr, 1);
	اگر (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		واپس (-1);
	}
	*val = flag != 0;
	debug_f("provider \"%s\" slot %lu object %lu: attrib %lu = %d",
	    k11->provider->name, k11->slotidx, obj, type, *val);
	واپس (0);
}

ساکن صحیح
pkcs11_get_کلید(ساخت pkcs11_کلید *k11, CK_MECHANISM_TYPE mech_type)
{
	ساخت pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	 obj;
	CK_RV			 rv;
	CK_OBJECT_CLASS		 نجی_کلید_class;
	CK_BBOOL		 true_val;
	CK_MECHANISM		 mech;
	CK_ATTRIBUTE		 کلید_filter[3];
	صحیح			 always_auth = 0;
	صحیح			 did_login = 0;

	اگر (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		واپس (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	اگر ((si->token.flags & CKF_LOGIN_REQUIRED) && !si->logged_اندر) {
		اگر (pkcs11_login(k11, CKU_USER) < 0) {
			error("login failed");
			واپس (-1);
		}
		did_login = 1;
	}

	memset(&کلید_filter, 0, حجم(کلید_filter));
	نجی_کلید_class = CKO_نجی_کلید;
	کلید_filter[0].type = CKA_CLASS;
	کلید_filter[0].p_قدر = &نجی_کلید_class;
	کلید_filter[0].ul_قدر_Len = حجم(نجی_کلید_class);

	کلید_filter[1].type = CKA_ID;
	کلید_filter[1].p_قدر = k11->keyid;
	کلید_filter[1].ul_قدر_Len = k11->keyid_len;

	true_val = CK_TRUE;
	کلید_filter[2].type = CKA_SIGN;
	کلید_filter[2].p_قدر = &true_val;
	کلید_filter[2].ul_قدر_Len = حجم(true_val);

	/* try to find object w/CKA_SIGN first, retry w/o */
	اگر (pkcs11_ڈھونڈو(k11->provider, k11->slotidx, کلید_filter, 3, &obj) < 0 &&
	    pkcs11_ڈھونڈو(k11->provider, k11->slotidx, کلید_filter, 2, &obj) < 0) {
		error("cannot find private key");
		واپس (-1);
	}

	memset(&mech, 0, حجم(mech));
	mech.mechanism = mech_type;
	mech.pParameter = NULL_PTR;
	mech.ulParameterLen = 0;

	اگر ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
		واپس (-1);
	}

	pkcs11_check_obj_bool_attrib(k11, obj, CKA_ALWAYS_AUTHENTICATE,
	    &always_auth); /* ignore errors here */
	اگر (always_auth && !did_login) {
		debug_f("always-auth key");
		اگر (pkcs11_login(k11, CKU_CONTEXT_SPECIFIC) < 0) {
			error("login failed for always-auth key");
			واپس (-1);
		}
	}

	واپس (0);
}

/* record the key information later use lookup by keyblob */
ساکن صحیح
pkcs11_ریکارڈ_کلید(ساخت pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, ساخت sshkey *کلید)
{
	ساخت sshbuf *keyblob;
	ساخت pkcs11_کلید *k11;
	صحیح r;
	حرف *hex;

	hex = tohex(keyid_attrib->p_قدر, keyid_attrib->ul_قدر_Len);
	debug_f("%s key: provider %s slot %lu keyid %s",
	    sshkey_type(کلید), provider->name, (u_long)slotidx, hex);
	آزاد(hex);

	اگر ((keyblob = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshkey_putb(کلید, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");

	/* Check if we've already recorded this key in a different slot */
	TAILQ_FOREACH(k11, &pkcs11_کلیدیں, اگلا) {
		اگر (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			hex = tohex(k11->keyid, k11->keyid_len);
			debug_f("Already seen this key at "
			    "provider %s slot %lu keyid %s",
			    k11->provider->name, k11->slotidx, hex);
			آزاد(hex);
			sshbuf_free(keyblob);
			واپس -1;
		}
	}

	k11 = xcalloc(1, حجم(*k11));
	k11->provider = provider;
	k11->keyblob = keyblob;
	provider->refcount++;	/* provider referenced by RSA key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ul_قدر_Len;
	اگر (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len);
		حافظہ_نقل(k11->keyid, keyid_attrib->p_قدر, k11->keyid_len);
	}
	TAILQ_INSERT_TAIL(&pkcs11_کلیدیں, k11, اگلا);

	واپس 0;
}

/* retrieve the key information by keyblob */
ساکن ساخت pkcs11_کلید *
pkcs11_lookup_کلید(ساخت sshkey *کلید)
{
	ساخت pkcs11_کلید *k11, *ملا = تہی;
	ساخت sshbuf *keyblob;
	صحیح r;

	اگر ((keyblob = sshbuf_new()) == تہی)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshkey_putb(کلید, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");
	TAILQ_FOREACH(k11, &pkcs11_کلیدیں, اگلا) {
		اگر (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			ملا = k11;
			توڑو;
		}
	}
	sshbuf_free(keyblob);
	واپس ملا;
}

#اگر_تعریف_شدہ WITH_OPENSSL
/*
 * See:
 * https://datatracker.ietf.org/doc/html/rfc8017#section-9.2
 */

/*
 * id-sha1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
 *	oiw(14) secsig(3) algorithms(2) 26 }
 */
ساکن ثابت u_char id_sha1[] = {
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
ساکن ثابت u_char id_sha256[] = {
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
ساکن ثابت u_char id_sha512[] = {
	0x30, 0x51, /* type Sequence, length 0x51 (81) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, /* id-sha512 */
	0x05, 0x00, /* NULL */
	0x04, 0x40  /* Octet string, length 0x40 (64), followed by sha512 hash */
};

ساکن صحیح
rsa_hash_alg_oid(صحیح hash_alg, ثابت u_char **oidp, سائز_t *oidlenp)
{
	انتخاب (hash_alg) {
	حالت SSH_DIGEST_SHA1:
		*oidp = id_sha1;
		*oidlenp = حجم(id_sha1);
		توڑو;
	حالت SSH_DIGEST_SHA256:
		*oidp = id_sha256;
		*oidlenp = حجم(id_sha256);
		توڑو;
	حالت SSH_DIGEST_SHA512:
		*oidp = id_sha512;
		*oidlenp = حجم(id_sha512);
		توڑو;
	طےشدہ:
		واپس SSH_ERR_INVALID_دلیل;
	}
	واپس 0;
}

ساکن صحیح
pkcs11_sign_rsa(ساخت sshkey *کلید,
    u_char **sigp, سائز_t *lenp,
    ثابت u_char *ڈیٹا, سائز_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider,
    ثابت حرف *sk_pin, u_int compat)
{
	ساخت pkcs11_کلید	*k11;
	ساخت pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	صحیح			hashalg, r, diff, siglen, ret = -1;
	u_char			*oid_dgst = تہی, *sig = تہی;
	سائز_t			dgst_len, oid_len, oid_dgst_len = 0;
	ثابت u_char		*oid;

	اگر (sigp != تہی)
		*sigp = تہی;
	اگر (lenp != تہی)
		*lenp = 0;

	اگر ((k11 = pkcs11_lookup_کلید(کلید)) == تہی) {
		error_f("no key found");
		واپس SSH_ERR_کلید_NOT_ملا;
	}

	debug3_f("sign with alg \"%s\" using provider %s slotidx %lu",
	    alg == تہی ? "" : alg, k11->provider->name, (u_long)k11->slotidx);

	اگر (pkcs11_get_کلید(k11, CKM_RSA_PKCS) == -1) {
		error("pkcs11_get_key failed");
		واپس SSH_ERR_AGENT_FAILURE;
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	اگر ((siglen = EVP_PKEY_سائز(کلید->pkey)) <= 0)
		واپس SSH_ERR_INVALID_دلیل;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* Determine hash algorithm and OID for signature */
	اگر (alg == تہی || *alg == '\0')
		hashalg = SSH_DIGEST_SHA1;
	ورنہ اگر ((hashalg = ssh_rsa_hash_id_from_keyname(alg)) == -1)
		fatal_f("couldn't determine RSA hash alg \"%s\"", alg);
	اگر ((r = rsa_hash_alg_oid(hashalg, &oid, &oid_len)) != 0)
		fatal_fr(r, "rsa_hash_alg_oid failed");
	اگر ((dgst_len = ssh_digest_بائٹیں(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);

	/* Prepare { oid || digest } */
	oid_dgst_len = oid_len + dgst_len;
	oid_dgst = xcalloc(1, oid_dgst_len);
	حافظہ_نقل(oid_dgst, oid, oid_len);
	اگر ((r = ssh_digest_حافظہ(hashalg, ڈیٹا, datalen,
	    oid_dgst + oid_len, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	اگر ((rv = f->C_Sign(si->session, (CK_BYTE *)oid_dgst,
	    oid_dgst_len, sig, &slen)) != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		جاؤ مکمل;
	}

	اگر (slen < (CK_ULONG)siglen) {
		diff = siglen - slen;
		debug3_f("repack %lu < %d (diff %d)",
		    (u_long)slen, siglen, diff);
		memmove(sig + diff, sig, slen);
		explicit_bzero(sig, diff);
	} ورنہ اگر (slen > (سائز_t)siglen)
		fatal_f("bad C_Sign length");

	اگر ((ret = ssh_rsa_encode_store_sig(hashalg, sig, siglen,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 مکمل:
	freezero(oid_dgst, oid_dgst_len);
	آزاد(sig);
	واپس ret;
}

ساکن صحیح
pkcs11_sign_ecdsa(ساخت sshkey *کلید,
    u_char **sigp, سائز_t *lenp,
    ثابت u_char *ڈیٹا, سائز_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider,
    ثابت حرف *sk_pin, u_int compat)
{
	ساخت pkcs11_کلید	*k11;
	ساخت pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0, bnlen;
	CK_RV			rv;
	BIGNUM			*sig_r = تہی, *sig_s = تہی;
	u_char			*sig = تہی, *dgst = تہی;
	سائز_t			dgst_len = 0;
	صحیح			hashalg, ret = -1, r, siglen;

	اگر (sigp != تہی)
		*sigp = تہی;
	اگر (lenp != تہی)
		*lenp = 0;

	اگر ((k11 = pkcs11_lookup_کلید(کلید)) == تہی) {
		error_f("no key found");
		واپس SSH_ERR_کلید_NOT_ملا;
	}

	اگر (pkcs11_get_کلید(k11, CKM_ECDSA) == -1) {
		error("pkcs11_get_key failed");
		واپس SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	/* Prepare digest to be signed */
	اگر ((hashalg = sshkey_ec_nid_مقصد_hash_alg(کلید->ecdsa_nid)) == -1)
		fatal_f("couldn't determine ECDSA hash alg");
	اگر ((dgst_len = ssh_digest_بائٹیں(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);
	dgst = xcalloc(1, dgst_len);
	اگر ((r = ssh_digest_حافظہ(hashalg, ڈیٹا, datalen,
	    dgst, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	اگر ((siglen = EVP_PKEY_سائز(کلید->pkey)) <= 0)
		واپس SSH_ERR_INVALID_دلیل;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dgst_len, sig, &slen);
	اگر (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		جاؤ مکمل;
	}
	اگر (slen < 64 || slen > 132 || slen % 2) {
		error_f("bad signature length: %lu", (u_long)slen);
		جاؤ مکمل;
	}
	bnlen = slen/2;
	اگر ((sig_r = BN_bin2bn(sig, bnlen, تہی)) == تہی ||
	    (sig_s = BN_bin2bn(sig+bnlen, bnlen, تہی)) == تہی) {
		ossl_error("BN_bin2bn failed");
		جاؤ مکمل;
	}

	اگر ((ret = ssh_ecdsa_encode_store_sig(کلید, sig_r, sig_s,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 مکمل:
	freezero(dgst, dgst_len);
	BN_free(sig_r);
	BN_free(sig_s);
	آزاد(sig);
	واپس ret;
}
#اگر_ختم /* WITH_OPENSSL */

ساکن صحیح
pkcs11_sign_ed25519(ساخت sshkey *کلید,
    u_char **sigp, سائز_t *lenp,
    ثابت u_char *ڈیٹا, سائز_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider,
    ثابت حرف *sk_pin, u_int compat)
{
	ساخت pkcs11_کلید	*k11;
	ساخت pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	u_char			*sig = تہی;
	CK_BYTE			*xdata = تہی;
	صحیح			ret = -1;

	اگر (sigp != تہی)
		*sigp = تہی;
	اگر (lenp != تہی)
		*lenp = 0;

	اگر ((k11 = pkcs11_lookup_کلید(کلید)) == تہی) {
		error_f("no key found");
		واپس SSH_ERR_کلید_NOT_ملا;
	}

	اگر (pkcs11_get_کلید(k11, CKM_EDDSA) == -1) {
		error("pkcs11_get_key failed");
		واپس SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	xdata = xmalloc(datalen);
	حافظہ_نقل(xdata, ڈیٹا, datalen);
	sig = xmalloc(crypto_sign_ed25519_بائٹیں);
	slen = crypto_sign_ed25519_بائٹیں;

	rv = f->C_Sign(si->session, xdata, datalen, sig, &slen);
	اگر (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		جاؤ مکمل;
	}
	اگر (slen != crypto_sign_ed25519_بائٹیں) {
		error_f("bad signature length: %lu", (u_long)slen);
		جاؤ مکمل;
	}
	اگر ((ret = ssh_ed25519_encode_store_sig(sig, slen, sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 مکمل:
	اگر (xdata != تہی)
		freezero(xdata, datalen);
	آزاد(sig);
	واپس ret;
}

/* remove trailing spaces */
ساکن حرف *
rmspace(u_char *buf, سائز_t len)
{
	سائز_t i;

	اگر (len == 0)
		واپس buf;
	برائے (i = len - 1; i > 0; i--)
		اگر (buf[i] == ' ')
			buf[i] = '\0';
		ورنہ
			توڑو;
	واپس buf;
}
/* Used to printf fixed-width, space-padded, unterminated strings using %.*s */
#تعریف_کرو RMSPACE(s) (صحیح)حجم(s), rmspace(s, حجم(s))

/*
 * open a pkcs11 session and login if required.
 * if pin == NULL we delay login until key use
 */
ساکن صحیح
pkcs11_open_session(ساخت pkcs11_provider *p, CK_ULONG slotidx, حرف *pin,
    CK_ULONG user)
{
	ساخت pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_RV			rv;
	CK_SESSION_HANDLE	session;
	صحیح			login_required, ret;

	f = p->function_list;
	si = &p->slotinfo[slotidx];

	login_required = si->token.flags & CKF_LOGIN_REQUIRED;

	/* fail early before opening session */
	اگر (login_required && !pkcs11_interactive &&
	    (pin == تہی || لڑی_لمبائی(pin) == 0)) {
		error("pin required");
		واپس (-SSH_PKCS11_ERR_PIN_REQUIRED);
	}
	اگر ((rv = f->C_OpenSession(p->slotlist[slotidx], CKF_RW_SESSION|
	    CKF_SERIAL_SESSION, تہی, تہی, &session)) != CKR_OK) {
		error("C_OpenSession failed: %lu", rv);
		واپس (-1);
	}
	اگر (login_required && pin != تہی && لڑی_لمبائی(pin) != 0) {
		rv = f->C_Login(session, user, (u_char *)pin, لڑی_لمبائی(pin));
		اگر (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_اندر) {
			error("C_Login failed: %lu", rv);
			ret = (rv == CKR_PIN_LOCKED) ?
			    -SSH_PKCS11_ERR_PIN_LOCKED :
			    -SSH_PKCS11_ERR_LOGIN_FAIL;
			اگر ((rv = f->C_CloseSession(session)) != CKR_OK)
				error("C_CloseSession failed: %lu", rv);
			واپس (ret);
		}
		si->logged_اندر = 1;
	}
	si->session = session;
	واپس (0);
}

ساکن صحیح
pkcs11_کلید_included(ساخت sshkey ***keysp, صحیح *nkeys, ساخت sshkey *کلید)
{
	صحیح i;

	برائے (i = 0; i < *nkeys; i++)
		اگر (sshkey_equal(کلید, (*keysp)[i]))
			واپس (1);
	واپس (0);
}

#اگر_تعریف_شدہ WITH_OPENSSL
ساکن ساخت sshkey *
pkcs11_fetch_ecdsa_pubkey(ساخت pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 کلید_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = تہی;
	CK_RV			 rv;
	ASN1_OCTET_STRING	*octet = تہی;
	EC_کلید			*ec = تہی;
	EC_گروہ		*گروہ = تہی;
	ساخت sshkey		*کلید = تہی;
	ثابت غیرعلامتی حرف	*attrp = تہی;
	صحیح			 success = -1, r, i, nid;

	memset(&کلید_attr, 0, حجم(کلید_attr));
	کلید_attr[0].type = CKA_ID;
	کلید_attr[1].type = CKA_EC_نقطہ;
	کلید_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_قدر(session, *obj, کلید_attr, 3);
	اگر (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		واپس (تہی);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	اگر (کلید_attr[1].ul_قدر_Len == 0 ||
	    کلید_attr[2].ul_قدر_Len == 0) {
		error("invalid attribute length");
		واپس (تہی);
	}

	/* allocate buffers for attributes */
	برائے (i = 0; i < 3; i++)
		اگر (کلید_attr[i].ul_قدر_Len > 0)
			کلید_attr[i].p_قدر = xcalloc(1, کلید_attr[i].ul_قدر_Len);

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_قدر(session, *obj, کلید_attr, 3);
	اگر (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		جاؤ fail;
	}

	ec = EC_کلید_new();
	اگر (ec == تہی) {
		error("EC_KEY_new failed");
		جاؤ fail;
	}

	attrp = کلید_attr[2].p_قدر;
	گروہ = d2i_ECPKParameters(تہی, &attrp, کلید_attr[2].ul_قدر_Len);
	اگر (گروہ == تہی) {
		ossl_error("d2i_ECPKParameters failed");
		جاؤ fail;
	}

	اگر (EC_کلید_سیٹ_گروہ(ec, گروہ) == 0) {
		ossl_error("EC_KEY_set_group failed");
		جاؤ fail;
	}

	اگر (کلید_attr[1].ul_قدر_Len <= 2) {
		error("CKA_EC_POINT too small");
		جاؤ fail;
	}

	attrp = کلید_attr[1].p_قدر;
	octet = d2i_ASN1_OCTET_STRING(تہی, &attrp, کلید_attr[1].ul_قدر_Len);
	اگر (octet == تہی) {
		ossl_error("d2i_ASN1_OCTET_STRING failed");
		جاؤ fail;
	}
	attrp = ASN1_STRING_get0_ڈیٹا(octet);
	اگر (o2i_ECPublic_کلید(&ec, &attrp, ASN1_STRING_لمبائی(octet)) == تہی) {
		ossl_error("o2i_ECPublicKey failed");
		جاؤ fail;
	}
	اگر ((r = sshkey_ec_validate_عوامی(EC_کلید_get0_گروہ(ec),
	    EC_کلید_get0_عوامی_کلید(ec))) != 0) {
		error_fr(r, "invalid EC key");
		جاؤ fail;
	}

	nid = sshkey_ecdsa_کلید_مقصد_nid(ec);
	اگر (nid < 0) {
		error("couldn't get curve nid");
		جاؤ fail;
	}

	کلید = sshkey_new(کلید_UNSPEC);
	اگر (کلید == تہی) {
		error("sshkey_new failed");
		جاؤ fail;
	}

	EVP_PKEY_free(کلید->pkey);
	اگر ((کلید->pkey = EVP_PKEY_new()) == تہی)
		fatal("EVP_PKEY_new failed");
	اگر (EVP_PKEY_set1_EC_کلید(کلید->pkey, ec) != 1)
		fatal("EVP_PKEY_set1_EC_KEY failed");
	کلید->ecdsa_nid = nid;
	کلید->type = کلید_ECDSA;
	کلید->flags |= SSHKEY_FLAG_EXT;
	اگر (pkcs11_ریکارڈ_کلید(p, slotidx, &کلید_attr[0], کلید))
		جاؤ fail;
	/* success */
	success = 0;
fail:
	اگر (success != 0) {
		sshkey_free(کلید);
		کلید = تہی;
	}
	برائے (i = 0; i < 3; i++)
		آزاد(کلید_attr[i].p_قدر);
	اگر (ec)
		EC_کلید_free(ec);
	اگر (گروہ)
		EC_گروہ_free(گروہ);
	اگر (octet)
		ASN1_OCTET_STRING_free(octet);

	واپس (کلید);
}

ساکن ساخت sshkey *
pkcs11_fetch_rsa_pubkey(ساخت pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 کلید_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = تہی;
	CK_RV			 rv;
	RSA			*rsa = تہی;
	BIGNUM			*rsa_n, *rsa_e;
	ساخت sshkey		*کلید = تہی;
	صحیح			 i, success = -1;

	memset(&کلید_attr, 0, حجم(کلید_attr));
	کلید_attr[0].type = CKA_ID;
	کلید_attr[1].type = CKA_MODULUS;
	کلید_attr[2].type = CKA_عوامی_EXPONENT;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_قدر(session, *obj, کلید_attr, 3);
	اگر (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		واپس (تہی);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	اگر (کلید_attr[1].ul_قدر_Len == 0 ||
	    کلید_attr[2].ul_قدر_Len == 0) {
		error("invalid attribute length");
		واپس (تہی);
	}

	/* allocate buffers for attributes */
	برائے (i = 0; i < 3; i++)
		اگر (کلید_attr[i].ul_قدر_Len > 0)
			کلید_attr[i].p_قدر = xcalloc(1, کلید_attr[i].ul_قدر_Len);

	/* retrieve ID, modulus and public exponent of RSA key */
	rv = f->C_Get_Attribute_قدر(session, *obj, کلید_attr, 3);
	اگر (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		جاؤ fail;
	}

	rsa = RSA_new();
	اگر (rsa == تہی) {
		error("RSA_new failed");
		جاؤ fail;
	}

	rsa_n = BN_bin2bn(کلید_attr[1].p_قدر, کلید_attr[1].ul_قدر_Len, تہی);
	rsa_e = BN_bin2bn(کلید_attr[2].p_قدر, کلید_attr[2].ul_قدر_Len, تہی);
	اگر (rsa_n == تہی || rsa_e == تہی) {
		error("BN_bin2bn failed");
		جاؤ fail;
	}
	اگر (!RSA_set0_کلید(rsa, rsa_n, rsa_e, تہی))
		fatal_f("set key");
	rsa_n = rsa_e = تہی; /* transferred */

	کلید = sshkey_new(کلید_UNSPEC);
	اگر (کلید == تہی) {
		error("sshkey_new failed");
		جاؤ fail;
	}

	EVP_PKEY_free(کلید->pkey);
	اگر ((کلید->pkey = EVP_PKEY_new()) == تہی)
		fatal("EVP_PKEY_new failed");
	اگر (EVP_PKEY_set1_RSA(کلید->pkey, rsa) != 1)
		fatal("EVP_PKEY_set1_RSA failed");
	کلید->type = کلید_RSA;
	کلید->flags |= SSHKEY_FLAG_EXT;
	اگر (EVP_PKEY_بٹ(کلید->pkey) < SSH_RSA_MINIMUM_MODULUS_سائز) {
		error_f("RSA key too small %d < minimum %d",
		    EVP_PKEY_بٹ(کلید->pkey), SSH_RSA_MINIMUM_MODULUS_سائز);
		جاؤ fail;
	}
	اگر (pkcs11_ریکارڈ_کلید(p, slotidx, &کلید_attr[0], کلید))
		جاؤ fail;
	/* success */
	success = 0;
fail:
	برائے (i = 0; i < 3; i++)
		آزاد(کلید_attr[i].p_قدر);
	RSA_free(rsa);
	اگر (success != 0) {
		sshkey_free(کلید);
		کلید = تہی;
	}
	واپس کلید;
}
#اگر_ختم /* WITH_OPENSSL */

ساکن ساخت sshkey *
pkcs11_fetch_ed25519_pubkey(ساخت pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 کلید_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = تہی;
	CK_RV			 rv;
	ساخت sshkey		*کلید = تہی;
	ثابت غیرعلامتی حرف	*d = تہی;
	سائز_t			len;
	حرف			*hex = تہی;
	صحیح			 success = -1, i;
	/* https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061180 */
	ثابت u_char		 id1[14] = {
		0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64,
		0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
	}; /* PrintableString { "edwards25519" } */
	ثابت u_char		 id2[5] = {
		0x06, 0x03, 0x2b, 0x65, 0x70,
	}; /* OBJECT_IDENTIFIER { 1.3.101.112 } */

	memset(&کلید_attr, 0, حجم(کلید_attr));
	کلید_attr[0].type = CKA_ID;
	کلید_attr[1].type = CKA_EC_نقطہ; /* XXX or CKA_VALUE ? */
	کلید_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_قدر(session, *obj, کلید_attr, 3);
	اگر (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		واپس (تہی);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	اگر (کلید_attr[1].ul_قدر_Len == 0 ||
	    کلید_attr[2].ul_قدر_Len == 0) {
		error("invalid attribute length");
		واپس (تہی);
	}

	/* allocate buffers for attributes */
	برائے (i = 0; i < 3; i++) {
		اگر (کلید_attr[i].ul_قدر_Len > 0)
			کلید_attr[i].p_قدر = xcalloc(1, کلید_attr[i].ul_قدر_Len);
	}

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_قدر(session, *obj, کلید_attr, 3);
	اگر (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		جاؤ fail;
	}

	/* Expect one of the supported identifiers in CKA_EC_PARAMS */
	d = (u_char *)کلید_attr[2].p_قدر;
	len = کلید_attr[2].ul_قدر_Len;
	اگر ((len != حجم(id1) || memcmp(d, id1, حجم(id1)) != 0) &&
	    (len != حجم(id2) || memcmp(d, id2, حجم(id2)) != 0)) {
		hex = tohex(d, len);
		logit_f("unsupported CKA_EC_PARAMS: %s (len %zu)", hex, len);
		جاؤ fail;
	}

	/*
	 * Expect either a raw 32 byte pubkey or an OCTET STRING with
	 * a 32 byte pubkey in CKA_VALUE
	 */
	d = (u_char *)کلید_attr[1].p_قدر;
	len = کلید_attr[1].ul_قدر_Len;
	اگر (len == ED25519_PK_SZ + 2 && d[0] == 0x04 && d[1] == ED25519_PK_SZ) {
		d += 2;
		len -= 2;
	}
	اگر (len != ED25519_PK_SZ) {
		hex = tohex(کلید_attr[1].p_قدر, کلید_attr[1].ul_قدر_Len);
		logit_f("CKA_EC_POINT invalid octet str: %s (len %lu)",
		    hex, (u_long)کلید_attr[1].ul_قدر_Len);
		جاؤ fail;
	}

	اگر ((کلید = sshkey_new(کلید_UNSPEC)) == تہی)
		fatal_f("sshkey_new failed");
	کلید->ed25519_pk = xmalloc(ED25519_PK_SZ);
	حافظہ_نقل(کلید->ed25519_pk, d, ED25519_PK_SZ);
	کلید->type = کلید_ED25519;
	کلید->flags |= SSHKEY_FLAG_EXT;
	اگر (pkcs11_ریکارڈ_کلید(p, slotidx, &کلید_attr[0], کلید))
		جاؤ fail;
	/* success */
	success = 0;
 fail:
	اگر (success != 0) {
		sshkey_free(کلید);
		کلید = تہی;
	}
	آزاد(hex);
	برائے (i = 0; i < 3; i++)
		آزاد(کلید_attr[i].p_قدر);
	واپس کلید;
}

#اگر_تعریف_شدہ WITH_OPENSSL
ساکن صحیح
pkcs11_fetch_x509_pubkey(ساخت pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj, ساخت sshkey **keyp, حرف **labelp)
{
	CK_ATTRIBUTE		 cert_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = تہی;
	CK_RV			 rv;
	X509			*x509 = تہی;
	X509_NAME		*x509_name = تہی;
	EVP_PKEY		*evp;
	RSA			*rsa = تہی;
	EC_کلید			*ec = تہی;
	ساخت sshkey		*کلید = تہی;
	صحیح			 r, i, nid, success = -1;
	ثابت u_char		*cp;
	حرف			*subject = تہی;
#اگر_تعریف_شدہ OPENSSL_HAS_ED25519
	سائز_t			len;
#اگر_ختم /* OPENSSL_HAS_ED25519 */

	*keyp = تہی;
	*labelp = تہی;

	memset(&cert_attr, 0, حجم(cert_attr));
	cert_attr[0].type = CKA_ID;
	cert_attr[1].type = CKA_SUBJECT;
	cert_attr[2].type = CKA_قدر;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_قدر(session, *obj, cert_attr, 3);
	اگر (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		واپس -1;
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	اگر (cert_attr[1].ul_قدر_Len == 0 ||
	    cert_attr[2].ul_قدر_Len == 0) {
		error("invalid attribute length");
		واپس -1;
	}

	/* allocate buffers for attributes */
	برائے (i = 0; i < 3; i++)
		اگر (cert_attr[i].ul_قدر_Len > 0)
			cert_attr[i].p_قدر = xcalloc(1, cert_attr[i].ul_قدر_Len);

	/* retrieve ID, subject and value of certificate */
	rv = f->C_Get_Attribute_قدر(session, *obj, cert_attr, 3);
	اگر (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		جاؤ برآمد;
	}

	/* Decode DER-encoded cert subject */
	cp = cert_attr[1].p_قدر;
	اگر ((x509_name = d2i_X509_NAME(تہی, &cp,
	    cert_attr[1].ul_قدر_Len)) == تہی ||
	    (subject = X509_NAME_oneline(x509_name, تہی, 0)) == تہی)
		subject = xstrdup("invalid subject");
	X509_NAME_free(x509_name);

	cp = cert_attr[2].p_قدر;
	اگر ((x509 = d2i_X509(تہی, &cp, cert_attr[2].ul_قدر_Len)) == تہی) {
		error("d2i_x509 failed");
		جاؤ برآمد;
	}

	اگر ((evp = X509_get_pubkey(x509)) == تہی) {
		error("X509_get_pubkey failed");
		جاؤ برآمد;
	}

	اگر (EVP_PKEY_بنیاد_id(evp) == EVP_PKEY_RSA) {
		اگر (EVP_PKEY_get0_RSA(evp) == تہی) {
			error("invalid x509; no rsa key");
			جاؤ برآمد;
		}
		اگر ((rsa = RSAPublic_کلید_dup(EVP_PKEY_get0_RSA(evp))) == تہی) {
			error("RSAPublicKey_dup failed");
			جاؤ برآمد;
		}

		کلید = sshkey_new(کلید_UNSPEC);
		اگر (کلید == تہی) {
			error("sshkey_new failed");
			جاؤ برآمد;
		}

		EVP_PKEY_free(کلید->pkey);
		اگر ((کلید->pkey = EVP_PKEY_new()) == تہی)
			fatal("EVP_PKEY_new failed");
		اگر (EVP_PKEY_set1_RSA(کلید->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		کلید->type = کلید_RSA;
		کلید->flags |= SSHKEY_FLAG_EXT;
		اگر (EVP_PKEY_بٹ(کلید->pkey) < SSH_RSA_MINIMUM_MODULUS_سائز) {
			error_f("RSA key too small %d < minimum %d",
			    EVP_PKEY_بٹ(کلید->pkey),
			    SSH_RSA_MINIMUM_MODULUS_سائز);
			جاؤ برآمد;
		}
		اگر (pkcs11_ریکارڈ_کلید(p, slotidx, &cert_attr[0], کلید))
			جاؤ برآمد;
		/* success */
		success = 0;
	} ورنہ اگر (EVP_PKEY_بنیاد_id(evp) == EVP_PKEY_EC) {
		اگر (EVP_PKEY_get0_EC_کلید(evp) == تہی) {
			error("invalid x509; no ec key");
			جاؤ برآمد;
		}
		اگر ((ec = EC_کلید_dup(EVP_PKEY_get0_EC_کلید(evp))) == تہی) {
			error("EC_KEY_dup failed");
			جاؤ برآمد;
		}
		اگر ((r = sshkey_ec_validate_عوامی(EC_کلید_get0_گروہ(ec),
		    EC_کلید_get0_عوامی_کلید(ec))) != 0) {
			error_fr(r, "invalid EC key");
			جاؤ برآمد;
		}
		nid = sshkey_ecdsa_کلید_مقصد_nid(ec);
		اگر (nid < 0) {
			error("couldn't get curve nid");
			جاؤ برآمد;
		}

		کلید = sshkey_new(کلید_UNSPEC);
		اگر (کلید == تہی) {
			error("sshkey_new failed");
			جاؤ برآمد;
		}

		EVP_PKEY_free(کلید->pkey);
		اگر ((کلید->pkey = EVP_PKEY_new()) == تہی)
			fatal("EVP_PKEY_new failed");
		اگر (EVP_PKEY_set1_EC_کلید(کلید->pkey, ec) != 1)
			fatal("EVP_PKEY_set1_EC_KEY failed");
		کلید->ecdsa_nid = nid;
		کلید->type = کلید_ECDSA;
		کلید->flags |= SSHKEY_FLAG_EXT;
		اگر (pkcs11_ریکارڈ_کلید(p, slotidx, &cert_attr[0], کلید))
			جاؤ برآمد;
		/* success */
		success = 0;
#اگر_تعریف_شدہ OPENSSL_HAS_ED25519
	} ورنہ اگر (EVP_PKEY_بنیاد_id(evp) == EVP_PKEY_ED25519) {
		اگر ((کلید = sshkey_new(کلید_UNSPEC)) == تہی ||
		    (کلید->ed25519_pk = صفر_حافظہ_دو(1, ED25519_PK_SZ)) == تہی)
			fatal_f("allocation failed");
		len = ED25519_PK_SZ;
		اگر (!EVP_PKEY_get_raw_عوامی_کلید(evp, کلید->ed25519_pk, &len)) {
			ossl_error("EVP_PKEY_get_raw_public_key failed");
			جاؤ برآمد;
		}
		اگر (len != ED25519_PK_SZ) {
			error_f("incorrect returned public key "
			    "length for ed25519");
			جاؤ برآمد;
		}
		کلید->type = کلید_ED25519;
		کلید->flags |= SSHKEY_FLAG_EXT;
		اگر (pkcs11_ریکارڈ_کلید(p, slotidx, &cert_attr[0], کلید))
			جاؤ برآمد;
		/* success */
		success = 0;
#اگر_ختم /* OPENSSL_HAS_ED25519 */
	} ورنہ {
		error("unknown certificate key type");
		جاؤ برآمد;
	}
 برآمد:
	برائے (i = 0; i < 3; i++)
		آزاد(cert_attr[i].p_قدر);
	X509_free(x509);
	RSA_free(rsa);
	EC_کلید_free(ec);
	اگر (success != 0 || کلید == تہی) {
		sshkey_free(کلید);
		آزاد(subject);
		واپس -1;
	}
	/* success */
	*keyp = کلید;
	*labelp = subject;
	واپس 0;
}
#اگر_ختم /* WITH_OPENSSL */

ساکن خالی
note_کلید(ساخت pkcs11_provider *p, CK_ULONG slotidx, ثابت حرف *context,
    ساخت sshkey *کلید)
{
	حرف *fp;

	اگر ((fp = sshkey_fingerprint(کلید, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == تہی) {
		error_f("sshkey_fingerprint failed");
		واپس;
	}
	debug2("%s: provider %s slot %lu: %s %s", context, p->name,
	    (u_long)slotidx, sshkey_type(کلید), fp);
	آزاد(fp);
}

#اگر_تعریف_شدہ WITH_OPENSSL /* libcrypto needed for certificate parsing */
/*
 * lookup certificates for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
ساکن صحیح
pkcs11_fetch_certs(ساخت pkcs11_provider *p, CK_ULONG slotidx,
    ساخت sshkey ***keysp, حرف ***labelsp, صحیح *nkeys)
{
	ساخت sshkey		*کلید = تہی;
	CK_OBJECT_CLASS		 کلید_class;
	CK_ATTRIBUTE		 کلید_attr[1];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = تہی;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	صحیح			 ret = -1;
	حرف			*label;

	memset(&کلید_attr, 0, حجم(کلید_attr));
	memset(&obj, 0, حجم(obj));

	کلید_class = CKO_CERTIFICATE;
	کلید_attr[0].type = CKA_CLASS;
	کلید_attr[0].p_قدر = &کلید_class;
	کلید_attr[0].ul_قدر_Len = حجم(کلید_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_ڈھونڈو_Objects_Init(session, کلید_attr, 1);
	اگر (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		جاؤ fail;
	}

	جب (1) {
		CK_CERTIFICATE_TYPE	ck_cert_type;

		rv = f->C_ڈھونڈو_Objects(session, &obj, 1, &n);
		اگر (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			جاؤ fail;
		}
		اگر (n == 0)
			توڑو;

		memset(&ck_cert_type, 0, حجم(ck_cert_type));
		memset(&کلید_attr, 0, حجم(کلید_attr));
		کلید_attr[0].type = CKA_CERTIFICATE_TYPE;
		کلید_attr[0].p_قدر = &ck_cert_type;
		کلید_attr[0].ul_قدر_Len = حجم(ck_cert_type);

		rv = f->C_Get_Attribute_قدر(session, obj, کلید_attr, 1);
		اگر (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			جاؤ fail;
		}

		کلید = تہی;
		label = تہی;
		انتخاب (ck_cert_type) {
		حالت CKC_X_509:
			اگر (pkcs11_fetch_x509_pubkey(p, slotidx, &obj,
			    &کلید, &label) != 0) {
				debug_f("failed to fetch key");
				جاری;
			}
			توڑو;
		طےشدہ:
			error("skipping unsupported certificate type %lu",
			    ck_cert_type);
			جاری;
		}
		note_کلید(p, slotidx, __func__, کلید);
		اگر (pkcs11_کلید_included(keysp, nkeys, کلید)) {
			debug2_f("key already included");
			sshkey_free(کلید);
		} ورنہ {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, حجم(ساخت sshkey *));
			(*keysp)[*nkeys] = کلید;
			اگر (labelsp != تہی) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, حجم(حرف *));
				(*labelsp)[*nkeys] = xstrdup((حرف *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_ڈھونڈو_Objects_Final(session);
	اگر (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	واپس (ret);
}
#اگر_ختم /* WITH_OPENSSL */

/*
 * lookup public keys for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
ساکن صحیح
pkcs11_fetch_کلیدیں(ساخت pkcs11_provider *p, CK_ULONG slotidx,
    ساخت sshkey ***keysp, حرف ***labelsp, صحیح *nkeys)
{
	ساخت sshkey		*کلید = تہی;
	CK_OBJECT_CLASS		 کلید_class;
	CK_ATTRIBUTE		 کلید_attr[2];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = تہی;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	صحیح			 ret = -1;

	memset(&کلید_attr, 0, حجم(کلید_attr));
	memset(&obj, 0, حجم(obj));

	کلید_class = CKO_عوامی_کلید;
	کلید_attr[0].type = CKA_CLASS;
	کلید_attr[0].p_قدر = &کلید_class;
	کلید_attr[0].ul_قدر_Len = حجم(کلید_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_ڈھونڈو_Objects_Init(session, کلید_attr, 1);
	اگر (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		جاؤ fail;
	}

	جب (1) {
		CK_کلید_TYPE	ck_کلید_type;
		CK_UTF8CHAR	label[256];

		rv = f->C_ڈھونڈو_Objects(session, &obj, 1, &n);
		اگر (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			جاؤ fail;
		}
		اگر (n == 0)
			توڑو;

		memset(&ck_کلید_type, 0, حجم(ck_کلید_type));
		memset(&کلید_attr, 0, حجم(کلید_attr));
		کلید_attr[0].type = CKA_کلید_TYPE;
		کلید_attr[0].p_قدر = &ck_کلید_type;
		کلید_attr[0].ul_قدر_Len = حجم(ck_کلید_type);
		کلید_attr[1].type = CKA_LABEL;
		کلید_attr[1].p_قدر = &label;
		کلید_attr[1].ul_قدر_Len = حجم(label) - 1;

		rv = f->C_Get_Attribute_قدر(session, obj, کلید_attr, 2);
		اگر (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			جاؤ fail;
		}

		label[کلید_attr[1].ul_قدر_Len] = '\0';

		انتخاب (ck_کلید_type) {
#اگر_تعریف_شدہ WITH_OPENSSL
		حالت CKK_RSA:
			کلید = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			توڑو;
		حالت CKK_ECDSA:
			کلید = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			توڑو;
#اگر_ختم /* WITH_OPENSSL */
		حالت CKK_EC_EDWARDS:
			کلید = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			توڑو;
		طےشدہ:
			/* XXX print key type? */
			کلید = تہی;
			error("skipping unsupported key type 0x%lx",
			    (u_long)ck_کلید_type);
		}

		اگر (کلید == تہی) {
			debug_f("failed to fetch key");
			جاری;
		}
		note_کلید(p, slotidx, __func__, کلید);
		اگر (pkcs11_کلید_included(keysp, nkeys, کلید)) {
			debug2_f("key already included");
			sshkey_free(کلید);
		} ورنہ {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, حجم(ساخت sshkey *));
			(*keysp)[*nkeys] = کلید;
			اگر (labelsp != تہی) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, حجم(حرف *));
				(*labelsp)[*nkeys] = xstrdup((حرف *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_ڈھونڈو_Objects_Final(session);
	اگر (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	واپس (ret);
}

#اگر_تعریف_شدہ WITH_PKCS11_KEYGEN
#تعریف_کرو FILL_ATTR(attr, idx, typ, val, len) \
	{ (attr[idx]).type=(typ); (attr[idx]).p_قدر=(val); (attr[idx]).ul_قدر_Len=len; idx++; }

ساکن ساخت sshkey *
pkcs11_rsa_generate_نجی_کلید(ساخت pkcs11_provider *p, CK_ULONG slotidx,
    حرف *label, CK_ULONG بٹ, CK_BYTE keyid, uint32_t *err)
{
	ساخت pkcs11_slotinfo	*si;
	حرف			*plabel = label ? label : "";
	صحیح			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_کلید_2, priv_کلید;
	CK_ATTRIBUTE		 tpub[16], tpriv[16];
	CK_MECHANISM		 mech = {
	    CKM_RSA_PKCS_کلید_PAIR_GEN, NULL_PTR, 0
	};
	CK_BYTE			 pubExponent[] = {
	    0x01, 0x00, 0x01 /* RSA_F4 in bytes */
	};
	pubkey_filter[0].p_قدر = &pubkey_class;
	cert_filter[0].p_قدر = &cert_class;

	*err = 0;

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, حجم(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, لڑی_لمبائی(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, حجم(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, حجم(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    حجم(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, حجم(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, حجم(false_val));
	FILL_ATTR(tpub, npub, CKA_MODULUS_بٹ, &بٹ, حجم(بٹ));
	FILL_ATTR(tpub, npub, CKA_عوامی_EXPONENT, pubExponent,
	    حجم(pubExponent));
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, حجم(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN,  &true_val, حجم(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL,  plabel, لڑی_لمبائی(plabel));
	FILL_ATTR(tpriv, npriv, CKA_نجی,  &true_val, حجم(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE,  &true_val, حجم(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT,  &false_val, حجم(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN,  &true_val, حجم(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER,  &false_val,
	    حجم(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP,  &false_val, حجم(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE,  &false_val, حجم(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, حجم(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	اگر ((rv = f->C_Generate_کلید_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_کلید_2, &priv_کلید)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		واپس تہی;
	}

	واپس pkcs11_fetch_rsa_pubkey(p, slotidx, &pub_کلید_2);
}

ساکن صحیح
h2i(حرف c)
{
	اگر (c >= '0' && c <= '9')
		واپس c - '0';
	ورنہ اگر (c >= 'a' && c <= 'f')
		واپس c - 'a' + 10;
	ورنہ اگر (c >= 'A' && c <= 'F')
		واپس c - 'A' + 10;
	ورنہ
		واپس -1;
}

ساکن صحیح
pkcs11_decode_hex(ثابت حرف *hex, غیرعلامتی حرف **dest, سائز_t *rlen)
{
	سائز_t	i, len;

	اگر (dest)
		*dest = تہی;
	اگر (rlen)
		*rlen = 0;

	اگر ((len = لڑی_لمبائی(hex)) % 2)
		واپس -1;
	len /= 2;

	*dest = xmalloc(len);

	برائے (i = 0; i < len; i++) {
		صحیح hi, lo;

		hi = h2i(hex[2 * i]);
		lo = h2i(hex[(2 * i) + 1]);
		اگر (hi == -1 || lo == -1)
			واپس -1;
		(*dest)[i] = (hi << 4) | lo;
	}

	اگر (rlen)
		*rlen = len;

	واپس 0;
}

ساکن ساخت ec_خم_info {
	ثابت حرف	*name;
	ثابت حرف	*oid;
	ثابت حرف	*oid_encoded;
	سائز_t		 سائز;
} ec_خم_infos[] = {
	{"prime256v1",	"1.2.840.10045.3.1.7",	"06082A8648CE3D030107", 256},
	{"secp384r1",	"1.3.132.0.34",		"06052B81040022",	384},
	{"secp521r1",	"1.3.132.0.35",		"06052B81040023",	521},
	{تہی,		تہی,			تہی,			0},
};

ساکن ساخت sshkey *
pkcs11_ecdsa_generate_نجی_کلید(ساخت pkcs11_provider *p, CK_ULONG slotidx,
    حرف *label, CK_ULONG بٹ, CK_BYTE keyid, uint32_t *err)
{
	ساخت pkcs11_slotinfo	*si;
	حرف			*plabel = label ? label : "";
	صحیح			 i;
	سائز_t			 ecparams_سائز;
	غیرعلامتی حرف		*ecparams = تہی;
	صحیح			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_کلید_2, priv_کلید;
	CK_MECHANISM		 mech = {
	    CKM_EC_کلید_PAIR_GEN, NULL_PTR, 0
	};
	CK_ATTRIBUTE		 tpub[16], tpriv[16];

	*err = 0;

	برائے (i = 0; ec_خم_infos[i].name; i++) {
		اگر (ec_خم_infos[i].سائز == بٹ)
			توڑو;
	}
	اگر (!ec_خم_infos[i].name) {
		error_f("invalid key size %lu", بٹ);
		واپس تہی;
	}
	اگر (pkcs11_decode_hex(ec_خم_infos[i].oid_encoded, &ecparams,
	    &ecparams_سائز) == -1) {
		error_f("invalid oid");
		واپس تہی;
	}

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, حجم(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, لڑی_لمبائی(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, حجم(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, حجم(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    حجم(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, حجم(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, حجم(false_val));
	FILL_ATTR(tpub, npub, CKA_EC_PARAMS, ecparams, ecparams_سائز);
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, حجم(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN, &true_val, حجم(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL, plabel, لڑی_لمبائی(plabel));
	FILL_ATTR(tpriv, npriv, CKA_نجی, &true_val, حجم(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE, &true_val, حجم(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT, &false_val, حجم(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN, &true_val, حجم(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER, &false_val,
	    حجم(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP, &false_val, حجم(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE, &false_val, حجم(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, حجم(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	اگر ((rv = f->C_Generate_کلید_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_کلید_2, &priv_کلید)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		واپس تہی;
	}

	واپس pkcs11_fetch_ecdsa_pubkey(p, slotidx, &pub_کلید_2);
}
#اگر_ختم /* WITH_PKCS11_KEYGEN */

/*
 * register a new provider, fails if provider already exists. if
 * keyp is provided, fetch keys.
 */
ساکن صحیح
pkcs11_رجسٹر_provider(حرف *provider_id, حرف *pin,
    ساخت sshkey ***keyp, حرف ***labelsp,
    ساخت pkcs11_provider **providerp, CK_ULONG user)
{
	صحیح nkeys, need_finalize = 0;
	صحیح ret = -1;
	ساخت pkcs11_provider *p = تہی;
	خالی *handle = تہی;
	CK_RV (*getfunctionlist)(CK_FUNCTION_LIST **);
	CK_RV rv;
	CK_FUNCTION_LIST *f = تہی;
	CK_TOKEN_INFO *token;
	CK_ULONG i;

	اگر (providerp == تہی)
		جاؤ fail;
	*providerp = تہی;

	اگر (keyp != تہی)
		*keyp = تہی;
	اگر (labelsp != تہی)
		*labelsp = تہی;

	اگر (pkcs11_provider_lookup(provider_id) != تہی) {
		debug_f("provider already registered: %s", provider_id);
		جاؤ fail;
	}
	اگر (lib_شامل_ہے_علامت(provider_id, "C_GetFunctionList") != 0) {
		error("provider %s is not a PKCS11 library", provider_id);
		جاؤ fail;
	}
	/* open shared pkcs11-library */
	اگر ((handle = dlopen(provider_id, RTLD_NOW)) == تہی) {
		error("dlopen %s failed: %s", provider_id, dlerror());
		جاؤ fail;
	}
	اگر ((getfunctionlist = dlsym(handle, "C_GetFunctionList")) == تہی)
		fatal("dlsym(C_GetFunctionList) failed: %s", dlerror());
	p = xcalloc(1, حجم(*p));
	p->name = xstrdup(provider_id);
	p->handle = handle;
	/* set up the pkcs11 callbacks */
	اگر ((rv = (*getfunctionlist)(&f)) != CKR_OK) {
		error("C_GetFunctionList for provider %s failed: %lu",
		    provider_id, rv);
		جاؤ fail;
	}
	p->function_list = f;
	اگر ((rv = f->C_Initialize(تہی)) != CKR_OK) {
		error("C_Initialize for provider %s failed: %lu",
		    provider_id, rv);
		جاؤ fail;
	}
	need_finalize = 1;
	اگر ((rv = f->C_GetInfo(&p->info)) != CKR_OK) {
		error("C_GetInfo for provider %s failed: %lu",
		    provider_id, rv);
		جاؤ fail;
	}
	debug("provider %s: manufacturerID <%.*s> cryptokiVersion %d.%d"
	    " libraryDescription <%.*s> libraryVersion %d.%d",
	    provider_id,
	    RMSPACE(p->info.manufacturerID),
	    p->info.cryptoki_نسخہ_2.major,
	    p->info.cryptoki_نسخہ_2.minor,
	    RMSPACE(p->info.libraryDescription),
	    p->info.library_نسخہ_2.major,
	    p->info.library_نسخہ_2.minor);
	اگر ((rv = f->C_Get_خانہ_List(CK_TRUE, تہی, &p->nslots)) != CKR_OK) {
		error("C_GetSlotList failed: %lu", rv);
		جاؤ fail;
	}
	اگر (p->nslots == 0) {
		debug_f("provider %s returned no slots", provider_id);
		ret = -SSH_PKCS11_ERR_NO_SLOTS;
		جاؤ fail;
	}
	p->slotlist = xcalloc(p->nslots, حجم(CK_خانہ_ID));
	اگر ((rv = f->C_Get_خانہ_List(CK_TRUE, p->slotlist, &p->nslots))
	    != CKR_OK) {
		error("C_GetSlotList for provider %s failed: %lu",
		    provider_id, rv);
		جاؤ fail;
	}
	p->slotinfo = xcalloc(p->nslots, حجم(ساخت pkcs11_slotinfo));
	p->valid = 1;
	nkeys = 0;
	برائے (i = 0; i < p->nslots; i++) {
		token = &p->slotinfo[i].token;
		اگر ((rv = f->C_GetTokenInfo(p->slotlist[i], token))
		    != CKR_OK) {
			error("C_GetTokenInfo for provider %s slot %lu "
			    "failed: %lu", provider_id, (u_long)i, rv);
			جاری;
		}
		اگر ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
			debug2_f("ignoring uninitialised token in "
			    "provider %s slot %lu", provider_id, (u_long)i);
			جاری;
		}
		debug("provider %s slot %lu: label <%.*s> "
		    "manufacturerID <%.*s> model <%.*s> serial <%.*s> "
		    "flags 0x%lx",
		    provider_id, (غیرعلامتی طویل)i,
		    RMSPACE(token->label), RMSPACE(token->manufacturerID),
		    RMSPACE(token->model), RMSPACE(token->serial_نمبر_2),
		    token->flags);
		/*
		 * open session, login with pin and retrieve public
		 * keys (if keyp is provided)
		 */
		اگر ((ret = pkcs11_open_session(p, i, pin, user)) != 0 ||
		    keyp == تہی)
			جاری;
		pkcs11_fetch_کلیدیں(p, i, keyp, labelsp, &nkeys);
#اگر_تعریف_شدہ WITH_OPENSSL
		pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#اگر_ختم
		اگر (nkeys == 0 && !p->slotinfo[i].logged_اندر &&
		    pkcs11_interactive) {
			/*
			 * Some tokens require login before they will
			 * expose keys.
			 */
			اگر (pkcs11_login_خانہ(p, &p->slotinfo[i],
			    CKU_USER) < 0) {
				error("login failed");
				جاری;
			}
			pkcs11_fetch_کلیدیں(p, i, keyp, labelsp, &nkeys);
#اگر_تعریف_شدہ WITH_OPENSSL
			pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#اگر_ختم
		}
	}

	/* now owned by caller */
	*providerp = p;

	TAILQ_INSERT_TAIL(&pkcs11_providers, p, اگلا);
	p->refcount++;	/* add to provider list */

	واپس (nkeys);
fail:
	اگر (need_finalize && (rv = f->C_Finalize(تہی)) != CKR_OK)
		error("C_Finalize for provider %s failed: %lu",
		    provider_id, rv);
	اگر (p) {
		آزاد(p->name);
		آزاد(p->slotlist);
		آزاد(p->slotinfo);
		آزاد(p);
	}
	اگر (handle)
		dlclose(handle);
	اگر (ret > 0)
		ret = -1;
	واپس (ret);
}

صحیح
pkcs11_init(صحیح interactive)
{
	debug3_f("called, interactive = %d", interactive);

	pkcs11_interactive = interactive;
	TAILQ_INIT(&pkcs11_providers);
	TAILQ_INIT(&pkcs11_کلیدیں);
	واپس (0);
}

/* unregister all providers, keys might still point to the providers */
خالی
pkcs11_terminate(خالی)
{
	ساخت pkcs11_provider *p;
	ساخت pkcs11_کلید *k11;

	debug3_f("called");

	جب ((k11 = TAILQ_FIRST(&pkcs11_کلیدیں)) != تہی) {
		TAILQ_REMOVE(&pkcs11_کلیدیں, k11, اگلا);
		pkcs11_k11_free(k11);
	}
	جب ((p = TAILQ_FIRST(&pkcs11_providers)) != تہی) {
		TAILQ_REMOVE(&pkcs11_providers, p, اگلا);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
}

/*
 * register a new provider and get number of keys hold by the token,
 * fails if provider already exists
 */
صحیح
pkcs11_جوڑو_provider(حرف *provider_id, حرف *pin, ساخت sshkey ***keyp,
    حرف ***labelsp)
{
	ساخت pkcs11_provider *p = تہی;
	صحیح nkeys;

	nkeys = pkcs11_رجسٹر_provider(provider_id, pin, keyp, labelsp,
	    &p, CKU_USER);

	/* no keys found or some other error, de-register provider */
	اگر (nkeys <= 0 && p != تہی) {
		TAILQ_REMOVE(&pkcs11_providers, p, اگلا);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
	اگر (nkeys == 0)
		debug_f("provider %s returned no keys", provider_id);

	واپس (nkeys);
}

صحیح
pkcs11_sign(ساخت sshkey *کلید,
    u_char **sigp, سائز_t *lenp,
    ثابت u_char *ڈیٹا, سائز_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider,
    ثابت حرف *sk_pin, u_int compat)
{
	انتخاب (کلید->type) {
#اگر_تعریف_شدہ WITH_OPENSSL
	حالت کلید_RSA:
	حالت کلید_RSA_CERT:
		واپس pkcs11_sign_rsa(کلید, sigp, lenp, ڈیٹا, datalen,
		    alg, sk_provider, sk_pin, compat);
	حالت کلید_ECDSA:
	حالت کلید_ECDSA_CERT:
		واپس pkcs11_sign_ecdsa(کلید, sigp, lenp, ڈیٹا, datalen,
		    alg, sk_provider, sk_pin, compat);
#اگر_ختم /* WITH_OPENSSL */
	حالت کلید_ED25519:
	حالت کلید_ED25519_CERT:
		واپس pkcs11_sign_ed25519(کلید, sigp, lenp, ڈیٹا, datalen,
		    alg, sk_provider, sk_pin, compat);
	طےشدہ:
		واپس SSH_ERR_کلید_TYPE_UNKNOWN;
	}
}

خالی
pkcs11_کلید_free(ساخت sshkey *کلید)
{
	/* never called */
}

#اگر_تعریف_شدہ WITH_PKCS11_KEYGEN
ساخت sshkey *
pkcs11_gakp(حرف *provider_id, حرف *pin, غیرعلامتی صحیح slotidx, حرف *label,
    غیرعلامتی صحیح type, غیرعلامتی صحیح بٹ, غیرعلامتی حرف keyid, uint32_t *err)
{
	ساخت pkcs11_provider	*p = تہی;
	ساخت pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	ساخت sshkey		*k = تہی;
	صحیح			 ret = -1, reset_pin = 0, reset_provider = 0;
	CK_RV			 rv;

	*err = 0;

	اگر ((p = pkcs11_provider_lookup(provider_id)) != تہی)
		debug_f("provider \"%s\" available", provider_id);
	ورنہ اگر ((ret = pkcs11_رجسٹر_provider(provider_id, pin, تہی, تہی,
	    &p, CKU_SO)) < 0) {
		debug_f("could not register provider %s", provider_id);
		جاؤ برآمد;
	} ورنہ
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	اگر ((rv = f->C_سیٹ_Operation_State(session , pin, لڑی_لمبائی(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} ورنہ
		reset_pin = 1;

	انتخاب (type) {
	حالت کلید_RSA:
		اگر ((k = pkcs11_rsa_generate_نجی_کلید(p, slotidx, label,
		    بٹ, keyid, err)) == تہی) {
			debug_f("failed to generate RSA key");
			جاؤ برآمد;
		}
		توڑو;
	حالت کلید_ECDSA:
		اگر ((k = pkcs11_ecdsa_generate_نجی_کلید(p, slotidx, label,
		    بٹ, keyid, err)) == تہی) {
			debug_f("failed to generate ECDSA key");
			جاؤ برآمد;
		}
		توڑو;
	طےشدہ:
		*err = SSH_PKCS11_ERR_GENERIC;
		debug_f("unknown type %d", type);
		جاؤ برآمد;
	}

برآمد:
	اگر (reset_pin)
		f->C_سیٹ_Operation_State(session , تہی, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	اگر (reset_provider)
		pkcs11_del_provider(provider_id);

	واپس (k);
}

ساخت sshkey *
pkcs11_destroy_keypair(حرف *provider_id, حرف *pin, غیرعلامتی طویل slotidx,
    غیرعلامتی حرف keyid, uint32_t *err)
{
	ساخت pkcs11_provider	*p = تہی;
	ساخت pkcs11_slotinfo	*si;
	ساخت sshkey		*k = تہی;
	صحیح			 reset_pin = 0, reset_provider = 0;
	CK_ULONG		 nattrs;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_ATTRIBUTE		 attrs[16];
	CK_OBJECT_CLASS		 کلید_class;
	CK_کلید_TYPE		 کلید_type;
	CK_OBJECT_HANDLE	 obj = CK_INVALID_HANDLE;
	CK_RV			 rv;

	*err = 0;

	اگر ((p = pkcs11_provider_lookup(provider_id)) != تہی) {
		debug_f("using provider \"%s\"", provider_id);
	} ورنہ اگر (pkcs11_رجسٹر_provider(provider_id, pin, تہی, تہی, &p,
	    CKU_SO) < 0) {
		debug_f("could not register provider %s",
		    provider_id);
		جاؤ برآمد;
	} ورنہ
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	اگر ((rv = f->C_سیٹ_Operation_State(session , pin, لڑی_لمبائی(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} ورنہ
		reset_pin = 1;

	/* private key */
	nattrs = 0;
	کلید_class = CKO_نجی_کلید;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &کلید_class, حجم(کلید_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, حجم(keyid));

	اگر (pkcs11_ڈھونڈو(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {
		اگر ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy private key 0x%hhx",
			    keyid);
			*err = rv;
			جاؤ برآمد;
		}
	}

	/* public key */
	nattrs = 0;
	کلید_class = CKO_عوامی_کلید;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &کلید_class, حجم(کلید_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, حجم(keyid));

	اگر (pkcs11_ڈھونڈو(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {

		/* get key type */
		nattrs = 0;
		FILL_ATTR(attrs, nattrs, CKA_کلید_TYPE, &کلید_type,
		    حجم(کلید_type));
		rv = f->C_Get_Attribute_قدر(session, obj, attrs, nattrs);
		اگر (rv != CKR_OK) {
			debug_f("could not get key type of public key 0x%hhx",
			    keyid);
			*err = rv;
			کلید_type = -1;
		}
		انتخاب (کلید_type) {
#اگر_تعریف_شدہ WITH_OPENSSL
		حالت CKK_RSA:
			k = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			توڑو;
		حالت CKK_ECDSA:
			k = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			توڑو;
#اگر_ختم /* WITH_OPENSSL */
		حالت CKK_EC_EDWARDS:
			k = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			توڑو;
		طےشدہ:
			debug_f("unsupported key type %lu", (u_long)کلید_type);
			توڑو;
		}

		اگر ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy public key 0x%hhx", keyid);
			*err = rv;
			جاؤ برآمد;
		}
	}

برآمد:
	اگر (reset_pin)
		f->C_سیٹ_Operation_State(session , تہی, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	اگر (reset_provider)
		pkcs11_del_provider(provider_id);

	واپس (k);
}
#اگر_ختم /* WITH_PKCS11_KEYGEN */
#ورنہ /* ENABLE_PKCS11 */

#شامل <sys/types.h>
#شامل <stdarg.h>
#شامل <stdio.h>

#شامل "log.h"
#شامل "sshkey.h"
#شامل "ssherr.h"
#شامل "ssh-pkcs11.h"

صحیح
pkcs11_init(صحیح interactive)
{
	error_f("PKCS#11 not supported");
	واپس (-1);
}

صحیح
pkcs11_جوڑو_provider(حرف *provider_id, حرف *pin, ساخت sshkey ***keyp,
    حرف ***labelsp)
{
	error_f("PKCS#11 not supported");
	واپس (-1);
}

خالی
pkcs11_کلید_free(ساخت sshkey *کلید)
{
	error_f("PKCS#11 not supported");
}

صحیح
pkcs11_sign(ساخت sshkey *کلید,
    u_char **sigp, سائز_t *lenp,
    ثابت u_char *ڈیٹا, سائز_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider,
    ثابت حرف *sk_pin, u_int compat)
{
	error_f("PKCS#11 not supported");
	واپس SSH_ERR_FEATURE_UNSUPPORTED;
}

خالی
pkcs11_terminate(خالی)
{
	error_f("PKCS#11 not supported");
}
#اگر_ختم /* ENABLE_PKCS11 */
