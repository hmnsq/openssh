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

#ifdef ENABLE_PKCS11

#شامل <sys/time.h>

#شامل <sys/types.h>
#شامل <sys/queue.h>
#شامل <stdarg.h>
#شامل <stdio.h>

#شامل <string.h>
#شامل <dlfcn.h>

#ifdef WITH_OPENSSL
#شامل "openbsd-compat/openssl-compat.h"
#شامل <openssl/bn.h>
#شامل <openssl/ecdsa.h>
#شامل <openssl/x509.h>
#شامل <openssl/err.h>
#endif

#define CRYPTOKI_COMPAT
#شامل "pkcs11.h"

#define SSHKEY_INTERNAL
#شامل "sshkey.h"

#شامل "log.h"
#شامل "misc.h"
#شامل "sshbuf.h"
#شامل "ssh-pkcs11.h"
#شامل "digest.h"
#شامل "xmalloc.h"
#شامل "crypto_api.h"

ساختار pkcs11_slotinfo {
	CK_TOKEN_INFO		token;
	CK_SESSION_HANDLE	session;
	صحیح			logged_in;
};

ساختار pkcs11_provider {
	نویسه			*name;
	تهی			*handle;
	CK_FUNCTION_LIST	*function_list;
	CK_INFO			info;
	CK_ULONG		nslots;
	CK_SLOT_ID		*slotlist;
	ساختار pkcs11_slotinfo	*slotinfo;
	صحیح			valid;
	صحیح			refcount;
	TAILQ_ENTRY(pkcs11_provider) next;
};

TAILQ_HEAD(, pkcs11_provider) pkcs11_providers;

ساختار pkcs11_کلید {
	ساختار sshbuf		*keyblob;
	ساختار pkcs11_provider	*provider;
	CK_ULONG		slotidx;
	نویسه			*keyid;
	صحیح			keyid_len;
	TAILQ_ENTRY(pkcs11_کلید)	next;
};

TAILQ_HEAD(, pkcs11_کلید) pkcs11_کلیدها; /* XXX a tree would be better */

صحیح pkcs11_interactive = 0;

#ifdef WITH_OPENSSL
ایستا تهی
ossl_error(ثابت نویسه *پیام)
{
	unsigned long    e;

	error_f("%s", پیام);
	وقتی ((e = ERR_get_error()) != 0)
		error_f("libcrypto error: %s", ERR_error_string(e, پوچ));
}
#endif

/*
 * finalize a provider shared library, it's no longer usable.
 * however, there might still be keys referencing this provider,
 * so the actual freeing of memory is handled by pkcs11_provider_unref().
 * this is called when a provider gets unregistered.
 */
ایستا تهی
pkcs11_provider_finalize(ساختار pkcs11_provider *p)
{
	CK_RV rv;
	CK_ULONG i;

	debug_f("provider \"%s\" refcount %d valid %d",
	    p->name, p->refcount, p->valid);
	اگر (!p->valid)
		بازگشت;
	برای (i = 0; i < p->nslots; i++) {
		اگر (p->slotinfo[i].session &&
		    (rv = p->function_list->C_CloseSession(
		    p->slotinfo[i].session)) != CKR_OK)
			error("C_CloseSession failed: %lu", rv);
	}
	اگر ((rv = p->function_list->C_Finalize(پوچ)) != CKR_OK)
		error("C_Finalize failed: %lu", rv);
	p->valid = 0;
	p->function_list = پوچ;
	dlclose(p->handle);
}

/*
 * remove a reference to the provider.
 * called when a key gets destroyed or when the provider is unregistered.
 */
ایستا تهی
pkcs11_provider_unref(ساختار pkcs11_provider *p)
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
ایستا ساختار pkcs11_provider *
pkcs11_provider_lookup(نویسه *provider_id)
{
	ساختار pkcs11_provider *p;

	TAILQ_FOREACH(p, &pkcs11_providers, next) {
		debug("check provider \"%s\"", p->name);
		اگر (!strcmp(provider_id, p->name))
			بازگشت (p);
	}
	بازگشت (پوچ);
}

/* unregister provider by name */
صحیح
pkcs11_del_provider(نویسه *provider_id)
{
	ساختار pkcs11_provider *p;

	اگر ((p = pkcs11_provider_lookup(provider_id)) != پوچ) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
		بازگشت (0);
	}
	بازگشت (-1);
}

/* release a wrapped object */
ایستا تهی
pkcs11_k11_free(ساختار pkcs11_کلید *k11)
{
	اگر (k11 == پوچ)
		بازگشت;
	اگر (k11->provider)
		pkcs11_provider_unref(k11->provider);
	آزاد(k11->keyid);
	sshbuf_free(k11->keyblob);
	آزاد(k11);
}

/* find a single 'obj' for given attributes */
ایستا صحیح
pkcs11_find(ساختار pkcs11_provider *p, CK_ULONG slotidx, CK_ATTRIBUTE *attr,
    CK_ULONG nattr, CK_OBJECT_HANDLE *obj)
{
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	session;
	CK_ULONG		nfound = 0;
	CK_RV			rv;
	صحیح			ret = -1;

	f = p->function_list;
	session = p->slotinfo[slotidx].session;
	اگر ((rv = f->C_FindObjectsInit(session, attr, nattr)) != CKR_OK) {
		error("C_FindObjectsInit failed (nattr %lu): %lu", nattr, rv);
		بازگشت (-1);
	}
	اگر ((rv = f->C_FindObjects(session, obj, 1, &nfound)) != CKR_OK ||
	    nfound != 1) {
		debug("C_FindObjects failed (nfound %lu nattr %lu): %lu",
		    nfound, nattr, rv);
	} وگرنه
		ret = 0;
	اگر ((rv = f->C_FindObjectsFinal(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	بازگشت (ret);
}

ایستا صحیح
pkcs11_login_slot(ساختار pkcs11_provider *provider, ساختار pkcs11_slotinfo *si,
    CK_USER_TYPE type)
{
	نویسه			*pin = پوچ, prompt[1024];
	CK_RV			 rv;

	اگر (provider == پوچ || si == پوچ || !provider->valid) {
		error("no pkcs11 (valid) provider found");
		بازگشت (-1);
	}

	اگر (!pkcs11_interactive) {
		error("need pin entry%s",
		    (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH) ?
		    " on reader keypad" : "");
		بازگشت (-1);
	}
	اگر (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
		verbose("Deferring PIN entry to reader keypad.");
	وگرنه {
		snprintf(prompt, اندازه(prompt), "Enter PIN for '%s': ",
		    si->token.label);
		اگر ((pin = read_passphrase(prompt, RP_ALLOW_EOF)) == پوچ) {
			debug_f("no pin specified");
			بازگشت (-1);	/* bail out */
		}
	}
	rv = provider->function_list->C_Login(si->session, type, (u_char *)pin,
	    (pin != پوچ) ? strlen(pin) : 0);
	اگر (pin != پوچ)
		freezero(pin, strlen(pin));

	انتخاب (rv) {
	حالت CKR_OK:
	حالت CKR_USER_ALREADY_LOGGED_IN:
		/* success */
		بشکن;
	حالت CKR_PIN_LEN_RANGE:
		error("PKCS#11 login failed: PIN length out of range");
		بازگشت -1;
	حالت CKR_PIN_INCORRECT:
		error("PKCS#11 login failed: PIN incorrect");
		بازگشت -1;
	حالت CKR_PIN_LOCKED:
		error("PKCS#11 login failed: PIN locked");
		بازگشت -1;
	پیشفرض:
		error("PKCS#11 login failed: error %lu", rv);
		بازگشت -1;
	}
	si->logged_in = 1;
	بازگشت (0);
}

ایستا صحیح
pkcs11_login(ساختار pkcs11_کلید *k11, CK_USER_TYPE type)
{
	اگر (k11 == پوچ || k11->provider == پوچ || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		بازگشت (-1);
	}

	بازگشت pkcs11_login_slot(k11->provider,
	    &k11->provider->slotinfo[k11->slotidx], type);
}


ایستا صحیح
pkcs11_check_obj_bool_attrib(ساختار pkcs11_کلید *k11, CK_OBJECT_HANDLE obj,
    CK_ATTRIBUTE_TYPE type, صحیح *val)
{
	ساختار pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_BBOOL		flag = 0;
	CK_ATTRIBUTE		attr;
	CK_RV			 rv;

	*val = 0;

	اگر (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		بازگشت (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	attr.type = type;
	attr.p_مقدار = &flag;
	attr.ul_مقدار_Len = اندازه(flag);

	rv = f->C_Get_Attribute_مقدار(si->session, obj, &attr, 1);
	اگر (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		بازگشت (-1);
	}
	*val = flag != 0;
	debug_f("provider \"%s\" slot %lu object %lu: attrib %lu = %d",
	    k11->provider->name, k11->slotidx, obj, type, *val);
	بازگشت (0);
}

ایستا صحیح
pkcs11_get_کلید(ساختار pkcs11_کلید *k11, CK_MECHANISM_TYPE mech_type)
{
	ساختار pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	 obj;
	CK_RV			 rv;
	CK_OBJECT_CLASS		 private_کلید_class;
	CK_BBOOL		 true_val;
	CK_MECHANISM		 mech;
	CK_ATTRIBUTE		 کلید_filter[3];
	صحیح			 always_auth = 0;
	صحیح			 did_login = 0;

	اگر (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		بازگشت (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	اگر ((si->token.flags & CKF_LOGIN_REQUIRED) && !si->logged_in) {
		اگر (pkcs11_login(k11, CKU_USER) < 0) {
			error("login failed");
			بازگشت (-1);
		}
		did_login = 1;
	}

	memset(&کلید_filter, 0, اندازه(کلید_filter));
	private_کلید_class = CKO_PRIVATE_کلید;
	کلید_filter[0].type = CKA_CLASS;
	کلید_filter[0].p_مقدار = &private_کلید_class;
	کلید_filter[0].ul_مقدار_Len = اندازه(private_کلید_class);

	کلید_filter[1].type = CKA_ID;
	کلید_filter[1].p_مقدار = k11->keyid;
	کلید_filter[1].ul_مقدار_Len = k11->keyid_len;

	true_val = CK_TRUE;
	کلید_filter[2].type = CKA_SIGN;
	کلید_filter[2].p_مقدار = &true_val;
	کلید_filter[2].ul_مقدار_Len = اندازه(true_val);

	/* try to find object w/CKA_SIGN first, retry w/o */
	اگر (pkcs11_find(k11->provider, k11->slotidx, کلید_filter, 3, &obj) < 0 &&
	    pkcs11_find(k11->provider, k11->slotidx, کلید_filter, 2, &obj) < 0) {
		error("cannot find private key");
		بازگشت (-1);
	}

	memset(&mech, 0, اندازه(mech));
	mech.mechanism = mech_type;
	mech.pParameter = NULL_PTR;
	mech.ulParameterLen = 0;

	اگر ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
		بازگشت (-1);
	}

	pkcs11_check_obj_bool_attrib(k11, obj, CKA_ALWAYS_AUTHENTICATE,
	    &always_auth); /* ignore errors here */
	اگر (always_auth && !did_login) {
		debug_f("always-auth key");
		اگر (pkcs11_login(k11, CKU_CONTEXT_SPECIFIC) < 0) {
			error("login failed for always-auth key");
			بازگشت (-1);
		}
	}

	بازگشت (0);
}

/* record the key information later use lookup by keyblob */
ایستا صحیح
pkcs11_record_کلید(ساختار pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, ساختار sshkey *کلید)
{
	ساختار sshbuf *keyblob;
	ساختار pkcs11_کلید *k11;
	صحیح r;
	نویسه *hex;

	hex = tohex(keyid_attrib->p_مقدار, keyid_attrib->ul_مقدار_Len);
	debug_f("%s key: provider %s slot %lu keyid %s",
	    sshkey_type(کلید), provider->name, (u_long)slotidx, hex);
	آزاد(hex);

	اگر ((keyblob = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshkey_putb(کلید, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");

	/* Check if we've already recorded this key in a different slot */
	TAILQ_FOREACH(k11, &pkcs11_کلیدها, next) {
		اگر (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			hex = tohex(k11->keyid, k11->keyid_len);
			debug_f("Already seen this key at "
			    "provider %s slot %lu keyid %s",
			    k11->provider->name, k11->slotidx, hex);
			آزاد(hex);
			sshbuf_free(keyblob);
			بازگشت -1;
		}
	}

	k11 = xcalloc(1, اندازه(*k11));
	k11->provider = provider;
	k11->keyblob = keyblob;
	provider->refcount++;	/* provider referenced by RSA key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ul_مقدار_Len;
	اگر (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len);
		memcpy(k11->keyid, keyid_attrib->p_مقدار, k11->keyid_len);
	}
	TAILQ_INSERT_TAIL(&pkcs11_کلیدها, k11, next);

	بازگشت 0;
}

/* retrieve the key information by keyblob */
ایستا ساختار pkcs11_کلید *
pkcs11_lookup_کلید(ساختار sshkey *کلید)
{
	ساختار pkcs11_کلید *k11, *found = پوچ;
	ساختار sshbuf *keyblob;
	صحیح r;

	اگر ((keyblob = sshbuf_new()) == پوچ)
		fatal_f("sshbuf_new failed");
	اگر ((r = sshkey_putb(کلید, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");
	TAILQ_FOREACH(k11, &pkcs11_کلیدها, next) {
		اگر (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			found = k11;
			بشکن;
		}
	}
	sshbuf_free(keyblob);
	بازگشت found;
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
ایستا ثابت u_char id_sha1[] = {
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
ایستا ثابت u_char id_sha256[] = {
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
ایستا ثابت u_char id_sha512[] = {
	0x30, 0x51, /* type Sequence, length 0x51 (81) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, /* id-sha512 */
	0x05, 0x00, /* NULL */
	0x04, 0x40  /* Octet string, length 0x40 (64), followed by sha512 hash */
};

ایستا صحیح
rsa_hash_alg_oid(صحیح hash_alg, ثابت u_char **oidp, size_t *oidlenp)
{
	انتخاب (hash_alg) {
	حالت SSH_DIGEST_SHA1:
		*oidp = id_sha1;
		*oidlenp = اندازه(id_sha1);
		بشکن;
	حالت SSH_DIGEST_SHA256:
		*oidp = id_sha256;
		*oidlenp = اندازه(id_sha256);
		بشکن;
	حالت SSH_DIGEST_SHA512:
		*oidp = id_sha512;
		*oidlenp = اندازه(id_sha512);
		بشکن;
	پیشفرض:
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	}
	بازگشت 0;
}

ایستا صحیح
pkcs11_sign_rsa(ساختار sshkey *کلید,
    u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت نویسه *alg, ثابت نویسه *sk_provider,
    ثابت نویسه *sk_pin, u_int compat)
{
	ساختار pkcs11_کلید	*k11;
	ساختار pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	صحیح			hashalg, r, diff, siglen, ret = -1;
	u_char			*oid_dgst = پوچ, *sig = پوچ;
	size_t			dgst_len, oid_len, oid_dgst_len = 0;
	ثابت u_char		*oid;

	اگر (sigp != پوچ)
		*sigp = پوچ;
	اگر (lenp != پوچ)
		*lenp = 0;

	اگر ((k11 = pkcs11_lookup_کلید(کلید)) == پوچ) {
		error_f("no key found");
		بازگشت SSH_ERR_کلید_NOT_FOUND;
	}

	debug3_f("sign with alg \"%s\" using provider %s slotidx %lu",
	    alg == پوچ ? "" : alg, k11->provider->name, (u_long)k11->slotidx);

	اگر (pkcs11_get_کلید(k11, CKM_RSA_PKCS) == -1) {
		error("pkcs11_get_key failed");
		بازگشت SSH_ERR_AGENT_FAILURE;
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	اگر ((siglen = EVP_PKEY_size(کلید->pkey)) <= 0)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* Determine hash algorithm and OID for signature */
	اگر (alg == پوچ || *alg == '\0')
		hashalg = SSH_DIGEST_SHA1;
	وگرنه اگر ((hashalg = ssh_rsa_hash_id_from_keyname(alg)) == -1)
		fatal_f("couldn't determine RSA hash alg \"%s\"", alg);
	اگر ((r = rsa_hash_alg_oid(hashalg, &oid, &oid_len)) != 0)
		fatal_fr(r, "rsa_hash_alg_oid failed");
	اگر ((dgst_len = ssh_digest_bytes(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);

	/* Prepare { oid || digest } */
	oid_dgst_len = oid_len + dgst_len;
	oid_dgst = xcalloc(1, oid_dgst_len);
	memcpy(oid_dgst, oid, oid_len);
	اگر ((r = ssh_digest_memory(hashalg, data, datalen,
	    oid_dgst + oid_len, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	اگر ((rv = f->C_Sign(si->session, (CK_BYTE *)oid_dgst,
	    oid_dgst_len, sig, &slen)) != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		برو done;
	}

	اگر (slen < (CK_ULONG)siglen) {
		diff = siglen - slen;
		debug3_f("repack %lu < %d (diff %d)",
		    (u_long)slen, siglen, diff);
		memmove(sig + diff, sig, slen);
		explicit_bzero(sig, diff);
	} وگرنه اگر (slen > (size_t)siglen)
		fatal_f("bad C_Sign length");

	اگر ((ret = ssh_rsa_encode_store_sig(hashalg, sig, siglen,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	freezero(oid_dgst, oid_dgst_len);
	آزاد(sig);
	بازگشت ret;
}

ایستا صحیح
pkcs11_sign_ecdsa(ساختار sshkey *کلید,
    u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت نویسه *alg, ثابت نویسه *sk_provider,
    ثابت نویسه *sk_pin, u_int compat)
{
	ساختار pkcs11_کلید	*k11;
	ساختار pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0, bnlen;
	CK_RV			rv;
	BIGNUM			*sig_r = پوچ, *sig_s = پوچ;
	u_char			*sig = پوچ, *dgst = پوچ;
	size_t			dgst_len = 0;
	صحیح			hashalg, ret = -1, r, siglen;

	اگر (sigp != پوچ)
		*sigp = پوچ;
	اگر (lenp != پوچ)
		*lenp = 0;

	اگر ((k11 = pkcs11_lookup_کلید(کلید)) == پوچ) {
		error_f("no key found");
		بازگشت SSH_ERR_کلید_NOT_FOUND;
	}

	اگر (pkcs11_get_کلید(k11, CKM_ECDSA) == -1) {
		error("pkcs11_get_key failed");
		بازگشت SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	/* Prepare digest to be signed */
	اگر ((hashalg = sshkey_ec_nid_to_hash_alg(کلید->ecdsa_nid)) == -1)
		fatal_f("couldn't determine ECDSA hash alg");
	اگر ((dgst_len = ssh_digest_bytes(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);
	dgst = xcalloc(1, dgst_len);
	اگر ((r = ssh_digest_memory(hashalg, data, datalen,
	    dgst, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	اگر ((siglen = EVP_PKEY_size(کلید->pkey)) <= 0)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dgst_len, sig, &slen);
	اگر (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		برو done;
	}
	اگر (slen < 64 || slen > 132 || slen % 2) {
		error_f("bad signature length: %lu", (u_long)slen);
		برو done;
	}
	bnlen = slen/2;
	اگر ((sig_r = BN_bin2bn(sig, bnlen, پوچ)) == پوچ ||
	    (sig_s = BN_bin2bn(sig+bnlen, bnlen, پوچ)) == پوچ) {
		ossl_error("BN_bin2bn failed");
		برو done;
	}

	اگر ((ret = ssh_ecdsa_encode_store_sig(کلید, sig_r, sig_s,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	freezero(dgst, dgst_len);
	BN_free(sig_r);
	BN_free(sig_s);
	آزاد(sig);
	بازگشت ret;
}
#endif /* WITH_OPENSSL */

ایستا صحیح
pkcs11_sign_ed25519(ساختار sshkey *کلید,
    u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت نویسه *alg, ثابت نویسه *sk_provider,
    ثابت نویسه *sk_pin, u_int compat)
{
	ساختار pkcs11_کلید	*k11;
	ساختار pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	u_char			*sig = پوچ;
	CK_BYTE			*xdata = پوچ;
	صحیح			ret = -1;

	اگر (sigp != پوچ)
		*sigp = پوچ;
	اگر (lenp != پوچ)
		*lenp = 0;

	اگر ((k11 = pkcs11_lookup_کلید(کلید)) == پوچ) {
		error_f("no key found");
		بازگشت SSH_ERR_کلید_NOT_FOUND;
	}

	اگر (pkcs11_get_کلید(k11, CKM_EDDSA) == -1) {
		error("pkcs11_get_key failed");
		بازگشت SSH_ERR_AGENT_FAILURE;
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
	اگر (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		برو done;
	}
	اگر (slen != crypto_sign_ed25519_BYTES) {
		error_f("bad signature length: %lu", (u_long)slen);
		برو done;
	}
	اگر ((ret = ssh_ed25519_encode_store_sig(sig, slen, sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	اگر (xdata != پوچ)
		freezero(xdata, datalen);
	آزاد(sig);
	بازگشت ret;
}

/* remove trailing spaces */
ایستا نویسه *
rmspace(u_char *buf, size_t len)
{
	size_t i;

	اگر (len == 0)
		بازگشت buf;
	برای (i = len - 1; i > 0; i--)
		اگر (buf[i] == ' ')
			buf[i] = '\0';
		وگرنه
			بشکن;
	بازگشت buf;
}
/* Used to printf fixed-width, space-padded, unterminated strings using %.*s */
#define RMSPACE(s) (صحیح)اندازه(s), rmspace(s, اندازه(s))

/*
 * open a pkcs11 session and login if required.
 * if pin == NULL we delay login until key use
 */
ایستا صحیح
pkcs11_open_session(ساختار pkcs11_provider *p, CK_ULONG slotidx, نویسه *pin,
    CK_ULONG user)
{
	ساختار pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_RV			rv;
	CK_SESSION_HANDLE	session;
	صحیح			login_required, ret;

	f = p->function_list;
	si = &p->slotinfo[slotidx];

	login_required = si->token.flags & CKF_LOGIN_REQUIRED;

	/* fail early before opening session */
	اگر (login_required && !pkcs11_interactive &&
	    (pin == پوچ || strlen(pin) == 0)) {
		error("pin required");
		بازگشت (-SSH_PKCS11_ERR_PIN_REQUIRED);
	}
	اگر ((rv = f->C_OpenSession(p->slotlist[slotidx], CKF_RW_SESSION|
	    CKF_SERIAL_SESSION, پوچ, پوچ, &session)) != CKR_OK) {
		error("C_OpenSession failed: %lu", rv);
		بازگشت (-1);
	}
	اگر (login_required && pin != پوچ && strlen(pin) != 0) {
		rv = f->C_Login(session, user, (u_char *)pin, strlen(pin));
		اگر (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
			error("C_Login failed: %lu", rv);
			ret = (rv == CKR_PIN_LOCKED) ?
			    -SSH_PKCS11_ERR_PIN_LOCKED :
			    -SSH_PKCS11_ERR_LOGIN_FAIL;
			اگر ((rv = f->C_CloseSession(session)) != CKR_OK)
				error("C_CloseSession failed: %lu", rv);
			بازگشت (ret);
		}
		si->logged_in = 1;
	}
	si->session = session;
	بازگشت (0);
}

ایستا صحیح
pkcs11_کلید_included(ساختار sshkey ***keysp, صحیح *nkeys, ساختار sshkey *کلید)
{
	صحیح i;

	برای (i = 0; i < *nkeys; i++)
		اگر (sshkey_equal(کلید, (*keysp)[i]))
			بازگشت (1);
	بازگشت (0);
}

#ifdef WITH_OPENSSL
ایستا ساختار sshkey *
pkcs11_fetch_ecdsa_pubkey(ساختار pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 کلید_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = پوچ;
	CK_RV			 rv;
	ASN1_OCTET_STRING	*octet = پوچ;
	EC_کلید			*ec = پوچ;
	EC_GROUP		*group = پوچ;
	ساختار sshkey		*کلید = پوچ;
	ثابت unsigned نویسه	*attrp = پوچ;
	صحیح			 success = -1, r, i, nid;

	memset(&کلید_attr, 0, اندازه(کلید_attr));
	کلید_attr[0].type = CKA_ID;
	کلید_attr[1].type = CKA_EC_POINT;
	کلید_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_مقدار(session, *obj, کلید_attr, 3);
	اگر (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		بازگشت (پوچ);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	اگر (کلید_attr[1].ul_مقدار_Len == 0 ||
	    کلید_attr[2].ul_مقدار_Len == 0) {
		error("invalid attribute length");
		بازگشت (پوچ);
	}

	/* allocate buffers for attributes */
	برای (i = 0; i < 3; i++)
		اگر (کلید_attr[i].ul_مقدار_Len > 0)
			کلید_attr[i].p_مقدار = xcalloc(1, کلید_attr[i].ul_مقدار_Len);

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_مقدار(session, *obj, کلید_attr, 3);
	اگر (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		برو fail;
	}

	ec = EC_کلید_new();
	اگر (ec == پوچ) {
		error("EC_KEY_new failed");
		برو fail;
	}

	attrp = کلید_attr[2].p_مقدار;
	group = d2i_ECPKParameters(پوچ, &attrp, کلید_attr[2].ul_مقدار_Len);
	اگر (group == پوچ) {
		ossl_error("d2i_ECPKParameters failed");
		برو fail;
	}

	اگر (EC_کلید_set_group(ec, group) == 0) {
		ossl_error("EC_KEY_set_group failed");
		برو fail;
	}

	اگر (کلید_attr[1].ul_مقدار_Len <= 2) {
		error("CKA_EC_POINT too small");
		برو fail;
	}

	attrp = کلید_attr[1].p_مقدار;
	octet = d2i_ASN1_OCTET_STRING(پوچ, &attrp, کلید_attr[1].ul_مقدار_Len);
	اگر (octet == پوچ) {
		ossl_error("d2i_ASN1_OCTET_STRING failed");
		برو fail;
	}
	attrp = ASN1_STRING_get0_data(octet);
	اگر (o2i_ECPublic_کلید(&ec, &attrp, ASN1_STRING_length(octet)) == پوچ) {
		ossl_error("o2i_ECPublicKey failed");
		برو fail;
	}
	اگر ((r = sshkey_ec_validate_public(EC_کلید_get0_group(ec),
	    EC_کلید_get0_public_کلید(ec))) != 0) {
		error_fr(r, "invalid EC key");
		برو fail;
	}

	nid = sshkey_ecdsa_کلید_to_nid(ec);
	اگر (nid < 0) {
		error("couldn't get curve nid");
		برو fail;
	}

	کلید = sshkey_new(کلید_UNSPEC);
	اگر (کلید == پوچ) {
		error("sshkey_new failed");
		برو fail;
	}

	EVP_PKEY_free(کلید->pkey);
	اگر ((کلید->pkey = EVP_PKEY_new()) == پوچ)
		fatal("EVP_PKEY_new failed");
	اگر (EVP_PKEY_set1_EC_کلید(کلید->pkey, ec) != 1)
		fatal("EVP_PKEY_set1_EC_KEY failed");
	کلید->ecdsa_nid = nid;
	کلید->type = کلید_ECDSA;
	کلید->flags |= SSHKEY_FLAG_EXT;
	اگر (pkcs11_record_کلید(p, slotidx, &کلید_attr[0], کلید))
		برو fail;
	/* success */
	success = 0;
fail:
	اگر (success != 0) {
		sshkey_free(کلید);
		کلید = پوچ;
	}
	برای (i = 0; i < 3; i++)
		آزاد(کلید_attr[i].p_مقدار);
	اگر (ec)
		EC_کلید_free(ec);
	اگر (group)
		EC_GROUP_free(group);
	اگر (octet)
		ASN1_OCTET_STRING_free(octet);

	بازگشت (کلید);
}

ایستا ساختار sshkey *
pkcs11_fetch_rsa_pubkey(ساختار pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 کلید_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = پوچ;
	CK_RV			 rv;
	RSA			*rsa = پوچ;
	BIGNUM			*rsa_n, *rsa_e;
	ساختار sshkey		*کلید = پوچ;
	صحیح			 i, success = -1;

	memset(&کلید_attr, 0, اندازه(کلید_attr));
	کلید_attr[0].type = CKA_ID;
	کلید_attr[1].type = CKA_MODULUS;
	کلید_attr[2].type = CKA_PUBLIC_EXPONENT;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_مقدار(session, *obj, کلید_attr, 3);
	اگر (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		بازگشت (پوچ);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	اگر (کلید_attr[1].ul_مقدار_Len == 0 ||
	    کلید_attr[2].ul_مقدار_Len == 0) {
		error("invalid attribute length");
		بازگشت (پوچ);
	}

	/* allocate buffers for attributes */
	برای (i = 0; i < 3; i++)
		اگر (کلید_attr[i].ul_مقدار_Len > 0)
			کلید_attr[i].p_مقدار = xcalloc(1, کلید_attr[i].ul_مقدار_Len);

	/* retrieve ID, modulus and public exponent of RSA key */
	rv = f->C_Get_Attribute_مقدار(session, *obj, کلید_attr, 3);
	اگر (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		برو fail;
	}

	rsa = RSA_new();
	اگر (rsa == پوچ) {
		error("RSA_new failed");
		برو fail;
	}

	rsa_n = BN_bin2bn(کلید_attr[1].p_مقدار, کلید_attr[1].ul_مقدار_Len, پوچ);
	rsa_e = BN_bin2bn(کلید_attr[2].p_مقدار, کلید_attr[2].ul_مقدار_Len, پوچ);
	اگر (rsa_n == پوچ || rsa_e == پوچ) {
		error("BN_bin2bn failed");
		برو fail;
	}
	اگر (!RSA_set0_کلید(rsa, rsa_n, rsa_e, پوچ))
		fatal_f("set key");
	rsa_n = rsa_e = پوچ; /* transferred */

	کلید = sshkey_new(کلید_UNSPEC);
	اگر (کلید == پوچ) {
		error("sshkey_new failed");
		برو fail;
	}

	EVP_PKEY_free(کلید->pkey);
	اگر ((کلید->pkey = EVP_PKEY_new()) == پوچ)
		fatal("EVP_PKEY_new failed");
	اگر (EVP_PKEY_set1_RSA(کلید->pkey, rsa) != 1)
		fatal("EVP_PKEY_set1_RSA failed");
	کلید->type = کلید_RSA;
	کلید->flags |= SSHKEY_FLAG_EXT;
	اگر (EVP_PKEY_bits(کلید->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE) {
		error_f("RSA key too small %d < minimum %d",
		    EVP_PKEY_bits(کلید->pkey), SSH_RSA_MINIMUM_MODULUS_SIZE);
		برو fail;
	}
	اگر (pkcs11_record_کلید(p, slotidx, &کلید_attr[0], کلید))
		برو fail;
	/* success */
	success = 0;
fail:
	برای (i = 0; i < 3; i++)
		آزاد(کلید_attr[i].p_مقدار);
	RSA_free(rsa);
	اگر (success != 0) {
		sshkey_free(کلید);
		کلید = پوچ;
	}
	بازگشت کلید;
}
#endif /* WITH_OPENSSL */

ایستا ساختار sshkey *
pkcs11_fetch_ed25519_pubkey(ساختار pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 کلید_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = پوچ;
	CK_RV			 rv;
	ساختار sshkey		*کلید = پوچ;
	ثابت unsigned نویسه	*d = پوچ;
	size_t			len;
	نویسه			*hex = پوچ;
	صحیح			 success = -1, i;
	/* https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061180 */
	ثابت u_char		 id1[14] = {
		0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64,
		0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
	}; /* PrintableString { "edwards25519" } */
	ثابت u_char		 id2[5] = {
		0x06, 0x03, 0x2b, 0x65, 0x70,
	}; /* OBJECT_IDENTIFIER { 1.3.101.112 } */

	memset(&کلید_attr, 0, اندازه(کلید_attr));
	کلید_attr[0].type = CKA_ID;
	کلید_attr[1].type = CKA_EC_POINT; /* XXX or CKA_VALUE ? */
	کلید_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_مقدار(session, *obj, کلید_attr, 3);
	اگر (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		بازگشت (پوچ);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	اگر (کلید_attr[1].ul_مقدار_Len == 0 ||
	    کلید_attr[2].ul_مقدار_Len == 0) {
		error("invalid attribute length");
		بازگشت (پوچ);
	}

	/* allocate buffers for attributes */
	برای (i = 0; i < 3; i++) {
		اگر (کلید_attr[i].ul_مقدار_Len > 0)
			کلید_attr[i].p_مقدار = xcalloc(1, کلید_attr[i].ul_مقدار_Len);
	}

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_مقدار(session, *obj, کلید_attr, 3);
	اگر (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		برو fail;
	}

	/* Expect one of the supported identifiers in CKA_EC_PARAMS */
	d = (u_char *)کلید_attr[2].p_مقدار;
	len = کلید_attr[2].ul_مقدار_Len;
	اگر ((len != اندازه(id1) || memcmp(d, id1, اندازه(id1)) != 0) &&
	    (len != اندازه(id2) || memcmp(d, id2, اندازه(id2)) != 0)) {
		hex = tohex(d, len);
		logit_f("unsupported CKA_EC_PARAMS: %s (len %zu)", hex, len);
		برو fail;
	}

	/*
	 * Expect either a raw 32 byte pubkey or an OCTET STRING with
	 * a 32 byte pubkey in CKA_VALUE
	 */
	d = (u_char *)کلید_attr[1].p_مقدار;
	len = کلید_attr[1].ul_مقدار_Len;
	اگر (len == ED25519_PK_SZ + 2 && d[0] == 0x04 && d[1] == ED25519_PK_SZ) {
		d += 2;
		len -= 2;
	}
	اگر (len != ED25519_PK_SZ) {
		hex = tohex(کلید_attr[1].p_مقدار, کلید_attr[1].ul_مقدار_Len);
		logit_f("CKA_EC_POINT invalid octet str: %s (len %lu)",
		    hex, (u_long)کلید_attr[1].ul_مقدار_Len);
		برو fail;
	}

	اگر ((کلید = sshkey_new(کلید_UNSPEC)) == پوچ)
		fatal_f("sshkey_new failed");
	کلید->ed25519_pk = xmalloc(ED25519_PK_SZ);
	memcpy(کلید->ed25519_pk, d, ED25519_PK_SZ);
	کلید->type = کلید_ED25519;
	کلید->flags |= SSHKEY_FLAG_EXT;
	اگر (pkcs11_record_کلید(p, slotidx, &کلید_attr[0], کلید))
		برو fail;
	/* success */
	success = 0;
 fail:
	اگر (success != 0) {
		sshkey_free(کلید);
		کلید = پوچ;
	}
	آزاد(hex);
	برای (i = 0; i < 3; i++)
		آزاد(کلید_attr[i].p_مقدار);
	بازگشت کلید;
}

#ifdef WITH_OPENSSL
ایستا صحیح
pkcs11_fetch_x509_pubkey(ساختار pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj, ساختار sshkey **keyp, نویسه **labelp)
{
	CK_ATTRIBUTE		 cert_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = پوچ;
	CK_RV			 rv;
	X509			*x509 = پوچ;
	X509_NAME		*x509_name = پوچ;
	EVP_PKEY		*evp;
	RSA			*rsa = پوچ;
	EC_کلید			*ec = پوچ;
	ساختار sshkey		*کلید = پوچ;
	صحیح			 r, i, nid, success = -1;
	ثابت u_char		*cp;
	نویسه			*subject = پوچ;
#ifdef OPENSSL_HAS_ED25519
	size_t			len;
#endif /* OPENSSL_HAS_ED25519 */

	*keyp = پوچ;
	*labelp = پوچ;

	memset(&cert_attr, 0, اندازه(cert_attr));
	cert_attr[0].type = CKA_ID;
	cert_attr[1].type = CKA_SUBJECT;
	cert_attr[2].type = CKA_مقدار;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_مقدار(session, *obj, cert_attr, 3);
	اگر (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		بازگشت -1;
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	اگر (cert_attr[1].ul_مقدار_Len == 0 ||
	    cert_attr[2].ul_مقدار_Len == 0) {
		error("invalid attribute length");
		بازگشت -1;
	}

	/* allocate buffers for attributes */
	برای (i = 0; i < 3; i++)
		اگر (cert_attr[i].ul_مقدار_Len > 0)
			cert_attr[i].p_مقدار = xcalloc(1, cert_attr[i].ul_مقدار_Len);

	/* retrieve ID, subject and value of certificate */
	rv = f->C_Get_Attribute_مقدار(session, *obj, cert_attr, 3);
	اگر (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		برو out;
	}

	/* Decode DER-encoded cert subject */
	cp = cert_attr[1].p_مقدار;
	اگر ((x509_name = d2i_X509_NAME(پوچ, &cp,
	    cert_attr[1].ul_مقدار_Len)) == پوچ ||
	    (subject = X509_NAME_oneline(x509_name, پوچ, 0)) == پوچ)
		subject = xstrdup("invalid subject");
	X509_NAME_free(x509_name);

	cp = cert_attr[2].p_مقدار;
	اگر ((x509 = d2i_X509(پوچ, &cp, cert_attr[2].ul_مقدار_Len)) == پوچ) {
		error("d2i_x509 failed");
		برو out;
	}

	اگر ((evp = X509_get_pubkey(x509)) == پوچ) {
		error("X509_get_pubkey failed");
		برو out;
	}

	اگر (EVP_PKEY_base_id(evp) == EVP_PKEY_RSA) {
		اگر (EVP_PKEY_get0_RSA(evp) == پوچ) {
			error("invalid x509; no rsa key");
			برو out;
		}
		اگر ((rsa = RSAPublic_کلید_dup(EVP_PKEY_get0_RSA(evp))) == پوچ) {
			error("RSAPublicKey_dup failed");
			برو out;
		}

		کلید = sshkey_new(کلید_UNSPEC);
		اگر (کلید == پوچ) {
			error("sshkey_new failed");
			برو out;
		}

		EVP_PKEY_free(کلید->pkey);
		اگر ((کلید->pkey = EVP_PKEY_new()) == پوچ)
			fatal("EVP_PKEY_new failed");
		اگر (EVP_PKEY_set1_RSA(کلید->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		کلید->type = کلید_RSA;
		کلید->flags |= SSHKEY_FLAG_EXT;
		اگر (EVP_PKEY_bits(کلید->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE) {
			error_f("RSA key too small %d < minimum %d",
			    EVP_PKEY_bits(کلید->pkey),
			    SSH_RSA_MINIMUM_MODULUS_SIZE);
			برو out;
		}
		اگر (pkcs11_record_کلید(p, slotidx, &cert_attr[0], کلید))
			برو out;
		/* success */
		success = 0;
	} وگرنه اگر (EVP_PKEY_base_id(evp) == EVP_PKEY_EC) {
		اگر (EVP_PKEY_get0_EC_کلید(evp) == پوچ) {
			error("invalid x509; no ec key");
			برو out;
		}
		اگر ((ec = EC_کلید_dup(EVP_PKEY_get0_EC_کلید(evp))) == پوچ) {
			error("EC_KEY_dup failed");
			برو out;
		}
		اگر ((r = sshkey_ec_validate_public(EC_کلید_get0_group(ec),
		    EC_کلید_get0_public_کلید(ec))) != 0) {
			error_fr(r, "invalid EC key");
			برو out;
		}
		nid = sshkey_ecdsa_کلید_to_nid(ec);
		اگر (nid < 0) {
			error("couldn't get curve nid");
			برو out;
		}

		کلید = sshkey_new(کلید_UNSPEC);
		اگر (کلید == پوچ) {
			error("sshkey_new failed");
			برو out;
		}

		EVP_PKEY_free(کلید->pkey);
		اگر ((کلید->pkey = EVP_PKEY_new()) == پوچ)
			fatal("EVP_PKEY_new failed");
		اگر (EVP_PKEY_set1_EC_کلید(کلید->pkey, ec) != 1)
			fatal("EVP_PKEY_set1_EC_KEY failed");
		کلید->ecdsa_nid = nid;
		کلید->type = کلید_ECDSA;
		کلید->flags |= SSHKEY_FLAG_EXT;
		اگر (pkcs11_record_کلید(p, slotidx, &cert_attr[0], کلید))
			برو out;
		/* success */
		success = 0;
#ifdef OPENSSL_HAS_ED25519
	} وگرنه اگر (EVP_PKEY_base_id(evp) == EVP_PKEY_ED25519) {
		اگر ((کلید = sshkey_new(کلید_UNSPEC)) == پوچ ||
		    (کلید->ed25519_pk = calloc(1, ED25519_PK_SZ)) == پوچ)
			fatal_f("allocation failed");
		len = ED25519_PK_SZ;
		اگر (!EVP_PKEY_get_raw_public_کلید(evp, کلید->ed25519_pk, &len)) {
			ossl_error("EVP_PKEY_get_raw_public_key failed");
			برو out;
		}
		اگر (len != ED25519_PK_SZ) {
			error_f("incorrect returned public key "
			    "length for ed25519");
			برو out;
		}
		کلید->type = کلید_ED25519;
		کلید->flags |= SSHKEY_FLAG_EXT;
		اگر (pkcs11_record_کلید(p, slotidx, &cert_attr[0], کلید))
			برو out;
		/* success */
		success = 0;
#endif /* OPENSSL_HAS_ED25519 */
	} وگرنه {
		error("unknown certificate key type");
		برو out;
	}
 out:
	برای (i = 0; i < 3; i++)
		آزاد(cert_attr[i].p_مقدار);
	X509_free(x509);
	RSA_free(rsa);
	EC_کلید_free(ec);
	اگر (success != 0 || کلید == پوچ) {
		sshkey_free(کلید);
		آزاد(subject);
		بازگشت -1;
	}
	/* success */
	*keyp = کلید;
	*labelp = subject;
	بازگشت 0;
}
#endif /* WITH_OPENSSL */

ایستا تهی
note_کلید(ساختار pkcs11_provider *p, CK_ULONG slotidx, ثابت نویسه *context,
    ساختار sshkey *کلید)
{
	نویسه *fp;

	اگر ((fp = sshkey_fingerprint(کلید, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == پوچ) {
		error_f("sshkey_fingerprint failed");
		بازگشت;
	}
	debug2("%s: provider %s slot %lu: %s %s", context, p->name,
	    (u_long)slotidx, sshkey_type(کلید), fp);
	آزاد(fp);
}

#ifdef WITH_OPENSSL /* libcrypto needed for certificate parsing */
/*
 * lookup certificates for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
ایستا صحیح
pkcs11_fetch_certs(ساختار pkcs11_provider *p, CK_ULONG slotidx,
    ساختار sshkey ***keysp, نویسه ***labelsp, صحیح *nkeys)
{
	ساختار sshkey		*کلید = پوچ;
	CK_OBJECT_CLASS		 کلید_class;
	CK_ATTRIBUTE		 کلید_attr[1];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = پوچ;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	صحیح			 ret = -1;
	نویسه			*label;

	memset(&کلید_attr, 0, اندازه(کلید_attr));
	memset(&obj, 0, اندازه(obj));

	کلید_class = CKO_CERTIFICATE;
	کلید_attr[0].type = CKA_CLASS;
	کلید_attr[0].p_مقدار = &کلید_class;
	کلید_attr[0].ul_مقدار_Len = اندازه(کلید_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, کلید_attr, 1);
	اگر (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		برو fail;
	}

	وقتی (1) {
		CK_CERTIFICATE_TYPE	ck_cert_type;

		rv = f->C_FindObjects(session, &obj, 1, &n);
		اگر (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			برو fail;
		}
		اگر (n == 0)
			بشکن;

		memset(&ck_cert_type, 0, اندازه(ck_cert_type));
		memset(&کلید_attr, 0, اندازه(کلید_attr));
		کلید_attr[0].type = CKA_CERTIFICATE_TYPE;
		کلید_attr[0].p_مقدار = &ck_cert_type;
		کلید_attr[0].ul_مقدار_Len = اندازه(ck_cert_type);

		rv = f->C_Get_Attribute_مقدار(session, obj, کلید_attr, 1);
		اگر (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			برو fail;
		}

		کلید = پوچ;
		label = پوچ;
		انتخاب (ck_cert_type) {
		حالت CKC_X_509:
			اگر (pkcs11_fetch_x509_pubkey(p, slotidx, &obj,
			    &کلید, &label) != 0) {
				debug_f("failed to fetch key");
				ادامه;
			}
			بشکن;
		پیشفرض:
			error("skipping unsupported certificate type %lu",
			    ck_cert_type);
			ادامه;
		}
		note_کلید(p, slotidx, __func__, کلید);
		اگر (pkcs11_کلید_included(keysp, nkeys, کلید)) {
			debug2_f("key already included");
			sshkey_free(کلید);
		} وگرنه {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, اندازه(ساختار sshkey *));
			(*keysp)[*nkeys] = کلید;
			اگر (labelsp != پوچ) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, اندازه(نویسه *));
				(*labelsp)[*nkeys] = xstrdup((نویسه *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_FindObjectsFinal(session);
	اگر (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	بازگشت (ret);
}
#endif /* WITH_OPENSSL */

/*
 * lookup public keys for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
ایستا صحیح
pkcs11_fetch_کلیدها(ساختار pkcs11_provider *p, CK_ULONG slotidx,
    ساختار sshkey ***keysp, نویسه ***labelsp, صحیح *nkeys)
{
	ساختار sshkey		*کلید = پوچ;
	CK_OBJECT_CLASS		 کلید_class;
	CK_ATTRIBUTE		 کلید_attr[2];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = پوچ;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	صحیح			 ret = -1;

	memset(&کلید_attr, 0, اندازه(کلید_attr));
	memset(&obj, 0, اندازه(obj));

	کلید_class = CKO_PUBLIC_کلید;
	کلید_attr[0].type = CKA_CLASS;
	کلید_attr[0].p_مقدار = &کلید_class;
	کلید_attr[0].ul_مقدار_Len = اندازه(کلید_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, کلید_attr, 1);
	اگر (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		برو fail;
	}

	وقتی (1) {
		CK_کلید_TYPE	ck_کلید_type;
		CK_UTF8CHAR	label[256];

		rv = f->C_FindObjects(session, &obj, 1, &n);
		اگر (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			برو fail;
		}
		اگر (n == 0)
			بشکن;

		memset(&ck_کلید_type, 0, اندازه(ck_کلید_type));
		memset(&کلید_attr, 0, اندازه(کلید_attr));
		کلید_attr[0].type = CKA_کلید_TYPE;
		کلید_attr[0].p_مقدار = &ck_کلید_type;
		کلید_attr[0].ul_مقدار_Len = اندازه(ck_کلید_type);
		کلید_attr[1].type = CKA_LABEL;
		کلید_attr[1].p_مقدار = &label;
		کلید_attr[1].ul_مقدار_Len = اندازه(label) - 1;

		rv = f->C_Get_Attribute_مقدار(session, obj, کلید_attr, 2);
		اگر (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			برو fail;
		}

		label[کلید_attr[1].ul_مقدار_Len] = '\0';

		انتخاب (ck_کلید_type) {
#ifdef WITH_OPENSSL
		حالت CKK_RSA:
			کلید = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			بشکن;
		حالت CKK_ECDSA:
			کلید = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			بشکن;
#endif /* WITH_OPENSSL */
		حالت CKK_EC_EDWARDS:
			کلید = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			بشکن;
		پیشفرض:
			/* XXX print key type? */
			کلید = پوچ;
			error("skipping unsupported key type 0x%lx",
			    (u_long)ck_کلید_type);
		}

		اگر (کلید == پوچ) {
			debug_f("failed to fetch key");
			ادامه;
		}
		note_کلید(p, slotidx, __func__, کلید);
		اگر (pkcs11_کلید_included(keysp, nkeys, کلید)) {
			debug2_f("key already included");
			sshkey_free(کلید);
		} وگرنه {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, اندازه(ساختار sshkey *));
			(*keysp)[*nkeys] = کلید;
			اگر (labelsp != پوچ) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, اندازه(نویسه *));
				(*labelsp)[*nkeys] = xstrdup((نویسه *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_FindObjectsFinal(session);
	اگر (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	بازگشت (ret);
}

#ifdef WITH_PKCS11_KEYGEN
#define FILL_ATTR(attr, idx, typ, val, len) \
	{ (attr[idx]).type=(typ); (attr[idx]).p_مقدار=(val); (attr[idx]).ul_مقدار_Len=len; idx++; }

ایستا ساختار sshkey *
pkcs11_rsa_generate_private_کلید(ساختار pkcs11_provider *p, CK_ULONG slotidx,
    نویسه *label, CK_ULONG bits, CK_BYTE keyid, uint32_t *err)
{
	ساختار pkcs11_slotinfo	*si;
	نویسه			*plabel = label ? label : "";
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
	pubkey_filter[0].p_مقدار = &pubkey_class;
	cert_filter[0].p_مقدار = &cert_class;

	*err = 0;

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, اندازه(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, اندازه(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, اندازه(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    اندازه(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, اندازه(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, اندازه(false_val));
	FILL_ATTR(tpub, npub, CKA_MODULUS_BITS, &bits, اندازه(bits));
	FILL_ATTR(tpub, npub, CKA_PUBLIC_EXPONENT, pubExponent,
	    اندازه(pubExponent));
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, اندازه(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN,  &true_val, اندازه(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL,  plabel, strlen(plabel));
	FILL_ATTR(tpriv, npriv, CKA_PRIVATE,  &true_val, اندازه(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE,  &true_val, اندازه(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT,  &false_val, اندازه(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN,  &true_val, اندازه(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER,  &false_val,
	    اندازه(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP,  &false_val, اندازه(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE,  &false_val, اندازه(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, اندازه(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	اگر ((rv = f->C_Generate_کلید_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_کلید_2, &priv_کلید)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		بازگشت پوچ;
	}

	بازگشت pkcs11_fetch_rsa_pubkey(p, slotidx, &pub_کلید_2);
}

ایستا صحیح
h2i(نویسه c)
{
	اگر (c >= '0' && c <= '9')
		بازگشت c - '0';
	وگرنه اگر (c >= 'a' && c <= 'f')
		بازگشت c - 'a' + 10;
	وگرنه اگر (c >= 'A' && c <= 'F')
		بازگشت c - 'A' + 10;
	وگرنه
		بازگشت -1;
}

ایستا صحیح
pkcs11_decode_hex(ثابت نویسه *hex, unsigned نویسه **dest, size_t *rlen)
{
	size_t	i, len;

	اگر (dest)
		*dest = پوچ;
	اگر (rlen)
		*rlen = 0;

	اگر ((len = strlen(hex)) % 2)
		بازگشت -1;
	len /= 2;

	*dest = xmalloc(len);

	برای (i = 0; i < len; i++) {
		صحیح hi, lo;

		hi = h2i(hex[2 * i]);
		lo = h2i(hex[(2 * i) + 1]);
		اگر (hi == -1 || lo == -1)
			بازگشت -1;
		(*dest)[i] = (hi << 4) | lo;
	}

	اگر (rlen)
		*rlen = len;

	بازگشت 0;
}

ایستا ساختار ec_curve_info {
	ثابت نویسه	*name;
	ثابت نویسه	*oid;
	ثابت نویسه	*oid_encoded;
	size_t		 size;
} ec_curve_infos[] = {
	{"prime256v1",	"1.2.840.10045.3.1.7",	"06082A8648CE3D030107", 256},
	{"secp384r1",	"1.3.132.0.34",		"06052B81040022",	384},
	{"secp521r1",	"1.3.132.0.35",		"06052B81040023",	521},
	{پوچ,		پوچ,			پوچ,			0},
};

ایستا ساختار sshkey *
pkcs11_ecdsa_generate_private_کلید(ساختار pkcs11_provider *p, CK_ULONG slotidx,
    نویسه *label, CK_ULONG bits, CK_BYTE keyid, uint32_t *err)
{
	ساختار pkcs11_slotinfo	*si;
	نویسه			*plabel = label ? label : "";
	صحیح			 i;
	size_t			 ecparams_size;
	unsigned نویسه		*ecparams = پوچ;
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

	برای (i = 0; ec_curve_infos[i].name; i++) {
		اگر (ec_curve_infos[i].size == bits)
			بشکن;
	}
	اگر (!ec_curve_infos[i].name) {
		error_f("invalid key size %lu", bits);
		بازگشت پوچ;
	}
	اگر (pkcs11_decode_hex(ec_curve_infos[i].oid_encoded, &ecparams,
	    &ecparams_size) == -1) {
		error_f("invalid oid");
		بازگشت پوچ;
	}

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, اندازه(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, اندازه(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, اندازه(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    اندازه(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, اندازه(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, اندازه(false_val));
	FILL_ATTR(tpub, npub, CKA_EC_PARAMS, ecparams, ecparams_size);
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, اندازه(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN, &true_val, اندازه(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpriv, npriv, CKA_PRIVATE, &true_val, اندازه(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE, &true_val, اندازه(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT, &false_val, اندازه(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN, &true_val, اندازه(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER, &false_val,
	    اندازه(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP, &false_val, اندازه(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE, &false_val, اندازه(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, اندازه(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	اگر ((rv = f->C_Generate_کلید_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_کلید_2, &priv_کلید)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		بازگشت پوچ;
	}

	بازگشت pkcs11_fetch_ecdsa_pubkey(p, slotidx, &pub_کلید_2);
}
#endif /* WITH_PKCS11_KEYGEN */

/*
 * register a new provider, fails if provider already exists. if
 * keyp is provided, fetch keys.
 */
ایستا صحیح
pkcs11_register_provider(نویسه *provider_id, نویسه *pin,
    ساختار sshkey ***keyp, نویسه ***labelsp,
    ساختار pkcs11_provider **providerp, CK_ULONG user)
{
	صحیح nkeys, need_finalize = 0;
	صحیح ret = -1;
	ساختار pkcs11_provider *p = پوچ;
	تهی *handle = پوچ;
	CK_RV (*getfunctionlist)(CK_FUNCTION_LIST **);
	CK_RV rv;
	CK_FUNCTION_LIST *f = پوچ;
	CK_TOKEN_INFO *token;
	CK_ULONG i;

	اگر (providerp == پوچ)
		برو fail;
	*providerp = پوچ;

	اگر (keyp != پوچ)
		*keyp = پوچ;
	اگر (labelsp != پوچ)
		*labelsp = پوچ;

	اگر (pkcs11_provider_lookup(provider_id) != پوچ) {
		debug_f("provider already registered: %s", provider_id);
		برو fail;
	}
	اگر (lib_contains_نماد(provider_id, "C_GetFunctionList") != 0) {
		error("provider %s is not a PKCS11 library", provider_id);
		برو fail;
	}
	/* open shared pkcs11-library */
	اگر ((handle = dlopen(provider_id, RTLD_NOW)) == پوچ) {
		error("dlopen %s failed: %s", provider_id, dlerror());
		برو fail;
	}
	اگر ((getfunctionlist = dlsym(handle, "C_GetFunctionList")) == پوچ)
		fatal("dlsym(C_GetFunctionList) failed: %s", dlerror());
	p = xcalloc(1, اندازه(*p));
	p->name = xstrdup(provider_id);
	p->handle = handle;
	/* set up the pkcs11 callbacks */
	اگر ((rv = (*getfunctionlist)(&f)) != CKR_OK) {
		error("C_GetFunctionList for provider %s failed: %lu",
		    provider_id, rv);
		برو fail;
	}
	p->function_list = f;
	اگر ((rv = f->C_Initialize(پوچ)) != CKR_OK) {
		error("C_Initialize for provider %s failed: %lu",
		    provider_id, rv);
		برو fail;
	}
	need_finalize = 1;
	اگر ((rv = f->C_GetInfo(&p->info)) != CKR_OK) {
		error("C_GetInfo for provider %s failed: %lu",
		    provider_id, rv);
		برو fail;
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
	اگر ((rv = f->C_GetSlotList(CK_TRUE, پوچ, &p->nslots)) != CKR_OK) {
		error("C_GetSlotList failed: %lu", rv);
		برو fail;
	}
	اگر (p->nslots == 0) {
		debug_f("provider %s returned no slots", provider_id);
		ret = -SSH_PKCS11_ERR_NO_SLOTS;
		برو fail;
	}
	p->slotlist = xcalloc(p->nslots, اندازه(CK_SLOT_ID));
	اگر ((rv = f->C_GetSlotList(CK_TRUE, p->slotlist, &p->nslots))
	    != CKR_OK) {
		error("C_GetSlotList for provider %s failed: %lu",
		    provider_id, rv);
		برو fail;
	}
	p->slotinfo = xcalloc(p->nslots, اندازه(ساختار pkcs11_slotinfo));
	p->valid = 1;
	nkeys = 0;
	برای (i = 0; i < p->nslots; i++) {
		token = &p->slotinfo[i].token;
		اگر ((rv = f->C_GetTokenInfo(p->slotlist[i], token))
		    != CKR_OK) {
			error("C_GetTokenInfo for provider %s slot %lu "
			    "failed: %lu", provider_id, (u_long)i, rv);
			ادامه;
		}
		اگر ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
			debug2_f("ignoring uninitialised token in "
			    "provider %s slot %lu", provider_id, (u_long)i);
			ادامه;
		}
		debug("provider %s slot %lu: label <%.*s> "
		    "manufacturerID <%.*s> model <%.*s> serial <%.*s> "
		    "flags 0x%lx",
		    provider_id, (unsigned long)i,
		    RMSPACE(token->label), RMSPACE(token->manufacturerID),
		    RMSPACE(token->model), RMSPACE(token->serial_عدد_2),
		    token->flags);
		/*
		 * open session, login with pin and retrieve public
		 * keys (if keyp is provided)
		 */
		اگر ((ret = pkcs11_open_session(p, i, pin, user)) != 0 ||
		    keyp == پوچ)
			ادامه;
		pkcs11_fetch_کلیدها(p, i, keyp, labelsp, &nkeys);
#ifdef WITH_OPENSSL
		pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#endif
		اگر (nkeys == 0 && !p->slotinfo[i].logged_in &&
		    pkcs11_interactive) {
			/*
			 * Some tokens require login before they will
			 * expose keys.
			 */
			اگر (pkcs11_login_slot(p, &p->slotinfo[i],
			    CKU_USER) < 0) {
				error("login failed");
				ادامه;
			}
			pkcs11_fetch_کلیدها(p, i, keyp, labelsp, &nkeys);
#ifdef WITH_OPENSSL
			pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#endif
		}
	}

	/* now owned by caller */
	*providerp = p;

	TAILQ_INSERT_TAIL(&pkcs11_providers, p, next);
	p->refcount++;	/* add to provider list */

	بازگشت (nkeys);
fail:
	اگر (need_finalize && (rv = f->C_Finalize(پوچ)) != CKR_OK)
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
	بازگشت (ret);
}

صحیح
pkcs11_init(صحیح interactive)
{
	debug3_f("called, interactive = %d", interactive);

	pkcs11_interactive = interactive;
	TAILQ_INIT(&pkcs11_providers);
	TAILQ_INIT(&pkcs11_کلیدها);
	بازگشت (0);
}

/* unregister all providers, keys might still point to the providers */
تهی
pkcs11_terminate(تهی)
{
	ساختار pkcs11_provider *p;
	ساختار pkcs11_کلید *k11;

	debug3_f("called");

	وقتی ((k11 = TAILQ_FIRST(&pkcs11_کلیدها)) != پوچ) {
		TAILQ_REMOVE(&pkcs11_کلیدها, k11, next);
		pkcs11_k11_free(k11);
	}
	وقتی ((p = TAILQ_FIRST(&pkcs11_providers)) != پوچ) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
}

/*
 * register a new provider and get number of keys hold by the token,
 * fails if provider already exists
 */
صحیح
pkcs11_add_provider(نویسه *provider_id, نویسه *pin, ساختار sshkey ***keyp,
    نویسه ***labelsp)
{
	ساختار pkcs11_provider *p = پوچ;
	صحیح nkeys;

	nkeys = pkcs11_register_provider(provider_id, pin, keyp, labelsp,
	    &p, CKU_USER);

	/* no keys found or some other error, de-register provider */
	اگر (nkeys <= 0 && p != پوچ) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
	اگر (nkeys == 0)
		debug_f("provider %s returned no keys", provider_id);

	بازگشت (nkeys);
}

صحیح
pkcs11_sign(ساختار sshkey *کلید,
    u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت نویسه *alg, ثابت نویسه *sk_provider,
    ثابت نویسه *sk_pin, u_int compat)
{
	انتخاب (کلید->type) {
#ifdef WITH_OPENSSL
	حالت کلید_RSA:
	حالت کلید_RSA_CERT:
		بازگشت pkcs11_sign_rsa(کلید, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	حالت کلید_ECDSA:
	حالت کلید_ECDSA_CERT:
		بازگشت pkcs11_sign_ecdsa(کلید, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
#endif /* WITH_OPENSSL */
	حالت کلید_ED25519:
	حالت کلید_ED25519_CERT:
		بازگشت pkcs11_sign_ed25519(کلید, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	پیشفرض:
		بازگشت SSH_ERR_کلید_TYPE_UNKNOWN;
	}
}

تهی
pkcs11_کلید_free(ساختار sshkey *کلید)
{
	/* never called */
}

#ifdef WITH_PKCS11_KEYGEN
ساختار sshkey *
pkcs11_gakp(نویسه *provider_id, نویسه *pin, unsigned صحیح slotidx, نویسه *label,
    unsigned صحیح type, unsigned صحیح bits, unsigned نویسه keyid, uint32_t *err)
{
	ساختار pkcs11_provider	*p = پوچ;
	ساختار pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	ساختار sshkey		*k = پوچ;
	صحیح			 ret = -1, reset_pin = 0, reset_provider = 0;
	CK_RV			 rv;

	*err = 0;

	اگر ((p = pkcs11_provider_lookup(provider_id)) != پوچ)
		debug_f("provider \"%s\" available", provider_id);
	وگرنه اگر ((ret = pkcs11_register_provider(provider_id, pin, پوچ, پوچ,
	    &p, CKU_SO)) < 0) {
		debug_f("could not register provider %s", provider_id);
		برو out;
	} وگرنه
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	اگر ((rv = f->C_SetOperationState(session , pin, strlen(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} وگرنه
		reset_pin = 1;

	انتخاب (type) {
	حالت کلید_RSA:
		اگر ((k = pkcs11_rsa_generate_private_کلید(p, slotidx, label,
		    bits, keyid, err)) == پوچ) {
			debug_f("failed to generate RSA key");
			برو out;
		}
		بشکن;
	حالت کلید_ECDSA:
		اگر ((k = pkcs11_ecdsa_generate_private_کلید(p, slotidx, label,
		    bits, keyid, err)) == پوچ) {
			debug_f("failed to generate ECDSA key");
			برو out;
		}
		بشکن;
	پیشفرض:
		*err = SSH_PKCS11_ERR_GENERIC;
		debug_f("unknown type %d", type);
		برو out;
	}

out:
	اگر (reset_pin)
		f->C_SetOperationState(session , پوچ, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	اگر (reset_provider)
		pkcs11_del_provider(provider_id);

	بازگشت (k);
}

ساختار sshkey *
pkcs11_destroy_keypair(نویسه *provider_id, نویسه *pin, unsigned long slotidx,
    unsigned نویسه keyid, uint32_t *err)
{
	ساختار pkcs11_provider	*p = پوچ;
	ساختار pkcs11_slotinfo	*si;
	ساختار sshkey		*k = پوچ;
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

	اگر ((p = pkcs11_provider_lookup(provider_id)) != پوچ) {
		debug_f("using provider \"%s\"", provider_id);
	} وگرنه اگر (pkcs11_register_provider(provider_id, pin, پوچ, پوچ, &p,
	    CKU_SO) < 0) {
		debug_f("could not register provider %s",
		    provider_id);
		برو out;
	} وگرنه
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	اگر ((rv = f->C_SetOperationState(session , pin, strlen(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} وگرنه
		reset_pin = 1;

	/* private key */
	nattrs = 0;
	کلید_class = CKO_PRIVATE_کلید;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &کلید_class, اندازه(کلید_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, اندازه(keyid));

	اگر (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {
		اگر ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy private key 0x%hhx",
			    keyid);
			*err = rv;
			برو out;
		}
	}

	/* public key */
	nattrs = 0;
	کلید_class = CKO_PUBLIC_کلید;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &کلید_class, اندازه(کلید_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, اندازه(keyid));

	اگر (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {

		/* get key type */
		nattrs = 0;
		FILL_ATTR(attrs, nattrs, CKA_کلید_TYPE, &کلید_type,
		    اندازه(کلید_type));
		rv = f->C_Get_Attribute_مقدار(session, obj, attrs, nattrs);
		اگر (rv != CKR_OK) {
			debug_f("could not get key type of public key 0x%hhx",
			    keyid);
			*err = rv;
			کلید_type = -1;
		}
		انتخاب (کلید_type) {
#ifdef WITH_OPENSSL
		حالت CKK_RSA:
			k = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			بشکن;
		حالت CKK_ECDSA:
			k = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			بشکن;
#endif /* WITH_OPENSSL */
		حالت CKK_EC_EDWARDS:
			k = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			بشکن;
		پیشفرض:
			debug_f("unsupported key type %lu", (u_long)کلید_type);
			بشکن;
		}

		اگر ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy public key 0x%hhx", keyid);
			*err = rv;
			برو out;
		}
	}

out:
	اگر (reset_pin)
		f->C_SetOperationState(session , پوچ, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	اگر (reset_provider)
		pkcs11_del_provider(provider_id);

	بازگشت (k);
}
#endif /* WITH_PKCS11_KEYGEN */
#وگرنه /* ENABLE_PKCS11 */

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
	بازگشت (-1);
}

صحیح
pkcs11_add_provider(نویسه *provider_id, نویسه *pin, ساختار sshkey ***keyp,
    نویسه ***labelsp)
{
	error_f("PKCS#11 not supported");
	بازگشت (-1);
}

تهی
pkcs11_کلید_free(ساختار sshkey *کلید)
{
	error_f("PKCS#11 not supported");
}

صحیح
pkcs11_sign(ساختار sshkey *کلید,
    u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت نویسه *alg, ثابت نویسه *sk_provider,
    ثابت نویسه *sk_pin, u_int compat)
{
	error_f("PKCS#11 not supported");
	بازگشت SSH_ERR_FEATURE_UNSUPPORTED;
}

تهی
pkcs11_terminate(تهی)
{
	error_f("PKCS#11 not supported");
}
#endif /* ENABLE_PKCS11 */
