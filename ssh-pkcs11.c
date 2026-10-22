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

#ضمن "includes.h"

#اگر_تعریف_شده ENABLE_PKCS11

#ضمن <sys/time.h>

#ضمن <sys/types.h>
#ضمن <sys/queue.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>

#ضمن <string.h>
#ضمن <dlfcn.h>

#اگر_تعریف_شده WITH_OPENSSL
#ضمن "openbsd-compat/openssl-compat.h"
#ضمن <openssl/bn.h>
#ضمن <openssl/ecdsa.h>
#ضمن <openssl/x509.h>
#ضمن <openssl/err.h>
#پایان_اگر

#تعریف_کن CRYPTOKI_COMPAT
#ضمن "pkcs11.h"

#تعریف_کن SSHKEY_داخلی
#ضمن "sshkey.h"

#ضمن "log.h"
#ضمن "misc.h"
#ضمن "sshbuf.h"
#ضمن "ssh-pkcs11.h"
#ضمن "digest.h"
#ضمن "xmalloc.h"
#ضمن "crypto_api.h"

بنية pkcs11_slotinfo {
	CK_TOKEN_INFO		token;
	CK_SESSION_HANDLE	session;
	صحيح			logged_درون;
};

بنية pkcs11_provider {
	حرف			*name;
	فراغ			*handle;
	CK_FUNCTION_LIST	*function_list;
	CK_INFO			info;
	CK_ULONG		nslots;
	CK_جایگاه_ID		*slotlist;
	بنية pkcs11_slotinfo	*slotinfo;
	صحيح			valid;
	صحيح			refcount;
	TAILQ_ENTRY(pkcs11_provider) بعدی;
};

TAILQ_HEAD(, pkcs11_provider) pkcs11_providers;

بنية pkcs11_کلید {
	بنية sshbuf		*keyblob;
	بنية pkcs11_provider	*provider;
	CK_ULONG		slotidx;
	حرف			*keyid;
	صحيح			keyid_len;
	TAILQ_ENTRY(pkcs11_کلید)	بعدی;
};

TAILQ_HEAD(, pkcs11_کلید) pkcs11_کلیدها; /* XXX a tree would be better */

صحيح pkcs11_interactive = 0;

#اگر_تعریف_شده WITH_OPENSSL
ساكن فراغ
ossl_error(ثابت حرف *پیام)
{
	بیعلامت دراز    e;

	error_f("%s", پیام);
	طالما ((e = ERR_get_error()) != 0)
		error_f("libcrypto error: %s", ERR_error_string(e, عدم));
}
#پایان_اگر

/*
 * finalize a provider shared library, it's no longer usable.
 * however, there might still be keys referencing this provider,
 * so the actual freeing of memory is handled by pkcs11_provider_unref().
 * this is called when a provider gets unregistered.
 */
ساكن فراغ
pkcs11_provider_finalize(بنية pkcs11_provider *p)
{
	CK_RV rv;
	CK_ULONG i;

	debug_f("provider \"%s\" refcount %d valid %d",
	    p->name, p->refcount, p->valid);
	إذا (!p->valid)
		أرجع;
	لكل (i = 0; i < p->nslots; i++) {
		إذا (p->slotinfo[i].session &&
		    (rv = p->function_list->C_CloseSession(
		    p->slotinfo[i].session)) != CKR_OK)
			error("C_CloseSession failed: %lu", rv);
	}
	إذا ((rv = p->function_list->C_Finalize(عدم)) != CKR_OK)
		error("C_Finalize failed: %lu", rv);
	p->valid = 0;
	p->function_list = عدم;
	dlclose(p->handle);
}

/*
 * remove a reference to the provider.
 * called when a key gets destroyed or when the provider is unregistered.
 */
ساكن فراغ
pkcs11_provider_unref(بنية pkcs11_provider *p)
{
	debug_f("provider \"%s\" refcount %d", p->name, p->refcount);
	إذا (--p->refcount <= 0) {
		إذا (p->valid)
			error_f("provider \"%s\" still valid", p->name);
		حرر(p->name);
		حرر(p->slotlist);
		حرر(p->slotinfo);
		حرر(p);
	}
}

/* lookup provider by name */
ساكن بنية pkcs11_provider *
pkcs11_provider_lookup(حرف *provider_id)
{
	بنية pkcs11_provider *p;

	TAILQ_FOREACH(p, &pkcs11_providers, بعدی) {
		debug("check provider \"%s\"", p->name);
		إذا (!strcmp(provider_id, p->name))
			أرجع (p);
	}
	أرجع (عدم);
}

/* unregister provider by name */
صحيح
pkcs11_del_provider(حرف *provider_id)
{
	بنية pkcs11_provider *p;

	إذا ((p = pkcs11_provider_lookup(provider_id)) != عدم) {
		TAILQ_REMOVE(&pkcs11_providers, p, بعدی);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
		أرجع (0);
	}
	أرجع (-1);
}

/* release a wrapped object */
ساكن فراغ
pkcs11_k11_free(بنية pkcs11_کلید *k11)
{
	إذا (k11 == عدم)
		أرجع;
	إذا (k11->provider)
		pkcs11_provider_unref(k11->provider);
	حرر(k11->keyid);
	sshbuf_free(k11->keyblob);
	حرر(k11);
}

/* find a single 'obj' for given attributes */
ساكن صحيح
pkcs11_پیدا_کن(بنية pkcs11_provider *p, CK_ULONG slotidx, CK_ATTRIBUTE *attr,
    CK_ULONG nattr, CK_OBJECT_HANDLE *obj)
{
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	session;
	CK_ULONG		nfound = 0;
	CK_RV			rv;
	صحيح			ret = -1;

	f = p->function_list;
	session = p->slotinfo[slotidx].session;
	إذا ((rv = f->C_پیدا_کن_Objects_Init(session, attr, nattr)) != CKR_OK) {
		error("C_FindObjectsInit failed (nattr %lu): %lu", nattr, rv);
		أرجع (-1);
	}
	إذا ((rv = f->C_پیدا_کن_Objects(session, obj, 1, &nfound)) != CKR_OK ||
	    nfound != 1) {
		debug("C_FindObjects failed (nfound %lu nattr %lu): %lu",
		    nfound, nattr, rv);
	} وإلا
		ret = 0;
	إذا ((rv = f->C_پیدا_کن_Objects_Final(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	أرجع (ret);
}

ساكن صحيح
pkcs11_login_جایگاه(بنية pkcs11_provider *provider, بنية pkcs11_slotinfo *si,
    CK_USER_TYPE type)
{
	حرف			*pin = عدم, prompt[1024];
	CK_RV			 rv;

	إذا (provider == عدم || si == عدم || !provider->valid) {
		error("no pkcs11 (valid) provider found");
		أرجع (-1);
	}

	إذا (!pkcs11_interactive) {
		error("need pin entry%s",
		    (si->token.flags & CKF_PROTECTED_AUTHENTICATION_مسیر) ?
		    " on reader keypad" : "");
		أرجع (-1);
	}
	إذا (si->token.flags & CKF_PROTECTED_AUTHENTICATION_مسیر)
		verbose("Deferring PIN entry to reader keypad.");
	وإلا {
		snprintf(prompt, حجم(prompt), "Enter PIN for '%s': ",
		    si->token.label);
		إذا ((pin = read_passphrase(prompt, RP_ALLOW_EOF)) == عدم) {
			debug_f("no pin specified");
			أرجع (-1);	/* bail out */
		}
	}
	rv = provider->function_list->C_Login(si->session, type, (u_char *)pin,
	    (pin != عدم) ? طول_رشته(pin) : 0);
	إذا (pin != عدم)
		freezero(pin, طول_رشته(pin));

	بدل (rv) {
	حالة CKR_OK:
	حالة CKR_USER_ALREADY_LOGGED_درون:
		/* success */
		اكسر;
	حالة CKR_PIN_LEN_RANGE:
		error("PKCS#11 login failed: PIN length out of range");
		أرجع -1;
	حالة CKR_PIN_INCORRECT:
		error("PKCS#11 login failed: PIN incorrect");
		أرجع -1;
	حالة CKR_PIN_LOCKED:
		error("PKCS#11 login failed: PIN locked");
		أرجع -1;
	افتراضي:
		error("PKCS#11 login failed: error %lu", rv);
		أرجع -1;
	}
	si->logged_درون = 1;
	أرجع (0);
}

ساكن صحيح
pkcs11_login(بنية pkcs11_کلید *k11, CK_USER_TYPE type)
{
	إذا (k11 == عدم || k11->provider == عدم || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		أرجع (-1);
	}

	أرجع pkcs11_login_جایگاه(k11->provider,
	    &k11->provider->slotinfo[k11->slotidx], type);
}


ساكن صحيح
pkcs11_check_obj_bool_attrib(بنية pkcs11_کلید *k11, CK_OBJECT_HANDLE obj,
    CK_ATTRIBUTE_TYPE type, صحيح *val)
{
	بنية pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_BBOOL		flag = 0;
	CK_ATTRIBUTE		attr;
	CK_RV			 rv;

	*val = 0;

	إذا (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		أرجع (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	attr.type = type;
	attr.p_مقدار = &flag;
	attr.ul_مقدار_Len = حجم(flag);

	rv = f->C_Get_Attribute_مقدار(si->session, obj, &attr, 1);
	إذا (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		أرجع (-1);
	}
	*val = flag != 0;
	debug_f("provider \"%s\" slot %lu object %lu: attrib %lu = %d",
	    k11->provider->name, k11->slotidx, obj, type, *val);
	أرجع (0);
}

ساكن صحيح
pkcs11_get_کلید(بنية pkcs11_کلید *k11, CK_MECHANISM_TYPE mech_type)
{
	بنية pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	 obj;
	CK_RV			 rv;
	CK_OBJECT_CLASS		 خصوصی_کلید_class;
	CK_BBOOL		 true_val;
	CK_MECHANISM		 mech;
	CK_ATTRIBUTE		 کلید_filter[3];
	صحيح			 always_auth = 0;
	صحيح			 did_login = 0;

	إذا (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		أرجع (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	إذا ((si->token.flags & CKF_LOGIN_REQUIRED) && !si->logged_درون) {
		إذا (pkcs11_login(k11, CKU_USER) < 0) {
			error("login failed");
			أرجع (-1);
		}
		did_login = 1;
	}

	memset(&کلید_filter, 0, حجم(کلید_filter));
	خصوصی_کلید_class = CKO_خصوصی_کلید;
	کلید_filter[0].type = CKA_CLASS;
	کلید_filter[0].p_مقدار = &خصوصی_کلید_class;
	کلید_filter[0].ul_مقدار_Len = حجم(خصوصی_کلید_class);

	کلید_filter[1].type = CKA_ID;
	کلید_filter[1].p_مقدار = k11->keyid;
	کلید_filter[1].ul_مقدار_Len = k11->keyid_len;

	true_val = CK_TRUE;
	کلید_filter[2].type = CKA_SIGN;
	کلید_filter[2].p_مقدار = &true_val;
	کلید_filter[2].ul_مقدار_Len = حجم(true_val);

	/* try to find object w/CKA_SIGN first, retry w/o */
	إذا (pkcs11_پیدا_کن(k11->provider, k11->slotidx, کلید_filter, 3, &obj) < 0 &&
	    pkcs11_پیدا_کن(k11->provider, k11->slotidx, کلید_filter, 2, &obj) < 0) {
		error("cannot find private key");
		أرجع (-1);
	}

	memset(&mech, 0, حجم(mech));
	mech.mechanism = mech_type;
	mech.pParameter = NULL_PTR;
	mech.ulParameterLen = 0;

	إذا ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
		أرجع (-1);
	}

	pkcs11_check_obj_bool_attrib(k11, obj, CKA_ALWAYS_AUTHENTICATE,
	    &always_auth); /* ignore errors here */
	إذا (always_auth && !did_login) {
		debug_f("always-auth key");
		إذا (pkcs11_login(k11, CKU_CONTEXT_SPECIFIC) < 0) {
			error("login failed for always-auth key");
			أرجع (-1);
		}
	}

	أرجع (0);
}

/* record the key information later use lookup by keyblob */
ساكن صحيح
pkcs11_رکورد_کلید(بنية pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, بنية sshkey *کلید)
{
	بنية sshbuf *keyblob;
	بنية pkcs11_کلید *k11;
	صحيح r;
	حرف *hex;

	hex = tohex(keyid_attrib->p_مقدار, keyid_attrib->ul_مقدار_Len);
	debug_f("%s key: provider %s slot %lu keyid %s",
	    sshkey_type(کلید), provider->name, (u_long)slotidx, hex);
	حرر(hex);

	إذا ((keyblob = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshkey_putb(کلید, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");

	/* Check if we've already recorded this key in a different slot */
	TAILQ_FOREACH(k11, &pkcs11_کلیدها, بعدی) {
		إذا (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			hex = tohex(k11->keyid, k11->keyid_len);
			debug_f("Already seen this key at "
			    "provider %s slot %lu keyid %s",
			    k11->provider->name, k11->slotidx, hex);
			حرر(hex);
			sshbuf_free(keyblob);
			أرجع -1;
		}
	}

	k11 = xcalloc(1, حجم(*k11));
	k11->provider = provider;
	k11->keyblob = keyblob;
	provider->refcount++;	/* provider referenced by RSA key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ul_مقدار_Len;
	إذا (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len);
		کپی_حافظه(k11->keyid, keyid_attrib->p_مقدار, k11->keyid_len);
	}
	TAILQ_INSERT_TAIL(&pkcs11_کلیدها, k11, بعدی);

	أرجع 0;
}

/* retrieve the key information by keyblob */
ساكن بنية pkcs11_کلید *
pkcs11_lookup_کلید(بنية sshkey *کلید)
{
	بنية pkcs11_کلید *k11, *یافت = عدم;
	بنية sshbuf *keyblob;
	صحيح r;

	إذا ((keyblob = sshbuf_new()) == عدم)
		fatal_f("sshbuf_new failed");
	إذا ((r = sshkey_putb(کلید, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");
	TAILQ_FOREACH(k11, &pkcs11_کلیدها, بعدی) {
		إذا (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			یافت = k11;
			اكسر;
		}
	}
	sshbuf_free(keyblob);
	أرجع یافت;
}

#اگر_تعریف_شده WITH_OPENSSL
/*
 * See:
 * https://datatracker.ietf.org/doc/html/rfc8017#section-9.2
 */

/*
 * id-sha1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
 *	oiw(14) secsig(3) algorithms(2) 26 }
 */
ساكن ثابت u_char id_sha1[] = {
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
ساكن ثابت u_char id_sha256[] = {
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
ساكن ثابت u_char id_sha512[] = {
	0x30, 0x51, /* type Sequence, length 0x51 (81) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, /* id-sha512 */
	0x05, 0x00, /* NULL */
	0x04, 0x40  /* Octet string, length 0x40 (64), followed by sha512 hash */
};

ساكن صحيح
rsa_hash_alg_oid(صحيح hash_alg, ثابت u_char **oidp, اندازه_t *oidlenp)
{
	بدل (hash_alg) {
	حالة SSH_DIGEST_SHA1:
		*oidp = id_sha1;
		*oidlenp = حجم(id_sha1);
		اكسر;
	حالة SSH_DIGEST_SHA256:
		*oidp = id_sha256;
		*oidlenp = حجم(id_sha256);
		اكسر;
	حالة SSH_DIGEST_SHA512:
		*oidp = id_sha512;
		*oidlenp = حجم(id_sha512);
		اكسر;
	افتراضي:
		أرجع SSH_ERR_INVALID_آرگومان;
	}
	أرجع 0;
}

ساكن صحيح
pkcs11_sign_rsa(بنية sshkey *کلید,
    u_char **sigp, اندازه_t *lenp,
    ثابت u_char *داده, اندازه_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider,
    ثابت حرف *sk_pin, u_int compat)
{
	بنية pkcs11_کلید	*k11;
	بنية pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	صحيح			hashalg, r, diff, siglen, ret = -1;
	u_char			*oid_dgst = عدم, *sig = عدم;
	اندازه_t			dgst_len, oid_len, oid_dgst_len = 0;
	ثابت u_char		*oid;

	إذا (sigp != عدم)
		*sigp = عدم;
	إذا (lenp != عدم)
		*lenp = 0;

	إذا ((k11 = pkcs11_lookup_کلید(کلید)) == عدم) {
		error_f("no key found");
		أرجع SSH_ERR_کلید_NOT_یافت;
	}

	debug3_f("sign with alg \"%s\" using provider %s slotidx %lu",
	    alg == عدم ? "" : alg, k11->provider->name, (u_long)k11->slotidx);

	إذا (pkcs11_get_کلید(k11, CKM_RSA_PKCS) == -1) {
		error("pkcs11_get_key failed");
		أرجع SSH_ERR_AGENT_FAILURE;
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	إذا ((siglen = EVP_PKEY_اندازه(کلید->pkey)) <= 0)
		أرجع SSH_ERR_INVALID_آرگومان;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* Determine hash algorithm and OID for signature */
	إذا (alg == عدم || *alg == '\0')
		hashalg = SSH_DIGEST_SHA1;
	وإلا إذا ((hashalg = ssh_rsa_hash_id_from_keyname(alg)) == -1)
		fatal_f("couldn't determine RSA hash alg \"%s\"", alg);
	إذا ((r = rsa_hash_alg_oid(hashalg, &oid, &oid_len)) != 0)
		fatal_fr(r, "rsa_hash_alg_oid failed");
	إذا ((dgst_len = ssh_digest_بایتها(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);

	/* Prepare { oid || digest } */
	oid_dgst_len = oid_len + dgst_len;
	oid_dgst = xcalloc(1, oid_dgst_len);
	کپی_حافظه(oid_dgst, oid, oid_len);
	إذا ((r = ssh_digest_حافظه(hashalg, داده, datalen,
	    oid_dgst + oid_len, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	إذا ((rv = f->C_Sign(si->session, (CK_BYTE *)oid_dgst,
	    oid_dgst_len, sig, &slen)) != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		اذهب انجامشده;
	}

	إذا (slen < (CK_ULONG)siglen) {
		diff = siglen - slen;
		debug3_f("repack %lu < %d (diff %d)",
		    (u_long)slen, siglen, diff);
		memmove(sig + diff, sig, slen);
		explicit_bzero(sig, diff);
	} وإلا إذا (slen > (اندازه_t)siglen)
		fatal_f("bad C_Sign length");

	إذا ((ret = ssh_rsa_encode_store_sig(hashalg, sig, siglen,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 انجامشده:
	freezero(oid_dgst, oid_dgst_len);
	حرر(sig);
	أرجع ret;
}

ساكن صحيح
pkcs11_sign_ecdsa(بنية sshkey *کلید,
    u_char **sigp, اندازه_t *lenp,
    ثابت u_char *داده, اندازه_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider,
    ثابت حرف *sk_pin, u_int compat)
{
	بنية pkcs11_کلید	*k11;
	بنية pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0, bnlen;
	CK_RV			rv;
	BIGNUM			*sig_r = عدم, *sig_s = عدم;
	u_char			*sig = عدم, *dgst = عدم;
	اندازه_t			dgst_len = 0;
	صحيح			hashalg, ret = -1, r, siglen;

	إذا (sigp != عدم)
		*sigp = عدم;
	إذا (lenp != عدم)
		*lenp = 0;

	إذا ((k11 = pkcs11_lookup_کلید(کلید)) == عدم) {
		error_f("no key found");
		أرجع SSH_ERR_کلید_NOT_یافت;
	}

	إذا (pkcs11_get_کلید(k11, CKM_ECDSA) == -1) {
		error("pkcs11_get_key failed");
		أرجع SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	/* Prepare digest to be signed */
	إذا ((hashalg = sshkey_ec_nid_مقصد_hash_alg(کلید->ecdsa_nid)) == -1)
		fatal_f("couldn't determine ECDSA hash alg");
	إذا ((dgst_len = ssh_digest_بایتها(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);
	dgst = xcalloc(1, dgst_len);
	إذا ((r = ssh_digest_حافظه(hashalg, داده, datalen,
	    dgst, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	إذا ((siglen = EVP_PKEY_اندازه(کلید->pkey)) <= 0)
		أرجع SSH_ERR_INVALID_آرگومان;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dgst_len, sig, &slen);
	إذا (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		اذهب انجامشده;
	}
	إذا (slen < 64 || slen > 132 || slen % 2) {
		error_f("bad signature length: %lu", (u_long)slen);
		اذهب انجامشده;
	}
	bnlen = slen/2;
	إذا ((sig_r = BN_bin2bn(sig, bnlen, عدم)) == عدم ||
	    (sig_s = BN_bin2bn(sig+bnlen, bnlen, عدم)) == عدم) {
		ossl_error("BN_bin2bn failed");
		اذهب انجامشده;
	}

	إذا ((ret = ssh_ecdsa_encode_store_sig(کلید, sig_r, sig_s,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 انجامشده:
	freezero(dgst, dgst_len);
	BN_free(sig_r);
	BN_free(sig_s);
	حرر(sig);
	أرجع ret;
}
#پایان_اگر /* WITH_OPENSSL */

ساكن صحيح
pkcs11_sign_ed25519(بنية sshkey *کلید,
    u_char **sigp, اندازه_t *lenp,
    ثابت u_char *داده, اندازه_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider,
    ثابت حرف *sk_pin, u_int compat)
{
	بنية pkcs11_کلید	*k11;
	بنية pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	u_char			*sig = عدم;
	CK_BYTE			*xdata = عدم;
	صحيح			ret = -1;

	إذا (sigp != عدم)
		*sigp = عدم;
	إذا (lenp != عدم)
		*lenp = 0;

	إذا ((k11 = pkcs11_lookup_کلید(کلید)) == عدم) {
		error_f("no key found");
		أرجع SSH_ERR_کلید_NOT_یافت;
	}

	إذا (pkcs11_get_کلید(k11, CKM_EDDSA) == -1) {
		error("pkcs11_get_key failed");
		أرجع SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	xdata = xmalloc(datalen);
	کپی_حافظه(xdata, داده, datalen);
	sig = xmalloc(crypto_sign_ed25519_بایتها);
	slen = crypto_sign_ed25519_بایتها;

	rv = f->C_Sign(si->session, xdata, datalen, sig, &slen);
	إذا (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		اذهب انجامشده;
	}
	إذا (slen != crypto_sign_ed25519_بایتها) {
		error_f("bad signature length: %lu", (u_long)slen);
		اذهب انجامشده;
	}
	إذا ((ret = ssh_ed25519_encode_store_sig(sig, slen, sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 انجامشده:
	إذا (xdata != عدم)
		freezero(xdata, datalen);
	حرر(sig);
	أرجع ret;
}

/* remove trailing spaces */
ساكن حرف *
rmspace(u_char *buf, اندازه_t len)
{
	اندازه_t i;

	إذا (len == 0)
		أرجع buf;
	لكل (i = len - 1; i > 0; i--)
		إذا (buf[i] == ' ')
			buf[i] = '\0';
		وإلا
			اكسر;
	أرجع buf;
}
/* Used to printf fixed-width, space-padded, unterminated strings using %.*s */
#تعریف_کن RMSPACE(s) (صحيح)حجم(s), rmspace(s, حجم(s))

/*
 * open a pkcs11 session and login if required.
 * if pin == NULL we delay login until key use
 */
ساكن صحيح
pkcs11_open_session(بنية pkcs11_provider *p, CK_ULONG slotidx, حرف *pin,
    CK_ULONG user)
{
	بنية pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_RV			rv;
	CK_SESSION_HANDLE	session;
	صحيح			login_required, ret;

	f = p->function_list;
	si = &p->slotinfo[slotidx];

	login_required = si->token.flags & CKF_LOGIN_REQUIRED;

	/* fail early before opening session */
	إذا (login_required && !pkcs11_interactive &&
	    (pin == عدم || طول_رشته(pin) == 0)) {
		error("pin required");
		أرجع (-SSH_PKCS11_ERR_PIN_REQUIRED);
	}
	إذا ((rv = f->C_OpenSession(p->slotlist[slotidx], CKF_RW_SESSION|
	    CKF_SERIAL_SESSION, عدم, عدم, &session)) != CKR_OK) {
		error("C_OpenSession failed: %lu", rv);
		أرجع (-1);
	}
	إذا (login_required && pin != عدم && طول_رشته(pin) != 0) {
		rv = f->C_Login(session, user, (u_char *)pin, طول_رشته(pin));
		إذا (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_درون) {
			error("C_Login failed: %lu", rv);
			ret = (rv == CKR_PIN_LOCKED) ?
			    -SSH_PKCS11_ERR_PIN_LOCKED :
			    -SSH_PKCS11_ERR_LOGIN_FAIL;
			إذا ((rv = f->C_CloseSession(session)) != CKR_OK)
				error("C_CloseSession failed: %lu", rv);
			أرجع (ret);
		}
		si->logged_درون = 1;
	}
	si->session = session;
	أرجع (0);
}

ساكن صحيح
pkcs11_کلید_included(بنية sshkey ***keysp, صحيح *nkeys, بنية sshkey *کلید)
{
	صحيح i;

	لكل (i = 0; i < *nkeys; i++)
		إذا (sshkey_equal(کلید, (*keysp)[i]))
			أرجع (1);
	أرجع (0);
}

#اگر_تعریف_شده WITH_OPENSSL
ساكن بنية sshkey *
pkcs11_fetch_ecdsa_pubkey(بنية pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 کلید_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = عدم;
	CK_RV			 rv;
	ASN1_OCTET_STRING	*octet = عدم;
	EC_کلید			*ec = عدم;
	EC_گروه		*گروه = عدم;
	بنية sshkey		*کلید = عدم;
	ثابت بیعلامت حرف	*attrp = عدم;
	صحيح			 success = -1, r, i, nid;

	memset(&کلید_attr, 0, حجم(کلید_attr));
	کلید_attr[0].type = CKA_ID;
	کلید_attr[1].type = CKA_EC_نقطه;
	کلید_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_مقدار(session, *obj, کلید_attr, 3);
	إذا (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		أرجع (عدم);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	إذا (کلید_attr[1].ul_مقدار_Len == 0 ||
	    کلید_attr[2].ul_مقدار_Len == 0) {
		error("invalid attribute length");
		أرجع (عدم);
	}

	/* allocate buffers for attributes */
	لكل (i = 0; i < 3; i++)
		إذا (کلید_attr[i].ul_مقدار_Len > 0)
			کلید_attr[i].p_مقدار = xcalloc(1, کلید_attr[i].ul_مقدار_Len);

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_مقدار(session, *obj, کلید_attr, 3);
	إذا (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		اذهب fail;
	}

	ec = EC_کلید_new();
	إذا (ec == عدم) {
		error("EC_KEY_new failed");
		اذهب fail;
	}

	attrp = کلید_attr[2].p_مقدار;
	گروه = d2i_ECPKParameters(عدم, &attrp, کلید_attr[2].ul_مقدار_Len);
	إذا (گروه == عدم) {
		ossl_error("d2i_ECPKParameters failed");
		اذهب fail;
	}

	إذا (EC_کلید_مجموعه_گروه(ec, گروه) == 0) {
		ossl_error("EC_KEY_set_group failed");
		اذهب fail;
	}

	إذا (کلید_attr[1].ul_مقدار_Len <= 2) {
		error("CKA_EC_POINT too small");
		اذهب fail;
	}

	attrp = کلید_attr[1].p_مقدار;
	octet = d2i_ASN1_OCTET_STRING(عدم, &attrp, کلید_attr[1].ul_مقدار_Len);
	إذا (octet == عدم) {
		ossl_error("d2i_ASN1_OCTET_STRING failed");
		اذهب fail;
	}
	attrp = ASN1_STRING_get0_داده(octet);
	إذا (o2i_ECPublic_کلید(&ec, &attrp, ASN1_STRING_درازی(octet)) == عدم) {
		ossl_error("o2i_ECPublicKey failed");
		اذهب fail;
	}
	إذا ((r = sshkey_ec_validate_عمومی(EC_کلید_get0_گروه(ec),
	    EC_کلید_get0_عمومی_کلید(ec))) != 0) {
		error_fr(r, "invalid EC key");
		اذهب fail;
	}

	nid = sshkey_ecdsa_کلید_مقصد_nid(ec);
	إذا (nid < 0) {
		error("couldn't get curve nid");
		اذهب fail;
	}

	کلید = sshkey_new(کلید_UNSPEC);
	إذا (کلید == عدم) {
		error("sshkey_new failed");
		اذهب fail;
	}

	EVP_PKEY_free(کلید->pkey);
	إذا ((کلید->pkey = EVP_PKEY_new()) == عدم)
		fatal("EVP_PKEY_new failed");
	إذا (EVP_PKEY_set1_EC_کلید(کلید->pkey, ec) != 1)
		fatal("EVP_PKEY_set1_EC_KEY failed");
	کلید->ecdsa_nid = nid;
	کلید->type = کلید_ECDSA;
	کلید->flags |= SSHKEY_FLAG_EXT;
	إذا (pkcs11_رکورد_کلید(p, slotidx, &کلید_attr[0], کلید))
		اذهب fail;
	/* success */
	success = 0;
fail:
	إذا (success != 0) {
		sshkey_free(کلید);
		کلید = عدم;
	}
	لكل (i = 0; i < 3; i++)
		حرر(کلید_attr[i].p_مقدار);
	إذا (ec)
		EC_کلید_free(ec);
	إذا (گروه)
		EC_گروه_free(گروه);
	إذا (octet)
		ASN1_OCTET_STRING_free(octet);

	أرجع (کلید);
}

ساكن بنية sshkey *
pkcs11_fetch_rsa_pubkey(بنية pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 کلید_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = عدم;
	CK_RV			 rv;
	RSA			*rsa = عدم;
	BIGNUM			*rsa_n, *rsa_e;
	بنية sshkey		*کلید = عدم;
	صحيح			 i, success = -1;

	memset(&کلید_attr, 0, حجم(کلید_attr));
	کلید_attr[0].type = CKA_ID;
	کلید_attr[1].type = CKA_MODULUS;
	کلید_attr[2].type = CKA_عمومی_EXPONENT;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_مقدار(session, *obj, کلید_attr, 3);
	إذا (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		أرجع (عدم);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	إذا (کلید_attr[1].ul_مقدار_Len == 0 ||
	    کلید_attr[2].ul_مقدار_Len == 0) {
		error("invalid attribute length");
		أرجع (عدم);
	}

	/* allocate buffers for attributes */
	لكل (i = 0; i < 3; i++)
		إذا (کلید_attr[i].ul_مقدار_Len > 0)
			کلید_attr[i].p_مقدار = xcalloc(1, کلید_attr[i].ul_مقدار_Len);

	/* retrieve ID, modulus and public exponent of RSA key */
	rv = f->C_Get_Attribute_مقدار(session, *obj, کلید_attr, 3);
	إذا (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		اذهب fail;
	}

	rsa = RSA_new();
	إذا (rsa == عدم) {
		error("RSA_new failed");
		اذهب fail;
	}

	rsa_n = BN_bin2bn(کلید_attr[1].p_مقدار, کلید_attr[1].ul_مقدار_Len, عدم);
	rsa_e = BN_bin2bn(کلید_attr[2].p_مقدار, کلید_attr[2].ul_مقدار_Len, عدم);
	إذا (rsa_n == عدم || rsa_e == عدم) {
		error("BN_bin2bn failed");
		اذهب fail;
	}
	إذا (!RSA_set0_کلید(rsa, rsa_n, rsa_e, عدم))
		fatal_f("set key");
	rsa_n = rsa_e = عدم; /* transferred */

	کلید = sshkey_new(کلید_UNSPEC);
	إذا (کلید == عدم) {
		error("sshkey_new failed");
		اذهب fail;
	}

	EVP_PKEY_free(کلید->pkey);
	إذا ((کلید->pkey = EVP_PKEY_new()) == عدم)
		fatal("EVP_PKEY_new failed");
	إذا (EVP_PKEY_set1_RSA(کلید->pkey, rsa) != 1)
		fatal("EVP_PKEY_set1_RSA failed");
	کلید->type = کلید_RSA;
	کلید->flags |= SSHKEY_FLAG_EXT;
	إذا (EVP_PKEY_بیتها(کلید->pkey) < SSH_RSA_MINIMUM_MODULUS_اندازه) {
		error_f("RSA key too small %d < minimum %d",
		    EVP_PKEY_بیتها(کلید->pkey), SSH_RSA_MINIMUM_MODULUS_اندازه);
		اذهب fail;
	}
	إذا (pkcs11_رکورد_کلید(p, slotidx, &کلید_attr[0], کلید))
		اذهب fail;
	/* success */
	success = 0;
fail:
	لكل (i = 0; i < 3; i++)
		حرر(کلید_attr[i].p_مقدار);
	RSA_free(rsa);
	إذا (success != 0) {
		sshkey_free(کلید);
		کلید = عدم;
	}
	أرجع کلید;
}
#پایان_اگر /* WITH_OPENSSL */

ساكن بنية sshkey *
pkcs11_fetch_ed25519_pubkey(بنية pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 کلید_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = عدم;
	CK_RV			 rv;
	بنية sshkey		*کلید = عدم;
	ثابت بیعلامت حرف	*d = عدم;
	اندازه_t			len;
	حرف			*hex = عدم;
	صحيح			 success = -1, i;
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
	کلید_attr[1].type = CKA_EC_نقطه; /* XXX or CKA_VALUE ? */
	کلید_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_مقدار(session, *obj, کلید_attr, 3);
	إذا (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		أرجع (عدم);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	إذا (کلید_attr[1].ul_مقدار_Len == 0 ||
	    کلید_attr[2].ul_مقدار_Len == 0) {
		error("invalid attribute length");
		أرجع (عدم);
	}

	/* allocate buffers for attributes */
	لكل (i = 0; i < 3; i++) {
		إذا (کلید_attr[i].ul_مقدار_Len > 0)
			کلید_attr[i].p_مقدار = xcalloc(1, کلید_attr[i].ul_مقدار_Len);
	}

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_مقدار(session, *obj, کلید_attr, 3);
	إذا (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		اذهب fail;
	}

	/* Expect one of the supported identifiers in CKA_EC_PARAMS */
	d = (u_char *)کلید_attr[2].p_مقدار;
	len = کلید_attr[2].ul_مقدار_Len;
	إذا ((len != حجم(id1) || memcmp(d, id1, حجم(id1)) != 0) &&
	    (len != حجم(id2) || memcmp(d, id2, حجم(id2)) != 0)) {
		hex = tohex(d, len);
		logit_f("unsupported CKA_EC_PARAMS: %s (len %zu)", hex, len);
		اذهب fail;
	}

	/*
	 * Expect either a raw 32 byte pubkey or an OCTET STRING with
	 * a 32 byte pubkey in CKA_VALUE
	 */
	d = (u_char *)کلید_attr[1].p_مقدار;
	len = کلید_attr[1].ul_مقدار_Len;
	إذا (len == ED25519_PK_SZ + 2 && d[0] == 0x04 && d[1] == ED25519_PK_SZ) {
		d += 2;
		len -= 2;
	}
	إذا (len != ED25519_PK_SZ) {
		hex = tohex(کلید_attr[1].p_مقدار, کلید_attr[1].ul_مقدار_Len);
		logit_f("CKA_EC_POINT invalid octet str: %s (len %lu)",
		    hex, (u_long)کلید_attr[1].ul_مقدار_Len);
		اذهب fail;
	}

	إذا ((کلید = sshkey_new(کلید_UNSPEC)) == عدم)
		fatal_f("sshkey_new failed");
	کلید->ed25519_pk = xmalloc(ED25519_PK_SZ);
	کپی_حافظه(کلید->ed25519_pk, d, ED25519_PK_SZ);
	کلید->type = کلید_ED25519;
	کلید->flags |= SSHKEY_FLAG_EXT;
	إذا (pkcs11_رکورد_کلید(p, slotidx, &کلید_attr[0], کلید))
		اذهب fail;
	/* success */
	success = 0;
 fail:
	إذا (success != 0) {
		sshkey_free(کلید);
		کلید = عدم;
	}
	حرر(hex);
	لكل (i = 0; i < 3; i++)
		حرر(کلید_attr[i].p_مقدار);
	أرجع کلید;
}

#اگر_تعریف_شده WITH_OPENSSL
ساكن صحيح
pkcs11_fetch_x509_pubkey(بنية pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj, بنية sshkey **keyp, حرف **labelp)
{
	CK_ATTRIBUTE		 cert_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = عدم;
	CK_RV			 rv;
	X509			*x509 = عدم;
	X509_NAME		*x509_name = عدم;
	EVP_PKEY		*evp;
	RSA			*rsa = عدم;
	EC_کلید			*ec = عدم;
	بنية sshkey		*کلید = عدم;
	صحيح			 r, i, nid, success = -1;
	ثابت u_char		*cp;
	حرف			*subject = عدم;
#اگر_تعریف_شده OPENSSL_HAS_ED25519
	اندازه_t			len;
#پایان_اگر /* OPENSSL_HAS_ED25519 */

	*keyp = عدم;
	*labelp = عدم;

	memset(&cert_attr, 0, حجم(cert_attr));
	cert_attr[0].type = CKA_ID;
	cert_attr[1].type = CKA_SUBJECT;
	cert_attr[2].type = CKA_مقدار;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_مقدار(session, *obj, cert_attr, 3);
	إذا (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		أرجع -1;
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	إذا (cert_attr[1].ul_مقدار_Len == 0 ||
	    cert_attr[2].ul_مقدار_Len == 0) {
		error("invalid attribute length");
		أرجع -1;
	}

	/* allocate buffers for attributes */
	لكل (i = 0; i < 3; i++)
		إذا (cert_attr[i].ul_مقدار_Len > 0)
			cert_attr[i].p_مقدار = xcalloc(1, cert_attr[i].ul_مقدار_Len);

	/* retrieve ID, subject and value of certificate */
	rv = f->C_Get_Attribute_مقدار(session, *obj, cert_attr, 3);
	إذا (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		اذهب بیرون;
	}

	/* Decode DER-encoded cert subject */
	cp = cert_attr[1].p_مقدار;
	إذا ((x509_name = d2i_X509_NAME(عدم, &cp,
	    cert_attr[1].ul_مقدار_Len)) == عدم ||
	    (subject = X509_NAME_oneline(x509_name, عدم, 0)) == عدم)
		subject = xstrdup("invalid subject");
	X509_NAME_free(x509_name);

	cp = cert_attr[2].p_مقدار;
	إذا ((x509 = d2i_X509(عدم, &cp, cert_attr[2].ul_مقدار_Len)) == عدم) {
		error("d2i_x509 failed");
		اذهب بیرون;
	}

	إذا ((evp = X509_get_pubkey(x509)) == عدم) {
		error("X509_get_pubkey failed");
		اذهب بیرون;
	}

	إذا (EVP_PKEY_پایه_id(evp) == EVP_PKEY_RSA) {
		إذا (EVP_PKEY_get0_RSA(evp) == عدم) {
			error("invalid x509; no rsa key");
			اذهب بیرون;
		}
		إذا ((rsa = RSAPublic_کلید_dup(EVP_PKEY_get0_RSA(evp))) == عدم) {
			error("RSAPublicKey_dup failed");
			اذهب بیرون;
		}

		کلید = sshkey_new(کلید_UNSPEC);
		إذا (کلید == عدم) {
			error("sshkey_new failed");
			اذهب بیرون;
		}

		EVP_PKEY_free(کلید->pkey);
		إذا ((کلید->pkey = EVP_PKEY_new()) == عدم)
			fatal("EVP_PKEY_new failed");
		إذا (EVP_PKEY_set1_RSA(کلید->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		کلید->type = کلید_RSA;
		کلید->flags |= SSHKEY_FLAG_EXT;
		إذا (EVP_PKEY_بیتها(کلید->pkey) < SSH_RSA_MINIMUM_MODULUS_اندازه) {
			error_f("RSA key too small %d < minimum %d",
			    EVP_PKEY_بیتها(کلید->pkey),
			    SSH_RSA_MINIMUM_MODULUS_اندازه);
			اذهب بیرون;
		}
		إذا (pkcs11_رکورد_کلید(p, slotidx, &cert_attr[0], کلید))
			اذهب بیرون;
		/* success */
		success = 0;
	} وإلا إذا (EVP_PKEY_پایه_id(evp) == EVP_PKEY_EC) {
		إذا (EVP_PKEY_get0_EC_کلید(evp) == عدم) {
			error("invalid x509; no ec key");
			اذهب بیرون;
		}
		إذا ((ec = EC_کلید_dup(EVP_PKEY_get0_EC_کلید(evp))) == عدم) {
			error("EC_KEY_dup failed");
			اذهب بیرون;
		}
		إذا ((r = sshkey_ec_validate_عمومی(EC_کلید_get0_گروه(ec),
		    EC_کلید_get0_عمومی_کلید(ec))) != 0) {
			error_fr(r, "invalid EC key");
			اذهب بیرون;
		}
		nid = sshkey_ecdsa_کلید_مقصد_nid(ec);
		إذا (nid < 0) {
			error("couldn't get curve nid");
			اذهب بیرون;
		}

		کلید = sshkey_new(کلید_UNSPEC);
		إذا (کلید == عدم) {
			error("sshkey_new failed");
			اذهب بیرون;
		}

		EVP_PKEY_free(کلید->pkey);
		إذا ((کلید->pkey = EVP_PKEY_new()) == عدم)
			fatal("EVP_PKEY_new failed");
		إذا (EVP_PKEY_set1_EC_کلید(کلید->pkey, ec) != 1)
			fatal("EVP_PKEY_set1_EC_KEY failed");
		کلید->ecdsa_nid = nid;
		کلید->type = کلید_ECDSA;
		کلید->flags |= SSHKEY_FLAG_EXT;
		إذا (pkcs11_رکورد_کلید(p, slotidx, &cert_attr[0], کلید))
			اذهب بیرون;
		/* success */
		success = 0;
#اگر_تعریف_شده OPENSSL_HAS_ED25519
	} وإلا إذا (EVP_PKEY_پایه_id(evp) == EVP_PKEY_ED25519) {
		إذا ((کلید = sshkey_new(کلید_UNSPEC)) == عدم ||
		    (کلید->ed25519_pk = حافظه_صفر_بده(1, ED25519_PK_SZ)) == عدم)
			fatal_f("allocation failed");
		len = ED25519_PK_SZ;
		إذا (!EVP_PKEY_get_raw_عمومی_کلید(evp, کلید->ed25519_pk, &len)) {
			ossl_error("EVP_PKEY_get_raw_public_key failed");
			اذهب بیرون;
		}
		إذا (len != ED25519_PK_SZ) {
			error_f("incorrect returned public key "
			    "length for ed25519");
			اذهب بیرون;
		}
		کلید->type = کلید_ED25519;
		کلید->flags |= SSHKEY_FLAG_EXT;
		إذا (pkcs11_رکورد_کلید(p, slotidx, &cert_attr[0], کلید))
			اذهب بیرون;
		/* success */
		success = 0;
#پایان_اگر /* OPENSSL_HAS_ED25519 */
	} وإلا {
		error("unknown certificate key type");
		اذهب بیرون;
	}
 بیرون:
	لكل (i = 0; i < 3; i++)
		حرر(cert_attr[i].p_مقدار);
	X509_free(x509);
	RSA_free(rsa);
	EC_کلید_free(ec);
	إذا (success != 0 || کلید == عدم) {
		sshkey_free(کلید);
		حرر(subject);
		أرجع -1;
	}
	/* success */
	*keyp = کلید;
	*labelp = subject;
	أرجع 0;
}
#پایان_اگر /* WITH_OPENSSL */

ساكن فراغ
note_کلید(بنية pkcs11_provider *p, CK_ULONG slotidx, ثابت حرف *context,
    بنية sshkey *کلید)
{
	حرف *fp;

	إذا ((fp = sshkey_fingerprint(کلید, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == عدم) {
		error_f("sshkey_fingerprint failed");
		أرجع;
	}
	debug2("%s: provider %s slot %lu: %s %s", context, p->name,
	    (u_long)slotidx, sshkey_type(کلید), fp);
	حرر(fp);
}

#اگر_تعریف_شده WITH_OPENSSL /* libcrypto needed for certificate parsing */
/*
 * lookup certificates for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
ساكن صحيح
pkcs11_fetch_certs(بنية pkcs11_provider *p, CK_ULONG slotidx,
    بنية sshkey ***keysp, حرف ***labelsp, صحيح *nkeys)
{
	بنية sshkey		*کلید = عدم;
	CK_OBJECT_CLASS		 کلید_class;
	CK_ATTRIBUTE		 کلید_attr[1];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = عدم;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	صحيح			 ret = -1;
	حرف			*label;

	memset(&کلید_attr, 0, حجم(کلید_attr));
	memset(&obj, 0, حجم(obj));

	کلید_class = CKO_CERTIFICATE;
	کلید_attr[0].type = CKA_CLASS;
	کلید_attr[0].p_مقدار = &کلید_class;
	کلید_attr[0].ul_مقدار_Len = حجم(کلید_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_پیدا_کن_Objects_Init(session, کلید_attr, 1);
	إذا (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		اذهب fail;
	}

	طالما (1) {
		CK_CERTIFICATE_TYPE	ck_cert_type;

		rv = f->C_پیدا_کن_Objects(session, &obj, 1, &n);
		إذا (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			اذهب fail;
		}
		إذا (n == 0)
			اكسر;

		memset(&ck_cert_type, 0, حجم(ck_cert_type));
		memset(&کلید_attr, 0, حجم(کلید_attr));
		کلید_attr[0].type = CKA_CERTIFICATE_TYPE;
		کلید_attr[0].p_مقدار = &ck_cert_type;
		کلید_attr[0].ul_مقدار_Len = حجم(ck_cert_type);

		rv = f->C_Get_Attribute_مقدار(session, obj, کلید_attr, 1);
		إذا (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			اذهب fail;
		}

		کلید = عدم;
		label = عدم;
		بدل (ck_cert_type) {
		حالة CKC_X_509:
			إذا (pkcs11_fetch_x509_pubkey(p, slotidx, &obj,
			    &کلید, &label) != 0) {
				debug_f("failed to fetch key");
				استمر;
			}
			اكسر;
		افتراضي:
			error("skipping unsupported certificate type %lu",
			    ck_cert_type);
			استمر;
		}
		note_کلید(p, slotidx, __func__, کلید);
		إذا (pkcs11_کلید_included(keysp, nkeys, کلید)) {
			debug2_f("key already included");
			sshkey_free(کلید);
		} وإلا {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, حجم(بنية sshkey *));
			(*keysp)[*nkeys] = کلید;
			إذا (labelsp != عدم) {
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
	rv = f->C_پیدا_کن_Objects_Final(session);
	إذا (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	أرجع (ret);
}
#پایان_اگر /* WITH_OPENSSL */

/*
 * lookup public keys for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
ساكن صحيح
pkcs11_fetch_کلیدها(بنية pkcs11_provider *p, CK_ULONG slotidx,
    بنية sshkey ***keysp, حرف ***labelsp, صحيح *nkeys)
{
	بنية sshkey		*کلید = عدم;
	CK_OBJECT_CLASS		 کلید_class;
	CK_ATTRIBUTE		 کلید_attr[2];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = عدم;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	صحيح			 ret = -1;

	memset(&کلید_attr, 0, حجم(کلید_attr));
	memset(&obj, 0, حجم(obj));

	کلید_class = CKO_عمومی_کلید;
	کلید_attr[0].type = CKA_CLASS;
	کلید_attr[0].p_مقدار = &کلید_class;
	کلید_attr[0].ul_مقدار_Len = حجم(کلید_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_پیدا_کن_Objects_Init(session, کلید_attr, 1);
	إذا (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		اذهب fail;
	}

	طالما (1) {
		CK_کلید_TYPE	ck_کلید_type;
		CK_UTF8CHAR	label[256];

		rv = f->C_پیدا_کن_Objects(session, &obj, 1, &n);
		إذا (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			اذهب fail;
		}
		إذا (n == 0)
			اكسر;

		memset(&ck_کلید_type, 0, حجم(ck_کلید_type));
		memset(&کلید_attr, 0, حجم(کلید_attr));
		کلید_attr[0].type = CKA_کلید_TYPE;
		کلید_attr[0].p_مقدار = &ck_کلید_type;
		کلید_attr[0].ul_مقدار_Len = حجم(ck_کلید_type);
		کلید_attr[1].type = CKA_LABEL;
		کلید_attr[1].p_مقدار = &label;
		کلید_attr[1].ul_مقدار_Len = حجم(label) - 1;

		rv = f->C_Get_Attribute_مقدار(session, obj, کلید_attr, 2);
		إذا (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			اذهب fail;
		}

		label[کلید_attr[1].ul_مقدار_Len] = '\0';

		بدل (ck_کلید_type) {
#اگر_تعریف_شده WITH_OPENSSL
		حالة CKK_RSA:
			کلید = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			اكسر;
		حالة CKK_ECDSA:
			کلید = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			اكسر;
#پایان_اگر /* WITH_OPENSSL */
		حالة CKK_EC_EDWARDS:
			کلید = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			اكسر;
		افتراضي:
			/* XXX print key type? */
			کلید = عدم;
			error("skipping unsupported key type 0x%lx",
			    (u_long)ck_کلید_type);
		}

		إذا (کلید == عدم) {
			debug_f("failed to fetch key");
			استمر;
		}
		note_کلید(p, slotidx, __func__, کلید);
		إذا (pkcs11_کلید_included(keysp, nkeys, کلید)) {
			debug2_f("key already included");
			sshkey_free(کلید);
		} وإلا {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, حجم(بنية sshkey *));
			(*keysp)[*nkeys] = کلید;
			إذا (labelsp != عدم) {
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
	rv = f->C_پیدا_کن_Objects_Final(session);
	إذا (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	أرجع (ret);
}

#اگر_تعریف_شده WITH_PKCS11_KEYGEN
#تعریف_کن FILL_ATTR(attr, idx, typ, val, len) \
	{ (attr[idx]).type=(typ); (attr[idx]).p_مقدار=(val); (attr[idx]).ul_مقدار_Len=len; idx++; }

ساكن بنية sshkey *
pkcs11_rsa_generate_خصوصی_کلید(بنية pkcs11_provider *p, CK_ULONG slotidx,
    حرف *label, CK_ULONG بیتها, CK_BYTE keyid, uint32_t *err)
{
	بنية pkcs11_slotinfo	*si;
	حرف			*plabel = label ? label : "";
	صحيح			 npub = 0, npriv = 0;
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

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, حجم(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, طول_رشته(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, حجم(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, حجم(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    حجم(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, حجم(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, حجم(false_val));
	FILL_ATTR(tpub, npub, CKA_MODULUS_بیتها, &بیتها, حجم(بیتها));
	FILL_ATTR(tpub, npub, CKA_عمومی_EXPONENT, pubExponent,
	    حجم(pubExponent));
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, حجم(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN,  &true_val, حجم(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL,  plabel, طول_رشته(plabel));
	FILL_ATTR(tpriv, npriv, CKA_خصوصی,  &true_val, حجم(true_val));
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

	إذا ((rv = f->C_Generate_کلید_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_کلید_2, &priv_کلید)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		أرجع عدم;
	}

	أرجع pkcs11_fetch_rsa_pubkey(p, slotidx, &pub_کلید_2);
}

ساكن صحيح
h2i(حرف c)
{
	إذا (c >= '0' && c <= '9')
		أرجع c - '0';
	وإلا إذا (c >= 'a' && c <= 'f')
		أرجع c - 'a' + 10;
	وإلا إذا (c >= 'A' && c <= 'F')
		أرجع c - 'A' + 10;
	وإلا
		أرجع -1;
}

ساكن صحيح
pkcs11_decode_hex(ثابت حرف *hex, بیعلامت حرف **dest, اندازه_t *rlen)
{
	اندازه_t	i, len;

	إذا (dest)
		*dest = عدم;
	إذا (rlen)
		*rlen = 0;

	إذا ((len = طول_رشته(hex)) % 2)
		أرجع -1;
	len /= 2;

	*dest = xmalloc(len);

	لكل (i = 0; i < len; i++) {
		صحيح hi, lo;

		hi = h2i(hex[2 * i]);
		lo = h2i(hex[(2 * i) + 1]);
		إذا (hi == -1 || lo == -1)
			أرجع -1;
		(*dest)[i] = (hi << 4) | lo;
	}

	إذا (rlen)
		*rlen = len;

	أرجع 0;
}

ساكن بنية ec_منحنی_info {
	ثابت حرف	*name;
	ثابت حرف	*oid;
	ثابت حرف	*oid_encoded;
	اندازه_t		 اندازه;
} ec_منحنی_infos[] = {
	{"prime256v1",	"1.2.840.10045.3.1.7",	"06082A8648CE3D030107", 256},
	{"secp384r1",	"1.3.132.0.34",		"06052B81040022",	384},
	{"secp521r1",	"1.3.132.0.35",		"06052B81040023",	521},
	{عدم,		عدم,			عدم,			0},
};

ساكن بنية sshkey *
pkcs11_ecdsa_generate_خصوصی_کلید(بنية pkcs11_provider *p, CK_ULONG slotidx,
    حرف *label, CK_ULONG بیتها, CK_BYTE keyid, uint32_t *err)
{
	بنية pkcs11_slotinfo	*si;
	حرف			*plabel = label ? label : "";
	صحيح			 i;
	اندازه_t			 ecparams_اندازه;
	بیعلامت حرف		*ecparams = عدم;
	صحيح			 npub = 0, npriv = 0;
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

	لكل (i = 0; ec_منحنی_infos[i].name; i++) {
		إذا (ec_منحنی_infos[i].اندازه == بیتها)
			اكسر;
	}
	إذا (!ec_منحنی_infos[i].name) {
		error_f("invalid key size %lu", بیتها);
		أرجع عدم;
	}
	إذا (pkcs11_decode_hex(ec_منحنی_infos[i].oid_encoded, &ecparams,
	    &ecparams_اندازه) == -1) {
		error_f("invalid oid");
		أرجع عدم;
	}

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, حجم(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, طول_رشته(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, حجم(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, حجم(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    حجم(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, حجم(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, حجم(false_val));
	FILL_ATTR(tpub, npub, CKA_EC_PARAMS, ecparams, ecparams_اندازه);
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, حجم(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN, &true_val, حجم(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL, plabel, طول_رشته(plabel));
	FILL_ATTR(tpriv, npriv, CKA_خصوصی, &true_val, حجم(true_val));
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

	إذا ((rv = f->C_Generate_کلید_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_کلید_2, &priv_کلید)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		أرجع عدم;
	}

	أرجع pkcs11_fetch_ecdsa_pubkey(p, slotidx, &pub_کلید_2);
}
#پایان_اگر /* WITH_PKCS11_KEYGEN */

/*
 * register a new provider, fails if provider already exists. if
 * keyp is provided, fetch keys.
 */
ساكن صحيح
pkcs11_ثبات_provider(حرف *provider_id, حرف *pin,
    بنية sshkey ***keyp, حرف ***labelsp,
    بنية pkcs11_provider **providerp, CK_ULONG user)
{
	صحيح nkeys, need_finalize = 0;
	صحيح ret = -1;
	بنية pkcs11_provider *p = عدم;
	فراغ *handle = عدم;
	CK_RV (*getfunctionlist)(CK_FUNCTION_LIST **);
	CK_RV rv;
	CK_FUNCTION_LIST *f = عدم;
	CK_TOKEN_INFO *token;
	CK_ULONG i;

	إذا (providerp == عدم)
		اذهب fail;
	*providerp = عدم;

	إذا (keyp != عدم)
		*keyp = عدم;
	إذا (labelsp != عدم)
		*labelsp = عدم;

	إذا (pkcs11_provider_lookup(provider_id) != عدم) {
		debug_f("provider already registered: %s", provider_id);
		اذهب fail;
	}
	إذا (lib_شامل_است_نماد(provider_id, "C_GetFunctionList") != 0) {
		error("provider %s is not a PKCS11 library", provider_id);
		اذهب fail;
	}
	/* open shared pkcs11-library */
	إذا ((handle = dlopen(provider_id, RTLD_NOW)) == عدم) {
		error("dlopen %s failed: %s", provider_id, dlerror());
		اذهب fail;
	}
	إذا ((getfunctionlist = dlsym(handle, "C_GetFunctionList")) == عدم)
		fatal("dlsym(C_GetFunctionList) failed: %s", dlerror());
	p = xcalloc(1, حجم(*p));
	p->name = xstrdup(provider_id);
	p->handle = handle;
	/* set up the pkcs11 callbacks */
	إذا ((rv = (*getfunctionlist)(&f)) != CKR_OK) {
		error("C_GetFunctionList for provider %s failed: %lu",
		    provider_id, rv);
		اذهب fail;
	}
	p->function_list = f;
	إذا ((rv = f->C_Initialize(عدم)) != CKR_OK) {
		error("C_Initialize for provider %s failed: %lu",
		    provider_id, rv);
		اذهب fail;
	}
	need_finalize = 1;
	إذا ((rv = f->C_GetInfo(&p->info)) != CKR_OK) {
		error("C_GetInfo for provider %s failed: %lu",
		    provider_id, rv);
		اذهب fail;
	}
	debug("provider %s: manufacturerID <%.*s> cryptokiVersion %d.%d"
	    " libraryDescription <%.*s> libraryVersion %d.%d",
	    provider_id,
	    RMSPACE(p->info.manufacturerID),
	    p->info.cryptoki_نسخه_2.major,
	    p->info.cryptoki_نسخه_2.minor,
	    RMSPACE(p->info.libraryDescription),
	    p->info.library_نسخه_2.major,
	    p->info.library_نسخه_2.minor);
	إذا ((rv = f->C_Get_جایگاه_List(CK_TRUE, عدم, &p->nslots)) != CKR_OK) {
		error("C_GetSlotList failed: %lu", rv);
		اذهب fail;
	}
	إذا (p->nslots == 0) {
		debug_f("provider %s returned no slots", provider_id);
		ret = -SSH_PKCS11_ERR_NO_SLOTS;
		اذهب fail;
	}
	p->slotlist = xcalloc(p->nslots, حجم(CK_جایگاه_ID));
	إذا ((rv = f->C_Get_جایگاه_List(CK_TRUE, p->slotlist, &p->nslots))
	    != CKR_OK) {
		error("C_GetSlotList for provider %s failed: %lu",
		    provider_id, rv);
		اذهب fail;
	}
	p->slotinfo = xcalloc(p->nslots, حجم(بنية pkcs11_slotinfo));
	p->valid = 1;
	nkeys = 0;
	لكل (i = 0; i < p->nslots; i++) {
		token = &p->slotinfo[i].token;
		إذا ((rv = f->C_GetTokenInfo(p->slotlist[i], token))
		    != CKR_OK) {
			error("C_GetTokenInfo for provider %s slot %lu "
			    "failed: %lu", provider_id, (u_long)i, rv);
			استمر;
		}
		إذا ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
			debug2_f("ignoring uninitialised token in "
			    "provider %s slot %lu", provider_id, (u_long)i);
			استمر;
		}
		debug("provider %s slot %lu: label <%.*s> "
		    "manufacturerID <%.*s> model <%.*s> serial <%.*s> "
		    "flags 0x%lx",
		    provider_id, (بیعلامت دراز)i,
		    RMSPACE(token->label), RMSPACE(token->manufacturerID),
		    RMSPACE(token->model), RMSPACE(token->serial_عدد_2),
		    token->flags);
		/*
		 * open session, login with pin and retrieve public
		 * keys (if keyp is provided)
		 */
		إذا ((ret = pkcs11_open_session(p, i, pin, user)) != 0 ||
		    keyp == عدم)
			استمر;
		pkcs11_fetch_کلیدها(p, i, keyp, labelsp, &nkeys);
#اگر_تعریف_شده WITH_OPENSSL
		pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#پایان_اگر
		إذا (nkeys == 0 && !p->slotinfo[i].logged_درون &&
		    pkcs11_interactive) {
			/*
			 * Some tokens require login before they will
			 * expose keys.
			 */
			إذا (pkcs11_login_جایگاه(p, &p->slotinfo[i],
			    CKU_USER) < 0) {
				error("login failed");
				استمر;
			}
			pkcs11_fetch_کلیدها(p, i, keyp, labelsp, &nkeys);
#اگر_تعریف_شده WITH_OPENSSL
			pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#پایان_اگر
		}
	}

	/* now owned by caller */
	*providerp = p;

	TAILQ_INSERT_TAIL(&pkcs11_providers, p, بعدی);
	p->refcount++;	/* add to provider list */

	أرجع (nkeys);
fail:
	إذا (need_finalize && (rv = f->C_Finalize(عدم)) != CKR_OK)
		error("C_Finalize for provider %s failed: %lu",
		    provider_id, rv);
	إذا (p) {
		حرر(p->name);
		حرر(p->slotlist);
		حرر(p->slotinfo);
		حرر(p);
	}
	إذا (handle)
		dlclose(handle);
	إذا (ret > 0)
		ret = -1;
	أرجع (ret);
}

صحيح
pkcs11_init(صحيح interactive)
{
	debug3_f("called, interactive = %d", interactive);

	pkcs11_interactive = interactive;
	TAILQ_INIT(&pkcs11_providers);
	TAILQ_INIT(&pkcs11_کلیدها);
	أرجع (0);
}

/* unregister all providers, keys might still point to the providers */
فراغ
pkcs11_terminate(فراغ)
{
	بنية pkcs11_provider *p;
	بنية pkcs11_کلید *k11;

	debug3_f("called");

	طالما ((k11 = TAILQ_FIRST(&pkcs11_کلیدها)) != عدم) {
		TAILQ_REMOVE(&pkcs11_کلیدها, k11, بعدی);
		pkcs11_k11_free(k11);
	}
	طالما ((p = TAILQ_FIRST(&pkcs11_providers)) != عدم) {
		TAILQ_REMOVE(&pkcs11_providers, p, بعدی);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
}

/*
 * register a new provider and get number of keys hold by the token,
 * fails if provider already exists
 */
صحيح
pkcs11_جمع_کن_provider(حرف *provider_id, حرف *pin, بنية sshkey ***keyp,
    حرف ***labelsp)
{
	بنية pkcs11_provider *p = عدم;
	صحيح nkeys;

	nkeys = pkcs11_ثبات_provider(provider_id, pin, keyp, labelsp,
	    &p, CKU_USER);

	/* no keys found or some other error, de-register provider */
	إذا (nkeys <= 0 && p != عدم) {
		TAILQ_REMOVE(&pkcs11_providers, p, بعدی);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
	إذا (nkeys == 0)
		debug_f("provider %s returned no keys", provider_id);

	أرجع (nkeys);
}

صحيح
pkcs11_sign(بنية sshkey *کلید,
    u_char **sigp, اندازه_t *lenp,
    ثابت u_char *داده, اندازه_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider,
    ثابت حرف *sk_pin, u_int compat)
{
	بدل (کلید->type) {
#اگر_تعریف_شده WITH_OPENSSL
	حالة کلید_RSA:
	حالة کلید_RSA_CERT:
		أرجع pkcs11_sign_rsa(کلید, sigp, lenp, داده, datalen,
		    alg, sk_provider, sk_pin, compat);
	حالة کلید_ECDSA:
	حالة کلید_ECDSA_CERT:
		أرجع pkcs11_sign_ecdsa(کلید, sigp, lenp, داده, datalen,
		    alg, sk_provider, sk_pin, compat);
#پایان_اگر /* WITH_OPENSSL */
	حالة کلید_ED25519:
	حالة کلید_ED25519_CERT:
		أرجع pkcs11_sign_ed25519(کلید, sigp, lenp, داده, datalen,
		    alg, sk_provider, sk_pin, compat);
	افتراضي:
		أرجع SSH_ERR_کلید_TYPE_UNKNOWN;
	}
}

فراغ
pkcs11_کلید_free(بنية sshkey *کلید)
{
	/* never called */
}

#اگر_تعریف_شده WITH_PKCS11_KEYGEN
بنية sshkey *
pkcs11_gakp(حرف *provider_id, حرف *pin, بیعلامت صحيح slotidx, حرف *label,
    بیعلامت صحيح type, بیعلامت صحيح بیتها, بیعلامت حرف keyid, uint32_t *err)
{
	بنية pkcs11_provider	*p = عدم;
	بنية pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	بنية sshkey		*k = عدم;
	صحيح			 ret = -1, reset_pin = 0, reset_provider = 0;
	CK_RV			 rv;

	*err = 0;

	إذا ((p = pkcs11_provider_lookup(provider_id)) != عدم)
		debug_f("provider \"%s\" available", provider_id);
	وإلا إذا ((ret = pkcs11_ثبات_provider(provider_id, pin, عدم, عدم,
	    &p, CKU_SO)) < 0) {
		debug_f("could not register provider %s", provider_id);
		اذهب بیرون;
	} وإلا
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	إذا ((rv = f->C_مجموعه_Operation_State(session , pin, طول_رشته(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} وإلا
		reset_pin = 1;

	بدل (type) {
	حالة کلید_RSA:
		إذا ((k = pkcs11_rsa_generate_خصوصی_کلید(p, slotidx, label,
		    بیتها, keyid, err)) == عدم) {
			debug_f("failed to generate RSA key");
			اذهب بیرون;
		}
		اكسر;
	حالة کلید_ECDSA:
		إذا ((k = pkcs11_ecdsa_generate_خصوصی_کلید(p, slotidx, label,
		    بیتها, keyid, err)) == عدم) {
			debug_f("failed to generate ECDSA key");
			اذهب بیرون;
		}
		اكسر;
	افتراضي:
		*err = SSH_PKCS11_ERR_GENERIC;
		debug_f("unknown type %d", type);
		اذهب بیرون;
	}

بیرون:
	إذا (reset_pin)
		f->C_مجموعه_Operation_State(session , عدم, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	إذا (reset_provider)
		pkcs11_del_provider(provider_id);

	أرجع (k);
}

بنية sshkey *
pkcs11_destroy_keypair(حرف *provider_id, حرف *pin, بیعلامت دراز slotidx,
    بیعلامت حرف keyid, uint32_t *err)
{
	بنية pkcs11_provider	*p = عدم;
	بنية pkcs11_slotinfo	*si;
	بنية sshkey		*k = عدم;
	صحيح			 reset_pin = 0, reset_provider = 0;
	CK_ULONG		 nattrs;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_ATTRIBUTE		 attrs[16];
	CK_OBJECT_CLASS		 کلید_class;
	CK_کلید_TYPE		 کلید_type;
	CK_OBJECT_HANDLE	 obj = CK_INVALID_HANDLE;
	CK_RV			 rv;

	*err = 0;

	إذا ((p = pkcs11_provider_lookup(provider_id)) != عدم) {
		debug_f("using provider \"%s\"", provider_id);
	} وإلا إذا (pkcs11_ثبات_provider(provider_id, pin, عدم, عدم, &p,
	    CKU_SO) < 0) {
		debug_f("could not register provider %s",
		    provider_id);
		اذهب بیرون;
	} وإلا
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	إذا ((rv = f->C_مجموعه_Operation_State(session , pin, طول_رشته(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} وإلا
		reset_pin = 1;

	/* private key */
	nattrs = 0;
	کلید_class = CKO_خصوصی_کلید;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &کلید_class, حجم(کلید_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, حجم(keyid));

	إذا (pkcs11_پیدا_کن(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {
		إذا ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy private key 0x%hhx",
			    keyid);
			*err = rv;
			اذهب بیرون;
		}
	}

	/* public key */
	nattrs = 0;
	کلید_class = CKO_عمومی_کلید;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &کلید_class, حجم(کلید_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, حجم(keyid));

	إذا (pkcs11_پیدا_کن(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {

		/* get key type */
		nattrs = 0;
		FILL_ATTR(attrs, nattrs, CKA_کلید_TYPE, &کلید_type,
		    حجم(کلید_type));
		rv = f->C_Get_Attribute_مقدار(session, obj, attrs, nattrs);
		إذا (rv != CKR_OK) {
			debug_f("could not get key type of public key 0x%hhx",
			    keyid);
			*err = rv;
			کلید_type = -1;
		}
		بدل (کلید_type) {
#اگر_تعریف_شده WITH_OPENSSL
		حالة CKK_RSA:
			k = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			اكسر;
		حالة CKK_ECDSA:
			k = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			اكسر;
#پایان_اگر /* WITH_OPENSSL */
		حالة CKK_EC_EDWARDS:
			k = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			اكسر;
		افتراضي:
			debug_f("unsupported key type %lu", (u_long)کلید_type);
			اكسر;
		}

		إذا ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy public key 0x%hhx", keyid);
			*err = rv;
			اذهب بیرون;
		}
	}

بیرون:
	إذا (reset_pin)
		f->C_مجموعه_Operation_State(session , عدم, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	إذا (reset_provider)
		pkcs11_del_provider(provider_id);

	أرجع (k);
}
#پایان_اگر /* WITH_PKCS11_KEYGEN */
#وإلا /* ENABLE_PKCS11 */

#ضمن <sys/types.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>

#ضمن "log.h"
#ضمن "sshkey.h"
#ضمن "ssherr.h"
#ضمن "ssh-pkcs11.h"

صحيح
pkcs11_init(صحيح interactive)
{
	error_f("PKCS#11 not supported");
	أرجع (-1);
}

صحيح
pkcs11_جمع_کن_provider(حرف *provider_id, حرف *pin, بنية sshkey ***keyp,
    حرف ***labelsp)
{
	error_f("PKCS#11 not supported");
	أرجع (-1);
}

فراغ
pkcs11_کلید_free(بنية sshkey *کلید)
{
	error_f("PKCS#11 not supported");
}

صحيح
pkcs11_sign(بنية sshkey *کلید,
    u_char **sigp, اندازه_t *lenp,
    ثابت u_char *داده, اندازه_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider,
    ثابت حرف *sk_pin, u_int compat)
{
	error_f("PKCS#11 not supported");
	أرجع SSH_ERR_FEATURE_UNSUPPORTED;
}

فراغ
pkcs11_terminate(فراغ)
{
	error_f("PKCS#11 not supported");
}
#پایان_اگر /* ENABLE_PKCS11 */
