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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifdef ENABLE_PKCS11

#ଅନ୍ତର୍ଭାଵ <sys/time.h>

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/queue.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>

#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <dlfcn.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"
#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ecdsa.h>
#ଅନ୍ତର୍ଭାଵ <openssl/x509.h>
#ଅନ୍ତର୍ଭାଵ <openssl/err.h>
#endif

#define CRYPTOKI_COMPAT
#ଅନ୍ତର୍ଭାଵ "pkcs11.h"

#define SSHKEY_INTERNAL
#ଅନ୍ତର୍ଭାଵ "sshkey.h"

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssh-pkcs11.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "crypto_api.h"

ସଂରଚନା pkcs11_slotinfo {
	CK_TOKEN_INFO		token;
	CK_SESSION_HANDLE	session;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			logged_in;
};

ସଂରଚନା pkcs11_provider {
	ଅକ୍ଷର			*name;
	ଶୂନ୍ୟ			*handle;
	CK_FUNCTION_LIST	*function_list;
	CK_INFO			info;
	CK_ULONG		nslots;
	CK_SLOT_ID		*slotlist;
	ସଂରଚନା pkcs11_slotinfo	*slotinfo;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			valid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			refcount;
	TAILQ_ENTRY(pkcs11_provider) next;
};

TAILQ_HEAD(, pkcs11_provider) pkcs11_providers;

ସଂରଚନା pkcs11_ଚାବି {
	ସଂରଚନା sshbuf		*keyblob;
	ସଂରଚନା pkcs11_provider	*provider;
	CK_ULONG		slotidx;
	ଅକ୍ଷର			*keyid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			keyid_len;
	TAILQ_ENTRY(pkcs11_ଚାବି)	next;
};

TAILQ_HEAD(, pkcs11_ଚାବି) pkcs11_ଚାବିଗୁଡ଼ିକ; /* XXX a tree would be better */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା pkcs11_interactive = 0;

#ifdef WITH_OPENSSL
ସ୍ଥିର ଶୂନ୍ୟ
ossl_error(ଅଚଳ ଅକ୍ଷର *ସନ୍ଦେଶ)
{
	unsigned long    e;

	error_f("%s", ସନ୍ଦେଶ);
	ଯେତେବେଳେ ((e = ERR_get_error()) != 0)
		error_f("libcrypto error: %s", ERR_error_string(e, ଖାଲି));
}
#endif

/*
 * finalize a provider shared library, it's no longer usable.
 * however, there might still be keys referencing this provider,
 * so the actual freeing of memory is handled by pkcs11_provider_unref().
 * this is called when a provider gets unregistered.
 */
ସ୍ଥିର ଶୂନ୍ୟ
pkcs11_provider_finalize(ସଂରଚନା pkcs11_provider *p)
{
	CK_RV rv;
	CK_ULONG i;

	debug_f("provider \"%s\" refcount %d valid %d",
	    p->name, p->refcount, p->valid);
	ଯଦି (!p->valid)
		ଫେରନ୍ତୁ;
	ପାଇଁ (i = 0; i < p->nslots; i++) {
		ଯଦି (p->slotinfo[i].session &&
		    (rv = p->function_list->C_CloseSession(
		    p->slotinfo[i].session)) != CKR_OK)
			error("C_CloseSession failed: %lu", rv);
	}
	ଯଦି ((rv = p->function_list->C_Finalize(ଖାଲି)) != CKR_OK)
		error("C_Finalize failed: %lu", rv);
	p->valid = 0;
	p->function_list = ଖାଲି;
	dlclose(p->handle);
}

/*
 * remove a reference to the provider.
 * called when a key gets destroyed or when the provider is unregistered.
 */
ସ୍ଥିର ଶୂନ୍ୟ
pkcs11_provider_unref(ସଂରଚନା pkcs11_provider *p)
{
	debug_f("provider \"%s\" refcount %d", p->name, p->refcount);
	ଯଦି (--p->refcount <= 0) {
		ଯଦି (p->valid)
			error_f("provider \"%s\" still valid", p->name);
		ମୁକ୍ତ(p->name);
		ମୁକ୍ତ(p->slotlist);
		ମୁକ୍ତ(p->slotinfo);
		ମୁକ୍ତ(p);
	}
}

/* lookup provider by name */
ସ୍ଥିର ସଂରଚନା pkcs11_provider *
pkcs11_provider_lookup(ଅକ୍ଷର *provider_id)
{
	ସଂରଚନା pkcs11_provider *p;

	TAILQ_FOREACH(p, &pkcs11_providers, next) {
		debug("check provider \"%s\"", p->name);
		ଯଦି (!strcmp(provider_id, p->name))
			ଫେରନ୍ତୁ (p);
	}
	ଫେରନ୍ତୁ (ଖାଲି);
}

/* unregister provider by name */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_del_provider(ଅକ୍ଷର *provider_id)
{
	ସଂରଚନା pkcs11_provider *p;

	ଯଦି ((p = pkcs11_provider_lookup(provider_id)) != ଖାଲି) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
		ଫେରନ୍ତୁ (0);
	}
	ଫେରନ୍ତୁ (-1);
}

/* release a wrapped object */
ସ୍ଥିର ଶୂନ୍ୟ
pkcs11_k11_free(ସଂରଚନା pkcs11_ଚାବି *k11)
{
	ଯଦି (k11 == ଖାଲି)
		ଫେରନ୍ତୁ;
	ଯଦି (k11->provider)
		pkcs11_provider_unref(k11->provider);
	ମୁକ୍ତ(k11->keyid);
	sshbuf_free(k11->keyblob);
	ମୁକ୍ତ(k11);
}

/* find a single 'obj' for given attributes */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_find(ସଂରଚନା pkcs11_provider *p, CK_ULONG slotidx, CK_ATTRIBUTE *attr,
    CK_ULONG nattr, CK_OBJECT_HANDLE *obj)
{
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	session;
	CK_ULONG		nfound = 0;
	CK_RV			rv;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			ret = -1;

	f = p->function_list;
	session = p->slotinfo[slotidx].session;
	ଯଦି ((rv = f->C_FindObjectsInit(session, attr, nattr)) != CKR_OK) {
		error("C_FindObjectsInit failed (nattr %lu): %lu", nattr, rv);
		ଫେରନ୍ତୁ (-1);
	}
	ଯଦି ((rv = f->C_FindObjects(session, obj, 1, &nfound)) != CKR_OK ||
	    nfound != 1) {
		debug("C_FindObjects failed (nfound %lu nattr %lu): %lu",
		    nfound, nattr, rv);
	} ଅନ୍ୟଥା
		ret = 0;
	ଯଦି ((rv = f->C_FindObjectsFinal(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	ଫେରନ୍ତୁ (ret);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_login_slot(ସଂରଚନା pkcs11_provider *provider, ସଂରଚନା pkcs11_slotinfo *si,
    CK_USER_TYPE type)
{
	ଅକ୍ଷର			*pin = ଖାଲି, prompt[1024];
	CK_RV			 rv;

	ଯଦି (provider == ଖାଲି || si == ଖାଲି || !provider->valid) {
		error("no pkcs11 (valid) provider found");
		ଫେରନ୍ତୁ (-1);
	}

	ଯଦି (!pkcs11_interactive) {
		error("need pin entry%s",
		    (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH) ?
		    " on reader keypad" : "");
		ଫେରନ୍ତୁ (-1);
	}
	ଯଦି (si->token.flags & CKF_PROTECTED_AUTHENTICATION_PATH)
		verbose("Deferring PIN entry to reader keypad.");
	ଅନ୍ୟଥା {
		snprintf(prompt, ଆକାର(prompt), "Enter PIN for '%s': ",
		    si->token.label);
		ଯଦି ((pin = read_passphrase(prompt, RP_ALLOW_EOF)) == ଖାଲି) {
			debug_f("no pin specified");
			ଫେରନ୍ତୁ (-1);	/* bail out */
		}
	}
	rv = provider->function_list->C_Login(si->session, type, (u_char *)pin,
	    (pin != ଖାଲି) ? strlen(pin) : 0);
	ଯଦି (pin != ଖାଲି)
		freezero(pin, strlen(pin));

	ବାଛ (rv) {
	ସ୍ଥିତି CKR_OK:
	ସ୍ଥିତି CKR_USER_ALREADY_LOGGED_IN:
		/* success */
		ଭାଙ୍ଗ;
	ସ୍ଥିତି CKR_PIN_LEN_RANGE:
		error("PKCS#11 login failed: PIN length out of range");
		ଫେରନ୍ତୁ -1;
	ସ୍ଥିତି CKR_PIN_INCORRECT:
		error("PKCS#11 login failed: PIN incorrect");
		ଫେରନ୍ତୁ -1;
	ସ୍ଥିତି CKR_PIN_LOCKED:
		error("PKCS#11 login failed: PIN locked");
		ଫେରନ୍ତୁ -1;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		error("PKCS#11 login failed: error %lu", rv);
		ଫେରନ୍ତୁ -1;
	}
	si->logged_in = 1;
	ଫେରନ୍ତୁ (0);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_login(ସଂରଚନା pkcs11_ଚାବି *k11, CK_USER_TYPE type)
{
	ଯଦି (k11 == ଖାଲି || k11->provider == ଖାଲି || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		ଫେରନ୍ତୁ (-1);
	}

	ଫେରନ୍ତୁ pkcs11_login_slot(k11->provider,
	    &k11->provider->slotinfo[k11->slotidx], type);
}


ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_check_obj_bool_attrib(ସଂରଚନା pkcs11_ଚାବି *k11, CK_OBJECT_HANDLE obj,
    CK_ATTRIBUTE_TYPE type, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *val)
{
	ସଂରଚନା pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_BBOOL		flag = 0;
	CK_ATTRIBUTE		attr;
	CK_RV			 rv;

	*val = 0;

	ଯଦି (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		ଫେରନ୍ତୁ (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	attr.type = type;
	attr.p_ମୂଲ୍ୟ = &flag;
	attr.ul_ମୂଲ୍ୟ_Len = ଆକାର(flag);

	rv = f->C_Get_Attribute_ମୂଲ୍ୟ(si->session, obj, &attr, 1);
	ଯଦି (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ଫେରନ୍ତୁ (-1);
	}
	*val = flag != 0;
	debug_f("provider \"%s\" slot %lu object %lu: attrib %lu = %d",
	    k11->provider->name, k11->slotidx, obj, type, *val);
	ଫେରନ୍ତୁ (0);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_get_ଚାବି(ସଂରଚନା pkcs11_ଚାବି *k11, CK_MECHANISM_TYPE mech_type)
{
	ସଂରଚନା pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	 obj;
	CK_RV			 rv;
	CK_OBJECT_CLASS		 private_ଚାବି_class;
	CK_BBOOL		 true_val;
	CK_MECHANISM		 mech;
	CK_ATTRIBUTE		 ଚାବି_filter[3];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			 always_auth = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			 did_login = 0;

	ଯଦି (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		ଫେରନ୍ତୁ (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	ଯଦି ((si->token.flags & CKF_LOGIN_REQUIRED) && !si->logged_in) {
		ଯଦି (pkcs11_login(k11, CKU_USER) < 0) {
			error("login failed");
			ଫେରନ୍ତୁ (-1);
		}
		did_login = 1;
	}

	memset(&ଚାବି_filter, 0, ଆକାର(ଚାବି_filter));
	private_ଚାବି_class = CKO_PRIVATE_ଚାବି;
	ଚାବି_filter[0].type = CKA_CLASS;
	ଚାବି_filter[0].p_ମୂଲ୍ୟ = &private_ଚାବି_class;
	ଚାବି_filter[0].ul_ମୂଲ୍ୟ_Len = ଆକାର(private_ଚାବି_class);

	ଚାବି_filter[1].type = CKA_ID;
	ଚାବି_filter[1].p_ମୂଲ୍ୟ = k11->keyid;
	ଚାବି_filter[1].ul_ମୂଲ୍ୟ_Len = k11->keyid_len;

	true_val = CK_TRUE;
	ଚାବି_filter[2].type = CKA_SIGN;
	ଚାବି_filter[2].p_ମୂଲ୍ୟ = &true_val;
	ଚାବି_filter[2].ul_ମୂଲ୍ୟ_Len = ଆକାର(true_val);

	/* try to find object w/CKA_SIGN first, retry w/o */
	ଯଦି (pkcs11_find(k11->provider, k11->slotidx, ଚାବି_filter, 3, &obj) < 0 &&
	    pkcs11_find(k11->provider, k11->slotidx, ଚାବି_filter, 2, &obj) < 0) {
		error("cannot find private key");
		ଫେରନ୍ତୁ (-1);
	}

	memset(&mech, 0, ଆକାର(mech));
	mech.mechanism = mech_type;
	mech.pParameter = NULL_PTR;
	mech.ulParameterLen = 0;

	ଯଦି ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
		ଫେରନ୍ତୁ (-1);
	}

	pkcs11_check_obj_bool_attrib(k11, obj, CKA_ALWAYS_AUTHENTICATE,
	    &always_auth); /* ignore errors here */
	ଯଦି (always_auth && !did_login) {
		debug_f("always-auth key");
		ଯଦି (pkcs11_login(k11, CKU_CONTEXT_SPECIFIC) < 0) {
			error("login failed for always-auth key");
			ଫେରନ୍ତୁ (-1);
		}
	}

	ଫେରନ୍ତୁ (0);
}

/* record the key information later use lookup by keyblob */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_record_ଚାବି(ସଂରଚନା pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, ସଂରଚନା sshkey *ଚାବି)
{
	ସଂରଚନା sshbuf *keyblob;
	ସଂରଚନା pkcs11_ଚାବି *k11;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅକ୍ଷର *hex;

	hex = tohex(keyid_attrib->p_ମୂଲ୍ୟ, keyid_attrib->ul_ମୂଲ୍ୟ_Len);
	debug_f("%s key: provider %s slot %lu keyid %s",
	    sshkey_type(ଚାବି), provider->name, (u_long)slotidx, hex);
	ମୁକ୍ତ(hex);

	ଯଦି ((keyblob = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshkey_putb(ଚାବି, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");

	/* Check if we've already recorded this key in a different slot */
	TAILQ_FOREACH(k11, &pkcs11_ଚାବିଗୁଡ଼ିକ, next) {
		ଯଦି (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			hex = tohex(k11->keyid, k11->keyid_len);
			debug_f("Already seen this key at "
			    "provider %s slot %lu keyid %s",
			    k11->provider->name, k11->slotidx, hex);
			ମୁକ୍ତ(hex);
			sshbuf_free(keyblob);
			ଫେରନ୍ତୁ -1;
		}
	}

	k11 = xcalloc(1, ଆକାର(*k11));
	k11->provider = provider;
	k11->keyblob = keyblob;
	provider->refcount++;	/* provider referenced by RSA key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ul_ମୂଲ୍ୟ_Len;
	ଯଦି (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len);
		memcpy(k11->keyid, keyid_attrib->p_ମୂଲ୍ୟ, k11->keyid_len);
	}
	TAILQ_INSERT_TAIL(&pkcs11_ଚାବିଗୁଡ଼ିକ, k11, next);

	ଫେରନ୍ତୁ 0;
}

/* retrieve the key information by keyblob */
ସ୍ଥିର ସଂରଚନା pkcs11_ଚାବି *
pkcs11_lookup_ଚାବି(ସଂରଚନା sshkey *ଚାବି)
{
	ସଂରଚନା pkcs11_ଚାବି *k11, *found = ଖାଲି;
	ସଂରଚନା sshbuf *keyblob;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((keyblob = sshbuf_new()) == ଖାଲି)
		fatal_f("sshbuf_new failed");
	ଯଦି ((r = sshkey_putb(ଚାବି, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");
	TAILQ_FOREACH(k11, &pkcs11_ଚାବିଗୁଡ଼ିକ, next) {
		ଯଦି (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			found = k11;
			ଭାଙ୍ଗ;
		}
	}
	sshbuf_free(keyblob);
	ଫେରନ୍ତୁ found;
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
ସ୍ଥିର ଅଚଳ u_char id_sha1[] = {
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
ସ୍ଥିର ଅଚଳ u_char id_sha256[] = {
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
ସ୍ଥିର ଅଚଳ u_char id_sha512[] = {
	0x30, 0x51, /* type Sequence, length 0x51 (81) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, /* id-sha512 */
	0x05, 0x00, /* NULL */
	0x04, 0x40  /* Octet string, length 0x40 (64), followed by sha512 hash */
};

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
rsa_hash_alg_oid(ପୂର୍ଣ୍ଣସଂଖ୍ୟା hash_alg, ଅଚଳ u_char **oidp, size_t *oidlenp)
{
	ବାଛ (hash_alg) {
	ସ୍ଥିତି SSH_DIGEST_SHA1:
		*oidp = id_sha1;
		*oidlenp = ଆକାର(id_sha1);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_DIGEST_SHA256:
		*oidp = id_sha256;
		*oidlenp = ଆକାର(id_sha256);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_DIGEST_SHA512:
		*oidp = id_sha512;
		*oidlenp = ଆକାର(id_sha512);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_sign_rsa(ସଂରଚନା sshkey *ଚାବି,
    u_char **sigp, size_t *lenp,
    ଅଚଳ u_char *data, size_t datalen,
    ଅଚଳ ଅକ୍ଷର *alg, ଅଚଳ ଅକ୍ଷର *sk_provider,
    ଅଚଳ ଅକ୍ଷର *sk_pin, u_int compat)
{
	ସଂରଚନା pkcs11_ଚାବି	*k11;
	ସଂରଚନା pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			hashalg, r, diff, siglen, ret = -1;
	u_char			*oid_dgst = ଖାଲି, *sig = ଖାଲି;
	size_t			dgst_len, oid_len, oid_dgst_len = 0;
	ଅଚଳ u_char		*oid;

	ଯଦି (sigp != ଖାଲି)
		*sigp = ଖାଲି;
	ଯଦି (lenp != ଖାଲି)
		*lenp = 0;

	ଯଦି ((k11 = pkcs11_lookup_ଚାବି(ଚାବି)) == ଖାଲି) {
		error_f("no key found");
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_NOT_FOUND;
	}

	debug3_f("sign with alg \"%s\" using provider %s slotidx %lu",
	    alg == ଖାଲି ? "" : alg, k11->provider->name, (u_long)k11->slotidx);

	ଯଦି (pkcs11_get_ଚାବି(k11, CKM_RSA_PKCS) == -1) {
		error("pkcs11_get_key failed");
		ଫେରନ୍ତୁ SSH_ERR_AGENT_FAILURE;
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	ଯଦି ((siglen = EVP_PKEY_size(ଚାବି->pkey)) <= 0)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* Determine hash algorithm and OID for signature */
	ଯଦି (alg == ଖାଲି || *alg == '\0')
		hashalg = SSH_DIGEST_SHA1;
	ଅନ୍ୟଥା ଯଦି ((hashalg = ssh_rsa_hash_id_from_keyname(alg)) == -1)
		fatal_f("couldn't determine RSA hash alg \"%s\"", alg);
	ଯଦି ((r = rsa_hash_alg_oid(hashalg, &oid, &oid_len)) != 0)
		fatal_fr(r, "rsa_hash_alg_oid failed");
	ଯଦି ((dgst_len = ssh_digest_bytes(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);

	/* Prepare { oid || digest } */
	oid_dgst_len = oid_len + dgst_len;
	oid_dgst = xcalloc(1, oid_dgst_len);
	memcpy(oid_dgst, oid, oid_len);
	ଯଦି ((r = ssh_digest_memory(hashalg, data, datalen,
	    oid_dgst + oid_len, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	ଯଦି ((rv = f->C_Sign(si->session, (CK_BYTE *)oid_dgst,
	    oid_dgst_len, sig, &slen)) != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		ଯାଅ done;
	}

	ଯଦି (slen < (CK_ULONG)siglen) {
		diff = siglen - slen;
		debug3_f("repack %lu < %d (diff %d)",
		    (u_long)slen, siglen, diff);
		memmove(sig + diff, sig, slen);
		explicit_bzero(sig, diff);
	} ଅନ୍ୟଥା ଯଦି (slen > (size_t)siglen)
		fatal_f("bad C_Sign length");

	ଯଦି ((ret = ssh_rsa_encode_store_sig(hashalg, sig, siglen,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	freezero(oid_dgst, oid_dgst_len);
	ମୁକ୍ତ(sig);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_sign_ecdsa(ସଂରଚନା sshkey *ଚାବି,
    u_char **sigp, size_t *lenp,
    ଅଚଳ u_char *data, size_t datalen,
    ଅଚଳ ଅକ୍ଷର *alg, ଅଚଳ ଅକ୍ଷର *sk_provider,
    ଅଚଳ ଅକ୍ଷର *sk_pin, u_int compat)
{
	ସଂରଚନା pkcs11_ଚାବି	*k11;
	ସଂରଚନା pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0, bnlen;
	CK_RV			rv;
	BIGNUM			*sig_r = ଖାଲି, *sig_s = ଖାଲି;
	u_char			*sig = ଖାଲି, *dgst = ଖାଲି;
	size_t			dgst_len = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			hashalg, ret = -1, r, siglen;

	ଯଦି (sigp != ଖାଲି)
		*sigp = ଖାଲି;
	ଯଦି (lenp != ଖାଲି)
		*lenp = 0;

	ଯଦି ((k11 = pkcs11_lookup_ଚାବି(ଚାବି)) == ଖାଲି) {
		error_f("no key found");
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_NOT_FOUND;
	}

	ଯଦି (pkcs11_get_ଚାବି(k11, CKM_ECDSA) == -1) {
		error("pkcs11_get_key failed");
		ଫେରନ୍ତୁ SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	/* Prepare digest to be signed */
	ଯଦି ((hashalg = sshkey_ec_nid_to_hash_alg(ଚାବି->ecdsa_nid)) == -1)
		fatal_f("couldn't determine ECDSA hash alg");
	ଯଦି ((dgst_len = ssh_digest_bytes(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);
	dgst = xcalloc(1, dgst_len);
	ଯଦି ((r = ssh_digest_memory(hashalg, data, datalen,
	    dgst, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	ଯଦି ((siglen = EVP_PKEY_size(ଚାବି->pkey)) <= 0)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dgst_len, sig, &slen);
	ଯଦି (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		ଯାଅ done;
	}
	ଯଦି (slen < 64 || slen > 132 || slen % 2) {
		error_f("bad signature length: %lu", (u_long)slen);
		ଯାଅ done;
	}
	bnlen = slen/2;
	ଯଦି ((sig_r = BN_bin2bn(sig, bnlen, ଖାଲି)) == ଖାଲି ||
	    (sig_s = BN_bin2bn(sig+bnlen, bnlen, ଖାଲି)) == ଖାଲି) {
		ossl_error("BN_bin2bn failed");
		ଯାଅ done;
	}

	ଯଦି ((ret = ssh_ecdsa_encode_store_sig(ଚାବି, sig_r, sig_s,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	freezero(dgst, dgst_len);
	BN_free(sig_r);
	BN_free(sig_s);
	ମୁକ୍ତ(sig);
	ଫେରନ୍ତୁ ret;
}
#endif /* WITH_OPENSSL */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_sign_ed25519(ସଂରଚନା sshkey *ଚାବି,
    u_char **sigp, size_t *lenp,
    ଅଚଳ u_char *data, size_t datalen,
    ଅଚଳ ଅକ୍ଷର *alg, ଅଚଳ ଅକ୍ଷର *sk_provider,
    ଅଚଳ ଅକ୍ଷର *sk_pin, u_int compat)
{
	ସଂରଚନା pkcs11_ଚାବି	*k11;
	ସଂରଚନା pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	u_char			*sig = ଖାଲି;
	CK_BYTE			*xdata = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			ret = -1;

	ଯଦି (sigp != ଖାଲି)
		*sigp = ଖାଲି;
	ଯଦି (lenp != ଖାଲି)
		*lenp = 0;

	ଯଦି ((k11 = pkcs11_lookup_ଚାବି(ଚାବି)) == ଖାଲି) {
		error_f("no key found");
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_NOT_FOUND;
	}

	ଯଦି (pkcs11_get_ଚାବି(k11, CKM_EDDSA) == -1) {
		error("pkcs11_get_key failed");
		ଫେରନ୍ତୁ SSH_ERR_AGENT_FAILURE;
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
	ଯଦି (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		ଯାଅ done;
	}
	ଯଦି (slen != crypto_sign_ed25519_BYTES) {
		error_f("bad signature length: %lu", (u_long)slen);
		ଯାଅ done;
	}
	ଯଦି ((ret = ssh_ed25519_encode_store_sig(sig, slen, sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 done:
	ଯଦି (xdata != ଖାଲି)
		freezero(xdata, datalen);
	ମୁକ୍ତ(sig);
	ଫେରନ୍ତୁ ret;
}

/* remove trailing spaces */
ସ୍ଥିର ଅକ୍ଷର *
rmspace(u_char *buf, size_t len)
{
	size_t i;

	ଯଦି (len == 0)
		ଫେରନ୍ତୁ buf;
	ପାଇଁ (i = len - 1; i > 0; i--)
		ଯଦି (buf[i] == ' ')
			buf[i] = '\0';
		ଅନ୍ୟଥା
			ଭାଙ୍ଗ;
	ଫେରନ୍ତୁ buf;
}
/* Used to printf fixed-width, space-padded, unterminated strings using %.*s */
#define RMSPACE(s) (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)ଆକାର(s), rmspace(s, ଆକାର(s))

/*
 * open a pkcs11 session and login if required.
 * if pin == NULL we delay login until key use
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_open_session(ସଂରଚନା pkcs11_provider *p, CK_ULONG slotidx, ଅକ୍ଷର *pin,
    CK_ULONG user)
{
	ସଂରଚନା pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_RV			rv;
	CK_SESSION_HANDLE	session;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			login_required, ret;

	f = p->function_list;
	si = &p->slotinfo[slotidx];

	login_required = si->token.flags & CKF_LOGIN_REQUIRED;

	/* fail early before opening session */
	ଯଦି (login_required && !pkcs11_interactive &&
	    (pin == ଖାଲି || strlen(pin) == 0)) {
		error("pin required");
		ଫେରନ୍ତୁ (-SSH_PKCS11_ERR_PIN_REQUIRED);
	}
	ଯଦି ((rv = f->C_OpenSession(p->slotlist[slotidx], CKF_RW_SESSION|
	    CKF_SERIAL_SESSION, ଖାଲି, ଖାଲି, &session)) != CKR_OK) {
		error("C_OpenSession failed: %lu", rv);
		ଫେରନ୍ତୁ (-1);
	}
	ଯଦି (login_required && pin != ଖାଲି && strlen(pin) != 0) {
		rv = f->C_Login(session, user, (u_char *)pin, strlen(pin));
		ଯଦି (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
			error("C_Login failed: %lu", rv);
			ret = (rv == CKR_PIN_LOCKED) ?
			    -SSH_PKCS11_ERR_PIN_LOCKED :
			    -SSH_PKCS11_ERR_LOGIN_FAIL;
			ଯଦି ((rv = f->C_CloseSession(session)) != CKR_OK)
				error("C_CloseSession failed: %lu", rv);
			ଫେରନ୍ତୁ (ret);
		}
		si->logged_in = 1;
	}
	si->session = session;
	ଫେରନ୍ତୁ (0);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_ଚାବି_included(ସଂରଚନା sshkey ***keysp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *nkeys, ସଂରଚନା sshkey *ଚାବି)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ପାଇଁ (i = 0; i < *nkeys; i++)
		ଯଦି (sshkey_equal(ଚାବି, (*keysp)[i]))
			ଫେରନ୍ତୁ (1);
	ଫେରନ୍ତୁ (0);
}

#ifdef WITH_OPENSSL
ସ୍ଥିର ସଂରଚନା sshkey *
pkcs11_fetch_ecdsa_pubkey(ସଂରଚନା pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 ଚାବି_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ଖାଲି;
	CK_RV			 rv;
	ASN1_OCTET_STRING	*octet = ଖାଲି;
	EC_ଚାବି			*ec = ଖାଲି;
	EC_GROUP		*group = ଖାଲି;
	ସଂରଚନା sshkey		*ଚାବି = ଖାଲି;
	ଅଚଳ unsigned ଅକ୍ଷର	*attrp = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			 success = -1, r, i, nid;

	memset(&ଚାବି_attr, 0, ଆକାର(ଚାବି_attr));
	ଚାବି_attr[0].type = CKA_ID;
	ଚାବି_attr[1].type = CKA_EC_POINT;
	ଚାବି_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_ମୂଲ୍ୟ(session, *obj, ଚାବି_attr, 3);
	ଯଦି (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ଫେରନ୍ତୁ (ଖାଲି);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	ଯଦି (ଚାବି_attr[1].ul_ମୂଲ୍ୟ_Len == 0 ||
	    ଚାବି_attr[2].ul_ମୂଲ୍ୟ_Len == 0) {
		error("invalid attribute length");
		ଫେରନ୍ତୁ (ଖାଲି);
	}

	/* allocate buffers for attributes */
	ପାଇଁ (i = 0; i < 3; i++)
		ଯଦି (ଚାବି_attr[i].ul_ମୂଲ୍ୟ_Len > 0)
			ଚାବି_attr[i].p_ମୂଲ୍ୟ = xcalloc(1, ଚାବି_attr[i].ul_ମୂଲ୍ୟ_Len);

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_ମୂଲ୍ୟ(session, *obj, ଚାବି_attr, 3);
	ଯଦି (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ଯାଅ fail;
	}

	ec = EC_ଚାବି_new();
	ଯଦି (ec == ଖାଲି) {
		error("EC_KEY_new failed");
		ଯାଅ fail;
	}

	attrp = ଚାବି_attr[2].p_ମୂଲ୍ୟ;
	group = d2i_ECPKParameters(ଖାଲି, &attrp, ଚାବି_attr[2].ul_ମୂଲ୍ୟ_Len);
	ଯଦି (group == ଖାଲି) {
		ossl_error("d2i_ECPKParameters failed");
		ଯାଅ fail;
	}

	ଯଦି (EC_ଚାବି_set_group(ec, group) == 0) {
		ossl_error("EC_KEY_set_group failed");
		ଯାଅ fail;
	}

	ଯଦି (ଚାବି_attr[1].ul_ମୂଲ୍ୟ_Len <= 2) {
		error("CKA_EC_POINT too small");
		ଯାଅ fail;
	}

	attrp = ଚାବି_attr[1].p_ମୂଲ୍ୟ;
	octet = d2i_ASN1_OCTET_STRING(ଖାଲି, &attrp, ଚାବି_attr[1].ul_ମୂଲ୍ୟ_Len);
	ଯଦି (octet == ଖାଲି) {
		ossl_error("d2i_ASN1_OCTET_STRING failed");
		ଯାଅ fail;
	}
	attrp = ASN1_STRING_get0_data(octet);
	ଯଦି (o2i_ECPublic_ଚାବି(&ec, &attrp, ASN1_STRING_length(octet)) == ଖାଲି) {
		ossl_error("o2i_ECPublicKey failed");
		ଯାଅ fail;
	}
	ଯଦି ((r = sshkey_ec_validate_public(EC_ଚାବି_get0_group(ec),
	    EC_ଚାବି_get0_public_ଚାବି(ec))) != 0) {
		error_fr(r, "invalid EC key");
		ଯାଅ fail;
	}

	nid = sshkey_ecdsa_ଚାବି_to_nid(ec);
	ଯଦି (nid < 0) {
		error("couldn't get curve nid");
		ଯାଅ fail;
	}

	ଚାବି = sshkey_new(ଚାବି_UNSPEC);
	ଯଦି (ଚାବି == ଖାଲି) {
		error("sshkey_new failed");
		ଯାଅ fail;
	}

	EVP_PKEY_free(ଚାବି->pkey);
	ଯଦି ((ଚାବି->pkey = EVP_PKEY_new()) == ଖାଲି)
		fatal("EVP_PKEY_new failed");
	ଯଦି (EVP_PKEY_set1_EC_ଚାବି(ଚାବି->pkey, ec) != 1)
		fatal("EVP_PKEY_set1_EC_KEY failed");
	ଚାବି->ecdsa_nid = nid;
	ଚାବି->type = ଚାବି_ECDSA;
	ଚାବି->flags |= SSHKEY_FLAG_EXT;
	ଯଦି (pkcs11_record_ଚାବି(p, slotidx, &ଚାବି_attr[0], ଚାବି))
		ଯାଅ fail;
	/* success */
	success = 0;
fail:
	ଯଦି (success != 0) {
		sshkey_free(ଚାବି);
		ଚାବି = ଖାଲି;
	}
	ପାଇଁ (i = 0; i < 3; i++)
		ମୁକ୍ତ(ଚାବି_attr[i].p_ମୂଲ୍ୟ);
	ଯଦି (ec)
		EC_ଚାବି_free(ec);
	ଯଦି (group)
		EC_GROUP_free(group);
	ଯଦି (octet)
		ASN1_OCTET_STRING_free(octet);

	ଫେରନ୍ତୁ (ଚାବି);
}

ସ୍ଥିର ସଂରଚନା sshkey *
pkcs11_fetch_rsa_pubkey(ସଂରଚନା pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 ଚାବି_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ଖାଲି;
	CK_RV			 rv;
	RSA			*rsa = ଖାଲି;
	BIGNUM			*rsa_n, *rsa_e;
	ସଂରଚନା sshkey		*ଚାବି = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			 i, success = -1;

	memset(&ଚାବି_attr, 0, ଆକାର(ଚାବି_attr));
	ଚାବି_attr[0].type = CKA_ID;
	ଚାବି_attr[1].type = CKA_MODULUS;
	ଚାବି_attr[2].type = CKA_PUBLIC_EXPONENT;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_ମୂଲ୍ୟ(session, *obj, ଚାବି_attr, 3);
	ଯଦି (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ଫେରନ୍ତୁ (ଖାଲି);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	ଯଦି (ଚାବି_attr[1].ul_ମୂଲ୍ୟ_Len == 0 ||
	    ଚାବି_attr[2].ul_ମୂଲ୍ୟ_Len == 0) {
		error("invalid attribute length");
		ଫେରନ୍ତୁ (ଖାଲି);
	}

	/* allocate buffers for attributes */
	ପାଇଁ (i = 0; i < 3; i++)
		ଯଦି (ଚାବି_attr[i].ul_ମୂଲ୍ୟ_Len > 0)
			ଚାବି_attr[i].p_ମୂଲ୍ୟ = xcalloc(1, ଚାବି_attr[i].ul_ମୂଲ୍ୟ_Len);

	/* retrieve ID, modulus and public exponent of RSA key */
	rv = f->C_Get_Attribute_ମୂଲ୍ୟ(session, *obj, ଚାବି_attr, 3);
	ଯଦି (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ଯାଅ fail;
	}

	rsa = RSA_new();
	ଯଦି (rsa == ଖାଲି) {
		error("RSA_new failed");
		ଯାଅ fail;
	}

	rsa_n = BN_bin2bn(ଚାବି_attr[1].p_ମୂଲ୍ୟ, ଚାବି_attr[1].ul_ମୂଲ୍ୟ_Len, ଖାଲି);
	rsa_e = BN_bin2bn(ଚାବି_attr[2].p_ମୂଲ୍ୟ, ଚାବି_attr[2].ul_ମୂଲ୍ୟ_Len, ଖାଲି);
	ଯଦି (rsa_n == ଖାଲି || rsa_e == ଖାଲି) {
		error("BN_bin2bn failed");
		ଯାଅ fail;
	}
	ଯଦି (!RSA_set0_ଚାବି(rsa, rsa_n, rsa_e, ଖାଲି))
		fatal_f("set key");
	rsa_n = rsa_e = ଖାଲି; /* transferred */

	ଚାବି = sshkey_new(ଚାବି_UNSPEC);
	ଯଦି (ଚାବି == ଖାଲି) {
		error("sshkey_new failed");
		ଯାଅ fail;
	}

	EVP_PKEY_free(ଚାବି->pkey);
	ଯଦି ((ଚାବି->pkey = EVP_PKEY_new()) == ଖାଲି)
		fatal("EVP_PKEY_new failed");
	ଯଦି (EVP_PKEY_set1_RSA(ଚାବି->pkey, rsa) != 1)
		fatal("EVP_PKEY_set1_RSA failed");
	ଚାବି->type = ଚାବି_RSA;
	ଚାବି->flags |= SSHKEY_FLAG_EXT;
	ଯଦି (EVP_PKEY_bits(ଚାବି->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE) {
		error_f("RSA key too small %d < minimum %d",
		    EVP_PKEY_bits(ଚାବି->pkey), SSH_RSA_MINIMUM_MODULUS_SIZE);
		ଯାଅ fail;
	}
	ଯଦି (pkcs11_record_ଚାବି(p, slotidx, &ଚାବି_attr[0], ଚାବି))
		ଯାଅ fail;
	/* success */
	success = 0;
fail:
	ପାଇଁ (i = 0; i < 3; i++)
		ମୁକ୍ତ(ଚାବି_attr[i].p_ମୂଲ୍ୟ);
	RSA_free(rsa);
	ଯଦି (success != 0) {
		sshkey_free(ଚାବି);
		ଚାବି = ଖାଲି;
	}
	ଫେରନ୍ତୁ ଚାବି;
}
#endif /* WITH_OPENSSL */

ସ୍ଥିର ସଂରଚନା sshkey *
pkcs11_fetch_ed25519_pubkey(ସଂରଚନା pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 ଚାବି_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ଖାଲି;
	CK_RV			 rv;
	ସଂରଚନା sshkey		*ଚାବି = ଖାଲି;
	ଅଚଳ unsigned ଅକ୍ଷର	*d = ଖାଲି;
	size_t			len;
	ଅକ୍ଷର			*hex = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			 success = -1, i;
	/* https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061180 */
	ଅଚଳ u_char		 id1[14] = {
		0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64,
		0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
	}; /* PrintableString { "edwards25519" } */
	ଅଚଳ u_char		 id2[5] = {
		0x06, 0x03, 0x2b, 0x65, 0x70,
	}; /* OBJECT_IDENTIFIER { 1.3.101.112 } */

	memset(&ଚାବି_attr, 0, ଆକାର(ଚାବି_attr));
	ଚାବି_attr[0].type = CKA_ID;
	ଚାବି_attr[1].type = CKA_EC_POINT; /* XXX or CKA_VALUE ? */
	ଚାବି_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_ମୂଲ୍ୟ(session, *obj, ଚାବି_attr, 3);
	ଯଦି (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ଫେରନ୍ତୁ (ଖାଲି);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	ଯଦି (ଚାବି_attr[1].ul_ମୂଲ୍ୟ_Len == 0 ||
	    ଚାବି_attr[2].ul_ମୂଲ୍ୟ_Len == 0) {
		error("invalid attribute length");
		ଫେରନ୍ତୁ (ଖାଲି);
	}

	/* allocate buffers for attributes */
	ପାଇଁ (i = 0; i < 3; i++) {
		ଯଦି (ଚାବି_attr[i].ul_ମୂଲ୍ୟ_Len > 0)
			ଚାବି_attr[i].p_ମୂଲ୍ୟ = xcalloc(1, ଚାବି_attr[i].ul_ମୂଲ୍ୟ_Len);
	}

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_ମୂଲ୍ୟ(session, *obj, ଚାବି_attr, 3);
	ଯଦି (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ଯାଅ fail;
	}

	/* Expect one of the supported identifiers in CKA_EC_PARAMS */
	d = (u_char *)ଚାବି_attr[2].p_ମୂଲ୍ୟ;
	len = ଚାବି_attr[2].ul_ମୂଲ୍ୟ_Len;
	ଯଦି ((len != ଆକାର(id1) || memcmp(d, id1, ଆକାର(id1)) != 0) &&
	    (len != ଆକାର(id2) || memcmp(d, id2, ଆକାର(id2)) != 0)) {
		hex = tohex(d, len);
		logit_f("unsupported CKA_EC_PARAMS: %s (len %zu)", hex, len);
		ଯାଅ fail;
	}

	/*
	 * Expect either a raw 32 byte pubkey or an OCTET STRING with
	 * a 32 byte pubkey in CKA_VALUE
	 */
	d = (u_char *)ଚାବି_attr[1].p_ମୂଲ୍ୟ;
	len = ଚାବି_attr[1].ul_ମୂଲ୍ୟ_Len;
	ଯଦି (len == ED25519_PK_SZ + 2 && d[0] == 0x04 && d[1] == ED25519_PK_SZ) {
		d += 2;
		len -= 2;
	}
	ଯଦି (len != ED25519_PK_SZ) {
		hex = tohex(ଚାବି_attr[1].p_ମୂଲ୍ୟ, ଚାବି_attr[1].ul_ମୂଲ୍ୟ_Len);
		logit_f("CKA_EC_POINT invalid octet str: %s (len %lu)",
		    hex, (u_long)ଚାବି_attr[1].ul_ମୂଲ୍ୟ_Len);
		ଯାଅ fail;
	}

	ଯଦି ((ଚାବି = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି)
		fatal_f("sshkey_new failed");
	ଚାବି->ed25519_pk = xmalloc(ED25519_PK_SZ);
	memcpy(ଚାବି->ed25519_pk, d, ED25519_PK_SZ);
	ଚାବି->type = ଚାବି_ED25519;
	ଚାବି->flags |= SSHKEY_FLAG_EXT;
	ଯଦି (pkcs11_record_ଚାବି(p, slotidx, &ଚାବି_attr[0], ଚାବି))
		ଯାଅ fail;
	/* success */
	success = 0;
 fail:
	ଯଦି (success != 0) {
		sshkey_free(ଚାବି);
		ଚାବି = ଖାଲି;
	}
	ମୁକ୍ତ(hex);
	ପାଇଁ (i = 0; i < 3; i++)
		ମୁକ୍ତ(ଚାବି_attr[i].p_ମୂଲ୍ୟ);
	ଫେରନ୍ତୁ ଚାବି;
}

#ifdef WITH_OPENSSL
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_fetch_x509_pubkey(ସଂରଚନା pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj, ସଂରଚନା sshkey **keyp, ଅକ୍ଷର **labelp)
{
	CK_ATTRIBUTE		 cert_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ଖାଲି;
	CK_RV			 rv;
	X509			*x509 = ଖାଲି;
	X509_NAME		*x509_name = ଖାଲି;
	EVP_PKEY		*evp;
	RSA			*rsa = ଖାଲି;
	EC_ଚାବି			*ec = ଖାଲି;
	ସଂରଚନା sshkey		*ଚାବି = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			 r, i, nid, success = -1;
	ଅଚଳ u_char		*cp;
	ଅକ୍ଷର			*subject = ଖାଲି;
#ifdef OPENSSL_HAS_ED25519
	size_t			len;
#endif /* OPENSSL_HAS_ED25519 */

	*keyp = ଖାଲି;
	*labelp = ଖାଲି;

	memset(&cert_attr, 0, ଆକାର(cert_attr));
	cert_attr[0].type = CKA_ID;
	cert_attr[1].type = CKA_SUBJECT;
	cert_attr[2].type = CKA_ମୂଲ୍ୟ;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_ମୂଲ୍ୟ(session, *obj, cert_attr, 3);
	ଯଦି (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ଫେରନ୍ତୁ -1;
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	ଯଦି (cert_attr[1].ul_ମୂଲ୍ୟ_Len == 0 ||
	    cert_attr[2].ul_ମୂଲ୍ୟ_Len == 0) {
		error("invalid attribute length");
		ଫେରନ୍ତୁ -1;
	}

	/* allocate buffers for attributes */
	ପାଇଁ (i = 0; i < 3; i++)
		ଯଦି (cert_attr[i].ul_ମୂଲ୍ୟ_Len > 0)
			cert_attr[i].p_ମୂଲ୍ୟ = xcalloc(1, cert_attr[i].ul_ମୂଲ୍ୟ_Len);

	/* retrieve ID, subject and value of certificate */
	rv = f->C_Get_Attribute_ମୂଲ୍ୟ(session, *obj, cert_attr, 3);
	ଯଦି (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		ଯାଅ out;
	}

	/* Decode DER-encoded cert subject */
	cp = cert_attr[1].p_ମୂଲ୍ୟ;
	ଯଦି ((x509_name = d2i_X509_NAME(ଖାଲି, &cp,
	    cert_attr[1].ul_ମୂଲ୍ୟ_Len)) == ଖାଲି ||
	    (subject = X509_NAME_oneline(x509_name, ଖାଲି, 0)) == ଖାଲି)
		subject = xstrdup("invalid subject");
	X509_NAME_free(x509_name);

	cp = cert_attr[2].p_ମୂଲ୍ୟ;
	ଯଦି ((x509 = d2i_X509(ଖାଲି, &cp, cert_attr[2].ul_ମୂଲ୍ୟ_Len)) == ଖାଲି) {
		error("d2i_x509 failed");
		ଯାଅ out;
	}

	ଯଦି ((evp = X509_get_pubkey(x509)) == ଖାଲି) {
		error("X509_get_pubkey failed");
		ଯାଅ out;
	}

	ଯଦି (EVP_PKEY_base_id(evp) == EVP_PKEY_RSA) {
		ଯଦି (EVP_PKEY_get0_RSA(evp) == ଖାଲି) {
			error("invalid x509; no rsa key");
			ଯାଅ out;
		}
		ଯଦି ((rsa = RSAPublic_ଚାବି_dup(EVP_PKEY_get0_RSA(evp))) == ଖାଲି) {
			error("RSAPublicKey_dup failed");
			ଯାଅ out;
		}

		ଚାବି = sshkey_new(ଚାବି_UNSPEC);
		ଯଦି (ଚାବି == ଖାଲି) {
			error("sshkey_new failed");
			ଯାଅ out;
		}

		EVP_PKEY_free(ଚାବି->pkey);
		ଯଦି ((ଚାବି->pkey = EVP_PKEY_new()) == ଖାଲି)
			fatal("EVP_PKEY_new failed");
		ଯଦି (EVP_PKEY_set1_RSA(ଚାବି->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		ଚାବି->type = ଚାବି_RSA;
		ଚାବି->flags |= SSHKEY_FLAG_EXT;
		ଯଦି (EVP_PKEY_bits(ଚାବି->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE) {
			error_f("RSA key too small %d < minimum %d",
			    EVP_PKEY_bits(ଚାବି->pkey),
			    SSH_RSA_MINIMUM_MODULUS_SIZE);
			ଯାଅ out;
		}
		ଯଦି (pkcs11_record_ଚାବି(p, slotidx, &cert_attr[0], ଚାବି))
			ଯାଅ out;
		/* success */
		success = 0;
	} ଅନ୍ୟଥା ଯଦି (EVP_PKEY_base_id(evp) == EVP_PKEY_EC) {
		ଯଦି (EVP_PKEY_get0_EC_ଚାବି(evp) == ଖାଲି) {
			error("invalid x509; no ec key");
			ଯାଅ out;
		}
		ଯଦି ((ec = EC_ଚାବି_dup(EVP_PKEY_get0_EC_ଚାବି(evp))) == ଖାଲି) {
			error("EC_KEY_dup failed");
			ଯାଅ out;
		}
		ଯଦି ((r = sshkey_ec_validate_public(EC_ଚାବି_get0_group(ec),
		    EC_ଚାବି_get0_public_ଚାବି(ec))) != 0) {
			error_fr(r, "invalid EC key");
			ଯାଅ out;
		}
		nid = sshkey_ecdsa_ଚାବି_to_nid(ec);
		ଯଦି (nid < 0) {
			error("couldn't get curve nid");
			ଯାଅ out;
		}

		ଚାବି = sshkey_new(ଚାବି_UNSPEC);
		ଯଦି (ଚାବି == ଖାଲି) {
			error("sshkey_new failed");
			ଯାଅ out;
		}

		EVP_PKEY_free(ଚାବି->pkey);
		ଯଦି ((ଚାବି->pkey = EVP_PKEY_new()) == ଖାଲି)
			fatal("EVP_PKEY_new failed");
		ଯଦି (EVP_PKEY_set1_EC_ଚାବି(ଚାବି->pkey, ec) != 1)
			fatal("EVP_PKEY_set1_EC_KEY failed");
		ଚାବି->ecdsa_nid = nid;
		ଚାବି->type = ଚାବି_ECDSA;
		ଚାବି->flags |= SSHKEY_FLAG_EXT;
		ଯଦି (pkcs11_record_ଚାବି(p, slotidx, &cert_attr[0], ଚାବି))
			ଯାଅ out;
		/* success */
		success = 0;
#ifdef OPENSSL_HAS_ED25519
	} ଅନ୍ୟଥା ଯଦି (EVP_PKEY_base_id(evp) == EVP_PKEY_ED25519) {
		ଯଦି ((ଚାବି = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି ||
		    (ଚାବି->ed25519_pk = calloc(1, ED25519_PK_SZ)) == ଖାଲି)
			fatal_f("allocation failed");
		len = ED25519_PK_SZ;
		ଯଦି (!EVP_PKEY_get_raw_public_ଚାବି(evp, ଚାବି->ed25519_pk, &len)) {
			ossl_error("EVP_PKEY_get_raw_public_key failed");
			ଯାଅ out;
		}
		ଯଦି (len != ED25519_PK_SZ) {
			error_f("incorrect returned public key "
			    "length for ed25519");
			ଯାଅ out;
		}
		ଚାବି->type = ଚାବି_ED25519;
		ଚାବି->flags |= SSHKEY_FLAG_EXT;
		ଯଦି (pkcs11_record_ଚାବି(p, slotidx, &cert_attr[0], ଚାବି))
			ଯାଅ out;
		/* success */
		success = 0;
#endif /* OPENSSL_HAS_ED25519 */
	} ଅନ୍ୟଥା {
		error("unknown certificate key type");
		ଯାଅ out;
	}
 out:
	ପାଇଁ (i = 0; i < 3; i++)
		ମୁକ୍ତ(cert_attr[i].p_ମୂଲ୍ୟ);
	X509_free(x509);
	RSA_free(rsa);
	EC_ଚାବି_free(ec);
	ଯଦି (success != 0 || ଚାବି == ଖାଲି) {
		sshkey_free(ଚାବି);
		ମୁକ୍ତ(subject);
		ଫେରନ୍ତୁ -1;
	}
	/* success */
	*keyp = ଚାବି;
	*labelp = subject;
	ଫେରନ୍ତୁ 0;
}
#endif /* WITH_OPENSSL */

ସ୍ଥିର ଶୂନ୍ୟ
note_ଚାବି(ସଂରଚନା pkcs11_provider *p, CK_ULONG slotidx, ଅଚଳ ଅକ୍ଷର *context,
    ସଂରଚନା sshkey *ଚାବି)
{
	ଅକ୍ଷର *fp;

	ଯଦି ((fp = sshkey_fingerprint(ଚାବି, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ଖାଲି) {
		error_f("sshkey_fingerprint failed");
		ଫେରନ୍ତୁ;
	}
	debug2("%s: provider %s slot %lu: %s %s", context, p->name,
	    (u_long)slotidx, sshkey_type(ଚାବି), fp);
	ମୁକ୍ତ(fp);
}

#ifdef WITH_OPENSSL /* libcrypto needed for certificate parsing */
/*
 * lookup certificates for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_fetch_certs(ସଂରଚନା pkcs11_provider *p, CK_ULONG slotidx,
    ସଂରଚନା sshkey ***keysp, ଅକ୍ଷର ***labelsp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *nkeys)
{
	ସଂରଚନା sshkey		*ଚାବି = ଖାଲି;
	CK_OBJECT_CLASS		 ଚାବି_class;
	CK_ATTRIBUTE		 ଚାବି_attr[1];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ଖାଲି;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			 ret = -1;
	ଅକ୍ଷର			*label;

	memset(&ଚାବି_attr, 0, ଆକାର(ଚାବି_attr));
	memset(&obj, 0, ଆକାର(obj));

	ଚାବି_class = CKO_CERTIFICATE;
	ଚାବି_attr[0].type = CKA_CLASS;
	ଚାବି_attr[0].p_ମୂଲ୍ୟ = &ଚାବି_class;
	ଚାବି_attr[0].ul_ମୂଲ୍ୟ_Len = ଆକାର(ଚାବି_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, ଚାବି_attr, 1);
	ଯଦି (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		ଯାଅ fail;
	}

	ଯେତେବେଳେ (1) {
		CK_CERTIFICATE_TYPE	ck_cert_type;

		rv = f->C_FindObjects(session, &obj, 1, &n);
		ଯଦି (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			ଯାଅ fail;
		}
		ଯଦି (n == 0)
			ଭାଙ୍ଗ;

		memset(&ck_cert_type, 0, ଆକାର(ck_cert_type));
		memset(&ଚାବି_attr, 0, ଆକାର(ଚାବି_attr));
		ଚାବି_attr[0].type = CKA_CERTIFICATE_TYPE;
		ଚାବି_attr[0].p_ମୂଲ୍ୟ = &ck_cert_type;
		ଚାବି_attr[0].ul_ମୂଲ୍ୟ_Len = ଆକାର(ck_cert_type);

		rv = f->C_Get_Attribute_ମୂଲ୍ୟ(session, obj, ଚାବି_attr, 1);
		ଯଦି (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			ଯାଅ fail;
		}

		ଚାବି = ଖାଲି;
		label = ଖାଲି;
		ବାଛ (ck_cert_type) {
		ସ୍ଥିତି CKC_X_509:
			ଯଦି (pkcs11_fetch_x509_pubkey(p, slotidx, &obj,
			    &ଚାବି, &label) != 0) {
				debug_f("failed to fetch key");
				ଜାରି;
			}
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			error("skipping unsupported certificate type %lu",
			    ck_cert_type);
			ଜାରି;
		}
		note_ଚାବି(p, slotidx, __func__, ଚାବି);
		ଯଦି (pkcs11_ଚାବି_included(keysp, nkeys, ଚାବି)) {
			debug2_f("key already included");
			sshkey_free(ଚାବି);
		} ଅନ୍ୟଥା {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, ଆକାର(ସଂରଚନା sshkey *));
			(*keysp)[*nkeys] = ଚାବି;
			ଯଦି (labelsp != ଖାଲି) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, ଆକାର(ଅକ୍ଷର *));
				(*labelsp)[*nkeys] = xstrdup((ଅକ୍ଷର *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_FindObjectsFinal(session);
	ଯଦି (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	ଫେରନ୍ତୁ (ret);
}
#endif /* WITH_OPENSSL */

/*
 * lookup public keys for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_fetch_ଚାବିଗୁଡ଼ିକ(ସଂରଚନା pkcs11_provider *p, CK_ULONG slotidx,
    ସଂରଚନା sshkey ***keysp, ଅକ୍ଷର ***labelsp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *nkeys)
{
	ସଂରଚନା sshkey		*ଚାବି = ଖାଲି;
	CK_OBJECT_CLASS		 ଚାବି_class;
	CK_ATTRIBUTE		 ଚାବି_attr[2];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ଖାଲି;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			 ret = -1;

	memset(&ଚାବି_attr, 0, ଆକାର(ଚାବି_attr));
	memset(&obj, 0, ଆକାର(obj));

	ଚାବି_class = CKO_PUBLIC_ଚାବି;
	ଚାବି_attr[0].type = CKA_CLASS;
	ଚାବି_attr[0].p_ମୂଲ୍ୟ = &ଚାବି_class;
	ଚାବି_attr[0].ul_ମୂଲ୍ୟ_Len = ଆକାର(ଚାବି_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_FindObjectsInit(session, ଚାବି_attr, 1);
	ଯଦି (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		ଯାଅ fail;
	}

	ଯେତେବେଳେ (1) {
		CK_ଚାବି_TYPE	ck_ଚାବି_type;
		CK_UTF8CHAR	label[256];

		rv = f->C_FindObjects(session, &obj, 1, &n);
		ଯଦି (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			ଯାଅ fail;
		}
		ଯଦି (n == 0)
			ଭାଙ୍ଗ;

		memset(&ck_ଚାବି_type, 0, ଆକାର(ck_ଚାବି_type));
		memset(&ଚାବି_attr, 0, ଆକାର(ଚାବି_attr));
		ଚାବି_attr[0].type = CKA_ଚାବି_TYPE;
		ଚାବି_attr[0].p_ମୂଲ୍ୟ = &ck_ଚାବି_type;
		ଚାବି_attr[0].ul_ମୂଲ୍ୟ_Len = ଆକାର(ck_ଚାବି_type);
		ଚାବି_attr[1].type = CKA_LABEL;
		ଚାବି_attr[1].p_ମୂଲ୍ୟ = &label;
		ଚାବି_attr[1].ul_ମୂଲ୍ୟ_Len = ଆକାର(label) - 1;

		rv = f->C_Get_Attribute_ମୂଲ୍ୟ(session, obj, ଚାବି_attr, 2);
		ଯଦି (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			ଯାଅ fail;
		}

		label[ଚାବି_attr[1].ul_ମୂଲ୍ୟ_Len] = '\0';

		ବାଛ (ck_ଚାବି_type) {
#ifdef WITH_OPENSSL
		ସ୍ଥିତି CKK_RSA:
			ଚାବି = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି CKK_ECDSA:
			ଚାବି = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			ଭାଙ୍ଗ;
#endif /* WITH_OPENSSL */
		ସ୍ଥିତି CKK_EC_EDWARDS:
			ଚାବି = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			/* XXX print key type? */
			ଚାବି = ଖାଲି;
			error("skipping unsupported key type 0x%lx",
			    (u_long)ck_ଚାବି_type);
		}

		ଯଦି (ଚାବି == ଖାଲି) {
			debug_f("failed to fetch key");
			ଜାରି;
		}
		note_ଚାବି(p, slotidx, __func__, ଚାବି);
		ଯଦି (pkcs11_ଚାବି_included(keysp, nkeys, ଚାବି)) {
			debug2_f("key already included");
			sshkey_free(ଚାବି);
		} ଅନ୍ୟଥା {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, ଆକାର(ସଂରଚନା sshkey *));
			(*keysp)[*nkeys] = ଚାବି;
			ଯଦି (labelsp != ଖାଲି) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, ଆକାର(ଅକ୍ଷର *));
				(*labelsp)[*nkeys] = xstrdup((ଅକ୍ଷର *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_FindObjectsFinal(session);
	ଯଦି (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	ଫେରନ୍ତୁ (ret);
}

#ifdef WITH_PKCS11_KEYGEN
#define FILL_ATTR(attr, idx, typ, val, len) \
	{ (attr[idx]).type=(typ); (attr[idx]).p_ମୂଲ୍ୟ=(val); (attr[idx]).ul_ମୂଲ୍ୟ_Len=len; idx++; }

ସ୍ଥିର ସଂରଚନା sshkey *
pkcs11_rsa_generate_private_ଚାବି(ସଂରଚନା pkcs11_provider *p, CK_ULONG slotidx,
    ଅକ୍ଷର *label, CK_ULONG bits, CK_BYTE keyid, uint32_t *err)
{
	ସଂରଚନା pkcs11_slotinfo	*si;
	ଅକ୍ଷର			*plabel = label ? label : "";
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_ଚାବି_2, priv_ଚାବି;
	CK_ATTRIBUTE		 tpub[16], tpriv[16];
	CK_MECHANISM		 mech = {
	    CKM_RSA_PKCS_ଚାବି_PAIR_GEN, NULL_PTR, 0
	};
	CK_BYTE			 pubExponent[] = {
	    0x01, 0x00, 0x01 /* RSA_F4 in bytes */
	};
	pubkey_filter[0].p_ମୂଲ୍ୟ = &pubkey_class;
	cert_filter[0].p_ମୂଲ୍ୟ = &cert_class;

	*err = 0;

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, ଆକାର(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, ଆକାର(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, ଆକାର(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    ଆକାର(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, ଆକାର(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, ଆକାର(false_val));
	FILL_ATTR(tpub, npub, CKA_MODULUS_BITS, &bits, ଆକାର(bits));
	FILL_ATTR(tpub, npub, CKA_PUBLIC_EXPONENT, pubExponent,
	    ଆକାର(pubExponent));
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, ଆକାର(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN,  &true_val, ଆକାର(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL,  plabel, strlen(plabel));
	FILL_ATTR(tpriv, npriv, CKA_PRIVATE,  &true_val, ଆକାର(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE,  &true_val, ଆକାର(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT,  &false_val, ଆକାର(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN,  &true_val, ଆକାର(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER,  &false_val,
	    ଆକାର(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP,  &false_val, ଆକାର(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE,  &false_val, ଆକାର(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, ଆକାର(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	ଯଦି ((rv = f->C_Generate_ଚାବି_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_ଚାବି_2, &priv_ଚାବି)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		ଫେରନ୍ତୁ ଖାଲି;
	}

	ଫେରନ୍ତୁ pkcs11_fetch_rsa_pubkey(p, slotidx, &pub_ଚାବି_2);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
h2i(ଅକ୍ଷର c)
{
	ଯଦି (c >= '0' && c <= '9')
		ଫେରନ୍ତୁ c - '0';
	ଅନ୍ୟଥା ଯଦି (c >= 'a' && c <= 'f')
		ଫେରନ୍ତୁ c - 'a' + 10;
	ଅନ୍ୟଥା ଯଦି (c >= 'A' && c <= 'F')
		ଫେରନ୍ତୁ c - 'A' + 10;
	ଅନ୍ୟଥା
		ଫେରନ୍ତୁ -1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_decode_hex(ଅଚଳ ଅକ୍ଷର *hex, unsigned ଅକ୍ଷର **dest, size_t *rlen)
{
	size_t	i, len;

	ଯଦି (dest)
		*dest = ଖାଲି;
	ଯଦି (rlen)
		*rlen = 0;

	ଯଦି ((len = strlen(hex)) % 2)
		ଫେରନ୍ତୁ -1;
	len /= 2;

	*dest = xmalloc(len);

	ପାଇଁ (i = 0; i < len; i++) {
		ପୂର୍ଣ୍ଣସଂଖ୍ୟା hi, lo;

		hi = h2i(hex[2 * i]);
		lo = h2i(hex[(2 * i) + 1]);
		ଯଦି (hi == -1 || lo == -1)
			ଫେରନ୍ତୁ -1;
		(*dest)[i] = (hi << 4) | lo;
	}

	ଯଦି (rlen)
		*rlen = len;

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ସଂରଚନା ec_curve_info {
	ଅଚଳ ଅକ୍ଷର	*name;
	ଅଚଳ ଅକ୍ଷର	*oid;
	ଅଚଳ ଅକ୍ଷର	*oid_encoded;
	size_t		 size;
} ec_curve_infos[] = {
	{"prime256v1",	"1.2.840.10045.3.1.7",	"06082A8648CE3D030107", 256},
	{"secp384r1",	"1.3.132.0.34",		"06052B81040022",	384},
	{"secp521r1",	"1.3.132.0.35",		"06052B81040023",	521},
	{ଖାଲି,		ଖାଲି,			ଖାଲି,			0},
};

ସ୍ଥିର ସଂରଚନା sshkey *
pkcs11_ecdsa_generate_private_ଚାବି(ସଂରଚନା pkcs11_provider *p, CK_ULONG slotidx,
    ଅକ୍ଷର *label, CK_ULONG bits, CK_BYTE keyid, uint32_t *err)
{
	ସଂରଚନା pkcs11_slotinfo	*si;
	ଅକ୍ଷର			*plabel = label ? label : "";
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			 i;
	size_t			 ecparams_size;
	unsigned ଅକ୍ଷର		*ecparams = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_ଚାବି_2, priv_ଚାବି;
	CK_MECHANISM		 mech = {
	    CKM_EC_ଚାବି_PAIR_GEN, NULL_PTR, 0
	};
	CK_ATTRIBUTE		 tpub[16], tpriv[16];

	*err = 0;

	ପାଇଁ (i = 0; ec_curve_infos[i].name; i++) {
		ଯଦି (ec_curve_infos[i].size == bits)
			ଭାଙ୍ଗ;
	}
	ଯଦି (!ec_curve_infos[i].name) {
		error_f("invalid key size %lu", bits);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି (pkcs11_decode_hex(ec_curve_infos[i].oid_encoded, &ecparams,
	    &ecparams_size) == -1) {
		error_f("invalid oid");
		ଫେରନ୍ତୁ ଖାଲି;
	}

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, ଆକାର(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, ଆକାର(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, ଆକାର(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    ଆକାର(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, ଆକାର(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, ଆକାର(false_val));
	FILL_ATTR(tpub, npub, CKA_EC_PARAMS, ecparams, ecparams_size);
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, ଆକାର(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN, &true_val, ଆକାର(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL, plabel, strlen(plabel));
	FILL_ATTR(tpriv, npriv, CKA_PRIVATE, &true_val, ଆକାର(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE, &true_val, ଆକାର(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT, &false_val, ଆକାର(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN, &true_val, ଆକାର(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER, &false_val,
	    ଆକାର(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP, &false_val, ଆକାର(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE, &false_val, ଆକାର(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, ଆକାର(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	ଯଦି ((rv = f->C_Generate_ଚାବି_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_ଚାବି_2, &priv_ଚାବି)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		ଫେରନ୍ତୁ ଖାଲି;
	}

	ଫେରନ୍ତୁ pkcs11_fetch_ecdsa_pubkey(p, slotidx, &pub_ଚାବି_2);
}
#endif /* WITH_PKCS11_KEYGEN */

/*
 * register a new provider, fails if provider already exists. if
 * keyp is provided, fetch keys.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_register_provider(ଅକ୍ଷର *provider_id, ଅକ୍ଷର *pin,
    ସଂରଚନା sshkey ***keyp, ଅକ୍ଷର ***labelsp,
    ସଂରଚନା pkcs11_provider **providerp, CK_ULONG user)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା nkeys, need_finalize = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;
	ସଂରଚନା pkcs11_provider *p = ଖାଲି;
	ଶୂନ୍ୟ *handle = ଖାଲି;
	CK_RV (*getfunctionlist)(CK_FUNCTION_LIST **);
	CK_RV rv;
	CK_FUNCTION_LIST *f = ଖାଲି;
	CK_TOKEN_INFO *token;
	CK_ULONG i;

	ଯଦି (providerp == ଖାଲି)
		ଯାଅ fail;
	*providerp = ଖାଲି;

	ଯଦି (keyp != ଖାଲି)
		*keyp = ଖାଲି;
	ଯଦି (labelsp != ଖାଲି)
		*labelsp = ଖାଲି;

	ଯଦି (pkcs11_provider_lookup(provider_id) != ଖାଲି) {
		debug_f("provider already registered: %s", provider_id);
		ଯାଅ fail;
	}
	ଯଦି (lib_contains_ପ୍ରତୀକ(provider_id, "C_GetFunctionList") != 0) {
		error("provider %s is not a PKCS11 library", provider_id);
		ଯାଅ fail;
	}
	/* open shared pkcs11-library */
	ଯଦି ((handle = dlopen(provider_id, RTLD_NOW)) == ଖାଲି) {
		error("dlopen %s failed: %s", provider_id, dlerror());
		ଯାଅ fail;
	}
	ଯଦି ((getfunctionlist = dlsym(handle, "C_GetFunctionList")) == ଖାଲି)
		fatal("dlsym(C_GetFunctionList) failed: %s", dlerror());
	p = xcalloc(1, ଆକାର(*p));
	p->name = xstrdup(provider_id);
	p->handle = handle;
	/* set up the pkcs11 callbacks */
	ଯଦି ((rv = (*getfunctionlist)(&f)) != CKR_OK) {
		error("C_GetFunctionList for provider %s failed: %lu",
		    provider_id, rv);
		ଯାଅ fail;
	}
	p->function_list = f;
	ଯଦି ((rv = f->C_Initialize(ଖାଲି)) != CKR_OK) {
		error("C_Initialize for provider %s failed: %lu",
		    provider_id, rv);
		ଯାଅ fail;
	}
	need_finalize = 1;
	ଯଦି ((rv = f->C_GetInfo(&p->info)) != CKR_OK) {
		error("C_GetInfo for provider %s failed: %lu",
		    provider_id, rv);
		ଯାଅ fail;
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
	ଯଦି ((rv = f->C_GetSlotList(CK_TRUE, ଖାଲି, &p->nslots)) != CKR_OK) {
		error("C_GetSlotList failed: %lu", rv);
		ଯାଅ fail;
	}
	ଯଦି (p->nslots == 0) {
		debug_f("provider %s returned no slots", provider_id);
		ret = -SSH_PKCS11_ERR_NO_SLOTS;
		ଯାଅ fail;
	}
	p->slotlist = xcalloc(p->nslots, ଆକାର(CK_SLOT_ID));
	ଯଦି ((rv = f->C_GetSlotList(CK_TRUE, p->slotlist, &p->nslots))
	    != CKR_OK) {
		error("C_GetSlotList for provider %s failed: %lu",
		    provider_id, rv);
		ଯାଅ fail;
	}
	p->slotinfo = xcalloc(p->nslots, ଆକାର(ସଂରଚନା pkcs11_slotinfo));
	p->valid = 1;
	nkeys = 0;
	ପାଇଁ (i = 0; i < p->nslots; i++) {
		token = &p->slotinfo[i].token;
		ଯଦି ((rv = f->C_GetTokenInfo(p->slotlist[i], token))
		    != CKR_OK) {
			error("C_GetTokenInfo for provider %s slot %lu "
			    "failed: %lu", provider_id, (u_long)i, rv);
			ଜାରି;
		}
		ଯଦି ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
			debug2_f("ignoring uninitialised token in "
			    "provider %s slot %lu", provider_id, (u_long)i);
			ଜାରି;
		}
		debug("provider %s slot %lu: label <%.*s> "
		    "manufacturerID <%.*s> model <%.*s> serial <%.*s> "
		    "flags 0x%lx",
		    provider_id, (unsigned long)i,
		    RMSPACE(token->label), RMSPACE(token->manufacturerID),
		    RMSPACE(token->model), RMSPACE(token->serial_ସଂଖ୍ୟା_2),
		    token->flags);
		/*
		 * open session, login with pin and retrieve public
		 * keys (if keyp is provided)
		 */
		ଯଦି ((ret = pkcs11_open_session(p, i, pin, user)) != 0 ||
		    keyp == ଖାଲି)
			ଜାରି;
		pkcs11_fetch_ଚାବିଗୁଡ଼ିକ(p, i, keyp, labelsp, &nkeys);
#ifdef WITH_OPENSSL
		pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#endif
		ଯଦି (nkeys == 0 && !p->slotinfo[i].logged_in &&
		    pkcs11_interactive) {
			/*
			 * Some tokens require login before they will
			 * expose keys.
			 */
			ଯଦି (pkcs11_login_slot(p, &p->slotinfo[i],
			    CKU_USER) < 0) {
				error("login failed");
				ଜାରି;
			}
			pkcs11_fetch_ଚାବିଗୁଡ଼ିକ(p, i, keyp, labelsp, &nkeys);
#ifdef WITH_OPENSSL
			pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#endif
		}
	}

	/* now owned by caller */
	*providerp = p;

	TAILQ_INSERT_TAIL(&pkcs11_providers, p, next);
	p->refcount++;	/* add to provider list */

	ଫେରନ୍ତୁ (nkeys);
fail:
	ଯଦି (need_finalize && (rv = f->C_Finalize(ଖାଲି)) != CKR_OK)
		error("C_Finalize for provider %s failed: %lu",
		    provider_id, rv);
	ଯଦି (p) {
		ମୁକ୍ତ(p->name);
		ମୁକ୍ତ(p->slotlist);
		ମୁକ୍ତ(p->slotinfo);
		ମୁକ୍ତ(p);
	}
	ଯଦି (handle)
		dlclose(handle);
	ଯଦି (ret > 0)
		ret = -1;
	ଫେରନ୍ତୁ (ret);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_init(ପୂର୍ଣ୍ଣସଂଖ୍ୟା interactive)
{
	debug3_f("called, interactive = %d", interactive);

	pkcs11_interactive = interactive;
	TAILQ_INIT(&pkcs11_providers);
	TAILQ_INIT(&pkcs11_ଚାବିଗୁଡ଼ିକ);
	ଫେରନ୍ତୁ (0);
}

/* unregister all providers, keys might still point to the providers */
ଶୂନ୍ୟ
pkcs11_terminate(ଶୂନ୍ୟ)
{
	ସଂରଚନା pkcs11_provider *p;
	ସଂରଚନା pkcs11_ଚାବି *k11;

	debug3_f("called");

	ଯେତେବେଳେ ((k11 = TAILQ_FIRST(&pkcs11_ଚାବିଗୁଡ଼ିକ)) != ଖାଲି) {
		TAILQ_REMOVE(&pkcs11_ଚାବିଗୁଡ଼ିକ, k11, next);
		pkcs11_k11_free(k11);
	}
	ଯେତେବେଳେ ((p = TAILQ_FIRST(&pkcs11_providers)) != ଖାଲି) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
}

/*
 * register a new provider and get number of keys hold by the token,
 * fails if provider already exists
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_add_provider(ଅକ୍ଷର *provider_id, ଅକ୍ଷର *pin, ସଂରଚନା sshkey ***keyp,
    ଅକ୍ଷର ***labelsp)
{
	ସଂରଚନା pkcs11_provider *p = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା nkeys;

	nkeys = pkcs11_register_provider(provider_id, pin, keyp, labelsp,
	    &p, CKU_USER);

	/* no keys found or some other error, de-register provider */
	ଯଦି (nkeys <= 0 && p != ଖାଲି) {
		TAILQ_REMOVE(&pkcs11_providers, p, next);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
	ଯଦି (nkeys == 0)
		debug_f("provider %s returned no keys", provider_id);

	ଫେରନ୍ତୁ (nkeys);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_sign(ସଂରଚନା sshkey *ଚାବି,
    u_char **sigp, size_t *lenp,
    ଅଚଳ u_char *data, size_t datalen,
    ଅଚଳ ଅକ୍ଷର *alg, ଅଚଳ ଅକ୍ଷର *sk_provider,
    ଅଚଳ ଅକ୍ଷର *sk_pin, u_int compat)
{
	ବାଛ (ଚାବି->type) {
#ifdef WITH_OPENSSL
	ସ୍ଥିତି ଚାବି_RSA:
	ସ୍ଥିତି ଚାବି_RSA_CERT:
		ଫେରନ୍ତୁ pkcs11_sign_rsa(ଚାବି, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	ସ୍ଥିତି ଚାବି_ECDSA:
	ସ୍ଥିତି ଚାବି_ECDSA_CERT:
		ଫେରନ୍ତୁ pkcs11_sign_ecdsa(ଚାବି, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
#endif /* WITH_OPENSSL */
	ସ୍ଥିତି ଚାବି_ED25519:
	ସ୍ଥିତି ଚାବି_ED25519_CERT:
		ଫେରନ୍ତୁ pkcs11_sign_ed25519(ଚାବି, sigp, lenp, data, datalen,
		    alg, sk_provider, sk_pin, compat);
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_TYPE_UNKNOWN;
	}
}

ଶୂନ୍ୟ
pkcs11_ଚାବି_free(ସଂରଚନା sshkey *ଚାବି)
{
	/* never called */
}

#ifdef WITH_PKCS11_KEYGEN
ସଂରଚନା sshkey *
pkcs11_gakp(ଅକ୍ଷର *provider_id, ଅକ୍ଷର *pin, unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା slotidx, ଅକ୍ଷର *label,
    unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, unsigned ପୂର୍ଣ୍ଣସଂଖ୍ୟା bits, unsigned ଅକ୍ଷର keyid, uint32_t *err)
{
	ସଂରଚନା pkcs11_provider	*p = ଖାଲି;
	ସଂରଚନା pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	ସଂରଚନା sshkey		*k = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			 ret = -1, reset_pin = 0, reset_provider = 0;
	CK_RV			 rv;

	*err = 0;

	ଯଦି ((p = pkcs11_provider_lookup(provider_id)) != ଖାଲି)
		debug_f("provider \"%s\" available", provider_id);
	ଅନ୍ୟଥା ଯଦି ((ret = pkcs11_register_provider(provider_id, pin, ଖାଲି, ଖାଲି,
	    &p, CKU_SO)) < 0) {
		debug_f("could not register provider %s", provider_id);
		ଯାଅ out;
	} ଅନ୍ୟଥା
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	ଯଦି ((rv = f->C_SetOperationState(session , pin, strlen(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} ଅନ୍ୟଥା
		reset_pin = 1;

	ବାଛ (type) {
	ସ୍ଥିତି ଚାବି_RSA:
		ଯଦି ((k = pkcs11_rsa_generate_private_ଚାବି(p, slotidx, label,
		    bits, keyid, err)) == ଖାଲି) {
			debug_f("failed to generate RSA key");
			ଯାଅ out;
		}
		ଭାଙ୍ଗ;
	ସ୍ଥିତି ଚାବି_ECDSA:
		ଯଦି ((k = pkcs11_ecdsa_generate_private_ଚାବି(p, slotidx, label,
		    bits, keyid, err)) == ଖାଲି) {
			debug_f("failed to generate ECDSA key");
			ଯାଅ out;
		}
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		*err = SSH_PKCS11_ERR_GENERIC;
		debug_f("unknown type %d", type);
		ଯାଅ out;
	}

out:
	ଯଦି (reset_pin)
		f->C_SetOperationState(session , ଖାଲି, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	ଯଦି (reset_provider)
		pkcs11_del_provider(provider_id);

	ଫେରନ୍ତୁ (k);
}

ସଂରଚନା sshkey *
pkcs11_destroy_keypair(ଅକ୍ଷର *provider_id, ଅକ୍ଷର *pin, unsigned long slotidx,
    unsigned ଅକ୍ଷର keyid, uint32_t *err)
{
	ସଂରଚନା pkcs11_provider	*p = ଖାଲି;
	ସଂରଚନା pkcs11_slotinfo	*si;
	ସଂରଚନା sshkey		*k = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା			 reset_pin = 0, reset_provider = 0;
	CK_ULONG		 nattrs;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_ATTRIBUTE		 attrs[16];
	CK_OBJECT_CLASS		 ଚାବି_class;
	CK_ଚାବି_TYPE		 ଚାବି_type;
	CK_OBJECT_HANDLE	 obj = CK_INVALID_HANDLE;
	CK_RV			 rv;

	*err = 0;

	ଯଦି ((p = pkcs11_provider_lookup(provider_id)) != ଖାଲି) {
		debug_f("using provider \"%s\"", provider_id);
	} ଅନ୍ୟଥା ଯଦି (pkcs11_register_provider(provider_id, pin, ଖାଲି, ଖାଲି, &p,
	    CKU_SO) < 0) {
		debug_f("could not register provider %s",
		    provider_id);
		ଯାଅ out;
	} ଅନ୍ୟଥା
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	ଯଦି ((rv = f->C_SetOperationState(session , pin, strlen(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} ଅନ୍ୟଥା
		reset_pin = 1;

	/* private key */
	nattrs = 0;
	ଚାବି_class = CKO_PRIVATE_ଚାବି;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &ଚାବି_class, ଆକାର(ଚାବି_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, ଆକାର(keyid));

	ଯଦି (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {
		ଯଦି ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy private key 0x%hhx",
			    keyid);
			*err = rv;
			ଯାଅ out;
		}
	}

	/* public key */
	nattrs = 0;
	ଚାବି_class = CKO_PUBLIC_ଚାବି;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &ଚାବି_class, ଆକାର(ଚାବି_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, ଆକାର(keyid));

	ଯଦି (pkcs11_find(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {

		/* get key type */
		nattrs = 0;
		FILL_ATTR(attrs, nattrs, CKA_ଚାବି_TYPE, &ଚାବି_type,
		    ଆକାର(ଚାବି_type));
		rv = f->C_Get_Attribute_ମୂଲ୍ୟ(session, obj, attrs, nattrs);
		ଯଦି (rv != CKR_OK) {
			debug_f("could not get key type of public key 0x%hhx",
			    keyid);
			*err = rv;
			ଚାବି_type = -1;
		}
		ବାଛ (ଚାବି_type) {
#ifdef WITH_OPENSSL
		ସ୍ଥିତି CKK_RSA:
			k = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି CKK_ECDSA:
			k = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			ଭାଙ୍ଗ;
#endif /* WITH_OPENSSL */
		ସ୍ଥିତି CKK_EC_EDWARDS:
			k = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			debug_f("unsupported key type %lu", (u_long)ଚାବି_type);
			ଭାଙ୍ଗ;
		}

		ଯଦି ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy public key 0x%hhx", keyid);
			*err = rv;
			ଯାଅ out;
		}
	}

out:
	ଯଦି (reset_pin)
		f->C_SetOperationState(session , ଖାଲି, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	ଯଦି (reset_provider)
		pkcs11_del_provider(provider_id);

	ଫେରନ୍ତୁ (k);
}
#endif /* WITH_PKCS11_KEYGEN */
#ଅନ୍ୟଥା /* ENABLE_PKCS11 */

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "ssh-pkcs11.h"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_init(ପୂର୍ଣ୍ଣସଂଖ୍ୟା interactive)
{
	error_f("PKCS#11 not supported");
	ଫେରନ୍ତୁ (-1);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_add_provider(ଅକ୍ଷର *provider_id, ଅକ୍ଷର *pin, ସଂରଚନା sshkey ***keyp,
    ଅକ୍ଷର ***labelsp)
{
	error_f("PKCS#11 not supported");
	ଫେରନ୍ତୁ (-1);
}

ଶୂନ୍ୟ
pkcs11_ଚାବି_free(ସଂରଚନା sshkey *ଚାବି)
{
	error_f("PKCS#11 not supported");
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
pkcs11_sign(ସଂରଚନା sshkey *ଚାବି,
    u_char **sigp, size_t *lenp,
    ଅଚଳ u_char *data, size_t datalen,
    ଅଚଳ ଅକ୍ଷର *alg, ଅଚଳ ଅକ୍ଷର *sk_provider,
    ଅଚଳ ଅକ୍ଷର *sk_pin, u_int compat)
{
	error_f("PKCS#11 not supported");
	ଫେରନ୍ତୁ SSH_ERR_FEATURE_UNSUPPORTED;
}

ଶୂନ୍ୟ
pkcs11_terminate(ଶୂନ୍ୟ)
{
	error_f("PKCS#11 not supported");
}
#endif /* ENABLE_PKCS11 */
