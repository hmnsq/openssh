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

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే ENABLE_PKCS11

#అన్తర్భావ <sys/time.h>

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/queue.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>

#అన్తర్భావ <string.h>
#అన్తర్భావ <dlfcn.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ "openbsd-compat/openssl-compat.h"
#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/ecdsa.h>
#అన్తర్భావ <openssl/x509.h>
#అన్తర్భావ <openssl/err.h>
#అయితే_ముగింపు

#నిర్వచించు CRYPTOKI_COMPAT
#అన్తర్భావ "pkcs11.h"

#నిర్వచించు SSHKEY_అంతర్గత
#అన్తర్భావ "sshkey.h"

#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssh-pkcs11.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "crypto_api.h"

నిర్మాణం pkcs11_slotinfo {
	CK_TOKEN_INFO		token;
	CK_SESSION_HANDLE	session;
	పూర్ణాంకం			logged_లోపల;
};

నిర్మాణం pkcs11_provider {
	అక్షరం			*name;
	శూన్య			*handle;
	CK_FUNCTION_LIST	*function_list;
	CK_INFO			info;
	CK_ULONG		nslots;
	CK_స్థానం_ID		*slotlist;
	నిర్మాణం pkcs11_slotinfo	*slotinfo;
	పూర్ణాంకం			valid;
	పూర్ణాంకం			refcount;
	TAILQ_ENTRY(pkcs11_provider) తదుపరి;
};

TAILQ_HEAD(, pkcs11_provider) pkcs11_providers;

నిర్మాణం pkcs11_కీలకం {
	నిర్మాణం sshbuf		*keyblob;
	నిర్మాణం pkcs11_provider	*provider;
	CK_ULONG		slotidx;
	అక్షరం			*keyid;
	పూర్ణాంకం			keyid_len;
	TAILQ_ENTRY(pkcs11_కీలకం)	తదుపరి;
};

TAILQ_HEAD(, pkcs11_కీలకం) pkcs11_కీలకాలు; /* XXX a tree would be better */

పూర్ణాంకం pkcs11_interactive = 0;

#నిర్వచితమైతే WITH_OPENSSL
స్థిర శూన్య
ossl_error(స్థిరరాశి అక్షరం *సందేశం)
{
	గుర్తులేని దీర్ఘ    e;

	error_f("%s", సందేశం);
	అయితే ((e = ERR_get_error()) != 0)
		error_f("libcrypto error: %s", ERR_error_string(e, ఖాళీ));
}
#అయితే_ముగింపు

/*
 * finalize a provider shared library, it's no longer usable.
 * however, there might still be keys referencing this provider,
 * so the actual freeing of memory is handled by pkcs11_provider_unref().
 * this is called when a provider gets unregistered.
 */
స్థిర శూన్య
pkcs11_provider_finalize(నిర్మాణం pkcs11_provider *p)
{
	CK_RV rv;
	CK_ULONG i;

	debug_f("provider \"%s\" refcount %d valid %d",
	    p->name, p->refcount, p->valid);
	ఒకవేళ (!p->valid)
		తిరిగి;
	కొరకు (i = 0; i < p->nslots; i++) {
		ఒకవేళ (p->slotinfo[i].session &&
		    (rv = p->function_list->C_CloseSession(
		    p->slotinfo[i].session)) != CKR_OK)
			error("C_CloseSession failed: %lu", rv);
	}
	ఒకవేళ ((rv = p->function_list->C_Finalize(ఖాళీ)) != CKR_OK)
		error("C_Finalize failed: %lu", rv);
	p->valid = 0;
	p->function_list = ఖాళీ;
	dlclose(p->handle);
}

/*
 * remove a reference to the provider.
 * called when a key gets destroyed or when the provider is unregistered.
 */
స్థిర శూన్య
pkcs11_provider_unref(నిర్మాణం pkcs11_provider *p)
{
	debug_f("provider \"%s\" refcount %d", p->name, p->refcount);
	ఒకవేళ (--p->refcount <= 0) {
		ఒకవేళ (p->valid)
			error_f("provider \"%s\" still valid", p->name);
		విడుదల(p->name);
		విడుదల(p->slotlist);
		విడుదల(p->slotinfo);
		విడుదల(p);
	}
}

/* lookup provider by name */
స్థిర నిర్మాణం pkcs11_provider *
pkcs11_provider_lookup(అక్షరం *provider_id)
{
	నిర్మాణం pkcs11_provider *p;

	TAILQ_FOREACH(p, &pkcs11_providers, తదుపరి) {
		debug("check provider \"%s\"", p->name);
		ఒకవేళ (!strcmp(provider_id, p->name))
			తిరిగి (p);
	}
	తిరిగి (ఖాళీ);
}

/* unregister provider by name */
పూర్ణాంకం
pkcs11_del_provider(అక్షరం *provider_id)
{
	నిర్మాణం pkcs11_provider *p;

	ఒకవేళ ((p = pkcs11_provider_lookup(provider_id)) != ఖాళీ) {
		TAILQ_REMOVE(&pkcs11_providers, p, తదుపరి);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
		తిరిగి (0);
	}
	తిరిగి (-1);
}

/* release a wrapped object */
స్థిర శూన్య
pkcs11_k11_free(నిర్మాణం pkcs11_కీలకం *k11)
{
	ఒకవేళ (k11 == ఖాళీ)
		తిరిగి;
	ఒకవేళ (k11->provider)
		pkcs11_provider_unref(k11->provider);
	విడుదల(k11->keyid);
	sshbuf_free(k11->keyblob);
	విడుదల(k11);
}

/* find a single 'obj' for given attributes */
స్థిర పూర్ణాంకం
pkcs11_కనుగొను(నిర్మాణం pkcs11_provider *p, CK_ULONG slotidx, CK_ATTRIBUTE *attr,
    CK_ULONG nattr, CK_OBJECT_HANDLE *obj)
{
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	session;
	CK_ULONG		nfound = 0;
	CK_RV			rv;
	పూర్ణాంకం			ret = -1;

	f = p->function_list;
	session = p->slotinfo[slotidx].session;
	ఒకవేళ ((rv = f->C_కనుగొను_Objects_Init(session, attr, nattr)) != CKR_OK) {
		error("C_FindObjectsInit failed (nattr %lu): %lu", nattr, rv);
		తిరిగి (-1);
	}
	ఒకవేళ ((rv = f->C_కనుగొను_Objects(session, obj, 1, &nfound)) != CKR_OK ||
	    nfound != 1) {
		debug("C_FindObjects failed (nfound %lu nattr %lu): %lu",
		    nfound, nattr, rv);
	} లేకపోతే
		ret = 0;
	ఒకవేళ ((rv = f->C_కనుగొను_Objects_Final(session)) != CKR_OK)
		error("C_FindObjectsFinal failed: %lu", rv);
	తిరిగి (ret);
}

స్థిర పూర్ణాంకం
pkcs11_login_స్థానం(నిర్మాణం pkcs11_provider *provider, నిర్మాణం pkcs11_slotinfo *si,
    CK_USER_TYPE type)
{
	అక్షరం			*pin = ఖాళీ, prompt[1024];
	CK_RV			 rv;

	ఒకవేళ (provider == ఖాళీ || si == ఖాళీ || !provider->valid) {
		error("no pkcs11 (valid) provider found");
		తిరిగి (-1);
	}

	ఒకవేళ (!pkcs11_interactive) {
		error("need pin entry%s",
		    (si->token.flags & CKF_PROTECTED_AUTHENTICATION_మార్గం) ?
		    " on reader keypad" : "");
		తిరిగి (-1);
	}
	ఒకవేళ (si->token.flags & CKF_PROTECTED_AUTHENTICATION_మార్గం)
		verbose("Deferring PIN entry to reader keypad.");
	లేకపోతే {
		snprintf(prompt, పరిమాణం(prompt), "Enter PIN for '%s': ",
		    si->token.label);
		ఒకవేళ ((pin = read_passphrase(prompt, RP_ALLOW_EOF)) == ఖాళీ) {
			debug_f("no pin specified");
			తిరిగి (-1);	/* bail out */
		}
	}
	rv = provider->function_list->C_Login(si->session, type, (u_char *)pin,
	    (pin != ఖాళీ) ? అక్షరశ్రేణి_పొడవు(pin) : 0);
	ఒకవేళ (pin != ఖాళీ)
		freezero(pin, అక్షరశ్రేణి_పొడవు(pin));

	ఎంపిక (rv) {
	స్థితి CKR_OK:
	స్థితి CKR_USER_ALREADY_LOGGED_లోపల:
		/* success */
		ఆపు;
	స్థితి CKR_PIN_LEN_RANGE:
		error("PKCS#11 login failed: PIN length out of range");
		తిరిగి -1;
	స్థితి CKR_PIN_INCORRECT:
		error("PKCS#11 login failed: PIN incorrect");
		తిరిగి -1;
	స్థితి CKR_PIN_LOCKED:
		error("PKCS#11 login failed: PIN locked");
		తిరిగి -1;
	అప్రమేయ:
		error("PKCS#11 login failed: error %lu", rv);
		తిరిగి -1;
	}
	si->logged_లోపల = 1;
	తిరిగి (0);
}

స్థిర పూర్ణాంకం
pkcs11_login(నిర్మాణం pkcs11_కీలకం *k11, CK_USER_TYPE type)
{
	ఒకవేళ (k11 == ఖాళీ || k11->provider == ఖాళీ || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		తిరిగి (-1);
	}

	తిరిగి pkcs11_login_స్థానం(k11->provider,
	    &k11->provider->slotinfo[k11->slotidx], type);
}


స్థిర పూర్ణాంకం
pkcs11_check_obj_bool_attrib(నిర్మాణం pkcs11_కీలకం *k11, CK_OBJECT_HANDLE obj,
    CK_ATTRIBUTE_TYPE type, పూర్ణాంకం *val)
{
	నిర్మాణం pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_BBOOL		flag = 0;
	CK_ATTRIBUTE		attr;
	CK_RV			 rv;

	*val = 0;

	ఒకవేళ (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		తిరిగి (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	attr.type = type;
	attr.p_విలువ = &flag;
	attr.ul_విలువ_Len = పరిమాణం(flag);

	rv = f->C_Get_Attribute_విలువ(si->session, obj, &attr, 1);
	ఒకవేళ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		తిరిగి (-1);
	}
	*val = flag != 0;
	debug_f("provider \"%s\" slot %lu object %lu: attrib %lu = %d",
	    k11->provider->name, k11->slotidx, obj, type, *val);
	తిరిగి (0);
}

స్థిర పూర్ణాంకం
pkcs11_get_కీలకం(నిర్మాణం pkcs11_కీలకం *k11, CK_MECHANISM_TYPE mech_type)
{
	నిర్మాణం pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_OBJECT_HANDLE	 obj;
	CK_RV			 rv;
	CK_OBJECT_CLASS		 వ్యక్తిగత_కీలకం_class;
	CK_BBOOL		 true_val;
	CK_MECHANISM		 mech;
	CK_ATTRIBUTE		 కీలకం_filter[3];
	పూర్ణాంకం			 always_auth = 0;
	పూర్ణాంకం			 did_login = 0;

	ఒకవేళ (!k11->provider || !k11->provider->valid) {
		error("no pkcs11 (valid) provider found");
		తిరిగి (-1);
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	ఒకవేళ ((si->token.flags & CKF_LOGIN_REQUIRED) && !si->logged_లోపల) {
		ఒకవేళ (pkcs11_login(k11, CKU_USER) < 0) {
			error("login failed");
			తిరిగి (-1);
		}
		did_login = 1;
	}

	memset(&కీలకం_filter, 0, పరిమాణం(కీలకం_filter));
	వ్యక్తిగత_కీలకం_class = CKO_వ్యక్తిగత_కీలకం;
	కీలకం_filter[0].type = CKA_CLASS;
	కీలకం_filter[0].p_విలువ = &వ్యక్తిగత_కీలకం_class;
	కీలకం_filter[0].ul_విలువ_Len = పరిమాణం(వ్యక్తిగత_కీలకం_class);

	కీలకం_filter[1].type = CKA_ID;
	కీలకం_filter[1].p_విలువ = k11->keyid;
	కీలకం_filter[1].ul_విలువ_Len = k11->keyid_len;

	true_val = CK_TRUE;
	కీలకం_filter[2].type = CKA_SIGN;
	కీలకం_filter[2].p_విలువ = &true_val;
	కీలకం_filter[2].ul_విలువ_Len = పరిమాణం(true_val);

	/* try to find object w/CKA_SIGN first, retry w/o */
	ఒకవేళ (pkcs11_కనుగొను(k11->provider, k11->slotidx, కీలకం_filter, 3, &obj) < 0 &&
	    pkcs11_కనుగొను(k11->provider, k11->slotidx, కీలకం_filter, 2, &obj) < 0) {
		error("cannot find private key");
		తిరిగి (-1);
	}

	memset(&mech, 0, పరిమాణం(mech));
	mech.mechanism = mech_type;
	mech.pParameter = NULL_PTR;
	mech.ulParameterLen = 0;

	ఒకవేళ ((rv = f->C_SignInit(si->session, &mech, obj)) != CKR_OK) {
		error("C_SignInit failed: %lu", rv);
		తిరిగి (-1);
	}

	pkcs11_check_obj_bool_attrib(k11, obj, CKA_ALWAYS_AUTHENTICATE,
	    &always_auth); /* ignore errors here */
	ఒకవేళ (always_auth && !did_login) {
		debug_f("always-auth key");
		ఒకవేళ (pkcs11_login(k11, CKU_CONTEXT_SPECIFIC) < 0) {
			error("login failed for always-auth key");
			తిరిగి (-1);
		}
	}

	తిరిగి (0);
}

/* record the key information later use lookup by keyblob */
స్థిర పూర్ణాంకం
pkcs11_రికార్డు_కీలకం(నిర్మాణం pkcs11_provider *provider, CK_ULONG slotidx,
    CK_ATTRIBUTE *keyid_attrib, నిర్మాణం sshkey *కీలకం)
{
	నిర్మాణం sshbuf *keyblob;
	నిర్మాణం pkcs11_కీలకం *k11;
	పూర్ణాంకం r;
	అక్షరం *hex;

	hex = tohex(keyid_attrib->p_విలువ, keyid_attrib->ul_విలువ_Len);
	debug_f("%s key: provider %s slot %lu keyid %s",
	    sshkey_type(కీలకం), provider->name, (u_long)slotidx, hex);
	విడుదల(hex);

	ఒకవేళ ((keyblob = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshkey_putb(కీలకం, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");

	/* Check if we've already recorded this key in a different slot */
	TAILQ_FOREACH(k11, &pkcs11_కీలకాలు, తదుపరి) {
		ఒకవేళ (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			hex = tohex(k11->keyid, k11->keyid_len);
			debug_f("Already seen this key at "
			    "provider %s slot %lu keyid %s",
			    k11->provider->name, k11->slotidx, hex);
			విడుదల(hex);
			sshbuf_free(keyblob);
			తిరిగి -1;
		}
	}

	k11 = xcalloc(1, పరిమాణం(*k11));
	k11->provider = provider;
	k11->keyblob = keyblob;
	provider->refcount++;	/* provider referenced by RSA key */
	k11->slotidx = slotidx;
	/* identify key object on smartcard */
	k11->keyid_len = keyid_attrib->ul_విలువ_Len;
	ఒకవేళ (k11->keyid_len > 0) {
		k11->keyid = xmalloc(k11->keyid_len);
		జ్ఞాపకం_నకలు(k11->keyid, keyid_attrib->p_విలువ, k11->keyid_len);
	}
	TAILQ_INSERT_TAIL(&pkcs11_కీలకాలు, k11, తదుపరి);

	తిరిగి 0;
}

/* retrieve the key information by keyblob */
స్థిర నిర్మాణం pkcs11_కీలకం *
pkcs11_lookup_కీలకం(నిర్మాణం sshkey *కీలకం)
{
	నిర్మాణం pkcs11_కీలకం *k11, *దొరికింది = ఖాళీ;
	నిర్మాణం sshbuf *keyblob;
	పూర్ణాంకం r;

	ఒకవేళ ((keyblob = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	ఒకవేళ ((r = sshkey_putb(కీలకం, keyblob)) != 0)
		fatal_fr(r, "sshkey_putb");
	TAILQ_FOREACH(k11, &pkcs11_కీలకాలు, తదుపరి) {
		ఒకవేళ (sshbuf_equals(k11->keyblob, keyblob) == 0) {
			దొరికింది = k11;
			ఆపు;
		}
	}
	sshbuf_free(keyblob);
	తిరిగి దొరికింది;
}

#నిర్వచితమైతే WITH_OPENSSL
/*
 * See:
 * https://datatracker.ietf.org/doc/html/rfc8017#section-9.2
 */

/*
 * id-sha1 OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
 *	oiw(14) secsig(3) algorithms(2) 26 }
 */
స్థిర స్థిరరాశి u_char id_sha1[] = {
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
స్థిర స్థిరరాశి u_char id_sha256[] = {
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
స్థిర స్థిరరాశి u_char id_sha512[] = {
	0x30, 0x51, /* type Sequence, length 0x51 (81) */
	0x30, 0x0d, /* type Sequence, length 0x0d (13) */
	0x06, 0x09, /* type OID, length 0x09 */
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, /* id-sha512 */
	0x05, 0x00, /* NULL */
	0x04, 0x40  /* Octet string, length 0x40 (64), followed by sha512 hash */
};

స్థిర పూర్ణాంకం
rsa_hash_alg_oid(పూర్ణాంకం hash_alg, స్థిరరాశి u_char **oidp, కొలత_t *oidlenp)
{
	ఎంపిక (hash_alg) {
	స్థితి SSH_DIGEST_SHA1:
		*oidp = id_sha1;
		*oidlenp = పరిమాణం(id_sha1);
		ఆపు;
	స్థితి SSH_DIGEST_SHA256:
		*oidp = id_sha256;
		*oidlenp = పరిమాణం(id_sha256);
		ఆపు;
	స్థితి SSH_DIGEST_SHA512:
		*oidp = id_sha512;
		*oidlenp = పరిమాణం(id_sha512);
		ఆపు;
	అప్రమేయ:
		తిరిగి SSH_ERR_INVALID_వాదం;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
pkcs11_sign_rsa(నిర్మాణం sshkey *కీలకం,
    u_char **sigp, కొలత_t *lenp,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen,
    స్థిరరాశి అక్షరం *alg, స్థిరరాశి అక్షరం *sk_provider,
    స్థిరరాశి అక్షరం *sk_pin, u_int compat)
{
	నిర్మాణం pkcs11_కీలకం	*k11;
	నిర్మాణం pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	పూర్ణాంకం			hashalg, r, diff, siglen, ret = -1;
	u_char			*oid_dgst = ఖాళీ, *sig = ఖాళీ;
	కొలత_t			dgst_len, oid_len, oid_dgst_len = 0;
	స్థిరరాశి u_char		*oid;

	ఒకవేళ (sigp != ఖాళీ)
		*sigp = ఖాళీ;
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = 0;

	ఒకవేళ ((k11 = pkcs11_lookup_కీలకం(కీలకం)) == ఖాళీ) {
		error_f("no key found");
		తిరిగి SSH_ERR_కీలకం_NOT_దొరికింది;
	}

	debug3_f("sign with alg \"%s\" using provider %s slotidx %lu",
	    alg == ఖాళీ ? "" : alg, k11->provider->name, (u_long)k11->slotidx);

	ఒకవేళ (pkcs11_get_కీలకం(k11, CKM_RSA_PKCS) == -1) {
		error("pkcs11_get_key failed");
		తిరిగి SSH_ERR_AGENT_FAILURE;
	}

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	ఒకవేళ ((siglen = EVP_PKEY_కొలత(కీలకం->pkey)) <= 0)
		తిరిగి SSH_ERR_INVALID_వాదం;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* Determine hash algorithm and OID for signature */
	ఒకవేళ (alg == ఖాళీ || *alg == '\0')
		hashalg = SSH_DIGEST_SHA1;
	లేకపోతే ఒకవేళ ((hashalg = ssh_rsa_hash_id_from_keyname(alg)) == -1)
		fatal_f("couldn't determine RSA hash alg \"%s\"", alg);
	ఒకవేళ ((r = rsa_hash_alg_oid(hashalg, &oid, &oid_len)) != 0)
		fatal_fr(r, "rsa_hash_alg_oid failed");
	ఒకవేళ ((dgst_len = ssh_digest_బైట్లు(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);

	/* Prepare { oid || digest } */
	oid_dgst_len = oid_len + dgst_len;
	oid_dgst = xcalloc(1, oid_dgst_len);
	జ్ఞాపకం_నకలు(oid_dgst, oid, oid_len);
	ఒకవేళ ((r = ssh_digest_జ్ఞాపకం(hashalg, దత్తాంశం, datalen,
	    oid_dgst + oid_len, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	ఒకవేళ ((rv = f->C_Sign(si->session, (CK_BYTE *)oid_dgst,
	    oid_dgst_len, sig, &slen)) != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		వెళ్ళు పూర్తి;
	}

	ఒకవేళ (slen < (CK_ULONG)siglen) {
		diff = siglen - slen;
		debug3_f("repack %lu < %d (diff %d)",
		    (u_long)slen, siglen, diff);
		memmove(sig + diff, sig, slen);
		explicit_bzero(sig, diff);
	} లేకపోతే ఒకవేళ (slen > (కొలత_t)siglen)
		fatal_f("bad C_Sign length");

	ఒకవేళ ((ret = ssh_rsa_encode_store_sig(hashalg, sig, siglen,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 పూర్తి:
	freezero(oid_dgst, oid_dgst_len);
	విడుదల(sig);
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
pkcs11_sign_ecdsa(నిర్మాణం sshkey *కీలకం,
    u_char **sigp, కొలత_t *lenp,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen,
    స్థిరరాశి అక్షరం *alg, స్థిరరాశి అక్షరం *sk_provider,
    స్థిరరాశి అక్షరం *sk_pin, u_int compat)
{
	నిర్మాణం pkcs11_కీలకం	*k11;
	నిర్మాణం pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0, bnlen;
	CK_RV			rv;
	BIGNUM			*sig_r = ఖాళీ, *sig_s = ఖాళీ;
	u_char			*sig = ఖాళీ, *dgst = ఖాళీ;
	కొలత_t			dgst_len = 0;
	పూర్ణాంకం			hashalg, ret = -1, r, siglen;

	ఒకవేళ (sigp != ఖాళీ)
		*sigp = ఖాళీ;
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = 0;

	ఒకవేళ ((k11 = pkcs11_lookup_కీలకం(కీలకం)) == ఖాళీ) {
		error_f("no key found");
		తిరిగి SSH_ERR_కీలకం_NOT_దొరికింది;
	}

	ఒకవేళ (pkcs11_get_కీలకం(k11, CKM_ECDSA) == -1) {
		error("pkcs11_get_key failed");
		తిరిగి SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	/* Prepare digest to be signed */
	ఒకవేళ ((hashalg = sshkey_ec_nid_గమ్యం_hash_alg(కీలకం->ecdsa_nid)) == -1)
		fatal_f("couldn't determine ECDSA hash alg");
	ఒకవేళ ((dgst_len = ssh_digest_బైట్లు(hashalg)) == 0)
		fatal_f("bad hash alg %d", hashalg);
	dgst = xcalloc(1, dgst_len);
	ఒకవేళ ((r = ssh_digest_జ్ఞాపకం(hashalg, దత్తాంశం, datalen,
	    dgst, dgst_len)) == -1)
		fatal_fr(r, "hash failed");

	ఒకవేళ ((siglen = EVP_PKEY_కొలత(కీలకం->pkey)) <= 0)
		తిరిగి SSH_ERR_INVALID_వాదం;
	sig = xmalloc(siglen);
	slen = (CK_ULONG)siglen;

	/* XXX handle CKR_BUFFER_TOO_SMALL */
	rv = f->C_Sign(si->session, (CK_BYTE *)dgst, dgst_len, sig, &slen);
	ఒకవేళ (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ (slen < 64 || slen > 132 || slen % 2) {
		error_f("bad signature length: %lu", (u_long)slen);
		వెళ్ళు పూర్తి;
	}
	bnlen = slen/2;
	ఒకవేళ ((sig_r = BN_bin2bn(sig, bnlen, ఖాళీ)) == ఖాళీ ||
	    (sig_s = BN_bin2bn(sig+bnlen, bnlen, ఖాళీ)) == ఖాళీ) {
		ossl_error("BN_bin2bn failed");
		వెళ్ళు పూర్తి;
	}

	ఒకవేళ ((ret = ssh_ecdsa_encode_store_sig(కీలకం, sig_r, sig_s,
	    sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 పూర్తి:
	freezero(dgst, dgst_len);
	BN_free(sig_r);
	BN_free(sig_s);
	విడుదల(sig);
	తిరిగి ret;
}
#అయితే_ముగింపు /* WITH_OPENSSL */

స్థిర పూర్ణాంకం
pkcs11_sign_ed25519(నిర్మాణం sshkey *కీలకం,
    u_char **sigp, కొలత_t *lenp,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen,
    స్థిరరాశి అక్షరం *alg, స్థిరరాశి అక్షరం *sk_provider,
    స్థిరరాశి అక్షరం *sk_pin, u_int compat)
{
	నిర్మాణం pkcs11_కీలకం	*k11;
	నిర్మాణం pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_ULONG		slen = 0;
	CK_RV			rv;
	u_char			*sig = ఖాళీ;
	CK_BYTE			*xdata = ఖాళీ;
	పూర్ణాంకం			ret = -1;

	ఒకవేళ (sigp != ఖాళీ)
		*sigp = ఖాళీ;
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = 0;

	ఒకవేళ ((k11 = pkcs11_lookup_కీలకం(కీలకం)) == ఖాళీ) {
		error_f("no key found");
		తిరిగి SSH_ERR_కీలకం_NOT_దొరికింది;
	}

	ఒకవేళ (pkcs11_get_కీలకం(k11, CKM_EDDSA) == -1) {
		error("pkcs11_get_key failed");
		తిరిగి SSH_ERR_AGENT_FAILURE;
	}

	debug3_f("sign using provider %s slotidx %lu",
	    k11->provider->name, (u_long)k11->slotidx);

	f = k11->provider->function_list;
	si = &k11->provider->slotinfo[k11->slotidx];

	xdata = xmalloc(datalen);
	జ్ఞాపకం_నకలు(xdata, దత్తాంశం, datalen);
	sig = xmalloc(crypto_sign_ed25519_బైట్లు);
	slen = crypto_sign_ed25519_బైట్లు;

	rv = f->C_Sign(si->session, xdata, datalen, sig, &slen);
	ఒకవేళ (rv != CKR_OK) {
		error("C_Sign failed: %lu", rv);
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ (slen != crypto_sign_ed25519_బైట్లు) {
		error_f("bad signature length: %lu", (u_long)slen);
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ ((ret = ssh_ed25519_encode_store_sig(sig, slen, sigp, lenp)) != 0)
		fatal_fr(ret, "couldn't store signature");

	/* success */
	ret = 0;
 పూర్తి:
	ఒకవేళ (xdata != ఖాళీ)
		freezero(xdata, datalen);
	విడుదల(sig);
	తిరిగి ret;
}

/* remove trailing spaces */
స్థిర అక్షరం *
rmspace(u_char *buf, కొలత_t len)
{
	కొలత_t i;

	ఒకవేళ (len == 0)
		తిరిగి buf;
	కొరకు (i = len - 1; i > 0; i--)
		ఒకవేళ (buf[i] == ' ')
			buf[i] = '\0';
		లేకపోతే
			ఆపు;
	తిరిగి buf;
}
/* Used to printf fixed-width, space-padded, unterminated strings using %.*s */
#నిర్వచించు RMSPACE(s) (పూర్ణాంకం)పరిమాణం(s), rmspace(s, పరిమాణం(s))

/*
 * open a pkcs11 session and login if required.
 * if pin == NULL we delay login until key use
 */
స్థిర పూర్ణాంకం
pkcs11_open_session(నిర్మాణం pkcs11_provider *p, CK_ULONG slotidx, అక్షరం *pin,
    CK_ULONG user)
{
	నిర్మాణం pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_RV			rv;
	CK_SESSION_HANDLE	session;
	పూర్ణాంకం			login_required, ret;

	f = p->function_list;
	si = &p->slotinfo[slotidx];

	login_required = si->token.flags & CKF_LOGIN_REQUIRED;

	/* fail early before opening session */
	ఒకవేళ (login_required && !pkcs11_interactive &&
	    (pin == ఖాళీ || అక్షరశ్రేణి_పొడవు(pin) == 0)) {
		error("pin required");
		తిరిగి (-SSH_PKCS11_ERR_PIN_REQUIRED);
	}
	ఒకవేళ ((rv = f->C_OpenSession(p->slotlist[slotidx], CKF_RW_SESSION|
	    CKF_SERIAL_SESSION, ఖాళీ, ఖాళీ, &session)) != CKR_OK) {
		error("C_OpenSession failed: %lu", rv);
		తిరిగి (-1);
	}
	ఒకవేళ (login_required && pin != ఖాళీ && అక్షరశ్రేణి_పొడవు(pin) != 0) {
		rv = f->C_Login(session, user, (u_char *)pin, అక్షరశ్రేణి_పొడవు(pin));
		ఒకవేళ (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_లోపల) {
			error("C_Login failed: %lu", rv);
			ret = (rv == CKR_PIN_LOCKED) ?
			    -SSH_PKCS11_ERR_PIN_LOCKED :
			    -SSH_PKCS11_ERR_LOGIN_FAIL;
			ఒకవేళ ((rv = f->C_CloseSession(session)) != CKR_OK)
				error("C_CloseSession failed: %lu", rv);
			తిరిగి (ret);
		}
		si->logged_లోపల = 1;
	}
	si->session = session;
	తిరిగి (0);
}

స్థిర పూర్ణాంకం
pkcs11_కీలకం_included(నిర్మాణం sshkey ***keysp, పూర్ణాంకం *nkeys, నిర్మాణం sshkey *కీలకం)
{
	పూర్ణాంకం i;

	కొరకు (i = 0; i < *nkeys; i++)
		ఒకవేళ (sshkey_equal(కీలకం, (*keysp)[i]))
			తిరిగి (1);
	తిరిగి (0);
}

#నిర్వచితమైతే WITH_OPENSSL
స్థిర నిర్మాణం sshkey *
pkcs11_fetch_ecdsa_pubkey(నిర్మాణం pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 కీలకం_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ఖాళీ;
	CK_RV			 rv;
	ASN1_OCTET_STRING	*octet = ఖాళీ;
	EC_కీలకం			*ec = ఖాళీ;
	EC_సమూహం		*సమూహం = ఖాళీ;
	నిర్మాణం sshkey		*కీలకం = ఖాళీ;
	స్థిరరాశి గుర్తులేని అక్షరం	*attrp = ఖాళీ;
	పూర్ణాంకం			 success = -1, r, i, nid;

	memset(&కీలకం_attr, 0, పరిమాణం(కీలకం_attr));
	కీలకం_attr[0].type = CKA_ID;
	కీలకం_attr[1].type = CKA_EC_బిందువు;
	కీలకం_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_విలువ(session, *obj, కీలకం_attr, 3);
	ఒకవేళ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		తిరిగి (ఖాళీ);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	ఒకవేళ (కీలకం_attr[1].ul_విలువ_Len == 0 ||
	    కీలకం_attr[2].ul_విలువ_Len == 0) {
		error("invalid attribute length");
		తిరిగి (ఖాళీ);
	}

	/* allocate buffers for attributes */
	కొరకు (i = 0; i < 3; i++)
		ఒకవేళ (కీలకం_attr[i].ul_విలువ_Len > 0)
			కీలకం_attr[i].p_విలువ = xcalloc(1, కీలకం_attr[i].ul_విలువ_Len);

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_విలువ(session, *obj, కీలకం_attr, 3);
	ఒకవేళ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		వెళ్ళు fail;
	}

	ec = EC_కీలకం_new();
	ఒకవేళ (ec == ఖాళీ) {
		error("EC_KEY_new failed");
		వెళ్ళు fail;
	}

	attrp = కీలకం_attr[2].p_విలువ;
	సమూహం = d2i_ECPKParameters(ఖాళీ, &attrp, కీలకం_attr[2].ul_విలువ_Len);
	ఒకవేళ (సమూహం == ఖాళీ) {
		ossl_error("d2i_ECPKParameters failed");
		వెళ్ళు fail;
	}

	ఒకవేళ (EC_కీలకం_సమితి_సమూహం(ec, సమూహం) == 0) {
		ossl_error("EC_KEY_set_group failed");
		వెళ్ళు fail;
	}

	ఒకవేళ (కీలకం_attr[1].ul_విలువ_Len <= 2) {
		error("CKA_EC_POINT too small");
		వెళ్ళు fail;
	}

	attrp = కీలకం_attr[1].p_విలువ;
	octet = d2i_ASN1_OCTET_STRING(ఖాళీ, &attrp, కీలకం_attr[1].ul_విలువ_Len);
	ఒకవేళ (octet == ఖాళీ) {
		ossl_error("d2i_ASN1_OCTET_STRING failed");
		వెళ్ళు fail;
	}
	attrp = ASN1_STRING_get0_దత్తాంశం(octet);
	ఒకవేళ (o2i_ECPublic_కీలకం(&ec, &attrp, ASN1_STRING_నిడివి(octet)) == ఖాళీ) {
		ossl_error("o2i_ECPublicKey failed");
		వెళ్ళు fail;
	}
	ఒకవేళ ((r = sshkey_ec_validate_ప్రజా(EC_కీలకం_get0_సమూహం(ec),
	    EC_కీలకం_get0_ప్రజా_కీలకం(ec))) != 0) {
		error_fr(r, "invalid EC key");
		వెళ్ళు fail;
	}

	nid = sshkey_ecdsa_కీలకం_గమ్యం_nid(ec);
	ఒకవేళ (nid < 0) {
		error("couldn't get curve nid");
		వెళ్ళు fail;
	}

	కీలకం = sshkey_new(కీలకం_UNSPEC);
	ఒకవేళ (కీలకం == ఖాళీ) {
		error("sshkey_new failed");
		వెళ్ళు fail;
	}

	EVP_PKEY_free(కీలకం->pkey);
	ఒకవేళ ((కీలకం->pkey = EVP_PKEY_new()) == ఖాళీ)
		fatal("EVP_PKEY_new failed");
	ఒకవేళ (EVP_PKEY_set1_EC_కీలకం(కీలకం->pkey, ec) != 1)
		fatal("EVP_PKEY_set1_EC_KEY failed");
	కీలకం->ecdsa_nid = nid;
	కీలకం->type = కీలకం_ECDSA;
	కీలకం->flags |= SSHKEY_FLAG_EXT;
	ఒకవేళ (pkcs11_రికార్డు_కీలకం(p, slotidx, &కీలకం_attr[0], కీలకం))
		వెళ్ళు fail;
	/* success */
	success = 0;
fail:
	ఒకవేళ (success != 0) {
		sshkey_free(కీలకం);
		కీలకం = ఖాళీ;
	}
	కొరకు (i = 0; i < 3; i++)
		విడుదల(కీలకం_attr[i].p_విలువ);
	ఒకవేళ (ec)
		EC_కీలకం_free(ec);
	ఒకవేళ (సమూహం)
		EC_సమూహం_free(సమూహం);
	ఒకవేళ (octet)
		ASN1_OCTET_STRING_free(octet);

	తిరిగి (కీలకం);
}

స్థిర నిర్మాణం sshkey *
pkcs11_fetch_rsa_pubkey(నిర్మాణం pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 కీలకం_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ఖాళీ;
	CK_RV			 rv;
	RSA			*rsa = ఖాళీ;
	BIGNUM			*rsa_n, *rsa_e;
	నిర్మాణం sshkey		*కీలకం = ఖాళీ;
	పూర్ణాంకం			 i, success = -1;

	memset(&కీలకం_attr, 0, పరిమాణం(కీలకం_attr));
	కీలకం_attr[0].type = CKA_ID;
	కీలకం_attr[1].type = CKA_MODULUS;
	కీలకం_attr[2].type = CKA_ప్రజా_EXPONENT;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_విలువ(session, *obj, కీలకం_attr, 3);
	ఒకవేళ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		తిరిగి (ఖాళీ);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	ఒకవేళ (కీలకం_attr[1].ul_విలువ_Len == 0 ||
	    కీలకం_attr[2].ul_విలువ_Len == 0) {
		error("invalid attribute length");
		తిరిగి (ఖాళీ);
	}

	/* allocate buffers for attributes */
	కొరకు (i = 0; i < 3; i++)
		ఒకవేళ (కీలకం_attr[i].ul_విలువ_Len > 0)
			కీలకం_attr[i].p_విలువ = xcalloc(1, కీలకం_attr[i].ul_విలువ_Len);

	/* retrieve ID, modulus and public exponent of RSA key */
	rv = f->C_Get_Attribute_విలువ(session, *obj, కీలకం_attr, 3);
	ఒకవేళ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		వెళ్ళు fail;
	}

	rsa = RSA_new();
	ఒకవేళ (rsa == ఖాళీ) {
		error("RSA_new failed");
		వెళ్ళు fail;
	}

	rsa_n = BN_bin2bn(కీలకం_attr[1].p_విలువ, కీలకం_attr[1].ul_విలువ_Len, ఖాళీ);
	rsa_e = BN_bin2bn(కీలకం_attr[2].p_విలువ, కీలకం_attr[2].ul_విలువ_Len, ఖాళీ);
	ఒకవేళ (rsa_n == ఖాళీ || rsa_e == ఖాళీ) {
		error("BN_bin2bn failed");
		వెళ్ళు fail;
	}
	ఒకవేళ (!RSA_set0_కీలకం(rsa, rsa_n, rsa_e, ఖాళీ))
		fatal_f("set key");
	rsa_n = rsa_e = ఖాళీ; /* transferred */

	కీలకం = sshkey_new(కీలకం_UNSPEC);
	ఒకవేళ (కీలకం == ఖాళీ) {
		error("sshkey_new failed");
		వెళ్ళు fail;
	}

	EVP_PKEY_free(కీలకం->pkey);
	ఒకవేళ ((కీలకం->pkey = EVP_PKEY_new()) == ఖాళీ)
		fatal("EVP_PKEY_new failed");
	ఒకవేళ (EVP_PKEY_set1_RSA(కీలకం->pkey, rsa) != 1)
		fatal("EVP_PKEY_set1_RSA failed");
	కీలకం->type = కీలకం_RSA;
	కీలకం->flags |= SSHKEY_FLAG_EXT;
	ఒకవేళ (EVP_PKEY_బిట్లు(కీలకం->pkey) < SSH_RSA_MINIMUM_MODULUS_కొలత) {
		error_f("RSA key too small %d < minimum %d",
		    EVP_PKEY_బిట్లు(కీలకం->pkey), SSH_RSA_MINIMUM_MODULUS_కొలత);
		వెళ్ళు fail;
	}
	ఒకవేళ (pkcs11_రికార్డు_కీలకం(p, slotidx, &కీలకం_attr[0], కీలకం))
		వెళ్ళు fail;
	/* success */
	success = 0;
fail:
	కొరకు (i = 0; i < 3; i++)
		విడుదల(కీలకం_attr[i].p_విలువ);
	RSA_free(rsa);
	ఒకవేళ (success != 0) {
		sshkey_free(కీలకం);
		కీలకం = ఖాళీ;
	}
	తిరిగి కీలకం;
}
#అయితే_ముగింపు /* WITH_OPENSSL */

స్థిర నిర్మాణం sshkey *
pkcs11_fetch_ed25519_pubkey(నిర్మాణం pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj)
{
	CK_ATTRIBUTE		 కీలకం_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ఖాళీ;
	CK_RV			 rv;
	నిర్మాణం sshkey		*కీలకం = ఖాళీ;
	స్థిరరాశి గుర్తులేని అక్షరం	*d = ఖాళీ;
	కొలత_t			len;
	అక్షరం			*hex = ఖాళీ;
	పూర్ణాంకం			 success = -1, i;
	/* https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/os/pkcs11-curr-v3.0-os.html#_Toc30061180 */
	స్థిరరాశి u_char		 id1[14] = {
		0x13, 0x0c, 0x65, 0x64, 0x77, 0x61, 0x72, 0x64,
		0x73, 0x32, 0x35, 0x35, 0x31, 0x39,
	}; /* PrintableString { "edwards25519" } */
	స్థిరరాశి u_char		 id2[5] = {
		0x06, 0x03, 0x2b, 0x65, 0x70,
	}; /* OBJECT_IDENTIFIER { 1.3.101.112 } */

	memset(&కీలకం_attr, 0, పరిమాణం(కీలకం_attr));
	కీలకం_attr[0].type = CKA_ID;
	కీలకం_attr[1].type = CKA_EC_బిందువు; /* XXX or CKA_VALUE ? */
	కీలకం_attr[2].type = CKA_EC_PARAMS;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_విలువ(session, *obj, కీలకం_attr, 3);
	ఒకవేళ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		తిరిగి (ఖాళీ);
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	ఒకవేళ (కీలకం_attr[1].ul_విలువ_Len == 0 ||
	    కీలకం_attr[2].ul_విలువ_Len == 0) {
		error("invalid attribute length");
		తిరిగి (ఖాళీ);
	}

	/* allocate buffers for attributes */
	కొరకు (i = 0; i < 3; i++) {
		ఒకవేళ (కీలకం_attr[i].ul_విలువ_Len > 0)
			కీలకం_attr[i].p_విలువ = xcalloc(1, కీలకం_attr[i].ul_విలువ_Len);
	}

	/* retrieve ID, public point and curve parameters of EC key */
	rv = f->C_Get_Attribute_విలువ(session, *obj, కీలకం_attr, 3);
	ఒకవేళ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		వెళ్ళు fail;
	}

	/* Expect one of the supported identifiers in CKA_EC_PARAMS */
	d = (u_char *)కీలకం_attr[2].p_విలువ;
	len = కీలకం_attr[2].ul_విలువ_Len;
	ఒకవేళ ((len != పరిమాణం(id1) || memcmp(d, id1, పరిమాణం(id1)) != 0) &&
	    (len != పరిమాణం(id2) || memcmp(d, id2, పరిమాణం(id2)) != 0)) {
		hex = tohex(d, len);
		logit_f("unsupported CKA_EC_PARAMS: %s (len %zu)", hex, len);
		వెళ్ళు fail;
	}

	/*
	 * Expect either a raw 32 byte pubkey or an OCTET STRING with
	 * a 32 byte pubkey in CKA_VALUE
	 */
	d = (u_char *)కీలకం_attr[1].p_విలువ;
	len = కీలకం_attr[1].ul_విలువ_Len;
	ఒకవేళ (len == ED25519_PK_SZ + 2 && d[0] == 0x04 && d[1] == ED25519_PK_SZ) {
		d += 2;
		len -= 2;
	}
	ఒకవేళ (len != ED25519_PK_SZ) {
		hex = tohex(కీలకం_attr[1].p_విలువ, కీలకం_attr[1].ul_విలువ_Len);
		logit_f("CKA_EC_POINT invalid octet str: %s (len %lu)",
		    hex, (u_long)కీలకం_attr[1].ul_విలువ_Len);
		వెళ్ళు fail;
	}

	ఒకవేళ ((కీలకం = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ)
		fatal_f("sshkey_new failed");
	కీలకం->ed25519_pk = xmalloc(ED25519_PK_SZ);
	జ్ఞాపకం_నకలు(కీలకం->ed25519_pk, d, ED25519_PK_SZ);
	కీలకం->type = కీలకం_ED25519;
	కీలకం->flags |= SSHKEY_FLAG_EXT;
	ఒకవేళ (pkcs11_రికార్డు_కీలకం(p, slotidx, &కీలకం_attr[0], కీలకం))
		వెళ్ళు fail;
	/* success */
	success = 0;
 fail:
	ఒకవేళ (success != 0) {
		sshkey_free(కీలకం);
		కీలకం = ఖాళీ;
	}
	విడుదల(hex);
	కొరకు (i = 0; i < 3; i++)
		విడుదల(కీలకం_attr[i].p_విలువ);
	తిరిగి కీలకం;
}

#నిర్వచితమైతే WITH_OPENSSL
స్థిర పూర్ణాంకం
pkcs11_fetch_x509_pubkey(నిర్మాణం pkcs11_provider *p, CK_ULONG slotidx,
    CK_OBJECT_HANDLE *obj, నిర్మాణం sshkey **keyp, అక్షరం **labelp)
{
	CK_ATTRIBUTE		 cert_attr[3];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ఖాళీ;
	CK_RV			 rv;
	X509			*x509 = ఖాళీ;
	X509_NAME		*x509_name = ఖాళీ;
	EVP_PKEY		*evp;
	RSA			*rsa = ఖాళీ;
	EC_కీలకం			*ec = ఖాళీ;
	నిర్మాణం sshkey		*కీలకం = ఖాళీ;
	పూర్ణాంకం			 r, i, nid, success = -1;
	స్థిరరాశి u_char		*cp;
	అక్షరం			*subject = ఖాళీ;
#నిర్వచితమైతే OPENSSL_HAS_ED25519
	కొలత_t			len;
#అయితే_ముగింపు /* OPENSSL_HAS_ED25519 */

	*keyp = ఖాళీ;
	*labelp = ఖాళీ;

	memset(&cert_attr, 0, పరిమాణం(cert_attr));
	cert_attr[0].type = CKA_ID;
	cert_attr[1].type = CKA_SUBJECT;
	cert_attr[2].type = CKA_విలువ;

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	/* figure out size of the attributes */
	rv = f->C_Get_Attribute_విలువ(session, *obj, cert_attr, 3);
	ఒకవేళ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		తిరిగి -1;
	}

	/*
	 * Allow CKA_ID (always first attribute) to be empty, but
	 * ensure that none of the others are zero length.
	 * XXX assumes CKA_ID is always first.
	 */
	ఒకవేళ (cert_attr[1].ul_విలువ_Len == 0 ||
	    cert_attr[2].ul_విలువ_Len == 0) {
		error("invalid attribute length");
		తిరిగి -1;
	}

	/* allocate buffers for attributes */
	కొరకు (i = 0; i < 3; i++)
		ఒకవేళ (cert_attr[i].ul_విలువ_Len > 0)
			cert_attr[i].p_విలువ = xcalloc(1, cert_attr[i].ul_విలువ_Len);

	/* retrieve ID, subject and value of certificate */
	rv = f->C_Get_Attribute_విలువ(session, *obj, cert_attr, 3);
	ఒకవేళ (rv != CKR_OK) {
		error("C_GetAttributeValue failed: %lu", rv);
		వెళ్ళు బహిర్గతం;
	}

	/* Decode DER-encoded cert subject */
	cp = cert_attr[1].p_విలువ;
	ఒకవేళ ((x509_name = d2i_X509_NAME(ఖాళీ, &cp,
	    cert_attr[1].ul_విలువ_Len)) == ఖాళీ ||
	    (subject = X509_NAME_oneline(x509_name, ఖాళీ, 0)) == ఖాళీ)
		subject = xstrdup("invalid subject");
	X509_NAME_free(x509_name);

	cp = cert_attr[2].p_విలువ;
	ఒకవేళ ((x509 = d2i_X509(ఖాళీ, &cp, cert_attr[2].ul_విలువ_Len)) == ఖాళీ) {
		error("d2i_x509 failed");
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((evp = X509_get_pubkey(x509)) == ఖాళీ) {
		error("X509_get_pubkey failed");
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (EVP_PKEY_పునాది_id(evp) == EVP_PKEY_RSA) {
		ఒకవేళ (EVP_PKEY_get0_RSA(evp) == ఖాళీ) {
			error("invalid x509; no rsa key");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((rsa = RSAPublic_కీలకం_dup(EVP_PKEY_get0_RSA(evp))) == ఖాళీ) {
			error("RSAPublicKey_dup failed");
			వెళ్ళు బహిర్గతం;
		}

		కీలకం = sshkey_new(కీలకం_UNSPEC);
		ఒకవేళ (కీలకం == ఖాళీ) {
			error("sshkey_new failed");
			వెళ్ళు బహిర్గతం;
		}

		EVP_PKEY_free(కీలకం->pkey);
		ఒకవేళ ((కీలకం->pkey = EVP_PKEY_new()) == ఖాళీ)
			fatal("EVP_PKEY_new failed");
		ఒకవేళ (EVP_PKEY_set1_RSA(కీలకం->pkey, rsa) != 1)
			fatal("EVP_PKEY_set1_RSA failed");
		కీలకం->type = కీలకం_RSA;
		కీలకం->flags |= SSHKEY_FLAG_EXT;
		ఒకవేళ (EVP_PKEY_బిట్లు(కీలకం->pkey) < SSH_RSA_MINIMUM_MODULUS_కొలత) {
			error_f("RSA key too small %d < minimum %d",
			    EVP_PKEY_బిట్లు(కీలకం->pkey),
			    SSH_RSA_MINIMUM_MODULUS_కొలత);
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (pkcs11_రికార్డు_కీలకం(p, slotidx, &cert_attr[0], కీలకం))
			వెళ్ళు బహిర్గతం;
		/* success */
		success = 0;
	} లేకపోతే ఒకవేళ (EVP_PKEY_పునాది_id(evp) == EVP_PKEY_EC) {
		ఒకవేళ (EVP_PKEY_get0_EC_కీలకం(evp) == ఖాళీ) {
			error("invalid x509; no ec key");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((ec = EC_కీలకం_dup(EVP_PKEY_get0_EC_కీలకం(evp))) == ఖాళీ) {
			error("EC_KEY_dup failed");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = sshkey_ec_validate_ప్రజా(EC_కీలకం_get0_సమూహం(ec),
		    EC_కీలకం_get0_ప్రజా_కీలకం(ec))) != 0) {
			error_fr(r, "invalid EC key");
			వెళ్ళు బహిర్గతం;
		}
		nid = sshkey_ecdsa_కీలకం_గమ్యం_nid(ec);
		ఒకవేళ (nid < 0) {
			error("couldn't get curve nid");
			వెళ్ళు బహిర్గతం;
		}

		కీలకం = sshkey_new(కీలకం_UNSPEC);
		ఒకవేళ (కీలకం == ఖాళీ) {
			error("sshkey_new failed");
			వెళ్ళు బహిర్గతం;
		}

		EVP_PKEY_free(కీలకం->pkey);
		ఒకవేళ ((కీలకం->pkey = EVP_PKEY_new()) == ఖాళీ)
			fatal("EVP_PKEY_new failed");
		ఒకవేళ (EVP_PKEY_set1_EC_కీలకం(కీలకం->pkey, ec) != 1)
			fatal("EVP_PKEY_set1_EC_KEY failed");
		కీలకం->ecdsa_nid = nid;
		కీలకం->type = కీలకం_ECDSA;
		కీలకం->flags |= SSHKEY_FLAG_EXT;
		ఒకవేళ (pkcs11_రికార్డు_కీలకం(p, slotidx, &cert_attr[0], కీలకం))
			వెళ్ళు బహిర్గతం;
		/* success */
		success = 0;
#నిర్వచితమైతే OPENSSL_HAS_ED25519
	} లేకపోతే ఒకవేళ (EVP_PKEY_పునాది_id(evp) == EVP_PKEY_ED25519) {
		ఒకవేళ ((కీలకం = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ ||
		    (కీలకం->ed25519_pk = సున్నా_జ్ఞాపకం_ఇవ్వు(1, ED25519_PK_SZ)) == ఖాళీ)
			fatal_f("allocation failed");
		len = ED25519_PK_SZ;
		ఒకవేళ (!EVP_PKEY_get_raw_ప్రజా_కీలకం(evp, కీలకం->ed25519_pk, &len)) {
			ossl_error("EVP_PKEY_get_raw_public_key failed");
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (len != ED25519_PK_SZ) {
			error_f("incorrect returned public key "
			    "length for ed25519");
			వెళ్ళు బహిర్గతం;
		}
		కీలకం->type = కీలకం_ED25519;
		కీలకం->flags |= SSHKEY_FLAG_EXT;
		ఒకవేళ (pkcs11_రికార్డు_కీలకం(p, slotidx, &cert_attr[0], కీలకం))
			వెళ్ళు బహిర్గతం;
		/* success */
		success = 0;
#అయితే_ముగింపు /* OPENSSL_HAS_ED25519 */
	} లేకపోతే {
		error("unknown certificate key type");
		వెళ్ళు బహిర్గతం;
	}
 బహిర్గతం:
	కొరకు (i = 0; i < 3; i++)
		విడుదల(cert_attr[i].p_విలువ);
	X509_free(x509);
	RSA_free(rsa);
	EC_కీలకం_free(ec);
	ఒకవేళ (success != 0 || కీలకం == ఖాళీ) {
		sshkey_free(కీలకం);
		విడుదల(subject);
		తిరిగి -1;
	}
	/* success */
	*keyp = కీలకం;
	*labelp = subject;
	తిరిగి 0;
}
#అయితే_ముగింపు /* WITH_OPENSSL */

స్థిర శూన్య
note_కీలకం(నిర్మాణం pkcs11_provider *p, CK_ULONG slotidx, స్థిరరాశి అక్షరం *context,
    నిర్మాణం sshkey *కీలకం)
{
	అక్షరం *fp;

	ఒకవేళ ((fp = sshkey_fingerprint(కీలకం, SSH_FP_HASH_DEFAULT,
	    SSH_FP_DEFAULT)) == ఖాళీ) {
		error_f("sshkey_fingerprint failed");
		తిరిగి;
	}
	debug2("%s: provider %s slot %lu: %s %s", context, p->name,
	    (u_long)slotidx, sshkey_type(కీలకం), fp);
	విడుదల(fp);
}

#నిర్వచితమైతే WITH_OPENSSL /* libcrypto needed for certificate parsing */
/*
 * lookup certificates for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
స్థిర పూర్ణాంకం
pkcs11_fetch_certs(నిర్మాణం pkcs11_provider *p, CK_ULONG slotidx,
    నిర్మాణం sshkey ***keysp, అక్షరం ***labelsp, పూర్ణాంకం *nkeys)
{
	నిర్మాణం sshkey		*కీలకం = ఖాళీ;
	CK_OBJECT_CLASS		 కీలకం_class;
	CK_ATTRIBUTE		 కీలకం_attr[1];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ఖాళీ;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	పూర్ణాంకం			 ret = -1;
	అక్షరం			*label;

	memset(&కీలకం_attr, 0, పరిమాణం(కీలకం_attr));
	memset(&obj, 0, పరిమాణం(obj));

	కీలకం_class = CKO_CERTIFICATE;
	కీలకం_attr[0].type = CKA_CLASS;
	కీలకం_attr[0].p_విలువ = &కీలకం_class;
	కీలకం_attr[0].ul_విలువ_Len = పరిమాణం(కీలకం_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_కనుగొను_Objects_Init(session, కీలకం_attr, 1);
	ఒకవేళ (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		వెళ్ళు fail;
	}

	అయితే (1) {
		CK_CERTIFICATE_TYPE	ck_cert_type;

		rv = f->C_కనుగొను_Objects(session, &obj, 1, &n);
		ఒకవేళ (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			వెళ్ళు fail;
		}
		ఒకవేళ (n == 0)
			ఆపు;

		memset(&ck_cert_type, 0, పరిమాణం(ck_cert_type));
		memset(&కీలకం_attr, 0, పరిమాణం(కీలకం_attr));
		కీలకం_attr[0].type = CKA_CERTIFICATE_TYPE;
		కీలకం_attr[0].p_విలువ = &ck_cert_type;
		కీలకం_attr[0].ul_విలువ_Len = పరిమాణం(ck_cert_type);

		rv = f->C_Get_Attribute_విలువ(session, obj, కీలకం_attr, 1);
		ఒకవేళ (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			వెళ్ళు fail;
		}

		కీలకం = ఖాళీ;
		label = ఖాళీ;
		ఎంపిక (ck_cert_type) {
		స్థితి CKC_X_509:
			ఒకవేళ (pkcs11_fetch_x509_pubkey(p, slotidx, &obj,
			    &కీలకం, &label) != 0) {
				debug_f("failed to fetch key");
				కొనసాగు;
			}
			ఆపు;
		అప్రమేయ:
			error("skipping unsupported certificate type %lu",
			    ck_cert_type);
			కొనసాగు;
		}
		note_కీలకం(p, slotidx, __func__, కీలకం);
		ఒకవేళ (pkcs11_కీలకం_included(keysp, nkeys, కీలకం)) {
			debug2_f("key already included");
			sshkey_free(కీలకం);
		} లేకపోతే {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, పరిమాణం(నిర్మాణం sshkey *));
			(*keysp)[*nkeys] = కీలకం;
			ఒకవేళ (labelsp != ఖాళీ) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, పరిమాణం(అక్షరం *));
				(*labelsp)[*nkeys] = xstrdup((అక్షరం *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_కనుగొను_Objects_Final(session);
	ఒకవేళ (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	తిరిగి (ret);
}
#అయితే_ముగింపు /* WITH_OPENSSL */

/*
 * lookup public keys for token in slot identified by slotidx,
 * add 'wrapped' public keys to the 'keysp' array and increment nkeys.
 * keysp points to an (possibly empty) array with *nkeys keys.
 */
స్థిర పూర్ణాంకం
pkcs11_fetch_కీలకాలు(నిర్మాణం pkcs11_provider *p, CK_ULONG slotidx,
    నిర్మాణం sshkey ***keysp, అక్షరం ***labelsp, పూర్ణాంకం *nkeys)
{
	నిర్మాణం sshkey		*కీలకం = ఖాళీ;
	CK_OBJECT_CLASS		 కీలకం_class;
	CK_ATTRIBUTE		 కీలకం_attr[2];
	CK_SESSION_HANDLE	 session;
	CK_FUNCTION_LIST	*f = ఖాళీ;
	CK_RV			 rv;
	CK_OBJECT_HANDLE	 obj;
	CK_ULONG		 n = 0;
	పూర్ణాంకం			 ret = -1;

	memset(&కీలకం_attr, 0, పరిమాణం(కీలకం_attr));
	memset(&obj, 0, పరిమాణం(obj));

	కీలకం_class = CKO_ప్రజా_కీలకం;
	కీలకం_attr[0].type = CKA_CLASS;
	కీలకం_attr[0].p_విలువ = &కీలకం_class;
	కీలకం_attr[0].ul_విలువ_Len = పరిమాణం(కీలకం_class);

	session = p->slotinfo[slotidx].session;
	f = p->function_list;

	rv = f->C_కనుగొను_Objects_Init(session, కీలకం_attr, 1);
	ఒకవేళ (rv != CKR_OK) {
		error("C_FindObjectsInit failed: %lu", rv);
		వెళ్ళు fail;
	}

	అయితే (1) {
		CK_కీలకం_TYPE	ck_కీలకం_type;
		CK_UTF8CHAR	label[256];

		rv = f->C_కనుగొను_Objects(session, &obj, 1, &n);
		ఒకవేళ (rv != CKR_OK) {
			error("C_FindObjects failed: %lu", rv);
			వెళ్ళు fail;
		}
		ఒకవేళ (n == 0)
			ఆపు;

		memset(&ck_కీలకం_type, 0, పరిమాణం(ck_కీలకం_type));
		memset(&కీలకం_attr, 0, పరిమాణం(కీలకం_attr));
		కీలకం_attr[0].type = CKA_కీలకం_TYPE;
		కీలకం_attr[0].p_విలువ = &ck_కీలకం_type;
		కీలకం_attr[0].ul_విలువ_Len = పరిమాణం(ck_కీలకం_type);
		కీలకం_attr[1].type = CKA_LABEL;
		కీలకం_attr[1].p_విలువ = &label;
		కీలకం_attr[1].ul_విలువ_Len = పరిమాణం(label) - 1;

		rv = f->C_Get_Attribute_విలువ(session, obj, కీలకం_attr, 2);
		ఒకవేళ (rv != CKR_OK) {
			error("C_GetAttributeValue failed: %lu", rv);
			వెళ్ళు fail;
		}

		label[కీలకం_attr[1].ul_విలువ_Len] = '\0';

		ఎంపిక (ck_కీలకం_type) {
#నిర్వచితమైతే WITH_OPENSSL
		స్థితి CKK_RSA:
			కీలకం = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			ఆపు;
		స్థితి CKK_ECDSA:
			కీలకం = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			ఆపు;
#అయితే_ముగింపు /* WITH_OPENSSL */
		స్థితి CKK_EC_EDWARDS:
			కీలకం = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			ఆపు;
		అప్రమేయ:
			/* XXX print key type? */
			కీలకం = ఖాళీ;
			error("skipping unsupported key type 0x%lx",
			    (u_long)ck_కీలకం_type);
		}

		ఒకవేళ (కీలకం == ఖాళీ) {
			debug_f("failed to fetch key");
			కొనసాగు;
		}
		note_కీలకం(p, slotidx, __func__, కీలకం);
		ఒకవేళ (pkcs11_కీలకం_included(keysp, nkeys, కీలకం)) {
			debug2_f("key already included");
			sshkey_free(కీలకం);
		} లేకపోతే {
			/* expand key array and add key */
			*keysp = xrecallocarray(*keysp, *nkeys,
			    *nkeys + 1, పరిమాణం(నిర్మాణం sshkey *));
			(*keysp)[*nkeys] = కీలకం;
			ఒకవేళ (labelsp != ఖాళీ) {
				*labelsp = xrecallocarray(*labelsp, *nkeys,
				    *nkeys + 1, పరిమాణం(అక్షరం *));
				(*labelsp)[*nkeys] = xstrdup((అక్షరం *)label);
			}
			*nkeys = *nkeys + 1;
			debug("have %d keys", *nkeys);
		}
	}

	ret = 0;
fail:
	rv = f->C_కనుగొను_Objects_Final(session);
	ఒకవేళ (rv != CKR_OK) {
		error("C_FindObjectsFinal failed: %lu", rv);
		ret = -1;
	}

	తిరిగి (ret);
}

#నిర్వచితమైతే WITH_PKCS11_KEYGEN
#నిర్వచించు FILL_ATTR(attr, idx, typ, val, len) \
	{ (attr[idx]).type=(typ); (attr[idx]).p_విలువ=(val); (attr[idx]).ul_విలువ_Len=len; idx++; }

స్థిర నిర్మాణం sshkey *
pkcs11_rsa_generate_వ్యక్తిగత_కీలకం(నిర్మాణం pkcs11_provider *p, CK_ULONG slotidx,
    అక్షరం *label, CK_ULONG బిట్లు, CK_BYTE keyid, uint32_t *err)
{
	నిర్మాణం pkcs11_slotinfo	*si;
	అక్షరం			*plabel = label ? label : "";
	పూర్ణాంకం			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_కీలకం_2, priv_కీలకం;
	CK_ATTRIBUTE		 tpub[16], tpriv[16];
	CK_MECHANISM		 mech = {
	    CKM_RSA_PKCS_కీలకం_PAIR_GEN, NULL_PTR, 0
	};
	CK_BYTE			 pubExponent[] = {
	    0x01, 0x00, 0x01 /* RSA_F4 in bytes */
	};
	pubkey_filter[0].p_విలువ = &pubkey_class;
	cert_filter[0].p_విలువ = &cert_class;

	*err = 0;

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, పరిమాణం(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, అక్షరశ్రేణి_పొడవు(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, పరిమాణం(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, పరిమాణం(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    పరిమాణం(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, పరిమాణం(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, పరిమాణం(false_val));
	FILL_ATTR(tpub, npub, CKA_MODULUS_బిట్లు, &బిట్లు, పరిమాణం(బిట్లు));
	FILL_ATTR(tpub, npub, CKA_ప్రజా_EXPONENT, pubExponent,
	    పరిమాణం(pubExponent));
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, పరిమాణం(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN,  &true_val, పరిమాణం(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL,  plabel, అక్షరశ్రేణి_పొడవు(plabel));
	FILL_ATTR(tpriv, npriv, CKA_వ్యక్తిగత,  &true_val, పరిమాణం(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE,  &true_val, పరిమాణం(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT,  &false_val, పరిమాణం(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN,  &true_val, పరిమాణం(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER,  &false_val,
	    పరిమాణం(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP,  &false_val, పరిమాణం(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE,  &false_val, పరిమాణం(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, పరిమాణం(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	ఒకవేళ ((rv = f->C_Generate_కీలకం_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_కీలకం_2, &priv_కీలకం)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		తిరిగి ఖాళీ;
	}

	తిరిగి pkcs11_fetch_rsa_pubkey(p, slotidx, &pub_కీలకం_2);
}

స్థిర పూర్ణాంకం
h2i(అక్షరం c)
{
	ఒకవేళ (c >= '0' && c <= '9')
		తిరిగి c - '0';
	లేకపోతే ఒకవేళ (c >= 'a' && c <= 'f')
		తిరిగి c - 'a' + 10;
	లేకపోతే ఒకవేళ (c >= 'A' && c <= 'F')
		తిరిగి c - 'A' + 10;
	లేకపోతే
		తిరిగి -1;
}

స్థిర పూర్ణాంకం
pkcs11_decode_hex(స్థిరరాశి అక్షరం *hex, గుర్తులేని అక్షరం **dest, కొలత_t *rlen)
{
	కొలత_t	i, len;

	ఒకవేళ (dest)
		*dest = ఖాళీ;
	ఒకవేళ (rlen)
		*rlen = 0;

	ఒకవేళ ((len = అక్షరశ్రేణి_పొడవు(hex)) % 2)
		తిరిగి -1;
	len /= 2;

	*dest = xmalloc(len);

	కొరకు (i = 0; i < len; i++) {
		పూర్ణాంకం hi, lo;

		hi = h2i(hex[2 * i]);
		lo = h2i(hex[(2 * i) + 1]);
		ఒకవేళ (hi == -1 || lo == -1)
			తిరిగి -1;
		(*dest)[i] = (hi << 4) | lo;
	}

	ఒకవేళ (rlen)
		*rlen = len;

	తిరిగి 0;
}

స్థిర నిర్మాణం ec_వక్రం_info {
	స్థిరరాశి అక్షరం	*name;
	స్థిరరాశి అక్షరం	*oid;
	స్థిరరాశి అక్షరం	*oid_encoded;
	కొలత_t		 కొలత;
} ec_వక్రం_infos[] = {
	{"prime256v1",	"1.2.840.10045.3.1.7",	"06082A8648CE3D030107", 256},
	{"secp384r1",	"1.3.132.0.34",		"06052B81040022",	384},
	{"secp521r1",	"1.3.132.0.35",		"06052B81040023",	521},
	{ఖాళీ,		ఖాళీ,			ఖాళీ,			0},
};

స్థిర నిర్మాణం sshkey *
pkcs11_ecdsa_generate_వ్యక్తిగత_కీలకం(నిర్మాణం pkcs11_provider *p, CK_ULONG slotidx,
    అక్షరం *label, CK_ULONG బిట్లు, CK_BYTE keyid, uint32_t *err)
{
	నిర్మాణం pkcs11_slotinfo	*si;
	అక్షరం			*plabel = label ? label : "";
	పూర్ణాంకం			 i;
	కొలత_t			 ecparams_కొలత;
	గుర్తులేని అక్షరం		*ecparams = ఖాళీ;
	పూర్ణాంకం			 npub = 0, npriv = 0;
	CK_RV			 rv;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_BBOOL		 true_val = CK_TRUE, false_val = CK_FALSE;
	CK_OBJECT_HANDLE	 pub_కీలకం_2, priv_కీలకం;
	CK_MECHANISM		 mech = {
	    CKM_EC_కీలకం_PAIR_GEN, NULL_PTR, 0
	};
	CK_ATTRIBUTE		 tpub[16], tpriv[16];

	*err = 0;

	కొరకు (i = 0; ec_వక్రం_infos[i].name; i++) {
		ఒకవేళ (ec_వక్రం_infos[i].కొలత == బిట్లు)
			ఆపు;
	}
	ఒకవేళ (!ec_వక్రం_infos[i].name) {
		error_f("invalid key size %lu", బిట్లు);
		తిరిగి ఖాళీ;
	}
	ఒకవేళ (pkcs11_decode_hex(ec_వక్రం_infos[i].oid_encoded, &ecparams,
	    &ecparams_కొలత) == -1) {
		error_f("invalid oid");
		తిరిగి ఖాళీ;
	}

	FILL_ATTR(tpub, npub, CKA_TOKEN, &true_val, పరిమాణం(true_val));
	FILL_ATTR(tpub, npub, CKA_LABEL, plabel, అక్షరశ్రేణి_పొడవు(plabel));
	FILL_ATTR(tpub, npub, CKA_ENCRYPT, &false_val, పరిమాణం(false_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY, &true_val, పరిమాణం(true_val));
	FILL_ATTR(tpub, npub, CKA_VERIFY_RECOVER, &false_val,
	    పరిమాణం(false_val));
	FILL_ATTR(tpub, npub, CKA_WRAP, &false_val, పరిమాణం(false_val));
	FILL_ATTR(tpub, npub, CKA_DERIVE, &false_val, పరిమాణం(false_val));
	FILL_ATTR(tpub, npub, CKA_EC_PARAMS, ecparams, ecparams_కొలత);
	FILL_ATTR(tpub, npub, CKA_ID, &keyid, పరిమాణం(keyid));

	FILL_ATTR(tpriv, npriv, CKA_TOKEN, &true_val, పరిమాణం(true_val));
	FILL_ATTR(tpriv, npriv, CKA_LABEL, plabel, అక్షరశ్రేణి_పొడవు(plabel));
	FILL_ATTR(tpriv, npriv, CKA_వ్యక్తిగత, &true_val, పరిమాణం(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SENSITIVE, &true_val, పరిమాణం(true_val));
	FILL_ATTR(tpriv, npriv, CKA_DECRYPT, &false_val, పరిమాణం(false_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN, &true_val, పరిమాణం(true_val));
	FILL_ATTR(tpriv, npriv, CKA_SIGN_RECOVER, &false_val,
	    పరిమాణం(false_val));
	FILL_ATTR(tpriv, npriv, CKA_UNWRAP, &false_val, పరిమాణం(false_val));
	FILL_ATTR(tpriv, npriv, CKA_DERIVE, &false_val, పరిమాణం(false_val));
	FILL_ATTR(tpriv, npriv, CKA_ID, &keyid, పరిమాణం(keyid));

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	ఒకవేళ ((rv = f->C_Generate_కీలకం_Pair(session, &mech, tpub, npub, tpriv, npriv,
	    &pub_కీలకం_2, &priv_కీలకం)) != CKR_OK) {
		error_f("key generation failed: error 0x%lx", rv);
		*err = rv;
		తిరిగి ఖాళీ;
	}

	తిరిగి pkcs11_fetch_ecdsa_pubkey(p, slotidx, &pub_కీలకం_2);
}
#అయితే_ముగింపు /* WITH_PKCS11_KEYGEN */

/*
 * register a new provider, fails if provider already exists. if
 * keyp is provided, fetch keys.
 */
స్థిర పూర్ణాంకం
pkcs11_రిజిస్టరు_provider(అక్షరం *provider_id, అక్షరం *pin,
    నిర్మాణం sshkey ***keyp, అక్షరం ***labelsp,
    నిర్మాణం pkcs11_provider **providerp, CK_ULONG user)
{
	పూర్ణాంకం nkeys, need_finalize = 0;
	పూర్ణాంకం ret = -1;
	నిర్మాణం pkcs11_provider *p = ఖాళీ;
	శూన్య *handle = ఖాళీ;
	CK_RV (*getfunctionlist)(CK_FUNCTION_LIST **);
	CK_RV rv;
	CK_FUNCTION_LIST *f = ఖాళీ;
	CK_TOKEN_INFO *token;
	CK_ULONG i;

	ఒకవేళ (providerp == ఖాళీ)
		వెళ్ళు fail;
	*providerp = ఖాళీ;

	ఒకవేళ (keyp != ఖాళీ)
		*keyp = ఖాళీ;
	ఒకవేళ (labelsp != ఖాళీ)
		*labelsp = ఖాళీ;

	ఒకవేళ (pkcs11_provider_lookup(provider_id) != ఖాళీ) {
		debug_f("provider already registered: %s", provider_id);
		వెళ్ళు fail;
	}
	ఒకవేళ (lib_కలిగియుంది_చిహ్నం(provider_id, "C_GetFunctionList") != 0) {
		error("provider %s is not a PKCS11 library", provider_id);
		వెళ్ళు fail;
	}
	/* open shared pkcs11-library */
	ఒకవేళ ((handle = dlopen(provider_id, RTLD_NOW)) == ఖాళీ) {
		error("dlopen %s failed: %s", provider_id, dlerror());
		వెళ్ళు fail;
	}
	ఒకవేళ ((getfunctionlist = dlsym(handle, "C_GetFunctionList")) == ఖాళీ)
		fatal("dlsym(C_GetFunctionList) failed: %s", dlerror());
	p = xcalloc(1, పరిమాణం(*p));
	p->name = xstrdup(provider_id);
	p->handle = handle;
	/* set up the pkcs11 callbacks */
	ఒకవేళ ((rv = (*getfunctionlist)(&f)) != CKR_OK) {
		error("C_GetFunctionList for provider %s failed: %lu",
		    provider_id, rv);
		వెళ్ళు fail;
	}
	p->function_list = f;
	ఒకవేళ ((rv = f->C_Initialize(ఖాళీ)) != CKR_OK) {
		error("C_Initialize for provider %s failed: %lu",
		    provider_id, rv);
		వెళ్ళు fail;
	}
	need_finalize = 1;
	ఒకవేళ ((rv = f->C_GetInfo(&p->info)) != CKR_OK) {
		error("C_GetInfo for provider %s failed: %lu",
		    provider_id, rv);
		వెళ్ళు fail;
	}
	debug("provider %s: manufacturerID <%.*s> cryptokiVersion %d.%d"
	    " libraryDescription <%.*s> libraryVersion %d.%d",
	    provider_id,
	    RMSPACE(p->info.manufacturerID),
	    p->info.cryptoki_సంస్కరణ_2.major,
	    p->info.cryptoki_సంస్కరణ_2.minor,
	    RMSPACE(p->info.libraryDescription),
	    p->info.library_సంస్కరణ_2.major,
	    p->info.library_సంస్కరణ_2.minor);
	ఒకవేళ ((rv = f->C_Get_స్థానం_List(CK_TRUE, ఖాళీ, &p->nslots)) != CKR_OK) {
		error("C_GetSlotList failed: %lu", rv);
		వెళ్ళు fail;
	}
	ఒకవేళ (p->nslots == 0) {
		debug_f("provider %s returned no slots", provider_id);
		ret = -SSH_PKCS11_ERR_NO_SLOTS;
		వెళ్ళు fail;
	}
	p->slotlist = xcalloc(p->nslots, పరిమాణం(CK_స్థానం_ID));
	ఒకవేళ ((rv = f->C_Get_స్థానం_List(CK_TRUE, p->slotlist, &p->nslots))
	    != CKR_OK) {
		error("C_GetSlotList for provider %s failed: %lu",
		    provider_id, rv);
		వెళ్ళు fail;
	}
	p->slotinfo = xcalloc(p->nslots, పరిమాణం(నిర్మాణం pkcs11_slotinfo));
	p->valid = 1;
	nkeys = 0;
	కొరకు (i = 0; i < p->nslots; i++) {
		token = &p->slotinfo[i].token;
		ఒకవేళ ((rv = f->C_GetTokenInfo(p->slotlist[i], token))
		    != CKR_OK) {
			error("C_GetTokenInfo for provider %s slot %lu "
			    "failed: %lu", provider_id, (u_long)i, rv);
			కొనసాగు;
		}
		ఒకవేళ ((token->flags & CKF_TOKEN_INITIALIZED) == 0) {
			debug2_f("ignoring uninitialised token in "
			    "provider %s slot %lu", provider_id, (u_long)i);
			కొనసాగు;
		}
		debug("provider %s slot %lu: label <%.*s> "
		    "manufacturerID <%.*s> model <%.*s> serial <%.*s> "
		    "flags 0x%lx",
		    provider_id, (గుర్తులేని దీర్ఘ)i,
		    RMSPACE(token->label), RMSPACE(token->manufacturerID),
		    RMSPACE(token->model), RMSPACE(token->serial_సంఖ్య_2),
		    token->flags);
		/*
		 * open session, login with pin and retrieve public
		 * keys (if keyp is provided)
		 */
		ఒకవేళ ((ret = pkcs11_open_session(p, i, pin, user)) != 0 ||
		    keyp == ఖాళీ)
			కొనసాగు;
		pkcs11_fetch_కీలకాలు(p, i, keyp, labelsp, &nkeys);
#నిర్వచితమైతే WITH_OPENSSL
		pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#అయితే_ముగింపు
		ఒకవేళ (nkeys == 0 && !p->slotinfo[i].logged_లోపల &&
		    pkcs11_interactive) {
			/*
			 * Some tokens require login before they will
			 * expose keys.
			 */
			ఒకవేళ (pkcs11_login_స్థానం(p, &p->slotinfo[i],
			    CKU_USER) < 0) {
				error("login failed");
				కొనసాగు;
			}
			pkcs11_fetch_కీలకాలు(p, i, keyp, labelsp, &nkeys);
#నిర్వచితమైతే WITH_OPENSSL
			pkcs11_fetch_certs(p, i, keyp, labelsp, &nkeys);
#అయితే_ముగింపు
		}
	}

	/* now owned by caller */
	*providerp = p;

	TAILQ_INSERT_TAIL(&pkcs11_providers, p, తదుపరి);
	p->refcount++;	/* add to provider list */

	తిరిగి (nkeys);
fail:
	ఒకవేళ (need_finalize && (rv = f->C_Finalize(ఖాళీ)) != CKR_OK)
		error("C_Finalize for provider %s failed: %lu",
		    provider_id, rv);
	ఒకవేళ (p) {
		విడుదల(p->name);
		విడుదల(p->slotlist);
		విడుదల(p->slotinfo);
		విడుదల(p);
	}
	ఒకవేళ (handle)
		dlclose(handle);
	ఒకవేళ (ret > 0)
		ret = -1;
	తిరిగి (ret);
}

పూర్ణాంకం
pkcs11_init(పూర్ణాంకం interactive)
{
	debug3_f("called, interactive = %d", interactive);

	pkcs11_interactive = interactive;
	TAILQ_INIT(&pkcs11_providers);
	TAILQ_INIT(&pkcs11_కీలకాలు);
	తిరిగి (0);
}

/* unregister all providers, keys might still point to the providers */
శూన్య
pkcs11_terminate(శూన్య)
{
	నిర్మాణం pkcs11_provider *p;
	నిర్మాణం pkcs11_కీలకం *k11;

	debug3_f("called");

	అయితే ((k11 = TAILQ_FIRST(&pkcs11_కీలకాలు)) != ఖాళీ) {
		TAILQ_REMOVE(&pkcs11_కీలకాలు, k11, తదుపరి);
		pkcs11_k11_free(k11);
	}
	అయితే ((p = TAILQ_FIRST(&pkcs11_providers)) != ఖాళీ) {
		TAILQ_REMOVE(&pkcs11_providers, p, తదుపరి);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
}

/*
 * register a new provider and get number of keys hold by the token,
 * fails if provider already exists
 */
పూర్ణాంకం
pkcs11_కూడు_provider(అక్షరం *provider_id, అక్షరం *pin, నిర్మాణం sshkey ***keyp,
    అక్షరం ***labelsp)
{
	నిర్మాణం pkcs11_provider *p = ఖాళీ;
	పూర్ణాంకం nkeys;

	nkeys = pkcs11_రిజిస్టరు_provider(provider_id, pin, keyp, labelsp,
	    &p, CKU_USER);

	/* no keys found or some other error, de-register provider */
	ఒకవేళ (nkeys <= 0 && p != ఖాళీ) {
		TAILQ_REMOVE(&pkcs11_providers, p, తదుపరి);
		pkcs11_provider_finalize(p);
		pkcs11_provider_unref(p);
	}
	ఒకవేళ (nkeys == 0)
		debug_f("provider %s returned no keys", provider_id);

	తిరిగి (nkeys);
}

పూర్ణాంకం
pkcs11_sign(నిర్మాణం sshkey *కీలకం,
    u_char **sigp, కొలత_t *lenp,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen,
    స్థిరరాశి అక్షరం *alg, స్థిరరాశి అక్షరం *sk_provider,
    స్థిరరాశి అక్షరం *sk_pin, u_int compat)
{
	ఎంపిక (కీలకం->type) {
#నిర్వచితమైతే WITH_OPENSSL
	స్థితి కీలకం_RSA:
	స్థితి కీలకం_RSA_CERT:
		తిరిగి pkcs11_sign_rsa(కీలకం, sigp, lenp, దత్తాంశం, datalen,
		    alg, sk_provider, sk_pin, compat);
	స్థితి కీలకం_ECDSA:
	స్థితి కీలకం_ECDSA_CERT:
		తిరిగి pkcs11_sign_ecdsa(కీలకం, sigp, lenp, దత్తాంశం, datalen,
		    alg, sk_provider, sk_pin, compat);
#అయితే_ముగింపు /* WITH_OPENSSL */
	స్థితి కీలకం_ED25519:
	స్థితి కీలకం_ED25519_CERT:
		తిరిగి pkcs11_sign_ed25519(కీలకం, sigp, lenp, దత్తాంశం, datalen,
		    alg, sk_provider, sk_pin, compat);
	అప్రమేయ:
		తిరిగి SSH_ERR_కీలకం_TYPE_UNKNOWN;
	}
}

శూన్య
pkcs11_కీలకం_free(నిర్మాణం sshkey *కీలకం)
{
	/* never called */
}

#నిర్వచితమైతే WITH_PKCS11_KEYGEN
నిర్మాణం sshkey *
pkcs11_gakp(అక్షరం *provider_id, అక్షరం *pin, గుర్తులేని పూర్ణాంకం slotidx, అక్షరం *label,
    గుర్తులేని పూర్ణాంకం type, గుర్తులేని పూర్ణాంకం బిట్లు, గుర్తులేని అక్షరం keyid, uint32_t *err)
{
	నిర్మాణం pkcs11_provider	*p = ఖాళీ;
	నిర్మాణం pkcs11_slotinfo	*si;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	నిర్మాణం sshkey		*k = ఖాళీ;
	పూర్ణాంకం			 ret = -1, reset_pin = 0, reset_provider = 0;
	CK_RV			 rv;

	*err = 0;

	ఒకవేళ ((p = pkcs11_provider_lookup(provider_id)) != ఖాళీ)
		debug_f("provider \"%s\" available", provider_id);
	లేకపోతే ఒకవేళ ((ret = pkcs11_రిజిస్టరు_provider(provider_id, pin, ఖాళీ, ఖాళీ,
	    &p, CKU_SO)) < 0) {
		debug_f("could not register provider %s", provider_id);
		వెళ్ళు బహిర్గతం;
	} లేకపోతే
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	ఒకవేళ ((rv = f->C_సమితి_Operation_State(session , pin, అక్షరశ్రేణి_పొడవు(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} లేకపోతే
		reset_pin = 1;

	ఎంపిక (type) {
	స్థితి కీలకం_RSA:
		ఒకవేళ ((k = pkcs11_rsa_generate_వ్యక్తిగత_కీలకం(p, slotidx, label,
		    బిట్లు, keyid, err)) == ఖాళీ) {
			debug_f("failed to generate RSA key");
			వెళ్ళు బహిర్గతం;
		}
		ఆపు;
	స్థితి కీలకం_ECDSA:
		ఒకవేళ ((k = pkcs11_ecdsa_generate_వ్యక్తిగత_కీలకం(p, slotidx, label,
		    బిట్లు, keyid, err)) == ఖాళీ) {
			debug_f("failed to generate ECDSA key");
			వెళ్ళు బహిర్గతం;
		}
		ఆపు;
	అప్రమేయ:
		*err = SSH_PKCS11_ERR_GENERIC;
		debug_f("unknown type %d", type);
		వెళ్ళు బహిర్గతం;
	}

బహిర్గతం:
	ఒకవేళ (reset_pin)
		f->C_సమితి_Operation_State(session , ఖాళీ, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	ఒకవేళ (reset_provider)
		pkcs11_del_provider(provider_id);

	తిరిగి (k);
}

నిర్మాణం sshkey *
pkcs11_destroy_keypair(అక్షరం *provider_id, అక్షరం *pin, గుర్తులేని దీర్ఘ slotidx,
    గుర్తులేని అక్షరం keyid, uint32_t *err)
{
	నిర్మాణం pkcs11_provider	*p = ఖాళీ;
	నిర్మాణం pkcs11_slotinfo	*si;
	నిర్మాణం sshkey		*k = ఖాళీ;
	పూర్ణాంకం			 reset_pin = 0, reset_provider = 0;
	CK_ULONG		 nattrs;
	CK_FUNCTION_LIST	*f;
	CK_SESSION_HANDLE	 session;
	CK_ATTRIBUTE		 attrs[16];
	CK_OBJECT_CLASS		 కీలకం_class;
	CK_కీలకం_TYPE		 కీలకం_type;
	CK_OBJECT_HANDLE	 obj = CK_INVALID_HANDLE;
	CK_RV			 rv;

	*err = 0;

	ఒకవేళ ((p = pkcs11_provider_lookup(provider_id)) != ఖాళీ) {
		debug_f("using provider \"%s\"", provider_id);
	} లేకపోతే ఒకవేళ (pkcs11_రిజిస్టరు_provider(provider_id, pin, ఖాళీ, ఖాళీ, &p,
	    CKU_SO) < 0) {
		debug_f("could not register provider %s",
		    provider_id);
		వెళ్ళు బహిర్గతం;
	} లేకపోతే
		reset_provider = 1;

	f = p->function_list;
	si = &p->slotinfo[slotidx];
	session = si->session;

	ఒకవేళ ((rv = f->C_సమితి_Operation_State(session , pin, అక్షరశ్రేణి_పొడవు(pin),
	    CK_INVALID_HANDLE, CK_INVALID_HANDLE)) != CKR_OK) {
		debug_f("could not supply SO pin: %lu", rv);
		reset_pin = 0;
	} లేకపోతే
		reset_pin = 1;

	/* private key */
	nattrs = 0;
	కీలకం_class = CKO_వ్యక్తిగత_కీలకం;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &కీలకం_class, పరిమాణం(కీలకం_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, పరిమాణం(keyid));

	ఒకవేళ (pkcs11_కనుగొను(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {
		ఒకవేళ ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy private key 0x%hhx",
			    keyid);
			*err = rv;
			వెళ్ళు బహిర్గతం;
		}
	}

	/* public key */
	nattrs = 0;
	కీలకం_class = CKO_ప్రజా_కీలకం;
	FILL_ATTR(attrs, nattrs, CKA_CLASS, &కీలకం_class, పరిమాణం(కీలకం_class));
	FILL_ATTR(attrs, nattrs, CKA_ID, &keyid, పరిమాణం(keyid));

	ఒకవేళ (pkcs11_కనుగొను(p, slotidx, attrs, nattrs, &obj) == 0 &&
	    obj != CK_INVALID_HANDLE) {

		/* get key type */
		nattrs = 0;
		FILL_ATTR(attrs, nattrs, CKA_కీలకం_TYPE, &కీలకం_type,
		    పరిమాణం(కీలకం_type));
		rv = f->C_Get_Attribute_విలువ(session, obj, attrs, nattrs);
		ఒకవేళ (rv != CKR_OK) {
			debug_f("could not get key type of public key 0x%hhx",
			    keyid);
			*err = rv;
			కీలకం_type = -1;
		}
		ఎంపిక (కీలకం_type) {
#నిర్వచితమైతే WITH_OPENSSL
		స్థితి CKK_RSA:
			k = pkcs11_fetch_rsa_pubkey(p, slotidx, &obj);
			ఆపు;
		స్థితి CKK_ECDSA:
			k = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &obj);
			ఆపు;
#అయితే_ముగింపు /* WITH_OPENSSL */
		స్థితి CKK_EC_EDWARDS:
			k = pkcs11_fetch_ed25519_pubkey(p, slotidx, &obj);
			ఆపు;
		అప్రమేయ:
			debug_f("unsupported key type %lu", (u_long)కీలకం_type);
			ఆపు;
		}

		ఒకవేళ ((rv = f->C_DestroyObject(session, obj)) != CKR_OK) {
			debug_f("could not destroy public key 0x%hhx", keyid);
			*err = rv;
			వెళ్ళు బహిర్గతం;
		}
	}

బహిర్గతం:
	ఒకవేళ (reset_pin)
		f->C_సమితి_Operation_State(session , ఖాళీ, 0, CK_INVALID_HANDLE,
		    CK_INVALID_HANDLE);

	ఒకవేళ (reset_provider)
		pkcs11_del_provider(provider_id);

	తిరిగి (k);
}
#అయితే_ముగింపు /* WITH_PKCS11_KEYGEN */
#లేకపోతే /* ENABLE_PKCS11 */

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>

#అన్తర్భావ "log.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "ssh-pkcs11.h"

పూర్ణాంకం
pkcs11_init(పూర్ణాంకం interactive)
{
	error_f("PKCS#11 not supported");
	తిరిగి (-1);
}

పూర్ణాంకం
pkcs11_కూడు_provider(అక్షరం *provider_id, అక్షరం *pin, నిర్మాణం sshkey ***keyp,
    అక్షరం ***labelsp)
{
	error_f("PKCS#11 not supported");
	తిరిగి (-1);
}

శూన్య
pkcs11_కీలకం_free(నిర్మాణం sshkey *కీలకం)
{
	error_f("PKCS#11 not supported");
}

పూర్ణాంకం
pkcs11_sign(నిర్మాణం sshkey *కీలకం,
    u_char **sigp, కొలత_t *lenp,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen,
    స్థిరరాశి అక్షరం *alg, స్థిరరాశి అక్షరం *sk_provider,
    స్థిరరాశి అక్షరం *sk_pin, u_int compat)
{
	error_f("PKCS#11 not supported");
	తిరిగి SSH_ERR_FEATURE_UNSUPPORTED;
}

శూన్య
pkcs11_terminate(శూన్య)
{
	error_f("PKCS#11 not supported");
}
#అయితే_ముగింపు /* ENABLE_PKCS11 */
