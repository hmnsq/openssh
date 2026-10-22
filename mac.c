/* $OpenBSD: mac.c,v 1.39 2026/05/13 05:58:58 djm Exp $ */
/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "digest.h"
#अन्तर्भाव "hmac.h"
#अन्तर्भाव "umac.h"
#अन्तर्भाव "mac.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"

#अन्तर्भाव "openbsd-compat/openssl-compat.h"

#define SSH_DIGEST	1	/* SSH_DIGEST_XXX */
#define SSH_UMAC	2	/* UMAC (not integrated with OpenSSL) */
#define SSH_UMAC128	3

संरचना macalg {
	वर्ण		*name;
	पूर्णाङ्क		type;
	पूर्णाङ्क		alg;
	पूर्णाङ्क		truncatebits;	/* truncate digest if != 0 */
	पूर्णाङ्क		कुंजी_len;	/* just for UMAC */
	पूर्णाङ्क		len;		/* just for UMAC */
	पूर्णाङ्क		etm;		/* Encrypt-then-MAC */
};

स्थिर ध्रुव संरचना macalg macs[] = {
	/* Encrypt-and-MAC (encrypt-and-authenticate) variants */
	{ "hmac-sha1",				SSH_DIGEST, SSH_DIGEST_SHA1, 0, 0, 0, 0 },
	{ "hmac-sha1-96",			SSH_DIGEST, SSH_DIGEST_SHA1, 96, 0, 0, 0 },
	{ "hmac-sha2-256",			SSH_DIGEST, SSH_DIGEST_SHA256, 0, 0, 0, 0 },
	{ "hmac-sha2-512",			SSH_DIGEST, SSH_DIGEST_SHA512, 0, 0, 0, 0 },
	{ "hmac-md5",				SSH_DIGEST, SSH_DIGEST_MD5, 0, 0, 0, 0 },
	{ "hmac-md5-96",			SSH_DIGEST, SSH_DIGEST_MD5, 96, 0, 0, 0 },
	{ "umac-64@openssh.com",		SSH_UMAC, 0, 0, 128, 64, 0 },
	{ "umac-128@openssh.com",		SSH_UMAC128, 0, 0, 128, 128, 0 },

	/* Encrypt-then-MAC variants */
	{ "hmac-sha1-etm@openssh.com",		SSH_DIGEST, SSH_DIGEST_SHA1, 0, 0, 0, 1 },
	{ "hmac-sha1-96-etm@openssh.com",	SSH_DIGEST, SSH_DIGEST_SHA1, 96, 0, 0, 1 },
	{ "hmac-sha2-256-etm@openssh.com",	SSH_DIGEST, SSH_DIGEST_SHA256, 0, 0, 0, 1 },
	{ "hmac-sha2-512-etm@openssh.com",	SSH_DIGEST, SSH_DIGEST_SHA512, 0, 0, 0, 1 },
	{ "hmac-md5-etm@openssh.com",		SSH_DIGEST, SSH_DIGEST_MD5, 0, 0, 0, 1 },
	{ "hmac-md5-96-etm@openssh.com",	SSH_DIGEST, SSH_DIGEST_MD5, 96, 0, 0, 1 },
	{ "umac-64-etm@openssh.com",		SSH_UMAC, 0, 0, 128, 64, 1 },
	{ "umac-128-etm@openssh.com",		SSH_UMAC128, 0, 0, 128, 128, 1 },

	{ रिक्त,					0, 0, 0, 0, 0, 0 }
};

/* Returns a list of supported MACs separated by the specified char. */
वर्ण *
mac_alg_list(वर्ण sep)
{
	वर्ण *ret = रिक्त;
	ध्रुव संरचना macalg *m;
	वर्ण sep_str[2] = {sep, '\0'};

	प्रति (m = macs; m->name != रिक्त; m++)
		xextendf(&ret, sep_str, "%s", m->name);

	प्रत्यागम ret;
}

स्थिर पूर्णाङ्क
mac_setup_by_alg(संरचना sshmac *mac, ध्रुव संरचना macalg *macalg)
{
	mac->type = macalg->type;
	यदि (mac->type == SSH_DIGEST) {
		यदि ((mac->hmac_ctx = ssh_hmac_start(macalg->alg)) == रिक्त)
			प्रत्यागम SSH_ERR_ALLOC_FAIL;
		mac->कुंजी_len = mac->mac_len = ssh_hmac_bytes(macalg->alg);
	} अन्यथा {
		mac->mac_len = macalg->len / 8;
		mac->कुंजी_len = macalg->कुंजी_len / 8;
		mac->umac_ctx = रिक्त;
	}
	यदि (macalg->truncatebits != 0)
		mac->mac_len = macalg->truncatebits / 8;
	mac->etm = macalg->etm;
	प्रत्यागम 0;
}

पूर्णाङ्क
mac_setup(संरचना sshmac *mac, वर्ण *name)
{
	ध्रुव संरचना macalg *m;

	प्रति (m = macs; m->name != रिक्त; m++) {
		यदि (म_भेद(name, m->name) != 0)
			अनुवर्त;
		यदि (mac != रिक्त)
			प्रत्यागम mac_setup_by_alg(mac, m);
		प्रत्यागम 0;
	}
	प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
}

पूर्णाङ्क
mac_init(संरचना sshmac *mac)
{
	यदि (mac->कुंजी == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	विकल्प (mac->type) {
	पक्ष SSH_DIGEST:
		यदि (mac->hmac_ctx == रिक्त ||
		    ssh_hmac_init(mac->hmac_ctx, mac->कुंजी, mac->कुंजी_len) < 0)
			प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
		प्रत्यागम 0;
	पक्ष SSH_UMAC:
		यदि ((mac->umac_ctx = umac_new(mac->कुंजी)) == रिक्त)
			प्रत्यागम SSH_ERR_ALLOC_FAIL;
		प्रत्यागम 0;
	पक्ष SSH_UMAC128:
		यदि ((mac->umac_ctx = umac128_new(mac->कुंजी)) == रिक्त)
			प्रत्यागम SSH_ERR_ALLOC_FAIL;
		प्रत्यागम 0;
	स्वभाव:
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	}
}

पूर्णाङ्क
mac_compute(संरचना sshmac *mac, uint32_t seqno,
    ध्रुव u_char *data, पूर्णाङ्क datalen,
    u_char *digest, माप_प्रकार dlen)
{
	स्थिर सङ्घ {
		u_char m[SSH_DIGEST_MAX_LENGTH];
		uint64_t for_align;
	} u;
	u_char b[4];
	u_char nonce[8];

	यदि (mac->mac_len > परिमाण(u))
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;

	विकल्प (mac->type) {
	पक्ष SSH_DIGEST:
		put_u32(b, seqno);
		/* reset HMAC context */
		यदि (ssh_hmac_init(mac->hmac_ctx, रिक्त, 0) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, b, परिमाण(b)) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, data, datalen) < 0 ||
		    ssh_hmac_final(mac->hmac_ctx, u.m, परिमाण(u.m)) < 0)
			प्रत्यागम SSH_ERR_LIBCRYPTO_ERROR;
		भङ्ग;
	पक्ष SSH_UMAC:
		POKE_U64(nonce, seqno);
		umac_update(mac->umac_ctx, data, datalen);
		umac_final(mac->umac_ctx, u.m, nonce);
		भङ्ग;
	पक्ष SSH_UMAC128:
		put_u64(nonce, seqno);
		umac128_update(mac->umac_ctx, data, datalen);
		umac128_final(mac->umac_ctx, u.m, nonce);
		भङ्ग;
	स्वभाव:
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	}
	यदि (digest != रिक्त) {
		यदि (dlen > mac->mac_len)
			dlen = mac->mac_len;
		स_नकल(digest, u.m, dlen);
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
mac_check(संरचना sshmac *mac, uint32_t seqno,
    ध्रुव u_char *data, माप_प्रकार dlen,
    ध्रुव u_char *theirmac, माप_प्रकार mlen)
{
	u_char ourmac[SSH_DIGEST_MAX_LENGTH];
	पूर्णाङ्क r;

	यदि (mac->mac_len > mlen)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	यदि ((r = mac_compute(mac, seqno, data, dlen,
	    ourmac, परिमाण(ourmac))) != 0)
		प्रत्यागम r;
	यदि (timingsafe_bcmp(ourmac, theirmac, mac->mac_len) != 0)
		प्रत्यागम SSH_ERR_MAC_INVALID;
	प्रत्यागम 0;
}

शून्य
mac_clear(संरचना sshmac *mac)
{
	यदि (mac->type == SSH_UMAC) {
		यदि (mac->umac_ctx != रिक्त)
			umac_delete(mac->umac_ctx);
	} अन्यथा यदि (mac->type == SSH_UMAC128) {
		यदि (mac->umac_ctx != रिक्त)
			umac128_delete(mac->umac_ctx);
	} अन्यथा यदि (mac->hmac_ctx != रिक्त)
		ssh_hmac_free(mac->hmac_ctx);
	mac->hmac_ctx = रिक्त;
	mac->umac_ctx = रिक्त;
}

/* XXX copied from ciphers_valid */
#define	MAC_SEP	","
पूर्णाङ्क
mac_valid(ध्रुव वर्ण *names)
{
	वर्ण *maclist, *cp, *p;
	पूर्णाङ्क found = 0;

	यदि (names == रिक्त || म_भेद(names, "") == 0)
		प्रत्यागम 0;
	यदि ((maclist = cp = strdup(names)) == रिक्त)
		प्रत्यागम 0;
	प्रति ((p = strsep(&cp, MAC_SEP)); p && *p != '\0';
	    (p = strsep(&cp, MAC_SEP))) {
		यदि (mac_setup(रिक्त, p) < 0) {
			मुक्त(maclist);
			प्रत्यागम 0;
		} अन्यथा
			found = 1;
	}
	मुक्त(maclist);
	प्रत्यागम found;
}
