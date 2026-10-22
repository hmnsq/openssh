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
	पूर्णाङ्क		साँचो_len;	/* just for UMAC */
	पूर्णाङ्क		len;		/* just for UMAC */
	पूर्णाङ्क		etm;		/* Encrypt-then-MAC */
};

स्थिर अचर संरचना macalg macs[] = {
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
	अचर संरचना macalg *m;
	वर्ण sep_str[2] = {sep, '\0'};

	लागि (m = macs; m->name != रिक्त; m++)
		xextendf(&ret, sep_str, "%s", m->name);

	फर्काऊ ret;
}

स्थिर पूर्णाङ्क
mac_setup_by_alg(संरचना sshmac *mac, अचर संरचना macalg *macalg)
{
	mac->type = macalg->type;
	यदि (mac->type == SSH_DIGEST) {
		यदि ((mac->hmac_ctx = ssh_hmac_start(macalg->alg)) == रिक्त)
			फर्काऊ SSH_ERR_ALLOC_FAIL;
		mac->साँचो_len = mac->mac_len = ssh_hmac_bytes(macalg->alg);
	} अन्यथा {
		mac->mac_len = macalg->len / 8;
		mac->साँचो_len = macalg->साँचो_len / 8;
		mac->umac_ctx = रिक्त;
	}
	यदि (macalg->truncatebits != 0)
		mac->mac_len = macalg->truncatebits / 8;
	mac->etm = macalg->etm;
	फर्काऊ 0;
}

पूर्णाङ्क
mac_setup(संरचना sshmac *mac, वर्ण *name)
{
	अचर संरचना macalg *m;

	लागि (m = macs; m->name != रिक्त; m++) {
		यदि (म_भेद(name, m->name) != 0)
			जारी;
		यदि (mac != रिक्त)
			फर्काऊ mac_setup_by_alg(mac, m);
		फर्काऊ 0;
	}
	फर्काऊ SSH_ERR_INVALID_ARGUMENT;
}

पूर्णाङ्क
mac_init(संरचना sshmac *mac)
{
	यदि (mac->साँचो == रिक्त)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	विकल्प (mac->type) {
	पक्ष SSH_DIGEST:
		यदि (mac->hmac_ctx == रिक्त ||
		    ssh_hmac_init(mac->hmac_ctx, mac->साँचो, mac->साँचो_len) < 0)
			फर्काऊ SSH_ERR_INVALID_ARGUMENT;
		फर्काऊ 0;
	पक्ष SSH_UMAC:
		यदि ((mac->umac_ctx = umac_new(mac->साँचो)) == रिक्त)
			फर्काऊ SSH_ERR_ALLOC_FAIL;
		फर्काऊ 0;
	पक्ष SSH_UMAC128:
		यदि ((mac->umac_ctx = umac128_new(mac->साँचो)) == रिक्त)
			फर्काऊ SSH_ERR_ALLOC_FAIL;
		फर्काऊ 0;
	स्वभाव:
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	}
}

पूर्णाङ्क
mac_compute(संरचना sshmac *mac, uint32_t seqno,
    अचर u_char *data, पूर्णाङ्क datalen,
    u_char *digest, माप_प्रकार dlen)
{
	स्थिर सङ्घ {
		u_char m[SSH_DIGEST_MAX_LENGTH];
		uint64_t for_align;
	} u;
	u_char b[4];
	u_char nonce[8];

	यदि (mac->mac_len > परिमाण(u))
		फर्काऊ SSH_ERR_INTERNAL_ERROR;

	विकल्प (mac->type) {
	पक्ष SSH_DIGEST:
		put_u32(b, seqno);
		/* reset HMAC context */
		यदि (ssh_hmac_init(mac->hmac_ctx, रिक्त, 0) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, b, परिमाण(b)) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, data, datalen) < 0 ||
		    ssh_hmac_final(mac->hmac_ctx, u.m, परिमाण(u.m)) < 0)
			फर्काऊ SSH_ERR_LIBCRYPTO_ERROR;
		रोक;
	पक्ष SSH_UMAC:
		POKE_U64(nonce, seqno);
		umac_update(mac->umac_ctx, data, datalen);
		umac_final(mac->umac_ctx, u.m, nonce);
		रोक;
	पक्ष SSH_UMAC128:
		put_u64(nonce, seqno);
		umac128_update(mac->umac_ctx, data, datalen);
		umac128_final(mac->umac_ctx, u.m, nonce);
		रोक;
	स्वभाव:
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	}
	यदि (digest != रिक्त) {
		यदि (dlen > mac->mac_len)
			dlen = mac->mac_len;
		स_नकल(digest, u.m, dlen);
	}
	फर्काऊ 0;
}

पूर्णाङ्क
mac_check(संरचना sshmac *mac, uint32_t seqno,
    अचर u_char *data, माप_प्रकार dlen,
    अचर u_char *theirmac, माप_प्रकार mlen)
{
	u_char ourmac[SSH_DIGEST_MAX_LENGTH];
	पूर्णाङ्क r;

	यदि (mac->mac_len > mlen)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि ((r = mac_compute(mac, seqno, data, dlen,
	    ourmac, परिमाण(ourmac))) != 0)
		फर्काऊ r;
	यदि (timingsafe_bcmp(ourmac, theirmac, mac->mac_len) != 0)
		फर्काऊ SSH_ERR_MAC_INVALID;
	फर्काऊ 0;
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
mac_valid(अचर वर्ण *names)
{
	वर्ण *maclist, *cp, *p;
	पूर्णाङ्क found = 0;

	यदि (names == रिक्त || म_भेद(names, "") == 0)
		फर्काऊ 0;
	यदि ((maclist = cp = strdup(names)) == रिक्त)
		फर्काऊ 0;
	लागि ((p = strsep(&cp, MAC_SEP)); p && *p != '\0';
	    (p = strsep(&cp, MAC_SEP))) {
		यदि (mac_setup(रिक्त, p) < 0) {
			मुक्त(maclist);
			फर्काऊ 0;
		} अन्यथा
			found = 1;
	}
	मुक्त(maclist);
	फर्काऊ found;
}
