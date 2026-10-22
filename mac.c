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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "digest.h"
#అన్తర్భావ "hmac.h"
#అన్తర్భావ "umac.h"
#అన్తర్భావ "mac.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"

#అన్తర్భావ "openbsd-compat/openssl-compat.h"

#నిర్వచించు SSH_DIGEST	1	/* SSH_DIGEST_XXX */
#నిర్వచించు SSH_UMAC	2	/* UMAC (not integrated with OpenSSL) */
#నిర్వచించు SSH_UMAC128	3

నిర్మాణం macalg {
	అక్షరం		*name;
	పూర్ణాంకం		type;
	పూర్ణాంకం		alg;
	పూర్ణాంకం		truncatebits;	/* truncate digest if != 0 */
	పూర్ణాంకం		కీలకం_len;	/* just for UMAC */
	పూర్ణాంకం		len;		/* just for UMAC */
	పూర్ణాంకం		etm;		/* Encrypt-then-MAC */
};

స్థిర స్థిరరాశి నిర్మాణం macalg macs[] = {
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

	{ ఖాళీ,					0, 0, 0, 0, 0, 0 }
};

/* Returns a list of supported MACs separated by the specified char. */
అక్షరం *
mac_alg_list(అక్షరం sep)
{
	అక్షరం *ret = ఖాళీ;
	స్థిరరాశి నిర్మాణం macalg *m;
	అక్షరం sep_str[2] = {sep, '\0'};

	కొరకు (m = macs; m->name != ఖాళీ; m++)
		xextendf(&ret, sep_str, "%s", m->name);

	తిరిగి ret;
}

స్థిర పూర్ణాంకం
mac_అమరిక_by_alg(నిర్మాణం sshmac *mac, స్థిరరాశి నిర్మాణం macalg *macalg)
{
	mac->type = macalg->type;
	ఒకవేళ (mac->type == SSH_DIGEST) {
		ఒకవేళ ((mac->hmac_ctx = ssh_hmac_ప్రారంభం(macalg->alg)) == ఖాళీ)
			తిరిగి SSH_ERR_ALLOC_FAIL;
		mac->కీలకం_len = mac->mac_len = ssh_hmac_బైట్లు(macalg->alg);
	} లేకపోతే {
		mac->mac_len = macalg->len / 8;
		mac->కీలకం_len = macalg->కీలకం_len / 8;
		mac->umac_ctx = ఖాళీ;
	}
	ఒకవేళ (macalg->truncatebits != 0)
		mac->mac_len = macalg->truncatebits / 8;
	mac->etm = macalg->etm;
	తిరిగి 0;
}

పూర్ణాంకం
mac_అమరిక(నిర్మాణం sshmac *mac, అక్షరం *name)
{
	స్థిరరాశి నిర్మాణం macalg *m;

	కొరకు (m = macs; m->name != ఖాళీ; m++) {
		ఒకవేళ (strcmp(name, m->name) != 0)
			కొనసాగు;
		ఒకవేళ (mac != ఖాళీ)
			తిరిగి mac_అమరిక_by_alg(mac, m);
		తిరిగి 0;
	}
	తిరిగి SSH_ERR_INVALID_వాదం;
}

పూర్ణాంకం
mac_init(నిర్మాణం sshmac *mac)
{
	ఒకవేళ (mac->కీలకం == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఎంపిక (mac->type) {
	స్థితి SSH_DIGEST:
		ఒకవేళ (mac->hmac_ctx == ఖాళీ ||
		    ssh_hmac_init(mac->hmac_ctx, mac->కీలకం, mac->కీలకం_len) < 0)
			తిరిగి SSH_ERR_INVALID_వాదం;
		తిరిగి 0;
	స్థితి SSH_UMAC:
		ఒకవేళ ((mac->umac_ctx = umac_new(mac->కీలకం)) == ఖాళీ)
			తిరిగి SSH_ERR_ALLOC_FAIL;
		తిరిగి 0;
	స్థితి SSH_UMAC128:
		ఒకవేళ ((mac->umac_ctx = umac128_new(mac->కీలకం)) == ఖాళీ)
			తిరిగి SSH_ERR_ALLOC_FAIL;
		తిరిగి 0;
	అప్రమేయ:
		తిరిగి SSH_ERR_INVALID_వాదం;
	}
}

పూర్ణాంకం
mac_compute(నిర్మాణం sshmac *mac, uint32_t seqno,
    స్థిరరాశి u_char *దత్తాంశం, పూర్ణాంకం datalen,
    u_char *digest, కొలత_t dlen)
{
	స్థిర సంఘం {
		u_char m[SSH_DIGEST_MAX_నిడివి];
		uint64_t for_align;
	} u;
	u_char b[4];
	u_char nonce[8];

	ఒకవేళ (mac->mac_len > పరిమాణం(u))
		తిరిగి SSH_ERR_అంతర్గత_ERROR;

	ఎంపిక (mac->type) {
	స్థితి SSH_DIGEST:
		put_u32(b, seqno);
		/* reset HMAC context */
		ఒకవేళ (ssh_hmac_init(mac->hmac_ctx, ఖాళీ, 0) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, b, పరిమాణం(b)) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, దత్తాంశం, datalen) < 0 ||
		    ssh_hmac_final(mac->hmac_ctx, u.m, పరిమాణం(u.m)) < 0)
			తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
		ఆపు;
	స్థితి SSH_UMAC:
		POKE_U64(nonce, seqno);
		umac_update(mac->umac_ctx, దత్తాంశం, datalen);
		umac_final(mac->umac_ctx, u.m, nonce);
		ఆపు;
	స్థితి SSH_UMAC128:
		put_u64(nonce, seqno);
		umac128_update(mac->umac_ctx, దత్తాంశం, datalen);
		umac128_final(mac->umac_ctx, u.m, nonce);
		ఆపు;
	అప్రమేయ:
		తిరిగి SSH_ERR_INVALID_వాదం;
	}
	ఒకవేళ (digest != ఖాళీ) {
		ఒకవేళ (dlen > mac->mac_len)
			dlen = mac->mac_len;
		జ్ఞాపకం_నకలు(digest, u.m, dlen);
	}
	తిరిగి 0;
}

పూర్ణాంకం
mac_check(నిర్మాణం sshmac *mac, uint32_t seqno,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t dlen,
    స్థిరరాశి u_char *theirmac, కొలత_t mlen)
{
	u_char ourmac[SSH_DIGEST_MAX_నిడివి];
	పూర్ణాంకం r;

	ఒకవేళ (mac->mac_len > mlen)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ ((r = mac_compute(mac, seqno, దత్తాంశం, dlen,
	    ourmac, పరిమాణం(ourmac))) != 0)
		తిరిగి r;
	ఒకవేళ (timingsafe_bcmp(ourmac, theirmac, mac->mac_len) != 0)
		తిరిగి SSH_ERR_MAC_INVALID;
	తిరిగి 0;
}

శూన్య
mac_clear(నిర్మాణం sshmac *mac)
{
	ఒకవేళ (mac->type == SSH_UMAC) {
		ఒకవేళ (mac->umac_ctx != ఖాళీ)
			umac_delete(mac->umac_ctx);
	} లేకపోతే ఒకవేళ (mac->type == SSH_UMAC128) {
		ఒకవేళ (mac->umac_ctx != ఖాళీ)
			umac128_delete(mac->umac_ctx);
	} లేకపోతే ఒకవేళ (mac->hmac_ctx != ఖాళీ)
		ssh_hmac_free(mac->hmac_ctx);
	mac->hmac_ctx = ఖాళీ;
	mac->umac_ctx = ఖాళీ;
}

/* XXX copied from ciphers_valid */
#నిర్వచించు	MAC_SEP	","
పూర్ణాంకం
mac_valid(స్థిరరాశి అక్షరం *పేర్లు)
{
	అక్షరం *maclist, *cp, *p;
	పూర్ణాంకం దొరికింది = 0;

	ఒకవేళ (పేర్లు == ఖాళీ || strcmp(పేర్లు, "") == 0)
		తిరిగి 0;
	ఒకవేళ ((maclist = cp = strdup(పేర్లు)) == ఖాళీ)
		తిరిగి 0;
	కొరకు ((p = strsep(&cp, MAC_SEP)); p && *p != '\0';
	    (p = strsep(&cp, MAC_SEP))) {
		ఒకవేళ (mac_అమరిక(ఖాళీ, p) < 0) {
			విడుదల(maclist);
			తిరిగి 0;
		} లేకపోతే
			దొరికింది = 1;
	}
	విడుదల(maclist);
	తిరిగి దొరికింది;
}
