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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "hmac.h"
#ଅନ୍ତର୍ଭାଵ "umac.h"
#ଅନ୍ତର୍ଭାଵ "mac.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"

#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"

#define SSH_DIGEST	1	/* SSH_DIGEST_XXX */
#define SSH_UMAC	2	/* UMAC (not integrated with OpenSSL) */
#define SSH_UMAC128	3

ସଂରଚନା macalg {
	ଅକ୍ଷର		*name;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା		type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା		alg;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା		truncatebits;	/* truncate digest if != 0 */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା		ଚାବି_len;	/* just for UMAC */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା		len;		/* just for UMAC */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା		etm;		/* Encrypt-then-MAC */
};

ସ୍ଥିର ଅଚଳ ସଂରଚନା macalg macs[] = {
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

	{ ଖାଲି,					0, 0, 0, 0, 0, 0 }
};

/* Returns a list of supported MACs separated by the specified char. */
ଅକ୍ଷର *
mac_alg_list(ଅକ୍ଷର sep)
{
	ଅକ୍ଷର *ret = ଖାଲି;
	ଅଚଳ ସଂରଚନା macalg *m;
	ଅକ୍ଷର sep_str[2] = {sep, '\0'};

	ପାଇଁ (m = macs; m->name != ଖାଲି; m++)
		xextendf(&ret, sep_str, "%s", m->name);

	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mac_setup_by_alg(ସଂରଚନା sshmac *mac, ଅଚଳ ସଂରଚନା macalg *macalg)
{
	mac->type = macalg->type;
	ଯଦି (mac->type == SSH_DIGEST) {
		ଯଦି ((mac->hmac_ctx = ssh_hmac_start(macalg->alg)) == ଖାଲି)
			ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
		mac->ଚାବି_len = mac->mac_len = ssh_hmac_bytes(macalg->alg);
	} ଅନ୍ୟଥା {
		mac->mac_len = macalg->len / 8;
		mac->ଚାବି_len = macalg->ଚାବି_len / 8;
		mac->umac_ctx = ଖାଲି;
	}
	ଯଦି (macalg->truncatebits != 0)
		mac->mac_len = macalg->truncatebits / 8;
	mac->etm = macalg->etm;
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mac_setup(ସଂରଚନା sshmac *mac, ଅକ୍ଷର *name)
{
	ଅଚଳ ସଂରଚନା macalg *m;

	ପାଇଁ (m = macs; m->name != ଖାଲି; m++) {
		ଯଦି (strcmp(name, m->name) != 0)
			ଜାରି;
		ଯଦି (mac != ଖାଲି)
			ଫେରନ୍ତୁ mac_setup_by_alg(mac, m);
		ଫେରନ୍ତୁ 0;
	}
	ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mac_init(ସଂରଚନା sshmac *mac)
{
	ଯଦି (mac->ଚାବି == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ବାଛ (mac->type) {
	ସ୍ଥିତି SSH_DIGEST:
		ଯଦି (mac->hmac_ctx == ଖାଲି ||
		    ssh_hmac_init(mac->hmac_ctx, mac->ଚାବି, mac->ଚାବି_len) < 0)
			ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
		ଫେରନ୍ତୁ 0;
	ସ୍ଥିତି SSH_UMAC:
		ଯଦି ((mac->umac_ctx = umac_new(mac->ଚାବି)) == ଖାଲି)
			ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
		ଫେରନ୍ତୁ 0;
	ସ୍ଥିତି SSH_UMAC128:
		ଯଦି ((mac->umac_ctx = umac128_new(mac->ଚାବି)) == ଖାଲି)
			ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
		ଫେରନ୍ତୁ 0;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	}
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mac_compute(ସଂରଚନା sshmac *mac, uint32_t seqno,
    ଅଚଳ u_char *data, ପୂର୍ଣ୍ଣସଂଖ୍ୟା datalen,
    u_char *digest, size_t dlen)
{
	ସ୍ଥିର ସଂଘ {
		u_char m[SSH_DIGEST_MAX_LENGTH];
		uint64_t for_align;
	} u;
	u_char b[4];
	u_char nonce[8];

	ଯଦି (mac->mac_len > ଆକାର(u))
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;

	ବାଛ (mac->type) {
	ସ୍ଥିତି SSH_DIGEST:
		put_u32(b, seqno);
		/* reset HMAC context */
		ଯଦି (ssh_hmac_init(mac->hmac_ctx, ଖାଲି, 0) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, b, ଆକାର(b)) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, data, datalen) < 0 ||
		    ssh_hmac_final(mac->hmac_ctx, u.m, ଆକାର(u.m)) < 0)
			ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_UMAC:
		POKE_U64(nonce, seqno);
		umac_update(mac->umac_ctx, data, datalen);
		umac_final(mac->umac_ctx, u.m, nonce);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି SSH_UMAC128:
		put_u64(nonce, seqno);
		umac128_update(mac->umac_ctx, data, datalen);
		umac128_final(mac->umac_ctx, u.m, nonce);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	}
	ଯଦି (digest != ଖାଲି) {
		ଯଦି (dlen > mac->mac_len)
			dlen = mac->mac_len;
		memcpy(digest, u.m, dlen);
	}
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mac_check(ସଂରଚନା sshmac *mac, uint32_t seqno,
    ଅଚଳ u_char *data, size_t dlen,
    ଅଚଳ u_char *theirmac, size_t mlen)
{
	u_char ourmac[SSH_DIGEST_MAX_LENGTH];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (mac->mac_len > mlen)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି ((r = mac_compute(mac, seqno, data, dlen,
	    ourmac, ଆକାର(ourmac))) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (timingsafe_bcmp(ourmac, theirmac, mac->mac_len) != 0)
		ଫେରନ୍ତୁ SSH_ERR_MAC_INVALID;
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
mac_clear(ସଂରଚନା sshmac *mac)
{
	ଯଦି (mac->type == SSH_UMAC) {
		ଯଦି (mac->umac_ctx != ଖାଲି)
			umac_delete(mac->umac_ctx);
	} ଅନ୍ୟଥା ଯଦି (mac->type == SSH_UMAC128) {
		ଯଦି (mac->umac_ctx != ଖାଲି)
			umac128_delete(mac->umac_ctx);
	} ଅନ୍ୟଥା ଯଦି (mac->hmac_ctx != ଖାଲି)
		ssh_hmac_free(mac->hmac_ctx);
	mac->hmac_ctx = ଖାଲି;
	mac->umac_ctx = ଖାଲି;
}

/* XXX copied from ciphers_valid */
#define	MAC_SEP	","
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mac_valid(ଅଚଳ ଅକ୍ଷର *names)
{
	ଅକ୍ଷର *maclist, *cp, *p;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା found = 0;

	ଯଦି (names == ଖାଲି || strcmp(names, "") == 0)
		ଫେରନ୍ତୁ 0;
	ଯଦି ((maclist = cp = strdup(names)) == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ପାଇଁ ((p = strsep(&cp, MAC_SEP)); p && *p != '\0';
	    (p = strsep(&cp, MAC_SEP))) {
		ଯଦି (mac_setup(ଖାଲି, p) < 0) {
			ମୁକ୍ତ(maclist);
			ଫେରନ୍ତୁ 0;
		} ଅନ୍ୟଥା
			found = 1;
	}
	ମୁକ୍ତ(maclist);
	ଫେରନ୍ତୁ found;
}
