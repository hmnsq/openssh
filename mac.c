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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>

#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>

#অন্তর্ভাৱ "digest.h"
#অন্তর্ভাৱ "hmac.h"
#অন্তর্ভাৱ "umac.h"
#অন্তর্ভাৱ "mac.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "sshbuf.h"

#অন্তর্ভাৱ "openbsd-compat/openssl-compat.h"

#define SSH_DIGEST	1	/* SSH_DIGEST_XXX */
#define SSH_UMAC	2	/* UMAC (not integrated with OpenSSL) */
#define SSH_UMAC128	3

সংরচনা macalg {
	ৱর্ণ		*name;
	পূর্ণাঙ্ক		type;
	পূর্ণাঙ্ক		alg;
	পূর্ণাঙ্ক		truncatebits;	/* truncate digest if != 0 */
	পূর্ণাঙ্ক		চাবি_len;	/* just for UMAC */
	পূর্ণাঙ্ক		len;		/* just for UMAC */
	পূর্ণাঙ্ক		etm;		/* Encrypt-then-MAC */
};

স্থির ধ্রুৱ সংরচনা macalg macs[] = {
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

	{ রিক্ত,					0, 0, 0, 0, 0, 0 }
};

/* Returns a list of supported MACs separated by the specified char. */
ৱর্ণ *
mac_alg_list(ৱর্ণ sep)
{
	ৱর্ণ *ret = রিক্ত;
	ধ্রুৱ সংরচনা macalg *m;
	ৱর্ণ sep_str[2] = {sep, '\0'};

	বাবে (m = macs; m->name != রিক্ত; m++)
		xextendf(&ret, sep_str, "%s", m->name);

	ঘূৰাই ret;
}

স্থির পূর্ণাঙ্ক
mac_setup_by_alg(সংরচনা sshmac *mac, ধ্রুৱ সংরচনা macalg *macalg)
{
	mac->type = macalg->type;
	যদি (mac->type == SSH_DIGEST) {
		যদি ((mac->hmac_ctx = ssh_hmac_start(macalg->alg)) == রিক্ত)
			ঘূৰাই SSH_ERR_ALLOC_FAIL;
		mac->চাবি_len = mac->mac_len = ssh_hmac_bytes(macalg->alg);
	} অন্যথা {
		mac->mac_len = macalg->len / 8;
		mac->চাবি_len = macalg->চাবি_len / 8;
		mac->umac_ctx = রিক্ত;
	}
	যদি (macalg->truncatebits != 0)
		mac->mac_len = macalg->truncatebits / 8;
	mac->etm = macalg->etm;
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
mac_setup(সংরচনা sshmac *mac, ৱর্ণ *name)
{
	ধ্রুৱ সংরচনা macalg *m;

	বাবে (m = macs; m->name != রিক্ত; m++) {
		যদি (strcmp(name, m->name) != 0)
			অনুৱর্ত;
		যদি (mac != রিক্ত)
			ঘূৰাই mac_setup_by_alg(mac, m);
		ঘূৰাই 0;
	}
	ঘূৰাই SSH_ERR_INVALID_ARGUMENT;
}

পূর্ণাঙ্ক
mac_init(সংরচনা sshmac *mac)
{
	যদি (mac->চাবি == রিক্ত)
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;
	ৱিকল্প (mac->type) {
	পক্ষ SSH_DIGEST:
		যদি (mac->hmac_ctx == রিক্ত ||
		    ssh_hmac_init(mac->hmac_ctx, mac->চাবি, mac->চাবি_len) < 0)
			ঘূৰাই SSH_ERR_INVALID_ARGUMENT;
		ঘূৰাই 0;
	পক্ষ SSH_UMAC:
		যদি ((mac->umac_ctx = umac_new(mac->চাবি)) == রিক্ত)
			ঘূৰাই SSH_ERR_ALLOC_FAIL;
		ঘূৰাই 0;
	পক্ষ SSH_UMAC128:
		যদি ((mac->umac_ctx = umac128_new(mac->চাবি)) == রিক্ত)
			ঘূৰাই SSH_ERR_ALLOC_FAIL;
		ঘূৰাই 0;
	স্ৱভাৱ:
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;
	}
}

পূর্ণাঙ্ক
mac_compute(সংরচনা sshmac *mac, uint32_t seqno,
    ধ্রুৱ u_char *data, পূর্ণাঙ্ক datalen,
    u_char *digest, size_t dlen)
{
	স্থির সঙ্ঘ {
		u_char m[SSH_DIGEST_MAX_LENGTH];
		uint64_t for_align;
	} u;
	u_char b[4];
	u_char nonce[8];

	যদি (mac->mac_len > পরিমাণ(u))
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;

	ৱিকল্প (mac->type) {
	পক্ষ SSH_DIGEST:
		put_u32(b, seqno);
		/* reset HMAC context */
		যদি (ssh_hmac_init(mac->hmac_ctx, রিক্ত, 0) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, b, পরিমাণ(b)) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, data, datalen) < 0 ||
		    ssh_hmac_final(mac->hmac_ctx, u.m, পরিমাণ(u.m)) < 0)
			ঘূৰাই SSH_ERR_LIBCRYPTO_ERROR;
		ভঙ্গ;
	পক্ষ SSH_UMAC:
		POKE_U64(nonce, seqno);
		umac_update(mac->umac_ctx, data, datalen);
		umac_final(mac->umac_ctx, u.m, nonce);
		ভঙ্গ;
	পক্ষ SSH_UMAC128:
		put_u64(nonce, seqno);
		umac128_update(mac->umac_ctx, data, datalen);
		umac128_final(mac->umac_ctx, u.m, nonce);
		ভঙ্গ;
	স্ৱভাৱ:
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;
	}
	যদি (digest != রিক্ত) {
		যদি (dlen > mac->mac_len)
			dlen = mac->mac_len;
		memcpy(digest, u.m, dlen);
	}
	ঘূৰাই 0;
}

পূর্ণাঙ্ক
mac_check(সংরচনা sshmac *mac, uint32_t seqno,
    ধ্রুৱ u_char *data, size_t dlen,
    ধ্রুৱ u_char *theirmac, size_t mlen)
{
	u_char ourmac[SSH_DIGEST_MAX_LENGTH];
	পূর্ণাঙ্ক r;

	যদি (mac->mac_len > mlen)
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;
	যদি ((r = mac_compute(mac, seqno, data, dlen,
	    ourmac, পরিমাণ(ourmac))) != 0)
		ঘূৰাই r;
	যদি (timingsafe_bcmp(ourmac, theirmac, mac->mac_len) != 0)
		ঘূৰাই SSH_ERR_MAC_INVALID;
	ঘূৰাই 0;
}

শূন্য
mac_clear(সংরচনা sshmac *mac)
{
	যদি (mac->type == SSH_UMAC) {
		যদি (mac->umac_ctx != রিক্ত)
			umac_delete(mac->umac_ctx);
	} অন্যথা যদি (mac->type == SSH_UMAC128) {
		যদি (mac->umac_ctx != রিক্ত)
			umac128_delete(mac->umac_ctx);
	} অন্যথা যদি (mac->hmac_ctx != রিক্ত)
		ssh_hmac_free(mac->hmac_ctx);
	mac->hmac_ctx = রিক্ত;
	mac->umac_ctx = রিক্ত;
}

/* XXX copied from ciphers_valid */
#define	MAC_SEP	","
পূর্ণাঙ্ক
mac_valid(ধ্রুৱ ৱর্ণ *names)
{
	ৱর্ণ *maclist, *cp, *p;
	পূর্ণাঙ্ক found = 0;

	যদি (names == রিক্ত || strcmp(names, "") == 0)
		ঘূৰাই 0;
	যদি ((maclist = cp = strdup(names)) == রিক্ত)
		ঘূৰাই 0;
	বাবে ((p = strsep(&cp, MAC_SEP)); p && *p != '\0';
	    (p = strsep(&cp, MAC_SEP))) {
		যদি (mac_setup(রিক্ত, p) < 0) {
			মুক্ত(maclist);
			ঘূৰাই 0;
		} অন্যথা
			found = 1;
	}
	মুক্ত(maclist);
	ঘূৰাই found;
}
