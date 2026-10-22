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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "hmac.h"
#অন্তর্ভাব "umac.h"
#অন্তর্ভাব "mac.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"

#অন্তর্ভাব "openbsd-compat/openssl-compat.h"

#define SSH_DIGEST	1	/* SSH_DIGEST_XXX */
#define SSH_UMAC	2	/* UMAC (not integrated with OpenSSL) */
#define SSH_UMAC128	3

কাঠামো macalg {
	অক্ষর		*name;
	পূর্ণসংখ্যা		type;
	পূর্ণসংখ্যা		alg;
	পূর্ণসংখ্যা		truncatebits;	/* truncate digest if != 0 */
	পূর্ণসংখ্যা		চাবি_len;	/* just for UMAC */
	পূর্ণসংখ্যা		len;		/* just for UMAC */
	পূর্ণসংখ্যা		etm;		/* Encrypt-then-MAC */
};

স্থির ধ্রুবক কাঠামো macalg macs[] = {
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

	{ ফাঁকা,					0, 0, 0, 0, 0, 0 }
};

/* Returns a list of supported MACs separated by the specified char. */
অক্ষর *
mac_alg_list(অক্ষর sep)
{
	অক্ষর *ret = ফাঁকা;
	ধ্রুবক কাঠামো macalg *m;
	অক্ষর sep_str[2] = {sep, '\0'};

	জন্য (m = macs; m->name != ফাঁকা; m++)
		xextendf(&ret, sep_str, "%s", m->name);

	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
mac_setup_by_alg(কাঠামো sshmac *mac, ধ্রুবক কাঠামো macalg *macalg)
{
	mac->type = macalg->type;
	যদি (mac->type == SSH_DIGEST) {
		যদি ((mac->hmac_ctx = ssh_hmac_start(macalg->alg)) == ফাঁকা)
			ফেরত SSH_ERR_ALLOC_FAIL;
		mac->চাবি_len = mac->mac_len = ssh_hmac_bytes(macalg->alg);
	} অন্যথা {
		mac->mac_len = macalg->len / 8;
		mac->চাবি_len = macalg->চাবি_len / 8;
		mac->umac_ctx = ফাঁকা;
	}
	যদি (macalg->truncatebits != 0)
		mac->mac_len = macalg->truncatebits / 8;
	mac->etm = macalg->etm;
	ফেরত 0;
}

পূর্ণসংখ্যা
mac_setup(কাঠামো sshmac *mac, অক্ষর *name)
{
	ধ্রুবক কাঠামো macalg *m;

	জন্য (m = macs; m->name != ফাঁকা; m++) {
		যদি (strcmp(name, m->name) != 0)
			চালু;
		যদি (mac != ফাঁকা)
			ফেরত mac_setup_by_alg(mac, m);
		ফেরত 0;
	}
	ফেরত SSH_ERR_INVALID_ARGUMENT;
}

পূর্ণসংখ্যা
mac_init(কাঠামো sshmac *mac)
{
	যদি (mac->চাবি == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	নির্বাচন (mac->type) {
	ক্ষেত্র SSH_DIGEST:
		যদি (mac->hmac_ctx == ফাঁকা ||
		    ssh_hmac_init(mac->hmac_ctx, mac->চাবি, mac->চাবি_len) < 0)
			ফেরত SSH_ERR_INVALID_ARGUMENT;
		ফেরত 0;
	ক্ষেত্র SSH_UMAC:
		যদি ((mac->umac_ctx = umac_new(mac->চাবি)) == ফাঁকা)
			ফেরত SSH_ERR_ALLOC_FAIL;
		ফেরত 0;
	ক্ষেত্র SSH_UMAC128:
		যদি ((mac->umac_ctx = umac128_new(mac->চাবি)) == ফাঁকা)
			ফেরত SSH_ERR_ALLOC_FAIL;
		ফেরত 0;
	পূর্বনির্ধারিত:
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	}
}

পূর্ণসংখ্যা
mac_compute(কাঠামো sshmac *mac, uint32_t seqno,
    ধ্রুবক u_char *তথ্য, পূর্ণসংখ্যা datalen,
    u_char *digest, আকার_t dlen)
{
	স্থির সংঘ {
		u_char m[SSH_DIGEST_MAX_দৈর্ঘ্য];
		uint64_t for_align;
	} u;
	u_char b[4];
	u_char nonce[8];

	যদি (mac->mac_len > আকার(u))
		ফেরত SSH_ERR_INTERNAL_ERROR;

	নির্বাচন (mac->type) {
	ক্ষেত্র SSH_DIGEST:
		put_u32(b, seqno);
		/* reset HMAC context */
		যদি (ssh_hmac_init(mac->hmac_ctx, ফাঁকা, 0) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, b, আকার(b)) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, তথ্য, datalen) < 0 ||
		    ssh_hmac_final(mac->hmac_ctx, u.m, আকার(u.m)) < 0)
			ফেরত SSH_ERR_LIBCRYPTO_ERROR;
		বিরতি;
	ক্ষেত্র SSH_UMAC:
		POKE_U64(nonce, seqno);
		umac_update(mac->umac_ctx, তথ্য, datalen);
		umac_final(mac->umac_ctx, u.m, nonce);
		বিরতি;
	ক্ষেত্র SSH_UMAC128:
		put_u64(nonce, seqno);
		umac128_update(mac->umac_ctx, তথ্য, datalen);
		umac128_final(mac->umac_ctx, u.m, nonce);
		বিরতি;
	পূর্বনির্ধারিত:
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	}
	যদি (digest != ফাঁকা) {
		যদি (dlen > mac->mac_len)
			dlen = mac->mac_len;
		memcpy(digest, u.m, dlen);
	}
	ফেরত 0;
}

পূর্ণসংখ্যা
mac_check(কাঠামো sshmac *mac, uint32_t seqno,
    ধ্রুবক u_char *তথ্য, আকার_t dlen,
    ধ্রুবক u_char *theirmac, আকার_t mlen)
{
	u_char ourmac[SSH_DIGEST_MAX_দৈর্ঘ্য];
	পূর্ণসংখ্যা r;

	যদি (mac->mac_len > mlen)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি ((r = mac_compute(mac, seqno, তথ্য, dlen,
	    ourmac, আকার(ourmac))) != 0)
		ফেরত r;
	যদি (timingsafe_bcmp(ourmac, theirmac, mac->mac_len) != 0)
		ফেরত SSH_ERR_MAC_INVALID;
	ফেরত 0;
}

শূন্য
mac_clear(কাঠামো sshmac *mac)
{
	যদি (mac->type == SSH_UMAC) {
		যদি (mac->umac_ctx != ফাঁকা)
			umac_delete(mac->umac_ctx);
	} অন্যথা যদি (mac->type == SSH_UMAC128) {
		যদি (mac->umac_ctx != ফাঁকা)
			umac128_delete(mac->umac_ctx);
	} অন্যথা যদি (mac->hmac_ctx != ফাঁকা)
		ssh_hmac_free(mac->hmac_ctx);
	mac->hmac_ctx = ফাঁকা;
	mac->umac_ctx = ফাঁকা;
}

/* XXX copied from ciphers_valid */
#define	MAC_SEP	","
পূর্ণসংখ্যা
mac_valid(ধ্রুবক অক্ষর *names)
{
	অক্ষর *maclist, *cp, *p;
	পূর্ণসংখ্যা found = 0;

	যদি (names == ফাঁকা || strcmp(names, "") == 0)
		ফেরত 0;
	যদি ((maclist = cp = strdup(names)) == ফাঁকা)
		ফেরত 0;
	জন্য ((p = strsep(&cp, MAC_SEP)); p && *p != '\0';
	    (p = strsep(&cp, MAC_SEP))) {
		যদি (mac_setup(ফাঁকা, p) < 0) {
			মুক্ত(maclist);
			ফেরত 0;
		} অন্যথা
			found = 1;
	}
	মুক্ত(maclist);
	ফেরত found;
}
