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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>

#شامل "digest.h"
#شامل "hmac.h"
#شامل "umac.h"
#شامل "mac.h"
#شامل "misc.h"
#شامل "ssherr.h"
#شامل "sshbuf.h"

#شامل "openbsd-compat/openssl-compat.h"

#تعریف_کرو SSH_DIGEST	1	/* SSH_DIGEST_XXX */
#تعریف_کرو SSH_UMAC	2	/* UMAC (not integrated with OpenSSL) */
#تعریف_کرو SSH_UMAC128	3

ساخت macalg {
	حرف		*name;
	صحیح		type;
	صحیح		alg;
	صحیح		truncatebits;	/* truncate digest if != 0 */
	صحیح		کلید_len;	/* just for UMAC */
	صحیح		len;		/* just for UMAC */
	صحیح		etm;		/* Encrypt-then-MAC */
};

ساکن ثابت ساخت macalg macs[] = {
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

	{ تہی,					0, 0, 0, 0, 0, 0 }
};

/* Returns a list of supported MACs separated by the specified char. */
حرف *
mac_alg_list(حرف sep)
{
	حرف *ret = تہی;
	ثابت ساخت macalg *m;
	حرف sep_str[2] = {sep, '\0'};

	برائے (m = macs; m->name != تہی; m++)
		xextendf(&ret, sep_str, "%s", m->name);

	واپس ret;
}

ساکن صحیح
mac_تیاری_by_alg(ساخت sshmac *mac, ثابت ساخت macalg *macalg)
{
	mac->type = macalg->type;
	اگر (mac->type == SSH_DIGEST) {
		اگر ((mac->hmac_ctx = ssh_hmac_آغاز(macalg->alg)) == تہی)
			واپس SSH_ERR_ALLOC_FAIL;
		mac->کلید_len = mac->mac_len = ssh_hmac_بائٹیں(macalg->alg);
	} ورنہ {
		mac->mac_len = macalg->len / 8;
		mac->کلید_len = macalg->کلید_len / 8;
		mac->umac_ctx = تہی;
	}
	اگر (macalg->truncatebits != 0)
		mac->mac_len = macalg->truncatebits / 8;
	mac->etm = macalg->etm;
	واپس 0;
}

صحیح
mac_تیاری(ساخت sshmac *mac, حرف *name)
{
	ثابت ساخت macalg *m;

	برائے (m = macs; m->name != تہی; m++) {
		اگر (strcmp(name, m->name) != 0)
			جاری;
		اگر (mac != تہی)
			واپس mac_تیاری_by_alg(mac, m);
		واپس 0;
	}
	واپس SSH_ERR_INVALID_دلیل;
}

صحیح
mac_init(ساخت sshmac *mac)
{
	اگر (mac->کلید == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	انتخاب (mac->type) {
	حالت SSH_DIGEST:
		اگر (mac->hmac_ctx == تہی ||
		    ssh_hmac_init(mac->hmac_ctx, mac->کلید, mac->کلید_len) < 0)
			واپس SSH_ERR_INVALID_دلیل;
		واپس 0;
	حالت SSH_UMAC:
		اگر ((mac->umac_ctx = umac_new(mac->کلید)) == تہی)
			واپس SSH_ERR_ALLOC_FAIL;
		واپس 0;
	حالت SSH_UMAC128:
		اگر ((mac->umac_ctx = umac128_new(mac->کلید)) == تہی)
			واپس SSH_ERR_ALLOC_FAIL;
		واپس 0;
	طےشدہ:
		واپس SSH_ERR_INVALID_دلیل;
	}
}

صحیح
mac_compute(ساخت sshmac *mac, uint32_t seqno,
    ثابت u_char *ڈیٹا, صحیح datalen,
    u_char *digest, سائز_t dlen)
{
	ساکن اتحاد {
		u_char m[SSH_DIGEST_MAX_لمبائی];
		uint64_t for_align;
	} u;
	u_char b[4];
	u_char nonce[8];

	اگر (mac->mac_len > حجم(u))
		واپس SSH_ERR_اندرونی_ERROR;

	انتخاب (mac->type) {
	حالت SSH_DIGEST:
		put_u32(b, seqno);
		/* reset HMAC context */
		اگر (ssh_hmac_init(mac->hmac_ctx, تہی, 0) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, b, حجم(b)) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, ڈیٹا, datalen) < 0 ||
		    ssh_hmac_final(mac->hmac_ctx, u.m, حجم(u.m)) < 0)
			واپس SSH_ERR_LIBCRYPTO_ERROR;
		توڑو;
	حالت SSH_UMAC:
		POKE_U64(nonce, seqno);
		umac_update(mac->umac_ctx, ڈیٹا, datalen);
		umac_final(mac->umac_ctx, u.m, nonce);
		توڑو;
	حالت SSH_UMAC128:
		put_u64(nonce, seqno);
		umac128_update(mac->umac_ctx, ڈیٹا, datalen);
		umac128_final(mac->umac_ctx, u.m, nonce);
		توڑو;
	طےشدہ:
		واپس SSH_ERR_INVALID_دلیل;
	}
	اگر (digest != تہی) {
		اگر (dlen > mac->mac_len)
			dlen = mac->mac_len;
		حافظہ_نقل(digest, u.m, dlen);
	}
	واپس 0;
}

صحیح
mac_check(ساخت sshmac *mac, uint32_t seqno,
    ثابت u_char *ڈیٹا, سائز_t dlen,
    ثابت u_char *theirmac, سائز_t mlen)
{
	u_char ourmac[SSH_DIGEST_MAX_لمبائی];
	صحیح r;

	اگر (mac->mac_len > mlen)
		واپس SSH_ERR_INVALID_دلیل;
	اگر ((r = mac_compute(mac, seqno, ڈیٹا, dlen,
	    ourmac, حجم(ourmac))) != 0)
		واپس r;
	اگر (timingsafe_bcmp(ourmac, theirmac, mac->mac_len) != 0)
		واپس SSH_ERR_MAC_INVALID;
	واپس 0;
}

خالی
mac_clear(ساخت sshmac *mac)
{
	اگر (mac->type == SSH_UMAC) {
		اگر (mac->umac_ctx != تہی)
			umac_delete(mac->umac_ctx);
	} ورنہ اگر (mac->type == SSH_UMAC128) {
		اگر (mac->umac_ctx != تہی)
			umac128_delete(mac->umac_ctx);
	} ورنہ اگر (mac->hmac_ctx != تہی)
		ssh_hmac_free(mac->hmac_ctx);
	mac->hmac_ctx = تہی;
	mac->umac_ctx = تہی;
}

/* XXX copied from ciphers_valid */
#تعریف_کرو	MAC_SEP	","
صحیح
mac_valid(ثابت حرف *نام)
{
	حرف *maclist, *cp, *p;
	صحیح ملا = 0;

	اگر (نام == تہی || strcmp(نام, "") == 0)
		واپس 0;
	اگر ((maclist = cp = strdup(نام)) == تہی)
		واپس 0;
	برائے ((p = strsep(&cp, MAC_SEP)); p && *p != '\0';
	    (p = strsep(&cp, MAC_SEP))) {
		اگر (mac_تیاری(تہی, p) < 0) {
			آزاد(maclist);
			واپس 0;
		} ورنہ
			ملا = 1;
	}
	آزاد(maclist);
	واپس ملا;
}
