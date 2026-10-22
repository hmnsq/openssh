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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>

#ضمن "digest.h"
#ضمن "hmac.h"
#ضمن "umac.h"
#ضمن "mac.h"
#ضمن "misc.h"
#ضمن "ssherr.h"
#ضمن "sshbuf.h"

#ضمن "openbsd-compat/openssl-compat.h"

#تعریف_کړه SSH_DIGEST	1	/* SSH_DIGEST_XXX */
#تعریف_کړه SSH_UMAC	2	/* UMAC (not integrated with OpenSSL) */
#تعریف_کړه SSH_UMAC128	3

بنية macalg {
	حرف		*name;
	صحيح		type;
	صحيح		alg;
	صحيح		truncatebits;	/* truncate digest if != 0 */
	صحيح		کلی_len;	/* just for UMAC */
	صحيح		len;		/* just for UMAC */
	صحيح		etm;		/* Encrypt-then-MAC */
};

ساكن ثابت بنية macalg macs[] = {
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

	{ عدم,					0, 0, 0, 0, 0, 0 }
};

/* Returns a list of supported MACs separated by the specified char. */
حرف *
mac_alg_list(حرف sep)
{
	حرف *ret = عدم;
	ثابت بنية macalg *m;
	حرف sep_str[2] = {sep, '\0'};

	لكل (m = macs; m->name != عدم; m++)
		xextendf(&ret, sep_str, "%s", m->name);

	أرجع ret;
}

ساكن صحيح
mac_تیاری_by_alg(بنية sshmac *mac, ثابت بنية macalg *macalg)
{
	mac->type = macalg->type;
	إذا (mac->type == SSH_DIGEST) {
		إذا ((mac->hmac_ctx = ssh_hmac_پیل(macalg->alg)) == عدم)
			أرجع SSH_ERR_ALLOC_FAIL;
		mac->کلی_len = mac->mac_len = ssh_hmac_بایټونه(macalg->alg);
	} وإلا {
		mac->mac_len = macalg->len / 8;
		mac->کلی_len = macalg->کلی_len / 8;
		mac->umac_ctx = عدم;
	}
	إذا (macalg->truncatebits != 0)
		mac->mac_len = macalg->truncatebits / 8;
	mac->etm = macalg->etm;
	أرجع 0;
}

صحيح
mac_تیاری(بنية sshmac *mac, حرف *name)
{
	ثابت بنية macalg *m;

	لكل (m = macs; m->name != عدم; m++) {
		إذا (strcmp(name, m->name) != 0)
			استمر;
		إذا (mac != عدم)
			أرجع mac_تیاری_by_alg(mac, m);
		أرجع 0;
	}
	أرجع SSH_ERR_INVALID_دلیل;
}

صحيح
mac_init(بنية sshmac *mac)
{
	إذا (mac->کلی == عدم)
		أرجع SSH_ERR_INVALID_دلیل;
	بدل (mac->type) {
	حالة SSH_DIGEST:
		إذا (mac->hmac_ctx == عدم ||
		    ssh_hmac_init(mac->hmac_ctx, mac->کلی, mac->کلی_len) < 0)
			أرجع SSH_ERR_INVALID_دلیل;
		أرجع 0;
	حالة SSH_UMAC:
		إذا ((mac->umac_ctx = umac_new(mac->کلی)) == عدم)
			أرجع SSH_ERR_ALLOC_FAIL;
		أرجع 0;
	حالة SSH_UMAC128:
		إذا ((mac->umac_ctx = umac128_new(mac->کلی)) == عدم)
			أرجع SSH_ERR_ALLOC_FAIL;
		أرجع 0;
	افتراضي:
		أرجع SSH_ERR_INVALID_دلیل;
	}
}

صحيح
mac_compute(بنية sshmac *mac, uint32_t seqno,
    ثابت u_char *معلومات, صحيح datalen,
    u_char *digest, اندازه_t dlen)
{
	ساكن اتحاد {
		u_char m[SSH_DIGEST_MAX_اوږدتیا];
		uint64_t for_align;
	} u;
	u_char b[4];
	u_char nonce[8];

	إذا (mac->mac_len > حجم(u))
		أرجع SSH_ERR_دننی_ERROR;

	بدل (mac->type) {
	حالة SSH_DIGEST:
		put_u32(b, seqno);
		/* reset HMAC context */
		إذا (ssh_hmac_init(mac->hmac_ctx, عدم, 0) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, b, حجم(b)) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, معلومات, datalen) < 0 ||
		    ssh_hmac_final(mac->hmac_ctx, u.m, حجم(u.m)) < 0)
			أرجع SSH_ERR_LIBCRYPTO_ERROR;
		اكسر;
	حالة SSH_UMAC:
		POKE_U64(nonce, seqno);
		umac_update(mac->umac_ctx, معلومات, datalen);
		umac_final(mac->umac_ctx, u.m, nonce);
		اكسر;
	حالة SSH_UMAC128:
		put_u64(nonce, seqno);
		umac128_update(mac->umac_ctx, معلومات, datalen);
		umac128_final(mac->umac_ctx, u.m, nonce);
		اكسر;
	افتراضي:
		أرجع SSH_ERR_INVALID_دلیل;
	}
	إذا (digest != عدم) {
		إذا (dlen > mac->mac_len)
			dlen = mac->mac_len;
		حافظه_نقل(digest, u.m, dlen);
	}
	أرجع 0;
}

صحيح
mac_check(بنية sshmac *mac, uint32_t seqno,
    ثابت u_char *معلومات, اندازه_t dlen,
    ثابت u_char *theirmac, اندازه_t mlen)
{
	u_char ourmac[SSH_DIGEST_MAX_اوږدتیا];
	صحيح r;

	إذا (mac->mac_len > mlen)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا ((r = mac_compute(mac, seqno, معلومات, dlen,
	    ourmac, حجم(ourmac))) != 0)
		أرجع r;
	إذا (timingsafe_bcmp(ourmac, theirmac, mac->mac_len) != 0)
		أرجع SSH_ERR_MAC_INVALID;
	أرجع 0;
}

فراغ
mac_clear(بنية sshmac *mac)
{
	إذا (mac->type == SSH_UMAC) {
		إذا (mac->umac_ctx != عدم)
			umac_delete(mac->umac_ctx);
	} وإلا إذا (mac->type == SSH_UMAC128) {
		إذا (mac->umac_ctx != عدم)
			umac128_delete(mac->umac_ctx);
	} وإلا إذا (mac->hmac_ctx != عدم)
		ssh_hmac_free(mac->hmac_ctx);
	mac->hmac_ctx = عدم;
	mac->umac_ctx = عدم;
}

/* XXX copied from ciphers_valid */
#تعریف_کړه	MAC_SEP	","
صحيح
mac_valid(ثابت حرف *نومونه)
{
	حرف *maclist, *cp, *p;
	صحيح وموندل = 0;

	إذا (نومونه == عدم || strcmp(نومونه, "") == 0)
		أرجع 0;
	إذا ((maclist = cp = strdup(نومونه)) == عدم)
		أرجع 0;
	لكل ((p = strsep(&cp, MAC_SEP)); p && *p != '\0';
	    (p = strsep(&cp, MAC_SEP))) {
		إذا (mac_تیاری(عدم, p) < 0) {
			حرر(maclist);
			أرجع 0;
		} وإلا
			وموندل = 1;
	}
	حرر(maclist);
	أرجع وموندل;
}
