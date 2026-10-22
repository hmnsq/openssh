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

#define SSH_DIGEST	1	/* SSH_DIGEST_XXX */
#define SSH_UMAC	2	/* UMAC (not integrated with OpenSSL) */
#define SSH_UMAC128	3

ساختار macalg {
	نویسه		*name;
	صحیح		type;
	صحیح		alg;
	صحیح		truncatebits;	/* truncate digest if != 0 */
	صحیح		کلید_len;	/* just for UMAC */
	صحیح		len;		/* just for UMAC */
	صحیح		etm;		/* Encrypt-then-MAC */
};

ایستا ثابت ساختار macalg macs[] = {
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

	{ پوچ,					0, 0, 0, 0, 0, 0 }
};

/* Returns a list of supported MACs separated by the specified char. */
نویسه *
mac_alg_list(نویسه sep)
{
	نویسه *ret = پوچ;
	ثابت ساختار macalg *m;
	نویسه sep_str[2] = {sep, '\0'};

	برای (m = macs; m->name != پوچ; m++)
		xextendf(&ret, sep_str, "%s", m->name);

	بازگشت ret;
}

ایستا صحیح
mac_setup_by_alg(ساختار sshmac *mac, ثابت ساختار macalg *macalg)
{
	mac->type = macalg->type;
	اگر (mac->type == SSH_DIGEST) {
		اگر ((mac->hmac_ctx = ssh_hmac_start(macalg->alg)) == پوچ)
			بازگشت SSH_ERR_ALLOC_FAIL;
		mac->کلید_len = mac->mac_len = ssh_hmac_bytes(macalg->alg);
	} وگرنه {
		mac->mac_len = macalg->len / 8;
		mac->کلید_len = macalg->کلید_len / 8;
		mac->umac_ctx = پوچ;
	}
	اگر (macalg->truncatebits != 0)
		mac->mac_len = macalg->truncatebits / 8;
	mac->etm = macalg->etm;
	بازگشت 0;
}

صحیح
mac_setup(ساختار sshmac *mac, نویسه *name)
{
	ثابت ساختار macalg *m;

	برای (m = macs; m->name != پوچ; m++) {
		اگر (strcmp(name, m->name) != 0)
			ادامه;
		اگر (mac != پوچ)
			بازگشت mac_setup_by_alg(mac, m);
		بازگشت 0;
	}
	بازگشت SSH_ERR_INVALID_ARGUMENT;
}

صحیح
mac_init(ساختار sshmac *mac)
{
	اگر (mac->کلید == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	انتخاب (mac->type) {
	حالت SSH_DIGEST:
		اگر (mac->hmac_ctx == پوچ ||
		    ssh_hmac_init(mac->hmac_ctx, mac->کلید, mac->کلید_len) < 0)
			بازگشت SSH_ERR_INVALID_ARGUMENT;
		بازگشت 0;
	حالت SSH_UMAC:
		اگر ((mac->umac_ctx = umac_new(mac->کلید)) == پوچ)
			بازگشت SSH_ERR_ALLOC_FAIL;
		بازگشت 0;
	حالت SSH_UMAC128:
		اگر ((mac->umac_ctx = umac128_new(mac->کلید)) == پوچ)
			بازگشت SSH_ERR_ALLOC_FAIL;
		بازگشت 0;
	پیشفرض:
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	}
}

صحیح
mac_compute(ساختار sshmac *mac, uint32_t seqno,
    ثابت u_char *data, صحیح datalen,
    u_char *digest, size_t dlen)
{
	ایستا اجتماع {
		u_char m[SSH_DIGEST_MAX_LENGTH];
		uint64_t for_align;
	} u;
	u_char b[4];
	u_char nonce[8];

	اگر (mac->mac_len > اندازه(u))
		بازگشت SSH_ERR_INTERNAL_ERROR;

	انتخاب (mac->type) {
	حالت SSH_DIGEST:
		put_u32(b, seqno);
		/* reset HMAC context */
		اگر (ssh_hmac_init(mac->hmac_ctx, پوچ, 0) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, b, اندازه(b)) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, data, datalen) < 0 ||
		    ssh_hmac_final(mac->hmac_ctx, u.m, اندازه(u.m)) < 0)
			بازگشت SSH_ERR_LIBCRYPTO_ERROR;
		بشکن;
	حالت SSH_UMAC:
		POKE_U64(nonce, seqno);
		umac_update(mac->umac_ctx, data, datalen);
		umac_final(mac->umac_ctx, u.m, nonce);
		بشکن;
	حالت SSH_UMAC128:
		put_u64(nonce, seqno);
		umac128_update(mac->umac_ctx, data, datalen);
		umac128_final(mac->umac_ctx, u.m, nonce);
		بشکن;
	پیشفرض:
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	}
	اگر (digest != پوچ) {
		اگر (dlen > mac->mac_len)
			dlen = mac->mac_len;
		memcpy(digest, u.m, dlen);
	}
	بازگشت 0;
}

صحیح
mac_check(ساختار sshmac *mac, uint32_t seqno,
    ثابت u_char *data, size_t dlen,
    ثابت u_char *theirmac, size_t mlen)
{
	u_char ourmac[SSH_DIGEST_MAX_LENGTH];
	صحیح r;

	اگر (mac->mac_len > mlen)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر ((r = mac_compute(mac, seqno, data, dlen,
	    ourmac, اندازه(ourmac))) != 0)
		بازگشت r;
	اگر (timingsafe_bcmp(ourmac, theirmac, mac->mac_len) != 0)
		بازگشت SSH_ERR_MAC_INVALID;
	بازگشت 0;
}

تهی
mac_clear(ساختار sshmac *mac)
{
	اگر (mac->type == SSH_UMAC) {
		اگر (mac->umac_ctx != پوچ)
			umac_delete(mac->umac_ctx);
	} وگرنه اگر (mac->type == SSH_UMAC128) {
		اگر (mac->umac_ctx != پوچ)
			umac128_delete(mac->umac_ctx);
	} وگرنه اگر (mac->hmac_ctx != پوچ)
		ssh_hmac_free(mac->hmac_ctx);
	mac->hmac_ctx = پوچ;
	mac->umac_ctx = پوچ;
}

/* XXX copied from ciphers_valid */
#define	MAC_SEP	","
صحیح
mac_valid(ثابت نویسه *names)
{
	نویسه *maclist, *cp, *p;
	صحیح found = 0;

	اگر (names == پوچ || strcmp(names, "") == 0)
		بازگشت 0;
	اگر ((maclist = cp = strdup(names)) == پوچ)
		بازگشت 0;
	برای ((p = strsep(&cp, MAC_SEP)); p && *p != '\0';
	    (p = strsep(&cp, MAC_SEP))) {
		اگر (mac_setup(پوچ, p) < 0) {
			آزاد(maclist);
			بازگشت 0;
		} وگرنه
			found = 1;
	}
	آزاد(maclist);
	بازگشت found;
}
