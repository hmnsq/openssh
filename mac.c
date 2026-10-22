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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hmac.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "umac.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "mac.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_DIGEST	1	/* SSH_DIGEST_XXX */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_UMAC	2	/* UMAC (not integrated with OpenSSL) */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_UMAC128	3

ਬਣਤਰ macalg {
	ਅੱਖਰ		*name;
	ਪੂਰਨ		type;
	ਪੂਰਨ		alg;
	ਪੂਰਨ		truncatebits;	/* truncate digest if != 0 */
	ਪੂਰਨ		ਕੁੰਜੀ_len;	/* just for UMAC */
	ਪੂਰਨ		len;		/* just for UMAC */
	ਪੂਰਨ		etm;		/* Encrypt-then-MAC */
};

ਸਥਿਰ ਅਚਲ ਬਣਤਰ macalg macs[] = {
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

	{ ਨਿਰਾ,					0, 0, 0, 0, 0, 0 }
};

/* Returns a list of supported MACs separated by the specified char. */
ਅੱਖਰ *
mac_alg_list(ਅੱਖਰ sep)
{
	ਅੱਖਰ *ret = ਨਿਰਾ;
	ਅਚਲ ਬਣਤਰ macalg *m;
	ਅੱਖਰ sep_str[2] = {sep, '\0'};

	ਲਈ (m = macs; m->name != ਨਿਰਾ; m++)
		xextendf(&ret, sep_str, "%s", m->name);

	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
mac_ਤਿਆਰੀ_by_alg(ਬਣਤਰ sshmac *mac, ਅਚਲ ਬਣਤਰ macalg *macalg)
{
	mac->type = macalg->type;
	ਜੇ (mac->type == SSH_DIGEST) {
		ਜੇ ((mac->hmac_ctx = ssh_hmac_ਸ਼ੁਰੂ(macalg->alg)) == ਨਿਰਾ)
			ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
		mac->ਕੁੰਜੀ_len = mac->mac_len = ssh_hmac_ਬਾਈਟਾਂ(macalg->alg);
	} ਨਹੀਂਤਾਂ {
		mac->mac_len = macalg->len / 8;
		mac->ਕੁੰਜੀ_len = macalg->ਕੁੰਜੀ_len / 8;
		mac->umac_ctx = ਨਿਰਾ;
	}
	ਜੇ (macalg->truncatebits != 0)
		mac->mac_len = macalg->truncatebits / 8;
	mac->etm = macalg->etm;
	ਵਾਪਸ 0;
}

ਪੂਰਨ
mac_ਤਿਆਰੀ(ਬਣਤਰ sshmac *mac, ਅੱਖਰ *name)
{
	ਅਚਲ ਬਣਤਰ macalg *m;

	ਲਈ (m = macs; m->name != ਨਿਰਾ; m++) {
		ਜੇ (strcmp(name, m->name) != 0)
			ਜਾਰੀ;
		ਜੇ (mac != ਨਿਰਾ)
			ਵਾਪਸ mac_ਤਿਆਰੀ_by_alg(mac, m);
		ਵਾਪਸ 0;
	}
	ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
}

ਪੂਰਨ
mac_init(ਬਣਤਰ sshmac *mac)
{
	ਜੇ (mac->ਕੁੰਜੀ == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਚੋਣ (mac->type) {
	ਹਾਲਤ SSH_DIGEST:
		ਜੇ (mac->hmac_ctx == ਨਿਰਾ ||
		    ssh_hmac_init(mac->hmac_ctx, mac->ਕੁੰਜੀ, mac->ਕੁੰਜੀ_len) < 0)
			ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
		ਵਾਪਸ 0;
	ਹਾਲਤ SSH_UMAC:
		ਜੇ ((mac->umac_ctx = umac_new(mac->ਕੁੰਜੀ)) == ਨਿਰਾ)
			ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
		ਵਾਪਸ 0;
	ਹਾਲਤ SSH_UMAC128:
		ਜੇ ((mac->umac_ctx = umac128_new(mac->ਕੁੰਜੀ)) == ਨਿਰਾ)
			ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
		ਵਾਪਸ 0;
	ਮੂਲ:
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	}
}

ਪੂਰਨ
mac_compute(ਬਣਤਰ sshmac *mac, uint32_t seqno,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਪੂਰਨ datalen,
    u_char *digest, ਮਾਪ_t dlen)
{
	ਸਥਿਰ ਸੰਘ {
		u_char m[SSH_DIGEST_MAX_ਲੰਮਾਈ];
		uint64_t for_align;
	} u;
	u_char b[4];
	u_char nonce[8];

	ਜੇ (mac->mac_len > ਆਕਾਰ(u))
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਚੋਣ (mac->type) {
	ਹਾਲਤ SSH_DIGEST:
		put_u32(b, seqno);
		/* reset HMAC context */
		ਜੇ (ssh_hmac_init(mac->hmac_ctx, ਨਿਰਾ, 0) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, b, ਆਕਾਰ(b)) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, ਅੰਕੜੇ, datalen) < 0 ||
		    ssh_hmac_final(mac->hmac_ctx, u.m, ਆਕਾਰ(u.m)) < 0)
			ਵਾਪਸ SSH_ERR_LIBCRYPTO_ERROR;
		ਰੋਕੋ;
	ਹਾਲਤ SSH_UMAC:
		POKE_U64(nonce, seqno);
		umac_update(mac->umac_ctx, ਅੰਕੜੇ, datalen);
		umac_final(mac->umac_ctx, u.m, nonce);
		ਰੋਕੋ;
	ਹਾਲਤ SSH_UMAC128:
		put_u64(nonce, seqno);
		umac128_update(mac->umac_ctx, ਅੰਕੜੇ, datalen);
		umac128_final(mac->umac_ctx, u.m, nonce);
		ਰੋਕੋ;
	ਮੂਲ:
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	}
	ਜੇ (digest != ਨਿਰਾ) {
		ਜੇ (dlen > mac->mac_len)
			dlen = mac->mac_len;
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(digest, u.m, dlen);
	}
	ਵਾਪਸ 0;
}

ਪੂਰਨ
mac_check(ਬਣਤਰ sshmac *mac, uint32_t seqno,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t dlen,
    ਅਚਲ u_char *theirmac, ਮਾਪ_t mlen)
{
	u_char ourmac[SSH_DIGEST_MAX_ਲੰਮਾਈ];
	ਪੂਰਨ r;

	ਜੇ (mac->mac_len > mlen)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ ((r = mac_compute(mac, seqno, ਅੰਕੜੇ, dlen,
	    ourmac, ਆਕਾਰ(ourmac))) != 0)
		ਵਾਪਸ r;
	ਜੇ (timingsafe_bcmp(ourmac, theirmac, mac->mac_len) != 0)
		ਵਾਪਸ SSH_ERR_MAC_INVALID;
	ਵਾਪਸ 0;
}

ਖਾਲੀ
mac_clear(ਬਣਤਰ sshmac *mac)
{
	ਜੇ (mac->type == SSH_UMAC) {
		ਜੇ (mac->umac_ctx != ਨਿਰਾ)
			umac_delete(mac->umac_ctx);
	} ਨਹੀਂਤਾਂ ਜੇ (mac->type == SSH_UMAC128) {
		ਜੇ (mac->umac_ctx != ਨਿਰਾ)
			umac128_delete(mac->umac_ctx);
	} ਨਹੀਂਤਾਂ ਜੇ (mac->hmac_ctx != ਨਿਰਾ)
		ssh_hmac_free(mac->hmac_ctx);
	mac->hmac_ctx = ਨਿਰਾ;
	mac->umac_ctx = ਨਿਰਾ;
}

/* XXX copied from ciphers_valid */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	MAC_SEP	","
ਪੂਰਨ
mac_valid(ਅਚਲ ਅੱਖਰ *ਨਾਂ)
{
	ਅੱਖਰ *maclist, *cp, *p;
	ਪੂਰਨ ਮਿਲਿਆ = 0;

	ਜੇ (ਨਾਂ == ਨਿਰਾ || strcmp(ਨਾਂ, "") == 0)
		ਵਾਪਸ 0;
	ਜੇ ((maclist = cp = strdup(ਨਾਂ)) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਲਈ ((p = strsep(&cp, MAC_SEP)); p && *p != '\0';
	    (p = strsep(&cp, MAC_SEP))) {
		ਜੇ (mac_ਤਿਆਰੀ(ਨਿਰਾ, p) < 0) {
			ਮੁਕਤ(maclist);
			ਵਾਪਸ 0;
		} ਨਹੀਂਤਾਂ
			ਮਿਲਿਆ = 1;
	}
	ਮੁਕਤ(maclist);
	ਵਾਪਸ ਮਿਲਿਆ;
}
