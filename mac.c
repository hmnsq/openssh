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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "hmac.h"
#ಅನ್ತರ್ಭಾವ "umac.h"
#ಅನ್ತರ್ಭಾವ "mac.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"

#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

#define SSH_DIGEST	1	/* SSH_DIGEST_XXX */
#define SSH_UMAC	2	/* UMAC (not integrated with OpenSSL) */
#define SSH_UMAC128	3

ಸಂರಚನಾ macalg {
	ವರ್ಣ		*name;
	ಪೂರ್ಣಾಙ್ಕ		type;
	ಪೂರ್ಣಾಙ್ಕ		alg;
	ಪೂರ್ಣಾಙ್ಕ		truncatebits;	/* truncate digest if != 0 */
	ಪೂರ್ಣಾಙ್ಕ		ಕೀಲಿ_len;	/* just for UMAC */
	ಪೂರ್ಣಾಙ್ಕ		len;		/* just for UMAC */
	ಪೂರ್ಣಾಙ್ಕ		etm;		/* Encrypt-then-MAC */
};

ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ macalg macs[] = {
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

	{ ರಿಕ್ತ,					0, 0, 0, 0, 0, 0 }
};

/* Returns a list of supported MACs separated by the specified char. */
ವರ್ಣ *
mac_alg_list(ವರ್ಣ sep)
{
	ವರ್ಣ *ret = ರಿಕ್ತ;
	ಧ್ರುವ ಸಂರಚನಾ macalg *m;
	ವರ್ಣ sep_str[2] = {sep, '\0'};

	ಪ್ರತಿ (m = macs; m->name != ರಿಕ್ತ; m++)
		xextendf(&ret, sep_str, "%s", m->name);

	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
mac_setup_by_alg(ಸಂರಚನಾ sshmac *mac, ಧ್ರುವ ಸಂರಚನಾ macalg *macalg)
{
	mac->type = macalg->type;
	ಯದಿ (mac->type == SSH_DIGEST) {
		ಯದಿ ((mac->hmac_ctx = ssh_hmac_start(macalg->alg)) == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
		mac->ಕೀಲಿ_len = mac->mac_len = ssh_hmac_bytes(macalg->alg);
	} ಅನ್ಯಥಾ {
		mac->mac_len = macalg->len / 8;
		mac->ಕೀಲಿ_len = macalg->ಕೀಲಿ_len / 8;
		mac->umac_ctx = ರಿಕ್ತ;
	}
	ಯದಿ (macalg->truncatebits != 0)
		mac->mac_len = macalg->truncatebits / 8;
	mac->etm = macalg->etm;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
mac_setup(ಸಂರಚನಾ sshmac *mac, ವರ್ಣ *name)
{
	ಧ್ರುವ ಸಂರಚನಾ macalg *m;

	ಪ್ರತಿ (m = macs; m->name != ರಿಕ್ತ; m++) {
		ಯದಿ (strcmp(name, m->name) != 0)
			ಅನುವರ್ತ;
		ಯದಿ (mac != ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ mac_setup_by_alg(mac, m);
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
}

ಪೂರ್ಣಾಙ್ಕ
mac_init(ಸಂರಚನಾ sshmac *mac)
{
	ಯದಿ (mac->ಕೀಲಿ == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ವಿಕಲ್ಪ (mac->type) {
	ಪಕ್ಷ SSH_DIGEST:
		ಯದಿ (mac->hmac_ctx == ರಿಕ್ತ ||
		    ssh_hmac_init(mac->hmac_ctx, mac->ಕೀಲಿ, mac->ಕೀಲಿ_len) < 0)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪಕ್ಷ SSH_UMAC:
		ಯದಿ ((mac->umac_ctx = umac_new(mac->ಕೀಲಿ)) == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪಕ್ಷ SSH_UMAC128:
		ಯದಿ ((mac->umac_ctx = umac128_new(mac->ಕೀಲಿ)) == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
		ಪ್ರತ್ಯಾಗಮ 0;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	}
}

ಪೂರ್ಣಾಙ್ಕ
mac_compute(ಸಂರಚನಾ sshmac *mac, uint32_t seqno,
    ಧ್ರುವ u_char *data, ಪೂರ್ಣಾಙ್ಕ datalen,
    u_char *digest, size_t dlen)
{
	ಸ್ಥಿರ ಸಙ್ಘ {
		u_char m[SSH_DIGEST_MAX_LENGTH];
		uint64_t for_align;
	} u;
	u_char b[4];
	u_char nonce[8];

	ಯದಿ (mac->mac_len > ಪರಿಮಾಣ(u))
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;

	ವಿಕಲ್ಪ (mac->type) {
	ಪಕ್ಷ SSH_DIGEST:
		put_u32(b, seqno);
		/* reset HMAC context */
		ಯದಿ (ssh_hmac_init(mac->hmac_ctx, ರಿಕ್ತ, 0) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, b, ಪರಿಮಾಣ(b)) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, data, datalen) < 0 ||
		    ssh_hmac_final(mac->hmac_ctx, u.m, ಪರಿಮಾಣ(u.m)) < 0)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_LIBCRYPTO_ERROR;
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_UMAC:
		POKE_U64(nonce, seqno);
		umac_update(mac->umac_ctx, data, datalen);
		umac_final(mac->umac_ctx, u.m, nonce);
		ಭಙ್ಗ;
	ಪಕ್ಷ SSH_UMAC128:
		put_u64(nonce, seqno);
		umac128_update(mac->umac_ctx, data, datalen);
		umac128_final(mac->umac_ctx, u.m, nonce);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	}
	ಯದಿ (digest != ರಿಕ್ತ) {
		ಯದಿ (dlen > mac->mac_len)
			dlen = mac->mac_len;
		memcpy(digest, u.m, dlen);
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
mac_check(ಸಂರಚನಾ sshmac *mac, uint32_t seqno,
    ಧ್ರುವ u_char *data, size_t dlen,
    ಧ್ರುವ u_char *theirmac, size_t mlen)
{
	u_char ourmac[SSH_DIGEST_MAX_LENGTH];
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (mac->mac_len > mlen)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ ((r = mac_compute(mac, seqno, data, dlen,
	    ourmac, ಪರಿಮಾಣ(ourmac))) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (timingsafe_bcmp(ourmac, theirmac, mac->mac_len) != 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_MAC_INVALID;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
mac_clear(ಸಂರಚನಾ sshmac *mac)
{
	ಯದಿ (mac->type == SSH_UMAC) {
		ಯದಿ (mac->umac_ctx != ರಿಕ್ತ)
			umac_delete(mac->umac_ctx);
	} ಅನ್ಯಥಾ ಯದಿ (mac->type == SSH_UMAC128) {
		ಯದಿ (mac->umac_ctx != ರಿಕ್ತ)
			umac128_delete(mac->umac_ctx);
	} ಅನ್ಯಥಾ ಯದಿ (mac->hmac_ctx != ರಿಕ್ತ)
		ssh_hmac_free(mac->hmac_ctx);
	mac->hmac_ctx = ರಿಕ್ತ;
	mac->umac_ctx = ರಿಕ್ತ;
}

/* XXX copied from ciphers_valid */
#define	MAC_SEP	","
ಪೂರ್ಣಾಙ್ಕ
mac_valid(ಧ್ರುವ ವರ್ಣ *names)
{
	ವರ್ಣ *maclist, *cp, *p;
	ಪೂರ್ಣಾಙ್ಕ found = 0;

	ಯದಿ (names == ರಿಕ್ತ || strcmp(names, "") == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ ((maclist = cp = strdup(names)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತಿ ((p = strsep(&cp, MAC_SEP)); p && *p != '\0';
	    (p = strsep(&cp, MAC_SEP))) {
		ಯದಿ (mac_setup(ರಿಕ್ತ, p) < 0) {
			ಮುಕ್ತ(maclist);
			ಪ್ರತ್ಯಾಗಮ 0;
		} ಅನ್ಯಥಾ
			found = 1;
	}
	ಮುಕ್ತ(maclist);
	ಪ್ರತ್ಯಾಗಮ found;
}
