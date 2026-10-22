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

#ವ್ಯಾಖ್ಯಾನಿಸು SSH_DIGEST	1	/* SSH_DIGEST_XXX */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_UMAC	2	/* UMAC (not integrated with OpenSSL) */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_UMAC128	3

ರಚನೆ macalg {
	ಅಕ್ಷರ		*name;
	ಪೂರ್ಣಾಂಕ		type;
	ಪೂರ್ಣಾಂಕ		alg;
	ಪೂರ್ಣಾಂಕ		truncatebits;	/* truncate digest if != 0 */
	ಪೂರ್ಣಾಂಕ		ಕೀಲಿ_len;	/* just for UMAC */
	ಪೂರ್ಣಾಂಕ		len;		/* just for UMAC */
	ಪೂರ್ಣಾಂಕ		etm;		/* Encrypt-then-MAC */
};

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ macalg macs[] = {
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

	{ ಖಾಲಿ,					0, 0, 0, 0, 0, 0 }
};

/* Returns a list of supported MACs separated by the specified char. */
ಅಕ್ಷರ *
mac_alg_list(ಅಕ್ಷರ sep)
{
	ಅಕ್ಷರ *ret = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ರಚನೆ macalg *m;
	ಅಕ್ಷರ sep_str[2] = {sep, '\0'};

	ಗಾಗಿ (m = macs; m->name != ಖಾಲಿ; m++)
		xextendf(&ret, sep_str, "%s", m->name);

	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
mac_ಸಿದ್ಧತೆ_by_alg(ರಚನೆ sshmac *mac, ಸ್ಥಿರಾಂಕ ರಚನೆ macalg *macalg)
{
	mac->type = macalg->type;
	ಆದರೆ (mac->type == SSH_DIGEST) {
		ಆದರೆ ((mac->hmac_ctx = ssh_hmac_ಆರಂಭ(macalg->alg)) == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
		mac->ಕೀಲಿ_len = mac->mac_len = ssh_hmac_ಬೈಟುಗಳು(macalg->alg);
	} ಇಲ್ಲದಿದ್ದರೆ {
		mac->mac_len = macalg->len / 8;
		mac->ಕೀಲಿ_len = macalg->ಕೀಲಿ_len / 8;
		mac->umac_ctx = ಖಾಲಿ;
	}
	ಆದರೆ (macalg->truncatebits != 0)
		mac->mac_len = macalg->truncatebits / 8;
	mac->etm = macalg->etm;
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
mac_ಸಿದ್ಧತೆ(ರಚನೆ sshmac *mac, ಅಕ್ಷರ *name)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ macalg *m;

	ಗಾಗಿ (m = macs; m->name != ಖಾಲಿ; m++) {
		ಆದರೆ (strcmp(name, m->name) != 0)
			ಮುಂದುವರಿ;
		ಆದರೆ (mac != ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ mac_ಸಿದ್ಧತೆ_by_alg(mac, m);
		ಹಿಂತಿರುಗಿ 0;
	}
	ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
}

ಪೂರ್ಣಾಂಕ
mac_init(ರಚನೆ sshmac *mac)
{
	ಆದರೆ (mac->ಕೀಲಿ == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆಯ್ಕೆ (mac->type) {
	ಸ್ಥಿತಿ SSH_DIGEST:
		ಆದರೆ (mac->hmac_ctx == ಖಾಲಿ ||
		    ssh_hmac_init(mac->hmac_ctx, mac->ಕೀಲಿ, mac->ಕೀಲಿ_len) < 0)
			ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
		ಹಿಂತಿರುಗಿ 0;
	ಸ್ಥಿತಿ SSH_UMAC:
		ಆದರೆ ((mac->umac_ctx = umac_new(mac->ಕೀಲಿ)) == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
		ಹಿಂತಿರುಗಿ 0;
	ಸ್ಥಿತಿ SSH_UMAC128:
		ಆದರೆ ((mac->umac_ctx = umac128_new(mac->ಕೀಲಿ)) == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
		ಹಿಂತಿರುಗಿ 0;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	}
}

ಪೂರ್ಣಾಂಕ
mac_compute(ರಚನೆ sshmac *mac, uint32_t seqno,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಪೂರ್ಣಾಂಕ datalen,
    u_char *digest, ಗಾತ್ರ_t dlen)
{
	ಸ್ಥಿರ ಒಕ್ಕೂಟ {
		u_char m[SSH_DIGEST_MAX_ಉದ್ದಳತೆ];
		uint64_t for_align;
	} u;
	u_char b[4];
	u_char nonce[8];

	ಆದರೆ (mac->mac_len > ಗಾತ್ರ(u))
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆಯ್ಕೆ (mac->type) {
	ಸ್ಥಿತಿ SSH_DIGEST:
		put_u32(b, seqno);
		/* reset HMAC context */
		ಆದರೆ (ssh_hmac_init(mac->hmac_ctx, ಖಾಲಿ, 0) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, b, ಗಾತ್ರ(b)) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, ದತ್ತಾಂಶ, datalen) < 0 ||
		    ssh_hmac_final(mac->hmac_ctx, u.m, ಗಾತ್ರ(u.m)) < 0)
			ಹಿಂತಿರುಗಿ SSH_ERR_LIBCRYPTO_ERROR;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_UMAC:
		POKE_U64(nonce, seqno);
		umac_update(mac->umac_ctx, ದತ್ತಾಂಶ, datalen);
		umac_final(mac->umac_ctx, u.m, nonce);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ SSH_UMAC128:
		put_u64(nonce, seqno);
		umac128_update(mac->umac_ctx, ದತ್ತಾಂಶ, datalen);
		umac128_final(mac->umac_ctx, u.m, nonce);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	}
	ಆದರೆ (digest != ಖಾಲಿ) {
		ಆದರೆ (dlen > mac->mac_len)
			dlen = mac->mac_len;
		ಸ್ಮರಣೆ_ನಕಲು(digest, u.m, dlen);
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
mac_check(ರಚನೆ sshmac *mac, uint32_t seqno,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t dlen,
    ಸ್ಥಿರಾಂಕ u_char *theirmac, ಗಾತ್ರ_t mlen)
{
	u_char ourmac[SSH_DIGEST_MAX_ಉದ್ದಳತೆ];
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (mac->mac_len > mlen)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ ((r = mac_compute(mac, seqno, ದತ್ತಾಂಶ, dlen,
	    ourmac, ಗಾತ್ರ(ourmac))) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (timingsafe_bcmp(ourmac, theirmac, mac->mac_len) != 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_MAC_INVALID;
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
mac_clear(ರಚನೆ sshmac *mac)
{
	ಆದರೆ (mac->type == SSH_UMAC) {
		ಆದರೆ (mac->umac_ctx != ಖಾಲಿ)
			umac_delete(mac->umac_ctx);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (mac->type == SSH_UMAC128) {
		ಆದರೆ (mac->umac_ctx != ಖಾಲಿ)
			umac128_delete(mac->umac_ctx);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (mac->hmac_ctx != ಖಾಲಿ)
		ssh_hmac_free(mac->hmac_ctx);
	mac->hmac_ctx = ಖಾಲಿ;
	mac->umac_ctx = ಖಾಲಿ;
}

/* XXX copied from ciphers_valid */
#ವ್ಯಾಖ್ಯಾನಿಸು	MAC_SEP	","
ಪೂರ್ಣಾಂಕ
mac_valid(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಹೆಸರುಗಳು)
{
	ಅಕ್ಷರ *maclist, *cp, *p;
	ಪೂರ್ಣಾಂಕ ಸಿಕ್ಕಿತು = 0;

	ಆದರೆ (ಹೆಸರುಗಳು == ಖಾಲಿ || strcmp(ಹೆಸರುಗಳು, "") == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ ((maclist = cp = strdup(ಹೆಸರುಗಳು)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಗಾಗಿ ((p = strsep(&cp, MAC_SEP)); p && *p != '\0';
	    (p = strsep(&cp, MAC_SEP))) {
		ಆದರೆ (mac_ಸಿದ್ಧತೆ(ಖಾಲಿ, p) < 0) {
			ಬಿಡುಗಡೆ(maclist);
			ಹಿಂತಿರುಗಿ 0;
		} ಇಲ್ಲದಿದ್ದರೆ
			ಸಿಕ್ಕಿತು = 1;
	}
	ಬಿಡುಗಡೆ(maclist);
	ಹಿಂತಿರುಗಿ ಸಿಕ್ಕಿತು;
}
