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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "hmac.h"
#അന്തര്ഭാവ "umac.h"
#അന്തര്ഭാവ "mac.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshbuf.h"

#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"

#define SSH_DIGEST	1	/* SSH_DIGEST_XXX */
#define SSH_UMAC	2	/* UMAC (not integrated with OpenSSL) */
#define SSH_UMAC128	3

ഘടന macalg {
	അക്ഷരം		*name;
	പൂർണ്ണസംഖ്യ		type;
	പൂർണ്ണസംഖ്യ		alg;
	പൂർണ്ണസംഖ്യ		truncatebits;	/* truncate digest if != 0 */
	പൂർണ്ണസംഖ്യ		താക്കോൽ_len;	/* just for UMAC */
	പൂർണ്ണസംഖ്യ		len;		/* just for UMAC */
	പൂർണ്ണസംഖ്യ		etm;		/* Encrypt-then-MAC */
};

സ്ഥിതം സ്ഥിരം ഘടന macalg macs[] = {
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

	{ ശൂന്യ,					0, 0, 0, 0, 0, 0 }
};

/* Returns a list of supported MACs separated by the specified char. */
അക്ഷരം *
mac_alg_list(അക്ഷരം sep)
{
	അക്ഷരം *ret = ശൂന്യ;
	സ്ഥിരം ഘടന macalg *m;
	അക്ഷരം sep_str[2] = {sep, '\0'};

	വേണ്ടി (m = macs; m->name != ശൂന്യ; m++)
		xextendf(&ret, sep_str, "%s", m->name);

	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
mac_setup_by_alg(ഘടന sshmac *mac, സ്ഥിരം ഘടന macalg *macalg)
{
	mac->type = macalg->type;
	എങ്കിൽ (mac->type == SSH_DIGEST) {
		എങ്കിൽ ((mac->hmac_ctx = ssh_hmac_start(macalg->alg)) == ശൂന്യ)
			തിരികെ SSH_ERR_ALLOC_FAIL;
		mac->താക്കോൽ_len = mac->mac_len = ssh_hmac_bytes(macalg->alg);
	} അല്ലെങ്കിൽ {
		mac->mac_len = macalg->len / 8;
		mac->താക്കോൽ_len = macalg->താക്കോൽ_len / 8;
		mac->umac_ctx = ശൂന്യ;
	}
	എങ്കിൽ (macalg->truncatebits != 0)
		mac->mac_len = macalg->truncatebits / 8;
	mac->etm = macalg->etm;
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
mac_setup(ഘടന sshmac *mac, അക്ഷരം *name)
{
	സ്ഥിരം ഘടന macalg *m;

	വേണ്ടി (m = macs; m->name != ശൂന്യ; m++) {
		എങ്കിൽ (strcmp(name, m->name) != 0)
			തുടരുക;
		എങ്കിൽ (mac != ശൂന്യ)
			തിരികെ mac_setup_by_alg(mac, m);
		തിരികെ 0;
	}
	തിരികെ SSH_ERR_INVALID_ARGUMENT;
}

പൂർണ്ണസംഖ്യ
mac_init(ഘടന sshmac *mac)
{
	എങ്കിൽ (mac->താക്കോൽ == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	തിരഞ്ഞെടുപ്പ് (mac->type) {
	അവസ്ഥ SSH_DIGEST:
		എങ്കിൽ (mac->hmac_ctx == ശൂന്യ ||
		    ssh_hmac_init(mac->hmac_ctx, mac->താക്കോൽ, mac->താക്കോൽ_len) < 0)
			തിരികെ SSH_ERR_INVALID_ARGUMENT;
		തിരികെ 0;
	അവസ്ഥ SSH_UMAC:
		എങ്കിൽ ((mac->umac_ctx = umac_new(mac->താക്കോൽ)) == ശൂന്യ)
			തിരികെ SSH_ERR_ALLOC_FAIL;
		തിരികെ 0;
	അവസ്ഥ SSH_UMAC128:
		എങ്കിൽ ((mac->umac_ctx = umac128_new(mac->താക്കോൽ)) == ശൂന്യ)
			തിരികെ SSH_ERR_ALLOC_FAIL;
		തിരികെ 0;
	സ്ഥിരസ്ഥിതി:
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	}
}

പൂർണ്ണസംഖ്യ
mac_compute(ഘടന sshmac *mac, uint32_t seqno,
    സ്ഥിരം u_char *data, പൂർണ്ണസംഖ്യ datalen,
    u_char *digest, size_t dlen)
{
	സ്ഥിതം സംഘം {
		u_char m[SSH_DIGEST_MAX_LENGTH];
		uint64_t for_align;
	} u;
	u_char b[4];
	u_char nonce[8];

	എങ്കിൽ (mac->mac_len > വലുപ്പം(u))
		തിരികെ SSH_ERR_INTERNAL_ERROR;

	തിരഞ്ഞെടുപ്പ് (mac->type) {
	അവസ്ഥ SSH_DIGEST:
		put_u32(b, seqno);
		/* reset HMAC context */
		എങ്കിൽ (ssh_hmac_init(mac->hmac_ctx, ശൂന്യ, 0) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, b, വലുപ്പം(b)) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, data, datalen) < 0 ||
		    ssh_hmac_final(mac->hmac_ctx, u.m, വലുപ്പം(u.m)) < 0)
			തിരികെ SSH_ERR_LIBCRYPTO_ERROR;
		നിർത്തുക;
	അവസ്ഥ SSH_UMAC:
		POKE_U64(nonce, seqno);
		umac_update(mac->umac_ctx, data, datalen);
		umac_final(mac->umac_ctx, u.m, nonce);
		നിർത്തുക;
	അവസ്ഥ SSH_UMAC128:
		put_u64(nonce, seqno);
		umac128_update(mac->umac_ctx, data, datalen);
		umac128_final(mac->umac_ctx, u.m, nonce);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	}
	എങ്കിൽ (digest != ശൂന്യ) {
		എങ്കിൽ (dlen > mac->mac_len)
			dlen = mac->mac_len;
		memcpy(digest, u.m, dlen);
	}
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
mac_check(ഘടന sshmac *mac, uint32_t seqno,
    സ്ഥിരം u_char *data, size_t dlen,
    സ്ഥിരം u_char *theirmac, size_t mlen)
{
	u_char ourmac[SSH_DIGEST_MAX_LENGTH];
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (mac->mac_len > mlen)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ ((r = mac_compute(mac, seqno, data, dlen,
	    ourmac, വലുപ്പം(ourmac))) != 0)
		തിരികെ r;
	എങ്കിൽ (timingsafe_bcmp(ourmac, theirmac, mac->mac_len) != 0)
		തിരികെ SSH_ERR_MAC_INVALID;
	തിരികെ 0;
}

ശൂന്യം
mac_clear(ഘടന sshmac *mac)
{
	എങ്കിൽ (mac->type == SSH_UMAC) {
		എങ്കിൽ (mac->umac_ctx != ശൂന്യ)
			umac_delete(mac->umac_ctx);
	} അല്ലെങ്കിൽ എങ്കിൽ (mac->type == SSH_UMAC128) {
		എങ്കിൽ (mac->umac_ctx != ശൂന്യ)
			umac128_delete(mac->umac_ctx);
	} അല്ലെങ്കിൽ എങ്കിൽ (mac->hmac_ctx != ശൂന്യ)
		ssh_hmac_free(mac->hmac_ctx);
	mac->hmac_ctx = ശൂന്യ;
	mac->umac_ctx = ശൂന്യ;
}

/* XXX copied from ciphers_valid */
#define	MAC_SEP	","
പൂർണ്ണസംഖ്യ
mac_valid(സ്ഥിരം അക്ഷരം *names)
{
	അക്ഷരം *maclist, *cp, *p;
	പൂർണ്ണസംഖ്യ found = 0;

	എങ്കിൽ (names == ശൂന്യ || strcmp(names, "") == 0)
		തിരികെ 0;
	എങ്കിൽ ((maclist = cp = strdup(names)) == ശൂന്യ)
		തിരികെ 0;
	വേണ്ടി ((p = strsep(&cp, MAC_SEP)); p && *p != '\0';
	    (p = strsep(&cp, MAC_SEP))) {
		എങ്കിൽ (mac_setup(ശൂന്യ, p) < 0) {
			സ്വതന്ത്രം(maclist);
			തിരികെ 0;
		} അല്ലെങ്കിൽ
			found = 1;
	}
	സ്വതന്ത്രം(maclist);
	തിരികെ found;
}
