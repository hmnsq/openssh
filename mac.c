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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "hmac.h"
#અન્તર્ભાવ "umac.h"
#અન્તર્ભાવ "mac.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"

#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"

#define SSH_DIGEST	1	/* SSH_DIGEST_XXX */
#define SSH_UMAC	2	/* UMAC (not integrated with OpenSSL) */
#define SSH_UMAC128	3

સંરચના macalg {
	અક્ષર		*name;
	પૂર્ણાંક		type;
	પૂર્ણાંક		alg;
	પૂર્ણાંક		truncatebits;	/* truncate digest if != 0 */
	પૂર્ણાંક		ચાવી_len;	/* just for UMAC */
	પૂર્ણાંક		len;		/* just for UMAC */
	પૂર્ણાંક		etm;		/* Encrypt-then-MAC */
};

સ્થિર અચલ સંરચના macalg macs[] = {
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

	{ ખાલી,					0, 0, 0, 0, 0, 0 }
};

/* Returns a list of supported MACs separated by the specified char. */
અક્ષર *
mac_alg_list(અક્ષર sep)
{
	અક્ષર *ret = ખાલી;
	અચલ સંરચના macalg *m;
	અક્ષર sep_str[2] = {sep, '\0'};

	માટે (m = macs; m->name != ખાલી; m++)
		xextendf(&ret, sep_str, "%s", m->name);

	પાછા ret;
}

સ્થિર પૂર્ણાંક
mac_setup_by_alg(સંરચના sshmac *mac, અચલ સંરચના macalg *macalg)
{
	mac->type = macalg->type;
	જો (mac->type == SSH_DIGEST) {
		જો ((mac->hmac_ctx = ssh_hmac_start(macalg->alg)) == ખાલી)
			પાછા SSH_ERR_ALLOC_FAIL;
		mac->ચાવી_len = mac->mac_len = ssh_hmac_bytes(macalg->alg);
	} નહીંતર {
		mac->mac_len = macalg->len / 8;
		mac->ચાવી_len = macalg->ચાવી_len / 8;
		mac->umac_ctx = ખાલી;
	}
	જો (macalg->truncatebits != 0)
		mac->mac_len = macalg->truncatebits / 8;
	mac->etm = macalg->etm;
	પાછા 0;
}

પૂર્ણાંક
mac_setup(સંરચના sshmac *mac, અક્ષર *name)
{
	અચલ સંરચના macalg *m;

	માટે (m = macs; m->name != ખાલી; m++) {
		જો (strcmp(name, m->name) != 0)
			ચાલુ;
		જો (mac != ખાલી)
			પાછા mac_setup_by_alg(mac, m);
		પાછા 0;
	}
	પાછા SSH_ERR_INVALID_ARGUMENT;
}

પૂર્ણાંક
mac_init(સંરચના sshmac *mac)
{
	જો (mac->ચાવી == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	પસંદગી (mac->type) {
	સ્થિતિ SSH_DIGEST:
		જો (mac->hmac_ctx == ખાલી ||
		    ssh_hmac_init(mac->hmac_ctx, mac->ચાવી, mac->ચાવી_len) < 0)
			પાછા SSH_ERR_INVALID_ARGUMENT;
		પાછા 0;
	સ્થિતિ SSH_UMAC:
		જો ((mac->umac_ctx = umac_new(mac->ચાવી)) == ખાલી)
			પાછા SSH_ERR_ALLOC_FAIL;
		પાછા 0;
	સ્થિતિ SSH_UMAC128:
		જો ((mac->umac_ctx = umac128_new(mac->ચાવી)) == ખાલી)
			પાછા SSH_ERR_ALLOC_FAIL;
		પાછા 0;
	મૂળભૂત:
		પાછા SSH_ERR_INVALID_ARGUMENT;
	}
}

પૂર્ણાંક
mac_compute(સંરચના sshmac *mac, uint32_t seqno,
    અચલ u_char *data, પૂર્ણાંક datalen,
    u_char *digest, size_t dlen)
{
	સ્થિર સંઘ {
		u_char m[SSH_DIGEST_MAX_LENGTH];
		uint64_t for_align;
	} u;
	u_char b[4];
	u_char nonce[8];

	જો (mac->mac_len > કદ(u))
		પાછા SSH_ERR_INTERNAL_ERROR;

	પસંદગી (mac->type) {
	સ્થિતિ SSH_DIGEST:
		put_u32(b, seqno);
		/* reset HMAC context */
		જો (ssh_hmac_init(mac->hmac_ctx, ખાલી, 0) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, b, કદ(b)) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, data, datalen) < 0 ||
		    ssh_hmac_final(mac->hmac_ctx, u.m, કદ(u.m)) < 0)
			પાછા SSH_ERR_LIBCRYPTO_ERROR;
		તોડો;
	સ્થિતિ SSH_UMAC:
		POKE_U64(nonce, seqno);
		umac_update(mac->umac_ctx, data, datalen);
		umac_final(mac->umac_ctx, u.m, nonce);
		તોડો;
	સ્થિતિ SSH_UMAC128:
		put_u64(nonce, seqno);
		umac128_update(mac->umac_ctx, data, datalen);
		umac128_final(mac->umac_ctx, u.m, nonce);
		તોડો;
	મૂળભૂત:
		પાછા SSH_ERR_INVALID_ARGUMENT;
	}
	જો (digest != ખાલી) {
		જો (dlen > mac->mac_len)
			dlen = mac->mac_len;
		memcpy(digest, u.m, dlen);
	}
	પાછા 0;
}

પૂર્ણાંક
mac_check(સંરચના sshmac *mac, uint32_t seqno,
    અચલ u_char *data, size_t dlen,
    અચલ u_char *theirmac, size_t mlen)
{
	u_char ourmac[SSH_DIGEST_MAX_LENGTH];
	પૂર્ણાંક r;

	જો (mac->mac_len > mlen)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો ((r = mac_compute(mac, seqno, data, dlen,
	    ourmac, કદ(ourmac))) != 0)
		પાછા r;
	જો (timingsafe_bcmp(ourmac, theirmac, mac->mac_len) != 0)
		પાછા SSH_ERR_MAC_INVALID;
	પાછા 0;
}

શૂન્ય
mac_clear(સંરચના sshmac *mac)
{
	જો (mac->type == SSH_UMAC) {
		જો (mac->umac_ctx != ખાલી)
			umac_delete(mac->umac_ctx);
	} નહીંતર જો (mac->type == SSH_UMAC128) {
		જો (mac->umac_ctx != ખાલી)
			umac128_delete(mac->umac_ctx);
	} નહીંતર જો (mac->hmac_ctx != ખાલી)
		ssh_hmac_free(mac->hmac_ctx);
	mac->hmac_ctx = ખાલી;
	mac->umac_ctx = ખાલી;
}

/* XXX copied from ciphers_valid */
#define	MAC_SEP	","
પૂર્ણાંક
mac_valid(અચલ અક્ષર *names)
{
	અક્ષર *maclist, *cp, *p;
	પૂર્ણાંક found = 0;

	જો (names == ખાલી || strcmp(names, "") == 0)
		પાછા 0;
	જો ((maclist = cp = strdup(names)) == ખાલી)
		પાછા 0;
	માટે ((p = strsep(&cp, MAC_SEP)); p && *p != '\0';
	    (p = strsep(&cp, MAC_SEP))) {
		જો (mac_setup(ખાલી, p) < 0) {
			મુક્ત(maclist);
			પાછા 0;
		} નહીંતર
			found = 1;
	}
	મુક્ત(maclist);
	પાછા found;
}
