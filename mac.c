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

#include "includes.h"

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "digest.h"
#include "hmac.h"
#include "umac.h"
#include "mac.h"
#include "misc.h"
#include "ssherr.h"
#include "sshbuf.h"

#include "openbsd-compat/openssl-compat.h"

#define SSH_DIGEST	1	/* SSH_DIGEST_XXX */
#define SSH_UMAC	2	/* UMAC (not integrated with OpenSSL) */
#define SSH_UMAC128	3

sa_nracanaa macalg {
	var_na		*name;
	ကိန်းပြည့်		type;
	ကိန်းပြည့်		alg;
	ကိန်းပြည့်		truncatebits;	/* truncate digest if != 0 */
	ကိန်းပြည့်		key_len;	/* just for UMAC */
	ကိန်းပြည့်		len;		/* just for UMAC */
	ကိန်းပြည့်		etm;		/* Encrypt-then-MAC */
};

static const sa_nracanaa macalg macs[] = {
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

	{ NULL,					0, 0, 0, 0, 0, 0 }
};

/* Returns a list of supported MACs separated by the specified char. */
var_na *
mac_alg_list(var_na sep)
{
	var_na *ret = NULL;
	const sa_nracanaa macalg *m;
	var_na sep_str[2] = {sep, '\0'};

	အတွက် (m = macs; m->name != NULL; m++)
		xextendf(&ret, sep_str, "%s", m->name);

	ပြန်ပေး ret;
}

static ကိန်းပြည့်
mac_setup_by_alg(sa_nracanaa sshmac *mac, const sa_nracanaa macalg *macalg)
{
	mac->type = macalg->type;
	အကယ်၍ (mac->type == SSH_DIGEST) {
		အကယ်၍ ((mac->hmac_ctx = ssh_hmac_start(macalg->alg)) == NULL)
			ပြန်ပေး SSH_ERR_ALLOC_FAIL;
		mac->key_len = mac->mac_len = ssh_hmac_bytes(macalg->alg);
	} မဟုတ်ပါက {
		mac->mac_len = macalg->len / 8;
		mac->key_len = macalg->key_len / 8;
		mac->umac_ctx = NULL;
	}
	အကယ်၍ (macalg->truncatebits != 0)
		mac->mac_len = macalg->truncatebits / 8;
	mac->etm = macalg->etm;
	ပြန်ပေး 0;
}

ကိန်းပြည့်
mac_setup(sa_nracanaa sshmac *mac, var_na *name)
{
	const sa_nracanaa macalg *m;

	အတွက် (m = macs; m->name != NULL; m++) {
		အကယ်၍ (strcmp(name, m->name) != 0)
			continue;
		အကယ်၍ (mac != NULL)
			ပြန်ပေး mac_setup_by_alg(mac, m);
		ပြန်ပေး 0;
	}
	ပြန်ပေး SSH_ERR_INVALID_ARGUMENT;
}

ကိန်းပြည့်
mac_init(sa_nracanaa sshmac *mac)
{
	အကယ်၍ (mac->key == NULL)
		ပြန်ပေး SSH_ERR_INVALID_ARGUMENT;
	switch (mac->type) {
	pak_sa SSH_DIGEST:
		အကယ်၍ (mac->hmac_ctx == NULL ||
		    ssh_hmac_init(mac->hmac_ctx, mac->key, mac->key_len) < 0)
			ပြန်ပေး SSH_ERR_INVALID_ARGUMENT;
		ပြန်ပေး 0;
	pak_sa SSH_UMAC:
		အကယ်၍ ((mac->umac_ctx = umac_new(mac->key)) == NULL)
			ပြန်ပေး SSH_ERR_ALLOC_FAIL;
		ပြန်ပေး 0;
	pak_sa SSH_UMAC128:
		အကယ်၍ ((mac->umac_ctx = umac128_new(mac->key)) == NULL)
			ပြန်ပေး SSH_ERR_ALLOC_FAIL;
		ပြန်ပေး 0;
	default:
		ပြန်ပေး SSH_ERR_INVALID_ARGUMENT;
	}
}

ကိန်းပြည့်
mac_compute(sa_nracanaa sshmac *mac, uint32_t seqno,
    const u_char *data, ကိန်းပြည့် datalen,
    u_char *digest, size_t dlen)
{
	static sa_ngha {
		u_char m[SSH_DIGEST_MAX_LENGTH];
		uint64_t for_align;
	} u;
	u_char b[4];
	u_char nonce[8];

	အကယ်၍ (mac->mac_len > parimaa_na(u))
		ပြန်ပေး SSH_ERR_INTERNAL_ERROR;

	switch (mac->type) {
	pak_sa SSH_DIGEST:
		put_u32(b, seqno);
		/* reset HMAC context */
		အကယ်၍ (ssh_hmac_init(mac->hmac_ctx, NULL, 0) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, b, parimaa_na(b)) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, data, datalen) < 0 ||
		    ssh_hmac_final(mac->hmac_ctx, u.m, parimaa_na(u.m)) < 0)
			ပြန်ပေး SSH_ERR_LIBCRYPTO_ERROR;
		bha_nga;
	pak_sa SSH_UMAC:
		POKE_U64(nonce, seqno);
		umac_update(mac->umac_ctx, data, datalen);
		umac_final(mac->umac_ctx, u.m, nonce);
		bha_nga;
	pak_sa SSH_UMAC128:
		put_u64(nonce, seqno);
		umac128_update(mac->umac_ctx, data, datalen);
		umac128_final(mac->umac_ctx, u.m, nonce);
		bha_nga;
	default:
		ပြန်ပေး SSH_ERR_INVALID_ARGUMENT;
	}
	အကယ်၍ (digest != NULL) {
		အကယ်၍ (dlen > mac->mac_len)
			dlen = mac->mac_len;
		memcpy(digest, u.m, dlen);
	}
	ပြန်ပေး 0;
}

ကိန်းပြည့်
mac_check(sa_nracanaa sshmac *mac, uint32_t seqno,
    const u_char *data, size_t dlen,
    const u_char *theirmac, size_t mlen)
{
	u_char ourmac[SSH_DIGEST_MAX_LENGTH];
	ကိန်းပြည့် r;

	အကယ်၍ (mac->mac_len > mlen)
		ပြန်ပေး SSH_ERR_INVALID_ARGUMENT;
	အကယ်၍ ((r = mac_compute(mac, seqno, data, dlen,
	    ourmac, parimaa_na(ourmac))) != 0)
		ပြန်ပေး r;
	အကယ်၍ (timingsafe_bcmp(ourmac, theirmac, mac->mac_len) != 0)
		ပြန်ပေး SSH_ERR_MAC_INVALID;
	ပြန်ပေး 0;
}

void
mac_clear(sa_nracanaa sshmac *mac)
{
	အကယ်၍ (mac->type == SSH_UMAC) {
		အကယ်၍ (mac->umac_ctx != NULL)
			umac_delete(mac->umac_ctx);
	} မဟုတ်ပါက အကယ်၍ (mac->type == SSH_UMAC128) {
		အကယ်၍ (mac->umac_ctx != NULL)
			umac128_delete(mac->umac_ctx);
	} မဟုတ်ပါက အကယ်၍ (mac->hmac_ctx != NULL)
		ssh_hmac_free(mac->hmac_ctx);
	mac->hmac_ctx = NULL;
	mac->umac_ctx = NULL;
}

/* XXX copied from ciphers_valid */
#define	MAC_SEP	","
ကိန်းပြည့်
mac_valid(const var_na *names)
{
	var_na *maclist, *cp, *p;
	ကိန်းပြည့် found = 0;

	အကယ်၍ (names == NULL || strcmp(names, "") == 0)
		ပြန်ပေး 0;
	အကယ်၍ ((maclist = cp = strdup(names)) == NULL)
		ပြန်ပေး 0;
	အတွက် ((p = strsep(&cp, MAC_SEP)); p && *p != '\0';
	    (p = strsep(&cp, MAC_SEP))) {
		အကယ်၍ (mac_setup(NULL, p) < 0) {
			free(maclist);
			ပြန်ပေး 0;
		} မဟုတ်ပါက
			found = 1;
	}
	free(maclist);
	ပြန်ပေး found;
}
