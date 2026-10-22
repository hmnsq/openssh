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

struct macalg {
	char		*name;
	정수		type;
	정수		alg;
	정수		truncatebits;	/* truncate digest if != 0 */
	정수		key_len;	/* just for UMAC */
	정수		len;		/* just for UMAC */
	정수		etm;		/* Encrypt-then-MAC */
};

static const struct macalg macs[] = {
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
char *
mac_alg_list(char sep)
{
	char *ret = NULL;
	const struct macalg *m;
	char sep_str[2] = {sep, '\0'};

	위해 (m = macs; m->name != NULL; m++)
		xextendf(&ret, sep_str, "%s", m->name);

	반환 ret;
}

static 정수
mac_setup_by_alg(struct sshmac *mac, const struct macalg *macalg)
{
	mac->type = macalg->type;
	만약 (mac->type == SSH_DIGEST) {
		만약 ((mac->hmac_ctx = ssh_hmac_start(macalg->alg)) == NULL)
			반환 SSH_ERR_ALLOC_FAIL;
		mac->key_len = mac->mac_len = ssh_hmac_bytes(macalg->alg);
	} 아니면 {
		mac->mac_len = macalg->len / 8;
		mac->key_len = macalg->key_len / 8;
		mac->umac_ctx = NULL;
	}
	만약 (macalg->truncatebits != 0)
		mac->mac_len = macalg->truncatebits / 8;
	mac->etm = macalg->etm;
	반환 0;
}

정수
mac_setup(struct sshmac *mac, char *name)
{
	const struct macalg *m;

	위해 (m = macs; m->name != NULL; m++) {
		만약 (strcmp(name, m->name) != 0)
			continue;
		만약 (mac != NULL)
			반환 mac_setup_by_alg(mac, m);
		반환 0;
	}
	반환 SSH_ERR_INVALID_ARGUMENT;
}

정수
mac_init(struct sshmac *mac)
{
	만약 (mac->key == NULL)
		반환 SSH_ERR_INVALID_ARGUMENT;
	switch (mac->type) {
	case SSH_DIGEST:
		만약 (mac->hmac_ctx == NULL ||
		    ssh_hmac_init(mac->hmac_ctx, mac->key, mac->key_len) < 0)
			반환 SSH_ERR_INVALID_ARGUMENT;
		반환 0;
	case SSH_UMAC:
		만약 ((mac->umac_ctx = umac_new(mac->key)) == NULL)
			반환 SSH_ERR_ALLOC_FAIL;
		반환 0;
	case SSH_UMAC128:
		만약 ((mac->umac_ctx = umac128_new(mac->key)) == NULL)
			반환 SSH_ERR_ALLOC_FAIL;
		반환 0;
	default:
		반환 SSH_ERR_INVALID_ARGUMENT;
	}
}

정수
mac_compute(struct sshmac *mac, uint32_t seqno,
    const u_char *data, 정수 datalen,
    u_char *digest, size_t dlen)
{
	static union {
		u_char m[SSH_DIGEST_MAX_LENGTH];
		uint64_t for_align;
	} u;
	u_char b[4];
	u_char nonce[8];

	만약 (mac->mac_len > sizeof(u))
		반환 SSH_ERR_INTERNAL_ERROR;

	switch (mac->type) {
	case SSH_DIGEST:
		put_u32(b, seqno);
		/* reset HMAC context */
		만약 (ssh_hmac_init(mac->hmac_ctx, NULL, 0) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, b, sizeof(b)) < 0 ||
		    ssh_hmac_update(mac->hmac_ctx, data, datalen) < 0 ||
		    ssh_hmac_final(mac->hmac_ctx, u.m, sizeof(u.m)) < 0)
			반환 SSH_ERR_LIBCRYPTO_ERROR;
		break;
	case SSH_UMAC:
		POKE_U64(nonce, seqno);
		umac_update(mac->umac_ctx, data, datalen);
		umac_final(mac->umac_ctx, u.m, nonce);
		break;
	case SSH_UMAC128:
		put_u64(nonce, seqno);
		umac128_update(mac->umac_ctx, data, datalen);
		umac128_final(mac->umac_ctx, u.m, nonce);
		break;
	default:
		반환 SSH_ERR_INVALID_ARGUMENT;
	}
	만약 (digest != NULL) {
		만약 (dlen > mac->mac_len)
			dlen = mac->mac_len;
		memcpy(digest, u.m, dlen);
	}
	반환 0;
}

정수
mac_check(struct sshmac *mac, uint32_t seqno,
    const u_char *data, size_t dlen,
    const u_char *theirmac, size_t mlen)
{
	u_char ourmac[SSH_DIGEST_MAX_LENGTH];
	정수 r;

	만약 (mac->mac_len > mlen)
		반환 SSH_ERR_INVALID_ARGUMENT;
	만약 ((r = mac_compute(mac, seqno, data, dlen,
	    ourmac, sizeof(ourmac))) != 0)
		반환 r;
	만약 (timingsafe_bcmp(ourmac, theirmac, mac->mac_len) != 0)
		반환 SSH_ERR_MAC_INVALID;
	반환 0;
}

void
mac_clear(struct sshmac *mac)
{
	만약 (mac->type == SSH_UMAC) {
		만약 (mac->umac_ctx != NULL)
			umac_delete(mac->umac_ctx);
	} 아니면 만약 (mac->type == SSH_UMAC128) {
		만약 (mac->umac_ctx != NULL)
			umac128_delete(mac->umac_ctx);
	} 아니면 만약 (mac->hmac_ctx != NULL)
		ssh_hmac_free(mac->hmac_ctx);
	mac->hmac_ctx = NULL;
	mac->umac_ctx = NULL;
}

/* XXX copied from ciphers_valid */
#define	MAC_SEP	","
정수
mac_valid(const char *names)
{
	char *maclist, *cp, *p;
	정수 found = 0;

	만약 (names == NULL || strcmp(names, "") == 0)
		반환 0;
	만약 ((maclist = cp = strdup(names)) == NULL)
		반환 0;
	위해 ((p = strsep(&cp, MAC_SEP)); p && *p != '\0';
	    (p = strsep(&cp, MAC_SEP))) {
		만약 (mac_setup(NULL, p) < 0) {
			free(maclist);
			반환 0;
		} 아니면
			found = 1;
	}
	free(maclist);
	반환 found;
}
