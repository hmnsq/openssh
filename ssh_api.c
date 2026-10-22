/* $OpenBSD: ssh_api.c,v 1.35 2026/07/27 12:28:52 markus Exp $ */
/*
 * Copyright (c) 2012 Markus Friedl.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

#ಅನ್ತರ್ಭಾವ "ssh_api.h"
#ಅನ್ತರ್ಭಾವ "compat.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "dh.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "version.h"
#ಅನ್ತರ್ಭಾವ "myproposal.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"

#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

#ಅನ್ತರ್ಭಾವ <string.h>

ಪೂರ್ಣಾಂಕ	_ssh_exchange_banner(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	_ssh_send_banner(ರಚನೆ ssh *, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ	_ssh_read_banner(ರಚನೆ ssh *, ರಚನೆ sshbuf *);
ಪೂರ್ಣಾಂಕ	ssh_ಕ್ರಮ_hostkeyalgs(ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	ssh_verify_host_ಕೀಲಿ(ರಚನೆ sshkey *, ರಚನೆ ssh *);
ರಚನೆ sshkey *ssh_host_ಬಹಿರಂಗ_ಕೀಲಿ(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ರಚನೆ ssh *);
ರಚನೆ sshkey *ssh_host_ಖಾಸಗಿ_ಕೀಲಿ(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ರಚನೆ ssh *);
ಪೂರ್ಣಾಂಕ	ssh_host_ಕೀಲಿ_sign(ರಚನೆ ssh *, ರಚನೆ sshkey *, ರಚನೆ sshkey *,
    u_char **, ಗಾತ್ರ_t *, ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
ಪೂರ್ಣಾಂಕ	mm_sshkey_sign(ರಚನೆ sshkey *, u_char **, u_int *,
    ಸ್ಥಿರಾಂಕ u_char *, u_int, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, u_int);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
DH	*mm_ಆರಿಸು_dh(ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ, ಪೂರ್ಣಾಂಕ);
#ಆದರೆ_ಅಂತ್ಯ

ಪೂರ್ಣಾಂಕ
mm_sshkey_sign(ರಚನೆ sshkey *ಕೀಲಿ, u_char **sigp, u_int *lenp,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, u_int datalen, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin, u_int compat)
{
	ಗಾತ್ರ_t slen = 0;
	ಪೂರ್ಣಾಂಕ ret;

	ret = sshkey_sign(ಕೀಲಿ, sigp, &slen, ದತ್ತಾಂಶ, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	ಹಿಂತಿರುಗಿ ret;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
DH *
mm_ಆರಿಸು_dh(ಪೂರ್ಣಾಂಕ min, ಪೂರ್ಣಾಂಕ nbits, ಪೂರ್ಣಾಂಕ max)
{
	ಹಿಂತಿರುಗಿ ಆರಿಸು_dh(min, nbits, max);
}
#ಆದರೆ_ಅಂತ್ಯ

/* API */

ಪೂರ್ಣಾಂಕ
ssh_init(ರಚನೆ ssh **sshp, ಪೂರ್ಣಾಂಕ is_server, ರಚನೆ kex_params *kex_params)
{
	ಅಕ್ಷರ *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	ಅಕ್ಷರ *populated[PROPOSAL_MAX];
	ರಚನೆ ssh *ssh;
	ಅಕ್ಷರ **proposal;
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ called;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (!called) {
		ಬೀಜ_rng();
		called = 1;
	}

	ಆದರೆ ((ssh = ssh_packet_ಗಣ_connection(ಖಾಲಿ, -1, -1)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ (is_server)
		ssh_packet_ಗಣ_server(ssh);

	/* Initialize key exchange */
	proposal = kex_params ? kex_params->proposal : myproposal;
	kex_proposal_populate_entries(ssh, populated,
	    proposal[PROPOSAL_KEX_ALGS],
	    proposal[PROPOSAL_ENC_ALGS_CTOS],
	    proposal[PROPOSAL_MAC_ALGS_CTOS],
	    proposal[PROPOSAL_COMP_ALGS_CTOS],
	    proposal[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS]);
	r = kex_ready(ssh, populated);
	kex_proposal_free_entries(populated);
	ಆದರೆ (r != 0) {
		ssh_free(ssh);
		ಹಿಂತಿರುಗಿ r;
	}

	ssh->kex->server = is_server;
	ಆದರೆ (is_server) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
		ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
		ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
		ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
		ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
		ssh->kex->ತುಂಬು_host_ಬಹಿರಂಗ_ಕೀಲಿ=&ssh_host_ಬಹಿರಂಗ_ಕೀಲಿ;
		ssh->kex->ತುಂಬು_host_ಖಾಸಗಿ_ಕೀಲಿ=&ssh_host_ಖಾಸಗಿ_ಕೀಲಿ;
		ssh->kex->sign=&ssh_host_ಕೀಲಿ_sign;
	} ಇಲ್ಲದಿದ್ದರೆ {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
		ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
		ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
		ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
		ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
		ssh->kex->verify_host_ಕೀಲಿ =&ssh_verify_host_ಕೀಲಿ;
	}
	*sshp = ssh;
	ಹಿಂತಿರುಗಿ 0;
}

ಶೂನ್ಯ
ssh_free(ರಚನೆ ssh *ssh)
{
	ರಚನೆ ಕೀಲಿ_ನಮೂದು *k;

	ಆದರೆ (ssh == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	ಆಗ ((k = TAILQ_FIRST(&ssh->ಬಹಿರಂಗ_ಕೀಲಿಗಳು)) != ಖಾಲಿ) {
		TAILQ_REMOVE(&ssh->ಬಹಿರಂಗ_ಕೀಲಿಗಳು, k, ಮುಂದಿನ);
		ಆದರೆ (ssh->kex && ssh->kex->server)
			sshkey_free(k->ಕೀಲಿ);
		ಬಿಡುಗಡೆ(k);
	}
	ಆಗ ((k = TAILQ_FIRST(&ssh->ಖಾಸಗಿ_ಕೀಲಿಗಳು)) != ಖಾಲಿ) {
		TAILQ_REMOVE(&ssh->ಖಾಸಗಿ_ಕೀಲಿಗಳು, k, ಮುಂದಿನ);
		ಬಿಡುಗಡೆ(k);
	}
	ssh_packet_close(ssh);
	ಬಿಡುಗಡೆ(ssh);
}

ಶೂನ್ಯ
ssh_ಗಣ_app_ದತ್ತಾಂಶ(ರಚನೆ ssh *ssh, ಶೂನ್ಯ *app_ದತ್ತಾಂಶ)
{
	ssh->app_ದತ್ತಾಂಶ = app_ದತ್ತಾಂಶ;
}

ಶೂನ್ಯ *
ssh_get_app_ದತ್ತಾಂಶ(ರಚನೆ ssh *ssh)
{
	ಹಿಂತಿರುಗಿ ssh->app_ದತ್ತಾಂಶ;
}

/* Returns < 0 on error, 0 otherwise */
ಪೂರ್ಣಾಂಕ
ssh_ಕೂಡಿಸು_hostkey(ರಚನೆ ssh *ssh, ರಚನೆ sshkey *ಕೀಲಿ)
{
	ರಚನೆ sshkey *pubkey = ಖಾಲಿ;
	ರಚನೆ ಕೀಲಿ_ನಮೂದು *k = ಖಾಲಿ, *k_prv = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (ssh->kex->server) {
		ಆದರೆ ((r = sshkey_from_ಖಾಸಗಿ(ಕೀಲಿ, &pubkey)) != 0)
			ಹಿಂತಿರುಗಿ r;
		ಆದರೆ ((k = ಸ್ಮರಣೆ_ಕೊಡು(ಗಾತ್ರ(*k))) == ಖಾಲಿ ||
		    (k_prv = ಸ್ಮರಣೆ_ಕೊಡು(ಗಾತ್ರ(*k_prv))) == ಖಾಲಿ) {
			ಬಿಡುಗಡೆ(k);
			sshkey_free(pubkey);
			ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
		}
		k_prv->ಕೀಲಿ = ಕೀಲಿ;
		TAILQ_INSERT_TAIL(&ssh->ಖಾಸಗಿ_ಕೀಲಿಗಳು, k_prv, ಮುಂದಿನ);

		/* add the public key, too */
		k->ಕೀಲಿ = pubkey;
		TAILQ_INSERT_TAIL(&ssh->ಬಹಿರಂಗ_ಕೀಲಿಗಳು, k, ಮುಂದಿನ);
		r = 0;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ ((k = ಸ್ಮರಣೆ_ಕೊಡು(ಗಾತ್ರ(*k))) == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
		k->ಕೀಲಿ = ಕೀಲಿ;
		TAILQ_INSERT_TAIL(&ssh->ಬಹಿರಂಗ_ಕೀಲಿಗಳು, k, ಮುಂದಿನ);
		r = 0;
	}

	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
ssh_ಗಣ_verify_host_ಕೀಲಿ_callback(ರಚನೆ ssh *ssh,
    ಪೂರ್ಣಾಂಕ (*cb)(ರಚನೆ sshkey *, ರಚನೆ ssh *))
{
	ಆದರೆ (cb == ಖಾಲಿ || ssh->kex == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;

	ssh->kex->verify_host_ಕೀಲಿ = cb;

	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
ssh_ಒಳಹರಿವು_append(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t len)
{
	ಹಿಂತಿರುಗಿ sshbuf_put(ssh_packet_get_ಒಳಹರಿವು(ssh), ದತ್ತಾಂಶ, len);
}

ಪೂರ್ಣಾಂಕ
ssh_packet_ಮುಂದಿನ(ರಚನೆ ssh *ssh, u_char *typep)
{
	ಪೂರ್ಣಾಂಕ r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_ಸಂದೇಶ_NONE;
	ಆದರೆ (sshbuf_len(ssh->kex->client_ಆವೃತ್ತಿ) == 0 ||
	    sshbuf_len(ssh->kex->server_ಆವೃತ್ತಿ) == 0)
		ಹಿಂತಿರುಗಿ _ssh_exchange_banner(ssh);
	/*
	 * If we enough data and a dispatch function then
	 * call the function and get the next packet.
	 * Otherwise return the packet type to the caller so it
	 * can decide how to go on.
	 *
	 * We will only call the dispatch function for:
	 *     20-29    Algorithm negotiation
	 *     30-49    Key exchange method specific (numbers can be reused for
	 *              different authentication methods)
	 */
	ಗಾಗಿ (;;) {
		ಆದರೆ ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			ಹಿಂತಿರುಗಿ r;
		ಆದರೆ (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_ಸಂದೇಶ_KEXINIT && type <= SSH2_ಸಂದೇಶ_TRANSPORT_MAX &&
		    ssh->dispatch[type] != ಖಾಲಿ) {
			ಆದರೆ ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				ಹಿಂತಿರುಗಿ r;
		} ಇಲ್ಲದಿದ್ದರೆ {
			*typep = type;
			ಹಿಂತಿರುಗಿ 0;
		}
	}
}

ಸ್ಥಿರಾಂಕ u_char *
ssh_packet_payload(ರಚನೆ ssh *ssh, ಗಾತ್ರ_t *lenp)
{
	ಹಿಂತಿರುಗಿ sshpkt_ptr(ssh, lenp);
}

ಪೂರ್ಣಾಂಕ
ssh_packet_put(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ type, ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t len)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, ದತ್ತಾಂಶ, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರಾಂಕ u_char *
ssh_output_ptr(ರಚನೆ ssh *ssh, ಗಾತ್ರ_t *len)
{
	ರಚನೆ sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	ಹಿಂತಿರುಗಿ sshbuf_ptr(output);
}

ಪೂರ್ಣಾಂಕ
ssh_output_consume(ರಚನೆ ssh *ssh, ಗಾತ್ರ_t len)
{
	ಹಿಂತಿರುಗಿ sshbuf_consume(ssh_packet_get_output(ssh), len);
}

ಪೂರ್ಣಾಂಕ
ssh_output_space(ರಚನೆ ssh *ssh, ಗಾತ್ರ_t len)
{
	ಹಿಂತಿರುಗಿ (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

ಪೂರ್ಣಾಂಕ
ssh_ಒಳಹರಿವು_space(ರಚನೆ ssh *ssh, ಗಾತ್ರ_t len)
{
	ಹಿಂತಿರುಗಿ (0 == sshbuf_check_reserve(ssh_packet_get_ಒಳಹರಿವು(ssh), len));
}

/* Read other side's version identification. */
ಪೂರ್ಣಾಂಕ
_ssh_read_banner(ರಚನೆ ssh *ssh, ರಚನೆ sshbuf *banner)
{
	ರಚನೆ sshbuf *ಒಳಹರಿವು = ssh_packet_get_ಒಳಹರಿವು(ssh);
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *mismatch = "Protocol mismatch.\r\n";
	ಸ್ಥಿರಾಂಕ u_char *s = sshbuf_ptr(ಒಳಹರಿವು);
	u_char c;
	ಅಕ್ಷರ *cp = ಖಾಲಿ, *remote_ಆವೃತ್ತಿ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = 0, remote_major, remote_minor, expect_nl;
	ಗಾತ್ರ_t n, j;

	ಗಾಗಿ (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		ಗಾಗಿ (;;) {
			ಆದರೆ (j >= sshbuf_len(ಒಳಹರಿವು))
				ಹಿಂತಿರುಗಿ 0; /* insufficient data in input buf */
			c = s[j++];
			ಆದರೆ (c == '\r') {
				expect_nl = 1;
				ಮುಂದುವರಿ;
			}
			ಆದರೆ (c == '\n')
				ನಿಲ್ಲಿಸು;
			ಆದರೆ (expect_nl)
				ಹೋಗು bad;
			ಆದರೆ ((r = sshbuf_put_u8(banner, c)) != 0)
				ಹಿಂತಿರುಗಿ r;
			ಆದರೆ (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				ಹೋಗು bad;
		}
		ಆದರೆ (sshbuf_len(banner) >= 4 &&
		    memcmp(sshbuf_ptr(banner), "SSH-", 4) == 0)
			ನಿಲ್ಲಿಸು;
		debug_f("%.*s", (ಪೂರ್ಣಾಂಕ)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		ಆದರೆ (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_ಸಾಲುಗಳು) {
  bad:
			ಆದರೆ ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(mismatch))) != 0)
				ಹಿಂತಿರುಗಿ r;
			ಹಿಂತಿರುಗಿ SSH_ERR_NO_PROTOCOL_ಆವೃತ್ತಿ;
		}
	}
	ಆದರೆ ((r = sshbuf_consume(ಒಳಹರಿವು, j)) != 0)
		ಹಿಂತಿರುಗಿ r;

	/* XXX remote version must be the same size as banner for sscanf */
	ಆದರೆ ((cp = sshbuf_dup_string(banner)) == ಖಾಲಿ ||
	    (remote_ಆವೃತ್ತಿ = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, sshbuf_len(banner))) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಓದು(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_ಆವೃತ್ತಿ) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_ಆವೃತ್ತಿ);

	compat_banner(ssh, remote_ಆವೃತ್ತಿ);
	ಆದರೆ  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	ಆದರೆ (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(cp);
	ಬಿಡುಗಡೆ(remote_ಆವೃತ್ತಿ);
	ಹಿಂತಿರುಗಿ r;
}

/* Send our own protocol version identification. */
ಪೂರ್ಣಾಂಕ
_ssh_send_banner(ರಚನೆ ssh *ssh, ರಚನೆ sshbuf *banner)
{
	ಅಕ್ಷರ *cp;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_ಆವೃತ್ತಿ)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		ಹಿಂತಿರುಗಿ r;
	/* Remove trailing \r\n */
	ಆದರೆ ((r = sshbuf_consume_ಕೊನೆ(banner, 2)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((cp = sshbuf_dup_string(banner)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	ಬಿಡುಗಡೆ(cp);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
_ssh_exchange_banner(ರಚನೆ ssh *ssh)
{
	ರಚನೆ kex *kex = ssh->kex;
	ಪೂರ್ಣಾಂಕ r;

	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */

	r = 0;
	ಆದರೆ (kex->server) {
		ಆದರೆ (sshbuf_len(ssh->kex->server_ಆವೃತ್ತಿ) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_ಆವೃತ್ತಿ);
		ಆದರೆ (r == 0 &&
		    sshbuf_len(ssh->kex->server_ಆವೃತ್ತಿ) != 0 &&
		    sshbuf_len(ssh->kex->client_ಆವೃತ್ತಿ) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_ಆವೃತ್ತಿ);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (sshbuf_len(ssh->kex->server_ಆವೃತ್ತಿ) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_ಆವೃತ್ತಿ);
		ಆದರೆ (r == 0 &&
		    sshbuf_len(ssh->kex->server_ಆವೃತ್ತಿ) != 0 &&
		    sshbuf_len(ssh->kex->client_ಆವೃತ್ತಿ) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_ಆವೃತ್ತಿ);
	}
	ಆದರೆ (r != 0)
		ಹಿಂತಿರುಗಿ r;
	/* start initial kex as soon as we have exchanged the banners */
	ಆದರೆ (sshbuf_len(ssh->kex->server_ಆವೃತ್ತಿ) != 0 &&
	    sshbuf_len(ssh->kex->client_ಆವೃತ್ತಿ) != 0) {
		ಆದರೆ ((r = ssh_ಕ್ರಮ_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ರಚನೆ sshkey *
ssh_host_ಬಹಿರಂಗ_ಕೀಲಿ(ಪೂರ್ಣಾಂಕ type, ಪೂರ್ಣಾಂಕ nid, ರಚನೆ ssh *ssh)
{
	ರಚನೆ ಕೀಲಿ_ನಮೂದು *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->ಬಹಿರಂಗ_ಕೀಲಿಗಳು, ಮುಂದಿನ) {
		debug3_f("check %s", sshkey_type(k->ಕೀಲಿ));
		ಆದರೆ (k->ಕೀಲಿ->type == type &&
		    (type != ಕೀಲಿ_ECDSA || k->ಕೀಲಿ->ecdsa_nid == nid))
			ಹಿಂತಿರುಗಿ (k->ಕೀಲಿ);
	}
	ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
}

ರಚನೆ sshkey *
ssh_host_ಖಾಸಗಿ_ಕೀಲಿ(ಪೂರ್ಣಾಂಕ type, ಪೂರ್ಣಾಂಕ nid, ರಚನೆ ssh *ssh)
{
	ರಚನೆ ಕೀಲಿ_ನಮೂದು *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->ಖಾಸಗಿ_ಕೀಲಿಗಳು, ಮುಂದಿನ) {
		debug3_f("check %s", sshkey_type(k->ಕೀಲಿ));
		ಆದರೆ (k->ಕೀಲಿ->type == type &&
		    (type != ಕೀಲಿ_ECDSA || k->ಕೀಲಿ->ecdsa_nid == nid))
			ಹಿಂತಿರುಗಿ (k->ಕೀಲಿ);
	}
	ಹಿಂತಿರುಗಿ (ಖಾಲಿ);
}

ಪೂರ್ಣಾಂಕ
ssh_verify_host_ಕೀಲಿ(ರಚನೆ sshkey *hostkey, ರಚನೆ ssh *ssh)
{
	ರಚನೆ ಕೀಲಿ_ನಮೂದು *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->ಬಹಿರಂಗ_ಕೀಲಿಗಳು, ಮುಂದಿನ) {
		debug3_f("check %s", sshkey_type(k->ಕೀಲಿ));
		ಆದರೆ (sshkey_equal_ಬಹಿರಂಗ(hostkey, k->ಕೀಲಿ))
			ಹಿಂತಿರುಗಿ (0);	/* ok */
	}
	ಹಿಂತಿರುಗಿ (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
ಪೂರ್ಣಾಂಕ
ssh_ಕ್ರಮ_hostkeyalgs(ರಚನೆ ssh *ssh)
{
	ರಚನೆ ಕೀಲಿ_ನಮೂದು *k;
	ಅಕ್ಷರ *orig, *avail, *oavail = ಖಾಲಿ, *alg, *replace = ಖಾಲಿ;
	ಅಕ್ಷರ **proposal;
	ಗಾತ್ರ_t maxlen;
	ಪೂರ್ಣಾಂಕ ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	ಆದರೆ ((r = kex_buf2prop(ssh->kex->my, ಖಾಲಿ, &proposal)) != 0)
		ಹಿಂತಿರುಗಿ r;
	orig = proposal[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS];
	ಆದರೆ ((oavail = avail = strdup(orig)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	maxlen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(avail) + 1;
	ಆದರೆ ((replace = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, maxlen)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	*replace = '\0';
	ಆಗ ((alg = strsep(&avail, ",")) && *alg != '\0') {
		ಆದರೆ ((ktype = sshkey_type_from_name(alg)) == ಕೀಲಿ_UNSPEC)
			ಮುಂದುವರಿ;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->ಬಹಿರಂಗ_ಕೀಲಿಗಳು, ಮುಂದಿನ) {
			ಆದರೆ (k->ಕೀಲಿ->type != ktype &&
			    (!sshkey_is_cert(k->ಕೀಲಿ) ||
			    k->ಕೀಲಿ->type != sshkey_type_plain(ktype)))
				ಮುಂದುವರಿ;
			ಆದರೆ (sshkey_type_plain(k->ಕೀಲಿ->type) == ಕೀಲಿ_ECDSA &&
			    k->ಕೀಲಿ->ecdsa_nid != nid)
				ಮುಂದುವರಿ;
			/* Candidate */
			ಆದರೆ (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			ನಿಲ್ಲಿಸು;
		}
	}
	ಆದರೆ (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		ಬಿಡುಗಡೆ(orig);
		proposal[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS] = replace;
		replace = ಖಾಲಿ;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(oavail);
	ಬಿಡುಗಡೆ(replace);
	kex_prop_free(proposal);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
ssh_host_ಕೀಲಿ_sign(ರಚನೆ ssh *ssh, ರಚನೆ sshkey *privkey,
    ರಚನೆ sshkey *pubkey, u_char **signature, ಗಾತ್ರ_t *slen,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t dlen, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg)
{
	ಹಿಂತಿರುಗಿ sshkey_sign(privkey, signature, slen, ದತ್ತಾಂಶ, dlen,
	    alg, ಖಾಲಿ, ಖಾಲಿ, ssh->compat);
}
