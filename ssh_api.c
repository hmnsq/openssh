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

ಪೂರ್ಣಾಙ್ಕ	_ssh_exchange_banner(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	_ssh_send_banner(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ	_ssh_read_banner(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ	_ssh_order_hostkeyalgs(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	ssh_verify_host_ಕೀಲಿ(ಸಂರಚನಾ sshkey *, ಸಂರಚನಾ ssh *);
ಸಂರಚನಾ sshkey *ssh_host_public_ಕೀಲಿ(ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ ssh *);
ಸಂರಚನಾ sshkey *ssh_host_private_ಕೀಲಿ(ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	ssh_host_ಕೀಲಿ_sign(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ sshkey *, ಸಂರಚನಾ sshkey *,
    u_char **, size_t *, ಧ್ರುವ u_char *, size_t, ಧ್ರುವ ವರ್ಣ *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
ಪೂರ್ಣಾಙ್ಕ	mm_sshkey_sign(ಸಂರಚನಾ sshkey *, u_char **, u_int *,
    ಧ್ರುವ u_char *, u_int, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, u_int);

#ifdef WITH_OPENSSL
DH	*mm_choose_dh(ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
#endif

ಪೂರ್ಣಾಙ್ಕ
mm_sshkey_sign(ಸಂರಚನಾ sshkey *ಕೀಲಿ, u_char **sigp, u_int *lenp,
    ಧ್ರುವ u_char *data, u_int datalen, ಧ್ರುವ ವರ್ಣ *alg,
    ಧ್ರುವ ವರ್ಣ *sk_provider, ಧ್ರುವ ವರ್ಣ *sk_pin, u_int compat)
{
	size_t slen = 0;
	ಪೂರ್ಣಾಙ್ಕ ret;

	ret = sshkey_sign(ಕೀಲಿ, sigp, &slen, data, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	ಪ್ರತ್ಯಾಗಮ ret;
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(ಪೂರ್ಣಾಙ್ಕ min, ಪೂರ್ಣಾಙ್ಕ nbits, ಪೂರ್ಣಾಙ್ಕ max)
{
	ಪ್ರತ್ಯಾಗಮ choose_dh(min, nbits, max);
}
#endif

/* API */

ಪೂರ್ಣಾಙ್ಕ
ssh_init(ಸಂರಚನಾ ssh **sshp, ಪೂರ್ಣಾಙ್ಕ is_server, ಸಂರಚನಾ kex_params *kex_params)
{
	ವರ್ಣ *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	ವರ್ಣ *populated[PROPOSAL_MAX];
	ಸಂರಚನಾ ssh *ssh;
	ವರ್ಣ **proposal;
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ called;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (!called) {
		seed_rng();
		called = 1;
	}

	ಯದಿ ((ssh = ssh_packet_set_connection(ರಿಕ್ತ, -1, -1)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ (is_server)
		ssh_packet_set_server(ssh);

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
	ಯದಿ (r != 0) {
		ssh_free(ssh);
		ಪ್ರತ್ಯಾಗಮ r;
	}

	ssh->kex->server = is_server;
	ಯದಿ (is_server) {
#ifdef WITH_OPENSSL
		ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
		ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
		ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
#endif /* WITH_OPENSSL */
		ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
		ssh->kex->load_host_public_ಕೀಲಿ=&ssh_host_public_ಕೀಲಿ;
		ssh->kex->load_host_private_ಕೀಲಿ=&ssh_host_private_ಕೀಲಿ;
		ssh->kex->sign=&ssh_host_ಕೀಲಿ_sign;
	} ಅನ್ಯಥಾ {
#ifdef WITH_OPENSSL
		ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
		ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
		ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#endif /* WITH_OPENSSL */
		ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
		ssh->kex->verify_host_ಕೀಲಿ =&ssh_verify_host_ಕೀಲಿ;
	}
	*sshp = ssh;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಶೂನ್ಯ
ssh_free(ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ ಕೀಲಿ_entry *k;

	ಯದಿ (ssh == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	ಯಾವತ್ ((k = TAILQ_FIRST(&ssh->public_ಕೀಲಿಗಳು)) != ರಿಕ್ತ) {
		TAILQ_REMOVE(&ssh->public_ಕೀಲಿಗಳು, k, next);
		ಯದಿ (ssh->kex && ssh->kex->server)
			sshkey_free(k->ಕೀಲಿ);
		ಮುಕ್ತ(k);
	}
	ಯಾವತ್ ((k = TAILQ_FIRST(&ssh->private_ಕೀಲಿಗಳು)) != ರಿಕ್ತ) {
		TAILQ_REMOVE(&ssh->private_ಕೀಲಿಗಳು, k, next);
		ಮುಕ್ತ(k);
	}
	ssh_packet_close(ssh);
	ಮುಕ್ತ(ssh);
}

ಶೂನ್ಯ
ssh_set_app_data(ಸಂರಚನಾ ssh *ssh, ಶೂನ್ಯ *app_data)
{
	ssh->app_data = app_data;
}

ಶೂನ್ಯ *
ssh_get_app_data(ಸಂರಚನಾ ssh *ssh)
{
	ಪ್ರತ್ಯಾಗಮ ssh->app_data;
}

/* Returns < 0 on error, 0 otherwise */
ಪೂರ್ಣಾಙ್ಕ
ssh_add_hostkey(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಸಂರಚನಾ sshkey *pubkey = ರಿಕ್ತ;
	ಸಂರಚನಾ ಕೀಲಿ_entry *k = ರಿಕ್ತ, *k_prv = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (ssh->kex->server) {
		ಯದಿ ((r = sshkey_from_private(ಕೀಲಿ, &pubkey)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
		ಯದಿ ((k = malloc(ಪರಿಮಾಣ(*k))) == ರಿಕ್ತ ||
		    (k_prv = malloc(ಪರಿಮಾಣ(*k_prv))) == ರಿಕ್ತ) {
			ಮುಕ್ತ(k);
			sshkey_free(pubkey);
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
		}
		k_prv->ಕೀಲಿ = ಕೀಲಿ;
		TAILQ_INSERT_TAIL(&ssh->private_ಕೀಲಿಗಳು, k_prv, next);

		/* add the public key, too */
		k->ಕೀಲಿ = pubkey;
		TAILQ_INSERT_TAIL(&ssh->public_ಕೀಲಿಗಳು, k, next);
		r = 0;
	} ಅನ್ಯಥಾ {
		ಯದಿ ((k = malloc(ಪರಿಮಾಣ(*k))) == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
		k->ಕೀಲಿ = ಕೀಲಿ;
		TAILQ_INSERT_TAIL(&ssh->public_ಕೀಲಿಗಳು, k, next);
		r = 0;
	}

	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_set_verify_host_ಕೀಲಿ_callback(ಸಂರಚನಾ ssh *ssh,
    ಪೂರ್ಣಾಙ್ಕ (*cb)(ಸಂರಚನಾ sshkey *, ಸಂರಚನಾ ssh *))
{
	ಯದಿ (cb == ರಿಕ್ತ || ssh->kex == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;

	ssh->kex->verify_host_ಕೀಲಿ = cb;

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_ಒಳಹರಿವು_append(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ u_char *data, size_t len)
{
	ಪ್ರತ್ಯಾಗಮ sshbuf_put(ssh_packet_get_ಒಳಹರಿವು(ssh), data, len);
}

ಪೂರ್ಣಾಙ್ಕ
ssh_packet_next(ಸಂರಚನಾ ssh *ssh, u_char *typep)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_ಸಂದೇಶ_NONE;
	ಯದಿ (sshbuf_len(ssh->kex->client_version) == 0 ||
	    sshbuf_len(ssh->kex->server_version) == 0)
		ಪ್ರತ್ಯಾಗಮ _ssh_exchange_banner(ssh);
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
	ಪ್ರತಿ (;;) {
		ಯದಿ ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
		ಯದಿ (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_ಸಂದೇಶ_KEXINIT && type <= SSH2_ಸಂದೇಶ_TRANSPORT_MAX &&
		    ssh->dispatch[type] != ರಿಕ್ತ) {
			ಯದಿ ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				ಪ್ರತ್ಯಾಗಮ r;
		} ಅನ್ಯಥಾ {
			*typep = type;
			ಪ್ರತ್ಯಾಗಮ 0;
		}
	}
}

ಧ್ರುವ u_char *
ssh_packet_payload(ಸಂರಚನಾ ssh *ssh, size_t *lenp)
{
	ಪ್ರತ್ಯಾಗಮ sshpkt_ptr(ssh, lenp);
}

ಪೂರ್ಣಾಙ್ಕ
ssh_packet_put(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ type, ಧ್ರುವ u_char *data, size_t len)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshpkt_start(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, data, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಧ್ರುವ u_char *
ssh_output_ptr(ಸಂರಚನಾ ssh *ssh, size_t *len)
{
	ಸಂರಚನಾ sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	ಪ್ರತ್ಯಾಗಮ sshbuf_ptr(output);
}

ಪೂರ್ಣಾಙ್ಕ
ssh_output_consume(ಸಂರಚನಾ ssh *ssh, size_t len)
{
	ಪ್ರತ್ಯಾಗಮ sshbuf_consume(ssh_packet_get_output(ssh), len);
}

ಪೂರ್ಣಾಙ್ಕ
ssh_output_space(ಸಂರಚನಾ ssh *ssh, size_t len)
{
	ಪ್ರತ್ಯಾಗಮ (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

ಪೂರ್ಣಾಙ್ಕ
ssh_ಒಳಹರಿವು_space(ಸಂರಚನಾ ssh *ssh, size_t len)
{
	ಪ್ರತ್ಯಾಗಮ (0 == sshbuf_check_reserve(ssh_packet_get_ಒಳಹರಿವು(ssh), len));
}

/* Read other side's version identification. */
ಪೂರ್ಣಾಙ್ಕ
_ssh_read_banner(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ sshbuf *banner)
{
	ಸಂರಚನಾ sshbuf *ಒಳಹರಿವು = ssh_packet_get_ಒಳಹರಿವು(ssh);
	ಧ್ರುವ ವರ್ಣ *mismatch = "Protocol mismatch.\r\n";
	ಧ್ರುವ u_char *s = sshbuf_ptr(ಒಳಹರಿವು);
	u_char c;
	ವರ್ಣ *cp = ರಿಕ್ತ, *remote_version = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = 0, remote_major, remote_minor, expect_nl;
	size_t n, j;

	ಪ್ರತಿ (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		ಪ್ರತಿ (;;) {
			ಯದಿ (j >= sshbuf_len(ಒಳಹರಿವು))
				ಪ್ರತ್ಯಾಗಮ 0; /* insufficient data in input buf */
			c = s[j++];
			ಯದಿ (c == '\r') {
				expect_nl = 1;
				ಅನುವರ್ತ;
			}
			ಯದಿ (c == '\n')
				ಭಙ್ಗ;
			ಯದಿ (expect_nl)
				ಗಚ್ಛ bad;
			ಯದಿ ((r = sshbuf_put_u8(banner, c)) != 0)
				ಪ್ರತ್ಯಾಗಮ r;
			ಯದಿ (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				ಗಚ್ಛ bad;
		}
		ಯದಿ (sshbuf_len(banner) >= 4 &&
		    memcmp(sshbuf_ptr(banner), "SSH-", 4) == 0)
			ಭಙ್ಗ;
		debug_f("%.*s", (ಪೂರ್ಣಾಙ್ಕ)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		ಯದಿ (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_ಸಾಲುಗಳು) {
  bad:
			ಯದಿ ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, strlen(mismatch))) != 0)
				ಪ್ರತ್ಯಾಗಮ r;
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_NO_PROTOCOL_VERSION;
		}
	}
	ಯದಿ ((r = sshbuf_consume(ಒಳಹರಿವು, j)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	/* XXX remote version must be the same size as banner for sscanf */
	ಯದಿ ((cp = sshbuf_dup_string(banner)) == ರಿಕ್ತ ||
	    (remote_version = calloc(1, sshbuf_len(banner))) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	ಯದಿ (sscanf(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);

	compat_banner(ssh, remote_version);
	ಯದಿ  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	ಯದಿ (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 out:
	ಮುಕ್ತ(cp);
	ಮುಕ್ತ(remote_version);
	ಪ್ರತ್ಯಾಗಮ r;
}

/* Send our own protocol version identification. */
ಪೂರ್ಣಾಙ್ಕ
_ssh_send_banner(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ sshbuf *banner)
{
	ವರ್ಣ *cp;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_VERSION)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	/* Remove trailing \r\n */
	ಯದಿ ((r = sshbuf_consume_end(banner, 2)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((cp = sshbuf_dup_string(banner)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	ಮುಕ್ತ(cp);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
_ssh_exchange_banner(ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ kex *kex = ssh->kex;
	ಪೂರ್ಣಾಙ್ಕ r;

	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */

	r = 0;
	ಯದಿ (kex->server) {
		ಯದಿ (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_version);
		ಯದಿ (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_version);
	} ಅನ್ಯಥಾ {
		ಯದಿ (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_version);
		ಯದಿ (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_version);
	}
	ಯದಿ (r != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	/* start initial kex as soon as we have exchanged the banners */
	ಯದಿ (sshbuf_len(ssh->kex->server_version) != 0 &&
	    sshbuf_len(ssh->kex->client_version) != 0) {
		ಯದಿ ((r = _ssh_order_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸಂರಚನಾ sshkey *
ssh_host_public_ಕೀಲಿ(ಪೂರ್ಣಾಙ್ಕ type, ಪೂರ್ಣಾಙ್ಕ nid, ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ ಕೀಲಿ_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->public_ಕೀಲಿಗಳು, next) {
		debug3_f("check %s", sshkey_type(k->ಕೀಲಿ));
		ಯದಿ (k->ಕೀಲಿ->type == type &&
		    (type != ಕೀಲಿ_ECDSA || k->ಕೀಲಿ->ecdsa_nid == nid))
			ಪ್ರತ್ಯಾಗಮ (k->ಕೀಲಿ);
	}
	ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
}

ಸಂರಚನಾ sshkey *
ssh_host_private_ಕೀಲಿ(ಪೂರ್ಣಾಙ್ಕ type, ಪೂರ್ಣಾಙ್ಕ nid, ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ ಕೀಲಿ_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->private_ಕೀಲಿಗಳು, next) {
		debug3_f("check %s", sshkey_type(k->ಕೀಲಿ));
		ಯದಿ (k->ಕೀಲಿ->type == type &&
		    (type != ಕೀಲಿ_ECDSA || k->ಕೀಲಿ->ecdsa_nid == nid))
			ಪ್ರತ್ಯಾಗಮ (k->ಕೀಲಿ);
	}
	ಪ್ರತ್ಯಾಗಮ (ರಿಕ್ತ);
}

ಪೂರ್ಣಾಙ್ಕ
ssh_verify_host_ಕೀಲಿ(ಸಂರಚನಾ sshkey *hostkey, ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ ಕೀಲಿ_entry *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->public_ಕೀಲಿಗಳು, next) {
		debug3_f("check %s", sshkey_type(k->ಕೀಲಿ));
		ಯದಿ (sshkey_equal_public(hostkey, k->ಕೀಲಿ))
			ಪ್ರತ್ಯಾಗಮ (0);	/* ok */
	}
	ಪ್ರತ್ಯಾಗಮ (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
ಪೂರ್ಣಾಙ್ಕ
_ssh_order_hostkeyalgs(ಸಂರಚನಾ ssh *ssh)
{
	ಸಂರಚನಾ ಕೀಲಿ_entry *k;
	ವರ್ಣ *orig, *avail, *oavail = ರಿಕ್ತ, *alg, *replace = ರಿಕ್ತ;
	ವರ್ಣ **proposal;
	size_t maxlen;
	ಪೂರ್ಣಾಙ್ಕ ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	ಯದಿ ((r = kex_buf2prop(ssh->kex->my, ರಿಕ್ತ, &proposal)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	orig = proposal[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS];
	ಯದಿ ((oavail = avail = strdup(orig)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	maxlen = strlen(avail) + 1;
	ಯದಿ ((replace = calloc(1, maxlen)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	*replace = '\0';
	ಯಾವತ್ ((alg = strsep(&avail, ",")) && *alg != '\0') {
		ಯದಿ ((ktype = sshkey_type_from_name(alg)) == ಕೀಲಿ_UNSPEC)
			ಅನುವರ್ತ;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->public_ಕೀಲಿಗಳು, next) {
			ಯದಿ (k->ಕೀಲಿ->type != ktype &&
			    (!sshkey_is_cert(k->ಕೀಲಿ) ||
			    k->ಕೀಲಿ->type != sshkey_type_plain(ktype)))
				ಅನುವರ್ತ;
			ಯದಿ (sshkey_type_plain(k->ಕೀಲಿ->type) == ಕೀಲಿ_ECDSA &&
			    k->ಕೀಲಿ->ecdsa_nid != nid)
				ಅನುವರ್ತ;
			/* Candidate */
			ಯದಿ (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			ಭಙ್ಗ;
		}
	}
	ಯದಿ (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		ಮುಕ್ತ(orig);
		proposal[PROPOSAL_SERVER_HOST_ಕೀಲಿ_ALGS] = replace;
		replace = ರಿಕ್ತ;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 out:
	ಮುಕ್ತ(oavail);
	ಮುಕ್ತ(replace);
	kex_prop_free(proposal);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_host_ಕೀಲಿ_sign(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ sshkey *privkey,
    ಸಂರಚನಾ sshkey *pubkey, u_char **signature, size_t *slen,
    ಧ್ರುವ u_char *data, size_t dlen, ಧ್ರುವ ವರ್ಣ *alg)
{
	ಪ್ರತ್ಯಾಗಮ sshkey_sign(privkey, signature, slen, data, dlen,
	    alg, ರಿಕ್ತ, ರಿಕ್ತ, ssh->compat);
}
