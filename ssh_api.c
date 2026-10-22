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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "ssh_api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh2.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "version.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "myproposal.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

ਪੂਰਨ	_ssh_exchange_banner(ਬਣਤਰ ssh *);
ਪੂਰਨ	_ssh_send_banner(ਬਣਤਰ ssh *, ਬਣਤਰ sshbuf *);
ਪੂਰਨ	_ssh_read_banner(ਬਣਤਰ ssh *, ਬਣਤਰ sshbuf *);
ਪੂਰਨ	ssh_ਕ੍ਰਮ_hostkeyalgs(ਬਣਤਰ ssh *);
ਪੂਰਨ	ssh_verify_host_ਕੁੰਜੀ(ਬਣਤਰ sshkey *, ਬਣਤਰ ssh *);
ਬਣਤਰ sshkey *ssh_host_ਜਨਤਕ_ਕੁੰਜੀ(ਪੂਰਨ, ਪੂਰਨ, ਬਣਤਰ ssh *);
ਬਣਤਰ sshkey *ssh_host_ਨਿੱਜੀ_ਕੁੰਜੀ(ਪੂਰਨ, ਪੂਰਨ, ਬਣਤਰ ssh *);
ਪੂਰਨ	ssh_host_ਕੁੰਜੀ_sign(ਬਣਤਰ ssh *, ਬਣਤਰ sshkey *, ਬਣਤਰ sshkey *,
    u_char **, ਮਾਪ_t *, ਅਚਲ u_char *, ਮਾਪ_t, ਅਚਲ ਅੱਖਰ *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
ਪੂਰਨ	mm_sshkey_sign(ਬਣਤਰ sshkey *, u_char **, u_int *,
    ਅਚਲ u_char *, u_int, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, u_int);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
DH	*mm_ਚੁਣੋ_dh(ਪੂਰਨ, ਪੂਰਨ, ਪੂਰਨ);
#ਜੇ_ਅੰਤ

ਪੂਰਨ
mm_sshkey_sign(ਬਣਤਰ sshkey *ਕੁੰਜੀ, u_char **sigp, u_int *lenp,
    ਅਚਲ u_char *ਅੰਕੜੇ, u_int datalen, ਅਚਲ ਅੱਖਰ *alg,
    ਅਚਲ ਅੱਖਰ *sk_provider, ਅਚਲ ਅੱਖਰ *sk_pin, u_int compat)
{
	ਮਾਪ_t slen = 0;
	ਪੂਰਨ ret;

	ret = sshkey_sign(ਕੁੰਜੀ, sigp, &slen, ਅੰਕੜੇ, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	ਵਾਪਸ ret;
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
DH *
mm_ਚੁਣੋ_dh(ਪੂਰਨ min, ਪੂਰਨ nbits, ਪੂਰਨ max)
{
	ਵਾਪਸ ਚੁਣੋ_dh(min, nbits, max);
}
#ਜੇ_ਅੰਤ

/* API */

ਪੂਰਨ
ssh_init(ਬਣਤਰ ssh **sshp, ਪੂਰਨ is_server, ਬਣਤਰ kex_params *kex_params)
{
	ਅੱਖਰ *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	ਅੱਖਰ *populated[PROPOSAL_MAX];
	ਬਣਤਰ ssh *ssh;
	ਅੱਖਰ **proposal;
	ਸਥਿਰ ਪੂਰਨ called;
	ਪੂਰਨ r;

	ਜੇ (!called) {
		ਬੀਜ_rng();
		called = 1;
	}

	ਜੇ ((ssh = ssh_packet_ਸੈੱਟ_connection(ਨਿਰਾ, -1, -1)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ (is_server)
		ssh_packet_ਸੈੱਟ_server(ssh);

	/* Initialize key exchange */
	proposal = kex_params ? kex_params->proposal : myproposal;
	kex_proposal_populate_entries(ssh, populated,
	    proposal[PROPOSAL_KEX_ALGS],
	    proposal[PROPOSAL_ENC_ALGS_CTOS],
	    proposal[PROPOSAL_MAC_ALGS_CTOS],
	    proposal[PROPOSAL_COMP_ALGS_CTOS],
	    proposal[PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS]);
	r = kex_ready(ssh, populated);
	kex_proposal_free_entries(populated);
	ਜੇ (r != 0) {
		ssh_free(ssh);
		ਵਾਪਸ r;
	}

	ssh->kex->server = is_server;
	ਜੇ (is_server) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
		ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
		ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
		ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
		ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
		ssh->kex->ਲੱਦੋ_host_ਜਨਤਕ_ਕੁੰਜੀ=&ssh_host_ਜਨਤਕ_ਕੁੰਜੀ;
		ssh->kex->ਲੱਦੋ_host_ਨਿੱਜੀ_ਕੁੰਜੀ=&ssh_host_ਨਿੱਜੀ_ਕੁੰਜੀ;
		ssh->kex->sign=&ssh_host_ਕੁੰਜੀ_sign;
	} ਨਹੀਂਤਾਂ {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
		ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
		ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
		ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
		ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
		ssh->kex->verify_host_ਕੁੰਜੀ =&ssh_verify_host_ਕੁੰਜੀ;
	}
	*sshp = ssh;
	ਵਾਪਸ 0;
}

ਖਾਲੀ
ssh_free(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ ਕੁੰਜੀ_ਇੰਦਰਾਜ *k;

	ਜੇ (ssh == ਨਿਰਾ)
		ਵਾਪਸ;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	ਜਦੋਂ ((k = TAILQ_FIRST(&ssh->ਜਨਤਕ_ਕੁੰਜੀਆਂ)) != ਨਿਰਾ) {
		TAILQ_REMOVE(&ssh->ਜਨਤਕ_ਕੁੰਜੀਆਂ, k, ਅਗਲਾ);
		ਜੇ (ssh->kex && ssh->kex->server)
			sshkey_free(k->ਕੁੰਜੀ);
		ਮੁਕਤ(k);
	}
	ਜਦੋਂ ((k = TAILQ_FIRST(&ssh->ਨਿੱਜੀ_ਕੁੰਜੀਆਂ)) != ਨਿਰਾ) {
		TAILQ_REMOVE(&ssh->ਨਿੱਜੀ_ਕੁੰਜੀਆਂ, k, ਅਗਲਾ);
		ਮੁਕਤ(k);
	}
	ssh_packet_close(ssh);
	ਮੁਕਤ(ssh);
}

ਖਾਲੀ
ssh_ਸੈੱਟ_app_ਅੰਕੜੇ(ਬਣਤਰ ssh *ssh, ਖਾਲੀ *app_ਅੰਕੜੇ)
{
	ssh->app_ਅੰਕੜੇ = app_ਅੰਕੜੇ;
}

ਖਾਲੀ *
ssh_get_app_ਅੰਕੜੇ(ਬਣਤਰ ssh *ssh)
{
	ਵਾਪਸ ssh->app_ਅੰਕੜੇ;
}

/* Returns < 0 on error, 0 otherwise */
ਪੂਰਨ
ssh_ਜੋੜੋ_hostkey(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਬਣਤਰ sshkey *pubkey = ਨਿਰਾ;
	ਬਣਤਰ ਕੁੰਜੀ_ਇੰਦਰਾਜ *k = ਨਿਰਾ, *k_prv = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ (ssh->kex->server) {
		ਜੇ ((r = sshkey_from_ਨਿੱਜੀ(ਕੁੰਜੀ, &pubkey)) != 0)
			ਵਾਪਸ r;
		ਜੇ ((k = ਸਮ੍ਰਿਤੀ_ਦਿਓ(ਆਕਾਰ(*k))) == ਨਿਰਾ ||
		    (k_prv = ਸਮ੍ਰਿਤੀ_ਦਿਓ(ਆਕਾਰ(*k_prv))) == ਨਿਰਾ) {
			ਮੁਕਤ(k);
			sshkey_free(pubkey);
			ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
		}
		k_prv->ਕੁੰਜੀ = ਕੁੰਜੀ;
		TAILQ_INSERT_TAIL(&ssh->ਨਿੱਜੀ_ਕੁੰਜੀਆਂ, k_prv, ਅਗਲਾ);

		/* add the public key, too */
		k->ਕੁੰਜੀ = pubkey;
		TAILQ_INSERT_TAIL(&ssh->ਜਨਤਕ_ਕੁੰਜੀਆਂ, k, ਅਗਲਾ);
		r = 0;
	} ਨਹੀਂਤਾਂ {
		ਜੇ ((k = ਸਮ੍ਰਿਤੀ_ਦਿਓ(ਆਕਾਰ(*k))) == ਨਿਰਾ)
			ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
		k->ਕੁੰਜੀ = ਕੁੰਜੀ;
		TAILQ_INSERT_TAIL(&ssh->ਜਨਤਕ_ਕੁੰਜੀਆਂ, k, ਅਗਲਾ);
		r = 0;
	}

	ਵਾਪਸ r;
}

ਪੂਰਨ
ssh_ਸੈੱਟ_verify_host_ਕੁੰਜੀ_callback(ਬਣਤਰ ssh *ssh,
    ਪੂਰਨ (*cb)(ਬਣਤਰ sshkey *, ਬਣਤਰ ssh *))
{
	ਜੇ (cb == ਨਿਰਾ || ssh->kex == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;

	ssh->kex->verify_host_ਕੁੰਜੀ = cb;

	ਵਾਪਸ 0;
}

ਪੂਰਨ
ssh_ਨਿਵੇਸ਼_append(ਬਣਤਰ ssh *ssh, ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t len)
{
	ਵਾਪਸ sshbuf_put(ssh_packet_get_ਨਿਵੇਸ਼(ssh), ਅੰਕੜੇ, len);
}

ਪੂਰਨ
ssh_packet_ਅਗਲਾ(ਬਣਤਰ ssh *ssh, u_char *typep)
{
	ਪੂਰਨ r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_ਸੁਨੇਹਾ_NONE;
	ਜੇ (sshbuf_len(ssh->kex->client_ਸੰਸਕਰਣ) == 0 ||
	    sshbuf_len(ssh->kex->server_ਸੰਸਕਰਣ) == 0)
		ਵਾਪਸ _ssh_exchange_banner(ssh);
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
	ਲਈ (;;) {
		ਜੇ ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			ਵਾਪਸ r;
		ਜੇ (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_ਸੁਨੇਹਾ_KEXINIT && type <= SSH2_ਸੁਨੇਹਾ_TRANSPORT_MAX &&
		    ssh->dispatch[type] != ਨਿਰਾ) {
			ਜੇ ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				ਵਾਪਸ r;
		} ਨਹੀਂਤਾਂ {
			*typep = type;
			ਵਾਪਸ 0;
		}
	}
}

ਅਚਲ u_char *
ssh_packet_payload(ਬਣਤਰ ssh *ssh, ਮਾਪ_t *lenp)
{
	ਵਾਪਸ sshpkt_ptr(ssh, lenp);
}

ਪੂਰਨ
ssh_packet_put(ਬਣਤਰ ssh *ssh, ਪੂਰਨ type, ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t len)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshpkt_ਸ਼ੁਰੂ(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, ਅੰਕੜੇ, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ਵਾਪਸ r;
	ਵਾਪਸ 0;
}

ਅਚਲ u_char *
ssh_output_ptr(ਬਣਤਰ ssh *ssh, ਮਾਪ_t *len)
{
	ਬਣਤਰ sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	ਵਾਪਸ sshbuf_ptr(output);
}

ਪੂਰਨ
ssh_output_consume(ਬਣਤਰ ssh *ssh, ਮਾਪ_t len)
{
	ਵਾਪਸ sshbuf_consume(ssh_packet_get_output(ssh), len);
}

ਪੂਰਨ
ssh_output_space(ਬਣਤਰ ssh *ssh, ਮਾਪ_t len)
{
	ਵਾਪਸ (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

ਪੂਰਨ
ssh_ਨਿਵੇਸ਼_space(ਬਣਤਰ ssh *ssh, ਮਾਪ_t len)
{
	ਵਾਪਸ (0 == sshbuf_check_reserve(ssh_packet_get_ਨਿਵੇਸ਼(ssh), len));
}

/* Read other side's version identification. */
ਪੂਰਨ
_ssh_read_banner(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshbuf *banner)
{
	ਬਣਤਰ sshbuf *ਨਿਵੇਸ਼ = ssh_packet_get_ਨਿਵੇਸ਼(ssh);
	ਅਚਲ ਅੱਖਰ *mismatch = "Protocol mismatch.\r\n";
	ਅਚਲ u_char *s = sshbuf_ptr(ਨਿਵੇਸ਼);
	u_char c;
	ਅੱਖਰ *cp = ਨਿਰਾ, *remote_ਸੰਸਕਰਣ = ਨਿਰਾ;
	ਪੂਰਨ r = 0, remote_major, remote_minor, expect_nl;
	ਮਾਪ_t n, j;

	ਲਈ (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		ਲਈ (;;) {
			ਜੇ (j >= sshbuf_len(ਨਿਵੇਸ਼))
				ਵਾਪਸ 0; /* insufficient data in input buf */
			c = s[j++];
			ਜੇ (c == '\r') {
				expect_nl = 1;
				ਜਾਰੀ;
			}
			ਜੇ (c == '\n')
				ਰੋਕੋ;
			ਜੇ (expect_nl)
				ਜਾਓ bad;
			ਜੇ ((r = sshbuf_put_u8(banner, c)) != 0)
				ਵਾਪਸ r;
			ਜੇ (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				ਜਾਓ bad;
		}
		ਜੇ (sshbuf_len(banner) >= 4 &&
		    memcmp(sshbuf_ptr(banner), "SSH-", 4) == 0)
			ਰੋਕੋ;
		debug_f("%.*s", (ਪੂਰਨ)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		ਜੇ (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_ਸਤਰਾਂ) {
  bad:
			ਜੇ ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, ਲੜੀ_ਲੰਬਾਈ(mismatch))) != 0)
				ਵਾਪਸ r;
			ਵਾਪਸ SSH_ERR_NO_PROTOCOL_ਸੰਸਕਰਣ;
		}
	}
	ਜੇ ((r = sshbuf_consume(ਨਿਵੇਸ਼, j)) != 0)
		ਵਾਪਸ r;

	/* XXX remote version must be the same size as banner for sscanf */
	ਜੇ ((cp = sshbuf_dup_string(banner)) == ਨਿਰਾ ||
	    (remote_ਸੰਸਕਰਣ = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, sshbuf_len(banner))) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	ਜੇ (ਲੜੀ_ਤੋਂ_ਪੜ੍ਹੋ(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_ਸੰਸਕਰਣ) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_ਸੰਸਕਰਣ);

	compat_banner(ssh, remote_ਸੰਸਕਰਣ);
	ਜੇ  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	ਜੇ (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(cp);
	ਮੁਕਤ(remote_ਸੰਸਕਰਣ);
	ਵਾਪਸ r;
}

/* Send our own protocol version identification. */
ਪੂਰਨ
_ssh_send_banner(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshbuf *banner)
{
	ਅੱਖਰ *cp;
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_ਸੰਸਕਰਣ)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		ਵਾਪਸ r;
	/* Remove trailing \r\n */
	ਜੇ ((r = sshbuf_consume_ਸਿਰਾ(banner, 2)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((cp = sshbuf_dup_string(banner)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	ਮੁਕਤ(cp);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
_ssh_exchange_banner(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ kex *kex = ssh->kex;
	ਪੂਰਨ r;

	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */

	r = 0;
	ਜੇ (kex->server) {
		ਜੇ (sshbuf_len(ssh->kex->server_ਸੰਸਕਰਣ) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_ਸੰਸਕਰਣ);
		ਜੇ (r == 0 &&
		    sshbuf_len(ssh->kex->server_ਸੰਸਕਰਣ) != 0 &&
		    sshbuf_len(ssh->kex->client_ਸੰਸਕਰਣ) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_ਸੰਸਕਰਣ);
	} ਨਹੀਂਤਾਂ {
		ਜੇ (sshbuf_len(ssh->kex->server_ਸੰਸਕਰਣ) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_ਸੰਸਕਰਣ);
		ਜੇ (r == 0 &&
		    sshbuf_len(ssh->kex->server_ਸੰਸਕਰਣ) != 0 &&
		    sshbuf_len(ssh->kex->client_ਸੰਸਕਰਣ) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_ਸੰਸਕਰਣ);
	}
	ਜੇ (r != 0)
		ਵਾਪਸ r;
	/* start initial kex as soon as we have exchanged the banners */
	ਜੇ (sshbuf_len(ssh->kex->server_ਸੰਸਕਰਣ) != 0 &&
	    sshbuf_len(ssh->kex->client_ਸੰਸਕਰਣ) != 0) {
		ਜੇ ((r = ssh_ਕ੍ਰਮ_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			ਵਾਪਸ r;
	}
	ਵਾਪਸ 0;
}

ਬਣਤਰ sshkey *
ssh_host_ਜਨਤਕ_ਕੁੰਜੀ(ਪੂਰਨ type, ਪੂਰਨ nid, ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ ਕੁੰਜੀ_ਇੰਦਰਾਜ *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->ਜਨਤਕ_ਕੁੰਜੀਆਂ, ਅਗਲਾ) {
		debug3_f("check %s", sshkey_type(k->ਕੁੰਜੀ));
		ਜੇ (k->ਕੁੰਜੀ->type == type &&
		    (type != ਕੁੰਜੀ_ECDSA || k->ਕੁੰਜੀ->ecdsa_nid == nid))
			ਵਾਪਸ (k->ਕੁੰਜੀ);
	}
	ਵਾਪਸ (ਨਿਰਾ);
}

ਬਣਤਰ sshkey *
ssh_host_ਨਿੱਜੀ_ਕੁੰਜੀ(ਪੂਰਨ type, ਪੂਰਨ nid, ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ ਕੁੰਜੀ_ਇੰਦਰਾਜ *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->ਨਿੱਜੀ_ਕੁੰਜੀਆਂ, ਅਗਲਾ) {
		debug3_f("check %s", sshkey_type(k->ਕੁੰਜੀ));
		ਜੇ (k->ਕੁੰਜੀ->type == type &&
		    (type != ਕੁੰਜੀ_ECDSA || k->ਕੁੰਜੀ->ecdsa_nid == nid))
			ਵਾਪਸ (k->ਕੁੰਜੀ);
	}
	ਵਾਪਸ (ਨਿਰਾ);
}

ਪੂਰਨ
ssh_verify_host_ਕੁੰਜੀ(ਬਣਤਰ sshkey *hostkey, ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ ਕੁੰਜੀ_ਇੰਦਰਾਜ *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->ਜਨਤਕ_ਕੁੰਜੀਆਂ, ਅਗਲਾ) {
		debug3_f("check %s", sshkey_type(k->ਕੁੰਜੀ));
		ਜੇ (sshkey_equal_ਜਨਤਕ(hostkey, k->ਕੁੰਜੀ))
			ਵਾਪਸ (0);	/* ok */
	}
	ਵਾਪਸ (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
ਪੂਰਨ
ssh_ਕ੍ਰਮ_hostkeyalgs(ਬਣਤਰ ssh *ssh)
{
	ਬਣਤਰ ਕੁੰਜੀ_ਇੰਦਰਾਜ *k;
	ਅੱਖਰ *orig, *avail, *oavail = ਨਿਰਾ, *alg, *replace = ਨਿਰਾ;
	ਅੱਖਰ **proposal;
	ਮਾਪ_t maxlen;
	ਪੂਰਨ ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	ਜੇ ((r = kex_buf2prop(ssh->kex->my, ਨਿਰਾ, &proposal)) != 0)
		ਵਾਪਸ r;
	orig = proposal[PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS];
	ਜੇ ((oavail = avail = strdup(orig)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	maxlen = ਲੜੀ_ਲੰਬਾਈ(avail) + 1;
	ਜੇ ((replace = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, maxlen)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	*replace = '\0';
	ਜਦੋਂ ((alg = strsep(&avail, ",")) && *alg != '\0') {
		ਜੇ ((ktype = sshkey_type_from_name(alg)) == ਕੁੰਜੀ_UNSPEC)
			ਜਾਰੀ;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->ਜਨਤਕ_ਕੁੰਜੀਆਂ, ਅਗਲਾ) {
			ਜੇ (k->ਕੁੰਜੀ->type != ktype &&
			    (!sshkey_is_cert(k->ਕੁੰਜੀ) ||
			    k->ਕੁੰਜੀ->type != sshkey_type_plain(ktype)))
				ਜਾਰੀ;
			ਜੇ (sshkey_type_plain(k->ਕੁੰਜੀ->type) == ਕੁੰਜੀ_ECDSA &&
			    k->ਕੁੰਜੀ->ecdsa_nid != nid)
				ਜਾਰੀ;
			/* Candidate */
			ਜੇ (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			ਰੋਕੋ;
		}
	}
	ਜੇ (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		ਮੁਕਤ(orig);
		proposal[PROPOSAL_SERVER_HOST_ਕੁੰਜੀ_ALGS] = replace;
		replace = ਨਿਰਾ;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(oavail);
	ਮੁਕਤ(replace);
	kex_prop_free(proposal);
	ਵਾਪਸ r;
}

ਪੂਰਨ
ssh_host_ਕੁੰਜੀ_sign(ਬਣਤਰ ssh *ssh, ਬਣਤਰ sshkey *privkey,
    ਬਣਤਰ sshkey *pubkey, u_char **signature, ਮਾਪ_t *slen,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t dlen, ਅਚਲ ਅੱਖਰ *alg)
{
	ਵਾਪਸ sshkey_sign(privkey, signature, slen, ਅੰਕੜੇ, dlen,
	    alg, ਨਿਰਾ, ਨਿਰਾ, ssh->compat);
}
