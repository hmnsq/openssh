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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>

#ଅନ୍ତର୍ଭାଵ "ssh_api.h"
#ଅନ୍ତର୍ଭାଵ "compat.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "dh.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "ssh2.h"
#ଅନ୍ତର୍ଭାଵ "version.h"
#ଅନ୍ତର୍ଭାଵ "myproposal.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"

#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"

#ଅନ୍ତର୍ଭାଵ <string.h>

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	_ssh_exchange_banner(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	_ssh_send_banner(ସଂରଚନା ssh *, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	_ssh_read_banner(ସଂରଚନା ssh *, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	_ssh_order_hostkeyalgs(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ssh_verify_host_ଚାବି(ସଂରଚନା sshkey *, ସଂରଚନା ssh *);
ସଂରଚନା sshkey *ssh_host_public_ଚାବି(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା ssh *);
ସଂରଚନା sshkey *ssh_host_private_ଚାବି(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	ssh_host_ଚାବି_sign(ସଂରଚନା ssh *, ସଂରଚନା sshkey *, ସଂରଚନା sshkey *,
    u_char **, size_t *, ଅଚଳ u_char *, size_t, ଅଚଳ ଅକ୍ଷର *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	mm_sshkey_sign(ସଂରଚନା sshkey *, u_char **, u_int *,
    ଅଚଳ u_char *, u_int, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, u_int);

#ifdef WITH_OPENSSL
DH	*mm_choose_dh(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
#endif

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
mm_sshkey_sign(ସଂରଚନା sshkey *ଚାବି, u_char **sigp, u_int *lenp,
    ଅଚଳ u_char *data, u_int datalen, ଅଚଳ ଅକ୍ଷର *alg,
    ଅଚଳ ଅକ୍ଷର *sk_provider, ଅଚଳ ଅକ୍ଷର *sk_pin, u_int compat)
{
	size_t slen = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;

	ret = sshkey_sign(ଚାବି, sigp, &slen, data, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	ଫେରନ୍ତୁ ret;
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(ପୂର୍ଣ୍ଣସଂଖ୍ୟା min, ପୂର୍ଣ୍ଣସଂଖ୍ୟା nbits, ପୂର୍ଣ୍ଣସଂଖ୍ୟା max)
{
	ଫେରନ୍ତୁ choose_dh(min, nbits, max);
}
#endif

/* API */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_init(ସଂରଚନା ssh **sshp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା is_server, ସଂରଚନା kex_params *kex_params)
{
	ଅକ୍ଷର *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	ଅକ୍ଷର *populated[PROPOSAL_MAX];
	ସଂରଚନା ssh *ssh;
	ଅକ୍ଷର **proposal;
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା called;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (!called) {
		seed_rng();
		called = 1;
	}

	ଯଦି ((ssh = ssh_packet_set_connection(ଖାଲି, -1, -1)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି (is_server)
		ssh_packet_set_server(ssh);

	/* Initialize key exchange */
	proposal = kex_params ? kex_params->proposal : myproposal;
	kex_proposal_populate_entries(ssh, populated,
	    proposal[PROPOSAL_KEX_ALGS],
	    proposal[PROPOSAL_ENC_ALGS_CTOS],
	    proposal[PROPOSAL_MAC_ALGS_CTOS],
	    proposal[PROPOSAL_COMP_ALGS_CTOS],
	    proposal[PROPOSAL_SERVER_HOST_ଚାବି_ALGS]);
	r = kex_ready(ssh, populated);
	kex_proposal_free_entries(populated);
	ଯଦି (r != 0) {
		ssh_free(ssh);
		ଫେରନ୍ତୁ r;
	}

	ssh->kex->server = is_server;
	ଯଦି (is_server) {
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
		ssh->kex->load_host_public_ଚାବି=&ssh_host_public_ଚାବି;
		ssh->kex->load_host_private_ଚାବି=&ssh_host_private_ଚାବି;
		ssh->kex->sign=&ssh_host_ଚାବି_sign;
	} ଅନ୍ୟଥା {
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
		ssh->kex->verify_host_ଚାବି =&ssh_verify_host_ଚାବି;
	}
	*sshp = ssh;
	ଫେରନ୍ତୁ 0;
}

ଶୂନ୍ୟ
ssh_free(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା ଚାବି_entry *k;

	ଯଦି (ssh == ଖାଲି)
		ଫେରନ୍ତୁ;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	ଯେତେବେଳେ ((k = TAILQ_FIRST(&ssh->public_ଚାବିଗୁଡ଼ିକ)) != ଖାଲି) {
		TAILQ_REMOVE(&ssh->public_ଚାବିଗୁଡ଼ିକ, k, next);
		ଯଦି (ssh->kex && ssh->kex->server)
			sshkey_free(k->ଚାବି);
		ମୁକ୍ତ(k);
	}
	ଯେତେବେଳେ ((k = TAILQ_FIRST(&ssh->private_ଚାବିଗୁଡ଼ିକ)) != ଖାଲି) {
		TAILQ_REMOVE(&ssh->private_ଚାବିଗୁଡ଼ିକ, k, next);
		ମୁକ୍ତ(k);
	}
	ssh_packet_close(ssh);
	ମୁକ୍ତ(ssh);
}

ଶୂନ୍ୟ
ssh_set_app_data(ସଂରଚନା ssh *ssh, ଶୂନ୍ୟ *app_data)
{
	ssh->app_data = app_data;
}

ଶୂନ୍ୟ *
ssh_get_app_data(ସଂରଚନା ssh *ssh)
{
	ଫେରନ୍ତୁ ssh->app_data;
}

/* Returns < 0 on error, 0 otherwise */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_add_hostkey(ସଂରଚନା ssh *ssh, ସଂରଚନା sshkey *ଚାବି)
{
	ସଂରଚନା sshkey *pubkey = ଖାଲି;
	ସଂରଚନା ଚାବି_entry *k = ଖାଲି, *k_prv = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (ssh->kex->server) {
		ଯଦି ((r = sshkey_from_private(ଚାବି, &pubkey)) != 0)
			ଫେରନ୍ତୁ r;
		ଯଦି ((k = malloc(ଆକାର(*k))) == ଖାଲି ||
		    (k_prv = malloc(ଆକାର(*k_prv))) == ଖାଲି) {
			ମୁକ୍ତ(k);
			sshkey_free(pubkey);
			ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
		}
		k_prv->ଚାବି = ଚାବି;
		TAILQ_INSERT_TAIL(&ssh->private_ଚାବିଗୁଡ଼ିକ, k_prv, next);

		/* add the public key, too */
		k->ଚାବି = pubkey;
		TAILQ_INSERT_TAIL(&ssh->public_ଚାବିଗୁଡ଼ିକ, k, next);
		r = 0;
	} ଅନ୍ୟଥା {
		ଯଦି ((k = malloc(ଆକାର(*k))) == ଖାଲି)
			ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
		k->ଚାବି = ଚାବି;
		TAILQ_INSERT_TAIL(&ssh->public_ଚାବିଗୁଡ଼ିକ, k, next);
		r = 0;
	}

	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_set_verify_host_ଚାବି_callback(ସଂରଚନା ssh *ssh,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*cb)(ସଂରଚନା sshkey *, ସଂରଚନା ssh *))
{
	ଯଦି (cb == ଖାଲି || ssh->kex == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;

	ssh->kex->verify_host_ଚାବି = cb;

	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ନିବେଶ_append(ସଂରଚନା ssh *ssh, ଅଚଳ u_char *data, size_t len)
{
	ଫେରନ୍ତୁ sshbuf_put(ssh_packet_get_ନିବେଶ(ssh), data, len);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_next(ସଂରଚନା ssh *ssh, u_char *typep)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_ସନ୍ଦେଶ_NONE;
	ଯଦି (sshbuf_len(ssh->kex->client_version) == 0 ||
	    sshbuf_len(ssh->kex->server_version) == 0)
		ଫେରନ୍ତୁ _ssh_exchange_banner(ssh);
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
	ପାଇଁ (;;) {
		ଯଦି ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			ଫେରନ୍ତୁ r;
		ଯଦି (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_ସନ୍ଦେଶ_KEXINIT && type <= SSH2_ସନ୍ଦେଶ_TRANSPORT_MAX &&
		    ssh->dispatch[type] != ଖାଲି) {
			ଯଦି ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				ଫେରନ୍ତୁ r;
		} ଅନ୍ୟଥା {
			*typep = type;
			ଫେରନ୍ତୁ 0;
		}
	}
}

ଅଚଳ u_char *
ssh_packet_payload(ସଂରଚନା ssh *ssh, size_t *lenp)
{
	ଫେରନ୍ତୁ sshpkt_ptr(ssh, lenp);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_packet_put(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ଅଚଳ u_char *data, size_t len)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshpkt_start(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, data, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ 0;
}

ଅଚଳ u_char *
ssh_output_ptr(ସଂରଚନା ssh *ssh, size_t *len)
{
	ସଂରଚନା sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	ଫେରନ୍ତୁ sshbuf_ptr(output);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_output_consume(ସଂରଚନା ssh *ssh, size_t len)
{
	ଫେରନ୍ତୁ sshbuf_consume(ssh_packet_get_output(ssh), len);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_output_space(ସଂରଚନା ssh *ssh, size_t len)
{
	ଫେରନ୍ତୁ (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ନିବେଶ_space(ସଂରଚନା ssh *ssh, size_t len)
{
	ଫେରନ୍ତୁ (0 == sshbuf_check_reserve(ssh_packet_get_ନିବେଶ(ssh), len));
}

/* Read other side's version identification. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
_ssh_read_banner(ସଂରଚନା ssh *ssh, ସଂରଚନା sshbuf *banner)
{
	ସଂରଚନା sshbuf *ନିବେଶ = ssh_packet_get_ନିବେଶ(ssh);
	ଅଚଳ ଅକ୍ଷର *mismatch = "Protocol mismatch.\r\n";
	ଅଚଳ u_char *s = sshbuf_ptr(ନିବେଶ);
	u_char c;
	ଅକ୍ଷର *cp = ଖାଲି, *remote_version = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = 0, remote_major, remote_minor, expect_nl;
	size_t n, j;

	ପାଇଁ (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		ପାଇଁ (;;) {
			ଯଦି (j >= sshbuf_len(ନିବେଶ))
				ଫେରନ୍ତୁ 0; /* insufficient data in input buf */
			c = s[j++];
			ଯଦି (c == '\r') {
				expect_nl = 1;
				ଜାରି;
			}
			ଯଦି (c == '\n')
				ଭାଙ୍ଗ;
			ଯଦି (expect_nl)
				ଯାଅ bad;
			ଯଦି ((r = sshbuf_put_u8(banner, c)) != 0)
				ଫେରନ୍ତୁ r;
			ଯଦି (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				ଯାଅ bad;
		}
		ଯଦି (sshbuf_len(banner) >= 4 &&
		    memcmp(sshbuf_ptr(banner), "SSH-", 4) == 0)
			ଭାଙ୍ଗ;
		debug_f("%.*s", (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		ଯଦି (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_ଧାଡ଼ିଗୁଡ଼ିକ) {
  bad:
			ଯଦି ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, strlen(mismatch))) != 0)
				ଫେରନ୍ତୁ r;
			ଫେରନ୍ତୁ SSH_ERR_NO_PROTOCOL_VERSION;
		}
	}
	ଯଦି ((r = sshbuf_consume(ନିବେଶ, j)) != 0)
		ଫେରନ୍ତୁ r;

	/* XXX remote version must be the same size as banner for sscanf */
	ଯଦି ((cp = sshbuf_dup_string(banner)) == ଖାଲି ||
	    (remote_version = calloc(1, sshbuf_len(banner))) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	ଯଦି (sscanf(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);

	compat_banner(ssh, remote_version);
	ଯଦି  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	ଯଦି (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 out:
	ମୁକ୍ତ(cp);
	ମୁକ୍ତ(remote_version);
	ଫେରନ୍ତୁ r;
}

/* Send our own protocol version identification. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
_ssh_send_banner(ସଂରଚନା ssh *ssh, ସଂରଚନା sshbuf *banner)
{
	ଅକ୍ଷର *cp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_VERSION)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		ଫେରନ୍ତୁ r;
	/* Remove trailing \r\n */
	ଯଦି ((r = sshbuf_consume_end(banner, 2)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((cp = sshbuf_dup_string(banner)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	ମୁକ୍ତ(cp);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
_ssh_exchange_banner(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା kex *kex = ssh->kex;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */

	r = 0;
	ଯଦି (kex->server) {
		ଯଦି (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_version);
		ଯଦି (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_version);
	} ଅନ୍ୟଥା {
		ଯଦି (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_version);
		ଯଦି (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_version);
	}
	ଯଦି (r != 0)
		ଫେରନ୍ତୁ r;
	/* start initial kex as soon as we have exchanged the banners */
	ଯଦି (sshbuf_len(ssh->kex->server_version) != 0 &&
	    sshbuf_len(ssh->kex->client_version) != 0) {
		ଯଦି ((r = _ssh_order_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			ଫେରନ୍ତୁ r;
	}
	ଫେରନ୍ତୁ 0;
}

ସଂରଚନା sshkey *
ssh_host_public_ଚାବି(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ପୂର୍ଣ୍ଣସଂଖ୍ୟା nid, ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା ଚାବି_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->public_ଚାବିଗୁଡ଼ିକ, next) {
		debug3_f("check %s", sshkey_type(k->ଚାବି));
		ଯଦି (k->ଚାବି->type == type &&
		    (type != ଚାବି_ECDSA || k->ଚାବି->ecdsa_nid == nid))
			ଫେରନ୍ତୁ (k->ଚାବି);
	}
	ଫେରନ୍ତୁ (ଖାଲି);
}

ସଂରଚନା sshkey *
ssh_host_private_ଚାବି(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ପୂର୍ଣ୍ଣସଂଖ୍ୟା nid, ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା ଚାବି_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->private_ଚାବିଗୁଡ଼ିକ, next) {
		debug3_f("check %s", sshkey_type(k->ଚାବି));
		ଯଦି (k->ଚାବି->type == type &&
		    (type != ଚାବି_ECDSA || k->ଚାବି->ecdsa_nid == nid))
			ଫେରନ୍ତୁ (k->ଚାବି);
	}
	ଫେରନ୍ତୁ (ଖାଲି);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_verify_host_ଚାବି(ସଂରଚନା sshkey *hostkey, ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା ଚାବି_entry *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->public_ଚାବିଗୁଡ଼ିକ, next) {
		debug3_f("check %s", sshkey_type(k->ଚାବି));
		ଯଦି (sshkey_equal_public(hostkey, k->ଚାବି))
			ଫେରନ୍ତୁ (0);	/* ok */
	}
	ଫେରନ୍ତୁ (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
_ssh_order_hostkeyalgs(ସଂରଚନା ssh *ssh)
{
	ସଂରଚନା ଚାବି_entry *k;
	ଅକ୍ଷର *orig, *avail, *oavail = ଖାଲି, *alg, *replace = ଖାଲି;
	ଅକ୍ଷର **proposal;
	size_t maxlen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	ଯଦି ((r = kex_buf2prop(ssh->kex->my, ଖାଲି, &proposal)) != 0)
		ଫେରନ୍ତୁ r;
	orig = proposal[PROPOSAL_SERVER_HOST_ଚାବି_ALGS];
	ଯଦି ((oavail = avail = strdup(orig)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	maxlen = strlen(avail) + 1;
	ଯଦି ((replace = calloc(1, maxlen)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	*replace = '\0';
	ଯେତେବେଳେ ((alg = strsep(&avail, ",")) && *alg != '\0') {
		ଯଦି ((ktype = sshkey_type_from_name(alg)) == ଚାବି_UNSPEC)
			ଜାରି;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->public_ଚାବିଗୁଡ଼ିକ, next) {
			ଯଦି (k->ଚାବି->type != ktype &&
			    (!sshkey_is_cert(k->ଚାବି) ||
			    k->ଚାବି->type != sshkey_type_plain(ktype)))
				ଜାରି;
			ଯଦି (sshkey_type_plain(k->ଚାବି->type) == ଚାବି_ECDSA &&
			    k->ଚାବି->ecdsa_nid != nid)
				ଜାରି;
			/* Candidate */
			ଯଦି (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			ଭାଙ୍ଗ;
		}
	}
	ଯଦି (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		ମୁକ୍ତ(orig);
		proposal[PROPOSAL_SERVER_HOST_ଚାବି_ALGS] = replace;
		replace = ଖାଲି;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 out:
	ମୁକ୍ତ(oavail);
	ମୁକ୍ତ(replace);
	kex_prop_free(proposal);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_host_ଚାବି_sign(ସଂରଚନା ssh *ssh, ସଂରଚନା sshkey *privkey,
    ସଂରଚନା sshkey *pubkey, u_char **signature, size_t *slen,
    ଅଚଳ u_char *data, size_t dlen, ଅଚଳ ଅକ୍ଷର *alg)
{
	ଫେରନ୍ତୁ sshkey_sign(privkey, signature, slen, data, dlen,
	    alg, ଖାଲି, ଖାଲି, ssh->compat);
}
