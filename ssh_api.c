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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>

#અન્તર્ભાવ "ssh_api.h"
#અન્તર્ભાવ "compat.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "dh.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "version.h"
#અન્તર્ભાવ "myproposal.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"

#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"

#અન્તર્ભાવ <string.h>

પૂર્ણાંક	_ssh_exchange_banner(સંરચના ssh *);
પૂર્ણાંક	_ssh_send_banner(સંરચના ssh *, સંરચના sshbuf *);
પૂર્ણાંક	_ssh_read_banner(સંરચના ssh *, સંરચના sshbuf *);
પૂર્ણાંક	_ssh_order_hostkeyalgs(સંરચના ssh *);
પૂર્ણાંક	ssh_verify_host_ચાવી(સંરચના sshkey *, સંરચના ssh *);
સંરચના sshkey *ssh_host_public_ચાવી(પૂર્ણાંક, પૂર્ણાંક, સંરચના ssh *);
સંરચના sshkey *ssh_host_private_ચાવી(પૂર્ણાંક, પૂર્ણાંક, સંરચના ssh *);
પૂર્ણાંક	ssh_host_ચાવી_sign(સંરચના ssh *, સંરચના sshkey *, સંરચના sshkey *,
    u_char **, size_t *, અચલ u_char *, size_t, અચલ અક્ષર *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
પૂર્ણાંક	mm_sshkey_sign(સંરચના sshkey *, u_char **, u_int *,
    અચલ u_char *, u_int, અચલ અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *, u_int);

#ifdef WITH_OPENSSL
DH	*mm_choose_dh(પૂર્ણાંક, પૂર્ણાંક, પૂર્ણાંક);
#endif

પૂર્ણાંક
mm_sshkey_sign(સંરચના sshkey *ચાવી, u_char **sigp, u_int *lenp,
    અચલ u_char *data, u_int datalen, અચલ અક્ષર *alg,
    અચલ અક્ષર *sk_provider, અચલ અક્ષર *sk_pin, u_int compat)
{
	size_t slen = 0;
	પૂર્ણાંક ret;

	ret = sshkey_sign(ચાવી, sigp, &slen, data, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	પાછા ret;
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(પૂર્ણાંક min, પૂર્ણાંક nbits, પૂર્ણાંક max)
{
	પાછા choose_dh(min, nbits, max);
}
#endif

/* API */

પૂર્ણાંક
ssh_init(સંરચના ssh **sshp, પૂર્ણાંક is_server, સંરચના kex_params *kex_params)
{
	અક્ષર *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	અક્ષર *populated[PROPOSAL_MAX];
	સંરચના ssh *ssh;
	અક્ષર **proposal;
	સ્થિર પૂર્ણાંક called;
	પૂર્ણાંક r;

	જો (!called) {
		seed_rng();
		called = 1;
	}

	જો ((ssh = ssh_packet_set_connection(ખાલી, -1, -1)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો (is_server)
		ssh_packet_set_server(ssh);

	/* Initialize key exchange */
	proposal = kex_params ? kex_params->proposal : myproposal;
	kex_proposal_populate_entries(ssh, populated,
	    proposal[PROPOSAL_KEX_ALGS],
	    proposal[PROPOSAL_ENC_ALGS_CTOS],
	    proposal[PROPOSAL_MAC_ALGS_CTOS],
	    proposal[PROPOSAL_COMP_ALGS_CTOS],
	    proposal[PROPOSAL_SERVER_HOST_ચાવી_ALGS]);
	r = kex_ready(ssh, populated);
	kex_proposal_free_entries(populated);
	જો (r != 0) {
		ssh_free(ssh);
		પાછા r;
	}

	ssh->kex->server = is_server;
	જો (is_server) {
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
		ssh->kex->load_host_public_ચાવી=&ssh_host_public_ચાવી;
		ssh->kex->load_host_private_ચાવી=&ssh_host_private_ચાવી;
		ssh->kex->sign=&ssh_host_ચાવી_sign;
	} નહીંતર {
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
		ssh->kex->verify_host_ચાવી =&ssh_verify_host_ચાવી;
	}
	*sshp = ssh;
	પાછા 0;
}

શૂન્ય
ssh_free(સંરચના ssh *ssh)
{
	સંરચના ચાવી_entry *k;

	જો (ssh == ખાલી)
		પાછા;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	જ્યારે ((k = TAILQ_FIRST(&ssh->public_ચાવીઓ)) != ખાલી) {
		TAILQ_REMOVE(&ssh->public_ચાવીઓ, k, next);
		જો (ssh->kex && ssh->kex->server)
			sshkey_free(k->ચાવી);
		મુક્ત(k);
	}
	જ્યારે ((k = TAILQ_FIRST(&ssh->private_ચાવીઓ)) != ખાલી) {
		TAILQ_REMOVE(&ssh->private_ચાવીઓ, k, next);
		મુક્ત(k);
	}
	ssh_packet_close(ssh);
	મુક્ત(ssh);
}

શૂન્ય
ssh_set_app_data(સંરચના ssh *ssh, શૂન્ય *app_data)
{
	ssh->app_data = app_data;
}

શૂન્ય *
ssh_get_app_data(સંરચના ssh *ssh)
{
	પાછા ssh->app_data;
}

/* Returns < 0 on error, 0 otherwise */
પૂર્ણાંક
ssh_add_hostkey(સંરચના ssh *ssh, સંરચના sshkey *ચાવી)
{
	સંરચના sshkey *pubkey = ખાલી;
	સંરચના ચાવી_entry *k = ખાલી, *k_prv = ખાલી;
	પૂર્ણાંક r;

	જો (ssh->kex->server) {
		જો ((r = sshkey_from_private(ચાવી, &pubkey)) != 0)
			પાછા r;
		જો ((k = malloc(કદ(*k))) == ખાલી ||
		    (k_prv = malloc(કદ(*k_prv))) == ખાલી) {
			મુક્ત(k);
			sshkey_free(pubkey);
			પાછા SSH_ERR_ALLOC_FAIL;
		}
		k_prv->ચાવી = ચાવી;
		TAILQ_INSERT_TAIL(&ssh->private_ચાવીઓ, k_prv, next);

		/* add the public key, too */
		k->ચાવી = pubkey;
		TAILQ_INSERT_TAIL(&ssh->public_ચાવીઓ, k, next);
		r = 0;
	} નહીંતર {
		જો ((k = malloc(કદ(*k))) == ખાલી)
			પાછા SSH_ERR_ALLOC_FAIL;
		k->ચાવી = ચાવી;
		TAILQ_INSERT_TAIL(&ssh->public_ચાવીઓ, k, next);
		r = 0;
	}

	પાછા r;
}

પૂર્ણાંક
ssh_set_verify_host_ચાવી_callback(સંરચના ssh *ssh,
    પૂર્ણાંક (*cb)(સંરચના sshkey *, સંરચના ssh *))
{
	જો (cb == ખાલી || ssh->kex == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;

	ssh->kex->verify_host_ચાવી = cb;

	પાછા 0;
}

પૂર્ણાંક
ssh_આગત_append(સંરચના ssh *ssh, અચલ u_char *data, size_t len)
{
	પાછા sshbuf_put(ssh_packet_get_આગત(ssh), data, len);
}

પૂર્ણાંક
ssh_packet_next(સંરચના ssh *ssh, u_char *typep)
{
	પૂર્ણાંક r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_સંદેશ_NONE;
	જો (sshbuf_len(ssh->kex->client_version) == 0 ||
	    sshbuf_len(ssh->kex->server_version) == 0)
		પાછા _ssh_exchange_banner(ssh);
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
	માટે (;;) {
		જો ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			પાછા r;
		જો (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_સંદેશ_KEXINIT && type <= SSH2_સંદેશ_TRANSPORT_MAX &&
		    ssh->dispatch[type] != ખાલી) {
			જો ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				પાછા r;
		} નહીંતર {
			*typep = type;
			પાછા 0;
		}
	}
}

અચલ u_char *
ssh_packet_payload(સંરચના ssh *ssh, size_t *lenp)
{
	પાછા sshpkt_ptr(ssh, lenp);
}

પૂર્ણાંક
ssh_packet_put(સંરચના ssh *ssh, પૂર્ણાંક type, અચલ u_char *data, size_t len)
{
	પૂર્ણાંક r;

	જો ((r = sshpkt_start(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, data, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		પાછા r;
	પાછા 0;
}

અચલ u_char *
ssh_output_ptr(સંરચના ssh *ssh, size_t *len)
{
	સંરચના sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	પાછા sshbuf_ptr(output);
}

પૂર્ણાંક
ssh_output_consume(સંરચના ssh *ssh, size_t len)
{
	પાછા sshbuf_consume(ssh_packet_get_output(ssh), len);
}

પૂર્ણાંક
ssh_output_space(સંરચના ssh *ssh, size_t len)
{
	પાછા (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

પૂર્ણાંક
ssh_આગત_space(સંરચના ssh *ssh, size_t len)
{
	પાછા (0 == sshbuf_check_reserve(ssh_packet_get_આગત(ssh), len));
}

/* Read other side's version identification. */
પૂર્ણાંક
_ssh_read_banner(સંરચના ssh *ssh, સંરચના sshbuf *banner)
{
	સંરચના sshbuf *આગત = ssh_packet_get_આગત(ssh);
	અચલ અક્ષર *mismatch = "Protocol mismatch.\r\n";
	અચલ u_char *s = sshbuf_ptr(આગત);
	u_char c;
	અક્ષર *cp = ખાલી, *remote_version = ખાલી;
	પૂર્ણાંક r = 0, remote_major, remote_minor, expect_nl;
	size_t n, j;

	માટે (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		માટે (;;) {
			જો (j >= sshbuf_len(આગત))
				પાછા 0; /* insufficient data in input buf */
			c = s[j++];
			જો (c == '\r') {
				expect_nl = 1;
				ચાલુ;
			}
			જો (c == '\n')
				તોડો;
			જો (expect_nl)
				જાઓ bad;
			જો ((r = sshbuf_put_u8(banner, c)) != 0)
				પાછા r;
			જો (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				જાઓ bad;
		}
		જો (sshbuf_len(banner) >= 4 &&
		    memcmp(sshbuf_ptr(banner), "SSH-", 4) == 0)
			તોડો;
		debug_f("%.*s", (પૂર્ણાંક)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		જો (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_લીટીઓ) {
  bad:
			જો ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, strlen(mismatch))) != 0)
				પાછા r;
			પાછા SSH_ERR_NO_PROTOCOL_VERSION;
		}
	}
	જો ((r = sshbuf_consume(આગત, j)) != 0)
		પાછા r;

	/* XXX remote version must be the same size as banner for sscanf */
	જો ((cp = sshbuf_dup_string(banner)) == ખાલી ||
	    (remote_version = calloc(1, sshbuf_len(banner))) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	જો (sscanf(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);

	compat_banner(ssh, remote_version);
	જો  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	જો (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 out:
	મુક્ત(cp);
	મુક્ત(remote_version);
	પાછા r;
}

/* Send our own protocol version identification. */
પૂર્ણાંક
_ssh_send_banner(સંરચના ssh *ssh, સંરચના sshbuf *banner)
{
	અક્ષર *cp;
	પૂર્ણાંક r;

	જો ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_VERSION)) != 0)
		પાછા r;
	જો ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		પાછા r;
	/* Remove trailing \r\n */
	જો ((r = sshbuf_consume_end(banner, 2)) != 0)
		પાછા r;
	જો ((cp = sshbuf_dup_string(banner)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	મુક્ત(cp);
	પાછા 0;
}

પૂર્ણાંક
_ssh_exchange_banner(સંરચના ssh *ssh)
{
	સંરચના kex *kex = ssh->kex;
	પૂર્ણાંક r;

	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */

	r = 0;
	જો (kex->server) {
		જો (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_version);
		જો (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_version);
	} નહીંતર {
		જો (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_version);
		જો (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_version);
	}
	જો (r != 0)
		પાછા r;
	/* start initial kex as soon as we have exchanged the banners */
	જો (sshbuf_len(ssh->kex->server_version) != 0 &&
	    sshbuf_len(ssh->kex->client_version) != 0) {
		જો ((r = _ssh_order_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			પાછા r;
	}
	પાછા 0;
}

સંરચના sshkey *
ssh_host_public_ચાવી(પૂર્ણાંક type, પૂર્ણાંક nid, સંરચના ssh *ssh)
{
	સંરચના ચાવી_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->public_ચાવીઓ, next) {
		debug3_f("check %s", sshkey_type(k->ચાવી));
		જો (k->ચાવી->type == type &&
		    (type != ચાવી_ECDSA || k->ચાવી->ecdsa_nid == nid))
			પાછા (k->ચાવી);
	}
	પાછા (ખાલી);
}

સંરચના sshkey *
ssh_host_private_ચાવી(પૂર્ણાંક type, પૂર્ણાંક nid, સંરચના ssh *ssh)
{
	સંરચના ચાવી_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->private_ચાવીઓ, next) {
		debug3_f("check %s", sshkey_type(k->ચાવી));
		જો (k->ચાવી->type == type &&
		    (type != ચાવી_ECDSA || k->ચાવી->ecdsa_nid == nid))
			પાછા (k->ચાવી);
	}
	પાછા (ખાલી);
}

પૂર્ણાંક
ssh_verify_host_ચાવી(સંરચના sshkey *hostkey, સંરચના ssh *ssh)
{
	સંરચના ચાવી_entry *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->public_ચાવીઓ, next) {
		debug3_f("check %s", sshkey_type(k->ચાવી));
		જો (sshkey_equal_public(hostkey, k->ચાવી))
			પાછા (0);	/* ok */
	}
	પાછા (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
પૂર્ણાંક
_ssh_order_hostkeyalgs(સંરચના ssh *ssh)
{
	સંરચના ચાવી_entry *k;
	અક્ષર *orig, *avail, *oavail = ખાલી, *alg, *replace = ખાલી;
	અક્ષર **proposal;
	size_t maxlen;
	પૂર્ણાંક ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	જો ((r = kex_buf2prop(ssh->kex->my, ખાલી, &proposal)) != 0)
		પાછા r;
	orig = proposal[PROPOSAL_SERVER_HOST_ચાવી_ALGS];
	જો ((oavail = avail = strdup(orig)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	maxlen = strlen(avail) + 1;
	જો ((replace = calloc(1, maxlen)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	*replace = '\0';
	જ્યારે ((alg = strsep(&avail, ",")) && *alg != '\0') {
		જો ((ktype = sshkey_type_from_name(alg)) == ચાવી_UNSPEC)
			ચાલુ;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->public_ચાવીઓ, next) {
			જો (k->ચાવી->type != ktype &&
			    (!sshkey_is_cert(k->ચાવી) ||
			    k->ચાવી->type != sshkey_type_plain(ktype)))
				ચાલુ;
			જો (sshkey_type_plain(k->ચાવી->type) == ચાવી_ECDSA &&
			    k->ચાવી->ecdsa_nid != nid)
				ચાલુ;
			/* Candidate */
			જો (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			તોડો;
		}
	}
	જો (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		મુક્ત(orig);
		proposal[PROPOSAL_SERVER_HOST_ચાવી_ALGS] = replace;
		replace = ખાલી;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 out:
	મુક્ત(oavail);
	મુક્ત(replace);
	kex_prop_free(proposal);
	પાછા r;
}

પૂર્ણાંક
ssh_host_ચાવી_sign(સંરચના ssh *ssh, સંરચના sshkey *privkey,
    સંરચના sshkey *pubkey, u_char **signature, size_t *slen,
    અચલ u_char *data, size_t dlen, અચલ અક્ષર *alg)
{
	પાછા sshkey_sign(privkey, signature, slen, data, dlen,
	    alg, ખાલી, ખાલી, ssh->compat);
}
