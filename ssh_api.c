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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>

#অন্তর্ভাব "ssh_api.h"
#অন্তর্ভাব "compat.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "dh.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "ssh2.h"
#অন্তর্ভাব "version.h"
#অন্তর্ভাব "myproposal.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshbuf.h"

#অন্তর্ভাব "openbsd-compat/openssl-compat.h"

#অন্তর্ভাব <string.h>

পূর্ণাঙ্ক	_ssh_exchange_banner(সংরচনা ssh *);
পূর্ণাঙ্ক	_ssh_send_banner(সংরচনা ssh *, সংরচনা sshbuf *);
পূর্ণাঙ্ক	_ssh_read_banner(সংরচনা ssh *, সংরচনা sshbuf *);
পূর্ণাঙ্ক	_ssh_order_hostkeyalgs(সংরচনা ssh *);
পূর্ণাঙ্ক	ssh_verify_host_চাবি(সংরচনা sshkey *, সংরচনা ssh *);
সংরচনা sshkey *ssh_host_public_চাবি(পূর্ণাঙ্ক, পূর্ণাঙ্ক, সংরচনা ssh *);
সংরচনা sshkey *ssh_host_private_চাবি(পূর্ণাঙ্ক, পূর্ণাঙ্ক, সংরচনা ssh *);
পূর্ণাঙ্ক	ssh_host_চাবি_sign(সংরচনা ssh *, সংরচনা sshkey *, সংরচনা sshkey *,
    u_char **, size_t *, ধ্রুব u_char *, size_t, ধ্রুব বর্ণ *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
পূর্ণাঙ্ক	mm_sshkey_sign(সংরচনা sshkey *, u_char **, u_int *,
    ধ্রুব u_char *, u_int, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, ধ্রুব বর্ণ *, u_int);

#ifdef WITH_OPENSSL
DH	*mm_choose_dh(পূর্ণাঙ্ক, পূর্ণাঙ্ক, পূর্ণাঙ্ক);
#endif

পূর্ণাঙ্ক
mm_sshkey_sign(সংরচনা sshkey *চাবি, u_char **sigp, u_int *lenp,
    ধ্রুব u_char *data, u_int datalen, ধ্রুব বর্ণ *alg,
    ধ্রুব বর্ণ *sk_provider, ধ্রুব বর্ণ *sk_pin, u_int compat)
{
	size_t slen = 0;
	পূর্ণাঙ্ক ret;

	ret = sshkey_sign(চাবি, sigp, &slen, data, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	প্রত্যাগম ret;
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(পূর্ণাঙ্ক min, পূর্ণাঙ্ক nbits, পূর্ণাঙ্ক max)
{
	প্রত্যাগম choose_dh(min, nbits, max);
}
#endif

/* API */

পূর্ণাঙ্ক
ssh_init(সংরচনা ssh **sshp, পূর্ণাঙ্ক is_server, সংরচনা kex_params *kex_params)
{
	বর্ণ *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	বর্ণ *populated[PROPOSAL_MAX];
	সংরচনা ssh *ssh;
	বর্ণ **proposal;
	স্থির পূর্ণাঙ্ক called;
	পূর্ণাঙ্ক r;

	যদি (!called) {
		seed_rng();
		called = 1;
	}

	যদি ((ssh = ssh_packet_set_connection(রিক্ত, -1, -1)) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি (is_server)
		ssh_packet_set_server(ssh);

	/* Initialize key exchange */
	proposal = kex_params ? kex_params->proposal : myproposal;
	kex_proposal_populate_entries(ssh, populated,
	    proposal[PROPOSAL_KEX_ALGS],
	    proposal[PROPOSAL_ENC_ALGS_CTOS],
	    proposal[PROPOSAL_MAC_ALGS_CTOS],
	    proposal[PROPOSAL_COMP_ALGS_CTOS],
	    proposal[PROPOSAL_SERVER_HOST_চাবি_ALGS]);
	r = kex_ready(ssh, populated);
	kex_proposal_free_entries(populated);
	যদি (r != 0) {
		ssh_free(ssh);
		প্রত্যাগম r;
	}

	ssh->kex->server = is_server;
	যদি (is_server) {
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
		ssh->kex->load_host_public_চাবি=&ssh_host_public_চাবি;
		ssh->kex->load_host_private_চাবি=&ssh_host_private_চাবি;
		ssh->kex->sign=&ssh_host_চাবি_sign;
	} অন্যথা {
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
		ssh->kex->verify_host_চাবি =&ssh_verify_host_চাবি;
	}
	*sshp = ssh;
	প্রত্যাগম 0;
}

শূন্য
ssh_free(সংরচনা ssh *ssh)
{
	সংরচনা চাবি_entry *k;

	যদি (ssh == রিক্ত)
		প্রত্যাগম;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	যাবত্ ((k = TAILQ_FIRST(&ssh->public_চাবিগুলি)) != রিক্ত) {
		TAILQ_REMOVE(&ssh->public_চাবিগুলি, k, next);
		যদি (ssh->kex && ssh->kex->server)
			sshkey_free(k->চাবি);
		মুক্ত(k);
	}
	যাবত্ ((k = TAILQ_FIRST(&ssh->private_চাবিগুলি)) != রিক্ত) {
		TAILQ_REMOVE(&ssh->private_চাবিগুলি, k, next);
		মুক্ত(k);
	}
	ssh_packet_close(ssh);
	মুক্ত(ssh);
}

শূন্য
ssh_set_app_data(সংরচনা ssh *ssh, শূন্য *app_data)
{
	ssh->app_data = app_data;
}

শূন্য *
ssh_get_app_data(সংরচনা ssh *ssh)
{
	প্রত্যাগম ssh->app_data;
}

/* Returns < 0 on error, 0 otherwise */
পূর্ণাঙ্ক
ssh_add_hostkey(সংরচনা ssh *ssh, সংরচনা sshkey *চাবি)
{
	সংরচনা sshkey *pubkey = রিক্ত;
	সংরচনা চাবি_entry *k = রিক্ত, *k_prv = রিক্ত;
	পূর্ণাঙ্ক r;

	যদি (ssh->kex->server) {
		যদি ((r = sshkey_from_private(চাবি, &pubkey)) != 0)
			প্রত্যাগম r;
		যদি ((k = malloc(পরিমাণ(*k))) == রিক্ত ||
		    (k_prv = malloc(পরিমাণ(*k_prv))) == রিক্ত) {
			মুক্ত(k);
			sshkey_free(pubkey);
			প্রত্যাগম SSH_ERR_ALLOC_FAIL;
		}
		k_prv->চাবি = চাবি;
		TAILQ_INSERT_TAIL(&ssh->private_চাবিগুলি, k_prv, next);

		/* add the public key, too */
		k->চাবি = pubkey;
		TAILQ_INSERT_TAIL(&ssh->public_চাবিগুলি, k, next);
		r = 0;
	} অন্যথা {
		যদি ((k = malloc(পরিমাণ(*k))) == রিক্ত)
			প্রত্যাগম SSH_ERR_ALLOC_FAIL;
		k->চাবি = চাবি;
		TAILQ_INSERT_TAIL(&ssh->public_চাবিগুলি, k, next);
		r = 0;
	}

	প্রত্যাগম r;
}

পূর্ণাঙ্ক
ssh_set_verify_host_চাবি_callback(সংরচনা ssh *ssh,
    পূর্ণাঙ্ক (*cb)(সংরচনা sshkey *, সংরচনা ssh *))
{
	যদি (cb == রিক্ত || ssh->kex == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;

	ssh->kex->verify_host_চাবি = cb;

	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
ssh_প্রবেশ_append(সংরচনা ssh *ssh, ধ্রুব u_char *data, size_t len)
{
	প্রত্যাগম sshbuf_put(ssh_packet_get_প্রবেশ(ssh), data, len);
}

পূর্ণাঙ্ক
ssh_packet_next(সংরচনা ssh *ssh, u_char *typep)
{
	পূর্ণাঙ্ক r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_বার্তা_NONE;
	যদি (sshbuf_len(ssh->kex->client_version) == 0 ||
	    sshbuf_len(ssh->kex->server_version) == 0)
		প্রত্যাগম _ssh_exchange_banner(ssh);
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
	প্রতি (;;) {
		যদি ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			প্রত্যাগম r;
		যদি (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_বার্তা_KEXINIT && type <= SSH2_বার্তা_TRANSPORT_MAX &&
		    ssh->dispatch[type] != রিক্ত) {
			যদি ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				প্রত্যাগম r;
		} অন্যথা {
			*typep = type;
			প্রত্যাগম 0;
		}
	}
}

ধ্রুব u_char *
ssh_packet_payload(সংরচনা ssh *ssh, size_t *lenp)
{
	প্রত্যাগম sshpkt_ptr(ssh, lenp);
}

পূর্ণাঙ্ক
ssh_packet_put(সংরচনা ssh *ssh, পূর্ণাঙ্ক type, ধ্রুব u_char *data, size_t len)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshpkt_start(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, data, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		প্রত্যাগম r;
	প্রত্যাগম 0;
}

ধ্রুব u_char *
ssh_output_ptr(সংরচনা ssh *ssh, size_t *len)
{
	সংরচনা sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	প্রত্যাগম sshbuf_ptr(output);
}

পূর্ণাঙ্ক
ssh_output_consume(সংরচনা ssh *ssh, size_t len)
{
	প্রত্যাগম sshbuf_consume(ssh_packet_get_output(ssh), len);
}

পূর্ণাঙ্ক
ssh_output_space(সংরচনা ssh *ssh, size_t len)
{
	প্রত্যাগম (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

পূর্ণাঙ্ক
ssh_প্রবেশ_space(সংরচনা ssh *ssh, size_t len)
{
	প্রত্যাগম (0 == sshbuf_check_reserve(ssh_packet_get_প্রবেশ(ssh), len));
}

/* Read other side's version identification. */
পূর্ণাঙ্ক
_ssh_read_banner(সংরচনা ssh *ssh, সংরচনা sshbuf *banner)
{
	সংরচনা sshbuf *প্রবেশ = ssh_packet_get_প্রবেশ(ssh);
	ধ্রুব বর্ণ *mismatch = "Protocol mismatch.\r\n";
	ধ্রুব u_char *s = sshbuf_ptr(প্রবেশ);
	u_char c;
	বর্ণ *cp = রিক্ত, *remote_version = রিক্ত;
	পূর্ণাঙ্ক r = 0, remote_major, remote_minor, expect_nl;
	size_t n, j;

	প্রতি (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		প্রতি (;;) {
			যদি (j >= sshbuf_len(প্রবেশ))
				প্রত্যাগম 0; /* insufficient data in input buf */
			c = s[j++];
			যদি (c == '\r') {
				expect_nl = 1;
				অনুবর্ত;
			}
			যদি (c == '\n')
				ভঙ্গ;
			যদি (expect_nl)
				গচ্ছ bad;
			যদি ((r = sshbuf_put_u8(banner, c)) != 0)
				প্রত্যাগম r;
			যদি (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				গচ্ছ bad;
		}
		যদি (sshbuf_len(banner) >= 4 &&
		    memcmp(sshbuf_ptr(banner), "SSH-", 4) == 0)
			ভঙ্গ;
		debug_f("%.*s", (পূর্ণাঙ্ক)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		যদি (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_সারিগুলি) {
  bad:
			যদি ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, strlen(mismatch))) != 0)
				প্রত্যাগম r;
			প্রত্যাগম SSH_ERR_NO_PROTOCOL_VERSION;
		}
	}
	যদি ((r = sshbuf_consume(প্রবেশ, j)) != 0)
		প্রত্যাগম r;

	/* XXX remote version must be the same size as banner for sscanf */
	যদি ((cp = sshbuf_dup_string(banner)) == রিক্ত ||
	    (remote_version = calloc(1, sshbuf_len(banner))) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	যদি (sscanf(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);

	compat_banner(ssh, remote_version);
	যদি  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	যদি (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 out:
	মুক্ত(cp);
	মুক্ত(remote_version);
	প্রত্যাগম r;
}

/* Send our own protocol version identification. */
পূর্ণাঙ্ক
_ssh_send_banner(সংরচনা ssh *ssh, সংরচনা sshbuf *banner)
{
	বর্ণ *cp;
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_VERSION)) != 0)
		প্রত্যাগম r;
	যদি ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		প্রত্যাগম r;
	/* Remove trailing \r\n */
	যদি ((r = sshbuf_consume_end(banner, 2)) != 0)
		প্রত্যাগম r;
	যদি ((cp = sshbuf_dup_string(banner)) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	মুক্ত(cp);
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
_ssh_exchange_banner(সংরচনা ssh *ssh)
{
	সংরচনা kex *kex = ssh->kex;
	পূর্ণাঙ্ক r;

	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */

	r = 0;
	যদি (kex->server) {
		যদি (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_version);
		যদি (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_version);
	} অন্যথা {
		যদি (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_version);
		যদি (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_version);
	}
	যদি (r != 0)
		প্রত্যাগম r;
	/* start initial kex as soon as we have exchanged the banners */
	যদি (sshbuf_len(ssh->kex->server_version) != 0 &&
	    sshbuf_len(ssh->kex->client_version) != 0) {
		যদি ((r = _ssh_order_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			প্রত্যাগম r;
	}
	প্রত্যাগম 0;
}

সংরচনা sshkey *
ssh_host_public_চাবি(পূর্ণাঙ্ক type, পূর্ণাঙ্ক nid, সংরচনা ssh *ssh)
{
	সংরচনা চাবি_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->public_চাবিগুলি, next) {
		debug3_f("check %s", sshkey_type(k->চাবি));
		যদি (k->চাবি->type == type &&
		    (type != চাবি_ECDSA || k->চাবি->ecdsa_nid == nid))
			প্রত্যাগম (k->চাবি);
	}
	প্রত্যাগম (রিক্ত);
}

সংরচনা sshkey *
ssh_host_private_চাবি(পূর্ণাঙ্ক type, পূর্ণাঙ্ক nid, সংরচনা ssh *ssh)
{
	সংরচনা চাবি_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->private_চাবিগুলি, next) {
		debug3_f("check %s", sshkey_type(k->চাবি));
		যদি (k->চাবি->type == type &&
		    (type != চাবি_ECDSA || k->চাবি->ecdsa_nid == nid))
			প্রত্যাগম (k->চাবি);
	}
	প্রত্যাগম (রিক্ত);
}

পূর্ণাঙ্ক
ssh_verify_host_চাবি(সংরচনা sshkey *hostkey, সংরচনা ssh *ssh)
{
	সংরচনা চাবি_entry *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->public_চাবিগুলি, next) {
		debug3_f("check %s", sshkey_type(k->চাবি));
		যদি (sshkey_equal_public(hostkey, k->চাবি))
			প্রত্যাগম (0);	/* ok */
	}
	প্রত্যাগম (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
পূর্ণাঙ্ক
_ssh_order_hostkeyalgs(সংরচনা ssh *ssh)
{
	সংরচনা চাবি_entry *k;
	বর্ণ *orig, *avail, *oavail = রিক্ত, *alg, *replace = রিক্ত;
	বর্ণ **proposal;
	size_t maxlen;
	পূর্ণাঙ্ক ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	যদি ((r = kex_buf2prop(ssh->kex->my, রিক্ত, &proposal)) != 0)
		প্রত্যাগম r;
	orig = proposal[PROPOSAL_SERVER_HOST_চাবি_ALGS];
	যদি ((oavail = avail = strdup(orig)) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	maxlen = strlen(avail) + 1;
	যদি ((replace = calloc(1, maxlen)) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	*replace = '\0';
	যাবত্ ((alg = strsep(&avail, ",")) && *alg != '\0') {
		যদি ((ktype = sshkey_type_from_name(alg)) == চাবি_UNSPEC)
			অনুবর্ত;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->public_চাবিগুলি, next) {
			যদি (k->চাবি->type != ktype &&
			    (!sshkey_is_cert(k->চাবি) ||
			    k->চাবি->type != sshkey_type_plain(ktype)))
				অনুবর্ত;
			যদি (sshkey_type_plain(k->চাবি->type) == চাবি_ECDSA &&
			    k->চাবি->ecdsa_nid != nid)
				অনুবর্ত;
			/* Candidate */
			যদি (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			ভঙ্গ;
		}
	}
	যদি (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		মুক্ত(orig);
		proposal[PROPOSAL_SERVER_HOST_চাবি_ALGS] = replace;
		replace = রিক্ত;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 out:
	মুক্ত(oavail);
	মুক্ত(replace);
	kex_prop_free(proposal);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
ssh_host_চাবি_sign(সংরচনা ssh *ssh, সংরচনা sshkey *privkey,
    সংরচনা sshkey *pubkey, u_char **signature, size_t *slen,
    ধ্রুব u_char *data, size_t dlen, ধ্রুব বর্ণ *alg)
{
	প্রত্যাগম sshkey_sign(privkey, signature, slen, data, dlen,
	    alg, রিক্ত, রিক্ত, ssh->compat);
}
