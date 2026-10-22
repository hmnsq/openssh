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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>

#அந்தர்பாவ "ssh_api.h"
#அந்தர்பாவ "compat.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "dh.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "ssh2.h"
#அந்தர்பாவ "version.h"
#அந்தர்பாவ "myproposal.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshbuf.h"

#அந்தர்பாவ "openbsd-compat/openssl-compat.h"

#அந்தர்பாவ <string.h>

முழு	_ssh_exchange_banner(கட்டமைப்பு ssh *);
முழு	_ssh_send_banner(கட்டமைப்பு ssh *, கட்டமைப்பு sshbuf *);
முழு	_ssh_read_banner(கட்டமைப்பு ssh *, கட்டமைப்பு sshbuf *);
முழு	_ssh_order_hostkeyalgs(கட்டமைப்பு ssh *);
முழு	ssh_verify_host_சாவி(கட்டமைப்பு sshkey *, கட்டமைப்பு ssh *);
கட்டமைப்பு sshkey *ssh_host_public_சாவி(முழு, முழு, கட்டமைப்பு ssh *);
கட்டமைப்பு sshkey *ssh_host_private_சாவி(முழு, முழு, கட்டமைப்பு ssh *);
முழு	ssh_host_சாவி_sign(கட்டமைப்பு ssh *, கட்டமைப்பு sshkey *, கட்டமைப்பு sshkey *,
    u_char **, size_t *, மாறிலி u_char *, size_t, மாறிலி எழுத்து *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
முழு	mm_sshkey_sign(கட்டமைப்பு sshkey *, u_char **, u_int *,
    மாறிலி u_char *, u_int, மாறிலி எழுத்து *, மாறிலி எழுத்து *, மாறிலி எழுத்து *, u_int);

#ifdef WITH_OPENSSL
DH	*mm_choose_dh(முழு, முழு, முழு);
#endif

முழு
mm_sshkey_sign(கட்டமைப்பு sshkey *சாவி, u_char **sigp, u_int *lenp,
    மாறிலி u_char *data, u_int datalen, மாறிலி எழுத்து *alg,
    மாறிலி எழுத்து *sk_provider, மாறிலி எழுத்து *sk_pin, u_int compat)
{
	size_t slen = 0;
	முழு ret;

	ret = sshkey_sign(சாவி, sigp, &slen, data, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	திரும்பு ret;
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(முழு min, முழு nbits, முழு max)
{
	திரும்பு choose_dh(min, nbits, max);
}
#endif

/* API */

முழு
ssh_init(கட்டமைப்பு ssh **sshp, முழு is_server, கட்டமைப்பு kex_params *kex_params)
{
	எழுத்து *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	எழுத்து *populated[PROPOSAL_MAX];
	கட்டமைப்பு ssh *ssh;
	எழுத்து **proposal;
	நிலையான முழு called;
	முழு r;

	எனில் (!called) {
		seed_rng();
		called = 1;
	}

	எனில் ((ssh = ssh_packet_set_connection(வெற்று, -1, -1)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் (is_server)
		ssh_packet_set_server(ssh);

	/* Initialize key exchange */
	proposal = kex_params ? kex_params->proposal : myproposal;
	kex_proposal_populate_entries(ssh, populated,
	    proposal[PROPOSAL_KEX_ALGS],
	    proposal[PROPOSAL_ENC_ALGS_CTOS],
	    proposal[PROPOSAL_MAC_ALGS_CTOS],
	    proposal[PROPOSAL_COMP_ALGS_CTOS],
	    proposal[PROPOSAL_SERVER_HOST_சாவி_ALGS]);
	r = kex_ready(ssh, populated);
	kex_proposal_free_entries(populated);
	எனில் (r != 0) {
		ssh_free(ssh);
		திரும்பு r;
	}

	ssh->kex->server = is_server;
	எனில் (is_server) {
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
		ssh->kex->load_host_public_சாவி=&ssh_host_public_சாவி;
		ssh->kex->load_host_private_சாவி=&ssh_host_private_சாவி;
		ssh->kex->sign=&ssh_host_சாவி_sign;
	} இல்லையெனில் {
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
		ssh->kex->verify_host_சாவி =&ssh_verify_host_சாவி;
	}
	*sshp = ssh;
	திரும்பு 0;
}

வெறுமை
ssh_free(கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு சாவி_entry *k;

	எனில் (ssh == வெற்று)
		திரும்பு;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	போது ((k = TAILQ_FIRST(&ssh->public_சாவிகள்)) != வெற்று) {
		TAILQ_REMOVE(&ssh->public_சாவிகள், k, next);
		எனில் (ssh->kex && ssh->kex->server)
			sshkey_free(k->சாவி);
		விடுவி(k);
	}
	போது ((k = TAILQ_FIRST(&ssh->private_சாவிகள்)) != வெற்று) {
		TAILQ_REMOVE(&ssh->private_சாவிகள், k, next);
		விடுவி(k);
	}
	ssh_packet_close(ssh);
	விடுவி(ssh);
}

வெறுமை
ssh_set_app_data(கட்டமைப்பு ssh *ssh, வெறுமை *app_data)
{
	ssh->app_data = app_data;
}

வெறுமை *
ssh_get_app_data(கட்டமைப்பு ssh *ssh)
{
	திரும்பு ssh->app_data;
}

/* Returns < 0 on error, 0 otherwise */
முழு
ssh_add_hostkey(கட்டமைப்பு ssh *ssh, கட்டமைப்பு sshkey *சாவி)
{
	கட்டமைப்பு sshkey *pubkey = வெற்று;
	கட்டமைப்பு சாவி_entry *k = வெற்று, *k_prv = வெற்று;
	முழு r;

	எனில் (ssh->kex->server) {
		எனில் ((r = sshkey_from_private(சாவி, &pubkey)) != 0)
			திரும்பு r;
		எனில் ((k = malloc(அளவு(*k))) == வெற்று ||
		    (k_prv = malloc(அளவு(*k_prv))) == வெற்று) {
			விடுவி(k);
			sshkey_free(pubkey);
			திரும்பு SSH_ERR_ALLOC_FAIL;
		}
		k_prv->சாவி = சாவி;
		TAILQ_INSERT_TAIL(&ssh->private_சாவிகள், k_prv, next);

		/* add the public key, too */
		k->சாவி = pubkey;
		TAILQ_INSERT_TAIL(&ssh->public_சாவிகள், k, next);
		r = 0;
	} இல்லையெனில் {
		எனில் ((k = malloc(அளவு(*k))) == வெற்று)
			திரும்பு SSH_ERR_ALLOC_FAIL;
		k->சாவி = சாவி;
		TAILQ_INSERT_TAIL(&ssh->public_சாவிகள், k, next);
		r = 0;
	}

	திரும்பு r;
}

முழு
ssh_set_verify_host_சாவி_callback(கட்டமைப்பு ssh *ssh,
    முழு (*cb)(கட்டமைப்பு sshkey *, கட்டமைப்பு ssh *))
{
	எனில் (cb == வெற்று || ssh->kex == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;

	ssh->kex->verify_host_சாவி = cb;

	திரும்பு 0;
}

முழு
ssh_உள்ளீடு_append(கட்டமைப்பு ssh *ssh, மாறிலி u_char *data, size_t len)
{
	திரும்பு sshbuf_put(ssh_packet_get_உள்ளீடு(ssh), data, len);
}

முழு
ssh_packet_next(கட்டமைப்பு ssh *ssh, u_char *typep)
{
	முழு r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_செய்தி_NONE;
	எனில் (sshbuf_len(ssh->kex->client_version) == 0 ||
	    sshbuf_len(ssh->kex->server_version) == 0)
		திரும்பு _ssh_exchange_banner(ssh);
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
	க்கு (;;) {
		எனில் ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			திரும்பு r;
		எனில் (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_செய்தி_KEXINIT && type <= SSH2_செய்தி_TRANSPORT_MAX &&
		    ssh->dispatch[type] != வெற்று) {
			எனில் ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				திரும்பு r;
		} இல்லையெனில் {
			*typep = type;
			திரும்பு 0;
		}
	}
}

மாறிலி u_char *
ssh_packet_payload(கட்டமைப்பு ssh *ssh, size_t *lenp)
{
	திரும்பு sshpkt_ptr(ssh, lenp);
}

முழு
ssh_packet_put(கட்டமைப்பு ssh *ssh, முழு type, மாறிலி u_char *data, size_t len)
{
	முழு r;

	எனில் ((r = sshpkt_start(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, data, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		திரும்பு r;
	திரும்பு 0;
}

மாறிலி u_char *
ssh_output_ptr(கட்டமைப்பு ssh *ssh, size_t *len)
{
	கட்டமைப்பு sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	திரும்பு sshbuf_ptr(output);
}

முழு
ssh_output_consume(கட்டமைப்பு ssh *ssh, size_t len)
{
	திரும்பு sshbuf_consume(ssh_packet_get_output(ssh), len);
}

முழு
ssh_output_space(கட்டமைப்பு ssh *ssh, size_t len)
{
	திரும்பு (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

முழு
ssh_உள்ளீடு_space(கட்டமைப்பு ssh *ssh, size_t len)
{
	திரும்பு (0 == sshbuf_check_reserve(ssh_packet_get_உள்ளீடு(ssh), len));
}

/* Read other side's version identification. */
முழு
_ssh_read_banner(கட்டமைப்பு ssh *ssh, கட்டமைப்பு sshbuf *banner)
{
	கட்டமைப்பு sshbuf *உள்ளீடு = ssh_packet_get_உள்ளீடு(ssh);
	மாறிலி எழுத்து *mismatch = "Protocol mismatch.\r\n";
	மாறிலி u_char *s = sshbuf_ptr(உள்ளீடு);
	u_char c;
	எழுத்து *cp = வெற்று, *remote_version = வெற்று;
	முழு r = 0, remote_major, remote_minor, expect_nl;
	size_t n, j;

	க்கு (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		க்கு (;;) {
			எனில் (j >= sshbuf_len(உள்ளீடு))
				திரும்பு 0; /* insufficient data in input buf */
			c = s[j++];
			எனில் (c == '\r') {
				expect_nl = 1;
				தொடர்;
			}
			எனில் (c == '\n')
				நிறுத்து;
			எனில் (expect_nl)
				செல் bad;
			எனில் ((r = sshbuf_put_u8(banner, c)) != 0)
				திரும்பு r;
			எனில் (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				செல் bad;
		}
		எனில் (sshbuf_len(banner) >= 4 &&
		    memcmp(sshbuf_ptr(banner), "SSH-", 4) == 0)
			நிறுத்து;
		debug_f("%.*s", (முழு)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		எனில் (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_வரிகள்) {
  bad:
			எனில் ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, strlen(mismatch))) != 0)
				திரும்பு r;
			திரும்பு SSH_ERR_NO_PROTOCOL_VERSION;
		}
	}
	எனில் ((r = sshbuf_consume(உள்ளீடு, j)) != 0)
		திரும்பு r;

	/* XXX remote version must be the same size as banner for sscanf */
	எனில் ((cp = sshbuf_dup_string(banner)) == வெற்று ||
	    (remote_version = calloc(1, sshbuf_len(banner))) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	எனில் (sscanf(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);

	compat_banner(ssh, remote_version);
	எனில்  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	எனில் (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 out:
	விடுவி(cp);
	விடுவி(remote_version);
	திரும்பு r;
}

/* Send our own protocol version identification. */
முழு
_ssh_send_banner(கட்டமைப்பு ssh *ssh, கட்டமைப்பு sshbuf *banner)
{
	எழுத்து *cp;
	முழு r;

	எனில் ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_VERSION)) != 0)
		திரும்பு r;
	எனில் ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		திரும்பு r;
	/* Remove trailing \r\n */
	எனில் ((r = sshbuf_consume_end(banner, 2)) != 0)
		திரும்பு r;
	எனில் ((cp = sshbuf_dup_string(banner)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	விடுவி(cp);
	திரும்பு 0;
}

முழு
_ssh_exchange_banner(கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு kex *kex = ssh->kex;
	முழு r;

	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */

	r = 0;
	எனில் (kex->server) {
		எனில் (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_version);
		எனில் (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_version);
	} இல்லையெனில் {
		எனில் (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_version);
		எனில் (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_version);
	}
	எனில் (r != 0)
		திரும்பு r;
	/* start initial kex as soon as we have exchanged the banners */
	எனில் (sshbuf_len(ssh->kex->server_version) != 0 &&
	    sshbuf_len(ssh->kex->client_version) != 0) {
		எனில் ((r = _ssh_order_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			திரும்பு r;
	}
	திரும்பு 0;
}

கட்டமைப்பு sshkey *
ssh_host_public_சாவி(முழு type, முழு nid, கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு சாவி_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->public_சாவிகள், next) {
		debug3_f("check %s", sshkey_type(k->சாவி));
		எனில் (k->சாவி->type == type &&
		    (type != சாவி_ECDSA || k->சாவி->ecdsa_nid == nid))
			திரும்பு (k->சாவி);
	}
	திரும்பு (வெற்று);
}

கட்டமைப்பு sshkey *
ssh_host_private_சாவி(முழு type, முழு nid, கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு சாவி_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->private_சாவிகள், next) {
		debug3_f("check %s", sshkey_type(k->சாவி));
		எனில் (k->சாவி->type == type &&
		    (type != சாவி_ECDSA || k->சாவி->ecdsa_nid == nid))
			திரும்பு (k->சாவி);
	}
	திரும்பு (வெற்று);
}

முழு
ssh_verify_host_சாவி(கட்டமைப்பு sshkey *hostkey, கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு சாவி_entry *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->public_சாவிகள், next) {
		debug3_f("check %s", sshkey_type(k->சாவி));
		எனில் (sshkey_equal_public(hostkey, k->சாவி))
			திரும்பு (0);	/* ok */
	}
	திரும்பு (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
முழு
_ssh_order_hostkeyalgs(கட்டமைப்பு ssh *ssh)
{
	கட்டமைப்பு சாவி_entry *k;
	எழுத்து *orig, *avail, *oavail = வெற்று, *alg, *replace = வெற்று;
	எழுத்து **proposal;
	size_t maxlen;
	முழு ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	எனில் ((r = kex_buf2prop(ssh->kex->my, வெற்று, &proposal)) != 0)
		திரும்பு r;
	orig = proposal[PROPOSAL_SERVER_HOST_சாவி_ALGS];
	எனில் ((oavail = avail = strdup(orig)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	maxlen = strlen(avail) + 1;
	எனில் ((replace = calloc(1, maxlen)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	*replace = '\0';
	போது ((alg = strsep(&avail, ",")) && *alg != '\0') {
		எனில் ((ktype = sshkey_type_from_name(alg)) == சாவி_UNSPEC)
			தொடர்;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->public_சாவிகள், next) {
			எனில் (k->சாவி->type != ktype &&
			    (!sshkey_is_cert(k->சாவி) ||
			    k->சாவி->type != sshkey_type_plain(ktype)))
				தொடர்;
			எனில் (sshkey_type_plain(k->சாவி->type) == சாவி_ECDSA &&
			    k->சாவி->ecdsa_nid != nid)
				தொடர்;
			/* Candidate */
			எனில் (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			நிறுத்து;
		}
	}
	எனில் (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		விடுவி(orig);
		proposal[PROPOSAL_SERVER_HOST_சாவி_ALGS] = replace;
		replace = வெற்று;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 out:
	விடுவி(oavail);
	விடுவி(replace);
	kex_prop_free(proposal);
	திரும்பு r;
}

முழு
ssh_host_சாவி_sign(கட்டமைப்பு ssh *ssh, கட்டமைப்பு sshkey *privkey,
    கட்டமைப்பு sshkey *pubkey, u_char **signature, size_t *slen,
    மாறிலி u_char *data, size_t dlen, மாறிலி எழுத்து *alg)
{
	திரும்பு sshkey_sign(privkey, signature, slen, data, dlen,
	    alg, வெற்று, வெற்று, ssh->compat);
}
