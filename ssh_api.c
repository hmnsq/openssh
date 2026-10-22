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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <stdio.h>
#ضمن <stdlib.h>

#ضمن "ssh_api.h"
#ضمن "compat.h"
#ضمن "log.h"
#ضمن "authfile.h"
#ضمن "sshkey.h"
#ضمن "dh.h"
#ضمن "misc.h"
#ضمن "ssh2.h"
#ضمن "version.h"
#ضمن "myproposal.h"
#ضمن "ssherr.h"
#ضمن "sshbuf.h"

#ضمن "openbsd-compat/openssl-compat.h"

#ضمن <string.h>

صحيح	_ssh_exchange_banner(بنية ssh *);
صحيح	_ssh_send_banner(بنية ssh *, بنية sshbuf *);
صحيح	_ssh_read_banner(بنية ssh *, بنية sshbuf *);
صحيح	_ssh_order_hostkeyalgs(بنية ssh *);
صحيح	_ssh_verify_host_key(بنية sshkey *, بنية ssh *);
بنية sshkey *_ssh_host_public_key(صحيح, صحيح, بنية ssh *);
بنية sshkey *_ssh_host_private_key(صحيح, صحيح, بنية ssh *);
صحيح	_ssh_host_key_sign(بنية ssh *, بنية sshkey *, بنية sshkey *,
    u_char **, size_t *, ثابت u_char *, size_t, ثابت حرف *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
صحيح	mm_sshkey_sign(بنية sshkey *, u_char **, u_int *,
    ثابت u_char *, u_int, ثابت حرف *, ثابت حرف *, ثابت حرف *, u_int);

#ifdef WITH_OPENSSL
DH	*mm_choose_dh(صحيح, صحيح, صحيح);
#endif

صحيح
mm_sshkey_sign(بنية sshkey *key, u_char **sigp, u_int *lenp,
    ثابت u_char *data, u_int datalen, ثابت حرف *alg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin, u_int compat)
{
	size_t slen = 0;
	صحيح ret;

	ret = sshkey_sign(key, sigp, &slen, data, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	أرجع ret;
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(صحيح min, صحيح nbits, صحيح max)
{
	أرجع choose_dh(min, nbits, max);
}
#endif

/* API */

صحيح
ssh_init(بنية ssh **sshp, صحيح is_server, بنية kex_params *kex_params)
{
	حرف *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	حرف *populated[PROPOSAL_MAX];
	بنية ssh *ssh;
	حرف **proposal;
	ساكن صحيح called;
	صحيح r;

	𐤀𐤌 (!called) {
		seed_rng();
		called = 1;
	}

	𐤀𐤌 ((ssh = ssh_packet_set_connection(عدم, -1, -1)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	𐤀𐤌 (is_server)
		ssh_packet_set_server(ssh);

	/* Initialize key exchange */
	proposal = kex_params ? kex_params->proposal : myproposal;
	kex_proposal_populate_entries(ssh, populated,
	    proposal[PROPOSAL_KEX_ALGS],
	    proposal[PROPOSAL_ENC_ALGS_CTOS],
	    proposal[PROPOSAL_MAC_ALGS_CTOS],
	    proposal[PROPOSAL_COMP_ALGS_CTOS],
	    proposal[PROPOSAL_SERVER_HOST_KEY_ALGS]);
	r = kex_ready(ssh, populated);
	kex_proposal_free_entries(populated);
	𐤀𐤌 (r != 0) {
		ssh_free(ssh);
		أرجع r;
	}

	ssh->kex->server = is_server;
	𐤀𐤌 (is_server) {
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
		ssh->kex->load_host_public_key=&_ssh_host_public_key;
		ssh->kex->load_host_private_key=&_ssh_host_private_key;
		ssh->kex->sign=&_ssh_host_key_sign;
	} وإلا {
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
		ssh->kex->verify_host_key =&_ssh_verify_host_key;
	}
	*sshp = ssh;
	أرجع 0;
}

فراغ
ssh_free(بنية ssh *ssh)
{
	بنية key_entry *k;

	𐤀𐤌 (ssh == عدم)
		أرجع;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	طالما ((k = TAILQ_FIRST(&ssh->public_keys)) != عدم) {
		TAILQ_REMOVE(&ssh->public_keys, k, next);
		𐤀𐤌 (ssh->kex && ssh->kex->server)
			sshkey_free(k->key);
		حرر(k);
	}
	طالما ((k = TAILQ_FIRST(&ssh->private_keys)) != عدم) {
		TAILQ_REMOVE(&ssh->private_keys, k, next);
		حرر(k);
	}
	ssh_packet_close(ssh);
	حرر(ssh);
}

فراغ
ssh_set_app_data(بنية ssh *ssh, فراغ *app_data)
{
	ssh->app_data = app_data;
}

فراغ *
ssh_get_app_data(بنية ssh *ssh)
{
	أرجع ssh->app_data;
}

/* Returns < 0 on error, 0 otherwise */
صحيح
ssh_add_hostkey(بنية ssh *ssh, بنية sshkey *key)
{
	بنية sshkey *pubkey = عدم;
	بنية key_entry *k = عدم, *k_prv = عدم;
	صحيح r;

	𐤀𐤌 (ssh->kex->server) {
		𐤀𐤌 ((r = sshkey_from_private(key, &pubkey)) != 0)
			أرجع r;
		𐤀𐤌 ((k = malloc(حجم(*k))) == عدم ||
		    (k_prv = malloc(حجم(*k_prv))) == عدم) {
			حرر(k);
			sshkey_free(pubkey);
			أرجع SSH_ERR_ALLOC_FAIL;
		}
		k_prv->key = key;
		TAILQ_INSERT_TAIL(&ssh->private_keys, k_prv, next);

		/* add the public key, too */
		k->key = pubkey;
		TAILQ_INSERT_TAIL(&ssh->public_keys, k, next);
		r = 0;
	} وإلا {
		𐤀𐤌 ((k = malloc(حجم(*k))) == عدم)
			أرجع SSH_ERR_ALLOC_FAIL;
		k->key = key;
		TAILQ_INSERT_TAIL(&ssh->public_keys, k, next);
		r = 0;
	}

	أرجع r;
}

صحيح
ssh_set_verify_host_key_callback(بنية ssh *ssh,
    صحيح (*cb)(بنية sshkey *, بنية ssh *))
{
	𐤀𐤌 (cb == عدم || ssh->kex == عدم)
		أرجع SSH_ERR_INVALID_ARGUMENT;

	ssh->kex->verify_host_key = cb;

	أرجع 0;
}

صحيح
ssh_input_append(بنية ssh *ssh, ثابت u_char *data, size_t len)
{
	أرجع sshbuf_put(ssh_packet_get_input(ssh), data, len);
}

صحيح
ssh_packet_next(بنية ssh *ssh, u_char *typep)
{
	صحيح r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_MSG_NONE;
	𐤀𐤌 (sshbuf_len(ssh->kex->client_version) == 0 ||
	    sshbuf_len(ssh->kex->server_version) == 0)
		أرجع _ssh_exchange_banner(ssh);
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
	لكل (;;) {
		𐤀𐤌 ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			أرجع r;
		𐤀𐤌 (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_MSG_KEXINIT && type <= SSH2_MSG_TRANSPORT_MAX &&
		    ssh->dispatch[type] != عدم) {
			𐤀𐤌 ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				أرجع r;
		} وإلا {
			*typep = type;
			أرجع 0;
		}
	}
}

ثابت u_char *
ssh_packet_payload(بنية ssh *ssh, size_t *lenp)
{
	أرجع sshpkt_ptr(ssh, lenp);
}

صحيح
ssh_packet_put(بنية ssh *ssh, صحيح type, ثابت u_char *data, size_t len)
{
	صحيح r;

	𐤀𐤌 ((r = sshpkt_start(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, data, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		أرجع r;
	أرجع 0;
}

ثابت u_char *
ssh_output_ptr(بنية ssh *ssh, size_t *len)
{
	بنية sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	أرجع sshbuf_ptr(output);
}

صحيح
ssh_output_consume(بنية ssh *ssh, size_t len)
{
	أرجع sshbuf_consume(ssh_packet_get_output(ssh), len);
}

صحيح
ssh_output_space(بنية ssh *ssh, size_t len)
{
	أرجع (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

صحيح
ssh_input_space(بنية ssh *ssh, size_t len)
{
	أرجع (0 == sshbuf_check_reserve(ssh_packet_get_input(ssh), len));
}

/* Read other side's version identification. */
صحيح
_ssh_read_banner(بنية ssh *ssh, بنية sshbuf *banner)
{
	بنية sshbuf *input = ssh_packet_get_input(ssh);
	ثابت حرف *mismatch = "Protocol mismatch.\r\n";
	ثابت u_char *s = sshbuf_ptr(input);
	u_char c;
	حرف *cp = عدم, *remote_version = عدم;
	صحيح r = 0, remote_major, remote_minor, expect_nl;
	size_t n, j;

	لكل (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		لكل (;;) {
			𐤀𐤌 (j >= sshbuf_len(input))
				أرجع 0; /* insufficient data in input buf */
			c = s[j++];
			𐤀𐤌 (c == '\r') {
				expect_nl = 1;
				استمر;
			}
			𐤀𐤌 (c == '\n')
				اكسر;
			𐤀𐤌 (expect_nl)
				اذهب bad;
			𐤀𐤌 ((r = sshbuf_put_u8(banner, c)) != 0)
				أرجع r;
			𐤀𐤌 (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				اذهب bad;
		}
		𐤀𐤌 (sshbuf_len(banner) >= 4 &&
		    memcmp(sshbuf_ptr(banner), "SSH-", 4) == 0)
			اكسر;
		debug_f("%.*s", (صحيح)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		𐤀𐤌 (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_LINES) {
  bad:
			𐤀𐤌 ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, strlen(mismatch))) != 0)
				أرجع r;
			أرجع SSH_ERR_NO_PROTOCOL_VERSION;
		}
	}
	𐤀𐤌 ((r = sshbuf_consume(input, j)) != 0)
		أرجع r;

	/* XXX remote version must be the same size as banner for sscanf */
	𐤀𐤌 ((cp = sshbuf_dup_string(banner)) == عدم ||
	    (remote_version = calloc(1, sshbuf_len(banner))) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	𐤀𐤌 (sscanf(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);

	compat_banner(ssh, remote_version);
	𐤀𐤌  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	𐤀𐤌 (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 out:
	حرر(cp);
	حرر(remote_version);
	أرجع r;
}

/* Send our own protocol version identification. */
صحيح
_ssh_send_banner(بنية ssh *ssh, بنية sshbuf *banner)
{
	حرف *cp;
	صحيح r;

	𐤀𐤌 ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_VERSION)) != 0)
		أرجع r;
	𐤀𐤌 ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		أرجع r;
	/* Remove trailing \r\n */
	𐤀𐤌 ((r = sshbuf_consume_end(banner, 2)) != 0)
		أرجع r;
	𐤀𐤌 ((cp = sshbuf_dup_string(banner)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	حرر(cp);
	أرجع 0;
}

صحيح
_ssh_exchange_banner(بنية ssh *ssh)
{
	بنية kex *kex = ssh->kex;
	صحيح r;

	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */

	r = 0;
	𐤀𐤌 (kex->server) {
		𐤀𐤌 (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_version);
		𐤀𐤌 (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_version);
	} وإلا {
		𐤀𐤌 (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_version);
		𐤀𐤌 (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_version);
	}
	𐤀𐤌 (r != 0)
		أرجع r;
	/* start initial kex as soon as we have exchanged the banners */
	𐤀𐤌 (sshbuf_len(ssh->kex->server_version) != 0 &&
	    sshbuf_len(ssh->kex->client_version) != 0) {
		𐤀𐤌 ((r = _ssh_order_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			أرجع r;
	}
	أرجع 0;
}

بنية sshkey *
_ssh_host_public_key(صحيح type, صحيح nid, بنية ssh *ssh)
{
	بنية key_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->public_keys, next) {
		debug3_f("check %s", sshkey_type(k->key));
		𐤀𐤌 (k->key->type == type &&
		    (type != KEY_ECDSA || k->key->ecdsa_nid == nid))
			أرجع (k->key);
	}
	أرجع (عدم);
}

بنية sshkey *
_ssh_host_private_key(صحيح type, صحيح nid, بنية ssh *ssh)
{
	بنية key_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->private_keys, next) {
		debug3_f("check %s", sshkey_type(k->key));
		𐤀𐤌 (k->key->type == type &&
		    (type != KEY_ECDSA || k->key->ecdsa_nid == nid))
			أرجع (k->key);
	}
	أرجع (عدم);
}

صحيح
_ssh_verify_host_key(بنية sshkey *hostkey, بنية ssh *ssh)
{
	بنية key_entry *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->public_keys, next) {
		debug3_f("check %s", sshkey_type(k->key));
		𐤀𐤌 (sshkey_equal_public(hostkey, k->key))
			أرجع (0);	/* ok */
	}
	أرجع (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
صحيح
_ssh_order_hostkeyalgs(بنية ssh *ssh)
{
	بنية key_entry *k;
	حرف *orig, *avail, *oavail = عدم, *alg, *replace = عدم;
	حرف **proposal;
	size_t maxlen;
	صحيح ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	𐤀𐤌 ((r = kex_buf2prop(ssh->kex->my, عدم, &proposal)) != 0)
		أرجع r;
	orig = proposal[PROPOSAL_SERVER_HOST_KEY_ALGS];
	𐤀𐤌 ((oavail = avail = strdup(orig)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	maxlen = strlen(avail) + 1;
	𐤀𐤌 ((replace = calloc(1, maxlen)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	*replace = '\0';
	طالما ((alg = strsep(&avail, ",")) && *alg != '\0') {
		𐤀𐤌 ((ktype = sshkey_type_from_name(alg)) == KEY_UNSPEC)
			استمر;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->public_keys, next) {
			𐤀𐤌 (k->key->type != ktype &&
			    (!sshkey_is_cert(k->key) ||
			    k->key->type != sshkey_type_plain(ktype)))
				استمر;
			𐤀𐤌 (sshkey_type_plain(k->key->type) == KEY_ECDSA &&
			    k->key->ecdsa_nid != nid)
				استمر;
			/* Candidate */
			𐤀𐤌 (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			اكسر;
		}
	}
	𐤀𐤌 (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		حرر(orig);
		proposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = replace;
		replace = عدم;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 out:
	حرر(oavail);
	حرر(replace);
	kex_prop_free(proposal);
	أرجع r;
}

صحيح
_ssh_host_key_sign(بنية ssh *ssh, بنية sshkey *privkey,
    بنية sshkey *pubkey, u_char **signature, size_t *slen,
    ثابت u_char *data, size_t dlen, ثابت حرف *alg)
{
	أرجع sshkey_sign(privkey, signature, slen, data, dlen,
	    alg, عدم, عدم, ssh->compat);
}
