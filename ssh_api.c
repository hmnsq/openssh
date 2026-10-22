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

#include "includes.h"

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>

#include "ssh_api.h"
#include "compat.h"
#include "log.h"
#include "authfile.h"
#include "sshkey.h"
#include "dh.h"
#include "misc.h"
#include "ssh2.h"
#include "version.h"
#include "myproposal.h"
#include "ssherr.h"
#include "sshbuf.h"

#include "openbsd-compat/openssl-compat.h"

#include <string.h>

ចំនួនគត់	_ssh_exchange_banner(sa_nracanaa ssh *);
ចំនួនគត់	_ssh_send_banner(sa_nracanaa ssh *, sa_nracanaa sshbuf *);
ចំនួនគត់	_ssh_read_banner(sa_nracanaa ssh *, sa_nracanaa sshbuf *);
ចំនួនគត់	_ssh_order_hostkeyalgs(sa_nracanaa ssh *);
ចំនួនគត់	_ssh_verify_host_key(sa_nracanaa sshkey *, sa_nracanaa ssh *);
sa_nracanaa sshkey *_ssh_host_public_key(ចំនួនគត់, ចំនួនគត់, sa_nracanaa ssh *);
sa_nracanaa sshkey *_ssh_host_private_key(ចំនួនគត់, ចំនួនគត់, sa_nracanaa ssh *);
ចំនួនគត់	_ssh_host_key_sign(sa_nracanaa ssh *, sa_nracanaa sshkey *, sa_nracanaa sshkey *,
    u_char **, size_t *, const u_char *, size_t, const var_na *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
ចំនួនគត់	mm_sshkey_sign(sa_nracanaa sshkey *, u_char **, u_int *,
    const u_char *, u_int, const var_na *, const var_na *, const var_na *, u_int);

#ifdef WITH_OPENSSL
DH	*mm_choose_dh(ចំនួនគត់, ចំនួនគត់, ចំនួនគត់);
#endif

ចំនួនគត់
mm_sshkey_sign(sa_nracanaa sshkey *key, u_char **sigp, u_int *lenp,
    const u_char *data, u_int datalen, const var_na *alg,
    const var_na *sk_provider, const var_na *sk_pin, u_int compat)
{
	size_t slen = 0;
	ចំនួនគត់ ret;

	ret = sshkey_sign(key, sigp, &slen, data, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	ត្រឡប់ ret;
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(ចំនួនគត់ min, ចំនួនគត់ nbits, ចំនួនគត់ max)
{
	ត្រឡប់ choose_dh(min, nbits, max);
}
#endif

/* API */

ចំនួនគត់
ssh_init(sa_nracanaa ssh **sshp, ចំនួនគត់ is_server, sa_nracanaa kex_params *kex_params)
{
	var_na *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	var_na *populated[PROPOSAL_MAX];
	sa_nracanaa ssh *ssh;
	var_na **proposal;
	static ចំនួនគត់ called;
	ចំនួនគត់ r;

	ប្រសិនបើ (!called) {
		seed_rng();
		called = 1;
	}

	ប្រសិនបើ ((ssh = ssh_packet_set_connection(NULL, -1, -1)) == NULL)
		ត្រឡប់ SSH_ERR_ALLOC_FAIL;
	ប្រសិនបើ (is_server)
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
	ប្រសិនបើ (r != 0) {
		ssh_free(ssh);
		ត្រឡប់ r;
	}

	ssh->kex->server = is_server;
	ប្រសិនបើ (is_server) {
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
	} បើមិនដូច្នេះ {
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
	ត្រឡប់ 0;
}

void
ssh_free(sa_nracanaa ssh *ssh)
{
	sa_nracanaa key_entry *k;

	ប្រសិនបើ (ssh == NULL)
		ត្រឡប់;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	ខណៈពេល ((k = TAILQ_FIRST(&ssh->public_keys)) != NULL) {
		TAILQ_REMOVE(&ssh->public_keys, k, next);
		ប្រសិនបើ (ssh->kex && ssh->kex->server)
			sshkey_free(k->key);
		free(k);
	}
	ខណៈពេល ((k = TAILQ_FIRST(&ssh->private_keys)) != NULL) {
		TAILQ_REMOVE(&ssh->private_keys, k, next);
		free(k);
	}
	ssh_packet_close(ssh);
	free(ssh);
}

void
ssh_set_app_data(sa_nracanaa ssh *ssh, void *app_data)
{
	ssh->app_data = app_data;
}

void *
ssh_get_app_data(sa_nracanaa ssh *ssh)
{
	ត្រឡប់ ssh->app_data;
}

/* Returns < 0 on error, 0 otherwise */
ចំនួនគត់
ssh_add_hostkey(sa_nracanaa ssh *ssh, sa_nracanaa sshkey *key)
{
	sa_nracanaa sshkey *pubkey = NULL;
	sa_nracanaa key_entry *k = NULL, *k_prv = NULL;
	ចំនួនគត់ r;

	ប្រសិនបើ (ssh->kex->server) {
		ប្រសិនបើ ((r = sshkey_from_private(key, &pubkey)) != 0)
			ត្រឡប់ r;
		ប្រសិនបើ ((k = malloc(parimaa_na(*k))) == NULL ||
		    (k_prv = malloc(parimaa_na(*k_prv))) == NULL) {
			free(k);
			sshkey_free(pubkey);
			ត្រឡប់ SSH_ERR_ALLOC_FAIL;
		}
		k_prv->key = key;
		TAILQ_INSERT_TAIL(&ssh->private_keys, k_prv, next);

		/* add the public key, too */
		k->key = pubkey;
		TAILQ_INSERT_TAIL(&ssh->public_keys, k, next);
		r = 0;
	} បើមិនដូច្នេះ {
		ប្រសិនបើ ((k = malloc(parimaa_na(*k))) == NULL)
			ត្រឡប់ SSH_ERR_ALLOC_FAIL;
		k->key = key;
		TAILQ_INSERT_TAIL(&ssh->public_keys, k, next);
		r = 0;
	}

	ត្រឡប់ r;
}

ចំនួនគត់
ssh_set_verify_host_key_callback(sa_nracanaa ssh *ssh,
    ចំនួនគត់ (*cb)(sa_nracanaa sshkey *, sa_nracanaa ssh *))
{
	ប្រសិនបើ (cb == NULL || ssh->kex == NULL)
		ត្រឡប់ SSH_ERR_INVALID_ARGUMENT;

	ssh->kex->verify_host_key = cb;

	ត្រឡប់ 0;
}

ចំនួនគត់
ssh_input_append(sa_nracanaa ssh *ssh, const u_char *data, size_t len)
{
	ត្រឡប់ sshbuf_put(ssh_packet_get_input(ssh), data, len);
}

ចំនួនគត់
ssh_packet_next(sa_nracanaa ssh *ssh, u_char *typep)
{
	ចំនួនគត់ r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_MSG_NONE;
	ប្រសិនបើ (sshbuf_len(ssh->kex->client_version) == 0 ||
	    sshbuf_len(ssh->kex->server_version) == 0)
		ត្រឡប់ _ssh_exchange_banner(ssh);
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
	សម្រាប់ (;;) {
		ប្រសិនបើ ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			ត្រឡប់ r;
		ប្រសិនបើ (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_MSG_KEXINIT && type <= SSH2_MSG_TRANSPORT_MAX &&
		    ssh->dispatch[type] != NULL) {
			ប្រសិនបើ ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				ត្រឡប់ r;
		} បើមិនដូច្នេះ {
			*typep = type;
			ត្រឡប់ 0;
		}
	}
}

const u_char *
ssh_packet_payload(sa_nracanaa ssh *ssh, size_t *lenp)
{
	ត្រឡប់ sshpkt_ptr(ssh, lenp);
}

ចំនួនគត់
ssh_packet_put(sa_nracanaa ssh *ssh, ចំនួនគត់ type, const u_char *data, size_t len)
{
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = sshpkt_start(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, data, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ត្រឡប់ r;
	ត្រឡប់ 0;
}

const u_char *
ssh_output_ptr(sa_nracanaa ssh *ssh, size_t *len)
{
	sa_nracanaa sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	ត្រឡប់ sshbuf_ptr(output);
}

ចំនួនគត់
ssh_output_consume(sa_nracanaa ssh *ssh, size_t len)
{
	ត្រឡប់ sshbuf_consume(ssh_packet_get_output(ssh), len);
}

ចំនួនគត់
ssh_output_space(sa_nracanaa ssh *ssh, size_t len)
{
	ត្រឡប់ (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

ចំនួនគត់
ssh_input_space(sa_nracanaa ssh *ssh, size_t len)
{
	ត្រឡប់ (0 == sshbuf_check_reserve(ssh_packet_get_input(ssh), len));
}

/* Read other side's version identification. */
ចំនួនគត់
_ssh_read_banner(sa_nracanaa ssh *ssh, sa_nracanaa sshbuf *banner)
{
	sa_nracanaa sshbuf *input = ssh_packet_get_input(ssh);
	const var_na *mismatch = "Protocol mismatch.\r\n";
	const u_char *s = sshbuf_ptr(input);
	u_char c;
	var_na *cp = NULL, *remote_version = NULL;
	ចំនួនគត់ r = 0, remote_major, remote_minor, expect_nl;
	size_t n, j;

	សម្រាប់ (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		សម្រាប់ (;;) {
			ប្រសិនបើ (j >= sshbuf_len(input))
				ត្រឡប់ 0; /* insufficient data in input buf */
			c = s[j++];
			ប្រសិនបើ (c == '\r') {
				expect_nl = 1;
				continue;
			}
			ប្រសិនបើ (c == '\n')
				bha_nga;
			ប្រសិនបើ (expect_nl)
				goto bad;
			ប្រសិនបើ ((r = sshbuf_put_u8(banner, c)) != 0)
				ត្រឡប់ r;
			ប្រសិនបើ (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				goto bad;
		}
		ប្រសិនបើ (sshbuf_len(banner) >= 4 &&
		    memcmp(sshbuf_ptr(banner), "SSH-", 4) == 0)
			bha_nga;
		debug_f("%.*s", (ចំនួនគត់)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		ប្រសិនបើ (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_LINES) {
  bad:
			ប្រសិនបើ ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, strlen(mismatch))) != 0)
				ត្រឡប់ r;
			ត្រឡប់ SSH_ERR_NO_PROTOCOL_VERSION;
		}
	}
	ប្រសិនបើ ((r = sshbuf_consume(input, j)) != 0)
		ត្រឡប់ r;

	/* XXX remote version must be the same size as banner for sscanf */
	ប្រសិនបើ ((cp = sshbuf_dup_string(banner)) == NULL ||
	    (remote_version = calloc(1, sshbuf_len(banner))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	ប្រសិនបើ (sscanf(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);

	compat_banner(ssh, remote_version);
	ប្រសិនបើ  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	ប្រសិនបើ (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 out:
	free(cp);
	free(remote_version);
	ត្រឡប់ r;
}

/* Send our own protocol version identification. */
ចំនួនគត់
_ssh_send_banner(sa_nracanaa ssh *ssh, sa_nracanaa sshbuf *banner)
{
	var_na *cp;
	ចំនួនគត់ r;

	ប្រសិនបើ ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_VERSION)) != 0)
		ត្រឡប់ r;
	ប្រសិនបើ ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		ត្រឡប់ r;
	/* Remove trailing \r\n */
	ប្រសិនបើ ((r = sshbuf_consume_end(banner, 2)) != 0)
		ត្រឡប់ r;
	ប្រសិនបើ ((cp = sshbuf_dup_string(banner)) == NULL)
		ត្រឡប់ SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	free(cp);
	ត្រឡប់ 0;
}

ចំនួនគត់
_ssh_exchange_banner(sa_nracanaa ssh *ssh)
{
	sa_nracanaa kex *kex = ssh->kex;
	ចំនួនគត់ r;

	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */

	r = 0;
	ប្រសិនបើ (kex->server) {
		ប្រសិនបើ (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_version);
		ប្រសិនបើ (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_version);
	} បើមិនដូច្នេះ {
		ប្រសិនបើ (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_version);
		ប្រសិនបើ (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_version);
	}
	ប្រសិនបើ (r != 0)
		ត្រឡប់ r;
	/* start initial kex as soon as we have exchanged the banners */
	ប្រសិនបើ (sshbuf_len(ssh->kex->server_version) != 0 &&
	    sshbuf_len(ssh->kex->client_version) != 0) {
		ប្រសិនបើ ((r = _ssh_order_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			ត្រឡប់ r;
	}
	ត្រឡប់ 0;
}

sa_nracanaa sshkey *
_ssh_host_public_key(ចំនួនគត់ type, ចំនួនគត់ nid, sa_nracanaa ssh *ssh)
{
	sa_nracanaa key_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->public_keys, next) {
		debug3_f("check %s", sshkey_type(k->key));
		ប្រសិនបើ (k->key->type == type &&
		    (type != KEY_ECDSA || k->key->ecdsa_nid == nid))
			ត្រឡប់ (k->key);
	}
	ត្រឡប់ (NULL);
}

sa_nracanaa sshkey *
_ssh_host_private_key(ចំនួនគត់ type, ចំនួនគត់ nid, sa_nracanaa ssh *ssh)
{
	sa_nracanaa key_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->private_keys, next) {
		debug3_f("check %s", sshkey_type(k->key));
		ប្រសិនបើ (k->key->type == type &&
		    (type != KEY_ECDSA || k->key->ecdsa_nid == nid))
			ត្រឡប់ (k->key);
	}
	ត្រឡប់ (NULL);
}

ចំនួនគត់
_ssh_verify_host_key(sa_nracanaa sshkey *hostkey, sa_nracanaa ssh *ssh)
{
	sa_nracanaa key_entry *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->public_keys, next) {
		debug3_f("check %s", sshkey_type(k->key));
		ប្រសិនបើ (sshkey_equal_public(hostkey, k->key))
			ត្រឡប់ (0);	/* ok */
	}
	ត្រឡប់ (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
ចំនួនគត់
_ssh_order_hostkeyalgs(sa_nracanaa ssh *ssh)
{
	sa_nracanaa key_entry *k;
	var_na *orig, *avail, *oavail = NULL, *alg, *replace = NULL;
	var_na **proposal;
	size_t maxlen;
	ចំនួនគត់ ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	ប្រសិនបើ ((r = kex_buf2prop(ssh->kex->my, NULL, &proposal)) != 0)
		ត្រឡប់ r;
	orig = proposal[PROPOSAL_SERVER_HOST_KEY_ALGS];
	ប្រសិនបើ ((oavail = avail = strdup(orig)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	maxlen = strlen(avail) + 1;
	ប្រសិនបើ ((replace = calloc(1, maxlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	*replace = '\0';
	ខណៈពេល ((alg = strsep(&avail, ",")) && *alg != '\0') {
		ប្រសិនបើ ((ktype = sshkey_type_from_name(alg)) == KEY_UNSPEC)
			continue;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->public_keys, next) {
			ប្រសិនបើ (k->key->type != ktype &&
			    (!sshkey_is_cert(k->key) ||
			    k->key->type != sshkey_type_plain(ktype)))
				continue;
			ប្រសិនបើ (sshkey_type_plain(k->key->type) == KEY_ECDSA &&
			    k->key->ecdsa_nid != nid)
				continue;
			/* Candidate */
			ប្រសិនបើ (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			bha_nga;
		}
	}
	ប្រសិនបើ (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		free(orig);
		proposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = replace;
		replace = NULL;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 out:
	free(oavail);
	free(replace);
	kex_prop_free(proposal);
	ត្រឡប់ r;
}

ចំនួនគត់
_ssh_host_key_sign(sa_nracanaa ssh *ssh, sa_nracanaa sshkey *privkey,
    sa_nracanaa sshkey *pubkey, u_char **signature, size_t *slen,
    const u_char *data, size_t dlen, const var_na *alg)
{
	ត្រឡប់ sshkey_sign(privkey, signature, slen, data, dlen,
	    alg, NULL, NULL, ssh->compat);
}
