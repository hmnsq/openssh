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

整数	_ssh_exchange_banner(struct ssh *);
整数	_ssh_send_banner(struct ssh *, struct sshbuf *);
整数	_ssh_read_banner(struct ssh *, struct sshbuf *);
整数	_ssh_order_hostkeyalgs(struct ssh *);
整数	_ssh_verify_host_key(struct sshkey *, struct ssh *);
struct sshkey *_ssh_host_public_key(整数, 整数, struct ssh *);
struct sshkey *_ssh_host_private_key(整数, 整数, struct ssh *);
整数	_ssh_host_key_sign(struct ssh *, struct sshkey *, struct sshkey *,
    u_char **, size_t *, const u_char *, size_t, const char *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
整数	mm_sshkey_sign(struct sshkey *, u_char **, u_int *,
    const u_char *, u_int, const char *, const char *, const char *, u_int);

#ifdef WITH_OPENSSL
DH	*mm_choose_dh(整数, 整数, 整数);
#endif

整数
mm_sshkey_sign(struct sshkey *key, u_char **sigp, u_int *lenp,
    const u_char *data, u_int datalen, const char *alg,
    const char *sk_provider, const char *sk_pin, u_int compat)
{
	size_t slen = 0;
	整数 ret;

	ret = sshkey_sign(key, sigp, &slen, data, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	返回 ret;
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(整数 min, 整数 nbits, 整数 max)
{
	返回 choose_dh(min, nbits, max);
}
#endif

/* API */

整数
ssh_init(struct ssh **sshp, 整数 is_server, struct kex_params *kex_params)
{
	char *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	char *populated[PROPOSAL_MAX];
	struct ssh *ssh;
	char **proposal;
	static 整数 called;
	整数 r;

	如果 (!called) {
		seed_rng();
		called = 1;
	}

	如果 ((ssh = ssh_packet_set_connection(NULL, -1, -1)) == NULL)
		返回 SSH_ERR_ALLOC_FAIL;
	如果 (is_server)
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
	如果 (r != 0) {
		ssh_free(ssh);
		返回 r;
	}

	ssh->kex->server = is_server;
	如果 (is_server) {
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
	} 否则 {
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
	返回 0;
}

void
ssh_free(struct ssh *ssh)
{
	struct key_entry *k;

	如果 (ssh == NULL)
		返回;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	当 ((k = TAILQ_FIRST(&ssh->public_keys)) != NULL) {
		TAILQ_REMOVE(&ssh->public_keys, k, next);
		如果 (ssh->kex && ssh->kex->server)
			sshkey_free(k->key);
		free(k);
	}
	当 ((k = TAILQ_FIRST(&ssh->private_keys)) != NULL) {
		TAILQ_REMOVE(&ssh->private_keys, k, next);
		free(k);
	}
	ssh_packet_close(ssh);
	free(ssh);
}

void
ssh_set_app_data(struct ssh *ssh, void *app_data)
{
	ssh->app_data = app_data;
}

void *
ssh_get_app_data(struct ssh *ssh)
{
	返回 ssh->app_data;
}

/* Returns < 0 on error, 0 otherwise */
整数
ssh_add_hostkey(struct ssh *ssh, struct sshkey *key)
{
	struct sshkey *pubkey = NULL;
	struct key_entry *k = NULL, *k_prv = NULL;
	整数 r;

	如果 (ssh->kex->server) {
		如果 ((r = sshkey_from_private(key, &pubkey)) != 0)
			返回 r;
		如果 ((k = malloc(sizeof(*k))) == NULL ||
		    (k_prv = malloc(sizeof(*k_prv))) == NULL) {
			free(k);
			sshkey_free(pubkey);
			返回 SSH_ERR_ALLOC_FAIL;
		}
		k_prv->key = key;
		TAILQ_INSERT_TAIL(&ssh->private_keys, k_prv, next);

		/* add the public key, too */
		k->key = pubkey;
		TAILQ_INSERT_TAIL(&ssh->public_keys, k, next);
		r = 0;
	} 否则 {
		如果 ((k = malloc(sizeof(*k))) == NULL)
			返回 SSH_ERR_ALLOC_FAIL;
		k->key = key;
		TAILQ_INSERT_TAIL(&ssh->public_keys, k, next);
		r = 0;
	}

	返回 r;
}

整数
ssh_set_verify_host_key_callback(struct ssh *ssh,
    整数 (*cb)(struct sshkey *, struct ssh *))
{
	如果 (cb == NULL || ssh->kex == NULL)
		返回 SSH_ERR_INVALID_ARGUMENT;

	ssh->kex->verify_host_key = cb;

	返回 0;
}

整数
ssh_input_append(struct ssh *ssh, const u_char *data, size_t len)
{
	返回 sshbuf_put(ssh_packet_get_input(ssh), data, len);
}

整数
ssh_packet_next(struct ssh *ssh, u_char *typep)
{
	整数 r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_MSG_NONE;
	如果 (sshbuf_len(ssh->kex->client_version) == 0 ||
	    sshbuf_len(ssh->kex->server_version) == 0)
		返回 _ssh_exchange_banner(ssh);
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
	为 (;;) {
		如果 ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			返回 r;
		如果 (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_MSG_KEXINIT && type <= SSH2_MSG_TRANSPORT_MAX &&
		    ssh->dispatch[type] != NULL) {
			如果 ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				返回 r;
		} 否则 {
			*typep = type;
			返回 0;
		}
	}
}

const u_char *
ssh_packet_payload(struct ssh *ssh, size_t *lenp)
{
	返回 sshpkt_ptr(ssh, lenp);
}

整数
ssh_packet_put(struct ssh *ssh, 整数 type, const u_char *data, size_t len)
{
	整数 r;

	如果 ((r = sshpkt_start(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, data, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		返回 r;
	返回 0;
}

const u_char *
ssh_output_ptr(struct ssh *ssh, size_t *len)
{
	struct sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	返回 sshbuf_ptr(output);
}

整数
ssh_output_consume(struct ssh *ssh, size_t len)
{
	返回 sshbuf_consume(ssh_packet_get_output(ssh), len);
}

整数
ssh_output_space(struct ssh *ssh, size_t len)
{
	返回 (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

整数
ssh_input_space(struct ssh *ssh, size_t len)
{
	返回 (0 == sshbuf_check_reserve(ssh_packet_get_input(ssh), len));
}

/* Read other side's version identification. */
整数
_ssh_read_banner(struct ssh *ssh, struct sshbuf *banner)
{
	struct sshbuf *input = ssh_packet_get_input(ssh);
	const char *mismatch = "Protocol mismatch.\r\n";
	const u_char *s = sshbuf_ptr(input);
	u_char c;
	char *cp = NULL, *remote_version = NULL;
	整数 r = 0, remote_major, remote_minor, expect_nl;
	size_t n, j;

	为 (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		为 (;;) {
			如果 (j >= sshbuf_len(input))
				返回 0; /* insufficient data in input buf */
			c = s[j++];
			如果 (c == '\r') {
				expect_nl = 1;
				continue;
			}
			如果 (c == '\n')
				break;
			如果 (expect_nl)
				goto bad;
			如果 ((r = sshbuf_put_u8(banner, c)) != 0)
				返回 r;
			如果 (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				goto bad;
		}
		如果 (sshbuf_len(banner) >= 4 &&
		    memcmp(sshbuf_ptr(banner), "SSH-", 4) == 0)
			break;
		debug_f("%.*s", (整数)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		如果 (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_LINES) {
  bad:
			如果 ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, strlen(mismatch))) != 0)
				返回 r;
			返回 SSH_ERR_NO_PROTOCOL_VERSION;
		}
	}
	如果 ((r = sshbuf_consume(input, j)) != 0)
		返回 r;

	/* XXX remote version must be the same size as banner for sscanf */
	如果 ((cp = sshbuf_dup_string(banner)) == NULL ||
	    (remote_version = calloc(1, sshbuf_len(banner))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	如果 (sscanf(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);

	compat_banner(ssh, remote_version);
	如果  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	如果 (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 out:
	free(cp);
	free(remote_version);
	返回 r;
}

/* Send our own protocol version identification. */
整数
_ssh_send_banner(struct ssh *ssh, struct sshbuf *banner)
{
	char *cp;
	整数 r;

	如果 ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_VERSION)) != 0)
		返回 r;
	如果 ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		返回 r;
	/* Remove trailing \r\n */
	如果 ((r = sshbuf_consume_end(banner, 2)) != 0)
		返回 r;
	如果 ((cp = sshbuf_dup_string(banner)) == NULL)
		返回 SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	free(cp);
	返回 0;
}

整数
_ssh_exchange_banner(struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	整数 r;

	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */

	r = 0;
	如果 (kex->server) {
		如果 (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_version);
		如果 (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_version);
	} 否则 {
		如果 (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_version);
		如果 (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_version);
	}
	如果 (r != 0)
		返回 r;
	/* start initial kex as soon as we have exchanged the banners */
	如果 (sshbuf_len(ssh->kex->server_version) != 0 &&
	    sshbuf_len(ssh->kex->client_version) != 0) {
		如果 ((r = _ssh_order_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			返回 r;
	}
	返回 0;
}

struct sshkey *
_ssh_host_public_key(整数 type, 整数 nid, struct ssh *ssh)
{
	struct key_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->public_keys, next) {
		debug3_f("check %s", sshkey_type(k->key));
		如果 (k->key->type == type &&
		    (type != KEY_ECDSA || k->key->ecdsa_nid == nid))
			返回 (k->key);
	}
	返回 (NULL);
}

struct sshkey *
_ssh_host_private_key(整数 type, 整数 nid, struct ssh *ssh)
{
	struct key_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->private_keys, next) {
		debug3_f("check %s", sshkey_type(k->key));
		如果 (k->key->type == type &&
		    (type != KEY_ECDSA || k->key->ecdsa_nid == nid))
			返回 (k->key);
	}
	返回 (NULL);
}

整数
_ssh_verify_host_key(struct sshkey *hostkey, struct ssh *ssh)
{
	struct key_entry *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->public_keys, next) {
		debug3_f("check %s", sshkey_type(k->key));
		如果 (sshkey_equal_public(hostkey, k->key))
			返回 (0);	/* ok */
	}
	返回 (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
整数
_ssh_order_hostkeyalgs(struct ssh *ssh)
{
	struct key_entry *k;
	char *orig, *avail, *oavail = NULL, *alg, *replace = NULL;
	char **proposal;
	size_t maxlen;
	整数 ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	如果 ((r = kex_buf2prop(ssh->kex->my, NULL, &proposal)) != 0)
		返回 r;
	orig = proposal[PROPOSAL_SERVER_HOST_KEY_ALGS];
	如果 ((oavail = avail = strdup(orig)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	maxlen = strlen(avail) + 1;
	如果 ((replace = calloc(1, maxlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	*replace = '\0';
	当 ((alg = strsep(&avail, ",")) && *alg != '\0') {
		如果 ((ktype = sshkey_type_from_name(alg)) == KEY_UNSPEC)
			continue;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->public_keys, next) {
			如果 (k->key->type != ktype &&
			    (!sshkey_is_cert(k->key) ||
			    k->key->type != sshkey_type_plain(ktype)))
				continue;
			如果 (sshkey_type_plain(k->key->type) == KEY_ECDSA &&
			    k->key->ecdsa_nid != nid)
				continue;
			/* Candidate */
			如果 (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			break;
		}
	}
	如果 (*replace != '\0') {
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
	返回 r;
}

整数
_ssh_host_key_sign(struct ssh *ssh, struct sshkey *privkey,
    struct sshkey *pubkey, u_char **signature, size_t *slen,
    const u_char *data, size_t dlen, const char *alg)
{
	返回 sshkey_sign(privkey, signature, slen, data, dlen,
	    alg, NULL, NULL, ssh->compat);
}
