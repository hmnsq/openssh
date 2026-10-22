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

ціле	_ssh_exchange_banner(struct ssh *);
ціле	_ssh_send_banner(struct ssh *, struct sshbuf *);
ціле	_ssh_read_banner(struct ssh *, struct sshbuf *);
ціле	_ssh_order_hostkeyalgs(struct ssh *);
ціле	_ssh_verify_host_key(struct sshkey *, struct ssh *);
struct sshkey *_ssh_host_public_key(ціле, ціле, struct ssh *);
struct sshkey *_ssh_host_private_key(ціле, ціле, struct ssh *);
ціле	_ssh_host_key_sign(struct ssh *, struct sshkey *, struct sshkey *,
    u_char **, size_t *, const u_char *, size_t, const char *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
ціле	mm_sshkey_sign(struct sshkey *, u_char **, u_int *,
    const u_char *, u_int, const char *, const char *, const char *, u_int);

#ifdef WITH_OPENSSL
DH	*mm_choose_dh(ціле, ціле, ціле);
#endif

ціле
mm_sshkey_sign(struct sshkey *key, u_char **sigp, u_int *lenp,
    const u_char *data, u_int datalen, const char *alg,
    const char *sk_provider, const char *sk_pin, u_int compat)
{
	size_t slen = 0;
	ціле ret;

	ret = sshkey_sign(key, sigp, &slen, data, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	повернути ret;
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(ціле min, ціле nbits, ціле max)
{
	повернути choose_dh(min, nbits, max);
}
#endif

/* API */

ціле
ssh_init(struct ssh **sshp, ціле is_server, struct kex_params *kex_params)
{
	char *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	char *populated[PROPOSAL_MAX];
	struct ssh *ssh;
	char **proposal;
	static ціле called;
	ціле r;

	якщо (!called) {
		seed_rng();
		called = 1;
	}

	якщо ((ssh = ssh_packet_set_connection(NULL, -1, -1)) == NULL)
		повернути SSH_ERR_ALLOC_FAIL;
	якщо (is_server)
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
	якщо (r != 0) {
		ssh_free(ssh);
		повернути r;
	}

	ssh->kex->server = is_server;
	якщо (is_server) {
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
	} інакше {
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
	повернути 0;
}

void
ssh_free(struct ssh *ssh)
{
	struct key_entry *k;

	якщо (ssh == NULL)
		повернути;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	поки ((k = TAILQ_FIRST(&ssh->public_keys)) != NULL) {
		TAILQ_REMOVE(&ssh->public_keys, k, next);
		якщо (ssh->kex && ssh->kex->server)
			sshkey_free(k->key);
		free(k);
	}
	поки ((k = TAILQ_FIRST(&ssh->private_keys)) != NULL) {
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
	повернути ssh->app_data;
}

/* Returns < 0 on error, 0 otherwise */
ціле
ssh_add_hostkey(struct ssh *ssh, struct sshkey *key)
{
	struct sshkey *pubkey = NULL;
	struct key_entry *k = NULL, *k_prv = NULL;
	ціле r;

	якщо (ssh->kex->server) {
		якщо ((r = sshkey_from_private(key, &pubkey)) != 0)
			повернути r;
		якщо ((k = malloc(sizeof(*k))) == NULL ||
		    (k_prv = malloc(sizeof(*k_prv))) == NULL) {
			free(k);
			sshkey_free(pubkey);
			повернути SSH_ERR_ALLOC_FAIL;
		}
		k_prv->key = key;
		TAILQ_INSERT_TAIL(&ssh->private_keys, k_prv, next);

		/* add the public key, too */
		k->key = pubkey;
		TAILQ_INSERT_TAIL(&ssh->public_keys, k, next);
		r = 0;
	} інакше {
		якщо ((k = malloc(sizeof(*k))) == NULL)
			повернути SSH_ERR_ALLOC_FAIL;
		k->key = key;
		TAILQ_INSERT_TAIL(&ssh->public_keys, k, next);
		r = 0;
	}

	повернути r;
}

ціле
ssh_set_verify_host_key_callback(struct ssh *ssh,
    ціле (*cb)(struct sshkey *, struct ssh *))
{
	якщо (cb == NULL || ssh->kex == NULL)
		повернути SSH_ERR_INVALID_ARGUMENT;

	ssh->kex->verify_host_key = cb;

	повернути 0;
}

ціле
ssh_input_append(struct ssh *ssh, const u_char *data, size_t len)
{
	повернути sshbuf_put(ssh_packet_get_input(ssh), data, len);
}

ціле
ssh_packet_next(struct ssh *ssh, u_char *typep)
{
	ціле r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_MSG_NONE;
	якщо (sshbuf_len(ssh->kex->client_version) == 0 ||
	    sshbuf_len(ssh->kex->server_version) == 0)
		повернути _ssh_exchange_banner(ssh);
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
	для (;;) {
		якщо ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			повернути r;
		якщо (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_MSG_KEXINIT && type <= SSH2_MSG_TRANSPORT_MAX &&
		    ssh->dispatch[type] != NULL) {
			якщо ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				повернути r;
		} інакше {
			*typep = type;
			повернути 0;
		}
	}
}

const u_char *
ssh_packet_payload(struct ssh *ssh, size_t *lenp)
{
	повернути sshpkt_ptr(ssh, lenp);
}

ціле
ssh_packet_put(struct ssh *ssh, ціле type, const u_char *data, size_t len)
{
	ціле r;

	якщо ((r = sshpkt_start(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, data, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		повернути r;
	повернути 0;
}

const u_char *
ssh_output_ptr(struct ssh *ssh, size_t *len)
{
	struct sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	повернути sshbuf_ptr(output);
}

ціле
ssh_output_consume(struct ssh *ssh, size_t len)
{
	повернути sshbuf_consume(ssh_packet_get_output(ssh), len);
}

ціле
ssh_output_space(struct ssh *ssh, size_t len)
{
	повернути (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

ціле
ssh_input_space(struct ssh *ssh, size_t len)
{
	повернути (0 == sshbuf_check_reserve(ssh_packet_get_input(ssh), len));
}

/* Read other side's version identification. */
ціле
_ssh_read_banner(struct ssh *ssh, struct sshbuf *banner)
{
	struct sshbuf *input = ssh_packet_get_input(ssh);
	const char *mismatch = "Protocol mismatch.\r\n";
	const u_char *s = sshbuf_ptr(input);
	u_char c;
	char *cp = NULL, *remote_version = NULL;
	ціле r = 0, remote_major, remote_minor, expect_nl;
	size_t n, j;

	для (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		для (;;) {
			якщо (j >= sshbuf_len(input))
				повернути 0; /* insufficient data in input buf */
			c = s[j++];
			якщо (c == '\r') {
				expect_nl = 1;
				continue;
			}
			якщо (c == '\n')
				break;
			якщо (expect_nl)
				goto bad;
			якщо ((r = sshbuf_put_u8(banner, c)) != 0)
				повернути r;
			якщо (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				goto bad;
		}
		якщо (sshbuf_len(banner) >= 4 &&
		    memcmp(sshbuf_ptr(banner), "SSH-", 4) == 0)
			break;
		debug_f("%.*s", (ціле)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		якщо (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_LINES) {
  bad:
			якщо ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, strlen(mismatch))) != 0)
				повернути r;
			повернути SSH_ERR_NO_PROTOCOL_VERSION;
		}
	}
	якщо ((r = sshbuf_consume(input, j)) != 0)
		повернути r;

	/* XXX remote version must be the same size as banner for sscanf */
	якщо ((cp = sshbuf_dup_string(banner)) == NULL ||
	    (remote_version = calloc(1, sshbuf_len(banner))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	якщо (sscanf(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);

	compat_banner(ssh, remote_version);
	якщо  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	якщо (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 out:
	free(cp);
	free(remote_version);
	повернути r;
}

/* Send our own protocol version identification. */
ціле
_ssh_send_banner(struct ssh *ssh, struct sshbuf *banner)
{
	char *cp;
	ціле r;

	якщо ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_VERSION)) != 0)
		повернути r;
	якщо ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		повернути r;
	/* Remove trailing \r\n */
	якщо ((r = sshbuf_consume_end(banner, 2)) != 0)
		повернути r;
	якщо ((cp = sshbuf_dup_string(banner)) == NULL)
		повернути SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	free(cp);
	повернути 0;
}

ціле
_ssh_exchange_banner(struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	ціле r;

	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */

	r = 0;
	якщо (kex->server) {
		якщо (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_version);
		якщо (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_version);
	} інакше {
		якщо (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_version);
		якщо (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_version);
	}
	якщо (r != 0)
		повернути r;
	/* start initial kex as soon as we have exchanged the banners */
	якщо (sshbuf_len(ssh->kex->server_version) != 0 &&
	    sshbuf_len(ssh->kex->client_version) != 0) {
		якщо ((r = _ssh_order_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			повернути r;
	}
	повернути 0;
}

struct sshkey *
_ssh_host_public_key(ціле type, ціле nid, struct ssh *ssh)
{
	struct key_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->public_keys, next) {
		debug3_f("check %s", sshkey_type(k->key));
		якщо (k->key->type == type &&
		    (type != KEY_ECDSA || k->key->ecdsa_nid == nid))
			повернути (k->key);
	}
	повернути (NULL);
}

struct sshkey *
_ssh_host_private_key(ціле type, ціле nid, struct ssh *ssh)
{
	struct key_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->private_keys, next) {
		debug3_f("check %s", sshkey_type(k->key));
		якщо (k->key->type == type &&
		    (type != KEY_ECDSA || k->key->ecdsa_nid == nid))
			повернути (k->key);
	}
	повернути (NULL);
}

ціле
_ssh_verify_host_key(struct sshkey *hostkey, struct ssh *ssh)
{
	struct key_entry *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->public_keys, next) {
		debug3_f("check %s", sshkey_type(k->key));
		якщо (sshkey_equal_public(hostkey, k->key))
			повернути (0);	/* ok */
	}
	повернути (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
ціле
_ssh_order_hostkeyalgs(struct ssh *ssh)
{
	struct key_entry *k;
	char *orig, *avail, *oavail = NULL, *alg, *replace = NULL;
	char **proposal;
	size_t maxlen;
	ціле ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	якщо ((r = kex_buf2prop(ssh->kex->my, NULL, &proposal)) != 0)
		повернути r;
	orig = proposal[PROPOSAL_SERVER_HOST_KEY_ALGS];
	якщо ((oavail = avail = strdup(orig)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	maxlen = strlen(avail) + 1;
	якщо ((replace = calloc(1, maxlen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	*replace = '\0';
	поки ((alg = strsep(&avail, ",")) && *alg != '\0') {
		якщо ((ktype = sshkey_type_from_name(alg)) == KEY_UNSPEC)
			continue;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->public_keys, next) {
			якщо (k->key->type != ktype &&
			    (!sshkey_is_cert(k->key) ||
			    k->key->type != sshkey_type_plain(ktype)))
				continue;
			якщо (sshkey_type_plain(k->key->type) == KEY_ECDSA &&
			    k->key->ecdsa_nid != nid)
				continue;
			/* Candidate */
			якщо (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			break;
		}
	}
	якщо (*replace != '\0') {
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
	повернути r;
}

ціле
_ssh_host_key_sign(struct ssh *ssh, struct sshkey *privkey,
    struct sshkey *pubkey, u_char **signature, size_t *slen,
    const u_char *data, size_t dlen, const char *alg)
{
	повернути sshkey_sign(privkey, signature, slen, data, dlen,
	    alg, NULL, NULL, ssh->compat);
}
