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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>

#അന്തര്ഭാവ "ssh_api.h"
#അന്തര്ഭാവ "compat.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "dh.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "version.h"
#അന്തര്ഭാവ "myproposal.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshbuf.h"

#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"

#അന്തര്ഭാവ <string.h>

പൂർണ്ണസംഖ്യ	_ssh_exchange_banner(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	_ssh_send_banner(ഘടന ssh *, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ	_ssh_read_banner(ഘടന ssh *, ഘടന sshbuf *);
പൂർണ്ണസംഖ്യ	_ssh_order_hostkeyalgs(ഘടന ssh *);
പൂർണ്ണസംഖ്യ	ssh_verify_host_താക്കോൽ(ഘടന sshkey *, ഘടന ssh *);
ഘടന sshkey *ssh_host_public_താക്കോൽ(പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, ഘടന ssh *);
ഘടന sshkey *ssh_host_private_താക്കോൽ(പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, ഘടന ssh *);
പൂർണ്ണസംഖ്യ	ssh_host_താക്കോൽ_sign(ഘടന ssh *, ഘടന sshkey *, ഘടന sshkey *,
    u_char **, size_t *, സ്ഥിരം u_char *, size_t, സ്ഥിരം അക്ഷരം *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
പൂർണ്ണസംഖ്യ	mm_sshkey_sign(ഘടന sshkey *, u_char **, u_int *,
    സ്ഥിരം u_char *, u_int, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, u_int);

#ifdef WITH_OPENSSL
DH	*mm_choose_dh(പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ, പൂർണ്ണസംഖ്യ);
#endif

പൂർണ്ണസംഖ്യ
mm_sshkey_sign(ഘടന sshkey *താക്കോൽ, u_char **sigp, u_int *lenp,
    സ്ഥിരം u_char *data, u_int datalen, സ്ഥിരം അക്ഷരം *alg,
    സ്ഥിരം അക്ഷരം *sk_provider, സ്ഥിരം അക്ഷരം *sk_pin, u_int compat)
{
	size_t slen = 0;
	പൂർണ്ണസംഖ്യ ret;

	ret = sshkey_sign(താക്കോൽ, sigp, &slen, data, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	തിരികെ ret;
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(പൂർണ്ണസംഖ്യ min, പൂർണ്ണസംഖ്യ nbits, പൂർണ്ണസംഖ്യ max)
{
	തിരികെ choose_dh(min, nbits, max);
}
#endif

/* API */

പൂർണ്ണസംഖ്യ
ssh_init(ഘടന ssh **sshp, പൂർണ്ണസംഖ്യ is_server, ഘടന kex_params *kex_params)
{
	അക്ഷരം *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	അക്ഷരം *populated[PROPOSAL_MAX];
	ഘടന ssh *ssh;
	അക്ഷരം **proposal;
	സ്ഥിതം പൂർണ്ണസംഖ്യ called;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (!called) {
		seed_rng();
		called = 1;
	}

	എങ്കിൽ ((ssh = ssh_packet_set_connection(ശൂന്യ, -1, -1)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ (is_server)
		ssh_packet_set_server(ssh);

	/* Initialize key exchange */
	proposal = kex_params ? kex_params->proposal : myproposal;
	kex_proposal_populate_entries(ssh, populated,
	    proposal[PROPOSAL_KEX_ALGS],
	    proposal[PROPOSAL_ENC_ALGS_CTOS],
	    proposal[PROPOSAL_MAC_ALGS_CTOS],
	    proposal[PROPOSAL_COMP_ALGS_CTOS],
	    proposal[PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS]);
	r = kex_ready(ssh, populated);
	kex_proposal_free_entries(populated);
	എങ്കിൽ (r != 0) {
		ssh_free(ssh);
		തിരികെ r;
	}

	ssh->kex->server = is_server;
	എങ്കിൽ (is_server) {
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
		ssh->kex->load_host_public_താക്കോൽ=&ssh_host_public_താക്കോൽ;
		ssh->kex->load_host_private_താക്കോൽ=&ssh_host_private_താക്കോൽ;
		ssh->kex->sign=&ssh_host_താക്കോൽ_sign;
	} അല്ലെങ്കിൽ {
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
		ssh->kex->verify_host_താക്കോൽ =&ssh_verify_host_താക്കോൽ;
	}
	*sshp = ssh;
	തിരികെ 0;
}

ശൂന്യം
ssh_free(ഘടന ssh *ssh)
{
	ഘടന താക്കോൽ_entry *k;

	എങ്കിൽ (ssh == ശൂന്യ)
		തിരികെ;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	ആകുമ്പോൾ ((k = TAILQ_FIRST(&ssh->public_താക്കോലുകൾ)) != ശൂന്യ) {
		TAILQ_REMOVE(&ssh->public_താക്കോലുകൾ, k, next);
		എങ്കിൽ (ssh->kex && ssh->kex->server)
			sshkey_free(k->താക്കോൽ);
		സ്വതന്ത്രം(k);
	}
	ആകുമ്പോൾ ((k = TAILQ_FIRST(&ssh->private_താക്കോലുകൾ)) != ശൂന്യ) {
		TAILQ_REMOVE(&ssh->private_താക്കോലുകൾ, k, next);
		സ്വതന്ത്രം(k);
	}
	ssh_packet_close(ssh);
	സ്വതന്ത്രം(ssh);
}

ശൂന്യം
ssh_set_app_data(ഘടന ssh *ssh, ശൂന്യം *app_data)
{
	ssh->app_data = app_data;
}

ശൂന്യം *
ssh_get_app_data(ഘടന ssh *ssh)
{
	തിരികെ ssh->app_data;
}

/* Returns < 0 on error, 0 otherwise */
പൂർണ്ണസംഖ്യ
ssh_add_hostkey(ഘടന ssh *ssh, ഘടന sshkey *താക്കോൽ)
{
	ഘടന sshkey *pubkey = ശൂന്യ;
	ഘടന താക്കോൽ_entry *k = ശൂന്യ, *k_prv = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (ssh->kex->server) {
		എങ്കിൽ ((r = sshkey_from_private(താക്കോൽ, &pubkey)) != 0)
			തിരികെ r;
		എങ്കിൽ ((k = malloc(വലുപ്പം(*k))) == ശൂന്യ ||
		    (k_prv = malloc(വലുപ്പം(*k_prv))) == ശൂന്യ) {
			സ്വതന്ത്രം(k);
			sshkey_free(pubkey);
			തിരികെ SSH_ERR_ALLOC_FAIL;
		}
		k_prv->താക്കോൽ = താക്കോൽ;
		TAILQ_INSERT_TAIL(&ssh->private_താക്കോലുകൾ, k_prv, next);

		/* add the public key, too */
		k->താക്കോൽ = pubkey;
		TAILQ_INSERT_TAIL(&ssh->public_താക്കോലുകൾ, k, next);
		r = 0;
	} അല്ലെങ്കിൽ {
		എങ്കിൽ ((k = malloc(വലുപ്പം(*k))) == ശൂന്യ)
			തിരികെ SSH_ERR_ALLOC_FAIL;
		k->താക്കോൽ = താക്കോൽ;
		TAILQ_INSERT_TAIL(&ssh->public_താക്കോലുകൾ, k, next);
		r = 0;
	}

	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
ssh_set_verify_host_താക്കോൽ_callback(ഘടന ssh *ssh,
    പൂർണ്ണസംഖ്യ (*cb)(ഘടന sshkey *, ഘടന ssh *))
{
	എങ്കിൽ (cb == ശൂന്യ || ssh->kex == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;

	ssh->kex->verify_host_താക്കോൽ = cb;

	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
ssh_നിവേശം_append(ഘടന ssh *ssh, സ്ഥിരം u_char *data, size_t len)
{
	തിരികെ sshbuf_put(ssh_packet_get_നിവേശം(ssh), data, len);
}

പൂർണ്ണസംഖ്യ
ssh_packet_next(ഘടന ssh *ssh, u_char *typep)
{
	പൂർണ്ണസംഖ്യ r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_സന്ദേശം_NONE;
	എങ്കിൽ (sshbuf_len(ssh->kex->client_version) == 0 ||
	    sshbuf_len(ssh->kex->server_version) == 0)
		തിരികെ _ssh_exchange_banner(ssh);
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
	വേണ്ടി (;;) {
		എങ്കിൽ ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			തിരികെ r;
		എങ്കിൽ (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_സന്ദേശം_KEXINIT && type <= SSH2_സന്ദേശം_TRANSPORT_MAX &&
		    ssh->dispatch[type] != ശൂന്യ) {
			എങ്കിൽ ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				തിരികെ r;
		} അല്ലെങ്കിൽ {
			*typep = type;
			തിരികെ 0;
		}
	}
}

സ്ഥിരം u_char *
ssh_packet_payload(ഘടന ssh *ssh, size_t *lenp)
{
	തിരികെ sshpkt_ptr(ssh, lenp);
}

പൂർണ്ണസംഖ്യ
ssh_packet_put(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ type, സ്ഥിരം u_char *data, size_t len)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshpkt_start(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, data, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		തിരികെ r;
	തിരികെ 0;
}

സ്ഥിരം u_char *
ssh_output_ptr(ഘടന ssh *ssh, size_t *len)
{
	ഘടന sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	തിരികെ sshbuf_ptr(output);
}

പൂർണ്ണസംഖ്യ
ssh_output_consume(ഘടന ssh *ssh, size_t len)
{
	തിരികെ sshbuf_consume(ssh_packet_get_output(ssh), len);
}

പൂർണ്ണസംഖ്യ
ssh_output_space(ഘടന ssh *ssh, size_t len)
{
	തിരികെ (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

പൂർണ്ണസംഖ്യ
ssh_നിവേശം_space(ഘടന ssh *ssh, size_t len)
{
	തിരികെ (0 == sshbuf_check_reserve(ssh_packet_get_നിവേശം(ssh), len));
}

/* Read other side's version identification. */
പൂർണ്ണസംഖ്യ
_ssh_read_banner(ഘടന ssh *ssh, ഘടന sshbuf *banner)
{
	ഘടന sshbuf *നിവേശം = ssh_packet_get_നിവേശം(ssh);
	സ്ഥിരം അക്ഷരം *mismatch = "Protocol mismatch.\r\n";
	സ്ഥിരം u_char *s = sshbuf_ptr(നിവേശം);
	u_char c;
	അക്ഷരം *cp = ശൂന്യ, *remote_version = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = 0, remote_major, remote_minor, expect_nl;
	size_t n, j;

	വേണ്ടി (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		വേണ്ടി (;;) {
			എങ്കിൽ (j >= sshbuf_len(നിവേശം))
				തിരികെ 0; /* insufficient data in input buf */
			c = s[j++];
			എങ്കിൽ (c == '\r') {
				expect_nl = 1;
				തുടരുക;
			}
			എങ്കിൽ (c == '\n')
				നിർത്തുക;
			എങ്കിൽ (expect_nl)
				പോകുക bad;
			എങ്കിൽ ((r = sshbuf_put_u8(banner, c)) != 0)
				തിരികെ r;
			എങ്കിൽ (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				പോകുക bad;
		}
		എങ്കിൽ (sshbuf_len(banner) >= 4 &&
		    memcmp(sshbuf_ptr(banner), "SSH-", 4) == 0)
			നിർത്തുക;
		debug_f("%.*s", (പൂർണ്ണസംഖ്യ)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		എങ്കിൽ (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_വരികൾ) {
  bad:
			എങ്കിൽ ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, strlen(mismatch))) != 0)
				തിരികെ r;
			തിരികെ SSH_ERR_NO_PROTOCOL_VERSION;
		}
	}
	എങ്കിൽ ((r = sshbuf_consume(നിവേശം, j)) != 0)
		തിരികെ r;

	/* XXX remote version must be the same size as banner for sscanf */
	എങ്കിൽ ((cp = sshbuf_dup_string(banner)) == ശൂന്യ ||
	    (remote_version = calloc(1, sshbuf_len(banner))) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	എങ്കിൽ (sscanf(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);

	compat_banner(ssh, remote_version);
	എങ്കിൽ  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	എങ്കിൽ (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 out:
	സ്വതന്ത്രം(cp);
	സ്വതന്ത്രം(remote_version);
	തിരികെ r;
}

/* Send our own protocol version identification. */
പൂർണ്ണസംഖ്യ
_ssh_send_banner(ഘടന ssh *ssh, ഘടന sshbuf *banner)
{
	അക്ഷരം *cp;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_VERSION)) != 0)
		തിരികെ r;
	എങ്കിൽ ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		തിരികെ r;
	/* Remove trailing \r\n */
	എങ്കിൽ ((r = sshbuf_consume_end(banner, 2)) != 0)
		തിരികെ r;
	എങ്കിൽ ((cp = sshbuf_dup_string(banner)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	സ്വതന്ത്രം(cp);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
_ssh_exchange_banner(ഘടന ssh *ssh)
{
	ഘടന kex *kex = ssh->kex;
	പൂർണ്ണസംഖ്യ r;

	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */

	r = 0;
	എങ്കിൽ (kex->server) {
		എങ്കിൽ (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_version);
		എങ്കിൽ (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_version);
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_version);
		എങ്കിൽ (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_version);
	}
	എങ്കിൽ (r != 0)
		തിരികെ r;
	/* start initial kex as soon as we have exchanged the banners */
	എങ്കിൽ (sshbuf_len(ssh->kex->server_version) != 0 &&
	    sshbuf_len(ssh->kex->client_version) != 0) {
		എങ്കിൽ ((r = _ssh_order_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			തിരികെ r;
	}
	തിരികെ 0;
}

ഘടന sshkey *
ssh_host_public_താക്കോൽ(പൂർണ്ണസംഖ്യ type, പൂർണ്ണസംഖ്യ nid, ഘടന ssh *ssh)
{
	ഘടന താക്കോൽ_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->public_താക്കോലുകൾ, next) {
		debug3_f("check %s", sshkey_type(k->താക്കോൽ));
		എങ്കിൽ (k->താക്കോൽ->type == type &&
		    (type != താക്കോൽ_ECDSA || k->താക്കോൽ->ecdsa_nid == nid))
			തിരികെ (k->താക്കോൽ);
	}
	തിരികെ (ശൂന്യ);
}

ഘടന sshkey *
ssh_host_private_താക്കോൽ(പൂർണ്ണസംഖ്യ type, പൂർണ്ണസംഖ്യ nid, ഘടന ssh *ssh)
{
	ഘടന താക്കോൽ_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->private_താക്കോലുകൾ, next) {
		debug3_f("check %s", sshkey_type(k->താക്കോൽ));
		എങ്കിൽ (k->താക്കോൽ->type == type &&
		    (type != താക്കോൽ_ECDSA || k->താക്കോൽ->ecdsa_nid == nid))
			തിരികെ (k->താക്കോൽ);
	}
	തിരികെ (ശൂന്യ);
}

പൂർണ്ണസംഖ്യ
ssh_verify_host_താക്കോൽ(ഘടന sshkey *hostkey, ഘടന ssh *ssh)
{
	ഘടന താക്കോൽ_entry *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->public_താക്കോലുകൾ, next) {
		debug3_f("check %s", sshkey_type(k->താക്കോൽ));
		എങ്കിൽ (sshkey_equal_public(hostkey, k->താക്കോൽ))
			തിരികെ (0);	/* ok */
	}
	തിരികെ (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
പൂർണ്ണസംഖ്യ
_ssh_order_hostkeyalgs(ഘടന ssh *ssh)
{
	ഘടന താക്കോൽ_entry *k;
	അക്ഷരം *orig, *avail, *oavail = ശൂന്യ, *alg, *replace = ശൂന്യ;
	അക്ഷരം **proposal;
	size_t maxlen;
	പൂർണ്ണസംഖ്യ ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	എങ്കിൽ ((r = kex_buf2prop(ssh->kex->my, ശൂന്യ, &proposal)) != 0)
		തിരികെ r;
	orig = proposal[PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS];
	എങ്കിൽ ((oavail = avail = strdup(orig)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	maxlen = strlen(avail) + 1;
	എങ്കിൽ ((replace = calloc(1, maxlen)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	*replace = '\0';
	ആകുമ്പോൾ ((alg = strsep(&avail, ",")) && *alg != '\0') {
		എങ്കിൽ ((ktype = sshkey_type_from_name(alg)) == താക്കോൽ_UNSPEC)
			തുടരുക;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->public_താക്കോലുകൾ, next) {
			എങ്കിൽ (k->താക്കോൽ->type != ktype &&
			    (!sshkey_is_cert(k->താക്കോൽ) ||
			    k->താക്കോൽ->type != sshkey_type_plain(ktype)))
				തുടരുക;
			എങ്കിൽ (sshkey_type_plain(k->താക്കോൽ->type) == താക്കോൽ_ECDSA &&
			    k->താക്കോൽ->ecdsa_nid != nid)
				തുടരുക;
			/* Candidate */
			എങ്കിൽ (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			നിർത്തുക;
		}
	}
	എങ്കിൽ (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		സ്വതന്ത്രം(orig);
		proposal[PROPOSAL_SERVER_HOST_താക്കോൽ_ALGS] = replace;
		replace = ശൂന്യ;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 out:
	സ്വതന്ത്രം(oavail);
	സ്വതന്ത്രം(replace);
	kex_prop_free(proposal);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
ssh_host_താക്കോൽ_sign(ഘടന ssh *ssh, ഘടന sshkey *privkey,
    ഘടന sshkey *pubkey, u_char **signature, size_t *slen,
    സ്ഥിരം u_char *data, size_t dlen, സ്ഥിരം അക്ഷരം *alg)
{
	തിരികെ sshkey_sign(privkey, signature, slen, data, dlen,
	    alg, ശൂന്യ, ശൂന്യ, ssh->compat);
}
