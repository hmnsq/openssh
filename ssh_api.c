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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>

#अन्तर्भाव "ssh_api.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "dh.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "version.h"
#अन्तर्भाव "myproposal.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"

#अन्तर्भाव "openbsd-compat/openssl-compat.h"

#अन्तर्भाव <string.h>

पूर्णाङ्क	_ssh_exchange_banner(संरचना ssh *);
पूर्णाङ्क	_ssh_send_banner(संरचना ssh *, संरचना sshbuf *);
पूर्णाङ्क	_ssh_read_banner(संरचना ssh *, संरचना sshbuf *);
पूर्णाङ्क	_ssh_order_hostkeyalgs(संरचना ssh *);
पूर्णाङ्क	ssh_verify_host_कुञ्चिका(संरचना sshkey *, संरचना ssh *);
संरचना sshkey *ssh_host_public_कुञ्चिका(पूर्णाङ्क, पूर्णाङ्क, संरचना ssh *);
संरचना sshkey *ssh_host_private_कुञ्चिका(पूर्णाङ्क, पूर्णाङ्क, संरचना ssh *);
पूर्णाङ्क	ssh_host_कुञ्चिका_sign(संरचना ssh *, संरचना sshkey *, संरचना sshkey *,
    u_char **, size_t *, ध्रुव u_char *, size_t, ध्रुव वर्ण *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
पूर्णाङ्क	mm_sshkey_sign(संरचना sshkey *, u_char **, u_int *,
    ध्रुव u_char *, u_int, ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *, u_int);

#ifdef WITH_OPENSSL
DH	*mm_choose_dh(पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क);
#endif

पूर्णाङ्क
mm_sshkey_sign(संरचना sshkey *कुञ्चिका, u_char **sigp, u_int *lenp,
    ध्रुव u_char *data, u_int datalen, ध्रुव वर्ण *alg,
    ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin, u_int compat)
{
	size_t slen = 0;
	पूर्णाङ्क ret;

	ret = sshkey_sign(कुञ्चिका, sigp, &slen, data, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	प्रत्यागम ret;
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(पूर्णाङ्क min, पूर्णाङ्क nbits, पूर्णाङ्क max)
{
	प्रत्यागम choose_dh(min, nbits, max);
}
#endif

/* API */

पूर्णाङ्क
ssh_init(संरचना ssh **sshp, पूर्णाङ्क is_server, संरचना kex_params *kex_params)
{
	वर्ण *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	वर्ण *populated[PROPOSAL_MAX];
	संरचना ssh *ssh;
	वर्ण **proposal;
	स्थिर पूर्णाङ्क called;
	पूर्णाङ्क r;

	जइ (!called) {
		seed_rng();
		called = 1;
	}

	जइ ((ssh = ssh_packet_set_connection(रिक्त, -1, -1)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	जइ (is_server)
		ssh_packet_set_server(ssh);

	/* Initialize key exchange */
	proposal = kex_params ? kex_params->proposal : myproposal;
	kex_proposal_populate_entries(ssh, populated,
	    proposal[PROPOSAL_KEX_ALGS],
	    proposal[PROPOSAL_ENC_ALGS_CTOS],
	    proposal[PROPOSAL_MAC_ALGS_CTOS],
	    proposal[PROPOSAL_COMP_ALGS_CTOS],
	    proposal[PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS]);
	r = kex_ready(ssh, populated);
	kex_proposal_free_entries(populated);
	जइ (r != 0) {
		ssh_free(ssh);
		प्रत्यागम r;
	}

	ssh->kex->server = is_server;
	जइ (is_server) {
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
		ssh->kex->load_host_public_कुञ्चिका=&ssh_host_public_कुञ्चिका;
		ssh->kex->load_host_private_कुञ्चिका=&ssh_host_private_कुञ्चिका;
		ssh->kex->sign=&ssh_host_कुञ्चिका_sign;
	} अण्णहा {
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
		ssh->kex->verify_host_कुञ्चिका =&ssh_verify_host_कुञ्चिका;
	}
	*sshp = ssh;
	प्रत्यागम 0;
}

शून्य
ssh_free(संरचना ssh *ssh)
{
	संरचना कुञ्चिका_entry *k;

	जइ (ssh == रिक्त)
		प्रत्यागम;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	जाव ((k = TAILQ_FIRST(&ssh->public_कुञ्चिकाः)) != रिक्त) {
		TAILQ_REMOVE(&ssh->public_कुञ्चिकाः, k, next);
		जइ (ssh->kex && ssh->kex->server)
			sshkey_free(k->कुञ्चिका);
		मुक्त(k);
	}
	जाव ((k = TAILQ_FIRST(&ssh->private_कुञ्चिकाः)) != रिक्त) {
		TAILQ_REMOVE(&ssh->private_कुञ्चिकाः, k, next);
		मुक्त(k);
	}
	ssh_packet_close(ssh);
	मुक्त(ssh);
}

शून्य
ssh_set_app_data(संरचना ssh *ssh, शून्य *app_data)
{
	ssh->app_data = app_data;
}

शून्य *
ssh_get_app_data(संरचना ssh *ssh)
{
	प्रत्यागम ssh->app_data;
}

/* Returns < 0 on error, 0 otherwise */
पूर्णाङ्क
ssh_add_hostkey(संरचना ssh *ssh, संरचना sshkey *कुञ्चिका)
{
	संरचना sshkey *pubkey = रिक्त;
	संरचना कुञ्चिका_entry *k = रिक्त, *k_prv = रिक्त;
	पूर्णाङ्क r;

	जइ (ssh->kex->server) {
		जइ ((r = sshkey_from_private(कुञ्चिका, &pubkey)) != 0)
			प्रत्यागम r;
		जइ ((k = malloc(परिमाण(*k))) == रिक्त ||
		    (k_prv = malloc(परिमाण(*k_prv))) == रिक्त) {
			मुक्त(k);
			sshkey_free(pubkey);
			प्रत्यागम SSH_ERR_ALLOC_FAIL;
		}
		k_prv->कुञ्चिका = कुञ्चिका;
		TAILQ_INSERT_TAIL(&ssh->private_कुञ्चिकाः, k_prv, next);

		/* add the public key, too */
		k->कुञ्चिका = pubkey;
		TAILQ_INSERT_TAIL(&ssh->public_कुञ्चिकाः, k, next);
		r = 0;
	} अण्णहा {
		जइ ((k = malloc(परिमाण(*k))) == रिक्त)
			प्रत्यागम SSH_ERR_ALLOC_FAIL;
		k->कुञ्चिका = कुञ्चिका;
		TAILQ_INSERT_TAIL(&ssh->public_कुञ्चिकाः, k, next);
		r = 0;
	}

	प्रत्यागम r;
}

पूर्णाङ्क
ssh_set_verify_host_कुञ्चिका_callback(संरचना ssh *ssh,
    पूर्णाङ्क (*cb)(संरचना sshkey *, संरचना ssh *))
{
	जइ (cb == रिक्त || ssh->kex == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;

	ssh->kex->verify_host_कुञ्चिका = cb;

	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_निवेशः_append(संरचना ssh *ssh, ध्रुव u_char *data, size_t len)
{
	प्रत्यागम sshbuf_put(ssh_packet_get_निवेशः(ssh), data, len);
}

पूर्णाङ्क
ssh_packet_next(संरचना ssh *ssh, u_char *typep)
{
	पूर्णाङ्क r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_सन्देशः_NONE;
	जइ (sshbuf_len(ssh->kex->client_version) == 0 ||
	    sshbuf_len(ssh->kex->server_version) == 0)
		प्रत्यागम _ssh_exchange_banner(ssh);
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
	प्रति (;;) {
		जइ ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			प्रत्यागम r;
		जइ (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_सन्देशः_KEXINIT && type <= SSH2_सन्देशः_TRANSPORT_MAX &&
		    ssh->dispatch[type] != रिक्त) {
			जइ ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				प्रत्यागम r;
		} अण्णहा {
			*typep = type;
			प्रत्यागम 0;
		}
	}
}

ध्रुव u_char *
ssh_packet_payload(संरचना ssh *ssh, size_t *lenp)
{
	प्रत्यागम sshpkt_ptr(ssh, lenp);
}

पूर्णाङ्क
ssh_packet_put(संरचना ssh *ssh, पूर्णाङ्क type, ध्रुव u_char *data, size_t len)
{
	पूर्णाङ्क r;

	जइ ((r = sshpkt_start(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, data, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		प्रत्यागम r;
	प्रत्यागम 0;
}

ध्रुव u_char *
ssh_output_ptr(संरचना ssh *ssh, size_t *len)
{
	संरचना sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	प्रत्यागम sshbuf_ptr(output);
}

पूर्णाङ्क
ssh_output_consume(संरचना ssh *ssh, size_t len)
{
	प्रत्यागम sshbuf_consume(ssh_packet_get_output(ssh), len);
}

पूर्णाङ्क
ssh_output_space(संरचना ssh *ssh, size_t len)
{
	प्रत्यागम (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

पूर्णाङ्क
ssh_निवेशः_space(संरचना ssh *ssh, size_t len)
{
	प्रत्यागम (0 == sshbuf_check_reserve(ssh_packet_get_निवेशः(ssh), len));
}

/* Read other side's version identification. */
पूर्णाङ्क
_ssh_read_banner(संरचना ssh *ssh, संरचना sshbuf *banner)
{
	संरचना sshbuf *निवेशः = ssh_packet_get_निवेशः(ssh);
	ध्रुव वर्ण *mismatch = "Protocol mismatch.\r\n";
	ध्रुव u_char *s = sshbuf_ptr(निवेशः);
	u_char c;
	वर्ण *cp = रिक्त, *remote_version = रिक्त;
	पूर्णाङ्क r = 0, remote_major, remote_minor, expect_nl;
	size_t n, j;

	प्रति (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		प्रति (;;) {
			जइ (j >= sshbuf_len(निवेशः))
				प्रत्यागम 0; /* insufficient data in input buf */
			c = s[j++];
			जइ (c == '\r') {
				expect_nl = 1;
				अनुवर्त;
			}
			जइ (c == '\n')
				भङ्ग;
			जइ (expect_nl)
				गच्छ bad;
			जइ ((r = sshbuf_put_u8(banner, c)) != 0)
				प्रत्यागम r;
			जइ (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				गच्छ bad;
		}
		जइ (sshbuf_len(banner) >= 4 &&
		    memcmp(sshbuf_ptr(banner), "SSH-", 4) == 0)
			भङ्ग;
		debug_f("%.*s", (पूर्णाङ्क)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		जइ (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_पङ्क्तयः) {
  bad:
			जइ ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, strlen(mismatch))) != 0)
				प्रत्यागम r;
			प्रत्यागम SSH_ERR_NO_PROTOCOL_VERSION;
		}
	}
	जइ ((r = sshbuf_consume(निवेशः, j)) != 0)
		प्रत्यागम r;

	/* XXX remote version must be the same size as banner for sscanf */
	जइ ((cp = sshbuf_dup_string(banner)) == रिक्त ||
	    (remote_version = calloc(1, sshbuf_len(banner))) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	जइ (sscanf(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);

	compat_banner(ssh, remote_version);
	जइ  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	जइ (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 out:
	मुक्त(cp);
	मुक्त(remote_version);
	प्रत्यागम r;
}

/* Send our own protocol version identification. */
पूर्णाङ्क
_ssh_send_banner(संरचना ssh *ssh, संरचना sshbuf *banner)
{
	वर्ण *cp;
	पूर्णाङ्क r;

	जइ ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_VERSION)) != 0)
		प्रत्यागम r;
	जइ ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		प्रत्यागम r;
	/* Remove trailing \r\n */
	जइ ((r = sshbuf_consume_end(banner, 2)) != 0)
		प्रत्यागम r;
	जइ ((cp = sshbuf_dup_string(banner)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	मुक्त(cp);
	प्रत्यागम 0;
}

पूर्णाङ्क
_ssh_exchange_banner(संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	पूर्णाङ्क r;

	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */

	r = 0;
	जइ (kex->server) {
		जइ (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_version);
		जइ (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_version);
	} अण्णहा {
		जइ (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_version);
		जइ (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_version);
	}
	जइ (r != 0)
		प्रत्यागम r;
	/* start initial kex as soon as we have exchanged the banners */
	जइ (sshbuf_len(ssh->kex->server_version) != 0 &&
	    sshbuf_len(ssh->kex->client_version) != 0) {
		जइ ((r = _ssh_order_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			प्रत्यागम r;
	}
	प्रत्यागम 0;
}

संरचना sshkey *
ssh_host_public_कुञ्चिका(पूर्णाङ्क type, पूर्णाङ्क nid, संरचना ssh *ssh)
{
	संरचना कुञ्चिका_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->public_कुञ्चिकाः, next) {
		debug3_f("check %s", sshkey_type(k->कुञ्चिका));
		जइ (k->कुञ्चिका->type == type &&
		    (type != कुञ्चिका_ECDSA || k->कुञ्चिका->ecdsa_nid == nid))
			प्रत्यागम (k->कुञ्चिका);
	}
	प्रत्यागम (रिक्त);
}

संरचना sshkey *
ssh_host_private_कुञ्चिका(पूर्णाङ्क type, पूर्णाङ्क nid, संरचना ssh *ssh)
{
	संरचना कुञ्चिका_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->private_कुञ्चिकाः, next) {
		debug3_f("check %s", sshkey_type(k->कुञ्चिका));
		जइ (k->कुञ्चिका->type == type &&
		    (type != कुञ्चिका_ECDSA || k->कुञ्चिका->ecdsa_nid == nid))
			प्रत्यागम (k->कुञ्चिका);
	}
	प्रत्यागम (रिक्त);
}

पूर्णाङ्क
ssh_verify_host_कुञ्चिका(संरचना sshkey *hostkey, संरचना ssh *ssh)
{
	संरचना कुञ्चिका_entry *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->public_कुञ्चिकाः, next) {
		debug3_f("check %s", sshkey_type(k->कुञ्चिका));
		जइ (sshkey_equal_public(hostkey, k->कुञ्चिका))
			प्रत्यागम (0);	/* ok */
	}
	प्रत्यागम (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
पूर्णाङ्क
_ssh_order_hostkeyalgs(संरचना ssh *ssh)
{
	संरचना कुञ्चिका_entry *k;
	वर्ण *orig, *avail, *oavail = रिक्त, *alg, *replace = रिक्त;
	वर्ण **proposal;
	size_t maxlen;
	पूर्णाङ्क ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	जइ ((r = kex_buf2prop(ssh->kex->my, रिक्त, &proposal)) != 0)
		प्रत्यागम r;
	orig = proposal[PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS];
	जइ ((oavail = avail = strdup(orig)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	maxlen = strlen(avail) + 1;
	जइ ((replace = calloc(1, maxlen)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	*replace = '\0';
	जाव ((alg = strsep(&avail, ",")) && *alg != '\0') {
		जइ ((ktype = sshkey_type_from_name(alg)) == कुञ्चिका_UNSPEC)
			अनुवर्त;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->public_कुञ्चिकाः, next) {
			जइ (k->कुञ्चिका->type != ktype &&
			    (!sshkey_is_cert(k->कुञ्चिका) ||
			    k->कुञ्चिका->type != sshkey_type_plain(ktype)))
				अनुवर्त;
			जइ (sshkey_type_plain(k->कुञ्चिका->type) == कुञ्चिका_ECDSA &&
			    k->कुञ्चिका->ecdsa_nid != nid)
				अनुवर्त;
			/* Candidate */
			जइ (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			भङ्ग;
		}
	}
	जइ (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		मुक्त(orig);
		proposal[PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS] = replace;
		replace = रिक्त;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 out:
	मुक्त(oavail);
	मुक्त(replace);
	kex_prop_free(proposal);
	प्रत्यागम r;
}

पूर्णाङ्क
ssh_host_कुञ्चिका_sign(संरचना ssh *ssh, संरचना sshkey *privkey,
    संरचना sshkey *pubkey, u_char **signature, size_t *slen,
    ध्रुव u_char *data, size_t dlen, ध्रुव वर्ण *alg)
{
	प्रत्यागम sshkey_sign(privkey, signature, slen, data, dlen,
	    alg, रिक्त, रिक्त, ssh->compat);
}
