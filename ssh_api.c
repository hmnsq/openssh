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
पूर्णाङ्क	ssh_क्रमः_hostkeyalgs(संरचना ssh *);
पूर्णाङ्क	ssh_verify_host_कुञ्चिका(संरचना sshkey *, संरचना ssh *);
संरचना sshkey *ssh_host_लौकिकम्_कुञ्चिका(पूर्णाङ्क, पूर्णाङ्क, संरचना ssh *);
संरचना sshkey *ssh_host_वैयक्तिकम्_कुञ्चिका(पूर्णाङ्क, पूर्णाङ्क, संरचना ssh *);
पूर्णाङ्क	ssh_host_कुञ्चिका_sign(संरचना ssh *, संरचना sshkey *, संरचना sshkey *,
    u_char **, आकार_t *, ध्रुव u_char *, आकार_t, ध्रुव वर्ण *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
पूर्णाङ्क	mm_sshkey_sign(संरचना sshkey *, u_char **, u_int *,
    ध्रुव u_char *, u_int, ध्रुव वर्ण *, ध्रुव वर्ण *, ध्रुव वर्ण *, u_int);

#यदि_परिभाषितम् WITH_OPENSSL
DH	*mm_वृणु_dh(पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क);
#यदि_अन्तः

पूर्णाङ्क
mm_sshkey_sign(संरचना sshkey *कुञ्चिका, u_char **sigp, u_int *lenp,
    ध्रुव u_char *दत्त, u_int datalen, ध्रुव वर्ण *alg,
    ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin, u_int compat)
{
	आकार_t slen = 0;
	पूर्णाङ्क ret;

	ret = sshkey_sign(कुञ्चिका, sigp, &slen, दत्त, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	प्रत्यागम ret;
}

#यदि_परिभाषितम् WITH_OPENSSL
DH *
mm_वृणु_dh(पूर्णाङ्क min, पूर्णाङ्क nbits, पूर्णाङ्क max)
{
	प्रत्यागम वृणु_dh(min, nbits, max);
}
#यदि_अन्तः

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

	यदि (!called) {
		बीजम्_rng();
		called = 1;
	}

	यदि ((ssh = ssh_packet_समुच्चयः_connection(रिक्त, -1, -1)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि (is_server)
		ssh_packet_समुच्चयः_server(ssh);

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
	यदि (r != 0) {
		ssh_free(ssh);
		प्रत्यागम r;
	}

	ssh->kex->server = is_server;
	यदि (is_server) {
#यदि_परिभाषितम् WITH_OPENSSL
		ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
		ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
		ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
#यदि_अन्तः /* WITH_OPENSSL */
		ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
		ssh->kex->आरोपय_host_लौकिकम्_कुञ्चिका=&ssh_host_लौकिकम्_कुञ्चिका;
		ssh->kex->आरोपय_host_वैयक्तिकम्_कुञ्चिका=&ssh_host_वैयक्तिकम्_कुञ्चिका;
		ssh->kex->sign=&ssh_host_कुञ्चिका_sign;
	} अन्यथा {
#यदि_परिभाषितम् WITH_OPENSSL
		ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
		ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
		ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#यदि_अन्तः /* WITH_OPENSSL */
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
	संरचना कुञ्चिका_प्रविष्टिः *k;

	यदि (ssh == रिक्त)
		प्रत्यागम;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	यावत् ((k = TAILQ_FIRST(&ssh->लौकिकम्_कुञ्चिकाः)) != रिक्त) {
		TAILQ_REMOVE(&ssh->लौकिकम्_कुञ्चिकाः, k, अग्र);
		यदि (ssh->kex && ssh->kex->server)
			sshkey_free(k->कुञ्चिका);
		मुक्त(k);
	}
	यावत् ((k = TAILQ_FIRST(&ssh->वैयक्तिकम्_कुञ्चिकाः)) != रिक्त) {
		TAILQ_REMOVE(&ssh->वैयक्तिकम्_कुञ्चिकाः, k, अग्र);
		मुक्त(k);
	}
	ssh_packet_close(ssh);
	मुक्त(ssh);
}

शून्य
ssh_समुच्चयः_app_दत्त(संरचना ssh *ssh, शून्य *app_दत्त)
{
	ssh->app_दत्त = app_दत्त;
}

शून्य *
ssh_get_app_दत्त(संरचना ssh *ssh)
{
	प्रत्यागम ssh->app_दत्त;
}

/* Returns < 0 on error, 0 otherwise */
पूर्णाङ्क
ssh_सङ्कलय_hostkey(संरचना ssh *ssh, संरचना sshkey *कुञ्चिका)
{
	संरचना sshkey *pubkey = रिक्त;
	संरचना कुञ्चिका_प्रविष्टिः *k = रिक्त, *k_prv = रिक्त;
	पूर्णाङ्क r;

	यदि (ssh->kex->server) {
		यदि ((r = sshkey_from_वैयक्तिकम्(कुञ्चिका, &pubkey)) != 0)
			प्रत्यागम r;
		यदि ((k = स्मृतिं_देहि(परिमाण(*k))) == रिक्त ||
		    (k_prv = स्मृतिं_देहि(परिमाण(*k_prv))) == रिक्त) {
			मुक्त(k);
			sshkey_free(pubkey);
			प्रत्यागम SSH_ERR_ALLOC_FAIL;
		}
		k_prv->कुञ्चिका = कुञ्चिका;
		TAILQ_INSERT_TAIL(&ssh->वैयक्तिकम्_कुञ्चिकाः, k_prv, अग्र);

		/* add the public key, too */
		k->कुञ्चिका = pubkey;
		TAILQ_INSERT_TAIL(&ssh->लौकिकम्_कुञ्चिकाः, k, अग्र);
		r = 0;
	} अन्यथा {
		यदि ((k = स्मृतिं_देहि(परिमाण(*k))) == रिक्त)
			प्रत्यागम SSH_ERR_ALLOC_FAIL;
		k->कुञ्चिका = कुञ्चिका;
		TAILQ_INSERT_TAIL(&ssh->लौकिकम्_कुञ्चिकाः, k, अग्र);
		r = 0;
	}

	प्रत्यागम r;
}

पूर्णाङ्क
ssh_समुच्चयः_verify_host_कुञ्चिका_callback(संरचना ssh *ssh,
    पूर्णाङ्क (*cb)(संरचना sshkey *, संरचना ssh *))
{
	यदि (cb == रिक्त || ssh->kex == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;

	ssh->kex->verify_host_कुञ्चिका = cb;

	प्रत्यागम 0;
}

पूर्णाङ्क
ssh_निवेशः_append(संरचना ssh *ssh, ध्रुव u_char *दत्त, आकार_t len)
{
	प्रत्यागम sshbuf_put(ssh_packet_get_निवेशः(ssh), दत्त, len);
}

पूर्णाङ्क
ssh_packet_अग्र(संरचना ssh *ssh, u_char *typep)
{
	पूर्णाङ्क r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_सन्देशः_NONE;
	यदि (sshbuf_len(ssh->kex->client_संस्करणम्) == 0 ||
	    sshbuf_len(ssh->kex->server_संस्करणम्) == 0)
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
		यदि ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			प्रत्यागम r;
		यदि (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_सन्देशः_KEXINIT && type <= SSH2_सन्देशः_TRANSPORT_MAX &&
		    ssh->dispatch[type] != रिक्त) {
			यदि ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				प्रत्यागम r;
		} अन्यथा {
			*typep = type;
			प्रत्यागम 0;
		}
	}
}

ध्रुव u_char *
ssh_packet_payload(संरचना ssh *ssh, आकार_t *lenp)
{
	प्रत्यागम sshpkt_ptr(ssh, lenp);
}

पूर्णाङ्क
ssh_packet_put(संरचना ssh *ssh, पूर्णाङ्क type, ध्रुव u_char *दत्त, आकार_t len)
{
	पूर्णाङ्क r;

	यदि ((r = sshpkt_start(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, दत्त, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		प्रत्यागम r;
	प्रत्यागम 0;
}

ध्रुव u_char *
ssh_output_ptr(संरचना ssh *ssh, आकार_t *len)
{
	संरचना sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	प्रत्यागम sshbuf_ptr(output);
}

पूर्णाङ्क
ssh_output_consume(संरचना ssh *ssh, आकार_t len)
{
	प्रत्यागम sshbuf_consume(ssh_packet_get_output(ssh), len);
}

पूर्णाङ्क
ssh_output_space(संरचना ssh *ssh, आकार_t len)
{
	प्रत्यागम (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

पूर्णाङ्क
ssh_निवेशः_space(संरचना ssh *ssh, आकार_t len)
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
	वर्ण *cp = रिक्त, *remote_संस्करणम् = रिक्त;
	पूर्णाङ्क r = 0, remote_major, remote_minor, expect_nl;
	आकार_t n, j;

	प्रति (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		प्रति (;;) {
			यदि (j >= sshbuf_len(निवेशः))
				प्रत्यागम 0; /* insufficient data in input buf */
			c = s[j++];
			यदि (c == '\r') {
				expect_nl = 1;
				अनुवर्त;
			}
			यदि (c == '\n')
				भङ्ग;
			यदि (expect_nl)
				गच्छ bad;
			यदि ((r = sshbuf_put_u8(banner, c)) != 0)
				प्रत्यागम r;
			यदि (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				गच्छ bad;
		}
		यदि (sshbuf_len(banner) >= 4 &&
		    memcmp(sshbuf_ptr(banner), "SSH-", 4) == 0)
			भङ्ग;
		debug_f("%.*s", (पूर्णाङ्क)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		यदि (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_पङ्क्तयः) {
  bad:
			यदि ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, वाक्यदैर्घ्यम्(mismatch))) != 0)
				प्रत्यागम r;
			प्रत्यागम SSH_ERR_NO_PROTOCOL_संस्करणम्;
		}
	}
	यदि ((r = sshbuf_consume(निवेशः, j)) != 0)
		प्रत्यागम r;

	/* XXX remote version must be the same size as banner for sscanf */
	यदि ((cp = sshbuf_dup_string(banner)) == रिक्त ||
	    (remote_संस्करणम् = शून्यस्मृतिं_देहि(1, sshbuf_len(banner))) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	यदि (वाक्यात्_पठ(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_संस्करणम्) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_संस्करणम्);

	compat_banner(ssh, remote_संस्करणम्);
	यदि  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	यदि (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 बहिर्गमनम्:
	मुक्त(cp);
	मुक्त(remote_संस्करणम्);
	प्रत्यागम r;
}

/* Send our own protocol version identification. */
पूर्णाङ्क
_ssh_send_banner(संरचना ssh *ssh, संरचना sshbuf *banner)
{
	वर्ण *cp;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_संस्करणम्)) != 0)
		प्रत्यागम r;
	यदि ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		प्रत्यागम r;
	/* Remove trailing \r\n */
	यदि ((r = sshbuf_consume_अन्तः(banner, 2)) != 0)
		प्रत्यागम r;
	यदि ((cp = sshbuf_dup_string(banner)) == रिक्त)
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
	यदि (kex->server) {
		यदि (sshbuf_len(ssh->kex->server_संस्करणम्) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_संस्करणम्);
		यदि (r == 0 &&
		    sshbuf_len(ssh->kex->server_संस्करणम्) != 0 &&
		    sshbuf_len(ssh->kex->client_संस्करणम्) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_संस्करणम्);
	} अन्यथा {
		यदि (sshbuf_len(ssh->kex->server_संस्करणम्) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_संस्करणम्);
		यदि (r == 0 &&
		    sshbuf_len(ssh->kex->server_संस्करणम्) != 0 &&
		    sshbuf_len(ssh->kex->client_संस्करणम्) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_संस्करणम्);
	}
	यदि (r != 0)
		प्रत्यागम r;
	/* start initial kex as soon as we have exchanged the banners */
	यदि (sshbuf_len(ssh->kex->server_संस्करणम्) != 0 &&
	    sshbuf_len(ssh->kex->client_संस्करणम्) != 0) {
		यदि ((r = ssh_क्रमः_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			प्रत्यागम r;
	}
	प्रत्यागम 0;
}

संरचना sshkey *
ssh_host_लौकिकम्_कुञ्चिका(पूर्णाङ्क type, पूर्णाङ्क nid, संरचना ssh *ssh)
{
	संरचना कुञ्चिका_प्रविष्टिः *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->लौकिकम्_कुञ्चिकाः, अग्र) {
		debug3_f("check %s", sshkey_type(k->कुञ्चिका));
		यदि (k->कुञ्चिका->type == type &&
		    (type != कुञ्चिका_ECDSA || k->कुञ्चिका->ecdsa_nid == nid))
			प्रत्यागम (k->कुञ्चिका);
	}
	प्रत्यागम (रिक्त);
}

संरचना sshkey *
ssh_host_वैयक्तिकम्_कुञ्चिका(पूर्णाङ्क type, पूर्णाङ्क nid, संरचना ssh *ssh)
{
	संरचना कुञ्चिका_प्रविष्टिः *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->वैयक्तिकम्_कुञ्चिकाः, अग्र) {
		debug3_f("check %s", sshkey_type(k->कुञ्चिका));
		यदि (k->कुञ्चिका->type == type &&
		    (type != कुञ्चिका_ECDSA || k->कुञ्चिका->ecdsa_nid == nid))
			प्रत्यागम (k->कुञ्चिका);
	}
	प्रत्यागम (रिक्त);
}

पूर्णाङ्क
ssh_verify_host_कुञ्चिका(संरचना sshkey *hostkey, संरचना ssh *ssh)
{
	संरचना कुञ्चिका_प्रविष्टिः *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->लौकिकम्_कुञ्चिकाः, अग्र) {
		debug3_f("check %s", sshkey_type(k->कुञ्चिका));
		यदि (sshkey_equal_लौकिकम्(hostkey, k->कुञ्चिका))
			प्रत्यागम (0);	/* ok */
	}
	प्रत्यागम (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
पूर्णाङ्क
ssh_क्रमः_hostkeyalgs(संरचना ssh *ssh)
{
	संरचना कुञ्चिका_प्रविष्टिः *k;
	वर्ण *orig, *avail, *oavail = रिक्त, *alg, *replace = रिक्त;
	वर्ण **proposal;
	आकार_t maxlen;
	पूर्णाङ्क ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	यदि ((r = kex_buf2prop(ssh->kex->my, रिक्त, &proposal)) != 0)
		प्रत्यागम r;
	orig = proposal[PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS];
	यदि ((oavail = avail = strdup(orig)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	maxlen = वाक्यदैर्घ्यम्(avail) + 1;
	यदि ((replace = शून्यस्मृतिं_देहि(1, maxlen)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	*replace = '\0';
	यावत् ((alg = strsep(&avail, ",")) && *alg != '\0') {
		यदि ((ktype = sshkey_type_from_name(alg)) == कुञ्चिका_UNSPEC)
			अनुवर्त;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->लौकिकम्_कुञ्चिकाः, अग्र) {
			यदि (k->कुञ्चिका->type != ktype &&
			    (!sshkey_is_cert(k->कुञ्चिका) ||
			    k->कुञ्चिका->type != sshkey_type_plain(ktype)))
				अनुवर्त;
			यदि (sshkey_type_plain(k->कुञ्चिका->type) == कुञ्चिका_ECDSA &&
			    k->कुञ्चिका->ecdsa_nid != nid)
				अनुवर्त;
			/* Candidate */
			यदि (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			भङ्ग;
		}
	}
	यदि (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		मुक्त(orig);
		proposal[PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS] = replace;
		replace = रिक्त;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 बहिर्गमनम्:
	मुक्त(oavail);
	मुक्त(replace);
	kex_prop_free(proposal);
	प्रत्यागम r;
}

पूर्णाङ्क
ssh_host_कुञ्चिका_sign(संरचना ssh *ssh, संरचना sshkey *privkey,
    संरचना sshkey *pubkey, u_char **signature, आकार_t *slen,
    ध्रुव u_char *दत्त, आकार_t dlen, ध्रुव वर्ण *alg)
{
	प्रत्यागम sshkey_sign(privkey, signature, slen, दत्त, dlen,
	    alg, रिक्त, रिक्त, ssh->compat);
}
