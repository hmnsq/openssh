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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>

#అన్తర్భావ "ssh_api.h"
#అన్తర్భావ "compat.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "dh.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "version.h"
#అన్తర్భావ "myproposal.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"

#అన్తర్భావ "openbsd-compat/openssl-compat.h"

#అన్తర్భావ <string.h>

పూర్ణాంకం	_ssh_exchange_banner(నిర్మాణం ssh *);
పూర్ణాంకం	_ssh_send_banner(నిర్మాణం ssh *, నిర్మాణం sshbuf *);
పూర్ణాంకం	_ssh_read_banner(నిర్మాణం ssh *, నిర్మాణం sshbuf *);
పూర్ణాంకం	ssh_క్రమం_hostkeyalgs(నిర్మాణం ssh *);
పూర్ణాంకం	ssh_verify_host_కీలకం(నిర్మాణం sshkey *, నిర్మాణం ssh *);
నిర్మాణం sshkey *ssh_host_ప్రజా_కీలకం(పూర్ణాంకం, పూర్ణాంకం, నిర్మాణం ssh *);
నిర్మాణం sshkey *ssh_host_వ్యక్తిగత_కీలకం(పూర్ణాంకం, పూర్ణాంకం, నిర్మాణం ssh *);
పూర్ణాంకం	ssh_host_కీలకం_sign(నిర్మాణం ssh *, నిర్మాణం sshkey *, నిర్మాణం sshkey *,
    u_char **, కొలత_t *, స్థిరరాశి u_char *, కొలత_t, స్థిరరాశి అక్షరం *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
పూర్ణాంకం	mm_sshkey_sign(నిర్మాణం sshkey *, u_char **, u_int *,
    స్థిరరాశి u_char *, u_int, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, u_int);

#నిర్వచితమైతే WITH_OPENSSL
DH	*mm_ఎంచుకో_dh(పూర్ణాంకం, పూర్ణాంకం, పూర్ణాంకం);
#అయితే_ముగింపు

పూర్ణాంకం
mm_sshkey_sign(నిర్మాణం sshkey *కీలకం, u_char **sigp, u_int *lenp,
    స్థిరరాశి u_char *దత్తాంశం, u_int datalen, స్థిరరాశి అక్షరం *alg,
    స్థిరరాశి అక్షరం *sk_provider, స్థిరరాశి అక్షరం *sk_pin, u_int compat)
{
	కొలత_t slen = 0;
	పూర్ణాంకం ret;

	ret = sshkey_sign(కీలకం, sigp, &slen, దత్తాంశం, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	తిరిగి ret;
}

#నిర్వచితమైతే WITH_OPENSSL
DH *
mm_ఎంచుకో_dh(పూర్ణాంకం min, పూర్ణాంకం nbits, పూర్ణాంకం max)
{
	తిరిగి ఎంచుకో_dh(min, nbits, max);
}
#అయితే_ముగింపు

/* API */

పూర్ణాంకం
ssh_init(నిర్మాణం ssh **sshp, పూర్ణాంకం is_server, నిర్మాణం kex_params *kex_params)
{
	అక్షరం *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	అక్షరం *populated[PROPOSAL_MAX];
	నిర్మాణం ssh *ssh;
	అక్షరం **proposal;
	స్థిర పూర్ణాంకం called;
	పూర్ణాంకం r;

	ఒకవేళ (!called) {
		విత్తనం_rng();
		called = 1;
	}

	ఒకవేళ ((ssh = ssh_packet_సమితి_connection(ఖాళీ, -1, -1)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ (is_server)
		ssh_packet_సమితి_server(ssh);

	/* Initialize key exchange */
	proposal = kex_params ? kex_params->proposal : myproposal;
	kex_proposal_populate_entries(ssh, populated,
	    proposal[PROPOSAL_KEX_ALGS],
	    proposal[PROPOSAL_ENC_ALGS_CTOS],
	    proposal[PROPOSAL_MAC_ALGS_CTOS],
	    proposal[PROPOSAL_COMP_ALGS_CTOS],
	    proposal[PROPOSAL_SERVER_HOST_కీలకం_ALGS]);
	r = kex_ready(ssh, populated);
	kex_proposal_free_entries(populated);
	ఒకవేళ (r != 0) {
		ssh_free(ssh);
		తిరిగి r;
	}

	ssh->kex->server = is_server;
	ఒకవేళ (is_server) {
#నిర్వచితమైతే WITH_OPENSSL
		ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
		ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
		ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
#అయితే_ముగింపు /* WITH_OPENSSL */
		ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
		ssh->kex->ఎక్కించు_host_ప్రజా_కీలకం=&ssh_host_ప్రజా_కీలకం;
		ssh->kex->ఎక్కించు_host_వ్యక్తిగత_కీలకం=&ssh_host_వ్యక్తిగత_కీలకం;
		ssh->kex->sign=&ssh_host_కీలకం_sign;
	} లేకపోతే {
#నిర్వచితమైతే WITH_OPENSSL
		ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
		ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
		ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#అయితే_ముగింపు /* WITH_OPENSSL */
		ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
		ssh->kex->verify_host_కీలకం =&ssh_verify_host_కీలకం;
	}
	*sshp = ssh;
	తిరిగి 0;
}

శూన్య
ssh_free(నిర్మాణం ssh *ssh)
{
	నిర్మాణం కీలకం_నమోదు *k;

	ఒకవేళ (ssh == ఖాళీ)
		తిరిగి;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	అయితే ((k = TAILQ_FIRST(&ssh->ప్రజా_కీలకాలు)) != ఖాళీ) {
		TAILQ_REMOVE(&ssh->ప్రజా_కీలకాలు, k, తదుపరి);
		ఒకవేళ (ssh->kex && ssh->kex->server)
			sshkey_free(k->కీలకం);
		విడుదల(k);
	}
	అయితే ((k = TAILQ_FIRST(&ssh->వ్యక్తిగత_కీలకాలు)) != ఖాళీ) {
		TAILQ_REMOVE(&ssh->వ్యక్తిగత_కీలకాలు, k, తదుపరి);
		విడుదల(k);
	}
	ssh_packet_close(ssh);
	విడుదల(ssh);
}

శూన్య
ssh_సమితి_app_దత్తాంశం(నిర్మాణం ssh *ssh, శూన్య *app_దత్తాంశం)
{
	ssh->app_దత్తాంశం = app_దత్తాంశం;
}

శూన్య *
ssh_get_app_దత్తాంశం(నిర్మాణం ssh *ssh)
{
	తిరిగి ssh->app_దత్తాంశం;
}

/* Returns < 0 on error, 0 otherwise */
పూర్ణాంకం
ssh_కూడు_hostkey(నిర్మాణం ssh *ssh, నిర్మాణం sshkey *కీలకం)
{
	నిర్మాణం sshkey *pubkey = ఖాళీ;
	నిర్మాణం కీలకం_నమోదు *k = ఖాళీ, *k_prv = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ (ssh->kex->server) {
		ఒకవేళ ((r = sshkey_from_వ్యక్తిగత(కీలకం, &pubkey)) != 0)
			తిరిగి r;
		ఒకవేళ ((k = జ్ఞాపకం_ఇవ్వు(పరిమాణం(*k))) == ఖాళీ ||
		    (k_prv = జ్ఞాపకం_ఇవ్వు(పరిమాణం(*k_prv))) == ఖాళీ) {
			విడుదల(k);
			sshkey_free(pubkey);
			తిరిగి SSH_ERR_ALLOC_FAIL;
		}
		k_prv->కీలకం = కీలకం;
		TAILQ_INSERT_TAIL(&ssh->వ్యక్తిగత_కీలకాలు, k_prv, తదుపరి);

		/* add the public key, too */
		k->కీలకం = pubkey;
		TAILQ_INSERT_TAIL(&ssh->ప్రజా_కీలకాలు, k, తదుపరి);
		r = 0;
	} లేకపోతే {
		ఒకవేళ ((k = జ్ఞాపకం_ఇవ్వు(పరిమాణం(*k))) == ఖాళీ)
			తిరిగి SSH_ERR_ALLOC_FAIL;
		k->కీలకం = కీలకం;
		TAILQ_INSERT_TAIL(&ssh->ప్రజా_కీలకాలు, k, తదుపరి);
		r = 0;
	}

	తిరిగి r;
}

పూర్ణాంకం
ssh_సమితి_verify_host_కీలకం_callback(నిర్మాణం ssh *ssh,
    పూర్ణాంకం (*cb)(నిర్మాణం sshkey *, నిర్మాణం ssh *))
{
	ఒకవేళ (cb == ఖాళీ || ssh->kex == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;

	ssh->kex->verify_host_కీలకం = cb;

	తిరిగి 0;
}

పూర్ణాంకం
ssh_ఆదానం_append(నిర్మాణం ssh *ssh, స్థిరరాశి u_char *దత్తాంశం, కొలత_t len)
{
	తిరిగి sshbuf_put(ssh_packet_get_ఆదానం(ssh), దత్తాంశం, len);
}

పూర్ణాంకం
ssh_packet_తదుపరి(నిర్మాణం ssh *ssh, u_char *typep)
{
	పూర్ణాంకం r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_సందేశం_NONE;
	ఒకవేళ (sshbuf_len(ssh->kex->client_సంస్కరణ) == 0 ||
	    sshbuf_len(ssh->kex->server_సంస్కరణ) == 0)
		తిరిగి _ssh_exchange_banner(ssh);
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
	కొరకు (;;) {
		ఒకవేళ ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			తిరిగి r;
		ఒకవేళ (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_సందేశం_KEXINIT && type <= SSH2_సందేశం_TRANSPORT_MAX &&
		    ssh->dispatch[type] != ఖాళీ) {
			ఒకవేళ ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				తిరిగి r;
		} లేకపోతే {
			*typep = type;
			తిరిగి 0;
		}
	}
}

స్థిరరాశి u_char *
ssh_packet_payload(నిర్మాణం ssh *ssh, కొలత_t *lenp)
{
	తిరిగి sshpkt_ptr(ssh, lenp);
}

పూర్ణాంకం
ssh_packet_put(నిర్మాణం ssh *ssh, పూర్ణాంకం type, స్థిరరాశి u_char *దత్తాంశం, కొలత_t len)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, దత్తాంశం, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		తిరిగి r;
	తిరిగి 0;
}

స్థిరరాశి u_char *
ssh_output_ptr(నిర్మాణం ssh *ssh, కొలత_t *len)
{
	నిర్మాణం sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	తిరిగి sshbuf_ptr(output);
}

పూర్ణాంకం
ssh_output_consume(నిర్మాణం ssh *ssh, కొలత_t len)
{
	తిరిగి sshbuf_consume(ssh_packet_get_output(ssh), len);
}

పూర్ణాంకం
ssh_output_space(నిర్మాణం ssh *ssh, కొలత_t len)
{
	తిరిగి (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

పూర్ణాంకం
ssh_ఆదానం_space(నిర్మాణం ssh *ssh, కొలత_t len)
{
	తిరిగి (0 == sshbuf_check_reserve(ssh_packet_get_ఆదానం(ssh), len));
}

/* Read other side's version identification. */
పూర్ణాంకం
_ssh_read_banner(నిర్మాణం ssh *ssh, నిర్మాణం sshbuf *banner)
{
	నిర్మాణం sshbuf *ఆదానం = ssh_packet_get_ఆదానం(ssh);
	స్థిరరాశి అక్షరం *mismatch = "Protocol mismatch.\r\n";
	స్థిరరాశి u_char *s = sshbuf_ptr(ఆదానం);
	u_char c;
	అక్షరం *cp = ఖాళీ, *remote_సంస్కరణ = ఖాళీ;
	పూర్ణాంకం r = 0, remote_major, remote_minor, expect_nl;
	కొలత_t n, j;

	కొరకు (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		కొరకు (;;) {
			ఒకవేళ (j >= sshbuf_len(ఆదానం))
				తిరిగి 0; /* insufficient data in input buf */
			c = s[j++];
			ఒకవేళ (c == '\r') {
				expect_nl = 1;
				కొనసాగు;
			}
			ఒకవేళ (c == '\n')
				ఆపు;
			ఒకవేళ (expect_nl)
				వెళ్ళు bad;
			ఒకవేళ ((r = sshbuf_put_u8(banner, c)) != 0)
				తిరిగి r;
			ఒకవేళ (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				వెళ్ళు bad;
		}
		ఒకవేళ (sshbuf_len(banner) >= 4 &&
		    memcmp(sshbuf_ptr(banner), "SSH-", 4) == 0)
			ఆపు;
		debug_f("%.*s", (పూర్ణాంకం)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		ఒకవేళ (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_పంక్తులు) {
  bad:
			ఒకవేళ ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, అక్షరశ్రేణి_పొడవు(mismatch))) != 0)
				తిరిగి r;
			తిరిగి SSH_ERR_NO_PROTOCOL_సంస్కరణ;
		}
	}
	ఒకవేళ ((r = sshbuf_consume(ఆదానం, j)) != 0)
		తిరిగి r;

	/* XXX remote version must be the same size as banner for sscanf */
	ఒకవేళ ((cp = sshbuf_dup_string(banner)) == ఖాళీ ||
	    (remote_సంస్కరణ = సున్నా_జ్ఞాపకం_ఇవ్వు(1, sshbuf_len(banner))) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	ఒకవేళ (అక్షరశ్రేణి_చదువు(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_సంస్కరణ) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_సంస్కరణ);

	compat_banner(ssh, remote_సంస్కరణ);
	ఒకవేళ  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	ఒకవేళ (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 బహిర్గతం:
	విడుదల(cp);
	విడుదల(remote_సంస్కరణ);
	తిరిగి r;
}

/* Send our own protocol version identification. */
పూర్ణాంకం
_ssh_send_banner(నిర్మాణం ssh *ssh, నిర్మాణం sshbuf *banner)
{
	అక్షరం *cp;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_సంస్కరణ)) != 0)
		తిరిగి r;
	ఒకవేళ ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		తిరిగి r;
	/* Remove trailing \r\n */
	ఒకవేళ ((r = sshbuf_consume_చివర(banner, 2)) != 0)
		తిరిగి r;
	ఒకవేళ ((cp = sshbuf_dup_string(banner)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	విడుదల(cp);
	తిరిగి 0;
}

పూర్ణాంకం
_ssh_exchange_banner(నిర్మాణం ssh *ssh)
{
	నిర్మాణం kex *kex = ssh->kex;
	పూర్ణాంకం r;

	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */

	r = 0;
	ఒకవేళ (kex->server) {
		ఒకవేళ (sshbuf_len(ssh->kex->server_సంస్కరణ) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_సంస్కరణ);
		ఒకవేళ (r == 0 &&
		    sshbuf_len(ssh->kex->server_సంస్కరణ) != 0 &&
		    sshbuf_len(ssh->kex->client_సంస్కరణ) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_సంస్కరణ);
	} లేకపోతే {
		ఒకవేళ (sshbuf_len(ssh->kex->server_సంస్కరణ) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_సంస్కరణ);
		ఒకవేళ (r == 0 &&
		    sshbuf_len(ssh->kex->server_సంస్కరణ) != 0 &&
		    sshbuf_len(ssh->kex->client_సంస్కరణ) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_సంస్కరణ);
	}
	ఒకవేళ (r != 0)
		తిరిగి r;
	/* start initial kex as soon as we have exchanged the banners */
	ఒకవేళ (sshbuf_len(ssh->kex->server_సంస్కరణ) != 0 &&
	    sshbuf_len(ssh->kex->client_సంస్కరణ) != 0) {
		ఒకవేళ ((r = ssh_క్రమం_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			తిరిగి r;
	}
	తిరిగి 0;
}

నిర్మాణం sshkey *
ssh_host_ప్రజా_కీలకం(పూర్ణాంకం type, పూర్ణాంకం nid, నిర్మాణం ssh *ssh)
{
	నిర్మాణం కీలకం_నమోదు *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->ప్రజా_కీలకాలు, తదుపరి) {
		debug3_f("check %s", sshkey_type(k->కీలకం));
		ఒకవేళ (k->కీలకం->type == type &&
		    (type != కీలకం_ECDSA || k->కీలకం->ecdsa_nid == nid))
			తిరిగి (k->కీలకం);
	}
	తిరిగి (ఖాళీ);
}

నిర్మాణం sshkey *
ssh_host_వ్యక్తిగత_కీలకం(పూర్ణాంకం type, పూర్ణాంకం nid, నిర్మాణం ssh *ssh)
{
	నిర్మాణం కీలకం_నమోదు *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->వ్యక్తిగత_కీలకాలు, తదుపరి) {
		debug3_f("check %s", sshkey_type(k->కీలకం));
		ఒకవేళ (k->కీలకం->type == type &&
		    (type != కీలకం_ECDSA || k->కీలకం->ecdsa_nid == nid))
			తిరిగి (k->కీలకం);
	}
	తిరిగి (ఖాళీ);
}

పూర్ణాంకం
ssh_verify_host_కీలకం(నిర్మాణం sshkey *hostkey, నిర్మాణం ssh *ssh)
{
	నిర్మాణం కీలకం_నమోదు *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->ప్రజా_కీలకాలు, తదుపరి) {
		debug3_f("check %s", sshkey_type(k->కీలకం));
		ఒకవేళ (sshkey_equal_ప్రజా(hostkey, k->కీలకం))
			తిరిగి (0);	/* ok */
	}
	తిరిగి (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
పూర్ణాంకం
ssh_క్రమం_hostkeyalgs(నిర్మాణం ssh *ssh)
{
	నిర్మాణం కీలకం_నమోదు *k;
	అక్షరం *orig, *avail, *oavail = ఖాళీ, *alg, *replace = ఖాళీ;
	అక్షరం **proposal;
	కొలత_t maxlen;
	పూర్ణాంకం ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	ఒకవేళ ((r = kex_buf2prop(ssh->kex->my, ఖాళీ, &proposal)) != 0)
		తిరిగి r;
	orig = proposal[PROPOSAL_SERVER_HOST_కీలకం_ALGS];
	ఒకవేళ ((oavail = avail = strdup(orig)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	maxlen = అక్షరశ్రేణి_పొడవు(avail) + 1;
	ఒకవేళ ((replace = సున్నా_జ్ఞాపకం_ఇవ్వు(1, maxlen)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	*replace = '\0';
	అయితే ((alg = strsep(&avail, ",")) && *alg != '\0') {
		ఒకవేళ ((ktype = sshkey_type_from_name(alg)) == కీలకం_UNSPEC)
			కొనసాగు;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->ప్రజా_కీలకాలు, తదుపరి) {
			ఒకవేళ (k->కీలకం->type != ktype &&
			    (!sshkey_is_cert(k->కీలకం) ||
			    k->కీలకం->type != sshkey_type_plain(ktype)))
				కొనసాగు;
			ఒకవేళ (sshkey_type_plain(k->కీలకం->type) == కీలకం_ECDSA &&
			    k->కీలకం->ecdsa_nid != nid)
				కొనసాగు;
			/* Candidate */
			ఒకవేళ (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			ఆపు;
		}
	}
	ఒకవేళ (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		విడుదల(orig);
		proposal[PROPOSAL_SERVER_HOST_కీలకం_ALGS] = replace;
		replace = ఖాళీ;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 బహిర్గతం:
	విడుదల(oavail);
	విడుదల(replace);
	kex_prop_free(proposal);
	తిరిగి r;
}

పూర్ణాంకం
ssh_host_కీలకం_sign(నిర్మాణం ssh *ssh, నిర్మాణం sshkey *privkey,
    నిర్మాణం sshkey *pubkey, u_char **signature, కొలత_t *slen,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t dlen, స్థిరరాశి అక్షరం *alg)
{
	తిరిగి sshkey_sign(privkey, signature, slen, దత్తాంశం, dlen,
	    alg, ఖాళీ, ఖాళీ, ssh->compat);
}
