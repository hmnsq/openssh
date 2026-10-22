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

পূর্ণসংখ্যা	_ssh_exchange_banner(কাঠামো ssh *);
পূর্ণসংখ্যা	_ssh_send_banner(কাঠামো ssh *, কাঠামো sshbuf *);
পূর্ণসংখ্যা	_ssh_read_banner(কাঠামো ssh *, কাঠামো sshbuf *);
পূর্ণসংখ্যা	_ssh_order_hostkeyalgs(কাঠামো ssh *);
পূর্ণসংখ্যা	ssh_verify_host_চাবি(কাঠামো sshkey *, কাঠামো ssh *);
কাঠামো sshkey *ssh_host_public_চাবি(পূর্ণসংখ্যা, পূর্ণসংখ্যা, কাঠামো ssh *);
কাঠামো sshkey *ssh_host_private_চাবি(পূর্ণসংখ্যা, পূর্ণসংখ্যা, কাঠামো ssh *);
পূর্ণসংখ্যা	ssh_host_চাবি_sign(কাঠামো ssh *, কাঠামো sshkey *, কাঠামো sshkey *,
    u_char **, আকার_t *, ধ্রুবক u_char *, আকার_t, ধ্রুবক অক্ষর *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
পূর্ণসংখ্যা	mm_sshkey_sign(কাঠামো sshkey *, u_char **, u_int *,
    ধ্রুবক u_char *, u_int, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, u_int);

#ifdef WITH_OPENSSL
DH	*mm_choose_dh(পূর্ণসংখ্যা, পূর্ণসংখ্যা, পূর্ণসংখ্যা);
#endif

পূর্ণসংখ্যা
mm_sshkey_sign(কাঠামো sshkey *চাবি, u_char **sigp, u_int *lenp,
    ধ্রুবক u_char *তথ্য, u_int datalen, ধ্রুবক অক্ষর *alg,
    ধ্রুবক অক্ষর *sk_provider, ধ্রুবক অক্ষর *sk_pin, u_int compat)
{
	আকার_t slen = 0;
	পূর্ণসংখ্যা ret;

	ret = sshkey_sign(চাবি, sigp, &slen, তথ্য, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	ফেরত ret;
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(পূর্ণসংখ্যা min, পূর্ণসংখ্যা nbits, পূর্ণসংখ্যা max)
{
	ফেরত choose_dh(min, nbits, max);
}
#endif

/* API */

পূর্ণসংখ্যা
ssh_init(কাঠামো ssh **sshp, পূর্ণসংখ্যা is_server, কাঠামো kex_params *kex_params)
{
	অক্ষর *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	অক্ষর *populated[PROPOSAL_MAX];
	কাঠামো ssh *ssh;
	অক্ষর **proposal;
	স্থির পূর্ণসংখ্যা called;
	পূর্ণসংখ্যা r;

	যদি (!called) {
		seed_rng();
		called = 1;
	}

	যদি ((ssh = ssh_packet_set_connection(ফাঁকা, -1, -1)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
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
		ফেরত r;
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
	ফেরত 0;
}

শূন্য
ssh_free(কাঠামো ssh *ssh)
{
	কাঠামো চাবি_entry *k;

	যদি (ssh == ফাঁকা)
		ফেরত;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	যখন ((k = TAILQ_FIRST(&ssh->public_চাবিগুলি)) != ফাঁকা) {
		TAILQ_REMOVE(&ssh->public_চাবিগুলি, k, পরবর্তী);
		যদি (ssh->kex && ssh->kex->server)
			sshkey_free(k->চাবি);
		মুক্ত(k);
	}
	যখন ((k = TAILQ_FIRST(&ssh->private_চাবিগুলি)) != ফাঁকা) {
		TAILQ_REMOVE(&ssh->private_চাবিগুলি, k, পরবর্তী);
		মুক্ত(k);
	}
	ssh_packet_close(ssh);
	মুক্ত(ssh);
}

শূন্য
ssh_set_app_তথ্য(কাঠামো ssh *ssh, শূন্য *app_তথ্য)
{
	ssh->app_তথ্য = app_তথ্য;
}

শূন্য *
ssh_get_app_তথ্য(কাঠামো ssh *ssh)
{
	ফেরত ssh->app_তথ্য;
}

/* Returns < 0 on error, 0 otherwise */
পূর্ণসংখ্যা
ssh_add_hostkey(কাঠামো ssh *ssh, কাঠামো sshkey *চাবি)
{
	কাঠামো sshkey *pubkey = ফাঁকা;
	কাঠামো চাবি_entry *k = ফাঁকা, *k_prv = ফাঁকা;
	পূর্ণসংখ্যা r;

	যদি (ssh->kex->server) {
		যদি ((r = sshkey_from_private(চাবি, &pubkey)) != 0)
			ফেরত r;
		যদি ((k = malloc(আকার(*k))) == ফাঁকা ||
		    (k_prv = malloc(আকার(*k_prv))) == ফাঁকা) {
			মুক্ত(k);
			sshkey_free(pubkey);
			ফেরত SSH_ERR_ALLOC_FAIL;
		}
		k_prv->চাবি = চাবি;
		TAILQ_INSERT_TAIL(&ssh->private_চাবিগুলি, k_prv, পরবর্তী);

		/* add the public key, too */
		k->চাবি = pubkey;
		TAILQ_INSERT_TAIL(&ssh->public_চাবিগুলি, k, পরবর্তী);
		r = 0;
	} অন্যথা {
		যদি ((k = malloc(আকার(*k))) == ফাঁকা)
			ফেরত SSH_ERR_ALLOC_FAIL;
		k->চাবি = চাবি;
		TAILQ_INSERT_TAIL(&ssh->public_চাবিগুলি, k, পরবর্তী);
		r = 0;
	}

	ফেরত r;
}

পূর্ণসংখ্যা
ssh_set_verify_host_চাবি_callback(কাঠামো ssh *ssh,
    পূর্ণসংখ্যা (*cb)(কাঠামো sshkey *, কাঠামো ssh *))
{
	যদি (cb == ফাঁকা || ssh->kex == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;

	ssh->kex->verify_host_চাবি = cb;

	ফেরত 0;
}

পূর্ণসংখ্যা
ssh_প্রবেশ_append(কাঠামো ssh *ssh, ধ্রুবক u_char *তথ্য, আকার_t len)
{
	ফেরত sshbuf_put(ssh_packet_get_প্রবেশ(ssh), তথ্য, len);
}

পূর্ণসংখ্যা
ssh_packet_পরবর্তী(কাঠামো ssh *ssh, u_char *typep)
{
	পূর্ণসংখ্যা r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_বার্তা_NONE;
	যদি (sshbuf_len(ssh->kex->client_version) == 0 ||
	    sshbuf_len(ssh->kex->server_version) == 0)
		ফেরত _ssh_exchange_banner(ssh);
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
	জন্য (;;) {
		যদি ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			ফেরত r;
		যদি (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_বার্তা_KEXINIT && type <= SSH2_বার্তা_TRANSPORT_MAX &&
		    ssh->dispatch[type] != ফাঁকা) {
			যদি ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				ফেরত r;
		} অন্যথা {
			*typep = type;
			ফেরত 0;
		}
	}
}

ধ্রুবক u_char *
ssh_packet_payload(কাঠামো ssh *ssh, আকার_t *lenp)
{
	ফেরত sshpkt_ptr(ssh, lenp);
}

পূর্ণসংখ্যা
ssh_packet_put(কাঠামো ssh *ssh, পূর্ণসংখ্যা type, ধ্রুবক u_char *তথ্য, আকার_t len)
{
	পূর্ণসংখ্যা r;

	যদি ((r = sshpkt_start(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, তথ্য, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ফেরত r;
	ফেরত 0;
}

ধ্রুবক u_char *
ssh_output_ptr(কাঠামো ssh *ssh, আকার_t *len)
{
	কাঠামো sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	ফেরত sshbuf_ptr(output);
}

পূর্ণসংখ্যা
ssh_output_consume(কাঠামো ssh *ssh, আকার_t len)
{
	ফেরত sshbuf_consume(ssh_packet_get_output(ssh), len);
}

পূর্ণসংখ্যা
ssh_output_space(কাঠামো ssh *ssh, আকার_t len)
{
	ফেরত (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

পূর্ণসংখ্যা
ssh_প্রবেশ_space(কাঠামো ssh *ssh, আকার_t len)
{
	ফেরত (0 == sshbuf_check_reserve(ssh_packet_get_প্রবেশ(ssh), len));
}

/* Read other side's version identification. */
পূর্ণসংখ্যা
_ssh_read_banner(কাঠামো ssh *ssh, কাঠামো sshbuf *banner)
{
	কাঠামো sshbuf *প্রবেশ = ssh_packet_get_প্রবেশ(ssh);
	ধ্রুবক অক্ষর *mismatch = "Protocol mismatch.\r\n";
	ধ্রুবক u_char *s = sshbuf_ptr(প্রবেশ);
	u_char c;
	অক্ষর *cp = ফাঁকা, *remote_version = ফাঁকা;
	পূর্ণসংখ্যা r = 0, remote_major, remote_minor, expect_nl;
	আকার_t n, j;

	জন্য (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		জন্য (;;) {
			যদি (j >= sshbuf_len(প্রবেশ))
				ফেরত 0; /* insufficient data in input buf */
			c = s[j++];
			যদি (c == '\r') {
				expect_nl = 1;
				চালু;
			}
			যদি (c == '\n')
				বিরতি;
			যদি (expect_nl)
				যাও bad;
			যদি ((r = sshbuf_put_u8(banner, c)) != 0)
				ফেরত r;
			যদি (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				যাও bad;
		}
		যদি (sshbuf_len(banner) >= 4 &&
		    memcmp(sshbuf_ptr(banner), "SSH-", 4) == 0)
			বিরতি;
		debug_f("%.*s", (পূর্ণসংখ্যা)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		যদি (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_সারিগুলি) {
  bad:
			যদি ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, strlen(mismatch))) != 0)
				ফেরত r;
			ফেরত SSH_ERR_NO_PROTOCOL_VERSION;
		}
	}
	যদি ((r = sshbuf_consume(প্রবেশ, j)) != 0)
		ফেরত r;

	/* XXX remote version must be the same size as banner for sscanf */
	যদি ((cp = sshbuf_dup_string(banner)) == ফাঁকা ||
	    (remote_version = calloc(1, sshbuf_len(banner))) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	যদি (sscanf(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
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
	ফেরত r;
}

/* Send our own protocol version identification. */
পূর্ণসংখ্যা
_ssh_send_banner(কাঠামো ssh *ssh, কাঠামো sshbuf *banner)
{
	অক্ষর *cp;
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_VERSION)) != 0)
		ফেরত r;
	যদি ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		ফেরত r;
	/* Remove trailing \r\n */
	যদি ((r = sshbuf_consume_end(banner, 2)) != 0)
		ফেরত r;
	যদি ((cp = sshbuf_dup_string(banner)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	মুক্ত(cp);
	ফেরত 0;
}

পূর্ণসংখ্যা
_ssh_exchange_banner(কাঠামো ssh *ssh)
{
	কাঠামো kex *kex = ssh->kex;
	পূর্ণসংখ্যা r;

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
		ফেরত r;
	/* start initial kex as soon as we have exchanged the banners */
	যদি (sshbuf_len(ssh->kex->server_version) != 0 &&
	    sshbuf_len(ssh->kex->client_version) != 0) {
		যদি ((r = _ssh_order_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			ফেরত r;
	}
	ফেরত 0;
}

কাঠামো sshkey *
ssh_host_public_চাবি(পূর্ণসংখ্যা type, পূর্ণসংখ্যা nid, কাঠামো ssh *ssh)
{
	কাঠামো চাবি_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->public_চাবিগুলি, পরবর্তী) {
		debug3_f("check %s", sshkey_type(k->চাবি));
		যদি (k->চাবি->type == type &&
		    (type != চাবি_ECDSA || k->চাবি->ecdsa_nid == nid))
			ফেরত (k->চাবি);
	}
	ফেরত (ফাঁকা);
}

কাঠামো sshkey *
ssh_host_private_চাবি(পূর্ণসংখ্যা type, পূর্ণসংখ্যা nid, কাঠামো ssh *ssh)
{
	কাঠামো চাবি_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->private_চাবিগুলি, পরবর্তী) {
		debug3_f("check %s", sshkey_type(k->চাবি));
		যদি (k->চাবি->type == type &&
		    (type != চাবি_ECDSA || k->চাবি->ecdsa_nid == nid))
			ফেরত (k->চাবি);
	}
	ফেরত (ফাঁকা);
}

পূর্ণসংখ্যা
ssh_verify_host_চাবি(কাঠামো sshkey *hostkey, কাঠামো ssh *ssh)
{
	কাঠামো চাবি_entry *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->public_চাবিগুলি, পরবর্তী) {
		debug3_f("check %s", sshkey_type(k->চাবি));
		যদি (sshkey_equal_public(hostkey, k->চাবি))
			ফেরত (0);	/* ok */
	}
	ফেরত (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
পূর্ণসংখ্যা
_ssh_order_hostkeyalgs(কাঠামো ssh *ssh)
{
	কাঠামো চাবি_entry *k;
	অক্ষর *orig, *avail, *oavail = ফাঁকা, *alg, *replace = ফাঁকা;
	অক্ষর **proposal;
	আকার_t maxlen;
	পূর্ণসংখ্যা ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	যদি ((r = kex_buf2prop(ssh->kex->my, ফাঁকা, &proposal)) != 0)
		ফেরত r;
	orig = proposal[PROPOSAL_SERVER_HOST_চাবি_ALGS];
	যদি ((oavail = avail = strdup(orig)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	maxlen = strlen(avail) + 1;
	যদি ((replace = calloc(1, maxlen)) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	*replace = '\0';
	যখন ((alg = strsep(&avail, ",")) && *alg != '\0') {
		যদি ((ktype = sshkey_type_from_name(alg)) == চাবি_UNSPEC)
			চালু;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->public_চাবিগুলি, পরবর্তী) {
			যদি (k->চাবি->type != ktype &&
			    (!sshkey_is_cert(k->চাবি) ||
			    k->চাবি->type != sshkey_type_plain(ktype)))
				চালু;
			যদি (sshkey_type_plain(k->চাবি->type) == চাবি_ECDSA &&
			    k->চাবি->ecdsa_nid != nid)
				চালু;
			/* Candidate */
			যদি (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			বিরতি;
		}
	}
	যদি (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		মুক্ত(orig);
		proposal[PROPOSAL_SERVER_HOST_চাবি_ALGS] = replace;
		replace = ফাঁকা;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 out:
	মুক্ত(oavail);
	মুক্ত(replace);
	kex_prop_free(proposal);
	ফেরত r;
}

পূর্ণসংখ্যা
ssh_host_চাবি_sign(কাঠামো ssh *ssh, কাঠামো sshkey *privkey,
    কাঠামো sshkey *pubkey, u_char **signature, আকার_t *slen,
    ধ্রুবক u_char *তথ্য, আকার_t dlen, ধ্রুবক অক্ষর *alg)
{
	ফেরত sshkey_sign(privkey, signature, slen, তথ্য, dlen,
	    alg, ফাঁকা, ফাঁকা, ssh->compat);
}
