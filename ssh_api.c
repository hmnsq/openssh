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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <stdio.h>
#شامل <stdlib.h>

#شامل "ssh_api.h"
#شامل "compat.h"
#شامل "log.h"
#شامل "authfile.h"
#شامل "sshkey.h"
#شامل "dh.h"
#شامل "misc.h"
#شامل "ssh2.h"
#شامل "version.h"
#شامل "myproposal.h"
#شامل "ssherr.h"
#شامل "sshbuf.h"

#شامل "openbsd-compat/openssl-compat.h"

#شامل <string.h>

صحیح	_ssh_exchange_banner(ساختار ssh *);
صحیح	_ssh_send_banner(ساختار ssh *, ساختار sshbuf *);
صحیح	_ssh_read_banner(ساختار ssh *, ساختار sshbuf *);
صحیح	_ssh_order_hostkeyalgs(ساختار ssh *);
صحیح	ssh_verify_host_کلید(ساختار sshkey *, ساختار ssh *);
ساختار sshkey *ssh_host_public_کلید(صحیح, صحیح, ساختار ssh *);
ساختار sshkey *ssh_host_private_کلید(صحیح, صحیح, ساختار ssh *);
صحیح	ssh_host_کلید_sign(ساختار ssh *, ساختار sshkey *, ساختار sshkey *,
    u_char **, size_t *, ثابت u_char *, size_t, ثابت نویسه *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
صحیح	mm_sshkey_sign(ساختار sshkey *, u_char **, u_int *,
    ثابت u_char *, u_int, ثابت نویسه *, ثابت نویسه *, ثابت نویسه *, u_int);

#ifdef WITH_OPENSSL
DH	*mm_choose_dh(صحیح, صحیح, صحیح);
#endif

صحیح
mm_sshkey_sign(ساختار sshkey *کلید, u_char **sigp, u_int *lenp,
    ثابت u_char *data, u_int datalen, ثابت نویسه *alg,
    ثابت نویسه *sk_provider, ثابت نویسه *sk_pin, u_int compat)
{
	size_t slen = 0;
	صحیح ret;

	ret = sshkey_sign(کلید, sigp, &slen, data, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	بازگشت ret;
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(صحیح min, صحیح nbits, صحیح max)
{
	بازگشت choose_dh(min, nbits, max);
}
#endif

/* API */

صحیح
ssh_init(ساختار ssh **sshp, صحیح is_server, ساختار kex_params *kex_params)
{
	نویسه *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	نویسه *populated[PROPOSAL_MAX];
	ساختار ssh *ssh;
	نویسه **proposal;
	ایستا صحیح called;
	صحیح r;

	اگر (!called) {
		seed_rng();
		called = 1;
	}

	اگر ((ssh = ssh_packet_set_connection(پوچ, -1, -1)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر (is_server)
		ssh_packet_set_server(ssh);

	/* Initialize key exchange */
	proposal = kex_params ? kex_params->proposal : myproposal;
	kex_proposal_populate_entries(ssh, populated,
	    proposal[PROPOSAL_KEX_ALGS],
	    proposal[PROPOSAL_ENC_ALGS_CTOS],
	    proposal[PROPOSAL_MAC_ALGS_CTOS],
	    proposal[PROPOSAL_COMP_ALGS_CTOS],
	    proposal[PROPOSAL_SERVER_HOST_کلید_ALGS]);
	r = kex_ready(ssh, populated);
	kex_proposal_free_entries(populated);
	اگر (r != 0) {
		ssh_free(ssh);
		بازگشت r;
	}

	ssh->kex->server = is_server;
	اگر (is_server) {
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
		ssh->kex->load_host_public_کلید=&ssh_host_public_کلید;
		ssh->kex->load_host_private_کلید=&ssh_host_private_کلید;
		ssh->kex->sign=&ssh_host_کلید_sign;
	} وگرنه {
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
		ssh->kex->verify_host_کلید =&ssh_verify_host_کلید;
	}
	*sshp = ssh;
	بازگشت 0;
}

تهی
ssh_free(ساختار ssh *ssh)
{
	ساختار کلید_entry *k;

	اگر (ssh == پوچ)
		بازگشت;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	وقتی ((k = TAILQ_FIRST(&ssh->public_کلیدها)) != پوچ) {
		TAILQ_REMOVE(&ssh->public_کلیدها, k, next);
		اگر (ssh->kex && ssh->kex->server)
			sshkey_free(k->کلید);
		آزاد(k);
	}
	وقتی ((k = TAILQ_FIRST(&ssh->private_کلیدها)) != پوچ) {
		TAILQ_REMOVE(&ssh->private_کلیدها, k, next);
		آزاد(k);
	}
	ssh_packet_close(ssh);
	آزاد(ssh);
}

تهی
ssh_set_app_data(ساختار ssh *ssh, تهی *app_data)
{
	ssh->app_data = app_data;
}

تهی *
ssh_get_app_data(ساختار ssh *ssh)
{
	بازگشت ssh->app_data;
}

/* Returns < 0 on error, 0 otherwise */
صحیح
ssh_add_hostkey(ساختار ssh *ssh, ساختار sshkey *کلید)
{
	ساختار sshkey *pubkey = پوچ;
	ساختار کلید_entry *k = پوچ, *k_prv = پوچ;
	صحیح r;

	اگر (ssh->kex->server) {
		اگر ((r = sshkey_from_private(کلید, &pubkey)) != 0)
			بازگشت r;
		اگر ((k = malloc(اندازه(*k))) == پوچ ||
		    (k_prv = malloc(اندازه(*k_prv))) == پوچ) {
			آزاد(k);
			sshkey_free(pubkey);
			بازگشت SSH_ERR_ALLOC_FAIL;
		}
		k_prv->کلید = کلید;
		TAILQ_INSERT_TAIL(&ssh->private_کلیدها, k_prv, next);

		/* add the public key, too */
		k->کلید = pubkey;
		TAILQ_INSERT_TAIL(&ssh->public_کلیدها, k, next);
		r = 0;
	} وگرنه {
		اگر ((k = malloc(اندازه(*k))) == پوچ)
			بازگشت SSH_ERR_ALLOC_FAIL;
		k->کلید = کلید;
		TAILQ_INSERT_TAIL(&ssh->public_کلیدها, k, next);
		r = 0;
	}

	بازگشت r;
}

صحیح
ssh_set_verify_host_کلید_callback(ساختار ssh *ssh,
    صحیح (*cb)(ساختار sshkey *, ساختار ssh *))
{
	اگر (cb == پوچ || ssh->kex == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;

	ssh->kex->verify_host_کلید = cb;

	بازگشت 0;
}

صحیح
ssh_درون_داد_append(ساختار ssh *ssh, ثابت u_char *data, size_t len)
{
	بازگشت sshbuf_put(ssh_packet_get_درون_داد(ssh), data, len);
}

صحیح
ssh_packet_next(ساختار ssh *ssh, u_char *typep)
{
	صحیح r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_پیام_NONE;
	اگر (sshbuf_len(ssh->kex->client_version) == 0 ||
	    sshbuf_len(ssh->kex->server_version) == 0)
		بازگشت _ssh_exchange_banner(ssh);
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
	برای (;;) {
		اگر ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			بازگشت r;
		اگر (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_پیام_KEXINIT && type <= SSH2_پیام_TRANSPORT_MAX &&
		    ssh->dispatch[type] != پوچ) {
			اگر ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				بازگشت r;
		} وگرنه {
			*typep = type;
			بازگشت 0;
		}
	}
}

ثابت u_char *
ssh_packet_payload(ساختار ssh *ssh, size_t *lenp)
{
	بازگشت sshpkt_ptr(ssh, lenp);
}

صحیح
ssh_packet_put(ساختار ssh *ssh, صحیح type, ثابت u_char *data, size_t len)
{
	صحیح r;

	اگر ((r = sshpkt_start(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, data, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		بازگشت r;
	بازگشت 0;
}

ثابت u_char *
ssh_output_ptr(ساختار ssh *ssh, size_t *len)
{
	ساختار sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	بازگشت sshbuf_ptr(output);
}

صحیح
ssh_output_consume(ساختار ssh *ssh, size_t len)
{
	بازگشت sshbuf_consume(ssh_packet_get_output(ssh), len);
}

صحیح
ssh_output_space(ساختار ssh *ssh, size_t len)
{
	بازگشت (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

صحیح
ssh_درون_داد_space(ساختار ssh *ssh, size_t len)
{
	بازگشت (0 == sshbuf_check_reserve(ssh_packet_get_درون_داد(ssh), len));
}

/* Read other side's version identification. */
صحیح
_ssh_read_banner(ساختار ssh *ssh, ساختار sshbuf *banner)
{
	ساختار sshbuf *درون_داد = ssh_packet_get_درون_داد(ssh);
	ثابت نویسه *mismatch = "Protocol mismatch.\r\n";
	ثابت u_char *s = sshbuf_ptr(درون_داد);
	u_char c;
	نویسه *cp = پوچ, *remote_version = پوچ;
	صحیح r = 0, remote_major, remote_minor, expect_nl;
	size_t n, j;

	برای (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		برای (;;) {
			اگر (j >= sshbuf_len(درون_داد))
				بازگشت 0; /* insufficient data in input buf */
			c = s[j++];
			اگر (c == '\r') {
				expect_nl = 1;
				ادامه;
			}
			اگر (c == '\n')
				بشکن;
			اگر (expect_nl)
				برو bad;
			اگر ((r = sshbuf_put_u8(banner, c)) != 0)
				بازگشت r;
			اگر (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				برو bad;
		}
		اگر (sshbuf_len(banner) >= 4 &&
		    memcmp(sshbuf_ptr(banner), "SSH-", 4) == 0)
			بشکن;
		debug_f("%.*s", (صحیح)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		اگر (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_سطرها) {
  bad:
			اگر ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, strlen(mismatch))) != 0)
				بازگشت r;
			بازگشت SSH_ERR_NO_PROTOCOL_VERSION;
		}
	}
	اگر ((r = sshbuf_consume(درون_داد, j)) != 0)
		بازگشت r;

	/* XXX remote version must be the same size as banner for sscanf */
	اگر ((cp = sshbuf_dup_string(banner)) == پوچ ||
	    (remote_version = calloc(1, sshbuf_len(banner))) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	اگر (sscanf(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);

	compat_banner(ssh, remote_version);
	اگر  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	اگر (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 out:
	آزاد(cp);
	آزاد(remote_version);
	بازگشت r;
}

/* Send our own protocol version identification. */
صحیح
_ssh_send_banner(ساختار ssh *ssh, ساختار sshbuf *banner)
{
	نویسه *cp;
	صحیح r;

	اگر ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_VERSION)) != 0)
		بازگشت r;
	اگر ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		بازگشت r;
	/* Remove trailing \r\n */
	اگر ((r = sshbuf_consume_end(banner, 2)) != 0)
		بازگشت r;
	اگر ((cp = sshbuf_dup_string(banner)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	آزاد(cp);
	بازگشت 0;
}

صحیح
_ssh_exchange_banner(ساختار ssh *ssh)
{
	ساختار kex *kex = ssh->kex;
	صحیح r;

	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */

	r = 0;
	اگر (kex->server) {
		اگر (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_version);
		اگر (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_version);
	} وگرنه {
		اگر (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_version);
		اگر (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_version);
	}
	اگر (r != 0)
		بازگشت r;
	/* start initial kex as soon as we have exchanged the banners */
	اگر (sshbuf_len(ssh->kex->server_version) != 0 &&
	    sshbuf_len(ssh->kex->client_version) != 0) {
		اگر ((r = _ssh_order_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			بازگشت r;
	}
	بازگشت 0;
}

ساختار sshkey *
ssh_host_public_کلید(صحیح type, صحیح nid, ساختار ssh *ssh)
{
	ساختار کلید_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->public_کلیدها, next) {
		debug3_f("check %s", sshkey_type(k->کلید));
		اگر (k->کلید->type == type &&
		    (type != کلید_ECDSA || k->کلید->ecdsa_nid == nid))
			بازگشت (k->کلید);
	}
	بازگشت (پوچ);
}

ساختار sshkey *
ssh_host_private_کلید(صحیح type, صحیح nid, ساختار ssh *ssh)
{
	ساختار کلید_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->private_کلیدها, next) {
		debug3_f("check %s", sshkey_type(k->کلید));
		اگر (k->کلید->type == type &&
		    (type != کلید_ECDSA || k->کلید->ecdsa_nid == nid))
			بازگشت (k->کلید);
	}
	بازگشت (پوچ);
}

صحیح
ssh_verify_host_کلید(ساختار sshkey *hostkey, ساختار ssh *ssh)
{
	ساختار کلید_entry *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->public_کلیدها, next) {
		debug3_f("check %s", sshkey_type(k->کلید));
		اگر (sshkey_equal_public(hostkey, k->کلید))
			بازگشت (0);	/* ok */
	}
	بازگشت (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
صحیح
_ssh_order_hostkeyalgs(ساختار ssh *ssh)
{
	ساختار کلید_entry *k;
	نویسه *orig, *avail, *oavail = پوچ, *alg, *replace = پوچ;
	نویسه **proposal;
	size_t maxlen;
	صحیح ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	اگر ((r = kex_buf2prop(ssh->kex->my, پوچ, &proposal)) != 0)
		بازگشت r;
	orig = proposal[PROPOSAL_SERVER_HOST_کلید_ALGS];
	اگر ((oavail = avail = strdup(orig)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	maxlen = strlen(avail) + 1;
	اگر ((replace = calloc(1, maxlen)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	*replace = '\0';
	وقتی ((alg = strsep(&avail, ",")) && *alg != '\0') {
		اگر ((ktype = sshkey_type_from_name(alg)) == کلید_UNSPEC)
			ادامه;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->public_کلیدها, next) {
			اگر (k->کلید->type != ktype &&
			    (!sshkey_is_cert(k->کلید) ||
			    k->کلید->type != sshkey_type_plain(ktype)))
				ادامه;
			اگر (sshkey_type_plain(k->کلید->type) == کلید_ECDSA &&
			    k->کلید->ecdsa_nid != nid)
				ادامه;
			/* Candidate */
			اگر (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			بشکن;
		}
	}
	اگر (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		آزاد(orig);
		proposal[PROPOSAL_SERVER_HOST_کلید_ALGS] = replace;
		replace = پوچ;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 out:
	آزاد(oavail);
	آزاد(replace);
	kex_prop_free(proposal);
	بازگشت r;
}

صحیح
ssh_host_کلید_sign(ساختار ssh *ssh, ساختار sshkey *privkey,
    ساختار sshkey *pubkey, u_char **signature, size_t *slen,
    ثابت u_char *data, size_t dlen, ثابت نویسه *alg)
{
	بازگشت sshkey_sign(privkey, signature, slen, data, dlen,
	    alg, پوچ, پوچ, ssh->compat);
}
