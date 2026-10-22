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

صحیح	_ssh_exchange_banner(ساخت ssh *);
صحیح	_ssh_send_banner(ساخت ssh *, ساخت sshbuf *);
صحیح	_ssh_read_banner(ساخت ssh *, ساخت sshbuf *);
صحیح	ssh_ترتیب_hostkeyalgs(ساخت ssh *);
صحیح	ssh_verify_host_کلید(ساخت sshkey *, ساخت ssh *);
ساخت sshkey *ssh_host_عوامی_کلید(صحیح, صحیح, ساخت ssh *);
ساخت sshkey *ssh_host_نجی_کلید(صحیح, صحیح, ساخت ssh *);
صحیح	ssh_host_کلید_sign(ساخت ssh *, ساخت sshkey *, ساخت sshkey *,
    u_char **, سائز_t *, ثابت u_char *, سائز_t, ثابت حرف *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
صحیح	mm_sshkey_sign(ساخت sshkey *, u_char **, u_int *,
    ثابت u_char *, u_int, ثابت حرف *, ثابت حرف *, ثابت حرف *, u_int);

#اگر_تعریف_شدہ WITH_OPENSSL
DH	*mm_انتخاب_dh(صحیح, صحیح, صحیح);
#اگر_ختم

صحیح
mm_sshkey_sign(ساخت sshkey *کلید, u_char **sigp, u_int *lenp,
    ثابت u_char *ڈیٹا, u_int datalen, ثابت حرف *alg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin, u_int compat)
{
	سائز_t slen = 0;
	صحیح ret;

	ret = sshkey_sign(کلید, sigp, &slen, ڈیٹا, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	واپس ret;
}

#اگر_تعریف_شدہ WITH_OPENSSL
DH *
mm_انتخاب_dh(صحیح min, صحیح nbits, صحیح max)
{
	واپس انتخاب_dh(min, nbits, max);
}
#اگر_ختم

/* API */

صحیح
ssh_init(ساخت ssh **sshp, صحیح is_server, ساخت kex_params *kex_params)
{
	حرف *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	حرف *populated[PROPOSAL_MAX];
	ساخت ssh *ssh;
	حرف **proposal;
	ساکن صحیح called;
	صحیح r;

	اگر (!called) {
		بیج_rng();
		called = 1;
	}

	اگر ((ssh = ssh_packet_سیٹ_connection(تہی, -1, -1)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر (is_server)
		ssh_packet_سیٹ_server(ssh);

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
		واپس r;
	}

	ssh->kex->server = is_server;
	اگر (is_server) {
#اگر_تعریف_شدہ WITH_OPENSSL
		ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
		ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
		ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
#اگر_ختم /* WITH_OPENSSL */
		ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
		ssh->kex->بھرو_host_عوامی_کلید=&ssh_host_عوامی_کلید;
		ssh->kex->بھرو_host_نجی_کلید=&ssh_host_نجی_کلید;
		ssh->kex->sign=&ssh_host_کلید_sign;
	} ورنہ {
#اگر_تعریف_شدہ WITH_OPENSSL
		ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
		ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
		ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#اگر_ختم /* WITH_OPENSSL */
		ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
		ssh->kex->verify_host_کلید =&ssh_verify_host_کلید;
	}
	*sshp = ssh;
	واپس 0;
}

خالی
ssh_free(ساخت ssh *ssh)
{
	ساخت کلید_اندراج *k;

	اگر (ssh == تہی)
		واپس;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	جب ((k = TAILQ_FIRST(&ssh->عوامی_کلیدیں)) != تہی) {
		TAILQ_REMOVE(&ssh->عوامی_کلیدیں, k, اگلا);
		اگر (ssh->kex && ssh->kex->server)
			sshkey_free(k->کلید);
		آزاد(k);
	}
	جب ((k = TAILQ_FIRST(&ssh->نجی_کلیدیں)) != تہی) {
		TAILQ_REMOVE(&ssh->نجی_کلیدیں, k, اگلا);
		آزاد(k);
	}
	ssh_packet_close(ssh);
	آزاد(ssh);
}

خالی
ssh_سیٹ_app_ڈیٹا(ساخت ssh *ssh, خالی *app_ڈیٹا)
{
	ssh->app_ڈیٹا = app_ڈیٹا;
}

خالی *
ssh_get_app_ڈیٹا(ساخت ssh *ssh)
{
	واپس ssh->app_ڈیٹا;
}

/* Returns < 0 on error, 0 otherwise */
صحیح
ssh_جوڑو_hostkey(ساخت ssh *ssh, ساخت sshkey *کلید)
{
	ساخت sshkey *pubkey = تہی;
	ساخت کلید_اندراج *k = تہی, *k_prv = تہی;
	صحیح r;

	اگر (ssh->kex->server) {
		اگر ((r = sshkey_from_نجی(کلید, &pubkey)) != 0)
			واپس r;
		اگر ((k = حافظہ_دو(حجم(*k))) == تہی ||
		    (k_prv = حافظہ_دو(حجم(*k_prv))) == تہی) {
			آزاد(k);
			sshkey_free(pubkey);
			واپس SSH_ERR_ALLOC_FAIL;
		}
		k_prv->کلید = کلید;
		TAILQ_INSERT_TAIL(&ssh->نجی_کلیدیں, k_prv, اگلا);

		/* add the public key, too */
		k->کلید = pubkey;
		TAILQ_INSERT_TAIL(&ssh->عوامی_کلیدیں, k, اگلا);
		r = 0;
	} ورنہ {
		اگر ((k = حافظہ_دو(حجم(*k))) == تہی)
			واپس SSH_ERR_ALLOC_FAIL;
		k->کلید = کلید;
		TAILQ_INSERT_TAIL(&ssh->عوامی_کلیدیں, k, اگلا);
		r = 0;
	}

	واپس r;
}

صحیح
ssh_سیٹ_verify_host_کلید_callback(ساخت ssh *ssh,
    صحیح (*cb)(ساخت sshkey *, ساخت ssh *))
{
	اگر (cb == تہی || ssh->kex == تہی)
		واپس SSH_ERR_INVALID_دلیل;

	ssh->kex->verify_host_کلید = cb;

	واپس 0;
}

صحیح
ssh_داخلہ_append(ساخت ssh *ssh, ثابت u_char *ڈیٹا, سائز_t len)
{
	واپس sshbuf_put(ssh_packet_get_داخلہ(ssh), ڈیٹا, len);
}

صحیح
ssh_packet_اگلا(ساخت ssh *ssh, u_char *typep)
{
	صحیح r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_پیغام_NONE;
	اگر (sshbuf_len(ssh->kex->client_نسخہ) == 0 ||
	    sshbuf_len(ssh->kex->server_نسخہ) == 0)
		واپس _ssh_exchange_banner(ssh);
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
	برائے (;;) {
		اگر ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			واپس r;
		اگر (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_پیغام_KEXINIT && type <= SSH2_پیغام_TRANSPORT_MAX &&
		    ssh->dispatch[type] != تہی) {
			اگر ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				واپس r;
		} ورنہ {
			*typep = type;
			واپس 0;
		}
	}
}

ثابت u_char *
ssh_packet_payload(ساخت ssh *ssh, سائز_t *lenp)
{
	واپس sshpkt_ptr(ssh, lenp);
}

صحیح
ssh_packet_put(ساخت ssh *ssh, صحیح type, ثابت u_char *ڈیٹا, سائز_t len)
{
	صحیح r;

	اگر ((r = sshpkt_آغاز(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, ڈیٹا, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		واپس r;
	واپس 0;
}

ثابت u_char *
ssh_output_ptr(ساخت ssh *ssh, سائز_t *len)
{
	ساخت sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	واپس sshbuf_ptr(output);
}

صحیح
ssh_output_consume(ساخت ssh *ssh, سائز_t len)
{
	واپس sshbuf_consume(ssh_packet_get_output(ssh), len);
}

صحیح
ssh_output_space(ساخت ssh *ssh, سائز_t len)
{
	واپس (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

صحیح
ssh_داخلہ_space(ساخت ssh *ssh, سائز_t len)
{
	واپس (0 == sshbuf_check_reserve(ssh_packet_get_داخلہ(ssh), len));
}

/* Read other side's version identification. */
صحیح
_ssh_read_banner(ساخت ssh *ssh, ساخت sshbuf *banner)
{
	ساخت sshbuf *داخلہ = ssh_packet_get_داخلہ(ssh);
	ثابت حرف *mismatch = "Protocol mismatch.\r\n";
	ثابت u_char *s = sshbuf_ptr(داخلہ);
	u_char c;
	حرف *cp = تہی, *remote_نسخہ = تہی;
	صحیح r = 0, remote_major, remote_minor, expect_nl;
	سائز_t n, j;

	برائے (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		برائے (;;) {
			اگر (j >= sshbuf_len(داخلہ))
				واپس 0; /* insufficient data in input buf */
			c = s[j++];
			اگر (c == '\r') {
				expect_nl = 1;
				جاری;
			}
			اگر (c == '\n')
				توڑو;
			اگر (expect_nl)
				جاؤ bad;
			اگر ((r = sshbuf_put_u8(banner, c)) != 0)
				واپس r;
			اگر (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				جاؤ bad;
		}
		اگر (sshbuf_len(banner) >= 4 &&
		    memcmp(sshbuf_ptr(banner), "SSH-", 4) == 0)
			توڑو;
		debug_f("%.*s", (صحیح)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		اگر (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_سطریں) {
  bad:
			اگر ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, لڑی_لمبائی(mismatch))) != 0)
				واپس r;
			واپس SSH_ERR_NO_PROTOCOL_نسخہ;
		}
	}
	اگر ((r = sshbuf_consume(داخلہ, j)) != 0)
		واپس r;

	/* XXX remote version must be the same size as banner for sscanf */
	اگر ((cp = sshbuf_dup_string(banner)) == تہی ||
	    (remote_نسخہ = صفر_حافظہ_دو(1, sshbuf_len(banner))) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	اگر (لڑی_سے_پڑھو(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_نسخہ) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_نسخہ);

	compat_banner(ssh, remote_نسخہ);
	اگر  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	اگر (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 برآمد:
	آزاد(cp);
	آزاد(remote_نسخہ);
	واپس r;
}

/* Send our own protocol version identification. */
صحیح
_ssh_send_banner(ساخت ssh *ssh, ساخت sshbuf *banner)
{
	حرف *cp;
	صحیح r;

	اگر ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_نسخہ)) != 0)
		واپس r;
	اگر ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		واپس r;
	/* Remove trailing \r\n */
	اگر ((r = sshbuf_consume_انتہا(banner, 2)) != 0)
		واپس r;
	اگر ((cp = sshbuf_dup_string(banner)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	آزاد(cp);
	واپس 0;
}

صحیح
_ssh_exchange_banner(ساخت ssh *ssh)
{
	ساخت kex *kex = ssh->kex;
	صحیح r;

	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */

	r = 0;
	اگر (kex->server) {
		اگر (sshbuf_len(ssh->kex->server_نسخہ) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_نسخہ);
		اگر (r == 0 &&
		    sshbuf_len(ssh->kex->server_نسخہ) != 0 &&
		    sshbuf_len(ssh->kex->client_نسخہ) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_نسخہ);
	} ورنہ {
		اگر (sshbuf_len(ssh->kex->server_نسخہ) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_نسخہ);
		اگر (r == 0 &&
		    sshbuf_len(ssh->kex->server_نسخہ) != 0 &&
		    sshbuf_len(ssh->kex->client_نسخہ) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_نسخہ);
	}
	اگر (r != 0)
		واپس r;
	/* start initial kex as soon as we have exchanged the banners */
	اگر (sshbuf_len(ssh->kex->server_نسخہ) != 0 &&
	    sshbuf_len(ssh->kex->client_نسخہ) != 0) {
		اگر ((r = ssh_ترتیب_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			واپس r;
	}
	واپس 0;
}

ساخت sshkey *
ssh_host_عوامی_کلید(صحیح type, صحیح nid, ساخت ssh *ssh)
{
	ساخت کلید_اندراج *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->عوامی_کلیدیں, اگلا) {
		debug3_f("check %s", sshkey_type(k->کلید));
		اگر (k->کلید->type == type &&
		    (type != کلید_ECDSA || k->کلید->ecdsa_nid == nid))
			واپس (k->کلید);
	}
	واپس (تہی);
}

ساخت sshkey *
ssh_host_نجی_کلید(صحیح type, صحیح nid, ساخت ssh *ssh)
{
	ساخت کلید_اندراج *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->نجی_کلیدیں, اگلا) {
		debug3_f("check %s", sshkey_type(k->کلید));
		اگر (k->کلید->type == type &&
		    (type != کلید_ECDSA || k->کلید->ecdsa_nid == nid))
			واپس (k->کلید);
	}
	واپس (تہی);
}

صحیح
ssh_verify_host_کلید(ساخت sshkey *hostkey, ساخت ssh *ssh)
{
	ساخت کلید_اندراج *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->عوامی_کلیدیں, اگلا) {
		debug3_f("check %s", sshkey_type(k->کلید));
		اگر (sshkey_equal_عوامی(hostkey, k->کلید))
			واپس (0);	/* ok */
	}
	واپس (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
صحیح
ssh_ترتیب_hostkeyalgs(ساخت ssh *ssh)
{
	ساخت کلید_اندراج *k;
	حرف *orig, *avail, *oavail = تہی, *alg, *replace = تہی;
	حرف **proposal;
	سائز_t maxlen;
	صحیح ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	اگر ((r = kex_buf2prop(ssh->kex->my, تہی, &proposal)) != 0)
		واپس r;
	orig = proposal[PROPOSAL_SERVER_HOST_کلید_ALGS];
	اگر ((oavail = avail = strdup(orig)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	maxlen = لڑی_لمبائی(avail) + 1;
	اگر ((replace = صفر_حافظہ_دو(1, maxlen)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	*replace = '\0';
	جب ((alg = strsep(&avail, ",")) && *alg != '\0') {
		اگر ((ktype = sshkey_type_from_name(alg)) == کلید_UNSPEC)
			جاری;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->عوامی_کلیدیں, اگلا) {
			اگر (k->کلید->type != ktype &&
			    (!sshkey_is_cert(k->کلید) ||
			    k->کلید->type != sshkey_type_plain(ktype)))
				جاری;
			اگر (sshkey_type_plain(k->کلید->type) == کلید_ECDSA &&
			    k->کلید->ecdsa_nid != nid)
				جاری;
			/* Candidate */
			اگر (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			توڑو;
		}
	}
	اگر (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		آزاد(orig);
		proposal[PROPOSAL_SERVER_HOST_کلید_ALGS] = replace;
		replace = تہی;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 برآمد:
	آزاد(oavail);
	آزاد(replace);
	kex_prop_free(proposal);
	واپس r;
}

صحیح
ssh_host_کلید_sign(ساخت ssh *ssh, ساخت sshkey *privkey,
    ساخت sshkey *pubkey, u_char **signature, سائز_t *slen,
    ثابت u_char *ڈیٹا, سائز_t dlen, ثابت حرف *alg)
{
	واپس sshkey_sign(privkey, signature, slen, ڈیٹا, dlen,
	    alg, تہی, تہی, ssh->compat);
}
