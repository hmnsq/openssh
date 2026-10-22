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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <stdio.h>
#ضمن <stdlib.h>

#ضمن "ssh_api.h"
#ضمن "compat.h"
#ضمن "log.h"
#ضمن "authfile.h"
#ضمن "sshkey.h"
#ضمن "dh.h"
#ضمن "misc.h"
#ضمن "ssh2.h"
#ضمن "version.h"
#ضمن "myproposal.h"
#ضمن "ssherr.h"
#ضمن "sshbuf.h"

#ضمن "openbsd-compat/openssl-compat.h"

#ضمن <string.h>

صحيح	_ssh_exchange_banner(بنية ssh *);
صحيح	_ssh_send_banner(بنية ssh *, بنية sshbuf *);
صحيح	_ssh_read_banner(بنية ssh *, بنية sshbuf *);
صحيح	ssh_ترتیب_hostkeyalgs(بنية ssh *);
صحيح	ssh_verify_host_کلید(بنية sshkey *, بنية ssh *);
بنية sshkey *ssh_host_عمومی_کلید(صحيح, صحيح, بنية ssh *);
بنية sshkey *ssh_host_خصوصی_کلید(صحيح, صحيح, بنية ssh *);
صحيح	ssh_host_کلید_sign(بنية ssh *, بنية sshkey *, بنية sshkey *,
    u_char **, اندازه_t *, ثابت u_char *, اندازه_t, ثابت حرف *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
صحيح	mm_sshkey_sign(بنية sshkey *, u_char **, u_int *,
    ثابت u_char *, u_int, ثابت حرف *, ثابت حرف *, ثابت حرف *, u_int);

#اگر_تعریف_شده WITH_OPENSSL
DH	*mm_انتخاب_dh(صحيح, صحيح, صحيح);
#پایان_اگر

صحيح
mm_sshkey_sign(بنية sshkey *کلید, u_char **sigp, u_int *lenp,
    ثابت u_char *داده, u_int datalen, ثابت حرف *alg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin, u_int compat)
{
	اندازه_t slen = 0;
	صحيح ret;

	ret = sshkey_sign(کلید, sigp, &slen, داده, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	أرجع ret;
}

#اگر_تعریف_شده WITH_OPENSSL
DH *
mm_انتخاب_dh(صحيح min, صحيح nbits, صحيح max)
{
	أرجع انتخاب_dh(min, nbits, max);
}
#پایان_اگر

/* API */

صحيح
ssh_init(بنية ssh **sshp, صحيح is_server, بنية kex_params *kex_params)
{
	حرف *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	حرف *populated[PROPOSAL_MAX];
	بنية ssh *ssh;
	حرف **proposal;
	ساكن صحيح called;
	صحيح r;

	إذا (!called) {
		دانه_rng();
		called = 1;
	}

	إذا ((ssh = ssh_packet_مجموعه_connection(عدم, -1, -1)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا (is_server)
		ssh_packet_مجموعه_server(ssh);

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
	إذا (r != 0) {
		ssh_free(ssh);
		أرجع r;
	}

	ssh->kex->server = is_server;
	إذا (is_server) {
#اگر_تعریف_شده WITH_OPENSSL
		ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
		ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
		ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
#پایان_اگر /* WITH_OPENSSL */
		ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
		ssh->kex->بارگیری_host_عمومی_کلید=&ssh_host_عمومی_کلید;
		ssh->kex->بارگیری_host_خصوصی_کلید=&ssh_host_خصوصی_کلید;
		ssh->kex->sign=&ssh_host_کلید_sign;
	} وإلا {
#اگر_تعریف_شده WITH_OPENSSL
		ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
		ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
		ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#پایان_اگر /* WITH_OPENSSL */
		ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
		ssh->kex->verify_host_کلید =&ssh_verify_host_کلید;
	}
	*sshp = ssh;
	أرجع 0;
}

فراغ
ssh_free(بنية ssh *ssh)
{
	بنية کلید_مدخل *k;

	إذا (ssh == عدم)
		أرجع;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	طالما ((k = TAILQ_FIRST(&ssh->عمومی_کلیدها)) != عدم) {
		TAILQ_REMOVE(&ssh->عمومی_کلیدها, k, بعدی);
		إذا (ssh->kex && ssh->kex->server)
			sshkey_free(k->کلید);
		حرر(k);
	}
	طالما ((k = TAILQ_FIRST(&ssh->خصوصی_کلیدها)) != عدم) {
		TAILQ_REMOVE(&ssh->خصوصی_کلیدها, k, بعدی);
		حرر(k);
	}
	ssh_packet_close(ssh);
	حرر(ssh);
}

فراغ
ssh_مجموعه_app_داده(بنية ssh *ssh, فراغ *app_داده)
{
	ssh->app_داده = app_داده;
}

فراغ *
ssh_get_app_داده(بنية ssh *ssh)
{
	أرجع ssh->app_داده;
}

/* Returns < 0 on error, 0 otherwise */
صحيح
ssh_جمع_کن_hostkey(بنية ssh *ssh, بنية sshkey *کلید)
{
	بنية sshkey *pubkey = عدم;
	بنية کلید_مدخل *k = عدم, *k_prv = عدم;
	صحيح r;

	إذا (ssh->kex->server) {
		إذا ((r = sshkey_from_خصوصی(کلید, &pubkey)) != 0)
			أرجع r;
		إذا ((k = حافظه_بده(حجم(*k))) == عدم ||
		    (k_prv = حافظه_بده(حجم(*k_prv))) == عدم) {
			حرر(k);
			sshkey_free(pubkey);
			أرجع SSH_ERR_ALLOC_FAIL;
		}
		k_prv->کلید = کلید;
		TAILQ_INSERT_TAIL(&ssh->خصوصی_کلیدها, k_prv, بعدی);

		/* add the public key, too */
		k->کلید = pubkey;
		TAILQ_INSERT_TAIL(&ssh->عمومی_کلیدها, k, بعدی);
		r = 0;
	} وإلا {
		إذا ((k = حافظه_بده(حجم(*k))) == عدم)
			أرجع SSH_ERR_ALLOC_FAIL;
		k->کلید = کلید;
		TAILQ_INSERT_TAIL(&ssh->عمومی_کلیدها, k, بعدی);
		r = 0;
	}

	أرجع r;
}

صحيح
ssh_مجموعه_verify_host_کلید_callback(بنية ssh *ssh,
    صحيح (*cb)(بنية sshkey *, بنية ssh *))
{
	إذا (cb == عدم || ssh->kex == عدم)
		أرجع SSH_ERR_INVALID_آرگومان;

	ssh->kex->verify_host_کلید = cb;

	أرجع 0;
}

صحيح
ssh_درون_داد_append(بنية ssh *ssh, ثابت u_char *داده, اندازه_t len)
{
	أرجع sshbuf_put(ssh_packet_get_درون_داد(ssh), داده, len);
}

صحيح
ssh_packet_بعدی(بنية ssh *ssh, u_char *typep)
{
	صحيح r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_پیام_NONE;
	إذا (sshbuf_len(ssh->kex->client_نسخه) == 0 ||
	    sshbuf_len(ssh->kex->server_نسخه) == 0)
		أرجع _ssh_exchange_banner(ssh);
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
	لكل (;;) {
		إذا ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			أرجع r;
		إذا (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_پیام_KEXINIT && type <= SSH2_پیام_TRANSPORT_MAX &&
		    ssh->dispatch[type] != عدم) {
			إذا ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				أرجع r;
		} وإلا {
			*typep = type;
			أرجع 0;
		}
	}
}

ثابت u_char *
ssh_packet_payload(بنية ssh *ssh, اندازه_t *lenp)
{
	أرجع sshpkt_ptr(ssh, lenp);
}

صحيح
ssh_packet_put(بنية ssh *ssh, صحيح type, ثابت u_char *داده, اندازه_t len)
{
	صحيح r;

	إذا ((r = sshpkt_شروع(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, داده, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		أرجع r;
	أرجع 0;
}

ثابت u_char *
ssh_output_ptr(بنية ssh *ssh, اندازه_t *len)
{
	بنية sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	أرجع sshbuf_ptr(output);
}

صحيح
ssh_output_consume(بنية ssh *ssh, اندازه_t len)
{
	أرجع sshbuf_consume(ssh_packet_get_output(ssh), len);
}

صحيح
ssh_output_space(بنية ssh *ssh, اندازه_t len)
{
	أرجع (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

صحيح
ssh_درون_داد_space(بنية ssh *ssh, اندازه_t len)
{
	أرجع (0 == sshbuf_check_reserve(ssh_packet_get_درون_داد(ssh), len));
}

/* Read other side's version identification. */
صحيح
_ssh_read_banner(بنية ssh *ssh, بنية sshbuf *banner)
{
	بنية sshbuf *درون_داد = ssh_packet_get_درون_داد(ssh);
	ثابت حرف *mismatch = "Protocol mismatch.\r\n";
	ثابت u_char *s = sshbuf_ptr(درون_داد);
	u_char c;
	حرف *cp = عدم, *remote_نسخه = عدم;
	صحيح r = 0, remote_major, remote_minor, expect_nl;
	اندازه_t n, j;

	لكل (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		لكل (;;) {
			إذا (j >= sshbuf_len(درون_داد))
				أرجع 0; /* insufficient data in input buf */
			c = s[j++];
			إذا (c == '\r') {
				expect_nl = 1;
				استمر;
			}
			إذا (c == '\n')
				اكسر;
			إذا (expect_nl)
				اذهب bad;
			إذا ((r = sshbuf_put_u8(banner, c)) != 0)
				أرجع r;
			إذا (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				اذهب bad;
		}
		إذا (sshbuf_len(banner) >= 4 &&
		    memcmp(sshbuf_ptr(banner), "SSH-", 4) == 0)
			اكسر;
		debug_f("%.*s", (صحيح)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		إذا (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_سطرها) {
  bad:
			إذا ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, طول_رشته(mismatch))) != 0)
				أرجع r;
			أرجع SSH_ERR_NO_PROTOCOL_نسخه;
		}
	}
	إذا ((r = sshbuf_consume(درون_داد, j)) != 0)
		أرجع r;

	/* XXX remote version must be the same size as banner for sscanf */
	إذا ((cp = sshbuf_dup_string(banner)) == عدم ||
	    (remote_نسخه = حافظه_صفر_بده(1, sshbuf_len(banner))) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	إذا (از_رشته_بخوان(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_نسخه) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بیرون;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_نسخه);

	compat_banner(ssh, remote_نسخه);
	إذا  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	إذا (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 بیرون:
	حرر(cp);
	حرر(remote_نسخه);
	أرجع r;
}

/* Send our own protocol version identification. */
صحيح
_ssh_send_banner(بنية ssh *ssh, بنية sshbuf *banner)
{
	حرف *cp;
	صحيح r;

	إذا ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_نسخه)) != 0)
		أرجع r;
	إذا ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		أرجع r;
	/* Remove trailing \r\n */
	إذا ((r = sshbuf_consume_انتها(banner, 2)) != 0)
		أرجع r;
	إذا ((cp = sshbuf_dup_string(banner)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	حرر(cp);
	أرجع 0;
}

صحيح
_ssh_exchange_banner(بنية ssh *ssh)
{
	بنية kex *kex = ssh->kex;
	صحيح r;

	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */

	r = 0;
	إذا (kex->server) {
		إذا (sshbuf_len(ssh->kex->server_نسخه) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_نسخه);
		إذا (r == 0 &&
		    sshbuf_len(ssh->kex->server_نسخه) != 0 &&
		    sshbuf_len(ssh->kex->client_نسخه) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_نسخه);
	} وإلا {
		إذا (sshbuf_len(ssh->kex->server_نسخه) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_نسخه);
		إذا (r == 0 &&
		    sshbuf_len(ssh->kex->server_نسخه) != 0 &&
		    sshbuf_len(ssh->kex->client_نسخه) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_نسخه);
	}
	إذا (r != 0)
		أرجع r;
	/* start initial kex as soon as we have exchanged the banners */
	إذا (sshbuf_len(ssh->kex->server_نسخه) != 0 &&
	    sshbuf_len(ssh->kex->client_نسخه) != 0) {
		إذا ((r = ssh_ترتیب_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			أرجع r;
	}
	أرجع 0;
}

بنية sshkey *
ssh_host_عمومی_کلید(صحيح type, صحيح nid, بنية ssh *ssh)
{
	بنية کلید_مدخل *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->عمومی_کلیدها, بعدی) {
		debug3_f("check %s", sshkey_type(k->کلید));
		إذا (k->کلید->type == type &&
		    (type != کلید_ECDSA || k->کلید->ecdsa_nid == nid))
			أرجع (k->کلید);
	}
	أرجع (عدم);
}

بنية sshkey *
ssh_host_خصوصی_کلید(صحيح type, صحيح nid, بنية ssh *ssh)
{
	بنية کلید_مدخل *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->خصوصی_کلیدها, بعدی) {
		debug3_f("check %s", sshkey_type(k->کلید));
		إذا (k->کلید->type == type &&
		    (type != کلید_ECDSA || k->کلید->ecdsa_nid == nid))
			أرجع (k->کلید);
	}
	أرجع (عدم);
}

صحيح
ssh_verify_host_کلید(بنية sshkey *hostkey, بنية ssh *ssh)
{
	بنية کلید_مدخل *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->عمومی_کلیدها, بعدی) {
		debug3_f("check %s", sshkey_type(k->کلید));
		إذا (sshkey_equal_عمومی(hostkey, k->کلید))
			أرجع (0);	/* ok */
	}
	أرجع (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
صحيح
ssh_ترتیب_hostkeyalgs(بنية ssh *ssh)
{
	بنية کلید_مدخل *k;
	حرف *orig, *avail, *oavail = عدم, *alg, *replace = عدم;
	حرف **proposal;
	اندازه_t maxlen;
	صحيح ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	إذا ((r = kex_buf2prop(ssh->kex->my, عدم, &proposal)) != 0)
		أرجع r;
	orig = proposal[PROPOSAL_SERVER_HOST_کلید_ALGS];
	إذا ((oavail = avail = strdup(orig)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	maxlen = طول_رشته(avail) + 1;
	إذا ((replace = حافظه_صفر_بده(1, maxlen)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	*replace = '\0';
	طالما ((alg = strsep(&avail, ",")) && *alg != '\0') {
		إذا ((ktype = sshkey_type_from_name(alg)) == کلید_UNSPEC)
			استمر;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->عمومی_کلیدها, بعدی) {
			إذا (k->کلید->type != ktype &&
			    (!sshkey_is_cert(k->کلید) ||
			    k->کلید->type != sshkey_type_plain(ktype)))
				استمر;
			إذا (sshkey_type_plain(k->کلید->type) == کلید_ECDSA &&
			    k->کلید->ecdsa_nid != nid)
				استمر;
			/* Candidate */
			إذا (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			اكسر;
		}
	}
	إذا (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		حرر(orig);
		proposal[PROPOSAL_SERVER_HOST_کلید_ALGS] = replace;
		replace = عدم;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 بیرون:
	حرر(oavail);
	حرر(replace);
	kex_prop_free(proposal);
	أرجع r;
}

صحيح
ssh_host_کلید_sign(بنية ssh *ssh, بنية sshkey *privkey,
    بنية sshkey *pubkey, u_char **signature, اندازه_t *slen,
    ثابت u_char *داده, اندازه_t dlen, ثابت حرف *alg)
{
	أرجع sshkey_sign(privkey, signature, slen, داده, dlen,
	    alg, عدم, عدم, ssh->compat);
}
