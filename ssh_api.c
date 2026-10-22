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

पूर्णांक	_ssh_exchange_banner(संरचना ssh *);
पूर्णांक	_ssh_send_banner(संरचना ssh *, संरचना sshbuf *);
पूर्णांक	_ssh_read_banner(संरचना ssh *, संरचना sshbuf *);
पूर्णांक	_ssh_order_hostkeyalgs(संरचना ssh *);
पूर्णांक	ssh_verify_host_किल्ली(संरचना sshkey *, संरचना ssh *);
संरचना sshkey *ssh_host_public_किल्ली(पूर्णांक, पूर्णांक, संरचना ssh *);
संरचना sshkey *ssh_host_private_किल्ली(पूर्णांक, पूर्णांक, संरचना ssh *);
पूर्णांक	ssh_host_किल्ली_sign(संरचना ssh *, संरचना sshkey *, संरचना sshkey *,
    u_char **, माप_प्रकार *, स्थिरांक u_char *, माप_प्रकार, स्थिरांक अक्षर *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
पूर्णांक	mm_sshkey_sign(संरचना sshkey *, u_char **, u_int *,
    स्थिरांक u_char *, u_int, स्थिरांक अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *, u_int);

#ifdef WITH_OPENSSL
DH	*mm_choose_dh(पूर्णांक, पूर्णांक, पूर्णांक);
#endif

पूर्णांक
mm_sshkey_sign(संरचना sshkey *किल्ली, u_char **sigp, u_int *lenp,
    स्थिरांक u_char *data, u_int datalen, स्थिरांक अक्षर *alg,
    स्थिरांक अक्षर *sk_provider, स्थिरांक अक्षर *sk_pin, u_int compat)
{
	माप_प्रकार slen = 0;
	पूर्णांक ret;

	ret = sshkey_sign(किल्ली, sigp, &slen, data, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	परत ret;
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(पूर्णांक min, पूर्णांक nbits, पूर्णांक max)
{
	परत choose_dh(min, nbits, max);
}
#endif

/* API */

पूर्णांक
ssh_init(संरचना ssh **sshp, पूर्णांक is_server, संरचना kex_params *kex_params)
{
	अक्षर *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	अक्षर *populated[PROPOSAL_MAX];
	संरचना ssh *ssh;
	अक्षर **proposal;
	स्थिर पूर्णांक called;
	पूर्णांक r;

	जर (!called) {
		seed_rng();
		called = 1;
	}

	जर ((ssh = ssh_packet_set_connection(रिक्त, -1, -1)) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर (is_server)
		ssh_packet_set_server(ssh);

	/* Initialize key exchange */
	proposal = kex_params ? kex_params->proposal : myproposal;
	kex_proposal_populate_entries(ssh, populated,
	    proposal[PROPOSAL_KEX_ALGS],
	    proposal[PROPOSAL_ENC_ALGS_CTOS],
	    proposal[PROPOSAL_MAC_ALGS_CTOS],
	    proposal[PROPOSAL_COMP_ALGS_CTOS],
	    proposal[PROPOSAL_SERVER_HOST_किल्ली_ALGS]);
	r = kex_ready(ssh, populated);
	kex_proposal_free_entries(populated);
	जर (r != 0) {
		ssh_free(ssh);
		परत r;
	}

	ssh->kex->server = is_server;
	जर (is_server) {
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
		ssh->kex->load_host_public_किल्ली=&ssh_host_public_किल्ली;
		ssh->kex->load_host_private_किल्ली=&ssh_host_private_किल्ली;
		ssh->kex->sign=&ssh_host_किल्ली_sign;
	} अन्यथा {
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
		ssh->kex->verify_host_किल्ली =&ssh_verify_host_किल्ली;
	}
	*sshp = ssh;
	परत 0;
}

शून्य
ssh_free(संरचना ssh *ssh)
{
	संरचना किल्ली_entry *k;

	जर (ssh == रिक्त)
		परत;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	पर्यंत ((k = TAILQ_FIRST(&ssh->public_किल्ल्या)) != रिक्त) {
		TAILQ_REMOVE(&ssh->public_किल्ल्या, k, next);
		जर (ssh->kex && ssh->kex->server)
			sshkey_free(k->किल्ली);
		मुक्त(k);
	}
	पर्यंत ((k = TAILQ_FIRST(&ssh->private_किल्ल्या)) != रिक्त) {
		TAILQ_REMOVE(&ssh->private_किल्ल्या, k, next);
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
	परत ssh->app_data;
}

/* Returns < 0 on error, 0 otherwise */
पूर्णांक
ssh_add_hostkey(संरचना ssh *ssh, संरचना sshkey *किल्ली)
{
	संरचना sshkey *pubkey = रिक्त;
	संरचना किल्ली_entry *k = रिक्त, *k_prv = रिक्त;
	पूर्णांक r;

	जर (ssh->kex->server) {
		जर ((r = sshkey_from_private(किल्ली, &pubkey)) != 0)
			परत r;
		जर ((k = दो_स्मृति(आकार(*k))) == रिक्त ||
		    (k_prv = दो_स्मृति(आकार(*k_prv))) == रिक्त) {
			मुक्त(k);
			sshkey_free(pubkey);
			परत SSH_ERR_ALLOC_FAIL;
		}
		k_prv->किल्ली = किल्ली;
		TAILQ_INSERT_TAIL(&ssh->private_किल्ल्या, k_prv, next);

		/* add the public key, too */
		k->किल्ली = pubkey;
		TAILQ_INSERT_TAIL(&ssh->public_किल्ल्या, k, next);
		r = 0;
	} अन्यथा {
		जर ((k = दो_स्मृति(आकार(*k))) == रिक्त)
			परत SSH_ERR_ALLOC_FAIL;
		k->किल्ली = किल्ली;
		TAILQ_INSERT_TAIL(&ssh->public_किल्ल्या, k, next);
		r = 0;
	}

	परत r;
}

पूर्णांक
ssh_set_verify_host_किल्ली_callback(संरचना ssh *ssh,
    पूर्णांक (*cb)(संरचना sshkey *, संरचना ssh *))
{
	जर (cb == रिक्त || ssh->kex == रिक्त)
		परत SSH_ERR_INVALID_ARGUMENT;

	ssh->kex->verify_host_किल्ली = cb;

	परत 0;
}

पूर्णांक
ssh_आदान_append(संरचना ssh *ssh, स्थिरांक u_char *data, माप_प्रकार len)
{
	परत sshbuf_put(ssh_packet_get_आदान(ssh), data, len);
}

पूर्णांक
ssh_packet_next(संरचना ssh *ssh, u_char *typep)
{
	पूर्णांक r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_संदेश_NONE;
	जर (sshbuf_len(ssh->kex->client_version) == 0 ||
	    sshbuf_len(ssh->kex->server_version) == 0)
		परत _ssh_exchange_banner(ssh);
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
	साठी (;;) {
		जर ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			परत r;
		जर (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_संदेश_KEXINIT && type <= SSH2_संदेश_TRANSPORT_MAX &&
		    ssh->dispatch[type] != रिक्त) {
			जर ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				परत r;
		} अन्यथा {
			*typep = type;
			परत 0;
		}
	}
}

स्थिरांक u_char *
ssh_packet_payload(संरचना ssh *ssh, माप_प्रकार *lenp)
{
	परत sshpkt_ptr(ssh, lenp);
}

पूर्णांक
ssh_packet_put(संरचना ssh *ssh, पूर्णांक type, स्थिरांक u_char *data, माप_प्रकार len)
{
	पूर्णांक r;

	जर ((r = sshpkt_start(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, data, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		परत r;
	परत 0;
}

स्थिरांक u_char *
ssh_output_ptr(संरचना ssh *ssh, माप_प्रकार *len)
{
	संरचना sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	परत sshbuf_ptr(output);
}

पूर्णांक
ssh_output_consume(संरचना ssh *ssh, माप_प्रकार len)
{
	परत sshbuf_consume(ssh_packet_get_output(ssh), len);
}

पूर्णांक
ssh_output_space(संरचना ssh *ssh, माप_प्रकार len)
{
	परत (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

पूर्णांक
ssh_आदान_space(संरचना ssh *ssh, माप_प्रकार len)
{
	परत (0 == sshbuf_check_reserve(ssh_packet_get_आदान(ssh), len));
}

/* Read other side's version identification. */
पूर्णांक
_ssh_read_banner(संरचना ssh *ssh, संरचना sshbuf *banner)
{
	संरचना sshbuf *आदान = ssh_packet_get_आदान(ssh);
	स्थिरांक अक्षर *mismatch = "Protocol mismatch.\r\n";
	स्थिरांक u_char *s = sshbuf_ptr(आदान);
	u_char c;
	अक्षर *cp = रिक्त, *remote_version = रिक्त;
	पूर्णांक r = 0, remote_major, remote_minor, expect_nl;
	माप_प्रकार n, j;

	साठी (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		साठी (;;) {
			जर (j >= sshbuf_len(आदान))
				परत 0; /* insufficient data in input buf */
			c = s[j++];
			जर (c == '\r') {
				expect_nl = 1;
				सुरूठेवा;
			}
			जर (c == '\n')
				थांबा;
			जर (expect_nl)
				जा bad;
			जर ((r = sshbuf_put_u8(banner, c)) != 0)
				परत r;
			जर (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				जा bad;
		}
		जर (sshbuf_len(banner) >= 4 &&
		    स_भेद(sshbuf_ptr(banner), "SSH-", 4) == 0)
			थांबा;
		debug_f("%.*s", (पूर्णांक)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		जर (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_ओळी) {
  bad:
			जर ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, म_माप(mismatch))) != 0)
				परत r;
			परत SSH_ERR_NO_PROTOCOL_VERSION;
		}
	}
	जर ((r = sshbuf_consume(आदान, j)) != 0)
		परत r;

	/* XXX remote version must be the same size as banner for sscanf */
	जर ((cp = sshbuf_dup_string(banner)) == रिक्त ||
	    (remote_version = सुस्मृति(1, sshbuf_len(banner))) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	जर (माला_पूछो(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);

	compat_banner(ssh, remote_version);
	जर  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	जर (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 out:
	मुक्त(cp);
	मुक्त(remote_version);
	परत r;
}

/* Send our own protocol version identification. */
पूर्णांक
_ssh_send_banner(संरचना ssh *ssh, संरचना sshbuf *banner)
{
	अक्षर *cp;
	पूर्णांक r;

	जर ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_VERSION)) != 0)
		परत r;
	जर ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		परत r;
	/* Remove trailing \r\n */
	जर ((r = sshbuf_consume_end(banner, 2)) != 0)
		परत r;
	जर ((cp = sshbuf_dup_string(banner)) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	मुक्त(cp);
	परत 0;
}

पूर्णांक
_ssh_exchange_banner(संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	पूर्णांक r;

	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */

	r = 0;
	जर (kex->server) {
		जर (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_version);
		जर (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_version);
	} अन्यथा {
		जर (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_version);
		जर (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_version);
	}
	जर (r != 0)
		परत r;
	/* start initial kex as soon as we have exchanged the banners */
	जर (sshbuf_len(ssh->kex->server_version) != 0 &&
	    sshbuf_len(ssh->kex->client_version) != 0) {
		जर ((r = _ssh_order_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			परत r;
	}
	परत 0;
}

संरचना sshkey *
ssh_host_public_किल्ली(पूर्णांक type, पूर्णांक nid, संरचना ssh *ssh)
{
	संरचना किल्ली_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->public_किल्ल्या, next) {
		debug3_f("check %s", sshkey_type(k->किल्ली));
		जर (k->किल्ली->type == type &&
		    (type != किल्ली_ECDSA || k->किल्ली->ecdsa_nid == nid))
			परत (k->किल्ली);
	}
	परत (रिक्त);
}

संरचना sshkey *
ssh_host_private_किल्ली(पूर्णांक type, पूर्णांक nid, संरचना ssh *ssh)
{
	संरचना किल्ली_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->private_किल्ल्या, next) {
		debug3_f("check %s", sshkey_type(k->किल्ली));
		जर (k->किल्ली->type == type &&
		    (type != किल्ली_ECDSA || k->किल्ली->ecdsa_nid == nid))
			परत (k->किल्ली);
	}
	परत (रिक्त);
}

पूर्णांक
ssh_verify_host_किल्ली(संरचना sshkey *hostkey, संरचना ssh *ssh)
{
	संरचना किल्ली_entry *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->public_किल्ल्या, next) {
		debug3_f("check %s", sshkey_type(k->किल्ली));
		जर (sshkey_equal_public(hostkey, k->किल्ली))
			परत (0);	/* ok */
	}
	परत (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
पूर्णांक
_ssh_order_hostkeyalgs(संरचना ssh *ssh)
{
	संरचना किल्ली_entry *k;
	अक्षर *orig, *avail, *oavail = रिक्त, *alg, *replace = रिक्त;
	अक्षर **proposal;
	माप_प्रकार maxlen;
	पूर्णांक ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	जर ((r = kex_buf2prop(ssh->kex->my, रिक्त, &proposal)) != 0)
		परत r;
	orig = proposal[PROPOSAL_SERVER_HOST_किल्ली_ALGS];
	जर ((oavail = avail = strdup(orig)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	maxlen = म_माप(avail) + 1;
	जर ((replace = सुस्मृति(1, maxlen)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	*replace = '\0';
	पर्यंत ((alg = strsep(&avail, ",")) && *alg != '\0') {
		जर ((ktype = sshkey_type_from_name(alg)) == किल्ली_UNSPEC)
			सुरूठेवा;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->public_किल्ल्या, next) {
			जर (k->किल्ली->type != ktype &&
			    (!sshkey_is_cert(k->किल्ली) ||
			    k->किल्ली->type != sshkey_type_plain(ktype)))
				सुरूठेवा;
			जर (sshkey_type_plain(k->किल्ली->type) == किल्ली_ECDSA &&
			    k->किल्ली->ecdsa_nid != nid)
				सुरूठेवा;
			/* Candidate */
			जर (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			थांबा;
		}
	}
	जर (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		मुक्त(orig);
		proposal[PROPOSAL_SERVER_HOST_किल्ली_ALGS] = replace;
		replace = रिक्त;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 out:
	मुक्त(oavail);
	मुक्त(replace);
	kex_prop_free(proposal);
	परत r;
}

पूर्णांक
ssh_host_किल्ली_sign(संरचना ssh *ssh, संरचना sshkey *privkey,
    संरचना sshkey *pubkey, u_char **signature, माप_प्रकार *slen,
    स्थिरांक u_char *data, माप_प्रकार dlen, स्थिरांक अक्षर *alg)
{
	परत sshkey_sign(privkey, signature, slen, data, dlen,
	    alg, रिक्त, रिक्त, ssh->compat);
}
