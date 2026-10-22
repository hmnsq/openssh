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

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <stdio.h>
#समावेश <stdlib.h>

#समावेश "ssh_api.h"
#समावेश "compat.h"
#समावेश "log.h"
#समावेश "authfile.h"
#समावेश "sshkey.h"
#समावेश "dh.h"
#समावेश "misc.h"
#समावेश "ssh2.h"
#समावेश "version.h"
#समावेश "myproposal.h"
#समावेश "ssherr.h"
#समावेश "sshbuf.h"

#समावेश "openbsd-compat/openssl-compat.h"

#समावेश <string.h>

पूर्णांक	_ssh_exchange_banner(काष्ठा ssh *);
पूर्णांक	_ssh_send_banner(काष्ठा ssh *, काष्ठा sshbuf *);
पूर्णांक	_ssh_read_banner(काष्ठा ssh *, काष्ठा sshbuf *);
पूर्णांक	_ssh_order_hostkeyalgs(काष्ठा ssh *);
पूर्णांक	ssh_verify_host_कुंजी(काष्ठा sshkey *, काष्ठा ssh *);
काष्ठा sshkey *ssh_host_public_कुंजी(पूर्णांक, पूर्णांक, काष्ठा ssh *);
काष्ठा sshkey *ssh_host_private_कुंजी(पूर्णांक, पूर्णांक, काष्ठा ssh *);
पूर्णांक	ssh_host_कुंजी_sign(काष्ठा ssh *, काष्ठा sshkey *, काष्ठा sshkey *,
    u_char **, माप_प्रकार *, स्थिर u_char *, माप_प्रकार, स्थिर अक्षर *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
पूर्णांक	mm_sshkey_sign(काष्ठा sshkey *, u_char **, u_int *,
    स्थिर u_char *, u_int, स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *, u_int);

#अगर_घोषित WITH_OPENSSL
DH	*mm_choose_dh(पूर्णांक, पूर्णांक, पूर्णांक);
#पूर्ण_अगर

पूर्णांक
mm_sshkey_sign(काष्ठा sshkey *कुंजी, u_char **sigp, u_int *lenp,
    स्थिर u_char *तथ्य, u_int datalen, स्थिर अक्षर *alg,
    स्थिर अक्षर *sk_provider, स्थिर अक्षर *sk_pin, u_int compat)
{
	माप_प्रकार slen = 0;
	पूर्णांक ret;

	ret = sshkey_sign(कुंजी, sigp, &slen, तथ्य, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	वापस ret;
}

#अगर_घोषित WITH_OPENSSL
DH *
mm_choose_dh(पूर्णांक min, पूर्णांक nbits, पूर्णांक max)
{
	वापस choose_dh(min, nbits, max);
}
#पूर्ण_अगर

/* API */

पूर्णांक
ssh_init(काष्ठा ssh **sshp, पूर्णांक is_server, काष्ठा kex_params *kex_params)
{
	अक्षर *myproposal[PROPOSAL_MAX] = { KEX_CLIENT };
	अक्षर *populated[PROPOSAL_MAX];
	काष्ठा ssh *ssh;
	अक्षर **proposal;
	अटल पूर्णांक called;
	पूर्णांक r;

	अगर (!called) {
		seed_rng();
		called = 1;
	}

	अगर ((ssh = ssh_packet_set_connection(शून्य, -1, -1)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर (is_server)
		ssh_packet_set_server(ssh);

	/* Initialize key exchange */
	proposal = kex_params ? kex_params->proposal : myproposal;
	kex_proposal_populate_entries(ssh, populated,
	    proposal[PROPOSAL_KEX_ALGS],
	    proposal[PROPOSAL_ENC_ALGS_CTOS],
	    proposal[PROPOSAL_MAC_ALGS_CTOS],
	    proposal[PROPOSAL_COMP_ALGS_CTOS],
	    proposal[PROPOSAL_SERVER_HOST_कुंजी_ALGS]);
	r = kex_ready(ssh, populated);
	kex_proposal_free_entries(populated);
	अगर (r != 0) {
		ssh_free(ssh);
		वापस r;
	}

	ssh->kex->server = is_server;
	अगर (is_server) {
#अगर_घोषित WITH_OPENSSL
		ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
		ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_server;
		ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_server;
#पूर्ण_अगर /* WITH_OPENSSL */
		ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_server;
		ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_server;
		ssh->kex->load_host_public_कुंजी=&ssh_host_public_कुंजी;
		ssh->kex->load_host_private_कुंजी=&ssh_host_private_कुंजी;
		ssh->kex->sign=&ssh_host_कुंजी_sign;
	} अन्यथा {
#अगर_घोषित WITH_OPENSSL
		ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
		ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
		ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#पूर्ण_अगर /* WITH_OPENSSL */
		ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
		ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
		ssh->kex->verify_host_कुंजी =&ssh_verify_host_कुंजी;
	}
	*sshp = ssh;
	वापस 0;
}

व्योम
ssh_free(काष्ठा ssh *ssh)
{
	काष्ठा कुंजी_entry *k;

	अगर (ssh == शून्य)
		वापस;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	जबतक ((k = TAILQ_FIRST(&ssh->public_कुंजियाँ)) != शून्य) {
		TAILQ_REMOVE(&ssh->public_कुंजियाँ, k, अग्र);
		अगर (ssh->kex && ssh->kex->server)
			sshkey_free(k->कुंजी);
		मुक्त(k);
	}
	जबतक ((k = TAILQ_FIRST(&ssh->private_कुंजियाँ)) != शून्य) {
		TAILQ_REMOVE(&ssh->private_कुंजियाँ, k, अग्र);
		मुक्त(k);
	}
	ssh_packet_close(ssh);
	मुक्त(ssh);
}

व्योम
ssh_set_app_तथ्य(काष्ठा ssh *ssh, व्योम *app_तथ्य)
{
	ssh->app_तथ्य = app_तथ्य;
}

व्योम *
ssh_get_app_तथ्य(काष्ठा ssh *ssh)
{
	वापस ssh->app_तथ्य;
}

/* Returns < 0 on error, 0 otherwise */
पूर्णांक
ssh_add_hostkey(काष्ठा ssh *ssh, काष्ठा sshkey *कुंजी)
{
	काष्ठा sshkey *pubkey = शून्य;
	काष्ठा कुंजी_entry *k = शून्य, *k_prv = शून्य;
	पूर्णांक r;

	अगर (ssh->kex->server) {
		अगर ((r = sshkey_from_private(कुंजी, &pubkey)) != 0)
			वापस r;
		अगर ((k = दो_स्मृति(माप(*k))) == शून्य ||
		    (k_prv = दो_स्मृति(माप(*k_prv))) == शून्य) {
			मुक्त(k);
			sshkey_free(pubkey);
			वापस SSH_ERR_ALLOC_FAIL;
		}
		k_prv->कुंजी = कुंजी;
		TAILQ_INSERT_TAIL(&ssh->private_कुंजियाँ, k_prv, अग्र);

		/* add the public key, too */
		k->कुंजी = pubkey;
		TAILQ_INSERT_TAIL(&ssh->public_कुंजियाँ, k, अग्र);
		r = 0;
	} अन्यथा {
		अगर ((k = दो_स्मृति(माप(*k))) == शून्य)
			वापस SSH_ERR_ALLOC_FAIL;
		k->कुंजी = कुंजी;
		TAILQ_INSERT_TAIL(&ssh->public_कुंजियाँ, k, अग्र);
		r = 0;
	}

	वापस r;
}

पूर्णांक
ssh_set_verify_host_कुंजी_callback(काष्ठा ssh *ssh,
    पूर्णांक (*cb)(काष्ठा sshkey *, काष्ठा ssh *))
{
	अगर (cb == शून्य || ssh->kex == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;

	ssh->kex->verify_host_कुंजी = cb;

	वापस 0;
}

पूर्णांक
ssh_निवेश_append(काष्ठा ssh *ssh, स्थिर u_char *तथ्य, माप_प्रकार len)
{
	वापस sshbuf_put(ssh_packet_get_निवेश(ssh), तथ्य, len);
}

पूर्णांक
ssh_packet_अग्र(काष्ठा ssh *ssh, u_char *typep)
{
	पूर्णांक r;
	uint32_t seqnr;
	u_char type;

	/*
	 * Try to read a packet. Return SSH_MSG_NONE if no packet or not
	 * enough data.
	 */
	*typep = SSH_संदेश_NONE;
	अगर (sshbuf_len(ssh->kex->client_version) == 0 ||
	    sshbuf_len(ssh->kex->server_version) == 0)
		वापस _ssh_exchange_banner(ssh);
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
	क्रम (;;) {
		अगर ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			वापस r;
		अगर (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_संदेश_KEXINIT && type <= SSH2_संदेश_TRANSPORT_MAX &&
		    ssh->dispatch[type] != शून्य) {
			अगर ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				वापस r;
		} अन्यथा {
			*typep = type;
			वापस 0;
		}
	}
}

स्थिर u_char *
ssh_packet_payload(काष्ठा ssh *ssh, माप_प्रकार *lenp)
{
	वापस sshpkt_ptr(ssh, lenp);
}

पूर्णांक
ssh_packet_put(काष्ठा ssh *ssh, पूर्णांक type, स्थिर u_char *तथ्य, माप_प्रकार len)
{
	पूर्णांक r;

	अगर ((r = sshpkt_start(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, तथ्य, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		वापस r;
	वापस 0;
}

स्थिर u_char *
ssh_output_ptr(काष्ठा ssh *ssh, माप_प्रकार *len)
{
	काष्ठा sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	वापस sshbuf_ptr(output);
}

पूर्णांक
ssh_output_consume(काष्ठा ssh *ssh, माप_प्रकार len)
{
	वापस sshbuf_consume(ssh_packet_get_output(ssh), len);
}

पूर्णांक
ssh_output_space(काष्ठा ssh *ssh, माप_प्रकार len)
{
	वापस (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

पूर्णांक
ssh_निवेश_space(काष्ठा ssh *ssh, माप_प्रकार len)
{
	वापस (0 == sshbuf_check_reserve(ssh_packet_get_निवेश(ssh), len));
}

/* Read other side's version identification. */
पूर्णांक
_ssh_read_banner(काष्ठा ssh *ssh, काष्ठा sshbuf *banner)
{
	काष्ठा sshbuf *निवेश = ssh_packet_get_निवेश(ssh);
	स्थिर अक्षर *mismatch = "Protocol mismatch.\r\n";
	स्थिर u_char *s = sshbuf_ptr(निवेश);
	u_char c;
	अक्षर *cp = शून्य, *remote_version = शून्य;
	पूर्णांक r = 0, remote_major, remote_minor, expect_nl;
	माप_प्रकार n, j;

	क्रम (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		क्रम (;;) {
			अगर (j >= sshbuf_len(निवेश))
				वापस 0; /* insufficient data in input buf */
			c = s[j++];
			अगर (c == '\r') {
				expect_nl = 1;
				जारी;
			}
			अगर (c == '\n')
				अवरोध;
			अगर (expect_nl)
				जाओ bad;
			अगर ((r = sshbuf_put_u8(banner, c)) != 0)
				वापस r;
			अगर (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				जाओ bad;
		}
		अगर (sshbuf_len(banner) >= 4 &&
		    स_भेद(sshbuf_ptr(banner), "SSH-", 4) == 0)
			अवरोध;
		debug_f("%.*s", (पूर्णांक)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		अगर (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_पंक्तियाँ) {
  bad:
			अगर ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, म_माप(mismatch))) != 0)
				वापस r;
			वापस SSH_ERR_NO_PROTOCOL_VERSION;
		}
	}
	अगर ((r = sshbuf_consume(निवेश, j)) != 0)
		वापस r;

	/* XXX remote version must be the same size as banner for sscanf */
	अगर ((cp = sshbuf_dup_string(banner)) == शून्य ||
	    (remote_version = सुस्मृति(1, sshbuf_len(banner))) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	अगर (माला_पूछो(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);

	compat_banner(ssh, remote_version);
	अगर  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	अगर (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 out:
	मुक्त(cp);
	मुक्त(remote_version);
	वापस r;
}

/* Send our own protocol version identification. */
पूर्णांक
_ssh_send_banner(काष्ठा ssh *ssh, काष्ठा sshbuf *banner)
{
	अक्षर *cp;
	पूर्णांक r;

	अगर ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_VERSION)) != 0)
		वापस r;
	अगर ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		वापस r;
	/* Remove trailing \r\n */
	अगर ((r = sshbuf_consume_end(banner, 2)) != 0)
		वापस r;
	अगर ((cp = sshbuf_dup_string(banner)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	मुक्त(cp);
	वापस 0;
}

पूर्णांक
_ssh_exchange_banner(काष्ठा ssh *ssh)
{
	काष्ठा kex *kex = ssh->kex;
	पूर्णांक r;

	/*
	 * if _ssh_read_banner() cannot parse a full version string
	 * it will return NULL and we end up calling it again.
	 */

	r = 0;
	अगर (kex->server) {
		अगर (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_version);
		अगर (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_version);
	} अन्यथा {
		अगर (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_version);
		अगर (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_version);
	}
	अगर (r != 0)
		वापस r;
	/* start initial kex as soon as we have exchanged the banners */
	अगर (sshbuf_len(ssh->kex->server_version) != 0 &&
	    sshbuf_len(ssh->kex->client_version) != 0) {
		अगर ((r = _ssh_order_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			वापस r;
	}
	वापस 0;
}

काष्ठा sshkey *
ssh_host_public_कुंजी(पूर्णांक type, पूर्णांक nid, काष्ठा ssh *ssh)
{
	काष्ठा कुंजी_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->public_कुंजियाँ, अग्र) {
		debug3_f("check %s", sshkey_type(k->कुंजी));
		अगर (k->कुंजी->type == type &&
		    (type != कुंजी_ECDSA || k->कुंजी->ecdsa_nid == nid))
			वापस (k->कुंजी);
	}
	वापस (शून्य);
}

काष्ठा sshkey *
ssh_host_private_कुंजी(पूर्णांक type, पूर्णांक nid, काष्ठा ssh *ssh)
{
	काष्ठा कुंजी_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->private_कुंजियाँ, अग्र) {
		debug3_f("check %s", sshkey_type(k->कुंजी));
		अगर (k->कुंजी->type == type &&
		    (type != कुंजी_ECDSA || k->कुंजी->ecdsa_nid == nid))
			वापस (k->कुंजी);
	}
	वापस (शून्य);
}

पूर्णांक
ssh_verify_host_कुंजी(काष्ठा sshkey *hostkey, काष्ठा ssh *ssh)
{
	काष्ठा कुंजी_entry *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->public_कुंजियाँ, अग्र) {
		debug3_f("check %s", sshkey_type(k->कुंजी));
		अगर (sshkey_equal_public(hostkey, k->कुंजी))
			वापस (0);	/* ok */
	}
	वापस (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
पूर्णांक
_ssh_order_hostkeyalgs(काष्ठा ssh *ssh)
{
	काष्ठा कुंजी_entry *k;
	अक्षर *orig, *avail, *oavail = शून्य, *alg, *replace = शून्य;
	अक्षर **proposal;
	माप_प्रकार maxlen;
	पूर्णांक ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	अगर ((r = kex_buf2prop(ssh->kex->my, शून्य, &proposal)) != 0)
		वापस r;
	orig = proposal[PROPOSAL_SERVER_HOST_कुंजी_ALGS];
	अगर ((oavail = avail = strdup(orig)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	maxlen = म_माप(avail) + 1;
	अगर ((replace = सुस्मृति(1, maxlen)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	*replace = '\0';
	जबतक ((alg = strsep(&avail, ",")) && *alg != '\0') {
		अगर ((ktype = sshkey_type_from_name(alg)) == कुंजी_UNSPEC)
			जारी;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->public_कुंजियाँ, अग्र) {
			अगर (k->कुंजी->type != ktype &&
			    (!sshkey_is_cert(k->कुंजी) ||
			    k->कुंजी->type != sshkey_type_plain(ktype)))
				जारी;
			अगर (sshkey_type_plain(k->कुंजी->type) == कुंजी_ECDSA &&
			    k->कुंजी->ecdsa_nid != nid)
				जारी;
			/* Candidate */
			अगर (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			अवरोध;
		}
	}
	अगर (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		मुक्त(orig);
		proposal[PROPOSAL_SERVER_HOST_कुंजी_ALGS] = replace;
		replace = शून्य;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 out:
	मुक्त(oavail);
	मुक्त(replace);
	kex_prop_free(proposal);
	वापस r;
}

पूर्णांक
ssh_host_कुंजी_sign(काष्ठा ssh *ssh, काष्ठा sshkey *privkey,
    काष्ठा sshkey *pubkey, u_char **signature, माप_प्रकार *slen,
    स्थिर u_char *तथ्य, माप_प्रकार dlen, स्थिर अक्षर *alg)
{
	वापस sshkey_sign(privkey, signature, slen, तथ्य, dlen,
	    alg, शून्य, शून्य, ssh->compat);
}
