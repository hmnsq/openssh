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
पूर्णाङ्क	ssh_verify_host_साँचो(संरचना sshkey *, संरचना ssh *);
संरचना sshkey *ssh_host_public_साँचो(पूर्णाङ्क, पूर्णाङ्क, संरचना ssh *);
संरचना sshkey *ssh_host_private_साँचो(पूर्णाङ्क, पूर्णाङ्क, संरचना ssh *);
पूर्णाङ्क	ssh_host_साँचो_sign(संरचना ssh *, संरचना sshkey *, संरचना sshkey *,
    u_char **, माप_प्रकार *, अचर u_char *, माप_प्रकार, अचर वर्ण *);

/*
 * stubs for privsep calls in the server side implementation of kex.
 */
पूर्णाङ्क	mm_sshkey_sign(संरचना sshkey *, u_char **, u_int *,
    अचर u_char *, u_int, अचर वर्ण *, अचर वर्ण *, अचर वर्ण *, u_int);

#ifdef WITH_OPENSSL
DH	*mm_choose_dh(पूर्णाङ्क, पूर्णाङ्क, पूर्णाङ्क);
#endif

पूर्णाङ्क
mm_sshkey_sign(संरचना sshkey *साँचो, u_char **sigp, u_int *lenp,
    अचर u_char *data, u_int datalen, अचर वर्ण *alg,
    अचर वर्ण *sk_provider, अचर वर्ण *sk_pin, u_int compat)
{
	माप_प्रकार slen = 0;
	पूर्णाङ्क ret;

	ret = sshkey_sign(साँचो, sigp, &slen, data, datalen, alg,
	    sk_provider, sk_pin, compat);
	*lenp = slen;
	फर्काऊ ret;
}

#ifdef WITH_OPENSSL
DH *
mm_choose_dh(पूर्णाङ्क min, पूर्णाङ्क nbits, पूर्णाङ्क max)
{
	फर्काऊ choose_dh(min, nbits, max);
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

	यदि (!called) {
		seed_rng();
		called = 1;
	}

	यदि ((ssh = ssh_packet_set_connection(रिक्त, -1, -1)) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	यदि (is_server)
		ssh_packet_set_server(ssh);

	/* Initialize key exchange */
	proposal = kex_params ? kex_params->proposal : myproposal;
	kex_proposal_populate_entries(ssh, populated,
	    proposal[PROPOSAL_KEX_ALGS],
	    proposal[PROPOSAL_ENC_ALGS_CTOS],
	    proposal[PROPOSAL_MAC_ALGS_CTOS],
	    proposal[PROPOSAL_COMP_ALGS_CTOS],
	    proposal[PROPOSAL_SERVER_HOST_साँचो_ALGS]);
	r = kex_ready(ssh, populated);
	kex_proposal_free_entries(populated);
	यदि (r != 0) {
		ssh_free(ssh);
		फर्काऊ r;
	}

	ssh->kex->server = is_server;
	यदि (is_server) {
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
		ssh->kex->load_host_public_साँचो=&ssh_host_public_साँचो;
		ssh->kex->load_host_private_साँचो=&ssh_host_private_साँचो;
		ssh->kex->sign=&ssh_host_साँचो_sign;
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
		ssh->kex->verify_host_साँचो =&ssh_verify_host_साँचो;
	}
	*sshp = ssh;
	फर्काऊ 0;
}

शून्य
ssh_free(संरचना ssh *ssh)
{
	संरचना साँचो_entry *k;

	यदि (ssh == रिक्त)
		फर्काऊ;

	/*
	 * we've only created the public keys variants in case we
	 * are a acting as a server.
	 */
	जबसम्म ((k = TAILQ_FIRST(&ssh->public_साँचोहरू)) != रिक्त) {
		TAILQ_REMOVE(&ssh->public_साँचोहरू, k, next);
		यदि (ssh->kex && ssh->kex->server)
			sshkey_free(k->साँचो);
		मुक्त(k);
	}
	जबसम्म ((k = TAILQ_FIRST(&ssh->private_साँचोहरू)) != रिक्त) {
		TAILQ_REMOVE(&ssh->private_साँचोहरू, k, next);
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
	फर्काऊ ssh->app_data;
}

/* Returns < 0 on error, 0 otherwise */
पूर्णाङ्क
ssh_add_hostkey(संरचना ssh *ssh, संरचना sshkey *साँचो)
{
	संरचना sshkey *pubkey = रिक्त;
	संरचना साँचो_entry *k = रिक्त, *k_prv = रिक्त;
	पूर्णाङ्क r;

	यदि (ssh->kex->server) {
		यदि ((r = sshkey_from_private(साँचो, &pubkey)) != 0)
			फर्काऊ r;
		यदि ((k = दो_स्मृति(परिमाण(*k))) == रिक्त ||
		    (k_prv = दो_स्मृति(परिमाण(*k_prv))) == रिक्त) {
			मुक्त(k);
			sshkey_free(pubkey);
			फर्काऊ SSH_ERR_ALLOC_FAIL;
		}
		k_prv->साँचो = साँचो;
		TAILQ_INSERT_TAIL(&ssh->private_साँचोहरू, k_prv, next);

		/* add the public key, too */
		k->साँचो = pubkey;
		TAILQ_INSERT_TAIL(&ssh->public_साँचोहरू, k, next);
		r = 0;
	} अन्यथा {
		यदि ((k = दो_स्मृति(परिमाण(*k))) == रिक्त)
			फर्काऊ SSH_ERR_ALLOC_FAIL;
		k->साँचो = साँचो;
		TAILQ_INSERT_TAIL(&ssh->public_साँचोहरू, k, next);
		r = 0;
	}

	फर्काऊ r;
}

पूर्णाङ्क
ssh_set_verify_host_साँचो_callback(संरचना ssh *ssh,
    पूर्णाङ्क (*cb)(संरचना sshkey *, संरचना ssh *))
{
	यदि (cb == रिक्त || ssh->kex == रिक्त)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;

	ssh->kex->verify_host_साँचो = cb;

	फर्काऊ 0;
}

पूर्णाङ्क
ssh_आगत_append(संरचना ssh *ssh, अचर u_char *data, माप_प्रकार len)
{
	फर्काऊ sshbuf_put(ssh_packet_get_आगत(ssh), data, len);
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
	*typep = SSH_सन्देश_NONE;
	यदि (sshbuf_len(ssh->kex->client_version) == 0 ||
	    sshbuf_len(ssh->kex->server_version) == 0)
		फर्काऊ _ssh_exchange_banner(ssh);
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
	लागि (;;) {
		यदि ((r = ssh_packet_read_poll2(ssh, &type, &seqnr)) != 0)
			फर्काऊ r;
		यदि (type > 0 && type < DISPATCH_MAX &&
		    type >= SSH2_सन्देश_KEXINIT && type <= SSH2_सन्देश_TRANSPORT_MAX &&
		    ssh->dispatch[type] != रिक्त) {
			यदि ((r = (*ssh->dispatch[type])(type, seqnr, ssh)) != 0)
				फर्काऊ r;
		} अन्यथा {
			*typep = type;
			फर्काऊ 0;
		}
	}
}

अचर u_char *
ssh_packet_payload(संरचना ssh *ssh, माप_प्रकार *lenp)
{
	फर्काऊ sshpkt_ptr(ssh, lenp);
}

पूर्णाङ्क
ssh_packet_put(संरचना ssh *ssh, पूर्णाङ्क type, अचर u_char *data, माप_प्रकार len)
{
	पूर्णाङ्क r;

	यदि ((r = sshpkt_start(ssh, type)) != 0 ||
	    (r = sshpkt_put(ssh, data, len)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		फर्काऊ r;
	फर्काऊ 0;
}

अचर u_char *
ssh_output_ptr(संरचना ssh *ssh, माप_प्रकार *len)
{
	संरचना sshbuf *output = ssh_packet_get_output(ssh);

	*len = sshbuf_len(output);
	फर्काऊ sshbuf_ptr(output);
}

पूर्णाङ्क
ssh_output_consume(संरचना ssh *ssh, माप_प्रकार len)
{
	फर्काऊ sshbuf_consume(ssh_packet_get_output(ssh), len);
}

पूर्णाङ्क
ssh_output_space(संरचना ssh *ssh, माप_प्रकार len)
{
	फर्काऊ (0 == sshbuf_check_reserve(ssh_packet_get_output(ssh), len));
}

पूर्णाङ्क
ssh_आगत_space(संरचना ssh *ssh, माप_प्रकार len)
{
	फर्काऊ (0 == sshbuf_check_reserve(ssh_packet_get_आगत(ssh), len));
}

/* Read other side's version identification. */
पूर्णाङ्क
_ssh_read_banner(संरचना ssh *ssh, संरचना sshbuf *banner)
{
	संरचना sshbuf *आगत = ssh_packet_get_आगत(ssh);
	अचर वर्ण *mismatch = "Protocol mismatch.\r\n";
	अचर u_char *s = sshbuf_ptr(आगत);
	u_char c;
	वर्ण *cp = रिक्त, *remote_version = रिक्त;
	पूर्णाङ्क r = 0, remote_major, remote_minor, expect_nl;
	माप_प्रकार n, j;

	लागि (j = n = 0;;) {
		sshbuf_reset(banner);
		expect_nl = 0;
		लागि (;;) {
			यदि (j >= sshbuf_len(आगत))
				फर्काऊ 0; /* insufficient data in input buf */
			c = s[j++];
			यदि (c == '\r') {
				expect_nl = 1;
				जारी;
			}
			यदि (c == '\n')
				रोक;
			यदि (expect_nl)
				गच्छ bad;
			यदि ((r = sshbuf_put_u8(banner, c)) != 0)
				फर्काऊ r;
			यदि (sshbuf_len(banner) > SSH_MAX_BANNER_LEN)
				गच्छ bad;
		}
		यदि (sshbuf_len(banner) >= 4 &&
		    स_भेद(sshbuf_ptr(banner), "SSH-", 4) == 0)
			रोक;
		debug_f("%.*s", (पूर्णाङ्क)sshbuf_len(banner),
		    sshbuf_ptr(banner));
		/* Accept lines before banner only on client */
		यदि (ssh->kex->server || ++n > SSH_MAX_PRE_BANNER_पङ्क्तिहरू) {
  bad:
			यदि ((r = sshbuf_put(ssh_packet_get_output(ssh),
			    mismatch, म_माप(mismatch))) != 0)
				फर्काऊ r;
			फर्काऊ SSH_ERR_NO_PROTOCOL_VERSION;
		}
	}
	यदि ((r = sshbuf_consume(आगत, j)) != 0)
		फर्काऊ r;

	/* XXX remote version must be the same size as banner for sscanf */
	यदि ((cp = sshbuf_dup_string(banner)) == रिक्त ||
	    (remote_version = सुस्मृति(1, sshbuf_len(banner))) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	यदि (माला_पूछो(cp, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);

	compat_banner(ssh, remote_version);
	यदि  (remote_major == 1 && remote_minor == 99) {
		remote_major = 2;
		remote_minor = 0;
	}
	यदि (remote_major != 2)
		r = SSH_ERR_PROTOCOL_MISMATCH;

	debug("Remote version string %.100s", cp);
 out:
	मुक्त(cp);
	मुक्त(remote_version);
	फर्काऊ r;
}

/* Send our own protocol version identification. */
पूर्णाङ्क
_ssh_send_banner(संरचना ssh *ssh, संरचना sshbuf *banner)
{
	वर्ण *cp;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_putf(banner, "SSH-2.0-%.100s\r\n", SSH_VERSION)) != 0)
		फर्काऊ r;
	यदि ((r = sshbuf_putb(ssh_packet_get_output(ssh), banner)) != 0)
		फर्काऊ r;
	/* Remove trailing \r\n */
	यदि ((r = sshbuf_consume_end(banner, 2)) != 0)
		फर्काऊ r;
	यदि ((cp = sshbuf_dup_string(banner)) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	debug("Local version string %.100s", cp);
	मुक्त(cp);
	फर्काऊ 0;
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
		यदि (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->server_version);
		यदि (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->client_version);
	} अन्यथा {
		यदि (sshbuf_len(ssh->kex->server_version) == 0)
			r = _ssh_read_banner(ssh, ssh->kex->server_version);
		यदि (r == 0 &&
		    sshbuf_len(ssh->kex->server_version) != 0 &&
		    sshbuf_len(ssh->kex->client_version) == 0)
			r = _ssh_send_banner(ssh, ssh->kex->client_version);
	}
	यदि (r != 0)
		फर्काऊ r;
	/* start initial kex as soon as we have exchanged the banners */
	यदि (sshbuf_len(ssh->kex->server_version) != 0 &&
	    sshbuf_len(ssh->kex->client_version) != 0) {
		यदि ((r = _ssh_order_hostkeyalgs(ssh)) != 0 ||
		    (r = kex_send_kexinit(ssh)) != 0)
			फर्काऊ r;
	}
	फर्काऊ 0;
}

संरचना sshkey *
ssh_host_public_साँचो(पूर्णाङ्क type, पूर्णाङ्क nid, संरचना ssh *ssh)
{
	संरचना साँचो_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->public_साँचोहरू, next) {
		debug3_f("check %s", sshkey_type(k->साँचो));
		यदि (k->साँचो->type == type &&
		    (type != साँचो_ECDSA || k->साँचो->ecdsa_nid == nid))
			फर्काऊ (k->साँचो);
	}
	फर्काऊ (रिक्त);
}

संरचना sshkey *
ssh_host_private_साँचो(पूर्णाङ्क type, पूर्णाङ्क nid, संरचना ssh *ssh)
{
	संरचना साँचो_entry *k;

	debug3_f("need %d", type);
	TAILQ_FOREACH(k, &ssh->private_साँचोहरू, next) {
		debug3_f("check %s", sshkey_type(k->साँचो));
		यदि (k->साँचो->type == type &&
		    (type != साँचो_ECDSA || k->साँचो->ecdsa_nid == nid))
			फर्काऊ (k->साँचो);
	}
	फर्काऊ (रिक्त);
}

पूर्णाङ्क
ssh_verify_host_साँचो(संरचना sshkey *hostkey, संरचना ssh *ssh)
{
	संरचना साँचो_entry *k;

	debug3_f("need %s", sshkey_type(hostkey));
	TAILQ_FOREACH(k, &ssh->public_साँचोहरू, next) {
		debug3_f("check %s", sshkey_type(k->साँचो));
		यदि (sshkey_equal_public(hostkey, k->साँचो))
			फर्काऊ (0);	/* ok */
	}
	फर्काऊ (-1);	/* failed */
}

/* offer hostkey algorithms in kexinit depending on registered keys */
पूर्णाङ्क
_ssh_order_hostkeyalgs(संरचना ssh *ssh)
{
	संरचना साँचो_entry *k;
	वर्ण *orig, *avail, *oavail = रिक्त, *alg, *replace = रिक्त;
	वर्ण **proposal;
	माप_प्रकार maxlen;
	पूर्णाङ्क ktype, nid, r;

	/* XXX we de-serialize ssh->kex->my, modify it, and change it */
	यदि ((r = kex_buf2prop(ssh->kex->my, रिक्त, &proposal)) != 0)
		फर्काऊ r;
	orig = proposal[PROPOSAL_SERVER_HOST_साँचो_ALGS];
	यदि ((oavail = avail = strdup(orig)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	maxlen = म_माप(avail) + 1;
	यदि ((replace = सुस्मृति(1, maxlen)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	*replace = '\0';
	जबसम्म ((alg = strsep(&avail, ",")) && *alg != '\0') {
		यदि ((ktype = sshkey_type_from_name(alg)) == साँचो_UNSPEC)
			जारी;
		nid = sshkey_ecdsa_nid_from_name(alg);
		TAILQ_FOREACH(k, &ssh->public_साँचोहरू, next) {
			यदि (k->साँचो->type != ktype &&
			    (!sshkey_is_cert(k->साँचो) ||
			    k->साँचो->type != sshkey_type_plain(ktype)))
				जारी;
			यदि (sshkey_type_plain(k->साँचो->type) == साँचो_ECDSA &&
			    k->साँचो->ecdsa_nid != nid)
				जारी;
			/* Candidate */
			यदि (*replace != '\0')
				strlcat(replace, ",", maxlen);
			strlcat(replace, alg, maxlen);
			रोक;
		}
	}
	यदि (*replace != '\0') {
		debug2_f("orig/%d    %s", ssh->kex->server, orig);
		debug2_f("replace/%d %s", ssh->kex->server, replace);
		मुक्त(orig);
		proposal[PROPOSAL_SERVER_HOST_साँचो_ALGS] = replace;
		replace = रिक्त;	/* owned by proposal */
		r = kex_prop2buf(ssh->kex->my, proposal);
	}
 out:
	मुक्त(oavail);
	मुक्त(replace);
	kex_prop_free(proposal);
	फर्काऊ r;
}

पूर्णाङ्क
ssh_host_साँचो_sign(संरचना ssh *ssh, संरचना sshkey *privkey,
    संरचना sshkey *pubkey, u_char **signature, माप_प्रकार *slen,
    अचर u_char *data, माप_प्रकार dlen, अचर वर्ण *alg)
{
	फर्काऊ sshkey_sign(privkey, signature, slen, data, dlen,
	    alg, रिक्त, रिक्त, ssh->compat);
}
