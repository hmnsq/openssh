/* $OpenBSD: kex.c,v 1.196 2026/09/22 00:24:47 dtucker Exp $ */
/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#यदि_परिभाषितम् WITH_OPENSSL
#अन्तर्भाव <openssl/crypto.h>
#अन्तर्भाव <openssl/dh.h>
#यदि_अन्तः

#अन्तर्भाव "ssh.h"
#अन्तर्भाव "ssh2.h"
#अन्तर्भाव "atomicio.h"
#अन्तर्भाव "version.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "compat.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "mac.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "dispatch.h"
#अन्तर्भाव "myproposal.h"

#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "xmalloc.h"

/* prototype */
स्थिर पूर्णाङ्क kex_वृणु_conf(संरचना ssh *, uint32_t seq);
स्थिर पूर्णाङ्क kex_निवेशः_newkeys(पूर्णाङ्क, uint32_t, संरचना ssh *);

स्थिर ध्रुव वर्ण * ध्रुव proposal_नामानि[PROPOSAL_MAX] = {
	"KEX algorithms",
	"host key algorithms",
	"ciphers ctos",
	"ciphers stoc",
	"MACs ctos",
	"MACs stoc",
	"compression ctos",
	"compression stoc",
	"languages ctos",
	"languages stoc",
};

/*
 * Fill out a proposal array with dynamically allocated values, which may
 * be modified as required for compatibility reasons.
 * Any of the options may be NULL, in which case the default is used.
 * Array contents must be freed by calling kex_proposal_free_entries.
 */
शून्य
kex_proposal_populate_entries(संरचना ssh *ssh, वर्ण *prop[PROPOSAL_MAX],
    ध्रुव वर्ण *kexalgos, ध्रुव वर्ण *ciphers, ध्रुव वर्ण *macs,
    ध्रुव वर्ण *comp, ध्रुव वर्ण *hkalgs)
{
	ध्रुव वर्ण *defpropserver[PROPOSAL_MAX] = { KEX_SERVER };
	ध्रुव वर्ण *defpropclient[PROPOSAL_MAX] = { KEX_CLIENT };
	ध्रुव वर्ण **defprop = ssh->kex->server ? defpropserver : defpropclient;
	u_int i;
	वर्ण *cp;

	यदि (prop == रिक्त)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	यदि (kexalgos == रिक्त)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	यदि ((cp = kex_नामानि_cat(kexalgos, ssh->kex->server ?
	    "ext-info-s,kex-strict-s-v00@openssh.com" :
	    "ext-info-c,kex-strict-c-v00@openssh.com")) == रिक्त)
		fatal_f("kex_names_cat");

	प्रति (i = 0; i < PROPOSAL_MAX; i++) {
		विकल्प(i) {
		पक्ष PROPOSAL_KEX_ALGS:
			prop[i] = compat_kex_proposal(ssh, cp);
			भङ्ग;
		पक्ष PROPOSAL_ENC_ALGS_CTOS:
		पक्ष PROPOSAL_ENC_ALGS_STOC:
			prop[i] = xstrdup(ciphers ? ciphers : defprop[i]);
			भङ्ग;
		पक्ष PROPOSAL_MAC_ALGS_CTOS:
		पक्ष PROPOSAL_MAC_ALGS_STOC:
			prop[i]  = xstrdup(macs ? macs : defprop[i]);
			भङ्ग;
		पक्ष PROPOSAL_COMP_ALGS_CTOS:
		पक्ष PROPOSAL_COMP_ALGS_STOC:
			prop[i] = xstrdup(comp ? comp : defprop[i]);
			भङ्ग;
		पक्ष PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS:
			prop[i] = xstrdup(hkalgs ? hkalgs : defprop[i]);
			भङ्ग;
		स्वभाव:
			prop[i] = xstrdup(defprop[i]);
		}
	}
	मुक्त(cp);
}

शून्य
kex_proposal_free_entries(वर्ण *prop[PROPOSAL_MAX])
{
	u_int i;

	प्रति (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(prop[i]);
}

/* put algorithm proposal into buffer */
पूर्णाङ्क
kex_prop2buf(संरचना sshbuf *b, वर्ण *proposal[PROPOSAL_MAX])
{
	u_int i;
	पूर्णाङ्क r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	प्रति (i = 0; i < KEX_COOKIE_LEN; i++) {
		यदि ((r = sshbuf_put_u8(b, 0)) != 0)
			प्रत्यागम r;
	}
	प्रति (i = 0; i < PROPOSAL_MAX; i++) {
		यदि ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			प्रत्यागम r;
	}
	यदि ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		प्रत्यागम r;
	प्रत्यागम 0;
}

/* parse buffer and return algorithm proposal */
पूर्णाङ्क
kex_buf2prop(संरचना sshbuf *raw, पूर्णाङ्क *first_kex_follows, वर्ण ***propp)
{
	संरचना sshbuf *b = रिक्त;
	u_char v;
	u_int i;
	वर्ण **proposal = रिक्त;
	पूर्णाङ्क r;

	*propp = रिक्त;
	यदि ((proposal = शून्यस्मृतिं_देहि(PROPOSAL_MAX, परिमाण(वर्ण *))) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((b = sshbuf_fromb(raw)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		गच्छ बहिर्गमनम्;
	}
	/* extract kex init proposal strings */
	प्रति (i = 0; i < PROPOSAL_MAX; i++) {
		यदि ((r = sshbuf_get_cstring(b, &(proposal[i]), रिक्त)) != 0) {
			error_fr(r, "parse proposal %u", i);
			गच्छ बहिर्गमनम्;
		}
		debug2("%s: %s", proposal_नामानि[i], proposal[i]);
	}
	/* first kex follows / reserved */
	यदि ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		गच्छ बहिर्गमनम्;
	}
	यदि (first_kex_follows != रिक्त)
		*first_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 बहिर्गमनम्:
	यदि (r != 0 && proposal != रिक्त)
		kex_prop_free(proposal);
	sshbuf_free(b);
	प्रत्यागम r;
}

शून्य
kex_prop_free(वर्ण **proposal)
{
	u_int i;

	यदि (proposal == रिक्त)
		प्रत्यागम;
	प्रति (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(proposal[i]);
	मुक्त(proposal);
}

पूर्णाङ्क
kex_protocol_error(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	पूर्णाङ्क r;

	/* If in strict mode, any unexpected message is an error */
	यदि ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		प्रत्यागम r;
	प्रत्यागम 0;
}

स्थिर शून्य
kex_reset_dispatch(संरचना ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_सन्देशः_TRANSPORT_MIN,
	    SSH2_सन्देशः_TRANSPORT_MAX, &kex_protocol_error);
}

शून्य
kex_समुच्चयः_server_sig_algs(संरचना ssh *ssh, ध्रुव वर्ण *allowed_algs)
{
	वर्ण *alg, *oalgs, *algs, *sigalgs;
	ध्रुव वर्ण *sigalg;

	/*
	 * NB. allowed algorithms may contain certificate algorithms that
	 * map to a specific plain signature type, e.g.
	 * rsa-sha2-512-cert-v01@openssh.com => rsa-sha2-512
	 * We need to be careful here to match these, retain the mapping
	 * and only add each signature algorithm once.
	 */
	यदि ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == रिक्त)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	मुक्त(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = रिक्त;
	प्रति ((alg = strsep(&algs, ",")); alg != रिक्त && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		यदि ((sigalg = sshkey_sigalg_by_name(alg)) == रिक्त)
			अनुवर्त;
		यदि (!kex_has_any_alg(sigalg, sigalgs))
			अनुवर्त;
		/* Don't add an algorithm twice. */
		यदि (ssh->kex->server_sig_algs != रिक्त &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			अनुवर्त;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	मुक्त(oalgs);
	मुक्त(sigalgs);
	यदि (ssh->kex->server_sig_algs == रिक्त)
		ssh->kex->server_sig_algs = xstrdup("");
}

शून्य
kex_समुच्चयः_warn_weak_crypto(संरचना ssh *ssh, पूर्णाङ्क warn_weak_crypto)
{
	यदि (ssh != रिक्त && ssh->kex != रिक्त)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

शून्य
kex_check_warn_weak_crypto(संरचना ssh *ssh)
{
	वर्ण remote_id[512];
	पूर्णाङ्क rekeyed = 0;

	यदि (ssh == रिक्त || ssh->kex == रिक्त || ssh->kex->name == रिक्त ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		प्रत्यागम;
	यदि (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		प्रत्यागम;
	}

	यदि (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	यदि (!rekeyed && !ssh->kex->server)
		प्रत्यागम; /* client logs initial KEX warning separately */

	sshpkt_fmt_connection_id(ssh, remote_id, परिमाण(remote_id));
	logit("WARNING: %sconnection%s%s is not using a post-quantum "
	    "key exchange algorithm: \"%s\"", rekeyed ? "rekeyed " : "",
	    ssh->kex->server ? " from " : "",
	    ssh->kex->server ? remote_id : "", ssh->kex->name);
	ssh->kex->non_pq_kex_warned = 1;
}

स्थिर पूर्णाङ्क
kex_compose_ext_info_server(संरचना ssh *ssh, संरचना sshbuf *m)
{
	पूर्णाङ्क r;

	यदि (ssh->kex->server_sig_algs == रिक्त &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_put_u32(m, 4)) != 0 ||
	    (r = sshbuf_put_cstring(m, "server-sig-algs")) != 0 ||
	    (r = sshbuf_put_cstring(m, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshbuf_put_cstring(m,
	    "publickey-hostbound@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0 ||
	    (r = sshbuf_put_cstring(m, "ping@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0 ||
	    (r = sshbuf_put_cstring(m, "agent-forward")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		प्रत्यागम r;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
kex_compose_ext_info_client(संरचना ssh *ssh, संरचना sshbuf *m)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		गच्छ बहिर्गमनम्;
	}
	/* success */
	r = 0;
 बहिर्गमनम्:
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
kex_maybe_send_ext_info(संरचना ssh *ssh)
{
	पूर्णाङ्क r;
	संरचना sshbuf *m = रिक्त;

	यदि ((ssh->kex->flags & KEX_INITIAL) == 0)
		प्रत्यागम 0;
	यदि (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		प्रत्यागम 0;

	/* Compose EXT_INFO packet. */
	यदि ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	यदि (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		गच्छ fail;
	यदि (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		गच्छ fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		गच्छ fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	प्रत्यागम r;
}

पूर्णाङ्क
kex_server_update_ext_info(संरचना ssh *ssh)
{
	पूर्णाङ्क r;

	यदि ((ssh->kex->flags & KEX_HAS_EXT_INFO_अन्तर्_AUTH) == 0)
		प्रत्यागम 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		प्रत्यागम r;
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
kex_send_newkeys(संरचना ssh *ssh)
{
	पूर्णाङ्क r;

	kex_reset_dispatch(ssh);
	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		प्रत्यागम r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_NEWKEYS, &kex_निवेशः_newkeys);
	यदि ((r = kex_maybe_send_ext_info(ssh)) != 0)
		प्रत्यागम r;
	debug("expecting SSH2_MSG_NEWKEYS");
	प्रत्यागम 0;
}

/* Check whether an ext_info value contains the expected version string */
स्थिर पूर्णाङ्क
kex_ext_info_check_ver(संरचना kex *kex, ध्रुव वर्ण *name,
    ध्रुव u_char *val, आकार_t len, ध्रुव वर्ण *want_ver, u_int flag)
{
	यदि (memchr(val, '\0', len) != रिक्त) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	यदि (वाक्यं_तुलय(val, want_ver) == 0)
		kex->flags |= flag;
	अन्यथा
		debug_f("unsupported version of %s extension", name);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
kex_ext_info_client_parse(संरचना ssh *ssh, ध्रुव वर्ण *name,
    ध्रुव u_char *मानम्, आकार_t vlen)
{
	पूर्णाङ्क r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	यदि (वाक्यं_तुलय(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		यदि (memchr(मानम्, '\0', vlen) != रिक्त) {
			error_f("nul byte in %s", name);
			प्रत्यागम SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, मानम्);
		मुक्त(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((ध्रुव वर्ण *)मानम्);
	} अन्यथा यदि (ssh->kex->ext_info_received == 1 &&
	    वाक्यं_तुलय(name, "publickey-hostbound@openssh.com") == 0) {
		यदि ((r = kex_ext_info_check_ver(ssh->kex, name, मानम्, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			प्रत्यागम r;
		}
	} अन्यथा यदि (ssh->kex->ext_info_received == 1 &&
	    वाक्यं_तुलय(name, "ping@openssh.com") == 0) {
		यदि ((r = kex_ext_info_check_ver(ssh->kex, name, मानम्, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			प्रत्यागम r;
		}
	} अन्यथा यदि (ssh->kex->ext_info_received == 1 &&
	    वाक्यं_तुलय(name, "agent-forward") == 0) {
		यदि ((r = kex_ext_info_check_ver(ssh->kex, name, मानम्, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			प्रत्यागम r;
		}
	} अन्यथा
		debug_f("%s (unrecognised)", name);

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
kex_ext_info_server_parse(संरचना ssh *ssh, ध्रुव वर्ण *name,
    ध्रुव u_char *मानम्, आकार_t vlen)
{
	पूर्णाङ्क r;

	यदि (वाक्यं_तुलय(name, "ext-info-in-auth@openssh.com") == 0) {
		यदि ((r = kex_ext_info_check_ver(ssh->kex, name, मानम्, vlen,
		    "0", KEX_HAS_EXT_INFO_अन्तर्_AUTH)) != 0) {
			प्रत्यागम r;
		}
	} अन्यथा
		debug_f("%s (unrecognised)", name);
	प्रत्यागम 0;
}

पूर्णाङ्क
kex_निवेशः_ext_info(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	ध्रुव पूर्णाङ्क max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	वर्ण *name;
	u_char *val;
	आकार_t vlen;
	पूर्णाङ्क r;

	debug("SSH2_MSG_EXT_INFO received");
	यदि (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		प्रत्यागम dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_EXT_INFO, &kex_protocol_error);
	यदि ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		प्रत्यागम r;
	यदि (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		प्रत्यागम dispatch_protocol_error(type, seq, ssh);
	}
	प्रति (i = 0; i < ninfo; i++) {
		यदि ((r = sshpkt_get_cstring(ssh, &name, रिक्त)) != 0)
			प्रत्यागम r;
		यदि ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			मुक्त(name);
			प्रत्यागम r;
		}
		debug3_f("extension %s", name);
		यदि (kex->server) {
			यदि ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				प्रत्यागम r;
		} अन्यथा {
			यदि ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				प्रत्यागम r;
		}
		मुक्त(name);
		मुक्त(val);
	}
	प्रत्यागम sshpkt_get_अन्तः(ssh);
}

स्थिर पूर्णाङ्क
kex_निवेशः_newkeys(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	पूर्णाङ्क r, initial = (kex->flags & KEX_INITIAL) != 0;
	वर्ण *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	यदि (kex->ext_info_c && initial)
		ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_EXT_INFO, &kex_निवेशः_ext_info);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_KEXINIT, &kex_निवेशः_kexinit);
	यदि ((r = sshpkt_get_अन्तः(ssh)) != 0)
		प्रत्यागम r;
	यदि ((r = ssh_समुच्चयः_newkeys(ssh, बहुलकम्_अन्तर्)) != 0)
		प्रत्यागम r;
	यदि (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		यदि ((r = kex_buf2prop(kex->my, रिक्त, &prop)) != 0)
			प्रत्यागम r;
		यदि ((cp = मेलनम्_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == रिक्त) {
			error_f("match_filter_denylist failed");
			गच्छ fail;
		}
		मुक्त(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		यदि ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			मुक्त(prop);
			प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
		}
		kex_proposal_free_entries(prop);
		मुक्त(prop);
	}
	kex->समाप्तम् = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_प्रेषितम्|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	प्रत्यागम 0;
}

पूर्णाङ्क
kex_send_kexinit(संरचना ssh *ssh)
{
	u_char *cookie;
	संरचना kex *kex = ssh->kex;
	पूर्णाङ्क r;

	यदि (kex == रिक्त) {
		error_f("no kex");
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	}
	यदि (kex->flags & KEX_INIT_प्रेषितम्)
		प्रत्यागम 0;
	kex->समाप्तम् = 0;

	/* generate a random cookie */
	यदि (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	}
	यदि ((cookie = sshbuf_mutable_ptr(kex->my)) == रिक्त) {
		error_f("buffer error");
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	यदि ((r = sshpkt_start(ssh, SSH2_सन्देशः_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		प्रत्यागम r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_प्रेषितम्;
	प्रत्यागम 0;
}

पूर्णाङ्क
kex_निवेशः_kexinit(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	ध्रुव u_char *ptr;
	u_int i;
	आकार_t dlen;
	पूर्णाङ्क r;

	debug("SSH2_MSG_KEXINIT received");
	यदि (kex == रिक्त) {
		error_f("no kex");
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	}
	मुक्त(kex->name);
	kex->name = रिक्त;
	यदि ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	यदि ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		प्रत्यागम r;

	/* discard packet */
	प्रति (i = 0; i < KEX_COOKIE_LEN; i++) {
		यदि ((r = sshpkt_get_u8(ssh, रिक्त)) != 0) {
			error_fr(r, "discard cookie");
			प्रत्यागम r;
		}
	}
	प्रति (i = 0; i < PROPOSAL_MAX; i++) {
		यदि ((r = sshpkt_get_string(ssh, रिक्त, रिक्त)) != 0) {
			error_fr(r, "discard proposal");
			प्रत्यागम r;
		}
	}
	/*
	 * XXX RFC4253 sec 7: "each side MAY guess" - currently no supported
	 * KEX method has the server move first, but a server might be using
	 * a custom method or one that we otherwise don't support. We should
	 * be prepared to remember first_kex_follows here so we can eat a
	 * packet later.
	 * XXX2 - RFC4253 is kind of ambiguous on what first_kex_follows means
	 * for cases where the server *doesn't* go first. I guess we should
	 * ignore it when it is set for these cases, which is what we do now.
	 */
	यदि ((r = sshpkt_get_u8(ssh, रिक्त)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, रिक्त)) != 0 ||	/* reserved */
	    (r = sshpkt_get_अन्तः(ssh)) != 0)
			प्रत्यागम r;

	यदि (!(kex->flags & KEX_INIT_प्रेषितम्))
		यदि ((r = kex_send_kexinit(ssh)) != 0)
			प्रत्यागम r;
	यदि ((r = kex_वृणु_conf(ssh, seq)) != 0)
		प्रत्यागम r;

	यदि (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != रिक्त)
		प्रत्यागम (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
}

संरचना kex *
kex_new(शून्य)
{
	संरचना kex *kex;

	यदि ((kex = शून्यस्मृतिं_देहि(1, परिमाण(*kex))) == रिक्त ||
	    (kex->peer = sshbuf_new()) == रिक्त ||
	    (kex->my = sshbuf_new()) == रिक्त ||
	    (kex->client_संस्करणम् = sshbuf_new()) == रिक्त ||
	    (kex->server_संस्करणम् = sshbuf_new()) == रिक्त ||
	    (kex->session_id = sshbuf_new()) == रिक्त) {
		kex_free(kex);
		प्रत्यागम रिक्त;
	}
	प्रत्यागम kex;
}

शून्य
kex_free_newkeys(संरचना newkeys *newkeys)
{
	यदि (newkeys == रिक्त)
		प्रत्यागम;
	यदि (newkeys->enc.कुञ्चिका) {
		explicit_bzero(newkeys->enc.कुञ्चिका, newkeys->enc.कुञ्चिका_len);
		मुक्त(newkeys->enc.कुञ्चिका);
		newkeys->enc.कुञ्चिका = रिक्त;
	}
	यदि (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		मुक्त(newkeys->enc.iv);
		newkeys->enc.iv = रिक्त;
	}
	मुक्त(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, परिमाण(newkeys->enc));
	मुक्त(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, परिमाण(newkeys->comp));
	mac_clear(&newkeys->mac);
	यदि (newkeys->mac.कुञ्चिका) {
		explicit_bzero(newkeys->mac.कुञ्चिका, newkeys->mac.कुञ्चिका_len);
		मुक्त(newkeys->mac.कुञ्चिका);
		newkeys->mac.कुञ्चिका = रिक्त;
	}
	मुक्त(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, परिमाण(newkeys->mac));
	freezero(newkeys, परिमाण(*newkeys));
}

शून्य
kex_free(संरचना kex *kex)
{
	u_int बहुलकम्;

	यदि (kex == रिक्त)
		प्रत्यागम;

#यदि_परिभाषितम् WITH_OPENSSL
	DH_free(kex->dh);
	EC_कुञ्चिका_free(kex->ec_client_कुञ्चिका);
#यदि_अन्तः /* WITH_OPENSSL */
	प्रति (बहुलकम् = 0; बहुलकम् < बहुलकम्_MAX; बहुलकम्++) {
		kex_free_newkeys(kex->newkeys[बहुलकम्]);
		kex->newkeys[बहुलकम्] = रिक्त;
	}
	sshbuf_free(kex->peer);
	sshbuf_free(kex->my);
	sshbuf_free(kex->client_संस्करणम्);
	sshbuf_free(kex->server_संस्करणम्);
	sshbuf_free(kex->client_pub);
	sshbuf_free(kex->session_id);
	sshbuf_free(kex->initial_sig);
	sshkey_free(kex->initial_hostkey);
	मुक्त(kex->failed_choice);
	मुक्त(kex->hostkey_alg);
	मुक्त(kex->name);
	मुक्त(kex->server_sig_algs);
	मुक्त(kex);
}

पूर्णाङ्क
kex_ready(संरचना ssh *ssh, वर्ण *proposal[PROPOSAL_MAX])
{
	पूर्णाङ्क r;

	यदि ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		प्रत्यागम r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_समुच्चयः(ssh, SSH2_सन्देशः_KEXINIT, &kex_निवेशः_kexinit);
	प्रत्यागम 0;
}

पूर्णाङ्क
kex_सज्जता(संरचना ssh *ssh, वर्ण *proposal[PROPOSAL_MAX])
{
	पूर्णाङ्क r;

	यदि ((r = kex_ready(ssh, proposal)) != 0)
		प्रत्यागम r;
	यदि ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = रिक्त;
		प्रत्यागम r;
	}
	प्रत्यागम 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
पूर्णाङ्क
kex_start_rekex(संरचना ssh *ssh)
{
	यदि (ssh->kex == रिक्त) {
		error_f("no kex");
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	}
	यदि (ssh->kex->समाप्तम् == 0) {
		error_f("requested twice");
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	}
	ssh->kex->समाप्तम् = 0;
	प्रत्यागम kex_send_kexinit(ssh);
}

स्थिर पूर्णाङ्क
वृणु_enc(संरचना sshenc *enc, वर्ण *client, वर्ण *server)
{
	वर्ण *name = मेलनम्_list(client, server, रिक्त);

	यदि (name == रिक्त)
		प्रत्यागम SSH_ERR_NO_CIPHER_ALG_मेलनम्;
	यदि ((enc->cipher = cipher_by_name(name)) == रिक्त) {
		error_f("unsupported cipher %s", name);
		मुक्त(name);
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = रिक्त;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->कुञ्चिका = रिक्त;
	enc->कुञ्चिका_len = cipher_keylen(enc->cipher);
	enc->खण्डम्_आकार = cipher_blocksize(enc->cipher);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
वृणु_mac(संरचना ssh *ssh, संरचना sshmac *mac, वर्ण *client, वर्ण *server)
{
	वर्ण *name = मेलनम्_list(client, server, रिक्त);

	यदि (name == रिक्त)
		प्रत्यागम SSH_ERR_NO_MAC_ALG_मेलनम्;
	यदि (mac_सज्जता(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		मुक्त(name);
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	}
	mac->name = name;
	mac->कुञ्चिका = रिक्त;
	mac->enabled = 0;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
वृणु_comp(संरचना sshcomp *comp, वर्ण *client, वर्ण *server)
{
	वर्ण *name = मेलनम्_list(client, server, रिक्त);

	यदि (name == रिक्त)
		प्रत्यागम SSH_ERR_NO_COMPRESS_ALG_मेलनम्;
#यदि_परिभाषितम् WITH_ZLIB
	यदि (वाक्यं_तुलय(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} अन्यथा
#यदि_अन्तः	/* WITH_ZLIB */
	यदि (वाक्यं_तुलय(name, "none") == 0) {
		comp->type = COMP_NONE;
	} अन्यथा {
		error_f("unsupported compression scheme %s", name);
		मुक्त(name);
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	}
	comp->name = name;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
वृणु_kex(संरचना kex *k, वर्ण *client, वर्ण *server)
{
	k->name = मेलनम्_list(client, server, रिक्त);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	यदि (k->name == रिक्त)
		प्रत्यागम SSH_ERR_NO_KEX_ALG_मेलनम्;
	यदि (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
वृणु_hostkeyalg(संरचना kex *k, वर्ण *client, वर्ण *server)
{
	मुक्त(k->hostkey_alg);
	k->hostkey_alg = मेलनम्_list(client, server, रिक्त);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	यदि (k->hostkey_alg == रिक्त)
		प्रत्यागम SSH_ERR_NO_HOSTKEY_ALG_मेलनम्;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	यदि (k->hostkey_type == कुञ्चिका_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
proposals_मेलनम्(वर्ण *my[PROPOSAL_MAX], वर्ण *peer[PROPOSAL_MAX])
{
	स्थिर पूर्णाङ्क check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS, -1
	};
	पूर्णाङ्क *idx;
	वर्ण *p;

	प्रति (idx = &check[0]; *idx != -1; idx++) {
		यदि ((p = strchr(my[*idx], ',')) != रिक्त)
			*p = '\0';
		यदि ((p = strchr(peer[*idx], ',')) != रिक्त)
			*p = '\0';
		यदि (वाक्यं_तुलय(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			प्रत्यागम (0);
		}
	}
	debug2("proposals match");
	प्रत्यागम (1);
}

स्थिर पूर्णाङ्क
kexalgs_अन्तर्भवति(वर्ण **peer, ध्रुव वर्ण *ext)
{
	प्रत्यागम kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

स्थिर पूर्णाङ्क
kex_वृणु_conf(संरचना ssh *ssh, uint32_t seq)
{
	संरचना kex *kex = ssh->kex;
	संरचना newkeys *newkeys;
	वर्ण **my = रिक्त, **peer = रिक्त;
	वर्ण **cprop, **sprop;
	पूर्णाङ्क nenc, nmac, ncomp;
	u_int बहुलकम्, ctos, need, dh_need, authlen;
	पूर्णाङ्क r, first_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	यदि ((r = kex_buf2prop(kex->my, रिक्त, &my)) != 0)
		गच्छ बहिर्गमनम्;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	यदि ((r = kex_buf2prop(kex->peer, &first_kex_follows, &peer)) != 0)
		गच्छ बहिर्गमनम्;

	यदि (kex->server) {
		cprop=peer;
		sprop=my;
	} अन्यथा {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	यदि ((kex->flags & KEX_INITIAL) != 0) {
		यदि (kex->server) {
			kex->ext_info_c = kexalgs_अन्तर्भवति(peer, "ext-info-c");
			kex->kex_strict = kexalgs_अन्तर्भवति(peer,
			    "kex-strict-c-v00@openssh.com");
		} अन्यथा {
			kex->ext_info_s = kexalgs_अन्तर्भवति(peer, "ext-info-s");
			kex->kex_strict = kexalgs_अन्तर्भवति(peer,
			    "kex-strict-s-v00@openssh.com");
		}
		यदि (kex->kex_strict) {
			debug3_f("will use strict KEX ordering");
			यदि (seq != 0)
				ssh_packet_disconnect(ssh,
				    "strict KEX violation: "
				    "KEXINIT was not the first packet");
		}
	}

	/* Check whether client supports rsa-sha2 algorithms */
	यदि (kex->server && (kex->flags & KEX_INITIAL)) {
		यदि (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		यदि (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	यदि ((r = वृणु_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = रिक्त;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = वृणु_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS];
		peer[PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS] = रिक्त;
		गच्छ बहिर्गमनम्;
	}
	प्रति (बहुलकम् = 0; बहुलकम् < बहुलकम्_MAX; बहुलकम्++) {
		यदि ((newkeys = शून्यस्मृतिं_देहि(1, परिमाण(*newkeys))) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ बहिर्गमनम्;
		}
		kex->newkeys[बहुलकम्] = newkeys;
		ctos = (!kex->server && बहुलकम् == बहुलकम्_बहिर्गमनम्) ||
		    (kex->server && बहुलकम् == बहुलकम्_अन्तर्);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		यदि ((r = वृणु_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = रिक्त;
			गच्छ बहिर्गमनम्;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		यदि (authlen == 0 &&
		    (r = वृणु_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = रिक्त;
			गच्छ बहिर्गमनम्;
		}
		यदि ((r = वृणु_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0) {
			kex->failed_choice = peer[ncomp];
			peer[ncomp] = रिक्त;
			गच्छ बहिर्गमनम्;
		}
		debug("kex: %s cipher: %s MAC: %s compression: %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    authlen == 0 ? newkeys->mac.name : "<implicit>",
		    newkeys->comp.name);
	}
	need = dh_need = 0;
	प्रति (बहुलकम् = 0; बहुलकम् < बहुलकम्_MAX; बहुलकम्++) {
		newkeys = kex->newkeys[बहुलकम्];
		need = अधिकतमम्(need, newkeys->enc.कुञ्चिका_len);
		need = अधिकतमम्(need, newkeys->enc.खण्डम्_आकार);
		need = अधिकतमम्(need, newkeys->enc.iv_len);
		need = अधिकतमम्(need, newkeys->mac.कुञ्चिका_len);
		dh_need = अधिकतमम्(dh_need, cipher_seclen(newkeys->enc.cipher));
		dh_need = अधिकतमम्(dh_need, newkeys->enc.खण्डम्_आकार);
		dh_need = अधिकतमम्(dh_need, newkeys->enc.iv_len);
		dh_need = अधिकतमम्(dh_need, newkeys->mac.कुञ्चिका_len);
	}
	/* XXX need runden? */
	kex->we_need = need;
	kex->dh_need = dh_need;

	/* ignore the next message if the proposals do not match */
	यदि (first_kex_follows && !proposals_मेलनम्(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 बहिर्गमनम्:
	kex_prop_free(my);
	kex_prop_free(peer);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
derive_कुञ्चिका(संरचना ssh *ssh, पूर्णाङ्क id, u_int need, u_char *hash, u_int hashlen,
    ध्रुव संरचना sshbuf *shared_secret, u_char **keyp)
{
	संरचना kex *kex = ssh->kex;
	संरचना ssh_digest_ctx *hashctx = रिक्त;
	वर्ण c = id;
	u_int have;
	आकार_t mdsz;
	u_char *digest;
	पूर्णाङ्क r;

	यदि ((mdsz = ssh_digest_अष्टकानि(kex->hash_alg)) == 0)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	यदि ((digest = शून्यस्मृतिं_देहि(1, ROUNDUP(need, mdsz))) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	यदि ((hashctx = ssh_digest_start(kex->hash_alg)) == रिक्त ||
	    ssh_digest_update_बफर(hashctx, shared_secret) != 0 ||
	    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
	    ssh_digest_update(hashctx, &c, 1) != 0 ||
	    ssh_digest_update_बफर(hashctx, kex->session_id) != 0 ||
	    ssh_digest_final(hashctx, digest, mdsz) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		error_f("KEX hash failed");
		गच्छ बहिर्गमनम्;
	}
	ssh_digest_free(hashctx);
	hashctx = रिक्त;

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	प्रति (have = mdsz; need > have; have += mdsz) {
		यदि ((hashctx = ssh_digest_start(kex->hash_alg)) == रिक्त ||
		    ssh_digest_update_बफर(hashctx, shared_secret) != 0 ||
		    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
		    ssh_digest_update(hashctx, digest, have) != 0 ||
		    ssh_digest_final(hashctx, digest + have, mdsz) != 0) {
			error_f("KDF failed");
			r = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ बहिर्गमनम्;
		}
		ssh_digest_free(hashctx);
		hashctx = रिक्त;
	}
#यदि_परिभाषितम् DEBUG_KEX
	fprintf(stderr, "key '%c'== ", c);
	dump_digest("key", digest, need);
#यदि_अन्तः
	*keyp = digest;
	digest = रिक्त;
	r = 0;
 बहिर्गमनम्:
	मुक्त(digest);
	ssh_digest_free(hashctx);
	प्रत्यागम r;
}

#परिभाषय NKEYS	6
पूर्णाङ्क
kex_derive_कुञ्चिकाः(संरचना ssh *ssh, u_char *hash, u_int hashlen,
    ध्रुव संरचना sshbuf *shared_secret)
{
	संरचना kex *kex = ssh->kex;
	u_char *कुञ्चिकाः[NKEYS];
	u_int i, j, बहुलकम्, ctos;
	पूर्णाङ्क r;

	/* save initial hash as session id */
	यदि ((kex->flags & KEX_INITIAL) != 0) {
		यदि (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
		}
		यदि ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			प्रत्यागम r;
	} अन्यथा यदि (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	}
	प्रति (i = 0; i < NKEYS; i++) {
		यदि ((r = derive_कुञ्चिका(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &कुञ्चिकाः[i])) != 0) {
			प्रति (j = 0; j < i; j++)
				मुक्त(कुञ्चिकाः[j]);
			प्रत्यागम r;
		}
	}
	प्रति (बहुलकम् = 0; बहुलकम् < बहुलकम्_MAX; बहुलकम्++) {
		ctos = (!kex->server && बहुलकम् == बहुलकम्_बहिर्गमनम्) ||
		    (kex->server && बहुलकम् == बहुलकम्_अन्तर्);
		kex->newkeys[बहुलकम्]->enc.iv  = कुञ्चिकाः[ctos ? 0 : 1];
		kex->newkeys[बहुलकम्]->enc.कुञ्चिका = कुञ्चिकाः[ctos ? 2 : 3];
		kex->newkeys[बहुलकम्]->mac.कुञ्चिका = कुञ्चिकाः[ctos ? 4 : 5];
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
kex_आरोपय_hostkey(संरचना ssh *ssh, संरचना sshkey **prvp, संरचना sshkey **pubp)
{
	संरचना kex *kex = ssh->kex;

	*pubp = रिक्त;
	*prvp = रिक्त;
	यदि (kex->आरोपय_host_लौकिकम्_कुञ्चिका == रिक्त ||
	    kex->आरोपय_host_वैयक्तिकम्_कुञ्चिका == रिक्त) {
		error_f("missing hostkey loader");
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	}
	*pubp = kex->आरोपय_host_लौकिकम्_कुञ्चिका(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->आरोपय_host_वैयक्तिकम्_कुञ्चिका(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	यदि (*pubp == रिक्त)
		प्रत्यागम SSH_ERR_NO_HOSTKEY_LOADED;
	प्रत्यागम 0;
}

पूर्णाङ्क
kex_verify_host_कुञ्चिका(संरचना ssh *ssh, संरचना sshkey *server_host_कुञ्चिका)
{
	संरचना kex *kex = ssh->kex;

	यदि (kex->verify_host_कुञ्चिका == रिक्त) {
		error_f("missing hostkey verifier");
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	}
	यदि (server_host_कुञ्चिका->type != kex->hostkey_type ||
	    (kex->hostkey_type == कुञ्चिका_ECDSA &&
	    server_host_कुञ्चिका->ecdsa_nid != kex->hostkey_nid))
		प्रत्यागम SSH_ERR_कुञ्चिका_TYPE_MISMATCH;
	यदि (kex->verify_host_कुञ्चिका(server_host_कुञ्चिका, ssh) == -1)
		प्रत्यागम  SSH_ERR_SIGNATURE_INVALID;
	प्रत्यागम 0;
}

#यदि defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
शून्य
dump_digest(ध्रुव वर्ण *सन्देशः, ध्रुव u_char *digest, पूर्णाङ्क len)
{
	fprintf(stderr, "%s\n", सन्देशः);
	sshbuf_dump_दत्त(digest, len, stderr);
}
#यदि_अन्तः

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
स्थिर शून्य
send_error(संरचना ssh *ssh, वर्ण *सन्देशः)
{
	वर्ण *crnl = "\r\n";

	यदि (!ssh->kex->server)
		प्रत्यागम;

	यदि (atomicio(vwrite, ssh_packet_get_connection_बहिर्गमनम्(ssh),
	    सन्देशः, वाक्यदैर्घ्यम्(सन्देशः)) != वाक्यदैर्घ्यम्(सन्देशः) ||
	    atomicio(vwrite, ssh_packet_get_connection_बहिर्गमनम्(ssh),
	    crnl, वाक्यदैर्घ्यम्(crnl)) != वाक्यदैर्घ्यम्(crnl))
		error_f("write: %.100s", strerror(errno));
}

/*
 * Sends our identification string and waits for the peer's. Will block for
 * up to timeout_ms (or indefinitely if timeout_ms <= 0).
 * Returns on 0 success or a ssherr.h code on failure.
 */
पूर्णाङ्क
kex_exchange_identification(संरचना ssh *ssh, पूर्णाङ्क timeout_ms,
    ध्रुव वर्ण *संस्करणम्_addendum)
{
	पूर्णाङ्क remote_major, remote_minor, mismatch, oerrno = 0;
	आकार_t len, n;
	पूर्णाङ्क r, expect_nl;
	u_char c;
	संरचना sshbuf *our_संस्करणम् = ssh->kex->server ?
	    ssh->kex->server_संस्करणम् : ssh->kex->client_संस्करणम्;
	संरचना sshbuf *peer_संस्करणम् = ssh->kex->server ?
	    ssh->kex->client_संस्करणम् : ssh->kex->server_संस्करणम्;
	वर्ण *our_संस्करणम्_string = रिक्त, *peer_संस्करणम्_string = रिक्त;
	वर्ण *cp, *remote_संस्करणम् = रिक्त;

	/* Prepare and send our banner */
	sshbuf_reset(our_संस्करणम्);
	यदि (संस्करणम्_addendum != रिक्त && *संस्करणम्_addendum == '\0')
		संस्करणम्_addendum = रिक्त;
	यदि ((r = sshbuf_putf(our_संस्करणम्, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_संस्करणम्,
	    संस्करणम्_addendum == रिक्त ? "" : " ",
	    संस्करणम्_addendum == रिक्त ? "" : संस्करणम्_addendum)) != 0) {
		oerrno = errno;
		error_fr(r, "sshbuf_putf");
		गच्छ बहिर्गमनम्;
	}

	यदि (atomicio(vwrite, ssh_packet_get_connection_बहिर्गमनम्(ssh),
	    sshbuf_mutable_ptr(our_संस्करणम्),
	    sshbuf_len(our_संस्करणम्)) != sshbuf_len(our_संस्करणम्)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_consume_अन्तः(our_संस्करणम्, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		गच्छ बहिर्गमनम्;
	}
	our_संस्करणम्_string = sshbuf_dup_string(our_संस्करणम्);
	यदि (our_संस्करणम्_string == रिक्त) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	debug("Local version string %.100s", our_संस्करणम्_string);

	/* Read other side's version identification. */
	प्रति (n = 0; ; n++) {
		यदि (n >= SSH_MAX_PRE_BANNER_पङ्क्तयः) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_पङ्क्तयः);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ बहिर्गमनम्;
		}
		sshbuf_reset(peer_संस्करणम्);
		expect_nl = 0;
		प्रति (;;) {
			यदि (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_अन्तर्(ssh),
				    &timeout_ms, रिक्त);
				यदि (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					गच्छ बहिर्गमनम्;
				} अन्यथा यदि (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					गच्छ बहिर्गमनम्;
				}
			}

			len = atomicio(पठ, ssh_packet_get_connection_अन्तर्(ssh),
			    &c, 1);
			यदि (len != 1 && errno == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				गच्छ बहिर्गमनम्;
			} अन्यथा यदि (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				गच्छ बहिर्गमनम्;
			}
			यदि (c == '\r') {
				expect_nl = 1;
				अनुवर्त;
			}
			यदि (c == '\n')
				भङ्ग;
			यदि (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				गच्छ invalid;
			}
			यदि ((r = sshbuf_put_u8(peer_संस्करणम्, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				गच्छ बहिर्गमनम्;
			}
			यदि (sshbuf_len(peer_संस्करणम्) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				गच्छ invalid;
			}
		}
		/* Is this an actual protocol banner? */
		यदि (sshbuf_len(peer_संस्करणम्) > 4 &&
		    memcmp(sshbuf_ptr(peer_संस्करणम्), "SSH-", 4) == 0)
			भङ्ग;
		/* If not, then just log the line and continue */
		यदि ((cp = sshbuf_dup_string(peer_संस्करणम्)) == रिक्त) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ बहिर्गमनम्;
		}
		/* Do not accept lines before the SSH ident from a client */
		यदि (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			मुक्त(cp);
			गच्छ invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		मुक्त(cp);
	}
	peer_संस्करणम्_string = sshbuf_dup_string(peer_संस्करणम्);
	यदि (peer_संस्करणम्_string == रिक्त)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	यदि ((remote_संस्करणम् = शून्यस्मृतिं_देहि(1, sshbuf_len(peer_संस्करणम्))) == रिक्त) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	यदि (वाक्यात्_पठ(peer_संस्करणम्_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_संस्करणम्) != 3) {
		error("Bad remote protocol version identification: '%.100s'",
		    peer_संस्करणम्_string);
 invalid:
		send_error(ssh, "Invalid SSH identification string.");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_संस्करणम्);
	compat_banner(ssh, remote_संस्करणम्);

	mismatch = 0;
	विकल्प (remote_major) {
	पक्ष 2:
		भङ्ग;
	पक्ष 1:
		यदि (remote_minor != 99)
			mismatch = 1;
		भङ्ग;
	स्वभाव:
		mismatch = 1;
		भङ्ग;
	}
	यदि (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_संस्करणम्;
		गच्छ बहिर्गमनम्;
	}

	यदि (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_पत्तनम्(ssh),
		    peer_संस्करणम्_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		गच्छ बहिर्गमनम्;
	}
	यदि (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
		logit("scanned from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_पत्तनम्(ssh),
		    peer_संस्करणम्_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		गच्छ बहिर्गमनम्;
	}
	/* success */
	r = 0;
 बहिर्गमनम्:
	मुक्त(our_संस्करणम्_string);
	मुक्त(peer_संस्करणम्_string);
	ssh->remote_संस्करणम् = remote_संस्करणम्;  /* transferred */
	यदि (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	प्रत्यागम r;
}

