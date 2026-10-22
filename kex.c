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

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/crypto.h>
#अन्तर्भाव <openssl/dh.h>
#endif

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
स्थिर पूर्णाङ्क kex_choose_conf(संरचना ssh *, uint32_t seq);
स्थिर पूर्णाङ्क kex_निवेश_newkeys(पूर्णाङ्क, uint32_t, संरचना ssh *);

स्थिर ध्रुव वर्ण * ध्रुव proposal_names[PROPOSAL_MAX] = {
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
	यदि ((cp = kex_names_cat(kexalgos, ssh->kex->server ?
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
		पक्ष PROPOSAL_SERVER_HOST_कुंजी_ALGS:
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
	यदि ((proposal = calloc(PROPOSAL_MAX, परिमाण(वर्ण *))) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((b = sshbuf_fromb(raw)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		गच्छ out;
	}
	/* extract kex init proposal strings */
	प्रति (i = 0; i < PROPOSAL_MAX; i++) {
		यदि ((r = sshbuf_get_cstring(b, &(proposal[i]), रिक्त)) != 0) {
			error_fr(r, "parse proposal %u", i);
			गच्छ out;
		}
		debug2("%s: %s", proposal_names[i], proposal[i]);
	}
	/* first kex follows / reserved */
	यदि ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		गच्छ out;
	}
	यदि (first_kex_follows != रिक्त)
		*first_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 out:
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
	यदि ((r = sshpkt_start(ssh, SSH2_संदेश_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		प्रत्यागम r;
	प्रत्यागम 0;
}

स्थिर शून्य
kex_reset_dispatch(संरचना ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_संदेश_TRANSPORT_MIN,
	    SSH2_संदेश_TRANSPORT_MAX, &kex_protocol_error);
}

शून्य
kex_set_server_sig_algs(संरचना ssh *ssh, ध्रुव वर्ण *allowed_algs)
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
kex_set_warn_weak_crypto(संरचना ssh *ssh, पूर्णाङ्क warn_weak_crypto)
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
		गच्छ out;
	}
	/* success */
	r = 0;
 out:
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
	यदि ((r = sshpkt_start(ssh, SSH2_संदेश_EXT_INFO)) != 0 ||
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

	यदि ((ssh->kex->flags & KEX_HAS_EXT_INFO_IN_AUTH) == 0)
		प्रत्यागम 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	यदि ((r = sshpkt_start(ssh, SSH2_संदेश_EXT_INFO)) != 0 ||
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
	यदि ((r = sshpkt_start(ssh, SSH2_संदेश_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		प्रत्यागम r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_set(ssh, SSH2_संदेश_NEWKEYS, &kex_निवेश_newkeys);
	यदि ((r = kex_maybe_send_ext_info(ssh)) != 0)
		प्रत्यागम r;
	debug("expecting SSH2_MSG_NEWKEYS");
	प्रत्यागम 0;
}

/* Check whether an ext_info value contains the expected version string */
स्थिर पूर्णाङ्क
kex_ext_info_check_ver(संरचना kex *kex, ध्रुव वर्ण *name,
    ध्रुव u_char *val, size_t len, ध्रुव वर्ण *want_ver, u_int flag)
{
	यदि (memchr(val, '\0', len) != रिक्त) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	यदि (strcmp(val, want_ver) == 0)
		kex->flags |= flag;
	अन्यथा
		debug_f("unsupported version of %s extension", name);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
kex_ext_info_client_parse(संरचना ssh *ssh, ध्रुव वर्ण *name,
    ध्रुव u_char *मूल्य, size_t vlen)
{
	पूर्णाङ्क r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	यदि (strcmp(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		यदि (memchr(मूल्य, '\0', vlen) != रिक्त) {
			error_f("nul byte in %s", name);
			प्रत्यागम SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, मूल्य);
		मुक्त(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((ध्रुव वर्ण *)मूल्य);
	} अन्यथा यदि (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "publickey-hostbound@openssh.com") == 0) {
		यदि ((r = kex_ext_info_check_ver(ssh->kex, name, मूल्य, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			प्रत्यागम r;
		}
	} अन्यथा यदि (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "ping@openssh.com") == 0) {
		यदि ((r = kex_ext_info_check_ver(ssh->kex, name, मूल्य, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			प्रत्यागम r;
		}
	} अन्यथा यदि (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "agent-forward") == 0) {
		यदि ((r = kex_ext_info_check_ver(ssh->kex, name, मूल्य, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			प्रत्यागम r;
		}
	} अन्यथा
		debug_f("%s (unrecognised)", name);

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
kex_ext_info_server_parse(संरचना ssh *ssh, ध्रुव वर्ण *name,
    ध्रुव u_char *मूल्य, size_t vlen)
{
	पूर्णाङ्क r;

	यदि (strcmp(name, "ext-info-in-auth@openssh.com") == 0) {
		यदि ((r = kex_ext_info_check_ver(ssh->kex, name, मूल्य, vlen,
		    "0", KEX_HAS_EXT_INFO_IN_AUTH)) != 0) {
			प्रत्यागम r;
		}
	} अन्यथा
		debug_f("%s (unrecognised)", name);
	प्रत्यागम 0;
}

पूर्णाङ्क
kex_निवेश_ext_info(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	ध्रुव पूर्णाङ्क max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	वर्ण *name;
	u_char *val;
	size_t vlen;
	पूर्णाङ्क r;

	debug("SSH2_MSG_EXT_INFO received");
	यदि (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		प्रत्यागम dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_set(ssh, SSH2_संदेश_EXT_INFO, &kex_protocol_error);
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
	प्रत्यागम sshpkt_get_end(ssh);
}

स्थिर पूर्णाङ्क
kex_निवेश_newkeys(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	पूर्णाङ्क r, initial = (kex->flags & KEX_INITIAL) != 0;
	वर्ण *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	यदि (kex->ext_info_c && initial)
		ssh_dispatch_set(ssh, SSH2_संदेश_EXT_INFO, &kex_निवेश_ext_info);
	ssh_dispatch_set(ssh, SSH2_संदेश_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_set(ssh, SSH2_संदेश_KEXINIT, &kex_निवेश_kexinit);
	यदि ((r = sshpkt_get_end(ssh)) != 0)
		प्रत्यागम r;
	यदि ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0)
		प्रत्यागम r;
	यदि (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		यदि ((r = kex_buf2prop(kex->my, रिक्त, &prop)) != 0)
			प्रत्यागम r;
		यदि ((cp = match_filter_denylist(prop[PROPOSAL_KEX_ALGS],
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
			प्रत्यागम SSH_ERR_INTERNAL_ERROR;
		}
		kex_proposal_free_entries(prop);
		मुक्त(prop);
	}
	kex->done = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_SENT|KEX_INIT_RECVD);
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
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	}
	यदि (kex->flags & KEX_INIT_SENT)
		प्रत्यागम 0;
	kex->done = 0;

	/* generate a random cookie */
	यदि (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	}
	यदि ((cookie = sshbuf_mutable_ptr(kex->my)) == रिक्त) {
		error_f("buffer error");
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	यदि ((r = sshpkt_start(ssh, SSH2_संदेश_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		प्रत्यागम r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_SENT;
	प्रत्यागम 0;
}

पूर्णाङ्क
kex_निवेश_kexinit(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	ध्रुव u_char *ptr;
	u_int i;
	size_t dlen;
	पूर्णाङ्क r;

	debug("SSH2_MSG_KEXINIT received");
	यदि (kex == रिक्त) {
		error_f("no kex");
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	}
	मुक्त(kex->name);
	kex->name = रिक्त;
	यदि ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_set(ssh, SSH2_संदेश_KEXINIT, &kex_protocol_error);
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
	    (r = sshpkt_get_end(ssh)) != 0)
			प्रत्यागम r;

	यदि (!(kex->flags & KEX_INIT_SENT))
		यदि ((r = kex_send_kexinit(ssh)) != 0)
			प्रत्यागम r;
	यदि ((r = kex_choose_conf(ssh, seq)) != 0)
		प्रत्यागम r;

	यदि (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != रिक्त)
		प्रत्यागम (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	प्रत्यागम SSH_ERR_INTERNAL_ERROR;
}

संरचना kex *
kex_new(शून्य)
{
	संरचना kex *kex;

	यदि ((kex = calloc(1, परिमाण(*kex))) == रिक्त ||
	    (kex->peer = sshbuf_new()) == रिक्त ||
	    (kex->my = sshbuf_new()) == रिक्त ||
	    (kex->client_version = sshbuf_new()) == रिक्त ||
	    (kex->server_version = sshbuf_new()) == रिक्त ||
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
	यदि (newkeys->enc.कुंजी) {
		explicit_bzero(newkeys->enc.कुंजी, newkeys->enc.कुंजी_len);
		मुक्त(newkeys->enc.कुंजी);
		newkeys->enc.कुंजी = रिक्त;
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
	यदि (newkeys->mac.कुंजी) {
		explicit_bzero(newkeys->mac.कुंजी, newkeys->mac.कुंजी_len);
		मुक्त(newkeys->mac.कुंजी);
		newkeys->mac.कुंजी = रिक्त;
	}
	मुक्त(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, परिमाण(newkeys->mac));
	freezero(newkeys, परिमाण(*newkeys));
}

शून्य
kex_free(संरचना kex *kex)
{
	u_int mode;

	यदि (kex == रिक्त)
		प्रत्यागम;

#ifdef WITH_OPENSSL
	DH_free(kex->dh);
	EC_कुंजी_free(kex->ec_client_कुंजी);
#endif /* WITH_OPENSSL */
	प्रति (mode = 0; mode < MODE_MAX; mode++) {
		kex_free_newkeys(kex->newkeys[mode]);
		kex->newkeys[mode] = रिक्त;
	}
	sshbuf_free(kex->peer);
	sshbuf_free(kex->my);
	sshbuf_free(kex->client_version);
	sshbuf_free(kex->server_version);
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
	ssh_dispatch_set(ssh, SSH2_संदेश_KEXINIT, &kex_निवेश_kexinit);
	प्रत्यागम 0;
}

पूर्णाङ्क
kex_setup(संरचना ssh *ssh, वर्ण *proposal[PROPOSAL_MAX])
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
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	}
	यदि (ssh->kex->done == 0) {
		error_f("requested twice");
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	}
	ssh->kex->done = 0;
	प्रत्यागम kex_send_kexinit(ssh);
}

स्थिर पूर्णाङ्क
choose_enc(संरचना sshenc *enc, वर्ण *client, वर्ण *server)
{
	वर्ण *name = match_list(client, server, रिक्त);

	यदि (name == रिक्त)
		प्रत्यागम SSH_ERR_NO_CIPHER_ALG_MATCH;
	यदि ((enc->cipher = cipher_by_name(name)) == रिक्त) {
		error_f("unsupported cipher %s", name);
		मुक्त(name);
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = रिक्त;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->कुंजी = रिक्त;
	enc->कुंजी_len = cipher_keylen(enc->cipher);
	enc->block_size = cipher_blocksize(enc->cipher);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
choose_mac(संरचना ssh *ssh, संरचना sshmac *mac, वर्ण *client, वर्ण *server)
{
	वर्ण *name = match_list(client, server, रिक्त);

	यदि (name == रिक्त)
		प्रत्यागम SSH_ERR_NO_MAC_ALG_MATCH;
	यदि (mac_setup(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		मुक्त(name);
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	}
	mac->name = name;
	mac->कुंजी = रिक्त;
	mac->enabled = 0;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
choose_comp(संरचना sshcomp *comp, वर्ण *client, वर्ण *server)
{
	वर्ण *name = match_list(client, server, रिक्त);

	यदि (name == रिक्त)
		प्रत्यागम SSH_ERR_NO_COMPRESS_ALG_MATCH;
#ifdef WITH_ZLIB
	यदि (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} अन्यथा
#endif	/* WITH_ZLIB */
	यदि (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} अन्यथा {
		error_f("unsupported compression scheme %s", name);
		मुक्त(name);
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	}
	comp->name = name;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
choose_kex(संरचना kex *k, वर्ण *client, वर्ण *server)
{
	k->name = match_list(client, server, रिक्त);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	यदि (k->name == रिक्त)
		प्रत्यागम SSH_ERR_NO_KEX_ALG_MATCH;
	यदि (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
choose_hostkeyalg(संरचना kex *k, वर्ण *client, वर्ण *server)
{
	मुक्त(k->hostkey_alg);
	k->hostkey_alg = match_list(client, server, रिक्त);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	यदि (k->hostkey_alg == रिक्त)
		प्रत्यागम SSH_ERR_NO_HOSTKEY_ALG_MATCH;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	यदि (k->hostkey_type == कुंजी_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
proposals_match(वर्ण *my[PROPOSAL_MAX], वर्ण *peer[PROPOSAL_MAX])
{
	स्थिर पूर्णाङ्क check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_कुंजी_ALGS, -1
	};
	पूर्णाङ्क *idx;
	वर्ण *p;

	प्रति (idx = &check[0]; *idx != -1; idx++) {
		यदि ((p = strchr(my[*idx], ',')) != रिक्त)
			*p = '\0';
		यदि ((p = strchr(peer[*idx], ',')) != रिक्त)
			*p = '\0';
		यदि (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			प्रत्यागम (0);
		}
	}
	debug2("proposals match");
	प्रत्यागम (1);
}

स्थिर पूर्णाङ्क
kexalgs_contains(वर्ण **peer, ध्रुव वर्ण *ext)
{
	प्रत्यागम kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

स्थिर पूर्णाङ्क
kex_choose_conf(संरचना ssh *ssh, uint32_t seq)
{
	संरचना kex *kex = ssh->kex;
	संरचना newkeys *newkeys;
	वर्ण **my = रिक्त, **peer = रिक्त;
	वर्ण **cprop, **sprop;
	पूर्णाङ्क nenc, nmac, ncomp;
	u_int mode, ctos, need, dh_need, authlen;
	पूर्णाङ्क r, first_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	यदि ((r = kex_buf2prop(kex->my, रिक्त, &my)) != 0)
		गच्छ out;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	यदि ((r = kex_buf2prop(kex->peer, &first_kex_follows, &peer)) != 0)
		गच्छ out;

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
			kex->ext_info_c = kexalgs_contains(peer, "ext-info-c");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-c-v00@openssh.com");
		} अन्यथा {
			kex->ext_info_s = kexalgs_contains(peer, "ext-info-s");
			kex->kex_strict = kexalgs_contains(peer,
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
		यदि (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_कुंजी_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		यदि (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_कुंजी_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	यदि ((r = choose_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = रिक्त;
		गच्छ out;
	}
	यदि ((r = choose_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_कुंजी_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_कुंजी_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_कुंजी_ALGS];
		peer[PROPOSAL_SERVER_HOST_कुंजी_ALGS] = रिक्त;
		गच्छ out;
	}
	प्रति (mode = 0; mode < MODE_MAX; mode++) {
		यदि ((newkeys = calloc(1, परिमाण(*newkeys))) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		kex->newkeys[mode] = newkeys;
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		यदि ((r = choose_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = रिक्त;
			गच्छ out;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		यदि (authlen == 0 &&
		    (r = choose_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = रिक्त;
			गच्छ out;
		}
		यदि ((r = choose_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0) {
			kex->failed_choice = peer[ncomp];
			peer[ncomp] = रिक्त;
			गच्छ out;
		}
		debug("kex: %s cipher: %s MAC: %s compression: %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    authlen == 0 ? newkeys->mac.name : "<implicit>",
		    newkeys->comp.name);
	}
	need = dh_need = 0;
	प्रति (mode = 0; mode < MODE_MAX; mode++) {
		newkeys = kex->newkeys[mode];
		need = MAXIMUM(need, newkeys->enc.कुंजी_len);
		need = MAXIMUM(need, newkeys->enc.block_size);
		need = MAXIMUM(need, newkeys->enc.iv_len);
		need = MAXIMUM(need, newkeys->mac.कुंजी_len);
		dh_need = MAXIMUM(dh_need, cipher_seclen(newkeys->enc.cipher));
		dh_need = MAXIMUM(dh_need, newkeys->enc.block_size);
		dh_need = MAXIMUM(dh_need, newkeys->enc.iv_len);
		dh_need = MAXIMUM(dh_need, newkeys->mac.कुंजी_len);
	}
	/* XXX need runden? */
	kex->we_need = need;
	kex->dh_need = dh_need;

	/* ignore the next message if the proposals do not match */
	यदि (first_kex_follows && !proposals_match(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 out:
	kex_prop_free(my);
	kex_prop_free(peer);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
derive_कुंजी(संरचना ssh *ssh, पूर्णाङ्क id, u_int need, u_char *hash, u_int hashlen,
    ध्रुव संरचना sshbuf *shared_secret, u_char **keyp)
{
	संरचना kex *kex = ssh->kex;
	संरचना ssh_digest_ctx *hashctx = रिक्त;
	वर्ण c = id;
	u_int have;
	size_t mdsz;
	u_char *digest;
	पूर्णाङ्क r;

	यदि ((mdsz = ssh_digest_bytes(kex->hash_alg)) == 0)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	यदि ((digest = calloc(1, ROUNDUP(need, mdsz))) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	यदि ((hashctx = ssh_digest_start(kex->hash_alg)) == रिक्त ||
	    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
	    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
	    ssh_digest_update(hashctx, &c, 1) != 0 ||
	    ssh_digest_update_buffer(hashctx, kex->session_id) != 0 ||
	    ssh_digest_final(hashctx, digest, mdsz) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		error_f("KEX hash failed");
		गच्छ out;
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
		    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
		    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
		    ssh_digest_update(hashctx, digest, have) != 0 ||
		    ssh_digest_final(hashctx, digest + have, mdsz) != 0) {
			error_f("KDF failed");
			r = SSH_ERR_LIBCRYPTO_ERROR;
			गच्छ out;
		}
		ssh_digest_free(hashctx);
		hashctx = रिक्त;
	}
#ifdef DEBUG_KEX
	fprintf(stderr, "key '%c'== ", c);
	dump_digest("key", digest, need);
#endif
	*keyp = digest;
	digest = रिक्त;
	r = 0;
 out:
	मुक्त(digest);
	ssh_digest_free(hashctx);
	प्रत्यागम r;
}

#define NKEYS	6
पूर्णाङ्क
kex_derive_कुंजियाँ(संरचना ssh *ssh, u_char *hash, u_int hashlen,
    ध्रुव संरचना sshbuf *shared_secret)
{
	संरचना kex *kex = ssh->kex;
	u_char *कुंजियाँ[NKEYS];
	u_int i, j, mode, ctos;
	पूर्णाङ्क r;

	/* save initial hash as session id */
	यदि ((kex->flags & KEX_INITIAL) != 0) {
		यदि (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			प्रत्यागम SSH_ERR_INTERNAL_ERROR;
		}
		यदि ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			प्रत्यागम r;
	} अन्यथा यदि (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	}
	प्रति (i = 0; i < NKEYS; i++) {
		यदि ((r = derive_कुंजी(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &कुंजियाँ[i])) != 0) {
			प्रति (j = 0; j < i; j++)
				मुक्त(कुंजियाँ[j]);
			प्रत्यागम r;
		}
	}
	प्रति (mode = 0; mode < MODE_MAX; mode++) {
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		kex->newkeys[mode]->enc.iv  = कुंजियाँ[ctos ? 0 : 1];
		kex->newkeys[mode]->enc.कुंजी = कुंजियाँ[ctos ? 2 : 3];
		kex->newkeys[mode]->mac.कुंजी = कुंजियाँ[ctos ? 4 : 5];
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
kex_load_hostkey(संरचना ssh *ssh, संरचना sshkey **prvp, संरचना sshkey **pubp)
{
	संरचना kex *kex = ssh->kex;

	*pubp = रिक्त;
	*prvp = रिक्त;
	यदि (kex->load_host_public_कुंजी == रिक्त ||
	    kex->load_host_private_कुंजी == रिक्त) {
		error_f("missing hostkey loader");
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	}
	*pubp = kex->load_host_public_कुंजी(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->load_host_private_कुंजी(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	यदि (*pubp == रिक्त)
		प्रत्यागम SSH_ERR_NO_HOSTKEY_LOADED;
	प्रत्यागम 0;
}

पूर्णाङ्क
kex_verify_host_कुंजी(संरचना ssh *ssh, संरचना sshkey *server_host_कुंजी)
{
	संरचना kex *kex = ssh->kex;

	यदि (kex->verify_host_कुंजी == रिक्त) {
		error_f("missing hostkey verifier");
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	}
	यदि (server_host_कुंजी->type != kex->hostkey_type ||
	    (kex->hostkey_type == कुंजी_ECDSA &&
	    server_host_कुंजी->ecdsa_nid != kex->hostkey_nid))
		प्रत्यागम SSH_ERR_कुंजी_TYPE_MISMATCH;
	यदि (kex->verify_host_कुंजी(server_host_कुंजी, ssh) == -1)
		प्रत्यागम  SSH_ERR_SIGNATURE_INVALID;
	प्रत्यागम 0;
}

#यदि defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
शून्य
dump_digest(ध्रुव वर्ण *संदेश, ध्रुव u_char *digest, पूर्णाङ्क len)
{
	fprintf(stderr, "%s\n", संदेश);
	sshbuf_dump_data(digest, len, stderr);
}
#endif

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
स्थिर शून्य
send_error(संरचना ssh *ssh, वर्ण *संदेश)
{
	वर्ण *crnl = "\r\n";

	यदि (!ssh->kex->server)
		प्रत्यागम;

	यदि (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    संदेश, strlen(संदेश)) != strlen(संदेश) ||
	    atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    crnl, strlen(crnl)) != strlen(crnl))
		error_f("write: %.100s", strerror(errno));
}

/*
 * Sends our identification string and waits for the peer's. Will block for
 * up to timeout_ms (or indefinitely if timeout_ms <= 0).
 * Returns on 0 success or a ssherr.h code on failure.
 */
पूर्णाङ्क
kex_exchange_identification(संरचना ssh *ssh, पूर्णाङ्क timeout_ms,
    ध्रुव वर्ण *version_addendum)
{
	पूर्णाङ्क remote_major, remote_minor, mismatch, oerrno = 0;
	size_t len, n;
	पूर्णाङ्क r, expect_nl;
	u_char c;
	संरचना sshbuf *our_version = ssh->kex->server ?
	    ssh->kex->server_version : ssh->kex->client_version;
	संरचना sshbuf *peer_version = ssh->kex->server ?
	    ssh->kex->client_version : ssh->kex->server_version;
	वर्ण *our_version_string = रिक्त, *peer_version_string = रिक्त;
	वर्ण *cp, *remote_version = रिक्त;

	/* Prepare and send our banner */
	sshbuf_reset(our_version);
	यदि (version_addendum != रिक्त && *version_addendum == '\0')
		version_addendum = रिक्त;
	यदि ((r = sshbuf_putf(our_version, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_VERSION,
	    version_addendum == रिक्त ? "" : " ",
	    version_addendum == रिक्त ? "" : version_addendum)) != 0) {
		oerrno = errno;
		error_fr(r, "sshbuf_putf");
		गच्छ out;
	}

	यदि (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    sshbuf_mutable_ptr(our_version),
	    sshbuf_len(our_version)) != sshbuf_len(our_version)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		गच्छ out;
	}
	यदि ((r = sshbuf_consume_end(our_version, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		गच्छ out;
	}
	our_version_string = sshbuf_dup_string(our_version);
	यदि (our_version_string == रिक्त) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	debug("Local version string %.100s", our_version_string);

	/* Read other side's version identification. */
	प्रति (n = 0; ; n++) {
		यदि (n >= SSH_MAX_PRE_BANNER_पंक्तियाँ) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_पंक्तियाँ);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
		sshbuf_reset(peer_version);
		expect_nl = 0;
		प्रति (;;) {
			यदि (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_in(ssh),
				    &timeout_ms, रिक्त);
				यदि (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					गच्छ out;
				} अन्यथा यदि (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					गच्छ out;
				}
			}

			len = atomicio(पठ, ssh_packet_get_connection_in(ssh),
			    &c, 1);
			यदि (len != 1 && errno == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				गच्छ out;
			} अन्यथा यदि (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				गच्छ out;
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
			यदि ((r = sshbuf_put_u8(peer_version, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				गच्छ out;
			}
			यदि (sshbuf_len(peer_version) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				गच्छ invalid;
			}
		}
		/* Is this an actual protocol banner? */
		यदि (sshbuf_len(peer_version) > 4 &&
		    memcmp(sshbuf_ptr(peer_version), "SSH-", 4) == 0)
			भङ्ग;
		/* If not, then just log the line and continue */
		यदि ((cp = sshbuf_dup_string(peer_version)) == रिक्त) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
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
	peer_version_string = sshbuf_dup_string(peer_version);
	यदि (peer_version_string == रिक्त)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	यदि ((remote_version = calloc(1, sshbuf_len(peer_version))) == रिक्त) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	यदि (sscanf(peer_version_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		error("Bad remote protocol version identification: '%.100s'",
		    peer_version_string);
 invalid:
		send_error(ssh, "Invalid SSH identification string.");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);
	compat_banner(ssh, remote_version);

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
		r = SSH_ERR_NO_PROTOCOL_VERSION;
		गच्छ out;
	}

	यदि (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		गच्छ out;
	}
	यदि (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
		logit("scanned from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		गच्छ out;
	}
	/* success */
	r = 0;
 out:
	मुक्त(our_version_string);
	मुक्त(peer_version_string);
	ssh->remote_version = remote_version;  /* transferred */
	यदि (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	प्रत्यागम r;
}

