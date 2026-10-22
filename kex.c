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
स्थिर पूर्णाङ्क kex_निवेशः_newkeys(पूर्णाङ्क, uint32_t, संरचना ssh *);

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

	सचे (prop == रिक्त)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	सचे (kexalgos == रिक्त)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	सचे ((cp = kex_names_cat(kexalgos, ssh->kex->server ?
	    "ext-info-s,kex-strict-s-v00@openssh.com" :
	    "ext-info-c,kex-strict-c-v00@openssh.com")) == रिक्त)
		fatal_f("kex_names_cat");

	अत्थाय (i = 0; i < PROPOSAL_MAX; i++) {
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

	अत्थाय (i = 0; i < PROPOSAL_MAX; i++)
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
	अत्थाय (i = 0; i < KEX_COOKIE_LEN; i++) {
		सचे ((r = sshbuf_put_u8(b, 0)) != 0)
			पटिनिवत्त r;
	}
	अत्थाय (i = 0; i < PROPOSAL_MAX; i++) {
		सचे ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			पटिनिवत्त r;
	}
	सचे ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		पटिनिवत्त r;
	पटिनिवत्त 0;
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
	सचे ((proposal = calloc(PROPOSAL_MAX, परिमाण(वर्ण *))) == रिक्त)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	सचे ((b = sshbuf_fromb(raw)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		गच्छ out;
	}
	/* extract kex init proposal strings */
	अत्थाय (i = 0; i < PROPOSAL_MAX; i++) {
		सचे ((r = sshbuf_get_cstring(b, &(proposal[i]), रिक्त)) != 0) {
			error_fr(r, "parse proposal %u", i);
			गच्छ out;
		}
		debug2("%s: %s", proposal_names[i], proposal[i]);
	}
	/* first kex follows / reserved */
	सचे ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		गच्छ out;
	}
	सचे (first_kex_follows != रिक्त)
		*first_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 out:
	सचे (r != 0 && proposal != रिक्त)
		kex_prop_free(proposal);
	sshbuf_free(b);
	पटिनिवत्त r;
}

शून्य
kex_prop_free(वर्ण **proposal)
{
	u_int i;

	सचे (proposal == रिक्त)
		पटिनिवत्त;
	अत्थाय (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(proposal[i]);
	मुक्त(proposal);
}

पूर्णाङ्क
kex_protocol_error(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	पूर्णाङ्क r;

	/* If in strict mode, any unexpected message is an error */
	सचे ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	सचे ((r = sshpkt_start(ssh, SSH2_सन्देशः_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		पटिनिवत्त r;
	पटिनिवत्त 0;
}

स्थिर शून्य
kex_reset_dispatch(संरचना ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_सन्देशः_TRANSPORT_MIN,
	    SSH2_सन्देशः_TRANSPORT_MAX, &kex_protocol_error);
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
	सचे ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == रिक्त)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	मुक्त(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = रिक्त;
	अत्थाय ((alg = strsep(&algs, ",")); alg != रिक्त && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		सचे ((sigalg = sshkey_sigalg_by_name(alg)) == रिक्त)
			अनुवर्त;
		सचे (!kex_has_any_alg(sigalg, sigalgs))
			अनुवर्त;
		/* Don't add an algorithm twice. */
		सचे (ssh->kex->server_sig_algs != रिक्त &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			अनुवर्त;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	मुक्त(oalgs);
	मुक्त(sigalgs);
	सचे (ssh->kex->server_sig_algs == रिक्त)
		ssh->kex->server_sig_algs = xstrdup("");
}

शून्य
kex_set_warn_weak_crypto(संरचना ssh *ssh, पूर्णाङ्क warn_weak_crypto)
{
	सचे (ssh != रिक्त && ssh->kex != रिक्त)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

शून्य
kex_check_warn_weak_crypto(संरचना ssh *ssh)
{
	वर्ण remote_id[512];
	पूर्णाङ्क rekeyed = 0;

	सचे (ssh == रिक्त || ssh->kex == रिक्त || ssh->kex->name == रिक्त ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		पटिनिवत्त;
	सचे (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		पटिनिवत्त;
	}

	सचे (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	सचे (!rekeyed && !ssh->kex->server)
		पटिनिवत्त; /* client logs initial KEX warning separately */

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

	सचे (ssh->kex->server_sig_algs == रिक्त &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == रिक्त)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	सचे ((r = sshbuf_put_u32(m, 4)) != 0 ||
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
		पटिनिवत्त r;
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
kex_compose_ext_info_client(संरचना ssh *ssh, संरचना sshbuf *m)
{
	पूर्णाङ्क r;

	सचे ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		गच्छ out;
	}
	/* success */
	r = 0;
 out:
	पटिनिवत्त r;
}

स्थिर पूर्णाङ्क
kex_maybe_send_ext_info(संरचना ssh *ssh)
{
	पूर्णाङ्क r;
	संरचना sshbuf *m = रिक्त;

	सचे ((ssh->kex->flags & KEX_INITIAL) == 0)
		पटिनिवत्त 0;
	सचे (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		पटिनिवत्त 0;

	/* Compose EXT_INFO packet. */
	सचे ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	सचे (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		गच्छ fail;
	सचे (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		गच्छ fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	सचे ((r = sshpkt_start(ssh, SSH2_सन्देशः_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		गच्छ fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	पटिनिवत्त r;
}

पूर्णाङ्क
kex_server_update_ext_info(संरचना ssh *ssh)
{
	पूर्णाङ्क r;

	सचे ((ssh->kex->flags & KEX_HAS_EXT_INFO_IN_AUTH) == 0)
		पटिनिवत्त 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	सचे ((r = sshpkt_start(ssh, SSH2_सन्देशः_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		पटिनिवत्त r;
	}
	पटिनिवत्त 0;
}

पूर्णाङ्क
kex_send_newkeys(संरचना ssh *ssh)
{
	पूर्णाङ्क r;

	kex_reset_dispatch(ssh);
	सचे ((r = sshpkt_start(ssh, SSH2_सन्देशः_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		पटिनिवत्त r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_set(ssh, SSH2_सन्देशः_NEWKEYS, &kex_निवेशः_newkeys);
	सचे ((r = kex_maybe_send_ext_info(ssh)) != 0)
		पटिनिवत्त r;
	debug("expecting SSH2_MSG_NEWKEYS");
	पटिनिवत्त 0;
}

/* Check whether an ext_info value contains the expected version string */
स्थिर पूर्णाङ्क
kex_ext_info_check_ver(संरचना kex *kex, ध्रुव वर्ण *name,
    ध्रुव u_char *val, size_t len, ध्रुव वर्ण *want_ver, u_int flag)
{
	सचे (memchr(val, '\0', len) != रिक्त) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	सचे (strcmp(val, want_ver) == 0)
		kex->flags |= flag;
	अञ्ञथा
		debug_f("unsupported version of %s extension", name);
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
kex_ext_info_client_parse(संरचना ssh *ssh, ध्रुव वर्ण *name,
    ध्रुव u_char *मानम्, size_t vlen)
{
	पूर्णाङ्क r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	सचे (strcmp(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		सचे (memchr(मानम्, '\0', vlen) != रिक्त) {
			error_f("nul byte in %s", name);
			पटिनिवत्त SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, मानम्);
		मुक्त(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((ध्रुव वर्ण *)मानम्);
	} अञ्ञथा सचे (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "publickey-hostbound@openssh.com") == 0) {
		सचे ((r = kex_ext_info_check_ver(ssh->kex, name, मानम्, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			पटिनिवत्त r;
		}
	} अञ्ञथा सचे (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "ping@openssh.com") == 0) {
		सचे ((r = kex_ext_info_check_ver(ssh->kex, name, मानम्, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			पटिनिवत्त r;
		}
	} अञ्ञथा सचे (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "agent-forward") == 0) {
		सचे ((r = kex_ext_info_check_ver(ssh->kex, name, मानम्, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			पटिनिवत्त r;
		}
	} अञ्ञथा
		debug_f("%s (unrecognised)", name);

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
kex_ext_info_server_parse(संरचना ssh *ssh, ध्रुव वर्ण *name,
    ध्रुव u_char *मानम्, size_t vlen)
{
	पूर्णाङ्क r;

	सचे (strcmp(name, "ext-info-in-auth@openssh.com") == 0) {
		सचे ((r = kex_ext_info_check_ver(ssh->kex, name, मानम्, vlen,
		    "0", KEX_HAS_EXT_INFO_IN_AUTH)) != 0) {
			पटिनिवत्त r;
		}
	} अञ्ञथा
		debug_f("%s (unrecognised)", name);
	पटिनिवत्त 0;
}

पूर्णाङ्क
kex_निवेशः_ext_info(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	ध्रुव पूर्णाङ्क max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	वर्ण *name;
	u_char *val;
	size_t vlen;
	पूर्णाङ्क r;

	debug("SSH2_MSG_EXT_INFO received");
	सचे (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		पटिनिवत्त dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_set(ssh, SSH2_सन्देशः_EXT_INFO, &kex_protocol_error);
	सचे ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		पटिनिवत्त r;
	सचे (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		पटिनिवत्त dispatch_protocol_error(type, seq, ssh);
	}
	अत्थाय (i = 0; i < ninfo; i++) {
		सचे ((r = sshpkt_get_cstring(ssh, &name, रिक्त)) != 0)
			पटिनिवत्त r;
		सचे ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			मुक्त(name);
			पटिनिवत्त r;
		}
		debug3_f("extension %s", name);
		सचे (kex->server) {
			सचे ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				पटिनिवत्त r;
		} अञ्ञथा {
			सचे ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				पटिनिवत्त r;
		}
		मुक्त(name);
		मुक्त(val);
	}
	पटिनिवत्त sshpkt_get_end(ssh);
}

स्थिर पूर्णाङ्क
kex_निवेशः_newkeys(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	पूर्णाङ्क r, initial = (kex->flags & KEX_INITIAL) != 0;
	वर्ण *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	सचे (kex->ext_info_c && initial)
		ssh_dispatch_set(ssh, SSH2_सन्देशः_EXT_INFO, &kex_निवेशः_ext_info);
	ssh_dispatch_set(ssh, SSH2_सन्देशः_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_set(ssh, SSH2_सन्देशः_KEXINIT, &kex_निवेशः_kexinit);
	सचे ((r = sshpkt_get_end(ssh)) != 0)
		पटिनिवत्त r;
	सचे ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0)
		पटिनिवत्त r;
	सचे (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		सचे ((r = kex_buf2prop(kex->my, रिक्त, &prop)) != 0)
			पटिनिवत्त r;
		सचे ((cp = match_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == रिक्त) {
			error_f("match_filter_denylist failed");
			गच्छ fail;
		}
		मुक्त(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		सचे ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			मुक्त(prop);
			पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
		}
		kex_proposal_free_entries(prop);
		मुक्त(prop);
	}
	kex->done = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_SENT|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	पटिनिवत्त 0;
}

पूर्णाङ्क
kex_send_kexinit(संरचना ssh *ssh)
{
	u_char *cookie;
	संरचना kex *kex = ssh->kex;
	पूर्णाङ्क r;

	सचे (kex == रिक्त) {
		error_f("no kex");
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
	}
	सचे (kex->flags & KEX_INIT_SENT)
		पटिनिवत्त 0;
	kex->done = 0;

	/* generate a random cookie */
	सचे (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	}
	सचे ((cookie = sshbuf_mutable_ptr(kex->my)) == रिक्त) {
		error_f("buffer error");
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	सचे ((r = sshpkt_start(ssh, SSH2_सन्देशः_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		पटिनिवत्त r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_SENT;
	पटिनिवत्त 0;
}

पूर्णाङ्क
kex_निवेशः_kexinit(पूर्णाङ्क type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	ध्रुव u_char *ptr;
	u_int i;
	size_t dlen;
	पूर्णाङ्क r;

	debug("SSH2_MSG_KEXINIT received");
	सचे (kex == रिक्त) {
		error_f("no kex");
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
	}
	मुक्त(kex->name);
	kex->name = रिक्त;
	सचे ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_set(ssh, SSH2_सन्देशः_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	सचे ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		पटिनिवत्त r;

	/* discard packet */
	अत्थाय (i = 0; i < KEX_COOKIE_LEN; i++) {
		सचे ((r = sshpkt_get_u8(ssh, रिक्त)) != 0) {
			error_fr(r, "discard cookie");
			पटिनिवत्त r;
		}
	}
	अत्थाय (i = 0; i < PROPOSAL_MAX; i++) {
		सचे ((r = sshpkt_get_string(ssh, रिक्त, रिक्त)) != 0) {
			error_fr(r, "discard proposal");
			पटिनिवत्त r;
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
	सचे ((r = sshpkt_get_u8(ssh, रिक्त)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, रिक्त)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
			पटिनिवत्त r;

	सचे (!(kex->flags & KEX_INIT_SENT))
		सचे ((r = kex_send_kexinit(ssh)) != 0)
			पटिनिवत्त r;
	सचे ((r = kex_choose_conf(ssh, seq)) != 0)
		पटिनिवत्त r;

	सचे (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != रिक्त)
		पटिनिवत्त (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
}

संरचना kex *
kex_new(शून्य)
{
	संरचना kex *kex;

	सचे ((kex = calloc(1, परिमाण(*kex))) == रिक्त ||
	    (kex->peer = sshbuf_new()) == रिक्त ||
	    (kex->my = sshbuf_new()) == रिक्त ||
	    (kex->client_version = sshbuf_new()) == रिक्त ||
	    (kex->server_version = sshbuf_new()) == रिक्त ||
	    (kex->session_id = sshbuf_new()) == रिक्त) {
		kex_free(kex);
		पटिनिवत्त रिक्त;
	}
	पटिनिवत्त kex;
}

शून्य
kex_free_newkeys(संरचना newkeys *newkeys)
{
	सचे (newkeys == रिक्त)
		पटिनिवत्त;
	सचे (newkeys->enc.कुञ्चिका) {
		explicit_bzero(newkeys->enc.कुञ्चिका, newkeys->enc.कुञ्चिका_len);
		मुक्त(newkeys->enc.कुञ्चिका);
		newkeys->enc.कुञ्चिका = रिक्त;
	}
	सचे (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		मुक्त(newkeys->enc.iv);
		newkeys->enc.iv = रिक्त;
	}
	मुक्त(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, परिमाण(newkeys->enc));
	मुक्त(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, परिमाण(newkeys->comp));
	mac_clear(&newkeys->mac);
	सचे (newkeys->mac.कुञ्चिका) {
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
	u_int mode;

	सचे (kex == रिक्त)
		पटिनिवत्त;

#ifdef WITH_OPENSSL
	DH_free(kex->dh);
	EC_कुञ्चिका_free(kex->ec_client_कुञ्चिका);
#endif /* WITH_OPENSSL */
	अत्थाय (mode = 0; mode < MODE_MAX; mode++) {
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

	सचे ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		पटिनिवत्त r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_set(ssh, SSH2_सन्देशः_KEXINIT, &kex_निवेशः_kexinit);
	पटिनिवत्त 0;
}

पूर्णाङ्क
kex_setup(संरचना ssh *ssh, वर्ण *proposal[PROPOSAL_MAX])
{
	पूर्णाङ्क r;

	सचे ((r = kex_ready(ssh, proposal)) != 0)
		पटिनिवत्त r;
	सचे ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = रिक्त;
		पटिनिवत्त r;
	}
	पटिनिवत्त 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
पूर्णाङ्क
kex_start_rekex(संरचना ssh *ssh)
{
	सचे (ssh->kex == रिक्त) {
		error_f("no kex");
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
	}
	सचे (ssh->kex->done == 0) {
		error_f("requested twice");
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
	}
	ssh->kex->done = 0;
	पटिनिवत्त kex_send_kexinit(ssh);
}

स्थिर पूर्णाङ्क
choose_enc(संरचना sshenc *enc, वर्ण *client, वर्ण *server)
{
	वर्ण *name = match_list(client, server, रिक्त);

	सचे (name == रिक्त)
		पटिनिवत्त SSH_ERR_NO_CIPHER_ALG_MATCH;
	सचे ((enc->cipher = cipher_by_name(name)) == रिक्त) {
		error_f("unsupported cipher %s", name);
		मुक्त(name);
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = रिक्त;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->कुञ्चिका = रिक्त;
	enc->कुञ्चिका_len = cipher_keylen(enc->cipher);
	enc->block_size = cipher_blocksize(enc->cipher);
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
choose_mac(संरचना ssh *ssh, संरचना sshmac *mac, वर्ण *client, वर्ण *server)
{
	वर्ण *name = match_list(client, server, रिक्त);

	सचे (name == रिक्त)
		पटिनिवत्त SSH_ERR_NO_MAC_ALG_MATCH;
	सचे (mac_setup(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		मुक्त(name);
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
	}
	mac->name = name;
	mac->कुञ्चिका = रिक्त;
	mac->enabled = 0;
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
choose_comp(संरचना sshcomp *comp, वर्ण *client, वर्ण *server)
{
	वर्ण *name = match_list(client, server, रिक्त);

	सचे (name == रिक्त)
		पटिनिवत्त SSH_ERR_NO_COMPRESS_ALG_MATCH;
#ifdef WITH_ZLIB
	सचे (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} अञ्ञथा
#endif	/* WITH_ZLIB */
	सचे (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} अञ्ञथा {
		error_f("unsupported compression scheme %s", name);
		मुक्त(name);
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
	}
	comp->name = name;
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
choose_kex(संरचना kex *k, वर्ण *client, वर्ण *server)
{
	k->name = match_list(client, server, रिक्त);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	सचे (k->name == रिक्त)
		पटिनिवत्त SSH_ERR_NO_KEX_ALG_MATCH;
	सचे (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
choose_hostkeyalg(संरचना kex *k, वर्ण *client, वर्ण *server)
{
	मुक्त(k->hostkey_alg);
	k->hostkey_alg = match_list(client, server, रिक्त);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	सचे (k->hostkey_alg == रिक्त)
		पटिनिवत्त SSH_ERR_NO_HOSTKEY_ALG_MATCH;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	सचे (k->hostkey_type == कुञ्चिका_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
proposals_match(वर्ण *my[PROPOSAL_MAX], वर्ण *peer[PROPOSAL_MAX])
{
	स्थिर पूर्णाङ्क check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS, -1
	};
	पूर्णाङ्क *idx;
	वर्ण *p;

	अत्थाय (idx = &check[0]; *idx != -1; idx++) {
		सचे ((p = strchr(my[*idx], ',')) != रिक्त)
			*p = '\0';
		सचे ((p = strchr(peer[*idx], ',')) != रिक्त)
			*p = '\0';
		सचे (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			पटिनिवत्त (0);
		}
	}
	debug2("proposals match");
	पटिनिवत्त (1);
}

स्थिर पूर्णाङ्क
kexalgs_contains(वर्ण **peer, ध्रुव वर्ण *ext)
{
	पटिनिवत्त kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
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
	सचे ((r = kex_buf2prop(kex->my, रिक्त, &my)) != 0)
		गच्छ out;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	सचे ((r = kex_buf2prop(kex->peer, &first_kex_follows, &peer)) != 0)
		गच्छ out;

	सचे (kex->server) {
		cprop=peer;
		sprop=my;
	} अञ्ञथा {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	सचे ((kex->flags & KEX_INITIAL) != 0) {
		सचे (kex->server) {
			kex->ext_info_c = kexalgs_contains(peer, "ext-info-c");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-c-v00@openssh.com");
		} अञ्ञथा {
			kex->ext_info_s = kexalgs_contains(peer, "ext-info-s");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-s-v00@openssh.com");
		}
		सचे (kex->kex_strict) {
			debug3_f("will use strict KEX ordering");
			सचे (seq != 0)
				ssh_packet_disconnect(ssh,
				    "strict KEX violation: "
				    "KEXINIT was not the first packet");
		}
	}

	/* Check whether client supports rsa-sha2 algorithms */
	सचे (kex->server && (kex->flags & KEX_INITIAL)) {
		सचे (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		सचे (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	सचे ((r = choose_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = रिक्त;
		गच्छ out;
	}
	सचे ((r = choose_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS];
		peer[PROPOSAL_SERVER_HOST_कुञ्चिका_ALGS] = रिक्त;
		गच्छ out;
	}
	अत्थाय (mode = 0; mode < MODE_MAX; mode++) {
		सचे ((newkeys = calloc(1, परिमाण(*newkeys))) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		kex->newkeys[mode] = newkeys;
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		सचे ((r = choose_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = रिक्त;
			गच्छ out;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		सचे (authlen == 0 &&
		    (r = choose_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = रिक्त;
			गच्छ out;
		}
		सचे ((r = choose_comp(&newkeys->comp, cprop[ncomp],
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
	अत्थाय (mode = 0; mode < MODE_MAX; mode++) {
		newkeys = kex->newkeys[mode];
		need = MAXIMUM(need, newkeys->enc.कुञ्चिका_len);
		need = MAXIMUM(need, newkeys->enc.block_size);
		need = MAXIMUM(need, newkeys->enc.iv_len);
		need = MAXIMUM(need, newkeys->mac.कुञ्चिका_len);
		dh_need = MAXIMUM(dh_need, cipher_seclen(newkeys->enc.cipher));
		dh_need = MAXIMUM(dh_need, newkeys->enc.block_size);
		dh_need = MAXIMUM(dh_need, newkeys->enc.iv_len);
		dh_need = MAXIMUM(dh_need, newkeys->mac.कुञ्चिका_len);
	}
	/* XXX need runden? */
	kex->we_need = need;
	kex->dh_need = dh_need;

	/* ignore the next message if the proposals do not match */
	सचे (first_kex_follows && !proposals_match(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 out:
	kex_prop_free(my);
	kex_prop_free(peer);
	पटिनिवत्त r;
}

स्थिर पूर्णाङ्क
derive_कुञ्चिका(संरचना ssh *ssh, पूर्णाङ्क id, u_int need, u_char *hash, u_int hashlen,
    ध्रुव संरचना sshbuf *shared_secret, u_char **keyp)
{
	संरचना kex *kex = ssh->kex;
	संरचना ssh_digest_ctx *hashctx = रिक्त;
	वर्ण c = id;
	u_int have;
	size_t mdsz;
	u_char *digest;
	पूर्णाङ्क r;

	सचे ((mdsz = ssh_digest_bytes(kex->hash_alg)) == 0)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	सचे ((digest = calloc(1, ROUNDUP(need, mdsz))) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	सचे ((hashctx = ssh_digest_start(kex->hash_alg)) == रिक्त ||
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
	अत्थाय (have = mdsz; need > have; have += mdsz) {
		सचे ((hashctx = ssh_digest_start(kex->hash_alg)) == रिक्त ||
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
	पटिनिवत्त r;
}

#define NKEYS	6
पूर्णाङ्क
kex_derive_कुञ्चिकाः(संरचना ssh *ssh, u_char *hash, u_int hashlen,
    ध्रुव संरचना sshbuf *shared_secret)
{
	संरचना kex *kex = ssh->kex;
	u_char *कुञ्चिकाः[NKEYS];
	u_int i, j, mode, ctos;
	पूर्णाङ्क r;

	/* save initial hash as session id */
	सचे ((kex->flags & KEX_INITIAL) != 0) {
		सचे (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
		}
		सचे ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			पटिनिवत्त r;
	} अञ्ञथा सचे (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
	}
	अत्थाय (i = 0; i < NKEYS; i++) {
		सचे ((r = derive_कुञ्चिका(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &कुञ्चिकाः[i])) != 0) {
			अत्थाय (j = 0; j < i; j++)
				मुक्त(कुञ्चिकाः[j]);
			पटिनिवत्त r;
		}
	}
	अत्थाय (mode = 0; mode < MODE_MAX; mode++) {
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		kex->newkeys[mode]->enc.iv  = कुञ्चिकाः[ctos ? 0 : 1];
		kex->newkeys[mode]->enc.कुञ्चिका = कुञ्चिकाः[ctos ? 2 : 3];
		kex->newkeys[mode]->mac.कुञ्चिका = कुञ्चिकाः[ctos ? 4 : 5];
	}
	पटिनिवत्त 0;
}

पूर्णाङ्क
kex_load_hostkey(संरचना ssh *ssh, संरचना sshkey **prvp, संरचना sshkey **pubp)
{
	संरचना kex *kex = ssh->kex;

	*pubp = रिक्त;
	*prvp = रिक्त;
	सचे (kex->load_host_public_कुञ्चिका == रिक्त ||
	    kex->load_host_private_कुञ्चिका == रिक्त) {
		error_f("missing hostkey loader");
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	}
	*pubp = kex->load_host_public_कुञ्चिका(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->load_host_private_कुञ्चिका(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	सचे (*pubp == रिक्त)
		पटिनिवत्त SSH_ERR_NO_HOSTKEY_LOADED;
	पटिनिवत्त 0;
}

पूर्णाङ्क
kex_verify_host_कुञ्चिका(संरचना ssh *ssh, संरचना sshkey *server_host_कुञ्चिका)
{
	संरचना kex *kex = ssh->kex;

	सचे (kex->verify_host_कुञ्चिका == रिक्त) {
		error_f("missing hostkey verifier");
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	}
	सचे (server_host_कुञ्चिका->type != kex->hostkey_type ||
	    (kex->hostkey_type == कुञ्चिका_ECDSA &&
	    server_host_कुञ्चिका->ecdsa_nid != kex->hostkey_nid))
		पटिनिवत्त SSH_ERR_कुञ्चिका_TYPE_MISMATCH;
	सचे (kex->verify_host_कुञ्चिका(server_host_कुञ्चिका, ssh) == -1)
		पटिनिवत्त  SSH_ERR_SIGNATURE_INVALID;
	पटिनिवत्त 0;
}

#सचे defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
शून्य
dump_digest(ध्रुव वर्ण *सन्देशः, ध्रुव u_char *digest, पूर्णाङ्क len)
{
	fprintf(stderr, "%s\n", सन्देशः);
	sshbuf_dump_data(digest, len, stderr);
}
#endif

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
स्थिर शून्य
send_error(संरचना ssh *ssh, वर्ण *सन्देशः)
{
	वर्ण *crnl = "\r\n";

	सचे (!ssh->kex->server)
		पटिनिवत्त;

	सचे (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    सन्देशः, strlen(सन्देशः)) != strlen(सन्देशः) ||
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
	सचे (version_addendum != रिक्त && *version_addendum == '\0')
		version_addendum = रिक्त;
	सचे ((r = sshbuf_putf(our_version, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_VERSION,
	    version_addendum == रिक्त ? "" : " ",
	    version_addendum == रिक्त ? "" : version_addendum)) != 0) {
		oerrno = errno;
		error_fr(r, "sshbuf_putf");
		गच्छ out;
	}

	सचे (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    sshbuf_mutable_ptr(our_version),
	    sshbuf_len(our_version)) != sshbuf_len(our_version)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		गच्छ out;
	}
	सचे ((r = sshbuf_consume_end(our_version, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		गच्छ out;
	}
	our_version_string = sshbuf_dup_string(our_version);
	सचे (our_version_string == रिक्त) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	debug("Local version string %.100s", our_version_string);

	/* Read other side's version identification. */
	अत्थाय (n = 0; ; n++) {
		सचे (n >= SSH_MAX_PRE_BANNER_पङ्क्तयः) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_पङ्क्तयः);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
		sshbuf_reset(peer_version);
		expect_nl = 0;
		अत्थाय (;;) {
			सचे (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_in(ssh),
				    &timeout_ms, रिक्त);
				सचे (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					गच्छ out;
				} अञ्ञथा सचे (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					गच्छ out;
				}
			}

			len = atomicio(पठ, ssh_packet_get_connection_in(ssh),
			    &c, 1);
			सचे (len != 1 && errno == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				गच्छ out;
			} अञ्ञथा सचे (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				गच्छ out;
			}
			सचे (c == '\r') {
				expect_nl = 1;
				अनुवर्त;
			}
			सचे (c == '\n')
				भङ्ग;
			सचे (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				गच्छ invalid;
			}
			सचे ((r = sshbuf_put_u8(peer_version, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				गच्छ out;
			}
			सचे (sshbuf_len(peer_version) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				गच्छ invalid;
			}
		}
		/* Is this an actual protocol banner? */
		सचे (sshbuf_len(peer_version) > 4 &&
		    memcmp(sshbuf_ptr(peer_version), "SSH-", 4) == 0)
			भङ्ग;
		/* If not, then just log the line and continue */
		सचे ((cp = sshbuf_dup_string(peer_version)) == रिक्त) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		/* Do not accept lines before the SSH ident from a client */
		सचे (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			मुक्त(cp);
			गच्छ invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		मुक्त(cp);
	}
	peer_version_string = sshbuf_dup_string(peer_version);
	सचे (peer_version_string == रिक्त)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	सचे ((remote_version = calloc(1, sshbuf_len(peer_version))) == रिक्त) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	सचे (sscanf(peer_version_string, "SSH-%d.%d-%[^\n]\n",
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
		सचे (remote_minor != 99)
			mismatch = 1;
		भङ्ग;
	स्वभाव:
		mismatch = 1;
		भङ्ग;
	}
	सचे (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_VERSION;
		गच्छ out;
	}

	सचे (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		गच्छ out;
	}
	सचे (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
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
	सचे (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	पटिनिवत्त r;
}

