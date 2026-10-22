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
स्थिर पूर्णांक kex_choose_conf(संरचना ssh *, uint32_t seq);
स्थिर पूर्णांक kex_आदान_newkeys(पूर्णांक, uint32_t, संरचना ssh *);

स्थिर स्थिरांक अक्षर * स्थिरांक proposal_names[PROPOSAL_MAX] = {
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
kex_proposal_populate_entries(संरचना ssh *ssh, अक्षर *prop[PROPOSAL_MAX],
    स्थिरांक अक्षर *kexalgos, स्थिरांक अक्षर *ciphers, स्थिरांक अक्षर *macs,
    स्थिरांक अक्षर *comp, स्थिरांक अक्षर *hkalgs)
{
	स्थिरांक अक्षर *defpropserver[PROPOSAL_MAX] = { KEX_SERVER };
	स्थिरांक अक्षर *defpropclient[PROPOSAL_MAX] = { KEX_CLIENT };
	स्थिरांक अक्षर **defprop = ssh->kex->server ? defpropserver : defpropclient;
	u_int i;
	अक्षर *cp;

	जर (prop == रिक्त)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	जर (kexalgos == रिक्त)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	जर ((cp = kex_names_cat(kexalgos, ssh->kex->server ?
	    "ext-info-s,kex-strict-s-v00@openssh.com" :
	    "ext-info-c,kex-strict-c-v00@openssh.com")) == रिक्त)
		fatal_f("kex_names_cat");

	साठी (i = 0; i < PROPOSAL_MAX; i++) {
		निवड(i) {
		स्थिती PROPOSAL_KEX_ALGS:
			prop[i] = compat_kex_proposal(ssh, cp);
			थांबा;
		स्थिती PROPOSAL_ENC_ALGS_CTOS:
		स्थिती PROPOSAL_ENC_ALGS_STOC:
			prop[i] = xstrdup(ciphers ? ciphers : defprop[i]);
			थांबा;
		स्थिती PROPOSAL_MAC_ALGS_CTOS:
		स्थिती PROPOSAL_MAC_ALGS_STOC:
			prop[i]  = xstrdup(macs ? macs : defprop[i]);
			थांबा;
		स्थिती PROPOSAL_COMP_ALGS_CTOS:
		स्थिती PROPOSAL_COMP_ALGS_STOC:
			prop[i] = xstrdup(comp ? comp : defprop[i]);
			थांबा;
		स्थिती PROPOSAL_SERVER_HOST_किल्ली_ALGS:
			prop[i] = xstrdup(hkalgs ? hkalgs : defprop[i]);
			थांबा;
		पूर्वनिर्धारित:
			prop[i] = xstrdup(defprop[i]);
		}
	}
	मुक्त(cp);
}

शून्य
kex_proposal_free_entries(अक्षर *prop[PROPOSAL_MAX])
{
	u_int i;

	साठी (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(prop[i]);
}

/* put algorithm proposal into buffer */
पूर्णांक
kex_prop2buf(संरचना sshbuf *b, अक्षर *proposal[PROPOSAL_MAX])
{
	u_int i;
	पूर्णांक r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	साठी (i = 0; i < KEX_COOKIE_LEN; i++) {
		जर ((r = sshbuf_put_u8(b, 0)) != 0)
			परत r;
	}
	साठी (i = 0; i < PROPOSAL_MAX; i++) {
		जर ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			परत r;
	}
	जर ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		परत r;
	परत 0;
}

/* parse buffer and return algorithm proposal */
पूर्णांक
kex_buf2prop(संरचना sshbuf *raw, पूर्णांक *first_kex_follows, अक्षर ***propp)
{
	संरचना sshbuf *b = रिक्त;
	u_char v;
	u_int i;
	अक्षर **proposal = रिक्त;
	पूर्णांक r;

	*propp = रिक्त;
	जर ((proposal = सुस्मृति(PROPOSAL_MAX, आकार(अक्षर *))) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((b = sshbuf_fromb(raw)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		जा out;
	}
	/* extract kex init proposal strings */
	साठी (i = 0; i < PROPOSAL_MAX; i++) {
		जर ((r = sshbuf_get_cstring(b, &(proposal[i]), रिक्त)) != 0) {
			error_fr(r, "parse proposal %u", i);
			जा out;
		}
		debug2("%s: %s", proposal_names[i], proposal[i]);
	}
	/* first kex follows / reserved */
	जर ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		जा out;
	}
	जर (first_kex_follows != रिक्त)
		*first_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 out:
	जर (r != 0 && proposal != रिक्त)
		kex_prop_free(proposal);
	sshbuf_free(b);
	परत r;
}

शून्य
kex_prop_free(अक्षर **proposal)
{
	u_int i;

	जर (proposal == रिक्त)
		परत;
	साठी (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(proposal[i]);
	मुक्त(proposal);
}

पूर्णांक
kex_protocol_error(पूर्णांक type, uint32_t seq, संरचना ssh *ssh)
{
	पूर्णांक r;

	/* If in strict mode, any unexpected message is an error */
	जर ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	जर ((r = sshpkt_start(ssh, SSH2_संदेश_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		परत r;
	परत 0;
}

स्थिर शून्य
kex_reset_dispatch(संरचना ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_संदेश_TRANSPORT_MIN,
	    SSH2_संदेश_TRANSPORT_MAX, &kex_protocol_error);
}

शून्य
kex_set_server_sig_algs(संरचना ssh *ssh, स्थिरांक अक्षर *allowed_algs)
{
	अक्षर *alg, *oalgs, *algs, *sigalgs;
	स्थिरांक अक्षर *sigalg;

	/*
	 * NB. allowed algorithms may contain certificate algorithms that
	 * map to a specific plain signature type, e.g.
	 * rsa-sha2-512-cert-v01@openssh.com => rsa-sha2-512
	 * We need to be careful here to match these, retain the mapping
	 * and only add each signature algorithm once.
	 */
	जर ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == रिक्त)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	मुक्त(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = रिक्त;
	साठी ((alg = strsep(&algs, ",")); alg != रिक्त && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		जर ((sigalg = sshkey_sigalg_by_name(alg)) == रिक्त)
			सुरूठेवा;
		जर (!kex_has_any_alg(sigalg, sigalgs))
			सुरूठेवा;
		/* Don't add an algorithm twice. */
		जर (ssh->kex->server_sig_algs != रिक्त &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			सुरूठेवा;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	मुक्त(oalgs);
	मुक्त(sigalgs);
	जर (ssh->kex->server_sig_algs == रिक्त)
		ssh->kex->server_sig_algs = xstrdup("");
}

शून्य
kex_set_warn_weak_crypto(संरचना ssh *ssh, पूर्णांक warn_weak_crypto)
{
	जर (ssh != रिक्त && ssh->kex != रिक्त)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

शून्य
kex_check_warn_weak_crypto(संरचना ssh *ssh)
{
	अक्षर remote_id[512];
	पूर्णांक rekeyed = 0;

	जर (ssh == रिक्त || ssh->kex == रिक्त || ssh->kex->name == रिक्त ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		परत;
	जर (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		परत;
	}

	जर (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	जर (!rekeyed && !ssh->kex->server)
		परत; /* client logs initial KEX warning separately */

	sshpkt_fmt_connection_id(ssh, remote_id, आकार(remote_id));
	logit("WARNING: %sconnection%s%s is not using a post-quantum "
	    "key exchange algorithm: \"%s\"", rekeyed ? "rekeyed " : "",
	    ssh->kex->server ? " from " : "",
	    ssh->kex->server ? remote_id : "", ssh->kex->name);
	ssh->kex->non_pq_kex_warned = 1;
}

स्थिर पूर्णांक
kex_compose_ext_info_server(संरचना ssh *ssh, संरचना sshbuf *m)
{
	पूर्णांक r;

	जर (ssh->kex->server_sig_algs == रिक्त &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = sshbuf_put_u32(m, 4)) != 0 ||
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
		परत r;
	}
	परत 0;
}

स्थिर पूर्णांक
kex_compose_ext_info_client(संरचना ssh *ssh, संरचना sshbuf *m)
{
	पूर्णांक r;

	जर ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		जा out;
	}
	/* success */
	r = 0;
 out:
	परत r;
}

स्थिर पूर्णांक
kex_maybe_send_ext_info(संरचना ssh *ssh)
{
	पूर्णांक r;
	संरचना sshbuf *m = रिक्त;

	जर ((ssh->kex->flags & KEX_INITIAL) == 0)
		परत 0;
	जर (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		परत 0;

	/* Compose EXT_INFO packet. */
	जर ((m = sshbuf_new()) == रिक्त)
		fatal_f("sshbuf_new failed");
	जर (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		जा fail;
	जर (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		जा fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	जर ((r = sshpkt_start(ssh, SSH2_संदेश_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		जा fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	परत r;
}

पूर्णांक
kex_server_update_ext_info(संरचना ssh *ssh)
{
	पूर्णांक r;

	जर ((ssh->kex->flags & KEX_HAS_EXT_INFO_IN_AUTH) == 0)
		परत 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	जर ((r = sshpkt_start(ssh, SSH2_संदेश_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		परत r;
	}
	परत 0;
}

पूर्णांक
kex_send_newkeys(संरचना ssh *ssh)
{
	पूर्णांक r;

	kex_reset_dispatch(ssh);
	जर ((r = sshpkt_start(ssh, SSH2_संदेश_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		परत r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_set(ssh, SSH2_संदेश_NEWKEYS, &kex_आदान_newkeys);
	जर ((r = kex_maybe_send_ext_info(ssh)) != 0)
		परत r;
	debug("expecting SSH2_MSG_NEWKEYS");
	परत 0;
}

/* Check whether an ext_info value contains the expected version string */
स्थिर पूर्णांक
kex_ext_info_check_ver(संरचना kex *kex, स्थिरांक अक्षर *name,
    स्थिरांक u_char *val, माप_प्रकार len, स्थिरांक अक्षर *want_ver, u_int flag)
{
	जर (स_प्रथम(val, '\0', len) != रिक्त) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		परत SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	जर (म_भेद(val, want_ver) == 0)
		kex->flags |= flag;
	अन्यथा
		debug_f("unsupported version of %s extension", name);
	परत 0;
}

स्थिर पूर्णांक
kex_ext_info_client_parse(संरचना ssh *ssh, स्थिरांक अक्षर *name,
    स्थिरांक u_char *मूल्य, माप_प्रकार vlen)
{
	पूर्णांक r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	जर (म_भेद(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		जर (स_प्रथम(मूल्य, '\0', vlen) != रिक्त) {
			error_f("nul byte in %s", name);
			परत SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, मूल्य);
		मुक्त(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((स्थिरांक अक्षर *)मूल्य);
	} अन्यथा जर (ssh->kex->ext_info_received == 1 &&
	    म_भेद(name, "publickey-hostbound@openssh.com") == 0) {
		जर ((r = kex_ext_info_check_ver(ssh->kex, name, मूल्य, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			परत r;
		}
	} अन्यथा जर (ssh->kex->ext_info_received == 1 &&
	    म_भेद(name, "ping@openssh.com") == 0) {
		जर ((r = kex_ext_info_check_ver(ssh->kex, name, मूल्य, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			परत r;
		}
	} अन्यथा जर (ssh->kex->ext_info_received == 1 &&
	    म_भेद(name, "agent-forward") == 0) {
		जर ((r = kex_ext_info_check_ver(ssh->kex, name, मूल्य, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			परत r;
		}
	} अन्यथा
		debug_f("%s (unrecognised)", name);

	परत 0;
}

स्थिर पूर्णांक
kex_ext_info_server_parse(संरचना ssh *ssh, स्थिरांक अक्षर *name,
    स्थिरांक u_char *मूल्य, माप_प्रकार vlen)
{
	पूर्णांक r;

	जर (म_भेद(name, "ext-info-in-auth@openssh.com") == 0) {
		जर ((r = kex_ext_info_check_ver(ssh->kex, name, मूल्य, vlen,
		    "0", KEX_HAS_EXT_INFO_IN_AUTH)) != 0) {
			परत r;
		}
	} अन्यथा
		debug_f("%s (unrecognised)", name);
	परत 0;
}

पूर्णांक
kex_आदान_ext_info(पूर्णांक type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	स्थिरांक पूर्णांक max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	अक्षर *name;
	u_char *val;
	माप_प्रकार vlen;
	पूर्णांक r;

	debug("SSH2_MSG_EXT_INFO received");
	जर (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		परत dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_set(ssh, SSH2_संदेश_EXT_INFO, &kex_protocol_error);
	जर ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		परत r;
	जर (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		परत dispatch_protocol_error(type, seq, ssh);
	}
	साठी (i = 0; i < ninfo; i++) {
		जर ((r = sshpkt_get_cstring(ssh, &name, रिक्त)) != 0)
			परत r;
		जर ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			मुक्त(name);
			परत r;
		}
		debug3_f("extension %s", name);
		जर (kex->server) {
			जर ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				परत r;
		} अन्यथा {
			जर ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				परत r;
		}
		मुक्त(name);
		मुक्त(val);
	}
	परत sshpkt_get_end(ssh);
}

स्थिर पूर्णांक
kex_आदान_newkeys(पूर्णांक type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	पूर्णांक r, initial = (kex->flags & KEX_INITIAL) != 0;
	अक्षर *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	जर (kex->ext_info_c && initial)
		ssh_dispatch_set(ssh, SSH2_संदेश_EXT_INFO, &kex_आदान_ext_info);
	ssh_dispatch_set(ssh, SSH2_संदेश_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_set(ssh, SSH2_संदेश_KEXINIT, &kex_आदान_kexinit);
	जर ((r = sshpkt_get_end(ssh)) != 0)
		परत r;
	जर ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0)
		परत r;
	जर (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		जर ((r = kex_buf2prop(kex->my, रिक्त, &prop)) != 0)
			परत r;
		जर ((cp = match_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == रिक्त) {
			error_f("match_filter_denylist failed");
			जा fail;
		}
		मुक्त(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		जर ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			मुक्त(prop);
			परत SSH_ERR_INTERNAL_ERROR;
		}
		kex_proposal_free_entries(prop);
		मुक्त(prop);
	}
	kex->done = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_SENT|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	परत 0;
}

पूर्णांक
kex_send_kexinit(संरचना ssh *ssh)
{
	u_char *cookie;
	संरचना kex *kex = ssh->kex;
	पूर्णांक r;

	जर (kex == रिक्त) {
		error_f("no kex");
		परत SSH_ERR_INTERNAL_ERROR;
	}
	जर (kex->flags & KEX_INIT_SENT)
		परत 0;
	kex->done = 0;

	/* generate a random cookie */
	जर (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		परत SSH_ERR_INVALID_FORMAT;
	}
	जर ((cookie = sshbuf_mutable_ptr(kex->my)) == रिक्त) {
		error_f("buffer error");
		परत SSH_ERR_INTERNAL_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	जर ((r = sshpkt_start(ssh, SSH2_संदेश_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		परत r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_SENT;
	परत 0;
}

पूर्णांक
kex_आदान_kexinit(पूर्णांक type, uint32_t seq, संरचना ssh *ssh)
{
	संरचना kex *kex = ssh->kex;
	स्थिरांक u_char *ptr;
	u_int i;
	माप_प्रकार dlen;
	पूर्णांक r;

	debug("SSH2_MSG_KEXINIT received");
	जर (kex == रिक्त) {
		error_f("no kex");
		परत SSH_ERR_INTERNAL_ERROR;
	}
	मुक्त(kex->name);
	kex->name = रिक्त;
	जर ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_set(ssh, SSH2_संदेश_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	जर ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		परत r;

	/* discard packet */
	साठी (i = 0; i < KEX_COOKIE_LEN; i++) {
		जर ((r = sshpkt_get_u8(ssh, रिक्त)) != 0) {
			error_fr(r, "discard cookie");
			परत r;
		}
	}
	साठी (i = 0; i < PROPOSAL_MAX; i++) {
		जर ((r = sshpkt_get_string(ssh, रिक्त, रिक्त)) != 0) {
			error_fr(r, "discard proposal");
			परत r;
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
	जर ((r = sshpkt_get_u8(ssh, रिक्त)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, रिक्त)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
			परत r;

	जर (!(kex->flags & KEX_INIT_SENT))
		जर ((r = kex_send_kexinit(ssh)) != 0)
			परत r;
	जर ((r = kex_choose_conf(ssh, seq)) != 0)
		परत r;

	जर (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != रिक्त)
		परत (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	परत SSH_ERR_INTERNAL_ERROR;
}

संरचना kex *
kex_new(शून्य)
{
	संरचना kex *kex;

	जर ((kex = सुस्मृति(1, आकार(*kex))) == रिक्त ||
	    (kex->peer = sshbuf_new()) == रिक्त ||
	    (kex->my = sshbuf_new()) == रिक्त ||
	    (kex->client_version = sshbuf_new()) == रिक्त ||
	    (kex->server_version = sshbuf_new()) == रिक्त ||
	    (kex->session_id = sshbuf_new()) == रिक्त) {
		kex_free(kex);
		परत रिक्त;
	}
	परत kex;
}

शून्य
kex_free_newkeys(संरचना newkeys *newkeys)
{
	जर (newkeys == रिक्त)
		परत;
	जर (newkeys->enc.किल्ली) {
		explicit_bzero(newkeys->enc.किल्ली, newkeys->enc.किल्ली_len);
		मुक्त(newkeys->enc.किल्ली);
		newkeys->enc.किल्ली = रिक्त;
	}
	जर (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		मुक्त(newkeys->enc.iv);
		newkeys->enc.iv = रिक्त;
	}
	मुक्त(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, आकार(newkeys->enc));
	मुक्त(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, आकार(newkeys->comp));
	mac_clear(&newkeys->mac);
	जर (newkeys->mac.किल्ली) {
		explicit_bzero(newkeys->mac.किल्ली, newkeys->mac.किल्ली_len);
		मुक्त(newkeys->mac.किल्ली);
		newkeys->mac.किल्ली = रिक्त;
	}
	मुक्त(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, आकार(newkeys->mac));
	freezero(newkeys, आकार(*newkeys));
}

शून्य
kex_free(संरचना kex *kex)
{
	u_int mode;

	जर (kex == रिक्त)
		परत;

#ifdef WITH_OPENSSL
	DH_free(kex->dh);
	EC_किल्ली_free(kex->ec_client_किल्ली);
#endif /* WITH_OPENSSL */
	साठी (mode = 0; mode < MODE_MAX; mode++) {
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

पूर्णांक
kex_ready(संरचना ssh *ssh, अक्षर *proposal[PROPOSAL_MAX])
{
	पूर्णांक r;

	जर ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		परत r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_set(ssh, SSH2_संदेश_KEXINIT, &kex_आदान_kexinit);
	परत 0;
}

पूर्णांक
kex_setup(संरचना ssh *ssh, अक्षर *proposal[PROPOSAL_MAX])
{
	पूर्णांक r;

	जर ((r = kex_ready(ssh, proposal)) != 0)
		परत r;
	जर ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = रिक्त;
		परत r;
	}
	परत 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
पूर्णांक
kex_start_rekex(संरचना ssh *ssh)
{
	जर (ssh->kex == रिक्त) {
		error_f("no kex");
		परत SSH_ERR_INTERNAL_ERROR;
	}
	जर (ssh->kex->done == 0) {
		error_f("requested twice");
		परत SSH_ERR_INTERNAL_ERROR;
	}
	ssh->kex->done = 0;
	परत kex_send_kexinit(ssh);
}

स्थिर पूर्णांक
choose_enc(संरचना sshenc *enc, अक्षर *client, अक्षर *server)
{
	अक्षर *name = match_list(client, server, रिक्त);

	जर (name == रिक्त)
		परत SSH_ERR_NO_CIPHER_ALG_MATCH;
	जर ((enc->cipher = cipher_by_name(name)) == रिक्त) {
		error_f("unsupported cipher %s", name);
		मुक्त(name);
		परत SSH_ERR_INTERNAL_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = रिक्त;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->किल्ली = रिक्त;
	enc->किल्ली_len = cipher_keylen(enc->cipher);
	enc->block_size = cipher_blocksize(enc->cipher);
	परत 0;
}

स्थिर पूर्णांक
choose_mac(संरचना ssh *ssh, संरचना sshmac *mac, अक्षर *client, अक्षर *server)
{
	अक्षर *name = match_list(client, server, रिक्त);

	जर (name == रिक्त)
		परत SSH_ERR_NO_MAC_ALG_MATCH;
	जर (mac_setup(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		मुक्त(name);
		परत SSH_ERR_INTERNAL_ERROR;
	}
	mac->name = name;
	mac->किल्ली = रिक्त;
	mac->enabled = 0;
	परत 0;
}

स्थिर पूर्णांक
choose_comp(संरचना sshcomp *comp, अक्षर *client, अक्षर *server)
{
	अक्षर *name = match_list(client, server, रिक्त);

	जर (name == रिक्त)
		परत SSH_ERR_NO_COMPRESS_ALG_MATCH;
#ifdef WITH_ZLIB
	जर (म_भेद(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} अन्यथा
#endif	/* WITH_ZLIB */
	जर (म_भेद(name, "none") == 0) {
		comp->type = COMP_NONE;
	} अन्यथा {
		error_f("unsupported compression scheme %s", name);
		मुक्त(name);
		परत SSH_ERR_INTERNAL_ERROR;
	}
	comp->name = name;
	परत 0;
}

स्थिर पूर्णांक
choose_kex(संरचना kex *k, अक्षर *client, अक्षर *server)
{
	k->name = match_list(client, server, रिक्त);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	जर (k->name == रिक्त)
		परत SSH_ERR_NO_KEX_ALG_MATCH;
	जर (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		परत SSH_ERR_INTERNAL_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	परत 0;
}

स्थिर पूर्णांक
choose_hostkeyalg(संरचना kex *k, अक्षर *client, अक्षर *server)
{
	मुक्त(k->hostkey_alg);
	k->hostkey_alg = match_list(client, server, रिक्त);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	जर (k->hostkey_alg == रिक्त)
		परत SSH_ERR_NO_HOSTKEY_ALG_MATCH;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	जर (k->hostkey_type == किल्ली_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		परत SSH_ERR_INTERNAL_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	परत 0;
}

स्थिर पूर्णांक
proposals_match(अक्षर *my[PROPOSAL_MAX], अक्षर *peer[PROPOSAL_MAX])
{
	स्थिर पूर्णांक check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_किल्ली_ALGS, -1
	};
	पूर्णांक *idx;
	अक्षर *p;

	साठी (idx = &check[0]; *idx != -1; idx++) {
		जर ((p = म_अक्षर(my[*idx], ',')) != रिक्त)
			*p = '\0';
		जर ((p = म_अक्षर(peer[*idx], ',')) != रिक्त)
			*p = '\0';
		जर (म_भेद(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			परत (0);
		}
	}
	debug2("proposals match");
	परत (1);
}

स्थिर पूर्णांक
kexalgs_contains(अक्षर **peer, स्थिरांक अक्षर *ext)
{
	परत kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

स्थिर पूर्णांक
kex_choose_conf(संरचना ssh *ssh, uint32_t seq)
{
	संरचना kex *kex = ssh->kex;
	संरचना newkeys *newkeys;
	अक्षर **my = रिक्त, **peer = रिक्त;
	अक्षर **cprop, **sprop;
	पूर्णांक nenc, nmac, ncomp;
	u_int mode, ctos, need, dh_need, authlen;
	पूर्णांक r, first_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	जर ((r = kex_buf2prop(kex->my, रिक्त, &my)) != 0)
		जा out;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	जर ((r = kex_buf2prop(kex->peer, &first_kex_follows, &peer)) != 0)
		जा out;

	जर (kex->server) {
		cprop=peer;
		sprop=my;
	} अन्यथा {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	जर ((kex->flags & KEX_INITIAL) != 0) {
		जर (kex->server) {
			kex->ext_info_c = kexalgs_contains(peer, "ext-info-c");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-c-v00@openssh.com");
		} अन्यथा {
			kex->ext_info_s = kexalgs_contains(peer, "ext-info-s");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-s-v00@openssh.com");
		}
		जर (kex->kex_strict) {
			debug3_f("will use strict KEX ordering");
			जर (seq != 0)
				ssh_packet_disconnect(ssh,
				    "strict KEX violation: "
				    "KEXINIT was not the first packet");
		}
	}

	/* Check whether client supports rsa-sha2 algorithms */
	जर (kex->server && (kex->flags & KEX_INITIAL)) {
		जर (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_किल्ली_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		जर (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_किल्ली_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	जर ((r = choose_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = रिक्त;
		जा out;
	}
	जर ((r = choose_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_किल्ली_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_किल्ली_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_किल्ली_ALGS];
		peer[PROPOSAL_SERVER_HOST_किल्ली_ALGS] = रिक्त;
		जा out;
	}
	साठी (mode = 0; mode < MODE_MAX; mode++) {
		जर ((newkeys = सुस्मृति(1, आकार(*newkeys))) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			जा out;
		}
		kex->newkeys[mode] = newkeys;
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		जर ((r = choose_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = रिक्त;
			जा out;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		जर (authlen == 0 &&
		    (r = choose_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = रिक्त;
			जा out;
		}
		जर ((r = choose_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0) {
			kex->failed_choice = peer[ncomp];
			peer[ncomp] = रिक्त;
			जा out;
		}
		debug("kex: %s cipher: %s MAC: %s compression: %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    authlen == 0 ? newkeys->mac.name : "<implicit>",
		    newkeys->comp.name);
	}
	need = dh_need = 0;
	साठी (mode = 0; mode < MODE_MAX; mode++) {
		newkeys = kex->newkeys[mode];
		need = MAXIMUM(need, newkeys->enc.किल्ली_len);
		need = MAXIMUM(need, newkeys->enc.block_size);
		need = MAXIMUM(need, newkeys->enc.iv_len);
		need = MAXIMUM(need, newkeys->mac.किल्ली_len);
		dh_need = MAXIMUM(dh_need, cipher_seclen(newkeys->enc.cipher));
		dh_need = MAXIMUM(dh_need, newkeys->enc.block_size);
		dh_need = MAXIMUM(dh_need, newkeys->enc.iv_len);
		dh_need = MAXIMUM(dh_need, newkeys->mac.किल्ली_len);
	}
	/* XXX need runden? */
	kex->we_need = need;
	kex->dh_need = dh_need;

	/* ignore the next message if the proposals do not match */
	जर (first_kex_follows && !proposals_match(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 out:
	kex_prop_free(my);
	kex_prop_free(peer);
	परत r;
}

स्थिर पूर्णांक
derive_किल्ली(संरचना ssh *ssh, पूर्णांक id, u_int need, u_char *hash, u_int hashlen,
    स्थिरांक संरचना sshbuf *shared_secret, u_char **keyp)
{
	संरचना kex *kex = ssh->kex;
	संरचना ssh_digest_ctx *hashctx = रिक्त;
	अक्षर c = id;
	u_int have;
	माप_प्रकार mdsz;
	u_char *digest;
	पूर्णांक r;

	जर ((mdsz = ssh_digest_bytes(kex->hash_alg)) == 0)
		परत SSH_ERR_INVALID_ARGUMENT;
	जर ((digest = सुस्मृति(1, ROUNDUP(need, mdsz))) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	जर ((hashctx = ssh_digest_start(kex->hash_alg)) == रिक्त ||
	    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
	    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
	    ssh_digest_update(hashctx, &c, 1) != 0 ||
	    ssh_digest_update_buffer(hashctx, kex->session_id) != 0 ||
	    ssh_digest_final(hashctx, digest, mdsz) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		error_f("KEX hash failed");
		जा out;
	}
	ssh_digest_free(hashctx);
	hashctx = रिक्त;

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	साठी (have = mdsz; need > have; have += mdsz) {
		जर ((hashctx = ssh_digest_start(kex->hash_alg)) == रिक्त ||
		    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
		    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
		    ssh_digest_update(hashctx, digest, have) != 0 ||
		    ssh_digest_final(hashctx, digest + have, mdsz) != 0) {
			error_f("KDF failed");
			r = SSH_ERR_LIBCRYPTO_ERROR;
			जा out;
		}
		ssh_digest_free(hashctx);
		hashctx = रिक्त;
	}
#ifdef DEBUG_KEX
	ख_लिखो(मानक_त्रुटि, "key '%c'== ", c);
	dump_digest("key", digest, need);
#endif
	*keyp = digest;
	digest = रिक्त;
	r = 0;
 out:
	मुक्त(digest);
	ssh_digest_free(hashctx);
	परत r;
}

#define NKEYS	6
पूर्णांक
kex_derive_किल्ल्या(संरचना ssh *ssh, u_char *hash, u_int hashlen,
    स्थिरांक संरचना sshbuf *shared_secret)
{
	संरचना kex *kex = ssh->kex;
	u_char *किल्ल्या[NKEYS];
	u_int i, j, mode, ctos;
	पूर्णांक r;

	/* save initial hash as session id */
	जर ((kex->flags & KEX_INITIAL) != 0) {
		जर (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			परत SSH_ERR_INTERNAL_ERROR;
		}
		जर ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			परत r;
	} अन्यथा जर (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		परत SSH_ERR_INTERNAL_ERROR;
	}
	साठी (i = 0; i < NKEYS; i++) {
		जर ((r = derive_किल्ली(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &किल्ल्या[i])) != 0) {
			साठी (j = 0; j < i; j++)
				मुक्त(किल्ल्या[j]);
			परत r;
		}
	}
	साठी (mode = 0; mode < MODE_MAX; mode++) {
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		kex->newkeys[mode]->enc.iv  = किल्ल्या[ctos ? 0 : 1];
		kex->newkeys[mode]->enc.किल्ली = किल्ल्या[ctos ? 2 : 3];
		kex->newkeys[mode]->mac.किल्ली = किल्ल्या[ctos ? 4 : 5];
	}
	परत 0;
}

पूर्णांक
kex_load_hostkey(संरचना ssh *ssh, संरचना sshkey **prvp, संरचना sshkey **pubp)
{
	संरचना kex *kex = ssh->kex;

	*pubp = रिक्त;
	*prvp = रिक्त;
	जर (kex->load_host_public_किल्ली == रिक्त ||
	    kex->load_host_private_किल्ली == रिक्त) {
		error_f("missing hostkey loader");
		परत SSH_ERR_INVALID_ARGUMENT;
	}
	*pubp = kex->load_host_public_किल्ली(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->load_host_private_किल्ली(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	जर (*pubp == रिक्त)
		परत SSH_ERR_NO_HOSTKEY_LOADED;
	परत 0;
}

पूर्णांक
kex_verify_host_किल्ली(संरचना ssh *ssh, संरचना sshkey *server_host_किल्ली)
{
	संरचना kex *kex = ssh->kex;

	जर (kex->verify_host_किल्ली == रिक्त) {
		error_f("missing hostkey verifier");
		परत SSH_ERR_INVALID_ARGUMENT;
	}
	जर (server_host_किल्ली->type != kex->hostkey_type ||
	    (kex->hostkey_type == किल्ली_ECDSA &&
	    server_host_किल्ली->ecdsa_nid != kex->hostkey_nid))
		परत SSH_ERR_किल्ली_TYPE_MISMATCH;
	जर (kex->verify_host_किल्ली(server_host_किल्ली, ssh) == -1)
		परत  SSH_ERR_SIGNATURE_INVALID;
	परत 0;
}

#जर defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
शून्य
dump_digest(स्थिरांक अक्षर *संदेश, स्थिरांक u_char *digest, पूर्णांक len)
{
	ख_लिखो(मानक_त्रुटि, "%s\n", संदेश);
	sshbuf_dump_data(digest, len, मानक_त्रुटि);
}
#endif

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
स्थिर शून्य
send_error(संरचना ssh *ssh, अक्षर *संदेश)
{
	अक्षर *crnl = "\r\n";

	जर (!ssh->kex->server)
		परत;

	जर (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    संदेश, म_माप(संदेश)) != म_माप(संदेश) ||
	    atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    crnl, म_माप(crnl)) != म_माप(crnl))
		error_f("write: %.100s", म_त्रुटि(त्रुटि_सं));
}

/*
 * Sends our identification string and waits for the peer's. Will block for
 * up to timeout_ms (or indefinitely if timeout_ms <= 0).
 * Returns on 0 success or a ssherr.h code on failure.
 */
पूर्णांक
kex_exchange_identification(संरचना ssh *ssh, पूर्णांक timeout_ms,
    स्थिरांक अक्षर *version_addendum)
{
	पूर्णांक remote_major, remote_minor, mismatch, oerrno = 0;
	माप_प्रकार len, n;
	पूर्णांक r, expect_nl;
	u_char c;
	संरचना sshbuf *our_version = ssh->kex->server ?
	    ssh->kex->server_version : ssh->kex->client_version;
	संरचना sshbuf *peer_version = ssh->kex->server ?
	    ssh->kex->client_version : ssh->kex->server_version;
	अक्षर *our_version_string = रिक्त, *peer_version_string = रिक्त;
	अक्षर *cp, *remote_version = रिक्त;

	/* Prepare and send our banner */
	sshbuf_reset(our_version);
	जर (version_addendum != रिक्त && *version_addendum == '\0')
		version_addendum = रिक्त;
	जर ((r = sshbuf_putf(our_version, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_VERSION,
	    version_addendum == रिक्त ? "" : " ",
	    version_addendum == रिक्त ? "" : version_addendum)) != 0) {
		oerrno = त्रुटि_सं;
		error_fr(r, "sshbuf_putf");
		जा out;
	}

	जर (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    sshbuf_mutable_ptr(our_version),
	    sshbuf_len(our_version)) != sshbuf_len(our_version)) {
		oerrno = त्रुटि_सं;
		debug_f("write: %.100s", म_त्रुटि(त्रुटि_सं));
		r = SSH_ERR_SYSTEM_ERROR;
		जा out;
	}
	जर ((r = sshbuf_consume_end(our_version, 2)) != 0) { /* trim \r\n */
		oerrno = त्रुटि_सं;
		error_fr(r, "sshbuf_consume_end");
		जा out;
	}
	our_version_string = sshbuf_dup_string(our_version);
	जर (our_version_string == रिक्त) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	debug("Local version string %.100s", our_version_string);

	/* Read other side's version identification. */
	साठी (n = 0; ; n++) {
		जर (n >= SSH_MAX_PRE_BANNER_ओळी) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_ओळी);
			r = SSH_ERR_INVALID_FORMAT;
			जा out;
		}
		sshbuf_reset(peer_version);
		expect_nl = 0;
		साठी (;;) {
			जर (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_in(ssh),
				    &timeout_ms, रिक्त);
				जर (r == -1 && त्रुटि_सं == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					जा out;
				} अन्यथा जर (r == -1) {
					oerrno = त्रुटि_सं;
					error_f("%s", म_त्रुटि(त्रुटि_सं));
					r = SSH_ERR_SYSTEM_ERROR;
					जा out;
				}
			}

			len = atomicio(पठ, ssh_packet_get_connection_in(ssh),
			    &c, 1);
			जर (len != 1 && त्रुटि_सं == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				जा out;
			} अन्यथा जर (len != 1) {
				oerrno = त्रुटि_सं;
				error_f("read: %.100s", म_त्रुटि(त्रुटि_सं));
				r = SSH_ERR_SYSTEM_ERROR;
				जा out;
			}
			जर (c == '\r') {
				expect_nl = 1;
				सुरूठेवा;
			}
			जर (c == '\n')
				थांबा;
			जर (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				जा invalid;
			}
			जर ((r = sshbuf_put_u8(peer_version, c)) != 0) {
				oerrno = त्रुटि_सं;
				error_fr(r, "sshbuf_put");
				जा out;
			}
			जर (sshbuf_len(peer_version) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				जा invalid;
			}
		}
		/* Is this an actual protocol banner? */
		जर (sshbuf_len(peer_version) > 4 &&
		    स_भेद(sshbuf_ptr(peer_version), "SSH-", 4) == 0)
			थांबा;
		/* If not, then just log the line and continue */
		जर ((cp = sshbuf_dup_string(peer_version)) == रिक्त) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			जा out;
		}
		/* Do not accept lines before the SSH ident from a client */
		जर (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			मुक्त(cp);
			जा invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		मुक्त(cp);
	}
	peer_version_string = sshbuf_dup_string(peer_version);
	जर (peer_version_string == रिक्त)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	जर ((remote_version = सुस्मृति(1, sshbuf_len(peer_version))) == रिक्त) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	जर (माला_पूछो(peer_version_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		error("Bad remote protocol version identification: '%.100s'",
		    peer_version_string);
 invalid:
		send_error(ssh, "Invalid SSH identification string.");
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);
	compat_banner(ssh, remote_version);

	mismatch = 0;
	निवड (remote_major) {
	स्थिती 2:
		थांबा;
	स्थिती 1:
		जर (remote_minor != 99)
			mismatch = 1;
		थांबा;
	पूर्वनिर्धारित:
		mismatch = 1;
		थांबा;
	}
	जर (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_VERSION;
		जा out;
	}

	जर (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		जा out;
	}
	जर (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
		logit("scanned from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		जा out;
	}
	/* success */
	r = 0;
 out:
	मुक्त(our_version_string);
	मुक्त(peer_version_string);
	ssh->remote_version = remote_version;  /* transferred */
	जर (r == SSH_ERR_SYSTEM_ERROR)
		त्रुटि_सं = oerrno;
	परत r;
}

