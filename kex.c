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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <errno.h>
#समावेश <signal.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/crypto.h>
#समावेश <openssl/dh.h>
#पूर्ण_अगर

#समावेश "ssh.h"
#समावेश "ssh2.h"
#समावेश "atomicio.h"
#समावेश "version.h"
#समावेश "packet.h"
#समावेश "compat.h"
#समावेश "cipher.h"
#समावेश "sshkey.h"
#समावेश "kex.h"
#समावेश "log.h"
#समावेश "mac.h"
#समावेश "match.h"
#समावेश "misc.h"
#समावेश "dispatch.h"
#समावेश "myproposal.h"

#समावेश "ssherr.h"
#समावेश "sshbuf.h"
#समावेश "digest.h"
#समावेश "xmalloc.h"

/* prototype */
अटल पूर्णांक kex_choose_conf(काष्ठा ssh *, uint32_t seq);
अटल पूर्णांक kex_निवेश_newkeys(पूर्णांक, uint32_t, काष्ठा ssh *);

अटल स्थिर अक्षर * स्थिर proposal_names[PROPOSAL_MAX] = {
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
व्योम
kex_proposal_populate_entries(काष्ठा ssh *ssh, अक्षर *prop[PROPOSAL_MAX],
    स्थिर अक्षर *kexalgos, स्थिर अक्षर *ciphers, स्थिर अक्षर *macs,
    स्थिर अक्षर *comp, स्थिर अक्षर *hkalgs)
{
	स्थिर अक्षर *defpropserver[PROPOSAL_MAX] = { KEX_SERVER };
	स्थिर अक्षर *defpropclient[PROPOSAL_MAX] = { KEX_CLIENT };
	स्थिर अक्षर **defprop = ssh->kex->server ? defpropserver : defpropclient;
	u_int i;
	अक्षर *cp;

	अगर (prop == शून्य)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	अगर (kexalgos == शून्य)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	अगर ((cp = kex_names_cat(kexalgos, ssh->kex->server ?
	    "ext-info-s,kex-strict-s-v00@openssh.com" :
	    "ext-info-c,kex-strict-c-v00@openssh.com")) == शून्य)
		fatal_f("kex_names_cat");

	क्रम (i = 0; i < PROPOSAL_MAX; i++) {
		चयन(i) {
		हाल PROPOSAL_KEX_ALGS:
			prop[i] = compat_kex_proposal(ssh, cp);
			अवरोध;
		हाल PROPOSAL_ENC_ALGS_CTOS:
		हाल PROPOSAL_ENC_ALGS_STOC:
			prop[i] = xstrdup(ciphers ? ciphers : defprop[i]);
			अवरोध;
		हाल PROPOSAL_MAC_ALGS_CTOS:
		हाल PROPOSAL_MAC_ALGS_STOC:
			prop[i]  = xstrdup(macs ? macs : defprop[i]);
			अवरोध;
		हाल PROPOSAL_COMP_ALGS_CTOS:
		हाल PROPOSAL_COMP_ALGS_STOC:
			prop[i] = xstrdup(comp ? comp : defprop[i]);
			अवरोध;
		हाल PROPOSAL_SERVER_HOST_कुंजी_ALGS:
			prop[i] = xstrdup(hkalgs ? hkalgs : defprop[i]);
			अवरोध;
		शेष:
			prop[i] = xstrdup(defprop[i]);
		}
	}
	मुक्त(cp);
}

व्योम
kex_proposal_free_entries(अक्षर *prop[PROPOSAL_MAX])
{
	u_int i;

	क्रम (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(prop[i]);
}

/* put algorithm proposal into buffer */
पूर्णांक
kex_prop2buf(काष्ठा sshbuf *b, अक्षर *proposal[PROPOSAL_MAX])
{
	u_int i;
	पूर्णांक r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	क्रम (i = 0; i < KEX_COOKIE_LEN; i++) {
		अगर ((r = sshbuf_put_u8(b, 0)) != 0)
			वापस r;
	}
	क्रम (i = 0; i < PROPOSAL_MAX; i++) {
		अगर ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			वापस r;
	}
	अगर ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		वापस r;
	वापस 0;
}

/* parse buffer and return algorithm proposal */
पूर्णांक
kex_buf2prop(काष्ठा sshbuf *raw, पूर्णांक *first_kex_follows, अक्षर ***propp)
{
	काष्ठा sshbuf *b = शून्य;
	u_char v;
	u_int i;
	अक्षर **proposal = शून्य;
	पूर्णांक r;

	*propp = शून्य;
	अगर ((proposal = सुस्मृति(PROPOSAL_MAX, माप(अक्षर *))) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((b = sshbuf_fromb(raw)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		जाओ out;
	}
	/* extract kex init proposal strings */
	क्रम (i = 0; i < PROPOSAL_MAX; i++) {
		अगर ((r = sshbuf_get_cstring(b, &(proposal[i]), शून्य)) != 0) {
			error_fr(r, "parse proposal %u", i);
			जाओ out;
		}
		debug2("%s: %s", proposal_names[i], proposal[i]);
	}
	/* first kex follows / reserved */
	अगर ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		जाओ out;
	}
	अगर (first_kex_follows != शून्य)
		*first_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 out:
	अगर (r != 0 && proposal != शून्य)
		kex_prop_free(proposal);
	sshbuf_free(b);
	वापस r;
}

व्योम
kex_prop_free(अक्षर **proposal)
{
	u_int i;

	अगर (proposal == शून्य)
		वापस;
	क्रम (i = 0; i < PROPOSAL_MAX; i++)
		मुक्त(proposal[i]);
	मुक्त(proposal);
}

पूर्णांक
kex_protocol_error(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	पूर्णांक r;

	/* If in strict mode, any unexpected message is an error */
	अगर ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		वापस r;
	वापस 0;
}

अटल व्योम
kex_reset_dispatch(काष्ठा ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_संदेश_TRANSPORT_MIN,
	    SSH2_संदेश_TRANSPORT_MAX, &kex_protocol_error);
}

व्योम
kex_set_server_sig_algs(काष्ठा ssh *ssh, स्थिर अक्षर *allowed_algs)
{
	अक्षर *alg, *oalgs, *algs, *sigalgs;
	स्थिर अक्षर *sigalg;

	/*
	 * NB. allowed algorithms may contain certificate algorithms that
	 * map to a specific plain signature type, e.g.
	 * rsa-sha2-512-cert-v01@openssh.com => rsa-sha2-512
	 * We need to be careful here to match these, retain the mapping
	 * and only add each signature algorithm once.
	 */
	अगर ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == शून्य)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	मुक्त(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = शून्य;
	क्रम ((alg = strsep(&algs, ",")); alg != शून्य && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		अगर ((sigalg = sshkey_sigalg_by_name(alg)) == शून्य)
			जारी;
		अगर (!kex_has_any_alg(sigalg, sigalgs))
			जारी;
		/* Don't add an algorithm twice. */
		अगर (ssh->kex->server_sig_algs != शून्य &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			जारी;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	मुक्त(oalgs);
	मुक्त(sigalgs);
	अगर (ssh->kex->server_sig_algs == शून्य)
		ssh->kex->server_sig_algs = xstrdup("");
}

व्योम
kex_set_warn_weak_crypto(काष्ठा ssh *ssh, पूर्णांक warn_weak_crypto)
{
	अगर (ssh != शून्य && ssh->kex != शून्य)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

व्योम
kex_check_warn_weak_crypto(काष्ठा ssh *ssh)
{
	अक्षर remote_id[512];
	पूर्णांक rekeyed = 0;

	अगर (ssh == शून्य || ssh->kex == शून्य || ssh->kex->name == शून्य ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		वापस;
	अगर (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		वापस;
	}

	अगर (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	अगर (!rekeyed && !ssh->kex->server)
		वापस; /* client logs initial KEX warning separately */

	sshpkt_fmt_connection_id(ssh, remote_id, माप(remote_id));
	logit("WARNING: %sconnection%s%s is not using a post-quantum "
	    "key exchange algorithm: \"%s\"", rekeyed ? "rekeyed " : "",
	    ssh->kex->server ? " from " : "",
	    ssh->kex->server ? remote_id : "", ssh->kex->name);
	ssh->kex->non_pq_kex_warned = 1;
}

अटल पूर्णांक
kex_compose_ext_info_server(काष्ठा ssh *ssh, काष्ठा sshbuf *m)
{
	पूर्णांक r;

	अगर (ssh->kex->server_sig_algs == शून्य &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_put_u32(m, 4)) != 0 ||
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
		वापस r;
	}
	वापस 0;
}

अटल पूर्णांक
kex_compose_ext_info_client(काष्ठा ssh *ssh, काष्ठा sshbuf *m)
{
	पूर्णांक r;

	अगर ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		जाओ out;
	}
	/* success */
	r = 0;
 out:
	वापस r;
}

अटल पूर्णांक
kex_maybe_send_ext_info(काष्ठा ssh *ssh)
{
	पूर्णांक r;
	काष्ठा sshbuf *m = शून्य;

	अगर ((ssh->kex->flags & KEX_INITIAL) == 0)
		वापस 0;
	अगर (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		वापस 0;

	/* Compose EXT_INFO packet. */
	अगर ((m = sshbuf_new()) == शून्य)
		fatal_f("sshbuf_new failed");
	अगर (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		जाओ fail;
	अगर (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		जाओ fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		जाओ fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	वापस r;
}

पूर्णांक
kex_server_update_ext_info(काष्ठा ssh *ssh)
{
	पूर्णांक r;

	अगर ((ssh->kex->flags & KEX_HAS_EXT_INFO_IN_AUTH) == 0)
		वापस 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		वापस r;
	}
	वापस 0;
}

पूर्णांक
kex_send_newkeys(काष्ठा ssh *ssh)
{
	पूर्णांक r;

	kex_reset_dispatch(ssh);
	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		वापस r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_set(ssh, SSH2_संदेश_NEWKEYS, &kex_निवेश_newkeys);
	अगर ((r = kex_maybe_send_ext_info(ssh)) != 0)
		वापस r;
	debug("expecting SSH2_MSG_NEWKEYS");
	वापस 0;
}

/* Check whether an ext_info value contains the expected version string */
अटल पूर्णांक
kex_ext_info_check_ver(काष्ठा kex *kex, स्थिर अक्षर *name,
    स्थिर u_char *val, माप_प्रकार len, स्थिर अक्षर *want_ver, u_int flag)
{
	अगर (स_प्रथम(val, '\0', len) != शून्य) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		वापस SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	अगर (म_भेद(val, want_ver) == 0)
		kex->flags |= flag;
	अन्यथा
		debug_f("unsupported version of %s extension", name);
	वापस 0;
}

अटल पूर्णांक
kex_ext_info_client_parse(काष्ठा ssh *ssh, स्थिर अक्षर *name,
    स्थिर u_char *मूल्य, माप_प्रकार vlen)
{
	पूर्णांक r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	अगर (म_भेद(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		अगर (स_प्रथम(मूल्य, '\0', vlen) != शून्य) {
			error_f("nul byte in %s", name);
			वापस SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, मूल्य);
		मुक्त(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((स्थिर अक्षर *)मूल्य);
	} अन्यथा अगर (ssh->kex->ext_info_received == 1 &&
	    म_भेद(name, "publickey-hostbound@openssh.com") == 0) {
		अगर ((r = kex_ext_info_check_ver(ssh->kex, name, मूल्य, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			वापस r;
		}
	} अन्यथा अगर (ssh->kex->ext_info_received == 1 &&
	    म_भेद(name, "ping@openssh.com") == 0) {
		अगर ((r = kex_ext_info_check_ver(ssh->kex, name, मूल्य, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			वापस r;
		}
	} अन्यथा अगर (ssh->kex->ext_info_received == 1 &&
	    म_भेद(name, "agent-forward") == 0) {
		अगर ((r = kex_ext_info_check_ver(ssh->kex, name, मूल्य, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			वापस r;
		}
	} अन्यथा
		debug_f("%s (unrecognised)", name);

	वापस 0;
}

अटल पूर्णांक
kex_ext_info_server_parse(काष्ठा ssh *ssh, स्थिर अक्षर *name,
    स्थिर u_char *मूल्य, माप_प्रकार vlen)
{
	पूर्णांक r;

	अगर (म_भेद(name, "ext-info-in-auth@openssh.com") == 0) {
		अगर ((r = kex_ext_info_check_ver(ssh->kex, name, मूल्य, vlen,
		    "0", KEX_HAS_EXT_INFO_IN_AUTH)) != 0) {
			वापस r;
		}
	} अन्यथा
		debug_f("%s (unrecognised)", name);
	वापस 0;
}

पूर्णांक
kex_निवेश_ext_info(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	काष्ठा kex *kex = ssh->kex;
	स्थिर पूर्णांक max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	अक्षर *name;
	u_char *val;
	माप_प्रकार vlen;
	पूर्णांक r;

	debug("SSH2_MSG_EXT_INFO received");
	अगर (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		वापस dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_set(ssh, SSH2_संदेश_EXT_INFO, &kex_protocol_error);
	अगर ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		वापस r;
	अगर (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		वापस dispatch_protocol_error(type, seq, ssh);
	}
	क्रम (i = 0; i < ninfo; i++) {
		अगर ((r = sshpkt_get_cstring(ssh, &name, शून्य)) != 0)
			वापस r;
		अगर ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			मुक्त(name);
			वापस r;
		}
		debug3_f("extension %s", name);
		अगर (kex->server) {
			अगर ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				वापस r;
		} अन्यथा {
			अगर ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				वापस r;
		}
		मुक्त(name);
		मुक्त(val);
	}
	वापस sshpkt_get_end(ssh);
}

अटल पूर्णांक
kex_निवेश_newkeys(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	काष्ठा kex *kex = ssh->kex;
	पूर्णांक r, initial = (kex->flags & KEX_INITIAL) != 0;
	अक्षर *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	अगर (kex->ext_info_c && initial)
		ssh_dispatch_set(ssh, SSH2_संदेश_EXT_INFO, &kex_निवेश_ext_info);
	ssh_dispatch_set(ssh, SSH2_संदेश_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_set(ssh, SSH2_संदेश_KEXINIT, &kex_निवेश_kexinit);
	अगर ((r = sshpkt_get_end(ssh)) != 0)
		वापस r;
	अगर ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0)
		वापस r;
	अगर (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		अगर ((r = kex_buf2prop(kex->my, शून्य, &prop)) != 0)
			वापस r;
		अगर ((cp = match_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == शून्य) {
			error_f("match_filter_denylist failed");
			जाओ fail;
		}
		मुक्त(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		अगर ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			मुक्त(prop);
			वापस SSH_ERR_INTERNAL_ERROR;
		}
		kex_proposal_free_entries(prop);
		मुक्त(prop);
	}
	kex->done = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_SENT|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	वापस 0;
}

पूर्णांक
kex_send_kexinit(काष्ठा ssh *ssh)
{
	u_char *cookie;
	काष्ठा kex *kex = ssh->kex;
	पूर्णांक r;

	अगर (kex == शून्य) {
		error_f("no kex");
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	अगर (kex->flags & KEX_INIT_SENT)
		वापस 0;
	kex->done = 0;

	/* generate a random cookie */
	अगर (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		वापस SSH_ERR_INVALID_FORMAT;
	}
	अगर ((cookie = sshbuf_mutable_ptr(kex->my)) == शून्य) {
		error_f("buffer error");
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	अगर ((r = sshpkt_start(ssh, SSH2_संदेश_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		वापस r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_SENT;
	वापस 0;
}

पूर्णांक
kex_निवेश_kexinit(पूर्णांक type, uint32_t seq, काष्ठा ssh *ssh)
{
	काष्ठा kex *kex = ssh->kex;
	स्थिर u_char *ptr;
	u_int i;
	माप_प्रकार dlen;
	पूर्णांक r;

	debug("SSH2_MSG_KEXINIT received");
	अगर (kex == शून्य) {
		error_f("no kex");
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	मुक्त(kex->name);
	kex->name = शून्य;
	अगर ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_set(ssh, SSH2_संदेश_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	अगर ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		वापस r;

	/* discard packet */
	क्रम (i = 0; i < KEX_COOKIE_LEN; i++) {
		अगर ((r = sshpkt_get_u8(ssh, शून्य)) != 0) {
			error_fr(r, "discard cookie");
			वापस r;
		}
	}
	क्रम (i = 0; i < PROPOSAL_MAX; i++) {
		अगर ((r = sshpkt_get_string(ssh, शून्य, शून्य)) != 0) {
			error_fr(r, "discard proposal");
			वापस r;
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
	अगर ((r = sshpkt_get_u8(ssh, शून्य)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, शून्य)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
			वापस r;

	अगर (!(kex->flags & KEX_INIT_SENT))
		अगर ((r = kex_send_kexinit(ssh)) != 0)
			वापस r;
	अगर ((r = kex_choose_conf(ssh, seq)) != 0)
		वापस r;

	अगर (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != शून्य)
		वापस (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	वापस SSH_ERR_INTERNAL_ERROR;
}

काष्ठा kex *
kex_new(व्योम)
{
	काष्ठा kex *kex;

	अगर ((kex = सुस्मृति(1, माप(*kex))) == शून्य ||
	    (kex->peer = sshbuf_new()) == शून्य ||
	    (kex->my = sshbuf_new()) == शून्य ||
	    (kex->client_version = sshbuf_new()) == शून्य ||
	    (kex->server_version = sshbuf_new()) == शून्य ||
	    (kex->session_id = sshbuf_new()) == शून्य) {
		kex_free(kex);
		वापस शून्य;
	}
	वापस kex;
}

व्योम
kex_free_newkeys(काष्ठा newkeys *newkeys)
{
	अगर (newkeys == शून्य)
		वापस;
	अगर (newkeys->enc.कुंजी) {
		explicit_bzero(newkeys->enc.कुंजी, newkeys->enc.कुंजी_len);
		मुक्त(newkeys->enc.कुंजी);
		newkeys->enc.कुंजी = शून्य;
	}
	अगर (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		मुक्त(newkeys->enc.iv);
		newkeys->enc.iv = शून्य;
	}
	मुक्त(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, माप(newkeys->enc));
	मुक्त(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, माप(newkeys->comp));
	mac_clear(&newkeys->mac);
	अगर (newkeys->mac.कुंजी) {
		explicit_bzero(newkeys->mac.कुंजी, newkeys->mac.कुंजी_len);
		मुक्त(newkeys->mac.कुंजी);
		newkeys->mac.कुंजी = शून्य;
	}
	मुक्त(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, माप(newkeys->mac));
	freezero(newkeys, माप(*newkeys));
}

व्योम
kex_free(काष्ठा kex *kex)
{
	u_int mode;

	अगर (kex == शून्य)
		वापस;

#अगर_घोषित WITH_OPENSSL
	DH_free(kex->dh);
	EC_कुंजी_free(kex->ec_client_कुंजी);
#पूर्ण_अगर /* WITH_OPENSSL */
	क्रम (mode = 0; mode < MODE_MAX; mode++) {
		kex_free_newkeys(kex->newkeys[mode]);
		kex->newkeys[mode] = शून्य;
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
kex_ready(काष्ठा ssh *ssh, अक्षर *proposal[PROPOSAL_MAX])
{
	पूर्णांक r;

	अगर ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		वापस r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_set(ssh, SSH2_संदेश_KEXINIT, &kex_निवेश_kexinit);
	वापस 0;
}

पूर्णांक
kex_setup(काष्ठा ssh *ssh, अक्षर *proposal[PROPOSAL_MAX])
{
	पूर्णांक r;

	अगर ((r = kex_ready(ssh, proposal)) != 0)
		वापस r;
	अगर ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = शून्य;
		वापस r;
	}
	वापस 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
पूर्णांक
kex_start_rekex(काष्ठा ssh *ssh)
{
	अगर (ssh->kex == शून्य) {
		error_f("no kex");
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	अगर (ssh->kex->done == 0) {
		error_f("requested twice");
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	ssh->kex->done = 0;
	वापस kex_send_kexinit(ssh);
}

अटल पूर्णांक
choose_enc(काष्ठा sshenc *enc, अक्षर *client, अक्षर *server)
{
	अक्षर *name = match_list(client, server, शून्य);

	अगर (name == शून्य)
		वापस SSH_ERR_NO_CIPHER_ALG_MATCH;
	अगर ((enc->cipher = cipher_by_name(name)) == शून्य) {
		error_f("unsupported cipher %s", name);
		मुक्त(name);
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = शून्य;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->कुंजी = शून्य;
	enc->कुंजी_len = cipher_keylen(enc->cipher);
	enc->block_आकार = cipher_blocksize(enc->cipher);
	वापस 0;
}

अटल पूर्णांक
choose_mac(काष्ठा ssh *ssh, काष्ठा sshmac *mac, अक्षर *client, अक्षर *server)
{
	अक्षर *name = match_list(client, server, शून्य);

	अगर (name == शून्य)
		वापस SSH_ERR_NO_MAC_ALG_MATCH;
	अगर (mac_setup(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		मुक्त(name);
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	mac->name = name;
	mac->कुंजी = शून्य;
	mac->enabled = 0;
	वापस 0;
}

अटल पूर्णांक
choose_comp(काष्ठा sshcomp *comp, अक्षर *client, अक्षर *server)
{
	अक्षर *name = match_list(client, server, शून्य);

	अगर (name == शून्य)
		वापस SSH_ERR_NO_COMPRESS_ALG_MATCH;
#अगर_घोषित WITH_ZLIB
	अगर (म_भेद(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} अन्यथा
#पूर्ण_अगर	/* WITH_ZLIB */
	अगर (म_भेद(name, "none") == 0) {
		comp->type = COMP_NONE;
	} अन्यथा {
		error_f("unsupported compression scheme %s", name);
		मुक्त(name);
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	comp->name = name;
	वापस 0;
}

अटल पूर्णांक
choose_kex(काष्ठा kex *k, अक्षर *client, अक्षर *server)
{
	k->name = match_list(client, server, शून्य);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	अगर (k->name == शून्य)
		वापस SSH_ERR_NO_KEX_ALG_MATCH;
	अगर (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	वापस 0;
}

अटल पूर्णांक
choose_hostkeyalg(काष्ठा kex *k, अक्षर *client, अक्षर *server)
{
	मुक्त(k->hostkey_alg);
	k->hostkey_alg = match_list(client, server, शून्य);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	अगर (k->hostkey_alg == शून्य)
		वापस SSH_ERR_NO_HOSTKEY_ALG_MATCH;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	अगर (k->hostkey_type == कुंजी_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	वापस 0;
}

अटल पूर्णांक
proposals_match(अक्षर *my[PROPOSAL_MAX], अक्षर *peer[PROPOSAL_MAX])
{
	अटल पूर्णांक check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_कुंजी_ALGS, -1
	};
	पूर्णांक *idx;
	अक्षर *p;

	क्रम (idx = &check[0]; *idx != -1; idx++) {
		अगर ((p = म_अक्षर(my[*idx], ',')) != शून्य)
			*p = '\0';
		अगर ((p = म_अक्षर(peer[*idx], ',')) != शून्य)
			*p = '\0';
		अगर (म_भेद(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			वापस (0);
		}
	}
	debug2("proposals match");
	वापस (1);
}

अटल पूर्णांक
kexalgs_contains(अक्षर **peer, स्थिर अक्षर *ext)
{
	वापस kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

अटल पूर्णांक
kex_choose_conf(काष्ठा ssh *ssh, uint32_t seq)
{
	काष्ठा kex *kex = ssh->kex;
	काष्ठा newkeys *newkeys;
	अक्षर **my = शून्य, **peer = शून्य;
	अक्षर **cprop, **sprop;
	पूर्णांक nenc, nmac, ncomp;
	u_int mode, ctos, need, dh_need, authlen;
	पूर्णांक r, first_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	अगर ((r = kex_buf2prop(kex->my, शून्य, &my)) != 0)
		जाओ out;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	अगर ((r = kex_buf2prop(kex->peer, &first_kex_follows, &peer)) != 0)
		जाओ out;

	अगर (kex->server) {
		cprop=peer;
		sprop=my;
	} अन्यथा {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	अगर ((kex->flags & KEX_INITIAL) != 0) {
		अगर (kex->server) {
			kex->ext_info_c = kexalgs_contains(peer, "ext-info-c");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-c-v00@openssh.com");
		} अन्यथा {
			kex->ext_info_s = kexalgs_contains(peer, "ext-info-s");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-s-v00@openssh.com");
		}
		अगर (kex->kex_strict) {
			debug3_f("will use strict KEX ordering");
			अगर (seq != 0)
				ssh_packet_disconnect(ssh,
				    "strict KEX violation: "
				    "KEXINIT was not the first packet");
		}
	}

	/* Check whether client supports rsa-sha2 algorithms */
	अगर (kex->server && (kex->flags & KEX_INITIAL)) {
		अगर (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_कुंजी_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		अगर (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_कुंजी_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	अगर ((r = choose_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = शून्य;
		जाओ out;
	}
	अगर ((r = choose_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_कुंजी_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_कुंजी_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_कुंजी_ALGS];
		peer[PROPOSAL_SERVER_HOST_कुंजी_ALGS] = शून्य;
		जाओ out;
	}
	क्रम (mode = 0; mode < MODE_MAX; mode++) {
		अगर ((newkeys = सुस्मृति(1, माप(*newkeys))) == शून्य) {
			r = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		kex->newkeys[mode] = newkeys;
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		अगर ((r = choose_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = शून्य;
			जाओ out;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		अगर (authlen == 0 &&
		    (r = choose_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = शून्य;
			जाओ out;
		}
		अगर ((r = choose_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0) {
			kex->failed_choice = peer[ncomp];
			peer[ncomp] = शून्य;
			जाओ out;
		}
		debug("kex: %s cipher: %s MAC: %s compression: %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    authlen == 0 ? newkeys->mac.name : "<implicit>",
		    newkeys->comp.name);
	}
	need = dh_need = 0;
	क्रम (mode = 0; mode < MODE_MAX; mode++) {
		newkeys = kex->newkeys[mode];
		need = MAXIMUM(need, newkeys->enc.कुंजी_len);
		need = MAXIMUM(need, newkeys->enc.block_आकार);
		need = MAXIMUM(need, newkeys->enc.iv_len);
		need = MAXIMUM(need, newkeys->mac.कुंजी_len);
		dh_need = MAXIMUM(dh_need, cipher_seclen(newkeys->enc.cipher));
		dh_need = MAXIMUM(dh_need, newkeys->enc.block_आकार);
		dh_need = MAXIMUM(dh_need, newkeys->enc.iv_len);
		dh_need = MAXIMUM(dh_need, newkeys->mac.कुंजी_len);
	}
	/* XXX need runden? */
	kex->we_need = need;
	kex->dh_need = dh_need;

	/* ignore the next message if the proposals do not match */
	अगर (first_kex_follows && !proposals_match(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 out:
	kex_prop_free(my);
	kex_prop_free(peer);
	वापस r;
}

अटल पूर्णांक
derive_कुंजी(काष्ठा ssh *ssh, पूर्णांक id, u_int need, u_char *hash, u_int hashlen,
    स्थिर काष्ठा sshbuf *shared_secret, u_char **keyp)
{
	काष्ठा kex *kex = ssh->kex;
	काष्ठा ssh_digest_ctx *hashctx = शून्य;
	अक्षर c = id;
	u_int have;
	माप_प्रकार mdsz;
	u_char *digest;
	पूर्णांक r;

	अगर ((mdsz = ssh_digest_bytes(kex->hash_alg)) == 0)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर ((digest = सुस्मृति(1, ROUNDUP(need, mdsz))) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	अगर ((hashctx = ssh_digest_start(kex->hash_alg)) == शून्य ||
	    ssh_digest_update_बफर(hashctx, shared_secret) != 0 ||
	    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
	    ssh_digest_update(hashctx, &c, 1) != 0 ||
	    ssh_digest_update_बफर(hashctx, kex->session_id) != 0 ||
	    ssh_digest_final(hashctx, digest, mdsz) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		error_f("KEX hash failed");
		जाओ out;
	}
	ssh_digest_free(hashctx);
	hashctx = शून्य;

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	क्रम (have = mdsz; need > have; have += mdsz) {
		अगर ((hashctx = ssh_digest_start(kex->hash_alg)) == शून्य ||
		    ssh_digest_update_बफर(hashctx, shared_secret) != 0 ||
		    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
		    ssh_digest_update(hashctx, digest, have) != 0 ||
		    ssh_digest_final(hashctx, digest + have, mdsz) != 0) {
			error_f("KDF failed");
			r = SSH_ERR_LIBCRYPTO_ERROR;
			जाओ out;
		}
		ssh_digest_free(hashctx);
		hashctx = शून्य;
	}
#अगर_घोषित DEBUG_KEX
	ख_लिखो(मानक_त्रुटि, "key '%c'== ", c);
	dump_digest("key", digest, need);
#पूर्ण_अगर
	*keyp = digest;
	digest = शून्य;
	r = 0;
 out:
	मुक्त(digest);
	ssh_digest_free(hashctx);
	वापस r;
}

#घोषणा NKEYS	6
पूर्णांक
kex_derive_कुंजियाँ(काष्ठा ssh *ssh, u_char *hash, u_int hashlen,
    स्थिर काष्ठा sshbuf *shared_secret)
{
	काष्ठा kex *kex = ssh->kex;
	u_char *कुंजियाँ[NKEYS];
	u_int i, j, mode, ctos;
	पूर्णांक r;

	/* save initial hash as session id */
	अगर ((kex->flags & KEX_INITIAL) != 0) {
		अगर (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			वापस SSH_ERR_INTERNAL_ERROR;
		}
		अगर ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			वापस r;
	} अन्यथा अगर (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	क्रम (i = 0; i < NKEYS; i++) {
		अगर ((r = derive_कुंजी(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &कुंजियाँ[i])) != 0) {
			क्रम (j = 0; j < i; j++)
				मुक्त(कुंजियाँ[j]);
			वापस r;
		}
	}
	क्रम (mode = 0; mode < MODE_MAX; mode++) {
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		kex->newkeys[mode]->enc.iv  = कुंजियाँ[ctos ? 0 : 1];
		kex->newkeys[mode]->enc.कुंजी = कुंजियाँ[ctos ? 2 : 3];
		kex->newkeys[mode]->mac.कुंजी = कुंजियाँ[ctos ? 4 : 5];
	}
	वापस 0;
}

पूर्णांक
kex_load_hostkey(काष्ठा ssh *ssh, काष्ठा sshkey **prvp, काष्ठा sshkey **pubp)
{
	काष्ठा kex *kex = ssh->kex;

	*pubp = शून्य;
	*prvp = शून्य;
	अगर (kex->load_host_public_कुंजी == शून्य ||
	    kex->load_host_private_कुंजी == शून्य) {
		error_f("missing hostkey loader");
		वापस SSH_ERR_INVALID_ARGUMENT;
	}
	*pubp = kex->load_host_public_कुंजी(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->load_host_private_कुंजी(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	अगर (*pubp == शून्य)
		वापस SSH_ERR_NO_HOSTKEY_LOADED;
	वापस 0;
}

पूर्णांक
kex_verify_host_कुंजी(काष्ठा ssh *ssh, काष्ठा sshkey *server_host_कुंजी)
{
	काष्ठा kex *kex = ssh->kex;

	अगर (kex->verify_host_कुंजी == शून्य) {
		error_f("missing hostkey verifier");
		वापस SSH_ERR_INVALID_ARGUMENT;
	}
	अगर (server_host_कुंजी->type != kex->hostkey_type ||
	    (kex->hostkey_type == कुंजी_ECDSA &&
	    server_host_कुंजी->ecdsa_nid != kex->hostkey_nid))
		वापस SSH_ERR_कुंजी_TYPE_MISMATCH;
	अगर (kex->verify_host_कुंजी(server_host_कुंजी, ssh) == -1)
		वापस  SSH_ERR_SIGNATURE_INVALID;
	वापस 0;
}

#अगर defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
व्योम
dump_digest(स्थिर अक्षर *संदेश, स्थिर u_char *digest, पूर्णांक len)
{
	ख_लिखो(मानक_त्रुटि, "%s\n", संदेश);
	sshbuf_dump_तथ्य(digest, len, मानक_त्रुटि);
}
#पूर्ण_अगर

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
अटल व्योम
send_error(काष्ठा ssh *ssh, अक्षर *संदेश)
{
	अक्षर *crnl = "\r\n";

	अगर (!ssh->kex->server)
		वापस;

	अगर (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
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
kex_exchange_identification(काष्ठा ssh *ssh, पूर्णांक timeout_ms,
    स्थिर अक्षर *version_addendum)
{
	पूर्णांक remote_major, remote_minor, mismatch, oerrno = 0;
	माप_प्रकार len, n;
	पूर्णांक r, expect_nl;
	u_char c;
	काष्ठा sshbuf *our_version = ssh->kex->server ?
	    ssh->kex->server_version : ssh->kex->client_version;
	काष्ठा sshbuf *peer_version = ssh->kex->server ?
	    ssh->kex->client_version : ssh->kex->server_version;
	अक्षर *our_version_string = शून्य, *peer_version_string = शून्य;
	अक्षर *cp, *remote_version = शून्य;

	/* Prepare and send our banner */
	sshbuf_reset(our_version);
	अगर (version_addendum != शून्य && *version_addendum == '\0')
		version_addendum = शून्य;
	अगर ((r = sshbuf_putf(our_version, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_VERSION,
	    version_addendum == शून्य ? "" : " ",
	    version_addendum == शून्य ? "" : version_addendum)) != 0) {
		oerrno = त्रुटि_सं;
		error_fr(r, "sshbuf_putf");
		जाओ out;
	}

	अगर (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    sshbuf_mutable_ptr(our_version),
	    sshbuf_len(our_version)) != sshbuf_len(our_version)) {
		oerrno = त्रुटि_सं;
		debug_f("write: %.100s", म_त्रुटि(त्रुटि_सं));
		r = SSH_ERR_SYSTEM_ERROR;
		जाओ out;
	}
	अगर ((r = sshbuf_consume_end(our_version, 2)) != 0) { /* trim \r\n */
		oerrno = त्रुटि_सं;
		error_fr(r, "sshbuf_consume_end");
		जाओ out;
	}
	our_version_string = sshbuf_dup_string(our_version);
	अगर (our_version_string == शून्य) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	debug("Local version string %.100s", our_version_string);

	/* Read other side's version identification. */
	क्रम (n = 0; ; n++) {
		अगर (n >= SSH_MAX_PRE_BANNER_पंक्तियाँ) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_पंक्तियाँ);
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
		sshbuf_reset(peer_version);
		expect_nl = 0;
		क्रम (;;) {
			अगर (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_in(ssh),
				    &timeout_ms, शून्य);
				अगर (r == -1 && त्रुटि_सं == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					जाओ out;
				} अन्यथा अगर (r == -1) {
					oerrno = त्रुटि_सं;
					error_f("%s", म_त्रुटि(त्रुटि_सं));
					r = SSH_ERR_SYSTEM_ERROR;
					जाओ out;
				}
			}

			len = atomicio(पढ़ो, ssh_packet_get_connection_in(ssh),
			    &c, 1);
			अगर (len != 1 && त्रुटि_सं == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				जाओ out;
			} अन्यथा अगर (len != 1) {
				oerrno = त्रुटि_सं;
				error_f("read: %.100s", म_त्रुटि(त्रुटि_सं));
				r = SSH_ERR_SYSTEM_ERROR;
				जाओ out;
			}
			अगर (c == '\r') {
				expect_nl = 1;
				जारी;
			}
			अगर (c == '\n')
				अवरोध;
			अगर (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				जाओ invalid;
			}
			अगर ((r = sshbuf_put_u8(peer_version, c)) != 0) {
				oerrno = त्रुटि_सं;
				error_fr(r, "sshbuf_put");
				जाओ out;
			}
			अगर (sshbuf_len(peer_version) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				जाओ invalid;
			}
		}
		/* Is this an actual protocol banner? */
		अगर (sshbuf_len(peer_version) > 4 &&
		    स_भेद(sshbuf_ptr(peer_version), "SSH-", 4) == 0)
			अवरोध;
		/* If not, then just log the line and continue */
		अगर ((cp = sshbuf_dup_string(peer_version)) == शून्य) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		/* Do not accept lines before the SSH ident from a client */
		अगर (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			मुक्त(cp);
			जाओ invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		मुक्त(cp);
	}
	peer_version_string = sshbuf_dup_string(peer_version);
	अगर (peer_version_string == शून्य)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	अगर ((remote_version = सुस्मृति(1, sshbuf_len(peer_version))) == शून्य) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	अगर (माला_पूछो(peer_version_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		error("Bad remote protocol version identification: '%.100s'",
		    peer_version_string);
 invalid:
		send_error(ssh, "Invalid SSH identification string.");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);
	compat_banner(ssh, remote_version);

	mismatch = 0;
	चयन (remote_major) {
	हाल 2:
		अवरोध;
	हाल 1:
		अगर (remote_minor != 99)
			mismatch = 1;
		अवरोध;
	शेष:
		mismatch = 1;
		अवरोध;
	}
	अगर (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_VERSION;
		जाओ out;
	}

	अगर (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		जाओ out;
	}
	अगर (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
		logit("scanned from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		जाओ out;
	}
	/* success */
	r = 0;
 out:
	मुक्त(our_version_string);
	मुक्त(peer_version_string);
	ssh->remote_version = remote_version;  /* transferred */
	अगर (r == SSH_ERR_SYSTEM_ERROR)
		त्रुटि_सं = oerrno;
	वापस r;
}

