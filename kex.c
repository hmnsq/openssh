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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/crypto.h>
#અન્તર્ભાવ <openssl/dh.h>
#endif

#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "ssh2.h"
#અન્તર્ભાવ "atomicio.h"
#અન્તર્ભાવ "version.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "compat.h"
#અન્તર્ભાવ "cipher.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "kex.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "mac.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "dispatch.h"
#અન્તર્ભાવ "myproposal.h"

#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "digest.h"
#અન્તર્ભાવ "xmalloc.h"

/* prototype */
સ્થિર પૂર્ણાંક kex_choose_conf(સંરચના ssh *, uint32_t seq);
સ્થિર પૂર્ણાંક kex_આગત_newkeys(પૂર્ણાંક, uint32_t, સંરચના ssh *);

સ્થિર અચલ અક્ષર * અચલ proposal_names[PROPOSAL_MAX] = {
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
શૂન્ય
kex_proposal_populate_entries(સંરચના ssh *ssh, અક્ષર *prop[PROPOSAL_MAX],
    અચલ અક્ષર *kexalgos, અચલ અક્ષર *ciphers, અચલ અક્ષર *macs,
    અચલ અક્ષર *comp, અચલ અક્ષર *hkalgs)
{
	અચલ અક્ષર *defpropserver[PROPOSAL_MAX] = { KEX_SERVER };
	અચલ અક્ષર *defpropclient[PROPOSAL_MAX] = { KEX_CLIENT };
	અચલ અક્ષર **defprop = ssh->kex->server ? defpropserver : defpropclient;
	u_int i;
	અક્ષર *cp;

	જો (prop == ખાલી)
		fatal_f("proposal missing");

	/* Append EXT_INFO signalling to KexAlgorithms */
	જો (kexalgos == ખાલી)
		kexalgos = defprop[PROPOSAL_KEX_ALGS];
	જો ((cp = kex_names_cat(kexalgos, ssh->kex->server ?
	    "ext-info-s,kex-strict-s-v00@openssh.com" :
	    "ext-info-c,kex-strict-c-v00@openssh.com")) == ખાલી)
		fatal_f("kex_names_cat");

	માટે (i = 0; i < PROPOSAL_MAX; i++) {
		પસંદગી(i) {
		સ્થિતિ PROPOSAL_KEX_ALGS:
			prop[i] = compat_kex_proposal(ssh, cp);
			તોડો;
		સ્થિતિ PROPOSAL_ENC_ALGS_CTOS:
		સ્થિતિ PROPOSAL_ENC_ALGS_STOC:
			prop[i] = xstrdup(ciphers ? ciphers : defprop[i]);
			તોડો;
		સ્થિતિ PROPOSAL_MAC_ALGS_CTOS:
		સ્થિતિ PROPOSAL_MAC_ALGS_STOC:
			prop[i]  = xstrdup(macs ? macs : defprop[i]);
			તોડો;
		સ્થિતિ PROPOSAL_COMP_ALGS_CTOS:
		સ્થિતિ PROPOSAL_COMP_ALGS_STOC:
			prop[i] = xstrdup(comp ? comp : defprop[i]);
			તોડો;
		સ્થિતિ PROPOSAL_SERVER_HOST_ચાવી_ALGS:
			prop[i] = xstrdup(hkalgs ? hkalgs : defprop[i]);
			તોડો;
		મૂળભૂત:
			prop[i] = xstrdup(defprop[i]);
		}
	}
	મુક્ત(cp);
}

શૂન્ય
kex_proposal_free_entries(અક્ષર *prop[PROPOSAL_MAX])
{
	u_int i;

	માટે (i = 0; i < PROPOSAL_MAX; i++)
		મુક્ત(prop[i]);
}

/* put algorithm proposal into buffer */
પૂર્ણાંક
kex_prop2buf(સંરચના sshbuf *b, અક્ષર *proposal[PROPOSAL_MAX])
{
	u_int i;
	પૂર્ણાંક r;

	sshbuf_reset(b);

	/*
	 * add a dummy cookie, the cookie will be overwritten by
	 * kex_send_kexinit(), each time a kexinit is set
	 */
	માટે (i = 0; i < KEX_COOKIE_LEN; i++) {
		જો ((r = sshbuf_put_u8(b, 0)) != 0)
			પાછા r;
	}
	માટે (i = 0; i < PROPOSAL_MAX; i++) {
		જો ((r = sshbuf_put_cstring(b, proposal[i])) != 0)
			પાછા r;
	}
	જો ((r = sshbuf_put_u8(b, 0)) != 0 ||	/* first_kex_packet_follows */
	    (r = sshbuf_put_u32(b, 0)) != 0)	/* uint32 reserved */
		પાછા r;
	પાછા 0;
}

/* parse buffer and return algorithm proposal */
પૂર્ણાંક
kex_buf2prop(સંરચના sshbuf *raw, પૂર્ણાંક *first_kex_follows, અક્ષર ***propp)
{
	સંરચના sshbuf *b = ખાલી;
	u_char v;
	u_int i;
	અક્ષર **proposal = ખાલી;
	પૂર્ણાંક r;

	*propp = ખાલી;
	જો ((proposal = calloc(PROPOSAL_MAX, કદ(અક્ષર *))) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((b = sshbuf_fromb(raw)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshbuf_consume(b, KEX_COOKIE_LEN)) != 0) { /* skip cookie */
		error_fr(r, "consume cookie");
		જાઓ out;
	}
	/* extract kex init proposal strings */
	માટે (i = 0; i < PROPOSAL_MAX; i++) {
		જો ((r = sshbuf_get_cstring(b, &(proposal[i]), ખાલી)) != 0) {
			error_fr(r, "parse proposal %u", i);
			જાઓ out;
		}
		debug2("%s: %s", proposal_names[i], proposal[i]);
	}
	/* first kex follows / reserved */
	જો ((r = sshbuf_get_u8(b, &v)) != 0 ||	/* first_kex_follows */
	    (r = sshbuf_get_u32(b, &i)) != 0) {	/* reserved */
		error_fr(r, "parse");
		જાઓ out;
	}
	જો (first_kex_follows != ખાલી)
		*first_kex_follows = v;
	debug2("first_kex_follows %d ", v);
	debug2("reserved %u ", i);
	r = 0;
	*propp = proposal;
 out:
	જો (r != 0 && proposal != ખાલી)
		kex_prop_free(proposal);
	sshbuf_free(b);
	પાછા r;
}

શૂન્ય
kex_prop_free(અક્ષર **proposal)
{
	u_int i;

	જો (proposal == ખાલી)
		પાછા;
	માટે (i = 0; i < PROPOSAL_MAX; i++)
		મુક્ત(proposal[i]);
	મુક્ત(proposal);
}

પૂર્ણાંક
kex_protocol_error(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	પૂર્ણાંક r;

	/* If in strict mode, any unexpected message is an error */
	જો ((ssh->kex->flags & KEX_INITIAL) && ssh->kex->kex_strict) {
		ssh_packet_disconnect(ssh, "strict KEX violation: "
		    "unexpected packet type %u (seqnr %u)", type, seq);
	}
	error_f("type %u seq %u", type, seq);
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_UNIMPLEMENTED)) != 0 ||
	    (r = sshpkt_put_u32(ssh, seq)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		પાછા r;
	પાછા 0;
}

સ્થિર શૂન્ય
kex_reset_dispatch(સંરચના ssh *ssh)
{
	ssh_dispatch_range(ssh, SSH2_સંદેશ_TRANSPORT_MIN,
	    SSH2_સંદેશ_TRANSPORT_MAX, &kex_protocol_error);
}

શૂન્ય
kex_set_server_sig_algs(સંરચના ssh *ssh, અચલ અક્ષર *allowed_algs)
{
	અક્ષર *alg, *oalgs, *algs, *sigalgs;
	અચલ અક્ષર *sigalg;

	/*
	 * NB. allowed algorithms may contain certificate algorithms that
	 * map to a specific plain signature type, e.g.
	 * rsa-sha2-512-cert-v01@openssh.com => rsa-sha2-512
	 * We need to be careful here to match these, retain the mapping
	 * and only add each signature algorithm once.
	 */
	જો ((sigalgs = sshkey_alg_list(0, 1, 1, ',')) == ખાલી)
		fatal_f("sshkey_alg_list failed");
	oalgs = algs = xstrdup(allowed_algs);
	મુક્ત(ssh->kex->server_sig_algs);
	ssh->kex->server_sig_algs = ખાલી;
	માટે ((alg = strsep(&algs, ",")); alg != ખાલી && *alg != '\0';
	    (alg = strsep(&algs, ","))) {
		જો ((sigalg = sshkey_sigalg_by_name(alg)) == ખાલી)
			ચાલુ;
		જો (!kex_has_any_alg(sigalg, sigalgs))
			ચાલુ;
		/* Don't add an algorithm twice. */
		જો (ssh->kex->server_sig_algs != ખાલી &&
		    kex_has_any_alg(sigalg, ssh->kex->server_sig_algs))
			ચાલુ;
		xextendf(&ssh->kex->server_sig_algs, ",", "%s", sigalg);
	}
	મુક્ત(oalgs);
	મુક્ત(sigalgs);
	જો (ssh->kex->server_sig_algs == ખાલી)
		ssh->kex->server_sig_algs = xstrdup("");
}

શૂન્ય
kex_set_warn_weak_crypto(સંરચના ssh *ssh, પૂર્ણાંક warn_weak_crypto)
{
	જો (ssh != ખાલી && ssh->kex != ખાલી)
		ssh->kex->warn_weak_crypto = warn_weak_crypto != 0;
}

શૂન્ય
kex_check_warn_weak_crypto(સંરચના ssh *ssh)
{
	અક્ષર remote_id[512];
	પૂર્ણાંક rekeyed = 0;

	જો (ssh == ખાલી || ssh->kex == ખાલી || ssh->kex->name == ખાલી ||
	    !ssh->kex->warn_weak_crypto || ssh->kex->non_pq_kex_warned)
		પાછા;
	જો (kex_is_pq_from_name(ssh->kex->name)) {
		ssh->kex->pq_kex_negotiated = 1;
		પાછા;
	}

	જો (ssh->kex->pq_kex_negotiated)
		rekeyed = 1;
	જો (!rekeyed && !ssh->kex->server)
		પાછા; /* client logs initial KEX warning separately */

	sshpkt_fmt_connection_id(ssh, remote_id, કદ(remote_id));
	logit("WARNING: %sconnection%s%s is not using a post-quantum "
	    "key exchange algorithm: \"%s\"", rekeyed ? "rekeyed " : "",
	    ssh->kex->server ? " from " : "",
	    ssh->kex->server ? remote_id : "", ssh->kex->name);
	ssh->kex->non_pq_kex_warned = 1;
}

સ્થિર પૂર્ણાંક
kex_compose_ext_info_server(સંરચના ssh *ssh, સંરચના sshbuf *m)
{
	પૂર્ણાંક r;

	જો (ssh->kex->server_sig_algs == ખાલી &&
	    (ssh->kex->server_sig_algs = sshkey_alg_list(0, 1, 1, ',')) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_put_u32(m, 4)) != 0 ||
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
		પાછા r;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
kex_compose_ext_info_client(સંરચના ssh *ssh, સંરચના sshbuf *m)
{
	પૂર્ણાંક r;

	જો ((r = sshbuf_put_u32(m, 1)) != 0 ||
	    (r = sshbuf_put_cstring(m, "ext-info-in-auth@openssh.com")) != 0 ||
	    (r = sshbuf_put_cstring(m, "0")) != 0) {
		error_fr(r, "compose");
		જાઓ out;
	}
	/* success */
	r = 0;
 out:
	પાછા r;
}

સ્થિર પૂર્ણાંક
kex_maybe_send_ext_info(સંરચના ssh *ssh)
{
	પૂર્ણાંક r;
	સંરચના sshbuf *m = ખાલી;

	જો ((ssh->kex->flags & KEX_INITIAL) == 0)
		પાછા 0;
	જો (!ssh->kex->ext_info_c && !ssh->kex->ext_info_s)
		પાછા 0;

	/* Compose EXT_INFO packet. */
	જો ((m = sshbuf_new()) == ખાલી)
		fatal_f("sshbuf_new failed");
	જો (ssh->kex->ext_info_c &&
	    (r = kex_compose_ext_info_server(ssh, m)) != 0)
		જાઓ fail;
	જો (ssh->kex->ext_info_s &&
	    (r = kex_compose_ext_info_client(ssh, m)) != 0)
		જાઓ fail;

	/* Send the actual KEX_INFO packet */
	debug("Sending SSH2_MSG_EXT_INFO");
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_EXT_INFO)) != 0 ||
	    (r = sshpkt_putb(ssh, m)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		જાઓ fail;
	}

	r = 0;

 fail:
	sshbuf_free(m);
	પાછા r;
}

પૂર્ણાંક
kex_server_update_ext_info(સંરચના ssh *ssh)
{
	પૂર્ણાંક r;

	જો ((ssh->kex->flags & KEX_HAS_EXT_INFO_IN_AUTH) == 0)
		પાછા 0;

	debug_f("Sending SSH2_MSG_EXT_INFO");
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_EXT_INFO)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "server-sig-algs")) != 0 ||
	    (r = sshpkt_put_cstring(ssh, ssh->kex->server_sig_algs)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_f("send EXT_INFO");
		પાછા r;
	}
	પાછા 0;
}

પૂર્ણાંક
kex_send_newkeys(સંરચના ssh *ssh)
{
	પૂર્ણાંક r;

	kex_reset_dispatch(ssh);
	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_NEWKEYS)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		પાછા r;
	debug("SSH2_MSG_NEWKEYS sent");
	ssh_dispatch_set(ssh, SSH2_સંદેશ_NEWKEYS, &kex_આગત_newkeys);
	જો ((r = kex_maybe_send_ext_info(ssh)) != 0)
		પાછા r;
	debug("expecting SSH2_MSG_NEWKEYS");
	પાછા 0;
}

/* Check whether an ext_info value contains the expected version string */
સ્થિર પૂર્ણાંક
kex_ext_info_check_ver(સંરચના kex *kex, અચલ અક્ષર *name,
    અચલ u_char *val, size_t len, અચલ અક્ષર *want_ver, u_int flag)
{
	જો (memchr(val, '\0', len) != ખાલી) {
		error("SSH2_MSG_EXT_INFO: %s value contains nul byte", name);
		પાછા SSH_ERR_INVALID_FORMAT;
	}
	debug_f("%s=<%s>", name, val);
	જો (strcmp(val, want_ver) == 0)
		kex->flags |= flag;
	નહીંતર
		debug_f("unsupported version of %s extension", name);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
kex_ext_info_client_parse(સંરચના ssh *ssh, અચલ અક્ષર *name,
    અચલ u_char *કિંમત, size_t vlen)
{
	પૂર્ણાંક r;

	/* NB. some messages are only accepted in the initial EXT_INFO */
	જો (strcmp(name, "server-sig-algs") == 0) {
		/* Ensure no \0 lurking in value */
		જો (memchr(કિંમત, '\0', vlen) != ખાલી) {
			error_f("nul byte in %s", name);
			પાછા SSH_ERR_INVALID_FORMAT;
		}
		debug_f("%s=<%s>", name, કિંમત);
		મુક્ત(ssh->kex->server_sig_algs);
		ssh->kex->server_sig_algs = xstrdup((અચલ અક્ષર *)કિંમત);
	} નહીંતર જો (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "publickey-hostbound@openssh.com") == 0) {
		જો ((r = kex_ext_info_check_ver(ssh->kex, name, કિંમત, vlen,
		    "0", KEX_HAS_PUBKEY_HOSTBOUND)) != 0) {
			પાછા r;
		}
	} નહીંતર જો (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "ping@openssh.com") == 0) {
		જો ((r = kex_ext_info_check_ver(ssh->kex, name, કિંમત, vlen,
		    "0", KEX_HAS_PING)) != 0) {
			પાછા r;
		}
	} નહીંતર જો (ssh->kex->ext_info_received == 1 &&
	    strcmp(name, "agent-forward") == 0) {
		જો ((r = kex_ext_info_check_ver(ssh->kex, name, કિંમત, vlen,
		    "0", KEX_HAS_NEWAGENT)) != 0) {
			પાછા r;
		}
	} નહીંતર
		debug_f("%s (unrecognised)", name);

	પાછા 0;
}

સ્થિર પૂર્ણાંક
kex_ext_info_server_parse(સંરચના ssh *ssh, અચલ અક્ષર *name,
    અચલ u_char *કિંમત, size_t vlen)
{
	પૂર્ણાંક r;

	જો (strcmp(name, "ext-info-in-auth@openssh.com") == 0) {
		જો ((r = kex_ext_info_check_ver(ssh->kex, name, કિંમત, vlen,
		    "0", KEX_HAS_EXT_INFO_IN_AUTH)) != 0) {
			પાછા r;
		}
	} નહીંતર
		debug_f("%s (unrecognised)", name);
	પાછા 0;
}

પૂર્ણાંક
kex_આગત_ext_info(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	સંરચના kex *kex = ssh->kex;
	અચલ પૂર્ણાંક max_ext_info = kex->server ? 1 : 2;
	uint32_t i, ninfo;
	અક્ષર *name;
	u_char *val;
	size_t vlen;
	પૂર્ણાંક r;

	debug("SSH2_MSG_EXT_INFO received");
	જો (++kex->ext_info_received > max_ext_info) {
		error("too many SSH2_MSG_EXT_INFO messages sent by peer");
		પાછા dispatch_protocol_error(type, seq, ssh);
	}
	ssh_dispatch_set(ssh, SSH2_સંદેશ_EXT_INFO, &kex_protocol_error);
	જો ((r = sshpkt_get_u32(ssh, &ninfo)) != 0)
		પાછા r;
	જો (ninfo >= 1024) {
		error("SSH2_MSG_EXT_INFO with too many entries, expected "
		    "<=1024, received %u", ninfo);
		પાછા dispatch_protocol_error(type, seq, ssh);
	}
	માટે (i = 0; i < ninfo; i++) {
		જો ((r = sshpkt_get_cstring(ssh, &name, ખાલી)) != 0)
			પાછા r;
		જો ((r = sshpkt_get_string(ssh, &val, &vlen)) != 0) {
			મુક્ત(name);
			પાછા r;
		}
		debug3_f("extension %s", name);
		જો (kex->server) {
			જો ((r = kex_ext_info_server_parse(ssh, name,
			    val, vlen)) != 0)
				પાછા r;
		} નહીંતર {
			જો ((r = kex_ext_info_client_parse(ssh, name,
			    val, vlen)) != 0)
				પાછા r;
		}
		મુક્ત(name);
		મુક્ત(val);
	}
	પાછા sshpkt_get_end(ssh);
}

સ્થિર પૂર્ણાંક
kex_આગત_newkeys(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	સંરચના kex *kex = ssh->kex;
	પૂર્ણાંક r, initial = (kex->flags & KEX_INITIAL) != 0;
	અક્ષર *cp, **prop;

	debug("SSH2_MSG_NEWKEYS received");
	જો (kex->ext_info_c && initial)
		ssh_dispatch_set(ssh, SSH2_સંદેશ_EXT_INFO, &kex_આગત_ext_info);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_NEWKEYS, &kex_protocol_error);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_KEXINIT, &kex_આગત_kexinit);
	જો ((r = sshpkt_get_end(ssh)) != 0)
		પાછા r;
	જો ((r = ssh_set_newkeys(ssh, MODE_IN)) != 0)
		પાછા r;
	જો (initial) {
		/* Remove initial KEX signalling from proposal for rekeying */
		જો ((r = kex_buf2prop(kex->my, ખાલી, &prop)) != 0)
			પાછા r;
		જો ((cp = match_filter_denylist(prop[PROPOSAL_KEX_ALGS],
		    kex->server ?
		    "ext-info-s,kex-strict-s-v00@openssh.com" :
		    "ext-info-c,kex-strict-c-v00@openssh.com")) == ખાલી) {
			error_f("match_filter_denylist failed");
			જાઓ fail;
		}
		મુક્ત(prop[PROPOSAL_KEX_ALGS]);
		prop[PROPOSAL_KEX_ALGS] = cp;
		જો ((r = kex_prop2buf(ssh->kex->my, prop)) != 0) {
			error_f("kex_prop2buf failed");
 fail:
			kex_proposal_free_entries(prop);
			મુક્ત(prop);
			પાછા SSH_ERR_INTERNAL_ERROR;
		}
		kex_proposal_free_entries(prop);
		મુક્ત(prop);
	}
	kex->done = 1;
	kex->flags &= ~KEX_INITIAL;
	sshbuf_reset(kex->peer);
	kex->flags &= ~(KEX_INIT_SENT|KEX_INIT_RECVD);
	kex_check_warn_weak_crypto(ssh);
	પાછા 0;
}

પૂર્ણાંક
kex_send_kexinit(સંરચના ssh *ssh)
{
	u_char *cookie;
	સંરચના kex *kex = ssh->kex;
	પૂર્ણાંક r;

	જો (kex == ખાલી) {
		error_f("no kex");
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	જો (kex->flags & KEX_INIT_SENT)
		પાછા 0;
	kex->done = 0;

	/* generate a random cookie */
	જો (sshbuf_len(kex->my) < KEX_COOKIE_LEN) {
		error_f("bad kex length: %zu < %d",
		    sshbuf_len(kex->my), KEX_COOKIE_LEN);
		પાછા SSH_ERR_INVALID_FORMAT;
	}
	જો ((cookie = sshbuf_mutable_ptr(kex->my)) == ખાલી) {
		error_f("buffer error");
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	arc4random_buf(cookie, KEX_COOKIE_LEN);

	જો ((r = sshpkt_start(ssh, SSH2_સંદેશ_KEXINIT)) != 0 ||
	    (r = sshpkt_putb(ssh, kex->my)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "compose reply");
		પાછા r;
	}
	debug("SSH2_MSG_KEXINIT sent");
	kex->flags |= KEX_INIT_SENT;
	પાછા 0;
}

પૂર્ણાંક
kex_આગત_kexinit(પૂર્ણાંક type, uint32_t seq, સંરચના ssh *ssh)
{
	સંરચના kex *kex = ssh->kex;
	અચલ u_char *ptr;
	u_int i;
	size_t dlen;
	પૂર્ણાંક r;

	debug("SSH2_MSG_KEXINIT received");
	જો (kex == ખાલી) {
		error_f("no kex");
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	મુક્ત(kex->name);
	kex->name = ખાલી;
	જો ((kex->flags & KEX_INIT_RECVD) != 0) {
		ssh_packet_disconnect(ssh,
		    "multiple KEXINIT received from peer");
	}
	kex->flags |= KEX_INIT_RECVD;
	ssh_dispatch_set(ssh, SSH2_સંદેશ_KEXINIT, &kex_protocol_error);
	ptr = sshpkt_ptr(ssh, &dlen);
	જો ((r = sshbuf_put(kex->peer, ptr, dlen)) != 0)
		પાછા r;

	/* discard packet */
	માટે (i = 0; i < KEX_COOKIE_LEN; i++) {
		જો ((r = sshpkt_get_u8(ssh, ખાલી)) != 0) {
			error_fr(r, "discard cookie");
			પાછા r;
		}
	}
	માટે (i = 0; i < PROPOSAL_MAX; i++) {
		જો ((r = sshpkt_get_string(ssh, ખાલી, ખાલી)) != 0) {
			error_fr(r, "discard proposal");
			પાછા r;
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
	જો ((r = sshpkt_get_u8(ssh, ખાલી)) != 0 ||	/* first_kex_follows */
	    (r = sshpkt_get_u32(ssh, ખાલી)) != 0 ||	/* reserved */
	    (r = sshpkt_get_end(ssh)) != 0)
			પાછા r;

	જો (!(kex->flags & KEX_INIT_SENT))
		જો ((r = kex_send_kexinit(ssh)) != 0)
			પાછા r;
	જો ((r = kex_choose_conf(ssh, seq)) != 0)
		પાછા r;

	જો (kex->kex_type < KEX_MAX && kex->kex[kex->kex_type] != ખાલી)
		પાછા (kex->kex[kex->kex_type])(ssh);

	error_f("unknown kex type %u", kex->kex_type);
	પાછા SSH_ERR_INTERNAL_ERROR;
}

સંરચના kex *
kex_new(શૂન્ય)
{
	સંરચના kex *kex;

	જો ((kex = calloc(1, કદ(*kex))) == ખાલી ||
	    (kex->peer = sshbuf_new()) == ખાલી ||
	    (kex->my = sshbuf_new()) == ખાલી ||
	    (kex->client_version = sshbuf_new()) == ખાલી ||
	    (kex->server_version = sshbuf_new()) == ખાલી ||
	    (kex->session_id = sshbuf_new()) == ખાલી) {
		kex_free(kex);
		પાછા ખાલી;
	}
	પાછા kex;
}

શૂન્ય
kex_free_newkeys(સંરચના newkeys *newkeys)
{
	જો (newkeys == ખાલી)
		પાછા;
	જો (newkeys->enc.ચાવી) {
		explicit_bzero(newkeys->enc.ચાવી, newkeys->enc.ચાવી_len);
		મુક્ત(newkeys->enc.ચાવી);
		newkeys->enc.ચાવી = ખાલી;
	}
	જો (newkeys->enc.iv) {
		explicit_bzero(newkeys->enc.iv, newkeys->enc.iv_len);
		મુક્ત(newkeys->enc.iv);
		newkeys->enc.iv = ખાલી;
	}
	મુક્ત(newkeys->enc.name);
	explicit_bzero(&newkeys->enc, કદ(newkeys->enc));
	મુક્ત(newkeys->comp.name);
	explicit_bzero(&newkeys->comp, કદ(newkeys->comp));
	mac_clear(&newkeys->mac);
	જો (newkeys->mac.ચાવી) {
		explicit_bzero(newkeys->mac.ચાવી, newkeys->mac.ચાવી_len);
		મુક્ત(newkeys->mac.ચાવી);
		newkeys->mac.ચાવી = ખાલી;
	}
	મુક્ત(newkeys->mac.name);
	explicit_bzero(&newkeys->mac, કદ(newkeys->mac));
	freezero(newkeys, કદ(*newkeys));
}

શૂન્ય
kex_free(સંરચના kex *kex)
{
	u_int mode;

	જો (kex == ખાલી)
		પાછા;

#ifdef WITH_OPENSSL
	DH_free(kex->dh);
	EC_ચાવી_free(kex->ec_client_ચાવી);
#endif /* WITH_OPENSSL */
	માટે (mode = 0; mode < MODE_MAX; mode++) {
		kex_free_newkeys(kex->newkeys[mode]);
		kex->newkeys[mode] = ખાલી;
	}
	sshbuf_free(kex->peer);
	sshbuf_free(kex->my);
	sshbuf_free(kex->client_version);
	sshbuf_free(kex->server_version);
	sshbuf_free(kex->client_pub);
	sshbuf_free(kex->session_id);
	sshbuf_free(kex->initial_sig);
	sshkey_free(kex->initial_hostkey);
	મુક્ત(kex->failed_choice);
	મુક્ત(kex->hostkey_alg);
	મુક્ત(kex->name);
	મુક્ત(kex->server_sig_algs);
	મુક્ત(kex);
}

પૂર્ણાંક
kex_ready(સંરચના ssh *ssh, અક્ષર *proposal[PROPOSAL_MAX])
{
	પૂર્ણાંક r;

	જો ((r = kex_prop2buf(ssh->kex->my, proposal)) != 0)
		પાછા r;
	ssh->kex->flags = KEX_INITIAL;
	kex_reset_dispatch(ssh);
	ssh_dispatch_set(ssh, SSH2_સંદેશ_KEXINIT, &kex_આગત_kexinit);
	પાછા 0;
}

પૂર્ણાંક
kex_setup(સંરચના ssh *ssh, અક્ષર *proposal[PROPOSAL_MAX])
{
	પૂર્ણાંક r;

	જો ((r = kex_ready(ssh, proposal)) != 0)
		પાછા r;
	જો ((r = kex_send_kexinit(ssh)) != 0) {		/* we start */
		kex_free(ssh->kex);
		ssh->kex = ખાલી;
		પાછા r;
	}
	પાછા 0;
}

/*
 * Request key re-exchange, returns 0 on success or a ssherr.h error
 * code otherwise. Must not be called if KEX is incomplete or in-progress.
 */
પૂર્ણાંક
kex_start_rekex(સંરચના ssh *ssh)
{
	જો (ssh->kex == ખાલી) {
		error_f("no kex");
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	જો (ssh->kex->done == 0) {
		error_f("requested twice");
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	ssh->kex->done = 0;
	પાછા kex_send_kexinit(ssh);
}

સ્થિર પૂર્ણાંક
choose_enc(સંરચના sshenc *enc, અક્ષર *client, અક્ષર *server)
{
	અક્ષર *name = match_list(client, server, ખાલી);

	જો (name == ખાલી)
		પાછા SSH_ERR_NO_CIPHER_ALG_MATCH;
	જો ((enc->cipher = cipher_by_name(name)) == ખાલી) {
		error_f("unsupported cipher %s", name);
		મુક્ત(name);
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	enc->name = name;
	enc->enabled = 0;
	enc->iv = ખાલી;
	enc->iv_len = cipher_ivlen(enc->cipher);
	enc->ચાવી = ખાલી;
	enc->ચાવી_len = cipher_keylen(enc->cipher);
	enc->block_size = cipher_blocksize(enc->cipher);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
choose_mac(સંરચના ssh *ssh, સંરચના sshmac *mac, અક્ષર *client, અક્ષર *server)
{
	અક્ષર *name = match_list(client, server, ખાલી);

	જો (name == ખાલી)
		પાછા SSH_ERR_NO_MAC_ALG_MATCH;
	જો (mac_setup(mac, name) < 0) {
		error_f("unsupported MAC %s", name);
		મુક્ત(name);
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	mac->name = name;
	mac->ચાવી = ખાલી;
	mac->enabled = 0;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
choose_comp(સંરચના sshcomp *comp, અક્ષર *client, અક્ષર *server)
{
	અક્ષર *name = match_list(client, server, ખાલી);

	જો (name == ખાલી)
		પાછા SSH_ERR_NO_COMPRESS_ALG_MATCH;
#ifdef WITH_ZLIB
	જો (strcmp(name, "zlib@openssh.com") == 0) {
		comp->type = COMP_DELAYED;
	} નહીંતર
#endif	/* WITH_ZLIB */
	જો (strcmp(name, "none") == 0) {
		comp->type = COMP_NONE;
	} નહીંતર {
		error_f("unsupported compression scheme %s", name);
		મુક્ત(name);
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	comp->name = name;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
choose_kex(સંરચના kex *k, અક્ષર *client, અક્ષર *server)
{
	k->name = match_list(client, server, ખાલી);

	debug("kex: algorithm: %s", k->name ? k->name : "(no match)");
	જો (k->name == ખાલી)
		પાછા SSH_ERR_NO_KEX_ALG_MATCH;
	જો (!kex_name_valid(k->name)) {
		error_f("unsupported KEX method %s", k->name);
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	k->kex_type = kex_type_from_name(k->name);
	k->hash_alg = kex_hash_from_name(k->name);
	k->ec_nid = kex_nid_from_name(k->name);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
choose_hostkeyalg(સંરચના kex *k, અક્ષર *client, અક્ષર *server)
{
	મુક્ત(k->hostkey_alg);
	k->hostkey_alg = match_list(client, server, ખાલી);

	debug("kex: host key algorithm: %s",
	    k->hostkey_alg ? k->hostkey_alg : "(no match)");
	જો (k->hostkey_alg == ખાલી)
		પાછા SSH_ERR_NO_HOSTKEY_ALG_MATCH;
	k->hostkey_type = sshkey_type_from_name(k->hostkey_alg);
	જો (k->hostkey_type == ચાવી_UNSPEC) {
		error_f("unsupported hostkey algorithm %s", k->hostkey_alg);
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	k->hostkey_nid = sshkey_ecdsa_nid_from_name(k->hostkey_alg);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
proposals_match(અક્ષર *my[PROPOSAL_MAX], અક્ષર *peer[PROPOSAL_MAX])
{
	સ્થિર પૂર્ણાંક check[] = {
		PROPOSAL_KEX_ALGS, PROPOSAL_SERVER_HOST_ચાવી_ALGS, -1
	};
	પૂર્ણાંક *idx;
	અક્ષર *p;

	માટે (idx = &check[0]; *idx != -1; idx++) {
		જો ((p = strchr(my[*idx], ',')) != ખાલી)
			*p = '\0';
		જો ((p = strchr(peer[*idx], ',')) != ખાલી)
			*p = '\0';
		જો (strcmp(my[*idx], peer[*idx]) != 0) {
			debug2("proposal mismatch: my %s peer %s",
			    my[*idx], peer[*idx]);
			પાછા (0);
		}
	}
	debug2("proposals match");
	પાછા (1);
}

સ્થિર પૂર્ણાંક
kexalgs_contains(અક્ષર **peer, અચલ અક્ષર *ext)
{
	પાછા kex_has_any_alg(peer[PROPOSAL_KEX_ALGS], ext);
}

સ્થિર પૂર્ણાંક
kex_choose_conf(સંરચના ssh *ssh, uint32_t seq)
{
	સંરચના kex *kex = ssh->kex;
	સંરચના newkeys *newkeys;
	અક્ષર **my = ખાલી, **peer = ખાલી;
	અક્ષર **cprop, **sprop;
	પૂર્ણાંક nenc, nmac, ncomp;
	u_int mode, ctos, need, dh_need, authlen;
	પૂર્ણાંક r, first_kex_follows;

	debug2("local %s KEXINIT proposal", kex->server ? "server" : "client");
	જો ((r = kex_buf2prop(kex->my, ખાલી, &my)) != 0)
		જાઓ out;
	debug2("peer %s KEXINIT proposal", kex->server ? "client" : "server");
	જો ((r = kex_buf2prop(kex->peer, &first_kex_follows, &peer)) != 0)
		જાઓ out;

	જો (kex->server) {
		cprop=peer;
		sprop=my;
	} નહીંતર {
		cprop=my;
		sprop=peer;
	}

	/* Check whether peer supports ext_info/kex_strict */
	જો ((kex->flags & KEX_INITIAL) != 0) {
		જો (kex->server) {
			kex->ext_info_c = kexalgs_contains(peer, "ext-info-c");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-c-v00@openssh.com");
		} નહીંતર {
			kex->ext_info_s = kexalgs_contains(peer, "ext-info-s");
			kex->kex_strict = kexalgs_contains(peer,
			    "kex-strict-s-v00@openssh.com");
		}
		જો (kex->kex_strict) {
			debug3_f("will use strict KEX ordering");
			જો (seq != 0)
				ssh_packet_disconnect(ssh,
				    "strict KEX violation: "
				    "KEXINIT was not the first packet");
		}
	}

	/* Check whether client supports rsa-sha2 algorithms */
	જો (kex->server && (kex->flags & KEX_INITIAL)) {
		જો (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_ચાવી_ALGS],
		    "rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_256_SUPPORTED;
		જો (kex_has_any_alg(peer[PROPOSAL_SERVER_HOST_ચાવી_ALGS],
		    "rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com"))
			kex->flags |= KEX_RSA_SHA2_512_SUPPORTED;
	}

	/* Algorithm Negotiation */
	જો ((r = choose_kex(kex, cprop[PROPOSAL_KEX_ALGS],
	    sprop[PROPOSAL_KEX_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_KEX_ALGS];
		peer[PROPOSAL_KEX_ALGS] = ખાલી;
		જાઓ out;
	}
	જો ((r = choose_hostkeyalg(kex, cprop[PROPOSAL_SERVER_HOST_ચાવી_ALGS],
	    sprop[PROPOSAL_SERVER_HOST_ચાવી_ALGS])) != 0) {
		kex->failed_choice = peer[PROPOSAL_SERVER_HOST_ચાવી_ALGS];
		peer[PROPOSAL_SERVER_HOST_ચાવી_ALGS] = ખાલી;
		જાઓ out;
	}
	માટે (mode = 0; mode < MODE_MAX; mode++) {
		જો ((newkeys = calloc(1, કદ(*newkeys))) == ખાલી) {
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		kex->newkeys[mode] = newkeys;
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		nenc  = ctos ? PROPOSAL_ENC_ALGS_CTOS  : PROPOSAL_ENC_ALGS_STOC;
		nmac  = ctos ? PROPOSAL_MAC_ALGS_CTOS  : PROPOSAL_MAC_ALGS_STOC;
		ncomp = ctos ? PROPOSAL_COMP_ALGS_CTOS : PROPOSAL_COMP_ALGS_STOC;
		જો ((r = choose_enc(&newkeys->enc, cprop[nenc],
		    sprop[nenc])) != 0) {
			kex->failed_choice = peer[nenc];
			peer[nenc] = ખાલી;
			જાઓ out;
		}
		authlen = cipher_authlen(newkeys->enc.cipher);
		/* ignore mac for authenticated encryption */
		જો (authlen == 0 &&
		    (r = choose_mac(ssh, &newkeys->mac, cprop[nmac],
		    sprop[nmac])) != 0) {
			kex->failed_choice = peer[nmac];
			peer[nmac] = ખાલી;
			જાઓ out;
		}
		જો ((r = choose_comp(&newkeys->comp, cprop[ncomp],
		    sprop[ncomp])) != 0) {
			kex->failed_choice = peer[ncomp];
			peer[ncomp] = ખાલી;
			જાઓ out;
		}
		debug("kex: %s cipher: %s MAC: %s compression: %s",
		    ctos ? "client->server" : "server->client",
		    newkeys->enc.name,
		    authlen == 0 ? newkeys->mac.name : "<implicit>",
		    newkeys->comp.name);
	}
	need = dh_need = 0;
	માટે (mode = 0; mode < MODE_MAX; mode++) {
		newkeys = kex->newkeys[mode];
		need = MAXIMUM(need, newkeys->enc.ચાવી_len);
		need = MAXIMUM(need, newkeys->enc.block_size);
		need = MAXIMUM(need, newkeys->enc.iv_len);
		need = MAXIMUM(need, newkeys->mac.ચાવી_len);
		dh_need = MAXIMUM(dh_need, cipher_seclen(newkeys->enc.cipher));
		dh_need = MAXIMUM(dh_need, newkeys->enc.block_size);
		dh_need = MAXIMUM(dh_need, newkeys->enc.iv_len);
		dh_need = MAXIMUM(dh_need, newkeys->mac.ચાવી_len);
	}
	/* XXX need runden? */
	kex->we_need = need;
	kex->dh_need = dh_need;

	/* ignore the next message if the proposals do not match */
	જો (first_kex_follows && !proposals_match(my, peer))
		ssh->dispatch_skip_packets = 1;
	r = 0;
 out:
	kex_prop_free(my);
	kex_prop_free(peer);
	પાછા r;
}

સ્થિર પૂર્ણાંક
derive_ચાવી(સંરચના ssh *ssh, પૂર્ણાંક id, u_int need, u_char *hash, u_int hashlen,
    અચલ સંરચના sshbuf *shared_secret, u_char **keyp)
{
	સંરચના kex *kex = ssh->kex;
	સંરચના ssh_digest_ctx *hashctx = ખાલી;
	અક્ષર c = id;
	u_int have;
	size_t mdsz;
	u_char *digest;
	પૂર્ણાંક r;

	જો ((mdsz = ssh_digest_bytes(kex->hash_alg)) == 0)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો ((digest = calloc(1, ROUNDUP(need, mdsz))) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}

	/* K1 = HASH(K || H || "A" || session_id) */
	જો ((hashctx = ssh_digest_start(kex->hash_alg)) == ખાલી ||
	    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
	    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
	    ssh_digest_update(hashctx, &c, 1) != 0 ||
	    ssh_digest_update_buffer(hashctx, kex->session_id) != 0 ||
	    ssh_digest_final(hashctx, digest, mdsz) != 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		error_f("KEX hash failed");
		જાઓ out;
	}
	ssh_digest_free(hashctx);
	hashctx = ખાલી;

	/*
	 * expand key:
	 * Kn = HASH(K || H || K1 || K2 || ... || Kn-1)
	 * Key = K1 || K2 || ... || Kn
	 */
	માટે (have = mdsz; need > have; have += mdsz) {
		જો ((hashctx = ssh_digest_start(kex->hash_alg)) == ખાલી ||
		    ssh_digest_update_buffer(hashctx, shared_secret) != 0 ||
		    ssh_digest_update(hashctx, hash, hashlen) != 0 ||
		    ssh_digest_update(hashctx, digest, have) != 0 ||
		    ssh_digest_final(hashctx, digest + have, mdsz) != 0) {
			error_f("KDF failed");
			r = SSH_ERR_LIBCRYPTO_ERROR;
			જાઓ out;
		}
		ssh_digest_free(hashctx);
		hashctx = ખાલી;
	}
#ifdef DEBUG_KEX
	fprintf(stderr, "key '%c'== ", c);
	dump_digest("key", digest, need);
#endif
	*keyp = digest;
	digest = ખાલી;
	r = 0;
 out:
	મુક્ત(digest);
	ssh_digest_free(hashctx);
	પાછા r;
}

#define NKEYS	6
પૂર્ણાંક
kex_derive_ચાવીઓ(સંરચના ssh *ssh, u_char *hash, u_int hashlen,
    અચલ સંરચના sshbuf *shared_secret)
{
	સંરચના kex *kex = ssh->kex;
	u_char *ચાવીઓ[NKEYS];
	u_int i, j, mode, ctos;
	પૂર્ણાંક r;

	/* save initial hash as session id */
	જો ((kex->flags & KEX_INITIAL) != 0) {
		જો (sshbuf_len(kex->session_id) != 0) {
			error_f("already have session ID at kex");
			પાછા SSH_ERR_INTERNAL_ERROR;
		}
		જો ((r = sshbuf_put(kex->session_id, hash, hashlen)) != 0)
			પાછા r;
	} નહીંતર જો (sshbuf_len(kex->session_id) == 0) {
		error_f("no session ID in rekex");
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	માટે (i = 0; i < NKEYS; i++) {
		જો ((r = derive_ચાવી(ssh, 'A'+i, kex->we_need, hash, hashlen,
		    shared_secret, &ચાવીઓ[i])) != 0) {
			માટે (j = 0; j < i; j++)
				મુક્ત(ચાવીઓ[j]);
			પાછા r;
		}
	}
	માટે (mode = 0; mode < MODE_MAX; mode++) {
		ctos = (!kex->server && mode == MODE_OUT) ||
		    (kex->server && mode == MODE_IN);
		kex->newkeys[mode]->enc.iv  = ચાવીઓ[ctos ? 0 : 1];
		kex->newkeys[mode]->enc.ચાવી = ચાવીઓ[ctos ? 2 : 3];
		kex->newkeys[mode]->mac.ચાવી = ચાવીઓ[ctos ? 4 : 5];
	}
	પાછા 0;
}

પૂર્ણાંક
kex_load_hostkey(સંરચના ssh *ssh, સંરચના sshkey **prvp, સંરચના sshkey **pubp)
{
	સંરચના kex *kex = ssh->kex;

	*pubp = ખાલી;
	*prvp = ખાલી;
	જો (kex->load_host_public_ચાવી == ખાલી ||
	    kex->load_host_private_ચાવી == ખાલી) {
		error_f("missing hostkey loader");
		પાછા SSH_ERR_INVALID_ARGUMENT;
	}
	*pubp = kex->load_host_public_ચાવી(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	*prvp = kex->load_host_private_ચાવી(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	જો (*pubp == ખાલી)
		પાછા SSH_ERR_NO_HOSTKEY_LOADED;
	પાછા 0;
}

પૂર્ણાંક
kex_verify_host_ચાવી(સંરચના ssh *ssh, સંરચના sshkey *server_host_ચાવી)
{
	સંરચના kex *kex = ssh->kex;

	જો (kex->verify_host_ચાવી == ખાલી) {
		error_f("missing hostkey verifier");
		પાછા SSH_ERR_INVALID_ARGUMENT;
	}
	જો (server_host_ચાવી->type != kex->hostkey_type ||
	    (kex->hostkey_type == ચાવી_ECDSA &&
	    server_host_ચાવી->ecdsa_nid != kex->hostkey_nid))
		પાછા SSH_ERR_ચાવી_TYPE_MISMATCH;
	જો (kex->verify_host_ચાવી(server_host_ચાવી, ssh) == -1)
		પાછા  SSH_ERR_SIGNATURE_INVALID;
	પાછા 0;
}

#જો defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
શૂન્ય
dump_digest(અચલ અક્ષર *સંદેશ, અચલ u_char *digest, પૂર્ણાંક len)
{
	fprintf(stderr, "%s\n", સંદેશ);
	sshbuf_dump_data(digest, len, stderr);
}
#endif

/*
 * Send a plaintext error message to the peer, suffixed by \r\n.
 * Only used during banner exchange, and there only for the server.
 */
સ્થિર શૂન્ય
send_error(સંરચના ssh *ssh, અક્ષર *સંદેશ)
{
	અક્ષર *crnl = "\r\n";

	જો (!ssh->kex->server)
		પાછા;

	જો (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    સંદેશ, strlen(સંદેશ)) != strlen(સંદેશ) ||
	    atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    crnl, strlen(crnl)) != strlen(crnl))
		error_f("write: %.100s", strerror(errno));
}

/*
 * Sends our identification string and waits for the peer's. Will block for
 * up to timeout_ms (or indefinitely if timeout_ms <= 0).
 * Returns on 0 success or a ssherr.h code on failure.
 */
પૂર્ણાંક
kex_exchange_identification(સંરચના ssh *ssh, પૂર્ણાંક timeout_ms,
    અચલ અક્ષર *version_addendum)
{
	પૂર્ણાંક remote_major, remote_minor, mismatch, oerrno = 0;
	size_t len, n;
	પૂર્ણાંક r, expect_nl;
	u_char c;
	સંરચના sshbuf *our_version = ssh->kex->server ?
	    ssh->kex->server_version : ssh->kex->client_version;
	સંરચના sshbuf *peer_version = ssh->kex->server ?
	    ssh->kex->client_version : ssh->kex->server_version;
	અક્ષર *our_version_string = ખાલી, *peer_version_string = ખાલી;
	અક્ષર *cp, *remote_version = ખાલી;

	/* Prepare and send our banner */
	sshbuf_reset(our_version);
	જો (version_addendum != ખાલી && *version_addendum == '\0')
		version_addendum = ખાલી;
	જો ((r = sshbuf_putf(our_version, "SSH-%d.%d-%s%s%s\r\n",
	    PROTOCOL_MAJOR_2, PROTOCOL_MINOR_2, SSH_VERSION,
	    version_addendum == ખાલી ? "" : " ",
	    version_addendum == ખાલી ? "" : version_addendum)) != 0) {
		oerrno = errno;
		error_fr(r, "sshbuf_putf");
		જાઓ out;
	}

	જો (atomicio(vwrite, ssh_packet_get_connection_out(ssh),
	    sshbuf_mutable_ptr(our_version),
	    sshbuf_len(our_version)) != sshbuf_len(our_version)) {
		oerrno = errno;
		debug_f("write: %.100s", strerror(errno));
		r = SSH_ERR_SYSTEM_ERROR;
		જાઓ out;
	}
	જો ((r = sshbuf_consume_end(our_version, 2)) != 0) { /* trim \r\n */
		oerrno = errno;
		error_fr(r, "sshbuf_consume_end");
		જાઓ out;
	}
	our_version_string = sshbuf_dup_string(our_version);
	જો (our_version_string == ખાલી) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	debug("Local version string %.100s", our_version_string);

	/* Read other side's version identification. */
	માટે (n = 0; ; n++) {
		જો (n >= SSH_MAX_PRE_BANNER_લીટીઓ) {
			send_error(ssh, "No SSH identification string "
			    "received.");
			error_f("No SSH version received in first %u lines "
			    "from server", SSH_MAX_PRE_BANNER_લીટીઓ);
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
		sshbuf_reset(peer_version);
		expect_nl = 0;
		માટે (;;) {
			જો (timeout_ms > 0) {
				r = waitrfd(ssh_packet_get_connection_in(ssh),
				    &timeout_ms, ખાલી);
				જો (r == -1 && errno == ETIMEDOUT) {
					send_error(ssh, "Timed out waiting "
					    "for SSH identification string.");
					error("Connection timed out during "
					    "banner exchange");
					r = SSH_ERR_CONN_TIMEOUT;
					જાઓ out;
				} નહીંતર જો (r == -1) {
					oerrno = errno;
					error_f("%s", strerror(errno));
					r = SSH_ERR_SYSTEM_ERROR;
					જાઓ out;
				}
			}

			len = atomicio(પઠ, ssh_packet_get_connection_in(ssh),
			    &c, 1);
			જો (len != 1 && errno == EPIPE) {
				verbose_f("Connection closed by remote host");
				r = SSH_ERR_CONN_CLOSED;
				જાઓ out;
			} નહીંતર જો (len != 1) {
				oerrno = errno;
				error_f("read: %.100s", strerror(errno));
				r = SSH_ERR_SYSTEM_ERROR;
				જાઓ out;
			}
			જો (c == '\r') {
				expect_nl = 1;
				ચાલુ;
			}
			જો (c == '\n')
				તોડો;
			જો (c == '\0' || expect_nl) {
				verbose_f("banner line contains invalid "
				    "characters");
				જાઓ invalid;
			}
			જો ((r = sshbuf_put_u8(peer_version, c)) != 0) {
				oerrno = errno;
				error_fr(r, "sshbuf_put");
				જાઓ out;
			}
			જો (sshbuf_len(peer_version) > SSH_MAX_BANNER_LEN) {
				verbose_f("banner line too long");
				જાઓ invalid;
			}
		}
		/* Is this an actual protocol banner? */
		જો (sshbuf_len(peer_version) > 4 &&
		    memcmp(sshbuf_ptr(peer_version), "SSH-", 4) == 0)
			તોડો;
		/* If not, then just log the line and continue */
		જો ((cp = sshbuf_dup_string(peer_version)) == ખાલી) {
			error_f("sshbuf_dup_string failed");
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		/* Do not accept lines before the SSH ident from a client */
		જો (ssh->kex->server) {
			verbose_f("client sent invalid protocol identifier "
			    "\"%.256s\"", cp);
			મુક્ત(cp);
			જાઓ invalid;
		}
		debug_f("banner line %zu: %s", n, cp);
		મુક્ત(cp);
	}
	peer_version_string = sshbuf_dup_string(peer_version);
	જો (peer_version_string == ખાલી)
		fatal_f("sshbuf_dup_string failed");
	/* XXX must be same size for sscanf */
	જો ((remote_version = calloc(1, sshbuf_len(peer_version))) == ખાલી) {
		error_f("calloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	જો (sscanf(peer_version_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		error("Bad remote protocol version identification: '%.100s'",
		    peer_version_string);
 invalid:
		send_error(ssh, "Invalid SSH identification string.");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	debug("Remote protocol version %d.%d, remote software version %.100s",
	    remote_major, remote_minor, remote_version);
	compat_banner(ssh, remote_version);

	mismatch = 0;
	પસંદગી (remote_major) {
	સ્થિતિ 2:
		તોડો;
	સ્થિતિ 1:
		જો (remote_minor != 99)
			mismatch = 1;
		તોડો;
	મૂળભૂત:
		mismatch = 1;
		તોડો;
	}
	જો (mismatch) {
		error("Protocol major versions differ: %d vs. %d",
		    PROTOCOL_MAJOR_2, remote_major);
		send_error(ssh, "Protocol major versions differ.");
		r = SSH_ERR_NO_PROTOCOL_VERSION;
		જાઓ out;
	}

	જો (ssh->kex->server && (ssh->compat & SSH_BUG_PROBE) != 0) {
		logit("probed from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		જાઓ out;
	}
	જો (ssh->kex->server && (ssh->compat & SSH_BUG_SCANNER) != 0) {
		logit("scanned from %s port %d with %s.  Don't panic.",
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    peer_version_string);
		r = SSH_ERR_CONN_CLOSED; /* XXX */
		જાઓ out;
	}
	/* success */
	r = 0;
 out:
	મુક્ત(our_version_string);
	મુક્ત(peer_version_string);
	ssh->remote_version = remote_version;  /* transferred */
	જો (r == SSH_ERR_SYSTEM_ERROR)
		errno = oerrno;
	પાછા r;
}

