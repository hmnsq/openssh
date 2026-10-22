/* $OpenBSD: sshconnect2.c,v 1.395 2026/10/11 20:41:20 dtucker Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2008 Damien Miller.  All rights reserved.
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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>
#ಅನ್ತರ್ಭಾವ <sys/queue.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಯದಿ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#ಅನ್ತರ್ಭಾವ <vis.h>
#endif

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh2.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "compat.h"
#ಅನ್ತರ್ಭಾವ "cipher.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "sshconnect.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "authfd.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "readconf.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "dispatch.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "msg.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "utf8.h"
#ಅನ್ತರ್ಭಾವ "ssh-sk.h"
#ಅನ್ತರ್ಭಾವ "sk-api.h"

#ifdef GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#endif

/* import */
ಬಾಹ್ಯ Options options;

/*
 * SSH2 key exchange
 */

ಸ್ಥಿರ ವರ್ಣ *xxx_host;
ಸ್ಥಿರ ಸಂರಚನಾ sockaddr_storage xxx_hostaddr;
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ ssh_conn_info *xxx_conn_info;
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಕೀಲಿ_type_allowed(ಸಂರಚನಾ sshkey *, ಧ್ರುವ ವರ್ಣ *);

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
verify_host_ಕೀಲಿ_callback(ಸಂರಚನಾ sshkey *hostkey, ಸಂರಚನಾ ssh *ssh)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshkey_check_rsa_length(hostkey,
	    options.required_rsa_size)) != 0)
		fatal_r(r, "Bad server host key");
	ಯದಿ (!ಕೀಲಿ_type_allowed(hostkey, options.hostkeyalgorithms)) {
		fatal("Server host key %s not in HostKeyAlgorithms",
		    sshkey_ssh_name(hostkey));
	}
	ಯದಿ (verify_host_ಕೀಲಿ(xxx_host, (ಸಂರಚನಾ sockaddr *)&xxx_hostaddr, hostkey,
	    xxx_conn_info) != 0)
		fatal("Host key verification failed.");
	ಪ್ರತ್ಯಾಗಮ 0;
}

/* Returns the first item from a comma-separated algorithm list */
ಸ್ಥಿರ ವರ್ಣ *
first_alg(ಧ್ರುವ ವರ್ಣ *algs)
{
	ವರ್ಣ *ret, *cp;

	ret = xstrdup(algs);
	ಯದಿ ((cp = strchr(ret, ',')) != ರಿಕ್ತ)
		*cp = '\0';
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ವರ್ಣ *
order_hostkeyalgs(ವರ್ಣ *host, ಸಂರಚನಾ sockaddr *hostaddr, u_short port,
    ಧ್ರುವ ಸಂರಚನಾ ssh_conn_info *cinfo)
{
	ವರ್ಣ *oavail = ರಿಕ್ತ, *avail = ರಿಕ್ತ, *first = ರಿಕ್ತ, *last = ರಿಕ್ತ;
	ವರ್ಣ *alg = ರಿಕ್ತ, *hostname = ರಿಕ್ತ, *ret = ರಿಕ್ತ, *best = ರಿಕ್ತ;
	size_t maxlen;
	ಸಂರಚನಾ hostkeys *hostkeys = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, port, &hostname, ರಿಕ್ತ);
	hostkeys = init_hostkeys();
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_user_hostfiles; i++)
		load_hostkeys(hostkeys, hostname, options.user_hostfiles[i], 0);
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_system_hostfiles; i++) {
		load_hostkeys(hostkeys, hostname,
		    options.system_hostfiles[i], 0);
	}
	ಯದಿ (options.known_hosts_command != ರಿಕ್ತ) {
		load_hostkeys_command(hostkeys, options.known_hosts_command,
		    "ORDER", cinfo, ರಿಕ್ತ, hostname);
	}
	/*
	 * If a plain public key exists that matches the type of the best
	 * preference HostkeyAlgorithms, then use the whole list as is.
	 * Note that we ignore whether the best preference algorithm is a
	 * certificate type, as sshconnect.c will downgrade certs to
	 * plain keys if necessary.
	 */
	best = first_alg(options.hostkeyalgorithms);
	ಯದಿ (lookup_ಕೀಲಿ_in_hostkeys_by_type(hostkeys,
	    sshkey_type_plain(sshkey_type_from_name(best)),
	    sshkey_ecdsa_nid_from_name(best), ರಿಕ್ತ)) {
		debug3_f("have matching best-preference key type %s, "
		    "using HostkeyAlgorithms verbatim", best);
		ret = xstrdup(options.hostkeyalgorithms);
		ಗಚ್ಛ out;
	}

	/*
	 * Otherwise, prefer the host key algorithms that match known keys
	 * while keeping the ordering of HostkeyAlgorithms as much as possible.
	 */
	oavail = avail = xstrdup(options.hostkeyalgorithms);
	maxlen = strlen(avail) + 1;
	first = xmalloc(maxlen);
	last = xmalloc(maxlen);
	*first = *last = '\0';

#define ALG_APPEND(to, from) \
	ಕುರು { \
		ಯದಿ (*to != '\0') \
			strlcat(to, ",", maxlen); \
		strlcat(to, from, maxlen); \
	} ಯಾವತ್ (0)

	ಯಾವತ್ ((alg = strsep(&avail, ",")) && *alg != '\0') {
		ಯದಿ ((ktype = sshkey_type_from_name(alg)) == ಕೀಲಿ_UNSPEC)
			fatal_f("unknown alg %s", alg);
		/*
		 * If we have a @cert-authority marker in known_hosts then
		 * prefer all certificate algorithms.
		 */
		ಯದಿ (sshkey_type_is_cert(ktype) &&
		    lookup_marker_in_hostkeys(hostkeys, MRK_CA)) {
			ALG_APPEND(first, alg);
			ಅನುವರ್ತ;
		}
		/* If the key appears in known_hosts then prefer it */
		ಯದಿ (lookup_ಕೀಲಿ_in_hostkeys_by_type(hostkeys,
		    sshkey_type_plain(ktype),
		    sshkey_ecdsa_nid_from_name(alg), ರಿಕ್ತ)) {
			ALG_APPEND(first, alg);
			ಅನುವರ್ತ;
		}
		/* Otherwise, put it last */
		ALG_APPEND(last, alg);
	}
#undef ALG_APPEND
	xasprintf(&ret, "%s%s%s", first,
	    (*first == '\0' || *last == '\0') ? "" : ",", last);
	ಯದಿ (*first != '\0')
		debug3_f("prefer hostkeyalgs: %s", first);
	ಅನ್ಯಥಾ
		debug3_f("no algorithms matched; accept original");
 out:
	ಮುಕ್ತ(best);
	ಮುಕ್ತ(first);
	ಮುಕ್ತ(last);
	ಮುಕ್ತ(hostname);
	ಮುಕ್ತ(oavail);
	free_hostkeys(hostkeys);

	ಪ್ರತ್ಯಾಗಮ ret;
}

ಶೂನ್ಯ
ssh_kex2(ಸಂರಚನಾ ssh *ssh, ವರ್ಣ *host, ಸಂರಚನಾ sockaddr_storage *hostaddr,
    u_short port, ಧ್ರುವ ಸಂರಚನಾ ssh_conn_info *cinfo)
{
	ವರ್ಣ *myproposal[PROPOSAL_MAX];
	ವರ್ಣ *all_ಕೀಲಿ, *hkalgs = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, use_known_hosts_order = 0;

	xxx_host = xstrdup(host);
	xxx_hostaddr = *hostaddr;
	xxx_conn_info = ssh_conn_info_dup(cinfo);

	ssh_packet_set_rekey_limits(ssh, options.rekey_limit,
	    options.rekey_interval);

	/*
	 * If the user has not specified HostkeyAlgorithms, or has only
	 * appended or removed algorithms from that list then prefer algorithms
	 * that are in the list that are supported by known_hosts keys.
	 */
	ಯದಿ (options.hostkeyalgorithms == ರಿಕ್ತ ||
	    options.hostkeyalgorithms[0] == '-' ||
	    options.hostkeyalgorithms[0] == '+')
		use_known_hosts_order = 1;

	/* Expand or fill in HostkeyAlgorithms */
	all_ಕೀಲಿ = sshkey_alg_list(0, 0, 1, ',');
	ಯದಿ ((r = kex_assemble_names(&options.hostkeyalgorithms,
	    kex_default_pk_alg(), all_ಕೀಲಿ)) != 0)
		fatal_fr(r, "kex_assemble_namelist");
	ಮುಕ್ತ(all_ಕೀಲಿ);

	ಯದಿ (use_known_hosts_order) {
		hkalgs = order_hostkeyalgs(host, (ಸಂರಚನಾ sockaddr *)hostaddr,
		    port, cinfo);
	}

	kex_proposal_populate_entries(ssh, myproposal,
	    options.kex_algorithms, options.ciphers, options.macs,
	    compression_alg_list(options.compression),
	    hkalgs ? hkalgs : options.hostkeyalgorithms);

	ಮುಕ್ತ(hkalgs);

	/* start key exchange */
	ಯದಿ ((r = kex_setup(ssh, myproposal)) != 0)
		fatal_r(r, "kex_setup");
#ifdef WITH_OPENSSL
	ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#endif
	ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
	ssh->kex->verify_host_ಕೀಲಿ=&verify_host_ಕೀಲಿ_callback;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &ssh->kex->done);
	kex_proposal_free_entries(myproposal);

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");
#endif
}

/*
 * Authenticate user
 */

ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ cauthctxt Authctxt;
ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ cauthmethod Authmethod;
ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ identity Identity;
ಪ್ರಕಾರನಿರ್ದೇಶ ಸಂರಚನಾ idlist Idlist;

ಸಂರಚನಾ identity {
	TAILQ_ENTRY(identity) next;
	ಪೂರ್ಣಾಙ್ಕ	agent_fd;		/* >=0 if agent supports key */
	ಸಂರಚನಾ sshkey	*ಕೀಲಿ;		/* public/private key */
	ವರ್ಣ	*filename;		/* comment for agent-only keys */
	ಪೂರ್ಣಾಙ್ಕ	tried;
	ಪೂರ್ಣಾಙ್ಕ	isprivate;		/* key points to the private key */
	ಪೂರ್ಣಾಙ್ಕ	userprovided;
};
TAILQ_HEAD(idlist, identity);

ಸಂರಚನಾ cauthctxt {
	ಧ್ರುವ ವರ್ಣ *server_user;
	ಧ್ರುವ ವರ್ಣ *local_user;
	ಧ್ರುವ ವರ್ಣ *host;
	ಧ್ರುವ ವರ್ಣ *service;
	ಸಂರಚನಾ cauthmethod *method;
	sig_atomic_t success;
	ವರ್ಣ *authlist;
#ifdef GSSAPI
	/* gssapi */
	gss_OID_set gss_supported_mechs;
	u_int mech_tried;
#endif
	/* pubkey */
	ಸಂರಚನಾ idlist ಕೀಲಿಗಳು;
	ಪೂರ್ಣಾಙ್ಕ agent_fd;
	/* hostbased */
	Sensitive *sensitive;
	ವರ್ಣ *oktypes, *ktypes;
	ಧ್ರುವ ವರ್ಣ *active_ktype;
	/* kbd-interactive */
	ಪೂರ್ಣಾಙ್ಕ info_req_seen;
	ಪೂರ್ಣಾಙ್ಕ attempt_kbdint;
	/* password */
	ಪೂರ್ಣಾಙ್ಕ attempt_passwd;
	/* generic */
	ಶೂನ್ಯ *methoddata;
};

ಸಂರಚನಾ cauthmethod {
	ವರ್ಣ	*name;		/* string to compare against server's list */
	ಪೂರ್ಣಾಙ್ಕ	(*userauth)(ಸಂರಚನಾ ssh *ssh);
	ಶೂನ್ಯ	(*cleanup)(ಸಂರಚನಾ ssh *ssh);
	ಪೂರ್ಣಾಙ್ಕ	*enabled;	/* flag in option struct that enables method */
	ಪೂರ್ಣಾಙ್ಕ	*batch_flag;	/* flag in option struct that disables method */
};

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_userauth_service_accept(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_userauth_success(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_userauth_failure(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_userauth_banner(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_userauth_error(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_userauth_info_req(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_userauth_pk_ok(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_userauth_passwd_changereq(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ userauth_none(ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ userauth_pubkey(ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ userauth_passwd(ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ userauth_kbdint(ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ userauth_hostbased(ಸಂರಚನಾ ssh *);

#ifdef GSSAPI
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ userauth_gssapi(ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಶೂನ್ಯ userauth_gssapi_cleanup(ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_gssapi_response(ಪೂರ್ಣಾಙ್ಕ type, uint32_t, ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_gssapi_token(ಪೂರ್ಣಾಙ್ಕ type, uint32_t, ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_gssapi_error(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು_gssapi_errtok(ಪೂರ್ಣಾಙ್ಕ, uint32_t, ಸಂರಚನಾ ssh *);
#endif

ಶೂನ್ಯ	userauth(ಸಂರಚನಾ ssh *, ವರ್ಣ *);

ಸ್ಥಿರ ಶೂನ್ಯ pubkey_cleanup(ಸಂರಚನಾ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ sign_and_send_pubkey(ಸಂರಚನಾ ssh *ssh, Identity *);
ಸ್ಥಿರ ಶೂನ್ಯ pubkey_prepare(ಸಂರಚನಾ ssh *, Authctxt *);
ಸ್ಥಿರ ಶೂನ್ಯ pubkey_reset(Authctxt *);
ಸ್ಥಿರ ಸಂರಚನಾ sshkey *load_identity_file(Identity *);

ಸ್ಥಿರ Authmethod *authmethod_get(ವರ್ಣ *authlist);
ಸ್ಥಿರ Authmethod *authmethod_lookup(ಧ್ರುವ ವರ್ಣ *name);
ಸ್ಥಿರ ವರ್ಣ *authmethods_get(ಶೂನ್ಯ);

Authmethod authmethods[] = {
#ifdef GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		userauth_gssapi_cleanup,
		&options.gss_authentication,
		ರಿಕ್ತ},
#endif
	{"hostbased",
		userauth_hostbased,
		ರಿಕ್ತ,
		&options.hostbased_authentication,
		ರಿಕ್ತ},
	{"publickey",
		userauth_pubkey,
		ರಿಕ್ತ,
		&options.pubkey_authentication,
		ರಿಕ್ತ},
	{"keyboard-interactive",
		userauth_kbdint,
		ರಿಕ್ತ,
		&options.kbd_interactive_authentication,
		&options.batch_mode},
	{"password",
		userauth_passwd,
		ರಿಕ್ತ,
		&options.password_authentication,
		&options.batch_mode},
	{"none",
		userauth_none,
		ರಿಕ್ತ,
		ರಿಕ್ತ,
		ರಿಕ್ತ},
	{ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ, ರಿಕ್ತ}
};

ಶೂನ್ಯ
ssh_userauth2(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *local_user,
    ಧ್ರುವ ವರ್ಣ *server_user, ವರ್ಣ *host, Sensitive *sensitive)
{
	Authctxt authctxt;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (options.preferred_authentications == ರಿಕ್ತ)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	memset(&authctxt, 0, ಪರಿಮಾಣ(authctxt));
	authctxt.server_user = server_user;
	authctxt.local_user = local_user;
	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.method = authmethod_lookup("none");
	authctxt.authlist = ರಿಕ್ತ;
	authctxt.methoddata = ರಿಕ್ತ;
	authctxt.sensitive = sensitive;
	authctxt.active_ktype = authctxt.oktypes = authctxt.ktypes = ರಿಕ್ತ;
	authctxt.info_req_seen = 0;
	authctxt.attempt_kbdint = 0;
	authctxt.attempt_passwd = 0;
#ಯದಿ GSSAPI
	authctxt.gss_supported_mechs = ರಿಕ್ತ;
	authctxt.mech_tried = 0;
#endif
	authctxt.agent_fd = -1;
	ಯದಿ (authctxt.method == ರಿಕ್ತ)
		fatal_f("internal error: cannot send userauth none request");

	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_SERVICE_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "ssh-userauth")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh->authctxt = &authctxt;
	ssh_dispatch_init(ssh, &ಒಳಹರಿವು_userauth_error);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_EXT_INFO, kex_ಒಳಹರಿವು_ext_info);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_SERVICE_ACCEPT, &ಒಳಹರಿವು_userauth_service_accept);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt.success);	/* loop until success */
	pubkey_cleanup(ssh);
#ifdef GSSAPI
	ಯದಿ (authctxt.gss_supported_mechs != ರಿಕ್ತ) {
		u_int ms;

		gss_release_oid_set(&ms, &authctxt.gss_supported_mechs);
		authctxt.gss_supported_mechs = ರಿಕ್ತ;
	}
#endif
	ssh->authctxt = ರಿಕ್ತ;

	ssh_dispatch_range(ssh, SSH2_ಸಂದೇಶ_USERAUTH_MIN, SSH2_ಸಂದೇಶ_USERAUTH_MAX, ರಿಕ್ತ);

	ಯದಿ (!authctxt.success)
		fatal("Authentication failed.");
	ಯದಿ (ssh_packet_connection_is_on_socket(ssh)) {
		verbose("Authenticated to %s ([%s]:%d) using \"%s\".", host,
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    authctxt.method->name);
	} ಅನ್ಯಥಾ {
		verbose("Authenticated to %s (via proxy) using \"%s\".", host,
		    authctxt.method->name);
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_userauth_service_accept(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (ssh_packet_remaining(ssh) > 0) {
		ವರ್ಣ *reply;

		ಯದಿ ((r = sshpkt_get_cstring(ssh, &reply, ರಿಕ್ತ)) != 0)
			ಗಚ್ಛ out;
		debug2("service_accept: %s", reply);
		ಮುಕ್ತ(reply);
	} ಅನ್ಯಥಾ {
		debug2("buggy server: service_accept w/o service");
	}
	ಯದಿ ((r = sshpkt_get_end(ssh)) != 0)
		ಗಚ್ಛ out;
	debug("SSH2_MSG_SERVICE_ACCEPT received");

	/* initial userauth request */
	userauth_none(ssh);

	/* accept EXT_INFO at any time during userauth */
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_EXT_INFO, ssh->kex->ext_info_s ?
	    &kex_ಒಳಹರಿವು_ext_info : &ಒಳಹರಿವು_userauth_error);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_SUCCESS, &ಒಳಹರಿವು_userauth_success);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_FAILURE, &ಒಳಹರಿವು_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_BANNER, &ಒಳಹರಿವು_userauth_banner);
	r = 0;
 out:
	ಪ್ರತ್ಯಾಗಮ r;
}

ಶೂನ್ಯ
userauth(ಸಂರಚನಾ ssh *ssh, ವರ್ಣ *authlist)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	ಯದಿ (authctxt->method != ರಿಕ್ತ && authctxt->method->cleanup != ರಿಕ್ತ)
		authctxt->method->cleanup(ssh);

	ಮುಕ್ತ(authctxt->methoddata);
	authctxt->methoddata = ರಿಕ್ತ;
	ಯದಿ (authlist == ರಿಕ್ತ) {
		authlist = authctxt->authlist;
	} ಅನ್ಯಥಾ {
		ಮುಕ್ತ(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	ಪ್ರತಿ (;;) {
		Authmethod *method = authmethod_get(authlist);
		ಯದಿ (method == ರಿಕ್ತ)
			fatal("%s@%s: Permission denied (%s).",
			    authctxt->server_user, authctxt->host, authlist);
		authctxt->method = method;

		/* reset the per method handler */
		ssh_dispatch_range(ssh, SSH2_ಸಂದೇಶ_USERAUTH_PER_METHOD_MIN,
		    SSH2_ಸಂದೇಶ_USERAUTH_PER_METHOD_MAX, ರಿಕ್ತ);

		/* and try new method */
		ಯದಿ (method->userauth(ssh) != 0) {
			debug2("we sent a %s packet, wait for reply", method->name);
			ಭಙ್ಗ;
		} ಅನ್ಯಥಾ {
			debug2("we did not send a packet, disable method");
			method->enabled = ರಿಕ್ತ;
		}
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_userauth_error(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	fatal_f("bad message during authentication: type %d", type);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_userauth_banner(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	ವರ್ಣ *ಸಂದೇಶ = ರಿಕ್ತ;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ r;

	debug3_f("entering");
	ಯದಿ ((r = sshpkt_get_cstring(ssh, &ಸಂದೇಶ, &len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, ರಿಕ್ತ, ರಿಕ್ತ)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO)
		fmprintf(stderr, "%s", ಸಂದೇಶ);
	r = 0;
 out:
	ಮುಕ್ತ(ಸಂದೇಶ);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_userauth_success(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ಯದಿ (authctxt == ರಿಕ್ತ)
		fatal_f("no authentication context");
	ಮುಕ್ತ(authctxt->authlist);
	authctxt->authlist = ರಿಕ್ತ;
	ಯದಿ (authctxt->method != ರಿಕ್ತ && authctxt->method->cleanup != ರಿಕ್ತ)
		authctxt->method->cleanup(ssh);
	ಮುಕ್ತ(authctxt->methoddata);
	authctxt->methoddata = ರಿಕ್ತ;
	authctxt->success = 1;			/* break out */
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_EXT_INFO, dispatch_protocol_error);
	ಪ್ರತ್ಯಾಗಮ 0;
}

#ಯದಿ 0
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_userauth_success_unexpected(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ಯದಿ (authctxt == ರಿಕ್ತ)
		fatal_f("no authentication context");

	fatal("Unexpected authentication success during %s.",
	    authctxt->method->name);
	ಪ್ರತ್ಯಾಗಮ 0;
}
#endif

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_userauth_failure(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ವರ್ಣ *authlist = ರಿಕ್ತ;
	u_char partial;

	ಯದಿ (authctxt == ರಿಕ್ತ)
		fatal("input_userauth_failure: no authentication context");

	ಯದಿ (sshpkt_get_cstring(ssh, &authlist, ರಿಕ್ತ) != 0 ||
	    sshpkt_get_u8(ssh, &partial) != 0 ||
	    sshpkt_get_end(ssh) != 0)
		ಗಚ್ಛ out;

	ಯದಿ (partial != 0) {
		verbose("Authenticated using \"%s\" with partial success.",
		    authctxt->method->name);
		/* reset state */
		pubkey_reset(authctxt);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(ssh, authlist);
	authlist = ರಿಕ್ತ;
 out:
	ಮುಕ್ತ(authlist);
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Format an identity for logging including filename, key type, fingerprint
 * and location (agent, etc.). Caller must free.
 */
ಸ್ಥಿರ ವರ್ಣ *
format_identity(Identity *id)
{
	ವರ್ಣ *fp = ರಿಕ್ತ, *ret = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *note = "";

	ಯದಿ (id->ಕೀಲಿ != ರಿಕ್ತ) {
		fp = sshkey_fingerprint(id->ಕೀಲಿ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
	}
	ಯದಿ (id->ಕೀಲಿ) {
		ಯದಿ ((id->ಕೀಲಿ->flags & SSHKEY_FLAG_EXT) != 0)
			note = " token";
		ಅನ್ಯಥಾ ಯದಿ (sshkey_is_sk(id->ಕೀಲಿ))
			note = " authenticator";
	}
	xasprintf(&ret, "%s %s%s%s%s%s%s",
	    id->filename,
	    id->ಕೀಲಿ ? sshkey_type(id->ಕೀಲಿ) : "", id->ಕೀಲಿ ? " " : "",
	    fp ? fp : "",
	    id->userprovided ? " explicit" : "", note,
	    id->agent_fd != -1 ? " agent" : "");
	ಮುಕ್ತ(fp);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_userauth_pk_ok(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *keyblob = ರಿಕ್ತ;
	Identity *id = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ pktype, found = 0, sent = 0;
	ವರ್ಣ *pkalg = ರಿಕ್ತ, *fp = ರಿಕ್ತ, *ident = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (authctxt == ರಿಕ್ತ)
		fatal_f("no authentication context");

	ಯದಿ ((r = sshpkt_get_cstring(ssh, &pkalg, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ಗಚ್ಛ done;

	ಯದಿ (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		error_f("server replied to PK_OK with signature type %s not "
		    "in PubkeyAcceptedAlgorithms", pkalg);
		r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		ಗಚ್ಛ done;
	}
	ಯದಿ ((pktype = sshkey_type_from_name(pkalg)) == ಕೀಲಿ_UNSPEC) {
		debug_f("server sent unknown pkalg %s", pkalg);
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ done;
	}
	/* inner key type should match signature type */
	ಯದಿ ((r = sshkey_fromb_allowlist(keyblob, &ಕೀಲಿ, pkalg, ರಿಕ್ತ)) != 0) {
		debug_r(r, "no key from blob. pkalg %s", pkalg);
		ಗಚ್ಛ done;
	}
	ಯದಿ (ಕೀಲಿ->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    ಕೀಲಿ->type, pktype);
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ done;
	}

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_REVERSE(id, &authctxt->ಕೀಲಿಗಳು, idlist, next) {
		ಯದಿ (sshkey_equal(ಕೀಲಿ, id->ಕೀಲಿ)) {
			found = 1;
			ಭಙ್ಗ;
		}
	}
	ಯದಿ (!found || id == ರಿಕ್ತ) {
		fp = sshkey_fingerprint(ಕೀಲಿ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		error_f("server replied with unknown key: %s %s",
		    sshkey_type(ಕೀಲಿ), fp == ರಿಕ್ತ ? "<ERROR>" : fp);
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ done;
	}
	ident = format_identity(id);
	debug("Server accepts key: %s", ident);
	sent = sign_and_send_pubkey(ssh, id);
	r = 0;
 done:
	sshkey_free(ಕೀಲಿ);
	sshbuf_free(keyblob);
	ಮುಕ್ತ(ident);
	ಮುಕ್ತ(fp);
	ಮುಕ್ತ(pkalg);

	/* try another method if we did not send a packet */
	ಯದಿ (r == 0 && sent == 0)
		userauth(ssh, ರಿಕ್ತ);
	ಪ್ರತ್ಯಾಗಮ r;
}

#ifdef GSSAPI
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
userauth_gssapi(ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = ರಿಕ್ತ;
	OM_uint32 min;
	ಪೂರ್ಣಾಙ್ಕ r, ok = 0;
	gss_OID mech = ರಿಕ್ತ;

	/* Try one GSSAPI method at a time, rather than sending them all at
	 * once. */

	ಯದಿ (authctxt->gss_supported_mechs == ರಿಕ್ತ)
		gss_indicate_mechs(&min, &authctxt->gss_supported_mechs);

	/* Check to see whether the mechanism is usable before we offer it */
	ಯಾವತ್ (authctxt->mech_tried < authctxt->gss_supported_mechs->ಎಣಿಕೆ &&
	    !ok) {
		mech = &authctxt->gss_supported_mechs->
		    elements[authctxt->mech_tried];
		/* My DER encoding requires length<128 */
		ಯದಿ (mech->length < 128 && ssh_gssapi_check_mechanism(&gssctxt,
		    mech, authctxt->host)) {
			ok = 1; /* Mechanism works */
		} ಅನ್ಯಥಾ {
			authctxt->mech_tried++;
		}
	}

	ಯದಿ (!ok || mech == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;

	authctxt->methoddata=(ಶೂನ್ಯ *)gssctxt;

	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_u32(ssh, (mech->length) + 2)) != 0 ||
	    (r = sshpkt_put_u8(ssh, SSH_GSS_OIDTYPE)) != 0 ||
	    (r = sshpkt_put_u8(ssh, mech->length)) != 0 ||
	    (r = sshpkt_put(ssh, mech->elements, mech->length)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_RESPONSE, &ಒಳಹರಿವು_gssapi_response);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN, &ಒಳಹರಿವು_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERROR, &ಒಳಹರಿವು_gssapi_error);
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERRTOK, &ಒಳಹರಿವು_gssapi_errtok);

	authctxt->mech_tried++; /* Move along to next candidate */

	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
userauth_gssapi_cleanup(ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = (Gssctxt *)authctxt->methoddata;

	ssh_gssapi_delete_ctx(&gssctxt);
	authctxt->methoddata = ರಿಕ್ತ;
}

ಸ್ಥಿರ OM_uint32
process_gssapi_token(ಸಂರಚನಾ ssh *ssh, gss_buffer_t recv_tok)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt = authctxt->methoddata;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc mic = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc gssbuf;
	OM_uint32 status, ms, flags;
	ಪೂರ್ಣಾಙ್ಕ r;

	status = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	ಯದಿ (send_tok.length > 0) {
		u_char type = GSS_ERROR(status) ?
		    SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERRTOK :
		    SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN;

		ಯದಿ ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put_string(ssh, send_tok.ಮೌಲ್ಯ,
		    send_tok.length)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send %u packet", type);

		gss_release_buffer(&ms, &send_tok);
	}

	ಯದಿ (status == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		ಯದಿ (!(flags & GSS_C_INTEG_FLAG)) {
			ಯದಿ ((r = sshpkt_start(ssh,
			    SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send completion");
		} ಅನ್ಯಥಾ {
			ಸಂರಚನಾ sshbuf *b;

			ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
				fatal_f("sshbuf_new failed");
			ssh_gssapi_buildmic(b, authctxt->server_user,
			    authctxt->service, "gssapi-with-mic",
			    ssh->kex->session_id);

			ಯದಿ ((gssbuf.ಮೌಲ್ಯ = sshbuf_mutable_ptr(b)) == ರಿಕ್ತ)
				fatal_f("sshbuf_mutable_ptr failed");
			gssbuf.length = sshbuf_len(b);

			status = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			ಯದಿ (!GSS_ERROR(status)) {
				ಯದಿ ((r = sshpkt_start(ssh,
				    SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_MIC)) != 0 ||
				    (r = sshpkt_put_string(ssh, mic.ಮೌಲ್ಯ,
				    mic.length)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send MIC");
			}

			sshbuf_free(b);
			gss_release_buffer(&ms, &mic);
		}
	}

	ಪ್ರತ್ಯಾಗಮ status;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_gssapi_response(ಪೂರ್ಣಾಙ್ಕ type, uint32_t plen, ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	size_t oidlen;
	u_char *oidv = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (authctxt == ರಿಕ್ತ)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	ಯದಿ ((r = sshpkt_get_string(ssh, &oidv, &oidlen)) != 0)
		ಗಚ್ಛ done;

	ಯದಿ (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		debug("Badly encoded mechanism OID received");
		userauth(ssh, ರಿಕ್ತ);
		ಗಚ್ಛ ok;
	}

	ಯದಿ (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	ಯದಿ ((r = sshpkt_get_end(ssh)) != 0)
		ಗಚ್ಛ done;

	ಯದಿ (GSS_ERROR(process_gssapi_token(ssh, GSS_C_NO_BUFFER))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(ssh, ರಿಕ್ತ);
		ಗಚ್ಛ ok;
	}
 ok:
	r = 0;
 done:
	ಮುಕ್ತ(oidv);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_gssapi_token(ಪೂರ್ಣಾಙ್ಕ type, uint32_t plen, ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_buffer_desc recv_tok;
	u_char *p = ರಿಕ್ತ;
	size_t len;
	OM_uint32 status;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (authctxt == ರಿಕ್ತ)
		fatal("input_gssapi_response: no authentication context");

	ಯದಿ ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		ಗಚ್ಛ out;

	recv_tok.ಮೌಲ್ಯ = p;
	recv_tok.length = len;
	status = process_gssapi_token(ssh, &recv_tok);

	/* Start again with the next method in the list */
	ಯದಿ (GSS_ERROR(status)) {
		userauth(ssh, ರಿಕ್ತ);
		/* ok */
	}
	r = 0;
 out:
	ಮುಕ್ತ(p);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_gssapi_errtok(ಪೂರ್ಣಾಙ್ಕ type, uint32_t plen, ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 ms;
	u_char *p = ರಿಕ್ತ;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (authctxt == ರಿಕ್ತ)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	ಯದಿ ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		ಮುಕ್ತ(p);
		ಪ್ರತ್ಯಾಗಮ r;
	}

	/* Stick it into GSSAPI and see what it says */
	recv_tok.ಮೌಲ್ಯ = p;
	recv_tok.length = len;
	(ಶೂನ್ಯ)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, ರಿಕ್ತ);
	ಮುಕ್ತ(p);
	gss_release_buffer(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_gssapi_error(ಪೂರ್ಣಾಙ್ಕ type, uint32_t plen, ಸಂರಚನಾ ssh *ssh)
{
	ವರ್ಣ *ಸಂದೇಶ = ರಿಕ್ತ;
	ವರ್ಣ *lang = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshpkt_get_u32(ssh, ರಿಕ್ತ)) != 0 ||	/* maj */
	    (r = sshpkt_get_u32(ssh, ರಿಕ್ತ)) != 0 ||	/* min */
	    (r = sshpkt_get_cstring(ssh, &ಸಂದೇಶ, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ರಿಕ್ತ)) != 0)
		ಗಚ್ಛ out;
	r = sshpkt_get_end(ssh);
	debug("Server GSSAPI Error:\n%s", ಸಂದೇಶ);
 out:
	ಮುಕ್ತ(ಸಂದೇಶ);
	ಮುಕ್ತ(lang);
	ಪ್ರತ್ಯಾಗಮ r;
}
#endif /* GSSAPI */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
userauth_none(ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ಪೂರ್ಣಾಙ್ಕ r;

	/* initial userauth request */
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
userauth_passwd(ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ವರ್ಣ *password, *prompt = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *host = options.host_ಕೀಲಿ_alias ?  options.host_ಕೀಲಿ_alias :
	    authctxt->host;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (authctxt->attempt_passwd++ >= options.ಸಂಖ್ಯೆ_of_password_prompts)
		ಪ್ರತ್ಯಾಗಮ 0;

	ಯದಿ (authctxt->attempt_passwd != 1)
		error("Permission denied, please try again.");

	xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ಮುಕ್ತ(prompt);
	ಯದಿ (password != ರಿಕ್ತ)
		freezero(password, strlen(password));

	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_PASSWD_CHANGEREQ,
	    &ಒಳಹರಿವು_userauth_passwd_changereq);

	ಪ್ರತ್ಯಾಗಮ 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_userauth_passwd_changereq(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seqnr, ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ವರ್ಣ *info = ರಿಕ್ತ, *lang = ರಿಕ್ತ, *password = ರಿಕ್ತ, *retype = ರಿಕ್ತ;
	ವರ್ಣ prompt[256];
	ಧ್ರುವ ವರ್ಣ *host;
	ಪೂರ್ಣಾಙ್ಕ r, addnl;
	size_t len;

	debug2("input_userauth_passwd_changereq");

	ಯದಿ (authctxt == ರಿಕ್ತ)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");
	host = options.host_ಕೀಲಿ_alias ? options.host_ಕೀಲಿ_alias : authctxt->host;

	ಯದಿ ((r = sshpkt_get_cstring(ssh, &info, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ರಿಕ್ತ)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((len = strlen(info)) > 0) {
		addnl = info[len] != '\n';
		fmprintf(stderr, "%s%s", info, addnl ? "\n" : "");
	}
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0)	/* additional info */
		ಗಚ್ಛ out;

	snprintf(prompt, ಪರಿಮಾಣ(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	ಯದಿ ((r = sshpkt_put_cstring(ssh, password)) != 0)
		ಗಚ್ಛ out;

	freezero(password, strlen(password));
	password = ರಿಕ್ತ;
	ಯಾವತ್ (password == ರಿಕ್ತ) {
		snprintf(prompt, ಪರಿಮಾಣ(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		ಯದಿ (password == ರಿಕ್ತ) {
			/* bail out */
			r = 0;
			ಗಚ್ಛ out;
		}
		snprintf(prompt, ಪರಿಮಾಣ(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		ಯದಿ (strcmp(password, retype) != 0) {
			freezero(password, strlen(password));
			logit("Mismatch; try again, EOF to quit.");
			password = ರಿಕ್ತ;
		}
		freezero(retype, strlen(retype));
	}
	ಯದಿ ((r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಗಚ್ಛ out;

	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_PASSWD_CHANGEREQ,
	    &ಒಳಹರಿವು_userauth_passwd_changereq);
	r = 0;
 out:
	ಯದಿ (password)
		freezero(password, strlen(password));
	ಮುಕ್ತ(info);
	ಮುಕ್ತ(lang);
	ಪ್ರತ್ಯಾಗಮ r;
}

/*
 * Select an algorithm for publickey signatures.
 * Returns algorithm (caller must free) or NULL if no mutual algorithm found.
 *
 * Call with ssh==NULL to ignore server-sig-algs extension list and
 * only attempt with the key's base signature type.
 */
ಸ್ಥಿರ ವರ್ಣ *
ಕೀಲಿ_sig_algorithm(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ವರ್ಣ *allowed, *oallowed, *cp, *tmp, *alg = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *server_sig_algs;

	/*
	 * The signature algorithm will only differ from the key algorithm
	 * for RSA keys/certs and when the server advertises support for
	 * newer (SHA2) algorithms.
	 */
	ಯದಿ (ssh == ರಿಕ್ತ || ssh->kex->server_sig_algs == ರಿಕ್ತ ||
	    (ಕೀಲಿ->type != ಕೀಲಿ_RSA && ಕೀಲಿ->type != ಕೀಲಿ_RSA_CERT) ||
	    (ಕೀಲಿ->type == ಕೀಲಿ_RSA_CERT && (ssh->compat & SSH_BUG_SIGTYPE))) {
		/* Filter base key signature alg against our configuration */
		ಪ್ರತ್ಯಾಗಮ match_list(sshkey_ssh_name(ಕೀಲಿ),
		    options.pubkey_accepted_algos, ರಿಕ್ತ);
	}

	/*
	 * Workaround OpenSSH 7.4 bug: this version supports RSA/SHA-2 but
	 * fails to advertise it via SSH2_MSG_EXT_INFO.
	 */
	server_sig_algs = ssh->kex->server_sig_algs;
	ಯದಿ (ಕೀಲಿ->type == ಕೀಲಿ_RSA && (ssh->compat & SSH_BUG_SIGTYPE74))
		server_sig_algs = "rsa-sha2-256,rsa-sha2-512";

	/*
	 * For RSA keys/certs, since these might have a different sig type:
	 * find the first entry in PubkeyAcceptedAlgorithms of the right type
	 * that also appears in the supported signature algorithms list from
	 * the server.
	 */
	oallowed = allowed = xstrdup(options.pubkey_accepted_algos);
	ಯಾವತ್ ((cp = strsep(&allowed, ",")) != ರಿಕ್ತ) {
		ಯದಿ (sshkey_type_from_name(cp) != ಕೀಲಿ->type)
			ಅನುವರ್ತ;
		tmp = match_list(sshkey_sigalg_by_name(cp),
		    server_sig_algs, ರಿಕ್ತ);
		ಯದಿ (tmp != ರಿಕ್ತ)
			alg = xstrdup(cp);
		ಮುಕ್ತ(tmp);
		ಯದಿ (alg != ರಿಕ್ತ)
			ಭಙ್ಗ;
	}
	ಮುಕ್ತ(oallowed);
	ಪ್ರತ್ಯಾಗಮ alg;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
identity_sign(ಸಂರಚನಾ identity *id, u_char **sigp, size_t *lenp,
    ಧ್ರುವ u_char *data, size_t datalen, u_int compat, ಧ್ರುವ ವರ್ಣ *alg)
{
	ಸಂರಚನಾ sshkey *sign_ಕೀಲಿ = ರಿಕ್ತ, *prv = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ is_agent = 0, retried = 0, r = SSH_ERR_INTERNAL_ERROR;
	ಸಂರಚನಾ notifier_ctx *notifier = ರಿಕ್ತ;
	ವರ್ಣ *fp = ರಿಕ್ತ, *pin = ರಿಕ್ತ, *prompt = ರಿಕ್ತ;

	*sigp = ರಿಕ್ತ;
	*lenp = 0;

	/* The agent supports this key. */
	ಯದಿ (id->ಕೀಲಿ != ರಿಕ್ತ && id->agent_fd != -1) {
		ಪ್ರತ್ಯಾಗಮ ssh_agent_sign(id->agent_fd, id->ಕೀಲಿ, sigp, lenp,
		    data, datalen, alg, compat);
	}

	/*
	 * We have already loaded the private key or the private key is
	 * stored in external hardware.
	 */
	ಯದಿ (id->ಕೀಲಿ != ರಿಕ್ತ &&
	    (id->isprivate || (id->ಕೀಲಿ->flags & SSHKEY_FLAG_EXT))) {
		sign_ಕೀಲಿ = id->ಕೀಲಿ;
		is_agent = 1;
	} ಅನ್ಯಥಾ {
		/* Load the private key from the file. */
		ಯದಿ ((prv = load_identity_file(id)) == ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_NOT_FOUND;
		ಯದಿ (id->ಕೀಲಿ != ರಿಕ್ತ && !sshkey_equal_public(prv, id->ಕೀಲಿ)) {
			error_f("private key %s contents do not match public",
			    id->filename);
			r = SSH_ERR_ಕೀಲಿ_NOT_FOUND;
			ಗಚ್ಛ out;
		}
		sign_ಕೀಲಿ = prv;
	}
 retry_pin:
	/* Prompt for touch for non-agent FIDO keys that request UP */
	ಯದಿ (!is_agent && sshkey_is_sk(sign_ಕೀಲಿ) &&
	    (sign_ಕೀಲಿ->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
		/* XXX should batch mode just skip these? */
		ಯದಿ ((fp = sshkey_fingerprint(sign_ಕೀಲಿ,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ರಿಕ್ತ)
			fatal_f("fingerprint failed");
		notifier = notify_start(options.batch_mode,
		    "Confirm user presence for key %s %s",
		    sshkey_type(sign_ಕೀಲಿ), fp);
		ಮುಕ್ತ(fp);
	}
	ಯದಿ ((r = sshkey_sign(sign_ಕೀಲಿ, sigp, lenp, data, datalen,
	    alg, options.sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		ಯದಿ (!retried && pin == ರಿಕ್ತ && !is_agent &&
		    sshkey_is_sk(sign_ಕೀಲಿ) &&
		    r == SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE) {
			notify_complete(notifier, ರಿಕ್ತ);
			notifier = ರಿಕ್ತ;
			xasprintf(&prompt, "Enter PIN for %s key %s: ",
			    sshkey_type(sign_ಕೀಲಿ), id->filename);
			pin = read_passphrase(prompt, 0);
			retried = 1;
			ಗಚ್ಛ retry_pin;
		}
		ಗಚ್ಛ out;
	}

	/*
	 * PKCS#11 tokens may not support all signature algorithms,
	 * so check what we get back.
	 */
	ಯದಿ (id->ಕೀಲಿ != ರಿಕ್ತ && (id->ಕೀಲಿ->flags & SSHKEY_FLAG_EXT) != 0 &&
	    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
		debug_fr(r, "sshkey_check_sigtype");
		ಗಚ್ಛ out;
	}
	/* success */
	r = 0;
 out:
	ಮುಕ್ತ(prompt);
	ಯದಿ (pin != ರಿಕ್ತ)
		freezero(pin, strlen(pin));
	notify_complete(notifier, r == 0 ? "User presence confirmed" : ರಿಕ್ತ);
	sshkey_free(prv);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
id_filename_matches(Identity *id, Identity *private_id)
{
	ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ * ಧ್ರುವ suffixes[] = { ".pub", "-cert.pub", ರಿಕ್ತ };
	size_t len = strlen(id->filename), plen = strlen(private_id->filename);
	size_t i, slen;

	ಯದಿ (strcmp(id->filename, private_id->filename) == 0)
		ಪ್ರತ್ಯಾಗಮ 1;
	ಪ್ರತಿ (i = 0; suffixes[i]; i++) {
		slen = strlen(suffixes[i]);
		ಯದಿ (len > slen && plen == len - slen &&
		    strcmp(id->filename + (len - slen), suffixes[i]) == 0 &&
		    memcmp(id->filename, private_id->filename, plen) == 0)
			ಪ್ರತ್ಯಾಗಮ 1;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sign_and_send_pubkey(ಸಂರಚನಾ ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	Identity *private_id, *sign_id = ರಿಕ್ತ;
	u_char *signature = ರಿಕ್ತ;
	size_t slen = 0, skip = 0;
	ಪೂರ್ಣಾಙ್ಕ r, fallback_sigtype, sent = 0;
	ವರ್ಣ *alg = ರಿಕ್ತ, *fp = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *loc = "", *method = "publickey";
	ಪೂರ್ಣಾಙ್ಕ hostbound = 0;

	/* prefer host-bound pubkey signatures if supported by server */
	ಯದಿ ((ssh->kex->flags & KEX_HAS_PUBKEY_HOSTBOUND) != 0 &&
	    (options.pubkey_authentication & SSH_PUBKEY_AUTH_HBOUND) != 0) {
		hostbound = 1;
		method = "publickey-hostbound-v00@openssh.com";
	}

	ಯದಿ ((fp = sshkey_fingerprint(id->ಕೀಲಿ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;

	debug3_f("using %s with %s %s", method, sshkey_type(id->ಕೀಲಿ), fp);

	/*
	 * If the key is an certificate, try to find a matching private key
	 * and use it to complete the signature.
	 * If no such private key exists, fall back to trying the certificate
	 * key itself in case it has a private half already loaded.
	 * This will try to set sign_id to the private key that will perform
	 * the signature.
	 */
	ಯದಿ (id->agent_fd == -1 && sshkey_is_cert(id->ಕೀಲಿ)) {
		TAILQ_FOREACH(private_id, &authctxt->ಕೀಲಿಗಳು, next) {
			ಯದಿ (sshkey_equal_public(id->ಕೀಲಿ, private_id->ಕೀಲಿ) &&
			    id->ಕೀಲಿ->type != private_id->ಕೀಲಿ->type) {
				sign_id = private_id;
				ಭಙ್ಗ;
			}
		}
		/*
		 * Exact key matches are preferred, but also allow
		 * filename matches for non-PKCS#11/agent keys that
		 * didn't load public keys. This supports the case
		 * of keeping just a private key file and public
		 * certificate on disk.
		 */
		ಯದಿ (sign_id == ರಿಕ್ತ &&
		    !id->isprivate && id->agent_fd == -1 &&
		    (id->ಕೀಲಿ->flags & SSHKEY_FLAG_EXT) == 0) {
			TAILQ_FOREACH(private_id, &authctxt->ಕೀಲಿಗಳು, next) {
				ಯದಿ (private_id->ಕೀಲಿ == ರಿಕ್ತ &&
				    id_filename_matches(id, private_id)) {
					sign_id = private_id;
					ಭಙ್ಗ;
				}
			}
		}
		ಯದಿ (sign_id != ರಿಕ್ತ) {
			debug2_f("using private key \"%s\"%s for "
			    "certificate", sign_id->filename,
			    sign_id->agent_fd != -1 ? " from agent" : "");
		} ಅನ್ಯಥಾ {
			debug_f("no separate private key for certificate "
			    "\"%s\"", id->filename);
		}
	}

	/*
	 * If the above didn't select another identity to do the signing
	 * then default to the one we started with.
	 */
	ಯದಿ (sign_id == ರಿಕ್ತ)
		sign_id = id;

	/* assemble and sign data */
	ಪ್ರತಿ (fallback_sigtype = 0; fallback_sigtype <= 1; fallback_sigtype++) {
		ಮುಕ್ತ(alg);
		slen = 0;
		signature = ರಿಕ್ತ;
		ಯದಿ ((alg = ಕೀಲಿ_sig_algorithm(fallback_sigtype ? ರಿಕ್ತ : ssh,
		    id->ಕೀಲಿ)) == ರಿಕ್ತ) {
			error_f("no mutual signature supported");
			ಗಚ್ಛ out;
		}
		debug3_f("signing using %s %s", alg, fp);

		sshbuf_free(b);
		ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
			fatal_f("sshbuf_new failed");
		ಯದಿ ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "sshbuf_put_stringb");
		skip = sshbuf_len(b);
		ಯದಿ ((r = sshbuf_put_u8(b, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, 1)) != 0 ||
		    (r = sshbuf_put_cstring(b, alg)) != 0 ||
		    (r = sshkey_puts(id->ಕೀಲಿ, b)) != 0) {
			fatal_fr(r, "assemble signed data");
		}
		ಯದಿ (hostbound) {
			ಯದಿ (ssh->kex->initial_hostkey == ರಿಕ್ತ) {
				fatal_f("internal error: initial hostkey "
				    "not recorded");
			}
			ಯದಿ ((r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
				fatal_fr(r, "assemble %s hostkey", method);
		}
		/* generate signature */
		r = identity_sign(sign_id, &signature, &slen,
		    sshbuf_ptr(b), sshbuf_len(b), ssh->compat, alg);
		ಯದಿ (r == 0)
			ಭಙ್ಗ;
		ಅನ್ಯಥಾ ಯದಿ (r == SSH_ERR_ಕೀಲಿ_NOT_FOUND)
			ಗಚ್ಛ out; /* soft failure */
		ಅನ್ಯಥಾ ಯದಿ (r == SSH_ERR_SIGN_ALG_UNSUPPORTED &&
		    !fallback_sigtype) {
			ಯದಿ (sign_id->agent_fd != -1)
				loc = "agent ";
			ಅನ್ಯಥಾ ಯದಿ (sign_id->ಕೀಲಿ != ರಿಕ್ತ &&
			    (sign_id->ಕೀಲಿ->flags & SSHKEY_FLAG_EXT) != 0)
				loc = "token ";
			logit("%skey %s %s returned incorrect signature type",
			    loc, sshkey_type(id->ಕೀಲಿ), fp);
			ಅನುವರ್ತ;
		}
		error_fr(r, "signing failed for %s \"%s\"%s",
		    sshkey_type(sign_id->ಕೀಲಿ), sign_id->filename,
		    id->agent_fd != -1 ? " from agent" : "");
		ಗಚ್ಛ out;
	}
	ಯದಿ (slen == 0 || signature == ರಿಕ್ತ) /* shouldn't happen */
		fatal_f("no signature");

	/* append signature */
	ಯದಿ ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_fr(r, "append signature");

#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	/* skip session id and packet type */
	ಯದಿ ((r = sshbuf_consume(b, skip + 1)) != 0)
		fatal_fr(r, "consume");

	/* put remaining data from buffer into packet */
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_putb(ssh, b)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "enqueue request");

	/* success */
	sent = 1;

 out:
	ಮುಕ್ತ(fp);
	ಮುಕ್ತ(alg);
	sshbuf_free(b);
	freezero(signature, slen);
	ಪ್ರತ್ಯಾಗಮ sent;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
send_pubkey_test(ಸಂರಚನಾ ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	u_char *blob = ರಿಕ್ತ;
	ವರ್ಣ *alg = ರಿಕ್ತ;
	size_t bloblen;
	u_int have_sig = 0;
	ಪೂರ್ಣಾಙ್ಕ sent = 0, r;

	ಯದಿ ((alg = ಕೀಲಿ_sig_algorithm(ssh, id->ಕೀಲಿ)) == ರಿಕ್ತ) {
		debug_f("no mutual signature algorithm");
		ಗಚ್ಛ out;
	}

	ಯದಿ ((r = sshkey_to_blob(id->ಕೀಲಿ, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3_f("cannot handle key");
		ಗಚ್ಛ out;
	}
	/* register callback for USERAUTH_PK_OK message */
	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_PK_OK, &ಒಳಹರಿವು_userauth_pk_ok);

	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, have_sig)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, alg)) != 0 ||
	    (r = sshpkt_put_string(ssh, blob, bloblen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	sent = 1;

 out:
	ಮುಕ್ತ(alg);
	ಮುಕ್ತ(blob);
	ಪ್ರತ್ಯಾಗಮ sent;
}

ಸ್ಥಿರ ಸಂರಚನಾ sshkey *
load_identity_file(Identity *id)
{
	ಸಂರಚನಾ sshkey *ಗುಪ್ತ = ರಿಕ್ತ;
	ವರ್ಣ prompt[300], *passphrase, *comment;
	ಪೂರ್ಣಾಙ್ಕ r, quit = 0, i;
	ಸಂರಚನಾ stat st;

	ಯದಿ (stat(id->filename, &st) == -1) {
		do_log2(id->userprovided ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_DEBUG3,
		    "no such identity: %s: %s", id->filename, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	snprintf(prompt, ಪರಿಮಾಣ prompt,
	    "Enter passphrase for key '%.100s': ", id->filename);
	ಪ್ರತಿ (i = 0; i <= options.ಸಂಖ್ಯೆ_of_password_prompts; i++) {
		ಯದಿ (i == 0)
			passphrase = "";
		ಅನ್ಯಥಾ {
			passphrase = read_passphrase(prompt, 0);
			ಯದಿ (*passphrase == '\0') {
				debug2("no passphrase given, try next key");
				ಮುಕ್ತ(passphrase);
				ಭಙ್ಗ;
			}
		}
		ವಿಕಲ್ಪ ((r = sshkey_load_private_type(ಕೀಲಿ_UNSPEC, id->filename,
		    passphrase, &ಗುಪ್ತ, &comment))) {
		ಪಕ್ಷ 0:
			ಭಙ್ಗ;
		ಪಕ್ಷ SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE:
			ಯದಿ (options.batch_mode) {
				quit = 1;
				ಭಙ್ಗ;
			}
			ಯದಿ (i != 0)
				debug2("bad passphrase given, try again...");
			ಭಙ್ಗ;
		ಪಕ್ಷ SSH_ERR_SYSTEM_ERROR:
			ಯದಿ (errno == ENOENT) {
				debug2_r(r, "Load key \"%s\"", id->filename);
				quit = 1;
				ಭಙ್ಗ;
			}
			/* FALLTHROUGH */
		ಸ್ವಭಾವ:
			error_r(r, "Load key \"%s\"", id->filename);
			quit = 1;
			ಭಙ್ಗ;
		}
		ಯದಿ (ಗುಪ್ತ != ರಿಕ್ತ && sshkey_is_sk(ಗುಪ್ತ) &&
		    options.sk_provider == ರಿಕ್ತ) {
			debug("key \"%s\" is an authenticator-hosted key, "
			    "but no provider specified", id->filename);
			sshkey_free(ಗುಪ್ತ);
			ಗುಪ್ತ = ರಿಕ್ತ;
			quit = 1;
		}
		ಯದಿ (!quit && (r = sshkey_check_rsa_length(ಗುಪ್ತ,
		    options.required_rsa_size)) != 0) {
			debug_fr(r, "Skipping key %s", id->filename);
			sshkey_free(ಗುಪ್ತ);
			ಗುಪ್ತ = ರಿಕ್ತ;
			quit = 1;
		}
		ಯದಿ (!quit && ಗುಪ್ತ != ರಿಕ್ತ && id->agent_fd == -1 &&
		    !(id->ಕೀಲಿ && id->isprivate))
			maybe_add_ಕೀಲಿ_to_agent(id->filename, ಗುಪ್ತ, comment,
			    passphrase);
		ಯದಿ (i > 0)
			freezero(passphrase, strlen(passphrase));
		ಮುಕ್ತ(comment);
		ಯದಿ (ಗುಪ್ತ != ರಿಕ್ತ || quit)
			ಭಙ್ಗ;
	}
	ಪ್ರತ್ಯಾಗಮ ಗುಪ್ತ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಕೀಲಿ_type_allowed(ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *allowlist)
{
	ಯದಿ (match_pattern_list(sshkey_ssh_name(ಕೀಲಿ), allowlist, 0) == 1)
		ಪ್ರತ್ಯಾಗಮ 1;

	/* RSA keys/certs might be allowed by alternate signature types */
	ವಿಕಲ್ಪ (ಕೀಲಿ->type) {
	ಪಕ್ಷ ಕೀಲಿ_RSA:
		ಯದಿ (match_pattern_list("rsa-sha2-512", allowlist, 0) == 1)
			ಪ್ರತ್ಯಾಗಮ 1;
		ಯದಿ (match_pattern_list("rsa-sha2-256", allowlist, 0) == 1)
			ಪ್ರತ್ಯಾಗಮ 1;
		ಭಙ್ಗ;
	ಪಕ್ಷ ಕೀಲಿ_RSA_CERT:
		ಯದಿ (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			ಪ್ರತ್ಯಾಗಮ 1;
		ಯದಿ (match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			ಪ್ರತ್ಯಾಗಮ 1;
		ಭಙ್ಗ;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಕೀಲಿ_type_allowed_by_config(ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಪ್ರತ್ಯಾಗಮ ಕೀಲಿ_type_allowed(ಕೀಲಿ, options.pubkey_accepted_algos);
}

/* obtain a list of keys from the agent */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
get_agent_identities(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ *agent_fdp,
    ಸಂರಚನಾ ssh_identitylist **idlistp)
{
	ಪೂರ್ಣಾಙ್ಕ r, agent_fd;
	ಸಂರಚನಾ ssh_identitylist *idlist;

	ಯದಿ ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		ಯದಿ (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ (ssh != ರಿಕ್ತ && ssh->kex != ರಿಕ್ತ) {
		ಯದಿ ((r = ssh_agent_bind_hostkey(agent_fd, ssh->kex->initial_hostkey,
		    ssh->kex->session_id, ssh->kex->initial_sig, 0)) == 0)
			debug_f("bound agent to hostkey");
		ಅನ್ಯಥಾ
			debug2_fr(r, "ssh_agent_bind_hostkey");
	}

	ಯದಿ ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		close(agent_fd);
		ಪ್ರತ್ಯಾಗಮ r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * Returns nonzero if the certificate extensions/critical-options section
 * has the specified option present, zero otherwise.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
cert_has_option(ಸಂರಚನಾ sshbuf *oblob, ಧ್ರುವ ವರ್ಣ *target)
{
	ಸಂರಚನಾ sshbuf *c = ರಿಕ್ತ, *data = ರಿಕ್ತ;
	ವರ್ಣ *name = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, found = 0;

	ಯದಿ (oblob == ರಿಕ್ತ || (c = sshbuf_fromb(oblob)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯಾವತ್ (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = ರಿಕ್ತ;
		ಮುಕ್ತ(name);
		name = ರಿಕ್ತ;
		ಯದಿ ((r = sshbuf_get_cstring(c, &name, ರಿಕ್ತ)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0)
			ಭಙ್ಗ;
		ಯದಿ (strcmp(name, target) == 0) {
			found = 1;
			ಭಙ್ಗ;
		}
	}
	sshbuf_free(data);
	ಮುಕ್ತ(name);
	sshbuf_free(c);
	ಪ್ರತ್ಯಾಗಮ found;
}

/*
 * Returns an integer describing the priority of the identity
 * within its group. Lower numbers are higher priority.
 */
#define MAX_ID_PRIORITY 3
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
identity_prioritise(ಸಂರಚನಾ identity *id)
{
	ಯದಿ (id == ರಿಕ್ತ || id->ಕೀಲಿ == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 3;
	ಯದಿ (!sshkey_is_cert(id->ಕೀಲಿ) || id->ಕೀಲಿ->cert == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 3;
	ಯದಿ (sshkey_is_sk(id->ಕೀಲಿ) &&
	    cert_has_option(id->ಕೀಲಿ->cert->critical, "verify-required"))
		ಪ್ರತ್ಯಾಗಮ 2;
	ಯದಿ (sshkey_is_sk(id->ಕೀಲಿ) &&
	    cert_has_option(id->ಕೀಲಿ->cert->extensions, "no-touch-required"))
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
order_identities_by_prio(ಸಂರಚನಾ idlist *list)
{
	ಸಂರಚನಾ idlist prio[MAX_ID_PRIORITY + 1], sorted;
	ಸಂರಚನಾ identity *id, *tmp, *dummy;
	ಪೂರ್ಣಾಙ್ಕ p;

	ಪ್ರತಿ (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_INIT(&prio[p]);
	TAILQ_INIT(&sorted);

	TAILQ_FOREACH_SAFE(id, list, next, tmp) {
		ಯದಿ (id->userprovided)
			ಅನುವರ್ತ;
		dummy = xcalloc(1, ಪರಿಮಾಣ(*dummy));
		dummy->userprovided = -1;
		TAILQ_INSERT_BEFORE(id, dummy, next);
		TAILQ_REMOVE(list, id, next);
		p = identity_prioritise(id);
		ಯದಿ (p < 0 || p > MAX_ID_PRIORITY)
			fatal_f("internal error: bad priority");
		TAILQ_INSERT_TAIL(&prio[p], id, next);
	}
	ಪ್ರತಿ (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_CONCAT(&sorted, &prio[p], next);

	TAILQ_FOREACH_SAFE(id, list, next, tmp) {
		ಯದಿ (id->userprovided != -1)
			ಅನುವರ್ತ;
		ಸಂರಚನಾ identity *s = TAILQ_FIRST(&sorted);
		TAILQ_REMOVE(&sorted, s, next);
		TAILQ_INSERT_BEFORE(id, s, next);
		TAILQ_REMOVE(list, id, next);
		ಮುಕ್ತ(id);
	}
}

/*
 * try keys in the following order:
 *	1. certificates listed in the config file
 *	2. agent keys that are found in the config file
 *	3. other agent keys
 *	4. PKCS#11 keys that are found in the config file
 *	5. keys that are only listed in the config file
 */
ಸ್ಥಿರ ಶೂನ್ಯ
pubkey_prepare(ಸಂರಚನಾ ssh *ssh, Authctxt *authctxt)
{
	ಸಂರಚನಾ identity *id, *id2, *tmp;
	ಸಂರಚನಾ idlist agent, files, certs, agent_ಕೀಲಿಗಳು, *preferred;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ;
	ಪೂರ್ಣಾಙ್ಕ disallowed, agent_fd = -1, i, r, found;
	size_t j;
	ಸಂರಚನಾ ssh_identitylist *idlist;
	ವರ್ಣ *cp, *ident;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	TAILQ_INIT(&certs);	/* certificates specified by user */
	TAILQ_INIT(&agent_ಕೀಲಿಗಳು); /* keys supported by the agent */
	preferred = &authctxt->ಕೀಲಿಗಳು;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_identity_files; i++) {
		ಕೀಲಿ = options.identity_ಕೀಲಿಗಳು[i];
		ಯದಿ (ಕೀಲಿ && ಕೀಲಿ->cert &&
		    ಕೀಲಿ->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			ಅನುವರ್ತ;
		}
		ಯದಿ (ಕೀಲಿ && sshkey_is_sk(ಕೀಲಿ) && options.sk_provider == ರಿಕ್ತ) {
			debug_f("ignoring authenticator-hosted key %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			ಅನುವರ್ತ;
		}
		options.identity_ಕೀಲಿಗಳು[i] = ರಿಕ್ತ;
		id = xcalloc(1, ಪರಿಮಾಣ(*id));
		id->agent_fd = -1;
		id->ಕೀಲಿ = ಕೀಲಿ;
		id->filename = xstrdup(options.identity_files[i]);
		id->userprovided = options.identity_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, next);
	}

	/* list of certificates specified by user */
	ಪ್ರತಿ (i = 0; i < options.ಅಂಕೆ_certificate_files; i++) {
		ಕೀಲಿ = options.certificates[i];
		ಯದಿ (!sshkey_is_cert(ಕೀಲಿ) || ಕೀಲಿ->cert == ರಿಕ್ತ ||
		    ಕೀಲಿ->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			ಅನುವರ್ತ;
		}
		ಯದಿ (ಕೀಲಿ && sshkey_is_sk(ಕೀಲಿ) && options.sk_provider == ರಿಕ್ತ) {
			debug_f("ignoring authenticator-hosted key "
			    "certificate %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			ಅನುವರ್ತ;
		}
		id = xcalloc(1, ಪರಿಮಾಣ(*id));
		id->agent_fd = -1;
		id->ಕೀಲಿ = ಕೀಲಿ;
		id->filename = xstrdup(options.certificate_files[i]);
		id->userprovided = options.certificate_file_userprovided[i];
		TAILQ_INSERT_TAIL(&certs, id, next);
	}
	order_identities_by_prio(&certs);
	TAILQ_CONCAT(preferred, &certs, next);

	/* list of keys supported by the agent */
	ಯದಿ ((r = get_agent_identities(ssh, &agent_fd, &idlist)) == 0) {
		ಪ್ರತಿ (j = 0; j < idlist->nkeys; j++) {
			ಯದಿ ((r = sshkey_check_rsa_length(idlist->ಕೀಲಿಗಳು[j],
			    options.required_rsa_size)) != 0) {
				debug_fr(r, "ignoring %s agent key",
				    sshkey_ssh_name(idlist->ಕೀಲಿಗಳು[j]));
				ಅನುವರ್ತ;
			}
			found = 0;
			TAILQ_FOREACH(id, &files, next) {
				/*
				 * agent keys from the config file are
				 * preferred
				 */
				ಯದಿ (sshkey_equal(idlist->ಕೀಲಿಗಳು[j], id->ಕೀಲಿ)) {
					TAILQ_REMOVE(&files, id, next);
					TAILQ_INSERT_TAIL(&agent_ಕೀಲಿಗಳು, id, next);
					id->agent_fd = agent_fd;
					found = 1;
					ಭಙ್ಗ;
				}
			}
			ಯದಿ (!found && !options.identities_only) {
				id = xcalloc(1, ಪರಿಮಾಣ(*id));
				/* XXX "steals" key/comment from idlist */
				id->ಕೀಲಿ = idlist->ಕೀಲಿಗಳು[j];
				id->filename = idlist->comments[j];
				idlist->ಕೀಲಿಗಳು[j] = ರಿಕ್ತ;
				idlist->comments[j] = ರಿಕ್ತ;
				id->agent_fd = agent_fd;
				TAILQ_INSERT_TAIL(&agent, id, next);
			}
		}
		ssh_free_identitylist(idlist);
		/* append remaining agent keys */
		TAILQ_CONCAT(&agent_ಕೀಲಿಗಳು, &agent, next);
		order_identities_by_prio(&agent_ಕೀಲಿಗಳು);
		TAILQ_CONCAT(preferred, &agent_ಕೀಲಿಗಳು, next);
		authctxt->agent_fd = agent_fd;
	}
	/* Prefer PKCS11 keys that are explicitly listed */
	TAILQ_FOREACH_SAFE(id, &files, next, tmp) {
		ಯದಿ (id->ಕೀಲಿ == ರಿಕ್ತ || (id->ಕೀಲಿ->flags & SSHKEY_FLAG_EXT) == 0)
			ಅನುವರ್ತ;
		found = 0;
		TAILQ_FOREACH(id2, &files, next) {
			ಯದಿ (id2->ಕೀಲಿ == ರಿಕ್ತ ||
			    (id2->ಕೀಲಿ->flags & SSHKEY_FLAG_EXT) != 0)
				ಅನುವರ್ತ;
			ಯದಿ (sshkey_equal(id->ಕೀಲಿ, id2->ಕೀಲಿ)) {
				TAILQ_REMOVE(&files, id, next);
				TAILQ_INSERT_TAIL(preferred, id, next);
				found = 1;
				ಭಙ್ಗ;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		ಯದಿ (!found && options.identities_only) {
			TAILQ_REMOVE(&files, id, next);
			freezero(id, ಪರಿಮಾಣ(*id));
		}
	}
	order_identities_by_prio(&files);
	/* append remaining keys from the config file */
	TAILQ_CONCAT(preferred, &files, next);
	/* finally, filter by PubkeyAcceptedAlgorithms */
	TAILQ_FOREACH_SAFE(id, preferred, next, id2) {
		disallowed = 0;
		cp = ರಿಕ್ತ;
		ಯದಿ (id->ಕೀಲಿ == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		ಯದಿ (!ಕೀಲಿ_type_allowed_by_config(id->ಕೀಲಿ)) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not in PubkeyAcceptedAlgorithms",
			    sshkey_ssh_name(id->ಕೀಲಿ), id->filename);
			disallowed = 1;
		} ಅನ್ಯಥಾ ಯದಿ (ssh != ರಿಕ್ತ && ssh->kex != ರಿಕ್ತ &&
		    ssh->kex->server_sig_algs != ರಿಕ್ತ &&
		    (cp = ಕೀಲಿ_sig_algorithm(ssh, id->ಕೀಲಿ)) == ರಿಕ್ತ) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not supported by server",
			    sshkey_ssh_name(id->ಕೀಲಿ), id->filename);
			disallowed = 1;
		}
		ಮುಕ್ತ(cp);
		ಯದಿ (!disallowed)
			ಅನುವರ್ತ;
		/* remove key */
		TAILQ_REMOVE(preferred, id, next);
		sshkey_free(id->ಕೀಲಿ);
		ಮುಕ್ತ(id->filename);
		freezero(id, ಪರಿಮಾಣ(*id));
	}
	/* List the keys we plan on using */
	TAILQ_FOREACH_SAFE(id, preferred, next, id2) {
		ident = format_identity(id);
		debug("Will attempt key: %s", ident);
		ಮುಕ್ತ(ident);
	}
	debug2_f("done");
}

ಸ್ಥಿರ ಶೂನ್ಯ
pubkey_cleanup(ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;

	ಯದಿ (authctxt->agent_fd != -1) {
		ssh_close_authentication_socket(authctxt->agent_fd);
		authctxt->agent_fd = -1;
	}
	ಪ್ರತಿ (id = TAILQ_FIRST(&authctxt->ಕೀಲಿಗಳು); id;
	    id = TAILQ_FIRST(&authctxt->ಕೀಲಿಗಳು)) {
		TAILQ_REMOVE(&authctxt->ಕೀಲಿಗಳು, id, next);
		sshkey_free(id->ಕೀಲಿ);
		ಮುಕ್ತ(id->filename);
		ಮುಕ್ತ(id);
	}
}

ಶೂನ್ಯ
pubkey_dump(ಸಂರಚನಾ ssh *ssh)
{
	Authctxt authctxt;
	Identity *id;
	ವರ್ಣ *ident;

	memset(&authctxt, 0, ಪರಿಮಾಣ(authctxt));
	authctxt.agent_fd = -1;
	ssh->authctxt = &authctxt;

	pubkey_prepare(ssh, &authctxt);
	TAILQ_FOREACH(id, &authctxt.ಕೀಲಿಗಳು, next) {
		ident = format_identity(id);
		fprintf(stdout, "%s\n", ident);
		ಮುಕ್ತ(ident);
	}
	pubkey_cleanup(ssh);
	ssh->authctxt = ರಿಕ್ತ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
pubkey_reset(Authctxt *authctxt)
{
	Identity *id;

	TAILQ_FOREACH(id, &authctxt->ಕೀಲಿಗಳು, next)
		id->tried = 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
userauth_pubkey(ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;
	ಪೂರ್ಣಾಙ್ಕ sent = 0;
	ವರ್ಣ *ident;
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ prepared;

	ಯದಿ (!prepared) {
		pubkey_prepare(ssh, authctxt);
		prepared = 1;
	}

	ಯಾವತ್ ((id = TAILQ_FIRST(&authctxt->ಕೀಲಿಗಳು))) {
		ಯದಿ (id->tried++)
			ಪ್ರತ್ಯಾಗಮ (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->ಕೀಲಿಗಳು, id, next);
		TAILQ_INSERT_TAIL(&authctxt->ಕೀಲಿಗಳು, id, next);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		ಯದಿ (id->ಕೀಲಿ != ರಿಕ್ತ) {
			ident = format_identity(id);
			debug("Offering public key: %s", ident);
			ಮುಕ್ತ(ident);
			sent = send_pubkey_test(ssh, id);
		} ಅನ್ಯಥಾ {
			debug("Trying private key: %s", id->filename);
			id->ಕೀಲಿ = load_identity_file(id);
			ಯದಿ (id->ಕೀಲಿ != ರಿಕ್ತ) {
				id->isprivate = 1;
				sent = sign_and_send_pubkey(ssh, id);
				sshkey_free(id->ಕೀಲಿ);
				id->ಕೀಲಿ = ರಿಕ್ತ;
				id->isprivate = 0;
			}
		}
		ಯದಿ (sent)
			ಪ್ರತ್ಯಾಗಮ (sent);
	}
	ಪ್ರತ್ಯಾಗಮ (0);
}

/*
 * Send userauth request message specifying keyboard-interactive method.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
userauth_kbdint(ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (authctxt->attempt_kbdint++ >= options.ಸಂಖ್ಯೆ_of_password_prompts)
		ಪ್ರತ್ಯಾಗಮ 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	ಯದಿ (authctxt->attempt_kbdint > 1 && !authctxt->info_req_seen) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_INFO_REQUEST, ರಿಕ್ತ);
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	debug2("userauth_kbdint");
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||		/* lang */
	    (r = sshpkt_put_cstring(ssh, options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_set(ssh, SSH2_ಸಂದೇಶ_USERAUTH_INFO_REQUEST, &ಒಳಹರಿವು_userauth_info_req);
	ಪ್ರತ್ಯಾಗಮ 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ಒಳಹರಿವು_userauth_info_req(ಪೂರ್ಣಾಙ್ಕ type, uint32_t seq, ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ವರ್ಣ *name = ರಿಕ್ತ, *inst = ರಿಕ್ತ, *lang = ರಿಕ್ತ, *prompt = ರಿಕ್ತ;
	ವರ್ಣ *display_prompt = ರಿಕ್ತ, *response = ರಿಕ್ತ;
	u_char echo = 0;
	u_int ಅಂಕೆ_prompts, i;
	ಪೂರ್ಣಾಙ್ಕ r, addnl;
	size_t len;

	debug2_f("entering");

	ಯದಿ (authctxt == ರಿಕ್ತ)
		fatal_f("no authentication context");

	authctxt->info_req_seen = 1;

	ಯದಿ ((r = sshpkt_get_cstring(ssh, &name, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &inst, ರಿಕ್ತ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ರಿಕ್ತ)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((len = strlen(name)) > 0) {
		addnl = name[len] != '\n';
		fmprintf(stderr, "%s%s", name, addnl ? "\n" : "");
	}
	ಯದಿ ((len = strlen(inst)) > 0) {
		addnl = inst[len] != '\n';
		fmprintf(stderr, "%s%s", inst, addnl ? "\n" : "");
	}

	ಯದಿ ((r = sshpkt_get_u32(ssh, &ಅಂಕೆ_prompts)) != 0)
		ಗಚ್ಛ out;
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_USERAUTH_INFO_RESPONSE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, ಅಂಕೆ_prompts)) != 0)
		ಗಚ್ಛ out;

	debug2_f("num_prompts %d", ಅಂಕೆ_prompts);
	ಪ್ರತಿ (i = 0; i < ಅಂಕೆ_prompts; i++) {
		ಯದಿ ((r = sshpkt_get_cstring(ssh, &prompt, ರಿಕ್ತ)) != 0 ||
		    (r = sshpkt_get_u8(ssh, &echo)) != 0)
			ಗಚ್ಛ out;
		ಯದಿ (asmprintf(&display_prompt, INT_MAX, ರಿಕ್ತ, "(%s@%s) %s",
		    authctxt->server_user, options.host_ಕೀಲಿ_alias ?
		    options.host_ಕೀಲಿ_alias : authctxt->host, prompt) == -1)
			fatal_f("asmprintf failed");
		response = read_passphrase(display_prompt, echo ? RP_ECHO : 0);
		ಯದಿ ((r = sshpkt_put_cstring(ssh, response)) != 0)
			ಗಚ್ಛ out;
		freezero(response, strlen(response));
		ಮುಕ್ತ(prompt);
		ಮುಕ್ತ(display_prompt);
		display_prompt = response = prompt = ರಿಕ್ತ;
	}
	/* done with parsing incoming message. */
	ಯದಿ ((r = sshpkt_get_end(ssh)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0)
		ಗಚ್ಛ out;
	r = sshpkt_send(ssh);
 out:
	ಯದಿ (response)
		freezero(response, strlen(response));
	ಮುಕ್ತ(prompt);
	ಮುಕ್ತ(display_prompt);
	ಮುಕ್ತ(name);
	ಮುಕ್ತ(inst);
	ಮುಕ್ತ(lang);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_keysign(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ sshkey *ಕೀಲಿ, u_char **sigp, size_t *lenp,
    ಧ್ರುವ u_char *data, size_t datalen)
{
	ಸಂರಚನಾ sshbuf *b;
	ಸಂರಚನಾ stat st;
	pid_t pid;
	ಪೂರ್ಣಾಙ್ಕ r, to[2], from[2], status;
	ಪೂರ್ಣಾಙ್ಕ sock = ssh_packet_get_connection_in(ssh);
	u_char rversion = 0, version = 2;
	ಶೂನ್ಯ (*osigchld)(ಪೂರ್ಣಾಙ್ಕ);

	*sigp = ರಿಕ್ತ;
	*lenp = 0;

	ಯದಿ (stat(PATH_SSH_ಕೀಲಿ_SIGN, &st) == -1) {
		error_f("not installed: %s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (fflush(stdout) != 0) {
		error_f("fflush: %s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (pipe(to) == -1) {
		error_f("pipe: %s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ (pipe(from) == -1) {
		error_f("pipe: %s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಯದಿ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ಯದಿ (pid == 0) {
		close(from[0]);
		ಯದಿ (dup2(from[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(to[1]);
		ಯದಿ (dup2(to[0], STDIN_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(from[1]);
		close(to[0]);

		ಯದಿ (dup2(sock, STDERR_FILENO + 1) == -1)
			fatal_f("dup2: %s", strerror(errno));
		sock = STDERR_FILENO + 1;
		ಯದಿ (fcntl(sock, F_SETFD, 0) == -1) /* keep the socket on exec */
			debug3_f("fcntl F_SETFD: %s", strerror(errno));
		closefrom(sock + 1);

		debug3_f("[child] pid=%ld, exec %s",
		    (long)getpid(), PATH_SSH_ಕೀಲಿ_SIGN);
		execl(PATH_SSH_ಕೀಲಿ_SIGN, PATH_SSH_ಕೀಲಿ_SIGN, (ವರ್ಣ *)ರಿಕ್ತ);
		fatal_f("exec(%s): %s", PATH_SSH_ಕೀಲಿ_SIGN,
		    strerror(errno));
	}
	close(from[1]);
	close(to[0]);
	sock = STDERR_FILENO + 1;

	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	/* send # of sock, data to be signed */
	ಯದಿ ((r = sshbuf_put_u32(b, sock)) != 0 ||
	    (r = sshbuf_put_string(b, data, datalen)) != 0)
		fatal_fr(r, "buffer error");
	ಯದಿ (ssh_ಸಂದೇಶ_send(to[1], version, b) == -1)
		fatal_f("couldn't send request");
	sshbuf_reset(b);
	r = ssh_ಸಂದೇಶ_recv(from[0], b);
	close(from[0]);
	close(to[1]);
	ಯದಿ (r < 0) {
		error_f("no reply");
		ಗಚ್ಛ fail;
	}

	errno = 0;
	ಯಾವತ್ (waitpid(pid, &status, 0) == -1) {
		ಯದಿ (errno != EINTR) {
			error_f("waitpid %ld: %s", (long)pid, strerror(errno));
			ಗಚ್ಛ fail;
		}
	}
	ಯದಿ (!WIFEXITED(status)) {
		error_f("exited abnormally");
		ಗಚ್ಛ fail;
	}
	ಯದಿ (WEXITSTATUS(status) != 0) {
		error_f("exited with status %d", WEXITSTATUS(status));
		ಗಚ್ಛ fail;
	}
	ಯದಿ ((r = sshbuf_get_u8(b, &rversion)) != 0) {
		error_fr(r, "buffer error");
		ಗಚ್ಛ fail;
	}
	ಯದಿ (rversion != version) {
		error_f("bad version");
		ಗಚ್ಛ fail;
	}
	ಯದಿ ((r = sshbuf_get_string(b, sigp, lenp)) != 0) {
		error_fr(r, "buffer error");
 fail:
		ssh_signal(SIGCHLD, osigchld);
		sshbuf_free(b);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ssh_signal(SIGCHLD, osigchld);
	sshbuf_free(b);

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
userauth_hostbased(ಸಂರಚನಾ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ಸಂರಚನಾ sshkey *ಗುಪ್ತ = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	u_char *sig = ರಿಕ್ತ, *keyblob = ರಿಕ್ತ;
	ವರ್ಣ *fp = ರಿಕ್ತ, *chost = ರಿಕ್ತ, *lname = ರಿಕ್ತ;
	size_t siglen = 0, keylen = 0;
	ಪೂರ್ಣಾಙ್ಕ i, r, success = 0;

	ಯದಿ (authctxt->ktypes == ರಿಕ್ತ) {
		authctxt->oktypes = xstrdup(options.hostbased_accepted_algos);
		authctxt->ktypes = authctxt->oktypes;
	}

	/*
	 * Work through each listed type pattern in HostbasedAcceptedAlgorithms,
	 * trying each hostkey that matches the type in turn.
	 */
	ಪ್ರತಿ (;;) {
		ಯದಿ (authctxt->active_ktype == ರಿಕ್ತ)
			authctxt->active_ktype = strsep(&authctxt->ktypes, ",");
		ಯದಿ (authctxt->active_ktype == ರಿಕ್ತ ||
		    *authctxt->active_ktype == '\0')
			ಭಙ್ಗ;
		debug3_f("trying key type %s", authctxt->active_ktype);

		/* check for a useful key */
		ಗುಪ್ತ = ರಿಕ್ತ;
		ಪ್ರತಿ (i = 0; i < authctxt->sensitive->nkeys; i++) {
			ಯದಿ (authctxt->sensitive->ಕೀಲಿಗಳು[i] == ರಿಕ್ತ ||
			    authctxt->sensitive->ಕೀಲಿಗಳು[i]->type == ಕೀಲಿ_UNSPEC)
				ಅನುವರ್ತ;
			ಯದಿ (!sshkey_match_keyname_to_sigalgs(
			    sshkey_ssh_name(authctxt->sensitive->ಕೀಲಿಗಳು[i]),
			    authctxt->active_ktype))
				ಅನುವರ್ತ;
			/* we take and free the key */
			ಗುಪ್ತ = authctxt->sensitive->ಕೀಲಿಗಳು[i];
			authctxt->sensitive->ಕೀಲಿಗಳು[i] = ರಿಕ್ತ;
			ಭಙ್ಗ;
		}
		/* Found one */
		ಯದಿ (ಗುಪ್ತ != ರಿಕ್ತ)
			ಭಙ್ಗ;
		/* No more keys of this type; advance */
		authctxt->active_ktype = ರಿಕ್ತ;
	}
	ಯದಿ (ಗುಪ್ತ == ರಿಕ್ತ) {
		ಮುಕ್ತ(authctxt->oktypes);
		authctxt->oktypes = authctxt->ktypes = ರಿಕ್ತ;
		authctxt->active_ktype = ರಿಕ್ತ;
		debug("No more client hostkeys for hostbased authentication.");
		ಗಚ್ಛ out;
	}

	ಯದಿ ((fp = sshkey_fingerprint(ಗುಪ್ತ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ರಿಕ್ತ) {
		error_f("sshkey_fingerprint failed");
		ಗಚ್ಛ out;
	}
	debug_f("trying hostkey %s %s using sigalg %s",
	    sshkey_ssh_name(ಗುಪ್ತ), fp, authctxt->active_ktype);

	/* figure out a name for the client host */
	lname = get_local_name(ssh_packet_get_connection_in(ssh));
	ಯದಿ (lname == ರಿಕ್ತ) {
		error_f("cannot get local ipaddr/name");
		ಗಚ್ಛ out;
	}

	/* XXX sshbuf_put_stringf? */
	xasprintf(&chost, "%s.", lname);
	debug2_f("chost %s", chost);

	/* construct data */
	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ) {
		error_f("sshbuf_new failed");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshkey_to_blob(ಗುಪ್ತ, &keyblob, &keylen)) != 0) {
		error_fr(r, "sshkey_to_blob");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->method->name)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->active_ktype)) != 0 ||
	    (r = sshbuf_put_string(b, keyblob, keylen)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->local_user)) != 0) {
		error_fr(r, "buffer error");
		ಗಚ್ಛ out;
	}

#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	ಯದಿ ((r = ssh_keysign(ssh, ಗುಪ್ತ, &sig, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b))) != 0) {
		error("sign using hostkey %s %s failed",
		    sshkey_ssh_name(ಗುಪ್ತ), fp);
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshpkt_start(ssh, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->active_ktype)) != 0 ||
	    (r = sshpkt_put_string(ssh, keyblob, keylen)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, chost)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->local_user)) != 0 ||
	    (r = sshpkt_put_string(ssh, sig, siglen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "packet error");
		ಗಚ್ಛ out;
	}
	success = 1;

 out:
	ಯದಿ (sig != ರಿಕ್ತ)
		freezero(sig, siglen);
	ಮುಕ್ತ(keyblob);
	ಮುಕ್ತ(lname);
	ಮುಕ್ತ(fp);
	ಮುಕ್ತ(chost);
	sshkey_free(ಗುಪ್ತ);
	sshbuf_free(b);

	ಪ್ರತ್ಯಾಗಮ success;
}

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
authmethod_is_enabled(Authmethod *method)
{
	ಯದಿ (method == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	/* return false if options indicate this method is disabled */
	ಯದಿ  (method->enabled == ರಿಕ್ತ || *method->enabled == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	ಯದಿ  (method->batch_flag != ರಿಕ್ತ && *method->batch_flag != 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ Authmethod *
authmethod_lookup(ಧ್ರುವ ವರ್ಣ *name)
{
	Authmethod *method = ರಿಕ್ತ;
	ಯದಿ (name != ರಿಕ್ತ)
		ಪ್ರತಿ (method = authmethods; method->name != ರಿಕ್ತ; method++)
			ಯದಿ (strcmp(name, method->name) == 0)
				ಪ್ರತ್ಯಾಗಮ method;
	debug2("Unrecognized authentication method name: %s", name ? name : "NULL");
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

/* XXX internal state */
ಸ್ಥಿರ Authmethod *current = ರಿಕ್ತ;
ಸ್ಥಿರ ವರ್ಣ *supported = ರಿಕ್ತ;
ಸ್ಥಿರ ವರ್ಣ *preferred = ರಿಕ್ತ;

/*
 * Given the authentication method list sent by the server, return the
 * next method we should try.  If the server initially sends a nil list,
 * use a built-in default list.
 */
ಸ್ಥಿರ Authmethod *
authmethod_get(ವರ್ಣ *authlist)
{
	ವರ್ಣ *name = ರಿಕ್ತ;
	u_int next;

	/* Use a suitable default if we're passed a nil list.  */
	ಯದಿ (authlist == ರಿಕ್ತ || strlen(authlist) == 0)
		authlist = options.preferred_authentications;

	ಯದಿ (supported == ರಿಕ್ತ || strcmp(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		ಮುಕ್ತ(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = ರಿಕ್ತ;
	} ಅನ್ಯಥಾ ಯದಿ (current != ರಿಕ್ತ && authmethod_is_enabled(current))
		ಪ್ರತ್ಯಾಗಮ current;

	ಪ್ರತಿ (;;) {
		ಯದಿ ((name = match_list(preferred, supported, &next)) == ರಿಕ್ತ) {
			debug("No more authentication methods to try.");
			current = ರಿಕ್ತ;
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
		}
		preferred += next;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		ಯದಿ ((current = authmethod_lookup(name)) != ರಿಕ್ತ &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("Next authentication method: %s", name);
			ಮುಕ್ತ(name);
			ಪ್ರತ್ಯಾಗಮ current;
		}
		ಮುಕ್ತ(name);
	}
}

ಸ್ಥಿರ ವರ್ಣ *
authmethods_get(ಶೂನ್ಯ)
{
	Authmethod *method = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *b;
	ವರ್ಣ *list;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ)
		fatal_f("sshbuf_new failed");
	ಪ್ರತಿ (method = authmethods; method->name != ರಿಕ್ತ; method++) {
		ಯದಿ (authmethod_is_enabled(method)) {
			ಯದಿ ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", method->name)) != 0)
				fatal_fr(r, "buffer error");
		}
	}
	ಯದಿ ((list = sshbuf_dup_string(b)) == ರಿಕ್ತ)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ list;
}
