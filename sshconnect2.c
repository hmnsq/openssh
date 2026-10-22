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
#ಆದರೆ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#ಅನ್ತರ್ಭಾವ <vis.h>
#ಆದರೆ_ಅಂತ್ಯ

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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#ಆದರೆ_ಅಂತ್ಯ

/* import */
ಬಾಹ್ಯ Options options;

/*
 * SSH2 key exchange
 */

ಸ್ಥಿರ ಅಕ್ಷರ *xxx_host;
ಸ್ಥಿರ ರಚನೆ sockaddr_storage xxx_hostaddr;
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_conn_info *xxx_conn_info;
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಕೀಲಿ_type_allowed(ರಚನೆ sshkey *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
verify_host_ಕೀಲಿ_callback(ರಚನೆ sshkey *hostkey, ರಚನೆ ssh *ssh)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshkey_check_rsa_ಉದ್ದಳತೆ(hostkey,
	    options.required_rsa_ಗಾತ್ರ)) != 0)
		fatal_r(r, "Bad server host key");
	ಆದರೆ (!ಕೀಲಿ_type_allowed(hostkey, options.hostkeyalgorithms)) {
		fatal("Server host key %s not in HostKeyAlgorithms",
		    sshkey_ssh_name(hostkey));
	}
	ಆದರೆ (verify_host_ಕೀಲಿ(xxx_host, (ರಚನೆ sockaddr *)&xxx_hostaddr, hostkey,
	    xxx_conn_info) != 0)
		fatal("Host key verification failed.");
	ಹಿಂತಿರುಗಿ 0;
}

/* Returns the first item from a comma-separated algorithm list */
ಸ್ಥಿರ ಅಕ್ಷರ *
ಮೊದಲ_alg(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *algs)
{
	ಅಕ್ಷರ *ret, *cp;

	ret = xstrdup(algs);
	ಆದರೆ ((cp = strchr(ret, ',')) != ಖಾಲಿ)
		*cp = '\0';
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಅಕ್ಷರ *
ಕ್ರಮ_hostkeyalgs(ಅಕ್ಷರ *host, ರಚನೆ sockaddr *hostaddr, u_short ಪೋರ್ಟ್,
    ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_conn_info *cinfo)
{
	ಅಕ್ಷರ *oavail = ಖಾಲಿ, *avail = ಖಾಲಿ, *ಮೊದಲ = ಖಾಲಿ, *ಕೊನೆಯ = ಖಾಲಿ;
	ಅಕ್ಷರ *alg = ಖಾಲಿ, *hostname = ಖಾಲಿ, *ret = ಖಾಲಿ, *ಉತ್ತಮ = ಖಾಲಿ;
	ಗಾತ್ರ_t maxlen;
	ರಚನೆ hostkeys *hostkeys = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, ಪೋರ್ಟ್, &hostname, ಖಾಲಿ);
	hostkeys = init_hostkeys();
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_user_hostfiles; i++)
		ತುಂಬು_hostkeys(hostkeys, hostname, options.user_hostfiles[i], 0);
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_system_hostfiles; i++) {
		ತುಂಬು_hostkeys(hostkeys, hostname,
		    options.system_hostfiles[i], 0);
	}
	ಆದರೆ (options.ತಿಳಿದ_hosts_command != ಖಾಲಿ) {
		ತುಂಬು_hostkeys_command(hostkeys, options.ತಿಳಿದ_hosts_command,
		    "ORDER", cinfo, ಖಾಲಿ, hostname);
	}
	/*
	 * If a plain public key exists that matches the type of the best
	 * preference HostkeyAlgorithms, then use the whole list as is.
	 * Note that we ignore whether the best preference algorithm is a
	 * certificate type, as sshconnect.c will downgrade certs to
	 * plain keys if necessary.
	 */
	ಉತ್ತಮ = ಮೊದಲ_alg(options.hostkeyalgorithms);
	ಆದರೆ (lookup_ಕೀಲಿ_ಒಳ_hostkeys_by_type(hostkeys,
	    sshkey_type_plain(sshkey_type_from_name(ಉತ್ತಮ)),
	    sshkey_ecdsa_nid_from_name(ಉತ್ತಮ), ಖಾಲಿ)) {
		debug3_f("have matching best-preference key type %s, "
		    "using HostkeyAlgorithms verbatim", ಉತ್ತಮ);
		ret = xstrdup(options.hostkeyalgorithms);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/*
	 * Otherwise, prefer the host key algorithms that match known keys
	 * while keeping the ordering of HostkeyAlgorithms as much as possible.
	 */
	oavail = avail = xstrdup(options.hostkeyalgorithms);
	maxlen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(avail) + 1;
	ಮೊದಲ = xmalloc(maxlen);
	ಕೊನೆಯ = xmalloc(maxlen);
	*ಮೊದಲ = *ಕೊನೆಯ = '\0';

#ವ್ಯಾಖ್ಯಾನಿಸು ALG_APPEND(ಗಮ್ಯ, from) \
	ಮಾಡು { \
		ಆದರೆ (*ಗಮ್ಯ != '\0') \
			strlcat(ಗಮ್ಯ, ",", maxlen); \
		strlcat(ಗಮ್ಯ, from, maxlen); \
	} ಆಗ (0)

	ಆಗ ((alg = strsep(&avail, ",")) && *alg != '\0') {
		ಆದರೆ ((ktype = sshkey_type_from_name(alg)) == ಕೀಲಿ_UNSPEC)
			fatal_f("unknown alg %s", alg);
		/*
		 * If we have a @cert-authority marker in known_hosts then
		 * prefer all certificate algorithms.
		 */
		ಆದರೆ (sshkey_type_is_cert(ktype) &&
		    lookup_marker_ಒಳ_hostkeys(hostkeys, MRK_CA)) {
			ALG_APPEND(ಮೊದಲ, alg);
			ಮುಂದುವರಿ;
		}
		/* If the key appears in known_hosts then prefer it */
		ಆದರೆ (lookup_ಕೀಲಿ_ಒಳ_hostkeys_by_type(hostkeys,
		    sshkey_type_plain(ktype),
		    sshkey_ecdsa_nid_from_name(alg), ಖಾಲಿ)) {
			ALG_APPEND(ಮೊದಲ, alg);
			ಮುಂದುವರಿ;
		}
		/* Otherwise, put it last */
		ALG_APPEND(ಕೊನೆಯ, alg);
	}
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ALG_APPEND
	xasprintf(&ret, "%s%s%s", ಮೊದಲ,
	    (*ಮೊದಲ == '\0' || *ಕೊನೆಯ == '\0') ? "" : ",", ಕೊನೆಯ);
	ಆದರೆ (*ಮೊದಲ != '\0')
		debug3_f("prefer hostkeyalgs: %s", ಮೊದಲ);
	ಇಲ್ಲದಿದ್ದರೆ
		debug3_f("no algorithms matched; accept original");
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(ಉತ್ತಮ);
	ಬಿಡುಗಡೆ(ಮೊದಲ);
	ಬಿಡುಗಡೆ(ಕೊನೆಯ);
	ಬಿಡುಗಡೆ(hostname);
	ಬಿಡುಗಡೆ(oavail);
	free_hostkeys(hostkeys);

	ಹಿಂತಿರುಗಿ ret;
}

ಶೂನ್ಯ
ssh_kex2(ರಚನೆ ssh *ssh, ಅಕ್ಷರ *host, ರಚನೆ sockaddr_storage *hostaddr,
    u_short ಪೋರ್ಟ್, ಸ್ಥಿರಾಂಕ ರಚನೆ ssh_conn_info *cinfo)
{
	ಅಕ್ಷರ *myproposal[PROPOSAL_MAX];
	ಅಕ್ಷರ *all_ಕೀಲಿ, *hkalgs = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, use_ತಿಳಿದ_hosts_ಕ್ರಮ = 0;

	xxx_host = xstrdup(host);
	xxx_hostaddr = *hostaddr;
	xxx_conn_info = ssh_conn_info_dup(cinfo);

	ssh_packet_ಗಣ_rekey_limits(ssh, options.rekey_ಎಲ್ಲೆ,
	    options.rekey_interval);

	/*
	 * If the user has not specified HostkeyAlgorithms, or has only
	 * appended or removed algorithms from that list then prefer algorithms
	 * that are in the list that are supported by known_hosts keys.
	 */
	ಆದರೆ (options.hostkeyalgorithms == ಖಾಲಿ ||
	    options.hostkeyalgorithms[0] == '-' ||
	    options.hostkeyalgorithms[0] == '+')
		use_ತಿಳಿದ_hosts_ಕ್ರಮ = 1;

	/* Expand or fill in HostkeyAlgorithms */
	all_ಕೀಲಿ = sshkey_alg_list(0, 0, 1, ',');
	ಆದರೆ ((r = kex_assemble_ಹೆಸರುಗಳು(&options.hostkeyalgorithms,
	    kex_default_pk_alg(), all_ಕೀಲಿ)) != 0)
		fatal_fr(r, "kex_assemble_namelist");
	ಬಿಡುಗಡೆ(all_ಕೀಲಿ);

	ಆದರೆ (use_ತಿಳಿದ_hosts_ಕ್ರಮ) {
		hkalgs = ಕ್ರಮ_hostkeyalgs(host, (ರಚನೆ sockaddr *)hostaddr,
		    ಪೋರ್ಟ್, cinfo);
	}

	kex_proposal_populate_entries(ssh, myproposal,
	    options.kex_algorithms, options.ciphers, options.macs,
	    compression_alg_list(options.compression),
	    hkalgs ? hkalgs : options.hostkeyalgorithms);

	ಬಿಡುಗಡೆ(hkalgs);

	/* start key exchange */
	ಆದರೆ ((r = kex_ಸಿದ್ಧತೆ(ssh, myproposal)) != 0)
		fatal_r(r, "kex_setup");
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#ಆದರೆ_ಅಂತ್ಯ
	ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
	ssh->kex->verify_host_ಕೀಲಿ=&verify_host_ಕೀಲಿ_callback;

	ssh_dispatch_ಸತತ_fatal(ssh, DISPATCH_ಖಂಡ, &ssh->kex->ಮುಗಿದ);
	kex_proposal_free_entries(myproposal);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");
#ಆದರೆ_ಅಂತ್ಯ
}

/*
 * Authenticate user
 */

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ cauthctxt Authctxt;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ cauthmethod Authmethod;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ ತಟಸ್ಥ_2 ತಟಸ್ಥ;
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ idlist Idlist;

ರಚನೆ ತಟಸ್ಥ_2 {
	TAILQ_ENTRY(ತಟಸ್ಥ_2) ಮುಂದಿನ;
	ಪೂರ್ಣಾಂಕ	agent_fd;		/* >=0 if agent supports key */
	ರಚನೆ sshkey	*ಕೀಲಿ;		/* public/private key */
	ಅಕ್ಷರ	*filename;		/* comment for agent-only keys */
	ಪೂರ್ಣಾಂಕ	tried;
	ಪೂರ್ಣಾಂಕ	isprivate;		/* key points to the private key */
	ಪೂರ್ಣಾಂಕ	userprovided;
};
TAILQ_HEAD(idlist, ತಟಸ್ಥ_2);

ರಚನೆ cauthctxt {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *server_user;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *local_user;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *service;
	ರಚನೆ cauthmethod *ವಿಧಾನ;
	sig_atomic_t success;
	ಅಕ್ಷರ *authlist;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
	/* gssapi */
	gss_OID_ಗಣ gss_supported_mechs;
	u_int mech_tried;
#ಆದರೆ_ಅಂತ್ಯ
	/* pubkey */
	ರಚನೆ idlist ಕೀಲಿಗಳು;
	ಪೂರ್ಣಾಂಕ agent_fd;
	/* hostbased */
	Sensitive *sensitive;
	ಅಕ್ಷರ *oktypes, *ktypes;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಸಕ್ರಿಯ_ktype;
	/* kbd-interactive */
	ಪೂರ್ಣಾಂಕ info_req_ನೋಡಿದ;
	ಪೂರ್ಣಾಂಕ attempt_kbdint;
	/* password */
	ಪೂರ್ಣಾಂಕ attempt_passwd;
	/* generic */
	ಶೂನ್ಯ *methoddata;
};

ರಚನೆ cauthmethod {
	ಅಕ್ಷರ	*name;		/* string to compare against server's list */
	ಪೂರ್ಣಾಂಕ	(*userauth)(ರಚನೆ ssh *ssh);
	ಶೂನ್ಯ	(*cleanup)(ರಚನೆ ssh *ssh);
	ಪೂರ್ಣಾಂಕ	*enabled;	/* flag in option struct that enables method */
	ಪೂರ್ಣಾಂಕ	*batch_flag;	/* flag in option struct that disables method */
};

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_userauth_service_accept(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_userauth_success(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_userauth_failure(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_userauth_banner(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_userauth_error(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_userauth_info_req(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_userauth_pk_ok(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_userauth_passwd_changereq(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ userauth_none(ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ userauth_pubkey(ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ userauth_passwd(ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ userauth_kbdint(ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ userauth_hostbased(ರಚನೆ ssh *);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ userauth_gssapi(ರಚನೆ ssh *);
ಸ್ಥಿರ ಶೂನ್ಯ userauth_gssapi_cleanup(ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_gssapi_response(ಪೂರ್ಣಾಂಕ type, uint32_t, ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_gssapi_token(ಪೂರ್ಣಾಂಕ type, uint32_t, ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_gssapi_error(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು_gssapi_errtok(ಪೂರ್ಣಾಂಕ, uint32_t, ರಚನೆ ssh *);
#ಆದರೆ_ಅಂತ್ಯ

ಶೂನ್ಯ	userauth(ರಚನೆ ssh *, ಅಕ್ಷರ *);

ಸ್ಥಿರ ಶೂನ್ಯ pubkey_cleanup(ರಚನೆ ssh *);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ sign_and_send_pubkey(ರಚನೆ ssh *ssh, ತಟಸ್ಥ *);
ಸ್ಥಿರ ಶೂನ್ಯ pubkey_prepare(ರಚನೆ ssh *, Authctxt *);
ಸ್ಥಿರ ಶೂನ್ಯ pubkey_reset(Authctxt *);
ಸ್ಥಿರ ರಚನೆ sshkey *ತುಂಬು_ತಟಸ್ಥ_file(ತಟಸ್ಥ *);

ಸ್ಥಿರ Authmethod *authmethod_get(ಅಕ್ಷರ *authlist);
ಸ್ಥಿರ Authmethod *authmethod_lookup(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name);
ಸ್ಥಿರ ಅಕ್ಷರ *authmethods_get(ಶೂನ್ಯ);

Authmethod authmethods[] = {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		userauth_gssapi_cleanup,
		&options.gss_authentication,
		ಖಾಲಿ},
#ಆದರೆ_ಅಂತ್ಯ
	{"hostbased",
		userauth_hostbased,
		ಖಾಲಿ,
		&options.hostbased_authentication,
		ಖಾಲಿ},
	{"publickey",
		userauth_pubkey,
		ಖಾಲಿ,
		&options.pubkey_authentication,
		ಖಾಲಿ},
	{"keyboard-interactive",
		userauth_kbdint,
		ಖಾಲಿ,
		&options.kbd_interactive_authentication,
		&options.batch_ಬಹುಲಕ},
	{"password",
		userauth_passwd,
		ಖಾಲಿ,
		&options.password_authentication,
		&options.batch_ಬಹುಲಕ},
	{"none",
		userauth_none,
		ಖಾಲಿ,
		ಖಾಲಿ,
		ಖಾಲಿ},
	{ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ, ಖಾಲಿ}
};

ಶೂನ್ಯ
ssh_userauth2(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *local_user,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *server_user, ಅಕ್ಷರ *host, Sensitive *sensitive)
{
	Authctxt authctxt;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (options.preferred_authentications == ಖಾಲಿ)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	memset(&authctxt, 0, ಗಾತ್ರ(authctxt));
	authctxt.server_user = server_user;
	authctxt.local_user = local_user;
	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.ವಿಧಾನ = authmethod_lookup("none");
	authctxt.authlist = ಖಾಲಿ;
	authctxt.methoddata = ಖಾಲಿ;
	authctxt.sensitive = sensitive;
	authctxt.ಸಕ್ರಿಯ_ktype = authctxt.oktypes = authctxt.ktypes = ಖಾಲಿ;
	authctxt.info_req_ನೋಡಿದ = 0;
	authctxt.attempt_kbdint = 0;
	authctxt.attempt_passwd = 0;
#ಆದರೆ GSSAPI
	authctxt.gss_supported_mechs = ಖಾಲಿ;
	authctxt.mech_tried = 0;
#ಆದರೆ_ಅಂತ್ಯ
	authctxt.agent_fd = -1;
	ಆದರೆ (authctxt.ವಿಧಾನ == ಖಾಲಿ)
		fatal_f("internal error: cannot send userauth none request");

	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_SERVICE_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "ssh-userauth")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh->authctxt = &authctxt;
	ssh_dispatch_init(ssh, &ಒಳಹರಿವು_userauth_error);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_EXT_INFO, kex_ಒಳಹರಿವು_ext_info);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_SERVICE_ACCEPT, &ಒಳಹರಿವು_userauth_service_accept);
	ssh_dispatch_ಸತತ_fatal(ssh, DISPATCH_ಖಂಡ, &authctxt.success);	/* loop until success */
	pubkey_cleanup(ssh);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
	ಆದರೆ (authctxt.gss_supported_mechs != ಖಾಲಿ) {
		u_int ms;

		gss_release_oid_ಗಣ(&ms, &authctxt.gss_supported_mechs);
		authctxt.gss_supported_mechs = ಖಾಲಿ;
	}
#ಆದರೆ_ಅಂತ್ಯ
	ssh->authctxt = ಖಾಲಿ;

	ssh_dispatch_range(ssh, SSH2_ಸಂದೇಶ_USERAUTH_MIN, SSH2_ಸಂದೇಶ_USERAUTH_MAX, ಖಾಲಿ);

	ಆದರೆ (!authctxt.success)
		fatal("Authentication failed.");
	ಆದರೆ (ssh_packet_connection_is_on_socket(ssh)) {
		verbose("Authenticated to %s ([%s]:%d) using \"%s\".", host,
		    ssh_remote_ipaddr(ssh), ssh_remote_ಪೋರ್ಟ್(ssh),
		    authctxt.ವಿಧಾನ->name);
	} ಇಲ್ಲದಿದ್ದರೆ {
		verbose("Authenticated to %s (via proxy) using \"%s\".", host,
		    authctxt.ವಿಧಾನ->name);
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_userauth_service_accept(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (ssh_packet_ಉಳಿದ(ssh) > 0) {
		ಅಕ್ಷರ *ಉತ್ತರ;

		ಆದರೆ ((r = sshpkt_get_cstring(ssh, &ಉತ್ತರ, ಖಾಲಿ)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		debug2("service_accept: %s", ಉತ್ತರ);
		ಬಿಡುಗಡೆ(ಉತ್ತರ);
	} ಇಲ್ಲದಿದ್ದರೆ {
		debug2("buggy server: service_accept w/o service");
	}
	ಆದರೆ ((r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	debug("SSH2_MSG_SERVICE_ACCEPT received");

	/* initial userauth request */
	userauth_none(ssh);

	/* accept EXT_INFO at any time during userauth */
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_EXT_INFO, ssh->kex->ext_info_s ?
	    &kex_ಒಳಹರಿವು_ext_info : &ಒಳಹರಿವು_userauth_error);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_SUCCESS, &ಒಳಹರಿವು_userauth_success);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_FAILURE, &ಒಳಹರಿವು_userauth_failure);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_BANNER, &ಒಳಹರಿವು_userauth_banner);
	r = 0;
 ಹೊರಹೋಗು:
	ಹಿಂತಿರುಗಿ r;
}

ಶೂನ್ಯ
userauth(ರಚನೆ ssh *ssh, ಅಕ್ಷರ *authlist)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	ಆದರೆ (authctxt->ವಿಧಾನ != ಖಾಲಿ && authctxt->ವಿಧಾನ->cleanup != ಖಾಲಿ)
		authctxt->ವಿಧಾನ->cleanup(ssh);

	ಬಿಡುಗಡೆ(authctxt->methoddata);
	authctxt->methoddata = ಖಾಲಿ;
	ಆದರೆ (authlist == ಖಾಲಿ) {
		authlist = authctxt->authlist;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಬಿಡುಗಡೆ(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	ಗಾಗಿ (;;) {
		Authmethod *ವಿಧಾನ = authmethod_get(authlist);
		ಆದರೆ (ವಿಧಾನ == ಖಾಲಿ)
			fatal("%s@%s: Permission denied (%s).",
			    authctxt->server_user, authctxt->host, authlist);
		authctxt->ವಿಧಾನ = ವಿಧಾನ;

		/* reset the per method handler */
		ssh_dispatch_range(ssh, SSH2_ಸಂದೇಶ_USERAUTH_ಪ್ರತಿ_ವಿಧಾನ_MIN,
		    SSH2_ಸಂದೇಶ_USERAUTH_ಪ್ರತಿ_ವಿಧಾನ_MAX, ಖಾಲಿ);

		/* and try new method */
		ಆದರೆ (ವಿಧಾನ->userauth(ssh) != 0) {
			debug2("we sent a %s packet, wait for reply", ವಿಧಾನ->name);
			ನಿಲ್ಲಿಸು;
		} ಇಲ್ಲದಿದ್ದರೆ {
			debug2("we did not send a packet, disable method");
			ವಿಧಾನ->enabled = ಖಾಲಿ;
		}
	}
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_userauth_error(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	fatal_f("bad message during authentication: type %d", type);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_userauth_banner(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	ಅಕ್ಷರ *ಸಂದೇಶ = ಖಾಲಿ;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ r;

	debug3_f("entering");
	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &ಸಂದೇಶ, &len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, ಖಾಲಿ, ಖಾಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO)
		fmprintf(stderr, "%s", ಸಂದೇಶ);
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(ಸಂದೇಶ);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_userauth_success(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ಆದರೆ (authctxt == ಖಾಲಿ)
		fatal_f("no authentication context");
	ಬಿಡುಗಡೆ(authctxt->authlist);
	authctxt->authlist = ಖಾಲಿ;
	ಆದರೆ (authctxt->ವಿಧಾನ != ಖಾಲಿ && authctxt->ವಿಧಾನ->cleanup != ಖಾಲಿ)
		authctxt->ವಿಧಾನ->cleanup(ssh);
	ಬಿಡುಗಡೆ(authctxt->methoddata);
	authctxt->methoddata = ಖಾಲಿ;
	authctxt->success = 1;			/* break out */
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_EXT_INFO, dispatch_protocol_error);
	ಹಿಂತಿರುಗಿ 0;
}

#ಆದರೆ 0
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_userauth_success_unexpected(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ಆದರೆ (authctxt == ಖಾಲಿ)
		fatal_f("no authentication context");

	fatal("Unexpected authentication success during %s.",
	    authctxt->ವಿಧಾನ->name);
	ಹಿಂತಿರುಗಿ 0;
}
#ಆದರೆ_ಅಂತ್ಯ

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_userauth_failure(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ಅಕ್ಷರ *authlist = ಖಾಲಿ;
	u_char partial;

	ಆದರೆ (authctxt == ಖಾಲಿ)
		fatal("input_userauth_failure: no authentication context");

	ಆದರೆ (sshpkt_get_cstring(ssh, &authlist, ಖಾಲಿ) != 0 ||
	    sshpkt_get_u8(ssh, &partial) != 0 ||
	    sshpkt_get_ಕೊನೆ(ssh) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ (partial != 0) {
		verbose("Authenticated using \"%s\" with partial success.",
		    authctxt->ವಿಧಾನ->name);
		/* reset state */
		pubkey_reset(authctxt);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(ssh, authlist);
	authlist = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(authlist);
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Format an identity for logging including filename, key type, fingerprint
 * and location (agent, etc.). Caller must free.
 */
ಸ್ಥಿರ ಅಕ್ಷರ *
format_ತಟಸ್ಥ(ತಟಸ್ಥ *id)
{
	ಅಕ್ಷರ *fp = ಖಾಲಿ, *ret = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *note = "";

	ಆದರೆ (id->ಕೀಲಿ != ಖಾಲಿ) {
		fp = sshkey_fingerprint(id->ಕೀಲಿ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
	}
	ಆದರೆ (id->ಕೀಲಿ) {
		ಆದರೆ ((id->ಕೀಲಿ->flags & SSHKEY_FLAG_EXT) != 0)
			note = " token";
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (sshkey_is_sk(id->ಕೀಲಿ))
			note = " authenticator";
	}
	xasprintf(&ret, "%s %s%s%s%s%s%s",
	    id->filename,
	    id->ಕೀಲಿ ? sshkey_type(id->ಕೀಲಿ) : "", id->ಕೀಲಿ ? " " : "",
	    fp ? fp : "",
	    id->userprovided ? " explicit" : "", note,
	    id->agent_fd != -1 ? " agent" : "");
	ಬಿಡುಗಡೆ(fp);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_userauth_pk_ok(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ರಚನೆ sshbuf *keyblob = ಖಾಲಿ;
	ತಟಸ್ಥ *id = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ pktype, ಸಿಕ್ಕಿತು = 0, ಕಳುಹಿಸಿದ = 0;
	ಅಕ್ಷರ *pkalg = ಖಾಲಿ, *fp = ಖಾಲಿ, *ident = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (authctxt == ಖಾಲಿ)
		fatal_f("no authentication context");

	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &pkalg, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		ಹೋಗು ಮುಗಿದ;

	ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		error_f("server replied to PK_OK with signature type %s not "
		    "in PubkeyAcceptedAlgorithms", pkalg);
		r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ ((pktype = sshkey_type_from_name(pkalg)) == ಕೀಲಿ_UNSPEC) {
		debug_f("server sent unknown pkalg %s", pkalg);
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಮುಗಿದ;
	}
	/* inner key type should match signature type */
	ಆದರೆ ((r = sshkey_fromb_allowlist(keyblob, &ಕೀಲಿ, pkalg, ಖಾಲಿ)) != 0) {
		debug_r(r, "no key from blob. pkalg %s", pkalg);
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ (ಕೀಲಿ->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    ಕೀಲಿ->type, pktype);
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಮುಗಿದ;
	}

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_ಹಿಮ್ಮುಖ(id, &authctxt->ಕೀಲಿಗಳು, idlist, ಮುಂದಿನ) {
		ಆದರೆ (sshkey_equal(ಕೀಲಿ, id->ಕೀಲಿ)) {
			ಸಿಕ್ಕಿತು = 1;
			ನಿಲ್ಲಿಸು;
		}
	}
	ಆದರೆ (!ಸಿಕ್ಕಿತು || id == ಖಾಲಿ) {
		fp = sshkey_fingerprint(ಕೀಲಿ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		error_f("server replied with unknown key: %s %s",
		    sshkey_type(ಕೀಲಿ), fp == ಖಾಲಿ ? "<ERROR>" : fp);
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಮುಗಿದ;
	}
	ident = format_ತಟಸ್ಥ(id);
	debug("Server accepts key: %s", ident);
	ಕಳುಹಿಸಿದ = sign_and_send_pubkey(ssh, id);
	r = 0;
 ಮುಗಿದ:
	sshkey_free(ಕೀಲಿ);
	sshbuf_free(keyblob);
	ಬಿಡುಗಡೆ(ident);
	ಬಿಡುಗಡೆ(fp);
	ಬಿಡುಗಡೆ(pkalg);

	/* try another method if we did not send a packet */
	ಆದರೆ (r == 0 && ಕಳುಹಿಸಿದ == 0)
		userauth(ssh, ಖಾಲಿ);
	ಹಿಂತಿರುಗಿ r;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
userauth_gssapi(ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = ಖಾಲಿ;
	OM_uint32 min;
	ಪೂರ್ಣಾಂಕ r, ok = 0;
	gss_OID mech = ಖಾಲಿ;

	/* Try one GSSAPI method at a time, rather than sending them all at
	 * once. */

	ಆದರೆ (authctxt->gss_supported_mechs == ಖಾಲಿ)
		gss_indicate_mechs(&min, &authctxt->gss_supported_mechs);

	/* Check to see whether the mechanism is usable before we offer it */
	ಆಗ (authctxt->mech_tried < authctxt->gss_supported_mechs->ಎಣಿಕೆ_2 &&
	    !ok) {
		mech = &authctxt->gss_supported_mechs->
		    elements[authctxt->mech_tried];
		/* My DER encoding requires length<128 */
		ಆದರೆ (mech->ಉದ್ದಳತೆ < 128 && ssh_gssapi_check_mechanism(&gssctxt,
		    mech, authctxt->host)) {
			ok = 1; /* Mechanism works */
		} ಇಲ್ಲದಿದ್ದರೆ {
			authctxt->mech_tried++;
		}
	}

	ಆದರೆ (!ok || mech == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;

	authctxt->methoddata=(ಶೂನ್ಯ *)gssctxt;

	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->ವಿಧಾನ->name)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_u32(ssh, (mech->ಉದ್ದಳತೆ) + 2)) != 0 ||
	    (r = sshpkt_put_u8(ssh, SSH_GSS_OIDTYPE)) != 0 ||
	    (r = sshpkt_put_u8(ssh, mech->ಉದ್ದಳತೆ)) != 0 ||
	    (r = sshpkt_put(ssh, mech->elements, mech->ಉದ್ದಳತೆ)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_RESPONSE, &ಒಳಹರಿವು_gssapi_response);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN, &ಒಳಹರಿವು_gssapi_token);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERROR, &ಒಳಹರಿವು_gssapi_error);
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERRTOK, &ಒಳಹರಿವು_gssapi_errtok);

	authctxt->mech_tried++; /* Move along to next candidate */

	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
userauth_gssapi_cleanup(ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = (Gssctxt *)authctxt->methoddata;

	ssh_gssapi_delete_ctx(&gssctxt);
	authctxt->methoddata = ಖಾಲಿ;
}

ಸ್ಥಿರ OM_uint32
process_gssapi_token(ರಚನೆ ssh *ssh, gss_ಬಫರ್_t recv_tok)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt = authctxt->methoddata;
	gss_ಬಫರ್_desc send_tok = GSS_C_ಖಾಲಿಗಳು_ಬಫರ್;
	gss_ಬಫರ್_desc mic = GSS_C_ಖಾಲಿಗಳು_ಬಫರ್;
	gss_ಬಫರ್_desc gssbuf;
	OM_uint32 ಸ್ಥಿತಿ_2, ms, flags;
	ಪೂರ್ಣಾಂಕ r;

	ಸ್ಥಿತಿ_2 = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	ಆದರೆ (send_tok.ಉದ್ದಳತೆ > 0) {
		u_char type = GSS_ERROR(ಸ್ಥಿತಿ_2) ?
		    SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_ERRTOK :
		    SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_TOKEN;

		ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, type)) != 0 ||
		    (r = sshpkt_put_string(ssh, send_tok.ಮೌಲ್ಯ,
		    send_tok.ಉದ್ದಳತೆ)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send %u packet", type);

		gss_release_ಬಫರ್(&ms, &send_tok);
	}

	ಆದರೆ (ಸ್ಥಿತಿ_2 == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		ಆದರೆ (!(flags & GSS_C_INTEG_FLAG)) {
			ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh,
			    SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send completion");
		} ಇಲ್ಲದಿದ್ದರೆ {
			ರಚನೆ sshbuf *b;

			ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
				fatal_f("sshbuf_new failed");
			ssh_gssapi_buildmic(b, authctxt->server_user,
			    authctxt->service, "gssapi-with-mic",
			    ssh->kex->session_id);

			ಆದರೆ ((gssbuf.ಮೌಲ್ಯ = sshbuf_mutable_ptr(b)) == ಖಾಲಿ)
				fatal_f("sshbuf_mutable_ptr failed");
			gssbuf.ಉದ್ದಳತೆ = sshbuf_len(b);

			ಸ್ಥಿತಿ_2 = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			ಆದರೆ (!GSS_ERROR(ಸ್ಥಿತಿ_2)) {
				ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh,
				    SSH2_ಸಂದೇಶ_USERAUTH_GSSAPI_MIC)) != 0 ||
				    (r = sshpkt_put_string(ssh, mic.ಮೌಲ್ಯ,
				    mic.ಉದ್ದಳತೆ)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send MIC");
			}

			sshbuf_free(b);
			gss_release_ಬಫರ್(&ms, &mic);
		}
	}

	ಹಿಂತಿರುಗಿ ಸ್ಥಿತಿ_2;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_gssapi_response(ಪೂರ್ಣಾಂಕ type, uint32_t plen, ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	ಗಾತ್ರ_t oidlen;
	u_char *oidv = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (authctxt == ಖಾಲಿ)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	ಆದರೆ ((r = sshpkt_get_string(ssh, &oidv, &oidlen)) != 0)
		ಹೋಗು ಮುಗಿದ;

	ಆದರೆ (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		debug("Badly encoded mechanism OID received");
		userauth(ssh, ಖಾಲಿ);
		ಹೋಗು ok;
	}

	ಆದರೆ (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	ಆದರೆ ((r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		ಹೋಗು ಮುಗಿದ;

	ಆದರೆ (GSS_ERROR(process_gssapi_token(ssh, GSS_C_NO_ಬಫರ್))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(ssh, ಖಾಲಿ);
		ಹೋಗು ok;
	}
 ok:
	r = 0;
 ಮುಗಿದ:
	ಬಿಡುಗಡೆ(oidv);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_gssapi_token(ಪೂರ್ಣಾಂಕ type, uint32_t plen, ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_ಬಫರ್_desc recv_tok;
	u_char *p = ಖಾಲಿ;
	ಗಾತ್ರ_t len;
	OM_uint32 ಸ್ಥಿತಿ_2;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (authctxt == ಖಾಲಿ)
		fatal("input_gssapi_response: no authentication context");

	ಆದರೆ ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	recv_tok.ಮೌಲ್ಯ = p;
	recv_tok.ಉದ್ದಳತೆ = len;
	ಸ್ಥಿತಿ_2 = process_gssapi_token(ssh, &recv_tok);

	/* Start again with the next method in the list */
	ಆದರೆ (GSS_ERROR(ಸ್ಥಿತಿ_2)) {
		userauth(ssh, ಖಾಲಿ);
		/* ok */
	}
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(p);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_gssapi_errtok(ಪೂರ್ಣಾಂಕ type, uint32_t plen, ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_ಬಫರ್_desc send_tok = GSS_C_ಖಾಲಿಗಳು_ಬಫರ್;
	gss_ಬಫರ್_desc recv_tok;
	OM_uint32 ms;
	u_char *p = ಖಾಲಿ;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (authctxt == ಖಾಲಿ)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	ಆದರೆ ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_ಕೊನೆ(ssh)) != 0) {
		ಬಿಡುಗಡೆ(p);
		ಹಿಂತಿರುಗಿ r;
	}

	/* Stick it into GSSAPI and see what it says */
	recv_tok.ಮೌಲ್ಯ = p;
	recv_tok.ಉದ್ದಳತೆ = len;
	(ಶೂನ್ಯ)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, ಖಾಲಿ);
	ಬಿಡುಗಡೆ(p);
	gss_release_ಬಫರ್(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_gssapi_error(ಪೂರ್ಣಾಂಕ type, uint32_t plen, ರಚನೆ ssh *ssh)
{
	ಅಕ್ಷರ *ಸಂದೇಶ = ಖಾಲಿ;
	ಅಕ್ಷರ *lang = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshpkt_get_u32(ssh, ಖಾಲಿ)) != 0 ||	/* maj */
	    (r = sshpkt_get_u32(ssh, ಖಾಲಿ)) != 0 ||	/* min */
	    (r = sshpkt_get_cstring(ssh, &ಸಂದೇಶ, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ಖಾಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	r = sshpkt_get_ಕೊನೆ(ssh);
	debug("Server GSSAPI Error:\n%s", ಸಂದೇಶ);
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(ಸಂದೇಶ);
	ಬಿಡುಗಡೆ(lang);
	ಹಿಂತಿರುಗಿ r;
}
#ಆದರೆ_ಅಂತ್ಯ /* GSSAPI */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
userauth_none(ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ಪೂರ್ಣಾಂಕ r;

	/* initial userauth request */
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->ವಿಧಾನ->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
userauth_passwd(ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ಅಕ್ಷರ *password, *prompt = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host = options.host_ಕೀಲಿ_alias ?  options.host_ಕೀಲಿ_alias :
	    authctxt->host;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (authctxt->attempt_passwd++ >= options.ಸಂಖ್ಯೆ_ದ_password_prompts)
		ಹಿಂತಿರುಗಿ 0;

	ಆದರೆ (authctxt->attempt_passwd != 1)
		error("Permission denied, please try again.");

	xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->ವಿಧಾನ->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_ಕೂಡಿಸು_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ಬಿಡುಗಡೆ(prompt);
	ಆದರೆ (password != ಖಾಲಿ)
		freezero(password, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(password));

	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_PASSWD_CHANGEREQ,
	    &ಒಳಹರಿವು_userauth_passwd_changereq);

	ಹಿಂತಿರುಗಿ 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_userauth_passwd_changereq(ಪೂರ್ಣಾಂಕ type, uint32_t seqnr, ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ಅಕ್ಷರ *info = ಖಾಲಿ, *lang = ಖಾಲಿ, *password = ಖಾಲಿ, *retype = ಖಾಲಿ;
	ಅಕ್ಷರ prompt[256];
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host;
	ಪೂರ್ಣಾಂಕ r, addnl;
	ಗಾತ್ರ_t len;

	debug2("input_userauth_passwd_changereq");

	ಆದರೆ (authctxt == ಖಾಲಿ)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");
	host = options.host_ಕೀಲಿ_alias ? options.host_ಕೀಲಿ_alias : authctxt->host;

	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &info, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ಖಾಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(info)) > 0) {
		addnl = info[len] != '\n';
		fmprintf(stderr, "%s%s", info, addnl ? "\n" : "");
	}
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->ವಿಧಾನ->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0)	/* additional info */
		ಹೋಗು ಹೊರಹೋಗು;

	snprintf(prompt, ಗಾತ್ರ(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	ಆದರೆ ((r = sshpkt_put_cstring(ssh, password)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	freezero(password, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(password));
	password = ಖಾಲಿ;
	ಆಗ (password == ಖಾಲಿ) {
		snprintf(prompt, ಗಾತ್ರ(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		ಆದರೆ (password == ಖಾಲಿ) {
			/* bail out */
			r = 0;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		snprintf(prompt, ಗಾತ್ರ(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		ಆದರೆ (strcmp(password, retype) != 0) {
			freezero(password, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(password));
			logit("Mismatch; try again, EOF to quit.");
			password = ಖಾಲಿ;
		}
		freezero(retype, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(retype));
	}
	ಆದರೆ ((r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_ಕೂಡಿಸು_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_PASSWD_CHANGEREQ,
	    &ಒಳಹರಿವು_userauth_passwd_changereq);
	r = 0;
 ಹೊರಹೋಗು:
	ಆದರೆ (password)
		freezero(password, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(password));
	ಬಿಡುಗಡೆ(info);
	ಬಿಡುಗಡೆ(lang);
	ಹಿಂತಿರುಗಿ r;
}

/*
 * Select an algorithm for publickey signatures.
 * Returns algorithm (caller must free) or NULL if no mutual algorithm found.
 *
 * Call with ssh==NULL to ignore server-sig-algs extension list and
 * only attempt with the key's base signature type.
 */
ಸ್ಥಿರ ಅಕ್ಷರ *
ಕೀಲಿ_sig_algorithm(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಅಕ್ಷರ *allowed, *oallowed, *cp, *tmp, *alg = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *server_sig_algs;

	/*
	 * The signature algorithm will only differ from the key algorithm
	 * for RSA keys/certs and when the server advertises support for
	 * newer (SHA2) algorithms.
	 */
	ಆದರೆ (ssh == ಖಾಲಿ || ssh->kex->server_sig_algs == ಖಾಲಿ ||
	    (ಕೀಲಿ->type != ಕೀಲಿ_RSA && ಕೀಲಿ->type != ಕೀಲಿ_RSA_CERT) ||
	    (ಕೀಲಿ->type == ಕೀಲಿ_RSA_CERT && (ssh->compat & SSH_BUG_SIGTYPE))) {
		/* Filter base key signature alg against our configuration */
		ಹಿಂತಿರುಗಿ ಹೊಂದಿಕೆ_list(sshkey_ssh_name(ಕೀಲಿ),
		    options.pubkey_accepted_algos, ಖಾಲಿ);
	}

	/*
	 * Workaround OpenSSH 7.4 bug: this version supports RSA/SHA-2 but
	 * fails to advertise it via SSH2_MSG_EXT_INFO.
	 */
	server_sig_algs = ssh->kex->server_sig_algs;
	ಆದರೆ (ಕೀಲಿ->type == ಕೀಲಿ_RSA && (ssh->compat & SSH_BUG_SIGTYPE74))
		server_sig_algs = "rsa-sha2-256,rsa-sha2-512";

	/*
	 * For RSA keys/certs, since these might have a different sig type:
	 * find the first entry in PubkeyAcceptedAlgorithms of the right type
	 * that also appears in the supported signature algorithms list from
	 * the server.
	 */
	oallowed = allowed = xstrdup(options.pubkey_accepted_algos);
	ಆಗ ((cp = strsep(&allowed, ",")) != ಖಾಲಿ) {
		ಆದರೆ (sshkey_type_from_name(cp) != ಕೀಲಿ->type)
			ಮುಂದುವರಿ;
		tmp = ಹೊಂದಿಕೆ_list(sshkey_sigalg_by_name(cp),
		    server_sig_algs, ಖಾಲಿ);
		ಆದರೆ (tmp != ಖಾಲಿ)
			alg = xstrdup(cp);
		ಬಿಡುಗಡೆ(tmp);
		ಆದರೆ (alg != ಖಾಲಿ)
			ನಿಲ್ಲಿಸು;
	}
	ಬಿಡುಗಡೆ(oallowed);
	ಹಿಂತಿರುಗಿ alg;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ತಟಸ್ಥ_sign(ರಚನೆ ತಟಸ್ಥ_2 *id, u_char **sigp, ಗಾತ್ರ_t *lenp,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen, u_int compat, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg)
{
	ರಚನೆ sshkey *sign_ಕೀಲಿ = ಖಾಲಿ, *prv = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ is_agent = 0, retried = 0, r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ರಚನೆ notifier_ctx *notifier = ಖಾಲಿ;
	ಅಕ್ಷರ *fp = ಖಾಲಿ, *pin = ಖಾಲಿ, *prompt = ಖಾಲಿ;

	*sigp = ಖಾಲಿ;
	*lenp = 0;

	/* The agent supports this key. */
	ಆದರೆ (id->ಕೀಲಿ != ಖಾಲಿ && id->agent_fd != -1) {
		ಹಿಂತಿರುಗಿ ssh_agent_sign(id->agent_fd, id->ಕೀಲಿ, sigp, lenp,
		    ದತ್ತಾಂಶ, datalen, alg, compat);
	}

	/*
	 * We have already loaded the private key or the private key is
	 * stored in external hardware.
	 */
	ಆದರೆ (id->ಕೀಲಿ != ಖಾಲಿ &&
	    (id->isprivate || (id->ಕೀಲಿ->flags & SSHKEY_FLAG_EXT))) {
		sign_ಕೀಲಿ = id->ಕೀಲಿ;
		is_agent = 1;
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* Load the private key from the file. */
		ಆದರೆ ((prv = ತುಂಬು_ತಟಸ್ಥ_file(id)) == ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು;
		ಆದರೆ (id->ಕೀಲಿ != ಖಾಲಿ && !sshkey_equal_ಬಹಿರಂಗ(prv, id->ಕೀಲಿ)) {
			error_f("private key %s contents do not match public",
			    id->filename);
			r = SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		sign_ಕೀಲಿ = prv;
	}
 retry_pin:
	/* Prompt for touch for non-agent FIDO keys that request UP */
	ಆದರೆ (!is_agent && sshkey_is_sk(sign_ಕೀಲಿ) &&
	    (sign_ಕೀಲಿ->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
		/* XXX should batch mode just skip these? */
		ಆದರೆ ((fp = sshkey_fingerprint(sign_ಕೀಲಿ,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ಖಾಲಿ)
			fatal_f("fingerprint failed");
		notifier = notify_ಆರಂಭ(options.batch_ಬಹುಲಕ,
		    "Confirm user presence for key %s %s",
		    sshkey_type(sign_ಕೀಲಿ), fp);
		ಬಿಡುಗಡೆ(fp);
	}
	ಆದರೆ ((r = sshkey_sign(sign_ಕೀಲಿ, sigp, lenp, ದತ್ತಾಂಶ, datalen,
	    alg, options.sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		ಆದರೆ (!retried && pin == ಖಾಲಿ && !is_agent &&
		    sshkey_is_sk(sign_ಕೀಲಿ) &&
		    r == SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE) {
			notify_complete(notifier, ಖಾಲಿ);
			notifier = ಖಾಲಿ;
			xasprintf(&prompt, "Enter PIN for %s key %s: ",
			    sshkey_type(sign_ಕೀಲಿ), id->filename);
			pin = read_passphrase(prompt, 0);
			retried = 1;
			ಹೋಗು retry_pin;
		}
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/*
	 * PKCS#11 tokens may not support all signature algorithms,
	 * so check what we get back.
	 */
	ಆದರೆ (id->ಕೀಲಿ != ಖಾಲಿ && (id->ಕೀಲಿ->flags & SSHKEY_FLAG_EXT) != 0 &&
	    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
		debug_fr(r, "sshkey_check_sigtype");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(prompt);
	ಆದರೆ (pin != ಖಾಲಿ)
		freezero(pin, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pin));
	notify_complete(notifier, r == 0 ? "User presence confirmed" : ಖಾಲಿ);
	sshkey_free(prv);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
id_filename_matches(ತಟಸ್ಥ *id, ತಟಸ್ಥ *ಖಾಸಗಿ_id)
{
	ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ * ಸ್ಥಿರಾಂಕ suffixes[] = { ".pub", "-cert.pub", ಖಾಲಿ };
	ಗಾತ್ರ_t len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(id->filename), plen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಖಾಸಗಿ_id->filename);
	ಗಾತ್ರ_t i, slen;

	ಆದರೆ (strcmp(id->filename, ಖಾಸಗಿ_id->filename) == 0)
		ಹಿಂತಿರುಗಿ 1;
	ಗಾಗಿ (i = 0; suffixes[i]; i++) {
		slen = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(suffixes[i]);
		ಆದರೆ (len > slen && plen == len - slen &&
		    strcmp(id->filename + (len - slen), suffixes[i]) == 0 &&
		    memcmp(id->filename, ಖಾಸಗಿ_id->filename, plen) == 0)
			ಹಿಂತಿರುಗಿ 1;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sign_and_send_pubkey(ರಚನೆ ssh *ssh, ತಟಸ್ಥ *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	ತಟಸ್ಥ *ಖಾಸಗಿ_id, *sign_id = ಖಾಲಿ;
	u_char *signature = ಖಾಲಿ;
	ಗಾತ್ರ_t slen = 0, skip = 0;
	ಪೂರ್ಣಾಂಕ r, fallback_sigtype, ಕಳುಹಿಸಿದ = 0;
	ಅಕ್ಷರ *alg = ಖಾಲಿ, *fp = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *loc = "", *ವಿಧಾನ = "publickey";
	ಪೂರ್ಣಾಂಕ hostbound = 0;

	/* prefer host-bound pubkey signatures if supported by server */
	ಆದರೆ ((ssh->kex->flags & KEX_HAS_PUBKEY_HOSTBOUND) != 0 &&
	    (options.pubkey_authentication & SSH_PUBKEY_AUTH_HBOUND) != 0) {
		hostbound = 1;
		ವಿಧಾನ = "publickey-hostbound-v00@openssh.com";
	}

	ಆದರೆ ((fp = sshkey_fingerprint(id->ಕೀಲಿ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;

	debug3_f("using %s with %s %s", ವಿಧಾನ, sshkey_type(id->ಕೀಲಿ), fp);

	/*
	 * If the key is an certificate, try to find a matching private key
	 * and use it to complete the signature.
	 * If no such private key exists, fall back to trying the certificate
	 * key itself in case it has a private half already loaded.
	 * This will try to set sign_id to the private key that will perform
	 * the signature.
	 */
	ಆದರೆ (id->agent_fd == -1 && sshkey_is_cert(id->ಕೀಲಿ)) {
		TAILQ_FOREACH(ಖಾಸಗಿ_id, &authctxt->ಕೀಲಿಗಳು, ಮುಂದಿನ) {
			ಆದರೆ (sshkey_equal_ಬಹಿರಂಗ(id->ಕೀಲಿ, ಖಾಸಗಿ_id->ಕೀಲಿ) &&
			    id->ಕೀಲಿ->type != ಖಾಸಗಿ_id->ಕೀಲಿ->type) {
				sign_id = ಖಾಸಗಿ_id;
				ನಿಲ್ಲಿಸು;
			}
		}
		/*
		 * Exact key matches are preferred, but also allow
		 * filename matches for non-PKCS#11/agent keys that
		 * didn't load public keys. This supports the case
		 * of keeping just a private key file and public
		 * certificate on disk.
		 */
		ಆದರೆ (sign_id == ಖಾಲಿ &&
		    !id->isprivate && id->agent_fd == -1 &&
		    (id->ಕೀಲಿ->flags & SSHKEY_FLAG_EXT) == 0) {
			TAILQ_FOREACH(ಖಾಸಗಿ_id, &authctxt->ಕೀಲಿಗಳು, ಮುಂದಿನ) {
				ಆದರೆ (ಖಾಸಗಿ_id->ಕೀಲಿ == ಖಾಲಿ &&
				    id_filename_matches(id, ಖಾಸಗಿ_id)) {
					sign_id = ಖಾಸಗಿ_id;
					ನಿಲ್ಲಿಸು;
				}
			}
		}
		ಆದರೆ (sign_id != ಖಾಲಿ) {
			debug2_f("using private key \"%s\"%s for "
			    "certificate", sign_id->filename,
			    sign_id->agent_fd != -1 ? " from agent" : "");
		} ಇಲ್ಲದಿದ್ದರೆ {
			debug_f("no separate private key for certificate "
			    "\"%s\"", id->filename);
		}
	}

	/*
	 * If the above didn't select another identity to do the signing
	 * then default to the one we started with.
	 */
	ಆದರೆ (sign_id == ಖಾಲಿ)
		sign_id = id;

	/* assemble and sign data */
	ಗಾಗಿ (fallback_sigtype = 0; fallback_sigtype <= 1; fallback_sigtype++) {
		ಬಿಡುಗಡೆ(alg);
		slen = 0;
		signature = ಖಾಲಿ;
		ಆದರೆ ((alg = ಕೀಲಿ_sig_algorithm(fallback_sigtype ? ಖಾಲಿ : ssh,
		    id->ಕೀಲಿ)) == ಖಾಲಿ) {
			error_f("no mutual signature supported");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		debug3_f("signing using %s %s", alg, fp);

		sshbuf_free(b);
		ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
			fatal_f("sshbuf_new failed");
		ಆದರೆ ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "sshbuf_put_stringb");
		skip = sshbuf_len(b);
		ಆದರೆ ((r = sshbuf_put_u8(b, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, ವಿಧಾನ)) != 0 ||
		    (r = sshbuf_put_u8(b, 1)) != 0 ||
		    (r = sshbuf_put_cstring(b, alg)) != 0 ||
		    (r = sshkey_puts(id->ಕೀಲಿ, b)) != 0) {
			fatal_fr(r, "assemble signed data");
		}
		ಆದರೆ (hostbound) {
			ಆದರೆ (ssh->kex->initial_hostkey == ಖಾಲಿ) {
				fatal_f("internal error: initial hostkey "
				    "not recorded");
			}
			ಆದರೆ ((r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
				fatal_fr(r, "assemble %s hostkey", ವಿಧಾನ);
		}
		/* generate signature */
		r = ತಟಸ್ಥ_sign(sign_id, &signature, &slen,
		    sshbuf_ptr(b), sshbuf_len(b), ssh->compat, alg);
		ಆದರೆ (r == 0)
			ನಿಲ್ಲಿಸು;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r == SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು)
			ಹೋಗು ಹೊರಹೋಗು; /* soft failure */
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r == SSH_ERR_SIGN_ALG_UNSUPPORTED &&
		    !fallback_sigtype) {
			ಆದರೆ (sign_id->agent_fd != -1)
				loc = "agent ";
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (sign_id->ಕೀಲಿ != ಖಾಲಿ &&
			    (sign_id->ಕೀಲಿ->flags & SSHKEY_FLAG_EXT) != 0)
				loc = "token ";
			logit("%skey %s %s returned incorrect signature type",
			    loc, sshkey_type(id->ಕೀಲಿ), fp);
			ಮುಂದುವರಿ;
		}
		error_fr(r, "signing failed for %s \"%s\"%s",
		    sshkey_type(sign_id->ಕೀಲಿ), sign_id->filename,
		    id->agent_fd != -1 ? " from agent" : "");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (slen == 0 || signature == ಖಾಲಿ) /* shouldn't happen */
		fatal_f("no signature");

	/* append signature */
	ಆದರೆ ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_fr(r, "append signature");

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_PK
	sshbuf_dump(b, stderr);
#ಆದರೆ_ಅಂತ್ಯ
	/* skip session id and packet type */
	ಆದರೆ ((r = sshbuf_consume(b, skip + 1)) != 0)
		fatal_fr(r, "consume");

	/* put remaining data from buffer into packet */
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_putb(ssh, b)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "enqueue request");

	/* success */
	ಕಳುಹಿಸಿದ = 1;

 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(fp);
	ಬಿಡುಗಡೆ(alg);
	sshbuf_free(b);
	freezero(signature, slen);
	ಹಿಂತಿರುಗಿ ಕಳುಹಿಸಿದ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
send_pubkey_test(ರಚನೆ ssh *ssh, ತಟಸ್ಥ *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	u_char *blob = ಖಾಲಿ;
	ಅಕ್ಷರ *alg = ಖಾಲಿ;
	ಗಾತ್ರ_t bloblen;
	u_int have_sig = 0;
	ಪೂರ್ಣಾಂಕ ಕಳುಹಿಸಿದ = 0, r;

	ಆದರೆ ((alg = ಕೀಲಿ_sig_algorithm(ssh, id->ಕೀಲಿ)) == ಖಾಲಿ) {
		debug_f("no mutual signature algorithm");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((r = sshkey_ಗಮ್ಯ_blob(id->ಕೀಲಿ, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3_f("cannot handle key");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* register callback for USERAUTH_PK_OK message */
	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_PK_OK, &ಒಳಹರಿವು_userauth_pk_ok);

	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->ವಿಧಾನ->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, have_sig)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, alg)) != 0 ||
	    (r = sshpkt_put_string(ssh, blob, bloblen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	ಕಳುಹಿಸಿದ = 1;

 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(alg);
	ಬಿಡುಗಡೆ(blob);
	ಹಿಂತಿರುಗಿ ಕಳುಹಿಸಿದ;
}

ಸ್ಥಿರ ರಚನೆ sshkey *
ತುಂಬು_ತಟಸ್ಥ_file(ತಟಸ್ಥ *id)
{
	ರಚನೆ sshkey *ಖಾಸಗಿ = ಖಾಲಿ;
	ಅಕ್ಷರ prompt[300], *passphrase, *comment;
	ಪೂರ್ಣಾಂಕ r, quit = 0, i;
	ರಚನೆ stat st;

	ಆದರೆ (stat(id->filename, &st) == -1) {
		do_log2(id->userprovided ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_DEBUG3,
		    "no such identity: %s: %s", id->filename, strerror(errno));
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	snprintf(prompt, ಗಾತ್ರ prompt,
	    "Enter passphrase for key '%.100s': ", id->filename);
	ಗಾಗಿ (i = 0; i <= options.ಸಂಖ್ಯೆ_ದ_password_prompts; i++) {
		ಆದರೆ (i == 0)
			passphrase = "";
		ಇಲ್ಲದಿದ್ದರೆ {
			passphrase = read_passphrase(prompt, 0);
			ಆದರೆ (*passphrase == '\0') {
				debug2("no passphrase given, try next key");
				ಬಿಡುಗಡೆ(passphrase);
				ನಿಲ್ಲಿಸು;
			}
		}
		ಆಯ್ಕೆ ((r = sshkey_ತುಂಬು_ಖಾಸಗಿ_type(ಕೀಲಿ_UNSPEC, id->filename,
		    passphrase, &ಖಾಸಗಿ, &comment))) {
		ಸ್ಥಿತಿ 0:
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE:
			ಆದರೆ (options.batch_ಬಹುಲಕ) {
				quit = 1;
				ನಿಲ್ಲಿಸು;
			}
			ಆದರೆ (i != 0)
				debug2("bad passphrase given, try again...");
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ SSH_ERR_SYSTEM_ERROR:
			ಆದರೆ (errno == ENOENT) {
				debug2_r(r, "Load key \"%s\"", id->filename);
				quit = 1;
				ನಿಲ್ಲಿಸು;
			}
			/* FALLTHROUGH */
		ಪೂರ್ವನಿಯೋಜಿತ:
			error_r(r, "Load key \"%s\"", id->filename);
			quit = 1;
			ನಿಲ್ಲಿಸು;
		}
		ಆದರೆ (ಖಾಸಗಿ != ಖಾಲಿ && sshkey_is_sk(ಖಾಸಗಿ) &&
		    options.sk_provider == ಖಾಲಿ) {
			debug("key \"%s\" is an authenticator-hosted key, "
			    "but no provider specified", id->filename);
			sshkey_free(ಖಾಸಗಿ);
			ಖಾಸಗಿ = ಖಾಲಿ;
			quit = 1;
		}
		ಆದರೆ (!quit && (r = sshkey_check_rsa_ಉದ್ದಳತೆ(ಖಾಸಗಿ,
		    options.required_rsa_ಗಾತ್ರ)) != 0) {
			debug_fr(r, "Skipping key %s", id->filename);
			sshkey_free(ಖಾಸಗಿ);
			ಖಾಸಗಿ = ಖಾಲಿ;
			quit = 1;
		}
		ಆದರೆ (!quit && ಖಾಸಗಿ != ಖಾಲಿ && id->agent_fd == -1 &&
		    !(id->ಕೀಲಿ && id->isprivate))
			maybe_ಕೂಡಿಸು_ಕೀಲಿ_ಗಮ್ಯ_agent(id->filename, ಖಾಸಗಿ, comment,
			    passphrase);
		ಆದರೆ (i > 0)
			freezero(passphrase, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passphrase));
		ಬಿಡುಗಡೆ(comment);
		ಆದರೆ (ಖಾಸಗಿ != ಖಾಲಿ || quit)
			ನಿಲ್ಲಿಸು;
	}
	ಹಿಂತಿರುಗಿ ಖಾಸಗಿ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಕೀಲಿ_type_allowed(ರಚನೆ sshkey *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *allowlist)
{
	ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_list(sshkey_ssh_name(ಕೀಲಿ), allowlist, 0) == 1)
		ಹಿಂತಿರುಗಿ 1;

	/* RSA keys/certs might be allowed by alternate signature types */
	ಆಯ್ಕೆ (ಕೀಲಿ->type) {
	ಸ್ಥಿತಿ ಕೀಲಿ_RSA:
		ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_list("rsa-sha2-512", allowlist, 0) == 1)
			ಹಿಂತಿರುಗಿ 1;
		ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_list("rsa-sha2-256", allowlist, 0) == 1)
			ಹಿಂತಿರುಗಿ 1;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ ಕೀಲಿ_RSA_CERT:
		ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_list("rsa-sha2-512-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			ಹಿಂತಿರುಗಿ 1;
		ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_list("rsa-sha2-256-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			ಹಿಂತಿರುಗಿ 1;
		ನಿಲ್ಲಿಸು;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಕೀಲಿ_type_allowed_by_config(ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಹಿಂತಿರುಗಿ ಕೀಲಿ_type_allowed(ಕೀಲಿ, options.pubkey_accepted_algos);
}

/* obtain a list of keys from the agent */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
get_agent_identities(ರಚನೆ ssh *ssh, ಪೂರ್ಣಾಂಕ *agent_fdp,
    ರಚನೆ ssh_identitylist **idlistp)
{
	ಪೂರ್ಣಾಂಕ r, agent_fd;
	ರಚನೆ ssh_identitylist *idlist;

	ಆದರೆ ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		ಆದರೆ (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ (ssh != ಖಾಲಿ && ssh->kex != ಖಾಲಿ) {
		ಆದರೆ ((r = ssh_agent_bind_hostkey(agent_fd, ssh->kex->initial_hostkey,
		    ssh->kex->session_id, ssh->kex->initial_sig, 0)) == 0)
			debug_f("bound agent to hostkey");
		ಇಲ್ಲದಿದ್ದರೆ
			debug2_fr(r, "ssh_agent_bind_hostkey");
	}

	ಆದರೆ ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		close(agent_fd);
		ಹಿಂತಿರುಗಿ r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Returns nonzero if the certificate extensions/critical-options section
 * has the specified option present, zero otherwise.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
cert_has_option(ರಚನೆ sshbuf *oblob, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಗುರಿ)
{
	ರಚನೆ sshbuf *c = ಖಾಲಿ, *ದತ್ತಾಂಶ = ಖಾಲಿ;
	ಅಕ್ಷರ *name = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, ಸಿಕ್ಕಿತು = 0;

	ಆದರೆ (oblob == ಖಾಲಿ || (c = sshbuf_fromb(oblob)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆಗ (sshbuf_len(c) > 0) {
		sshbuf_free(ದತ್ತಾಂಶ);
		ದತ್ತಾಂಶ = ಖಾಲಿ;
		ಬಿಡುಗಡೆ(name);
		name = ಖಾಲಿ;
		ಆದರೆ ((r = sshbuf_get_cstring(c, &name, ಖಾಲಿ)) != 0 ||
		    (r = sshbuf_froms(c, &ದತ್ತಾಂಶ)) != 0)
			ನಿಲ್ಲಿಸು;
		ಆದರೆ (strcmp(name, ಗುರಿ) == 0) {
			ಸಿಕ್ಕಿತು = 1;
			ನಿಲ್ಲಿಸು;
		}
	}
	sshbuf_free(ದತ್ತಾಂಶ);
	ಬಿಡುಗಡೆ(name);
	sshbuf_free(c);
	ಹಿಂತಿರುಗಿ ಸಿಕ್ಕಿತು;
}

/*
 * Returns an integer describing the priority of the identity
 * within its group. Lower numbers are higher priority.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು MAX_ID_ಆದ್ಯತೆ 3
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ತಟಸ್ಥ_prioritise(ರಚನೆ ತಟಸ್ಥ_2 *id)
{
	ಆದರೆ (id == ಖಾಲಿ || id->ಕೀಲಿ == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 3;
	ಆದರೆ (!sshkey_is_cert(id->ಕೀಲಿ) || id->ಕೀಲಿ->cert == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 3;
	ಆದರೆ (sshkey_is_sk(id->ಕೀಲಿ) &&
	    cert_has_option(id->ಕೀಲಿ->cert->critical, "verify-required"))
		ಹಿಂತಿರುಗಿ 2;
	ಆದರೆ (sshkey_is_sk(id->ಕೀಲಿ) &&
	    cert_has_option(id->ಕೀಲಿ->cert->extensions, "no-touch-required"))
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಶೂನ್ಯ
ಕ್ರಮ_identities_by_prio(ರಚನೆ idlist *list)
{
	ರಚನೆ idlist prio[MAX_ID_ಆದ್ಯತೆ + 1], sorted;
	ರಚನೆ ತಟಸ್ಥ_2 *id, *tmp, *dummy;
	ಪೂರ್ಣಾಂಕ p;

	ಗಾಗಿ (p = 0; p <= MAX_ID_ಆದ್ಯತೆ; p++)
		TAILQ_INIT(&prio[p]);
	TAILQ_INIT(&sorted);

	TAILQ_FOREACH_ಸುರಕ್ಷಿತ(id, list, ಮುಂದಿನ, tmp) {
		ಆದರೆ (id->userprovided)
			ಮುಂದುವರಿ;
		dummy = xcalloc(1, ಗಾತ್ರ(*dummy));
		dummy->userprovided = -1;
		TAILQ_INSERT_BEFORE(id, dummy, ಮುಂದಿನ);
		TAILQ_REMOVE(list, id, ಮುಂದಿನ);
		p = ತಟಸ್ಥ_prioritise(id);
		ಆದರೆ (p < 0 || p > MAX_ID_ಆದ್ಯತೆ)
			fatal_f("internal error: bad priority");
		TAILQ_INSERT_TAIL(&prio[p], id, ಮುಂದಿನ);
	}
	ಗಾಗಿ (p = 0; p <= MAX_ID_ಆದ್ಯತೆ; p++)
		TAILQ_CONCAT(&sorted, &prio[p], ಮುಂದಿನ);

	TAILQ_FOREACH_ಸುರಕ್ಷಿತ(id, list, ಮುಂದಿನ, tmp) {
		ಆದರೆ (id->userprovided != -1)
			ಮುಂದುವರಿ;
		ರಚನೆ ತಟಸ್ಥ_2 *s = TAILQ_FIRST(&sorted);
		TAILQ_REMOVE(&sorted, s, ಮುಂದಿನ);
		TAILQ_INSERT_BEFORE(id, s, ಮುಂದಿನ);
		TAILQ_REMOVE(list, id, ಮುಂದಿನ);
		ಬಿಡುಗಡೆ(id);
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
pubkey_prepare(ರಚನೆ ssh *ssh, Authctxt *authctxt)
{
	ರಚನೆ ತಟಸ್ಥ_2 *id, *id2, *tmp;
	ರಚನೆ idlist agent, files, certs, agent_ಕೀಲಿಗಳು, *preferred;
	ರಚನೆ sshkey *ಕೀಲಿ;
	ಪೂರ್ಣಾಂಕ disallowed, agent_fd = -1, i, r, ಸಿಕ್ಕಿತು;
	ಗಾತ್ರ_t j;
	ರಚನೆ ssh_identitylist *idlist;
	ಅಕ್ಷರ *cp, *ident;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	TAILQ_INIT(&certs);	/* certificates specified by user */
	TAILQ_INIT(&agent_ಕೀಲಿಗಳು); /* keys supported by the agent */
	preferred = &authctxt->ಕೀಲಿಗಳು;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_ತಟಸ್ಥ_files; i++) {
		ಕೀಲಿ = options.ತಟಸ್ಥ_ಕೀಲಿಗಳು[i];
		ಆದರೆ (ಕೀಲಿ && ಕೀಲಿ->cert &&
		    ಕೀಲಿ->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.ತಟಸ್ಥ_files[i]);
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (ಕೀಲಿ && sshkey_is_sk(ಕೀಲಿ) && options.sk_provider == ಖಾಲಿ) {
			debug_f("ignoring authenticator-hosted key %s as no "
			    "SecurityKeyProvider has been specified",
			    options.ತಟಸ್ಥ_files[i]);
			ಮುಂದುವರಿ;
		}
		options.ತಟಸ್ಥ_ಕೀಲಿಗಳು[i] = ಖಾಲಿ;
		id = xcalloc(1, ಗಾತ್ರ(*id));
		id->agent_fd = -1;
		id->ಕೀಲಿ = ಕೀಲಿ;
		id->filename = xstrdup(options.ತಟಸ್ಥ_files[i]);
		id->userprovided = options.ತಟಸ್ಥ_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, ಮುಂದಿನ);
	}

	/* list of certificates specified by user */
	ಗಾಗಿ (i = 0; i < options.ಅಂಕೆ_certificate_files; i++) {
		ಕೀಲಿ = options.certificates[i];
		ಆದರೆ (!sshkey_is_cert(ಕೀಲಿ) || ಕೀಲಿ->cert == ಖಾಲಿ ||
		    ಕೀಲಿ->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.ತಟಸ್ಥ_files[i]);
			ಮುಂದುವರಿ;
		}
		ಆದರೆ (ಕೀಲಿ && sshkey_is_sk(ಕೀಲಿ) && options.sk_provider == ಖಾಲಿ) {
			debug_f("ignoring authenticator-hosted key "
			    "certificate %s as no "
			    "SecurityKeyProvider has been specified",
			    options.ತಟಸ್ಥ_files[i]);
			ಮುಂದುವರಿ;
		}
		id = xcalloc(1, ಗಾತ್ರ(*id));
		id->agent_fd = -1;
		id->ಕೀಲಿ = ಕೀಲಿ;
		id->filename = xstrdup(options.certificate_files[i]);
		id->userprovided = options.certificate_file_userprovided[i];
		TAILQ_INSERT_TAIL(&certs, id, ಮುಂದಿನ);
	}
	ಕ್ರಮ_identities_by_prio(&certs);
	TAILQ_CONCAT(preferred, &certs, ಮುಂದಿನ);

	/* list of keys supported by the agent */
	ಆದರೆ ((r = get_agent_identities(ssh, &agent_fd, &idlist)) == 0) {
		ಗಾಗಿ (j = 0; j < idlist->nkeys; j++) {
			ಆದರೆ ((r = sshkey_check_rsa_ಉದ್ದಳತೆ(idlist->ಕೀಲಿಗಳು[j],
			    options.required_rsa_ಗಾತ್ರ)) != 0) {
				debug_fr(r, "ignoring %s agent key",
				    sshkey_ssh_name(idlist->ಕೀಲಿಗಳು[j]));
				ಮುಂದುವರಿ;
			}
			ಸಿಕ್ಕಿತು = 0;
			TAILQ_FOREACH(id, &files, ಮುಂದಿನ) {
				/*
				 * agent keys from the config file are
				 * preferred
				 */
				ಆದರೆ (sshkey_equal(idlist->ಕೀಲಿಗಳು[j], id->ಕೀಲಿ)) {
					TAILQ_REMOVE(&files, id, ಮುಂದಿನ);
					TAILQ_INSERT_TAIL(&agent_ಕೀಲಿಗಳು, id, ಮುಂದಿನ);
					id->agent_fd = agent_fd;
					ಸಿಕ್ಕಿತು = 1;
					ನಿಲ್ಲಿಸು;
				}
			}
			ಆದರೆ (!ಸಿಕ್ಕಿತು && !options.identities_only) {
				id = xcalloc(1, ಗಾತ್ರ(*id));
				/* XXX "steals" key/comment from idlist */
				id->ಕೀಲಿ = idlist->ಕೀಲಿಗಳು[j];
				id->filename = idlist->comments[j];
				idlist->ಕೀಲಿಗಳು[j] = ಖಾಲಿ;
				idlist->comments[j] = ಖಾಲಿ;
				id->agent_fd = agent_fd;
				TAILQ_INSERT_TAIL(&agent, id, ಮುಂದಿನ);
			}
		}
		ssh_free_identitylist(idlist);
		/* append remaining agent keys */
		TAILQ_CONCAT(&agent_ಕೀಲಿಗಳು, &agent, ಮುಂದಿನ);
		ಕ್ರಮ_identities_by_prio(&agent_ಕೀಲಿಗಳು);
		TAILQ_CONCAT(preferred, &agent_ಕೀಲಿಗಳು, ಮುಂದಿನ);
		authctxt->agent_fd = agent_fd;
	}
	/* Prefer PKCS11 keys that are explicitly listed */
	TAILQ_FOREACH_ಸುರಕ್ಷಿತ(id, &files, ಮುಂದಿನ, tmp) {
		ಆದರೆ (id->ಕೀಲಿ == ಖಾಲಿ || (id->ಕೀಲಿ->flags & SSHKEY_FLAG_EXT) == 0)
			ಮುಂದುವರಿ;
		ಸಿಕ್ಕಿತು = 0;
		TAILQ_FOREACH(id2, &files, ಮುಂದಿನ) {
			ಆದರೆ (id2->ಕೀಲಿ == ಖಾಲಿ ||
			    (id2->ಕೀಲಿ->flags & SSHKEY_FLAG_EXT) != 0)
				ಮುಂದುವರಿ;
			ಆದರೆ (sshkey_equal(id->ಕೀಲಿ, id2->ಕೀಲಿ)) {
				TAILQ_REMOVE(&files, id, ಮುಂದಿನ);
				TAILQ_INSERT_TAIL(preferred, id, ಮುಂದಿನ);
				ಸಿಕ್ಕಿತು = 1;
				ನಿಲ್ಲಿಸು;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		ಆದರೆ (!ಸಿಕ್ಕಿತು && options.identities_only) {
			TAILQ_REMOVE(&files, id, ಮುಂದಿನ);
			freezero(id, ಗಾತ್ರ(*id));
		}
	}
	ಕ್ರಮ_identities_by_prio(&files);
	/* append remaining keys from the config file */
	TAILQ_CONCAT(preferred, &files, ಮುಂದಿನ);
	/* finally, filter by PubkeyAcceptedAlgorithms */
	TAILQ_FOREACH_ಸುರಕ್ಷಿತ(id, preferred, ಮುಂದಿನ, id2) {
		disallowed = 0;
		cp = ಖಾಲಿ;
		ಆದರೆ (id->ಕೀಲಿ == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		ಆದರೆ (!ಕೀಲಿ_type_allowed_by_config(id->ಕೀಲಿ)) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not in PubkeyAcceptedAlgorithms",
			    sshkey_ssh_name(id->ಕೀಲಿ), id->filename);
			disallowed = 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ssh != ಖಾಲಿ && ssh->kex != ಖಾಲಿ &&
		    ssh->kex->server_sig_algs != ಖಾಲಿ &&
		    (cp = ಕೀಲಿ_sig_algorithm(ssh, id->ಕೀಲಿ)) == ಖಾಲಿ) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not supported by server",
			    sshkey_ssh_name(id->ಕೀಲಿ), id->filename);
			disallowed = 1;
		}
		ಬಿಡುಗಡೆ(cp);
		ಆದರೆ (!disallowed)
			ಮುಂದುವರಿ;
		/* remove key */
		TAILQ_REMOVE(preferred, id, ಮುಂದಿನ);
		sshkey_free(id->ಕೀಲಿ);
		ಬಿಡುಗಡೆ(id->filename);
		freezero(id, ಗಾತ್ರ(*id));
	}
	/* List the keys we plan on using */
	TAILQ_FOREACH_ಸುರಕ್ಷಿತ(id, preferred, ಮುಂದಿನ, id2) {
		ident = format_ತಟಸ್ಥ(id);
		debug("Will attempt key: %s", ident);
		ಬಿಡುಗಡೆ(ident);
	}
	debug2_f("done");
}

ಸ್ಥಿರ ಶೂನ್ಯ
pubkey_cleanup(ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ತಟಸ್ಥ *id;

	ಆದರೆ (authctxt->agent_fd != -1) {
		ssh_close_authentication_socket(authctxt->agent_fd);
		authctxt->agent_fd = -1;
	}
	ಗಾಗಿ (id = TAILQ_FIRST(&authctxt->ಕೀಲಿಗಳು); id;
	    id = TAILQ_FIRST(&authctxt->ಕೀಲಿಗಳು)) {
		TAILQ_REMOVE(&authctxt->ಕೀಲಿಗಳು, id, ಮುಂದಿನ);
		sshkey_free(id->ಕೀಲಿ);
		ಬಿಡುಗಡೆ(id->filename);
		ಬಿಡುಗಡೆ(id);
	}
}

ಶೂನ್ಯ
pubkey_dump(ರಚನೆ ssh *ssh)
{
	Authctxt authctxt;
	ತಟಸ್ಥ *id;
	ಅಕ್ಷರ *ident;

	memset(&authctxt, 0, ಗಾತ್ರ(authctxt));
	authctxt.agent_fd = -1;
	ssh->authctxt = &authctxt;

	pubkey_prepare(ssh, &authctxt);
	TAILQ_FOREACH(id, &authctxt.ಕೀಲಿಗಳು, ಮುಂದಿನ) {
		ident = format_ತಟಸ್ಥ(id);
		fprintf(stdout, "%s\n", ident);
		ಬಿಡುಗಡೆ(ident);
	}
	pubkey_cleanup(ssh);
	ssh->authctxt = ಖಾಲಿ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
pubkey_reset(Authctxt *authctxt)
{
	ತಟಸ್ಥ *id;

	TAILQ_FOREACH(id, &authctxt->ಕೀಲಿಗಳು, ಮುಂದಿನ)
		id->tried = 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
userauth_pubkey(ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ತಟಸ್ಥ *id;
	ಪೂರ್ಣಾಂಕ ಕಳುಹಿಸಿದ = 0;
	ಅಕ್ಷರ *ident;
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ prepared;

	ಆದರೆ (!prepared) {
		pubkey_prepare(ssh, authctxt);
		prepared = 1;
	}

	ಆಗ ((id = TAILQ_FIRST(&authctxt->ಕೀಲಿಗಳು))) {
		ಆದರೆ (id->tried++)
			ಹಿಂತಿರುಗಿ (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->ಕೀಲಿಗಳು, id, ಮುಂದಿನ);
		TAILQ_INSERT_TAIL(&authctxt->ಕೀಲಿಗಳು, id, ಮುಂದಿನ);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		ಆದರೆ (id->ಕೀಲಿ != ಖಾಲಿ) {
			ident = format_ತಟಸ್ಥ(id);
			debug("Offering public key: %s", ident);
			ಬಿಡುಗಡೆ(ident);
			ಕಳುಹಿಸಿದ = send_pubkey_test(ssh, id);
		} ಇಲ್ಲದಿದ್ದರೆ {
			debug("Trying private key: %s", id->filename);
			id->ಕೀಲಿ = ತುಂಬು_ತಟಸ್ಥ_file(id);
			ಆದರೆ (id->ಕೀಲಿ != ಖಾಲಿ) {
				id->isprivate = 1;
				ಕಳುಹಿಸಿದ = sign_and_send_pubkey(ssh, id);
				sshkey_free(id->ಕೀಲಿ);
				id->ಕೀಲಿ = ಖಾಲಿ;
				id->isprivate = 0;
			}
		}
		ಆದರೆ (ಕಳುಹಿಸಿದ)
			ಹಿಂತಿರುಗಿ (ಕಳುಹಿಸಿದ);
	}
	ಹಿಂತಿರುಗಿ (0);
}

/*
 * Send userauth request message specifying keyboard-interactive method.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
userauth_kbdint(ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (authctxt->attempt_kbdint++ >= options.ಸಂಖ್ಯೆ_ದ_password_prompts)
		ಹಿಂತಿರುಗಿ 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	ಆದರೆ (authctxt->attempt_kbdint > 1 && !authctxt->info_req_ನೋಡಿದ) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_INFO_REQUEST, ಖಾಲಿ);
		ಹಿಂತಿರುಗಿ 0;
	}

	debug2("userauth_kbdint");
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->ವಿಧಾನ->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||		/* lang */
	    (r = sshpkt_put_cstring(ssh, options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_ಗಣ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_INFO_REQUEST, &ಒಳಹರಿವು_userauth_info_req);
	ಹಿಂತಿರುಗಿ 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಒಳಹರಿವು_userauth_info_req(ಪೂರ್ಣಾಂಕ type, uint32_t seq, ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ಅಕ್ಷರ *name = ಖಾಲಿ, *inst = ಖಾಲಿ, *lang = ಖಾಲಿ, *prompt = ಖಾಲಿ;
	ಅಕ್ಷರ *display_prompt = ಖಾಲಿ, *response = ಖಾಲಿ;
	u_char echo = 0;
	u_int ಅಂಕೆ_prompts, i;
	ಪೂರ್ಣಾಂಕ r, addnl;
	ಗಾತ್ರ_t len;

	debug2_f("entering");

	ಆದರೆ (authctxt == ಖಾಲಿ)
		fatal_f("no authentication context");

	authctxt->info_req_ನೋಡಿದ = 1;

	ಆದರೆ ((r = sshpkt_get_cstring(ssh, &name, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &inst, ಖಾಲಿ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ಖಾಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(name)) > 0) {
		addnl = name[len] != '\n';
		fmprintf(stderr, "%s%s", name, addnl ? "\n" : "");
	}
	ಆದರೆ ((len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(inst)) > 0) {
		addnl = inst[len] != '\n';
		fmprintf(stderr, "%s%s", inst, addnl ? "\n" : "");
	}

	ಆದರೆ ((r = sshpkt_get_u32(ssh, &ಅಂಕೆ_prompts)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_INFO_RESPONSE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, ಅಂಕೆ_prompts)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	debug2_f("num_prompts %d", ಅಂಕೆ_prompts);
	ಗಾಗಿ (i = 0; i < ಅಂಕೆ_prompts; i++) {
		ಆದರೆ ((r = sshpkt_get_cstring(ssh, &prompt, ಖಾಲಿ)) != 0 ||
		    (r = sshpkt_get_u8(ssh, &echo)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ಆದರೆ (asmprintf(&display_prompt, ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ, ಖಾಲಿ, "(%s@%s) %s",
		    authctxt->server_user, options.host_ಕೀಲಿ_alias ?
		    options.host_ಕೀಲಿ_alias : authctxt->host, prompt) == -1)
			fatal_f("asmprintf failed");
		response = read_passphrase(display_prompt, echo ? RP_ECHO : 0);
		ಆದರೆ ((r = sshpkt_put_cstring(ssh, response)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		freezero(response, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(response));
		ಬಿಡುಗಡೆ(prompt);
		ಬಿಡುಗಡೆ(display_prompt);
		display_prompt = response = prompt = ಖಾಲಿ;
	}
	/* done with parsing incoming message. */
	ಆದರೆ ((r = sshpkt_get_ಕೊನೆ(ssh)) != 0 ||
	    (r = sshpkt_ಕೂಡಿಸು_padding(ssh, 64)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	r = sshpkt_send(ssh);
 ಹೊರಹೋಗು:
	ಆದರೆ (response)
		freezero(response, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(response));
	ಬಿಡುಗಡೆ(prompt);
	ಬಿಡುಗಡೆ(display_prompt);
	ಬಿಡುಗಡೆ(name);
	ಬಿಡುಗಡೆ(inst);
	ಬಿಡುಗಡೆ(lang);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_keysign(ರಚನೆ ssh *ssh, ರಚನೆ sshkey *ಕೀಲಿ, u_char **sigp, ಗಾತ್ರ_t *lenp,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen)
{
	ರಚನೆ sshbuf *b;
	ರಚನೆ stat st;
	pid_t pid;
	ಪೂರ್ಣಾಂಕ r, ಗಮ್ಯ[2], from[2], ಸ್ಥಿತಿ_2;
	ಪೂರ್ಣಾಂಕ sock = ssh_packet_get_connection_ಒಳ(ssh);
	u_char rversion = 0, ಆವೃತ್ತಿ = 2;
	ಶೂನ್ಯ (*osigchld)(ಪೂರ್ಣಾಂಕ);

	*sigp = ಖಾಲಿ;
	*lenp = 0;

	ಆದರೆ (stat(ಮಾರ್ಗ_SSH_ಕೀಲಿ_SIGN, &st) == -1) {
		error_f("not installed: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (fflush(stdout) != 0) {
		error_f("fflush: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (pipe(ಗಮ್ಯ) == -1) {
		error_f("pipe: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ (pipe(from) == -1) {
		error_f("pipe: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	ಆದರೆ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ -1;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ಆದರೆ (pid == 0) {
		close(from[0]);
		ಆದರೆ (dup2(from[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(ಗಮ್ಯ[1]);
		ಆದರೆ (dup2(ಗಮ್ಯ[0], STDIN_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(from[1]);
		close(ಗಮ್ಯ[0]);

		ಆದರೆ (dup2(sock, STDERR_FILENO + 1) == -1)
			fatal_f("dup2: %s", strerror(errno));
		sock = STDERR_FILENO + 1;
		ಆದರೆ (fcntl(sock, F_SETFD, 0) == -1) /* keep the socket on exec */
			debug3_f("fcntl F_SETFD: %s", strerror(errno));
		closefrom(sock + 1);

		debug3_f("[child] pid=%ld, exec %s",
		    (ದೀರ್ಘ)getpid(), ಮಾರ್ಗ_SSH_ಕೀಲಿ_SIGN);
		execl(ಮಾರ್ಗ_SSH_ಕೀಲಿ_SIGN, ಮಾರ್ಗ_SSH_ಕೀಲಿ_SIGN, (ಅಕ್ಷರ *)ಖಾಲಿ);
		fatal_f("exec(%s): %s", ಮಾರ್ಗ_SSH_ಕೀಲಿ_SIGN,
		    strerror(errno));
	}
	close(from[1]);
	close(ಗಮ್ಯ[0]);
	sock = STDERR_FILENO + 1;

	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	/* send # of sock, data to be signed */
	ಆದರೆ ((r = sshbuf_put_u32(b, sock)) != 0 ||
	    (r = sshbuf_put_string(b, ದತ್ತಾಂಶ, datalen)) != 0)
		fatal_fr(r, "buffer error");
	ಆದರೆ (ssh_ಸಂದೇಶ_send(ಗಮ್ಯ[1], ಆವೃತ್ತಿ, b) == -1)
		fatal_f("couldn't send request");
	sshbuf_reset(b);
	r = ssh_ಸಂದೇಶ_recv(from[0], b);
	close(from[0]);
	close(ಗಮ್ಯ[1]);
	ಆದರೆ (r < 0) {
		error_f("no reply");
		ಹೋಗು fail;
	}

	errno = 0;
	ಆಗ (waitpid(pid, &ಸ್ಥಿತಿ_2, 0) == -1) {
		ಆದರೆ (errno != EINTR) {
			error_f("waitpid %ld: %s", (ದೀರ್ಘ)pid, strerror(errno));
			ಹೋಗು fail;
		}
	}
	ಆದರೆ (!WIFEXITED(ಸ್ಥಿತಿ_2)) {
		error_f("exited abnormally");
		ಹೋಗು fail;
	}
	ಆದರೆ (WEXITSTATUS(ಸ್ಥಿತಿ_2) != 0) {
		error_f("exited with status %d", WEXITSTATUS(ಸ್ಥಿತಿ_2));
		ಹೋಗು fail;
	}
	ಆದರೆ ((r = sshbuf_get_u8(b, &rversion)) != 0) {
		error_fr(r, "buffer error");
		ಹೋಗು fail;
	}
	ಆದರೆ (rversion != ಆವೃತ್ತಿ) {
		error_f("bad version");
		ಹೋಗು fail;
	}
	ಆದರೆ ((r = sshbuf_get_string(b, sigp, lenp)) != 0) {
		error_fr(r, "buffer error");
 fail:
		ssh_signal(SIGCHLD, osigchld);
		sshbuf_free(b);
		ಹಿಂತಿರುಗಿ -1;
	}
	ssh_signal(SIGCHLD, osigchld);
	sshbuf_free(b);

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
userauth_hostbased(ರಚನೆ ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ರಚನೆ sshkey *ಖಾಸಗಿ = ಖಾಲಿ;
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	u_char *sig = ಖಾಲಿ, *keyblob = ಖಾಲಿ;
	ಅಕ್ಷರ *fp = ಖಾಲಿ, *chost = ಖಾಲಿ, *lname = ಖಾಲಿ;
	ಗಾತ್ರ_t siglen = 0, keylen = 0;
	ಪೂರ್ಣಾಂಕ i, r, success = 0;

	ಆದರೆ (authctxt->ktypes == ಖಾಲಿ) {
		authctxt->oktypes = xstrdup(options.hostbased_accepted_algos);
		authctxt->ktypes = authctxt->oktypes;
	}

	/*
	 * Work through each listed type pattern in HostbasedAcceptedAlgorithms,
	 * trying each hostkey that matches the type in turn.
	 */
	ಗಾಗಿ (;;) {
		ಆದರೆ (authctxt->ಸಕ್ರಿಯ_ktype == ಖಾಲಿ)
			authctxt->ಸಕ್ರಿಯ_ktype = strsep(&authctxt->ktypes, ",");
		ಆದರೆ (authctxt->ಸಕ್ರಿಯ_ktype == ಖಾಲಿ ||
		    *authctxt->ಸಕ್ರಿಯ_ktype == '\0')
			ನಿಲ್ಲಿಸು;
		debug3_f("trying key type %s", authctxt->ಸಕ್ರಿಯ_ktype);

		/* check for a useful key */
		ಖಾಸಗಿ = ಖಾಲಿ;
		ಗಾಗಿ (i = 0; i < authctxt->sensitive->nkeys; i++) {
			ಆದರೆ (authctxt->sensitive->ಕೀಲಿಗಳು[i] == ಖಾಲಿ ||
			    authctxt->sensitive->ಕೀಲಿಗಳು[i]->type == ಕೀಲಿ_UNSPEC)
				ಮುಂದುವರಿ;
			ಆದರೆ (!sshkey_ಹೊಂದಿಕೆ_keyname_ಗಮ್ಯ_sigalgs(
			    sshkey_ssh_name(authctxt->sensitive->ಕೀಲಿಗಳು[i]),
			    authctxt->ಸಕ್ರಿಯ_ktype))
				ಮುಂದುವರಿ;
			/* we take and free the key */
			ಖಾಸಗಿ = authctxt->sensitive->ಕೀಲಿಗಳು[i];
			authctxt->sensitive->ಕೀಲಿಗಳು[i] = ಖಾಲಿ;
			ನಿಲ್ಲಿಸು;
		}
		/* Found one */
		ಆದರೆ (ಖಾಸಗಿ != ಖಾಲಿ)
			ನಿಲ್ಲಿಸು;
		/* No more keys of this type; advance */
		authctxt->ಸಕ್ರಿಯ_ktype = ಖಾಲಿ;
	}
	ಆದರೆ (ಖಾಸಗಿ == ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(authctxt->oktypes);
		authctxt->oktypes = authctxt->ktypes = ಖಾಲಿ;
		authctxt->ಸಕ್ರಿಯ_ktype = ಖಾಲಿ;
		debug("No more client hostkeys for hostbased authentication.");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((fp = sshkey_fingerprint(ಖಾಸಗಿ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ಖಾಲಿ) {
		error_f("sshkey_fingerprint failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	debug_f("trying hostkey %s %s using sigalg %s",
	    sshkey_ssh_name(ಖಾಸಗಿ), fp, authctxt->ಸಕ್ರಿಯ_ktype);

	/* figure out a name for the client host */
	lname = get_local_name(ssh_packet_get_connection_ಒಳ(ssh));
	ಆದರೆ (lname == ಖಾಲಿ) {
		error_f("cannot get local ipaddr/name");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* XXX sshbuf_put_stringf? */
	xasprintf(&chost, "%s.", lname);
	debug2_f("chost %s", chost);

	/* construct data */
	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ) {
		error_f("sshbuf_new failed");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshkey_ಗಮ್ಯ_blob(ಖಾಸಗಿ, &keyblob, &keylen)) != 0) {
		error_fr(r, "sshkey_to_blob");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->ವಿಧಾನ->name)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->ಸಕ್ರಿಯ_ktype)) != 0 ||
	    (r = sshbuf_put_string(b, keyblob, keylen)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->local_user)) != 0) {
		error_fr(r, "buffer error");
		ಹೋಗು ಹೊರಹೋಗು;
	}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_PK
	sshbuf_dump(b, stderr);
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ ((r = ssh_keysign(ssh, ಖಾಸಗಿ, &sig, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b))) != 0) {
		error("sign using hostkey %s %s failed",
		    sshkey_ssh_name(ಖಾಸಗಿ), fp);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshpkt_ಆರಂಭ(ssh, SSH2_ಸಂದೇಶ_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->ವಿಧಾನ->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->ಸಕ್ರಿಯ_ktype)) != 0 ||
	    (r = sshpkt_put_string(ssh, keyblob, keylen)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, chost)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->local_user)) != 0 ||
	    (r = sshpkt_put_string(ssh, sig, siglen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "packet error");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	success = 1;

 ಹೊರಹೋಗು:
	ಆದರೆ (sig != ಖಾಲಿ)
		freezero(sig, siglen);
	ಬಿಡುಗಡೆ(keyblob);
	ಬಿಡುಗಡೆ(lname);
	ಬಿಡುಗಡೆ(fp);
	ಬಿಡುಗಡೆ(chost);
	sshkey_free(ಖಾಸಗಿ);
	sshbuf_free(b);

	ಹಿಂತಿರುಗಿ success;
}

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
authmethod_is_enabled(Authmethod *ವಿಧಾನ)
{
	ಆದರೆ (ವಿಧಾನ == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	/* return false if options indicate this method is disabled */
	ಆದರೆ  (ವಿಧಾನ->enabled == ಖಾಲಿ || *ವಿಧಾನ->enabled == 0)
		ಹಿಂತಿರುಗಿ 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	ಆದರೆ  (ವಿಧಾನ->batch_flag != ಖಾಲಿ && *ವಿಧಾನ->batch_flag != 0)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ Authmethod *
authmethod_lookup(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name)
{
	Authmethod *ವಿಧಾನ = ಖಾಲಿ;
	ಆದರೆ (name != ಖಾಲಿ)
		ಗಾಗಿ (ವಿಧಾನ = authmethods; ವಿಧಾನ->name != ಖಾಲಿ; ವಿಧಾನ++)
			ಆದರೆ (strcmp(name, ವಿಧಾನ->name) == 0)
				ಹಿಂತಿರುಗಿ ವಿಧಾನ;
	debug2("Unrecognized authentication method name: %s", name ? name : "NULL");
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

/* XXX internal state */
ಸ್ಥಿರ Authmethod *current = ಖಾಲಿ;
ಸ್ಥಿರ ಅಕ್ಷರ *supported = ಖಾಲಿ;
ಸ್ಥಿರ ಅಕ್ಷರ *preferred = ಖಾಲಿ;

/*
 * Given the authentication method list sent by the server, return the
 * next method we should try.  If the server initially sends a nil list,
 * use a built-in default list.
 */
ಸ್ಥಿರ Authmethod *
authmethod_get(ಅಕ್ಷರ *authlist)
{
	ಅಕ್ಷರ *name = ಖಾಲಿ;
	u_int ಮುಂದಿನ;

	/* Use a suitable default if we're passed a nil list.  */
	ಆದರೆ (authlist == ಖಾಲಿ || ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(authlist) == 0)
		authlist = options.preferred_authentications;

	ಆದರೆ (supported == ಖಾಲಿ || strcmp(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		ಬಿಡುಗಡೆ(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = ಖಾಲಿ;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (current != ಖಾಲಿ && authmethod_is_enabled(current))
		ಹಿಂತಿರುಗಿ current;

	ಗಾಗಿ (;;) {
		ಆದರೆ ((name = ಹೊಂದಿಕೆ_list(preferred, supported, &ಮುಂದಿನ)) == ಖಾಲಿ) {
			debug("No more authentication methods to try.");
			current = ಖಾಲಿ;
			ಹಿಂತಿರುಗಿ ಖಾಲಿ;
		}
		preferred += ಮುಂದಿನ;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		ಆದರೆ ((current = authmethod_lookup(name)) != ಖಾಲಿ &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("Next authentication method: %s", name);
			ಬಿಡುಗಡೆ(name);
			ಹಿಂತಿರುಗಿ current;
		}
		ಬಿಡುಗಡೆ(name);
	}
}

ಸ್ಥಿರ ಅಕ್ಷರ *
authmethods_get(ಶೂನ್ಯ)
{
	Authmethod *ವಿಧಾನ = ಖಾಲಿ;
	ರಚನೆ sshbuf *b;
	ಅಕ್ಷರ *list;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ)
		fatal_f("sshbuf_new failed");
	ಗಾಗಿ (ವಿಧಾನ = authmethods; ವಿಧಾನ->name != ಖಾಲಿ; ವಿಧಾನ++) {
		ಆದರೆ (authmethod_is_enabled(ವಿಧಾನ)) {
			ಆದರೆ ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", ವಿಧಾನ->name)) != 0)
				fatal_fr(r, "buffer error");
		}
	}
	ಆದರೆ ((list = sshbuf_dup_string(b)) == ಖಾಲಿ)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ list;
}
