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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/wait.h>
#అన్తర్భావ <sys/queue.h>
#అన్తర్భావ <sys/stat.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <unistd.h>
#ఒకవేళ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#అన్తర్భావ <vis.h>
#అయితే_ముగింపు

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "compat.h"
#అన్తర్భావ "cipher.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "sshconnect.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "authfd.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "readconf.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "dispatch.h"
#అన్తర్భావ "canohost.h"
#అన్తర్భావ "msg.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "utf8.h"
#అన్తర్భావ "ssh-sk.h"
#అన్తర్భావ "sk-api.h"

#నిర్వచితమైతే GSSAPI
#అన్తర్భావ "ssh-gss.h"
#అయితే_ముగింపు

/* import */
బాహ్య Options options;

/*
 * SSH2 key exchange
 */

స్థిర అక్షరం *xxx_host;
స్థిర నిర్మాణం sockaddr_storage xxx_hostaddr;
స్థిర స్థిరరాశి నిర్మాణం ssh_conn_info *xxx_conn_info;
స్థిర పూర్ణాంకం కీలకం_type_allowed(నిర్మాణం sshkey *, స్థిరరాశి అక్షరం *);

స్థిర పూర్ణాంకం
verify_host_కీలకం_callback(నిర్మాణం sshkey *hostkey, నిర్మాణం ssh *ssh)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshkey_check_rsa_నిడివి(hostkey,
	    options.required_rsa_కొలత)) != 0)
		fatal_r(r, "Bad server host key");
	ఒకవేళ (!కీలకం_type_allowed(hostkey, options.hostkeyalgorithms)) {
		fatal("Server host key %s not in HostKeyAlgorithms",
		    sshkey_ssh_name(hostkey));
	}
	ఒకవేళ (verify_host_కీలకం(xxx_host, (నిర్మాణం sockaddr *)&xxx_hostaddr, hostkey,
	    xxx_conn_info) != 0)
		fatal("Host key verification failed.");
	తిరిగి 0;
}

/* Returns the first item from a comma-separated algorithm list */
స్థిర అక్షరం *
మొదటి_alg(స్థిరరాశి అక్షరం *algs)
{
	అక్షరం *ret, *cp;

	ret = xstrdup(algs);
	ఒకవేళ ((cp = strchr(ret, ',')) != ఖాళీ)
		*cp = '\0';
	తిరిగి ret;
}

స్థిర అక్షరం *
క్రమం_hostkeyalgs(అక్షరం *host, నిర్మాణం sockaddr *hostaddr, u_short పోర్టు,
    స్థిరరాశి నిర్మాణం ssh_conn_info *cinfo)
{
	అక్షరం *oavail = ఖాళీ, *avail = ఖాళీ, *మొదటి = ఖాళీ, *చివరి = ఖాళీ;
	అక్షరం *alg = ఖాళీ, *hostname = ఖాళీ, *ret = ఖాళీ, *ఉత్తమ = ఖాళీ;
	కొలత_t maxlen;
	నిర్మాణం hostkeys *hostkeys = ఖాళీ;
	పూర్ణాంకం ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, పోర్టు, &hostname, ఖాళీ);
	hostkeys = init_hostkeys();
	కొరకు (i = 0; i < options.అంకె_user_hostfiles; i++)
		ఎక్కించు_hostkeys(hostkeys, hostname, options.user_hostfiles[i], 0);
	కొరకు (i = 0; i < options.అంకె_system_hostfiles; i++) {
		ఎక్కించు_hostkeys(hostkeys, hostname,
		    options.system_hostfiles[i], 0);
	}
	ఒకవేళ (options.తెలిసిన_hosts_command != ఖాళీ) {
		ఎక్కించు_hostkeys_command(hostkeys, options.తెలిసిన_hosts_command,
		    "ORDER", cinfo, ఖాళీ, hostname);
	}
	/*
	 * If a plain public key exists that matches the type of the best
	 * preference HostkeyAlgorithms, then use the whole list as is.
	 * Note that we ignore whether the best preference algorithm is a
	 * certificate type, as sshconnect.c will downgrade certs to
	 * plain keys if necessary.
	 */
	ఉత్తమ = మొదటి_alg(options.hostkeyalgorithms);
	ఒకవేళ (lookup_కీలకం_లోపల_hostkeys_by_type(hostkeys,
	    sshkey_type_plain(sshkey_type_from_name(ఉత్తమ)),
	    sshkey_ecdsa_nid_from_name(ఉత్తమ), ఖాళీ)) {
		debug3_f("have matching best-preference key type %s, "
		    "using HostkeyAlgorithms verbatim", ఉత్తమ);
		ret = xstrdup(options.hostkeyalgorithms);
		వెళ్ళు బహిర్గతం;
	}

	/*
	 * Otherwise, prefer the host key algorithms that match known keys
	 * while keeping the ordering of HostkeyAlgorithms as much as possible.
	 */
	oavail = avail = xstrdup(options.hostkeyalgorithms);
	maxlen = అక్షరశ్రేణి_పొడవు(avail) + 1;
	మొదటి = xmalloc(maxlen);
	చివరి = xmalloc(maxlen);
	*మొదటి = *చివరి = '\0';

#నిర్వచించు ALG_APPEND(గమ్యం, from) \
	చేయి { \
		ఒకవేళ (*గమ్యం != '\0') \
			strlcat(గమ్యం, ",", maxlen); \
		strlcat(గమ్యం, from, maxlen); \
	} అయితే (0)

	అయితే ((alg = strsep(&avail, ",")) && *alg != '\0') {
		ఒకవేళ ((ktype = sshkey_type_from_name(alg)) == కీలకం_UNSPEC)
			fatal_f("unknown alg %s", alg);
		/*
		 * If we have a @cert-authority marker in known_hosts then
		 * prefer all certificate algorithms.
		 */
		ఒకవేళ (sshkey_type_is_cert(ktype) &&
		    lookup_marker_లోపల_hostkeys(hostkeys, MRK_CA)) {
			ALG_APPEND(మొదటి, alg);
			కొనసాగు;
		}
		/* If the key appears in known_hosts then prefer it */
		ఒకవేళ (lookup_కీలకం_లోపల_hostkeys_by_type(hostkeys,
		    sshkey_type_plain(ktype),
		    sshkey_ecdsa_nid_from_name(alg), ఖాళీ)) {
			ALG_APPEND(మొదటి, alg);
			కొనసాగు;
		}
		/* Otherwise, put it last */
		ALG_APPEND(చివరి, alg);
	}
#నిర్వచనం_రద్దు ALG_APPEND
	xasprintf(&ret, "%s%s%s", మొదటి,
	    (*మొదటి == '\0' || *చివరి == '\0') ? "" : ",", చివరి);
	ఒకవేళ (*మొదటి != '\0')
		debug3_f("prefer hostkeyalgs: %s", మొదటి);
	లేకపోతే
		debug3_f("no algorithms matched; accept original");
 బహిర్గతం:
	విడుదల(ఉత్తమ);
	విడుదల(మొదటి);
	విడుదల(చివరి);
	విడుదల(hostname);
	విడుదల(oavail);
	free_hostkeys(hostkeys);

	తిరిగి ret;
}

శూన్య
ssh_kex2(నిర్మాణం ssh *ssh, అక్షరం *host, నిర్మాణం sockaddr_storage *hostaddr,
    u_short పోర్టు, స్థిరరాశి నిర్మాణం ssh_conn_info *cinfo)
{
	అక్షరం *myproposal[PROPOSAL_MAX];
	అక్షరం *all_కీలకం, *hkalgs = ఖాళీ;
	పూర్ణాంకం r, use_తెలిసిన_hosts_క్రమం = 0;

	xxx_host = xstrdup(host);
	xxx_hostaddr = *hostaddr;
	xxx_conn_info = ssh_conn_info_dup(cinfo);

	ssh_packet_సమితి_rekey_limits(ssh, options.rekey_హద్దు,
	    options.rekey_interval);

	/*
	 * If the user has not specified HostkeyAlgorithms, or has only
	 * appended or removed algorithms from that list then prefer algorithms
	 * that are in the list that are supported by known_hosts keys.
	 */
	ఒకవేళ (options.hostkeyalgorithms == ఖాళీ ||
	    options.hostkeyalgorithms[0] == '-' ||
	    options.hostkeyalgorithms[0] == '+')
		use_తెలిసిన_hosts_క్రమం = 1;

	/* Expand or fill in HostkeyAlgorithms */
	all_కీలకం = sshkey_alg_list(0, 0, 1, ',');
	ఒకవేళ ((r = kex_assemble_పేర్లు(&options.hostkeyalgorithms,
	    kex_default_pk_alg(), all_కీలకం)) != 0)
		fatal_fr(r, "kex_assemble_namelist");
	విడుదల(all_కీలకం);

	ఒకవేళ (use_తెలిసిన_hosts_క్రమం) {
		hkalgs = క్రమం_hostkeyalgs(host, (నిర్మాణం sockaddr *)hostaddr,
		    పోర్టు, cinfo);
	}

	kex_proposal_populate_entries(ssh, myproposal,
	    options.kex_algorithms, options.ciphers, options.macs,
	    compression_alg_list(options.compression),
	    hkalgs ? hkalgs : options.hostkeyalgorithms);

	విడుదల(hkalgs);

	/* start key exchange */
	ఒకవేళ ((r = kex_అమరిక(ssh, myproposal)) != 0)
		fatal_r(r, "kex_setup");
#నిర్వచితమైతే WITH_OPENSSL
	ssh->kex->kex[KEX_DH_GRP1_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA1] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP16_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GRP18_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_DH_GEX_SHA1] = kexgex_client;
	ssh->kex->kex[KEX_DH_GEX_SHA256] = kexgex_client;
	ssh->kex->kex[KEX_ECDH_SHA2] = kex_gen_client;
#అయితే_ముగింపు
	ssh->kex->kex[KEX_C25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_SNTRUP761X25519_SHA512] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768X25519_SHA256] = kex_gen_client;
	ssh->kex->kex[KEX_KEM_MLKEM768ECDH_SHA256] = kex_gen_client;
	ssh->kex->verify_host_కీలకం=&verify_host_కీలకం_callback;

	ssh_dispatch_నిరంతరం_fatal(ssh, DISPATCH_ఖండం, &ssh->kex->పూర్తి);
	kex_proposal_free_entries(myproposal);

#నిర్వచితమైతే DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");
#అయితే_ముగింపు
}

/*
 * Authenticate user
 */

రకనిర్వచనం నిర్మాణం cauthctxt Authctxt;
రకనిర్వచనం నిర్మాణం cauthmethod Authmethod;
రకనిర్వచనం నిర్మాణం తటస్థం_2 తటస్థం;
రకనిర్వచనం నిర్మాణం idlist Idlist;

నిర్మాణం తటస్థం_2 {
	TAILQ_ENTRY(తటస్థం_2) తదుపరి;
	పూర్ణాంకం	agent_fd;		/* >=0 if agent supports key */
	నిర్మాణం sshkey	*కీలకం;		/* public/private key */
	అక్షరం	*filename;		/* comment for agent-only keys */
	పూర్ణాంకం	tried;
	పూర్ణాంకం	isprivate;		/* key points to the private key */
	పూర్ణాంకం	userprovided;
};
TAILQ_HEAD(idlist, తటస్థం_2);

నిర్మాణం cauthctxt {
	స్థిరరాశి అక్షరం *server_user;
	స్థిరరాశి అక్షరం *local_user;
	స్థిరరాశి అక్షరం *host;
	స్థిరరాశి అక్షరం *service;
	నిర్మాణం cauthmethod *పద్ధతి;
	sig_atomic_t success;
	అక్షరం *authlist;
#నిర్వచితమైతే GSSAPI
	/* gssapi */
	gss_OID_సమితి gss_supported_mechs;
	u_int mech_tried;
#అయితే_ముగింపు
	/* pubkey */
	నిర్మాణం idlist కీలకాలు;
	పూర్ణాంకం agent_fd;
	/* hostbased */
	Sensitive *sensitive;
	అక్షరం *oktypes, *ktypes;
	స్థిరరాశి అక్షరం *చురుకైన_ktype;
	/* kbd-interactive */
	పూర్ణాంకం info_req_చూసిన;
	పూర్ణాంకం attempt_kbdint;
	/* password */
	పూర్ణాంకం attempt_passwd;
	/* generic */
	శూన్య *methoddata;
};

నిర్మాణం cauthmethod {
	అక్షరం	*name;		/* string to compare against server's list */
	పూర్ణాంకం	(*userauth)(నిర్మాణం ssh *ssh);
	శూన్య	(*cleanup)(నిర్మాణం ssh *ssh);
	పూర్ణాంకం	*enabled;	/* flag in option struct that enables method */
	పూర్ణాంకం	*batch_flag;	/* flag in option struct that disables method */
};

స్థిర పూర్ణాంకం ఆదానం_userauth_service_accept(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
స్థిర పూర్ణాంకం ఆదానం_userauth_success(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
స్థిర పూర్ణాంకం ఆదానం_userauth_failure(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
స్థిర పూర్ణాంకం ఆదానం_userauth_banner(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
స్థిర పూర్ణాంకం ఆదానం_userauth_error(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
స్థిర పూర్ణాంకం ఆదానం_userauth_info_req(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
స్థిర పూర్ణాంకం ఆదానం_userauth_pk_ok(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
స్థిర పూర్ణాంకం ఆదానం_userauth_passwd_changereq(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);

స్థిర పూర్ణాంకం userauth_none(నిర్మాణం ssh *);
స్థిర పూర్ణాంకం userauth_pubkey(నిర్మాణం ssh *);
స్థిర పూర్ణాంకం userauth_passwd(నిర్మాణం ssh *);
స్థిర పూర్ణాంకం userauth_kbdint(నిర్మాణం ssh *);
స్థిర పూర్ణాంకం userauth_hostbased(నిర్మాణం ssh *);

#నిర్వచితమైతే GSSAPI
స్థిర పూర్ణాంకం userauth_gssapi(నిర్మాణం ssh *);
స్థిర శూన్య userauth_gssapi_cleanup(నిర్మాణం ssh *);
స్థిర పూర్ణాంకం ఆదానం_gssapi_response(పూర్ణాంకం type, uint32_t, నిర్మాణం ssh *);
స్థిర పూర్ణాంకం ఆదానం_gssapi_token(పూర్ణాంకం type, uint32_t, నిర్మాణం ssh *);
స్థిర పూర్ణాంకం ఆదానం_gssapi_error(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
స్థిర పూర్ణాంకం ఆదానం_gssapi_errtok(పూర్ణాంకం, uint32_t, నిర్మాణం ssh *);
#అయితే_ముగింపు

శూన్య	userauth(నిర్మాణం ssh *, అక్షరం *);

స్థిర శూన్య pubkey_cleanup(నిర్మాణం ssh *);
స్థిర పూర్ణాంకం sign_and_send_pubkey(నిర్మాణం ssh *ssh, తటస్థం *);
స్థిర శూన్య pubkey_prepare(నిర్మాణం ssh *, Authctxt *);
స్థిర శూన్య pubkey_reset(Authctxt *);
స్థిర నిర్మాణం sshkey *ఎక్కించు_తటస్థం_file(తటస్థం *);

స్థిర Authmethod *authmethod_get(అక్షరం *authlist);
స్థిర Authmethod *authmethod_lookup(స్థిరరాశి అక్షరం *name);
స్థిర అక్షరం *authmethods_get(శూన్య);

Authmethod authmethods[] = {
#నిర్వచితమైతే GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		userauth_gssapi_cleanup,
		&options.gss_authentication,
		ఖాళీ},
#అయితే_ముగింపు
	{"hostbased",
		userauth_hostbased,
		ఖాళీ,
		&options.hostbased_authentication,
		ఖాళీ},
	{"publickey",
		userauth_pubkey,
		ఖాళీ,
		&options.pubkey_authentication,
		ఖాళీ},
	{"keyboard-interactive",
		userauth_kbdint,
		ఖాళీ,
		&options.kbd_interactive_authentication,
		&options.batch_బహుళకం},
	{"password",
		userauth_passwd,
		ఖాళీ,
		&options.password_authentication,
		&options.batch_బహుళకం},
	{"none",
		userauth_none,
		ఖాళీ,
		ఖాళీ,
		ఖాళీ},
	{ఖాళీ, ఖాళీ, ఖాళీ, ఖాళీ, ఖాళీ}
};

శూన్య
ssh_userauth2(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *local_user,
    స్థిరరాశి అక్షరం *server_user, అక్షరం *host, Sensitive *sensitive)
{
	Authctxt authctxt;
	పూర్ణాంకం r;

	ఒకవేళ (options.preferred_authentications == ఖాళీ)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	memset(&authctxt, 0, పరిమాణం(authctxt));
	authctxt.server_user = server_user;
	authctxt.local_user = local_user;
	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.పద్ధతి = authmethod_lookup("none");
	authctxt.authlist = ఖాళీ;
	authctxt.methoddata = ఖాళీ;
	authctxt.sensitive = sensitive;
	authctxt.చురుకైన_ktype = authctxt.oktypes = authctxt.ktypes = ఖాళీ;
	authctxt.info_req_చూసిన = 0;
	authctxt.attempt_kbdint = 0;
	authctxt.attempt_passwd = 0;
#ఒకవేళ GSSAPI
	authctxt.gss_supported_mechs = ఖాళీ;
	authctxt.mech_tried = 0;
#అయితే_ముగింపు
	authctxt.agent_fd = -1;
	ఒకవేళ (authctxt.పద్ధతి == ఖాళీ)
		fatal_f("internal error: cannot send userauth none request");

	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_SERVICE_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "ssh-userauth")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh->authctxt = &authctxt;
	ssh_dispatch_init(ssh, &ఆదానం_userauth_error);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_EXT_INFO, kex_ఆదానం_ext_info);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_SERVICE_ACCEPT, &ఆదానం_userauth_service_accept);
	ssh_dispatch_నిరంతరం_fatal(ssh, DISPATCH_ఖండం, &authctxt.success);	/* loop until success */
	pubkey_cleanup(ssh);
#నిర్వచితమైతే GSSAPI
	ఒకవేళ (authctxt.gss_supported_mechs != ఖాళీ) {
		u_int ms;

		gss_release_oid_సమితి(&ms, &authctxt.gss_supported_mechs);
		authctxt.gss_supported_mechs = ఖాళీ;
	}
#అయితే_ముగింపు
	ssh->authctxt = ఖాళీ;

	ssh_dispatch_range(ssh, SSH2_సందేశం_USERAUTH_MIN, SSH2_సందేశం_USERAUTH_MAX, ఖాళీ);

	ఒకవేళ (!authctxt.success)
		fatal("Authentication failed.");
	ఒకవేళ (ssh_packet_connection_is_on_socket(ssh)) {
		verbose("Authenticated to %s ([%s]:%d) using \"%s\".", host,
		    ssh_remote_ipaddr(ssh), ssh_remote_పోర్టు(ssh),
		    authctxt.పద్ధతి->name);
	} లేకపోతే {
		verbose("Authenticated to %s (via proxy) using \"%s\".", host,
		    authctxt.పద్ధతి->name);
	}
}

స్థిర పూర్ణాంకం
ఆదానం_userauth_service_accept(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	పూర్ణాంకం r;

	ఒకవేళ (ssh_packet_మిగిలిన(ssh) > 0) {
		అక్షరం *జవాబు;

		ఒకవేళ ((r = sshpkt_get_cstring(ssh, &జవాబు, ఖాళీ)) != 0)
			వెళ్ళు బహిర్గతం;
		debug2("service_accept: %s", జవాబు);
		విడుదల(జవాబు);
	} లేకపోతే {
		debug2("buggy server: service_accept w/o service");
	}
	ఒకవేళ ((r = sshpkt_get_చివర(ssh)) != 0)
		వెళ్ళు బహిర్గతం;
	debug("SSH2_MSG_SERVICE_ACCEPT received");

	/* initial userauth request */
	userauth_none(ssh);

	/* accept EXT_INFO at any time during userauth */
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_EXT_INFO, ssh->kex->ext_info_s ?
	    &kex_ఆదానం_ext_info : &ఆదానం_userauth_error);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_SUCCESS, &ఆదానం_userauth_success);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_FAILURE, &ఆదానం_userauth_failure);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_BANNER, &ఆదానం_userauth_banner);
	r = 0;
 బహిర్గతం:
	తిరిగి r;
}

శూన్య
userauth(నిర్మాణం ssh *ssh, అక్షరం *authlist)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	ఒకవేళ (authctxt->పద్ధతి != ఖాళీ && authctxt->పద్ధతి->cleanup != ఖాళీ)
		authctxt->పద్ధతి->cleanup(ssh);

	విడుదల(authctxt->methoddata);
	authctxt->methoddata = ఖాళీ;
	ఒకవేళ (authlist == ఖాళీ) {
		authlist = authctxt->authlist;
	} లేకపోతే {
		విడుదల(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	కొరకు (;;) {
		Authmethod *పద్ధతి = authmethod_get(authlist);
		ఒకవేళ (పద్ధతి == ఖాళీ)
			fatal("%s@%s: Permission denied (%s).",
			    authctxt->server_user, authctxt->host, authlist);
		authctxt->పద్ధతి = పద్ధతి;

		/* reset the per method handler */
		ssh_dispatch_range(ssh, SSH2_సందేశం_USERAUTH_చొప్పున_పద్ధతి_MIN,
		    SSH2_సందేశం_USERAUTH_చొప్పున_పద్ధతి_MAX, ఖాళీ);

		/* and try new method */
		ఒకవేళ (పద్ధతి->userauth(ssh) != 0) {
			debug2("we sent a %s packet, wait for reply", పద్ధతి->name);
			ఆపు;
		} లేకపోతే {
			debug2("we did not send a packet, disable method");
			పద్ధతి->enabled = ఖాళీ;
		}
	}
}

స్థిర పూర్ణాంకం
ఆదానం_userauth_error(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	fatal_f("bad message during authentication: type %d", type);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ఆదానం_userauth_banner(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	అక్షరం *సందేశం = ఖాళీ;
	కొలత_t len;
	పూర్ణాంకం r;

	debug3_f("entering");
	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &సందేశం, &len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, ఖాళీ, ఖాళీ)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO)
		fmprintf(stderr, "%s", సందేశం);
	r = 0;
 బహిర్గతం:
	విడుదల(సందేశం);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
ఆదానం_userauth_success(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ఒకవేళ (authctxt == ఖాళీ)
		fatal_f("no authentication context");
	విడుదల(authctxt->authlist);
	authctxt->authlist = ఖాళీ;
	ఒకవేళ (authctxt->పద్ధతి != ఖాళీ && authctxt->పద్ధతి->cleanup != ఖాళీ)
		authctxt->పద్ధతి->cleanup(ssh);
	విడుదల(authctxt->methoddata);
	authctxt->methoddata = ఖాళీ;
	authctxt->success = 1;			/* break out */
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_EXT_INFO, dispatch_protocol_error);
	తిరిగి 0;
}

#ఒకవేళ 0
స్థిర పూర్ణాంకం
ఆదానం_userauth_success_unexpected(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	ఒకవేళ (authctxt == ఖాళీ)
		fatal_f("no authentication context");

	fatal("Unexpected authentication success during %s.",
	    authctxt->పద్ధతి->name);
	తిరిగి 0;
}
#అయితే_ముగింపు

స్థిర పూర్ణాంకం
ఆదానం_userauth_failure(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	అక్షరం *authlist = ఖాళీ;
	u_char partial;

	ఒకవేళ (authctxt == ఖాళీ)
		fatal("input_userauth_failure: no authentication context");

	ఒకవేళ (sshpkt_get_cstring(ssh, &authlist, ఖాళీ) != 0 ||
	    sshpkt_get_u8(ssh, &partial) != 0 ||
	    sshpkt_get_చివర(ssh) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ (partial != 0) {
		verbose("Authenticated using \"%s\" with partial success.",
		    authctxt->పద్ధతి->name);
		/* reset state */
		pubkey_reset(authctxt);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(ssh, authlist);
	authlist = ఖాళీ;
 బహిర్గతం:
	విడుదల(authlist);
	తిరిగి 0;
}

/*
 * Format an identity for logging including filename, key type, fingerprint
 * and location (agent, etc.). Caller must free.
 */
స్థిర అక్షరం *
format_తటస్థం(తటస్థం *id)
{
	అక్షరం *fp = ఖాళీ, *ret = ఖాళీ;
	స్థిరరాశి అక్షరం *note = "";

	ఒకవేళ (id->కీలకం != ఖాళీ) {
		fp = sshkey_fingerprint(id->కీలకం, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
	}
	ఒకవేళ (id->కీలకం) {
		ఒకవేళ ((id->కీలకం->flags & SSHKEY_FLAG_EXT) != 0)
			note = " token";
		లేకపోతే ఒకవేళ (sshkey_is_sk(id->కీలకం))
			note = " authenticator";
	}
	xasprintf(&ret, "%s %s%s%s%s%s%s",
	    id->filename,
	    id->కీలకం ? sshkey_type(id->కీలకం) : "", id->కీలకం ? " " : "",
	    fp ? fp : "",
	    id->userprovided ? " explicit" : "", note,
	    id->agent_fd != -1 ? " agent" : "");
	విడుదల(fp);
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
ఆదానం_userauth_pk_ok(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	నిర్మాణం sshbuf *keyblob = ఖాళీ;
	తటస్థం *id = ఖాళీ;
	పూర్ణాంకం pktype, దొరికింది = 0, పంపిన = 0;
	అక్షరం *pkalg = ఖాళీ, *fp = ఖాళీ, *ident = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ (authctxt == ఖాళీ)
		fatal_f("no authentication context");

	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &pkalg, ఖాళీ)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		వెళ్ళు పూర్తి;

	ఒకవేళ (సరిపోలిక_నమూనా_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		error_f("server replied to PK_OK with signature type %s not "
		    "in PubkeyAcceptedAlgorithms", pkalg);
		r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ ((pktype = sshkey_type_from_name(pkalg)) == కీలకం_UNSPEC) {
		debug_f("server sent unknown pkalg %s", pkalg);
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు పూర్తి;
	}
	/* inner key type should match signature type */
	ఒకవేళ ((r = sshkey_fromb_allowlist(keyblob, &కీలకం, pkalg, ఖాళీ)) != 0) {
		debug_r(r, "no key from blob. pkalg %s", pkalg);
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ (కీలకం->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    కీలకం->type, pktype);
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు పూర్తి;
	}

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_తిరగేయి(id, &authctxt->కీలకాలు, idlist, తదుపరి) {
		ఒకవేళ (sshkey_equal(కీలకం, id->కీలకం)) {
			దొరికింది = 1;
			ఆపు;
		}
	}
	ఒకవేళ (!దొరికింది || id == ఖాళీ) {
		fp = sshkey_fingerprint(కీలకం, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		error_f("server replied with unknown key: %s %s",
		    sshkey_type(కీలకం), fp == ఖాళీ ? "<ERROR>" : fp);
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు పూర్తి;
	}
	ident = format_తటస్థం(id);
	debug("Server accepts key: %s", ident);
	పంపిన = sign_and_send_pubkey(ssh, id);
	r = 0;
 పూర్తి:
	sshkey_free(కీలకం);
	sshbuf_free(keyblob);
	విడుదల(ident);
	విడుదల(fp);
	విడుదల(pkalg);

	/* try another method if we did not send a packet */
	ఒకవేళ (r == 0 && పంపిన == 0)
		userauth(ssh, ఖాళీ);
	తిరిగి r;
}

#నిర్వచితమైతే GSSAPI
స్థిర పూర్ణాంకం
userauth_gssapi(నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = ఖాళీ;
	OM_uint32 min;
	పూర్ణాంకం r, ok = 0;
	gss_OID mech = ఖాళీ;

	/* Try one GSSAPI method at a time, rather than sending them all at
	 * once. */

	ఒకవేళ (authctxt->gss_supported_mechs == ఖాళీ)
		gss_indicate_mechs(&min, &authctxt->gss_supported_mechs);

	/* Check to see whether the mechanism is usable before we offer it */
	అయితే (authctxt->mech_tried < authctxt->gss_supported_mechs->లెక్క &&
	    !ok) {
		mech = &authctxt->gss_supported_mechs->
		    elements[authctxt->mech_tried];
		/* My DER encoding requires length<128 */
		ఒకవేళ (mech->నిడివి < 128 && ssh_gssapi_check_mechanism(&gssctxt,
		    mech, authctxt->host)) {
			ok = 1; /* Mechanism works */
		} లేకపోతే {
			authctxt->mech_tried++;
		}
	}

	ఒకవేళ (!ok || mech == ఖాళీ)
		తిరిగి 0;

	authctxt->methoddata=(శూన్య *)gssctxt;

	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->పద్ధతి->name)) != 0 ||
	    (r = sshpkt_put_u32(ssh, 1)) != 0 ||
	    (r = sshpkt_put_u32(ssh, (mech->నిడివి) + 2)) != 0 ||
	    (r = sshpkt_put_u8(ssh, SSH_GSS_OIDTYPE)) != 0 ||
	    (r = sshpkt_put_u8(ssh, mech->నిడివి)) != 0 ||
	    (r = sshpkt_put(ssh, mech->elements, mech->నిడివి)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_RESPONSE, &ఆదానం_gssapi_response);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_TOKEN, &ఆదానం_gssapi_token);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_ERROR, &ఆదానం_gssapi_error);
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_GSSAPI_ERRTOK, &ఆదానం_gssapi_errtok);

	authctxt->mech_tried++; /* Move along to next candidate */

	తిరిగి 1;
}

స్థిర శూన్య
userauth_gssapi_cleanup(నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = (Gssctxt *)authctxt->methoddata;

	ssh_gssapi_delete_ctx(&gssctxt);
	authctxt->methoddata = ఖాళీ;
}

స్థిర OM_uint32
process_gssapi_token(నిర్మాణం ssh *ssh, gss_బఫరు_t recv_tok)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt = authctxt->methoddata;
	gss_బఫరు_desc send_tok = GSS_C_ఖాళీలు_బఫరు;
	gss_బఫరు_desc mic = GSS_C_ఖాళీలు_బఫరు;
	gss_బఫరు_desc gssbuf;
	OM_uint32 స్థితి_2, ms, flags;
	పూర్ణాంకం r;

	స్థితి_2 = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	ఒకవేళ (send_tok.నిడివి > 0) {
		u_char type = GSS_ERROR(స్థితి_2) ?
		    SSH2_సందేశం_USERAUTH_GSSAPI_ERRTOK :
		    SSH2_సందేశం_USERAUTH_GSSAPI_TOKEN;

		ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, type)) != 0 ||
		    (r = sshpkt_put_string(ssh, send_tok.విలువ,
		    send_tok.నిడివి)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send %u packet", type);

		gss_release_బఫరు(&ms, &send_tok);
	}

	ఒకవేళ (స్థితి_2 == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		ఒకవేళ (!(flags & GSS_C_INTEG_FLAG)) {
			ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh,
			    SSH2_సందేశం_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send completion");
		} లేకపోతే {
			నిర్మాణం sshbuf *b;

			ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
				fatal_f("sshbuf_new failed");
			ssh_gssapi_buildmic(b, authctxt->server_user,
			    authctxt->service, "gssapi-with-mic",
			    ssh->kex->session_id);

			ఒకవేళ ((gssbuf.విలువ = sshbuf_mutable_ptr(b)) == ఖాళీ)
				fatal_f("sshbuf_mutable_ptr failed");
			gssbuf.నిడివి = sshbuf_len(b);

			స్థితి_2 = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			ఒకవేళ (!GSS_ERROR(స్థితి_2)) {
				ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh,
				    SSH2_సందేశం_USERAUTH_GSSAPI_MIC)) != 0 ||
				    (r = sshpkt_put_string(ssh, mic.విలువ,
				    mic.నిడివి)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send MIC");
			}

			sshbuf_free(b);
			gss_release_బఫరు(&ms, &mic);
		}
	}

	తిరిగి స్థితి_2;
}

స్థిర పూర్ణాంకం
ఆదానం_gssapi_response(పూర్ణాంకం type, uint32_t plen, నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	కొలత_t oidlen;
	u_char *oidv = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ (authctxt == ఖాళీ)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	ఒకవేళ ((r = sshpkt_get_string(ssh, &oidv, &oidlen)) != 0)
		వెళ్ళు పూర్తి;

	ఒకవేళ (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		debug("Badly encoded mechanism OID received");
		userauth(ssh, ఖాళీ);
		వెళ్ళు ok;
	}

	ఒకవేళ (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	ఒకవేళ ((r = sshpkt_get_చివర(ssh)) != 0)
		వెళ్ళు పూర్తి;

	ఒకవేళ (GSS_ERROR(process_gssapi_token(ssh, GSS_C_NO_బఫరు))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(ssh, ఖాళీ);
		వెళ్ళు ok;
	}
 ok:
	r = 0;
 పూర్తి:
	విడుదల(oidv);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
ఆదానం_gssapi_token(పూర్ణాంకం type, uint32_t plen, నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_బఫరు_desc recv_tok;
	u_char *p = ఖాళీ;
	కొలత_t len;
	OM_uint32 స్థితి_2;
	పూర్ణాంకం r;

	ఒకవేళ (authctxt == ఖాళీ)
		fatal("input_gssapi_response: no authentication context");

	ఒకవేళ ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0)
		వెళ్ళు బహిర్గతం;

	recv_tok.విలువ = p;
	recv_tok.నిడివి = len;
	స్థితి_2 = process_gssapi_token(ssh, &recv_tok);

	/* Start again with the next method in the list */
	ఒకవేళ (GSS_ERROR(స్థితి_2)) {
		userauth(ssh, ఖాళీ);
		/* ok */
	}
	r = 0;
 బహిర్గతం:
	విడుదల(p);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
ఆదానం_gssapi_errtok(పూర్ణాంకం type, uint32_t plen, నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_బఫరు_desc send_tok = GSS_C_ఖాళీలు_బఫరు;
	gss_బఫరు_desc recv_tok;
	OM_uint32 ms;
	u_char *p = ఖాళీ;
	కొలత_t len;
	పూర్ణాంకం r;

	ఒకవేళ (authctxt == ఖాళీ)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	ఒకవేళ ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_చివర(ssh)) != 0) {
		విడుదల(p);
		తిరిగి r;
	}

	/* Stick it into GSSAPI and see what it says */
	recv_tok.విలువ = p;
	recv_tok.నిడివి = len;
	(శూన్య)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, ఖాళీ);
	విడుదల(p);
	gss_release_బఫరు(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ఆదానం_gssapi_error(పూర్ణాంకం type, uint32_t plen, నిర్మాణం ssh *ssh)
{
	అక్షరం *సందేశం = ఖాళీ;
	అక్షరం *lang = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshpkt_get_u32(ssh, ఖాళీ)) != 0 ||	/* maj */
	    (r = sshpkt_get_u32(ssh, ఖాళీ)) != 0 ||	/* min */
	    (r = sshpkt_get_cstring(ssh, &సందేశం, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ఖాళీ)) != 0)
		వెళ్ళు బహిర్గతం;
	r = sshpkt_get_చివర(ssh);
	debug("Server GSSAPI Error:\n%s", సందేశం);
 బహిర్గతం:
	విడుదల(సందేశం);
	విడుదల(lang);
	తిరిగి r;
}
#అయితే_ముగింపు /* GSSAPI */

స్థిర పూర్ణాంకం
userauth_none(నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	పూర్ణాంకం r;

	/* initial userauth request */
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->పద్ధతి->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	తిరిగి 1;
}

స్థిర పూర్ణాంకం
userauth_passwd(నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	అక్షరం *password, *prompt = ఖాళీ;
	స్థిరరాశి అక్షరం *host = options.host_కీలకం_alias ?  options.host_కీలకం_alias :
	    authctxt->host;
	పూర్ణాంకం r;

	ఒకవేళ (authctxt->attempt_passwd++ >= options.సంఖ్య_యొక్క_password_prompts)
		తిరిగి 0;

	ఒకవేళ (authctxt->attempt_passwd != 1)
		error("Permission denied, please try again.");

	xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->పద్ధతి->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_కూడు_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	విడుదల(prompt);
	ఒకవేళ (password != ఖాళీ)
		freezero(password, అక్షరశ్రేణి_పొడవు(password));

	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_PASSWD_CHANGEREQ,
	    &ఆదానం_userauth_passwd_changereq);

	తిరిగి 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
స్థిర పూర్ణాంకం
ఆదానం_userauth_passwd_changereq(పూర్ణాంకం type, uint32_t seqnr, నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	అక్షరం *info = ఖాళీ, *lang = ఖాళీ, *password = ఖాళీ, *retype = ఖాళీ;
	అక్షరం prompt[256];
	స్థిరరాశి అక్షరం *host;
	పూర్ణాంకం r, addnl;
	కొలత_t len;

	debug2("input_userauth_passwd_changereq");

	ఒకవేళ (authctxt == ఖాళీ)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");
	host = options.host_కీలకం_alias ? options.host_కీలకం_alias : authctxt->host;

	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &info, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ఖాళీ)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((len = అక్షరశ్రేణి_పొడవు(info)) > 0) {
		addnl = info[len] != '\n';
		fmprintf(stderr, "%s%s", info, addnl ? "\n" : "");
	}
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->పద్ధతి->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0)	/* additional info */
		వెళ్ళు బహిర్గతం;

	snprintf(prompt, పరిమాణం(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	ఒకవేళ ((r = sshpkt_put_cstring(ssh, password)) != 0)
		వెళ్ళు బహిర్గతం;

	freezero(password, అక్షరశ్రేణి_పొడవు(password));
	password = ఖాళీ;
	అయితే (password == ఖాళీ) {
		snprintf(prompt, పరిమాణం(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		ఒకవేళ (password == ఖాళీ) {
			/* bail out */
			r = 0;
			వెళ్ళు బహిర్గతం;
		}
		snprintf(prompt, పరిమాణం(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		ఒకవేళ (strcmp(password, retype) != 0) {
			freezero(password, అక్షరశ్రేణి_పొడవు(password));
			logit("Mismatch; try again, EOF to quit.");
			password = ఖాళీ;
		}
		freezero(retype, అక్షరశ్రేణి_పొడవు(retype));
	}
	ఒకవేళ ((r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_కూడు_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		వెళ్ళు బహిర్గతం;

	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_PASSWD_CHANGEREQ,
	    &ఆదానం_userauth_passwd_changereq);
	r = 0;
 బహిర్గతం:
	ఒకవేళ (password)
		freezero(password, అక్షరశ్రేణి_పొడవు(password));
	విడుదల(info);
	విడుదల(lang);
	తిరిగి r;
}

/*
 * Select an algorithm for publickey signatures.
 * Returns algorithm (caller must free) or NULL if no mutual algorithm found.
 *
 * Call with ssh==NULL to ignore server-sig-algs extension list and
 * only attempt with the key's base signature type.
 */
స్థిర అక్షరం *
కీలకం_sig_algorithm(నిర్మాణం ssh *ssh, స్థిరరాశి నిర్మాణం sshkey *కీలకం)
{
	అక్షరం *allowed, *oallowed, *cp, *tmp, *alg = ఖాళీ;
	స్థిరరాశి అక్షరం *server_sig_algs;

	/*
	 * The signature algorithm will only differ from the key algorithm
	 * for RSA keys/certs and when the server advertises support for
	 * newer (SHA2) algorithms.
	 */
	ఒకవేళ (ssh == ఖాళీ || ssh->kex->server_sig_algs == ఖాళీ ||
	    (కీలకం->type != కీలకం_RSA && కీలకం->type != కీలకం_RSA_CERT) ||
	    (కీలకం->type == కీలకం_RSA_CERT && (ssh->compat & SSH_BUG_SIGTYPE))) {
		/* Filter base key signature alg against our configuration */
		తిరిగి సరిపోలిక_list(sshkey_ssh_name(కీలకం),
		    options.pubkey_accepted_algos, ఖాళీ);
	}

	/*
	 * Workaround OpenSSH 7.4 bug: this version supports RSA/SHA-2 but
	 * fails to advertise it via SSH2_MSG_EXT_INFO.
	 */
	server_sig_algs = ssh->kex->server_sig_algs;
	ఒకవేళ (కీలకం->type == కీలకం_RSA && (ssh->compat & SSH_BUG_SIGTYPE74))
		server_sig_algs = "rsa-sha2-256,rsa-sha2-512";

	/*
	 * For RSA keys/certs, since these might have a different sig type:
	 * find the first entry in PubkeyAcceptedAlgorithms of the right type
	 * that also appears in the supported signature algorithms list from
	 * the server.
	 */
	oallowed = allowed = xstrdup(options.pubkey_accepted_algos);
	అయితే ((cp = strsep(&allowed, ",")) != ఖాళీ) {
		ఒకవేళ (sshkey_type_from_name(cp) != కీలకం->type)
			కొనసాగు;
		tmp = సరిపోలిక_list(sshkey_sigalg_by_name(cp),
		    server_sig_algs, ఖాళీ);
		ఒకవేళ (tmp != ఖాళీ)
			alg = xstrdup(cp);
		విడుదల(tmp);
		ఒకవేళ (alg != ఖాళీ)
			ఆపు;
	}
	విడుదల(oallowed);
	తిరిగి alg;
}

స్థిర పూర్ణాంకం
తటస్థం_sign(నిర్మాణం తటస్థం_2 *id, u_char **sigp, కొలత_t *lenp,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen, u_int compat, స్థిరరాశి అక్షరం *alg)
{
	నిర్మాణం sshkey *sign_కీలకం = ఖాళీ, *prv = ఖాళీ;
	పూర్ణాంకం is_agent = 0, retried = 0, r = SSH_ERR_అంతర్గత_ERROR;
	నిర్మాణం notifier_ctx *notifier = ఖాళీ;
	అక్షరం *fp = ఖాళీ, *pin = ఖాళీ, *prompt = ఖాళీ;

	*sigp = ఖాళీ;
	*lenp = 0;

	/* The agent supports this key. */
	ఒకవేళ (id->కీలకం != ఖాళీ && id->agent_fd != -1) {
		తిరిగి ssh_agent_sign(id->agent_fd, id->కీలకం, sigp, lenp,
		    దత్తాంశం, datalen, alg, compat);
	}

	/*
	 * We have already loaded the private key or the private key is
	 * stored in external hardware.
	 */
	ఒకవేళ (id->కీలకం != ఖాళీ &&
	    (id->isprivate || (id->కీలకం->flags & SSHKEY_FLAG_EXT))) {
		sign_కీలకం = id->కీలకం;
		is_agent = 1;
	} లేకపోతే {
		/* Load the private key from the file. */
		ఒకవేళ ((prv = ఎక్కించు_తటస్థం_file(id)) == ఖాళీ)
			తిరిగి SSH_ERR_కీలకం_NOT_దొరికింది;
		ఒకవేళ (id->కీలకం != ఖాళీ && !sshkey_equal_ప్రజా(prv, id->కీలకం)) {
			error_f("private key %s contents do not match public",
			    id->filename);
			r = SSH_ERR_కీలకం_NOT_దొరికింది;
			వెళ్ళు బహిర్గతం;
		}
		sign_కీలకం = prv;
	}
 retry_pin:
	/* Prompt for touch for non-agent FIDO keys that request UP */
	ఒకవేళ (!is_agent && sshkey_is_sk(sign_కీలకం) &&
	    (sign_కీలకం->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
		/* XXX should batch mode just skip these? */
		ఒకవేళ ((fp = sshkey_fingerprint(sign_కీలకం,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ఖాళీ)
			fatal_f("fingerprint failed");
		notifier = notify_ప్రారంభం(options.batch_బహుళకం,
		    "Confirm user presence for key %s %s",
		    sshkey_type(sign_కీలకం), fp);
		విడుదల(fp);
	}
	ఒకవేళ ((r = sshkey_sign(sign_కీలకం, sigp, lenp, దత్తాంశం, datalen,
	    alg, options.sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		ఒకవేళ (!retried && pin == ఖాళీ && !is_agent &&
		    sshkey_is_sk(sign_కీలకం) &&
		    r == SSH_ERR_కీలకం_WRONG_PASSPHRASE) {
			notify_complete(notifier, ఖాళీ);
			notifier = ఖాళీ;
			xasprintf(&prompt, "Enter PIN for %s key %s: ",
			    sshkey_type(sign_కీలకం), id->filename);
			pin = read_passphrase(prompt, 0);
			retried = 1;
			వెళ్ళు retry_pin;
		}
		వెళ్ళు బహిర్గతం;
	}

	/*
	 * PKCS#11 tokens may not support all signature algorithms,
	 * so check what we get back.
	 */
	ఒకవేళ (id->కీలకం != ఖాళీ && (id->కీలకం->flags & SSHKEY_FLAG_EXT) != 0 &&
	    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
		debug_fr(r, "sshkey_check_sigtype");
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	r = 0;
 బహిర్గతం:
	విడుదల(prompt);
	ఒకవేళ (pin != ఖాళీ)
		freezero(pin, అక్షరశ్రేణి_పొడవు(pin));
	notify_complete(notifier, r == 0 ? "User presence confirmed" : ఖాళీ);
	sshkey_free(prv);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
id_filename_matches(తటస్థం *id, తటస్థం *వ్యక్తిగత_id)
{
	స్థిర స్థిరరాశి అక్షరం * స్థిరరాశి suffixes[] = { ".pub", "-cert.pub", ఖాళీ };
	కొలత_t len = అక్షరశ్రేణి_పొడవు(id->filename), plen = అక్షరశ్రేణి_పొడవు(వ్యక్తిగత_id->filename);
	కొలత_t i, slen;

	ఒకవేళ (strcmp(id->filename, వ్యక్తిగత_id->filename) == 0)
		తిరిగి 1;
	కొరకు (i = 0; suffixes[i]; i++) {
		slen = అక్షరశ్రేణి_పొడవు(suffixes[i]);
		ఒకవేళ (len > slen && plen == len - slen &&
		    strcmp(id->filename + (len - slen), suffixes[i]) == 0 &&
		    memcmp(id->filename, వ్యక్తిగత_id->filename, plen) == 0)
			తిరిగి 1;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
sign_and_send_pubkey(నిర్మాణం ssh *ssh, తటస్థం *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	నిర్మాణం sshbuf *b = ఖాళీ;
	తటస్థం *వ్యక్తిగత_id, *sign_id = ఖాళీ;
	u_char *signature = ఖాళీ;
	కొలత_t slen = 0, skip = 0;
	పూర్ణాంకం r, fallback_sigtype, పంపిన = 0;
	అక్షరం *alg = ఖాళీ, *fp = ఖాళీ;
	స్థిరరాశి అక్షరం *loc = "", *పద్ధతి = "publickey";
	పూర్ణాంకం hostbound = 0;

	/* prefer host-bound pubkey signatures if supported by server */
	ఒకవేళ ((ssh->kex->flags & KEX_HAS_PUBKEY_HOSTBOUND) != 0 &&
	    (options.pubkey_authentication & SSH_PUBKEY_AUTH_HBOUND) != 0) {
		hostbound = 1;
		పద్ధతి = "publickey-hostbound-v00@openssh.com";
	}

	ఒకవేళ ((fp = sshkey_fingerprint(id->కీలకం, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ఖాళీ)
		తిరిగి 0;

	debug3_f("using %s with %s %s", పద్ధతి, sshkey_type(id->కీలకం), fp);

	/*
	 * If the key is an certificate, try to find a matching private key
	 * and use it to complete the signature.
	 * If no such private key exists, fall back to trying the certificate
	 * key itself in case it has a private half already loaded.
	 * This will try to set sign_id to the private key that will perform
	 * the signature.
	 */
	ఒకవేళ (id->agent_fd == -1 && sshkey_is_cert(id->కీలకం)) {
		TAILQ_FOREACH(వ్యక్తిగత_id, &authctxt->కీలకాలు, తదుపరి) {
			ఒకవేళ (sshkey_equal_ప్రజా(id->కీలకం, వ్యక్తిగత_id->కీలకం) &&
			    id->కీలకం->type != వ్యక్తిగత_id->కీలకం->type) {
				sign_id = వ్యక్తిగత_id;
				ఆపు;
			}
		}
		/*
		 * Exact key matches are preferred, but also allow
		 * filename matches for non-PKCS#11/agent keys that
		 * didn't load public keys. This supports the case
		 * of keeping just a private key file and public
		 * certificate on disk.
		 */
		ఒకవేళ (sign_id == ఖాళీ &&
		    !id->isprivate && id->agent_fd == -1 &&
		    (id->కీలకం->flags & SSHKEY_FLAG_EXT) == 0) {
			TAILQ_FOREACH(వ్యక్తిగత_id, &authctxt->కీలకాలు, తదుపరి) {
				ఒకవేళ (వ్యక్తిగత_id->కీలకం == ఖాళీ &&
				    id_filename_matches(id, వ్యక్తిగత_id)) {
					sign_id = వ్యక్తిగత_id;
					ఆపు;
				}
			}
		}
		ఒకవేళ (sign_id != ఖాళీ) {
			debug2_f("using private key \"%s\"%s for "
			    "certificate", sign_id->filename,
			    sign_id->agent_fd != -1 ? " from agent" : "");
		} లేకపోతే {
			debug_f("no separate private key for certificate "
			    "\"%s\"", id->filename);
		}
	}

	/*
	 * If the above didn't select another identity to do the signing
	 * then default to the one we started with.
	 */
	ఒకవేళ (sign_id == ఖాళీ)
		sign_id = id;

	/* assemble and sign data */
	కొరకు (fallback_sigtype = 0; fallback_sigtype <= 1; fallback_sigtype++) {
		విడుదల(alg);
		slen = 0;
		signature = ఖాళీ;
		ఒకవేళ ((alg = కీలకం_sig_algorithm(fallback_sigtype ? ఖాళీ : ssh,
		    id->కీలకం)) == ఖాళీ) {
			error_f("no mutual signature supported");
			వెళ్ళు బహిర్గతం;
		}
		debug3_f("signing using %s %s", alg, fp);

		sshbuf_free(b);
		ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
			fatal_f("sshbuf_new failed");
		ఒకవేళ ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "sshbuf_put_stringb");
		skip = sshbuf_len(b);
		ఒకవేళ ((r = sshbuf_put_u8(b, SSH2_సందేశం_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, పద్ధతి)) != 0 ||
		    (r = sshbuf_put_u8(b, 1)) != 0 ||
		    (r = sshbuf_put_cstring(b, alg)) != 0 ||
		    (r = sshkey_puts(id->కీలకం, b)) != 0) {
			fatal_fr(r, "assemble signed data");
		}
		ఒకవేళ (hostbound) {
			ఒకవేళ (ssh->kex->initial_hostkey == ఖాళీ) {
				fatal_f("internal error: initial hostkey "
				    "not recorded");
			}
			ఒకవేళ ((r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
				fatal_fr(r, "assemble %s hostkey", పద్ధతి);
		}
		/* generate signature */
		r = తటస్థం_sign(sign_id, &signature, &slen,
		    sshbuf_ptr(b), sshbuf_len(b), ssh->compat, alg);
		ఒకవేళ (r == 0)
			ఆపు;
		లేకపోతే ఒకవేళ (r == SSH_ERR_కీలకం_NOT_దొరికింది)
			వెళ్ళు బహిర్గతం; /* soft failure */
		లేకపోతే ఒకవేళ (r == SSH_ERR_SIGN_ALG_UNSUPPORTED &&
		    !fallback_sigtype) {
			ఒకవేళ (sign_id->agent_fd != -1)
				loc = "agent ";
			లేకపోతే ఒకవేళ (sign_id->కీలకం != ఖాళీ &&
			    (sign_id->కీలకం->flags & SSHKEY_FLAG_EXT) != 0)
				loc = "token ";
			logit("%skey %s %s returned incorrect signature type",
			    loc, sshkey_type(id->కీలకం), fp);
			కొనసాగు;
		}
		error_fr(r, "signing failed for %s \"%s\"%s",
		    sshkey_type(sign_id->కీలకం), sign_id->filename,
		    id->agent_fd != -1 ? " from agent" : "");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (slen == 0 || signature == ఖాళీ) /* shouldn't happen */
		fatal_f("no signature");

	/* append signature */
	ఒకవేళ ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_fr(r, "append signature");

#నిర్వచితమైతే DEBUG_PK
	sshbuf_dump(b, stderr);
#అయితే_ముగింపు
	/* skip session id and packet type */
	ఒకవేళ ((r = sshbuf_consume(b, skip + 1)) != 0)
		fatal_fr(r, "consume");

	/* put remaining data from buffer into packet */
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_putb(ssh, b)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "enqueue request");

	/* success */
	పంపిన = 1;

 బహిర్గతం:
	విడుదల(fp);
	విడుదల(alg);
	sshbuf_free(b);
	freezero(signature, slen);
	తిరిగి పంపిన;
}

స్థిర పూర్ణాంకం
send_pubkey_test(నిర్మాణం ssh *ssh, తటస్థం *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	u_char *blob = ఖాళీ;
	అక్షరం *alg = ఖాళీ;
	కొలత_t bloblen;
	u_int have_sig = 0;
	పూర్ణాంకం పంపిన = 0, r;

	ఒకవేళ ((alg = కీలకం_sig_algorithm(ssh, id->కీలకం)) == ఖాళీ) {
		debug_f("no mutual signature algorithm");
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((r = sshkey_గమ్యం_blob(id->కీలకం, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3_f("cannot handle key");
		వెళ్ళు బహిర్గతం;
	}
	/* register callback for USERAUTH_PK_OK message */
	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_PK_OK, &ఆదానం_userauth_pk_ok);

	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->పద్ధతి->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, have_sig)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, alg)) != 0 ||
	    (r = sshpkt_put_string(ssh, blob, bloblen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	పంపిన = 1;

 బహిర్గతం:
	విడుదల(alg);
	విడుదల(blob);
	తిరిగి పంపిన;
}

స్థిర నిర్మాణం sshkey *
ఎక్కించు_తటస్థం_file(తటస్థం *id)
{
	నిర్మాణం sshkey *అంతరంగ = ఖాళీ;
	అక్షరం prompt[300], *passphrase, *comment;
	పూర్ణాంకం r, quit = 0, i;
	నిర్మాణం stat st;

	ఒకవేళ (stat(id->filename, &st) == -1) {
		do_log2(id->userprovided ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_DEBUG3,
		    "no such identity: %s: %s", id->filename, strerror(errno));
		తిరిగి ఖాళీ;
	}
	snprintf(prompt, పరిమాణం prompt,
	    "Enter passphrase for key '%.100s': ", id->filename);
	కొరకు (i = 0; i <= options.సంఖ్య_యొక్క_password_prompts; i++) {
		ఒకవేళ (i == 0)
			passphrase = "";
		లేకపోతే {
			passphrase = read_passphrase(prompt, 0);
			ఒకవేళ (*passphrase == '\0') {
				debug2("no passphrase given, try next key");
				విడుదల(passphrase);
				ఆపు;
			}
		}
		ఎంపిక ((r = sshkey_ఎక్కించు_వ్యక్తిగత_type(కీలకం_UNSPEC, id->filename,
		    passphrase, &అంతరంగ, &comment))) {
		స్థితి 0:
			ఆపు;
		స్థితి SSH_ERR_కీలకం_WRONG_PASSPHRASE:
			ఒకవేళ (options.batch_బహుళకం) {
				quit = 1;
				ఆపు;
			}
			ఒకవేళ (i != 0)
				debug2("bad passphrase given, try again...");
			ఆపు;
		స్థితి SSH_ERR_SYSTEM_ERROR:
			ఒకవేళ (errno == ENOENT) {
				debug2_r(r, "Load key \"%s\"", id->filename);
				quit = 1;
				ఆపు;
			}
			/* FALLTHROUGH */
		అప్రమేయ:
			error_r(r, "Load key \"%s\"", id->filename);
			quit = 1;
			ఆపు;
		}
		ఒకవేళ (అంతరంగ != ఖాళీ && sshkey_is_sk(అంతరంగ) &&
		    options.sk_provider == ఖాళీ) {
			debug("key \"%s\" is an authenticator-hosted key, "
			    "but no provider specified", id->filename);
			sshkey_free(అంతరంగ);
			అంతరంగ = ఖాళీ;
			quit = 1;
		}
		ఒకవేళ (!quit && (r = sshkey_check_rsa_నిడివి(అంతరంగ,
		    options.required_rsa_కొలత)) != 0) {
			debug_fr(r, "Skipping key %s", id->filename);
			sshkey_free(అంతరంగ);
			అంతరంగ = ఖాళీ;
			quit = 1;
		}
		ఒకవేళ (!quit && అంతరంగ != ఖాళీ && id->agent_fd == -1 &&
		    !(id->కీలకం && id->isprivate))
			maybe_కూడు_కీలకం_గమ్యం_agent(id->filename, అంతరంగ, comment,
			    passphrase);
		ఒకవేళ (i > 0)
			freezero(passphrase, అక్షరశ్రేణి_పొడవు(passphrase));
		విడుదల(comment);
		ఒకవేళ (అంతరంగ != ఖాళీ || quit)
			ఆపు;
	}
	తిరిగి అంతరంగ;
}

స్థిర పూర్ణాంకం
కీలకం_type_allowed(నిర్మాణం sshkey *కీలకం, స్థిరరాశి అక్షరం *allowlist)
{
	ఒకవేళ (సరిపోలిక_నమూనా_list(sshkey_ssh_name(కీలకం), allowlist, 0) == 1)
		తిరిగి 1;

	/* RSA keys/certs might be allowed by alternate signature types */
	ఎంపిక (కీలకం->type) {
	స్థితి కీలకం_RSA:
		ఒకవేళ (సరిపోలిక_నమూనా_list("rsa-sha2-512", allowlist, 0) == 1)
			తిరిగి 1;
		ఒకవేళ (సరిపోలిక_నమూనా_list("rsa-sha2-256", allowlist, 0) == 1)
			తిరిగి 1;
		ఆపు;
	స్థితి కీలకం_RSA_CERT:
		ఒకవేళ (సరిపోలిక_నమూనా_list("rsa-sha2-512-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			తిరిగి 1;
		ఒకవేళ (సరిపోలిక_నమూనా_list("rsa-sha2-256-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			తిరిగి 1;
		ఆపు;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
కీలకం_type_allowed_by_config(నిర్మాణం sshkey *కీలకం)
{
	తిరిగి కీలకం_type_allowed(కీలకం, options.pubkey_accepted_algos);
}

/* obtain a list of keys from the agent */
స్థిర పూర్ణాంకం
get_agent_identities(నిర్మాణం ssh *ssh, పూర్ణాంకం *agent_fdp,
    నిర్మాణం ssh_identitylist **idlistp)
{
	పూర్ణాంకం r, agent_fd;
	నిర్మాణం ssh_identitylist *idlist;

	ఒకవేళ ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		ఒకవేళ (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		తిరిగి r;
	}
	ఒకవేళ (ssh != ఖాళీ && ssh->kex != ఖాళీ) {
		ఒకవేళ ((r = ssh_agent_bind_hostkey(agent_fd, ssh->kex->initial_hostkey,
		    ssh->kex->session_id, ssh->kex->initial_sig, 0)) == 0)
			debug_f("bound agent to hostkey");
		లేకపోతే
			debug2_fr(r, "ssh_agent_bind_hostkey");
	}

	ఒకవేళ ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		close(agent_fd);
		తిరిగి r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	తిరిగి 0;
}

/*
 * Returns nonzero if the certificate extensions/critical-options section
 * has the specified option present, zero otherwise.
 */
స్థిర పూర్ణాంకం
cert_has_option(నిర్మాణం sshbuf *oblob, స్థిరరాశి అక్షరం *లక్ష్యం)
{
	నిర్మాణం sshbuf *c = ఖాళీ, *దత్తాంశం = ఖాళీ;
	అక్షరం *name = ఖాళీ;
	పూర్ణాంకం r, దొరికింది = 0;

	ఒకవేళ (oblob == ఖాళీ || (c = sshbuf_fromb(oblob)) == ఖాళీ)
		తిరిగి 0;
	అయితే (sshbuf_len(c) > 0) {
		sshbuf_free(దత్తాంశం);
		దత్తాంశం = ఖాళీ;
		విడుదల(name);
		name = ఖాళీ;
		ఒకవేళ ((r = sshbuf_get_cstring(c, &name, ఖాళీ)) != 0 ||
		    (r = sshbuf_froms(c, &దత్తాంశం)) != 0)
			ఆపు;
		ఒకవేళ (strcmp(name, లక్ష్యం) == 0) {
			దొరికింది = 1;
			ఆపు;
		}
	}
	sshbuf_free(దత్తాంశం);
	విడుదల(name);
	sshbuf_free(c);
	తిరిగి దొరికింది;
}

/*
 * Returns an integer describing the priority of the identity
 * within its group. Lower numbers are higher priority.
 */
#నిర్వచించు MAX_ID_ప్రాధాన్యత 3
స్థిర పూర్ణాంకం
తటస్థం_prioritise(నిర్మాణం తటస్థం_2 *id)
{
	ఒకవేళ (id == ఖాళీ || id->కీలకం == ఖాళీ)
		తిరిగి 3;
	ఒకవేళ (!sshkey_is_cert(id->కీలకం) || id->కీలకం->cert == ఖాళీ)
		తిరిగి 3;
	ఒకవేళ (sshkey_is_sk(id->కీలకం) &&
	    cert_has_option(id->కీలకం->cert->critical, "verify-required"))
		తిరిగి 2;
	ఒకవేళ (sshkey_is_sk(id->కీలకం) &&
	    cert_has_option(id->కీలకం->cert->extensions, "no-touch-required"))
		తిరిగి 0;
	తిరిగి 1;
}

స్థిర శూన్య
క్రమం_identities_by_prio(నిర్మాణం idlist *list)
{
	నిర్మాణం idlist prio[MAX_ID_ప్రాధాన్యత + 1], sorted;
	నిర్మాణం తటస్థం_2 *id, *tmp, *dummy;
	పూర్ణాంకం p;

	కొరకు (p = 0; p <= MAX_ID_ప్రాధాన్యత; p++)
		TAILQ_INIT(&prio[p]);
	TAILQ_INIT(&sorted);

	TAILQ_FOREACH_సురక్షిత(id, list, తదుపరి, tmp) {
		ఒకవేళ (id->userprovided)
			కొనసాగు;
		dummy = xcalloc(1, పరిమాణం(*dummy));
		dummy->userprovided = -1;
		TAILQ_INSERT_BEFORE(id, dummy, తదుపరి);
		TAILQ_REMOVE(list, id, తదుపరి);
		p = తటస్థం_prioritise(id);
		ఒకవేళ (p < 0 || p > MAX_ID_ప్రాధాన్యత)
			fatal_f("internal error: bad priority");
		TAILQ_INSERT_TAIL(&prio[p], id, తదుపరి);
	}
	కొరకు (p = 0; p <= MAX_ID_ప్రాధాన్యత; p++)
		TAILQ_CONCAT(&sorted, &prio[p], తదుపరి);

	TAILQ_FOREACH_సురక్షిత(id, list, తదుపరి, tmp) {
		ఒకవేళ (id->userprovided != -1)
			కొనసాగు;
		నిర్మాణం తటస్థం_2 *s = TAILQ_FIRST(&sorted);
		TAILQ_REMOVE(&sorted, s, తదుపరి);
		TAILQ_INSERT_BEFORE(id, s, తదుపరి);
		TAILQ_REMOVE(list, id, తదుపరి);
		విడుదల(id);
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
స్థిర శూన్య
pubkey_prepare(నిర్మాణం ssh *ssh, Authctxt *authctxt)
{
	నిర్మాణం తటస్థం_2 *id, *id2, *tmp;
	నిర్మాణం idlist agent, files, certs, agent_కీలకాలు, *preferred;
	నిర్మాణం sshkey *కీలకం;
	పూర్ణాంకం disallowed, agent_fd = -1, i, r, దొరికింది;
	కొలత_t j;
	నిర్మాణం ssh_identitylist *idlist;
	అక్షరం *cp, *ident;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	TAILQ_INIT(&certs);	/* certificates specified by user */
	TAILQ_INIT(&agent_కీలకాలు); /* keys supported by the agent */
	preferred = &authctxt->కీలకాలు;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	కొరకు (i = 0; i < options.అంకె_తటస్థం_files; i++) {
		కీలకం = options.తటస్థం_కీలకాలు[i];
		ఒకవేళ (కీలకం && కీలకం->cert &&
		    కీలకం->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.తటస్థం_files[i]);
			కొనసాగు;
		}
		ఒకవేళ (కీలకం && sshkey_is_sk(కీలకం) && options.sk_provider == ఖాళీ) {
			debug_f("ignoring authenticator-hosted key %s as no "
			    "SecurityKeyProvider has been specified",
			    options.తటస్థం_files[i]);
			కొనసాగు;
		}
		options.తటస్థం_కీలకాలు[i] = ఖాళీ;
		id = xcalloc(1, పరిమాణం(*id));
		id->agent_fd = -1;
		id->కీలకం = కీలకం;
		id->filename = xstrdup(options.తటస్థం_files[i]);
		id->userprovided = options.తటస్థం_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, తదుపరి);
	}

	/* list of certificates specified by user */
	కొరకు (i = 0; i < options.అంకె_certificate_files; i++) {
		కీలకం = options.certificates[i];
		ఒకవేళ (!sshkey_is_cert(కీలకం) || కీలకం->cert == ఖాళీ ||
		    కీలకం->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.తటస్థం_files[i]);
			కొనసాగు;
		}
		ఒకవేళ (కీలకం && sshkey_is_sk(కీలకం) && options.sk_provider == ఖాళీ) {
			debug_f("ignoring authenticator-hosted key "
			    "certificate %s as no "
			    "SecurityKeyProvider has been specified",
			    options.తటస్థం_files[i]);
			కొనసాగు;
		}
		id = xcalloc(1, పరిమాణం(*id));
		id->agent_fd = -1;
		id->కీలకం = కీలకం;
		id->filename = xstrdup(options.certificate_files[i]);
		id->userprovided = options.certificate_file_userprovided[i];
		TAILQ_INSERT_TAIL(&certs, id, తదుపరి);
	}
	క్రమం_identities_by_prio(&certs);
	TAILQ_CONCAT(preferred, &certs, తదుపరి);

	/* list of keys supported by the agent */
	ఒకవేళ ((r = get_agent_identities(ssh, &agent_fd, &idlist)) == 0) {
		కొరకు (j = 0; j < idlist->nkeys; j++) {
			ఒకవేళ ((r = sshkey_check_rsa_నిడివి(idlist->కీలకాలు[j],
			    options.required_rsa_కొలత)) != 0) {
				debug_fr(r, "ignoring %s agent key",
				    sshkey_ssh_name(idlist->కీలకాలు[j]));
				కొనసాగు;
			}
			దొరికింది = 0;
			TAILQ_FOREACH(id, &files, తదుపరి) {
				/*
				 * agent keys from the config file are
				 * preferred
				 */
				ఒకవేళ (sshkey_equal(idlist->కీలకాలు[j], id->కీలకం)) {
					TAILQ_REMOVE(&files, id, తదుపరి);
					TAILQ_INSERT_TAIL(&agent_కీలకాలు, id, తదుపరి);
					id->agent_fd = agent_fd;
					దొరికింది = 1;
					ఆపు;
				}
			}
			ఒకవేళ (!దొరికింది && !options.identities_only) {
				id = xcalloc(1, పరిమాణం(*id));
				/* XXX "steals" key/comment from idlist */
				id->కీలకం = idlist->కీలకాలు[j];
				id->filename = idlist->comments[j];
				idlist->కీలకాలు[j] = ఖాళీ;
				idlist->comments[j] = ఖాళీ;
				id->agent_fd = agent_fd;
				TAILQ_INSERT_TAIL(&agent, id, తదుపరి);
			}
		}
		ssh_free_identitylist(idlist);
		/* append remaining agent keys */
		TAILQ_CONCAT(&agent_కీలకాలు, &agent, తదుపరి);
		క్రమం_identities_by_prio(&agent_కీలకాలు);
		TAILQ_CONCAT(preferred, &agent_కీలకాలు, తదుపరి);
		authctxt->agent_fd = agent_fd;
	}
	/* Prefer PKCS11 keys that are explicitly listed */
	TAILQ_FOREACH_సురక్షిత(id, &files, తదుపరి, tmp) {
		ఒకవేళ (id->కీలకం == ఖాళీ || (id->కీలకం->flags & SSHKEY_FLAG_EXT) == 0)
			కొనసాగు;
		దొరికింది = 0;
		TAILQ_FOREACH(id2, &files, తదుపరి) {
			ఒకవేళ (id2->కీలకం == ఖాళీ ||
			    (id2->కీలకం->flags & SSHKEY_FLAG_EXT) != 0)
				కొనసాగు;
			ఒకవేళ (sshkey_equal(id->కీలకం, id2->కీలకం)) {
				TAILQ_REMOVE(&files, id, తదుపరి);
				TAILQ_INSERT_TAIL(preferred, id, తదుపరి);
				దొరికింది = 1;
				ఆపు;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		ఒకవేళ (!దొరికింది && options.identities_only) {
			TAILQ_REMOVE(&files, id, తదుపరి);
			freezero(id, పరిమాణం(*id));
		}
	}
	క్రమం_identities_by_prio(&files);
	/* append remaining keys from the config file */
	TAILQ_CONCAT(preferred, &files, తదుపరి);
	/* finally, filter by PubkeyAcceptedAlgorithms */
	TAILQ_FOREACH_సురక్షిత(id, preferred, తదుపరి, id2) {
		disallowed = 0;
		cp = ఖాళీ;
		ఒకవేళ (id->కీలకం == ఖాళీ)
			కొనసాగు;
		ఒకవేళ (!కీలకం_type_allowed_by_config(id->కీలకం)) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not in PubkeyAcceptedAlgorithms",
			    sshkey_ssh_name(id->కీలకం), id->filename);
			disallowed = 1;
		} లేకపోతే ఒకవేళ (ssh != ఖాళీ && ssh->kex != ఖాళీ &&
		    ssh->kex->server_sig_algs != ఖాళీ &&
		    (cp = కీలకం_sig_algorithm(ssh, id->కీలకం)) == ఖాళీ) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not supported by server",
			    sshkey_ssh_name(id->కీలకం), id->filename);
			disallowed = 1;
		}
		విడుదల(cp);
		ఒకవేళ (!disallowed)
			కొనసాగు;
		/* remove key */
		TAILQ_REMOVE(preferred, id, తదుపరి);
		sshkey_free(id->కీలకం);
		విడుదల(id->filename);
		freezero(id, పరిమాణం(*id));
	}
	/* List the keys we plan on using */
	TAILQ_FOREACH_సురక్షిత(id, preferred, తదుపరి, id2) {
		ident = format_తటస్థం(id);
		debug("Will attempt key: %s", ident);
		విడుదల(ident);
	}
	debug2_f("done");
}

స్థిర శూన్య
pubkey_cleanup(నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	తటస్థం *id;

	ఒకవేళ (authctxt->agent_fd != -1) {
		ssh_close_authentication_socket(authctxt->agent_fd);
		authctxt->agent_fd = -1;
	}
	కొరకు (id = TAILQ_FIRST(&authctxt->కీలకాలు); id;
	    id = TAILQ_FIRST(&authctxt->కీలకాలు)) {
		TAILQ_REMOVE(&authctxt->కీలకాలు, id, తదుపరి);
		sshkey_free(id->కీలకం);
		విడుదల(id->filename);
		విడుదల(id);
	}
}

శూన్య
pubkey_dump(నిర్మాణం ssh *ssh)
{
	Authctxt authctxt;
	తటస్థం *id;
	అక్షరం *ident;

	memset(&authctxt, 0, పరిమాణం(authctxt));
	authctxt.agent_fd = -1;
	ssh->authctxt = &authctxt;

	pubkey_prepare(ssh, &authctxt);
	TAILQ_FOREACH(id, &authctxt.కీలకాలు, తదుపరి) {
		ident = format_తటస్థం(id);
		fprintf(stdout, "%s\n", ident);
		విడుదల(ident);
	}
	pubkey_cleanup(ssh);
	ssh->authctxt = ఖాళీ;
}

స్థిర శూన్య
pubkey_reset(Authctxt *authctxt)
{
	తటస్థం *id;

	TAILQ_FOREACH(id, &authctxt->కీలకాలు, తదుపరి)
		id->tried = 0;
}

స్థిర పూర్ణాంకం
userauth_pubkey(నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	తటస్థం *id;
	పూర్ణాంకం పంపిన = 0;
	అక్షరం *ident;
	స్థిర పూర్ణాంకం prepared;

	ఒకవేళ (!prepared) {
		pubkey_prepare(ssh, authctxt);
		prepared = 1;
	}

	అయితే ((id = TAILQ_FIRST(&authctxt->కీలకాలు))) {
		ఒకవేళ (id->tried++)
			తిరిగి (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->కీలకాలు, id, తదుపరి);
		TAILQ_INSERT_TAIL(&authctxt->కీలకాలు, id, తదుపరి);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		ఒకవేళ (id->కీలకం != ఖాళీ) {
			ident = format_తటస్థం(id);
			debug("Offering public key: %s", ident);
			విడుదల(ident);
			పంపిన = send_pubkey_test(ssh, id);
		} లేకపోతే {
			debug("Trying private key: %s", id->filename);
			id->కీలకం = ఎక్కించు_తటస్థం_file(id);
			ఒకవేళ (id->కీలకం != ఖాళీ) {
				id->isprivate = 1;
				పంపిన = sign_and_send_pubkey(ssh, id);
				sshkey_free(id->కీలకం);
				id->కీలకం = ఖాళీ;
				id->isprivate = 0;
			}
		}
		ఒకవేళ (పంపిన)
			తిరిగి (పంపిన);
	}
	తిరిగి (0);
}

/*
 * Send userauth request message specifying keyboard-interactive method.
 */
స్థిర పూర్ణాంకం
userauth_kbdint(నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	పూర్ణాంకం r;

	ఒకవేళ (authctxt->attempt_kbdint++ >= options.సంఖ్య_యొక్క_password_prompts)
		తిరిగి 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	ఒకవేళ (authctxt->attempt_kbdint > 1 && !authctxt->info_req_చూసిన) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_INFO_REQUEST, ఖాళీ);
		తిరిగి 0;
	}

	debug2("userauth_kbdint");
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->పద్ధతి->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||		/* lang */
	    (r = sshpkt_put_cstring(ssh, options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_సమితి(ssh, SSH2_సందేశం_USERAUTH_INFO_REQUEST, &ఆదానం_userauth_info_req);
	తిరిగి 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
స్థిర పూర్ణాంకం
ఆదానం_userauth_info_req(పూర్ణాంకం type, uint32_t seq, నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	అక్షరం *name = ఖాళీ, *inst = ఖాళీ, *lang = ఖాళీ, *prompt = ఖాళీ;
	అక్షరం *display_prompt = ఖాళీ, *response = ఖాళీ;
	u_char echo = 0;
	u_int అంకె_prompts, i;
	పూర్ణాంకం r, addnl;
	కొలత_t len;

	debug2_f("entering");

	ఒకవేళ (authctxt == ఖాళీ)
		fatal_f("no authentication context");

	authctxt->info_req_చూసిన = 1;

	ఒకవేళ ((r = sshpkt_get_cstring(ssh, &name, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &inst, ఖాళీ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ఖాళీ)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((len = అక్షరశ్రేణి_పొడవు(name)) > 0) {
		addnl = name[len] != '\n';
		fmprintf(stderr, "%s%s", name, addnl ? "\n" : "");
	}
	ఒకవేళ ((len = అక్షరశ్రేణి_పొడవు(inst)) > 0) {
		addnl = inst[len] != '\n';
		fmprintf(stderr, "%s%s", inst, addnl ? "\n" : "");
	}

	ఒకవేళ ((r = sshpkt_get_u32(ssh, &అంకె_prompts)) != 0)
		వెళ్ళు బహిర్గతం;
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_USERAUTH_INFO_RESPONSE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, అంకె_prompts)) != 0)
		వెళ్ళు బహిర్గతం;

	debug2_f("num_prompts %d", అంకె_prompts);
	కొరకు (i = 0; i < అంకె_prompts; i++) {
		ఒకవేళ ((r = sshpkt_get_cstring(ssh, &prompt, ఖాళీ)) != 0 ||
		    (r = sshpkt_get_u8(ssh, &echo)) != 0)
			వెళ్ళు బహిర్గతం;
		ఒకవేళ (asmprintf(&display_prompt, గరిష్ఠ_పూర్ణాంకం, ఖాళీ, "(%s@%s) %s",
		    authctxt->server_user, options.host_కీలకం_alias ?
		    options.host_కీలకం_alias : authctxt->host, prompt) == -1)
			fatal_f("asmprintf failed");
		response = read_passphrase(display_prompt, echo ? RP_ECHO : 0);
		ఒకవేళ ((r = sshpkt_put_cstring(ssh, response)) != 0)
			వెళ్ళు బహిర్గతం;
		freezero(response, అక్షరశ్రేణి_పొడవు(response));
		విడుదల(prompt);
		విడుదల(display_prompt);
		display_prompt = response = prompt = ఖాళీ;
	}
	/* done with parsing incoming message. */
	ఒకవేళ ((r = sshpkt_get_చివర(ssh)) != 0 ||
	    (r = sshpkt_కూడు_padding(ssh, 64)) != 0)
		వెళ్ళు బహిర్గతం;
	r = sshpkt_send(ssh);
 బహిర్గతం:
	ఒకవేళ (response)
		freezero(response, అక్షరశ్రేణి_పొడవు(response));
	విడుదల(prompt);
	విడుదల(display_prompt);
	విడుదల(name);
	విడుదల(inst);
	విడుదల(lang);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
ssh_keysign(నిర్మాణం ssh *ssh, నిర్మాణం sshkey *కీలకం, u_char **sigp, కొలత_t *lenp,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen)
{
	నిర్మాణం sshbuf *b;
	నిర్మాణం stat st;
	pid_t pid;
	పూర్ణాంకం r, గమ్యం[2], from[2], స్థితి_2;
	పూర్ణాంకం sock = ssh_packet_get_connection_లోపల(ssh);
	u_char rversion = 0, సంస్కరణ = 2;
	శూన్య (*osigchld)(పూర్ణాంకం);

	*sigp = ఖాళీ;
	*lenp = 0;

	ఒకవేళ (stat(మార్గం_SSH_కీలకం_SIGN, &st) == -1) {
		error_f("not installed: %s", strerror(errno));
		తిరిగి -1;
	}
	ఒకవేళ (fflush(stdout) != 0) {
		error_f("fflush: %s", strerror(errno));
		తిరిగి -1;
	}
	ఒకవేళ (pipe(గమ్యం) == -1) {
		error_f("pipe: %s", strerror(errno));
		తిరిగి -1;
	}
	ఒకవేళ (pipe(from) == -1) {
		error_f("pipe: %s", strerror(errno));
		తిరిగి -1;
	}
	ఒకవేళ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		తిరిగి -1;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ఒకవేళ (pid == 0) {
		close(from[0]);
		ఒకవేళ (dup2(from[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(గమ్యం[1]);
		ఒకవేళ (dup2(గమ్యం[0], STDIN_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(from[1]);
		close(గమ్యం[0]);

		ఒకవేళ (dup2(sock, STDERR_FILENO + 1) == -1)
			fatal_f("dup2: %s", strerror(errno));
		sock = STDERR_FILENO + 1;
		ఒకవేళ (fcntl(sock, F_SETFD, 0) == -1) /* keep the socket on exec */
			debug3_f("fcntl F_SETFD: %s", strerror(errno));
		closefrom(sock + 1);

		debug3_f("[child] pid=%ld, exec %s",
		    (దీర్ఘ)getpid(), మార్గం_SSH_కీలకం_SIGN);
		execl(మార్గం_SSH_కీలకం_SIGN, మార్గం_SSH_కీలకం_SIGN, (అక్షరం *)ఖాళీ);
		fatal_f("exec(%s): %s", మార్గం_SSH_కీలకం_SIGN,
		    strerror(errno));
	}
	close(from[1]);
	close(గమ్యం[0]);
	sock = STDERR_FILENO + 1;

	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	/* send # of sock, data to be signed */
	ఒకవేళ ((r = sshbuf_put_u32(b, sock)) != 0 ||
	    (r = sshbuf_put_string(b, దత్తాంశం, datalen)) != 0)
		fatal_fr(r, "buffer error");
	ఒకవేళ (ssh_సందేశం_send(గమ్యం[1], సంస్కరణ, b) == -1)
		fatal_f("couldn't send request");
	sshbuf_reset(b);
	r = ssh_సందేశం_recv(from[0], b);
	close(from[0]);
	close(గమ్యం[1]);
	ఒకవేళ (r < 0) {
		error_f("no reply");
		వెళ్ళు fail;
	}

	errno = 0;
	అయితే (waitpid(pid, &స్థితి_2, 0) == -1) {
		ఒకవేళ (errno != EINTR) {
			error_f("waitpid %ld: %s", (దీర్ఘ)pid, strerror(errno));
			వెళ్ళు fail;
		}
	}
	ఒకవేళ (!WIFEXITED(స్థితి_2)) {
		error_f("exited abnormally");
		వెళ్ళు fail;
	}
	ఒకవేళ (WEXITSTATUS(స్థితి_2) != 0) {
		error_f("exited with status %d", WEXITSTATUS(స్థితి_2));
		వెళ్ళు fail;
	}
	ఒకవేళ ((r = sshbuf_get_u8(b, &rversion)) != 0) {
		error_fr(r, "buffer error");
		వెళ్ళు fail;
	}
	ఒకవేళ (rversion != సంస్కరణ) {
		error_f("bad version");
		వెళ్ళు fail;
	}
	ఒకవేళ ((r = sshbuf_get_string(b, sigp, lenp)) != 0) {
		error_fr(r, "buffer error");
 fail:
		ssh_signal(SIGCHLD, osigchld);
		sshbuf_free(b);
		తిరిగి -1;
	}
	ssh_signal(SIGCHLD, osigchld);
	sshbuf_free(b);

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
userauth_hostbased(నిర్మాణం ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	నిర్మాణం sshkey *అంతరంగ = ఖాళీ;
	నిర్మాణం sshbuf *b = ఖాళీ;
	u_char *sig = ఖాళీ, *keyblob = ఖాళీ;
	అక్షరం *fp = ఖాళీ, *chost = ఖాళీ, *lname = ఖాళీ;
	కొలత_t siglen = 0, keylen = 0;
	పూర్ణాంకం i, r, success = 0;

	ఒకవేళ (authctxt->ktypes == ఖాళీ) {
		authctxt->oktypes = xstrdup(options.hostbased_accepted_algos);
		authctxt->ktypes = authctxt->oktypes;
	}

	/*
	 * Work through each listed type pattern in HostbasedAcceptedAlgorithms,
	 * trying each hostkey that matches the type in turn.
	 */
	కొరకు (;;) {
		ఒకవేళ (authctxt->చురుకైన_ktype == ఖాళీ)
			authctxt->చురుకైన_ktype = strsep(&authctxt->ktypes, ",");
		ఒకవేళ (authctxt->చురుకైన_ktype == ఖాళీ ||
		    *authctxt->చురుకైన_ktype == '\0')
			ఆపు;
		debug3_f("trying key type %s", authctxt->చురుకైన_ktype);

		/* check for a useful key */
		అంతరంగ = ఖాళీ;
		కొరకు (i = 0; i < authctxt->sensitive->nkeys; i++) {
			ఒకవేళ (authctxt->sensitive->కీలకాలు[i] == ఖాళీ ||
			    authctxt->sensitive->కీలకాలు[i]->type == కీలకం_UNSPEC)
				కొనసాగు;
			ఒకవేళ (!sshkey_సరిపోలిక_keyname_గమ్యం_sigalgs(
			    sshkey_ssh_name(authctxt->sensitive->కీలకాలు[i]),
			    authctxt->చురుకైన_ktype))
				కొనసాగు;
			/* we take and free the key */
			అంతరంగ = authctxt->sensitive->కీలకాలు[i];
			authctxt->sensitive->కీలకాలు[i] = ఖాళీ;
			ఆపు;
		}
		/* Found one */
		ఒకవేళ (అంతరంగ != ఖాళీ)
			ఆపు;
		/* No more keys of this type; advance */
		authctxt->చురుకైన_ktype = ఖాళీ;
	}
	ఒకవేళ (అంతరంగ == ఖాళీ) {
		విడుదల(authctxt->oktypes);
		authctxt->oktypes = authctxt->ktypes = ఖాళీ;
		authctxt->చురుకైన_ktype = ఖాళీ;
		debug("No more client hostkeys for hostbased authentication.");
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((fp = sshkey_fingerprint(అంతరంగ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ఖాళీ) {
		error_f("sshkey_fingerprint failed");
		వెళ్ళు బహిర్గతం;
	}
	debug_f("trying hostkey %s %s using sigalg %s",
	    sshkey_ssh_name(అంతరంగ), fp, authctxt->చురుకైన_ktype);

	/* figure out a name for the client host */
	lname = get_local_name(ssh_packet_get_connection_లోపల(ssh));
	ఒకవేళ (lname == ఖాళీ) {
		error_f("cannot get local ipaddr/name");
		వెళ్ళు బహిర్గతం;
	}

	/* XXX sshbuf_put_stringf? */
	xasprintf(&chost, "%s.", lname);
	debug2_f("chost %s", chost);

	/* construct data */
	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ) {
		error_f("sshbuf_new failed");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshkey_గమ్యం_blob(అంతరంగ, &keyblob, &keylen)) != 0) {
		error_fr(r, "sshkey_to_blob");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_సందేశం_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->పద్ధతి->name)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->చురుకైన_ktype)) != 0 ||
	    (r = sshbuf_put_string(b, keyblob, keylen)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->local_user)) != 0) {
		error_fr(r, "buffer error");
		వెళ్ళు బహిర్గతం;
	}

#నిర్వచితమైతే DEBUG_PK
	sshbuf_dump(b, stderr);
#అయితే_ముగింపు
	ఒకవేళ ((r = ssh_keysign(ssh, అంతరంగ, &sig, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b))) != 0) {
		error("sign using hostkey %s %s failed",
		    sshkey_ssh_name(అంతరంగ), fp);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshpkt_ప్రారంభం(ssh, SSH2_సందేశం_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->పద్ధతి->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->చురుకైన_ktype)) != 0 ||
	    (r = sshpkt_put_string(ssh, keyblob, keylen)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, chost)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->local_user)) != 0 ||
	    (r = sshpkt_put_string(ssh, sig, siglen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0) {
		error_fr(r, "packet error");
		వెళ్ళు బహిర్గతం;
	}
	success = 1;

 బహిర్గతం:
	ఒకవేళ (sig != ఖాళీ)
		freezero(sig, siglen);
	విడుదల(keyblob);
	విడుదల(lname);
	విడుదల(fp);
	విడుదల(chost);
	sshkey_free(అంతరంగ);
	sshbuf_free(b);

	తిరిగి success;
}

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
స్థిర పూర్ణాంకం
authmethod_is_enabled(Authmethod *పద్ధతి)
{
	ఒకవేళ (పద్ధతి == ఖాళీ)
		తిరిగి 0;
	/* return false if options indicate this method is disabled */
	ఒకవేళ  (పద్ధతి->enabled == ఖాళీ || *పద్ధతి->enabled == 0)
		తిరిగి 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	ఒకవేళ  (పద్ధతి->batch_flag != ఖాళీ && *పద్ధతి->batch_flag != 0)
		తిరిగి 0;
	తిరిగి 1;
}

స్థిర Authmethod *
authmethod_lookup(స్థిరరాశి అక్షరం *name)
{
	Authmethod *పద్ధతి = ఖాళీ;
	ఒకవేళ (name != ఖాళీ)
		కొరకు (పద్ధతి = authmethods; పద్ధతి->name != ఖాళీ; పద్ధతి++)
			ఒకవేళ (strcmp(name, పద్ధతి->name) == 0)
				తిరిగి పద్ధతి;
	debug2("Unrecognized authentication method name: %s", name ? name : "NULL");
	తిరిగి ఖాళీ;
}

/* XXX internal state */
స్థిర Authmethod *current = ఖాళీ;
స్థిర అక్షరం *supported = ఖాళీ;
స్థిర అక్షరం *preferred = ఖాళీ;

/*
 * Given the authentication method list sent by the server, return the
 * next method we should try.  If the server initially sends a nil list,
 * use a built-in default list.
 */
స్థిర Authmethod *
authmethod_get(అక్షరం *authlist)
{
	అక్షరం *name = ఖాళీ;
	u_int తదుపరి;

	/* Use a suitable default if we're passed a nil list.  */
	ఒకవేళ (authlist == ఖాళీ || అక్షరశ్రేణి_పొడవు(authlist) == 0)
		authlist = options.preferred_authentications;

	ఒకవేళ (supported == ఖాళీ || strcmp(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		విడుదల(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = ఖాళీ;
	} లేకపోతే ఒకవేళ (current != ఖాళీ && authmethod_is_enabled(current))
		తిరిగి current;

	కొరకు (;;) {
		ఒకవేళ ((name = సరిపోలిక_list(preferred, supported, &తదుపరి)) == ఖాళీ) {
			debug("No more authentication methods to try.");
			current = ఖాళీ;
			తిరిగి ఖాళీ;
		}
		preferred += తదుపరి;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		ఒకవేళ ((current = authmethod_lookup(name)) != ఖాళీ &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("Next authentication method: %s", name);
			విడుదల(name);
			తిరిగి current;
		}
		విడుదల(name);
	}
}

స్థిర అక్షరం *
authmethods_get(శూన్య)
{
	Authmethod *పద్ధతి = ఖాళీ;
	నిర్మాణం sshbuf *b;
	అక్షరం *list;
	పూర్ణాంకం r;

	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		fatal_f("sshbuf_new failed");
	కొరకు (పద్ధతి = authmethods; పద్ధతి->name != ఖాళీ; పద్ధతి++) {
		ఒకవేళ (authmethod_is_enabled(పద్ధతి)) {
			ఒకవేళ ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", పద్ధతి->name)) != 0)
				fatal_fr(r, "buffer error");
		}
	}
	ఒకవేళ ((list = sshbuf_dup_string(b)) == ఖాళీ)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	తిరిగి list;
}
