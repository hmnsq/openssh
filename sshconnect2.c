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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/wait.h>
#അന്തര്ഭാവ <sys/queue.h>
#അന്തര്ഭാവ <sys/stat.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <unistd.h>
#എങ്കിൽ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
#അന്തര്ഭാവ <vis.h>
#endif

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "ssh2.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "compat.h"
#അന്തര്ഭാവ "cipher.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "sshconnect.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "authfd.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "readconf.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "dispatch.h"
#അന്തര്ഭാവ "canohost.h"
#അന്തര്ഭാവ "msg.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "utf8.h"
#അന്തര്ഭാവ "ssh-sk.h"
#അന്തര്ഭാവ "sk-api.h"

#ifdef GSSAPI
#അന്തര്ഭാവ "ssh-gss.h"
#endif

/* import */
ബാഹ്യ Options options;

/*
 * SSH2 key exchange
 */

സ്ഥിതം അക്ഷരം *xxx_host;
സ്ഥിതം ഘടന sockaddr_storage xxx_hostaddr;
സ്ഥിതം സ്ഥിരം ഘടന ssh_conn_info *xxx_conn_info;
സ്ഥിതം പൂർണ്ണസംഖ്യ താക്കോൽ_type_allowed(ഘടന sshkey *, സ്ഥിരം അക്ഷരം *);

സ്ഥിതം പൂർണ്ണസംഖ്യ
verify_host_താക്കോൽ_callback(ഘടന sshkey *hostkey, ഘടന ssh *ssh)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshkey_check_rsa_length(hostkey,
	    options.required_rsa_size)) != 0)
		fatal_r(r, "Bad server host key");
	എങ്കിൽ (!താക്കോൽ_type_allowed(hostkey, options.hostkeyalgorithms)) {
		fatal("Server host key %s not in HostKeyAlgorithms",
		    sshkey_ssh_name(hostkey));
	}
	എങ്കിൽ (verify_host_താക്കോൽ(xxx_host, (ഘടന sockaddr *)&xxx_hostaddr, hostkey,
	    xxx_conn_info) != 0)
		fatal("Host key verification failed.");
	തിരികെ 0;
}

/* Returns the first item from a comma-separated algorithm list */
സ്ഥിതം അക്ഷരം *
first_alg(സ്ഥിരം അക്ഷരം *algs)
{
	അക്ഷരം *ret, *cp;

	ret = xstrdup(algs);
	എങ്കിൽ ((cp = strchr(ret, ',')) != ശൂന്യ)
		*cp = '\0';
	തിരികെ ret;
}

സ്ഥിതം അക്ഷരം *
order_hostkeyalgs(അക്ഷരം *host, ഘടന sockaddr *hostaddr, u_short port,
    സ്ഥിരം ഘടന ssh_conn_info *cinfo)
{
	അക്ഷരം *oavail = ശൂന്യ, *avail = ശൂന്യ, *first = ശൂന്യ, *last = ശൂന്യ;
	അക്ഷരം *alg = ശൂന്യ, *hostname = ശൂന്യ, *ret = ശൂന്യ, *best = ശൂന്യ;
	size_t maxlen;
	ഘടന hostkeys *hostkeys = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ktype;
	u_int i;

	/* Find all hostkeys for this hostname */
	get_hostfile_hostname_ipaddr(host, hostaddr, port, &hostname, ശൂന്യ);
	hostkeys = init_hostkeys();
	വേണ്ടി (i = 0; i < options.അക്കം_user_hostfiles; i++)
		load_hostkeys(hostkeys, hostname, options.user_hostfiles[i], 0);
	വേണ്ടി (i = 0; i < options.അക്കം_system_hostfiles; i++) {
		load_hostkeys(hostkeys, hostname,
		    options.system_hostfiles[i], 0);
	}
	എങ്കിൽ (options.known_hosts_command != ശൂന്യ) {
		load_hostkeys_command(hostkeys, options.known_hosts_command,
		    "ORDER", cinfo, ശൂന്യ, hostname);
	}
	/*
	 * If a plain public key exists that matches the type of the best
	 * preference HostkeyAlgorithms, then use the whole list as is.
	 * Note that we ignore whether the best preference algorithm is a
	 * certificate type, as sshconnect.c will downgrade certs to
	 * plain keys if necessary.
	 */
	best = first_alg(options.hostkeyalgorithms);
	എങ്കിൽ (lookup_താക്കോൽ_in_hostkeys_by_type(hostkeys,
	    sshkey_type_plain(sshkey_type_from_name(best)),
	    sshkey_ecdsa_nid_from_name(best), ശൂന്യ)) {
		debug3_f("have matching best-preference key type %s, "
		    "using HostkeyAlgorithms verbatim", best);
		ret = xstrdup(options.hostkeyalgorithms);
		പോകുക out;
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
	ചെയ്യുക { \
		എങ്കിൽ (*to != '\0') \
			strlcat(to, ",", maxlen); \
		strlcat(to, from, maxlen); \
	} ആകുമ്പോൾ (0)

	ആകുമ്പോൾ ((alg = strsep(&avail, ",")) && *alg != '\0') {
		എങ്കിൽ ((ktype = sshkey_type_from_name(alg)) == താക്കോൽ_UNSPEC)
			fatal_f("unknown alg %s", alg);
		/*
		 * If we have a @cert-authority marker in known_hosts then
		 * prefer all certificate algorithms.
		 */
		എങ്കിൽ (sshkey_type_is_cert(ktype) &&
		    lookup_marker_in_hostkeys(hostkeys, MRK_CA)) {
			ALG_APPEND(first, alg);
			തുടരുക;
		}
		/* If the key appears in known_hosts then prefer it */
		എങ്കിൽ (lookup_താക്കോൽ_in_hostkeys_by_type(hostkeys,
		    sshkey_type_plain(ktype),
		    sshkey_ecdsa_nid_from_name(alg), ശൂന്യ)) {
			ALG_APPEND(first, alg);
			തുടരുക;
		}
		/* Otherwise, put it last */
		ALG_APPEND(last, alg);
	}
#undef ALG_APPEND
	xasprintf(&ret, "%s%s%s", first,
	    (*first == '\0' || *last == '\0') ? "" : ",", last);
	എങ്കിൽ (*first != '\0')
		debug3_f("prefer hostkeyalgs: %s", first);
	അല്ലെങ്കിൽ
		debug3_f("no algorithms matched; accept original");
 out:
	സ്വതന്ത്രം(best);
	സ്വതന്ത്രം(first);
	സ്വതന്ത്രം(last);
	സ്വതന്ത്രം(hostname);
	സ്വതന്ത്രം(oavail);
	free_hostkeys(hostkeys);

	തിരികെ ret;
}

ശൂന്യം
ssh_kex2(ഘടന ssh *ssh, അക്ഷരം *host, ഘടന sockaddr_storage *hostaddr,
    u_short port, സ്ഥിരം ഘടന ssh_conn_info *cinfo)
{
	അക്ഷരം *myproposal[PROPOSAL_MAX];
	അക്ഷരം *all_താക്കോൽ, *hkalgs = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, use_known_hosts_order = 0;

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
	എങ്കിൽ (options.hostkeyalgorithms == ശൂന്യ ||
	    options.hostkeyalgorithms[0] == '-' ||
	    options.hostkeyalgorithms[0] == '+')
		use_known_hosts_order = 1;

	/* Expand or fill in HostkeyAlgorithms */
	all_താക്കോൽ = sshkey_alg_list(0, 0, 1, ',');
	എങ്കിൽ ((r = kex_assemble_names(&options.hostkeyalgorithms,
	    kex_default_pk_alg(), all_താക്കോൽ)) != 0)
		fatal_fr(r, "kex_assemble_namelist");
	സ്വതന്ത്രം(all_താക്കോൽ);

	എങ്കിൽ (use_known_hosts_order) {
		hkalgs = order_hostkeyalgs(host, (ഘടന sockaddr *)hostaddr,
		    port, cinfo);
	}

	kex_proposal_populate_entries(ssh, myproposal,
	    options.kex_algorithms, options.ciphers, options.macs,
	    compression_alg_list(options.compression),
	    hkalgs ? hkalgs : options.hostkeyalgorithms);

	സ്വതന്ത്രം(hkalgs);

	/* start key exchange */
	എങ്കിൽ ((r = kex_setup(ssh, myproposal)) != 0)
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
	ssh->kex->verify_host_താക്കോൽ=&verify_host_താക്കോൽ_callback;

	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &ssh->kex->done);
	kex_proposal_free_entries(myproposal);

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_IGNORE)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "markus")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0 ||
	    (r = ssh_packet_write_wait(ssh)) != 0)
		fatal_fr(r, "send packet");
#endif
}

/*
 * Authenticate user
 */

തരനിർവചനം ഘടന cauthctxt Authctxt;
തരനിർവചനം ഘടന cauthmethod Authmethod;
തരനിർവചനം ഘടന identity Identity;
തരനിർവചനം ഘടന idlist Idlist;

ഘടന identity {
	TAILQ_ENTRY(identity) next;
	പൂർണ്ണസംഖ്യ	agent_fd;		/* >=0 if agent supports key */
	ഘടന sshkey	*താക്കോൽ;		/* public/private key */
	അക്ഷരം	*filename;		/* comment for agent-only keys */
	പൂർണ്ണസംഖ്യ	tried;
	പൂർണ്ണസംഖ്യ	isprivate;		/* key points to the private key */
	പൂർണ്ണസംഖ്യ	userprovided;
};
TAILQ_HEAD(idlist, identity);

ഘടന cauthctxt {
	സ്ഥിരം അക്ഷരം *server_user;
	സ്ഥിരം അക്ഷരം *local_user;
	സ്ഥിരം അക്ഷരം *host;
	സ്ഥിരം അക്ഷരം *service;
	ഘടന cauthmethod *method;
	sig_atomic_t success;
	അക്ഷരം *authlist;
#ifdef GSSAPI
	/* gssapi */
	gss_OID_set gss_supported_mechs;
	u_int mech_tried;
#endif
	/* pubkey */
	ഘടന idlist താക്കോലുകൾ;
	പൂർണ്ണസംഖ്യ agent_fd;
	/* hostbased */
	Sensitive *sensitive;
	അക്ഷരം *oktypes, *ktypes;
	സ്ഥിരം അക്ഷരം *active_ktype;
	/* kbd-interactive */
	പൂർണ്ണസംഖ്യ info_req_seen;
	പൂർണ്ണസംഖ്യ attempt_kbdint;
	/* password */
	പൂർണ്ണസംഖ്യ attempt_passwd;
	/* generic */
	ശൂന്യം *methoddata;
};

ഘടന cauthmethod {
	അക്ഷരം	*name;		/* string to compare against server's list */
	പൂർണ്ണസംഖ്യ	(*userauth)(ഘടന ssh *ssh);
	ശൂന്യം	(*cleanup)(ഘടന ssh *ssh);
	പൂർണ്ണസംഖ്യ	*enabled;	/* flag in option struct that enables method */
	പൂർണ്ണസംഖ്യ	*batch_flag;	/* flag in option struct that disables method */
};

സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_userauth_service_accept(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_userauth_success(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_userauth_failure(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_userauth_banner(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_userauth_error(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_userauth_info_req(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_userauth_pk_ok(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_userauth_passwd_changereq(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);

സ്ഥിതം പൂർണ്ണസംഖ്യ userauth_none(ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ userauth_pubkey(ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ userauth_passwd(ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ userauth_kbdint(ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ userauth_hostbased(ഘടന ssh *);

#ifdef GSSAPI
സ്ഥിതം പൂർണ്ണസംഖ്യ userauth_gssapi(ഘടന ssh *);
സ്ഥിതം ശൂന്യം userauth_gssapi_cleanup(ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_gssapi_response(പൂർണ്ണസംഖ്യ type, uint32_t, ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_gssapi_token(പൂർണ്ണസംഖ്യ type, uint32_t, ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_gssapi_error(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ നിവേശം_gssapi_errtok(പൂർണ്ണസംഖ്യ, uint32_t, ഘടന ssh *);
#endif

ശൂന്യം	userauth(ഘടന ssh *, അക്ഷരം *);

സ്ഥിതം ശൂന്യം pubkey_cleanup(ഘടന ssh *);
സ്ഥിതം പൂർണ്ണസംഖ്യ sign_and_send_pubkey(ഘടന ssh *ssh, Identity *);
സ്ഥിതം ശൂന്യം pubkey_prepare(ഘടന ssh *, Authctxt *);
സ്ഥിതം ശൂന്യം pubkey_reset(Authctxt *);
സ്ഥിതം ഘടന sshkey *load_identity_file(Identity *);

സ്ഥിതം Authmethod *authmethod_get(അക്ഷരം *authlist);
സ്ഥിതം Authmethod *authmethod_lookup(സ്ഥിരം അക്ഷരം *name);
സ്ഥിതം അക്ഷരം *authmethods_get(ശൂന്യം);

Authmethod authmethods[] = {
#ifdef GSSAPI
	{"gssapi-with-mic",
		userauth_gssapi,
		userauth_gssapi_cleanup,
		&options.gss_authentication,
		ശൂന്യ},
#endif
	{"hostbased",
		userauth_hostbased,
		ശൂന്യ,
		&options.hostbased_authentication,
		ശൂന്യ},
	{"publickey",
		userauth_pubkey,
		ശൂന്യ,
		&options.pubkey_authentication,
		ശൂന്യ},
	{"keyboard-interactive",
		userauth_kbdint,
		ശൂന്യ,
		&options.kbd_interactive_authentication,
		&options.batch_mode},
	{"password",
		userauth_passwd,
		ശൂന്യ,
		&options.password_authentication,
		&options.batch_mode},
	{"none",
		userauth_none,
		ശൂന്യ,
		ശൂന്യ,
		ശൂന്യ},
	{ശൂന്യ, ശൂന്യ, ശൂന്യ, ശൂന്യ, ശൂന്യ}
};

ശൂന്യം
ssh_userauth2(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *local_user,
    സ്ഥിരം അക്ഷരം *server_user, അക്ഷരം *host, Sensitive *sensitive)
{
	Authctxt authctxt;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (options.preferred_authentications == ശൂന്യ)
		options.preferred_authentications = authmethods_get();

	/* setup authentication context */
	memset(&authctxt, 0, വലുപ്പം(authctxt));
	authctxt.server_user = server_user;
	authctxt.local_user = local_user;
	authctxt.host = host;
	authctxt.service = "ssh-connection";		/* service name */
	authctxt.success = 0;
	authctxt.method = authmethod_lookup("none");
	authctxt.authlist = ശൂന്യ;
	authctxt.methoddata = ശൂന്യ;
	authctxt.sensitive = sensitive;
	authctxt.active_ktype = authctxt.oktypes = authctxt.ktypes = ശൂന്യ;
	authctxt.info_req_seen = 0;
	authctxt.attempt_kbdint = 0;
	authctxt.attempt_passwd = 0;
#എങ്കിൽ GSSAPI
	authctxt.gss_supported_mechs = ശൂന്യ;
	authctxt.mech_tried = 0;
#endif
	authctxt.agent_fd = -1;
	എങ്കിൽ (authctxt.method == ശൂന്യ)
		fatal_f("internal error: cannot send userauth none request");

	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_SERVICE_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "ssh-userauth")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh->authctxt = &authctxt;
	ssh_dispatch_init(ssh, &നിവേശം_userauth_error);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_EXT_INFO, kex_നിവേശം_ext_info);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_SERVICE_ACCEPT, &നിവേശം_userauth_service_accept);
	ssh_dispatch_run_fatal(ssh, DISPATCH_BLOCK, &authctxt.success);	/* loop until success */
	pubkey_cleanup(ssh);
#ifdef GSSAPI
	എങ്കിൽ (authctxt.gss_supported_mechs != ശൂന്യ) {
		u_int ms;

		gss_release_oid_set(&ms, &authctxt.gss_supported_mechs);
		authctxt.gss_supported_mechs = ശൂന്യ;
	}
#endif
	ssh->authctxt = ശൂന്യ;

	ssh_dispatch_range(ssh, SSH2_സന്ദേശം_USERAUTH_MIN, SSH2_സന്ദേശം_USERAUTH_MAX, ശൂന്യ);

	എങ്കിൽ (!authctxt.success)
		fatal("Authentication failed.");
	എങ്കിൽ (ssh_packet_connection_is_on_socket(ssh)) {
		verbose("Authenticated to %s ([%s]:%d) using \"%s\".", host,
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh),
		    authctxt.method->name);
	} അല്ലെങ്കിൽ {
		verbose("Authenticated to %s (via proxy) using \"%s\".", host,
		    authctxt.method->name);
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_userauth_service_accept(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (ssh_packet_remaining(ssh) > 0) {
		അക്ഷരം *reply;

		എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &reply, ശൂന്യ)) != 0)
			പോകുക out;
		debug2("service_accept: %s", reply);
		സ്വതന്ത്രം(reply);
	} അല്ലെങ്കിൽ {
		debug2("buggy server: service_accept w/o service");
	}
	എങ്കിൽ ((r = sshpkt_get_end(ssh)) != 0)
		പോകുക out;
	debug("SSH2_MSG_SERVICE_ACCEPT received");

	/* initial userauth request */
	userauth_none(ssh);

	/* accept EXT_INFO at any time during userauth */
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_EXT_INFO, ssh->kex->ext_info_s ?
	    &kex_നിവേശം_ext_info : &നിവേശം_userauth_error);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_SUCCESS, &നിവേശം_userauth_success);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_FAILURE, &നിവേശം_userauth_failure);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_BANNER, &നിവേശം_userauth_banner);
	r = 0;
 out:
	തിരികെ r;
}

ശൂന്യം
userauth(ഘടന ssh *ssh, അക്ഷരം *authlist)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;

	എങ്കിൽ (authctxt->method != ശൂന്യ && authctxt->method->cleanup != ശൂന്യ)
		authctxt->method->cleanup(ssh);

	സ്വതന്ത്രം(authctxt->methoddata);
	authctxt->methoddata = ശൂന്യ;
	എങ്കിൽ (authlist == ശൂന്യ) {
		authlist = authctxt->authlist;
	} അല്ലെങ്കിൽ {
		സ്വതന്ത്രം(authctxt->authlist);
		authctxt->authlist = authlist;
	}
	വേണ്ടി (;;) {
		Authmethod *method = authmethod_get(authlist);
		എങ്കിൽ (method == ശൂന്യ)
			fatal("%s@%s: Permission denied (%s).",
			    authctxt->server_user, authctxt->host, authlist);
		authctxt->method = method;

		/* reset the per method handler */
		ssh_dispatch_range(ssh, SSH2_സന്ദേശം_USERAUTH_PER_METHOD_MIN,
		    SSH2_സന്ദേശം_USERAUTH_PER_METHOD_MAX, ശൂന്യ);

		/* and try new method */
		എങ്കിൽ (method->userauth(ssh) != 0) {
			debug2("we sent a %s packet, wait for reply", method->name);
			നിർത്തുക;
		} അല്ലെങ്കിൽ {
			debug2("we did not send a packet, disable method");
			method->enabled = ശൂന്യ;
		}
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_userauth_error(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	fatal_f("bad message during authentication: type %d", type);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_userauth_banner(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	അക്ഷരം *സന്ദേശം = ശൂന്യ;
	size_t len;
	പൂർണ്ണസംഖ്യ r;

	debug3_f("entering");
	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &സന്ദേശം, &len)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, ശൂന്യ, ശൂന്യ)) != 0)
		പോകുക out;
	എങ്കിൽ (len > 0 && options.log_level >= SYSLOG_LEVEL_INFO)
		fmprintf(stderr, "%s", സന്ദേശം);
	r = 0;
 out:
	സ്വതന്ത്രം(സന്ദേശം);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_userauth_success(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	എങ്കിൽ (authctxt == ശൂന്യ)
		fatal_f("no authentication context");
	സ്വതന്ത്രം(authctxt->authlist);
	authctxt->authlist = ശൂന്യ;
	എങ്കിൽ (authctxt->method != ശൂന്യ && authctxt->method->cleanup != ശൂന്യ)
		authctxt->method->cleanup(ssh);
	സ്വതന്ത്രം(authctxt->methoddata);
	authctxt->methoddata = ശൂന്യ;
	authctxt->success = 1;			/* break out */
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_EXT_INFO, dispatch_protocol_error);
	തിരികെ 0;
}

#എങ്കിൽ 0
സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_userauth_success_unexpected(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;

	എങ്കിൽ (authctxt == ശൂന്യ)
		fatal_f("no authentication context");

	fatal("Unexpected authentication success during %s.",
	    authctxt->method->name);
	തിരികെ 0;
}
#endif

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_userauth_failure(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	അക്ഷരം *authlist = ശൂന്യ;
	u_char partial;

	എങ്കിൽ (authctxt == ശൂന്യ)
		fatal("input_userauth_failure: no authentication context");

	എങ്കിൽ (sshpkt_get_cstring(ssh, &authlist, ശൂന്യ) != 0 ||
	    sshpkt_get_u8(ssh, &partial) != 0 ||
	    sshpkt_get_end(ssh) != 0)
		പോകുക out;

	എങ്കിൽ (partial != 0) {
		verbose("Authenticated using \"%s\" with partial success.",
		    authctxt->method->name);
		/* reset state */
		pubkey_reset(authctxt);
	}
	debug("Authentications that can continue: %s", authlist);

	userauth(ssh, authlist);
	authlist = ശൂന്യ;
 out:
	സ്വതന്ത്രം(authlist);
	തിരികെ 0;
}

/*
 * Format an identity for logging including filename, key type, fingerprint
 * and location (agent, etc.). Caller must free.
 */
സ്ഥിതം അക്ഷരം *
format_identity(Identity *id)
{
	അക്ഷരം *fp = ശൂന്യ, *ret = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *note = "";

	എങ്കിൽ (id->താക്കോൽ != ശൂന്യ) {
		fp = sshkey_fingerprint(id->താക്കോൽ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
	}
	എങ്കിൽ (id->താക്കോൽ) {
		എങ്കിൽ ((id->താക്കോൽ->flags & SSHKEY_FLAG_EXT) != 0)
			note = " token";
		അല്ലെങ്കിൽ എങ്കിൽ (sshkey_is_sk(id->താക്കോൽ))
			note = " authenticator";
	}
	xasprintf(&ret, "%s %s%s%s%s%s%s",
	    id->filename,
	    id->താക്കോൽ ? sshkey_type(id->താക്കോൽ) : "", id->താക്കോൽ ? " " : "",
	    fp ? fp : "",
	    id->userprovided ? " explicit" : "", note,
	    id->agent_fd != -1 ? " agent" : "");
	സ്വതന്ത്രം(fp);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_userauth_pk_ok(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	ഘടന sshbuf *keyblob = ശൂന്യ;
	Identity *id = ശൂന്യ;
	പൂർണ്ണസംഖ്യ pktype, found = 0, sent = 0;
	അക്ഷരം *pkalg = ശൂന്യ, *fp = ശൂന്യ, *ident = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (authctxt == ശൂന്യ)
		fatal_f("no authentication context");

	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &pkalg, ശൂന്യ)) != 0 ||
	    (r = sshpkt_getb_froms(ssh, &keyblob)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		പോകുക done;

	എങ്കിൽ (match_pattern_list(pkalg, options.pubkey_accepted_algos, 0) != 1) {
		error_f("server replied to PK_OK with signature type %s not "
		    "in PubkeyAcceptedAlgorithms", pkalg);
		r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
		പോകുക done;
	}
	എങ്കിൽ ((pktype = sshkey_type_from_name(pkalg)) == താക്കോൽ_UNSPEC) {
		debug_f("server sent unknown pkalg %s", pkalg);
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക done;
	}
	/* inner key type should match signature type */
	എങ്കിൽ ((r = sshkey_fromb_allowlist(keyblob, &താക്കോൽ, pkalg, ശൂന്യ)) != 0) {
		debug_r(r, "no key from blob. pkalg %s", pkalg);
		പോകുക done;
	}
	എങ്കിൽ (താക്കോൽ->type != pktype) {
		error("input_userauth_pk_ok: type mismatch "
		    "for decoded key (received %d, expected %d)",
		    താക്കോൽ->type, pktype);
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക done;
	}

	/*
	 * search keys in the reverse order, because last candidate has been
	 * moved to the end of the queue.  this also avoids confusion by
	 * duplicate keys
	 */
	TAILQ_FOREACH_REVERSE(id, &authctxt->താക്കോലുകൾ, idlist, next) {
		എങ്കിൽ (sshkey_equal(താക്കോൽ, id->താക്കോൽ)) {
			found = 1;
			നിർത്തുക;
		}
	}
	എങ്കിൽ (!found || id == ശൂന്യ) {
		fp = sshkey_fingerprint(താക്കോൽ, options.fingerprint_hash,
		    SSH_FP_DEFAULT);
		error_f("server replied with unknown key: %s %s",
		    sshkey_type(താക്കോൽ), fp == ശൂന്യ ? "<ERROR>" : fp);
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക done;
	}
	ident = format_identity(id);
	debug("Server accepts key: %s", ident);
	sent = sign_and_send_pubkey(ssh, id);
	r = 0;
 done:
	sshkey_free(താക്കോൽ);
	sshbuf_free(keyblob);
	സ്വതന്ത്രം(ident);
	സ്വതന്ത്രം(fp);
	സ്വതന്ത്രം(pkalg);

	/* try another method if we did not send a packet */
	എങ്കിൽ (r == 0 && sent == 0)
		userauth(ssh, ശൂന്യ);
	തിരികെ r;
}

#ifdef GSSAPI
സ്ഥിതം പൂർണ്ണസംഖ്യ
userauth_gssapi(ഘടന ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = ശൂന്യ;
	OM_uint32 min;
	പൂർണ്ണസംഖ്യ r, ok = 0;
	gss_OID mech = ശൂന്യ;

	/* Try one GSSAPI method at a time, rather than sending them all at
	 * once. */

	എങ്കിൽ (authctxt->gss_supported_mechs == ശൂന്യ)
		gss_indicate_mechs(&min, &authctxt->gss_supported_mechs);

	/* Check to see whether the mechanism is usable before we offer it */
	ആകുമ്പോൾ (authctxt->mech_tried < authctxt->gss_supported_mechs->എണ്ണം &&
	    !ok) {
		mech = &authctxt->gss_supported_mechs->
		    elements[authctxt->mech_tried];
		/* My DER encoding requires length<128 */
		എങ്കിൽ (mech->length < 128 && ssh_gssapi_check_mechanism(&gssctxt,
		    mech, authctxt->host)) {
			ok = 1; /* Mechanism works */
		} അല്ലെങ്കിൽ {
			authctxt->mech_tried++;
		}
	}

	എങ്കിൽ (!ok || mech == ശൂന്യ)
		തിരികെ 0;

	authctxt->methoddata=(ശൂന്യം *)gssctxt;

	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_USERAUTH_REQUEST)) != 0 ||
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

	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_RESPONSE, &നിവേശം_gssapi_response);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_TOKEN, &നിവേശം_gssapi_token);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_ERROR, &നിവേശം_gssapi_error);
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_GSSAPI_ERRTOK, &നിവേശം_gssapi_errtok);

	authctxt->mech_tried++; /* Move along to next candidate */

	തിരികെ 1;
}

സ്ഥിതം ശൂന്യം
userauth_gssapi_cleanup(ഘടന ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Gssctxt *gssctxt = (Gssctxt *)authctxt->methoddata;

	ssh_gssapi_delete_ctx(&gssctxt);
	authctxt->methoddata = ശൂന്യ;
}

സ്ഥിതം OM_uint32
process_gssapi_token(ഘടന ssh *ssh, gss_buffer_t recv_tok)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt = authctxt->methoddata;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc mic = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc gssbuf;
	OM_uint32 status, ms, flags;
	പൂർണ്ണസംഖ്യ r;

	status = ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    recv_tok, &send_tok, &flags);

	എങ്കിൽ (send_tok.length > 0) {
		u_char type = GSS_ERROR(status) ?
		    SSH2_സന്ദേശം_USERAUTH_GSSAPI_ERRTOK :
		    SSH2_സന്ദേശം_USERAUTH_GSSAPI_TOKEN;

		എങ്കിൽ ((r = sshpkt_start(ssh, type)) != 0 ||
		    (r = sshpkt_put_string(ssh, send_tok.മൂല്യം,
		    send_tok.length)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0)
			fatal_fr(r, "send %u packet", type);

		gss_release_buffer(&ms, &send_tok);
	}

	എങ്കിൽ (status == GSS_S_COMPLETE) {
		/* send either complete or MIC, depending on mechanism */
		എങ്കിൽ (!(flags & GSS_C_INTEG_FLAG)) {
			എങ്കിൽ ((r = sshpkt_start(ssh,
			    SSH2_സന്ദേശം_USERAUTH_GSSAPI_EXCHANGE_COMPLETE)) != 0 ||
			    (r = sshpkt_send(ssh)) != 0)
				fatal_fr(r, "send completion");
		} അല്ലെങ്കിൽ {
			ഘടന sshbuf *b;

			എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
				fatal_f("sshbuf_new failed");
			ssh_gssapi_buildmic(b, authctxt->server_user,
			    authctxt->service, "gssapi-with-mic",
			    ssh->kex->session_id);

			എങ്കിൽ ((gssbuf.മൂല്യം = sshbuf_mutable_ptr(b)) == ശൂന്യ)
				fatal_f("sshbuf_mutable_ptr failed");
			gssbuf.length = sshbuf_len(b);

			status = ssh_gssapi_sign(gssctxt, &gssbuf, &mic);

			എങ്കിൽ (!GSS_ERROR(status)) {
				എങ്കിൽ ((r = sshpkt_start(ssh,
				    SSH2_സന്ദേശം_USERAUTH_GSSAPI_MIC)) != 0 ||
				    (r = sshpkt_put_string(ssh, mic.മൂല്യം,
				    mic.length)) != 0 ||
				    (r = sshpkt_send(ssh)) != 0)
					fatal_fr(r, "send MIC");
			}

			sshbuf_free(b);
			gss_release_buffer(&ms, &mic);
		}
	}

	തിരികെ status;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_gssapi_response(പൂർണ്ണസംഖ്യ type, uint32_t plen, ഘടന ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	size_t oidlen;
	u_char *oidv = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (authctxt == ശൂന്യ)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	/* Setup our OID */
	എങ്കിൽ ((r = sshpkt_get_string(ssh, &oidv, &oidlen)) != 0)
		പോകുക done;

	എങ്കിൽ (oidlen <= 2 ||
	    oidv[0] != SSH_GSS_OIDTYPE ||
	    oidv[1] != oidlen - 2) {
		debug("Badly encoded mechanism OID received");
		userauth(ssh, ശൂന്യ);
		പോകുക ok;
	}

	എങ്കിൽ (!ssh_gssapi_check_oid(gssctxt, oidv + 2, oidlen - 2))
		fatal("Server returned different OID than expected");

	എങ്കിൽ ((r = sshpkt_get_end(ssh)) != 0)
		പോകുക done;

	എങ്കിൽ (GSS_ERROR(process_gssapi_token(ssh, GSS_C_NO_BUFFER))) {
		/* Start again with next method on list */
		debug("Trying to start again");
		userauth(ssh, ശൂന്യ);
		പോകുക ok;
	}
 ok:
	r = 0;
 done:
	സ്വതന്ത്രം(oidv);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_gssapi_token(പൂർണ്ണസംഖ്യ type, uint32_t plen, ഘടന ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	gss_buffer_desc recv_tok;
	u_char *p = ശൂന്യ;
	size_t len;
	OM_uint32 status;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (authctxt == ശൂന്യ)
		fatal("input_gssapi_response: no authentication context");

	എങ്കിൽ ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		പോകുക out;

	recv_tok.മൂല്യം = p;
	recv_tok.length = len;
	status = process_gssapi_token(ssh, &recv_tok);

	/* Start again with the next method in the list */
	എങ്കിൽ (GSS_ERROR(status)) {
		userauth(ssh, ശൂന്യ);
		/* ok */
	}
	r = 0;
 out:
	സ്വതന്ത്രം(p);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_gssapi_errtok(പൂർണ്ണസംഖ്യ type, uint32_t plen, ഘടന ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	Gssctxt *gssctxt;
	gss_buffer_desc send_tok = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc recv_tok;
	OM_uint32 ms;
	u_char *p = ശൂന്യ;
	size_t len;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (authctxt == ശൂന്യ)
		fatal("input_gssapi_response: no authentication context");
	gssctxt = authctxt->methoddata;

	എങ്കിൽ ((r = sshpkt_get_string(ssh, &p, &len)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		സ്വതന്ത്രം(p);
		തിരികെ r;
	}

	/* Stick it into GSSAPI and see what it says */
	recv_tok.മൂല്യം = p;
	recv_tok.length = len;
	(ശൂന്യം)ssh_gssapi_init_ctx(gssctxt, options.gss_deleg_creds,
	    &recv_tok, &send_tok, ശൂന്യ);
	സ്വതന്ത്രം(p);
	gss_release_buffer(&ms, &send_tok);

	/* Server will be returning a failed packet after this one */
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_gssapi_error(പൂർണ്ണസംഖ്യ type, uint32_t plen, ഘടന ssh *ssh)
{
	അക്ഷരം *സന്ദേശം = ശൂന്യ;
	അക്ഷരം *lang = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshpkt_get_u32(ssh, ശൂന്യ)) != 0 ||	/* maj */
	    (r = sshpkt_get_u32(ssh, ശൂന്യ)) != 0 ||	/* min */
	    (r = sshpkt_get_cstring(ssh, &സന്ദേശം, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ശൂന്യ)) != 0)
		പോകുക out;
	r = sshpkt_get_end(ssh);
	debug("Server GSSAPI Error:\n%s", സന്ദേശം);
 out:
	സ്വതന്ത്രം(സന്ദേശം);
	സ്വതന്ത്രം(lang);
	തിരികെ r;
}
#endif /* GSSAPI */

സ്ഥിതം പൂർണ്ണസംഖ്യ
userauth_none(ഘടന ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	പൂർണ്ണസംഖ്യ r;

	/* initial userauth request */
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");
	തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
userauth_passwd(ഘടന ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	അക്ഷരം *password, *prompt = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *host = options.host_താക്കോൽ_alias ?  options.host_താക്കോൽ_alias :
	    authctxt->host;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (authctxt->attempt_passwd++ >= options.സംഖ്യ_of_password_prompts)
		തിരികെ 0;

	എങ്കിൽ (authctxt->attempt_passwd != 1)
		error("Permission denied, please try again.");

	xasprintf(&prompt, "%s@%s's password: ", authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 0)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	സ്വതന്ത്രം(prompt);
	എങ്കിൽ (password != ശൂന്യ)
		freezero(password, strlen(password));

	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_PASSWD_CHANGEREQ,
	    &നിവേശം_userauth_passwd_changereq);

	തിരികെ 1;
}

/*
 * parse PASSWD_CHANGEREQ, prompt user and send SSH2_MSG_USERAUTH_REQUEST
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_userauth_passwd_changereq(പൂർണ്ണസംഖ്യ type, uint32_t seqnr, ഘടന ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	അക്ഷരം *info = ശൂന്യ, *lang = ശൂന്യ, *password = ശൂന്യ, *retype = ശൂന്യ;
	അക്ഷരം prompt[256];
	സ്ഥിരം അക്ഷരം *host;
	പൂർണ്ണസംഖ്യ r, addnl;
	size_t len;

	debug2("input_userauth_passwd_changereq");

	എങ്കിൽ (authctxt == ശൂന്യ)
		fatal("input_userauth_passwd_changereq: "
		    "no authentication context");
	host = options.host_താക്കോൽ_alias ? options.host_താക്കോൽ_alias : authctxt->host;

	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &info, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ശൂന്യ)) != 0)
		പോകുക out;
	എങ്കിൽ ((len = strlen(info)) > 0) {
		addnl = info[len] != '\n';
		fmprintf(stderr, "%s%s", info, addnl ? "\n" : "");
	}
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_u8(ssh, 1)) != 0)	/* additional info */
		പോകുക out;

	snprintf(prompt, വലുപ്പം(prompt),
	    "Enter %.30s@%.128s's old password: ",
	    authctxt->server_user, host);
	password = read_passphrase(prompt, 0);
	എങ്കിൽ ((r = sshpkt_put_cstring(ssh, password)) != 0)
		പോകുക out;

	freezero(password, strlen(password));
	password = ശൂന്യ;
	ആകുമ്പോൾ (password == ശൂന്യ) {
		snprintf(prompt, വലുപ്പം(prompt),
		    "Enter %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		password = read_passphrase(prompt, RP_ALLOW_EOF);
		എങ്കിൽ (password == ശൂന്യ) {
			/* bail out */
			r = 0;
			പോകുക out;
		}
		snprintf(prompt, വലുപ്പം(prompt),
		    "Retype %.30s@%.128s's new password: ",
		    authctxt->server_user, host);
		retype = read_passphrase(prompt, 0);
		എങ്കിൽ (strcmp(password, retype) != 0) {
			freezero(password, strlen(password));
			logit("Mismatch; try again, EOF to quit.");
			password = ശൂന്യ;
		}
		freezero(retype, strlen(retype));
	}
	എങ്കിൽ ((r = sshpkt_put_cstring(ssh, password)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		പോകുക out;

	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_PASSWD_CHANGEREQ,
	    &നിവേശം_userauth_passwd_changereq);
	r = 0;
 out:
	എങ്കിൽ (password)
		freezero(password, strlen(password));
	സ്വതന്ത്രം(info);
	സ്വതന്ത്രം(lang);
	തിരികെ r;
}

/*
 * Select an algorithm for publickey signatures.
 * Returns algorithm (caller must free) or NULL if no mutual algorithm found.
 *
 * Call with ssh==NULL to ignore server-sig-algs extension list and
 * only attempt with the key's base signature type.
 */
സ്ഥിതം അക്ഷരം *
താക്കോൽ_sig_algorithm(ഘടന ssh *ssh, സ്ഥിരം ഘടന sshkey *താക്കോൽ)
{
	അക്ഷരം *allowed, *oallowed, *cp, *tmp, *alg = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *server_sig_algs;

	/*
	 * The signature algorithm will only differ from the key algorithm
	 * for RSA keys/certs and when the server advertises support for
	 * newer (SHA2) algorithms.
	 */
	എങ്കിൽ (ssh == ശൂന്യ || ssh->kex->server_sig_algs == ശൂന്യ ||
	    (താക്കോൽ->type != താക്കോൽ_RSA && താക്കോൽ->type != താക്കോൽ_RSA_CERT) ||
	    (താക്കോൽ->type == താക്കോൽ_RSA_CERT && (ssh->compat & SSH_BUG_SIGTYPE))) {
		/* Filter base key signature alg against our configuration */
		തിരികെ match_list(sshkey_ssh_name(താക്കോൽ),
		    options.pubkey_accepted_algos, ശൂന്യ);
	}

	/*
	 * Workaround OpenSSH 7.4 bug: this version supports RSA/SHA-2 but
	 * fails to advertise it via SSH2_MSG_EXT_INFO.
	 */
	server_sig_algs = ssh->kex->server_sig_algs;
	എങ്കിൽ (താക്കോൽ->type == താക്കോൽ_RSA && (ssh->compat & SSH_BUG_SIGTYPE74))
		server_sig_algs = "rsa-sha2-256,rsa-sha2-512";

	/*
	 * For RSA keys/certs, since these might have a different sig type:
	 * find the first entry in PubkeyAcceptedAlgorithms of the right type
	 * that also appears in the supported signature algorithms list from
	 * the server.
	 */
	oallowed = allowed = xstrdup(options.pubkey_accepted_algos);
	ആകുമ്പോൾ ((cp = strsep(&allowed, ",")) != ശൂന്യ) {
		എങ്കിൽ (sshkey_type_from_name(cp) != താക്കോൽ->type)
			തുടരുക;
		tmp = match_list(sshkey_sigalg_by_name(cp),
		    server_sig_algs, ശൂന്യ);
		എങ്കിൽ (tmp != ശൂന്യ)
			alg = xstrdup(cp);
		സ്വതന്ത്രം(tmp);
		എങ്കിൽ (alg != ശൂന്യ)
			നിർത്തുക;
	}
	സ്വതന്ത്രം(oallowed);
	തിരികെ alg;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
identity_sign(ഘടന identity *id, u_char **sigp, size_t *lenp,
    സ്ഥിരം u_char *data, size_t datalen, u_int compat, സ്ഥിരം അക്ഷരം *alg)
{
	ഘടന sshkey *sign_താക്കോൽ = ശൂന്യ, *prv = ശൂന്യ;
	പൂർണ്ണസംഖ്യ is_agent = 0, retried = 0, r = SSH_ERR_INTERNAL_ERROR;
	ഘടന notifier_ctx *notifier = ശൂന്യ;
	അക്ഷരം *fp = ശൂന്യ, *pin = ശൂന്യ, *prompt = ശൂന്യ;

	*sigp = ശൂന്യ;
	*lenp = 0;

	/* The agent supports this key. */
	എങ്കിൽ (id->താക്കോൽ != ശൂന്യ && id->agent_fd != -1) {
		തിരികെ ssh_agent_sign(id->agent_fd, id->താക്കോൽ, sigp, lenp,
		    data, datalen, alg, compat);
	}

	/*
	 * We have already loaded the private key or the private key is
	 * stored in external hardware.
	 */
	എങ്കിൽ (id->താക്കോൽ != ശൂന്യ &&
	    (id->isprivate || (id->താക്കോൽ->flags & SSHKEY_FLAG_EXT))) {
		sign_താക്കോൽ = id->താക്കോൽ;
		is_agent = 1;
	} അല്ലെങ്കിൽ {
		/* Load the private key from the file. */
		എങ്കിൽ ((prv = load_identity_file(id)) == ശൂന്യ)
			തിരികെ SSH_ERR_താക്കോൽ_NOT_FOUND;
		എങ്കിൽ (id->താക്കോൽ != ശൂന്യ && !sshkey_equal_public(prv, id->താക്കോൽ)) {
			error_f("private key %s contents do not match public",
			    id->filename);
			r = SSH_ERR_താക്കോൽ_NOT_FOUND;
			പോകുക out;
		}
		sign_താക്കോൽ = prv;
	}
 retry_pin:
	/* Prompt for touch for non-agent FIDO keys that request UP */
	എങ്കിൽ (!is_agent && sshkey_is_sk(sign_താക്കോൽ) &&
	    (sign_താക്കോൽ->sk_flags & SSH_SK_USER_PRESENCE_REQD)) {
		/* XXX should batch mode just skip these? */
		എങ്കിൽ ((fp = sshkey_fingerprint(sign_താക്കോൽ,
		    options.fingerprint_hash, SSH_FP_DEFAULT)) == ശൂന്യ)
			fatal_f("fingerprint failed");
		notifier = notify_start(options.batch_mode,
		    "Confirm user presence for key %s %s",
		    sshkey_type(sign_താക്കോൽ), fp);
		സ്വതന്ത്രം(fp);
	}
	എങ്കിൽ ((r = sshkey_sign(sign_താക്കോൽ, sigp, lenp, data, datalen,
	    alg, options.sk_provider, pin, compat)) != 0) {
		debug_fr(r, "sshkey_sign");
		എങ്കിൽ (!retried && pin == ശൂന്യ && !is_agent &&
		    sshkey_is_sk(sign_താക്കോൽ) &&
		    r == SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE) {
			notify_complete(notifier, ശൂന്യ);
			notifier = ശൂന്യ;
			xasprintf(&prompt, "Enter PIN for %s key %s: ",
			    sshkey_type(sign_താക്കോൽ), id->filename);
			pin = read_passphrase(prompt, 0);
			retried = 1;
			പോകുക retry_pin;
		}
		പോകുക out;
	}

	/*
	 * PKCS#11 tokens may not support all signature algorithms,
	 * so check what we get back.
	 */
	എങ്കിൽ (id->താക്കോൽ != ശൂന്യ && (id->താക്കോൽ->flags & SSHKEY_FLAG_EXT) != 0 &&
	    (r = sshkey_check_sigtype(*sigp, *lenp, alg)) != 0) {
		debug_fr(r, "sshkey_check_sigtype");
		പോകുക out;
	}
	/* success */
	r = 0;
 out:
	സ്വതന്ത്രം(prompt);
	എങ്കിൽ (pin != ശൂന്യ)
		freezero(pin, strlen(pin));
	notify_complete(notifier, r == 0 ? "User presence confirmed" : ശൂന്യ);
	sshkey_free(prv);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
id_filename_matches(Identity *id, Identity *private_id)
{
	സ്ഥിതം സ്ഥിരം അക്ഷരം * സ്ഥിരം suffixes[] = { ".pub", "-cert.pub", ശൂന്യ };
	size_t len = strlen(id->filename), plen = strlen(private_id->filename);
	size_t i, slen;

	എങ്കിൽ (strcmp(id->filename, private_id->filename) == 0)
		തിരികെ 1;
	വേണ്ടി (i = 0; suffixes[i]; i++) {
		slen = strlen(suffixes[i]);
		എങ്കിൽ (len > slen && plen == len - slen &&
		    strcmp(id->filename + (len - slen), suffixes[i]) == 0 &&
		    memcmp(id->filename, private_id->filename, plen) == 0)
			തിരികെ 1;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sign_and_send_pubkey(ഘടന ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ഘടന sshbuf *b = ശൂന്യ;
	Identity *private_id, *sign_id = ശൂന്യ;
	u_char *signature = ശൂന്യ;
	size_t slen = 0, skip = 0;
	പൂർണ്ണസംഖ്യ r, fallback_sigtype, sent = 0;
	അക്ഷരം *alg = ശൂന്യ, *fp = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *loc = "", *method = "publickey";
	പൂർണ്ണസംഖ്യ hostbound = 0;

	/* prefer host-bound pubkey signatures if supported by server */
	എങ്കിൽ ((ssh->kex->flags & KEX_HAS_PUBKEY_HOSTBOUND) != 0 &&
	    (options.pubkey_authentication & SSH_PUBKEY_AUTH_HBOUND) != 0) {
		hostbound = 1;
		method = "publickey-hostbound-v00@openssh.com";
	}

	എങ്കിൽ ((fp = sshkey_fingerprint(id->താക്കോൽ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ശൂന്യ)
		തിരികെ 0;

	debug3_f("using %s with %s %s", method, sshkey_type(id->താക്കോൽ), fp);

	/*
	 * If the key is an certificate, try to find a matching private key
	 * and use it to complete the signature.
	 * If no such private key exists, fall back to trying the certificate
	 * key itself in case it has a private half already loaded.
	 * This will try to set sign_id to the private key that will perform
	 * the signature.
	 */
	എങ്കിൽ (id->agent_fd == -1 && sshkey_is_cert(id->താക്കോൽ)) {
		TAILQ_FOREACH(private_id, &authctxt->താക്കോലുകൾ, next) {
			എങ്കിൽ (sshkey_equal_public(id->താക്കോൽ, private_id->താക്കോൽ) &&
			    id->താക്കോൽ->type != private_id->താക്കോൽ->type) {
				sign_id = private_id;
				നിർത്തുക;
			}
		}
		/*
		 * Exact key matches are preferred, but also allow
		 * filename matches for non-PKCS#11/agent keys that
		 * didn't load public keys. This supports the case
		 * of keeping just a private key file and public
		 * certificate on disk.
		 */
		എങ്കിൽ (sign_id == ശൂന്യ &&
		    !id->isprivate && id->agent_fd == -1 &&
		    (id->താക്കോൽ->flags & SSHKEY_FLAG_EXT) == 0) {
			TAILQ_FOREACH(private_id, &authctxt->താക്കോലുകൾ, next) {
				എങ്കിൽ (private_id->താക്കോൽ == ശൂന്യ &&
				    id_filename_matches(id, private_id)) {
					sign_id = private_id;
					നിർത്തുക;
				}
			}
		}
		എങ്കിൽ (sign_id != ശൂന്യ) {
			debug2_f("using private key \"%s\"%s for "
			    "certificate", sign_id->filename,
			    sign_id->agent_fd != -1 ? " from agent" : "");
		} അല്ലെങ്കിൽ {
			debug_f("no separate private key for certificate "
			    "\"%s\"", id->filename);
		}
	}

	/*
	 * If the above didn't select another identity to do the signing
	 * then default to the one we started with.
	 */
	എങ്കിൽ (sign_id == ശൂന്യ)
		sign_id = id;

	/* assemble and sign data */
	വേണ്ടി (fallback_sigtype = 0; fallback_sigtype <= 1; fallback_sigtype++) {
		സ്വതന്ത്രം(alg);
		slen = 0;
		signature = ശൂന്യ;
		എങ്കിൽ ((alg = താക്കോൽ_sig_algorithm(fallback_sigtype ? ശൂന്യ : ssh,
		    id->താക്കോൽ)) == ശൂന്യ) {
			error_f("no mutual signature supported");
			പോകുക out;
		}
		debug3_f("signing using %s %s", alg, fp);

		sshbuf_free(b);
		എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
			fatal_f("sshbuf_new failed");
		എങ്കിൽ ((r = sshbuf_put_stringb(b,
		    ssh->kex->session_id)) != 0)
			fatal_fr(r, "sshbuf_put_stringb");
		skip = sshbuf_len(b);
		എങ്കിൽ ((r = sshbuf_put_u8(b, SSH2_സന്ദേശം_USERAUTH_REQUEST)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
		    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
		    (r = sshbuf_put_cstring(b, method)) != 0 ||
		    (r = sshbuf_put_u8(b, 1)) != 0 ||
		    (r = sshbuf_put_cstring(b, alg)) != 0 ||
		    (r = sshkey_puts(id->താക്കോൽ, b)) != 0) {
			fatal_fr(r, "assemble signed data");
		}
		എങ്കിൽ (hostbound) {
			എങ്കിൽ (ssh->kex->initial_hostkey == ശൂന്യ) {
				fatal_f("internal error: initial hostkey "
				    "not recorded");
			}
			എങ്കിൽ ((r = sshkey_puts(ssh->kex->initial_hostkey, b)) != 0)
				fatal_fr(r, "assemble %s hostkey", method);
		}
		/* generate signature */
		r = identity_sign(sign_id, &signature, &slen,
		    sshbuf_ptr(b), sshbuf_len(b), ssh->compat, alg);
		എങ്കിൽ (r == 0)
			നിർത്തുക;
		അല്ലെങ്കിൽ എങ്കിൽ (r == SSH_ERR_താക്കോൽ_NOT_FOUND)
			പോകുക out; /* soft failure */
		അല്ലെങ്കിൽ എങ്കിൽ (r == SSH_ERR_SIGN_ALG_UNSUPPORTED &&
		    !fallback_sigtype) {
			എങ്കിൽ (sign_id->agent_fd != -1)
				loc = "agent ";
			അല്ലെങ്കിൽ എങ്കിൽ (sign_id->താക്കോൽ != ശൂന്യ &&
			    (sign_id->താക്കോൽ->flags & SSHKEY_FLAG_EXT) != 0)
				loc = "token ";
			logit("%skey %s %s returned incorrect signature type",
			    loc, sshkey_type(id->താക്കോൽ), fp);
			തുടരുക;
		}
		error_fr(r, "signing failed for %s \"%s\"%s",
		    sshkey_type(sign_id->താക്കോൽ), sign_id->filename,
		    id->agent_fd != -1 ? " from agent" : "");
		പോകുക out;
	}
	എങ്കിൽ (slen == 0 || signature == ശൂന്യ) /* shouldn't happen */
		fatal_f("no signature");

	/* append signature */
	എങ്കിൽ ((r = sshbuf_put_string(b, signature, slen)) != 0)
		fatal_fr(r, "append signature");

#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	/* skip session id and packet type */
	എങ്കിൽ ((r = sshbuf_consume(b, skip + 1)) != 0)
		fatal_fr(r, "consume");

	/* put remaining data from buffer into packet */
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_putb(ssh, b)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "enqueue request");

	/* success */
	sent = 1;

 out:
	സ്വതന്ത്രം(fp);
	സ്വതന്ത്രം(alg);
	sshbuf_free(b);
	freezero(signature, slen);
	തിരികെ sent;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
send_pubkey_test(ഘടന ssh *ssh, Identity *id)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	u_char *blob = ശൂന്യ;
	അക്ഷരം *alg = ശൂന്യ;
	size_t bloblen;
	u_int have_sig = 0;
	പൂർണ്ണസംഖ്യ sent = 0, r;

	എങ്കിൽ ((alg = താക്കോൽ_sig_algorithm(ssh, id->താക്കോൽ)) == ശൂന്യ) {
		debug_f("no mutual signature algorithm");
		പോകുക out;
	}

	എങ്കിൽ ((r = sshkey_to_blob(id->താക്കോൽ, &blob, &bloblen)) != 0) {
		/* we cannot handle this key */
		debug3_f("cannot handle key");
		പോകുക out;
	}
	/* register callback for USERAUTH_PK_OK message */
	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_PK_OK, &നിവേശം_userauth_pk_ok);

	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_USERAUTH_REQUEST)) != 0 ||
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
	സ്വതന്ത്രം(alg);
	സ്വതന്ത്രം(blob);
	തിരികെ sent;
}

സ്ഥിതം ഘടന sshkey *
load_identity_file(Identity *id)
{
	ഘടന sshkey *സ്വകാര്യ = ശൂന്യ;
	അക്ഷരം prompt[300], *passphrase, *comment;
	പൂർണ്ണസംഖ്യ r, quit = 0, i;
	ഘടന stat st;

	എങ്കിൽ (stat(id->filename, &st) == -1) {
		do_log2(id->userprovided ?
		    SYSLOG_LEVEL_INFO : SYSLOG_LEVEL_DEBUG3,
		    "no such identity: %s: %s", id->filename, strerror(errno));
		തിരികെ ശൂന്യ;
	}
	snprintf(prompt, വലുപ്പം prompt,
	    "Enter passphrase for key '%.100s': ", id->filename);
	വേണ്ടി (i = 0; i <= options.സംഖ്യ_of_password_prompts; i++) {
		എങ്കിൽ (i == 0)
			passphrase = "";
		അല്ലെങ്കിൽ {
			passphrase = read_passphrase(prompt, 0);
			എങ്കിൽ (*passphrase == '\0') {
				debug2("no passphrase given, try next key");
				സ്വതന്ത്രം(passphrase);
				നിർത്തുക;
			}
		}
		തിരഞ്ഞെടുപ്പ് ((r = sshkey_load_private_type(താക്കോൽ_UNSPEC, id->filename,
		    passphrase, &സ്വകാര്യ, &comment))) {
		അവസ്ഥ 0:
			നിർത്തുക;
		അവസ്ഥ SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE:
			എങ്കിൽ (options.batch_mode) {
				quit = 1;
				നിർത്തുക;
			}
			എങ്കിൽ (i != 0)
				debug2("bad passphrase given, try again...");
			നിർത്തുക;
		അവസ്ഥ SSH_ERR_SYSTEM_ERROR:
			എങ്കിൽ (errno == ENOENT) {
				debug2_r(r, "Load key \"%s\"", id->filename);
				quit = 1;
				നിർത്തുക;
			}
			/* FALLTHROUGH */
		സ്ഥിരസ്ഥിതി:
			error_r(r, "Load key \"%s\"", id->filename);
			quit = 1;
			നിർത്തുക;
		}
		എങ്കിൽ (സ്വകാര്യ != ശൂന്യ && sshkey_is_sk(സ്വകാര്യ) &&
		    options.sk_provider == ശൂന്യ) {
			debug("key \"%s\" is an authenticator-hosted key, "
			    "but no provider specified", id->filename);
			sshkey_free(സ്വകാര്യ);
			സ്വകാര്യ = ശൂന്യ;
			quit = 1;
		}
		എങ്കിൽ (!quit && (r = sshkey_check_rsa_length(സ്വകാര്യ,
		    options.required_rsa_size)) != 0) {
			debug_fr(r, "Skipping key %s", id->filename);
			sshkey_free(സ്വകാര്യ);
			സ്വകാര്യ = ശൂന്യ;
			quit = 1;
		}
		എങ്കിൽ (!quit && സ്വകാര്യ != ശൂന്യ && id->agent_fd == -1 &&
		    !(id->താക്കോൽ && id->isprivate))
			maybe_add_താക്കോൽ_to_agent(id->filename, സ്വകാര്യ, comment,
			    passphrase);
		എങ്കിൽ (i > 0)
			freezero(passphrase, strlen(passphrase));
		സ്വതന്ത്രം(comment);
		എങ്കിൽ (സ്വകാര്യ != ശൂന്യ || quit)
			നിർത്തുക;
	}
	തിരികെ സ്വകാര്യ;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
താക്കോൽ_type_allowed(ഘടന sshkey *താക്കോൽ, സ്ഥിരം അക്ഷരം *allowlist)
{
	എങ്കിൽ (match_pattern_list(sshkey_ssh_name(താക്കോൽ), allowlist, 0) == 1)
		തിരികെ 1;

	/* RSA keys/certs might be allowed by alternate signature types */
	തിരഞ്ഞെടുപ്പ് (താക്കോൽ->type) {
	അവസ്ഥ താക്കോൽ_RSA:
		എങ്കിൽ (match_pattern_list("rsa-sha2-512", allowlist, 0) == 1)
			തിരികെ 1;
		എങ്കിൽ (match_pattern_list("rsa-sha2-256", allowlist, 0) == 1)
			തിരികെ 1;
		നിർത്തുക;
	അവസ്ഥ താക്കോൽ_RSA_CERT:
		എങ്കിൽ (match_pattern_list("rsa-sha2-512-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			തിരികെ 1;
		എങ്കിൽ (match_pattern_list("rsa-sha2-256-cert-v01@openssh.com",
		    allowlist, 0) == 1)
			തിരികെ 1;
		നിർത്തുക;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
താക്കോൽ_type_allowed_by_config(ഘടന sshkey *താക്കോൽ)
{
	തിരികെ താക്കോൽ_type_allowed(താക്കോൽ, options.pubkey_accepted_algos);
}

/* obtain a list of keys from the agent */
സ്ഥിതം പൂർണ്ണസംഖ്യ
get_agent_identities(ഘടന ssh *ssh, പൂർണ്ണസംഖ്യ *agent_fdp,
    ഘടന ssh_identitylist **idlistp)
{
	പൂർണ്ണസംഖ്യ r, agent_fd;
	ഘടന ssh_identitylist *idlist;

	എങ്കിൽ ((r = ssh_get_authentication_socket(&agent_fd)) != 0) {
		എങ്കിൽ (r != SSH_ERR_AGENT_NOT_PRESENT)
			debug_fr(r, "ssh_get_authentication_socket");
		തിരികെ r;
	}
	എങ്കിൽ (ssh != ശൂന്യ && ssh->kex != ശൂന്യ) {
		എങ്കിൽ ((r = ssh_agent_bind_hostkey(agent_fd, ssh->kex->initial_hostkey,
		    ssh->kex->session_id, ssh->kex->initial_sig, 0)) == 0)
			debug_f("bound agent to hostkey");
		അല്ലെങ്കിൽ
			debug2_fr(r, "ssh_agent_bind_hostkey");
	}

	എങ്കിൽ ((r = ssh_fetch_identitylist(agent_fd, &idlist)) != 0) {
		debug_fr(r, "ssh_fetch_identitylist");
		close(agent_fd);
		തിരികെ r;
	}
	/* success */
	*agent_fdp = agent_fd;
	*idlistp = idlist;
	debug_f("agent returned %zu keys", idlist->nkeys);
	തിരികെ 0;
}

/*
 * Returns nonzero if the certificate extensions/critical-options section
 * has the specified option present, zero otherwise.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
cert_has_option(ഘടന sshbuf *oblob, സ്ഥിരം അക്ഷരം *target)
{
	ഘടന sshbuf *c = ശൂന്യ, *data = ശൂന്യ;
	അക്ഷരം *name = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, found = 0;

	എങ്കിൽ (oblob == ശൂന്യ || (c = sshbuf_fromb(oblob)) == ശൂന്യ)
		തിരികെ 0;
	ആകുമ്പോൾ (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = ശൂന്യ;
		സ്വതന്ത്രം(name);
		name = ശൂന്യ;
		എങ്കിൽ ((r = sshbuf_get_cstring(c, &name, ശൂന്യ)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0)
			നിർത്തുക;
		എങ്കിൽ (strcmp(name, target) == 0) {
			found = 1;
			നിർത്തുക;
		}
	}
	sshbuf_free(data);
	സ്വതന്ത്രം(name);
	sshbuf_free(c);
	തിരികെ found;
}

/*
 * Returns an integer describing the priority of the identity
 * within its group. Lower numbers are higher priority.
 */
#define MAX_ID_PRIORITY 3
സ്ഥിതം പൂർണ്ണസംഖ്യ
identity_prioritise(ഘടന identity *id)
{
	എങ്കിൽ (id == ശൂന്യ || id->താക്കോൽ == ശൂന്യ)
		തിരികെ 3;
	എങ്കിൽ (!sshkey_is_cert(id->താക്കോൽ) || id->താക്കോൽ->cert == ശൂന്യ)
		തിരികെ 3;
	എങ്കിൽ (sshkey_is_sk(id->താക്കോൽ) &&
	    cert_has_option(id->താക്കോൽ->cert->critical, "verify-required"))
		തിരികെ 2;
	എങ്കിൽ (sshkey_is_sk(id->താക്കോൽ) &&
	    cert_has_option(id->താക്കോൽ->cert->extensions, "no-touch-required"))
		തിരികെ 0;
	തിരികെ 1;
}

സ്ഥിതം ശൂന്യം
order_identities_by_prio(ഘടന idlist *list)
{
	ഘടന idlist prio[MAX_ID_PRIORITY + 1], sorted;
	ഘടന identity *id, *tmp, *dummy;
	പൂർണ്ണസംഖ്യ p;

	വേണ്ടി (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_INIT(&prio[p]);
	TAILQ_INIT(&sorted);

	TAILQ_FOREACH_SAFE(id, list, next, tmp) {
		എങ്കിൽ (id->userprovided)
			തുടരുക;
		dummy = xcalloc(1, വലുപ്പം(*dummy));
		dummy->userprovided = -1;
		TAILQ_INSERT_BEFORE(id, dummy, next);
		TAILQ_REMOVE(list, id, next);
		p = identity_prioritise(id);
		എങ്കിൽ (p < 0 || p > MAX_ID_PRIORITY)
			fatal_f("internal error: bad priority");
		TAILQ_INSERT_TAIL(&prio[p], id, next);
	}
	വേണ്ടി (p = 0; p <= MAX_ID_PRIORITY; p++)
		TAILQ_CONCAT(&sorted, &prio[p], next);

	TAILQ_FOREACH_SAFE(id, list, next, tmp) {
		എങ്കിൽ (id->userprovided != -1)
			തുടരുക;
		ഘടന identity *s = TAILQ_FIRST(&sorted);
		TAILQ_REMOVE(&sorted, s, next);
		TAILQ_INSERT_BEFORE(id, s, next);
		TAILQ_REMOVE(list, id, next);
		സ്വതന്ത്രം(id);
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
സ്ഥിതം ശൂന്യം
pubkey_prepare(ഘടന ssh *ssh, Authctxt *authctxt)
{
	ഘടന identity *id, *id2, *tmp;
	ഘടന idlist agent, files, certs, agent_താക്കോലുകൾ, *preferred;
	ഘടന sshkey *താക്കോൽ;
	പൂർണ്ണസംഖ്യ disallowed, agent_fd = -1, i, r, found;
	size_t j;
	ഘടന ssh_identitylist *idlist;
	അക്ഷരം *cp, *ident;

	TAILQ_INIT(&agent);	/* keys from the agent */
	TAILQ_INIT(&files);	/* keys from the config file */
	TAILQ_INIT(&certs);	/* certificates specified by user */
	TAILQ_INIT(&agent_താക്കോലുകൾ); /* keys supported by the agent */
	preferred = &authctxt->താക്കോലുകൾ;
	TAILQ_INIT(preferred);	/* preferred order of keys */

	/* list of keys stored in the filesystem and PKCS#11 */
	വേണ്ടി (i = 0; i < options.അക്കം_identity_files; i++) {
		താക്കോൽ = options.identity_താക്കോലുകൾ[i];
		എങ്കിൽ (താക്കോൽ && താക്കോൽ->cert &&
		    താക്കോൽ->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			തുടരുക;
		}
		എങ്കിൽ (താക്കോൽ && sshkey_is_sk(താക്കോൽ) && options.sk_provider == ശൂന്യ) {
			debug_f("ignoring authenticator-hosted key %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			തുടരുക;
		}
		options.identity_താക്കോലുകൾ[i] = ശൂന്യ;
		id = xcalloc(1, വലുപ്പം(*id));
		id->agent_fd = -1;
		id->താക്കോൽ = താക്കോൽ;
		id->filename = xstrdup(options.identity_files[i]);
		id->userprovided = options.identity_file_userprovided[i];
		TAILQ_INSERT_TAIL(&files, id, next);
	}

	/* list of certificates specified by user */
	വേണ്ടി (i = 0; i < options.അക്കം_certificate_files; i++) {
		താക്കോൽ = options.certificates[i];
		എങ്കിൽ (!sshkey_is_cert(താക്കോൽ) || താക്കോൽ->cert == ശൂന്യ ||
		    താക്കോൽ->cert->type != SSH2_CERT_TYPE_USER) {
			debug_f("ignoring certificate %s: not a user "
			    "certificate", options.identity_files[i]);
			തുടരുക;
		}
		എങ്കിൽ (താക്കോൽ && sshkey_is_sk(താക്കോൽ) && options.sk_provider == ശൂന്യ) {
			debug_f("ignoring authenticator-hosted key "
			    "certificate %s as no "
			    "SecurityKeyProvider has been specified",
			    options.identity_files[i]);
			തുടരുക;
		}
		id = xcalloc(1, വലുപ്പം(*id));
		id->agent_fd = -1;
		id->താക്കോൽ = താക്കോൽ;
		id->filename = xstrdup(options.certificate_files[i]);
		id->userprovided = options.certificate_file_userprovided[i];
		TAILQ_INSERT_TAIL(&certs, id, next);
	}
	order_identities_by_prio(&certs);
	TAILQ_CONCAT(preferred, &certs, next);

	/* list of keys supported by the agent */
	എങ്കിൽ ((r = get_agent_identities(ssh, &agent_fd, &idlist)) == 0) {
		വേണ്ടി (j = 0; j < idlist->nkeys; j++) {
			എങ്കിൽ ((r = sshkey_check_rsa_length(idlist->താക്കോലുകൾ[j],
			    options.required_rsa_size)) != 0) {
				debug_fr(r, "ignoring %s agent key",
				    sshkey_ssh_name(idlist->താക്കോലുകൾ[j]));
				തുടരുക;
			}
			found = 0;
			TAILQ_FOREACH(id, &files, next) {
				/*
				 * agent keys from the config file are
				 * preferred
				 */
				എങ്കിൽ (sshkey_equal(idlist->താക്കോലുകൾ[j], id->താക്കോൽ)) {
					TAILQ_REMOVE(&files, id, next);
					TAILQ_INSERT_TAIL(&agent_താക്കോലുകൾ, id, next);
					id->agent_fd = agent_fd;
					found = 1;
					നിർത്തുക;
				}
			}
			എങ്കിൽ (!found && !options.identities_only) {
				id = xcalloc(1, വലുപ്പം(*id));
				/* XXX "steals" key/comment from idlist */
				id->താക്കോൽ = idlist->താക്കോലുകൾ[j];
				id->filename = idlist->comments[j];
				idlist->താക്കോലുകൾ[j] = ശൂന്യ;
				idlist->comments[j] = ശൂന്യ;
				id->agent_fd = agent_fd;
				TAILQ_INSERT_TAIL(&agent, id, next);
			}
		}
		ssh_free_identitylist(idlist);
		/* append remaining agent keys */
		TAILQ_CONCAT(&agent_താക്കോലുകൾ, &agent, next);
		order_identities_by_prio(&agent_താക്കോലുകൾ);
		TAILQ_CONCAT(preferred, &agent_താക്കോലുകൾ, next);
		authctxt->agent_fd = agent_fd;
	}
	/* Prefer PKCS11 keys that are explicitly listed */
	TAILQ_FOREACH_SAFE(id, &files, next, tmp) {
		എങ്കിൽ (id->താക്കോൽ == ശൂന്യ || (id->താക്കോൽ->flags & SSHKEY_FLAG_EXT) == 0)
			തുടരുക;
		found = 0;
		TAILQ_FOREACH(id2, &files, next) {
			എങ്കിൽ (id2->താക്കോൽ == ശൂന്യ ||
			    (id2->താക്കോൽ->flags & SSHKEY_FLAG_EXT) != 0)
				തുടരുക;
			എങ്കിൽ (sshkey_equal(id->താക്കോൽ, id2->താക്കോൽ)) {
				TAILQ_REMOVE(&files, id, next);
				TAILQ_INSERT_TAIL(preferred, id, next);
				found = 1;
				നിർത്തുക;
			}
		}
		/* If IdentitiesOnly set and key not found then don't use it */
		എങ്കിൽ (!found && options.identities_only) {
			TAILQ_REMOVE(&files, id, next);
			freezero(id, വലുപ്പം(*id));
		}
	}
	order_identities_by_prio(&files);
	/* append remaining keys from the config file */
	TAILQ_CONCAT(preferred, &files, next);
	/* finally, filter by PubkeyAcceptedAlgorithms */
	TAILQ_FOREACH_SAFE(id, preferred, next, id2) {
		disallowed = 0;
		cp = ശൂന്യ;
		എങ്കിൽ (id->താക്കോൽ == ശൂന്യ)
			തുടരുക;
		എങ്കിൽ (!താക്കോൽ_type_allowed_by_config(id->താക്കോൽ)) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not in PubkeyAcceptedAlgorithms",
			    sshkey_ssh_name(id->താക്കോൽ), id->filename);
			disallowed = 1;
		} അല്ലെങ്കിൽ എങ്കിൽ (ssh != ശൂന്യ && ssh->kex != ശൂന്യ &&
		    ssh->kex->server_sig_algs != ശൂന്യ &&
		    (cp = താക്കോൽ_sig_algorithm(ssh, id->താക്കോൽ)) == ശൂന്യ) {
			debug("Skipping %s key %s - corresponding algorithm "
			    "not supported by server",
			    sshkey_ssh_name(id->താക്കോൽ), id->filename);
			disallowed = 1;
		}
		സ്വതന്ത്രം(cp);
		എങ്കിൽ (!disallowed)
			തുടരുക;
		/* remove key */
		TAILQ_REMOVE(preferred, id, next);
		sshkey_free(id->താക്കോൽ);
		സ്വതന്ത്രം(id->filename);
		freezero(id, വലുപ്പം(*id));
	}
	/* List the keys we plan on using */
	TAILQ_FOREACH_SAFE(id, preferred, next, id2) {
		ident = format_identity(id);
		debug("Will attempt key: %s", ident);
		സ്വതന്ത്രം(ident);
	}
	debug2_f("done");
}

സ്ഥിതം ശൂന്യം
pubkey_cleanup(ഘടന ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;

	എങ്കിൽ (authctxt->agent_fd != -1) {
		ssh_close_authentication_socket(authctxt->agent_fd);
		authctxt->agent_fd = -1;
	}
	വേണ്ടി (id = TAILQ_FIRST(&authctxt->താക്കോലുകൾ); id;
	    id = TAILQ_FIRST(&authctxt->താക്കോലുകൾ)) {
		TAILQ_REMOVE(&authctxt->താക്കോലുകൾ, id, next);
		sshkey_free(id->താക്കോൽ);
		സ്വതന്ത്രം(id->filename);
		സ്വതന്ത്രം(id);
	}
}

ശൂന്യം
pubkey_dump(ഘടന ssh *ssh)
{
	Authctxt authctxt;
	Identity *id;
	അക്ഷരം *ident;

	memset(&authctxt, 0, വലുപ്പം(authctxt));
	authctxt.agent_fd = -1;
	ssh->authctxt = &authctxt;

	pubkey_prepare(ssh, &authctxt);
	TAILQ_FOREACH(id, &authctxt.താക്കോലുകൾ, next) {
		ident = format_identity(id);
		fprintf(stdout, "%s\n", ident);
		സ്വതന്ത്രം(ident);
	}
	pubkey_cleanup(ssh);
	ssh->authctxt = ശൂന്യ;
}

സ്ഥിതം ശൂന്യം
pubkey_reset(Authctxt *authctxt)
{
	Identity *id;

	TAILQ_FOREACH(id, &authctxt->താക്കോലുകൾ, next)
		id->tried = 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
userauth_pubkey(ഘടന ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	Identity *id;
	പൂർണ്ണസംഖ്യ sent = 0;
	അക്ഷരം *ident;
	സ്ഥിതം പൂർണ്ണസംഖ്യ prepared;

	എങ്കിൽ (!prepared) {
		pubkey_prepare(ssh, authctxt);
		prepared = 1;
	}

	ആകുമ്പോൾ ((id = TAILQ_FIRST(&authctxt->താക്കോലുകൾ))) {
		എങ്കിൽ (id->tried++)
			തിരികെ (0);
		/* move key to the end of the queue */
		TAILQ_REMOVE(&authctxt->താക്കോലുകൾ, id, next);
		TAILQ_INSERT_TAIL(&authctxt->താക്കോലുകൾ, id, next);
		/*
		 * send a test message if we have the public key. for
		 * encrypted keys we cannot do this and have to load the
		 * private key instead
		 */
		എങ്കിൽ (id->താക്കോൽ != ശൂന്യ) {
			ident = format_identity(id);
			debug("Offering public key: %s", ident);
			സ്വതന്ത്രം(ident);
			sent = send_pubkey_test(ssh, id);
		} അല്ലെങ്കിൽ {
			debug("Trying private key: %s", id->filename);
			id->താക്കോൽ = load_identity_file(id);
			എങ്കിൽ (id->താക്കോൽ != ശൂന്യ) {
				id->isprivate = 1;
				sent = sign_and_send_pubkey(ssh, id);
				sshkey_free(id->താക്കോൽ);
				id->താക്കോൽ = ശൂന്യ;
				id->isprivate = 0;
			}
		}
		എങ്കിൽ (sent)
			തിരികെ (sent);
	}
	തിരികെ (0);
}

/*
 * Send userauth request message specifying keyboard-interactive method.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
userauth_kbdint(ഘടന ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (authctxt->attempt_kbdint++ >= options.സംഖ്യ_of_password_prompts)
		തിരികെ 0;
	/* disable if no SSH2_MSG_USERAUTH_INFO_REQUEST has been seen */
	എങ്കിൽ (authctxt->attempt_kbdint > 1 && !authctxt->info_req_seen) {
		debug3("userauth_kbdint: disable: no info_req_seen");
		ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_INFO_REQUEST, ശൂന്യ);
		തിരികെ 0;
	}

	debug2("userauth_kbdint");
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_USERAUTH_REQUEST)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->server_user)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->service)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, authctxt->method->name)) != 0 ||
	    (r = sshpkt_put_cstring(ssh, "")) != 0 ||		/* lang */
	    (r = sshpkt_put_cstring(ssh, options.kbd_interactive_devices ?
	    options.kbd_interactive_devices : "")) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		fatal_fr(r, "send packet");

	ssh_dispatch_set(ssh, SSH2_സന്ദേശം_USERAUTH_INFO_REQUEST, &നിവേശം_userauth_info_req);
	തിരികെ 1;
}

/*
 * parse INFO_REQUEST, prompt user and send INFO_RESPONSE
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
നിവേശം_userauth_info_req(പൂർണ്ണസംഖ്യ type, uint32_t seq, ഘടന ssh *ssh)
{
	Authctxt *authctxt = ssh->authctxt;
	അക്ഷരം *name = ശൂന്യ, *inst = ശൂന്യ, *lang = ശൂന്യ, *prompt = ശൂന്യ;
	അക്ഷരം *display_prompt = ശൂന്യ, *response = ശൂന്യ;
	u_char echo = 0;
	u_int അക്കം_prompts, i;
	പൂർണ്ണസംഖ്യ r, addnl;
	size_t len;

	debug2_f("entering");

	എങ്കിൽ (authctxt == ശൂന്യ)
		fatal_f("no authentication context");

	authctxt->info_req_seen = 1;

	എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &name, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &inst, ശൂന്യ)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &lang, ശൂന്യ)) != 0)
		പോകുക out;
	എങ്കിൽ ((len = strlen(name)) > 0) {
		addnl = name[len] != '\n';
		fmprintf(stderr, "%s%s", name, addnl ? "\n" : "");
	}
	എങ്കിൽ ((len = strlen(inst)) > 0) {
		addnl = inst[len] != '\n';
		fmprintf(stderr, "%s%s", inst, addnl ? "\n" : "");
	}

	എങ്കിൽ ((r = sshpkt_get_u32(ssh, &അക്കം_prompts)) != 0)
		പോകുക out;
	/*
	 * Begin to build info response packet based on prompts requested.
	 * We commit to providing the correct number of responses, so if
	 * further on we run into a problem that prevents this, we have to
	 * be sure and clean this up and send a correct error response.
	 */
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_USERAUTH_INFO_RESPONSE)) != 0 ||
	    (r = sshpkt_put_u32(ssh, അക്കം_prompts)) != 0)
		പോകുക out;

	debug2_f("num_prompts %d", അക്കം_prompts);
	വേണ്ടി (i = 0; i < അക്കം_prompts; i++) {
		എങ്കിൽ ((r = sshpkt_get_cstring(ssh, &prompt, ശൂന്യ)) != 0 ||
		    (r = sshpkt_get_u8(ssh, &echo)) != 0)
			പോകുക out;
		എങ്കിൽ (asmprintf(&display_prompt, INT_MAX, ശൂന്യ, "(%s@%s) %s",
		    authctxt->server_user, options.host_താക്കോൽ_alias ?
		    options.host_താക്കോൽ_alias : authctxt->host, prompt) == -1)
			fatal_f("asmprintf failed");
		response = read_passphrase(display_prompt, echo ? RP_ECHO : 0);
		എങ്കിൽ ((r = sshpkt_put_cstring(ssh, response)) != 0)
			പോകുക out;
		freezero(response, strlen(response));
		സ്വതന്ത്രം(prompt);
		സ്വതന്ത്രം(display_prompt);
		display_prompt = response = prompt = ശൂന്യ;
	}
	/* done with parsing incoming message. */
	എങ്കിൽ ((r = sshpkt_get_end(ssh)) != 0 ||
	    (r = sshpkt_add_padding(ssh, 64)) != 0)
		പോകുക out;
	r = sshpkt_send(ssh);
 out:
	എങ്കിൽ (response)
		freezero(response, strlen(response));
	സ്വതന്ത്രം(prompt);
	സ്വതന്ത്രം(display_prompt);
	സ്വതന്ത്രം(name);
	സ്വതന്ത്രം(inst);
	സ്വതന്ത്രം(lang);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_keysign(ഘടന ssh *ssh, ഘടന sshkey *താക്കോൽ, u_char **sigp, size_t *lenp,
    സ്ഥിരം u_char *data, size_t datalen)
{
	ഘടന sshbuf *b;
	ഘടന stat st;
	pid_t pid;
	പൂർണ്ണസംഖ്യ r, to[2], from[2], status;
	പൂർണ്ണസംഖ്യ sock = ssh_packet_get_connection_in(ssh);
	u_char rversion = 0, version = 2;
	ശൂന്യം (*osigchld)(പൂർണ്ണസംഖ്യ);

	*sigp = ശൂന്യ;
	*lenp = 0;

	എങ്കിൽ (stat(PATH_SSH_താക്കോൽ_SIGN, &st) == -1) {
		error_f("not installed: %s", strerror(errno));
		തിരികെ -1;
	}
	എങ്കിൽ (fflush(stdout) != 0) {
		error_f("fflush: %s", strerror(errno));
		തിരികെ -1;
	}
	എങ്കിൽ (pipe(to) == -1) {
		error_f("pipe: %s", strerror(errno));
		തിരികെ -1;
	}
	എങ്കിൽ (pipe(from) == -1) {
		error_f("pipe: %s", strerror(errno));
		തിരികെ -1;
	}
	എങ്കിൽ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		തിരികെ -1;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	എങ്കിൽ (pid == 0) {
		close(from[0]);
		എങ്കിൽ (dup2(from[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(to[1]);
		എങ്കിൽ (dup2(to[0], STDIN_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		close(from[1]);
		close(to[0]);

		എങ്കിൽ (dup2(sock, STDERR_FILENO + 1) == -1)
			fatal_f("dup2: %s", strerror(errno));
		sock = STDERR_FILENO + 1;
		എങ്കിൽ (fcntl(sock, F_SETFD, 0) == -1) /* keep the socket on exec */
			debug3_f("fcntl F_SETFD: %s", strerror(errno));
		closefrom(sock + 1);

		debug3_f("[child] pid=%ld, exec %s",
		    (long)getpid(), PATH_SSH_താക്കോൽ_SIGN);
		execl(PATH_SSH_താക്കോൽ_SIGN, PATH_SSH_താക്കോൽ_SIGN, (അക്ഷരം *)ശൂന്യ);
		fatal_f("exec(%s): %s", PATH_SSH_താക്കോൽ_SIGN,
		    strerror(errno));
	}
	close(from[1]);
	close(to[0]);
	sock = STDERR_FILENO + 1;

	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	/* send # of sock, data to be signed */
	എങ്കിൽ ((r = sshbuf_put_u32(b, sock)) != 0 ||
	    (r = sshbuf_put_string(b, data, datalen)) != 0)
		fatal_fr(r, "buffer error");
	എങ്കിൽ (ssh_സന്ദേശം_send(to[1], version, b) == -1)
		fatal_f("couldn't send request");
	sshbuf_reset(b);
	r = ssh_സന്ദേശം_recv(from[0], b);
	close(from[0]);
	close(to[1]);
	എങ്കിൽ (r < 0) {
		error_f("no reply");
		പോകുക fail;
	}

	errno = 0;
	ആകുമ്പോൾ (waitpid(pid, &status, 0) == -1) {
		എങ്കിൽ (errno != EINTR) {
			error_f("waitpid %ld: %s", (long)pid, strerror(errno));
			പോകുക fail;
		}
	}
	എങ്കിൽ (!WIFEXITED(status)) {
		error_f("exited abnormally");
		പോകുക fail;
	}
	എങ്കിൽ (WEXITSTATUS(status) != 0) {
		error_f("exited with status %d", WEXITSTATUS(status));
		പോകുക fail;
	}
	എങ്കിൽ ((r = sshbuf_get_u8(b, &rversion)) != 0) {
		error_fr(r, "buffer error");
		പോകുക fail;
	}
	എങ്കിൽ (rversion != version) {
		error_f("bad version");
		പോകുക fail;
	}
	എങ്കിൽ ((r = sshbuf_get_string(b, sigp, lenp)) != 0) {
		error_fr(r, "buffer error");
 fail:
		ssh_signal(SIGCHLD, osigchld);
		sshbuf_free(b);
		തിരികെ -1;
	}
	ssh_signal(SIGCHLD, osigchld);
	sshbuf_free(b);

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
userauth_hostbased(ഘടന ssh *ssh)
{
	Authctxt *authctxt = (Authctxt *)ssh->authctxt;
	ഘടന sshkey *സ്വകാര്യ = ശൂന്യ;
	ഘടന sshbuf *b = ശൂന്യ;
	u_char *sig = ശൂന്യ, *keyblob = ശൂന്യ;
	അക്ഷരം *fp = ശൂന്യ, *chost = ശൂന്യ, *lname = ശൂന്യ;
	size_t siglen = 0, keylen = 0;
	പൂർണ്ണസംഖ്യ i, r, success = 0;

	എങ്കിൽ (authctxt->ktypes == ശൂന്യ) {
		authctxt->oktypes = xstrdup(options.hostbased_accepted_algos);
		authctxt->ktypes = authctxt->oktypes;
	}

	/*
	 * Work through each listed type pattern in HostbasedAcceptedAlgorithms,
	 * trying each hostkey that matches the type in turn.
	 */
	വേണ്ടി (;;) {
		എങ്കിൽ (authctxt->active_ktype == ശൂന്യ)
			authctxt->active_ktype = strsep(&authctxt->ktypes, ",");
		എങ്കിൽ (authctxt->active_ktype == ശൂന്യ ||
		    *authctxt->active_ktype == '\0')
			നിർത്തുക;
		debug3_f("trying key type %s", authctxt->active_ktype);

		/* check for a useful key */
		സ്വകാര്യ = ശൂന്യ;
		വേണ്ടി (i = 0; i < authctxt->sensitive->nkeys; i++) {
			എങ്കിൽ (authctxt->sensitive->താക്കോലുകൾ[i] == ശൂന്യ ||
			    authctxt->sensitive->താക്കോലുകൾ[i]->type == താക്കോൽ_UNSPEC)
				തുടരുക;
			എങ്കിൽ (!sshkey_match_keyname_to_sigalgs(
			    sshkey_ssh_name(authctxt->sensitive->താക്കോലുകൾ[i]),
			    authctxt->active_ktype))
				തുടരുക;
			/* we take and free the key */
			സ്വകാര്യ = authctxt->sensitive->താക്കോലുകൾ[i];
			authctxt->sensitive->താക്കോലുകൾ[i] = ശൂന്യ;
			നിർത്തുക;
		}
		/* Found one */
		എങ്കിൽ (സ്വകാര്യ != ശൂന്യ)
			നിർത്തുക;
		/* No more keys of this type; advance */
		authctxt->active_ktype = ശൂന്യ;
	}
	എങ്കിൽ (സ്വകാര്യ == ശൂന്യ) {
		സ്വതന്ത്രം(authctxt->oktypes);
		authctxt->oktypes = authctxt->ktypes = ശൂന്യ;
		authctxt->active_ktype = ശൂന്യ;
		debug("No more client hostkeys for hostbased authentication.");
		പോകുക out;
	}

	എങ്കിൽ ((fp = sshkey_fingerprint(സ്വകാര്യ, options.fingerprint_hash,
	    SSH_FP_DEFAULT)) == ശൂന്യ) {
		error_f("sshkey_fingerprint failed");
		പോകുക out;
	}
	debug_f("trying hostkey %s %s using sigalg %s",
	    sshkey_ssh_name(സ്വകാര്യ), fp, authctxt->active_ktype);

	/* figure out a name for the client host */
	lname = get_local_name(ssh_packet_get_connection_in(ssh));
	എങ്കിൽ (lname == ശൂന്യ) {
		error_f("cannot get local ipaddr/name");
		പോകുക out;
	}

	/* XXX sshbuf_put_stringf? */
	xasprintf(&chost, "%s.", lname);
	debug2_f("chost %s", chost);

	/* construct data */
	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ) {
		error_f("sshbuf_new failed");
		പോകുക out;
	}
	എങ്കിൽ ((r = sshkey_to_blob(സ്വകാര്യ, &keyblob, &keylen)) != 0) {
		error_fr(r, "sshkey_to_blob");
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put_stringb(b, ssh->kex->session_id)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_സന്ദേശം_USERAUTH_REQUEST)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->server_user)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->service)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->method->name)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->active_ktype)) != 0 ||
	    (r = sshbuf_put_string(b, keyblob, keylen)) != 0 ||
	    (r = sshbuf_put_cstring(b, chost)) != 0 ||
	    (r = sshbuf_put_cstring(b, authctxt->local_user)) != 0) {
		error_fr(r, "buffer error");
		പോകുക out;
	}

#ifdef DEBUG_PK
	sshbuf_dump(b, stderr);
#endif
	എങ്കിൽ ((r = ssh_keysign(ssh, സ്വകാര്യ, &sig, &siglen,
	    sshbuf_ptr(b), sshbuf_len(b))) != 0) {
		error("sign using hostkey %s %s failed",
		    sshkey_ssh_name(സ്വകാര്യ), fp);
		പോകുക out;
	}
	എങ്കിൽ ((r = sshpkt_start(ssh, SSH2_സന്ദേശം_USERAUTH_REQUEST)) != 0 ||
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
		പോകുക out;
	}
	success = 1;

 out:
	എങ്കിൽ (sig != ശൂന്യ)
		freezero(sig, siglen);
	സ്വതന്ത്രം(keyblob);
	സ്വതന്ത്രം(lname);
	സ്വതന്ത്രം(fp);
	സ്വതന്ത്രം(chost);
	sshkey_free(സ്വകാര്യ);
	sshbuf_free(b);

	തിരികെ success;
}

/* find auth method */

/*
 * given auth method name, if configurable options permit this method fill
 * in auth_ident field and return true, otherwise return false.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
authmethod_is_enabled(Authmethod *method)
{
	എങ്കിൽ (method == ശൂന്യ)
		തിരികെ 0;
	/* return false if options indicate this method is disabled */
	എങ്കിൽ  (method->enabled == ശൂന്യ || *method->enabled == 0)
		തിരികെ 0;
	/* return false if batch mode is enabled but method needs interactive mode */
	എങ്കിൽ  (method->batch_flag != ശൂന്യ && *method->batch_flag != 0)
		തിരികെ 0;
	തിരികെ 1;
}

സ്ഥിതം Authmethod *
authmethod_lookup(സ്ഥിരം അക്ഷരം *name)
{
	Authmethod *method = ശൂന്യ;
	എങ്കിൽ (name != ശൂന്യ)
		വേണ്ടി (method = authmethods; method->name != ശൂന്യ; method++)
			എങ്കിൽ (strcmp(name, method->name) == 0)
				തിരികെ method;
	debug2("Unrecognized authentication method name: %s", name ? name : "NULL");
	തിരികെ ശൂന്യ;
}

/* XXX internal state */
സ്ഥിതം Authmethod *current = ശൂന്യ;
സ്ഥിതം അക്ഷരം *supported = ശൂന്യ;
സ്ഥിതം അക്ഷരം *preferred = ശൂന്യ;

/*
 * Given the authentication method list sent by the server, return the
 * next method we should try.  If the server initially sends a nil list,
 * use a built-in default list.
 */
സ്ഥിതം Authmethod *
authmethod_get(അക്ഷരം *authlist)
{
	അക്ഷരം *name = ശൂന്യ;
	u_int next;

	/* Use a suitable default if we're passed a nil list.  */
	എങ്കിൽ (authlist == ശൂന്യ || strlen(authlist) == 0)
		authlist = options.preferred_authentications;

	എങ്കിൽ (supported == ശൂന്യ || strcmp(authlist, supported) != 0) {
		debug3("start over, passed a different list %s", authlist);
		സ്വതന്ത്രം(supported);
		supported = xstrdup(authlist);
		preferred = options.preferred_authentications;
		debug3("preferred %s", preferred);
		current = ശൂന്യ;
	} അല്ലെങ്കിൽ എങ്കിൽ (current != ശൂന്യ && authmethod_is_enabled(current))
		തിരികെ current;

	വേണ്ടി (;;) {
		എങ്കിൽ ((name = match_list(preferred, supported, &next)) == ശൂന്യ) {
			debug("No more authentication methods to try.");
			current = ശൂന്യ;
			തിരികെ ശൂന്യ;
		}
		preferred += next;
		debug3("authmethod_lookup %s", name);
		debug3("remaining preferred: %s", preferred);
		എങ്കിൽ ((current = authmethod_lookup(name)) != ശൂന്യ &&
		    authmethod_is_enabled(current)) {
			debug3("authmethod_is_enabled %s", name);
			debug("Next authentication method: %s", name);
			സ്വതന്ത്രം(name);
			തിരികെ current;
		}
		സ്വതന്ത്രം(name);
	}
}

സ്ഥിതം അക്ഷരം *
authmethods_get(ശൂന്യം)
{
	Authmethod *method = ശൂന്യ;
	ഘടന sshbuf *b;
	അക്ഷരം *list;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ)
		fatal_f("sshbuf_new failed");
	വേണ്ടി (method = authmethods; method->name != ശൂന്യ; method++) {
		എങ്കിൽ (authmethod_is_enabled(method)) {
			എങ്കിൽ ((r = sshbuf_putf(b, "%s%s",
			    sshbuf_len(b) ? "," : "", method->name)) != 0)
				fatal_fr(r, "buffer error");
		}
	}
	എങ്കിൽ ((list = sshbuf_dup_string(b)) == ശൂന്യ)
		fatal_f("sshbuf_dup_string failed");
	sshbuf_free(b);
	തിരികെ list;
}
