/* $OpenBSD: servconf.c,v 1.459 2026/10/09 10:48:43 dtucker Exp $ */
/*
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/queue.h>
#അന്തര്ഭാവ <sys/stat.h>
#ifdef __OpenBSD__
#അന്തര്ഭാവ <sys/sysctl.h>
#endif

#അന്തര്ഭാവ <netinet/in.h>
#അന്തര്ഭാവ <netinet/ip.h>
#ifdef HAVE_NET_ROUTE_H
#അന്തര്ഭാവ <net/route.h>
#endif

#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <glob.h>
#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <util.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "cipher.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "mac.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "channels.h"
#അന്തര്ഭാവ "groupaccess.h"
#അന്തര്ഭാവ "canohost.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "myproposal.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "version.h"

#define SSHD_CONFIG_BLOB_VERSION	1

#എങ്കിൽ !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#endif

സ്ഥിതം ശൂന്യം add_listen_addr(ServerOptions *, സ്ഥിരം അക്ഷരം *,
    സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ);
സ്ഥിതം ശൂന്യം add_one_listen_addr(ServerOptions *, സ്ഥിരം അക്ഷരം *,
    സ്ഥിരം അക്ഷരം *, പൂർണ്ണസംഖ്യ);
സ്ഥിതം ശൂന്യം parse_server_config_depth(ServerOptions *options,
    സ്ഥിരം അക്ഷരം *filename, ഘടന sshbuf *conf, ഘടന include_list *includes,
    ഘടന connection_info *connectinfo, പൂർണ്ണസംഖ്യ flags, പൂർണ്ണസംഖ്യ *activep, പൂർണ്ണസംഖ്യ depth);

ബാഹ്യ ഘടന sshbuf *cfg;

/* Initializes the server options to their default values. */

ശൂന്യം
initialize_server_options(ServerOptions *options)
{
	memset(options, 0, വലുപ്പം(*options));
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#define SSHCONF_STRING(var, conf, flags, cp)		options->var = ശൂന്യ;
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = ശൂന്യ;
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#define SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = ശൂന്യ;
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	/* Using macros for these is a bit overkill but forces consistency */
#define init_hostkeyfile(options) \
	options->host_താക്കോൽ_files = 0; \
	options->അക്കം_host_താക്കോൽ_files = 0; \
	options->host_താക്കോൽ_file_userprovided = ശൂന്യ;
#define init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#define init_listenaddress(options) \
	options->queued_listen_addrs = ശൂന്യ; \
	options->അക്കം_queued_listens = 0; \
	options->listen_addrs = ശൂന്യ; \
	options->അക്കം_listen_addrs = 0;
#define init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
#define init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_SET;
#define init_port(options) \
	options->അക്കം_ports = 0; \
	options->ports_from_cmdline = 0;
#define init_gatewayports(options) \
	options->fwd_opts.gateway_ports = -1;
#define init_streamlocalbindmask(options) \
	options->fwd_opts.streamlocal_bind_mask = (mode_t)-1;
#define init_streamlocalbindunlink(options) \
	options->fwd_opts.streamlocal_bind_unlink = -1;
#define init_maxstartups(options) \
	options->max_startups_begin = -1; \
	options->max_startups_rate = -1; \
	options->max_startups = -1;
#define init_permituserenv(options) \
	options->permit_user_env = -1; \
	options->permit_user_env_allowlist = ശൂന്യ;
#define init_persourcenetblocksize(options) \
	options->per_source_masklen_ipv4 = -1; \
	options->per_source_masklen_ipv6 = -1;
#define init_persourcepenalties(options) \
	options->per_source_penalty_exempt = ശൂന്യ; \
	options->per_source_penalty.enabled = -1; \
	options->per_source_penalty.max_sources4 = -1; \
	options->per_source_penalty.max_sources6 = -1; \
	options->per_source_penalty.overflow_mode = -1; \
	options->per_source_penalty.overflow_mode6 = -1; \
	options->per_source_penalty.penalty_crash = -1.0; \
	options->per_source_penalty.penalty_authfail = -1.0; \
	options->per_source_penalty.penalty_invaliduser = -1.0; \
	options->per_source_penalty.penalty_noauth = -1.0; \
	options->per_source_penalty.penalty_grace = -1.0; \
	options->per_source_penalty.penalty_refuseconnection = -1.0; \
	options->per_source_penalty.penalty_max = -1.0; \
	options->per_source_penalty.penalty_min = -1.0;
#define init_rekeylimit(options) \
	options->rekey_limit = -1; \
	options->rekey_interval = -1;
#define init_subsystem(options) \
	options->അക്കം_subsystems = 0; \
	options->subsystem_name = ശൂന്യ; \
	options->subsystem_command = ശൂന്യ; \
	options->subsystem_args = ശൂന്യ;
#define init_pubkey_auth_options(options) \
	options->pubkey_auth_options = -1; \
	options->max_pubkey_ok = -1;
#define init_timingsecret(options) \
	options->timing_secret = 0;

	SSHD_CONFIG_ENTRIES

#undef init_hostkeyfile
#undef init_ipqos
#undef init_listenaddress
#undef init_logfacility
#undef init_loglevel
#undef init_port
#undef init_gatewayports
#undef init_streamlocalbindmask
#undef init_streamlocalbindunlink
#undef init_maxstartups
#undef init_permituserenv
#undef init_persourcenetblocksize
#undef init_persourcepenalties
#undef init_rekeylimit
#undef init_subsystem
#undef init_timingsecret
#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
സ്ഥിതം പൂർണ്ണസംഖ്യ
option_clear_or_none(സ്ഥിരം അക്ഷരം *o)
{
	തിരികെ o == ശൂന്യ || strcasecmp(o, "none") == 0;
}

സ്ഥിതം ശൂന്യം
assemble_algorithms(ServerOptions *o)
{
	അക്ഷരം *all_cipher, *all_mac, *all_kex, *all_താക്കോൽ, *all_sig;
	അക്ഷരം *def_cipher, *def_mac, *def_kex, *def_താക്കോൽ, *def_sig;
	പൂർണ്ണസംഖ്യ r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_താക്കോൽ = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_താക്കോൽ = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_താക്കോൽ);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	ചെയ്യുക { \
		എങ്കിൽ ((r = kex_assemble_names(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} ആകുമ്പോൾ (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_താക്കോൽ, all_താക്കോൽ);
	ASSEMBLE(hostbased_accepted_algos, def_താക്കോൽ, all_താക്കോൽ);
	ASSEMBLE(pubkey_accepted_algos, def_താക്കോൽ, all_താക്കോൽ);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE
	സ്വതന്ത്രം(all_cipher);
	സ്വതന്ത്രം(all_mac);
	സ്വതന്ത്രം(all_kex);
	സ്വതന്ത്രം(all_താക്കോൽ);
	സ്വതന്ത്രം(all_sig);
	സ്വതന്ത്രം(def_cipher);
	സ്വതന്ത്രം(def_mac);
	സ്വതന്ത്രം(def_kex);
	സ്വതന്ത്രം(def_താക്കോൽ);
	സ്വതന്ത്രം(def_sig);
}

ശൂന്യം
servconf_add_hostkey(സ്ഥിരം അക്ഷരം *file, സ്ഥിരം പൂർണ്ണസംഖ്യ വരി,
    ServerOptions *options, സ്ഥിരം അക്ഷരം *path, പൂർണ്ണസംഖ്യ userprovided)
{
	അക്ഷരം *apath = derelativise_path(path);

	opt_array_append2(file, വരി, "HostKey",
	    &options->host_താക്കോൽ_files, &options->host_താക്കോൽ_file_userprovided,
	    &options->അക്കം_host_താക്കോൽ_files, apath, userprovided);
	സ്വതന്ത്രം(apath);
}

ശൂന്യം
servconf_add_hostcert(സ്ഥിരം അക്ഷരം *file, സ്ഥിരം പൂർണ്ണസംഖ്യ വരി,
    ServerOptions *options, സ്ഥിരം അക്ഷരം *path)
{
	അക്ഷരം *apath = derelativise_path(path);

	opt_array_append(file, വരി, "HostCertificate",
	    &options->host_cert_files, &options->അക്കം_host_cert_files, apath);
	സ്വതന്ത്രം(apath);
}

ശൂന്യം
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#ifdef SKIP_PRIVDROP
	എങ്കിൽ (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	എങ്കിൽ (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#endif

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	എങ്കിൽ (options->var == -1) \
		options->var = def;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	എങ്കിൽ (options->var == -1) \
		options->var = def;
#define SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#define SSHCONF_NONCONF(funcsuffix)			/* done manually */
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	ചെയ്യുക { \
		സ്വതന്ത്രം(options->var); \
		options->var = ശൂന്യ; \
	} ആകുമ്പോൾ (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	/* XXX maybe use macros here too to force consistency? */

	SSHD_CONFIG_ENTRIES

#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

#ifdef USE_PAM
	എങ്കിൽ (options->pam_service_name == ശൂന്യ)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#endif

	എങ്കിൽ (options->അക്കം_host_താക്കോൽ_files == 0) {
		/* fill default hostkeys */
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_RSA_താക്കോൽ_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ECDSA_താക്കോൽ_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ED25519_താക്കോൽ_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_MLDSA44_ED25519_താക്കോൽ_FILE, 0);
	}
	/* No certificates by default */
	എങ്കിൽ (options->അക്കം_ports == 0)
		options->ports[options->അക്കം_ports++] = SSH_DEFAULT_PORT;
	എങ്കിൽ (options->listen_addrs == ശൂന്യ)
		add_listen_addr(options, ശൂന്യ, ശൂന്യ, 0);
	എങ്കിൽ (options->pid_file == ശൂന്യ)
		options->pid_file = xstrdup(_PATH_SSH_DAEMON_PID_FILE);
	എങ്കിൽ (options->moduli_file == ശൂന്യ)
		options->moduli_file = xstrdup(_PATH_DH_MODULI);
	എങ്കിൽ (options->xauth_location == ശൂന്യ)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	എങ്കിൽ (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	എങ്കിൽ (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	എങ്കിൽ (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = ശൂന്യ;
	}
	എങ്കിൽ (options->rekey_limit == -1)
		options->rekey_limit = 0;
	എങ്കിൽ (options->rekey_interval == -1)
		options->rekey_interval = 0;
	എങ്കിൽ (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	എങ്കിൽ (options->max_startups == -1)
		options->max_startups = 100;
	എങ്കിൽ (options->max_startups_rate == -1)
		options->max_startups_rate = 30;		/* 30% */
	എങ്കിൽ (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	എങ്കിൽ (options->per_source_masklen_ipv4 == -1)
		options->per_source_masklen_ipv4 = 32;
	എങ്കിൽ (options->per_source_masklen_ipv6 == -1)
		options->per_source_masklen_ipv6 = 128;
	എങ്കിൽ (options->per_source_penalty.enabled == -1)
		options->per_source_penalty.enabled = 1;
	എങ്കിൽ (options->per_source_penalty.max_sources4 == -1)
		options->per_source_penalty.max_sources4 = 65536;
	എങ്കിൽ (options->per_source_penalty.max_sources6 == -1)
		options->per_source_penalty.max_sources6 = 65536;
	എങ്കിൽ (options->per_source_penalty.overflow_mode == -1)
		options->per_source_penalty.overflow_mode = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
	എങ്കിൽ (options->per_source_penalty.overflow_mode6 == -1)
		options->per_source_penalty.overflow_mode6 = options->per_source_penalty.overflow_mode;
	എങ്കിൽ (options->per_source_penalty.penalty_crash < 0.0)
		options->per_source_penalty.penalty_crash = 90.0;
	എങ്കിൽ (options->per_source_penalty.penalty_grace < 0.0)
		options->per_source_penalty.penalty_grace = 10.0;
	എങ്കിൽ (options->per_source_penalty.penalty_authfail < 0.0)
		options->per_source_penalty.penalty_authfail = 5.0;
	എങ്കിൽ (options->per_source_penalty.penalty_invaliduser < 0.0)
		options->per_source_penalty.penalty_invaliduser = 5.0;
	എങ്കിൽ (options->per_source_penalty.penalty_noauth < 0.0)
		options->per_source_penalty.penalty_noauth = 1.0;
	എങ്കിൽ (options->per_source_penalty.penalty_refuseconnection < 0.0)
		options->per_source_penalty.penalty_refuseconnection = 10.0;
	എങ്കിൽ (options->per_source_penalty.penalty_min < 0.0)
		options->per_source_penalty.penalty_min = 15.0;
	എങ്കിൽ (options->per_source_penalty.penalty_max < 0.0)
		options->per_source_penalty.penalty_max = 600.0;
	എങ്കിൽ (options->അക്കം_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_താക്കോലുകൾ_files,
		    &options->അക്കം_authkeys_files,
		    PATH_SSH_USER_PERMITTED_താക്കോലുകൾ);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_താക്കോലുകൾ_files,
		    &options->അക്കം_authkeys_files,
		    _PATH_SSH_USER_PERMITTED_KEYS2);
	}
	എങ്കിൽ (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	എങ്കിൽ (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	എങ്കിൽ (options->version_addendum == ശൂന്യ)
		options->version_addendum = xstrdup("");
	എങ്കിൽ (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	എങ്കിൽ (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	എങ്കിൽ (options->sk_provider == ശൂന്യ)
		options->sk_provider = xstrdup("internal");
	എങ്കിൽ (options->sshd_session_path == ശൂന്യ)
		options->sshd_session_path = xstrdup(_PATH_SSHD_SESSION);
	എങ്കിൽ (options->sshd_auth_path == ശൂന്യ)
		options->sshd_auth_path = xstrdup(_PATH_SSHD_AUTH);
	എങ്കിൽ (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	എങ്കിൽ (options->agent_socket_path == ശൂന്യ)
		options->agent_socket_path = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#define CLEAR_ON_NONE(v) \
	ചെയ്യുക { \
		എങ്കിൽ (option_clear_or_none(v)) { \
			സ്വതന്ത്രം(v); \
			v = ശൂന്യ; \
		} \
	} ആകുമ്പോൾ(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	ചെയ്യുക { \
		എങ്കിൽ (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			സ്വതന്ത്രം(options->v[0]); \
			സ്വതന്ത്രം(options->v); \
			options->v = ശൂന്യ; \
			options->nv = 0; \
		} \
	} ആകുമ്പോൾ (0)
	CLEAR_ON_NONE(options->pid_file);
	CLEAR_ON_NONE(options->xauth_location);
	CLEAR_ON_NONE(options->banner);
	CLEAR_ON_NONE(options->trusted_user_ca_താക്കോലുകൾ);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_താക്കോൽ_agent);
	CLEAR_ON_NONE(options->per_source_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_path);

	വേണ്ടി (i = 0; i < options->അക്കം_host_താക്കോൽ_files; i++)
		CLEAR_ON_NONE(options->host_താക്കോൽ_files[i]);
	വേണ്ടി (i = 0; i < options->അക്കം_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, അക്കം_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, അക്കം_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_താക്കോലുകൾ_files, അക്കം_revoked_താക്കോലുകൾ_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_താക്കോലുകൾ_files, അക്കം_authkeys_files, "none");
#undef CLEAR_ON_NONE
#undef CLEAR_ON_NONE_ARRAY
}

/* Macros to declare ServerOpCodes enum values */
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	s##conf,
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	s##conf,
#define SSHCONF_STRING(var, conf, flags, cp)		s##conf,
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	s##conf,
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	s##conf,
#define SSHCONF_NONCONF(funcsuffix)			/* empty */
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/* empty */
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/* empty */
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

/* Keyword tokens. */
തരനിർവചനം എണ്ണൽ {
	sBadOption,		/* == unknown option */
	SSHD_CONFIG_ENTRIES
	sMatch, sInclude,
	sDeprecated, sIgnore, sUnsupported
} ServerOpCodes;
#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

#define SSHCFG_GLOBAL		0x01	/* allowed in main section of config */
#define SSHCFG_MATCH		0x02	/* allowed inside a Match section */
#define SSHCFG_ALL		(SSHCFG_GLOBAL|SSHCFG_MATCH)
#define SSHCFG_NEVERMATCH	0x04  /* Match never matches; internal only */
#define SSHCFG_MATCH_ONLY	0x08  /* Match only in conditional blocks; internal only */

/* Macros to define keywords[] entries */
#define SSHCONF_KW(conf, flags)		{ #conf, s##conf, flags },
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	SSHCONF_KW(conf, flags)
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	SSHCONF_KW(conf, flags)
#define SSHCONF_STRING(var, conf, flags, cp)		SSHCONF_KW(conf, flags)
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	SSHCONF_KW(conf, flags)
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	SSHCONF_KW(conf, flags)
#define SSHCONF_NONCONF(funcsuffix)			/* empty */
#define SSHCONF_DEPRECATED				sDeprecated
#define SSHCONF_IGNORE					sIgnore
#define SSHCONF_DEPRECATE(conf, flags, opcode) \
	{ #conf, opcode, flags },
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#define SSHCONF_ALIAS(old, conf, flags) \
	{ #old, s##conf, flags },

/* Textual representation of the tokens. */
സ്ഥിതം ഘടന {
	സ്ഥിരം അക്ഷരം *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", sMatch, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ ശൂന്യ, sBadOption, 0 }
};
#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATED
#undef SSHCONF_IGNORE
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

സ്ഥിതം ഘടന {
	പൂർണ്ണസംഖ്യ val;
	അക്ഷരം *text;
} tunmode_desc[] = {
	{ SSH_TUNMODE_NO, "no" },
	{ SSH_TUNMODE_POINTOPOINT, "point-to-point" },
	{ SSH_TUNMODE_ETHERNET, "ethernet" },
	{ SSH_TUNMODE_YES, "yes" },
	{ -1, ശൂന്യ }
};

/* Returns an opcode name from its number */

സ്ഥിതം സ്ഥിരം അക്ഷരം *
lookup_opcode_name(ServerOpCodes code)
{
	u_int i;

	വേണ്ടി (i = 0; keywords[i].name != ശൂന്യ; i++)
		എങ്കിൽ (keywords[i].opcode == code)
			തിരികെ(keywords[i].name);
	തിരികെ "UNKNOWN";
}


/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

സ്ഥിതം ServerOpCodes
parse_token(സ്ഥിരം അക്ഷരം *cp, സ്ഥിരം അക്ഷരം *filename,
	    പൂർണ്ണസംഖ്യ linenum, u_int *flags)
{
	u_int i;

	വേണ്ടി (i = 0; keywords[i].name; i++)
		എങ്കിൽ (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			തിരികെ keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	തിരികെ sBadOption;
}

അക്ഷരം *
derelativise_path(സ്ഥിരം അക്ഷരം *path)
{
	അക്ഷരം *expanded, *ret, cwd[PATH_MAX];

	എങ്കിൽ (strcasecmp(path, "none") == 0)
		തിരികെ xstrdup("none");
	expanded = tilde_expand_filename(path, getuid());
	എങ്കിൽ (path_absolute(expanded))
		തിരികെ expanded;
	എങ്കിൽ (getcwd(cwd, വലുപ്പം(cwd)) == ശൂന്യ)
		fatal_f("getcwd: %s", strerror(errno));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	സ്വതന്ത്രം(expanded);
	തിരികെ ret;
}

സ്ഥിതം ശൂന്യം
add_listen_addr(ServerOptions *options, സ്ഥിരം അക്ഷരം *addr,
    സ്ഥിരം അക്ഷരം *rdomain, പൂർണ്ണസംഖ്യ port)
{
	u_int i;

	എങ്കിൽ (port > 0)
		add_one_listen_addr(options, addr, rdomain, port);
	അല്ലെങ്കിൽ {
		വേണ്ടി (i = 0; i < options->അക്കം_ports; i++) {
			add_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

സ്ഥിതം ശൂന്യം
add_one_listen_addr(ServerOptions *options, സ്ഥിരം അക്ഷരം *addr,
    സ്ഥിരം അക്ഷരം *rdomain, പൂർണ്ണസംഖ്യ port)
{
	ഘടന addrinfo hints, *ai, *aitop;
	അക്ഷരം strport[NI_MAXSERV];
	പൂർണ്ണസംഖ്യ gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	വേണ്ടി (i = 0; i < options->അക്കം_listen_addrs; i++) {
		എങ്കിൽ (rdomain == ശൂന്യ && options->listen_addrs[i].rdomain == ശൂന്യ)
			നിർത്തുക;
		എങ്കിൽ (rdomain == ശൂന്യ || options->listen_addrs[i].rdomain == ശൂന്യ)
			തുടരുക;
		എങ്കിൽ (strcmp(rdomain, options->listen_addrs[i].rdomain) == 0)
			നിർത്തുക;
	}
	എങ്കിൽ (i >= options->അക്കം_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		എങ്കിൽ (i >= INT_MAX)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->അക്കം_listen_addrs, options->അക്കം_listen_addrs + 1,
		    വലുപ്പം(*options->listen_addrs));
		i = options->അക്കം_listen_addrs++;
		എങ്കിൽ (rdomain != ശൂന്യ)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	memset(&hints, 0, വലുപ്പം(hints));
	hints.ai_family = options->address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == ശൂന്യ) ? AI_PASSIVE : 0;
	snprintf(strport, വലുപ്പം strport, "%d", port);
	എങ്കിൽ ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    ssh_gai_strerror(gaierr));
	വേണ്ടി (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs[i].addrs;
	options->listen_addrs[i].addrs = aitop;
}

/* Returns nonzero if the routing domain name is valid */
സ്ഥിതം പൂർണ്ണസംഖ്യ
valid_rdomain(സ്ഥിരം അക്ഷരം *name)
{
#എങ്കിൽ defined(HAVE_SYS_VALID_RDOMAIN)
	തിരികെ sys_valid_rdomain(name);
#അല്ലെങ്കിലെങ്കിൽ defined(__OpenBSD__)
	സ്ഥിരം അക്ഷരം *errstr;
	long long അക്കം;
	ഘടന rt_tableinfo info;
	പൂർണ്ണസംഖ്യ mib[6];
	size_t miblen = വലുപ്പം(mib);

	എങ്കിൽ (name == ശൂന്യ)
		തിരികെ 1;

	അക്കം = strtonum(name, 0, 255, &errstr);
	എങ്കിൽ (errstr != ശൂന്യ)
		തിരികെ 0;

	/* Check whether the table actually exists */
	memset(mib, 0, വലുപ്പം(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_TABLE;
	mib[5] = (പൂർണ്ണസംഖ്യ)അക്കം;
	എങ്കിൽ (sysctl(mib, 6, &info, &miblen, ശൂന്യ, 0) == -1)
		തിരികെ 0;

	തിരികെ 1;
#അല്ലെങ്കിൽ /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	തിരികെ 0;
#endif
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
സ്ഥിതം ശൂന്യം
queue_listen_addr(ServerOptions *options, സ്ഥിരം അക്ഷരം *addr,
    സ്ഥിരം അക്ഷരം *rdomain, പൂർണ്ണസംഖ്യ port)
{
	ഘടന queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->അക്കം_queued_listens, options->അക്കം_queued_listens + 1,
	    വലുപ്പം(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->അക്കം_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->port = port;
	qla->rdomain = rdomain == ശൂന്യ ? ശൂന്യ : xstrdup(rdomain);
}

/*
 * Process queued (text) ListenAddress entries.
 */
സ്ഥിതം ശൂന്യം
process_queued_listen_addrs(ServerOptions *options)
{
	u_int i;
	ഘടന queued_listenaddr *qla;

	എങ്കിൽ (options->അക്കം_ports == 0)
		options->ports[options->അക്കം_ports++] = SSH_DEFAULT_PORT;
	എങ്കിൽ (options->address_family == -1)
		options->address_family = AF_UNSPEC;

	വേണ്ടി (i = 0; i < options->അക്കം_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		add_listen_addr(options, qla->addr, qla->rdomain, qla->port);
		സ്വതന്ത്രം(qla->addr);
		സ്വതന്ത്രം(qla->rdomain);
	}
	സ്വതന്ത്രം(options->queued_listen_addrs);
	options->queued_listen_addrs = ശൂന്യ;
	options->അക്കം_queued_listens = 0;
}

/*
 * The strategy for the Match blocks is that the config file is parsed twice.
 *
 * The first time is at startup.  activep is initialized to 1 and the
 * directives in the global context are processed and acted on.  Hitting a
 * Match directive unsets activep and the directives inside the block are
 * checked for syntax only.
 *
 * The second time is after a connection has been established but before
 * authentication.  activep is initialized to 2 and global config directives
 * are ignored since they have already been processed.  If the criteria in a
 * Match block is met, activep is set and the subsequent directives
 * processed and actioned until EOF or another Match block unsets it.  Any
 * options set are copied into the main server config.
 *
 * Potential additions/improvements:
 *  - Add Match support for pre-kex directives, eg. Ciphers.
 *
 *  - Add a Tag directive (idea from David Leonard) ala pf, eg:
 *	Match Address 192.168.0.*
 *		Tag trusted
 *	Match Group wheel
 *		Tag trusted
 *	Match Tag trusted
 *		AllowTcpForwarding yes
 *		GatewayPorts clientspecified
 *		[...]
 *
 *  - Add a PermittedChannelRequests directive
 *	Match Group shell
 *		PermittedChannelRequests session,forwarded-tcpip
 */

സ്ഥിതം പൂർണ്ണസംഖ്യ
match_cfg_വരി_group(സ്ഥിരം അക്ഷരം *grps, പൂർണ്ണസംഖ്യ വരി, സ്ഥിരം അക്ഷരം *user)
{
	പൂർണ്ണസംഖ്യ result = 0;
	ഘടന passwd *pw;

	എങ്കിൽ (user == ശൂന്യ)
		പോകുക out;

	എങ്കിൽ ((pw = getpwnam(user)) == ശൂന്യ) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", വരി, user);
	} അല്ലെങ്കിൽ എങ്കിൽ (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, വരി);
	} അല്ലെങ്കിൽ എങ്കിൽ (ga_match_pattern_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, വരി);
	} അല്ലെങ്കിൽ {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, വരി);
		result = 1;
	}
out:
	ga_free();
	തിരികെ result;
}

സ്ഥിതം ശൂന്യം
match_test_missing_fatal(സ്ഥിരം അക്ഷരം *criteria, സ്ഥിരം അക്ഷരം *attrib)
{
	fatal("'Match %s' in configuration but '%s' not in connection "
	    "test specification.", criteria, attrib);
}

/*
 * All of the attributes on a single Match line are ANDed together, so we need
 * to check every attribute and set the result to zero if any attribute does
 * not match.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
match_cfg_വരി(സ്ഥിരം അക്ഷരം *full_വരി, പൂർണ്ണസംഖ്യ *acp, അക്ഷരം ***avp,
    പൂർണ്ണസംഖ്യ വരി, ഘടന connection_info *ci)
{
	പൂർണ്ണസംഖ്യ result = 1, attributes = 0, port;
	അക്ഷരം *arg, *attrib = ശൂന്യ, *oattrib;

	എങ്കിൽ (ci == ശൂന്യ) {
		debug3("checking syntax for 'Match %s' on line %d",
		    full_വരി, വരി);
	} അല്ലെങ്കിൽ {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", full_വരി,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->address ? ci->address : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", വരി);
	}

	ആകുമ്പോൾ ((oattrib = argv_next(acp, avp)) != ശൂന്യ) {
		/* Terminate on comment */
		എങ്കിൽ (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			നിർത്തുക;
		}
		attrib = xstrdup(oattrib);
		arg = ശൂന്യ;
		attributes++;
		/* Criterion "all" has no argument and must appear alone */
		എങ്കിൽ (strcasecmp(attrib, "all") == 0) {
			എങ്കിൽ (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != ശൂന്യ &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				result = -1;
				പോകുക out;
			}
			എങ്കിൽ (arg != ശൂന്യ && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			result = 1;
			പോകുക out;
		}
		/* Criterion "invalid-user" also has no argument */
		എങ്കിൽ (strcasecmp(attrib, "invalid-user") == 0) {
			എങ്കിൽ (ci == ശൂന്യ) {
				result = 0;
				പോകുക next;
			}
			എങ്കിൽ (ci->user_invalid == 0)
				result = 0;
			അല്ലെങ്കിൽ
				debug("matched invalid-user at line %d", വരി);
			പോകുക next;
		}

		/* Keep this list in sync with below */
		എങ്കിൽ (strprefix(attrib, "user=", 1) != ശൂന്യ ||
		    strprefix(attrib, "group=", 1) != ശൂന്യ ||
		    strprefix(attrib, "host=", 1) != ശൂന്യ ||
		    strprefix(attrib, "address=", 1) != ശൂന്യ ||
		    strprefix(attrib, "localaddress=", 1) != ശൂന്യ ||
		    strprefix(attrib, "localport=", 1) != ശൂന്യ ||
		    strprefix(attrib, "rdomain=", 1) != ശൂന്യ ||
		    strprefix(attrib, "version=", 1) != ശൂന്യ) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} അല്ലെങ്കിൽ {
			arg = argv_next(acp, avp);
		}

		/* All other criteria require an argument */
		എങ്കിൽ (arg == ശൂന്യ || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			പോകുക out;
		}
		എങ്കിൽ (strcasecmp(attrib, "user") == 0) {
			എങ്കിൽ (ci == ശൂന്യ || (ci->test && ci->user == ശൂന്യ)) {
				result = 0;
				പോകുക next;
			}
			എങ്കിൽ (ci->user == ശൂന്യ)
				match_test_missing_fatal("User", "user");
			എങ്കിൽ (match_usergroup_pattern_list(ci->user, arg) != 1)
				result = 0;
			അല്ലെങ്കിൽ
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, വരി);
		} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(attrib, "group") == 0) {
			എങ്കിൽ (ci == ശൂന്യ || (ci->test && ci->user == ശൂന്യ)) {
				result = 0;
				പോകുക next;
			}
			എങ്കിൽ (ci->user == ശൂന്യ)
				match_test_missing_fatal("Group", "user");
			തിരഞ്ഞെടുപ്പ് (match_cfg_വരി_group(arg, വരി, ci->user)) {
			അവസ്ഥ -1:
				result = -1;
				പോകുക out;
			അവസ്ഥ 0:
				result = 0;
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(attrib, "host") == 0) {
			എങ്കിൽ (ci == ശൂന്യ || (ci->test && ci->host == ശൂന്യ)) {
				result = 0;
				പോകുക next;
			}
			എങ്കിൽ (ci->host == ശൂന്യ)
				match_test_missing_fatal("Host", "host");
			എങ്കിൽ (match_hostname(ci->host, arg) != 1)
				result = 0;
			അല്ലെങ്കിൽ
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, വരി);
		} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(attrib, "address") == 0) {
			എങ്കിൽ (ci == ശൂന്യ || (ci->test && ci->address == ശൂന്യ)) {
				എങ്കിൽ (addr_match_list(ശൂന്യ, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, വരി);
				result = 0;
				പോകുക next;
			}
			എങ്കിൽ (ci->address == ശൂന്യ)
				match_test_missing_fatal("Address", "addr");
			തിരഞ്ഞെടുപ്പ് (addr_match_list(ci->address, arg)) {
			അവസ്ഥ 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->address, arg, വരി);
				നിർത്തുക;
			അവസ്ഥ 0:
			അവസ്ഥ -1:
				result = 0;
				നിർത്തുക;
			അവസ്ഥ -2:
				result = -1;
				പോകുക out;
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(attrib, "localaddress") == 0){
			എങ്കിൽ (ci == ശൂന്യ || (ci->test && ci->laddress == ശൂന്യ)) {
				എങ്കിൽ (addr_match_list(ശൂന്യ, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    വരി);
				result = 0;
				പോകുക next;
			}
			എങ്കിൽ (ci->laddress == ശൂന്യ)
				match_test_missing_fatal("LocalAddress",
				    "laddr");
			തിരഞ്ഞെടുപ്പ് (addr_match_list(ci->laddress, arg)) {
			അവസ്ഥ 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, വരി);
				നിർത്തുക;
			അവസ്ഥ 0:
			അവസ്ഥ -1:
				result = 0;
				നിർത്തുക;
			അവസ്ഥ -2:
				result = -1;
				പോകുക out;
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(attrib, "localport") == 0) {
			എങ്കിൽ ((port = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				result = -1;
				പോകുക out;
			}
			എങ്കിൽ (ci == ശൂന്യ || (ci->test && ci->lport == -1)) {
				result = 0;
				പോകുക next;
			}
			എങ്കിൽ (ci->lport == 0)
				match_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			എങ്കിൽ (port == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, port, വരി);
			അല്ലെങ്കിൽ
				result = 0;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(attrib, "rdomain") == 0) {
			എങ്കിൽ (ci == ശൂന്യ || (ci->test && ci->rdomain == ശൂന്യ)) {
				result = 0;
				പോകുക next;
			}
			എങ്കിൽ (ci->rdomain == ശൂന്യ)
				match_test_missing_fatal("RDomain", "rdomain");
			എങ്കിൽ (match_pattern_list(ci->rdomain, arg, 0) != 1)
				result = 0;
			അല്ലെങ്കിൽ
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, വരി);
		} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(attrib, "version") == 0) {
			എങ്കിൽ (match_pattern_list(SSH_RELEASE, arg, 0) != 1)
				result = 0;
			അല്ലെങ്കിൽ
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, വരി);
		} അല്ലെങ്കിൽ {
			error("Unsupported Match attribute %s", oattrib);
			result = -1;
			പോകുക out;
		}
 next:
		സ്വതന്ത്രം(attrib);
		attrib = ശൂന്യ;
	}
	എങ്കിൽ (attributes == 0) {
		error("One or more attributes required for Match");
		തിരികെ -1;
	}
 out:
	എങ്കിൽ (ci != ശൂന്യ && result != -1)
		debug3("match %sfound on line %d", result ? "" : "not ", വരി);
	സ്വതന്ത്രം(attrib);
	തിരികെ result;
}

#define WHITESPACE " \t\r\n"

/* Multistate option parsing */
ഘടന multistate {
	അക്ഷരം *താക്കോൽ;
	പൂർണ്ണസംഖ്യ മൂല്യം;
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ ശൂന്യ, -1 }
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_ignore_rhosts[] = {
	{ "yes",			IGNORE_RHOSTS_YES },
	{ "no",				IGNORE_RHOSTS_NO },
	{ "shosts-only",		IGNORE_RHOSTS_SHOSTS },
	{ ശൂന്യ, -1 }
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ ശൂന്യ, -1 }
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_permitrootlogin[] = {
	{ "prohibit-password",		PERMIT_NO_PASSWD },
	{ "without-password",		PERMIT_NO_PASSWD },
	{ "forced-commands-only",	PERMIT_FORCED_ONLY },
	{ "yes",			PERMIT_YES },
	{ "no",				PERMIT_NO },
	{ ശൂന്യ, -1 }
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ ശൂന്യ, -1 }
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_gatewayports[] = {
	{ "clientspecified",		2 },
	{ "yes",			1 },
	{ "no",				0 },
	{ ശൂന്യ, -1 }
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_tcpfwd[] = {
	{ "yes",			FORWARD_ALLOW },
	{ "all",			FORWARD_ALLOW },
	{ "no",				FORWARD_DENY },
	{ "remote",			FORWARD_REMOTE },
	{ "local",			FORWARD_LOCAL },
	{ ശൂന്യ, -1 }
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ ശൂന്യ, -1 }
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ ശൂന്യ, -1 }
};

സ്ഥിതം പൂർണ്ണസംഖ്യ
process_server_config_വരി_depth(ServerOptions *options, അക്ഷരം *വരി,
    സ്ഥിരം അക്ഷരം *filename, പൂർണ്ണസംഖ്യ linenum, പൂർണ്ണസംഖ്യ *activep,
    ഘടന connection_info *connectinfo, പൂർണ്ണസംഖ്യ *inc_flags, പൂർണ്ണസംഖ്യ depth,
    ഘടന include_list *includes)
{
	അക്ഷരം *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	പൂർണ്ണസംഖ്യ cmdline = 0, *intptr, മൂല്യം, value2, value3, n, port, oactive, r;
	ഇരട്ട dvalue, *doubleptr = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ca_only = 0, found = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	size_t len;
	long long val64;
	സ്ഥിരം ഘടന multistate *multistate_ptr;
	സ്ഥിരം അക്ഷരം *errstr;
	ഘടന include_item *item;
	glob_t gbuf;
	അക്ഷരം **oav = ശൂന്യ, **av;
	പൂർണ്ണസംഖ്യ oac = 0, ac;
	പൂർണ്ണസംഖ്യ ret = -1;
	അക്ഷരം **strs = ശൂന്യ; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	എങ്കിൽ ((len = strlen(വരി)) == 0)
		തിരികെ 0;
	വേണ്ടി (len--; len > 0; len--) {
		എങ്കിൽ (strchr(WHITESPACE "\f", വരി[len]) == ശൂന്യ)
			നിർത്തുക;
		വരി[len] = '\0';
	}

	str = വരി;
	എങ്കിൽ ((keyword = strdelim(&str)) == ശൂന്യ)
		തിരികെ 0;
	/* Ignore leading whitespace */
	എങ്കിൽ (*keyword == '\0')
		keyword = strdelim(&str);
	എങ്കിൽ (!keyword || !*keyword || *keyword == '#')
		തിരികെ 0;
	എങ്കിൽ (str == ശൂന്യ || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		തിരികെ -1;
	}
	intptr = ശൂന്യ;
	charptr = ശൂന്യ;
	opcode = parse_token(keyword, filename, linenum, &flags);

	എങ്കിൽ (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		തിരികെ -1;
	}
	ac = oac;
	av = oav;

	എങ്കിൽ (activep == ശൂന്യ) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	എങ്കിൽ (*activep && opcode != sMatch && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	എങ്കിൽ (*activep == 0 && !(flags & SSHCFG_MATCH)) {
		എങ്കിൽ (connectinfo == ശൂന്യ) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} അല്ലെങ്കിൽ { /* this is a directive we have already processed */
			ret = 0;
			പോകുക out;
		}
	}

	തിരഞ്ഞെടുപ്പ് (opcode) {
	/* Portable-specific options */
#ifdef USE_PAM
	അവസ്ഥ sUsePAM:
		intptr = &options->use_pam;
		പോകുക parse_flag;
	അവസ്ഥ sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		എങ്കിൽ (*activep && *charptr == ശൂന്യ)
			*charptr = xstrdup(arg);
		നിർത്തുക;
#endif

	/* Standard Options */
	അവസ്ഥ sBadOption:
		പോകുക out;
	അവസ്ഥ sPort:
		/* ignore ports from configfile if cmdline specifies ports */
		എങ്കിൽ (options->ports_from_cmdline) {
			argv_consume(&ac);
			നിർത്തുക;
		}
		എങ്കിൽ (options->അക്കം_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->അക്കം_ports++] = a2port(arg);
		എങ്കിൽ (options->ports[options->അക്കം_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		നിർത്തുക;

	അവസ്ഥ sLoginGraceTime:
		intptr = &options->login_grace_time;
 parse_time:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		എങ്കിൽ ((മൂല്യം = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		എങ്കിൽ (*activep && *intptr == -1)
			*intptr = മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ sListenAddress:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (arg == ശൂന്യ || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		എങ്കിൽ (strchr(arg, '[') == ശൂന്യ && (p = strchr(arg, ':')) != ശൂന്യ
		    && strchr(p+1, ':') != ശൂന്യ) {
			port = 0;
			p = arg;
		} അല്ലെങ്കിൽ {
			arg2 = ശൂന്യ;
			p = hpdelim(&arg);
			എങ്കിൽ (p == ശൂന്യ)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			എങ്കിൽ (arg == ശൂന്യ)
				port = 0;
			അല്ലെങ്കിൽ എങ്കിൽ ((port = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = ശൂന്യ;
		എങ്കിൽ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			എങ്കിൽ (strcmp(arg, "rdomain") != 0 ||
			    (arg2 = argv_next(&ac, &av)) == ശൂന്യ)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			എങ്കിൽ (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		queue_listen_addr(options, p, arg2, port);

		നിർത്തുക;

	അവസ്ഥ sAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		മൂല്യം = -1;
		വേണ്ടി (i = 0; multistate_ptr[i].താക്കോൽ != ശൂന്യ; i++) {
			എങ്കിൽ (strcasecmp(arg, multistate_ptr[i].താക്കോൽ) == 0) {
				മൂല്യം = multistate_ptr[i].മൂല്യം;
				നിർത്തുക;
			}
		}
		എങ്കിൽ (മൂല്യം == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		എങ്കിൽ (*activep && *intptr == -1)
			*intptr = മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ s_Host_താക്കോൽ:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		എങ്കിൽ (*activep) {
			servconf_add_hostkey(filename, linenum,
			    options, arg, 1);
		}
		നിർത്തുക;

	അവസ്ഥ s_Host_താക്കോൽ_Agent:
		charptr = &options->host_താക്കോൽ_agent;
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		എങ്കിൽ (*activep && *charptr == ശൂന്യ)
			*charptr = !strcmp(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_path(arg);
		നിർത്തുക;

	അവസ്ഥ sHostCertificate:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		എങ്കിൽ (*activep)
			servconf_add_hostcert(filename, linenum, options, arg);
		നിർത്തുക;

	അവസ്ഥ sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		എങ്കിൽ (*activep && *charptr == ശൂന്യ) {
			*charptr = derelativise_path(arg);
			/* increase optional counter */
			എങ്കിൽ (intptr != ശൂന്യ)
				*intptr = *intptr + 1;
		}
		നിർത്തുക;

	അവസ്ഥ sModuliFile:
		charptr = &options->moduli_file;
		പോകുക parse_filename;

	അവസ്ഥ s_Permit_വേര്_Login:
		intptr = &options->permit_വേര്_login;
		multistate_ptr = multistate_permitrootlogin;
		പോകുക parse_multistate;

	അവസ്ഥ sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
		multistate_ptr = multistate_ignore_rhosts;
		പോകുക parse_multistate;

	അവസ്ഥ sIgnoreUserKnownHosts:
		intptr = &options->ignore_user_known_hosts;
 parse_flag:
		multistate_ptr = multistate_flag;
		പോകുക parse_multistate;

	അവസ്ഥ sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		പോകുക parse_flag;

	അവസ്ഥ sHostbasedUsesNameFromPacketOnly:
		intptr = &options->hostbased_uses_name_from_packet_only;
		പോകുക parse_flag;

	അവസ്ഥ sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		എങ്കിൽ (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		എങ്കിൽ (*activep && *charptr == ശൂന്യ)
			*charptr = xstrdup(arg);
		നിർത്തുക;

	അവസ്ഥ s_Host_താക്കോൽ_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
		പോകുക parse_pubkey_algos;

	അവസ്ഥ sCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		പോകുക parse_pubkey_algos;

	അവസ്ഥ sPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		ca_only = 0;
		പോകുക parse_flag;

	അവസ്ഥ sPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		പോകുക parse_pubkey_algos;

	അവസ്ഥ sPubkeyAuthOptions:
		intptr = &options->pubkey_auth_options;
		മൂല്യം = 0;
		value2 = -1;
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			എങ്കിൽ (strcasecmp(arg, "none") == 0)
				തുടരുക;
			എങ്കിൽ (strcasecmp(arg, "touch-required") == 0)
				മൂല്യം |= PUBKEYAUTH_TOUCH_REQUIRED;
			അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(arg, "verify-required") == 0)
				മൂല്യം |= PUBKEYAUTH_VERIFY_REQUIRED;
			അല്ലെങ്കിൽ എങ്കിൽ (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				എങ്കിൽ (errstr != ശൂന്യ) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					പോകുക out;
				}
			} അല്ലെങ്കിൽ {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				പോകുക out;
			}
		}
		എങ്കിൽ (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = മൂല്യം;
			options->max_pubkey_ok = value2;
		}
		നിർത്തുക;

#ifdef KRB5
	അവസ്ഥ sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		പോകുക parse_flag;

	അവസ്ഥ sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		പോകുക parse_flag;

	അവസ്ഥ sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		പോകുക parse_flag;
#ifdef USE_AFS
	അവസ്ഥ sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		പോകുക parse_flag;
#endif /* USE_AFS */
#endif /* KRB5 */

#ifdef GSSAPI
	അവസ്ഥ sGSSAPIAuthentication:
		intptr = &options->gss_authentication;
		പോകുക parse_flag;

	അവസ്ഥ sGSSAPICleanupCredentials:
		intptr = &options->gss_cleanup_creds;
		പോകുക parse_flag;

	അവസ്ഥ sGSSAPIDelegateCredentials:
		intptr = &options->gss_deleg_creds;
		പോകുക parse_flag;

	അവസ്ഥ sGSSAPIStrictAcceptorCheck:
		intptr = &options->gss_strict_acceptor;
		പോകുക parse_flag;
#endif /* GSSAPI */

	അവസ്ഥ sPasswordAuthentication:
		intptr = &options->password_authentication;
		പോകുക parse_flag;

	അവസ്ഥ sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		പോകുക parse_flag;

	അവസ്ഥ sPrintMotd:
		intptr = &options->print_motd;
		പോകുക parse_flag;

#ifndef DISABLE_LASTLOG
	അവസ്ഥ sPrintLastLog:
		intptr = &options->print_lastlog;
		പോകുക parse_flag;
#endif

	അവസ്ഥ sX11Forwarding:
		intptr = &options->x11_forwarding;
		പോകുക parse_flag;

	അവസ്ഥ sX11DisplayOffset:
		intptr = &options->x11_display_offset;
 parse_int:
		arg = argv_next(&ac, &av);
		എങ്കിൽ ((errstr = atoi_err(arg, &മൂല്യം)) != ശൂന്യ)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		എങ്കിൽ (*activep && *intptr == -1)
			*intptr = മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ sX11UseLocalhost:
		intptr = &options->x11_use_localhost;
		പോകുക parse_flag;

	അവസ്ഥ sXAuthLocation:
		charptr = &options->xauth_location;
		പോകുക parse_filename;

	അവസ്ഥ sPermitTTY:
		intptr = &options->permit_tty;
		പോകുക parse_flag;

	അവസ്ഥ sPermitUserRC:
		intptr = &options->permit_user_rc;
		പോകുക parse_flag;

	അവസ്ഥ sStrictModes:
		intptr = &options->strict_modes;
		പോകുക parse_flag;

	അവസ്ഥ sTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		പോകുക parse_multistate;

	അവസ്ഥ sPermitEmptyPasswords:
		intptr = &options->permit_empty_passwd;
		പോകുക parse_flag;

	അവസ്ഥ sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		മൂല്യം = 0;
		p = ശൂന്യ;
		എങ്കിൽ (strcmp(arg, "yes") == 0)
			മൂല്യം = 1;
		അല്ലെങ്കിൽ എങ്കിൽ (strcmp(arg, "no") == 0)
			മൂല്യം = 0;
		അല്ലെങ്കിൽ {
			/* Pattern-list specified */
			മൂല്യം = 1;
			p = xstrdup(arg);
		}
		എങ്കിൽ (*activep && *intptr == -1) {
			*intptr = മൂല്യം;
			*charptr = p;
			p = ശൂന്യ;
		}
		സ്വതന്ത്രം(p);
		നിർത്തുക;

	അവസ്ഥ sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		പോകുക parse_multistate;

	അവസ്ഥ sRekeyLimit:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		എങ്കിൽ (strcmp(arg, "default") == 0) {
			val64 = 0;
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (scan_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, strerror(errno));
			എങ്കിൽ (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		എങ്കിൽ (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		എങ്കിൽ (ac != 0) { /* optional rekey interval present */
			എങ്കിൽ (strcmp(av[0], "none") == 0) {
				(ശൂന്യം)argv_next(&ac, &av);	/* discard */
				നിർത്തുക;
			}
			intptr = &options->rekey_interval;
			പോകുക parse_time;
		}
		നിർത്തുക;

	അവസ്ഥ sGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		multistate_ptr = multistate_gatewayports;
		പോകുക parse_multistate;

	അവസ്ഥ sUseDNS:
		intptr = &options->use_dns;
		പോകുക parse_flag;

	അവസ്ഥ sSyslogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		മൂല്യം = log_facility_സംഖ്യ(arg);
		എങ്കിൽ (മൂല്യം == SYSLOG_FACILITY_NOT_SET)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		എങ്കിൽ (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		മൂല്യം = log_level_സംഖ്യ(arg);
		എങ്കിൽ (മൂല്യം == SYSLOG_LEVEL_NOT_SET)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		എങ്കിൽ (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ sLogVerbose:
		found = options->അക്കം_log_verbose == 0;
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			എങ്കിൽ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				പോകുക out;
			}
			/* Allow "none" only in first position */
			എങ്കിൽ (strcasecmp(arg, "none") == 0) {
				എങ്കിൽ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					പോകുക out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		എങ്കിൽ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		എങ്കിൽ (found && *activep) {
			options->log_verbose = strs;
			options->അക്കം_log_verbose = nstrs;
			strs = ശൂന്യ; /* transferred */
			nstrs = 0;
		}
		നിർത്തുക;

	അവസ്ഥ sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		പോകുക parse_multistate;

	അവസ്ഥ sAllowStreamLocalForwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		പോകുക parse_multistate;

	അവസ്ഥ sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		പോകുക parse_flag;

	അവസ്ഥ sAgentSocketPath:
		charptr = &options->agent_socket_path;
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		എങ്കിൽ (strncmp(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			എങ്കിൽ (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (strncmp(arg, "user:", 5) == 0) {
			/* User paths must not be empty */
			എങ്കിൽ (arg[5] == '\0') {
				fatal("%s line %d: invalid user path.",
				    filename, linenum);
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(arg, "none") != 0)
			fatal("%s line %d: invalid path.", filename, linenum);
		എങ്കിൽ (*activep && *charptr == ശൂന്യ)
			*charptr = xstrdup(arg);
		നിർത്തുക;

	അവസ്ഥ sDisableForwarding:
		intptr = &options->disable_forwarding;
		പോകുക parse_flag;

	അവസ്ഥ sAllowUsers:
		chararrayptr = &options->allow_users;
		uintptr = &options->അക്കം_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			എങ്കിൽ (*arg == '\0' ||
			    match_user(ശൂന്യ, ശൂന്യ, ശൂന്യ, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			found = 1;
			എങ്കിൽ (!*activep)
				തുടരുക;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		എങ്കിൽ (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		നിർത്തുക;

	അവസ്ഥ sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->അക്കം_deny_users;
		പോകുക parse_allowdenyusers;

	അവസ്ഥ sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->അക്കം_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			എങ്കിൽ (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			found = 1;
			എങ്കിൽ (!*activep)
				തുടരുക;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		എങ്കിൽ (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		നിർത്തുക;

	അവസ്ഥ sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->അക്കം_deny_groups;
		പോകുക parse_allowdenygroups;

	അവസ്ഥ sCiphers:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		എങ്കിൽ (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		എങ്കിൽ (options->ciphers == ശൂന്യ)
			options->ciphers = xstrdup(arg);
		നിർത്തുക;

	അവസ്ഥ sMacs:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		എങ്കിൽ (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		എങ്കിൽ (options->macs == ശൂന്യ)
			options->macs = xstrdup(arg);
		നിർത്തുക;

	അവസ്ഥ sKexAlgorithms:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		എങ്കിൽ (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		എങ്കിൽ (options->kex_algorithms == ശൂന്യ)
			options->kex_algorithms = xstrdup(arg);
		നിർത്തുക;

	അവസ്ഥ sSubsystem:
		എങ്കിൽ ((arg = argv_next(&ac, &av)) == ശൂന്യ || *arg == '\0' ||
		   ((arg2 = argv_next(&ac, &av)) == ശൂന്യ || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		എങ്കിൽ (!*activep) {
			argv_consume(&ac);
			നിർത്തുക;
		}
		found = 0;
		വേണ്ടി (i = 0; i < options->അക്കം_subsystems; i++) {
			എങ്കിൽ (strcmp(arg, options->subsystem_name[i]) == 0) {
				found = 1;
				നിർത്തുക;
			}
		}
		എങ്കിൽ (found) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			നിർത്തുക;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->അക്കം_subsystems,
		    options->അക്കം_subsystems + 1,
		    വലുപ്പം(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->അക്കം_subsystems,
		    options->അക്കം_subsystems + 1,
		    വലുപ്പം(*options->subsystem_command));
		options->subsystem_args = xrecallocarray(
		    options->subsystem_args, options->അക്കം_subsystems,
		    options->അക്കം_subsystems + 1,
		    വലുപ്പം(*options->subsystem_args));
		options->subsystem_name[options->അക്കം_subsystems] = xstrdup(arg);
		options->subsystem_command[options->അക്കം_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_args[options->അക്കം_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		സ്വതന്ത്രം(arg2);
		സ്വതന്ത്രം(arg);
		argv_consume(&ac);
		options->അക്കം_subsystems++;
		നിർത്തുക;

	അവസ്ഥ sMaxStartups:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		എങ്കിൽ ((n = sscanf(arg, "%d:%d:%d",
		    &മൂല്യം, &value2, &value3)) == 3) {
			എങ്കിൽ (മൂല്യം > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} അല്ലെങ്കിൽ എങ്കിൽ (n == 1) {
			value3 = മൂല്യം;
			value2 = -1;
		} അല്ലെങ്കിൽ {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		എങ്കിൽ (മൂല്യം <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		എങ്കിൽ (*activep && options->max_startups == -1) {
			options->max_startups_begin = മൂല്യം;
			options->max_startups_rate = value2;
			options->max_startups = value3;
		}
		നിർത്തുക;

	അവസ്ഥ sPerSourceNetBlockSize:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		തിരഞ്ഞെടുപ്പ് (n = sscanf(arg, "%d:%d", &മൂല്യം, &value2)) {
		അവസ്ഥ 2:
			എങ്കിൽ (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		അവസ്ഥ 1:
			എങ്കിൽ (മൂല്യം < 0 || മൂല്യം > 32)
				n = -1;
		}
		എങ്കിൽ (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		എങ്കിൽ (*activep && options->per_source_masklen_ipv4 == -1) {
			options->per_source_masklen_ipv4 = മൂല്യം;
			എങ്കിൽ (n == 2)
				options->per_source_masklen_ipv6 = value2;
		}
		നിർത്തുക;

	അവസ്ഥ sPerSourceMaxStartups:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		എങ്കിൽ (strcmp(arg, "none") == 0) { /* no limit */
			മൂല്യം = INT_MAX;
		} അല്ലെങ്കിൽ {
			എങ്കിൽ ((errstr = atoi_err(arg, &മൂല്യം)) != ശൂന്യ)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		എങ്കിൽ (*activep && options->per_source_max_startups == -1)
			options->per_source_max_startups = മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ sPerSourcePenaltyExemptList:
		charptr = &options->per_source_penalty_exempt;
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		എങ്കിൽ (addr_match_list(ശൂന്യ, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		എങ്കിൽ (*activep && *charptr == ശൂന്യ)
			*charptr = xstrdup(arg);
		നിർത്തുക;

	അവസ്ഥ sPerSourcePenalties:
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			സ്ഥിരം അക്ഷരം *q = ശൂന്യ;

			found = 1;
			intptr = ശൂന്യ;
			doubleptr = ശൂന്യ;
			മൂല്യം = -1;
			value2 = 0;
			/* Allow no/yes only in first position */
			എങ്കിൽ (strcasecmp(arg, "no") == 0 ||
			    (value2 = (strcasecmp(arg, "yes") == 0))) {
				എങ്കിൽ (ac > 0) {
					fatal("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
				}
				എങ്കിൽ (*activep &&
				    options->per_source_penalty.enabled == -1)
					options->per_source_penalty.enabled = value2;
				തുടരുക;
			} അല്ലെങ്കിൽ എങ്കിൽ ((q = strprefix(arg, "crash:", 0)) != ശൂന്യ) {
				doubleptr = &options->per_source_penalty.penalty_crash;
			} അല്ലെങ്കിൽ എങ്കിൽ ((q = strprefix(arg, "authfail:", 0)) != ശൂന്യ) {
				doubleptr = &options->per_source_penalty.penalty_authfail;
			} അല്ലെങ്കിൽ എങ്കിൽ ((q = strprefix(arg, "invaliduser:", 0)) != ശൂന്യ) {
				doubleptr = &options->per_source_penalty.penalty_invaliduser;
			} അല്ലെങ്കിൽ എങ്കിൽ ((q = strprefix(arg, "noauth:", 0)) != ശൂന്യ) {
				doubleptr = &options->per_source_penalty.penalty_noauth;
			} അല്ലെങ്കിൽ എങ്കിൽ ((q = strprefix(arg, "grace-exceeded:", 0)) != ശൂന്യ) {
				doubleptr = &options->per_source_penalty.penalty_grace;
			} അല്ലെങ്കിൽ എങ്കിൽ ((q = strprefix(arg, "refuseconnection:", 0)) != ശൂന്യ) {
				doubleptr = &options->per_source_penalty.penalty_refuseconnection;
			} അല്ലെങ്കിൽ എങ്കിൽ ((q = strprefix(arg, "max:", 0)) != ശൂന്യ) {
				doubleptr = &options->per_source_penalty.penalty_max;
			} അല്ലെങ്കിൽ എങ്കിൽ ((q = strprefix(arg, "min:", 0)) != ശൂന്യ) {
				doubleptr = &options->per_source_penalty.penalty_min;
			} അല്ലെങ്കിൽ എങ്കിൽ ((q = strprefix(arg, "max-sources4:", 0)) != ശൂന്യ) {
				intptr = &options->per_source_penalty.max_sources4;
				എങ്കിൽ ((errstr = atoi_err(q, &മൂല്യം)) != ശൂന്യ)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} അല്ലെങ്കിൽ എങ്കിൽ ((q = strprefix(arg, "max-sources6:", 0)) != ശൂന്യ) {
				intptr = &options->per_source_penalty.max_sources6;
				എങ്കിൽ ((errstr = atoi_err(q, &മൂല്യം)) != ശൂന്യ)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(arg, "overflow:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				മൂല്യം = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(arg, "overflow:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				മൂല്യം = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(arg, "overflow6:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				മൂല്യം = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(arg, "overflow6:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				മൂല്യം = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} അല്ലെങ്കിൽ {
				fatal("%s line %d: unsupported %s keyword %s",
				    filename, linenum, keyword, arg);
			}

			എങ്കിൽ (doubleptr != ശൂന്യ) {
				എങ്കിൽ ((dvalue = convtime_double(q)) < 0) {
					fatal("%s line %d: invalid %s time value.",
					    filename, linenum, keyword);
				}
				എങ്കിൽ (*activep && *doubleptr < 0.0) {
					*doubleptr = dvalue;
					options->per_source_penalty.enabled = 1;
				}
			} അല്ലെങ്കിൽ എങ്കിൽ (intptr != ശൂന്യ) {
				എങ്കിൽ (*activep && *intptr == -1) {
					*intptr = മൂല്യം;
					options->per_source_penalty.enabled = 1;
				}
			} അല്ലെങ്കിൽ {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		എങ്കിൽ (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		നിർത്തുക;

	അവസ്ഥ sMaxAuthTries:
		intptr = &options->max_authtries;
		പോകുക parse_int;

	അവസ്ഥ sMaxSessions:
		intptr = &options->max_sessions;
		പോകുക parse_int;

	അവസ്ഥ sBanner:
		charptr = &options->banner;
		പോകുക parse_filename;

	/*
	 * These options can contain %X options expanded at
	 * connect time, so that you can specify paths like:
	 *
	 * AuthorizedKeysFile	/etc/ssh_keys/%u
	 */
	അവസ്ഥ s_Authorized_താക്കോലുകൾ_File:
		uintptr = &options->അക്കം_authkeys_files;
		chararrayptr = &options->authorized_താക്കോലുകൾ_files;
 parse_filenames:
		found = *uintptr == 0;
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			എങ്കിൽ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				പോകുക out;
			}
			/* Allow "none" only in first position */
			എങ്കിൽ (strcasecmp(arg, "none") == 0) {
				എങ്കിൽ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					പോകുക out;
				}
			}
			arg2 = tilde_expand_filename(arg, getuid());
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			സ്വതന്ത്രം(arg2);
		}
		എങ്കിൽ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		എങ്കിൽ (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = ശൂന്യ; /* transferred */
			nstrs = 0;
		}
		നിർത്തുക;

	അവസ്ഥ sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		എങ്കിൽ (*activep && *charptr == ശൂന്യ) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			എങ്കിൽ (intptr != ശൂന്യ)
				*intptr = *intptr + 1;
		}
		നിർത്തുക;

	അവസ്ഥ sClientAliveInterval:
		intptr = &options->client_alive_interval;
		പോകുക parse_time;

	അവസ്ഥ s_Client_Alive_എണ്ണം_Max:
		intptr = &options->client_alive_എണ്ണം_max;
		പോകുക parse_int;

	അവസ്ഥ sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			എങ്കിൽ (*arg == '\0' || strchr(arg, '=') != ശൂന്യ)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			found = 1;
			എങ്കിൽ (!*activep)
				തുടരുക;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->അക്കം_accept_env,
			    arg);
		}
		എങ്കിൽ (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		നിർത്തുക;

	അവസ്ഥ sSetEnv:
		found = options->അക്കം_setenv == 0;
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			എങ്കിൽ (*arg == '\0' || strchr(arg, '=') == ശൂന്യ)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			എങ്കിൽ (lookup_setenv_in_list(arg, strs, nstrs) != ശൂന്യ) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				തുടരുക;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		എങ്കിൽ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		എങ്കിൽ (found && *activep) {
			options->setenv = strs;
			options->അക്കം_setenv = nstrs;
			strs = ശൂന്യ; /* transferred */
			nstrs = 0;
		}
		നിർത്തുക;

	അവസ്ഥ sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		മൂല്യം = -1;
		വേണ്ടി (i = 0; tunmode_desc[i].val != -1; i++)
			എങ്കിൽ (strcmp(tunmode_desc[i].text, arg) == 0) {
				മൂല്യം = tunmode_desc[i].val;
				നിർത്തുക;
			}
		എങ്കിൽ (മൂല്യം == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		എങ്കിൽ (*activep && *intptr == -1)
			*intptr = മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ sInclude:
		എങ്കിൽ (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		മൂല്യം = 0;
		ആകുമ്പോൾ ((arg2 = argv_next(&ac, &av)) != ശൂന്യ) {
			എങ്കിൽ (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				പോകുക out;
			}
			മൂല്യം++;
			found = 0;
			എങ്കിൽ (*arg2 != '/' && *arg2 != '~') {
				xasprintf(&arg, "%s/%s", SSHDIR, arg2);
			} അല്ലെങ്കിൽ
				arg = xstrdup(arg2);

			/*
			 * Don't let included files clobber the containing
			 * file's Match state.
			 */
			oactive = *activep;

			/* consult cache of include files */
			TAILQ_FOREACH(item, includes, entry) {
				എങ്കിൽ (strcmp(item->selector, arg) != 0)
					തുടരുക;
				എങ്കിൽ (item->filename != ശൂന്യ) {
					parse_server_config_depth(options,
					    item->filename, item->contents,
					    includes, connectinfo,
					    (*inc_flags & SSHCFG_MATCH_ONLY
					        ? SSHCFG_MATCH_ONLY : (oactive
					            ? 0 : SSHCFG_NEVERMATCH)),
					    activep, depth + 1);
				}
				found = 1;
				*activep = oactive;
			}
			എങ്കിൽ (found != 0) {
				സ്വതന്ത്രം(arg);
				തുടരുക;
			}

			/* requested glob was not in cache */
			debug2("%s line %d: new include %s",
			    filename, linenum, arg);
			എങ്കിൽ ((r = glob(arg, 0, ശൂന്യ, &gbuf)) != 0) {
				എങ്കിൽ (r != GLOB_NOMATCH) {
					fatal("%s line %d: include \"%s\" glob "
					    "failed", filename, linenum, arg);
				}
				/*
				 * If no entry matched then record a
				 * placeholder to skip later glob calls.
				 */
				debug2("%s line %d: no match for %s",
				    filename, linenum, arg);
				item = xcalloc(1, വലുപ്പം(*item));
				item->selector = xstrdup(arg);
				TAILQ_INSERT_TAIL(includes,
				    item, entry);
			}
			എങ്കിൽ (gbuf.gl_pathc > INT_MAX)
				fatal_f("too many glob results");
			വേണ്ടി (n = 0; n < (പൂർണ്ണസംഖ്യ)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				item = xcalloc(1, വലുപ്പം(*item));
				item->selector = xstrdup(arg);
				item->filename = xstrdup(gbuf.gl_pathv[n]);
				എങ്കിൽ ((item->contents = sshbuf_new()) == ശൂന്യ)
					fatal_f("sshbuf_new failed");
				load_server_config(item->filename,
				    item->contents);
				parse_server_config_depth(options,
				    item->filename, item->contents,
				    includes, connectinfo,
				    (*inc_flags & SSHCFG_MATCH_ONLY
				        ? SSHCFG_MATCH_ONLY : (oactive
				            ? 0 : SSHCFG_NEVERMATCH)),
				    activep, depth + 1);
				*activep = oactive;
				TAILQ_INSERT_TAIL(includes, item, entry);
			}
			globfree(&gbuf);
			സ്വതന്ത്രം(arg);
		}
		എങ്കിൽ (മൂല്യം == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		നിർത്തുക;

	അവസ്ഥ sMatch:
		എങ്കിൽ (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		മൂല്യം = match_cfg_വരി(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? ശൂന്യ : connectinfo));
		എങ്കിൽ (മൂല്യം < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : മൂല്യം;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_MATCH_ONLY;
		നിർത്തുക;

	അവസ്ഥ sPermitListen:
	അവസ്ഥ sPermitOpen:
		എങ്കിൽ (opcode == sPermitListen) {
			uintptr = &options->അക്കം_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} അല്ലെങ്കിൽ {
			uintptr = &options->അക്കം_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		found = *uintptr == 0;
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			എങ്കിൽ (strcmp(arg, "any") == 0 ||
			    strcmp(arg, "none") == 0) {
				എങ്കിൽ (nstrs != 0) {
					fatal("%s line %d: %s must appear "
					    "alone on a %s line.",
					    filename, linenum, arg, keyword);
				}
				opt_array_append(filename, linenum, keyword,
				    &strs, &nstrs, arg);
				തുടരുക;
			}

			എങ്കിൽ (opcode == sPermitListen &&
			    strchr(arg, ':') == ശൂന്യ) {
				/*
				 * Allow bare port number for PermitListen
				 * to indicate a wildcard listen host.
				 */
				xasprintf(&arg2, "*:%s", arg);
			} അല്ലെങ്കിൽ {
				arg2 = xstrdup(arg);
				p = hpdelim(&arg);
				എങ്കിൽ (p == ശൂന്യ) {
					fatal("%s line %d: %s missing host",
					    filename, linenum, keyword);
				}
				p = cleanhostname(p);
			}
			എങ്കിൽ (arg == ശൂന്യ ||
			    ((port = permitopen_port(arg)) < 0)) {
				fatal("%s line %d: %s bad port number",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			സ്വതന്ത്രം(arg2);
		}
		എങ്കിൽ (nstrs == 0) {
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		}
		എങ്കിൽ (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = ശൂന്യ; /* transferred */
			nstrs = 0;
		}
		നിർത്തുക;

	അവസ്ഥ sForceCommand:
		എങ്കിൽ (str == ശൂന്യ || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		എങ്കിൽ (*activep && options->adm_forced_command == ശൂന്യ)
			options->adm_forced_command = xstrdup(str + len);
		argv_consume(&ac);
		നിർത്തുക;

	അവസ്ഥ sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		എങ്കിൽ (*activep && *charptr == ശൂന്യ)
			*charptr = xstrdup(arg);
		നിർത്തുക;

	അവസ്ഥ sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_താക്കോലുകൾ;
		പോകുക parse_filename;

	അവസ്ഥ s_Revoked_താക്കോലുകൾ:
		uintptr = &options->അക്കം_revoked_താക്കോലുകൾ_files;
		chararrayptr = &options->revoked_താക്കോലുകൾ_files;
		പോകുക parse_filenames;

	അവസ്ഥ s_Security_താക്കോൽ_Provider:
		charptr = &options->sk_provider;
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		എങ്കിൽ (*activep && *charptr == ശൂന്യ) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_path(arg);
			/* increase optional counter */
			എങ്കിൽ (intptr != ശൂന്യ)
				*intptr = *intptr + 1;
		}
		നിർത്തുക;

	അവസ്ഥ sIPQoS:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		എങ്കിൽ ((മൂല്യം = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		എങ്കിൽ (മൂല്യം == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			മൂല്യം = INT_MAX;
		}
		arg = argv_next(&ac, &av);
		എങ്കിൽ (arg == ശൂന്യ)
			value2 = മൂല്യം;
		അല്ലെങ്കിൽ എങ്കിൽ ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		എങ്കിൽ (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		എങ്കിൽ (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = മൂല്യം;
			options->ip_qos_bulk = value2;
		}
		നിർത്തുക;

	അവസ്ഥ sVersionAddendum:
		എങ്കിൽ (str == ശൂന്യ || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		എങ്കിൽ (strchr(str + len, '\r') != ശൂന്യ) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		എങ്കിൽ ((arg = strchr(വരി, '#')) != ശൂന്യ) {
			*arg = '\0';
			rtrim(വരി);
		}
		എങ്കിൽ (*activep && options->version_addendum == ശൂന്യ) {
			എങ്കിൽ (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			അല്ലെങ്കിൽ
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		നിർത്തുക;

	അവസ്ഥ s_Authorized_താക്കോലുകൾ_Command:
		charptr = &options->authorized_താക്കോലുകൾ_command;
 parse_command:
		len = strspn(str, WHITESPACE);
		എങ്കിൽ (str[len] != '/' && strcasecmp(str + len, "none") != 0) {
			fatal("%.200s line %d: %s must be an absolute path",
			    filename, linenum, keyword);
		}
		എങ്കിൽ (*activep && *charptr == ശൂന്യ)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		നിർത്തുക;

	അവസ്ഥ s_Authorized_താക്കോലുകൾ_Command_User:
		charptr = &options->authorized_താക്കോലുകൾ_command_user;
 parse_localuser:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			fatal("%s line %d: missing %s argument.",
			    filename, linenum, keyword);
		}
		എങ്കിൽ (*activep && *charptr == ശൂന്യ)
			*charptr = xstrdup(arg);
		നിർത്തുക;

	അവസ്ഥ sAuthorizedPrincipalsCommand:
		charptr = &options->authorized_principals_command;
		പോകുക parse_command;

	അവസ്ഥ sAuthorizedPrincipalsCommandUser:
		charptr = &options->authorized_principals_command_user;
		പോകുക parse_localuser;

	അവസ്ഥ sAuthenticationMethods:
		found = options->അക്കം_auth_methods == 0;
		മൂല്യം = 0; /* seen "any" pseudo-method */
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			എങ്കിൽ (strcmp(arg, "any") == 0) {
				എങ്കിൽ (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				മൂല്യം = 1;
			} അല്ലെങ്കിൽ എങ്കിൽ (മൂല്യം) {
				fatal("%s line %d: \"any\" must appear "
				    "alone in %s", filename, linenum, keyword);
			} അല്ലെങ്കിൽ എങ്കിൽ (auth2_methods_valid(arg, 0) != 0) {
				fatal("%s line %d: invalid %s method list.",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		എങ്കിൽ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		എങ്കിൽ (found && *activep) {
			options->auth_methods = strs;
			options->അക്കം_auth_methods = nstrs;
			strs = ശൂന്യ; /* transferred */
			nstrs = 0;
		}
		നിർത്തുക;

	അവസ്ഥ sStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		മൂല്യം = strtol(arg, &p, 8);
		എങ്കിൽ (arg == p || മൂല്യം < 0 || മൂല്യം > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		എങ്കിൽ (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ sStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		പോകുക parse_flag;

	അവസ്ഥ sFingerprintHash:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		എങ്കിൽ ((മൂല്യം = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		എങ്കിൽ (*activep)
			options->fingerprint_hash = മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		പോകുക parse_flag;

	അവസ്ഥ sRDomain:
#എങ്കിൽ !defined(__OpenBSD__) && !defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#endif
		charptr = &options->routing_domain;
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		എങ്കിൽ (strcasecmp(arg, "none") != 0 && strcmp(arg, "%D") != 0 &&
		    !valid_rdomain(arg))
			fatal("%s line %d: invalid routing domain",
			    filename, linenum);
		എങ്കിൽ (*activep && *charptr == ശൂന്യ)
			*charptr = xstrdup(arg);
		നിർത്തുക;

	അവസ്ഥ sRequiredRSASize:
		intptr = &options->required_rsa_size;
		പോകുക parse_int;

	അവസ്ഥ sChannelTimeout:
		found = options->അക്കം_channel_timeouts == 0;
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			/* Allow "none" only in first position */
			എങ്കിൽ (strcasecmp(arg, "none") == 0) {
				എങ്കിൽ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					പോകുക out;
				}
			} അല്ലെങ്കിൽ എങ്കിൽ (parse_pattern_interval(arg,
			    ശൂന്യ, ശൂന്യ) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		എങ്കിൽ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		എങ്കിൽ (found && *activep) {
			options->channel_timeouts = strs;
			options->അക്കം_channel_timeouts = nstrs;
			strs = ശൂന്യ; /* transferred */
			nstrs = 0;
		}
		നിർത്തുക;

	അവസ്ഥ sUnusedConnectionTimeout:
		intptr = &options->unused_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		എങ്കിൽ (av[0] != ശൂന്യ && strcasecmp(av[0], "none") == 0) {
			(ശൂന്യം)argv_next(&ac, &av); /* consume arg */
			എങ്കിൽ (*activep)
				*intptr = 0;
			നിർത്തുക;
		}
		പോകുക parse_time;

	അവസ്ഥ sSshdSessionPath:
		charptr = &options->sshd_session_path;
		പോകുക parse_filename;

	അവസ്ഥ sSshdAuthPath:
		charptr = &options->sshd_auth_path;
		പോകുക parse_filename;

	അവസ്ഥ sRefuseConnection:
		intptr = &options->refuse_connection;
		multistate_ptr = multistate_flag;
		പോകുക parse_multistate;

	അവസ്ഥ sWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		പോകുക parse_multistate;

	അവസ്ഥ sDeprecated:
	അവസ്ഥ sIgnore:
	അവസ്ഥ sUnsupported:
		do_log2(opcode == sIgnore ?
		    SYSLOG_LEVEL_DEBUG2 : SYSLOG_LEVEL_INFO,
		    "%s line %d: %s option %s", filename, linenum,
		    opcode == sUnsupported ? "Unsupported" : "Deprecated",
		    keyword);
		argv_consume(&ac);
		നിർത്തുക;

	സ്ഥിരസ്ഥിതി:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, keyword, opcode);
	}
	/* Check that there is no garbage at end of line. */
	എങ്കിൽ (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		പോകുക out;
	}

	/* success */
	ret = 0;
 out:
	opt_array_free2(strs, ശൂന്യ, nstrs);
	argv_free(oav, oac);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
process_server_config_വരി(ServerOptions *options, അക്ഷരം *വരി,
    സ്ഥിരം അക്ഷരം *filename, പൂർണ്ണസംഖ്യ linenum, പൂർണ്ണസംഖ്യ *activep,
    ഘടന connection_info *connectinfo, ഘടന include_list *includes)
{
	പൂർണ്ണസംഖ്യ inc_flags = 0;

	തിരികെ process_server_config_വരി_depth(options, വരി, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

ശൂന്യം
load_server_config(സ്ഥിരം അക്ഷരം *filename, ഘടന sshbuf *conf)
{
	ഘടന stat st;
	അക്ഷരം *വരി = ശൂന്യ, *cp;
	size_t linesize = 0;
	FILE *f;
	പൂർണ്ണസംഖ്യ r;

	debug2_f("filename %s", filename);
	എങ്കിൽ ((f = fopen(filename, "r")) == ശൂന്യ) {
		perror(filename);
		exit(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	എങ്കിൽ (fstat(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	ആകുമ്പോൾ (getline(&വരി, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = വരി + strspn(വരി, " \t\r");
		എങ്കിൽ ((r = sshbuf_put(conf, cp, strlen(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	സ്വതന്ത്രം(വരി);
	എങ്കിൽ ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	fclose(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

ശൂന്യം
parse_server_match_config(ServerOptions *options,
   ഘടന include_list *includes, ഘടന connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_set_server_options(options, &mo, 0);
	free_server_options(&mo);
}

പൂർണ്ണസംഖ്യ
parse_server_match_testspec(ഘടന connection_info *ci, അക്ഷരം *spec)
{
	അക്ഷരം *p;
	സ്ഥിരം അക്ഷരം *val;

	ആകുമ്പോൾ ((p = strsep(&spec, ",")) && *p != '\0') {
		എങ്കിൽ ((val = strprefix(p, "addr=", 0)) != ശൂന്യ) {
			ci->address = xstrdup(val);
		} അല്ലെങ്കിൽ എങ്കിൽ ((val = strprefix(p, "host=", 0)) != ശൂന്യ) {
			ci->host = xstrdup(val);
		} അല്ലെങ്കിൽ എങ്കിൽ ((val = strprefix(p, "user=", 0)) != ശൂന്യ) {
			ci->user = xstrdup(val);
		} അല്ലെങ്കിൽ എങ്കിൽ ((val = strprefix(p, "laddr=", 0)) != ശൂന്യ) {
			ci->laddress = xstrdup(val);
		} അല്ലെങ്കിൽ എങ്കിൽ ((val = strprefix(p, "rdomain=", 0)) != ശൂന്യ) {
			ci->rdomain = xstrdup(val);
		} അല്ലെങ്കിൽ എങ്കിൽ ((val = strprefix(p, "lport=", 0)) != ശൂന്യ) {
			ci->lport = a2port(val);
			എങ്കിൽ (ci->lport == -1) {
				fprintf(stderr, "Invalid port '%s' in test mode"
				    " specification %s\n", p+6, p);
				തിരികെ -1;
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(p, "invalid-user") == 0) {
			ci->user_invalid = 1;
		} അല്ലെങ്കിൽ {
			fprintf(stderr, "Invalid test mode specification %s\n",
			    p);
			തിരികെ -1;
		}
	}
	തിരികെ 0;
}

ശൂന്യം
servconf_merge_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, found;

	വേണ്ടി (i = 0; i < src->അക്കം_subsystems; i++) {
		found = 0;
		വേണ്ടി (j = 0; j < dst->അക്കം_subsystems; j++) {
			എങ്കിൽ (strcmp(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				found = 1;
				നിർത്തുക;
			}
		}
		എങ്കിൽ (found) {
			debug_f("override \"%s\"", dst->subsystem_name[j]);
			സ്വതന്ത്രം(dst->subsystem_command[j]);
			സ്വതന്ത്രം(dst->subsystem_args[j]);
			dst->subsystem_command[j] =
			    xstrdup(src->subsystem_command[i]);
			dst->subsystem_args[j] =
			    xstrdup(src->subsystem_args[i]);
			തുടരുക;
		}
		debug_f("add \"%s\"", src->subsystem_name[i]);
		dst->subsystem_name = xrecallocarray(
		    dst->subsystem_name, dst->അക്കം_subsystems,
		    dst->അക്കം_subsystems + 1, വലുപ്പം(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->അക്കം_subsystems,
		    dst->അക്കം_subsystems + 1, വലുപ്പം(*dst->subsystem_command));
		dst->subsystem_args = xrecallocarray(
		    dst->subsystem_args, dst->അക്കം_subsystems,
		    dst->അക്കം_subsystems + 1, വലുപ്പം(*dst->subsystem_args));
		j = dst->അക്കം_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_args[j] = xstrdup(src->subsystem_args[i]);
	}
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_s32(ഘടന sshbuf *buf, പൂർണ്ണസംഖ്യ v)
{
	uint32_t uv;
	പൂർണ്ണസംഖ്യ r;

	uv = v < 0 ? (uint32_t)(-(v + 1)) + 1 : (uint32_t)v;
	എങ്കിൽ ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u32(buf, uv)) != 0)
		തിരികെ r;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_s64(ഘടന sshbuf *buf, int64_t v)
{
	uint64_t uv;
	പൂർണ്ണസംഖ്യ r;

	uv = v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
	എങ്കിൽ ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u64(buf, uv)) != 0)
		തിരികെ r;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_mode(ഘടന sshbuf *buf, mode_t v)
{
	u_int uv;

	എങ്കിൽ (v == (mode_t)-1)
		തിരികെ serialise_s32(buf, -1);
	uv = (u_int)v;
	എങ്കിൽ ((mode_t)uv != v || uv > 0777)
		തിരികെ SSH_ERR_INVALID_FORMAT;
	തിരികെ serialise_s32(buf, (പൂർണ്ണസംഖ്യ)uv);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_double(ഘടന sshbuf *buf, ഇരട്ട v)
{
	/*
	 * XXX this is no good for a wire encoding.
	 * It's fine for passing configurations via RPC, but it would
	 * be nicer to have an exact binary encoding here.
	 */
	തിരികെ sshbuf_put(buf, &v, വലുപ്പം(v));
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_nullable_string(ഘടന sshbuf *buf, സ്ഥിരം അക്ഷരം *s)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_put_u8(buf, s != ശൂന്യ)) != 0)
		തിരികെ r;
	എങ്കിൽ (s == ശൂന്യ)
		തിരികെ 0;
	തിരികെ sshbuf_put_cstring(buf, s);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_nullable_string_array(ഘടന sshbuf *buf, അക്ഷരം **a, u_int n)
{
	പൂർണ്ണസംഖ്യ r;
	u_int i;

	എങ്കിൽ ((r = sshbuf_put_u32(buf, n)) != 0)
		തിരികെ r;
	വേണ്ടി (i = 0; i < n; i++) {
		എങ്കിൽ ((r = serialise_nullable_string(buf, a[i])) != 0)
			തിരികെ r;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_hostkeyfile(സ്ഥിരം ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;
	u_int i;

	എങ്കിൽ ((r = sshbuf_put_u32(buf, options->അക്കം_host_താക്കോൽ_files)) != 0) {
		error_fr(r, "serialise length");
		തിരികെ r;
	}
	വേണ്ടി (i = 0; i < options->അക്കം_host_താക്കോൽ_files; i++) {
		എങ്കിൽ ((r = serialise_s32(buf,
		    options->host_താക്കോൽ_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_താക്കോൽ_files[i])) != 0) {
			error_fr(r, "serialise member");
			തിരികെ r;
		}
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_ipqos(സ്ഥിരം ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = serialise_s32(buf, options->ip_qos_interactive)) != 0 ||
	    (r = serialise_s32(buf, options->ip_qos_bulk)) != 0) {
		error_fr(r, "serialise");
		തിരികെ r;
	}

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_listenaddress(സ്ഥിരം ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;
	u_int i;

	/* Note: only serialises queued listen addresses */
	എങ്കിൽ ((r = sshbuf_put_u32(buf, options->അക്കം_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		തിരികെ r;
	}
	വേണ്ടി (i = 0; i < options->അക്കം_queued_listens; i++) {
		സ്ഥിരം ഘടന queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		എങ്കിൽ ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->port)) != 0 ||
		    (r = serialise_nullable_string(buf, qla->rdomain)) != 0) {
			error_fr(r, "serialise member");
			തിരികെ r;
		}
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_logfacility(സ്ഥിരം ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = serialise_s32(buf, (പൂർണ്ണസംഖ്യ)options->log_facility)) != 0) {
		error_fr(r, "serialise");
		തിരികെ r;
	}

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_loglevel(സ്ഥിരം ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = serialise_s32(buf, (പൂർണ്ണസംഖ്യ)options->log_level)) != 0) {
		error_fr(r, "serialise");
		തിരികെ r;
	}

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_port(സ്ഥിരം ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;
	u_int i;

	എങ്കിൽ ((r = sshbuf_put_u32(buf, options->അക്കം_ports)) != 0) {
		error_fr(r, "serialise length");
		തിരികെ r;
	}
	വേണ്ടി (i = 0; i < options->അക്കം_ports; i++) {
		എങ്കിൽ ((r = serialise_s32(buf, options->ports[i])) != 0) {
			error_fr(r, "serialise port");
			തിരികെ r;
		}
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_gatewayports(സ്ഥിരം ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = serialise_s32(buf, options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "serialise");
		തിരികെ r;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_streamlocalbindmask(സ്ഥിരം ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = serialise_mode(buf,
	    options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "serialise");
		തിരികെ r;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_streamlocalbindunlink(സ്ഥിരം ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_put_u8(buf,
	    (options->fwd_opts.streamlocal_bind_unlink != 0))) != 0) {
		error_fr(r, "serialise");
		തിരികെ r;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_maxstartups(സ്ഥിരം ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = serialise_s32(buf, options->max_startups_begin)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups_rate)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups)) != 0) {
		error_fr(r, "serialise");
		തിരികെ r;
	}

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_permituserenv(സ്ഥിരം ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = serialise_s32(buf, options->permit_user_env)) != 0 ||
	    (r = serialise_nullable_string(buf,
	    options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "serialise");
		തിരികെ r;
	}

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_persourcenetblocksize(സ്ഥിരം ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = serialise_s32(buf, options->per_source_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		തിരികെ r;
	}

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_persourcepenalties(സ്ഥിരം ServerOptions *options, ഘടന sshbuf *buf)
{
	സ്ഥിരം ഘടന per_source_penalty *psp = &options->per_source_penalty;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = serialise_s32(buf, psp->enabled)) != 0 ||
	    (r = serialise_s32(buf, psp->max_sources4)) != 0 ||
	    (r = serialise_s32(buf, psp->max_sources6)) != 0 ||
	    (r = serialise_s32(buf, psp->overflow_mode)) != 0 ||
	    (r = serialise_s32(buf, psp->overflow_mode6)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_crash)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_grace)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_authfail)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_invaliduser)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_noauth)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_refuseconnection)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_max)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_min)) != 0) {
		error_fr(r, "serialise");
		തിരികെ r;
	}

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_rekeylimit(സ്ഥിരം ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = serialise_s64(buf, options->rekey_limit)) != 0 ||
	    (r = serialise_s32(buf, options->rekey_interval)) != 0) {
		error_fr(r, "serialise");
		തിരികെ r;
	}

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_subsystem(സ്ഥിരം ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;
	u_int i;

	എങ്കിൽ ((r = sshbuf_put_u32(buf, options->അക്കം_subsystems)) != 0) {
		error_fr(r, "serialise length");
		തിരികെ r;
	}
	വേണ്ടി (i = 0; i < options->അക്കം_subsystems; i++) {
		എങ്കിൽ ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_args[i])) != 0) {
			error_fr(r, "serialise member");
			തിരികെ r;
		}
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_pubkey_auth_options(സ്ഥിരം ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = serialise_s32(buf, options->pubkey_auth_options)) != 0 ||
	    (r = serialise_s32(buf, options->max_pubkey_ok)) != 0) {
		error_fr(r, "serialise");
		തിരികെ r;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
serialise_timingsecret(സ്ഥിരം ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_put_u64(buf, options->timing_secret)) != 0) {
		error_fr(r, "serialise");
		തിരികെ r;
	}
	തിരികെ 0;
}


പൂർണ്ണസംഖ്യ
serialise_server_options(സ്ഥിരം ServerOptions *options, ഘടന sshbuf **bufp)
{
	ഘടന sshbuf *buf = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	*bufp = ശൂന്യ;

	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_VERSION)) != 0) {
		error_fr(r, "serialise version");
		പോകുക out;
	}

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	എങ്കിൽ ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		പോകുക out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	എങ്കിൽ ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		പോകുക out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	എങ്കിൽ ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		പോകുക out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	എങ്കിൽ ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		പോകുക out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	എങ്കിൽ ((r = serialise_##funcsuffix(options, buf)) != 0) \
		പോകുക out;
#define SSHCONF_NONCONF(funcsuffix) \
	എങ്കിൽ ((r = serialise_##funcsuffix(options, buf)) != 0) \
		പോകുക out;
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/* empty */
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/* empty */
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

	/* success */
	r = 0;
	*bufp = buf;
	buf = ശൂന്യ; /* transferred */
 out:
	sshbuf_free(buf);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_s32(ഘടന sshbuf *buf, പൂർണ്ണസംഖ്യ *v)
{
	uint32_t tmp;
	പൂർണ്ണസംഖ്യ r;
	u_char was_signed;

	എങ്കിൽ ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u32(buf, &tmp)) != 0)
		തിരികെ r;
	എങ്കിൽ (was_signed > 1)
		തിരികെ SSH_ERR_INVALID_FORMAT;
	എങ്കിൽ (was_signed) {
		എങ്കിൽ (tmp > (uint32_t)INT_MAX + 1)
			തിരികെ SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)INT_MAX + 1 ? INT_MIN : -(പൂർണ്ണസംഖ്യ)tmp;
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (tmp > INT_MAX)
			തിരികെ SSH_ERR_INVALID_FORMAT;
		*v = (പൂർണ്ണസംഖ്യ)tmp;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_s64(ഘടന sshbuf *buf, int64_t *v)
{
	uint64_t tmp;
	പൂർണ്ണസംഖ്യ r;
	u_char was_signed;

	എങ്കിൽ ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u64(buf, &tmp)) != 0)
		തിരികെ r;
	എങ്കിൽ (was_signed > 1)
		തിരികെ SSH_ERR_INVALID_FORMAT;
	എങ്കിൽ (was_signed) {
		എങ്കിൽ (tmp > (uint64_t)INT64_MAX + 1)
			തിരികെ SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint64_t)INT64_MAX + 1 ?
		    INT64_MIN : -(int64_t)tmp;
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (tmp > INT64_MAX)
			തിരികെ SSH_ERR_INVALID_FORMAT;
		*v = (int64_t)tmp;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_mode(ഘടന sshbuf *buf, mode_t *v)
{
	പൂർണ്ണസംഖ്യ r, tmp;

	എങ്കിൽ ((r = deserialise_s32(buf, &tmp)) != 0)
		തിരികെ r;
	എങ്കിൽ (tmp == -1) {
		*v = (mode_t)-1;
		തിരികെ 0;
	}
	എങ്കിൽ (tmp < 0 || tmp > 0777)
		തിരികെ SSH_ERR_INVALID_FORMAT;
	*v = (mode_t)tmp;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_double(ഘടന sshbuf *buf, ഇരട്ട *v)
{
	തിരികെ sshbuf_get(buf, v, വലുപ്പം(*v));
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_nullable_string(ഘടന sshbuf *buf, അക്ഷരം **sp)
{
	പൂർണ്ണസംഖ്യ r;
	u_char present;

	എങ്കിൽ ((r = sshbuf_get_u8(buf, &present)) != 0)
		തിരികെ r;
	എങ്കിൽ (present == 0) {
		*sp = ശൂന്യ;
		തിരികെ 0;
	}
	എങ്കിൽ (present != 1)
		തിരികെ SSH_ERR_INVALID_FORMAT;
	തിരികെ sshbuf_get_cstring(buf, sp, ശൂന്യ);
}

സ്ഥിതം ശൂന്യം
free_string_array(അക്ഷരം **a, u_int n)
{
	u_int i;

	എങ്കിൽ (a == ശൂന്യ)
		തിരികെ;
	വേണ്ടി (i = 0; i < n; i++)
		സ്വതന്ത്രം(a[i]);
	സ്വതന്ത്രം(a);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_എണ്ണം(ഘടന sshbuf *buf, u_int *np, സ്ഥിരം അക്ഷരം *what)
{
	പൂർണ്ണസംഖ്യ r;
	uint32_t n;

	എങ്കിൽ ((r = sshbuf_get_u32(buf, &n)) != 0) {
		error_fr(r, "deserialise %s length", what);
		തിരികെ r;
	}
	എങ്കിൽ (n > UINT_MAX) {
		error_f("bad number of %s", what);
		തിരികെ SSH_ERR_INVALID_FORMAT;
	}
	എങ്കിൽ (n > sshbuf_len(buf)) {
		error_f("bad number of %s", what);
		തിരികെ SSH_ERR_INVALID_FORMAT;
	}
	*np = n;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_nullable_string_array(ഘടന sshbuf *buf, അക്ഷരം ***arrayp,
    u_int *np)
{
	അക്ഷരം **a = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;
	u_int i, n;

	*arrayp = ശൂന്യ;
	*np = 0;
	എങ്കിൽ ((r = deserialise_എണ്ണം(buf, &n, "strings")) != 0)
		തിരികെ r;
	എങ്കിൽ (n > 0)
		a = xcalloc(n, വലുപ്പം(*a));
	വേണ്ടി (i = 0; i < n; i++) {
		എങ്കിൽ ((r = deserialise_nullable_string(buf, a + i)) != 0) {
			free_string_array(a, i + 1);
			തിരികെ r;
		}
	}
	*arrayp = a;
	*np = n;
	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
free_queued_listen_addrs(ഘടന queued_listenaddr *qla, u_int n)
{
	u_int i;

	എങ്കിൽ (qla == ശൂന്യ)
		തിരികെ;
	വേണ്ടി (i = 0; i < n; i++) {
		സ്വതന്ത്രം(qla[i].addr);
		സ്വതന്ത്രം(qla[i].rdomain);
	}
	സ്വതന്ത്രം(qla);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_hostkeyfile(ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r, *userprovided = ശൂന്യ;
	u_int i, n;
	അക്ഷരം **files = ശൂന്യ;

	എങ്കിൽ ((r = deserialise_എണ്ണം(buf, &n, "host key files")) != 0)
		തിരികെ r;
	എങ്കിൽ (n > 0) {
		userprovided = xcalloc(n, വലുപ്പം(*userprovided));
		files = xcalloc(n, വലുപ്പം(*files));
	}
	വേണ്ടി (i = 0; i < n; i++) {
		എങ്കിൽ ((r = deserialise_s32(buf, userprovided + i)) != 0 ||
		    (r = deserialise_nullable_string(buf, files + i)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(files, i + 1);
			സ്വതന്ത്രം(userprovided);
			തിരികെ r;
		}
	}
	options->അക്കം_host_താക്കോൽ_files = n;
	options->host_താക്കോൽ_file_userprovided = userprovided;
	options->host_താക്കോൽ_files = files;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_ipqos(ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = deserialise_s32(buf, &options->ip_qos_interactive)) != 0 ||
	    (r = deserialise_s32(buf, &options->ip_qos_bulk)) != 0) {
		error_fr(r, "deserialise");
		തിരികെ r;
	}

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_listenaddress(ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;
	u_int i, n;
	ഘടന queued_listenaddr *qla = ശൂന്യ;

	എങ്കിൽ ((r = deserialise_എണ്ണം(buf, &n, "listen addresses")) != 0)
		തിരികെ r;
	എങ്കിൽ (n > 0)
		qla = xcalloc(n, വലുപ്പം(*qla));
	വേണ്ടി (i = 0; i < n; i++) {
		എങ്കിൽ ((r = sshbuf_get_cstring(buf, &qla[i].addr, ശൂന്യ)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].port)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			തിരികെ r;
		}
	}
	options->അക്കം_queued_listens = n;
	options->queued_listen_addrs = qla;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_logfacility(ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r, tmp;

	എങ്കിൽ ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		തിരികെ r;
	}
	എങ്കിൽ (tmp != SYSLOG_FACILITY_NOT_SET &&
	    log_facility_name((SyslogFacility)tmp) == ശൂന്യ) {
		error_f("bad syslog facility");
		തിരികെ SSH_ERR_INVALID_FORMAT;
	}
	options->log_facility = (SyslogFacility)tmp;

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_loglevel(ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r, tmp;

	എങ്കിൽ ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		തിരികെ r;
	}
	എങ്കിൽ (tmp != SYSLOG_LEVEL_NOT_SET &&
	    log_level_name((LogLevel)tmp) == ശൂന്യ) {
		error_f("bad log level");
		തിരികെ SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_port(ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;
	u_int i, n;

	എങ്കിൽ ((r = deserialise_എണ്ണം(buf, &n, "ports")) != 0)
		തിരികെ r;
	എങ്കിൽ (n > MAX_PORTS) {
		error_f("bad number of ports");
		തിരികെ SSH_ERR_INVALID_FORMAT;
	}
	options->അക്കം_ports = n;
	memset(options->ports, 0, വലുപ്പം(options->ports));
	വേണ്ടി (i = 0; i < options->അക്കം_ports; i++) {
		എങ്കിൽ ((r = deserialise_s32(buf, options->ports + i)) != 0) {
			error_fr(r, "deserialise port");
			തിരികെ r;
		}
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_gatewayports(ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = deserialise_s32(buf, &options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "deserialise");
		തിരികെ r;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_streamlocalbindmask(ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = deserialise_mode(buf,
	    &options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "deserialise");
		തിരികെ r;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_streamlocalbindunlink(ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;
	u_char tmp;

	എങ്കിൽ ((r = sshbuf_get_u8(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		തിരികെ r;
	}
	എങ്കിൽ (tmp > 1) {
		error_f("bad boolean");
		തിരികെ SSH_ERR_INVALID_FORMAT;
	}
	options->fwd_opts.streamlocal_bind_unlink = tmp;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_maxstartups(ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = deserialise_s32(buf, &options->max_startups_begin)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups_rate)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups)) != 0) {
		error_fr(r, "deserialise");
		തിരികെ r;
	}

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_permituserenv(ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = deserialise_s32(buf, &options->permit_user_env)) != 0 ||
	    (r = deserialise_nullable_string(buf,
	    &options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "deserialise");
		തിരികെ r;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_persourcenetblocksize(ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		തിരികെ r;
	}

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_persourcepenalties(ServerOptions *options, ഘടന sshbuf *buf)
{
	ഘടന per_source_penalty *psp = &options->per_source_penalty;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
	    (r = deserialise_s32(buf, &psp->max_sources4)) != 0 ||
	    (r = deserialise_s32(buf, &psp->max_sources6)) != 0 ||
	    (r = deserialise_s32(buf, &psp->overflow_mode)) != 0 ||
	    (r = deserialise_s32(buf, &psp->overflow_mode6)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_crash)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_grace)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_authfail)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_invaliduser)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_noauth)) != 0 ||
	    (r = deserialise_double(buf,
	    &psp->penalty_refuseconnection)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_max)) != 0 ||
	    (r = deserialise_double(buf, &psp->penalty_min)) != 0) {
		error_fr(r, "deserialise");
		തിരികെ r;
	}

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_rekeylimit(ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = deserialise_s64(buf, &options->rekey_limit)) != 0 ||
	    (r = deserialise_s32(buf, &options->rekey_interval)) != 0) {
		error_fr(r, "deserialise");
		തിരികെ r;
	}

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_subsystem(ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;
	u_int i, n;
	അക്ഷരം **names = ശൂന്യ, **commands = ശൂന്യ, **args = ശൂന്യ;

	എങ്കിൽ ((r = deserialise_എണ്ണം(buf, &n, "subsystems")) != 0)
		തിരികെ r;
	എങ്കിൽ (n > 0) {
		names = xcalloc(n, വലുപ്പം(*names));
		commands = xcalloc(n, വലുപ്പം(*names));
		args = xcalloc(n, വലുപ്പം(*args));
	}
	വേണ്ടി (i = 0; i < n; i++) {
		എങ്കിൽ ((r = sshbuf_get_cstring(buf, names + i, ശൂന്യ)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, ശൂന്യ)) != 0 ||
		    (r = sshbuf_get_cstring(buf, args + i, ശൂന്യ)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(names, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(args, i + 1);
			തിരികെ r;
		}
	}
	options->അക്കം_subsystems = n;
	options->subsystem_name = names;
	options->subsystem_command = commands;
	options->subsystem_args = args;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_pubkey_auth_options(ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = deserialise_s32(buf, &options->pubkey_auth_options)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_pubkey_ok)) != 0) {
		error_fr(r, "deserialise");
		തിരികെ r;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
deserialise_timingsecret(ServerOptions *options, ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_get_u64(buf, &options->timing_secret)) != 0) {
		error_fr(r, "deserialise");
		തിരികെ r;
	}
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
deserialise_server_options(ഘടന sshbuf *buf, ServerOptions *options)
{
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	uint32_t version;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	എങ്കിൽ ((r = sshbuf_get_u32(buf, &version)) != 0) {
		error_fr(r, "deserialise version");
		പോകുക out;
	}
	എങ്കിൽ (version != SSHD_CONFIG_BLOB_VERSION) {
		error_f("unsupported config blob version %u", version);
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	എങ്കിൽ ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		പോകുക out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	എങ്കിൽ ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		പോകുക out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	എങ്കിൽ ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		പോകുക out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	എങ്കിൽ ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		പോകുക out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	എങ്കിൽ ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		പോകുക out;
#define SSHCONF_NONCONF(funcsuffix) \
	എങ്കിൽ ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		പോകുക out;
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	ചെയ്യുക { \
		സ്വതന്ത്രം(new_options.var); \
		new_options.var = ശൂന്യ; \
	} ആകുമ്പോൾ (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

	എങ്കിൽ (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}

#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

	/* success */
	r = 0;
	free_server_options(options);
	*options = new_options;
	memset(&new_options, 0, വലുപ്പം(new_options));
 out:
	free_server_options(&new_options);
	തിരികെ r;
}

സ്ഥിതം ശൂന്യം
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	വേണ്ടി (i = 0; i < options->അക്കം_host_താക്കോൽ_files; i++)
		സ്വതന്ത്രം(options->host_താക്കോൽ_files[i]);
	സ്വതന്ത്രം(options->host_താക്കോൽ_files);
	സ്വതന്ത്രം(options->host_താക്കോൽ_file_userprovided);
}

സ്ഥിതം ശൂന്യം
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->അക്കം_queued_listens);

	വേണ്ടി (i = 0; i < options->അക്കം_listen_addrs; i++) {
		സ്വതന്ത്രം(options->listen_addrs[i].rdomain);
		എങ്കിൽ (options->listen_addrs[i].addrs != ശൂന്യ)
			freeaddrinfo(options->listen_addrs[i].addrs);
	}
	സ്വതന്ത്രം(options->listen_addrs);
}

സ്ഥിതം ശൂന്യം
free_permituserenv(ServerOptions *options)
{
	സ്വതന്ത്രം(options->permit_user_env_allowlist);
}

സ്ഥിതം ശൂന്യം
free_subsystem(ServerOptions *options)
{
	u_int i;

	വേണ്ടി (i = 0; i < options->അക്കം_subsystems; i++) {
		സ്വതന്ത്രം(options->subsystem_name[i]);
		സ്വതന്ത്രം(options->subsystem_command[i]);
		സ്വതന്ത്രം(options->subsystem_args[i]);
	}
	സ്വതന്ത്രം(options->subsystem_name);
	സ്വതന്ത്രം(options->subsystem_command);
	സ്വതന്ത്രം(options->subsystem_args);
}

ശൂന്യം
free_server_options(ServerOptions *options)
{
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	/* empty */
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	/* empty */
#define SSHCONF_STRING(var, conf, flags, cp)		സ്വതന്ത്രം(options->var);
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#define SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	ചെയ്യുക { \
		സ്വതന്ത്രം(options->var); \
		options->var = ശൂന്യ; \
	} ആകുമ്പോൾ (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

#define free_ipqos(options)
#define free_logfacility(options)
#define free_loglevel(options)
#define free_port(options)
#define free_gatewayports(options)
#define free_streamlocalbindmask(options)
#define free_streamlocalbindunlink(options)
#define free_maxstartups(options)
#define free_persourcenetblocksize(options)
#define free_persourcepenalties(options)
#define free_rekeylimit(options)
#define free_pubkey_auth_options(options)
#define free_timingsecret(options)

	SSHD_CONFIG_ENTRIES

#undef free_ipqos
#undef free_logfacility
#undef free_loglevel
#undef free_port
#undef free_gatewayports
#undef free_streamlocalbindmask
#undef free_streamlocalbindunlink
#undef free_maxstartups
#undef free_persourcenetblocksize
#undef free_persourcepenalties
#undef free_rekeylimit
#undef free_timingsecret

#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

	initialize_server_options(options);
}

സ്ഥിതം ശൂന്യം
copy_server_option_int(പൂർണ്ണസംഖ്യ *dst, പൂർണ്ണസംഖ്യ src)
{
	എങ്കിൽ (src != -1)
		*dst = src;
}

സ്ഥിതം ശൂന്യം
copy_server_option_int64(int64_t *dst, int64_t src)
{
	എങ്കിൽ (src != -1)
		*dst = src;
}

സ്ഥിതം ശൂന്യം
copy_server_option_string(അക്ഷരം **dst, സ്ഥിരം അക്ഷരം *src)
{
	എങ്കിൽ (src != ശൂന്യ && *dst != src) {
		സ്വതന്ത്രം(*dst);
		*dst = xstrdup(src);
	}
}

സ്ഥിതം ശൂന്യം
copy_server_option_strarray_മൂല്യങ്ങൾ(അക്ഷരം ***dst, u_int ndst,
    അക്ഷരം * സ്ഥിരം *src, u_int nsrc)
{
	u_int i;

	എങ്കിൽ (nsrc == 0)
		തിരികെ;
	വേണ്ടി (i = 0; i < ndst; i++)
		സ്വതന്ത്രം((*dst)[i]);
	സ്വതന്ത്രം(*dst);
	*dst = xcalloc(nsrc, വലുപ്പം(**dst));
	വേണ്ടി (i = 0; i < nsrc; i++)
		(*dst)[i] = src[i] == ശൂന്യ ? ശൂന്യ : xstrdup(src[i]);
}

സ്ഥിതം ശൂന്യം
copy_server_option_strarray(അക്ഷരം ***dst, u_int *ndst,
    അക്ഷരം * സ്ഥിരം *src, u_int nsrc)
{
	എങ്കിൽ (nsrc == 0)
		തിരികെ;
	copy_server_option_strarray_മൂല്യങ്ങൾ(dst, *ndst, src, nsrc);
	*ndst = nsrc;
}

സ്ഥിതം ശൂന്യം
copy_ipqos(ServerOptions *dst, സ്ഥിരം ServerOptions *src)
{
	copy_server_option_int(&dst->ip_qos_interactive,
	    src->ip_qos_interactive);
	copy_server_option_int(&dst->ip_qos_bulk, src->ip_qos_bulk);
}

സ്ഥിതം ശൂന്യം
copy_gatewayports(ServerOptions *dst, സ്ഥിരം ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.gateway_ports,
	    src->fwd_opts.gateway_ports);
}

സ്ഥിതം ശൂന്യം
copy_streamlocalbindunlink(ServerOptions *dst, സ്ഥിരം ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.streamlocal_bind_unlink,
	    src->fwd_opts.streamlocal_bind_unlink);
}

സ്ഥിതം ശൂന്യം
copy_loglevel(ServerOptions *dst, സ്ഥിരം ServerOptions *src)
{
	എങ്കിൽ (src->log_level != -1)
		dst->log_level = src->log_level;
}

സ്ഥിതം ശൂന്യം
copy_rekeylimit(ServerOptions *dst, സ്ഥിരം ServerOptions *src)
{
	copy_server_option_int64(&dst->rekey_limit, src->rekey_limit);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

സ്ഥിതം ശൂന്യം
copy_subsystem(ServerOptions *dst, സ്ഥിരം ServerOptions *src)
{
	u_int old_അക്കം_subsystems = dst->അക്കം_subsystems;

	എങ്കിൽ (src->അക്കം_subsystems == 0)
		തിരികെ;
	copy_server_option_strarray_മൂല്യങ്ങൾ(&dst->subsystem_name,
	    old_അക്കം_subsystems, src->subsystem_name, src->അക്കം_subsystems);
	copy_server_option_strarray_മൂല്യങ്ങൾ(&dst->subsystem_command,
	    old_അക്കം_subsystems, src->subsystem_command, src->അക്കം_subsystems);
	copy_server_option_strarray_മൂല്യങ്ങൾ(&dst->subsystem_args,
	    old_അക്കം_subsystems, src->subsystem_args, src->അക്കം_subsystems);
	dst->അക്കം_subsystems = src->അക്കം_subsystems;
}

സ്ഥിതം ശൂന്യം
copy_pubkey_auth_options(ServerOptions *dst, സ്ഥിരം ServerOptions *src)
{
	എങ്കിൽ (src->pubkey_auth_options != -1) {
		dst->pubkey_auth_options = src->pubkey_auth_options;
		dst->max_pubkey_ok = src->max_pubkey_ok;
	}
}

/*
 * Copy any supported values that are set.
 *
 * If the preauth flag is set, skip the post-authentication-only manual
 * string cleanup and subsystem merge below.
 */
ശൂന്യം
copy_set_server_options(ServerOptions *dst, ServerOptions *src, പൂർണ്ണസംഖ്യ preauth)
{
	എങ്കിൽ (dst == src)
		തിരികെ;

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#define SSHCONF_STRING(var, conf, flags, cp) \
	cp(copy_server_option_string(&dst->var, src->var);)
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	cp(copy_server_option_strarray(&dst->var, &dst->nvar, \
	    src->var, src->nvar);)
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	cp(copy_##funcsuffix(dst, src);)
#define SSHCONF_NONCONF(funcsuffix)			/* empty */
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	dst->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	ചെയ്യുക { \
		സ്വതന്ത്രം(dst->var); \
		dst->var = ശൂന്യ; \
	} ആകുമ്പോൾ (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

#undef SSHCONF_INT
#undef SSHCONF_INTFLAG
#undef SSHCONF_STRING
#undef SSHCONF_STRARRAY
#undef SSHCONF_CUSTOM
#undef SSHCONF_NONCONF
#undef SSHCONF_DEPRECATE
#undef SSHCONF_UNSUPPORTED_INT
#undef SSHCONF_UNSUPPORTED_STRING
#undef SSHCONF_ALIAS

	/*
	 * The bind_mask is a mode_t that may be unsigned, so we can't use
	 * copy_server_option_int - it does a signed comparison that causes
	 * compiler warnings.
	 */
	എങ്കിൽ (src->fwd_opts.streamlocal_bind_mask != (mode_t)-1) {
		dst->fwd_opts.streamlocal_bind_mask =
		    src->fwd_opts.streamlocal_bind_mask;
	}

	/* Arguments that accept '+...' need to be expanded */
	assemble_algorithms(dst);

	/*
	 * These options may be "none" to clear a global setting.  They are
	 * consulted before authentication, so they must be cleared here
	 * rather than in the post-auth section below.
	 */
#define CLEAR_ON_NONE(v) \
	ചെയ്യുക { \
		എങ്കിൽ (option_clear_or_none(v)) { \
			സ്വതന്ത്രം(v); \
			v = ശൂന്യ; \
		} \
	} ആകുമ്പോൾ(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_താക്കോലുകൾ);
	CLEAR_ON_NONE(dst->banner);

	/*
	 * The only things that should be below this point are string options
	 * which are only used after authentication.
	 */
	എങ്കിൽ (preauth)
		തിരികെ;

	/* These options may be "none" to clear a global setting */
	copy_server_option_string(&dst->adm_forced_command,
	    src->adm_forced_command);
	copy_server_option_string(&dst->chroot_directory,
	    src->chroot_directory);
	CLEAR_ON_NONE(dst->chroot_directory);
	CLEAR_ON_NONE(dst->adm_forced_command);
#undef CLEAR_ON_NONE

	/* Subsystems require merging. */
	servconf_merge_subsystems(dst, src);
}

#define SERVCONF_MAX_DEPTH	16
സ്ഥിതം ശൂന്യം
parse_server_config_depth(ServerOptions *options, സ്ഥിരം അക്ഷരം *filename,
    ഘടന sshbuf *conf, ഘടന include_list *includes,
    ഘടന connection_info *connectinfo, പൂർണ്ണസംഖ്യ flags, പൂർണ്ണസംഖ്യ *activep, പൂർണ്ണസംഖ്യ depth)
{
	പൂർണ്ണസംഖ്യ linenum, bad_options = 0;
	അക്ഷരം *cp, *obuf, *cbuf;

	എങ്കിൽ (depth < 0 || depth > SERVCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	എങ്കിൽ ((obuf = cbuf = sshbuf_dup_string(conf)) == ശൂന്യ)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	ആകുമ്പോൾ ((cp = strsep(&cbuf, "\n")) != ശൂന്യ) {
		എങ്കിൽ (process_server_config_വരി_depth(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    depth, includes) != 0)
			bad_options++;
	}
	സ്വതന്ത്രം(obuf);
	എങ്കിൽ (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

ശൂന്യം
parse_server_config(ServerOptions *options, സ്ഥിരം അക്ഷരം *filename,
    ഘടന sshbuf *conf, ഘടന include_list *includes,
    ഘടന connection_info *connectinfo, പൂർണ്ണസംഖ്യ reexec)
{
	പൂർണ്ണസംഖ്യ active = connectinfo ? 0 : 1;
	parse_server_config_depth(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_MATCH_ONLY : 0), &active, 0);
	എങ്കിൽ (!reexec)
		process_queued_listen_addrs(options);
}

സ്ഥിതം സ്ഥിരം അക്ഷരം *
fmt_multistate_int(പൂർണ്ണസംഖ്യ val, സ്ഥിരം ഘടന multistate *m)
{
	u_int i;

	വേണ്ടി (i = 0; m[i].താക്കോൽ != ശൂന്യ; i++) {
		എങ്കിൽ (m[i].മൂല്യം == val)
			തിരികെ m[i].താക്കോൽ;
	}
	തിരികെ "UNKNOWN";
}

സ്ഥിതം സ്ഥിരം അക്ഷരം *
fmt_intarg(ServerOpCodes code, പൂർണ്ണസംഖ്യ val)
{
	എങ്കിൽ (val == -1)
		തിരികെ "unset";
	തിരഞ്ഞെടുപ്പ് (code) {
	അവസ്ഥ sAddressFamily:
		തിരികെ fmt_multistate_int(val, multistate_addressfamily);
	അവസ്ഥ s_Permit_വേര്_Login:
		തിരികെ fmt_multistate_int(val, multistate_permitrootlogin);
	അവസ്ഥ sGatewayPorts:
		തിരികെ fmt_multistate_int(val, multistate_gatewayports);
	അവസ്ഥ sCompression:
		തിരികെ fmt_multistate_int(val, multistate_compression);
	അവസ്ഥ sAllowTcpForwarding:
		തിരികെ fmt_multistate_int(val, multistate_tcpfwd);
	അവസ്ഥ sAllowStreamLocalForwarding:
		തിരികെ fmt_multistate_int(val, multistate_tcpfwd);
	അവസ്ഥ sIgnoreRhosts:
		തിരികെ fmt_multistate_int(val, multistate_ignore_rhosts);
	അവസ്ഥ sTCPKeepAlive:
		തിരികെ fmt_multistate_int(val, multistate_keepalives);
	അവസ്ഥ sWarnWeakCrypto:
		തിരികെ fmt_multistate_int(val, multistate_warnweakcrypto);
	അവസ്ഥ sFingerprintHash:
		തിരികെ ssh_digest_alg_name(val);
	സ്ഥിരസ്ഥിതി:
		തിരഞ്ഞെടുപ്പ് (val) {
		അവസ്ഥ 0:
			തിരികെ "no";
		അവസ്ഥ 1:
			തിരികെ "yes";
		സ്ഥിരസ്ഥിതി:
			തിരികെ "UNKNOWN";
		}
	}
}

സ്ഥിതം ശൂന്യം
dump_cfg_int(ServerOpCodes code, പൂർണ്ണസംഖ്യ val)
{
	എങ്കിൽ (code == sUnusedConnectionTimeout && val == 0) {
		printf("%s none\n", lookup_opcode_name(code));
		തിരികെ;
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

സ്ഥിതം ശൂന്യം
dump_cfg_oct(ServerOpCodes code, പൂർണ്ണസംഖ്യ val)
{
	printf("%s 0%o\n", lookup_opcode_name(code), val);
}

സ്ഥിതം ശൂന്യം
dump_cfg_fmtint(ServerOpCodes code, പൂർണ്ണസംഖ്യ val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

സ്ഥിതം ശൂന്യം
dump_cfg_string(ServerOpCodes code, സ്ഥിരം അക്ഷരം *val)
{
	printf("%s %s\n", lookup_opcode_name(code),
	    val == ശൂന്യ ? "none" : val);
}

സ്ഥിതം ശൂന്യം
dump_cfg_strarray(ServerOpCodes code, u_int എണ്ണം, അക്ഷരം **vals)
{
	u_int i;

	വേണ്ടി (i = 0; i < എണ്ണം; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

സ്ഥിതം ശൂന്യം
dump_cfg_strarray_oneline(ServerOpCodes code, u_int എണ്ണം, അക്ഷരം **vals)
{
	u_int i;

	തിരഞ്ഞെടുപ്പ് (code) {
	അവസ്ഥ sAuthenticationMethods:
	അവസ്ഥ sChannelTimeout:
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		എങ്കിൽ (എണ്ണം <= 0)
			തിരികെ;
		നിർത്തുക;
	}

	printf("%s", lookup_opcode_name(code));
	വേണ്ടി (i = 0; i < എണ്ണം; i++)
		printf(" %s",  vals[i]);
	എങ്കിൽ (code == sAuthenticationMethods && എണ്ണം == 0)
		printf(" any");
	അല്ലെങ്കിൽ എങ്കിൽ (code == sChannelTimeout && എണ്ണം == 0)
		printf(" none");
	printf("\n");
}

സ്ഥിതം അക്ഷരം *
format_listen_addrs(ഘടന listenaddr *la)
{
	പൂർണ്ണസംഖ്യ r;
	ഘടന addrinfo *ai;
	അക്ഷരം addr[NI_MAXHOST], port[NI_MAXSERV];
	അക്ഷരം *laddr1 = xstrdup(""), *laddr2 = ശൂന്യ;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	വേണ്ടി (ai = la->addrs; ai; ai = ai->ai_next) {
		എങ്കിൽ ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    വലുപ്പം(addr), port, വലുപ്പം(port),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			തുടരുക;
		}
		laddr2 = laddr1;
		എങ്കിൽ (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == ശൂന്യ ? "" : " rdomain ",
			    la->rdomain == ശൂന്യ ? "" : la->rdomain,
			    laddr2);
		} അല്ലെങ്കിൽ {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == ശൂന്യ ? "" : " rdomain ",
			    la->rdomain == ശൂന്യ ? "" : la->rdomain,
			    laddr2);
		}
		സ്വതന്ത്രം(laddr2);
	}
	തിരികെ laddr1;
}

ശൂന്യം
dump_config(ServerOptions *o)
{
	അക്ഷരം *s;
	u_int i;

	/* these are usually at the top of the config */
	വേണ്ടി (i = 0; i < o->അക്കം_ports; i++)
		printf("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(sAddressFamily, o->address_family);

	വേണ്ടി (i = 0; i < o->അക്കം_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		printf("%s", s);
		സ്വതന്ത്രം(s);
	}

	/* integer arguments */
#ifdef USE_PAM
	dump_cfg_fmtint(sUsePAM, o->use_pam);
	dump_cfg_string(sPAMServiceName, o->pam_service_name);
#endif
	dump_cfg_int(sLoginGraceTime, o->login_grace_time);
	dump_cfg_int(sX11DisplayOffset, o->x11_display_offset);
	dump_cfg_int(sMaxAuthTries, o->max_authtries);
	dump_cfg_int(sMaxSessions, o->max_sessions);
	dump_cfg_int(sClientAliveInterval, o->client_alive_interval);
	dump_cfg_int(s_Client_Alive_എണ്ണം_Max, o->client_alive_എണ്ണം_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_size);
	dump_cfg_oct(sStreamLocalBindMask, o->fwd_opts.streamlocal_bind_mask);
	dump_cfg_int(sUnusedConnectionTimeout, o->unused_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(s_Permit_വേര്_Login, o->permit_വേര്_login);
	dump_cfg_fmtint(sIgnoreRhosts, o->ignore_rhosts);
	dump_cfg_fmtint(sIgnoreUserKnownHosts, o->ignore_user_known_hosts);
	dump_cfg_fmtint(sHostbasedAuthentication, o->hostbased_authentication);
	dump_cfg_fmtint(sHostbasedUsesNameFromPacketOnly,
	    o->hostbased_uses_name_from_packet_only);
	dump_cfg_fmtint(sPubkeyAuthentication, o->pubkey_authentication);
#ifdef KRB5
	dump_cfg_fmtint(sKerberosAuthentication, o->kerberos_authentication);
	dump_cfg_fmtint(sKerberosOrLocalPasswd, o->kerberos_or_local_passwd);
	dump_cfg_fmtint(sKerberosTicketCleanup, o->kerberos_ticket_cleanup);
# ifdef USE_AFS
	dump_cfg_fmtint(sKerberosGetAFSToken, o->kerberos_get_afs_token);
# endif
#endif
#ifdef GSSAPI
	dump_cfg_fmtint(sGSSAPIAuthentication, o->gss_authentication);
	dump_cfg_fmtint(sGSSAPICleanupCredentials, o->gss_cleanup_creds);
	dump_cfg_fmtint(sGSSAPIDelegateCredentials, o->gss_deleg_creds);
	dump_cfg_fmtint(sGSSAPIStrictAcceptorCheck, o->gss_strict_acceptor);
#endif
	dump_cfg_fmtint(sPasswordAuthentication, o->password_authentication);
	dump_cfg_fmtint(sKbdInteractiveAuthentication,
	    o->kbd_interactive_authentication);
	dump_cfg_fmtint(sPrintMotd, o->print_motd);
#ifndef DISABLE_LASTLOG
	dump_cfg_fmtint(sPrintLastLog, o->print_lastlog);
#endif
	dump_cfg_fmtint(sX11Forwarding, o->x11_forwarding);
	dump_cfg_fmtint(sX11UseLocalhost, o->x11_use_localhost);
	dump_cfg_fmtint(sPermitTTY, o->permit_tty);
	dump_cfg_fmtint(sPermitUserRC, o->permit_user_rc);
	dump_cfg_fmtint(sStrictModes, o->strict_modes);
	dump_cfg_fmtint(sTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(sPermitEmptyPasswords, o->permit_empty_passwd);
	dump_cfg_fmtint(sCompression, o->compression);
	dump_cfg_fmtint(sGatewayPorts, o->fwd_opts.gateway_ports);
	dump_cfg_fmtint(sUseDNS, o->use_dns);
	dump_cfg_fmtint(sAllowTcpForwarding, o->allow_tcp_forwarding);
	dump_cfg_fmtint(sAllowAgentForwarding, o->allow_agent_forwarding);
	dump_cfg_fmtint(sDisableForwarding, o->disable_forwarding);
	dump_cfg_fmtint(sAllowStreamLocalForwarding, o->allow_streamlocal_forwarding);
	dump_cfg_fmtint(sStreamLocalBindUnlink, o->fwd_opts.streamlocal_bind_unlink);
	dump_cfg_fmtint(sFingerprintHash, o->fingerprint_hash);
	dump_cfg_fmtint(sExposeAuthInfo, o->expose_userauth_info);
	dump_cfg_fmtint(sWarnWeakCrypto, o->warn_weak_crypto);
	dump_cfg_fmtint(sRefuseConnection, o->refuse_connection);

	/* string arguments */
	dump_cfg_string(sPidFile, o->pid_file);
	dump_cfg_string(sModuliFile, o->moduli_file);
	dump_cfg_string(sXAuthLocation, o->xauth_location);
	dump_cfg_string(sCiphers, o->ciphers);
	dump_cfg_string(sMacs, o->macs);
	dump_cfg_string(sBanner, o->banner);
	dump_cfg_string(sForceCommand, o->adm_forced_command);
	dump_cfg_string(sChrootDirectory, o->chroot_directory);
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_താക്കോലുകൾ);
	dump_cfg_string(s_Security_താക്കോൽ_Provider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(sVersionAddendum, *o->version_addendum == '\0'
	    ? "none" : o->version_addendum);
	dump_cfg_string(s_Authorized_താക്കോലുകൾ_Command, o->authorized_താക്കോലുകൾ_command);
	dump_cfg_string(s_Authorized_താക്കോലുകൾ_Command_User, o->authorized_താക്കോലുകൾ_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(s_Host_താക്കോൽ_Agent, o->host_താക്കോൽ_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(s_Host_താക്കോൽ_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#എങ്കിൽ defined(__OpenBSD__) || defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
	dump_cfg_string(sRDomain, o->routing_domain);
#endif
	dump_cfg_string(sSshdSessionPath, o->sshd_session_path);
	dump_cfg_string(sSshdAuthPath, o->sshd_auth_path);
	dump_cfg_string(sPerSourcePenaltyExemptList, o->per_source_penalty_exempt);
	dump_cfg_string(sAgentSocketPath, o->agent_socket_path);

	/* string arguments requiring a lookup */
	dump_cfg_string(sLogLevel, log_level_name(o->log_level));
	dump_cfg_string(sSyslogFacility, log_facility_name(o->log_facility));

	/* string array arguments */
	dump_cfg_strarray_oneline(s_Authorized_താക്കോലുകൾ_File, o->അക്കം_authkeys_files,
	    o->authorized_താക്കോലുകൾ_files);
	dump_cfg_strarray_oneline(s_Revoked_താക്കോലുകൾ, o->അക്കം_revoked_താക്കോലുകൾ_files,
	    o->revoked_താക്കോലുകൾ_files);
	dump_cfg_strarray(s_Host_താക്കോൽ, o->അക്കം_host_താക്കോൽ_files, o->host_താക്കോൽ_files);
	dump_cfg_strarray(sHostCertificate, o->അക്കം_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->അക്കം_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->അക്കം_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->അക്കം_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->അക്കം_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->അക്കം_accept_env, o->accept_env);
	dump_cfg_strarray(sSetEnv, o->അക്കം_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->അക്കം_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->അക്കം_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->അക്കം_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	വേണ്ടി (i = 0; i < o->അക്കം_subsystems; i++)
		printf("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_args[i]);

	printf("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_rate, o->max_startups);
	printf("PerSourceMaxStartups ");
	എങ്കിൽ (o->per_source_max_startups == INT_MAX)
		printf("none\n");
	അല്ലെങ്കിൽ
		printf("%d\n", o->per_source_max_startups);
	printf("PerSourceNetBlockSize %d:%d\n", o->per_source_masklen_ipv4,
	    o->per_source_masklen_ipv6);

	s = ശൂന്യ;
	വേണ്ടി (i = 0; tunmode_desc[i].val != -1; i++) {
		എങ്കിൽ (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].text;
			നിർത്തുക;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	printf("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	printf("%s\n", iptos2str(o->ip_qos_bulk));

	printf("RekeyLimit %llu %d\n", (unsigned long long)o->rekey_limit,
	    o->rekey_interval);

	printf("PermitOpen");
	എങ്കിൽ (o->അക്കം_permitted_opens == 0)
		printf(" any");
	അല്ലെങ്കിൽ {
		വേണ്ടി (i = 0; i < o->അക്കം_permitted_opens; i++)
			printf(" %s", o->permitted_opens[i]);
	}
	printf("\n");
	printf("PermitListen");
	എങ്കിൽ (o->അക്കം_permitted_listens == 0)
		printf(" any");
	അല്ലെങ്കിൽ {
		വേണ്ടി (i = 0; i < o->അക്കം_permitted_listens; i++)
			printf(" %s", o->permitted_listens[i]);
	}
	printf("\n");

	എങ്കിൽ (o->permit_user_env_allowlist == ശൂന്യ) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} അല്ലെങ്കിൽ {
		printf("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	printf("PubkeyAuthOptions");
	എങ്കിൽ (o->pubkey_auth_options == 0)
		printf(" none");
	എങ്കിൽ (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		printf(" touch-required");
	എങ്കിൽ (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		printf(" verify-required");
	എങ്കിൽ (o->max_pubkey_ok != -1)
		printf(" max-pk-ok:%d", o->max_pubkey_ok);
	printf("\n");

	എങ്കിൽ (o->per_source_penalty.enabled) {
		printf("PerSourcePenalties crash:%f authfail:%f noauth:%f "
		    "invaliduser:%f "
		    "grace-exceeded:%f refuseconnection:%f max:%f min:%f "
		    "max-sources4:%d max-sources6:%d "
		    "overflow:%s overflow6:%s\n",
		    o->per_source_penalty.penalty_crash,
		    o->per_source_penalty.penalty_authfail,
		    o->per_source_penalty.penalty_noauth,
		    o->per_source_penalty.penalty_invaliduser,
		    o->per_source_penalty.penalty_grace,
		    o->per_source_penalty.penalty_refuseconnection,
		    o->per_source_penalty.penalty_max,
		    o->per_source_penalty.penalty_min,
		    o->per_source_penalty.max_sources4,
		    o->per_source_penalty.max_sources6,
		    o->per_source_penalty.overflow_mode ==
		    PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL ?
		    "deny-all" : "permissive",
		    o->per_source_penalty.overflow_mode6 ==
		    PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL ?
		    "deny-all" : "permissive");
	} അല്ലെങ്കിൽ
		printf("PerSourcePenalties no\n");
}
