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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/queue.h>
#অন্তর্ভাব <sys/stat.h>
#ifdef __OpenBSD__
#অন্তর্ভাব <sys/sysctl.h>
#endif

#অন্তর্ভাব <netinet/in.h>
#অন্তর্ভাব <netinet/ip.h>
#ifdef HAVE_NET_ROUTE_H
#অন্তর্ভাব <net/route.h>
#endif

#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <glob.h>
#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <util.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "cipher.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "mac.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "channels.h"
#অন্তর্ভাব "groupaccess.h"
#অন্তর্ভাব "canohost.h"
#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "myproposal.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "version.h"

#define SSHD_CONFIG_BLOB_VERSION	1

#যদি !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#endif

স্থির শূন্য add_listen_addr(ServerOptions *, ধ্রুব বর্ণ *,
    ধ্রুব বর্ণ *, পূর্ণাঙ্ক);
স্থির শূন্য add_one_listen_addr(ServerOptions *, ধ্রুব বর্ণ *,
    ধ্রুব বর্ণ *, পূর্ণাঙ্ক);
স্থির শূন্য parse_server_config_depth(ServerOptions *options,
    ধ্রুব বর্ণ *filename, সংরচনা sshbuf *conf, সংরচনা include_list *includes,
    সংরচনা connection_info *connectinfo, পূর্ণাঙ্ক flags, পূর্ণাঙ্ক *activep, পূর্ণাঙ্ক depth);

বাহ্য সংরচনা sshbuf *cfg;

/* Initializes the server options to their default values. */

শূন্য
initialize_server_options(ServerOptions *options)
{
	memset(options, 0, পরিমাণ(*options));
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#define SSHCONF_STRING(var, conf, flags, cp)		options->var = রিক্ত;
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = রিক্ত;
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#define SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = রিক্ত;
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	/* Using macros for these is a bit overkill but forces consistency */
#define init_hostkeyfile(options) \
	options->host_চাবি_files = 0; \
	options->অঙ্ক_host_চাবি_files = 0; \
	options->host_চাবি_file_userprovided = রিক্ত;
#define init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#define init_listenaddress(options) \
	options->queued_listen_addrs = রিক্ত; \
	options->অঙ্ক_queued_listens = 0; \
	options->listen_addrs = রিক্ত; \
	options->অঙ্ক_listen_addrs = 0;
#define init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
#define init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_SET;
#define init_port(options) \
	options->অঙ্ক_ports = 0; \
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
	options->permit_user_env_allowlist = রিক্ত;
#define init_persourcenetblocksize(options) \
	options->per_source_masklen_ipv4 = -1; \
	options->per_source_masklen_ipv6 = -1;
#define init_persourcepenalties(options) \
	options->per_source_penalty_exempt = রিক্ত; \
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
	options->অঙ্ক_subsystems = 0; \
	options->subsystem_name = রিক্ত; \
	options->subsystem_command = রিক্ত; \
	options->subsystem_args = রিক্ত;
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
স্থির পূর্ণাঙ্ক
option_clear_or_none(ধ্রুব বর্ণ *o)
{
	প্রত্যাগম o == রিক্ত || strcasecmp(o, "none") == 0;
}

স্থির শূন্য
assemble_algorithms(ServerOptions *o)
{
	বর্ণ *all_cipher, *all_mac, *all_kex, *all_চাবি, *all_sig;
	বর্ণ *def_cipher, *def_mac, *def_kex, *def_চাবি, *def_sig;
	পূর্ণাঙ্ক r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_চাবি = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_চাবি = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_চাবি);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	কুরু { \
		যদি ((r = kex_assemble_names(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} যাবত্ (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_চাবি, all_চাবি);
	ASSEMBLE(hostbased_accepted_algos, def_চাবি, all_চাবি);
	ASSEMBLE(pubkey_accepted_algos, def_চাবি, all_চাবি);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE
	মুক্ত(all_cipher);
	মুক্ত(all_mac);
	মুক্ত(all_kex);
	মুক্ত(all_চাবি);
	মুক্ত(all_sig);
	মুক্ত(def_cipher);
	মুক্ত(def_mac);
	মুক্ত(def_kex);
	মুক্ত(def_চাবি);
	মুক্ত(def_sig);
}

শূন্য
servconf_add_hostkey(ধ্রুব বর্ণ *file, ধ্রুব পূর্ণাঙ্ক সারি,
    ServerOptions *options, ধ্রুব বর্ণ *path, পূর্ণাঙ্ক userprovided)
{
	বর্ণ *apath = derelativise_path(path);

	opt_array_append2(file, সারি, "HostKey",
	    &options->host_চাবি_files, &options->host_চাবি_file_userprovided,
	    &options->অঙ্ক_host_চাবি_files, apath, userprovided);
	মুক্ত(apath);
}

শূন্য
servconf_add_hostcert(ধ্রুব বর্ণ *file, ধ্রুব পূর্ণাঙ্ক সারি,
    ServerOptions *options, ধ্রুব বর্ণ *path)
{
	বর্ণ *apath = derelativise_path(path);

	opt_array_append(file, সারি, "HostCertificate",
	    &options->host_cert_files, &options->অঙ্ক_host_cert_files, apath);
	মুক্ত(apath);
}

শূন্য
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#ifdef SKIP_PRIVDROP
	যদি (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	যদি (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#endif

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	যদি (options->var == -1) \
		options->var = def;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	যদি (options->var == -1) \
		options->var = def;
#define SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#define SSHCONF_NONCONF(funcsuffix)			/* done manually */
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	কুরু { \
		মুক্ত(options->var); \
		options->var = রিক্ত; \
	} যাবত্ (0);
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
	যদি (options->pam_service_name == রিক্ত)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#endif

	যদি (options->অঙ্ক_host_চাবি_files == 0) {
		/* fill default hostkeys */
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_RSA_চাবি_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ECDSA_চাবি_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ED25519_চাবি_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_MLDSA44_ED25519_চাবি_FILE, 0);
	}
	/* No certificates by default */
	যদি (options->অঙ্ক_ports == 0)
		options->ports[options->অঙ্ক_ports++] = SSH_DEFAULT_PORT;
	যদি (options->listen_addrs == রিক্ত)
		add_listen_addr(options, রিক্ত, রিক্ত, 0);
	যদি (options->pid_file == রিক্ত)
		options->pid_file = xstrdup(_PATH_SSH_DAEMON_PID_FILE);
	যদি (options->moduli_file == রিক্ত)
		options->moduli_file = xstrdup(_PATH_DH_MODULI);
	যদি (options->xauth_location == রিক্ত)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	যদি (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	যদি (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	যদি (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = রিক্ত;
	}
	যদি (options->rekey_limit == -1)
		options->rekey_limit = 0;
	যদি (options->rekey_interval == -1)
		options->rekey_interval = 0;
	যদি (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	যদি (options->max_startups == -1)
		options->max_startups = 100;
	যদি (options->max_startups_rate == -1)
		options->max_startups_rate = 30;		/* 30% */
	যদি (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	যদি (options->per_source_masklen_ipv4 == -1)
		options->per_source_masklen_ipv4 = 32;
	যদি (options->per_source_masklen_ipv6 == -1)
		options->per_source_masklen_ipv6 = 128;
	যদি (options->per_source_penalty.enabled == -1)
		options->per_source_penalty.enabled = 1;
	যদি (options->per_source_penalty.max_sources4 == -1)
		options->per_source_penalty.max_sources4 = 65536;
	যদি (options->per_source_penalty.max_sources6 == -1)
		options->per_source_penalty.max_sources6 = 65536;
	যদি (options->per_source_penalty.overflow_mode == -1)
		options->per_source_penalty.overflow_mode = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
	যদি (options->per_source_penalty.overflow_mode6 == -1)
		options->per_source_penalty.overflow_mode6 = options->per_source_penalty.overflow_mode;
	যদি (options->per_source_penalty.penalty_crash < 0.0)
		options->per_source_penalty.penalty_crash = 90.0;
	যদি (options->per_source_penalty.penalty_grace < 0.0)
		options->per_source_penalty.penalty_grace = 10.0;
	যদি (options->per_source_penalty.penalty_authfail < 0.0)
		options->per_source_penalty.penalty_authfail = 5.0;
	যদি (options->per_source_penalty.penalty_invaliduser < 0.0)
		options->per_source_penalty.penalty_invaliduser = 5.0;
	যদি (options->per_source_penalty.penalty_noauth < 0.0)
		options->per_source_penalty.penalty_noauth = 1.0;
	যদি (options->per_source_penalty.penalty_refuseconnection < 0.0)
		options->per_source_penalty.penalty_refuseconnection = 10.0;
	যদি (options->per_source_penalty.penalty_min < 0.0)
		options->per_source_penalty.penalty_min = 15.0;
	যদি (options->per_source_penalty.penalty_max < 0.0)
		options->per_source_penalty.penalty_max = 600.0;
	যদি (options->অঙ্ক_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_চাবিগুলি_files,
		    &options->অঙ্ক_authkeys_files,
		    PATH_SSH_USER_PERMITTED_চাবিগুলি);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_চাবিগুলি_files,
		    &options->অঙ্ক_authkeys_files,
		    _PATH_SSH_USER_PERMITTED_KEYS2);
	}
	যদি (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	যদি (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	যদি (options->version_addendum == রিক্ত)
		options->version_addendum = xstrdup("");
	যদি (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	যদি (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	যদি (options->sk_provider == রিক্ত)
		options->sk_provider = xstrdup("internal");
	যদি (options->sshd_session_path == রিক্ত)
		options->sshd_session_path = xstrdup(_PATH_SSHD_SESSION);
	যদি (options->sshd_auth_path == রিক্ত)
		options->sshd_auth_path = xstrdup(_PATH_SSHD_AUTH);
	যদি (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	যদি (options->agent_socket_path == রিক্ত)
		options->agent_socket_path = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#define CLEAR_ON_NONE(v) \
	কুরু { \
		যদি (option_clear_or_none(v)) { \
			মুক্ত(v); \
			v = রিক্ত; \
		} \
	} যাবত্(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	কুরু { \
		যদি (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			মুক্ত(options->v[0]); \
			মুক্ত(options->v); \
			options->v = রিক্ত; \
			options->nv = 0; \
		} \
	} যাবত্ (0)
	CLEAR_ON_NONE(options->pid_file);
	CLEAR_ON_NONE(options->xauth_location);
	CLEAR_ON_NONE(options->banner);
	CLEAR_ON_NONE(options->trusted_user_ca_চাবিগুলি);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_চাবি_agent);
	CLEAR_ON_NONE(options->per_source_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_path);

	প্রতি (i = 0; i < options->অঙ্ক_host_চাবি_files; i++)
		CLEAR_ON_NONE(options->host_চাবি_files[i]);
	প্রতি (i = 0; i < options->অঙ্ক_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, অঙ্ক_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, অঙ্ক_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_চাবিগুলি_files, অঙ্ক_revoked_চাবিগুলি_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_চাবিগুলি_files, অঙ্ক_authkeys_files, "none");
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
প্রকারনির্দেশ গণনা {
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
স্থির সংরচনা {
	ধ্রুব বর্ণ *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", sMatch, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ রিক্ত, sBadOption, 0 }
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

স্থির সংরচনা {
	পূর্ণাঙ্ক val;
	বর্ণ *text;
} tunmode_desc[] = {
	{ SSH_TUNMODE_NO, "no" },
	{ SSH_TUNMODE_POINTOPOINT, "point-to-point" },
	{ SSH_TUNMODE_ETHERNET, "ethernet" },
	{ SSH_TUNMODE_YES, "yes" },
	{ -1, রিক্ত }
};

/* Returns an opcode name from its number */

স্থির ধ্রুব বর্ণ *
lookup_opcode_name(ServerOpCodes code)
{
	u_int i;

	প্রতি (i = 0; keywords[i].name != রিক্ত; i++)
		যদি (keywords[i].opcode == code)
			প্রত্যাগম(keywords[i].name);
	প্রত্যাগম "UNKNOWN";
}


/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

স্থির ServerOpCodes
parse_token(ধ্রুব বর্ণ *cp, ধ্রুব বর্ণ *filename,
	    পূর্ণাঙ্ক linenum, u_int *flags)
{
	u_int i;

	প্রতি (i = 0; keywords[i].name; i++)
		যদি (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			প্রত্যাগম keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	প্রত্যাগম sBadOption;
}

বর্ণ *
derelativise_path(ধ্রুব বর্ণ *path)
{
	বর্ণ *expanded, *ret, cwd[PATH_MAX];

	যদি (strcasecmp(path, "none") == 0)
		প্রত্যাগম xstrdup("none");
	expanded = tilde_expand_filename(path, getuid());
	যদি (path_absolute(expanded))
		প্রত্যাগম expanded;
	যদি (getcwd(cwd, পরিমাণ(cwd)) == রিক্ত)
		fatal_f("getcwd: %s", strerror(errno));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	মুক্ত(expanded);
	প্রত্যাগম ret;
}

স্থির শূন্য
add_listen_addr(ServerOptions *options, ধ্রুব বর্ণ *addr,
    ধ্রুব বর্ণ *rdomain, পূর্ণাঙ্ক port)
{
	u_int i;

	যদি (port > 0)
		add_one_listen_addr(options, addr, rdomain, port);
	অন্যথা {
		প্রতি (i = 0; i < options->অঙ্ক_ports; i++) {
			add_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

স্থির শূন্য
add_one_listen_addr(ServerOptions *options, ধ্রুব বর্ণ *addr,
    ধ্রুব বর্ণ *rdomain, পূর্ণাঙ্ক port)
{
	সংরচনা addrinfo hints, *ai, *aitop;
	বর্ণ strport[NI_MAXSERV];
	পূর্ণাঙ্ক gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	প্রতি (i = 0; i < options->অঙ্ক_listen_addrs; i++) {
		যদি (rdomain == রিক্ত && options->listen_addrs[i].rdomain == রিক্ত)
			ভঙ্গ;
		যদি (rdomain == রিক্ত || options->listen_addrs[i].rdomain == রিক্ত)
			অনুবর্ত;
		যদি (strcmp(rdomain, options->listen_addrs[i].rdomain) == 0)
			ভঙ্গ;
	}
	যদি (i >= options->অঙ্ক_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		যদি (i >= INT_MAX)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->অঙ্ক_listen_addrs, options->অঙ্ক_listen_addrs + 1,
		    পরিমাণ(*options->listen_addrs));
		i = options->অঙ্ক_listen_addrs++;
		যদি (rdomain != রিক্ত)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	memset(&hints, 0, পরিমাণ(hints));
	hints.ai_family = options->address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == রিক্ত) ? AI_PASSIVE : 0;
	snprintf(strport, পরিমাণ strport, "%d", port);
	যদি ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    ssh_gai_strerror(gaierr));
	প্রতি (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs[i].addrs;
	options->listen_addrs[i].addrs = aitop;
}

/* Returns nonzero if the routing domain name is valid */
স্থির পূর্ণাঙ্ক
valid_rdomain(ধ্রুব বর্ণ *name)
{
#যদি defined(HAVE_SYS_VALID_RDOMAIN)
	প্রত্যাগম sys_valid_rdomain(name);
#নোচেদ্যদি defined(__OpenBSD__)
	ধ্রুব বর্ণ *errstr;
	long long অঙ্ক;
	সংরচনা rt_tableinfo info;
	পূর্ণাঙ্ক mib[6];
	size_t miblen = পরিমাণ(mib);

	যদি (name == রিক্ত)
		প্রত্যাগম 1;

	অঙ্ক = strtonum(name, 0, 255, &errstr);
	যদি (errstr != রিক্ত)
		প্রত্যাগম 0;

	/* Check whether the table actually exists */
	memset(mib, 0, পরিমাণ(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_TABLE;
	mib[5] = (পূর্ণাঙ্ক)অঙ্ক;
	যদি (sysctl(mib, 6, &info, &miblen, রিক্ত, 0) == -1)
		প্রত্যাগম 0;

	প্রত্যাগম 1;
#অন্যথা /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	প্রত্যাগম 0;
#endif
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
স্থির শূন্য
queue_listen_addr(ServerOptions *options, ধ্রুব বর্ণ *addr,
    ধ্রুব বর্ণ *rdomain, পূর্ণাঙ্ক port)
{
	সংরচনা queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->অঙ্ক_queued_listens, options->অঙ্ক_queued_listens + 1,
	    পরিমাণ(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->অঙ্ক_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->port = port;
	qla->rdomain = rdomain == রিক্ত ? রিক্ত : xstrdup(rdomain);
}

/*
 * Process queued (text) ListenAddress entries.
 */
স্থির শূন্য
process_queued_listen_addrs(ServerOptions *options)
{
	u_int i;
	সংরচনা queued_listenaddr *qla;

	যদি (options->অঙ্ক_ports == 0)
		options->ports[options->অঙ্ক_ports++] = SSH_DEFAULT_PORT;
	যদি (options->address_family == -1)
		options->address_family = AF_UNSPEC;

	প্রতি (i = 0; i < options->অঙ্ক_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		add_listen_addr(options, qla->addr, qla->rdomain, qla->port);
		মুক্ত(qla->addr);
		মুক্ত(qla->rdomain);
	}
	মুক্ত(options->queued_listen_addrs);
	options->queued_listen_addrs = রিক্ত;
	options->অঙ্ক_queued_listens = 0;
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

স্থির পূর্ণাঙ্ক
match_cfg_সারি_group(ধ্রুব বর্ণ *grps, পূর্ণাঙ্ক সারি, ধ্রুব বর্ণ *user)
{
	পূর্ণাঙ্ক result = 0;
	সংরচনা passwd *pw;

	যদি (user == রিক্ত)
		গচ্ছ out;

	যদি ((pw = getpwnam(user)) == রিক্ত) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", সারি, user);
	} অন্যথা যদি (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, সারি);
	} অন্যথা যদি (ga_match_pattern_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, সারি);
	} অন্যথা {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, সারি);
		result = 1;
	}
out:
	ga_free();
	প্রত্যাগম result;
}

স্থির শূন্য
match_test_missing_fatal(ধ্রুব বর্ণ *criteria, ধ্রুব বর্ণ *attrib)
{
	fatal("'Match %s' in configuration but '%s' not in connection "
	    "test specification.", criteria, attrib);
}

/*
 * All of the attributes on a single Match line are ANDed together, so we need
 * to check every attribute and set the result to zero if any attribute does
 * not match.
 */
স্থির পূর্ণাঙ্ক
match_cfg_সারি(ধ্রুব বর্ণ *full_সারি, পূর্ণাঙ্ক *acp, বর্ণ ***avp,
    পূর্ণাঙ্ক সারি, সংরচনা connection_info *ci)
{
	পূর্ণাঙ্ক result = 1, attributes = 0, port;
	বর্ণ *arg, *attrib = রিক্ত, *oattrib;

	যদি (ci == রিক্ত) {
		debug3("checking syntax for 'Match %s' on line %d",
		    full_সারি, সারি);
	} অন্যথা {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", full_সারি,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->address ? ci->address : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", সারি);
	}

	যাবত্ ((oattrib = argv_next(acp, avp)) != রিক্ত) {
		/* Terminate on comment */
		যদি (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			ভঙ্গ;
		}
		attrib = xstrdup(oattrib);
		arg = রিক্ত;
		attributes++;
		/* Criterion "all" has no argument and must appear alone */
		যদি (strcasecmp(attrib, "all") == 0) {
			যদি (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != রিক্ত &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				result = -1;
				গচ্ছ out;
			}
			যদি (arg != রিক্ত && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			result = 1;
			গচ্ছ out;
		}
		/* Criterion "invalid-user" also has no argument */
		যদি (strcasecmp(attrib, "invalid-user") == 0) {
			যদি (ci == রিক্ত) {
				result = 0;
				গচ্ছ next;
			}
			যদি (ci->user_invalid == 0)
				result = 0;
			অন্যথা
				debug("matched invalid-user at line %d", সারি);
			গচ্ছ next;
		}

		/* Keep this list in sync with below */
		যদি (strprefix(attrib, "user=", 1) != রিক্ত ||
		    strprefix(attrib, "group=", 1) != রিক্ত ||
		    strprefix(attrib, "host=", 1) != রিক্ত ||
		    strprefix(attrib, "address=", 1) != রিক্ত ||
		    strprefix(attrib, "localaddress=", 1) != রিক্ত ||
		    strprefix(attrib, "localport=", 1) != রিক্ত ||
		    strprefix(attrib, "rdomain=", 1) != রিক্ত ||
		    strprefix(attrib, "version=", 1) != রিক্ত) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} অন্যথা {
			arg = argv_next(acp, avp);
		}

		/* All other criteria require an argument */
		যদি (arg == রিক্ত || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			গচ্ছ out;
		}
		যদি (strcasecmp(attrib, "user") == 0) {
			যদি (ci == রিক্ত || (ci->test && ci->user == রিক্ত)) {
				result = 0;
				গচ্ছ next;
			}
			যদি (ci->user == রিক্ত)
				match_test_missing_fatal("User", "user");
			যদি (match_usergroup_pattern_list(ci->user, arg) != 1)
				result = 0;
			অন্যথা
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, সারি);
		} অন্যথা যদি (strcasecmp(attrib, "group") == 0) {
			যদি (ci == রিক্ত || (ci->test && ci->user == রিক্ত)) {
				result = 0;
				গচ্ছ next;
			}
			যদি (ci->user == রিক্ত)
				match_test_missing_fatal("Group", "user");
			বিকল্প (match_cfg_সারি_group(arg, সারি, ci->user)) {
			পক্ষ -1:
				result = -1;
				গচ্ছ out;
			পক্ষ 0:
				result = 0;
			}
		} অন্যথা যদি (strcasecmp(attrib, "host") == 0) {
			যদি (ci == রিক্ত || (ci->test && ci->host == রিক্ত)) {
				result = 0;
				গচ্ছ next;
			}
			যদি (ci->host == রিক্ত)
				match_test_missing_fatal("Host", "host");
			যদি (match_hostname(ci->host, arg) != 1)
				result = 0;
			অন্যথা
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, সারি);
		} অন্যথা যদি (strcasecmp(attrib, "address") == 0) {
			যদি (ci == রিক্ত || (ci->test && ci->address == রিক্ত)) {
				যদি (addr_match_list(রিক্ত, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, সারি);
				result = 0;
				গচ্ছ next;
			}
			যদি (ci->address == রিক্ত)
				match_test_missing_fatal("Address", "addr");
			বিকল্প (addr_match_list(ci->address, arg)) {
			পক্ষ 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->address, arg, সারি);
				ভঙ্গ;
			পক্ষ 0:
			পক্ষ -1:
				result = 0;
				ভঙ্গ;
			পক্ষ -2:
				result = -1;
				গচ্ছ out;
			}
		} অন্যথা যদি (strcasecmp(attrib, "localaddress") == 0){
			যদি (ci == রিক্ত || (ci->test && ci->laddress == রিক্ত)) {
				যদি (addr_match_list(রিক্ত, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    সারি);
				result = 0;
				গচ্ছ next;
			}
			যদি (ci->laddress == রিক্ত)
				match_test_missing_fatal("LocalAddress",
				    "laddr");
			বিকল্প (addr_match_list(ci->laddress, arg)) {
			পক্ষ 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, সারি);
				ভঙ্গ;
			পক্ষ 0:
			পক্ষ -1:
				result = 0;
				ভঙ্গ;
			পক্ষ -2:
				result = -1;
				গচ্ছ out;
			}
		} অন্যথা যদি (strcasecmp(attrib, "localport") == 0) {
			যদি ((port = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				result = -1;
				গচ্ছ out;
			}
			যদি (ci == রিক্ত || (ci->test && ci->lport == -1)) {
				result = 0;
				গচ্ছ next;
			}
			যদি (ci->lport == 0)
				match_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			যদি (port == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, port, সারি);
			অন্যথা
				result = 0;
		} অন্যথা যদি (strcasecmp(attrib, "rdomain") == 0) {
			যদি (ci == রিক্ত || (ci->test && ci->rdomain == রিক্ত)) {
				result = 0;
				গচ্ছ next;
			}
			যদি (ci->rdomain == রিক্ত)
				match_test_missing_fatal("RDomain", "rdomain");
			যদি (match_pattern_list(ci->rdomain, arg, 0) != 1)
				result = 0;
			অন্যথা
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, সারি);
		} অন্যথা যদি (strcasecmp(attrib, "version") == 0) {
			যদি (match_pattern_list(SSH_RELEASE, arg, 0) != 1)
				result = 0;
			অন্যথা
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, সারি);
		} অন্যথা {
			error("Unsupported Match attribute %s", oattrib);
			result = -1;
			গচ্ছ out;
		}
 next:
		মুক্ত(attrib);
		attrib = রিক্ত;
	}
	যদি (attributes == 0) {
		error("One or more attributes required for Match");
		প্রত্যাগম -1;
	}
 out:
	যদি (ci != রিক্ত && result != -1)
		debug3("match %sfound on line %d", result ? "" : "not ", সারি);
	মুক্ত(attrib);
	প্রত্যাগম result;
}

#define WHITESPACE " \t\r\n"

/* Multistate option parsing */
সংরচনা multistate {
	বর্ণ *চাবি;
	পূর্ণাঙ্ক মান;
};
স্থির ধ্রুব সংরচনা multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ রিক্ত, -1 }
};
স্থির ধ্রুব সংরচনা multistate multistate_ignore_rhosts[] = {
	{ "yes",			IGNORE_RHOSTS_YES },
	{ "no",				IGNORE_RHOSTS_NO },
	{ "shosts-only",		IGNORE_RHOSTS_SHOSTS },
	{ রিক্ত, -1 }
};
স্থির ধ্রুব সংরচনা multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ রিক্ত, -1 }
};
স্থির ধ্রুব সংরচনা multistate multistate_permitrootlogin[] = {
	{ "prohibit-password",		PERMIT_NO_PASSWD },
	{ "without-password",		PERMIT_NO_PASSWD },
	{ "forced-commands-only",	PERMIT_FORCED_ONLY },
	{ "yes",			PERMIT_YES },
	{ "no",				PERMIT_NO },
	{ রিক্ত, -1 }
};
স্থির ধ্রুব সংরচনা multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ রিক্ত, -1 }
};
স্থির ধ্রুব সংরচনা multistate multistate_gatewayports[] = {
	{ "clientspecified",		2 },
	{ "yes",			1 },
	{ "no",				0 },
	{ রিক্ত, -1 }
};
স্থির ধ্রুব সংরচনা multistate multistate_tcpfwd[] = {
	{ "yes",			FORWARD_ALLOW },
	{ "all",			FORWARD_ALLOW },
	{ "no",				FORWARD_DENY },
	{ "remote",			FORWARD_REMOTE },
	{ "local",			FORWARD_LOCAL },
	{ রিক্ত, -1 }
};
স্থির ধ্রুব সংরচনা multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ রিক্ত, -1 }
};
স্থির ধ্রুব সংরচনা multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ রিক্ত, -1 }
};

স্থির পূর্ণাঙ্ক
process_server_config_সারি_depth(ServerOptions *options, বর্ণ *সারি,
    ধ্রুব বর্ণ *filename, পূর্ণাঙ্ক linenum, পূর্ণাঙ্ক *activep,
    সংরচনা connection_info *connectinfo, পূর্ণাঙ্ক *inc_flags, পূর্ণাঙ্ক depth,
    সংরচনা include_list *includes)
{
	বর্ণ *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	পূর্ণাঙ্ক cmdline = 0, *intptr, মান, value2, value3, n, port, oactive, r;
	দ্বিগুণ dvalue, *doubleptr = রিক্ত;
	পূর্ণাঙ্ক ca_only = 0, found = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	size_t len;
	long long val64;
	ধ্রুব সংরচনা multistate *multistate_ptr;
	ধ্রুব বর্ণ *errstr;
	সংরচনা include_item *item;
	glob_t gbuf;
	বর্ণ **oav = রিক্ত, **av;
	পূর্ণাঙ্ক oac = 0, ac;
	পূর্ণাঙ্ক ret = -1;
	বর্ণ **strs = রিক্ত; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	যদি ((len = strlen(সারি)) == 0)
		প্রত্যাগম 0;
	প্রতি (len--; len > 0; len--) {
		যদি (strchr(WHITESPACE "\f", সারি[len]) == রিক্ত)
			ভঙ্গ;
		সারি[len] = '\0';
	}

	str = সারি;
	যদি ((keyword = strdelim(&str)) == রিক্ত)
		প্রত্যাগম 0;
	/* Ignore leading whitespace */
	যদি (*keyword == '\0')
		keyword = strdelim(&str);
	যদি (!keyword || !*keyword || *keyword == '#')
		প্রত্যাগম 0;
	যদি (str == রিক্ত || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		প্রত্যাগম -1;
	}
	intptr = রিক্ত;
	charptr = রিক্ত;
	opcode = parse_token(keyword, filename, linenum, &flags);

	যদি (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		প্রত্যাগম -1;
	}
	ac = oac;
	av = oav;

	যদি (activep == রিক্ত) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	যদি (*activep && opcode != sMatch && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	যদি (*activep == 0 && !(flags & SSHCFG_MATCH)) {
		যদি (connectinfo == রিক্ত) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} অন্যথা { /* this is a directive we have already processed */
			ret = 0;
			গচ্ছ out;
		}
	}

	বিকল্প (opcode) {
	/* Portable-specific options */
#ifdef USE_PAM
	পক্ষ sUsePAM:
		intptr = &options->use_pam;
		গচ্ছ parse_flag;
	পক্ষ sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		যদি (*activep && *charptr == রিক্ত)
			*charptr = xstrdup(arg);
		ভঙ্গ;
#endif

	/* Standard Options */
	পক্ষ sBadOption:
		গচ্ছ out;
	পক্ষ sPort:
		/* ignore ports from configfile if cmdline specifies ports */
		যদি (options->ports_from_cmdline) {
			argv_consume(&ac);
			ভঙ্গ;
		}
		যদি (options->অঙ্ক_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->অঙ্ক_ports++] = a2port(arg);
		যদি (options->ports[options->অঙ্ক_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		ভঙ্গ;

	পক্ষ sLoginGraceTime:
		intptr = &options->login_grace_time;
 parse_time:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		যদি ((মান = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		যদি (*activep && *intptr == -1)
			*intptr = মান;
		ভঙ্গ;

	পক্ষ sListenAddress:
		arg = argv_next(&ac, &av);
		যদি (arg == রিক্ত || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		যদি (strchr(arg, '[') == রিক্ত && (p = strchr(arg, ':')) != রিক্ত
		    && strchr(p+1, ':') != রিক্ত) {
			port = 0;
			p = arg;
		} অন্যথা {
			arg2 = রিক্ত;
			p = hpdelim(&arg);
			যদি (p == রিক্ত)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			যদি (arg == রিক্ত)
				port = 0;
			অন্যথা যদি ((port = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = রিক্ত;
		যদি ((arg = argv_next(&ac, &av)) != রিক্ত) {
			যদি (strcmp(arg, "rdomain") != 0 ||
			    (arg2 = argv_next(&ac, &av)) == রিক্ত)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			যদি (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		queue_listen_addr(options, p, arg2, port);

		ভঙ্গ;

	পক্ষ sAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		মান = -1;
		প্রতি (i = 0; multistate_ptr[i].চাবি != রিক্ত; i++) {
			যদি (strcasecmp(arg, multistate_ptr[i].চাবি) == 0) {
				মান = multistate_ptr[i].মান;
				ভঙ্গ;
			}
		}
		যদি (মান == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		যদি (*activep && *intptr == -1)
			*intptr = মান;
		ভঙ্গ;

	পক্ষ s_Host_চাবি:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		যদি (*activep) {
			servconf_add_hostkey(filename, linenum,
			    options, arg, 1);
		}
		ভঙ্গ;

	পক্ষ s_Host_চাবি_Agent:
		charptr = &options->host_চাবি_agent;
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		যদি (*activep && *charptr == রিক্ত)
			*charptr = !strcmp(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_path(arg);
		ভঙ্গ;

	পক্ষ sHostCertificate:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		যদি (*activep)
			servconf_add_hostcert(filename, linenum, options, arg);
		ভঙ্গ;

	পক্ষ sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		যদি (*activep && *charptr == রিক্ত) {
			*charptr = derelativise_path(arg);
			/* increase optional counter */
			যদি (intptr != রিক্ত)
				*intptr = *intptr + 1;
		}
		ভঙ্গ;

	পক্ষ sModuliFile:
		charptr = &options->moduli_file;
		গচ্ছ parse_filename;

	পক্ষ s_Permit_মূল_Login:
		intptr = &options->permit_মূল_login;
		multistate_ptr = multistate_permitrootlogin;
		গচ্ছ parse_multistate;

	পক্ষ sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
		multistate_ptr = multistate_ignore_rhosts;
		গচ্ছ parse_multistate;

	পক্ষ sIgnoreUserKnownHosts:
		intptr = &options->ignore_user_known_hosts;
 parse_flag:
		multistate_ptr = multistate_flag;
		গচ্ছ parse_multistate;

	পক্ষ sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		গচ্ছ parse_flag;

	পক্ষ sHostbasedUsesNameFromPacketOnly:
		intptr = &options->hostbased_uses_name_from_packet_only;
		গচ্ছ parse_flag;

	পক্ষ sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		যদি (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		যদি (*activep && *charptr == রিক্ত)
			*charptr = xstrdup(arg);
		ভঙ্গ;

	পক্ষ s_Host_চাবি_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
		গচ্ছ parse_pubkey_algos;

	পক্ষ sCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		গচ্ছ parse_pubkey_algos;

	পক্ষ sPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		ca_only = 0;
		গচ্ছ parse_flag;

	পক্ষ sPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		গচ্ছ parse_pubkey_algos;

	পক্ষ sPubkeyAuthOptions:
		intptr = &options->pubkey_auth_options;
		মান = 0;
		value2 = -1;
		যাবত্ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			যদি (strcasecmp(arg, "none") == 0)
				অনুবর্ত;
			যদি (strcasecmp(arg, "touch-required") == 0)
				মান |= PUBKEYAUTH_TOUCH_REQUIRED;
			অন্যথা যদি (strcasecmp(arg, "verify-required") == 0)
				মান |= PUBKEYAUTH_VERIFY_REQUIRED;
			অন্যথা যদি (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				যদি (errstr != রিক্ত) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					গচ্ছ out;
				}
			} অন্যথা {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				গচ্ছ out;
			}
		}
		যদি (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = মান;
			options->max_pubkey_ok = value2;
		}
		ভঙ্গ;

#ifdef KRB5
	পক্ষ sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		গচ্ছ parse_flag;

	পক্ষ sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		গচ্ছ parse_flag;

	পক্ষ sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		গচ্ছ parse_flag;
#ifdef USE_AFS
	পক্ষ sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		গচ্ছ parse_flag;
#endif /* USE_AFS */
#endif /* KRB5 */

#ifdef GSSAPI
	পক্ষ sGSSAPIAuthentication:
		intptr = &options->gss_authentication;
		গচ্ছ parse_flag;

	পক্ষ sGSSAPICleanupCredentials:
		intptr = &options->gss_cleanup_creds;
		গচ্ছ parse_flag;

	পক্ষ sGSSAPIDelegateCredentials:
		intptr = &options->gss_deleg_creds;
		গচ্ছ parse_flag;

	পক্ষ sGSSAPIStrictAcceptorCheck:
		intptr = &options->gss_strict_acceptor;
		গচ্ছ parse_flag;
#endif /* GSSAPI */

	পক্ষ sPasswordAuthentication:
		intptr = &options->password_authentication;
		গচ্ছ parse_flag;

	পক্ষ sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		গচ্ছ parse_flag;

	পক্ষ sPrintMotd:
		intptr = &options->print_motd;
		গচ্ছ parse_flag;

#ifndef DISABLE_LASTLOG
	পক্ষ sPrintLastLog:
		intptr = &options->print_lastlog;
		গচ্ছ parse_flag;
#endif

	পক্ষ sX11Forwarding:
		intptr = &options->x11_forwarding;
		গচ্ছ parse_flag;

	পক্ষ sX11DisplayOffset:
		intptr = &options->x11_display_offset;
 parse_int:
		arg = argv_next(&ac, &av);
		যদি ((errstr = atoi_err(arg, &মান)) != রিক্ত)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		যদি (*activep && *intptr == -1)
			*intptr = মান;
		ভঙ্গ;

	পক্ষ sX11UseLocalhost:
		intptr = &options->x11_use_localhost;
		গচ্ছ parse_flag;

	পক্ষ sXAuthLocation:
		charptr = &options->xauth_location;
		গচ্ছ parse_filename;

	পক্ষ sPermitTTY:
		intptr = &options->permit_tty;
		গচ্ছ parse_flag;

	পক্ষ sPermitUserRC:
		intptr = &options->permit_user_rc;
		গচ্ছ parse_flag;

	পক্ষ sStrictModes:
		intptr = &options->strict_modes;
		গচ্ছ parse_flag;

	পক্ষ sTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		গচ্ছ parse_multistate;

	পক্ষ sPermitEmptyPasswords:
		intptr = &options->permit_empty_passwd;
		গচ্ছ parse_flag;

	পক্ষ sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		মান = 0;
		p = রিক্ত;
		যদি (strcmp(arg, "yes") == 0)
			মান = 1;
		অন্যথা যদি (strcmp(arg, "no") == 0)
			মান = 0;
		অন্যথা {
			/* Pattern-list specified */
			মান = 1;
			p = xstrdup(arg);
		}
		যদি (*activep && *intptr == -1) {
			*intptr = মান;
			*charptr = p;
			p = রিক্ত;
		}
		মুক্ত(p);
		ভঙ্গ;

	পক্ষ sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		গচ্ছ parse_multistate;

	পক্ষ sRekeyLimit:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি (strcmp(arg, "default") == 0) {
			val64 = 0;
		} অন্যথা {
			যদি (scan_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, strerror(errno));
			যদি (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		যদি (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		যদি (ac != 0) { /* optional rekey interval present */
			যদি (strcmp(av[0], "none") == 0) {
				(শূন্য)argv_next(&ac, &av);	/* discard */
				ভঙ্গ;
			}
			intptr = &options->rekey_interval;
			গচ্ছ parse_time;
		}
		ভঙ্গ;

	পক্ষ sGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		multistate_ptr = multistate_gatewayports;
		গচ্ছ parse_multistate;

	পক্ষ sUseDNS:
		intptr = &options->use_dns;
		গচ্ছ parse_flag;

	পক্ষ sSyslogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		মান = log_facility_সংখ্যা(arg);
		যদি (মান == SYSLOG_FACILITY_NOT_SET)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		যদি (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) মান;
		ভঙ্গ;

	পক্ষ sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		মান = log_level_সংখ্যা(arg);
		যদি (মান == SYSLOG_LEVEL_NOT_SET)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		যদি (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) মান;
		ভঙ্গ;

	পক্ষ sLogVerbose:
		found = options->অঙ্ক_log_verbose == 0;
		যাবত্ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			যদি (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				গচ্ছ out;
			}
			/* Allow "none" only in first position */
			যদি (strcasecmp(arg, "none") == 0) {
				যদি (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					গচ্ছ out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		যদি (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		যদি (found && *activep) {
			options->log_verbose = strs;
			options->অঙ্ক_log_verbose = nstrs;
			strs = রিক্ত; /* transferred */
			nstrs = 0;
		}
		ভঙ্গ;

	পক্ষ sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		গচ্ছ parse_multistate;

	পক্ষ sAllowStreamLocalForwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		গচ্ছ parse_multistate;

	পক্ষ sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		গচ্ছ parse_flag;

	পক্ষ sAgentSocketPath:
		charptr = &options->agent_socket_path;
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		যদি (strncmp(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			যদি (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} অন্যথা যদি (strncmp(arg, "user:", 5) == 0) {
			/* User paths must not be empty */
			যদি (arg[5] == '\0') {
				fatal("%s line %d: invalid user path.",
				    filename, linenum);
			}
		} অন্যথা যদি (strcmp(arg, "none") != 0)
			fatal("%s line %d: invalid path.", filename, linenum);
		যদি (*activep && *charptr == রিক্ত)
			*charptr = xstrdup(arg);
		ভঙ্গ;

	পক্ষ sDisableForwarding:
		intptr = &options->disable_forwarding;
		গচ্ছ parse_flag;

	পক্ষ sAllowUsers:
		chararrayptr = &options->allow_users;
		uintptr = &options->অঙ্ক_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		যাবত্ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			যদি (*arg == '\0' ||
			    match_user(রিক্ত, রিক্ত, রিক্ত, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			found = 1;
			যদি (!*activep)
				অনুবর্ত;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		যদি (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ভঙ্গ;

	পক্ষ sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->অঙ্ক_deny_users;
		গচ্ছ parse_allowdenyusers;

	পক্ষ sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->অঙ্ক_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		যাবত্ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			যদি (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			found = 1;
			যদি (!*activep)
				অনুবর্ত;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		যদি (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ভঙ্গ;

	পক্ষ sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->অঙ্ক_deny_groups;
		গচ্ছ parse_allowdenygroups;

	পক্ষ sCiphers:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		যদি (options->ciphers == রিক্ত)
			options->ciphers = xstrdup(arg);
		ভঙ্গ;

	পক্ষ sMacs:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		যদি (options->macs == রিক্ত)
			options->macs = xstrdup(arg);
		ভঙ্গ;

	পক্ষ sKexAlgorithms:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		যদি (options->kex_algorithms == রিক্ত)
			options->kex_algorithms = xstrdup(arg);
		ভঙ্গ;

	পক্ষ sSubsystem:
		যদি ((arg = argv_next(&ac, &av)) == রিক্ত || *arg == '\0' ||
		   ((arg2 = argv_next(&ac, &av)) == রিক্ত || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি (!*activep) {
			argv_consume(&ac);
			ভঙ্গ;
		}
		found = 0;
		প্রতি (i = 0; i < options->অঙ্ক_subsystems; i++) {
			যদি (strcmp(arg, options->subsystem_name[i]) == 0) {
				found = 1;
				ভঙ্গ;
			}
		}
		যদি (found) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			ভঙ্গ;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->অঙ্ক_subsystems,
		    options->অঙ্ক_subsystems + 1,
		    পরিমাণ(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->অঙ্ক_subsystems,
		    options->অঙ্ক_subsystems + 1,
		    পরিমাণ(*options->subsystem_command));
		options->subsystem_args = xrecallocarray(
		    options->subsystem_args, options->অঙ্ক_subsystems,
		    options->অঙ্ক_subsystems + 1,
		    পরিমাণ(*options->subsystem_args));
		options->subsystem_name[options->অঙ্ক_subsystems] = xstrdup(arg);
		options->subsystem_command[options->অঙ্ক_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_args[options->অঙ্ক_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		মুক্ত(arg2);
		মুক্ত(arg);
		argv_consume(&ac);
		options->অঙ্ক_subsystems++;
		ভঙ্গ;

	পক্ষ sMaxStartups:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		যদি ((n = sscanf(arg, "%d:%d:%d",
		    &মান, &value2, &value3)) == 3) {
			যদি (মান > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} অন্যথা যদি (n == 1) {
			value3 = মান;
			value2 = -1;
		} অন্যথা {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		যদি (মান <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		যদি (*activep && options->max_startups == -1) {
			options->max_startups_begin = মান;
			options->max_startups_rate = value2;
			options->max_startups = value3;
		}
		ভঙ্গ;

	পক্ষ sPerSourceNetBlockSize:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		বিকল্প (n = sscanf(arg, "%d:%d", &মান, &value2)) {
		পক্ষ 2:
			যদি (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		পক্ষ 1:
			যদি (মান < 0 || মান > 32)
				n = -1;
		}
		যদি (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		যদি (*activep && options->per_source_masklen_ipv4 == -1) {
			options->per_source_masklen_ipv4 = মান;
			যদি (n == 2)
				options->per_source_masklen_ipv6 = value2;
		}
		ভঙ্গ;

	পক্ষ sPerSourceMaxStartups:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি (strcmp(arg, "none") == 0) { /* no limit */
			মান = INT_MAX;
		} অন্যথা {
			যদি ((errstr = atoi_err(arg, &মান)) != রিক্ত)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		যদি (*activep && options->per_source_max_startups == -1)
			options->per_source_max_startups = মান;
		ভঙ্গ;

	পক্ষ sPerSourcePenaltyExemptList:
		charptr = &options->per_source_penalty_exempt;
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		যদি (addr_match_list(রিক্ত, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		যদি (*activep && *charptr == রিক্ত)
			*charptr = xstrdup(arg);
		ভঙ্গ;

	পক্ষ sPerSourcePenalties:
		যাবত্ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			ধ্রুব বর্ণ *q = রিক্ত;

			found = 1;
			intptr = রিক্ত;
			doubleptr = রিক্ত;
			মান = -1;
			value2 = 0;
			/* Allow no/yes only in first position */
			যদি (strcasecmp(arg, "no") == 0 ||
			    (value2 = (strcasecmp(arg, "yes") == 0))) {
				যদি (ac > 0) {
					fatal("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
				}
				যদি (*activep &&
				    options->per_source_penalty.enabled == -1)
					options->per_source_penalty.enabled = value2;
				অনুবর্ত;
			} অন্যথা যদি ((q = strprefix(arg, "crash:", 0)) != রিক্ত) {
				doubleptr = &options->per_source_penalty.penalty_crash;
			} অন্যথা যদি ((q = strprefix(arg, "authfail:", 0)) != রিক্ত) {
				doubleptr = &options->per_source_penalty.penalty_authfail;
			} অন্যথা যদি ((q = strprefix(arg, "invaliduser:", 0)) != রিক্ত) {
				doubleptr = &options->per_source_penalty.penalty_invaliduser;
			} অন্যথা যদি ((q = strprefix(arg, "noauth:", 0)) != রিক্ত) {
				doubleptr = &options->per_source_penalty.penalty_noauth;
			} অন্যথা যদি ((q = strprefix(arg, "grace-exceeded:", 0)) != রিক্ত) {
				doubleptr = &options->per_source_penalty.penalty_grace;
			} অন্যথা যদি ((q = strprefix(arg, "refuseconnection:", 0)) != রিক্ত) {
				doubleptr = &options->per_source_penalty.penalty_refuseconnection;
			} অন্যথা যদি ((q = strprefix(arg, "max:", 0)) != রিক্ত) {
				doubleptr = &options->per_source_penalty.penalty_max;
			} অন্যথা যদি ((q = strprefix(arg, "min:", 0)) != রিক্ত) {
				doubleptr = &options->per_source_penalty.penalty_min;
			} অন্যথা যদি ((q = strprefix(arg, "max-sources4:", 0)) != রিক্ত) {
				intptr = &options->per_source_penalty.max_sources4;
				যদি ((errstr = atoi_err(q, &মান)) != রিক্ত)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} অন্যথা যদি ((q = strprefix(arg, "max-sources6:", 0)) != রিক্ত) {
				intptr = &options->per_source_penalty.max_sources6;
				যদি ((errstr = atoi_err(q, &মান)) != রিক্ত)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} অন্যথা যদি (strcmp(arg, "overflow:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				মান = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} অন্যথা যদি (strcmp(arg, "overflow:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				মান = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} অন্যথা যদি (strcmp(arg, "overflow6:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				মান = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} অন্যথা যদি (strcmp(arg, "overflow6:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				মান = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} অন্যথা {
				fatal("%s line %d: unsupported %s keyword %s",
				    filename, linenum, keyword, arg);
			}

			যদি (doubleptr != রিক্ত) {
				যদি ((dvalue = convtime_double(q)) < 0) {
					fatal("%s line %d: invalid %s time value.",
					    filename, linenum, keyword);
				}
				যদি (*activep && *doubleptr < 0.0) {
					*doubleptr = dvalue;
					options->per_source_penalty.enabled = 1;
				}
			} অন্যথা যদি (intptr != রিক্ত) {
				যদি (*activep && *intptr == -1) {
					*intptr = মান;
					options->per_source_penalty.enabled = 1;
				}
			} অন্যথা {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		যদি (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ভঙ্গ;

	পক্ষ sMaxAuthTries:
		intptr = &options->max_authtries;
		গচ্ছ parse_int;

	পক্ষ sMaxSessions:
		intptr = &options->max_sessions;
		গচ্ছ parse_int;

	পক্ষ sBanner:
		charptr = &options->banner;
		গচ্ছ parse_filename;

	/*
	 * These options can contain %X options expanded at
	 * connect time, so that you can specify paths like:
	 *
	 * AuthorizedKeysFile	/etc/ssh_keys/%u
	 */
	পক্ষ s_Authorized_চাবিগুলি_File:
		uintptr = &options->অঙ্ক_authkeys_files;
		chararrayptr = &options->authorized_চাবিগুলি_files;
 parse_filenames:
		found = *uintptr == 0;
		যাবত্ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			যদি (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				গচ্ছ out;
			}
			/* Allow "none" only in first position */
			যদি (strcasecmp(arg, "none") == 0) {
				যদি (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					গচ্ছ out;
				}
			}
			arg2 = tilde_expand_filename(arg, getuid());
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			মুক্ত(arg2);
		}
		যদি (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		যদি (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = রিক্ত; /* transferred */
			nstrs = 0;
		}
		ভঙ্গ;

	পক্ষ sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি (*activep && *charptr == রিক্ত) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			যদি (intptr != রিক্ত)
				*intptr = *intptr + 1;
		}
		ভঙ্গ;

	পক্ষ sClientAliveInterval:
		intptr = &options->client_alive_interval;
		গচ্ছ parse_time;

	পক্ষ s_Client_Alive_গুনতি_Max:
		intptr = &options->client_alive_গুনতি_max;
		গচ্ছ parse_int;

	পক্ষ sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		যাবত্ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			যদি (*arg == '\0' || strchr(arg, '=') != রিক্ত)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			found = 1;
			যদি (!*activep)
				অনুবর্ত;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->অঙ্ক_accept_env,
			    arg);
		}
		যদি (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ভঙ্গ;

	পক্ষ sSetEnv:
		found = options->অঙ্ক_setenv == 0;
		যাবত্ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			যদি (*arg == '\0' || strchr(arg, '=') == রিক্ত)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			যদি (lookup_setenv_in_list(arg, strs, nstrs) != রিক্ত) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				অনুবর্ত;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		যদি (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		যদি (found && *activep) {
			options->setenv = strs;
			options->অঙ্ক_setenv = nstrs;
			strs = রিক্ত; /* transferred */
			nstrs = 0;
		}
		ভঙ্গ;

	পক্ষ sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		মান = -1;
		প্রতি (i = 0; tunmode_desc[i].val != -1; i++)
			যদি (strcmp(tunmode_desc[i].text, arg) == 0) {
				মান = tunmode_desc[i].val;
				ভঙ্গ;
			}
		যদি (মান == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		যদি (*activep && *intptr == -1)
			*intptr = মান;
		ভঙ্গ;

	পক্ষ sInclude:
		যদি (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		মান = 0;
		যাবত্ ((arg2 = argv_next(&ac, &av)) != রিক্ত) {
			যদি (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				গচ্ছ out;
			}
			মান++;
			found = 0;
			যদি (*arg2 != '/' && *arg2 != '~') {
				xasprintf(&arg, "%s/%s", SSHDIR, arg2);
			} অন্যথা
				arg = xstrdup(arg2);

			/*
			 * Don't let included files clobber the containing
			 * file's Match state.
			 */
			oactive = *activep;

			/* consult cache of include files */
			TAILQ_FOREACH(item, includes, entry) {
				যদি (strcmp(item->selector, arg) != 0)
					অনুবর্ত;
				যদি (item->filename != রিক্ত) {
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
			যদি (found != 0) {
				মুক্ত(arg);
				অনুবর্ত;
			}

			/* requested glob was not in cache */
			debug2("%s line %d: new include %s",
			    filename, linenum, arg);
			যদি ((r = glob(arg, 0, রিক্ত, &gbuf)) != 0) {
				যদি (r != GLOB_NOMATCH) {
					fatal("%s line %d: include \"%s\" glob "
					    "failed", filename, linenum, arg);
				}
				/*
				 * If no entry matched then record a
				 * placeholder to skip later glob calls.
				 */
				debug2("%s line %d: no match for %s",
				    filename, linenum, arg);
				item = xcalloc(1, পরিমাণ(*item));
				item->selector = xstrdup(arg);
				TAILQ_INSERT_TAIL(includes,
				    item, entry);
			}
			যদি (gbuf.gl_pathc > INT_MAX)
				fatal_f("too many glob results");
			প্রতি (n = 0; n < (পূর্ণাঙ্ক)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				item = xcalloc(1, পরিমাণ(*item));
				item->selector = xstrdup(arg);
				item->filename = xstrdup(gbuf.gl_pathv[n]);
				যদি ((item->contents = sshbuf_new()) == রিক্ত)
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
			মুক্ত(arg);
		}
		যদি (মান == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		ভঙ্গ;

	পক্ষ sMatch:
		যদি (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		মান = match_cfg_সারি(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? রিক্ত : connectinfo));
		যদি (মান < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : মান;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_MATCH_ONLY;
		ভঙ্গ;

	পক্ষ sPermitListen:
	পক্ষ sPermitOpen:
		যদি (opcode == sPermitListen) {
			uintptr = &options->অঙ্ক_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} অন্যথা {
			uintptr = &options->অঙ্ক_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		found = *uintptr == 0;
		যাবত্ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			যদি (strcmp(arg, "any") == 0 ||
			    strcmp(arg, "none") == 0) {
				যদি (nstrs != 0) {
					fatal("%s line %d: %s must appear "
					    "alone on a %s line.",
					    filename, linenum, arg, keyword);
				}
				opt_array_append(filename, linenum, keyword,
				    &strs, &nstrs, arg);
				অনুবর্ত;
			}

			যদি (opcode == sPermitListen &&
			    strchr(arg, ':') == রিক্ত) {
				/*
				 * Allow bare port number for PermitListen
				 * to indicate a wildcard listen host.
				 */
				xasprintf(&arg2, "*:%s", arg);
			} অন্যথা {
				arg2 = xstrdup(arg);
				p = hpdelim(&arg);
				যদি (p == রিক্ত) {
					fatal("%s line %d: %s missing host",
					    filename, linenum, keyword);
				}
				p = cleanhostname(p);
			}
			যদি (arg == রিক্ত ||
			    ((port = permitopen_port(arg)) < 0)) {
				fatal("%s line %d: %s bad port number",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			মুক্ত(arg2);
		}
		যদি (nstrs == 0) {
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		}
		যদি (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = রিক্ত; /* transferred */
			nstrs = 0;
		}
		ভঙ্গ;

	পক্ষ sForceCommand:
		যদি (str == রিক্ত || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		যদি (*activep && options->adm_forced_command == রিক্ত)
			options->adm_forced_command = xstrdup(str + len);
		argv_consume(&ac);
		ভঙ্গ;

	পক্ষ sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি (*activep && *charptr == রিক্ত)
			*charptr = xstrdup(arg);
		ভঙ্গ;

	পক্ষ sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_চাবিগুলি;
		গচ্ছ parse_filename;

	পক্ষ s_Revoked_চাবিগুলি:
		uintptr = &options->অঙ্ক_revoked_চাবিগুলি_files;
		chararrayptr = &options->revoked_চাবিগুলি_files;
		গচ্ছ parse_filenames;

	পক্ষ s_Security_চাবি_Provider:
		charptr = &options->sk_provider;
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি (*activep && *charptr == রিক্ত) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_path(arg);
			/* increase optional counter */
			যদি (intptr != রিক্ত)
				*intptr = *intptr + 1;
		}
		ভঙ্গ;

	পক্ষ sIPQoS:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি ((মান = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		যদি (মান == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			মান = INT_MAX;
		}
		arg = argv_next(&ac, &av);
		যদি (arg == রিক্ত)
			value2 = মান;
		অন্যথা যদি ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		যদি (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		যদি (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = মান;
			options->ip_qos_bulk = value2;
		}
		ভঙ্গ;

	পক্ষ sVersionAddendum:
		যদি (str == রিক্ত || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		যদি (strchr(str + len, '\r') != রিক্ত) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		যদি ((arg = strchr(সারি, '#')) != রিক্ত) {
			*arg = '\0';
			rtrim(সারি);
		}
		যদি (*activep && options->version_addendum == রিক্ত) {
			যদি (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			অন্যথা
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		ভঙ্গ;

	পক্ষ s_Authorized_চাবিগুলি_Command:
		charptr = &options->authorized_চাবিগুলি_command;
 parse_command:
		len = strspn(str, WHITESPACE);
		যদি (str[len] != '/' && strcasecmp(str + len, "none") != 0) {
			fatal("%.200s line %d: %s must be an absolute path",
			    filename, linenum, keyword);
		}
		যদি (*activep && *charptr == রিক্ত)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		ভঙ্গ;

	পক্ষ s_Authorized_চাবিগুলি_Command_User:
		charptr = &options->authorized_চাবিগুলি_command_user;
 parse_localuser:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			fatal("%s line %d: missing %s argument.",
			    filename, linenum, keyword);
		}
		যদি (*activep && *charptr == রিক্ত)
			*charptr = xstrdup(arg);
		ভঙ্গ;

	পক্ষ sAuthorizedPrincipalsCommand:
		charptr = &options->authorized_principals_command;
		গচ্ছ parse_command;

	পক্ষ sAuthorizedPrincipalsCommandUser:
		charptr = &options->authorized_principals_command_user;
		গচ্ছ parse_localuser;

	পক্ষ sAuthenticationMethods:
		found = options->অঙ্ক_auth_methods == 0;
		মান = 0; /* seen "any" pseudo-method */
		যাবত্ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			যদি (strcmp(arg, "any") == 0) {
				যদি (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				মান = 1;
			} অন্যথা যদি (মান) {
				fatal("%s line %d: \"any\" must appear "
				    "alone in %s", filename, linenum, keyword);
			} অন্যথা যদি (auth2_methods_valid(arg, 0) != 0) {
				fatal("%s line %d: invalid %s method list.",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		যদি (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		যদি (found && *activep) {
			options->auth_methods = strs;
			options->অঙ্ক_auth_methods = nstrs;
			strs = রিক্ত; /* transferred */
			nstrs = 0;
		}
		ভঙ্গ;

	পক্ষ sStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		মান = strtol(arg, &p, 8);
		যদি (arg == p || মান < 0 || মান > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		যদি (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)মান;
		ভঙ্গ;

	পক্ষ sStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		গচ্ছ parse_flag;

	পক্ষ sFingerprintHash:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি ((মান = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		যদি (*activep)
			options->fingerprint_hash = মান;
		ভঙ্গ;

	পক্ষ sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		গচ্ছ parse_flag;

	পক্ষ sRDomain:
#যদি !defined(__OpenBSD__) && !defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#endif
		charptr = &options->routing_domain;
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		যদি (strcasecmp(arg, "none") != 0 && strcmp(arg, "%D") != 0 &&
		    !valid_rdomain(arg))
			fatal("%s line %d: invalid routing domain",
			    filename, linenum);
		যদি (*activep && *charptr == রিক্ত)
			*charptr = xstrdup(arg);
		ভঙ্গ;

	পক্ষ sRequiredRSASize:
		intptr = &options->required_rsa_size;
		গচ্ছ parse_int;

	পক্ষ sChannelTimeout:
		found = options->অঙ্ক_channel_timeouts == 0;
		যাবত্ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			/* Allow "none" only in first position */
			যদি (strcasecmp(arg, "none") == 0) {
				যদি (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					গচ্ছ out;
				}
			} অন্যথা যদি (parse_pattern_interval(arg,
			    রিক্ত, রিক্ত) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		যদি (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		যদি (found && *activep) {
			options->channel_timeouts = strs;
			options->অঙ্ক_channel_timeouts = nstrs;
			strs = রিক্ত; /* transferred */
			nstrs = 0;
		}
		ভঙ্গ;

	পক্ষ sUnusedConnectionTimeout:
		intptr = &options->unused_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		যদি (av[0] != রিক্ত && strcasecmp(av[0], "none") == 0) {
			(শূন্য)argv_next(&ac, &av); /* consume arg */
			যদি (*activep)
				*intptr = 0;
			ভঙ্গ;
		}
		গচ্ছ parse_time;

	পক্ষ sSshdSessionPath:
		charptr = &options->sshd_session_path;
		গচ্ছ parse_filename;

	পক্ষ sSshdAuthPath:
		charptr = &options->sshd_auth_path;
		গচ্ছ parse_filename;

	পক্ষ sRefuseConnection:
		intptr = &options->refuse_connection;
		multistate_ptr = multistate_flag;
		গচ্ছ parse_multistate;

	পক্ষ sWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		গচ্ছ parse_multistate;

	পক্ষ sDeprecated:
	পক্ষ sIgnore:
	পক্ষ sUnsupported:
		do_log2(opcode == sIgnore ?
		    SYSLOG_LEVEL_DEBUG2 : SYSLOG_LEVEL_INFO,
		    "%s line %d: %s option %s", filename, linenum,
		    opcode == sUnsupported ? "Unsupported" : "Deprecated",
		    keyword);
		argv_consume(&ac);
		ভঙ্গ;

	স্বভাব:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, keyword, opcode);
	}
	/* Check that there is no garbage at end of line. */
	যদি (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		গচ্ছ out;
	}

	/* success */
	ret = 0;
 out:
	opt_array_free2(strs, রিক্ত, nstrs);
	argv_free(oav, oac);
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
process_server_config_সারি(ServerOptions *options, বর্ণ *সারি,
    ধ্রুব বর্ণ *filename, পূর্ণাঙ্ক linenum, পূর্ণাঙ্ক *activep,
    সংরচনা connection_info *connectinfo, সংরচনা include_list *includes)
{
	পূর্ণাঙ্ক inc_flags = 0;

	প্রত্যাগম process_server_config_সারি_depth(options, সারি, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

শূন্য
load_server_config(ধ্রুব বর্ণ *filename, সংরচনা sshbuf *conf)
{
	সংরচনা stat st;
	বর্ণ *সারি = রিক্ত, *cp;
	size_t linesize = 0;
	FILE *f;
	পূর্ণাঙ্ক r;

	debug2_f("filename %s", filename);
	যদি ((f = fopen(filename, "r")) == রিক্ত) {
		perror(filename);
		exit(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	যদি (fstat(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	যাবত্ (getline(&সারি, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = সারি + strspn(সারি, " \t\r");
		যদি ((r = sshbuf_put(conf, cp, strlen(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	মুক্ত(সারি);
	যদি ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	fclose(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

শূন্য
parse_server_match_config(ServerOptions *options,
   সংরচনা include_list *includes, সংরচনা connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_set_server_options(options, &mo, 0);
	free_server_options(&mo);
}

পূর্ণাঙ্ক
parse_server_match_testspec(সংরচনা connection_info *ci, বর্ণ *spec)
{
	বর্ণ *p;
	ধ্রুব বর্ণ *val;

	যাবত্ ((p = strsep(&spec, ",")) && *p != '\0') {
		যদি ((val = strprefix(p, "addr=", 0)) != রিক্ত) {
			ci->address = xstrdup(val);
		} অন্যথা যদি ((val = strprefix(p, "host=", 0)) != রিক্ত) {
			ci->host = xstrdup(val);
		} অন্যথা যদি ((val = strprefix(p, "user=", 0)) != রিক্ত) {
			ci->user = xstrdup(val);
		} অন্যথা যদি ((val = strprefix(p, "laddr=", 0)) != রিক্ত) {
			ci->laddress = xstrdup(val);
		} অন্যথা যদি ((val = strprefix(p, "rdomain=", 0)) != রিক্ত) {
			ci->rdomain = xstrdup(val);
		} অন্যথা যদি ((val = strprefix(p, "lport=", 0)) != রিক্ত) {
			ci->lport = a2port(val);
			যদি (ci->lport == -1) {
				fprintf(stderr, "Invalid port '%s' in test mode"
				    " specification %s\n", p+6, p);
				প্রত্যাগম -1;
			}
		} অন্যথা যদি (strcmp(p, "invalid-user") == 0) {
			ci->user_invalid = 1;
		} অন্যথা {
			fprintf(stderr, "Invalid test mode specification %s\n",
			    p);
			প্রত্যাগম -1;
		}
	}
	প্রত্যাগম 0;
}

শূন্য
servconf_merge_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, found;

	প্রতি (i = 0; i < src->অঙ্ক_subsystems; i++) {
		found = 0;
		প্রতি (j = 0; j < dst->অঙ্ক_subsystems; j++) {
			যদি (strcmp(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				found = 1;
				ভঙ্গ;
			}
		}
		যদি (found) {
			debug_f("override \"%s\"", dst->subsystem_name[j]);
			মুক্ত(dst->subsystem_command[j]);
			মুক্ত(dst->subsystem_args[j]);
			dst->subsystem_command[j] =
			    xstrdup(src->subsystem_command[i]);
			dst->subsystem_args[j] =
			    xstrdup(src->subsystem_args[i]);
			অনুবর্ত;
		}
		debug_f("add \"%s\"", src->subsystem_name[i]);
		dst->subsystem_name = xrecallocarray(
		    dst->subsystem_name, dst->অঙ্ক_subsystems,
		    dst->অঙ্ক_subsystems + 1, পরিমাণ(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->অঙ্ক_subsystems,
		    dst->অঙ্ক_subsystems + 1, পরিমাণ(*dst->subsystem_command));
		dst->subsystem_args = xrecallocarray(
		    dst->subsystem_args, dst->অঙ্ক_subsystems,
		    dst->অঙ্ক_subsystems + 1, পরিমাণ(*dst->subsystem_args));
		j = dst->অঙ্ক_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_args[j] = xstrdup(src->subsystem_args[i]);
	}
}

স্থির পূর্ণাঙ্ক
serialise_s32(সংরচনা sshbuf *buf, পূর্ণাঙ্ক v)
{
	uint32_t uv;
	পূর্ণাঙ্ক r;

	uv = v < 0 ? (uint32_t)(-(v + 1)) + 1 : (uint32_t)v;
	যদি ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u32(buf, uv)) != 0)
		প্রত্যাগম r;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
serialise_s64(সংরচনা sshbuf *buf, int64_t v)
{
	uint64_t uv;
	পূর্ণাঙ্ক r;

	uv = v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
	যদি ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u64(buf, uv)) != 0)
		প্রত্যাগম r;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
serialise_mode(সংরচনা sshbuf *buf, mode_t v)
{
	u_int uv;

	যদি (v == (mode_t)-1)
		প্রত্যাগম serialise_s32(buf, -1);
	uv = (u_int)v;
	যদি ((mode_t)uv != v || uv > 0777)
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	প্রত্যাগম serialise_s32(buf, (পূর্ণাঙ্ক)uv);
}

স্থির পূর্ণাঙ্ক
serialise_double(সংরচনা sshbuf *buf, দ্বিগুণ v)
{
	/*
	 * XXX this is no good for a wire encoding.
	 * It's fine for passing configurations via RPC, but it would
	 * be nicer to have an exact binary encoding here.
	 */
	প্রত্যাগম sshbuf_put(buf, &v, পরিমাণ(v));
}

স্থির পূর্ণাঙ্ক
serialise_nullable_string(সংরচনা sshbuf *buf, ধ্রুব বর্ণ *s)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_put_u8(buf, s != রিক্ত)) != 0)
		প্রত্যাগম r;
	যদি (s == রিক্ত)
		প্রত্যাগম 0;
	প্রত্যাগম sshbuf_put_cstring(buf, s);
}

স্থির পূর্ণাঙ্ক
serialise_nullable_string_array(সংরচনা sshbuf *buf, বর্ণ **a, u_int n)
{
	পূর্ণাঙ্ক r;
	u_int i;

	যদি ((r = sshbuf_put_u32(buf, n)) != 0)
		প্রত্যাগম r;
	প্রতি (i = 0; i < n; i++) {
		যদি ((r = serialise_nullable_string(buf, a[i])) != 0)
			প্রত্যাগম r;
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
serialise_hostkeyfile(ধ্রুব ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;
	u_int i;

	যদি ((r = sshbuf_put_u32(buf, options->অঙ্ক_host_চাবি_files)) != 0) {
		error_fr(r, "serialise length");
		প্রত্যাগম r;
	}
	প্রতি (i = 0; i < options->অঙ্ক_host_চাবি_files; i++) {
		যদি ((r = serialise_s32(buf,
		    options->host_চাবি_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_চাবি_files[i])) != 0) {
			error_fr(r, "serialise member");
			প্রত্যাগম r;
		}
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
serialise_ipqos(ধ্রুব ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = serialise_s32(buf, options->ip_qos_interactive)) != 0 ||
	    (r = serialise_s32(buf, options->ip_qos_bulk)) != 0) {
		error_fr(r, "serialise");
		প্রত্যাগম r;
	}

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
serialise_listenaddress(ধ্রুব ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;
	u_int i;

	/* Note: only serialises queued listen addresses */
	যদি ((r = sshbuf_put_u32(buf, options->অঙ্ক_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		প্রত্যাগম r;
	}
	প্রতি (i = 0; i < options->অঙ্ক_queued_listens; i++) {
		ধ্রুব সংরচনা queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		যদি ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->port)) != 0 ||
		    (r = serialise_nullable_string(buf, qla->rdomain)) != 0) {
			error_fr(r, "serialise member");
			প্রত্যাগম r;
		}
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
serialise_logfacility(ধ্রুব ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = serialise_s32(buf, (পূর্ণাঙ্ক)options->log_facility)) != 0) {
		error_fr(r, "serialise");
		প্রত্যাগম r;
	}

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
serialise_loglevel(ধ্রুব ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = serialise_s32(buf, (পূর্ণাঙ্ক)options->log_level)) != 0) {
		error_fr(r, "serialise");
		প্রত্যাগম r;
	}

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
serialise_port(ধ্রুব ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;
	u_int i;

	যদি ((r = sshbuf_put_u32(buf, options->অঙ্ক_ports)) != 0) {
		error_fr(r, "serialise length");
		প্রত্যাগম r;
	}
	প্রতি (i = 0; i < options->অঙ্ক_ports; i++) {
		যদি ((r = serialise_s32(buf, options->ports[i])) != 0) {
			error_fr(r, "serialise port");
			প্রত্যাগম r;
		}
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
serialise_gatewayports(ধ্রুব ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = serialise_s32(buf, options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "serialise");
		প্রত্যাগম r;
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
serialise_streamlocalbindmask(ধ্রুব ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = serialise_mode(buf,
	    options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "serialise");
		প্রত্যাগম r;
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
serialise_streamlocalbindunlink(ধ্রুব ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_put_u8(buf,
	    (options->fwd_opts.streamlocal_bind_unlink != 0))) != 0) {
		error_fr(r, "serialise");
		প্রত্যাগম r;
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
serialise_maxstartups(ধ্রুব ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = serialise_s32(buf, options->max_startups_begin)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups_rate)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups)) != 0) {
		error_fr(r, "serialise");
		প্রত্যাগম r;
	}

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
serialise_permituserenv(ধ্রুব ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = serialise_s32(buf, options->permit_user_env)) != 0 ||
	    (r = serialise_nullable_string(buf,
	    options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "serialise");
		প্রত্যাগম r;
	}

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
serialise_persourcenetblocksize(ধ্রুব ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = serialise_s32(buf, options->per_source_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		প্রত্যাগম r;
	}

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
serialise_persourcepenalties(ধ্রুব ServerOptions *options, সংরচনা sshbuf *buf)
{
	ধ্রুব সংরচনা per_source_penalty *psp = &options->per_source_penalty;
	পূর্ণাঙ্ক r;

	যদি ((r = serialise_s32(buf, psp->enabled)) != 0 ||
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
		প্রত্যাগম r;
	}

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
serialise_rekeylimit(ধ্রুব ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = serialise_s64(buf, options->rekey_limit)) != 0 ||
	    (r = serialise_s32(buf, options->rekey_interval)) != 0) {
		error_fr(r, "serialise");
		প্রত্যাগম r;
	}

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
serialise_subsystem(ধ্রুব ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;
	u_int i;

	যদি ((r = sshbuf_put_u32(buf, options->অঙ্ক_subsystems)) != 0) {
		error_fr(r, "serialise length");
		প্রত্যাগম r;
	}
	প্রতি (i = 0; i < options->অঙ্ক_subsystems; i++) {
		যদি ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_args[i])) != 0) {
			error_fr(r, "serialise member");
			প্রত্যাগম r;
		}
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
serialise_pubkey_auth_options(ধ্রুব ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = serialise_s32(buf, options->pubkey_auth_options)) != 0 ||
	    (r = serialise_s32(buf, options->max_pubkey_ok)) != 0) {
		error_fr(r, "serialise");
		প্রত্যাগম r;
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
serialise_timingsecret(ধ্রুব ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_put_u64(buf, options->timing_secret)) != 0) {
		error_fr(r, "serialise");
		প্রত্যাগম r;
	}
	প্রত্যাগম 0;
}


পূর্ণাঙ্ক
serialise_server_options(ধ্রুব ServerOptions *options, সংরচনা sshbuf **bufp)
{
	সংরচনা sshbuf *buf = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	*bufp = রিক্ত;

	যদি ((buf = sshbuf_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_VERSION)) != 0) {
		error_fr(r, "serialise version");
		গচ্ছ out;
	}

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	যদি ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		গচ্ছ out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	যদি ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		গচ্ছ out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	যদি ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		গচ্ছ out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	যদি ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		গচ্ছ out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	যদি ((r = serialise_##funcsuffix(options, buf)) != 0) \
		গচ্ছ out;
#define SSHCONF_NONCONF(funcsuffix) \
	যদি ((r = serialise_##funcsuffix(options, buf)) != 0) \
		গচ্ছ out;
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
	buf = রিক্ত; /* transferred */
 out:
	sshbuf_free(buf);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
deserialise_s32(সংরচনা sshbuf *buf, পূর্ণাঙ্ক *v)
{
	uint32_t tmp;
	পূর্ণাঙ্ক r;
	u_char was_signed;

	যদি ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u32(buf, &tmp)) != 0)
		প্রত্যাগম r;
	যদি (was_signed > 1)
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	যদি (was_signed) {
		যদি (tmp > (uint32_t)INT_MAX + 1)
			প্রত্যাগম SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)INT_MAX + 1 ? INT_MIN : -(পূর্ণাঙ্ক)tmp;
	} অন্যথা {
		যদি (tmp > INT_MAX)
			প্রত্যাগম SSH_ERR_INVALID_FORMAT;
		*v = (পূর্ণাঙ্ক)tmp;
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_s64(সংরচনা sshbuf *buf, int64_t *v)
{
	uint64_t tmp;
	পূর্ণাঙ্ক r;
	u_char was_signed;

	যদি ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u64(buf, &tmp)) != 0)
		প্রত্যাগম r;
	যদি (was_signed > 1)
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	যদি (was_signed) {
		যদি (tmp > (uint64_t)INT64_MAX + 1)
			প্রত্যাগম SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint64_t)INT64_MAX + 1 ?
		    INT64_MIN : -(int64_t)tmp;
	} অন্যথা {
		যদি (tmp > INT64_MAX)
			প্রত্যাগম SSH_ERR_INVALID_FORMAT;
		*v = (int64_t)tmp;
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_mode(সংরচনা sshbuf *buf, mode_t *v)
{
	পূর্ণাঙ্ক r, tmp;

	যদি ((r = deserialise_s32(buf, &tmp)) != 0)
		প্রত্যাগম r;
	যদি (tmp == -1) {
		*v = (mode_t)-1;
		প্রত্যাগম 0;
	}
	যদি (tmp < 0 || tmp > 0777)
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	*v = (mode_t)tmp;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_double(সংরচনা sshbuf *buf, দ্বিগুণ *v)
{
	প্রত্যাগম sshbuf_get(buf, v, পরিমাণ(*v));
}

স্থির পূর্ণাঙ্ক
deserialise_nullable_string(সংরচনা sshbuf *buf, বর্ণ **sp)
{
	পূর্ণাঙ্ক r;
	u_char present;

	যদি ((r = sshbuf_get_u8(buf, &present)) != 0)
		প্রত্যাগম r;
	যদি (present == 0) {
		*sp = রিক্ত;
		প্রত্যাগম 0;
	}
	যদি (present != 1)
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	প্রত্যাগম sshbuf_get_cstring(buf, sp, রিক্ত);
}

স্থির শূন্য
free_string_array(বর্ণ **a, u_int n)
{
	u_int i;

	যদি (a == রিক্ত)
		প্রত্যাগম;
	প্রতি (i = 0; i < n; i++)
		মুক্ত(a[i]);
	মুক্ত(a);
}

স্থির পূর্ণাঙ্ক
deserialise_গুনতি(সংরচনা sshbuf *buf, u_int *np, ধ্রুব বর্ণ *what)
{
	পূর্ণাঙ্ক r;
	uint32_t n;

	যদি ((r = sshbuf_get_u32(buf, &n)) != 0) {
		error_fr(r, "deserialise %s length", what);
		প্রত্যাগম r;
	}
	যদি (n > UINT_MAX) {
		error_f("bad number of %s", what);
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	}
	যদি (n > sshbuf_len(buf)) {
		error_f("bad number of %s", what);
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	}
	*np = n;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_nullable_string_array(সংরচনা sshbuf *buf, বর্ণ ***arrayp,
    u_int *np)
{
	বর্ণ **a = রিক্ত;
	পূর্ণাঙ্ক r;
	u_int i, n;

	*arrayp = রিক্ত;
	*np = 0;
	যদি ((r = deserialise_গুনতি(buf, &n, "strings")) != 0)
		প্রত্যাগম r;
	যদি (n > 0)
		a = xcalloc(n, পরিমাণ(*a));
	প্রতি (i = 0; i < n; i++) {
		যদি ((r = deserialise_nullable_string(buf, a + i)) != 0) {
			free_string_array(a, i + 1);
			প্রত্যাগম r;
		}
	}
	*arrayp = a;
	*np = n;
	প্রত্যাগম 0;
}

স্থির শূন্য
free_queued_listen_addrs(সংরচনা queued_listenaddr *qla, u_int n)
{
	u_int i;

	যদি (qla == রিক্ত)
		প্রত্যাগম;
	প্রতি (i = 0; i < n; i++) {
		মুক্ত(qla[i].addr);
		মুক্ত(qla[i].rdomain);
	}
	মুক্ত(qla);
}

স্থির পূর্ণাঙ্ক
deserialise_hostkeyfile(ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r, *userprovided = রিক্ত;
	u_int i, n;
	বর্ণ **files = রিক্ত;

	যদি ((r = deserialise_গুনতি(buf, &n, "host key files")) != 0)
		প্রত্যাগম r;
	যদি (n > 0) {
		userprovided = xcalloc(n, পরিমাণ(*userprovided));
		files = xcalloc(n, পরিমাণ(*files));
	}
	প্রতি (i = 0; i < n; i++) {
		যদি ((r = deserialise_s32(buf, userprovided + i)) != 0 ||
		    (r = deserialise_nullable_string(buf, files + i)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(files, i + 1);
			মুক্ত(userprovided);
			প্রত্যাগম r;
		}
	}
	options->অঙ্ক_host_চাবি_files = n;
	options->host_চাবি_file_userprovided = userprovided;
	options->host_চাবি_files = files;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_ipqos(ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = deserialise_s32(buf, &options->ip_qos_interactive)) != 0 ||
	    (r = deserialise_s32(buf, &options->ip_qos_bulk)) != 0) {
		error_fr(r, "deserialise");
		প্রত্যাগম r;
	}

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_listenaddress(ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;
	u_int i, n;
	সংরচনা queued_listenaddr *qla = রিক্ত;

	যদি ((r = deserialise_গুনতি(buf, &n, "listen addresses")) != 0)
		প্রত্যাগম r;
	যদি (n > 0)
		qla = xcalloc(n, পরিমাণ(*qla));
	প্রতি (i = 0; i < n; i++) {
		যদি ((r = sshbuf_get_cstring(buf, &qla[i].addr, রিক্ত)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].port)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			প্রত্যাগম r;
		}
	}
	options->অঙ্ক_queued_listens = n;
	options->queued_listen_addrs = qla;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_logfacility(ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r, tmp;

	যদি ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		প্রত্যাগম r;
	}
	যদি (tmp != SYSLOG_FACILITY_NOT_SET &&
	    log_facility_name((SyslogFacility)tmp) == রিক্ত) {
		error_f("bad syslog facility");
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	}
	options->log_facility = (SyslogFacility)tmp;

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_loglevel(ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r, tmp;

	যদি ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		প্রত্যাগম r;
	}
	যদি (tmp != SYSLOG_LEVEL_NOT_SET &&
	    log_level_name((LogLevel)tmp) == রিক্ত) {
		error_f("bad log level");
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_port(ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;
	u_int i, n;

	যদি ((r = deserialise_গুনতি(buf, &n, "ports")) != 0)
		প্রত্যাগম r;
	যদি (n > MAX_PORTS) {
		error_f("bad number of ports");
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	}
	options->অঙ্ক_ports = n;
	memset(options->ports, 0, পরিমাণ(options->ports));
	প্রতি (i = 0; i < options->অঙ্ক_ports; i++) {
		যদি ((r = deserialise_s32(buf, options->ports + i)) != 0) {
			error_fr(r, "deserialise port");
			প্রত্যাগম r;
		}
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_gatewayports(ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = deserialise_s32(buf, &options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "deserialise");
		প্রত্যাগম r;
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_streamlocalbindmask(ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = deserialise_mode(buf,
	    &options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "deserialise");
		প্রত্যাগম r;
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_streamlocalbindunlink(ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;
	u_char tmp;

	যদি ((r = sshbuf_get_u8(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		প্রত্যাগম r;
	}
	যদি (tmp > 1) {
		error_f("bad boolean");
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	}
	options->fwd_opts.streamlocal_bind_unlink = tmp;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_maxstartups(ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = deserialise_s32(buf, &options->max_startups_begin)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups_rate)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups)) != 0) {
		error_fr(r, "deserialise");
		প্রত্যাগম r;
	}

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_permituserenv(ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = deserialise_s32(buf, &options->permit_user_env)) != 0 ||
	    (r = deserialise_nullable_string(buf,
	    &options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "deserialise");
		প্রত্যাগম r;
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_persourcenetblocksize(ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		প্রত্যাগম r;
	}

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_persourcepenalties(ServerOptions *options, সংরচনা sshbuf *buf)
{
	সংরচনা per_source_penalty *psp = &options->per_source_penalty;
	পূর্ণাঙ্ক r;

	যদি ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
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
		প্রত্যাগম r;
	}

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_rekeylimit(ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = deserialise_s64(buf, &options->rekey_limit)) != 0 ||
	    (r = deserialise_s32(buf, &options->rekey_interval)) != 0) {
		error_fr(r, "deserialise");
		প্রত্যাগম r;
	}

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_subsystem(ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;
	u_int i, n;
	বর্ণ **names = রিক্ত, **commands = রিক্ত, **args = রিক্ত;

	যদি ((r = deserialise_গুনতি(buf, &n, "subsystems")) != 0)
		প্রত্যাগম r;
	যদি (n > 0) {
		names = xcalloc(n, পরিমাণ(*names));
		commands = xcalloc(n, পরিমাণ(*names));
		args = xcalloc(n, পরিমাণ(*args));
	}
	প্রতি (i = 0; i < n; i++) {
		যদি ((r = sshbuf_get_cstring(buf, names + i, রিক্ত)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, রিক্ত)) != 0 ||
		    (r = sshbuf_get_cstring(buf, args + i, রিক্ত)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(names, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(args, i + 1);
			প্রত্যাগম r;
		}
	}
	options->অঙ্ক_subsystems = n;
	options->subsystem_name = names;
	options->subsystem_command = commands;
	options->subsystem_args = args;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_pubkey_auth_options(ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = deserialise_s32(buf, &options->pubkey_auth_options)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_pubkey_ok)) != 0) {
		error_fr(r, "deserialise");
		প্রত্যাগম r;
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
deserialise_timingsecret(ServerOptions *options, সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_get_u64(buf, &options->timing_secret)) != 0) {
		error_fr(r, "deserialise");
		প্রত্যাগম r;
	}
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
deserialise_server_options(সংরচনা sshbuf *buf, ServerOptions *options)
{
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	uint32_t version;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	যদি ((r = sshbuf_get_u32(buf, &version)) != 0) {
		error_fr(r, "deserialise version");
		গচ্ছ out;
	}
	যদি (version != SSHD_CONFIG_BLOB_VERSION) {
		error_f("unsupported config blob version %u", version);
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	যদি ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		গচ্ছ out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	যদি ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		গচ্ছ out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	যদি ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		গচ্ছ out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	যদি ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		গচ্ছ out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	যদি ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		গচ্ছ out;
#define SSHCONF_NONCONF(funcsuffix) \
	যদি ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		গচ্ছ out;
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	কুরু { \
		মুক্ত(new_options.var); \
		new_options.var = রিক্ত; \
	} যাবত্ (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

	যদি (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
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
	memset(&new_options, 0, পরিমাণ(new_options));
 out:
	free_server_options(&new_options);
	প্রত্যাগম r;
}

স্থির শূন্য
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	প্রতি (i = 0; i < options->অঙ্ক_host_চাবি_files; i++)
		মুক্ত(options->host_চাবি_files[i]);
	মুক্ত(options->host_চাবি_files);
	মুক্ত(options->host_চাবি_file_userprovided);
}

স্থির শূন্য
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->অঙ্ক_queued_listens);

	প্রতি (i = 0; i < options->অঙ্ক_listen_addrs; i++) {
		মুক্ত(options->listen_addrs[i].rdomain);
		যদি (options->listen_addrs[i].addrs != রিক্ত)
			freeaddrinfo(options->listen_addrs[i].addrs);
	}
	মুক্ত(options->listen_addrs);
}

স্থির শূন্য
free_permituserenv(ServerOptions *options)
{
	মুক্ত(options->permit_user_env_allowlist);
}

স্থির শূন্য
free_subsystem(ServerOptions *options)
{
	u_int i;

	প্রতি (i = 0; i < options->অঙ্ক_subsystems; i++) {
		মুক্ত(options->subsystem_name[i]);
		মুক্ত(options->subsystem_command[i]);
		মুক্ত(options->subsystem_args[i]);
	}
	মুক্ত(options->subsystem_name);
	মুক্ত(options->subsystem_command);
	মুক্ত(options->subsystem_args);
}

শূন্য
free_server_options(ServerOptions *options)
{
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	/* empty */
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	/* empty */
#define SSHCONF_STRING(var, conf, flags, cp)		মুক্ত(options->var);
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#define SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	কুরু { \
		মুক্ত(options->var); \
		options->var = রিক্ত; \
	} যাবত্ (0);
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

স্থির শূন্য
copy_server_option_int(পূর্ণাঙ্ক *dst, পূর্ণাঙ্ক src)
{
	যদি (src != -1)
		*dst = src;
}

স্থির শূন্য
copy_server_option_int64(int64_t *dst, int64_t src)
{
	যদি (src != -1)
		*dst = src;
}

স্থির শূন্য
copy_server_option_string(বর্ণ **dst, ধ্রুব বর্ণ *src)
{
	যদি (src != রিক্ত && *dst != src) {
		মুক্ত(*dst);
		*dst = xstrdup(src);
	}
}

স্থির শূন্য
copy_server_option_strarray_মানসমূহ(বর্ণ ***dst, u_int ndst,
    বর্ণ * ধ্রুব *src, u_int nsrc)
{
	u_int i;

	যদি (nsrc == 0)
		প্রত্যাগম;
	প্রতি (i = 0; i < ndst; i++)
		মুক্ত((*dst)[i]);
	মুক্ত(*dst);
	*dst = xcalloc(nsrc, পরিমাণ(**dst));
	প্রতি (i = 0; i < nsrc; i++)
		(*dst)[i] = src[i] == রিক্ত ? রিক্ত : xstrdup(src[i]);
}

স্থির শূন্য
copy_server_option_strarray(বর্ণ ***dst, u_int *ndst,
    বর্ণ * ধ্রুব *src, u_int nsrc)
{
	যদি (nsrc == 0)
		প্রত্যাগম;
	copy_server_option_strarray_মানসমূহ(dst, *ndst, src, nsrc);
	*ndst = nsrc;
}

স্থির শূন্য
copy_ipqos(ServerOptions *dst, ধ্রুব ServerOptions *src)
{
	copy_server_option_int(&dst->ip_qos_interactive,
	    src->ip_qos_interactive);
	copy_server_option_int(&dst->ip_qos_bulk, src->ip_qos_bulk);
}

স্থির শূন্য
copy_gatewayports(ServerOptions *dst, ধ্রুব ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.gateway_ports,
	    src->fwd_opts.gateway_ports);
}

স্থির শূন্য
copy_streamlocalbindunlink(ServerOptions *dst, ধ্রুব ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.streamlocal_bind_unlink,
	    src->fwd_opts.streamlocal_bind_unlink);
}

স্থির শূন্য
copy_loglevel(ServerOptions *dst, ধ্রুব ServerOptions *src)
{
	যদি (src->log_level != -1)
		dst->log_level = src->log_level;
}

স্থির শূন্য
copy_rekeylimit(ServerOptions *dst, ধ্রুব ServerOptions *src)
{
	copy_server_option_int64(&dst->rekey_limit, src->rekey_limit);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

স্থির শূন্য
copy_subsystem(ServerOptions *dst, ধ্রুব ServerOptions *src)
{
	u_int old_অঙ্ক_subsystems = dst->অঙ্ক_subsystems;

	যদি (src->অঙ্ক_subsystems == 0)
		প্রত্যাগম;
	copy_server_option_strarray_মানসমূহ(&dst->subsystem_name,
	    old_অঙ্ক_subsystems, src->subsystem_name, src->অঙ্ক_subsystems);
	copy_server_option_strarray_মানসমূহ(&dst->subsystem_command,
	    old_অঙ্ক_subsystems, src->subsystem_command, src->অঙ্ক_subsystems);
	copy_server_option_strarray_মানসমূহ(&dst->subsystem_args,
	    old_অঙ্ক_subsystems, src->subsystem_args, src->অঙ্ক_subsystems);
	dst->অঙ্ক_subsystems = src->অঙ্ক_subsystems;
}

স্থির শূন্য
copy_pubkey_auth_options(ServerOptions *dst, ধ্রুব ServerOptions *src)
{
	যদি (src->pubkey_auth_options != -1) {
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
শূন্য
copy_set_server_options(ServerOptions *dst, ServerOptions *src, পূর্ণাঙ্ক preauth)
{
	যদি (dst == src)
		প্রত্যাগম;

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
	কুরু { \
		মুক্ত(dst->var); \
		dst->var = রিক্ত; \
	} যাবত্ (0);
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
	যদি (src->fwd_opts.streamlocal_bind_mask != (mode_t)-1) {
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
	কুরু { \
		যদি (option_clear_or_none(v)) { \
			মুক্ত(v); \
			v = রিক্ত; \
		} \
	} যাবত্(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_চাবিগুলি);
	CLEAR_ON_NONE(dst->banner);

	/*
	 * The only things that should be below this point are string options
	 * which are only used after authentication.
	 */
	যদি (preauth)
		প্রত্যাগম;

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
স্থির শূন্য
parse_server_config_depth(ServerOptions *options, ধ্রুব বর্ণ *filename,
    সংরচনা sshbuf *conf, সংরচনা include_list *includes,
    সংরচনা connection_info *connectinfo, পূর্ণাঙ্ক flags, পূর্ণাঙ্ক *activep, পূর্ণাঙ্ক depth)
{
	পূর্ণাঙ্ক linenum, bad_options = 0;
	বর্ণ *cp, *obuf, *cbuf;

	যদি (depth < 0 || depth > SERVCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	যদি ((obuf = cbuf = sshbuf_dup_string(conf)) == রিক্ত)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	যাবত্ ((cp = strsep(&cbuf, "\n")) != রিক্ত) {
		যদি (process_server_config_সারি_depth(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    depth, includes) != 0)
			bad_options++;
	}
	মুক্ত(obuf);
	যদি (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

শূন্য
parse_server_config(ServerOptions *options, ধ্রুব বর্ণ *filename,
    সংরচনা sshbuf *conf, সংরচনা include_list *includes,
    সংরচনা connection_info *connectinfo, পূর্ণাঙ্ক reexec)
{
	পূর্ণাঙ্ক active = connectinfo ? 0 : 1;
	parse_server_config_depth(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_MATCH_ONLY : 0), &active, 0);
	যদি (!reexec)
		process_queued_listen_addrs(options);
}

স্থির ধ্রুব বর্ণ *
fmt_multistate_int(পূর্ণাঙ্ক val, ধ্রুব সংরচনা multistate *m)
{
	u_int i;

	প্রতি (i = 0; m[i].চাবি != রিক্ত; i++) {
		যদি (m[i].মান == val)
			প্রত্যাগম m[i].চাবি;
	}
	প্রত্যাগম "UNKNOWN";
}

স্থির ধ্রুব বর্ণ *
fmt_intarg(ServerOpCodes code, পূর্ণাঙ্ক val)
{
	যদি (val == -1)
		প্রত্যাগম "unset";
	বিকল্প (code) {
	পক্ষ sAddressFamily:
		প্রত্যাগম fmt_multistate_int(val, multistate_addressfamily);
	পক্ষ s_Permit_মূল_Login:
		প্রত্যাগম fmt_multistate_int(val, multistate_permitrootlogin);
	পক্ষ sGatewayPorts:
		প্রত্যাগম fmt_multistate_int(val, multistate_gatewayports);
	পক্ষ sCompression:
		প্রত্যাগম fmt_multistate_int(val, multistate_compression);
	পক্ষ sAllowTcpForwarding:
		প্রত্যাগম fmt_multistate_int(val, multistate_tcpfwd);
	পক্ষ sAllowStreamLocalForwarding:
		প্রত্যাগম fmt_multistate_int(val, multistate_tcpfwd);
	পক্ষ sIgnoreRhosts:
		প্রত্যাগম fmt_multistate_int(val, multistate_ignore_rhosts);
	পক্ষ sTCPKeepAlive:
		প্রত্যাগম fmt_multistate_int(val, multistate_keepalives);
	পক্ষ sWarnWeakCrypto:
		প্রত্যাগম fmt_multistate_int(val, multistate_warnweakcrypto);
	পক্ষ sFingerprintHash:
		প্রত্যাগম ssh_digest_alg_name(val);
	স্বভাব:
		বিকল্প (val) {
		পক্ষ 0:
			প্রত্যাগম "no";
		পক্ষ 1:
			প্রত্যাগম "yes";
		স্বভাব:
			প্রত্যাগম "UNKNOWN";
		}
	}
}

স্থির শূন্য
dump_cfg_int(ServerOpCodes code, পূর্ণাঙ্ক val)
{
	যদি (code == sUnusedConnectionTimeout && val == 0) {
		printf("%s none\n", lookup_opcode_name(code));
		প্রত্যাগম;
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

স্থির শূন্য
dump_cfg_oct(ServerOpCodes code, পূর্ণাঙ্ক val)
{
	printf("%s 0%o\n", lookup_opcode_name(code), val);
}

স্থির শূন্য
dump_cfg_fmtint(ServerOpCodes code, পূর্ণাঙ্ক val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

স্থির শূন্য
dump_cfg_string(ServerOpCodes code, ধ্রুব বর্ণ *val)
{
	printf("%s %s\n", lookup_opcode_name(code),
	    val == রিক্ত ? "none" : val);
}

স্থির শূন্য
dump_cfg_strarray(ServerOpCodes code, u_int গুনতি, বর্ণ **vals)
{
	u_int i;

	প্রতি (i = 0; i < গুনতি; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

স্থির শূন্য
dump_cfg_strarray_oneline(ServerOpCodes code, u_int গুনতি, বর্ণ **vals)
{
	u_int i;

	বিকল্প (code) {
	পক্ষ sAuthenticationMethods:
	পক্ষ sChannelTimeout:
		ভঙ্গ;
	স্বভাব:
		যদি (গুনতি <= 0)
			প্রত্যাগম;
		ভঙ্গ;
	}

	printf("%s", lookup_opcode_name(code));
	প্রতি (i = 0; i < গুনতি; i++)
		printf(" %s",  vals[i]);
	যদি (code == sAuthenticationMethods && গুনতি == 0)
		printf(" any");
	অন্যথা যদি (code == sChannelTimeout && গুনতি == 0)
		printf(" none");
	printf("\n");
}

স্থির বর্ণ *
format_listen_addrs(সংরচনা listenaddr *la)
{
	পূর্ণাঙ্ক r;
	সংরচনা addrinfo *ai;
	বর্ণ addr[NI_MAXHOST], port[NI_MAXSERV];
	বর্ণ *laddr1 = xstrdup(""), *laddr2 = রিক্ত;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	প্রতি (ai = la->addrs; ai; ai = ai->ai_next) {
		যদি ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    পরিমাণ(addr), port, পরিমাণ(port),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			অনুবর্ত;
		}
		laddr2 = laddr1;
		যদি (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == রিক্ত ? "" : " rdomain ",
			    la->rdomain == রিক্ত ? "" : la->rdomain,
			    laddr2);
		} অন্যথা {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == রিক্ত ? "" : " rdomain ",
			    la->rdomain == রিক্ত ? "" : la->rdomain,
			    laddr2);
		}
		মুক্ত(laddr2);
	}
	প্রত্যাগম laddr1;
}

শূন্য
dump_config(ServerOptions *o)
{
	বর্ণ *s;
	u_int i;

	/* these are usually at the top of the config */
	প্রতি (i = 0; i < o->অঙ্ক_ports; i++)
		printf("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(sAddressFamily, o->address_family);

	প্রতি (i = 0; i < o->অঙ্ক_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		printf("%s", s);
		মুক্ত(s);
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
	dump_cfg_int(s_Client_Alive_গুনতি_Max, o->client_alive_গুনতি_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_size);
	dump_cfg_oct(sStreamLocalBindMask, o->fwd_opts.streamlocal_bind_mask);
	dump_cfg_int(sUnusedConnectionTimeout, o->unused_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(s_Permit_মূল_Login, o->permit_মূল_login);
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
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_চাবিগুলি);
	dump_cfg_string(s_Security_চাবি_Provider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(sVersionAddendum, *o->version_addendum == '\0'
	    ? "none" : o->version_addendum);
	dump_cfg_string(s_Authorized_চাবিগুলি_Command, o->authorized_চাবিগুলি_command);
	dump_cfg_string(s_Authorized_চাবিগুলি_Command_User, o->authorized_চাবিগুলি_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(s_Host_চাবি_Agent, o->host_চাবি_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(s_Host_চাবি_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#যদি defined(__OpenBSD__) || defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
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
	dump_cfg_strarray_oneline(s_Authorized_চাবিগুলি_File, o->অঙ্ক_authkeys_files,
	    o->authorized_চাবিগুলি_files);
	dump_cfg_strarray_oneline(s_Revoked_চাবিগুলি, o->অঙ্ক_revoked_চাবিগুলি_files,
	    o->revoked_চাবিগুলি_files);
	dump_cfg_strarray(s_Host_চাবি, o->অঙ্ক_host_চাবি_files, o->host_চাবি_files);
	dump_cfg_strarray(sHostCertificate, o->অঙ্ক_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->অঙ্ক_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->অঙ্ক_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->অঙ্ক_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->অঙ্ক_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->অঙ্ক_accept_env, o->accept_env);
	dump_cfg_strarray(sSetEnv, o->অঙ্ক_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->অঙ্ক_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->অঙ্ক_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->অঙ্ক_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	প্রতি (i = 0; i < o->অঙ্ক_subsystems; i++)
		printf("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_args[i]);

	printf("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_rate, o->max_startups);
	printf("PerSourceMaxStartups ");
	যদি (o->per_source_max_startups == INT_MAX)
		printf("none\n");
	অন্যথা
		printf("%d\n", o->per_source_max_startups);
	printf("PerSourceNetBlockSize %d:%d\n", o->per_source_masklen_ipv4,
	    o->per_source_masklen_ipv6);

	s = রিক্ত;
	প্রতি (i = 0; tunmode_desc[i].val != -1; i++) {
		যদি (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].text;
			ভঙ্গ;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	printf("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	printf("%s\n", iptos2str(o->ip_qos_bulk));

	printf("RekeyLimit %llu %d\n", (unsigned long long)o->rekey_limit,
	    o->rekey_interval);

	printf("PermitOpen");
	যদি (o->অঙ্ক_permitted_opens == 0)
		printf(" any");
	অন্যথা {
		প্রতি (i = 0; i < o->অঙ্ক_permitted_opens; i++)
			printf(" %s", o->permitted_opens[i]);
	}
	printf("\n");
	printf("PermitListen");
	যদি (o->অঙ্ক_permitted_listens == 0)
		printf(" any");
	অন্যথা {
		প্রতি (i = 0; i < o->অঙ্ক_permitted_listens; i++)
			printf(" %s", o->permitted_listens[i]);
	}
	printf("\n");

	যদি (o->permit_user_env_allowlist == রিক্ত) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} অন্যথা {
		printf("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	printf("PubkeyAuthOptions");
	যদি (o->pubkey_auth_options == 0)
		printf(" none");
	যদি (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		printf(" touch-required");
	যদি (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		printf(" verify-required");
	যদি (o->max_pubkey_ok != -1)
		printf(" max-pk-ok:%d", o->max_pubkey_ok);
	printf("\n");

	যদি (o->per_source_penalty.enabled) {
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
	} অন্যথা
		printf("PerSourcePenalties no\n");
}
