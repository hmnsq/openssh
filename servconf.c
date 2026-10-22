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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/socket.h>
#شامل <sys/queue.h>
#شامل <sys/stat.h>
#ifdef __OpenBSD__
#شامل <sys/sysctl.h>
#endif

#شامل <netinet/in.h>
#شامل <netinet/ip.h>
#ifdef HAVE_NET_ROUTE_H
#شامل <net/route.h>
#endif

#شامل <ctype.h>
#شامل <glob.h>
#شامل <netdb.h>
#شامل <pwd.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <signal.h>
#شامل <unistd.h>
#شامل <limits.h>
#شامل <stdarg.h>
#شامل <errno.h>
#شامل <util.h>

#شامل "xmalloc.h"
#شامل "ssh.h"
#شامل "log.h"
#شامل "sshbuf.h"
#شامل "misc.h"
#شامل "servconf.h"
#شامل "pathnames.h"
#شامل "cipher.h"
#شامل "sshkey.h"
#شامل "kex.h"
#شامل "mac.h"
#شامل "match.h"
#شامل "channels.h"
#شامل "groupaccess.h"
#شامل "canohost.h"
#شامل "packet.h"
#شامل "ssherr.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "myproposal.h"
#شامل "digest.h"
#شامل "version.h"

#define SSHD_CONFIG_BLOB_VERSION	1

#اگر !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#endif

ایستا تهی add_listen_addr(ServerOptions *, ثابت نویسه *,
    ثابت نویسه *, صحیح);
ایستا تهی add_one_listen_addr(ServerOptions *, ثابت نویسه *,
    ثابت نویسه *, صحیح);
ایستا تهی parse_server_config_depth(ServerOptions *options,
    ثابت نویسه *filename, ساختار sshbuf *conf, ساختار include_list *includes,
    ساختار connection_info *connectinfo, صحیح flags, صحیح *activep, صحیح depth);

بیرونی ساختار sshbuf *cfg;

/* Initializes the server options to their default values. */

تهی
initialize_server_options(ServerOptions *options)
{
	memset(options, 0, اندازه(*options));
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#define SSHCONF_STRING(var, conf, flags, cp)		options->var = پوچ;
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = پوچ;
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#define SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = پوچ;
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	/* Using macros for these is a bit overkill but forces consistency */
#define init_hostkeyfile(options) \
	options->host_کلید_files = 0; \
	options->رقم_host_کلید_files = 0; \
	options->host_کلید_file_userprovided = پوچ;
#define init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#define init_listenaddress(options) \
	options->queued_listen_addrs = پوچ; \
	options->رقم_queued_listens = 0; \
	options->listen_addrs = پوچ; \
	options->رقم_listen_addrs = 0;
#define init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
#define init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_SET;
#define init_port(options) \
	options->رقم_ports = 0; \
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
	options->permit_user_env_allowlist = پوچ;
#define init_persourcenetblocksize(options) \
	options->per_source_masklen_ipv4 = -1; \
	options->per_source_masklen_ipv6 = -1;
#define init_persourcepenalties(options) \
	options->per_source_penalty_exempt = پوچ; \
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
	options->رقم_subsystems = 0; \
	options->subsystem_name = پوچ; \
	options->subsystem_command = پوچ; \
	options->subsystem_args = پوچ;
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
ایستا صحیح
option_clear_or_none(ثابت نویسه *o)
{
	بازگشت o == پوچ || strcasecmp(o, "none") == 0;
}

ایستا تهی
assemble_algorithms(ServerOptions *o)
{
	نویسه *all_cipher, *all_mac, *all_kex, *all_کلید, *all_sig;
	نویسه *def_cipher, *def_mac, *def_kex, *def_کلید, *def_sig;
	صحیح r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_کلید = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_کلید = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_کلید);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	انجامبده { \
		اگر ((r = kex_assemble_names(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} وقتی (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_کلید, all_کلید);
	ASSEMBLE(hostbased_accepted_algos, def_کلید, all_کلید);
	ASSEMBLE(pubkey_accepted_algos, def_کلید, all_کلید);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE
	آزاد(all_cipher);
	آزاد(all_mac);
	آزاد(all_kex);
	آزاد(all_کلید);
	آزاد(all_sig);
	آزاد(def_cipher);
	آزاد(def_mac);
	آزاد(def_kex);
	آزاد(def_کلید);
	آزاد(def_sig);
}

تهی
servconf_add_hostkey(ثابت نویسه *file, ثابت صحیح سطر,
    ServerOptions *options, ثابت نویسه *path, صحیح userprovided)
{
	نویسه *apath = derelativise_path(path);

	opt_array_append2(file, سطر, "HostKey",
	    &options->host_کلید_files, &options->host_کلید_file_userprovided,
	    &options->رقم_host_کلید_files, apath, userprovided);
	آزاد(apath);
}

تهی
servconf_add_hostcert(ثابت نویسه *file, ثابت صحیح سطر,
    ServerOptions *options, ثابت نویسه *path)
{
	نویسه *apath = derelativise_path(path);

	opt_array_append(file, سطر, "HostCertificate",
	    &options->host_cert_files, &options->رقم_host_cert_files, apath);
	آزاد(apath);
}

تهی
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#ifdef SKIP_PRIVDROP
	اگر (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	اگر (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#endif

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	اگر (options->var == -1) \
		options->var = def;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	اگر (options->var == -1) \
		options->var = def;
#define SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#define SSHCONF_NONCONF(funcsuffix)			/* done manually */
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	انجامبده { \
		آزاد(options->var); \
		options->var = پوچ; \
	} وقتی (0);
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
	اگر (options->pam_service_name == پوچ)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#endif

	اگر (options->رقم_host_کلید_files == 0) {
		/* fill default hostkeys */
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_RSA_کلید_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ECDSA_کلید_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ED25519_کلید_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_MLDSA44_ED25519_کلید_FILE, 0);
	}
	/* No certificates by default */
	اگر (options->رقم_ports == 0)
		options->ports[options->رقم_ports++] = SSH_DEFAULT_PORT;
	اگر (options->listen_addrs == پوچ)
		add_listen_addr(options, پوچ, پوچ, 0);
	اگر (options->pid_file == پوچ)
		options->pid_file = xstrdup(_PATH_SSH_DAEMON_PID_FILE);
	اگر (options->moduli_file == پوچ)
		options->moduli_file = xstrdup(_PATH_DH_MODULI);
	اگر (options->xauth_location == پوچ)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	اگر (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	اگر (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	اگر (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = پوچ;
	}
	اگر (options->rekey_limit == -1)
		options->rekey_limit = 0;
	اگر (options->rekey_interval == -1)
		options->rekey_interval = 0;
	اگر (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	اگر (options->max_startups == -1)
		options->max_startups = 100;
	اگر (options->max_startups_rate == -1)
		options->max_startups_rate = 30;		/* 30% */
	اگر (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	اگر (options->per_source_masklen_ipv4 == -1)
		options->per_source_masklen_ipv4 = 32;
	اگر (options->per_source_masklen_ipv6 == -1)
		options->per_source_masklen_ipv6 = 128;
	اگر (options->per_source_penalty.enabled == -1)
		options->per_source_penalty.enabled = 1;
	اگر (options->per_source_penalty.max_sources4 == -1)
		options->per_source_penalty.max_sources4 = 65536;
	اگر (options->per_source_penalty.max_sources6 == -1)
		options->per_source_penalty.max_sources6 = 65536;
	اگر (options->per_source_penalty.overflow_mode == -1)
		options->per_source_penalty.overflow_mode = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
	اگر (options->per_source_penalty.overflow_mode6 == -1)
		options->per_source_penalty.overflow_mode6 = options->per_source_penalty.overflow_mode;
	اگر (options->per_source_penalty.penalty_crash < 0.0)
		options->per_source_penalty.penalty_crash = 90.0;
	اگر (options->per_source_penalty.penalty_grace < 0.0)
		options->per_source_penalty.penalty_grace = 10.0;
	اگر (options->per_source_penalty.penalty_authfail < 0.0)
		options->per_source_penalty.penalty_authfail = 5.0;
	اگر (options->per_source_penalty.penalty_invaliduser < 0.0)
		options->per_source_penalty.penalty_invaliduser = 5.0;
	اگر (options->per_source_penalty.penalty_noauth < 0.0)
		options->per_source_penalty.penalty_noauth = 1.0;
	اگر (options->per_source_penalty.penalty_refuseconnection < 0.0)
		options->per_source_penalty.penalty_refuseconnection = 10.0;
	اگر (options->per_source_penalty.penalty_min < 0.0)
		options->per_source_penalty.penalty_min = 15.0;
	اگر (options->per_source_penalty.penalty_max < 0.0)
		options->per_source_penalty.penalty_max = 600.0;
	اگر (options->رقم_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_کلیدها_files,
		    &options->رقم_authkeys_files,
		    PATH_SSH_USER_PERMITTED_کلیدها);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_کلیدها_files,
		    &options->رقم_authkeys_files,
		    _PATH_SSH_USER_PERMITTED_KEYS2);
	}
	اگر (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	اگر (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	اگر (options->version_addendum == پوچ)
		options->version_addendum = xstrdup("");
	اگر (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	اگر (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	اگر (options->sk_provider == پوچ)
		options->sk_provider = xstrdup("internal");
	اگر (options->sshd_session_path == پوچ)
		options->sshd_session_path = xstrdup(_PATH_SSHD_SESSION);
	اگر (options->sshd_auth_path == پوچ)
		options->sshd_auth_path = xstrdup(_PATH_SSHD_AUTH);
	اگر (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	اگر (options->agent_socket_path == پوچ)
		options->agent_socket_path = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#define CLEAR_ON_NONE(v) \
	انجامبده { \
		اگر (option_clear_or_none(v)) { \
			آزاد(v); \
			v = پوچ; \
		} \
	} وقتی(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	انجامبده { \
		اگر (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			آزاد(options->v[0]); \
			آزاد(options->v); \
			options->v = پوچ; \
			options->nv = 0; \
		} \
	} وقتی (0)
	CLEAR_ON_NONE(options->pid_file);
	CLEAR_ON_NONE(options->xauth_location);
	CLEAR_ON_NONE(options->banner);
	CLEAR_ON_NONE(options->trusted_user_ca_کلیدها);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_کلید_agent);
	CLEAR_ON_NONE(options->per_source_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_path);

	برای (i = 0; i < options->رقم_host_کلید_files; i++)
		CLEAR_ON_NONE(options->host_کلید_files[i]);
	برای (i = 0; i < options->رقم_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, رقم_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, رقم_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_کلیدها_files, رقم_revoked_کلیدها_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_کلیدها_files, رقم_authkeys_files, "none");
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
تعریفنوع شمارش {
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
ایستا ساختار {
	ثابت نویسه *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", sMatch, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ پوچ, sBadOption, 0 }
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

ایستا ساختار {
	صحیح val;
	نویسه *text;
} tunmode_desc[] = {
	{ SSH_TUNMODE_NO, "no" },
	{ SSH_TUNMODE_POINTOPOINT, "point-to-point" },
	{ SSH_TUNMODE_ETHERNET, "ethernet" },
	{ SSH_TUNMODE_YES, "yes" },
	{ -1, پوچ }
};

/* Returns an opcode name from its number */

ایستا ثابت نویسه *
lookup_opcode_name(ServerOpCodes code)
{
	u_int i;

	برای (i = 0; keywords[i].name != پوچ; i++)
		اگر (keywords[i].opcode == code)
			بازگشت(keywords[i].name);
	بازگشت "UNKNOWN";
}


/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

ایستا ServerOpCodes
parse_token(ثابت نویسه *cp, ثابت نویسه *filename,
	    صحیح linenum, u_int *flags)
{
	u_int i;

	برای (i = 0; keywords[i].name; i++)
		اگر (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			بازگشت keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	بازگشت sBadOption;
}

نویسه *
derelativise_path(ثابت نویسه *path)
{
	نویسه *expanded, *ret, cwd[PATH_MAX];

	اگر (strcasecmp(path, "none") == 0)
		بازگشت xstrdup("none");
	expanded = tilde_expand_filename(path, getuid());
	اگر (path_absolute(expanded))
		بازگشت expanded;
	اگر (getcwd(cwd, اندازه(cwd)) == پوچ)
		fatal_f("getcwd: %s", strerror(errno));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	آزاد(expanded);
	بازگشت ret;
}

ایستا تهی
add_listen_addr(ServerOptions *options, ثابت نویسه *addr,
    ثابت نویسه *rdomain, صحیح port)
{
	u_int i;

	اگر (port > 0)
		add_one_listen_addr(options, addr, rdomain, port);
	وگرنه {
		برای (i = 0; i < options->رقم_ports; i++) {
			add_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

ایستا تهی
add_one_listen_addr(ServerOptions *options, ثابت نویسه *addr,
    ثابت نویسه *rdomain, صحیح port)
{
	ساختار addrinfo hints, *ai, *aitop;
	نویسه strport[NI_MAXSERV];
	صحیح gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	برای (i = 0; i < options->رقم_listen_addrs; i++) {
		اگر (rdomain == پوچ && options->listen_addrs[i].rdomain == پوچ)
			بشکن;
		اگر (rdomain == پوچ || options->listen_addrs[i].rdomain == پوچ)
			ادامه;
		اگر (strcmp(rdomain, options->listen_addrs[i].rdomain) == 0)
			بشکن;
	}
	اگر (i >= options->رقم_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		اگر (i >= INT_MAX)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->رقم_listen_addrs, options->رقم_listen_addrs + 1,
		    اندازه(*options->listen_addrs));
		i = options->رقم_listen_addrs++;
		اگر (rdomain != پوچ)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	memset(&hints, 0, اندازه(hints));
	hints.ai_family = options->address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == پوچ) ? AI_PASSIVE : 0;
	snprintf(strport, اندازه strport, "%d", port);
	اگر ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    ssh_gai_strerror(gaierr));
	برای (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs[i].addrs;
	options->listen_addrs[i].addrs = aitop;
}

/* Returns nonzero if the routing domain name is valid */
ایستا صحیح
valid_rdomain(ثابت نویسه *name)
{
#اگر defined(HAVE_SYS_VALID_RDOMAIN)
	بازگشت sys_valid_rdomain(name);
#وگرنهاگر defined(__OpenBSD__)
	ثابت نویسه *errstr;
	long long رقم;
	ساختار rt_tableinfo info;
	صحیح mib[6];
	size_t miblen = اندازه(mib);

	اگر (name == پوچ)
		بازگشت 1;

	رقم = strtonum(name, 0, 255, &errstr);
	اگر (errstr != پوچ)
		بازگشت 0;

	/* Check whether the table actually exists */
	memset(mib, 0, اندازه(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_TABLE;
	mib[5] = (صحیح)رقم;
	اگر (sysctl(mib, 6, &info, &miblen, پوچ, 0) == -1)
		بازگشت 0;

	بازگشت 1;
#وگرنه /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	بازگشت 0;
#endif
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
ایستا تهی
queue_listen_addr(ServerOptions *options, ثابت نویسه *addr,
    ثابت نویسه *rdomain, صحیح port)
{
	ساختار queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->رقم_queued_listens, options->رقم_queued_listens + 1,
	    اندازه(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->رقم_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->port = port;
	qla->rdomain = rdomain == پوچ ? پوچ : xstrdup(rdomain);
}

/*
 * Process queued (text) ListenAddress entries.
 */
ایستا تهی
process_queued_listen_addrs(ServerOptions *options)
{
	u_int i;
	ساختار queued_listenaddr *qla;

	اگر (options->رقم_ports == 0)
		options->ports[options->رقم_ports++] = SSH_DEFAULT_PORT;
	اگر (options->address_family == -1)
		options->address_family = AF_UNSPEC;

	برای (i = 0; i < options->رقم_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		add_listen_addr(options, qla->addr, qla->rdomain, qla->port);
		آزاد(qla->addr);
		آزاد(qla->rdomain);
	}
	آزاد(options->queued_listen_addrs);
	options->queued_listen_addrs = پوچ;
	options->رقم_queued_listens = 0;
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

ایستا صحیح
match_cfg_سطر_group(ثابت نویسه *grps, صحیح سطر, ثابت نویسه *user)
{
	صحیح result = 0;
	ساختار passwd *pw;

	اگر (user == پوچ)
		برو out;

	اگر ((pw = getpwnam(user)) == پوچ) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", سطر, user);
	} وگرنه اگر (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, سطر);
	} وگرنه اگر (ga_match_pattern_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, سطر);
	} وگرنه {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, سطر);
		result = 1;
	}
out:
	ga_free();
	بازگشت result;
}

ایستا تهی
match_test_missing_fatal(ثابت نویسه *criteria, ثابت نویسه *attrib)
{
	fatal("'Match %s' in configuration but '%s' not in connection "
	    "test specification.", criteria, attrib);
}

/*
 * All of the attributes on a single Match line are ANDed together, so we need
 * to check every attribute and set the result to zero if any attribute does
 * not match.
 */
ایستا صحیح
match_cfg_سطر(ثابت نویسه *full_سطر, صحیح *acp, نویسه ***avp,
    صحیح سطر, ساختار connection_info *ci)
{
	صحیح result = 1, attributes = 0, port;
	نویسه *arg, *attrib = پوچ, *oattrib;

	اگر (ci == پوچ) {
		debug3("checking syntax for 'Match %s' on line %d",
		    full_سطر, سطر);
	} وگرنه {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", full_سطر,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->address ? ci->address : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", سطر);
	}

	وقتی ((oattrib = argv_next(acp, avp)) != پوچ) {
		/* Terminate on comment */
		اگر (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			بشکن;
		}
		attrib = xstrdup(oattrib);
		arg = پوچ;
		attributes++;
		/* Criterion "all" has no argument and must appear alone */
		اگر (strcasecmp(attrib, "all") == 0) {
			اگر (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != پوچ &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				result = -1;
				برو out;
			}
			اگر (arg != پوچ && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			result = 1;
			برو out;
		}
		/* Criterion "invalid-user" also has no argument */
		اگر (strcasecmp(attrib, "invalid-user") == 0) {
			اگر (ci == پوچ) {
				result = 0;
				برو next;
			}
			اگر (ci->user_invalid == 0)
				result = 0;
			وگرنه
				debug("matched invalid-user at line %d", سطر);
			برو next;
		}

		/* Keep this list in sync with below */
		اگر (strprefix(attrib, "user=", 1) != پوچ ||
		    strprefix(attrib, "group=", 1) != پوچ ||
		    strprefix(attrib, "host=", 1) != پوچ ||
		    strprefix(attrib, "address=", 1) != پوچ ||
		    strprefix(attrib, "localaddress=", 1) != پوچ ||
		    strprefix(attrib, "localport=", 1) != پوچ ||
		    strprefix(attrib, "rdomain=", 1) != پوچ ||
		    strprefix(attrib, "version=", 1) != پوچ) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} وگرنه {
			arg = argv_next(acp, avp);
		}

		/* All other criteria require an argument */
		اگر (arg == پوچ || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			برو out;
		}
		اگر (strcasecmp(attrib, "user") == 0) {
			اگر (ci == پوچ || (ci->test && ci->user == پوچ)) {
				result = 0;
				برو next;
			}
			اگر (ci->user == پوچ)
				match_test_missing_fatal("User", "user");
			اگر (match_usergroup_pattern_list(ci->user, arg) != 1)
				result = 0;
			وگرنه
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, سطر);
		} وگرنه اگر (strcasecmp(attrib, "group") == 0) {
			اگر (ci == پوچ || (ci->test && ci->user == پوچ)) {
				result = 0;
				برو next;
			}
			اگر (ci->user == پوچ)
				match_test_missing_fatal("Group", "user");
			انتخاب (match_cfg_سطر_group(arg, سطر, ci->user)) {
			حالت -1:
				result = -1;
				برو out;
			حالت 0:
				result = 0;
			}
		} وگرنه اگر (strcasecmp(attrib, "host") == 0) {
			اگر (ci == پوچ || (ci->test && ci->host == پوچ)) {
				result = 0;
				برو next;
			}
			اگر (ci->host == پوچ)
				match_test_missing_fatal("Host", "host");
			اگر (match_hostname(ci->host, arg) != 1)
				result = 0;
			وگرنه
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, سطر);
		} وگرنه اگر (strcasecmp(attrib, "address") == 0) {
			اگر (ci == پوچ || (ci->test && ci->address == پوچ)) {
				اگر (addr_match_list(پوچ, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, سطر);
				result = 0;
				برو next;
			}
			اگر (ci->address == پوچ)
				match_test_missing_fatal("Address", "addr");
			انتخاب (addr_match_list(ci->address, arg)) {
			حالت 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->address, arg, سطر);
				بشکن;
			حالت 0:
			حالت -1:
				result = 0;
				بشکن;
			حالت -2:
				result = -1;
				برو out;
			}
		} وگرنه اگر (strcasecmp(attrib, "localaddress") == 0){
			اگر (ci == پوچ || (ci->test && ci->laddress == پوچ)) {
				اگر (addr_match_list(پوچ, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    سطر);
				result = 0;
				برو next;
			}
			اگر (ci->laddress == پوچ)
				match_test_missing_fatal("LocalAddress",
				    "laddr");
			انتخاب (addr_match_list(ci->laddress, arg)) {
			حالت 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, سطر);
				بشکن;
			حالت 0:
			حالت -1:
				result = 0;
				بشکن;
			حالت -2:
				result = -1;
				برو out;
			}
		} وگرنه اگر (strcasecmp(attrib, "localport") == 0) {
			اگر ((port = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				result = -1;
				برو out;
			}
			اگر (ci == پوچ || (ci->test && ci->lport == -1)) {
				result = 0;
				برو next;
			}
			اگر (ci->lport == 0)
				match_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			اگر (port == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, port, سطر);
			وگرنه
				result = 0;
		} وگرنه اگر (strcasecmp(attrib, "rdomain") == 0) {
			اگر (ci == پوچ || (ci->test && ci->rdomain == پوچ)) {
				result = 0;
				برو next;
			}
			اگر (ci->rdomain == پوچ)
				match_test_missing_fatal("RDomain", "rdomain");
			اگر (match_pattern_list(ci->rdomain, arg, 0) != 1)
				result = 0;
			وگرنه
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, سطر);
		} وگرنه اگر (strcasecmp(attrib, "version") == 0) {
			اگر (match_pattern_list(SSH_RELEASE, arg, 0) != 1)
				result = 0;
			وگرنه
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, سطر);
		} وگرنه {
			error("Unsupported Match attribute %s", oattrib);
			result = -1;
			برو out;
		}
 next:
		آزاد(attrib);
		attrib = پوچ;
	}
	اگر (attributes == 0) {
		error("One or more attributes required for Match");
		بازگشت -1;
	}
 out:
	اگر (ci != پوچ && result != -1)
		debug3("match %sfound on line %d", result ? "" : "not ", سطر);
	آزاد(attrib);
	بازگشت result;
}

#define WHITESPACE " \t\r\n"

/* Multistate option parsing */
ساختار multistate {
	نویسه *کلید;
	صحیح مقدار;
};
ایستا ثابت ساختار multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ پوچ, -1 }
};
ایستا ثابت ساختار multistate multistate_ignore_rhosts[] = {
	{ "yes",			IGNORE_RHOSTS_YES },
	{ "no",				IGNORE_RHOSTS_NO },
	{ "shosts-only",		IGNORE_RHOSTS_SHOSTS },
	{ پوچ, -1 }
};
ایستا ثابت ساختار multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ پوچ, -1 }
};
ایستا ثابت ساختار multistate multistate_permitrootlogin[] = {
	{ "prohibit-password",		PERMIT_NO_PASSWD },
	{ "without-password",		PERMIT_NO_PASSWD },
	{ "forced-commands-only",	PERMIT_FORCED_ONLY },
	{ "yes",			PERMIT_YES },
	{ "no",				PERMIT_NO },
	{ پوچ, -1 }
};
ایستا ثابت ساختار multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ پوچ, -1 }
};
ایستا ثابت ساختار multistate multistate_gatewayports[] = {
	{ "clientspecified",		2 },
	{ "yes",			1 },
	{ "no",				0 },
	{ پوچ, -1 }
};
ایستا ثابت ساختار multistate multistate_tcpfwd[] = {
	{ "yes",			FORWARD_ALLOW },
	{ "all",			FORWARD_ALLOW },
	{ "no",				FORWARD_DENY },
	{ "remote",			FORWARD_REMOTE },
	{ "local",			FORWARD_LOCAL },
	{ پوچ, -1 }
};
ایستا ثابت ساختار multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ پوچ, -1 }
};
ایستا ثابت ساختار multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ پوچ, -1 }
};

ایستا صحیح
process_server_config_سطر_depth(ServerOptions *options, نویسه *سطر,
    ثابت نویسه *filename, صحیح linenum, صحیح *activep,
    ساختار connection_info *connectinfo, صحیح *inc_flags, صحیح depth,
    ساختار include_list *includes)
{
	نویسه *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	صحیح cmdline = 0, *intptr, مقدار, value2, value3, n, port, oactive, r;
	دوگانه dvalue, *doubleptr = پوچ;
	صحیح ca_only = 0, found = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	size_t len;
	long long val64;
	ثابت ساختار multistate *multistate_ptr;
	ثابت نویسه *errstr;
	ساختار include_item *item;
	glob_t gbuf;
	نویسه **oav = پوچ, **av;
	صحیح oac = 0, ac;
	صحیح ret = -1;
	نویسه **strs = پوچ; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	اگر ((len = strlen(سطر)) == 0)
		بازگشت 0;
	برای (len--; len > 0; len--) {
		اگر (strchr(WHITESPACE "\f", سطر[len]) == پوچ)
			بشکن;
		سطر[len] = '\0';
	}

	str = سطر;
	اگر ((keyword = strdelim(&str)) == پوچ)
		بازگشت 0;
	/* Ignore leading whitespace */
	اگر (*keyword == '\0')
		keyword = strdelim(&str);
	اگر (!keyword || !*keyword || *keyword == '#')
		بازگشت 0;
	اگر (str == پوچ || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		بازگشت -1;
	}
	intptr = پوچ;
	charptr = پوچ;
	opcode = parse_token(keyword, filename, linenum, &flags);

	اگر (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		بازگشت -1;
	}
	ac = oac;
	av = oav;

	اگر (activep == پوچ) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	اگر (*activep && opcode != sMatch && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	اگر (*activep == 0 && !(flags & SSHCFG_MATCH)) {
		اگر (connectinfo == پوچ) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} وگرنه { /* this is a directive we have already processed */
			ret = 0;
			برو out;
		}
	}

	انتخاب (opcode) {
	/* Portable-specific options */
#ifdef USE_PAM
	حالت sUsePAM:
		intptr = &options->use_pam;
		برو parse_flag;
	حالت sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		اگر (*activep && *charptr == پوچ)
			*charptr = xstrdup(arg);
		بشکن;
#endif

	/* Standard Options */
	حالت sBadOption:
		برو out;
	حالت sPort:
		/* ignore ports from configfile if cmdline specifies ports */
		اگر (options->ports_from_cmdline) {
			argv_consume(&ac);
			بشکن;
		}
		اگر (options->رقم_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->رقم_ports++] = a2port(arg);
		اگر (options->ports[options->رقم_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		بشکن;

	حالت sLoginGraceTime:
		intptr = &options->login_grace_time;
 parse_time:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		اگر ((مقدار = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		اگر (*activep && *intptr == -1)
			*intptr = مقدار;
		بشکن;

	حالت sListenAddress:
		arg = argv_next(&ac, &av);
		اگر (arg == پوچ || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		اگر (strchr(arg, '[') == پوچ && (p = strchr(arg, ':')) != پوچ
		    && strchr(p+1, ':') != پوچ) {
			port = 0;
			p = arg;
		} وگرنه {
			arg2 = پوچ;
			p = hpdelim(&arg);
			اگر (p == پوچ)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			اگر (arg == پوچ)
				port = 0;
			وگرنه اگر ((port = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = پوچ;
		اگر ((arg = argv_next(&ac, &av)) != پوچ) {
			اگر (strcmp(arg, "rdomain") != 0 ||
			    (arg2 = argv_next(&ac, &av)) == پوچ)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			اگر (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		queue_listen_addr(options, p, arg2, port);

		بشکن;

	حالت sAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		مقدار = -1;
		برای (i = 0; multistate_ptr[i].کلید != پوچ; i++) {
			اگر (strcasecmp(arg, multistate_ptr[i].کلید) == 0) {
				مقدار = multistate_ptr[i].مقدار;
				بشکن;
			}
		}
		اگر (مقدار == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		اگر (*activep && *intptr == -1)
			*intptr = مقدار;
		بشکن;

	حالت s_Host_کلید:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		اگر (*activep) {
			servconf_add_hostkey(filename, linenum,
			    options, arg, 1);
		}
		بشکن;

	حالت s_Host_کلید_Agent:
		charptr = &options->host_کلید_agent;
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		اگر (*activep && *charptr == پوچ)
			*charptr = !strcmp(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_path(arg);
		بشکن;

	حالت sHostCertificate:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		اگر (*activep)
			servconf_add_hostcert(filename, linenum, options, arg);
		بشکن;

	حالت sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		اگر (*activep && *charptr == پوچ) {
			*charptr = derelativise_path(arg);
			/* increase optional counter */
			اگر (intptr != پوچ)
				*intptr = *intptr + 1;
		}
		بشکن;

	حالت sModuliFile:
		charptr = &options->moduli_file;
		برو parse_filename;

	حالت s_Permit_ریشه_Login:
		intptr = &options->permit_ریشه_login;
		multistate_ptr = multistate_permitrootlogin;
		برو parse_multistate;

	حالت sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
		multistate_ptr = multistate_ignore_rhosts;
		برو parse_multistate;

	حالت sIgnoreUserKnownHosts:
		intptr = &options->ignore_user_known_hosts;
 parse_flag:
		multistate_ptr = multistate_flag;
		برو parse_multistate;

	حالت sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		برو parse_flag;

	حالت sHostbasedUsesNameFromPacketOnly:
		intptr = &options->hostbased_uses_name_from_packet_only;
		برو parse_flag;

	حالت sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		اگر (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		اگر (*activep && *charptr == پوچ)
			*charptr = xstrdup(arg);
		بشکن;

	حالت s_Host_کلید_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
		برو parse_pubkey_algos;

	حالت sCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		برو parse_pubkey_algos;

	حالت sPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		ca_only = 0;
		برو parse_flag;

	حالت sPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		برو parse_pubkey_algos;

	حالت sPubkeyAuthOptions:
		intptr = &options->pubkey_auth_options;
		مقدار = 0;
		value2 = -1;
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			اگر (strcasecmp(arg, "none") == 0)
				ادامه;
			اگر (strcasecmp(arg, "touch-required") == 0)
				مقدار |= PUBKEYAUTH_TOUCH_REQUIRED;
			وگرنه اگر (strcasecmp(arg, "verify-required") == 0)
				مقدار |= PUBKEYAUTH_VERIFY_REQUIRED;
			وگرنه اگر (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				اگر (errstr != پوچ) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					برو out;
				}
			} وگرنه {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				برو out;
			}
		}
		اگر (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = مقدار;
			options->max_pubkey_ok = value2;
		}
		بشکن;

#ifdef KRB5
	حالت sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		برو parse_flag;

	حالت sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		برو parse_flag;

	حالت sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		برو parse_flag;
#ifdef USE_AFS
	حالت sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		برو parse_flag;
#endif /* USE_AFS */
#endif /* KRB5 */

#ifdef GSSAPI
	حالت sGSSAPIAuthentication:
		intptr = &options->gss_authentication;
		برو parse_flag;

	حالت sGSSAPICleanupCredentials:
		intptr = &options->gss_cleanup_creds;
		برو parse_flag;

	حالت sGSSAPIDelegateCredentials:
		intptr = &options->gss_deleg_creds;
		برو parse_flag;

	حالت sGSSAPIStrictAcceptorCheck:
		intptr = &options->gss_strict_acceptor;
		برو parse_flag;
#endif /* GSSAPI */

	حالت sPasswordAuthentication:
		intptr = &options->password_authentication;
		برو parse_flag;

	حالت sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		برو parse_flag;

	حالت sPrintMotd:
		intptr = &options->print_motd;
		برو parse_flag;

#ifndef DISABLE_LASTLOG
	حالت sPrintLastLog:
		intptr = &options->print_lastlog;
		برو parse_flag;
#endif

	حالت sX11Forwarding:
		intptr = &options->x11_forwarding;
		برو parse_flag;

	حالت sX11DisplayOffset:
		intptr = &options->x11_display_offset;
 parse_int:
		arg = argv_next(&ac, &av);
		اگر ((errstr = atoi_err(arg, &مقدار)) != پوچ)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		اگر (*activep && *intptr == -1)
			*intptr = مقدار;
		بشکن;

	حالت sX11UseLocalhost:
		intptr = &options->x11_use_localhost;
		برو parse_flag;

	حالت sXAuthLocation:
		charptr = &options->xauth_location;
		برو parse_filename;

	حالت sPermitTTY:
		intptr = &options->permit_tty;
		برو parse_flag;

	حالت sPermitUserRC:
		intptr = &options->permit_user_rc;
		برو parse_flag;

	حالت sStrictModes:
		intptr = &options->strict_modes;
		برو parse_flag;

	حالت sTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		برو parse_multistate;

	حالت sPermitEmptyPasswords:
		intptr = &options->permit_empty_passwd;
		برو parse_flag;

	حالت sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		مقدار = 0;
		p = پوچ;
		اگر (strcmp(arg, "yes") == 0)
			مقدار = 1;
		وگرنه اگر (strcmp(arg, "no") == 0)
			مقدار = 0;
		وگرنه {
			/* Pattern-list specified */
			مقدار = 1;
			p = xstrdup(arg);
		}
		اگر (*activep && *intptr == -1) {
			*intptr = مقدار;
			*charptr = p;
			p = پوچ;
		}
		آزاد(p);
		بشکن;

	حالت sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		برو parse_multistate;

	حالت sRekeyLimit:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر (strcmp(arg, "default") == 0) {
			val64 = 0;
		} وگرنه {
			اگر (scan_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, strerror(errno));
			اگر (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		اگر (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		اگر (ac != 0) { /* optional rekey interval present */
			اگر (strcmp(av[0], "none") == 0) {
				(تهی)argv_next(&ac, &av);	/* discard */
				بشکن;
			}
			intptr = &options->rekey_interval;
			برو parse_time;
		}
		بشکن;

	حالت sGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		multistate_ptr = multistate_gatewayports;
		برو parse_multistate;

	حالت sUseDNS:
		intptr = &options->use_dns;
		برو parse_flag;

	حالت sSyslogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		مقدار = log_facility_عدد(arg);
		اگر (مقدار == SYSLOG_FACILITY_NOT_SET)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		اگر (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) مقدار;
		بشکن;

	حالت sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		مقدار = log_level_عدد(arg);
		اگر (مقدار == SYSLOG_LEVEL_NOT_SET)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		اگر (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) مقدار;
		بشکن;

	حالت sLogVerbose:
		found = options->رقم_log_verbose == 0;
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			اگر (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				برو out;
			}
			/* Allow "none" only in first position */
			اگر (strcasecmp(arg, "none") == 0) {
				اگر (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					برو out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		اگر (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اگر (found && *activep) {
			options->log_verbose = strs;
			options->رقم_log_verbose = nstrs;
			strs = پوچ; /* transferred */
			nstrs = 0;
		}
		بشکن;

	حالت sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		برو parse_multistate;

	حالت sAllowStreamLocalForwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		برو parse_multistate;

	حالت sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		برو parse_flag;

	حالت sAgentSocketPath:
		charptr = &options->agent_socket_path;
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		اگر (strncmp(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			اگر (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} وگرنه اگر (strncmp(arg, "user:", 5) == 0) {
			/* User paths must not be empty */
			اگر (arg[5] == '\0') {
				fatal("%s line %d: invalid user path.",
				    filename, linenum);
			}
		} وگرنه اگر (strcmp(arg, "none") != 0)
			fatal("%s line %d: invalid path.", filename, linenum);
		اگر (*activep && *charptr == پوچ)
			*charptr = xstrdup(arg);
		بشکن;

	حالت sDisableForwarding:
		intptr = &options->disable_forwarding;
		برو parse_flag;

	حالت sAllowUsers:
		chararrayptr = &options->allow_users;
		uintptr = &options->رقم_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			اگر (*arg == '\0' ||
			    match_user(پوچ, پوچ, پوچ, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			found = 1;
			اگر (!*activep)
				ادامه;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		اگر (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		بشکن;

	حالت sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->رقم_deny_users;
		برو parse_allowdenyusers;

	حالت sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->رقم_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			اگر (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			found = 1;
			اگر (!*activep)
				ادامه;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		اگر (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		بشکن;

	حالت sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->رقم_deny_groups;
		برو parse_allowdenygroups;

	حالت sCiphers:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		اگر (options->ciphers == پوچ)
			options->ciphers = xstrdup(arg);
		بشکن;

	حالت sMacs:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		اگر (options->macs == پوچ)
			options->macs = xstrdup(arg);
		بشکن;

	حالت sKexAlgorithms:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		اگر (options->kex_algorithms == پوچ)
			options->kex_algorithms = xstrdup(arg);
		بشکن;

	حالت sSubsystem:
		اگر ((arg = argv_next(&ac, &av)) == پوچ || *arg == '\0' ||
		   ((arg2 = argv_next(&ac, &av)) == پوچ || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر (!*activep) {
			argv_consume(&ac);
			بشکن;
		}
		found = 0;
		برای (i = 0; i < options->رقم_subsystems; i++) {
			اگر (strcmp(arg, options->subsystem_name[i]) == 0) {
				found = 1;
				بشکن;
			}
		}
		اگر (found) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			بشکن;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->رقم_subsystems,
		    options->رقم_subsystems + 1,
		    اندازه(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->رقم_subsystems,
		    options->رقم_subsystems + 1,
		    اندازه(*options->subsystem_command));
		options->subsystem_args = xrecallocarray(
		    options->subsystem_args, options->رقم_subsystems,
		    options->رقم_subsystems + 1,
		    اندازه(*options->subsystem_args));
		options->subsystem_name[options->رقم_subsystems] = xstrdup(arg);
		options->subsystem_command[options->رقم_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_args[options->رقم_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		آزاد(arg2);
		آزاد(arg);
		argv_consume(&ac);
		options->رقم_subsystems++;
		بشکن;

	حالت sMaxStartups:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		اگر ((n = sscanf(arg, "%d:%d:%d",
		    &مقدار, &value2, &value3)) == 3) {
			اگر (مقدار > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} وگرنه اگر (n == 1) {
			value3 = مقدار;
			value2 = -1;
		} وگرنه {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		اگر (مقدار <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		اگر (*activep && options->max_startups == -1) {
			options->max_startups_begin = مقدار;
			options->max_startups_rate = value2;
			options->max_startups = value3;
		}
		بشکن;

	حالت sPerSourceNetBlockSize:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		انتخاب (n = sscanf(arg, "%d:%d", &مقدار, &value2)) {
		حالت 2:
			اگر (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		حالت 1:
			اگر (مقدار < 0 || مقدار > 32)
				n = -1;
		}
		اگر (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		اگر (*activep && options->per_source_masklen_ipv4 == -1) {
			options->per_source_masklen_ipv4 = مقدار;
			اگر (n == 2)
				options->per_source_masklen_ipv6 = value2;
		}
		بشکن;

	حالت sPerSourceMaxStartups:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر (strcmp(arg, "none") == 0) { /* no limit */
			مقدار = INT_MAX;
		} وگرنه {
			اگر ((errstr = atoi_err(arg, &مقدار)) != پوچ)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		اگر (*activep && options->per_source_max_startups == -1)
			options->per_source_max_startups = مقدار;
		بشکن;

	حالت sPerSourcePenaltyExemptList:
		charptr = &options->per_source_penalty_exempt;
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		اگر (addr_match_list(پوچ, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		اگر (*activep && *charptr == پوچ)
			*charptr = xstrdup(arg);
		بشکن;

	حالت sPerSourcePenalties:
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			ثابت نویسه *q = پوچ;

			found = 1;
			intptr = پوچ;
			doubleptr = پوچ;
			مقدار = -1;
			value2 = 0;
			/* Allow no/yes only in first position */
			اگر (strcasecmp(arg, "no") == 0 ||
			    (value2 = (strcasecmp(arg, "yes") == 0))) {
				اگر (ac > 0) {
					fatal("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
				}
				اگر (*activep &&
				    options->per_source_penalty.enabled == -1)
					options->per_source_penalty.enabled = value2;
				ادامه;
			} وگرنه اگر ((q = strprefix(arg, "crash:", 0)) != پوچ) {
				doubleptr = &options->per_source_penalty.penalty_crash;
			} وگرنه اگر ((q = strprefix(arg, "authfail:", 0)) != پوچ) {
				doubleptr = &options->per_source_penalty.penalty_authfail;
			} وگرنه اگر ((q = strprefix(arg, "invaliduser:", 0)) != پوچ) {
				doubleptr = &options->per_source_penalty.penalty_invaliduser;
			} وگرنه اگر ((q = strprefix(arg, "noauth:", 0)) != پوچ) {
				doubleptr = &options->per_source_penalty.penalty_noauth;
			} وگرنه اگر ((q = strprefix(arg, "grace-exceeded:", 0)) != پوچ) {
				doubleptr = &options->per_source_penalty.penalty_grace;
			} وگرنه اگر ((q = strprefix(arg, "refuseconnection:", 0)) != پوچ) {
				doubleptr = &options->per_source_penalty.penalty_refuseconnection;
			} وگرنه اگر ((q = strprefix(arg, "max:", 0)) != پوچ) {
				doubleptr = &options->per_source_penalty.penalty_max;
			} وگرنه اگر ((q = strprefix(arg, "min:", 0)) != پوچ) {
				doubleptr = &options->per_source_penalty.penalty_min;
			} وگرنه اگر ((q = strprefix(arg, "max-sources4:", 0)) != پوچ) {
				intptr = &options->per_source_penalty.max_sources4;
				اگر ((errstr = atoi_err(q, &مقدار)) != پوچ)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} وگرنه اگر ((q = strprefix(arg, "max-sources6:", 0)) != پوچ) {
				intptr = &options->per_source_penalty.max_sources6;
				اگر ((errstr = atoi_err(q, &مقدار)) != پوچ)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} وگرنه اگر (strcmp(arg, "overflow:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				مقدار = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} وگرنه اگر (strcmp(arg, "overflow:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				مقدار = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} وگرنه اگر (strcmp(arg, "overflow6:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				مقدار = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} وگرنه اگر (strcmp(arg, "overflow6:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				مقدار = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} وگرنه {
				fatal("%s line %d: unsupported %s keyword %s",
				    filename, linenum, keyword, arg);
			}

			اگر (doubleptr != پوچ) {
				اگر ((dvalue = convtime_double(q)) < 0) {
					fatal("%s line %d: invalid %s time value.",
					    filename, linenum, keyword);
				}
				اگر (*activep && *doubleptr < 0.0) {
					*doubleptr = dvalue;
					options->per_source_penalty.enabled = 1;
				}
			} وگرنه اگر (intptr != پوچ) {
				اگر (*activep && *intptr == -1) {
					*intptr = مقدار;
					options->per_source_penalty.enabled = 1;
				}
			} وگرنه {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		اگر (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		بشکن;

	حالت sMaxAuthTries:
		intptr = &options->max_authtries;
		برو parse_int;

	حالت sMaxSessions:
		intptr = &options->max_sessions;
		برو parse_int;

	حالت sBanner:
		charptr = &options->banner;
		برو parse_filename;

	/*
	 * These options can contain %X options expanded at
	 * connect time, so that you can specify paths like:
	 *
	 * AuthorizedKeysFile	/etc/ssh_keys/%u
	 */
	حالت s_Authorized_کلیدها_File:
		uintptr = &options->رقم_authkeys_files;
		chararrayptr = &options->authorized_کلیدها_files;
 parse_filenames:
		found = *uintptr == 0;
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			اگر (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				برو out;
			}
			/* Allow "none" only in first position */
			اگر (strcasecmp(arg, "none") == 0) {
				اگر (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					برو out;
				}
			}
			arg2 = tilde_expand_filename(arg, getuid());
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			آزاد(arg2);
		}
		اگر (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اگر (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = پوچ; /* transferred */
			nstrs = 0;
		}
		بشکن;

	حالت sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر (*activep && *charptr == پوچ) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			اگر (intptr != پوچ)
				*intptr = *intptr + 1;
		}
		بشکن;

	حالت sClientAliveInterval:
		intptr = &options->client_alive_interval;
		برو parse_time;

	حالت s_Client_Alive_شمار_Max:
		intptr = &options->client_alive_شمار_max;
		برو parse_int;

	حالت sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			اگر (*arg == '\0' || strchr(arg, '=') != پوچ)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			found = 1;
			اگر (!*activep)
				ادامه;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->رقم_accept_env,
			    arg);
		}
		اگر (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		بشکن;

	حالت sSetEnv:
		found = options->رقم_setenv == 0;
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			اگر (*arg == '\0' || strchr(arg, '=') == پوچ)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			اگر (lookup_setenv_in_list(arg, strs, nstrs) != پوچ) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				ادامه;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		اگر (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اگر (found && *activep) {
			options->setenv = strs;
			options->رقم_setenv = nstrs;
			strs = پوچ; /* transferred */
			nstrs = 0;
		}
		بشکن;

	حالت sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		مقدار = -1;
		برای (i = 0; tunmode_desc[i].val != -1; i++)
			اگر (strcmp(tunmode_desc[i].text, arg) == 0) {
				مقدار = tunmode_desc[i].val;
				بشکن;
			}
		اگر (مقدار == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		اگر (*activep && *intptr == -1)
			*intptr = مقدار;
		بشکن;

	حالت sInclude:
		اگر (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		مقدار = 0;
		وقتی ((arg2 = argv_next(&ac, &av)) != پوچ) {
			اگر (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				برو out;
			}
			مقدار++;
			found = 0;
			اگر (*arg2 != '/' && *arg2 != '~') {
				xasprintf(&arg, "%s/%s", SSHDIR, arg2);
			} وگرنه
				arg = xstrdup(arg2);

			/*
			 * Don't let included files clobber the containing
			 * file's Match state.
			 */
			oactive = *activep;

			/* consult cache of include files */
			TAILQ_FOREACH(item, includes, entry) {
				اگر (strcmp(item->selector, arg) != 0)
					ادامه;
				اگر (item->filename != پوچ) {
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
			اگر (found != 0) {
				آزاد(arg);
				ادامه;
			}

			/* requested glob was not in cache */
			debug2("%s line %d: new include %s",
			    filename, linenum, arg);
			اگر ((r = glob(arg, 0, پوچ, &gbuf)) != 0) {
				اگر (r != GLOB_NOMATCH) {
					fatal("%s line %d: include \"%s\" glob "
					    "failed", filename, linenum, arg);
				}
				/*
				 * If no entry matched then record a
				 * placeholder to skip later glob calls.
				 */
				debug2("%s line %d: no match for %s",
				    filename, linenum, arg);
				item = xcalloc(1, اندازه(*item));
				item->selector = xstrdup(arg);
				TAILQ_INSERT_TAIL(includes,
				    item, entry);
			}
			اگر (gbuf.gl_pathc > INT_MAX)
				fatal_f("too many glob results");
			برای (n = 0; n < (صحیح)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				item = xcalloc(1, اندازه(*item));
				item->selector = xstrdup(arg);
				item->filename = xstrdup(gbuf.gl_pathv[n]);
				اگر ((item->contents = sshbuf_new()) == پوچ)
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
			آزاد(arg);
		}
		اگر (مقدار == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		بشکن;

	حالت sMatch:
		اگر (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		مقدار = match_cfg_سطر(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? پوچ : connectinfo));
		اگر (مقدار < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : مقدار;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_MATCH_ONLY;
		بشکن;

	حالت sPermitListen:
	حالت sPermitOpen:
		اگر (opcode == sPermitListen) {
			uintptr = &options->رقم_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} وگرنه {
			uintptr = &options->رقم_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		found = *uintptr == 0;
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			اگر (strcmp(arg, "any") == 0 ||
			    strcmp(arg, "none") == 0) {
				اگر (nstrs != 0) {
					fatal("%s line %d: %s must appear "
					    "alone on a %s line.",
					    filename, linenum, arg, keyword);
				}
				opt_array_append(filename, linenum, keyword,
				    &strs, &nstrs, arg);
				ادامه;
			}

			اگر (opcode == sPermitListen &&
			    strchr(arg, ':') == پوچ) {
				/*
				 * Allow bare port number for PermitListen
				 * to indicate a wildcard listen host.
				 */
				xasprintf(&arg2, "*:%s", arg);
			} وگرنه {
				arg2 = xstrdup(arg);
				p = hpdelim(&arg);
				اگر (p == پوچ) {
					fatal("%s line %d: %s missing host",
					    filename, linenum, keyword);
				}
				p = cleanhostname(p);
			}
			اگر (arg == پوچ ||
			    ((port = permitopen_port(arg)) < 0)) {
				fatal("%s line %d: %s bad port number",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			آزاد(arg2);
		}
		اگر (nstrs == 0) {
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		}
		اگر (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = پوچ; /* transferred */
			nstrs = 0;
		}
		بشکن;

	حالت sForceCommand:
		اگر (str == پوچ || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		اگر (*activep && options->adm_forced_command == پوچ)
			options->adm_forced_command = xstrdup(str + len);
		argv_consume(&ac);
		بشکن;

	حالت sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر (*activep && *charptr == پوچ)
			*charptr = xstrdup(arg);
		بشکن;

	حالت sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_کلیدها;
		برو parse_filename;

	حالت s_Revoked_کلیدها:
		uintptr = &options->رقم_revoked_کلیدها_files;
		chararrayptr = &options->revoked_کلیدها_files;
		برو parse_filenames;

	حالت s_Security_کلید_Provider:
		charptr = &options->sk_provider;
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر (*activep && *charptr == پوچ) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_path(arg);
			/* increase optional counter */
			اگر (intptr != پوچ)
				*intptr = *intptr + 1;
		}
		بشکن;

	حالت sIPQoS:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر ((مقدار = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		اگر (مقدار == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			مقدار = INT_MAX;
		}
		arg = argv_next(&ac, &av);
		اگر (arg == پوچ)
			value2 = مقدار;
		وگرنه اگر ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		اگر (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		اگر (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = مقدار;
			options->ip_qos_bulk = value2;
		}
		بشکن;

	حالت sVersionAddendum:
		اگر (str == پوچ || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		اگر (strchr(str + len, '\r') != پوچ) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		اگر ((arg = strchr(سطر, '#')) != پوچ) {
			*arg = '\0';
			rtrim(سطر);
		}
		اگر (*activep && options->version_addendum == پوچ) {
			اگر (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			وگرنه
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		بشکن;

	حالت s_Authorized_کلیدها_Command:
		charptr = &options->authorized_کلیدها_command;
 parse_command:
		len = strspn(str, WHITESPACE);
		اگر (str[len] != '/' && strcasecmp(str + len, "none") != 0) {
			fatal("%.200s line %d: %s must be an absolute path",
			    filename, linenum, keyword);
		}
		اگر (*activep && *charptr == پوچ)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		بشکن;

	حالت s_Authorized_کلیدها_Command_User:
		charptr = &options->authorized_کلیدها_command_user;
 parse_localuser:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0') {
			fatal("%s line %d: missing %s argument.",
			    filename, linenum, keyword);
		}
		اگر (*activep && *charptr == پوچ)
			*charptr = xstrdup(arg);
		بشکن;

	حالت sAuthorizedPrincipalsCommand:
		charptr = &options->authorized_principals_command;
		برو parse_command;

	حالت sAuthorizedPrincipalsCommandUser:
		charptr = &options->authorized_principals_command_user;
		برو parse_localuser;

	حالت sAuthenticationMethods:
		found = options->رقم_auth_methods == 0;
		مقدار = 0; /* seen "any" pseudo-method */
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			اگر (strcmp(arg, "any") == 0) {
				اگر (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				مقدار = 1;
			} وگرنه اگر (مقدار) {
				fatal("%s line %d: \"any\" must appear "
				    "alone in %s", filename, linenum, keyword);
			} وگرنه اگر (auth2_methods_valid(arg, 0) != 0) {
				fatal("%s line %d: invalid %s method list.",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		اگر (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اگر (found && *activep) {
			options->auth_methods = strs;
			options->رقم_auth_methods = nstrs;
			strs = پوچ; /* transferred */
			nstrs = 0;
		}
		بشکن;

	حالت sStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		مقدار = strtol(arg, &p, 8);
		اگر (arg == p || مقدار < 0 || مقدار > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		اگر (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)مقدار;
		بشکن;

	حالت sStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		برو parse_flag;

	حالت sFingerprintHash:
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر ((مقدار = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		اگر (*activep)
			options->fingerprint_hash = مقدار;
		بشکن;

	حالت sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		برو parse_flag;

	حالت sRDomain:
#اگر !defined(__OpenBSD__) && !defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#endif
		charptr = &options->routing_domain;
		arg = argv_next(&ac, &av);
		اگر (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		اگر (strcasecmp(arg, "none") != 0 && strcmp(arg, "%D") != 0 &&
		    !valid_rdomain(arg))
			fatal("%s line %d: invalid routing domain",
			    filename, linenum);
		اگر (*activep && *charptr == پوچ)
			*charptr = xstrdup(arg);
		بشکن;

	حالت sRequiredRSASize:
		intptr = &options->required_rsa_size;
		برو parse_int;

	حالت sChannelTimeout:
		found = options->رقم_channel_timeouts == 0;
		وقتی ((arg = argv_next(&ac, &av)) != پوچ) {
			/* Allow "none" only in first position */
			اگر (strcasecmp(arg, "none") == 0) {
				اگر (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					برو out;
				}
			} وگرنه اگر (parse_pattern_interval(arg,
			    پوچ, پوچ) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		اگر (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اگر (found && *activep) {
			options->channel_timeouts = strs;
			options->رقم_channel_timeouts = nstrs;
			strs = پوچ; /* transferred */
			nstrs = 0;
		}
		بشکن;

	حالت sUnusedConnectionTimeout:
		intptr = &options->unused_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		اگر (av[0] != پوچ && strcasecmp(av[0], "none") == 0) {
			(تهی)argv_next(&ac, &av); /* consume arg */
			اگر (*activep)
				*intptr = 0;
			بشکن;
		}
		برو parse_time;

	حالت sSshdSessionPath:
		charptr = &options->sshd_session_path;
		برو parse_filename;

	حالت sSshdAuthPath:
		charptr = &options->sshd_auth_path;
		برو parse_filename;

	حالت sRefuseConnection:
		intptr = &options->refuse_connection;
		multistate_ptr = multistate_flag;
		برو parse_multistate;

	حالت sWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		برو parse_multistate;

	حالت sDeprecated:
	حالت sIgnore:
	حالت sUnsupported:
		do_log2(opcode == sIgnore ?
		    SYSLOG_LEVEL_DEBUG2 : SYSLOG_LEVEL_INFO,
		    "%s line %d: %s option %s", filename, linenum,
		    opcode == sUnsupported ? "Unsupported" : "Deprecated",
		    keyword);
		argv_consume(&ac);
		بشکن;

	پیشفرض:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, keyword, opcode);
	}
	/* Check that there is no garbage at end of line. */
	اگر (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		برو out;
	}

	/* success */
	ret = 0;
 out:
	opt_array_free2(strs, پوچ, nstrs);
	argv_free(oav, oac);
	بازگشت ret;
}

صحیح
process_server_config_سطر(ServerOptions *options, نویسه *سطر,
    ثابت نویسه *filename, صحیح linenum, صحیح *activep,
    ساختار connection_info *connectinfo, ساختار include_list *includes)
{
	صحیح inc_flags = 0;

	بازگشت process_server_config_سطر_depth(options, سطر, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

تهی
load_server_config(ثابت نویسه *filename, ساختار sshbuf *conf)
{
	ساختار stat st;
	نویسه *سطر = پوچ, *cp;
	size_t linesize = 0;
	FILE *f;
	صحیح r;

	debug2_f("filename %s", filename);
	اگر ((f = fopen(filename, "r")) == پوچ) {
		perror(filename);
		exit(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	اگر (fstat(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	وقتی (getline(&سطر, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = سطر + strspn(سطر, " \t\r");
		اگر ((r = sshbuf_put(conf, cp, strlen(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	آزاد(سطر);
	اگر ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	fclose(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

تهی
parse_server_match_config(ServerOptions *options,
   ساختار include_list *includes, ساختار connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_set_server_options(options, &mo, 0);
	free_server_options(&mo);
}

صحیح
parse_server_match_testspec(ساختار connection_info *ci, نویسه *spec)
{
	نویسه *p;
	ثابت نویسه *val;

	وقتی ((p = strsep(&spec, ",")) && *p != '\0') {
		اگر ((val = strprefix(p, "addr=", 0)) != پوچ) {
			ci->address = xstrdup(val);
		} وگرنه اگر ((val = strprefix(p, "host=", 0)) != پوچ) {
			ci->host = xstrdup(val);
		} وگرنه اگر ((val = strprefix(p, "user=", 0)) != پوچ) {
			ci->user = xstrdup(val);
		} وگرنه اگر ((val = strprefix(p, "laddr=", 0)) != پوچ) {
			ci->laddress = xstrdup(val);
		} وگرنه اگر ((val = strprefix(p, "rdomain=", 0)) != پوچ) {
			ci->rdomain = xstrdup(val);
		} وگرنه اگر ((val = strprefix(p, "lport=", 0)) != پوچ) {
			ci->lport = a2port(val);
			اگر (ci->lport == -1) {
				fprintf(stderr, "Invalid port '%s' in test mode"
				    " specification %s\n", p+6, p);
				بازگشت -1;
			}
		} وگرنه اگر (strcmp(p, "invalid-user") == 0) {
			ci->user_invalid = 1;
		} وگرنه {
			fprintf(stderr, "Invalid test mode specification %s\n",
			    p);
			بازگشت -1;
		}
	}
	بازگشت 0;
}

تهی
servconf_merge_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, found;

	برای (i = 0; i < src->رقم_subsystems; i++) {
		found = 0;
		برای (j = 0; j < dst->رقم_subsystems; j++) {
			اگر (strcmp(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				found = 1;
				بشکن;
			}
		}
		اگر (found) {
			debug_f("override \"%s\"", dst->subsystem_name[j]);
			آزاد(dst->subsystem_command[j]);
			آزاد(dst->subsystem_args[j]);
			dst->subsystem_command[j] =
			    xstrdup(src->subsystem_command[i]);
			dst->subsystem_args[j] =
			    xstrdup(src->subsystem_args[i]);
			ادامه;
		}
		debug_f("add \"%s\"", src->subsystem_name[i]);
		dst->subsystem_name = xrecallocarray(
		    dst->subsystem_name, dst->رقم_subsystems,
		    dst->رقم_subsystems + 1, اندازه(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->رقم_subsystems,
		    dst->رقم_subsystems + 1, اندازه(*dst->subsystem_command));
		dst->subsystem_args = xrecallocarray(
		    dst->subsystem_args, dst->رقم_subsystems,
		    dst->رقم_subsystems + 1, اندازه(*dst->subsystem_args));
		j = dst->رقم_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_args[j] = xstrdup(src->subsystem_args[i]);
	}
}

ایستا صحیح
serialise_s32(ساختار sshbuf *buf, صحیح v)
{
	uint32_t uv;
	صحیح r;

	uv = v < 0 ? (uint32_t)(-(v + 1)) + 1 : (uint32_t)v;
	اگر ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u32(buf, uv)) != 0)
		بازگشت r;
	بازگشت 0;
}

ایستا صحیح
serialise_s64(ساختار sshbuf *buf, int64_t v)
{
	uint64_t uv;
	صحیح r;

	uv = v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
	اگر ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u64(buf, uv)) != 0)
		بازگشت r;
	بازگشت 0;
}

ایستا صحیح
serialise_mode(ساختار sshbuf *buf, mode_t v)
{
	u_int uv;

	اگر (v == (mode_t)-1)
		بازگشت serialise_s32(buf, -1);
	uv = (u_int)v;
	اگر ((mode_t)uv != v || uv > 0777)
		بازگشت SSH_ERR_INVALID_FORMAT;
	بازگشت serialise_s32(buf, (صحیح)uv);
}

ایستا صحیح
serialise_double(ساختار sshbuf *buf, دوگانه v)
{
	/*
	 * XXX this is no good for a wire encoding.
	 * It's fine for passing configurations via RPC, but it would
	 * be nicer to have an exact binary encoding here.
	 */
	بازگشت sshbuf_put(buf, &v, اندازه(v));
}

ایستا صحیح
serialise_nullable_string(ساختار sshbuf *buf, ثابت نویسه *s)
{
	صحیح r;

	اگر ((r = sshbuf_put_u8(buf, s != پوچ)) != 0)
		بازگشت r;
	اگر (s == پوچ)
		بازگشت 0;
	بازگشت sshbuf_put_cstring(buf, s);
}

ایستا صحیح
serialise_nullable_string_array(ساختار sshbuf *buf, نویسه **a, u_int n)
{
	صحیح r;
	u_int i;

	اگر ((r = sshbuf_put_u32(buf, n)) != 0)
		بازگشت r;
	برای (i = 0; i < n; i++) {
		اگر ((r = serialise_nullable_string(buf, a[i])) != 0)
			بازگشت r;
	}
	بازگشت 0;
}

ایستا صحیح
serialise_hostkeyfile(ثابت ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;
	u_int i;

	اگر ((r = sshbuf_put_u32(buf, options->رقم_host_کلید_files)) != 0) {
		error_fr(r, "serialise length");
		بازگشت r;
	}
	برای (i = 0; i < options->رقم_host_کلید_files; i++) {
		اگر ((r = serialise_s32(buf,
		    options->host_کلید_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_کلید_files[i])) != 0) {
			error_fr(r, "serialise member");
			بازگشت r;
		}
	}
	بازگشت 0;
}

ایستا صحیح
serialise_ipqos(ثابت ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = serialise_s32(buf, options->ip_qos_interactive)) != 0 ||
	    (r = serialise_s32(buf, options->ip_qos_bulk)) != 0) {
		error_fr(r, "serialise");
		بازگشت r;
	}

	بازگشت 0;
}

ایستا صحیح
serialise_listenaddress(ثابت ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;
	u_int i;

	/* Note: only serialises queued listen addresses */
	اگر ((r = sshbuf_put_u32(buf, options->رقم_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		بازگشت r;
	}
	برای (i = 0; i < options->رقم_queued_listens; i++) {
		ثابت ساختار queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		اگر ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->port)) != 0 ||
		    (r = serialise_nullable_string(buf, qla->rdomain)) != 0) {
			error_fr(r, "serialise member");
			بازگشت r;
		}
	}
	بازگشت 0;
}

ایستا صحیح
serialise_logfacility(ثابت ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = serialise_s32(buf, (صحیح)options->log_facility)) != 0) {
		error_fr(r, "serialise");
		بازگشت r;
	}

	بازگشت 0;
}

ایستا صحیح
serialise_loglevel(ثابت ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = serialise_s32(buf, (صحیح)options->log_level)) != 0) {
		error_fr(r, "serialise");
		بازگشت r;
	}

	بازگشت 0;
}

ایستا صحیح
serialise_port(ثابت ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;
	u_int i;

	اگر ((r = sshbuf_put_u32(buf, options->رقم_ports)) != 0) {
		error_fr(r, "serialise length");
		بازگشت r;
	}
	برای (i = 0; i < options->رقم_ports; i++) {
		اگر ((r = serialise_s32(buf, options->ports[i])) != 0) {
			error_fr(r, "serialise port");
			بازگشت r;
		}
	}
	بازگشت 0;
}

ایستا صحیح
serialise_gatewayports(ثابت ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = serialise_s32(buf, options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "serialise");
		بازگشت r;
	}
	بازگشت 0;
}

ایستا صحیح
serialise_streamlocalbindmask(ثابت ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = serialise_mode(buf,
	    options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "serialise");
		بازگشت r;
	}
	بازگشت 0;
}

ایستا صحیح
serialise_streamlocalbindunlink(ثابت ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = sshbuf_put_u8(buf,
	    (options->fwd_opts.streamlocal_bind_unlink != 0))) != 0) {
		error_fr(r, "serialise");
		بازگشت r;
	}
	بازگشت 0;
}

ایستا صحیح
serialise_maxstartups(ثابت ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = serialise_s32(buf, options->max_startups_begin)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups_rate)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups)) != 0) {
		error_fr(r, "serialise");
		بازگشت r;
	}

	بازگشت 0;
}

ایستا صحیح
serialise_permituserenv(ثابت ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = serialise_s32(buf, options->permit_user_env)) != 0 ||
	    (r = serialise_nullable_string(buf,
	    options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "serialise");
		بازگشت r;
	}

	بازگشت 0;
}

ایستا صحیح
serialise_persourcenetblocksize(ثابت ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = serialise_s32(buf, options->per_source_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		بازگشت r;
	}

	بازگشت 0;
}

ایستا صحیح
serialise_persourcepenalties(ثابت ServerOptions *options, ساختار sshbuf *buf)
{
	ثابت ساختار per_source_penalty *psp = &options->per_source_penalty;
	صحیح r;

	اگر ((r = serialise_s32(buf, psp->enabled)) != 0 ||
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
		بازگشت r;
	}

	بازگشت 0;
}

ایستا صحیح
serialise_rekeylimit(ثابت ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = serialise_s64(buf, options->rekey_limit)) != 0 ||
	    (r = serialise_s32(buf, options->rekey_interval)) != 0) {
		error_fr(r, "serialise");
		بازگشت r;
	}

	بازگشت 0;
}

ایستا صحیح
serialise_subsystem(ثابت ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;
	u_int i;

	اگر ((r = sshbuf_put_u32(buf, options->رقم_subsystems)) != 0) {
		error_fr(r, "serialise length");
		بازگشت r;
	}
	برای (i = 0; i < options->رقم_subsystems; i++) {
		اگر ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_args[i])) != 0) {
			error_fr(r, "serialise member");
			بازگشت r;
		}
	}
	بازگشت 0;
}

ایستا صحیح
serialise_pubkey_auth_options(ثابت ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = serialise_s32(buf, options->pubkey_auth_options)) != 0 ||
	    (r = serialise_s32(buf, options->max_pubkey_ok)) != 0) {
		error_fr(r, "serialise");
		بازگشت r;
	}
	بازگشت 0;
}

ایستا صحیح
serialise_timingsecret(ثابت ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = sshbuf_put_u64(buf, options->timing_secret)) != 0) {
		error_fr(r, "serialise");
		بازگشت r;
	}
	بازگشت 0;
}


صحیح
serialise_server_options(ثابت ServerOptions *options, ساختار sshbuf **bufp)
{
	ساختار sshbuf *buf = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	*bufp = پوچ;

	اگر ((buf = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_VERSION)) != 0) {
		error_fr(r, "serialise version");
		برو out;
	}

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	اگر ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		برو out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	اگر ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		برو out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	اگر ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		برو out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	اگر ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		برو out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	اگر ((r = serialise_##funcsuffix(options, buf)) != 0) \
		برو out;
#define SSHCONF_NONCONF(funcsuffix) \
	اگر ((r = serialise_##funcsuffix(options, buf)) != 0) \
		برو out;
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
	buf = پوچ; /* transferred */
 out:
	sshbuf_free(buf);
	بازگشت r;
}

ایستا صحیح
deserialise_s32(ساختار sshbuf *buf, صحیح *v)
{
	uint32_t tmp;
	صحیح r;
	u_char was_signed;

	اگر ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u32(buf, &tmp)) != 0)
		بازگشت r;
	اگر (was_signed > 1)
		بازگشت SSH_ERR_INVALID_FORMAT;
	اگر (was_signed) {
		اگر (tmp > (uint32_t)INT_MAX + 1)
			بازگشت SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)INT_MAX + 1 ? INT_MIN : -(صحیح)tmp;
	} وگرنه {
		اگر (tmp > INT_MAX)
			بازگشت SSH_ERR_INVALID_FORMAT;
		*v = (صحیح)tmp;
	}
	بازگشت 0;
}

ایستا صحیح
deserialise_s64(ساختار sshbuf *buf, int64_t *v)
{
	uint64_t tmp;
	صحیح r;
	u_char was_signed;

	اگر ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u64(buf, &tmp)) != 0)
		بازگشت r;
	اگر (was_signed > 1)
		بازگشت SSH_ERR_INVALID_FORMAT;
	اگر (was_signed) {
		اگر (tmp > (uint64_t)INT64_MAX + 1)
			بازگشت SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint64_t)INT64_MAX + 1 ?
		    INT64_MIN : -(int64_t)tmp;
	} وگرنه {
		اگر (tmp > INT64_MAX)
			بازگشت SSH_ERR_INVALID_FORMAT;
		*v = (int64_t)tmp;
	}
	بازگشت 0;
}

ایستا صحیح
deserialise_mode(ساختار sshbuf *buf, mode_t *v)
{
	صحیح r, tmp;

	اگر ((r = deserialise_s32(buf, &tmp)) != 0)
		بازگشت r;
	اگر (tmp == -1) {
		*v = (mode_t)-1;
		بازگشت 0;
	}
	اگر (tmp < 0 || tmp > 0777)
		بازگشت SSH_ERR_INVALID_FORMAT;
	*v = (mode_t)tmp;
	بازگشت 0;
}

ایستا صحیح
deserialise_double(ساختار sshbuf *buf, دوگانه *v)
{
	بازگشت sshbuf_get(buf, v, اندازه(*v));
}

ایستا صحیح
deserialise_nullable_string(ساختار sshbuf *buf, نویسه **sp)
{
	صحیح r;
	u_char present;

	اگر ((r = sshbuf_get_u8(buf, &present)) != 0)
		بازگشت r;
	اگر (present == 0) {
		*sp = پوچ;
		بازگشت 0;
	}
	اگر (present != 1)
		بازگشت SSH_ERR_INVALID_FORMAT;
	بازگشت sshbuf_get_cstring(buf, sp, پوچ);
}

ایستا تهی
free_string_array(نویسه **a, u_int n)
{
	u_int i;

	اگر (a == پوچ)
		بازگشت;
	برای (i = 0; i < n; i++)
		آزاد(a[i]);
	آزاد(a);
}

ایستا صحیح
deserialise_شمار(ساختار sshbuf *buf, u_int *np, ثابت نویسه *what)
{
	صحیح r;
	uint32_t n;

	اگر ((r = sshbuf_get_u32(buf, &n)) != 0) {
		error_fr(r, "deserialise %s length", what);
		بازگشت r;
	}
	اگر (n > UINT_MAX) {
		error_f("bad number of %s", what);
		بازگشت SSH_ERR_INVALID_FORMAT;
	}
	اگر (n > sshbuf_len(buf)) {
		error_f("bad number of %s", what);
		بازگشت SSH_ERR_INVALID_FORMAT;
	}
	*np = n;
	بازگشت 0;
}

ایستا صحیح
deserialise_nullable_string_array(ساختار sshbuf *buf, نویسه ***arrayp,
    u_int *np)
{
	نویسه **a = پوچ;
	صحیح r;
	u_int i, n;

	*arrayp = پوچ;
	*np = 0;
	اگر ((r = deserialise_شمار(buf, &n, "strings")) != 0)
		بازگشت r;
	اگر (n > 0)
		a = xcalloc(n, اندازه(*a));
	برای (i = 0; i < n; i++) {
		اگر ((r = deserialise_nullable_string(buf, a + i)) != 0) {
			free_string_array(a, i + 1);
			بازگشت r;
		}
	}
	*arrayp = a;
	*np = n;
	بازگشت 0;
}

ایستا تهی
free_queued_listen_addrs(ساختار queued_listenaddr *qla, u_int n)
{
	u_int i;

	اگر (qla == پوچ)
		بازگشت;
	برای (i = 0; i < n; i++) {
		آزاد(qla[i].addr);
		آزاد(qla[i].rdomain);
	}
	آزاد(qla);
}

ایستا صحیح
deserialise_hostkeyfile(ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r, *userprovided = پوچ;
	u_int i, n;
	نویسه **files = پوچ;

	اگر ((r = deserialise_شمار(buf, &n, "host key files")) != 0)
		بازگشت r;
	اگر (n > 0) {
		userprovided = xcalloc(n, اندازه(*userprovided));
		files = xcalloc(n, اندازه(*files));
	}
	برای (i = 0; i < n; i++) {
		اگر ((r = deserialise_s32(buf, userprovided + i)) != 0 ||
		    (r = deserialise_nullable_string(buf, files + i)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(files, i + 1);
			آزاد(userprovided);
			بازگشت r;
		}
	}
	options->رقم_host_کلید_files = n;
	options->host_کلید_file_userprovided = userprovided;
	options->host_کلید_files = files;
	بازگشت 0;
}

ایستا صحیح
deserialise_ipqos(ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = deserialise_s32(buf, &options->ip_qos_interactive)) != 0 ||
	    (r = deserialise_s32(buf, &options->ip_qos_bulk)) != 0) {
		error_fr(r, "deserialise");
		بازگشت r;
	}

	بازگشت 0;
}

ایستا صحیح
deserialise_listenaddress(ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;
	u_int i, n;
	ساختار queued_listenaddr *qla = پوچ;

	اگر ((r = deserialise_شمار(buf, &n, "listen addresses")) != 0)
		بازگشت r;
	اگر (n > 0)
		qla = xcalloc(n, اندازه(*qla));
	برای (i = 0; i < n; i++) {
		اگر ((r = sshbuf_get_cstring(buf, &qla[i].addr, پوچ)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].port)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			بازگشت r;
		}
	}
	options->رقم_queued_listens = n;
	options->queued_listen_addrs = qla;
	بازگشت 0;
}

ایستا صحیح
deserialise_logfacility(ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r, tmp;

	اگر ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		بازگشت r;
	}
	اگر (tmp != SYSLOG_FACILITY_NOT_SET &&
	    log_facility_name((SyslogFacility)tmp) == پوچ) {
		error_f("bad syslog facility");
		بازگشت SSH_ERR_INVALID_FORMAT;
	}
	options->log_facility = (SyslogFacility)tmp;

	بازگشت 0;
}

ایستا صحیح
deserialise_loglevel(ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r, tmp;

	اگر ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		بازگشت r;
	}
	اگر (tmp != SYSLOG_LEVEL_NOT_SET &&
	    log_level_name((LogLevel)tmp) == پوچ) {
		error_f("bad log level");
		بازگشت SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	بازگشت 0;
}

ایستا صحیح
deserialise_port(ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;
	u_int i, n;

	اگر ((r = deserialise_شمار(buf, &n, "ports")) != 0)
		بازگشت r;
	اگر (n > MAX_PORTS) {
		error_f("bad number of ports");
		بازگشت SSH_ERR_INVALID_FORMAT;
	}
	options->رقم_ports = n;
	memset(options->ports, 0, اندازه(options->ports));
	برای (i = 0; i < options->رقم_ports; i++) {
		اگر ((r = deserialise_s32(buf, options->ports + i)) != 0) {
			error_fr(r, "deserialise port");
			بازگشت r;
		}
	}
	بازگشت 0;
}

ایستا صحیح
deserialise_gatewayports(ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = deserialise_s32(buf, &options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "deserialise");
		بازگشت r;
	}
	بازگشت 0;
}

ایستا صحیح
deserialise_streamlocalbindmask(ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = deserialise_mode(buf,
	    &options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "deserialise");
		بازگشت r;
	}
	بازگشت 0;
}

ایستا صحیح
deserialise_streamlocalbindunlink(ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;
	u_char tmp;

	اگر ((r = sshbuf_get_u8(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		بازگشت r;
	}
	اگر (tmp > 1) {
		error_f("bad boolean");
		بازگشت SSH_ERR_INVALID_FORMAT;
	}
	options->fwd_opts.streamlocal_bind_unlink = tmp;
	بازگشت 0;
}

ایستا صحیح
deserialise_maxstartups(ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = deserialise_s32(buf, &options->max_startups_begin)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups_rate)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups)) != 0) {
		error_fr(r, "deserialise");
		بازگشت r;
	}

	بازگشت 0;
}

ایستا صحیح
deserialise_permituserenv(ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = deserialise_s32(buf, &options->permit_user_env)) != 0 ||
	    (r = deserialise_nullable_string(buf,
	    &options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "deserialise");
		بازگشت r;
	}
	بازگشت 0;
}

ایستا صحیح
deserialise_persourcenetblocksize(ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		بازگشت r;
	}

	بازگشت 0;
}

ایستا صحیح
deserialise_persourcepenalties(ServerOptions *options, ساختار sshbuf *buf)
{
	ساختار per_source_penalty *psp = &options->per_source_penalty;
	صحیح r;

	اگر ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
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
		بازگشت r;
	}

	بازگشت 0;
}

ایستا صحیح
deserialise_rekeylimit(ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = deserialise_s64(buf, &options->rekey_limit)) != 0 ||
	    (r = deserialise_s32(buf, &options->rekey_interval)) != 0) {
		error_fr(r, "deserialise");
		بازگشت r;
	}

	بازگشت 0;
}

ایستا صحیح
deserialise_subsystem(ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;
	u_int i, n;
	نویسه **names = پوچ, **commands = پوچ, **args = پوچ;

	اگر ((r = deserialise_شمار(buf, &n, "subsystems")) != 0)
		بازگشت r;
	اگر (n > 0) {
		names = xcalloc(n, اندازه(*names));
		commands = xcalloc(n, اندازه(*names));
		args = xcalloc(n, اندازه(*args));
	}
	برای (i = 0; i < n; i++) {
		اگر ((r = sshbuf_get_cstring(buf, names + i, پوچ)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, پوچ)) != 0 ||
		    (r = sshbuf_get_cstring(buf, args + i, پوچ)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(names, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(args, i + 1);
			بازگشت r;
		}
	}
	options->رقم_subsystems = n;
	options->subsystem_name = names;
	options->subsystem_command = commands;
	options->subsystem_args = args;
	بازگشت 0;
}

ایستا صحیح
deserialise_pubkey_auth_options(ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = deserialise_s32(buf, &options->pubkey_auth_options)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_pubkey_ok)) != 0) {
		error_fr(r, "deserialise");
		بازگشت r;
	}
	بازگشت 0;
}

ایستا صحیح
deserialise_timingsecret(ServerOptions *options, ساختار sshbuf *buf)
{
	صحیح r;

	اگر ((r = sshbuf_get_u64(buf, &options->timing_secret)) != 0) {
		error_fr(r, "deserialise");
		بازگشت r;
	}
	بازگشت 0;
}

صحیح
deserialise_server_options(ساختار sshbuf *buf, ServerOptions *options)
{
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	uint32_t version;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	اگر ((r = sshbuf_get_u32(buf, &version)) != 0) {
		error_fr(r, "deserialise version");
		برو out;
	}
	اگر (version != SSHD_CONFIG_BLOB_VERSION) {
		error_f("unsupported config blob version %u", version);
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	اگر ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		برو out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	اگر ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		برو out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	اگر ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		برو out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	اگر ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		برو out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	اگر ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		برو out;
#define SSHCONF_NONCONF(funcsuffix) \
	اگر ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		برو out;
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	انجامبده { \
		آزاد(new_options.var); \
		new_options.var = پوچ; \
	} وقتی (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

	اگر (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
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
	memset(&new_options, 0, اندازه(new_options));
 out:
	free_server_options(&new_options);
	بازگشت r;
}

ایستا تهی
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	برای (i = 0; i < options->رقم_host_کلید_files; i++)
		آزاد(options->host_کلید_files[i]);
	آزاد(options->host_کلید_files);
	آزاد(options->host_کلید_file_userprovided);
}

ایستا تهی
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->رقم_queued_listens);

	برای (i = 0; i < options->رقم_listen_addrs; i++) {
		آزاد(options->listen_addrs[i].rdomain);
		اگر (options->listen_addrs[i].addrs != پوچ)
			freeaddrinfo(options->listen_addrs[i].addrs);
	}
	آزاد(options->listen_addrs);
}

ایستا تهی
free_permituserenv(ServerOptions *options)
{
	آزاد(options->permit_user_env_allowlist);
}

ایستا تهی
free_subsystem(ServerOptions *options)
{
	u_int i;

	برای (i = 0; i < options->رقم_subsystems; i++) {
		آزاد(options->subsystem_name[i]);
		آزاد(options->subsystem_command[i]);
		آزاد(options->subsystem_args[i]);
	}
	آزاد(options->subsystem_name);
	آزاد(options->subsystem_command);
	آزاد(options->subsystem_args);
}

تهی
free_server_options(ServerOptions *options)
{
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	/* empty */
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	/* empty */
#define SSHCONF_STRING(var, conf, flags, cp)		آزاد(options->var);
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#define SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	انجامبده { \
		آزاد(options->var); \
		options->var = پوچ; \
	} وقتی (0);
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

ایستا تهی
copy_server_option_int(صحیح *dst, صحیح src)
{
	اگر (src != -1)
		*dst = src;
}

ایستا تهی
copy_server_option_int64(int64_t *dst, int64_t src)
{
	اگر (src != -1)
		*dst = src;
}

ایستا تهی
copy_server_option_string(نویسه **dst, ثابت نویسه *src)
{
	اگر (src != پوچ && *dst != src) {
		آزاد(*dst);
		*dst = xstrdup(src);
	}
}

ایستا تهی
copy_server_option_strarray_مقادیر(نویسه ***dst, u_int ndst,
    نویسه * ثابت *src, u_int nsrc)
{
	u_int i;

	اگر (nsrc == 0)
		بازگشت;
	برای (i = 0; i < ndst; i++)
		آزاد((*dst)[i]);
	آزاد(*dst);
	*dst = xcalloc(nsrc, اندازه(**dst));
	برای (i = 0; i < nsrc; i++)
		(*dst)[i] = src[i] == پوچ ? پوچ : xstrdup(src[i]);
}

ایستا تهی
copy_server_option_strarray(نویسه ***dst, u_int *ndst,
    نویسه * ثابت *src, u_int nsrc)
{
	اگر (nsrc == 0)
		بازگشت;
	copy_server_option_strarray_مقادیر(dst, *ndst, src, nsrc);
	*ndst = nsrc;
}

ایستا تهی
copy_ipqos(ServerOptions *dst, ثابت ServerOptions *src)
{
	copy_server_option_int(&dst->ip_qos_interactive,
	    src->ip_qos_interactive);
	copy_server_option_int(&dst->ip_qos_bulk, src->ip_qos_bulk);
}

ایستا تهی
copy_gatewayports(ServerOptions *dst, ثابت ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.gateway_ports,
	    src->fwd_opts.gateway_ports);
}

ایستا تهی
copy_streamlocalbindunlink(ServerOptions *dst, ثابت ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.streamlocal_bind_unlink,
	    src->fwd_opts.streamlocal_bind_unlink);
}

ایستا تهی
copy_loglevel(ServerOptions *dst, ثابت ServerOptions *src)
{
	اگر (src->log_level != -1)
		dst->log_level = src->log_level;
}

ایستا تهی
copy_rekeylimit(ServerOptions *dst, ثابت ServerOptions *src)
{
	copy_server_option_int64(&dst->rekey_limit, src->rekey_limit);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

ایستا تهی
copy_subsystem(ServerOptions *dst, ثابت ServerOptions *src)
{
	u_int old_رقم_subsystems = dst->رقم_subsystems;

	اگر (src->رقم_subsystems == 0)
		بازگشت;
	copy_server_option_strarray_مقادیر(&dst->subsystem_name,
	    old_رقم_subsystems, src->subsystem_name, src->رقم_subsystems);
	copy_server_option_strarray_مقادیر(&dst->subsystem_command,
	    old_رقم_subsystems, src->subsystem_command, src->رقم_subsystems);
	copy_server_option_strarray_مقادیر(&dst->subsystem_args,
	    old_رقم_subsystems, src->subsystem_args, src->رقم_subsystems);
	dst->رقم_subsystems = src->رقم_subsystems;
}

ایستا تهی
copy_pubkey_auth_options(ServerOptions *dst, ثابت ServerOptions *src)
{
	اگر (src->pubkey_auth_options != -1) {
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
تهی
copy_set_server_options(ServerOptions *dst, ServerOptions *src, صحیح preauth)
{
	اگر (dst == src)
		بازگشت;

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
	انجامبده { \
		آزاد(dst->var); \
		dst->var = پوچ; \
	} وقتی (0);
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
	اگر (src->fwd_opts.streamlocal_bind_mask != (mode_t)-1) {
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
	انجامبده { \
		اگر (option_clear_or_none(v)) { \
			آزاد(v); \
			v = پوچ; \
		} \
	} وقتی(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_کلیدها);
	CLEAR_ON_NONE(dst->banner);

	/*
	 * The only things that should be below this point are string options
	 * which are only used after authentication.
	 */
	اگر (preauth)
		بازگشت;

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
ایستا تهی
parse_server_config_depth(ServerOptions *options, ثابت نویسه *filename,
    ساختار sshbuf *conf, ساختار include_list *includes,
    ساختار connection_info *connectinfo, صحیح flags, صحیح *activep, صحیح depth)
{
	صحیح linenum, bad_options = 0;
	نویسه *cp, *obuf, *cbuf;

	اگر (depth < 0 || depth > SERVCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	اگر ((obuf = cbuf = sshbuf_dup_string(conf)) == پوچ)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	وقتی ((cp = strsep(&cbuf, "\n")) != پوچ) {
		اگر (process_server_config_سطر_depth(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    depth, includes) != 0)
			bad_options++;
	}
	آزاد(obuf);
	اگر (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

تهی
parse_server_config(ServerOptions *options, ثابت نویسه *filename,
    ساختار sshbuf *conf, ساختار include_list *includes,
    ساختار connection_info *connectinfo, صحیح reexec)
{
	صحیح active = connectinfo ? 0 : 1;
	parse_server_config_depth(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_MATCH_ONLY : 0), &active, 0);
	اگر (!reexec)
		process_queued_listen_addrs(options);
}

ایستا ثابت نویسه *
fmt_multistate_int(صحیح val, ثابت ساختار multistate *m)
{
	u_int i;

	برای (i = 0; m[i].کلید != پوچ; i++) {
		اگر (m[i].مقدار == val)
			بازگشت m[i].کلید;
	}
	بازگشت "UNKNOWN";
}

ایستا ثابت نویسه *
fmt_intarg(ServerOpCodes code, صحیح val)
{
	اگر (val == -1)
		بازگشت "unset";
	انتخاب (code) {
	حالت sAddressFamily:
		بازگشت fmt_multistate_int(val, multistate_addressfamily);
	حالت s_Permit_ریشه_Login:
		بازگشت fmt_multistate_int(val, multistate_permitrootlogin);
	حالت sGatewayPorts:
		بازگشت fmt_multistate_int(val, multistate_gatewayports);
	حالت sCompression:
		بازگشت fmt_multistate_int(val, multistate_compression);
	حالت sAllowTcpForwarding:
		بازگشت fmt_multistate_int(val, multistate_tcpfwd);
	حالت sAllowStreamLocalForwarding:
		بازگشت fmt_multistate_int(val, multistate_tcpfwd);
	حالت sIgnoreRhosts:
		بازگشت fmt_multistate_int(val, multistate_ignore_rhosts);
	حالت sTCPKeepAlive:
		بازگشت fmt_multistate_int(val, multistate_keepalives);
	حالت sWarnWeakCrypto:
		بازگشت fmt_multistate_int(val, multistate_warnweakcrypto);
	حالت sFingerprintHash:
		بازگشت ssh_digest_alg_name(val);
	پیشفرض:
		انتخاب (val) {
		حالت 0:
			بازگشت "no";
		حالت 1:
			بازگشت "yes";
		پیشفرض:
			بازگشت "UNKNOWN";
		}
	}
}

ایستا تهی
dump_cfg_int(ServerOpCodes code, صحیح val)
{
	اگر (code == sUnusedConnectionTimeout && val == 0) {
		printf("%s none\n", lookup_opcode_name(code));
		بازگشت;
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

ایستا تهی
dump_cfg_oct(ServerOpCodes code, صحیح val)
{
	printf("%s 0%o\n", lookup_opcode_name(code), val);
}

ایستا تهی
dump_cfg_fmtint(ServerOpCodes code, صحیح val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

ایستا تهی
dump_cfg_string(ServerOpCodes code, ثابت نویسه *val)
{
	printf("%s %s\n", lookup_opcode_name(code),
	    val == پوچ ? "none" : val);
}

ایستا تهی
dump_cfg_strarray(ServerOpCodes code, u_int شمار, نویسه **vals)
{
	u_int i;

	برای (i = 0; i < شمار; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

ایستا تهی
dump_cfg_strarray_oneline(ServerOpCodes code, u_int شمار, نویسه **vals)
{
	u_int i;

	انتخاب (code) {
	حالت sAuthenticationMethods:
	حالت sChannelTimeout:
		بشکن;
	پیشفرض:
		اگر (شمار <= 0)
			بازگشت;
		بشکن;
	}

	printf("%s", lookup_opcode_name(code));
	برای (i = 0; i < شمار; i++)
		printf(" %s",  vals[i]);
	اگر (code == sAuthenticationMethods && شمار == 0)
		printf(" any");
	وگرنه اگر (code == sChannelTimeout && شمار == 0)
		printf(" none");
	printf("\n");
}

ایستا نویسه *
format_listen_addrs(ساختار listenaddr *la)
{
	صحیح r;
	ساختار addrinfo *ai;
	نویسه addr[NI_MAXHOST], port[NI_MAXSERV];
	نویسه *laddr1 = xstrdup(""), *laddr2 = پوچ;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	برای (ai = la->addrs; ai; ai = ai->ai_next) {
		اگر ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    اندازه(addr), port, اندازه(port),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			ادامه;
		}
		laddr2 = laddr1;
		اگر (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == پوچ ? "" : " rdomain ",
			    la->rdomain == پوچ ? "" : la->rdomain,
			    laddr2);
		} وگرنه {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == پوچ ? "" : " rdomain ",
			    la->rdomain == پوچ ? "" : la->rdomain,
			    laddr2);
		}
		آزاد(laddr2);
	}
	بازگشت laddr1;
}

تهی
dump_config(ServerOptions *o)
{
	نویسه *s;
	u_int i;

	/* these are usually at the top of the config */
	برای (i = 0; i < o->رقم_ports; i++)
		printf("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(sAddressFamily, o->address_family);

	برای (i = 0; i < o->رقم_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		printf("%s", s);
		آزاد(s);
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
	dump_cfg_int(s_Client_Alive_شمار_Max, o->client_alive_شمار_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_size);
	dump_cfg_oct(sStreamLocalBindMask, o->fwd_opts.streamlocal_bind_mask);
	dump_cfg_int(sUnusedConnectionTimeout, o->unused_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(s_Permit_ریشه_Login, o->permit_ریشه_login);
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
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_کلیدها);
	dump_cfg_string(s_Security_کلید_Provider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(sVersionAddendum, *o->version_addendum == '\0'
	    ? "none" : o->version_addendum);
	dump_cfg_string(s_Authorized_کلیدها_Command, o->authorized_کلیدها_command);
	dump_cfg_string(s_Authorized_کلیدها_Command_User, o->authorized_کلیدها_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(s_Host_کلید_Agent, o->host_کلید_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(s_Host_کلید_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#اگر defined(__OpenBSD__) || defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
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
	dump_cfg_strarray_oneline(s_Authorized_کلیدها_File, o->رقم_authkeys_files,
	    o->authorized_کلیدها_files);
	dump_cfg_strarray_oneline(s_Revoked_کلیدها, o->رقم_revoked_کلیدها_files,
	    o->revoked_کلیدها_files);
	dump_cfg_strarray(s_Host_کلید, o->رقم_host_کلید_files, o->host_کلید_files);
	dump_cfg_strarray(sHostCertificate, o->رقم_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->رقم_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->رقم_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->رقم_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->رقم_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->رقم_accept_env, o->accept_env);
	dump_cfg_strarray(sSetEnv, o->رقم_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->رقم_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->رقم_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->رقم_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	برای (i = 0; i < o->رقم_subsystems; i++)
		printf("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_args[i]);

	printf("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_rate, o->max_startups);
	printf("PerSourceMaxStartups ");
	اگر (o->per_source_max_startups == INT_MAX)
		printf("none\n");
	وگرنه
		printf("%d\n", o->per_source_max_startups);
	printf("PerSourceNetBlockSize %d:%d\n", o->per_source_masklen_ipv4,
	    o->per_source_masklen_ipv6);

	s = پوچ;
	برای (i = 0; tunmode_desc[i].val != -1; i++) {
		اگر (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].text;
			بشکن;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	printf("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	printf("%s\n", iptos2str(o->ip_qos_bulk));

	printf("RekeyLimit %llu %d\n", (unsigned long long)o->rekey_limit,
	    o->rekey_interval);

	printf("PermitOpen");
	اگر (o->رقم_permitted_opens == 0)
		printf(" any");
	وگرنه {
		برای (i = 0; i < o->رقم_permitted_opens; i++)
			printf(" %s", o->permitted_opens[i]);
	}
	printf("\n");
	printf("PermitListen");
	اگر (o->رقم_permitted_listens == 0)
		printf(" any");
	وگرنه {
		برای (i = 0; i < o->رقم_permitted_listens; i++)
			printf(" %s", o->permitted_listens[i]);
	}
	printf("\n");

	اگر (o->permit_user_env_allowlist == پوچ) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} وگرنه {
		printf("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	printf("PubkeyAuthOptions");
	اگر (o->pubkey_auth_options == 0)
		printf(" none");
	اگر (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		printf(" touch-required");
	اگر (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		printf(" verify-required");
	اگر (o->max_pubkey_ok != -1)
		printf(" max-pk-ok:%d", o->max_pubkey_ok);
	printf("\n");

	اگر (o->per_source_penalty.enabled) {
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
	} وگرنه
		printf("PerSourcePenalties no\n");
}
