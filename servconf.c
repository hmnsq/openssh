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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/socket.h>
#ضمن <sys/queue.h>
#ضمن <sys/stat.h>
#ifdef __OpenBSD__
#ضمن <sys/sysctl.h>
#endif

#ضمن <netinet/in.h>
#ضمن <netinet/ip.h>
#ifdef HAVE_NET_ROUTE_H
#ضمن <net/route.h>
#endif

#ضمن <ctype.h>
#ضمن <glob.h>
#ضمن <netdb.h>
#ضمن <pwd.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <signal.h>
#ضمن <unistd.h>
#ضمن <limits.h>
#ضمن <stdarg.h>
#ضمن <errno.h>
#ضمن <util.h>

#ضمن "xmalloc.h"
#ضمن "ssh.h"
#ضمن "log.h"
#ضمن "sshbuf.h"
#ضمن "misc.h"
#ضمن "servconf.h"
#ضمن "pathnames.h"
#ضمن "cipher.h"
#ضمن "sshkey.h"
#ضمن "kex.h"
#ضمن "mac.h"
#ضمن "match.h"
#ضمن "channels.h"
#ضمن "groupaccess.h"
#ضمن "canohost.h"
#ضمن "packet.h"
#ضمن "ssherr.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "myproposal.h"
#ضمن "digest.h"
#ضمن "version.h"

#define SSHD_CONFIG_BLOB_VERSION	1

#𐡄𐡍 !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#endif

ساكن فراغ add_listen_addr(ServerOptions *, ثابت حرف *,
    ثابت حرف *, صحيح);
ساكن فراغ add_one_listen_addr(ServerOptions *, ثابت حرف *,
    ثابت حرف *, صحيح);
ساكن فراغ parse_server_config_depth(ServerOptions *options,
    ثابت حرف *filename, بنية sshbuf *conf, بنية include_list *includes,
    بنية connection_info *connectinfo, صحيح flags, صحيح *activep, صحيح depth);

خارجي بنية sshbuf *cfg;

/* Initializes the server options to their default values. */

فراغ
initialize_server_options(ServerOptions *options)
{
	memset(options, 0, حجم(*options));
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#define SSHCONF_STRING(var, conf, flags, cp)		options->var = عدم;
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = عدم;
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#define SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = عدم;
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	/* Using macros for these is a bit overkill but forces consistency */
#define init_hostkeyfile(options) \
	options->host_key_files = 0; \
	options->num_host_key_files = 0; \
	options->host_key_file_userprovided = عدم;
#define init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#define init_listenaddress(options) \
	options->queued_listen_addrs = عدم; \
	options->num_queued_listens = 0; \
	options->listen_addrs = عدم; \
	options->num_listen_addrs = 0;
#define init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
#define init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_SET;
#define init_port(options) \
	options->num_ports = 0; \
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
	options->permit_user_env_allowlist = عدم;
#define init_persourcenetblocksize(options) \
	options->per_source_masklen_ipv4 = -1; \
	options->per_source_masklen_ipv6 = -1;
#define init_persourcepenalties(options) \
	options->per_source_penalty_exempt = عدم; \
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
	options->num_subsystems = 0; \
	options->subsystem_name = عدم; \
	options->subsystem_command = عدم; \
	options->subsystem_args = عدم;
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
ساكن صحيح
option_clear_or_none(ثابت حرف *o)
{
	أرجع o == عدم || strcasecmp(o, "none") == 0;
}

ساكن فراغ
assemble_algorithms(ServerOptions *o)
{
	حرف *all_cipher, *all_mac, *all_kex, *all_key, *all_sig;
	حرف *def_cipher, *def_mac, *def_kex, *def_key, *def_sig;
	صحيح r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_key = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_key = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_key);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	𐡏𐡁𐡃 { \
		𐡄𐡍 ((r = kex_assemble_names(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} طالما (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_key, all_key);
	ASSEMBLE(hostbased_accepted_algos, def_key, all_key);
	ASSEMBLE(pubkey_accepted_algos, def_key, all_key);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE
	حرر(all_cipher);
	حرر(all_mac);
	حرر(all_kex);
	حرر(all_key);
	حرر(all_sig);
	حرر(def_cipher);
	حرر(def_mac);
	حرر(def_kex);
	حرر(def_key);
	حرر(def_sig);
}

فراغ
servconf_add_hostkey(ثابت حرف *file, ثابت صحيح line,
    ServerOptions *options, ثابت حرف *path, صحيح userprovided)
{
	حرف *apath = derelativise_path(path);

	opt_array_append2(file, line, "HostKey",
	    &options->host_key_files, &options->host_key_file_userprovided,
	    &options->num_host_key_files, apath, userprovided);
	حرر(apath);
}

فراغ
servconf_add_hostcert(ثابت حرف *file, ثابت صحيح line,
    ServerOptions *options, ثابت حرف *path)
{
	حرف *apath = derelativise_path(path);

	opt_array_append(file, line, "HostCertificate",
	    &options->host_cert_files, &options->num_host_cert_files, apath);
	حرر(apath);
}

فراغ
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#ifdef SKIP_PRIVDROP
	𐡄𐡍 (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	𐡄𐡍 (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#endif

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	𐡄𐡍 (options->var == -1) \
		options->var = def;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	𐡄𐡍 (options->var == -1) \
		options->var = def;
#define SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#define SSHCONF_NONCONF(funcsuffix)			/* done manually */
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	𐡏𐡁𐡃 { \
		حرر(options->var); \
		options->var = عدم; \
	} طالما (0);
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
	𐡄𐡍 (options->pam_service_name == عدم)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#endif

	𐡄𐡍 (options->num_host_key_files == 0) {
		/* fill default hostkeys */
		servconf_add_hostkey("[default]", 0, options,
		    _PATH_HOST_RSA_KEY_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    _PATH_HOST_ECDSA_KEY_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    _PATH_HOST_ED25519_KEY_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    _PATH_HOST_MLDSA44_ED25519_KEY_FILE, 0);
	}
	/* No certificates by default */
	𐡄𐡍 (options->num_ports == 0)
		options->ports[options->num_ports++] = SSH_DEFAULT_PORT;
	𐡄𐡍 (options->listen_addrs == عدم)
		add_listen_addr(options, عدم, عدم, 0);
	𐡄𐡍 (options->pid_file == عدم)
		options->pid_file = xstrdup(_PATH_SSH_DAEMON_PID_FILE);
	𐡄𐡍 (options->moduli_file == عدم)
		options->moduli_file = xstrdup(_PATH_DH_MODULI);
	𐡄𐡍 (options->xauth_location == عدم)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	𐡄𐡍 (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	𐡄𐡍 (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	𐡄𐡍 (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = عدم;
	}
	𐡄𐡍 (options->rekey_limit == -1)
		options->rekey_limit = 0;
	𐡄𐡍 (options->rekey_interval == -1)
		options->rekey_interval = 0;
	𐡄𐡍 (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	𐡄𐡍 (options->max_startups == -1)
		options->max_startups = 100;
	𐡄𐡍 (options->max_startups_rate == -1)
		options->max_startups_rate = 30;		/* 30% */
	𐡄𐡍 (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	𐡄𐡍 (options->per_source_masklen_ipv4 == -1)
		options->per_source_masklen_ipv4 = 32;
	𐡄𐡍 (options->per_source_masklen_ipv6 == -1)
		options->per_source_masklen_ipv6 = 128;
	𐡄𐡍 (options->per_source_penalty.enabled == -1)
		options->per_source_penalty.enabled = 1;
	𐡄𐡍 (options->per_source_penalty.max_sources4 == -1)
		options->per_source_penalty.max_sources4 = 65536;
	𐡄𐡍 (options->per_source_penalty.max_sources6 == -1)
		options->per_source_penalty.max_sources6 = 65536;
	𐡄𐡍 (options->per_source_penalty.overflow_mode == -1)
		options->per_source_penalty.overflow_mode = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
	𐡄𐡍 (options->per_source_penalty.overflow_mode6 == -1)
		options->per_source_penalty.overflow_mode6 = options->per_source_penalty.overflow_mode;
	𐡄𐡍 (options->per_source_penalty.penalty_crash < 0.0)
		options->per_source_penalty.penalty_crash = 90.0;
	𐡄𐡍 (options->per_source_penalty.penalty_grace < 0.0)
		options->per_source_penalty.penalty_grace = 10.0;
	𐡄𐡍 (options->per_source_penalty.penalty_authfail < 0.0)
		options->per_source_penalty.penalty_authfail = 5.0;
	𐡄𐡍 (options->per_source_penalty.penalty_invaliduser < 0.0)
		options->per_source_penalty.penalty_invaliduser = 5.0;
	𐡄𐡍 (options->per_source_penalty.penalty_noauth < 0.0)
		options->per_source_penalty.penalty_noauth = 1.0;
	𐡄𐡍 (options->per_source_penalty.penalty_refuseconnection < 0.0)
		options->per_source_penalty.penalty_refuseconnection = 10.0;
	𐡄𐡍 (options->per_source_penalty.penalty_min < 0.0)
		options->per_source_penalty.penalty_min = 15.0;
	𐡄𐡍 (options->per_source_penalty.penalty_max < 0.0)
		options->per_source_penalty.penalty_max = 600.0;
	𐡄𐡍 (options->num_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_keys_files,
		    &options->num_authkeys_files,
		    _PATH_SSH_USER_PERMITTED_KEYS);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_keys_files,
		    &options->num_authkeys_files,
		    _PATH_SSH_USER_PERMITTED_KEYS2);
	}
	𐡄𐡍 (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	𐡄𐡍 (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	𐡄𐡍 (options->version_addendum == عدم)
		options->version_addendum = xstrdup("");
	𐡄𐡍 (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	𐡄𐡍 (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	𐡄𐡍 (options->sk_provider == عدم)
		options->sk_provider = xstrdup("internal");
	𐡄𐡍 (options->sshd_session_path == عدم)
		options->sshd_session_path = xstrdup(_PATH_SSHD_SESSION);
	𐡄𐡍 (options->sshd_auth_path == عدم)
		options->sshd_auth_path = xstrdup(_PATH_SSHD_AUTH);
	𐡄𐡍 (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	𐡄𐡍 (options->agent_socket_path == عدم)
		options->agent_socket_path = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#define CLEAR_ON_NONE(v) \
	𐡏𐡁𐡃 { \
		𐡄𐡍 (option_clear_or_none(v)) { \
			حرر(v); \
			v = عدم; \
		} \
	} طالما(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	𐡏𐡁𐡃 { \
		𐡄𐡍 (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			حرر(options->v[0]); \
			حرر(options->v); \
			options->v = عدم; \
			options->nv = 0; \
		} \
	} طالما (0)
	CLEAR_ON_NONE(options->pid_file);
	CLEAR_ON_NONE(options->xauth_location);
	CLEAR_ON_NONE(options->banner);
	CLEAR_ON_NONE(options->trusted_user_ca_keys);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_key_agent);
	CLEAR_ON_NONE(options->per_source_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_path);

	لكل (i = 0; i < options->num_host_key_files; i++)
		CLEAR_ON_NONE(options->host_key_files[i]);
	لكل (i = 0; i < options->num_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, num_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, num_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_keys_files, num_revoked_keys_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_keys_files, num_authkeys_files, "none");
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
تعريفنوع تعداد {
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
ساكن بنية {
	ثابت حرف *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", sMatch, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ عدم, sBadOption, 0 }
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

ساكن بنية {
	صحيح val;
	حرف *text;
} tunmode_desc[] = {
	{ SSH_TUNMODE_NO, "no" },
	{ SSH_TUNMODE_POINTOPOINT, "point-to-point" },
	{ SSH_TUNMODE_ETHERNET, "ethernet" },
	{ SSH_TUNMODE_YES, "yes" },
	{ -1, عدم }
};

/* Returns an opcode name from its number */

ساكن ثابت حرف *
lookup_opcode_name(ServerOpCodes code)
{
	u_int i;

	لكل (i = 0; keywords[i].name != عدم; i++)
		𐡄𐡍 (keywords[i].opcode == code)
			أرجع(keywords[i].name);
	أرجع "UNKNOWN";
}


/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

ساكن ServerOpCodes
parse_token(ثابت حرف *cp, ثابت حرف *filename,
	    صحيح linenum, u_int *flags)
{
	u_int i;

	لكل (i = 0; keywords[i].name; i++)
		𐡄𐡍 (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			أرجع keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	أرجع sBadOption;
}

حرف *
derelativise_path(ثابت حرف *path)
{
	حرف *expanded, *ret, cwd[PATH_MAX];

	𐡄𐡍 (strcasecmp(path, "none") == 0)
		أرجع xstrdup("none");
	expanded = tilde_expand_filename(path, getuid());
	𐡄𐡍 (path_absolute(expanded))
		أرجع expanded;
	𐡄𐡍 (getcwd(cwd, حجم(cwd)) == عدم)
		fatal_f("getcwd: %s", strerror(errno));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	حرر(expanded);
	أرجع ret;
}

ساكن فراغ
add_listen_addr(ServerOptions *options, ثابت حرف *addr,
    ثابت حرف *rdomain, صحيح port)
{
	u_int i;

	𐡄𐡍 (port > 0)
		add_one_listen_addr(options, addr, rdomain, port);
	وإلا {
		لكل (i = 0; i < options->num_ports; i++) {
			add_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

ساكن فراغ
add_one_listen_addr(ServerOptions *options, ثابت حرف *addr,
    ثابت حرف *rdomain, صحيح port)
{
	بنية addrinfo hints, *ai, *aitop;
	حرف strport[NI_MAXSERV];
	صحيح gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	لكل (i = 0; i < options->num_listen_addrs; i++) {
		𐡄𐡍 (rdomain == عدم && options->listen_addrs[i].rdomain == عدم)
			اكسر;
		𐡄𐡍 (rdomain == عدم || options->listen_addrs[i].rdomain == عدم)
			استمر;
		𐡄𐡍 (strcmp(rdomain, options->listen_addrs[i].rdomain) == 0)
			اكسر;
	}
	𐡄𐡍 (i >= options->num_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		𐡄𐡍 (i >= INT_MAX)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->num_listen_addrs, options->num_listen_addrs + 1,
		    حجم(*options->listen_addrs));
		i = options->num_listen_addrs++;
		𐡄𐡍 (rdomain != عدم)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	memset(&hints, 0, حجم(hints));
	hints.ai_family = options->address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == عدم) ? AI_PASSIVE : 0;
	snprintf(strport, حجم strport, "%d", port);
	𐡄𐡍 ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    ssh_gai_strerror(gaierr));
	لكل (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs[i].addrs;
	options->listen_addrs[i].addrs = aitop;
}

/* Returns nonzero if the routing domain name is valid */
ساكن صحيح
valid_rdomain(ثابت حرف *name)
{
#𐡄𐡍 defined(HAVE_SYS_VALID_RDOMAIN)
	أرجع sys_valid_rdomain(name);
#وإلاإذا defined(__OpenBSD__)
	ثابت حرف *errstr;
	long long num;
	بنية rt_tableinfo info;
	صحيح mib[6];
	size_t miblen = حجم(mib);

	𐡄𐡍 (name == عدم)
		أرجع 1;

	num = strtonum(name, 0, 255, &errstr);
	𐡄𐡍 (errstr != عدم)
		أرجع 0;

	/* Check whether the table actually exists */
	memset(mib, 0, حجم(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_TABLE;
	mib[5] = (صحيح)num;
	𐡄𐡍 (sysctl(mib, 6, &info, &miblen, عدم, 0) == -1)
		أرجع 0;

	أرجع 1;
#وإلا /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	أرجع 0;
#endif
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
ساكن فراغ
queue_listen_addr(ServerOptions *options, ثابت حرف *addr,
    ثابت حرف *rdomain, صحيح port)
{
	بنية queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->num_queued_listens, options->num_queued_listens + 1,
	    حجم(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->num_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->port = port;
	qla->rdomain = rdomain == عدم ? عدم : xstrdup(rdomain);
}

/*
 * Process queued (text) ListenAddress entries.
 */
ساكن فراغ
process_queued_listen_addrs(ServerOptions *options)
{
	u_int i;
	بنية queued_listenaddr *qla;

	𐡄𐡍 (options->num_ports == 0)
		options->ports[options->num_ports++] = SSH_DEFAULT_PORT;
	𐡄𐡍 (options->address_family == -1)
		options->address_family = AF_UNSPEC;

	لكل (i = 0; i < options->num_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		add_listen_addr(options, qla->addr, qla->rdomain, qla->port);
		حرر(qla->addr);
		حرر(qla->rdomain);
	}
	حرر(options->queued_listen_addrs);
	options->queued_listen_addrs = عدم;
	options->num_queued_listens = 0;
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

ساكن صحيح
match_cfg_line_group(ثابت حرف *grps, صحيح line, ثابت حرف *user)
{
	صحيح result = 0;
	بنية passwd *pw;

	𐡄𐡍 (user == عدم)
		اذهب out;

	𐡄𐡍 ((pw = getpwnam(user)) == عدم) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", line, user);
	} وإلا 𐡄𐡍 (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, line);
	} وإلا 𐡄𐡍 (ga_match_pattern_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, line);
	} وإلا {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, line);
		result = 1;
	}
out:
	ga_free();
	أرجع result;
}

ساكن فراغ
match_test_missing_fatal(ثابت حرف *criteria, ثابت حرف *attrib)
{
	fatal("'Match %s' in configuration but '%s' not in connection "
	    "test specification.", criteria, attrib);
}

/*
 * All of the attributes on a single Match line are ANDed together, so we need
 * to check every attribute and set the result to zero if any attribute does
 * not match.
 */
ساكن صحيح
match_cfg_line(ثابت حرف *full_line, صحيح *acp, حرف ***avp,
    صحيح line, بنية connection_info *ci)
{
	صحيح result = 1, attributes = 0, port;
	حرف *arg, *attrib = عدم, *oattrib;

	𐡄𐡍 (ci == عدم) {
		debug3("checking syntax for 'Match %s' on line %d",
		    full_line, line);
	} وإلا {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", full_line,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->address ? ci->address : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", line);
	}

	طالما ((oattrib = argv_next(acp, avp)) != عدم) {
		/* Terminate on comment */
		𐡄𐡍 (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			اكسر;
		}
		attrib = xstrdup(oattrib);
		arg = عدم;
		attributes++;
		/* Criterion "all" has no argument and must appear alone */
		𐡄𐡍 (strcasecmp(attrib, "all") == 0) {
			𐡄𐡍 (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != عدم &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				result = -1;
				اذهب out;
			}
			𐡄𐡍 (arg != عدم && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			result = 1;
			اذهب out;
		}
		/* Criterion "invalid-user" also has no argument */
		𐡄𐡍 (strcasecmp(attrib, "invalid-user") == 0) {
			𐡄𐡍 (ci == عدم) {
				result = 0;
				اذهب next;
			}
			𐡄𐡍 (ci->user_invalid == 0)
				result = 0;
			وإلا
				debug("matched invalid-user at line %d", line);
			اذهب next;
		}

		/* Keep this list in sync with below */
		𐡄𐡍 (strprefix(attrib, "user=", 1) != عدم ||
		    strprefix(attrib, "group=", 1) != عدم ||
		    strprefix(attrib, "host=", 1) != عدم ||
		    strprefix(attrib, "address=", 1) != عدم ||
		    strprefix(attrib, "localaddress=", 1) != عدم ||
		    strprefix(attrib, "localport=", 1) != عدم ||
		    strprefix(attrib, "rdomain=", 1) != عدم ||
		    strprefix(attrib, "version=", 1) != عدم) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} وإلا {
			arg = argv_next(acp, avp);
		}

		/* All other criteria require an argument */
		𐡄𐡍 (arg == عدم || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			اذهب out;
		}
		𐡄𐡍 (strcasecmp(attrib, "user") == 0) {
			𐡄𐡍 (ci == عدم || (ci->test && ci->user == عدم)) {
				result = 0;
				اذهب next;
			}
			𐡄𐡍 (ci->user == عدم)
				match_test_missing_fatal("User", "user");
			𐡄𐡍 (match_usergroup_pattern_list(ci->user, arg) != 1)
				result = 0;
			وإلا
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, line);
		} وإلا 𐡄𐡍 (strcasecmp(attrib, "group") == 0) {
			𐡄𐡍 (ci == عدم || (ci->test && ci->user == عدم)) {
				result = 0;
				اذهب next;
			}
			𐡄𐡍 (ci->user == عدم)
				match_test_missing_fatal("Group", "user");
			بدل (match_cfg_line_group(arg, line, ci->user)) {
			حالة -1:
				result = -1;
				اذهب out;
			حالة 0:
				result = 0;
			}
		} وإلا 𐡄𐡍 (strcasecmp(attrib, "host") == 0) {
			𐡄𐡍 (ci == عدم || (ci->test && ci->host == عدم)) {
				result = 0;
				اذهب next;
			}
			𐡄𐡍 (ci->host == عدم)
				match_test_missing_fatal("Host", "host");
			𐡄𐡍 (match_hostname(ci->host, arg) != 1)
				result = 0;
			وإلا
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, line);
		} وإلا 𐡄𐡍 (strcasecmp(attrib, "address") == 0) {
			𐡄𐡍 (ci == عدم || (ci->test && ci->address == عدم)) {
				𐡄𐡍 (addr_match_list(عدم, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, line);
				result = 0;
				اذهب next;
			}
			𐡄𐡍 (ci->address == عدم)
				match_test_missing_fatal("Address", "addr");
			بدل (addr_match_list(ci->address, arg)) {
			حالة 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->address, arg, line);
				اكسر;
			حالة 0:
			حالة -1:
				result = 0;
				اكسر;
			حالة -2:
				result = -1;
				اذهب out;
			}
		} وإلا 𐡄𐡍 (strcasecmp(attrib, "localaddress") == 0){
			𐡄𐡍 (ci == عدم || (ci->test && ci->laddress == عدم)) {
				𐡄𐡍 (addr_match_list(عدم, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    line);
				result = 0;
				اذهب next;
			}
			𐡄𐡍 (ci->laddress == عدم)
				match_test_missing_fatal("LocalAddress",
				    "laddr");
			بدل (addr_match_list(ci->laddress, arg)) {
			حالة 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, line);
				اكسر;
			حالة 0:
			حالة -1:
				result = 0;
				اكسر;
			حالة -2:
				result = -1;
				اذهب out;
			}
		} وإلا 𐡄𐡍 (strcasecmp(attrib, "localport") == 0) {
			𐡄𐡍 ((port = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				result = -1;
				اذهب out;
			}
			𐡄𐡍 (ci == عدم || (ci->test && ci->lport == -1)) {
				result = 0;
				اذهب next;
			}
			𐡄𐡍 (ci->lport == 0)
				match_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			𐡄𐡍 (port == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, port, line);
			وإلا
				result = 0;
		} وإلا 𐡄𐡍 (strcasecmp(attrib, "rdomain") == 0) {
			𐡄𐡍 (ci == عدم || (ci->test && ci->rdomain == عدم)) {
				result = 0;
				اذهب next;
			}
			𐡄𐡍 (ci->rdomain == عدم)
				match_test_missing_fatal("RDomain", "rdomain");
			𐡄𐡍 (match_pattern_list(ci->rdomain, arg, 0) != 1)
				result = 0;
			وإلا
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, line);
		} وإلا 𐡄𐡍 (strcasecmp(attrib, "version") == 0) {
			𐡄𐡍 (match_pattern_list(SSH_RELEASE, arg, 0) != 1)
				result = 0;
			وإلا
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, line);
		} وإلا {
			error("Unsupported Match attribute %s", oattrib);
			result = -1;
			اذهب out;
		}
 next:
		حرر(attrib);
		attrib = عدم;
	}
	𐡄𐡍 (attributes == 0) {
		error("One or more attributes required for Match");
		أرجع -1;
	}
 out:
	𐡄𐡍 (ci != عدم && result != -1)
		debug3("match %sfound on line %d", result ? "" : "not ", line);
	حرر(attrib);
	أرجع result;
}

#define WHITESPACE " \t\r\n"

/* Multistate option parsing */
بنية multistate {
	حرف *key;
	صحيح value;
};
ساكن ثابت بنية multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_ignore_rhosts[] = {
	{ "yes",			IGNORE_RHOSTS_YES },
	{ "no",				IGNORE_RHOSTS_NO },
	{ "shosts-only",		IGNORE_RHOSTS_SHOSTS },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_permitrootlogin[] = {
	{ "prohibit-password",		PERMIT_NO_PASSWD },
	{ "without-password",		PERMIT_NO_PASSWD },
	{ "forced-commands-only",	PERMIT_FORCED_ONLY },
	{ "yes",			PERMIT_YES },
	{ "no",				PERMIT_NO },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_gatewayports[] = {
	{ "clientspecified",		2 },
	{ "yes",			1 },
	{ "no",				0 },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_tcpfwd[] = {
	{ "yes",			FORWARD_ALLOW },
	{ "all",			FORWARD_ALLOW },
	{ "no",				FORWARD_DENY },
	{ "remote",			FORWARD_REMOTE },
	{ "local",			FORWARD_LOCAL },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ عدم, -1 }
};
ساكن ثابت بنية multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ عدم, -1 }
};

ساكن صحيح
process_server_config_line_depth(ServerOptions *options, حرف *line,
    ثابت حرف *filename, صحيح linenum, صحيح *activep,
    بنية connection_info *connectinfo, صحيح *inc_flags, صحيح depth,
    بنية include_list *includes)
{
	حرف *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	صحيح cmdline = 0, *intptr, value, value2, value3, n, port, oactive, r;
	مزدوج dvalue, *doubleptr = عدم;
	صحيح ca_only = 0, found = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	size_t len;
	long long val64;
	ثابت بنية multistate *multistate_ptr;
	ثابت حرف *errstr;
	بنية include_item *item;
	glob_t gbuf;
	حرف **oav = عدم, **av;
	صحيح oac = 0, ac;
	صحيح ret = -1;
	حرف **strs = عدم; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	𐡄𐡍 ((len = strlen(line)) == 0)
		أرجع 0;
	لكل (len--; len > 0; len--) {
		𐡄𐡍 (strchr(WHITESPACE "\f", line[len]) == عدم)
			اكسر;
		line[len] = '\0';
	}

	str = line;
	𐡄𐡍 ((keyword = strdelim(&str)) == عدم)
		أرجع 0;
	/* Ignore leading whitespace */
	𐡄𐡍 (*keyword == '\0')
		keyword = strdelim(&str);
	𐡄𐡍 (!keyword || !*keyword || *keyword == '#')
		أرجع 0;
	𐡄𐡍 (str == عدم || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		أرجع -1;
	}
	intptr = عدم;
	charptr = عدم;
	opcode = parse_token(keyword, filename, linenum, &flags);

	𐡄𐡍 (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		أرجع -1;
	}
	ac = oac;
	av = oav;

	𐡄𐡍 (activep == عدم) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	𐡄𐡍 (*activep && opcode != sMatch && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	𐡄𐡍 (*activep == 0 && !(flags & SSHCFG_MATCH)) {
		𐡄𐡍 (connectinfo == عدم) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} وإلا { /* this is a directive we have already processed */
			ret = 0;
			اذهب out;
		}
	}

	بدل (opcode) {
	/* Portable-specific options */
#ifdef USE_PAM
	حالة sUsePAM:
		intptr = &options->use_pam;
		اذهب parse_flag;
	حالة sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		𐡄𐡍 (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;
#endif

	/* Standard Options */
	حالة sBadOption:
		اذهب out;
	حالة sPort:
		/* ignore ports from configfile if cmdline specifies ports */
		𐡄𐡍 (options->ports_from_cmdline) {
			argv_consume(&ac);
			اكسر;
		}
		𐡄𐡍 (options->num_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->num_ports++] = a2port(arg);
		𐡄𐡍 (options->ports[options->num_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		اكسر;

	حالة sLoginGraceTime:
		intptr = &options->login_grace_time;
 parse_time:
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		𐡄𐡍 ((value = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		𐡄𐡍 (*activep && *intptr == -1)
			*intptr = value;
		اكسر;

	حالة sListenAddress:
		arg = argv_next(&ac, &av);
		𐡄𐡍 (arg == عدم || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		𐡄𐡍 (strchr(arg, '[') == عدم && (p = strchr(arg, ':')) != عدم
		    && strchr(p+1, ':') != عدم) {
			port = 0;
			p = arg;
		} وإلا {
			arg2 = عدم;
			p = hpdelim(&arg);
			𐡄𐡍 (p == عدم)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			𐡄𐡍 (arg == عدم)
				port = 0;
			وإلا 𐡄𐡍 ((port = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = عدم;
		𐡄𐡍 ((arg = argv_next(&ac, &av)) != عدم) {
			𐡄𐡍 (strcmp(arg, "rdomain") != 0 ||
			    (arg2 = argv_next(&ac, &av)) == عدم)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			𐡄𐡍 (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		queue_listen_addr(options, p, arg2, port);

		اكسر;

	حالة sAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		value = -1;
		لكل (i = 0; multistate_ptr[i].key != عدم; i++) {
			𐡄𐡍 (strcasecmp(arg, multistate_ptr[i].key) == 0) {
				value = multistate_ptr[i].value;
				اكسر;
			}
		}
		𐡄𐡍 (value == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		𐡄𐡍 (*activep && *intptr == -1)
			*intptr = value;
		اكسر;

	حالة sHostKey:
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		𐡄𐡍 (*activep) {
			servconf_add_hostkey(filename, linenum,
			    options, arg, 1);
		}
		اكسر;

	حالة sHostKeyAgent:
		charptr = &options->host_key_agent;
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		𐡄𐡍 (*activep && *charptr == عدم)
			*charptr = !strcmp(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_path(arg);
		اكسر;

	حالة sHostCertificate:
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		𐡄𐡍 (*activep)
			servconf_add_hostcert(filename, linenum, options, arg);
		اكسر;

	حالة sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		𐡄𐡍 (*activep && *charptr == عدم) {
			*charptr = derelativise_path(arg);
			/* increase optional counter */
			𐡄𐡍 (intptr != عدم)
				*intptr = *intptr + 1;
		}
		اكسر;

	حالة sModuliFile:
		charptr = &options->moduli_file;
		اذهب parse_filename;

	حالة sPermitRootLogin:
		intptr = &options->permit_root_login;
		multistate_ptr = multistate_permitrootlogin;
		اذهب parse_multistate;

	حالة sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
		multistate_ptr = multistate_ignore_rhosts;
		اذهب parse_multistate;

	حالة sIgnoreUserKnownHosts:
		intptr = &options->ignore_user_known_hosts;
 parse_flag:
		multistate_ptr = multistate_flag;
		اذهب parse_multistate;

	حالة sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		اذهب parse_flag;

	حالة sHostbasedUsesNameFromPacketOnly:
		intptr = &options->hostbased_uses_name_from_packet_only;
		اذهب parse_flag;

	حالة sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		𐡄𐡍 (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		𐡄𐡍 (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة sHostKeyAlgorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
		اذهب parse_pubkey_algos;

	حالة sCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		اذهب parse_pubkey_algos;

	حالة sPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		ca_only = 0;
		اذهب parse_flag;

	حالة sPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		اذهب parse_pubkey_algos;

	حالة sPubkeyAuthOptions:
		intptr = &options->pubkey_auth_options;
		value = 0;
		value2 = -1;
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			𐡄𐡍 (strcasecmp(arg, "none") == 0)
				استمر;
			𐡄𐡍 (strcasecmp(arg, "touch-required") == 0)
				value |= PUBKEYAUTH_TOUCH_REQUIRED;
			وإلا 𐡄𐡍 (strcasecmp(arg, "verify-required") == 0)
				value |= PUBKEYAUTH_VERIFY_REQUIRED;
			وإلا 𐡄𐡍 (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				𐡄𐡍 (errstr != عدم) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					اذهب out;
				}
			} وإلا {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				اذهب out;
			}
		}
		𐡄𐡍 (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = value;
			options->max_pubkey_ok = value2;
		}
		اكسر;

#ifdef KRB5
	حالة sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		اذهب parse_flag;

	حالة sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		اذهب parse_flag;

	حالة sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		اذهب parse_flag;
#ifdef USE_AFS
	حالة sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		اذهب parse_flag;
#endif /* USE_AFS */
#endif /* KRB5 */

#ifdef GSSAPI
	حالة sGSSAPIAuthentication:
		intptr = &options->gss_authentication;
		اذهب parse_flag;

	حالة sGSSAPICleanupCredentials:
		intptr = &options->gss_cleanup_creds;
		اذهب parse_flag;

	حالة sGSSAPIDelegateCredentials:
		intptr = &options->gss_deleg_creds;
		اذهب parse_flag;

	حالة sGSSAPIStrictAcceptorCheck:
		intptr = &options->gss_strict_acceptor;
		اذهب parse_flag;
#endif /* GSSAPI */

	حالة sPasswordAuthentication:
		intptr = &options->password_authentication;
		اذهب parse_flag;

	حالة sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		اذهب parse_flag;

	حالة sPrintMotd:
		intptr = &options->print_motd;
		اذهب parse_flag;

#ifndef DISABLE_LASTLOG
	حالة sPrintLastLog:
		intptr = &options->print_lastlog;
		اذهب parse_flag;
#endif

	حالة sX11Forwarding:
		intptr = &options->x11_forwarding;
		اذهب parse_flag;

	حالة sX11DisplayOffset:
		intptr = &options->x11_display_offset;
 parse_int:
		arg = argv_next(&ac, &av);
		𐡄𐡍 ((errstr = atoi_err(arg, &value)) != عدم)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		𐡄𐡍 (*activep && *intptr == -1)
			*intptr = value;
		اكسر;

	حالة sX11UseLocalhost:
		intptr = &options->x11_use_localhost;
		اذهب parse_flag;

	حالة sXAuthLocation:
		charptr = &options->xauth_location;
		اذهب parse_filename;

	حالة sPermitTTY:
		intptr = &options->permit_tty;
		اذهب parse_flag;

	حالة sPermitUserRC:
		intptr = &options->permit_user_rc;
		اذهب parse_flag;

	حالة sStrictModes:
		intptr = &options->strict_modes;
		اذهب parse_flag;

	حالة sTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		اذهب parse_multistate;

	حالة sPermitEmptyPasswords:
		intptr = &options->permit_empty_passwd;
		اذهب parse_flag;

	حالة sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		value = 0;
		p = عدم;
		𐡄𐡍 (strcmp(arg, "yes") == 0)
			value = 1;
		وإلا 𐡄𐡍 (strcmp(arg, "no") == 0)
			value = 0;
		وإلا {
			/* Pattern-list specified */
			value = 1;
			p = xstrdup(arg);
		}
		𐡄𐡍 (*activep && *intptr == -1) {
			*intptr = value;
			*charptr = p;
			p = عدم;
		}
		حرر(p);
		اكسر;

	حالة sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		اذهب parse_multistate;

	حالة sRekeyLimit:
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		𐡄𐡍 (strcmp(arg, "default") == 0) {
			val64 = 0;
		} وإلا {
			𐡄𐡍 (scan_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, strerror(errno));
			𐡄𐡍 (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		𐡄𐡍 (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		𐡄𐡍 (ac != 0) { /* optional rekey interval present */
			𐡄𐡍 (strcmp(av[0], "none") == 0) {
				(فراغ)argv_next(&ac, &av);	/* discard */
				اكسر;
			}
			intptr = &options->rekey_interval;
			اذهب parse_time;
		}
		اكسر;

	حالة sGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		multistate_ptr = multistate_gatewayports;
		اذهب parse_multistate;

	حالة sUseDNS:
		intptr = &options->use_dns;
		اذهب parse_flag;

	حالة sSyslogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		value = log_facility_number(arg);
		𐡄𐡍 (value == SYSLOG_FACILITY_NOT_SET)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		𐡄𐡍 (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) value;
		اكسر;

	حالة sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		value = log_level_number(arg);
		𐡄𐡍 (value == SYSLOG_LEVEL_NOT_SET)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		𐡄𐡍 (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) value;
		اكسر;

	حالة sLogVerbose:
		found = options->num_log_verbose == 0;
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			𐡄𐡍 (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب out;
			}
			/* Allow "none" only in first position */
			𐡄𐡍 (strcasecmp(arg, "none") == 0) {
				𐡄𐡍 (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		𐡄𐡍 (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		𐡄𐡍 (found && *activep) {
			options->log_verbose = strs;
			options->num_log_verbose = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		اذهب parse_multistate;

	حالة sAllowStreamLocalForwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		اذهب parse_multistate;

	حالة sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		اذهب parse_flag;

	حالة sAgentSocketPath:
		charptr = &options->agent_socket_path;
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		𐡄𐡍 (strncmp(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			𐡄𐡍 (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} وإلا 𐡄𐡍 (strncmp(arg, "user:", 5) == 0) {
			/* User paths must not be empty */
			𐡄𐡍 (arg[5] == '\0') {
				fatal("%s line %d: invalid user path.",
				    filename, linenum);
			}
		} وإلا 𐡄𐡍 (strcmp(arg, "none") != 0)
			fatal("%s line %d: invalid path.", filename, linenum);
		𐡄𐡍 (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة sDisableForwarding:
		intptr = &options->disable_forwarding;
		اذهب parse_flag;

	حالة sAllowUsers:
		chararrayptr = &options->allow_users;
		uintptr = &options->num_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			𐡄𐡍 (*arg == '\0' ||
			    match_user(عدم, عدم, عدم, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			found = 1;
			𐡄𐡍 (!*activep)
				استمر;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		𐡄𐡍 (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اكسر;

	حالة sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->num_deny_users;
		اذهب parse_allowdenyusers;

	حالة sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->num_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			𐡄𐡍 (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			found = 1;
			𐡄𐡍 (!*activep)
				استمر;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		𐡄𐡍 (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اكسر;

	حالة sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->num_deny_groups;
		اذهب parse_allowdenygroups;

	حالة sCiphers:
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		𐡄𐡍 (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		𐡄𐡍 (options->ciphers == عدم)
			options->ciphers = xstrdup(arg);
		اكسر;

	حالة sMacs:
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		𐡄𐡍 (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		𐡄𐡍 (options->macs == عدم)
			options->macs = xstrdup(arg);
		اكسر;

	حالة sKexAlgorithms:
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		𐡄𐡍 (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		𐡄𐡍 (options->kex_algorithms == عدم)
			options->kex_algorithms = xstrdup(arg);
		اكسر;

	حالة sSubsystem:
		𐡄𐡍 ((arg = argv_next(&ac, &av)) == عدم || *arg == '\0' ||
		   ((arg2 = argv_next(&ac, &av)) == عدم || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		𐡄𐡍 (!*activep) {
			argv_consume(&ac);
			اكسر;
		}
		found = 0;
		لكل (i = 0; i < options->num_subsystems; i++) {
			𐡄𐡍 (strcmp(arg, options->subsystem_name[i]) == 0) {
				found = 1;
				اكسر;
			}
		}
		𐡄𐡍 (found) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			اكسر;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->num_subsystems,
		    options->num_subsystems + 1,
		    حجم(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->num_subsystems,
		    options->num_subsystems + 1,
		    حجم(*options->subsystem_command));
		options->subsystem_args = xrecallocarray(
		    options->subsystem_args, options->num_subsystems,
		    options->num_subsystems + 1,
		    حجم(*options->subsystem_args));
		options->subsystem_name[options->num_subsystems] = xstrdup(arg);
		options->subsystem_command[options->num_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_args[options->num_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		حرر(arg2);
		حرر(arg);
		argv_consume(&ac);
		options->num_subsystems++;
		اكسر;

	حالة sMaxStartups:
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		𐡄𐡍 ((n = sscanf(arg, "%d:%d:%d",
		    &value, &value2, &value3)) == 3) {
			𐡄𐡍 (value > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} وإلا 𐡄𐡍 (n == 1) {
			value3 = value;
			value2 = -1;
		} وإلا {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		𐡄𐡍 (value <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		𐡄𐡍 (*activep && options->max_startups == -1) {
			options->max_startups_begin = value;
			options->max_startups_rate = value2;
			options->max_startups = value3;
		}
		اكسر;

	حالة sPerSourceNetBlockSize:
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		بدل (n = sscanf(arg, "%d:%d", &value, &value2)) {
		حالة 2:
			𐡄𐡍 (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		حالة 1:
			𐡄𐡍 (value < 0 || value > 32)
				n = -1;
		}
		𐡄𐡍 (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		𐡄𐡍 (*activep && options->per_source_masklen_ipv4 == -1) {
			options->per_source_masklen_ipv4 = value;
			𐡄𐡍 (n == 2)
				options->per_source_masklen_ipv6 = value2;
		}
		اكسر;

	حالة sPerSourceMaxStartups:
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		𐡄𐡍 (strcmp(arg, "none") == 0) { /* no limit */
			value = INT_MAX;
		} وإلا {
			𐡄𐡍 ((errstr = atoi_err(arg, &value)) != عدم)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		𐡄𐡍 (*activep && options->per_source_max_startups == -1)
			options->per_source_max_startups = value;
		اكسر;

	حالة sPerSourcePenaltyExemptList:
		charptr = &options->per_source_penalty_exempt;
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		𐡄𐡍 (addr_match_list(عدم, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		𐡄𐡍 (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة sPerSourcePenalties:
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			ثابت حرف *q = عدم;

			found = 1;
			intptr = عدم;
			doubleptr = عدم;
			value = -1;
			value2 = 0;
			/* Allow no/yes only in first position */
			𐡄𐡍 (strcasecmp(arg, "no") == 0 ||
			    (value2 = (strcasecmp(arg, "yes") == 0))) {
				𐡄𐡍 (ac > 0) {
					fatal("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
				}
				𐡄𐡍 (*activep &&
				    options->per_source_penalty.enabled == -1)
					options->per_source_penalty.enabled = value2;
				استمر;
			} وإلا 𐡄𐡍 ((q = strprefix(arg, "crash:", 0)) != عدم) {
				doubleptr = &options->per_source_penalty.penalty_crash;
			} وإلا 𐡄𐡍 ((q = strprefix(arg, "authfail:", 0)) != عدم) {
				doubleptr = &options->per_source_penalty.penalty_authfail;
			} وإلا 𐡄𐡍 ((q = strprefix(arg, "invaliduser:", 0)) != عدم) {
				doubleptr = &options->per_source_penalty.penalty_invaliduser;
			} وإلا 𐡄𐡍 ((q = strprefix(arg, "noauth:", 0)) != عدم) {
				doubleptr = &options->per_source_penalty.penalty_noauth;
			} وإلا 𐡄𐡍 ((q = strprefix(arg, "grace-exceeded:", 0)) != عدم) {
				doubleptr = &options->per_source_penalty.penalty_grace;
			} وإلا 𐡄𐡍 ((q = strprefix(arg, "refuseconnection:", 0)) != عدم) {
				doubleptr = &options->per_source_penalty.penalty_refuseconnection;
			} وإلا 𐡄𐡍 ((q = strprefix(arg, "max:", 0)) != عدم) {
				doubleptr = &options->per_source_penalty.penalty_max;
			} وإلا 𐡄𐡍 ((q = strprefix(arg, "min:", 0)) != عدم) {
				doubleptr = &options->per_source_penalty.penalty_min;
			} وإلا 𐡄𐡍 ((q = strprefix(arg, "max-sources4:", 0)) != عدم) {
				intptr = &options->per_source_penalty.max_sources4;
				𐡄𐡍 ((errstr = atoi_err(q, &value)) != عدم)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} وإلا 𐡄𐡍 ((q = strprefix(arg, "max-sources6:", 0)) != عدم) {
				intptr = &options->per_source_penalty.max_sources6;
				𐡄𐡍 ((errstr = atoi_err(q, &value)) != عدم)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} وإلا 𐡄𐡍 (strcmp(arg, "overflow:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				value = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} وإلا 𐡄𐡍 (strcmp(arg, "overflow:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				value = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} وإلا 𐡄𐡍 (strcmp(arg, "overflow6:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				value = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} وإلا 𐡄𐡍 (strcmp(arg, "overflow6:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				value = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} وإلا {
				fatal("%s line %d: unsupported %s keyword %s",
				    filename, linenum, keyword, arg);
			}

			𐡄𐡍 (doubleptr != عدم) {
				𐡄𐡍 ((dvalue = convtime_double(q)) < 0) {
					fatal("%s line %d: invalid %s time value.",
					    filename, linenum, keyword);
				}
				𐡄𐡍 (*activep && *doubleptr < 0.0) {
					*doubleptr = dvalue;
					options->per_source_penalty.enabled = 1;
				}
			} وإلا 𐡄𐡍 (intptr != عدم) {
				𐡄𐡍 (*activep && *intptr == -1) {
					*intptr = value;
					options->per_source_penalty.enabled = 1;
				}
			} وإلا {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		𐡄𐡍 (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اكسر;

	حالة sMaxAuthTries:
		intptr = &options->max_authtries;
		اذهب parse_int;

	حالة sMaxSessions:
		intptr = &options->max_sessions;
		اذهب parse_int;

	حالة sBanner:
		charptr = &options->banner;
		اذهب parse_filename;

	/*
	 * These options can contain %X options expanded at
	 * connect time, so that you can specify paths like:
	 *
	 * AuthorizedKeysFile	/etc/ssh_keys/%u
	 */
	حالة sAuthorizedKeysFile:
		uintptr = &options->num_authkeys_files;
		chararrayptr = &options->authorized_keys_files;
 parse_filenames:
		found = *uintptr == 0;
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			𐡄𐡍 (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب out;
			}
			/* Allow "none" only in first position */
			𐡄𐡍 (strcasecmp(arg, "none") == 0) {
				𐡄𐡍 (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب out;
				}
			}
			arg2 = tilde_expand_filename(arg, getuid());
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			حرر(arg2);
		}
		𐡄𐡍 (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		𐡄𐡍 (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		𐡄𐡍 (*activep && *charptr == عدم) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			𐡄𐡍 (intptr != عدم)
				*intptr = *intptr + 1;
		}
		اكسر;

	حالة sClientAliveInterval:
		intptr = &options->client_alive_interval;
		اذهب parse_time;

	حالة sClientAliveCountMax:
		intptr = &options->client_alive_count_max;
		اذهب parse_int;

	حالة sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			𐡄𐡍 (*arg == '\0' || strchr(arg, '=') != عدم)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			found = 1;
			𐡄𐡍 (!*activep)
				استمر;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->num_accept_env,
			    arg);
		}
		𐡄𐡍 (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		اكسر;

	حالة sSetEnv:
		found = options->num_setenv == 0;
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			𐡄𐡍 (*arg == '\0' || strchr(arg, '=') == عدم)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			𐡄𐡍 (lookup_setenv_in_list(arg, strs, nstrs) != عدم) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				استمر;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		𐡄𐡍 (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		𐡄𐡍 (found && *activep) {
			options->setenv = strs;
			options->num_setenv = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		value = -1;
		لكل (i = 0; tunmode_desc[i].val != -1; i++)
			𐡄𐡍 (strcmp(tunmode_desc[i].text, arg) == 0) {
				value = tunmode_desc[i].val;
				اكسر;
			}
		𐡄𐡍 (value == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		𐡄𐡍 (*activep && *intptr == -1)
			*intptr = value;
		اكسر;

	حالة sInclude:
		𐡄𐡍 (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		value = 0;
		طالما ((arg2 = argv_next(&ac, &av)) != عدم) {
			𐡄𐡍 (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				اذهب out;
			}
			value++;
			found = 0;
			𐡄𐡍 (*arg2 != '/' && *arg2 != '~') {
				xasprintf(&arg, "%s/%s", SSHDIR, arg2);
			} وإلا
				arg = xstrdup(arg2);

			/*
			 * Don't let included files clobber the containing
			 * file's Match state.
			 */
			oactive = *activep;

			/* consult cache of include files */
			TAILQ_FOREACH(item, includes, entry) {
				𐡄𐡍 (strcmp(item->selector, arg) != 0)
					استمر;
				𐡄𐡍 (item->filename != عدم) {
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
			𐡄𐡍 (found != 0) {
				حرر(arg);
				استمر;
			}

			/* requested glob was not in cache */
			debug2("%s line %d: new include %s",
			    filename, linenum, arg);
			𐡄𐡍 ((r = glob(arg, 0, عدم, &gbuf)) != 0) {
				𐡄𐡍 (r != GLOB_NOMATCH) {
					fatal("%s line %d: include \"%s\" glob "
					    "failed", filename, linenum, arg);
				}
				/*
				 * If no entry matched then record a
				 * placeholder to skip later glob calls.
				 */
				debug2("%s line %d: no match for %s",
				    filename, linenum, arg);
				item = xcalloc(1, حجم(*item));
				item->selector = xstrdup(arg);
				TAILQ_INSERT_TAIL(includes,
				    item, entry);
			}
			𐡄𐡍 (gbuf.gl_pathc > INT_MAX)
				fatal_f("too many glob results");
			لكل (n = 0; n < (صحيح)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				item = xcalloc(1, حجم(*item));
				item->selector = xstrdup(arg);
				item->filename = xstrdup(gbuf.gl_pathv[n]);
				𐡄𐡍 ((item->contents = sshbuf_new()) == عدم)
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
			حرر(arg);
		}
		𐡄𐡍 (value == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		اكسر;

	حالة sMatch:
		𐡄𐡍 (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		value = match_cfg_line(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? عدم : connectinfo));
		𐡄𐡍 (value < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : value;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_MATCH_ONLY;
		اكسر;

	حالة sPermitListen:
	حالة sPermitOpen:
		𐡄𐡍 (opcode == sPermitListen) {
			uintptr = &options->num_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} وإلا {
			uintptr = &options->num_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		found = *uintptr == 0;
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			𐡄𐡍 (strcmp(arg, "any") == 0 ||
			    strcmp(arg, "none") == 0) {
				𐡄𐡍 (nstrs != 0) {
					fatal("%s line %d: %s must appear "
					    "alone on a %s line.",
					    filename, linenum, arg, keyword);
				}
				opt_array_append(filename, linenum, keyword,
				    &strs, &nstrs, arg);
				استمر;
			}

			𐡄𐡍 (opcode == sPermitListen &&
			    strchr(arg, ':') == عدم) {
				/*
				 * Allow bare port number for PermitListen
				 * to indicate a wildcard listen host.
				 */
				xasprintf(&arg2, "*:%s", arg);
			} وإلا {
				arg2 = xstrdup(arg);
				p = hpdelim(&arg);
				𐡄𐡍 (p == عدم) {
					fatal("%s line %d: %s missing host",
					    filename, linenum, keyword);
				}
				p = cleanhostname(p);
			}
			𐡄𐡍 (arg == عدم ||
			    ((port = permitopen_port(arg)) < 0)) {
				fatal("%s line %d: %s bad port number",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			حرر(arg2);
		}
		𐡄𐡍 (nstrs == 0) {
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		}
		𐡄𐡍 (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة sForceCommand:
		𐡄𐡍 (str == عدم || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		𐡄𐡍 (*activep && options->adm_forced_command == عدم)
			options->adm_forced_command = xstrdup(str + len);
		argv_consume(&ac);
		اكسر;

	حالة sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		𐡄𐡍 (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_keys;
		اذهب parse_filename;

	حالة sRevokedKeys:
		uintptr = &options->num_revoked_keys_files;
		chararrayptr = &options->revoked_keys_files;
		اذهب parse_filenames;

	حالة sSecurityKeyProvider:
		charptr = &options->sk_provider;
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		𐡄𐡍 (*activep && *charptr == عدم) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_path(arg);
			/* increase optional counter */
			𐡄𐡍 (intptr != عدم)
				*intptr = *intptr + 1;
		}
		اكسر;

	حالة sIPQoS:
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		𐡄𐡍 ((value = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		𐡄𐡍 (value == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value = INT_MAX;
		}
		arg = argv_next(&ac, &av);
		𐡄𐡍 (arg == عدم)
			value2 = value;
		وإلا 𐡄𐡍 ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		𐡄𐡍 (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		𐡄𐡍 (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = value;
			options->ip_qos_bulk = value2;
		}
		اكسر;

	حالة sVersionAddendum:
		𐡄𐡍 (str == عدم || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		𐡄𐡍 (strchr(str + len, '\r') != عدم) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		𐡄𐡍 ((arg = strchr(line, '#')) != عدم) {
			*arg = '\0';
			rtrim(line);
		}
		𐡄𐡍 (*activep && options->version_addendum == عدم) {
			𐡄𐡍 (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			وإلا
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		اكسر;

	حالة sAuthorizedKeysCommand:
		charptr = &options->authorized_keys_command;
 parse_command:
		len = strspn(str, WHITESPACE);
		𐡄𐡍 (str[len] != '/' && strcasecmp(str + len, "none") != 0) {
			fatal("%.200s line %d: %s must be an absolute path",
			    filename, linenum, keyword);
		}
		𐡄𐡍 (*activep && *charptr == عدم)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		اكسر;

	حالة sAuthorizedKeysCommandUser:
		charptr = &options->authorized_keys_command_user;
 parse_localuser:
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0') {
			fatal("%s line %d: missing %s argument.",
			    filename, linenum, keyword);
		}
		𐡄𐡍 (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة sAuthorizedPrincipalsCommand:
		charptr = &options->authorized_principals_command;
		اذهب parse_command;

	حالة sAuthorizedPrincipalsCommandUser:
		charptr = &options->authorized_principals_command_user;
		اذهب parse_localuser;

	حالة sAuthenticationMethods:
		found = options->num_auth_methods == 0;
		value = 0; /* seen "any" pseudo-method */
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			𐡄𐡍 (strcmp(arg, "any") == 0) {
				𐡄𐡍 (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				value = 1;
			} وإلا 𐡄𐡍 (value) {
				fatal("%s line %d: \"any\" must appear "
				    "alone in %s", filename, linenum, keyword);
			} وإلا 𐡄𐡍 (auth2_methods_valid(arg, 0) != 0) {
				fatal("%s line %d: invalid %s method list.",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		𐡄𐡍 (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		𐡄𐡍 (found && *activep) {
			options->auth_methods = strs;
			options->num_auth_methods = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة sStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		value = strtol(arg, &p, 8);
		𐡄𐡍 (arg == p || value < 0 || value > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		𐡄𐡍 (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)value;
		اكسر;

	حالة sStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		اذهب parse_flag;

	حالة sFingerprintHash:
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		𐡄𐡍 ((value = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		𐡄𐡍 (*activep)
			options->fingerprint_hash = value;
		اكسر;

	حالة sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		اذهب parse_flag;

	حالة sRDomain:
#𐡄𐡍 !defined(__OpenBSD__) && !defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#endif
		charptr = &options->routing_domain;
		arg = argv_next(&ac, &av);
		𐡄𐡍 (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		𐡄𐡍 (strcasecmp(arg, "none") != 0 && strcmp(arg, "%D") != 0 &&
		    !valid_rdomain(arg))
			fatal("%s line %d: invalid routing domain",
			    filename, linenum);
		𐡄𐡍 (*activep && *charptr == عدم)
			*charptr = xstrdup(arg);
		اكسر;

	حالة sRequiredRSASize:
		intptr = &options->required_rsa_size;
		اذهب parse_int;

	حالة sChannelTimeout:
		found = options->num_channel_timeouts == 0;
		طالما ((arg = argv_next(&ac, &av)) != عدم) {
			/* Allow "none" only in first position */
			𐡄𐡍 (strcasecmp(arg, "none") == 0) {
				𐡄𐡍 (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					اذهب out;
				}
			} وإلا 𐡄𐡍 (parse_pattern_interval(arg,
			    عدم, عدم) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		𐡄𐡍 (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		𐡄𐡍 (found && *activep) {
			options->channel_timeouts = strs;
			options->num_channel_timeouts = nstrs;
			strs = عدم; /* transferred */
			nstrs = 0;
		}
		اكسر;

	حالة sUnusedConnectionTimeout:
		intptr = &options->unused_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		𐡄𐡍 (av[0] != عدم && strcasecmp(av[0], "none") == 0) {
			(فراغ)argv_next(&ac, &av); /* consume arg */
			𐡄𐡍 (*activep)
				*intptr = 0;
			اكسر;
		}
		اذهب parse_time;

	حالة sSshdSessionPath:
		charptr = &options->sshd_session_path;
		اذهب parse_filename;

	حالة sSshdAuthPath:
		charptr = &options->sshd_auth_path;
		اذهب parse_filename;

	حالة sRefuseConnection:
		intptr = &options->refuse_connection;
		multistate_ptr = multistate_flag;
		اذهب parse_multistate;

	حالة sWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		اذهب parse_multistate;

	حالة sDeprecated:
	حالة sIgnore:
	حالة sUnsupported:
		do_log2(opcode == sIgnore ?
		    SYSLOG_LEVEL_DEBUG2 : SYSLOG_LEVEL_INFO,
		    "%s line %d: %s option %s", filename, linenum,
		    opcode == sUnsupported ? "Unsupported" : "Deprecated",
		    keyword);
		argv_consume(&ac);
		اكسر;

	افتراضي:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, keyword, opcode);
	}
	/* Check that there is no garbage at end of line. */
	𐡄𐡍 (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		اذهب out;
	}

	/* success */
	ret = 0;
 out:
	opt_array_free2(strs, عدم, nstrs);
	argv_free(oav, oac);
	أرجع ret;
}

صحيح
process_server_config_line(ServerOptions *options, حرف *line,
    ثابت حرف *filename, صحيح linenum, صحيح *activep,
    بنية connection_info *connectinfo, بنية include_list *includes)
{
	صحيح inc_flags = 0;

	أرجع process_server_config_line_depth(options, line, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

فراغ
load_server_config(ثابت حرف *filename, بنية sshbuf *conf)
{
	بنية stat st;
	حرف *line = عدم, *cp;
	size_t linesize = 0;
	FILE *f;
	صحيح r;

	debug2_f("filename %s", filename);
	𐡄𐡍 ((f = fopen(filename, "r")) == عدم) {
		perror(filename);
		exit(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	𐡄𐡍 (fstat(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	طالما (getline(&line, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = line + strspn(line, " \t\r");
		𐡄𐡍 ((r = sshbuf_put(conf, cp, strlen(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	حرر(line);
	𐡄𐡍 ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	fclose(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

فراغ
parse_server_match_config(ServerOptions *options,
   بنية include_list *includes, بنية connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_set_server_options(options, &mo, 0);
	free_server_options(&mo);
}

صحيح
parse_server_match_testspec(بنية connection_info *ci, حرف *spec)
{
	حرف *p;
	ثابت حرف *val;

	طالما ((p = strsep(&spec, ",")) && *p != '\0') {
		𐡄𐡍 ((val = strprefix(p, "addr=", 0)) != عدم) {
			ci->address = xstrdup(val);
		} وإلا 𐡄𐡍 ((val = strprefix(p, "host=", 0)) != عدم) {
			ci->host = xstrdup(val);
		} وإلا 𐡄𐡍 ((val = strprefix(p, "user=", 0)) != عدم) {
			ci->user = xstrdup(val);
		} وإلا 𐡄𐡍 ((val = strprefix(p, "laddr=", 0)) != عدم) {
			ci->laddress = xstrdup(val);
		} وإلا 𐡄𐡍 ((val = strprefix(p, "rdomain=", 0)) != عدم) {
			ci->rdomain = xstrdup(val);
		} وإلا 𐡄𐡍 ((val = strprefix(p, "lport=", 0)) != عدم) {
			ci->lport = a2port(val);
			𐡄𐡍 (ci->lport == -1) {
				fprintf(stderr, "Invalid port '%s' in test mode"
				    " specification %s\n", p+6, p);
				أرجع -1;
			}
		} وإلا 𐡄𐡍 (strcmp(p, "invalid-user") == 0) {
			ci->user_invalid = 1;
		} وإلا {
			fprintf(stderr, "Invalid test mode specification %s\n",
			    p);
			أرجع -1;
		}
	}
	أرجع 0;
}

فراغ
servconf_merge_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, found;

	لكل (i = 0; i < src->num_subsystems; i++) {
		found = 0;
		لكل (j = 0; j < dst->num_subsystems; j++) {
			𐡄𐡍 (strcmp(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				found = 1;
				اكسر;
			}
		}
		𐡄𐡍 (found) {
			debug_f("override \"%s\"", dst->subsystem_name[j]);
			حرر(dst->subsystem_command[j]);
			حرر(dst->subsystem_args[j]);
			dst->subsystem_command[j] =
			    xstrdup(src->subsystem_command[i]);
			dst->subsystem_args[j] =
			    xstrdup(src->subsystem_args[i]);
			استمر;
		}
		debug_f("add \"%s\"", src->subsystem_name[i]);
		dst->subsystem_name = xrecallocarray(
		    dst->subsystem_name, dst->num_subsystems,
		    dst->num_subsystems + 1, حجم(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->num_subsystems,
		    dst->num_subsystems + 1, حجم(*dst->subsystem_command));
		dst->subsystem_args = xrecallocarray(
		    dst->subsystem_args, dst->num_subsystems,
		    dst->num_subsystems + 1, حجم(*dst->subsystem_args));
		j = dst->num_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_args[j] = xstrdup(src->subsystem_args[i]);
	}
}

ساكن صحيح
serialise_s32(بنية sshbuf *buf, صحيح v)
{
	uint32_t uv;
	صحيح r;

	uv = v < 0 ? (uint32_t)(-(v + 1)) + 1 : (uint32_t)v;
	𐡄𐡍 ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u32(buf, uv)) != 0)
		أرجع r;
	أرجع 0;
}

ساكن صحيح
serialise_s64(بنية sshbuf *buf, int64_t v)
{
	uint64_t uv;
	صحيح r;

	uv = v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
	𐡄𐡍 ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u64(buf, uv)) != 0)
		أرجع r;
	أرجع 0;
}

ساكن صحيح
serialise_mode(بنية sshbuf *buf, mode_t v)
{
	u_int uv;

	𐡄𐡍 (v == (mode_t)-1)
		أرجع serialise_s32(buf, -1);
	uv = (u_int)v;
	𐡄𐡍 ((mode_t)uv != v || uv > 0777)
		أرجع SSH_ERR_INVALID_FORMAT;
	أرجع serialise_s32(buf, (صحيح)uv);
}

ساكن صحيح
serialise_double(بنية sshbuf *buf, مزدوج v)
{
	/*
	 * XXX this is no good for a wire encoding.
	 * It's fine for passing configurations via RPC, but it would
	 * be nicer to have an exact binary encoding here.
	 */
	أرجع sshbuf_put(buf, &v, حجم(v));
}

ساكن صحيح
serialise_nullable_string(بنية sshbuf *buf, ثابت حرف *s)
{
	صحيح r;

	𐡄𐡍 ((r = sshbuf_put_u8(buf, s != عدم)) != 0)
		أرجع r;
	𐡄𐡍 (s == عدم)
		أرجع 0;
	أرجع sshbuf_put_cstring(buf, s);
}

ساكن صحيح
serialise_nullable_string_array(بنية sshbuf *buf, حرف **a, u_int n)
{
	صحيح r;
	u_int i;

	𐡄𐡍 ((r = sshbuf_put_u32(buf, n)) != 0)
		أرجع r;
	لكل (i = 0; i < n; i++) {
		𐡄𐡍 ((r = serialise_nullable_string(buf, a[i])) != 0)
			أرجع r;
	}
	أرجع 0;
}

ساكن صحيح
serialise_hostkeyfile(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;
	u_int i;

	𐡄𐡍 ((r = sshbuf_put_u32(buf, options->num_host_key_files)) != 0) {
		error_fr(r, "serialise length");
		أرجع r;
	}
	لكل (i = 0; i < options->num_host_key_files; i++) {
		𐡄𐡍 ((r = serialise_s32(buf,
		    options->host_key_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_key_files[i])) != 0) {
			error_fr(r, "serialise member");
			أرجع r;
		}
	}
	أرجع 0;
}

ساكن صحيح
serialise_ipqos(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = serialise_s32(buf, options->ip_qos_interactive)) != 0 ||
	    (r = serialise_s32(buf, options->ip_qos_bulk)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
serialise_listenaddress(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;
	u_int i;

	/* Note: only serialises queued listen addresses */
	𐡄𐡍 ((r = sshbuf_put_u32(buf, options->num_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		أرجع r;
	}
	لكل (i = 0; i < options->num_queued_listens; i++) {
		ثابت بنية queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		𐡄𐡍 ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->port)) != 0 ||
		    (r = serialise_nullable_string(buf, qla->rdomain)) != 0) {
			error_fr(r, "serialise member");
			أرجع r;
		}
	}
	أرجع 0;
}

ساكن صحيح
serialise_logfacility(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = serialise_s32(buf, (صحيح)options->log_facility)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
serialise_loglevel(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = serialise_s32(buf, (صحيح)options->log_level)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
serialise_port(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;
	u_int i;

	𐡄𐡍 ((r = sshbuf_put_u32(buf, options->num_ports)) != 0) {
		error_fr(r, "serialise length");
		أرجع r;
	}
	لكل (i = 0; i < options->num_ports; i++) {
		𐡄𐡍 ((r = serialise_s32(buf, options->ports[i])) != 0) {
			error_fr(r, "serialise port");
			أرجع r;
		}
	}
	أرجع 0;
}

ساكن صحيح
serialise_gatewayports(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = serialise_s32(buf, options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}
	أرجع 0;
}

ساكن صحيح
serialise_streamlocalbindmask(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = serialise_mode(buf,
	    options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}
	أرجع 0;
}

ساكن صحيح
serialise_streamlocalbindunlink(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = sshbuf_put_u8(buf,
	    (options->fwd_opts.streamlocal_bind_unlink != 0))) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}
	أرجع 0;
}

ساكن صحيح
serialise_maxstartups(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = serialise_s32(buf, options->max_startups_begin)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups_rate)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
serialise_permituserenv(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = serialise_s32(buf, options->permit_user_env)) != 0 ||
	    (r = serialise_nullable_string(buf,
	    options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
serialise_persourcenetblocksize(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = serialise_s32(buf, options->per_source_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
serialise_persourcepenalties(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	ثابت بنية per_source_penalty *psp = &options->per_source_penalty;
	صحيح r;

	𐡄𐡍 ((r = serialise_s32(buf, psp->enabled)) != 0 ||
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
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
serialise_rekeylimit(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = serialise_s64(buf, options->rekey_limit)) != 0 ||
	    (r = serialise_s32(buf, options->rekey_interval)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
serialise_subsystem(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;
	u_int i;

	𐡄𐡍 ((r = sshbuf_put_u32(buf, options->num_subsystems)) != 0) {
		error_fr(r, "serialise length");
		أرجع r;
	}
	لكل (i = 0; i < options->num_subsystems; i++) {
		𐡄𐡍 ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_args[i])) != 0) {
			error_fr(r, "serialise member");
			أرجع r;
		}
	}
	أرجع 0;
}

ساكن صحيح
serialise_pubkey_auth_options(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = serialise_s32(buf, options->pubkey_auth_options)) != 0 ||
	    (r = serialise_s32(buf, options->max_pubkey_ok)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}
	أرجع 0;
}

ساكن صحيح
serialise_timingsecret(ثابت ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = sshbuf_put_u64(buf, options->timing_secret)) != 0) {
		error_fr(r, "serialise");
		أرجع r;
	}
	أرجع 0;
}


صحيح
serialise_server_options(ثابت ServerOptions *options, بنية sshbuf **bufp)
{
	بنية sshbuf *buf = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	*bufp = عدم;

	𐡄𐡍 ((buf = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	𐡄𐡍 ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_VERSION)) != 0) {
		error_fr(r, "serialise version");
		اذهب out;
	}

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	𐡄𐡍 ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		اذهب out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	𐡄𐡍 ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		اذهب out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	𐡄𐡍 ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		اذهب out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	𐡄𐡍 ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		اذهب out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	𐡄𐡍 ((r = serialise_##funcsuffix(options, buf)) != 0) \
		اذهب out;
#define SSHCONF_NONCONF(funcsuffix) \
	𐡄𐡍 ((r = serialise_##funcsuffix(options, buf)) != 0) \
		اذهب out;
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
	buf = عدم; /* transferred */
 out:
	sshbuf_free(buf);
	أرجع r;
}

ساكن صحيح
deserialise_s32(بنية sshbuf *buf, صحيح *v)
{
	uint32_t tmp;
	صحيح r;
	u_char was_signed;

	𐡄𐡍 ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u32(buf, &tmp)) != 0)
		أرجع r;
	𐡄𐡍 (was_signed > 1)
		أرجع SSH_ERR_INVALID_FORMAT;
	𐡄𐡍 (was_signed) {
		𐡄𐡍 (tmp > (uint32_t)INT_MAX + 1)
			أرجع SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)INT_MAX + 1 ? INT_MIN : -(صحيح)tmp;
	} وإلا {
		𐡄𐡍 (tmp > INT_MAX)
			أرجع SSH_ERR_INVALID_FORMAT;
		*v = (صحيح)tmp;
	}
	أرجع 0;
}

ساكن صحيح
deserialise_s64(بنية sshbuf *buf, int64_t *v)
{
	uint64_t tmp;
	صحيح r;
	u_char was_signed;

	𐡄𐡍 ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u64(buf, &tmp)) != 0)
		أرجع r;
	𐡄𐡍 (was_signed > 1)
		أرجع SSH_ERR_INVALID_FORMAT;
	𐡄𐡍 (was_signed) {
		𐡄𐡍 (tmp > (uint64_t)INT64_MAX + 1)
			أرجع SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint64_t)INT64_MAX + 1 ?
		    INT64_MIN : -(int64_t)tmp;
	} وإلا {
		𐡄𐡍 (tmp > INT64_MAX)
			أرجع SSH_ERR_INVALID_FORMAT;
		*v = (int64_t)tmp;
	}
	أرجع 0;
}

ساكن صحيح
deserialise_mode(بنية sshbuf *buf, mode_t *v)
{
	صحيح r, tmp;

	𐡄𐡍 ((r = deserialise_s32(buf, &tmp)) != 0)
		أرجع r;
	𐡄𐡍 (tmp == -1) {
		*v = (mode_t)-1;
		أرجع 0;
	}
	𐡄𐡍 (tmp < 0 || tmp > 0777)
		أرجع SSH_ERR_INVALID_FORMAT;
	*v = (mode_t)tmp;
	أرجع 0;
}

ساكن صحيح
deserialise_double(بنية sshbuf *buf, مزدوج *v)
{
	أرجع sshbuf_get(buf, v, حجم(*v));
}

ساكن صحيح
deserialise_nullable_string(بنية sshbuf *buf, حرف **sp)
{
	صحيح r;
	u_char present;

	𐡄𐡍 ((r = sshbuf_get_u8(buf, &present)) != 0)
		أرجع r;
	𐡄𐡍 (present == 0) {
		*sp = عدم;
		أرجع 0;
	}
	𐡄𐡍 (present != 1)
		أرجع SSH_ERR_INVALID_FORMAT;
	أرجع sshbuf_get_cstring(buf, sp, عدم);
}

ساكن فراغ
free_string_array(حرف **a, u_int n)
{
	u_int i;

	𐡄𐡍 (a == عدم)
		أرجع;
	لكل (i = 0; i < n; i++)
		حرر(a[i]);
	حرر(a);
}

ساكن صحيح
deserialise_count(بنية sshbuf *buf, u_int *np, ثابت حرف *what)
{
	صحيح r;
	uint32_t n;

	𐡄𐡍 ((r = sshbuf_get_u32(buf, &n)) != 0) {
		error_fr(r, "deserialise %s length", what);
		أرجع r;
	}
	𐡄𐡍 (n > UINT_MAX) {
		error_f("bad number of %s", what);
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	𐡄𐡍 (n > sshbuf_len(buf)) {
		error_f("bad number of %s", what);
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	*np = n;
	أرجع 0;
}

ساكن صحيح
deserialise_nullable_string_array(بنية sshbuf *buf, حرف ***arrayp,
    u_int *np)
{
	حرف **a = عدم;
	صحيح r;
	u_int i, n;

	*arrayp = عدم;
	*np = 0;
	𐡄𐡍 ((r = deserialise_count(buf, &n, "strings")) != 0)
		أرجع r;
	𐡄𐡍 (n > 0)
		a = xcalloc(n, حجم(*a));
	لكل (i = 0; i < n; i++) {
		𐡄𐡍 ((r = deserialise_nullable_string(buf, a + i)) != 0) {
			free_string_array(a, i + 1);
			أرجع r;
		}
	}
	*arrayp = a;
	*np = n;
	أرجع 0;
}

ساكن فراغ
free_queued_listen_addrs(بنية queued_listenaddr *qla, u_int n)
{
	u_int i;

	𐡄𐡍 (qla == عدم)
		أرجع;
	لكل (i = 0; i < n; i++) {
		حرر(qla[i].addr);
		حرر(qla[i].rdomain);
	}
	حرر(qla);
}

ساكن صحيح
deserialise_hostkeyfile(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r, *userprovided = عدم;
	u_int i, n;
	حرف **files = عدم;

	𐡄𐡍 ((r = deserialise_count(buf, &n, "host key files")) != 0)
		أرجع r;
	𐡄𐡍 (n > 0) {
		userprovided = xcalloc(n, حجم(*userprovided));
		files = xcalloc(n, حجم(*files));
	}
	لكل (i = 0; i < n; i++) {
		𐡄𐡍 ((r = deserialise_s32(buf, userprovided + i)) != 0 ||
		    (r = deserialise_nullable_string(buf, files + i)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(files, i + 1);
			حرر(userprovided);
			أرجع r;
		}
	}
	options->num_host_key_files = n;
	options->host_key_file_userprovided = userprovided;
	options->host_key_files = files;
	أرجع 0;
}

ساكن صحيح
deserialise_ipqos(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = deserialise_s32(buf, &options->ip_qos_interactive)) != 0 ||
	    (r = deserialise_s32(buf, &options->ip_qos_bulk)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
deserialise_listenaddress(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;
	u_int i, n;
	بنية queued_listenaddr *qla = عدم;

	𐡄𐡍 ((r = deserialise_count(buf, &n, "listen addresses")) != 0)
		أرجع r;
	𐡄𐡍 (n > 0)
		qla = xcalloc(n, حجم(*qla));
	لكل (i = 0; i < n; i++) {
		𐡄𐡍 ((r = sshbuf_get_cstring(buf, &qla[i].addr, عدم)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].port)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			أرجع r;
		}
	}
	options->num_queued_listens = n;
	options->queued_listen_addrs = qla;
	أرجع 0;
}

ساكن صحيح
deserialise_logfacility(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r, tmp;

	𐡄𐡍 ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}
	𐡄𐡍 (tmp != SYSLOG_FACILITY_NOT_SET &&
	    log_facility_name((SyslogFacility)tmp) == عدم) {
		error_f("bad syslog facility");
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	options->log_facility = (SyslogFacility)tmp;

	أرجع 0;
}

ساكن صحيح
deserialise_loglevel(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r, tmp;

	𐡄𐡍 ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}
	𐡄𐡍 (tmp != SYSLOG_LEVEL_NOT_SET &&
	    log_level_name((LogLevel)tmp) == عدم) {
		error_f("bad log level");
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	أرجع 0;
}

ساكن صحيح
deserialise_port(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;
	u_int i, n;

	𐡄𐡍 ((r = deserialise_count(buf, &n, "ports")) != 0)
		أرجع r;
	𐡄𐡍 (n > MAX_PORTS) {
		error_f("bad number of ports");
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	options->num_ports = n;
	memset(options->ports, 0, حجم(options->ports));
	لكل (i = 0; i < options->num_ports; i++) {
		𐡄𐡍 ((r = deserialise_s32(buf, options->ports + i)) != 0) {
			error_fr(r, "deserialise port");
			أرجع r;
		}
	}
	أرجع 0;
}

ساكن صحيح
deserialise_gatewayports(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = deserialise_s32(buf, &options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}
	أرجع 0;
}

ساكن صحيح
deserialise_streamlocalbindmask(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = deserialise_mode(buf,
	    &options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}
	أرجع 0;
}

ساكن صحيح
deserialise_streamlocalbindunlink(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;
	u_char tmp;

	𐡄𐡍 ((r = sshbuf_get_u8(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}
	𐡄𐡍 (tmp > 1) {
		error_f("bad boolean");
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	options->fwd_opts.streamlocal_bind_unlink = tmp;
	أرجع 0;
}

ساكن صحيح
deserialise_maxstartups(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = deserialise_s32(buf, &options->max_startups_begin)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups_rate)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
deserialise_permituserenv(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = deserialise_s32(buf, &options->permit_user_env)) != 0 ||
	    (r = deserialise_nullable_string(buf,
	    &options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}
	أرجع 0;
}

ساكن صحيح
deserialise_persourcenetblocksize(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
deserialise_persourcepenalties(ServerOptions *options, بنية sshbuf *buf)
{
	بنية per_source_penalty *psp = &options->per_source_penalty;
	صحيح r;

	𐡄𐡍 ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
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
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
deserialise_rekeylimit(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = deserialise_s64(buf, &options->rekey_limit)) != 0 ||
	    (r = deserialise_s32(buf, &options->rekey_interval)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}

	أرجع 0;
}

ساكن صحيح
deserialise_subsystem(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;
	u_int i, n;
	حرف **names = عدم, **commands = عدم, **args = عدم;

	𐡄𐡍 ((r = deserialise_count(buf, &n, "subsystems")) != 0)
		أرجع r;
	𐡄𐡍 (n > 0) {
		names = xcalloc(n, حجم(*names));
		commands = xcalloc(n, حجم(*names));
		args = xcalloc(n, حجم(*args));
	}
	لكل (i = 0; i < n; i++) {
		𐡄𐡍 ((r = sshbuf_get_cstring(buf, names + i, عدم)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, عدم)) != 0 ||
		    (r = sshbuf_get_cstring(buf, args + i, عدم)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(names, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(args, i + 1);
			أرجع r;
		}
	}
	options->num_subsystems = n;
	options->subsystem_name = names;
	options->subsystem_command = commands;
	options->subsystem_args = args;
	أرجع 0;
}

ساكن صحيح
deserialise_pubkey_auth_options(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = deserialise_s32(buf, &options->pubkey_auth_options)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_pubkey_ok)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}
	أرجع 0;
}

ساكن صحيح
deserialise_timingsecret(ServerOptions *options, بنية sshbuf *buf)
{
	صحيح r;

	𐡄𐡍 ((r = sshbuf_get_u64(buf, &options->timing_secret)) != 0) {
		error_fr(r, "deserialise");
		أرجع r;
	}
	أرجع 0;
}

صحيح
deserialise_server_options(بنية sshbuf *buf, ServerOptions *options)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	uint32_t version;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	𐡄𐡍 ((r = sshbuf_get_u32(buf, &version)) != 0) {
		error_fr(r, "deserialise version");
		اذهب out;
	}
	𐡄𐡍 (version != SSHD_CONFIG_BLOB_VERSION) {
		error_f("unsupported config blob version %u", version);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	𐡄𐡍 ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		اذهب out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	𐡄𐡍 ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		اذهب out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	𐡄𐡍 ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		اذهب out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	𐡄𐡍 ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		اذهب out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	𐡄𐡍 ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		اذهب out;
#define SSHCONF_NONCONF(funcsuffix) \
	𐡄𐡍 ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		اذهب out;
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	𐡏𐡁𐡃 { \
		حرر(new_options.var); \
		new_options.var = عدم; \
	} طالما (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

	𐡄𐡍 (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
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
	memset(&new_options, 0, حجم(new_options));
 out:
	free_server_options(&new_options);
	أرجع r;
}

ساكن فراغ
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	لكل (i = 0; i < options->num_host_key_files; i++)
		حرر(options->host_key_files[i]);
	حرر(options->host_key_files);
	حرر(options->host_key_file_userprovided);
}

ساكن فراغ
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->num_queued_listens);

	لكل (i = 0; i < options->num_listen_addrs; i++) {
		حرر(options->listen_addrs[i].rdomain);
		𐡄𐡍 (options->listen_addrs[i].addrs != عدم)
			freeaddrinfo(options->listen_addrs[i].addrs);
	}
	حرر(options->listen_addrs);
}

ساكن فراغ
free_permituserenv(ServerOptions *options)
{
	حرر(options->permit_user_env_allowlist);
}

ساكن فراغ
free_subsystem(ServerOptions *options)
{
	u_int i;

	لكل (i = 0; i < options->num_subsystems; i++) {
		حرر(options->subsystem_name[i]);
		حرر(options->subsystem_command[i]);
		حرر(options->subsystem_args[i]);
	}
	حرر(options->subsystem_name);
	حرر(options->subsystem_command);
	حرر(options->subsystem_args);
}

فراغ
free_server_options(ServerOptions *options)
{
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	/* empty */
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	/* empty */
#define SSHCONF_STRING(var, conf, flags, cp)		حرر(options->var);
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#define SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	𐡏𐡁𐡃 { \
		حرر(options->var); \
		options->var = عدم; \
	} طالما (0);
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

ساكن فراغ
copy_server_option_int(صحيح *dst, صحيح src)
{
	𐡄𐡍 (src != -1)
		*dst = src;
}

ساكن فراغ
copy_server_option_int64(int64_t *dst, int64_t src)
{
	𐡄𐡍 (src != -1)
		*dst = src;
}

ساكن فراغ
copy_server_option_string(حرف **dst, ثابت حرف *src)
{
	𐡄𐡍 (src != عدم && *dst != src) {
		حرر(*dst);
		*dst = xstrdup(src);
	}
}

ساكن فراغ
copy_server_option_strarray_values(حرف ***dst, u_int ndst,
    حرف * ثابت *src, u_int nsrc)
{
	u_int i;

	𐡄𐡍 (nsrc == 0)
		أرجع;
	لكل (i = 0; i < ndst; i++)
		حرر((*dst)[i]);
	حرر(*dst);
	*dst = xcalloc(nsrc, حجم(**dst));
	لكل (i = 0; i < nsrc; i++)
		(*dst)[i] = src[i] == عدم ? عدم : xstrdup(src[i]);
}

ساكن فراغ
copy_server_option_strarray(حرف ***dst, u_int *ndst,
    حرف * ثابت *src, u_int nsrc)
{
	𐡄𐡍 (nsrc == 0)
		أرجع;
	copy_server_option_strarray_values(dst, *ndst, src, nsrc);
	*ndst = nsrc;
}

ساكن فراغ
copy_ipqos(ServerOptions *dst, ثابت ServerOptions *src)
{
	copy_server_option_int(&dst->ip_qos_interactive,
	    src->ip_qos_interactive);
	copy_server_option_int(&dst->ip_qos_bulk, src->ip_qos_bulk);
}

ساكن فراغ
copy_gatewayports(ServerOptions *dst, ثابت ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.gateway_ports,
	    src->fwd_opts.gateway_ports);
}

ساكن فراغ
copy_streamlocalbindunlink(ServerOptions *dst, ثابت ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.streamlocal_bind_unlink,
	    src->fwd_opts.streamlocal_bind_unlink);
}

ساكن فراغ
copy_loglevel(ServerOptions *dst, ثابت ServerOptions *src)
{
	𐡄𐡍 (src->log_level != -1)
		dst->log_level = src->log_level;
}

ساكن فراغ
copy_rekeylimit(ServerOptions *dst, ثابت ServerOptions *src)
{
	copy_server_option_int64(&dst->rekey_limit, src->rekey_limit);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

ساكن فراغ
copy_subsystem(ServerOptions *dst, ثابت ServerOptions *src)
{
	u_int old_num_subsystems = dst->num_subsystems;

	𐡄𐡍 (src->num_subsystems == 0)
		أرجع;
	copy_server_option_strarray_values(&dst->subsystem_name,
	    old_num_subsystems, src->subsystem_name, src->num_subsystems);
	copy_server_option_strarray_values(&dst->subsystem_command,
	    old_num_subsystems, src->subsystem_command, src->num_subsystems);
	copy_server_option_strarray_values(&dst->subsystem_args,
	    old_num_subsystems, src->subsystem_args, src->num_subsystems);
	dst->num_subsystems = src->num_subsystems;
}

ساكن فراغ
copy_pubkey_auth_options(ServerOptions *dst, ثابت ServerOptions *src)
{
	𐡄𐡍 (src->pubkey_auth_options != -1) {
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
فراغ
copy_set_server_options(ServerOptions *dst, ServerOptions *src, صحيح preauth)
{
	𐡄𐡍 (dst == src)
		أرجع;

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
	𐡏𐡁𐡃 { \
		حرر(dst->var); \
		dst->var = عدم; \
	} طالما (0);
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
	𐡄𐡍 (src->fwd_opts.streamlocal_bind_mask != (mode_t)-1) {
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
	𐡏𐡁𐡃 { \
		𐡄𐡍 (option_clear_or_none(v)) { \
			حرر(v); \
			v = عدم; \
		} \
	} طالما(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_keys);
	CLEAR_ON_NONE(dst->banner);

	/*
	 * The only things that should be below this point are string options
	 * which are only used after authentication.
	 */
	𐡄𐡍 (preauth)
		أرجع;

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
ساكن فراغ
parse_server_config_depth(ServerOptions *options, ثابت حرف *filename,
    بنية sshbuf *conf, بنية include_list *includes,
    بنية connection_info *connectinfo, صحيح flags, صحيح *activep, صحيح depth)
{
	صحيح linenum, bad_options = 0;
	حرف *cp, *obuf, *cbuf;

	𐡄𐡍 (depth < 0 || depth > SERVCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	𐡄𐡍 ((obuf = cbuf = sshbuf_dup_string(conf)) == عدم)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	طالما ((cp = strsep(&cbuf, "\n")) != عدم) {
		𐡄𐡍 (process_server_config_line_depth(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    depth, includes) != 0)
			bad_options++;
	}
	حرر(obuf);
	𐡄𐡍 (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

فراغ
parse_server_config(ServerOptions *options, ثابت حرف *filename,
    بنية sshbuf *conf, بنية include_list *includes,
    بنية connection_info *connectinfo, صحيح reexec)
{
	صحيح active = connectinfo ? 0 : 1;
	parse_server_config_depth(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_MATCH_ONLY : 0), &active, 0);
	𐡄𐡍 (!reexec)
		process_queued_listen_addrs(options);
}

ساكن ثابت حرف *
fmt_multistate_int(صحيح val, ثابت بنية multistate *m)
{
	u_int i;

	لكل (i = 0; m[i].key != عدم; i++) {
		𐡄𐡍 (m[i].value == val)
			أرجع m[i].key;
	}
	أرجع "UNKNOWN";
}

ساكن ثابت حرف *
fmt_intarg(ServerOpCodes code, صحيح val)
{
	𐡄𐡍 (val == -1)
		أرجع "unset";
	بدل (code) {
	حالة sAddressFamily:
		أرجع fmt_multistate_int(val, multistate_addressfamily);
	حالة sPermitRootLogin:
		أرجع fmt_multistate_int(val, multistate_permitrootlogin);
	حالة sGatewayPorts:
		أرجع fmt_multistate_int(val, multistate_gatewayports);
	حالة sCompression:
		أرجع fmt_multistate_int(val, multistate_compression);
	حالة sAllowTcpForwarding:
		أرجع fmt_multistate_int(val, multistate_tcpfwd);
	حالة sAllowStreamLocalForwarding:
		أرجع fmt_multistate_int(val, multistate_tcpfwd);
	حالة sIgnoreRhosts:
		أرجع fmt_multistate_int(val, multistate_ignore_rhosts);
	حالة sTCPKeepAlive:
		أرجع fmt_multistate_int(val, multistate_keepalives);
	حالة sWarnWeakCrypto:
		أرجع fmt_multistate_int(val, multistate_warnweakcrypto);
	حالة sFingerprintHash:
		أرجع ssh_digest_alg_name(val);
	افتراضي:
		بدل (val) {
		حالة 0:
			أرجع "no";
		حالة 1:
			أرجع "yes";
		افتراضي:
			أرجع "UNKNOWN";
		}
	}
}

ساكن فراغ
dump_cfg_int(ServerOpCodes code, صحيح val)
{
	𐡄𐡍 (code == sUnusedConnectionTimeout && val == 0) {
		printf("%s none\n", lookup_opcode_name(code));
		أرجع;
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

ساكن فراغ
dump_cfg_oct(ServerOpCodes code, صحيح val)
{
	printf("%s 0%o\n", lookup_opcode_name(code), val);
}

ساكن فراغ
dump_cfg_fmtint(ServerOpCodes code, صحيح val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

ساكن فراغ
dump_cfg_string(ServerOpCodes code, ثابت حرف *val)
{
	printf("%s %s\n", lookup_opcode_name(code),
	    val == عدم ? "none" : val);
}

ساكن فراغ
dump_cfg_strarray(ServerOpCodes code, u_int count, حرف **vals)
{
	u_int i;

	لكل (i = 0; i < count; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

ساكن فراغ
dump_cfg_strarray_oneline(ServerOpCodes code, u_int count, حرف **vals)
{
	u_int i;

	بدل (code) {
	حالة sAuthenticationMethods:
	حالة sChannelTimeout:
		اكسر;
	افتراضي:
		𐡄𐡍 (count <= 0)
			أرجع;
		اكسر;
	}

	printf("%s", lookup_opcode_name(code));
	لكل (i = 0; i < count; i++)
		printf(" %s",  vals[i]);
	𐡄𐡍 (code == sAuthenticationMethods && count == 0)
		printf(" any");
	وإلا 𐡄𐡍 (code == sChannelTimeout && count == 0)
		printf(" none");
	printf("\n");
}

ساكن حرف *
format_listen_addrs(بنية listenaddr *la)
{
	صحيح r;
	بنية addrinfo *ai;
	حرف addr[NI_MAXHOST], port[NI_MAXSERV];
	حرف *laddr1 = xstrdup(""), *laddr2 = عدم;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	لكل (ai = la->addrs; ai; ai = ai->ai_next) {
		𐡄𐡍 ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    حجم(addr), port, حجم(port),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			استمر;
		}
		laddr2 = laddr1;
		𐡄𐡍 (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == عدم ? "" : " rdomain ",
			    la->rdomain == عدم ? "" : la->rdomain,
			    laddr2);
		} وإلا {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == عدم ? "" : " rdomain ",
			    la->rdomain == عدم ? "" : la->rdomain,
			    laddr2);
		}
		حرر(laddr2);
	}
	أرجع laddr1;
}

فراغ
dump_config(ServerOptions *o)
{
	حرف *s;
	u_int i;

	/* these are usually at the top of the config */
	لكل (i = 0; i < o->num_ports; i++)
		printf("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(sAddressFamily, o->address_family);

	لكل (i = 0; i < o->num_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		printf("%s", s);
		حرر(s);
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
	dump_cfg_int(sClientAliveCountMax, o->client_alive_count_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_size);
	dump_cfg_oct(sStreamLocalBindMask, o->fwd_opts.streamlocal_bind_mask);
	dump_cfg_int(sUnusedConnectionTimeout, o->unused_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(sPermitRootLogin, o->permit_root_login);
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
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_keys);
	dump_cfg_string(sSecurityKeyProvider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(sVersionAddendum, *o->version_addendum == '\0'
	    ? "none" : o->version_addendum);
	dump_cfg_string(sAuthorizedKeysCommand, o->authorized_keys_command);
	dump_cfg_string(sAuthorizedKeysCommandUser, o->authorized_keys_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(sHostKeyAgent, o->host_key_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(sHostKeyAlgorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#𐡄𐡍 defined(__OpenBSD__) || defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
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
	dump_cfg_strarray_oneline(sAuthorizedKeysFile, o->num_authkeys_files,
	    o->authorized_keys_files);
	dump_cfg_strarray_oneline(sRevokedKeys, o->num_revoked_keys_files,
	    o->revoked_keys_files);
	dump_cfg_strarray(sHostKey, o->num_host_key_files, o->host_key_files);
	dump_cfg_strarray(sHostCertificate, o->num_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->num_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->num_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->num_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->num_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->num_accept_env, o->accept_env);
	dump_cfg_strarray(sSetEnv, o->num_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->num_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->num_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->num_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	لكل (i = 0; i < o->num_subsystems; i++)
		printf("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_args[i]);

	printf("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_rate, o->max_startups);
	printf("PerSourceMaxStartups ");
	𐡄𐡍 (o->per_source_max_startups == INT_MAX)
		printf("none\n");
	وإلا
		printf("%d\n", o->per_source_max_startups);
	printf("PerSourceNetBlockSize %d:%d\n", o->per_source_masklen_ipv4,
	    o->per_source_masklen_ipv6);

	s = عدم;
	لكل (i = 0; tunmode_desc[i].val != -1; i++) {
		𐡄𐡍 (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].text;
			اكسر;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	printf("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	printf("%s\n", iptos2str(o->ip_qos_bulk));

	printf("RekeyLimit %llu %d\n", (unsigned long long)o->rekey_limit,
	    o->rekey_interval);

	printf("PermitOpen");
	𐡄𐡍 (o->num_permitted_opens == 0)
		printf(" any");
	وإلا {
		لكل (i = 0; i < o->num_permitted_opens; i++)
			printf(" %s", o->permitted_opens[i]);
	}
	printf("\n");
	printf("PermitListen");
	𐡄𐡍 (o->num_permitted_listens == 0)
		printf(" any");
	وإلا {
		لكل (i = 0; i < o->num_permitted_listens; i++)
			printf(" %s", o->permitted_listens[i]);
	}
	printf("\n");

	𐡄𐡍 (o->permit_user_env_allowlist == عدم) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} وإلا {
		printf("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	printf("PubkeyAuthOptions");
	𐡄𐡍 (o->pubkey_auth_options == 0)
		printf(" none");
	𐡄𐡍 (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		printf(" touch-required");
	𐡄𐡍 (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		printf(" verify-required");
	𐡄𐡍 (o->max_pubkey_ok != -1)
		printf(" max-pk-ok:%d", o->max_pubkey_ok);
	printf("\n");

	𐡄𐡍 (o->per_source_penalty.enabled) {
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
	} وإلا
		printf("PerSourcePenalties no\n");
}
