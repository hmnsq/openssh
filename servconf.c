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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/queue.h>
#अन्तर्भाव <sys/stat.h>
#ifdef __OpenBSD__
#अन्तर्भाव <sys/sysctl.h>
#endif

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <netinet/ip.h>
#ifdef HAVE_NET_ROUTE_H
#अन्तर्भाव <net/route.h>
#endif

#अन्तर्भाव <ctype.h>
#अन्तर्भाव <glob.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <util.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "mac.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "channels.h"
#अन्तर्भाव "groupaccess.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "myproposal.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "version.h"

#define SSHD_CONFIG_BLOB_VERSION	1

#यदि !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#endif

स्थिर शून्य add_listen_addr(ServerOptions *, अचर वर्ण *,
    अचर वर्ण *, पूर्णाङ्क);
स्थिर शून्य add_one_listen_addr(ServerOptions *, अचर वर्ण *,
    अचर वर्ण *, पूर्णाङ्क);
स्थिर शून्य parse_server_config_depth(ServerOptions *options,
    अचर वर्ण *filename, संरचना sshbuf *conf, संरचना include_list *includes,
    संरचना connection_info *connectinfo, पूर्णाङ्क flags, पूर्णाङ्क *activep, पूर्णाङ्क depth);

बाह्य संरचना sshbuf *cfg;

/* Initializes the server options to their default values. */

शून्य
initialize_server_options(ServerOptions *options)
{
	स_रखो(options, 0, परिमाण(*options));
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#define SSHCONF_STRING(var, conf, flags, cp)		options->var = रिक्त;
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = रिक्त;
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#define SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = रिक्त;
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	/* Using macros for these is a bit overkill but forces consistency */
#define init_hostkeyfile(options) \
	options->host_साँचो_files = 0; \
	options->अङ्क_host_साँचो_files = 0; \
	options->host_साँचो_file_userprovided = रिक्त;
#define init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#define init_listenaddress(options) \
	options->queued_listen_addrs = रिक्त; \
	options->अङ्क_queued_listens = 0; \
	options->listen_addrs = रिक्त; \
	options->अङ्क_listen_addrs = 0;
#define init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
#define init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_SET;
#define init_port(options) \
	options->अङ्क_ports = 0; \
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
	options->permit_user_env_allowlist = रिक्त;
#define init_persourcenetblocksize(options) \
	options->per_source_masklen_ipv4 = -1; \
	options->per_source_masklen_ipv6 = -1;
#define init_persourcepenalties(options) \
	options->per_source_penalty_exempt = रिक्त; \
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
	options->अङ्क_subsystems = 0; \
	options->subsystem_name = रिक्त; \
	options->subsystem_command = रिक्त; \
	options->subsystem_args = रिक्त;
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
स्थिर पूर्णाङ्क
option_clear_or_none(अचर वर्ण *o)
{
	फर्काऊ o == रिक्त || strcasecmp(o, "none") == 0;
}

स्थिर शून्य
assemble_algorithms(ServerOptions *o)
{
	वर्ण *all_cipher, *all_mac, *all_kex, *all_साँचो, *all_sig;
	वर्ण *def_cipher, *def_mac, *def_kex, *def_साँचो, *def_sig;
	पूर्णाङ्क r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_साँचो = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_साँचो = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_साँचो);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	गर { \
		यदि ((r = kex_assemble_names(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} जबसम्म (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_साँचो, all_साँचो);
	ASSEMBLE(hostbased_accepted_algos, def_साँचो, all_साँचो);
	ASSEMBLE(pubkey_accepted_algos, def_साँचो, all_साँचो);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE
	मुक्त(all_cipher);
	मुक्त(all_mac);
	मुक्त(all_kex);
	मुक्त(all_साँचो);
	मुक्त(all_sig);
	मुक्त(def_cipher);
	मुक्त(def_mac);
	मुक्त(def_kex);
	मुक्त(def_साँचो);
	मुक्त(def_sig);
}

शून्य
servconf_add_hostkey(अचर वर्ण *file, अचर पूर्णाङ्क पङ्क्ति,
    ServerOptions *options, अचर वर्ण *path, पूर्णाङ्क userprovided)
{
	वर्ण *apath = derelativise_path(path);

	opt_array_append2(file, पङ्क्ति, "HostKey",
	    &options->host_साँचो_files, &options->host_साँचो_file_userprovided,
	    &options->अङ्क_host_साँचो_files, apath, userprovided);
	मुक्त(apath);
}

शून्य
servconf_add_hostcert(अचर वर्ण *file, अचर पूर्णाङ्क पङ्क्ति,
    ServerOptions *options, अचर वर्ण *path)
{
	वर्ण *apath = derelativise_path(path);

	opt_array_append(file, पङ्क्ति, "HostCertificate",
	    &options->host_cert_files, &options->अङ्क_host_cert_files, apath);
	मुक्त(apath);
}

शून्य
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#ifdef SKIP_PRIVDROP
	यदि (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	यदि (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#endif

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	यदि (options->var == -1) \
		options->var = def;
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	यदि (options->var == -1) \
		options->var = def;
#define SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#define SSHCONF_NONCONF(funcsuffix)			/* done manually */
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	गर { \
		मुक्त(options->var); \
		options->var = रिक्त; \
	} जबसम्म (0);
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
	यदि (options->pam_service_name == रिक्त)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#endif

	यदि (options->अङ्क_host_साँचो_files == 0) {
		/* fill default hostkeys */
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_RSA_साँचो_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ECDSA_साँचो_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ED25519_साँचो_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_MLDSA44_ED25519_साँचो_FILE, 0);
	}
	/* No certificates by default */
	यदि (options->अङ्क_ports == 0)
		options->ports[options->अङ्क_ports++] = SSH_DEFAULT_PORT;
	यदि (options->listen_addrs == रिक्त)
		add_listen_addr(options, रिक्त, रिक्त, 0);
	यदि (options->pid_file == रिक्त)
		options->pid_file = xstrdup(_PATH_SSH_DAEMON_PID_FILE);
	यदि (options->moduli_file == रिक्त)
		options->moduli_file = xstrdup(_PATH_DH_MODULI);
	यदि (options->xauth_location == रिक्त)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	यदि (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	यदि (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	यदि (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = रिक्त;
	}
	यदि (options->rekey_limit == -1)
		options->rekey_limit = 0;
	यदि (options->rekey_interval == -1)
		options->rekey_interval = 0;
	यदि (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	यदि (options->max_startups == -1)
		options->max_startups = 100;
	यदि (options->max_startups_rate == -1)
		options->max_startups_rate = 30;		/* 30% */
	यदि (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	यदि (options->per_source_masklen_ipv4 == -1)
		options->per_source_masklen_ipv4 = 32;
	यदि (options->per_source_masklen_ipv6 == -1)
		options->per_source_masklen_ipv6 = 128;
	यदि (options->per_source_penalty.enabled == -1)
		options->per_source_penalty.enabled = 1;
	यदि (options->per_source_penalty.max_sources4 == -1)
		options->per_source_penalty.max_sources4 = 65536;
	यदि (options->per_source_penalty.max_sources6 == -1)
		options->per_source_penalty.max_sources6 = 65536;
	यदि (options->per_source_penalty.overflow_mode == -1)
		options->per_source_penalty.overflow_mode = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
	यदि (options->per_source_penalty.overflow_mode6 == -1)
		options->per_source_penalty.overflow_mode6 = options->per_source_penalty.overflow_mode;
	यदि (options->per_source_penalty.penalty_crash < 0.0)
		options->per_source_penalty.penalty_crash = 90.0;
	यदि (options->per_source_penalty.penalty_grace < 0.0)
		options->per_source_penalty.penalty_grace = 10.0;
	यदि (options->per_source_penalty.penalty_authfail < 0.0)
		options->per_source_penalty.penalty_authfail = 5.0;
	यदि (options->per_source_penalty.penalty_invaliduser < 0.0)
		options->per_source_penalty.penalty_invaliduser = 5.0;
	यदि (options->per_source_penalty.penalty_noauth < 0.0)
		options->per_source_penalty.penalty_noauth = 1.0;
	यदि (options->per_source_penalty.penalty_refuseconnection < 0.0)
		options->per_source_penalty.penalty_refuseconnection = 10.0;
	यदि (options->per_source_penalty.penalty_min < 0.0)
		options->per_source_penalty.penalty_min = 15.0;
	यदि (options->per_source_penalty.penalty_max < 0.0)
		options->per_source_penalty.penalty_max = 600.0;
	यदि (options->अङ्क_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_साँचोहरू_files,
		    &options->अङ्क_authkeys_files,
		    PATH_SSH_USER_PERMITTED_साँचोहरू);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_साँचोहरू_files,
		    &options->अङ्क_authkeys_files,
		    _PATH_SSH_USER_PERMITTED_KEYS2);
	}
	यदि (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	यदि (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	यदि (options->version_addendum == रिक्त)
		options->version_addendum = xstrdup("");
	यदि (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	यदि (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	यदि (options->sk_provider == रिक्त)
		options->sk_provider = xstrdup("internal");
	यदि (options->sshd_session_path == रिक्त)
		options->sshd_session_path = xstrdup(_PATH_SSHD_SESSION);
	यदि (options->sshd_auth_path == रिक्त)
		options->sshd_auth_path = xstrdup(_PATH_SSHD_AUTH);
	यदि (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	यदि (options->agent_socket_path == रिक्त)
		options->agent_socket_path = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#define CLEAR_ON_NONE(v) \
	गर { \
		यदि (option_clear_or_none(v)) { \
			मुक्त(v); \
			v = रिक्त; \
		} \
	} जबसम्म(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	गर { \
		यदि (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			मुक्त(options->v[0]); \
			मुक्त(options->v); \
			options->v = रिक्त; \
			options->nv = 0; \
		} \
	} जबसम्म (0)
	CLEAR_ON_NONE(options->pid_file);
	CLEAR_ON_NONE(options->xauth_location);
	CLEAR_ON_NONE(options->banner);
	CLEAR_ON_NONE(options->trusted_user_ca_साँचोहरू);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_साँचो_agent);
	CLEAR_ON_NONE(options->per_source_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_path);

	लागि (i = 0; i < options->अङ्क_host_साँचो_files; i++)
		CLEAR_ON_NONE(options->host_साँचो_files[i]);
	लागि (i = 0; i < options->अङ्क_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, अङ्क_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, अङ्क_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_साँचोहरू_files, अङ्क_revoked_साँचोहरू_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_साँचोहरू_files, अङ्क_authkeys_files, "none");
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
प्रकारनिर्देश गणना {
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
स्थिर संरचना {
	अचर वर्ण *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", sMatch, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ रिक्त, sBadOption, 0 }
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

स्थिर संरचना {
	पूर्णाङ्क val;
	वर्ण *text;
} tunmode_desc[] = {
	{ SSH_TUNMODE_NO, "no" },
	{ SSH_TUNMODE_POINTOPOINT, "point-to-point" },
	{ SSH_TUNMODE_ETHERNET, "ethernet" },
	{ SSH_TUNMODE_YES, "yes" },
	{ -1, रिक्त }
};

/* Returns an opcode name from its number */

स्थिर अचर वर्ण *
lookup_opcode_name(ServerOpCodes code)
{
	u_int i;

	लागि (i = 0; keywords[i].name != रिक्त; i++)
		यदि (keywords[i].opcode == code)
			फर्काऊ(keywords[i].name);
	फर्काऊ "UNKNOWN";
}


/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

स्थिर ServerOpCodes
parse_token(अचर वर्ण *cp, अचर वर्ण *filename,
	    पूर्णाङ्क linenum, u_int *flags)
{
	u_int i;

	लागि (i = 0; keywords[i].name; i++)
		यदि (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			फर्काऊ keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	फर्काऊ sBadOption;
}

वर्ण *
derelativise_path(अचर वर्ण *path)
{
	वर्ण *expanded, *ret, cwd[PATH_MAX];

	यदि (strcasecmp(path, "none") == 0)
		फर्काऊ xstrdup("none");
	expanded = tilde_expand_filename(path, getuid());
	यदि (path_absolute(expanded))
		फर्काऊ expanded;
	यदि (getcwd(cwd, परिमाण(cwd)) == रिक्त)
		fatal_f("getcwd: %s", म_त्रुटि(त्रुटि_सं));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	मुक्त(expanded);
	फर्काऊ ret;
}

स्थिर शून्य
add_listen_addr(ServerOptions *options, अचर वर्ण *addr,
    अचर वर्ण *rdomain, पूर्णाङ्क port)
{
	u_int i;

	यदि (port > 0)
		add_one_listen_addr(options, addr, rdomain, port);
	अन्यथा {
		लागि (i = 0; i < options->अङ्क_ports; i++) {
			add_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

स्थिर शून्य
add_one_listen_addr(ServerOptions *options, अचर वर्ण *addr,
    अचर वर्ण *rdomain, पूर्णाङ्क port)
{
	संरचना addrinfo hints, *ai, *aitop;
	वर्ण strport[NI_MAXSERV];
	पूर्णाङ्क gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	लागि (i = 0; i < options->अङ्क_listen_addrs; i++) {
		यदि (rdomain == रिक्त && options->listen_addrs[i].rdomain == रिक्त)
			रोक;
		यदि (rdomain == रिक्त || options->listen_addrs[i].rdomain == रिक्त)
			जारी;
		यदि (म_भेद(rdomain, options->listen_addrs[i].rdomain) == 0)
			रोक;
	}
	यदि (i >= options->अङ्क_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		यदि (i >= पूर्णांक_उच्च)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->अङ्क_listen_addrs, options->अङ्क_listen_addrs + 1,
		    परिमाण(*options->listen_addrs));
		i = options->अङ्क_listen_addrs++;
		यदि (rdomain != रिक्त)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	स_रखो(&hints, 0, परिमाण(hints));
	hints.ai_family = options->address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == रिक्त) ? AI_PASSIVE : 0;
	snprintf(strport, परिमाण strport, "%d", port);
	यदि ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    ssh_gai_strerror(gaierr));
	लागि (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs[i].addrs;
	options->listen_addrs[i].addrs = aitop;
}

/* Returns nonzero if the routing domain name is valid */
स्थिर पूर्णाङ्क
valid_rdomain(अचर वर्ण *name)
{
#यदि defined(HAVE_SYS_VALID_RDOMAIN)
	फर्काऊ sys_valid_rdomain(name);
#अथवायदि defined(__OpenBSD__)
	अचर वर्ण *errstr;
	दीर्घ दीर्घ अङ्क;
	संरचना rt_tableinfo info;
	पूर्णाङ्क mib[6];
	माप_प्रकार miblen = परिमाण(mib);

	यदि (name == रिक्त)
		फर्काऊ 1;

	अङ्क = strtonum(name, 0, 255, &errstr);
	यदि (errstr != रिक्त)
		फर्काऊ 0;

	/* Check whether the table actually exists */
	स_रखो(mib, 0, परिमाण(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_TABLE;
	mib[5] = (पूर्णाङ्क)अङ्क;
	यदि (sysctl(mib, 6, &info, &miblen, रिक्त, 0) == -1)
		फर्काऊ 0;

	फर्काऊ 1;
#अन्यथा /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	फर्काऊ 0;
#endif
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
स्थिर शून्य
queue_listen_addr(ServerOptions *options, अचर वर्ण *addr,
    अचर वर्ण *rdomain, पूर्णाङ्क port)
{
	संरचना queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->अङ्क_queued_listens, options->अङ्क_queued_listens + 1,
	    परिमाण(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->अङ्क_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->port = port;
	qla->rdomain = rdomain == रिक्त ? रिक्त : xstrdup(rdomain);
}

/*
 * Process queued (text) ListenAddress entries.
 */
स्थिर शून्य
process_queued_listen_addrs(ServerOptions *options)
{
	u_int i;
	संरचना queued_listenaddr *qla;

	यदि (options->अङ्क_ports == 0)
		options->ports[options->अङ्क_ports++] = SSH_DEFAULT_PORT;
	यदि (options->address_family == -1)
		options->address_family = AF_UNSPEC;

	लागि (i = 0; i < options->अङ्क_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		add_listen_addr(options, qla->addr, qla->rdomain, qla->port);
		मुक्त(qla->addr);
		मुक्त(qla->rdomain);
	}
	मुक्त(options->queued_listen_addrs);
	options->queued_listen_addrs = रिक्त;
	options->अङ्क_queued_listens = 0;
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

स्थिर पूर्णाङ्क
match_cfg_पङ्क्ति_group(अचर वर्ण *grps, पूर्णाङ्क पङ्क्ति, अचर वर्ण *user)
{
	पूर्णाङ्क result = 0;
	संरचना passwd *pw;

	यदि (user == रिक्त)
		गच्छ out;

	यदि ((pw = getpwnam(user)) == रिक्त) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", पङ्क्ति, user);
	} अन्यथा यदि (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, पङ्क्ति);
	} अन्यथा यदि (ga_match_pattern_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, पङ्क्ति);
	} अन्यथा {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, पङ्क्ति);
		result = 1;
	}
out:
	ga_free();
	फर्काऊ result;
}

स्थिर शून्य
match_test_missing_fatal(अचर वर्ण *criteria, अचर वर्ण *attrib)
{
	fatal("'Match %s' in configuration but '%s' not in connection "
	    "test specification.", criteria, attrib);
}

/*
 * All of the attributes on a single Match line are ANDed together, so we need
 * to check every attribute and set the result to zero if any attribute does
 * not match.
 */
स्थिर पूर्णाङ्क
match_cfg_पङ्क्ति(अचर वर्ण *full_पङ्क्ति, पूर्णाङ्क *acp, वर्ण ***avp,
    पूर्णाङ्क पङ्क्ति, संरचना connection_info *ci)
{
	पूर्णाङ्क result = 1, attributes = 0, port;
	वर्ण *arg, *attrib = रिक्त, *oattrib;

	यदि (ci == रिक्त) {
		debug3("checking syntax for 'Match %s' on line %d",
		    full_पङ्क्ति, पङ्क्ति);
	} अन्यथा {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", full_पङ्क्ति,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->address ? ci->address : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", पङ्क्ति);
	}

	जबसम्म ((oattrib = argv_next(acp, avp)) != रिक्त) {
		/* Terminate on comment */
		यदि (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			रोक;
		}
		attrib = xstrdup(oattrib);
		arg = रिक्त;
		attributes++;
		/* Criterion "all" has no argument and must appear alone */
		यदि (strcasecmp(attrib, "all") == 0) {
			यदि (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != रिक्त &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				result = -1;
				गच्छ out;
			}
			यदि (arg != रिक्त && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			result = 1;
			गच्छ out;
		}
		/* Criterion "invalid-user" also has no argument */
		यदि (strcasecmp(attrib, "invalid-user") == 0) {
			यदि (ci == रिक्त) {
				result = 0;
				गच्छ next;
			}
			यदि (ci->user_invalid == 0)
				result = 0;
			अन्यथा
				debug("matched invalid-user at line %d", पङ्क्ति);
			गच्छ next;
		}

		/* Keep this list in sync with below */
		यदि (strprefix(attrib, "user=", 1) != रिक्त ||
		    strprefix(attrib, "group=", 1) != रिक्त ||
		    strprefix(attrib, "host=", 1) != रिक्त ||
		    strprefix(attrib, "address=", 1) != रिक्त ||
		    strprefix(attrib, "localaddress=", 1) != रिक्त ||
		    strprefix(attrib, "localport=", 1) != रिक्त ||
		    strprefix(attrib, "rdomain=", 1) != रिक्त ||
		    strprefix(attrib, "version=", 1) != रिक्त) {
			arg = म_अक्षर(attrib, '=');
			*(arg++) = '\0';
		} अन्यथा {
			arg = argv_next(acp, avp);
		}

		/* All other criteria require an argument */
		यदि (arg == रिक्त || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			गच्छ out;
		}
		यदि (strcasecmp(attrib, "user") == 0) {
			यदि (ci == रिक्त || (ci->test && ci->user == रिक्त)) {
				result = 0;
				गच्छ next;
			}
			यदि (ci->user == रिक्त)
				match_test_missing_fatal("User", "user");
			यदि (match_usergroup_pattern_list(ci->user, arg) != 1)
				result = 0;
			अन्यथा
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, पङ्क्ति);
		} अन्यथा यदि (strcasecmp(attrib, "group") == 0) {
			यदि (ci == रिक्त || (ci->test && ci->user == रिक्त)) {
				result = 0;
				गच्छ next;
			}
			यदि (ci->user == रिक्त)
				match_test_missing_fatal("Group", "user");
			विकल्प (match_cfg_पङ्क्ति_group(arg, पङ्क्ति, ci->user)) {
			पक्ष -1:
				result = -1;
				गच्छ out;
			पक्ष 0:
				result = 0;
			}
		} अन्यथा यदि (strcasecmp(attrib, "host") == 0) {
			यदि (ci == रिक्त || (ci->test && ci->host == रिक्त)) {
				result = 0;
				गच्छ next;
			}
			यदि (ci->host == रिक्त)
				match_test_missing_fatal("Host", "host");
			यदि (match_hostname(ci->host, arg) != 1)
				result = 0;
			अन्यथा
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, पङ्क्ति);
		} अन्यथा यदि (strcasecmp(attrib, "address") == 0) {
			यदि (ci == रिक्त || (ci->test && ci->address == रिक्त)) {
				यदि (addr_match_list(रिक्त, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, पङ्क्ति);
				result = 0;
				गच्छ next;
			}
			यदि (ci->address == रिक्त)
				match_test_missing_fatal("Address", "addr");
			विकल्प (addr_match_list(ci->address, arg)) {
			पक्ष 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->address, arg, पङ्क्ति);
				रोक;
			पक्ष 0:
			पक्ष -1:
				result = 0;
				रोक;
			पक्ष -2:
				result = -1;
				गच्छ out;
			}
		} अन्यथा यदि (strcasecmp(attrib, "localaddress") == 0){
			यदि (ci == रिक्त || (ci->test && ci->laddress == रिक्त)) {
				यदि (addr_match_list(रिक्त, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    पङ्क्ति);
				result = 0;
				गच्छ next;
			}
			यदि (ci->laddress == रिक्त)
				match_test_missing_fatal("LocalAddress",
				    "laddr");
			विकल्प (addr_match_list(ci->laddress, arg)) {
			पक्ष 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, पङ्क्ति);
				रोक;
			पक्ष 0:
			पक्ष -1:
				result = 0;
				रोक;
			पक्ष -2:
				result = -1;
				गच्छ out;
			}
		} अन्यथा यदि (strcasecmp(attrib, "localport") == 0) {
			यदि ((port = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				result = -1;
				गच्छ out;
			}
			यदि (ci == रिक्त || (ci->test && ci->lport == -1)) {
				result = 0;
				गच्छ next;
			}
			यदि (ci->lport == 0)
				match_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			यदि (port == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, port, पङ्क्ति);
			अन्यथा
				result = 0;
		} अन्यथा यदि (strcasecmp(attrib, "rdomain") == 0) {
			यदि (ci == रिक्त || (ci->test && ci->rdomain == रिक्त)) {
				result = 0;
				गच्छ next;
			}
			यदि (ci->rdomain == रिक्त)
				match_test_missing_fatal("RDomain", "rdomain");
			यदि (match_pattern_list(ci->rdomain, arg, 0) != 1)
				result = 0;
			अन्यथा
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, पङ्क्ति);
		} अन्यथा यदि (strcasecmp(attrib, "version") == 0) {
			यदि (match_pattern_list(SSH_RELEASE, arg, 0) != 1)
				result = 0;
			अन्यथा
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, पङ्क्ति);
		} अन्यथा {
			error("Unsupported Match attribute %s", oattrib);
			result = -1;
			गच्छ out;
		}
 next:
		मुक्त(attrib);
		attrib = रिक्त;
	}
	यदि (attributes == 0) {
		error("One or more attributes required for Match");
		फर्काऊ -1;
	}
 out:
	यदि (ci != रिक्त && result != -1)
		debug3("match %sfound on line %d", result ? "" : "not ", पङ्क्ति);
	मुक्त(attrib);
	फर्काऊ result;
}

#define WHITESPACE " \t\r\n"

/* Multistate option parsing */
संरचना multistate {
	वर्ण *साँचो;
	पूर्णाङ्क मान;
};
स्थिर अचर संरचना multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ रिक्त, -1 }
};
स्थिर अचर संरचना multistate multistate_ignore_rhosts[] = {
	{ "yes",			IGNORE_RHOSTS_YES },
	{ "no",				IGNORE_RHOSTS_NO },
	{ "shosts-only",		IGNORE_RHOSTS_SHOSTS },
	{ रिक्त, -1 }
};
स्थिर अचर संरचना multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ रिक्त, -1 }
};
स्थिर अचर संरचना multistate multistate_permitrootlogin[] = {
	{ "prohibit-password",		PERMIT_NO_PASSWD },
	{ "without-password",		PERMIT_NO_PASSWD },
	{ "forced-commands-only",	PERMIT_FORCED_ONLY },
	{ "yes",			PERMIT_YES },
	{ "no",				PERMIT_NO },
	{ रिक्त, -1 }
};
स्थिर अचर संरचना multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ रिक्त, -1 }
};
स्थिर अचर संरचना multistate multistate_gatewayports[] = {
	{ "clientspecified",		2 },
	{ "yes",			1 },
	{ "no",				0 },
	{ रिक्त, -1 }
};
स्थिर अचर संरचना multistate multistate_tcpfwd[] = {
	{ "yes",			FORWARD_ALLOW },
	{ "all",			FORWARD_ALLOW },
	{ "no",				FORWARD_DENY },
	{ "remote",			FORWARD_REMOTE },
	{ "local",			FORWARD_LOCAL },
	{ रिक्त, -1 }
};
स्थिर अचर संरचना multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ रिक्त, -1 }
};
स्थिर अचर संरचना multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ रिक्त, -1 }
};

स्थिर पूर्णाङ्क
process_server_config_पङ्क्ति_depth(ServerOptions *options, वर्ण *पङ्क्ति,
    अचर वर्ण *filename, पूर्णाङ्क linenum, पूर्णाङ्क *activep,
    संरचना connection_info *connectinfo, पूर्णाङ्क *inc_flags, पूर्णाङ्क depth,
    संरचना include_list *includes)
{
	वर्ण *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	पूर्णाङ्क cmdline = 0, *intptr, मान, value2, value3, n, port, oactive, r;
	द्विगुण dvalue, *doubleptr = रिक्त;
	पूर्णाङ्क ca_only = 0, found = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	माप_प्रकार len;
	दीर्घ दीर्घ val64;
	अचर संरचना multistate *multistate_ptr;
	अचर वर्ण *errstr;
	संरचना include_item *item;
	glob_t gbuf;
	वर्ण **oav = रिक्त, **av;
	पूर्णाङ्क oac = 0, ac;
	पूर्णाङ्क ret = -1;
	वर्ण **strs = रिक्त; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	यदि ((len = म_माप(पङ्क्ति)) == 0)
		फर्काऊ 0;
	लागि (len--; len > 0; len--) {
		यदि (म_अक्षर(WHITESPACE "\f", पङ्क्ति[len]) == रिक्त)
			रोक;
		पङ्क्ति[len] = '\0';
	}

	str = पङ्क्ति;
	यदि ((keyword = strdelim(&str)) == रिक्त)
		फर्काऊ 0;
	/* Ignore leading whitespace */
	यदि (*keyword == '\0')
		keyword = strdelim(&str);
	यदि (!keyword || !*keyword || *keyword == '#')
		फर्काऊ 0;
	यदि (str == रिक्त || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		फर्काऊ -1;
	}
	intptr = रिक्त;
	charptr = रिक्त;
	opcode = parse_token(keyword, filename, linenum, &flags);

	यदि (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		फर्काऊ -1;
	}
	ac = oac;
	av = oav;

	यदि (activep == रिक्त) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	यदि (*activep && opcode != sMatch && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	यदि (*activep == 0 && !(flags & SSHCFG_MATCH)) {
		यदि (connectinfo == रिक्त) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} अन्यथा { /* this is a directive we have already processed */
			ret = 0;
			गच्छ out;
		}
	}

	विकल्प (opcode) {
	/* Portable-specific options */
#ifdef USE_PAM
	पक्ष sUsePAM:
		intptr = &options->use_pam;
		गच्छ parse_flag;
	पक्ष sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		यदि (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		रोक;
#endif

	/* Standard Options */
	पक्ष sBadOption:
		गच्छ out;
	पक्ष sPort:
		/* ignore ports from configfile if cmdline specifies ports */
		यदि (options->ports_from_cmdline) {
			argv_consume(&ac);
			रोक;
		}
		यदि (options->अङ्क_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->अङ्क_ports++] = a2port(arg);
		यदि (options->ports[options->अङ्क_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		रोक;

	पक्ष sLoginGraceTime:
		intptr = &options->login_grace_time;
 parse_time:
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		यदि ((मान = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		यदि (*activep && *intptr == -1)
			*intptr = मान;
		रोक;

	पक्ष sListenAddress:
		arg = argv_next(&ac, &av);
		यदि (arg == रिक्त || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		यदि (म_अक्षर(arg, '[') == रिक्त && (p = म_अक्षर(arg, ':')) != रिक्त
		    && म_अक्षर(p+1, ':') != रिक्त) {
			port = 0;
			p = arg;
		} अन्यथा {
			arg2 = रिक्त;
			p = hpdelim(&arg);
			यदि (p == रिक्त)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			यदि (arg == रिक्त)
				port = 0;
			अन्यथा यदि ((port = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = रिक्त;
		यदि ((arg = argv_next(&ac, &av)) != रिक्त) {
			यदि (म_भेद(arg, "rdomain") != 0 ||
			    (arg2 = argv_next(&ac, &av)) == रिक्त)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			यदि (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		queue_listen_addr(options, p, arg2, port);

		रोक;

	पक्ष sAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		मान = -1;
		लागि (i = 0; multistate_ptr[i].साँचो != रिक्त; i++) {
			यदि (strcasecmp(arg, multistate_ptr[i].साँचो) == 0) {
				मान = multistate_ptr[i].मान;
				रोक;
			}
		}
		यदि (मान == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		यदि (*activep && *intptr == -1)
			*intptr = मान;
		रोक;

	पक्ष s_Host_साँचो:
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		यदि (*activep) {
			servconf_add_hostkey(filename, linenum,
			    options, arg, 1);
		}
		रोक;

	पक्ष s_Host_साँचो_Agent:
		charptr = &options->host_साँचो_agent;
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		यदि (*activep && *charptr == रिक्त)
			*charptr = !म_भेद(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_path(arg);
		रोक;

	पक्ष sHostCertificate:
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		यदि (*activep)
			servconf_add_hostcert(filename, linenum, options, arg);
		रोक;

	पक्ष sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		यदि (*activep && *charptr == रिक्त) {
			*charptr = derelativise_path(arg);
			/* increase optional counter */
			यदि (intptr != रिक्त)
				*intptr = *intptr + 1;
		}
		रोक;

	पक्ष sModuliFile:
		charptr = &options->moduli_file;
		गच्छ parse_filename;

	पक्ष s_Permit_जरा_Login:
		intptr = &options->permit_जरा_login;
		multistate_ptr = multistate_permitrootlogin;
		गच्छ parse_multistate;

	पक्ष sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
		multistate_ptr = multistate_ignore_rhosts;
		गच्छ parse_multistate;

	पक्ष sIgnoreUserKnownHosts:
		intptr = &options->ignore_user_known_hosts;
 parse_flag:
		multistate_ptr = multistate_flag;
		गच्छ parse_multistate;

	पक्ष sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		गच्छ parse_flag;

	पक्ष sHostbasedUsesNameFromPacketOnly:
		intptr = &options->hostbased_uses_name_from_packet_only;
		गच्छ parse_flag;

	पक्ष sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		यदि (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		यदि (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		रोक;

	पक्ष s_Host_साँचो_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
		गच्छ parse_pubkey_algos;

	पक्ष sCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		गच्छ parse_pubkey_algos;

	पक्ष sPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		ca_only = 0;
		गच्छ parse_flag;

	पक्ष sPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		गच्छ parse_pubkey_algos;

	पक्ष sPubkeyAuthOptions:
		intptr = &options->pubkey_auth_options;
		मान = 0;
		value2 = -1;
		जबसम्म ((arg = argv_next(&ac, &av)) != रिक्त) {
			यदि (strcasecmp(arg, "none") == 0)
				जारी;
			यदि (strcasecmp(arg, "touch-required") == 0)
				मान |= PUBKEYAUTH_TOUCH_REQUIRED;
			अन्यथा यदि (strcasecmp(arg, "verify-required") == 0)
				मान |= PUBKEYAUTH_VERIFY_REQUIRED;
			अन्यथा यदि (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				यदि (errstr != रिक्त) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					गच्छ out;
				}
			} अन्यथा {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				गच्छ out;
			}
		}
		यदि (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = मान;
			options->max_pubkey_ok = value2;
		}
		रोक;

#ifdef KRB5
	पक्ष sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		गच्छ parse_flag;

	पक्ष sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		गच्छ parse_flag;

	पक्ष sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		गच्छ parse_flag;
#ifdef USE_AFS
	पक्ष sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		गच्छ parse_flag;
#endif /* USE_AFS */
#endif /* KRB5 */

#ifdef GSSAPI
	पक्ष sGSSAPIAuthentication:
		intptr = &options->gss_authentication;
		गच्छ parse_flag;

	पक्ष sGSSAPICleanupCredentials:
		intptr = &options->gss_cleanup_creds;
		गच्छ parse_flag;

	पक्ष sGSSAPIDelegateCredentials:
		intptr = &options->gss_deleg_creds;
		गच्छ parse_flag;

	पक्ष sGSSAPIStrictAcceptorCheck:
		intptr = &options->gss_strict_acceptor;
		गच्छ parse_flag;
#endif /* GSSAPI */

	पक्ष sPasswordAuthentication:
		intptr = &options->password_authentication;
		गच्छ parse_flag;

	पक्ष sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		गच्छ parse_flag;

	पक्ष sPrintMotd:
		intptr = &options->print_motd;
		गच्छ parse_flag;

#ifndef DISABLE_LASTLOG
	पक्ष sPrintLastLog:
		intptr = &options->print_lastlog;
		गच्छ parse_flag;
#endif

	पक्ष sX11Forwarding:
		intptr = &options->x11_forwarding;
		गच्छ parse_flag;

	पक्ष sX11DisplayOffset:
		intptr = &options->x11_display_offset;
 parse_int:
		arg = argv_next(&ac, &av);
		यदि ((errstr = atoi_err(arg, &मान)) != रिक्त)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		यदि (*activep && *intptr == -1)
			*intptr = मान;
		रोक;

	पक्ष sX11UseLocalhost:
		intptr = &options->x11_use_localhost;
		गच्छ parse_flag;

	पक्ष sXAuthLocation:
		charptr = &options->xauth_location;
		गच्छ parse_filename;

	पक्ष sPermitTTY:
		intptr = &options->permit_tty;
		गच्छ parse_flag;

	पक्ष sPermitUserRC:
		intptr = &options->permit_user_rc;
		गच्छ parse_flag;

	पक्ष sStrictModes:
		intptr = &options->strict_modes;
		गच्छ parse_flag;

	पक्ष sTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		गच्छ parse_multistate;

	पक्ष sPermitEmptyPasswords:
		intptr = &options->permit_empty_passwd;
		गच्छ parse_flag;

	पक्ष sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		मान = 0;
		p = रिक्त;
		यदि (म_भेद(arg, "yes") == 0)
			मान = 1;
		अन्यथा यदि (म_भेद(arg, "no") == 0)
			मान = 0;
		अन्यथा {
			/* Pattern-list specified */
			मान = 1;
			p = xstrdup(arg);
		}
		यदि (*activep && *intptr == -1) {
			*intptr = मान;
			*charptr = p;
			p = रिक्त;
		}
		मुक्त(p);
		रोक;

	पक्ष sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		गच्छ parse_multistate;

	पक्ष sRekeyLimit:
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि (म_भेद(arg, "default") == 0) {
			val64 = 0;
		} अन्यथा {
			यदि (scan_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, म_त्रुटि(त्रुटि_सं));
			यदि (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		यदि (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		यदि (ac != 0) { /* optional rekey interval present */
			यदि (म_भेद(av[0], "none") == 0) {
				(शून्य)argv_next(&ac, &av);	/* discard */
				रोक;
			}
			intptr = &options->rekey_interval;
			गच्छ parse_time;
		}
		रोक;

	पक्ष sGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		multistate_ptr = multistate_gatewayports;
		गच्छ parse_multistate;

	पक्ष sUseDNS:
		intptr = &options->use_dns;
		गच्छ parse_flag;

	पक्ष sSyslogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		मान = log_facility_सङ्ख्या(arg);
		यदि (मान == SYSLOG_FACILITY_NOT_SET)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		यदि (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) मान;
		रोक;

	पक्ष sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		मान = log_level_सङ्ख्या(arg);
		यदि (मान == SYSLOG_LEVEL_NOT_SET)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		यदि (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) मान;
		रोक;

	पक्ष sLogVerbose:
		found = options->अङ्क_log_verbose == 0;
		जबसम्म ((arg = argv_next(&ac, &av)) != रिक्त) {
			यदि (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				गच्छ out;
			}
			/* Allow "none" only in first position */
			यदि (strcasecmp(arg, "none") == 0) {
				यदि (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		यदि (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		यदि (found && *activep) {
			options->log_verbose = strs;
			options->अङ्क_log_verbose = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		रोक;

	पक्ष sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		गच्छ parse_multistate;

	पक्ष sAllowStreamLocalForwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		गच्छ parse_multistate;

	पक्ष sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		गच्छ parse_flag;

	पक्ष sAgentSocketPath:
		charptr = &options->agent_socket_path;
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		यदि (म_भेदन(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			यदि (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} अन्यथा यदि (म_भेदन(arg, "user:", 5) == 0) {
			/* User paths must not be empty */
			यदि (arg[5] == '\0') {
				fatal("%s line %d: invalid user path.",
				    filename, linenum);
			}
		} अन्यथा यदि (म_भेद(arg, "none") != 0)
			fatal("%s line %d: invalid path.", filename, linenum);
		यदि (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		रोक;

	पक्ष sDisableForwarding:
		intptr = &options->disable_forwarding;
		गच्छ parse_flag;

	पक्ष sAllowUsers:
		chararrayptr = &options->allow_users;
		uintptr = &options->अङ्क_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		जबसम्म ((arg = argv_next(&ac, &av)) != रिक्त) {
			यदि (*arg == '\0' ||
			    match_user(रिक्त, रिक्त, रिक्त, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			found = 1;
			यदि (!*activep)
				जारी;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		यदि (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		रोक;

	पक्ष sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->अङ्क_deny_users;
		गच्छ parse_allowdenyusers;

	पक्ष sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->अङ्क_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		जबसम्म ((arg = argv_next(&ac, &av)) != रिक्त) {
			यदि (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			found = 1;
			यदि (!*activep)
				जारी;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		यदि (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		रोक;

	पक्ष sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->अङ्क_deny_groups;
		गच्छ parse_allowdenygroups;

	पक्ष sCiphers:
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		यदि (options->ciphers == रिक्त)
			options->ciphers = xstrdup(arg);
		रोक;

	पक्ष sMacs:
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		यदि (options->macs == रिक्त)
			options->macs = xstrdup(arg);
		रोक;

	पक्ष sKexAlgorithms:
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		यदि (options->kex_algorithms == रिक्त)
			options->kex_algorithms = xstrdup(arg);
		रोक;

	पक्ष sSubsystem:
		यदि ((arg = argv_next(&ac, &av)) == रिक्त || *arg == '\0' ||
		   ((arg2 = argv_next(&ac, &av)) == रिक्त || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि (!*activep) {
			argv_consume(&ac);
			रोक;
		}
		found = 0;
		लागि (i = 0; i < options->अङ्क_subsystems; i++) {
			यदि (म_भेद(arg, options->subsystem_name[i]) == 0) {
				found = 1;
				रोक;
			}
		}
		यदि (found) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			रोक;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->अङ्क_subsystems,
		    options->अङ्क_subsystems + 1,
		    परिमाण(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->अङ्क_subsystems,
		    options->अङ्क_subsystems + 1,
		    परिमाण(*options->subsystem_command));
		options->subsystem_args = xrecallocarray(
		    options->subsystem_args, options->अङ्क_subsystems,
		    options->अङ्क_subsystems + 1,
		    परिमाण(*options->subsystem_args));
		options->subsystem_name[options->अङ्क_subsystems] = xstrdup(arg);
		options->subsystem_command[options->अङ्क_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_args[options->अङ्क_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		मुक्त(arg2);
		मुक्त(arg);
		argv_consume(&ac);
		options->अङ्क_subsystems++;
		रोक;

	पक्ष sMaxStartups:
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		यदि ((n = माला_पूछो(arg, "%d:%d:%d",
		    &मान, &value2, &value3)) == 3) {
			यदि (मान > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} अन्यथा यदि (n == 1) {
			value3 = मान;
			value2 = -1;
		} अन्यथा {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		यदि (मान <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		यदि (*activep && options->max_startups == -1) {
			options->max_startups_begin = मान;
			options->max_startups_rate = value2;
			options->max_startups = value3;
		}
		रोक;

	पक्ष sPerSourceNetBlockSize:
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		विकल्प (n = माला_पूछो(arg, "%d:%d", &मान, &value2)) {
		पक्ष 2:
			यदि (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		पक्ष 1:
			यदि (मान < 0 || मान > 32)
				n = -1;
		}
		यदि (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		यदि (*activep && options->per_source_masklen_ipv4 == -1) {
			options->per_source_masklen_ipv4 = मान;
			यदि (n == 2)
				options->per_source_masklen_ipv6 = value2;
		}
		रोक;

	पक्ष sPerSourceMaxStartups:
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि (म_भेद(arg, "none") == 0) { /* no limit */
			मान = पूर्णांक_उच्च;
		} अन्यथा {
			यदि ((errstr = atoi_err(arg, &मान)) != रिक्त)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		यदि (*activep && options->per_source_max_startups == -1)
			options->per_source_max_startups = मान;
		रोक;

	पक्ष sPerSourcePenaltyExemptList:
		charptr = &options->per_source_penalty_exempt;
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		यदि (addr_match_list(रिक्त, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		यदि (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		रोक;

	पक्ष sPerSourcePenalties:
		जबसम्म ((arg = argv_next(&ac, &av)) != रिक्त) {
			अचर वर्ण *q = रिक्त;

			found = 1;
			intptr = रिक्त;
			doubleptr = रिक्त;
			मान = -1;
			value2 = 0;
			/* Allow no/yes only in first position */
			यदि (strcasecmp(arg, "no") == 0 ||
			    (value2 = (strcasecmp(arg, "yes") == 0))) {
				यदि (ac > 0) {
					fatal("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
				}
				यदि (*activep &&
				    options->per_source_penalty.enabled == -1)
					options->per_source_penalty.enabled = value2;
				जारी;
			} अन्यथा यदि ((q = strprefix(arg, "crash:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_crash;
			} अन्यथा यदि ((q = strprefix(arg, "authfail:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_authfail;
			} अन्यथा यदि ((q = strprefix(arg, "invaliduser:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_invaliduser;
			} अन्यथा यदि ((q = strprefix(arg, "noauth:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_noauth;
			} अन्यथा यदि ((q = strprefix(arg, "grace-exceeded:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_grace;
			} अन्यथा यदि ((q = strprefix(arg, "refuseconnection:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_refuseconnection;
			} अन्यथा यदि ((q = strprefix(arg, "max:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_max;
			} अन्यथा यदि ((q = strprefix(arg, "min:", 0)) != रिक्त) {
				doubleptr = &options->per_source_penalty.penalty_min;
			} अन्यथा यदि ((q = strprefix(arg, "max-sources4:", 0)) != रिक्त) {
				intptr = &options->per_source_penalty.max_sources4;
				यदि ((errstr = atoi_err(q, &मान)) != रिक्त)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} अन्यथा यदि ((q = strprefix(arg, "max-sources6:", 0)) != रिक्त) {
				intptr = &options->per_source_penalty.max_sources6;
				यदि ((errstr = atoi_err(q, &मान)) != रिक्त)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} अन्यथा यदि (म_भेद(arg, "overflow:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				मान = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} अन्यथा यदि (म_भेद(arg, "overflow:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				मान = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} अन्यथा यदि (म_भेद(arg, "overflow6:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				मान = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} अन्यथा यदि (म_भेद(arg, "overflow6:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				मान = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} अन्यथा {
				fatal("%s line %d: unsupported %s keyword %s",
				    filename, linenum, keyword, arg);
			}

			यदि (doubleptr != रिक्त) {
				यदि ((dvalue = convtime_double(q)) < 0) {
					fatal("%s line %d: invalid %s time value.",
					    filename, linenum, keyword);
				}
				यदि (*activep && *doubleptr < 0.0) {
					*doubleptr = dvalue;
					options->per_source_penalty.enabled = 1;
				}
			} अन्यथा यदि (intptr != रिक्त) {
				यदि (*activep && *intptr == -1) {
					*intptr = मान;
					options->per_source_penalty.enabled = 1;
				}
			} अन्यथा {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		यदि (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		रोक;

	पक्ष sMaxAuthTries:
		intptr = &options->max_authtries;
		गच्छ parse_int;

	पक्ष sMaxSessions:
		intptr = &options->max_sessions;
		गच्छ parse_int;

	पक्ष sBanner:
		charptr = &options->banner;
		गच्छ parse_filename;

	/*
	 * These options can contain %X options expanded at
	 * connect time, so that you can specify paths like:
	 *
	 * AuthorizedKeysFile	/etc/ssh_keys/%u
	 */
	पक्ष s_Authorized_साँचोहरू_File:
		uintptr = &options->अङ्क_authkeys_files;
		chararrayptr = &options->authorized_साँचोहरू_files;
 parse_filenames:
		found = *uintptr == 0;
		जबसम्म ((arg = argv_next(&ac, &av)) != रिक्त) {
			यदि (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				गच्छ out;
			}
			/* Allow "none" only in first position */
			यदि (strcasecmp(arg, "none") == 0) {
				यदि (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ out;
				}
			}
			arg2 = tilde_expand_filename(arg, getuid());
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			मुक्त(arg2);
		}
		यदि (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		यदि (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		रोक;

	पक्ष sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि (*activep && *charptr == रिक्त) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			यदि (intptr != रिक्त)
				*intptr = *intptr + 1;
		}
		रोक;

	पक्ष sClientAliveInterval:
		intptr = &options->client_alive_interval;
		गच्छ parse_time;

	पक्ष s_Client_Alive_गन्ती_Max:
		intptr = &options->client_alive_गन्ती_max;
		गच्छ parse_int;

	पक्ष sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		जबसम्म ((arg = argv_next(&ac, &av)) != रिक्त) {
			यदि (*arg == '\0' || म_अक्षर(arg, '=') != रिक्त)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			found = 1;
			यदि (!*activep)
				जारी;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->अङ्क_accept_env,
			    arg);
		}
		यदि (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		रोक;

	पक्ष sSetEnv:
		found = options->अङ्क_setenv == 0;
		जबसम्म ((arg = argv_next(&ac, &av)) != रिक्त) {
			यदि (*arg == '\0' || म_अक्षर(arg, '=') == रिक्त)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			यदि (lookup_setenv_in_list(arg, strs, nstrs) != रिक्त) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				जारी;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		यदि (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		यदि (found && *activep) {
			options->setenv = strs;
			options->अङ्क_setenv = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		रोक;

	पक्ष sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		मान = -1;
		लागि (i = 0; tunmode_desc[i].val != -1; i++)
			यदि (म_भेद(tunmode_desc[i].text, arg) == 0) {
				मान = tunmode_desc[i].val;
				रोक;
			}
		यदि (मान == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		यदि (*activep && *intptr == -1)
			*intptr = मान;
		रोक;

	पक्ष sInclude:
		यदि (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		मान = 0;
		जबसम्म ((arg2 = argv_next(&ac, &av)) != रिक्त) {
			यदि (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				गच्छ out;
			}
			मान++;
			found = 0;
			यदि (*arg2 != '/' && *arg2 != '~') {
				xasprintf(&arg, "%s/%s", SSHDIR, arg2);
			} अन्यथा
				arg = xstrdup(arg2);

			/*
			 * Don't let included files clobber the containing
			 * file's Match state.
			 */
			oactive = *activep;

			/* consult cache of include files */
			TAILQ_FOREACH(item, includes, entry) {
				यदि (म_भेद(item->selector, arg) != 0)
					जारी;
				यदि (item->filename != रिक्त) {
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
			यदि (found != 0) {
				मुक्त(arg);
				जारी;
			}

			/* requested glob was not in cache */
			debug2("%s line %d: new include %s",
			    filename, linenum, arg);
			यदि ((r = glob(arg, 0, रिक्त, &gbuf)) != 0) {
				यदि (r != GLOB_NOMATCH) {
					fatal("%s line %d: include \"%s\" glob "
					    "failed", filename, linenum, arg);
				}
				/*
				 * If no entry matched then record a
				 * placeholder to skip later glob calls.
				 */
				debug2("%s line %d: no match for %s",
				    filename, linenum, arg);
				item = xcalloc(1, परिमाण(*item));
				item->selector = xstrdup(arg);
				TAILQ_INSERT_TAIL(includes,
				    item, entry);
			}
			यदि (gbuf.gl_pathc > पूर्णांक_उच्च)
				fatal_f("too many glob results");
			लागि (n = 0; n < (पूर्णाङ्क)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				item = xcalloc(1, परिमाण(*item));
				item->selector = xstrdup(arg);
				item->filename = xstrdup(gbuf.gl_pathv[n]);
				यदि ((item->contents = sshbuf_new()) == रिक्त)
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
			मुक्त(arg);
		}
		यदि (मान == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		रोक;

	पक्ष sMatch:
		यदि (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		मान = match_cfg_पङ्क्ति(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? रिक्त : connectinfo));
		यदि (मान < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : मान;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_MATCH_ONLY;
		रोक;

	पक्ष sPermitListen:
	पक्ष sPermitOpen:
		यदि (opcode == sPermitListen) {
			uintptr = &options->अङ्क_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} अन्यथा {
			uintptr = &options->अङ्क_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		found = *uintptr == 0;
		जबसम्म ((arg = argv_next(&ac, &av)) != रिक्त) {
			यदि (म_भेद(arg, "any") == 0 ||
			    म_भेद(arg, "none") == 0) {
				यदि (nstrs != 0) {
					fatal("%s line %d: %s must appear "
					    "alone on a %s line.",
					    filename, linenum, arg, keyword);
				}
				opt_array_append(filename, linenum, keyword,
				    &strs, &nstrs, arg);
				जारी;
			}

			यदि (opcode == sPermitListen &&
			    म_अक्षर(arg, ':') == रिक्त) {
				/*
				 * Allow bare port number for PermitListen
				 * to indicate a wildcard listen host.
				 */
				xasprintf(&arg2, "*:%s", arg);
			} अन्यथा {
				arg2 = xstrdup(arg);
				p = hpdelim(&arg);
				यदि (p == रिक्त) {
					fatal("%s line %d: %s missing host",
					    filename, linenum, keyword);
				}
				p = cleanhostname(p);
			}
			यदि (arg == रिक्त ||
			    ((port = permitopen_port(arg)) < 0)) {
				fatal("%s line %d: %s bad port number",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			मुक्त(arg2);
		}
		यदि (nstrs == 0) {
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		}
		यदि (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		रोक;

	पक्ष sForceCommand:
		यदि (str == रिक्त || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = म_अखोज(str, WHITESPACE);
		यदि (*activep && options->adm_forced_command == रिक्त)
			options->adm_forced_command = xstrdup(str + len);
		argv_consume(&ac);
		रोक;

	पक्ष sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		रोक;

	पक्ष sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_साँचोहरू;
		गच्छ parse_filename;

	पक्ष s_Revoked_साँचोहरू:
		uintptr = &options->अङ्क_revoked_साँचोहरू_files;
		chararrayptr = &options->revoked_साँचोहरू_files;
		गच्छ parse_filenames;

	पक्ष s_Security_साँचो_Provider:
		charptr = &options->sk_provider;
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि (*activep && *charptr == रिक्त) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_path(arg);
			/* increase optional counter */
			यदि (intptr != रिक्त)
				*intptr = *intptr + 1;
		}
		रोक;

	पक्ष sIPQoS:
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि ((मान = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		यदि (मान == पूर्णांक_न्यून) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			मान = पूर्णांक_उच्च;
		}
		arg = argv_next(&ac, &av);
		यदि (arg == रिक्त)
			value2 = मान;
		अन्यथा यदि ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		यदि (value2 == पूर्णांक_न्यून) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = पूर्णांक_उच्च;
		}
		यदि (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = मान;
			options->ip_qos_bulk = value2;
		}
		रोक;

	पक्ष sVersionAddendum:
		यदि (str == रिक्त || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = म_अखोज(str, WHITESPACE);
		यदि (म_अक्षर(str + len, '\r') != रिक्त) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		यदि ((arg = म_अक्षर(पङ्क्ति, '#')) != रिक्त) {
			*arg = '\0';
			rtrim(पङ्क्ति);
		}
		यदि (*activep && options->version_addendum == रिक्त) {
			यदि (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			अन्यथा
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		रोक;

	पक्ष s_Authorized_साँचोहरू_Command:
		charptr = &options->authorized_साँचोहरू_command;
 parse_command:
		len = म_अखोज(str, WHITESPACE);
		यदि (str[len] != '/' && strcasecmp(str + len, "none") != 0) {
			fatal("%.200s line %d: %s must be an absolute path",
			    filename, linenum, keyword);
		}
		यदि (*activep && *charptr == रिक्त)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		रोक;

	पक्ष s_Authorized_साँचोहरू_Command_User:
		charptr = &options->authorized_साँचोहरू_command_user;
 parse_localuser:
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0') {
			fatal("%s line %d: missing %s argument.",
			    filename, linenum, keyword);
		}
		यदि (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		रोक;

	पक्ष sAuthorizedPrincipalsCommand:
		charptr = &options->authorized_principals_command;
		गच्छ parse_command;

	पक्ष sAuthorizedPrincipalsCommandUser:
		charptr = &options->authorized_principals_command_user;
		गच्छ parse_localuser;

	पक्ष sAuthenticationMethods:
		found = options->अङ्क_auth_methods == 0;
		मान = 0; /* seen "any" pseudo-method */
		जबसम्म ((arg = argv_next(&ac, &av)) != रिक्त) {
			यदि (म_भेद(arg, "any") == 0) {
				यदि (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				मान = 1;
			} अन्यथा यदि (मान) {
				fatal("%s line %d: \"any\" must appear "
				    "alone in %s", filename, linenum, keyword);
			} अन्यथा यदि (auth2_methods_valid(arg, 0) != 0) {
				fatal("%s line %d: invalid %s method list.",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		यदि (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		यदि (found && *activep) {
			options->auth_methods = strs;
			options->अङ्क_auth_methods = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		रोक;

	पक्ष sStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		मान = म_से_दीर्घ(arg, &p, 8);
		यदि (arg == p || मान < 0 || मान > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		यदि (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)मान;
		रोक;

	पक्ष sStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		गच्छ parse_flag;

	पक्ष sFingerprintHash:
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि ((मान = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		यदि (*activep)
			options->fingerprint_hash = मान;
		रोक;

	पक्ष sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		गच्छ parse_flag;

	पक्ष sRDomain:
#यदि !defined(__OpenBSD__) && !defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#endif
		charptr = &options->routing_domain;
		arg = argv_next(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि (strcasecmp(arg, "none") != 0 && म_भेद(arg, "%D") != 0 &&
		    !valid_rdomain(arg))
			fatal("%s line %d: invalid routing domain",
			    filename, linenum);
		यदि (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		रोक;

	पक्ष sRequiredRSASize:
		intptr = &options->required_rsa_size;
		गच्छ parse_int;

	पक्ष sChannelTimeout:
		found = options->अङ्क_channel_timeouts == 0;
		जबसम्म ((arg = argv_next(&ac, &av)) != रिक्त) {
			/* Allow "none" only in first position */
			यदि (strcasecmp(arg, "none") == 0) {
				यदि (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ out;
				}
			} अन्यथा यदि (parse_pattern_interval(arg,
			    रिक्त, रिक्त) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		यदि (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		यदि (found && *activep) {
			options->channel_timeouts = strs;
			options->अङ्क_channel_timeouts = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		रोक;

	पक्ष sUnusedConnectionTimeout:
		intptr = &options->unused_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		यदि (av[0] != रिक्त && strcasecmp(av[0], "none") == 0) {
			(शून्य)argv_next(&ac, &av); /* consume arg */
			यदि (*activep)
				*intptr = 0;
			रोक;
		}
		गच्छ parse_time;

	पक्ष sSshdSessionPath:
		charptr = &options->sshd_session_path;
		गच्छ parse_filename;

	पक्ष sSshdAuthPath:
		charptr = &options->sshd_auth_path;
		गच्छ parse_filename;

	पक्ष sRefuseConnection:
		intptr = &options->refuse_connection;
		multistate_ptr = multistate_flag;
		गच्छ parse_multistate;

	पक्ष sWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		गच्छ parse_multistate;

	पक्ष sDeprecated:
	पक्ष sIgnore:
	पक्ष sUnsupported:
		do_log2(opcode == sIgnore ?
		    SYSLOG_LEVEL_DEBUG2 : SYSLOG_LEVEL_INFO,
		    "%s line %d: %s option %s", filename, linenum,
		    opcode == sUnsupported ? "Unsupported" : "Deprecated",
		    keyword);
		argv_consume(&ac);
		रोक;

	स्वभाव:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, keyword, opcode);
	}
	/* Check that there is no garbage at end of line. */
	यदि (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		गच्छ out;
	}

	/* success */
	ret = 0;
 out:
	opt_array_free2(strs, रिक्त, nstrs);
	argv_free(oav, oac);
	फर्काऊ ret;
}

पूर्णाङ्क
process_server_config_पङ्क्ति(ServerOptions *options, वर्ण *पङ्क्ति,
    अचर वर्ण *filename, पूर्णाङ्क linenum, पूर्णाङ्क *activep,
    संरचना connection_info *connectinfo, संरचना include_list *includes)
{
	पूर्णाङ्क inc_flags = 0;

	फर्काऊ process_server_config_पङ्क्ति_depth(options, पङ्क्ति, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

शून्य
load_server_config(अचर वर्ण *filename, संरचना sshbuf *conf)
{
	संरचना stat st;
	वर्ण *पङ्क्ति = रिक्त, *cp;
	माप_प्रकार linesize = 0;
	खाता *f;
	पूर्णाङ्क r;

	debug2_f("filename %s", filename);
	यदि ((f = ख_खोलो(filename, "r")) == रिक्त) {
		लिखो_त्रुटि(filename);
		निकास(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	यदि (ख_स्थिति(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	जबसम्म (getline(&पङ्क्ति, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = पङ्क्ति + म_अखोज(पङ्क्ति, " \t\r");
		यदि ((r = sshbuf_put(conf, cp, म_माप(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	मुक्त(पङ्क्ति);
	यदि ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	ख_बंद(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

शून्य
parse_server_match_config(ServerOptions *options,
   संरचना include_list *includes, संरचना connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_set_server_options(options, &mo, 0);
	free_server_options(&mo);
}

पूर्णाङ्क
parse_server_match_testspec(संरचना connection_info *ci, वर्ण *spec)
{
	वर्ण *p;
	अचर वर्ण *val;

	जबसम्म ((p = strsep(&spec, ",")) && *p != '\0') {
		यदि ((val = strprefix(p, "addr=", 0)) != रिक्त) {
			ci->address = xstrdup(val);
		} अन्यथा यदि ((val = strprefix(p, "host=", 0)) != रिक्त) {
			ci->host = xstrdup(val);
		} अन्यथा यदि ((val = strprefix(p, "user=", 0)) != रिक्त) {
			ci->user = xstrdup(val);
		} अन्यथा यदि ((val = strprefix(p, "laddr=", 0)) != रिक्त) {
			ci->laddress = xstrdup(val);
		} अन्यथा यदि ((val = strprefix(p, "rdomain=", 0)) != रिक्त) {
			ci->rdomain = xstrdup(val);
		} अन्यथा यदि ((val = strprefix(p, "lport=", 0)) != रिक्त) {
			ci->lport = a2port(val);
			यदि (ci->lport == -1) {
				ख_लिखो(मानक_त्रुटि, "Invalid port '%s' in test mode"
				    " specification %s\n", p+6, p);
				फर्काऊ -1;
			}
		} अन्यथा यदि (म_भेद(p, "invalid-user") == 0) {
			ci->user_invalid = 1;
		} अन्यथा {
			ख_लिखो(मानक_त्रुटि, "Invalid test mode specification %s\n",
			    p);
			फर्काऊ -1;
		}
	}
	फर्काऊ 0;
}

शून्य
servconf_merge_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, found;

	लागि (i = 0; i < src->अङ्क_subsystems; i++) {
		found = 0;
		लागि (j = 0; j < dst->अङ्क_subsystems; j++) {
			यदि (म_भेद(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				found = 1;
				रोक;
			}
		}
		यदि (found) {
			debug_f("override \"%s\"", dst->subsystem_name[j]);
			मुक्त(dst->subsystem_command[j]);
			मुक्त(dst->subsystem_args[j]);
			dst->subsystem_command[j] =
			    xstrdup(src->subsystem_command[i]);
			dst->subsystem_args[j] =
			    xstrdup(src->subsystem_args[i]);
			जारी;
		}
		debug_f("add \"%s\"", src->subsystem_name[i]);
		dst->subsystem_name = xrecallocarray(
		    dst->subsystem_name, dst->अङ्क_subsystems,
		    dst->अङ्क_subsystems + 1, परिमाण(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->अङ्क_subsystems,
		    dst->अङ्क_subsystems + 1, परिमाण(*dst->subsystem_command));
		dst->subsystem_args = xrecallocarray(
		    dst->subsystem_args, dst->अङ्क_subsystems,
		    dst->अङ्क_subsystems + 1, परिमाण(*dst->subsystem_args));
		j = dst->अङ्क_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_args[j] = xstrdup(src->subsystem_args[i]);
	}
}

स्थिर पूर्णाङ्क
serialise_s32(संरचना sshbuf *buf, पूर्णाङ्क v)
{
	uint32_t uv;
	पूर्णाङ्क r;

	uv = v < 0 ? (uint32_t)(-(v + 1)) + 1 : (uint32_t)v;
	यदि ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u32(buf, uv)) != 0)
		फर्काऊ r;
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
serialise_s64(संरचना sshbuf *buf, int64_t v)
{
	uint64_t uv;
	पूर्णाङ्क r;

	uv = v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
	यदि ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u64(buf, uv)) != 0)
		फर्काऊ r;
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
serialise_mode(संरचना sshbuf *buf, mode_t v)
{
	u_int uv;

	यदि (v == (mode_t)-1)
		फर्काऊ serialise_s32(buf, -1);
	uv = (u_int)v;
	यदि ((mode_t)uv != v || uv > 0777)
		फर्काऊ SSH_ERR_INVALID_FORMAT;
	फर्काऊ serialise_s32(buf, (पूर्णाङ्क)uv);
}

स्थिर पूर्णाङ्क
serialise_double(संरचना sshbuf *buf, द्विगुण v)
{
	/*
	 * XXX this is no good for a wire encoding.
	 * It's fine for passing configurations via RPC, but it would
	 * be nicer to have an exact binary encoding here.
	 */
	फर्काऊ sshbuf_put(buf, &v, परिमाण(v));
}

स्थिर पूर्णाङ्क
serialise_nullable_string(संरचना sshbuf *buf, अचर वर्ण *s)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_put_u8(buf, s != रिक्त)) != 0)
		फर्काऊ r;
	यदि (s == रिक्त)
		फर्काऊ 0;
	फर्काऊ sshbuf_put_cstring(buf, s);
}

स्थिर पूर्णाङ्क
serialise_nullable_string_array(संरचना sshbuf *buf, वर्ण **a, u_int n)
{
	पूर्णाङ्क r;
	u_int i;

	यदि ((r = sshbuf_put_u32(buf, n)) != 0)
		फर्काऊ r;
	लागि (i = 0; i < n; i++) {
		यदि ((r = serialise_nullable_string(buf, a[i])) != 0)
			फर्काऊ r;
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
serialise_hostkeyfile(अचर ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i;

	यदि ((r = sshbuf_put_u32(buf, options->अङ्क_host_साँचो_files)) != 0) {
		error_fr(r, "serialise length");
		फर्काऊ r;
	}
	लागि (i = 0; i < options->अङ्क_host_साँचो_files; i++) {
		यदि ((r = serialise_s32(buf,
		    options->host_साँचो_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_साँचो_files[i])) != 0) {
			error_fr(r, "serialise member");
			फर्काऊ r;
		}
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
serialise_ipqos(अचर ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = serialise_s32(buf, options->ip_qos_interactive)) != 0 ||
	    (r = serialise_s32(buf, options->ip_qos_bulk)) != 0) {
		error_fr(r, "serialise");
		फर्काऊ r;
	}

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
serialise_listenaddress(अचर ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i;

	/* Note: only serialises queued listen addresses */
	यदि ((r = sshbuf_put_u32(buf, options->अङ्क_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		फर्काऊ r;
	}
	लागि (i = 0; i < options->अङ्क_queued_listens; i++) {
		अचर संरचना queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		यदि ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->port)) != 0 ||
		    (r = serialise_nullable_string(buf, qla->rdomain)) != 0) {
			error_fr(r, "serialise member");
			फर्काऊ r;
		}
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
serialise_logfacility(अचर ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = serialise_s32(buf, (पूर्णाङ्क)options->log_facility)) != 0) {
		error_fr(r, "serialise");
		फर्काऊ r;
	}

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
serialise_loglevel(अचर ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = serialise_s32(buf, (पूर्णाङ्क)options->log_level)) != 0) {
		error_fr(r, "serialise");
		फर्काऊ r;
	}

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
serialise_port(अचर ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i;

	यदि ((r = sshbuf_put_u32(buf, options->अङ्क_ports)) != 0) {
		error_fr(r, "serialise length");
		फर्काऊ r;
	}
	लागि (i = 0; i < options->अङ्क_ports; i++) {
		यदि ((r = serialise_s32(buf, options->ports[i])) != 0) {
			error_fr(r, "serialise port");
			फर्काऊ r;
		}
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
serialise_gatewayports(अचर ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = serialise_s32(buf, options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "serialise");
		फर्काऊ r;
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
serialise_streamlocalbindmask(अचर ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = serialise_mode(buf,
	    options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "serialise");
		फर्काऊ r;
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
serialise_streamlocalbindunlink(अचर ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_put_u8(buf,
	    (options->fwd_opts.streamlocal_bind_unlink != 0))) != 0) {
		error_fr(r, "serialise");
		फर्काऊ r;
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
serialise_maxstartups(अचर ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = serialise_s32(buf, options->max_startups_begin)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups_rate)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups)) != 0) {
		error_fr(r, "serialise");
		फर्काऊ r;
	}

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
serialise_permituserenv(अचर ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = serialise_s32(buf, options->permit_user_env)) != 0 ||
	    (r = serialise_nullable_string(buf,
	    options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "serialise");
		फर्काऊ r;
	}

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
serialise_persourcenetblocksize(अचर ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = serialise_s32(buf, options->per_source_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		फर्काऊ r;
	}

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
serialise_persourcepenalties(अचर ServerOptions *options, संरचना sshbuf *buf)
{
	अचर संरचना per_source_penalty *psp = &options->per_source_penalty;
	पूर्णाङ्क r;

	यदि ((r = serialise_s32(buf, psp->enabled)) != 0 ||
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
		फर्काऊ r;
	}

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
serialise_rekeylimit(अचर ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = serialise_s64(buf, options->rekey_limit)) != 0 ||
	    (r = serialise_s32(buf, options->rekey_interval)) != 0) {
		error_fr(r, "serialise");
		फर्काऊ r;
	}

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
serialise_subsystem(अचर ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i;

	यदि ((r = sshbuf_put_u32(buf, options->अङ्क_subsystems)) != 0) {
		error_fr(r, "serialise length");
		फर्काऊ r;
	}
	लागि (i = 0; i < options->अङ्क_subsystems; i++) {
		यदि ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_args[i])) != 0) {
			error_fr(r, "serialise member");
			फर्काऊ r;
		}
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
serialise_pubkey_auth_options(अचर ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = serialise_s32(buf, options->pubkey_auth_options)) != 0 ||
	    (r = serialise_s32(buf, options->max_pubkey_ok)) != 0) {
		error_fr(r, "serialise");
		फर्काऊ r;
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
serialise_timingsecret(अचर ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_put_u64(buf, options->timing_secret)) != 0) {
		error_fr(r, "serialise");
		फर्काऊ r;
	}
	फर्काऊ 0;
}


पूर्णाङ्क
serialise_server_options(अचर ServerOptions *options, संरचना sshbuf **bufp)
{
	संरचना sshbuf *buf = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	*bufp = रिक्त;

	यदि ((buf = sshbuf_new()) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_VERSION)) != 0) {
		error_fr(r, "serialise version");
		गच्छ out;
	}

#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	यदि ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		गच्छ out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	यदि ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		गच्छ out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	यदि ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		गच्छ out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	यदि ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		गच्छ out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	यदि ((r = serialise_##funcsuffix(options, buf)) != 0) \
		गच्छ out;
#define SSHCONF_NONCONF(funcsuffix) \
	यदि ((r = serialise_##funcsuffix(options, buf)) != 0) \
		गच्छ out;
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
	buf = रिक्त; /* transferred */
 out:
	sshbuf_free(buf);
	फर्काऊ r;
}

स्थिर पूर्णाङ्क
deserialise_s32(संरचना sshbuf *buf, पूर्णाङ्क *v)
{
	uint32_t tmp;
	पूर्णाङ्क r;
	u_char was_signed;

	यदि ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u32(buf, &tmp)) != 0)
		फर्काऊ r;
	यदि (was_signed > 1)
		फर्काऊ SSH_ERR_INVALID_FORMAT;
	यदि (was_signed) {
		यदि (tmp > (uint32_t)पूर्णांक_उच्च + 1)
			फर्काऊ SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)पूर्णांक_उच्च + 1 ? पूर्णांक_न्यून : -(पूर्णाङ्क)tmp;
	} अन्यथा {
		यदि (tmp > पूर्णांक_उच्च)
			फर्काऊ SSH_ERR_INVALID_FORMAT;
		*v = (पूर्णाङ्क)tmp;
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
deserialise_s64(संरचना sshbuf *buf, int64_t *v)
{
	uint64_t tmp;
	पूर्णाङ्क r;
	u_char was_signed;

	यदि ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u64(buf, &tmp)) != 0)
		फर्काऊ r;
	यदि (was_signed > 1)
		फर्काऊ SSH_ERR_INVALID_FORMAT;
	यदि (was_signed) {
		यदि (tmp > (uint64_t)INT64_MAX + 1)
			फर्काऊ SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint64_t)INT64_MAX + 1 ?
		    INT64_MIN : -(int64_t)tmp;
	} अन्यथा {
		यदि (tmp > INT64_MAX)
			फर्काऊ SSH_ERR_INVALID_FORMAT;
		*v = (int64_t)tmp;
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
deserialise_mode(संरचना sshbuf *buf, mode_t *v)
{
	पूर्णाङ्क r, tmp;

	यदि ((r = deserialise_s32(buf, &tmp)) != 0)
		फर्काऊ r;
	यदि (tmp == -1) {
		*v = (mode_t)-1;
		फर्काऊ 0;
	}
	यदि (tmp < 0 || tmp > 0777)
		फर्काऊ SSH_ERR_INVALID_FORMAT;
	*v = (mode_t)tmp;
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
deserialise_double(संरचना sshbuf *buf, द्विगुण *v)
{
	फर्काऊ sshbuf_get(buf, v, परिमाण(*v));
}

स्थिर पूर्णाङ्क
deserialise_nullable_string(संरचना sshbuf *buf, वर्ण **sp)
{
	पूर्णाङ्क r;
	u_char present;

	यदि ((r = sshbuf_get_u8(buf, &present)) != 0)
		फर्काऊ r;
	यदि (present == 0) {
		*sp = रिक्त;
		फर्काऊ 0;
	}
	यदि (present != 1)
		फर्काऊ SSH_ERR_INVALID_FORMAT;
	फर्काऊ sshbuf_get_cstring(buf, sp, रिक्त);
}

स्थिर शून्य
free_string_array(वर्ण **a, u_int n)
{
	u_int i;

	यदि (a == रिक्त)
		फर्काऊ;
	लागि (i = 0; i < n; i++)
		मुक्त(a[i]);
	मुक्त(a);
}

स्थिर पूर्णाङ्क
deserialise_गन्ती(संरचना sshbuf *buf, u_int *np, अचर वर्ण *what)
{
	पूर्णाङ्क r;
	uint32_t n;

	यदि ((r = sshbuf_get_u32(buf, &n)) != 0) {
		error_fr(r, "deserialise %s length", what);
		फर्काऊ r;
	}
	यदि (n > अच_पूर्णांक_उच्च) {
		error_f("bad number of %s", what);
		फर्काऊ SSH_ERR_INVALID_FORMAT;
	}
	यदि (n > sshbuf_len(buf)) {
		error_f("bad number of %s", what);
		फर्काऊ SSH_ERR_INVALID_FORMAT;
	}
	*np = n;
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
deserialise_nullable_string_array(संरचना sshbuf *buf, वर्ण ***arrayp,
    u_int *np)
{
	वर्ण **a = रिक्त;
	पूर्णाङ्क r;
	u_int i, n;

	*arrayp = रिक्त;
	*np = 0;
	यदि ((r = deserialise_गन्ती(buf, &n, "strings")) != 0)
		फर्काऊ r;
	यदि (n > 0)
		a = xcalloc(n, परिमाण(*a));
	लागि (i = 0; i < n; i++) {
		यदि ((r = deserialise_nullable_string(buf, a + i)) != 0) {
			free_string_array(a, i + 1);
			फर्काऊ r;
		}
	}
	*arrayp = a;
	*np = n;
	फर्काऊ 0;
}

स्थिर शून्य
free_queued_listen_addrs(संरचना queued_listenaddr *qla, u_int n)
{
	u_int i;

	यदि (qla == रिक्त)
		फर्काऊ;
	लागि (i = 0; i < n; i++) {
		मुक्त(qla[i].addr);
		मुक्त(qla[i].rdomain);
	}
	मुक्त(qla);
}

स्थिर पूर्णाङ्क
deserialise_hostkeyfile(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r, *userprovided = रिक्त;
	u_int i, n;
	वर्ण **files = रिक्त;

	यदि ((r = deserialise_गन्ती(buf, &n, "host key files")) != 0)
		फर्काऊ r;
	यदि (n > 0) {
		userprovided = xcalloc(n, परिमाण(*userprovided));
		files = xcalloc(n, परिमाण(*files));
	}
	लागि (i = 0; i < n; i++) {
		यदि ((r = deserialise_s32(buf, userprovided + i)) != 0 ||
		    (r = deserialise_nullable_string(buf, files + i)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(files, i + 1);
			मुक्त(userprovided);
			फर्काऊ r;
		}
	}
	options->अङ्क_host_साँचो_files = n;
	options->host_साँचो_file_userprovided = userprovided;
	options->host_साँचो_files = files;
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
deserialise_ipqos(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = deserialise_s32(buf, &options->ip_qos_interactive)) != 0 ||
	    (r = deserialise_s32(buf, &options->ip_qos_bulk)) != 0) {
		error_fr(r, "deserialise");
		फर्काऊ r;
	}

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
deserialise_listenaddress(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i, n;
	संरचना queued_listenaddr *qla = रिक्त;

	यदि ((r = deserialise_गन्ती(buf, &n, "listen addresses")) != 0)
		फर्काऊ r;
	यदि (n > 0)
		qla = xcalloc(n, परिमाण(*qla));
	लागि (i = 0; i < n; i++) {
		यदि ((r = sshbuf_get_cstring(buf, &qla[i].addr, रिक्त)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].port)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			फर्काऊ r;
		}
	}
	options->अङ्क_queued_listens = n;
	options->queued_listen_addrs = qla;
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
deserialise_logfacility(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r, tmp;

	यदि ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		फर्काऊ r;
	}
	यदि (tmp != SYSLOG_FACILITY_NOT_SET &&
	    log_facility_name((SyslogFacility)tmp) == रिक्त) {
		error_f("bad syslog facility");
		फर्काऊ SSH_ERR_INVALID_FORMAT;
	}
	options->log_facility = (SyslogFacility)tmp;

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
deserialise_loglevel(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r, tmp;

	यदि ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		फर्काऊ r;
	}
	यदि (tmp != SYSLOG_LEVEL_NOT_SET &&
	    log_level_name((LogLevel)tmp) == रिक्त) {
		error_f("bad log level");
		फर्काऊ SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
deserialise_port(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i, n;

	यदि ((r = deserialise_गन्ती(buf, &n, "ports")) != 0)
		फर्काऊ r;
	यदि (n > MAX_PORTS) {
		error_f("bad number of ports");
		फर्काऊ SSH_ERR_INVALID_FORMAT;
	}
	options->अङ्क_ports = n;
	स_रखो(options->ports, 0, परिमाण(options->ports));
	लागि (i = 0; i < options->अङ्क_ports; i++) {
		यदि ((r = deserialise_s32(buf, options->ports + i)) != 0) {
			error_fr(r, "deserialise port");
			फर्काऊ r;
		}
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
deserialise_gatewayports(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = deserialise_s32(buf, &options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "deserialise");
		फर्काऊ r;
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
deserialise_streamlocalbindmask(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = deserialise_mode(buf,
	    &options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "deserialise");
		फर्काऊ r;
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
deserialise_streamlocalbindunlink(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_char tmp;

	यदि ((r = sshbuf_get_u8(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		फर्काऊ r;
	}
	यदि (tmp > 1) {
		error_f("bad boolean");
		फर्काऊ SSH_ERR_INVALID_FORMAT;
	}
	options->fwd_opts.streamlocal_bind_unlink = tmp;
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
deserialise_maxstartups(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = deserialise_s32(buf, &options->max_startups_begin)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups_rate)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups)) != 0) {
		error_fr(r, "deserialise");
		फर्काऊ r;
	}

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
deserialise_permituserenv(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = deserialise_s32(buf, &options->permit_user_env)) != 0 ||
	    (r = deserialise_nullable_string(buf,
	    &options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "deserialise");
		फर्काऊ r;
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
deserialise_persourcenetblocksize(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		फर्काऊ r;
	}

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
deserialise_persourcepenalties(ServerOptions *options, संरचना sshbuf *buf)
{
	संरचना per_source_penalty *psp = &options->per_source_penalty;
	पूर्णाङ्क r;

	यदि ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
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
		फर्काऊ r;
	}

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
deserialise_rekeylimit(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = deserialise_s64(buf, &options->rekey_limit)) != 0 ||
	    (r = deserialise_s32(buf, &options->rekey_interval)) != 0) {
		error_fr(r, "deserialise");
		फर्काऊ r;
	}

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
deserialise_subsystem(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i, n;
	वर्ण **names = रिक्त, **commands = रिक्त, **args = रिक्त;

	यदि ((r = deserialise_गन्ती(buf, &n, "subsystems")) != 0)
		फर्काऊ r;
	यदि (n > 0) {
		names = xcalloc(n, परिमाण(*names));
		commands = xcalloc(n, परिमाण(*names));
		args = xcalloc(n, परिमाण(*args));
	}
	लागि (i = 0; i < n; i++) {
		यदि ((r = sshbuf_get_cstring(buf, names + i, रिक्त)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, रिक्त)) != 0 ||
		    (r = sshbuf_get_cstring(buf, args + i, रिक्त)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(names, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(args, i + 1);
			फर्काऊ r;
		}
	}
	options->अङ्क_subsystems = n;
	options->subsystem_name = names;
	options->subsystem_command = commands;
	options->subsystem_args = args;
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
deserialise_pubkey_auth_options(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = deserialise_s32(buf, &options->pubkey_auth_options)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_pubkey_ok)) != 0) {
		error_fr(r, "deserialise");
		फर्काऊ r;
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
deserialise_timingsecret(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_get_u64(buf, &options->timing_secret)) != 0) {
		error_fr(r, "deserialise");
		फर्काऊ r;
	}
	फर्काऊ 0;
}

पूर्णाङ्क
deserialise_server_options(संरचना sshbuf *buf, ServerOptions *options)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	uint32_t version;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	यदि ((r = sshbuf_get_u32(buf, &version)) != 0) {
		error_fr(r, "deserialise version");
		गच्छ out;
	}
	यदि (version != SSHD_CONFIG_BLOB_VERSION) {
		error_f("unsupported config blob version %u", version);
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
#define SSHCONF_INT(var, conf, flags, ms, def, cp) \
	यदि ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		गच्छ out; \
	}
#define SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	यदि ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		गच्छ out; \
	}
#define SSHCONF_STRING(var, conf, flags, cp) \
	यदि ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		गच्छ out; \
	}
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	यदि ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		गच्छ out; \
	}
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	यदि ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		गच्छ out;
#define SSHCONF_NONCONF(funcsuffix) \
	यदि ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		गच्छ out;
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	गर { \
		मुक्त(new_options.var); \
		new_options.var = रिक्त; \
	} जबसम्म (0);
#define SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

	यदि (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
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
	स_रखो(&new_options, 0, परिमाण(new_options));
 out:
	free_server_options(&new_options);
	फर्काऊ r;
}

स्थिर शून्य
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	लागि (i = 0; i < options->अङ्क_host_साँचो_files; i++)
		मुक्त(options->host_साँचो_files[i]);
	मुक्त(options->host_साँचो_files);
	मुक्त(options->host_साँचो_file_userprovided);
}

स्थिर शून्य
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->अङ्क_queued_listens);

	लागि (i = 0; i < options->अङ्क_listen_addrs; i++) {
		मुक्त(options->listen_addrs[i].rdomain);
		यदि (options->listen_addrs[i].addrs != रिक्त)
			freeaddrinfo(options->listen_addrs[i].addrs);
	}
	मुक्त(options->listen_addrs);
}

स्थिर शून्य
free_permituserenv(ServerOptions *options)
{
	मुक्त(options->permit_user_env_allowlist);
}

स्थिर शून्य
free_subsystem(ServerOptions *options)
{
	u_int i;

	लागि (i = 0; i < options->अङ्क_subsystems; i++) {
		मुक्त(options->subsystem_name[i]);
		मुक्त(options->subsystem_command[i]);
		मुक्त(options->subsystem_args[i]);
	}
	मुक्त(options->subsystem_name);
	मुक्त(options->subsystem_command);
	मुक्त(options->subsystem_args);
}

शून्य
free_server_options(ServerOptions *options)
{
#define SSHCONF_INT(var, conf, flags, ms, def, cp)	/* empty */
#define SSHCONF_INTFLAG(var, conf, flags, def, cp)	/* empty */
#define SSHCONF_STRING(var, conf, flags, cp)		मुक्त(options->var);
#define SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#define SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#define SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#define SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#define SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#define SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	गर { \
		मुक्त(options->var); \
		options->var = रिक्त; \
	} जबसम्म (0);
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

स्थिर शून्य
copy_server_option_int(पूर्णाङ्क *dst, पूर्णाङ्क src)
{
	यदि (src != -1)
		*dst = src;
}

स्थिर शून्य
copy_server_option_int64(int64_t *dst, int64_t src)
{
	यदि (src != -1)
		*dst = src;
}

स्थिर शून्य
copy_server_option_string(वर्ण **dst, अचर वर्ण *src)
{
	यदि (src != रिक्त && *dst != src) {
		मुक्त(*dst);
		*dst = xstrdup(src);
	}
}

स्थिर शून्य
copy_server_option_strarray_मानहरू(वर्ण ***dst, u_int ndst,
    वर्ण * अचर *src, u_int nsrc)
{
	u_int i;

	यदि (nsrc == 0)
		फर्काऊ;
	लागि (i = 0; i < ndst; i++)
		मुक्त((*dst)[i]);
	मुक्त(*dst);
	*dst = xcalloc(nsrc, परिमाण(**dst));
	लागि (i = 0; i < nsrc; i++)
		(*dst)[i] = src[i] == रिक्त ? रिक्त : xstrdup(src[i]);
}

स्थिर शून्य
copy_server_option_strarray(वर्ण ***dst, u_int *ndst,
    वर्ण * अचर *src, u_int nsrc)
{
	यदि (nsrc == 0)
		फर्काऊ;
	copy_server_option_strarray_मानहरू(dst, *ndst, src, nsrc);
	*ndst = nsrc;
}

स्थिर शून्य
copy_ipqos(ServerOptions *dst, अचर ServerOptions *src)
{
	copy_server_option_int(&dst->ip_qos_interactive,
	    src->ip_qos_interactive);
	copy_server_option_int(&dst->ip_qos_bulk, src->ip_qos_bulk);
}

स्थिर शून्य
copy_gatewayports(ServerOptions *dst, अचर ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.gateway_ports,
	    src->fwd_opts.gateway_ports);
}

स्थिर शून्य
copy_streamlocalbindunlink(ServerOptions *dst, अचर ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.streamlocal_bind_unlink,
	    src->fwd_opts.streamlocal_bind_unlink);
}

स्थिर शून्य
copy_loglevel(ServerOptions *dst, अचर ServerOptions *src)
{
	यदि (src->log_level != -1)
		dst->log_level = src->log_level;
}

स्थिर शून्य
copy_rekeylimit(ServerOptions *dst, अचर ServerOptions *src)
{
	copy_server_option_int64(&dst->rekey_limit, src->rekey_limit);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

स्थिर शून्य
copy_subsystem(ServerOptions *dst, अचर ServerOptions *src)
{
	u_int old_अङ्क_subsystems = dst->अङ्क_subsystems;

	यदि (src->अङ्क_subsystems == 0)
		फर्काऊ;
	copy_server_option_strarray_मानहरू(&dst->subsystem_name,
	    old_अङ्क_subsystems, src->subsystem_name, src->अङ्क_subsystems);
	copy_server_option_strarray_मानहरू(&dst->subsystem_command,
	    old_अङ्क_subsystems, src->subsystem_command, src->अङ्क_subsystems);
	copy_server_option_strarray_मानहरू(&dst->subsystem_args,
	    old_अङ्क_subsystems, src->subsystem_args, src->अङ्क_subsystems);
	dst->अङ्क_subsystems = src->अङ्क_subsystems;
}

स्थिर शून्य
copy_pubkey_auth_options(ServerOptions *dst, अचर ServerOptions *src)
{
	यदि (src->pubkey_auth_options != -1) {
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
शून्य
copy_set_server_options(ServerOptions *dst, ServerOptions *src, पूर्णाङ्क preauth)
{
	यदि (dst == src)
		फर्काऊ;

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
	गर { \
		मुक्त(dst->var); \
		dst->var = रिक्त; \
	} जबसम्म (0);
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
	यदि (src->fwd_opts.streamlocal_bind_mask != (mode_t)-1) {
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
	गर { \
		यदि (option_clear_or_none(v)) { \
			मुक्त(v); \
			v = रिक्त; \
		} \
	} जबसम्म(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_साँचोहरू);
	CLEAR_ON_NONE(dst->banner);

	/*
	 * The only things that should be below this point are string options
	 * which are only used after authentication.
	 */
	यदि (preauth)
		फर्काऊ;

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
स्थिर शून्य
parse_server_config_depth(ServerOptions *options, अचर वर्ण *filename,
    संरचना sshbuf *conf, संरचना include_list *includes,
    संरचना connection_info *connectinfo, पूर्णाङ्क flags, पूर्णाङ्क *activep, पूर्णाङ्क depth)
{
	पूर्णाङ्क linenum, bad_options = 0;
	वर्ण *cp, *obuf, *cbuf;

	यदि (depth < 0 || depth > SERVCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	यदि ((obuf = cbuf = sshbuf_dup_string(conf)) == रिक्त)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	जबसम्म ((cp = strsep(&cbuf, "\n")) != रिक्त) {
		यदि (process_server_config_पङ्क्ति_depth(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    depth, includes) != 0)
			bad_options++;
	}
	मुक्त(obuf);
	यदि (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

शून्य
parse_server_config(ServerOptions *options, अचर वर्ण *filename,
    संरचना sshbuf *conf, संरचना include_list *includes,
    संरचना connection_info *connectinfo, पूर्णाङ्क reexec)
{
	पूर्णाङ्क active = connectinfo ? 0 : 1;
	parse_server_config_depth(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_MATCH_ONLY : 0), &active, 0);
	यदि (!reexec)
		process_queued_listen_addrs(options);
}

स्थिर अचर वर्ण *
fmt_multistate_int(पूर्णाङ्क val, अचर संरचना multistate *m)
{
	u_int i;

	लागि (i = 0; m[i].साँचो != रिक्त; i++) {
		यदि (m[i].मान == val)
			फर्काऊ m[i].साँचो;
	}
	फर्काऊ "UNKNOWN";
}

स्थिर अचर वर्ण *
fmt_intarg(ServerOpCodes code, पूर्णाङ्क val)
{
	यदि (val == -1)
		फर्काऊ "unset";
	विकल्प (code) {
	पक्ष sAddressFamily:
		फर्काऊ fmt_multistate_int(val, multistate_addressfamily);
	पक्ष s_Permit_जरा_Login:
		फर्काऊ fmt_multistate_int(val, multistate_permitrootlogin);
	पक्ष sGatewayPorts:
		फर्काऊ fmt_multistate_int(val, multistate_gatewayports);
	पक्ष sCompression:
		फर्काऊ fmt_multistate_int(val, multistate_compression);
	पक्ष sAllowTcpForwarding:
		फर्काऊ fmt_multistate_int(val, multistate_tcpfwd);
	पक्ष sAllowStreamLocalForwarding:
		फर्काऊ fmt_multistate_int(val, multistate_tcpfwd);
	पक्ष sIgnoreRhosts:
		फर्काऊ fmt_multistate_int(val, multistate_ignore_rhosts);
	पक्ष sTCPKeepAlive:
		फर्काऊ fmt_multistate_int(val, multistate_keepalives);
	पक्ष sWarnWeakCrypto:
		फर्काऊ fmt_multistate_int(val, multistate_warnweakcrypto);
	पक्ष sFingerprintHash:
		फर्काऊ ssh_digest_alg_name(val);
	स्वभाव:
		विकल्प (val) {
		पक्ष 0:
			फर्काऊ "no";
		पक्ष 1:
			फर्काऊ "yes";
		स्वभाव:
			फर्काऊ "UNKNOWN";
		}
	}
}

स्थिर शून्य
dump_cfg_int(ServerOpCodes code, पूर्णाङ्क val)
{
	यदि (code == sUnusedConnectionTimeout && val == 0) {
		म_लिखो("%s none\n", lookup_opcode_name(code));
		फर्काऊ;
	}
	म_लिखो("%s %d\n", lookup_opcode_name(code), val);
}

स्थिर शून्य
dump_cfg_oct(ServerOpCodes code, पूर्णाङ्क val)
{
	म_लिखो("%s 0%o\n", lookup_opcode_name(code), val);
}

स्थिर शून्य
dump_cfg_fmtint(ServerOpCodes code, पूर्णाङ्क val)
{
	म_लिखो("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

स्थिर शून्य
dump_cfg_string(ServerOpCodes code, अचर वर्ण *val)
{
	म_लिखो("%s %s\n", lookup_opcode_name(code),
	    val == रिक्त ? "none" : val);
}

स्थिर शून्य
dump_cfg_strarray(ServerOpCodes code, u_int गन्ती, वर्ण **vals)
{
	u_int i;

	लागि (i = 0; i < गन्ती; i++)
		म_लिखो("%s %s\n", lookup_opcode_name(code), vals[i]);
}

स्थिर शून्य
dump_cfg_strarray_oneline(ServerOpCodes code, u_int गन्ती, वर्ण **vals)
{
	u_int i;

	विकल्प (code) {
	पक्ष sAuthenticationMethods:
	पक्ष sChannelTimeout:
		रोक;
	स्वभाव:
		यदि (गन्ती <= 0)
			फर्काऊ;
		रोक;
	}

	म_लिखो("%s", lookup_opcode_name(code));
	लागि (i = 0; i < गन्ती; i++)
		म_लिखो(" %s",  vals[i]);
	यदि (code == sAuthenticationMethods && गन्ती == 0)
		म_लिखो(" any");
	अन्यथा यदि (code == sChannelTimeout && गन्ती == 0)
		म_लिखो(" none");
	म_लिखो("\n");
}

स्थिर वर्ण *
format_listen_addrs(संरचना listenaddr *la)
{
	पूर्णाङ्क r;
	संरचना addrinfo *ai;
	वर्ण addr[NI_MAXHOST], port[NI_MAXSERV];
	वर्ण *laddr1 = xstrdup(""), *laddr2 = रिक्त;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	लागि (ai = la->addrs; ai; ai = ai->ai_next) {
		यदि ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    परिमाण(addr), port, परिमाण(port),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			जारी;
		}
		laddr2 = laddr1;
		यदि (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == रिक्त ? "" : " rdomain ",
			    la->rdomain == रिक्त ? "" : la->rdomain,
			    laddr2);
		} अन्यथा {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == रिक्त ? "" : " rdomain ",
			    la->rdomain == रिक्त ? "" : la->rdomain,
			    laddr2);
		}
		मुक्त(laddr2);
	}
	फर्काऊ laddr1;
}

शून्य
dump_config(ServerOptions *o)
{
	वर्ण *s;
	u_int i;

	/* these are usually at the top of the config */
	लागि (i = 0; i < o->अङ्क_ports; i++)
		म_लिखो("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(sAddressFamily, o->address_family);

	लागि (i = 0; i < o->अङ्क_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		म_लिखो("%s", s);
		मुक्त(s);
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
	dump_cfg_int(s_Client_Alive_गन्ती_Max, o->client_alive_गन्ती_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_size);
	dump_cfg_oct(sStreamLocalBindMask, o->fwd_opts.streamlocal_bind_mask);
	dump_cfg_int(sUnusedConnectionTimeout, o->unused_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(s_Permit_जरा_Login, o->permit_जरा_login);
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
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_साँचोहरू);
	dump_cfg_string(s_Security_साँचो_Provider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(sVersionAddendum, *o->version_addendum == '\0'
	    ? "none" : o->version_addendum);
	dump_cfg_string(s_Authorized_साँचोहरू_Command, o->authorized_साँचोहरू_command);
	dump_cfg_string(s_Authorized_साँचोहरू_Command_User, o->authorized_साँचोहरू_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(s_Host_साँचो_Agent, o->host_साँचो_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(s_Host_साँचो_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#यदि defined(__OpenBSD__) || defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
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
	dump_cfg_strarray_oneline(s_Authorized_साँचोहरू_File, o->अङ्क_authkeys_files,
	    o->authorized_साँचोहरू_files);
	dump_cfg_strarray_oneline(s_Revoked_साँचोहरू, o->अङ्क_revoked_साँचोहरू_files,
	    o->revoked_साँचोहरू_files);
	dump_cfg_strarray(s_Host_साँचो, o->अङ्क_host_साँचो_files, o->host_साँचो_files);
	dump_cfg_strarray(sHostCertificate, o->अङ्क_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->अङ्क_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->अङ्क_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->अङ्क_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->अङ्क_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->अङ्क_accept_env, o->accept_env);
	dump_cfg_strarray(sSetEnv, o->अङ्क_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->अङ्क_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->अङ्क_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->अङ्क_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	लागि (i = 0; i < o->अङ्क_subsystems; i++)
		म_लिखो("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_args[i]);

	म_लिखो("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_rate, o->max_startups);
	म_लिखो("PerSourceMaxStartups ");
	यदि (o->per_source_max_startups == पूर्णांक_उच्च)
		म_लिखो("none\n");
	अन्यथा
		म_लिखो("%d\n", o->per_source_max_startups);
	म_लिखो("PerSourceNetBlockSize %d:%d\n", o->per_source_masklen_ipv4,
	    o->per_source_masklen_ipv6);

	s = रिक्त;
	लागि (i = 0; tunmode_desc[i].val != -1; i++) {
		यदि (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].text;
			रोक;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	म_लिखो("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	म_लिखो("%s\n", iptos2str(o->ip_qos_bulk));

	म_लिखो("RekeyLimit %llu %d\n", (अचिन्हित दीर्घ दीर्घ)o->rekey_limit,
	    o->rekey_interval);

	म_लिखो("PermitOpen");
	यदि (o->अङ्क_permitted_opens == 0)
		म_लिखो(" any");
	अन्यथा {
		लागि (i = 0; i < o->अङ्क_permitted_opens; i++)
			म_लिखो(" %s", o->permitted_opens[i]);
	}
	म_लिखो("\n");
	म_लिखो("PermitListen");
	यदि (o->अङ्क_permitted_listens == 0)
		म_लिखो(" any");
	अन्यथा {
		लागि (i = 0; i < o->अङ्क_permitted_listens; i++)
			म_लिखो(" %s", o->permitted_listens[i]);
	}
	म_लिखो("\n");

	यदि (o->permit_user_env_allowlist == रिक्त) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} अन्यथा {
		म_लिखो("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	म_लिखो("PubkeyAuthOptions");
	यदि (o->pubkey_auth_options == 0)
		म_लिखो(" none");
	यदि (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		म_लिखो(" touch-required");
	यदि (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		म_लिखो(" verify-required");
	यदि (o->max_pubkey_ok != -1)
		म_लिखो(" max-pk-ok:%d", o->max_pubkey_ok);
	म_लिखो("\n");

	यदि (o->per_source_penalty.enabled) {
		म_लिखो("PerSourcePenalties crash:%f authfail:%f noauth:%f "
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
	} अन्यथा
		म_लिखो("PerSourcePenalties no\n");
}
