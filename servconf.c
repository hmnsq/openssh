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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/socket.h>
#समावेश <sys/queue.h>
#समावेश <sys/stat.h>
#अगर_घोषित __OpenBSD__
#समावेश <sys/sysctl.h>
#पूर्ण_अगर

#समावेश <netinet/in.h>
#समावेश <netinet/ip.h>
#अगर_घोषित HAVE_NET_ROUTE_H
#समावेश <net/route.h>
#पूर्ण_अगर

#समावेश <ctype.h>
#समावेश <glob.h>
#समावेश <netdb.h>
#समावेश <pwd.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <signal.h>
#समावेश <unistd.h>
#समावेश <limits.h>
#समावेश <stdarg.h>
#समावेश <errno.h>
#समावेश <util.h>

#समावेश "xmalloc.h"
#समावेश "ssh.h"
#समावेश "log.h"
#समावेश "sshbuf.h"
#समावेश "misc.h"
#समावेश "servconf.h"
#समावेश "pathnames.h"
#समावेश "cipher.h"
#समावेश "sshkey.h"
#समावेश "kex.h"
#समावेश "mac.h"
#समावेश "match.h"
#समावेश "channels.h"
#समावेश "groupaccess.h"
#समावेश "canohost.h"
#समावेश "packet.h"
#समावेश "ssherr.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "myproposal.h"
#समावेश "digest.h"
#समावेश "version.h"

#घोषणा SSHD_CONFIG_BLOB_VERSION	1

#अगर !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#पूर्ण_अगर

अटल व्योम add_listen_addr(ServerOptions *, स्थिर अक्षर *,
    स्थिर अक्षर *, पूर्णांक);
अटल व्योम add_one_listen_addr(ServerOptions *, स्थिर अक्षर *,
    स्थिर अक्षर *, पूर्णांक);
अटल व्योम parse_server_config_depth(ServerOptions *options,
    स्थिर अक्षर *filename, काष्ठा sshbuf *conf, काष्ठा include_list *includes,
    काष्ठा connection_info *connectinfo, पूर्णांक flags, पूर्णांक *activep, पूर्णांक depth);

बाह्य काष्ठा sshbuf *cfg;

/* Initializes the server options to their default values. */

व्योम
initialize_server_options(ServerOptions *options)
{
	स_रखो(options, 0, माप(*options));
#घोषणा SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#घोषणा SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#घोषणा SSHCONF_STRING(var, conf, flags, cp)		options->var = शून्य;
#घोषणा SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = शून्य;
#घोषणा SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#घोषणा SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#घोषणा SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#घोषणा SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#घोषणा SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = शून्य;
#घोषणा SSHCONF_ALIAS(old, conf, flags)			/* empty */

	/* Using macros for these is a bit overkill but forces consistency */
#घोषणा init_hostkeyfile(options) \
	options->host_कुंजी_files = 0; \
	options->अंक_host_कुंजी_files = 0; \
	options->host_कुंजी_file_userprovided = शून्य;
#घोषणा init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#घोषणा init_listenaddress(options) \
	options->queued_listen_addrs = शून्य; \
	options->अंक_queued_listens = 0; \
	options->listen_addrs = शून्य; \
	options->अंक_listen_addrs = 0;
#घोषणा init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
#घोषणा init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_SET;
#घोषणा init_port(options) \
	options->अंक_ports = 0; \
	options->ports_from_cmdline = 0;
#घोषणा init_gatewayports(options) \
	options->fwd_opts.gateway_ports = -1;
#घोषणा init_streamlocalbindmask(options) \
	options->fwd_opts.streamlocal_bind_mask = (mode_t)-1;
#घोषणा init_streamlocalbindunlink(options) \
	options->fwd_opts.streamlocal_bind_unlink = -1;
#घोषणा init_maxstartups(options) \
	options->max_startups_begin = -1; \
	options->max_startups_rate = -1; \
	options->max_startups = -1;
#घोषणा init_permituserenv(options) \
	options->permit_user_env = -1; \
	options->permit_user_env_allowlist = शून्य;
#घोषणा init_persourcenetblocksize(options) \
	options->per_source_masklen_ipv4 = -1; \
	options->per_source_masklen_ipv6 = -1;
#घोषणा init_persourcepenalties(options) \
	options->per_source_penalty_exempt = शून्य; \
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
#घोषणा init_rekeylimit(options) \
	options->rekey_limit = -1; \
	options->rekey_interval = -1;
#घोषणा init_subsystem(options) \
	options->अंक_subsystems = 0; \
	options->subsystem_name = शून्य; \
	options->subsystem_command = शून्य; \
	options->subsystem_args = शून्य;
#घोषणा init_pubkey_auth_options(options) \
	options->pubkey_auth_options = -1; \
	options->max_pubkey_ok = -1;
#घोषणा init_timingsecret(options) \
	options->timing_secret = 0;

	SSHD_CONFIG_ENTRIES

#अघोषित init_hostkeyfile
#अघोषित init_ipqos
#अघोषित init_listenaddress
#अघोषित init_logfacility
#अघोषित init_loglevel
#अघोषित init_port
#अघोषित init_gatewayports
#अघोषित init_streamlocalbindmask
#अघोषित init_streamlocalbindunlink
#अघोषित init_maxstartups
#अघोषित init_permituserenv
#अघोषित init_persourcenetblocksize
#अघोषित init_persourcepenalties
#अघोषित init_rekeylimit
#अघोषित init_subsystem
#अघोषित init_timingsecret
#अघोषित SSHCONF_INT
#अघोषित SSHCONF_INTFLAG
#अघोषित SSHCONF_STRING
#अघोषित SSHCONF_STRARRAY
#अघोषित SSHCONF_CUSTOM
#अघोषित SSHCONF_NONCONF
#अघोषित SSHCONF_DEPRECATE
#अघोषित SSHCONF_UNSUPPORTED_INT
#अघोषित SSHCONF_UNSUPPORTED_STRING
#अघोषित SSHCONF_ALIAS
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
अटल पूर्णांक
option_clear_or_none(स्थिर अक्षर *o)
{
	वापस o == शून्य || strcasecmp(o, "none") == 0;
}

अटल व्योम
assemble_algorithms(ServerOptions *o)
{
	अक्षर *all_cipher, *all_mac, *all_kex, *all_कुंजी, *all_sig;
	अक्षर *def_cipher, *def_mac, *def_kex, *def_कुंजी, *def_sig;
	पूर्णांक r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_कुंजी = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_कुंजी = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_कुंजी);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#घोषणा ASSEMBLE(what, defaults, all) \
	करो { \
		अगर ((r = kex_assemble_names(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} जबतक (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_कुंजी, all_कुंजी);
	ASSEMBLE(hostbased_accepted_algos, def_कुंजी, all_कुंजी);
	ASSEMBLE(pubkey_accepted_algos, def_कुंजी, all_कुंजी);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#अघोषित ASSEMBLE
	मुक्त(all_cipher);
	मुक्त(all_mac);
	मुक्त(all_kex);
	मुक्त(all_कुंजी);
	मुक्त(all_sig);
	मुक्त(def_cipher);
	मुक्त(def_mac);
	मुक्त(def_kex);
	मुक्त(def_कुंजी);
	मुक्त(def_sig);
}

व्योम
servconf_add_hostkey(स्थिर अक्षर *file, स्थिर पूर्णांक पंक्ति,
    ServerOptions *options, स्थिर अक्षर *path, पूर्णांक userprovided)
{
	अक्षर *apath = derelativise_path(path);

	opt_array_append2(file, पंक्ति, "HostKey",
	    &options->host_कुंजी_files, &options->host_कुंजी_file_userprovided,
	    &options->अंक_host_कुंजी_files, apath, userprovided);
	मुक्त(apath);
}

व्योम
servconf_add_hostcert(स्थिर अक्षर *file, स्थिर पूर्णांक पंक्ति,
    ServerOptions *options, स्थिर अक्षर *path)
{
	अक्षर *apath = derelativise_path(path);

	opt_array_append(file, पंक्ति, "HostCertificate",
	    &options->host_cert_files, &options->अंक_host_cert_files, apath);
	मुक्त(apath);
}

व्योम
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#अगर_घोषित SKIP_PRIVDROP
	अगर (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	अगर (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#पूर्ण_अगर

#घोषणा SSHCONF_INT(var, conf, flags, ms, def, cp) \
	अगर (options->var == -1) \
		options->var = def;
#घोषणा SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	अगर (options->var == -1) \
		options->var = def;
#घोषणा SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#घोषणा SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#घोषणा SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#घोषणा SSHCONF_NONCONF(funcsuffix)			/* done manually */
#घोषणा SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#घोषणा SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#घोषणा SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	करो { \
		मुक्त(options->var); \
		options->var = शून्य; \
	} जबतक (0);
#घोषणा SSHCONF_ALIAS(old, conf, flags)			/* empty */

	/* XXX maybe use macros here too to force consistency? */

	SSHD_CONFIG_ENTRIES

#अघोषित SSHCONF_INT
#अघोषित SSHCONF_INTFLAG
#अघोषित SSHCONF_STRING
#अघोषित SSHCONF_STRARRAY
#अघोषित SSHCONF_CUSTOM
#अघोषित SSHCONF_NONCONF
#अघोषित SSHCONF_DEPRECATE
#अघोषित SSHCONF_UNSUPPORTED_INT
#अघोषित SSHCONF_UNSUPPORTED_STRING
#अघोषित SSHCONF_ALIAS

#अगर_घोषित USE_PAM
	अगर (options->pam_service_name == शून्य)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#पूर्ण_अगर

	अगर (options->अंक_host_कुंजी_files == 0) {
		/* fill default hostkeys */
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_RSA_कुंजी_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ECDSA_कुंजी_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_ED25519_कुंजी_FILE, 0);
		servconf_add_hostkey("[default]", 0, options,
		    PATH_HOST_MLDSA44_ED25519_कुंजी_FILE, 0);
	}
	/* No certificates by default */
	अगर (options->अंक_ports == 0)
		options->ports[options->अंक_ports++] = SSH_DEFAULT_PORT;
	अगर (options->listen_addrs == शून्य)
		add_listen_addr(options, शून्य, शून्य, 0);
	अगर (options->pid_file == शून्य)
		options->pid_file = xstrdup(_PATH_SSH_DAEMON_PID_FILE);
	अगर (options->moduli_file == शून्य)
		options->moduli_file = xstrdup(_PATH_DH_MODULI);
	अगर (options->xauth_location == शून्य)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	अगर (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	अगर (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	अगर (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = शून्य;
	}
	अगर (options->rekey_limit == -1)
		options->rekey_limit = 0;
	अगर (options->rekey_interval == -1)
		options->rekey_interval = 0;
	अगर (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	अगर (options->max_startups == -1)
		options->max_startups = 100;
	अगर (options->max_startups_rate == -1)
		options->max_startups_rate = 30;		/* 30% */
	अगर (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	अगर (options->per_source_masklen_ipv4 == -1)
		options->per_source_masklen_ipv4 = 32;
	अगर (options->per_source_masklen_ipv6 == -1)
		options->per_source_masklen_ipv6 = 128;
	अगर (options->per_source_penalty.enabled == -1)
		options->per_source_penalty.enabled = 1;
	अगर (options->per_source_penalty.max_sources4 == -1)
		options->per_source_penalty.max_sources4 = 65536;
	अगर (options->per_source_penalty.max_sources6 == -1)
		options->per_source_penalty.max_sources6 = 65536;
	अगर (options->per_source_penalty.overflow_mode == -1)
		options->per_source_penalty.overflow_mode = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
	अगर (options->per_source_penalty.overflow_mode6 == -1)
		options->per_source_penalty.overflow_mode6 = options->per_source_penalty.overflow_mode;
	अगर (options->per_source_penalty.penalty_crash < 0.0)
		options->per_source_penalty.penalty_crash = 90.0;
	अगर (options->per_source_penalty.penalty_grace < 0.0)
		options->per_source_penalty.penalty_grace = 10.0;
	अगर (options->per_source_penalty.penalty_authfail < 0.0)
		options->per_source_penalty.penalty_authfail = 5.0;
	अगर (options->per_source_penalty.penalty_invaliduser < 0.0)
		options->per_source_penalty.penalty_invaliduser = 5.0;
	अगर (options->per_source_penalty.penalty_noauth < 0.0)
		options->per_source_penalty.penalty_noauth = 1.0;
	अगर (options->per_source_penalty.penalty_refuseconnection < 0.0)
		options->per_source_penalty.penalty_refuseconnection = 10.0;
	अगर (options->per_source_penalty.penalty_min < 0.0)
		options->per_source_penalty.penalty_min = 15.0;
	अगर (options->per_source_penalty.penalty_max < 0.0)
		options->per_source_penalty.penalty_max = 600.0;
	अगर (options->अंक_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_कुंजियाँ_files,
		    &options->अंक_authkeys_files,
		    PATH_SSH_USER_PERMITTED_कुंजियाँ);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_कुंजियाँ_files,
		    &options->अंक_authkeys_files,
		    _PATH_SSH_USER_PERMITTED_KEYS2);
	}
	अगर (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	अगर (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	अगर (options->version_addendum == शून्य)
		options->version_addendum = xstrdup("");
	अगर (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	अगर (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	अगर (options->sk_provider == शून्य)
		options->sk_provider = xstrdup("internal");
	अगर (options->sshd_session_path == शून्य)
		options->sshd_session_path = xstrdup(_PATH_SSHD_SESSION);
	अगर (options->sshd_auth_path == शून्य)
		options->sshd_auth_path = xstrdup(_PATH_SSHD_AUTH);
	अगर (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	अगर (options->agent_socket_path == शून्य)
		options->agent_socket_path = xstrdup(_PATH_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#घोषणा CLEAR_ON_NONE(v) \
	करो { \
		अगर (option_clear_or_none(v)) { \
			मुक्त(v); \
			v = शून्य; \
		} \
	} जबतक(0)
#घोषणा CLEAR_ON_NONE_ARRAY(v, nv, none) \
	करो { \
		अगर (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			मुक्त(options->v[0]); \
			मुक्त(options->v); \
			options->v = शून्य; \
			options->nv = 0; \
		} \
	} जबतक (0)
	CLEAR_ON_NONE(options->pid_file);
	CLEAR_ON_NONE(options->xauth_location);
	CLEAR_ON_NONE(options->banner);
	CLEAR_ON_NONE(options->trusted_user_ca_कुंजियाँ);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_कुंजी_agent);
	CLEAR_ON_NONE(options->per_source_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_path);

	क्रम (i = 0; i < options->अंक_host_कुंजी_files; i++)
		CLEAR_ON_NONE(options->host_कुंजी_files[i]);
	क्रम (i = 0; i < options->अंक_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, अंक_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, अंक_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_कुंजियाँ_files, अंक_revoked_कुंजियाँ_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_कुंजियाँ_files, अंक_authkeys_files, "none");
#अघोषित CLEAR_ON_NONE
#अघोषित CLEAR_ON_NONE_ARRAY
}

/* Macros to declare ServerOpCodes enum values */
#घोषणा SSHCONF_INT(var, conf, flags, ms, def, cp)	s##conf,
#घोषणा SSHCONF_INTFLAG(var, conf, flags, def, cp)	s##conf,
#घोषणा SSHCONF_STRING(var, conf, flags, cp)		s##conf,
#घोषणा SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	s##conf,
#घोषणा SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	s##conf,
#घोषणा SSHCONF_NONCONF(funcsuffix)			/* empty */
#घोषणा SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#घोषणा SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/* empty */
#घोषणा SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/* empty */
#घोषणा SSHCONF_ALIAS(old, conf, flags)			/* empty */

/* Keyword tokens. */
प्रकार क्रमागत {
	sBadOption,		/* == unknown option */
	SSHD_CONFIG_ENTRIES
	sMatch, sInclude,
	sDeprecated, sIgnore, sUnsupported
} ServerOpCodes;
#अघोषित SSHCONF_INT
#अघोषित SSHCONF_INTFLAG
#अघोषित SSHCONF_STRING
#अघोषित SSHCONF_STRARRAY
#अघोषित SSHCONF_CUSTOM
#अघोषित SSHCONF_NONCONF
#अघोषित SSHCONF_DEPRECATE
#अघोषित SSHCONF_UNSUPPORTED_INT
#अघोषित SSHCONF_UNSUPPORTED_STRING
#अघोषित SSHCONF_ALIAS

#घोषणा SSHCFG_GLOBAL		0x01	/* allowed in main section of config */
#घोषणा SSHCFG_MATCH		0x02	/* allowed inside a Match section */
#घोषणा SSHCFG_ALL		(SSHCFG_GLOBAL|SSHCFG_MATCH)
#घोषणा SSHCFG_NEVERMATCH	0x04  /* Match never matches; internal only */
#घोषणा SSHCFG_MATCH_ONLY	0x08  /* Match only in conditional blocks; internal only */

/* Macros to define keywords[] entries */
#घोषणा SSHCONF_KW(conf, flags)		{ #conf, s##conf, flags },
#घोषणा SSHCONF_INT(var, conf, flags, ms, def, cp)	SSHCONF_KW(conf, flags)
#घोषणा SSHCONF_INTFLAG(var, conf, flags, def, cp)	SSHCONF_KW(conf, flags)
#घोषणा SSHCONF_STRING(var, conf, flags, cp)		SSHCONF_KW(conf, flags)
#घोषणा SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	SSHCONF_KW(conf, flags)
#घोषणा SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	SSHCONF_KW(conf, flags)
#घोषणा SSHCONF_NONCONF(funcsuffix)			/* empty */
#घोषणा SSHCONF_DEPRECATED				sDeprecated
#घोषणा SSHCONF_IGNORE					sIgnore
#घोषणा SSHCONF_DEPRECATE(conf, flags, opcode) \
	{ #conf, opcode, flags },
#घोषणा SSHCONF_UNSUPPORTED_INT(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#घोषणा SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#घोषणा SSHCONF_ALIAS(old, conf, flags) \
	{ #old, s##conf, flags },

/* Textual representation of the tokens. */
अटल काष्ठा {
	स्थिर अक्षर *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", sMatch, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ शून्य, sBadOption, 0 }
};
#अघोषित SSHCONF_INT
#अघोषित SSHCONF_INTFLAG
#अघोषित SSHCONF_STRING
#अघोषित SSHCONF_STRARRAY
#अघोषित SSHCONF_CUSTOM
#अघोषित SSHCONF_NONCONF
#अघोषित SSHCONF_DEPRECATED
#अघोषित SSHCONF_IGNORE
#अघोषित SSHCONF_DEPRECATE
#अघोषित SSHCONF_UNSUPPORTED_INT
#अघोषित SSHCONF_UNSUPPORTED_STRING
#अघोषित SSHCONF_ALIAS

अटल काष्ठा {
	पूर्णांक val;
	अक्षर *text;
} tunmode_desc[] = {
	{ SSH_TUNMODE_NO, "no" },
	{ SSH_TUNMODE_POINTOPOINT, "point-to-point" },
	{ SSH_TUNMODE_ETHERNET, "ethernet" },
	{ SSH_TUNMODE_YES, "yes" },
	{ -1, शून्य }
};

/* Returns an opcode name from its number */

अटल स्थिर अक्षर *
lookup_opcode_name(ServerOpCodes code)
{
	u_int i;

	क्रम (i = 0; keywords[i].name != शून्य; i++)
		अगर (keywords[i].opcode == code)
			वापस(keywords[i].name);
	वापस "UNKNOWN";
}


/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

अटल ServerOpCodes
parse_token(स्थिर अक्षर *cp, स्थिर अक्षर *filename,
	    पूर्णांक linenum, u_int *flags)
{
	u_int i;

	क्रम (i = 0; keywords[i].name; i++)
		अगर (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			वापस keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	वापस sBadOption;
}

अक्षर *
derelativise_path(स्थिर अक्षर *path)
{
	अक्षर *expanded, *ret, cwd[PATH_MAX];

	अगर (strcasecmp(path, "none") == 0)
		वापस xstrdup("none");
	expanded = tilde_expand_filename(path, getuid());
	अगर (path_absolute(expanded))
		वापस expanded;
	अगर (getcwd(cwd, माप(cwd)) == शून्य)
		fatal_f("getcwd: %s", म_त्रुटि(त्रुटि_सं));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	मुक्त(expanded);
	वापस ret;
}

अटल व्योम
add_listen_addr(ServerOptions *options, स्थिर अक्षर *addr,
    स्थिर अक्षर *rdomain, पूर्णांक port)
{
	u_int i;

	अगर (port > 0)
		add_one_listen_addr(options, addr, rdomain, port);
	अन्यथा {
		क्रम (i = 0; i < options->अंक_ports; i++) {
			add_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

अटल व्योम
add_one_listen_addr(ServerOptions *options, स्थिर अक्षर *addr,
    स्थिर अक्षर *rdomain, पूर्णांक port)
{
	काष्ठा addrinfo hints, *ai, *aitop;
	अक्षर strport[NI_MAXSERV];
	पूर्णांक gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	क्रम (i = 0; i < options->अंक_listen_addrs; i++) {
		अगर (rdomain == शून्य && options->listen_addrs[i].rdomain == शून्य)
			अवरोध;
		अगर (rdomain == शून्य || options->listen_addrs[i].rdomain == शून्य)
			जारी;
		अगर (म_भेद(rdomain, options->listen_addrs[i].rdomain) == 0)
			अवरोध;
	}
	अगर (i >= options->अंक_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		अगर (i >= पूर्णांक_उच्च)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->अंक_listen_addrs, options->अंक_listen_addrs + 1,
		    माप(*options->listen_addrs));
		i = options->अंक_listen_addrs++;
		अगर (rdomain != शून्य)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	स_रखो(&hints, 0, माप(hints));
	hints.ai_family = options->address_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == शून्य) ? AI_PASSIVE : 0;
	snprintf(strport, माप strport, "%d", port);
	अगर ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    ssh_gai_strerror(gaierr));
	क्रम (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs[i].addrs;
	options->listen_addrs[i].addrs = aitop;
}

/* Returns nonzero if the routing domain name is valid */
अटल पूर्णांक
valid_rdomain(स्थिर अक्षर *name)
{
#अगर defined(HAVE_SYS_VALID_RDOMAIN)
	वापस sys_valid_rdomain(name);
#या_अगर defined(__OpenBSD__)
	स्थिर अक्षर *errstr;
	दीर्घ दीर्घ अंक;
	काष्ठा rt_tableinfo info;
	पूर्णांक mib[6];
	माप_प्रकार miblen = माप(mib);

	अगर (name == शून्य)
		वापस 1;

	अंक = strtonum(name, 0, 255, &errstr);
	अगर (errstr != शून्य)
		वापस 0;

	/* Check whether the table actually exists */
	स_रखो(mib, 0, माप(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_TABLE;
	mib[5] = (पूर्णांक)अंक;
	अगर (sysctl(mib, 6, &info, &miblen, शून्य, 0) == -1)
		वापस 0;

	वापस 1;
#अन्यथा /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	वापस 0;
#पूर्ण_अगर
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
अटल व्योम
queue_listen_addr(ServerOptions *options, स्थिर अक्षर *addr,
    स्थिर अक्षर *rdomain, पूर्णांक port)
{
	काष्ठा queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->अंक_queued_listens, options->अंक_queued_listens + 1,
	    माप(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->अंक_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->port = port;
	qla->rdomain = rdomain == शून्य ? शून्य : xstrdup(rdomain);
}

/*
 * Process queued (text) ListenAddress entries.
 */
अटल व्योम
process_queued_listen_addrs(ServerOptions *options)
{
	u_int i;
	काष्ठा queued_listenaddr *qla;

	अगर (options->अंक_ports == 0)
		options->ports[options->अंक_ports++] = SSH_DEFAULT_PORT;
	अगर (options->address_family == -1)
		options->address_family = AF_UNSPEC;

	क्रम (i = 0; i < options->अंक_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		add_listen_addr(options, qla->addr, qla->rdomain, qla->port);
		मुक्त(qla->addr);
		मुक्त(qla->rdomain);
	}
	मुक्त(options->queued_listen_addrs);
	options->queued_listen_addrs = शून्य;
	options->अंक_queued_listens = 0;
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

अटल पूर्णांक
match_cfg_पंक्ति_group(स्थिर अक्षर *grps, पूर्णांक पंक्ति, स्थिर अक्षर *user)
{
	पूर्णांक परिणाम = 0;
	काष्ठा passwd *pw;

	अगर (user == शून्य)
		जाओ out;

	अगर ((pw = getpwnam(user)) == शून्य) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", पंक्ति, user);
	} अन्यथा अगर (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, पंक्ति);
	} अन्यथा अगर (ga_match_pattern_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, पंक्ति);
	} अन्यथा {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, पंक्ति);
		परिणाम = 1;
	}
out:
	ga_free();
	वापस परिणाम;
}

अटल व्योम
match_test_missing_fatal(स्थिर अक्षर *criteria, स्थिर अक्षर *attrib)
{
	fatal("'Match %s' in configuration but '%s' not in connection "
	    "test specification.", criteria, attrib);
}

/*
 * All of the attributes on a single Match line are ANDed together, so we need
 * to check every attribute and set the result to zero if any attribute does
 * not match.
 */
अटल पूर्णांक
match_cfg_पंक्ति(स्थिर अक्षर *full_पंक्ति, पूर्णांक *acp, अक्षर ***avp,
    पूर्णांक पंक्ति, काष्ठा connection_info *ci)
{
	पूर्णांक परिणाम = 1, attributes = 0, port;
	अक्षर *arg, *attrib = शून्य, *oattrib;

	अगर (ci == शून्य) {
		debug3("checking syntax for 'Match %s' on line %d",
		    full_पंक्ति, पंक्ति);
	} अन्यथा {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", full_पंक्ति,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->address ? ci->address : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", पंक्ति);
	}

	जबतक ((oattrib = argv_अग्र(acp, avp)) != शून्य) {
		/* Terminate on comment */
		अगर (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			अवरोध;
		}
		attrib = xstrdup(oattrib);
		arg = शून्य;
		attributes++;
		/* Criterion "all" has no argument and must appear alone */
		अगर (strcasecmp(attrib, "all") == 0) {
			अगर (attributes > 1 ||
			    ((arg = argv_अग्र(acp, avp)) != शून्य &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				परिणाम = -1;
				जाओ out;
			}
			अगर (arg != शून्य && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			परिणाम = 1;
			जाओ out;
		}
		/* Criterion "invalid-user" also has no argument */
		अगर (strcasecmp(attrib, "invalid-user") == 0) {
			अगर (ci == शून्य) {
				परिणाम = 0;
				जाओ अग्र;
			}
			अगर (ci->user_invalid == 0)
				परिणाम = 0;
			अन्यथा
				debug("matched invalid-user at line %d", पंक्ति);
			जाओ अग्र;
		}

		/* Keep this list in sync with below */
		अगर (strprefix(attrib, "user=", 1) != शून्य ||
		    strprefix(attrib, "group=", 1) != शून्य ||
		    strprefix(attrib, "host=", 1) != शून्य ||
		    strprefix(attrib, "address=", 1) != शून्य ||
		    strprefix(attrib, "localaddress=", 1) != शून्य ||
		    strprefix(attrib, "localport=", 1) != शून्य ||
		    strprefix(attrib, "rdomain=", 1) != शून्य ||
		    strprefix(attrib, "version=", 1) != शून्य) {
			arg = म_अक्षर(attrib, '=');
			*(arg++) = '\0';
		} अन्यथा {
			arg = argv_अग्र(acp, avp);
		}

		/* All other criteria require an argument */
		अगर (arg == शून्य || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			परिणाम = -1;
			जाओ out;
		}
		अगर (strcasecmp(attrib, "user") == 0) {
			अगर (ci == शून्य || (ci->test && ci->user == शून्य)) {
				परिणाम = 0;
				जाओ अग्र;
			}
			अगर (ci->user == शून्य)
				match_test_missing_fatal("User", "user");
			अगर (match_usergroup_pattern_list(ci->user, arg) != 1)
				परिणाम = 0;
			अन्यथा
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, पंक्ति);
		} अन्यथा अगर (strcasecmp(attrib, "group") == 0) {
			अगर (ci == शून्य || (ci->test && ci->user == शून्य)) {
				परिणाम = 0;
				जाओ अग्र;
			}
			अगर (ci->user == शून्य)
				match_test_missing_fatal("Group", "user");
			चयन (match_cfg_पंक्ति_group(arg, पंक्ति, ci->user)) {
			हाल -1:
				परिणाम = -1;
				जाओ out;
			हाल 0:
				परिणाम = 0;
			}
		} अन्यथा अगर (strcasecmp(attrib, "host") == 0) {
			अगर (ci == शून्य || (ci->test && ci->host == शून्य)) {
				परिणाम = 0;
				जाओ अग्र;
			}
			अगर (ci->host == शून्य)
				match_test_missing_fatal("Host", "host");
			अगर (match_hostname(ci->host, arg) != 1)
				परिणाम = 0;
			अन्यथा
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, पंक्ति);
		} अन्यथा अगर (strcasecmp(attrib, "address") == 0) {
			अगर (ci == शून्य || (ci->test && ci->address == शून्य)) {
				अगर (addr_match_list(शून्य, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, पंक्ति);
				परिणाम = 0;
				जाओ अग्र;
			}
			अगर (ci->address == शून्य)
				match_test_missing_fatal("Address", "addr");
			चयन (addr_match_list(ci->address, arg)) {
			हाल 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->address, arg, पंक्ति);
				अवरोध;
			हाल 0:
			हाल -1:
				परिणाम = 0;
				अवरोध;
			हाल -2:
				परिणाम = -1;
				जाओ out;
			}
		} अन्यथा अगर (strcasecmp(attrib, "localaddress") == 0){
			अगर (ci == शून्य || (ci->test && ci->laddress == शून्य)) {
				अगर (addr_match_list(शून्य, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    पंक्ति);
				परिणाम = 0;
				जाओ अग्र;
			}
			अगर (ci->laddress == शून्य)
				match_test_missing_fatal("LocalAddress",
				    "laddr");
			चयन (addr_match_list(ci->laddress, arg)) {
			हाल 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, पंक्ति);
				अवरोध;
			हाल 0:
			हाल -1:
				परिणाम = 0;
				अवरोध;
			हाल -2:
				परिणाम = -1;
				जाओ out;
			}
		} अन्यथा अगर (strcasecmp(attrib, "localport") == 0) {
			अगर ((port = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				परिणाम = -1;
				जाओ out;
			}
			अगर (ci == शून्य || (ci->test && ci->lport == -1)) {
				परिणाम = 0;
				जाओ अग्र;
			}
			अगर (ci->lport == 0)
				match_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			अगर (port == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, port, पंक्ति);
			अन्यथा
				परिणाम = 0;
		} अन्यथा अगर (strcasecmp(attrib, "rdomain") == 0) {
			अगर (ci == शून्य || (ci->test && ci->rdomain == शून्य)) {
				परिणाम = 0;
				जाओ अग्र;
			}
			अगर (ci->rdomain == शून्य)
				match_test_missing_fatal("RDomain", "rdomain");
			अगर (match_pattern_list(ci->rdomain, arg, 0) != 1)
				परिणाम = 0;
			अन्यथा
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, पंक्ति);
		} अन्यथा अगर (strcasecmp(attrib, "version") == 0) {
			अगर (match_pattern_list(SSH_RELEASE, arg, 0) != 1)
				परिणाम = 0;
			अन्यथा
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, पंक्ति);
		} अन्यथा {
			error("Unsupported Match attribute %s", oattrib);
			परिणाम = -1;
			जाओ out;
		}
 अग्र:
		मुक्त(attrib);
		attrib = शून्य;
	}
	अगर (attributes == 0) {
		error("One or more attributes required for Match");
		वापस -1;
	}
 out:
	अगर (ci != शून्य && परिणाम != -1)
		debug3("match %sfound on line %d", परिणाम ? "" : "not ", पंक्ति);
	मुक्त(attrib);
	वापस परिणाम;
}

#घोषणा WHITESPACE " \t\r\n"

/* Multistate option parsing */
काष्ठा multistate {
	अक्षर *कुंजी;
	पूर्णांक मूल्य;
};
अटल स्थिर काष्ठा multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ शून्य, -1 }
};
अटल स्थिर काष्ठा multistate multistate_ignore_rhosts[] = {
	{ "yes",			IGNORE_RHOSTS_YES },
	{ "no",				IGNORE_RHOSTS_NO },
	{ "shosts-only",		IGNORE_RHOSTS_SHOSTS },
	{ शून्य, -1 }
};
अटल स्थिर काष्ठा multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ शून्य, -1 }
};
अटल स्थिर काष्ठा multistate multistate_permitrootlogin[] = {
	{ "prohibit-password",		PERMIT_NO_PASSWD },
	{ "without-password",		PERMIT_NO_PASSWD },
	{ "forced-commands-only",	PERMIT_FORCED_ONLY },
	{ "yes",			PERMIT_YES },
	{ "no",				PERMIT_NO },
	{ शून्य, -1 }
};
अटल स्थिर काष्ठा multistate multistate_compression[] = {
#अगर_घोषित WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#पूर्ण_अगर
	{ "no",				COMP_NONE },
	{ शून्य, -1 }
};
अटल स्थिर काष्ठा multistate multistate_gatewayports[] = {
	{ "clientspecified",		2 },
	{ "yes",			1 },
	{ "no",				0 },
	{ शून्य, -1 }
};
अटल स्थिर काष्ठा multistate multistate_tcpfwd[] = {
	{ "yes",			FORWARD_ALLOW },
	{ "all",			FORWARD_ALLOW },
	{ "no",				FORWARD_DENY },
	{ "remote",			FORWARD_REMOTE },
	{ "local",			FORWARD_LOCAL },
	{ शून्य, -1 }
};
अटल स्थिर काष्ठा multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ शून्य, -1 }
};
अटल स्थिर काष्ठा multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ शून्य, -1 }
};

अटल पूर्णांक
process_server_config_पंक्ति_depth(ServerOptions *options, अक्षर *पंक्ति,
    स्थिर अक्षर *filename, पूर्णांक linenum, पूर्णांक *activep,
    काष्ठा connection_info *connectinfo, पूर्णांक *inc_flags, पूर्णांक depth,
    काष्ठा include_list *includes)
{
	अक्षर *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	पूर्णांक cmdline = 0, *intptr, मूल्य, value2, value3, n, port, oactive, r;
	द्विगुन dvalue, *doubleptr = शून्य;
	पूर्णांक ca_only = 0, found = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	माप_प्रकार len;
	दीर्घ दीर्घ val64;
	स्थिर काष्ठा multistate *multistate_ptr;
	स्थिर अक्षर *errstr;
	काष्ठा include_item *item;
	glob_t gbuf;
	अक्षर **oav = शून्य, **av;
	पूर्णांक oac = 0, ac;
	पूर्णांक ret = -1;
	अक्षर **strs = शून्य; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	अगर ((len = म_माप(पंक्ति)) == 0)
		वापस 0;
	क्रम (len--; len > 0; len--) {
		अगर (म_अक्षर(WHITESPACE "\f", पंक्ति[len]) == शून्य)
			अवरोध;
		पंक्ति[len] = '\0';
	}

	str = पंक्ति;
	अगर ((keyword = strdelim(&str)) == शून्य)
		वापस 0;
	/* Ignore leading whitespace */
	अगर (*keyword == '\0')
		keyword = strdelim(&str);
	अगर (!keyword || !*keyword || *keyword == '#')
		वापस 0;
	अगर (str == शून्य || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		वापस -1;
	}
	intptr = शून्य;
	charptr = शून्य;
	opcode = parse_token(keyword, filename, linenum, &flags);

	अगर (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		वापस -1;
	}
	ac = oac;
	av = oav;

	अगर (activep == शून्य) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	अगर (*activep && opcode != sMatch && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	अगर (*activep == 0 && !(flags & SSHCFG_MATCH)) {
		अगर (connectinfo == शून्य) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} अन्यथा { /* this is a directive we have already processed */
			ret = 0;
			जाओ out;
		}
	}

	चयन (opcode) {
	/* Portable-specific options */
#अगर_घोषित USE_PAM
	हाल sUsePAM:
		intptr = &options->use_pam;
		जाओ parse_flag;
	हाल sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		अगर (*activep && *charptr == शून्य)
			*charptr = xstrdup(arg);
		अवरोध;
#पूर्ण_अगर

	/* Standard Options */
	हाल sBadOption:
		जाओ out;
	हाल sPort:
		/* ignore ports from configfile if cmdline specifies ports */
		अगर (options->ports_from_cmdline) {
			argv_consume(&ac);
			अवरोध;
		}
		अगर (options->अंक_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->अंक_ports++] = a2port(arg);
		अगर (options->ports[options->अंक_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		अवरोध;

	हाल sLoginGraceTime:
		intptr = &options->login_grace_time;
 parse_time:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		अगर ((मूल्य = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		अगर (*activep && *intptr == -1)
			*intptr = मूल्य;
		अवरोध;

	हाल sListenAddress:
		arg = argv_अग्र(&ac, &av);
		अगर (arg == शून्य || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		अगर (म_अक्षर(arg, '[') == शून्य && (p = म_अक्षर(arg, ':')) != शून्य
		    && म_अक्षर(p+1, ':') != शून्य) {
			port = 0;
			p = arg;
		} अन्यथा {
			arg2 = शून्य;
			p = hpdelim(&arg);
			अगर (p == शून्य)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			अगर (arg == शून्य)
				port = 0;
			अन्यथा अगर ((port = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = शून्य;
		अगर ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			अगर (म_भेद(arg, "rdomain") != 0 ||
			    (arg2 = argv_अग्र(&ac, &av)) == शून्य)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			अगर (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		queue_listen_addr(options, p, arg2, port);

		अवरोध;

	हाल sAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		मूल्य = -1;
		क्रम (i = 0; multistate_ptr[i].कुंजी != शून्य; i++) {
			अगर (strcasecmp(arg, multistate_ptr[i].कुंजी) == 0) {
				मूल्य = multistate_ptr[i].मूल्य;
				अवरोध;
			}
		}
		अगर (मूल्य == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		अगर (*activep && *intptr == -1)
			*intptr = मूल्य;
		अवरोध;

	हाल s_Host_कुंजी:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		अगर (*activep) {
			servconf_add_hostkey(filename, linenum,
			    options, arg, 1);
		}
		अवरोध;

	हाल s_Host_कुंजी_Agent:
		charptr = &options->host_कुंजी_agent;
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		अगर (*activep && *charptr == शून्य)
			*charptr = !म_भेद(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_path(arg);
		अवरोध;

	हाल sHostCertificate:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		अगर (*activep)
			servconf_add_hostcert(filename, linenum, options, arg);
		अवरोध;

	हाल sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		अगर (*activep && *charptr == शून्य) {
			*charptr = derelativise_path(arg);
			/* increase optional counter */
			अगर (intptr != शून्य)
				*intptr = *intptr + 1;
		}
		अवरोध;

	हाल sModuliFile:
		charptr = &options->moduli_file;
		जाओ parse_filename;

	हाल s_Permit_मूल_Login:
		intptr = &options->permit_मूल_login;
		multistate_ptr = multistate_permitrootlogin;
		जाओ parse_multistate;

	हाल sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
		multistate_ptr = multistate_ignore_rhosts;
		जाओ parse_multistate;

	हाल sIgnoreUserKnownHosts:
		intptr = &options->ignore_user_known_hosts;
 parse_flag:
		multistate_ptr = multistate_flag;
		जाओ parse_multistate;

	हाल sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		जाओ parse_flag;

	हाल sHostbasedUsesNameFromPacketOnly:
		intptr = &options->hostbased_uses_name_from_packet_only;
		जाओ parse_flag;

	हाल sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		अगर (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		अगर (*activep && *charptr == शून्य)
			*charptr = xstrdup(arg);
		अवरोध;

	हाल s_Host_कुंजी_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
		जाओ parse_pubkey_algos;

	हाल sCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		जाओ parse_pubkey_algos;

	हाल sPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		ca_only = 0;
		जाओ parse_flag;

	हाल sPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		जाओ parse_pubkey_algos;

	हाल sPubkeyAuthOptions:
		intptr = &options->pubkey_auth_options;
		मूल्य = 0;
		value2 = -1;
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			अगर (strcasecmp(arg, "none") == 0)
				जारी;
			अगर (strcasecmp(arg, "touch-required") == 0)
				मूल्य |= PUBKEYAUTH_TOUCH_REQUIRED;
			अन्यथा अगर (strcasecmp(arg, "verify-required") == 0)
				मूल्य |= PUBKEYAUTH_VERIFY_REQUIRED;
			अन्यथा अगर (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				अगर (errstr != शून्य) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					जाओ out;
				}
			} अन्यथा {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				जाओ out;
			}
		}
		अगर (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = मूल्य;
			options->max_pubkey_ok = value2;
		}
		अवरोध;

#अगर_घोषित KRB5
	हाल sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		जाओ parse_flag;

	हाल sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		जाओ parse_flag;

	हाल sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		जाओ parse_flag;
#अगर_घोषित USE_AFS
	हाल sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		जाओ parse_flag;
#पूर्ण_अगर /* USE_AFS */
#पूर्ण_अगर /* KRB5 */

#अगर_घोषित GSSAPI
	हाल sGSSAPIAuthentication:
		intptr = &options->gss_authentication;
		जाओ parse_flag;

	हाल sGSSAPICleanupCredentials:
		intptr = &options->gss_cleanup_creds;
		जाओ parse_flag;

	हाल sGSSAPIDelegateCredentials:
		intptr = &options->gss_deleg_creds;
		जाओ parse_flag;

	हाल sGSSAPIStrictAcceptorCheck:
		intptr = &options->gss_strict_acceptor;
		जाओ parse_flag;
#पूर्ण_अगर /* GSSAPI */

	हाल sPasswordAuthentication:
		intptr = &options->password_authentication;
		जाओ parse_flag;

	हाल sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		जाओ parse_flag;

	हाल sPrintMotd:
		intptr = &options->print_motd;
		जाओ parse_flag;

#अगर_अघोषित DISABLE_LASTLOG
	हाल sPrintLastLog:
		intptr = &options->print_lastlog;
		जाओ parse_flag;
#पूर्ण_अगर

	हाल sX11Forwarding:
		intptr = &options->x11_forwarding;
		जाओ parse_flag;

	हाल sX11DisplayOffset:
		intptr = &options->x11_display_offset;
 parse_int:
		arg = argv_अग्र(&ac, &av);
		अगर ((errstr = atoi_err(arg, &मूल्य)) != शून्य)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		अगर (*activep && *intptr == -1)
			*intptr = मूल्य;
		अवरोध;

	हाल sX11UseLocalhost:
		intptr = &options->x11_use_localhost;
		जाओ parse_flag;

	हाल sXAuthLocation:
		charptr = &options->xauth_location;
		जाओ parse_filename;

	हाल sPermitTTY:
		intptr = &options->permit_tty;
		जाओ parse_flag;

	हाल sPermitUserRC:
		intptr = &options->permit_user_rc;
		जाओ parse_flag;

	हाल sStrictModes:
		intptr = &options->strict_modes;
		जाओ parse_flag;

	हाल sTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		जाओ parse_multistate;

	हाल sPermitEmptyPasswords:
		intptr = &options->permit_empty_passwd;
		जाओ parse_flag;

	हाल sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		मूल्य = 0;
		p = शून्य;
		अगर (म_भेद(arg, "yes") == 0)
			मूल्य = 1;
		अन्यथा अगर (म_भेद(arg, "no") == 0)
			मूल्य = 0;
		अन्यथा {
			/* Pattern-list specified */
			मूल्य = 1;
			p = xstrdup(arg);
		}
		अगर (*activep && *intptr == -1) {
			*intptr = मूल्य;
			*charptr = p;
			p = शून्य;
		}
		मुक्त(p);
		अवरोध;

	हाल sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		जाओ parse_multistate;

	हाल sRekeyLimit:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		अगर (म_भेद(arg, "default") == 0) {
			val64 = 0;
		} अन्यथा {
			अगर (scan_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, म_त्रुटि(त्रुटि_सं));
			अगर (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		अगर (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		अगर (ac != 0) { /* optional rekey interval present */
			अगर (म_भेद(av[0], "none") == 0) {
				(व्योम)argv_अग्र(&ac, &av);	/* discard */
				अवरोध;
			}
			intptr = &options->rekey_interval;
			जाओ parse_time;
		}
		अवरोध;

	हाल sGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		multistate_ptr = multistate_gatewayports;
		जाओ parse_multistate;

	हाल sUseDNS:
		intptr = &options->use_dns;
		जाओ parse_flag;

	हाल sSyslogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_अग्र(&ac, &av);
		मूल्य = log_facility_संख्या(arg);
		अगर (मूल्य == SYSLOG_FACILITY_NOT_SET)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		अगर (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) मूल्य;
		अवरोध;

	हाल sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_अग्र(&ac, &av);
		मूल्य = log_level_संख्या(arg);
		अगर (मूल्य == SYSLOG_LEVEL_NOT_SET)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		अगर (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) मूल्य;
		अवरोध;

	हाल sLogVerbose:
		found = options->अंक_log_verbose == 0;
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			अगर (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				जाओ out;
			}
			/* Allow "none" only in first position */
			अगर (strcasecmp(arg, "none") == 0) {
				अगर (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					जाओ out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		अगर (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		अगर (found && *activep) {
			options->log_verbose = strs;
			options->अंक_log_verbose = nstrs;
			strs = शून्य; /* transferred */
			nstrs = 0;
		}
		अवरोध;

	हाल sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		जाओ parse_multistate;

	हाल sAllowStreamLocalForwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		जाओ parse_multistate;

	हाल sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		जाओ parse_flag;

	हाल sAgentSocketPath:
		charptr = &options->agent_socket_path;
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		अगर (म_भेदन(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			अगर (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} अन्यथा अगर (म_भेदन(arg, "user:", 5) == 0) {
			/* User paths must not be empty */
			अगर (arg[5] == '\0') {
				fatal("%s line %d: invalid user path.",
				    filename, linenum);
			}
		} अन्यथा अगर (म_भेद(arg, "none") != 0)
			fatal("%s line %d: invalid path.", filename, linenum);
		अगर (*activep && *charptr == शून्य)
			*charptr = xstrdup(arg);
		अवरोध;

	हाल sDisableForwarding:
		intptr = &options->disable_forwarding;
		जाओ parse_flag;

	हाल sAllowUsers:
		chararrayptr = &options->allow_users;
		uintptr = &options->अंक_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			अगर (*arg == '\0' ||
			    match_user(शून्य, शून्य, शून्य, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			found = 1;
			अगर (!*activep)
				जारी;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		अगर (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		अवरोध;

	हाल sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->अंक_deny_users;
		जाओ parse_allowdenyusers;

	हाल sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->अंक_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			अगर (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			found = 1;
			अगर (!*activep)
				जारी;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		अगर (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		अवरोध;

	हाल sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->अंक_deny_groups;
		जाओ parse_allowdenygroups;

	हाल sCiphers:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		अगर (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		अगर (options->ciphers == शून्य)
			options->ciphers = xstrdup(arg);
		अवरोध;

	हाल sMacs:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		अगर (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		अगर (options->macs == शून्य)
			options->macs = xstrdup(arg);
		अवरोध;

	हाल sKexAlgorithms:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		अगर (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		अगर (options->kex_algorithms == शून्य)
			options->kex_algorithms = xstrdup(arg);
		अवरोध;

	हाल sSubsystem:
		अगर ((arg = argv_अग्र(&ac, &av)) == शून्य || *arg == '\0' ||
		   ((arg2 = argv_अग्र(&ac, &av)) == शून्य || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		अगर (!*activep) {
			argv_consume(&ac);
			अवरोध;
		}
		found = 0;
		क्रम (i = 0; i < options->अंक_subsystems; i++) {
			अगर (म_भेद(arg, options->subsystem_name[i]) == 0) {
				found = 1;
				अवरोध;
			}
		}
		अगर (found) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			अवरोध;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->अंक_subsystems,
		    options->अंक_subsystems + 1,
		    माप(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->अंक_subsystems,
		    options->अंक_subsystems + 1,
		    माप(*options->subsystem_command));
		options->subsystem_args = xrecallocarray(
		    options->subsystem_args, options->अंक_subsystems,
		    options->अंक_subsystems + 1,
		    माप(*options->subsystem_args));
		options->subsystem_name[options->अंक_subsystems] = xstrdup(arg);
		options->subsystem_command[options->अंक_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_args[options->अंक_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		मुक्त(arg2);
		मुक्त(arg);
		argv_consume(&ac);
		options->अंक_subsystems++;
		अवरोध;

	हाल sMaxStartups:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		अगर ((n = माला_पूछो(arg, "%d:%d:%d",
		    &मूल्य, &value2, &value3)) == 3) {
			अगर (मूल्य > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} अन्यथा अगर (n == 1) {
			value3 = मूल्य;
			value2 = -1;
		} अन्यथा {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		अगर (मूल्य <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		अगर (*activep && options->max_startups == -1) {
			options->max_startups_begin = मूल्य;
			options->max_startups_rate = value2;
			options->max_startups = value3;
		}
		अवरोध;

	हाल s_Per_Source_Net_Block_आकार:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		चयन (n = माला_पूछो(arg, "%d:%d", &मूल्य, &value2)) {
		हाल 2:
			अगर (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		हाल 1:
			अगर (मूल्य < 0 || मूल्य > 32)
				n = -1;
		}
		अगर (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		अगर (*activep && options->per_source_masklen_ipv4 == -1) {
			options->per_source_masklen_ipv4 = मूल्य;
			अगर (n == 2)
				options->per_source_masklen_ipv6 = value2;
		}
		अवरोध;

	हाल sPerSourceMaxStartups:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		अगर (म_भेद(arg, "none") == 0) { /* no limit */
			मूल्य = पूर्णांक_उच्च;
		} अन्यथा {
			अगर ((errstr = atoi_err(arg, &मूल्य)) != शून्य)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		अगर (*activep && options->per_source_max_startups == -1)
			options->per_source_max_startups = मूल्य;
		अवरोध;

	हाल sPerSourcePenaltyExemptList:
		charptr = &options->per_source_penalty_exempt;
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		अगर (addr_match_list(शून्य, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		अगर (*activep && *charptr == शून्य)
			*charptr = xstrdup(arg);
		अवरोध;

	हाल sPerSourcePenalties:
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			स्थिर अक्षर *q = शून्य;

			found = 1;
			intptr = शून्य;
			doubleptr = शून्य;
			मूल्य = -1;
			value2 = 0;
			/* Allow no/yes only in first position */
			अगर (strcasecmp(arg, "no") == 0 ||
			    (value2 = (strcasecmp(arg, "yes") == 0))) {
				अगर (ac > 0) {
					fatal("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
				}
				अगर (*activep &&
				    options->per_source_penalty.enabled == -1)
					options->per_source_penalty.enabled = value2;
				जारी;
			} अन्यथा अगर ((q = strprefix(arg, "crash:", 0)) != शून्य) {
				doubleptr = &options->per_source_penalty.penalty_crash;
			} अन्यथा अगर ((q = strprefix(arg, "authfail:", 0)) != शून्य) {
				doubleptr = &options->per_source_penalty.penalty_authfail;
			} अन्यथा अगर ((q = strprefix(arg, "invaliduser:", 0)) != शून्य) {
				doubleptr = &options->per_source_penalty.penalty_invaliduser;
			} अन्यथा अगर ((q = strprefix(arg, "noauth:", 0)) != शून्य) {
				doubleptr = &options->per_source_penalty.penalty_noauth;
			} अन्यथा अगर ((q = strprefix(arg, "grace-exceeded:", 0)) != शून्य) {
				doubleptr = &options->per_source_penalty.penalty_grace;
			} अन्यथा अगर ((q = strprefix(arg, "refuseconnection:", 0)) != शून्य) {
				doubleptr = &options->per_source_penalty.penalty_refuseconnection;
			} अन्यथा अगर ((q = strprefix(arg, "max:", 0)) != शून्य) {
				doubleptr = &options->per_source_penalty.penalty_max;
			} अन्यथा अगर ((q = strprefix(arg, "min:", 0)) != शून्य) {
				doubleptr = &options->per_source_penalty.penalty_min;
			} अन्यथा अगर ((q = strprefix(arg, "max-sources4:", 0)) != शून्य) {
				intptr = &options->per_source_penalty.max_sources4;
				अगर ((errstr = atoi_err(q, &मूल्य)) != शून्य)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} अन्यथा अगर ((q = strprefix(arg, "max-sources6:", 0)) != शून्य) {
				intptr = &options->per_source_penalty.max_sources6;
				अगर ((errstr = atoi_err(q, &मूल्य)) != शून्य)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} अन्यथा अगर (म_भेद(arg, "overflow:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				मूल्य = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} अन्यथा अगर (म_भेद(arg, "overflow:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode;
				मूल्य = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} अन्यथा अगर (म_भेद(arg, "overflow6:deny-all") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				मूल्य = PER_SOURCE_PENALTY_OVERFLOW_DENY_ALL;
			} अन्यथा अगर (म_भेद(arg, "overflow6:permissive") == 0) {
				intptr = &options->per_source_penalty.overflow_mode6;
				मूल्य = PER_SOURCE_PENALTY_OVERFLOW_PERMISSIVE;
			} अन्यथा {
				fatal("%s line %d: unsupported %s keyword %s",
				    filename, linenum, keyword, arg);
			}

			अगर (doubleptr != शून्य) {
				अगर ((dvalue = convtime_double(q)) < 0) {
					fatal("%s line %d: invalid %s time value.",
					    filename, linenum, keyword);
				}
				अगर (*activep && *doubleptr < 0.0) {
					*doubleptr = dvalue;
					options->per_source_penalty.enabled = 1;
				}
			} अन्यथा अगर (intptr != शून्य) {
				अगर (*activep && *intptr == -1) {
					*intptr = मूल्य;
					options->per_source_penalty.enabled = 1;
				}
			} अन्यथा {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		अगर (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		अवरोध;

	हाल sMaxAuthTries:
		intptr = &options->max_authtries;
		जाओ parse_int;

	हाल sMaxSessions:
		intptr = &options->max_sessions;
		जाओ parse_int;

	हाल sBanner:
		charptr = &options->banner;
		जाओ parse_filename;

	/*
	 * These options can contain %X options expanded at
	 * connect time, so that you can specify paths like:
	 *
	 * AuthorizedKeysFile	/etc/ssh_keys/%u
	 */
	हाल s_Authorized_कुंजियाँ_File:
		uintptr = &options->अंक_authkeys_files;
		chararrayptr = &options->authorized_कुंजियाँ_files;
 parse_filenames:
		found = *uintptr == 0;
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			अगर (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				जाओ out;
			}
			/* Allow "none" only in first position */
			अगर (strcasecmp(arg, "none") == 0) {
				अगर (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					जाओ out;
				}
			}
			arg2 = tilde_expand_filename(arg, getuid());
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			मुक्त(arg2);
		}
		अगर (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		अगर (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = शून्य; /* transferred */
			nstrs = 0;
		}
		अवरोध;

	हाल sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		अगर (*activep && *charptr == शून्य) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			अगर (intptr != शून्य)
				*intptr = *intptr + 1;
		}
		अवरोध;

	हाल sClientAliveInterval:
		intptr = &options->client_alive_interval;
		जाओ parse_time;

	हाल s_Client_Alive_गिनती_Max:
		intptr = &options->client_alive_गिनती_max;
		जाओ parse_int;

	हाल sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			अगर (*arg == '\0' || म_अक्षर(arg, '=') != शून्य)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			found = 1;
			अगर (!*activep)
				जारी;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->अंक_accept_env,
			    arg);
		}
		अगर (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		अवरोध;

	हाल sSetEnv:
		found = options->अंक_setenv == 0;
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			अगर (*arg == '\0' || म_अक्षर(arg, '=') == शून्य)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			अगर (lookup_setenv_in_list(arg, strs, nstrs) != शून्य) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				जारी;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		अगर (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		अगर (found && *activep) {
			options->setenv = strs;
			options->अंक_setenv = nstrs;
			strs = शून्य; /* transferred */
			nstrs = 0;
		}
		अवरोध;

	हाल sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		मूल्य = -1;
		क्रम (i = 0; tunmode_desc[i].val != -1; i++)
			अगर (म_भेद(tunmode_desc[i].text, arg) == 0) {
				मूल्य = tunmode_desc[i].val;
				अवरोध;
			}
		अगर (मूल्य == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		अगर (*activep && *intptr == -1)
			*intptr = मूल्य;
		अवरोध;

	हाल sInclude:
		अगर (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		मूल्य = 0;
		जबतक ((arg2 = argv_अग्र(&ac, &av)) != शून्य) {
			अगर (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				जाओ out;
			}
			मूल्य++;
			found = 0;
			अगर (*arg2 != '/' && *arg2 != '~') {
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
				अगर (म_भेद(item->selector, arg) != 0)
					जारी;
				अगर (item->filename != शून्य) {
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
			अगर (found != 0) {
				मुक्त(arg);
				जारी;
			}

			/* requested glob was not in cache */
			debug2("%s line %d: new include %s",
			    filename, linenum, arg);
			अगर ((r = glob(arg, 0, शून्य, &gbuf)) != 0) {
				अगर (r != GLOB_NOMATCH) {
					fatal("%s line %d: include \"%s\" glob "
					    "failed", filename, linenum, arg);
				}
				/*
				 * If no entry matched then record a
				 * placeholder to skip later glob calls.
				 */
				debug2("%s line %d: no match for %s",
				    filename, linenum, arg);
				item = xcalloc(1, माप(*item));
				item->selector = xstrdup(arg);
				TAILQ_INSERT_TAIL(includes,
				    item, entry);
			}
			अगर (gbuf.gl_pathc > पूर्णांक_उच्च)
				fatal_f("too many glob results");
			क्रम (n = 0; n < (पूर्णांक)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				item = xcalloc(1, माप(*item));
				item->selector = xstrdup(arg);
				item->filename = xstrdup(gbuf.gl_pathv[n]);
				अगर ((item->contents = sshbuf_new()) == शून्य)
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
		अगर (मूल्य == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		अवरोध;

	हाल sMatch:
		अगर (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		मूल्य = match_cfg_पंक्ति(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? शून्य : connectinfo));
		अगर (मूल्य < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : मूल्य;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_MATCH_ONLY;
		अवरोध;

	हाल sPermitListen:
	हाल sPermitOpen:
		अगर (opcode == sPermitListen) {
			uintptr = &options->अंक_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} अन्यथा {
			uintptr = &options->अंक_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		found = *uintptr == 0;
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			अगर (म_भेद(arg, "any") == 0 ||
			    म_भेद(arg, "none") == 0) {
				अगर (nstrs != 0) {
					fatal("%s line %d: %s must appear "
					    "alone on a %s line.",
					    filename, linenum, arg, keyword);
				}
				opt_array_append(filename, linenum, keyword,
				    &strs, &nstrs, arg);
				जारी;
			}

			अगर (opcode == sPermitListen &&
			    म_अक्षर(arg, ':') == शून्य) {
				/*
				 * Allow bare port number for PermitListen
				 * to indicate a wildcard listen host.
				 */
				xasprintf(&arg2, "*:%s", arg);
			} अन्यथा {
				arg2 = xstrdup(arg);
				p = hpdelim(&arg);
				अगर (p == शून्य) {
					fatal("%s line %d: %s missing host",
					    filename, linenum, keyword);
				}
				p = cleanhostname(p);
			}
			अगर (arg == शून्य ||
			    ((port = permitopen_port(arg)) < 0)) {
				fatal("%s line %d: %s bad port number",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			मुक्त(arg2);
		}
		अगर (nstrs == 0) {
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		}
		अगर (found && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = शून्य; /* transferred */
			nstrs = 0;
		}
		अवरोध;

	हाल sForceCommand:
		अगर (str == शून्य || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = म_अखोज(str, WHITESPACE);
		अगर (*activep && options->adm_forced_command == शून्य)
			options->adm_forced_command = xstrdup(str + len);
		argv_consume(&ac);
		अवरोध;

	हाल sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		अगर (*activep && *charptr == शून्य)
			*charptr = xstrdup(arg);
		अवरोध;

	हाल sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_कुंजियाँ;
		जाओ parse_filename;

	हाल s_Revoked_कुंजियाँ:
		uintptr = &options->अंक_revoked_कुंजियाँ_files;
		chararrayptr = &options->revoked_कुंजियाँ_files;
		जाओ parse_filenames;

	हाल s_Security_कुंजी_Provider:
		charptr = &options->sk_provider;
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		अगर (*activep && *charptr == शून्य) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_path(arg);
			/* increase optional counter */
			अगर (intptr != शून्य)
				*intptr = *intptr + 1;
		}
		अवरोध;

	हाल sIPQoS:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		अगर ((मूल्य = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		अगर (मूल्य == पूर्णांक_न्यून) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			मूल्य = पूर्णांक_उच्च;
		}
		arg = argv_अग्र(&ac, &av);
		अगर (arg == शून्य)
			value2 = मूल्य;
		अन्यथा अगर ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		अगर (value2 == पूर्णांक_न्यून) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = पूर्णांक_उच्च;
		}
		अगर (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = मूल्य;
			options->ip_qos_bulk = value2;
		}
		अवरोध;

	हाल sVersionAddendum:
		अगर (str == शून्य || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = म_अखोज(str, WHITESPACE);
		अगर (म_अक्षर(str + len, '\r') != शून्य) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		अगर ((arg = म_अक्षर(पंक्ति, '#')) != शून्य) {
			*arg = '\0';
			rtrim(पंक्ति);
		}
		अगर (*activep && options->version_addendum == शून्य) {
			अगर (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			अन्यथा
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		अवरोध;

	हाल s_Authorized_कुंजियाँ_Command:
		charptr = &options->authorized_कुंजियाँ_command;
 parse_command:
		len = म_अखोज(str, WHITESPACE);
		अगर (str[len] != '/' && strcasecmp(str + len, "none") != 0) {
			fatal("%.200s line %d: %s must be an absolute path",
			    filename, linenum, keyword);
		}
		अगर (*activep && *charptr == शून्य)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		अवरोध;

	हाल s_Authorized_कुंजियाँ_Command_User:
		charptr = &options->authorized_कुंजियाँ_command_user;
 parse_localuser:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			fatal("%s line %d: missing %s argument.",
			    filename, linenum, keyword);
		}
		अगर (*activep && *charptr == शून्य)
			*charptr = xstrdup(arg);
		अवरोध;

	हाल sAuthorizedPrincipalsCommand:
		charptr = &options->authorized_principals_command;
		जाओ parse_command;

	हाल sAuthorizedPrincipalsCommandUser:
		charptr = &options->authorized_principals_command_user;
		जाओ parse_localuser;

	हाल sAuthenticationMethods:
		found = options->अंक_auth_methods == 0;
		मूल्य = 0; /* seen "any" pseudo-method */
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			अगर (म_भेद(arg, "any") == 0) {
				अगर (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				मूल्य = 1;
			} अन्यथा अगर (मूल्य) {
				fatal("%s line %d: \"any\" must appear "
				    "alone in %s", filename, linenum, keyword);
			} अन्यथा अगर (auth2_methods_valid(arg, 0) != 0) {
				fatal("%s line %d: invalid %s method list.",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		अगर (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		अगर (found && *activep) {
			options->auth_methods = strs;
			options->अंक_auth_methods = nstrs;
			strs = शून्य; /* transferred */
			nstrs = 0;
		}
		अवरोध;

	हाल sStreamLocalBindMask:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		मूल्य = म_से_दीर्घ(arg, &p, 8);
		अगर (arg == p || मूल्य < 0 || मूल्य > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		अगर (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)मूल्य;
		अवरोध;

	हाल sStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		जाओ parse_flag;

	हाल sFingerprintHash:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		अगर ((मूल्य = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		अगर (*activep)
			options->fingerprint_hash = मूल्य;
		अवरोध;

	हाल sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		जाओ parse_flag;

	हाल sRDomain:
#अगर !defined(__OpenBSD__) && !defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#पूर्ण_अगर
		charptr = &options->routing_domain;
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		अगर (strcasecmp(arg, "none") != 0 && म_भेद(arg, "%D") != 0 &&
		    !valid_rdomain(arg))
			fatal("%s line %d: invalid routing domain",
			    filename, linenum);
		अगर (*activep && *charptr == शून्य)
			*charptr = xstrdup(arg);
		अवरोध;

	हाल sRequiredRSASize:
		intptr = &options->required_rsa_आकार;
		जाओ parse_int;

	हाल sChannelTimeout:
		found = options->अंक_channel_timeouts == 0;
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			/* Allow "none" only in first position */
			अगर (strcasecmp(arg, "none") == 0) {
				अगर (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					जाओ out;
				}
			} अन्यथा अगर (parse_pattern_interval(arg,
			    शून्य, शून्य) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		अगर (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		अगर (found && *activep) {
			options->channel_timeouts = strs;
			options->अंक_channel_timeouts = nstrs;
			strs = शून्य; /* transferred */
			nstrs = 0;
		}
		अवरोध;

	हाल sUnusedConnectionTimeout:
		intptr = &options->unused_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		अगर (av[0] != शून्य && strcasecmp(av[0], "none") == 0) {
			(व्योम)argv_अग्र(&ac, &av); /* consume arg */
			अगर (*activep)
				*intptr = 0;
			अवरोध;
		}
		जाओ parse_time;

	हाल sSshdSessionPath:
		charptr = &options->sshd_session_path;
		जाओ parse_filename;

	हाल sSshdAuthPath:
		charptr = &options->sshd_auth_path;
		जाओ parse_filename;

	हाल sRefuseConnection:
		intptr = &options->refuse_connection;
		multistate_ptr = multistate_flag;
		जाओ parse_multistate;

	हाल sWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		जाओ parse_multistate;

	हाल sDeprecated:
	हाल sIgnore:
	हाल sUnsupported:
		do_log2(opcode == sIgnore ?
		    SYSLOG_LEVEL_DEBUG2 : SYSLOG_LEVEL_INFO,
		    "%s line %d: %s option %s", filename, linenum,
		    opcode == sUnsupported ? "Unsupported" : "Deprecated",
		    keyword);
		argv_consume(&ac);
		अवरोध;

	शेष:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, keyword, opcode);
	}
	/* Check that there is no garbage at end of line. */
	अगर (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		जाओ out;
	}

	/* success */
	ret = 0;
 out:
	opt_array_free2(strs, शून्य, nstrs);
	argv_free(oav, oac);
	वापस ret;
}

पूर्णांक
process_server_config_पंक्ति(ServerOptions *options, अक्षर *पंक्ति,
    स्थिर अक्षर *filename, पूर्णांक linenum, पूर्णांक *activep,
    काष्ठा connection_info *connectinfo, काष्ठा include_list *includes)
{
	पूर्णांक inc_flags = 0;

	वापस process_server_config_पंक्ति_depth(options, पंक्ति, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

व्योम
load_server_config(स्थिर अक्षर *filename, काष्ठा sshbuf *conf)
{
	काष्ठा stat st;
	अक्षर *पंक्ति = शून्य, *cp;
	माप_प्रकार linesize = 0;
	खाता *f;
	पूर्णांक r;

	debug2_f("filename %s", filename);
	अगर ((f = ख_खोलो(filename, "r")) == शून्य) {
		लिखो_त्रुटि(filename);
		निकास(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	अगर (ख_स्थिति(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	जबतक (getline(&पंक्ति, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = पंक्ति + म_अखोज(पंक्ति, " \t\r");
		अगर ((r = sshbuf_put(conf, cp, म_माप(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	मुक्त(पंक्ति);
	अगर ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	ख_बंद(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

व्योम
parse_server_match_config(ServerOptions *options,
   काष्ठा include_list *includes, काष्ठा connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_set_server_options(options, &mo, 0);
	free_server_options(&mo);
}

पूर्णांक
parse_server_match_testspec(काष्ठा connection_info *ci, अक्षर *spec)
{
	अक्षर *p;
	स्थिर अक्षर *val;

	जबतक ((p = strsep(&spec, ",")) && *p != '\0') {
		अगर ((val = strprefix(p, "addr=", 0)) != शून्य) {
			ci->address = xstrdup(val);
		} अन्यथा अगर ((val = strprefix(p, "host=", 0)) != शून्य) {
			ci->host = xstrdup(val);
		} अन्यथा अगर ((val = strprefix(p, "user=", 0)) != शून्य) {
			ci->user = xstrdup(val);
		} अन्यथा अगर ((val = strprefix(p, "laddr=", 0)) != शून्य) {
			ci->laddress = xstrdup(val);
		} अन्यथा अगर ((val = strprefix(p, "rdomain=", 0)) != शून्य) {
			ci->rdomain = xstrdup(val);
		} अन्यथा अगर ((val = strprefix(p, "lport=", 0)) != शून्य) {
			ci->lport = a2port(val);
			अगर (ci->lport == -1) {
				ख_लिखो(मानक_त्रुटि, "Invalid port '%s' in test mode"
				    " specification %s\n", p+6, p);
				वापस -1;
			}
		} अन्यथा अगर (म_भेद(p, "invalid-user") == 0) {
			ci->user_invalid = 1;
		} अन्यथा {
			ख_लिखो(मानक_त्रुटि, "Invalid test mode specification %s\n",
			    p);
			वापस -1;
		}
	}
	वापस 0;
}

व्योम
servconf_merge_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, found;

	क्रम (i = 0; i < src->अंक_subsystems; i++) {
		found = 0;
		क्रम (j = 0; j < dst->अंक_subsystems; j++) {
			अगर (म_भेद(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				found = 1;
				अवरोध;
			}
		}
		अगर (found) {
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
		    dst->subsystem_name, dst->अंक_subsystems,
		    dst->अंक_subsystems + 1, माप(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->अंक_subsystems,
		    dst->अंक_subsystems + 1, माप(*dst->subsystem_command));
		dst->subsystem_args = xrecallocarray(
		    dst->subsystem_args, dst->अंक_subsystems,
		    dst->अंक_subsystems + 1, माप(*dst->subsystem_args));
		j = dst->अंक_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_args[j] = xstrdup(src->subsystem_args[i]);
	}
}

अटल पूर्णांक
serialise_s32(काष्ठा sshbuf *buf, पूर्णांक v)
{
	uint32_t uv;
	पूर्णांक r;

	uv = v < 0 ? (uint32_t)(-(v + 1)) + 1 : (uint32_t)v;
	अगर ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u32(buf, uv)) != 0)
		वापस r;
	वापस 0;
}

अटल पूर्णांक
serialise_s64(काष्ठा sshbuf *buf, int64_t v)
{
	uint64_t uv;
	पूर्णांक r;

	uv = v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
	अगर ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u64(buf, uv)) != 0)
		वापस r;
	वापस 0;
}

अटल पूर्णांक
serialise_mode(काष्ठा sshbuf *buf, mode_t v)
{
	u_int uv;

	अगर (v == (mode_t)-1)
		वापस serialise_s32(buf, -1);
	uv = (u_int)v;
	अगर ((mode_t)uv != v || uv > 0777)
		वापस SSH_ERR_INVALID_FORMAT;
	वापस serialise_s32(buf, (पूर्णांक)uv);
}

अटल पूर्णांक
serialise_double(काष्ठा sshbuf *buf, द्विगुन v)
{
	/*
	 * XXX this is no good for a wire encoding.
	 * It's fine for passing configurations via RPC, but it would
	 * be nicer to have an exact binary encoding here.
	 */
	वापस sshbuf_put(buf, &v, माप(v));
}

अटल पूर्णांक
serialise_nullable_string(काष्ठा sshbuf *buf, स्थिर अक्षर *s)
{
	पूर्णांक r;

	अगर ((r = sshbuf_put_u8(buf, s != शून्य)) != 0)
		वापस r;
	अगर (s == शून्य)
		वापस 0;
	वापस sshbuf_put_cstring(buf, s);
}

अटल पूर्णांक
serialise_nullable_string_array(काष्ठा sshbuf *buf, अक्षर **a, u_int n)
{
	पूर्णांक r;
	u_int i;

	अगर ((r = sshbuf_put_u32(buf, n)) != 0)
		वापस r;
	क्रम (i = 0; i < n; i++) {
		अगर ((r = serialise_nullable_string(buf, a[i])) != 0)
			वापस r;
	}
	वापस 0;
}

अटल पूर्णांक
serialise_hostkeyfile(स्थिर ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;
	u_int i;

	अगर ((r = sshbuf_put_u32(buf, options->अंक_host_कुंजी_files)) != 0) {
		error_fr(r, "serialise length");
		वापस r;
	}
	क्रम (i = 0; i < options->अंक_host_कुंजी_files; i++) {
		अगर ((r = serialise_s32(buf,
		    options->host_कुंजी_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_कुंजी_files[i])) != 0) {
			error_fr(r, "serialise member");
			वापस r;
		}
	}
	वापस 0;
}

अटल पूर्णांक
serialise_ipqos(स्थिर ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = serialise_s32(buf, options->ip_qos_interactive)) != 0 ||
	    (r = serialise_s32(buf, options->ip_qos_bulk)) != 0) {
		error_fr(r, "serialise");
		वापस r;
	}

	वापस 0;
}

अटल पूर्णांक
serialise_listenaddress(स्थिर ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;
	u_int i;

	/* Note: only serialises queued listen addresses */
	अगर ((r = sshbuf_put_u32(buf, options->अंक_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		वापस r;
	}
	क्रम (i = 0; i < options->अंक_queued_listens; i++) {
		स्थिर काष्ठा queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		अगर ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->port)) != 0 ||
		    (r = serialise_nullable_string(buf, qla->rdomain)) != 0) {
			error_fr(r, "serialise member");
			वापस r;
		}
	}
	वापस 0;
}

अटल पूर्णांक
serialise_logfacility(स्थिर ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = serialise_s32(buf, (पूर्णांक)options->log_facility)) != 0) {
		error_fr(r, "serialise");
		वापस r;
	}

	वापस 0;
}

अटल पूर्णांक
serialise_loglevel(स्थिर ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = serialise_s32(buf, (पूर्णांक)options->log_level)) != 0) {
		error_fr(r, "serialise");
		वापस r;
	}

	वापस 0;
}

अटल पूर्णांक
serialise_port(स्थिर ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;
	u_int i;

	अगर ((r = sshbuf_put_u32(buf, options->अंक_ports)) != 0) {
		error_fr(r, "serialise length");
		वापस r;
	}
	क्रम (i = 0; i < options->अंक_ports; i++) {
		अगर ((r = serialise_s32(buf, options->ports[i])) != 0) {
			error_fr(r, "serialise port");
			वापस r;
		}
	}
	वापस 0;
}

अटल पूर्णांक
serialise_gatewayports(स्थिर ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = serialise_s32(buf, options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "serialise");
		वापस r;
	}
	वापस 0;
}

अटल पूर्णांक
serialise_streamlocalbindmask(स्थिर ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = serialise_mode(buf,
	    options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "serialise");
		वापस r;
	}
	वापस 0;
}

अटल पूर्णांक
serialise_streamlocalbindunlink(स्थिर ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = sshbuf_put_u8(buf,
	    (options->fwd_opts.streamlocal_bind_unlink != 0))) != 0) {
		error_fr(r, "serialise");
		वापस r;
	}
	वापस 0;
}

अटल पूर्णांक
serialise_maxstartups(स्थिर ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = serialise_s32(buf, options->max_startups_begin)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups_rate)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups)) != 0) {
		error_fr(r, "serialise");
		वापस r;
	}

	वापस 0;
}

अटल पूर्णांक
serialise_permituserenv(स्थिर ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = serialise_s32(buf, options->permit_user_env)) != 0 ||
	    (r = serialise_nullable_string(buf,
	    options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "serialise");
		वापस r;
	}

	वापस 0;
}

अटल पूर्णांक
serialise_persourcenetblocksize(स्थिर ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = serialise_s32(buf, options->per_source_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		वापस r;
	}

	वापस 0;
}

अटल पूर्णांक
serialise_persourcepenalties(स्थिर ServerOptions *options, काष्ठा sshbuf *buf)
{
	स्थिर काष्ठा per_source_penalty *psp = &options->per_source_penalty;
	पूर्णांक r;

	अगर ((r = serialise_s32(buf, psp->enabled)) != 0 ||
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
		वापस r;
	}

	वापस 0;
}

अटल पूर्णांक
serialise_rekeylimit(स्थिर ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = serialise_s64(buf, options->rekey_limit)) != 0 ||
	    (r = serialise_s32(buf, options->rekey_interval)) != 0) {
		error_fr(r, "serialise");
		वापस r;
	}

	वापस 0;
}

अटल पूर्णांक
serialise_subsystem(स्थिर ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;
	u_int i;

	अगर ((r = sshbuf_put_u32(buf, options->अंक_subsystems)) != 0) {
		error_fr(r, "serialise length");
		वापस r;
	}
	क्रम (i = 0; i < options->अंक_subsystems; i++) {
		अगर ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_args[i])) != 0) {
			error_fr(r, "serialise member");
			वापस r;
		}
	}
	वापस 0;
}

अटल पूर्णांक
serialise_pubkey_auth_options(स्थिर ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = serialise_s32(buf, options->pubkey_auth_options)) != 0 ||
	    (r = serialise_s32(buf, options->max_pubkey_ok)) != 0) {
		error_fr(r, "serialise");
		वापस r;
	}
	वापस 0;
}

अटल पूर्णांक
serialise_timingsecret(स्थिर ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = sshbuf_put_u64(buf, options->timing_secret)) != 0) {
		error_fr(r, "serialise");
		वापस r;
	}
	वापस 0;
}


पूर्णांक
serialise_server_options(स्थिर ServerOptions *options, काष्ठा sshbuf **bufp)
{
	काष्ठा sshbuf *buf = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	*bufp = शून्य;

	अगर ((buf = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_VERSION)) != 0) {
		error_fr(r, "serialise version");
		जाओ out;
	}

#घोषणा SSHCONF_INT(var, conf, flags, ms, def, cp) \
	अगर ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		जाओ out; \
	}
#घोषणा SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	अगर ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		जाओ out; \
	}
#घोषणा SSHCONF_STRING(var, conf, flags, cp) \
	अगर ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		जाओ out; \
	}
#घोषणा SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	अगर ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		जाओ out; \
	}
#घोषणा SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	अगर ((r = serialise_##funcsuffix(options, buf)) != 0) \
		जाओ out;
#घोषणा SSHCONF_NONCONF(funcsuffix) \
	अगर ((r = serialise_##funcsuffix(options, buf)) != 0) \
		जाओ out;
#घोषणा SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#घोषणा SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/* empty */
#घोषणा SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/* empty */
#घोषणा SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

#अघोषित SSHCONF_INT
#अघोषित SSHCONF_INTFLAG
#अघोषित SSHCONF_STRING
#अघोषित SSHCONF_STRARRAY
#अघोषित SSHCONF_CUSTOM
#अघोषित SSHCONF_NONCONF
#अघोषित SSHCONF_DEPRECATE
#अघोषित SSHCONF_UNSUPPORTED_INT
#अघोषित SSHCONF_UNSUPPORTED_STRING
#अघोषित SSHCONF_ALIAS

	/* success */
	r = 0;
	*bufp = buf;
	buf = शून्य; /* transferred */
 out:
	sshbuf_free(buf);
	वापस r;
}

अटल पूर्णांक
deserialise_s32(काष्ठा sshbuf *buf, पूर्णांक *v)
{
	uint32_t tmp;
	पूर्णांक r;
	u_char was_signed;

	अगर ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u32(buf, &tmp)) != 0)
		वापस r;
	अगर (was_signed > 1)
		वापस SSH_ERR_INVALID_FORMAT;
	अगर (was_signed) {
		अगर (tmp > (uint32_t)पूर्णांक_उच्च + 1)
			वापस SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)पूर्णांक_उच्च + 1 ? पूर्णांक_न्यून : -(पूर्णांक)tmp;
	} अन्यथा {
		अगर (tmp > पूर्णांक_उच्च)
			वापस SSH_ERR_INVALID_FORMAT;
		*v = (पूर्णांक)tmp;
	}
	वापस 0;
}

अटल पूर्णांक
deserialise_s64(काष्ठा sshbuf *buf, int64_t *v)
{
	uint64_t tmp;
	पूर्णांक r;
	u_char was_signed;

	अगर ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u64(buf, &tmp)) != 0)
		वापस r;
	अगर (was_signed > 1)
		वापस SSH_ERR_INVALID_FORMAT;
	अगर (was_signed) {
		अगर (tmp > (uint64_t)INT64_MAX + 1)
			वापस SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint64_t)INT64_MAX + 1 ?
		    INT64_MIN : -(int64_t)tmp;
	} अन्यथा {
		अगर (tmp > INT64_MAX)
			वापस SSH_ERR_INVALID_FORMAT;
		*v = (int64_t)tmp;
	}
	वापस 0;
}

अटल पूर्णांक
deserialise_mode(काष्ठा sshbuf *buf, mode_t *v)
{
	पूर्णांक r, tmp;

	अगर ((r = deserialise_s32(buf, &tmp)) != 0)
		वापस r;
	अगर (tmp == -1) {
		*v = (mode_t)-1;
		वापस 0;
	}
	अगर (tmp < 0 || tmp > 0777)
		वापस SSH_ERR_INVALID_FORMAT;
	*v = (mode_t)tmp;
	वापस 0;
}

अटल पूर्णांक
deserialise_double(काष्ठा sshbuf *buf, द्विगुन *v)
{
	वापस sshbuf_get(buf, v, माप(*v));
}

अटल पूर्णांक
deserialise_nullable_string(काष्ठा sshbuf *buf, अक्षर **sp)
{
	पूर्णांक r;
	u_char present;

	अगर ((r = sshbuf_get_u8(buf, &present)) != 0)
		वापस r;
	अगर (present == 0) {
		*sp = शून्य;
		वापस 0;
	}
	अगर (present != 1)
		वापस SSH_ERR_INVALID_FORMAT;
	वापस sshbuf_get_cstring(buf, sp, शून्य);
}

अटल व्योम
free_string_array(अक्षर **a, u_int n)
{
	u_int i;

	अगर (a == शून्य)
		वापस;
	क्रम (i = 0; i < n; i++)
		मुक्त(a[i]);
	मुक्त(a);
}

अटल पूर्णांक
deserialise_गिनती(काष्ठा sshbuf *buf, u_int *np, स्थिर अक्षर *what)
{
	पूर्णांक r;
	uint32_t n;

	अगर ((r = sshbuf_get_u32(buf, &n)) != 0) {
		error_fr(r, "deserialise %s length", what);
		वापस r;
	}
	अगर (n > अच_पूर्णांक_उच्च) {
		error_f("bad number of %s", what);
		वापस SSH_ERR_INVALID_FORMAT;
	}
	अगर (n > sshbuf_len(buf)) {
		error_f("bad number of %s", what);
		वापस SSH_ERR_INVALID_FORMAT;
	}
	*np = n;
	वापस 0;
}

अटल पूर्णांक
deserialise_nullable_string_array(काष्ठा sshbuf *buf, अक्षर ***arrayp,
    u_int *np)
{
	अक्षर **a = शून्य;
	पूर्णांक r;
	u_int i, n;

	*arrayp = शून्य;
	*np = 0;
	अगर ((r = deserialise_गिनती(buf, &n, "strings")) != 0)
		वापस r;
	अगर (n > 0)
		a = xcalloc(n, माप(*a));
	क्रम (i = 0; i < n; i++) {
		अगर ((r = deserialise_nullable_string(buf, a + i)) != 0) {
			free_string_array(a, i + 1);
			वापस r;
		}
	}
	*arrayp = a;
	*np = n;
	वापस 0;
}

अटल व्योम
free_queued_listen_addrs(काष्ठा queued_listenaddr *qla, u_int n)
{
	u_int i;

	अगर (qla == शून्य)
		वापस;
	क्रम (i = 0; i < n; i++) {
		मुक्त(qla[i].addr);
		मुक्त(qla[i].rdomain);
	}
	मुक्त(qla);
}

अटल पूर्णांक
deserialise_hostkeyfile(ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r, *userprovided = शून्य;
	u_int i, n;
	अक्षर **files = शून्य;

	अगर ((r = deserialise_गिनती(buf, &n, "host key files")) != 0)
		वापस r;
	अगर (n > 0) {
		userprovided = xcalloc(n, माप(*userprovided));
		files = xcalloc(n, माप(*files));
	}
	क्रम (i = 0; i < n; i++) {
		अगर ((r = deserialise_s32(buf, userprovided + i)) != 0 ||
		    (r = deserialise_nullable_string(buf, files + i)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(files, i + 1);
			मुक्त(userprovided);
			वापस r;
		}
	}
	options->अंक_host_कुंजी_files = n;
	options->host_कुंजी_file_userprovided = userprovided;
	options->host_कुंजी_files = files;
	वापस 0;
}

अटल पूर्णांक
deserialise_ipqos(ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = deserialise_s32(buf, &options->ip_qos_interactive)) != 0 ||
	    (r = deserialise_s32(buf, &options->ip_qos_bulk)) != 0) {
		error_fr(r, "deserialise");
		वापस r;
	}

	वापस 0;
}

अटल पूर्णांक
deserialise_listenaddress(ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;
	u_int i, n;
	काष्ठा queued_listenaddr *qla = शून्य;

	अगर ((r = deserialise_गिनती(buf, &n, "listen addresses")) != 0)
		वापस r;
	अगर (n > 0)
		qla = xcalloc(n, माप(*qla));
	क्रम (i = 0; i < n; i++) {
		अगर ((r = sshbuf_get_cstring(buf, &qla[i].addr, शून्य)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].port)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			वापस r;
		}
	}
	options->अंक_queued_listens = n;
	options->queued_listen_addrs = qla;
	वापस 0;
}

अटल पूर्णांक
deserialise_logfacility(ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r, tmp;

	अगर ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		वापस r;
	}
	अगर (tmp != SYSLOG_FACILITY_NOT_SET &&
	    log_facility_name((SyslogFacility)tmp) == शून्य) {
		error_f("bad syslog facility");
		वापस SSH_ERR_INVALID_FORMAT;
	}
	options->log_facility = (SyslogFacility)tmp;

	वापस 0;
}

अटल पूर्णांक
deserialise_loglevel(ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r, tmp;

	अगर ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		वापस r;
	}
	अगर (tmp != SYSLOG_LEVEL_NOT_SET &&
	    log_level_name((LogLevel)tmp) == शून्य) {
		error_f("bad log level");
		वापस SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	वापस 0;
}

अटल पूर्णांक
deserialise_port(ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;
	u_int i, n;

	अगर ((r = deserialise_गिनती(buf, &n, "ports")) != 0)
		वापस r;
	अगर (n > MAX_PORTS) {
		error_f("bad number of ports");
		वापस SSH_ERR_INVALID_FORMAT;
	}
	options->अंक_ports = n;
	स_रखो(options->ports, 0, माप(options->ports));
	क्रम (i = 0; i < options->अंक_ports; i++) {
		अगर ((r = deserialise_s32(buf, options->ports + i)) != 0) {
			error_fr(r, "deserialise port");
			वापस r;
		}
	}
	वापस 0;
}

अटल पूर्णांक
deserialise_gatewayports(ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = deserialise_s32(buf, &options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "deserialise");
		वापस r;
	}
	वापस 0;
}

अटल पूर्णांक
deserialise_streamlocalbindmask(ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = deserialise_mode(buf,
	    &options->fwd_opts.streamlocal_bind_mask)) != 0) {
		error_fr(r, "deserialise");
		वापस r;
	}
	वापस 0;
}

अटल पूर्णांक
deserialise_streamlocalbindunlink(ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;
	u_char tmp;

	अगर ((r = sshbuf_get_u8(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		वापस r;
	}
	अगर (tmp > 1) {
		error_f("bad boolean");
		वापस SSH_ERR_INVALID_FORMAT;
	}
	options->fwd_opts.streamlocal_bind_unlink = tmp;
	वापस 0;
}

अटल पूर्णांक
deserialise_maxstartups(ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = deserialise_s32(buf, &options->max_startups_begin)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups_rate)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups)) != 0) {
		error_fr(r, "deserialise");
		वापस r;
	}

	वापस 0;
}

अटल पूर्णांक
deserialise_permituserenv(ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = deserialise_s32(buf, &options->permit_user_env)) != 0 ||
	    (r = deserialise_nullable_string(buf,
	    &options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "deserialise");
		वापस r;
	}
	वापस 0;
}

अटल पूर्णांक
deserialise_persourcenetblocksize(ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->per_source_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		वापस r;
	}

	वापस 0;
}

अटल पूर्णांक
deserialise_persourcepenalties(ServerOptions *options, काष्ठा sshbuf *buf)
{
	काष्ठा per_source_penalty *psp = &options->per_source_penalty;
	पूर्णांक r;

	अगर ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
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
		वापस r;
	}

	वापस 0;
}

अटल पूर्णांक
deserialise_rekeylimit(ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = deserialise_s64(buf, &options->rekey_limit)) != 0 ||
	    (r = deserialise_s32(buf, &options->rekey_interval)) != 0) {
		error_fr(r, "deserialise");
		वापस r;
	}

	वापस 0;
}

अटल पूर्णांक
deserialise_subsystem(ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;
	u_int i, n;
	अक्षर **names = शून्य, **commands = शून्य, **args = शून्य;

	अगर ((r = deserialise_गिनती(buf, &n, "subsystems")) != 0)
		वापस r;
	अगर (n > 0) {
		names = xcalloc(n, माप(*names));
		commands = xcalloc(n, माप(*names));
		args = xcalloc(n, माप(*args));
	}
	क्रम (i = 0; i < n; i++) {
		अगर ((r = sshbuf_get_cstring(buf, names + i, शून्य)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, शून्य)) != 0 ||
		    (r = sshbuf_get_cstring(buf, args + i, शून्य)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(names, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(args, i + 1);
			वापस r;
		}
	}
	options->अंक_subsystems = n;
	options->subsystem_name = names;
	options->subsystem_command = commands;
	options->subsystem_args = args;
	वापस 0;
}

अटल पूर्णांक
deserialise_pubkey_auth_options(ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = deserialise_s32(buf, &options->pubkey_auth_options)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_pubkey_ok)) != 0) {
		error_fr(r, "deserialise");
		वापस r;
	}
	वापस 0;
}

अटल पूर्णांक
deserialise_timingsecret(ServerOptions *options, काष्ठा sshbuf *buf)
{
	पूर्णांक r;

	अगर ((r = sshbuf_get_u64(buf, &options->timing_secret)) != 0) {
		error_fr(r, "deserialise");
		वापस r;
	}
	वापस 0;
}

पूर्णांक
deserialise_server_options(काष्ठा sshbuf *buf, ServerOptions *options)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	uint32_t version;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	अगर ((r = sshbuf_get_u32(buf, &version)) != 0) {
		error_fr(r, "deserialise version");
		जाओ out;
	}
	अगर (version != SSHD_CONFIG_BLOB_VERSION) {
		error_f("unsupported config blob version %u", version);
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
#घोषणा SSHCONF_INT(var, conf, flags, ms, def, cp) \
	अगर ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		जाओ out; \
	}
#घोषणा SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	अगर ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		जाओ out; \
	}
#घोषणा SSHCONF_STRING(var, conf, flags, cp) \
	अगर ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		जाओ out; \
	}
#घोषणा SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	अगर ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		जाओ out; \
	}
#घोषणा SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	अगर ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		जाओ out;
#घोषणा SSHCONF_NONCONF(funcsuffix) \
	अगर ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		जाओ out;
#घोषणा SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#घोषणा SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#घोषणा SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	करो { \
		मुक्त(new_options.var); \
		new_options.var = शून्य; \
	} जबतक (0);
#घोषणा SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

	अगर (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}

#अघोषित SSHCONF_INT
#अघोषित SSHCONF_INTFLAG
#अघोषित SSHCONF_STRING
#अघोषित SSHCONF_STRARRAY
#अघोषित SSHCONF_CUSTOM
#अघोषित SSHCONF_NONCONF
#अघोषित SSHCONF_DEPRECATE
#अघोषित SSHCONF_UNSUPPORTED_INT
#अघोषित SSHCONF_UNSUPPORTED_STRING
#अघोषित SSHCONF_ALIAS

	/* success */
	r = 0;
	free_server_options(options);
	*options = new_options;
	स_रखो(&new_options, 0, माप(new_options));
 out:
	free_server_options(&new_options);
	वापस r;
}

अटल व्योम
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	क्रम (i = 0; i < options->अंक_host_कुंजी_files; i++)
		मुक्त(options->host_कुंजी_files[i]);
	मुक्त(options->host_कुंजी_files);
	मुक्त(options->host_कुंजी_file_userprovided);
}

अटल व्योम
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->अंक_queued_listens);

	क्रम (i = 0; i < options->अंक_listen_addrs; i++) {
		मुक्त(options->listen_addrs[i].rdomain);
		अगर (options->listen_addrs[i].addrs != शून्य)
			freeaddrinfo(options->listen_addrs[i].addrs);
	}
	मुक्त(options->listen_addrs);
}

अटल व्योम
free_permituserenv(ServerOptions *options)
{
	मुक्त(options->permit_user_env_allowlist);
}

अटल व्योम
free_subsystem(ServerOptions *options)
{
	u_int i;

	क्रम (i = 0; i < options->अंक_subsystems; i++) {
		मुक्त(options->subsystem_name[i]);
		मुक्त(options->subsystem_command[i]);
		मुक्त(options->subsystem_args[i]);
	}
	मुक्त(options->subsystem_name);
	मुक्त(options->subsystem_command);
	मुक्त(options->subsystem_args);
}

व्योम
free_server_options(ServerOptions *options)
{
#घोषणा SSHCONF_INT(var, conf, flags, ms, def, cp)	/* empty */
#घोषणा SSHCONF_INTFLAG(var, conf, flags, def, cp)	/* empty */
#घोषणा SSHCONF_STRING(var, conf, flags, cp)		मुक्त(options->var);
#घोषणा SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#घोषणा SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#घोषणा SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#घोषणा SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#घोषणा SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#घोषणा SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	करो { \
		मुक्त(options->var); \
		options->var = शून्य; \
	} जबतक (0);
#घोषणा SSHCONF_ALIAS(old, conf, flags)			/* empty */

#घोषणा free_ipqos(options)
#घोषणा free_logfacility(options)
#घोषणा free_loglevel(options)
#घोषणा free_port(options)
#घोषणा free_gatewayports(options)
#घोषणा free_streamlocalbindmask(options)
#घोषणा free_streamlocalbindunlink(options)
#घोषणा free_maxstartups(options)
#घोषणा free_persourcenetblocksize(options)
#घोषणा free_persourcepenalties(options)
#घोषणा free_rekeylimit(options)
#घोषणा free_pubkey_auth_options(options)
#घोषणा free_timingsecret(options)

	SSHD_CONFIG_ENTRIES

#अघोषित free_ipqos
#अघोषित free_logfacility
#अघोषित free_loglevel
#अघोषित free_port
#अघोषित free_gatewayports
#अघोषित free_streamlocalbindmask
#अघोषित free_streamlocalbindunlink
#अघोषित free_maxstartups
#अघोषित free_persourcenetblocksize
#अघोषित free_persourcepenalties
#अघोषित free_rekeylimit
#अघोषित free_timingsecret

#अघोषित SSHCONF_INT
#अघोषित SSHCONF_INTFLAG
#अघोषित SSHCONF_STRING
#अघोषित SSHCONF_STRARRAY
#अघोषित SSHCONF_CUSTOM
#अघोषित SSHCONF_NONCONF
#अघोषित SSHCONF_DEPRECATE
#अघोषित SSHCONF_UNSUPPORTED_INT
#अघोषित SSHCONF_UNSUPPORTED_STRING
#अघोषित SSHCONF_ALIAS

	initialize_server_options(options);
}

अटल व्योम
copy_server_option_int(पूर्णांक *dst, पूर्णांक src)
{
	अगर (src != -1)
		*dst = src;
}

अटल व्योम
copy_server_option_int64(int64_t *dst, int64_t src)
{
	अगर (src != -1)
		*dst = src;
}

अटल व्योम
copy_server_option_string(अक्षर **dst, स्थिर अक्षर *src)
{
	अगर (src != शून्य && *dst != src) {
		मुक्त(*dst);
		*dst = xstrdup(src);
	}
}

अटल व्योम
copy_server_option_strarray_मूल्यावली(अक्षर ***dst, u_int ndst,
    अक्षर * स्थिर *src, u_int nsrc)
{
	u_int i;

	अगर (nsrc == 0)
		वापस;
	क्रम (i = 0; i < ndst; i++)
		मुक्त((*dst)[i]);
	मुक्त(*dst);
	*dst = xcalloc(nsrc, माप(**dst));
	क्रम (i = 0; i < nsrc; i++)
		(*dst)[i] = src[i] == शून्य ? शून्य : xstrdup(src[i]);
}

अटल व्योम
copy_server_option_strarray(अक्षर ***dst, u_int *ndst,
    अक्षर * स्थिर *src, u_int nsrc)
{
	अगर (nsrc == 0)
		वापस;
	copy_server_option_strarray_मूल्यावली(dst, *ndst, src, nsrc);
	*ndst = nsrc;
}

अटल व्योम
copy_ipqos(ServerOptions *dst, स्थिर ServerOptions *src)
{
	copy_server_option_int(&dst->ip_qos_interactive,
	    src->ip_qos_interactive);
	copy_server_option_int(&dst->ip_qos_bulk, src->ip_qos_bulk);
}

अटल व्योम
copy_gatewayports(ServerOptions *dst, स्थिर ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.gateway_ports,
	    src->fwd_opts.gateway_ports);
}

अटल व्योम
copy_streamlocalbindunlink(ServerOptions *dst, स्थिर ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.streamlocal_bind_unlink,
	    src->fwd_opts.streamlocal_bind_unlink);
}

अटल व्योम
copy_loglevel(ServerOptions *dst, स्थिर ServerOptions *src)
{
	अगर (src->log_level != -1)
		dst->log_level = src->log_level;
}

अटल व्योम
copy_rekeylimit(ServerOptions *dst, स्थिर ServerOptions *src)
{
	copy_server_option_int64(&dst->rekey_limit, src->rekey_limit);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

अटल व्योम
copy_subsystem(ServerOptions *dst, स्थिर ServerOptions *src)
{
	u_int old_अंक_subsystems = dst->अंक_subsystems;

	अगर (src->अंक_subsystems == 0)
		वापस;
	copy_server_option_strarray_मूल्यावली(&dst->subsystem_name,
	    old_अंक_subsystems, src->subsystem_name, src->अंक_subsystems);
	copy_server_option_strarray_मूल्यावली(&dst->subsystem_command,
	    old_अंक_subsystems, src->subsystem_command, src->अंक_subsystems);
	copy_server_option_strarray_मूल्यावली(&dst->subsystem_args,
	    old_अंक_subsystems, src->subsystem_args, src->अंक_subsystems);
	dst->अंक_subsystems = src->अंक_subsystems;
}

अटल व्योम
copy_pubkey_auth_options(ServerOptions *dst, स्थिर ServerOptions *src)
{
	अगर (src->pubkey_auth_options != -1) {
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
व्योम
copy_set_server_options(ServerOptions *dst, ServerOptions *src, पूर्णांक preauth)
{
	अगर (dst == src)
		वापस;

#घोषणा SSHCONF_INT(var, conf, flags, ms, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#घोषणा SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#घोषणा SSHCONF_STRING(var, conf, flags, cp) \
	cp(copy_server_option_string(&dst->var, src->var);)
#घोषणा SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	cp(copy_server_option_strarray(&dst->var, &dst->nvar, \
	    src->var, src->nvar);)
#घोषणा SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	cp(copy_##funcsuffix(dst, src);)
#घोषणा SSHCONF_NONCONF(funcsuffix)			/* empty */
#घोषणा SSHCONF_DEPRECATE(conf, flags, opcode)		/* empty */
#घोषणा SSHCONF_UNSUPPORTED_INT(var, conf, flags)	dst->var = 0;
#घोषणा SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	करो { \
		मुक्त(dst->var); \
		dst->var = शून्य; \
	} जबतक (0);
#घोषणा SSHCONF_ALIAS(old, conf, flags)			/* empty */

	SSHD_CONFIG_ENTRIES

#अघोषित SSHCONF_INT
#अघोषित SSHCONF_INTFLAG
#अघोषित SSHCONF_STRING
#अघोषित SSHCONF_STRARRAY
#अघोषित SSHCONF_CUSTOM
#अघोषित SSHCONF_NONCONF
#अघोषित SSHCONF_DEPRECATE
#अघोषित SSHCONF_UNSUPPORTED_INT
#अघोषित SSHCONF_UNSUPPORTED_STRING
#अघोषित SSHCONF_ALIAS

	/*
	 * The bind_mask is a mode_t that may be unsigned, so we can't use
	 * copy_server_option_int - it does a signed comparison that causes
	 * compiler warnings.
	 */
	अगर (src->fwd_opts.streamlocal_bind_mask != (mode_t)-1) {
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
#घोषणा CLEAR_ON_NONE(v) \
	करो { \
		अगर (option_clear_or_none(v)) { \
			मुक्त(v); \
			v = शून्य; \
		} \
	} जबतक(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_कुंजियाँ);
	CLEAR_ON_NONE(dst->banner);

	/*
	 * The only things that should be below this point are string options
	 * which are only used after authentication.
	 */
	अगर (preauth)
		वापस;

	/* These options may be "none" to clear a global setting */
	copy_server_option_string(&dst->adm_forced_command,
	    src->adm_forced_command);
	copy_server_option_string(&dst->chroot_directory,
	    src->chroot_directory);
	CLEAR_ON_NONE(dst->chroot_directory);
	CLEAR_ON_NONE(dst->adm_forced_command);
#अघोषित CLEAR_ON_NONE

	/* Subsystems require merging. */
	servconf_merge_subsystems(dst, src);
}

#घोषणा SERVCONF_MAX_DEPTH	16
अटल व्योम
parse_server_config_depth(ServerOptions *options, स्थिर अक्षर *filename,
    काष्ठा sshbuf *conf, काष्ठा include_list *includes,
    काष्ठा connection_info *connectinfo, पूर्णांक flags, पूर्णांक *activep, पूर्णांक depth)
{
	पूर्णांक linenum, bad_options = 0;
	अक्षर *cp, *obuf, *cbuf;

	अगर (depth < 0 || depth > SERVCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	अगर ((obuf = cbuf = sshbuf_dup_string(conf)) == शून्य)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	जबतक ((cp = strsep(&cbuf, "\n")) != शून्य) {
		अगर (process_server_config_पंक्ति_depth(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    depth, includes) != 0)
			bad_options++;
	}
	मुक्त(obuf);
	अगर (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

व्योम
parse_server_config(ServerOptions *options, स्थिर अक्षर *filename,
    काष्ठा sshbuf *conf, काष्ठा include_list *includes,
    काष्ठा connection_info *connectinfo, पूर्णांक reexec)
{
	पूर्णांक active = connectinfo ? 0 : 1;
	parse_server_config_depth(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_MATCH_ONLY : 0), &active, 0);
	अगर (!reexec)
		process_queued_listen_addrs(options);
}

अटल स्थिर अक्षर *
fmt_multistate_int(पूर्णांक val, स्थिर काष्ठा multistate *m)
{
	u_int i;

	क्रम (i = 0; m[i].कुंजी != शून्य; i++) {
		अगर (m[i].मूल्य == val)
			वापस m[i].कुंजी;
	}
	वापस "UNKNOWN";
}

अटल स्थिर अक्षर *
fmt_intarg(ServerOpCodes code, पूर्णांक val)
{
	अगर (val == -1)
		वापस "unset";
	चयन (code) {
	हाल sAddressFamily:
		वापस fmt_multistate_int(val, multistate_addressfamily);
	हाल s_Permit_मूल_Login:
		वापस fmt_multistate_int(val, multistate_permitrootlogin);
	हाल sGatewayPorts:
		वापस fmt_multistate_int(val, multistate_gatewayports);
	हाल sCompression:
		वापस fmt_multistate_int(val, multistate_compression);
	हाल sAllowTcpForwarding:
		वापस fmt_multistate_int(val, multistate_tcpfwd);
	हाल sAllowStreamLocalForwarding:
		वापस fmt_multistate_int(val, multistate_tcpfwd);
	हाल sIgnoreRhosts:
		वापस fmt_multistate_int(val, multistate_ignore_rhosts);
	हाल sTCPKeepAlive:
		वापस fmt_multistate_int(val, multistate_keepalives);
	हाल sWarnWeakCrypto:
		वापस fmt_multistate_int(val, multistate_warnweakcrypto);
	हाल sFingerprintHash:
		वापस ssh_digest_alg_name(val);
	शेष:
		चयन (val) {
		हाल 0:
			वापस "no";
		हाल 1:
			वापस "yes";
		शेष:
			वापस "UNKNOWN";
		}
	}
}

अटल व्योम
dump_cfg_int(ServerOpCodes code, पूर्णांक val)
{
	अगर (code == sUnusedConnectionTimeout && val == 0) {
		म_लिखो("%s none\n", lookup_opcode_name(code));
		वापस;
	}
	म_लिखो("%s %d\n", lookup_opcode_name(code), val);
}

अटल व्योम
dump_cfg_oct(ServerOpCodes code, पूर्णांक val)
{
	म_लिखो("%s 0%o\n", lookup_opcode_name(code), val);
}

अटल व्योम
dump_cfg_fmtint(ServerOpCodes code, पूर्णांक val)
{
	म_लिखो("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

अटल व्योम
dump_cfg_string(ServerOpCodes code, स्थिर अक्षर *val)
{
	म_लिखो("%s %s\n", lookup_opcode_name(code),
	    val == शून्य ? "none" : val);
}

अटल व्योम
dump_cfg_strarray(ServerOpCodes code, u_int गिनती, अक्षर **vals)
{
	u_int i;

	क्रम (i = 0; i < गिनती; i++)
		म_लिखो("%s %s\n", lookup_opcode_name(code), vals[i]);
}

अटल व्योम
dump_cfg_strarray_oneline(ServerOpCodes code, u_int गिनती, अक्षर **vals)
{
	u_int i;

	चयन (code) {
	हाल sAuthenticationMethods:
	हाल sChannelTimeout:
		अवरोध;
	शेष:
		अगर (गिनती <= 0)
			वापस;
		अवरोध;
	}

	म_लिखो("%s", lookup_opcode_name(code));
	क्रम (i = 0; i < गिनती; i++)
		म_लिखो(" %s",  vals[i]);
	अगर (code == sAuthenticationMethods && गिनती == 0)
		म_लिखो(" any");
	अन्यथा अगर (code == sChannelTimeout && गिनती == 0)
		म_लिखो(" none");
	म_लिखो("\n");
}

अटल अक्षर *
format_listen_addrs(काष्ठा listenaddr *la)
{
	पूर्णांक r;
	काष्ठा addrinfo *ai;
	अक्षर addr[NI_MAXHOST], port[NI_MAXSERV];
	अक्षर *laddr1 = xstrdup(""), *laddr2 = शून्य;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	क्रम (ai = la->addrs; ai; ai = ai->ai_next) {
		अगर ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    माप(addr), port, माप(port),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			जारी;
		}
		laddr2 = laddr1;
		अगर (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == शून्य ? "" : " rdomain ",
			    la->rdomain == शून्य ? "" : la->rdomain,
			    laddr2);
		} अन्यथा {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, port,
			    la->rdomain == शून्य ? "" : " rdomain ",
			    la->rdomain == शून्य ? "" : la->rdomain,
			    laddr2);
		}
		मुक्त(laddr2);
	}
	वापस laddr1;
}

व्योम
dump_config(ServerOptions *o)
{
	अक्षर *s;
	u_int i;

	/* these are usually at the top of the config */
	क्रम (i = 0; i < o->अंक_ports; i++)
		म_लिखो("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(sAddressFamily, o->address_family);

	क्रम (i = 0; i < o->अंक_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		म_लिखो("%s", s);
		मुक्त(s);
	}

	/* integer arguments */
#अगर_घोषित USE_PAM
	dump_cfg_fmtint(sUsePAM, o->use_pam);
	dump_cfg_string(sPAMServiceName, o->pam_service_name);
#पूर्ण_अगर
	dump_cfg_int(sLoginGraceTime, o->login_grace_time);
	dump_cfg_int(sX11DisplayOffset, o->x11_display_offset);
	dump_cfg_int(sMaxAuthTries, o->max_authtries);
	dump_cfg_int(sMaxSessions, o->max_sessions);
	dump_cfg_int(sClientAliveInterval, o->client_alive_interval);
	dump_cfg_int(s_Client_Alive_गिनती_Max, o->client_alive_गिनती_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_आकार);
	dump_cfg_oct(sStreamLocalBindMask, o->fwd_opts.streamlocal_bind_mask);
	dump_cfg_int(sUnusedConnectionTimeout, o->unused_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(s_Permit_मूल_Login, o->permit_मूल_login);
	dump_cfg_fmtint(sIgnoreRhosts, o->ignore_rhosts);
	dump_cfg_fmtint(sIgnoreUserKnownHosts, o->ignore_user_known_hosts);
	dump_cfg_fmtint(sHostbasedAuthentication, o->hostbased_authentication);
	dump_cfg_fmtint(sHostbasedUsesNameFromPacketOnly,
	    o->hostbased_uses_name_from_packet_only);
	dump_cfg_fmtint(sPubkeyAuthentication, o->pubkey_authentication);
#अगर_घोषित KRB5
	dump_cfg_fmtint(sKerberosAuthentication, o->kerberos_authentication);
	dump_cfg_fmtint(sKerberosOrLocalPasswd, o->kerberos_or_local_passwd);
	dump_cfg_fmtint(sKerberosTicketCleanup, o->kerberos_ticket_cleanup);
# ifdef USE_AFS
	dump_cfg_fmtint(sKerberosGetAFSToken, o->kerberos_get_afs_token);
# endif
#पूर्ण_अगर
#अगर_घोषित GSSAPI
	dump_cfg_fmtint(sGSSAPIAuthentication, o->gss_authentication);
	dump_cfg_fmtint(sGSSAPICleanupCredentials, o->gss_cleanup_creds);
	dump_cfg_fmtint(sGSSAPIDelegateCredentials, o->gss_deleg_creds);
	dump_cfg_fmtint(sGSSAPIStrictAcceptorCheck, o->gss_strict_acceptor);
#पूर्ण_अगर
	dump_cfg_fmtint(sPasswordAuthentication, o->password_authentication);
	dump_cfg_fmtint(sKbdInteractiveAuthentication,
	    o->kbd_interactive_authentication);
	dump_cfg_fmtint(sPrintMotd, o->print_motd);
#अगर_अघोषित DISABLE_LASTLOG
	dump_cfg_fmtint(sPrintLastLog, o->print_lastlog);
#पूर्ण_अगर
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
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_कुंजियाँ);
	dump_cfg_string(s_Security_कुंजी_Provider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(sVersionAddendum, *o->version_addendum == '\0'
	    ? "none" : o->version_addendum);
	dump_cfg_string(s_Authorized_कुंजियाँ_Command, o->authorized_कुंजियाँ_command);
	dump_cfg_string(s_Authorized_कुंजियाँ_Command_User, o->authorized_कुंजियाँ_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(s_Host_कुंजी_Agent, o->host_कुंजी_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(s_Host_कुंजी_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#अगर defined(__OpenBSD__) || defined(HAVE_SYS_SET_PROCESS_RDOMAIN)
	dump_cfg_string(sRDomain, o->routing_domain);
#पूर्ण_अगर
	dump_cfg_string(sSshdSessionPath, o->sshd_session_path);
	dump_cfg_string(sSshdAuthPath, o->sshd_auth_path);
	dump_cfg_string(sPerSourcePenaltyExemptList, o->per_source_penalty_exempt);
	dump_cfg_string(sAgentSocketPath, o->agent_socket_path);

	/* string arguments requiring a lookup */
	dump_cfg_string(sLogLevel, log_level_name(o->log_level));
	dump_cfg_string(sSyslogFacility, log_facility_name(o->log_facility));

	/* string array arguments */
	dump_cfg_strarray_oneline(s_Authorized_कुंजियाँ_File, o->अंक_authkeys_files,
	    o->authorized_कुंजियाँ_files);
	dump_cfg_strarray_oneline(s_Revoked_कुंजियाँ, o->अंक_revoked_कुंजियाँ_files,
	    o->revoked_कुंजियाँ_files);
	dump_cfg_strarray(s_Host_कुंजी, o->अंक_host_कुंजी_files, o->host_कुंजी_files);
	dump_cfg_strarray(sHostCertificate, o->अंक_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->अंक_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->अंक_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->अंक_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->अंक_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->अंक_accept_env, o->accept_env);
	dump_cfg_strarray(sSetEnv, o->अंक_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->अंक_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->अंक_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->अंक_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	क्रम (i = 0; i < o->अंक_subsystems; i++)
		म_लिखो("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_args[i]);

	म_लिखो("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_rate, o->max_startups);
	म_लिखो("PerSourceMaxStartups ");
	अगर (o->per_source_max_startups == पूर्णांक_उच्च)
		म_लिखो("none\n");
	अन्यथा
		म_लिखो("%d\n", o->per_source_max_startups);
	म_लिखो("PerSourceNetBlockSize %d:%d\n", o->per_source_masklen_ipv4,
	    o->per_source_masklen_ipv6);

	s = शून्य;
	क्रम (i = 0; tunmode_desc[i].val != -1; i++) {
		अगर (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].text;
			अवरोध;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	म_लिखो("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	म_लिखो("%s\n", iptos2str(o->ip_qos_bulk));

	म_लिखो("RekeyLimit %llu %d\n", (अचिन्हित दीर्घ दीर्घ)o->rekey_limit,
	    o->rekey_interval);

	म_लिखो("PermitOpen");
	अगर (o->अंक_permitted_opens == 0)
		म_लिखो(" any");
	अन्यथा {
		क्रम (i = 0; i < o->अंक_permitted_opens; i++)
			म_लिखो(" %s", o->permitted_opens[i]);
	}
	म_लिखो("\n");
	म_लिखो("PermitListen");
	अगर (o->अंक_permitted_listens == 0)
		म_लिखो(" any");
	अन्यथा {
		क्रम (i = 0; i < o->अंक_permitted_listens; i++)
			म_लिखो(" %s", o->permitted_listens[i]);
	}
	म_लिखो("\n");

	अगर (o->permit_user_env_allowlist == शून्य) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} अन्यथा {
		म_लिखो("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	म_लिखो("PubkeyAuthOptions");
	अगर (o->pubkey_auth_options == 0)
		म_लिखो(" none");
	अगर (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		म_लिखो(" touch-required");
	अगर (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		म_लिखो(" verify-required");
	अगर (o->max_pubkey_ok != -1)
		म_लिखो(" max-pk-ok:%d", o->max_pubkey_ok);
	म_लिखो("\n");

	अगर (o->per_source_penalty.enabled) {
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
