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
#यदि_परिभाषितम् __OpenBSD__
#अन्तर्भाव <sys/sysctl.h>
#यदि_अन्तः

#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <netinet/ip.h>
#यदि_परिभाषितम् HAVE_NET_ROUTE_H
#अन्तर्भाव <net/route.h>
#यदि_अन्तः

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

#परिभाषय SSHD_CONFIG_BLOB_संस्करणम्	1

#यदि !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#यदि_अन्तः

स्थिर शून्य सङ्कलय_listen_addr(ServerOptions *, ध्रुव वर्ण *,
    ध्रुव वर्ण *, पूर्णाङ्क);
स्थिर शून्य सङ्कलय_one_listen_addr(ServerOptions *, ध्रुव वर्ण *,
    ध्रुव वर्ण *, पूर्णाङ्क);
स्थिर शून्य parse_server_config_गभीरता(ServerOptions *options,
    ध्रुव वर्ण *filename, संरचना sshbuf *conf, संरचना include_list *includes,
    संरचना connection_info *connectinfo, पूर्णाङ्क flags, पूर्णाङ्क *activep, पूर्णाङ्क गभीरता);

बाह्य संरचना sshbuf *cfg;

/* Initializes the server options to their default values. */

शून्य
initialize_server_options(ServerOptions *options)
{
	स्मृतिं_पूरय(options, 0, परिमाण(*options));
#परिभाषय SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#परिभाषय SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#परिभाषय SSHCONF_STRING(var, conf, flags, cp)		options->var = रिक्त;
#परिभाषय SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = रिक्त;
#परिभाषय SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#परिभाषय SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#परिभाषय SSHCONF_DEPRECATE(conf, flags, opcode)		/*रिक्तानि*/
#परिभाषय SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#परिभाषय SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = रिक्त;
#परिभाषय SSHCONF_ALIAS(old, conf, flags)			/*रिक्तानि*/

	/* Using macros for these is a bit overkill but forces consistency */
#परिभाषय init_hostkeyfile(options) \
	options->host_कुञ्चिका_files = 0; \
	options->अङ्कः_host_कुञ्चिका_files = 0; \
	options->host_कुञ्चिका_file_userprovided = रिक्त;
#परिभाषय init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#परिभाषय init_listenaddress(options) \
	options->queued_listen_addrs = रिक्त; \
	options->अङ्कः_queued_listens = 0; \
	options->listen_addrs = रिक्त; \
	options->अङ्कः_listen_addrs = 0;
#परिभाषय init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_समुच्चयः;
#परिभाषय init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_समुच्चयः;
#परिभाषय init_पत्तनम्(options) \
	options->अङ्कः_ports = 0; \
	options->ports_from_cmdline = 0;
#परिभाषय init_gatewayports(options) \
	options->fwd_opts.gateway_ports = -1;
#परिभाषय init_streamlocalbindmask(options) \
	options->fwd_opts.streamlocal_bind_आवरणम् = (बहुलकम्_t)-1;
#परिभाषय init_streamlocalbindunlink(options) \
	options->fwd_opts.streamlocal_bind_unlink = -1;
#परिभाषय init_maxstartups(options) \
	options->max_startups_begin = -1; \
	options->max_startups_दरः = -1; \
	options->max_startups = -1;
#परिभाषय init_permituserenv(options) \
	options->permit_user_env = -1; \
	options->permit_user_env_allowlist = रिक्त;
#परिभाषय init_persourcenetblocksize(options) \
	options->प्रत्येकम्_source_masklen_ipv4 = -1; \
	options->प्रत्येकम्_source_masklen_ipv6 = -1;
#परिभाषय init_persourcepenalties(options) \
	options->प्रत्येकम्_source_penalty_exempt = रिक्त; \
	options->प्रत्येकम्_source_penalty.enabled = -1; \
	options->प्रत्येकम्_source_penalty.max_sources4 = -1; \
	options->प्रत्येकम्_source_penalty.max_sources6 = -1; \
	options->प्रत्येकम्_source_penalty.अतिप्रवाहः_बहुलकम् = -1; \
	options->प्रत्येकम्_source_penalty.अतिप्रवाहः_mode6 = -1; \
	options->प्रत्येकम्_source_penalty.penalty_crash = -1.0; \
	options->प्रत्येकम्_source_penalty.penalty_authfail = -1.0; \
	options->प्रत्येकम्_source_penalty.penalty_invaliduser = -1.0; \
	options->प्रत्येकम्_source_penalty.penalty_noauth = -1.0; \
	options->प्रत्येकम्_source_penalty.penalty_grace = -1.0; \
	options->प्रत्येकम्_source_penalty.penalty_refuseconnection = -1.0; \
	options->प्रत्येकम्_source_penalty.penalty_max = -1.0; \
	options->प्रत्येकम्_source_penalty.penalty_min = -1.0;
#परिभाषय init_rekeylimit(options) \
	options->rekey_सीमा = -1; \
	options->rekey_interval = -1;
#परिभाषय init_subsystem(options) \
	options->अङ्कः_subsystems = 0; \
	options->subsystem_name = रिक्त; \
	options->subsystem_command = रिक्त; \
	options->subsystem_तर्काः = रिक्त;
#परिभाषय init_pubkey_auth_options(options) \
	options->pubkey_auth_options = -1; \
	options->max_pubkey_ok = -1;
#परिभाषय init_timingsecret(options) \
	options->timing_secret = 0;

	SSHD_CONFIG_ENTRIES

#अपरिभाषय init_hostkeyfile
#अपरिभाषय init_ipqos
#अपरिभाषय init_listenaddress
#अपरिभाषय init_logfacility
#अपरिभाषय init_loglevel
#अपरिभाषय init_पत्तनम्
#अपरिभाषय init_gatewayports
#अपरिभाषय init_streamlocalbindmask
#अपरिभाषय init_streamlocalbindunlink
#अपरिभाषय init_maxstartups
#अपरिभाषय init_permituserenv
#अपरिभाषय init_persourcenetblocksize
#अपरिभाषय init_persourcepenalties
#अपरिभाषय init_rekeylimit
#अपरिभाषय init_subsystem
#अपरिभाषय init_timingsecret
#अपरिभाषय SSHCONF_INT
#अपरिभाषय SSHCONF_INTFLAG
#अपरिभाषय SSHCONF_STRING
#अपरिभाषय SSHCONF_STRARRAY
#अपरिभाषय SSHCONF_CUSTOM
#अपरिभाषय SSHCONF_NONCONF
#अपरिभाषय SSHCONF_DEPRECATE
#अपरिभाषय SSHCONF_UNSUPPORTED_INT
#अपरिभाषय SSHCONF_UNSUPPORTED_STRING
#अपरिभाषय SSHCONF_ALIAS
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
स्थिर पूर्णाङ्क
option_clear_or_none(ध्रुव वर्ण *o)
{
	प्रत्यागम o == रिक्त || strcasecmp(o, "none") == 0;
}

स्थिर शून्य
assemble_algorithms(ServerOptions *o)
{
	वर्ण *all_cipher, *all_mac, *all_kex, *all_कुञ्चिका, *all_sig;
	वर्ण *def_cipher, *def_mac, *def_kex, *def_कुञ्चिका, *def_sig;
	पूर्णाङ्क r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_कुञ्चिका = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = मेलनम्_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = मेलनम्_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = मेलनम्_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_कुञ्चिका = मेलनम्_filter_allowlist(KEX_DEFAULT_PK_ALG, all_कुञ्चिका);
	def_sig = मेलनम्_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#परिभाषय ASSEMBLE(what, defaults, all) \
	कुरु { \
		यदि ((r = kex_assemble_नामानि(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} यावत् (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_कुञ्चिका, all_कुञ्चिका);
	ASSEMBLE(hostbased_accepted_algos, def_कुञ्चिका, all_कुञ्चिका);
	ASSEMBLE(pubkey_accepted_algos, def_कुञ्चिका, all_कुञ्चिका);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#अपरिभाषय ASSEMBLE
	मुक्त(all_cipher);
	मुक्त(all_mac);
	मुक्त(all_kex);
	मुक्त(all_कुञ्चिका);
	मुक्त(all_sig);
	मुक्त(def_cipher);
	मुक्त(def_mac);
	मुक्त(def_kex);
	मुक्त(def_कुञ्चिका);
	मुक्त(def_sig);
}

शून्य
servconf_सङ्कलय_hostkey(ध्रुव वर्ण *file, ध्रुव पूर्णाङ्क पङ्क्तिः,
    ServerOptions *options, ध्रुव वर्ण *मार्गः, पूर्णाङ्क userprovided)
{
	वर्ण *apath = derelativise_मार्गः(मार्गः);

	opt_array_append2(file, पङ्क्तिः, "HostKey",
	    &options->host_कुञ्चिका_files, &options->host_कुञ्चिका_file_userprovided,
	    &options->अङ्कः_host_कुञ्चिका_files, apath, userprovided);
	मुक्त(apath);
}

शून्य
servconf_सङ्कलय_hostcert(ध्रुव वर्ण *file, ध्रुव पूर्णाङ्क पङ्क्तिः,
    ServerOptions *options, ध्रुव वर्ण *मार्गः)
{
	वर्ण *apath = derelativise_मार्गः(मार्गः);

	opt_array_append(file, पङ्क्तिः, "HostCertificate",
	    &options->host_cert_files, &options->अङ्कः_host_cert_files, apath);
	मुक्त(apath);
}

शून्य
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#यदि_परिभाषितम् SKIP_PRIVDROP
	यदि (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	यदि (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#यदि_अन्तः

#परिभाषय SSHCONF_INT(var, conf, flags, ms, def, cp) \
	यदि (options->var == -1) \
		options->var = def;
#परिभाषय SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	यदि (options->var == -1) \
		options->var = def;
#परिभाषय SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#परिभाषय SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#परिभाषय SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#परिभाषय SSHCONF_NONCONF(funcsuffix)			/* done manually */
#परिभाषय SSHCONF_DEPRECATE(conf, flags, opcode)		/*रिक्तानि*/
#परिभाषय SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#परिभाषय SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	कुरु { \
		मुक्त(options->var); \
		options->var = रिक्त; \
	} यावत् (0);
#परिभाषय SSHCONF_ALIAS(old, conf, flags)			/*रिक्तानि*/

	/* XXX maybe use macros here too to force consistency? */

	SSHD_CONFIG_ENTRIES

#अपरिभाषय SSHCONF_INT
#अपरिभाषय SSHCONF_INTFLAG
#अपरिभाषय SSHCONF_STRING
#अपरिभाषय SSHCONF_STRARRAY
#अपरिभाषय SSHCONF_CUSTOM
#अपरिभाषय SSHCONF_NONCONF
#अपरिभाषय SSHCONF_DEPRECATE
#अपरिभाषय SSHCONF_UNSUPPORTED_INT
#अपरिभाषय SSHCONF_UNSUPPORTED_STRING
#अपरिभाषय SSHCONF_ALIAS

#यदि_परिभाषितम् USE_PAM
	यदि (options->pam_service_name == रिक्त)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#यदि_अन्तः

	यदि (options->अङ्कः_host_कुञ्चिका_files == 0) {
		/* fill default hostkeys */
		servconf_सङ्कलय_hostkey("[default]", 0, options,
		    मार्गः_HOST_RSA_कुञ्चिका_FILE, 0);
		servconf_सङ्कलय_hostkey("[default]", 0, options,
		    मार्गः_HOST_ECDSA_कुञ्चिका_FILE, 0);
		servconf_सङ्कलय_hostkey("[default]", 0, options,
		    मार्गः_HOST_ED25519_कुञ्चिका_FILE, 0);
		servconf_सङ्कलय_hostkey("[default]", 0, options,
		    मार्गः_HOST_MLDSA44_ED25519_कुञ्चिका_FILE, 0);
	}
	/* No certificates by default */
	यदि (options->अङ्कः_ports == 0)
		options->ports[options->अङ्कः_ports++] = SSH_DEFAULT_पत्तनम्;
	यदि (options->listen_addrs == रिक्त)
		सङ्कलय_listen_addr(options, रिक्त, रिक्त, 0);
	यदि (options->pid_file == रिक्त)
		options->pid_file = xstrdup(मार्गः_SSH_DAEMON_PID_FILE);
	यदि (options->moduli_file == रिक्त)
		options->moduli_file = xstrdup(मार्गः_DH_MODULI);
	यदि (options->xauth_location == रिक्त)
		options->xauth_location = xstrdup(मार्गः_XAUTH);
	यदि (options->log_facility == SYSLOG_FACILITY_NOT_समुच्चयः)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	यदि (options->log_level == SYSLOG_LEVEL_NOT_समुच्चयः)
		options->log_level = SYSLOG_LEVEL_INFO;
	यदि (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = रिक्त;
	}
	यदि (options->rekey_सीमा == -1)
		options->rekey_सीमा = 0;
	यदि (options->rekey_interval == -1)
		options->rekey_interval = 0;
	यदि (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	यदि (options->max_startups == -1)
		options->max_startups = 100;
	यदि (options->max_startups_दरः == -1)
		options->max_startups_दरः = 30;		/* 30% */
	यदि (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	यदि (options->प्रत्येकम्_source_masklen_ipv4 == -1)
		options->प्रत्येकम्_source_masklen_ipv4 = 32;
	यदि (options->प्रत्येकम्_source_masklen_ipv6 == -1)
		options->प्रत्येकम्_source_masklen_ipv6 = 128;
	यदि (options->प्रत्येकम्_source_penalty.enabled == -1)
		options->प्रत्येकम्_source_penalty.enabled = 1;
	यदि (options->प्रत्येकम्_source_penalty.max_sources4 == -1)
		options->प्रत्येकम्_source_penalty.max_sources4 = 65536;
	यदि (options->प्रत्येकम्_source_penalty.max_sources6 == -1)
		options->प्रत्येकम्_source_penalty.max_sources6 = 65536;
	यदि (options->प्रत्येकम्_source_penalty.अतिप्रवाहः_बहुलकम् == -1)
		options->प्रत्येकम्_source_penalty.अतिप्रवाहः_बहुलकम् = प्रत्येकम्_SOURCE_PENALTY_अतिप्रवाहः_PERMISSIVE;
	यदि (options->प्रत्येकम्_source_penalty.अतिप्रवाहः_mode6 == -1)
		options->प्रत्येकम्_source_penalty.अतिप्रवाहः_mode6 = options->प्रत्येकम्_source_penalty.अतिप्रवाहः_बहुलकम्;
	यदि (options->प्रत्येकम्_source_penalty.penalty_crash < 0.0)
		options->प्रत्येकम्_source_penalty.penalty_crash = 90.0;
	यदि (options->प्रत्येकम्_source_penalty.penalty_grace < 0.0)
		options->प्रत्येकम्_source_penalty.penalty_grace = 10.0;
	यदि (options->प्रत्येकम्_source_penalty.penalty_authfail < 0.0)
		options->प्रत्येकम्_source_penalty.penalty_authfail = 5.0;
	यदि (options->प्रत्येकम्_source_penalty.penalty_invaliduser < 0.0)
		options->प्रत्येकम्_source_penalty.penalty_invaliduser = 5.0;
	यदि (options->प्रत्येकम्_source_penalty.penalty_noauth < 0.0)
		options->प्रत्येकम्_source_penalty.penalty_noauth = 1.0;
	यदि (options->प्रत्येकम्_source_penalty.penalty_refuseconnection < 0.0)
		options->प्रत्येकम्_source_penalty.penalty_refuseconnection = 10.0;
	यदि (options->प्रत्येकम्_source_penalty.penalty_min < 0.0)
		options->प्रत्येकम्_source_penalty.penalty_min = 15.0;
	यदि (options->प्रत्येकम्_source_penalty.penalty_max < 0.0)
		options->प्रत्येकम्_source_penalty.penalty_max = 600.0;
	यदि (options->अङ्कः_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_कुञ्चिकाः_files,
		    &options->अङ्कः_authkeys_files,
		    मार्गः_SSH_USER_PERMITTED_कुञ्चिकाः);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_कुञ्चिकाः_files,
		    &options->अङ्कः_authkeys_files,
		    मार्गः_SSH_USER_PERMITTED_KEYS2);
	}
	यदि (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	यदि (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	यदि (options->संस्करणम्_addendum == रिक्त)
		options->संस्करणम्_addendum = xstrdup("");
	यदि (options->fwd_opts.streamlocal_bind_आवरणम् == (बहुलकम्_t)-1)
		options->fwd_opts.streamlocal_bind_आवरणम् = 0177;
	यदि (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	यदि (options->sk_provider == रिक्त)
		options->sk_provider = xstrdup("internal");
	यदि (options->sshd_session_मार्गः == रिक्त)
		options->sshd_session_मार्गः = xstrdup(मार्गः_SSHD_SESSION);
	यदि (options->sshd_auth_मार्गः == रिक्त)
		options->sshd_auth_मार्गः = xstrdup(मार्गः_SSHD_AUTH);
	यदि (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	यदि (options->agent_socket_मार्गः == रिक्त)
		options->agent_socket_मार्गः = xstrdup(मार्गः_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#परिभाषय CLEAR_ON_NONE(v) \
	कुरु { \
		यदि (option_clear_or_none(v)) { \
			मुक्त(v); \
			v = रिक्त; \
		} \
	} यावत्(0)
#परिभाषय CLEAR_ON_NONE_ARRAY(v, nv, none) \
	कुरु { \
		यदि (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			मुक्त(options->v[0]); \
			मुक्त(options->v); \
			options->v = रिक्त; \
			options->nv = 0; \
		} \
	} यावत् (0)
	CLEAR_ON_NONE(options->pid_file);
	CLEAR_ON_NONE(options->xauth_location);
	CLEAR_ON_NONE(options->banner);
	CLEAR_ON_NONE(options->trusted_user_ca_कुञ्चिकाः);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_कुञ्चिका_agent);
	CLEAR_ON_NONE(options->प्रत्येकम्_source_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_मार्गः);

	प्रति (i = 0; i < options->अङ्कः_host_कुञ्चिका_files; i++)
		CLEAR_ON_NONE(options->host_कुञ्चिका_files[i]);
	प्रति (i = 0; i < options->अङ्कः_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, अङ्कः_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, अङ्कः_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_कुञ्चिकाः_files, अङ्कः_revoked_कुञ्चिकाः_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_कुञ्चिकाः_files, अङ्कः_authkeys_files, "none");
#अपरिभाषय CLEAR_ON_NONE
#अपरिभाषय CLEAR_ON_NONE_ARRAY
}

/* Macros to declare ServerOpCodes enum values */
#परिभाषय SSHCONF_INT(var, conf, flags, ms, def, cp)	s##conf,
#परिभाषय SSHCONF_INTFLAG(var, conf, flags, def, cp)	s##conf,
#परिभाषय SSHCONF_STRING(var, conf, flags, cp)		s##conf,
#परिभाषय SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	s##conf,
#परिभाषय SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	s##conf,
#परिभाषय SSHCONF_NONCONF(funcsuffix)			/*रिक्तानि*/
#परिभाषय SSHCONF_DEPRECATE(conf, flags, opcode)		/*रिक्तानि*/
#परिभाषय SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/*रिक्तानि*/
#परिभाषय SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/*रिक्तानि*/
#परिभाषय SSHCONF_ALIAS(old, conf, flags)			/*रिक्तानि*/

/* Keyword tokens. */
प्रकारनिर्देश गणना {
	sBadOption,		/* == unknown option */
	SSHD_CONFIG_ENTRIES
	s_मेलनम्, sInclude,
	sDeprecated, sIgnore, sUnsupported
} ServerOpCodes;
#अपरिभाषय SSHCONF_INT
#अपरिभाषय SSHCONF_INTFLAG
#अपरिभाषय SSHCONF_STRING
#अपरिभाषय SSHCONF_STRARRAY
#अपरिभाषय SSHCONF_CUSTOM
#अपरिभाषय SSHCONF_NONCONF
#अपरिभाषय SSHCONF_DEPRECATE
#अपरिभाषय SSHCONF_UNSUPPORTED_INT
#अपरिभाषय SSHCONF_UNSUPPORTED_STRING
#अपरिभाषय SSHCONF_ALIAS

#परिभाषय SSHCFG_GLOBAL		0x01	/* allowed in main section of config */
#परिभाषय SSHCFG_मेलनम्		0x02	/* allowed inside a Match section */
#परिभाषय SSHCFG_ALL		(SSHCFG_GLOBAL|SSHCFG_मेलनम्)
#परिभाषय SSHCFG_NEVERMATCH	0x04  /* Match never matches; internal only */
#परिभाषय SSHCFG_मेलनम्_ONLY	0x08  /* Match only in conditional blocks; internal only */

/* Macros to define keywords[] entries */
#परिभाषय SSHCONF_KW(conf, flags)		{ #conf, s##conf, flags },
#परिभाषय SSHCONF_INT(var, conf, flags, ms, def, cp)	SSHCONF_KW(conf, flags)
#परिभाषय SSHCONF_INTFLAG(var, conf, flags, def, cp)	SSHCONF_KW(conf, flags)
#परिभाषय SSHCONF_STRING(var, conf, flags, cp)		SSHCONF_KW(conf, flags)
#परिभाषय SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	SSHCONF_KW(conf, flags)
#परिभाषय SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	SSHCONF_KW(conf, flags)
#परिभाषय SSHCONF_NONCONF(funcsuffix)			/*रिक्तानि*/
#परिभाषय SSHCONF_DEPRECATED				sDeprecated
#परिभाषय SSHCONF_IGNORE					sIgnore
#परिभाषय SSHCONF_DEPRECATE(conf, flags, opcode) \
	{ #conf, opcode, flags },
#परिभाषय SSHCONF_UNSUPPORTED_INT(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#परिभाषय SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#परिभाषय SSHCONF_ALIAS(old, conf, flags) \
	{ #old, s##conf, flags },

/* Textual representation of the tokens. */
स्थिर संरचना {
	ध्रुव वर्ण *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", s_मेलनम्, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ रिक्त, sBadOption, 0 }
};
#अपरिभाषय SSHCONF_INT
#अपरिभाषय SSHCONF_INTFLAG
#अपरिभाषय SSHCONF_STRING
#अपरिभाषय SSHCONF_STRARRAY
#अपरिभाषय SSHCONF_CUSTOM
#अपरिभाषय SSHCONF_NONCONF
#अपरिभाषय SSHCONF_DEPRECATED
#अपरिभाषय SSHCONF_IGNORE
#अपरिभाषय SSHCONF_DEPRECATE
#अपरिभाषय SSHCONF_UNSUPPORTED_INT
#अपरिभाषय SSHCONF_UNSUPPORTED_STRING
#अपरिभाषय SSHCONF_ALIAS

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

स्थिर ध्रुव वर्ण *
lookup_opcode_name(ServerOpCodes संहिता)
{
	u_int i;

	प्रति (i = 0; keywords[i].name != रिक्त; i++)
		यदि (keywords[i].opcode == संहिता)
			प्रत्यागम(keywords[i].name);
	प्रत्यागम "UNKNOWN";
}


/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

स्थिर ServerOpCodes
parse_token(ध्रुव वर्ण *cp, ध्रुव वर्ण *filename,
	    पूर्णाङ्क linenum, u_int *flags)
{
	u_int i;

	प्रति (i = 0; keywords[i].name; i++)
		यदि (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			प्रत्यागम keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	प्रत्यागम sBadOption;
}

वर्ण *
derelativise_मार्गः(ध्रुव वर्ण *मार्गः)
{
	वर्ण *expanded, *ret, cwd[PATH_MAX];

	यदि (strcasecmp(मार्गः, "none") == 0)
		प्रत्यागम xstrdup("none");
	expanded = tilde_expand_filename(मार्गः, getuid());
	यदि (मार्गः_absolute(expanded))
		प्रत्यागम expanded;
	यदि (getcwd(cwd, परिमाण(cwd)) == रिक्त)
		fatal_f("getcwd: %s", strerror(errno));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	मुक्त(expanded);
	प्रत्यागम ret;
}

स्थिर शून्य
सङ्कलय_listen_addr(ServerOptions *options, ध्रुव वर्ण *addr,
    ध्रुव वर्ण *rdomain, पूर्णाङ्क पत्तनम्)
{
	u_int i;

	यदि (पत्तनम् > 0)
		सङ्कलय_one_listen_addr(options, addr, rdomain, पत्तनम्);
	अन्यथा {
		प्रति (i = 0; i < options->अङ्कः_ports; i++) {
			सङ्कलय_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

स्थिर शून्य
सङ्कलय_one_listen_addr(ServerOptions *options, ध्रुव वर्ण *addr,
    ध्रुव वर्ण *rdomain, पूर्णाङ्क पत्तनम्)
{
	संरचना addrinfo hints, *ai, *aitop;
	वर्ण strport[NI_MAXSERV];
	पूर्णाङ्क gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	प्रति (i = 0; i < options->अङ्कः_listen_addrs; i++) {
		यदि (rdomain == रिक्त && options->listen_addrs[i].rdomain == रिक्त)
			भङ्ग;
		यदि (rdomain == रिक्त || options->listen_addrs[i].rdomain == रिक्त)
			अनुवर्त;
		यदि (वाक्यं_तुलय(rdomain, options->listen_addrs[i].rdomain) == 0)
			भङ्ग;
	}
	यदि (i >= options->अङ्कः_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		यदि (i >= अधिकतम_पूर्णाङ्कः)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->अङ्कः_listen_addrs, options->अङ्कः_listen_addrs + 1,
		    परिमाण(*options->listen_addrs));
		i = options->अङ्कः_listen_addrs++;
		यदि (rdomain != रिक्त)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	स्मृतिं_पूरय(&hints, 0, परिमाण(hints));
	hints.ai_family = options->स्थानाङ्कः_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == रिक्त) ? AI_PASSIVE : 0;
	snprintf(strport, परिमाण strport, "%d", पत्तनम्);
	यदि ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    ssh_gai_strerror(gaierr));
	प्रति (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs[i].addrs;
	options->listen_addrs[i].addrs = aitop;
}

/* Returns nonzero if the routing domain name is valid */
स्थिर पूर्णाङ्क
valid_rdomain(ध्रुव वर्ण *name)
{
#यदि defined(HAVE_SYS_VALID_RDOMAIN)
	प्रत्यागम sys_valid_rdomain(name);
#नोचेद्यदि defined(__OpenBSD__)
	ध्रुव वर्ण *errstr;
	दीर्घ दीर्घ अङ्कः;
	संरचना rt_tableinfo info;
	पूर्णाङ्क mib[6];
	आकार_t miblen = परिमाण(mib);

	यदि (name == रिक्त)
		प्रत्यागम 1;

	अङ्कः = strtonum(name, 0, 255, &errstr);
	यदि (errstr != रिक्त)
		प्रत्यागम 0;

	/* Check whether the table actually exists */
	स्मृतिं_पूरय(mib, 0, परिमाण(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_सारणी;
	mib[5] = (पूर्णाङ्क)अङ्कः;
	यदि (sysctl(mib, 6, &info, &miblen, रिक्त, 0) == -1)
		प्रत्यागम 0;

	प्रत्यागम 1;
#अन्यथा /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	प्रत्यागम 0;
#यदि_अन्तः
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
स्थिर शून्य
queue_listen_addr(ServerOptions *options, ध्रुव वर्ण *addr,
    ध्रुव वर्ण *rdomain, पूर्णाङ्क पत्तनम्)
{
	संरचना queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->अङ्कः_queued_listens, options->अङ्कः_queued_listens + 1,
	    परिमाण(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->अङ्कः_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->पत्तनम् = पत्तनम्;
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

	यदि (options->अङ्कः_ports == 0)
		options->ports[options->अङ्कः_ports++] = SSH_DEFAULT_पत्तनम्;
	यदि (options->स्थानाङ्कः_family == -1)
		options->स्थानाङ्कः_family = AF_UNSPEC;

	प्रति (i = 0; i < options->अङ्कः_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		सङ्कलय_listen_addr(options, qla->addr, qla->rdomain, qla->पत्तनम्);
		मुक्त(qla->addr);
		मुक्त(qla->rdomain);
	}
	मुक्त(options->queued_listen_addrs);
	options->queued_listen_addrs = रिक्त;
	options->अङ्कः_queued_listens = 0;
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
मेलनम्_cfg_पङ्क्तिः_गणः(ध्रुव वर्ण *grps, पूर्णाङ्क पङ्क्तिः, ध्रुव वर्ण *user)
{
	पूर्णाङ्क परिणाम = 0;
	संरचना passwd *pw;

	यदि (user == रिक्त)
		गच्छ बहिर्गमनम्;

	यदि ((pw = getpwnam(user)) == रिक्त) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", पङ्क्तिः, user);
	} अन्यथा यदि (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, पङ्क्तिः);
	} अन्यथा यदि (ga_मेलनम्_आदर्शः_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, पङ्क्तिः);
	} अन्यथा {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, पङ्क्तिः);
		परिणाम = 1;
	}
बहिर्गमनम्:
	ga_free();
	प्रत्यागम परिणाम;
}

स्थिर शून्य
मेलनम्_test_missing_fatal(ध्रुव वर्ण *criteria, ध्रुव वर्ण *attrib)
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
मेलनम्_cfg_पङ्क्तिः(ध्रुव वर्ण *पूर्णम्_पङ्क्तिः, पूर्णाङ्क *acp, वर्ण ***avp,
    पूर्णाङ्क पङ्क्तिः, संरचना connection_info *ci)
{
	पूर्णाङ्क परिणाम = 1, गुणाः = 0, पत्तनम्;
	वर्ण *arg, *attrib = रिक्त, *oattrib;

	यदि (ci == रिक्त) {
		debug3("checking syntax for 'Match %s' on line %d",
		    पूर्णम्_पङ्क्तिः, पङ्क्तिः);
	} अन्यथा {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", पूर्णम्_पङ्क्तिः,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->स्थानाङ्कः ? ci->स्थानाङ्कः : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", पङ्क्तिः);
	}

	यावत् ((oattrib = argv_अग्र(acp, avp)) != रिक्त) {
		/* Terminate on comment */
		यदि (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			भङ्ग;
		}
		attrib = xstrdup(oattrib);
		arg = रिक्त;
		गुणाः++;
		/* Criterion "all" has no argument and must appear alone */
		यदि (strcasecmp(attrib, "all") == 0) {
			यदि (गुणाः > 1 ||
			    ((arg = argv_अग्र(acp, avp)) != रिक्त &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				परिणाम = -1;
				गच्छ बहिर्गमनम्;
			}
			यदि (arg != रिक्त && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			परिणाम = 1;
			गच्छ बहिर्गमनम्;
		}
		/* Criterion "invalid-user" also has no argument */
		यदि (strcasecmp(attrib, "invalid-user") == 0) {
			यदि (ci == रिक्त) {
				परिणाम = 0;
				गच्छ अग्र;
			}
			यदि (ci->user_invalid == 0)
				परिणाम = 0;
			अन्यथा
				debug("matched invalid-user at line %d", पङ्क्तिः);
			गच्छ अग्र;
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
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} अन्यथा {
			arg = argv_अग्र(acp, avp);
		}

		/* All other criteria require an argument */
		यदि (arg == रिक्त || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			परिणाम = -1;
			गच्छ बहिर्गमनम्;
		}
		यदि (strcasecmp(attrib, "user") == 0) {
			यदि (ci == रिक्त || (ci->test && ci->user == रिक्त)) {
				परिणाम = 0;
				गच्छ अग्र;
			}
			यदि (ci->user == रिक्त)
				मेलनम्_test_missing_fatal("User", "user");
			यदि (मेलनम्_usergroup_आदर्शः_list(ci->user, arg) != 1)
				परिणाम = 0;
			अन्यथा
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, पङ्क्तिः);
		} अन्यथा यदि (strcasecmp(attrib, "group") == 0) {
			यदि (ci == रिक्त || (ci->test && ci->user == रिक्त)) {
				परिणाम = 0;
				गच्छ अग्र;
			}
			यदि (ci->user == रिक्त)
				मेलनम्_test_missing_fatal("Group", "user");
			विकल्प (मेलनम्_cfg_पङ्क्तिः_गणः(arg, पङ्क्तिः, ci->user)) {
			पक्ष -1:
				परिणाम = -1;
				गच्छ बहिर्गमनम्;
			पक्ष 0:
				परिणाम = 0;
			}
		} अन्यथा यदि (strcasecmp(attrib, "host") == 0) {
			यदि (ci == रिक्त || (ci->test && ci->host == रिक्त)) {
				परिणाम = 0;
				गच्छ अग्र;
			}
			यदि (ci->host == रिक्त)
				मेलनम्_test_missing_fatal("Host", "host");
			यदि (मेलनम्_hostname(ci->host, arg) != 1)
				परिणाम = 0;
			अन्यथा
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, पङ्क्तिः);
		} अन्यथा यदि (strcasecmp(attrib, "address") == 0) {
			यदि (ci == रिक्त || (ci->test && ci->स्थानाङ्कः == रिक्त)) {
				यदि (addr_मेलनम्_list(रिक्त, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, पङ्क्तिः);
				परिणाम = 0;
				गच्छ अग्र;
			}
			यदि (ci->स्थानाङ्कः == रिक्त)
				मेलनम्_test_missing_fatal("Address", "addr");
			विकल्प (addr_मेलनम्_list(ci->स्थानाङ्कः, arg)) {
			पक्ष 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->स्थानाङ्कः, arg, पङ्क्तिः);
				भङ्ग;
			पक्ष 0:
			पक्ष -1:
				परिणाम = 0;
				भङ्ग;
			पक्ष -2:
				परिणाम = -1;
				गच्छ बहिर्गमनम्;
			}
		} अन्यथा यदि (strcasecmp(attrib, "localaddress") == 0){
			यदि (ci == रिक्त || (ci->test && ci->laddress == रिक्त)) {
				यदि (addr_मेलनम्_list(रिक्त, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    पङ्क्तिः);
				परिणाम = 0;
				गच्छ अग्र;
			}
			यदि (ci->laddress == रिक्त)
				मेलनम्_test_missing_fatal("LocalAddress",
				    "laddr");
			विकल्प (addr_मेलनम्_list(ci->laddress, arg)) {
			पक्ष 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, पङ्क्तिः);
				भङ्ग;
			पक्ष 0:
			पक्ष -1:
				परिणाम = 0;
				भङ्ग;
			पक्ष -2:
				परिणाम = -1;
				गच्छ बहिर्गमनम्;
			}
		} अन्यथा यदि (strcasecmp(attrib, "localport") == 0) {
			यदि ((पत्तनम् = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				परिणाम = -1;
				गच्छ बहिर्गमनम्;
			}
			यदि (ci == रिक्त || (ci->test && ci->lport == -1)) {
				परिणाम = 0;
				गच्छ अग्र;
			}
			यदि (ci->lport == 0)
				मेलनम्_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			यदि (पत्तनम् == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, पत्तनम्, पङ्क्तिः);
			अन्यथा
				परिणाम = 0;
		} अन्यथा यदि (strcasecmp(attrib, "rdomain") == 0) {
			यदि (ci == रिक्त || (ci->test && ci->rdomain == रिक्त)) {
				परिणाम = 0;
				गच्छ अग्र;
			}
			यदि (ci->rdomain == रिक्त)
				मेलनम्_test_missing_fatal("RDomain", "rdomain");
			यदि (मेलनम्_आदर्शः_list(ci->rdomain, arg, 0) != 1)
				परिणाम = 0;
			अन्यथा
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, पङ्क्तिः);
		} अन्यथा यदि (strcasecmp(attrib, "version") == 0) {
			यदि (मेलनम्_आदर्शः_list(SSH_RELEASE, arg, 0) != 1)
				परिणाम = 0;
			अन्यथा
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, पङ्क्तिः);
		} अन्यथा {
			error("Unsupported Match attribute %s", oattrib);
			परिणाम = -1;
			गच्छ बहिर्गमनम्;
		}
 अग्र:
		मुक्त(attrib);
		attrib = रिक्त;
	}
	यदि (गुणाः == 0) {
		error("One or more attributes required for Match");
		प्रत्यागम -1;
	}
 बहिर्गमनम्:
	यदि (ci != रिक्त && परिणाम != -1)
		debug3("match %sfound on line %d", परिणाम ? "" : "not ", पङ्क्तिः);
	मुक्त(attrib);
	प्रत्यागम परिणाम;
}

#परिभाषय WHITESPACE " \t\r\n"

/* Multistate option parsing */
संरचना multistate {
	वर्ण *कुञ्चिका;
	पूर्णाङ्क मानम्;
};
स्थिर ध्रुव संरचना multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_ignore_rhosts[] = {
	{ "yes",			IGNORE_RHOSTS_YES },
	{ "no",				IGNORE_RHOSTS_NO },
	{ "shosts-only",		IGNORE_RHOSTS_SHOSTS },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_permitrootlogin[] = {
	{ "prohibit-password",		PERMIT_NO_PASSWD },
	{ "without-password",		PERMIT_NO_PASSWD },
	{ "forced-commands-only",	PERMIT_FORCED_ONLY },
	{ "yes",			PERMIT_YES },
	{ "no",				PERMIT_NO },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_compression[] = {
#यदि_परिभाषितम् WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#यदि_अन्तः
	{ "no",				COMP_NONE },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_gatewayports[] = {
	{ "clientspecified",		2 },
	{ "yes",			1 },
	{ "no",				0 },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_tcpfwd[] = {
	{ "yes",			FORWARD_ALLOW },
	{ "all",			FORWARD_ALLOW },
	{ "no",				FORWARD_DENY },
	{ "remote",			FORWARD_REMOTE },
	{ "local",			FORWARD_LOCAL },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ रिक्त, -1 }
};

स्थिर पूर्णाङ्क
process_server_config_पङ्क्तिः_गभीरता(ServerOptions *options, वर्ण *पङ्क्तिः,
    ध्रुव वर्ण *filename, पूर्णाङ्क linenum, पूर्णाङ्क *activep,
    संरचना connection_info *connectinfo, पूर्णाङ्क *inc_flags, पूर्णाङ्क गभीरता,
    संरचना include_list *includes)
{
	वर्ण *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	पूर्णाङ्क cmdline = 0, *intptr, मानम्, value2, value3, n, पत्तनम्, oactive, r;
	द्विगुण dvalue, *doubleptr = रिक्त;
	पूर्णाङ्क ca_only = 0, प्राप्तम् = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	आकार_t len;
	दीर्घ दीर्घ val64;
	ध्रुव संरचना multistate *multistate_ptr;
	ध्रुव वर्ण *errstr;
	संरचना include_item *item;
	glob_t gbuf;
	वर्ण **oav = रिक्त, **av;
	पूर्णाङ्क oac = 0, ac;
	पूर्णाङ्क ret = -1;
	वर्ण **strs = रिक्त; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	यदि ((len = वाक्यदैर्घ्यम्(पङ्क्तिः)) == 0)
		प्रत्यागम 0;
	प्रति (len--; len > 0; len--) {
		यदि (strchr(WHITESPACE "\f", पङ्क्तिः[len]) == रिक्त)
			भङ्ग;
		पङ्क्तिः[len] = '\0';
	}

	str = पङ्क्तिः;
	यदि ((keyword = strdelim(&str)) == रिक्त)
		प्रत्यागम 0;
	/* Ignore leading whitespace */
	यदि (*keyword == '\0')
		keyword = strdelim(&str);
	यदि (!keyword || !*keyword || *keyword == '#')
		प्रत्यागम 0;
	यदि (str == रिक्त || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		प्रत्यागम -1;
	}
	intptr = रिक्त;
	charptr = रिक्त;
	opcode = parse_token(keyword, filename, linenum, &flags);

	यदि (argv_विभज(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		प्रत्यागम -1;
	}
	ac = oac;
	av = oav;

	यदि (activep == रिक्त) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	यदि (*activep && opcode != s_मेलनम् && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	यदि (*activep == 0 && !(flags & SSHCFG_मेलनम्)) {
		यदि (connectinfo == रिक्त) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} अन्यथा { /* this is a directive we have already processed */
			ret = 0;
			गच्छ बहिर्गमनम्;
		}
	}

	विकल्प (opcode) {
	/* Portable-specific options */
#यदि_परिभाषितम् USE_PAM
	पक्ष sUsePAM:
		intptr = &options->use_pam;
		गच्छ parse_flag;
	पक्ष sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		यदि (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		भङ्ग;
#यदि_अन्तः

	/* Standard Options */
	पक्ष sBadOption:
		गच्छ बहिर्गमनम्;
	पक्ष s_पत्तनम्:
		/* ignore ports from configfile if cmdline specifies ports */
		यदि (options->ports_from_cmdline) {
			argv_consume(&ac);
			भङ्ग;
		}
		यदि (options->अङ्कः_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->अङ्कः_ports++] = a2port(arg);
		यदि (options->ports[options->अङ्कः_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		भङ्ग;

	पक्ष sLoginGraceTime:
		intptr = &options->login_grace_time;
 parse_time:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		यदि ((मानम् = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		यदि (*activep && *intptr == -1)
			*intptr = मानम्;
		भङ्ग;

	पक्ष s_Listen_स्थानाङ्कः:
		arg = argv_अग्र(&ac, &av);
		यदि (arg == रिक्त || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		यदि (strchr(arg, '[') == रिक्त && (p = strchr(arg, ':')) != रिक्त
		    && strchr(p+1, ':') != रिक्त) {
			पत्तनम् = 0;
			p = arg;
		} अन्यथा {
			arg2 = रिक्त;
			p = hpdelim(&arg);
			यदि (p == रिक्त)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			यदि (arg == रिक्त)
				पत्तनम् = 0;
			अन्यथा यदि ((पत्तनम् = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = रिक्त;
		यदि ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			यदि (वाक्यं_तुलय(arg, "rdomain") != 0 ||
			    (arg2 = argv_अग्र(&ac, &av)) == रिक्त)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			यदि (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		queue_listen_addr(options, p, arg2, पत्तनम्);

		भङ्ग;

	पक्ष s_स्थानाङ्कः_Family:
		intptr = &options->स्थानाङ्कः_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		मानम् = -1;
		प्रति (i = 0; multistate_ptr[i].कुञ्चिका != रिक्त; i++) {
			यदि (strcasecmp(arg, multistate_ptr[i].कुञ्चिका) == 0) {
				मानम् = multistate_ptr[i].मानम्;
				भङ्ग;
			}
		}
		यदि (मानम् == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		यदि (*activep && *intptr == -1)
			*intptr = मानम्;
		भङ्ग;

	पक्ष s_Host_कुञ्चिका:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		यदि (*activep) {
			servconf_सङ्कलय_hostkey(filename, linenum,
			    options, arg, 1);
		}
		भङ्ग;

	पक्ष s_Host_कुञ्चिका_Agent:
		charptr = &options->host_कुञ्चिका_agent;
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		यदि (*activep && *charptr == रिक्त)
			*charptr = !वाक्यं_तुलय(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_मार्गः(arg);
		भङ्ग;

	पक्ष sHostCertificate:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		यदि (*activep)
			servconf_सङ्कलय_hostcert(filename, linenum, options, arg);
		भङ्ग;

	पक्ष sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		यदि (*activep && *charptr == रिक्त) {
			*charptr = derelativise_मार्गः(arg);
			/* increase optional counter */
			यदि (intptr != रिक्त)
				*intptr = *intptr + 1;
		}
		भङ्ग;

	पक्ष sModuliFile:
		charptr = &options->moduli_file;
		गच्छ parse_filename;

	पक्ष s_Permit_मूलम्_Login:
		intptr = &options->permit_मूलम्_login;
		multistate_ptr = multistate_permitrootlogin;
		गच्छ parse_multistate;

	पक्ष sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
		multistate_ptr = multistate_ignore_rhosts;
		गच्छ parse_multistate;

	पक्ष s_Ignore_User_ज्ञातम्_Hosts:
		intptr = &options->ignore_user_ज्ञातम्_hosts;
 parse_flag:
		multistate_ptr = multistate_flag;
		गच्छ parse_multistate;

	पक्ष sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		गच्छ parse_flag;

	पक्ष s_Hostbased_उपयुङ्क्ते_Name_From_Packet_Only:
		intptr = &options->hostbased_उपयुङ्क्ते_name_from_packet_only;
		गच्छ parse_flag;

	पक्ष sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		यदि (*arg != '-' &&
		    !sshkey_नामानि_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		यदि (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		भङ्ग;

	पक्ष s_Host_कुञ्चिका_Algorithms:
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
		मानम् = 0;
		value2 = -1;
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			यदि (strcasecmp(arg, "none") == 0)
				अनुवर्त;
			यदि (strcasecmp(arg, "touch-required") == 0)
				मानम् |= PUBKEYAUTH_TOUCH_REQUIRED;
			अन्यथा यदि (strcasecmp(arg, "verify-required") == 0)
				मानम् |= PUBKEYAUTH_VERIFY_REQUIRED;
			अन्यथा यदि (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				यदि (errstr != रिक्त) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					गच्छ बहिर्गमनम्;
				}
			} अन्यथा {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				गच्छ बहिर्गमनम्;
			}
		}
		यदि (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = मानम्;
			options->max_pubkey_ok = value2;
		}
		भङ्ग;

#यदि_परिभाषितम् KRB5
	पक्ष sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		गच्छ parse_flag;

	पक्ष sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		गच्छ parse_flag;

	पक्ष sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		गच्छ parse_flag;
#यदि_परिभाषितम् USE_AFS
	पक्ष sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		गच्छ parse_flag;
#यदि_अन्तः /* USE_AFS */
#यदि_अन्तः /* KRB5 */

#यदि_परिभाषितम् GSSAPI
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
#यदि_अन्तः /* GSSAPI */

	पक्ष sPasswordAuthentication:
		intptr = &options->password_authentication;
		गच्छ parse_flag;

	पक्ष sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		गच्छ parse_flag;

	पक्ष sPrintMotd:
		intptr = &options->print_motd;
		गच्छ parse_flag;

#यदि_अपरिभाषितम् DISABLE_LASTLOG
	पक्ष s_Print_चरमः_Log:
		intptr = &options->print_lastlog;
		गच्छ parse_flag;
#यदि_अन्तः

	पक्ष sX11Forwarding:
		intptr = &options->x11_forwarding;
		गच्छ parse_flag;

	पक्ष s_X11_Display_विस्थापनम्:
		intptr = &options->x11_display_विस्थापनम्;
 parse_int:
		arg = argv_अग्र(&ac, &av);
		यदि ((errstr = atoi_err(arg, &मानम्)) != रिक्त)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		यदि (*activep && *intptr == -1)
			*intptr = मानम्;
		भङ्ग;

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

	पक्ष s_Permit_रिक्तानि_Passwords:
		intptr = &options->permit_रिक्तानि_passwd;
		गच्छ parse_flag;

	पक्ष sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		मानम् = 0;
		p = रिक्त;
		यदि (वाक्यं_तुलय(arg, "yes") == 0)
			मानम् = 1;
		अन्यथा यदि (वाक्यं_तुलय(arg, "no") == 0)
			मानम् = 0;
		अन्यथा {
			/* Pattern-list specified */
			मानम् = 1;
			p = xstrdup(arg);
		}
		यदि (*activep && *intptr == -1) {
			*intptr = मानम्;
			*charptr = p;
			p = रिक्त;
		}
		मुक्त(p);
		भङ्ग;

	पक्ष sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		गच्छ parse_multistate;

	पक्ष s_Rekey_सीमा:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि (वाक्यं_तुलय(arg, "default") == 0) {
			val64 = 0;
		} अन्यथा {
			यदि (अवलोकनम्_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, strerror(errno));
			यदि (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		यदि (*activep && options->rekey_सीमा == -1)
			options->rekey_सीमा = val64;
		यदि (ac != 0) { /* optional rekey interval present */
			यदि (वाक्यं_तुलय(av[0], "none") == 0) {
				(शून्य)argv_अग्र(&ac, &av);	/* discard */
				भङ्ग;
			}
			intptr = &options->rekey_interval;
			गच्छ parse_time;
		}
		भङ्ग;

	पक्ष sGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		multistate_ptr = multistate_gatewayports;
		गच्छ parse_multistate;

	पक्ष sUseDNS:
		intptr = &options->use_dns;
		गच्छ parse_flag;

	पक्ष sSyslogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_अग्र(&ac, &av);
		मानम् = log_facility_सङ्ख्या(arg);
		यदि (मानम् == SYSLOG_FACILITY_NOT_समुच्चयः)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		यदि (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) मानम्;
		भङ्ग;

	पक्ष sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_अग्र(&ac, &av);
		मानम् = log_level_सङ्ख्या(arg);
		यदि (मानम् == SYSLOG_LEVEL_NOT_समुच्चयः)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		यदि (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) मानम्;
		भङ्ग;

	पक्ष sLogVerbose:
		प्राप्तम् = options->अङ्कः_log_verbose == 0;
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			यदि (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				गच्छ बहिर्गमनम्;
			}
			/* Allow "none" only in first position */
			यदि (strcasecmp(arg, "none") == 0) {
				यदि (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ बहिर्गमनम्;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		यदि (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		यदि (प्राप्तम् && *activep) {
			options->log_verbose = strs;
			options->अङ्कः_log_verbose = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		गच्छ parse_multistate;

	पक्ष s_Allow_प्रवाहः_Local_Forwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		गच्छ parse_multistate;

	पक्ष sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		गच्छ parse_flag;

	पक्ष s_Agent_Socket_मार्गः:
		charptr = &options->agent_socket_मार्गः;
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		यदि (वाक्ये_तुलय(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			यदि (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} अन्यथा यदि (वाक्ये_तुलय(arg, "user:", 5) == 0) {
			/* User paths must not be empty */
			यदि (arg[5] == '\0') {
				fatal("%s line %d: invalid user path.",
				    filename, linenum);
			}
		} अन्यथा यदि (वाक्यं_तुलय(arg, "none") != 0)
			fatal("%s line %d: invalid path.", filename, linenum);
		यदि (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		भङ्ग;

	पक्ष sDisableForwarding:
		intptr = &options->disable_forwarding;
		गच्छ parse_flag;

	पक्ष sAllowUsers:
		chararrayptr = &options->allow_users;
		uintptr = &options->अङ्कः_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			यदि (*arg == '\0' ||
			    मेलनम्_user(रिक्त, रिक्त, रिक्त, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			प्राप्तम् = 1;
			यदि (!*activep)
				अनुवर्त;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		यदि (!प्राप्तम्) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		भङ्ग;

	पक्ष sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->अङ्कः_deny_users;
		गच्छ parse_allowdenyusers;

	पक्ष sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->अङ्कः_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			यदि (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			प्राप्तम् = 1;
			यदि (!*activep)
				अनुवर्त;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		यदि (!प्राप्तम्) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		भङ्ग;

	पक्ष sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->अङ्कः_deny_groups;
		गच्छ parse_allowdenygroups;

	पक्ष sCiphers:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		यदि (options->ciphers == रिक्त)
			options->ciphers = xstrdup(arg);
		भङ्ग;

	पक्ष sMacs:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		यदि (options->macs == रिक्त)
			options->macs = xstrdup(arg);
		भङ्ग;

	पक्ष sKexAlgorithms:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि (*arg != '-' &&
		    !kex_नामानि_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		यदि (options->kex_algorithms == रिक्त)
			options->kex_algorithms = xstrdup(arg);
		भङ्ग;

	पक्ष sSubsystem:
		यदि ((arg = argv_अग्र(&ac, &av)) == रिक्त || *arg == '\0' ||
		   ((arg2 = argv_अग्र(&ac, &av)) == रिक्त || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि (!*activep) {
			argv_consume(&ac);
			भङ्ग;
		}
		प्राप्तम् = 0;
		प्रति (i = 0; i < options->अङ्कः_subsystems; i++) {
			यदि (वाक्यं_तुलय(arg, options->subsystem_name[i]) == 0) {
				प्राप्तम् = 1;
				भङ्ग;
			}
		}
		यदि (प्राप्तम्) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			भङ्ग;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->अङ्कः_subsystems,
		    options->अङ्कः_subsystems + 1,
		    परिमाण(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->अङ्कः_subsystems,
		    options->अङ्कः_subsystems + 1,
		    परिमाण(*options->subsystem_command));
		options->subsystem_तर्काः = xrecallocarray(
		    options->subsystem_तर्काः, options->अङ्कः_subsystems,
		    options->अङ्कः_subsystems + 1,
		    परिमाण(*options->subsystem_तर्काः));
		options->subsystem_name[options->अङ्कः_subsystems] = xstrdup(arg);
		options->subsystem_command[options->अङ्कः_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_तर्काः[options->अङ्कः_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		मुक्त(arg2);
		मुक्त(arg);
		argv_consume(&ac);
		options->अङ्कः_subsystems++;
		भङ्ग;

	पक्ष sMaxStartups:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		यदि ((n = वाक्यात्_पठ(arg, "%d:%d:%d",
		    &मानम्, &value2, &value3)) == 3) {
			यदि (मानम् > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} अन्यथा यदि (n == 1) {
			value3 = मानम्;
			value2 = -1;
		} अन्यथा {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		यदि (मानम् <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		यदि (*activep && options->max_startups == -1) {
			options->max_startups_begin = मानम्;
			options->max_startups_दरः = value2;
			options->max_startups = value3;
		}
		भङ्ग;

	पक्ष s_प्रत्येकम्_Source_Net_खण्डम्_आकार:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		विकल्प (n = वाक्यात्_पठ(arg, "%d:%d", &मानम्, &value2)) {
		पक्ष 2:
			यदि (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		पक्ष 1:
			यदि (मानम् < 0 || मानम् > 32)
				n = -1;
		}
		यदि (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		यदि (*activep && options->प्रत्येकम्_source_masklen_ipv4 == -1) {
			options->प्रत्येकम्_source_masklen_ipv4 = मानम्;
			यदि (n == 2)
				options->प्रत्येकम्_source_masklen_ipv6 = value2;
		}
		भङ्ग;

	पक्ष s_प्रत्येकम्_Source_Max_Startups:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि (वाक्यं_तुलय(arg, "none") == 0) { /* no limit */
			मानम् = अधिकतम_पूर्णाङ्कः;
		} अन्यथा {
			यदि ((errstr = atoi_err(arg, &मानम्)) != रिक्त)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		यदि (*activep && options->प्रत्येकम्_source_max_startups == -1)
			options->प्रत्येकम्_source_max_startups = मानम्;
		भङ्ग;

	पक्ष s_प्रत्येकम्_Source_Penalty_Exempt_List:
		charptr = &options->प्रत्येकम्_source_penalty_exempt;
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		यदि (addr_मेलनम्_list(रिक्त, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		यदि (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		भङ्ग;

	पक्ष s_प्रत्येकम्_Source_Penalties:
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			ध्रुव वर्ण *q = रिक्त;

			प्राप्तम् = 1;
			intptr = रिक्त;
			doubleptr = रिक्त;
			मानम् = -1;
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
				    options->प्रत्येकम्_source_penalty.enabled == -1)
					options->प्रत्येकम्_source_penalty.enabled = value2;
				अनुवर्त;
			} अन्यथा यदि ((q = strprefix(arg, "crash:", 0)) != रिक्त) {
				doubleptr = &options->प्रत्येकम्_source_penalty.penalty_crash;
			} अन्यथा यदि ((q = strprefix(arg, "authfail:", 0)) != रिक्त) {
				doubleptr = &options->प्रत्येकम्_source_penalty.penalty_authfail;
			} अन्यथा यदि ((q = strprefix(arg, "invaliduser:", 0)) != रिक्त) {
				doubleptr = &options->प्रत्येकम्_source_penalty.penalty_invaliduser;
			} अन्यथा यदि ((q = strprefix(arg, "noauth:", 0)) != रिक्त) {
				doubleptr = &options->प्रत्येकम्_source_penalty.penalty_noauth;
			} अन्यथा यदि ((q = strprefix(arg, "grace-exceeded:", 0)) != रिक्त) {
				doubleptr = &options->प्रत्येकम्_source_penalty.penalty_grace;
			} अन्यथा यदि ((q = strprefix(arg, "refuseconnection:", 0)) != रिक्त) {
				doubleptr = &options->प्रत्येकम्_source_penalty.penalty_refuseconnection;
			} अन्यथा यदि ((q = strprefix(arg, "max:", 0)) != रिक्त) {
				doubleptr = &options->प्रत्येकम्_source_penalty.penalty_max;
			} अन्यथा यदि ((q = strprefix(arg, "min:", 0)) != रिक्त) {
				doubleptr = &options->प्रत्येकम्_source_penalty.penalty_min;
			} अन्यथा यदि ((q = strprefix(arg, "max-sources4:", 0)) != रिक्त) {
				intptr = &options->प्रत्येकम्_source_penalty.max_sources4;
				यदि ((errstr = atoi_err(q, &मानम्)) != रिक्त)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} अन्यथा यदि ((q = strprefix(arg, "max-sources6:", 0)) != रिक्त) {
				intptr = &options->प्रत्येकम्_source_penalty.max_sources6;
				यदि ((errstr = atoi_err(q, &मानम्)) != रिक्त)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} अन्यथा यदि (वाक्यं_तुलय(arg, "overflow:deny-all") == 0) {
				intptr = &options->प्रत्येकम्_source_penalty.अतिप्रवाहः_बहुलकम्;
				मानम् = प्रत्येकम्_SOURCE_PENALTY_अतिप्रवाहः_DENY_ALL;
			} अन्यथा यदि (वाक्यं_तुलय(arg, "overflow:permissive") == 0) {
				intptr = &options->प्रत्येकम्_source_penalty.अतिप्रवाहः_बहुलकम्;
				मानम् = प्रत्येकम्_SOURCE_PENALTY_अतिप्रवाहः_PERMISSIVE;
			} अन्यथा यदि (वाक्यं_तुलय(arg, "overflow6:deny-all") == 0) {
				intptr = &options->प्रत्येकम्_source_penalty.अतिप्रवाहः_mode6;
				मानम् = प्रत्येकम्_SOURCE_PENALTY_अतिप्रवाहः_DENY_ALL;
			} अन्यथा यदि (वाक्यं_तुलय(arg, "overflow6:permissive") == 0) {
				intptr = &options->प्रत्येकम्_source_penalty.अतिप्रवाहः_mode6;
				मानम् = प्रत्येकम्_SOURCE_PENALTY_अतिप्रवाहः_PERMISSIVE;
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
					options->प्रत्येकम्_source_penalty.enabled = 1;
				}
			} अन्यथा यदि (intptr != रिक्त) {
				यदि (*activep && *intptr == -1) {
					*intptr = मानम्;
					options->प्रत्येकम्_source_penalty.enabled = 1;
				}
			} अन्यथा {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		यदि (!प्राप्तम्) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		भङ्ग;

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
	पक्ष s_Authorized_कुञ्चिकाः_File:
		uintptr = &options->अङ्कः_authkeys_files;
		chararrayptr = &options->authorized_कुञ्चिकाः_files;
 parse_filenames:
		प्राप्तम् = *uintptr == 0;
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			यदि (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				गच्छ बहिर्गमनम्;
			}
			/* Allow "none" only in first position */
			यदि (strcasecmp(arg, "none") == 0) {
				यदि (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ बहिर्गमनम्;
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
		यदि (प्राप्तम् && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि (*activep && *charptr == रिक्त) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			यदि (intptr != रिक्त)
				*intptr = *intptr + 1;
		}
		भङ्ग;

	पक्ष sClientAliveInterval:
		intptr = &options->client_alive_interval;
		गच्छ parse_time;

	पक्ष s_Client_Alive_गणनम्_Max:
		intptr = &options->client_alive_गणनम्_max;
		गच्छ parse_int;

	पक्ष sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			यदि (*arg == '\0' || strchr(arg, '=') != रिक्त)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			प्राप्तम् = 1;
			यदि (!*activep)
				अनुवर्त;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->अङ्कः_accept_env,
			    arg);
		}
		यदि (!प्राप्तम्) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		भङ्ग;

	पक्ष s_समुच्चयः_Env:
		प्राप्तम् = options->अङ्कः_setenv == 0;
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			यदि (*arg == '\0' || strchr(arg, '=') == रिक्त)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			यदि (lookup_setenv_अन्तर्_list(arg, strs, nstrs) != रिक्त) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				अनुवर्त;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		यदि (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		यदि (प्राप्तम् && *activep) {
			options->setenv = strs;
			options->अङ्कः_setenv = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		मानम् = -1;
		प्रति (i = 0; tunmode_desc[i].val != -1; i++)
			यदि (वाक्यं_तुलय(tunmode_desc[i].text, arg) == 0) {
				मानम् = tunmode_desc[i].val;
				भङ्ग;
			}
		यदि (मानम् == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		यदि (*activep && *intptr == -1)
			*intptr = मानम्;
		भङ्ग;

	पक्ष sInclude:
		यदि (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		मानम् = 0;
		यावत् ((arg2 = argv_अग्र(&ac, &av)) != रिक्त) {
			यदि (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				गच्छ बहिर्गमनम्;
			}
			मानम्++;
			प्राप्तम् = 0;
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
			TAILQ_FOREACH(item, includes, प्रविष्टिः) {
				यदि (वाक्यं_तुलय(item->selector, arg) != 0)
					अनुवर्त;
				यदि (item->filename != रिक्त) {
					parse_server_config_गभीरता(options,
					    item->filename, item->contents,
					    includes, connectinfo,
					    (*inc_flags & SSHCFG_मेलनम्_ONLY
					        ? SSHCFG_मेलनम्_ONLY : (oactive
					            ? 0 : SSHCFG_NEVERMATCH)),
					    activep, गभीरता + 1);
				}
				प्राप्तम् = 1;
				*activep = oactive;
			}
			यदि (प्राप्तम् != 0) {
				मुक्त(arg);
				अनुवर्त;
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
				    item, प्रविष्टिः);
			}
			यदि (gbuf.gl_pathc > अधिकतम_पूर्णाङ्कः)
				fatal_f("too many glob results");
			प्रति (n = 0; n < (पूर्णाङ्क)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				item = xcalloc(1, परिमाण(*item));
				item->selector = xstrdup(arg);
				item->filename = xstrdup(gbuf.gl_pathv[n]);
				यदि ((item->contents = sshbuf_new()) == रिक्त)
					fatal_f("sshbuf_new failed");
				आरोपय_server_config(item->filename,
				    item->contents);
				parse_server_config_गभीरता(options,
				    item->filename, item->contents,
				    includes, connectinfo,
				    (*inc_flags & SSHCFG_मेलनम्_ONLY
				        ? SSHCFG_मेलनम्_ONLY : (oactive
				            ? 0 : SSHCFG_NEVERMATCH)),
				    activep, गभीरता + 1);
				*activep = oactive;
				TAILQ_INSERT_TAIL(includes, item, प्रविष्टिः);
			}
			globfree(&gbuf);
			मुक्त(arg);
		}
		यदि (मानम् == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		भङ्ग;

	पक्ष s_मेलनम्:
		यदि (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		मानम् = मेलनम्_cfg_पङ्क्तिः(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? रिक्त : connectinfo));
		यदि (मानम् < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : मानम्;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_मेलनम्_ONLY;
		भङ्ग;

	पक्ष sPermitListen:
	पक्ष sPermitOpen:
		यदि (opcode == sPermitListen) {
			uintptr = &options->अङ्कः_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} अन्यथा {
			uintptr = &options->अङ्कः_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		प्राप्तम् = *uintptr == 0;
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			यदि (वाक्यं_तुलय(arg, "any") == 0 ||
			    वाक्यं_तुलय(arg, "none") == 0) {
				यदि (nstrs != 0) {
					fatal("%s line %d: %s must appear "
					    "alone on a %s line.",
					    filename, linenum, arg, keyword);
				}
				opt_array_append(filename, linenum, keyword,
				    &strs, &nstrs, arg);
				अनुवर्त;
			}

			यदि (opcode == sPermitListen &&
			    strchr(arg, ':') == रिक्त) {
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
			    ((पत्तनम् = permitopen_पत्तनम्(arg)) < 0)) {
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
		यदि (प्राप्तम् && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष sForceCommand:
		यदि (str == रिक्त || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		यदि (*activep && options->adm_forced_command == रिक्त)
			options->adm_forced_command = xstrdup(str + len);
		argv_consume(&ac);
		भङ्ग;

	पक्ष sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		भङ्ग;

	पक्ष sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_कुञ्चिकाः;
		गच्छ parse_filename;

	पक्ष s_Revoked_कुञ्चिकाः:
		uintptr = &options->अङ्कः_revoked_कुञ्चिकाः_files;
		chararrayptr = &options->revoked_कुञ्चिकाः_files;
		गच्छ parse_filenames;

	पक्ष s_Security_कुञ्चिका_Provider:
		charptr = &options->sk_provider;
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि (*activep && *charptr == रिक्त) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_मार्गः(arg);
			/* increase optional counter */
			यदि (intptr != रिक्त)
				*intptr = *intptr + 1;
		}
		भङ्ग;

	पक्ष sIPQoS:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि ((मानम् = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		यदि (मानम् == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			मानम् = अधिकतम_पूर्णाङ्कः;
		}
		arg = argv_अग्र(&ac, &av);
		यदि (arg == रिक्त)
			value2 = मानम्;
		अन्यथा यदि ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		यदि (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = अधिकतम_पूर्णाङ्कः;
		}
		यदि (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = मानम्;
			options->ip_qos_bulk = value2;
		}
		भङ्ग;

	पक्ष s_संस्करणम्_Addendum:
		यदि (str == रिक्त || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		यदि (strchr(str + len, '\r') != रिक्त) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		यदि ((arg = strchr(पङ्क्तिः, '#')) != रिक्त) {
			*arg = '\0';
			rtrim(पङ्क्तिः);
		}
		यदि (*activep && options->संस्करणम्_addendum == रिक्त) {
			यदि (strcasecmp(str + len, "none") == 0)
				options->संस्करणम्_addendum = xstrdup("");
			अन्यथा
				options->संस्करणम्_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		भङ्ग;

	पक्ष s_Authorized_कुञ्चिकाः_Command:
		charptr = &options->authorized_कुञ्चिकाः_command;
 parse_command:
		len = strspn(str, WHITESPACE);
		यदि (str[len] != '/' && strcasecmp(str + len, "none") != 0) {
			fatal("%.200s line %d: %s must be an absolute path",
			    filename, linenum, keyword);
		}
		यदि (*activep && *charptr == रिक्त)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		भङ्ग;

	पक्ष s_Authorized_कुञ्चिकाः_Command_User:
		charptr = &options->authorized_कुञ्चिकाः_command_user;
 parse_localuser:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0') {
			fatal("%s line %d: missing %s argument.",
			    filename, linenum, keyword);
		}
		यदि (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		भङ्ग;

	पक्ष sAuthorizedPrincipalsCommand:
		charptr = &options->authorized_principals_command;
		गच्छ parse_command;

	पक्ष sAuthorizedPrincipalsCommandUser:
		charptr = &options->authorized_principals_command_user;
		गच्छ parse_localuser;

	पक्ष sAuthenticationMethods:
		प्राप्तम् = options->अङ्कः_auth_methods == 0;
		मानम् = 0; /* seen "any" pseudo-method */
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			यदि (वाक्यं_तुलय(arg, "any") == 0) {
				यदि (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				मानम् = 1;
			} अन्यथा यदि (मानम्) {
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
		यदि (प्राप्तम् && *activep) {
			options->auth_methods = strs;
			options->अङ्कः_auth_methods = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष s_प्रवाहः_Local_Bind_आवरणम्:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		मानम् = strtol(arg, &p, 8);
		यदि (arg == p || मानम् < 0 || मानम् > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		यदि (*activep &&
		    options->fwd_opts.streamlocal_bind_आवरणम् == (बहुलकम्_t)-1)
			options->fwd_opts.streamlocal_bind_आवरणम् = (बहुलकम्_t)मानम्;
		भङ्ग;

	पक्ष s_प्रवाहः_Local_Bind_Unlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		गच्छ parse_flag;

	पक्ष sFingerprintHash:
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि ((मानम् = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		यदि (*activep)
			options->fingerprint_hash = मानम्;
		भङ्ग;

	पक्ष sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		गच्छ parse_flag;

	पक्ष sRDomain:
#यदि !defined(__OpenBSD__) && !defined(HAVE_SYS_समुच्चयः_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#यदि_अन्तः
		charptr = &options->routing_domain;
		arg = argv_अग्र(&ac, &av);
		यदि (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		यदि (strcasecmp(arg, "none") != 0 && वाक्यं_तुलय(arg, "%D") != 0 &&
		    !valid_rdomain(arg))
			fatal("%s line %d: invalid routing domain",
			    filename, linenum);
		यदि (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		भङ्ग;

	पक्ष sRequiredRSASize:
		intptr = &options->required_rsa_आकार;
		गच्छ parse_int;

	पक्ष sChannelTimeout:
		प्राप्तम् = options->अङ्कः_channel_timeouts == 0;
		यावत् ((arg = argv_अग्र(&ac, &av)) != रिक्त) {
			/* Allow "none" only in first position */
			यदि (strcasecmp(arg, "none") == 0) {
				यदि (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ बहिर्गमनम्;
				}
			} अन्यथा यदि (parse_आदर्शः_interval(arg,
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
		यदि (प्राप्तम् && *activep) {
			options->channel_timeouts = strs;
			options->अङ्कः_channel_timeouts = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष s_अप्रयुक्तम्_Connection_Timeout:
		intptr = &options->अप्रयुक्तम्_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		यदि (av[0] != रिक्त && strcasecmp(av[0], "none") == 0) {
			(शून्य)argv_अग्र(&ac, &av); /* consume arg */
			यदि (*activep)
				*intptr = 0;
			भङ्ग;
		}
		गच्छ parse_time;

	पक्ष s_Sshd_Session_मार्गः:
		charptr = &options->sshd_session_मार्गः;
		गच्छ parse_filename;

	पक्ष s_Sshd_Auth_मार्गः:
		charptr = &options->sshd_auth_मार्गः;
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
		भङ्ग;

	स्वभाव:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, keyword, opcode);
	}
	/* Check that there is no garbage at end of line. */
	यदि (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		गच्छ बहिर्गमनम्;
	}

	/* success */
	ret = 0;
 बहिर्गमनम्:
	opt_array_free2(strs, रिक्त, nstrs);
	argv_free(oav, oac);
	प्रत्यागम ret;
}

पूर्णाङ्क
process_server_config_पङ्क्तिः(ServerOptions *options, वर्ण *पङ्क्तिः,
    ध्रुव वर्ण *filename, पूर्णाङ्क linenum, पूर्णाङ्क *activep,
    संरचना connection_info *connectinfo, संरचना include_list *includes)
{
	पूर्णाङ्क inc_flags = 0;

	प्रत्यागम process_server_config_पङ्क्तिः_गभीरता(options, पङ्क्तिः, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

शून्य
आरोपय_server_config(ध्रुव वर्ण *filename, संरचना sshbuf *conf)
{
	संरचना stat st;
	वर्ण *पङ्क्तिः = रिक्त, *cp;
	आकार_t linesize = 0;
	FILE *f;
	पूर्णाङ्क r;

	debug2_f("filename %s", filename);
	यदि ((f = fopen(filename, "r")) == रिक्त) {
		perror(filename);
		निर्गच्छ(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	यदि (fstat(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	यावत् (getline(&पङ्क्तिः, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = पङ्क्तिः + strspn(पङ्क्तिः, " \t\r");
		यदि ((r = sshbuf_put(conf, cp, वाक्यदैर्घ्यम्(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	मुक्त(पङ्क्तिः);
	यदि ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	fclose(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

शून्य
parse_server_मेलनम्_config(ServerOptions *options,
   संरचना include_list *includes, संरचना connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_समुच्चयः_server_options(options, &mo, 0);
	free_server_options(&mo);
}

पूर्णाङ्क
parse_server_मेलनम्_testspec(संरचना connection_info *ci, वर्ण *spec)
{
	वर्ण *p;
	ध्रुव वर्ण *val;

	यावत् ((p = strsep(&spec, ",")) && *p != '\0') {
		यदि ((val = strprefix(p, "addr=", 0)) != रिक्त) {
			ci->स्थानाङ्कः = xstrdup(val);
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
				fprintf(stderr, "Invalid port '%s' in test mode"
				    " specification %s\n", p+6, p);
				प्रत्यागम -1;
			}
		} अन्यथा यदि (वाक्यं_तुलय(p, "invalid-user") == 0) {
			ci->user_invalid = 1;
		} अन्यथा {
			fprintf(stderr, "Invalid test mode specification %s\n",
			    p);
			प्रत्यागम -1;
		}
	}
	प्रत्यागम 0;
}

शून्य
servconf_merge_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, प्राप्तम्;

	प्रति (i = 0; i < src->अङ्कः_subsystems; i++) {
		प्राप्तम् = 0;
		प्रति (j = 0; j < dst->अङ्कः_subsystems; j++) {
			यदि (वाक्यं_तुलय(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				प्राप्तम् = 1;
				भङ्ग;
			}
		}
		यदि (प्राप्तम्) {
			debug_f("override \"%s\"", dst->subsystem_name[j]);
			मुक्त(dst->subsystem_command[j]);
			मुक्त(dst->subsystem_तर्काः[j]);
			dst->subsystem_command[j] =
			    xstrdup(src->subsystem_command[i]);
			dst->subsystem_तर्काः[j] =
			    xstrdup(src->subsystem_तर्काः[i]);
			अनुवर्त;
		}
		debug_f("add \"%s\"", src->subsystem_name[i]);
		dst->subsystem_name = xrecallocarray(
		    dst->subsystem_name, dst->अङ्कः_subsystems,
		    dst->अङ्कः_subsystems + 1, परिमाण(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->अङ्कः_subsystems,
		    dst->अङ्कः_subsystems + 1, परिमाण(*dst->subsystem_command));
		dst->subsystem_तर्काः = xrecallocarray(
		    dst->subsystem_तर्काः, dst->अङ्कः_subsystems,
		    dst->अङ्कः_subsystems + 1, परिमाण(*dst->subsystem_तर्काः));
		j = dst->अङ्कः_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_तर्काः[j] = xstrdup(src->subsystem_तर्काः[i]);
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
		प्रत्यागम r;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
serialise_s64(संरचना sshbuf *buf, int64_t v)
{
	uint64_t uv;
	पूर्णाङ्क r;

	uv = v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
	यदि ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u64(buf, uv)) != 0)
		प्रत्यागम r;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
serialise_बहुलकम्(संरचना sshbuf *buf, बहुलकम्_t v)
{
	u_int uv;

	यदि (v == (बहुलकम्_t)-1)
		प्रत्यागम serialise_s32(buf, -1);
	uv = (u_int)v;
	यदि ((बहुलकम्_t)uv != v || uv > 0777)
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	प्रत्यागम serialise_s32(buf, (पूर्णाङ्क)uv);
}

स्थिर पूर्णाङ्क
serialise_double(संरचना sshbuf *buf, द्विगुण v)
{
	/*
	 * XXX this is no good for a wire encoding.
	 * It's fine for passing configurations via RPC, but it would
	 * be nicer to have an exact binary encoding here.
	 */
	प्रत्यागम sshbuf_put(buf, &v, परिमाण(v));
}

स्थिर पूर्णाङ्क
serialise_nullable_string(संरचना sshbuf *buf, ध्रुव वर्ण *s)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_put_u8(buf, s != रिक्त)) != 0)
		प्रत्यागम r;
	यदि (s == रिक्त)
		प्रत्यागम 0;
	प्रत्यागम sshbuf_put_cstring(buf, s);
}

स्थिर पूर्णाङ्क
serialise_nullable_string_array(संरचना sshbuf *buf, वर्ण **a, u_int n)
{
	पूर्णाङ्क r;
	u_int i;

	यदि ((r = sshbuf_put_u32(buf, n)) != 0)
		प्रत्यागम r;
	प्रति (i = 0; i < n; i++) {
		यदि ((r = serialise_nullable_string(buf, a[i])) != 0)
			प्रत्यागम r;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
serialise_hostkeyfile(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i;

	यदि ((r = sshbuf_put_u32(buf, options->अङ्कः_host_कुञ्चिका_files)) != 0) {
		error_fr(r, "serialise length");
		प्रत्यागम r;
	}
	प्रति (i = 0; i < options->अङ्कः_host_कुञ्चिका_files; i++) {
		यदि ((r = serialise_s32(buf,
		    options->host_कुञ्चिका_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_कुञ्चिका_files[i])) != 0) {
			error_fr(r, "serialise member");
			प्रत्यागम r;
		}
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
serialise_ipqos(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = serialise_s32(buf, options->ip_qos_interactive)) != 0 ||
	    (r = serialise_s32(buf, options->ip_qos_bulk)) != 0) {
		error_fr(r, "serialise");
		प्रत्यागम r;
	}

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
serialise_listenaddress(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i;

	/* Note: only serialises queued listen addresses */
	यदि ((r = sshbuf_put_u32(buf, options->अङ्कः_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		प्रत्यागम r;
	}
	प्रति (i = 0; i < options->अङ्कः_queued_listens; i++) {
		ध्रुव संरचना queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		यदि ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->पत्तनम्)) != 0 ||
		    (r = serialise_nullable_string(buf, qla->rdomain)) != 0) {
			error_fr(r, "serialise member");
			प्रत्यागम r;
		}
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
serialise_logfacility(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = serialise_s32(buf, (पूर्णाङ्क)options->log_facility)) != 0) {
		error_fr(r, "serialise");
		प्रत्यागम r;
	}

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
serialise_loglevel(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = serialise_s32(buf, (पूर्णाङ्क)options->log_level)) != 0) {
		error_fr(r, "serialise");
		प्रत्यागम r;
	}

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
serialise_पत्तनम्(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i;

	यदि ((r = sshbuf_put_u32(buf, options->अङ्कः_ports)) != 0) {
		error_fr(r, "serialise length");
		प्रत्यागम r;
	}
	प्रति (i = 0; i < options->अङ्कः_ports; i++) {
		यदि ((r = serialise_s32(buf, options->ports[i])) != 0) {
			error_fr(r, "serialise port");
			प्रत्यागम r;
		}
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
serialise_gatewayports(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = serialise_s32(buf, options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "serialise");
		प्रत्यागम r;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
serialise_streamlocalbindmask(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = serialise_बहुलकम्(buf,
	    options->fwd_opts.streamlocal_bind_आवरणम्)) != 0) {
		error_fr(r, "serialise");
		प्रत्यागम r;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
serialise_streamlocalbindunlink(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_put_u8(buf,
	    (options->fwd_opts.streamlocal_bind_unlink != 0))) != 0) {
		error_fr(r, "serialise");
		प्रत्यागम r;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
serialise_maxstartups(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = serialise_s32(buf, options->max_startups_begin)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups_दरः)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups)) != 0) {
		error_fr(r, "serialise");
		प्रत्यागम r;
	}

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
serialise_permituserenv(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = serialise_s32(buf, options->permit_user_env)) != 0 ||
	    (r = serialise_nullable_string(buf,
	    options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "serialise");
		प्रत्यागम r;
	}

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
serialise_persourcenetblocksize(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = serialise_s32(buf, options->प्रत्येकम्_source_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->प्रत्येकम्_source_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		प्रत्यागम r;
	}

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
serialise_persourcepenalties(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	ध्रुव संरचना प्रत्येकम्_source_penalty *psp = &options->प्रत्येकम्_source_penalty;
	पूर्णाङ्क r;

	यदि ((r = serialise_s32(buf, psp->enabled)) != 0 ||
	    (r = serialise_s32(buf, psp->max_sources4)) != 0 ||
	    (r = serialise_s32(buf, psp->max_sources6)) != 0 ||
	    (r = serialise_s32(buf, psp->अतिप्रवाहः_बहुलकम्)) != 0 ||
	    (r = serialise_s32(buf, psp->अतिप्रवाहः_mode6)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_crash)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_grace)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_authfail)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_invaliduser)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_noauth)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_refuseconnection)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_max)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_min)) != 0) {
		error_fr(r, "serialise");
		प्रत्यागम r;
	}

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
serialise_rekeylimit(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = serialise_s64(buf, options->rekey_सीमा)) != 0 ||
	    (r = serialise_s32(buf, options->rekey_interval)) != 0) {
		error_fr(r, "serialise");
		प्रत्यागम r;
	}

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
serialise_subsystem(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i;

	यदि ((r = sshbuf_put_u32(buf, options->अङ्कः_subsystems)) != 0) {
		error_fr(r, "serialise length");
		प्रत्यागम r;
	}
	प्रति (i = 0; i < options->अङ्कः_subsystems; i++) {
		यदि ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_तर्काः[i])) != 0) {
			error_fr(r, "serialise member");
			प्रत्यागम r;
		}
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
serialise_pubkey_auth_options(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = serialise_s32(buf, options->pubkey_auth_options)) != 0 ||
	    (r = serialise_s32(buf, options->max_pubkey_ok)) != 0) {
		error_fr(r, "serialise");
		प्रत्यागम r;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
serialise_timingsecret(ध्रुव ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_put_u64(buf, options->timing_secret)) != 0) {
		error_fr(r, "serialise");
		प्रत्यागम r;
	}
	प्रत्यागम 0;
}


पूर्णाङ्क
serialise_server_options(ध्रुव ServerOptions *options, संरचना sshbuf **bufp)
{
	संरचना sshbuf *buf = रिक्त;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;

	*bufp = रिक्त;

	यदि ((buf = sshbuf_new()) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_संस्करणम्)) != 0) {
		error_fr(r, "serialise version");
		गच्छ बहिर्गमनम्;
	}

#परिभाषय SSHCONF_INT(var, conf, flags, ms, def, cp) \
	यदि ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		गच्छ बहिर्गमनम्; \
	}
#परिभाषय SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	यदि ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		गच्छ बहिर्गमनम्; \
	}
#परिभाषय SSHCONF_STRING(var, conf, flags, cp) \
	यदि ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		गच्छ बहिर्गमनम्; \
	}
#परिभाषय SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	यदि ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		गच्छ बहिर्गमनम्; \
	}
#परिभाषय SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	यदि ((r = serialise_##funcsuffix(options, buf)) != 0) \
		गच्छ बहिर्गमनम्;
#परिभाषय SSHCONF_NONCONF(funcsuffix) \
	यदि ((r = serialise_##funcsuffix(options, buf)) != 0) \
		गच्छ बहिर्गमनम्;
#परिभाषय SSHCONF_DEPRECATE(conf, flags, opcode)		/*रिक्तानि*/
#परिभाषय SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/*रिक्तानि*/
#परिभाषय SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/*रिक्तानि*/
#परिभाषय SSHCONF_ALIAS(old, conf, flags)			/*रिक्तानि*/

	SSHD_CONFIG_ENTRIES

#अपरिभाषय SSHCONF_INT
#अपरिभाषय SSHCONF_INTFLAG
#अपरिभाषय SSHCONF_STRING
#अपरिभाषय SSHCONF_STRARRAY
#अपरिभाषय SSHCONF_CUSTOM
#अपरिभाषय SSHCONF_NONCONF
#अपरिभाषय SSHCONF_DEPRECATE
#अपरिभाषय SSHCONF_UNSUPPORTED_INT
#अपरिभाषय SSHCONF_UNSUPPORTED_STRING
#अपरिभाषय SSHCONF_ALIAS

	/* success */
	r = 0;
	*bufp = buf;
	buf = रिक्त; /* transferred */
 बहिर्गमनम्:
	sshbuf_free(buf);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
deserialise_s32(संरचना sshbuf *buf, पूर्णाङ्क *v)
{
	uint32_t tmp;
	पूर्णाङ्क r;
	u_char was_signed;

	यदि ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u32(buf, &tmp)) != 0)
		प्रत्यागम r;
	यदि (was_signed > 1)
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	यदि (was_signed) {
		यदि (tmp > (uint32_t)अधिकतम_पूर्णाङ्कः + 1)
			प्रत्यागम SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)अधिकतम_पूर्णाङ्कः + 1 ? INT_MIN : -(पूर्णाङ्क)tmp;
	} अन्यथा {
		यदि (tmp > अधिकतम_पूर्णाङ्कः)
			प्रत्यागम SSH_ERR_INVALID_FORMAT;
		*v = (पूर्णाङ्क)tmp;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
deserialise_s64(संरचना sshbuf *buf, int64_t *v)
{
	uint64_t tmp;
	पूर्णाङ्क r;
	u_char was_signed;

	यदि ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u64(buf, &tmp)) != 0)
		प्रत्यागम r;
	यदि (was_signed > 1)
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	यदि (was_signed) {
		यदि (tmp > (uint64_t)INT64_MAX + 1)
			प्रत्यागम SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint64_t)INT64_MAX + 1 ?
		    INT64_MIN : -(int64_t)tmp;
	} अन्यथा {
		यदि (tmp > INT64_MAX)
			प्रत्यागम SSH_ERR_INVALID_FORMAT;
		*v = (int64_t)tmp;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
deserialise_बहुलकम्(संरचना sshbuf *buf, बहुलकम्_t *v)
{
	पूर्णाङ्क r, tmp;

	यदि ((r = deserialise_s32(buf, &tmp)) != 0)
		प्रत्यागम r;
	यदि (tmp == -1) {
		*v = (बहुलकम्_t)-1;
		प्रत्यागम 0;
	}
	यदि (tmp < 0 || tmp > 0777)
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	*v = (बहुलकम्_t)tmp;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
deserialise_double(संरचना sshbuf *buf, द्विगुण *v)
{
	प्रत्यागम sshbuf_get(buf, v, परिमाण(*v));
}

स्थिर पूर्णाङ्क
deserialise_nullable_string(संरचना sshbuf *buf, वर्ण **sp)
{
	पूर्णाङ्क r;
	u_char present;

	यदि ((r = sshbuf_get_u8(buf, &present)) != 0)
		प्रत्यागम r;
	यदि (present == 0) {
		*sp = रिक्त;
		प्रत्यागम 0;
	}
	यदि (present != 1)
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	प्रत्यागम sshbuf_get_cstring(buf, sp, रिक्त);
}

स्थिर शून्य
free_string_array(वर्ण **a, u_int n)
{
	u_int i;

	यदि (a == रिक्त)
		प्रत्यागम;
	प्रति (i = 0; i < n; i++)
		मुक्त(a[i]);
	मुक्त(a);
}

स्थिर पूर्णाङ्क
deserialise_गणनम्(संरचना sshbuf *buf, u_int *np, ध्रुव वर्ण *what)
{
	पूर्णाङ्क r;
	uint32_t n;

	यदि ((r = sshbuf_get_u32(buf, &n)) != 0) {
		error_fr(r, "deserialise %s length", what);
		प्रत्यागम r;
	}
	यदि (n > UINT_MAX) {
		error_f("bad number of %s", what);
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	}
	यदि (n > sshbuf_len(buf)) {
		error_f("bad number of %s", what);
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	}
	*np = n;
	प्रत्यागम 0;
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
	यदि ((r = deserialise_गणनम्(buf, &n, "strings")) != 0)
		प्रत्यागम r;
	यदि (n > 0)
		a = xcalloc(n, परिमाण(*a));
	प्रति (i = 0; i < n; i++) {
		यदि ((r = deserialise_nullable_string(buf, a + i)) != 0) {
			free_string_array(a, i + 1);
			प्रत्यागम r;
		}
	}
	*arrayp = a;
	*np = n;
	प्रत्यागम 0;
}

स्थिर शून्य
free_queued_listen_addrs(संरचना queued_listenaddr *qla, u_int n)
{
	u_int i;

	यदि (qla == रिक्त)
		प्रत्यागम;
	प्रति (i = 0; i < n; i++) {
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

	यदि ((r = deserialise_गणनम्(buf, &n, "host key files")) != 0)
		प्रत्यागम r;
	यदि (n > 0) {
		userprovided = xcalloc(n, परिमाण(*userprovided));
		files = xcalloc(n, परिमाण(*files));
	}
	प्रति (i = 0; i < n; i++) {
		यदि ((r = deserialise_s32(buf, userprovided + i)) != 0 ||
		    (r = deserialise_nullable_string(buf, files + i)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(files, i + 1);
			मुक्त(userprovided);
			प्रत्यागम r;
		}
	}
	options->अङ्कः_host_कुञ्चिका_files = n;
	options->host_कुञ्चिका_file_userprovided = userprovided;
	options->host_कुञ्चिका_files = files;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
deserialise_ipqos(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = deserialise_s32(buf, &options->ip_qos_interactive)) != 0 ||
	    (r = deserialise_s32(buf, &options->ip_qos_bulk)) != 0) {
		error_fr(r, "deserialise");
		प्रत्यागम r;
	}

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
deserialise_listenaddress(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i, n;
	संरचना queued_listenaddr *qla = रिक्त;

	यदि ((r = deserialise_गणनम्(buf, &n, "listen addresses")) != 0)
		प्रत्यागम r;
	यदि (n > 0)
		qla = xcalloc(n, परिमाण(*qla));
	प्रति (i = 0; i < n; i++) {
		यदि ((r = sshbuf_get_cstring(buf, &qla[i].addr, रिक्त)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].पत्तनम्)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			प्रत्यागम r;
		}
	}
	options->अङ्कः_queued_listens = n;
	options->queued_listen_addrs = qla;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
deserialise_logfacility(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r, tmp;

	यदि ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		प्रत्यागम r;
	}
	यदि (tmp != SYSLOG_FACILITY_NOT_समुच्चयः &&
	    log_facility_name((SyslogFacility)tmp) == रिक्त) {
		error_f("bad syslog facility");
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	}
	options->log_facility = (SyslogFacility)tmp;

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
deserialise_loglevel(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r, tmp;

	यदि ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		प्रत्यागम r;
	}
	यदि (tmp != SYSLOG_LEVEL_NOT_समुच्चयः &&
	    log_level_name((LogLevel)tmp) == रिक्त) {
		error_f("bad log level");
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
deserialise_पत्तनम्(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i, n;

	यदि ((r = deserialise_गणनम्(buf, &n, "ports")) != 0)
		प्रत्यागम r;
	यदि (n > MAX_PORTS) {
		error_f("bad number of ports");
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	}
	options->अङ्कः_ports = n;
	स्मृतिं_पूरय(options->ports, 0, परिमाण(options->ports));
	प्रति (i = 0; i < options->अङ्कः_ports; i++) {
		यदि ((r = deserialise_s32(buf, options->ports + i)) != 0) {
			error_fr(r, "deserialise port");
			प्रत्यागम r;
		}
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
deserialise_gatewayports(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = deserialise_s32(buf, &options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "deserialise");
		प्रत्यागम r;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
deserialise_streamlocalbindmask(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = deserialise_बहुलकम्(buf,
	    &options->fwd_opts.streamlocal_bind_आवरणम्)) != 0) {
		error_fr(r, "deserialise");
		प्रत्यागम r;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
deserialise_streamlocalbindunlink(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_char tmp;

	यदि ((r = sshbuf_get_u8(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		प्रत्यागम r;
	}
	यदि (tmp > 1) {
		error_f("bad boolean");
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	}
	options->fwd_opts.streamlocal_bind_unlink = tmp;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
deserialise_maxstartups(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = deserialise_s32(buf, &options->max_startups_begin)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups_दरः)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups)) != 0) {
		error_fr(r, "deserialise");
		प्रत्यागम r;
	}

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
deserialise_permituserenv(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = deserialise_s32(buf, &options->permit_user_env)) != 0 ||
	    (r = deserialise_nullable_string(buf,
	    &options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "deserialise");
		प्रत्यागम r;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
deserialise_persourcenetblocksize(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = deserialise_s32(buf,
	    &options->प्रत्येकम्_source_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->प्रत्येकम्_source_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		प्रत्यागम r;
	}

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
deserialise_persourcepenalties(ServerOptions *options, संरचना sshbuf *buf)
{
	संरचना प्रत्येकम्_source_penalty *psp = &options->प्रत्येकम्_source_penalty;
	पूर्णाङ्क r;

	यदि ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
	    (r = deserialise_s32(buf, &psp->max_sources4)) != 0 ||
	    (r = deserialise_s32(buf, &psp->max_sources6)) != 0 ||
	    (r = deserialise_s32(buf, &psp->अतिप्रवाहः_बहुलकम्)) != 0 ||
	    (r = deserialise_s32(buf, &psp->अतिप्रवाहः_mode6)) != 0 ||
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
		प्रत्यागम r;
	}

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
deserialise_rekeylimit(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = deserialise_s64(buf, &options->rekey_सीमा)) != 0 ||
	    (r = deserialise_s32(buf, &options->rekey_interval)) != 0) {
		error_fr(r, "deserialise");
		प्रत्यागम r;
	}

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
deserialise_subsystem(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;
	u_int i, n;
	वर्ण **नामानि = रिक्त, **commands = रिक्त, **तर्काः = रिक्त;

	यदि ((r = deserialise_गणनम्(buf, &n, "subsystems")) != 0)
		प्रत्यागम r;
	यदि (n > 0) {
		नामानि = xcalloc(n, परिमाण(*नामानि));
		commands = xcalloc(n, परिमाण(*नामानि));
		तर्काः = xcalloc(n, परिमाण(*तर्काः));
	}
	प्रति (i = 0; i < n; i++) {
		यदि ((r = sshbuf_get_cstring(buf, नामानि + i, रिक्त)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, रिक्त)) != 0 ||
		    (r = sshbuf_get_cstring(buf, तर्काः + i, रिक्त)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(नामानि, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(तर्काः, i + 1);
			प्रत्यागम r;
		}
	}
	options->अङ्कः_subsystems = n;
	options->subsystem_name = नामानि;
	options->subsystem_command = commands;
	options->subsystem_तर्काः = तर्काः;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
deserialise_pubkey_auth_options(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = deserialise_s32(buf, &options->pubkey_auth_options)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_pubkey_ok)) != 0) {
		error_fr(r, "deserialise");
		प्रत्यागम r;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
deserialise_timingsecret(ServerOptions *options, संरचना sshbuf *buf)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_get_u64(buf, &options->timing_secret)) != 0) {
		error_fr(r, "deserialise");
		प्रत्यागम r;
	}
	प्रत्यागम 0;
}

पूर्णाङ्क
deserialise_server_options(संरचना sshbuf *buf, ServerOptions *options)
{
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;
	uint32_t संस्करणम्;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	यदि ((r = sshbuf_get_u32(buf, &संस्करणम्)) != 0) {
		error_fr(r, "deserialise version");
		गच्छ बहिर्गमनम्;
	}
	यदि (संस्करणम् != SSHD_CONFIG_BLOB_संस्करणम्) {
		error_f("unsupported config blob version %u", संस्करणम्);
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
#परिभाषय SSHCONF_INT(var, conf, flags, ms, def, cp) \
	यदि ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		गच्छ बहिर्गमनम्; \
	}
#परिभाषय SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	यदि ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		गच्छ बहिर्गमनम्; \
	}
#परिभाषय SSHCONF_STRING(var, conf, flags, cp) \
	यदि ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		गच्छ बहिर्गमनम्; \
	}
#परिभाषय SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	यदि ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		गच्छ बहिर्गमनम्; \
	}
#परिभाषय SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	यदि ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		गच्छ बहिर्गमनम्;
#परिभाषय SSHCONF_NONCONF(funcsuffix) \
	यदि ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		गच्छ बहिर्गमनम्;
#परिभाषय SSHCONF_DEPRECATE(conf, flags, opcode)		/*रिक्तानि*/
#परिभाषय SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#परिभाषय SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	कुरु { \
		मुक्त(new_options.var); \
		new_options.var = रिक्त; \
	} यावत् (0);
#परिभाषय SSHCONF_ALIAS(old, conf, flags)			/*रिक्तानि*/

	SSHD_CONFIG_ENTRIES

	यदि (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}

#अपरिभाषय SSHCONF_INT
#अपरिभाषय SSHCONF_INTFLAG
#अपरिभाषय SSHCONF_STRING
#अपरिभाषय SSHCONF_STRARRAY
#अपरिभाषय SSHCONF_CUSTOM
#अपरिभाषय SSHCONF_NONCONF
#अपरिभाषय SSHCONF_DEPRECATE
#अपरिभाषय SSHCONF_UNSUPPORTED_INT
#अपरिभाषय SSHCONF_UNSUPPORTED_STRING
#अपरिभाषय SSHCONF_ALIAS

	/* success */
	r = 0;
	free_server_options(options);
	*options = new_options;
	स्मृतिं_पूरय(&new_options, 0, परिमाण(new_options));
 बहिर्गमनम्:
	free_server_options(&new_options);
	प्रत्यागम r;
}

स्थिर शून्य
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	प्रति (i = 0; i < options->अङ्कः_host_कुञ्चिका_files; i++)
		मुक्त(options->host_कुञ्चिका_files[i]);
	मुक्त(options->host_कुञ्चिका_files);
	मुक्त(options->host_कुञ्चिका_file_userprovided);
}

स्थिर शून्य
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->अङ्कः_queued_listens);

	प्रति (i = 0; i < options->अङ्कः_listen_addrs; i++) {
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

	प्रति (i = 0; i < options->अङ्कः_subsystems; i++) {
		मुक्त(options->subsystem_name[i]);
		मुक्त(options->subsystem_command[i]);
		मुक्त(options->subsystem_तर्काः[i]);
	}
	मुक्त(options->subsystem_name);
	मुक्त(options->subsystem_command);
	मुक्त(options->subsystem_तर्काः);
}

शून्य
free_server_options(ServerOptions *options)
{
#परिभाषय SSHCONF_INT(var, conf, flags, ms, def, cp)	/*रिक्तानि*/
#परिभाषय SSHCONF_INTFLAG(var, conf, flags, def, cp)	/*रिक्तानि*/
#परिभाषय SSHCONF_STRING(var, conf, flags, cp)		मुक्त(options->var);
#परिभाषय SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#परिभाषय SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#परिभाषय SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#परिभाषय SSHCONF_DEPRECATE(conf, flags, opcode)		/*रिक्तानि*/
#परिभाषय SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#परिभाषय SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	कुरु { \
		मुक्त(options->var); \
		options->var = रिक्त; \
	} यावत् (0);
#परिभाषय SSHCONF_ALIAS(old, conf, flags)			/*रिक्तानि*/

#परिभाषय free_ipqos(options)
#परिभाषय free_logfacility(options)
#परिभाषय free_loglevel(options)
#परिभाषय free_पत्तनम्(options)
#परिभाषय free_gatewayports(options)
#परिभाषय free_streamlocalbindmask(options)
#परिभाषय free_streamlocalbindunlink(options)
#परिभाषय free_maxstartups(options)
#परिभाषय free_persourcenetblocksize(options)
#परिभाषय free_persourcepenalties(options)
#परिभाषय free_rekeylimit(options)
#परिभाषय free_pubkey_auth_options(options)
#परिभाषय free_timingsecret(options)

	SSHD_CONFIG_ENTRIES

#अपरिभाषय free_ipqos
#अपरिभाषय free_logfacility
#अपरिभाषय free_loglevel
#अपरिभाषय free_पत्तनम्
#अपरिभाषय free_gatewayports
#अपरिभाषय free_streamlocalbindmask
#अपरिभाषय free_streamlocalbindunlink
#अपरिभाषय free_maxstartups
#अपरिभाषय free_persourcenetblocksize
#अपरिभाषय free_persourcepenalties
#अपरिभाषय free_rekeylimit
#अपरिभाषय free_timingsecret

#अपरिभाषय SSHCONF_INT
#अपरिभाषय SSHCONF_INTFLAG
#अपरिभाषय SSHCONF_STRING
#अपरिभाषय SSHCONF_STRARRAY
#अपरिभाषय SSHCONF_CUSTOM
#अपरिभाषय SSHCONF_NONCONF
#अपरिभाषय SSHCONF_DEPRECATE
#अपरिभाषय SSHCONF_UNSUPPORTED_INT
#अपरिभाषय SSHCONF_UNSUPPORTED_STRING
#अपरिभाषय SSHCONF_ALIAS

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
copy_server_option_string(वर्ण **dst, ध्रुव वर्ण *src)
{
	यदि (src != रिक्त && *dst != src) {
		मुक्त(*dst);
		*dst = xstrdup(src);
	}
}

स्थिर शून्य
copy_server_option_strarray_मानानि(वर्ण ***dst, u_int ndst,
    वर्ण * ध्रुव *src, u_int nsrc)
{
	u_int i;

	यदि (nsrc == 0)
		प्रत्यागम;
	प्रति (i = 0; i < ndst; i++)
		मुक्त((*dst)[i]);
	मुक्त(*dst);
	*dst = xcalloc(nsrc, परिमाण(**dst));
	प्रति (i = 0; i < nsrc; i++)
		(*dst)[i] = src[i] == रिक्त ? रिक्त : xstrdup(src[i]);
}

स्थिर शून्य
copy_server_option_strarray(वर्ण ***dst, u_int *ndst,
    वर्ण * ध्रुव *src, u_int nsrc)
{
	यदि (nsrc == 0)
		प्रत्यागम;
	copy_server_option_strarray_मानानि(dst, *ndst, src, nsrc);
	*ndst = nsrc;
}

स्थिर शून्य
copy_ipqos(ServerOptions *dst, ध्रुव ServerOptions *src)
{
	copy_server_option_int(&dst->ip_qos_interactive,
	    src->ip_qos_interactive);
	copy_server_option_int(&dst->ip_qos_bulk, src->ip_qos_bulk);
}

स्थिर शून्य
copy_gatewayports(ServerOptions *dst, ध्रुव ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.gateway_ports,
	    src->fwd_opts.gateway_ports);
}

स्थिर शून्य
copy_streamlocalbindunlink(ServerOptions *dst, ध्रुव ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.streamlocal_bind_unlink,
	    src->fwd_opts.streamlocal_bind_unlink);
}

स्थिर शून्य
copy_loglevel(ServerOptions *dst, ध्रुव ServerOptions *src)
{
	यदि (src->log_level != -1)
		dst->log_level = src->log_level;
}

स्थिर शून्य
copy_rekeylimit(ServerOptions *dst, ध्रुव ServerOptions *src)
{
	copy_server_option_int64(&dst->rekey_सीमा, src->rekey_सीमा);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

स्थिर शून्य
copy_subsystem(ServerOptions *dst, ध्रुव ServerOptions *src)
{
	u_int old_अङ्कः_subsystems = dst->अङ्कः_subsystems;

	यदि (src->अङ्कः_subsystems == 0)
		प्रत्यागम;
	copy_server_option_strarray_मानानि(&dst->subsystem_name,
	    old_अङ्कः_subsystems, src->subsystem_name, src->अङ्कः_subsystems);
	copy_server_option_strarray_मानानि(&dst->subsystem_command,
	    old_अङ्कः_subsystems, src->subsystem_command, src->अङ्कः_subsystems);
	copy_server_option_strarray_मानानि(&dst->subsystem_तर्काः,
	    old_अङ्कः_subsystems, src->subsystem_तर्काः, src->अङ्कः_subsystems);
	dst->अङ्कः_subsystems = src->अङ्कः_subsystems;
}

स्थिर शून्य
copy_pubkey_auth_options(ServerOptions *dst, ध्रुव ServerOptions *src)
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
copy_समुच्चयः_server_options(ServerOptions *dst, ServerOptions *src, पूर्णाङ्क preauth)
{
	यदि (dst == src)
		प्रत्यागम;

#परिभाषय SSHCONF_INT(var, conf, flags, ms, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#परिभाषय SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#परिभाषय SSHCONF_STRING(var, conf, flags, cp) \
	cp(copy_server_option_string(&dst->var, src->var);)
#परिभाषय SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	cp(copy_server_option_strarray(&dst->var, &dst->nvar, \
	    src->var, src->nvar);)
#परिभाषय SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	cp(copy_##funcsuffix(dst, src);)
#परिभाषय SSHCONF_NONCONF(funcsuffix)			/*रिक्तानि*/
#परिभाषय SSHCONF_DEPRECATE(conf, flags, opcode)		/*रिक्तानि*/
#परिभाषय SSHCONF_UNSUPPORTED_INT(var, conf, flags)	dst->var = 0;
#परिभाषय SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	कुरु { \
		मुक्त(dst->var); \
		dst->var = रिक्त; \
	} यावत् (0);
#परिभाषय SSHCONF_ALIAS(old, conf, flags)			/*रिक्तानि*/

	SSHD_CONFIG_ENTRIES

#अपरिभाषय SSHCONF_INT
#अपरिभाषय SSHCONF_INTFLAG
#अपरिभाषय SSHCONF_STRING
#अपरिभाषय SSHCONF_STRARRAY
#अपरिभाषय SSHCONF_CUSTOM
#अपरिभाषय SSHCONF_NONCONF
#अपरिभाषय SSHCONF_DEPRECATE
#अपरिभाषय SSHCONF_UNSUPPORTED_INT
#अपरिभाषय SSHCONF_UNSUPPORTED_STRING
#अपरिभाषय SSHCONF_ALIAS

	/*
	 * The bind_mask is a mode_t that may be unsigned, so we can't use
	 * copy_server_option_int - it does a signed comparison that causes
	 * compiler warnings.
	 */
	यदि (src->fwd_opts.streamlocal_bind_आवरणम् != (बहुलकम्_t)-1) {
		dst->fwd_opts.streamlocal_bind_आवरणम् =
		    src->fwd_opts.streamlocal_bind_आवरणम्;
	}

	/* Arguments that accept '+...' need to be expanded */
	assemble_algorithms(dst);

	/*
	 * These options may be "none" to clear a global setting.  They are
	 * consulted before authentication, so they must be cleared here
	 * rather than in the post-auth section below.
	 */
#परिभाषय CLEAR_ON_NONE(v) \
	कुरु { \
		यदि (option_clear_or_none(v)) { \
			मुक्त(v); \
			v = रिक्त; \
		} \
	} यावत्(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_कुञ्चिकाः);
	CLEAR_ON_NONE(dst->banner);

	/*
	 * The only things that should be below this point are string options
	 * which are only used after authentication.
	 */
	यदि (preauth)
		प्रत्यागम;

	/* These options may be "none" to clear a global setting */
	copy_server_option_string(&dst->adm_forced_command,
	    src->adm_forced_command);
	copy_server_option_string(&dst->chroot_directory,
	    src->chroot_directory);
	CLEAR_ON_NONE(dst->chroot_directory);
	CLEAR_ON_NONE(dst->adm_forced_command);
#अपरिभाषय CLEAR_ON_NONE

	/* Subsystems require merging. */
	servconf_merge_subsystems(dst, src);
}

#परिभाषय SERVCONF_MAX_गभीरता	16
स्थिर शून्य
parse_server_config_गभीरता(ServerOptions *options, ध्रुव वर्ण *filename,
    संरचना sshbuf *conf, संरचना include_list *includes,
    संरचना connection_info *connectinfo, पूर्णाङ्क flags, पूर्णाङ्क *activep, पूर्णाङ्क गभीरता)
{
	पूर्णाङ्क linenum, bad_options = 0;
	वर्ण *cp, *obuf, *cbuf;

	यदि (गभीरता < 0 || गभीरता > SERVCONF_MAX_गभीरता)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	यदि ((obuf = cbuf = sshbuf_dup_string(conf)) == रिक्त)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	यावत् ((cp = strsep(&cbuf, "\n")) != रिक्त) {
		यदि (process_server_config_पङ्क्तिः_गभीरता(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    गभीरता, includes) != 0)
			bad_options++;
	}
	मुक्त(obuf);
	यदि (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

शून्य
parse_server_config(ServerOptions *options, ध्रुव वर्ण *filename,
    संरचना sshbuf *conf, संरचना include_list *includes,
    संरचना connection_info *connectinfo, पूर्णाङ्क reexec)
{
	पूर्णाङ्क सक्रिय = connectinfo ? 0 : 1;
	parse_server_config_गभीरता(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_मेलनम्_ONLY : 0), &सक्रिय, 0);
	यदि (!reexec)
		process_queued_listen_addrs(options);
}

स्थिर ध्रुव वर्ण *
fmt_multistate_int(पूर्णाङ्क val, ध्रुव संरचना multistate *m)
{
	u_int i;

	प्रति (i = 0; m[i].कुञ्चिका != रिक्त; i++) {
		यदि (m[i].मानम् == val)
			प्रत्यागम m[i].कुञ्चिका;
	}
	प्रत्यागम "UNKNOWN";
}

स्थिर ध्रुव वर्ण *
fmt_intarg(ServerOpCodes संहिता, पूर्णाङ्क val)
{
	यदि (val == -1)
		प्रत्यागम "unset";
	विकल्प (संहिता) {
	पक्ष s_स्थानाङ्कः_Family:
		प्रत्यागम fmt_multistate_int(val, multistate_addressfamily);
	पक्ष s_Permit_मूलम्_Login:
		प्रत्यागम fmt_multistate_int(val, multistate_permitrootlogin);
	पक्ष sGatewayPorts:
		प्रत्यागम fmt_multistate_int(val, multistate_gatewayports);
	पक्ष sCompression:
		प्रत्यागम fmt_multistate_int(val, multistate_compression);
	पक्ष sAllowTcpForwarding:
		प्रत्यागम fmt_multistate_int(val, multistate_tcpfwd);
	पक्ष s_Allow_प्रवाहः_Local_Forwarding:
		प्रत्यागम fmt_multistate_int(val, multistate_tcpfwd);
	पक्ष sIgnoreRhosts:
		प्रत्यागम fmt_multistate_int(val, multistate_ignore_rhosts);
	पक्ष sTCPKeepAlive:
		प्रत्यागम fmt_multistate_int(val, multistate_keepalives);
	पक्ष sWarnWeakCrypto:
		प्रत्यागम fmt_multistate_int(val, multistate_warnweakcrypto);
	पक्ष sFingerprintHash:
		प्रत्यागम ssh_digest_alg_name(val);
	स्वभाव:
		विकल्प (val) {
		पक्ष 0:
			प्रत्यागम "no";
		पक्ष 1:
			प्रत्यागम "yes";
		स्वभाव:
			प्रत्यागम "UNKNOWN";
		}
	}
}

स्थिर शून्य
dump_cfg_int(ServerOpCodes संहिता, पूर्णाङ्क val)
{
	यदि (संहिता == s_अप्रयुक्तम्_Connection_Timeout && val == 0) {
		प्रारूप_लिख("%s none\n", lookup_opcode_name(संहिता));
		प्रत्यागम;
	}
	प्रारूप_लिख("%s %d\n", lookup_opcode_name(संहिता), val);
}

स्थिर शून्य
dump_cfg_oct(ServerOpCodes संहिता, पूर्णाङ्क val)
{
	प्रारूप_लिख("%s 0%o\n", lookup_opcode_name(संहिता), val);
}

स्थिर शून्य
dump_cfg_fmtint(ServerOpCodes संहिता, पूर्णाङ्क val)
{
	प्रारूप_लिख("%s %s\n", lookup_opcode_name(संहिता), fmt_intarg(संहिता, val));
}

स्थिर शून्य
dump_cfg_string(ServerOpCodes संहिता, ध्रुव वर्ण *val)
{
	प्रारूप_लिख("%s %s\n", lookup_opcode_name(संहिता),
	    val == रिक्त ? "none" : val);
}

स्थिर शून्य
dump_cfg_strarray(ServerOpCodes संहिता, u_int गणनम्, वर्ण **vals)
{
	u_int i;

	प्रति (i = 0; i < गणनम्; i++)
		प्रारूप_लिख("%s %s\n", lookup_opcode_name(संहिता), vals[i]);
}

स्थिर शून्य
dump_cfg_strarray_oneline(ServerOpCodes संहिता, u_int गणनम्, वर्ण **vals)
{
	u_int i;

	विकल्प (संहिता) {
	पक्ष sAuthenticationMethods:
	पक्ष sChannelTimeout:
		भङ्ग;
	स्वभाव:
		यदि (गणनम् <= 0)
			प्रत्यागम;
		भङ्ग;
	}

	प्रारूप_लिख("%s", lookup_opcode_name(संहिता));
	प्रति (i = 0; i < गणनम्; i++)
		प्रारूप_लिख(" %s",  vals[i]);
	यदि (संहिता == sAuthenticationMethods && गणनम् == 0)
		प्रारूप_लिख(" any");
	अन्यथा यदि (संहिता == sChannelTimeout && गणनम् == 0)
		प्रारूप_लिख(" none");
	प्रारूप_लिख("\n");
}

स्थिर वर्ण *
format_listen_addrs(संरचना listenaddr *la)
{
	पूर्णाङ्क r;
	संरचना addrinfo *ai;
	वर्ण addr[NI_MAXHOST], पत्तनम्[NI_MAXSERV];
	वर्ण *laddr1 = xstrdup(""), *laddr2 = रिक्त;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	प्रति (ai = la->addrs; ai; ai = ai->ai_next) {
		यदि ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    परिमाण(addr), पत्तनम्, परिमाण(पत्तनम्),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			अनुवर्त;
		}
		laddr2 = laddr1;
		यदि (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, पत्तनम्,
			    la->rdomain == रिक्त ? "" : " rdomain ",
			    la->rdomain == रिक्त ? "" : la->rdomain,
			    laddr2);
		} अन्यथा {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, पत्तनम्,
			    la->rdomain == रिक्त ? "" : " rdomain ",
			    la->rdomain == रिक्त ? "" : la->rdomain,
			    laddr2);
		}
		मुक्त(laddr2);
	}
	प्रत्यागम laddr1;
}

शून्य
dump_config(ServerOptions *o)
{
	वर्ण *s;
	u_int i;

	/* these are usually at the top of the config */
	प्रति (i = 0; i < o->अङ्कः_ports; i++)
		प्रारूप_लिख("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(s_स्थानाङ्कः_Family, o->स्थानाङ्कः_family);

	प्रति (i = 0; i < o->अङ्कः_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		प्रारूप_लिख("%s", s);
		मुक्त(s);
	}

	/* integer arguments */
#यदि_परिभाषितम् USE_PAM
	dump_cfg_fmtint(sUsePAM, o->use_pam);
	dump_cfg_string(sPAMServiceName, o->pam_service_name);
#यदि_अन्तः
	dump_cfg_int(sLoginGraceTime, o->login_grace_time);
	dump_cfg_int(s_X11_Display_विस्थापनम्, o->x11_display_विस्थापनम्);
	dump_cfg_int(sMaxAuthTries, o->max_authtries);
	dump_cfg_int(sMaxSessions, o->max_sessions);
	dump_cfg_int(sClientAliveInterval, o->client_alive_interval);
	dump_cfg_int(s_Client_Alive_गणनम्_Max, o->client_alive_गणनम्_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_आकार);
	dump_cfg_oct(s_प्रवाहः_Local_Bind_आवरणम्, o->fwd_opts.streamlocal_bind_आवरणम्);
	dump_cfg_int(s_अप्रयुक्तम्_Connection_Timeout, o->अप्रयुक्तम्_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(s_Permit_मूलम्_Login, o->permit_मूलम्_login);
	dump_cfg_fmtint(sIgnoreRhosts, o->ignore_rhosts);
	dump_cfg_fmtint(s_Ignore_User_ज्ञातम्_Hosts, o->ignore_user_ज्ञातम्_hosts);
	dump_cfg_fmtint(sHostbasedAuthentication, o->hostbased_authentication);
	dump_cfg_fmtint(s_Hostbased_उपयुङ्क्ते_Name_From_Packet_Only,
	    o->hostbased_उपयुङ्क्ते_name_from_packet_only);
	dump_cfg_fmtint(sPubkeyAuthentication, o->pubkey_authentication);
#यदि_परिभाषितम् KRB5
	dump_cfg_fmtint(sKerberosAuthentication, o->kerberos_authentication);
	dump_cfg_fmtint(sKerberosOrLocalPasswd, o->kerberos_or_local_passwd);
	dump_cfg_fmtint(sKerberosTicketCleanup, o->kerberos_ticket_cleanup);
# ifdef USE_AFS
	dump_cfg_fmtint(sKerberosGetAFSToken, o->kerberos_get_afs_token);
# endif
#यदि_अन्तः
#यदि_परिभाषितम् GSSAPI
	dump_cfg_fmtint(sGSSAPIAuthentication, o->gss_authentication);
	dump_cfg_fmtint(sGSSAPICleanupCredentials, o->gss_cleanup_creds);
	dump_cfg_fmtint(sGSSAPIDelegateCredentials, o->gss_deleg_creds);
	dump_cfg_fmtint(sGSSAPIStrictAcceptorCheck, o->gss_strict_acceptor);
#यदि_अन्तः
	dump_cfg_fmtint(sPasswordAuthentication, o->password_authentication);
	dump_cfg_fmtint(sKbdInteractiveAuthentication,
	    o->kbd_interactive_authentication);
	dump_cfg_fmtint(sPrintMotd, o->print_motd);
#यदि_अपरिभाषितम् DISABLE_LASTLOG
	dump_cfg_fmtint(s_Print_चरमः_Log, o->print_lastlog);
#यदि_अन्तः
	dump_cfg_fmtint(sX11Forwarding, o->x11_forwarding);
	dump_cfg_fmtint(sX11UseLocalhost, o->x11_use_localhost);
	dump_cfg_fmtint(sPermitTTY, o->permit_tty);
	dump_cfg_fmtint(sPermitUserRC, o->permit_user_rc);
	dump_cfg_fmtint(sStrictModes, o->strict_modes);
	dump_cfg_fmtint(sTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(s_Permit_रिक्तानि_Passwords, o->permit_रिक्तानि_passwd);
	dump_cfg_fmtint(sCompression, o->compression);
	dump_cfg_fmtint(sGatewayPorts, o->fwd_opts.gateway_ports);
	dump_cfg_fmtint(sUseDNS, o->use_dns);
	dump_cfg_fmtint(sAllowTcpForwarding, o->allow_tcp_forwarding);
	dump_cfg_fmtint(sAllowAgentForwarding, o->allow_agent_forwarding);
	dump_cfg_fmtint(sDisableForwarding, o->disable_forwarding);
	dump_cfg_fmtint(s_Allow_प्रवाहः_Local_Forwarding, o->allow_streamlocal_forwarding);
	dump_cfg_fmtint(s_प्रवाहः_Local_Bind_Unlink, o->fwd_opts.streamlocal_bind_unlink);
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
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_कुञ्चिकाः);
	dump_cfg_string(s_Security_कुञ्चिका_Provider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(s_संस्करणम्_Addendum, *o->संस्करणम्_addendum == '\0'
	    ? "none" : o->संस्करणम्_addendum);
	dump_cfg_string(s_Authorized_कुञ्चिकाः_Command, o->authorized_कुञ्चिकाः_command);
	dump_cfg_string(s_Authorized_कुञ्चिकाः_Command_User, o->authorized_कुञ्चिकाः_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(s_Host_कुञ्चिका_Agent, o->host_कुञ्चिका_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(s_Host_कुञ्चिका_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#यदि defined(__OpenBSD__) || defined(HAVE_SYS_समुच्चयः_PROCESS_RDOMAIN)
	dump_cfg_string(sRDomain, o->routing_domain);
#यदि_अन्तः
	dump_cfg_string(s_Sshd_Session_मार्गः, o->sshd_session_मार्गः);
	dump_cfg_string(s_Sshd_Auth_मार्गः, o->sshd_auth_मार्गः);
	dump_cfg_string(s_प्रत्येकम्_Source_Penalty_Exempt_List, o->प्रत्येकम्_source_penalty_exempt);
	dump_cfg_string(s_Agent_Socket_मार्गः, o->agent_socket_मार्गः);

	/* string arguments requiring a lookup */
	dump_cfg_string(sLogLevel, log_level_name(o->log_level));
	dump_cfg_string(sSyslogFacility, log_facility_name(o->log_facility));

	/* string array arguments */
	dump_cfg_strarray_oneline(s_Authorized_कुञ्चिकाः_File, o->अङ्कः_authkeys_files,
	    o->authorized_कुञ्चिकाः_files);
	dump_cfg_strarray_oneline(s_Revoked_कुञ्चिकाः, o->अङ्कः_revoked_कुञ्चिकाः_files,
	    o->revoked_कुञ्चिकाः_files);
	dump_cfg_strarray(s_Host_कुञ्चिका, o->अङ्कः_host_कुञ्चिका_files, o->host_कुञ्चिका_files);
	dump_cfg_strarray(sHostCertificate, o->अङ्कः_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->अङ्कः_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->अङ्कः_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->अङ्कः_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->अङ्कः_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->अङ्कः_accept_env, o->accept_env);
	dump_cfg_strarray(s_समुच्चयः_Env, o->अङ्कः_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->अङ्कः_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->अङ्कः_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->अङ्कः_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	प्रति (i = 0; i < o->अङ्कः_subsystems; i++)
		प्रारूप_लिख("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_तर्काः[i]);

	प्रारूप_लिख("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_दरः, o->max_startups);
	प्रारूप_लिख("PerSourceMaxStartups ");
	यदि (o->प्रत्येकम्_source_max_startups == अधिकतम_पूर्णाङ्कः)
		प्रारूप_लिख("none\n");
	अन्यथा
		प्रारूप_लिख("%d\n", o->प्रत्येकम्_source_max_startups);
	प्रारूप_लिख("PerSourceNetBlockSize %d:%d\n", o->प्रत्येकम्_source_masklen_ipv4,
	    o->प्रत्येकम्_source_masklen_ipv6);

	s = रिक्त;
	प्रति (i = 0; tunmode_desc[i].val != -1; i++) {
		यदि (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].text;
			भङ्ग;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	प्रारूप_लिख("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	प्रारूप_लिख("%s\n", iptos2str(o->ip_qos_bulk));

	प्रारूप_लिख("RekeyLimit %llu %d\n", (अचिह्नित दीर्घ दीर्घ)o->rekey_सीमा,
	    o->rekey_interval);

	प्रारूप_लिख("PermitOpen");
	यदि (o->अङ्कः_permitted_opens == 0)
		प्रारूप_लिख(" any");
	अन्यथा {
		प्रति (i = 0; i < o->अङ्कः_permitted_opens; i++)
			प्रारूप_लिख(" %s", o->permitted_opens[i]);
	}
	प्रारूप_लिख("\n");
	प्रारूप_लिख("PermitListen");
	यदि (o->अङ्कः_permitted_listens == 0)
		प्रारूप_लिख(" any");
	अन्यथा {
		प्रति (i = 0; i < o->अङ्कः_permitted_listens; i++)
			प्रारूप_लिख(" %s", o->permitted_listens[i]);
	}
	प्रारूप_लिख("\n");

	यदि (o->permit_user_env_allowlist == रिक्त) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} अन्यथा {
		प्रारूप_लिख("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	प्रारूप_लिख("PubkeyAuthOptions");
	यदि (o->pubkey_auth_options == 0)
		प्रारूप_लिख(" none");
	यदि (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		प्रारूप_लिख(" touch-required");
	यदि (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		प्रारूप_लिख(" verify-required");
	यदि (o->max_pubkey_ok != -1)
		प्रारूप_लिख(" max-pk-ok:%d", o->max_pubkey_ok);
	प्रारूप_लिख("\n");

	यदि (o->प्रत्येकम्_source_penalty.enabled) {
		प्रारूप_लिख("PerSourcePenalties crash:%f authfail:%f noauth:%f "
		    "invaliduser:%f "
		    "grace-exceeded:%f refuseconnection:%f max:%f min:%f "
		    "max-sources4:%d max-sources6:%d "
		    "overflow:%s overflow6:%s\n",
		    o->प्रत्येकम्_source_penalty.penalty_crash,
		    o->प्रत्येकम्_source_penalty.penalty_authfail,
		    o->प्रत्येकम्_source_penalty.penalty_noauth,
		    o->प्रत्येकम्_source_penalty.penalty_invaliduser,
		    o->प्रत्येकम्_source_penalty.penalty_grace,
		    o->प्रत्येकम्_source_penalty.penalty_refuseconnection,
		    o->प्रत्येकम्_source_penalty.penalty_max,
		    o->प्रत्येकम्_source_penalty.penalty_min,
		    o->प्रत्येकम्_source_penalty.max_sources4,
		    o->प्रत्येकम्_source_penalty.max_sources6,
		    o->प्रत्येकम्_source_penalty.अतिप्रवाहः_बहुलकम् ==
		    प्रत्येकम्_SOURCE_PENALTY_अतिप्रवाहः_DENY_ALL ?
		    "deny-all" : "permissive",
		    o->प्रत्येकम्_source_penalty.अतिप्रवाहः_mode6 ==
		    प्रत्येकम्_SOURCE_PENALTY_अतिप्रवाहः_DENY_ALL ?
		    "deny-all" : "permissive");
	} अन्यथा
		प्रारूप_लिख("PerSourcePenalties no\n");
}
