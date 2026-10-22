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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/queue.h>
#అన్తర్భావ <sys/stat.h>
#నిర్వచితమైతే __OpenBSD__
#అన్తర్భావ <sys/sysctl.h>
#అయితే_ముగింపు

#అన్తర్భావ <netinet/in.h>
#అన్తర్భావ <netinet/ip.h>
#నిర్వచితమైతే HAVE_NET_ROUTE_H
#అన్తర్భావ <net/route.h>
#అయితే_ముగింపు

#అన్తర్భావ <ctype.h>
#అన్తర్భావ <glob.h>
#అన్తర్భావ <netdb.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <limits.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <util.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "cipher.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "mac.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "channels.h"
#అన్తర్భావ "groupaccess.h"
#అన్తర్భావ "canohost.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "myproposal.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "version.h"

#నిర్వచించు SSHD_CONFIG_BLOB_సంస్కరణ	1

#ఒకవేళ !defined(SSHD_PAM_SERVICE)
# define SSHD_PAM_SERVICE		"sshd"
#అయితే_ముగింపు

స్థిర శూన్య కూడు_listen_addr(ServerOptions *, స్థిరరాశి అక్షరం *,
    స్థిరరాశి అక్షరం *, పూర్ణాంకం);
స్థిర శూన్య కూడు_one_listen_addr(ServerOptions *, స్థిరరాశి అక్షరం *,
    స్థిరరాశి అక్షరం *, పూర్ణాంకం);
స్థిర శూన్య parse_server_config_లోతు(ServerOptions *options,
    స్థిరరాశి అక్షరం *filename, నిర్మాణం sshbuf *conf, నిర్మాణం include_list *includes,
    నిర్మాణం connection_info *connectinfo, పూర్ణాంకం flags, పూర్ణాంకం *activep, పూర్ణాంకం లోతు);

బాహ్య నిర్మాణం sshbuf *cfg;

/* Initializes the server options to their default values. */

శూన్య
initialize_server_options(ServerOptions *options)
{
	memset(options, 0, పరిమాణం(*options));
#నిర్వచించు SSHCONF_INT(var, conf, flags, ms, def, cp)	options->var = -1;
#నిర్వచించు SSHCONF_INTFLAG(var, conf, flags, def, cp)	options->var = -1;
#నిర్వచించు SSHCONF_STRING(var, conf, flags, cp)		options->var = ఖాళీ;
#నిర్వచించు SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	options->nvar = 0; \
	options->var = ఖాళీ;
#నిర్వచించు SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	init_##funcsuffix(options)
#నిర్వచించు SSHCONF_NONCONF(funcsuffix) \
	init_##funcsuffix(options)
#నిర్వచించు SSHCONF_DEPRECATE(conf, flags, opcode)		/*ఖాళీలు*/
#నిర్వచించు SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#నిర్వచించు SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	options->var = ఖాళీ;
#నిర్వచించు SSHCONF_ALIAS(old, conf, flags)			/*ఖాళీలు*/

	/* Using macros for these is a bit overkill but forces consistency */
#నిర్వచించు init_hostkeyfile(options) \
	options->host_కీలకం_files = 0; \
	options->అంకె_host_కీలకం_files = 0; \
	options->host_కీలకం_file_userprovided = ఖాళీ;
#నిర్వచించు init_ipqos(options) \
	options->ip_qos_interactive = -1; \
	options->ip_qos_bulk = -1;
#నిర్వచించు init_listenaddress(options) \
	options->queued_listen_addrs = ఖాళీ; \
	options->అంకె_queued_listens = 0; \
	options->listen_addrs = ఖాళీ; \
	options->అంకె_listen_addrs = 0;
#నిర్వచించు init_logfacility(options) \
	options->log_facility = SYSLOG_FACILITY_NOT_సమితి;
#నిర్వచించు init_loglevel(options) \
	options->log_level = SYSLOG_LEVEL_NOT_సమితి;
#నిర్వచించు init_పోర్టు(options) \
	options->అంకె_ports = 0; \
	options->ports_from_cmdline = 0;
#నిర్వచించు init_gatewayports(options) \
	options->fwd_opts.gateway_ports = -1;
#నిర్వచించు init_streamlocalbindmask(options) \
	options->fwd_opts.streamlocal_bind_ముసుగు = (బహుళకం_t)-1;
#నిర్వచించు init_streamlocalbindunlink(options) \
	options->fwd_opts.streamlocal_bind_unlink = -1;
#నిర్వచించు init_maxstartups(options) \
	options->max_startups_begin = -1; \
	options->max_startups_రేటు = -1; \
	options->max_startups = -1;
#నిర్వచించు init_permituserenv(options) \
	options->permit_user_env = -1; \
	options->permit_user_env_allowlist = ఖాళీ;
#నిర్వచించు init_persourcenetblocksize(options) \
	options->చొప్పున_ఆధారం_masklen_ipv4 = -1; \
	options->చొప్పున_ఆధారం_masklen_ipv6 = -1;
#నిర్వచించు init_persourcepenalties(options) \
	options->చొప్పున_ఆధారం_penalty_exempt = ఖాళీ; \
	options->చొప్పున_ఆధారం_penalty.enabled = -1; \
	options->చొప్పున_ఆధారం_penalty.max_sources4 = -1; \
	options->చొప్పున_ఆధారం_penalty.max_sources6 = -1; \
	options->చొప్పున_ఆధారం_penalty.అధికప్రవాహం_బహుళకం = -1; \
	options->చొప్పున_ఆధారం_penalty.అధికప్రవాహం_mode6 = -1; \
	options->చొప్పున_ఆధారం_penalty.penalty_crash = -1.0; \
	options->చొప్పున_ఆధారం_penalty.penalty_authfail = -1.0; \
	options->చొప్పున_ఆధారం_penalty.penalty_invaliduser = -1.0; \
	options->చొప్పున_ఆధారం_penalty.penalty_noauth = -1.0; \
	options->చొప్పున_ఆధారం_penalty.penalty_grace = -1.0; \
	options->చొప్పున_ఆధారం_penalty.penalty_refuseconnection = -1.0; \
	options->చొప్పున_ఆధారం_penalty.penalty_max = -1.0; \
	options->చొప్పున_ఆధారం_penalty.penalty_min = -1.0;
#నిర్వచించు init_rekeylimit(options) \
	options->rekey_హద్దు = -1; \
	options->rekey_interval = -1;
#నిర్వచించు init_subsystem(options) \
	options->అంకె_subsystems = 0; \
	options->subsystem_name = ఖాళీ; \
	options->subsystem_command = ఖాళీ; \
	options->subsystem_వాదనలు = ఖాళీ;
#నిర్వచించు init_pubkey_auth_options(options) \
	options->pubkey_auth_options = -1; \
	options->max_pubkey_ok = -1;
#నిర్వచించు init_timingsecret(options) \
	options->timing_secret = 0;

	SSHD_CONFIG_ENTRIES

#నిర్వచనం_రద్దు init_hostkeyfile
#నిర్వచనం_రద్దు init_ipqos
#నిర్వచనం_రద్దు init_listenaddress
#నిర్వచనం_రద్దు init_logfacility
#నిర్వచనం_రద్దు init_loglevel
#నిర్వచనం_రద్దు init_పోర్టు
#నిర్వచనం_రద్దు init_gatewayports
#నిర్వచనం_రద్దు init_streamlocalbindmask
#నిర్వచనం_రద్దు init_streamlocalbindunlink
#నిర్వచనం_రద్దు init_maxstartups
#నిర్వచనం_రద్దు init_permituserenv
#నిర్వచనం_రద్దు init_persourcenetblocksize
#నిర్వచనం_రద్దు init_persourcepenalties
#నిర్వచనం_రద్దు init_rekeylimit
#నిర్వచనం_రద్దు init_subsystem
#నిర్వచనం_రద్దు init_timingsecret
#నిర్వచనం_రద్దు SSHCONF_INT
#నిర్వచనం_రద్దు SSHCONF_INTFLAG
#నిర్వచనం_రద్దు SSHCONF_STRING
#నిర్వచనం_రద్దు SSHCONF_STRARRAY
#నిర్వచనం_రద్దు SSHCONF_CUSTOM
#నిర్వచనం_రద్దు SSHCONF_NONCONF
#నిర్వచనం_రద్దు SSHCONF_DEPRECATE
#నిర్వచనం_రద్దు SSHCONF_UNSUPPORTED_INT
#నిర్వచనం_రద్దు SSHCONF_UNSUPPORTED_STRING
#నిర్వచనం_రద్దు SSHCONF_ALIAS
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
స్థిర పూర్ణాంకం
option_clear_or_none(స్థిరరాశి అక్షరం *o)
{
	తిరిగి o == ఖాళీ || strcasecmp(o, "none") == 0;
}

స్థిర శూన్య
assemble_algorithms(ServerOptions *o)
{
	అక్షరం *all_cipher, *all_mac, *all_kex, *all_కీలకం, *all_sig;
	అక్షరం *def_cipher, *def_mac, *def_kex, *def_కీలకం, *def_sig;
	పూర్ణాంకం r;

	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_కీలకం = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = సరిపోలిక_filter_allowlist(KEX_SERVER_ENCRYPT, all_cipher);
	def_mac = సరిపోలిక_filter_allowlist(KEX_SERVER_MAC, all_mac);
	def_kex = సరిపోలిక_filter_allowlist(KEX_SERVER_KEX, all_kex);
	def_కీలకం = సరిపోలిక_filter_allowlist(KEX_DEFAULT_PK_ALG, all_కీలకం);
	def_sig = సరిపోలిక_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#నిర్వచించు ASSEMBLE(what, defaults, all) \
	చేయి { \
		ఒకవేళ ((r = kex_assemble_పేర్లు(&o->what, defaults, all)) != 0) \
			fatal_fr(r, "%s", #what); \
	} అయితే (0)
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostkeyalgorithms, def_కీలకం, all_కీలకం);
	ASSEMBLE(hostbased_accepted_algos, def_కీలకం, all_కీలకం);
	ASSEMBLE(pubkey_accepted_algos, def_కీలకం, all_కీలకం);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#నిర్వచనం_రద్దు ASSEMBLE
	విడుదల(all_cipher);
	విడుదల(all_mac);
	విడుదల(all_kex);
	విడుదల(all_కీలకం);
	విడుదల(all_sig);
	విడుదల(def_cipher);
	విడుదల(def_mac);
	విడుదల(def_kex);
	విడుదల(def_కీలకం);
	విడుదల(def_sig);
}

శూన్య
servconf_కూడు_hostkey(స్థిరరాశి అక్షరం *file, స్థిరరాశి పూర్ణాంకం పంక్తి,
    ServerOptions *options, స్థిరరాశి అక్షరం *మార్గం, పూర్ణాంకం userprovided)
{
	అక్షరం *apath = derelativise_మార్గం(మార్గం);

	opt_array_append2(file, పంక్తి, "HostKey",
	    &options->host_కీలకం_files, &options->host_కీలకం_file_userprovided,
	    &options->అంకె_host_కీలకం_files, apath, userprovided);
	విడుదల(apath);
}

శూన్య
servconf_కూడు_hostcert(స్థిరరాశి అక్షరం *file, స్థిరరాశి పూర్ణాంకం పంక్తి,
    ServerOptions *options, స్థిరరాశి అక్షరం *మార్గం)
{
	అక్షరం *apath = derelativise_మార్గం(మార్గం);

	opt_array_append(file, పంక్తి, "HostCertificate",
	    &options->host_cert_files, &options->అంకె_host_cert_files, apath);
	విడుదల(apath);
}

శూన్య
fill_default_server_options(ServerOptions *options)
{
	u_int i;

	/* Portable-specific overrides */
#నిర్వచితమైతే SKIP_PRIVDROP
	ఒకవేళ (options->allow_streamlocal_forwarding != -1 &&
	    options->allow_streamlocal_forwarding != FORWARD_DENY)
		logit("StreamlocalForwarding is not supported on this system");
	options->allow_streamlocal_forwarding = 0;
	ఒకవేళ (options->fwd_opts.gateway_ports != -1 &&
	    options->fwd_opts.gateway_ports != 0)
		logit("GatewayPorts is not supported on this system");
	options->fwd_opts.gateway_ports = 0;
#అయితే_ముగింపు

#నిర్వచించు SSHCONF_INT(var, conf, flags, ms, def, cp) \
	ఒకవేళ (options->var == -1) \
		options->var = def;
#నిర్వచించు SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	ఒకవేళ (options->var == -1) \
		options->var = def;
#నిర్వచించు SSHCONF_STRING(var, conf, flags, cp)		/* done manually */
#నిర్వచించు SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	/* done manually */
#నిర్వచించు SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/* done manually */
#నిర్వచించు SSHCONF_NONCONF(funcsuffix)			/* done manually */
#నిర్వచించు SSHCONF_DEPRECATE(conf, flags, opcode)		/*ఖాళీలు*/
#నిర్వచించు SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#నిర్వచించు SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	చేయి { \
		విడుదల(options->var); \
		options->var = ఖాళీ; \
	} అయితే (0);
#నిర్వచించు SSHCONF_ALIAS(old, conf, flags)			/*ఖాళీలు*/

	/* XXX maybe use macros here too to force consistency? */

	SSHD_CONFIG_ENTRIES

#నిర్వచనం_రద్దు SSHCONF_INT
#నిర్వచనం_రద్దు SSHCONF_INTFLAG
#నిర్వచనం_రద్దు SSHCONF_STRING
#నిర్వచనం_రద్దు SSHCONF_STRARRAY
#నిర్వచనం_రద్దు SSHCONF_CUSTOM
#నిర్వచనం_రద్దు SSHCONF_NONCONF
#నిర్వచనం_రద్దు SSHCONF_DEPRECATE
#నిర్వచనం_రద్దు SSHCONF_UNSUPPORTED_INT
#నిర్వచనం_రద్దు SSHCONF_UNSUPPORTED_STRING
#నిర్వచనం_రద్దు SSHCONF_ALIAS

#నిర్వచితమైతే USE_PAM
	ఒకవేళ (options->pam_service_name == ఖాళీ)
		options->pam_service_name = xstrdup(SSHD_PAM_SERVICE);
#అయితే_ముగింపు

	ఒకవేళ (options->అంకె_host_కీలకం_files == 0) {
		/* fill default hostkeys */
		servconf_కూడు_hostkey("[default]", 0, options,
		    మార్గం_HOST_RSA_కీలకం_FILE, 0);
		servconf_కూడు_hostkey("[default]", 0, options,
		    మార్గం_HOST_ECDSA_కీలకం_FILE, 0);
		servconf_కూడు_hostkey("[default]", 0, options,
		    మార్గం_HOST_ED25519_కీలకం_FILE, 0);
		servconf_కూడు_hostkey("[default]", 0, options,
		    మార్గం_HOST_MLDSA44_ED25519_కీలకం_FILE, 0);
	}
	/* No certificates by default */
	ఒకవేళ (options->అంకె_ports == 0)
		options->ports[options->అంకె_ports++] = SSH_DEFAULT_పోర్టు;
	ఒకవేళ (options->listen_addrs == ఖాళీ)
		కూడు_listen_addr(options, ఖాళీ, ఖాళీ, 0);
	ఒకవేళ (options->pid_file == ఖాళీ)
		options->pid_file = xstrdup(మార్గం_SSH_DAEMON_PID_FILE);
	ఒకవేళ (options->moduli_file == ఖాళీ)
		options->moduli_file = xstrdup(మార్గం_DH_MODULI);
	ఒకవేళ (options->xauth_location == ఖాళీ)
		options->xauth_location = xstrdup(మార్గం_XAUTH);
	ఒకవేళ (options->log_facility == SYSLOG_FACILITY_NOT_సమితి)
		options->log_facility = SYSLOG_FACILITY_AUTH;
	ఒకవేళ (options->log_level == SYSLOG_LEVEL_NOT_సమితి)
		options->log_level = SYSLOG_LEVEL_INFO;
	ఒకవేళ (options->permit_user_env == -1) {
		options->permit_user_env = 0;
		options->permit_user_env_allowlist = ఖాళీ;
	}
	ఒకవేళ (options->rekey_హద్దు == -1)
		options->rekey_హద్దు = 0;
	ఒకవేళ (options->rekey_interval == -1)
		options->rekey_interval = 0;
	ఒకవేళ (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	ఒకవేళ (options->max_startups == -1)
		options->max_startups = 100;
	ఒకవేళ (options->max_startups_రేటు == -1)
		options->max_startups_రేటు = 30;		/* 30% */
	ఒకవేళ (options->max_startups_begin == -1)
		options->max_startups_begin = 10;
	ఒకవేళ (options->చొప్పున_ఆధారం_masklen_ipv4 == -1)
		options->చొప్పున_ఆధారం_masklen_ipv4 = 32;
	ఒకవేళ (options->చొప్పున_ఆధారం_masklen_ipv6 == -1)
		options->చొప్పున_ఆధారం_masklen_ipv6 = 128;
	ఒకవేళ (options->చొప్పున_ఆధారం_penalty.enabled == -1)
		options->చొప్పున_ఆధారం_penalty.enabled = 1;
	ఒకవేళ (options->చొప్పున_ఆధారం_penalty.max_sources4 == -1)
		options->చొప్పున_ఆధారం_penalty.max_sources4 = 65536;
	ఒకవేళ (options->చొప్పున_ఆధారం_penalty.max_sources6 == -1)
		options->చొప్పున_ఆధారం_penalty.max_sources6 = 65536;
	ఒకవేళ (options->చొప్పున_ఆధారం_penalty.అధికప్రవాహం_బహుళకం == -1)
		options->చొప్పున_ఆధారం_penalty.అధికప్రవాహం_బహుళకం = చొప్పున_ఆధారం_PENALTY_అధికప్రవాహం_PERMISSIVE;
	ఒకవేళ (options->చొప్పున_ఆధారం_penalty.అధికప్రవాహం_mode6 == -1)
		options->చొప్పున_ఆధారం_penalty.అధికప్రవాహం_mode6 = options->చొప్పున_ఆధారం_penalty.అధికప్రవాహం_బహుళకం;
	ఒకవేళ (options->చొప్పున_ఆధారం_penalty.penalty_crash < 0.0)
		options->చొప్పున_ఆధారం_penalty.penalty_crash = 90.0;
	ఒకవేళ (options->చొప్పున_ఆధారం_penalty.penalty_grace < 0.0)
		options->చొప్పున_ఆధారం_penalty.penalty_grace = 10.0;
	ఒకవేళ (options->చొప్పున_ఆధారం_penalty.penalty_authfail < 0.0)
		options->చొప్పున_ఆధారం_penalty.penalty_authfail = 5.0;
	ఒకవేళ (options->చొప్పున_ఆధారం_penalty.penalty_invaliduser < 0.0)
		options->చొప్పున_ఆధారం_penalty.penalty_invaliduser = 5.0;
	ఒకవేళ (options->చొప్పున_ఆధారం_penalty.penalty_noauth < 0.0)
		options->చొప్పున_ఆధారం_penalty.penalty_noauth = 1.0;
	ఒకవేళ (options->చొప్పున_ఆధారం_penalty.penalty_refuseconnection < 0.0)
		options->చొప్పున_ఆధారం_penalty.penalty_refuseconnection = 10.0;
	ఒకవేళ (options->చొప్పున_ఆధారం_penalty.penalty_min < 0.0)
		options->చొప్పున_ఆధారం_penalty.penalty_min = 15.0;
	ఒకవేళ (options->చొప్పున_ఆధారం_penalty.penalty_max < 0.0)
		options->చొప్పున_ఆధారం_penalty.penalty_max = 600.0;
	ఒకవేళ (options->అంకె_authkeys_files == 0) {
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_కీలకాలు_files,
		    &options->అంకె_authkeys_files,
		    మార్గం_SSH_USER_PERMITTED_కీలకాలు);
		opt_array_append("[default]", 0, "AuthorizedKeysFiles",
		    &options->authorized_కీలకాలు_files,
		    &options->అంకె_authkeys_files,
		    మార్గం_SSH_USER_PERMITTED_KEYS2);
	}
	ఒకవేళ (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	ఒకవేళ (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	ఒకవేళ (options->సంస్కరణ_addendum == ఖాళీ)
		options->సంస్కరణ_addendum = xstrdup("");
	ఒకవేళ (options->fwd_opts.streamlocal_bind_ముసుగు == (బహుళకం_t)-1)
		options->fwd_opts.streamlocal_bind_ముసుగు = 0177;
	ఒకవేళ (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	ఒకవేళ (options->sk_provider == ఖాళీ)
		options->sk_provider = xstrdup("internal");
	ఒకవేళ (options->sshd_session_మార్గం == ఖాళీ)
		options->sshd_session_మార్గం = xstrdup(మార్గం_SSHD_SESSION);
	ఒకవేళ (options->sshd_auth_మార్గం == ఖాళీ)
		options->sshd_auth_మార్గం = xstrdup(మార్గం_SSHD_AUTH);
	ఒకవేళ (options->pubkey_auth_options == -1) {
		options->pubkey_auth_options = 0;
		options->max_pubkey_ok = DEFAULT_AUTH_FAIL_MAX;
	}
	ఒకవేళ (options->agent_socket_మార్గం == ఖాళీ)
		options->agent_socket_మార్గం = xstrdup(మార్గం_SSH_AGENT_SOCKET_DIR);

	assemble_algorithms(options);

#నిర్వచించు CLEAR_ON_NONE(v) \
	చేయి { \
		ఒకవేళ (option_clear_or_none(v)) { \
			విడుదల(v); \
			v = ఖాళీ; \
		} \
	} అయితే(0)
#నిర్వచించు CLEAR_ON_NONE_ARRAY(v, nv, none) \
	చేయి { \
		ఒకవేళ (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			విడుదల(options->v[0]); \
			విడుదల(options->v); \
			options->v = ఖాళీ; \
			options->nv = 0; \
		} \
	} అయితే (0)
	CLEAR_ON_NONE(options->pid_file);
	CLEAR_ON_NONE(options->xauth_location);
	CLEAR_ON_NONE(options->banner);
	CLEAR_ON_NONE(options->trusted_user_ca_కీలకాలు);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->authorized_principals_file);
	CLEAR_ON_NONE(options->adm_forced_command);
	CLEAR_ON_NONE(options->chroot_directory);
	CLEAR_ON_NONE(options->routing_domain);
	CLEAR_ON_NONE(options->host_కీలకం_agent);
	CLEAR_ON_NONE(options->చొప్పున_ఆధారం_penalty_exempt);
	CLEAR_ON_NONE(options->agent_socket_మార్గం);

	కొరకు (i = 0; i < options->అంకె_host_కీలకం_files; i++)
		CLEAR_ON_NONE(options->host_కీలకం_files[i]);
	కొరకు (i = 0; i < options->అంకె_host_cert_files; i++)
		CLEAR_ON_NONE(options->host_cert_files[i]);

	CLEAR_ON_NONE_ARRAY(channel_timeouts, అంకె_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(auth_methods, అంకె_auth_methods, "any");
	CLEAR_ON_NONE_ARRAY(revoked_కీలకాలు_files, అంకె_revoked_కీలకాలు_files, "none");
	CLEAR_ON_NONE_ARRAY(authorized_కీలకాలు_files, అంకె_authkeys_files, "none");
#నిర్వచనం_రద్దు CLEAR_ON_NONE
#నిర్వచనం_రద్దు CLEAR_ON_NONE_ARRAY
}

/* Macros to declare ServerOpCodes enum values */
#నిర్వచించు SSHCONF_INT(var, conf, flags, ms, def, cp)	s##conf,
#నిర్వచించు SSHCONF_INTFLAG(var, conf, flags, def, cp)	s##conf,
#నిర్వచించు SSHCONF_STRING(var, conf, flags, cp)		s##conf,
#నిర్వచించు SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	s##conf,
#నిర్వచించు SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	s##conf,
#నిర్వచించు SSHCONF_NONCONF(funcsuffix)			/*ఖాళీలు*/
#నిర్వచించు SSHCONF_DEPRECATE(conf, flags, opcode)		/*ఖాళీలు*/
#నిర్వచించు SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/*ఖాళీలు*/
#నిర్వచించు SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/*ఖాళీలు*/
#నిర్వచించు SSHCONF_ALIAS(old, conf, flags)			/*ఖాళీలు*/

/* Keyword tokens. */
రకనిర్వచనం గణన {
	sBadOption,		/* == unknown option */
	SSHD_CONFIG_ENTRIES
	s_సరిపోలిక, sInclude,
	sDeprecated, sIgnore, sUnsupported
} ServerOpCodes;
#నిర్వచనం_రద్దు SSHCONF_INT
#నిర్వచనం_రద్దు SSHCONF_INTFLAG
#నిర్వచనం_రద్దు SSHCONF_STRING
#నిర్వచనం_రద్దు SSHCONF_STRARRAY
#నిర్వచనం_రద్దు SSHCONF_CUSTOM
#నిర్వచనం_రద్దు SSHCONF_NONCONF
#నిర్వచనం_రద్దు SSHCONF_DEPRECATE
#నిర్వచనం_రద్దు SSHCONF_UNSUPPORTED_INT
#నిర్వచనం_రద్దు SSHCONF_UNSUPPORTED_STRING
#నిర్వచనం_రద్దు SSHCONF_ALIAS

#నిర్వచించు SSHCFG_GLOBAL		0x01	/* allowed in main section of config */
#నిర్వచించు SSHCFG_సరిపోలిక		0x02	/* allowed inside a Match section */
#నిర్వచించు SSHCFG_ALL		(SSHCFG_GLOBAL|SSHCFG_సరిపోలిక)
#నిర్వచించు SSHCFG_NEVERMATCH	0x04  /* Match never matches; internal only */
#నిర్వచించు SSHCFG_సరిపోలిక_ONLY	0x08  /* Match only in conditional blocks; internal only */

/* Macros to define keywords[] entries */
#నిర్వచించు SSHCONF_KW(conf, flags)		{ #conf, s##conf, flags },
#నిర్వచించు SSHCONF_INT(var, conf, flags, ms, def, cp)	SSHCONF_KW(conf, flags)
#నిర్వచించు SSHCONF_INTFLAG(var, conf, flags, def, cp)	SSHCONF_KW(conf, flags)
#నిర్వచించు SSHCONF_STRING(var, conf, flags, cp)		SSHCONF_KW(conf, flags)
#నిర్వచించు SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	SSHCONF_KW(conf, flags)
#నిర్వచించు SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	SSHCONF_KW(conf, flags)
#నిర్వచించు SSHCONF_NONCONF(funcsuffix)			/*ఖాళీలు*/
#నిర్వచించు SSHCONF_DEPRECATED				sDeprecated
#నిర్వచించు SSHCONF_IGNORE					sIgnore
#నిర్వచించు SSHCONF_DEPRECATE(conf, flags, opcode) \
	{ #conf, opcode, flags },
#నిర్వచించు SSHCONF_UNSUPPORTED_INT(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#నిర్వచించు SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	{ #conf, sUnsupported, flags },
#నిర్వచించు SSHCONF_ALIAS(old, conf, flags) \
	{ #old, s##conf, flags },

/* Textual representation of the tokens. */
స్థిర నిర్మాణం {
	స్థిరరాశి అక్షరం *name;
	ServerOpCodes opcode;
	u_int flags;
} keywords[] = {
	SSHD_CONFIG_ENTRIES
	{ "match", s_సరిపోలిక, SSHCFG_ALL },
	{ "include", sInclude, SSHCFG_ALL },
	{ ఖాళీ, sBadOption, 0 }
};
#నిర్వచనం_రద్దు SSHCONF_INT
#నిర్వచనం_రద్దు SSHCONF_INTFLAG
#నిర్వచనం_రద్దు SSHCONF_STRING
#నిర్వచనం_రద్దు SSHCONF_STRARRAY
#నిర్వచనం_రద్దు SSHCONF_CUSTOM
#నిర్వచనం_రద్దు SSHCONF_NONCONF
#నిర్వచనం_రద్దు SSHCONF_DEPRECATED
#నిర్వచనం_రద్దు SSHCONF_IGNORE
#నిర్వచనం_రద్దు SSHCONF_DEPRECATE
#నిర్వచనం_రద్దు SSHCONF_UNSUPPORTED_INT
#నిర్వచనం_రద్దు SSHCONF_UNSUPPORTED_STRING
#నిర్వచనం_రద్దు SSHCONF_ALIAS

స్థిర నిర్మాణం {
	పూర్ణాంకం val;
	అక్షరం *పాఠ్యం;
} tunmode_desc[] = {
	{ SSH_TUNMODE_NO, "no" },
	{ SSH_TUNMODE_POINTOPOINT, "point-to-point" },
	{ SSH_TUNMODE_ETHERNET, "ethernet" },
	{ SSH_TUNMODE_YES, "yes" },
	{ -1, ఖాళీ }
};

/* Returns an opcode name from its number */

స్థిర స్థిరరాశి అక్షరం *
lookup_opcode_name(ServerOpCodes సంకేతం_2)
{
	u_int i;

	కొరకు (i = 0; keywords[i].name != ఖాళీ; i++)
		ఒకవేళ (keywords[i].opcode == సంకేతం_2)
			తిరిగి(keywords[i].name);
	తిరిగి "UNKNOWN";
}


/*
 * Returns the number of the token pointed to by cp or sBadOption.
 */

స్థిర ServerOpCodes
parse_token(స్థిరరాశి అక్షరం *cp, స్థిరరాశి అక్షరం *filename,
	    పూర్ణాంకం linenum, u_int *flags)
{
	u_int i;

	కొరకు (i = 0; keywords[i].name; i++)
		ఒకవేళ (strcasecmp(cp, keywords[i].name) == 0) {
			*flags = keywords[i].flags;
			తిరిగి keywords[i].opcode;
		}

	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	తిరిగి sBadOption;
}

అక్షరం *
derelativise_మార్గం(స్థిరరాశి అక్షరం *మార్గం)
{
	అక్షరం *expanded, *ret, cwd[PATH_MAX];

	ఒకవేళ (strcasecmp(మార్గం, "none") == 0)
		తిరిగి xstrdup("none");
	expanded = tilde_expand_filename(మార్గం, getuid());
	ఒకవేళ (మార్గం_absolute(expanded))
		తిరిగి expanded;
	ఒకవేళ (getcwd(cwd, పరిమాణం(cwd)) == ఖాళీ)
		fatal_f("getcwd: %s", strerror(errno));
	xasprintf(&ret, "%s/%s", cwd, expanded);
	విడుదల(expanded);
	తిరిగి ret;
}

స్థిర శూన్య
కూడు_listen_addr(ServerOptions *options, స్థిరరాశి అక్షరం *addr,
    స్థిరరాశి అక్షరం *rdomain, పూర్ణాంకం పోర్టు)
{
	u_int i;

	ఒకవేళ (పోర్టు > 0)
		కూడు_one_listen_addr(options, addr, rdomain, పోర్టు);
	లేకపోతే {
		కొరకు (i = 0; i < options->అంకె_ports; i++) {
			కూడు_one_listen_addr(options, addr, rdomain,
			    options->ports[i]);
		}
	}
}

స్థిర శూన్య
కూడు_one_listen_addr(ServerOptions *options, స్థిరరాశి అక్షరం *addr,
    స్థిరరాశి అక్షరం *rdomain, పూర్ణాంకం పోర్టు)
{
	నిర్మాణం addrinfo hints, *ai, *aitop;
	అక్షరం strport[NI_MAXSERV];
	పూర్ణాంకం gaierr;
	u_int i;

	/* Find listen_addrs entry for this rdomain */
	కొరకు (i = 0; i < options->అంకె_listen_addrs; i++) {
		ఒకవేళ (rdomain == ఖాళీ && options->listen_addrs[i].rdomain == ఖాళీ)
			ఆపు;
		ఒకవేళ (rdomain == ఖాళీ || options->listen_addrs[i].rdomain == ఖాళీ)
			కొనసాగు;
		ఒకవేళ (strcmp(rdomain, options->listen_addrs[i].rdomain) == 0)
			ఆపు;
	}
	ఒకవేళ (i >= options->అంకె_listen_addrs) {
		/* No entry for this rdomain; allocate one */
		ఒకవేళ (i >= గరిష్ఠ_పూర్ణాంకం)
			fatal_f("too many listen addresses");
		options->listen_addrs = xrecallocarray(options->listen_addrs,
		    options->అంకె_listen_addrs, options->అంకె_listen_addrs + 1,
		    పరిమాణం(*options->listen_addrs));
		i = options->అంకె_listen_addrs++;
		ఒకవేళ (rdomain != ఖాళీ)
			options->listen_addrs[i].rdomain = xstrdup(rdomain);
	}
	/* options->listen_addrs[i] points to the addresses for this rdomain */

	memset(&hints, 0, పరిమాణం(hints));
	hints.ai_family = options->చిరునామా_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (addr == ఖాళీ) ? AI_PASSIVE : 0;
	snprintf(strport, పరిమాణం strport, "%d", పోర్టు);
	ఒకవేళ ((gaierr = getaddrinfo(addr, strport, &hints, &aitop)) != 0)
		fatal("bad addr or host: %s (%s)",
		    addr ? addr : "<NULL>",
		    ssh_gai_strerror(gaierr));
	కొరకు (ai = aitop; ai->ai_next; ai = ai->ai_next)
		;
	ai->ai_next = options->listen_addrs[i].addrs;
	options->listen_addrs[i].addrs = aitop;
}

/* Returns nonzero if the routing domain name is valid */
స్థిర పూర్ణాంకం
valid_rdomain(స్థిరరాశి అక్షరం *name)
{
#ఒకవేళ defined(HAVE_SYS_VALID_RDOMAIN)
	తిరిగి sys_valid_rdomain(name);
#లేదావేళ defined(__OpenBSD__)
	స్థిరరాశి అక్షరం *errstr;
	దీర్ఘ దీర్ఘ అంకె;
	నిర్మాణం rt_tableinfo info;
	పూర్ణాంకం mib[6];
	కొలత_t miblen = పరిమాణం(mib);

	ఒకవేళ (name == ఖాళీ)
		తిరిగి 1;

	అంకె = strtonum(name, 0, 255, &errstr);
	ఒకవేళ (errstr != ఖాళీ)
		తిరిగి 0;

	/* Check whether the table actually exists */
	memset(mib, 0, పరిమాణం(mib));
	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[4] = NET_RT_పట్టిక;
	mib[5] = (పూర్ణాంకం)అంకె;
	ఒకవేళ (sysctl(mib, 6, &info, &miblen, ఖాళీ, 0) == -1)
		తిరిగి 0;

	తిరిగి 1;
#లేకపోతే /* defined(__OpenBSD__) */
	error("Routing domains are not supported on this platform");
	తిరిగి 0;
#అయితే_ముగింపు
}

/*
 * Queue a ListenAddress to be processed once we have all of the Ports
 * and AddressFamily options.
 */
స్థిర శూన్య
వరుస_listen_addr(ServerOptions *options, స్థిరరాశి అక్షరం *addr,
    స్థిరరాశి అక్షరం *rdomain, పూర్ణాంకం పోర్టు)
{
	నిర్మాణం queued_listenaddr *qla;

	options->queued_listen_addrs = xrecallocarray(
	    options->queued_listen_addrs,
	    options->అంకె_queued_listens, options->అంకె_queued_listens + 1,
	    పరిమాణం(*options->queued_listen_addrs));
	qla = &options->queued_listen_addrs[options->అంకె_queued_listens++];
	qla->addr = xstrdup(addr);
	qla->పోర్టు = పోర్టు;
	qla->rdomain = rdomain == ఖాళీ ? ఖాళీ : xstrdup(rdomain);
}

/*
 * Process queued (text) ListenAddress entries.
 */
స్థిర శూన్య
process_queued_listen_addrs(ServerOptions *options)
{
	u_int i;
	నిర్మాణం queued_listenaddr *qla;

	ఒకవేళ (options->అంకె_ports == 0)
		options->ports[options->అంకె_ports++] = SSH_DEFAULT_పోర్టు;
	ఒకవేళ (options->చిరునామా_family == -1)
		options->చిరునామా_family = AF_UNSPEC;

	కొరకు (i = 0; i < options->అంకె_queued_listens; i++) {
		qla = &options->queued_listen_addrs[i];
		కూడు_listen_addr(options, qla->addr, qla->rdomain, qla->పోర్టు);
		విడుదల(qla->addr);
		విడుదల(qla->rdomain);
	}
	విడుదల(options->queued_listen_addrs);
	options->queued_listen_addrs = ఖాళీ;
	options->అంకె_queued_listens = 0;
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

స్థిర పూర్ణాంకం
సరిపోలిక_cfg_పంక్తి_సమూహం(స్థిరరాశి అక్షరం *grps, పూర్ణాంకం పంక్తి, స్థిరరాశి అక్షరం *user)
{
	పూర్ణాంకం ఫలితం = 0;
	నిర్మాణం passwd *pw;

	ఒకవేళ (user == ఖాళీ)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ ((pw = getpwnam(user)) == ఖాళీ) {
		debug("Can't match group at line %d because user %.100s does "
		    "not exist", పంక్తి, user);
	} లేకపోతే ఒకవేళ (ga_init(pw->pw_name, pw->pw_gid) == 0) {
		debug("Can't Match group because user %.100s not in any group "
		    "at line %d", user, పంక్తి);
	} లేకపోతే ఒకవేళ (ga_సరిపోలిక_నమూనా_list(grps) != 1) {
		debug("user %.100s does not match group list %.100s at line %d",
		    user, grps, పంక్తి);
	} లేకపోతే {
		debug("user %.100s matched group list %.100s at line %d", user,
		    grps, పంక్తి);
		ఫలితం = 1;
	}
బహిర్గతం:
	ga_free();
	తిరిగి ఫలితం;
}

స్థిర శూన్య
సరిపోలిక_test_missing_fatal(స్థిరరాశి అక్షరం *criteria, స్థిరరాశి అక్షరం *attrib)
{
	fatal("'Match %s' in configuration but '%s' not in connection "
	    "test specification.", criteria, attrib);
}

/*
 * All of the attributes on a single Match line are ANDed together, so we need
 * to check every attribute and set the result to zero if any attribute does
 * not match.
 */
స్థిర పూర్ణాంకం
సరిపోలిక_cfg_పంక్తి(స్థిరరాశి అక్షరం *నిండిన_పంక్తి, పూర్ణాంకం *acp, అక్షరం ***avp,
    పూర్ణాంకం పంక్తి, నిర్మాణం connection_info *ci)
{
	పూర్ణాంకం ఫలితం = 1, లక్షణాలు = 0, పోర్టు;
	అక్షరం *arg, *attrib = ఖాళీ, *oattrib;

	ఒకవేళ (ci == ఖాళీ) {
		debug3("checking syntax for 'Match %s' on line %d",
		    నిండిన_పంక్తి, పంక్తి);
	} లేకపోతే {
		debug3("checking match for '%s' user %s%s host %s addr %s "
		    "laddr %s lport %d rdomain %s on line %d", నిండిన_పంక్తి,
		    ci->user ? ci->user : "(null)",
		    ci->user_invalid ? " (invalid)" : "",
		    ci->host ? ci->host : "(null)",
		    ci->చిరునామా ? ci->చిరునామా : "(null)",
		    ci->laddress ? ci->laddress : "(null)", ci->lport,
		    ci->rdomain ? ci->rdomain : "(null)", పంక్తి);
	}

	అయితే ((oattrib = argv_తదుపరి(acp, avp)) != ఖాళీ) {
		/* Terminate on comment */
		ఒకవేళ (*oattrib == '#') {
			argv_consume(acp); /* mark all arguments consumed */
			ఆపు;
		}
		attrib = xstrdup(oattrib);
		arg = ఖాళీ;
		లక్షణాలు++;
		/* Criterion "all" has no argument and must appear alone */
		ఒకవేళ (strcasecmp(attrib, "all") == 0) {
			ఒకవేళ (లక్షణాలు > 1 ||
			    ((arg = argv_తదుపరి(acp, avp)) != ఖాళీ &&
			    *arg != '\0' && *arg != '#')) {
				error("'all' cannot be combined with other "
				    "Match attributes");
				ఫలితం = -1;
				వెళ్ళు బహిర్గతం;
			}
			ఒకవేళ (arg != ఖాళీ && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			ఫలితం = 1;
			వెళ్ళు బహిర్గతం;
		}
		/* Criterion "invalid-user" also has no argument */
		ఒకవేళ (strcasecmp(attrib, "invalid-user") == 0) {
			ఒకవేళ (ci == ఖాళీ) {
				ఫలితం = 0;
				వెళ్ళు తదుపరి;
			}
			ఒకవేళ (ci->user_invalid == 0)
				ఫలితం = 0;
			లేకపోతే
				debug("matched invalid-user at line %d", పంక్తి);
			వెళ్ళు తదుపరి;
		}

		/* Keep this list in sync with below */
		ఒకవేళ (strprefix(attrib, "user=", 1) != ఖాళీ ||
		    strprefix(attrib, "group=", 1) != ఖాళీ ||
		    strprefix(attrib, "host=", 1) != ఖాళీ ||
		    strprefix(attrib, "address=", 1) != ఖాళీ ||
		    strprefix(attrib, "localaddress=", 1) != ఖాళీ ||
		    strprefix(attrib, "localport=", 1) != ఖాళీ ||
		    strprefix(attrib, "rdomain=", 1) != ఖాళీ ||
		    strprefix(attrib, "version=", 1) != ఖాళీ) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} లేకపోతే {
			arg = argv_తదుపరి(acp, avp);
		}

		/* All other criteria require an argument */
		ఒకవేళ (arg == ఖాళీ || *arg == '\0' || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			ఫలితం = -1;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (strcasecmp(attrib, "user") == 0) {
			ఒకవేళ (ci == ఖాళీ || (ci->test && ci->user == ఖాళీ)) {
				ఫలితం = 0;
				వెళ్ళు తదుపరి;
			}
			ఒకవేళ (ci->user == ఖాళీ)
				సరిపోలిక_test_missing_fatal("User", "user");
			ఒకవేళ (సరిపోలిక_usergroup_నమూనా_list(ci->user, arg) != 1)
				ఫలితం = 0;
			లేకపోతే
				debug("user %.100s matched 'User %.100s' at "
				    "line %d", ci->user, arg, పంక్తి);
		} లేకపోతే ఒకవేళ (strcasecmp(attrib, "group") == 0) {
			ఒకవేళ (ci == ఖాళీ || (ci->test && ci->user == ఖాళీ)) {
				ఫలితం = 0;
				వెళ్ళు తదుపరి;
			}
			ఒకవేళ (ci->user == ఖాళీ)
				సరిపోలిక_test_missing_fatal("Group", "user");
			ఎంపిక (సరిపోలిక_cfg_పంక్తి_సమూహం(arg, పంక్తి, ci->user)) {
			స్థితి -1:
				ఫలితం = -1;
				వెళ్ళు బహిర్గతం;
			స్థితి 0:
				ఫలితం = 0;
			}
		} లేకపోతే ఒకవేళ (strcasecmp(attrib, "host") == 0) {
			ఒకవేళ (ci == ఖాళీ || (ci->test && ci->host == ఖాళీ)) {
				ఫలితం = 0;
				వెళ్ళు తదుపరి;
			}
			ఒకవేళ (ci->host == ఖాళీ)
				సరిపోలిక_test_missing_fatal("Host", "host");
			ఒకవేళ (సరిపోలిక_hostname(ci->host, arg) != 1)
				ఫలితం = 0;
			లేకపోతే
				debug("connection from %.100s matched 'Host "
				    "%.100s' at line %d", ci->host, arg, పంక్తి);
		} లేకపోతే ఒకవేళ (strcasecmp(attrib, "address") == 0) {
			ఒకవేళ (ci == ఖాళీ || (ci->test && ci->చిరునామా == ఖాళీ)) {
				ఒకవేళ (addr_సరిపోలిక_list(ఖాళీ, arg) != 0)
					fatal("Invalid Match address argument "
					    "'%s' at line %d", arg, పంక్తి);
				ఫలితం = 0;
				వెళ్ళు తదుపరి;
			}
			ఒకవేళ (ci->చిరునామా == ఖాళీ)
				సరిపోలిక_test_missing_fatal("Address", "addr");
			ఎంపిక (addr_సరిపోలిక_list(ci->చిరునామా, arg)) {
			స్థితి 1:
				debug("connection from %.100s matched 'Address "
				    "%.100s' at line %d", ci->చిరునామా, arg, పంక్తి);
				ఆపు;
			స్థితి 0:
			స్థితి -1:
				ఫలితం = 0;
				ఆపు;
			స్థితి -2:
				ఫలితం = -1;
				వెళ్ళు బహిర్గతం;
			}
		} లేకపోతే ఒకవేళ (strcasecmp(attrib, "localaddress") == 0){
			ఒకవేళ (ci == ఖాళీ || (ci->test && ci->laddress == ఖాళీ)) {
				ఒకవేళ (addr_సరిపోలిక_list(ఖాళీ, arg) != 0)
					fatal("Invalid Match localaddress "
					    "argument '%s' at line %d", arg,
					    పంక్తి);
				ఫలితం = 0;
				వెళ్ళు తదుపరి;
			}
			ఒకవేళ (ci->laddress == ఖాళీ)
				సరిపోలిక_test_missing_fatal("LocalAddress",
				    "laddr");
			ఎంపిక (addr_సరిపోలిక_list(ci->laddress, arg)) {
			స్థితి 1:
				debug("connection from %.100s matched "
				    "'LocalAddress %.100s' at line %d",
				    ci->laddress, arg, పంక్తి);
				ఆపు;
			స్థితి 0:
			స్థితి -1:
				ఫలితం = 0;
				ఆపు;
			స్థితి -2:
				ఫలితం = -1;
				వెళ్ళు బహిర్గతం;
			}
		} లేకపోతే ఒకవేళ (strcasecmp(attrib, "localport") == 0) {
			ఒకవేళ ((పోర్టు = a2port(arg)) == -1) {
				error("Invalid LocalPort '%s' on Match line",
				    arg);
				ఫలితం = -1;
				వెళ్ళు బహిర్గతం;
			}
			ఒకవేళ (ci == ఖాళీ || (ci->test && ci->lport == -1)) {
				ఫలితం = 0;
				వెళ్ళు తదుపరి;
			}
			ఒకవేళ (ci->lport == 0)
				సరిపోలిక_test_missing_fatal("LocalPort", "lport");
			/* TODO support port lists */
			ఒకవేళ (పోర్టు == ci->lport)
				debug("connection from %.100s matched "
				    "'LocalPort %d' at line %d",
				    ci->laddress, పోర్టు, పంక్తి);
			లేకపోతే
				ఫలితం = 0;
		} లేకపోతే ఒకవేళ (strcasecmp(attrib, "rdomain") == 0) {
			ఒకవేళ (ci == ఖాళీ || (ci->test && ci->rdomain == ఖాళీ)) {
				ఫలితం = 0;
				వెళ్ళు తదుపరి;
			}
			ఒకవేళ (ci->rdomain == ఖాళీ)
				సరిపోలిక_test_missing_fatal("RDomain", "rdomain");
			ఒకవేళ (సరిపోలిక_నమూనా_list(ci->rdomain, arg, 0) != 1)
				ఫలితం = 0;
			లేకపోతే
				debug("connection RDomain %.100s matched "
				    "'RDomain %.100s' at line %d",
				    ci->rdomain, arg, పంక్తి);
		} లేకపోతే ఒకవేళ (strcasecmp(attrib, "version") == 0) {
			ఒకవేళ (సరిపోలిక_నమూనా_list(SSH_RELEASE, arg, 0) != 1)
				ఫలితం = 0;
			లేకపోతే
				debug("version %.100s matched "
				    "'version %.100s' at line %d",
				    SSH_RELEASE, arg, పంక్తి);
		} లేకపోతే {
			error("Unsupported Match attribute %s", oattrib);
			ఫలితం = -1;
			వెళ్ళు బహిర్గతం;
		}
 తదుపరి:
		విడుదల(attrib);
		attrib = ఖాళీ;
	}
	ఒకవేళ (లక్షణాలు == 0) {
		error("One or more attributes required for Match");
		తిరిగి -1;
	}
 బహిర్గతం:
	ఒకవేళ (ci != ఖాళీ && ఫలితం != -1)
		debug3("match %sfound on line %d", ఫలితం ? "" : "not ", పంక్తి);
	విడుదల(attrib);
	తిరిగి ఫలితం;
}

#నిర్వచించు WHITESPACE " \t\r\n"

/* Multistate option parsing */
నిర్మాణం multistate {
	అక్షరం *కీలకం;
	పూర్ణాంకం విలువ;
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_flag[] = {
	{ "yes",			1 },
	{ "no",				0 },
	{ ఖాళీ, -1 }
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_ignore_rhosts[] = {
	{ "yes",			IGNORE_RHOSTS_YES },
	{ "no",				IGNORE_RHOSTS_NO },
	{ "shosts-only",		IGNORE_RHOSTS_SHOSTS },
	{ ఖాళీ, -1 }
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ ఖాళీ, -1 }
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_permitrootlogin[] = {
	{ "prohibit-password",		PERMIT_NO_PASSWD },
	{ "without-password",		PERMIT_NO_PASSWD },
	{ "forced-commands-only",	PERMIT_FORCED_ONLY },
	{ "yes",			PERMIT_YES },
	{ "no",				PERMIT_NO },
	{ ఖాళీ, -1 }
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_compression[] = {
#నిర్వచితమైతే WITH_ZLIB
	{ "yes",			COMP_DELAYED },
	{ "delayed",			COMP_DELAYED },
#అయితే_ముగింపు
	{ "no",				COMP_NONE },
	{ ఖాళీ, -1 }
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_gatewayports[] = {
	{ "clientspecified",		2 },
	{ "yes",			1 },
	{ "no",				0 },
	{ ఖాళీ, -1 }
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_tcpfwd[] = {
	{ "yes",			FORWARD_ALLOW },
	{ "all",			FORWARD_ALLOW },
	{ "no",				FORWARD_DENY },
	{ "remote",			FORWARD_REMOTE },
	{ "local",			FORWARD_LOCAL },
	{ ఖాళీ, -1 }
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ ఖాళీ, -1 }
};
స్థిర స్థిరరాశి నిర్మాణం multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ ఖాళీ, -1 }
};

స్థిర పూర్ణాంకం
process_server_config_పంక్తి_లోతు(ServerOptions *options, అక్షరం *పంక్తి,
    స్థిరరాశి అక్షరం *filename, పూర్ణాంకం linenum, పూర్ణాంకం *activep,
    నిర్మాణం connection_info *connectinfo, పూర్ణాంకం *inc_flags, పూర్ణాంకం లోతు,
    నిర్మాణం include_list *includes)
{
	అక్షరం *str, ***chararrayptr, **charptr, *arg, *arg2, *p, *keyword;
	పూర్ణాంకం cmdline = 0, *intptr, విలువ, value2, value3, n, పోర్టు, oactive, r;
	ద్విగుణ dvalue, *doubleptr = ఖాళీ;
	పూర్ణాంకం ca_only = 0, దొరికింది = 0;
	SyslogFacility *log_facility_ptr;
	LogLevel *log_level_ptr;
	ServerOpCodes opcode;
	u_int i, *uintptr, flags = 0;
	కొలత_t len;
	దీర్ఘ దీర్ఘ val64;
	స్థిరరాశి నిర్మాణం multistate *multistate_ptr;
	స్థిరరాశి అక్షరం *errstr;
	నిర్మాణం include_అంశం *అంశం;
	glob_t gbuf;
	అక్షరం **oav = ఖాళీ, **av;
	పూర్ణాంకం oac = 0, ac;
	పూర్ణాంకం ret = -1;
	అక్షరం **strs = ఖాళీ; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	ఒకవేళ ((len = అక్షరశ్రేణి_పొడవు(పంక్తి)) == 0)
		తిరిగి 0;
	కొరకు (len--; len > 0; len--) {
		ఒకవేళ (strchr(WHITESPACE "\f", పంక్తి[len]) == ఖాళీ)
			ఆపు;
		పంక్తి[len] = '\0';
	}

	str = పంక్తి;
	ఒకవేళ ((keyword = strdelim(&str)) == ఖాళీ)
		తిరిగి 0;
	/* Ignore leading whitespace */
	ఒకవేళ (*keyword == '\0')
		keyword = strdelim(&str);
	ఒకవేళ (!keyword || !*keyword || *keyword == '#')
		తిరిగి 0;
	ఒకవేళ (str == ఖాళీ || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		తిరిగి -1;
	}
	intptr = ఖాళీ;
	charptr = ఖాళీ;
	opcode = parse_token(keyword, filename, linenum, &flags);

	ఒకవేళ (argv_విభజించు(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		తిరిగి -1;
	}
	ac = oac;
	av = oav;

	ఒకవేళ (activep == ఖాళీ) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}
	ఒకవేళ (*activep && opcode != s_సరిపోలిక && opcode != sInclude)
		debug3("%s:%d setting %s %s", filename, linenum, keyword, str);
	ఒకవేళ (*activep == 0 && !(flags & SSHCFG_సరిపోలిక)) {
		ఒకవేళ (connectinfo == ఖాళీ) {
			fatal("%s line %d: Directive '%s' is not allowed "
			    "within a Match block", filename, linenum, keyword);
		} లేకపోతే { /* this is a directive we have already processed */
			ret = 0;
			వెళ్ళు బహిర్గతం;
		}
	}

	ఎంపిక (opcode) {
	/* Portable-specific options */
#నిర్వచితమైతే USE_PAM
	స్థితి sUsePAM:
		intptr = &options->use_pam;
		వెళ్ళు parse_flag;
	స్థితి sPAMServiceName:
		charptr = &options->pam_service_name;
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		}
		ఒకవేళ (*activep && *charptr == ఖాళీ)
			*charptr = xstrdup(arg);
		ఆపు;
#అయితే_ముగింపు

	/* Standard Options */
	స్థితి sBadOption:
		వెళ్ళు బహిర్గతం;
	స్థితి s_పోర్టు:
		/* ignore ports from configfile if cmdline specifies ports */
		ఒకవేళ (options->ports_from_cmdline) {
			argv_consume(&ac);
			ఆపు;
		}
		ఒకవేళ (options->అంకె_ports >= MAX_PORTS)
			fatal("%s line %d: too many ports.",
			    filename, linenum);
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: missing port number.",
			    filename, linenum);
		options->ports[options->అంకె_ports++] = a2port(arg);
		ఒకవేళ (options->ports[options->అంకె_ports-1] <= 0)
			fatal("%s line %d: Badly formatted port number.",
			    filename, linenum);
		ఆపు;

	స్థితి s_Login_Grace_సమయం:
		intptr = &options->login_grace_సమయం;
 parse_సమయం:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: missing time value.",
			    filename, linenum);
		ఒకవేళ ((విలువ = convtime(arg)) == -1)
			fatal("%s line %d: invalid time value.",
			    filename, linenum);
		ఒకవేళ (*activep && *intptr == -1)
			*intptr = విలువ;
		ఆపు;

	స్థితి s_Listen_చిరునామా:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (arg == ఖాళీ || *arg == '\0')
			fatal("%s line %d: missing address",
			    filename, linenum);
		/* check for bare IPv6 address: no "[]" and 2 or more ":" */
		ఒకవేళ (strchr(arg, '[') == ఖాళీ && (p = strchr(arg, ':')) != ఖాళీ
		    && strchr(p+1, ':') != ఖాళీ) {
			పోర్టు = 0;
			p = arg;
		} లేకపోతే {
			arg2 = ఖాళీ;
			p = hpdelim(&arg);
			ఒకవేళ (p == ఖాళీ)
				fatal("%s line %d: bad address:port usage",
				    filename, linenum);
			p = cleanhostname(p);
			ఒకవేళ (arg == ఖాళీ)
				పోర్టు = 0;
			లేకపోతే ఒకవేళ ((పోర్టు = a2port(arg)) <= 0)
				fatal("%s line %d: bad port number",
				    filename, linenum);
		}
		/* Optional routing table */
		arg2 = ఖాళీ;
		ఒకవేళ ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			ఒకవేళ (strcmp(arg, "rdomain") != 0 ||
			    (arg2 = argv_తదుపరి(&ac, &av)) == ఖాళీ)
				fatal("%s line %d: bad ListenAddress syntax",
				    filename, linenum);
			ఒకవేళ (!valid_rdomain(arg2))
				fatal("%s line %d: bad routing domain",
				    filename, linenum);
		}
		వరుస_listen_addr(options, p, arg2, పోర్టు);

		ఆపు;

	స్థితి s_చిరునామా_Family:
		intptr = &options->చిరునామా_family;
		multistate_ptr = multistate_addressfamily;
 parse_multistate:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		విలువ = -1;
		కొరకు (i = 0; multistate_ptr[i].కీలకం != ఖాళీ; i++) {
			ఒకవేళ (strcasecmp(arg, multistate_ptr[i].కీలకం) == 0) {
				విలువ = multistate_ptr[i].విలువ;
				ఆపు;
			}
		}
		ఒకవేళ (విలువ == -1)
			fatal("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
		ఒకవేళ (*activep && *intptr == -1)
			*intptr = విలువ;
		ఆపు;

	స్థితి s_Host_కీలకం:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		ఒకవేళ (*activep) {
			servconf_కూడు_hostkey(filename, linenum,
			    options, arg, 1);
		}
		ఆపు;

	స్థితి s_Host_కీలకం_Agent:
		charptr = &options->host_కీలకం_agent;
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: missing socket name.",
			    filename, linenum);
		ఒకవేళ (*activep && *charptr == ఖాళీ)
			*charptr = !strcmp(arg, SSH_AUTHSOCKET_ENV_NAME) ?
			    xstrdup(arg) : derelativise_మార్గం(arg);
		ఆపు;

	స్థితి sHostCertificate:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		ఒకవేళ (*activep)
			servconf_కూడు_hostcert(filename, linenum, options, arg);
		ఆపు;

	స్థితి sPidFile:
		charptr = &options->pid_file;
 parse_filename:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: missing file name.",
			    filename, linenum);
		ఒకవేళ (*activep && *charptr == ఖాళీ) {
			*charptr = derelativise_మార్గం(arg);
			/* increase optional counter */
			ఒకవేళ (intptr != ఖాళీ)
				*intptr = *intptr + 1;
		}
		ఆపు;

	స్థితి sModuliFile:
		charptr = &options->moduli_file;
		వెళ్ళు parse_filename;

	స్థితి s_Permit_మూలం_Login:
		intptr = &options->permit_మూలం_login;
		multistate_ptr = multistate_permitrootlogin;
		వెళ్ళు parse_multistate;

	స్థితి sIgnoreRhosts:
		intptr = &options->ignore_rhosts;
		multistate_ptr = multistate_ignore_rhosts;
		వెళ్ళు parse_multistate;

	స్థితి s_Ignore_User_తెలిసిన_Hosts:
		intptr = &options->ignore_user_తెలిసిన_hosts;
 parse_flag:
		multistate_ptr = multistate_flag;
		వెళ్ళు parse_multistate;

	స్థితి sHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		వెళ్ళు parse_flag;

	స్థితి s_Hostbased_ఉపయోగిస్తుంది_Name_From_Packet_Only:
		intptr = &options->hostbased_ఉపయోగిస్తుంది_name_from_packet_only;
		వెళ్ళు parse_flag;

	స్థితి sHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
 parse_pubkey_algos:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: Missing argument.",
			    filename, linenum);
		ఒకవేళ (*arg != '-' &&
		    !sshkey_పేర్లు_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only))
			fatal("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		ఒకవేళ (*activep && *charptr == ఖాళీ)
			*charptr = xstrdup(arg);
		ఆపు;

	స్థితి s_Host_కీలకం_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
		వెళ్ళు parse_pubkey_algos;

	స్థితి sCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		వెళ్ళు parse_pubkey_algos;

	స్థితి sPubkeyAuthentication:
		intptr = &options->pubkey_authentication;
		ca_only = 0;
		వెళ్ళు parse_flag;

	స్థితి sPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		వెళ్ళు parse_pubkey_algos;

	స్థితి sPubkeyAuthOptions:
		intptr = &options->pubkey_auth_options;
		విలువ = 0;
		value2 = -1;
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			ఒకవేళ (strcasecmp(arg, "none") == 0)
				కొనసాగు;
			ఒకవేళ (strcasecmp(arg, "touch-required") == 0)
				విలువ |= PUBKEYAUTH_TOUCH_REQUIRED;
			లేకపోతే ఒకవేళ (strcasecmp(arg, "verify-required") == 0)
				విలువ |= PUBKEYAUTH_VERIFY_REQUIRED;
			లేకపోతే ఒకవేళ (strncasecmp(arg, "max-pk-ok:", 10) == 0) {
				value2 = strtonum(arg + 10, 0, 255, &errstr);
				ఒకవేళ (errstr != ఖాళీ) {
					error("%s line %d: bad %s max-pk-ok "
					    "value: %s", filename, linenum,
					keyword, errstr);
					వెళ్ళు బహిర్గతం;
				}
			} లేకపోతే {
				error("%s line %d: unsupported %s option %s",
				    filename, linenum, keyword, arg);
				వెళ్ళు బహిర్గతం;
			}
		}
		ఒకవేళ (*activep && options->pubkey_auth_options == -1) {
			options->pubkey_auth_options = విలువ;
			options->max_pubkey_ok = value2;
		}
		ఆపు;

#నిర్వచితమైతే KRB5
	స్థితి sKerberosAuthentication:
		intptr = &options->kerberos_authentication;
		వెళ్ళు parse_flag;

	స్థితి sKerberosOrLocalPasswd:
		intptr = &options->kerberos_or_local_passwd;
		వెళ్ళు parse_flag;

	స్థితి sKerberosTicketCleanup:
		intptr = &options->kerberos_ticket_cleanup;
		వెళ్ళు parse_flag;
#నిర్వచితమైతే USE_AFS
	స్థితి sKerberosGetAFSToken:
		intptr = &options->kerberos_get_afs_token;
		వెళ్ళు parse_flag;
#అయితే_ముగింపు /* USE_AFS */
#అయితే_ముగింపు /* KRB5 */

#నిర్వచితమైతే GSSAPI
	స్థితి sGSSAPIAuthentication:
		intptr = &options->gss_authentication;
		వెళ్ళు parse_flag;

	స్థితి sGSSAPICleanupCredentials:
		intptr = &options->gss_cleanup_creds;
		వెళ్ళు parse_flag;

	స్థితి sGSSAPIDelegateCredentials:
		intptr = &options->gss_deleg_creds;
		వెళ్ళు parse_flag;

	స్థితి sGSSAPIStrictAcceptorCheck:
		intptr = &options->gss_strict_acceptor;
		వెళ్ళు parse_flag;
#అయితే_ముగింపు /* GSSAPI */

	స్థితి sPasswordAuthentication:
		intptr = &options->password_authentication;
		వెళ్ళు parse_flag;

	స్థితి sKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		వెళ్ళు parse_flag;

	స్థితి sPrintMotd:
		intptr = &options->print_motd;
		వెళ్ళు parse_flag;

#నిర్వచితం_కాకపోతే DISABLE_LASTLOG
	స్థితి s_Print_చివరి_Log:
		intptr = &options->print_lastlog;
		వెళ్ళు parse_flag;
#అయితే_ముగింపు

	స్థితి sX11Forwarding:
		intptr = &options->x11_forwarding;
		వెళ్ళు parse_flag;

	స్థితి s_X11_Display_స్థానభ్రంశం:
		intptr = &options->x11_display_స్థానభ్రంశం;
 parse_int:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ ((errstr = atoi_err(arg, &విలువ)) != ఖాళీ)
			fatal("%s line %d: %s integer value %s.",
			    filename, linenum, keyword, errstr);
		ఒకవేళ (*activep && *intptr == -1)
			*intptr = విలువ;
		ఆపు;

	స్థితి sX11UseLocalhost:
		intptr = &options->x11_use_localhost;
		వెళ్ళు parse_flag;

	స్థితి sXAuthLocation:
		charptr = &options->xauth_location;
		వెళ్ళు parse_filename;

	స్థితి sPermitTTY:
		intptr = &options->permit_tty;
		వెళ్ళు parse_flag;

	స్థితి sPermitUserRC:
		intptr = &options->permit_user_rc;
		వెళ్ళు parse_flag;

	స్థితి sStrictModes:
		intptr = &options->strict_modes;
		వెళ్ళు parse_flag;

	స్థితి sTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		వెళ్ళు parse_multistate;

	స్థితి s_Permit_ఖాళీలు_Passwords:
		intptr = &options->permit_ఖాళీలు_passwd;
		వెళ్ళు parse_flag;

	స్థితి sPermitUserEnvironment:
		intptr = &options->permit_user_env;
		charptr = &options->permit_user_env_allowlist;
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		విలువ = 0;
		p = ఖాళీ;
		ఒకవేళ (strcmp(arg, "yes") == 0)
			విలువ = 1;
		లేకపోతే ఒకవేళ (strcmp(arg, "no") == 0)
			విలువ = 0;
		లేకపోతే {
			/* Pattern-list specified */
			విలువ = 1;
			p = xstrdup(arg);
		}
		ఒకవేళ (*activep && *intptr == -1) {
			*intptr = విలువ;
			*charptr = p;
			p = ఖాళీ;
		}
		విడుదల(p);
		ఆపు;

	స్థితి sCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		వెళ్ళు parse_multistate;

	స్థితి s_Rekey_హద్దు:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ఒకవేళ (strcmp(arg, "default") == 0) {
			val64 = 0;
		} లేకపోతే {
			ఒకవేళ (పరిశీలన_scaled(arg, &val64) == -1)
				fatal("%.200s line %d: Bad %s number '%s': %s",
				    filename, linenum, keyword,
				    arg, strerror(errno));
			ఒకవేళ (val64 != 0 && val64 < 16)
				fatal("%.200s line %d: %s too small",
				    filename, linenum, keyword);
		}
		ఒకవేళ (*activep && options->rekey_హద్దు == -1)
			options->rekey_హద్దు = val64;
		ఒకవేళ (ac != 0) { /* optional rekey interval present */
			ఒకవేళ (strcmp(av[0], "none") == 0) {
				(శూన్య)argv_తదుపరి(&ac, &av);	/* discard */
				ఆపు;
			}
			intptr = &options->rekey_interval;
			వెళ్ళు parse_సమయం;
		}
		ఆపు;

	స్థితి sGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		multistate_ptr = multistate_gatewayports;
		వెళ్ళు parse_multistate;

	స్థితి sUseDNS:
		intptr = &options->use_dns;
		వెళ్ళు parse_flag;

	స్థితి sSyslogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_తదుపరి(&ac, &av);
		విలువ = log_facility_సంఖ్య(arg);
		ఒకవేళ (విలువ == SYSLOG_FACILITY_NOT_సమితి)
			fatal("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		ఒకవేళ (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) విలువ;
		ఆపు;

	స్థితి sLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_తదుపరి(&ac, &av);
		విలువ = log_level_సంఖ్య(arg);
		ఒకవేళ (విలువ == SYSLOG_LEVEL_NOT_సమితి)
			fatal("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
		ఒకవేళ (*activep && *log_level_ptr == -1)
			*log_level_ptr = (LogLevel) విలువ;
		ఆపు;

	స్థితి sLogVerbose:
		దొరికింది = options->అంకె_log_verbose == 0;
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			ఒకవేళ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				వెళ్ళు బహిర్గతం;
			}
			/* Allow "none" only in first position */
			ఒకవేళ (strcasecmp(arg, "none") == 0) {
				ఒకవేళ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					వెళ్ళు బహిర్గతం;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ఒకవేళ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ఒకవేళ (దొరికింది && *activep) {
			options->log_verbose = strs;
			options->అంకె_log_verbose = nstrs;
			strs = ఖాళీ; /* transferred */
			nstrs = 0;
		}
		ఆపు;

	స్థితి sAllowTcpForwarding:
		intptr = &options->allow_tcp_forwarding;
		multistate_ptr = multistate_tcpfwd;
		వెళ్ళు parse_multistate;

	స్థితి s_Allow_ప్రవాహం_Local_Forwarding:
		intptr = &options->allow_streamlocal_forwarding;
		multistate_ptr = multistate_tcpfwd;
		వెళ్ళు parse_multistate;

	స్థితి sAllowAgentForwarding:
		intptr = &options->allow_agent_forwarding;
		వెళ్ళు parse_flag;

	స్థితి s_Agent_Socket_మార్గం:
		charptr = &options->agent_socket_మార్గం;
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: missing path.", filename, linenum);
		ఒకవేళ (అక్షరశ్రేణి_పోలిక(arg, "shared:", 7) == 0) {
			/* Shared paths must be absolute */
			ఒకవేళ (arg[7] != '/') {
				fatal("%s line %d: invalid shared path.",
				    filename, linenum);
			}
		} లేకపోతే ఒకవేళ (అక్షరశ్రేణి_పోలిక(arg, "user:", 5) == 0) {
			/* User paths must not be empty */
			ఒకవేళ (arg[5] == '\0') {
				fatal("%s line %d: invalid user path.",
				    filename, linenum);
			}
		} లేకపోతే ఒకవేళ (strcmp(arg, "none") != 0)
			fatal("%s line %d: invalid path.", filename, linenum);
		ఒకవేళ (*activep && *charptr == ఖాళీ)
			*charptr = xstrdup(arg);
		ఆపు;

	స్థితి sDisableForwarding:
		intptr = &options->disable_forwarding;
		వెళ్ళు parse_flag;

	స్థితి sAllowUsers:
		chararrayptr = &options->allow_users;
		uintptr = &options->అంకె_allow_users;
 parse_allowdenyusers:
		/* XXX appends to list; doesn't respect first-match-wins */
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			ఒకవేళ (*arg == '\0' ||
			    సరిపోలిక_user(ఖాళీ, ఖాళీ, ఖాళీ, arg) == -1)
				fatal("%s line %d: invalid %s pattern: \"%s\"",
				    filename, linenum, keyword, arg);
			దొరికింది = 1;
			ఒకవేళ (!*activep)
				కొనసాగు;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		ఒకవేళ (!దొరికింది) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ఆపు;

	స్థితి sDenyUsers:
		chararrayptr = &options->deny_users;
		uintptr = &options->అంకె_deny_users;
		వెళ్ళు parse_allowdenyusers;

	స్థితి sAllowGroups:
		chararrayptr = &options->allow_groups;
		uintptr = &options->అంకె_allow_groups;
		/* XXX appends to list; doesn't respect first-match-wins */
 parse_allowdenygroups:
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			ఒకవేళ (*arg == '\0')
				fatal("%s line %d: empty %s pattern",
				    filename, linenum, keyword);
			దొరికింది = 1;
			ఒకవేళ (!*activep)
				కొనసాగు;
			opt_array_append(filename, linenum, keyword,
			    chararrayptr, uintptr, arg);
		}
		ఒకవేళ (!దొరికింది) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ఆపు;

	స్థితి sDenyGroups:
		chararrayptr = &options->deny_groups;
		uintptr = &options->అంకె_deny_groups;
		వెళ్ళు parse_allowdenygroups;

	స్థితి sCiphers:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ఒకవేళ (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		ఒకవేళ (options->ciphers == ఖాళీ)
			options->ciphers = xstrdup(arg);
		ఆపు;

	స్థితి sMacs:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ఒకవేళ (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 mac spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		ఒకవేళ (options->macs == ఖాళీ)
			options->macs = xstrdup(arg);
		ఆపు;

	స్థితి sKexAlgorithms:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ఒకవేళ (*arg != '-' &&
		    !kex_పేర్లు_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg))
			fatal("%s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
		ఒకవేళ (options->kex_algorithms == ఖాళీ)
			options->kex_algorithms = xstrdup(arg);
		ఆపు;

	స్థితి sSubsystem:
		ఒకవేళ ((arg = argv_తదుపరి(&ac, &av)) == ఖాళీ || *arg == '\0' ||
		   ((arg2 = argv_తదుపరి(&ac, &av)) == ఖాళీ || *arg2 == '\0'))
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ఒకవేళ (!*activep) {
			argv_consume(&ac);
			ఆపు;
		}
		దొరికింది = 0;
		కొరకు (i = 0; i < options->అంకె_subsystems; i++) {
			ఒకవేళ (strcmp(arg, options->subsystem_name[i]) == 0) {
				దొరికింది = 1;
				ఆపు;
			}
		}
		ఒకవేళ (దొరికింది) {
			debug("%s line %d: Subsystem '%s' already defined.",
			    filename, linenum, arg);
			argv_consume(&ac);
			ఆపు;
		}
		options->subsystem_name = xrecallocarray(
		    options->subsystem_name, options->అంకె_subsystems,
		    options->అంకె_subsystems + 1,
		    పరిమాణం(*options->subsystem_name));
		options->subsystem_command = xrecallocarray(
		    options->subsystem_command, options->అంకె_subsystems,
		    options->అంకె_subsystems + 1,
		    పరిమాణం(*options->subsystem_command));
		options->subsystem_వాదనలు = xrecallocarray(
		    options->subsystem_వాదనలు, options->అంకె_subsystems,
		    options->అంకె_subsystems + 1,
		    పరిమాణం(*options->subsystem_వాదనలు));
		options->subsystem_name[options->అంకె_subsystems] = xstrdup(arg);
		options->subsystem_command[options->అంకె_subsystems] =
		    xstrdup(arg2);
		/* Collect arguments (separate to executable) */
		arg = argv_assemble(1, &arg2); /* quote command correctly */
		arg2 = argv_assemble(ac, av); /* rest of command */
		xasprintf(&options->subsystem_వాదనలు[options->అంకె_subsystems],
		    "%s%s%s", arg, *arg2 == '\0' ? "" : " ", arg2);
		విడుదల(arg2);
		విడుదల(arg);
		argv_consume(&ac);
		options->అంకె_subsystems++;
		ఆపు;

	స్థితి sMaxStartups:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* begin:rate:max */
		ఒకవేళ ((n = అక్షరశ్రేణి_చదువు(arg, "%d:%d:%d",
		    &విలువ, &value2, &value3)) == 3) {
			ఒకవేళ (విలువ > value3 || value2 > 100 || value2 < 1)
				fatal("%s line %d: Invalid %s spec.",
				    filename, linenum, keyword);
		} లేకపోతే ఒకవేళ (n == 1) {
			value3 = విలువ;
			value2 = -1;
		} లేకపోతే {
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		}
		ఒకవేళ (విలువ <= 0 || value3 <= 0)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		ఒకవేళ (*activep && options->max_startups == -1) {
			options->max_startups_begin = విలువ;
			options->max_startups_రేటు = value2;
			options->max_startups = value3;
		}
		ఆపు;

	స్థితి s_చొప్పున_ఆధారం_Net_ఖండం_కొలత:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ఎంపిక (n = అక్షరశ్రేణి_చదువు(arg, "%d:%d", &విలువ, &value2)) {
		స్థితి 2:
			ఒకవేళ (value2 < 0 || value2 > 128)
				n = -1;
			/* FALLTHROUGH */
		స్థితి 1:
			ఒకవేళ (విలువ < 0 || విలువ > 32)
				n = -1;
		}
		ఒకవేళ (n != 1 && n != 2)
			fatal("%s line %d: Invalid %s spec.",
			    filename, linenum, keyword);
		ఒకవేళ (*activep && options->చొప్పున_ఆధారం_masklen_ipv4 == -1) {
			options->చొప్పున_ఆధారం_masklen_ipv4 = విలువ;
			ఒకవేళ (n == 2)
				options->చొప్పున_ఆధారం_masklen_ipv6 = value2;
		}
		ఆపు;

	స్థితి s_చొప్పున_ఆధారం_Max_Startups:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ఒకవేళ (strcmp(arg, "none") == 0) { /* no limit */
			విలువ = గరిష్ఠ_పూర్ణాంకం;
		} లేకపోతే {
			ఒకవేళ ((errstr = atoi_err(arg, &విలువ)) != ఖాళీ)
				fatal("%s line %d: %s integer value %s.",
				    filename, linenum, keyword, errstr);
		}
		ఒకవేళ (*activep && options->చొప్పున_ఆధారం_max_startups == -1)
			options->చొప్పున_ఆధారం_max_startups = విలువ;
		ఆపు;

	స్థితి s_చొప్పున_ఆధారం_Penalty_Exempt_List:
		charptr = &options->చొప్పున_ఆధారం_penalty_exempt;
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: missing argument.",
			    filename, linenum);
		ఒకవేళ (addr_సరిపోలిక_list(ఖాళీ, arg) != 0) {
			fatal("%s line %d: keyword %s "
			    "invalid address argument.",
			    filename, linenum, keyword);
		}
		ఒకవేళ (*activep && *charptr == ఖాళీ)
			*charptr = xstrdup(arg);
		ఆపు;

	స్థితి s_చొప్పున_ఆధారం_Penalties:
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			స్థిరరాశి అక్షరం *q = ఖాళీ;

			దొరికింది = 1;
			intptr = ఖాళీ;
			doubleptr = ఖాళీ;
			విలువ = -1;
			value2 = 0;
			/* Allow no/yes only in first position */
			ఒకవేళ (strcasecmp(arg, "no") == 0 ||
			    (value2 = (strcasecmp(arg, "yes") == 0))) {
				ఒకవేళ (ac > 0) {
					fatal("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
				}
				ఒకవేళ (*activep &&
				    options->చొప్పున_ఆధారం_penalty.enabled == -1)
					options->చొప్పున_ఆధారం_penalty.enabled = value2;
				కొనసాగు;
			} లేకపోతే ఒకవేళ ((q = strprefix(arg, "crash:", 0)) != ఖాళీ) {
				doubleptr = &options->చొప్పున_ఆధారం_penalty.penalty_crash;
			} లేకపోతే ఒకవేళ ((q = strprefix(arg, "authfail:", 0)) != ఖాళీ) {
				doubleptr = &options->చొప్పున_ఆధారం_penalty.penalty_authfail;
			} లేకపోతే ఒకవేళ ((q = strprefix(arg, "invaliduser:", 0)) != ఖాళీ) {
				doubleptr = &options->చొప్పున_ఆధారం_penalty.penalty_invaliduser;
			} లేకపోతే ఒకవేళ ((q = strprefix(arg, "noauth:", 0)) != ఖాళీ) {
				doubleptr = &options->చొప్పున_ఆధారం_penalty.penalty_noauth;
			} లేకపోతే ఒకవేళ ((q = strprefix(arg, "grace-exceeded:", 0)) != ఖాళీ) {
				doubleptr = &options->చొప్పున_ఆధారం_penalty.penalty_grace;
			} లేకపోతే ఒకవేళ ((q = strprefix(arg, "refuseconnection:", 0)) != ఖాళీ) {
				doubleptr = &options->చొప్పున_ఆధారం_penalty.penalty_refuseconnection;
			} లేకపోతే ఒకవేళ ((q = strprefix(arg, "max:", 0)) != ఖాళీ) {
				doubleptr = &options->చొప్పున_ఆధారం_penalty.penalty_max;
			} లేకపోతే ఒకవేళ ((q = strprefix(arg, "min:", 0)) != ఖాళీ) {
				doubleptr = &options->చొప్పున_ఆధారం_penalty.penalty_min;
			} లేకపోతే ఒకవేళ ((q = strprefix(arg, "max-sources4:", 0)) != ఖాళీ) {
				intptr = &options->చొప్పున_ఆధారం_penalty.max_sources4;
				ఒకవేళ ((errstr = atoi_err(q, &విలువ)) != ఖాళీ)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} లేకపోతే ఒకవేళ ((q = strprefix(arg, "max-sources6:", 0)) != ఖాళీ) {
				intptr = &options->చొప్పున_ఆధారం_penalty.max_sources6;
				ఒకవేళ ((errstr = atoi_err(q, &విలువ)) != ఖాళీ)
					fatal("%s line %d: %s value %s.",
					    filename, linenum, keyword, errstr);
			} లేకపోతే ఒకవేళ (strcmp(arg, "overflow:deny-all") == 0) {
				intptr = &options->చొప్పున_ఆధారం_penalty.అధికప్రవాహం_బహుళకం;
				విలువ = చొప్పున_ఆధారం_PENALTY_అధికప్రవాహం_DENY_ALL;
			} లేకపోతే ఒకవేళ (strcmp(arg, "overflow:permissive") == 0) {
				intptr = &options->చొప్పున_ఆధారం_penalty.అధికప్రవాహం_బహుళకం;
				విలువ = చొప్పున_ఆధారం_PENALTY_అధికప్రవాహం_PERMISSIVE;
			} లేకపోతే ఒకవేళ (strcmp(arg, "overflow6:deny-all") == 0) {
				intptr = &options->చొప్పున_ఆధారం_penalty.అధికప్రవాహం_mode6;
				విలువ = చొప్పున_ఆధారం_PENALTY_అధికప్రవాహం_DENY_ALL;
			} లేకపోతే ఒకవేళ (strcmp(arg, "overflow6:permissive") == 0) {
				intptr = &options->చొప్పున_ఆధారం_penalty.అధికప్రవాహం_mode6;
				విలువ = చొప్పున_ఆధారం_PENALTY_అధికప్రవాహం_PERMISSIVE;
			} లేకపోతే {
				fatal("%s line %d: unsupported %s keyword %s",
				    filename, linenum, keyword, arg);
			}

			ఒకవేళ (doubleptr != ఖాళీ) {
				ఒకవేళ ((dvalue = convtime_double(q)) < 0) {
					fatal("%s line %d: invalid %s time value.",
					    filename, linenum, keyword);
				}
				ఒకవేళ (*activep && *doubleptr < 0.0) {
					*doubleptr = dvalue;
					options->చొప్పున_ఆధారం_penalty.enabled = 1;
				}
			} లేకపోతే ఒకవేళ (intptr != ఖాళీ) {
				ఒకవేళ (*activep && *intptr == -1) {
					*intptr = విలువ;
					options->చొప్పున_ఆధారం_penalty.enabled = 1;
				}
			} లేకపోతే {
				fatal_f("%s line %d: internal error",
				    filename, linenum);
			}
		}
		ఒకవేళ (!దొరికింది) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ఆపు;

	స్థితి sMaxAuthTries:
		intptr = &options->max_authtries;
		వెళ్ళు parse_int;

	స్థితి sMaxSessions:
		intptr = &options->max_sessions;
		వెళ్ళు parse_int;

	స్థితి sBanner:
		charptr = &options->banner;
		వెళ్ళు parse_filename;

	/*
	 * These options can contain %X options expanded at
	 * connect time, so that you can specify paths like:
	 *
	 * AuthorizedKeysFile	/etc/ssh_keys/%u
	 */
	స్థితి s_Authorized_కీలకాలు_File:
		uintptr = &options->అంకె_authkeys_files;
		chararrayptr = &options->authorized_కీలకాలు_files;
 parse_filenames:
		దొరికింది = *uintptr == 0;
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			ఒకవేళ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				వెళ్ళు బహిర్గతం;
			}
			/* Allow "none" only in first position */
			ఒకవేళ (strcasecmp(arg, "none") == 0) {
				ఒకవేళ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					వెళ్ళు బహిర్గతం;
				}
			}
			arg2 = tilde_expand_filename(arg, getuid());
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			విడుదల(arg2);
		}
		ఒకవేళ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ఒకవేళ (దొరికింది && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = ఖాళీ; /* transferred */
			nstrs = 0;
		}
		ఆపు;

	స్థితి sAuthorizedPrincipalsFile:
		charptr = &options->authorized_principals_file;
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ఒకవేళ (*activep && *charptr == ఖాళీ) {
			*charptr = tilde_expand_filename(arg, getuid());
			/* increase optional counter */
			ఒకవేళ (intptr != ఖాళీ)
				*intptr = *intptr + 1;
		}
		ఆపు;

	స్థితి sClientAliveInterval:
		intptr = &options->client_alive_interval;
		వెళ్ళు parse_సమయం;

	స్థితి s_Client_Alive_లెక్క_Max:
		intptr = &options->client_alive_లెక్క_max;
		వెళ్ళు parse_int;

	స్థితి sAcceptEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			ఒకవేళ (*arg == '\0' || strchr(arg, '=') != ఖాళీ)
				fatal("%s line %d: Invalid environment name.",
				    filename, linenum);
			దొరికింది = 1;
			ఒకవేళ (!*activep)
				కొనసాగు;
			opt_array_append(filename, linenum, keyword,
			    &options->accept_env, &options->అంకె_accept_env,
			    arg);
		}
		ఒకవేళ (!దొరికింది) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ఆపు;

	స్థితి s_సమితి_Env:
		దొరికింది = options->అంకె_setenv == 0;
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			ఒకవేళ (*arg == '\0' || strchr(arg, '=') == ఖాళీ)
				fatal("%s line %d: Invalid environment.",
				    filename, linenum);
			ఒకవేళ (lookup_setenv_లోపల_list(arg, strs, nstrs) != ఖాళీ) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				కొనసాగు;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ఒకవేళ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ఒకవేళ (దొరికింది && *activep) {
			options->setenv = strs;
			options->అంకె_setenv = nstrs;
			strs = ఖాళీ; /* transferred */
			nstrs = 0;
		}
		ఆపు;

	స్థితి sPermitTunnel:
		intptr = &options->permit_tun;
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		విలువ = -1;
		కొరకు (i = 0; tunmode_desc[i].val != -1; i++)
			ఒకవేళ (strcmp(tunmode_desc[i].పాఠ్యం, arg) == 0) {
				విలువ = tunmode_desc[i].val;
				ఆపు;
			}
		ఒకవేళ (విలువ == -1)
			fatal("%s line %d: bad %s argument %s",
			    filename, linenum, keyword, arg);
		ఒకవేళ (*activep && *intptr == -1)
			*intptr = విలువ;
		ఆపు;

	స్థితి sInclude:
		ఒకవేళ (cmdline) {
			fatal("Include directive not supported as a "
			    "command-line option");
		}
		విలువ = 0;
		అయితే ((arg2 = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			ఒకవేళ (*arg2 == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				వెళ్ళు బహిర్గతం;
			}
			విలువ++;
			దొరికింది = 0;
			ఒకవేళ (*arg2 != '/' && *arg2 != '~') {
				xasprintf(&arg, "%s/%s", SSHDIR, arg2);
			} లేకపోతే
				arg = xstrdup(arg2);

			/*
			 * Don't let included files clobber the containing
			 * file's Match state.
			 */
			oactive = *activep;

			/* consult cache of include files */
			TAILQ_FOREACH(అంశం, includes, నమోదు_2) {
				ఒకవేళ (strcmp(అంశం->selector, arg) != 0)
					కొనసాగు;
				ఒకవేళ (అంశం->filename != ఖాళీ) {
					parse_server_config_లోతు(options,
					    అంశం->filename, అంశం->contents,
					    includes, connectinfo,
					    (*inc_flags & SSHCFG_సరిపోలిక_ONLY
					        ? SSHCFG_సరిపోలిక_ONLY : (oactive
					            ? 0 : SSHCFG_NEVERMATCH)),
					    activep, లోతు + 1);
				}
				దొరికింది = 1;
				*activep = oactive;
			}
			ఒకవేళ (దొరికింది != 0) {
				విడుదల(arg);
				కొనసాగు;
			}

			/* requested glob was not in cache */
			debug2("%s line %d: new include %s",
			    filename, linenum, arg);
			ఒకవేళ ((r = glob(arg, 0, ఖాళీ, &gbuf)) != 0) {
				ఒకవేళ (r != GLOB_NOMATCH) {
					fatal("%s line %d: include \"%s\" glob "
					    "failed", filename, linenum, arg);
				}
				/*
				 * If no entry matched then record a
				 * placeholder to skip later glob calls.
				 */
				debug2("%s line %d: no match for %s",
				    filename, linenum, arg);
				అంశం = xcalloc(1, పరిమాణం(*అంశం));
				అంశం->selector = xstrdup(arg);
				TAILQ_INSERT_TAIL(includes,
				    అంశం, నమోదు_2);
			}
			ఒకవేళ (gbuf.gl_pathc > గరిష్ఠ_పూర్ణాంకం)
				fatal_f("too many glob results");
			కొరకు (n = 0; n < (పూర్ణాంకం)gbuf.gl_pathc; n++) {
				debug2("%s line %d: including %s",
				    filename, linenum, gbuf.gl_pathv[n]);
				అంశం = xcalloc(1, పరిమాణం(*అంశం));
				అంశం->selector = xstrdup(arg);
				అంశం->filename = xstrdup(gbuf.gl_pathv[n]);
				ఒకవేళ ((అంశం->contents = sshbuf_new()) == ఖాళీ)
					fatal_f("sshbuf_new failed");
				ఎక్కించు_server_config(అంశం->filename,
				    అంశం->contents);
				parse_server_config_లోతు(options,
				    అంశం->filename, అంశం->contents,
				    includes, connectinfo,
				    (*inc_flags & SSHCFG_సరిపోలిక_ONLY
				        ? SSHCFG_సరిపోలిక_ONLY : (oactive
				            ? 0 : SSHCFG_NEVERMATCH)),
				    activep, లోతు + 1);
				*activep = oactive;
				TAILQ_INSERT_TAIL(includes, అంశం, నమోదు_2);
			}
			globfree(&gbuf);
			విడుదల(arg);
		}
		ఒకవేళ (విలువ == 0) {
			fatal("%s line %d: %s missing filename argument",
			    filename, linenum, keyword);
		}
		ఆపు;

	స్థితి s_సరిపోలిక:
		ఒకవేళ (cmdline)
			fatal("Match directive not supported as a command-line "
			    "option");
		విలువ = సరిపోలిక_cfg_పంక్తి(str, &ac, &av, linenum,
		    (*inc_flags & SSHCFG_NEVERMATCH ? ఖాళీ : connectinfo));
		ఒకవేళ (విలువ < 0)
			fatal("%s line %d: Bad Match condition", filename,
			    linenum);
		*activep = (*inc_flags & SSHCFG_NEVERMATCH) ? 0 : విలువ;
		/*
		 * The MATCH_ONLY flag is applicable only until the first
		 * match block.
		 */
		*inc_flags &= ~SSHCFG_సరిపోలిక_ONLY;
		ఆపు;

	స్థితి sPermitListen:
	స్థితి sPermitOpen:
		ఒకవేళ (opcode == sPermitListen) {
			uintptr = &options->అంకె_permitted_listens;
			chararrayptr = &options->permitted_listens;
		} లేకపోతే {
			uintptr = &options->అంకె_permitted_opens;
			chararrayptr = &options->permitted_opens;
		}
		దొరికింది = *uintptr == 0;
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			ఒకవేళ (strcmp(arg, "any") == 0 ||
			    strcmp(arg, "none") == 0) {
				ఒకవేళ (nstrs != 0) {
					fatal("%s line %d: %s must appear "
					    "alone on a %s line.",
					    filename, linenum, arg, keyword);
				}
				opt_array_append(filename, linenum, keyword,
				    &strs, &nstrs, arg);
				కొనసాగు;
			}

			ఒకవేళ (opcode == sPermitListen &&
			    strchr(arg, ':') == ఖాళీ) {
				/*
				 * Allow bare port number for PermitListen
				 * to indicate a wildcard listen host.
				 */
				xasprintf(&arg2, "*:%s", arg);
			} లేకపోతే {
				arg2 = xstrdup(arg);
				p = hpdelim(&arg);
				ఒకవేళ (p == ఖాళీ) {
					fatal("%s line %d: %s missing host",
					    filename, linenum, keyword);
				}
				p = cleanhostname(p);
			}
			ఒకవేళ (arg == ఖాళీ ||
			    ((పోర్టు = permitopen_పోర్టు(arg)) < 0)) {
				fatal("%s line %d: %s bad port number",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg2);
			విడుదల(arg2);
		}
		ఒకవేళ (nstrs == 0) {
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		}
		ఒకవేళ (దొరికింది && *activep) {
			*chararrayptr = strs;
			*uintptr = nstrs;
			strs = ఖాళీ; /* transferred */
			nstrs = 0;
		}
		ఆపు;

	స్థితి sForceCommand:
		ఒకవేళ (str == ఖాళీ || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		ఒకవేళ (*activep && options->adm_forced_command == ఖాళీ)
			options->adm_forced_command = xstrdup(str + len);
		argv_consume(&ac);
		ఆపు;

	స్థితి sChrootDirectory:
		charptr = &options->chroot_directory;

		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ఒకవేళ (*activep && *charptr == ఖాళీ)
			*charptr = xstrdup(arg);
		ఆపు;

	స్థితి sTrustedUserCAKeys:
		charptr = &options->trusted_user_ca_కీలకాలు;
		వెళ్ళు parse_filename;

	స్థితి s_Revoked_కీలకాలు:
		uintptr = &options->అంకె_revoked_కీలకాలు_files;
		chararrayptr = &options->revoked_కీలకాలు_files;
		వెళ్ళు parse_filenames;

	స్థితి s_Security_కీలకం_Provider:
		charptr = &options->sk_provider;
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ఒకవేళ (*activep && *charptr == ఖాళీ) {
			*charptr = strcasecmp(arg, "internal") == 0 ?
			    xstrdup(arg) : derelativise_మార్గం(arg);
			/* increase optional counter */
			ఒకవేళ (intptr != ఖాళీ)
				*intptr = *intptr + 1;
		}
		ఆపు;

	స్థితి sIPQoS:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ఒకవేళ ((విలువ = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		ఒకవేళ (విలువ == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			విలువ = గరిష్ఠ_పూర్ణాంకం;
		}
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (arg == ఖాళీ)
			value2 = విలువ;
		లేకపోతే ఒకవేళ ((value2 = parse_ipqos(arg)) == -1)
			fatal("%s line %d: Bad %s value: %s",
			    filename, linenum, keyword, arg);
		ఒకవేళ (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = గరిష్ఠ_పూర్ణాంకం;
		}
		ఒకవేళ (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = విలువ;
			options->ip_qos_bulk = value2;
		}
		ఆపు;

	స్థితి s_సంస్కరణ_Addendum:
		ఒకవేళ (str == ఖాళీ || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		ఒకవేళ (strchr(str + len, '\r') != ఖాళీ) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		ఒకవేళ ((arg = strchr(పంక్తి, '#')) != ఖాళీ) {
			*arg = '\0';
			rtrim(పంక్తి);
		}
		ఒకవేళ (*activep && options->సంస్కరణ_addendum == ఖాళీ) {
			ఒకవేళ (strcasecmp(str + len, "none") == 0)
				options->సంస్కరణ_addendum = xstrdup("");
			లేకపోతే
				options->సంస్కరణ_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		ఆపు;

	స్థితి s_Authorized_కీలకాలు_Command:
		charptr = &options->authorized_కీలకాలు_command;
 parse_command:
		len = strspn(str, WHITESPACE);
		ఒకవేళ (str[len] != '/' && strcasecmp(str + len, "none") != 0) {
			fatal("%.200s line %d: %s must be an absolute path",
			    filename, linenum, keyword);
		}
		ఒకవేళ (*activep && *charptr == ఖాళీ)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		ఆపు;

	స్థితి s_Authorized_కీలకాలు_Command_User:
		charptr = &options->authorized_కీలకాలు_command_user;
 parse_localuser:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0') {
			fatal("%s line %d: missing %s argument.",
			    filename, linenum, keyword);
		}
		ఒకవేళ (*activep && *charptr == ఖాళీ)
			*charptr = xstrdup(arg);
		ఆపు;

	స్థితి sAuthorizedPrincipalsCommand:
		charptr = &options->authorized_principals_command;
		వెళ్ళు parse_command;

	స్థితి sAuthorizedPrincipalsCommandUser:
		charptr = &options->authorized_principals_command_user;
		వెళ్ళు parse_localuser;

	స్థితి sAuthenticationMethods:
		దొరికింది = options->అంకె_auth_methods == 0;
		విలువ = 0; /* seen "any" pseudo-method */
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			ఒకవేళ (strcmp(arg, "any") == 0) {
				ఒకవేళ (nstrs > 0) {
					fatal("%s line %d: \"any\" must "
					    "appear alone in %s",
					    filename, linenum, keyword);
				}
				విలువ = 1;
			} లేకపోతే ఒకవేళ (విలువ) {
				fatal("%s line %d: \"any\" must appear "
				    "alone in %s", filename, linenum, keyword);
			} లేకపోతే ఒకవేళ (auth2_methods_valid(arg, 0) != 0) {
				fatal("%s line %d: invalid %s method list.",
				    filename, linenum, keyword);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ఒకవేళ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ఒకవేళ (దొరికింది && *activep) {
			options->auth_methods = strs;
			options->అంకె_auth_methods = nstrs;
			strs = ఖాళీ; /* transferred */
			nstrs = 0;
		}
		ఆపు;

	స్థితి s_ప్రవాహం_Local_Bind_ముసుగు:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		/* Parse mode in octal format */
		విలువ = strtol(arg, &p, 8);
		ఒకవేళ (arg == p || విలువ < 0 || విలువ > 0777)
			fatal("%s line %d: Invalid %s.",
			    filename, linenum, keyword);
		ఒకవేళ (*activep &&
		    options->fwd_opts.streamlocal_bind_ముసుగు == (బహుళకం_t)-1)
			options->fwd_opts.streamlocal_bind_ముసుగు = (బహుళకం_t)విలువ;
		ఆపు;

	స్థితి s_ప్రవాహం_Local_Bind_Unlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		వెళ్ళు parse_flag;

	స్థితి sFingerprintHash:
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ఒకవేళ ((విలువ = ssh_digest_alg_by_name(arg)) == -1)
			fatal("%.200s line %d: Invalid %s algorithm \"%s\".",
			    filename, linenum, keyword, arg);
		ఒకవేళ (*activep)
			options->fingerprint_hash = విలువ;
		ఆపు;

	స్థితి sExposeAuthInfo:
		intptr = &options->expose_userauth_info;
		వెళ్ళు parse_flag;

	స్థితి sRDomain:
#ఒకవేళ !defined(__OpenBSD__) && !defined(HAVE_SYS_సమితి_PROCESS_RDOMAIN)
		fatal("%s line %d: setting RDomain not supported on this "
		    "platform.", filename, linenum);
#అయితే_ముగింపు
		charptr = &options->routing_domain;
		arg = argv_తదుపరి(&ac, &av);
		ఒకవేళ (!arg || *arg == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		ఒకవేళ (strcasecmp(arg, "none") != 0 && strcmp(arg, "%D") != 0 &&
		    !valid_rdomain(arg))
			fatal("%s line %d: invalid routing domain",
			    filename, linenum);
		ఒకవేళ (*activep && *charptr == ఖాళీ)
			*charptr = xstrdup(arg);
		ఆపు;

	స్థితి sRequiredRSASize:
		intptr = &options->required_rsa_కొలత;
		వెళ్ళు parse_int;

	స్థితి sChannelTimeout:
		దొరికింది = options->అంకె_channel_timeouts == 0;
		అయితే ((arg = argv_తదుపరి(&ac, &av)) != ఖాళీ) {
			/* Allow "none" only in first position */
			ఒకవేళ (strcasecmp(arg, "none") == 0) {
				ఒకవేళ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					వెళ్ళు బహిర్గతం;
				}
			} లేకపోతే ఒకవేళ (parse_నమూనా_interval(arg,
			    ఖాళీ, ఖాళీ) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ఒకవేళ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ఒకవేళ (దొరికింది && *activep) {
			options->channel_timeouts = strs;
			options->అంకె_channel_timeouts = nstrs;
			strs = ఖాళీ; /* transferred */
			nstrs = 0;
		}
		ఆపు;

	స్థితి s_వాడని_Connection_Timeout:
		intptr = &options->వాడని_connection_timeout;
		/* peek at first arg for "none" so we can reuse parse_time */
		ఒకవేళ (av[0] != ఖాళీ && strcasecmp(av[0], "none") == 0) {
			(శూన్య)argv_తదుపరి(&ac, &av); /* consume arg */
			ఒకవేళ (*activep)
				*intptr = 0;
			ఆపు;
		}
		వెళ్ళు parse_సమయం;

	స్థితి s_Sshd_Session_మార్గం:
		charptr = &options->sshd_session_మార్గం;
		వెళ్ళు parse_filename;

	స్థితి s_Sshd_Auth_మార్గం:
		charptr = &options->sshd_auth_మార్గం;
		వెళ్ళు parse_filename;

	స్థితి sRefuseConnection:
		intptr = &options->refuse_connection;
		multistate_ptr = multistate_flag;
		వెళ్ళు parse_multistate;

	స్థితి sWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		వెళ్ళు parse_multistate;

	స్థితి sDeprecated:
	స్థితి sIgnore:
	స్థితి sUnsupported:
		do_log2(opcode == sIgnore ?
		    SYSLOG_LEVEL_DEBUG2 : SYSLOG_LEVEL_INFO,
		    "%s line %d: %s option %s", filename, linenum,
		    opcode == sUnsupported ? "Unsupported" : "Deprecated",
		    keyword);
		argv_consume(&ac);
		ఆపు;

	అప్రమేయ:
		fatal("%s line %d: Missing handler for opcode %s (%d)",
		    filename, linenum, keyword, opcode);
	}
	/* Check that there is no garbage at end of line. */
	ఒకవేళ (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		వెళ్ళు బహిర్గతం;
	}

	/* success */
	ret = 0;
 బహిర్గతం:
	opt_array_free2(strs, ఖాళీ, nstrs);
	argv_free(oav, oac);
	తిరిగి ret;
}

పూర్ణాంకం
process_server_config_పంక్తి(ServerOptions *options, అక్షరం *పంక్తి,
    స్థిరరాశి అక్షరం *filename, పూర్ణాంకం linenum, పూర్ణాంకం *activep,
    నిర్మాణం connection_info *connectinfo, నిర్మాణం include_list *includes)
{
	పూర్ణాంకం inc_flags = 0;

	తిరిగి process_server_config_పంక్తి_లోతు(options, పంక్తి, filename,
	    linenum, activep, connectinfo, &inc_flags, 0, includes);
}


/* Reads the server configuration file. */

శూన్య
ఎక్కించు_server_config(స్థిరరాశి అక్షరం *filename, నిర్మాణం sshbuf *conf)
{
	నిర్మాణం stat st;
	అక్షరం *పంక్తి = ఖాళీ, *cp;
	కొలత_t linesize = 0;
	FILE *f;
	పూర్ణాంకం r;

	debug2_f("filename %s", filename);
	ఒకవేళ ((f = fopen(filename, "r")) == ఖాళీ) {
		perror(filename);
		నిష్క్రమించు(1);
	}
	sshbuf_reset(conf);
	/* grow buffer, so realloc is avoided for large config files */
	ఒకవేళ (fstat(fileno(f), &st) == 0 && st.st_size > 0 &&
	    (r = sshbuf_allocate(conf, st.st_size)) != 0)
		fatal_fr(r, "allocate");
	అయితే (getline(&పంక్తి, &linesize, f) != -1) {
		/*
		 * Strip whitespace
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages
		 */
		cp = పంక్తి + strspn(పంక్తి, " \t\r");
		ఒకవేళ ((r = sshbuf_put(conf, cp, అక్షరశ్రేణి_పొడవు(cp))) != 0)
			fatal_fr(r, "sshbuf_put");
	}
	విడుదల(పంక్తి);
	ఒకవేళ ((r = sshbuf_put_u8(conf, 0)) != 0)
		fatal_fr(r, "sshbuf_put_u8");
	fclose(f);
	debug2_f("done config len = %zu", sshbuf_len(conf));
}

శూన్య
parse_server_సరిపోలిక_config(ServerOptions *options,
   నిర్మాణం include_list *includes, నిర్మాణం connection_info *connectinfo)
{
	ServerOptions mo;

	initialize_server_options(&mo);
	parse_server_config(&mo, "reprocess config", cfg, includes,
	    connectinfo, 0);
	copy_సమితి_server_options(options, &mo, 0);
	free_server_options(&mo);
}

పూర్ణాంకం
parse_server_సరిపోలిక_testspec(నిర్మాణం connection_info *ci, అక్షరం *spec)
{
	అక్షరం *p;
	స్థిరరాశి అక్షరం *val;

	అయితే ((p = strsep(&spec, ",")) && *p != '\0') {
		ఒకవేళ ((val = strprefix(p, "addr=", 0)) != ఖాళీ) {
			ci->చిరునామా = xstrdup(val);
		} లేకపోతే ఒకవేళ ((val = strprefix(p, "host=", 0)) != ఖాళీ) {
			ci->host = xstrdup(val);
		} లేకపోతే ఒకవేళ ((val = strprefix(p, "user=", 0)) != ఖాళీ) {
			ci->user = xstrdup(val);
		} లేకపోతే ఒకవేళ ((val = strprefix(p, "laddr=", 0)) != ఖాళీ) {
			ci->laddress = xstrdup(val);
		} లేకపోతే ఒకవేళ ((val = strprefix(p, "rdomain=", 0)) != ఖాళీ) {
			ci->rdomain = xstrdup(val);
		} లేకపోతే ఒకవేళ ((val = strprefix(p, "lport=", 0)) != ఖాళీ) {
			ci->lport = a2port(val);
			ఒకవేళ (ci->lport == -1) {
				fprintf(stderr, "Invalid port '%s' in test mode"
				    " specification %s\n", p+6, p);
				తిరిగి -1;
			}
		} లేకపోతే ఒకవేళ (strcmp(p, "invalid-user") == 0) {
			ci->user_invalid = 1;
		} లేకపోతే {
			fprintf(stderr, "Invalid test mode specification %s\n",
			    p);
			తిరిగి -1;
		}
	}
	తిరిగి 0;
}

శూన్య
servconf_విలీనం_subsystems(ServerOptions *dst, ServerOptions *src)
{
	u_int i, j, దొరికింది;

	కొరకు (i = 0; i < src->అంకె_subsystems; i++) {
		దొరికింది = 0;
		కొరకు (j = 0; j < dst->అంకె_subsystems; j++) {
			ఒకవేళ (strcmp(src->subsystem_name[i],
			    dst->subsystem_name[j]) == 0) {
				దొరికింది = 1;
				ఆపు;
			}
		}
		ఒకవేళ (దొరికింది) {
			debug_f("override \"%s\"", dst->subsystem_name[j]);
			విడుదల(dst->subsystem_command[j]);
			విడుదల(dst->subsystem_వాదనలు[j]);
			dst->subsystem_command[j] =
			    xstrdup(src->subsystem_command[i]);
			dst->subsystem_వాదనలు[j] =
			    xstrdup(src->subsystem_వాదనలు[i]);
			కొనసాగు;
		}
		debug_f("add \"%s\"", src->subsystem_name[i]);
		dst->subsystem_name = xrecallocarray(
		    dst->subsystem_name, dst->అంకె_subsystems,
		    dst->అంకె_subsystems + 1, పరిమాణం(*dst->subsystem_name));
		dst->subsystem_command = xrecallocarray(
		    dst->subsystem_command, dst->అంకె_subsystems,
		    dst->అంకె_subsystems + 1, పరిమాణం(*dst->subsystem_command));
		dst->subsystem_వాదనలు = xrecallocarray(
		    dst->subsystem_వాదనలు, dst->అంకె_subsystems,
		    dst->అంకె_subsystems + 1, పరిమాణం(*dst->subsystem_వాదనలు));
		j = dst->అంకె_subsystems++;
		dst->subsystem_name[j] = xstrdup(src->subsystem_name[i]);
		dst->subsystem_command[j] = xstrdup(src->subsystem_command[i]);
		dst->subsystem_వాదనలు[j] = xstrdup(src->subsystem_వాదనలు[i]);
	}
}

స్థిర పూర్ణాంకం
serialise_s32(నిర్మాణం sshbuf *buf, పూర్ణాంకం v)
{
	uint32_t uv;
	పూర్ణాంకం r;

	uv = v < 0 ? (uint32_t)(-(v + 1)) + 1 : (uint32_t)v;
	ఒకవేళ ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u32(buf, uv)) != 0)
		తిరిగి r;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
serialise_s64(నిర్మాణం sshbuf *buf, int64_t v)
{
	uint64_t uv;
	పూర్ణాంకం r;

	uv = v < 0 ? (uint64_t)(-(v + 1)) + 1 : (uint64_t)v;
	ఒకవేళ ((r = sshbuf_put_u8(buf, v < 0)) != 0 ||
	    (r = sshbuf_put_u64(buf, uv)) != 0)
		తిరిగి r;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
serialise_బహుళకం(నిర్మాణం sshbuf *buf, బహుళకం_t v)
{
	u_int uv;

	ఒకవేళ (v == (బహుళకం_t)-1)
		తిరిగి serialise_s32(buf, -1);
	uv = (u_int)v;
	ఒకవేళ ((బహుళకం_t)uv != v || uv > 0777)
		తిరిగి SSH_ERR_INVALID_FORMAT;
	తిరిగి serialise_s32(buf, (పూర్ణాంకం)uv);
}

స్థిర పూర్ణాంకం
serialise_double(నిర్మాణం sshbuf *buf, ద్విగుణ v)
{
	/*
	 * XXX this is no good for a wire encoding.
	 * It's fine for passing configurations via RPC, but it would
	 * be nicer to have an exact binary encoding here.
	 */
	తిరిగి sshbuf_put(buf, &v, పరిమాణం(v));
}

స్థిర పూర్ణాంకం
serialise_nullable_string(నిర్మాణం sshbuf *buf, స్థిరరాశి అక్షరం *s)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_put_u8(buf, s != ఖాళీ)) != 0)
		తిరిగి r;
	ఒకవేళ (s == ఖాళీ)
		తిరిగి 0;
	తిరిగి sshbuf_put_cstring(buf, s);
}

స్థిర పూర్ణాంకం
serialise_nullable_string_array(నిర్మాణం sshbuf *buf, అక్షరం **a, u_int n)
{
	పూర్ణాంకం r;
	u_int i;

	ఒకవేళ ((r = sshbuf_put_u32(buf, n)) != 0)
		తిరిగి r;
	కొరకు (i = 0; i < n; i++) {
		ఒకవేళ ((r = serialise_nullable_string(buf, a[i])) != 0)
			తిరిగి r;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
serialise_hostkeyfile(స్థిరరాశి ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;
	u_int i;

	ఒకవేళ ((r = sshbuf_put_u32(buf, options->అంకె_host_కీలకం_files)) != 0) {
		error_fr(r, "serialise length");
		తిరిగి r;
	}
	కొరకు (i = 0; i < options->అంకె_host_కీలకం_files; i++) {
		ఒకవేళ ((r = serialise_s32(buf,
		    options->host_కీలకం_file_userprovided[i])) != 0 ||
		    (r = serialise_nullable_string(buf,
		    options->host_కీలకం_files[i])) != 0) {
			error_fr(r, "serialise member");
			తిరిగి r;
		}
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
serialise_ipqos(స్థిరరాశి ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = serialise_s32(buf, options->ip_qos_interactive)) != 0 ||
	    (r = serialise_s32(buf, options->ip_qos_bulk)) != 0) {
		error_fr(r, "serialise");
		తిరిగి r;
	}

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
serialise_listenaddress(స్థిరరాశి ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;
	u_int i;

	/* Note: only serialises queued listen addresses */
	ఒకవేళ ((r = sshbuf_put_u32(buf, options->అంకె_queued_listens)) != 0) {
		error_fr(r, "serialise length");
		తిరిగి r;
	}
	కొరకు (i = 0; i < options->అంకె_queued_listens; i++) {
		స్థిరరాశి నిర్మాణం queued_listenaddr *qla =
		    options->queued_listen_addrs + i;

		ఒకవేళ ((r = sshbuf_put_cstring(buf, qla->addr)) != 0 ||
		    (r = serialise_s32(buf, qla->పోర్టు)) != 0 ||
		    (r = serialise_nullable_string(buf, qla->rdomain)) != 0) {
			error_fr(r, "serialise member");
			తిరిగి r;
		}
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
serialise_logfacility(స్థిరరాశి ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = serialise_s32(buf, (పూర్ణాంకం)options->log_facility)) != 0) {
		error_fr(r, "serialise");
		తిరిగి r;
	}

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
serialise_loglevel(స్థిరరాశి ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = serialise_s32(buf, (పూర్ణాంకం)options->log_level)) != 0) {
		error_fr(r, "serialise");
		తిరిగి r;
	}

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
serialise_పోర్టు(స్థిరరాశి ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;
	u_int i;

	ఒకవేళ ((r = sshbuf_put_u32(buf, options->అంకె_ports)) != 0) {
		error_fr(r, "serialise length");
		తిరిగి r;
	}
	కొరకు (i = 0; i < options->అంకె_ports; i++) {
		ఒకవేళ ((r = serialise_s32(buf, options->ports[i])) != 0) {
			error_fr(r, "serialise port");
			తిరిగి r;
		}
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
serialise_gatewayports(స్థిరరాశి ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = serialise_s32(buf, options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "serialise");
		తిరిగి r;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
serialise_streamlocalbindmask(స్థిరరాశి ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = serialise_బహుళకం(buf,
	    options->fwd_opts.streamlocal_bind_ముసుగు)) != 0) {
		error_fr(r, "serialise");
		తిరిగి r;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
serialise_streamlocalbindunlink(స్థిరరాశి ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_put_u8(buf,
	    (options->fwd_opts.streamlocal_bind_unlink != 0))) != 0) {
		error_fr(r, "serialise");
		తిరిగి r;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
serialise_maxstartups(స్థిరరాశి ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = serialise_s32(buf, options->max_startups_begin)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups_రేటు)) != 0 ||
	    (r = serialise_s32(buf, options->max_startups)) != 0) {
		error_fr(r, "serialise");
		తిరిగి r;
	}

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
serialise_permituserenv(స్థిరరాశి ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = serialise_s32(buf, options->permit_user_env)) != 0 ||
	    (r = serialise_nullable_string(buf,
	    options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "serialise");
		తిరిగి r;
	}

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
serialise_persourcenetblocksize(స్థిరరాశి ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = serialise_s32(buf, options->చొప్పున_ఆధారం_masklen_ipv4)) != 0 ||
	    (r = serialise_s32(buf, options->చొప్పున_ఆధారం_masklen_ipv6)) != 0) {
		error_fr(r, "serialise");
		తిరిగి r;
	}

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
serialise_persourcepenalties(స్థిరరాశి ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	స్థిరరాశి నిర్మాణం చొప్పున_ఆధారం_penalty *psp = &options->చొప్పున_ఆధారం_penalty;
	పూర్ణాంకం r;

	ఒకవేళ ((r = serialise_s32(buf, psp->enabled)) != 0 ||
	    (r = serialise_s32(buf, psp->max_sources4)) != 0 ||
	    (r = serialise_s32(buf, psp->max_sources6)) != 0 ||
	    (r = serialise_s32(buf, psp->అధికప్రవాహం_బహుళకం)) != 0 ||
	    (r = serialise_s32(buf, psp->అధికప్రవాహం_mode6)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_crash)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_grace)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_authfail)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_invaliduser)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_noauth)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_refuseconnection)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_max)) != 0 ||
	    (r = serialise_double(buf, psp->penalty_min)) != 0) {
		error_fr(r, "serialise");
		తిరిగి r;
	}

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
serialise_rekeylimit(స్థిరరాశి ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = serialise_s64(buf, options->rekey_హద్దు)) != 0 ||
	    (r = serialise_s32(buf, options->rekey_interval)) != 0) {
		error_fr(r, "serialise");
		తిరిగి r;
	}

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
serialise_subsystem(స్థిరరాశి ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;
	u_int i;

	ఒకవేళ ((r = sshbuf_put_u32(buf, options->అంకె_subsystems)) != 0) {
		error_fr(r, "serialise length");
		తిరిగి r;
	}
	కొరకు (i = 0; i < options->అంకె_subsystems; i++) {
		ఒకవేళ ((r = sshbuf_put_cstring(buf,
		    options->subsystem_name[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_command[i])) != 0 ||
		    (r = sshbuf_put_cstring(buf,
		    options->subsystem_వాదనలు[i])) != 0) {
			error_fr(r, "serialise member");
			తిరిగి r;
		}
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
serialise_pubkey_auth_options(స్థిరరాశి ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = serialise_s32(buf, options->pubkey_auth_options)) != 0 ||
	    (r = serialise_s32(buf, options->max_pubkey_ok)) != 0) {
		error_fr(r, "serialise");
		తిరిగి r;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
serialise_timingsecret(స్థిరరాశి ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_put_u64(buf, options->timing_secret)) != 0) {
		error_fr(r, "serialise");
		తిరిగి r;
	}
	తిరిగి 0;
}


పూర్ణాంకం
serialise_server_options(స్థిరరాశి ServerOptions *options, నిర్మాణం sshbuf **bufp)
{
	నిర్మాణం sshbuf *buf = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	*bufp = ఖాళీ;

	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_put_u32(buf, SSHD_CONFIG_BLOB_సంస్కరణ)) != 0) {
		error_fr(r, "serialise version");
		వెళ్ళు బహిర్గతం;
	}

#నిర్వచించు SSHCONF_INT(var, conf, flags, ms, def, cp) \
	ఒకవేళ ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		వెళ్ళు బహిర్గతం; \
	}
#నిర్వచించు SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	ఒకవేళ ((r = serialise_s32(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		వెళ్ళు బహిర్గతం; \
	}
#నిర్వచించు SSHCONF_STRING(var, conf, flags, cp) \
	ఒకవేళ ((r = serialise_nullable_string(buf, options->var)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		వెళ్ళు బహిర్గతం; \
	}
#నిర్వచించు SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	ఒకవేళ ((r = serialise_nullable_string_array(buf, options->var, \
	    options->nvar)) != 0) { \
		error_fr(r, "serialise %s", #var); \
		వెళ్ళు బహిర్గతం; \
	}
#నిర్వచించు SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	ఒకవేళ ((r = serialise_##funcsuffix(options, buf)) != 0) \
		వెళ్ళు బహిర్గతం;
#నిర్వచించు SSHCONF_NONCONF(funcsuffix) \
	ఒకవేళ ((r = serialise_##funcsuffix(options, buf)) != 0) \
		వెళ్ళు బహిర్గతం;
#నిర్వచించు SSHCONF_DEPRECATE(conf, flags, opcode)		/*ఖాళీలు*/
#నిర్వచించు SSHCONF_UNSUPPORTED_INT(var, conf, flags)	/*ఖాళీలు*/
#నిర్వచించు SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	/*ఖాళీలు*/
#నిర్వచించు SSHCONF_ALIAS(old, conf, flags)			/*ఖాళీలు*/

	SSHD_CONFIG_ENTRIES

#నిర్వచనం_రద్దు SSHCONF_INT
#నిర్వచనం_రద్దు SSHCONF_INTFLAG
#నిర్వచనం_రద్దు SSHCONF_STRING
#నిర్వచనం_రద్దు SSHCONF_STRARRAY
#నిర్వచనం_రద్దు SSHCONF_CUSTOM
#నిర్వచనం_రద్దు SSHCONF_NONCONF
#నిర్వచనం_రద్దు SSHCONF_DEPRECATE
#నిర్వచనం_రద్దు SSHCONF_UNSUPPORTED_INT
#నిర్వచనం_రద్దు SSHCONF_UNSUPPORTED_STRING
#నిర్వచనం_రద్దు SSHCONF_ALIAS

	/* success */
	r = 0;
	*bufp = buf;
	buf = ఖాళీ; /* transferred */
 బహిర్గతం:
	sshbuf_free(buf);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
deserialise_s32(నిర్మాణం sshbuf *buf, పూర్ణాంకం *v)
{
	uint32_t tmp;
	పూర్ణాంకం r;
	u_char was_signed;

	ఒకవేళ ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u32(buf, &tmp)) != 0)
		తిరిగి r;
	ఒకవేళ (was_signed > 1)
		తిరిగి SSH_ERR_INVALID_FORMAT;
	ఒకవేళ (was_signed) {
		ఒకవేళ (tmp > (uint32_t)గరిష్ఠ_పూర్ణాంకం + 1)
			తిరిగి SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint32_t)గరిష్ఠ_పూర్ణాంకం + 1 ? INT_MIN : -(పూర్ణాంకం)tmp;
	} లేకపోతే {
		ఒకవేళ (tmp > గరిష్ఠ_పూర్ణాంకం)
			తిరిగి SSH_ERR_INVALID_FORMAT;
		*v = (పూర్ణాంకం)tmp;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_s64(నిర్మాణం sshbuf *buf, int64_t *v)
{
	uint64_t tmp;
	పూర్ణాంకం r;
	u_char was_signed;

	ఒకవేళ ((r = sshbuf_get_u8(buf, &was_signed)) != 0 ||
	    (r = sshbuf_get_u64(buf, &tmp)) != 0)
		తిరిగి r;
	ఒకవేళ (was_signed > 1)
		తిరిగి SSH_ERR_INVALID_FORMAT;
	ఒకవేళ (was_signed) {
		ఒకవేళ (tmp > (uint64_t)INT64_MAX + 1)
			తిరిగి SSH_ERR_INVALID_FORMAT;
		*v = tmp == (uint64_t)INT64_MAX + 1 ?
		    INT64_MIN : -(int64_t)tmp;
	} లేకపోతే {
		ఒకవేళ (tmp > INT64_MAX)
			తిరిగి SSH_ERR_INVALID_FORMAT;
		*v = (int64_t)tmp;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_బహుళకం(నిర్మాణం sshbuf *buf, బహుళకం_t *v)
{
	పూర్ణాంకం r, tmp;

	ఒకవేళ ((r = deserialise_s32(buf, &tmp)) != 0)
		తిరిగి r;
	ఒకవేళ (tmp == -1) {
		*v = (బహుళకం_t)-1;
		తిరిగి 0;
	}
	ఒకవేళ (tmp < 0 || tmp > 0777)
		తిరిగి SSH_ERR_INVALID_FORMAT;
	*v = (బహుళకం_t)tmp;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_double(నిర్మాణం sshbuf *buf, ద్విగుణ *v)
{
	తిరిగి sshbuf_get(buf, v, పరిమాణం(*v));
}

స్థిర పూర్ణాంకం
deserialise_nullable_string(నిర్మాణం sshbuf *buf, అక్షరం **sp)
{
	పూర్ణాంకం r;
	u_char present;

	ఒకవేళ ((r = sshbuf_get_u8(buf, &present)) != 0)
		తిరిగి r;
	ఒకవేళ (present == 0) {
		*sp = ఖాళీ;
		తిరిగి 0;
	}
	ఒకవేళ (present != 1)
		తిరిగి SSH_ERR_INVALID_FORMAT;
	తిరిగి sshbuf_get_cstring(buf, sp, ఖాళీ);
}

స్థిర శూన్య
free_string_array(అక్షరం **a, u_int n)
{
	u_int i;

	ఒకవేళ (a == ఖాళీ)
		తిరిగి;
	కొరకు (i = 0; i < n; i++)
		విడుదల(a[i]);
	విడుదల(a);
}

స్థిర పూర్ణాంకం
deserialise_లెక్క(నిర్మాణం sshbuf *buf, u_int *np, స్థిరరాశి అక్షరం *what)
{
	పూర్ణాంకం r;
	uint32_t n;

	ఒకవేళ ((r = sshbuf_get_u32(buf, &n)) != 0) {
		error_fr(r, "deserialise %s length", what);
		తిరిగి r;
	}
	ఒకవేళ (n > UINT_MAX) {
		error_f("bad number of %s", what);
		తిరిగి SSH_ERR_INVALID_FORMAT;
	}
	ఒకవేళ (n > sshbuf_len(buf)) {
		error_f("bad number of %s", what);
		తిరిగి SSH_ERR_INVALID_FORMAT;
	}
	*np = n;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_nullable_string_array(నిర్మాణం sshbuf *buf, అక్షరం ***arrayp,
    u_int *np)
{
	అక్షరం **a = ఖాళీ;
	పూర్ణాంకం r;
	u_int i, n;

	*arrayp = ఖాళీ;
	*np = 0;
	ఒకవేళ ((r = deserialise_లెక్క(buf, &n, "strings")) != 0)
		తిరిగి r;
	ఒకవేళ (n > 0)
		a = xcalloc(n, పరిమాణం(*a));
	కొరకు (i = 0; i < n; i++) {
		ఒకవేళ ((r = deserialise_nullable_string(buf, a + i)) != 0) {
			free_string_array(a, i + 1);
			తిరిగి r;
		}
	}
	*arrayp = a;
	*np = n;
	తిరిగి 0;
}

స్థిర శూన్య
free_queued_listen_addrs(నిర్మాణం queued_listenaddr *qla, u_int n)
{
	u_int i;

	ఒకవేళ (qla == ఖాళీ)
		తిరిగి;
	కొరకు (i = 0; i < n; i++) {
		విడుదల(qla[i].addr);
		విడుదల(qla[i].rdomain);
	}
	విడుదల(qla);
}

స్థిర పూర్ణాంకం
deserialise_hostkeyfile(ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r, *userprovided = ఖాళీ;
	u_int i, n;
	అక్షరం **files = ఖాళీ;

	ఒకవేళ ((r = deserialise_లెక్క(buf, &n, "host key files")) != 0)
		తిరిగి r;
	ఒకవేళ (n > 0) {
		userprovided = xcalloc(n, పరిమాణం(*userprovided));
		files = xcalloc(n, పరిమాణం(*files));
	}
	కొరకు (i = 0; i < n; i++) {
		ఒకవేళ ((r = deserialise_s32(buf, userprovided + i)) != 0 ||
		    (r = deserialise_nullable_string(buf, files + i)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(files, i + 1);
			విడుదల(userprovided);
			తిరిగి r;
		}
	}
	options->అంకె_host_కీలకం_files = n;
	options->host_కీలకం_file_userprovided = userprovided;
	options->host_కీలకం_files = files;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_ipqos(ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = deserialise_s32(buf, &options->ip_qos_interactive)) != 0 ||
	    (r = deserialise_s32(buf, &options->ip_qos_bulk)) != 0) {
		error_fr(r, "deserialise");
		తిరిగి r;
	}

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_listenaddress(ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;
	u_int i, n;
	నిర్మాణం queued_listenaddr *qla = ఖాళీ;

	ఒకవేళ ((r = deserialise_లెక్క(buf, &n, "listen addresses")) != 0)
		తిరిగి r;
	ఒకవేళ (n > 0)
		qla = xcalloc(n, పరిమాణం(*qla));
	కొరకు (i = 0; i < n; i++) {
		ఒకవేళ ((r = sshbuf_get_cstring(buf, &qla[i].addr, ఖాళీ)) != 0 ||
		    (r = deserialise_s32(buf, &qla[i].పోర్టు)) != 0 ||
		    (r = deserialise_nullable_string(buf,
		    &qla[i].rdomain)) != 0) {
			error_fr(r, "deserialise member");
			free_queued_listen_addrs(qla, i + 1);
			తిరిగి r;
		}
	}
	options->అంకె_queued_listens = n;
	options->queued_listen_addrs = qla;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_logfacility(ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r, tmp;

	ఒకవేళ ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		తిరిగి r;
	}
	ఒకవేళ (tmp != SYSLOG_FACILITY_NOT_సమితి &&
	    log_facility_name((SyslogFacility)tmp) == ఖాళీ) {
		error_f("bad syslog facility");
		తిరిగి SSH_ERR_INVALID_FORMAT;
	}
	options->log_facility = (SyslogFacility)tmp;

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_loglevel(ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r, tmp;

	ఒకవేళ ((r = deserialise_s32(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		తిరిగి r;
	}
	ఒకవేళ (tmp != SYSLOG_LEVEL_NOT_సమితి &&
	    log_level_name((LogLevel)tmp) == ఖాళీ) {
		error_f("bad log level");
		తిరిగి SSH_ERR_INVALID_FORMAT;
	}
	options->log_level = (LogLevel)tmp;

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_పోర్టు(ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;
	u_int i, n;

	ఒకవేళ ((r = deserialise_లెక్క(buf, &n, "ports")) != 0)
		తిరిగి r;
	ఒకవేళ (n > MAX_PORTS) {
		error_f("bad number of ports");
		తిరిగి SSH_ERR_INVALID_FORMAT;
	}
	options->అంకె_ports = n;
	memset(options->ports, 0, పరిమాణం(options->ports));
	కొరకు (i = 0; i < options->అంకె_ports; i++) {
		ఒకవేళ ((r = deserialise_s32(buf, options->ports + i)) != 0) {
			error_fr(r, "deserialise port");
			తిరిగి r;
		}
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_gatewayports(ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = deserialise_s32(buf, &options->fwd_opts.gateway_ports)) != 0) {
		error_fr(r, "deserialise");
		తిరిగి r;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_streamlocalbindmask(ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = deserialise_బహుళకం(buf,
	    &options->fwd_opts.streamlocal_bind_ముసుగు)) != 0) {
		error_fr(r, "deserialise");
		తిరిగి r;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_streamlocalbindunlink(ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;
	u_char tmp;

	ఒకవేళ ((r = sshbuf_get_u8(buf, &tmp)) != 0) {
		error_fr(r, "deserialise");
		తిరిగి r;
	}
	ఒకవేళ (tmp > 1) {
		error_f("bad boolean");
		తిరిగి SSH_ERR_INVALID_FORMAT;
	}
	options->fwd_opts.streamlocal_bind_unlink = tmp;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_maxstartups(ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = deserialise_s32(buf, &options->max_startups_begin)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups_రేటు)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_startups)) != 0) {
		error_fr(r, "deserialise");
		తిరిగి r;
	}

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_permituserenv(ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = deserialise_s32(buf, &options->permit_user_env)) != 0 ||
	    (r = deserialise_nullable_string(buf,
	    &options->permit_user_env_allowlist)) != 0) {
		error_fr(r, "deserialise");
		తిరిగి r;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_persourcenetblocksize(ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = deserialise_s32(buf,
	    &options->చొప్పున_ఆధారం_masklen_ipv4)) != 0 ||
	    (r = deserialise_s32(buf,
	    &options->చొప్పున_ఆధారం_masklen_ipv6)) != 0) {
		error_fr(r, "deserialise");
		తిరిగి r;
	}

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_persourcepenalties(ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	నిర్మాణం చొప్పున_ఆధారం_penalty *psp = &options->చొప్పున_ఆధారం_penalty;
	పూర్ణాంకం r;

	ఒకవేళ ((r = deserialise_s32(buf, &psp->enabled)) != 0 ||
	    (r = deserialise_s32(buf, &psp->max_sources4)) != 0 ||
	    (r = deserialise_s32(buf, &psp->max_sources6)) != 0 ||
	    (r = deserialise_s32(buf, &psp->అధికప్రవాహం_బహుళకం)) != 0 ||
	    (r = deserialise_s32(buf, &psp->అధికప్రవాహం_mode6)) != 0 ||
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
		తిరిగి r;
	}

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_rekeylimit(ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = deserialise_s64(buf, &options->rekey_హద్దు)) != 0 ||
	    (r = deserialise_s32(buf, &options->rekey_interval)) != 0) {
		error_fr(r, "deserialise");
		తిరిగి r;
	}

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_subsystem(ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;
	u_int i, n;
	అక్షరం **పేర్లు = ఖాళీ, **commands = ఖాళీ, **వాదనలు = ఖాళీ;

	ఒకవేళ ((r = deserialise_లెక్క(buf, &n, "subsystems")) != 0)
		తిరిగి r;
	ఒకవేళ (n > 0) {
		పేర్లు = xcalloc(n, పరిమాణం(*పేర్లు));
		commands = xcalloc(n, పరిమాణం(*పేర్లు));
		వాదనలు = xcalloc(n, పరిమాణం(*వాదనలు));
	}
	కొరకు (i = 0; i < n; i++) {
		ఒకవేళ ((r = sshbuf_get_cstring(buf, పేర్లు + i, ఖాళీ)) != 0 ||
		    (r = sshbuf_get_cstring(buf, commands + i, ఖాళీ)) != 0 ||
		    (r = sshbuf_get_cstring(buf, వాదనలు + i, ఖాళీ)) != 0) {
			error_fr(r, "deserialise member");
			free_string_array(పేర్లు, i + 1);
			free_string_array(commands, i + 1);
			free_string_array(వాదనలు, i + 1);
			తిరిగి r;
		}
	}
	options->అంకె_subsystems = n;
	options->subsystem_name = పేర్లు;
	options->subsystem_command = commands;
	options->subsystem_వాదనలు = వాదనలు;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_pubkey_auth_options(ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = deserialise_s32(buf, &options->pubkey_auth_options)) != 0 ||
	    (r = deserialise_s32(buf, &options->max_pubkey_ok)) != 0) {
		error_fr(r, "deserialise");
		తిరిగి r;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
deserialise_timingsecret(ServerOptions *options, నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_get_u64(buf, &options->timing_secret)) != 0) {
		error_fr(r, "deserialise");
		తిరిగి r;
	}
	తిరిగి 0;
}

పూర్ణాంకం
deserialise_server_options(నిర్మాణం sshbuf *buf, ServerOptions *options)
{
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	uint32_t సంస్కరణ;
	ServerOptions new_options;

	initialize_server_options(&new_options);
	ఒకవేళ ((r = sshbuf_get_u32(buf, &సంస్కరణ)) != 0) {
		error_fr(r, "deserialise version");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (సంస్కరణ != SSHD_CONFIG_BLOB_సంస్కరణ) {
		error_f("unsupported config blob version %u", సంస్కరణ);
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
#నిర్వచించు SSHCONF_INT(var, conf, flags, ms, def, cp) \
	ఒకవేళ ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		వెళ్ళు బహిర్గతం; \
	}
#నిర్వచించు SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	ఒకవేళ ((r = deserialise_s32(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		వెళ్ళు బహిర్గతం; \
	}
#నిర్వచించు SSHCONF_STRING(var, conf, flags, cp) \
	ఒకవేళ ((r = deserialise_nullable_string(buf, &new_options.var)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		వెళ్ళు బహిర్గతం; \
	}
#నిర్వచించు SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	ఒకవేళ ((r = deserialise_nullable_string_array(buf, &new_options.var, \
	    &new_options.nvar)) != 0) { \
		error_fr(r, "deserialise %s", #var); \
		వెళ్ళు బహిర్గతం; \
	}
#నిర్వచించు SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	ఒకవేళ ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		వెళ్ళు బహిర్గతం;
#నిర్వచించు SSHCONF_NONCONF(funcsuffix) \
	ఒకవేళ ((r = deserialise_##funcsuffix(&new_options, buf)) != 0) \
		వెళ్ళు బహిర్గతం;
#నిర్వచించు SSHCONF_DEPRECATE(conf, flags, opcode)		/*ఖాళీలు*/
#నిర్వచించు SSHCONF_UNSUPPORTED_INT(var, conf, flags)	new_options.var = 0;
#నిర్వచించు SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	చేయి { \
		విడుదల(new_options.var); \
		new_options.var = ఖాళీ; \
	} అయితే (0);
#నిర్వచించు SSHCONF_ALIAS(old, conf, flags)			/*ఖాళీలు*/

	SSHD_CONFIG_ENTRIES

	ఒకవేళ (sshbuf_len(buf) != 0) {
		error_f("trailing data in config blob");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}

#నిర్వచనం_రద్దు SSHCONF_INT
#నిర్వచనం_రద్దు SSHCONF_INTFLAG
#నిర్వచనం_రద్దు SSHCONF_STRING
#నిర్వచనం_రద్దు SSHCONF_STRARRAY
#నిర్వచనం_రద్దు SSHCONF_CUSTOM
#నిర్వచనం_రద్దు SSHCONF_NONCONF
#నిర్వచనం_రద్దు SSHCONF_DEPRECATE
#నిర్వచనం_రద్దు SSHCONF_UNSUPPORTED_INT
#నిర్వచనం_రద్దు SSHCONF_UNSUPPORTED_STRING
#నిర్వచనం_రద్దు SSHCONF_ALIAS

	/* success */
	r = 0;
	free_server_options(options);
	*options = new_options;
	memset(&new_options, 0, పరిమాణం(new_options));
 బహిర్గతం:
	free_server_options(&new_options);
	తిరిగి r;
}

స్థిర శూన్య
free_hostkeyfile(ServerOptions *options)
{
	u_int i;

	కొరకు (i = 0; i < options->అంకె_host_కీలకం_files; i++)
		విడుదల(options->host_కీలకం_files[i]);
	విడుదల(options->host_కీలకం_files);
	విడుదల(options->host_కీలకం_file_userprovided);
}

స్థిర శూన్య
free_listenaddress(ServerOptions *options)
{
	u_int i;

	free_queued_listen_addrs(options->queued_listen_addrs,
	    options->అంకె_queued_listens);

	కొరకు (i = 0; i < options->అంకె_listen_addrs; i++) {
		విడుదల(options->listen_addrs[i].rdomain);
		ఒకవేళ (options->listen_addrs[i].addrs != ఖాళీ)
			freeaddrinfo(options->listen_addrs[i].addrs);
	}
	విడుదల(options->listen_addrs);
}

స్థిర శూన్య
free_permituserenv(ServerOptions *options)
{
	విడుదల(options->permit_user_env_allowlist);
}

స్థిర శూన్య
free_subsystem(ServerOptions *options)
{
	u_int i;

	కొరకు (i = 0; i < options->అంకె_subsystems; i++) {
		విడుదల(options->subsystem_name[i]);
		విడుదల(options->subsystem_command[i]);
		విడుదల(options->subsystem_వాదనలు[i]);
	}
	విడుదల(options->subsystem_name);
	విడుదల(options->subsystem_command);
	విడుదల(options->subsystem_వాదనలు);
}

శూన్య
free_server_options(ServerOptions *options)
{
#నిర్వచించు SSHCONF_INT(var, conf, flags, ms, def, cp)	/*ఖాళీలు*/
#నిర్వచించు SSHCONF_INTFLAG(var, conf, flags, def, cp)	/*ఖాళీలు*/
#నిర్వచించు SSHCONF_STRING(var, conf, flags, cp)		విడుదల(options->var);
#నిర్వచించు SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	free_string_array(options->var, options->nvar);
#నిర్వచించు SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	free_##funcsuffix(options);
#నిర్వచించు SSHCONF_NONCONF(funcsuffix) \
	free_##funcsuffix(options);
#నిర్వచించు SSHCONF_DEPRECATE(conf, flags, opcode)		/*ఖాళీలు*/
#నిర్వచించు SSHCONF_UNSUPPORTED_INT(var, conf, flags)	options->var = 0;
#నిర్వచించు SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	చేయి { \
		విడుదల(options->var); \
		options->var = ఖాళీ; \
	} అయితే (0);
#నిర్వచించు SSHCONF_ALIAS(old, conf, flags)			/*ఖాళీలు*/

#నిర్వచించు free_ipqos(options)
#నిర్వచించు free_logfacility(options)
#నిర్వచించు free_loglevel(options)
#నిర్వచించు free_పోర్టు(options)
#నిర్వచించు free_gatewayports(options)
#నిర్వచించు free_streamlocalbindmask(options)
#నిర్వచించు free_streamlocalbindunlink(options)
#నిర్వచించు free_maxstartups(options)
#నిర్వచించు free_persourcenetblocksize(options)
#నిర్వచించు free_persourcepenalties(options)
#నిర్వచించు free_rekeylimit(options)
#నిర్వచించు free_pubkey_auth_options(options)
#నిర్వచించు free_timingsecret(options)

	SSHD_CONFIG_ENTRIES

#నిర్వచనం_రద్దు free_ipqos
#నిర్వచనం_రద్దు free_logfacility
#నిర్వచనం_రద్దు free_loglevel
#నిర్వచనం_రద్దు free_పోర్టు
#నిర్వచనం_రద్దు free_gatewayports
#నిర్వచనం_రద్దు free_streamlocalbindmask
#నిర్వచనం_రద్దు free_streamlocalbindunlink
#నిర్వచనం_రద్దు free_maxstartups
#నిర్వచనం_రద్దు free_persourcenetblocksize
#నిర్వచనం_రద్దు free_persourcepenalties
#నిర్వచనం_రద్దు free_rekeylimit
#నిర్వచనం_రద్దు free_timingsecret

#నిర్వచనం_రద్దు SSHCONF_INT
#నిర్వచనం_రద్దు SSHCONF_INTFLAG
#నిర్వచనం_రద్దు SSHCONF_STRING
#నిర్వచనం_రద్దు SSHCONF_STRARRAY
#నిర్వచనం_రద్దు SSHCONF_CUSTOM
#నిర్వచనం_రద్దు SSHCONF_NONCONF
#నిర్వచనం_రద్దు SSHCONF_DEPRECATE
#నిర్వచనం_రద్దు SSHCONF_UNSUPPORTED_INT
#నిర్వచనం_రద్దు SSHCONF_UNSUPPORTED_STRING
#నిర్వచనం_రద్దు SSHCONF_ALIAS

	initialize_server_options(options);
}

స్థిర శూన్య
copy_server_option_int(పూర్ణాంకం *dst, పూర్ణాంకం src)
{
	ఒకవేళ (src != -1)
		*dst = src;
}

స్థిర శూన్య
copy_server_option_int64(int64_t *dst, int64_t src)
{
	ఒకవేళ (src != -1)
		*dst = src;
}

స్థిర శూన్య
copy_server_option_string(అక్షరం **dst, స్థిరరాశి అక్షరం *src)
{
	ఒకవేళ (src != ఖాళీ && *dst != src) {
		విడుదల(*dst);
		*dst = xstrdup(src);
	}
}

స్థిర శూన్య
copy_server_option_strarray_విలువలు(అక్షరం ***dst, u_int ndst,
    అక్షరం * స్థిరరాశి *src, u_int nsrc)
{
	u_int i;

	ఒకవేళ (nsrc == 0)
		తిరిగి;
	కొరకు (i = 0; i < ndst; i++)
		విడుదల((*dst)[i]);
	విడుదల(*dst);
	*dst = xcalloc(nsrc, పరిమాణం(**dst));
	కొరకు (i = 0; i < nsrc; i++)
		(*dst)[i] = src[i] == ఖాళీ ? ఖాళీ : xstrdup(src[i]);
}

స్థిర శూన్య
copy_server_option_strarray(అక్షరం ***dst, u_int *ndst,
    అక్షరం * స్థిరరాశి *src, u_int nsrc)
{
	ఒకవేళ (nsrc == 0)
		తిరిగి;
	copy_server_option_strarray_విలువలు(dst, *ndst, src, nsrc);
	*ndst = nsrc;
}

స్థిర శూన్య
copy_ipqos(ServerOptions *dst, స్థిరరాశి ServerOptions *src)
{
	copy_server_option_int(&dst->ip_qos_interactive,
	    src->ip_qos_interactive);
	copy_server_option_int(&dst->ip_qos_bulk, src->ip_qos_bulk);
}

స్థిర శూన్య
copy_gatewayports(ServerOptions *dst, స్థిరరాశి ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.gateway_ports,
	    src->fwd_opts.gateway_ports);
}

స్థిర శూన్య
copy_streamlocalbindunlink(ServerOptions *dst, స్థిరరాశి ServerOptions *src)
{
	copy_server_option_int(&dst->fwd_opts.streamlocal_bind_unlink,
	    src->fwd_opts.streamlocal_bind_unlink);
}

స్థిర శూన్య
copy_loglevel(ServerOptions *dst, స్థిరరాశి ServerOptions *src)
{
	ఒకవేళ (src->log_level != -1)
		dst->log_level = src->log_level;
}

స్థిర శూన్య
copy_rekeylimit(ServerOptions *dst, స్థిరరాశి ServerOptions *src)
{
	copy_server_option_int64(&dst->rekey_హద్దు, src->rekey_హద్దు);
	copy_server_option_int(&dst->rekey_interval, src->rekey_interval);
}

స్థిర శూన్య
copy_subsystem(ServerOptions *dst, స్థిరరాశి ServerOptions *src)
{
	u_int old_అంకె_subsystems = dst->అంకె_subsystems;

	ఒకవేళ (src->అంకె_subsystems == 0)
		తిరిగి;
	copy_server_option_strarray_విలువలు(&dst->subsystem_name,
	    old_అంకె_subsystems, src->subsystem_name, src->అంకె_subsystems);
	copy_server_option_strarray_విలువలు(&dst->subsystem_command,
	    old_అంకె_subsystems, src->subsystem_command, src->అంకె_subsystems);
	copy_server_option_strarray_విలువలు(&dst->subsystem_వాదనలు,
	    old_అంకె_subsystems, src->subsystem_వాదనలు, src->అంకె_subsystems);
	dst->అంకె_subsystems = src->అంకె_subsystems;
}

స్థిర శూన్య
copy_pubkey_auth_options(ServerOptions *dst, స్థిరరాశి ServerOptions *src)
{
	ఒకవేళ (src->pubkey_auth_options != -1) {
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
శూన్య
copy_సమితి_server_options(ServerOptions *dst, ServerOptions *src, పూర్ణాంకం preauth)
{
	ఒకవేళ (dst == src)
		తిరిగి;

#నిర్వచించు SSHCONF_INT(var, conf, flags, ms, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#నిర్వచించు SSHCONF_INTFLAG(var, conf, flags, def, cp) \
	cp(copy_server_option_int(&dst->var, src->var);)
#నిర్వచించు SSHCONF_STRING(var, conf, flags, cp) \
	cp(copy_server_option_string(&dst->var, src->var);)
#నిర్వచించు SSHCONF_STRARRAY(var, nvar, conf, flags, cp) \
	cp(copy_server_option_strarray(&dst->var, &dst->nvar, \
	    src->var, src->nvar);)
#నిర్వచించు SSHCONF_CUSTOM(conf, funcsuffix, flags, cp) \
	cp(copy_##funcsuffix(dst, src);)
#నిర్వచించు SSHCONF_NONCONF(funcsuffix)			/*ఖాళీలు*/
#నిర్వచించు SSHCONF_DEPRECATE(conf, flags, opcode)		/*ఖాళీలు*/
#నిర్వచించు SSHCONF_UNSUPPORTED_INT(var, conf, flags)	dst->var = 0;
#నిర్వచించు SSHCONF_UNSUPPORTED_STRING(var, conf, flags) \
	చేయి { \
		విడుదల(dst->var); \
		dst->var = ఖాళీ; \
	} అయితే (0);
#నిర్వచించు SSHCONF_ALIAS(old, conf, flags)			/*ఖాళీలు*/

	SSHD_CONFIG_ENTRIES

#నిర్వచనం_రద్దు SSHCONF_INT
#నిర్వచనం_రద్దు SSHCONF_INTFLAG
#నిర్వచనం_రద్దు SSHCONF_STRING
#నిర్వచనం_రద్దు SSHCONF_STRARRAY
#నిర్వచనం_రద్దు SSHCONF_CUSTOM
#నిర్వచనం_రద్దు SSHCONF_NONCONF
#నిర్వచనం_రద్దు SSHCONF_DEPRECATE
#నిర్వచనం_రద్దు SSHCONF_UNSUPPORTED_INT
#నిర్వచనం_రద్దు SSHCONF_UNSUPPORTED_STRING
#నిర్వచనం_రద్దు SSHCONF_ALIAS

	/*
	 * The bind_mask is a mode_t that may be unsigned, so we can't use
	 * copy_server_option_int - it does a signed comparison that causes
	 * compiler warnings.
	 */
	ఒకవేళ (src->fwd_opts.streamlocal_bind_ముసుగు != (బహుళకం_t)-1) {
		dst->fwd_opts.streamlocal_bind_ముసుగు =
		    src->fwd_opts.streamlocal_bind_ముసుగు;
	}

	/* Arguments that accept '+...' need to be expanded */
	assemble_algorithms(dst);

	/*
	 * These options may be "none" to clear a global setting.  They are
	 * consulted before authentication, so they must be cleared here
	 * rather than in the post-auth section below.
	 */
#నిర్వచించు CLEAR_ON_NONE(v) \
	చేయి { \
		ఒకవేళ (option_clear_or_none(v)) { \
			విడుదల(v); \
			v = ఖాళీ; \
		} \
	} అయితే(0)
	CLEAR_ON_NONE(dst->authorized_principals_file);
	CLEAR_ON_NONE(dst->trusted_user_ca_కీలకాలు);
	CLEAR_ON_NONE(dst->banner);

	/*
	 * The only things that should be below this point are string options
	 * which are only used after authentication.
	 */
	ఒకవేళ (preauth)
		తిరిగి;

	/* These options may be "none" to clear a global setting */
	copy_server_option_string(&dst->adm_forced_command,
	    src->adm_forced_command);
	copy_server_option_string(&dst->chroot_directory,
	    src->chroot_directory);
	CLEAR_ON_NONE(dst->chroot_directory);
	CLEAR_ON_NONE(dst->adm_forced_command);
#నిర్వచనం_రద్దు CLEAR_ON_NONE

	/* Subsystems require merging. */
	servconf_విలీనం_subsystems(dst, src);
}

#నిర్వచించు SERVCONF_MAX_లోతు	16
స్థిర శూన్య
parse_server_config_లోతు(ServerOptions *options, స్థిరరాశి అక్షరం *filename,
    నిర్మాణం sshbuf *conf, నిర్మాణం include_list *includes,
    నిర్మాణం connection_info *connectinfo, పూర్ణాంకం flags, పూర్ణాంకం *activep, పూర్ణాంకం లోతు)
{
	పూర్ణాంకం linenum, bad_options = 0;
	అక్షరం *cp, *obuf, *cbuf;

	ఒకవేళ (లోతు < 0 || లోతు > SERVCONF_MAX_లోతు)
		fatal("Too many recursive configuration includes");

	debug2_f("config %s len %zu%s", filename, sshbuf_len(conf),
	    (flags & SSHCFG_NEVERMATCH ? " [checking syntax only]" : ""));

	ఒకవేళ ((obuf = cbuf = sshbuf_dup_string(conf)) == ఖాళీ)
		fatal_f("sshbuf_dup_string failed");
	linenum = 1;
	అయితే ((cp = strsep(&cbuf, "\n")) != ఖాళీ) {
		ఒకవేళ (process_server_config_పంక్తి_లోతు(options, cp,
		    filename, linenum++, activep, connectinfo, &flags,
		    లోతు, includes) != 0)
			bad_options++;
	}
	విడుదల(obuf);
	ఒకవేళ (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
}

శూన్య
parse_server_config(ServerOptions *options, స్థిరరాశి అక్షరం *filename,
    నిర్మాణం sshbuf *conf, నిర్మాణం include_list *includes,
    నిర్మాణం connection_info *connectinfo, పూర్ణాంకం reexec)
{
	పూర్ణాంకం చురుకైన = connectinfo ? 0 : 1;
	parse_server_config_లోతు(options, filename, conf, includes,
	    connectinfo, (connectinfo ? SSHCFG_సరిపోలిక_ONLY : 0), &చురుకైన, 0);
	ఒకవేళ (!reexec)
		process_queued_listen_addrs(options);
}

స్థిర స్థిరరాశి అక్షరం *
fmt_multistate_int(పూర్ణాంకం val, స్థిరరాశి నిర్మాణం multistate *m)
{
	u_int i;

	కొరకు (i = 0; m[i].కీలకం != ఖాళీ; i++) {
		ఒకవేళ (m[i].విలువ == val)
			తిరిగి m[i].కీలకం;
	}
	తిరిగి "UNKNOWN";
}

స్థిర స్థిరరాశి అక్షరం *
fmt_intarg(ServerOpCodes సంకేతం_2, పూర్ణాంకం val)
{
	ఒకవేళ (val == -1)
		తిరిగి "unset";
	ఎంపిక (సంకేతం_2) {
	స్థితి s_చిరునామా_Family:
		తిరిగి fmt_multistate_int(val, multistate_addressfamily);
	స్థితి s_Permit_మూలం_Login:
		తిరిగి fmt_multistate_int(val, multistate_permitrootlogin);
	స్థితి sGatewayPorts:
		తిరిగి fmt_multistate_int(val, multistate_gatewayports);
	స్థితి sCompression:
		తిరిగి fmt_multistate_int(val, multistate_compression);
	స్థితి sAllowTcpForwarding:
		తిరిగి fmt_multistate_int(val, multistate_tcpfwd);
	స్థితి s_Allow_ప్రవాహం_Local_Forwarding:
		తిరిగి fmt_multistate_int(val, multistate_tcpfwd);
	స్థితి sIgnoreRhosts:
		తిరిగి fmt_multistate_int(val, multistate_ignore_rhosts);
	స్థితి sTCPKeepAlive:
		తిరిగి fmt_multistate_int(val, multistate_keepalives);
	స్థితి sWarnWeakCrypto:
		తిరిగి fmt_multistate_int(val, multistate_warnweakcrypto);
	స్థితి sFingerprintHash:
		తిరిగి ssh_digest_alg_name(val);
	అప్రమేయ:
		ఎంపిక (val) {
		స్థితి 0:
			తిరిగి "no";
		స్థితి 1:
			తిరిగి "yes";
		అప్రమేయ:
			తిరిగి "UNKNOWN";
		}
	}
}

స్థిర శూన్య
dump_cfg_int(ServerOpCodes సంకేతం_2, పూర్ణాంకం val)
{
	ఒకవేళ (సంకేతం_2 == s_వాడని_Connection_Timeout && val == 0) {
		రాయి("%s none\n", lookup_opcode_name(సంకేతం_2));
		తిరిగి;
	}
	రాయి("%s %d\n", lookup_opcode_name(సంకేతం_2), val);
}

స్థిర శూన్య
dump_cfg_oct(ServerOpCodes సంకేతం_2, పూర్ణాంకం val)
{
	రాయి("%s 0%o\n", lookup_opcode_name(సంకేతం_2), val);
}

స్థిర శూన్య
dump_cfg_fmtint(ServerOpCodes సంకేతం_2, పూర్ణాంకం val)
{
	రాయి("%s %s\n", lookup_opcode_name(సంకేతం_2), fmt_intarg(సంకేతం_2, val));
}

స్థిర శూన్య
dump_cfg_string(ServerOpCodes సంకేతం_2, స్థిరరాశి అక్షరం *val)
{
	రాయి("%s %s\n", lookup_opcode_name(సంకేతం_2),
	    val == ఖాళీ ? "none" : val);
}

స్థిర శూన్య
dump_cfg_strarray(ServerOpCodes సంకేతం_2, u_int లెక్క, అక్షరం **vals)
{
	u_int i;

	కొరకు (i = 0; i < లెక్క; i++)
		రాయి("%s %s\n", lookup_opcode_name(సంకేతం_2), vals[i]);
}

స్థిర శూన్య
dump_cfg_strarray_oneline(ServerOpCodes సంకేతం_2, u_int లెక్క, అక్షరం **vals)
{
	u_int i;

	ఎంపిక (సంకేతం_2) {
	స్థితి sAuthenticationMethods:
	స్థితి sChannelTimeout:
		ఆపు;
	అప్రమేయ:
		ఒకవేళ (లెక్క <= 0)
			తిరిగి;
		ఆపు;
	}

	రాయి("%s", lookup_opcode_name(సంకేతం_2));
	కొరకు (i = 0; i < లెక్క; i++)
		రాయి(" %s",  vals[i]);
	ఒకవేళ (సంకేతం_2 == sAuthenticationMethods && లెక్క == 0)
		రాయి(" any");
	లేకపోతే ఒకవేళ (సంకేతం_2 == sChannelTimeout && లెక్క == 0)
		రాయి(" none");
	రాయి("\n");
}

స్థిర అక్షరం *
format_listen_addrs(నిర్మాణం listenaddr *la)
{
	పూర్ణాంకం r;
	నిర్మాణం addrinfo *ai;
	అక్షరం addr[NI_MAXHOST], పోర్టు[NI_MAXSERV];
	అక్షరం *laddr1 = xstrdup(""), *laddr2 = ఖాళీ;

	/*
	 * ListenAddress must be after Port.  add_one_listen_addr pushes
	 * addresses onto a stack, so to maintain ordering we need to
	 * print these in reverse order.
	 */
	కొరకు (ai = la->addrs; ai; ai = ai->ai_next) {
		ఒకవేళ ((r = getnameinfo(ai->ai_addr, ai->ai_addrlen, addr,
		    పరిమాణం(addr), పోర్టు, పరిమాణం(పోర్టు),
		    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
			error("getnameinfo: %.100s", ssh_gai_strerror(r));
			కొనసాగు;
		}
		laddr2 = laddr1;
		ఒకవేళ (ai->ai_family == AF_INET6) {
			xasprintf(&laddr1, "ListenAddress [%s]:%s%s%s\n%s",
			    addr, పోర్టు,
			    la->rdomain == ఖాళీ ? "" : " rdomain ",
			    la->rdomain == ఖాళీ ? "" : la->rdomain,
			    laddr2);
		} లేకపోతే {
			xasprintf(&laddr1, "ListenAddress %s:%s%s%s\n%s",
			    addr, పోర్టు,
			    la->rdomain == ఖాళీ ? "" : " rdomain ",
			    la->rdomain == ఖాళీ ? "" : la->rdomain,
			    laddr2);
		}
		విడుదల(laddr2);
	}
	తిరిగి laddr1;
}

శూన్య
dump_config(ServerOptions *o)
{
	అక్షరం *s;
	u_int i;

	/* these are usually at the top of the config */
	కొరకు (i = 0; i < o->అంకె_ports; i++)
		రాయి("Port %d\n", o->ports[i]);
	dump_cfg_fmtint(s_చిరునామా_Family, o->చిరునామా_family);

	కొరకు (i = 0; i < o->అంకె_listen_addrs; i++) {
		s = format_listen_addrs(&o->listen_addrs[i]);
		రాయి("%s", s);
		విడుదల(s);
	}

	/* integer arguments */
#నిర్వచితమైతే USE_PAM
	dump_cfg_fmtint(sUsePAM, o->use_pam);
	dump_cfg_string(sPAMServiceName, o->pam_service_name);
#అయితే_ముగింపు
	dump_cfg_int(s_Login_Grace_సమయం, o->login_grace_సమయం);
	dump_cfg_int(s_X11_Display_స్థానభ్రంశం, o->x11_display_స్థానభ్రంశం);
	dump_cfg_int(sMaxAuthTries, o->max_authtries);
	dump_cfg_int(sMaxSessions, o->max_sessions);
	dump_cfg_int(sClientAliveInterval, o->client_alive_interval);
	dump_cfg_int(s_Client_Alive_లెక్క_Max, o->client_alive_లెక్క_max);
	dump_cfg_int(sRequiredRSASize, o->required_rsa_కొలత);
	dump_cfg_oct(s_ప్రవాహం_Local_Bind_ముసుగు, o->fwd_opts.streamlocal_bind_ముసుగు);
	dump_cfg_int(s_వాడని_Connection_Timeout, o->వాడని_connection_timeout);

	/* formatted integer arguments */
	dump_cfg_fmtint(s_Permit_మూలం_Login, o->permit_మూలం_login);
	dump_cfg_fmtint(sIgnoreRhosts, o->ignore_rhosts);
	dump_cfg_fmtint(s_Ignore_User_తెలిసిన_Hosts, o->ignore_user_తెలిసిన_hosts);
	dump_cfg_fmtint(sHostbasedAuthentication, o->hostbased_authentication);
	dump_cfg_fmtint(s_Hostbased_ఉపయోగిస్తుంది_Name_From_Packet_Only,
	    o->hostbased_ఉపయోగిస్తుంది_name_from_packet_only);
	dump_cfg_fmtint(sPubkeyAuthentication, o->pubkey_authentication);
#నిర్వచితమైతే KRB5
	dump_cfg_fmtint(sKerberosAuthentication, o->kerberos_authentication);
	dump_cfg_fmtint(sKerberosOrLocalPasswd, o->kerberos_or_local_passwd);
	dump_cfg_fmtint(sKerberosTicketCleanup, o->kerberos_ticket_cleanup);
# ifdef USE_AFS
	dump_cfg_fmtint(sKerberosGetAFSToken, o->kerberos_get_afs_token);
# endif
#అయితే_ముగింపు
#నిర్వచితమైతే GSSAPI
	dump_cfg_fmtint(sGSSAPIAuthentication, o->gss_authentication);
	dump_cfg_fmtint(sGSSAPICleanupCredentials, o->gss_cleanup_creds);
	dump_cfg_fmtint(sGSSAPIDelegateCredentials, o->gss_deleg_creds);
	dump_cfg_fmtint(sGSSAPIStrictAcceptorCheck, o->gss_strict_acceptor);
#అయితే_ముగింపు
	dump_cfg_fmtint(sPasswordAuthentication, o->password_authentication);
	dump_cfg_fmtint(sKbdInteractiveAuthentication,
	    o->kbd_interactive_authentication);
	dump_cfg_fmtint(sPrintMotd, o->print_motd);
#నిర్వచితం_కాకపోతే DISABLE_LASTLOG
	dump_cfg_fmtint(s_Print_చివరి_Log, o->print_lastlog);
#అయితే_ముగింపు
	dump_cfg_fmtint(sX11Forwarding, o->x11_forwarding);
	dump_cfg_fmtint(sX11UseLocalhost, o->x11_use_localhost);
	dump_cfg_fmtint(sPermitTTY, o->permit_tty);
	dump_cfg_fmtint(sPermitUserRC, o->permit_user_rc);
	dump_cfg_fmtint(sStrictModes, o->strict_modes);
	dump_cfg_fmtint(sTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(s_Permit_ఖాళీలు_Passwords, o->permit_ఖాళీలు_passwd);
	dump_cfg_fmtint(sCompression, o->compression);
	dump_cfg_fmtint(sGatewayPorts, o->fwd_opts.gateway_ports);
	dump_cfg_fmtint(sUseDNS, o->use_dns);
	dump_cfg_fmtint(sAllowTcpForwarding, o->allow_tcp_forwarding);
	dump_cfg_fmtint(sAllowAgentForwarding, o->allow_agent_forwarding);
	dump_cfg_fmtint(sDisableForwarding, o->disable_forwarding);
	dump_cfg_fmtint(s_Allow_ప్రవాహం_Local_Forwarding, o->allow_streamlocal_forwarding);
	dump_cfg_fmtint(s_ప్రవాహం_Local_Bind_Unlink, o->fwd_opts.streamlocal_bind_unlink);
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
	dump_cfg_string(sTrustedUserCAKeys, o->trusted_user_ca_కీలకాలు);
	dump_cfg_string(s_Security_కీలకం_Provider, o->sk_provider);
	dump_cfg_string(sAuthorizedPrincipalsFile,
	    o->authorized_principals_file);
	dump_cfg_string(s_సంస్కరణ_Addendum, *o->సంస్కరణ_addendum == '\0'
	    ? "none" : o->సంస్కరణ_addendum);
	dump_cfg_string(s_Authorized_కీలకాలు_Command, o->authorized_కీలకాలు_command);
	dump_cfg_string(s_Authorized_కీలకాలు_Command_User, o->authorized_కీలకాలు_command_user);
	dump_cfg_string(sAuthorizedPrincipalsCommand, o->authorized_principals_command);
	dump_cfg_string(sAuthorizedPrincipalsCommandUser, o->authorized_principals_command_user);
	dump_cfg_string(s_Host_కీలకం_Agent, o->host_కీలకం_agent);
	dump_cfg_string(sKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(sCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(sHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(s_Host_కీలకం_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(sPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
#ఒకవేళ defined(__OpenBSD__) || defined(HAVE_SYS_సమితి_PROCESS_RDOMAIN)
	dump_cfg_string(sRDomain, o->routing_domain);
#అయితే_ముగింపు
	dump_cfg_string(s_Sshd_Session_మార్గం, o->sshd_session_మార్గం);
	dump_cfg_string(s_Sshd_Auth_మార్గం, o->sshd_auth_మార్గం);
	dump_cfg_string(s_చొప్పున_ఆధారం_Penalty_Exempt_List, o->చొప్పున_ఆధారం_penalty_exempt);
	dump_cfg_string(s_Agent_Socket_మార్గం, o->agent_socket_మార్గం);

	/* string arguments requiring a lookup */
	dump_cfg_string(sLogLevel, log_level_name(o->log_level));
	dump_cfg_string(sSyslogFacility, log_facility_name(o->log_facility));

	/* string array arguments */
	dump_cfg_strarray_oneline(s_Authorized_కీలకాలు_File, o->అంకె_authkeys_files,
	    o->authorized_కీలకాలు_files);
	dump_cfg_strarray_oneline(s_Revoked_కీలకాలు, o->అంకె_revoked_కీలకాలు_files,
	    o->revoked_కీలకాలు_files);
	dump_cfg_strarray(s_Host_కీలకం, o->అంకె_host_కీలకం_files, o->host_కీలకం_files);
	dump_cfg_strarray(sHostCertificate, o->అంకె_host_cert_files,
	    o->host_cert_files);
	dump_cfg_strarray(sAllowUsers, o->అంకె_allow_users, o->allow_users);
	dump_cfg_strarray(sDenyUsers, o->అంకె_deny_users, o->deny_users);
	dump_cfg_strarray(sAllowGroups, o->అంకె_allow_groups, o->allow_groups);
	dump_cfg_strarray(sDenyGroups, o->అంకె_deny_groups, o->deny_groups);
	dump_cfg_strarray(sAcceptEnv, o->అంకె_accept_env, o->accept_env);
	dump_cfg_strarray(s_సమితి_Env, o->అంకె_setenv, o->setenv);
	dump_cfg_strarray_oneline(sAuthenticationMethods,
	    o->అంకె_auth_methods, o->auth_methods);
	dump_cfg_strarray_oneline(sLogVerbose,
	    o->అంకె_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(sChannelTimeout,
	    o->అంకె_channel_timeouts, o->channel_timeouts);

	/* other arguments */
	కొరకు (i = 0; i < o->అంకె_subsystems; i++)
		రాయి("Subsystem %s %s\n", o->subsystem_name[i],
		    o->subsystem_వాదనలు[i]);

	రాయి("MaxStartups %d:%d:%d\n", o->max_startups_begin,
	    o->max_startups_రేటు, o->max_startups);
	రాయి("PerSourceMaxStartups ");
	ఒకవేళ (o->చొప్పున_ఆధారం_max_startups == గరిష్ఠ_పూర్ణాంకం)
		రాయి("none\n");
	లేకపోతే
		రాయి("%d\n", o->చొప్పున_ఆధారం_max_startups);
	రాయి("PerSourceNetBlockSize %d:%d\n", o->చొప్పున_ఆధారం_masklen_ipv4,
	    o->చొప్పున_ఆధారం_masklen_ipv6);

	s = ఖాళీ;
	కొరకు (i = 0; tunmode_desc[i].val != -1; i++) {
		ఒకవేళ (tunmode_desc[i].val == o->permit_tun) {
			s = tunmode_desc[i].పాఠ్యం;
			ఆపు;
		}
	}
	dump_cfg_string(sPermitTunnel, s);

	రాయి("IPQoS %s ", iptos2str(o->ip_qos_interactive));
	రాయి("%s\n", iptos2str(o->ip_qos_bulk));

	రాయి("RekeyLimit %llu %d\n", (గుర్తులేని దీర్ఘ దీర్ఘ)o->rekey_హద్దు,
	    o->rekey_interval);

	రాయి("PermitOpen");
	ఒకవేళ (o->అంకె_permitted_opens == 0)
		రాయి(" any");
	లేకపోతే {
		కొరకు (i = 0; i < o->అంకె_permitted_opens; i++)
			రాయి(" %s", o->permitted_opens[i]);
	}
	రాయి("\n");
	రాయి("PermitListen");
	ఒకవేళ (o->అంకె_permitted_listens == 0)
		రాయి(" any");
	లేకపోతే {
		కొరకు (i = 0; i < o->అంకె_permitted_listens; i++)
			రాయి(" %s", o->permitted_listens[i]);
	}
	రాయి("\n");

	ఒకవేళ (o->permit_user_env_allowlist == ఖాళీ) {
		dump_cfg_fmtint(sPermitUserEnvironment, o->permit_user_env);
	} లేకపోతే {
		రాయి("PermitUserEnvironment %s\n",
		    o->permit_user_env_allowlist);
	}

	రాయి("PubkeyAuthOptions");
	ఒకవేళ (o->pubkey_auth_options == 0)
		రాయి(" none");
	ఒకవేళ (o->pubkey_auth_options & PUBKEYAUTH_TOUCH_REQUIRED)
		రాయి(" touch-required");
	ఒకవేళ (o->pubkey_auth_options & PUBKEYAUTH_VERIFY_REQUIRED)
		రాయి(" verify-required");
	ఒకవేళ (o->max_pubkey_ok != -1)
		రాయి(" max-pk-ok:%d", o->max_pubkey_ok);
	రాయి("\n");

	ఒకవేళ (o->చొప్పున_ఆధారం_penalty.enabled) {
		రాయి("PerSourcePenalties crash:%f authfail:%f noauth:%f "
		    "invaliduser:%f "
		    "grace-exceeded:%f refuseconnection:%f max:%f min:%f "
		    "max-sources4:%d max-sources6:%d "
		    "overflow:%s overflow6:%s\n",
		    o->చొప్పున_ఆధారం_penalty.penalty_crash,
		    o->చొప్పున_ఆధారం_penalty.penalty_authfail,
		    o->చొప్పున_ఆధారం_penalty.penalty_noauth,
		    o->చొప్పున_ఆధారం_penalty.penalty_invaliduser,
		    o->చొప్పున_ఆధారం_penalty.penalty_grace,
		    o->చొప్పున_ఆధారం_penalty.penalty_refuseconnection,
		    o->చొప్పున_ఆధారం_penalty.penalty_max,
		    o->చొప్పున_ఆధారం_penalty.penalty_min,
		    o->చొప్పున_ఆధారం_penalty.max_sources4,
		    o->చొప్పున_ఆధారం_penalty.max_sources6,
		    o->చొప్పున_ఆధారం_penalty.అధికప్రవాహం_బహుళకం ==
		    చొప్పున_ఆధారం_PENALTY_అధికప్రవాహం_DENY_ALL ?
		    "deny-all" : "permissive",
		    o->చొప్పున_ఆధారం_penalty.అధికప్రవాహం_mode6 ==
		    చొప్పున_ఆధారం_PENALTY_అధికప్రవాహం_DENY_ALL ?
		    "deny-all" : "permissive");
	} లేకపోతే
		రాయి("PerSourcePenalties no\n");
}
