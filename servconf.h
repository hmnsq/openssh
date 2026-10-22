/* $OpenBSD: servconf.h,v 1.183 2026/09/16 00:29:44 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Definitions for server configuration data and for the functions reading it.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#నిర్వచితం_కాకపోతే SERVCONF_H
#నిర్వచించు SERVCONF_H

#అన్తర్భావ <sys/queue.h>

నిర్మాణం sshbuf;

#నిర్వచించు MAX_PORTS		256	/* Max # ports. */

/* permit_root_login */
#నిర్వచించు	PERMIT_NOT_సమితి		-1
#నిర్వచించు	PERMIT_NO		0
#నిర్వచించు	PERMIT_FORCED_ONLY	1
#నిర్వచించు	PERMIT_NO_PASSWD	2
#నిర్వచించు	PERMIT_YES		3

/* PermitOpen */
#నిర్వచించు PERMITOPEN_ANY		0
#నిర్వచించు PERMITOPEN_NONE		-2

/* IgnoreRhosts */
#నిర్వచించు IGNORE_RHOSTS_NO	0
#నిర్వచించు IGNORE_RHOSTS_YES	1
#నిర్వచించు IGNORE_RHOSTS_SHOSTS	2

#నిర్వచించు DEFAULT_AUTH_FAIL_MAX	6	/* Default for MaxAuthTries */
#నిర్వచించు DEFAULT_SESSIONS_MAX	10	/* Default for MaxSessions */

/* Magic name for internal sftp-server */
#నిర్వచించు అంతర్గత_SFTP_NAME	"internal-sftp"

/* PubkeyAuthOptions flags */
#నిర్వచించు PUBKEYAUTH_TOUCH_REQUIRED	(1)
#నిర్వచించు PUBKEYAUTH_VERIFY_REQUIRED	(1<<1)

/* Various defaults */
#నిర్వచించు SSHD_DEFAULT_LOGIN_GRACE_సమయం	120
#నిర్వచించు SSHD_DEFAULT_X11_DISPLAY_స్థానభ్రంశం	10
#నిర్వచితమైతే WITH_ZLIB
#నిర్వచించు SSHD_DEFAULT_COMPRESSION	COMP_DELAYED
#లేకపోతే
#నిర్వచించు SSHD_DEFAULT_COMPRESSION	COMP_NONE
#అయితే_ముగింపు

/* TCPKeepAlive flags */
#నిర్వచించు SSH_KEEPALIVES_OFF		0
#నిర్వచించు SSH_KEEPALIVES_TRANSPORT	1
#నిర్వచించు SSH_KEEPALIVES_ALL		2

నిర్మాణం ssh;

/*
 * Used to store addresses from ListenAddr directives. These may be
 * incomplete, as they may specify addresses that need to be merged
 * with any ports requested by ListenPort.
 */
నిర్మాణం queued_listenaddr {
	అక్షరం *addr;
	పూర్ణాంకం పోర్టు; /* <=0 if unspecified */
	అక్షరం *rdomain;
};

/* Resolved listen addresses, grouped by optional routing domain */
నిర్మాణం listenaddr {
	అక్షరం *rdomain;
	నిర్మాణం addrinfo *addrs;
};

#నిర్వచించు చొప్పున_ఆధారం_PENALTY_అధికప్రవాహం_DENY_ALL	1
#నిర్వచించు చొప్పున_ఆధారం_PENALTY_అధికప్రవాహం_PERMISSIVE	2
నిర్మాణం చొప్పున_ఆధారం_penalty {
	పూర్ణాంకం	enabled;
	పూర్ణాంకం	max_sources4;
	పూర్ణాంకం	max_sources6;
	పూర్ణాంకం	అధికప్రవాహం_బహుళకం;
	పూర్ణాంకం	అధికప్రవాహం_mode6;
	ద్విగుణ	penalty_crash;
	ద్విగుణ	penalty_grace;
	ద్విగుణ	penalty_authfail;
	ద్విగుణ	penalty_invaliduser;
	ద్విగుణ	penalty_noauth;
	ద్విగుణ	penalty_refuseconnection;
	ద్విగుణ	penalty_max;
	ద్విగుణ	penalty_min;
};

/* Options for whether config entries are copied after Match processing */
#నిర్వచించు SSHCFG_COPY_NONE(action)
#నిర్వచించు SSHCFG_COPY_సరిపోలిక(action)	action
#నిర్వచించు SSHCFG_COPY_MANUAL(action)

/*
 * This macro is used to generate most of ServerOptions and some of the
 * parsing and de/serialisation code in servconf.c. Every variable in
 * ServerOptions *must* be represented here.
 *
 * Variables and configuration options that need special handling (e.g.
 * those that represent a struct or use a single option to populate multiple
 * values) use the SSHCONF_CUSTOM macro and get manual variable entries in
 * ServerOptions below.
 *
 * Variables that exist in ServerOptions but aren't populated by a keyword
 * use the SSHCONF_NONCONF macro and also get manual entries in ServerOptions.
 *
 * Everything else uses one of the SSHCONF_INT, SSHCONF_INTFLAG,
 * SSHCONF_STRING, or SSHCONF_STRARRAY macros. These automatically populate
 * their corresponding variable definitions in ServerOptions. The integer
 * options also include defaults for initialisation.
 *
 * Deprecated and ignored options use SSHCONF_DEPRECATE and don't populate
 * ServerOptions. Unsupported options use SSHCONF_UNSUPPORTED_INT or
 * SSHCONF_UNSUPPORTED_STRING to populate placeholders in ServerOptions that
 * are not otherwise used. Deprecated aliases that still work use
 * SSHCONF_ALIAS.
 *
 * Why go to all this trouble? It ensures a level of consistency between
 * the configuration structure and the parsing code and helps us write
 * serialisation/deserialisation functions that we can be pretty sure will
 * capture every value in the configuration file.
 *
 * Entry formats:
 *   SSHCONF_INT(field, keyword, scope, multistate, default, copy)
 *   SSHCONF_INTFLAG(field, keyword, scope, default, copy)
 *   SSHCONF_STRING(field, keyword, scope, copy)
 *   SSHCONF_STRARRAY(field, nfield, keyword, scope, copy)
 *   SSHCONF_CUSTOM(keyword, suffix, scope, copy)
 *   SSHCONF_NONCONF(suffix)
 *   SSHCONF_DEPRECATE(keyword, scope, token)
 *   SSHCONF_UNSUPPORTED_INT(field, keyword, scope)
 *   SSHCONF_UNSUPPORTED_STRING(field, keyword, scope)
 *   SSHCONF_ALIAS(old_keyword, keyword, scope)
 */
#నిర్వచించు SSHD_CONFIG_ENTRIES_CUSTOM \
SSHCONF_CUSTOM(పోర్టు_2, పోర్టు, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Listen_చిరునామా, listenaddress, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Host_కీలకం, hostkeyfile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(IPQoS, ipqos, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_CUSTOM(GatewayPorts, gatewayports, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_CUSTOM(ప్రవాహం_Local_Bind_ముసుగు, streamlocalbindmask, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_CUSTOM(ప్రవాహం_Local_Bind_Unlink, streamlocalbindunlink, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_CUSTOM(SyslogFacility, logfacility, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(LogLevel, loglevel, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_CUSTOM(PermitUserEnvironment, permituserenv, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Subsystem, subsystem, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_CUSTOM(MaxStartups, maxstartups, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(చొప్పున_ఆధారం_Net_ఖండం_కొలత, persourcenetblocksize, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(చొప్పున_ఆధారం_Penalties, persourcepenalties, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Rekey_హద్దు, rekeylimit, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_CUSTOM(PubkeyAuthOptions, pubkey_auth_options, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_NONCONF(timingsecret)

#నిర్వచించు SSHD_CONFIG_ENTRIES_MAIN \
SSHCONF_INT(చిరునామా_family, చిరునామా_Family, SSHCFG_GLOBAL, multistate_addressfamily, AF_UNSPEC, SSHCFG_COPY_NONE) \
SSHCONF_STRING(routing_domain, RDomain, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRARRAY(host_cert_files, అంకె_host_cert_files, HostCertificate, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(host_కీలకం_agent, Host_కీలకం_Agent, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(pid_file, PidFile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(moduli_file, ModuliFile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(login_grace_సమయం, Login_Grace_సమయం, SSHCFG_GLOBAL, ఖాళీ, SSHD_DEFAULT_LOGIN_GRACE_సమయం, SSHCFG_COPY_NONE) \
SSHCONF_INT(permit_మూలం_login, Permit_మూలం_Login, SSHCFG_ALL, multistate_permitrootlogin, PERMIT_NO_PASSWD, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INT(ignore_rhosts, IgnoreRhosts, SSHCFG_ALL, multistate_ignore_rhosts, 1, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INTFLAG(ignore_user_తెలిసిన_hosts, Ignore_User_తెలిసిన_Hosts, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(print_motd, PrintMotd, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(x11_forwarding, X11Forwarding, SSHCFG_ALL, 0, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INT(x11_display_స్థానభ్రంశం, X11_Display_స్థానభ్రంశం, SSHCFG_ALL, ఖాళీ, SSHD_DEFAULT_X11_DISPLAY_స్థానభ్రంశం, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INTFLAG(x11_use_localhost, X11UseLocalhost, SSHCFG_ALL, 1, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRING(xauth_location, XAuthLocation, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(permit_tty, PermitTTY, SSHCFG_ALL, 1, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INTFLAG(permit_user_rc, PermitUserRC, SSHCFG_ALL, 1, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INTFLAG(strict_modes, StrictModes, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(tcp_keep_alive, TCPKeepAlive, SSHCFG_GLOBAL, SSH_KEEPALIVES_TRANSPORT, SSHCFG_COPY_NONE) \
SSHCONF_STRING(ciphers, Ciphers, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(macs, Macs, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(kex_algorithms, KexAlgorithms, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRARRAY(log_verbose, అంకె_log_verbose, LogVerbose, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INTFLAG(hostbased_authentication, HostbasedAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INTFLAG(hostbased_ఉపయోగిస్తుంది_name_from_packet_only, Hostbased_ఉపయోగిస్తుంది_Name_From_Packet_Only, SSHCFG_ALL, 0, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRING(hostbased_accepted_algos, HostbasedAcceptedAlgorithms, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRING(hostkeyalgorithms, Host_కీలకం_Algorithms, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(ca_sign_algorithms, CASignatureAlgorithms, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INTFLAG(pubkey_authentication, PubkeyAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRING(pubkey_accepted_algos, PubkeyAcceptedAlgorithms, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INTFLAG(password_authentication, PasswordAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INTFLAG(kbd_interactive_authentication, KbdInteractiveAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INTFLAG(permit_ఖాళీలు_passwd, Permit_ఖాళీలు_Passwords, SSHCFG_ALL, 0, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INT(compression, Compression, SSHCFG_GLOBAL, multistate_compression, SSHD_DEFAULT_COMPRESSION, SSHCFG_COPY_NONE) \
SSHCONF_INT(allow_tcp_forwarding, AllowTcpForwarding, SSHCFG_ALL, multistate_tcpfwd, FORWARD_ALLOW, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INT(allow_streamlocal_forwarding, Allow_ప్రవాహం_Local_Forwarding, SSHCFG_ALL, multistate_tcpfwd, FORWARD_ALLOW, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INTFLAG(allow_agent_forwarding, AllowAgentForwarding, SSHCFG_ALL, 1, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INTFLAG(disable_forwarding, DisableForwarding, SSHCFG_ALL, 0, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRARRAY(allow_users, అంకె_allow_users, AllowUsers, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRARRAY(deny_users, అంకె_deny_users, DenyUsers, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRARRAY(allow_groups, అంకె_allow_groups, AllowGroups, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRARRAY(deny_groups, అంకె_deny_groups, DenyGroups, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRARRAY(accept_env, అంకె_accept_env, AcceptEnv, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRARRAY(setenv, అంకె_setenv, సమితి_Env, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INT(చొప్పున_ఆధారం_max_startups, చొప్పున_ఆధారం_Max_Startups, SSHCFG_GLOBAL, ఖాళీ, గరిష్ఠ_పూర్ణాంకం, SSHCFG_COPY_NONE) \
SSHCONF_STRING(చొప్పున_ఆధారం_penalty_exempt, చొప్పున_ఆధారం_Penalty_Exempt_List, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(max_authtries, MaxAuthTries, SSHCFG_ALL, ఖాళీ, DEFAULT_AUTH_FAIL_MAX, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INT(max_sessions, MaxSessions, SSHCFG_ALL, ఖాళీ, DEFAULT_SESSIONS_MAX, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRING(banner, Banner, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INTFLAG(use_dns, UseDNS, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_INT(client_alive_interval, ClientAliveInterval, SSHCFG_ALL, ఖాళీ, 0, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INT(client_alive_లెక్క_max, Client_Alive_లెక్క_Max, SSHCFG_ALL, ఖాళీ, 3, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRARRAY(authorized_కీలకాలు_files, అంకె_authkeys_files, Authorized_కీలకాలు_File, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRING(adm_forced_command, ForceCommand, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_INTFLAG(permit_tun, PermitTunnel, SSHCFG_ALL, SSH_TUNMODE_NO, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRARRAY(permitted_opens, అంకె_permitted_opens, PermitOpen, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRARRAY(permitted_listens, అంకె_permitted_listens, PermitListen, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRING(chroot_directory, ChrootDirectory, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_STRARRAY(revoked_కీలకాలు_files, అంకె_revoked_కీలకాలు_files, Revoked_కీలకాలు, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRING(trusted_user_ca_కీలకాలు, TrustedUserCAKeys, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRING(authorized_కీలకాలు_command, Authorized_కీలకాలు_Command, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRING(authorized_కీలకాలు_command_user, Authorized_కీలకాలు_Command_User, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRING(authorized_principals_file, AuthorizedPrincipalsFile, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRING(authorized_principals_command, AuthorizedPrincipalsCommand, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRING(authorized_principals_command_user, AuthorizedPrincipalsCommandUser, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRING(సంస్కరణ_addendum, సంస్కరణ_Addendum, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRARRAY(auth_methods, అంకె_auth_methods, AuthenticationMethods, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INT(fingerprint_hash, FingerprintHash, SSHCFG_GLOBAL, ఖాళీ, SSH_FP_HASH_DEFAULT, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(expose_userauth_info, ExposeAuthInfo, SSHCFG_ALL, 0, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRING(sk_provider, Security_కీలకం_Provider, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(required_rsa_కొలత, RequiredRSASize, SSHCFG_ALL, ఖాళీ, SSH_RSA_MINIMUM_MODULUS_కొలత, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRARRAY(channel_timeouts, అంకె_channel_timeouts, ChannelTimeout, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INT(వాడని_connection_timeout, వాడని_Connection_Timeout, SSHCFG_ALL, ఖాళీ, 0, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRING(sshd_session_మార్గం, Sshd_Session_మార్గం, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(sshd_auth_మార్గం, Sshd_Auth_మార్గం, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(refuse_connection, RefuseConnection, SSHCFG_ALL, 0, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_STRING(agent_socket_మార్గం, Agent_Socket_మార్గం, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INT(warn_weak_crypto, WarnWeakCrypto, SSHCFG_GLOBAL, multistate_warnweakcrypto, 1, SSHCFG_COPY_NONE)

#నిర్వచించు SSHD_CONFIG_ENTRIES_LEGACY \
SSHCONF_DEPRECATE(Server_కీలకం_బిట్లు, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(కీలకం_Regeneration_Interval, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RHostsAuthentication, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RhostsRSAAuthentication, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RSAAuthentication, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(CheckMail, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(UseLogin, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Verify_తిరగేయి_Mapping, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(తిరగేయి_Mapping_Check, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Authorized_కీలకాలు_File2, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(UsePrivilegeSeparation, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(KerberosTgtPassing, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(AFSTokenPassing, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Protocol, SSHCFG_GLOBAL, SSHCONF_IGNORE)

#నిర్వచించు SSHD_CONFIG_ENTRIES_ALIASES \
SSHCONF_ALIAS(HostDSAKey, Host_కీలకం, SSHCFG_GLOBAL) \
SSHCONF_ALIAS(Host_Based_Accepted_కీలకం_Types, HostbasedAcceptedAlgorithms, SSHCFG_ALL) \
SSHCONF_ALIAS(Pubkey_Accepted_కీలకం_Types, PubkeyAcceptedAlgorithms, SSHCFG_ALL) \
SSHCONF_ALIAS(DSAAuthentication, PubkeyAuthentication, SSHCFG_GLOBAL) \
SSHCONF_ALIAS(ChallengeResponseAuthentication, KbdInteractiveAuthentication, SSHCFG_ALL) \
SSHCONF_ALIAS(SKeyAuthentication, KbdInteractiveAuthentication, SSHCFG_ALL) \
SSHCONF_ALIAS(KeepAlive, TCPKeepAlive, SSHCFG_GLOBAL)

#నిర్వచించు SSHD_CONFIG_ENTRIES_పునాది \
	SSHD_CONFIG_ENTRIES_CUSTOM \
	SSHD_CONFIG_ENTRIES_MAIN \
	SSHD_CONFIG_ENTRIES_LEGACY \
	SSHD_CONFIG_ENTRIES_ALIASES \
	SSHD_CONFIG_ENTRIES_PAM \
	SSHD_CONFIG_ENTRIES_LASTLOG

#నిర్వచితమైతే USE_PAM
#నిర్వచించు SSHD_CONFIG_ENTRIES_PAM \
SSHCONF_INTFLAG(use_pam, UsePAM, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_STRING(pam_service_name, PAMServiceName, SSHCFG_ALL, SSHCFG_COPY_సరిపోలిక)
#లేకపోతే
#నిర్వచించు SSHD_CONFIG_ENTRIES_PAM \
SSHCONF_UNSUPPORTED_INT(use_pam, UsePAM, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_STRING(pam_service_name, PAMServiceName, SSHCFG_ALL)
#అయితే_ముగింపు

#నిర్వచితమైతే DISABLE_LASTLOG
#నిర్వచించు SSHD_CONFIG_ENTRIES_LASTLOG \
SSHCONF_UNSUPPORTED_INT(print_lastlog, Print_చివరి_Log, SSHCFG_GLOBAL)
#లేకపోతే
#నిర్వచించు SSHD_CONFIG_ENTRIES_LASTLOG \
SSHCONF_INTFLAG(print_lastlog, Print_చివరి_Log, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE)
#అయితే_ముగింపు

/* Compile-time enabled options */
#నిర్వచితమైతే KRB5

#నిర్వచితమైతే USE_AFS
#నిర్వచించు SSHD_CONFIG_KRB5_AFS \
SSHCONF_INTFLAG(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE)
#లేకపోతే /* USE_AFS */
#నిర్వచించు SSHD_CONFIG_KRB5_AFS \
SSHCONF_UNSUPPORTED_INT(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL)
#అయితే_ముగింపు /* USE_AFS */

#నిర్వచించు SSHD_CONFIG_ENTRIES_KRB5 \
SSHCONF_INTFLAG(kerberos_authentication, KerberosAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INTFLAG(kerberos_or_local_passwd, KerberosOrLocalPasswd, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(kerberos_ticket_cleanup, KerberosTicketCleanup, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHD_CONFIG_KRB5_AFS
#లేకపోతే /* KRB5 */
#నిర్వచించు SSHD_CONFIG_ENTRIES_KRB5 \
SSHCONF_UNSUPPORTED_INT(kerberos_authentication, KerberosAuthentication, SSHCFG_ALL) \
SSHCONF_UNSUPPORTED_INT(kerberos_or_local_passwd, KerberosOrLocalPasswd, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(kerberos_ticket_cleanup, KerberosTicketCleanup, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL)
#అయితే_ముగింపు /* KRB5 */

#నిర్వచితమైతే GSSAPI
#నిర్వచించు SSHD_CONFIG_ENTRIES_GSS \
SSHCONF_INTFLAG(gss_authentication, GSSAPIAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_సరిపోలిక) \
SSHCONF_INTFLAG(gss_cleanup_creds, GSSAPICleanupCredentials, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(gss_deleg_creds, GSSAPIDelegateCredentials, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(gss_strict_acceptor, GSSAPIStrictAcceptorCheck, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE)
#లేకపోతే /* GSSAPI */
#నిర్వచించు SSHD_CONFIG_ENTRIES_GSS \
SSHCONF_UNSUPPORTED_INT(gss_authentication, GSSAPIAuthentication, SSHCFG_ALL) \
SSHCONF_UNSUPPORTED_INT(gss_cleanup_creds, GSSAPICleanupCredentials, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(gss_deleg_creds, GSSAPIDelegateCredentials, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(gss_strict_acceptor, GSSAPIStrictAcceptorCheck, SSHCFG_GLOBAL)
#అయితే_ముగింపు /* GSSAPI */

#నిర్వచించు SSHD_CONFIG_ENTRIES \
	SSHD_CONFIG_ENTRIES_పునాది \
	SSHD_CONFIG_ENTRIES_KRB5 \
	SSHD_CONFIG_ENTRIES_GSS \

/* Macros to declare ServerOptions member variables */
#నిర్వచించు SSHCONF_INT(var, conf, flags, ms, def, cp)	పూర్ణాంకం var;
#నిర్వచించు SSHCONF_INTFLAG(var, conf, flags, def, cp)	పూర్ణాంకం var;
#నిర్వచించు SSHCONF_STRING(var, conf, flags, cp)		అక్షరం *var;
#నిర్వచించు SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	\
	అక్షరం **var; \
	u_int nvar;
#నిర్వచించు SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/*ఖాళీలు*/
#నిర్వచించు SSHCONF_NONCONF(funcsuffix)			/*ఖాళీలు*/
#నిర్వచించు SSHCONF_DEPRECATE(conf, flags, opcode)		/*ఖాళీలు*/
#నిర్వచించు SSHCONF_UNSUPPORTED_INT(var, conf, flags)	పూర్ణాంకం var;
#నిర్వచించు SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	అక్షరం *var;
#నిర్వచించు SSHCONF_ALIAS(old, conf, flags)			/*ఖాళీలు*/

రకనిర్వచనం నిర్మాణం ServerOptions {
	SSHD_CONFIG_ENTRIES
	/* Ports */
	u_int	అంకె_ports;
	u_int	ports_from_cmdline;
	పూర్ణాంకం	ports[MAX_PORTS];	/* Port number to listen on. */
	/* ListenAddress */
	నిర్మాణం queued_listenaddr *queued_listen_addrs;
	u_int	అంకె_queued_listens;
	నిర్మాణం listenaddr *listen_addrs;
	u_int	అంకె_listen_addrs;
	/* HostKey */
	అక్షరం   **host_కీలకం_files;	/* Files containing host keys. */
	పూర్ణాంకం	*host_కీలకం_file_userprovided; /* Key was specified by user. */
	u_int	అంకె_host_కీలకం_files;     /* Number of files for host keys. */
	/* IPQoS */
	పూర్ణాంకం	ip_qos_interactive;	/* IP ToS/DSCP/class for interactive */
	పూర్ణాంకం	ip_qos_bulk;		/* IP ToS/DSCP/class for bulk traffic */
	/* GatewayPorts, StreamLocalBindMask, StreamLocalBindUnlink */
	నిర్మాణం ForwardOptions fwd_opts;	/* forwarding options */
	/* LogFacility */
	SyslogFacility log_facility;	/* Facility for system logging. */
	/* LogLevel */
	LogLevel log_level;	/* Level for system logging. */
	/* PermitUserEnvironment */
	పూర్ణాంకం     permit_user_env;	/* If true, read ~/.ssh/environment */
	అక్షరం   *permit_user_env_allowlist; /* pattern-list of allowed env names */
	/* Subsystem */
	u_int అంకె_subsystems;
	అక్షరం   **subsystem_name;
	అక్షరం   **subsystem_command;
	అక్షరం   **subsystem_వాదనలు;
	/* MaxStartups */
	పూర్ణాంకం	max_startups_begin;
	పూర్ణాంకం	max_startups_రేటు;
	పూర్ణాంకం	max_startups;
	/* PerSourceNetBlockSize */
	పూర్ణాంకం	చొప్పున_ఆధారం_masklen_ipv4;
	పూర్ణాంకం	చొప్పున_ఆధారం_masklen_ipv6;
	/* PerSourcePenalties */
	నిర్మాణం చొప్పున_ఆధారం_penalty చొప్పున_ఆధారం_penalty;
	/* RekeyLimit */
	int64_t rekey_హద్దు;
	పూర్ణాంకం	rekey_interval;
	/* PubkeyAuthOptions */
	పూర్ణాంకం	pubkey_auth_options;
	పూర్ణాంకం	max_pubkey_ok;
	/* Passed by config but not keyword for this */
	uint64_t timing_secret;
}       ServerOptions;
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

/* Information about the incoming connection as used by Match */
నిర్మాణం connection_info {
	స్థిరరాశి అక్షరం *user;
	పూర్ణాంకం user_invalid;
	స్థిరరాశి అక్షరం *host;	/* possibly resolved hostname */
	స్థిరరాశి అక్షరం *చిరునామా;	/* remote address */
	స్థిరరాశి అక్షరం *laddress;	/* local address */
	పూర్ణాంకం lport;		/* local port */
	స్థిరరాశి అక్షరం *rdomain;	/* routing domain if available */
	పూర్ణాంకం test;		/* test mode, allow some attributes to be
				 * unspecified */
};

/* List of included files for re-exec from the parsed configuration */
నిర్మాణం include_అంశం {
	అక్షరం *selector;
	అక్షరం *filename;
	నిర్మాణం sshbuf *contents;
	TAILQ_ENTRY(include_అంశం) నమోదు_2;
};
TAILQ_HEAD(include_list, include_అంశం);

శూన్య	 initialize_server_options(ServerOptions *);
శూన్య	 fill_default_server_options(ServerOptions *);
పూర్ణాంకం	 process_server_config_పంక్తి(ServerOptions *, అక్షరం *, స్థిరరాశి అక్షరం *, పూర్ణాంకం,
	    పూర్ణాంకం *, నిర్మాణం connection_info *, నిర్మాణం include_list *includes);
శూన్య	 ఎక్కించు_server_config(స్థిరరాశి అక్షరం *, నిర్మాణం sshbuf *);
శూన్య	 parse_server_config(ServerOptions *, స్థిరరాశి అక్షరం *, నిర్మాణం sshbuf *,
	    నిర్మాణం include_list *includes, నిర్మాణం connection_info *, పూర్ణాంకం);
శూన్య	 parse_server_సరిపోలిక_config(ServerOptions *,
	    నిర్మాణం include_list *includes, నిర్మాణం connection_info *);
పూర్ణాంకం	 parse_server_సరిపోలిక_testspec(నిర్మాణం connection_info *, అక్షరం *);
శూన్య	 servconf_విలీనం_subsystems(ServerOptions *, ServerOptions *);
శూన్య	 copy_సమితి_server_options(ServerOptions *, ServerOptions *, పూర్ణాంకం);
శూన్య	 dump_config(ServerOptions *);
అక్షరం	*derelativise_మార్గం(స్థిరరాశి అక్షరం *);
శూన్య	 servconf_కూడు_hostkey(స్థిరరాశి అక్షరం *, స్థిరరాశి పూర్ణాంకం,
	    ServerOptions *, స్థిరరాశి అక్షరం *మార్గం, పూర్ణాంకం);
శూన్య	 servconf_కూడు_hostcert(స్థిరరాశి అక్షరం *, స్థిరరాశి పూర్ణాంకం,
	    ServerOptions *, స్థిరరాశి అక్షరం *మార్గం);

పూర్ణాంకం	 serialise_server_options(స్థిరరాశి ServerOptions *, నిర్మాణం sshbuf **);
పూర్ణాంకం	 deserialise_server_options(నిర్మాణం sshbuf *, ServerOptions *);
శూన్య	 free_server_options(ServerOptions *);

#అయితే_ముగింపు				/* SERVCONF_H */
