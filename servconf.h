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

#جيڪڏهن_وصف_نه_ٿيل SERVCONF_H
#وصف_ڪريو SERVCONF_H

#ضمن <sys/queue.h>

بنية sshbuf;

#وصف_ڪريو MAX_PORTS		256	/* Max # ports. */

/* permit_root_login */
#وصف_ڪريو	PERMIT_NOT_سيٽ		-1
#وصف_ڪريو	PERMIT_NO		0
#وصف_ڪريو	PERMIT_FORCED_ONLY	1
#وصف_ڪريو	PERMIT_NO_PASSWD	2
#وصف_ڪريو	PERMIT_YES		3

/* PermitOpen */
#وصف_ڪريو PERMITOPEN_ANY		0
#وصف_ڪريو PERMITOPEN_NONE		-2

/* IgnoreRhosts */
#وصف_ڪريو IGNORE_RHOSTS_NO	0
#وصف_ڪريو IGNORE_RHOSTS_YES	1
#وصف_ڪريو IGNORE_RHOSTS_SHOSTS	2

#وصف_ڪريو DEFAULT_AUTH_FAIL_MAX	6	/* Default for MaxAuthTries */
#وصف_ڪريو DEFAULT_SESSIONS_MAX	10	/* Default for MaxSessions */

/* Magic name for internal sftp-server */
#وصف_ڪريو اندروني_SFTP_NAME	"internal-sftp"

/* PubkeyAuthOptions flags */
#وصف_ڪريو PUBKEYAUTH_TOUCH_REQUIRED	(1)
#وصف_ڪريو PUBKEYAUTH_VERIFY_REQUIRED	(1<<1)

/* Various defaults */
#وصف_ڪريو SSHD_DEFAULT_LOGIN_GRACE_وقت	120
#وصف_ڪريو SSHD_DEFAULT_X11_DISPLAY_وٿي	10
#جيڪڏهن_وصف_ٿيل WITH_ZLIB
#وصف_ڪريو SSHD_DEFAULT_COMPRESSION	COMP_DELAYED
#وإلا
#وصف_ڪريو SSHD_DEFAULT_COMPRESSION	COMP_NONE
#جيڪڏهن_پورو

/* TCPKeepAlive flags */
#وصف_ڪريو SSH_KEEPALIVES_OFF		0
#وصف_ڪريو SSH_KEEPALIVES_TRANSPORT	1
#وصف_ڪريو SSH_KEEPALIVES_ALL		2

بنية ssh;

/*
 * Used to store addresses from ListenAddr directives. These may be
 * incomplete, as they may specify addresses that need to be merged
 * with any ports requested by ListenPort.
 */
بنية queued_listenaddr {
	حرف *addr;
	صحيح پورٽ; /* <=0 if unspecified */
	حرف *rdomain;
};

/* Resolved listen addresses, grouped by optional routing domain */
بنية listenaddr {
	حرف *rdomain;
	بنية addrinfo *addrs;
};

#وصف_ڪريو في_ذريعو_PENALTY_حد_کان_مٿي_DENY_ALL	1
#وصف_ڪريو في_ذريعو_PENALTY_حد_کان_مٿي_PERMISSIVE	2
بنية في_ذريعو_penalty {
	صحيح	enabled;
	صحيح	max_sources4;
	صحيح	max_sources6;
	صحيح	حد_کان_مٿي_گهڻائي;
	صحيح	حد_کان_مٿي_mode6;
	مزدوج	penalty_crash;
	مزدوج	penalty_grace;
	مزدوج	penalty_authfail;
	مزدوج	penalty_invaliduser;
	مزدوج	penalty_noauth;
	مزدوج	penalty_refuseconnection;
	مزدوج	penalty_max;
	مزدوج	penalty_min;
};

/* Options for whether config entries are copied after Match processing */
#وصف_ڪريو SSHCFG_COPY_NONE(action)
#وصف_ڪريو SSHCFG_COPY_ميلاپ(action)	action
#وصف_ڪريو SSHCFG_COPY_MANUAL(action)

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
#وصف_ڪريو SSHD_CONFIG_ENTRIES_CUSTOM \
SSHCONF_CUSTOM(پورٽ_2, پورٽ, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Listen_پتو, listenaddress, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Host_ڪنجي, hostkeyfile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(IPQoS, ipqos, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_CUSTOM(GatewayPorts, gatewayports, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_CUSTOM(وهڪرو_Local_Bind_نقاب, streamlocalbindmask, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_CUSTOM(وهڪرو_Local_Bind_Unlink, streamlocalbindunlink, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_CUSTOM(SyslogFacility, logfacility, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(LogLevel, loglevel, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_CUSTOM(PermitUserEnvironment, permituserenv, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Subsystem, subsystem, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_CUSTOM(MaxStartups, maxstartups, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(في_ذريعو_Net_بلاڪ_سائيز, persourcenetblocksize, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(في_ذريعو_Penalties, persourcepenalties, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Rekey_حد_بندي, rekeylimit, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_CUSTOM(PubkeyAuthOptions, pubkey_auth_options, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_NONCONF(timingsecret)

#وصف_ڪريو SSHD_CONFIG_ENTRIES_MAIN \
SSHCONF_INT(پتو_family, پتو_Family, SSHCFG_GLOBAL, multistate_addressfamily, AF_UNSPEC, SSHCFG_COPY_NONE) \
SSHCONF_STRING(routing_domain, RDomain, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRARRAY(host_cert_files, انگ_host_cert_files, HostCertificate, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(host_ڪنجي_agent, Host_ڪنجي_Agent, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(pid_file, PidFile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(moduli_file, ModuliFile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(login_grace_وقت, Login_Grace_وقت, SSHCFG_GLOBAL, عدم, SSHD_DEFAULT_LOGIN_GRACE_وقت, SSHCFG_COPY_NONE) \
SSHCONF_INT(permit_پاڙ_login, Permit_پاڙ_Login, SSHCFG_ALL, multistate_permitrootlogin, PERMIT_NO_PASSWD, SSHCFG_COPY_ميلاپ) \
SSHCONF_INT(ignore_rhosts, IgnoreRhosts, SSHCFG_ALL, multistate_ignore_rhosts, 1, SSHCFG_COPY_ميلاپ) \
SSHCONF_INTFLAG(ignore_user_معلوم_hosts, Ignore_User_معلوم_Hosts, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(print_motd, PrintMotd, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(x11_forwarding, X11Forwarding, SSHCFG_ALL, 0, SSHCFG_COPY_ميلاپ) \
SSHCONF_INT(x11_display_وٿي, X11_Display_وٿي, SSHCFG_ALL, عدم, SSHD_DEFAULT_X11_DISPLAY_وٿي, SSHCFG_COPY_ميلاپ) \
SSHCONF_INTFLAG(x11_use_localhost, X11UseLocalhost, SSHCFG_ALL, 1, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRING(xauth_location, XAuthLocation, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(permit_tty, PermitTTY, SSHCFG_ALL, 1, SSHCFG_COPY_ميلاپ) \
SSHCONF_INTFLAG(permit_user_rc, PermitUserRC, SSHCFG_ALL, 1, SSHCFG_COPY_ميلاپ) \
SSHCONF_INTFLAG(strict_modes, StrictModes, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(tcp_keep_alive, TCPKeepAlive, SSHCFG_GLOBAL, SSH_KEEPALIVES_TRANSPORT, SSHCFG_COPY_NONE) \
SSHCONF_STRING(ciphers, Ciphers, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(macs, Macs, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(kex_algorithms, KexAlgorithms, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRARRAY(log_verbose, انگ_log_verbose, LogVerbose, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_INTFLAG(hostbased_authentication, HostbasedAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_ميلاپ) \
SSHCONF_INTFLAG(hostbased_استعمال_ڪري_name_from_packet_only, Hostbased_استعمال_ڪري_Name_From_Packet_Only, SSHCFG_ALL, 0, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRING(hostbased_accepted_algos, HostbasedAcceptedAlgorithms, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRING(hostkeyalgorithms, Host_ڪنجي_Algorithms, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(ca_sign_algorithms, CASignatureAlgorithms, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_INTFLAG(pubkey_authentication, PubkeyAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRING(pubkey_accepted_algos, PubkeyAcceptedAlgorithms, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_INTFLAG(password_authentication, PasswordAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_ميلاپ) \
SSHCONF_INTFLAG(kbd_interactive_authentication, KbdInteractiveAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_ميلاپ) \
SSHCONF_INTFLAG(permit_خالي_جايون_passwd, Permit_خالي_جايون_Passwords, SSHCFG_ALL, 0, SSHCFG_COPY_ميلاپ) \
SSHCONF_INT(compression, Compression, SSHCFG_GLOBAL, multistate_compression, SSHD_DEFAULT_COMPRESSION, SSHCFG_COPY_NONE) \
SSHCONF_INT(allow_tcp_forwarding, AllowTcpForwarding, SSHCFG_ALL, multistate_tcpfwd, FORWARD_ALLOW, SSHCFG_COPY_ميلاپ) \
SSHCONF_INT(allow_streamlocal_forwarding, Allow_وهڪرو_Local_Forwarding, SSHCFG_ALL, multistate_tcpfwd, FORWARD_ALLOW, SSHCFG_COPY_ميلاپ) \
SSHCONF_INTFLAG(allow_agent_forwarding, AllowAgentForwarding, SSHCFG_ALL, 1, SSHCFG_COPY_ميلاپ) \
SSHCONF_INTFLAG(disable_forwarding, DisableForwarding, SSHCFG_ALL, 0, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRARRAY(allow_users, انگ_allow_users, AllowUsers, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRARRAY(deny_users, انگ_deny_users, DenyUsers, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRARRAY(allow_groups, انگ_allow_groups, AllowGroups, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRARRAY(deny_groups, انگ_deny_groups, DenyGroups, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRARRAY(accept_env, انگ_accept_env, AcceptEnv, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRARRAY(setenv, انگ_setenv, سيٽ_Env, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_INT(في_ذريعو_max_startups, في_ذريعو_Max_Startups, SSHCFG_GLOBAL, عدم, وڌ_کان_وڌ_عدد, SSHCFG_COPY_NONE) \
SSHCONF_STRING(في_ذريعو_penalty_exempt, في_ذريعو_Penalty_Exempt_List, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(max_authtries, MaxAuthTries, SSHCFG_ALL, عدم, DEFAULT_AUTH_FAIL_MAX, SSHCFG_COPY_ميلاپ) \
SSHCONF_INT(max_sessions, MaxSessions, SSHCFG_ALL, عدم, DEFAULT_SESSIONS_MAX, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRING(banner, Banner, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_INTFLAG(use_dns, UseDNS, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_INT(client_alive_interval, ClientAliveInterval, SSHCFG_ALL, عدم, 0, SSHCFG_COPY_ميلاپ) \
SSHCONF_INT(client_alive_ڳڻپ_max, Client_Alive_ڳڻپ_Max, SSHCFG_ALL, عدم, 3, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRARRAY(authorized_ڪنجيون_files, انگ_authkeys_files, Authorized_ڪنجيون_File, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRING(adm_forced_command, ForceCommand, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_INTFLAG(permit_tun, PermitTunnel, SSHCFG_ALL, SSH_TUNMODE_NO, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRARRAY(permitted_opens, انگ_permitted_opens, PermitOpen, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRARRAY(permitted_listens, انگ_permitted_listens, PermitListen, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRING(chroot_directory, ChrootDirectory, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_STRARRAY(revoked_ڪنجيون_files, انگ_revoked_ڪنجيون_files, Revoked_ڪنجيون, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRING(trusted_user_ca_ڪنجيون, TrustedUserCAKeys, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRING(authorized_ڪنجيون_command, Authorized_ڪنجيون_Command, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRING(authorized_ڪنجيون_command_user, Authorized_ڪنجيون_Command_User, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRING(authorized_principals_file, AuthorizedPrincipalsFile, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRING(authorized_principals_command, AuthorizedPrincipalsCommand, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRING(authorized_principals_command_user, AuthorizedPrincipalsCommandUser, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRING(نسخو_addendum, نسخو_Addendum, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRARRAY(auth_methods, انگ_auth_methods, AuthenticationMethods, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_INT(fingerprint_hash, FingerprintHash, SSHCFG_GLOBAL, عدم, SSH_FP_HASH_DEFAULT, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(expose_userauth_info, ExposeAuthInfo, SSHCFG_ALL, 0, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRING(sk_provider, Security_ڪنجي_Provider, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(required_rsa_سائيز, RequiredRSASize, SSHCFG_ALL, عدم, SSH_RSA_MINIMUM_MODULUS_سائيز, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRARRAY(channel_timeouts, انگ_channel_timeouts, ChannelTimeout, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_INT(اڻ_استعمال_ٿيل_connection_timeout, اڻ_استعمال_ٿيل_Connection_Timeout, SSHCFG_ALL, عدم, 0, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRING(sshd_session_رستو, Sshd_Session_رستو, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(sshd_auth_رستو, Sshd_Auth_رستو, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(refuse_connection, RefuseConnection, SSHCFG_ALL, 0, SSHCFG_COPY_ميلاپ) \
SSHCONF_STRING(agent_socket_رستو, Agent_Socket_رستو, SSHCFG_ALL, SSHCFG_COPY_ميلاپ) \
SSHCONF_INT(warn_weak_crypto, WarnWeakCrypto, SSHCFG_GLOBAL, multistate_warnweakcrypto, 1, SSHCFG_COPY_NONE)

#وصف_ڪريو SSHD_CONFIG_ENTRIES_LEGACY \
SSHCONF_DEPRECATE(Server_ڪنجي_بٽ, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(ڪنجي_Regeneration_Interval, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RHostsAuthentication, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RhostsRSAAuthentication, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RSAAuthentication, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(CheckMail, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(UseLogin, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Verify_ابتو_Mapping, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(ابتو_Mapping_Check, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Authorized_ڪنجيون_File2, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(UsePrivilegeSeparation, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(KerberosTgtPassing, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(AFSTokenPassing, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Protocol, SSHCFG_GLOBAL, SSHCONF_IGNORE)

#وصف_ڪريو SSHD_CONFIG_ENTRIES_ALIASES \
SSHCONF_ALIAS(HostDSAKey, Host_ڪنجي, SSHCFG_GLOBAL) \
SSHCONF_ALIAS(Host_Based_Accepted_ڪنجي_Types, HostbasedAcceptedAlgorithms, SSHCFG_ALL) \
SSHCONF_ALIAS(Pubkey_Accepted_ڪنجي_Types, PubkeyAcceptedAlgorithms, SSHCFG_ALL) \
SSHCONF_ALIAS(DSAAuthentication, PubkeyAuthentication, SSHCFG_GLOBAL) \
SSHCONF_ALIAS(ChallengeResponseAuthentication, KbdInteractiveAuthentication, SSHCFG_ALL) \
SSHCONF_ALIAS(SKeyAuthentication, KbdInteractiveAuthentication, SSHCFG_ALL) \
SSHCONF_ALIAS(KeepAlive, TCPKeepAlive, SSHCFG_GLOBAL)

#وصف_ڪريو SSHD_CONFIG_ENTRIES_بنياد \
	SSHD_CONFIG_ENTRIES_CUSTOM \
	SSHD_CONFIG_ENTRIES_MAIN \
	SSHD_CONFIG_ENTRIES_LEGACY \
	SSHD_CONFIG_ENTRIES_ALIASES \
	SSHD_CONFIG_ENTRIES_PAM \
	SSHD_CONFIG_ENTRIES_LASTLOG

#جيڪڏهن_وصف_ٿيل USE_PAM
#وصف_ڪريو SSHD_CONFIG_ENTRIES_PAM \
SSHCONF_INTFLAG(use_pam, UsePAM, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_STRING(pam_service_name, PAMServiceName, SSHCFG_ALL, SSHCFG_COPY_ميلاپ)
#وإلا
#وصف_ڪريو SSHD_CONFIG_ENTRIES_PAM \
SSHCONF_UNSUPPORTED_INT(use_pam, UsePAM, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_STRING(pam_service_name, PAMServiceName, SSHCFG_ALL)
#جيڪڏهن_پورو

#جيڪڏهن_وصف_ٿيل DISABLE_LASTLOG
#وصف_ڪريو SSHD_CONFIG_ENTRIES_LASTLOG \
SSHCONF_UNSUPPORTED_INT(print_lastlog, Print_آخري_Log, SSHCFG_GLOBAL)
#وإلا
#وصف_ڪريو SSHD_CONFIG_ENTRIES_LASTLOG \
SSHCONF_INTFLAG(print_lastlog, Print_آخري_Log, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE)
#جيڪڏهن_پورو

/* Compile-time enabled options */
#جيڪڏهن_وصف_ٿيل KRB5

#جيڪڏهن_وصف_ٿيل USE_AFS
#وصف_ڪريو SSHD_CONFIG_KRB5_AFS \
SSHCONF_INTFLAG(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE)
#وإلا /* USE_AFS */
#وصف_ڪريو SSHD_CONFIG_KRB5_AFS \
SSHCONF_UNSUPPORTED_INT(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL)
#جيڪڏهن_پورو /* USE_AFS */

#وصف_ڪريو SSHD_CONFIG_ENTRIES_KRB5 \
SSHCONF_INTFLAG(kerberos_authentication, KerberosAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_ميلاپ) \
SSHCONF_INTFLAG(kerberos_or_local_passwd, KerberosOrLocalPasswd, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(kerberos_ticket_cleanup, KerberosTicketCleanup, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHD_CONFIG_KRB5_AFS
#وإلا /* KRB5 */
#وصف_ڪريو SSHD_CONFIG_ENTRIES_KRB5 \
SSHCONF_UNSUPPORTED_INT(kerberos_authentication, KerberosAuthentication, SSHCFG_ALL) \
SSHCONF_UNSUPPORTED_INT(kerberos_or_local_passwd, KerberosOrLocalPasswd, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(kerberos_ticket_cleanup, KerberosTicketCleanup, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL)
#جيڪڏهن_پورو /* KRB5 */

#جيڪڏهن_وصف_ٿيل GSSAPI
#وصف_ڪريو SSHD_CONFIG_ENTRIES_GSS \
SSHCONF_INTFLAG(gss_authentication, GSSAPIAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_ميلاپ) \
SSHCONF_INTFLAG(gss_cleanup_creds, GSSAPICleanupCredentials, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(gss_deleg_creds, GSSAPIDelegateCredentials, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(gss_strict_acceptor, GSSAPIStrictAcceptorCheck, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE)
#وإلا /* GSSAPI */
#وصف_ڪريو SSHD_CONFIG_ENTRIES_GSS \
SSHCONF_UNSUPPORTED_INT(gss_authentication, GSSAPIAuthentication, SSHCFG_ALL) \
SSHCONF_UNSUPPORTED_INT(gss_cleanup_creds, GSSAPICleanupCredentials, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(gss_deleg_creds, GSSAPIDelegateCredentials, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(gss_strict_acceptor, GSSAPIStrictAcceptorCheck, SSHCFG_GLOBAL)
#جيڪڏهن_پورو /* GSSAPI */

#وصف_ڪريو SSHD_CONFIG_ENTRIES \
	SSHD_CONFIG_ENTRIES_بنياد \
	SSHD_CONFIG_ENTRIES_KRB5 \
	SSHD_CONFIG_ENTRIES_GSS \

/* Macros to declare ServerOptions member variables */
#وصف_ڪريو SSHCONF_INT(var, conf, flags, ms, def, cp)	صحيح var;
#وصف_ڪريو SSHCONF_INTFLAG(var, conf, flags, def, cp)	صحيح var;
#وصف_ڪريو SSHCONF_STRING(var, conf, flags, cp)		حرف *var;
#وصف_ڪريو SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	\
	حرف **var; \
	u_int nvar;
#وصف_ڪريو SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/*خالي_جايون*/
#وصف_ڪريو SSHCONF_NONCONF(funcsuffix)			/*خالي_جايون*/
#وصف_ڪريو SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالي_جايون*/
#وصف_ڪريو SSHCONF_UNSUPPORTED_INT(var, conf, flags)	صحيح var;
#وصف_ڪريو SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	حرف *var;
#وصف_ڪريو SSHCONF_ALIAS(old, conf, flags)			/*خالي_جايون*/

تعريفنوع بنية ServerOptions {
	SSHD_CONFIG_ENTRIES
	/* Ports */
	u_int	انگ_ports;
	u_int	ports_from_cmdline;
	صحيح	ports[MAX_PORTS];	/* Port number to listen on. */
	/* ListenAddress */
	بنية queued_listenaddr *queued_listen_addrs;
	u_int	انگ_queued_listens;
	بنية listenaddr *listen_addrs;
	u_int	انگ_listen_addrs;
	/* HostKey */
	حرف   **host_ڪنجي_files;	/* Files containing host keys. */
	صحيح	*host_ڪنجي_file_userprovided; /* Key was specified by user. */
	u_int	انگ_host_ڪنجي_files;     /* Number of files for host keys. */
	/* IPQoS */
	صحيح	ip_qos_interactive;	/* IP ToS/DSCP/class for interactive */
	صحيح	ip_qos_bulk;		/* IP ToS/DSCP/class for bulk traffic */
	/* GatewayPorts, StreamLocalBindMask, StreamLocalBindUnlink */
	بنية ForwardOptions fwd_opts;	/* forwarding options */
	/* LogFacility */
	SyslogFacility log_facility;	/* Facility for system logging. */
	/* LogLevel */
	LogLevel log_level;	/* Level for system logging. */
	/* PermitUserEnvironment */
	صحيح     permit_user_env;	/* If true, read ~/.ssh/environment */
	حرف   *permit_user_env_allowlist; /* pattern-list of allowed env names */
	/* Subsystem */
	u_int انگ_subsystems;
	حرف   **subsystem_name;
	حرف   **subsystem_command;
	حرف   **subsystem_دليلون;
	/* MaxStartups */
	صحيح	max_startups_begin;
	صحيح	max_startups_شرح;
	صحيح	max_startups;
	/* PerSourceNetBlockSize */
	صحيح	في_ذريعو_masklen_ipv4;
	صحيح	في_ذريعو_masklen_ipv6;
	/* PerSourcePenalties */
	بنية في_ذريعو_penalty في_ذريعو_penalty;
	/* RekeyLimit */
	int64_t rekey_حد_بندي;
	صحيح	rekey_interval;
	/* PubkeyAuthOptions */
	صحيح	pubkey_auth_options;
	صحيح	max_pubkey_ok;
	/* Passed by config but not keyword for this */
	uint64_t timing_secret;
}       ServerOptions;
#وصف_رد SSHCONF_INT
#وصف_رد SSHCONF_INTFLAG
#وصف_رد SSHCONF_STRING
#وصف_رد SSHCONF_STRARRAY
#وصف_رد SSHCONF_CUSTOM
#وصف_رد SSHCONF_NONCONF
#وصف_رد SSHCONF_DEPRECATE
#وصف_رد SSHCONF_UNSUPPORTED_INT
#وصف_رد SSHCONF_UNSUPPORTED_STRING
#وصف_رد SSHCONF_ALIAS

/* Information about the incoming connection as used by Match */
بنية connection_info {
	ثابت حرف *user;
	صحيح user_invalid;
	ثابت حرف *host;	/* possibly resolved hostname */
	ثابت حرف *پتو;	/* remote address */
	ثابت حرف *laddress;	/* local address */
	صحيح lport;		/* local port */
	ثابت حرف *rdomain;	/* routing domain if available */
	صحيح test;		/* test mode, allow some attributes to be
				 * unspecified */
};

/* List of included files for re-exec from the parsed configuration */
بنية include_شي {
	حرف *selector;
	حرف *filename;
	بنية sshbuf *contents;
	TAILQ_ENTRY(include_شي) داخلا;
};
TAILQ_HEAD(include_list, include_شي);

فراغ	 initialize_server_options(ServerOptions *);
فراغ	 fill_default_server_options(ServerOptions *);
صحيح	 process_server_config_سٽ(ServerOptions *, حرف *, ثابت حرف *, صحيح,
	    صحيح *, بنية connection_info *, بنية include_list *includes);
فراغ	 ڀريو_server_config(ثابت حرف *, بنية sshbuf *);
فراغ	 parse_server_config(ServerOptions *, ثابت حرف *, بنية sshbuf *,
	    بنية include_list *includes, بنية connection_info *, صحيح);
فراغ	 parse_server_ميلاپ_config(ServerOptions *,
	    بنية include_list *includes, بنية connection_info *);
صحيح	 parse_server_ميلاپ_testspec(بنية connection_info *, حرف *);
فراغ	 servconf_ملايو_subsystems(ServerOptions *, ServerOptions *);
فراغ	 copy_سيٽ_server_options(ServerOptions *, ServerOptions *, صحيح);
فراغ	 dump_config(ServerOptions *);
حرف	*derelativise_رستو(ثابت حرف *);
فراغ	 servconf_جوڙيو_hostkey(ثابت حرف *, ثابت صحيح,
	    ServerOptions *, ثابت حرف *رستو, صحيح);
فراغ	 servconf_جوڙيو_hostcert(ثابت حرف *, ثابت صحيح,
	    ServerOptions *, ثابت حرف *رستو);

صحيح	 serialise_server_options(ثابت ServerOptions *, بنية sshbuf **);
صحيح	 deserialise_server_options(بنية sshbuf *, ServerOptions *);
فراغ	 free_server_options(ServerOptions *);

#جيڪڏهن_پورو				/* SERVCONF_H */
