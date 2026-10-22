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

#جے_بنا_تعریف SERVCONF_H
#تعریف_کرو SERVCONF_H

#ضمن <sys/queue.h>

بنية sshbuf;

#تعریف_کرو MAX_PORTS		256	/* Max # ports. */

/* permit_root_login */
#تعریف_کرو	PERMIT_NOT_سیٹ		-1
#تعریف_کرو	PERMIT_NO		0
#تعریف_کرو	PERMIT_FORCED_ONLY	1
#تعریف_کرو	PERMIT_NO_PASSWD	2
#تعریف_کرو	PERMIT_YES		3

/* PermitOpen */
#تعریف_کرو PERMITOPEN_ANY		0
#تعریف_کرو PERMITOPEN_NONE		-2

/* IgnoreRhosts */
#تعریف_کرو IGNORE_RHOSTS_NO	0
#تعریف_کرو IGNORE_RHOSTS_YES	1
#تعریف_کرو IGNORE_RHOSTS_SHOSTS	2

#تعریف_کرو DEFAULT_AUTH_FAIL_MAX	6	/* Default for MaxAuthTries */
#تعریف_کرو DEFAULT_SESSIONS_MAX	10	/* Default for MaxSessions */

/* Magic name for internal sftp-server */
#تعریف_کرو اندرونی_SFTP_NAME	"internal-sftp"

/* PubkeyAuthOptions flags */
#تعریف_کرو PUBKEYAUTH_TOUCH_REQUIRED	(1)
#تعریف_کرو PUBKEYAUTH_VERIFY_REQUIRED	(1<<1)

/* Various defaults */
#تعریف_کرو SSHD_DEFAULT_LOGIN_GRACE_ویلا	120
#تعریف_کرو SSHD_DEFAULT_X11_DISPLAY_وتھ	10
#جے_تعریف_شدہ WITH_ZLIB
#تعریف_کرو SSHD_DEFAULT_COMPRESSION	COMP_DELAYED
#وإلا
#تعریف_کرو SSHD_DEFAULT_COMPRESSION	COMP_NONE
#جے_انت

/* TCPKeepAlive flags */
#تعریف_کرو SSH_KEEPALIVES_OFF		0
#تعریف_کرو SSH_KEEPALIVES_TRANSPORT	1
#تعریف_کرو SSH_KEEPALIVES_ALL		2

بنية ssh;

/*
 * Used to store addresses from ListenAddr directives. These may be
 * incomplete, as they may specify addresses that need to be merged
 * with any ports requested by ListenPort.
 */
بنية queued_listenaddr {
	حرف *addr;
	صحيح پورٹ; /* <=0 if unspecified */
	حرف *rdomain;
};

/* Resolved listen addresses, grouped by optional routing domain */
بنية listenaddr {
	حرف *rdomain;
	بنية addrinfo *addrs;
};

#تعریف_کرو فی_سروت_PENALTY_حد_توں_ودھ_DENY_ALL	1
#تعریف_کرو فی_سروت_PENALTY_حد_توں_ودھ_PERMISSIVE	2
بنية فی_سروت_penalty {
	صحيح	enabled;
	صحيح	max_sources4;
	صحيح	max_sources6;
	صحيح	حد_توں_ودھ_منوال;
	صحيح	حد_توں_ودھ_mode6;
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
#تعریف_کرو SSHCFG_COPY_NONE(action)
#تعریف_کرو SSHCFG_COPY_میل(action)	action
#تعریف_کرو SSHCFG_COPY_MANUAL(action)

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
#تعریف_کرو SSHD_CONFIG_ENTRIES_CUSTOM \
SSHCONF_CUSTOM(پورٹ_2, پورٹ, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Listen_پتہ, listenaddress, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Host_کلید, hostkeyfile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(IPQoS, ipqos, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_CUSTOM(GatewayPorts, gatewayports, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_CUSTOM(دھارا_Local_Bind_نقاب, streamlocalbindmask, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_CUSTOM(دھارا_Local_Bind_Unlink, streamlocalbindunlink, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_CUSTOM(SyslogFacility, logfacility, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(LogLevel, loglevel, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_CUSTOM(PermitUserEnvironment, permituserenv, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Subsystem, subsystem, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_CUSTOM(MaxStartups, maxstartups, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(فی_سروت_Net_بلاک_ناپ, persourcenetblocksize, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(فی_سروت_Penalties, persourcepenalties, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Rekey_حد_بندی, rekeylimit, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_CUSTOM(PubkeyAuthOptions, pubkey_auth_options, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_NONCONF(timingsecret)

#تعریف_کرو SSHD_CONFIG_ENTRIES_MAIN \
SSHCONF_INT(پتہ_family, پتہ_Family, SSHCFG_GLOBAL, multistate_addressfamily, AF_UNSPEC, SSHCFG_COPY_NONE) \
SSHCONF_STRING(routing_domain, RDomain, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_STRARRAY(host_cert_files, عدد_host_cert_files, HostCertificate, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(host_کلید_agent, Host_کلید_Agent, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(pid_file, PidFile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(moduli_file, ModuliFile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(login_grace_ویلا, Login_Grace_ویلا, SSHCFG_GLOBAL, عدم, SSHD_DEFAULT_LOGIN_GRACE_ویلا, SSHCFG_COPY_NONE) \
SSHCONF_INT(permit_جڑ_login, Permit_جڑ_Login, SSHCFG_ALL, multistate_permitrootlogin, PERMIT_NO_PASSWD, SSHCFG_COPY_میل) \
SSHCONF_INT(ignore_rhosts, IgnoreRhosts, SSHCFG_ALL, multistate_ignore_rhosts, 1, SSHCFG_COPY_میل) \
SSHCONF_INTFLAG(ignore_user_معلوم_hosts, Ignore_User_معلوم_Hosts, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(print_motd, PrintMotd, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(x11_forwarding, X11Forwarding, SSHCFG_ALL, 0, SSHCFG_COPY_میل) \
SSHCONF_INT(x11_display_وتھ, X11_Display_وتھ, SSHCFG_ALL, عدم, SSHD_DEFAULT_X11_DISPLAY_وتھ, SSHCFG_COPY_میل) \
SSHCONF_INTFLAG(x11_use_localhost, X11UseLocalhost, SSHCFG_ALL, 1, SSHCFG_COPY_میل) \
SSHCONF_STRING(xauth_location, XAuthLocation, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(permit_tty, PermitTTY, SSHCFG_ALL, 1, SSHCFG_COPY_میل) \
SSHCONF_INTFLAG(permit_user_rc, PermitUserRC, SSHCFG_ALL, 1, SSHCFG_COPY_میل) \
SSHCONF_INTFLAG(strict_modes, StrictModes, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(tcp_keep_alive, TCPKeepAlive, SSHCFG_GLOBAL, SSH_KEEPALIVES_TRANSPORT, SSHCFG_COPY_NONE) \
SSHCONF_STRING(ciphers, Ciphers, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(macs, Macs, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(kex_algorithms, KexAlgorithms, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRARRAY(log_verbose, عدد_log_verbose, LogVerbose, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_INTFLAG(hostbased_authentication, HostbasedAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_میل) \
SSHCONF_INTFLAG(hostbased_ورتدا_name_from_packet_only, Hostbased_ورتدا_Name_From_Packet_Only, SSHCFG_ALL, 0, SSHCFG_COPY_میل) \
SSHCONF_STRING(hostbased_accepted_algos, HostbasedAcceptedAlgorithms, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_STRING(hostkeyalgorithms, Host_کلید_Algorithms, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(ca_sign_algorithms, CASignatureAlgorithms, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_INTFLAG(pubkey_authentication, PubkeyAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_میل) \
SSHCONF_STRING(pubkey_accepted_algos, PubkeyAcceptedAlgorithms, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_INTFLAG(password_authentication, PasswordAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_میل) \
SSHCONF_INTFLAG(kbd_interactive_authentication, KbdInteractiveAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_میل) \
SSHCONF_INTFLAG(permit_خالی_تھاواں_passwd, Permit_خالی_تھاواں_Passwords, SSHCFG_ALL, 0, SSHCFG_COPY_میل) \
SSHCONF_INT(compression, Compression, SSHCFG_GLOBAL, multistate_compression, SSHD_DEFAULT_COMPRESSION, SSHCFG_COPY_NONE) \
SSHCONF_INT(allow_tcp_forwarding, AllowTcpForwarding, SSHCFG_ALL, multistate_tcpfwd, FORWARD_ALLOW, SSHCFG_COPY_میل) \
SSHCONF_INT(allow_streamlocal_forwarding, Allow_دھارا_Local_Forwarding, SSHCFG_ALL, multistate_tcpfwd, FORWARD_ALLOW, SSHCFG_COPY_میل) \
SSHCONF_INTFLAG(allow_agent_forwarding, AllowAgentForwarding, SSHCFG_ALL, 1, SSHCFG_COPY_میل) \
SSHCONF_INTFLAG(disable_forwarding, DisableForwarding, SSHCFG_ALL, 0, SSHCFG_COPY_میل) \
SSHCONF_STRARRAY(allow_users, عدد_allow_users, AllowUsers, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_STRARRAY(deny_users, عدد_deny_users, DenyUsers, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_STRARRAY(allow_groups, عدد_allow_groups, AllowGroups, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_STRARRAY(deny_groups, عدد_deny_groups, DenyGroups, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_STRARRAY(accept_env, عدد_accept_env, AcceptEnv, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_STRARRAY(setenv, عدد_setenv, سیٹ_Env, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_INT(فی_سروت_max_startups, فی_سروت_Max_Startups, SSHCFG_GLOBAL, عدم, ودھ_توں_ودھ_عدد, SSHCFG_COPY_NONE) \
SSHCONF_STRING(فی_سروت_penalty_exempt, فی_سروت_Penalty_Exempt_List, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(max_authtries, MaxAuthTries, SSHCFG_ALL, عدم, DEFAULT_AUTH_FAIL_MAX, SSHCFG_COPY_میل) \
SSHCONF_INT(max_sessions, MaxSessions, SSHCFG_ALL, عدم, DEFAULT_SESSIONS_MAX, SSHCFG_COPY_میل) \
SSHCONF_STRING(banner, Banner, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_INTFLAG(use_dns, UseDNS, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_INT(client_alive_interval, ClientAliveInterval, SSHCFG_ALL, عدم, 0, SSHCFG_COPY_میل) \
SSHCONF_INT(client_alive_گنتی_max, Client_Alive_گنتی_Max, SSHCFG_ALL, عدم, 3, SSHCFG_COPY_میل) \
SSHCONF_STRARRAY(authorized_کلیدیں_files, عدد_authkeys_files, Authorized_کلیدیں_File, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_STRING(adm_forced_command, ForceCommand, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_INTFLAG(permit_tun, PermitTunnel, SSHCFG_ALL, SSH_TUNMODE_NO, SSHCFG_COPY_میل) \
SSHCONF_STRARRAY(permitted_opens, عدد_permitted_opens, PermitOpen, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_STRARRAY(permitted_listens, عدد_permitted_listens, PermitListen, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_STRING(chroot_directory, ChrootDirectory, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_STRARRAY(revoked_کلیدیں_files, عدد_revoked_کلیدیں_files, Revoked_کلیدیں, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_STRING(trusted_user_ca_کلیدیں, TrustedUserCAKeys, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_STRING(authorized_کلیدیں_command, Authorized_کلیدیں_Command, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_STRING(authorized_کلیدیں_command_user, Authorized_کلیدیں_Command_User, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_STRING(authorized_principals_file, AuthorizedPrincipalsFile, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_STRING(authorized_principals_command, AuthorizedPrincipalsCommand, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_STRING(authorized_principals_command_user, AuthorizedPrincipalsCommandUser, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_STRING(نسخہ_addendum, نسخہ_Addendum, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRARRAY(auth_methods, عدد_auth_methods, AuthenticationMethods, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_INT(fingerprint_hash, FingerprintHash, SSHCFG_GLOBAL, عدم, SSH_FP_HASH_DEFAULT, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(expose_userauth_info, ExposeAuthInfo, SSHCFG_ALL, 0, SSHCFG_COPY_میل) \
SSHCONF_STRING(sk_provider, Security_کلید_Provider, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(required_rsa_ناپ, RequiredRSASize, SSHCFG_ALL, عدم, SSH_RSA_MINIMUM_MODULUS_ناپ, SSHCFG_COPY_میل) \
SSHCONF_STRARRAY(channel_timeouts, عدد_channel_timeouts, ChannelTimeout, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_INT(بن_ورتیا_connection_timeout, بن_ورتیا_Connection_Timeout, SSHCFG_ALL, عدم, 0, SSHCFG_COPY_میل) \
SSHCONF_STRING(sshd_session_رستہ, Sshd_Session_رستہ, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(sshd_auth_رستہ, Sshd_Auth_رستہ, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(refuse_connection, RefuseConnection, SSHCFG_ALL, 0, SSHCFG_COPY_میل) \
SSHCONF_STRING(agent_socket_رستہ, Agent_Socket_رستہ, SSHCFG_ALL, SSHCFG_COPY_میل) \
SSHCONF_INT(warn_weak_crypto, WarnWeakCrypto, SSHCFG_GLOBAL, multistate_warnweakcrypto, 1, SSHCFG_COPY_NONE)

#تعریف_کرو SSHD_CONFIG_ENTRIES_LEGACY \
SSHCONF_DEPRECATE(Server_کلید_بٹ, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(کلید_Regeneration_Interval, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RHostsAuthentication, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RhostsRSAAuthentication, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RSAAuthentication, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(CheckMail, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(UseLogin, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Verify_الٹ_Mapping, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(الٹ_Mapping_Check, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Authorized_کلیدیں_File2, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(UsePrivilegeSeparation, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(KerberosTgtPassing, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(AFSTokenPassing, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Protocol, SSHCFG_GLOBAL, SSHCONF_IGNORE)

#تعریف_کرو SSHD_CONFIG_ENTRIES_ALIASES \
SSHCONF_ALIAS(HostDSAKey, Host_کلید, SSHCFG_GLOBAL) \
SSHCONF_ALIAS(Host_Based_Accepted_کلید_Types, HostbasedAcceptedAlgorithms, SSHCFG_ALL) \
SSHCONF_ALIAS(Pubkey_Accepted_کلید_Types, PubkeyAcceptedAlgorithms, SSHCFG_ALL) \
SSHCONF_ALIAS(DSAAuthentication, PubkeyAuthentication, SSHCFG_GLOBAL) \
SSHCONF_ALIAS(ChallengeResponseAuthentication, KbdInteractiveAuthentication, SSHCFG_ALL) \
SSHCONF_ALIAS(SKeyAuthentication, KbdInteractiveAuthentication, SSHCFG_ALL) \
SSHCONF_ALIAS(KeepAlive, TCPKeepAlive, SSHCFG_GLOBAL)

#تعریف_کرو SSHD_CONFIG_ENTRIES_ادھار \
	SSHD_CONFIG_ENTRIES_CUSTOM \
	SSHD_CONFIG_ENTRIES_MAIN \
	SSHD_CONFIG_ENTRIES_LEGACY \
	SSHD_CONFIG_ENTRIES_ALIASES \
	SSHD_CONFIG_ENTRIES_PAM \
	SSHD_CONFIG_ENTRIES_LASTLOG

#جے_تعریف_شدہ USE_PAM
#تعریف_کرو SSHD_CONFIG_ENTRIES_PAM \
SSHCONF_INTFLAG(use_pam, UsePAM, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_STRING(pam_service_name, PAMServiceName, SSHCFG_ALL, SSHCFG_COPY_میل)
#وإلا
#تعریف_کرو SSHD_CONFIG_ENTRIES_PAM \
SSHCONF_UNSUPPORTED_INT(use_pam, UsePAM, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_STRING(pam_service_name, PAMServiceName, SSHCFG_ALL)
#جے_انت

#جے_تعریف_شدہ DISABLE_LASTLOG
#تعریف_کرو SSHD_CONFIG_ENTRIES_LASTLOG \
SSHCONF_UNSUPPORTED_INT(print_lastlog, Print_آخری_Log, SSHCFG_GLOBAL)
#وإلا
#تعریف_کرو SSHD_CONFIG_ENTRIES_LASTLOG \
SSHCONF_INTFLAG(print_lastlog, Print_آخری_Log, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE)
#جے_انت

/* Compile-time enabled options */
#جے_تعریف_شدہ KRB5

#جے_تعریف_شدہ USE_AFS
#تعریف_کرو SSHD_CONFIG_KRB5_AFS \
SSHCONF_INTFLAG(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE)
#وإلا /* USE_AFS */
#تعریف_کرو SSHD_CONFIG_KRB5_AFS \
SSHCONF_UNSUPPORTED_INT(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL)
#جے_انت /* USE_AFS */

#تعریف_کرو SSHD_CONFIG_ENTRIES_KRB5 \
SSHCONF_INTFLAG(kerberos_authentication, KerberosAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_میل) \
SSHCONF_INTFLAG(kerberos_or_local_passwd, KerberosOrLocalPasswd, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(kerberos_ticket_cleanup, KerberosTicketCleanup, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHD_CONFIG_KRB5_AFS
#وإلا /* KRB5 */
#تعریف_کرو SSHD_CONFIG_ENTRIES_KRB5 \
SSHCONF_UNSUPPORTED_INT(kerberos_authentication, KerberosAuthentication, SSHCFG_ALL) \
SSHCONF_UNSUPPORTED_INT(kerberos_or_local_passwd, KerberosOrLocalPasswd, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(kerberos_ticket_cleanup, KerberosTicketCleanup, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL)
#جے_انت /* KRB5 */

#جے_تعریف_شدہ GSSAPI
#تعریف_کرو SSHD_CONFIG_ENTRIES_GSS \
SSHCONF_INTFLAG(gss_authentication, GSSAPIAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_میل) \
SSHCONF_INTFLAG(gss_cleanup_creds, GSSAPICleanupCredentials, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(gss_deleg_creds, GSSAPIDelegateCredentials, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(gss_strict_acceptor, GSSAPIStrictAcceptorCheck, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE)
#وإلا /* GSSAPI */
#تعریف_کرو SSHD_CONFIG_ENTRIES_GSS \
SSHCONF_UNSUPPORTED_INT(gss_authentication, GSSAPIAuthentication, SSHCFG_ALL) \
SSHCONF_UNSUPPORTED_INT(gss_cleanup_creds, GSSAPICleanupCredentials, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(gss_deleg_creds, GSSAPIDelegateCredentials, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(gss_strict_acceptor, GSSAPIStrictAcceptorCheck, SSHCFG_GLOBAL)
#جے_انت /* GSSAPI */

#تعریف_کرو SSHD_CONFIG_ENTRIES \
	SSHD_CONFIG_ENTRIES_ادھار \
	SSHD_CONFIG_ENTRIES_KRB5 \
	SSHD_CONFIG_ENTRIES_GSS \

/* Macros to declare ServerOptions member variables */
#تعریف_کرو SSHCONF_INT(var, conf, flags, ms, def, cp)	صحيح var;
#تعریف_کرو SSHCONF_INTFLAG(var, conf, flags, def, cp)	صحيح var;
#تعریف_کرو SSHCONF_STRING(var, conf, flags, cp)		حرف *var;
#تعریف_کرو SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	\
	حرف **var; \
	u_int nvar;
#تعریف_کرو SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/*خالی_تھاواں*/
#تعریف_کرو SSHCONF_NONCONF(funcsuffix)			/*خالی_تھاواں*/
#تعریف_کرو SSHCONF_DEPRECATE(conf, flags, opcode)		/*خالی_تھاواں*/
#تعریف_کرو SSHCONF_UNSUPPORTED_INT(var, conf, flags)	صحيح var;
#تعریف_کرو SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	حرف *var;
#تعریف_کرو SSHCONF_ALIAS(old, conf, flags)			/*خالی_تھاواں*/

تعريفنوع بنية ServerOptions {
	SSHD_CONFIG_ENTRIES
	/* Ports */
	u_int	عدد_ports;
	u_int	ports_from_cmdline;
	صحيح	ports[MAX_PORTS];	/* Port number to listen on. */
	/* ListenAddress */
	بنية queued_listenaddr *queued_listen_addrs;
	u_int	عدد_queued_listens;
	بنية listenaddr *listen_addrs;
	u_int	عدد_listen_addrs;
	/* HostKey */
	حرف   **host_کلید_files;	/* Files containing host keys. */
	صحيح	*host_کلید_file_userprovided; /* Key was specified by user. */
	u_int	عدد_host_کلید_files;     /* Number of files for host keys. */
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
	u_int عدد_subsystems;
	حرف   **subsystem_name;
	حرف   **subsystem_command;
	حرف   **subsystem_دلیلاں;
	/* MaxStartups */
	صحيح	max_startups_begin;
	صحيح	max_startups_شرح;
	صحيح	max_startups;
	/* PerSourceNetBlockSize */
	صحيح	فی_سروت_masklen_ipv4;
	صحيح	فی_سروت_masklen_ipv6;
	/* PerSourcePenalties */
	بنية فی_سروت_penalty فی_سروت_penalty;
	/* RekeyLimit */
	int64_t rekey_حد_بندی;
	صحيح	rekey_interval;
	/* PubkeyAuthOptions */
	صحيح	pubkey_auth_options;
	صحيح	max_pubkey_ok;
	/* Passed by config but not keyword for this */
	uint64_t timing_secret;
}       ServerOptions;
#تعریف_رد SSHCONF_INT
#تعریف_رد SSHCONF_INTFLAG
#تعریف_رد SSHCONF_STRING
#تعریف_رد SSHCONF_STRARRAY
#تعریف_رد SSHCONF_CUSTOM
#تعریف_رد SSHCONF_NONCONF
#تعریف_رد SSHCONF_DEPRECATE
#تعریف_رد SSHCONF_UNSUPPORTED_INT
#تعریف_رد SSHCONF_UNSUPPORTED_STRING
#تعریف_رد SSHCONF_ALIAS

/* Information about the incoming connection as used by Match */
بنية connection_info {
	ثابت حرف *user;
	صحيح user_invalid;
	ثابت حرف *host;	/* possibly resolved hostname */
	ثابت حرف *پتہ;	/* remote address */
	ثابت حرف *laddress;	/* local address */
	صحيح lport;		/* local port */
	ثابت حرف *rdomain;	/* routing domain if available */
	صحيح test;		/* test mode, allow some attributes to be
				 * unspecified */
};

/* List of included files for re-exec from the parsed configuration */
بنية include_شے {
	حرف *selector;
	حرف *filename;
	بنية sshbuf *contents;
	TAILQ_ENTRY(include_شے) اندراج;
};
TAILQ_HEAD(include_list, include_شے);

فراغ	 initialize_server_options(ServerOptions *);
فراغ	 fill_default_server_options(ServerOptions *);
صحيح	 process_server_config_سطر(ServerOptions *, حرف *, ثابت حرف *, صحيح,
	    صحيح *, بنية connection_info *, بنية include_list *includes);
فراغ	 لدو_server_config(ثابت حرف *, بنية sshbuf *);
فراغ	 parse_server_config(ServerOptions *, ثابت حرف *, بنية sshbuf *,
	    بنية include_list *includes, بنية connection_info *, صحيح);
فراغ	 parse_server_میل_config(ServerOptions *,
	    بنية include_list *includes, بنية connection_info *);
صحيح	 parse_server_میل_testspec(بنية connection_info *, حرف *);
فراغ	 servconf_ملاؤ_subsystems(ServerOptions *, ServerOptions *);
فراغ	 copy_سیٹ_server_options(ServerOptions *, ServerOptions *, صحيح);
فراغ	 dump_config(ServerOptions *);
حرف	*derelativise_رستہ(ثابت حرف *);
فراغ	 servconf_جوڑو_hostkey(ثابت حرف *, ثابت صحيح,
	    ServerOptions *, ثابت حرف *رستہ, صحيح);
فراغ	 servconf_جوڑو_hostcert(ثابت حرف *, ثابت صحيح,
	    ServerOptions *, ثابت حرف *رستہ);

صحيح	 serialise_server_options(ثابت ServerOptions *, بنية sshbuf **);
صحيح	 deserialise_server_options(بنية sshbuf *, ServerOptions *);
فراغ	 free_server_options(ServerOptions *);

#جے_انت				/* SERVCONF_H */
