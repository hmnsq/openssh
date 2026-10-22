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

#यदि_अपरिभाषितम् SERVCONF_H
#परिभाषय SERVCONF_H

#अन्तर्भाव <sys/queue.h>

संरचना sshbuf;

#परिभाषय MAX_PORTS		256	/* Max # ports. */

/* permit_root_login */
#परिभाषय	PERMIT_NOT_समुच्चयः		-1
#परिभाषय	PERMIT_NO		0
#परिभाषय	PERMIT_FORCED_ONLY	1
#परिभाषय	PERMIT_NO_PASSWD	2
#परिभाषय	PERMIT_YES		3

/* PermitOpen */
#परिभाषय PERMITOPEN_ANY		0
#परिभाषय PERMITOPEN_NONE		-2

/* IgnoreRhosts */
#परिभाषय IGNORE_RHOSTS_NO	0
#परिभाषय IGNORE_RHOSTS_YES	1
#परिभाषय IGNORE_RHOSTS_SHOSTS	2

#परिभाषय DEFAULT_AUTH_FAIL_MAX	6	/* Default for MaxAuthTries */
#परिभाषय DEFAULT_SESSIONS_MAX	10	/* Default for MaxSessions */

/* Magic name for internal sftp-server */
#परिभाषय आन्तरिकम्_SFTP_NAME	"internal-sftp"

/* PubkeyAuthOptions flags */
#परिभाषय PUBKEYAUTH_TOUCH_REQUIRED	(1)
#परिभाषय PUBKEYAUTH_VERIFY_REQUIRED	(1<<1)

/* Various defaults */
#परिभाषय SSHD_DEFAULT_LOGIN_GRACE_TIME	120
#परिभाषय SSHD_DEFAULT_X11_DISPLAY_विस्थापनम्	10
#यदि_परिभाषितम् WITH_ZLIB
#परिभाषय SSHD_DEFAULT_COMPRESSION	COMP_DELAYED
#अन्यथा
#परिभाषय SSHD_DEFAULT_COMPRESSION	COMP_NONE
#यदि_अन्तः

/* TCPKeepAlive flags */
#परिभाषय SSH_KEEPALIVES_OFF		0
#परिभाषय SSH_KEEPALIVES_TRANSPORT	1
#परिभाषय SSH_KEEPALIVES_ALL		2

संरचना ssh;

/*
 * Used to store addresses from ListenAddr directives. These may be
 * incomplete, as they may specify addresses that need to be merged
 * with any ports requested by ListenPort.
 */
संरचना queued_listenaddr {
	वर्ण *addr;
	पूर्णाङ्क पत्तनम्; /* <=0 if unspecified */
	वर्ण *rdomain;
};

/* Resolved listen addresses, grouped by optional routing domain */
संरचना listenaddr {
	वर्ण *rdomain;
	संरचना addrinfo *addrs;
};

#परिभाषय प्रत्येकम्_SOURCE_PENALTY_अतिप्रवाहः_DENY_ALL	1
#परिभाषय प्रत्येकम्_SOURCE_PENALTY_अतिप्रवाहः_PERMISSIVE	2
संरचना प्रत्येकम्_source_penalty {
	पूर्णाङ्क	enabled;
	पूर्णाङ्क	max_sources4;
	पूर्णाङ्क	max_sources6;
	पूर्णाङ्क	अतिप्रवाहः_बहुलकम्;
	पूर्णाङ्क	अतिप्रवाहः_mode6;
	द्विगुण	penalty_crash;
	द्विगुण	penalty_grace;
	द्विगुण	penalty_authfail;
	द्विगुण	penalty_invaliduser;
	द्विगुण	penalty_noauth;
	द्विगुण	penalty_refuseconnection;
	द्विगुण	penalty_max;
	द्विगुण	penalty_min;
};

/* Options for whether config entries are copied after Match processing */
#परिभाषय SSHCFG_COPY_NONE(action)
#परिभाषय SSHCFG_COPY_मेलनम्(action)	action
#परिभाषय SSHCFG_COPY_MANUAL(action)

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
#परिभाषय SSHD_CONFIG_ENTRIES_CUSTOM \
SSHCONF_CUSTOM(पत्तनम्_2, पत्तनम्, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Listen_स्थानाङ्कः, listenaddress, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Host_कुञ्चिका, hostkeyfile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(IPQoS, ipqos, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_CUSTOM(GatewayPorts, gatewayports, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_CUSTOM(प्रवाहः_Local_Bind_आवरणम्, streamlocalbindmask, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_CUSTOM(प्रवाहः_Local_Bind_Unlink, streamlocalbindunlink, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_CUSTOM(SyslogFacility, logfacility, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(LogLevel, loglevel, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_CUSTOM(PermitUserEnvironment, permituserenv, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Subsystem, subsystem, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_CUSTOM(MaxStartups, maxstartups, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(प्रत्येकम्_Source_Net_खण्डम्_आकार, persourcenetblocksize, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(प्रत्येकम्_Source_Penalties, persourcepenalties, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_CUSTOM(Rekey_सीमा, rekeylimit, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_CUSTOM(PubkeyAuthOptions, pubkey_auth_options, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_NONCONF(timingsecret)

#परिभाषय SSHD_CONFIG_ENTRIES_MAIN \
SSHCONF_INT(स्थानाङ्कः_family, स्थानाङ्कः_Family, SSHCFG_GLOBAL, multistate_addressfamily, AF_UNSPEC, SSHCFG_COPY_NONE) \
SSHCONF_STRING(routing_domain, RDomain, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRARRAY(host_cert_files, अङ्कः_host_cert_files, HostCertificate, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(host_कुञ्चिका_agent, Host_कुञ्चिका_Agent, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(pid_file, PidFile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(moduli_file, ModuliFile, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(login_grace_time, LoginGraceTime, SSHCFG_GLOBAL, रिक्त, SSHD_DEFAULT_LOGIN_GRACE_TIME, SSHCFG_COPY_NONE) \
SSHCONF_INT(permit_मूलम्_login, Permit_मूलम्_Login, SSHCFG_ALL, multistate_permitrootlogin, PERMIT_NO_PASSWD, SSHCFG_COPY_मेलनम्) \
SSHCONF_INT(ignore_rhosts, IgnoreRhosts, SSHCFG_ALL, multistate_ignore_rhosts, 1, SSHCFG_COPY_मेलनम्) \
SSHCONF_INTFLAG(ignore_user_ज्ञातम्_hosts, Ignore_User_ज्ञातम्_Hosts, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(print_motd, PrintMotd, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(x11_forwarding, X11Forwarding, SSHCFG_ALL, 0, SSHCFG_COPY_मेलनम्) \
SSHCONF_INT(x11_display_विस्थापनम्, X11_Display_विस्थापनम्, SSHCFG_ALL, रिक्त, SSHD_DEFAULT_X11_DISPLAY_विस्थापनम्, SSHCFG_COPY_मेलनम्) \
SSHCONF_INTFLAG(x11_use_localhost, X11UseLocalhost, SSHCFG_ALL, 1, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRING(xauth_location, XAuthLocation, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(permit_tty, PermitTTY, SSHCFG_ALL, 1, SSHCFG_COPY_मेलनम्) \
SSHCONF_INTFLAG(permit_user_rc, PermitUserRC, SSHCFG_ALL, 1, SSHCFG_COPY_मेलनम्) \
SSHCONF_INTFLAG(strict_modes, StrictModes, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(tcp_keep_alive, TCPKeepAlive, SSHCFG_GLOBAL, SSH_KEEPALIVES_TRANSPORT, SSHCFG_COPY_NONE) \
SSHCONF_STRING(ciphers, Ciphers, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(macs, Macs, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(kex_algorithms, KexAlgorithms, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRARRAY(log_verbose, अङ्कः_log_verbose, LogVerbose, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_INTFLAG(hostbased_authentication, HostbasedAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_मेलनम्) \
SSHCONF_INTFLAG(hostbased_उपयुङ्क्ते_name_from_packet_only, Hostbased_उपयुङ्क्ते_Name_From_Packet_Only, SSHCFG_ALL, 0, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRING(hostbased_accepted_algos, HostbasedAcceptedAlgorithms, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRING(hostkeyalgorithms, Host_कुञ्चिका_Algorithms, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(ca_sign_algorithms, CASignatureAlgorithms, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_INTFLAG(pubkey_authentication, PubkeyAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRING(pubkey_accepted_algos, PubkeyAcceptedAlgorithms, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_INTFLAG(password_authentication, PasswordAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_मेलनम्) \
SSHCONF_INTFLAG(kbd_interactive_authentication, KbdInteractiveAuthentication, SSHCFG_ALL, 1, SSHCFG_COPY_मेलनम्) \
SSHCONF_INTFLAG(permit_रिक्तानि_passwd, Permit_रिक्तानि_Passwords, SSHCFG_ALL, 0, SSHCFG_COPY_मेलनम्) \
SSHCONF_INT(compression, Compression, SSHCFG_GLOBAL, multistate_compression, SSHD_DEFAULT_COMPRESSION, SSHCFG_COPY_NONE) \
SSHCONF_INT(allow_tcp_forwarding, AllowTcpForwarding, SSHCFG_ALL, multistate_tcpfwd, FORWARD_ALLOW, SSHCFG_COPY_मेलनम्) \
SSHCONF_INT(allow_streamlocal_forwarding, Allow_प्रवाहः_Local_Forwarding, SSHCFG_ALL, multistate_tcpfwd, FORWARD_ALLOW, SSHCFG_COPY_मेलनम्) \
SSHCONF_INTFLAG(allow_agent_forwarding, AllowAgentForwarding, SSHCFG_ALL, 1, SSHCFG_COPY_मेलनम्) \
SSHCONF_INTFLAG(disable_forwarding, DisableForwarding, SSHCFG_ALL, 0, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRARRAY(allow_users, अङ्कः_allow_users, AllowUsers, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRARRAY(deny_users, अङ्कः_deny_users, DenyUsers, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRARRAY(allow_groups, अङ्कः_allow_groups, AllowGroups, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRARRAY(deny_groups, अङ्कः_deny_groups, DenyGroups, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRARRAY(accept_env, अङ्कः_accept_env, AcceptEnv, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRARRAY(setenv, अङ्कः_setenv, समुच्चयः_Env, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_INT(प्रत्येकम्_source_max_startups, प्रत्येकम्_Source_Max_Startups, SSHCFG_GLOBAL, रिक्त, अधिकतम_पूर्णाङ्कः, SSHCFG_COPY_NONE) \
SSHCONF_STRING(प्रत्येकम्_source_penalty_exempt, प्रत्येकम्_Source_Penalty_Exempt_List, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(max_authtries, MaxAuthTries, SSHCFG_ALL, रिक्त, DEFAULT_AUTH_FAIL_MAX, SSHCFG_COPY_मेलनम्) \
SSHCONF_INT(max_sessions, MaxSessions, SSHCFG_ALL, रिक्त, DEFAULT_SESSIONS_MAX, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRING(banner, Banner, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_INTFLAG(use_dns, UseDNS, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_INT(client_alive_interval, ClientAliveInterval, SSHCFG_ALL, रिक्त, 0, SSHCFG_COPY_मेलनम्) \
SSHCONF_INT(client_alive_गणनम्_max, Client_Alive_गणनम्_Max, SSHCFG_ALL, रिक्त, 3, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRARRAY(authorized_कुञ्चिकाः_files, अङ्कः_authkeys_files, Authorized_कुञ्चिकाः_File, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRING(adm_forced_command, ForceCommand, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_INTFLAG(permit_tun, PermitTunnel, SSHCFG_ALL, SSH_TUNMODE_NO, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRARRAY(permitted_opens, अङ्कः_permitted_opens, PermitOpen, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRARRAY(permitted_listens, अङ्कः_permitted_listens, PermitListen, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRING(chroot_directory, ChrootDirectory, SSHCFG_ALL, SSHCFG_COPY_MANUAL) \
SSHCONF_STRARRAY(revoked_कुञ्चिकाः_files, अङ्कः_revoked_कुञ्चिकाः_files, Revoked_कुञ्चिकाः, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRING(trusted_user_ca_कुञ्चिकाः, TrustedUserCAKeys, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRING(authorized_कुञ्चिकाः_command, Authorized_कुञ्चिकाः_Command, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRING(authorized_कुञ्चिकाः_command_user, Authorized_कुञ्चिकाः_Command_User, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRING(authorized_principals_file, AuthorizedPrincipalsFile, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRING(authorized_principals_command, AuthorizedPrincipalsCommand, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRING(authorized_principals_command_user, AuthorizedPrincipalsCommandUser, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRING(संस्करणम्_addendum, संस्करणम्_Addendum, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRARRAY(auth_methods, अङ्कः_auth_methods, AuthenticationMethods, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_INT(fingerprint_hash, FingerprintHash, SSHCFG_GLOBAL, रिक्त, SSH_FP_HASH_DEFAULT, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(expose_userauth_info, ExposeAuthInfo, SSHCFG_ALL, 0, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRING(sk_provider, Security_कुञ्चिका_Provider, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INT(required_rsa_आकार, RequiredRSASize, SSHCFG_ALL, रिक्त, SSH_RSA_MINIMUM_MODULUS_आकार, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRARRAY(channel_timeouts, अङ्कः_channel_timeouts, ChannelTimeout, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_INT(अप्रयुक्तम्_connection_timeout, अप्रयुक्तम्_Connection_Timeout, SSHCFG_ALL, रिक्त, 0, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRING(sshd_session_मार्गः, Sshd_Session_मार्गः, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_STRING(sshd_auth_मार्गः, Sshd_Auth_मार्गः, SSHCFG_GLOBAL, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(refuse_connection, RefuseConnection, SSHCFG_ALL, 0, SSHCFG_COPY_मेलनम्) \
SSHCONF_STRING(agent_socket_मार्गः, Agent_Socket_मार्गः, SSHCFG_ALL, SSHCFG_COPY_मेलनम्) \
SSHCONF_INT(warn_weak_crypto, WarnWeakCrypto, SSHCFG_GLOBAL, multistate_warnweakcrypto, 1, SSHCFG_COPY_NONE)

#परिभाषय SSHD_CONFIG_ENTRIES_LEGACY \
SSHCONF_DEPRECATE(Server_कुञ्चिका_द्वयङ्काः, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(कुञ्चिका_Regeneration_Interval, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RHostsAuthentication, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RhostsRSAAuthentication, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(RSAAuthentication, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(CheckMail, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(UseLogin, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(VerifyReverseMapping, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(ReverseMappingCheck, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Authorized_कुञ्चिकाः_File2, SSHCFG_ALL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(UsePrivilegeSeparation, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(KerberosTgtPassing, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(AFSTokenPassing, SSHCFG_GLOBAL, SSHCONF_DEPRECATED) \
SSHCONF_DEPRECATE(Protocol, SSHCFG_GLOBAL, SSHCONF_IGNORE)

#परिभाषय SSHD_CONFIG_ENTRIES_ALIASES \
SSHCONF_ALIAS(HostDSAKey, Host_कुञ्चिका, SSHCFG_GLOBAL) \
SSHCONF_ALIAS(Host_Based_Accepted_कुञ्चिका_Types, HostbasedAcceptedAlgorithms, SSHCFG_ALL) \
SSHCONF_ALIAS(Pubkey_Accepted_कुञ्चिका_Types, PubkeyAcceptedAlgorithms, SSHCFG_ALL) \
SSHCONF_ALIAS(DSAAuthentication, PubkeyAuthentication, SSHCFG_GLOBAL) \
SSHCONF_ALIAS(ChallengeResponseAuthentication, KbdInteractiveAuthentication, SSHCFG_ALL) \
SSHCONF_ALIAS(SKeyAuthentication, KbdInteractiveAuthentication, SSHCFG_ALL) \
SSHCONF_ALIAS(KeepAlive, TCPKeepAlive, SSHCFG_GLOBAL)

#परिभाषय SSHD_CONFIG_ENTRIES_आधारः \
	SSHD_CONFIG_ENTRIES_CUSTOM \
	SSHD_CONFIG_ENTRIES_MAIN \
	SSHD_CONFIG_ENTRIES_LEGACY \
	SSHD_CONFIG_ENTRIES_ALIASES \
	SSHD_CONFIG_ENTRIES_PAM \
	SSHD_CONFIG_ENTRIES_LASTLOG

#यदि_परिभाषितम् USE_PAM
#परिभाषय SSHD_CONFIG_ENTRIES_PAM \
SSHCONF_INTFLAG(use_pam, UsePAM, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE) \
SSHCONF_STRING(pam_service_name, PAMServiceName, SSHCFG_ALL, SSHCFG_COPY_मेलनम्)
#अन्यथा
#परिभाषय SSHD_CONFIG_ENTRIES_PAM \
SSHCONF_UNSUPPORTED_INT(use_pam, UsePAM, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_STRING(pam_service_name, PAMServiceName, SSHCFG_ALL)
#यदि_अन्तः

#यदि_परिभाषितम् DISABLE_LASTLOG
#परिभाषय SSHD_CONFIG_ENTRIES_LASTLOG \
SSHCONF_UNSUPPORTED_INT(print_lastlog, Print_चरमः_Log, SSHCFG_GLOBAL)
#अन्यथा
#परिभाषय SSHD_CONFIG_ENTRIES_LASTLOG \
SSHCONF_INTFLAG(print_lastlog, Print_चरमः_Log, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE)
#यदि_अन्तः

/* Compile-time enabled options */
#यदि_परिभाषितम् KRB5

#यदि_परिभाषितम् USE_AFS
#परिभाषय SSHD_CONFIG_KRB5_AFS \
SSHCONF_INTFLAG(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL, 0, SSHCFG_COPY_NONE)
#अन्यथा /* USE_AFS */
#परिभाषय SSHD_CONFIG_KRB5_AFS \
SSHCONF_UNSUPPORTED_INT(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL)
#यदि_अन्तः /* USE_AFS */

#परिभाषय SSHD_CONFIG_ENTRIES_KRB5 \
SSHCONF_INTFLAG(kerberos_authentication, KerberosAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_मेलनम्) \
SSHCONF_INTFLAG(kerberos_or_local_passwd, KerberosOrLocalPasswd, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(kerberos_ticket_cleanup, KerberosTicketCleanup, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHD_CONFIG_KRB5_AFS
#अन्यथा /* KRB5 */
#परिभाषय SSHD_CONFIG_ENTRIES_KRB5 \
SSHCONF_UNSUPPORTED_INT(kerberos_authentication, KerberosAuthentication, SSHCFG_ALL) \
SSHCONF_UNSUPPORTED_INT(kerberos_or_local_passwd, KerberosOrLocalPasswd, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(kerberos_ticket_cleanup, KerberosTicketCleanup, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(kerberos_get_afs_token, KerberosGetAFSToken, SSHCFG_GLOBAL)
#यदि_अन्तः /* KRB5 */

#यदि_परिभाषितम् GSSAPI
#परिभाषय SSHD_CONFIG_ENTRIES_GSS \
SSHCONF_INTFLAG(gss_authentication, GSSAPIAuthentication, SSHCFG_ALL, 0, SSHCFG_COPY_मेलनम्) \
SSHCONF_INTFLAG(gss_cleanup_creds, GSSAPICleanupCredentials, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(gss_deleg_creds, GSSAPIDelegateCredentials, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE) \
SSHCONF_INTFLAG(gss_strict_acceptor, GSSAPIStrictAcceptorCheck, SSHCFG_GLOBAL, 1, SSHCFG_COPY_NONE)
#अन्यथा /* GSSAPI */
#परिभाषय SSHD_CONFIG_ENTRIES_GSS \
SSHCONF_UNSUPPORTED_INT(gss_authentication, GSSAPIAuthentication, SSHCFG_ALL) \
SSHCONF_UNSUPPORTED_INT(gss_cleanup_creds, GSSAPICleanupCredentials, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(gss_deleg_creds, GSSAPIDelegateCredentials, SSHCFG_GLOBAL) \
SSHCONF_UNSUPPORTED_INT(gss_strict_acceptor, GSSAPIStrictAcceptorCheck, SSHCFG_GLOBAL)
#यदि_अन्तः /* GSSAPI */

#परिभाषय SSHD_CONFIG_ENTRIES \
	SSHD_CONFIG_ENTRIES_आधारः \
	SSHD_CONFIG_ENTRIES_KRB5 \
	SSHD_CONFIG_ENTRIES_GSS \

/* Macros to declare ServerOptions member variables */
#परिभाषय SSHCONF_INT(var, conf, flags, ms, def, cp)	पूर्णाङ्क var;
#परिभाषय SSHCONF_INTFLAG(var, conf, flags, def, cp)	पूर्णाङ्क var;
#परिभाषय SSHCONF_STRING(var, conf, flags, cp)		वर्ण *var;
#परिभाषय SSHCONF_STRARRAY(var, nvar, conf, flags, cp)	\
	वर्ण **var; \
	u_int nvar;
#परिभाषय SSHCONF_CUSTOM(conf, funcsuffix, flags, cp)	/*रिक्तानि*/
#परिभाषय SSHCONF_NONCONF(funcsuffix)			/*रिक्तानि*/
#परिभाषय SSHCONF_DEPRECATE(conf, flags, opcode)		/*रिक्तानि*/
#परिभाषय SSHCONF_UNSUPPORTED_INT(var, conf, flags)	पूर्णाङ्क var;
#परिभाषय SSHCONF_UNSUPPORTED_STRING(var, conf, flags)	वर्ण *var;
#परिभाषय SSHCONF_ALIAS(old, conf, flags)			/*रिक्तानि*/

प्रकारनिर्देश संरचना ServerOptions {
	SSHD_CONFIG_ENTRIES
	/* Ports */
	u_int	अङ्कः_ports;
	u_int	ports_from_cmdline;
	पूर्णाङ्क	ports[MAX_PORTS];	/* Port number to listen on. */
	/* ListenAddress */
	संरचना queued_listenaddr *queued_listen_addrs;
	u_int	अङ्कः_queued_listens;
	संरचना listenaddr *listen_addrs;
	u_int	अङ्कः_listen_addrs;
	/* HostKey */
	वर्ण   **host_कुञ्चिका_files;	/* Files containing host keys. */
	पूर्णाङ्क	*host_कुञ्चिका_file_userprovided; /* Key was specified by user. */
	u_int	अङ्कः_host_कुञ्चिका_files;     /* Number of files for host keys. */
	/* IPQoS */
	पूर्णाङ्क	ip_qos_interactive;	/* IP ToS/DSCP/class for interactive */
	पूर्णाङ्क	ip_qos_bulk;		/* IP ToS/DSCP/class for bulk traffic */
	/* GatewayPorts, StreamLocalBindMask, StreamLocalBindUnlink */
	संरचना ForwardOptions fwd_opts;	/* forwarding options */
	/* LogFacility */
	SyslogFacility log_facility;	/* Facility for system logging. */
	/* LogLevel */
	LogLevel log_level;	/* Level for system logging. */
	/* PermitUserEnvironment */
	पूर्णाङ्क     permit_user_env;	/* If true, read ~/.ssh/environment */
	वर्ण   *permit_user_env_allowlist; /* pattern-list of allowed env names */
	/* Subsystem */
	u_int अङ्कः_subsystems;
	वर्ण   **subsystem_name;
	वर्ण   **subsystem_command;
	वर्ण   **subsystem_तर्काः;
	/* MaxStartups */
	पूर्णाङ्क	max_startups_begin;
	पूर्णाङ्क	max_startups_दरः;
	पूर्णाङ्क	max_startups;
	/* PerSourceNetBlockSize */
	पूर्णाङ्क	प्रत्येकम्_source_masklen_ipv4;
	पूर्णाङ्क	प्रत्येकम्_source_masklen_ipv6;
	/* PerSourcePenalties */
	संरचना प्रत्येकम्_source_penalty प्रत्येकम्_source_penalty;
	/* RekeyLimit */
	int64_t rekey_सीमा;
	पूर्णाङ्क	rekey_interval;
	/* PubkeyAuthOptions */
	पूर्णाङ्क	pubkey_auth_options;
	पूर्णाङ्क	max_pubkey_ok;
	/* Passed by config but not keyword for this */
	uint64_t timing_secret;
}       ServerOptions;
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

/* Information about the incoming connection as used by Match */
संरचना connection_info {
	ध्रुव वर्ण *user;
	पूर्णाङ्क user_invalid;
	ध्रुव वर्ण *host;	/* possibly resolved hostname */
	ध्रुव वर्ण *स्थानाङ्कः;	/* remote address */
	ध्रुव वर्ण *laddress;	/* local address */
	पूर्णाङ्क lport;		/* local port */
	ध्रुव वर्ण *rdomain;	/* routing domain if available */
	पूर्णाङ्क test;		/* test mode, allow some attributes to be
				 * unspecified */
};

/* List of included files for re-exec from the parsed configuration */
संरचना include_item {
	वर्ण *selector;
	वर्ण *filename;
	संरचना sshbuf *contents;
	TAILQ_ENTRY(include_item) प्रविष्टिः;
};
TAILQ_HEAD(include_list, include_item);

शून्य	 initialize_server_options(ServerOptions *);
शून्य	 fill_default_server_options(ServerOptions *);
पूर्णाङ्क	 process_server_config_पङ्क्तिः(ServerOptions *, वर्ण *, ध्रुव वर्ण *, पूर्णाङ्क,
	    पूर्णाङ्क *, संरचना connection_info *, संरचना include_list *includes);
शून्य	 आरोपय_server_config(ध्रुव वर्ण *, संरचना sshbuf *);
शून्य	 parse_server_config(ServerOptions *, ध्रुव वर्ण *, संरचना sshbuf *,
	    संरचना include_list *includes, संरचना connection_info *, पूर्णाङ्क);
शून्य	 parse_server_मेलनम्_config(ServerOptions *,
	    संरचना include_list *includes, संरचना connection_info *);
पूर्णाङ्क	 parse_server_मेलनम्_testspec(संरचना connection_info *, वर्ण *);
शून्य	 servconf_merge_subsystems(ServerOptions *, ServerOptions *);
शून्य	 copy_समुच्चयः_server_options(ServerOptions *, ServerOptions *, पूर्णाङ्क);
शून्य	 dump_config(ServerOptions *);
वर्ण	*derelativise_मार्गः(ध्रुव वर्ण *);
शून्य	 servconf_सङ्कलय_hostkey(ध्रुव वर्ण *, ध्रुव पूर्णाङ्क,
	    ServerOptions *, ध्रुव वर्ण *मार्गः, पूर्णाङ्क);
शून्य	 servconf_सङ्कलय_hostcert(ध्रुव वर्ण *, ध्रुव पूर्णाङ्क,
	    ServerOptions *, ध्रुव वर्ण *मार्गः);

पूर्णाङ्क	 serialise_server_options(ध्रुव ServerOptions *, संरचना sshbuf **);
पूर्णाङ्क	 deserialise_server_options(संरचना sshbuf *, ServerOptions *);
शून्य	 free_server_options(ServerOptions *);

#यदि_अन्तः				/* SERVCONF_H */
