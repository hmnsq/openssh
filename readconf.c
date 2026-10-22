/* $OpenBSD: readconf.c,v 1.419 2026/10/05 06:03:40 dtucker Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Functions for reading the configuration files.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/stat.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>
#ಅನ್ತರ್ಭಾವ <sys/un.h>

#ಅನ್ತರ್ಭಾವ <net/if.h>
#ಅನ್ತರ್ಭಾವ <netinet/in.h>
#ಅನ್ತರ್ಭಾವ <netinet/ip.h>
#ಅನ್ತರ್ಭಾವ <arpa/inet.h>

#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <glob.h>
#ಅನ್ತರ್ಭಾವ <ifaddrs.h>
#ಅನ್ತರ್ಭಾವ <limits.h>
#ಅನ್ತರ್ಭಾವ <netdb.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <util.h>
#ಯದಿ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "cipher.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "readconf.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "mac.h"
#ಅನ್ತರ್ಭಾವ "myproposal.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ಅನ್ತರ್ಭಾವ "version.h"

/* Format of the configuration file:

   # Configuration data is parsed as follows:
   #  1. command line options
   #  2. user-specific file
   #  3. system-wide file
   # Any configuration value is only changed the first time it is set.
   # Thus, host-specific definitions should be at the beginning of the
   # configuration file, and defaults at the end.

   # Host-specific declarations.  These may override anything above.  A single
   # host may match multiple declarations; these are processed in the order
   # that they are given in.

   Host *.ngs.fi ngs.fi
     User foo

   Host fake.com
     Hostname another.host.name.real.org
     User blaah
     Port 34289
     ForwardX11 no
     ForwardAgent no

   Host books.com
     RemoteForward 9999 shadows.cs.hut.fi:9999
     Ciphers 3des-cbc

   Host fascist.blob.com
     Port 23123
     User tylonen
     PasswordAuthentication no

   Host puukko.hut.fi
     User t35124p
     ProxyCommand ssh-proxy %h %p

   Host *.fr
     PublicKeyAuthentication no

   Host *.su
     Ciphers aes128-ctr
     PasswordAuthentication no

   Host vpn.fake.com
     Tunnel yes
     TunnelDevice 3

   # Defaults for various options
   Host *
     ForwardAgent no
     ForwardX11 no
     PasswordAuthentication yes
     StrictHostKeyChecking yes
     TcpKeepAlive no
     IdentityFile ~/.ssh/identity
     Port 22
     EscapeChar ~

*/

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ read_config_file_depth(ಧ್ರುವ ವರ್ಣ *filename, ಸಂರಚನಾ passwd *pw,
    ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *original_host, ಧ್ರುವ ವರ್ಣ *remote_command,
    Options *options, ಪೂರ್ಣಾಙ್ಕ flags, ಪೂರ್ಣಾಙ್ಕ *activep, ಪೂರ್ಣಾಙ್ಕ *want_final_pass, ಪೂರ್ಣಾಙ್ಕ depth);
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ process_config_ಸಾಲು_depth(Options *options, ಸಂರಚನಾ passwd *pw,
    ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *original_host, ಧ್ರುವ ವರ್ಣ *remote_command,
    ವರ್ಣ *ಸಾಲು, ಧ್ರುವ ವರ್ಣ *filename, ಪೂರ್ಣಾಙ್ಕ linenum, ಪೂರ್ಣಾಙ್ಕ *activep, ಪೂರ್ಣಾಙ್ಕ flags,
    ಪೂರ್ಣಾಙ್ಕ *want_final_pass, ಪೂರ್ಣಾಙ್ಕ depth);

/* Keyword tokens. */

ಪ್ರಕಾರನಿರ್ದೇಶ ಗಣನಾ {
	oBadOption,
	oHost, oMatch, oInclude, oTag,
	oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout,
	oGatewayPorts, oExitOnForwardFailure,
	oPasswordAuthentication,
	oXAuthLocation,
	oIdentityFile, oHostname, oPort, oRemoteForward, oLocalForward,
	oPermitRemoteOpen,
	oCertificateFile, o_Add_ಕೀಲಿಗಳು_To_Agent, oIdentityAgent,
	oUser, oEscapeChar, oProxyCommand,
	oGlobalKnownHostsFile, oUserKnownHostsFile, oConnectionAttempts,
	oBatchMode, oCheckHostIP, o_Strict_Host_ಕೀಲಿ_Checking, oCompression,
	oTCPKeepAlive, o_ಸಂಖ್ಯೆ_Of_Password_Prompts,
	oLogFacility, oLogLevel, oLogVerbose, oCiphers, oMacs,
	oPubkeyAuthentication,
	oKbdInteractiveAuthentication, oKbdInteractiveDevices, o_Host_ಕೀಲಿ_Alias,
	oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication,
	o_Host_ಕೀಲಿ_Algorithms, oBindAddress, oBindInterface, oPKCS11Provider,
	oClearAllForwardings, oNoHostAuthenticationForLocalhost,
	oEnableSSHKeysign, oRekeyLimit, o_Verify_Host_ಕೀಲಿ_DNS, oConnectTimeout,
	oAddressFamily, oGssAuthentication, oGssDelegateCreds,
	oServerAliveInterval, o_Server_Alive_ಎಣಿಕೆ_Max, oIdentitiesOnly,
	oSendEnv, oSetEnv, oControlPath, oControlMaster, oControlPersist,
	oHashKnownHosts,
	oTunnel, oTunnelDevice,
	oLocalCommand, oPermitLocalCommand, oRemoteCommand,
	o_Visual_Host_ಕೀಲಿ,
	oKexAlgorithms, oIPQoS, oRequestTTY, oSessionType, oStdinNull,
	oForkAfterAuthentication, oIgnoreUnknown, oProxyUseFdpass,
	oCanonicalDomains, oCanonicalizeHostname, oCanonicalizeMaxDots,
	oCanonicalizeFallbackLocal, oCanonicalizePermittedCNAMEs,
	oStreamLocalBindMask, oStreamLocalBindUnlink, o_Revoked_Host_ಕೀಲಿಗಳು,
	oFingerprintHash, oUpdateHostkeys, oHostbasedAcceptedAlgorithms,
	oPubkeyAcceptedAlgorithms, oCASignatureAlgorithms, oProxyJump,
	o_Security_ಕೀಲಿ_Provider, oKnownHostsCommand, oRequiredRSASize,
	oEnableEscapeCommandline, oObscureKeystrokeTiming, oChannelTimeout,
	oVersionAddendum, oRefuseConnection, oWarnWeakCrypto,
	oIgnore, oIgnoredUnknownOption, oDeprecated, oUnsupported
} OpCodes;

/* Textual representations of the tokens. */

ಸ್ಥಿರ ಸಂರಚನಾ {
	ಧ್ರುವ ವರ್ಣ *name;
	OpCodes opcode;
} keywords[] = {
	/* Deprecated options */
	{ "protocol", oIgnore }, /* NB. silently ignored */
	{ "cipher", oDeprecated },
	{ "fallbacktorsh", oDeprecated },
	{ "globalknownhostsfile2", oDeprecated },
	{ "rhostsauthentication", oDeprecated },
	{ "userknownhostsfile2", oDeprecated },
	{ "useroaming", oDeprecated },
	{ "usersh", oDeprecated },
	{ "useprivilegedport", oDeprecated },

	/* Unsupported options */
	{ "afstokenpassing", oUnsupported },
	{ "kerberosauthentication", oUnsupported },
	{ "kerberostgtpassing", oUnsupported },
	{ "rsaauthentication", oUnsupported },
	{ "rhostsrsaauthentication", oUnsupported },
	{ "compressionlevel", oUnsupported },

	/* Sometimes-unsupported options */
#ಯದಿ defined(GSSAPI)
	{ "gssapiauthentication", oGssAuthentication },
	{ "gssapidelegatecredentials", oGssDelegateCreds },
# ಅನ್ಯಥಾ
	{ "gssapiauthentication", oUnsupported },
	{ "gssapidelegatecredentials", oUnsupported },
#endif
#ifdef ENABLE_PKCS11
	{ "pkcs11provider", oPKCS11Provider },
	{ "smartcarddevice", oPKCS11Provider },
# ಅನ್ಯಥಾ
	{ "smartcarddevice", oUnsupported },
	{ "pkcs11provider", oUnsupported },
#endif

	{ "forwardagent", oForwardAgent },
	{ "forwardx11", oForwardX11 },
	{ "forwardx11trusted", oForwardX11Trusted },
	{ "forwardx11timeout", oForwardX11Timeout },
	{ "exitonforwardfailure", oExitOnForwardFailure },
	{ "xauthlocation", oXAuthLocation },
	{ "gatewayports", oGatewayPorts },
	{ "passwordauthentication", oPasswordAuthentication },
	{ "kbdinteractiveauthentication", oKbdInteractiveAuthentication },
	{ "kbdinteractivedevices", oKbdInteractiveDevices },
	{ "challengeresponseauthentication", oKbdInteractiveAuthentication }, /* alias */
	{ "skeyauthentication", oKbdInteractiveAuthentication }, /* alias */
	{ "tisauthentication", oKbdInteractiveAuthentication },  /* alias */
	{ "pubkeyauthentication", oPubkeyAuthentication },
	{ "dsaauthentication", oPubkeyAuthentication },		    /* alias */
	{ "hostbasedauthentication", oHostbasedAuthentication },
	{ "identityfile", oIdentityFile },
	{ "identityfile2", oIdentityFile },			/* obsolete */
	{ "identitiesonly", oIdentitiesOnly },
	{ "certificatefile", oCertificateFile },
	{ "addkeystoagent", o_Add_ಕೀಲಿಗಳು_To_Agent },
	{ "identityagent", oIdentityAgent },
	{ "hostname", oHostname },
	{ "hostkeyalias", o_Host_ಕೀಲಿ_Alias },
	{ "proxycommand", oProxyCommand },
	{ "port", oPort },
	{ "ciphers", oCiphers },
	{ "macs", oMacs },
	{ "remoteforward", oRemoteForward },
	{ "localforward", oLocalForward },
	{ "permitremoteopen", oPermitRemoteOpen },
	{ "user", oUser },
	{ "host", oHost },
	{ "match", oMatch },
	{ "tag", oTag },
	{ "escapechar", oEscapeChar },
	{ "globalknownhostsfile", oGlobalKnownHostsFile },
	{ "userknownhostsfile", oUserKnownHostsFile },
	{ "connectionattempts", oConnectionAttempts },
	{ "batchmode", oBatchMode },
	{ "checkhostip", oCheckHostIP },
	{ "stricthostkeychecking", o_Strict_Host_ಕೀಲಿ_Checking },
	{ "compression", oCompression },
	{ "tcpkeepalive", oTCPKeepAlive },
	{ "keepalive", oTCPKeepAlive },				/* obsolete */
	{ "numberofpasswordprompts", o_ಸಂಖ್ಯೆ_Of_Password_Prompts },
	{ "syslogfacility", oLogFacility },
	{ "loglevel", oLogLevel },
	{ "logverbose", oLogVerbose },
	{ "dynamicforward", oDynamicForward },
	{ "preferredauthentications", oPreferredAuthentications },
	{ "hostkeyalgorithms", o_Host_ಕೀಲಿ_Algorithms },
	{ "casignaturealgorithms", oCASignatureAlgorithms },
	{ "bindaddress", oBindAddress },
	{ "bindinterface", oBindInterface },
	{ "clearallforwardings", oClearAllForwardings },
	{ "enablesshkeysign", oEnableSSHKeysign },
	{ "verifyhostkeydns", o_Verify_Host_ಕೀಲಿ_DNS },
	{ "nohostauthenticationforlocalhost", oNoHostAuthenticationForLocalhost },
	{ "rekeylimit", oRekeyLimit },
	{ "connecttimeout", oConnectTimeout },
	{ "addressfamily", oAddressFamily },
	{ "serveraliveinterval", oServerAliveInterval },
	{ "serveralivecountmax", o_Server_Alive_ಎಣಿಕೆ_Max },
	{ "sendenv", oSendEnv },
	{ "setenv", oSetEnv },
	{ "controlpath", oControlPath },
	{ "controlmaster", oControlMaster },
	{ "controlpersist", oControlPersist },
	{ "hashknownhosts", oHashKnownHosts },
	{ "include", oInclude },
	{ "tunnel", oTunnel },
	{ "tunneldevice", oTunnelDevice },
	{ "localcommand", oLocalCommand },
	{ "permitlocalcommand", oPermitLocalCommand },
	{ "remotecommand", oRemoteCommand },
	{ "visualhostkey", o_Visual_Host_ಕೀಲಿ },
	{ "kexalgorithms", oKexAlgorithms },
	{ "ipqos", oIPQoS },
	{ "requesttty", oRequestTTY },
	{ "sessiontype", oSessionType },
	{ "stdinnull", oStdinNull },
	{ "forkafterauthentication", oForkAfterAuthentication },
	{ "proxyusefdpass", oProxyUseFdpass },
	{ "canonicaldomains", oCanonicalDomains },
	{ "canonicalizefallbacklocal", oCanonicalizeFallbackLocal },
	{ "canonicalizehostname", oCanonicalizeHostname },
	{ "canonicalizemaxdots", oCanonicalizeMaxDots },
	{ "canonicalizepermittedcnames", oCanonicalizePermittedCNAMEs },
	{ "streamlocalbindmask", oStreamLocalBindMask },
	{ "streamlocalbindunlink", oStreamLocalBindUnlink },
	{ "revokedhostkeys", o_Revoked_Host_ಕೀಲಿಗಳು },
	{ "fingerprinthash", oFingerprintHash },
	{ "updatehostkeys", oUpdateHostkeys },
	{ "hostbasedacceptedalgorithms", oHostbasedAcceptedAlgorithms },
	{ "hostbasedkeytypes", oHostbasedAcceptedAlgorithms }, /* obsolete */
	{ "pubkeyacceptedalgorithms", oPubkeyAcceptedAlgorithms },
	{ "pubkeyacceptedkeytypes", oPubkeyAcceptedAlgorithms }, /* obsolete */
	{ "ignoreunknown", oIgnoreUnknown },
	{ "proxyjump", oProxyJump },
	{ "securitykeyprovider", o_Security_ಕೀಲಿ_Provider },
	{ "knownhostscommand", oKnownHostsCommand },
	{ "requiredrsasize", oRequiredRSASize },
	{ "enableescapecommandline", oEnableEscapeCommandline },
	{ "obscurekeystroketiming", oObscureKeystrokeTiming },
	{ "channeltimeout", oChannelTimeout },
	{ "versionaddendum", oVersionAddendum },
	{ "refuseconnection", oRefuseConnection },
	{ "warnweakcrypto", oWarnWeakCrypto },

	{ ರಿಕ್ತ, oBadOption }
};

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *lookup_opcode_name(OpCodes code);

ಧ್ರುವ ವರ್ಣ *
kex_default_pk_alg(ಶೂನ್ಯ)
{
	ಸ್ಥಿರ ವರ್ಣ *pkalgs;

	ಯದಿ (pkalgs == ರಿಕ್ತ) {
		ವರ್ಣ *all_ಕೀಲಿ;

		all_ಕೀಲಿ = sshkey_alg_list(0, 0, 1, ',');
		pkalgs = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_ಕೀಲಿ);
		ಮುಕ್ತ(all_ಕೀಲಿ);
	}
	ಪ್ರತ್ಯಾಗಮ pkalgs;
}

ವರ್ಣ *
ssh_connection_hash(ಧ್ರುವ ವರ್ಣ *thishost, ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *portstr,
    ಧ್ರುವ ವರ್ಣ *user, ಧ್ರುವ ವರ್ಣ *jumphost)
{
	ಸಂರಚನಾ ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_LENGTH];

	ಯದಿ ((md = ssh_digest_start(SSH_DIGEST_SHA1)) == ರಿಕ್ತ ||
	    ssh_digest_update(md, thishost, strlen(thishost)) < 0 ||
	    ssh_digest_update(md, host, strlen(host)) < 0 ||
	    ssh_digest_update(md, portstr, strlen(portstr)) < 0 ||
	    ssh_digest_update(md, user, strlen(user)) < 0 ||
	    ssh_digest_update(md, jumphost, strlen(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, ಪರಿಮಾಣ(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	ಪ್ರತ್ಯಾಗಮ tohex(conn_hash, ssh_digest_bytes(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

ಶೂನ್ಯ
add_local_forward(Options *options, ಧ್ರುವ ಸಂರಚನಾ Forward *newfwd)
{
	ಸಂರಚನಾ Forward *fwd;
	ಪೂರ್ಣಾಙ್ಕ i;

	/* Don't add duplicates */
	ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_local_forwards; i++) {
		ಯದಿ (forward_equals(newfwd, options->local_forwards + i))
			ಪ್ರತ್ಯಾಗಮ;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->ಅಂಕೆ_local_forwards + 1,
	    ಪರಿಮಾಣ(*options->local_forwards));
	fwd = &options->local_forwards[options->ಅಂಕೆ_local_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_port = newfwd->listen_port;
	fwd->listen_path = newfwd->listen_path;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_port = newfwd->connect_port;
	fwd->connect_path = newfwd->connect_path;
}

/*
 * Adds a remote TCP/IP port forward to options.  Never returns if there is
 * an error.
 */

ಶೂನ್ಯ
add_remote_forward(Options *options, ಧ್ರುವ ಸಂರಚನಾ Forward *newfwd)
{
	ಸಂರಚನಾ Forward *fwd;
	ಪೂರ್ಣಾಙ್ಕ i;

	/* Don't add duplicates */
	ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_remote_forwards; i++) {
		ಯದಿ (forward_equals(newfwd, options->remote_forwards + i))
			ಪ್ರತ್ಯಾಗಮ;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->ಅಂಕೆ_remote_forwards + 1,
	    ಪರಿಮಾಣ(*options->remote_forwards));
	fwd = &options->remote_forwards[options->ಅಂಕೆ_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_port = newfwd->listen_port;
	fwd->listen_path = newfwd->listen_path;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_port = newfwd->connect_port;
	fwd->connect_path = newfwd->connect_path;
	fwd->handle = newfwd->handle;
	fwd->allocated_port = 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
clear_forwardings(Options *options)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_local_forwards; i++) {
		ಮುಕ್ತ(options->local_forwards[i].listen_host);
		ಮುಕ್ತ(options->local_forwards[i].listen_path);
		ಮುಕ್ತ(options->local_forwards[i].connect_host);
		ಮುಕ್ತ(options->local_forwards[i].connect_path);
	}
	ಯದಿ (options->ಅಂಕೆ_local_forwards > 0) {
		ಮುಕ್ತ(options->local_forwards);
		options->local_forwards = ರಿಕ್ತ;
	}
	options->ಅಂಕೆ_local_forwards = 0;
	ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_remote_forwards; i++) {
		ಮುಕ್ತ(options->remote_forwards[i].listen_host);
		ಮುಕ್ತ(options->remote_forwards[i].listen_path);
		ಮುಕ್ತ(options->remote_forwards[i].connect_host);
		ಮುಕ್ತ(options->remote_forwards[i].connect_path);
	}
	ಯದಿ (options->ಅಂಕೆ_remote_forwards > 0) {
		ಮುಕ್ತ(options->remote_forwards);
		options->remote_forwards = ರಿಕ್ತ;
	}
	options->ಅಂಕೆ_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

ಶೂನ್ಯ
add_certificate_file(Options *options, ಧ್ರುವ ವರ್ಣ *path, ಪೂರ್ಣಾಙ್ಕ userprovided)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (options->ಅಂಕೆ_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_certificate_files; i++) {
		ಯದಿ (options->certificate_file_userprovided[i] == userprovided &&
		    strcmp(options->certificate_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			ಪ್ರತ್ಯಾಗಮ;
		}
	}

	options->certificate_file_userprovided[options->ಅಂಕೆ_certificate_files] =
	    userprovided;
	options->certificate_files[options->ಅಂಕೆ_certificate_files++] =
	    xstrdup(path);
}

ಶೂನ್ಯ
add_identity_file(Options *options, ಧ್ರುವ ವರ್ಣ *dir, ಧ್ರುವ ವರ್ಣ *filename,
    ಪೂರ್ಣಾಙ್ಕ userprovided)
{
	ವರ್ಣ *path;
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (options->ಅಂಕೆ_identity_files >= SSH_MAX_IDENTITY_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_IDENTITY_FILES);

	ಯದಿ (dir == ರಿಕ್ತ) /* no dir, filename is absolute */
		path = xstrdup(filename);
	ಅನ್ಯಥಾ ಯದಿ (xasprintf(&path, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", path);

	/* Avoid registering duplicates */
	ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_identity_files; i++) {
		ಯದಿ (options->identity_file_userprovided[i] == userprovided &&
		    strcmp(options->identity_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			ಮುಕ್ತ(path);
			ಪ್ರತ್ಯಾಗಮ;
		}
	}

	options->identity_file_userprovided[options->ಅಂಕೆ_identity_files] =
	    userprovided;
	options->identity_files[options->ಅಂಕೆ_identity_files++] = path;
}

ಪೂರ್ಣಾಙ್ಕ
default_ssh_port(ಶೂನ್ಯ)
{
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ port;
	ಸಂರಚನಾ servent *sp;

	ಯದಿ (port == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		port = sp ? ntohs(sp->s_port) : SSH_DEFAULT_PORT;
	}
	ಪ್ರತ್ಯಾಗಮ port;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
execute_in_shell(ಧ್ರುವ ವರ್ಣ *cmd)
{
	ವರ್ಣ *shell;
	pid_t pid;
	ಪೂರ್ಣಾಙ್ಕ status;

	ಯದಿ ((shell = getenv("SHELL")) == ರಿಕ್ತ)
		shell = _PATH_BSHELL;

	ಯದಿ (access(shell, X_OK) == -1) {
		fatal("Shell \"%s\" is not executable: %s",
		    shell, strerror(errno));
	}

	debug("Executing command: '%.500s'", cmd);

	/* Fork and execute the command. */
	ಯದಿ ((pid = fork()) == 0) {
		ವರ್ಣ *argv[4];

		ಯದಿ (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = xstrdup(cmd);
		argv[3] = ರಿಕ್ತ;

		execv(argv[0], argv);
		error("Unable to execute '%.100s': %s", cmd, strerror(errno));
		/* Die with signal to make this error apparent to parent. */
		ssh_signal(SIGTERM, SIG_DFL);
		kill(getpid(), SIGTERM);
		_exit(1);
	}
	/* Parent. */
	ಯದಿ (pid == -1)
		fatal_f("fork: %.100s", strerror(errno));

	ಯಾವತ್ (waitpid(pid, &status, 0) == -1) {
		ಯದಿ (errno != EINTR && errno != EAGAIN)
			fatal_f("waitpid: %s", strerror(errno));
	}
	ಯದಿ (!WIFEXITED(status)) {
		error("command '%.100s' exited abnormally", cmd);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	debug3("command returned status %d", WEXITSTATUS(status));
	ಪ್ರತ್ಯಾಗಮ WEXITSTATUS(status);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
check_match_ifaddrs(ಧ್ರುವ ವರ್ಣ *addrlist)
{
#ifdef HAVE_IFADDRS_H
	ಸಂರಚನಾ ifaddrs *ifa, *ifaddrs = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, found = 0;
	ವರ್ಣ addr[NI_MAXHOST];
	socklen_t salen;

	ಯದಿ (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    strerror(errno));
		ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಪ್ರತಿ (ifa = ifaddrs; ifa != ರಿಕ್ತ; ifa = ifa->ifa_next) {
		ಯದಿ (ifa->ifa_addr == ರಿಕ್ತ || ifa->ifa_name == ರಿಕ್ತ ||
		    (ifa->ifa_flags & IFF_UP) == 0)
			ಅನುವರ್ತ;
		ವಿಕಲ್ಪ (ifa->ifa_addr->sa_family) {
		ಪಕ್ಷ AF_INET:
			salen = ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr_in);
			ಭಙ್ಗ;
		ಪಕ್ಷ AF_INET6:
			salen = ಪರಿಮಾಣ(ಸಂರಚನಾ sockaddr_in6);
			ಭಙ್ಗ;
#ifdef AF_LINK
		ಪಕ್ಷ AF_LINK:
			/* ignore */
			ಅನುವರ್ತ;
#endif /* AF_LINK */
		ಸ್ವಭಾವ:
			debug2_f("interface %s: unsupported address family %d",
			    ifa->ifa_name, ifa->ifa_addr->sa_family);
			ಅನುವರ್ತ;
		}
		ಯದಿ ((r = getnameinfo(ifa->ifa_addr, salen, addr, ಪರಿಮಾಣ(addr),
		    ರಿಕ್ತ, 0, NI_NUMERICHOST)) != 0) {
			debug2_f("interface %s getnameinfo failed: %s",
			    ifa->ifa_name, gai_strerror(r));
			ಅನುವರ್ತ;
		}
		debug3_f("interface %s addr %s", ifa->ifa_name, addr);
		ಯದಿ (addr_match_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			found = 1;
			ಭಙ್ಗ;
		}
	}
	freeifaddrs(ifaddrs);
	ಪ್ರತ್ಯಾಗಮ found;
#ಅನ್ಯಥಾ /* HAVE_IFADDRS_H */
	error("match localnetwork: not supported on this platform");
	ಪ್ರತ್ಯಾಗಮ 0;
#endif /* HAVE_IFADDRS_H */
}

/*
 * Expand a "match exec" command or an Include path, caller must free returned
 * value.
 */
ಸ್ಥಿರ ವರ್ಣ *
expand_match_exec_or_include_path(ಧ್ರುವ ವರ್ಣ *path, Options *options,
    ಸಂರಚನಾ passwd *pw, ಧ್ರುವ ವರ್ಣ *host_arg, ಧ್ರುವ ವರ್ಣ *original_host,
    ಪೂರ್ಣಾಙ್ಕ final_pass, ಪೂರ್ಣಾಙ್ಕ is_include_path)
{
	ವರ್ಣ thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	ವರ್ಣ uidstr[32], *conn_hash_hex, *keyalias, *jmphost, *ruser;
	ವರ್ಣ *host, *ret;
	ಪೂರ್ಣಾಙ್ಕ port;

	port = options->port <= 0 ? default_ssh_port() : options->port;
	ruser = options->user == ರಿಕ್ತ ? pw->pw_name : options->user;
	ಯದಿ (final_pass) {
		host = xstrdup(options->hostname);
	} ಅನ್ಯಥಾ ಯದಿ (options->hostname != ರಿಕ್ತ) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (ವರ್ಣ *)ರಿಕ್ತ);
	} ಅನ್ಯಥಾ {
		host = xstrdup(host_arg);
	}
	ಯದಿ (gethostname(thishost, ಪರಿಮಾಣ(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	jmphost = option_clear_or_none(options->jump_host) ?
	    "" : options->jump_host;
	strlcpy(shorthost, thishost, ಪರಿಮಾಣ(shorthost));
	shorthost[strcspn(thishost, ".")] = '\0';
	snprintf(portstr, ಪರಿಮಾಣ(portstr), "%d", port);
	snprintf(uidstr, ಪರಿಮಾಣ(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	conn_hash_hex = ssh_connection_hash(thishost, host,
	    portstr, ruser, jmphost);
	keyalias = options->host_ಕೀಲಿ_alias ?  options->host_ಕೀಲಿ_alias : host;

	ret = (is_include_path ? percent_dollar_expand : percent_expand)(path,
	    "C", conn_hash_hex,
	    "L", shorthost,
	    "d", pw->pw_dir,
	    "h", host,
	    "k", keyalias,
	    "l", thishost,
	    "n", original_host,
	    "p", portstr,
	    "r", ruser,
	    "u", pw->pw_name,
	    "i", uidstr,
	    "j", jmphost,
	    (ವರ್ಣ *)ರಿಕ್ತ);
	ಮುಕ್ತ(host);
	ಮುಕ್ತ(conn_hash_hex);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Parse and execute a Match directive.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
match_cfg_ಸಾಲು(Options *options, ಧ್ರುವ ವರ್ಣ *full_ಸಾಲು, ಪೂರ್ಣಾಙ್ಕ *acp, ವರ್ಣ ***avp,
    ಸಂರಚನಾ passwd *pw, ಧ್ರುವ ವರ್ಣ *host_arg, ಧ್ರುವ ವರ್ಣ *original_host,
    ಧ್ರುವ ವರ್ಣ *remote_command, ಪೂರ್ಣಾಙ್ಕ final_pass, ಪೂರ್ಣಾಙ್ಕ *want_final_pass,
    ಧ್ರುವ ವರ್ಣ *filename, ಪೂರ್ಣಾಙ್ಕ linenum)
{
	ವರ್ಣ *arg, *oattrib = ರಿಕ್ತ, *attrib = ರಿಕ್ತ, *cmd, *host, *criteria;
	ಧ್ರುವ ವರ್ಣ *ruser;
	ಪೂರ್ಣಾಙ್ಕ r, this_result, result = 1, attributes = 0, negate;

	/*
	 * Configuration is likely to be incomplete at this point so we
	 * must be prepared to use default values.
	 */
	ruser = options->user == ರಿಕ್ತ ? pw->pw_name : options->user;
	ಯದಿ (final_pass) {
		host = xstrdup(options->hostname);
	} ಅನ್ಯಥಾ ಯದಿ (options->hostname != ರಿಕ್ತ) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (ವರ್ಣ *)ರಿಕ್ತ);
	} ಅನ್ಯಥಾ {
		host = xstrdup(host_arg);
	}

	debug2("checking match for '%s' host %s originally %s",
	    full_ಸಾಲು, host, original_host);
	ಯಾವತ್ ((attrib = argv_next(acp, avp)) != ರಿಕ್ತ) {
		/* Terminate on comment */
		ಯದಿ (*attrib == '#') {
			argv_consume(acp);
			ಭಙ್ಗ;
		}
		attrib = oattrib = xstrdup(attrib);
		arg = criteria = ರಿಕ್ತ;
		this_result = 1;
		ಯದಿ ((negate = (attrib[0] == '!')))
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		ಯದಿ (strcasecmp(attrib, "all") == 0) {
			ಯದಿ (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != ರಿಕ್ತ &&
			    *arg != '\0' && *arg != '#')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				result = -1;
				ಗಚ್ಛ out;
			}
			ಯದಿ (arg != ರಿಕ್ತ && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			ಯದಿ (result)
				result = negate ? 0 : 1;
			ಗಚ್ಛ out;
		}
		attributes++;
		/* criteria "final" and "canonical" have no argument */
		ಯದಿ (strcasecmp(attrib, "canonical") == 0 ||
		    strcasecmp(attrib, "final") == 0) {
			/*
			 * If the config requests "Match final" without
			 * negation then remember this so we can perform a
			 * second pass later.
			 */
			ಯದಿ (strcasecmp(attrib, "final") == 0 &&
			    want_final_pass != ರಿಕ್ತ)
				*want_final_pass |= !negate;
			r = !!final_pass;  /* force bitmask member to boolean */
			ಯದಿ (r == (negate ? 1 : 0))
				this_result = result = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_result ? "" : "not ", oattrib);
			ಗಚ್ಛ next;
		}

		/* Keep this list in sync with below */
		ಯದಿ (strprefix(attrib, "host=", 1)  != ರಿಕ್ತ ||
		    strprefix(attrib, "originalhost=", 1) != ರಿಕ್ತ ||
		    strprefix(attrib, "user=", 1) != ರಿಕ್ತ ||
		    strprefix(attrib, "localuser=", 1) != ರಿಕ್ತ ||
		    strprefix(attrib, "localnetwork=", 1) != ರಿಕ್ತ ||
		    strprefix(attrib, "version=", 1) != ರಿಕ್ತ ||
		    strprefix(attrib, "tagged=", 1) != ರಿಕ್ತ ||
		    strprefix(attrib, "command=", 1) != ರಿಕ್ತ ||
		    strprefix(attrib, "exec=", 1) != ರಿಕ್ತ) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} ಅನ್ಯಥಾ ಯದಿ ((arg = argv_next(acp, avp)) == ರಿಕ್ತ) {
			error("%.200s line %d: missing argument for Match '%s'",
			    filename, linenum, oattrib);
			result = -1;
			ಗಚ್ಛ out;
		}

		/*
		 * All other criteria require an argument, though it may
		 * be the empty string for the "tagged" and "command"
		 * options.
		 */
		ಯದಿ (*arg == '\0' &&
		    strcasecmp(attrib, "tagged") != 0 &&
		    strcasecmp(attrib, "command") != 0)
			arg = ರಿಕ್ತ;
		ಯದಿ (arg == ರಿಕ್ತ || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			ಗಚ್ಛ out;
		}
		ಯದಿ (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = match_hostname(host, arg) == 1;
			ಯದಿ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = match_hostname(original_host, arg) == 1;
			ಯದಿ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = match_pattern_list(ruser, arg, 0) == 1;
			ಯದಿ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = match_pattern_list(pw->pw_name, arg, 0) == 1;
			ಯದಿ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(attrib, "localnetwork") == 0) {
			ಯದಿ (addr_match_cidr_list(ರಿಕ್ತ, arg) == -1) {
				/* Error already printed */
				result = -1;
				ಗಚ್ಛ out;
			}
			r = check_match_ifaddrs(arg) == 1;
			ಯದಿ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(attrib, "version") == 0) {
			criteria = xstrdup(SSH_RELEASE);
			r = match_pattern_list(SSH_RELEASE, arg, 0) == 1;
			ಯದಿ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->tag == ರಿಕ್ತ ? "" :
			    options->tag);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			ಯದಿ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(attrib, "command") == 0) {
			criteria = xstrdup(remote_command == ರಿಕ್ತ ?
			    "" : remote_command);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			ಯದಿ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(attrib, "sessiontype") == 0) {
			ಯದಿ (options->session_type == SESSION_TYPE_SUBSYSTEM)
				criteria = xstrdup("subsystem");
			ಅನ್ಯಥಾ ಯದಿ (options->session_type == SESSION_TYPE_NONE)
				criteria = xstrdup("none");
			ಅನ್ಯಥಾ ಯದಿ (remote_command != ರಿಕ್ತ &&
			    *remote_command != '\0')
				criteria = xstrdup("exec");
			ಅನ್ಯಥಾ
				criteria = xstrdup("shell");
			r = match_pattern_list(criteria, arg, 0) == 1;
			ಯದಿ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(attrib, "exec") == 0) {
			ಯದಿ ((cmd = expand_match_exec_or_include_path(arg,
			    options, pw, host_arg, original_host,
			    final_pass, 0)) == ರಿಕ್ತ) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			ಯದಿ (result != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				ಮುಕ್ತ(cmd);
				ಗಚ್ಛ next;
			}
			r = execute_in_shell(cmd);
			ಯದಿ (r == -1) {
				fatal("%.200s line %d: match exec "
				    "'%.100s' error", filename,
				    linenum, cmd);
			}
			criteria = xstrdup(cmd);
			ಮುಕ್ತ(cmd);
			/* Force exit status to boolean */
			r = r == 0;
			ಯದಿ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} ಅನ್ಯಥಾ {
			error("Unsupported Match attribute %s", attrib);
			result = -1;
			ಗಚ್ಛ out;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s' ",
		    filename, linenum, this_result ? "": "not ", oattrib,
		    criteria == ರಿಕ್ತ ? "" : " \"",
		    criteria == ರಿಕ್ತ ? "" : criteria,
		    criteria == ರಿಕ್ತ ? "" : "\"");
 next:
		ಮುಕ್ತ(criteria);
		ಮುಕ್ತ(oattrib);
		oattrib = attrib = ರಿಕ್ತ;
	}
	ಯದಿ (attributes == 0) {
		error("One or more attributes required for Match");
		result = -1;
		ಗಚ್ಛ out;
	}
 out:
	ಯದಿ (result != -1)
		debug2("match %sfound", result ? "" : "not ");
	ಮುಕ್ತ(oattrib);
	ಮುಕ್ತ(host);
	ಪ್ರತ್ಯಾಗಮ result;
}

/* Remove environment variable by pattern */
ಸ್ಥಿರ ಶೂನ್ಯ
rm_env(Options *options, ಧ್ರುವ ವರ್ಣ *arg, ಧ್ರುವ ವರ್ಣ *filename, ಪೂರ್ಣಾಙ್ಕ linenum)
{
	u_int i, j, onum_send_env = options->ಅಂಕೆ_send_env;

	/* Remove an environment variable */
	ಪ್ರತಿ (i = 0; i < options->ಅಂಕೆ_send_env; ) {
		ಯದಿ (!match_pattern(options->send_env[i], arg + 1)) {
			i++;
			ಅನುವರ್ತ;
		}
		debug3("%s line %d: removing environment %s",
		    filename, linenum, options->send_env[i]);
		ಮುಕ್ತ(options->send_env[i]);
		options->send_env[i] = ರಿಕ್ತ;
		ಪ್ರತಿ (j = i; j < options->ಅಂಕೆ_send_env - 1; j++) {
			options->send_env[j] = options->send_env[j + 1];
			options->send_env[j + 1] = ರಿಕ್ತ;
		}
		options->ಅಂಕೆ_send_env--;
		/* NB. don't increment i */
	}
	ಯದಿ (onum_send_env != options->ಅಂಕೆ_send_env) {
		options->send_env = xrecallocarray(options->send_env,
		    onum_send_env, options->ಅಂಕೆ_send_env,
		    ಪರಿಮಾಣ(*options->send_env));
	}
}

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */
ಸ್ಥಿರ OpCodes
parse_token(ಧ್ರುವ ವರ್ಣ *cp, ಧ್ರುವ ವರ್ಣ *filename, ಪೂರ್ಣಾಙ್ಕ linenum,
    ಧ್ರುವ ವರ್ಣ *ignored_unknown)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಪ್ರತಿ (i = 0; keywords[i].name; i++)
		ಯದಿ (strcmp(cp, keywords[i].name) == 0)
			ಪ್ರತ್ಯಾಗಮ keywords[i].opcode;
	ಯದಿ (ignored_unknown != ರಿಕ್ತ &&
	    match_pattern_list(cp, ignored_unknown, 1) == 1)
		ಪ್ರತ್ಯಾಗಮ oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	ಪ್ರತ್ಯಾಗಮ oBadOption;
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_canon_cnames(ಸಂರಚನಾ allowed_cname *cnames, u_int n)
{
	u_int i;

	ಯದಿ (cnames == ರಿಕ್ತ || n == 0)
		ಪ್ರತ್ಯಾಗಮ;
	ಪ್ರತಿ (i = 0; i < n; i++) {
		ಮುಕ್ತ(cnames[i].source_list);
		ಮುಕ್ತ(cnames[i].target_list);
	}
	ಮುಕ್ತ(cnames);
}

/* Multistate option parsing */
ಸಂರಚನಾ multistate {
	ವರ್ಣ *ಕೀಲಿ;
	ಪೂರ್ಣಾಙ್ಕ ಮೌಲ್ಯ;
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_flag[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ ರಿಕ್ತ, -1 }
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_yesnoask[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ ರಿಕ್ತ, -1 }
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_strict_hostkey[] = {
	{ "true",			SSH_STRICT_HOSTKEY_YES },
	{ "false",			SSH_STRICT_HOSTKEY_OFF },
	{ "yes",			SSH_STRICT_HOSTKEY_YES },
	{ "no",				SSH_STRICT_HOSTKEY_OFF },
	{ "ask",			SSH_STRICT_HOSTKEY_ASK },
	{ "off",			SSH_STRICT_HOSTKEY_OFF },
	{ "accept-new",			SSH_STRICT_HOSTKEY_NEW },
	{ ರಿಕ್ತ, -1 }
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_yesnoaskconfirm[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "confirm",			3 },
	{ ರಿಕ್ತ, -1 }
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ ರಿಕ್ತ, -1 }
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_controlmaster[] = {
	{ "true",			SSHCTL_MASTER_YES },
	{ "yes",			SSHCTL_MASTER_YES },
	{ "false",			SSHCTL_MASTER_NO },
	{ "no",				SSHCTL_MASTER_NO },
	{ "auto",			SSHCTL_MASTER_AUTO },
	{ "ask",			SSHCTL_MASTER_ASK },
	{ "autoask",			SSHCTL_MASTER_AUTO_ASK },
	{ ರಿಕ್ತ, -1 }
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET },
	{ "point-to-point",		SSH_TUNMODE_POINTOPOINT },
	{ "true",			SSH_TUNMODE_DEFAULT },
	{ "yes",			SSH_TUNMODE_DEFAULT },
	{ "false",			SSH_TUNMODE_NO },
	{ "no",				SSH_TUNMODE_NO },
	{ ರಿಕ್ತ, -1 }
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_requesttty[] = {
	{ "true",			REQUEST_TTY_YES },
	{ "yes",			REQUEST_TTY_YES },
	{ "false",			REQUEST_TTY_NO },
	{ "no",				REQUEST_TTY_NO },
	{ "force",			REQUEST_TTY_FORCE },
	{ "auto",			REQUEST_TTY_AUTO },
	{ ರಿಕ್ತ, -1 }
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_sessiontype[] = {
	{ "none",			SESSION_TYPE_NONE },
	{ "subsystem",			SESSION_TYPE_SUBSYSTEM },
	{ "default",			SESSION_TYPE_DEFAULT },
	{ ರಿಕ್ತ, -1 }
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_canonicalizehostname[] = {
	{ "true",			SSH_CANONICALISE_YES },
	{ "false",			SSH_CANONICALISE_NO },
	{ "yes",			SSH_CANONICALISE_YES },
	{ "no",				SSH_CANONICALISE_NO },
	{ "always",			SSH_CANONICALISE_ALWAYS },
	{ ರಿಕ್ತ, -1 }
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_pubkey_auth[] = {
	{ "true",			SSH_PUBKEY_AUTH_ALL },
	{ "false",			SSH_PUBKEY_AUTH_NO },
	{ "yes",			SSH_PUBKEY_AUTH_ALL },
	{ "no",				SSH_PUBKEY_AUTH_NO },
	{ "unbound",			SSH_PUBKEY_AUTH_UNBOUND },
	{ "host-bound",			SSH_PUBKEY_AUTH_HBOUND },
	{ ರಿಕ್ತ, -1 }
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ ರಿಕ್ತ, -1 }
};
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ ರಿಕ್ತ, -1 }
};
/* XXX this will need to be replaced with a bitmask if we add more flags */
ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ ರಿಕ್ತ, -1 }
};

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_multistate_ಮೌಲ್ಯ(ಧ್ರುವ ವರ್ಣ *arg, ಧ್ರುವ ವರ್ಣ *filename, ಪೂರ್ಣಾಙ್ಕ linenum,
    ಧ್ರುವ ಸಂರಚನಾ multistate *multistate_ptr)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (!arg || *arg == '\0') {
		error("%s line %d: missing argument.", filename, linenum);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ಪ್ರತಿ (i = 0; multistate_ptr[i].ಕೀಲಿ != ರಿಕ್ತ; i++) {
		ಯದಿ (strcasecmp(arg, multistate_ptr[i].ಕೀಲಿ) == 0)
			ಪ್ರತ್ಯಾಗಮ multistate_ptr[i].ಮೌಲ್ಯ;
	}
	ಪ್ರತ್ಯಾಗಮ -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
ಪೂರ್ಣಾಙ್ಕ
process_config_ಸಾಲು(Options *options, ಸಂರಚನಾ passwd *pw, ಧ್ರುವ ವರ್ಣ *host,
    ಧ್ರುವ ವರ್ಣ *original_host, ಧ್ರುವ ವರ್ಣ *remote_command, ವರ್ಣ *ಸಾಲು,
    ಧ್ರುವ ವರ್ಣ *filename, ಪೂರ್ಣಾಙ್ಕ linenum, ಪೂರ್ಣಾಙ್ಕ *activep, ಪೂರ್ಣಾಙ್ಕ flags)
{
	ಪ್ರತ್ಯಾಗಮ process_config_ಸಾಲು_depth(options, pw, host, original_host,
	    remote_command, ಸಾಲು, filename, linenum, activep, flags, ರಿಕ್ತ, 0);
}

#define WHITESPACE " \t\r\n"
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
process_config_ಸಾಲು_depth(Options *options, ಸಂರಚನಾ passwd *pw, ಧ್ರುವ ವರ್ಣ *host,
    ಧ್ರುವ ವರ್ಣ *original_host, ಧ್ರುವ ವರ್ಣ *remote_command, ವರ್ಣ *ಸಾಲು,
    ಧ್ರುವ ವರ್ಣ *filename, ಪೂರ್ಣಾಙ್ಕ linenum, ಪೂರ್ಣಾಙ್ಕ *activep, ಪೂರ್ಣಾಙ್ಕ flags,
    ಪೂರ್ಣಾಙ್ಕ *want_final_pass, ಪೂರ್ಣಾಙ್ಕ depth)
{
	ವರ್ಣ *str, **charptr, *endofnumber, *keyword, *arg, *arg2, *p;
	ವರ್ಣ **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	ಪೂರ್ಣಾಙ್ಕ r, oactive, negated, opcode, *intptr, ಮೌಲ್ಯ, value2, cmdline = 0;
	ಪೂರ್ಣಾಙ್ಕ remotefwd, dynamicfwd, ca_only = 0, found = 0;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	long long val64;
	size_t len;
	ಸಂರಚನಾ Forward fwd;
	ಧ್ರುವ ಸಂರಚನಾ multistate *multistate_ptr;
	glob_t gl;
	ಧ್ರುವ ವರ್ಣ *errstr;
	ವರ್ಣ **oav = ರಿಕ್ತ, **av;
	ಪೂರ್ಣಾಙ್ಕ oac = 0, ac;
	ಪೂರ್ಣಾಙ್ಕ ret = -1;
	ಸಂರಚನಾ allowed_cname *cnames = ರಿಕ್ತ;
	u_int ncnames = 0;
	ವರ್ಣ **strs = ರಿಕ್ತ; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	ಯದಿ (activep == ರಿಕ್ತ) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	ಯದಿ ((len = strlen(ಸಾಲು)) == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತಿ (len--; len > 0; len--) {
		ಯದಿ (strchr(WHITESPACE "\f", ಸಾಲು[len]) == ರಿಕ್ತ)
			ಭಙ್ಗ;
		ಸಾಲು[len] = '\0';
	}

	str = ಸಾಲು;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	ಯದಿ ((keyword = strdelim(&str)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	/* Ignore leading whitespace. */
	ಯದಿ (*keyword == '\0')
		keyword = strdelim(&str);
	ಯದಿ (keyword == ರಿಕ್ತ || !*keyword || *keyword == '\n' || *keyword == '#')
		ಪ್ರತ್ಯಾಗಮ 0;
	/* Match lowercase keyword */
	lowercase(keyword);

	/* Prepare to parse remainder of line */
	ಯದಿ (str != ರಿಕ್ತ)
		str += strspn(str, WHITESPACE);
	ಯದಿ (str == ರಿಕ್ತ || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	opcode = parse_token(keyword, filename, linenum,
	    options->ignored_unknown);
	ಯದಿ (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		ಪ್ರತ್ಯಾಗಮ -1;
	}
	ac = oac;
	av = oav;

	ವಿಕಲ್ಪ (opcode) {
	ಪಕ್ಷ oBadOption:
		/* don't panic, but count bad options */
		ಗಚ್ಛ out;
	ಪಕ್ಷ oIgnore:
		argv_consume(&ac);
		ಭಙ್ಗ;
	ಪಕ್ಷ oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		ಭಙ್ಗ;
	ಪಕ್ಷ oConnectTimeout:
		intptr = &options->connection_timeout;
parse_time:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		ಯದಿ (strcmp(arg, "none") == 0)
			ಮೌಲ್ಯ = -1;
		ಅನ್ಯಥಾ ಯದಿ ((ಮೌಲ್ಯ = convtime(arg)) == -1) {
			error("%s line %d: invalid time value.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		ಯದಿ (*activep && *intptr == -1)
			*intptr = ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			error("%s line %d: missing argument.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}

		ಮೌಲ್ಯ = -1;
		multistate_ptr = multistate_flag;
		ಪ್ರತಿ (i = 0; multistate_ptr[i].ಕೀಲಿ != ರಿಕ್ತ; i++) {
			ಯದಿ (strcasecmp(arg, multistate_ptr[i].ಕೀಲಿ) == 0) {
				ಮೌಲ್ಯ = multistate_ptr[i].ಮೌಲ್ಯ;
				ಭಙ್ಗ;
			}
		}
		ಯದಿ (ಮೌಲ್ಯ != -1) {
			ಯದಿ (*activep && *intptr == -1)
				*intptr = ಮೌಲ್ಯ;
			ಭಙ್ಗ;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		ಯದಿ (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_path;
		ಗಚ್ಛ parse_agent_path;

	ಪಕ್ಷ oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_next(&ac, &av);
		ಯದಿ ((ಮೌಲ್ಯ = parse_multistate_ಮೌಲ್ಯ(arg, filename, linenum,
		    multistate_ptr)) == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			ಗಚ್ಛ out;
		}
		ಯದಿ (*activep && *intptr == -1)
			*intptr = ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		ಗಚ್ಛ parse_time;

	ಪಕ್ಷ oGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ oPasswordAuthentication:
		intptr = &options->password_authentication;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		ಗಚ್ಛ parse_string;

	ಪಕ್ಷ oPubkeyAuthentication:
		multistate_ptr = multistate_pubkey_auth;
		intptr = &options->pubkey_authentication;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ oGssAuthentication:
		intptr = &options->gss_authentication;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ oBatchMode:
		intptr = &options->batch_mode;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ oCheckHostIP:
		intptr = &options->check_host_ip;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ o_Verify_Host_ಕೀಲಿ_DNS:
		intptr = &options->verify_host_ಕೀಲಿ_dns;
		multistate_ptr = multistate_yesnoask;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ o_Strict_Host_ಕೀಲಿ_Checking:
		intptr = &options->strict_host_ಕೀಲಿ_checking;
		multistate_ptr = multistate_strict_hostkey;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ oCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ o_ಸಂಖ್ಯೆ_Of_Password_Prompts:
		intptr = &options->ಸಂಖ್ಯೆ_of_password_prompts;
		ಗಚ್ಛ parse_int;

	ಪಕ್ಷ oRekeyLimit:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.", filename,
			    linenum);
			ಗಚ್ಛ out;
		}
		ಯದಿ (strcmp(arg, "default") == 0) {
			val64 = 0;
		} ಅನ್ಯಥಾ {
			ಯದಿ (scan_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, strerror(errno));
				ಗಚ್ಛ out;
			}
			ಯದಿ (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				ಗಚ್ಛ out;
			}
		}
		ಯದಿ (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		ಯದಿ (ac != 0) { /* optional rekey interval present */
			ಯದಿ (strcmp(av[0], "none") == 0) {
				(ಶೂನ್ಯ)argv_next(&ac, &av);	/* discard */
				ಭಙ್ಗ;
			}
			intptr = &options->rekey_interval;
			ಗಚ್ಛ parse_time;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ oIdentityFile:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		ಯದಿ (*activep) {
			intptr = &options->ಅಂಕೆ_identity_files;
			ಯದಿ (*intptr >= SSH_MAX_IDENTITY_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_IDENTITY_FILES);
				ಗಚ್ಛ out;
			}
			add_identity_file(options, ರಿಕ್ತ,
			    arg, flags & SSHCONF_USERCONF);
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ oCertificateFile:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		ಯದಿ (*activep) {
			intptr = &options->ಅಂಕೆ_certificate_files;
			ಯದಿ (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				ಗಚ್ಛ out;
			}
			add_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ oXAuthLocation:
		charptr=&options->xauth_location;
		ಗಚ್ಛ parse_string;

	ಪಕ್ಷ oUser:
		charptr = &options->user;
parse_string:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		ಯದಿ (*activep && *charptr == ರಿಕ್ತ)
			*charptr = xstrdup(arg);
		ಭಙ್ಗ;

	ಪಕ್ಷ oGlobalKnownHostsFile:
		cpptr = (ವರ್ಣ **)&options->system_hostfiles;
		uintptr = &options->ಅಂಕೆ_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		i = 0;
		ಮೌಲ್ಯ = *uintptr == 0; /* was array empty when we started? */
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			ಯದಿ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ಗಚ್ಛ out;
			}
			/* Allow "none" only in first position */
			ಯದಿ (strcasecmp(arg, "none") == 0) {
				ಯದಿ (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ಗಚ್ಛ out;
				}
			}
			i++;
			ಯದಿ (*activep && ಮೌಲ್ಯ) {
				ಯದಿ ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries.", filename, linenum,
					    keyword);
					ಗಚ್ಛ out;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ oUserKnownHostsFile:
		cpptr = (ವರ್ಣ **)&options->user_hostfiles;
		uintptr = &options->ಅಂಕೆ_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		ಗಚ್ಛ parse_char_array;

	ಪಕ್ಷ oHostname:
		charptr = &options->hostname;
		ಗಚ್ಛ parse_string;

	ಪಕ್ಷ oTag:
		charptr = &options->tag;
		ಗಚ್ಛ parse_string;

	ಪಕ್ಷ o_Host_ಕೀಲಿ_Alias:
		charptr = &options->host_ಕೀಲಿ_alias;
		ಗಚ್ಛ parse_string;

	ಪಕ್ಷ oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		ಗಚ್ಛ parse_string;

	ಪಕ್ಷ oBindAddress:
		charptr = &options->bind_address;
		ಗಚ್ಛ parse_string;

	ಪಕ್ಷ oBindInterface:
		charptr = &options->bind_interface;
		ಗಚ್ಛ parse_string;

	ಪಕ್ಷ oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		ಗಚ್ಛ parse_string;

	ಪಕ್ಷ o_Security_ಕೀಲಿ_Provider:
		charptr = &options->sk_provider;
		ಗಚ್ಛ parse_string;

	ಪಕ್ಷ oKnownHostsCommand:
		charptr = &options->known_hosts_command;
		ಗಚ್ಛ parse_command;

	ಪಕ್ಷ oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		ಯದಿ (str == ರಿಕ್ತ) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		len = strspn(str, WHITESPACE "=");
		ಯದಿ (*activep && *charptr == ರಿಕ್ತ)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		ಭಙ್ಗ;

	ಪಕ್ಷ oProxyJump:
		ಯದಿ (str == ರಿಕ್ತ) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		len = strspn(str, WHITESPACE "=");
		/* XXX use argv? */
		ಯದಿ (parse_jump(str + len, options, cmdline, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			ಗಚ್ಛ out;
		}
		argv_consume(&ac);
		ಭಙ್ಗ;

	ಪಕ್ಷ oPort:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		ಮೌಲ್ಯ = a2port(arg);
		ಯದಿ (ಮೌಲ್ಯ <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			ಗಚ್ಛ out;
		}
		ಯದಿ (*activep && options->port == -1)
			options->port = ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_next(&ac, &av);
		ಯದಿ ((errstr = atoi_err(arg, &ಮೌಲ್ಯ)) != ರಿಕ್ತ) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			ಗಚ್ಛ out;
		}
		ಯದಿ (*activep && *intptr == -1)
			*intptr = ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ oCiphers:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		ಯದಿ (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			ಗಚ್ಛ out;
		}
		ಯದಿ (*activep && options->ciphers == ರಿಕ್ತ)
			options->ciphers = xstrdup(arg);
		ಭಙ್ಗ;

	ಪಕ್ಷ oMacs:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		ಯದಿ (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			ಗಚ್ಛ out;
		}
		ಯದಿ (*activep && options->macs == ರಿಕ್ತ)
			options->macs = xstrdup(arg);
		ಭಙ್ಗ;

	ಪಕ್ಷ oKexAlgorithms:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		ಯದಿ (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			ಗಚ್ಛ out;
		}
		ಯದಿ (*activep && options->kex_algorithms == ರಿಕ್ತ)
			options->kex_algorithms = xstrdup(arg);
		ಭಙ್ಗ;

	ಪಕ್ಷ o_Host_ಕೀಲಿ_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		ಯದಿ (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			ಗಚ್ಛ out;
		}
		ಯದಿ (*activep && *charptr == ರಿಕ್ತ)
			*charptr = xstrdup(arg);
		ಭಙ್ಗ;

	ಪಕ್ಷ oCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		ಗಚ್ಛ parse_pubkey_algos;

	ಪಕ್ಷ oLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		ಮೌಲ್ಯ = log_level_ಸಂಖ್ಯೆ(arg);
		ಯದಿ (ಮೌಲ್ಯ == SYSLOG_LEVEL_NOT_SET) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			ಗಚ್ಛ out;
		}
		ಯದಿ (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_SET)
			*log_level_ptr = (LogLevel) ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		ಮೌಲ್ಯ = log_facility_ಸಂಖ್ಯೆ(arg);
		ಯದಿ (ಮೌಲ್ಯ == SYSLOG_FACILITY_NOT_SET) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			ಗಚ್ಛ out;
		}
		ಯದಿ (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ oLogVerbose:
		cppptr = &options->log_verbose;
		uintptr = &options->ಅಂಕೆ_log_verbose;
		i = 0;
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			ಯದಿ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ಗಚ್ಛ out;
			}
			/* Allow "none" only in first position */
			ಯದಿ (strcasecmp(arg, "none") == 0) {
				ಯದಿ (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ಗಚ್ಛ out;
				}
			}
			i++;
			ಯದಿ (*activep && *uintptr == 0) {
				*cppptr = xrecallocarray(*cppptr, *uintptr,
				    *uintptr + 1, ಪರಿಮಾಣ(**cppptr));
				(*cppptr)[(*uintptr)++] = xstrdup(arg);
			}
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ oLocalForward:
	ಪಕ್ಷ oRemoteForward:
	ಪಕ್ಷ oDynamicForward:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		ಯದಿ (!dynamicfwd) {
			arg2 = argv_next(&ac, &av);
			ಯದಿ (arg2 == ರಿಕ್ತ || *arg2 == '\0') {
				ಯದಿ (remotefwd)
					dynamicfwd = 1;
				ಅನ್ಯಥಾ {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					ಗಚ್ಛ out;
				}
			} ಅನ್ಯಥಾ {
				/* construct a string for parse_forward */
				snprintf(fwdarg, ಪರಿಮಾಣ(fwdarg), "%s:%s", arg,
				    arg2);
			}
		}
		ಯದಿ (dynamicfwd)
			strlcpy(fwdarg, arg, ಪರಿಮಾಣ(fwdarg));

		ಯದಿ (parse_forward(&fwd, fwdarg, dynamicfwd, remotefwd) == 0) {
			error("%.200s line %d: Bad forwarding specification.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}

		ಯದಿ (*activep) {
			ಯದಿ (remotefwd) {
				add_remote_forward(options, &fwd);
			} ಅನ್ಯಥಾ {
				add_local_forward(options, &fwd);
			}
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ oPermitRemoteOpen:
		uintptr = &options->ಅಂಕೆ_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		found = *uintptr == 0;
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			ಯದಿ (strcasecmp(arg, "none") == 0 ||
			    strcasecmp(arg, "any") == 0) {
				ಯದಿ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					ಮುಕ್ತ(arg2);
					ಗಚ್ಛ out;
				}
			} ಅನ್ಯಥಾ {
				p = hpdelim(&arg);
				ಯದಿ (p == ರಿಕ್ತ) {
					fatal("%s line %d: missing host in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
				}
				p = cleanhostname(p);
				/*
				 * don't want to use permitopen_port to avoid
				 * dependency on channels.[ch] here.
				 */
				ಯದಿ (arg == ರಿಕ್ತ || (strcmp(arg, "*") != 0 &&
				    a2port(arg) <= 0)) {
					fatal("%s line %d: bad port number "
					    "in %s", filename, linenum,
					    lookup_opcode_name(opcode));
				}
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg2);
			ಮುಕ್ತ(arg2);
		}
		ಯದಿ (nstrs == 0)
			fatal("%s line %d: missing %s specification",
			    filename, linenum, lookup_opcode_name(opcode));
		ಯದಿ (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = ರಿಕ್ತ; /* transferred */
			nstrs = 0;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ oClearAllForwardings:
		intptr = &options->clear_forwardings;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ oHost:
		ಯದಿ (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			ಗಚ್ಛ out;
		}
		*activep = 0;
		arg2 = ರಿಕ್ತ;
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			ಯದಿ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ಗಚ್ಛ out;
			}
			ಯದಿ ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				ಭಙ್ಗ;
			}
			negated = *arg == '!';
			ಯದಿ (negated)
				arg++;
			ಯದಿ (match_pattern(host, arg)) {
				ಯದಿ (negated) {
					debug("%.200s line %d: Skipping Host "
					    "block because of negated match "
					    "for %.100s", filename, linenum,
					    arg);
					*activep = 0;
					argv_consume(&ac);
					ಭಙ್ಗ;
				}
				ಯದಿ (!*activep)
					arg2 = arg; /* logged below */
				*activep = 1;
			}
		}
		ಯದಿ (*activep)
			debug("%.200s line %d: Applying options for %.100s",
			    filename, linenum, arg2);
		ಭಙ್ಗ;

	ಪಕ್ಷ oMatch:
		ಯದಿ (cmdline) {
			error("Match directive not supported as a command-line "
			    "option");
			ಗಚ್ಛ out;
		}
		ಮೌಲ್ಯ = match_cfg_ಸಾಲು(options, str, &ac, &av, pw, host,
		    original_host, remote_command, flags & SSHCONF_FINAL,
		    want_final_pass, filename, linenum);
		ಯದಿ (ಮೌಲ್ಯ < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			ಗಚ್ಛ out;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		ಯದಿ (strcmp(arg, "none") == 0)
			ಮೌಲ್ಯ = SSH_ESCAPECHAR_NONE;
		ಅನ್ಯಥಾ ಯದಿ (arg[1] == '\0')
			ಮೌಲ್ಯ = (u_char) arg[0];
		ಅನ್ಯಥಾ ಯದಿ (arg[0] == '^' && arg[2] == 0 &&
		    (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			ಮೌಲ್ಯ = (u_char) arg[1] & 31;
		ಅನ್ಯಥಾ {
			error("%.200s line %d: Bad escape character.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		ಯದಿ (*activep && *intptr == -1)
			*intptr = ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ oAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ oIdentitiesOnly:
		intptr = &options->identities_only;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ oServerAliveInterval:
		intptr = &options->server_alive_interval;
		ಗಚ್ಛ parse_time;

	ಪಕ್ಷ o_Server_Alive_ಎಣಿಕೆ_Max:
		intptr = &options->server_alive_ಎಣಿಕೆ_max;
		ಗಚ್ಛ parse_int;

	ಪಕ್ಷ oSendEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			ಯದಿ (*arg == '\0' || strchr(arg, '=') != ರಿಕ್ತ) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				ಗಚ್ಛ out;
			}
			found = 1;
			ಯದಿ (!*activep)
				ಅನುವರ್ತ;
			ಯದಿ (*arg == '-') {
				/* Removing an env var */
				rm_env(options, arg, filename, linenum);
				ಅನುವರ್ತ;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->ಅಂಕೆ_send_env, arg);
		}
		ಯದಿ (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ oSetEnv:
		found = options->ಅಂಕೆ_setenv == 0;
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			ಯದಿ (strchr(arg, '=') == ರಿಕ್ತ) {
				error("%s line %d: Invalid SetEnv.",
				    filename, linenum);
				ಗಚ್ಛ out;
			}
			ಯದಿ (lookup_setenv_in_list(arg, strs, nstrs) != ರಿಕ್ತ) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				ಅನುವರ್ತ;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg);
		}
		ಯದಿ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಯದಿ (found && *activep) {
			options->setenv = strs;
			options->ಅಂಕೆ_setenv = nstrs;
			strs = ರಿಕ್ತ; /* transferred */
			nstrs = 0;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ oControlPath:
		charptr = &options->control_path;
		ಗಚ್ಛ parse_string;

	ಪಕ್ಷ oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing ControlPersist"
			    " argument.", filename, linenum);
			ಗಚ್ಛ out;
		}
		ಮೌಲ್ಯ = 0;
		value2 = 0;	/* timeout */
		ಯದಿ (strcmp(arg, "no") == 0 || strcmp(arg, "false") == 0)
			ಮೌಲ್ಯ = 0;
		ಅನ್ಯಥಾ ಯದಿ (strcmp(arg, "yes") == 0 || strcmp(arg, "true") == 0)
			ಮೌಲ್ಯ = 1;
		ಅನ್ಯಥಾ ಯದಿ ((value2 = convtime(arg)) >= 0)
			ಮೌಲ್ಯ = 1;
		ಅನ್ಯಥಾ {
			error("%.200s line %d: Bad ControlPersist argument.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		ಯದಿ (*activep && *intptr == -1) {
			*intptr = ಮೌಲ್ಯ;
			options->control_persist_timeout = value2;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ oHashKnownHosts:
		intptr = &options->hash_known_hosts;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ oTunnelDevice:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		ಮೌಲ್ಯ = a2tun(arg, &value2);
		ಯದಿ (ಮೌಲ್ಯ == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		ಯದಿ (*activep && options->tun_local == -1) {
			options->tun_local = ಮೌಲ್ಯ;
			options->tun_remote = value2;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ oLocalCommand:
		charptr = &options->local_command;
		ಗಚ್ಛ parse_command;

	ಪಕ್ಷ oPermitLocalCommand:
		intptr = &options->permit_local_command;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ oRemoteCommand:
		charptr = &options->remote_command;
		ಗಚ್ಛ parse_command;

	ಪಕ್ಷ o_Visual_Host_ಕೀಲಿ:
		intptr = &options->visual_host_ಕೀಲಿ;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ oInclude:
		ಯದಿ (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			ಗಚ್ಛ out;
		}
		ಮೌಲ್ಯ = 0;
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			ಯದಿ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ಗಚ್ಛ out;
			}
			/* Expand %tokens and environment variables */
			ಯದಿ ((p = expand_match_exec_or_include_path(arg,
			    options, pw, host, original_host,
			    flags & SSHCONF_FINAL, 1)) == ರಿಕ್ತ) {
				error("%.200s line %d: Unable to expand user "
				    "config file '%.100s'",
				    filename, linenum, arg);
				ಅನುವರ್ತ;
			}
			/*
			 * Ensure all paths are anchored. User configuration
			 * files may begin with '~/' but system configurations
			 * must not. If the path is relative, then treat it
			 * as living in ~/.ssh for user configurations or
			 * /etc/ssh for system ones.
			 */
			ಯದಿ (*p == '~' && (flags & SSHCONF_USERCONF) == 0) {
				error("%.200s line %d: bad include path %s.",
				    filename, linenum, p);
				ಗಚ್ಛ out;
			}
			ಯದಿ (!path_absolute(p) && *p != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" _PATH_SSH_USER_DIR : SSHDIR, p);
			} ಅನ್ಯಥಾ {
				arg2 = xstrdup(p);
			}
			ಮುಕ್ತ(p);
			memset(&gl, 0, ಪರಿಮಾಣ(gl));
			r = glob(arg2, GLOB_TILDE, ರಿಕ್ತ, &gl);
			ಯದಿ (r == GLOB_NOMATCH) {
				debug("%.200s line %d: include %s matched no "
				    "files",filename, linenum, arg2);
				ಮುಕ್ತ(arg2);
				ಅನುವರ್ತ;
			} ಅನ್ಯಥಾ ಯದಿ (r != 0) {
				error("%.200s line %d: glob failed for %s.",
				    filename, linenum, arg2);
				ಗಚ್ಛ out;
			}
			ಮುಕ್ತ(arg2);
			oactive = *activep;
			ಪ್ರತಿ (i = 0; i < gl.gl_pathc; i++) {
				debug3("%.200s line %d: Including file %s "
				    "depth %d%s", filename, linenum,
				    gl.gl_pathv[i], depth,
				    oactive ? "" : " (parse only)");
				r = read_config_file_depth(gl.gl_pathv[i],
				    pw, host, original_host, remote_command,
				    options, flags | SSHCONF_CHECKPERM |
				    (oactive ? 0 : SSHCONF_NEVERMATCH),
				    activep, want_final_pass, depth + 1);
				ಯದಿ (r != 1 && errno != ENOENT) {
					error("%.200s line %d: Can't open user "
					    "config file %.100s: %.100s",
					    filename, linenum, gl.gl_pathv[i],
					    strerror(errno));
					globfree(&gl);
					ಗಚ್ಛ out;
				}
				/*
				 * don't let Match in includes clobber the
				 * containing file's Match state.
				 */
				*activep = oactive;
				ಯದಿ (r != 1)
					ಮೌಲ್ಯ = -1;
			}
			globfree(&gl);
		}
		ಯದಿ (ಮೌಲ್ಯ != 0)
			ret = ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ oIPQoS:
		arg = argv_next(&ac, &av);
		ಯದಿ ((ಮೌಲ್ಯ = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			ಗಚ್ಛ out;
		}
		ಯದಿ (ಮೌಲ್ಯ == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			ಮೌಲ್ಯ = INT_MAX;
		}
		arg = argv_next(&ac, &av);
		ಯದಿ (arg == ರಿಕ್ತ)
			value2 = ಮೌಲ್ಯ;
		ಅನ್ಯಥಾ ಯದಿ ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			ಗಚ್ಛ out;
		}
		ಯದಿ (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		ಯದಿ (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = ಮೌಲ್ಯ;
			options->ip_qos_bulk = value2;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ oSessionType:
		intptr = &options->session_type;
		multistate_ptr = multistate_sessiontype;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ oStdinNull:
		intptr = &options->stdin_null;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ oForkAfterAuthentication:
		intptr = &options->fork_after_authentication;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		ಗಚ್ಛ parse_string;

	ಪಕ್ಷ oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ oCanonicalDomains:
		found = options->ಅಂಕೆ_canonical_domains == 0;
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			/* Allow "none" only in first position */
			ಯದಿ (strcasecmp(arg, "none") == 0) {
				ಯದಿ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ಗಚ್ಛ out;
				}
			}
			ಯದಿ (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				ಗಚ್ಛ out;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ಯದಿ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಯದಿ (found && *activep) {
			options->canonical_domains = strs;
			options->ಅಂಕೆ_canonical_domains = nstrs;
			strs = ರಿಕ್ತ; /* transferred */
			nstrs = 0;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ oCanonicalizePermittedCNAMEs:
		found = options->ಅಂಕೆ_permitted_cnames == 0;
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			ಯದಿ (strcasecmp(arg, "none") == 0) {
				ಯದಿ (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ಗಚ್ಛ out;
				}
				arg2 = "";
			} ಅನ್ಯಥಾ ಯದಿ (strcmp(arg, "*") == 0) {
				arg2 = arg;
			} ಅನ್ಯಥಾ {
				lowercase(arg);
				ಯದಿ ((arg2 = strchr(arg, ':')) == ರಿಕ್ತ ||
				    arg2[1] == '\0') {
					error("%s line %d: "
					    "Invalid permitted CNAME \"%s\"",
					    filename, linenum, arg);
					ಗಚ್ಛ out;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    ಪರಿಮಾಣ(*cnames));
			cnames[ncnames].source_list = xstrdup(arg);
			cnames[ncnames].target_list = xstrdup(arg2);
			ncnames++;
		}
		ಯದಿ (ncnames == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಯದಿ (found && *activep) {
			options->permitted_cnames = cnames;
			options->ಅಂಕೆ_permitted_cnames = ncnames;
			cnames = ರಿಕ್ತ; /* transferred */
			ncnames = 0;
		}
		/* un-transferred cnames is cleaned up before exit */
		ಭಙ್ಗ;

	ಪಕ್ಷ oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		ಗಚ್ಛ parse_int;

	ಪಕ್ಷ oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ oStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			ಗಚ್ಛ out;
		}
		/* Parse mode in octal format */
		ಮೌಲ್ಯ = strtol(arg, &endofnumber, 8);
		ಯದಿ (arg == endofnumber || ಮೌಲ್ಯ < 0 || ಮೌಲ್ಯ > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			ಗಚ್ಛ out;
		}
		ಯದಿ (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ oStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ o_Revoked_Host_ಕೀಲಿಗಳು:
		uintptr = &options->ಅಂಕೆ_revoked_host_ಕೀಲಿಗಳು;
		cppptr = &options->revoked_host_ಕೀಲಿಗಳು;
		found = *uintptr == 0;
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			ಯದಿ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ಗಚ್ಛ out;
			}
			/* Allow "none" only in first position */
			ಯದಿ (strcasecmp(arg, "none") == 0) {
				ಯದಿ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ಗಚ್ಛ out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ಯದಿ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಯದಿ (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = ರಿಕ್ತ; /* transferred */
			nstrs = 0;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		ಯದಿ ((ಮೌಲ್ಯ = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			ಗಚ್ಛ out;
		}
		ಯದಿ (*activep && *intptr == -1)
			*intptr = ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ oUpdateHostkeys:
		intptr = &options->update_hostkeys;
		multistate_ptr = multistate_yesnoask;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ oHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
		ಗಚ್ಛ parse_pubkey_algos;

	ಪಕ್ಷ oPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		ಗಚ್ಛ parse_pubkey_algos;

	ಪಕ್ಷ o_Add_ಕೀಲಿಗಳು_To_Agent:
		arg = argv_next(&ac, &av);
		arg2 = argv_next(&ac, &av);
		ಮೌಲ್ಯ = parse_multistate_ಮೌಲ್ಯ(arg, filename, linenum,
		    multistate_yesnoaskconfirm);
		value2 = 0; /* unlimited lifespan by default */
		ಯದಿ (ಮೌಲ್ಯ == 3 && arg2 != ರಿಕ್ತ) {
			/* allow "AddKeysToAgent confirm 5m" */
			ಯದಿ ((value2 = convtime(arg2)) == -1) {
				error("%s line %d: invalid time value.",
				    filename, linenum);
				ಗಚ್ಛ out;
			}
		} ಅನ್ಯಥಾ ಯದಿ (ಮೌಲ್ಯ == -1 && arg2 == ರಿಕ್ತ) {
			ಯದಿ ((value2 = convtime(arg)) == -1) {
				error("%s line %d: unsupported option",
				    filename, linenum);
				ಗಚ್ಛ out;
			}
			ಮೌಲ್ಯ = 1; /* yes */
		} ಅನ್ಯಥಾ ಯದಿ (ಮೌಲ್ಯ == -1 || arg2 != ರಿಕ್ತ) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		ಯದಿ (*activep && options->add_ಕೀಲಿಗಳು_to_agent == -1) {
			options->add_ಕೀಲಿಗಳು_to_agent = ಮೌಲ್ಯ;
			options->add_ಕೀಲಿಗಳು_to_agent_lifespan = value2;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ oIdentityAgent:
		charptr = &options->identity_agent;
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
  parse_agent_path:
		/* Extra validation if the string represents an env var. */
		ಯದಿ ((arg2 = dollar_expand(&r, arg)) == ರಿಕ್ತ || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			ಗಚ್ಛ out;
		}
		ಮುಕ್ತ(arg2);
		/* check for legacy environment format */
		ಯದಿ (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			ಗಚ್ಛ out;
		}
		ಯದಿ (*activep && *charptr == ರಿಕ್ತ)
			*charptr = xstrdup(arg);
		ಭಙ್ಗ;

	ಪಕ್ಷ oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		ಗಚ್ಛ parse_flag;

	ಪಕ್ಷ oRequiredRSASize:
		intptr = &options->required_rsa_size;
		ಗಚ್ಛ parse_int;

	ಪಕ್ಷ oWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		ಗಚ್ಛ parse_multistate;

	ಪಕ್ಷ oObscureKeystrokeTiming:
		ಮೌಲ್ಯ = -1;
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			ಯದಿ (ಮೌಲ್ಯ != -1) {
				error("%s line %d: invalid arguments",
				    filename, linenum);
				ಗಚ್ಛ out;
			}
			ಯದಿ (strcmp(arg, "yes") == 0 ||
			    strcmp(arg, "true") == 0)
				ಮೌಲ್ಯ = SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
			ಅನ್ಯಥಾ ಯದಿ (strcmp(arg, "no") == 0 ||
			    strcmp(arg, "false") == 0)
				ಮೌಲ್ಯ = 0;
			ಅನ್ಯಥಾ ಯದಿ (strncmp(arg, "interval:", 9) == 0) {
				ಯದಿ ((errstr = atoi_err(arg + 9,
				    &ಮೌಲ್ಯ)) != ರಿಕ್ತ) {
					error("%s line %d: integer value %s.",
					    filename, linenum, errstr);
					ಗಚ್ಛ out;
				}
				ಯದಿ (ಮೌಲ್ಯ <= 0 || ಮೌಲ್ಯ > 1000) {
					error("%s line %d: value out of range.",
					    filename, linenum);
					ಗಚ್ಛ out;
				}
			} ಅನ್ಯಥಾ {
				error("%s line %d: unsupported argument \"%s\"",
				    filename, linenum, arg);
				ಗಚ್ಛ out;
			}
		}
		ಯದಿ (ಮೌಲ್ಯ == -1) {
			error("%s line %d: missing argument",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		intptr = &options->obscure_keystroke_timing_interval;
		ಯದಿ (*activep && *intptr == -1)
			*intptr = ಮೌಲ್ಯ;
		ಭಙ್ಗ;

	ಪಕ್ಷ oChannelTimeout:
		found = options->ಅಂಕೆ_channel_timeouts == 0;
		ಯಾವತ್ ((arg = argv_next(&ac, &av)) != ರಿಕ್ತ) {
			/* Allow "none" only in first position */
			ಯದಿ (strcasecmp(arg, "none") == 0) {
				ಯದಿ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ಗಚ್ಛ out;
				}
			} ಅನ್ಯಥಾ ಯದಿ (parse_pattern_interval(arg,
			    ರಿಕ್ತ, ರಿಕ್ತ) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ಯದಿ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಯದಿ (found && *activep) {
			options->channel_timeouts = strs;
			options->ಅಂಕೆ_channel_timeouts = nstrs;
			strs = ರಿಕ್ತ; /* transferred */
			nstrs = 0;
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ oVersionAddendum:
		ಯದಿ (str == ರಿಕ್ತ || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		ಯದಿ (strchr(str + len, '\r') != ರಿಕ್ತ) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		ಯದಿ ((arg = strchr(ಸಾಲು, '#')) != ರಿಕ್ತ) {
			*arg = '\0';
			rtrim(ಸಾಲು);
		}
		ಯದಿ (*activep && options->version_addendum == ರಿಕ್ತ) {
			ಯದಿ (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			ಅನ್ಯಥಾ
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		ಭಙ್ಗ;

	ಪಕ್ಷ oRefuseConnection:
		arg = argv_next(&ac, &av);
		ಯದಿ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಗಚ್ಛ out;
		}
		ಯದಿ (*activep) {
			fatal("%.200s line %d: RefuseConnection: %s",
			    filename, linenum, arg);
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		ಭಙ್ಗ;

	ಪಕ್ಷ oUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		ಭಙ್ಗ;

	ಸ್ವಭಾವ:
		error("%s line %d: Unimplemented opcode %d",
		    filename, linenum, opcode);
		ಗಚ್ಛ out;
	}

	/* Check that there is no garbage at end of line. */
	ಯದಿ (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		ಗಚ್ಛ out;
	}

	/* success */
	ret = 0;
 out:
	free_canon_cnames(cnames, ncnames);
	opt_array_free2(strs, ರಿಕ್ತ, nstrs);
	argv_free(oav, oac);
	ಪ್ರತ್ಯಾಗಮ ret;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */
ಪೂರ್ಣಾಙ್ಕ
read_config_file(ಧ್ರುವ ವರ್ಣ *filename, ಸಂರಚನಾ passwd *pw, ಧ್ರುವ ವರ್ಣ *host,
    ಧ್ರುವ ವರ್ಣ *original_host, ಧ್ರುವ ವರ್ಣ *remote_command, Options *options, ಪೂರ್ಣಾಙ್ಕ flags,
    ಪೂರ್ಣಾಙ್ಕ *want_final_pass)
{
	ಪೂರ್ಣಾಙ್ಕ active = 1;

	ಪ್ರತ್ಯಾಗಮ read_config_file_depth(filename, pw, host, original_host,
	    remote_command, options, flags, &active, want_final_pass, 0);
}

#define READCONF_MAX_DEPTH	16
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
read_config_file_depth(ಧ್ರುವ ವರ್ಣ *filename, ಸಂರಚನಾ passwd *pw,
    ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *original_host, ಧ್ರುವ ವರ್ಣ *remote_command,
    Options *options, ಪೂರ್ಣಾಙ್ಕ flags, ಪೂರ್ಣಾಙ್ಕ *activep, ಪೂರ್ಣಾಙ್ಕ *want_final_pass, ಪೂರ್ಣಾಙ್ಕ depth)
{
	FILE *f;
	ವರ್ಣ *ಸಾಲು = ರಿಕ್ತ;
	size_t linesize = 0;
	ಪೂರ್ಣಾಙ್ಕ linenum;
	ಪೂರ್ಣಾಙ್ಕ bad_options = 0;

	ಯದಿ (depth < 0 || depth > READCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	ಯದಿ ((f = fopen(filename, "r")) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;

	ಯದಿ (flags & SSHCONF_CHECKPERM) {
		ಸಂರಚನಾ stat sb;

		ಯದಿ (fstat(fileno(f), &sb) == -1)
			fatal("fstat %s: %s", filename, strerror(errno));
		ಯದಿ (((sb.st_uid != 0 && sb.st_uid != getuid()) ||
		    (sb.st_mode & 022) != 0))
			fatal("Bad owner or permissions on %s", filename);
	}

	debug("Reading configuration data %.200s", filename);

	/*
	 * Mark that we are now processing the options.  This flag is turned
	 * on/off by Host specifications.
	 */
	linenum = 0;
	ಯಾವತ್ (getline(&ಸಾಲು, &linesize, f) != -1) {
		/* Update line number counter. */
		linenum++;
		/*
		 * Trim out comments and strip whitespace.
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages.
		 */
		ಯದಿ (process_config_ಸಾಲು_depth(options, pw, host, original_host,
		    remote_command, ಸಾಲು, filename, linenum, activep, flags,
		    want_final_pass, depth) != 0)
			bad_options++;
	}
	ಮುಕ್ತ(ಸಾಲು);
	fclose(f);
	ಯದಿ (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
	ಪ್ರತ್ಯಾಗಮ 1;
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
ಪೂರ್ಣಾಙ್ಕ
option_clear_or_none(ಧ್ರುವ ವರ್ಣ *o)
{
	ಪ್ರತ್ಯಾಗಮ o == ರಿಕ್ತ || strcasecmp(o, "none") == 0;
}

/*
 * Returns 1 if CanonicalizePermittedCNAMEs have been specified, 0 otherwise.
 * Allowed to be called on non-final configuration.
 */
ಪೂರ್ಣಾಙ್ಕ
config_has_permitted_cnames(Options *options)
{
	ಯದಿ (options->ಅಂಕೆ_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].source_list, "none") == 0 &&
	    strcmp(options->permitted_cnames[0].target_list, "") == 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ options->ಅಂಕೆ_permitted_cnames > 0;
}

/*
 * Initializes options to special values that indicate that they have not yet
 * been set.  Read_config_file will only set options with this value. Options
 * are processed in the following order: command line, user config file,
 * system config file.  Last, fill_default_options is called.
 */

ಶೂನ್ಯ
initialize_options(Options * options)
{
	memset(options, 'X', ಪರಿಮಾಣ(*options));
	options->host_arg = ರಿಕ್ತ;
	options->forward_agent = -1;
	options->forward_agent_sock_path = ರಿಕ್ತ;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = ರಿಕ್ತ;
	options->stdio_forward_port = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = ರಿಕ್ತ;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_mask = (mode_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = ರಿಕ್ತ;
	options->hostbased_authentication = -1;
	options->batch_mode = -1;
	options->check_host_ip = -1;
	options->strict_host_ಕೀಲಿ_checking = -1;
	options->compression = -1;
	options->tcp_keep_alive = -1;
	options->port = -1;
	options->address_family = -1;
	options->connection_attempts = -1;
	options->connection_timeout = -1;
	options->ಸಂಖ್ಯೆ_of_password_prompts = -1;
	options->ciphers = ರಿಕ್ತ;
	options->macs = ರಿಕ್ತ;
	options->kex_algorithms = ರಿಕ್ತ;
	options->hostkeyalgorithms = ರಿಕ್ತ;
	options->ca_sign_algorithms = ರಿಕ್ತ;
	options->ಅಂಕೆ_identity_files = 0;
	memset(options->identity_ಕೀಲಿಗಳು, 0, ಪರಿಮಾಣ(options->identity_ಕೀಲಿಗಳು));
	options->ಅಂಕೆ_certificate_files = 0;
	memset(options->certificates, 0, ಪರಿಮಾಣ(options->certificates));
	options->hostname = ರಿಕ್ತ;
	options->host_ಕೀಲಿ_alias = ರಿಕ್ತ;
	options->proxy_command = ರಿಕ್ತ;
	options->jump_user = ರಿಕ್ತ;
	options->jump_host = ರಿಕ್ತ;
	options->jump_port = -1;
	options->jump_extra = ರಿಕ್ತ;
	options->user = ರಿಕ್ತ;
	options->escape_char = -1;
	options->ಅಂಕೆ_system_hostfiles = 0;
	options->ಅಂಕೆ_user_hostfiles = 0;
	options->local_forwards = ರಿಕ್ತ;
	options->ಅಂಕೆ_local_forwards = 0;
	options->remote_forwards = ರಿಕ್ತ;
	options->ಅಂಕೆ_remote_forwards = 0;
	options->permitted_remote_opens = ರಿಕ್ತ;
	options->ಅಂಕೆ_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
	options->log_level = SYSLOG_LEVEL_NOT_SET;
	options->ಅಂಕೆ_log_verbose = 0;
	options->log_verbose = ರಿಕ್ತ;
	options->preferred_authentications = ರಿಕ್ತ;
	options->bind_address = ರಿಕ್ತ;
	options->bind_interface = ರಿಕ್ತ;
	options->pkcs11_provider = ರಿಕ್ತ;
	options->sk_provider = ರಿಕ್ತ;
	options->enable_ssh_keysign = -1;
	options->no_host_authentication_for_localhost = -1;
	options->identities_only = -1;
	options->rekey_limit = -1;
	options->rekey_interval = -1;
	options->verify_host_ಕೀಲಿ_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_ಎಣಿಕೆ_max = -1;
	options->send_env = ರಿಕ್ತ;
	options->ಅಂಕೆ_send_env = 0;
	options->setenv = ರಿಕ್ತ;
	options->ಅಂಕೆ_setenv = 0;
	options->control_path = ರಿಕ್ತ;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_known_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = ರಿಕ್ತ;
	options->permit_local_command = -1;
	options->remote_command = ರಿಕ್ತ;
	options->add_ಕೀಲಿಗಳು_to_agent = -1;
	options->add_ಕೀಲಿಗಳು_to_agent_lifespan = -1;
	options->identity_agent = ರಿಕ್ತ;
	options->visual_host_ಕೀಲಿ = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = ರಿಕ್ತ;
	options->ಅಂಕೆ_canonical_domains = 0;
	options->ಅಂಕೆ_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_ಕೀಲಿಗಳು = ರಿಕ್ತ;
	options->ಅಂಕೆ_revoked_host_ಕೀಲಿಗಳು = 0;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->hostbased_accepted_algos = ರಿಕ್ತ;
	options->pubkey_accepted_algos = ರಿಕ್ತ;
	options->known_hosts_command = ರಿಕ್ತ;
	options->required_rsa_size = -1;
	options->warn_weak_crypto = -1;
	options->enable_escape_commandline = -1;
	options->obscure_keystroke_timing_interval = -1;
	options->tag = ರಿಕ್ತ;
	options->channel_timeouts = ರಿಕ್ತ;
	options->ಅಂಕೆ_channel_timeouts = 0;
	options->version_addendum = ರಿಕ್ತ;
}

/*
 * A petite version of fill_default_options() that just fills the options
 * needed for hostname canonicalization to proceed.
 */
ಶೂನ್ಯ
fill_default_options_for_canonicalization(Options *options)
{
	ಯದಿ (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	ಯದಿ (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	ಯದಿ (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
}

/*
 * Called after processing other sources of option data, this fills those
 * options for which no value has been specified with their default values.
 */
ಪೂರ್ಣಾಙ್ಕ
fill_default_options(Options * options)
{
	ವರ್ಣ *all_cipher, *all_mac, *all_kex, *all_ಕೀಲಿ, *all_sig;
	ವರ್ಣ *def_cipher, *def_mac, *def_kex, *def_ಕೀಲಿ, *def_sig;
	ಪೂರ್ಣಾಙ್ಕ ret = -1, r;

	ಯದಿ (options->forward_agent == -1)
		options->forward_agent = 0;
	ಯದಿ (options->forward_x11 == -1)
		options->forward_x11 = 0;
	ಯದಿ (options->forward_x11_trusted == -1)
		options->forward_x11_trusted = 0;
	ಯದಿ (options->forward_x11_timeout == -1)
		options->forward_x11_timeout = 1200;
	/*
	 * stdio forwarding (-W) changes the default for these but we defer
	 * setting the values so they can be overridden.
	 */
	ಯದಿ (options->exit_on_forward_failure == -1)
		options->exit_on_forward_failure =
		    options->stdio_forward_host != ರಿಕ್ತ ? 1 : 0;
	ಯದಿ (options->clear_forwardings == -1)
		options->clear_forwardings =
		    options->stdio_forward_host != ರಿಕ್ತ ? 1 : 0;
	ಯದಿ (options->clear_forwardings == 1)
		clear_forwardings(options);

	ಯದಿ (options->xauth_location == ರಿಕ್ತ)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	ಯದಿ (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	ಯದಿ (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	ಯದಿ (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	ಯದಿ (options->pubkey_authentication == -1)
		options->pubkey_authentication = SSH_PUBKEY_AUTH_ALL;
	ಯದಿ (options->gss_authentication == -1)
		options->gss_authentication = 0;
	ಯದಿ (options->gss_deleg_creds == -1)
		options->gss_deleg_creds = 0;
	ಯದಿ (options->password_authentication == -1)
		options->password_authentication = 1;
	ಯದಿ (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	ಯದಿ (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	ಯದಿ (options->batch_mode == -1)
		options->batch_mode = 0;
	ಯದಿ (options->check_host_ip == -1)
		options->check_host_ip = 0;
	ಯದಿ (options->strict_host_ಕೀಲಿ_checking == -1)
		options->strict_host_ಕೀಲಿ_checking = SSH_STRICT_HOSTKEY_ASK;
	ಯದಿ (options->compression == -1)
		options->compression = 0;
	ಯದಿ (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = SSH_KEEPALIVES_TRANSPORT;
	ಯದಿ (options->port == -1)
		options->port = 0;	/* Filled in ssh_connect. */
	ಯದಿ (options->address_family == -1)
		options->address_family = AF_UNSPEC;
	ಯದಿ (options->connection_attempts == -1)
		options->connection_attempts = 1;
	ಯದಿ (options->ಸಂಖ್ಯೆ_of_password_prompts == -1)
		options->ಸಂಖ್ಯೆ_of_password_prompts = 3;
	/* options->hostkeyalgorithms, default set in myproposals.h */
	ಯದಿ (options->add_ಕೀಲಿಗಳು_to_agent == -1) {
		options->add_ಕೀಲಿಗಳು_to_agent = 0;
		options->add_ಕೀಲಿಗಳು_to_agent_lifespan = 0;
	}
	ಯದಿ (options->ಅಂಕೆ_identity_files == 0) {
		add_identity_file(options, "~/", _PATH_SSH_CLIENT_ID_RSA, 0);
		add_identity_file(options, "~/", _PATH_SSH_CLIENT_ID_ECDSA, 0);
		add_identity_file(options, "~/",
		    _PATH_SSH_CLIENT_ID_ECDSA_SK, 0);
		add_identity_file(options, "~/",
		    _PATH_SSH_CLIENT_ID_ED25519, 0);
		add_identity_file(options, "~/",
		    _PATH_SSH_CLIENT_ID_ED25519_SK, 0);
		add_identity_file(options, "~/",
		    _PATH_SSH_CLIENT_ID_MLDSA44_ED25519, 0);
	}
	ಯದಿ (options->escape_char == -1)
		options->escape_char = '~';
	ಯದಿ (options->ಅಂಕೆ_system_hostfiles == 0) {
		options->system_hostfiles[options->ಅಂಕೆ_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->ಅಂಕೆ_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE2);
	}
	ಯದಿ (options->update_hostkeys == -1) {
		ಯದಿ (options->verify_host_ಕೀಲಿ_dns <= 0 &&
		    (options->ಅಂಕೆ_user_hostfiles == 0 ||
		    (options->ಅಂಕೆ_user_hostfiles == 1 && strcmp(options->
		    user_hostfiles[0], _PATH_SSH_USER_HOSTFILE) == 0)))
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_YES;
		ಅನ್ಯಥಾ
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_NO;
	}
	ಯದಿ (options->ಅಂಕೆ_user_hostfiles == 0) {
		options->user_hostfiles[options->ಅಂಕೆ_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->ಅಂಕೆ_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE2);
	}
	ಯದಿ (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	ಯದಿ (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_USER;
	ಯದಿ (options->no_host_authentication_for_localhost == -1)
		options->no_host_authentication_for_localhost = 0;
	ಯದಿ (options->identities_only == -1)
		options->identities_only = 0;
	ಯದಿ (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	ಯದಿ (options->rekey_limit == -1)
		options->rekey_limit = 0;
	ಯದಿ (options->rekey_interval == -1)
		options->rekey_interval = 0;
	ಯದಿ (options->verify_host_ಕೀಲಿ_dns == -1)
		options->verify_host_ಕೀಲಿ_dns = 0;
	ಯದಿ (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	ಯದಿ (options->server_alive_ಎಣಿಕೆ_max == -1)
		options->server_alive_ಎಣಿಕೆ_max = 3;
	ಯದಿ (options->control_master == -1)
		options->control_master = 0;
	ಯದಿ (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	ಯದಿ (options->hash_known_hosts == -1)
		options->hash_known_hosts = 0;
	ಯದಿ (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	ಯದಿ (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	ಯದಿ (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	ಯದಿ (options->permit_local_command == -1)
		options->permit_local_command = 0;
	ಯದಿ (options->visual_host_ಕೀಲಿ == -1)
		options->visual_host_ಕೀಲಿ = 0;
	ಯದಿ (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	ಯದಿ (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	ಯದಿ (options->request_tty == -1)
		options->request_tty = REQUEST_TTY_AUTO;
	ಯದಿ (options->session_type == -1)
		options->session_type = SESSION_TYPE_DEFAULT;
	ಯದಿ (options->stdin_null == -1)
		options->stdin_null = 0;
	ಯದಿ (options->fork_after_authentication == -1)
		options->fork_after_authentication = 0;
	ಯದಿ (options->proxy_use_fdpass == -1)
		options->proxy_use_fdpass = 0;
	ಯದಿ (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	ಯದಿ (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	ಯದಿ (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
	ಯದಿ (options->fingerprint_hash == -1)
		options->fingerprint_hash = SSH_FP_HASH_DEFAULT;
#ifdef ENABLE_SK_INTERNAL
	ಯದಿ (options->sk_provider == ರಿಕ್ತ)
		options->sk_provider = xstrdup("internal");
#ಅನ್ಯಥಾ
	ಯದಿ (options->sk_provider == ರಿಕ್ತ)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
#endif
	ಯದಿ (options->required_rsa_size == -1)
		options->required_rsa_size = SSH_RSA_MINIMUM_MODULUS_SIZE;
	ಯದಿ (options->warn_weak_crypto == -1)
		options->warn_weak_crypto = 1;
	ಯದಿ (options->enable_escape_commandline == -1)
		options->enable_escape_commandline = 0;
	ಯದಿ (options->obscure_keystroke_timing_interval == -1) {
		options->obscure_keystroke_timing_interval =
		    SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
	}

	/* Expand KEX name lists */
	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_ಕೀಲಿ = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_CLIENT_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_CLIENT_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_CLIENT_KEX, all_kex);
	def_ಕೀಲಿ = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_ಕೀಲಿ);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	ಕುರು { \
		ಯದಿ ((r = kex_assemble_names(&options->what, \
		    defaults, all)) != 0) { \
			error_fr(r, "%s", #what); \
			ಗಚ್ಛ fail; \
		} \
	} ಯಾವತ್ (0)
	options->kex_algorithms_set = options->kex_algorithms != ರಿಕ್ತ;
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostbased_accepted_algos, def_ಕೀಲಿ, all_ಕೀಲಿ);
	ASSEMBLE(pubkey_accepted_algos, def_ಕೀಲಿ, all_ಕೀಲಿ);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE

#define CLEAR_ON_NONE(v) \
	ಕುರು { \
		ಯದಿ (option_clear_or_none(v)) { \
			ಮುಕ್ತ(v); \
			v = ರಿಕ್ತ; \
		} \
	} ಯಾವತ್(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	ಕುರು { \
		ಯದಿ (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			ಮುಕ್ತ(options->v[0]); \
			ಮುಕ್ತ(options->v); \
			options->v = ರಿಕ್ತ; \
			options->nv = 0; \
		} \
	} ಯಾವತ್ (0)
	CLEAR_ON_NONE(options->local_command);
	CLEAR_ON_NONE(options->remote_command);
	CLEAR_ON_NONE(options->proxy_command);
	CLEAR_ON_NONE(options->control_path);
	CLEAR_ON_NONE(options->pkcs11_provider);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->known_hosts_command);
	CLEAR_ON_NONE_ARRAY(channel_timeouts, ಅಂಕೆ_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(revoked_host_ಕೀಲಿಗಳು, ಅಂಕೆ_revoked_host_ಕೀಲಿಗಳು, "none");
#undef CLEAR_ON_NONE
#undef CLEAR_ON_NONE_ARRAY
	ಯದಿ (options->jump_host != ರಿಕ್ತ &&
	    strcmp(options->jump_host, "none") == 0 &&
	    options->jump_port == 0 && options->jump_user == ರಿಕ್ತ) {
		ಮುಕ್ತ(options->jump_host);
		options->jump_host = ರಿಕ್ತ;
	}
	ಯದಿ (options->ಅಂಕೆ_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		ಮುಕ್ತ(options->permitted_cnames[0].source_list);
		ಮುಕ್ತ(options->permitted_cnames[0].target_list);
		memset(options->permitted_cnames, '\0',
		    ಪರಿಮಾಣ(*options->permitted_cnames));
		options->ಅಂಕೆ_permitted_cnames = 0;
	}
	/* options->identity_agent distinguishes NULL from 'none' */
	/* options->user will be set in the main program if appropriate */
	/* options->hostname will be set in the main program if appropriate */
	/* options->host_key_alias should not be set by default */
	/* options->preferred_authentications will be set in ssh */

	/* success */
	ret = 0;
 fail:
	ಮುಕ್ತ(all_cipher);
	ಮುಕ್ತ(all_mac);
	ಮುಕ್ತ(all_kex);
	ಮುಕ್ತ(all_ಕೀಲಿ);
	ಮುಕ್ತ(all_sig);
	ಮುಕ್ತ(def_cipher);
	ಮುಕ್ತ(def_mac);
	ಮುಕ್ತ(def_kex);
	ಮುಕ್ತ(def_ಕೀಲಿ);
	ಮುಕ್ತ(def_sig);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಶೂನ್ಯ
free_options(Options *o)
{
	ಪೂರ್ಣಾಙ್ಕ i;

	ಯದಿ (o == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;

#define FREE_ARRAY(type, n, a) \
	ಕುರು { \
		type _i; \
		ಪ್ರತಿ (_i = 0; _i < (n); _i++) \
			ಮುಕ್ತ((a)[_i]); \
	} ಯಾವತ್ (0)

	ಮುಕ್ತ(o->forward_agent_sock_path);
	ಮುಕ್ತ(o->xauth_location);
	FREE_ARRAY(u_int, o->ಅಂಕೆ_log_verbose, o->log_verbose);
	ಮುಕ್ತ(o->log_verbose);
	ಮುಕ್ತ(o->ciphers);
	ಮುಕ್ತ(o->macs);
	ಮುಕ್ತ(o->hostkeyalgorithms);
	ಮುಕ್ತ(o->kex_algorithms);
	ಮುಕ್ತ(o->ca_sign_algorithms);
	ಮುಕ್ತ(o->hostname);
	ಮುಕ್ತ(o->host_ಕೀಲಿ_alias);
	ಮುಕ್ತ(o->proxy_command);
	ಮುಕ್ತ(o->user);
	FREE_ARRAY(u_int, o->ಅಂಕೆ_system_hostfiles, o->system_hostfiles);
	FREE_ARRAY(u_int, o->ಅಂಕೆ_user_hostfiles, o->user_hostfiles);
	ಮುಕ್ತ(o->preferred_authentications);
	ಮುಕ್ತ(o->bind_address);
	ಮುಕ್ತ(o->bind_interface);
	ಮುಕ್ತ(o->pkcs11_provider);
	ಮುಕ್ತ(o->sk_provider);
	ಪ್ರತಿ (i = 0; i < o->ಅಂಕೆ_identity_files; i++) {
		ಮುಕ್ತ(o->identity_files[i]);
		sshkey_free(o->identity_ಕೀಲಿಗಳು[i]);
	}
	ಪ್ರತಿ (i = 0; i < o->ಅಂಕೆ_certificate_files; i++) {
		ಮುಕ್ತ(o->certificate_files[i]);
		sshkey_free(o->certificates[i]);
	}
	ಮುಕ್ತ(o->identity_agent);
	ಪ್ರತಿ (i = 0; i < o->ಅಂಕೆ_local_forwards; i++) {
		ಮುಕ್ತ(o->local_forwards[i].listen_host);
		ಮುಕ್ತ(o->local_forwards[i].listen_path);
		ಮುಕ್ತ(o->local_forwards[i].connect_host);
		ಮುಕ್ತ(o->local_forwards[i].connect_path);
	}
	ಮುಕ್ತ(o->local_forwards);
	ಪ್ರತಿ (i = 0; i < o->ಅಂಕೆ_remote_forwards; i++) {
		ಮುಕ್ತ(o->remote_forwards[i].listen_host);
		ಮುಕ್ತ(o->remote_forwards[i].listen_path);
		ಮುಕ್ತ(o->remote_forwards[i].connect_host);
		ಮುಕ್ತ(o->remote_forwards[i].connect_path);
	}
	ಮುಕ್ತ(o->remote_forwards);
	ಮುಕ್ತ(o->stdio_forward_host);
	FREE_ARRAY(u_int, o->ಅಂಕೆ_send_env, o->send_env);
	ಮುಕ್ತ(o->send_env);
	FREE_ARRAY(u_int, o->ಅಂಕೆ_setenv, o->setenv);
	ಮುಕ್ತ(o->setenv);
	ಮುಕ್ತ(o->control_path);
	ಮುಕ್ತ(o->local_command);
	ಮುಕ್ತ(o->remote_command);
	FREE_ARRAY(ಪೂರ್ಣಾಙ್ಕ, o->ಅಂಕೆ_canonical_domains, o->canonical_domains);
	ಪ್ರತಿ (i = 0; i < o->ಅಂಕೆ_permitted_cnames; i++) {
		ಮುಕ್ತ(o->permitted_cnames[i].source_list);
		ಮುಕ್ತ(o->permitted_cnames[i].target_list);
	}
	FREE_ARRAY(u_int, o->ಅಂಕೆ_revoked_host_ಕೀಲಿಗಳು, o->revoked_host_ಕೀಲಿಗಳು);
	ಮುಕ್ತ(o->revoked_host_ಕೀಲಿಗಳು);
	ಮುಕ್ತ(o->hostbased_accepted_algos);
	ಮುಕ್ತ(o->pubkey_accepted_algos);
	ಮುಕ್ತ(o->jump_user);
	ಮುಕ್ತ(o->jump_host);
	ಮುಕ್ತ(o->jump_extra);
	ಮುಕ್ತ(o->ignored_unknown);
	explicit_bzero(o, ಪರಿಮಾಣ(*o));
#undef FREE_ARRAY
}

ಸಂರಚನಾ fwdarg {
	ವರ್ಣ *arg;
	ಪೂರ್ಣಾಙ್ಕ ispath;
};

/*
 * parse_fwd_field
 * parses the next field in a port forwarding specification.
 * sets fwd to the parsed field and advances p past the colon
 * or sets it to NULL at end of string.
 * returns 0 on success, else non-zero.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_fwd_field(ವರ್ಣ **p, ಸಂರಚನಾ fwdarg *fwd)
{
	ವರ್ಣ *ep, *cp = *p;
	ಪೂರ್ಣಾಙ್ಕ ispath = 0;

	ಯದಿ (*cp == '\0') {
		*p = ರಿಕ್ತ;
		ಪ್ರತ್ಯಾಗಮ -1;	/* end of string */
	}

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	ಯದಿ (*cp == '[') {
		/* find matching ']' */
		ಪ್ರತಿ (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++) {
			ಯದಿ (*ep == '/')
				ispath = 1;
		}
		/* no matching ']' or not at end of field. */
		ಯದಿ (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			ಪ್ರತ್ಯಾಗಮ -1;
		/* NUL terminate the field and advance p past the colon */
		*ep++ = '\0';
		ಯದಿ (*ep != '\0')
			*ep++ = '\0';
		fwd->arg = cp + 1;
		fwd->ispath = ispath;
		*p = ep;
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	ಪ್ರತಿ (cp = *p; *cp != '\0'; cp++) {
		ವಿಕಲ್ಪ (*cp) {
		ಪಕ್ಷ '\\':
			memmove(cp, cp + 1, strlen(cp + 1) + 1);
			ಯದಿ (*cp == '\0')
				ಪ್ರತ್ಯಾಗಮ -1;
			ಭಙ್ಗ;
		ಪಕ್ಷ '/':
			ispath = 1;
			ಭಙ್ಗ;
		ಪಕ್ಷ ':':
			*cp++ = '\0';
			ಗಚ್ಛ done;
		}
	}
done:
	fwd->arg = *p;
	fwd->ispath = ispath;
	*p = cp;
	ಪ್ರತ್ಯಾಗಮ 0;
}

/*
 * parse_forward
 * parses a string containing a port forwarding specification of the form:
 *   dynamicfwd == 0
 *	[listenhost:]listenport|listenpath:connecthost:connectport|connectpath
 *	listenpath:connectpath
 *   dynamicfwd == 1
 *	[listenhost:]listenport
 * returns number of arguments parsed or zero on error
 */
ಪೂರ್ಣಾಙ್ಕ
parse_forward(ಸಂರಚನಾ Forward *fwd, ಧ್ರುವ ವರ್ಣ *fwdspec, ಪೂರ್ಣಾಙ್ಕ dynamicfwd, ಪೂರ್ಣಾಙ್ಕ remotefwd)
{
	ಸಂರಚನಾ fwdarg fwdargs[4];
	ವರ್ಣ *p, *cp;
	ಪೂರ್ಣಾಙ್ಕ i, err;

	memset(fwd, 0, ಪರಿಮಾಣ(*fwd));
	memset(fwdargs, 0, ಪರಿಮಾಣ(fwdargs));

	/*
	 * We expand environment variables before checking if we think they're
	 * paths so that if ${VAR} expands to a fully qualified path it is
	 * treated as a path.
	 */
	cp = p = dollar_expand(&err, fwdspec);
	ಯದಿ (p == ರಿಕ್ತ || err)
		ಪ್ರತ್ಯಾಗಮ 0;

	/* skip leading spaces */
	ಯಾವತ್ (isspace((u_char)*cp))
		cp++;

	ಪ್ರತಿ (i = 0; i < 4; ++i) {
		ಯದಿ (parse_fwd_field(&cp, &fwdargs[i]) != 0)
			ಭಙ್ಗ;
	}

	/* Check for trailing garbage */
	ಯದಿ (cp != ರಿಕ್ತ && *cp != '\0') {
		i = 0;	/* failure */
	}

	ವಿಕಲ್ಪ (i) {
	ಪಕ್ಷ 1:
		ಯದಿ (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
		} ಅನ್ಯಥಾ {
			fwd->listen_host = ರಿಕ್ತ;
			fwd->listen_port = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		ಭಙ್ಗ;

	ಪಕ್ಷ 2:
		ಯದಿ (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} ಅನ್ಯಥಾ ಯದಿ (fwdargs[1].ispath) {
			fwd->listen_host = ರಿಕ್ತ;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} ಅನ್ಯಥಾ {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ 3:
		ಯದಿ (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		} ಅನ್ಯಥಾ ಯದಿ (fwdargs[2].ispath) {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_path = xstrdup(fwdargs[2].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} ಅನ್ಯಥಾ {
			fwd->listen_host = ರಿಕ್ತ;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		}
		ಭಙ್ಗ;

	ಪಕ್ಷ 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_port = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_port = a2port(fwdargs[3].arg);
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		i = 0; /* failure */
	}

	ಮುಕ್ತ(p);

	ಯದಿ (dynamicfwd) {
		ಯದಿ (!(i == 1 || i == 2))
			ಗಚ್ಛ fail_free;
	} ಅನ್ಯಥಾ {
		ಯದಿ (!(i == 3 || i == 4)) {
			ಯದಿ (fwd->connect_path == ರಿಕ್ತ &&
			    fwd->listen_path == ರಿಕ್ತ)
				ಗಚ್ಛ fail_free;
		}
		ಯದಿ (fwd->connect_port <= 0 && fwd->connect_path == ರಿಕ್ತ)
			ಗಚ್ಛ fail_free;
	}

	ಯದಿ ((fwd->listen_port < 0 && fwd->listen_path == ರಿಕ್ತ) ||
	    (!remotefwd && fwd->listen_port == 0))
		ಗಚ್ಛ fail_free;
	ಯದಿ (fwd->connect_host != ರಿಕ್ತ &&
	    strlen(fwd->connect_host) >= NI_MAXHOST)
		ಗಚ್ಛ fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	ಯದಿ (fwd->connect_path != ರಿಕ್ತ &&
	    strlen(fwd->connect_path) >= PATH_MAX_SUN)
		ಗಚ್ಛ fail_free;
	ಯದಿ (fwd->listen_host != ರಿಕ್ತ &&
	    strlen(fwd->listen_host) >= NI_MAXHOST)
		ಗಚ್ಛ fail_free;
	ಯದಿ (fwd->listen_path != ರಿಕ್ತ &&
	    strlen(fwd->listen_path) >= PATH_MAX_SUN)
		ಗಚ್ಛ fail_free;

	ಪ್ರತ್ಯಾಗಮ (i);

 fail_free:
	ಮುಕ್ತ(fwd->connect_host);
	fwd->connect_host = ರಿಕ್ತ;
	ಮುಕ್ತ(fwd->connect_path);
	fwd->connect_path = ರಿಕ್ತ;
	ಮುಕ್ತ(fwd->listen_host);
	fwd->listen_host = ರಿಕ್ತ;
	ಮುಕ್ತ(fwd->listen_path);
	fwd->listen_path = ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ (0);
}

ಪೂರ್ಣಾಙ್ಕ
ssh_valid_hostname(ಧ್ರುವ ವರ್ಣ *s)
{
	size_t i;

	ಯದಿ (*s == '-')
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತಿ (i = 0; s[i] != 0; i++) {
		ಯದಿ (strchr("'`\"$\\;&<>|(){},", s[i]) != ರಿಕ್ತ ||
		    isspace((u_char)s[i]) || iscntrl((u_char)s[i]))
			ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_valid_ruser(ಧ್ರುವ ವರ್ಣ *s)
{
	size_t i;

	ಯದಿ (*s == '-')
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತಿ (i = 0; s[i] != 0; i++) {
		ಯದಿ (iscntrl((u_char)s[i]))
			ಪ್ರತ್ಯಾಗಮ 0;
		ಯದಿ (strchr("'`\";&<>|(){}$\\", s[i]) != ರಿಕ್ತ)
			ಪ್ರತ್ಯಾಗಮ 0;
		/* Disallow '-' after whitespace */
		ಯದಿ (isspace((u_char)s[i]) && s[i + 1] == '-')
			ಪ್ರತ್ಯಾಗಮ 0;
	}
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಪೂರ್ಣಾಙ್ಕ
parse_jump(ಧ್ರುವ ವರ್ಣ *s, Options *o, ಪೂರ್ಣಾಙ್ಕ strict, ಪೂರ್ಣಾಙ್ಕ active)
{
	ವರ್ಣ *orig = ರಿಕ್ತ, *sdup = ರಿಕ್ತ, *cp;
	ವರ್ಣ *tmp_user = ರಿಕ್ತ, *tmp_host = ರಿಕ್ತ, *host = ರಿಕ್ತ, *user = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, ret = -1, tmp_port = -1, port = -1, first = 1;

	ಯದಿ (strcasecmp(s, "none") == 0) {
		ಯದಿ (active && o->jump_host == ರಿಕ್ತ) {
			o->jump_host = xstrdup("none");
			o->jump_port = 0;
		}
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	orig = xstrdup(s);
	ಯದಿ ((cp = strchr(orig, '#')) != ರಿಕ್ತ)
		*cp = '\0';
	rtrim(orig);

	active &= o->proxy_command == ರಿಕ್ತ && o->jump_host == ರಿಕ್ತ;
	sdup = xstrdup(orig);
	ಕುರು {
		/* Work backwards through string */
		ಯದಿ ((cp = strrchr(sdup, ',')) == ರಿಕ್ತ)
			cp = sdup; /* last */
		ಅನ್ಯಥಾ
			*cp++ = '\0';

		r = parse_ssh_uri(cp, &tmp_user, &tmp_host, &tmp_port);
		ಯದಿ (r == -1 || (r == 1 && parse_user_host_port(cp,
		    &tmp_user, &tmp_host, &tmp_port) != 0))
			ಗಚ್ಛ out; /* error already logged */
		ಯದಿ (strict) {
			ಯದಿ (!ssh_valid_hostname(tmp_host)) {
				error_f("invalid hostname \"%s\"", tmp_host);
				ಗಚ್ಛ out;
			}
			ಯದಿ (tmp_user != ರಿಕ್ತ && !ssh_valid_ruser(tmp_user)) {
				error_f("invalid username \"%s\"", tmp_user);
				ಗಚ್ಛ out;
			}
		}
		ಯದಿ (first) {
			user = tmp_user;
			host = tmp_host;
			port = tmp_port;
			tmp_user = tmp_host = ರಿಕ್ತ; /* transferred */
		}
		first = 0; /* only check syntax for subsequent hosts */
		ಮುಕ್ತ(tmp_user);
		ಮುಕ್ತ(tmp_host);
		tmp_user = tmp_host = ರಿಕ್ತ;
		tmp_port = -1;
	} ಯಾವತ್ (cp != sdup);

	/* success */
	ಯದಿ (active) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_port = port;
		o->proxy_command = xstrdup("none");
		user = host = ರಿಕ್ತ; /* transferred */
		ಯದಿ (orig != ರಿಕ್ತ && (cp = strrchr(orig, ',')) != ರಿಕ್ತ) {
			o->jump_extra = xstrdup(orig);
			o->jump_extra[cp - orig] = '\0';
		}
	}
	ret = 0;
 out:
	ಮುಕ್ತ(orig);
	ಮುಕ್ತ(sdup);
	ಮುಕ್ತ(tmp_user);
	ಮುಕ್ತ(tmp_host);
	ಮುಕ್ತ(user);
	ಮುಕ್ತ(host);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
parse_ssh_uri(ಧ್ರುವ ವರ್ಣ *uri, ವರ್ಣ **userp, ವರ್ಣ **hostp, ಪೂರ್ಣಾಙ್ಕ *portp)
{
	ವರ್ಣ *user = ರಿಕ್ತ, *host = ರಿಕ್ತ, *path = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, port;

	r = parse_uri("ssh", uri, &user, &host, &port, &path);
	ಯದಿ (r == 0 && path != ರಿಕ್ತ)
		r = -1;		/* path not allowed */
	ಯದಿ (r == 0) {
		ಯದಿ (userp != ರಿಕ್ತ) {
			*userp = user;
			user = ರಿಕ್ತ;
		}
		ಯದಿ (hostp != ರಿಕ್ತ) {
			*hostp = host;
			host = ರಿಕ್ತ;
		}
		ಯದಿ (portp != ರಿಕ್ತ)
			*portp = port;
	}
	ಮುಕ್ತ(user);
	ಮುಕ್ತ(host);
	ಮುಕ್ತ(path);
	ಪ್ರತ್ಯಾಗಮ r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
fmt_multistate_int(ಪೂರ್ಣಾಙ್ಕ val, ಧ್ರುವ ಸಂರಚನಾ multistate *m)
{
	u_int i;

	ಪ್ರತಿ (i = 0; m[i].ಕೀಲಿ != ರಿಕ್ತ; i++) {
		ಯದಿ (m[i].ಮೌಲ್ಯ == val)
			ಪ್ರತ್ಯಾಗಮ m[i].ಕೀಲಿ;
	}
	ಪ್ರತ್ಯಾಗಮ "UNKNOWN";
}

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
fmt_intarg(OpCodes code, ಪೂರ್ಣಾಙ್ಕ val)
{
	ಯದಿ (val == -1)
		ಪ್ರತ್ಯಾಗಮ "unset";
	ವಿಕಲ್ಪ (code) {
	ಪಕ್ಷ oAddressFamily:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_addressfamily);
	ಪಕ್ಷ oCompression:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_compression);
	ಪಕ್ಷ o_Verify_Host_ಕೀಲಿ_DNS:
	ಪಕ್ಷ oUpdateHostkeys:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_yesnoask);
	ಪಕ್ಷ o_Strict_Host_ಕೀಲಿ_Checking:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_strict_hostkey);
	ಪಕ್ಷ oControlMaster:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_controlmaster);
	ಪಕ್ಷ oTunnel:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_tunnel);
	ಪಕ್ಷ oRequestTTY:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_requesttty);
	ಪಕ್ಷ oSessionType:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_sessiontype);
	ಪಕ್ಷ oCanonicalizeHostname:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_canonicalizehostname);
	ಪಕ್ಷ o_Add_ಕೀಲಿಗಳು_To_Agent:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_yesnoaskconfirm);
	ಪಕ್ಷ oPubkeyAuthentication:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_pubkey_auth);
	ಪಕ್ಷ oTCPKeepAlive:
		ಪ್ರತ್ಯಾಗಮ fmt_multistate_int(val, multistate_keepalives);
	ಪಕ್ಷ oFingerprintHash:
		ಪ್ರತ್ಯಾಗಮ ssh_digest_alg_name(val);
	ಸ್ವಭಾವ:
		ವಿಕಲ್ಪ (val) {
		ಪಕ್ಷ 0:
			ಪ್ರತ್ಯಾಗಮ "no";
		ಪಕ್ಷ 1:
			ಪ್ರತ್ಯಾಗಮ "yes";
		ಸ್ವಭಾವ:
			ಪ್ರತ್ಯಾಗಮ "UNKNOWN";
		}
	}
}

ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
lookup_opcode_name(OpCodes code)
{
	u_int i;

	ಪ್ರತಿ (i = 0; keywords[i].name != ರಿಕ್ತ; i++)
		ಯದಿ (keywords[i].opcode == code)
			ಪ್ರತ್ಯಾಗಮ(keywords[i].name);
	ಪ್ರತ್ಯಾಗಮ "UNKNOWN";
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_int(OpCodes code, ಪೂರ್ಣಾಙ್ಕ val)
{
	ಯದಿ (code == oObscureKeystrokeTiming) {
		ಯದಿ (val == 0) {
			printf("%s no\n", lookup_opcode_name(code));
			ಪ್ರತ್ಯಾಗಮ;
		} ಅನ್ಯಥಾ ಯದಿ (val == SSH_KEYSTROKE_DEFAULT_INTERVAL_MS) {
			printf("%s yes\n", lookup_opcode_name(code));
			ಪ್ರತ್ಯಾಗಮ;
		}
		/* FALLTHROUGH */
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_fmtint(OpCodes code, ಪೂರ್ಣಾಙ್ಕ val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_string(OpCodes code, ಧ್ರುವ ವರ್ಣ *val)
{
	ಯದಿ (val == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	printf("%s %s\n", lookup_opcode_name(code), val);
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_strarray(OpCodes code, u_int ಎಣಿಕೆ, ವರ್ಣ **vals)
{
	u_int i;

	ಪ್ರತಿ (i = 0; i < ಎಣಿಕೆ; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_strarray_oneline(OpCodes code, u_int ಎಣಿಕೆ, ವರ್ಣ **vals)
{
	u_int i;

	printf("%s", lookup_opcode_name(code));
	ಯದಿ (ಎಣಿಕೆ == 0)
		printf(" none");
	ಪ್ರತಿ (i = 0; i < ಎಣಿಕೆ; i++)
		printf(" %s",  vals[i]);
	printf("\n");
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_forwards(OpCodes code, u_int ಎಣಿಕೆ, ಧ್ರುವ ಸಂರಚನಾ Forward *fwds)
{
	ಧ್ರುವ ಸಂರಚನಾ Forward *fwd;
	u_int i;

	/* oDynamicForward */
	ಪ್ರತಿ (i = 0; i < ಎಣಿಕೆ; i++) {
		fwd = &fwds[i];
		ಯದಿ (code == oDynamicForward && fwd->connect_host != ರಿಕ್ತ &&
		    strcmp(fwd->connect_host, "socks") != 0)
			ಅನುವರ್ತ;
		ಯದಿ (code == oLocalForward && fwd->connect_host != ರಿಕ್ತ &&
		    strcmp(fwd->connect_host, "socks") == 0)
			ಅನುವರ್ತ;
		printf("%s", lookup_opcode_name(code));
		ಯದಿ (fwd->listen_port == PORT_STREAMLOCAL)
			printf(" %s", fwd->listen_path);
		ಅನ್ಯಥಾ ಯದಿ (fwd->listen_host == ರಿಕ್ತ)
			printf(" %d", fwd->listen_port);
		ಅನ್ಯಥಾ {
			printf(" [%s]:%d",
			    fwd->listen_host, fwd->listen_port);
		}
		ಯದಿ (code != oDynamicForward) {
			ಯದಿ (fwd->connect_port == PORT_STREAMLOCAL)
				printf(" %s", fwd->connect_path);
			ಅನ್ಯಥಾ ಯದಿ (fwd->connect_host == ರಿಕ್ತ)
				printf(" %d", fwd->connect_port);
			ಅನ್ಯಥಾ {
				printf(" [%s]:%d",
				    fwd->connect_host, fwd->connect_port);
			}
		}
		printf("\n");
	}
}

ಶೂನ್ಯ
dump_client_config(Options *o, ಧ್ರುವ ವರ್ಣ *host)
{
	ಪೂರ್ಣಾಙ್ಕ i, r;
	ವರ್ಣ buf[8], *all_ಕೀಲಿ;

	/*
	 * Expand HostKeyAlgorithms name lists. This isn't handled in
	 * fill_default_options() like the other algorithm lists because
	 * the host key algorithms are by default dynamically chosen based
	 * on the host's keys found in known_hosts.
	 */
	all_ಕೀಲಿ = sshkey_alg_list(0, 0, 1, ',');
	ಯದಿ ((r = kex_assemble_names(&o->hostkeyalgorithms, kex_default_pk_alg(),
	    all_ಕೀಲಿ)) != 0)
		fatal_fr(r, "expand HostKeyAlgorithms");
	ಮುಕ್ತ(all_ಕೀಲಿ);

	/* Most interesting options first: user, host, port */
	dump_cfg_string(oHost, o->host_arg);
	dump_cfg_string(oUser, o->user);
	dump_cfg_string(oHostname, host);
	dump_cfg_int(oPort, o->port);

	/* Flag options */
	dump_cfg_fmtint(oAddressFamily, o->address_family);
	dump_cfg_fmtint(oBatchMode, o->batch_mode);
	dump_cfg_fmtint(oCanonicalizeFallbackLocal, o->canonicalize_fallback_local);
	dump_cfg_fmtint(oCanonicalizeHostname, o->canonicalize_hostname);
	dump_cfg_fmtint(oCheckHostIP, o->check_host_ip);
	dump_cfg_fmtint(oCompression, o->compression);
	dump_cfg_fmtint(oControlMaster, o->control_master);
	dump_cfg_fmtint(oEnableSSHKeysign, o->enable_ssh_keysign);
	dump_cfg_fmtint(oClearAllForwardings, o->clear_forwardings);
	dump_cfg_fmtint(oExitOnForwardFailure, o->exit_on_forward_failure);
	dump_cfg_fmtint(oFingerprintHash, o->fingerprint_hash);
	dump_cfg_fmtint(oForwardX11, o->forward_x11);
	dump_cfg_fmtint(oForwardX11Trusted, o->forward_x11_trusted);
	dump_cfg_fmtint(oGatewayPorts, o->fwd_opts.gateway_ports);
#ifdef GSSAPI
	dump_cfg_fmtint(oGssAuthentication, o->gss_authentication);
	dump_cfg_fmtint(oGssDelegateCreds, o->gss_deleg_creds);
#endif /* GSSAPI */
	dump_cfg_fmtint(oHashKnownHosts, o->hash_known_hosts);
	dump_cfg_fmtint(oHostbasedAuthentication, o->hostbased_authentication);
	dump_cfg_fmtint(oIdentitiesOnly, o->identities_only);
	dump_cfg_fmtint(oKbdInteractiveAuthentication, o->kbd_interactive_authentication);
	dump_cfg_fmtint(oNoHostAuthenticationForLocalhost, o->no_host_authentication_for_localhost);
	dump_cfg_fmtint(oPasswordAuthentication, o->password_authentication);
	dump_cfg_fmtint(oPermitLocalCommand, o->permit_local_command);
	dump_cfg_fmtint(oProxyUseFdpass, o->proxy_use_fdpass);
	dump_cfg_fmtint(oPubkeyAuthentication, o->pubkey_authentication);
	dump_cfg_fmtint(oRequestTTY, o->request_tty);
	dump_cfg_fmtint(oSessionType, o->session_type);
	dump_cfg_fmtint(oStdinNull, o->stdin_null);
	dump_cfg_fmtint(oForkAfterAuthentication, o->fork_after_authentication);
	dump_cfg_fmtint(oStreamLocalBindUnlink, o->fwd_opts.streamlocal_bind_unlink);
	dump_cfg_fmtint(o_Strict_Host_ಕೀಲಿ_Checking, o->strict_host_ಕೀಲಿ_checking);
	dump_cfg_fmtint(oTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(oTunnel, o->tun_open);
	dump_cfg_fmtint(o_Verify_Host_ಕೀಲಿ_DNS, o->verify_host_ಕೀಲಿ_dns);
	dump_cfg_fmtint(o_Visual_Host_ಕೀಲಿ, o->visual_host_ಕೀಲಿ);
	dump_cfg_fmtint(oUpdateHostkeys, o->update_hostkeys);
	dump_cfg_fmtint(oEnableEscapeCommandline, o->enable_escape_commandline);
	dump_cfg_fmtint(oWarnWeakCrypto, o->warn_weak_crypto);

	/* Integer options */
	dump_cfg_int(oCanonicalizeMaxDots, o->canonicalize_max_dots);
	dump_cfg_int(oConnectionAttempts, o->connection_attempts);
	dump_cfg_int(oForwardX11Timeout, o->forward_x11_timeout);
	dump_cfg_int(o_ಸಂಖ್ಯೆ_Of_Password_Prompts, o->ಸಂಖ್ಯೆ_of_password_prompts);
	dump_cfg_int(o_Server_Alive_ಎಣಿಕೆ_Max, o->server_alive_ಎಣಿಕೆ_max);
	dump_cfg_int(oServerAliveInterval, o->server_alive_interval);
	dump_cfg_int(oRequiredRSASize, o->required_rsa_size);
	dump_cfg_int(oObscureKeystrokeTiming,
	    o->obscure_keystroke_timing_interval);

	/* String options */
	dump_cfg_string(oBindAddress, o->bind_address);
	dump_cfg_string(oBindInterface, o->bind_interface);
	dump_cfg_string(oCiphers, o->ciphers);
	dump_cfg_string(oControlPath, o->control_path);
	dump_cfg_string(o_Host_ಕೀಲಿ_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(o_Host_ಕೀಲಿ_Alias, o->host_ಕೀಲಿ_alias);
	dump_cfg_string(oHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(oIdentityAgent, o->identity_agent);
	dump_cfg_string(oIgnoreUnknown, o->ignored_unknown);
	dump_cfg_string(oKbdInteractiveDevices, o->kbd_interactive_devices);
	dump_cfg_string(oKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(oCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(oLocalCommand, o->local_command);
	dump_cfg_string(oRemoteCommand, o->remote_command);
	dump_cfg_string(oLogLevel, log_level_name(o->log_level));
	dump_cfg_string(oMacs, o->macs);
#ifdef ENABLE_PKCS11
	dump_cfg_string(oPKCS11Provider, o->pkcs11_provider);
#endif
	dump_cfg_string(o_Security_ಕೀಲಿ_Provider, o->sk_provider);
	dump_cfg_string(oPreferredAuthentications, o->preferred_authentications);
	dump_cfg_string(oPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
	dump_cfg_string(oXAuthLocation, o->xauth_location);
	dump_cfg_string(oKnownHostsCommand, o->known_hosts_command);
	dump_cfg_string(oTag, o->tag);
	dump_cfg_string(oVersionAddendum, o->version_addendum);

	/* Forwards */
	dump_cfg_forwards(oDynamicForward, o->ಅಂಕೆ_local_forwards, o->local_forwards);
	dump_cfg_forwards(oLocalForward, o->ಅಂಕೆ_local_forwards, o->local_forwards);
	dump_cfg_forwards(oRemoteForward, o->ಅಂಕೆ_remote_forwards, o->remote_forwards);

	/* String array options */
	dump_cfg_strarray(oIdentityFile, o->ಅಂಕೆ_identity_files, o->identity_files);
	dump_cfg_strarray_oneline(oCanonicalDomains, o->ಅಂಕೆ_canonical_domains, o->canonical_domains);
	dump_cfg_strarray(oCertificateFile, o->ಅಂಕೆ_certificate_files, o->certificate_files);
	dump_cfg_strarray_oneline(oGlobalKnownHostsFile, o->ಅಂಕೆ_system_hostfiles, o->system_hostfiles);
	dump_cfg_strarray_oneline(oUserKnownHostsFile, o->ಅಂಕೆ_user_hostfiles, o->user_hostfiles);
	dump_cfg_strarray_oneline(o_Revoked_Host_ಕೀಲಿಗಳು, o->ಅಂಕೆ_revoked_host_ಕೀಲಿಗಳು, o->revoked_host_ಕೀಲಿಗಳು);
	dump_cfg_strarray(oSendEnv, o->ಅಂಕೆ_send_env, o->send_env);
	dump_cfg_strarray(oSetEnv, o->ಅಂಕೆ_setenv, o->setenv);
	dump_cfg_strarray_oneline(oLogVerbose,
	    o->ಅಂಕೆ_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(oChannelTimeout,
	    o->ಅಂಕೆ_channel_timeouts, o->channel_timeouts);

	/* Special cases */

	/* PermitRemoteOpen */
	ಯದಿ (o->ಅಂಕೆ_permitted_remote_opens == 0)
		printf("%s any\n", lookup_opcode_name(oPermitRemoteOpen));
	ಅನ್ಯಥಾ
		dump_cfg_strarray_oneline(oPermitRemoteOpen,
		    o->ಅಂಕೆ_permitted_remote_opens, o->permitted_remote_opens);

	/* AddKeysToAgent */
	ಯದಿ (o->add_ಕೀಲಿಗಳು_to_agent_lifespan <= 0)
		dump_cfg_fmtint(o_Add_ಕೀಲಿಗಳು_To_Agent, o->add_ಕೀಲಿಗಳು_to_agent);
	ಅನ್ಯಥಾ {
		printf("addkeystoagent%s %d\n",
		    o->add_ಕೀಲಿಗಳು_to_agent == 3 ? " confirm" : "",
		    o->add_ಕೀಲಿಗಳು_to_agent_lifespan);
	}

	/* oForwardAgent */
	ಯದಿ (o->forward_agent_sock_path == ರಿಕ್ತ)
		dump_cfg_fmtint(oForwardAgent, o->forward_agent);
	ಅನ್ಯಥಾ
		dump_cfg_string(oForwardAgent, o->forward_agent_sock_path);

	/* oConnectTimeout */
	ಯದಿ (o->connection_timeout == -1)
		printf("connecttimeout none\n");
	ಅನ್ಯಥಾ
		dump_cfg_int(oConnectTimeout, o->connection_timeout);

	/* oTunnelDevice */
	printf("tunneldevice");
	ಯದಿ (o->tun_local == SSH_TUNID_ANY)
		printf(" any");
	ಅನ್ಯಥಾ
		printf(" %d", o->tun_local);
	ಯದಿ (o->tun_remote == SSH_TUNID_ANY)
		printf(":any");
	ಅನ್ಯಥಾ
		printf(":%d", o->tun_remote);
	printf("\n");

	/* oCanonicalizePermittedCNAMEs */
	printf("canonicalizepermittedcnames");
	ಯದಿ (o->ಅಂಕೆ_permitted_cnames == 0)
		printf(" none");
	ಪ್ರತಿ (i = 0; i < o->ಅಂಕೆ_permitted_cnames; i++) {
		printf(" %s:%s", o->permitted_cnames[i].source_list,
		    o->permitted_cnames[i].target_list);
	}
	printf("\n");

	/* oControlPersist */
	ಯದಿ (o->control_persist == 0 || o->control_persist_timeout == 0)
		dump_cfg_fmtint(oControlPersist, o->control_persist);
	ಅನ್ಯಥಾ
		dump_cfg_int(oControlPersist, o->control_persist_timeout);

	/* oEscapeChar */
	ಯದಿ (o->escape_char == SSH_ESCAPECHAR_NONE)
		printf("escapechar none\n");
	ಅನ್ಯಥಾ {
		vis(buf, o->escape_char, VIS_WHITE, 0);
		printf("escapechar %s\n", buf);
	}

	/* oIPQoS */
	printf("ipqos %s ", iptos2str(o->ip_qos_interactive));
	printf("%s\n", iptos2str(o->ip_qos_bulk));

	/* oRekeyLimit */
	printf("rekeylimit %llu %d\n",
	    (unsigned long long)o->rekey_limit, o->rekey_interval);

	/* oStreamLocalBindMask */
	printf("streamlocalbindmask 0%o\n",
	    o->fwd_opts.streamlocal_bind_mask);

	/* oLogFacility */
	printf("syslogfacility %s\n", log_facility_name(o->log_facility));

	/* oProxyCommand / oProxyJump */
	ಯದಿ (o->jump_host == ರಿಕ್ತ)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	ಅನ್ಯಥಾ {
		/* Check for numeric addresses */
		i = strchr(o->jump_host, ':') != ರಿಕ್ತ ||
		    strspn(o->jump_host, "1234567890.") == strlen(o->jump_host);
		snprintf(buf, ಪರಿಮಾಣ(buf), "%d", o->jump_port);
		printf("proxyjump %s%s%s%s%s%s%s%s%s\n",
		    /* optional additional jump spec */
		    o->jump_extra == ರಿಕ್ತ ? "" : o->jump_extra,
		    o->jump_extra == ರಿಕ್ತ ? "" : ",",
		    /* optional user */
		    o->jump_user == ರಿಕ್ತ ? "" : o->jump_user,
		    o->jump_user == ರಿಕ್ತ ? "" : "@",
		    /* opening [ if hostname is numeric */
		    i ? "[" : "",
		    /* mandatory hostname */
		    o->jump_host,
		    /* closing ] if hostname is numeric */
		    i ? "]" : "",
		    /* optional port number */
		    o->jump_port <= 0 ? "" : ":",
		    o->jump_port <= 0 ? "" : buf);
	}
}
