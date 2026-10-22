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
#ಆದರೆ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#ಆದರೆ_ಅಂತ್ಯ

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

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ read_config_file_ಆಳ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ರಚನೆ passwd *pw,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *original_host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_command,
    Options *options, ಪೂರ್ಣಾಂಕ flags, ಪೂರ್ಣಾಂಕ *activep, ಪೂರ್ಣಾಂಕ *want_final_pass, ಪೂರ್ಣಾಂಕ ಆಳ);
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ process_config_ಸಾಲು_ಆಳ(Options *options, ರಚನೆ passwd *pw,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *original_host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_command,
    ಅಕ್ಷರ *ಸಾಲು, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಪೂರ್ಣಾಂಕ linenum, ಪೂರ್ಣಾಂಕ *activep, ಪೂರ್ಣಾಂಕ flags,
    ಪೂರ್ಣಾಂಕ *want_final_pass, ಪೂರ್ಣಾಂಕ ಆಳ);

/* Keyword tokens. */

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಎಣಿಕೆ {
	oBadOption,
	oHost, o_ಹೊಂದಿಕೆ, oInclude, o_ಟ್ಯಾಗ್,
	oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout,
	oGatewayPorts, oExitOnForwardFailure,
	oPasswordAuthentication,
	oXAuthLocation,
	o_ತಟಸ್ಥ_File, oHostname, o_ಪೋರ್ಟ್, oRemoteForward, oLocalForward,
	oPermitRemoteOpen,
	oCertificateFile, o_ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_Agent, o_ತಟಸ್ಥ_Agent,
	oUser, oEscapeChar, oProxyCommand,
	o_Global_ತಿಳಿದ_Hosts_File, o_User_ತಿಳಿದ_Hosts_File, oConnectionAttempts,
	o_Batch_ಬಹುಲಕ, oCheckHostIP, o_Strict_Host_ಕೀಲಿ_Checking, oCompression,
	oTCPKeepAlive, o_ಸಂಖ್ಯೆ_ದ_Password_Prompts,
	oLogFacility, oLogLevel, oLogVerbose, oCiphers, oMacs,
	oPubkeyAuthentication,
	oKbdInteractiveAuthentication, oKbdInteractiveDevices, o_Host_ಕೀಲಿ_Alias,
	oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication,
	o_Host_ಕೀಲಿ_Algorithms, o_Bind_ವಿಳಾಸ, oBindInterface, oPKCS11Provider,
	oClearAllForwardings, oNoHostAuthenticationForLocalhost,
	oEnableSSHKeysign, o_Rekey_ಎಲ್ಲೆ, o_Verify_Host_ಕೀಲಿ_DNS, oConnectTimeout,
	o_ವಿಳಾಸ_Family, oGssAuthentication, oGssDelegateCreds,
	oServerAliveInterval, o_Server_Alive_ಎಣಿಕೆ_Max, oIdentitiesOnly,
	oSendEnv, o_ಗಣ_Env, o_Control_ಮಾರ್ಗ, oControlMaster, oControlPersist,
	o_Hash_ತಿಳಿದ_Hosts,
	oTunnel, oTunnelDevice,
	oLocalCommand, oPermitLocalCommand, oRemoteCommand,
	o_Visual_Host_ಕೀಲಿ,
	oKexAlgorithms, oIPQoS, oRequestTTY, oSessionType, oStdinNull,
	oForkAfterAuthentication, oIgnoreUnknown, oProxyUseFdpass,
	oCanonicalDomains, oCanonicalizeHostname, oCanonicalizeMaxDots,
	oCanonicalizeFallbackLocal, oCanonicalizePermittedCNAMEs,
	o_ಹರಿವು_Local_Bind_ಮುಖವಾಡ, o_ಹರಿವು_Local_Bind_Unlink, o_Revoked_Host_ಕೀಲಿಗಳು,
	oFingerprintHash, oUpdateHostkeys, oHostbasedAcceptedAlgorithms,
	oPubkeyAcceptedAlgorithms, oCASignatureAlgorithms, oProxyJump,
	o_Security_ಕೀಲಿ_Provider, o_ತಿಳಿದ_Hosts_Command, oRequiredRSASize,
	oEnableEscapeCommandline, oObscureKeystrokeTiming, oChannelTimeout,
	o_ಆವೃತ್ತಿ_Addendum, oRefuseConnection, oWarnWeakCrypto,
	oIgnore, oIgnoredUnknownOption, oDeprecated, oUnsupported
} OpCodes;

/* Textual representations of the tokens. */

ಸ್ಥಿರ ರಚನೆ {
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name;
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
#ಆದರೆ defined(GSSAPI)
	{ "gssapiauthentication", oGssAuthentication },
	{ "gssapidelegatecredentials", oGssDelegateCreds },
# ಇಲ್ಲದಿದ್ದರೆ
	{ "gssapiauthentication", oUnsupported },
	{ "gssapidelegatecredentials", oUnsupported },
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_PKCS11
	{ "pkcs11provider", oPKCS11Provider },
	{ "smartcarddevice", oPKCS11Provider },
# ಇಲ್ಲದಿದ್ದರೆ
	{ "smartcarddevice", oUnsupported },
	{ "pkcs11provider", oUnsupported },
#ಆದರೆ_ಅಂತ್ಯ

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
	{ "identityfile", o_ತಟಸ್ಥ_File },
	{ "identityfile2", o_ತಟಸ್ಥ_File },			/* obsolete */
	{ "identitiesonly", oIdentitiesOnly },
	{ "certificatefile", oCertificateFile },
	{ "addkeystoagent", o_ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_Agent },
	{ "identityagent", o_ತಟಸ್ಥ_Agent },
	{ "hostname", oHostname },
	{ "hostkeyalias", o_Host_ಕೀಲಿ_Alias },
	{ "proxycommand", oProxyCommand },
	{ "port", o_ಪೋರ್ಟ್ },
	{ "ciphers", oCiphers },
	{ "macs", oMacs },
	{ "remoteforward", oRemoteForward },
	{ "localforward", oLocalForward },
	{ "permitremoteopen", oPermitRemoteOpen },
	{ "user", oUser },
	{ "host", oHost },
	{ "match", o_ಹೊಂದಿಕೆ },
	{ "tag", o_ಟ್ಯಾಗ್ },
	{ "escapechar", oEscapeChar },
	{ "globalknownhostsfile", o_Global_ತಿಳಿದ_Hosts_File },
	{ "userknownhostsfile", o_User_ತಿಳಿದ_Hosts_File },
	{ "connectionattempts", oConnectionAttempts },
	{ "batchmode", o_Batch_ಬಹುಲಕ },
	{ "checkhostip", oCheckHostIP },
	{ "stricthostkeychecking", o_Strict_Host_ಕೀಲಿ_Checking },
	{ "compression", oCompression },
	{ "tcpkeepalive", oTCPKeepAlive },
	{ "keepalive", oTCPKeepAlive },				/* obsolete */
	{ "numberofpasswordprompts", o_ಸಂಖ್ಯೆ_ದ_Password_Prompts },
	{ "syslogfacility", oLogFacility },
	{ "loglevel", oLogLevel },
	{ "logverbose", oLogVerbose },
	{ "dynamicforward", oDynamicForward },
	{ "preferredauthentications", oPreferredAuthentications },
	{ "hostkeyalgorithms", o_Host_ಕೀಲಿ_Algorithms },
	{ "casignaturealgorithms", oCASignatureAlgorithms },
	{ "bindaddress", o_Bind_ವಿಳಾಸ },
	{ "bindinterface", oBindInterface },
	{ "clearallforwardings", oClearAllForwardings },
	{ "enablesshkeysign", oEnableSSHKeysign },
	{ "verifyhostkeydns", o_Verify_Host_ಕೀಲಿ_DNS },
	{ "nohostauthenticationforlocalhost", oNoHostAuthenticationForLocalhost },
	{ "rekeylimit", o_Rekey_ಎಲ್ಲೆ },
	{ "connecttimeout", oConnectTimeout },
	{ "addressfamily", o_ವಿಳಾಸ_Family },
	{ "serveraliveinterval", oServerAliveInterval },
	{ "serveralivecountmax", o_Server_Alive_ಎಣಿಕೆ_Max },
	{ "sendenv", oSendEnv },
	{ "setenv", o_ಗಣ_Env },
	{ "controlpath", o_Control_ಮಾರ್ಗ },
	{ "controlmaster", oControlMaster },
	{ "controlpersist", oControlPersist },
	{ "hashknownhosts", o_Hash_ತಿಳಿದ_Hosts },
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
	{ "streamlocalbindmask", o_ಹರಿವು_Local_Bind_ಮುಖವಾಡ },
	{ "streamlocalbindunlink", o_ಹರಿವು_Local_Bind_Unlink },
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
	{ "knownhostscommand", o_ತಿಳಿದ_Hosts_Command },
	{ "requiredrsasize", oRequiredRSASize },
	{ "enableescapecommandline", oEnableEscapeCommandline },
	{ "obscurekeystroketiming", oObscureKeystrokeTiming },
	{ "channeltimeout", oChannelTimeout },
	{ "versionaddendum", o_ಆವೃತ್ತಿ_Addendum },
	{ "refuseconnection", oRefuseConnection },
	{ "warnweakcrypto", oWarnWeakCrypto },

	{ ಖಾಲಿ, oBadOption }
};

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *lookup_opcode_name(OpCodes ಸಂಕೇತ_2);

ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
kex_default_pk_alg(ಶೂನ್ಯ)
{
	ಸ್ಥಿರ ಅಕ್ಷರ *pkalgs;

	ಆದರೆ (pkalgs == ಖಾಲಿ) {
		ಅಕ್ಷರ *all_ಕೀಲಿ;

		all_ಕೀಲಿ = sshkey_alg_list(0, 0, 1, ',');
		pkalgs = ಹೊಂದಿಕೆ_filter_allowlist(KEX_DEFAULT_PK_ALG, all_ಕೀಲಿ);
		ಬಿಡುಗಡೆ(all_ಕೀಲಿ);
	}
	ಹಿಂತಿರುಗಿ pkalgs;
}

ಅಕ್ಷರ *
ssh_connection_hash(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *thishost, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *portstr,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *jumphost)
{
	ರಚನೆ ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_ಉದ್ದಳತೆ];

	ಆದರೆ ((md = ssh_digest_ಆರಂಭ(SSH_DIGEST_SHA1)) == ಖಾಲಿ ||
	    ssh_digest_update(md, thishost, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(thishost)) < 0 ||
	    ssh_digest_update(md, host, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(host)) < 0 ||
	    ssh_digest_update(md, portstr, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(portstr)) < 0 ||
	    ssh_digest_update(md, user, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(user)) < 0 ||
	    ssh_digest_update(md, jumphost, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, ಗಾತ್ರ(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	ಹಿಂತಿರುಗಿ tohex(conn_hash, ssh_digest_ಬೈಟುಗಳು(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

ಶೂನ್ಯ
ಕೂಡಿಸು_local_forward(Options *options, ಸ್ಥಿರಾಂಕ ರಚನೆ Forward *newfwd)
{
	ರಚನೆ Forward *fwd;
	ಪೂರ್ಣಾಂಕ i;

	/* Don't add duplicates */
	ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_local_forwards; i++) {
		ಆದರೆ (forward_equals(newfwd, options->local_forwards + i))
			ಹಿಂತಿರುಗಿ;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->ಅಂಕೆ_local_forwards + 1,
	    ಗಾತ್ರ(*options->local_forwards));
	fwd = &options->local_forwards[options->ಅಂಕೆ_local_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_ಪೋರ್ಟ್ = newfwd->listen_ಪೋರ್ಟ್;
	fwd->listen_ಮಾರ್ಗ = newfwd->listen_ಮಾರ್ಗ;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_ಪೋರ್ಟ್ = newfwd->connect_ಪೋರ್ಟ್;
	fwd->connect_ಮಾರ್ಗ = newfwd->connect_ಮಾರ್ಗ;
}

/*
 * Adds a remote TCP/IP port forward to options.  Never returns if there is
 * an error.
 */

ಶೂನ್ಯ
ಕೂಡಿಸು_remote_forward(Options *options, ಸ್ಥಿರಾಂಕ ರಚನೆ Forward *newfwd)
{
	ರಚನೆ Forward *fwd;
	ಪೂರ್ಣಾಂಕ i;

	/* Don't add duplicates */
	ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_remote_forwards; i++) {
		ಆದರೆ (forward_equals(newfwd, options->remote_forwards + i))
			ಹಿಂತಿರುಗಿ;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->ಅಂಕೆ_remote_forwards + 1,
	    ಗಾತ್ರ(*options->remote_forwards));
	fwd = &options->remote_forwards[options->ಅಂಕೆ_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_ಪೋರ್ಟ್ = newfwd->listen_ಪೋರ್ಟ್;
	fwd->listen_ಮಾರ್ಗ = newfwd->listen_ಮಾರ್ಗ;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_ಪೋರ್ಟ್ = newfwd->connect_ಪೋರ್ಟ್;
	fwd->connect_ಮಾರ್ಗ = newfwd->connect_ಮಾರ್ಗ;
	fwd->handle = newfwd->handle;
	fwd->allocated_ಪೋರ್ಟ್ = 0;
}

ಸ್ಥಿರ ಶೂನ್ಯ
clear_forwardings(Options *options)
{
	ಪೂರ್ಣಾಂಕ i;

	ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_local_forwards; i++) {
		ಬಿಡುಗಡೆ(options->local_forwards[i].listen_host);
		ಬಿಡುಗಡೆ(options->local_forwards[i].listen_ಮಾರ್ಗ);
		ಬಿಡುಗಡೆ(options->local_forwards[i].connect_host);
		ಬಿಡುಗಡೆ(options->local_forwards[i].connect_ಮಾರ್ಗ);
	}
	ಆದರೆ (options->ಅಂಕೆ_local_forwards > 0) {
		ಬಿಡುಗಡೆ(options->local_forwards);
		options->local_forwards = ಖಾಲಿ;
	}
	options->ಅಂಕೆ_local_forwards = 0;
	ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_remote_forwards; i++) {
		ಬಿಡುಗಡೆ(options->remote_forwards[i].listen_host);
		ಬಿಡುಗಡೆ(options->remote_forwards[i].listen_ಮಾರ್ಗ);
		ಬಿಡುಗಡೆ(options->remote_forwards[i].connect_host);
		ಬಿಡುಗಡೆ(options->remote_forwards[i].connect_ಮಾರ್ಗ);
	}
	ಆದರೆ (options->ಅಂಕೆ_remote_forwards > 0) {
		ಬಿಡುಗಡೆ(options->remote_forwards);
		options->remote_forwards = ಖಾಲಿ;
	}
	options->ಅಂಕೆ_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

ಶೂನ್ಯ
ಕೂಡಿಸು_certificate_file(Options *options, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಪೂರ್ಣಾಂಕ userprovided)
{
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (options->ಅಂಕೆ_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_certificate_files; i++) {
		ಆದರೆ (options->certificate_file_userprovided[i] == userprovided &&
		    strcmp(options->certificate_files[i], ಮಾರ್ಗ) == 0) {
			debug2_f("ignoring duplicate key %s", ಮಾರ್ಗ);
			ಹಿಂತಿರುಗಿ;
		}
	}

	options->certificate_file_userprovided[options->ಅಂಕೆ_certificate_files] =
	    userprovided;
	options->certificate_files[options->ಅಂಕೆ_certificate_files++] =
	    xstrdup(ಮಾರ್ಗ);
}

ಶೂನ್ಯ
ಕೂಡಿಸು_ತಟಸ್ಥ_file(Options *options, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *dir, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename,
    ಪೂರ್ಣಾಂಕ userprovided)
{
	ಅಕ್ಷರ *ಮಾರ್ಗ;
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (options->ಅಂಕೆ_ತಟಸ್ಥ_files >= SSH_MAX_ತಟಸ್ಥ_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_ತಟಸ್ಥ_FILES);

	ಆದರೆ (dir == ಖಾಲಿ) /* no dir, filename is absolute */
		ಮಾರ್ಗ = xstrdup(filename);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (xasprintf(&ಮಾರ್ಗ, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", ಮಾರ್ಗ);

	/* Avoid registering duplicates */
	ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_ತಟಸ್ಥ_files; i++) {
		ಆದರೆ (options->ತಟಸ್ಥ_file_userprovided[i] == userprovided &&
		    strcmp(options->ತಟಸ್ಥ_files[i], ಮಾರ್ಗ) == 0) {
			debug2_f("ignoring duplicate key %s", ಮಾರ್ಗ);
			ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
			ಹಿಂತಿರುಗಿ;
		}
	}

	options->ತಟಸ್ಥ_file_userprovided[options->ಅಂಕೆ_ತಟಸ್ಥ_files] =
	    userprovided;
	options->ತಟಸ್ಥ_files[options->ಅಂಕೆ_ತಟಸ್ಥ_files++] = ಮಾರ್ಗ;
}

ಪೂರ್ಣಾಂಕ
default_ssh_ಪೋರ್ಟ್(ಶೂನ್ಯ)
{
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್;
	ರಚನೆ servent *sp;

	ಆದರೆ (ಪೋರ್ಟ್ == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		ಪೋರ್ಟ್ = sp ? ntohs(sp->s_port) : SSH_DEFAULT_ಪೋರ್ಟ್;
	}
	ಹಿಂತಿರುಗಿ ಪೋರ್ಟ್;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
execute_ಒಳ_shell(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cmd)
{
	ಅಕ್ಷರ *shell;
	pid_t pid;
	ಪೂರ್ಣಾಂಕ ಸ್ಥಿತಿ_2;

	ಆದರೆ ((shell = getenv("SHELL")) == ಖಾಲಿ)
		shell = _PATH_BSHELL;

	ಆದರೆ (access(shell, X_OK) == -1) {
		fatal("Shell \"%s\" is not executable: %s",
		    shell, strerror(errno));
	}

	debug("Executing command: '%.500s'", cmd);

	/* Fork and execute the command. */
	ಆದರೆ ((pid = fork()) == 0) {
		ಅಕ್ಷರ *argv[4];

		ಆದರೆ (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = xstrdup(cmd);
		argv[3] = ಖಾಲಿ;

		execv(argv[0], argv);
		error("Unable to execute '%.100s': %s", cmd, strerror(errno));
		/* Die with signal to make this error apparent to parent. */
		ssh_signal(SIGTERM, SIG_DFL);
		kill(getpid(), SIGTERM);
		_exit(1);
	}
	/* Parent. */
	ಆದರೆ (pid == -1)
		fatal_f("fork: %.100s", strerror(errno));

	ಆಗ (waitpid(pid, &ಸ್ಥಿತಿ_2, 0) == -1) {
		ಆದರೆ (errno != EINTR && errno != EAGAIN)
			fatal_f("waitpid: %s", strerror(errno));
	}
	ಆದರೆ (!WIFEXITED(ಸ್ಥಿತಿ_2)) {
		error("command '%.100s' exited abnormally", cmd);
		ಹಿಂತಿರುಗಿ -1;
	}
	debug3("command returned status %d", WEXITSTATUS(ಸ್ಥಿತಿ_2));
	ಹಿಂತಿರುಗಿ WEXITSTATUS(ಸ್ಥಿತಿ_2);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
check_ಹೊಂದಿಕೆ_ifaddrs(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *addrlist)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_IFADDRS_H
	ರಚನೆ ifaddrs *ifa, *ifaddrs = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, ಸಿಕ್ಕಿತು = 0;
	ಅಕ್ಷರ addr[NI_MAXHOST];
	socklen_t salen;

	ಆದರೆ (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    strerror(errno));
		ಹಿಂತಿರುಗಿ 0;
	}
	ಗಾಗಿ (ifa = ifaddrs; ifa != ಖಾಲಿ; ifa = ifa->ifa_ಮುಂದಿನ) {
		ಆದರೆ (ifa->ifa_addr == ಖಾಲಿ || ifa->ifa_name == ಖಾಲಿ ||
		    (ifa->ifa_flags & IFF_UP) == 0)
			ಮುಂದುವರಿ;
		ಆಯ್ಕೆ (ifa->ifa_addr->sa_family) {
		ಸ್ಥಿತಿ AF_INET:
			salen = ಗಾತ್ರ(ರಚನೆ sockaddr_in);
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ AF_INET6:
			salen = ಗಾತ್ರ(ರಚನೆ sockaddr_in6);
			ನಿಲ್ಲಿಸು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ AF_LINK
		ಸ್ಥಿತಿ AF_LINK:
			/* ignore */
			ಮುಂದುವರಿ;
#ಆದರೆ_ಅಂತ್ಯ /* AF_LINK */
		ಪೂರ್ವನಿಯೋಜಿತ:
			debug2_f("interface %s: unsupported address family %d",
			    ifa->ifa_name, ifa->ifa_addr->sa_family);
			ಮುಂದುವರಿ;
		}
		ಆದರೆ ((r = getnameinfo(ifa->ifa_addr, salen, addr, ಗಾತ್ರ(addr),
		    ಖಾಲಿ, 0, NI_NUMERICHOST)) != 0) {
			debug2_f("interface %s getnameinfo failed: %s",
			    ifa->ifa_name, gai_strerror(r));
			ಮುಂದುವರಿ;
		}
		debug3_f("interface %s addr %s", ifa->ifa_name, addr);
		ಆದರೆ (addr_ಹೊಂದಿಕೆ_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			ಸಿಕ್ಕಿತು = 1;
			ನಿಲ್ಲಿಸು;
		}
	}
	freeifaddrs(ifaddrs);
	ಹಿಂತಿರುಗಿ ಸಿಕ್ಕಿತು;
#ಇಲ್ಲದಿದ್ದರೆ /* HAVE_IFADDRS_H */
	error("match localnetwork: not supported on this platform");
	ಹಿಂತಿರುಗಿ 0;
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_IFADDRS_H */
}

/*
 * Expand a "match exec" command or an Include path, caller must free returned
 * value.
 */
ಸ್ಥಿರ ಅಕ್ಷರ *
expand_ಹೊಂದಿಕೆ_exec_or_include_ಮಾರ್ಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, Options *options,
    ರಚನೆ passwd *pw, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host_arg, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *original_host,
    ಪೂರ್ಣಾಂಕ final_pass, ಪೂರ್ಣಾಂಕ is_include_ಮಾರ್ಗ)
{
	ಅಕ್ಷರ thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	ಅಕ್ಷರ uidstr[32], *conn_hash_hex, *keyalias, *jmphost, *ruser;
	ಅಕ್ಷರ *host, *ret;
	ಪೂರ್ಣಾಂಕ ಪೋರ್ಟ್;

	ಪೋರ್ಟ್ = options->ಪೋರ್ಟ್ <= 0 ? default_ssh_ಪೋರ್ಟ್() : options->ಪೋರ್ಟ್;
	ruser = options->user == ಖಾಲಿ ? pw->pw_name : options->user;
	ಆದರೆ (final_pass) {
		host = xstrdup(options->hostname);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (options->hostname != ಖಾಲಿ) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (ಅಕ್ಷರ *)ಖಾಲಿ);
	} ಇಲ್ಲದಿದ್ದರೆ {
		host = xstrdup(host_arg);
	}
	ಆದರೆ (gethostname(thishost, ಗಾತ್ರ(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	jmphost = option_clear_or_none(options->jump_host) ?
	    "" : options->jump_host;
	strlcpy(shorthost, thishost, ಗಾತ್ರ(shorthost));
	shorthost[strcspn(thishost, ".")] = '\0';
	snprintf(portstr, ಗಾತ್ರ(portstr), "%d", ಪೋರ್ಟ್);
	snprintf(uidstr, ಗಾತ್ರ(uidstr), "%llu",
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)pw->pw_uid);
	conn_hash_hex = ssh_connection_hash(thishost, host,
	    portstr, ruser, jmphost);
	keyalias = options->host_ಕೀಲಿ_alias ?  options->host_ಕೀಲಿ_alias : host;

	ret = (is_include_ಮಾರ್ಗ ? percent_dollar_expand : percent_expand)(ಮಾರ್ಗ,
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
	    (ಅಕ್ಷರ *)ಖಾಲಿ);
	ಬಿಡುಗಡೆ(host);
	ಬಿಡುಗಡೆ(conn_hash_hex);
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Parse and execute a Match directive.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ಹೊಂದಿಕೆ_cfg_ಸಾಲು(Options *options, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ತುಂಬಿದ_ಸಾಲು, ಪೂರ್ಣಾಂಕ *acp, ಅಕ್ಷರ ***avp,
    ರಚನೆ passwd *pw, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host_arg, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *original_host,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_command, ಪೂರ್ಣಾಂಕ final_pass, ಪೂರ್ಣಾಂಕ *want_final_pass,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಪೂರ್ಣಾಂಕ linenum)
{
	ಅಕ್ಷರ *arg, *oattrib = ಖಾಲಿ, *attrib = ಖಾಲಿ, *cmd, *host, *criteria;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ruser;
	ಪೂರ್ಣಾಂಕ r, this_ಫಲಿತಾಂಶ, ಫಲಿತಾಂಶ = 1, ಗುಣಲಕ್ಷಣಗಳು = 0, negate;

	/*
	 * Configuration is likely to be incomplete at this point so we
	 * must be prepared to use default values.
	 */
	ruser = options->user == ಖಾಲಿ ? pw->pw_name : options->user;
	ಆದರೆ (final_pass) {
		host = xstrdup(options->hostname);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (options->hostname != ಖಾಲಿ) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (ಅಕ್ಷರ *)ಖಾಲಿ);
	} ಇಲ್ಲದಿದ್ದರೆ {
		host = xstrdup(host_arg);
	}

	debug2("checking match for '%s' host %s originally %s",
	    ತುಂಬಿದ_ಸಾಲು, host, original_host);
	ಆಗ ((attrib = argv_ಮುಂದಿನ(acp, avp)) != ಖಾಲಿ) {
		/* Terminate on comment */
		ಆದರೆ (*attrib == '#') {
			argv_consume(acp);
			ನಿಲ್ಲಿಸು;
		}
		attrib = oattrib = xstrdup(attrib);
		arg = criteria = ಖಾಲಿ;
		this_ಫಲಿತಾಂಶ = 1;
		ಆದರೆ ((negate = (attrib[0] == '!')))
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		ಆದರೆ (strcasecmp(attrib, "all") == 0) {
			ಆದರೆ (ಗುಣಲಕ್ಷಣಗಳು > 1 ||
			    ((arg = argv_ಮುಂದಿನ(acp, avp)) != ಖಾಲಿ &&
			    *arg != '\0' && *arg != '#')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				ಫಲಿತಾಂಶ = -1;
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಆದರೆ (arg != ಖಾಲಿ && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			ಆದರೆ (ಫಲಿತಾಂಶ)
				ಫಲಿತಾಂಶ = negate ? 0 : 1;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಗುಣಲಕ್ಷಣಗಳು++;
		/* criteria "final" and "canonical" have no argument */
		ಆದರೆ (strcasecmp(attrib, "canonical") == 0 ||
		    strcasecmp(attrib, "final") == 0) {
			/*
			 * If the config requests "Match final" without
			 * negation then remember this so we can perform a
			 * second pass later.
			 */
			ಆದರೆ (strcasecmp(attrib, "final") == 0 &&
			    want_final_pass != ಖಾಲಿ)
				*want_final_pass |= !negate;
			r = !!final_pass;  /* force bitmask member to boolean */
			ಆದರೆ (r == (negate ? 1 : 0))
				this_ಫಲಿತಾಂಶ = ಫಲಿತಾಂಶ = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_ಫಲಿತಾಂಶ ? "" : "not ", oattrib);
			ಹೋಗು ಮುಂದಿನ;
		}

		/* Keep this list in sync with below */
		ಆದರೆ (strprefix(attrib, "host=", 1)  != ಖಾಲಿ ||
		    strprefix(attrib, "originalhost=", 1) != ಖಾಲಿ ||
		    strprefix(attrib, "user=", 1) != ಖಾಲಿ ||
		    strprefix(attrib, "localuser=", 1) != ಖಾಲಿ ||
		    strprefix(attrib, "localnetwork=", 1) != ಖಾಲಿ ||
		    strprefix(attrib, "version=", 1) != ಖಾಲಿ ||
		    strprefix(attrib, "tagged=", 1) != ಖಾಲಿ ||
		    strprefix(attrib, "command=", 1) != ಖಾಲಿ ||
		    strprefix(attrib, "exec=", 1) != ಖಾಲಿ) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((arg = argv_ಮುಂದಿನ(acp, avp)) == ಖಾಲಿ) {
			error("%.200s line %d: missing argument for Match '%s'",
			    filename, linenum, oattrib);
			ಫಲಿತಾಂಶ = -1;
			ಹೋಗು ಹೊರಹೋಗು;
		}

		/*
		 * All other criteria require an argument, though it may
		 * be the empty string for the "tagged" and "command"
		 * options.
		 */
		ಆದರೆ (*arg == '\0' &&
		    strcasecmp(attrib, "tagged") != 0 &&
		    strcasecmp(attrib, "command") != 0)
			arg = ಖಾಲಿ;
		ಆದರೆ (arg == ಖಾಲಿ || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			ಫಲಿತಾಂಶ = -1;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = ಹೊಂದಿಕೆ_hostname(host, arg) == 1;
			ಆದರೆ (r == (negate ? 1 : 0))
				this_ಫಲಿತಾಂಶ = ಫಲಿತಾಂಶ = 0;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = ಹೊಂದಿಕೆ_hostname(original_host, arg) == 1;
			ಆದರೆ (r == (negate ? 1 : 0))
				this_ಫಲಿತಾಂಶ = ಫಲಿತಾಂಶ = 0;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = ಹೊಂದಿಕೆ_ನಮೂನೆ_list(ruser, arg, 0) == 1;
			ಆದರೆ (r == (negate ? 1 : 0))
				this_ಫಲಿತಾಂಶ = ಫಲಿತಾಂಶ = 0;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = ಹೊಂದಿಕೆ_ನಮೂನೆ_list(pw->pw_name, arg, 0) == 1;
			ಆದರೆ (r == (negate ? 1 : 0))
				this_ಫಲಿತಾಂಶ = ಫಲಿತಾಂಶ = 0;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(attrib, "localnetwork") == 0) {
			ಆದರೆ (addr_ಹೊಂದಿಕೆ_cidr_list(ಖಾಲಿ, arg) == -1) {
				/* Error already printed */
				ಫಲಿತಾಂಶ = -1;
				ಹೋಗು ಹೊರಹೋಗು;
			}
			r = check_ಹೊಂದಿಕೆ_ifaddrs(arg) == 1;
			ಆದರೆ (r == (negate ? 1 : 0))
				this_ಫಲಿತಾಂಶ = ಫಲಿತಾಂಶ = 0;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(attrib, "version") == 0) {
			criteria = xstrdup(SSH_RELEASE);
			r = ಹೊಂದಿಕೆ_ನಮೂನೆ_list(SSH_RELEASE, arg, 0) == 1;
			ಆದರೆ (r == (negate ? 1 : 0))
				this_ಫಲಿತಾಂಶ = ಫಲಿತಾಂಶ = 0;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->ಟ್ಯಾಗ್ == ಖಾಲಿ ? "" :
			    options->ಟ್ಯಾಗ್);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    ಹೊಂದಿಕೆ_ನಮೂನೆ_list(criteria, arg, 0) == 1;
			ಆದರೆ (r == (negate ? 1 : 0))
				this_ಫಲಿತಾಂಶ = ಫಲಿತಾಂಶ = 0;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(attrib, "command") == 0) {
			criteria = xstrdup(remote_command == ಖಾಲಿ ?
			    "" : remote_command);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    ಹೊಂದಿಕೆ_ನಮೂನೆ_list(criteria, arg, 0) == 1;
			ಆದರೆ (r == (negate ? 1 : 0))
				this_ಫಲಿತಾಂಶ = ಫಲಿತಾಂಶ = 0;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(attrib, "sessiontype") == 0) {
			ಆದರೆ (options->session_type == SESSION_TYPE_SUBSYSTEM)
				criteria = xstrdup("subsystem");
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (options->session_type == SESSION_TYPE_NONE)
				criteria = xstrdup("none");
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (remote_command != ಖಾಲಿ &&
			    *remote_command != '\0')
				criteria = xstrdup("exec");
			ಇಲ್ಲದಿದ್ದರೆ
				criteria = xstrdup("shell");
			r = ಹೊಂದಿಕೆ_ನಮೂನೆ_list(criteria, arg, 0) == 1;
			ಆದರೆ (r == (negate ? 1 : 0))
				this_ಫಲಿತಾಂಶ = ಫಲಿತಾಂಶ = 0;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(attrib, "exec") == 0) {
			ಆದರೆ ((cmd = expand_ಹೊಂದಿಕೆ_exec_or_include_ಮಾರ್ಗ(arg,
			    options, pw, host_arg, original_host,
			    final_pass, 0)) == ಖಾಲಿ) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			ಆದರೆ (ಫಲಿತಾಂಶ != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				ಬಿಡುಗಡೆ(cmd);
				ಹೋಗು ಮುಂದಿನ;
			}
			r = execute_ಒಳ_shell(cmd);
			ಆದರೆ (r == -1) {
				fatal("%.200s line %d: match exec "
				    "'%.100s' error", filename,
				    linenum, cmd);
			}
			criteria = xstrdup(cmd);
			ಬಿಡುಗಡೆ(cmd);
			/* Force exit status to boolean */
			r = r == 0;
			ಆದರೆ (r == (negate ? 1 : 0))
				this_ಫಲಿತಾಂಶ = ಫಲಿತಾಂಶ = 0;
		} ಇಲ್ಲದಿದ್ದರೆ {
			error("Unsupported Match attribute %s", attrib);
			ಫಲಿತಾಂಶ = -1;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s' ",
		    filename, linenum, this_ಫಲಿತಾಂಶ ? "": "not ", oattrib,
		    criteria == ಖಾಲಿ ? "" : " \"",
		    criteria == ಖಾಲಿ ? "" : criteria,
		    criteria == ಖಾಲಿ ? "" : "\"");
 ಮುಂದಿನ:
		ಬಿಡುಗಡೆ(criteria);
		ಬಿಡುಗಡೆ(oattrib);
		oattrib = attrib = ಖಾಲಿ;
	}
	ಆದರೆ (ಗುಣಲಕ್ಷಣಗಳು == 0) {
		error("One or more attributes required for Match");
		ಫಲಿತಾಂಶ = -1;
		ಹೋಗು ಹೊರಹೋಗು;
	}
 ಹೊರಹೋಗು:
	ಆದರೆ (ಫಲಿತಾಂಶ != -1)
		debug2("match %sfound", ಫಲಿತಾಂಶ ? "" : "not ");
	ಬಿಡುಗಡೆ(oattrib);
	ಬಿಡುಗಡೆ(host);
	ಹಿಂತಿರುಗಿ ಫಲಿತಾಂಶ;
}

/* Remove environment variable by pattern */
ಸ್ಥಿರ ಶೂನ್ಯ
rm_env(Options *options, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *arg, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಪೂರ್ಣಾಂಕ linenum)
{
	u_int i, j, onum_send_env = options->ಅಂಕೆ_send_env;

	/* Remove an environment variable */
	ಗಾಗಿ (i = 0; i < options->ಅಂಕೆ_send_env; ) {
		ಆದರೆ (!ಹೊಂದಿಕೆ_ನಮೂನೆ(options->send_env[i], arg + 1)) {
			i++;
			ಮುಂದುವರಿ;
		}
		debug3("%s line %d: removing environment %s",
		    filename, linenum, options->send_env[i]);
		ಬಿಡುಗಡೆ(options->send_env[i]);
		options->send_env[i] = ಖಾಲಿ;
		ಗಾಗಿ (j = i; j < options->ಅಂಕೆ_send_env - 1; j++) {
			options->send_env[j] = options->send_env[j + 1];
			options->send_env[j + 1] = ಖಾಲಿ;
		}
		options->ಅಂಕೆ_send_env--;
		/* NB. don't increment i */
	}
	ಆದರೆ (onum_send_env != options->ಅಂಕೆ_send_env) {
		options->send_env = xrecallocarray(options->send_env,
		    onum_send_env, options->ಅಂಕೆ_send_env,
		    ಗಾತ್ರ(*options->send_env));
	}
}

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */
ಸ್ಥಿರ OpCodes
parse_token(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cp, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಪೂರ್ಣಾಂಕ linenum,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ignored_unknown)
{
	ಪೂರ್ಣಾಂಕ i;

	ಗಾಗಿ (i = 0; keywords[i].name; i++)
		ಆದರೆ (strcmp(cp, keywords[i].name) == 0)
			ಹಿಂತಿರುಗಿ keywords[i].opcode;
	ಆದರೆ (ignored_unknown != ಖಾಲಿ &&
	    ಹೊಂದಿಕೆ_ನಮೂನೆ_list(cp, ignored_unknown, 1) == 1)
		ಹಿಂತಿರುಗಿ oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	ಹಿಂತಿರುಗಿ oBadOption;
}

ಸ್ಥಿರ ಶೂನ್ಯ
free_canon_cnames(ರಚನೆ allowed_cname *cnames, u_int n)
{
	u_int i;

	ಆದರೆ (cnames == ಖಾಲಿ || n == 0)
		ಹಿಂತಿರುಗಿ;
	ಗಾಗಿ (i = 0; i < n; i++) {
		ಬಿಡುಗಡೆ(cnames[i].ಮೂಲ_list);
		ಬಿಡುಗಡೆ(cnames[i].ಗುರಿ_list);
	}
	ಬಿಡುಗಡೆ(cnames);
}

/* Multistate option parsing */
ರಚನೆ multistate {
	ಅಕ್ಷರ *ಕೀಲಿ;
	ಪೂರ್ಣಾಂಕ ಮೌಲ್ಯ;
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_flag[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ ಖಾಲಿ, -1 }
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_yesnoask[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ ಖಾಲಿ, -1 }
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_strict_hostkey[] = {
	{ "true",			SSH_STRICT_HOSTKEY_YES },
	{ "false",			SSH_STRICT_HOSTKEY_OFF },
	{ "yes",			SSH_STRICT_HOSTKEY_YES },
	{ "no",				SSH_STRICT_HOSTKEY_OFF },
	{ "ask",			SSH_STRICT_HOSTKEY_ASK },
	{ "off",			SSH_STRICT_HOSTKEY_OFF },
	{ "accept-new",			SSH_STRICT_HOSTKEY_NEW },
	{ ಖಾಲಿ, -1 }
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_yesnoaskconfirm[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "confirm",			3 },
	{ ಖಾಲಿ, -1 }
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ ಖಾಲಿ, -1 }
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_controlmaster[] = {
	{ "true",			SSHCTL_MASTER_YES },
	{ "yes",			SSHCTL_MASTER_YES },
	{ "false",			SSHCTL_MASTER_NO },
	{ "no",				SSHCTL_MASTER_NO },
	{ "auto",			SSHCTL_MASTER_AUTO },
	{ "ask",			SSHCTL_MASTER_ASK },
	{ "autoask",			SSHCTL_MASTER_AUTO_ASK },
	{ ಖಾಲಿ, -1 }
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET },
	{ "point-to-point",		SSH_TUNMODE_POINTOPOINT },
	{ "true",			SSH_TUNMODE_DEFAULT },
	{ "yes",			SSH_TUNMODE_DEFAULT },
	{ "false",			SSH_TUNMODE_NO },
	{ "no",				SSH_TUNMODE_NO },
	{ ಖಾಲಿ, -1 }
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_requesttty[] = {
	{ "true",			REQUEST_TTY_YES },
	{ "yes",			REQUEST_TTY_YES },
	{ "false",			REQUEST_TTY_NO },
	{ "no",				REQUEST_TTY_NO },
	{ "force",			REQUEST_TTY_FORCE },
	{ "auto",			REQUEST_TTY_AUTO },
	{ ಖಾಲಿ, -1 }
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_sessiontype[] = {
	{ "none",			SESSION_TYPE_NONE },
	{ "subsystem",			SESSION_TYPE_SUBSYSTEM },
	{ "default",			SESSION_TYPE_DEFAULT },
	{ ಖಾಲಿ, -1 }
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_canonicalizehostname[] = {
	{ "true",			SSH_CANONICALISE_YES },
	{ "false",			SSH_CANONICALISE_NO },
	{ "yes",			SSH_CANONICALISE_YES },
	{ "no",				SSH_CANONICALISE_NO },
	{ "always",			SSH_CANONICALISE_ALWAYS },
	{ ಖಾಲಿ, -1 }
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_pubkey_auth[] = {
	{ "true",			SSH_PUBKEY_AUTH_ALL },
	{ "false",			SSH_PUBKEY_AUTH_NO },
	{ "yes",			SSH_PUBKEY_AUTH_ALL },
	{ "no",				SSH_PUBKEY_AUTH_NO },
	{ "unbound",			SSH_PUBKEY_AUTH_UNBOUND },
	{ "host-bound",			SSH_PUBKEY_AUTH_HBOUND },
	{ ಖಾಲಿ, -1 }
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_compression[] = {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_ZLIB
	{ "yes",			COMP_DELAYED },
#ಆದರೆ_ಅಂತ್ಯ
	{ "no",				COMP_NONE },
	{ ಖಾಲಿ, -1 }
};
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ ಖಾಲಿ, -1 }
};
/* XXX this will need to be replaced with a bitmask if we add more flags */
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ ಖಾಲಿ, -1 }
};

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_multistate_ಮೌಲ್ಯ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *arg, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಪೂರ್ಣಾಂಕ linenum,
    ಸ್ಥಿರಾಂಕ ರಚನೆ multistate *multistate_ptr)
{
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (!arg || *arg == '\0') {
		error("%s line %d: missing argument.", filename, linenum);
		ಹಿಂತಿರುಗಿ -1;
	}
	ಗಾಗಿ (i = 0; multistate_ptr[i].ಕೀಲಿ != ಖಾಲಿ; i++) {
		ಆದರೆ (strcasecmp(arg, multistate_ptr[i].ಕೀಲಿ) == 0)
			ಹಿಂತಿರುಗಿ multistate_ptr[i].ಮೌಲ್ಯ;
	}
	ಹಿಂತಿರುಗಿ -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
ಪೂರ್ಣಾಂಕ
process_config_ಸಾಲು(Options *options, ರಚನೆ passwd *pw, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *original_host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_command, ಅಕ್ಷರ *ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಪೂರ್ಣಾಂಕ linenum, ಪೂರ್ಣಾಂಕ *activep, ಪೂರ್ಣಾಂಕ flags)
{
	ಹಿಂತಿರುಗಿ process_config_ಸಾಲು_ಆಳ(options, pw, host, original_host,
	    remote_command, ಸಾಲು, filename, linenum, activep, flags, ಖಾಲಿ, 0);
}

#ವ್ಯಾಖ್ಯಾನಿಸು WHITESPACE " \t\r\n"
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
process_config_ಸಾಲು_ಆಳ(Options *options, ರಚನೆ passwd *pw, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *original_host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_command, ಅಕ್ಷರ *ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ಪೂರ್ಣಾಂಕ linenum, ಪೂರ್ಣಾಂಕ *activep, ಪೂರ್ಣಾಂಕ flags,
    ಪೂರ್ಣಾಂಕ *want_final_pass, ಪೂರ್ಣಾಂಕ ಆಳ)
{
	ಅಕ್ಷರ *str, **charptr, *endofnumber, *keyword, *arg, *arg2, *p;
	ಅಕ್ಷರ **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	ಪೂರ್ಣಾಂಕ r, oactive, negated, opcode, *intptr, ಮೌಲ್ಯ, value2, cmdline = 0;
	ಪೂರ್ಣಾಂಕ remotefwd, dynamicfwd, ca_only = 0, ಸಿಕ್ಕಿತು = 0;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	ದೀರ್ಘ ದೀರ್ಘ val64;
	ಗಾತ್ರ_t len;
	ರಚನೆ Forward fwd;
	ಸ್ಥಿರಾಂಕ ರಚನೆ multistate *multistate_ptr;
	glob_t gl;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr;
	ಅಕ್ಷರ **oav = ಖಾಲಿ, **av;
	ಪೂರ್ಣಾಂಕ oac = 0, ac;
	ಪೂರ್ಣಾಂಕ ret = -1;
	ರಚನೆ allowed_cname *cnames = ಖಾಲಿ;
	u_int ncnames = 0;
	ಅಕ್ಷರ **strs = ಖಾಲಿ; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	ಆದರೆ (activep == ಖಾಲಿ) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	ಆದರೆ ((len = ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಸಾಲು)) == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಗಾಗಿ (len--; len > 0; len--) {
		ಆದರೆ (strchr(WHITESPACE "\f", ಸಾಲು[len]) == ಖಾಲಿ)
			ನಿಲ್ಲಿಸು;
		ಸಾಲು[len] = '\0';
	}

	str = ಸಾಲು;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	ಆದರೆ ((keyword = strdelim(&str)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	/* Ignore leading whitespace. */
	ಆದರೆ (*keyword == '\0')
		keyword = strdelim(&str);
	ಆದರೆ (keyword == ಖಾಲಿ || !*keyword || *keyword == '\n' || *keyword == '#')
		ಹಿಂತಿರುಗಿ 0;
	/* Match lowercase keyword */
	lowercase(keyword);

	/* Prepare to parse remainder of line */
	ಆದರೆ (str != ಖಾಲಿ)
		str += strspn(str, WHITESPACE);
	ಆದರೆ (str == ಖಾಲಿ || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		ಹಿಂತಿರುಗಿ -1;
	}
	opcode = parse_token(keyword, filename, linenum,
	    options->ignored_unknown);
	ಆದರೆ (argv_ವಿಭಜಿಸು(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		ಹಿಂತಿರುಗಿ -1;
	}
	ac = oac;
	av = oav;

	ಆಯ್ಕೆ (opcode) {
	ಸ್ಥಿತಿ oBadOption:
		/* don't panic, but count bad options */
		ಹೋಗು ಹೊರಹೋಗು;
	ಸ್ಥಿತಿ oIgnore:
		argv_consume(&ac);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ oConnectTimeout:
		intptr = &options->connection_timeout;
parse_ಸಮಯ:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (strcmp(arg, "none") == 0)
			ಮೌಲ್ಯ = -1;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((ಮೌಲ್ಯ = convtime(arg)) == -1) {
			error("%s line %d: invalid time value.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*activep && *intptr == -1)
			*intptr = ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			error("%s line %d: missing argument.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}

		ಮೌಲ್ಯ = -1;
		multistate_ptr = multistate_flag;
		ಗಾಗಿ (i = 0; multistate_ptr[i].ಕೀಲಿ != ಖಾಲಿ; i++) {
			ಆದರೆ (strcasecmp(arg, multistate_ptr[i].ಕೀಲಿ) == 0) {
				ಮೌಲ್ಯ = multistate_ptr[i].ಮೌಲ್ಯ;
				ನಿಲ್ಲಿಸು;
			}
		}
		ಆದರೆ (ಮೌಲ್ಯ != -1) {
			ಆದರೆ (*activep && *intptr == -1)
				*intptr = ಮೌಲ್ಯ;
			ನಿಲ್ಲಿಸು;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		ಆದರೆ (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_ಮಾರ್ಗ;
		ಹೋಗು parse_agent_ಮಾರ್ಗ;

	ಸ್ಥಿತಿ oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ ((ಮೌಲ್ಯ = parse_multistate_ಮೌಲ್ಯ(arg, filename, linenum,
		    multistate_ptr)) == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*activep && *intptr == -1)
			*intptr = ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		ಹೋಗು parse_ಸಮಯ;

	ಸ್ಥಿತಿ oGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ oPasswordAuthentication:
		intptr = &options->password_authentication;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		ಹೋಗು parse_string;

	ಸ್ಥಿತಿ oPubkeyAuthentication:
		multistate_ptr = multistate_pubkey_auth;
		intptr = &options->pubkey_authentication;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ oGssAuthentication:
		intptr = &options->gss_authentication;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ o_Batch_ಬಹುಲಕ:
		intptr = &options->batch_ಬಹುಲಕ;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ oCheckHostIP:
		intptr = &options->check_host_ip;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ o_Verify_Host_ಕೀಲಿ_DNS:
		intptr = &options->verify_host_ಕೀಲಿ_dns;
		multistate_ptr = multistate_yesnoask;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ o_Strict_Host_ಕೀಲಿ_Checking:
		intptr = &options->strict_host_ಕೀಲಿ_checking;
		multistate_ptr = multistate_strict_hostkey;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ oCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ o_ಸಂಖ್ಯೆ_ದ_Password_Prompts:
		intptr = &options->ಸಂಖ್ಯೆ_ದ_password_prompts;
		ಹೋಗು parse_int;

	ಸ್ಥಿತಿ o_Rekey_ಎಲ್ಲೆ:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.", filename,
			    linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (strcmp(arg, "default") == 0) {
			val64 = 0;
		} ಇಲ್ಲದಿದ್ದರೆ {
			ಆದರೆ (ಪರಿಶೀಲನೆ_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, strerror(errno));
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಆದರೆ (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				ಹೋಗು ಹೊರಹೋಗು;
			}
		}
		ಆದರೆ (*activep && options->rekey_ಎಲ್ಲೆ == -1)
			options->rekey_ಎಲ್ಲೆ = val64;
		ಆದರೆ (ac != 0) { /* optional rekey interval present */
			ಆದರೆ (strcmp(av[0], "none") == 0) {
				(ಶೂನ್ಯ)argv_ಮುಂದಿನ(&ac, &av);	/* discard */
				ನಿಲ್ಲಿಸು;
			}
			intptr = &options->rekey_interval;
			ಹೋಗು parse_ಸಮಯ;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ o_ತಟಸ್ಥ_File:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*activep) {
			intptr = &options->ಅಂಕೆ_ತಟಸ್ಥ_files;
			ಆದರೆ (*intptr >= SSH_MAX_ತಟಸ್ಥ_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_ತಟಸ್ಥ_FILES);
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಕೂಡಿಸು_ತಟಸ್ಥ_file(options, ಖಾಲಿ,
			    arg, flags & SSHCONF_USERCONF);
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oCertificateFile:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*activep) {
			intptr = &options->ಅಂಕೆ_certificate_files;
			ಆದರೆ (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಕೂಡಿಸು_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oXAuthLocation:
		charptr=&options->xauth_location;
		ಹೋಗು parse_string;

	ಸ್ಥಿತಿ oUser:
		charptr = &options->user;
parse_string:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*activep && *charptr == ಖಾಲಿ)
			*charptr = xstrdup(arg);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ o_Global_ತಿಳಿದ_Hosts_File:
		cpptr = (ಅಕ್ಷರ **)&options->system_hostfiles;
		uintptr = &options->ಅಂಕೆ_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		i = 0;
		ಮೌಲ್ಯ = *uintptr == 0; /* was array empty when we started? */
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			ಆದರೆ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ಹೋಗು ಹೊರಹೋಗು;
			}
			/* Allow "none" only in first position */
			ಆದರೆ (strcasecmp(arg, "none") == 0) {
				ಆದರೆ (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ಹೋಗು ಹೊರಹೋಗು;
				}
			}
			i++;
			ಆದರೆ (*activep && ಮೌಲ್ಯ) {
				ಆದರೆ ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries.", filename, linenum,
					    keyword);
					ಹೋಗು ಹೊರಹೋಗು;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ o_User_ತಿಳಿದ_Hosts_File:
		cpptr = (ಅಕ್ಷರ **)&options->user_hostfiles;
		uintptr = &options->ಅಂಕೆ_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		ಹೋಗು parse_char_array;

	ಸ್ಥಿತಿ oHostname:
		charptr = &options->hostname;
		ಹೋಗು parse_string;

	ಸ್ಥಿತಿ o_ಟ್ಯಾಗ್:
		charptr = &options->ಟ್ಯಾಗ್;
		ಹೋಗು parse_string;

	ಸ್ಥಿತಿ o_Host_ಕೀಲಿ_Alias:
		charptr = &options->host_ಕೀಲಿ_alias;
		ಹೋಗು parse_string;

	ಸ್ಥಿತಿ oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		ಹೋಗು parse_string;

	ಸ್ಥಿತಿ o_Bind_ವಿಳಾಸ:
		charptr = &options->bind_ವಿಳಾಸ;
		ಹೋಗು parse_string;

	ಸ್ಥಿತಿ oBindInterface:
		charptr = &options->bind_interface;
		ಹೋಗು parse_string;

	ಸ್ಥಿತಿ oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		ಹೋಗು parse_string;

	ಸ್ಥಿತಿ o_Security_ಕೀಲಿ_Provider:
		charptr = &options->sk_provider;
		ಹೋಗು parse_string;

	ಸ್ಥಿತಿ o_ತಿಳಿದ_Hosts_Command:
		charptr = &options->ತಿಳಿದ_hosts_command;
		ಹೋಗು parse_command;

	ಸ್ಥಿತಿ oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		ಆದರೆ (str == ಖಾಲಿ) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		len = strspn(str, WHITESPACE "=");
		ಆದರೆ (*activep && *charptr == ಖಾಲಿ)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oProxyJump:
		ಆದರೆ (str == ಖಾಲಿ) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		len = strspn(str, WHITESPACE "=");
		/* XXX use argv? */
		ಆದರೆ (parse_jump(str + len, options, cmdline, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		argv_consume(&ac);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ o_ಪೋರ್ಟ್:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಮೌಲ್ಯ = a2port(arg);
		ಆದರೆ (ಮೌಲ್ಯ <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*activep && options->ಪೋರ್ಟ್ == -1)
			options->ಪೋರ್ಟ್ = ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ ((errstr = atoi_err(arg, &ಮೌಲ್ಯ)) != ಖಾಲಿ) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*activep && *intptr == -1)
			*intptr = ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oCiphers:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*activep && options->ciphers == ಖಾಲಿ)
			options->ciphers = xstrdup(arg);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oMacs:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*activep && options->macs == ಖಾಲಿ)
			options->macs = xstrdup(arg);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oKexAlgorithms:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*arg != '-' &&
		    !kex_ಹೆಸರುಗಳು_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*activep && options->kex_algorithms == ಖಾಲಿ)
			options->kex_algorithms = xstrdup(arg);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ o_Host_ಕೀಲಿ_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
parse_pubkey_algos:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*arg != '-' &&
		    !sshkey_ಹೆಸರುಗಳು_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*activep && *charptr == ಖಾಲಿ)
			*charptr = xstrdup(arg);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		ಹೋಗು parse_pubkey_algos;

	ಸ್ಥಿತಿ oLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಮೌಲ್ಯ = log_level_ಸಂಖ್ಯೆ(arg);
		ಆದರೆ (ಮೌಲ್ಯ == SYSLOG_LEVEL_NOT_ಗಣ) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_ಗಣ)
			*log_level_ptr = (LogLevel) ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಮೌಲ್ಯ = log_facility_ಸಂಖ್ಯೆ(arg);
		ಆದರೆ (ಮೌಲ್ಯ == SYSLOG_FACILITY_NOT_ಗಣ) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oLogVerbose:
		cppptr = &options->log_verbose;
		uintptr = &options->ಅಂಕೆ_log_verbose;
		i = 0;
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			ಆದರೆ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ಹೋಗು ಹೊರಹೋಗು;
			}
			/* Allow "none" only in first position */
			ಆದರೆ (strcasecmp(arg, "none") == 0) {
				ಆದರೆ (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ಹೋಗು ಹೊರಹೋಗು;
				}
			}
			i++;
			ಆದರೆ (*activep && *uintptr == 0) {
				*cppptr = xrecallocarray(*cppptr, *uintptr,
				    *uintptr + 1, ಗಾತ್ರ(**cppptr));
				(*cppptr)[(*uintptr)++] = xstrdup(arg);
			}
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oLocalForward:
	ಸ್ಥಿತಿ oRemoteForward:
	ಸ್ಥಿತಿ oDynamicForward:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		ಆದರೆ (!dynamicfwd) {
			arg2 = argv_ಮುಂದಿನ(&ac, &av);
			ಆದರೆ (arg2 == ಖಾಲಿ || *arg2 == '\0') {
				ಆದರೆ (remotefwd)
					dynamicfwd = 1;
				ಇಲ್ಲದಿದ್ದರೆ {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					ಹೋಗು ಹೊರಹೋಗು;
				}
			} ಇಲ್ಲದಿದ್ದರೆ {
				/* construct a string for parse_forward */
				snprintf(fwdarg, ಗಾತ್ರ(fwdarg), "%s:%s", arg,
				    arg2);
			}
		}
		ಆದರೆ (dynamicfwd)
			strlcpy(fwdarg, arg, ಗಾತ್ರ(fwdarg));

		ಆದರೆ (parse_forward(&fwd, fwdarg, dynamicfwd, remotefwd) == 0) {
			error("%.200s line %d: Bad forwarding specification.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}

		ಆದರೆ (*activep) {
			ಆದರೆ (remotefwd) {
				ಕೂಡಿಸು_remote_forward(options, &fwd);
			} ಇಲ್ಲದಿದ್ದರೆ {
				ಕೂಡಿಸು_local_forward(options, &fwd);
			}
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oPermitRemoteOpen:
		uintptr = &options->ಅಂಕೆ_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		ಸಿಕ್ಕಿತು = *uintptr == 0;
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			ಆದರೆ (strcasecmp(arg, "none") == 0 ||
			    strcasecmp(arg, "any") == 0) {
				ಆದರೆ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					ಬಿಡುಗಡೆ(arg2);
					ಹೋಗು ಹೊರಹೋಗು;
				}
			} ಇಲ್ಲದಿದ್ದರೆ {
				p = hpdelim(&arg);
				ಆದರೆ (p == ಖಾಲಿ) {
					fatal("%s line %d: missing host in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
				}
				p = cleanhostname(p);
				/*
				 * don't want to use permitopen_port to avoid
				 * dependency on channels.[ch] here.
				 */
				ಆದರೆ (arg == ಖಾಲಿ || (strcmp(arg, "*") != 0 &&
				    a2port(arg) <= 0)) {
					fatal("%s line %d: bad port number "
					    "in %s", filename, linenum,
					    lookup_opcode_name(opcode));
				}
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg2);
			ಬಿಡುಗಡೆ(arg2);
		}
		ಆದರೆ (nstrs == 0)
			fatal("%s line %d: missing %s specification",
			    filename, linenum, lookup_opcode_name(opcode));
		ಆದರೆ (ಸಿಕ್ಕಿತು && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = ಖಾಲಿ; /* transferred */
			nstrs = 0;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oClearAllForwardings:
		intptr = &options->clear_forwardings;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ oHost:
		ಆದರೆ (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		*activep = 0;
		arg2 = ಖಾಲಿ;
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			ಆದರೆ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಆದರೆ ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				ನಿಲ್ಲಿಸು;
			}
			negated = *arg == '!';
			ಆದರೆ (negated)
				arg++;
			ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ(host, arg)) {
				ಆದರೆ (negated) {
					debug("%.200s line %d: Skipping Host "
					    "block because of negated match "
					    "for %.100s", filename, linenum,
					    arg);
					*activep = 0;
					argv_consume(&ac);
					ನಿಲ್ಲಿಸು;
				}
				ಆದರೆ (!*activep)
					arg2 = arg; /* logged below */
				*activep = 1;
			}
		}
		ಆದರೆ (*activep)
			debug("%.200s line %d: Applying options for %.100s",
			    filename, linenum, arg2);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ o_ಹೊಂದಿಕೆ:
		ಆದರೆ (cmdline) {
			error("Match directive not supported as a command-line "
			    "option");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಮೌಲ್ಯ = ಹೊಂದಿಕೆ_cfg_ಸಾಲು(options, str, &ac, &av, pw, host,
		    original_host, remote_command, flags & SSHCONF_FINAL,
		    want_final_pass, filename, linenum);
		ಆದರೆ (ಮೌಲ್ಯ < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (strcmp(arg, "none") == 0)
			ಮೌಲ್ಯ = SSH_ESCAPECHAR_NONE;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (arg[1] == '\0')
			ಮೌಲ್ಯ = (u_char) arg[0];
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (arg[0] == '^' && arg[2] == 0 &&
		    (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			ಮೌಲ್ಯ = (u_char) arg[1] & 31;
		ಇಲ್ಲದಿದ್ದರೆ {
			error("%.200s line %d: Bad escape character.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*activep && *intptr == -1)
			*intptr = ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ o_ವಿಳಾಸ_Family:
		intptr = &options->ವಿಳಾಸ_family;
		multistate_ptr = multistate_addressfamily;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ oIdentitiesOnly:
		intptr = &options->identities_only;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ oServerAliveInterval:
		intptr = &options->server_alive_interval;
		ಹೋಗು parse_ಸಮಯ;

	ಸ್ಥಿತಿ o_Server_Alive_ಎಣಿಕೆ_Max:
		intptr = &options->server_alive_ಎಣಿಕೆ_max;
		ಹೋಗು parse_int;

	ಸ್ಥಿತಿ oSendEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			ಆದರೆ (*arg == '\0' || strchr(arg, '=') != ಖಾಲಿ) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಸಿಕ್ಕಿತು = 1;
			ಆದರೆ (!*activep)
				ಮುಂದುವರಿ;
			ಆದರೆ (*arg == '-') {
				/* Removing an env var */
				rm_env(options, arg, filename, linenum);
				ಮುಂದುವರಿ;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->ಅಂಕೆ_send_env, arg);
		}
		ಆದರೆ (!ಸಿಕ್ಕಿತು) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ o_ಗಣ_Env:
		ಸಿಕ್ಕಿತು = options->ಅಂಕೆ_setenv == 0;
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			ಆದರೆ (strchr(arg, '=') == ಖಾಲಿ) {
				error("%s line %d: Invalid SetEnv.",
				    filename, linenum);
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಆದರೆ (lookup_setenv_ಒಳ_list(arg, strs, nstrs) != ಖಾಲಿ) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				ಮುಂದುವರಿ;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg);
		}
		ಆದರೆ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಆದರೆ (ಸಿಕ್ಕಿತು && *activep) {
			options->setenv = strs;
			options->ಅಂಕೆ_setenv = nstrs;
			strs = ಖಾಲಿ; /* transferred */
			nstrs = 0;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ o_Control_ಮಾರ್ಗ:
		charptr = &options->control_ಮಾರ್ಗ;
		ಹೋಗು parse_string;

	ಸ್ಥಿತಿ oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing ControlPersist"
			    " argument.", filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಮೌಲ್ಯ = 0;
		value2 = 0;	/* timeout */
		ಆದರೆ (strcmp(arg, "no") == 0 || strcmp(arg, "false") == 0)
			ಮೌಲ್ಯ = 0;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(arg, "yes") == 0 || strcmp(arg, "true") == 0)
			ಮೌಲ್ಯ = 1;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((value2 = convtime(arg)) >= 0)
			ಮೌಲ್ಯ = 1;
		ಇಲ್ಲದಿದ್ದರೆ {
			error("%.200s line %d: Bad ControlPersist argument.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*activep && *intptr == -1) {
			*intptr = ಮೌಲ್ಯ;
			options->control_persist_timeout = value2;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ o_Hash_ತಿಳಿದ_Hosts:
		intptr = &options->hash_ತಿಳಿದ_hosts;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ oTunnelDevice:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಮೌಲ್ಯ = a2tun(arg, &value2);
		ಆದರೆ (ಮೌಲ್ಯ == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*activep && options->tun_local == -1) {
			options->tun_local = ಮೌಲ್ಯ;
			options->tun_remote = value2;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oLocalCommand:
		charptr = &options->local_command;
		ಹೋಗು parse_command;

	ಸ್ಥಿತಿ oPermitLocalCommand:
		intptr = &options->permit_local_command;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ oRemoteCommand:
		charptr = &options->remote_command;
		ಹೋಗು parse_command;

	ಸ್ಥಿತಿ o_Visual_Host_ಕೀಲಿ:
		intptr = &options->visual_host_ಕೀಲಿ;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ oInclude:
		ಆದರೆ (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಮೌಲ್ಯ = 0;
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			ಆದರೆ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ಹೋಗು ಹೊರಹೋಗು;
			}
			/* Expand %tokens and environment variables */
			ಆದರೆ ((p = expand_ಹೊಂದಿಕೆ_exec_or_include_ಮಾರ್ಗ(arg,
			    options, pw, host, original_host,
			    flags & SSHCONF_FINAL, 1)) == ಖಾಲಿ) {
				error("%.200s line %d: Unable to expand user "
				    "config file '%.100s'",
				    filename, linenum, arg);
				ಮುಂದುವರಿ;
			}
			/*
			 * Ensure all paths are anchored. User configuration
			 * files may begin with '~/' but system configurations
			 * must not. If the path is relative, then treat it
			 * as living in ~/.ssh for user configurations or
			 * /etc/ssh for system ones.
			 */
			ಆದರೆ (*p == '~' && (flags & SSHCONF_USERCONF) == 0) {
				error("%.200s line %d: bad include path %s.",
				    filename, linenum, p);
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಆದರೆ (!ಮಾರ್ಗ_absolute(p) && *p != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" ಮಾರ್ಗ_SSH_USER_DIR : SSHDIR, p);
			} ಇಲ್ಲದಿದ್ದರೆ {
				arg2 = xstrdup(p);
			}
			ಬಿಡುಗಡೆ(p);
			memset(&gl, 0, ಗಾತ್ರ(gl));
			r = glob(arg2, GLOB_TILDE, ಖಾಲಿ, &gl);
			ಆದರೆ (r == GLOB_NOMATCH) {
				debug("%.200s line %d: include %s matched no "
				    "files",filename, linenum, arg2);
				ಬಿಡುಗಡೆ(arg2);
				ಮುಂದುವರಿ;
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r != 0) {
				error("%.200s line %d: glob failed for %s.",
				    filename, linenum, arg2);
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಬಿಡುಗಡೆ(arg2);
			oactive = *activep;
			ಗಾಗಿ (i = 0; i < gl.gl_pathc; i++) {
				debug3("%.200s line %d: Including file %s "
				    "depth %d%s", filename, linenum,
				    gl.gl_pathv[i], ಆಳ,
				    oactive ? "" : " (parse only)");
				r = read_config_file_ಆಳ(gl.gl_pathv[i],
				    pw, host, original_host, remote_command,
				    options, flags | SSHCONF_CHECKPERM |
				    (oactive ? 0 : SSHCONF_NEVERMATCH),
				    activep, want_final_pass, ಆಳ + 1);
				ಆದರೆ (r != 1 && errno != ENOENT) {
					error("%.200s line %d: Can't open user "
					    "config file %.100s: %.100s",
					    filename, linenum, gl.gl_pathv[i],
					    strerror(errno));
					globfree(&gl);
					ಹೋಗು ಹೊರಹೋಗು;
				}
				/*
				 * don't let Match in includes clobber the
				 * containing file's Match state.
				 */
				*activep = oactive;
				ಆದರೆ (r != 1)
					ಮೌಲ್ಯ = -1;
			}
			globfree(&gl);
		}
		ಆದರೆ (ಮೌಲ್ಯ != 0)
			ret = ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oIPQoS:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ ((ಮೌಲ್ಯ = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (ಮೌಲ್ಯ == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			ಮೌಲ್ಯ = ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ;
		}
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (arg == ಖಾಲಿ)
			value2 = ಮೌಲ್ಯ;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ;
		}
		ಆದರೆ (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = ಮೌಲ್ಯ;
			options->ip_qos_bulk = value2;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ oSessionType:
		intptr = &options->session_type;
		multistate_ptr = multistate_sessiontype;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ oStdinNull:
		intptr = &options->stdin_null;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ oForkAfterAuthentication:
		intptr = &options->fork_after_authentication;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		ಹೋಗು parse_string;

	ಸ್ಥಿತಿ oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ oCanonicalDomains:
		ಸಿಕ್ಕಿತು = options->ಅಂಕೆ_canonical_domains == 0;
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			/* Allow "none" only in first position */
			ಆದರೆ (strcasecmp(arg, "none") == 0) {
				ಆದರೆ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ಹೋಗು ಹೊರಹೋಗು;
				}
			}
			ಆದರೆ (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				ಹೋಗು ಹೊರಹೋಗು;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ಆದರೆ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಆದರೆ (ಸಿಕ್ಕಿತು && *activep) {
			options->canonical_domains = strs;
			options->ಅಂಕೆ_canonical_domains = nstrs;
			strs = ಖಾಲಿ; /* transferred */
			nstrs = 0;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oCanonicalizePermittedCNAMEs:
		ಸಿಕ್ಕಿತು = options->ಅಂಕೆ_permitted_cnames == 0;
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			ಆದರೆ (strcasecmp(arg, "none") == 0) {
				ಆದರೆ (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ಹೋಗು ಹೊರಹೋಗು;
				}
				arg2 = "";
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(arg, "*") == 0) {
				arg2 = arg;
			} ಇಲ್ಲದಿದ್ದರೆ {
				lowercase(arg);
				ಆದರೆ ((arg2 = strchr(arg, ':')) == ಖಾಲಿ ||
				    arg2[1] == '\0') {
					error("%s line %d: "
					    "Invalid permitted CNAME \"%s\"",
					    filename, linenum, arg);
					ಹೋಗು ಹೊರಹೋಗು;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    ಗಾತ್ರ(*cnames));
			cnames[ncnames].ಮೂಲ_list = xstrdup(arg);
			cnames[ncnames].ಗುರಿ_list = xstrdup(arg2);
			ncnames++;
		}
		ಆದರೆ (ncnames == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಆದರೆ (ಸಿಕ್ಕಿತು && *activep) {
			options->permitted_cnames = cnames;
			options->ಅಂಕೆ_permitted_cnames = ncnames;
			cnames = ಖಾಲಿ; /* transferred */
			ncnames = 0;
		}
		/* un-transferred cnames is cleaned up before exit */
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		ಹೋಗು parse_int;

	ಸ್ಥಿತಿ oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ o_ಹರಿವು_Local_Bind_ಮುಖವಾಡ:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		/* Parse mode in octal format */
		ಮೌಲ್ಯ = strtol(arg, &endofnumber, 8);
		ಆದರೆ (arg == endofnumber || ಮೌಲ್ಯ < 0 || ಮೌಲ್ಯ > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*activep &&
		    options->fwd_opts.streamlocal_bind_ಮುಖವಾಡ == (ಬಹುಲಕ_t)-1)
			options->fwd_opts.streamlocal_bind_ಮುಖವಾಡ = (ಬಹುಲಕ_t)ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ o_ಹರಿವು_Local_Bind_Unlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ o_Revoked_Host_ಕೀಲಿಗಳು:
		uintptr = &options->ಅಂಕೆ_revoked_host_ಕೀಲಿಗಳು;
		cppptr = &options->revoked_host_ಕೀಲಿಗಳು;
		ಸಿಕ್ಕಿತು = *uintptr == 0;
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			ಆದರೆ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ಹೋಗು ಹೊರಹೋಗು;
			}
			/* Allow "none" only in first position */
			ಆದರೆ (strcasecmp(arg, "none") == 0) {
				ಆದರೆ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ಹೋಗು ಹೊರಹೋಗು;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ಆದರೆ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಆದರೆ (ಸಿಕ್ಕಿತು && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = ಖಾಲಿ; /* transferred */
			nstrs = 0;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((ಮೌಲ್ಯ = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*activep && *intptr == -1)
			*intptr = ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oUpdateHostkeys:
		intptr = &options->update_hostkeys;
		multistate_ptr = multistate_yesnoask;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ oHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
		ಹೋಗು parse_pubkey_algos;

	ಸ್ಥಿತಿ oPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		ಹೋಗು parse_pubkey_algos;

	ಸ್ಥಿತಿ o_ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_Agent:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		arg2 = argv_ಮುಂದಿನ(&ac, &av);
		ಮೌಲ್ಯ = parse_multistate_ಮೌಲ್ಯ(arg, filename, linenum,
		    multistate_yesnoaskconfirm);
		value2 = 0; /* unlimited lifespan by default */
		ಆದರೆ (ಮೌಲ್ಯ == 3 && arg2 != ಖಾಲಿ) {
			/* allow "AddKeysToAgent confirm 5m" */
			ಆದರೆ ((value2 = convtime(arg2)) == -1) {
				error("%s line %d: invalid time value.",
				    filename, linenum);
				ಹೋಗು ಹೊರಹೋಗು;
			}
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಮೌಲ್ಯ == -1 && arg2 == ಖಾಲಿ) {
			ಆದರೆ ((value2 = convtime(arg)) == -1) {
				error("%s line %d: unsupported option",
				    filename, linenum);
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಮೌಲ್ಯ = 1; /* yes */
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಮೌಲ್ಯ == -1 || arg2 != ಖಾಲಿ) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*activep && options->ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_agent == -1) {
			options->ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_agent = ಮೌಲ್ಯ;
			options->ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_agent_lifespan = value2;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ o_ತಟಸ್ಥ_Agent:
		charptr = &options->ತಟಸ್ಥ_agent;
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
  parse_agent_ಮಾರ್ಗ:
		/* Extra validation if the string represents an env var. */
		ಆದರೆ ((arg2 = dollar_expand(&r, arg)) == ಖಾಲಿ || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಬಿಡುಗಡೆ(arg2);
		/* check for legacy environment format */
		ಆದರೆ (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*activep && *charptr == ಖಾಲಿ)
			*charptr = xstrdup(arg);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		ಹೋಗು parse_flag;

	ಸ್ಥಿತಿ oRequiredRSASize:
		intptr = &options->required_rsa_ಗಾತ್ರ;
		ಹೋಗು parse_int;

	ಸ್ಥಿತಿ oWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		ಹೋಗು parse_multistate;

	ಸ್ಥಿತಿ oObscureKeystrokeTiming:
		ಮೌಲ್ಯ = -1;
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			ಆದರೆ (ಮೌಲ್ಯ != -1) {
				error("%s line %d: invalid arguments",
				    filename, linenum);
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಆದರೆ (strcmp(arg, "yes") == 0 ||
			    strcmp(arg, "true") == 0)
				ಮೌಲ್ಯ = SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(arg, "no") == 0 ||
			    strcmp(arg, "false") == 0)
				ಮೌಲ್ಯ = 0;
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(arg, "interval:", 9) == 0) {
				ಆದರೆ ((errstr = atoi_err(arg + 9,
				    &ಮೌಲ್ಯ)) != ಖಾಲಿ) {
					error("%s line %d: integer value %s.",
					    filename, linenum, errstr);
					ಹೋಗು ಹೊರಹೋಗು;
				}
				ಆದರೆ (ಮೌಲ್ಯ <= 0 || ಮೌಲ್ಯ > 1000) {
					error("%s line %d: value out of range.",
					    filename, linenum);
					ಹೋಗು ಹೊರಹೋಗು;
				}
			} ಇಲ್ಲದಿದ್ದರೆ {
				error("%s line %d: unsupported argument \"%s\"",
				    filename, linenum, arg);
				ಹೋಗು ಹೊರಹೋಗು;
			}
		}
		ಆದರೆ (ಮೌಲ್ಯ == -1) {
			error("%s line %d: missing argument",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		intptr = &options->obscure_keystroke_timing_interval;
		ಆದರೆ (*activep && *intptr == -1)
			*intptr = ಮೌಲ್ಯ;
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oChannelTimeout:
		ಸಿಕ್ಕಿತು = options->ಅಂಕೆ_channel_timeouts == 0;
		ಆಗ ((arg = argv_ಮುಂದಿನ(&ac, &av)) != ಖಾಲಿ) {
			/* Allow "none" only in first position */
			ಆದರೆ (strcasecmp(arg, "none") == 0) {
				ಆದರೆ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ಹೋಗು ಹೊರಹೋಗು;
				}
			} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (parse_ನಮೂನೆ_interval(arg,
			    ಖಾಲಿ, ಖಾಲಿ) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ಆದರೆ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ಆದರೆ (ಸಿಕ್ಕಿತು && *activep) {
			options->channel_timeouts = strs;
			options->ಅಂಕೆ_channel_timeouts = nstrs;
			strs = ಖಾಲಿ; /* transferred */
			nstrs = 0;
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ o_ಆವೃತ್ತಿ_Addendum:
		ಆದರೆ (str == ಖಾಲಿ || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		ಆದರೆ (strchr(str + len, '\r') != ಖಾಲಿ) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		ಆದರೆ ((arg = strchr(ಸಾಲು, '#')) != ಖಾಲಿ) {
			*arg = '\0';
			rtrim(ಸಾಲು);
		}
		ಆದರೆ (*activep && options->ಆವೃತ್ತಿ_addendum == ಖಾಲಿ) {
			ಆದರೆ (strcasecmp(str + len, "none") == 0)
				options->ಆವೃತ್ತಿ_addendum = xstrdup("");
			ಇಲ್ಲದಿದ್ದರೆ
				options->ಆವೃತ್ತಿ_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oRefuseConnection:
		arg = argv_ಮುಂದಿನ(&ac, &av);
		ಆದರೆ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (*activep) {
			fatal("%.200s line %d: RefuseConnection: %s",
			    filename, linenum, arg);
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ oUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		ನಿಲ್ಲಿಸು;

	ಪೂರ್ವನಿಯೋಜಿತ:
		error("%s line %d: Unimplemented opcode %d",
		    filename, linenum, opcode);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* Check that there is no garbage at end of line. */
	ಆದರೆ (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* success */
	ret = 0;
 ಹೊರಹೋಗು:
	free_canon_cnames(cnames, ncnames);
	opt_array_free2(strs, ಖಾಲಿ, nstrs);
	argv_free(oav, oac);
	ಹಿಂತಿರುಗಿ ret;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */
ಪೂರ್ಣಾಂಕ
read_config_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ರಚನೆ passwd *pw, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *original_host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_command, Options *options, ಪೂರ್ಣಾಂಕ flags,
    ಪೂರ್ಣಾಂಕ *want_final_pass)
{
	ಪೂರ್ಣಾಂಕ ಸಕ್ರಿಯ = 1;

	ಹಿಂತಿರುಗಿ read_config_file_ಆಳ(filename, pw, host, original_host,
	    remote_command, options, flags, &ಸಕ್ರಿಯ, want_final_pass, 0);
}

#ವ್ಯಾಖ್ಯಾನಿಸು READCONF_MAX_ಆಳ	16
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
read_config_file_ಆಳ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *filename, ರಚನೆ passwd *pw,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *original_host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *remote_command,
    Options *options, ಪೂರ್ಣಾಂಕ flags, ಪೂರ್ಣಾಂಕ *activep, ಪೂರ್ಣಾಂಕ *want_final_pass, ಪೂರ್ಣಾಂಕ ಆಳ)
{
	FILE *f;
	ಅಕ್ಷರ *ಸಾಲು = ಖಾಲಿ;
	ಗಾತ್ರ_t linesize = 0;
	ಪೂರ್ಣಾಂಕ linenum;
	ಪೂರ್ಣಾಂಕ bad_options = 0;

	ಆದರೆ (ಆಳ < 0 || ಆಳ > READCONF_MAX_ಆಳ)
		fatal("Too many recursive configuration includes");

	ಆದರೆ ((f = fopen(filename, "r")) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;

	ಆದರೆ (flags & SSHCONF_CHECKPERM) {
		ರಚನೆ stat sb;

		ಆದರೆ (fstat(fileno(f), &sb) == -1)
			fatal("fstat %s: %s", filename, strerror(errno));
		ಆದರೆ (((sb.st_uid != 0 && sb.st_uid != getuid()) ||
		    (sb.st_mode & 022) != 0))
			fatal("Bad owner or permissions on %s", filename);
	}

	debug("Reading configuration data %.200s", filename);

	/*
	 * Mark that we are now processing the options.  This flag is turned
	 * on/off by Host specifications.
	 */
	linenum = 0;
	ಆಗ (getline(&ಸಾಲು, &linesize, f) != -1) {
		/* Update line number counter. */
		linenum++;
		/*
		 * Trim out comments and strip whitespace.
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages.
		 */
		ಆದರೆ (process_config_ಸಾಲು_ಆಳ(options, pw, host, original_host,
		    remote_command, ಸಾಲು, filename, linenum, activep, flags,
		    want_final_pass, ಆಳ) != 0)
			bad_options++;
	}
	ಬಿಡುಗಡೆ(ಸಾಲು);
	fclose(f);
	ಆದರೆ (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
	ಹಿಂತಿರುಗಿ 1;
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
ಪೂರ್ಣಾಂಕ
option_clear_or_none(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *o)
{
	ಹಿಂತಿರುಗಿ o == ಖಾಲಿ || strcasecmp(o, "none") == 0;
}

/*
 * Returns 1 if CanonicalizePermittedCNAMEs have been specified, 0 otherwise.
 * Allowed to be called on non-final configuration.
 */
ಪೂರ್ಣಾಂಕ
config_has_permitted_cnames(Options *options)
{
	ಆದರೆ (options->ಅಂಕೆ_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].ಮೂಲ_list, "none") == 0 &&
	    strcmp(options->permitted_cnames[0].ಗುರಿ_list, "") == 0)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ options->ಅಂಕೆ_permitted_cnames > 0;
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
	memset(options, 'X', ಗಾತ್ರ(*options));
	options->host_arg = ಖಾಲಿ;
	options->forward_agent = -1;
	options->forward_agent_sock_ಮಾರ್ಗ = ಖಾಲಿ;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = ಖಾಲಿ;
	options->stdio_forward_ಪೋರ್ಟ್ = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = ಖಾಲಿ;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_ಮುಖವಾಡ = (ಬಹುಲಕ_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = ಖಾಲಿ;
	options->hostbased_authentication = -1;
	options->batch_ಬಹುಲಕ = -1;
	options->check_host_ip = -1;
	options->strict_host_ಕೀಲಿ_checking = -1;
	options->compression = -1;
	options->tcp_keep_alive = -1;
	options->ಪೋರ್ಟ್ = -1;
	options->ವಿಳಾಸ_family = -1;
	options->connection_attempts = -1;
	options->connection_timeout = -1;
	options->ಸಂಖ್ಯೆ_ದ_password_prompts = -1;
	options->ciphers = ಖಾಲಿ;
	options->macs = ಖಾಲಿ;
	options->kex_algorithms = ಖಾಲಿ;
	options->hostkeyalgorithms = ಖಾಲಿ;
	options->ca_sign_algorithms = ಖಾಲಿ;
	options->ಅಂಕೆ_ತಟಸ್ಥ_files = 0;
	memset(options->ತಟಸ್ಥ_ಕೀಲಿಗಳು, 0, ಗಾತ್ರ(options->ತಟಸ್ಥ_ಕೀಲಿಗಳು));
	options->ಅಂಕೆ_certificate_files = 0;
	memset(options->certificates, 0, ಗಾತ್ರ(options->certificates));
	options->hostname = ಖಾಲಿ;
	options->host_ಕೀಲಿ_alias = ಖಾಲಿ;
	options->proxy_command = ಖಾಲಿ;
	options->jump_user = ಖಾಲಿ;
	options->jump_host = ಖಾಲಿ;
	options->jump_ಪೋರ್ಟ್ = -1;
	options->jump_extra = ಖಾಲಿ;
	options->user = ಖಾಲಿ;
	options->escape_char = -1;
	options->ಅಂಕೆ_system_hostfiles = 0;
	options->ಅಂಕೆ_user_hostfiles = 0;
	options->local_forwards = ಖಾಲಿ;
	options->ಅಂಕೆ_local_forwards = 0;
	options->remote_forwards = ಖಾಲಿ;
	options->ಅಂಕೆ_remote_forwards = 0;
	options->permitted_remote_opens = ಖಾಲಿ;
	options->ಅಂಕೆ_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_ಗಣ;
	options->log_level = SYSLOG_LEVEL_NOT_ಗಣ;
	options->ಅಂಕೆ_log_verbose = 0;
	options->log_verbose = ಖಾಲಿ;
	options->preferred_authentications = ಖಾಲಿ;
	options->bind_ವಿಳಾಸ = ಖಾಲಿ;
	options->bind_interface = ಖಾಲಿ;
	options->pkcs11_provider = ಖಾಲಿ;
	options->sk_provider = ಖಾಲಿ;
	options->enable_ssh_keysign = -1;
	options->no_host_authentication_for_localhost = -1;
	options->identities_only = -1;
	options->rekey_ಎಲ್ಲೆ = -1;
	options->rekey_interval = -1;
	options->verify_host_ಕೀಲಿ_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_ಎಣಿಕೆ_max = -1;
	options->send_env = ಖಾಲಿ;
	options->ಅಂಕೆ_send_env = 0;
	options->setenv = ಖಾಲಿ;
	options->ಅಂಕೆ_setenv = 0;
	options->control_ಮಾರ್ಗ = ಖಾಲಿ;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_ತಿಳಿದ_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = ಖಾಲಿ;
	options->permit_local_command = -1;
	options->remote_command = ಖಾಲಿ;
	options->ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_agent = -1;
	options->ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_agent_lifespan = -1;
	options->ತಟಸ್ಥ_agent = ಖಾಲಿ;
	options->visual_host_ಕೀಲಿ = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = ಖಾಲಿ;
	options->ಅಂಕೆ_canonical_domains = 0;
	options->ಅಂಕೆ_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_ಕೀಲಿಗಳು = ಖಾಲಿ;
	options->ಅಂಕೆ_revoked_host_ಕೀಲಿಗಳು = 0;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->hostbased_accepted_algos = ಖಾಲಿ;
	options->pubkey_accepted_algos = ಖಾಲಿ;
	options->ತಿಳಿದ_hosts_command = ಖಾಲಿ;
	options->required_rsa_ಗಾತ್ರ = -1;
	options->warn_weak_crypto = -1;
	options->enable_escape_commandline = -1;
	options->obscure_keystroke_timing_interval = -1;
	options->ಟ್ಯಾಗ್ = ಖಾಲಿ;
	options->channel_timeouts = ಖಾಲಿ;
	options->ಅಂಕೆ_channel_timeouts = 0;
	options->ಆವೃತ್ತಿ_addendum = ಖಾಲಿ;
}

/*
 * A petite version of fill_default_options() that just fills the options
 * needed for hostname canonicalization to proceed.
 */
ಶೂನ್ಯ
fill_default_options_for_canonicalization(Options *options)
{
	ಆದರೆ (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	ಆದರೆ (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	ಆದರೆ (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
}

/*
 * Called after processing other sources of option data, this fills those
 * options for which no value has been specified with their default values.
 */
ಪೂರ್ಣಾಂಕ
fill_default_options(Options * options)
{
	ಅಕ್ಷರ *all_cipher, *all_mac, *all_kex, *all_ಕೀಲಿ, *all_sig;
	ಅಕ್ಷರ *def_cipher, *def_mac, *def_kex, *def_ಕೀಲಿ, *def_sig;
	ಪೂರ್ಣಾಂಕ ret = -1, r;

	ಆದರೆ (options->forward_agent == -1)
		options->forward_agent = 0;
	ಆದರೆ (options->forward_x11 == -1)
		options->forward_x11 = 0;
	ಆದರೆ (options->forward_x11_trusted == -1)
		options->forward_x11_trusted = 0;
	ಆದರೆ (options->forward_x11_timeout == -1)
		options->forward_x11_timeout = 1200;
	/*
	 * stdio forwarding (-W) changes the default for these but we defer
	 * setting the values so they can be overridden.
	 */
	ಆದರೆ (options->exit_on_forward_failure == -1)
		options->exit_on_forward_failure =
		    options->stdio_forward_host != ಖಾಲಿ ? 1 : 0;
	ಆದರೆ (options->clear_forwardings == -1)
		options->clear_forwardings =
		    options->stdio_forward_host != ಖಾಲಿ ? 1 : 0;
	ಆದರೆ (options->clear_forwardings == 1)
		clear_forwardings(options);

	ಆದರೆ (options->xauth_location == ಖಾಲಿ)
		options->xauth_location = xstrdup(ಮಾರ್ಗ_XAUTH);
	ಆದರೆ (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	ಆದರೆ (options->fwd_opts.streamlocal_bind_ಮುಖವಾಡ == (ಬಹುಲಕ_t)-1)
		options->fwd_opts.streamlocal_bind_ಮುಖವಾಡ = 0177;
	ಆದರೆ (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	ಆದರೆ (options->pubkey_authentication == -1)
		options->pubkey_authentication = SSH_PUBKEY_AUTH_ALL;
	ಆದರೆ (options->gss_authentication == -1)
		options->gss_authentication = 0;
	ಆದರೆ (options->gss_deleg_creds == -1)
		options->gss_deleg_creds = 0;
	ಆದರೆ (options->password_authentication == -1)
		options->password_authentication = 1;
	ಆದರೆ (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	ಆದರೆ (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	ಆದರೆ (options->batch_ಬಹುಲಕ == -1)
		options->batch_ಬಹುಲಕ = 0;
	ಆದರೆ (options->check_host_ip == -1)
		options->check_host_ip = 0;
	ಆದರೆ (options->strict_host_ಕೀಲಿ_checking == -1)
		options->strict_host_ಕೀಲಿ_checking = SSH_STRICT_HOSTKEY_ASK;
	ಆದರೆ (options->compression == -1)
		options->compression = 0;
	ಆದರೆ (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = SSH_KEEPALIVES_TRANSPORT;
	ಆದರೆ (options->ಪೋರ್ಟ್ == -1)
		options->ಪೋರ್ಟ್ = 0;	/* Filled in ssh_connect. */
	ಆದರೆ (options->ವಿಳಾಸ_family == -1)
		options->ವಿಳಾಸ_family = AF_UNSPEC;
	ಆದರೆ (options->connection_attempts == -1)
		options->connection_attempts = 1;
	ಆದರೆ (options->ಸಂಖ್ಯೆ_ದ_password_prompts == -1)
		options->ಸಂಖ್ಯೆ_ದ_password_prompts = 3;
	/* options->hostkeyalgorithms, default set in myproposals.h */
	ಆದರೆ (options->ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_agent == -1) {
		options->ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_agent = 0;
		options->ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_agent_lifespan = 0;
	}
	ಆದರೆ (options->ಅಂಕೆ_ತಟಸ್ಥ_files == 0) {
		ಕೂಡಿಸು_ತಟಸ್ಥ_file(options, "~/", ಮಾರ್ಗ_SSH_CLIENT_ID_RSA, 0);
		ಕೂಡಿಸು_ತಟಸ್ಥ_file(options, "~/", ಮಾರ್ಗ_SSH_CLIENT_ID_ECDSA, 0);
		ಕೂಡಿಸು_ತಟಸ್ಥ_file(options, "~/",
		    ಮಾರ್ಗ_SSH_CLIENT_ID_ECDSA_SK, 0);
		ಕೂಡಿಸು_ತಟಸ್ಥ_file(options, "~/",
		    ಮಾರ್ಗ_SSH_CLIENT_ID_ED25519, 0);
		ಕೂಡಿಸು_ತಟಸ್ಥ_file(options, "~/",
		    ಮಾರ್ಗ_SSH_CLIENT_ID_ED25519_SK, 0);
		ಕೂಡಿಸು_ತಟಸ್ಥ_file(options, "~/",
		    ಮಾರ್ಗ_SSH_CLIENT_ID_MLDSA44_ED25519, 0);
	}
	ಆದರೆ (options->escape_char == -1)
		options->escape_char = '~';
	ಆದರೆ (options->ಅಂಕೆ_system_hostfiles == 0) {
		options->system_hostfiles[options->ಅಂಕೆ_system_hostfiles++] =
		    xstrdup(ಮಾರ್ಗ_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->ಅಂಕೆ_system_hostfiles++] =
		    xstrdup(ಮಾರ್ಗ_SSH_SYSTEM_HOSTFILE2);
	}
	ಆದರೆ (options->update_hostkeys == -1) {
		ಆದರೆ (options->verify_host_ಕೀಲಿ_dns <= 0 &&
		    (options->ಅಂಕೆ_user_hostfiles == 0 ||
		    (options->ಅಂಕೆ_user_hostfiles == 1 && strcmp(options->
		    user_hostfiles[0], ಮಾರ್ಗ_SSH_USER_HOSTFILE) == 0)))
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_YES;
		ಇಲ್ಲದಿದ್ದರೆ
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_NO;
	}
	ಆದರೆ (options->ಅಂಕೆ_user_hostfiles == 0) {
		options->user_hostfiles[options->ಅಂಕೆ_user_hostfiles++] =
		    xstrdup(ಮಾರ್ಗ_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->ಅಂಕೆ_user_hostfiles++] =
		    xstrdup(ಮಾರ್ಗ_SSH_USER_HOSTFILE2);
	}
	ಆದರೆ (options->log_level == SYSLOG_LEVEL_NOT_ಗಣ)
		options->log_level = SYSLOG_LEVEL_INFO;
	ಆದರೆ (options->log_facility == SYSLOG_FACILITY_NOT_ಗಣ)
		options->log_facility = SYSLOG_FACILITY_USER;
	ಆದರೆ (options->no_host_authentication_for_localhost == -1)
		options->no_host_authentication_for_localhost = 0;
	ಆದರೆ (options->identities_only == -1)
		options->identities_only = 0;
	ಆದರೆ (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	ಆದರೆ (options->rekey_ಎಲ್ಲೆ == -1)
		options->rekey_ಎಲ್ಲೆ = 0;
	ಆದರೆ (options->rekey_interval == -1)
		options->rekey_interval = 0;
	ಆದರೆ (options->verify_host_ಕೀಲಿ_dns == -1)
		options->verify_host_ಕೀಲಿ_dns = 0;
	ಆದರೆ (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	ಆದರೆ (options->server_alive_ಎಣಿಕೆ_max == -1)
		options->server_alive_ಎಣಿಕೆ_max = 3;
	ಆದರೆ (options->control_master == -1)
		options->control_master = 0;
	ಆದರೆ (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	ಆದರೆ (options->hash_ತಿಳಿದ_hosts == -1)
		options->hash_ತಿಳಿದ_hosts = 0;
	ಆದರೆ (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	ಆದರೆ (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	ಆದರೆ (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	ಆದರೆ (options->permit_local_command == -1)
		options->permit_local_command = 0;
	ಆದರೆ (options->visual_host_ಕೀಲಿ == -1)
		options->visual_host_ಕೀಲಿ = 0;
	ಆದರೆ (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	ಆದರೆ (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	ಆದರೆ (options->request_tty == -1)
		options->request_tty = REQUEST_TTY_AUTO;
	ಆದರೆ (options->session_type == -1)
		options->session_type = SESSION_TYPE_DEFAULT;
	ಆದರೆ (options->stdin_null == -1)
		options->stdin_null = 0;
	ಆದರೆ (options->fork_after_authentication == -1)
		options->fork_after_authentication = 0;
	ಆದರೆ (options->proxy_use_fdpass == -1)
		options->proxy_use_fdpass = 0;
	ಆದರೆ (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	ಆದರೆ (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	ಆದರೆ (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
	ಆದರೆ (options->fingerprint_hash == -1)
		options->fingerprint_hash = SSH_FP_HASH_DEFAULT;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_SK_ಆಂತರಿಕ
	ಆದರೆ (options->sk_provider == ಖಾಲಿ)
		options->sk_provider = xstrdup("internal");
#ಇಲ್ಲದಿದ್ದರೆ
	ಆದರೆ (options->sk_provider == ಖಾಲಿ)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (options->required_rsa_ಗಾತ್ರ == -1)
		options->required_rsa_ಗಾತ್ರ = SSH_RSA_MINIMUM_MODULUS_ಗಾತ್ರ;
	ಆದರೆ (options->warn_weak_crypto == -1)
		options->warn_weak_crypto = 1;
	ಆದರೆ (options->enable_escape_commandline == -1)
		options->enable_escape_commandline = 0;
	ಆದರೆ (options->obscure_keystroke_timing_interval == -1) {
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
	def_cipher = ಹೊಂದಿಕೆ_filter_allowlist(KEX_CLIENT_ENCRYPT, all_cipher);
	def_mac = ಹೊಂದಿಕೆ_filter_allowlist(KEX_CLIENT_MAC, all_mac);
	def_kex = ಹೊಂದಿಕೆ_filter_allowlist(KEX_CLIENT_KEX, all_kex);
	def_ಕೀಲಿ = ಹೊಂದಿಕೆ_filter_allowlist(KEX_DEFAULT_PK_ALG, all_ಕೀಲಿ);
	def_sig = ಹೊಂದಿಕೆ_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#ವ್ಯಾಖ್ಯಾನಿಸು ASSEMBLE(what, defaults, all) \
	ಮಾಡು { \
		ಆದರೆ ((r = kex_assemble_ಹೆಸರುಗಳು(&options->what, \
		    defaults, all)) != 0) { \
			error_fr(r, "%s", #what); \
			ಹೋಗು fail; \
		} \
	} ಆಗ (0)
	options->kex_algorithms_ಗಣ = options->kex_algorithms != ಖಾಲಿ;
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostbased_accepted_algos, def_ಕೀಲಿ, all_ಕೀಲಿ);
	ASSEMBLE(pubkey_accepted_algos, def_ಕೀಲಿ, all_ಕೀಲಿ);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು ASSEMBLE

#ವ್ಯಾಖ್ಯಾನಿಸು CLEAR_ON_NONE(v) \
	ಮಾಡು { \
		ಆದರೆ (option_clear_or_none(v)) { \
			ಬಿಡುಗಡೆ(v); \
			v = ಖಾಲಿ; \
		} \
	} ಆಗ(0)
#ವ್ಯಾಖ್ಯಾನಿಸು CLEAR_ON_NONE_ARRAY(v, nv, none) \
	ಮಾಡು { \
		ಆದರೆ (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			ಬಿಡುಗಡೆ(options->v[0]); \
			ಬಿಡುಗಡೆ(options->v); \
			options->v = ಖಾಲಿ; \
			options->nv = 0; \
		} \
	} ಆಗ (0)
	CLEAR_ON_NONE(options->local_command);
	CLEAR_ON_NONE(options->remote_command);
	CLEAR_ON_NONE(options->proxy_command);
	CLEAR_ON_NONE(options->control_ಮಾರ್ಗ);
	CLEAR_ON_NONE(options->pkcs11_provider);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->ತಿಳಿದ_hosts_command);
	CLEAR_ON_NONE_ARRAY(channel_timeouts, ಅಂಕೆ_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(revoked_host_ಕೀಲಿಗಳು, ಅಂಕೆ_revoked_host_ಕೀಲಿಗಳು, "none");
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CLEAR_ON_NONE
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು CLEAR_ON_NONE_ARRAY
	ಆದರೆ (options->jump_host != ಖಾಲಿ &&
	    strcmp(options->jump_host, "none") == 0 &&
	    options->jump_ಪೋರ್ಟ್ == 0 && options->jump_user == ಖಾಲಿ) {
		ಬಿಡುಗಡೆ(options->jump_host);
		options->jump_host = ಖಾಲಿ;
	}
	ಆದರೆ (options->ಅಂಕೆ_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		ಬಿಡುಗಡೆ(options->permitted_cnames[0].ಮೂಲ_list);
		ಬಿಡುಗಡೆ(options->permitted_cnames[0].ಗುರಿ_list);
		memset(options->permitted_cnames, '\0',
		    ಗಾತ್ರ(*options->permitted_cnames));
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
	ಬಿಡುಗಡೆ(all_cipher);
	ಬಿಡುಗಡೆ(all_mac);
	ಬಿಡುಗಡೆ(all_kex);
	ಬಿಡುಗಡೆ(all_ಕೀಲಿ);
	ಬಿಡುಗಡೆ(all_sig);
	ಬಿಡುಗಡೆ(def_cipher);
	ಬಿಡುಗಡೆ(def_mac);
	ಬಿಡುಗಡೆ(def_kex);
	ಬಿಡುಗಡೆ(def_ಕೀಲಿ);
	ಬಿಡುಗಡೆ(def_sig);
	ಹಿಂತಿರುಗಿ ret;
}

ಶೂನ್ಯ
free_options(Options *o)
{
	ಪೂರ್ಣಾಂಕ i;

	ಆದರೆ (o == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;

#ವ್ಯಾಖ್ಯಾನಿಸು FREE_ARRAY(type, n, a) \
	ಮಾಡು { \
		type _i; \
		ಗಾಗಿ (_i = 0; _i < (n); _i++) \
			ಬಿಡುಗಡೆ((a)[_i]); \
	} ಆಗ (0)

	ಬಿಡುಗಡೆ(o->forward_agent_sock_ಮಾರ್ಗ);
	ಬಿಡುಗಡೆ(o->xauth_location);
	FREE_ARRAY(u_int, o->ಅಂಕೆ_log_verbose, o->log_verbose);
	ಬಿಡುಗಡೆ(o->log_verbose);
	ಬಿಡುಗಡೆ(o->ciphers);
	ಬಿಡುಗಡೆ(o->macs);
	ಬಿಡುಗಡೆ(o->hostkeyalgorithms);
	ಬಿಡುಗಡೆ(o->kex_algorithms);
	ಬಿಡುಗಡೆ(o->ca_sign_algorithms);
	ಬಿಡುಗಡೆ(o->hostname);
	ಬಿಡುಗಡೆ(o->host_ಕೀಲಿ_alias);
	ಬಿಡುಗಡೆ(o->proxy_command);
	ಬಿಡುಗಡೆ(o->user);
	FREE_ARRAY(u_int, o->ಅಂಕೆ_system_hostfiles, o->system_hostfiles);
	FREE_ARRAY(u_int, o->ಅಂಕೆ_user_hostfiles, o->user_hostfiles);
	ಬಿಡುಗಡೆ(o->preferred_authentications);
	ಬಿಡುಗಡೆ(o->bind_ವಿಳಾಸ);
	ಬಿಡುಗಡೆ(o->bind_interface);
	ಬಿಡುಗಡೆ(o->pkcs11_provider);
	ಬಿಡುಗಡೆ(o->sk_provider);
	ಗಾಗಿ (i = 0; i < o->ಅಂಕೆ_ತಟಸ್ಥ_files; i++) {
		ಬಿಡುಗಡೆ(o->ತಟಸ್ಥ_files[i]);
		sshkey_free(o->ತಟಸ್ಥ_ಕೀಲಿಗಳು[i]);
	}
	ಗಾಗಿ (i = 0; i < o->ಅಂಕೆ_certificate_files; i++) {
		ಬಿಡುಗಡೆ(o->certificate_files[i]);
		sshkey_free(o->certificates[i]);
	}
	ಬಿಡುಗಡೆ(o->ತಟಸ್ಥ_agent);
	ಗಾಗಿ (i = 0; i < o->ಅಂಕೆ_local_forwards; i++) {
		ಬಿಡುಗಡೆ(o->local_forwards[i].listen_host);
		ಬಿಡುಗಡೆ(o->local_forwards[i].listen_ಮಾರ್ಗ);
		ಬಿಡುಗಡೆ(o->local_forwards[i].connect_host);
		ಬಿಡುಗಡೆ(o->local_forwards[i].connect_ಮಾರ್ಗ);
	}
	ಬಿಡುಗಡೆ(o->local_forwards);
	ಗಾಗಿ (i = 0; i < o->ಅಂಕೆ_remote_forwards; i++) {
		ಬಿಡುಗಡೆ(o->remote_forwards[i].listen_host);
		ಬಿಡುಗಡೆ(o->remote_forwards[i].listen_ಮಾರ್ಗ);
		ಬಿಡುಗಡೆ(o->remote_forwards[i].connect_host);
		ಬಿಡುಗಡೆ(o->remote_forwards[i].connect_ಮಾರ್ಗ);
	}
	ಬಿಡುಗಡೆ(o->remote_forwards);
	ಬಿಡುಗಡೆ(o->stdio_forward_host);
	FREE_ARRAY(u_int, o->ಅಂಕೆ_send_env, o->send_env);
	ಬಿಡುಗಡೆ(o->send_env);
	FREE_ARRAY(u_int, o->ಅಂಕೆ_setenv, o->setenv);
	ಬಿಡುಗಡೆ(o->setenv);
	ಬಿಡುಗಡೆ(o->control_ಮಾರ್ಗ);
	ಬಿಡುಗಡೆ(o->local_command);
	ಬಿಡುಗಡೆ(o->remote_command);
	FREE_ARRAY(ಪೂರ್ಣಾಂಕ, o->ಅಂಕೆ_canonical_domains, o->canonical_domains);
	ಗಾಗಿ (i = 0; i < o->ಅಂಕೆ_permitted_cnames; i++) {
		ಬಿಡುಗಡೆ(o->permitted_cnames[i].ಮೂಲ_list);
		ಬಿಡುಗಡೆ(o->permitted_cnames[i].ಗುರಿ_list);
	}
	FREE_ARRAY(u_int, o->ಅಂಕೆ_revoked_host_ಕೀಲಿಗಳು, o->revoked_host_ಕೀಲಿಗಳು);
	ಬಿಡುಗಡೆ(o->revoked_host_ಕೀಲಿಗಳು);
	ಬಿಡುಗಡೆ(o->hostbased_accepted_algos);
	ಬಿಡುಗಡೆ(o->pubkey_accepted_algos);
	ಬಿಡುಗಡೆ(o->jump_user);
	ಬಿಡುಗಡೆ(o->jump_host);
	ಬಿಡುಗಡೆ(o->jump_extra);
	ಬಿಡುಗಡೆ(o->ignored_unknown);
	explicit_bzero(o, ಗಾತ್ರ(*o));
#ವ್ಯಾಖ್ಯಾನ_ರದ್ದು FREE_ARRAY
}

ರಚನೆ fwdarg {
	ಅಕ್ಷರ *arg;
	ಪೂರ್ಣಾಂಕ ispath;
};

/*
 * parse_fwd_field
 * parses the next field in a port forwarding specification.
 * sets fwd to the parsed field and advances p past the colon
 * or sets it to NULL at end of string.
 * returns 0 on success, else non-zero.
 */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_fwd_ಕ್ಷೇತ್ರ(ಅಕ್ಷರ **p, ರಚನೆ fwdarg *fwd)
{
	ಅಕ್ಷರ *ep, *cp = *p;
	ಪೂರ್ಣಾಂಕ ispath = 0;

	ಆದರೆ (*cp == '\0') {
		*p = ಖಾಲಿ;
		ಹಿಂತಿರುಗಿ -1;	/* end of string */
	}

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	ಆದರೆ (*cp == '[') {
		/* find matching ']' */
		ಗಾಗಿ (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++) {
			ಆದರೆ (*ep == '/')
				ispath = 1;
		}
		/* no matching ']' or not at end of field. */
		ಆದರೆ (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			ಹಿಂತಿರುಗಿ -1;
		/* NUL terminate the field and advance p past the colon */
		*ep++ = '\0';
		ಆದರೆ (*ep != '\0')
			*ep++ = '\0';
		fwd->arg = cp + 1;
		fwd->ispath = ispath;
		*p = ep;
		ಹಿಂತಿರುಗಿ 0;
	}

	ಗಾಗಿ (cp = *p; *cp != '\0'; cp++) {
		ಆಯ್ಕೆ (*cp) {
		ಸ್ಥಿತಿ '\\':
			memmove(cp, cp + 1, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(cp + 1) + 1);
			ಆದರೆ (*cp == '\0')
				ಹಿಂತಿರುಗಿ -1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ '/':
			ispath = 1;
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ ':':
			*cp++ = '\0';
			ಹೋಗು ಮುಗಿದ;
		}
	}
ಮುಗಿದ:
	fwd->arg = *p;
	fwd->ispath = ispath;
	*p = cp;
	ಹಿಂತಿರುಗಿ 0;
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
ಪೂರ್ಣಾಂಕ
parse_forward(ರಚನೆ Forward *fwd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fwdspec, ಪೂರ್ಣಾಂಕ dynamicfwd, ಪೂರ್ಣಾಂಕ remotefwd)
{
	ರಚನೆ fwdarg fwdargs[4];
	ಅಕ್ಷರ *p, *cp;
	ಪೂರ್ಣಾಂಕ i, err;

	memset(fwd, 0, ಗಾತ್ರ(*fwd));
	memset(fwdargs, 0, ಗಾತ್ರ(fwdargs));

	/*
	 * We expand environment variables before checking if we think they're
	 * paths so that if ${VAR} expands to a fully qualified path it is
	 * treated as a path.
	 */
	cp = p = dollar_expand(&err, fwdspec);
	ಆದರೆ (p == ಖಾಲಿ || err)
		ಹಿಂತಿರುಗಿ 0;

	/* skip leading spaces */
	ಆಗ (ಖಾಲಿಯೇ((u_char)*cp))
		cp++;

	ಗಾಗಿ (i = 0; i < 4; ++i) {
		ಆದರೆ (parse_fwd_ಕ್ಷೇತ್ರ(&cp, &fwdargs[i]) != 0)
			ನಿಲ್ಲಿಸು;
	}

	/* Check for trailing garbage */
	ಆದರೆ (cp != ಖಾಲಿ && *cp != '\0') {
		i = 0;	/* failure */
	}

	ಆಯ್ಕೆ (i) {
	ಸ್ಥಿತಿ 1:
		ಆದರೆ (fwdargs[0].ispath) {
			fwd->listen_ಮಾರ್ಗ = xstrdup(fwdargs[0].arg);
			fwd->listen_ಪೋರ್ಟ್ = ಪೋರ್ಟ್_STREAMLOCAL;
		} ಇಲ್ಲದಿದ್ದರೆ {
			fwd->listen_host = ಖಾಲಿ;
			fwd->listen_ಪೋರ್ಟ್ = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ 2:
		ಆದರೆ (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_ಮಾರ್ಗ = xstrdup(fwdargs[0].arg);
			fwd->listen_ಪೋರ್ಟ್ = ಪೋರ್ಟ್_STREAMLOCAL;
			fwd->connect_ಮಾರ್ಗ = xstrdup(fwdargs[1].arg);
			fwd->connect_ಪೋರ್ಟ್ = ಪೋರ್ಟ್_STREAMLOCAL;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (fwdargs[1].ispath) {
			fwd->listen_host = ಖಾಲಿ;
			fwd->listen_ಪೋರ್ಟ್ = a2port(fwdargs[0].arg);
			fwd->connect_ಮಾರ್ಗ = xstrdup(fwdargs[1].arg);
			fwd->connect_ಪೋರ್ಟ್ = ಪೋರ್ಟ್_STREAMLOCAL;
		} ಇಲ್ಲದಿದ್ದರೆ {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_ಪೋರ್ಟ್ = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ 3:
		ಆದರೆ (fwdargs[0].ispath) {
			fwd->listen_ಮಾರ್ಗ = xstrdup(fwdargs[0].arg);
			fwd->listen_ಪೋರ್ಟ್ = ಪೋರ್ಟ್_STREAMLOCAL;
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_ಪೋರ್ಟ್ = a2port(fwdargs[2].arg);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (fwdargs[2].ispath) {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_ಪೋರ್ಟ್ = a2port(fwdargs[1].arg);
			fwd->connect_ಮಾರ್ಗ = xstrdup(fwdargs[2].arg);
			fwd->connect_ಪೋರ್ಟ್ = ಪೋರ್ಟ್_STREAMLOCAL;
		} ಇಲ್ಲದಿದ್ದರೆ {
			fwd->listen_host = ಖಾಲಿ;
			fwd->listen_ಪೋರ್ಟ್ = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_ಪೋರ್ಟ್ = a2port(fwdargs[2].arg);
		}
		ನಿಲ್ಲಿಸು;

	ಸ್ಥಿತಿ 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_ಪೋರ್ಟ್ = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_ಪೋರ್ಟ್ = a2port(fwdargs[3].arg);
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		i = 0; /* failure */
	}

	ಬಿಡುಗಡೆ(p);

	ಆದರೆ (dynamicfwd) {
		ಆದರೆ (!(i == 1 || i == 2))
			ಹೋಗು fail_free;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (!(i == 3 || i == 4)) {
			ಆದರೆ (fwd->connect_ಮಾರ್ಗ == ಖಾಲಿ &&
			    fwd->listen_ಮಾರ್ಗ == ಖಾಲಿ)
				ಹೋಗು fail_free;
		}
		ಆದರೆ (fwd->connect_ಪೋರ್ಟ್ <= 0 && fwd->connect_ಮಾರ್ಗ == ಖಾಲಿ)
			ಹೋಗು fail_free;
	}

	ಆದರೆ ((fwd->listen_ಪೋರ್ಟ್ < 0 && fwd->listen_ಮಾರ್ಗ == ಖಾಲಿ) ||
	    (!remotefwd && fwd->listen_ಪೋರ್ಟ್ == 0))
		ಹೋಗು fail_free;
	ಆದರೆ (fwd->connect_host != ಖಾಲಿ &&
	    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(fwd->connect_host) >= NI_MAXHOST)
		ಹೋಗು fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	ಆದರೆ (fwd->connect_ಮಾರ್ಗ != ಖಾಲಿ &&
	    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(fwd->connect_ಮಾರ್ಗ) >= ಮಾರ್ಗ_MAX_SUN)
		ಹೋಗು fail_free;
	ಆದರೆ (fwd->listen_host != ಖಾಲಿ &&
	    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(fwd->listen_host) >= NI_MAXHOST)
		ಹೋಗು fail_free;
	ಆದರೆ (fwd->listen_ಮಾರ್ಗ != ಖಾಲಿ &&
	    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(fwd->listen_ಮಾರ್ಗ) >= ಮಾರ್ಗ_MAX_SUN)
		ಹೋಗು fail_free;

	ಹಿಂತಿರುಗಿ (i);

 fail_free:
	ಬಿಡುಗಡೆ(fwd->connect_host);
	fwd->connect_host = ಖಾಲಿ;
	ಬಿಡುಗಡೆ(fwd->connect_ಮಾರ್ಗ);
	fwd->connect_ಮಾರ್ಗ = ಖಾಲಿ;
	ಬಿಡುಗಡೆ(fwd->listen_host);
	fwd->listen_host = ಖಾಲಿ;
	ಬಿಡುಗಡೆ(fwd->listen_ಮಾರ್ಗ);
	fwd->listen_ಮಾರ್ಗ = ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ (0);
}

ಪೂರ್ಣಾಂಕ
ssh_valid_hostname(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s)
{
	ಗಾತ್ರ_t i;

	ಆದರೆ (*s == '-')
		ಹಿಂತಿರುಗಿ 0;
	ಗಾಗಿ (i = 0; s[i] != 0; i++) {
		ಆದರೆ (strchr("'`\"$\\;&<>|(){},", s[i]) != ಖಾಲಿ ||
		    ಖಾಲಿಯೇ((u_char)s[i]) || iscntrl((u_char)s[i]))
			ಹಿಂತಿರುಗಿ 0;
	}
	ಹಿಂತಿರುಗಿ 1;
}

ಪೂರ್ಣಾಂಕ
ssh_valid_ruser(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s)
{
	ಗಾತ್ರ_t i;

	ಆದರೆ (*s == '-')
		ಹಿಂತಿರುಗಿ 0;
	ಗಾಗಿ (i = 0; s[i] != 0; i++) {
		ಆದರೆ (iscntrl((u_char)s[i]))
			ಹಿಂತಿರುಗಿ 0;
		ಆದರೆ (strchr("'`\";&<>|(){}$\\", s[i]) != ಖಾಲಿ)
			ಹಿಂತಿರುಗಿ 0;
		/* Disallow '-' after whitespace */
		ಆದರೆ (ಖಾಲಿಯೇ((u_char)s[i]) && s[i + 1] == '-')
			ಹಿಂತಿರುಗಿ 0;
	}
	ಹಿಂತಿರುಗಿ 1;
}

ಪೂರ್ಣಾಂಕ
parse_jump(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s, Options *o, ಪೂರ್ಣಾಂಕ strict, ಪೂರ್ಣಾಂಕ ಸಕ್ರಿಯ)
{
	ಅಕ್ಷರ *orig = ಖಾಲಿ, *sdup = ಖಾಲಿ, *cp;
	ಅಕ್ಷರ *tmp_user = ಖಾಲಿ, *tmp_host = ಖಾಲಿ, *host = ಖಾಲಿ, *user = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, ret = -1, tmp_ಪೋರ್ಟ್ = -1, ಪೋರ್ಟ್ = -1, ಮೊದಲ = 1;

	ಆದರೆ (strcasecmp(s, "none") == 0) {
		ಆದರೆ (ಸಕ್ರಿಯ && o->jump_host == ಖಾಲಿ) {
			o->jump_host = xstrdup("none");
			o->jump_ಪೋರ್ಟ್ = 0;
		}
		ಹಿಂತಿರುಗಿ 0;
	}

	orig = xstrdup(s);
	ಆದರೆ ((cp = strchr(orig, '#')) != ಖಾಲಿ)
		*cp = '\0';
	rtrim(orig);

	ಸಕ್ರಿಯ &= o->proxy_command == ಖಾಲಿ && o->jump_host == ಖಾಲಿ;
	sdup = xstrdup(orig);
	ಮಾಡು {
		/* Work backwards through string */
		ಆದರೆ ((cp = strrchr(sdup, ',')) == ಖಾಲಿ)
			cp = sdup; /*ಕೊನೆಯ*/
		ಇಲ್ಲದಿದ್ದರೆ
			*cp++ = '\0';

		r = parse_ssh_uri(cp, &tmp_user, &tmp_host, &tmp_ಪೋರ್ಟ್);
		ಆದರೆ (r == -1 || (r == 1 && parse_user_host_ಪೋರ್ಟ್(cp,
		    &tmp_user, &tmp_host, &tmp_ಪೋರ್ಟ್) != 0))
			ಹೋಗು ಹೊರಹೋಗು; /* error already logged */
		ಆದರೆ (strict) {
			ಆದರೆ (!ssh_valid_hostname(tmp_host)) {
				error_f("invalid hostname \"%s\"", tmp_host);
				ಹೋಗು ಹೊರಹೋಗು;
			}
			ಆದರೆ (tmp_user != ಖಾಲಿ && !ssh_valid_ruser(tmp_user)) {
				error_f("invalid username \"%s\"", tmp_user);
				ಹೋಗು ಹೊರಹೋಗು;
			}
		}
		ಆದರೆ (ಮೊದಲ) {
			user = tmp_user;
			host = tmp_host;
			ಪೋರ್ಟ್ = tmp_ಪೋರ್ಟ್;
			tmp_user = tmp_host = ಖಾಲಿ; /* transferred */
		}
		ಮೊದಲ = 0; /* only check syntax for subsequent hosts */
		ಬಿಡುಗಡೆ(tmp_user);
		ಬಿಡುಗಡೆ(tmp_host);
		tmp_user = tmp_host = ಖಾಲಿ;
		tmp_ಪೋರ್ಟ್ = -1;
	} ಆಗ (cp != sdup);

	/* success */
	ಆದರೆ (ಸಕ್ರಿಯ) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_ಪೋರ್ಟ್ = ಪೋರ್ಟ್;
		o->proxy_command = xstrdup("none");
		user = host = ಖಾಲಿ; /* transferred */
		ಆದರೆ (orig != ಖಾಲಿ && (cp = strrchr(orig, ',')) != ಖಾಲಿ) {
			o->jump_extra = xstrdup(orig);
			o->jump_extra[cp - orig] = '\0';
		}
	}
	ret = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(orig);
	ಬಿಡುಗಡೆ(sdup);
	ಬಿಡುಗಡೆ(tmp_user);
	ಬಿಡುಗಡೆ(tmp_host);
	ಬಿಡುಗಡೆ(user);
	ಬಿಡುಗಡೆ(host);
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
parse_ssh_uri(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *uri, ಅಕ್ಷರ **userp, ಅಕ್ಷರ **hostp, ಪೂರ್ಣಾಂಕ *portp)
{
	ಅಕ್ಷರ *user = ಖಾಲಿ, *host = ಖಾಲಿ, *ಮಾರ್ಗ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, ಪೋರ್ಟ್;

	r = parse_uri("ssh", uri, &user, &host, &ಪೋರ್ಟ್, &ಮಾರ್ಗ);
	ಆದರೆ (r == 0 && ಮಾರ್ಗ != ಖಾಲಿ)
		r = -1;		/* path not allowed */
	ಆದರೆ (r == 0) {
		ಆದರೆ (userp != ಖಾಲಿ) {
			*userp = user;
			user = ಖಾಲಿ;
		}
		ಆದರೆ (hostp != ಖಾಲಿ) {
			*hostp = host;
			host = ಖಾಲಿ;
		}
		ಆದರೆ (portp != ಖಾಲಿ)
			*portp = ಪೋರ್ಟ್;
	}
	ಬಿಡುಗಡೆ(user);
	ಬಿಡುಗಡೆ(host);
	ಬಿಡುಗಡೆ(ಮಾರ್ಗ);
	ಹಿಂತಿರುಗಿ r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
fmt_multistate_int(ಪೂರ್ಣಾಂಕ val, ಸ್ಥಿರಾಂಕ ರಚನೆ multistate *m)
{
	u_int i;

	ಗಾಗಿ (i = 0; m[i].ಕೀಲಿ != ಖಾಲಿ; i++) {
		ಆದರೆ (m[i].ಮೌಲ್ಯ == val)
			ಹಿಂತಿರುಗಿ m[i].ಕೀಲಿ;
	}
	ಹಿಂತಿರುಗಿ "UNKNOWN";
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
fmt_intarg(OpCodes ಸಂಕೇತ_2, ಪೂರ್ಣಾಂಕ val)
{
	ಆದರೆ (val == -1)
		ಹಿಂತಿರುಗಿ "unset";
	ಆಯ್ಕೆ (ಸಂಕೇತ_2) {
	ಸ್ಥಿತಿ o_ವಿಳಾಸ_Family:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_addressfamily);
	ಸ್ಥಿತಿ oCompression:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_compression);
	ಸ್ಥಿತಿ o_Verify_Host_ಕೀಲಿ_DNS:
	ಸ್ಥಿತಿ oUpdateHostkeys:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_yesnoask);
	ಸ್ಥಿತಿ o_Strict_Host_ಕೀಲಿ_Checking:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_strict_hostkey);
	ಸ್ಥಿತಿ oControlMaster:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_controlmaster);
	ಸ್ಥಿತಿ oTunnel:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_tunnel);
	ಸ್ಥಿತಿ oRequestTTY:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_requesttty);
	ಸ್ಥಿತಿ oSessionType:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_sessiontype);
	ಸ್ಥಿತಿ oCanonicalizeHostname:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_canonicalizehostname);
	ಸ್ಥಿತಿ o_ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_Agent:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_yesnoaskconfirm);
	ಸ್ಥಿತಿ oPubkeyAuthentication:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_pubkey_auth);
	ಸ್ಥಿತಿ oTCPKeepAlive:
		ಹಿಂತಿರುಗಿ fmt_multistate_int(val, multistate_keepalives);
	ಸ್ಥಿತಿ oFingerprintHash:
		ಹಿಂತಿರುಗಿ ssh_digest_alg_name(val);
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಆಯ್ಕೆ (val) {
		ಸ್ಥಿತಿ 0:
			ಹಿಂತಿರುಗಿ "no";
		ಸ್ಥಿತಿ 1:
			ಹಿಂತಿರುಗಿ "yes";
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಹಿಂತಿರುಗಿ "UNKNOWN";
		}
	}
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
lookup_opcode_name(OpCodes ಸಂಕೇತ_2)
{
	u_int i;

	ಗಾಗಿ (i = 0; keywords[i].name != ಖಾಲಿ; i++)
		ಆದರೆ (keywords[i].opcode == ಸಂಕೇತ_2)
			ಹಿಂತಿರುಗಿ(keywords[i].name);
	ಹಿಂತಿರುಗಿ "UNKNOWN";
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_int(OpCodes ಸಂಕೇತ_2, ಪೂರ್ಣಾಂಕ val)
{
	ಆದರೆ (ಸಂಕೇತ_2 == oObscureKeystrokeTiming) {
		ಆದರೆ (val == 0) {
			ಬರೆ("%s no\n", lookup_opcode_name(ಸಂಕೇತ_2));
			ಹಿಂತಿರುಗಿ;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (val == SSH_KEYSTROKE_DEFAULT_INTERVAL_MS) {
			ಬರೆ("%s yes\n", lookup_opcode_name(ಸಂಕೇತ_2));
			ಹಿಂತಿರುಗಿ;
		}
		/* FALLTHROUGH */
	}
	ಬರೆ("%s %d\n", lookup_opcode_name(ಸಂಕೇತ_2), val);
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_fmtint(OpCodes ಸಂಕೇತ_2, ಪೂರ್ಣಾಂಕ val)
{
	ಬರೆ("%s %s\n", lookup_opcode_name(ಸಂಕೇತ_2), fmt_intarg(ಸಂಕೇತ_2, val));
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_string(OpCodes ಸಂಕೇತ_2, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *val)
{
	ಆದರೆ (val == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಬರೆ("%s %s\n", lookup_opcode_name(ಸಂಕೇತ_2), val);
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_strarray(OpCodes ಸಂಕೇತ_2, u_int ಎಣಿಕೆ_2, ಅಕ್ಷರ **vals)
{
	u_int i;

	ಗಾಗಿ (i = 0; i < ಎಣಿಕೆ_2; i++)
		ಬರೆ("%s %s\n", lookup_opcode_name(ಸಂಕೇತ_2), vals[i]);
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_strarray_oneline(OpCodes ಸಂಕೇತ_2, u_int ಎಣಿಕೆ_2, ಅಕ್ಷರ **vals)
{
	u_int i;

	ಬರೆ("%s", lookup_opcode_name(ಸಂಕೇತ_2));
	ಆದರೆ (ಎಣಿಕೆ_2 == 0)
		ಬರೆ(" none");
	ಗಾಗಿ (i = 0; i < ಎಣಿಕೆ_2; i++)
		ಬರೆ(" %s",  vals[i]);
	ಬರೆ("\n");
}

ಸ್ಥಿರ ಶೂನ್ಯ
dump_cfg_forwards(OpCodes ಸಂಕೇತ_2, u_int ಎಣಿಕೆ_2, ಸ್ಥಿರಾಂಕ ರಚನೆ Forward *fwds)
{
	ಸ್ಥಿರಾಂಕ ರಚನೆ Forward *fwd;
	u_int i;

	/* oDynamicForward */
	ಗಾಗಿ (i = 0; i < ಎಣಿಕೆ_2; i++) {
		fwd = &fwds[i];
		ಆದರೆ (ಸಂಕೇತ_2 == oDynamicForward && fwd->connect_host != ಖಾಲಿ &&
		    strcmp(fwd->connect_host, "socks") != 0)
			ಮುಂದುವರಿ;
		ಆದರೆ (ಸಂಕೇತ_2 == oLocalForward && fwd->connect_host != ಖಾಲಿ &&
		    strcmp(fwd->connect_host, "socks") == 0)
			ಮುಂದುವರಿ;
		ಬರೆ("%s", lookup_opcode_name(ಸಂಕೇತ_2));
		ಆದರೆ (fwd->listen_ಪೋರ್ಟ್ == ಪೋರ್ಟ್_STREAMLOCAL)
			ಬರೆ(" %s", fwd->listen_ಮಾರ್ಗ);
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (fwd->listen_host == ಖಾಲಿ)
			ಬರೆ(" %d", fwd->listen_ಪೋರ್ಟ್);
		ಇಲ್ಲದಿದ್ದರೆ {
			ಬರೆ(" [%s]:%d",
			    fwd->listen_host, fwd->listen_ಪೋರ್ಟ್);
		}
		ಆದರೆ (ಸಂಕೇತ_2 != oDynamicForward) {
			ಆದರೆ (fwd->connect_ಪೋರ್ಟ್ == ಪೋರ್ಟ್_STREAMLOCAL)
				ಬರೆ(" %s", fwd->connect_ಮಾರ್ಗ);
			ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (fwd->connect_host == ಖಾಲಿ)
				ಬರೆ(" %d", fwd->connect_ಪೋರ್ಟ್);
			ಇಲ್ಲದಿದ್ದರೆ {
				ಬರೆ(" [%s]:%d",
				    fwd->connect_host, fwd->connect_ಪೋರ್ಟ್);
			}
		}
		ಬರೆ("\n");
	}
}

ಶೂನ್ಯ
dump_client_config(Options *o, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host)
{
	ಪೂರ್ಣಾಂಕ i, r;
	ಅಕ್ಷರ buf[8], *all_ಕೀಲಿ;

	/*
	 * Expand HostKeyAlgorithms name lists. This isn't handled in
	 * fill_default_options() like the other algorithm lists because
	 * the host key algorithms are by default dynamically chosen based
	 * on the host's keys found in known_hosts.
	 */
	all_ಕೀಲಿ = sshkey_alg_list(0, 0, 1, ',');
	ಆದರೆ ((r = kex_assemble_ಹೆಸರುಗಳು(&o->hostkeyalgorithms, kex_default_pk_alg(),
	    all_ಕೀಲಿ)) != 0)
		fatal_fr(r, "expand HostKeyAlgorithms");
	ಬಿಡುಗಡೆ(all_ಕೀಲಿ);

	/* Most interesting options first: user, host, port */
	dump_cfg_string(oHost, o->host_arg);
	dump_cfg_string(oUser, o->user);
	dump_cfg_string(oHostname, host);
	dump_cfg_int(o_ಪೋರ್ಟ್, o->ಪೋರ್ಟ್);

	/* Flag options */
	dump_cfg_fmtint(o_ವಿಳಾಸ_Family, o->ವಿಳಾಸ_family);
	dump_cfg_fmtint(o_Batch_ಬಹುಲಕ, o->batch_ಬಹುಲಕ);
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
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ GSSAPI
	dump_cfg_fmtint(oGssAuthentication, o->gss_authentication);
	dump_cfg_fmtint(oGssDelegateCreds, o->gss_deleg_creds);
#ಆದರೆ_ಅಂತ್ಯ /* GSSAPI */
	dump_cfg_fmtint(o_Hash_ತಿಳಿದ_Hosts, o->hash_ತಿಳಿದ_hosts);
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
	dump_cfg_fmtint(o_ಹರಿವು_Local_Bind_Unlink, o->fwd_opts.streamlocal_bind_unlink);
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
	dump_cfg_int(o_ಸಂಖ್ಯೆ_ದ_Password_Prompts, o->ಸಂಖ್ಯೆ_ದ_password_prompts);
	dump_cfg_int(o_Server_Alive_ಎಣಿಕೆ_Max, o->server_alive_ಎಣಿಕೆ_max);
	dump_cfg_int(oServerAliveInterval, o->server_alive_interval);
	dump_cfg_int(oRequiredRSASize, o->required_rsa_ಗಾತ್ರ);
	dump_cfg_int(oObscureKeystrokeTiming,
	    o->obscure_keystroke_timing_interval);

	/* String options */
	dump_cfg_string(o_Bind_ವಿಳಾಸ, o->bind_ವಿಳಾಸ);
	dump_cfg_string(oBindInterface, o->bind_interface);
	dump_cfg_string(oCiphers, o->ciphers);
	dump_cfg_string(o_Control_ಮಾರ್ಗ, o->control_ಮಾರ್ಗ);
	dump_cfg_string(o_Host_ಕೀಲಿ_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(o_Host_ಕೀಲಿ_Alias, o->host_ಕೀಲಿ_alias);
	dump_cfg_string(oHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(o_ತಟಸ್ಥ_Agent, o->ತಟಸ್ಥ_agent);
	dump_cfg_string(oIgnoreUnknown, o->ignored_unknown);
	dump_cfg_string(oKbdInteractiveDevices, o->kbd_interactive_devices);
	dump_cfg_string(oKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(oCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(oLocalCommand, o->local_command);
	dump_cfg_string(oRemoteCommand, o->remote_command);
	dump_cfg_string(oLogLevel, log_level_name(o->log_level));
	dump_cfg_string(oMacs, o->macs);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_PKCS11
	dump_cfg_string(oPKCS11Provider, o->pkcs11_provider);
#ಆದರೆ_ಅಂತ್ಯ
	dump_cfg_string(o_Security_ಕೀಲಿ_Provider, o->sk_provider);
	dump_cfg_string(oPreferredAuthentications, o->preferred_authentications);
	dump_cfg_string(oPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
	dump_cfg_string(oXAuthLocation, o->xauth_location);
	dump_cfg_string(o_ತಿಳಿದ_Hosts_Command, o->ತಿಳಿದ_hosts_command);
	dump_cfg_string(o_ಟ್ಯಾಗ್, o->ಟ್ಯಾಗ್);
	dump_cfg_string(o_ಆವೃತ್ತಿ_Addendum, o->ಆವೃತ್ತಿ_addendum);

	/* Forwards */
	dump_cfg_forwards(oDynamicForward, o->ಅಂಕೆ_local_forwards, o->local_forwards);
	dump_cfg_forwards(oLocalForward, o->ಅಂಕೆ_local_forwards, o->local_forwards);
	dump_cfg_forwards(oRemoteForward, o->ಅಂಕೆ_remote_forwards, o->remote_forwards);

	/* String array options */
	dump_cfg_strarray(o_ತಟಸ್ಥ_File, o->ಅಂಕೆ_ತಟಸ್ಥ_files, o->ತಟಸ್ಥ_files);
	dump_cfg_strarray_oneline(oCanonicalDomains, o->ಅಂಕೆ_canonical_domains, o->canonical_domains);
	dump_cfg_strarray(oCertificateFile, o->ಅಂಕೆ_certificate_files, o->certificate_files);
	dump_cfg_strarray_oneline(o_Global_ತಿಳಿದ_Hosts_File, o->ಅಂಕೆ_system_hostfiles, o->system_hostfiles);
	dump_cfg_strarray_oneline(o_User_ತಿಳಿದ_Hosts_File, o->ಅಂಕೆ_user_hostfiles, o->user_hostfiles);
	dump_cfg_strarray_oneline(o_Revoked_Host_ಕೀಲಿಗಳು, o->ಅಂಕೆ_revoked_host_ಕೀಲಿಗಳು, o->revoked_host_ಕೀಲಿಗಳು);
	dump_cfg_strarray(oSendEnv, o->ಅಂಕೆ_send_env, o->send_env);
	dump_cfg_strarray(o_ಗಣ_Env, o->ಅಂಕೆ_setenv, o->setenv);
	dump_cfg_strarray_oneline(oLogVerbose,
	    o->ಅಂಕೆ_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(oChannelTimeout,
	    o->ಅಂಕೆ_channel_timeouts, o->channel_timeouts);

	/* Special cases */

	/* PermitRemoteOpen */
	ಆದರೆ (o->ಅಂಕೆ_permitted_remote_opens == 0)
		ಬರೆ("%s any\n", lookup_opcode_name(oPermitRemoteOpen));
	ಇಲ್ಲದಿದ್ದರೆ
		dump_cfg_strarray_oneline(oPermitRemoteOpen,
		    o->ಅಂಕೆ_permitted_remote_opens, o->permitted_remote_opens);

	/* AddKeysToAgent */
	ಆದರೆ (o->ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_agent_lifespan <= 0)
		dump_cfg_fmtint(o_ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_Agent, o->ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_agent);
	ಇಲ್ಲದಿದ್ದರೆ {
		ಬರೆ("addkeystoagent%s %d\n",
		    o->ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_agent == 3 ? " confirm" : "",
		    o->ಕೂಡಿಸು_ಕೀಲಿಗಳು_ಗಮ್ಯ_agent_lifespan);
	}

	/* oForwardAgent */
	ಆದರೆ (o->forward_agent_sock_ಮಾರ್ಗ == ಖಾಲಿ)
		dump_cfg_fmtint(oForwardAgent, o->forward_agent);
	ಇಲ್ಲದಿದ್ದರೆ
		dump_cfg_string(oForwardAgent, o->forward_agent_sock_ಮಾರ್ಗ);

	/* oConnectTimeout */
	ಆದರೆ (o->connection_timeout == -1)
		ಬರೆ("connecttimeout none\n");
	ಇಲ್ಲದಿದ್ದರೆ
		dump_cfg_int(oConnectTimeout, o->connection_timeout);

	/* oTunnelDevice */
	ಬರೆ("tunneldevice");
	ಆದರೆ (o->tun_local == SSH_TUNID_ANY)
		ಬರೆ(" any");
	ಇಲ್ಲದಿದ್ದರೆ
		ಬರೆ(" %d", o->tun_local);
	ಆದರೆ (o->tun_remote == SSH_TUNID_ANY)
		ಬರೆ(":any");
	ಇಲ್ಲದಿದ್ದರೆ
		ಬರೆ(":%d", o->tun_remote);
	ಬರೆ("\n");

	/* oCanonicalizePermittedCNAMEs */
	ಬರೆ("canonicalizepermittedcnames");
	ಆದರೆ (o->ಅಂಕೆ_permitted_cnames == 0)
		ಬರೆ(" none");
	ಗಾಗಿ (i = 0; i < o->ಅಂಕೆ_permitted_cnames; i++) {
		ಬರೆ(" %s:%s", o->permitted_cnames[i].ಮೂಲ_list,
		    o->permitted_cnames[i].ಗುರಿ_list);
	}
	ಬರೆ("\n");

	/* oControlPersist */
	ಆದರೆ (o->control_persist == 0 || o->control_persist_timeout == 0)
		dump_cfg_fmtint(oControlPersist, o->control_persist);
	ಇಲ್ಲದಿದ್ದರೆ
		dump_cfg_int(oControlPersist, o->control_persist_timeout);

	/* oEscapeChar */
	ಆದರೆ (o->escape_char == SSH_ESCAPECHAR_NONE)
		ಬರೆ("escapechar none\n");
	ಇಲ್ಲದಿದ್ದರೆ {
		vis(buf, o->escape_char, VIS_WHITE, 0);
		ಬರೆ("escapechar %s\n", buf);
	}

	/* oIPQoS */
	ಬರೆ("ipqos %s ", iptos2str(o->ip_qos_interactive));
	ಬರೆ("%s\n", iptos2str(o->ip_qos_bulk));

	/* oRekeyLimit */
	ಬರೆ("rekeylimit %llu %d\n",
	    (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ)o->rekey_ಎಲ್ಲೆ, o->rekey_interval);

	/* oStreamLocalBindMask */
	ಬರೆ("streamlocalbindmask 0%o\n",
	    o->fwd_opts.streamlocal_bind_ಮುಖವಾಡ);

	/* oLogFacility */
	ಬರೆ("syslogfacility %s\n", log_facility_name(o->log_facility));

	/* oProxyCommand / oProxyJump */
	ಆದರೆ (o->jump_host == ಖಾಲಿ)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	ಇಲ್ಲದಿದ್ದರೆ {
		/* Check for numeric addresses */
		i = strchr(o->jump_host, ':') != ಖಾಲಿ ||
		    strspn(o->jump_host, "1234567890.") == ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(o->jump_host);
		snprintf(buf, ಗಾತ್ರ(buf), "%d", o->jump_ಪೋರ್ಟ್);
		ಬರೆ("proxyjump %s%s%s%s%s%s%s%s%s\n",
		    /* optional additional jump spec */
		    o->jump_extra == ಖಾಲಿ ? "" : o->jump_extra,
		    o->jump_extra == ಖಾಲಿ ? "" : ",",
		    /* optional user */
		    o->jump_user == ಖಾಲಿ ? "" : o->jump_user,
		    o->jump_user == ಖಾಲಿ ? "" : "@",
		    /* opening [ if hostname is numeric */
		    i ? "[" : "",
		    /* mandatory hostname */
		    o->jump_host,
		    /* closing ] if hostname is numeric */
		    i ? "]" : "",
		    /* optional port number */
		    o->jump_ಪೋರ್ಟ್ <= 0 ? "" : ":",
		    o->jump_ಪೋರ್ಟ್ <= 0 ? "" : buf);
	}
}
