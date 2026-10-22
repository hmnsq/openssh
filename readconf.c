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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/stat.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/un.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <net/if.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/in.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netinet/ip.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <arpa/inet.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <ctype.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <glob.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <ifaddrs.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <netdb.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <paths.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <util.h>
#ਜੇ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "cipher.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "readconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "mac.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "myproposal.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "version.h"

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

ਸਥਿਰ ਪੂਰਨ read_config_file_ਡੂੰਘਾਈ(ਅਚਲ ਅੱਖਰ *filename, ਬਣਤਰ passwd *pw,
    ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *original_host, ਅਚਲ ਅੱਖਰ *remote_command,
    Options *options, ਪੂਰਨ flags, ਪੂਰਨ *activep, ਪੂਰਨ *want_final_pass, ਪੂਰਨ ਡੂੰਘਾਈ);
ਸਥਿਰ ਪੂਰਨ process_config_ਸਤਰ_ਡੂੰਘਾਈ(Options *options, ਬਣਤਰ passwd *pw,
    ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *original_host, ਅਚਲ ਅੱਖਰ *remote_command,
    ਅੱਖਰ *ਸਤਰ, ਅਚਲ ਅੱਖਰ *filename, ਪੂਰਨ linenum, ਪੂਰਨ *activep, ਪੂਰਨ flags,
    ਪੂਰਨ *want_final_pass, ਪੂਰਨ ਡੂੰਘਾਈ);

/* Keyword tokens. */

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਗਿਣਤੀ {
	oBadOption,
	oHost, o_ਮੇਲ, oInclude, o_ਟੈਗ,
	oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout,
	oGatewayPorts, oExitOnForwardFailure,
	oPasswordAuthentication,
	oXAuthLocation,
	o_ਪਛਾਣ_ਤੱਤ_File, oHostname, o_ਪੋਰਟ, oRemoteForward, oLocalForward,
	oPermitRemoteOpen,
	oCertificateFile, o_ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_Agent, o_ਪਛਾਣ_ਤੱਤ_Agent,
	oUser, oEscapeChar, oProxyCommand,
	o_Global_ਗਿਆਤ_Hosts_File, o_User_ਗਿਆਤ_Hosts_File, oConnectionAttempts,
	o_Batch_ਬਹੁਲਕ, oCheckHostIP, o_Strict_Host_ਕੁੰਜੀ_Checking, oCompression,
	oTCPKeepAlive, o_ਸੰਖਿਆ_ਦਾ_Password_Prompts,
	oLogFacility, oLogLevel, oLogVerbose, oCiphers, oMacs,
	oPubkeyAuthentication,
	oKbdInteractiveAuthentication, oKbdInteractiveDevices, o_Host_ਕੁੰਜੀ_Alias,
	oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication,
	o_Host_ਕੁੰਜੀ_Algorithms, o_Bind_ਪਤਾ, oBindInterface, oPKCS11Provider,
	oClearAllForwardings, oNoHostAuthenticationForLocalhost,
	oEnableSSHKeysign, o_Rekey_ਹੱਦਬੰਦੀ, o_Verify_Host_ਕੁੰਜੀ_DNS, oConnectTimeout,
	o_ਪਤਾ_Family, oGssAuthentication, oGssDelegateCreds,
	oServerAliveInterval, o_Server_Alive_ਗਿਣਤੀ_Max, oIdentitiesOnly,
	oSendEnv, o_ਸੈੱਟ_Env, o_Control_ਰਸਤਾ, oControlMaster, oControlPersist,
	o_Hash_ਗਿਆਤ_Hosts,
	oTunnel, oTunnelDevice,
	oLocalCommand, oPermitLocalCommand, oRemoteCommand,
	o_Visual_Host_ਕੁੰਜੀ,
	oKexAlgorithms, oIPQoS, oRequestTTY, oSessionType, oStdinNull,
	oForkAfterAuthentication, oIgnoreUnknown, oProxyUseFdpass,
	oCanonicalDomains, oCanonicalizeHostname, oCanonicalizeMaxDots,
	oCanonicalizeFallbackLocal, oCanonicalizePermittedCNAMEs,
	o_ਧਾਰਾ_Local_Bind_ਨਕਾਬ, o_ਧਾਰਾ_Local_Bind_Unlink, o_Revoked_Host_ਕੁੰਜੀਆਂ,
	oFingerprintHash, oUpdateHostkeys, oHostbasedAcceptedAlgorithms,
	oPubkeyAcceptedAlgorithms, oCASignatureAlgorithms, oProxyJump,
	o_Security_ਕੁੰਜੀ_Provider, o_ਗਿਆਤ_Hosts_Command, oRequiredRSASize,
	oEnableEscapeCommandline, oObscureKeystrokeTiming, oChannelTimeout,
	o_ਸੰਸਕਰਣ_Addendum, oRefuseConnection, oWarnWeakCrypto,
	oIgnore, oIgnoredUnknownOption, oDeprecated, oUnsupported
} OpCodes;

/* Textual representations of the tokens. */

ਸਥਿਰ ਬਣਤਰ {
	ਅਚਲ ਅੱਖਰ *name;
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
#ਜੇ defined(GSSAPI)
	{ "gssapiauthentication", oGssAuthentication },
	{ "gssapidelegatecredentials", oGssDelegateCreds },
# ਨਹੀਂਤਾਂ
	{ "gssapiauthentication", oUnsupported },
	{ "gssapidelegatecredentials", oUnsupported },
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_PKCS11
	{ "pkcs11provider", oPKCS11Provider },
	{ "smartcarddevice", oPKCS11Provider },
# ਨਹੀਂਤਾਂ
	{ "smartcarddevice", oUnsupported },
	{ "pkcs11provider", oUnsupported },
#ਜੇ_ਅੰਤ

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
	{ "identityfile", o_ਪਛਾਣ_ਤੱਤ_File },
	{ "identityfile2", o_ਪਛਾਣ_ਤੱਤ_File },			/* obsolete */
	{ "identitiesonly", oIdentitiesOnly },
	{ "certificatefile", oCertificateFile },
	{ "addkeystoagent", o_ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_Agent },
	{ "identityagent", o_ਪਛਾਣ_ਤੱਤ_Agent },
	{ "hostname", oHostname },
	{ "hostkeyalias", o_Host_ਕੁੰਜੀ_Alias },
	{ "proxycommand", oProxyCommand },
	{ "port", o_ਪੋਰਟ },
	{ "ciphers", oCiphers },
	{ "macs", oMacs },
	{ "remoteforward", oRemoteForward },
	{ "localforward", oLocalForward },
	{ "permitremoteopen", oPermitRemoteOpen },
	{ "user", oUser },
	{ "host", oHost },
	{ "match", o_ਮੇਲ },
	{ "tag", o_ਟੈਗ },
	{ "escapechar", oEscapeChar },
	{ "globalknownhostsfile", o_Global_ਗਿਆਤ_Hosts_File },
	{ "userknownhostsfile", o_User_ਗਿਆਤ_Hosts_File },
	{ "connectionattempts", oConnectionAttempts },
	{ "batchmode", o_Batch_ਬਹੁਲਕ },
	{ "checkhostip", oCheckHostIP },
	{ "stricthostkeychecking", o_Strict_Host_ਕੁੰਜੀ_Checking },
	{ "compression", oCompression },
	{ "tcpkeepalive", oTCPKeepAlive },
	{ "keepalive", oTCPKeepAlive },				/* obsolete */
	{ "numberofpasswordprompts", o_ਸੰਖਿਆ_ਦਾ_Password_Prompts },
	{ "syslogfacility", oLogFacility },
	{ "loglevel", oLogLevel },
	{ "logverbose", oLogVerbose },
	{ "dynamicforward", oDynamicForward },
	{ "preferredauthentications", oPreferredAuthentications },
	{ "hostkeyalgorithms", o_Host_ਕੁੰਜੀ_Algorithms },
	{ "casignaturealgorithms", oCASignatureAlgorithms },
	{ "bindaddress", o_Bind_ਪਤਾ },
	{ "bindinterface", oBindInterface },
	{ "clearallforwardings", oClearAllForwardings },
	{ "enablesshkeysign", oEnableSSHKeysign },
	{ "verifyhostkeydns", o_Verify_Host_ਕੁੰਜੀ_DNS },
	{ "nohostauthenticationforlocalhost", oNoHostAuthenticationForLocalhost },
	{ "rekeylimit", o_Rekey_ਹੱਦਬੰਦੀ },
	{ "connecttimeout", oConnectTimeout },
	{ "addressfamily", o_ਪਤਾ_Family },
	{ "serveraliveinterval", oServerAliveInterval },
	{ "serveralivecountmax", o_Server_Alive_ਗਿਣਤੀ_Max },
	{ "sendenv", oSendEnv },
	{ "setenv", o_ਸੈੱਟ_Env },
	{ "controlpath", o_Control_ਰਸਤਾ },
	{ "controlmaster", oControlMaster },
	{ "controlpersist", oControlPersist },
	{ "hashknownhosts", o_Hash_ਗਿਆਤ_Hosts },
	{ "include", oInclude },
	{ "tunnel", oTunnel },
	{ "tunneldevice", oTunnelDevice },
	{ "localcommand", oLocalCommand },
	{ "permitlocalcommand", oPermitLocalCommand },
	{ "remotecommand", oRemoteCommand },
	{ "visualhostkey", o_Visual_Host_ਕੁੰਜੀ },
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
	{ "streamlocalbindmask", o_ਧਾਰਾ_Local_Bind_ਨਕਾਬ },
	{ "streamlocalbindunlink", o_ਧਾਰਾ_Local_Bind_Unlink },
	{ "revokedhostkeys", o_Revoked_Host_ਕੁੰਜੀਆਂ },
	{ "fingerprinthash", oFingerprintHash },
	{ "updatehostkeys", oUpdateHostkeys },
	{ "hostbasedacceptedalgorithms", oHostbasedAcceptedAlgorithms },
	{ "hostbasedkeytypes", oHostbasedAcceptedAlgorithms }, /* obsolete */
	{ "pubkeyacceptedalgorithms", oPubkeyAcceptedAlgorithms },
	{ "pubkeyacceptedkeytypes", oPubkeyAcceptedAlgorithms }, /* obsolete */
	{ "ignoreunknown", oIgnoreUnknown },
	{ "proxyjump", oProxyJump },
	{ "securitykeyprovider", o_Security_ਕੁੰਜੀ_Provider },
	{ "knownhostscommand", o_ਗਿਆਤ_Hosts_Command },
	{ "requiredrsasize", oRequiredRSASize },
	{ "enableescapecommandline", oEnableEscapeCommandline },
	{ "obscurekeystroketiming", oObscureKeystrokeTiming },
	{ "channeltimeout", oChannelTimeout },
	{ "versionaddendum", o_ਸੰਸਕਰਣ_Addendum },
	{ "refuseconnection", oRefuseConnection },
	{ "warnweakcrypto", oWarnWeakCrypto },

	{ ਨਿਰਾ, oBadOption }
};

ਸਥਿਰ ਅਚਲ ਅੱਖਰ *lookup_opcode_name(OpCodes ਕੋਡ);

ਅਚਲ ਅੱਖਰ *
kex_default_pk_alg(ਖਾਲੀ)
{
	ਸਥਿਰ ਅੱਖਰ *pkalgs;

	ਜੇ (pkalgs == ਨਿਰਾ) {
		ਅੱਖਰ *all_ਕੁੰਜੀ;

		all_ਕੁੰਜੀ = sshkey_alg_list(0, 0, 1, ',');
		pkalgs = ਮੇਲ_filter_allowlist(KEX_DEFAULT_PK_ALG, all_ਕੁੰਜੀ);
		ਮੁਕਤ(all_ਕੁੰਜੀ);
	}
	ਵਾਪਸ pkalgs;
}

ਅੱਖਰ *
ssh_connection_hash(ਅਚਲ ਅੱਖਰ *thishost, ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *portstr,
    ਅਚਲ ਅੱਖਰ *user, ਅਚਲ ਅੱਖਰ *jumphost)
{
	ਬਣਤਰ ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_ਲੰਮਾਈ];

	ਜੇ ((md = ssh_digest_ਸ਼ੁਰੂ(SSH_DIGEST_SHA1)) == ਨਿਰਾ ||
	    ssh_digest_update(md, thishost, ਲੜੀ_ਲੰਬਾਈ(thishost)) < 0 ||
	    ssh_digest_update(md, host, ਲੜੀ_ਲੰਬਾਈ(host)) < 0 ||
	    ssh_digest_update(md, portstr, ਲੜੀ_ਲੰਬਾਈ(portstr)) < 0 ||
	    ssh_digest_update(md, user, ਲੜੀ_ਲੰਬਾਈ(user)) < 0 ||
	    ssh_digest_update(md, jumphost, ਲੜੀ_ਲੰਬਾਈ(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, ਆਕਾਰ(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	ਵਾਪਸ tohex(conn_hash, ssh_digest_ਬਾਈਟਾਂ(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

ਖਾਲੀ
ਜੋੜੋ_local_forward(Options *options, ਅਚਲ ਬਣਤਰ Forward *newfwd)
{
	ਬਣਤਰ Forward *fwd;
	ਪੂਰਨ i;

	/* Don't add duplicates */
	ਲਈ (i = 0; i < options->ਅੰਕ_local_forwards; i++) {
		ਜੇ (forward_equals(newfwd, options->local_forwards + i))
			ਵਾਪਸ;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->ਅੰਕ_local_forwards + 1,
	    ਆਕਾਰ(*options->local_forwards));
	fwd = &options->local_forwards[options->ਅੰਕ_local_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_ਪੋਰਟ = newfwd->listen_ਪੋਰਟ;
	fwd->listen_ਰਸਤਾ = newfwd->listen_ਰਸਤਾ;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_ਪੋਰਟ = newfwd->connect_ਪੋਰਟ;
	fwd->connect_ਰਸਤਾ = newfwd->connect_ਰਸਤਾ;
}

/*
 * Adds a remote TCP/IP port forward to options.  Never returns if there is
 * an error.
 */

ਖਾਲੀ
ਜੋੜੋ_remote_forward(Options *options, ਅਚਲ ਬਣਤਰ Forward *newfwd)
{
	ਬਣਤਰ Forward *fwd;
	ਪੂਰਨ i;

	/* Don't add duplicates */
	ਲਈ (i = 0; i < options->ਅੰਕ_remote_forwards; i++) {
		ਜੇ (forward_equals(newfwd, options->remote_forwards + i))
			ਵਾਪਸ;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->ਅੰਕ_remote_forwards + 1,
	    ਆਕਾਰ(*options->remote_forwards));
	fwd = &options->remote_forwards[options->ਅੰਕ_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_ਪੋਰਟ = newfwd->listen_ਪੋਰਟ;
	fwd->listen_ਰਸਤਾ = newfwd->listen_ਰਸਤਾ;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_ਪੋਰਟ = newfwd->connect_ਪੋਰਟ;
	fwd->connect_ਰਸਤਾ = newfwd->connect_ਰਸਤਾ;
	fwd->handle = newfwd->handle;
	fwd->allocated_ਪੋਰਟ = 0;
}

ਸਥਿਰ ਖਾਲੀ
clear_forwardings(Options *options)
{
	ਪੂਰਨ i;

	ਲਈ (i = 0; i < options->ਅੰਕ_local_forwards; i++) {
		ਮੁਕਤ(options->local_forwards[i].listen_host);
		ਮੁਕਤ(options->local_forwards[i].listen_ਰਸਤਾ);
		ਮੁਕਤ(options->local_forwards[i].connect_host);
		ਮੁਕਤ(options->local_forwards[i].connect_ਰਸਤਾ);
	}
	ਜੇ (options->ਅੰਕ_local_forwards > 0) {
		ਮੁਕਤ(options->local_forwards);
		options->local_forwards = ਨਿਰਾ;
	}
	options->ਅੰਕ_local_forwards = 0;
	ਲਈ (i = 0; i < options->ਅੰਕ_remote_forwards; i++) {
		ਮੁਕਤ(options->remote_forwards[i].listen_host);
		ਮੁਕਤ(options->remote_forwards[i].listen_ਰਸਤਾ);
		ਮੁਕਤ(options->remote_forwards[i].connect_host);
		ਮੁਕਤ(options->remote_forwards[i].connect_ਰਸਤਾ);
	}
	ਜੇ (options->ਅੰਕ_remote_forwards > 0) {
		ਮੁਕਤ(options->remote_forwards);
		options->remote_forwards = ਨਿਰਾ;
	}
	options->ਅੰਕ_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

ਖਾਲੀ
ਜੋੜੋ_certificate_file(Options *options, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਪੂਰਨ userprovided)
{
	ਪੂਰਨ i;

	ਜੇ (options->ਅੰਕ_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	ਲਈ (i = 0; i < options->ਅੰਕ_certificate_files; i++) {
		ਜੇ (options->certificate_file_userprovided[i] == userprovided &&
		    strcmp(options->certificate_files[i], ਰਸਤਾ) == 0) {
			debug2_f("ignoring duplicate key %s", ਰਸਤਾ);
			ਵਾਪਸ;
		}
	}

	options->certificate_file_userprovided[options->ਅੰਕ_certificate_files] =
	    userprovided;
	options->certificate_files[options->ਅੰਕ_certificate_files++] =
	    xstrdup(ਰਸਤਾ);
}

ਖਾਲੀ
ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ_file(Options *options, ਅਚਲ ਅੱਖਰ *dir, ਅਚਲ ਅੱਖਰ *filename,
    ਪੂਰਨ userprovided)
{
	ਅੱਖਰ *ਰਸਤਾ;
	ਪੂਰਨ i;

	ਜੇ (options->ਅੰਕ_ਪਛਾਣ_ਤੱਤ_files >= SSH_MAX_ਪਛਾਣ_ਤੱਤ_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_ਪਛਾਣ_ਤੱਤ_FILES);

	ਜੇ (dir == ਨਿਰਾ) /* no dir, filename is absolute */
		ਰਸਤਾ = xstrdup(filename);
	ਨਹੀਂਤਾਂ ਜੇ (xasprintf(&ਰਸਤਾ, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", ਰਸਤਾ);

	/* Avoid registering duplicates */
	ਲਈ (i = 0; i < options->ਅੰਕ_ਪਛਾਣ_ਤੱਤ_files; i++) {
		ਜੇ (options->ਪਛਾਣ_ਤੱਤ_file_userprovided[i] == userprovided &&
		    strcmp(options->ਪਛਾਣ_ਤੱਤ_files[i], ਰਸਤਾ) == 0) {
			debug2_f("ignoring duplicate key %s", ਰਸਤਾ);
			ਮੁਕਤ(ਰਸਤਾ);
			ਵਾਪਸ;
		}
	}

	options->ਪਛਾਣ_ਤੱਤ_file_userprovided[options->ਅੰਕ_ਪਛਾਣ_ਤੱਤ_files] =
	    userprovided;
	options->ਪਛਾਣ_ਤੱਤ_files[options->ਅੰਕ_ਪਛਾਣ_ਤੱਤ_files++] = ਰਸਤਾ;
}

ਪੂਰਨ
default_ssh_ਪੋਰਟ(ਖਾਲੀ)
{
	ਸਥਿਰ ਪੂਰਨ ਪੋਰਟ;
	ਬਣਤਰ servent *sp;

	ਜੇ (ਪੋਰਟ == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		ਪੋਰਟ = sp ? ntohs(sp->s_port) : SSH_DEFAULT_ਪੋਰਟ;
	}
	ਵਾਪਸ ਪੋਰਟ;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
ਸਥਿਰ ਪੂਰਨ
execute_ਵਿੱਚ_shell(ਅਚਲ ਅੱਖਰ *cmd)
{
	ਅੱਖਰ *shell;
	pid_t pid;
	ਪੂਰਨ ਸਥਿਤੀ;

	ਜੇ ((shell = getenv("SHELL")) == ਨਿਰਾ)
		shell = _PATH_BSHELL;

	ਜੇ (access(shell, X_OK) == -1) {
		fatal("Shell \"%s\" is not executable: %s",
		    shell, strerror(errno));
	}

	debug("Executing command: '%.500s'", cmd);

	/* Fork and execute the command. */
	ਜੇ ((pid = fork()) == 0) {
		ਅੱਖਰ *argv[4];

		ਜੇ (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = xstrdup(cmd);
		argv[3] = ਨਿਰਾ;

		execv(argv[0], argv);
		error("Unable to execute '%.100s': %s", cmd, strerror(errno));
		/* Die with signal to make this error apparent to parent. */
		ssh_signal(SIGTERM, SIG_DFL);
		kill(getpid(), SIGTERM);
		_exit(1);
	}
	/* Parent. */
	ਜੇ (pid == -1)
		fatal_f("fork: %.100s", strerror(errno));

	ਜਦੋਂ (waitpid(pid, &ਸਥਿਤੀ, 0) == -1) {
		ਜੇ (errno != EINTR && errno != EAGAIN)
			fatal_f("waitpid: %s", strerror(errno));
	}
	ਜੇ (!WIFEXITED(ਸਥਿਤੀ)) {
		error("command '%.100s' exited abnormally", cmd);
		ਵਾਪਸ -1;
	}
	debug3("command returned status %d", WEXITSTATUS(ਸਥਿਤੀ));
	ਵਾਪਸ WEXITSTATUS(ਸਥਿਤੀ);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
ਸਥਿਰ ਪੂਰਨ
check_ਮੇਲ_ifaddrs(ਅਚਲ ਅੱਖਰ *addrlist)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_IFADDRS_H
	ਬਣਤਰ ifaddrs *ifa, *ifaddrs = ਨਿਰਾ;
	ਪੂਰਨ r, ਮਿਲਿਆ = 0;
	ਅੱਖਰ addr[NI_MAXHOST];
	socklen_t salen;

	ਜੇ (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    strerror(errno));
		ਵਾਪਸ 0;
	}
	ਲਈ (ifa = ifaddrs; ifa != ਨਿਰਾ; ifa = ifa->ifa_ਅਗਲਾ) {
		ਜੇ (ifa->ifa_addr == ਨਿਰਾ || ifa->ifa_name == ਨਿਰਾ ||
		    (ifa->ifa_flags & IFF_UP) == 0)
			ਜਾਰੀ;
		ਚੋਣ (ifa->ifa_addr->sa_family) {
		ਹਾਲਤ AF_INET:
			salen = ਆਕਾਰ(ਬਣਤਰ sockaddr_in);
			ਰੋਕੋ;
		ਹਾਲਤ AF_INET6:
			salen = ਆਕਾਰ(ਬਣਤਰ sockaddr_in6);
			ਰੋਕੋ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ AF_LINK
		ਹਾਲਤ AF_LINK:
			/* ignore */
			ਜਾਰੀ;
#ਜੇ_ਅੰਤ /* AF_LINK */
		ਮੂਲ:
			debug2_f("interface %s: unsupported address family %d",
			    ifa->ifa_name, ifa->ifa_addr->sa_family);
			ਜਾਰੀ;
		}
		ਜੇ ((r = getnameinfo(ifa->ifa_addr, salen, addr, ਆਕਾਰ(addr),
		    ਨਿਰਾ, 0, NI_NUMERICHOST)) != 0) {
			debug2_f("interface %s getnameinfo failed: %s",
			    ifa->ifa_name, gai_strerror(r));
			ਜਾਰੀ;
		}
		debug3_f("interface %s addr %s", ifa->ifa_name, addr);
		ਜੇ (addr_ਮੇਲ_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			ਮਿਲਿਆ = 1;
			ਰੋਕੋ;
		}
	}
	freeifaddrs(ifaddrs);
	ਵਾਪਸ ਮਿਲਿਆ;
#ਨਹੀਂਤਾਂ /* HAVE_IFADDRS_H */
	error("match localnetwork: not supported on this platform");
	ਵਾਪਸ 0;
#ਜੇ_ਅੰਤ /* HAVE_IFADDRS_H */
}

/*
 * Expand a "match exec" command or an Include path, caller must free returned
 * value.
 */
ਸਥਿਰ ਅੱਖਰ *
expand_ਮੇਲ_exec_or_include_ਰਸਤਾ(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, Options *options,
    ਬਣਤਰ passwd *pw, ਅਚਲ ਅੱਖਰ *host_arg, ਅਚਲ ਅੱਖਰ *original_host,
    ਪੂਰਨ final_pass, ਪੂਰਨ is_include_ਰਸਤਾ)
{
	ਅੱਖਰ thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	ਅੱਖਰ uidstr[32], *conn_hash_hex, *keyalias, *jmphost, *ruser;
	ਅੱਖਰ *host, *ret;
	ਪੂਰਨ ਪੋਰਟ;

	ਪੋਰਟ = options->ਪੋਰਟ <= 0 ? default_ssh_ਪੋਰਟ() : options->ਪੋਰਟ;
	ruser = options->user == ਨਿਰਾ ? pw->pw_name : options->user;
	ਜੇ (final_pass) {
		host = xstrdup(options->hostname);
	} ਨਹੀਂਤਾਂ ਜੇ (options->hostname != ਨਿਰਾ) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (ਅੱਖਰ *)ਨਿਰਾ);
	} ਨਹੀਂਤਾਂ {
		host = xstrdup(host_arg);
	}
	ਜੇ (gethostname(thishost, ਆਕਾਰ(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	jmphost = option_clear_or_none(options->jump_host) ?
	    "" : options->jump_host;
	strlcpy(shorthost, thishost, ਆਕਾਰ(shorthost));
	shorthost[strcspn(thishost, ".")] = '\0';
	snprintf(portstr, ਆਕਾਰ(portstr), "%d", ਪੋਰਟ);
	snprintf(uidstr, ਆਕਾਰ(uidstr), "%llu",
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)pw->pw_uid);
	conn_hash_hex = ssh_connection_hash(thishost, host,
	    portstr, ruser, jmphost);
	keyalias = options->host_ਕੁੰਜੀ_alias ?  options->host_ਕੁੰਜੀ_alias : host;

	ret = (is_include_ਰਸਤਾ ? percent_dollar_expand : percent_expand)(ਰਸਤਾ,
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
	    (ਅੱਖਰ *)ਨਿਰਾ);
	ਮੁਕਤ(host);
	ਮੁਕਤ(conn_hash_hex);
	ਵਾਪਸ ret;
}

/*
 * Parse and execute a Match directive.
 */
ਸਥਿਰ ਪੂਰਨ
ਮੇਲ_cfg_ਸਤਰ(Options *options, ਅਚਲ ਅੱਖਰ *ਭਰਿਆ_ਸਤਰ, ਪੂਰਨ *acp, ਅੱਖਰ ***avp,
    ਬਣਤਰ passwd *pw, ਅਚਲ ਅੱਖਰ *host_arg, ਅਚਲ ਅੱਖਰ *original_host,
    ਅਚਲ ਅੱਖਰ *remote_command, ਪੂਰਨ final_pass, ਪੂਰਨ *want_final_pass,
    ਅਚਲ ਅੱਖਰ *filename, ਪੂਰਨ linenum)
{
	ਅੱਖਰ *arg, *oattrib = ਨਿਰਾ, *attrib = ਨਿਰਾ, *cmd, *host, *criteria;
	ਅਚਲ ਅੱਖਰ *ruser;
	ਪੂਰਨ r, this_ਨਤੀਜਾ, ਨਤੀਜਾ = 1, ਗੁਣ = 0, negate;

	/*
	 * Configuration is likely to be incomplete at this point so we
	 * must be prepared to use default values.
	 */
	ruser = options->user == ਨਿਰਾ ? pw->pw_name : options->user;
	ਜੇ (final_pass) {
		host = xstrdup(options->hostname);
	} ਨਹੀਂਤਾਂ ਜੇ (options->hostname != ਨਿਰਾ) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (ਅੱਖਰ *)ਨਿਰਾ);
	} ਨਹੀਂਤਾਂ {
		host = xstrdup(host_arg);
	}

	debug2("checking match for '%s' host %s originally %s",
	    ਭਰਿਆ_ਸਤਰ, host, original_host);
	ਜਦੋਂ ((attrib = argv_ਅਗਲਾ(acp, avp)) != ਨਿਰਾ) {
		/* Terminate on comment */
		ਜੇ (*attrib == '#') {
			argv_consume(acp);
			ਰੋਕੋ;
		}
		attrib = oattrib = xstrdup(attrib);
		arg = criteria = ਨਿਰਾ;
		this_ਨਤੀਜਾ = 1;
		ਜੇ ((negate = (attrib[0] == '!')))
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		ਜੇ (strcasecmp(attrib, "all") == 0) {
			ਜੇ (ਗੁਣ > 1 ||
			    ((arg = argv_ਅਗਲਾ(acp, avp)) != ਨਿਰਾ &&
			    *arg != '\0' && *arg != '#')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				ਨਤੀਜਾ = -1;
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਜੇ (arg != ਨਿਰਾ && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			ਜੇ (ਨਤੀਜਾ)
				ਨਤੀਜਾ = negate ? 0 : 1;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਗੁਣ++;
		/* criteria "final" and "canonical" have no argument */
		ਜੇ (strcasecmp(attrib, "canonical") == 0 ||
		    strcasecmp(attrib, "final") == 0) {
			/*
			 * If the config requests "Match final" without
			 * negation then remember this so we can perform a
			 * second pass later.
			 */
			ਜੇ (strcasecmp(attrib, "final") == 0 &&
			    want_final_pass != ਨਿਰਾ)
				*want_final_pass |= !negate;
			r = !!final_pass;  /* force bitmask member to boolean */
			ਜੇ (r == (negate ? 1 : 0))
				this_ਨਤੀਜਾ = ਨਤੀਜਾ = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_ਨਤੀਜਾ ? "" : "not ", oattrib);
			ਜਾਓ ਅਗਲਾ;
		}

		/* Keep this list in sync with below */
		ਜੇ (strprefix(attrib, "host=", 1)  != ਨਿਰਾ ||
		    strprefix(attrib, "originalhost=", 1) != ਨਿਰਾ ||
		    strprefix(attrib, "user=", 1) != ਨਿਰਾ ||
		    strprefix(attrib, "localuser=", 1) != ਨਿਰਾ ||
		    strprefix(attrib, "localnetwork=", 1) != ਨਿਰਾ ||
		    strprefix(attrib, "version=", 1) != ਨਿਰਾ ||
		    strprefix(attrib, "tagged=", 1) != ਨਿਰਾ ||
		    strprefix(attrib, "command=", 1) != ਨਿਰਾ ||
		    strprefix(attrib, "exec=", 1) != ਨਿਰਾ) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} ਨਹੀਂਤਾਂ ਜੇ ((arg = argv_ਅਗਲਾ(acp, avp)) == ਨਿਰਾ) {
			error("%.200s line %d: missing argument for Match '%s'",
			    filename, linenum, oattrib);
			ਨਤੀਜਾ = -1;
			ਜਾਓ ਬਾਹਰਲਾ;
		}

		/*
		 * All other criteria require an argument, though it may
		 * be the empty string for the "tagged" and "command"
		 * options.
		 */
		ਜੇ (*arg == '\0' &&
		    strcasecmp(attrib, "tagged") != 0 &&
		    strcasecmp(attrib, "command") != 0)
			arg = ਨਿਰਾ;
		ਜੇ (arg == ਨਿਰਾ || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			ਨਤੀਜਾ = -1;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = ਮੇਲ_hostname(host, arg) == 1;
			ਜੇ (r == (negate ? 1 : 0))
				this_ਨਤੀਜਾ = ਨਤੀਜਾ = 0;
		} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = ਮੇਲ_hostname(original_host, arg) == 1;
			ਜੇ (r == (negate ? 1 : 0))
				this_ਨਤੀਜਾ = ਨਤੀਜਾ = 0;
		} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = ਮੇਲ_ਨਮੂਨਾ_list(ruser, arg, 0) == 1;
			ਜੇ (r == (negate ? 1 : 0))
				this_ਨਤੀਜਾ = ਨਤੀਜਾ = 0;
		} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = ਮੇਲ_ਨਮੂਨਾ_list(pw->pw_name, arg, 0) == 1;
			ਜੇ (r == (negate ? 1 : 0))
				this_ਨਤੀਜਾ = ਨਤੀਜਾ = 0;
		} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(attrib, "localnetwork") == 0) {
			ਜੇ (addr_ਮੇਲ_cidr_list(ਨਿਰਾ, arg) == -1) {
				/* Error already printed */
				ਨਤੀਜਾ = -1;
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			r = check_ਮੇਲ_ifaddrs(arg) == 1;
			ਜੇ (r == (negate ? 1 : 0))
				this_ਨਤੀਜਾ = ਨਤੀਜਾ = 0;
		} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(attrib, "version") == 0) {
			criteria = xstrdup(SSH_RELEASE);
			r = ਮੇਲ_ਨਮੂਨਾ_list(SSH_RELEASE, arg, 0) == 1;
			ਜੇ (r == (negate ? 1 : 0))
				this_ਨਤੀਜਾ = ਨਤੀਜਾ = 0;
		} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->ਟੈਗ == ਨਿਰਾ ? "" :
			    options->ਟੈਗ);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    ਮੇਲ_ਨਮੂਨਾ_list(criteria, arg, 0) == 1;
			ਜੇ (r == (negate ? 1 : 0))
				this_ਨਤੀਜਾ = ਨਤੀਜਾ = 0;
		} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(attrib, "command") == 0) {
			criteria = xstrdup(remote_command == ਨਿਰਾ ?
			    "" : remote_command);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    ਮੇਲ_ਨਮੂਨਾ_list(criteria, arg, 0) == 1;
			ਜੇ (r == (negate ? 1 : 0))
				this_ਨਤੀਜਾ = ਨਤੀਜਾ = 0;
		} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(attrib, "sessiontype") == 0) {
			ਜੇ (options->session_type == SESSION_TYPE_SUBSYSTEM)
				criteria = xstrdup("subsystem");
			ਨਹੀਂਤਾਂ ਜੇ (options->session_type == SESSION_TYPE_NONE)
				criteria = xstrdup("none");
			ਨਹੀਂਤਾਂ ਜੇ (remote_command != ਨਿਰਾ &&
			    *remote_command != '\0')
				criteria = xstrdup("exec");
			ਨਹੀਂਤਾਂ
				criteria = xstrdup("shell");
			r = ਮੇਲ_ਨਮੂਨਾ_list(criteria, arg, 0) == 1;
			ਜੇ (r == (negate ? 1 : 0))
				this_ਨਤੀਜਾ = ਨਤੀਜਾ = 0;
		} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(attrib, "exec") == 0) {
			ਜੇ ((cmd = expand_ਮੇਲ_exec_or_include_ਰਸਤਾ(arg,
			    options, pw, host_arg, original_host,
			    final_pass, 0)) == ਨਿਰਾ) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			ਜੇ (ਨਤੀਜਾ != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				ਮੁਕਤ(cmd);
				ਜਾਓ ਅਗਲਾ;
			}
			r = execute_ਵਿੱਚ_shell(cmd);
			ਜੇ (r == -1) {
				fatal("%.200s line %d: match exec "
				    "'%.100s' error", filename,
				    linenum, cmd);
			}
			criteria = xstrdup(cmd);
			ਮੁਕਤ(cmd);
			/* Force exit status to boolean */
			r = r == 0;
			ਜੇ (r == (negate ? 1 : 0))
				this_ਨਤੀਜਾ = ਨਤੀਜਾ = 0;
		} ਨਹੀਂਤਾਂ {
			error("Unsupported Match attribute %s", attrib);
			ਨਤੀਜਾ = -1;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s' ",
		    filename, linenum, this_ਨਤੀਜਾ ? "": "not ", oattrib,
		    criteria == ਨਿਰਾ ? "" : " \"",
		    criteria == ਨਿਰਾ ? "" : criteria,
		    criteria == ਨਿਰਾ ? "" : "\"");
 ਅਗਲਾ:
		ਮੁਕਤ(criteria);
		ਮੁਕਤ(oattrib);
		oattrib = attrib = ਨਿਰਾ;
	}
	ਜੇ (ਗੁਣ == 0) {
		error("One or more attributes required for Match");
		ਨਤੀਜਾ = -1;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
 ਬਾਹਰਲਾ:
	ਜੇ (ਨਤੀਜਾ != -1)
		debug2("match %sfound", ਨਤੀਜਾ ? "" : "not ");
	ਮੁਕਤ(oattrib);
	ਮੁਕਤ(host);
	ਵਾਪਸ ਨਤੀਜਾ;
}

/* Remove environment variable by pattern */
ਸਥਿਰ ਖਾਲੀ
rm_env(Options *options, ਅਚਲ ਅੱਖਰ *arg, ਅਚਲ ਅੱਖਰ *filename, ਪੂਰਨ linenum)
{
	u_int i, j, onum_send_env = options->ਅੰਕ_send_env;

	/* Remove an environment variable */
	ਲਈ (i = 0; i < options->ਅੰਕ_send_env; ) {
		ਜੇ (!ਮੇਲ_ਨਮੂਨਾ(options->send_env[i], arg + 1)) {
			i++;
			ਜਾਰੀ;
		}
		debug3("%s line %d: removing environment %s",
		    filename, linenum, options->send_env[i]);
		ਮੁਕਤ(options->send_env[i]);
		options->send_env[i] = ਨਿਰਾ;
		ਲਈ (j = i; j < options->ਅੰਕ_send_env - 1; j++) {
			options->send_env[j] = options->send_env[j + 1];
			options->send_env[j + 1] = ਨਿਰਾ;
		}
		options->ਅੰਕ_send_env--;
		/* NB. don't increment i */
	}
	ਜੇ (onum_send_env != options->ਅੰਕ_send_env) {
		options->send_env = xrecallocarray(options->send_env,
		    onum_send_env, options->ਅੰਕ_send_env,
		    ਆਕਾਰ(*options->send_env));
	}
}

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */
ਸਥਿਰ OpCodes
parse_token(ਅਚਲ ਅੱਖਰ *cp, ਅਚਲ ਅੱਖਰ *filename, ਪੂਰਨ linenum,
    ਅਚਲ ਅੱਖਰ *ignored_unknown)
{
	ਪੂਰਨ i;

	ਲਈ (i = 0; keywords[i].name; i++)
		ਜੇ (strcmp(cp, keywords[i].name) == 0)
			ਵਾਪਸ keywords[i].opcode;
	ਜੇ (ignored_unknown != ਨਿਰਾ &&
	    ਮੇਲ_ਨਮੂਨਾ_list(cp, ignored_unknown, 1) == 1)
		ਵਾਪਸ oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	ਵਾਪਸ oBadOption;
}

ਸਥਿਰ ਖਾਲੀ
free_canon_cnames(ਬਣਤਰ allowed_cname *cnames, u_int n)
{
	u_int i;

	ਜੇ (cnames == ਨਿਰਾ || n == 0)
		ਵਾਪਸ;
	ਲਈ (i = 0; i < n; i++) {
		ਮੁਕਤ(cnames[i].ਸਰੋਤ_list);
		ਮੁਕਤ(cnames[i].ਨਿਸ਼ਾਨਾ_list);
	}
	ਮੁਕਤ(cnames);
}

/* Multistate option parsing */
ਬਣਤਰ multistate {
	ਅੱਖਰ *ਕੁੰਜੀ;
	ਪੂਰਨ ਮੁੱਲ;
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_flag[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ ਨਿਰਾ, -1 }
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_yesnoask[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ ਨਿਰਾ, -1 }
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_strict_hostkey[] = {
	{ "true",			SSH_STRICT_HOSTKEY_YES },
	{ "false",			SSH_STRICT_HOSTKEY_OFF },
	{ "yes",			SSH_STRICT_HOSTKEY_YES },
	{ "no",				SSH_STRICT_HOSTKEY_OFF },
	{ "ask",			SSH_STRICT_HOSTKEY_ASK },
	{ "off",			SSH_STRICT_HOSTKEY_OFF },
	{ "accept-new",			SSH_STRICT_HOSTKEY_NEW },
	{ ਨਿਰਾ, -1 }
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_yesnoaskconfirm[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "confirm",			3 },
	{ ਨਿਰਾ, -1 }
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ ਨਿਰਾ, -1 }
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_controlmaster[] = {
	{ "true",			SSHCTL_MASTER_YES },
	{ "yes",			SSHCTL_MASTER_YES },
	{ "false",			SSHCTL_MASTER_NO },
	{ "no",				SSHCTL_MASTER_NO },
	{ "auto",			SSHCTL_MASTER_AUTO },
	{ "ask",			SSHCTL_MASTER_ASK },
	{ "autoask",			SSHCTL_MASTER_AUTO_ASK },
	{ ਨਿਰਾ, -1 }
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET },
	{ "point-to-point",		SSH_TUNMODE_POINTOPOINT },
	{ "true",			SSH_TUNMODE_DEFAULT },
	{ "yes",			SSH_TUNMODE_DEFAULT },
	{ "false",			SSH_TUNMODE_NO },
	{ "no",				SSH_TUNMODE_NO },
	{ ਨਿਰਾ, -1 }
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_requesttty[] = {
	{ "true",			REQUEST_TTY_YES },
	{ "yes",			REQUEST_TTY_YES },
	{ "false",			REQUEST_TTY_NO },
	{ "no",				REQUEST_TTY_NO },
	{ "force",			REQUEST_TTY_FORCE },
	{ "auto",			REQUEST_TTY_AUTO },
	{ ਨਿਰਾ, -1 }
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_sessiontype[] = {
	{ "none",			SESSION_TYPE_NONE },
	{ "subsystem",			SESSION_TYPE_SUBSYSTEM },
	{ "default",			SESSION_TYPE_DEFAULT },
	{ ਨਿਰਾ, -1 }
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_canonicalizehostname[] = {
	{ "true",			SSH_CANONICALISE_YES },
	{ "false",			SSH_CANONICALISE_NO },
	{ "yes",			SSH_CANONICALISE_YES },
	{ "no",				SSH_CANONICALISE_NO },
	{ "always",			SSH_CANONICALISE_ALWAYS },
	{ ਨਿਰਾ, -1 }
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_pubkey_auth[] = {
	{ "true",			SSH_PUBKEY_AUTH_ALL },
	{ "false",			SSH_PUBKEY_AUTH_NO },
	{ "yes",			SSH_PUBKEY_AUTH_ALL },
	{ "no",				SSH_PUBKEY_AUTH_NO },
	{ "unbound",			SSH_PUBKEY_AUTH_UNBOUND },
	{ "host-bound",			SSH_PUBKEY_AUTH_HBOUND },
	{ ਨਿਰਾ, -1 }
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_compression[] = {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_ZLIB
	{ "yes",			COMP_DELAYED },
#ਜੇ_ਅੰਤ
	{ "no",				COMP_NONE },
	{ ਨਿਰਾ, -1 }
};
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ ਨਿਰਾ, -1 }
};
/* XXX this will need to be replaced with a bitmask if we add more flags */
ਸਥਿਰ ਅਚਲ ਬਣਤਰ multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ ਨਿਰਾ, -1 }
};

ਸਥਿਰ ਪੂਰਨ
parse_multistate_ਮੁੱਲ(ਅਚਲ ਅੱਖਰ *arg, ਅਚਲ ਅੱਖਰ *filename, ਪੂਰਨ linenum,
    ਅਚਲ ਬਣਤਰ multistate *multistate_ptr)
{
	ਪੂਰਨ i;

	ਜੇ (!arg || *arg == '\0') {
		error("%s line %d: missing argument.", filename, linenum);
		ਵਾਪਸ -1;
	}
	ਲਈ (i = 0; multistate_ptr[i].ਕੁੰਜੀ != ਨਿਰਾ; i++) {
		ਜੇ (strcasecmp(arg, multistate_ptr[i].ਕੁੰਜੀ) == 0)
			ਵਾਪਸ multistate_ptr[i].ਮੁੱਲ;
	}
	ਵਾਪਸ -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
ਪੂਰਨ
process_config_ਸਤਰ(Options *options, ਬਣਤਰ passwd *pw, ਅਚਲ ਅੱਖਰ *host,
    ਅਚਲ ਅੱਖਰ *original_host, ਅਚਲ ਅੱਖਰ *remote_command, ਅੱਖਰ *ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *filename, ਪੂਰਨ linenum, ਪੂਰਨ *activep, ਪੂਰਨ flags)
{
	ਵਾਪਸ process_config_ਸਤਰ_ਡੂੰਘਾਈ(options, pw, host, original_host,
	    remote_command, ਸਤਰ, filename, linenum, activep, flags, ਨਿਰਾ, 0);
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ WHITESPACE " \t\r\n"
ਸਥਿਰ ਪੂਰਨ
process_config_ਸਤਰ_ਡੂੰਘਾਈ(Options *options, ਬਣਤਰ passwd *pw, ਅਚਲ ਅੱਖਰ *host,
    ਅਚਲ ਅੱਖਰ *original_host, ਅਚਲ ਅੱਖਰ *remote_command, ਅੱਖਰ *ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *filename, ਪੂਰਨ linenum, ਪੂਰਨ *activep, ਪੂਰਨ flags,
    ਪੂਰਨ *want_final_pass, ਪੂਰਨ ਡੂੰਘਾਈ)
{
	ਅੱਖਰ *str, **charptr, *endofnumber, *keyword, *arg, *arg2, *p;
	ਅੱਖਰ **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	ਪੂਰਨ r, oactive, negated, opcode, *intptr, ਮੁੱਲ, value2, cmdline = 0;
	ਪੂਰਨ remotefwd, dynamicfwd, ca_only = 0, ਮਿਲਿਆ = 0;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	ਲੰਮਾ ਲੰਮਾ val64;
	ਮਾਪ_t len;
	ਬਣਤਰ Forward fwd;
	ਅਚਲ ਬਣਤਰ multistate *multistate_ptr;
	glob_t gl;
	ਅਚਲ ਅੱਖਰ *errstr;
	ਅੱਖਰ **oav = ਨਿਰਾ, **av;
	ਪੂਰਨ oac = 0, ac;
	ਪੂਰਨ ret = -1;
	ਬਣਤਰ allowed_cname *cnames = ਨਿਰਾ;
	u_int ncnames = 0;
	ਅੱਖਰ **strs = ਨਿਰਾ; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	ਜੇ (activep == ਨਿਰਾ) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	ਜੇ ((len = ਲੜੀ_ਲੰਬਾਈ(ਸਤਰ)) == 0)
		ਵਾਪਸ 0;
	ਲਈ (len--; len > 0; len--) {
		ਜੇ (strchr(WHITESPACE "\f", ਸਤਰ[len]) == ਨਿਰਾ)
			ਰੋਕੋ;
		ਸਤਰ[len] = '\0';
	}

	str = ਸਤਰ;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	ਜੇ ((keyword = strdelim(&str)) == ਨਿਰਾ)
		ਵਾਪਸ 0;
	/* Ignore leading whitespace. */
	ਜੇ (*keyword == '\0')
		keyword = strdelim(&str);
	ਜੇ (keyword == ਨਿਰਾ || !*keyword || *keyword == '\n' || *keyword == '#')
		ਵਾਪਸ 0;
	/* Match lowercase keyword */
	lowercase(keyword);

	/* Prepare to parse remainder of line */
	ਜੇ (str != ਨਿਰਾ)
		str += strspn(str, WHITESPACE);
	ਜੇ (str == ਨਿਰਾ || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		ਵਾਪਸ -1;
	}
	opcode = parse_token(keyword, filename, linenum,
	    options->ignored_unknown);
	ਜੇ (argv_ਵੰਡੋ(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		ਵਾਪਸ -1;
	}
	ac = oac;
	av = oav;

	ਚੋਣ (opcode) {
	ਹਾਲਤ oBadOption:
		/* don't panic, but count bad options */
		ਜਾਓ ਬਾਹਰਲਾ;
	ਹਾਲਤ oIgnore:
		argv_consume(&ac);
		ਰੋਕੋ;
	ਹਾਲਤ oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		ਰੋਕੋ;
	ਹਾਲਤ oConnectTimeout:
		intptr = &options->connection_timeout;
parse_ਸਮਾਂ:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (strcmp(arg, "none") == 0)
			ਮੁੱਲ = -1;
		ਨਹੀਂਤਾਂ ਜੇ ((ਮੁੱਲ = convtime(arg)) == -1) {
			error("%s line %d: invalid time value.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*activep && *intptr == -1)
			*intptr = ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			error("%s line %d: missing argument.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}

		ਮੁੱਲ = -1;
		multistate_ptr = multistate_flag;
		ਲਈ (i = 0; multistate_ptr[i].ਕੁੰਜੀ != ਨਿਰਾ; i++) {
			ਜੇ (strcasecmp(arg, multistate_ptr[i].ਕੁੰਜੀ) == 0) {
				ਮੁੱਲ = multistate_ptr[i].ਮੁੱਲ;
				ਰੋਕੋ;
			}
		}
		ਜੇ (ਮੁੱਲ != -1) {
			ਜੇ (*activep && *intptr == -1)
				*intptr = ਮੁੱਲ;
			ਰੋਕੋ;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		ਜੇ (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_ਰਸਤਾ;
		ਜਾਓ parse_agent_ਰਸਤਾ;

	ਹਾਲਤ oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ ((ਮੁੱਲ = parse_multistate_ਮੁੱਲ(arg, filename, linenum,
		    multistate_ptr)) == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*activep && *intptr == -1)
			*intptr = ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		ਜਾਓ parse_flag;

	ਹਾਲਤ oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		ਜਾਓ parse_ਸਮਾਂ;

	ਹਾਲਤ oGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		ਜਾਓ parse_flag;

	ਹਾਲਤ oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		ਜਾਓ parse_flag;

	ਹਾਲਤ oPasswordAuthentication:
		intptr = &options->password_authentication;
		ਜਾਓ parse_flag;

	ਹਾਲਤ oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		ਜਾਓ parse_flag;

	ਹਾਲਤ oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		ਜਾਓ parse_string;

	ਹਾਲਤ oPubkeyAuthentication:
		multistate_ptr = multistate_pubkey_auth;
		intptr = &options->pubkey_authentication;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		ਜਾਓ parse_flag;

	ਹਾਲਤ oGssAuthentication:
		intptr = &options->gss_authentication;
		ਜਾਓ parse_flag;

	ਹਾਲਤ oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		ਜਾਓ parse_flag;

	ਹਾਲਤ o_Batch_ਬਹੁਲਕ:
		intptr = &options->batch_ਬਹੁਲਕ;
		ਜਾਓ parse_flag;

	ਹਾਲਤ oCheckHostIP:
		intptr = &options->check_host_ip;
		ਜਾਓ parse_flag;

	ਹਾਲਤ o_Verify_Host_ਕੁੰਜੀ_DNS:
		intptr = &options->verify_host_ਕੁੰਜੀ_dns;
		multistate_ptr = multistate_yesnoask;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ o_Strict_Host_ਕੁੰਜੀ_Checking:
		intptr = &options->strict_host_ਕੁੰਜੀ_checking;
		multistate_ptr = multistate_strict_hostkey;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ oCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		ਜਾਓ parse_flag;

	ਹਾਲਤ o_ਸੰਖਿਆ_ਦਾ_Password_Prompts:
		intptr = &options->ਸੰਖਿਆ_ਦਾ_password_prompts;
		ਜਾਓ parse_int;

	ਹਾਲਤ o_Rekey_ਹੱਦਬੰਦੀ:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.", filename,
			    linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (strcmp(arg, "default") == 0) {
			val64 = 0;
		} ਨਹੀਂਤਾਂ {
			ਜੇ (ਜਾਂਚ_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, strerror(errno));
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਜੇ (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
		}
		ਜੇ (*activep && options->rekey_ਹੱਦਬੰਦੀ == -1)
			options->rekey_ਹੱਦਬੰਦੀ = val64;
		ਜੇ (ac != 0) { /* optional rekey interval present */
			ਜੇ (strcmp(av[0], "none") == 0) {
				(ਖਾਲੀ)argv_ਅਗਲਾ(&ac, &av);	/* discard */
				ਰੋਕੋ;
			}
			intptr = &options->rekey_interval;
			ਜਾਓ parse_ਸਮਾਂ;
		}
		ਰੋਕੋ;

	ਹਾਲਤ o_ਪਛਾਣ_ਤੱਤ_File:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*activep) {
			intptr = &options->ਅੰਕ_ਪਛਾਣ_ਤੱਤ_files;
			ਜੇ (*intptr >= SSH_MAX_ਪਛਾਣ_ਤੱਤ_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_ਪਛਾਣ_ਤੱਤ_FILES);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ_file(options, ਨਿਰਾ,
			    arg, flags & SSHCONF_USERCONF);
		}
		ਰੋਕੋ;

	ਹਾਲਤ oCertificateFile:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*activep) {
			intptr = &options->ਅੰਕ_certificate_files;
			ਜੇ (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਜੋੜੋ_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		ਰੋਕੋ;

	ਹਾਲਤ oXAuthLocation:
		charptr=&options->xauth_location;
		ਜਾਓ parse_string;

	ਹਾਲਤ oUser:
		charptr = &options->user;
parse_string:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*activep && *charptr == ਨਿਰਾ)
			*charptr = xstrdup(arg);
		ਰੋਕੋ;

	ਹਾਲਤ o_Global_ਗਿਆਤ_Hosts_File:
		cpptr = (ਅੱਖਰ **)&options->system_hostfiles;
		uintptr = &options->ਅੰਕ_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		i = 0;
		ਮੁੱਲ = *uintptr == 0; /* was array empty when we started? */
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			ਜੇ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			/* Allow "none" only in first position */
			ਜੇ (strcasecmp(arg, "none") == 0) {
				ਜੇ (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
			}
			i++;
			ਜੇ (*activep && ਮੁੱਲ) {
				ਜੇ ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries.", filename, linenum,
					    keyword);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		ਰੋਕੋ;

	ਹਾਲਤ o_User_ਗਿਆਤ_Hosts_File:
		cpptr = (ਅੱਖਰ **)&options->user_hostfiles;
		uintptr = &options->ਅੰਕ_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		ਜਾਓ parse_char_array;

	ਹਾਲਤ oHostname:
		charptr = &options->hostname;
		ਜਾਓ parse_string;

	ਹਾਲਤ o_ਟੈਗ:
		charptr = &options->ਟੈਗ;
		ਜਾਓ parse_string;

	ਹਾਲਤ o_Host_ਕੁੰਜੀ_Alias:
		charptr = &options->host_ਕੁੰਜੀ_alias;
		ਜਾਓ parse_string;

	ਹਾਲਤ oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		ਜਾਓ parse_string;

	ਹਾਲਤ o_Bind_ਪਤਾ:
		charptr = &options->bind_ਪਤਾ;
		ਜਾਓ parse_string;

	ਹਾਲਤ oBindInterface:
		charptr = &options->bind_interface;
		ਜਾਓ parse_string;

	ਹਾਲਤ oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		ਜਾਓ parse_string;

	ਹਾਲਤ o_Security_ਕੁੰਜੀ_Provider:
		charptr = &options->sk_provider;
		ਜਾਓ parse_string;

	ਹਾਲਤ o_ਗਿਆਤ_Hosts_Command:
		charptr = &options->ਗਿਆਤ_hosts_command;
		ਜਾਓ parse_command;

	ਹਾਲਤ oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		ਜੇ (str == ਨਿਰਾ) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		len = strspn(str, WHITESPACE "=");
		ਜੇ (*activep && *charptr == ਨਿਰਾ)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		ਰੋਕੋ;

	ਹਾਲਤ oProxyJump:
		ਜੇ (str == ਨਿਰਾ) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		len = strspn(str, WHITESPACE "=");
		/* XXX use argv? */
		ਜੇ (parse_jump(str + len, options, cmdline, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		argv_consume(&ac);
		ਰੋਕੋ;

	ਹਾਲਤ o_ਪੋਰਟ:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਮੁੱਲ = a2port(arg);
		ਜੇ (ਮੁੱਲ <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*activep && options->ਪੋਰਟ == -1)
			options->ਪੋਰਟ = ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ ((errstr = atoi_err(arg, &ਮੁੱਲ)) != ਨਿਰਾ) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*activep && *intptr == -1)
			*intptr = ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ oCiphers:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*activep && options->ciphers == ਨਿਰਾ)
			options->ciphers = xstrdup(arg);
		ਰੋਕੋ;

	ਹਾਲਤ oMacs:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*activep && options->macs == ਨਿਰਾ)
			options->macs = xstrdup(arg);
		ਰੋਕੋ;

	ਹਾਲਤ oKexAlgorithms:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*arg != '-' &&
		    !kex_ਨਾਂ_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*activep && options->kex_algorithms == ਨਿਰਾ)
			options->kex_algorithms = xstrdup(arg);
		ਰੋਕੋ;

	ਹਾਲਤ o_Host_ਕੁੰਜੀ_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
parse_pubkey_algos:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*arg != '-' &&
		    !sshkey_ਨਾਂ_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*activep && *charptr == ਨਿਰਾ)
			*charptr = xstrdup(arg);
		ਰੋਕੋ;

	ਹਾਲਤ oCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		ਜਾਓ parse_pubkey_algos;

	ਹਾਲਤ oLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਮੁੱਲ = log_level_ਸੰਖਿਆ(arg);
		ਜੇ (ਮੁੱਲ == SYSLOG_LEVEL_NOT_ਸੈੱਟ) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_ਸੈੱਟ)
			*log_level_ptr = (LogLevel) ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਮੁੱਲ = log_facility_ਸੰਖਿਆ(arg);
		ਜੇ (ਮੁੱਲ == SYSLOG_FACILITY_NOT_ਸੈੱਟ) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ oLogVerbose:
		cppptr = &options->log_verbose;
		uintptr = &options->ਅੰਕ_log_verbose;
		i = 0;
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			ਜੇ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			/* Allow "none" only in first position */
			ਜੇ (strcasecmp(arg, "none") == 0) {
				ਜੇ (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
			}
			i++;
			ਜੇ (*activep && *uintptr == 0) {
				*cppptr = xrecallocarray(*cppptr, *uintptr,
				    *uintptr + 1, ਆਕਾਰ(**cppptr));
				(*cppptr)[(*uintptr)++] = xstrdup(arg);
			}
		}
		ਰੋਕੋ;

	ਹਾਲਤ oLocalForward:
	ਹਾਲਤ oRemoteForward:
	ਹਾਲਤ oDynamicForward:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		ਜੇ (!dynamicfwd) {
			arg2 = argv_ਅਗਲਾ(&ac, &av);
			ਜੇ (arg2 == ਨਿਰਾ || *arg2 == '\0') {
				ਜੇ (remotefwd)
					dynamicfwd = 1;
				ਨਹੀਂਤਾਂ {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
			} ਨਹੀਂਤਾਂ {
				/* construct a string for parse_forward */
				snprintf(fwdarg, ਆਕਾਰ(fwdarg), "%s:%s", arg,
				    arg2);
			}
		}
		ਜੇ (dynamicfwd)
			strlcpy(fwdarg, arg, ਆਕਾਰ(fwdarg));

		ਜੇ (parse_forward(&fwd, fwdarg, dynamicfwd, remotefwd) == 0) {
			error("%.200s line %d: Bad forwarding specification.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}

		ਜੇ (*activep) {
			ਜੇ (remotefwd) {
				ਜੋੜੋ_remote_forward(options, &fwd);
			} ਨਹੀਂਤਾਂ {
				ਜੋੜੋ_local_forward(options, &fwd);
			}
		}
		ਰੋਕੋ;

	ਹਾਲਤ oPermitRemoteOpen:
		uintptr = &options->ਅੰਕ_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		ਮਿਲਿਆ = *uintptr == 0;
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			ਜੇ (strcasecmp(arg, "none") == 0 ||
			    strcasecmp(arg, "any") == 0) {
				ਜੇ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					ਮੁਕਤ(arg2);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
			} ਨਹੀਂਤਾਂ {
				p = hpdelim(&arg);
				ਜੇ (p == ਨਿਰਾ) {
					fatal("%s line %d: missing host in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
				}
				p = cleanhostname(p);
				/*
				 * don't want to use permitopen_port to avoid
				 * dependency on channels.[ch] here.
				 */
				ਜੇ (arg == ਨਿਰਾ || (strcmp(arg, "*") != 0 &&
				    a2port(arg) <= 0)) {
					fatal("%s line %d: bad port number "
					    "in %s", filename, linenum,
					    lookup_opcode_name(opcode));
				}
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg2);
			ਮੁਕਤ(arg2);
		}
		ਜੇ (nstrs == 0)
			fatal("%s line %d: missing %s specification",
			    filename, linenum, lookup_opcode_name(opcode));
		ਜੇ (ਮਿਲਿਆ && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = ਨਿਰਾ; /* transferred */
			nstrs = 0;
		}
		ਰੋਕੋ;

	ਹਾਲਤ oClearAllForwardings:
		intptr = &options->clear_forwardings;
		ਜਾਓ parse_flag;

	ਹਾਲਤ oHost:
		ਜੇ (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		*activep = 0;
		arg2 = ਨਿਰਾ;
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			ਜੇ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਜੇ ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				ਰੋਕੋ;
			}
			negated = *arg == '!';
			ਜੇ (negated)
				arg++;
			ਜੇ (ਮੇਲ_ਨਮੂਨਾ(host, arg)) {
				ਜੇ (negated) {
					debug("%.200s line %d: Skipping Host "
					    "block because of negated match "
					    "for %.100s", filename, linenum,
					    arg);
					*activep = 0;
					argv_consume(&ac);
					ਰੋਕੋ;
				}
				ਜੇ (!*activep)
					arg2 = arg; /* logged below */
				*activep = 1;
			}
		}
		ਜੇ (*activep)
			debug("%.200s line %d: Applying options for %.100s",
			    filename, linenum, arg2);
		ਰੋਕੋ;

	ਹਾਲਤ o_ਮੇਲ:
		ਜੇ (cmdline) {
			error("Match directive not supported as a command-line "
			    "option");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਮੁੱਲ = ਮੇਲ_cfg_ਸਤਰ(options, str, &ac, &av, pw, host,
		    original_host, remote_command, flags & SSHCONF_FINAL,
		    want_final_pass, filename, linenum);
		ਜੇ (ਮੁੱਲ < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (strcmp(arg, "none") == 0)
			ਮੁੱਲ = SSH_ESCAPECHAR_NONE;
		ਨਹੀਂਤਾਂ ਜੇ (arg[1] == '\0')
			ਮੁੱਲ = (u_char) arg[0];
		ਨਹੀਂਤਾਂ ਜੇ (arg[0] == '^' && arg[2] == 0 &&
		    (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			ਮੁੱਲ = (u_char) arg[1] & 31;
		ਨਹੀਂਤਾਂ {
			error("%.200s line %d: Bad escape character.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*activep && *intptr == -1)
			*intptr = ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ o_ਪਤਾ_Family:
		intptr = &options->ਪਤਾ_family;
		multistate_ptr = multistate_addressfamily;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		ਜਾਓ parse_flag;

	ਹਾਲਤ oIdentitiesOnly:
		intptr = &options->identities_only;
		ਜਾਓ parse_flag;

	ਹਾਲਤ oServerAliveInterval:
		intptr = &options->server_alive_interval;
		ਜਾਓ parse_ਸਮਾਂ;

	ਹਾਲਤ o_Server_Alive_ਗਿਣਤੀ_Max:
		intptr = &options->server_alive_ਗਿਣਤੀ_max;
		ਜਾਓ parse_int;

	ਹਾਲਤ oSendEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			ਜੇ (*arg == '\0' || strchr(arg, '=') != ਨਿਰਾ) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਮਿਲਿਆ = 1;
			ਜੇ (!*activep)
				ਜਾਰੀ;
			ਜੇ (*arg == '-') {
				/* Removing an env var */
				rm_env(options, arg, filename, linenum);
				ਜਾਰੀ;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->ਅੰਕ_send_env, arg);
		}
		ਜੇ (!ਮਿਲਿਆ) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ਰੋਕੋ;

	ਹਾਲਤ o_ਸੈੱਟ_Env:
		ਮਿਲਿਆ = options->ਅੰਕ_setenv == 0;
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			ਜੇ (strchr(arg, '=') == ਨਿਰਾ) {
				error("%s line %d: Invalid SetEnv.",
				    filename, linenum);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਜੇ (lookup_setenv_ਵਿੱਚ_list(arg, strs, nstrs) != ਨਿਰਾ) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				ਜਾਰੀ;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg);
		}
		ਜੇ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ਜੇ (ਮਿਲਿਆ && *activep) {
			options->setenv = strs;
			options->ਅੰਕ_setenv = nstrs;
			strs = ਨਿਰਾ; /* transferred */
			nstrs = 0;
		}
		ਰੋਕੋ;

	ਹਾਲਤ o_Control_ਰਸਤਾ:
		charptr = &options->control_ਰਸਤਾ;
		ਜਾਓ parse_string;

	ਹਾਲਤ oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing ControlPersist"
			    " argument.", filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਮੁੱਲ = 0;
		value2 = 0;	/* timeout */
		ਜੇ (strcmp(arg, "no") == 0 || strcmp(arg, "false") == 0)
			ਮੁੱਲ = 0;
		ਨਹੀਂਤਾਂ ਜੇ (strcmp(arg, "yes") == 0 || strcmp(arg, "true") == 0)
			ਮੁੱਲ = 1;
		ਨਹੀਂਤਾਂ ਜੇ ((value2 = convtime(arg)) >= 0)
			ਮੁੱਲ = 1;
		ਨਹੀਂਤਾਂ {
			error("%.200s line %d: Bad ControlPersist argument.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*activep && *intptr == -1) {
			*intptr = ਮੁੱਲ;
			options->control_persist_timeout = value2;
		}
		ਰੋਕੋ;

	ਹਾਲਤ o_Hash_ਗਿਆਤ_Hosts:
		intptr = &options->hash_ਗਿਆਤ_hosts;
		ਜਾਓ parse_flag;

	ਹਾਲਤ oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ oTunnelDevice:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਮੁੱਲ = a2tun(arg, &value2);
		ਜੇ (ਮੁੱਲ == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*activep && options->tun_local == -1) {
			options->tun_local = ਮੁੱਲ;
			options->tun_remote = value2;
		}
		ਰੋਕੋ;

	ਹਾਲਤ oLocalCommand:
		charptr = &options->local_command;
		ਜਾਓ parse_command;

	ਹਾਲਤ oPermitLocalCommand:
		intptr = &options->permit_local_command;
		ਜਾਓ parse_flag;

	ਹਾਲਤ oRemoteCommand:
		charptr = &options->remote_command;
		ਜਾਓ parse_command;

	ਹਾਲਤ o_Visual_Host_ਕੁੰਜੀ:
		intptr = &options->visual_host_ਕੁੰਜੀ;
		ਜਾਓ parse_flag;

	ਹਾਲਤ oInclude:
		ਜੇ (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਮੁੱਲ = 0;
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			ਜੇ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			/* Expand %tokens and environment variables */
			ਜੇ ((p = expand_ਮੇਲ_exec_or_include_ਰਸਤਾ(arg,
			    options, pw, host, original_host,
			    flags & SSHCONF_FINAL, 1)) == ਨਿਰਾ) {
				error("%.200s line %d: Unable to expand user "
				    "config file '%.100s'",
				    filename, linenum, arg);
				ਜਾਰੀ;
			}
			/*
			 * Ensure all paths are anchored. User configuration
			 * files may begin with '~/' but system configurations
			 * must not. If the path is relative, then treat it
			 * as living in ~/.ssh for user configurations or
			 * /etc/ssh for system ones.
			 */
			ਜੇ (*p == '~' && (flags & SSHCONF_USERCONF) == 0) {
				error("%.200s line %d: bad include path %s.",
				    filename, linenum, p);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਜੇ (!ਰਸਤਾ_absolute(p) && *p != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" ਰਸਤਾ_SSH_USER_DIR : SSHDIR, p);
			} ਨਹੀਂਤਾਂ {
				arg2 = xstrdup(p);
			}
			ਮੁਕਤ(p);
			memset(&gl, 0, ਆਕਾਰ(gl));
			r = glob(arg2, GLOB_TILDE, ਨਿਰਾ, &gl);
			ਜੇ (r == GLOB_NOMATCH) {
				debug("%.200s line %d: include %s matched no "
				    "files",filename, linenum, arg2);
				ਮੁਕਤ(arg2);
				ਜਾਰੀ;
			} ਨਹੀਂਤਾਂ ਜੇ (r != 0) {
				error("%.200s line %d: glob failed for %s.",
				    filename, linenum, arg2);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਮੁਕਤ(arg2);
			oactive = *activep;
			ਲਈ (i = 0; i < gl.gl_pathc; i++) {
				debug3("%.200s line %d: Including file %s "
				    "depth %d%s", filename, linenum,
				    gl.gl_pathv[i], ਡੂੰਘਾਈ,
				    oactive ? "" : " (parse only)");
				r = read_config_file_ਡੂੰਘਾਈ(gl.gl_pathv[i],
				    pw, host, original_host, remote_command,
				    options, flags | SSHCONF_CHECKPERM |
				    (oactive ? 0 : SSHCONF_NEVERMATCH),
				    activep, want_final_pass, ਡੂੰਘਾਈ + 1);
				ਜੇ (r != 1 && errno != ENOENT) {
					error("%.200s line %d: Can't open user "
					    "config file %.100s: %.100s",
					    filename, linenum, gl.gl_pathv[i],
					    strerror(errno));
					globfree(&gl);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
				/*
				 * don't let Match in includes clobber the
				 * containing file's Match state.
				 */
				*activep = oactive;
				ਜੇ (r != 1)
					ਮੁੱਲ = -1;
			}
			globfree(&gl);
		}
		ਜੇ (ਮੁੱਲ != 0)
			ret = ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ oIPQoS:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ ((ਮੁੱਲ = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (ਮੁੱਲ == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			ਮੁੱਲ = ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ;
		}
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (arg == ਨਿਰਾ)
			value2 = ਮੁੱਲ;
		ਨਹੀਂਤਾਂ ਜੇ ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ;
		}
		ਜੇ (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = ਮੁੱਲ;
			options->ip_qos_bulk = value2;
		}
		ਰੋਕੋ;

	ਹਾਲਤ oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ oSessionType:
		intptr = &options->session_type;
		multistate_ptr = multistate_sessiontype;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ oStdinNull:
		intptr = &options->stdin_null;
		ਜਾਓ parse_flag;

	ਹਾਲਤ oForkAfterAuthentication:
		intptr = &options->fork_after_authentication;
		ਜਾਓ parse_flag;

	ਹਾਲਤ oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		ਜਾਓ parse_string;

	ਹਾਲਤ oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		ਜਾਓ parse_flag;

	ਹਾਲਤ oCanonicalDomains:
		ਮਿਲਿਆ = options->ਅੰਕ_canonical_domains == 0;
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			/* Allow "none" only in first position */
			ਜੇ (strcasecmp(arg, "none") == 0) {
				ਜੇ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
			}
			ਜੇ (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ਜੇ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ਜੇ (ਮਿਲਿਆ && *activep) {
			options->canonical_domains = strs;
			options->ਅੰਕ_canonical_domains = nstrs;
			strs = ਨਿਰਾ; /* transferred */
			nstrs = 0;
		}
		ਰੋਕੋ;

	ਹਾਲਤ oCanonicalizePermittedCNAMEs:
		ਮਿਲਿਆ = options->ਅੰਕ_permitted_cnames == 0;
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			ਜੇ (strcasecmp(arg, "none") == 0) {
				ਜੇ (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
				arg2 = "";
			} ਨਹੀਂਤਾਂ ਜੇ (strcmp(arg, "*") == 0) {
				arg2 = arg;
			} ਨਹੀਂਤਾਂ {
				lowercase(arg);
				ਜੇ ((arg2 = strchr(arg, ':')) == ਨਿਰਾ ||
				    arg2[1] == '\0') {
					error("%s line %d: "
					    "Invalid permitted CNAME \"%s\"",
					    filename, linenum, arg);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    ਆਕਾਰ(*cnames));
			cnames[ncnames].ਸਰੋਤ_list = xstrdup(arg);
			cnames[ncnames].ਨਿਸ਼ਾਨਾ_list = xstrdup(arg2);
			ncnames++;
		}
		ਜੇ (ncnames == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ਜੇ (ਮਿਲਿਆ && *activep) {
			options->permitted_cnames = cnames;
			options->ਅੰਕ_permitted_cnames = ncnames;
			cnames = ਨਿਰਾ; /* transferred */
			ncnames = 0;
		}
		/* un-transferred cnames is cleaned up before exit */
		ਰੋਕੋ;

	ਹਾਲਤ oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		ਜਾਓ parse_int;

	ਹਾਲਤ oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		ਜਾਓ parse_flag;

	ਹਾਲਤ o_ਧਾਰਾ_Local_Bind_ਨਕਾਬ:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		/* Parse mode in octal format */
		ਮੁੱਲ = strtol(arg, &endofnumber, 8);
		ਜੇ (arg == endofnumber || ਮੁੱਲ < 0 || ਮੁੱਲ > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*activep &&
		    options->fwd_opts.streamlocal_bind_ਨਕਾਬ == (ਬਹੁਲਕ_t)-1)
			options->fwd_opts.streamlocal_bind_ਨਕਾਬ = (ਬਹੁਲਕ_t)ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ o_ਧਾਰਾ_Local_Bind_Unlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		ਜਾਓ parse_flag;

	ਹਾਲਤ o_Revoked_Host_ਕੁੰਜੀਆਂ:
		uintptr = &options->ਅੰਕ_revoked_host_ਕੁੰਜੀਆਂ;
		cppptr = &options->revoked_host_ਕੁੰਜੀਆਂ;
		ਮਿਲਿਆ = *uintptr == 0;
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			ਜੇ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			/* Allow "none" only in first position */
			ਜੇ (strcasecmp(arg, "none") == 0) {
				ਜੇ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ਜੇ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ਜੇ (ਮਿਲਿਆ && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = ਨਿਰਾ; /* transferred */
			nstrs = 0;
		}
		ਰੋਕੋ;

	ਹਾਲਤ oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ ((ਮੁੱਲ = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*activep && *intptr == -1)
			*intptr = ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ oUpdateHostkeys:
		intptr = &options->update_hostkeys;
		multistate_ptr = multistate_yesnoask;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ oHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
		ਜਾਓ parse_pubkey_algos;

	ਹਾਲਤ oPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		ਜਾਓ parse_pubkey_algos;

	ਹਾਲਤ o_ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_Agent:
		arg = argv_ਅਗਲਾ(&ac, &av);
		arg2 = argv_ਅਗਲਾ(&ac, &av);
		ਮੁੱਲ = parse_multistate_ਮੁੱਲ(arg, filename, linenum,
		    multistate_yesnoaskconfirm);
		value2 = 0; /* unlimited lifespan by default */
		ਜੇ (ਮੁੱਲ == 3 && arg2 != ਨਿਰਾ) {
			/* allow "AddKeysToAgent confirm 5m" */
			ਜੇ ((value2 = convtime(arg2)) == -1) {
				error("%s line %d: invalid time value.",
				    filename, linenum);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
		} ਨਹੀਂਤਾਂ ਜੇ (ਮੁੱਲ == -1 && arg2 == ਨਿਰਾ) {
			ਜੇ ((value2 = convtime(arg)) == -1) {
				error("%s line %d: unsupported option",
				    filename, linenum);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਮੁੱਲ = 1; /* yes */
		} ਨਹੀਂਤਾਂ ਜੇ (ਮੁੱਲ == -1 || arg2 != ਨਿਰਾ) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*activep && options->ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_agent == -1) {
			options->ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_agent = ਮੁੱਲ;
			options->ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_agent_lifespan = value2;
		}
		ਰੋਕੋ;

	ਹਾਲਤ o_ਪਛਾਣ_ਤੱਤ_Agent:
		charptr = &options->ਪਛਾਣ_ਤੱਤ_agent;
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
  parse_agent_ਰਸਤਾ:
		/* Extra validation if the string represents an env var. */
		ਜੇ ((arg2 = dollar_expand(&r, arg)) == ਨਿਰਾ || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਮੁਕਤ(arg2);
		/* check for legacy environment format */
		ਜੇ (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*activep && *charptr == ਨਿਰਾ)
			*charptr = xstrdup(arg);
		ਰੋਕੋ;

	ਹਾਲਤ oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		ਜਾਓ parse_flag;

	ਹਾਲਤ oRequiredRSASize:
		intptr = &options->required_rsa_ਮਾਪ;
		ਜਾਓ parse_int;

	ਹਾਲਤ oWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		ਜਾਓ parse_multistate;

	ਹਾਲਤ oObscureKeystrokeTiming:
		ਮੁੱਲ = -1;
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			ਜੇ (ਮੁੱਲ != -1) {
				error("%s line %d: invalid arguments",
				    filename, linenum);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਜੇ (strcmp(arg, "yes") == 0 ||
			    strcmp(arg, "true") == 0)
				ਮੁੱਲ = SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
			ਨਹੀਂਤਾਂ ਜੇ (strcmp(arg, "no") == 0 ||
			    strcmp(arg, "false") == 0)
				ਮੁੱਲ = 0;
			ਨਹੀਂਤਾਂ ਜੇ (ਲੜੀ_ਤੁਲਨਾ(arg, "interval:", 9) == 0) {
				ਜੇ ((errstr = atoi_err(arg + 9,
				    &ਮੁੱਲ)) != ਨਿਰਾ) {
					error("%s line %d: integer value %s.",
					    filename, linenum, errstr);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
				ਜੇ (ਮੁੱਲ <= 0 || ਮੁੱਲ > 1000) {
					error("%s line %d: value out of range.",
					    filename, linenum);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
			} ਨਹੀਂਤਾਂ {
				error("%s line %d: unsupported argument \"%s\"",
				    filename, linenum, arg);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
		}
		ਜੇ (ਮੁੱਲ == -1) {
			error("%s line %d: missing argument",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		intptr = &options->obscure_keystroke_timing_interval;
		ਜੇ (*activep && *intptr == -1)
			*intptr = ਮੁੱਲ;
		ਰੋਕੋ;

	ਹਾਲਤ oChannelTimeout:
		ਮਿਲਿਆ = options->ਅੰਕ_channel_timeouts == 0;
		ਜਦੋਂ ((arg = argv_ਅਗਲਾ(&ac, &av)) != ਨਿਰਾ) {
			/* Allow "none" only in first position */
			ਜੇ (strcasecmp(arg, "none") == 0) {
				ਜੇ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ਜਾਓ ਬਾਹਰਲਾ;
				}
			} ਨਹੀਂਤਾਂ ਜੇ (parse_ਨਮੂਨਾ_interval(arg,
			    ਨਿਰਾ, ਨਿਰਾ) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ਜੇ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ਜੇ (ਮਿਲਿਆ && *activep) {
			options->channel_timeouts = strs;
			options->ਅੰਕ_channel_timeouts = nstrs;
			strs = ਨਿਰਾ; /* transferred */
			nstrs = 0;
		}
		ਰੋਕੋ;

	ਹਾਲਤ o_ਸੰਸਕਰਣ_Addendum:
		ਜੇ (str == ਨਿਰਾ || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		ਜੇ (strchr(str + len, '\r') != ਨਿਰਾ) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		ਜੇ ((arg = strchr(ਸਤਰ, '#')) != ਨਿਰਾ) {
			*arg = '\0';
			rtrim(ਸਤਰ);
		}
		ਜੇ (*activep && options->ਸੰਸਕਰਣ_addendum == ਨਿਰਾ) {
			ਜੇ (strcasecmp(str + len, "none") == 0)
				options->ਸੰਸਕਰਣ_addendum = xstrdup("");
			ਨਹੀਂਤਾਂ
				options->ਸੰਸਕਰਣ_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		ਰੋਕੋ;

	ਹਾਲਤ oRefuseConnection:
		arg = argv_ਅਗਲਾ(&ac, &av);
		ਜੇ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (*activep) {
			fatal("%.200s line %d: RefuseConnection: %s",
			    filename, linenum, arg);
		}
		ਰੋਕੋ;

	ਹਾਲਤ oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		ਰੋਕੋ;

	ਹਾਲਤ oUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		ਰੋਕੋ;

	ਮੂਲ:
		error("%s line %d: Unimplemented opcode %d",
		    filename, linenum, opcode);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* Check that there is no garbage at end of line. */
	ਜੇ (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* success */
	ret = 0;
 ਬਾਹਰਲਾ:
	free_canon_cnames(cnames, ncnames);
	opt_array_free2(strs, ਨਿਰਾ, nstrs);
	argv_free(oav, oac);
	ਵਾਪਸ ret;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */
ਪੂਰਨ
read_config_file(ਅਚਲ ਅੱਖਰ *filename, ਬਣਤਰ passwd *pw, ਅਚਲ ਅੱਖਰ *host,
    ਅਚਲ ਅੱਖਰ *original_host, ਅਚਲ ਅੱਖਰ *remote_command, Options *options, ਪੂਰਨ flags,
    ਪੂਰਨ *want_final_pass)
{
	ਪੂਰਨ ਸਰਗਰਮ = 1;

	ਵਾਪਸ read_config_file_ਡੂੰਘਾਈ(filename, pw, host, original_host,
	    remote_command, options, flags, &ਸਰਗਰਮ, want_final_pass, 0);
}

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ READCONF_MAX_ਡੂੰਘਾਈ	16
ਸਥਿਰ ਪੂਰਨ
read_config_file_ਡੂੰਘਾਈ(ਅਚਲ ਅੱਖਰ *filename, ਬਣਤਰ passwd *pw,
    ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *original_host, ਅਚਲ ਅੱਖਰ *remote_command,
    Options *options, ਪੂਰਨ flags, ਪੂਰਨ *activep, ਪੂਰਨ *want_final_pass, ਪੂਰਨ ਡੂੰਘਾਈ)
{
	FILE *f;
	ਅੱਖਰ *ਸਤਰ = ਨਿਰਾ;
	ਮਾਪ_t linesize = 0;
	ਪੂਰਨ linenum;
	ਪੂਰਨ bad_options = 0;

	ਜੇ (ਡੂੰਘਾਈ < 0 || ਡੂੰਘਾਈ > READCONF_MAX_ਡੂੰਘਾਈ)
		fatal("Too many recursive configuration includes");

	ਜੇ ((f = fopen(filename, "r")) == ਨਿਰਾ)
		ਵਾਪਸ 0;

	ਜੇ (flags & SSHCONF_CHECKPERM) {
		ਬਣਤਰ stat sb;

		ਜੇ (fstat(fileno(f), &sb) == -1)
			fatal("fstat %s: %s", filename, strerror(errno));
		ਜੇ (((sb.st_uid != 0 && sb.st_uid != getuid()) ||
		    (sb.st_mode & 022) != 0))
			fatal("Bad owner or permissions on %s", filename);
	}

	debug("Reading configuration data %.200s", filename);

	/*
	 * Mark that we are now processing the options.  This flag is turned
	 * on/off by Host specifications.
	 */
	linenum = 0;
	ਜਦੋਂ (getline(&ਸਤਰ, &linesize, f) != -1) {
		/* Update line number counter. */
		linenum++;
		/*
		 * Trim out comments and strip whitespace.
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages.
		 */
		ਜੇ (process_config_ਸਤਰ_ਡੂੰਘਾਈ(options, pw, host, original_host,
		    remote_command, ਸਤਰ, filename, linenum, activep, flags,
		    want_final_pass, ਡੂੰਘਾਈ) != 0)
			bad_options++;
	}
	ਮੁਕਤ(ਸਤਰ);
	fclose(f);
	ਜੇ (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
	ਵਾਪਸ 1;
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
ਪੂਰਨ
option_clear_or_none(ਅਚਲ ਅੱਖਰ *o)
{
	ਵਾਪਸ o == ਨਿਰਾ || strcasecmp(o, "none") == 0;
}

/*
 * Returns 1 if CanonicalizePermittedCNAMEs have been specified, 0 otherwise.
 * Allowed to be called on non-final configuration.
 */
ਪੂਰਨ
config_has_permitted_cnames(Options *options)
{
	ਜੇ (options->ਅੰਕ_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].ਸਰੋਤ_list, "none") == 0 &&
	    strcmp(options->permitted_cnames[0].ਨਿਸ਼ਾਨਾ_list, "") == 0)
		ਵਾਪਸ 0;
	ਵਾਪਸ options->ਅੰਕ_permitted_cnames > 0;
}

/*
 * Initializes options to special values that indicate that they have not yet
 * been set.  Read_config_file will only set options with this value. Options
 * are processed in the following order: command line, user config file,
 * system config file.  Last, fill_default_options is called.
 */

ਖਾਲੀ
initialize_options(Options * options)
{
	memset(options, 'X', ਆਕਾਰ(*options));
	options->host_arg = ਨਿਰਾ;
	options->forward_agent = -1;
	options->forward_agent_sock_ਰਸਤਾ = ਨਿਰਾ;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = ਨਿਰਾ;
	options->stdio_forward_ਪੋਰਟ = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = ਨਿਰਾ;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_ਨਕਾਬ = (ਬਹੁਲਕ_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = ਨਿਰਾ;
	options->hostbased_authentication = -1;
	options->batch_ਬਹੁਲਕ = -1;
	options->check_host_ip = -1;
	options->strict_host_ਕੁੰਜੀ_checking = -1;
	options->compression = -1;
	options->tcp_keep_alive = -1;
	options->ਪੋਰਟ = -1;
	options->ਪਤਾ_family = -1;
	options->connection_attempts = -1;
	options->connection_timeout = -1;
	options->ਸੰਖਿਆ_ਦਾ_password_prompts = -1;
	options->ciphers = ਨਿਰਾ;
	options->macs = ਨਿਰਾ;
	options->kex_algorithms = ਨਿਰਾ;
	options->hostkeyalgorithms = ਨਿਰਾ;
	options->ca_sign_algorithms = ਨਿਰਾ;
	options->ਅੰਕ_ਪਛਾਣ_ਤੱਤ_files = 0;
	memset(options->ਪਛਾਣ_ਤੱਤ_ਕੁੰਜੀਆਂ, 0, ਆਕਾਰ(options->ਪਛਾਣ_ਤੱਤ_ਕੁੰਜੀਆਂ));
	options->ਅੰਕ_certificate_files = 0;
	memset(options->certificates, 0, ਆਕਾਰ(options->certificates));
	options->hostname = ਨਿਰਾ;
	options->host_ਕੁੰਜੀ_alias = ਨਿਰਾ;
	options->proxy_command = ਨਿਰਾ;
	options->jump_user = ਨਿਰਾ;
	options->jump_host = ਨਿਰਾ;
	options->jump_ਪੋਰਟ = -1;
	options->jump_extra = ਨਿਰਾ;
	options->user = ਨਿਰਾ;
	options->escape_char = -1;
	options->ਅੰਕ_system_hostfiles = 0;
	options->ਅੰਕ_user_hostfiles = 0;
	options->local_forwards = ਨਿਰਾ;
	options->ਅੰਕ_local_forwards = 0;
	options->remote_forwards = ਨਿਰਾ;
	options->ਅੰਕ_remote_forwards = 0;
	options->permitted_remote_opens = ਨਿਰਾ;
	options->ਅੰਕ_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_ਸੈੱਟ;
	options->log_level = SYSLOG_LEVEL_NOT_ਸੈੱਟ;
	options->ਅੰਕ_log_verbose = 0;
	options->log_verbose = ਨਿਰਾ;
	options->preferred_authentications = ਨਿਰਾ;
	options->bind_ਪਤਾ = ਨਿਰਾ;
	options->bind_interface = ਨਿਰਾ;
	options->pkcs11_provider = ਨਿਰਾ;
	options->sk_provider = ਨਿਰਾ;
	options->enable_ssh_keysign = -1;
	options->no_host_authentication_for_localhost = -1;
	options->identities_only = -1;
	options->rekey_ਹੱਦਬੰਦੀ = -1;
	options->rekey_interval = -1;
	options->verify_host_ਕੁੰਜੀ_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_ਗਿਣਤੀ_max = -1;
	options->send_env = ਨਿਰਾ;
	options->ਅੰਕ_send_env = 0;
	options->setenv = ਨਿਰਾ;
	options->ਅੰਕ_setenv = 0;
	options->control_ਰਸਤਾ = ਨਿਰਾ;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_ਗਿਆਤ_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = ਨਿਰਾ;
	options->permit_local_command = -1;
	options->remote_command = ਨਿਰਾ;
	options->ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_agent = -1;
	options->ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_agent_lifespan = -1;
	options->ਪਛਾਣ_ਤੱਤ_agent = ਨਿਰਾ;
	options->visual_host_ਕੁੰਜੀ = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = ਨਿਰਾ;
	options->ਅੰਕ_canonical_domains = 0;
	options->ਅੰਕ_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_ਕੁੰਜੀਆਂ = ਨਿਰਾ;
	options->ਅੰਕ_revoked_host_ਕੁੰਜੀਆਂ = 0;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->hostbased_accepted_algos = ਨਿਰਾ;
	options->pubkey_accepted_algos = ਨਿਰਾ;
	options->ਗਿਆਤ_hosts_command = ਨਿਰਾ;
	options->required_rsa_ਮਾਪ = -1;
	options->warn_weak_crypto = -1;
	options->enable_escape_commandline = -1;
	options->obscure_keystroke_timing_interval = -1;
	options->ਟੈਗ = ਨਿਰਾ;
	options->channel_timeouts = ਨਿਰਾ;
	options->ਅੰਕ_channel_timeouts = 0;
	options->ਸੰਸਕਰਣ_addendum = ਨਿਰਾ;
}

/*
 * A petite version of fill_default_options() that just fills the options
 * needed for hostname canonicalization to proceed.
 */
ਖਾਲੀ
fill_default_options_for_canonicalization(Options *options)
{
	ਜੇ (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	ਜੇ (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	ਜੇ (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
}

/*
 * Called after processing other sources of option data, this fills those
 * options for which no value has been specified with their default values.
 */
ਪੂਰਨ
fill_default_options(Options * options)
{
	ਅੱਖਰ *all_cipher, *all_mac, *all_kex, *all_ਕੁੰਜੀ, *all_sig;
	ਅੱਖਰ *def_cipher, *def_mac, *def_kex, *def_ਕੁੰਜੀ, *def_sig;
	ਪੂਰਨ ret = -1, r;

	ਜੇ (options->forward_agent == -1)
		options->forward_agent = 0;
	ਜੇ (options->forward_x11 == -1)
		options->forward_x11 = 0;
	ਜੇ (options->forward_x11_trusted == -1)
		options->forward_x11_trusted = 0;
	ਜੇ (options->forward_x11_timeout == -1)
		options->forward_x11_timeout = 1200;
	/*
	 * stdio forwarding (-W) changes the default for these but we defer
	 * setting the values so they can be overridden.
	 */
	ਜੇ (options->exit_on_forward_failure == -1)
		options->exit_on_forward_failure =
		    options->stdio_forward_host != ਨਿਰਾ ? 1 : 0;
	ਜੇ (options->clear_forwardings == -1)
		options->clear_forwardings =
		    options->stdio_forward_host != ਨਿਰਾ ? 1 : 0;
	ਜੇ (options->clear_forwardings == 1)
		clear_forwardings(options);

	ਜੇ (options->xauth_location == ਨਿਰਾ)
		options->xauth_location = xstrdup(ਰਸਤਾ_XAUTH);
	ਜੇ (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	ਜੇ (options->fwd_opts.streamlocal_bind_ਨਕਾਬ == (ਬਹੁਲਕ_t)-1)
		options->fwd_opts.streamlocal_bind_ਨਕਾਬ = 0177;
	ਜੇ (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	ਜੇ (options->pubkey_authentication == -1)
		options->pubkey_authentication = SSH_PUBKEY_AUTH_ALL;
	ਜੇ (options->gss_authentication == -1)
		options->gss_authentication = 0;
	ਜੇ (options->gss_deleg_creds == -1)
		options->gss_deleg_creds = 0;
	ਜੇ (options->password_authentication == -1)
		options->password_authentication = 1;
	ਜੇ (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	ਜੇ (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	ਜੇ (options->batch_ਬਹੁਲਕ == -1)
		options->batch_ਬਹੁਲਕ = 0;
	ਜੇ (options->check_host_ip == -1)
		options->check_host_ip = 0;
	ਜੇ (options->strict_host_ਕੁੰਜੀ_checking == -1)
		options->strict_host_ਕੁੰਜੀ_checking = SSH_STRICT_HOSTKEY_ASK;
	ਜੇ (options->compression == -1)
		options->compression = 0;
	ਜੇ (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = SSH_KEEPALIVES_TRANSPORT;
	ਜੇ (options->ਪੋਰਟ == -1)
		options->ਪੋਰਟ = 0;	/* Filled in ssh_connect. */
	ਜੇ (options->ਪਤਾ_family == -1)
		options->ਪਤਾ_family = AF_UNSPEC;
	ਜੇ (options->connection_attempts == -1)
		options->connection_attempts = 1;
	ਜੇ (options->ਸੰਖਿਆ_ਦਾ_password_prompts == -1)
		options->ਸੰਖਿਆ_ਦਾ_password_prompts = 3;
	/* options->hostkeyalgorithms, default set in myproposals.h */
	ਜੇ (options->ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_agent == -1) {
		options->ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_agent = 0;
		options->ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_agent_lifespan = 0;
	}
	ਜੇ (options->ਅੰਕ_ਪਛਾਣ_ਤੱਤ_files == 0) {
		ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ_file(options, "~/", ਰਸਤਾ_SSH_CLIENT_ID_RSA, 0);
		ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ_file(options, "~/", ਰਸਤਾ_SSH_CLIENT_ID_ECDSA, 0);
		ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ_file(options, "~/",
		    ਰਸਤਾ_SSH_CLIENT_ID_ECDSA_SK, 0);
		ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ_file(options, "~/",
		    ਰਸਤਾ_SSH_CLIENT_ID_ED25519, 0);
		ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ_file(options, "~/",
		    ਰਸਤਾ_SSH_CLIENT_ID_ED25519_SK, 0);
		ਜੋੜੋ_ਪਛਾਣ_ਤੱਤ_file(options, "~/",
		    ਰਸਤਾ_SSH_CLIENT_ID_MLDSA44_ED25519, 0);
	}
	ਜੇ (options->escape_char == -1)
		options->escape_char = '~';
	ਜੇ (options->ਅੰਕ_system_hostfiles == 0) {
		options->system_hostfiles[options->ਅੰਕ_system_hostfiles++] =
		    xstrdup(ਰਸਤਾ_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->ਅੰਕ_system_hostfiles++] =
		    xstrdup(ਰਸਤਾ_SSH_SYSTEM_HOSTFILE2);
	}
	ਜੇ (options->update_hostkeys == -1) {
		ਜੇ (options->verify_host_ਕੁੰਜੀ_dns <= 0 &&
		    (options->ਅੰਕ_user_hostfiles == 0 ||
		    (options->ਅੰਕ_user_hostfiles == 1 && strcmp(options->
		    user_hostfiles[0], ਰਸਤਾ_SSH_USER_HOSTFILE) == 0)))
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_YES;
		ਨਹੀਂਤਾਂ
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_NO;
	}
	ਜੇ (options->ਅੰਕ_user_hostfiles == 0) {
		options->user_hostfiles[options->ਅੰਕ_user_hostfiles++] =
		    xstrdup(ਰਸਤਾ_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->ਅੰਕ_user_hostfiles++] =
		    xstrdup(ਰਸਤਾ_SSH_USER_HOSTFILE2);
	}
	ਜੇ (options->log_level == SYSLOG_LEVEL_NOT_ਸੈੱਟ)
		options->log_level = SYSLOG_LEVEL_INFO;
	ਜੇ (options->log_facility == SYSLOG_FACILITY_NOT_ਸੈੱਟ)
		options->log_facility = SYSLOG_FACILITY_USER;
	ਜੇ (options->no_host_authentication_for_localhost == -1)
		options->no_host_authentication_for_localhost = 0;
	ਜੇ (options->identities_only == -1)
		options->identities_only = 0;
	ਜੇ (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	ਜੇ (options->rekey_ਹੱਦਬੰਦੀ == -1)
		options->rekey_ਹੱਦਬੰਦੀ = 0;
	ਜੇ (options->rekey_interval == -1)
		options->rekey_interval = 0;
	ਜੇ (options->verify_host_ਕੁੰਜੀ_dns == -1)
		options->verify_host_ਕੁੰਜੀ_dns = 0;
	ਜੇ (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	ਜੇ (options->server_alive_ਗਿਣਤੀ_max == -1)
		options->server_alive_ਗਿਣਤੀ_max = 3;
	ਜੇ (options->control_master == -1)
		options->control_master = 0;
	ਜੇ (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	ਜੇ (options->hash_ਗਿਆਤ_hosts == -1)
		options->hash_ਗਿਆਤ_hosts = 0;
	ਜੇ (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	ਜੇ (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	ਜੇ (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	ਜੇ (options->permit_local_command == -1)
		options->permit_local_command = 0;
	ਜੇ (options->visual_host_ਕੁੰਜੀ == -1)
		options->visual_host_ਕੁੰਜੀ = 0;
	ਜੇ (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	ਜੇ (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	ਜੇ (options->request_tty == -1)
		options->request_tty = REQUEST_TTY_AUTO;
	ਜੇ (options->session_type == -1)
		options->session_type = SESSION_TYPE_DEFAULT;
	ਜੇ (options->stdin_null == -1)
		options->stdin_null = 0;
	ਜੇ (options->fork_after_authentication == -1)
		options->fork_after_authentication = 0;
	ਜੇ (options->proxy_use_fdpass == -1)
		options->proxy_use_fdpass = 0;
	ਜੇ (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	ਜੇ (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	ਜੇ (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
	ਜੇ (options->fingerprint_hash == -1)
		options->fingerprint_hash = SSH_FP_HASH_DEFAULT;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_SK_ਅੰਦਰੂਨੀ
	ਜੇ (options->sk_provider == ਨਿਰਾ)
		options->sk_provider = xstrdup("internal");
#ਨਹੀਂਤਾਂ
	ਜੇ (options->sk_provider == ਨਿਰਾ)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
#ਜੇ_ਅੰਤ
	ਜੇ (options->required_rsa_ਮਾਪ == -1)
		options->required_rsa_ਮਾਪ = SSH_RSA_MINIMUM_MODULUS_ਮਾਪ;
	ਜੇ (options->warn_weak_crypto == -1)
		options->warn_weak_crypto = 1;
	ਜੇ (options->enable_escape_commandline == -1)
		options->enable_escape_commandline = 0;
	ਜੇ (options->obscure_keystroke_timing_interval == -1) {
		options->obscure_keystroke_timing_interval =
		    SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
	}

	/* Expand KEX name lists */
	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_ਕੁੰਜੀ = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = ਮੇਲ_filter_allowlist(KEX_CLIENT_ENCRYPT, all_cipher);
	def_mac = ਮੇਲ_filter_allowlist(KEX_CLIENT_MAC, all_mac);
	def_kex = ਮੇਲ_filter_allowlist(KEX_CLIENT_KEX, all_kex);
	def_ਕੁੰਜੀ = ਮੇਲ_filter_allowlist(KEX_DEFAULT_PK_ALG, all_ਕੁੰਜੀ);
	def_sig = ਮੇਲ_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ASSEMBLE(what, defaults, all) \
	ਕਰੋ { \
		ਜੇ ((r = kex_assemble_ਨਾਂ(&options->what, \
		    defaults, all)) != 0) { \
			error_fr(r, "%s", #what); \
			ਜਾਓ fail; \
		} \
	} ਜਦੋਂ (0)
	options->kex_algorithms_ਸੈੱਟ = options->kex_algorithms != ਨਿਰਾ;
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostbased_accepted_algos, def_ਕੁੰਜੀ, all_ਕੁੰਜੀ);
	ASSEMBLE(pubkey_accepted_algos, def_ਕੁੰਜੀ, all_ਕੁੰਜੀ);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ ASSEMBLE

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CLEAR_ON_NONE(v) \
	ਕਰੋ { \
		ਜੇ (option_clear_or_none(v)) { \
			ਮੁਕਤ(v); \
			v = ਨਿਰਾ; \
		} \
	} ਜਦੋਂ(0)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CLEAR_ON_NONE_ARRAY(v, nv, none) \
	ਕਰੋ { \
		ਜੇ (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			ਮੁਕਤ(options->v[0]); \
			ਮੁਕਤ(options->v); \
			options->v = ਨਿਰਾ; \
			options->nv = 0; \
		} \
	} ਜਦੋਂ (0)
	CLEAR_ON_NONE(options->local_command);
	CLEAR_ON_NONE(options->remote_command);
	CLEAR_ON_NONE(options->proxy_command);
	CLEAR_ON_NONE(options->control_ਰਸਤਾ);
	CLEAR_ON_NONE(options->pkcs11_provider);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->ਗਿਆਤ_hosts_command);
	CLEAR_ON_NONE_ARRAY(channel_timeouts, ਅੰਕ_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(revoked_host_ਕੁੰਜੀਆਂ, ਅੰਕ_revoked_host_ਕੁੰਜੀਆਂ, "none");
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CLEAR_ON_NONE
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ CLEAR_ON_NONE_ARRAY
	ਜੇ (options->jump_host != ਨਿਰਾ &&
	    strcmp(options->jump_host, "none") == 0 &&
	    options->jump_ਪੋਰਟ == 0 && options->jump_user == ਨਿਰਾ) {
		ਮੁਕਤ(options->jump_host);
		options->jump_host = ਨਿਰਾ;
	}
	ਜੇ (options->ਅੰਕ_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		ਮੁਕਤ(options->permitted_cnames[0].ਸਰੋਤ_list);
		ਮੁਕਤ(options->permitted_cnames[0].ਨਿਸ਼ਾਨਾ_list);
		memset(options->permitted_cnames, '\0',
		    ਆਕਾਰ(*options->permitted_cnames));
		options->ਅੰਕ_permitted_cnames = 0;
	}
	/* options->identity_agent distinguishes NULL from 'none' */
	/* options->user will be set in the main program if appropriate */
	/* options->hostname will be set in the main program if appropriate */
	/* options->host_key_alias should not be set by default */
	/* options->preferred_authentications will be set in ssh */

	/* success */
	ret = 0;
 fail:
	ਮੁਕਤ(all_cipher);
	ਮੁਕਤ(all_mac);
	ਮੁਕਤ(all_kex);
	ਮੁਕਤ(all_ਕੁੰਜੀ);
	ਮੁਕਤ(all_sig);
	ਮੁਕਤ(def_cipher);
	ਮੁਕਤ(def_mac);
	ਮੁਕਤ(def_kex);
	ਮੁਕਤ(def_ਕੁੰਜੀ);
	ਮੁਕਤ(def_sig);
	ਵਾਪਸ ret;
}

ਖਾਲੀ
free_options(Options *o)
{
	ਪੂਰਨ i;

	ਜੇ (o == ਨਿਰਾ)
		ਵਾਪਸ;

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ FREE_ARRAY(type, n, a) \
	ਕਰੋ { \
		type _i; \
		ਲਈ (_i = 0; _i < (n); _i++) \
			ਮੁਕਤ((a)[_i]); \
	} ਜਦੋਂ (0)

	ਮੁਕਤ(o->forward_agent_sock_ਰਸਤਾ);
	ਮੁਕਤ(o->xauth_location);
	FREE_ARRAY(u_int, o->ਅੰਕ_log_verbose, o->log_verbose);
	ਮੁਕਤ(o->log_verbose);
	ਮੁਕਤ(o->ciphers);
	ਮੁਕਤ(o->macs);
	ਮੁਕਤ(o->hostkeyalgorithms);
	ਮੁਕਤ(o->kex_algorithms);
	ਮੁਕਤ(o->ca_sign_algorithms);
	ਮੁਕਤ(o->hostname);
	ਮੁਕਤ(o->host_ਕੁੰਜੀ_alias);
	ਮੁਕਤ(o->proxy_command);
	ਮੁਕਤ(o->user);
	FREE_ARRAY(u_int, o->ਅੰਕ_system_hostfiles, o->system_hostfiles);
	FREE_ARRAY(u_int, o->ਅੰਕ_user_hostfiles, o->user_hostfiles);
	ਮੁਕਤ(o->preferred_authentications);
	ਮੁਕਤ(o->bind_ਪਤਾ);
	ਮੁਕਤ(o->bind_interface);
	ਮੁਕਤ(o->pkcs11_provider);
	ਮੁਕਤ(o->sk_provider);
	ਲਈ (i = 0; i < o->ਅੰਕ_ਪਛਾਣ_ਤੱਤ_files; i++) {
		ਮੁਕਤ(o->ਪਛਾਣ_ਤੱਤ_files[i]);
		sshkey_free(o->ਪਛਾਣ_ਤੱਤ_ਕੁੰਜੀਆਂ[i]);
	}
	ਲਈ (i = 0; i < o->ਅੰਕ_certificate_files; i++) {
		ਮੁਕਤ(o->certificate_files[i]);
		sshkey_free(o->certificates[i]);
	}
	ਮੁਕਤ(o->ਪਛਾਣ_ਤੱਤ_agent);
	ਲਈ (i = 0; i < o->ਅੰਕ_local_forwards; i++) {
		ਮੁਕਤ(o->local_forwards[i].listen_host);
		ਮੁਕਤ(o->local_forwards[i].listen_ਰਸਤਾ);
		ਮੁਕਤ(o->local_forwards[i].connect_host);
		ਮੁਕਤ(o->local_forwards[i].connect_ਰਸਤਾ);
	}
	ਮੁਕਤ(o->local_forwards);
	ਲਈ (i = 0; i < o->ਅੰਕ_remote_forwards; i++) {
		ਮੁਕਤ(o->remote_forwards[i].listen_host);
		ਮੁਕਤ(o->remote_forwards[i].listen_ਰਸਤਾ);
		ਮੁਕਤ(o->remote_forwards[i].connect_host);
		ਮੁਕਤ(o->remote_forwards[i].connect_ਰਸਤਾ);
	}
	ਮੁਕਤ(o->remote_forwards);
	ਮੁਕਤ(o->stdio_forward_host);
	FREE_ARRAY(u_int, o->ਅੰਕ_send_env, o->send_env);
	ਮੁਕਤ(o->send_env);
	FREE_ARRAY(u_int, o->ਅੰਕ_setenv, o->setenv);
	ਮੁਕਤ(o->setenv);
	ਮੁਕਤ(o->control_ਰਸਤਾ);
	ਮੁਕਤ(o->local_command);
	ਮੁਕਤ(o->remote_command);
	FREE_ARRAY(ਪੂਰਨ, o->ਅੰਕ_canonical_domains, o->canonical_domains);
	ਲਈ (i = 0; i < o->ਅੰਕ_permitted_cnames; i++) {
		ਮੁਕਤ(o->permitted_cnames[i].ਸਰੋਤ_list);
		ਮੁਕਤ(o->permitted_cnames[i].ਨਿਸ਼ਾਨਾ_list);
	}
	FREE_ARRAY(u_int, o->ਅੰਕ_revoked_host_ਕੁੰਜੀਆਂ, o->revoked_host_ਕੁੰਜੀਆਂ);
	ਮੁਕਤ(o->revoked_host_ਕੁੰਜੀਆਂ);
	ਮੁਕਤ(o->hostbased_accepted_algos);
	ਮੁਕਤ(o->pubkey_accepted_algos);
	ਮੁਕਤ(o->jump_user);
	ਮੁਕਤ(o->jump_host);
	ਮੁਕਤ(o->jump_extra);
	ਮੁਕਤ(o->ignored_unknown);
	explicit_bzero(o, ਆਕਾਰ(*o));
#ਪਰਿਭਾਸ਼ਾ_ਰੱਦ FREE_ARRAY
}

ਬਣਤਰ fwdarg {
	ਅੱਖਰ *arg;
	ਪੂਰਨ ispath;
};

/*
 * parse_fwd_field
 * parses the next field in a port forwarding specification.
 * sets fwd to the parsed field and advances p past the colon
 * or sets it to NULL at end of string.
 * returns 0 on success, else non-zero.
 */
ਸਥਿਰ ਪੂਰਨ
parse_fwd_ਖੇਤਰ(ਅੱਖਰ **p, ਬਣਤਰ fwdarg *fwd)
{
	ਅੱਖਰ *ep, *cp = *p;
	ਪੂਰਨ ispath = 0;

	ਜੇ (*cp == '\0') {
		*p = ਨਿਰਾ;
		ਵਾਪਸ -1;	/* end of string */
	}

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	ਜੇ (*cp == '[') {
		/* find matching ']' */
		ਲਈ (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++) {
			ਜੇ (*ep == '/')
				ispath = 1;
		}
		/* no matching ']' or not at end of field. */
		ਜੇ (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			ਵਾਪਸ -1;
		/* NUL terminate the field and advance p past the colon */
		*ep++ = '\0';
		ਜੇ (*ep != '\0')
			*ep++ = '\0';
		fwd->arg = cp + 1;
		fwd->ispath = ispath;
		*p = ep;
		ਵਾਪਸ 0;
	}

	ਲਈ (cp = *p; *cp != '\0'; cp++) {
		ਚੋਣ (*cp) {
		ਹਾਲਤ '\\':
			memmove(cp, cp + 1, ਲੜੀ_ਲੰਬਾਈ(cp + 1) + 1);
			ਜੇ (*cp == '\0')
				ਵਾਪਸ -1;
			ਰੋਕੋ;
		ਹਾਲਤ '/':
			ispath = 1;
			ਰੋਕੋ;
		ਹਾਲਤ ':':
			*cp++ = '\0';
			ਜਾਓ ਪੂਰਾ;
		}
	}
ਪੂਰਾ:
	fwd->arg = *p;
	fwd->ispath = ispath;
	*p = cp;
	ਵਾਪਸ 0;
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
ਪੂਰਨ
parse_forward(ਬਣਤਰ Forward *fwd, ਅਚਲ ਅੱਖਰ *fwdspec, ਪੂਰਨ dynamicfwd, ਪੂਰਨ remotefwd)
{
	ਬਣਤਰ fwdarg fwdargs[4];
	ਅੱਖਰ *p, *cp;
	ਪੂਰਨ i, err;

	memset(fwd, 0, ਆਕਾਰ(*fwd));
	memset(fwdargs, 0, ਆਕਾਰ(fwdargs));

	/*
	 * We expand environment variables before checking if we think they're
	 * paths so that if ${VAR} expands to a fully qualified path it is
	 * treated as a path.
	 */
	cp = p = dollar_expand(&err, fwdspec);
	ਜੇ (p == ਨਿਰਾ || err)
		ਵਾਪਸ 0;

	/* skip leading spaces */
	ਜਦੋਂ (ਖਾਲੀ_ਥਾਂ_ਹੈ((u_char)*cp))
		cp++;

	ਲਈ (i = 0; i < 4; ++i) {
		ਜੇ (parse_fwd_ਖੇਤਰ(&cp, &fwdargs[i]) != 0)
			ਰੋਕੋ;
	}

	/* Check for trailing garbage */
	ਜੇ (cp != ਨਿਰਾ && *cp != '\0') {
		i = 0;	/* failure */
	}

	ਚੋਣ (i) {
	ਹਾਲਤ 1:
		ਜੇ (fwdargs[0].ispath) {
			fwd->listen_ਰਸਤਾ = xstrdup(fwdargs[0].arg);
			fwd->listen_ਪੋਰਟ = ਪੋਰਟ_STREAMLOCAL;
		} ਨਹੀਂਤਾਂ {
			fwd->listen_host = ਨਿਰਾ;
			fwd->listen_ਪੋਰਟ = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		ਰੋਕੋ;

	ਹਾਲਤ 2:
		ਜੇ (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_ਰਸਤਾ = xstrdup(fwdargs[0].arg);
			fwd->listen_ਪੋਰਟ = ਪੋਰਟ_STREAMLOCAL;
			fwd->connect_ਰਸਤਾ = xstrdup(fwdargs[1].arg);
			fwd->connect_ਪੋਰਟ = ਪੋਰਟ_STREAMLOCAL;
		} ਨਹੀਂਤਾਂ ਜੇ (fwdargs[1].ispath) {
			fwd->listen_host = ਨਿਰਾ;
			fwd->listen_ਪੋਰਟ = a2port(fwdargs[0].arg);
			fwd->connect_ਰਸਤਾ = xstrdup(fwdargs[1].arg);
			fwd->connect_ਪੋਰਟ = ਪੋਰਟ_STREAMLOCAL;
		} ਨਹੀਂਤਾਂ {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_ਪੋਰਟ = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		ਰੋਕੋ;

	ਹਾਲਤ 3:
		ਜੇ (fwdargs[0].ispath) {
			fwd->listen_ਰਸਤਾ = xstrdup(fwdargs[0].arg);
			fwd->listen_ਪੋਰਟ = ਪੋਰਟ_STREAMLOCAL;
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_ਪੋਰਟ = a2port(fwdargs[2].arg);
		} ਨਹੀਂਤਾਂ ਜੇ (fwdargs[2].ispath) {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_ਪੋਰਟ = a2port(fwdargs[1].arg);
			fwd->connect_ਰਸਤਾ = xstrdup(fwdargs[2].arg);
			fwd->connect_ਪੋਰਟ = ਪੋਰਟ_STREAMLOCAL;
		} ਨਹੀਂਤਾਂ {
			fwd->listen_host = ਨਿਰਾ;
			fwd->listen_ਪੋਰਟ = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_ਪੋਰਟ = a2port(fwdargs[2].arg);
		}
		ਰੋਕੋ;

	ਹਾਲਤ 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_ਪੋਰਟ = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_ਪੋਰਟ = a2port(fwdargs[3].arg);
		ਰੋਕੋ;
	ਮੂਲ:
		i = 0; /* failure */
	}

	ਮੁਕਤ(p);

	ਜੇ (dynamicfwd) {
		ਜੇ (!(i == 1 || i == 2))
			ਜਾਓ fail_free;
	} ਨਹੀਂਤਾਂ {
		ਜੇ (!(i == 3 || i == 4)) {
			ਜੇ (fwd->connect_ਰਸਤਾ == ਨਿਰਾ &&
			    fwd->listen_ਰਸਤਾ == ਨਿਰਾ)
				ਜਾਓ fail_free;
		}
		ਜੇ (fwd->connect_ਪੋਰਟ <= 0 && fwd->connect_ਰਸਤਾ == ਨਿਰਾ)
			ਜਾਓ fail_free;
	}

	ਜੇ ((fwd->listen_ਪੋਰਟ < 0 && fwd->listen_ਰਸਤਾ == ਨਿਰਾ) ||
	    (!remotefwd && fwd->listen_ਪੋਰਟ == 0))
		ਜਾਓ fail_free;
	ਜੇ (fwd->connect_host != ਨਿਰਾ &&
	    ਲੜੀ_ਲੰਬਾਈ(fwd->connect_host) >= NI_MAXHOST)
		ਜਾਓ fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	ਜੇ (fwd->connect_ਰਸਤਾ != ਨਿਰਾ &&
	    ਲੜੀ_ਲੰਬਾਈ(fwd->connect_ਰਸਤਾ) >= ਰਸਤਾ_MAX_SUN)
		ਜਾਓ fail_free;
	ਜੇ (fwd->listen_host != ਨਿਰਾ &&
	    ਲੜੀ_ਲੰਬਾਈ(fwd->listen_host) >= NI_MAXHOST)
		ਜਾਓ fail_free;
	ਜੇ (fwd->listen_ਰਸਤਾ != ਨਿਰਾ &&
	    ਲੜੀ_ਲੰਬਾਈ(fwd->listen_ਰਸਤਾ) >= ਰਸਤਾ_MAX_SUN)
		ਜਾਓ fail_free;

	ਵਾਪਸ (i);

 fail_free:
	ਮੁਕਤ(fwd->connect_host);
	fwd->connect_host = ਨਿਰਾ;
	ਮੁਕਤ(fwd->connect_ਰਸਤਾ);
	fwd->connect_ਰਸਤਾ = ਨਿਰਾ;
	ਮੁਕਤ(fwd->listen_host);
	fwd->listen_host = ਨਿਰਾ;
	ਮੁਕਤ(fwd->listen_ਰਸਤਾ);
	fwd->listen_ਰਸਤਾ = ਨਿਰਾ;
	ਵਾਪਸ (0);
}

ਪੂਰਨ
ssh_valid_hostname(ਅਚਲ ਅੱਖਰ *s)
{
	ਮਾਪ_t i;

	ਜੇ (*s == '-')
		ਵਾਪਸ 0;
	ਲਈ (i = 0; s[i] != 0; i++) {
		ਜੇ (strchr("'`\"$\\;&<>|(){},", s[i]) != ਨਿਰਾ ||
		    ਖਾਲੀ_ਥਾਂ_ਹੈ((u_char)s[i]) || iscntrl((u_char)s[i]))
			ਵਾਪਸ 0;
	}
	ਵਾਪਸ 1;
}

ਪੂਰਨ
ssh_valid_ruser(ਅਚਲ ਅੱਖਰ *s)
{
	ਮਾਪ_t i;

	ਜੇ (*s == '-')
		ਵਾਪਸ 0;
	ਲਈ (i = 0; s[i] != 0; i++) {
		ਜੇ (iscntrl((u_char)s[i]))
			ਵਾਪਸ 0;
		ਜੇ (strchr("'`\";&<>|(){}$\\", s[i]) != ਨਿਰਾ)
			ਵਾਪਸ 0;
		/* Disallow '-' after whitespace */
		ਜੇ (ਖਾਲੀ_ਥਾਂ_ਹੈ((u_char)s[i]) && s[i + 1] == '-')
			ਵਾਪਸ 0;
	}
	ਵਾਪਸ 1;
}

ਪੂਰਨ
parse_jump(ਅਚਲ ਅੱਖਰ *s, Options *o, ਪੂਰਨ strict, ਪੂਰਨ ਸਰਗਰਮ)
{
	ਅੱਖਰ *orig = ਨਿਰਾ, *sdup = ਨਿਰਾ, *cp;
	ਅੱਖਰ *tmp_user = ਨਿਰਾ, *tmp_host = ਨਿਰਾ, *host = ਨਿਰਾ, *user = ਨਿਰਾ;
	ਪੂਰਨ r, ret = -1, tmp_ਪੋਰਟ = -1, ਪੋਰਟ = -1, ਪਹਿਲਾ = 1;

	ਜੇ (strcasecmp(s, "none") == 0) {
		ਜੇ (ਸਰਗਰਮ && o->jump_host == ਨਿਰਾ) {
			o->jump_host = xstrdup("none");
			o->jump_ਪੋਰਟ = 0;
		}
		ਵਾਪਸ 0;
	}

	orig = xstrdup(s);
	ਜੇ ((cp = strchr(orig, '#')) != ਨਿਰਾ)
		*cp = '\0';
	rtrim(orig);

	ਸਰਗਰਮ &= o->proxy_command == ਨਿਰਾ && o->jump_host == ਨਿਰਾ;
	sdup = xstrdup(orig);
	ਕਰੋ {
		/* Work backwards through string */
		ਜੇ ((cp = strrchr(sdup, ',')) == ਨਿਰਾ)
			cp = sdup; /*ਆਖਰੀ*/
		ਨਹੀਂਤਾਂ
			*cp++ = '\0';

		r = parse_ssh_uri(cp, &tmp_user, &tmp_host, &tmp_ਪੋਰਟ);
		ਜੇ (r == -1 || (r == 1 && parse_user_host_ਪੋਰਟ(cp,
		    &tmp_user, &tmp_host, &tmp_ਪੋਰਟ) != 0))
			ਜਾਓ ਬਾਹਰਲਾ; /* error already logged */
		ਜੇ (strict) {
			ਜੇ (!ssh_valid_hostname(tmp_host)) {
				error_f("invalid hostname \"%s\"", tmp_host);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
			ਜੇ (tmp_user != ਨਿਰਾ && !ssh_valid_ruser(tmp_user)) {
				error_f("invalid username \"%s\"", tmp_user);
				ਜਾਓ ਬਾਹਰਲਾ;
			}
		}
		ਜੇ (ਪਹਿਲਾ) {
			user = tmp_user;
			host = tmp_host;
			ਪੋਰਟ = tmp_ਪੋਰਟ;
			tmp_user = tmp_host = ਨਿਰਾ; /* transferred */
		}
		ਪਹਿਲਾ = 0; /* only check syntax for subsequent hosts */
		ਮੁਕਤ(tmp_user);
		ਮੁਕਤ(tmp_host);
		tmp_user = tmp_host = ਨਿਰਾ;
		tmp_ਪੋਰਟ = -1;
	} ਜਦੋਂ (cp != sdup);

	/* success */
	ਜੇ (ਸਰਗਰਮ) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_ਪੋਰਟ = ਪੋਰਟ;
		o->proxy_command = xstrdup("none");
		user = host = ਨਿਰਾ; /* transferred */
		ਜੇ (orig != ਨਿਰਾ && (cp = strrchr(orig, ',')) != ਨਿਰਾ) {
			o->jump_extra = xstrdup(orig);
			o->jump_extra[cp - orig] = '\0';
		}
	}
	ret = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(orig);
	ਮੁਕਤ(sdup);
	ਮੁਕਤ(tmp_user);
	ਮੁਕਤ(tmp_host);
	ਮੁਕਤ(user);
	ਮੁਕਤ(host);
	ਵਾਪਸ ret;
}

ਪੂਰਨ
parse_ssh_uri(ਅਚਲ ਅੱਖਰ *uri, ਅੱਖਰ **userp, ਅੱਖਰ **hostp, ਪੂਰਨ *portp)
{
	ਅੱਖਰ *user = ਨਿਰਾ, *host = ਨਿਰਾ, *ਰਸਤਾ = ਨਿਰਾ;
	ਪੂਰਨ r, ਪੋਰਟ;

	r = parse_uri("ssh", uri, &user, &host, &ਪੋਰਟ, &ਰਸਤਾ);
	ਜੇ (r == 0 && ਰਸਤਾ != ਨਿਰਾ)
		r = -1;		/* path not allowed */
	ਜੇ (r == 0) {
		ਜੇ (userp != ਨਿਰਾ) {
			*userp = user;
			user = ਨਿਰਾ;
		}
		ਜੇ (hostp != ਨਿਰਾ) {
			*hostp = host;
			host = ਨਿਰਾ;
		}
		ਜੇ (portp != ਨਿਰਾ)
			*portp = ਪੋਰਟ;
	}
	ਮੁਕਤ(user);
	ਮੁਕਤ(host);
	ਮੁਕਤ(ਰਸਤਾ);
	ਵਾਪਸ r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
fmt_multistate_int(ਪੂਰਨ val, ਅਚਲ ਬਣਤਰ multistate *m)
{
	u_int i;

	ਲਈ (i = 0; m[i].ਕੁੰਜੀ != ਨਿਰਾ; i++) {
		ਜੇ (m[i].ਮੁੱਲ == val)
			ਵਾਪਸ m[i].ਕੁੰਜੀ;
	}
	ਵਾਪਸ "UNKNOWN";
}

ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
fmt_intarg(OpCodes ਕੋਡ, ਪੂਰਨ val)
{
	ਜੇ (val == -1)
		ਵਾਪਸ "unset";
	ਚੋਣ (ਕੋਡ) {
	ਹਾਲਤ o_ਪਤਾ_Family:
		ਵਾਪਸ fmt_multistate_int(val, multistate_addressfamily);
	ਹਾਲਤ oCompression:
		ਵਾਪਸ fmt_multistate_int(val, multistate_compression);
	ਹਾਲਤ o_Verify_Host_ਕੁੰਜੀ_DNS:
	ਹਾਲਤ oUpdateHostkeys:
		ਵਾਪਸ fmt_multistate_int(val, multistate_yesnoask);
	ਹਾਲਤ o_Strict_Host_ਕੁੰਜੀ_Checking:
		ਵਾਪਸ fmt_multistate_int(val, multistate_strict_hostkey);
	ਹਾਲਤ oControlMaster:
		ਵਾਪਸ fmt_multistate_int(val, multistate_controlmaster);
	ਹਾਲਤ oTunnel:
		ਵਾਪਸ fmt_multistate_int(val, multistate_tunnel);
	ਹਾਲਤ oRequestTTY:
		ਵਾਪਸ fmt_multistate_int(val, multistate_requesttty);
	ਹਾਲਤ oSessionType:
		ਵਾਪਸ fmt_multistate_int(val, multistate_sessiontype);
	ਹਾਲਤ oCanonicalizeHostname:
		ਵਾਪਸ fmt_multistate_int(val, multistate_canonicalizehostname);
	ਹਾਲਤ o_ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_Agent:
		ਵਾਪਸ fmt_multistate_int(val, multistate_yesnoaskconfirm);
	ਹਾਲਤ oPubkeyAuthentication:
		ਵਾਪਸ fmt_multistate_int(val, multistate_pubkey_auth);
	ਹਾਲਤ oTCPKeepAlive:
		ਵਾਪਸ fmt_multistate_int(val, multistate_keepalives);
	ਹਾਲਤ oFingerprintHash:
		ਵਾਪਸ ssh_digest_alg_name(val);
	ਮੂਲ:
		ਚੋਣ (val) {
		ਹਾਲਤ 0:
			ਵਾਪਸ "no";
		ਹਾਲਤ 1:
			ਵਾਪਸ "yes";
		ਮੂਲ:
			ਵਾਪਸ "UNKNOWN";
		}
	}
}

ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
lookup_opcode_name(OpCodes ਕੋਡ)
{
	u_int i;

	ਲਈ (i = 0; keywords[i].name != ਨਿਰਾ; i++)
		ਜੇ (keywords[i].opcode == ਕੋਡ)
			ਵਾਪਸ(keywords[i].name);
	ਵਾਪਸ "UNKNOWN";
}

ਸਥਿਰ ਖਾਲੀ
dump_cfg_int(OpCodes ਕੋਡ, ਪੂਰਨ val)
{
	ਜੇ (ਕੋਡ == oObscureKeystrokeTiming) {
		ਜੇ (val == 0) {
			ਲਿਖੋ("%s no\n", lookup_opcode_name(ਕੋਡ));
			ਵਾਪਸ;
		} ਨਹੀਂਤਾਂ ਜੇ (val == SSH_KEYSTROKE_DEFAULT_INTERVAL_MS) {
			ਲਿਖੋ("%s yes\n", lookup_opcode_name(ਕੋਡ));
			ਵਾਪਸ;
		}
		/* FALLTHROUGH */
	}
	ਲਿਖੋ("%s %d\n", lookup_opcode_name(ਕੋਡ), val);
}

ਸਥਿਰ ਖਾਲੀ
dump_cfg_fmtint(OpCodes ਕੋਡ, ਪੂਰਨ val)
{
	ਲਿਖੋ("%s %s\n", lookup_opcode_name(ਕੋਡ), fmt_intarg(ਕੋਡ, val));
}

ਸਥਿਰ ਖਾਲੀ
dump_cfg_string(OpCodes ਕੋਡ, ਅਚਲ ਅੱਖਰ *val)
{
	ਜੇ (val == ਨਿਰਾ)
		ਵਾਪਸ;
	ਲਿਖੋ("%s %s\n", lookup_opcode_name(ਕੋਡ), val);
}

ਸਥਿਰ ਖਾਲੀ
dump_cfg_strarray(OpCodes ਕੋਡ, u_int ਗਿਣਤੀ_2, ਅੱਖਰ **vals)
{
	u_int i;

	ਲਈ (i = 0; i < ਗਿਣਤੀ_2; i++)
		ਲਿਖੋ("%s %s\n", lookup_opcode_name(ਕੋਡ), vals[i]);
}

ਸਥਿਰ ਖਾਲੀ
dump_cfg_strarray_oneline(OpCodes ਕੋਡ, u_int ਗਿਣਤੀ_2, ਅੱਖਰ **vals)
{
	u_int i;

	ਲਿਖੋ("%s", lookup_opcode_name(ਕੋਡ));
	ਜੇ (ਗਿਣਤੀ_2 == 0)
		ਲਿਖੋ(" none");
	ਲਈ (i = 0; i < ਗਿਣਤੀ_2; i++)
		ਲਿਖੋ(" %s",  vals[i]);
	ਲਿਖੋ("\n");
}

ਸਥਿਰ ਖਾਲੀ
dump_cfg_forwards(OpCodes ਕੋਡ, u_int ਗਿਣਤੀ_2, ਅਚਲ ਬਣਤਰ Forward *fwds)
{
	ਅਚਲ ਬਣਤਰ Forward *fwd;
	u_int i;

	/* oDynamicForward */
	ਲਈ (i = 0; i < ਗਿਣਤੀ_2; i++) {
		fwd = &fwds[i];
		ਜੇ (ਕੋਡ == oDynamicForward && fwd->connect_host != ਨਿਰਾ &&
		    strcmp(fwd->connect_host, "socks") != 0)
			ਜਾਰੀ;
		ਜੇ (ਕੋਡ == oLocalForward && fwd->connect_host != ਨਿਰਾ &&
		    strcmp(fwd->connect_host, "socks") == 0)
			ਜਾਰੀ;
		ਲਿਖੋ("%s", lookup_opcode_name(ਕੋਡ));
		ਜੇ (fwd->listen_ਪੋਰਟ == ਪੋਰਟ_STREAMLOCAL)
			ਲਿਖੋ(" %s", fwd->listen_ਰਸਤਾ);
		ਨਹੀਂਤਾਂ ਜੇ (fwd->listen_host == ਨਿਰਾ)
			ਲਿਖੋ(" %d", fwd->listen_ਪੋਰਟ);
		ਨਹੀਂਤਾਂ {
			ਲਿਖੋ(" [%s]:%d",
			    fwd->listen_host, fwd->listen_ਪੋਰਟ);
		}
		ਜੇ (ਕੋਡ != oDynamicForward) {
			ਜੇ (fwd->connect_ਪੋਰਟ == ਪੋਰਟ_STREAMLOCAL)
				ਲਿਖੋ(" %s", fwd->connect_ਰਸਤਾ);
			ਨਹੀਂਤਾਂ ਜੇ (fwd->connect_host == ਨਿਰਾ)
				ਲਿਖੋ(" %d", fwd->connect_ਪੋਰਟ);
			ਨਹੀਂਤਾਂ {
				ਲਿਖੋ(" [%s]:%d",
				    fwd->connect_host, fwd->connect_ਪੋਰਟ);
			}
		}
		ਲਿਖੋ("\n");
	}
}

ਖਾਲੀ
dump_client_config(Options *o, ਅਚਲ ਅੱਖਰ *host)
{
	ਪੂਰਨ i, r;
	ਅੱਖਰ buf[8], *all_ਕੁੰਜੀ;

	/*
	 * Expand HostKeyAlgorithms name lists. This isn't handled in
	 * fill_default_options() like the other algorithm lists because
	 * the host key algorithms are by default dynamically chosen based
	 * on the host's keys found in known_hosts.
	 */
	all_ਕੁੰਜੀ = sshkey_alg_list(0, 0, 1, ',');
	ਜੇ ((r = kex_assemble_ਨਾਂ(&o->hostkeyalgorithms, kex_default_pk_alg(),
	    all_ਕੁੰਜੀ)) != 0)
		fatal_fr(r, "expand HostKeyAlgorithms");
	ਮੁਕਤ(all_ਕੁੰਜੀ);

	/* Most interesting options first: user, host, port */
	dump_cfg_string(oHost, o->host_arg);
	dump_cfg_string(oUser, o->user);
	dump_cfg_string(oHostname, host);
	dump_cfg_int(o_ਪੋਰਟ, o->ਪੋਰਟ);

	/* Flag options */
	dump_cfg_fmtint(o_ਪਤਾ_Family, o->ਪਤਾ_family);
	dump_cfg_fmtint(o_Batch_ਬਹੁਲਕ, o->batch_ਬਹੁਲਕ);
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
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ GSSAPI
	dump_cfg_fmtint(oGssAuthentication, o->gss_authentication);
	dump_cfg_fmtint(oGssDelegateCreds, o->gss_deleg_creds);
#ਜੇ_ਅੰਤ /* GSSAPI */
	dump_cfg_fmtint(o_Hash_ਗਿਆਤ_Hosts, o->hash_ਗਿਆਤ_hosts);
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
	dump_cfg_fmtint(o_ਧਾਰਾ_Local_Bind_Unlink, o->fwd_opts.streamlocal_bind_unlink);
	dump_cfg_fmtint(o_Strict_Host_ਕੁੰਜੀ_Checking, o->strict_host_ਕੁੰਜੀ_checking);
	dump_cfg_fmtint(oTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(oTunnel, o->tun_open);
	dump_cfg_fmtint(o_Verify_Host_ਕੁੰਜੀ_DNS, o->verify_host_ਕੁੰਜੀ_dns);
	dump_cfg_fmtint(o_Visual_Host_ਕੁੰਜੀ, o->visual_host_ਕੁੰਜੀ);
	dump_cfg_fmtint(oUpdateHostkeys, o->update_hostkeys);
	dump_cfg_fmtint(oEnableEscapeCommandline, o->enable_escape_commandline);
	dump_cfg_fmtint(oWarnWeakCrypto, o->warn_weak_crypto);

	/* Integer options */
	dump_cfg_int(oCanonicalizeMaxDots, o->canonicalize_max_dots);
	dump_cfg_int(oConnectionAttempts, o->connection_attempts);
	dump_cfg_int(oForwardX11Timeout, o->forward_x11_timeout);
	dump_cfg_int(o_ਸੰਖਿਆ_ਦਾ_Password_Prompts, o->ਸੰਖਿਆ_ਦਾ_password_prompts);
	dump_cfg_int(o_Server_Alive_ਗਿਣਤੀ_Max, o->server_alive_ਗਿਣਤੀ_max);
	dump_cfg_int(oServerAliveInterval, o->server_alive_interval);
	dump_cfg_int(oRequiredRSASize, o->required_rsa_ਮਾਪ);
	dump_cfg_int(oObscureKeystrokeTiming,
	    o->obscure_keystroke_timing_interval);

	/* String options */
	dump_cfg_string(o_Bind_ਪਤਾ, o->bind_ਪਤਾ);
	dump_cfg_string(oBindInterface, o->bind_interface);
	dump_cfg_string(oCiphers, o->ciphers);
	dump_cfg_string(o_Control_ਰਸਤਾ, o->control_ਰਸਤਾ);
	dump_cfg_string(o_Host_ਕੁੰਜੀ_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(o_Host_ਕੁੰਜੀ_Alias, o->host_ਕੁੰਜੀ_alias);
	dump_cfg_string(oHostbasedAcceptedAlgorithms, o->hostbased_accepted_algos);
	dump_cfg_string(o_ਪਛਾਣ_ਤੱਤ_Agent, o->ਪਛਾਣ_ਤੱਤ_agent);
	dump_cfg_string(oIgnoreUnknown, o->ignored_unknown);
	dump_cfg_string(oKbdInteractiveDevices, o->kbd_interactive_devices);
	dump_cfg_string(oKexAlgorithms, o->kex_algorithms);
	dump_cfg_string(oCASignatureAlgorithms, o->ca_sign_algorithms);
	dump_cfg_string(oLocalCommand, o->local_command);
	dump_cfg_string(oRemoteCommand, o->remote_command);
	dump_cfg_string(oLogLevel, log_level_name(o->log_level));
	dump_cfg_string(oMacs, o->macs);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_PKCS11
	dump_cfg_string(oPKCS11Provider, o->pkcs11_provider);
#ਜੇ_ਅੰਤ
	dump_cfg_string(o_Security_ਕੁੰਜੀ_Provider, o->sk_provider);
	dump_cfg_string(oPreferredAuthentications, o->preferred_authentications);
	dump_cfg_string(oPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
	dump_cfg_string(oXAuthLocation, o->xauth_location);
	dump_cfg_string(o_ਗਿਆਤ_Hosts_Command, o->ਗਿਆਤ_hosts_command);
	dump_cfg_string(o_ਟੈਗ, o->ਟੈਗ);
	dump_cfg_string(o_ਸੰਸਕਰਣ_Addendum, o->ਸੰਸਕਰਣ_addendum);

	/* Forwards */
	dump_cfg_forwards(oDynamicForward, o->ਅੰਕ_local_forwards, o->local_forwards);
	dump_cfg_forwards(oLocalForward, o->ਅੰਕ_local_forwards, o->local_forwards);
	dump_cfg_forwards(oRemoteForward, o->ਅੰਕ_remote_forwards, o->remote_forwards);

	/* String array options */
	dump_cfg_strarray(o_ਪਛਾਣ_ਤੱਤ_File, o->ਅੰਕ_ਪਛਾਣ_ਤੱਤ_files, o->ਪਛਾਣ_ਤੱਤ_files);
	dump_cfg_strarray_oneline(oCanonicalDomains, o->ਅੰਕ_canonical_domains, o->canonical_domains);
	dump_cfg_strarray(oCertificateFile, o->ਅੰਕ_certificate_files, o->certificate_files);
	dump_cfg_strarray_oneline(o_Global_ਗਿਆਤ_Hosts_File, o->ਅੰਕ_system_hostfiles, o->system_hostfiles);
	dump_cfg_strarray_oneline(o_User_ਗਿਆਤ_Hosts_File, o->ਅੰਕ_user_hostfiles, o->user_hostfiles);
	dump_cfg_strarray_oneline(o_Revoked_Host_ਕੁੰਜੀਆਂ, o->ਅੰਕ_revoked_host_ਕੁੰਜੀਆਂ, o->revoked_host_ਕੁੰਜੀਆਂ);
	dump_cfg_strarray(oSendEnv, o->ਅੰਕ_send_env, o->send_env);
	dump_cfg_strarray(o_ਸੈੱਟ_Env, o->ਅੰਕ_setenv, o->setenv);
	dump_cfg_strarray_oneline(oLogVerbose,
	    o->ਅੰਕ_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(oChannelTimeout,
	    o->ਅੰਕ_channel_timeouts, o->channel_timeouts);

	/* Special cases */

	/* PermitRemoteOpen */
	ਜੇ (o->ਅੰਕ_permitted_remote_opens == 0)
		ਲਿਖੋ("%s any\n", lookup_opcode_name(oPermitRemoteOpen));
	ਨਹੀਂਤਾਂ
		dump_cfg_strarray_oneline(oPermitRemoteOpen,
		    o->ਅੰਕ_permitted_remote_opens, o->permitted_remote_opens);

	/* AddKeysToAgent */
	ਜੇ (o->ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_agent_lifespan <= 0)
		dump_cfg_fmtint(o_ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_Agent, o->ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_agent);
	ਨਹੀਂਤਾਂ {
		ਲਿਖੋ("addkeystoagent%s %d\n",
		    o->ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_agent == 3 ? " confirm" : "",
		    o->ਜੋੜੋ_ਕੁੰਜੀਆਂ_ਮੰਜ਼ਿਲ_agent_lifespan);
	}

	/* oForwardAgent */
	ਜੇ (o->forward_agent_sock_ਰਸਤਾ == ਨਿਰਾ)
		dump_cfg_fmtint(oForwardAgent, o->forward_agent);
	ਨਹੀਂਤਾਂ
		dump_cfg_string(oForwardAgent, o->forward_agent_sock_ਰਸਤਾ);

	/* oConnectTimeout */
	ਜੇ (o->connection_timeout == -1)
		ਲਿਖੋ("connecttimeout none\n");
	ਨਹੀਂਤਾਂ
		dump_cfg_int(oConnectTimeout, o->connection_timeout);

	/* oTunnelDevice */
	ਲਿਖੋ("tunneldevice");
	ਜੇ (o->tun_local == SSH_TUNID_ANY)
		ਲਿਖੋ(" any");
	ਨਹੀਂਤਾਂ
		ਲਿਖੋ(" %d", o->tun_local);
	ਜੇ (o->tun_remote == SSH_TUNID_ANY)
		ਲਿਖੋ(":any");
	ਨਹੀਂਤਾਂ
		ਲਿਖੋ(":%d", o->tun_remote);
	ਲਿਖੋ("\n");

	/* oCanonicalizePermittedCNAMEs */
	ਲਿਖੋ("canonicalizepermittedcnames");
	ਜੇ (o->ਅੰਕ_permitted_cnames == 0)
		ਲਿਖੋ(" none");
	ਲਈ (i = 0; i < o->ਅੰਕ_permitted_cnames; i++) {
		ਲਿਖੋ(" %s:%s", o->permitted_cnames[i].ਸਰੋਤ_list,
		    o->permitted_cnames[i].ਨਿਸ਼ਾਨਾ_list);
	}
	ਲਿਖੋ("\n");

	/* oControlPersist */
	ਜੇ (o->control_persist == 0 || o->control_persist_timeout == 0)
		dump_cfg_fmtint(oControlPersist, o->control_persist);
	ਨਹੀਂਤਾਂ
		dump_cfg_int(oControlPersist, o->control_persist_timeout);

	/* oEscapeChar */
	ਜੇ (o->escape_char == SSH_ESCAPECHAR_NONE)
		ਲਿਖੋ("escapechar none\n");
	ਨਹੀਂਤਾਂ {
		vis(buf, o->escape_char, VIS_WHITE, 0);
		ਲਿਖੋ("escapechar %s\n", buf);
	}

	/* oIPQoS */
	ਲਿਖੋ("ipqos %s ", iptos2str(o->ip_qos_interactive));
	ਲਿਖੋ("%s\n", iptos2str(o->ip_qos_bulk));

	/* oRekeyLimit */
	ਲਿਖੋ("rekeylimit %llu %d\n",
	    (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ)o->rekey_ਹੱਦਬੰਦੀ, o->rekey_interval);

	/* oStreamLocalBindMask */
	ਲਿਖੋ("streamlocalbindmask 0%o\n",
	    o->fwd_opts.streamlocal_bind_ਨਕਾਬ);

	/* oLogFacility */
	ਲਿਖੋ("syslogfacility %s\n", log_facility_name(o->log_facility));

	/* oProxyCommand / oProxyJump */
	ਜੇ (o->jump_host == ਨਿਰਾ)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	ਨਹੀਂਤਾਂ {
		/* Check for numeric addresses */
		i = strchr(o->jump_host, ':') != ਨਿਰਾ ||
		    strspn(o->jump_host, "1234567890.") == ਲੜੀ_ਲੰਬਾਈ(o->jump_host);
		snprintf(buf, ਆਕਾਰ(buf), "%d", o->jump_ਪੋਰਟ);
		ਲਿਖੋ("proxyjump %s%s%s%s%s%s%s%s%s\n",
		    /* optional additional jump spec */
		    o->jump_extra == ਨਿਰਾ ? "" : o->jump_extra,
		    o->jump_extra == ਨਿਰਾ ? "" : ",",
		    /* optional user */
		    o->jump_user == ਨਿਰਾ ? "" : o->jump_user,
		    o->jump_user == ਨਿਰਾ ? "" : "@",
		    /* opening [ if hostname is numeric */
		    i ? "[" : "",
		    /* mandatory hostname */
		    o->jump_host,
		    /* closing ] if hostname is numeric */
		    i ? "]" : "",
		    /* optional port number */
		    o->jump_ਪੋਰਟ <= 0 ? "" : ":",
		    o->jump_ਪੋਰਟ <= 0 ? "" : buf);
	}
}
