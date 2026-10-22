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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/stat.h>
#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/wait.h>
#അന്തര്ഭാവ <sys/un.h>

#അന്തര്ഭാവ <net/if.h>
#അന്തര്ഭാവ <netinet/in.h>
#അന്തര്ഭാവ <netinet/ip.h>
#അന്തര്ഭാവ <arpa/inet.h>

#അന്തര്ഭാവ <ctype.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <glob.h>
#അന്തര്ഭാവ <ifaddrs.h>
#അന്തര്ഭാവ <limits.h>
#അന്തര്ഭാവ <netdb.h>
#അന്തര്ഭാവ <paths.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <util.h>
#എങ്കിൽ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "cipher.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "readconf.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "kex.h"
#അന്തര്ഭാവ "mac.h"
#അന്തര്ഭാവ "myproposal.h"
#അന്തര്ഭാവ "digest.h"
#അന്തര്ഭാവ "version.h"

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

സ്ഥിതം പൂർണ്ണസംഖ്യ read_config_file_depth(സ്ഥിരം അക്ഷരം *filename, ഘടന passwd *pw,
    സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *original_host, സ്ഥിരം അക്ഷരം *remote_command,
    Options *options, പൂർണ്ണസംഖ്യ flags, പൂർണ്ണസംഖ്യ *activep, പൂർണ്ണസംഖ്യ *want_final_pass, പൂർണ്ണസംഖ്യ depth);
സ്ഥിതം പൂർണ്ണസംഖ്യ process_config_വരി_depth(Options *options, ഘടന passwd *pw,
    സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *original_host, സ്ഥിരം അക്ഷരം *remote_command,
    അക്ഷരം *വരി, സ്ഥിരം അക്ഷരം *filename, പൂർണ്ണസംഖ്യ linenum, പൂർണ്ണസംഖ്യ *activep, പൂർണ്ണസംഖ്യ flags,
    പൂർണ്ണസംഖ്യ *want_final_pass, പൂർണ്ണസംഖ്യ depth);

/* Keyword tokens. */

തരനിർവചനം എണ്ണൽ {
	oBadOption,
	oHost, oMatch, oInclude, oTag,
	oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout,
	oGatewayPorts, oExitOnForwardFailure,
	oPasswordAuthentication,
	oXAuthLocation,
	oIdentityFile, oHostname, oPort, oRemoteForward, oLocalForward,
	oPermitRemoteOpen,
	oCertificateFile, o_Add_താക്കോലുകൾ_To_Agent, oIdentityAgent,
	oUser, oEscapeChar, oProxyCommand,
	oGlobalKnownHostsFile, oUserKnownHostsFile, oConnectionAttempts,
	oBatchMode, oCheckHostIP, o_Strict_Host_താക്കോൽ_Checking, oCompression,
	oTCPKeepAlive, o_സംഖ്യ_Of_Password_Prompts,
	oLogFacility, oLogLevel, oLogVerbose, oCiphers, oMacs,
	oPubkeyAuthentication,
	oKbdInteractiveAuthentication, oKbdInteractiveDevices, o_Host_താക്കോൽ_Alias,
	oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication,
	o_Host_താക്കോൽ_Algorithms, oBindAddress, oBindInterface, oPKCS11Provider,
	oClearAllForwardings, oNoHostAuthenticationForLocalhost,
	oEnableSSHKeysign, oRekeyLimit, o_Verify_Host_താക്കോൽ_DNS, oConnectTimeout,
	oAddressFamily, oGssAuthentication, oGssDelegateCreds,
	oServerAliveInterval, o_Server_Alive_എണ്ണം_Max, oIdentitiesOnly,
	oSendEnv, oSetEnv, oControlPath, oControlMaster, oControlPersist,
	oHashKnownHosts,
	oTunnel, oTunnelDevice,
	oLocalCommand, oPermitLocalCommand, oRemoteCommand,
	o_Visual_Host_താക്കോൽ,
	oKexAlgorithms, oIPQoS, oRequestTTY, oSessionType, oStdinNull,
	oForkAfterAuthentication, oIgnoreUnknown, oProxyUseFdpass,
	oCanonicalDomains, oCanonicalizeHostname, oCanonicalizeMaxDots,
	oCanonicalizeFallbackLocal, oCanonicalizePermittedCNAMEs,
	oStreamLocalBindMask, oStreamLocalBindUnlink, o_Revoked_Host_താക്കോലുകൾ,
	oFingerprintHash, oUpdateHostkeys, oHostbasedAcceptedAlgorithms,
	oPubkeyAcceptedAlgorithms, oCASignatureAlgorithms, oProxyJump,
	o_Security_താക്കോൽ_Provider, oKnownHostsCommand, oRequiredRSASize,
	oEnableEscapeCommandline, oObscureKeystrokeTiming, oChannelTimeout,
	oVersionAddendum, oRefuseConnection, oWarnWeakCrypto,
	oIgnore, oIgnoredUnknownOption, oDeprecated, oUnsupported
} OpCodes;

/* Textual representations of the tokens. */

സ്ഥിതം ഘടന {
	സ്ഥിരം അക്ഷരം *name;
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
#എങ്കിൽ defined(GSSAPI)
	{ "gssapiauthentication", oGssAuthentication },
	{ "gssapidelegatecredentials", oGssDelegateCreds },
# അല്ലെങ്കിൽ
	{ "gssapiauthentication", oUnsupported },
	{ "gssapidelegatecredentials", oUnsupported },
#endif
#ifdef ENABLE_PKCS11
	{ "pkcs11provider", oPKCS11Provider },
	{ "smartcarddevice", oPKCS11Provider },
# അല്ലെങ്കിൽ
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
	{ "addkeystoagent", o_Add_താക്കോലുകൾ_To_Agent },
	{ "identityagent", oIdentityAgent },
	{ "hostname", oHostname },
	{ "hostkeyalias", o_Host_താക്കോൽ_Alias },
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
	{ "stricthostkeychecking", o_Strict_Host_താക്കോൽ_Checking },
	{ "compression", oCompression },
	{ "tcpkeepalive", oTCPKeepAlive },
	{ "keepalive", oTCPKeepAlive },				/* obsolete */
	{ "numberofpasswordprompts", o_സംഖ്യ_Of_Password_Prompts },
	{ "syslogfacility", oLogFacility },
	{ "loglevel", oLogLevel },
	{ "logverbose", oLogVerbose },
	{ "dynamicforward", oDynamicForward },
	{ "preferredauthentications", oPreferredAuthentications },
	{ "hostkeyalgorithms", o_Host_താക്കോൽ_Algorithms },
	{ "casignaturealgorithms", oCASignatureAlgorithms },
	{ "bindaddress", oBindAddress },
	{ "bindinterface", oBindInterface },
	{ "clearallforwardings", oClearAllForwardings },
	{ "enablesshkeysign", oEnableSSHKeysign },
	{ "verifyhostkeydns", o_Verify_Host_താക്കോൽ_DNS },
	{ "nohostauthenticationforlocalhost", oNoHostAuthenticationForLocalhost },
	{ "rekeylimit", oRekeyLimit },
	{ "connecttimeout", oConnectTimeout },
	{ "addressfamily", oAddressFamily },
	{ "serveraliveinterval", oServerAliveInterval },
	{ "serveralivecountmax", o_Server_Alive_എണ്ണം_Max },
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
	{ "visualhostkey", o_Visual_Host_താക്കോൽ },
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
	{ "revokedhostkeys", o_Revoked_Host_താക്കോലുകൾ },
	{ "fingerprinthash", oFingerprintHash },
	{ "updatehostkeys", oUpdateHostkeys },
	{ "hostbasedacceptedalgorithms", oHostbasedAcceptedAlgorithms },
	{ "hostbasedkeytypes", oHostbasedAcceptedAlgorithms }, /* obsolete */
	{ "pubkeyacceptedalgorithms", oPubkeyAcceptedAlgorithms },
	{ "pubkeyacceptedkeytypes", oPubkeyAcceptedAlgorithms }, /* obsolete */
	{ "ignoreunknown", oIgnoreUnknown },
	{ "proxyjump", oProxyJump },
	{ "securitykeyprovider", o_Security_താക്കോൽ_Provider },
	{ "knownhostscommand", oKnownHostsCommand },
	{ "requiredrsasize", oRequiredRSASize },
	{ "enableescapecommandline", oEnableEscapeCommandline },
	{ "obscurekeystroketiming", oObscureKeystrokeTiming },
	{ "channeltimeout", oChannelTimeout },
	{ "versionaddendum", oVersionAddendum },
	{ "refuseconnection", oRefuseConnection },
	{ "warnweakcrypto", oWarnWeakCrypto },

	{ ശൂന്യ, oBadOption }
};

സ്ഥിതം സ്ഥിരം അക്ഷരം *lookup_opcode_name(OpCodes code);

സ്ഥിരം അക്ഷരം *
kex_default_pk_alg(ശൂന്യം)
{
	സ്ഥിതം അക്ഷരം *pkalgs;

	എങ്കിൽ (pkalgs == ശൂന്യ) {
		അക്ഷരം *all_താക്കോൽ;

		all_താക്കോൽ = sshkey_alg_list(0, 0, 1, ',');
		pkalgs = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_താക്കോൽ);
		സ്വതന്ത്രം(all_താക്കോൽ);
	}
	തിരികെ pkalgs;
}

അക്ഷരം *
ssh_connection_hash(സ്ഥിരം അക്ഷരം *thishost, സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *portstr,
    സ്ഥിരം അക്ഷരം *user, സ്ഥിരം അക്ഷരം *jumphost)
{
	ഘടന ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_LENGTH];

	എങ്കിൽ ((md = ssh_digest_start(SSH_DIGEST_SHA1)) == ശൂന്യ ||
	    ssh_digest_update(md, thishost, strlen(thishost)) < 0 ||
	    ssh_digest_update(md, host, strlen(host)) < 0 ||
	    ssh_digest_update(md, portstr, strlen(portstr)) < 0 ||
	    ssh_digest_update(md, user, strlen(user)) < 0 ||
	    ssh_digest_update(md, jumphost, strlen(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, വലുപ്പം(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	തിരികെ tohex(conn_hash, ssh_digest_bytes(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

ശൂന്യം
add_local_forward(Options *options, സ്ഥിരം ഘടന Forward *newfwd)
{
	ഘടന Forward *fwd;
	പൂർണ്ണസംഖ്യ i;

	/* Don't add duplicates */
	വേണ്ടി (i = 0; i < options->അക്കം_local_forwards; i++) {
		എങ്കിൽ (forward_equals(newfwd, options->local_forwards + i))
			തിരികെ;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->അക്കം_local_forwards + 1,
	    വലുപ്പം(*options->local_forwards));
	fwd = &options->local_forwards[options->അക്കം_local_forwards++];

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

ശൂന്യം
add_remote_forward(Options *options, സ്ഥിരം ഘടന Forward *newfwd)
{
	ഘടന Forward *fwd;
	പൂർണ്ണസംഖ്യ i;

	/* Don't add duplicates */
	വേണ്ടി (i = 0; i < options->അക്കം_remote_forwards; i++) {
		എങ്കിൽ (forward_equals(newfwd, options->remote_forwards + i))
			തിരികെ;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->അക്കം_remote_forwards + 1,
	    വലുപ്പം(*options->remote_forwards));
	fwd = &options->remote_forwards[options->അക്കം_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_port = newfwd->listen_port;
	fwd->listen_path = newfwd->listen_path;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_port = newfwd->connect_port;
	fwd->connect_path = newfwd->connect_path;
	fwd->handle = newfwd->handle;
	fwd->allocated_port = 0;
}

സ്ഥിതം ശൂന്യം
clear_forwardings(Options *options)
{
	പൂർണ്ണസംഖ്യ i;

	വേണ്ടി (i = 0; i < options->അക്കം_local_forwards; i++) {
		സ്വതന്ത്രം(options->local_forwards[i].listen_host);
		സ്വതന്ത്രം(options->local_forwards[i].listen_path);
		സ്വതന്ത്രം(options->local_forwards[i].connect_host);
		സ്വതന്ത്രം(options->local_forwards[i].connect_path);
	}
	എങ്കിൽ (options->അക്കം_local_forwards > 0) {
		സ്വതന്ത്രം(options->local_forwards);
		options->local_forwards = ശൂന്യ;
	}
	options->അക്കം_local_forwards = 0;
	വേണ്ടി (i = 0; i < options->അക്കം_remote_forwards; i++) {
		സ്വതന്ത്രം(options->remote_forwards[i].listen_host);
		സ്വതന്ത്രം(options->remote_forwards[i].listen_path);
		സ്വതന്ത്രം(options->remote_forwards[i].connect_host);
		സ്വതന്ത്രം(options->remote_forwards[i].connect_path);
	}
	എങ്കിൽ (options->അക്കം_remote_forwards > 0) {
		സ്വതന്ത്രം(options->remote_forwards);
		options->remote_forwards = ശൂന്യ;
	}
	options->അക്കം_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

ശൂന്യം
add_certificate_file(Options *options, സ്ഥിരം അക്ഷരം *path, പൂർണ്ണസംഖ്യ userprovided)
{
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (options->അക്കം_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	വേണ്ടി (i = 0; i < options->അക്കം_certificate_files; i++) {
		എങ്കിൽ (options->certificate_file_userprovided[i] == userprovided &&
		    strcmp(options->certificate_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			തിരികെ;
		}
	}

	options->certificate_file_userprovided[options->അക്കം_certificate_files] =
	    userprovided;
	options->certificate_files[options->അക്കം_certificate_files++] =
	    xstrdup(path);
}

ശൂന്യം
add_identity_file(Options *options, സ്ഥിരം അക്ഷരം *dir, സ്ഥിരം അക്ഷരം *filename,
    പൂർണ്ണസംഖ്യ userprovided)
{
	അക്ഷരം *path;
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (options->അക്കം_identity_files >= SSH_MAX_IDENTITY_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_IDENTITY_FILES);

	എങ്കിൽ (dir == ശൂന്യ) /* no dir, filename is absolute */
		path = xstrdup(filename);
	അല്ലെങ്കിൽ എങ്കിൽ (xasprintf(&path, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", path);

	/* Avoid registering duplicates */
	വേണ്ടി (i = 0; i < options->അക്കം_identity_files; i++) {
		എങ്കിൽ (options->identity_file_userprovided[i] == userprovided &&
		    strcmp(options->identity_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			സ്വതന്ത്രം(path);
			തിരികെ;
		}
	}

	options->identity_file_userprovided[options->അക്കം_identity_files] =
	    userprovided;
	options->identity_files[options->അക്കം_identity_files++] = path;
}

പൂർണ്ണസംഖ്യ
default_ssh_port(ശൂന്യം)
{
	സ്ഥിതം പൂർണ്ണസംഖ്യ port;
	ഘടന servent *sp;

	എങ്കിൽ (port == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		port = sp ? ntohs(sp->s_port) : SSH_DEFAULT_PORT;
	}
	തിരികെ port;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
execute_in_shell(സ്ഥിരം അക്ഷരം *cmd)
{
	അക്ഷരം *shell;
	pid_t pid;
	പൂർണ്ണസംഖ്യ status;

	എങ്കിൽ ((shell = getenv("SHELL")) == ശൂന്യ)
		shell = _PATH_BSHELL;

	എങ്കിൽ (access(shell, X_OK) == -1) {
		fatal("Shell \"%s\" is not executable: %s",
		    shell, strerror(errno));
	}

	debug("Executing command: '%.500s'", cmd);

	/* Fork and execute the command. */
	എങ്കിൽ ((pid = fork()) == 0) {
		അക്ഷരം *argv[4];

		എങ്കിൽ (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = xstrdup(cmd);
		argv[3] = ശൂന്യ;

		execv(argv[0], argv);
		error("Unable to execute '%.100s': %s", cmd, strerror(errno));
		/* Die with signal to make this error apparent to parent. */
		ssh_signal(SIGTERM, SIG_DFL);
		kill(getpid(), SIGTERM);
		_exit(1);
	}
	/* Parent. */
	എങ്കിൽ (pid == -1)
		fatal_f("fork: %.100s", strerror(errno));

	ആകുമ്പോൾ (waitpid(pid, &status, 0) == -1) {
		എങ്കിൽ (errno != EINTR && errno != EAGAIN)
			fatal_f("waitpid: %s", strerror(errno));
	}
	എങ്കിൽ (!WIFEXITED(status)) {
		error("command '%.100s' exited abnormally", cmd);
		തിരികെ -1;
	}
	debug3("command returned status %d", WEXITSTATUS(status));
	തിരികെ WEXITSTATUS(status);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
check_match_ifaddrs(സ്ഥിരം അക്ഷരം *addrlist)
{
#ifdef HAVE_IFADDRS_H
	ഘടന ifaddrs *ifa, *ifaddrs = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, found = 0;
	അക്ഷരം addr[NI_MAXHOST];
	socklen_t salen;

	എങ്കിൽ (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    strerror(errno));
		തിരികെ 0;
	}
	വേണ്ടി (ifa = ifaddrs; ifa != ശൂന്യ; ifa = ifa->ifa_next) {
		എങ്കിൽ (ifa->ifa_addr == ശൂന്യ || ifa->ifa_name == ശൂന്യ ||
		    (ifa->ifa_flags & IFF_UP) == 0)
			തുടരുക;
		തിരഞ്ഞെടുപ്പ് (ifa->ifa_addr->sa_family) {
		അവസ്ഥ AF_INET:
			salen = വലുപ്പം(ഘടന sockaddr_in);
			നിർത്തുക;
		അവസ്ഥ AF_INET6:
			salen = വലുപ്പം(ഘടന sockaddr_in6);
			നിർത്തുക;
#ifdef AF_LINK
		അവസ്ഥ AF_LINK:
			/* ignore */
			തുടരുക;
#endif /* AF_LINK */
		സ്ഥിരസ്ഥിതി:
			debug2_f("interface %s: unsupported address family %d",
			    ifa->ifa_name, ifa->ifa_addr->sa_family);
			തുടരുക;
		}
		എങ്കിൽ ((r = getnameinfo(ifa->ifa_addr, salen, addr, വലുപ്പം(addr),
		    ശൂന്യ, 0, NI_NUMERICHOST)) != 0) {
			debug2_f("interface %s getnameinfo failed: %s",
			    ifa->ifa_name, gai_strerror(r));
			തുടരുക;
		}
		debug3_f("interface %s addr %s", ifa->ifa_name, addr);
		എങ്കിൽ (addr_match_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			found = 1;
			നിർത്തുക;
		}
	}
	freeifaddrs(ifaddrs);
	തിരികെ found;
#അല്ലെങ്കിൽ /* HAVE_IFADDRS_H */
	error("match localnetwork: not supported on this platform");
	തിരികെ 0;
#endif /* HAVE_IFADDRS_H */
}

/*
 * Expand a "match exec" command or an Include path, caller must free returned
 * value.
 */
സ്ഥിതം അക്ഷരം *
expand_match_exec_or_include_path(സ്ഥിരം അക്ഷരം *path, Options *options,
    ഘടന passwd *pw, സ്ഥിരം അക്ഷരം *host_arg, സ്ഥിരം അക്ഷരം *original_host,
    പൂർണ്ണസംഖ്യ final_pass, പൂർണ്ണസംഖ്യ is_include_path)
{
	അക്ഷരം thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	അക്ഷരം uidstr[32], *conn_hash_hex, *keyalias, *jmphost, *ruser;
	അക്ഷരം *host, *ret;
	പൂർണ്ണസംഖ്യ port;

	port = options->port <= 0 ? default_ssh_port() : options->port;
	ruser = options->user == ശൂന്യ ? pw->pw_name : options->user;
	എങ്കിൽ (final_pass) {
		host = xstrdup(options->hostname);
	} അല്ലെങ്കിൽ എങ്കിൽ (options->hostname != ശൂന്യ) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (അക്ഷരം *)ശൂന്യ);
	} അല്ലെങ്കിൽ {
		host = xstrdup(host_arg);
	}
	എങ്കിൽ (gethostname(thishost, വലുപ്പം(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	jmphost = option_clear_or_none(options->jump_host) ?
	    "" : options->jump_host;
	strlcpy(shorthost, thishost, വലുപ്പം(shorthost));
	shorthost[strcspn(thishost, ".")] = '\0';
	snprintf(portstr, വലുപ്പം(portstr), "%d", port);
	snprintf(uidstr, വലുപ്പം(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	conn_hash_hex = ssh_connection_hash(thishost, host,
	    portstr, ruser, jmphost);
	keyalias = options->host_താക്കോൽ_alias ?  options->host_താക്കോൽ_alias : host;

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
	    (അക്ഷരം *)ശൂന്യ);
	സ്വതന്ത്രം(host);
	സ്വതന്ത്രം(conn_hash_hex);
	തിരികെ ret;
}

/*
 * Parse and execute a Match directive.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
match_cfg_വരി(Options *options, സ്ഥിരം അക്ഷരം *full_വരി, പൂർണ്ണസംഖ്യ *acp, അക്ഷരം ***avp,
    ഘടന passwd *pw, സ്ഥിരം അക്ഷരം *host_arg, സ്ഥിരം അക്ഷരം *original_host,
    സ്ഥിരം അക്ഷരം *remote_command, പൂർണ്ണസംഖ്യ final_pass, പൂർണ്ണസംഖ്യ *want_final_pass,
    സ്ഥിരം അക്ഷരം *filename, പൂർണ്ണസംഖ്യ linenum)
{
	അക്ഷരം *arg, *oattrib = ശൂന്യ, *attrib = ശൂന്യ, *cmd, *host, *criteria;
	സ്ഥിരം അക്ഷരം *ruser;
	പൂർണ്ണസംഖ്യ r, this_result, result = 1, attributes = 0, negate;

	/*
	 * Configuration is likely to be incomplete at this point so we
	 * must be prepared to use default values.
	 */
	ruser = options->user == ശൂന്യ ? pw->pw_name : options->user;
	എങ്കിൽ (final_pass) {
		host = xstrdup(options->hostname);
	} അല്ലെങ്കിൽ എങ്കിൽ (options->hostname != ശൂന്യ) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (അക്ഷരം *)ശൂന്യ);
	} അല്ലെങ്കിൽ {
		host = xstrdup(host_arg);
	}

	debug2("checking match for '%s' host %s originally %s",
	    full_വരി, host, original_host);
	ആകുമ്പോൾ ((attrib = argv_next(acp, avp)) != ശൂന്യ) {
		/* Terminate on comment */
		എങ്കിൽ (*attrib == '#') {
			argv_consume(acp);
			നിർത്തുക;
		}
		attrib = oattrib = xstrdup(attrib);
		arg = criteria = ശൂന്യ;
		this_result = 1;
		എങ്കിൽ ((negate = (attrib[0] == '!')))
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		എങ്കിൽ (strcasecmp(attrib, "all") == 0) {
			എങ്കിൽ (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != ശൂന്യ &&
			    *arg != '\0' && *arg != '#')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				result = -1;
				പോകുക out;
			}
			എങ്കിൽ (arg != ശൂന്യ && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			എങ്കിൽ (result)
				result = negate ? 0 : 1;
			പോകുക out;
		}
		attributes++;
		/* criteria "final" and "canonical" have no argument */
		എങ്കിൽ (strcasecmp(attrib, "canonical") == 0 ||
		    strcasecmp(attrib, "final") == 0) {
			/*
			 * If the config requests "Match final" without
			 * negation then remember this so we can perform a
			 * second pass later.
			 */
			എങ്കിൽ (strcasecmp(attrib, "final") == 0 &&
			    want_final_pass != ശൂന്യ)
				*want_final_pass |= !negate;
			r = !!final_pass;  /* force bitmask member to boolean */
			എങ്കിൽ (r == (negate ? 1 : 0))
				this_result = result = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_result ? "" : "not ", oattrib);
			പോകുക next;
		}

		/* Keep this list in sync with below */
		എങ്കിൽ (strprefix(attrib, "host=", 1)  != ശൂന്യ ||
		    strprefix(attrib, "originalhost=", 1) != ശൂന്യ ||
		    strprefix(attrib, "user=", 1) != ശൂന്യ ||
		    strprefix(attrib, "localuser=", 1) != ശൂന്യ ||
		    strprefix(attrib, "localnetwork=", 1) != ശൂന്യ ||
		    strprefix(attrib, "version=", 1) != ശൂന്യ ||
		    strprefix(attrib, "tagged=", 1) != ശൂന്യ ||
		    strprefix(attrib, "command=", 1) != ശൂന്യ ||
		    strprefix(attrib, "exec=", 1) != ശൂന്യ) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} അല്ലെങ്കിൽ എങ്കിൽ ((arg = argv_next(acp, avp)) == ശൂന്യ) {
			error("%.200s line %d: missing argument for Match '%s'",
			    filename, linenum, oattrib);
			result = -1;
			പോകുക out;
		}

		/*
		 * All other criteria require an argument, though it may
		 * be the empty string for the "tagged" and "command"
		 * options.
		 */
		എങ്കിൽ (*arg == '\0' &&
		    strcasecmp(attrib, "tagged") != 0 &&
		    strcasecmp(attrib, "command") != 0)
			arg = ശൂന്യ;
		എങ്കിൽ (arg == ശൂന്യ || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			പോകുക out;
		}
		എങ്കിൽ (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = match_hostname(host, arg) == 1;
			എങ്കിൽ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = match_hostname(original_host, arg) == 1;
			എങ്കിൽ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = match_pattern_list(ruser, arg, 0) == 1;
			എങ്കിൽ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = match_pattern_list(pw->pw_name, arg, 0) == 1;
			എങ്കിൽ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(attrib, "localnetwork") == 0) {
			എങ്കിൽ (addr_match_cidr_list(ശൂന്യ, arg) == -1) {
				/* Error already printed */
				result = -1;
				പോകുക out;
			}
			r = check_match_ifaddrs(arg) == 1;
			എങ്കിൽ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(attrib, "version") == 0) {
			criteria = xstrdup(SSH_RELEASE);
			r = match_pattern_list(SSH_RELEASE, arg, 0) == 1;
			എങ്കിൽ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->tag == ശൂന്യ ? "" :
			    options->tag);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			എങ്കിൽ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(attrib, "command") == 0) {
			criteria = xstrdup(remote_command == ശൂന്യ ?
			    "" : remote_command);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			എങ്കിൽ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(attrib, "sessiontype") == 0) {
			എങ്കിൽ (options->session_type == SESSION_TYPE_SUBSYSTEM)
				criteria = xstrdup("subsystem");
			അല്ലെങ്കിൽ എങ്കിൽ (options->session_type == SESSION_TYPE_NONE)
				criteria = xstrdup("none");
			അല്ലെങ്കിൽ എങ്കിൽ (remote_command != ശൂന്യ &&
			    *remote_command != '\0')
				criteria = xstrdup("exec");
			അല്ലെങ്കിൽ
				criteria = xstrdup("shell");
			r = match_pattern_list(criteria, arg, 0) == 1;
			എങ്കിൽ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(attrib, "exec") == 0) {
			എങ്കിൽ ((cmd = expand_match_exec_or_include_path(arg,
			    options, pw, host_arg, original_host,
			    final_pass, 0)) == ശൂന്യ) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			എങ്കിൽ (result != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				സ്വതന്ത്രം(cmd);
				പോകുക next;
			}
			r = execute_in_shell(cmd);
			എങ്കിൽ (r == -1) {
				fatal("%.200s line %d: match exec "
				    "'%.100s' error", filename,
				    linenum, cmd);
			}
			criteria = xstrdup(cmd);
			സ്വതന്ത്രം(cmd);
			/* Force exit status to boolean */
			r = r == 0;
			എങ്കിൽ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} അല്ലെങ്കിൽ {
			error("Unsupported Match attribute %s", attrib);
			result = -1;
			പോകുക out;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s' ",
		    filename, linenum, this_result ? "": "not ", oattrib,
		    criteria == ശൂന്യ ? "" : " \"",
		    criteria == ശൂന്യ ? "" : criteria,
		    criteria == ശൂന്യ ? "" : "\"");
 next:
		സ്വതന്ത്രം(criteria);
		സ്വതന്ത്രം(oattrib);
		oattrib = attrib = ശൂന്യ;
	}
	എങ്കിൽ (attributes == 0) {
		error("One or more attributes required for Match");
		result = -1;
		പോകുക out;
	}
 out:
	എങ്കിൽ (result != -1)
		debug2("match %sfound", result ? "" : "not ");
	സ്വതന്ത്രം(oattrib);
	സ്വതന്ത്രം(host);
	തിരികെ result;
}

/* Remove environment variable by pattern */
സ്ഥിതം ശൂന്യം
rm_env(Options *options, സ്ഥിരം അക്ഷരം *arg, സ്ഥിരം അക്ഷരം *filename, പൂർണ്ണസംഖ്യ linenum)
{
	u_int i, j, onum_send_env = options->അക്കം_send_env;

	/* Remove an environment variable */
	വേണ്ടി (i = 0; i < options->അക്കം_send_env; ) {
		എങ്കിൽ (!match_pattern(options->send_env[i], arg + 1)) {
			i++;
			തുടരുക;
		}
		debug3("%s line %d: removing environment %s",
		    filename, linenum, options->send_env[i]);
		സ്വതന്ത്രം(options->send_env[i]);
		options->send_env[i] = ശൂന്യ;
		വേണ്ടി (j = i; j < options->അക്കം_send_env - 1; j++) {
			options->send_env[j] = options->send_env[j + 1];
			options->send_env[j + 1] = ശൂന്യ;
		}
		options->അക്കം_send_env--;
		/* NB. don't increment i */
	}
	എങ്കിൽ (onum_send_env != options->അക്കം_send_env) {
		options->send_env = xrecallocarray(options->send_env,
		    onum_send_env, options->അക്കം_send_env,
		    വലുപ്പം(*options->send_env));
	}
}

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */
സ്ഥിതം OpCodes
parse_token(സ്ഥിരം അക്ഷരം *cp, സ്ഥിരം അക്ഷരം *filename, പൂർണ്ണസംഖ്യ linenum,
    സ്ഥിരം അക്ഷരം *ignored_unknown)
{
	പൂർണ്ണസംഖ്യ i;

	വേണ്ടി (i = 0; keywords[i].name; i++)
		എങ്കിൽ (strcmp(cp, keywords[i].name) == 0)
			തിരികെ keywords[i].opcode;
	എങ്കിൽ (ignored_unknown != ശൂന്യ &&
	    match_pattern_list(cp, ignored_unknown, 1) == 1)
		തിരികെ oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	തിരികെ oBadOption;
}

സ്ഥിതം ശൂന്യം
free_canon_cnames(ഘടന allowed_cname *cnames, u_int n)
{
	u_int i;

	എങ്കിൽ (cnames == ശൂന്യ || n == 0)
		തിരികെ;
	വേണ്ടി (i = 0; i < n; i++) {
		സ്വതന്ത്രം(cnames[i].source_list);
		സ്വതന്ത്രം(cnames[i].target_list);
	}
	സ്വതന്ത്രം(cnames);
}

/* Multistate option parsing */
ഘടന multistate {
	അക്ഷരം *താക്കോൽ;
	പൂർണ്ണസംഖ്യ മൂല്യം;
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_flag[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ ശൂന്യ, -1 }
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_yesnoask[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ ശൂന്യ, -1 }
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_strict_hostkey[] = {
	{ "true",			SSH_STRICT_HOSTKEY_YES },
	{ "false",			SSH_STRICT_HOSTKEY_OFF },
	{ "yes",			SSH_STRICT_HOSTKEY_YES },
	{ "no",				SSH_STRICT_HOSTKEY_OFF },
	{ "ask",			SSH_STRICT_HOSTKEY_ASK },
	{ "off",			SSH_STRICT_HOSTKEY_OFF },
	{ "accept-new",			SSH_STRICT_HOSTKEY_NEW },
	{ ശൂന്യ, -1 }
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_yesnoaskconfirm[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "confirm",			3 },
	{ ശൂന്യ, -1 }
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ ശൂന്യ, -1 }
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_controlmaster[] = {
	{ "true",			SSHCTL_MASTER_YES },
	{ "yes",			SSHCTL_MASTER_YES },
	{ "false",			SSHCTL_MASTER_NO },
	{ "no",				SSHCTL_MASTER_NO },
	{ "auto",			SSHCTL_MASTER_AUTO },
	{ "ask",			SSHCTL_MASTER_ASK },
	{ "autoask",			SSHCTL_MASTER_AUTO_ASK },
	{ ശൂന്യ, -1 }
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET },
	{ "point-to-point",		SSH_TUNMODE_POINTOPOINT },
	{ "true",			SSH_TUNMODE_DEFAULT },
	{ "yes",			SSH_TUNMODE_DEFAULT },
	{ "false",			SSH_TUNMODE_NO },
	{ "no",				SSH_TUNMODE_NO },
	{ ശൂന്യ, -1 }
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_requesttty[] = {
	{ "true",			REQUEST_TTY_YES },
	{ "yes",			REQUEST_TTY_YES },
	{ "false",			REQUEST_TTY_NO },
	{ "no",				REQUEST_TTY_NO },
	{ "force",			REQUEST_TTY_FORCE },
	{ "auto",			REQUEST_TTY_AUTO },
	{ ശൂന്യ, -1 }
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_sessiontype[] = {
	{ "none",			SESSION_TYPE_NONE },
	{ "subsystem",			SESSION_TYPE_SUBSYSTEM },
	{ "default",			SESSION_TYPE_DEFAULT },
	{ ശൂന്യ, -1 }
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_canonicalizehostname[] = {
	{ "true",			SSH_CANONICALISE_YES },
	{ "false",			SSH_CANONICALISE_NO },
	{ "yes",			SSH_CANONICALISE_YES },
	{ "no",				SSH_CANONICALISE_NO },
	{ "always",			SSH_CANONICALISE_ALWAYS },
	{ ശൂന്യ, -1 }
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_pubkey_auth[] = {
	{ "true",			SSH_PUBKEY_AUTH_ALL },
	{ "false",			SSH_PUBKEY_AUTH_NO },
	{ "yes",			SSH_PUBKEY_AUTH_ALL },
	{ "no",				SSH_PUBKEY_AUTH_NO },
	{ "unbound",			SSH_PUBKEY_AUTH_UNBOUND },
	{ "host-bound",			SSH_PUBKEY_AUTH_HBOUND },
	{ ശൂന്യ, -1 }
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ ശൂന്യ, -1 }
};
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ ശൂന്യ, -1 }
};
/* XXX this will need to be replaced with a bitmask if we add more flags */
സ്ഥിതം സ്ഥിരം ഘടന multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ ശൂന്യ, -1 }
};

സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_multistate_മൂല്യം(സ്ഥിരം അക്ഷരം *arg, സ്ഥിരം അക്ഷരം *filename, പൂർണ്ണസംഖ്യ linenum,
    സ്ഥിരം ഘടന multistate *multistate_ptr)
{
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (!arg || *arg == '\0') {
		error("%s line %d: missing argument.", filename, linenum);
		തിരികെ -1;
	}
	വേണ്ടി (i = 0; multistate_ptr[i].താക്കോൽ != ശൂന്യ; i++) {
		എങ്കിൽ (strcasecmp(arg, multistate_ptr[i].താക്കോൽ) == 0)
			തിരികെ multistate_ptr[i].മൂല്യം;
	}
	തിരികെ -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
പൂർണ്ണസംഖ്യ
process_config_വരി(Options *options, ഘടന passwd *pw, സ്ഥിരം അക്ഷരം *host,
    സ്ഥിരം അക്ഷരം *original_host, സ്ഥിരം അക്ഷരം *remote_command, അക്ഷരം *വരി,
    സ്ഥിരം അക്ഷരം *filename, പൂർണ്ണസംഖ്യ linenum, പൂർണ്ണസംഖ്യ *activep, പൂർണ്ണസംഖ്യ flags)
{
	തിരികെ process_config_വരി_depth(options, pw, host, original_host,
	    remote_command, വരി, filename, linenum, activep, flags, ശൂന്യ, 0);
}

#define WHITESPACE " \t\r\n"
സ്ഥിതം പൂർണ്ണസംഖ്യ
process_config_വരി_depth(Options *options, ഘടന passwd *pw, സ്ഥിരം അക്ഷരം *host,
    സ്ഥിരം അക്ഷരം *original_host, സ്ഥിരം അക്ഷരം *remote_command, അക്ഷരം *വരി,
    സ്ഥിരം അക്ഷരം *filename, പൂർണ്ണസംഖ്യ linenum, പൂർണ്ണസംഖ്യ *activep, പൂർണ്ണസംഖ്യ flags,
    പൂർണ്ണസംഖ്യ *want_final_pass, പൂർണ്ണസംഖ്യ depth)
{
	അക്ഷരം *str, **charptr, *endofnumber, *keyword, *arg, *arg2, *p;
	അക്ഷരം **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	പൂർണ്ണസംഖ്യ r, oactive, negated, opcode, *intptr, മൂല്യം, value2, cmdline = 0;
	പൂർണ്ണസംഖ്യ remotefwd, dynamicfwd, ca_only = 0, found = 0;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	long long val64;
	size_t len;
	ഘടന Forward fwd;
	സ്ഥിരം ഘടന multistate *multistate_ptr;
	glob_t gl;
	സ്ഥിരം അക്ഷരം *errstr;
	അക്ഷരം **oav = ശൂന്യ, **av;
	പൂർണ്ണസംഖ്യ oac = 0, ac;
	പൂർണ്ണസംഖ്യ ret = -1;
	ഘടന allowed_cname *cnames = ശൂന്യ;
	u_int ncnames = 0;
	അക്ഷരം **strs = ശൂന്യ; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	എങ്കിൽ (activep == ശൂന്യ) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	എങ്കിൽ ((len = strlen(വരി)) == 0)
		തിരികെ 0;
	വേണ്ടി (len--; len > 0; len--) {
		എങ്കിൽ (strchr(WHITESPACE "\f", വരി[len]) == ശൂന്യ)
			നിർത്തുക;
		വരി[len] = '\0';
	}

	str = വരി;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	എങ്കിൽ ((keyword = strdelim(&str)) == ശൂന്യ)
		തിരികെ 0;
	/* Ignore leading whitespace. */
	എങ്കിൽ (*keyword == '\0')
		keyword = strdelim(&str);
	എങ്കിൽ (keyword == ശൂന്യ || !*keyword || *keyword == '\n' || *keyword == '#')
		തിരികെ 0;
	/* Match lowercase keyword */
	lowercase(keyword);

	/* Prepare to parse remainder of line */
	എങ്കിൽ (str != ശൂന്യ)
		str += strspn(str, WHITESPACE);
	എങ്കിൽ (str == ശൂന്യ || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		തിരികെ -1;
	}
	opcode = parse_token(keyword, filename, linenum,
	    options->ignored_unknown);
	എങ്കിൽ (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		തിരികെ -1;
	}
	ac = oac;
	av = oav;

	തിരഞ്ഞെടുപ്പ് (opcode) {
	അവസ്ഥ oBadOption:
		/* don't panic, but count bad options */
		പോകുക out;
	അവസ്ഥ oIgnore:
		argv_consume(&ac);
		നിർത്തുക;
	അവസ്ഥ oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		നിർത്തുക;
	അവസ്ഥ oConnectTimeout:
		intptr = &options->connection_timeout;
parse_time:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			പോകുക out;
		}
		എങ്കിൽ (strcmp(arg, "none") == 0)
			മൂല്യം = -1;
		അല്ലെങ്കിൽ എങ്കിൽ ((മൂല്യം = convtime(arg)) == -1) {
			error("%s line %d: invalid time value.",
			    filename, linenum);
			പോകുക out;
		}
		എങ്കിൽ (*activep && *intptr == -1)
			*intptr = മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			error("%s line %d: missing argument.",
			    filename, linenum);
			പോകുക out;
		}

		മൂല്യം = -1;
		multistate_ptr = multistate_flag;
		വേണ്ടി (i = 0; multistate_ptr[i].താക്കോൽ != ശൂന്യ; i++) {
			എങ്കിൽ (strcasecmp(arg, multistate_ptr[i].താക്കോൽ) == 0) {
				മൂല്യം = multistate_ptr[i].മൂല്യം;
				നിർത്തുക;
			}
		}
		എങ്കിൽ (മൂല്യം != -1) {
			എങ്കിൽ (*activep && *intptr == -1)
				*intptr = മൂല്യം;
			നിർത്തുക;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		എങ്കിൽ (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_path;
		പോകുക parse_agent_path;

	അവസ്ഥ oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_next(&ac, &av);
		എങ്കിൽ ((മൂല്യം = parse_multistate_മൂല്യം(arg, filename, linenum,
		    multistate_ptr)) == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			പോകുക out;
		}
		എങ്കിൽ (*activep && *intptr == -1)
			*intptr = മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		പോകുക parse_flag;

	അവസ്ഥ oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		പോകുക parse_time;

	അവസ്ഥ oGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		പോകുക parse_flag;

	അവസ്ഥ oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		പോകുക parse_flag;

	അവസ്ഥ oPasswordAuthentication:
		intptr = &options->password_authentication;
		പോകുക parse_flag;

	അവസ്ഥ oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		പോകുക parse_flag;

	അവസ്ഥ oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		പോകുക parse_string;

	അവസ്ഥ oPubkeyAuthentication:
		multistate_ptr = multistate_pubkey_auth;
		intptr = &options->pubkey_authentication;
		പോകുക parse_multistate;

	അവസ്ഥ oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		പോകുക parse_flag;

	അവസ്ഥ oGssAuthentication:
		intptr = &options->gss_authentication;
		പോകുക parse_flag;

	അവസ്ഥ oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		പോകുക parse_flag;

	അവസ്ഥ oBatchMode:
		intptr = &options->batch_mode;
		പോകുക parse_flag;

	അവസ്ഥ oCheckHostIP:
		intptr = &options->check_host_ip;
		പോകുക parse_flag;

	അവസ്ഥ o_Verify_Host_താക്കോൽ_DNS:
		intptr = &options->verify_host_താക്കോൽ_dns;
		multistate_ptr = multistate_yesnoask;
		പോകുക parse_multistate;

	അവസ്ഥ o_Strict_Host_താക്കോൽ_Checking:
		intptr = &options->strict_host_താക്കോൽ_checking;
		multistate_ptr = multistate_strict_hostkey;
		പോകുക parse_multistate;

	അവസ്ഥ oCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		പോകുക parse_multistate;

	അവസ്ഥ oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		പോകുക parse_multistate;

	അവസ്ഥ oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		പോകുക parse_flag;

	അവസ്ഥ o_സംഖ്യ_Of_Password_Prompts:
		intptr = &options->സംഖ്യ_of_password_prompts;
		പോകുക parse_int;

	അവസ്ഥ oRekeyLimit:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.", filename,
			    linenum);
			പോകുക out;
		}
		എങ്കിൽ (strcmp(arg, "default") == 0) {
			val64 = 0;
		} അല്ലെങ്കിൽ {
			എങ്കിൽ (scan_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, strerror(errno));
				പോകുക out;
			}
			എങ്കിൽ (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				പോകുക out;
			}
		}
		എങ്കിൽ (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		എങ്കിൽ (ac != 0) { /* optional rekey interval present */
			എങ്കിൽ (strcmp(av[0], "none") == 0) {
				(ശൂന്യം)argv_next(&ac, &av);	/* discard */
				നിർത്തുക;
			}
			intptr = &options->rekey_interval;
			പോകുക parse_time;
		}
		നിർത്തുക;

	അവസ്ഥ oIdentityFile:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			പോകുക out;
		}
		എങ്കിൽ (*activep) {
			intptr = &options->അക്കം_identity_files;
			എങ്കിൽ (*intptr >= SSH_MAX_IDENTITY_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_IDENTITY_FILES);
				പോകുക out;
			}
			add_identity_file(options, ശൂന്യ,
			    arg, flags & SSHCONF_USERCONF);
		}
		നിർത്തുക;

	അവസ്ഥ oCertificateFile:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			പോകുക out;
		}
		എങ്കിൽ (*activep) {
			intptr = &options->അക്കം_certificate_files;
			എങ്കിൽ (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				പോകുക out;
			}
			add_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		നിർത്തുക;

	അവസ്ഥ oXAuthLocation:
		charptr=&options->xauth_location;
		പോകുക parse_string;

	അവസ്ഥ oUser:
		charptr = &options->user;
parse_string:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			പോകുക out;
		}
		എങ്കിൽ (*activep && *charptr == ശൂന്യ)
			*charptr = xstrdup(arg);
		നിർത്തുക;

	അവസ്ഥ oGlobalKnownHostsFile:
		cpptr = (അക്ഷരം **)&options->system_hostfiles;
		uintptr = &options->അക്കം_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		i = 0;
		മൂല്യം = *uintptr == 0; /* was array empty when we started? */
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			എങ്കിൽ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				പോകുക out;
			}
			/* Allow "none" only in first position */
			എങ്കിൽ (strcasecmp(arg, "none") == 0) {
				എങ്കിൽ (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					പോകുക out;
				}
			}
			i++;
			എങ്കിൽ (*activep && മൂല്യം) {
				എങ്കിൽ ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries.", filename, linenum,
					    keyword);
					പോകുക out;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		നിർത്തുക;

	അവസ്ഥ oUserKnownHostsFile:
		cpptr = (അക്ഷരം **)&options->user_hostfiles;
		uintptr = &options->അക്കം_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		പോകുക parse_char_array;

	അവസ്ഥ oHostname:
		charptr = &options->hostname;
		പോകുക parse_string;

	അവസ്ഥ oTag:
		charptr = &options->tag;
		പോകുക parse_string;

	അവസ്ഥ o_Host_താക്കോൽ_Alias:
		charptr = &options->host_താക്കോൽ_alias;
		പോകുക parse_string;

	അവസ്ഥ oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		പോകുക parse_string;

	അവസ്ഥ oBindAddress:
		charptr = &options->bind_address;
		പോകുക parse_string;

	അവസ്ഥ oBindInterface:
		charptr = &options->bind_interface;
		പോകുക parse_string;

	അവസ്ഥ oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		പോകുക parse_string;

	അവസ്ഥ o_Security_താക്കോൽ_Provider:
		charptr = &options->sk_provider;
		പോകുക parse_string;

	അവസ്ഥ oKnownHostsCommand:
		charptr = &options->known_hosts_command;
		പോകുക parse_command;

	അവസ്ഥ oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		എങ്കിൽ (str == ശൂന്യ) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			പോകുക out;
		}
		len = strspn(str, WHITESPACE "=");
		എങ്കിൽ (*activep && *charptr == ശൂന്യ)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		നിർത്തുക;

	അവസ്ഥ oProxyJump:
		എങ്കിൽ (str == ശൂന്യ) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			പോകുക out;
		}
		len = strspn(str, WHITESPACE "=");
		/* XXX use argv? */
		എങ്കിൽ (parse_jump(str + len, options, cmdline, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			പോകുക out;
		}
		argv_consume(&ac);
		നിർത്തുക;

	അവസ്ഥ oPort:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			പോകുക out;
		}
		മൂല്യം = a2port(arg);
		എങ്കിൽ (മൂല്യം <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			പോകുക out;
		}
		എങ്കിൽ (*activep && options->port == -1)
			options->port = മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_next(&ac, &av);
		എങ്കിൽ ((errstr = atoi_err(arg, &മൂല്യം)) != ശൂന്യ) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			പോകുക out;
		}
		എങ്കിൽ (*activep && *intptr == -1)
			*intptr = മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ oCiphers:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			പോകുക out;
		}
		എങ്കിൽ (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			പോകുക out;
		}
		എങ്കിൽ (*activep && options->ciphers == ശൂന്യ)
			options->ciphers = xstrdup(arg);
		നിർത്തുക;

	അവസ്ഥ oMacs:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			പോകുക out;
		}
		എങ്കിൽ (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			പോകുക out;
		}
		എങ്കിൽ (*activep && options->macs == ശൂന്യ)
			options->macs = xstrdup(arg);
		നിർത്തുക;

	അവസ്ഥ oKexAlgorithms:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			പോകുക out;
		}
		എങ്കിൽ (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			പോകുക out;
		}
		എങ്കിൽ (*activep && options->kex_algorithms == ശൂന്യ)
			options->kex_algorithms = xstrdup(arg);
		നിർത്തുക;

	അവസ്ഥ o_Host_താക്കോൽ_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			പോകുക out;
		}
		എങ്കിൽ (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			പോകുക out;
		}
		എങ്കിൽ (*activep && *charptr == ശൂന്യ)
			*charptr = xstrdup(arg);
		നിർത്തുക;

	അവസ്ഥ oCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		പോകുക parse_pubkey_algos;

	അവസ്ഥ oLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		മൂല്യം = log_level_സംഖ്യ(arg);
		എങ്കിൽ (മൂല്യം == SYSLOG_LEVEL_NOT_SET) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			പോകുക out;
		}
		എങ്കിൽ (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_SET)
			*log_level_ptr = (LogLevel) മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		മൂല്യം = log_facility_സംഖ്യ(arg);
		എങ്കിൽ (മൂല്യം == SYSLOG_FACILITY_NOT_SET) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			പോകുക out;
		}
		എങ്കിൽ (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ oLogVerbose:
		cppptr = &options->log_verbose;
		uintptr = &options->അക്കം_log_verbose;
		i = 0;
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			എങ്കിൽ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				പോകുക out;
			}
			/* Allow "none" only in first position */
			എങ്കിൽ (strcasecmp(arg, "none") == 0) {
				എങ്കിൽ (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					പോകുക out;
				}
			}
			i++;
			എങ്കിൽ (*activep && *uintptr == 0) {
				*cppptr = xrecallocarray(*cppptr, *uintptr,
				    *uintptr + 1, വലുപ്പം(**cppptr));
				(*cppptr)[(*uintptr)++] = xstrdup(arg);
			}
		}
		നിർത്തുക;

	അവസ്ഥ oLocalForward:
	അവസ്ഥ oRemoteForward:
	അവസ്ഥ oDynamicForward:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			പോകുക out;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		എങ്കിൽ (!dynamicfwd) {
			arg2 = argv_next(&ac, &av);
			എങ്കിൽ (arg2 == ശൂന്യ || *arg2 == '\0') {
				എങ്കിൽ (remotefwd)
					dynamicfwd = 1;
				അല്ലെങ്കിൽ {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					പോകുക out;
				}
			} അല്ലെങ്കിൽ {
				/* construct a string for parse_forward */
				snprintf(fwdarg, വലുപ്പം(fwdarg), "%s:%s", arg,
				    arg2);
			}
		}
		എങ്കിൽ (dynamicfwd)
			strlcpy(fwdarg, arg, വലുപ്പം(fwdarg));

		എങ്കിൽ (parse_forward(&fwd, fwdarg, dynamicfwd, remotefwd) == 0) {
			error("%.200s line %d: Bad forwarding specification.",
			    filename, linenum);
			പോകുക out;
		}

		എങ്കിൽ (*activep) {
			എങ്കിൽ (remotefwd) {
				add_remote_forward(options, &fwd);
			} അല്ലെങ്കിൽ {
				add_local_forward(options, &fwd);
			}
		}
		നിർത്തുക;

	അവസ്ഥ oPermitRemoteOpen:
		uintptr = &options->അക്കം_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		found = *uintptr == 0;
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			എങ്കിൽ (strcasecmp(arg, "none") == 0 ||
			    strcasecmp(arg, "any") == 0) {
				എങ്കിൽ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					സ്വതന്ത്രം(arg2);
					പോകുക out;
				}
			} അല്ലെങ്കിൽ {
				p = hpdelim(&arg);
				എങ്കിൽ (p == ശൂന്യ) {
					fatal("%s line %d: missing host in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
				}
				p = cleanhostname(p);
				/*
				 * don't want to use permitopen_port to avoid
				 * dependency on channels.[ch] here.
				 */
				എങ്കിൽ (arg == ശൂന്യ || (strcmp(arg, "*") != 0 &&
				    a2port(arg) <= 0)) {
					fatal("%s line %d: bad port number "
					    "in %s", filename, linenum,
					    lookup_opcode_name(opcode));
				}
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg2);
			സ്വതന്ത്രം(arg2);
		}
		എങ്കിൽ (nstrs == 0)
			fatal("%s line %d: missing %s specification",
			    filename, linenum, lookup_opcode_name(opcode));
		എങ്കിൽ (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = ശൂന്യ; /* transferred */
			nstrs = 0;
		}
		നിർത്തുക;

	അവസ്ഥ oClearAllForwardings:
		intptr = &options->clear_forwardings;
		പോകുക parse_flag;

	അവസ്ഥ oHost:
		എങ്കിൽ (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			പോകുക out;
		}
		*activep = 0;
		arg2 = ശൂന്യ;
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			എങ്കിൽ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				പോകുക out;
			}
			എങ്കിൽ ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				നിർത്തുക;
			}
			negated = *arg == '!';
			എങ്കിൽ (negated)
				arg++;
			എങ്കിൽ (match_pattern(host, arg)) {
				എങ്കിൽ (negated) {
					debug("%.200s line %d: Skipping Host "
					    "block because of negated match "
					    "for %.100s", filename, linenum,
					    arg);
					*activep = 0;
					argv_consume(&ac);
					നിർത്തുക;
				}
				എങ്കിൽ (!*activep)
					arg2 = arg; /* logged below */
				*activep = 1;
			}
		}
		എങ്കിൽ (*activep)
			debug("%.200s line %d: Applying options for %.100s",
			    filename, linenum, arg2);
		നിർത്തുക;

	അവസ്ഥ oMatch:
		എങ്കിൽ (cmdline) {
			error("Match directive not supported as a command-line "
			    "option");
			പോകുക out;
		}
		മൂല്യം = match_cfg_വരി(options, str, &ac, &av, pw, host,
		    original_host, remote_command, flags & SSHCONF_FINAL,
		    want_final_pass, filename, linenum);
		എങ്കിൽ (മൂല്യം < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			പോകുക out;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			പോകുക out;
		}
		എങ്കിൽ (strcmp(arg, "none") == 0)
			മൂല്യം = SSH_ESCAPECHAR_NONE;
		അല്ലെങ്കിൽ എങ്കിൽ (arg[1] == '\0')
			മൂല്യം = (u_char) arg[0];
		അല്ലെങ്കിൽ എങ്കിൽ (arg[0] == '^' && arg[2] == 0 &&
		    (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			മൂല്യം = (u_char) arg[1] & 31;
		അല്ലെങ്കിൽ {
			error("%.200s line %d: Bad escape character.",
			    filename, linenum);
			പോകുക out;
		}
		എങ്കിൽ (*activep && *intptr == -1)
			*intptr = മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ oAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
		പോകുക parse_multistate;

	അവസ്ഥ oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		പോകുക parse_flag;

	അവസ്ഥ oIdentitiesOnly:
		intptr = &options->identities_only;
		പോകുക parse_flag;

	അവസ്ഥ oServerAliveInterval:
		intptr = &options->server_alive_interval;
		പോകുക parse_time;

	അവസ്ഥ o_Server_Alive_എണ്ണം_Max:
		intptr = &options->server_alive_എണ്ണം_max;
		പോകുക parse_int;

	അവസ്ഥ oSendEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			എങ്കിൽ (*arg == '\0' || strchr(arg, '=') != ശൂന്യ) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				പോകുക out;
			}
			found = 1;
			എങ്കിൽ (!*activep)
				തുടരുക;
			എങ്കിൽ (*arg == '-') {
				/* Removing an env var */
				rm_env(options, arg, filename, linenum);
				തുടരുക;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->അക്കം_send_env, arg);
		}
		എങ്കിൽ (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		നിർത്തുക;

	അവസ്ഥ oSetEnv:
		found = options->അക്കം_setenv == 0;
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			എങ്കിൽ (strchr(arg, '=') == ശൂന്യ) {
				error("%s line %d: Invalid SetEnv.",
				    filename, linenum);
				പോകുക out;
			}
			എങ്കിൽ (lookup_setenv_in_list(arg, strs, nstrs) != ശൂന്യ) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				തുടരുക;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg);
		}
		എങ്കിൽ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		എങ്കിൽ (found && *activep) {
			options->setenv = strs;
			options->അക്കം_setenv = nstrs;
			strs = ശൂന്യ; /* transferred */
			nstrs = 0;
		}
		നിർത്തുക;

	അവസ്ഥ oControlPath:
		charptr = &options->control_path;
		പോകുക parse_string;

	അവസ്ഥ oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		പോകുക parse_multistate;

	അവസ്ഥ oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing ControlPersist"
			    " argument.", filename, linenum);
			പോകുക out;
		}
		മൂല്യം = 0;
		value2 = 0;	/* timeout */
		എങ്കിൽ (strcmp(arg, "no") == 0 || strcmp(arg, "false") == 0)
			മൂല്യം = 0;
		അല്ലെങ്കിൽ എങ്കിൽ (strcmp(arg, "yes") == 0 || strcmp(arg, "true") == 0)
			മൂല്യം = 1;
		അല്ലെങ്കിൽ എങ്കിൽ ((value2 = convtime(arg)) >= 0)
			മൂല്യം = 1;
		അല്ലെങ്കിൽ {
			error("%.200s line %d: Bad ControlPersist argument.",
			    filename, linenum);
			പോകുക out;
		}
		എങ്കിൽ (*activep && *intptr == -1) {
			*intptr = മൂല്യം;
			options->control_persist_timeout = value2;
		}
		നിർത്തുക;

	അവസ്ഥ oHashKnownHosts:
		intptr = &options->hash_known_hosts;
		പോകുക parse_flag;

	അവസ്ഥ oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		പോകുക parse_multistate;

	അവസ്ഥ oTunnelDevice:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			പോകുക out;
		}
		മൂല്യം = a2tun(arg, &value2);
		എങ്കിൽ (മൂല്യം == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			പോകുക out;
		}
		എങ്കിൽ (*activep && options->tun_local == -1) {
			options->tun_local = മൂല്യം;
			options->tun_remote = value2;
		}
		നിർത്തുക;

	അവസ്ഥ oLocalCommand:
		charptr = &options->local_command;
		പോകുക parse_command;

	അവസ്ഥ oPermitLocalCommand:
		intptr = &options->permit_local_command;
		പോകുക parse_flag;

	അവസ്ഥ oRemoteCommand:
		charptr = &options->remote_command;
		പോകുക parse_command;

	അവസ്ഥ o_Visual_Host_താക്കോൽ:
		intptr = &options->visual_host_താക്കോൽ;
		പോകുക parse_flag;

	അവസ്ഥ oInclude:
		എങ്കിൽ (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			പോകുക out;
		}
		മൂല്യം = 0;
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			എങ്കിൽ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				പോകുക out;
			}
			/* Expand %tokens and environment variables */
			എങ്കിൽ ((p = expand_match_exec_or_include_path(arg,
			    options, pw, host, original_host,
			    flags & SSHCONF_FINAL, 1)) == ശൂന്യ) {
				error("%.200s line %d: Unable to expand user "
				    "config file '%.100s'",
				    filename, linenum, arg);
				തുടരുക;
			}
			/*
			 * Ensure all paths are anchored. User configuration
			 * files may begin with '~/' but system configurations
			 * must not. If the path is relative, then treat it
			 * as living in ~/.ssh for user configurations or
			 * /etc/ssh for system ones.
			 */
			എങ്കിൽ (*p == '~' && (flags & SSHCONF_USERCONF) == 0) {
				error("%.200s line %d: bad include path %s.",
				    filename, linenum, p);
				പോകുക out;
			}
			എങ്കിൽ (!path_absolute(p) && *p != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" _PATH_SSH_USER_DIR : SSHDIR, p);
			} അല്ലെങ്കിൽ {
				arg2 = xstrdup(p);
			}
			സ്വതന്ത്രം(p);
			memset(&gl, 0, വലുപ്പം(gl));
			r = glob(arg2, GLOB_TILDE, ശൂന്യ, &gl);
			എങ്കിൽ (r == GLOB_NOMATCH) {
				debug("%.200s line %d: include %s matched no "
				    "files",filename, linenum, arg2);
				സ്വതന്ത്രം(arg2);
				തുടരുക;
			} അല്ലെങ്കിൽ എങ്കിൽ (r != 0) {
				error("%.200s line %d: glob failed for %s.",
				    filename, linenum, arg2);
				പോകുക out;
			}
			സ്വതന്ത്രം(arg2);
			oactive = *activep;
			വേണ്ടി (i = 0; i < gl.gl_pathc; i++) {
				debug3("%.200s line %d: Including file %s "
				    "depth %d%s", filename, linenum,
				    gl.gl_pathv[i], depth,
				    oactive ? "" : " (parse only)");
				r = read_config_file_depth(gl.gl_pathv[i],
				    pw, host, original_host, remote_command,
				    options, flags | SSHCONF_CHECKPERM |
				    (oactive ? 0 : SSHCONF_NEVERMATCH),
				    activep, want_final_pass, depth + 1);
				എങ്കിൽ (r != 1 && errno != ENOENT) {
					error("%.200s line %d: Can't open user "
					    "config file %.100s: %.100s",
					    filename, linenum, gl.gl_pathv[i],
					    strerror(errno));
					globfree(&gl);
					പോകുക out;
				}
				/*
				 * don't let Match in includes clobber the
				 * containing file's Match state.
				 */
				*activep = oactive;
				എങ്കിൽ (r != 1)
					മൂല്യം = -1;
			}
			globfree(&gl);
		}
		എങ്കിൽ (മൂല്യം != 0)
			ret = മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ oIPQoS:
		arg = argv_next(&ac, &av);
		എങ്കിൽ ((മൂല്യം = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			പോകുക out;
		}
		എങ്കിൽ (മൂല്യം == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			മൂല്യം = INT_MAX;
		}
		arg = argv_next(&ac, &av);
		എങ്കിൽ (arg == ശൂന്യ)
			value2 = മൂല്യം;
		അല്ലെങ്കിൽ എങ്കിൽ ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			പോകുക out;
		}
		എങ്കിൽ (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		എങ്കിൽ (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = മൂല്യം;
			options->ip_qos_bulk = value2;
		}
		നിർത്തുക;

	അവസ്ഥ oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		പോകുക parse_multistate;

	അവസ്ഥ oSessionType:
		intptr = &options->session_type;
		multistate_ptr = multistate_sessiontype;
		പോകുക parse_multistate;

	അവസ്ഥ oStdinNull:
		intptr = &options->stdin_null;
		പോകുക parse_flag;

	അവസ്ഥ oForkAfterAuthentication:
		intptr = &options->fork_after_authentication;
		പോകുക parse_flag;

	അവസ്ഥ oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		പോകുക parse_string;

	അവസ്ഥ oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		പോകുക parse_flag;

	അവസ്ഥ oCanonicalDomains:
		found = options->അക്കം_canonical_domains == 0;
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			/* Allow "none" only in first position */
			എങ്കിൽ (strcasecmp(arg, "none") == 0) {
				എങ്കിൽ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					പോകുക out;
				}
			}
			എങ്കിൽ (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				പോകുക out;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		എങ്കിൽ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		എങ്കിൽ (found && *activep) {
			options->canonical_domains = strs;
			options->അക്കം_canonical_domains = nstrs;
			strs = ശൂന്യ; /* transferred */
			nstrs = 0;
		}
		നിർത്തുക;

	അവസ്ഥ oCanonicalizePermittedCNAMEs:
		found = options->അക്കം_permitted_cnames == 0;
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			എങ്കിൽ (strcasecmp(arg, "none") == 0) {
				എങ്കിൽ (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					പോകുക out;
				}
				arg2 = "";
			} അല്ലെങ്കിൽ എങ്കിൽ (strcmp(arg, "*") == 0) {
				arg2 = arg;
			} അല്ലെങ്കിൽ {
				lowercase(arg);
				എങ്കിൽ ((arg2 = strchr(arg, ':')) == ശൂന്യ ||
				    arg2[1] == '\0') {
					error("%s line %d: "
					    "Invalid permitted CNAME \"%s\"",
					    filename, linenum, arg);
					പോകുക out;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    വലുപ്പം(*cnames));
			cnames[ncnames].source_list = xstrdup(arg);
			cnames[ncnames].target_list = xstrdup(arg2);
			ncnames++;
		}
		എങ്കിൽ (ncnames == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		എങ്കിൽ (found && *activep) {
			options->permitted_cnames = cnames;
			options->അക്കം_permitted_cnames = ncnames;
			cnames = ശൂന്യ; /* transferred */
			ncnames = 0;
		}
		/* un-transferred cnames is cleaned up before exit */
		നിർത്തുക;

	അവസ്ഥ oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		പോകുക parse_multistate;

	അവസ്ഥ oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		പോകുക parse_int;

	അവസ്ഥ oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		പോകുക parse_flag;

	അവസ്ഥ oStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			പോകുക out;
		}
		/* Parse mode in octal format */
		മൂല്യം = strtol(arg, &endofnumber, 8);
		എങ്കിൽ (arg == endofnumber || മൂല്യം < 0 || മൂല്യം > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			പോകുക out;
		}
		എങ്കിൽ (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ oStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		പോകുക parse_flag;

	അവസ്ഥ o_Revoked_Host_താക്കോലുകൾ:
		uintptr = &options->അക്കം_revoked_host_താക്കോലുകൾ;
		cppptr = &options->revoked_host_താക്കോലുകൾ;
		found = *uintptr == 0;
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			എങ്കിൽ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				പോകുക out;
			}
			/* Allow "none" only in first position */
			എങ്കിൽ (strcasecmp(arg, "none") == 0) {
				എങ്കിൽ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					പോകുക out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		എങ്കിൽ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		എങ്കിൽ (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = ശൂന്യ; /* transferred */
			nstrs = 0;
		}
		നിർത്തുക;

	അവസ്ഥ oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			പോകുക out;
		}
		എങ്കിൽ ((മൂല്യം = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			പോകുക out;
		}
		എങ്കിൽ (*activep && *intptr == -1)
			*intptr = മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ oUpdateHostkeys:
		intptr = &options->update_hostkeys;
		multistate_ptr = multistate_yesnoask;
		പോകുക parse_multistate;

	അവസ്ഥ oHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
		പോകുക parse_pubkey_algos;

	അവസ്ഥ oPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		പോകുക parse_pubkey_algos;

	അവസ്ഥ o_Add_താക്കോലുകൾ_To_Agent:
		arg = argv_next(&ac, &av);
		arg2 = argv_next(&ac, &av);
		മൂല്യം = parse_multistate_മൂല്യം(arg, filename, linenum,
		    multistate_yesnoaskconfirm);
		value2 = 0; /* unlimited lifespan by default */
		എങ്കിൽ (മൂല്യം == 3 && arg2 != ശൂന്യ) {
			/* allow "AddKeysToAgent confirm 5m" */
			എങ്കിൽ ((value2 = convtime(arg2)) == -1) {
				error("%s line %d: invalid time value.",
				    filename, linenum);
				പോകുക out;
			}
		} അല്ലെങ്കിൽ എങ്കിൽ (മൂല്യം == -1 && arg2 == ശൂന്യ) {
			എങ്കിൽ ((value2 = convtime(arg)) == -1) {
				error("%s line %d: unsupported option",
				    filename, linenum);
				പോകുക out;
			}
			മൂല്യം = 1; /* yes */
		} അല്ലെങ്കിൽ എങ്കിൽ (മൂല്യം == -1 || arg2 != ശൂന്യ) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			പോകുക out;
		}
		എങ്കിൽ (*activep && options->add_താക്കോലുകൾ_to_agent == -1) {
			options->add_താക്കോലുകൾ_to_agent = മൂല്യം;
			options->add_താക്കോലുകൾ_to_agent_lifespan = value2;
		}
		നിർത്തുക;

	അവസ്ഥ oIdentityAgent:
		charptr = &options->identity_agent;
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			പോകുക out;
		}
  parse_agent_path:
		/* Extra validation if the string represents an env var. */
		എങ്കിൽ ((arg2 = dollar_expand(&r, arg)) == ശൂന്യ || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			പോകുക out;
		}
		സ്വതന്ത്രം(arg2);
		/* check for legacy environment format */
		എങ്കിൽ (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			പോകുക out;
		}
		എങ്കിൽ (*activep && *charptr == ശൂന്യ)
			*charptr = xstrdup(arg);
		നിർത്തുക;

	അവസ്ഥ oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		പോകുക parse_flag;

	അവസ്ഥ oRequiredRSASize:
		intptr = &options->required_rsa_size;
		പോകുക parse_int;

	അവസ്ഥ oWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		പോകുക parse_multistate;

	അവസ്ഥ oObscureKeystrokeTiming:
		മൂല്യം = -1;
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			എങ്കിൽ (മൂല്യം != -1) {
				error("%s line %d: invalid arguments",
				    filename, linenum);
				പോകുക out;
			}
			എങ്കിൽ (strcmp(arg, "yes") == 0 ||
			    strcmp(arg, "true") == 0)
				മൂല്യം = SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
			അല്ലെങ്കിൽ എങ്കിൽ (strcmp(arg, "no") == 0 ||
			    strcmp(arg, "false") == 0)
				മൂല്യം = 0;
			അല്ലെങ്കിൽ എങ്കിൽ (strncmp(arg, "interval:", 9) == 0) {
				എങ്കിൽ ((errstr = atoi_err(arg + 9,
				    &മൂല്യം)) != ശൂന്യ) {
					error("%s line %d: integer value %s.",
					    filename, linenum, errstr);
					പോകുക out;
				}
				എങ്കിൽ (മൂല്യം <= 0 || മൂല്യം > 1000) {
					error("%s line %d: value out of range.",
					    filename, linenum);
					പോകുക out;
				}
			} അല്ലെങ്കിൽ {
				error("%s line %d: unsupported argument \"%s\"",
				    filename, linenum, arg);
				പോകുക out;
			}
		}
		എങ്കിൽ (മൂല്യം == -1) {
			error("%s line %d: missing argument",
			    filename, linenum);
			പോകുക out;
		}
		intptr = &options->obscure_keystroke_timing_interval;
		എങ്കിൽ (*activep && *intptr == -1)
			*intptr = മൂല്യം;
		നിർത്തുക;

	അവസ്ഥ oChannelTimeout:
		found = options->അക്കം_channel_timeouts == 0;
		ആകുമ്പോൾ ((arg = argv_next(&ac, &av)) != ശൂന്യ) {
			/* Allow "none" only in first position */
			എങ്കിൽ (strcasecmp(arg, "none") == 0) {
				എങ്കിൽ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					പോകുക out;
				}
			} അല്ലെങ്കിൽ എങ്കിൽ (parse_pattern_interval(arg,
			    ശൂന്യ, ശൂന്യ) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		എങ്കിൽ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		എങ്കിൽ (found && *activep) {
			options->channel_timeouts = strs;
			options->അക്കം_channel_timeouts = nstrs;
			strs = ശൂന്യ; /* transferred */
			nstrs = 0;
		}
		നിർത്തുക;

	അവസ്ഥ oVersionAddendum:
		എങ്കിൽ (str == ശൂന്യ || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		എങ്കിൽ (strchr(str + len, '\r') != ശൂന്യ) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		എങ്കിൽ ((arg = strchr(വരി, '#')) != ശൂന്യ) {
			*arg = '\0';
			rtrim(വരി);
		}
		എങ്കിൽ (*activep && options->version_addendum == ശൂന്യ) {
			എങ്കിൽ (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			അല്ലെങ്കിൽ
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		നിർത്തുക;

	അവസ്ഥ oRefuseConnection:
		arg = argv_next(&ac, &av);
		എങ്കിൽ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			പോകുക out;
		}
		എങ്കിൽ (*activep) {
			fatal("%.200s line %d: RefuseConnection: %s",
			    filename, linenum, arg);
		}
		നിർത്തുക;

	അവസ്ഥ oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		നിർത്തുക;

	അവസ്ഥ oUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		നിർത്തുക;

	സ്ഥിരസ്ഥിതി:
		error("%s line %d: Unimplemented opcode %d",
		    filename, linenum, opcode);
		പോകുക out;
	}

	/* Check that there is no garbage at end of line. */
	എങ്കിൽ (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		പോകുക out;
	}

	/* success */
	ret = 0;
 out:
	free_canon_cnames(cnames, ncnames);
	opt_array_free2(strs, ശൂന്യ, nstrs);
	argv_free(oav, oac);
	തിരികെ ret;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */
പൂർണ്ണസംഖ്യ
read_config_file(സ്ഥിരം അക്ഷരം *filename, ഘടന passwd *pw, സ്ഥിരം അക്ഷരം *host,
    സ്ഥിരം അക്ഷരം *original_host, സ്ഥിരം അക്ഷരം *remote_command, Options *options, പൂർണ്ണസംഖ്യ flags,
    പൂർണ്ണസംഖ്യ *want_final_pass)
{
	പൂർണ്ണസംഖ്യ active = 1;

	തിരികെ read_config_file_depth(filename, pw, host, original_host,
	    remote_command, options, flags, &active, want_final_pass, 0);
}

#define READCONF_MAX_DEPTH	16
സ്ഥിതം പൂർണ്ണസംഖ്യ
read_config_file_depth(സ്ഥിരം അക്ഷരം *filename, ഘടന passwd *pw,
    സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *original_host, സ്ഥിരം അക്ഷരം *remote_command,
    Options *options, പൂർണ്ണസംഖ്യ flags, പൂർണ്ണസംഖ്യ *activep, പൂർണ്ണസംഖ്യ *want_final_pass, പൂർണ്ണസംഖ്യ depth)
{
	FILE *f;
	അക്ഷരം *വരി = ശൂന്യ;
	size_t linesize = 0;
	പൂർണ്ണസംഖ്യ linenum;
	പൂർണ്ണസംഖ്യ bad_options = 0;

	എങ്കിൽ (depth < 0 || depth > READCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	എങ്കിൽ ((f = fopen(filename, "r")) == ശൂന്യ)
		തിരികെ 0;

	എങ്കിൽ (flags & SSHCONF_CHECKPERM) {
		ഘടന stat sb;

		എങ്കിൽ (fstat(fileno(f), &sb) == -1)
			fatal("fstat %s: %s", filename, strerror(errno));
		എങ്കിൽ (((sb.st_uid != 0 && sb.st_uid != getuid()) ||
		    (sb.st_mode & 022) != 0))
			fatal("Bad owner or permissions on %s", filename);
	}

	debug("Reading configuration data %.200s", filename);

	/*
	 * Mark that we are now processing the options.  This flag is turned
	 * on/off by Host specifications.
	 */
	linenum = 0;
	ആകുമ്പോൾ (getline(&വരി, &linesize, f) != -1) {
		/* Update line number counter. */
		linenum++;
		/*
		 * Trim out comments and strip whitespace.
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages.
		 */
		എങ്കിൽ (process_config_വരി_depth(options, pw, host, original_host,
		    remote_command, വരി, filename, linenum, activep, flags,
		    want_final_pass, depth) != 0)
			bad_options++;
	}
	സ്വതന്ത്രം(വരി);
	fclose(f);
	എങ്കിൽ (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
	തിരികെ 1;
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
പൂർണ്ണസംഖ്യ
option_clear_or_none(സ്ഥിരം അക്ഷരം *o)
{
	തിരികെ o == ശൂന്യ || strcasecmp(o, "none") == 0;
}

/*
 * Returns 1 if CanonicalizePermittedCNAMEs have been specified, 0 otherwise.
 * Allowed to be called on non-final configuration.
 */
പൂർണ്ണസംഖ്യ
config_has_permitted_cnames(Options *options)
{
	എങ്കിൽ (options->അക്കം_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].source_list, "none") == 0 &&
	    strcmp(options->permitted_cnames[0].target_list, "") == 0)
		തിരികെ 0;
	തിരികെ options->അക്കം_permitted_cnames > 0;
}

/*
 * Initializes options to special values that indicate that they have not yet
 * been set.  Read_config_file will only set options with this value. Options
 * are processed in the following order: command line, user config file,
 * system config file.  Last, fill_default_options is called.
 */

ശൂന്യം
initialize_options(Options * options)
{
	memset(options, 'X', വലുപ്പം(*options));
	options->host_arg = ശൂന്യ;
	options->forward_agent = -1;
	options->forward_agent_sock_path = ശൂന്യ;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = ശൂന്യ;
	options->stdio_forward_port = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = ശൂന്യ;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_mask = (mode_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = ശൂന്യ;
	options->hostbased_authentication = -1;
	options->batch_mode = -1;
	options->check_host_ip = -1;
	options->strict_host_താക്കോൽ_checking = -1;
	options->compression = -1;
	options->tcp_keep_alive = -1;
	options->port = -1;
	options->address_family = -1;
	options->connection_attempts = -1;
	options->connection_timeout = -1;
	options->സംഖ്യ_of_password_prompts = -1;
	options->ciphers = ശൂന്യ;
	options->macs = ശൂന്യ;
	options->kex_algorithms = ശൂന്യ;
	options->hostkeyalgorithms = ശൂന്യ;
	options->ca_sign_algorithms = ശൂന്യ;
	options->അക്കം_identity_files = 0;
	memset(options->identity_താക്കോലുകൾ, 0, വലുപ്പം(options->identity_താക്കോലുകൾ));
	options->അക്കം_certificate_files = 0;
	memset(options->certificates, 0, വലുപ്പം(options->certificates));
	options->hostname = ശൂന്യ;
	options->host_താക്കോൽ_alias = ശൂന്യ;
	options->proxy_command = ശൂന്യ;
	options->jump_user = ശൂന്യ;
	options->jump_host = ശൂന്യ;
	options->jump_port = -1;
	options->jump_extra = ശൂന്യ;
	options->user = ശൂന്യ;
	options->escape_char = -1;
	options->അക്കം_system_hostfiles = 0;
	options->അക്കം_user_hostfiles = 0;
	options->local_forwards = ശൂന്യ;
	options->അക്കം_local_forwards = 0;
	options->remote_forwards = ശൂന്യ;
	options->അക്കം_remote_forwards = 0;
	options->permitted_remote_opens = ശൂന്യ;
	options->അക്കം_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
	options->log_level = SYSLOG_LEVEL_NOT_SET;
	options->അക്കം_log_verbose = 0;
	options->log_verbose = ശൂന്യ;
	options->preferred_authentications = ശൂന്യ;
	options->bind_address = ശൂന്യ;
	options->bind_interface = ശൂന്യ;
	options->pkcs11_provider = ശൂന്യ;
	options->sk_provider = ശൂന്യ;
	options->enable_ssh_keysign = -1;
	options->no_host_authentication_for_localhost = -1;
	options->identities_only = -1;
	options->rekey_limit = -1;
	options->rekey_interval = -1;
	options->verify_host_താക്കോൽ_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_എണ്ണം_max = -1;
	options->send_env = ശൂന്യ;
	options->അക്കം_send_env = 0;
	options->setenv = ശൂന്യ;
	options->അക്കം_setenv = 0;
	options->control_path = ശൂന്യ;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_known_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = ശൂന്യ;
	options->permit_local_command = -1;
	options->remote_command = ശൂന്യ;
	options->add_താക്കോലുകൾ_to_agent = -1;
	options->add_താക്കോലുകൾ_to_agent_lifespan = -1;
	options->identity_agent = ശൂന്യ;
	options->visual_host_താക്കോൽ = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = ശൂന്യ;
	options->അക്കം_canonical_domains = 0;
	options->അക്കം_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_താക്കോലുകൾ = ശൂന്യ;
	options->അക്കം_revoked_host_താക്കോലുകൾ = 0;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->hostbased_accepted_algos = ശൂന്യ;
	options->pubkey_accepted_algos = ശൂന്യ;
	options->known_hosts_command = ശൂന്യ;
	options->required_rsa_size = -1;
	options->warn_weak_crypto = -1;
	options->enable_escape_commandline = -1;
	options->obscure_keystroke_timing_interval = -1;
	options->tag = ശൂന്യ;
	options->channel_timeouts = ശൂന്യ;
	options->അക്കം_channel_timeouts = 0;
	options->version_addendum = ശൂന്യ;
}

/*
 * A petite version of fill_default_options() that just fills the options
 * needed for hostname canonicalization to proceed.
 */
ശൂന്യം
fill_default_options_for_canonicalization(Options *options)
{
	എങ്കിൽ (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	എങ്കിൽ (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	എങ്കിൽ (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
}

/*
 * Called after processing other sources of option data, this fills those
 * options for which no value has been specified with their default values.
 */
പൂർണ്ണസംഖ്യ
fill_default_options(Options * options)
{
	അക്ഷരം *all_cipher, *all_mac, *all_kex, *all_താക്കോൽ, *all_sig;
	അക്ഷരം *def_cipher, *def_mac, *def_kex, *def_താക്കോൽ, *def_sig;
	പൂർണ്ണസംഖ്യ ret = -1, r;

	എങ്കിൽ (options->forward_agent == -1)
		options->forward_agent = 0;
	എങ്കിൽ (options->forward_x11 == -1)
		options->forward_x11 = 0;
	എങ്കിൽ (options->forward_x11_trusted == -1)
		options->forward_x11_trusted = 0;
	എങ്കിൽ (options->forward_x11_timeout == -1)
		options->forward_x11_timeout = 1200;
	/*
	 * stdio forwarding (-W) changes the default for these but we defer
	 * setting the values so they can be overridden.
	 */
	എങ്കിൽ (options->exit_on_forward_failure == -1)
		options->exit_on_forward_failure =
		    options->stdio_forward_host != ശൂന്യ ? 1 : 0;
	എങ്കിൽ (options->clear_forwardings == -1)
		options->clear_forwardings =
		    options->stdio_forward_host != ശൂന്യ ? 1 : 0;
	എങ്കിൽ (options->clear_forwardings == 1)
		clear_forwardings(options);

	എങ്കിൽ (options->xauth_location == ശൂന്യ)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	എങ്കിൽ (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	എങ്കിൽ (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	എങ്കിൽ (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	എങ്കിൽ (options->pubkey_authentication == -1)
		options->pubkey_authentication = SSH_PUBKEY_AUTH_ALL;
	എങ്കിൽ (options->gss_authentication == -1)
		options->gss_authentication = 0;
	എങ്കിൽ (options->gss_deleg_creds == -1)
		options->gss_deleg_creds = 0;
	എങ്കിൽ (options->password_authentication == -1)
		options->password_authentication = 1;
	എങ്കിൽ (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	എങ്കിൽ (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	എങ്കിൽ (options->batch_mode == -1)
		options->batch_mode = 0;
	എങ്കിൽ (options->check_host_ip == -1)
		options->check_host_ip = 0;
	എങ്കിൽ (options->strict_host_താക്കോൽ_checking == -1)
		options->strict_host_താക്കോൽ_checking = SSH_STRICT_HOSTKEY_ASK;
	എങ്കിൽ (options->compression == -1)
		options->compression = 0;
	എങ്കിൽ (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = SSH_KEEPALIVES_TRANSPORT;
	എങ്കിൽ (options->port == -1)
		options->port = 0;	/* Filled in ssh_connect. */
	എങ്കിൽ (options->address_family == -1)
		options->address_family = AF_UNSPEC;
	എങ്കിൽ (options->connection_attempts == -1)
		options->connection_attempts = 1;
	എങ്കിൽ (options->സംഖ്യ_of_password_prompts == -1)
		options->സംഖ്യ_of_password_prompts = 3;
	/* options->hostkeyalgorithms, default set in myproposals.h */
	എങ്കിൽ (options->add_താക്കോലുകൾ_to_agent == -1) {
		options->add_താക്കോലുകൾ_to_agent = 0;
		options->add_താക്കോലുകൾ_to_agent_lifespan = 0;
	}
	എങ്കിൽ (options->അക്കം_identity_files == 0) {
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
	എങ്കിൽ (options->escape_char == -1)
		options->escape_char = '~';
	എങ്കിൽ (options->അക്കം_system_hostfiles == 0) {
		options->system_hostfiles[options->അക്കം_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->അക്കം_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE2);
	}
	എങ്കിൽ (options->update_hostkeys == -1) {
		എങ്കിൽ (options->verify_host_താക്കോൽ_dns <= 0 &&
		    (options->അക്കം_user_hostfiles == 0 ||
		    (options->അക്കം_user_hostfiles == 1 && strcmp(options->
		    user_hostfiles[0], _PATH_SSH_USER_HOSTFILE) == 0)))
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_YES;
		അല്ലെങ്കിൽ
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_NO;
	}
	എങ്കിൽ (options->അക്കം_user_hostfiles == 0) {
		options->user_hostfiles[options->അക്കം_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->അക്കം_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE2);
	}
	എങ്കിൽ (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	എങ്കിൽ (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_USER;
	എങ്കിൽ (options->no_host_authentication_for_localhost == -1)
		options->no_host_authentication_for_localhost = 0;
	എങ്കിൽ (options->identities_only == -1)
		options->identities_only = 0;
	എങ്കിൽ (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	എങ്കിൽ (options->rekey_limit == -1)
		options->rekey_limit = 0;
	എങ്കിൽ (options->rekey_interval == -1)
		options->rekey_interval = 0;
	എങ്കിൽ (options->verify_host_താക്കോൽ_dns == -1)
		options->verify_host_താക്കോൽ_dns = 0;
	എങ്കിൽ (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	എങ്കിൽ (options->server_alive_എണ്ണം_max == -1)
		options->server_alive_എണ്ണം_max = 3;
	എങ്കിൽ (options->control_master == -1)
		options->control_master = 0;
	എങ്കിൽ (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	എങ്കിൽ (options->hash_known_hosts == -1)
		options->hash_known_hosts = 0;
	എങ്കിൽ (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	എങ്കിൽ (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	എങ്കിൽ (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	എങ്കിൽ (options->permit_local_command == -1)
		options->permit_local_command = 0;
	എങ്കിൽ (options->visual_host_താക്കോൽ == -1)
		options->visual_host_താക്കോൽ = 0;
	എങ്കിൽ (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	എങ്കിൽ (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	എങ്കിൽ (options->request_tty == -1)
		options->request_tty = REQUEST_TTY_AUTO;
	എങ്കിൽ (options->session_type == -1)
		options->session_type = SESSION_TYPE_DEFAULT;
	എങ്കിൽ (options->stdin_null == -1)
		options->stdin_null = 0;
	എങ്കിൽ (options->fork_after_authentication == -1)
		options->fork_after_authentication = 0;
	എങ്കിൽ (options->proxy_use_fdpass == -1)
		options->proxy_use_fdpass = 0;
	എങ്കിൽ (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	എങ്കിൽ (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	എങ്കിൽ (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
	എങ്കിൽ (options->fingerprint_hash == -1)
		options->fingerprint_hash = SSH_FP_HASH_DEFAULT;
#ifdef ENABLE_SK_INTERNAL
	എങ്കിൽ (options->sk_provider == ശൂന്യ)
		options->sk_provider = xstrdup("internal");
#അല്ലെങ്കിൽ
	എങ്കിൽ (options->sk_provider == ശൂന്യ)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
#endif
	എങ്കിൽ (options->required_rsa_size == -1)
		options->required_rsa_size = SSH_RSA_MINIMUM_MODULUS_SIZE;
	എങ്കിൽ (options->warn_weak_crypto == -1)
		options->warn_weak_crypto = 1;
	എങ്കിൽ (options->enable_escape_commandline == -1)
		options->enable_escape_commandline = 0;
	എങ്കിൽ (options->obscure_keystroke_timing_interval == -1) {
		options->obscure_keystroke_timing_interval =
		    SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
	}

	/* Expand KEX name lists */
	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_താക്കോൽ = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_CLIENT_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_CLIENT_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_CLIENT_KEX, all_kex);
	def_താക്കോൽ = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_താക്കോൽ);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	ചെയ്യുക { \
		എങ്കിൽ ((r = kex_assemble_names(&options->what, \
		    defaults, all)) != 0) { \
			error_fr(r, "%s", #what); \
			പോകുക fail; \
		} \
	} ആകുമ്പോൾ (0)
	options->kex_algorithms_set = options->kex_algorithms != ശൂന്യ;
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostbased_accepted_algos, def_താക്കോൽ, all_താക്കോൽ);
	ASSEMBLE(pubkey_accepted_algos, def_താക്കോൽ, all_താക്കോൽ);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE

#define CLEAR_ON_NONE(v) \
	ചെയ്യുക { \
		എങ്കിൽ (option_clear_or_none(v)) { \
			സ്വതന്ത്രം(v); \
			v = ശൂന്യ; \
		} \
	} ആകുമ്പോൾ(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	ചെയ്യുക { \
		എങ്കിൽ (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			സ്വതന്ത്രം(options->v[0]); \
			സ്വതന്ത്രം(options->v); \
			options->v = ശൂന്യ; \
			options->nv = 0; \
		} \
	} ആകുമ്പോൾ (0)
	CLEAR_ON_NONE(options->local_command);
	CLEAR_ON_NONE(options->remote_command);
	CLEAR_ON_NONE(options->proxy_command);
	CLEAR_ON_NONE(options->control_path);
	CLEAR_ON_NONE(options->pkcs11_provider);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->known_hosts_command);
	CLEAR_ON_NONE_ARRAY(channel_timeouts, അക്കം_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(revoked_host_താക്കോലുകൾ, അക്കം_revoked_host_താക്കോലുകൾ, "none");
#undef CLEAR_ON_NONE
#undef CLEAR_ON_NONE_ARRAY
	എങ്കിൽ (options->jump_host != ശൂന്യ &&
	    strcmp(options->jump_host, "none") == 0 &&
	    options->jump_port == 0 && options->jump_user == ശൂന്യ) {
		സ്വതന്ത്രം(options->jump_host);
		options->jump_host = ശൂന്യ;
	}
	എങ്കിൽ (options->അക്കം_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		സ്വതന്ത്രം(options->permitted_cnames[0].source_list);
		സ്വതന്ത്രം(options->permitted_cnames[0].target_list);
		memset(options->permitted_cnames, '\0',
		    വലുപ്പം(*options->permitted_cnames));
		options->അക്കം_permitted_cnames = 0;
	}
	/* options->identity_agent distinguishes NULL from 'none' */
	/* options->user will be set in the main program if appropriate */
	/* options->hostname will be set in the main program if appropriate */
	/* options->host_key_alias should not be set by default */
	/* options->preferred_authentications will be set in ssh */

	/* success */
	ret = 0;
 fail:
	സ്വതന്ത്രം(all_cipher);
	സ്വതന്ത്രം(all_mac);
	സ്വതന്ത്രം(all_kex);
	സ്വതന്ത്രം(all_താക്കോൽ);
	സ്വതന്ത്രം(all_sig);
	സ്വതന്ത്രം(def_cipher);
	സ്വതന്ത്രം(def_mac);
	സ്വതന്ത്രം(def_kex);
	സ്വതന്ത്രം(def_താക്കോൽ);
	സ്വതന്ത്രം(def_sig);
	തിരികെ ret;
}

ശൂന്യം
free_options(Options *o)
{
	പൂർണ്ണസംഖ്യ i;

	എങ്കിൽ (o == ശൂന്യ)
		തിരികെ;

#define FREE_ARRAY(type, n, a) \
	ചെയ്യുക { \
		type _i; \
		വേണ്ടി (_i = 0; _i < (n); _i++) \
			സ്വതന്ത്രം((a)[_i]); \
	} ആകുമ്പോൾ (0)

	സ്വതന്ത്രം(o->forward_agent_sock_path);
	സ്വതന്ത്രം(o->xauth_location);
	FREE_ARRAY(u_int, o->അക്കം_log_verbose, o->log_verbose);
	സ്വതന്ത്രം(o->log_verbose);
	സ്വതന്ത്രം(o->ciphers);
	സ്വതന്ത്രം(o->macs);
	സ്വതന്ത്രം(o->hostkeyalgorithms);
	സ്വതന്ത്രം(o->kex_algorithms);
	സ്വതന്ത്രം(o->ca_sign_algorithms);
	സ്വതന്ത്രം(o->hostname);
	സ്വതന്ത്രം(o->host_താക്കോൽ_alias);
	സ്വതന്ത്രം(o->proxy_command);
	സ്വതന്ത്രം(o->user);
	FREE_ARRAY(u_int, o->അക്കം_system_hostfiles, o->system_hostfiles);
	FREE_ARRAY(u_int, o->അക്കം_user_hostfiles, o->user_hostfiles);
	സ്വതന്ത്രം(o->preferred_authentications);
	സ്വതന്ത്രം(o->bind_address);
	സ്വതന്ത്രം(o->bind_interface);
	സ്വതന്ത്രം(o->pkcs11_provider);
	സ്വതന്ത്രം(o->sk_provider);
	വേണ്ടി (i = 0; i < o->അക്കം_identity_files; i++) {
		സ്വതന്ത്രം(o->identity_files[i]);
		sshkey_free(o->identity_താക്കോലുകൾ[i]);
	}
	വേണ്ടി (i = 0; i < o->അക്കം_certificate_files; i++) {
		സ്വതന്ത്രം(o->certificate_files[i]);
		sshkey_free(o->certificates[i]);
	}
	സ്വതന്ത്രം(o->identity_agent);
	വേണ്ടി (i = 0; i < o->അക്കം_local_forwards; i++) {
		സ്വതന്ത്രം(o->local_forwards[i].listen_host);
		സ്വതന്ത്രം(o->local_forwards[i].listen_path);
		സ്വതന്ത്രം(o->local_forwards[i].connect_host);
		സ്വതന്ത്രം(o->local_forwards[i].connect_path);
	}
	സ്വതന്ത്രം(o->local_forwards);
	വേണ്ടി (i = 0; i < o->അക്കം_remote_forwards; i++) {
		സ്വതന്ത്രം(o->remote_forwards[i].listen_host);
		സ്വതന്ത്രം(o->remote_forwards[i].listen_path);
		സ്വതന്ത്രം(o->remote_forwards[i].connect_host);
		സ്വതന്ത്രം(o->remote_forwards[i].connect_path);
	}
	സ്വതന്ത്രം(o->remote_forwards);
	സ്വതന്ത്രം(o->stdio_forward_host);
	FREE_ARRAY(u_int, o->അക്കം_send_env, o->send_env);
	സ്വതന്ത്രം(o->send_env);
	FREE_ARRAY(u_int, o->അക്കം_setenv, o->setenv);
	സ്വതന്ത്രം(o->setenv);
	സ്വതന്ത്രം(o->control_path);
	സ്വതന്ത്രം(o->local_command);
	സ്വതന്ത്രം(o->remote_command);
	FREE_ARRAY(പൂർണ്ണസംഖ്യ, o->അക്കം_canonical_domains, o->canonical_domains);
	വേണ്ടി (i = 0; i < o->അക്കം_permitted_cnames; i++) {
		സ്വതന്ത്രം(o->permitted_cnames[i].source_list);
		സ്വതന്ത്രം(o->permitted_cnames[i].target_list);
	}
	FREE_ARRAY(u_int, o->അക്കം_revoked_host_താക്കോലുകൾ, o->revoked_host_താക്കോലുകൾ);
	സ്വതന്ത്രം(o->revoked_host_താക്കോലുകൾ);
	സ്വതന്ത്രം(o->hostbased_accepted_algos);
	സ്വതന്ത്രം(o->pubkey_accepted_algos);
	സ്വതന്ത്രം(o->jump_user);
	സ്വതന്ത്രം(o->jump_host);
	സ്വതന്ത്രം(o->jump_extra);
	സ്വതന്ത്രം(o->ignored_unknown);
	explicit_bzero(o, വലുപ്പം(*o));
#undef FREE_ARRAY
}

ഘടന fwdarg {
	അക്ഷരം *arg;
	പൂർണ്ണസംഖ്യ ispath;
};

/*
 * parse_fwd_field
 * parses the next field in a port forwarding specification.
 * sets fwd to the parsed field and advances p past the colon
 * or sets it to NULL at end of string.
 * returns 0 on success, else non-zero.
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_fwd_field(അക്ഷരം **p, ഘടന fwdarg *fwd)
{
	അക്ഷരം *ep, *cp = *p;
	പൂർണ്ണസംഖ്യ ispath = 0;

	എങ്കിൽ (*cp == '\0') {
		*p = ശൂന്യ;
		തിരികെ -1;	/* end of string */
	}

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	എങ്കിൽ (*cp == '[') {
		/* find matching ']' */
		വേണ്ടി (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++) {
			എങ്കിൽ (*ep == '/')
				ispath = 1;
		}
		/* no matching ']' or not at end of field. */
		എങ്കിൽ (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			തിരികെ -1;
		/* NUL terminate the field and advance p past the colon */
		*ep++ = '\0';
		എങ്കിൽ (*ep != '\0')
			*ep++ = '\0';
		fwd->arg = cp + 1;
		fwd->ispath = ispath;
		*p = ep;
		തിരികെ 0;
	}

	വേണ്ടി (cp = *p; *cp != '\0'; cp++) {
		തിരഞ്ഞെടുപ്പ് (*cp) {
		അവസ്ഥ '\\':
			memmove(cp, cp + 1, strlen(cp + 1) + 1);
			എങ്കിൽ (*cp == '\0')
				തിരികെ -1;
			നിർത്തുക;
		അവസ്ഥ '/':
			ispath = 1;
			നിർത്തുക;
		അവസ്ഥ ':':
			*cp++ = '\0';
			പോകുക done;
		}
	}
done:
	fwd->arg = *p;
	fwd->ispath = ispath;
	*p = cp;
	തിരികെ 0;
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
പൂർണ്ണസംഖ്യ
parse_forward(ഘടന Forward *fwd, സ്ഥിരം അക്ഷരം *fwdspec, പൂർണ്ണസംഖ്യ dynamicfwd, പൂർണ്ണസംഖ്യ remotefwd)
{
	ഘടന fwdarg fwdargs[4];
	അക്ഷരം *p, *cp;
	പൂർണ്ണസംഖ്യ i, err;

	memset(fwd, 0, വലുപ്പം(*fwd));
	memset(fwdargs, 0, വലുപ്പം(fwdargs));

	/*
	 * We expand environment variables before checking if we think they're
	 * paths so that if ${VAR} expands to a fully qualified path it is
	 * treated as a path.
	 */
	cp = p = dollar_expand(&err, fwdspec);
	എങ്കിൽ (p == ശൂന്യ || err)
		തിരികെ 0;

	/* skip leading spaces */
	ആകുമ്പോൾ (isspace((u_char)*cp))
		cp++;

	വേണ്ടി (i = 0; i < 4; ++i) {
		എങ്കിൽ (parse_fwd_field(&cp, &fwdargs[i]) != 0)
			നിർത്തുക;
	}

	/* Check for trailing garbage */
	എങ്കിൽ (cp != ശൂന്യ && *cp != '\0') {
		i = 0;	/* failure */
	}

	തിരഞ്ഞെടുപ്പ് (i) {
	അവസ്ഥ 1:
		എങ്കിൽ (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
		} അല്ലെങ്കിൽ {
			fwd->listen_host = ശൂന്യ;
			fwd->listen_port = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		നിർത്തുക;

	അവസ്ഥ 2:
		എങ്കിൽ (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} അല്ലെങ്കിൽ എങ്കിൽ (fwdargs[1].ispath) {
			fwd->listen_host = ശൂന്യ;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} അല്ലെങ്കിൽ {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		നിർത്തുക;

	അവസ്ഥ 3:
		എങ്കിൽ (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		} അല്ലെങ്കിൽ എങ്കിൽ (fwdargs[2].ispath) {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_path = xstrdup(fwdargs[2].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} അല്ലെങ്കിൽ {
			fwd->listen_host = ശൂന്യ;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		}
		നിർത്തുക;

	അവസ്ഥ 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_port = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_port = a2port(fwdargs[3].arg);
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		i = 0; /* failure */
	}

	സ്വതന്ത്രം(p);

	എങ്കിൽ (dynamicfwd) {
		എങ്കിൽ (!(i == 1 || i == 2))
			പോകുക fail_free;
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (!(i == 3 || i == 4)) {
			എങ്കിൽ (fwd->connect_path == ശൂന്യ &&
			    fwd->listen_path == ശൂന്യ)
				പോകുക fail_free;
		}
		എങ്കിൽ (fwd->connect_port <= 0 && fwd->connect_path == ശൂന്യ)
			പോകുക fail_free;
	}

	എങ്കിൽ ((fwd->listen_port < 0 && fwd->listen_path == ശൂന്യ) ||
	    (!remotefwd && fwd->listen_port == 0))
		പോകുക fail_free;
	എങ്കിൽ (fwd->connect_host != ശൂന്യ &&
	    strlen(fwd->connect_host) >= NI_MAXHOST)
		പോകുക fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	എങ്കിൽ (fwd->connect_path != ശൂന്യ &&
	    strlen(fwd->connect_path) >= PATH_MAX_SUN)
		പോകുക fail_free;
	എങ്കിൽ (fwd->listen_host != ശൂന്യ &&
	    strlen(fwd->listen_host) >= NI_MAXHOST)
		പോകുക fail_free;
	എങ്കിൽ (fwd->listen_path != ശൂന്യ &&
	    strlen(fwd->listen_path) >= PATH_MAX_SUN)
		പോകുക fail_free;

	തിരികെ (i);

 fail_free:
	സ്വതന്ത്രം(fwd->connect_host);
	fwd->connect_host = ശൂന്യ;
	സ്വതന്ത്രം(fwd->connect_path);
	fwd->connect_path = ശൂന്യ;
	സ്വതന്ത്രം(fwd->listen_host);
	fwd->listen_host = ശൂന്യ;
	സ്വതന്ത്രം(fwd->listen_path);
	fwd->listen_path = ശൂന്യ;
	തിരികെ (0);
}

പൂർണ്ണസംഖ്യ
ssh_valid_hostname(സ്ഥിരം അക്ഷരം *s)
{
	size_t i;

	എങ്കിൽ (*s == '-')
		തിരികെ 0;
	വേണ്ടി (i = 0; s[i] != 0; i++) {
		എങ്കിൽ (strchr("'`\"$\\;&<>|(){},", s[i]) != ശൂന്യ ||
		    isspace((u_char)s[i]) || iscntrl((u_char)s[i]))
			തിരികെ 0;
	}
	തിരികെ 1;
}

പൂർണ്ണസംഖ്യ
ssh_valid_ruser(സ്ഥിരം അക്ഷരം *s)
{
	size_t i;

	എങ്കിൽ (*s == '-')
		തിരികെ 0;
	വേണ്ടി (i = 0; s[i] != 0; i++) {
		എങ്കിൽ (iscntrl((u_char)s[i]))
			തിരികെ 0;
		എങ്കിൽ (strchr("'`\";&<>|(){}$\\", s[i]) != ശൂന്യ)
			തിരികെ 0;
		/* Disallow '-' after whitespace */
		എങ്കിൽ (isspace((u_char)s[i]) && s[i + 1] == '-')
			തിരികെ 0;
	}
	തിരികെ 1;
}

പൂർണ്ണസംഖ്യ
parse_jump(സ്ഥിരം അക്ഷരം *s, Options *o, പൂർണ്ണസംഖ്യ strict, പൂർണ്ണസംഖ്യ active)
{
	അക്ഷരം *orig = ശൂന്യ, *sdup = ശൂന്യ, *cp;
	അക്ഷരം *tmp_user = ശൂന്യ, *tmp_host = ശൂന്യ, *host = ശൂന്യ, *user = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, ret = -1, tmp_port = -1, port = -1, first = 1;

	എങ്കിൽ (strcasecmp(s, "none") == 0) {
		എങ്കിൽ (active && o->jump_host == ശൂന്യ) {
			o->jump_host = xstrdup("none");
			o->jump_port = 0;
		}
		തിരികെ 0;
	}

	orig = xstrdup(s);
	എങ്കിൽ ((cp = strchr(orig, '#')) != ശൂന്യ)
		*cp = '\0';
	rtrim(orig);

	active &= o->proxy_command == ശൂന്യ && o->jump_host == ശൂന്യ;
	sdup = xstrdup(orig);
	ചെയ്യുക {
		/* Work backwards through string */
		എങ്കിൽ ((cp = strrchr(sdup, ',')) == ശൂന്യ)
			cp = sdup; /* last */
		അല്ലെങ്കിൽ
			*cp++ = '\0';

		r = parse_ssh_uri(cp, &tmp_user, &tmp_host, &tmp_port);
		എങ്കിൽ (r == -1 || (r == 1 && parse_user_host_port(cp,
		    &tmp_user, &tmp_host, &tmp_port) != 0))
			പോകുക out; /* error already logged */
		എങ്കിൽ (strict) {
			എങ്കിൽ (!ssh_valid_hostname(tmp_host)) {
				error_f("invalid hostname \"%s\"", tmp_host);
				പോകുക out;
			}
			എങ്കിൽ (tmp_user != ശൂന്യ && !ssh_valid_ruser(tmp_user)) {
				error_f("invalid username \"%s\"", tmp_user);
				പോകുക out;
			}
		}
		എങ്കിൽ (first) {
			user = tmp_user;
			host = tmp_host;
			port = tmp_port;
			tmp_user = tmp_host = ശൂന്യ; /* transferred */
		}
		first = 0; /* only check syntax for subsequent hosts */
		സ്വതന്ത്രം(tmp_user);
		സ്വതന്ത്രം(tmp_host);
		tmp_user = tmp_host = ശൂന്യ;
		tmp_port = -1;
	} ആകുമ്പോൾ (cp != sdup);

	/* success */
	എങ്കിൽ (active) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_port = port;
		o->proxy_command = xstrdup("none");
		user = host = ശൂന്യ; /* transferred */
		എങ്കിൽ (orig != ശൂന്യ && (cp = strrchr(orig, ',')) != ശൂന്യ) {
			o->jump_extra = xstrdup(orig);
			o->jump_extra[cp - orig] = '\0';
		}
	}
	ret = 0;
 out:
	സ്വതന്ത്രം(orig);
	സ്വതന്ത്രം(sdup);
	സ്വതന്ത്രം(tmp_user);
	സ്വതന്ത്രം(tmp_host);
	സ്വതന്ത്രം(user);
	സ്വതന്ത്രം(host);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
parse_ssh_uri(സ്ഥിരം അക്ഷരം *uri, അക്ഷരം **userp, അക്ഷരം **hostp, പൂർണ്ണസംഖ്യ *portp)
{
	അക്ഷരം *user = ശൂന്യ, *host = ശൂന്യ, *path = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, port;

	r = parse_uri("ssh", uri, &user, &host, &port, &path);
	എങ്കിൽ (r == 0 && path != ശൂന്യ)
		r = -1;		/* path not allowed */
	എങ്കിൽ (r == 0) {
		എങ്കിൽ (userp != ശൂന്യ) {
			*userp = user;
			user = ശൂന്യ;
		}
		എങ്കിൽ (hostp != ശൂന്യ) {
			*hostp = host;
			host = ശൂന്യ;
		}
		എങ്കിൽ (portp != ശൂന്യ)
			*portp = port;
	}
	സ്വതന്ത്രം(user);
	സ്വതന്ത്രം(host);
	സ്വതന്ത്രം(path);
	തിരികെ r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
സ്ഥിതം സ്ഥിരം അക്ഷരം *
fmt_multistate_int(പൂർണ്ണസംഖ്യ val, സ്ഥിരം ഘടന multistate *m)
{
	u_int i;

	വേണ്ടി (i = 0; m[i].താക്കോൽ != ശൂന്യ; i++) {
		എങ്കിൽ (m[i].മൂല്യം == val)
			തിരികെ m[i].താക്കോൽ;
	}
	തിരികെ "UNKNOWN";
}

സ്ഥിതം സ്ഥിരം അക്ഷരം *
fmt_intarg(OpCodes code, പൂർണ്ണസംഖ്യ val)
{
	എങ്കിൽ (val == -1)
		തിരികെ "unset";
	തിരഞ്ഞെടുപ്പ് (code) {
	അവസ്ഥ oAddressFamily:
		തിരികെ fmt_multistate_int(val, multistate_addressfamily);
	അവസ്ഥ oCompression:
		തിരികെ fmt_multistate_int(val, multistate_compression);
	അവസ്ഥ o_Verify_Host_താക്കോൽ_DNS:
	അവസ്ഥ oUpdateHostkeys:
		തിരികെ fmt_multistate_int(val, multistate_yesnoask);
	അവസ്ഥ o_Strict_Host_താക്കോൽ_Checking:
		തിരികെ fmt_multistate_int(val, multistate_strict_hostkey);
	അവസ്ഥ oControlMaster:
		തിരികെ fmt_multistate_int(val, multistate_controlmaster);
	അവസ്ഥ oTunnel:
		തിരികെ fmt_multistate_int(val, multistate_tunnel);
	അവസ്ഥ oRequestTTY:
		തിരികെ fmt_multistate_int(val, multistate_requesttty);
	അവസ്ഥ oSessionType:
		തിരികെ fmt_multistate_int(val, multistate_sessiontype);
	അവസ്ഥ oCanonicalizeHostname:
		തിരികെ fmt_multistate_int(val, multistate_canonicalizehostname);
	അവസ്ഥ o_Add_താക്കോലുകൾ_To_Agent:
		തിരികെ fmt_multistate_int(val, multistate_yesnoaskconfirm);
	അവസ്ഥ oPubkeyAuthentication:
		തിരികെ fmt_multistate_int(val, multistate_pubkey_auth);
	അവസ്ഥ oTCPKeepAlive:
		തിരികെ fmt_multistate_int(val, multistate_keepalives);
	അവസ്ഥ oFingerprintHash:
		തിരികെ ssh_digest_alg_name(val);
	സ്ഥിരസ്ഥിതി:
		തിരഞ്ഞെടുപ്പ് (val) {
		അവസ്ഥ 0:
			തിരികെ "no";
		അവസ്ഥ 1:
			തിരികെ "yes";
		സ്ഥിരസ്ഥിതി:
			തിരികെ "UNKNOWN";
		}
	}
}

സ്ഥിതം സ്ഥിരം അക്ഷരം *
lookup_opcode_name(OpCodes code)
{
	u_int i;

	വേണ്ടി (i = 0; keywords[i].name != ശൂന്യ; i++)
		എങ്കിൽ (keywords[i].opcode == code)
			തിരികെ(keywords[i].name);
	തിരികെ "UNKNOWN";
}

സ്ഥിതം ശൂന്യം
dump_cfg_int(OpCodes code, പൂർണ്ണസംഖ്യ val)
{
	എങ്കിൽ (code == oObscureKeystrokeTiming) {
		എങ്കിൽ (val == 0) {
			printf("%s no\n", lookup_opcode_name(code));
			തിരികെ;
		} അല്ലെങ്കിൽ എങ്കിൽ (val == SSH_KEYSTROKE_DEFAULT_INTERVAL_MS) {
			printf("%s yes\n", lookup_opcode_name(code));
			തിരികെ;
		}
		/* FALLTHROUGH */
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

സ്ഥിതം ശൂന്യം
dump_cfg_fmtint(OpCodes code, പൂർണ്ണസംഖ്യ val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

സ്ഥിതം ശൂന്യം
dump_cfg_string(OpCodes code, സ്ഥിരം അക്ഷരം *val)
{
	എങ്കിൽ (val == ശൂന്യ)
		തിരികെ;
	printf("%s %s\n", lookup_opcode_name(code), val);
}

സ്ഥിതം ശൂന്യം
dump_cfg_strarray(OpCodes code, u_int എണ്ണം, അക്ഷരം **vals)
{
	u_int i;

	വേണ്ടി (i = 0; i < എണ്ണം; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

സ്ഥിതം ശൂന്യം
dump_cfg_strarray_oneline(OpCodes code, u_int എണ്ണം, അക്ഷരം **vals)
{
	u_int i;

	printf("%s", lookup_opcode_name(code));
	എങ്കിൽ (എണ്ണം == 0)
		printf(" none");
	വേണ്ടി (i = 0; i < എണ്ണം; i++)
		printf(" %s",  vals[i]);
	printf("\n");
}

സ്ഥിതം ശൂന്യം
dump_cfg_forwards(OpCodes code, u_int എണ്ണം, സ്ഥിരം ഘടന Forward *fwds)
{
	സ്ഥിരം ഘടന Forward *fwd;
	u_int i;

	/* oDynamicForward */
	വേണ്ടി (i = 0; i < എണ്ണം; i++) {
		fwd = &fwds[i];
		എങ്കിൽ (code == oDynamicForward && fwd->connect_host != ശൂന്യ &&
		    strcmp(fwd->connect_host, "socks") != 0)
			തുടരുക;
		എങ്കിൽ (code == oLocalForward && fwd->connect_host != ശൂന്യ &&
		    strcmp(fwd->connect_host, "socks") == 0)
			തുടരുക;
		printf("%s", lookup_opcode_name(code));
		എങ്കിൽ (fwd->listen_port == PORT_STREAMLOCAL)
			printf(" %s", fwd->listen_path);
		അല്ലെങ്കിൽ എങ്കിൽ (fwd->listen_host == ശൂന്യ)
			printf(" %d", fwd->listen_port);
		അല്ലെങ്കിൽ {
			printf(" [%s]:%d",
			    fwd->listen_host, fwd->listen_port);
		}
		എങ്കിൽ (code != oDynamicForward) {
			എങ്കിൽ (fwd->connect_port == PORT_STREAMLOCAL)
				printf(" %s", fwd->connect_path);
			അല്ലെങ്കിൽ എങ്കിൽ (fwd->connect_host == ശൂന്യ)
				printf(" %d", fwd->connect_port);
			അല്ലെങ്കിൽ {
				printf(" [%s]:%d",
				    fwd->connect_host, fwd->connect_port);
			}
		}
		printf("\n");
	}
}

ശൂന്യം
dump_client_config(Options *o, സ്ഥിരം അക്ഷരം *host)
{
	പൂർണ്ണസംഖ്യ i, r;
	അക്ഷരം buf[8], *all_താക്കോൽ;

	/*
	 * Expand HostKeyAlgorithms name lists. This isn't handled in
	 * fill_default_options() like the other algorithm lists because
	 * the host key algorithms are by default dynamically chosen based
	 * on the host's keys found in known_hosts.
	 */
	all_താക്കോൽ = sshkey_alg_list(0, 0, 1, ',');
	എങ്കിൽ ((r = kex_assemble_names(&o->hostkeyalgorithms, kex_default_pk_alg(),
	    all_താക്കോൽ)) != 0)
		fatal_fr(r, "expand HostKeyAlgorithms");
	സ്വതന്ത്രം(all_താക്കോൽ);

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
	dump_cfg_fmtint(o_Strict_Host_താക്കോൽ_Checking, o->strict_host_താക്കോൽ_checking);
	dump_cfg_fmtint(oTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(oTunnel, o->tun_open);
	dump_cfg_fmtint(o_Verify_Host_താക്കോൽ_DNS, o->verify_host_താക്കോൽ_dns);
	dump_cfg_fmtint(o_Visual_Host_താക്കോൽ, o->visual_host_താക്കോൽ);
	dump_cfg_fmtint(oUpdateHostkeys, o->update_hostkeys);
	dump_cfg_fmtint(oEnableEscapeCommandline, o->enable_escape_commandline);
	dump_cfg_fmtint(oWarnWeakCrypto, o->warn_weak_crypto);

	/* Integer options */
	dump_cfg_int(oCanonicalizeMaxDots, o->canonicalize_max_dots);
	dump_cfg_int(oConnectionAttempts, o->connection_attempts);
	dump_cfg_int(oForwardX11Timeout, o->forward_x11_timeout);
	dump_cfg_int(o_സംഖ്യ_Of_Password_Prompts, o->സംഖ്യ_of_password_prompts);
	dump_cfg_int(o_Server_Alive_എണ്ണം_Max, o->server_alive_എണ്ണം_max);
	dump_cfg_int(oServerAliveInterval, o->server_alive_interval);
	dump_cfg_int(oRequiredRSASize, o->required_rsa_size);
	dump_cfg_int(oObscureKeystrokeTiming,
	    o->obscure_keystroke_timing_interval);

	/* String options */
	dump_cfg_string(oBindAddress, o->bind_address);
	dump_cfg_string(oBindInterface, o->bind_interface);
	dump_cfg_string(oCiphers, o->ciphers);
	dump_cfg_string(oControlPath, o->control_path);
	dump_cfg_string(o_Host_താക്കോൽ_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(o_Host_താക്കോൽ_Alias, o->host_താക്കോൽ_alias);
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
	dump_cfg_string(o_Security_താക്കോൽ_Provider, o->sk_provider);
	dump_cfg_string(oPreferredAuthentications, o->preferred_authentications);
	dump_cfg_string(oPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
	dump_cfg_string(oXAuthLocation, o->xauth_location);
	dump_cfg_string(oKnownHostsCommand, o->known_hosts_command);
	dump_cfg_string(oTag, o->tag);
	dump_cfg_string(oVersionAddendum, o->version_addendum);

	/* Forwards */
	dump_cfg_forwards(oDynamicForward, o->അക്കം_local_forwards, o->local_forwards);
	dump_cfg_forwards(oLocalForward, o->അക്കം_local_forwards, o->local_forwards);
	dump_cfg_forwards(oRemoteForward, o->അക്കം_remote_forwards, o->remote_forwards);

	/* String array options */
	dump_cfg_strarray(oIdentityFile, o->അക്കം_identity_files, o->identity_files);
	dump_cfg_strarray_oneline(oCanonicalDomains, o->അക്കം_canonical_domains, o->canonical_domains);
	dump_cfg_strarray(oCertificateFile, o->അക്കം_certificate_files, o->certificate_files);
	dump_cfg_strarray_oneline(oGlobalKnownHostsFile, o->അക്കം_system_hostfiles, o->system_hostfiles);
	dump_cfg_strarray_oneline(oUserKnownHostsFile, o->അക്കം_user_hostfiles, o->user_hostfiles);
	dump_cfg_strarray_oneline(o_Revoked_Host_താക്കോലുകൾ, o->അക്കം_revoked_host_താക്കോലുകൾ, o->revoked_host_താക്കോലുകൾ);
	dump_cfg_strarray(oSendEnv, o->അക്കം_send_env, o->send_env);
	dump_cfg_strarray(oSetEnv, o->അക്കം_setenv, o->setenv);
	dump_cfg_strarray_oneline(oLogVerbose,
	    o->അക്കം_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(oChannelTimeout,
	    o->അക്കം_channel_timeouts, o->channel_timeouts);

	/* Special cases */

	/* PermitRemoteOpen */
	എങ്കിൽ (o->അക്കം_permitted_remote_opens == 0)
		printf("%s any\n", lookup_opcode_name(oPermitRemoteOpen));
	അല്ലെങ്കിൽ
		dump_cfg_strarray_oneline(oPermitRemoteOpen,
		    o->അക്കം_permitted_remote_opens, o->permitted_remote_opens);

	/* AddKeysToAgent */
	എങ്കിൽ (o->add_താക്കോലുകൾ_to_agent_lifespan <= 0)
		dump_cfg_fmtint(o_Add_താക്കോലുകൾ_To_Agent, o->add_താക്കോലുകൾ_to_agent);
	അല്ലെങ്കിൽ {
		printf("addkeystoagent%s %d\n",
		    o->add_താക്കോലുകൾ_to_agent == 3 ? " confirm" : "",
		    o->add_താക്കോലുകൾ_to_agent_lifespan);
	}

	/* oForwardAgent */
	എങ്കിൽ (o->forward_agent_sock_path == ശൂന്യ)
		dump_cfg_fmtint(oForwardAgent, o->forward_agent);
	അല്ലെങ്കിൽ
		dump_cfg_string(oForwardAgent, o->forward_agent_sock_path);

	/* oConnectTimeout */
	എങ്കിൽ (o->connection_timeout == -1)
		printf("connecttimeout none\n");
	അല്ലെങ്കിൽ
		dump_cfg_int(oConnectTimeout, o->connection_timeout);

	/* oTunnelDevice */
	printf("tunneldevice");
	എങ്കിൽ (o->tun_local == SSH_TUNID_ANY)
		printf(" any");
	അല്ലെങ്കിൽ
		printf(" %d", o->tun_local);
	എങ്കിൽ (o->tun_remote == SSH_TUNID_ANY)
		printf(":any");
	അല്ലെങ്കിൽ
		printf(":%d", o->tun_remote);
	printf("\n");

	/* oCanonicalizePermittedCNAMEs */
	printf("canonicalizepermittedcnames");
	എങ്കിൽ (o->അക്കം_permitted_cnames == 0)
		printf(" none");
	വേണ്ടി (i = 0; i < o->അക്കം_permitted_cnames; i++) {
		printf(" %s:%s", o->permitted_cnames[i].source_list,
		    o->permitted_cnames[i].target_list);
	}
	printf("\n");

	/* oControlPersist */
	എങ്കിൽ (o->control_persist == 0 || o->control_persist_timeout == 0)
		dump_cfg_fmtint(oControlPersist, o->control_persist);
	അല്ലെങ്കിൽ
		dump_cfg_int(oControlPersist, o->control_persist_timeout);

	/* oEscapeChar */
	എങ്കിൽ (o->escape_char == SSH_ESCAPECHAR_NONE)
		printf("escapechar none\n");
	അല്ലെങ്കിൽ {
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
	എങ്കിൽ (o->jump_host == ശൂന്യ)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	അല്ലെങ്കിൽ {
		/* Check for numeric addresses */
		i = strchr(o->jump_host, ':') != ശൂന്യ ||
		    strspn(o->jump_host, "1234567890.") == strlen(o->jump_host);
		snprintf(buf, വലുപ്പം(buf), "%d", o->jump_port);
		printf("proxyjump %s%s%s%s%s%s%s%s%s\n",
		    /* optional additional jump spec */
		    o->jump_extra == ശൂന്യ ? "" : o->jump_extra,
		    o->jump_extra == ശൂന്യ ? "" : ",",
		    /* optional user */
		    o->jump_user == ശൂന്യ ? "" : o->jump_user,
		    o->jump_user == ശൂന്യ ? "" : "@",
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
