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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/stat.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/wait.h>
#ଅନ୍ତର୍ଭାଵ <sys/un.h>

#ଅନ୍ତର୍ଭାଵ <net/if.h>
#ଅନ୍ତର୍ଭାଵ <netinet/in.h>
#ଅନ୍ତର୍ଭାଵ <netinet/ip.h>
#ଅନ୍ତର୍ଭାଵ <arpa/inet.h>

#ଅନ୍ତର୍ଭାଵ <ctype.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <glob.h>
#ଅନ୍ତର୍ଭାଵ <ifaddrs.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>
#ଅନ୍ତର୍ଭାଵ <netdb.h>
#ଅନ୍ତର୍ଭାଵ <paths.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <util.h>
#ଯଦି defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "cipher.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "readconf.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "mac.h"
#ଅନ୍ତର୍ଭାଵ "myproposal.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "version.h"

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

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା read_config_file_depth(ଅଚଳ ଅକ୍ଷର *filename, ସଂରଚନା passwd *pw,
    ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *original_host, ଅଚଳ ଅକ୍ଷର *remote_command,
    Options *options, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *activep, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *want_final_pass, ପୂର୍ଣ୍ଣସଂଖ୍ୟା depth);
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା process_config_ଧାଡ଼ି_depth(Options *options, ସଂରଚନା passwd *pw,
    ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *original_host, ଅଚଳ ଅକ୍ଷର *remote_command,
    ଅକ୍ଷର *ଧାଡ଼ି, ଅଚଳ ଅକ୍ଷର *filename, ପୂର୍ଣ୍ଣସଂଖ୍ୟା linenum, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *activep, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା *want_final_pass, ପୂର୍ଣ୍ଣସଂଖ୍ୟା depth);

/* Keyword tokens. */

ପ୍ରକାରବ୍ୟାଖ୍ୟା ଗଣନା {
	oBadOption,
	oHost, oMatch, oInclude, oTag,
	oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout,
	oGatewayPorts, oExitOnForwardFailure,
	oPasswordAuthentication,
	oXAuthLocation,
	oIdentityFile, oHostname, oPort, oRemoteForward, oLocalForward,
	oPermitRemoteOpen,
	oCertificateFile, o_Add_ଚାବିଗୁଡ଼ିକ_To_Agent, oIdentityAgent,
	oUser, oEscapeChar, oProxyCommand,
	oGlobalKnownHostsFile, oUserKnownHostsFile, oConnectionAttempts,
	oBatchMode, oCheckHostIP, o_Strict_Host_ଚାବି_Checking, oCompression,
	oTCPKeepAlive, o_ସଂଖ୍ୟା_Of_Password_Prompts,
	oLogFacility, oLogLevel, oLogVerbose, oCiphers, oMacs,
	oPubkeyAuthentication,
	oKbdInteractiveAuthentication, oKbdInteractiveDevices, o_Host_ଚାବି_Alias,
	oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication,
	o_Host_ଚାବି_Algorithms, oBindAddress, oBindInterface, oPKCS11Provider,
	oClearAllForwardings, oNoHostAuthenticationForLocalhost,
	oEnableSSHKeysign, oRekeyLimit, o_Verify_Host_ଚାବି_DNS, oConnectTimeout,
	oAddressFamily, oGssAuthentication, oGssDelegateCreds,
	oServerAliveInterval, o_Server_Alive_ଗଣନା_Max, oIdentitiesOnly,
	oSendEnv, oSetEnv, oControlPath, oControlMaster, oControlPersist,
	oHashKnownHosts,
	oTunnel, oTunnelDevice,
	oLocalCommand, oPermitLocalCommand, oRemoteCommand,
	o_Visual_Host_ଚାବି,
	oKexAlgorithms, oIPQoS, oRequestTTY, oSessionType, oStdinNull,
	oForkAfterAuthentication, oIgnoreUnknown, oProxyUseFdpass,
	oCanonicalDomains, oCanonicalizeHostname, oCanonicalizeMaxDots,
	oCanonicalizeFallbackLocal, oCanonicalizePermittedCNAMEs,
	oStreamLocalBindMask, oStreamLocalBindUnlink, o_Revoked_Host_ଚାବିଗୁଡ଼ିକ,
	oFingerprintHash, oUpdateHostkeys, oHostbasedAcceptedAlgorithms,
	oPubkeyAcceptedAlgorithms, oCASignatureAlgorithms, oProxyJump,
	o_Security_ଚାବି_Provider, oKnownHostsCommand, oRequiredRSASize,
	oEnableEscapeCommandline, oObscureKeystrokeTiming, oChannelTimeout,
	oVersionAddendum, oRefuseConnection, oWarnWeakCrypto,
	oIgnore, oIgnoredUnknownOption, oDeprecated, oUnsupported
} OpCodes;

/* Textual representations of the tokens. */

ସ୍ଥିର ସଂରଚନା {
	ଅଚଳ ଅକ୍ଷର *name;
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
#ଯଦି defined(GSSAPI)
	{ "gssapiauthentication", oGssAuthentication },
	{ "gssapidelegatecredentials", oGssDelegateCreds },
# ଅନ୍ୟଥା
	{ "gssapiauthentication", oUnsupported },
	{ "gssapidelegatecredentials", oUnsupported },
#endif
#ifdef ENABLE_PKCS11
	{ "pkcs11provider", oPKCS11Provider },
	{ "smartcarddevice", oPKCS11Provider },
# ଅନ୍ୟଥା
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
	{ "addkeystoagent", o_Add_ଚାବିଗୁଡ଼ିକ_To_Agent },
	{ "identityagent", oIdentityAgent },
	{ "hostname", oHostname },
	{ "hostkeyalias", o_Host_ଚାବି_Alias },
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
	{ "stricthostkeychecking", o_Strict_Host_ଚାବି_Checking },
	{ "compression", oCompression },
	{ "tcpkeepalive", oTCPKeepAlive },
	{ "keepalive", oTCPKeepAlive },				/* obsolete */
	{ "numberofpasswordprompts", o_ସଂଖ୍ୟା_Of_Password_Prompts },
	{ "syslogfacility", oLogFacility },
	{ "loglevel", oLogLevel },
	{ "logverbose", oLogVerbose },
	{ "dynamicforward", oDynamicForward },
	{ "preferredauthentications", oPreferredAuthentications },
	{ "hostkeyalgorithms", o_Host_ଚାବି_Algorithms },
	{ "casignaturealgorithms", oCASignatureAlgorithms },
	{ "bindaddress", oBindAddress },
	{ "bindinterface", oBindInterface },
	{ "clearallforwardings", oClearAllForwardings },
	{ "enablesshkeysign", oEnableSSHKeysign },
	{ "verifyhostkeydns", o_Verify_Host_ଚାବି_DNS },
	{ "nohostauthenticationforlocalhost", oNoHostAuthenticationForLocalhost },
	{ "rekeylimit", oRekeyLimit },
	{ "connecttimeout", oConnectTimeout },
	{ "addressfamily", oAddressFamily },
	{ "serveraliveinterval", oServerAliveInterval },
	{ "serveralivecountmax", o_Server_Alive_ଗଣନା_Max },
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
	{ "visualhostkey", o_Visual_Host_ଚାବି },
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
	{ "revokedhostkeys", o_Revoked_Host_ଚାବିଗୁଡ଼ିକ },
	{ "fingerprinthash", oFingerprintHash },
	{ "updatehostkeys", oUpdateHostkeys },
	{ "hostbasedacceptedalgorithms", oHostbasedAcceptedAlgorithms },
	{ "hostbasedkeytypes", oHostbasedAcceptedAlgorithms }, /* obsolete */
	{ "pubkeyacceptedalgorithms", oPubkeyAcceptedAlgorithms },
	{ "pubkeyacceptedkeytypes", oPubkeyAcceptedAlgorithms }, /* obsolete */
	{ "ignoreunknown", oIgnoreUnknown },
	{ "proxyjump", oProxyJump },
	{ "securitykeyprovider", o_Security_ଚାବି_Provider },
	{ "knownhostscommand", oKnownHostsCommand },
	{ "requiredrsasize", oRequiredRSASize },
	{ "enableescapecommandline", oEnableEscapeCommandline },
	{ "obscurekeystroketiming", oObscureKeystrokeTiming },
	{ "channeltimeout", oChannelTimeout },
	{ "versionaddendum", oVersionAddendum },
	{ "refuseconnection", oRefuseConnection },
	{ "warnweakcrypto", oWarnWeakCrypto },

	{ ଖାଲି, oBadOption }
};

ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *lookup_opcode_name(OpCodes code);

ଅଚଳ ଅକ୍ଷର *
kex_default_pk_alg(ଶୂନ୍ୟ)
{
	ସ୍ଥିର ଅକ୍ଷର *pkalgs;

	ଯଦି (pkalgs == ଖାଲି) {
		ଅକ୍ଷର *all_ଚାବି;

		all_ଚାବି = sshkey_alg_list(0, 0, 1, ',');
		pkalgs = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_ଚାବି);
		ମୁକ୍ତ(all_ଚାବି);
	}
	ଫେରନ୍ତୁ pkalgs;
}

ଅକ୍ଷର *
ssh_connection_hash(ଅଚଳ ଅକ୍ଷର *thishost, ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *portstr,
    ଅଚଳ ଅକ୍ଷର *user, ଅଚଳ ଅକ୍ଷର *jumphost)
{
	ସଂରଚନା ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_LENGTH];

	ଯଦି ((md = ssh_digest_start(SSH_DIGEST_SHA1)) == ଖାଲି ||
	    ssh_digest_update(md, thishost, strlen(thishost)) < 0 ||
	    ssh_digest_update(md, host, strlen(host)) < 0 ||
	    ssh_digest_update(md, portstr, strlen(portstr)) < 0 ||
	    ssh_digest_update(md, user, strlen(user)) < 0 ||
	    ssh_digest_update(md, jumphost, strlen(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, ଆକାର(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	ଫେରନ୍ତୁ tohex(conn_hash, ssh_digest_bytes(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

ଶୂନ୍ୟ
add_local_forward(Options *options, ଅଚଳ ସଂରଚନା Forward *newfwd)
{
	ସଂରଚନା Forward *fwd;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	/* Don't add duplicates */
	ପାଇଁ (i = 0; i < options->ଅଙ୍କ_local_forwards; i++) {
		ଯଦି (forward_equals(newfwd, options->local_forwards + i))
			ଫେରନ୍ତୁ;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->ଅଙ୍କ_local_forwards + 1,
	    ଆକାର(*options->local_forwards));
	fwd = &options->local_forwards[options->ଅଙ୍କ_local_forwards++];

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

ଶୂନ୍ୟ
add_remote_forward(Options *options, ଅଚଳ ସଂରଚନା Forward *newfwd)
{
	ସଂରଚନା Forward *fwd;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	/* Don't add duplicates */
	ପାଇଁ (i = 0; i < options->ଅଙ୍କ_remote_forwards; i++) {
		ଯଦି (forward_equals(newfwd, options->remote_forwards + i))
			ଫେରନ୍ତୁ;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->ଅଙ୍କ_remote_forwards + 1,
	    ଆକାର(*options->remote_forwards));
	fwd = &options->remote_forwards[options->ଅଙ୍କ_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_port = newfwd->listen_port;
	fwd->listen_path = newfwd->listen_path;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_port = newfwd->connect_port;
	fwd->connect_path = newfwd->connect_path;
	fwd->handle = newfwd->handle;
	fwd->allocated_port = 0;
}

ସ୍ଥିର ଶୂନ୍ୟ
clear_forwardings(Options *options)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ପାଇଁ (i = 0; i < options->ଅଙ୍କ_local_forwards; i++) {
		ମୁକ୍ତ(options->local_forwards[i].listen_host);
		ମୁକ୍ତ(options->local_forwards[i].listen_path);
		ମୁକ୍ତ(options->local_forwards[i].connect_host);
		ମୁକ୍ତ(options->local_forwards[i].connect_path);
	}
	ଯଦି (options->ଅଙ୍କ_local_forwards > 0) {
		ମୁକ୍ତ(options->local_forwards);
		options->local_forwards = ଖାଲି;
	}
	options->ଅଙ୍କ_local_forwards = 0;
	ପାଇଁ (i = 0; i < options->ଅଙ୍କ_remote_forwards; i++) {
		ମୁକ୍ତ(options->remote_forwards[i].listen_host);
		ମୁକ୍ତ(options->remote_forwards[i].listen_path);
		ମୁକ୍ତ(options->remote_forwards[i].connect_host);
		ମୁକ୍ତ(options->remote_forwards[i].connect_path);
	}
	ଯଦି (options->ଅଙ୍କ_remote_forwards > 0) {
		ମୁକ୍ତ(options->remote_forwards);
		options->remote_forwards = ଖାଲି;
	}
	options->ଅଙ୍କ_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

ଶୂନ୍ୟ
add_certificate_file(Options *options, ଅଚଳ ଅକ୍ଷର *path, ପୂର୍ଣ୍ଣସଂଖ୍ୟା userprovided)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (options->ଅଙ୍କ_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	ପାଇଁ (i = 0; i < options->ଅଙ୍କ_certificate_files; i++) {
		ଯଦି (options->certificate_file_userprovided[i] == userprovided &&
		    strcmp(options->certificate_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			ଫେରନ୍ତୁ;
		}
	}

	options->certificate_file_userprovided[options->ଅଙ୍କ_certificate_files] =
	    userprovided;
	options->certificate_files[options->ଅଙ୍କ_certificate_files++] =
	    xstrdup(path);
}

ଶୂନ୍ୟ
add_identity_file(Options *options, ଅଚଳ ଅକ୍ଷର *dir, ଅଚଳ ଅକ୍ଷର *filename,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା userprovided)
{
	ଅକ୍ଷର *path;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (options->ଅଙ୍କ_identity_files >= SSH_MAX_IDENTITY_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_IDENTITY_FILES);

	ଯଦି (dir == ଖାଲି) /* no dir, filename is absolute */
		path = xstrdup(filename);
	ଅନ୍ୟଥା ଯଦି (xasprintf(&path, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", path);

	/* Avoid registering duplicates */
	ପାଇଁ (i = 0; i < options->ଅଙ୍କ_identity_files; i++) {
		ଯଦି (options->identity_file_userprovided[i] == userprovided &&
		    strcmp(options->identity_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			ମୁକ୍ତ(path);
			ଫେରନ୍ତୁ;
		}
	}

	options->identity_file_userprovided[options->ଅଙ୍କ_identity_files] =
	    userprovided;
	options->identity_files[options->ଅଙ୍କ_identity_files++] = path;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
default_ssh_port(ଶୂନ୍ୟ)
{
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା port;
	ସଂରଚନା servent *sp;

	ଯଦି (port == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		port = sp ? ntohs(sp->s_port) : SSH_DEFAULT_PORT;
	}
	ଫେରନ୍ତୁ port;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
execute_in_shell(ଅଚଳ ଅକ୍ଷର *cmd)
{
	ଅକ୍ଷର *shell;
	pid_t pid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା status;

	ଯଦି ((shell = getenv("SHELL")) == ଖାଲି)
		shell = _PATH_BSHELL;

	ଯଦି (access(shell, X_OK) == -1) {
		fatal("Shell \"%s\" is not executable: %s",
		    shell, strerror(errno));
	}

	debug("Executing command: '%.500s'", cmd);

	/* Fork and execute the command. */
	ଯଦି ((pid = fork()) == 0) {
		ଅକ୍ଷର *argv[4];

		ଯଦି (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = xstrdup(cmd);
		argv[3] = ଖାଲି;

		execv(argv[0], argv);
		error("Unable to execute '%.100s': %s", cmd, strerror(errno));
		/* Die with signal to make this error apparent to parent. */
		ssh_signal(SIGTERM, SIG_DFL);
		kill(getpid(), SIGTERM);
		_exit(1);
	}
	/* Parent. */
	ଯଦି (pid == -1)
		fatal_f("fork: %.100s", strerror(errno));

	ଯେତେବେଳେ (waitpid(pid, &status, 0) == -1) {
		ଯଦି (errno != EINTR && errno != EAGAIN)
			fatal_f("waitpid: %s", strerror(errno));
	}
	ଯଦି (!WIFEXITED(status)) {
		error("command '%.100s' exited abnormally", cmd);
		ଫେରନ୍ତୁ -1;
	}
	debug3("command returned status %d", WEXITSTATUS(status));
	ଫେରନ୍ତୁ WEXITSTATUS(status);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check_match_ifaddrs(ଅଚଳ ଅକ୍ଷର *addrlist)
{
#ifdef HAVE_IFADDRS_H
	ସଂରଚନା ifaddrs *ifa, *ifaddrs = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, found = 0;
	ଅକ୍ଷର addr[NI_MAXHOST];
	socklen_t salen;

	ଯଦି (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    strerror(errno));
		ଫେରନ୍ତୁ 0;
	}
	ପାଇଁ (ifa = ifaddrs; ifa != ଖାଲି; ifa = ifa->ifa_next) {
		ଯଦି (ifa->ifa_addr == ଖାଲି || ifa->ifa_name == ଖାଲି ||
		    (ifa->ifa_flags & IFF_UP) == 0)
			ଜାରି;
		ବାଛ (ifa->ifa_addr->sa_family) {
		ସ୍ଥିତି AF_INET:
			salen = ଆକାର(ସଂରଚନା sockaddr_in);
			ଭାଙ୍ଗ;
		ସ୍ଥିତି AF_INET6:
			salen = ଆକାର(ସଂରଚନା sockaddr_in6);
			ଭାଙ୍ଗ;
#ifdef AF_LINK
		ସ୍ଥିତି AF_LINK:
			/* ignore */
			ଜାରି;
#endif /* AF_LINK */
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			debug2_f("interface %s: unsupported address family %d",
			    ifa->ifa_name, ifa->ifa_addr->sa_family);
			ଜାରି;
		}
		ଯଦି ((r = getnameinfo(ifa->ifa_addr, salen, addr, ଆକାର(addr),
		    ଖାଲି, 0, NI_NUMERICHOST)) != 0) {
			debug2_f("interface %s getnameinfo failed: %s",
			    ifa->ifa_name, gai_strerror(r));
			ଜାରି;
		}
		debug3_f("interface %s addr %s", ifa->ifa_name, addr);
		ଯଦି (addr_match_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			found = 1;
			ଭାଙ୍ଗ;
		}
	}
	freeifaddrs(ifaddrs);
	ଫେରନ୍ତୁ found;
#ଅନ୍ୟଥା /* HAVE_IFADDRS_H */
	error("match localnetwork: not supported on this platform");
	ଫେରନ୍ତୁ 0;
#endif /* HAVE_IFADDRS_H */
}

/*
 * Expand a "match exec" command or an Include path, caller must free returned
 * value.
 */
ସ୍ଥିର ଅକ୍ଷର *
expand_match_exec_or_include_path(ଅଚଳ ଅକ୍ଷର *path, Options *options,
    ସଂରଚନା passwd *pw, ଅଚଳ ଅକ୍ଷର *host_arg, ଅଚଳ ଅକ୍ଷର *original_host,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା final_pass, ପୂର୍ଣ୍ଣସଂଖ୍ୟା is_include_path)
{
	ଅକ୍ଷର thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	ଅକ୍ଷର uidstr[32], *conn_hash_hex, *keyalias, *jmphost, *ruser;
	ଅକ୍ଷର *host, *ret;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା port;

	port = options->port <= 0 ? default_ssh_port() : options->port;
	ruser = options->user == ଖାଲି ? pw->pw_name : options->user;
	ଯଦି (final_pass) {
		host = xstrdup(options->hostname);
	} ଅନ୍ୟଥା ଯଦି (options->hostname != ଖାଲି) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (ଅକ୍ଷର *)ଖାଲି);
	} ଅନ୍ୟଥା {
		host = xstrdup(host_arg);
	}
	ଯଦି (gethostname(thishost, ଆକାର(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	jmphost = option_clear_or_none(options->jump_host) ?
	    "" : options->jump_host;
	strlcpy(shorthost, thishost, ଆକାର(shorthost));
	shorthost[strcspn(thishost, ".")] = '\0';
	snprintf(portstr, ଆକାର(portstr), "%d", port);
	snprintf(uidstr, ଆକାର(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	conn_hash_hex = ssh_connection_hash(thishost, host,
	    portstr, ruser, jmphost);
	keyalias = options->host_ଚାବି_alias ?  options->host_ଚାବି_alias : host;

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
	    (ଅକ୍ଷର *)ଖାଲି);
	ମୁକ୍ତ(host);
	ମୁକ୍ତ(conn_hash_hex);
	ଫେରନ୍ତୁ ret;
}

/*
 * Parse and execute a Match directive.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
match_cfg_ଧାଡ଼ି(Options *options, ଅଚଳ ଅକ୍ଷର *full_ଧାଡ଼ି, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *acp, ଅକ୍ଷର ***avp,
    ସଂରଚନା passwd *pw, ଅଚଳ ଅକ୍ଷର *host_arg, ଅଚଳ ଅକ୍ଷର *original_host,
    ଅଚଳ ଅକ୍ଷର *remote_command, ପୂର୍ଣ୍ଣସଂଖ୍ୟା final_pass, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *want_final_pass,
    ଅଚଳ ଅକ୍ଷର *filename, ପୂର୍ଣ୍ଣସଂଖ୍ୟା linenum)
{
	ଅକ୍ଷର *arg, *oattrib = ଖାଲି, *attrib = ଖାଲି, *cmd, *host, *criteria;
	ଅଚଳ ଅକ୍ଷର *ruser;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, this_result, result = 1, attributes = 0, negate;

	/*
	 * Configuration is likely to be incomplete at this point so we
	 * must be prepared to use default values.
	 */
	ruser = options->user == ଖାଲି ? pw->pw_name : options->user;
	ଯଦି (final_pass) {
		host = xstrdup(options->hostname);
	} ଅନ୍ୟଥା ଯଦି (options->hostname != ଖାଲି) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (ଅକ୍ଷର *)ଖାଲି);
	} ଅନ୍ୟଥା {
		host = xstrdup(host_arg);
	}

	debug2("checking match for '%s' host %s originally %s",
	    full_ଧାଡ଼ି, host, original_host);
	ଯେତେବେଳେ ((attrib = argv_next(acp, avp)) != ଖାଲି) {
		/* Terminate on comment */
		ଯଦି (*attrib == '#') {
			argv_consume(acp);
			ଭାଙ୍ଗ;
		}
		attrib = oattrib = xstrdup(attrib);
		arg = criteria = ଖାଲି;
		this_result = 1;
		ଯଦି ((negate = (attrib[0] == '!')))
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		ଯଦି (strcasecmp(attrib, "all") == 0) {
			ଯଦି (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != ଖାଲି &&
			    *arg != '\0' && *arg != '#')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				result = -1;
				ଯାଅ out;
			}
			ଯଦି (arg != ଖାଲି && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			ଯଦି (result)
				result = negate ? 0 : 1;
			ଯାଅ out;
		}
		attributes++;
		/* criteria "final" and "canonical" have no argument */
		ଯଦି (strcasecmp(attrib, "canonical") == 0 ||
		    strcasecmp(attrib, "final") == 0) {
			/*
			 * If the config requests "Match final" without
			 * negation then remember this so we can perform a
			 * second pass later.
			 */
			ଯଦି (strcasecmp(attrib, "final") == 0 &&
			    want_final_pass != ଖାଲି)
				*want_final_pass |= !negate;
			r = !!final_pass;  /* force bitmask member to boolean */
			ଯଦି (r == (negate ? 1 : 0))
				this_result = result = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_result ? "" : "not ", oattrib);
			ଯାଅ next;
		}

		/* Keep this list in sync with below */
		ଯଦି (strprefix(attrib, "host=", 1)  != ଖାଲି ||
		    strprefix(attrib, "originalhost=", 1) != ଖାଲି ||
		    strprefix(attrib, "user=", 1) != ଖାଲି ||
		    strprefix(attrib, "localuser=", 1) != ଖାଲି ||
		    strprefix(attrib, "localnetwork=", 1) != ଖାଲି ||
		    strprefix(attrib, "version=", 1) != ଖାଲି ||
		    strprefix(attrib, "tagged=", 1) != ଖାଲି ||
		    strprefix(attrib, "command=", 1) != ଖାଲି ||
		    strprefix(attrib, "exec=", 1) != ଖାଲି) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} ଅନ୍ୟଥା ଯଦି ((arg = argv_next(acp, avp)) == ଖାଲି) {
			error("%.200s line %d: missing argument for Match '%s'",
			    filename, linenum, oattrib);
			result = -1;
			ଯାଅ out;
		}

		/*
		 * All other criteria require an argument, though it may
		 * be the empty string for the "tagged" and "command"
		 * options.
		 */
		ଯଦି (*arg == '\0' &&
		    strcasecmp(attrib, "tagged") != 0 &&
		    strcasecmp(attrib, "command") != 0)
			arg = ଖାଲି;
		ଯଦି (arg == ଖାଲି || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			ଯାଅ out;
		}
		ଯଦି (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = match_hostname(host, arg) == 1;
			ଯଦି (r == (negate ? 1 : 0))
				this_result = result = 0;
		} ଅନ୍ୟଥା ଯଦି (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = match_hostname(original_host, arg) == 1;
			ଯଦି (r == (negate ? 1 : 0))
				this_result = result = 0;
		} ଅନ୍ୟଥା ଯଦି (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = match_pattern_list(ruser, arg, 0) == 1;
			ଯଦି (r == (negate ? 1 : 0))
				this_result = result = 0;
		} ଅନ୍ୟଥା ଯଦି (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = match_pattern_list(pw->pw_name, arg, 0) == 1;
			ଯଦି (r == (negate ? 1 : 0))
				this_result = result = 0;
		} ଅନ୍ୟଥା ଯଦି (strcasecmp(attrib, "localnetwork") == 0) {
			ଯଦି (addr_match_cidr_list(ଖାଲି, arg) == -1) {
				/* Error already printed */
				result = -1;
				ଯାଅ out;
			}
			r = check_match_ifaddrs(arg) == 1;
			ଯଦି (r == (negate ? 1 : 0))
				this_result = result = 0;
		} ଅନ୍ୟଥା ଯଦି (strcasecmp(attrib, "version") == 0) {
			criteria = xstrdup(SSH_RELEASE);
			r = match_pattern_list(SSH_RELEASE, arg, 0) == 1;
			ଯଦି (r == (negate ? 1 : 0))
				this_result = result = 0;
		} ଅନ୍ୟଥା ଯଦି (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->tag == ଖାଲି ? "" :
			    options->tag);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			ଯଦି (r == (negate ? 1 : 0))
				this_result = result = 0;
		} ଅନ୍ୟଥା ଯଦି (strcasecmp(attrib, "command") == 0) {
			criteria = xstrdup(remote_command == ଖାଲି ?
			    "" : remote_command);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			ଯଦି (r == (negate ? 1 : 0))
				this_result = result = 0;
		} ଅନ୍ୟଥା ଯଦି (strcasecmp(attrib, "sessiontype") == 0) {
			ଯଦି (options->session_type == SESSION_TYPE_SUBSYSTEM)
				criteria = xstrdup("subsystem");
			ଅନ୍ୟଥା ଯଦି (options->session_type == SESSION_TYPE_NONE)
				criteria = xstrdup("none");
			ଅନ୍ୟଥା ଯଦି (remote_command != ଖାଲି &&
			    *remote_command != '\0')
				criteria = xstrdup("exec");
			ଅନ୍ୟଥା
				criteria = xstrdup("shell");
			r = match_pattern_list(criteria, arg, 0) == 1;
			ଯଦି (r == (negate ? 1 : 0))
				this_result = result = 0;
		} ଅନ୍ୟଥା ଯଦି (strcasecmp(attrib, "exec") == 0) {
			ଯଦି ((cmd = expand_match_exec_or_include_path(arg,
			    options, pw, host_arg, original_host,
			    final_pass, 0)) == ଖାଲି) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			ଯଦି (result != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				ମୁକ୍ତ(cmd);
				ଯାଅ next;
			}
			r = execute_in_shell(cmd);
			ଯଦି (r == -1) {
				fatal("%.200s line %d: match exec "
				    "'%.100s' error", filename,
				    linenum, cmd);
			}
			criteria = xstrdup(cmd);
			ମୁକ୍ତ(cmd);
			/* Force exit status to boolean */
			r = r == 0;
			ଯଦି (r == (negate ? 1 : 0))
				this_result = result = 0;
		} ଅନ୍ୟଥା {
			error("Unsupported Match attribute %s", attrib);
			result = -1;
			ଯାଅ out;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s' ",
		    filename, linenum, this_result ? "": "not ", oattrib,
		    criteria == ଖାଲି ? "" : " \"",
		    criteria == ଖାଲି ? "" : criteria,
		    criteria == ଖାଲି ? "" : "\"");
 next:
		ମୁକ୍ତ(criteria);
		ମୁକ୍ତ(oattrib);
		oattrib = attrib = ଖାଲି;
	}
	ଯଦି (attributes == 0) {
		error("One or more attributes required for Match");
		result = -1;
		ଯାଅ out;
	}
 out:
	ଯଦି (result != -1)
		debug2("match %sfound", result ? "" : "not ");
	ମୁକ୍ତ(oattrib);
	ମୁକ୍ତ(host);
	ଫେରନ୍ତୁ result;
}

/* Remove environment variable by pattern */
ସ୍ଥିର ଶୂନ୍ୟ
rm_env(Options *options, ଅଚଳ ଅକ୍ଷର *arg, ଅଚଳ ଅକ୍ଷର *filename, ପୂର୍ଣ୍ଣସଂଖ୍ୟା linenum)
{
	u_int i, j, onum_send_env = options->ଅଙ୍କ_send_env;

	/* Remove an environment variable */
	ପାଇଁ (i = 0; i < options->ଅଙ୍କ_send_env; ) {
		ଯଦି (!match_pattern(options->send_env[i], arg + 1)) {
			i++;
			ଜାରି;
		}
		debug3("%s line %d: removing environment %s",
		    filename, linenum, options->send_env[i]);
		ମୁକ୍ତ(options->send_env[i]);
		options->send_env[i] = ଖାଲି;
		ପାଇଁ (j = i; j < options->ଅଙ୍କ_send_env - 1; j++) {
			options->send_env[j] = options->send_env[j + 1];
			options->send_env[j + 1] = ଖାଲି;
		}
		options->ଅଙ୍କ_send_env--;
		/* NB. don't increment i */
	}
	ଯଦି (onum_send_env != options->ଅଙ୍କ_send_env) {
		options->send_env = xrecallocarray(options->send_env,
		    onum_send_env, options->ଅଙ୍କ_send_env,
		    ଆକାର(*options->send_env));
	}
}

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */
ସ୍ଥିର OpCodes
parse_token(ଅଚଳ ଅକ୍ଷର *cp, ଅଚଳ ଅକ୍ଷର *filename, ପୂର୍ଣ୍ଣସଂଖ୍ୟା linenum,
    ଅଚଳ ଅକ୍ଷର *ignored_unknown)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ପାଇଁ (i = 0; keywords[i].name; i++)
		ଯଦି (strcmp(cp, keywords[i].name) == 0)
			ଫେରନ୍ତୁ keywords[i].opcode;
	ଯଦି (ignored_unknown != ଖାଲି &&
	    match_pattern_list(cp, ignored_unknown, 1) == 1)
		ଫେରନ୍ତୁ oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	ଫେରନ୍ତୁ oBadOption;
}

ସ୍ଥିର ଶୂନ୍ୟ
free_canon_cnames(ସଂରଚନା allowed_cname *cnames, u_int n)
{
	u_int i;

	ଯଦି (cnames == ଖାଲି || n == 0)
		ଫେରନ୍ତୁ;
	ପାଇଁ (i = 0; i < n; i++) {
		ମୁକ୍ତ(cnames[i].source_list);
		ମୁକ୍ତ(cnames[i].target_list);
	}
	ମୁକ୍ତ(cnames);
}

/* Multistate option parsing */
ସଂରଚନା multistate {
	ଅକ୍ଷର *ଚାବି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ମୂଲ୍ୟ;
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_flag[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ ଖାଲି, -1 }
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_yesnoask[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ ଖାଲି, -1 }
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_strict_hostkey[] = {
	{ "true",			SSH_STRICT_HOSTKEY_YES },
	{ "false",			SSH_STRICT_HOSTKEY_OFF },
	{ "yes",			SSH_STRICT_HOSTKEY_YES },
	{ "no",				SSH_STRICT_HOSTKEY_OFF },
	{ "ask",			SSH_STRICT_HOSTKEY_ASK },
	{ "off",			SSH_STRICT_HOSTKEY_OFF },
	{ "accept-new",			SSH_STRICT_HOSTKEY_NEW },
	{ ଖାଲି, -1 }
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_yesnoaskconfirm[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "confirm",			3 },
	{ ଖାଲି, -1 }
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ ଖାଲି, -1 }
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_controlmaster[] = {
	{ "true",			SSHCTL_MASTER_YES },
	{ "yes",			SSHCTL_MASTER_YES },
	{ "false",			SSHCTL_MASTER_NO },
	{ "no",				SSHCTL_MASTER_NO },
	{ "auto",			SSHCTL_MASTER_AUTO },
	{ "ask",			SSHCTL_MASTER_ASK },
	{ "autoask",			SSHCTL_MASTER_AUTO_ASK },
	{ ଖାଲି, -1 }
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET },
	{ "point-to-point",		SSH_TUNMODE_POINTOPOINT },
	{ "true",			SSH_TUNMODE_DEFAULT },
	{ "yes",			SSH_TUNMODE_DEFAULT },
	{ "false",			SSH_TUNMODE_NO },
	{ "no",				SSH_TUNMODE_NO },
	{ ଖାଲି, -1 }
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_requesttty[] = {
	{ "true",			REQUEST_TTY_YES },
	{ "yes",			REQUEST_TTY_YES },
	{ "false",			REQUEST_TTY_NO },
	{ "no",				REQUEST_TTY_NO },
	{ "force",			REQUEST_TTY_FORCE },
	{ "auto",			REQUEST_TTY_AUTO },
	{ ଖାଲି, -1 }
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_sessiontype[] = {
	{ "none",			SESSION_TYPE_NONE },
	{ "subsystem",			SESSION_TYPE_SUBSYSTEM },
	{ "default",			SESSION_TYPE_DEFAULT },
	{ ଖାଲି, -1 }
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_canonicalizehostname[] = {
	{ "true",			SSH_CANONICALISE_YES },
	{ "false",			SSH_CANONICALISE_NO },
	{ "yes",			SSH_CANONICALISE_YES },
	{ "no",				SSH_CANONICALISE_NO },
	{ "always",			SSH_CANONICALISE_ALWAYS },
	{ ଖାଲି, -1 }
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_pubkey_auth[] = {
	{ "true",			SSH_PUBKEY_AUTH_ALL },
	{ "false",			SSH_PUBKEY_AUTH_NO },
	{ "yes",			SSH_PUBKEY_AUTH_ALL },
	{ "no",				SSH_PUBKEY_AUTH_NO },
	{ "unbound",			SSH_PUBKEY_AUTH_UNBOUND },
	{ "host-bound",			SSH_PUBKEY_AUTH_HBOUND },
	{ ଖାଲି, -1 }
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ ଖାଲି, -1 }
};
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ ଖାଲି, -1 }
};
/* XXX this will need to be replaced with a bitmask if we add more flags */
ସ୍ଥିର ଅଚଳ ସଂରଚନା multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ ଖାଲି, -1 }
};

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_multistate_ମୂଲ୍ୟ(ଅଚଳ ଅକ୍ଷର *arg, ଅଚଳ ଅକ୍ଷର *filename, ପୂର୍ଣ୍ଣସଂଖ୍ୟା linenum,
    ଅଚଳ ସଂରଚନା multistate *multistate_ptr)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (!arg || *arg == '\0') {
		error("%s line %d: missing argument.", filename, linenum);
		ଫେରନ୍ତୁ -1;
	}
	ପାଇଁ (i = 0; multistate_ptr[i].ଚାବି != ଖାଲି; i++) {
		ଯଦି (strcasecmp(arg, multistate_ptr[i].ଚାବି) == 0)
			ଫେରନ୍ତୁ multistate_ptr[i].ମୂଲ୍ୟ;
	}
	ଫେରନ୍ତୁ -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
process_config_ଧାଡ଼ି(Options *options, ସଂରଚନା passwd *pw, ଅଚଳ ଅକ୍ଷର *host,
    ଅଚଳ ଅକ୍ଷର *original_host, ଅଚଳ ଅକ୍ଷର *remote_command, ଅକ୍ଷର *ଧାଡ଼ି,
    ଅଚଳ ଅକ୍ଷର *filename, ପୂର୍ଣ୍ଣସଂଖ୍ୟା linenum, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *activep, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags)
{
	ଫେରନ୍ତୁ process_config_ଧାଡ଼ି_depth(options, pw, host, original_host,
	    remote_command, ଧାଡ଼ି, filename, linenum, activep, flags, ଖାଲି, 0);
}

#define WHITESPACE " \t\r\n"
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
process_config_ଧାଡ଼ି_depth(Options *options, ସଂରଚନା passwd *pw, ଅଚଳ ଅକ୍ଷର *host,
    ଅଚଳ ଅକ୍ଷର *original_host, ଅଚଳ ଅକ୍ଷର *remote_command, ଅକ୍ଷର *ଧାଡ଼ି,
    ଅଚଳ ଅକ୍ଷର *filename, ପୂର୍ଣ୍ଣସଂଖ୍ୟା linenum, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *activep, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା *want_final_pass, ପୂର୍ଣ୍ଣସଂଖ୍ୟା depth)
{
	ଅକ୍ଷର *str, **charptr, *endofnumber, *keyword, *arg, *arg2, *p;
	ଅକ୍ଷର **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, oactive, negated, opcode, *intptr, ମୂଲ୍ୟ, value2, cmdline = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା remotefwd, dynamicfwd, ca_only = 0, found = 0;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	long long val64;
	size_t len;
	ସଂରଚନା Forward fwd;
	ଅଚଳ ସଂରଚନା multistate *multistate_ptr;
	glob_t gl;
	ଅଚଳ ଅକ୍ଷର *errstr;
	ଅକ୍ଷର **oav = ଖାଲି, **av;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା oac = 0, ac;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;
	ସଂରଚନା allowed_cname *cnames = ଖାଲି;
	u_int ncnames = 0;
	ଅକ୍ଷର **strs = ଖାଲି; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	ଯଦି (activep == ଖାଲି) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	ଯଦି ((len = strlen(ଧାଡ଼ି)) == 0)
		ଫେରନ୍ତୁ 0;
	ପାଇଁ (len--; len > 0; len--) {
		ଯଦି (strchr(WHITESPACE "\f", ଧାଡ଼ି[len]) == ଖାଲି)
			ଭାଙ୍ଗ;
		ଧାଡ଼ି[len] = '\0';
	}

	str = ଧାଡ଼ି;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	ଯଦି ((keyword = strdelim(&str)) == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	/* Ignore leading whitespace. */
	ଯଦି (*keyword == '\0')
		keyword = strdelim(&str);
	ଯଦି (keyword == ଖାଲି || !*keyword || *keyword == '\n' || *keyword == '#')
		ଫେରନ୍ତୁ 0;
	/* Match lowercase keyword */
	lowercase(keyword);

	/* Prepare to parse remainder of line */
	ଯଦି (str != ଖାଲି)
		str += strspn(str, WHITESPACE);
	ଯଦି (str == ଖାଲି || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		ଫେରନ୍ତୁ -1;
	}
	opcode = parse_token(keyword, filename, linenum,
	    options->ignored_unknown);
	ଯଦି (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		ଫେରନ୍ତୁ -1;
	}
	ac = oac;
	av = oav;

	ବାଛ (opcode) {
	ସ୍ଥିତି oBadOption:
		/* don't panic, but count bad options */
		ଯାଅ out;
	ସ୍ଥିତି oIgnore:
		argv_consume(&ac);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		ଭାଙ୍ଗ;
	ସ୍ଥିତି oConnectTimeout:
		intptr = &options->connection_timeout;
parse_time:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			ଯାଅ out;
		}
		ଯଦି (strcmp(arg, "none") == 0)
			ମୂଲ୍ୟ = -1;
		ଅନ୍ୟଥା ଯଦି ((ମୂଲ୍ୟ = convtime(arg)) == -1) {
			error("%s line %d: invalid time value.",
			    filename, linenum);
			ଯାଅ out;
		}
		ଯଦି (*activep && *intptr == -1)
			*intptr = ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			error("%s line %d: missing argument.",
			    filename, linenum);
			ଯାଅ out;
		}

		ମୂଲ୍ୟ = -1;
		multistate_ptr = multistate_flag;
		ପାଇଁ (i = 0; multistate_ptr[i].ଚାବି != ଖାଲି; i++) {
			ଯଦି (strcasecmp(arg, multistate_ptr[i].ଚାବି) == 0) {
				ମୂଲ୍ୟ = multistate_ptr[i].ମୂଲ୍ୟ;
				ଭାଙ୍ଗ;
			}
		}
		ଯଦି (ମୂଲ୍ୟ != -1) {
			ଯଦି (*activep && *intptr == -1)
				*intptr = ମୂଲ୍ୟ;
			ଭାଙ୍ଗ;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		ଯଦି (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_path;
		ଯାଅ parse_agent_path;

	ସ୍ଥିତି oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_next(&ac, &av);
		ଯଦି ((ମୂଲ୍ୟ = parse_multistate_ମୂଲ୍ୟ(arg, filename, linenum,
		    multistate_ptr)) == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			ଯାଅ out;
		}
		ଯଦି (*activep && *intptr == -1)
			*intptr = ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		ଯାଅ parse_flag;

	ସ୍ଥିତି oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		ଯାଅ parse_time;

	ସ୍ଥିତି oGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		ଯାଅ parse_flag;

	ସ୍ଥିତି oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		ଯାଅ parse_flag;

	ସ୍ଥିତି oPasswordAuthentication:
		intptr = &options->password_authentication;
		ଯାଅ parse_flag;

	ସ୍ଥିତି oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		ଯାଅ parse_flag;

	ସ୍ଥିତି oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		ଯାଅ parse_string;

	ସ୍ଥିତି oPubkeyAuthentication:
		multistate_ptr = multistate_pubkey_auth;
		intptr = &options->pubkey_authentication;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		ଯାଅ parse_flag;

	ସ୍ଥିତି oGssAuthentication:
		intptr = &options->gss_authentication;
		ଯାଅ parse_flag;

	ସ୍ଥିତି oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		ଯାଅ parse_flag;

	ସ୍ଥିତି oBatchMode:
		intptr = &options->batch_mode;
		ଯାଅ parse_flag;

	ସ୍ଥିତି oCheckHostIP:
		intptr = &options->check_host_ip;
		ଯାଅ parse_flag;

	ସ୍ଥିତି o_Verify_Host_ଚାବି_DNS:
		intptr = &options->verify_host_ଚାବି_dns;
		multistate_ptr = multistate_yesnoask;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି o_Strict_Host_ଚାବି_Checking:
		intptr = &options->strict_host_ଚାବି_checking;
		multistate_ptr = multistate_strict_hostkey;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି oCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		ଯାଅ parse_flag;

	ସ୍ଥିତି o_ସଂଖ୍ୟା_Of_Password_Prompts:
		intptr = &options->ସଂଖ୍ୟା_of_password_prompts;
		ଯାଅ parse_int;

	ସ୍ଥିତି oRekeyLimit:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.", filename,
			    linenum);
			ଯାଅ out;
		}
		ଯଦି (strcmp(arg, "default") == 0) {
			val64 = 0;
		} ଅନ୍ୟଥା {
			ଯଦି (scan_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, strerror(errno));
				ଯାଅ out;
			}
			ଯଦି (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				ଯାଅ out;
			}
		}
		ଯଦି (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		ଯଦି (ac != 0) { /* optional rekey interval present */
			ଯଦି (strcmp(av[0], "none") == 0) {
				(ଶୂନ୍ୟ)argv_next(&ac, &av);	/* discard */
				ଭାଙ୍ଗ;
			}
			intptr = &options->rekey_interval;
			ଯାଅ parse_time;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oIdentityFile:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ଯାଅ out;
		}
		ଯଦି (*activep) {
			intptr = &options->ଅଙ୍କ_identity_files;
			ଯଦି (*intptr >= SSH_MAX_IDENTITY_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_IDENTITY_FILES);
				ଯାଅ out;
			}
			add_identity_file(options, ଖାଲି,
			    arg, flags & SSHCONF_USERCONF);
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oCertificateFile:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ଯାଅ out;
		}
		ଯଦି (*activep) {
			intptr = &options->ଅଙ୍କ_certificate_files;
			ଯଦି (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				ଯାଅ out;
			}
			add_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oXAuthLocation:
		charptr=&options->xauth_location;
		ଯାଅ parse_string;

	ସ୍ଥିତି oUser:
		charptr = &options->user;
parse_string:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ଯାଅ out;
		}
		ଯଦି (*activep && *charptr == ଖାଲି)
			*charptr = xstrdup(arg);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oGlobalKnownHostsFile:
		cpptr = (ଅକ୍ଷର **)&options->system_hostfiles;
		uintptr = &options->ଅଙ୍କ_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		i = 0;
		ମୂଲ୍ୟ = *uintptr == 0; /* was array empty when we started? */
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			ଯଦି (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ଯାଅ out;
			}
			/* Allow "none" only in first position */
			ଯଦି (strcasecmp(arg, "none") == 0) {
				ଯଦି (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ଯାଅ out;
				}
			}
			i++;
			ଯଦି (*activep && ମୂଲ୍ୟ) {
				ଯଦି ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries.", filename, linenum,
					    keyword);
					ଯାଅ out;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oUserKnownHostsFile:
		cpptr = (ଅକ୍ଷର **)&options->user_hostfiles;
		uintptr = &options->ଅଙ୍କ_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		ଯାଅ parse_char_array;

	ସ୍ଥିତି oHostname:
		charptr = &options->hostname;
		ଯାଅ parse_string;

	ସ୍ଥିତି oTag:
		charptr = &options->tag;
		ଯାଅ parse_string;

	ସ୍ଥିତି o_Host_ଚାବି_Alias:
		charptr = &options->host_ଚାବି_alias;
		ଯାଅ parse_string;

	ସ୍ଥିତି oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		ଯାଅ parse_string;

	ସ୍ଥିତି oBindAddress:
		charptr = &options->bind_address;
		ଯାଅ parse_string;

	ସ୍ଥିତି oBindInterface:
		charptr = &options->bind_interface;
		ଯାଅ parse_string;

	ସ୍ଥିତି oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		ଯାଅ parse_string;

	ସ୍ଥିତି o_Security_ଚାବି_Provider:
		charptr = &options->sk_provider;
		ଯାଅ parse_string;

	ସ୍ଥିତି oKnownHostsCommand:
		charptr = &options->known_hosts_command;
		ଯାଅ parse_command;

	ସ୍ଥିତି oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		ଯଦି (str == ଖାଲି) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ଯାଅ out;
		}
		len = strspn(str, WHITESPACE "=");
		ଯଦି (*activep && *charptr == ଖାଲି)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oProxyJump:
		ଯଦି (str == ଖାଲି) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ଯାଅ out;
		}
		len = strspn(str, WHITESPACE "=");
		/* XXX use argv? */
		ଯଦି (parse_jump(str + len, options, cmdline, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			ଯାଅ out;
		}
		argv_consume(&ac);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oPort:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ଯାଅ out;
		}
		ମୂଲ୍ୟ = a2port(arg);
		ଯଦି (ମୂଲ୍ୟ <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			ଯାଅ out;
		}
		ଯଦି (*activep && options->port == -1)
			options->port = ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_next(&ac, &av);
		ଯଦି ((errstr = atoi_err(arg, &ମୂଲ୍ୟ)) != ଖାଲି) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			ଯାଅ out;
		}
		ଯଦି (*activep && *intptr == -1)
			*intptr = ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oCiphers:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ଯାଅ out;
		}
		ଯଦି (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			ଯାଅ out;
		}
		ଯଦି (*activep && options->ciphers == ଖାଲି)
			options->ciphers = xstrdup(arg);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oMacs:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ଯାଅ out;
		}
		ଯଦି (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			ଯାଅ out;
		}
		ଯଦି (*activep && options->macs == ଖାଲି)
			options->macs = xstrdup(arg);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oKexAlgorithms:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ଯାଅ out;
		}
		ଯଦି (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			ଯାଅ out;
		}
		ଯଦି (*activep && options->kex_algorithms == ଖାଲି)
			options->kex_algorithms = xstrdup(arg);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି o_Host_ଚାବି_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ଯାଅ out;
		}
		ଯଦି (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			ଯାଅ out;
		}
		ଯଦି (*activep && *charptr == ଖାଲି)
			*charptr = xstrdup(arg);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		ଯାଅ parse_pubkey_algos;

	ସ୍ଥିତି oLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		ମୂଲ୍ୟ = log_level_ସଂଖ୍ୟା(arg);
		ଯଦି (ମୂଲ୍ୟ == SYSLOG_LEVEL_NOT_SET) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			ଯାଅ out;
		}
		ଯଦି (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_SET)
			*log_level_ptr = (LogLevel) ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		ମୂଲ୍ୟ = log_facility_ସଂଖ୍ୟା(arg);
		ଯଦି (ମୂଲ୍ୟ == SYSLOG_FACILITY_NOT_SET) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			ଯାଅ out;
		}
		ଯଦି (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oLogVerbose:
		cppptr = &options->log_verbose;
		uintptr = &options->ଅଙ୍କ_log_verbose;
		i = 0;
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			ଯଦି (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ଯାଅ out;
			}
			/* Allow "none" only in first position */
			ଯଦି (strcasecmp(arg, "none") == 0) {
				ଯଦି (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ଯାଅ out;
				}
			}
			i++;
			ଯଦି (*activep && *uintptr == 0) {
				*cppptr = xrecallocarray(*cppptr, *uintptr,
				    *uintptr + 1, ଆକାର(**cppptr));
				(*cppptr)[(*uintptr)++] = xstrdup(arg);
			}
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oLocalForward:
	ସ୍ଥିତି oRemoteForward:
	ସ୍ଥିତି oDynamicForward:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ଯାଅ out;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		ଯଦି (!dynamicfwd) {
			arg2 = argv_next(&ac, &av);
			ଯଦି (arg2 == ଖାଲି || *arg2 == '\0') {
				ଯଦି (remotefwd)
					dynamicfwd = 1;
				ଅନ୍ୟଥା {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					ଯାଅ out;
				}
			} ଅନ୍ୟଥା {
				/* construct a string for parse_forward */
				snprintf(fwdarg, ଆକାର(fwdarg), "%s:%s", arg,
				    arg2);
			}
		}
		ଯଦି (dynamicfwd)
			strlcpy(fwdarg, arg, ଆକାର(fwdarg));

		ଯଦି (parse_forward(&fwd, fwdarg, dynamicfwd, remotefwd) == 0) {
			error("%.200s line %d: Bad forwarding specification.",
			    filename, linenum);
			ଯାଅ out;
		}

		ଯଦି (*activep) {
			ଯଦି (remotefwd) {
				add_remote_forward(options, &fwd);
			} ଅନ୍ୟଥା {
				add_local_forward(options, &fwd);
			}
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oPermitRemoteOpen:
		uintptr = &options->ଅଙ୍କ_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		found = *uintptr == 0;
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			ଯଦି (strcasecmp(arg, "none") == 0 ||
			    strcasecmp(arg, "any") == 0) {
				ଯଦି (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					ମୁକ୍ତ(arg2);
					ଯାଅ out;
				}
			} ଅନ୍ୟଥା {
				p = hpdelim(&arg);
				ଯଦି (p == ଖାଲି) {
					fatal("%s line %d: missing host in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
				}
				p = cleanhostname(p);
				/*
				 * don't want to use permitopen_port to avoid
				 * dependency on channels.[ch] here.
				 */
				ଯଦି (arg == ଖାଲି || (strcmp(arg, "*") != 0 &&
				    a2port(arg) <= 0)) {
					fatal("%s line %d: bad port number "
					    "in %s", filename, linenum,
					    lookup_opcode_name(opcode));
				}
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg2);
			ମୁକ୍ତ(arg2);
		}
		ଯଦି (nstrs == 0)
			fatal("%s line %d: missing %s specification",
			    filename, linenum, lookup_opcode_name(opcode));
		ଯଦି (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = ଖାଲି; /* transferred */
			nstrs = 0;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oClearAllForwardings:
		intptr = &options->clear_forwardings;
		ଯାଅ parse_flag;

	ସ୍ଥିତି oHost:
		ଯଦି (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			ଯାଅ out;
		}
		*activep = 0;
		arg2 = ଖାଲି;
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			ଯଦି (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ଯାଅ out;
			}
			ଯଦି ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				ଭାଙ୍ଗ;
			}
			negated = *arg == '!';
			ଯଦି (negated)
				arg++;
			ଯଦି (match_pattern(host, arg)) {
				ଯଦି (negated) {
					debug("%.200s line %d: Skipping Host "
					    "block because of negated match "
					    "for %.100s", filename, linenum,
					    arg);
					*activep = 0;
					argv_consume(&ac);
					ଭାଙ୍ଗ;
				}
				ଯଦି (!*activep)
					arg2 = arg; /* logged below */
				*activep = 1;
			}
		}
		ଯଦି (*activep)
			debug("%.200s line %d: Applying options for %.100s",
			    filename, linenum, arg2);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oMatch:
		ଯଦି (cmdline) {
			error("Match directive not supported as a command-line "
			    "option");
			ଯାଅ out;
		}
		ମୂଲ୍ୟ = match_cfg_ଧାଡ଼ି(options, str, &ac, &av, pw, host,
		    original_host, remote_command, flags & SSHCONF_FINAL,
		    want_final_pass, filename, linenum);
		ଯଦି (ମୂଲ୍ୟ < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			ଯାଅ out;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ଯାଅ out;
		}
		ଯଦି (strcmp(arg, "none") == 0)
			ମୂଲ୍ୟ = SSH_ESCAPECHAR_NONE;
		ଅନ୍ୟଥା ଯଦି (arg[1] == '\0')
			ମୂଲ୍ୟ = (u_char) arg[0];
		ଅନ୍ୟଥା ଯଦି (arg[0] == '^' && arg[2] == 0 &&
		    (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			ମୂଲ୍ୟ = (u_char) arg[1] & 31;
		ଅନ୍ୟଥା {
			error("%.200s line %d: Bad escape character.",
			    filename, linenum);
			ଯାଅ out;
		}
		ଯଦି (*activep && *intptr == -1)
			*intptr = ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		ଯାଅ parse_flag;

	ସ୍ଥିତି oIdentitiesOnly:
		intptr = &options->identities_only;
		ଯାଅ parse_flag;

	ସ୍ଥିତି oServerAliveInterval:
		intptr = &options->server_alive_interval;
		ଯାଅ parse_time;

	ସ୍ଥିତି o_Server_Alive_ଗଣନା_Max:
		intptr = &options->server_alive_ଗଣନା_max;
		ଯାଅ parse_int;

	ସ୍ଥିତି oSendEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			ଯଦି (*arg == '\0' || strchr(arg, '=') != ଖାଲି) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				ଯାଅ out;
			}
			found = 1;
			ଯଦି (!*activep)
				ଜାରି;
			ଯଦି (*arg == '-') {
				/* Removing an env var */
				rm_env(options, arg, filename, linenum);
				ଜାରି;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->ଅଙ୍କ_send_env, arg);
		}
		ଯଦି (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oSetEnv:
		found = options->ଅଙ୍କ_setenv == 0;
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			ଯଦି (strchr(arg, '=') == ଖାଲି) {
				error("%s line %d: Invalid SetEnv.",
				    filename, linenum);
				ଯାଅ out;
			}
			ଯଦି (lookup_setenv_in_list(arg, strs, nstrs) != ଖାଲି) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				ଜାରି;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg);
		}
		ଯଦି (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ଯଦି (found && *activep) {
			options->setenv = strs;
			options->ଅଙ୍କ_setenv = nstrs;
			strs = ଖାଲି; /* transferred */
			nstrs = 0;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oControlPath:
		charptr = &options->control_path;
		ଯାଅ parse_string;

	ସ୍ଥିତି oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			error("%.200s line %d: Missing ControlPersist"
			    " argument.", filename, linenum);
			ଯାଅ out;
		}
		ମୂଲ୍ୟ = 0;
		value2 = 0;	/* timeout */
		ଯଦି (strcmp(arg, "no") == 0 || strcmp(arg, "false") == 0)
			ମୂଲ୍ୟ = 0;
		ଅନ୍ୟଥା ଯଦି (strcmp(arg, "yes") == 0 || strcmp(arg, "true") == 0)
			ମୂଲ୍ୟ = 1;
		ଅନ୍ୟଥା ଯଦି ((value2 = convtime(arg)) >= 0)
			ମୂଲ୍ୟ = 1;
		ଅନ୍ୟଥା {
			error("%.200s line %d: Bad ControlPersist argument.",
			    filename, linenum);
			ଯାଅ out;
		}
		ଯଦି (*activep && *intptr == -1) {
			*intptr = ମୂଲ୍ୟ;
			options->control_persist_timeout = value2;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oHashKnownHosts:
		intptr = &options->hash_known_hosts;
		ଯାଅ parse_flag;

	ସ୍ଥିତି oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି oTunnelDevice:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ଯାଅ out;
		}
		ମୂଲ୍ୟ = a2tun(arg, &value2);
		ଯଦି (ମୂଲ୍ୟ == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			ଯାଅ out;
		}
		ଯଦି (*activep && options->tun_local == -1) {
			options->tun_local = ମୂଲ୍ୟ;
			options->tun_remote = value2;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oLocalCommand:
		charptr = &options->local_command;
		ଯାଅ parse_command;

	ସ୍ଥିତି oPermitLocalCommand:
		intptr = &options->permit_local_command;
		ଯାଅ parse_flag;

	ସ୍ଥିତି oRemoteCommand:
		charptr = &options->remote_command;
		ଯାଅ parse_command;

	ସ୍ଥିତି o_Visual_Host_ଚାବି:
		intptr = &options->visual_host_ଚାବି;
		ଯାଅ parse_flag;

	ସ୍ଥିତି oInclude:
		ଯଦି (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			ଯାଅ out;
		}
		ମୂଲ୍ୟ = 0;
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			ଯଦି (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ଯାଅ out;
			}
			/* Expand %tokens and environment variables */
			ଯଦି ((p = expand_match_exec_or_include_path(arg,
			    options, pw, host, original_host,
			    flags & SSHCONF_FINAL, 1)) == ଖାଲି) {
				error("%.200s line %d: Unable to expand user "
				    "config file '%.100s'",
				    filename, linenum, arg);
				ଜାରି;
			}
			/*
			 * Ensure all paths are anchored. User configuration
			 * files may begin with '~/' but system configurations
			 * must not. If the path is relative, then treat it
			 * as living in ~/.ssh for user configurations or
			 * /etc/ssh for system ones.
			 */
			ଯଦି (*p == '~' && (flags & SSHCONF_USERCONF) == 0) {
				error("%.200s line %d: bad include path %s.",
				    filename, linenum, p);
				ଯାଅ out;
			}
			ଯଦି (!path_absolute(p) && *p != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" _PATH_SSH_USER_DIR : SSHDIR, p);
			} ଅନ୍ୟଥା {
				arg2 = xstrdup(p);
			}
			ମୁକ୍ତ(p);
			memset(&gl, 0, ଆକାର(gl));
			r = glob(arg2, GLOB_TILDE, ଖାଲି, &gl);
			ଯଦି (r == GLOB_NOMATCH) {
				debug("%.200s line %d: include %s matched no "
				    "files",filename, linenum, arg2);
				ମୁକ୍ତ(arg2);
				ଜାରି;
			} ଅନ୍ୟଥା ଯଦି (r != 0) {
				error("%.200s line %d: glob failed for %s.",
				    filename, linenum, arg2);
				ଯାଅ out;
			}
			ମୁକ୍ତ(arg2);
			oactive = *activep;
			ପାଇଁ (i = 0; i < gl.gl_pathc; i++) {
				debug3("%.200s line %d: Including file %s "
				    "depth %d%s", filename, linenum,
				    gl.gl_pathv[i], depth,
				    oactive ? "" : " (parse only)");
				r = read_config_file_depth(gl.gl_pathv[i],
				    pw, host, original_host, remote_command,
				    options, flags | SSHCONF_CHECKPERM |
				    (oactive ? 0 : SSHCONF_NEVERMATCH),
				    activep, want_final_pass, depth + 1);
				ଯଦି (r != 1 && errno != ENOENT) {
					error("%.200s line %d: Can't open user "
					    "config file %.100s: %.100s",
					    filename, linenum, gl.gl_pathv[i],
					    strerror(errno));
					globfree(&gl);
					ଯାଅ out;
				}
				/*
				 * don't let Match in includes clobber the
				 * containing file's Match state.
				 */
				*activep = oactive;
				ଯଦି (r != 1)
					ମୂଲ୍ୟ = -1;
			}
			globfree(&gl);
		}
		ଯଦି (ମୂଲ୍ୟ != 0)
			ret = ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oIPQoS:
		arg = argv_next(&ac, &av);
		ଯଦି ((ମୂଲ୍ୟ = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			ଯାଅ out;
		}
		ଯଦି (ମୂଲ୍ୟ == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			ମୂଲ୍ୟ = INT_MAX;
		}
		arg = argv_next(&ac, &av);
		ଯଦି (arg == ଖାଲି)
			value2 = ମୂଲ୍ୟ;
		ଅନ୍ୟଥା ଯଦି ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			ଯାଅ out;
		}
		ଯଦି (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		ଯଦି (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = ମୂଲ୍ୟ;
			options->ip_qos_bulk = value2;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି oSessionType:
		intptr = &options->session_type;
		multistate_ptr = multistate_sessiontype;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି oStdinNull:
		intptr = &options->stdin_null;
		ଯାଅ parse_flag;

	ସ୍ଥିତି oForkAfterAuthentication:
		intptr = &options->fork_after_authentication;
		ଯାଅ parse_flag;

	ସ୍ଥିତି oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		ଯାଅ parse_string;

	ସ୍ଥିତି oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		ଯାଅ parse_flag;

	ସ୍ଥିତି oCanonicalDomains:
		found = options->ଅଙ୍କ_canonical_domains == 0;
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			/* Allow "none" only in first position */
			ଯଦି (strcasecmp(arg, "none") == 0) {
				ଯଦି (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ଯାଅ out;
				}
			}
			ଯଦି (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				ଯାଅ out;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ଯଦି (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ଯଦି (found && *activep) {
			options->canonical_domains = strs;
			options->ଅଙ୍କ_canonical_domains = nstrs;
			strs = ଖାଲି; /* transferred */
			nstrs = 0;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oCanonicalizePermittedCNAMEs:
		found = options->ଅଙ୍କ_permitted_cnames == 0;
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			ଯଦି (strcasecmp(arg, "none") == 0) {
				ଯଦି (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ଯାଅ out;
				}
				arg2 = "";
			} ଅନ୍ୟଥା ଯଦି (strcmp(arg, "*") == 0) {
				arg2 = arg;
			} ଅନ୍ୟଥା {
				lowercase(arg);
				ଯଦି ((arg2 = strchr(arg, ':')) == ଖାଲି ||
				    arg2[1] == '\0') {
					error("%s line %d: "
					    "Invalid permitted CNAME \"%s\"",
					    filename, linenum, arg);
					ଯାଅ out;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    ଆକାର(*cnames));
			cnames[ncnames].source_list = xstrdup(arg);
			cnames[ncnames].target_list = xstrdup(arg2);
			ncnames++;
		}
		ଯଦି (ncnames == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ଯଦି (found && *activep) {
			options->permitted_cnames = cnames;
			options->ଅଙ୍କ_permitted_cnames = ncnames;
			cnames = ଖାଲି; /* transferred */
			ncnames = 0;
		}
		/* un-transferred cnames is cleaned up before exit */
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		ଯାଅ parse_int;

	ସ୍ଥିତି oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		ଯାଅ parse_flag;

	ସ୍ଥିତି oStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			ଯାଅ out;
		}
		/* Parse mode in octal format */
		ମୂଲ୍ୟ = strtol(arg, &endofnumber, 8);
		ଯଦି (arg == endofnumber || ମୂଲ୍ୟ < 0 || ମୂଲ୍ୟ > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			ଯାଅ out;
		}
		ଯଦି (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		ଯାଅ parse_flag;

	ସ୍ଥିତି o_Revoked_Host_ଚାବିଗୁଡ଼ିକ:
		uintptr = &options->ଅଙ୍କ_revoked_host_ଚାବିଗୁଡ଼ିକ;
		cppptr = &options->revoked_host_ଚାବିଗୁଡ଼ିକ;
		found = *uintptr == 0;
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			ଯଦି (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				ଯାଅ out;
			}
			/* Allow "none" only in first position */
			ଯଦି (strcasecmp(arg, "none") == 0) {
				ଯଦି (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ଯାଅ out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ଯଦି (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ଯଦି (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = ଖାଲି; /* transferred */
			nstrs = 0;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ଯାଅ out;
		}
		ଯଦି ((ମୂଲ୍ୟ = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			ଯାଅ out;
		}
		ଯଦି (*activep && *intptr == -1)
			*intptr = ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oUpdateHostkeys:
		intptr = &options->update_hostkeys;
		multistate_ptr = multistate_yesnoask;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି oHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
		ଯାଅ parse_pubkey_algos;

	ସ୍ଥିତି oPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		ଯାଅ parse_pubkey_algos;

	ସ୍ଥିତି o_Add_ଚାବିଗୁଡ଼ିକ_To_Agent:
		arg = argv_next(&ac, &av);
		arg2 = argv_next(&ac, &av);
		ମୂଲ୍ୟ = parse_multistate_ମୂଲ୍ୟ(arg, filename, linenum,
		    multistate_yesnoaskconfirm);
		value2 = 0; /* unlimited lifespan by default */
		ଯଦି (ମୂଲ୍ୟ == 3 && arg2 != ଖାଲି) {
			/* allow "AddKeysToAgent confirm 5m" */
			ଯଦି ((value2 = convtime(arg2)) == -1) {
				error("%s line %d: invalid time value.",
				    filename, linenum);
				ଯାଅ out;
			}
		} ଅନ୍ୟଥା ଯଦି (ମୂଲ୍ୟ == -1 && arg2 == ଖାଲି) {
			ଯଦି ((value2 = convtime(arg)) == -1) {
				error("%s line %d: unsupported option",
				    filename, linenum);
				ଯାଅ out;
			}
			ମୂଲ୍ୟ = 1; /* yes */
		} ଅନ୍ୟଥା ଯଦି (ମୂଲ୍ୟ == -1 || arg2 != ଖାଲି) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			ଯାଅ out;
		}
		ଯଦି (*activep && options->add_ଚାବିଗୁଡ଼ିକ_to_agent == -1) {
			options->add_ଚାବିଗୁଡ଼ିକ_to_agent = ମୂଲ୍ୟ;
			options->add_ଚାବିଗୁଡ଼ିକ_to_agent_lifespan = value2;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oIdentityAgent:
		charptr = &options->identity_agent;
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ଯାଅ out;
		}
  parse_agent_path:
		/* Extra validation if the string represents an env var. */
		ଯଦି ((arg2 = dollar_expand(&r, arg)) == ଖାଲି || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			ଯାଅ out;
		}
		ମୁକ୍ତ(arg2);
		/* check for legacy environment format */
		ଯଦି (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			ଯାଅ out;
		}
		ଯଦି (*activep && *charptr == ଖାଲି)
			*charptr = xstrdup(arg);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		ଯାଅ parse_flag;

	ସ୍ଥିତି oRequiredRSASize:
		intptr = &options->required_rsa_size;
		ଯାଅ parse_int;

	ସ୍ଥିତି oWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		ଯାଅ parse_multistate;

	ସ୍ଥିତି oObscureKeystrokeTiming:
		ମୂଲ୍ୟ = -1;
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			ଯଦି (ମୂଲ୍ୟ != -1) {
				error("%s line %d: invalid arguments",
				    filename, linenum);
				ଯାଅ out;
			}
			ଯଦି (strcmp(arg, "yes") == 0 ||
			    strcmp(arg, "true") == 0)
				ମୂଲ୍ୟ = SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
			ଅନ୍ୟଥା ଯଦି (strcmp(arg, "no") == 0 ||
			    strcmp(arg, "false") == 0)
				ମୂଲ୍ୟ = 0;
			ଅନ୍ୟଥା ଯଦି (strncmp(arg, "interval:", 9) == 0) {
				ଯଦି ((errstr = atoi_err(arg + 9,
				    &ମୂଲ୍ୟ)) != ଖାଲି) {
					error("%s line %d: integer value %s.",
					    filename, linenum, errstr);
					ଯାଅ out;
				}
				ଯଦି (ମୂଲ୍ୟ <= 0 || ମୂଲ୍ୟ > 1000) {
					error("%s line %d: value out of range.",
					    filename, linenum);
					ଯାଅ out;
				}
			} ଅନ୍ୟଥା {
				error("%s line %d: unsupported argument \"%s\"",
				    filename, linenum, arg);
				ଯାଅ out;
			}
		}
		ଯଦି (ମୂଲ୍ୟ == -1) {
			error("%s line %d: missing argument",
			    filename, linenum);
			ଯାଅ out;
		}
		intptr = &options->obscure_keystroke_timing_interval;
		ଯଦି (*activep && *intptr == -1)
			*intptr = ମୂଲ୍ୟ;
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oChannelTimeout:
		found = options->ଅଙ୍କ_channel_timeouts == 0;
		ଯେତେବେଳେ ((arg = argv_next(&ac, &av)) != ଖାଲି) {
			/* Allow "none" only in first position */
			ଯଦି (strcasecmp(arg, "none") == 0) {
				ଯଦି (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					ଯାଅ out;
				}
			} ଅନ୍ୟଥା ଯଦି (parse_pattern_interval(arg,
			    ଖାଲି, ଖାଲି) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		ଯଦି (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ଯଦି (found && *activep) {
			options->channel_timeouts = strs;
			options->ଅଙ୍କ_channel_timeouts = nstrs;
			strs = ଖାଲି; /* transferred */
			nstrs = 0;
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oVersionAddendum:
		ଯଦି (str == ଖାଲି || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		ଯଦି (strchr(str + len, '\r') != ଖାଲି) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		ଯଦି ((arg = strchr(ଧାଡ଼ି, '#')) != ଖାଲି) {
			*arg = '\0';
			rtrim(ଧାଡ଼ି);
		}
		ଯଦି (*activep && options->version_addendum == ଖାଲି) {
			ଯଦି (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			ଅନ୍ୟଥା
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oRefuseConnection:
		arg = argv_next(&ac, &av);
		ଯଦି (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			ଯାଅ out;
		}
		ଯଦି (*activep) {
			fatal("%.200s line %d: RefuseConnection: %s",
			    filename, linenum, arg);
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		ଭାଙ୍ଗ;

	ସ୍ଥିତି oUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		ଭାଙ୍ଗ;

	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		error("%s line %d: Unimplemented opcode %d",
		    filename, linenum, opcode);
		ଯାଅ out;
	}

	/* Check that there is no garbage at end of line. */
	ଯଦି (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		ଯାଅ out;
	}

	/* success */
	ret = 0;
 out:
	free_canon_cnames(cnames, ncnames);
	opt_array_free2(strs, ଖାଲି, nstrs);
	argv_free(oav, oac);
	ଫେରନ୍ତୁ ret;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
read_config_file(ଅଚଳ ଅକ୍ଷର *filename, ସଂରଚନା passwd *pw, ଅଚଳ ଅକ୍ଷର *host,
    ଅଚଳ ଅକ୍ଷର *original_host, ଅଚଳ ଅକ୍ଷର *remote_command, Options *options, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା *want_final_pass)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା active = 1;

	ଫେରନ୍ତୁ read_config_file_depth(filename, pw, host, original_host,
	    remote_command, options, flags, &active, want_final_pass, 0);
}

#define READCONF_MAX_DEPTH	16
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
read_config_file_depth(ଅଚଳ ଅକ୍ଷର *filename, ସଂରଚନା passwd *pw,
    ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *original_host, ଅଚଳ ଅକ୍ଷର *remote_command,
    Options *options, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *activep, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *want_final_pass, ପୂର୍ଣ୍ଣସଂଖ୍ୟା depth)
{
	FILE *f;
	ଅକ୍ଷର *ଧାଡ଼ି = ଖାଲି;
	size_t linesize = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା linenum;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା bad_options = 0;

	ଯଦି (depth < 0 || depth > READCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	ଯଦି ((f = fopen(filename, "r")) == ଖାଲି)
		ଫେରନ୍ତୁ 0;

	ଯଦି (flags & SSHCONF_CHECKPERM) {
		ସଂରଚନା stat sb;

		ଯଦି (fstat(fileno(f), &sb) == -1)
			fatal("fstat %s: %s", filename, strerror(errno));
		ଯଦି (((sb.st_uid != 0 && sb.st_uid != getuid()) ||
		    (sb.st_mode & 022) != 0))
			fatal("Bad owner or permissions on %s", filename);
	}

	debug("Reading configuration data %.200s", filename);

	/*
	 * Mark that we are now processing the options.  This flag is turned
	 * on/off by Host specifications.
	 */
	linenum = 0;
	ଯେତେବେଳେ (getline(&ଧାଡ଼ି, &linesize, f) != -1) {
		/* Update line number counter. */
		linenum++;
		/*
		 * Trim out comments and strip whitespace.
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages.
		 */
		ଯଦି (process_config_ଧାଡ଼ି_depth(options, pw, host, original_host,
		    remote_command, ଧାଡ଼ି, filename, linenum, activep, flags,
		    want_final_pass, depth) != 0)
			bad_options++;
	}
	ମୁକ୍ତ(ଧାଡ଼ି);
	fclose(f);
	ଯଦି (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
	ଫେରନ୍ତୁ 1;
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
option_clear_or_none(ଅଚଳ ଅକ୍ଷର *o)
{
	ଫେରନ୍ତୁ o == ଖାଲି || strcasecmp(o, "none") == 0;
}

/*
 * Returns 1 if CanonicalizePermittedCNAMEs have been specified, 0 otherwise.
 * Allowed to be called on non-final configuration.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
config_has_permitted_cnames(Options *options)
{
	ଯଦି (options->ଅଙ୍କ_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].source_list, "none") == 0 &&
	    strcmp(options->permitted_cnames[0].target_list, "") == 0)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ options->ଅଙ୍କ_permitted_cnames > 0;
}

/*
 * Initializes options to special values that indicate that they have not yet
 * been set.  Read_config_file will only set options with this value. Options
 * are processed in the following order: command line, user config file,
 * system config file.  Last, fill_default_options is called.
 */

ଶୂନ୍ୟ
initialize_options(Options * options)
{
	memset(options, 'X', ଆକାର(*options));
	options->host_arg = ଖାଲି;
	options->forward_agent = -1;
	options->forward_agent_sock_path = ଖାଲି;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = ଖାଲି;
	options->stdio_forward_port = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = ଖାଲି;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_mask = (mode_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = ଖାଲି;
	options->hostbased_authentication = -1;
	options->batch_mode = -1;
	options->check_host_ip = -1;
	options->strict_host_ଚାବି_checking = -1;
	options->compression = -1;
	options->tcp_keep_alive = -1;
	options->port = -1;
	options->address_family = -1;
	options->connection_attempts = -1;
	options->connection_timeout = -1;
	options->ସଂଖ୍ୟା_of_password_prompts = -1;
	options->ciphers = ଖାଲି;
	options->macs = ଖାଲି;
	options->kex_algorithms = ଖାଲି;
	options->hostkeyalgorithms = ଖାଲି;
	options->ca_sign_algorithms = ଖାଲି;
	options->ଅଙ୍କ_identity_files = 0;
	memset(options->identity_ଚାବିଗୁଡ଼ିକ, 0, ଆକାର(options->identity_ଚାବିଗୁଡ଼ିକ));
	options->ଅଙ୍କ_certificate_files = 0;
	memset(options->certificates, 0, ଆକାର(options->certificates));
	options->hostname = ଖାଲି;
	options->host_ଚାବି_alias = ଖାଲି;
	options->proxy_command = ଖାଲି;
	options->jump_user = ଖାଲି;
	options->jump_host = ଖାଲି;
	options->jump_port = -1;
	options->jump_extra = ଖାଲି;
	options->user = ଖାଲି;
	options->escape_char = -1;
	options->ଅଙ୍କ_system_hostfiles = 0;
	options->ଅଙ୍କ_user_hostfiles = 0;
	options->local_forwards = ଖାଲି;
	options->ଅଙ୍କ_local_forwards = 0;
	options->remote_forwards = ଖାଲି;
	options->ଅଙ୍କ_remote_forwards = 0;
	options->permitted_remote_opens = ଖାଲି;
	options->ଅଙ୍କ_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
	options->log_level = SYSLOG_LEVEL_NOT_SET;
	options->ଅଙ୍କ_log_verbose = 0;
	options->log_verbose = ଖାଲି;
	options->preferred_authentications = ଖାଲି;
	options->bind_address = ଖାଲି;
	options->bind_interface = ଖାଲି;
	options->pkcs11_provider = ଖାଲି;
	options->sk_provider = ଖାଲି;
	options->enable_ssh_keysign = -1;
	options->no_host_authentication_for_localhost = -1;
	options->identities_only = -1;
	options->rekey_limit = -1;
	options->rekey_interval = -1;
	options->verify_host_ଚାବି_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_ଗଣନା_max = -1;
	options->send_env = ଖାଲି;
	options->ଅଙ୍କ_send_env = 0;
	options->setenv = ଖାଲି;
	options->ଅଙ୍କ_setenv = 0;
	options->control_path = ଖାଲି;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_known_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = ଖାଲି;
	options->permit_local_command = -1;
	options->remote_command = ଖାଲି;
	options->add_ଚାବିଗୁଡ଼ିକ_to_agent = -1;
	options->add_ଚାବିଗୁଡ଼ିକ_to_agent_lifespan = -1;
	options->identity_agent = ଖାଲି;
	options->visual_host_ଚାବି = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = ଖାଲି;
	options->ଅଙ୍କ_canonical_domains = 0;
	options->ଅଙ୍କ_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_ଚାବିଗୁଡ଼ିକ = ଖାଲି;
	options->ଅଙ୍କ_revoked_host_ଚାବିଗୁଡ଼ିକ = 0;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->hostbased_accepted_algos = ଖାଲି;
	options->pubkey_accepted_algos = ଖାଲି;
	options->known_hosts_command = ଖାଲି;
	options->required_rsa_size = -1;
	options->warn_weak_crypto = -1;
	options->enable_escape_commandline = -1;
	options->obscure_keystroke_timing_interval = -1;
	options->tag = ଖାଲି;
	options->channel_timeouts = ଖାଲି;
	options->ଅଙ୍କ_channel_timeouts = 0;
	options->version_addendum = ଖାଲି;
}

/*
 * A petite version of fill_default_options() that just fills the options
 * needed for hostname canonicalization to proceed.
 */
ଶୂନ୍ୟ
fill_default_options_for_canonicalization(Options *options)
{
	ଯଦି (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	ଯଦି (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	ଯଦି (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
}

/*
 * Called after processing other sources of option data, this fills those
 * options for which no value has been specified with their default values.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fill_default_options(Options * options)
{
	ଅକ୍ଷର *all_cipher, *all_mac, *all_kex, *all_ଚାବି, *all_sig;
	ଅକ୍ଷର *def_cipher, *def_mac, *def_kex, *def_ଚାବି, *def_sig;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1, r;

	ଯଦି (options->forward_agent == -1)
		options->forward_agent = 0;
	ଯଦି (options->forward_x11 == -1)
		options->forward_x11 = 0;
	ଯଦି (options->forward_x11_trusted == -1)
		options->forward_x11_trusted = 0;
	ଯଦି (options->forward_x11_timeout == -1)
		options->forward_x11_timeout = 1200;
	/*
	 * stdio forwarding (-W) changes the default for these but we defer
	 * setting the values so they can be overridden.
	 */
	ଯଦି (options->exit_on_forward_failure == -1)
		options->exit_on_forward_failure =
		    options->stdio_forward_host != ଖାଲି ? 1 : 0;
	ଯଦି (options->clear_forwardings == -1)
		options->clear_forwardings =
		    options->stdio_forward_host != ଖାଲି ? 1 : 0;
	ଯଦି (options->clear_forwardings == 1)
		clear_forwardings(options);

	ଯଦି (options->xauth_location == ଖାଲି)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	ଯଦି (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	ଯଦି (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	ଯଦି (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	ଯଦି (options->pubkey_authentication == -1)
		options->pubkey_authentication = SSH_PUBKEY_AUTH_ALL;
	ଯଦି (options->gss_authentication == -1)
		options->gss_authentication = 0;
	ଯଦି (options->gss_deleg_creds == -1)
		options->gss_deleg_creds = 0;
	ଯଦି (options->password_authentication == -1)
		options->password_authentication = 1;
	ଯଦି (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	ଯଦି (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	ଯଦି (options->batch_mode == -1)
		options->batch_mode = 0;
	ଯଦି (options->check_host_ip == -1)
		options->check_host_ip = 0;
	ଯଦି (options->strict_host_ଚାବି_checking == -1)
		options->strict_host_ଚାବି_checking = SSH_STRICT_HOSTKEY_ASK;
	ଯଦି (options->compression == -1)
		options->compression = 0;
	ଯଦି (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = SSH_KEEPALIVES_TRANSPORT;
	ଯଦି (options->port == -1)
		options->port = 0;	/* Filled in ssh_connect. */
	ଯଦି (options->address_family == -1)
		options->address_family = AF_UNSPEC;
	ଯଦି (options->connection_attempts == -1)
		options->connection_attempts = 1;
	ଯଦି (options->ସଂଖ୍ୟା_of_password_prompts == -1)
		options->ସଂଖ୍ୟା_of_password_prompts = 3;
	/* options->hostkeyalgorithms, default set in myproposals.h */
	ଯଦି (options->add_ଚାବିଗୁଡ଼ିକ_to_agent == -1) {
		options->add_ଚାବିଗୁଡ଼ିକ_to_agent = 0;
		options->add_ଚାବିଗୁଡ଼ିକ_to_agent_lifespan = 0;
	}
	ଯଦି (options->ଅଙ୍କ_identity_files == 0) {
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
	ଯଦି (options->escape_char == -1)
		options->escape_char = '~';
	ଯଦି (options->ଅଙ୍କ_system_hostfiles == 0) {
		options->system_hostfiles[options->ଅଙ୍କ_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->ଅଙ୍କ_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE2);
	}
	ଯଦି (options->update_hostkeys == -1) {
		ଯଦି (options->verify_host_ଚାବି_dns <= 0 &&
		    (options->ଅଙ୍କ_user_hostfiles == 0 ||
		    (options->ଅଙ୍କ_user_hostfiles == 1 && strcmp(options->
		    user_hostfiles[0], _PATH_SSH_USER_HOSTFILE) == 0)))
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_YES;
		ଅନ୍ୟଥା
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_NO;
	}
	ଯଦି (options->ଅଙ୍କ_user_hostfiles == 0) {
		options->user_hostfiles[options->ଅଙ୍କ_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->ଅଙ୍କ_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE2);
	}
	ଯଦି (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	ଯଦି (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_USER;
	ଯଦି (options->no_host_authentication_for_localhost == -1)
		options->no_host_authentication_for_localhost = 0;
	ଯଦି (options->identities_only == -1)
		options->identities_only = 0;
	ଯଦି (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	ଯଦି (options->rekey_limit == -1)
		options->rekey_limit = 0;
	ଯଦି (options->rekey_interval == -1)
		options->rekey_interval = 0;
	ଯଦି (options->verify_host_ଚାବି_dns == -1)
		options->verify_host_ଚାବି_dns = 0;
	ଯଦି (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	ଯଦି (options->server_alive_ଗଣନା_max == -1)
		options->server_alive_ଗଣନା_max = 3;
	ଯଦି (options->control_master == -1)
		options->control_master = 0;
	ଯଦି (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	ଯଦି (options->hash_known_hosts == -1)
		options->hash_known_hosts = 0;
	ଯଦି (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	ଯଦି (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	ଯଦି (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	ଯଦି (options->permit_local_command == -1)
		options->permit_local_command = 0;
	ଯଦି (options->visual_host_ଚାବି == -1)
		options->visual_host_ଚାବି = 0;
	ଯଦି (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	ଯଦି (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	ଯଦି (options->request_tty == -1)
		options->request_tty = REQUEST_TTY_AUTO;
	ଯଦି (options->session_type == -1)
		options->session_type = SESSION_TYPE_DEFAULT;
	ଯଦି (options->stdin_null == -1)
		options->stdin_null = 0;
	ଯଦି (options->fork_after_authentication == -1)
		options->fork_after_authentication = 0;
	ଯଦି (options->proxy_use_fdpass == -1)
		options->proxy_use_fdpass = 0;
	ଯଦି (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	ଯଦି (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	ଯଦି (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
	ଯଦି (options->fingerprint_hash == -1)
		options->fingerprint_hash = SSH_FP_HASH_DEFAULT;
#ifdef ENABLE_SK_INTERNAL
	ଯଦି (options->sk_provider == ଖାଲି)
		options->sk_provider = xstrdup("internal");
#ଅନ୍ୟଥା
	ଯଦି (options->sk_provider == ଖାଲି)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
#endif
	ଯଦି (options->required_rsa_size == -1)
		options->required_rsa_size = SSH_RSA_MINIMUM_MODULUS_SIZE;
	ଯଦି (options->warn_weak_crypto == -1)
		options->warn_weak_crypto = 1;
	ଯଦି (options->enable_escape_commandline == -1)
		options->enable_escape_commandline = 0;
	ଯଦି (options->obscure_keystroke_timing_interval == -1) {
		options->obscure_keystroke_timing_interval =
		    SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
	}

	/* Expand KEX name lists */
	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_ଚାବି = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_CLIENT_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_CLIENT_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_CLIENT_KEX, all_kex);
	def_ଚାବି = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_ଚାବି);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	କର { \
		ଯଦି ((r = kex_assemble_names(&options->what, \
		    defaults, all)) != 0) { \
			error_fr(r, "%s", #what); \
			ଯାଅ fail; \
		} \
	} ଯେତେବେଳେ (0)
	options->kex_algorithms_set = options->kex_algorithms != ଖାଲି;
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostbased_accepted_algos, def_ଚାବି, all_ଚାବି);
	ASSEMBLE(pubkey_accepted_algos, def_ଚାବି, all_ଚାବି);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE

#define CLEAR_ON_NONE(v) \
	କର { \
		ଯଦି (option_clear_or_none(v)) { \
			ମୁକ୍ତ(v); \
			v = ଖାଲି; \
		} \
	} ଯେତେବେଳେ(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	କର { \
		ଯଦି (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			ମୁକ୍ତ(options->v[0]); \
			ମୁକ୍ତ(options->v); \
			options->v = ଖାଲି; \
			options->nv = 0; \
		} \
	} ଯେତେବେଳେ (0)
	CLEAR_ON_NONE(options->local_command);
	CLEAR_ON_NONE(options->remote_command);
	CLEAR_ON_NONE(options->proxy_command);
	CLEAR_ON_NONE(options->control_path);
	CLEAR_ON_NONE(options->pkcs11_provider);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->known_hosts_command);
	CLEAR_ON_NONE_ARRAY(channel_timeouts, ଅଙ୍କ_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(revoked_host_ଚାବିଗୁଡ଼ିକ, ଅଙ୍କ_revoked_host_ଚାବିଗୁଡ଼ିକ, "none");
#undef CLEAR_ON_NONE
#undef CLEAR_ON_NONE_ARRAY
	ଯଦି (options->jump_host != ଖାଲି &&
	    strcmp(options->jump_host, "none") == 0 &&
	    options->jump_port == 0 && options->jump_user == ଖାଲି) {
		ମୁକ୍ତ(options->jump_host);
		options->jump_host = ଖାଲି;
	}
	ଯଦି (options->ଅଙ୍କ_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		ମୁକ୍ତ(options->permitted_cnames[0].source_list);
		ମୁକ୍ତ(options->permitted_cnames[0].target_list);
		memset(options->permitted_cnames, '\0',
		    ଆକାର(*options->permitted_cnames));
		options->ଅଙ୍କ_permitted_cnames = 0;
	}
	/* options->identity_agent distinguishes NULL from 'none' */
	/* options->user will be set in the main program if appropriate */
	/* options->hostname will be set in the main program if appropriate */
	/* options->host_key_alias should not be set by default */
	/* options->preferred_authentications will be set in ssh */

	/* success */
	ret = 0;
 fail:
	ମୁକ୍ତ(all_cipher);
	ମୁକ୍ତ(all_mac);
	ମୁକ୍ତ(all_kex);
	ମୁକ୍ତ(all_ଚାବି);
	ମୁକ୍ତ(all_sig);
	ମୁକ୍ତ(def_cipher);
	ମୁକ୍ତ(def_mac);
	ମୁକ୍ତ(def_kex);
	ମୁକ୍ତ(def_ଚାବି);
	ମୁକ୍ତ(def_sig);
	ଫେରନ୍ତୁ ret;
}

ଶୂନ୍ୟ
free_options(Options *o)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i;

	ଯଦି (o == ଖାଲି)
		ଫେରନ୍ତୁ;

#define FREE_ARRAY(type, n, a) \
	କର { \
		type _i; \
		ପାଇଁ (_i = 0; _i < (n); _i++) \
			ମୁକ୍ତ((a)[_i]); \
	} ଯେତେବେଳେ (0)

	ମୁକ୍ତ(o->forward_agent_sock_path);
	ମୁକ୍ତ(o->xauth_location);
	FREE_ARRAY(u_int, o->ଅଙ୍କ_log_verbose, o->log_verbose);
	ମୁକ୍ତ(o->log_verbose);
	ମୁକ୍ତ(o->ciphers);
	ମୁକ୍ତ(o->macs);
	ମୁକ୍ତ(o->hostkeyalgorithms);
	ମୁକ୍ତ(o->kex_algorithms);
	ମୁକ୍ତ(o->ca_sign_algorithms);
	ମୁକ୍ତ(o->hostname);
	ମୁକ୍ତ(o->host_ଚାବି_alias);
	ମୁକ୍ତ(o->proxy_command);
	ମୁକ୍ତ(o->user);
	FREE_ARRAY(u_int, o->ଅଙ୍କ_system_hostfiles, o->system_hostfiles);
	FREE_ARRAY(u_int, o->ଅଙ୍କ_user_hostfiles, o->user_hostfiles);
	ମୁକ୍ତ(o->preferred_authentications);
	ମୁକ୍ତ(o->bind_address);
	ମୁକ୍ତ(o->bind_interface);
	ମୁକ୍ତ(o->pkcs11_provider);
	ମୁକ୍ତ(o->sk_provider);
	ପାଇଁ (i = 0; i < o->ଅଙ୍କ_identity_files; i++) {
		ମୁକ୍ତ(o->identity_files[i]);
		sshkey_free(o->identity_ଚାବିଗୁଡ଼ିକ[i]);
	}
	ପାଇଁ (i = 0; i < o->ଅଙ୍କ_certificate_files; i++) {
		ମୁକ୍ତ(o->certificate_files[i]);
		sshkey_free(o->certificates[i]);
	}
	ମୁକ୍ତ(o->identity_agent);
	ପାଇଁ (i = 0; i < o->ଅଙ୍କ_local_forwards; i++) {
		ମୁକ୍ତ(o->local_forwards[i].listen_host);
		ମୁକ୍ତ(o->local_forwards[i].listen_path);
		ମୁକ୍ତ(o->local_forwards[i].connect_host);
		ମୁକ୍ତ(o->local_forwards[i].connect_path);
	}
	ମୁକ୍ତ(o->local_forwards);
	ପାଇଁ (i = 0; i < o->ଅଙ୍କ_remote_forwards; i++) {
		ମୁକ୍ତ(o->remote_forwards[i].listen_host);
		ମୁକ୍ତ(o->remote_forwards[i].listen_path);
		ମୁକ୍ତ(o->remote_forwards[i].connect_host);
		ମୁକ୍ତ(o->remote_forwards[i].connect_path);
	}
	ମୁକ୍ତ(o->remote_forwards);
	ମୁକ୍ତ(o->stdio_forward_host);
	FREE_ARRAY(u_int, o->ଅଙ୍କ_send_env, o->send_env);
	ମୁକ୍ତ(o->send_env);
	FREE_ARRAY(u_int, o->ଅଙ୍କ_setenv, o->setenv);
	ମୁକ୍ତ(o->setenv);
	ମୁକ୍ତ(o->control_path);
	ମୁକ୍ତ(o->local_command);
	ମୁକ୍ତ(o->remote_command);
	FREE_ARRAY(ପୂର୍ଣ୍ଣସଂଖ୍ୟା, o->ଅଙ୍କ_canonical_domains, o->canonical_domains);
	ପାଇଁ (i = 0; i < o->ଅଙ୍କ_permitted_cnames; i++) {
		ମୁକ୍ତ(o->permitted_cnames[i].source_list);
		ମୁକ୍ତ(o->permitted_cnames[i].target_list);
	}
	FREE_ARRAY(u_int, o->ଅଙ୍କ_revoked_host_ଚାବିଗୁଡ଼ିକ, o->revoked_host_ଚାବିଗୁଡ଼ିକ);
	ମୁକ୍ତ(o->revoked_host_ଚାବିଗୁଡ଼ିକ);
	ମୁକ୍ତ(o->hostbased_accepted_algos);
	ମୁକ୍ତ(o->pubkey_accepted_algos);
	ମୁକ୍ତ(o->jump_user);
	ମୁକ୍ତ(o->jump_host);
	ମୁକ୍ତ(o->jump_extra);
	ମୁକ୍ତ(o->ignored_unknown);
	explicit_bzero(o, ଆକାର(*o));
#undef FREE_ARRAY
}

ସଂରଚନା fwdarg {
	ଅକ୍ଷର *arg;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ispath;
};

/*
 * parse_fwd_field
 * parses the next field in a port forwarding specification.
 * sets fwd to the parsed field and advances p past the colon
 * or sets it to NULL at end of string.
 * returns 0 on success, else non-zero.
 */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_fwd_field(ଅକ୍ଷର **p, ସଂରଚନା fwdarg *fwd)
{
	ଅକ୍ଷର *ep, *cp = *p;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ispath = 0;

	ଯଦି (*cp == '\0') {
		*p = ଖାଲି;
		ଫେରନ୍ତୁ -1;	/* end of string */
	}

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	ଯଦି (*cp == '[') {
		/* find matching ']' */
		ପାଇଁ (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++) {
			ଯଦି (*ep == '/')
				ispath = 1;
		}
		/* no matching ']' or not at end of field. */
		ଯଦି (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			ଫେରନ୍ତୁ -1;
		/* NUL terminate the field and advance p past the colon */
		*ep++ = '\0';
		ଯଦି (*ep != '\0')
			*ep++ = '\0';
		fwd->arg = cp + 1;
		fwd->ispath = ispath;
		*p = ep;
		ଫେରନ୍ତୁ 0;
	}

	ପାଇଁ (cp = *p; *cp != '\0'; cp++) {
		ବାଛ (*cp) {
		ସ୍ଥିତି '\\':
			memmove(cp, cp + 1, strlen(cp + 1) + 1);
			ଯଦି (*cp == '\0')
				ଫେରନ୍ତୁ -1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି '/':
			ispath = 1;
			ଭାଙ୍ଗ;
		ସ୍ଥିତି ':':
			*cp++ = '\0';
			ଯାଅ done;
		}
	}
done:
	fwd->arg = *p;
	fwd->ispath = ispath;
	*p = cp;
	ଫେରନ୍ତୁ 0;
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
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_forward(ସଂରଚନା Forward *fwd, ଅଚଳ ଅକ୍ଷର *fwdspec, ପୂର୍ଣ୍ଣସଂଖ୍ୟା dynamicfwd, ପୂର୍ଣ୍ଣସଂଖ୍ୟା remotefwd)
{
	ସଂରଚନା fwdarg fwdargs[4];
	ଅକ୍ଷର *p, *cp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, err;

	memset(fwd, 0, ଆକାର(*fwd));
	memset(fwdargs, 0, ଆକାର(fwdargs));

	/*
	 * We expand environment variables before checking if we think they're
	 * paths so that if ${VAR} expands to a fully qualified path it is
	 * treated as a path.
	 */
	cp = p = dollar_expand(&err, fwdspec);
	ଯଦି (p == ଖାଲି || err)
		ଫେରନ୍ତୁ 0;

	/* skip leading spaces */
	ଯେତେବେଳେ (isspace((u_char)*cp))
		cp++;

	ପାଇଁ (i = 0; i < 4; ++i) {
		ଯଦି (parse_fwd_field(&cp, &fwdargs[i]) != 0)
			ଭାଙ୍ଗ;
	}

	/* Check for trailing garbage */
	ଯଦି (cp != ଖାଲି && *cp != '\0') {
		i = 0;	/* failure */
	}

	ବାଛ (i) {
	ସ୍ଥିତି 1:
		ଯଦି (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
		} ଅନ୍ୟଥା {
			fwd->listen_host = ଖାଲି;
			fwd->listen_port = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		ଭାଙ୍ଗ;

	ସ୍ଥିତି 2:
		ଯଦି (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} ଅନ୍ୟଥା ଯଦି (fwdargs[1].ispath) {
			fwd->listen_host = ଖାଲି;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} ଅନ୍ୟଥା {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି 3:
		ଯଦି (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		} ଅନ୍ୟଥା ଯଦି (fwdargs[2].ispath) {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_path = xstrdup(fwdargs[2].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} ଅନ୍ୟଥା {
			fwd->listen_host = ଖାଲି;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		}
		ଭାଙ୍ଗ;

	ସ୍ଥିତି 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_port = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_port = a2port(fwdargs[3].arg);
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		i = 0; /* failure */
	}

	ମୁକ୍ତ(p);

	ଯଦି (dynamicfwd) {
		ଯଦି (!(i == 1 || i == 2))
			ଯାଅ fail_free;
	} ଅନ୍ୟଥା {
		ଯଦି (!(i == 3 || i == 4)) {
			ଯଦି (fwd->connect_path == ଖାଲି &&
			    fwd->listen_path == ଖାଲି)
				ଯାଅ fail_free;
		}
		ଯଦି (fwd->connect_port <= 0 && fwd->connect_path == ଖାଲି)
			ଯାଅ fail_free;
	}

	ଯଦି ((fwd->listen_port < 0 && fwd->listen_path == ଖାଲି) ||
	    (!remotefwd && fwd->listen_port == 0))
		ଯାଅ fail_free;
	ଯଦି (fwd->connect_host != ଖାଲି &&
	    strlen(fwd->connect_host) >= NI_MAXHOST)
		ଯାଅ fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	ଯଦି (fwd->connect_path != ଖାଲି &&
	    strlen(fwd->connect_path) >= PATH_MAX_SUN)
		ଯାଅ fail_free;
	ଯଦି (fwd->listen_host != ଖାଲି &&
	    strlen(fwd->listen_host) >= NI_MAXHOST)
		ଯାଅ fail_free;
	ଯଦି (fwd->listen_path != ଖାଲି &&
	    strlen(fwd->listen_path) >= PATH_MAX_SUN)
		ଯାଅ fail_free;

	ଫେରନ୍ତୁ (i);

 fail_free:
	ମୁକ୍ତ(fwd->connect_host);
	fwd->connect_host = ଖାଲି;
	ମୁକ୍ତ(fwd->connect_path);
	fwd->connect_path = ଖାଲି;
	ମୁକ୍ତ(fwd->listen_host);
	fwd->listen_host = ଖାଲି;
	ମୁକ୍ତ(fwd->listen_path);
	fwd->listen_path = ଖାଲି;
	ଫେରନ୍ତୁ (0);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_valid_hostname(ଅଚଳ ଅକ୍ଷର *s)
{
	size_t i;

	ଯଦି (*s == '-')
		ଫେରନ୍ତୁ 0;
	ପାଇଁ (i = 0; s[i] != 0; i++) {
		ଯଦି (strchr("'`\"$\\;&<>|(){},", s[i]) != ଖାଲି ||
		    isspace((u_char)s[i]) || iscntrl((u_char)s[i]))
			ଫେରନ୍ତୁ 0;
	}
	ଫେରନ୍ତୁ 1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_valid_ruser(ଅଚଳ ଅକ୍ଷର *s)
{
	size_t i;

	ଯଦି (*s == '-')
		ଫେରନ୍ତୁ 0;
	ପାଇଁ (i = 0; s[i] != 0; i++) {
		ଯଦି (iscntrl((u_char)s[i]))
			ଫେରନ୍ତୁ 0;
		ଯଦି (strchr("'`\";&<>|(){}$\\", s[i]) != ଖାଲି)
			ଫେରନ୍ତୁ 0;
		/* Disallow '-' after whitespace */
		ଯଦି (isspace((u_char)s[i]) && s[i + 1] == '-')
			ଫେରନ୍ତୁ 0;
	}
	ଫେରନ୍ତୁ 1;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_jump(ଅଚଳ ଅକ୍ଷର *s, Options *o, ପୂର୍ଣ୍ଣସଂଖ୍ୟା strict, ପୂର୍ଣ୍ଣସଂଖ୍ୟା active)
{
	ଅକ୍ଷର *orig = ଖାଲି, *sdup = ଖାଲି, *cp;
	ଅକ୍ଷର *tmp_user = ଖାଲି, *tmp_host = ଖାଲି, *host = ଖାଲି, *user = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret = -1, tmp_port = -1, port = -1, first = 1;

	ଯଦି (strcasecmp(s, "none") == 0) {
		ଯଦି (active && o->jump_host == ଖାଲି) {
			o->jump_host = xstrdup("none");
			o->jump_port = 0;
		}
		ଫେରନ୍ତୁ 0;
	}

	orig = xstrdup(s);
	ଯଦି ((cp = strchr(orig, '#')) != ଖାଲି)
		*cp = '\0';
	rtrim(orig);

	active &= o->proxy_command == ଖାଲି && o->jump_host == ଖାଲି;
	sdup = xstrdup(orig);
	କର {
		/* Work backwards through string */
		ଯଦି ((cp = strrchr(sdup, ',')) == ଖାଲି)
			cp = sdup; /* last */
		ଅନ୍ୟଥା
			*cp++ = '\0';

		r = parse_ssh_uri(cp, &tmp_user, &tmp_host, &tmp_port);
		ଯଦି (r == -1 || (r == 1 && parse_user_host_port(cp,
		    &tmp_user, &tmp_host, &tmp_port) != 0))
			ଯାଅ out; /* error already logged */
		ଯଦି (strict) {
			ଯଦି (!ssh_valid_hostname(tmp_host)) {
				error_f("invalid hostname \"%s\"", tmp_host);
				ଯାଅ out;
			}
			ଯଦି (tmp_user != ଖାଲି && !ssh_valid_ruser(tmp_user)) {
				error_f("invalid username \"%s\"", tmp_user);
				ଯାଅ out;
			}
		}
		ଯଦି (first) {
			user = tmp_user;
			host = tmp_host;
			port = tmp_port;
			tmp_user = tmp_host = ଖାଲି; /* transferred */
		}
		first = 0; /* only check syntax for subsequent hosts */
		ମୁକ୍ତ(tmp_user);
		ମୁକ୍ତ(tmp_host);
		tmp_user = tmp_host = ଖାଲି;
		tmp_port = -1;
	} ଯେତେବେଳେ (cp != sdup);

	/* success */
	ଯଦି (active) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_port = port;
		o->proxy_command = xstrdup("none");
		user = host = ଖାଲି; /* transferred */
		ଯଦି (orig != ଖାଲି && (cp = strrchr(orig, ',')) != ଖାଲି) {
			o->jump_extra = xstrdup(orig);
			o->jump_extra[cp - orig] = '\0';
		}
	}
	ret = 0;
 out:
	ମୁକ୍ତ(orig);
	ମୁକ୍ତ(sdup);
	ମୁକ୍ତ(tmp_user);
	ମୁକ୍ତ(tmp_host);
	ମୁକ୍ତ(user);
	ମୁକ୍ତ(host);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_ssh_uri(ଅଚଳ ଅକ୍ଷର *uri, ଅକ୍ଷର **userp, ଅକ୍ଷର **hostp, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *portp)
{
	ଅକ୍ଷର *user = ଖାଲି, *host = ଖାଲି, *path = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, port;

	r = parse_uri("ssh", uri, &user, &host, &port, &path);
	ଯଦି (r == 0 && path != ଖାଲି)
		r = -1;		/* path not allowed */
	ଯଦି (r == 0) {
		ଯଦି (userp != ଖାଲି) {
			*userp = user;
			user = ଖାଲି;
		}
		ଯଦି (hostp != ଖାଲି) {
			*hostp = host;
			host = ଖାଲି;
		}
		ଯଦି (portp != ଖାଲି)
			*portp = port;
	}
	ମୁକ୍ତ(user);
	ମୁକ୍ତ(host);
	ମୁକ୍ତ(path);
	ଫେରନ୍ତୁ r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
fmt_multistate_int(ପୂର୍ଣ୍ଣସଂଖ୍ୟା val, ଅଚଳ ସଂରଚନା multistate *m)
{
	u_int i;

	ପାଇଁ (i = 0; m[i].ଚାବି != ଖାଲି; i++) {
		ଯଦି (m[i].ମୂଲ୍ୟ == val)
			ଫେରନ୍ତୁ m[i].ଚାବି;
	}
	ଫେରନ୍ତୁ "UNKNOWN";
}

ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
fmt_intarg(OpCodes code, ପୂର୍ଣ୍ଣସଂଖ୍ୟା val)
{
	ଯଦି (val == -1)
		ଫେରନ୍ତୁ "unset";
	ବାଛ (code) {
	ସ୍ଥିତି oAddressFamily:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_addressfamily);
	ସ୍ଥିତି oCompression:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_compression);
	ସ୍ଥିତି o_Verify_Host_ଚାବି_DNS:
	ସ୍ଥିତି oUpdateHostkeys:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_yesnoask);
	ସ୍ଥିତି o_Strict_Host_ଚାବି_Checking:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_strict_hostkey);
	ସ୍ଥିତି oControlMaster:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_controlmaster);
	ସ୍ଥିତି oTunnel:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_tunnel);
	ସ୍ଥିତି oRequestTTY:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_requesttty);
	ସ୍ଥିତି oSessionType:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_sessiontype);
	ସ୍ଥିତି oCanonicalizeHostname:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_canonicalizehostname);
	ସ୍ଥିତି o_Add_ଚାବିଗୁଡ଼ିକ_To_Agent:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_yesnoaskconfirm);
	ସ୍ଥିତି oPubkeyAuthentication:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_pubkey_auth);
	ସ୍ଥିତି oTCPKeepAlive:
		ଫେରନ୍ତୁ fmt_multistate_int(val, multistate_keepalives);
	ସ୍ଥିତି oFingerprintHash:
		ଫେରନ୍ତୁ ssh_digest_alg_name(val);
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ବାଛ (val) {
		ସ୍ଥିତି 0:
			ଫେରନ୍ତୁ "no";
		ସ୍ଥିତି 1:
			ଫେରନ୍ତୁ "yes";
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଫେରନ୍ତୁ "UNKNOWN";
		}
	}
}

ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
lookup_opcode_name(OpCodes code)
{
	u_int i;

	ପାଇଁ (i = 0; keywords[i].name != ଖାଲି; i++)
		ଯଦି (keywords[i].opcode == code)
			ଫେରନ୍ତୁ(keywords[i].name);
	ଫେରନ୍ତୁ "UNKNOWN";
}

ସ୍ଥିର ଶୂନ୍ୟ
dump_cfg_int(OpCodes code, ପୂର୍ଣ୍ଣସଂଖ୍ୟା val)
{
	ଯଦି (code == oObscureKeystrokeTiming) {
		ଯଦି (val == 0) {
			printf("%s no\n", lookup_opcode_name(code));
			ଫେରନ୍ତୁ;
		} ଅନ୍ୟଥା ଯଦି (val == SSH_KEYSTROKE_DEFAULT_INTERVAL_MS) {
			printf("%s yes\n", lookup_opcode_name(code));
			ଫେରନ୍ତୁ;
		}
		/* FALLTHROUGH */
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

ସ୍ଥିର ଶୂନ୍ୟ
dump_cfg_fmtint(OpCodes code, ପୂର୍ଣ୍ଣସଂଖ୍ୟା val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

ସ୍ଥିର ଶୂନ୍ୟ
dump_cfg_string(OpCodes code, ଅଚଳ ଅକ୍ଷର *val)
{
	ଯଦି (val == ଖାଲି)
		ଫେରନ୍ତୁ;
	printf("%s %s\n", lookup_opcode_name(code), val);
}

ସ୍ଥିର ଶୂନ୍ୟ
dump_cfg_strarray(OpCodes code, u_int ଗଣନା_2, ଅକ୍ଷର **vals)
{
	u_int i;

	ପାଇଁ (i = 0; i < ଗଣନା_2; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

ସ୍ଥିର ଶୂନ୍ୟ
dump_cfg_strarray_oneline(OpCodes code, u_int ଗଣନା_2, ଅକ୍ଷର **vals)
{
	u_int i;

	printf("%s", lookup_opcode_name(code));
	ଯଦି (ଗଣନା_2 == 0)
		printf(" none");
	ପାଇଁ (i = 0; i < ଗଣନା_2; i++)
		printf(" %s",  vals[i]);
	printf("\n");
}

ସ୍ଥିର ଶୂନ୍ୟ
dump_cfg_forwards(OpCodes code, u_int ଗଣନା_2, ଅଚଳ ସଂରଚନା Forward *fwds)
{
	ଅଚଳ ସଂରଚନା Forward *fwd;
	u_int i;

	/* oDynamicForward */
	ପାଇଁ (i = 0; i < ଗଣନା_2; i++) {
		fwd = &fwds[i];
		ଯଦି (code == oDynamicForward && fwd->connect_host != ଖାଲି &&
		    strcmp(fwd->connect_host, "socks") != 0)
			ଜାରି;
		ଯଦି (code == oLocalForward && fwd->connect_host != ଖାଲି &&
		    strcmp(fwd->connect_host, "socks") == 0)
			ଜାରି;
		printf("%s", lookup_opcode_name(code));
		ଯଦି (fwd->listen_port == PORT_STREAMLOCAL)
			printf(" %s", fwd->listen_path);
		ଅନ୍ୟଥା ଯଦି (fwd->listen_host == ଖାଲି)
			printf(" %d", fwd->listen_port);
		ଅନ୍ୟଥା {
			printf(" [%s]:%d",
			    fwd->listen_host, fwd->listen_port);
		}
		ଯଦି (code != oDynamicForward) {
			ଯଦି (fwd->connect_port == PORT_STREAMLOCAL)
				printf(" %s", fwd->connect_path);
			ଅନ୍ୟଥା ଯଦି (fwd->connect_host == ଖାଲି)
				printf(" %d", fwd->connect_port);
			ଅନ୍ୟଥା {
				printf(" [%s]:%d",
				    fwd->connect_host, fwd->connect_port);
			}
		}
		printf("\n");
	}
}

ଶୂନ୍ୟ
dump_client_config(Options *o, ଅଚଳ ଅକ୍ଷର *host)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା i, r;
	ଅକ୍ଷର buf[8], *all_ଚାବି;

	/*
	 * Expand HostKeyAlgorithms name lists. This isn't handled in
	 * fill_default_options() like the other algorithm lists because
	 * the host key algorithms are by default dynamically chosen based
	 * on the host's keys found in known_hosts.
	 */
	all_ଚାବି = sshkey_alg_list(0, 0, 1, ',');
	ଯଦି ((r = kex_assemble_names(&o->hostkeyalgorithms, kex_default_pk_alg(),
	    all_ଚାବି)) != 0)
		fatal_fr(r, "expand HostKeyAlgorithms");
	ମୁକ୍ତ(all_ଚାବି);

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
	dump_cfg_fmtint(o_Strict_Host_ଚାବି_Checking, o->strict_host_ଚାବି_checking);
	dump_cfg_fmtint(oTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(oTunnel, o->tun_open);
	dump_cfg_fmtint(o_Verify_Host_ଚାବି_DNS, o->verify_host_ଚାବି_dns);
	dump_cfg_fmtint(o_Visual_Host_ଚାବି, o->visual_host_ଚାବି);
	dump_cfg_fmtint(oUpdateHostkeys, o->update_hostkeys);
	dump_cfg_fmtint(oEnableEscapeCommandline, o->enable_escape_commandline);
	dump_cfg_fmtint(oWarnWeakCrypto, o->warn_weak_crypto);

	/* Integer options */
	dump_cfg_int(oCanonicalizeMaxDots, o->canonicalize_max_dots);
	dump_cfg_int(oConnectionAttempts, o->connection_attempts);
	dump_cfg_int(oForwardX11Timeout, o->forward_x11_timeout);
	dump_cfg_int(o_ସଂଖ୍ୟା_Of_Password_Prompts, o->ସଂଖ୍ୟା_of_password_prompts);
	dump_cfg_int(o_Server_Alive_ଗଣନା_Max, o->server_alive_ଗଣନା_max);
	dump_cfg_int(oServerAliveInterval, o->server_alive_interval);
	dump_cfg_int(oRequiredRSASize, o->required_rsa_size);
	dump_cfg_int(oObscureKeystrokeTiming,
	    o->obscure_keystroke_timing_interval);

	/* String options */
	dump_cfg_string(oBindAddress, o->bind_address);
	dump_cfg_string(oBindInterface, o->bind_interface);
	dump_cfg_string(oCiphers, o->ciphers);
	dump_cfg_string(oControlPath, o->control_path);
	dump_cfg_string(o_Host_ଚାବି_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(o_Host_ଚାବି_Alias, o->host_ଚାବି_alias);
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
	dump_cfg_string(o_Security_ଚାବି_Provider, o->sk_provider);
	dump_cfg_string(oPreferredAuthentications, o->preferred_authentications);
	dump_cfg_string(oPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
	dump_cfg_string(oXAuthLocation, o->xauth_location);
	dump_cfg_string(oKnownHostsCommand, o->known_hosts_command);
	dump_cfg_string(oTag, o->tag);
	dump_cfg_string(oVersionAddendum, o->version_addendum);

	/* Forwards */
	dump_cfg_forwards(oDynamicForward, o->ଅଙ୍କ_local_forwards, o->local_forwards);
	dump_cfg_forwards(oLocalForward, o->ଅଙ୍କ_local_forwards, o->local_forwards);
	dump_cfg_forwards(oRemoteForward, o->ଅଙ୍କ_remote_forwards, o->remote_forwards);

	/* String array options */
	dump_cfg_strarray(oIdentityFile, o->ଅଙ୍କ_identity_files, o->identity_files);
	dump_cfg_strarray_oneline(oCanonicalDomains, o->ଅଙ୍କ_canonical_domains, o->canonical_domains);
	dump_cfg_strarray(oCertificateFile, o->ଅଙ୍କ_certificate_files, o->certificate_files);
	dump_cfg_strarray_oneline(oGlobalKnownHostsFile, o->ଅଙ୍କ_system_hostfiles, o->system_hostfiles);
	dump_cfg_strarray_oneline(oUserKnownHostsFile, o->ଅଙ୍କ_user_hostfiles, o->user_hostfiles);
	dump_cfg_strarray_oneline(o_Revoked_Host_ଚାବିଗୁଡ଼ିକ, o->ଅଙ୍କ_revoked_host_ଚାବିଗୁଡ଼ିକ, o->revoked_host_ଚାବିଗୁଡ଼ିକ);
	dump_cfg_strarray(oSendEnv, o->ଅଙ୍କ_send_env, o->send_env);
	dump_cfg_strarray(oSetEnv, o->ଅଙ୍କ_setenv, o->setenv);
	dump_cfg_strarray_oneline(oLogVerbose,
	    o->ଅଙ୍କ_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(oChannelTimeout,
	    o->ଅଙ୍କ_channel_timeouts, o->channel_timeouts);

	/* Special cases */

	/* PermitRemoteOpen */
	ଯଦି (o->ଅଙ୍କ_permitted_remote_opens == 0)
		printf("%s any\n", lookup_opcode_name(oPermitRemoteOpen));
	ଅନ୍ୟଥା
		dump_cfg_strarray_oneline(oPermitRemoteOpen,
		    o->ଅଙ୍କ_permitted_remote_opens, o->permitted_remote_opens);

	/* AddKeysToAgent */
	ଯଦି (o->add_ଚାବିଗୁଡ଼ିକ_to_agent_lifespan <= 0)
		dump_cfg_fmtint(o_Add_ଚାବିଗୁଡ଼ିକ_To_Agent, o->add_ଚାବିଗୁଡ଼ିକ_to_agent);
	ଅନ୍ୟଥା {
		printf("addkeystoagent%s %d\n",
		    o->add_ଚାବିଗୁଡ଼ିକ_to_agent == 3 ? " confirm" : "",
		    o->add_ଚାବିଗୁଡ଼ିକ_to_agent_lifespan);
	}

	/* oForwardAgent */
	ଯଦି (o->forward_agent_sock_path == ଖାଲି)
		dump_cfg_fmtint(oForwardAgent, o->forward_agent);
	ଅନ୍ୟଥା
		dump_cfg_string(oForwardAgent, o->forward_agent_sock_path);

	/* oConnectTimeout */
	ଯଦି (o->connection_timeout == -1)
		printf("connecttimeout none\n");
	ଅନ୍ୟଥା
		dump_cfg_int(oConnectTimeout, o->connection_timeout);

	/* oTunnelDevice */
	printf("tunneldevice");
	ଯଦି (o->tun_local == SSH_TUNID_ANY)
		printf(" any");
	ଅନ୍ୟଥା
		printf(" %d", o->tun_local);
	ଯଦି (o->tun_remote == SSH_TUNID_ANY)
		printf(":any");
	ଅନ୍ୟଥା
		printf(":%d", o->tun_remote);
	printf("\n");

	/* oCanonicalizePermittedCNAMEs */
	printf("canonicalizepermittedcnames");
	ଯଦି (o->ଅଙ୍କ_permitted_cnames == 0)
		printf(" none");
	ପାଇଁ (i = 0; i < o->ଅଙ୍କ_permitted_cnames; i++) {
		printf(" %s:%s", o->permitted_cnames[i].source_list,
		    o->permitted_cnames[i].target_list);
	}
	printf("\n");

	/* oControlPersist */
	ଯଦି (o->control_persist == 0 || o->control_persist_timeout == 0)
		dump_cfg_fmtint(oControlPersist, o->control_persist);
	ଅନ୍ୟଥା
		dump_cfg_int(oControlPersist, o->control_persist_timeout);

	/* oEscapeChar */
	ଯଦି (o->escape_char == SSH_ESCAPECHAR_NONE)
		printf("escapechar none\n");
	ଅନ୍ୟଥା {
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
	ଯଦି (o->jump_host == ଖାଲି)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	ଅନ୍ୟଥା {
		/* Check for numeric addresses */
		i = strchr(o->jump_host, ':') != ଖାଲି ||
		    strspn(o->jump_host, "1234567890.") == strlen(o->jump_host);
		snprintf(buf, ଆକାର(buf), "%d", o->jump_port);
		printf("proxyjump %s%s%s%s%s%s%s%s%s\n",
		    /* optional additional jump spec */
		    o->jump_extra == ଖାଲି ? "" : o->jump_extra,
		    o->jump_extra == ଖାଲି ? "" : ",",
		    /* optional user */
		    o->jump_user == ଖାଲି ? "" : o->jump_user,
		    o->jump_user == ଖାଲି ? "" : "@",
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
