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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/stat.h>
#অন্তর্ভাৱ <sys/socket.h>
#অন্তর্ভাৱ <sys/wait.h>
#অন্তর্ভাৱ <sys/un.h>

#অন্তর্ভাৱ <net/if.h>
#অন্তর্ভাৱ <netinet/in.h>
#অন্তর্ভাৱ <netinet/ip.h>
#অন্তর্ভাৱ <arpa/inet.h>

#অন্তর্ভাৱ <ctype.h>
#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <glob.h>
#অন্তর্ভাৱ <ifaddrs.h>
#অন্তর্ভাৱ <limits.h>
#অন্তর্ভাৱ <netdb.h>
#অন্তর্ভাৱ <paths.h>
#অন্তর্ভাৱ <pwd.h>
#অন্তর্ভাৱ <signal.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <util.h>
#যদি defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "ssh.h"
#অন্তর্ভাৱ "cipher.h"
#অন্তর্ভাৱ "pathnames.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "readconf.h"
#অন্তর্ভাৱ "match.h"
#অন্তর্ভাৱ "kex.h"
#অন্তর্ভাৱ "mac.h"
#অন্তর্ভাৱ "myproposal.h"
#অন্তর্ভাৱ "digest.h"
#অন্তর্ভাৱ "version.h"

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

স্থির পূর্ণাঙ্ক read_config_file_depth(ধ্রুৱ ৱর্ণ *filename, সংরচনা passwd *pw,
    ধ্রুৱ ৱর্ণ *host, ধ্রুৱ ৱর্ণ *original_host, ধ্রুৱ ৱর্ণ *remote_command,
    Options *options, পূর্ণাঙ্ক flags, পূর্ণাঙ্ক *activep, পূর্ণাঙ্ক *want_final_pass, পূর্ণাঙ্ক depth);
স্থির পূর্ণাঙ্ক process_config_সাৰি_depth(Options *options, সংরচনা passwd *pw,
    ধ্রুৱ ৱর্ণ *host, ধ্রুৱ ৱর্ণ *original_host, ধ্রুৱ ৱর্ণ *remote_command,
    ৱর্ণ *সাৰি, ধ্রুৱ ৱর্ণ *filename, পূর্ণাঙ্ক linenum, পূর্ণাঙ্ক *activep, পূর্ণাঙ্ক flags,
    পূর্ণাঙ্ক *want_final_pass, পূর্ণাঙ্ক depth);

/* Keyword tokens. */

প্রকারনির্দেশ গণনা {
	oBadOption,
	oHost, oMatch, oInclude, oTag,
	oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout,
	oGatewayPorts, oExitOnForwardFailure,
	oPasswordAuthentication,
	oXAuthLocation,
	oIdentityFile, oHostname, oPort, oRemoteForward, oLocalForward,
	oPermitRemoteOpen,
	oCertificateFile, o_Add_চাবিগুলি_To_Agent, oIdentityAgent,
	oUser, oEscapeChar, oProxyCommand,
	oGlobalKnownHostsFile, oUserKnownHostsFile, oConnectionAttempts,
	oBatchMode, oCheckHostIP, o_Strict_Host_চাবি_Checking, oCompression,
	oTCPKeepAlive, o_সংখ্যা_Of_Password_Prompts,
	oLogFacility, oLogLevel, oLogVerbose, oCiphers, oMacs,
	oPubkeyAuthentication,
	oKbdInteractiveAuthentication, oKbdInteractiveDevices, o_Host_চাবি_Alias,
	oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication,
	o_Host_চাবি_Algorithms, oBindAddress, oBindInterface, oPKCS11Provider,
	oClearAllForwardings, oNoHostAuthenticationForLocalhost,
	oEnableSSHKeysign, oRekeyLimit, o_Verify_Host_চাবি_DNS, oConnectTimeout,
	oAddressFamily, oGssAuthentication, oGssDelegateCreds,
	oServerAliveInterval, o_Server_Alive_গুনতি_Max, oIdentitiesOnly,
	oSendEnv, oSetEnv, oControlPath, oControlMaster, oControlPersist,
	oHashKnownHosts,
	oTunnel, oTunnelDevice,
	oLocalCommand, oPermitLocalCommand, oRemoteCommand,
	o_Visual_Host_চাবি,
	oKexAlgorithms, oIPQoS, oRequestTTY, oSessionType, oStdinNull,
	oForkAfterAuthentication, oIgnoreUnknown, oProxyUseFdpass,
	oCanonicalDomains, oCanonicalizeHostname, oCanonicalizeMaxDots,
	oCanonicalizeFallbackLocal, oCanonicalizePermittedCNAMEs,
	oStreamLocalBindMask, oStreamLocalBindUnlink, o_Revoked_Host_চাবিগুলি,
	oFingerprintHash, oUpdateHostkeys, oHostbasedAcceptedAlgorithms,
	oPubkeyAcceptedAlgorithms, oCASignatureAlgorithms, oProxyJump,
	o_Security_চাবি_Provider, oKnownHostsCommand, oRequiredRSASize,
	oEnableEscapeCommandline, oObscureKeystrokeTiming, oChannelTimeout,
	oVersionAddendum, oRefuseConnection, oWarnWeakCrypto,
	oIgnore, oIgnoredUnknownOption, oDeprecated, oUnsupported
} OpCodes;

/* Textual representations of the tokens. */

স্থির সংরচনা {
	ধ্রুৱ ৱর্ণ *name;
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
#যদি defined(GSSAPI)
	{ "gssapiauthentication", oGssAuthentication },
	{ "gssapidelegatecredentials", oGssDelegateCreds },
# অন্যথা
	{ "gssapiauthentication", oUnsupported },
	{ "gssapidelegatecredentials", oUnsupported },
#endif
#ifdef ENABLE_PKCS11
	{ "pkcs11provider", oPKCS11Provider },
	{ "smartcarddevice", oPKCS11Provider },
# অন্যথা
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
	{ "addkeystoagent", o_Add_চাবিগুলি_To_Agent },
	{ "identityagent", oIdentityAgent },
	{ "hostname", oHostname },
	{ "hostkeyalias", o_Host_চাবি_Alias },
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
	{ "stricthostkeychecking", o_Strict_Host_চাবি_Checking },
	{ "compression", oCompression },
	{ "tcpkeepalive", oTCPKeepAlive },
	{ "keepalive", oTCPKeepAlive },				/* obsolete */
	{ "numberofpasswordprompts", o_সংখ্যা_Of_Password_Prompts },
	{ "syslogfacility", oLogFacility },
	{ "loglevel", oLogLevel },
	{ "logverbose", oLogVerbose },
	{ "dynamicforward", oDynamicForward },
	{ "preferredauthentications", oPreferredAuthentications },
	{ "hostkeyalgorithms", o_Host_চাবি_Algorithms },
	{ "casignaturealgorithms", oCASignatureAlgorithms },
	{ "bindaddress", oBindAddress },
	{ "bindinterface", oBindInterface },
	{ "clearallforwardings", oClearAllForwardings },
	{ "enablesshkeysign", oEnableSSHKeysign },
	{ "verifyhostkeydns", o_Verify_Host_চাবি_DNS },
	{ "nohostauthenticationforlocalhost", oNoHostAuthenticationForLocalhost },
	{ "rekeylimit", oRekeyLimit },
	{ "connecttimeout", oConnectTimeout },
	{ "addressfamily", oAddressFamily },
	{ "serveraliveinterval", oServerAliveInterval },
	{ "serveralivecountmax", o_Server_Alive_গুনতি_Max },
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
	{ "visualhostkey", o_Visual_Host_চাবি },
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
	{ "revokedhostkeys", o_Revoked_Host_চাবিগুলি },
	{ "fingerprinthash", oFingerprintHash },
	{ "updatehostkeys", oUpdateHostkeys },
	{ "hostbasedacceptedalgorithms", oHostbasedAcceptedAlgorithms },
	{ "hostbasedkeytypes", oHostbasedAcceptedAlgorithms }, /* obsolete */
	{ "pubkeyacceptedalgorithms", oPubkeyAcceptedAlgorithms },
	{ "pubkeyacceptedkeytypes", oPubkeyAcceptedAlgorithms }, /* obsolete */
	{ "ignoreunknown", oIgnoreUnknown },
	{ "proxyjump", oProxyJump },
	{ "securitykeyprovider", o_Security_চাবি_Provider },
	{ "knownhostscommand", oKnownHostsCommand },
	{ "requiredrsasize", oRequiredRSASize },
	{ "enableescapecommandline", oEnableEscapeCommandline },
	{ "obscurekeystroketiming", oObscureKeystrokeTiming },
	{ "channeltimeout", oChannelTimeout },
	{ "versionaddendum", oVersionAddendum },
	{ "refuseconnection", oRefuseConnection },
	{ "warnweakcrypto", oWarnWeakCrypto },

	{ রিক্ত, oBadOption }
};

স্থির ধ্রুৱ ৱর্ণ *lookup_opcode_name(OpCodes code);

ধ্রুৱ ৱর্ণ *
kex_default_pk_alg(শূন্য)
{
	স্থির ৱর্ণ *pkalgs;

	যদি (pkalgs == রিক্ত) {
		ৱর্ণ *all_চাবি;

		all_চাবি = sshkey_alg_list(0, 0, 1, ',');
		pkalgs = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_চাবি);
		মুক্ত(all_চাবি);
	}
	ঘূৰাই pkalgs;
}

ৱর্ণ *
ssh_connection_hash(ধ্রুৱ ৱর্ণ *thishost, ধ্রুৱ ৱর্ণ *host, ধ্রুৱ ৱর্ণ *portstr,
    ধ্রুৱ ৱর্ণ *user, ধ্রুৱ ৱর্ণ *jumphost)
{
	সংরচনা ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_LENGTH];

	যদি ((md = ssh_digest_start(SSH_DIGEST_SHA1)) == রিক্ত ||
	    ssh_digest_update(md, thishost, strlen(thishost)) < 0 ||
	    ssh_digest_update(md, host, strlen(host)) < 0 ||
	    ssh_digest_update(md, portstr, strlen(portstr)) < 0 ||
	    ssh_digest_update(md, user, strlen(user)) < 0 ||
	    ssh_digest_update(md, jumphost, strlen(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, পরিমাণ(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	ঘূৰাই tohex(conn_hash, ssh_digest_bytes(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

শূন্য
add_local_forward(Options *options, ধ্রুৱ সংরচনা Forward *newfwd)
{
	সংরচনা Forward *fwd;
	পূর্ণাঙ্ক i;

	/* Don't add duplicates */
	বাবে (i = 0; i < options->অঙ্ক_local_forwards; i++) {
		যদি (forward_equals(newfwd, options->local_forwards + i))
			ঘূৰাই;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->অঙ্ক_local_forwards + 1,
	    পরিমাণ(*options->local_forwards));
	fwd = &options->local_forwards[options->অঙ্ক_local_forwards++];

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

শূন্য
add_remote_forward(Options *options, ধ্রুৱ সংরচনা Forward *newfwd)
{
	সংরচনা Forward *fwd;
	পূর্ণাঙ্ক i;

	/* Don't add duplicates */
	বাবে (i = 0; i < options->অঙ্ক_remote_forwards; i++) {
		যদি (forward_equals(newfwd, options->remote_forwards + i))
			ঘূৰাই;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->অঙ্ক_remote_forwards + 1,
	    পরিমাণ(*options->remote_forwards));
	fwd = &options->remote_forwards[options->অঙ্ক_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_port = newfwd->listen_port;
	fwd->listen_path = newfwd->listen_path;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_port = newfwd->connect_port;
	fwd->connect_path = newfwd->connect_path;
	fwd->handle = newfwd->handle;
	fwd->allocated_port = 0;
}

স্থির শূন্য
clear_forwardings(Options *options)
{
	পূর্ণাঙ্ক i;

	বাবে (i = 0; i < options->অঙ্ক_local_forwards; i++) {
		মুক্ত(options->local_forwards[i].listen_host);
		মুক্ত(options->local_forwards[i].listen_path);
		মুক্ত(options->local_forwards[i].connect_host);
		মুক্ত(options->local_forwards[i].connect_path);
	}
	যদি (options->অঙ্ক_local_forwards > 0) {
		মুক্ত(options->local_forwards);
		options->local_forwards = রিক্ত;
	}
	options->অঙ্ক_local_forwards = 0;
	বাবে (i = 0; i < options->অঙ্ক_remote_forwards; i++) {
		মুক্ত(options->remote_forwards[i].listen_host);
		মুক্ত(options->remote_forwards[i].listen_path);
		মুক্ত(options->remote_forwards[i].connect_host);
		মুক্ত(options->remote_forwards[i].connect_path);
	}
	যদি (options->অঙ্ক_remote_forwards > 0) {
		মুক্ত(options->remote_forwards);
		options->remote_forwards = রিক্ত;
	}
	options->অঙ্ক_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

শূন্য
add_certificate_file(Options *options, ধ্রুৱ ৱর্ণ *path, পূর্ণাঙ্ক userprovided)
{
	পূর্ণাঙ্ক i;

	যদি (options->অঙ্ক_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	বাবে (i = 0; i < options->অঙ্ক_certificate_files; i++) {
		যদি (options->certificate_file_userprovided[i] == userprovided &&
		    strcmp(options->certificate_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			ঘূৰাই;
		}
	}

	options->certificate_file_userprovided[options->অঙ্ক_certificate_files] =
	    userprovided;
	options->certificate_files[options->অঙ্ক_certificate_files++] =
	    xstrdup(path);
}

শূন্য
add_identity_file(Options *options, ধ্রুৱ ৱর্ণ *dir, ধ্রুৱ ৱর্ণ *filename,
    পূর্ণাঙ্ক userprovided)
{
	ৱর্ণ *path;
	পূর্ণাঙ্ক i;

	যদি (options->অঙ্ক_identity_files >= SSH_MAX_IDENTITY_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_IDENTITY_FILES);

	যদি (dir == রিক্ত) /* no dir, filename is absolute */
		path = xstrdup(filename);
	অন্যথা যদি (xasprintf(&path, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", path);

	/* Avoid registering duplicates */
	বাবে (i = 0; i < options->অঙ্ক_identity_files; i++) {
		যদি (options->identity_file_userprovided[i] == userprovided &&
		    strcmp(options->identity_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			মুক্ত(path);
			ঘূৰাই;
		}
	}

	options->identity_file_userprovided[options->অঙ্ক_identity_files] =
	    userprovided;
	options->identity_files[options->অঙ্ক_identity_files++] = path;
}

পূর্ণাঙ্ক
default_ssh_port(শূন্য)
{
	স্থির পূর্ণাঙ্ক port;
	সংরচনা servent *sp;

	যদি (port == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		port = sp ? ntohs(sp->s_port) : SSH_DEFAULT_PORT;
	}
	ঘূৰাই port;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
স্থির পূর্ণাঙ্ক
execute_in_shell(ধ্রুৱ ৱর্ণ *cmd)
{
	ৱর্ণ *shell;
	pid_t pid;
	পূর্ণাঙ্ক status;

	যদি ((shell = getenv("SHELL")) == রিক্ত)
		shell = _PATH_BSHELL;

	যদি (access(shell, X_OK) == -1) {
		fatal("Shell \"%s\" is not executable: %s",
		    shell, strerror(errno));
	}

	debug("Executing command: '%.500s'", cmd);

	/* Fork and execute the command. */
	যদি ((pid = fork()) == 0) {
		ৱর্ণ *argv[4];

		যদি (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = xstrdup(cmd);
		argv[3] = রিক্ত;

		execv(argv[0], argv);
		error("Unable to execute '%.100s': %s", cmd, strerror(errno));
		/* Die with signal to make this error apparent to parent. */
		ssh_signal(SIGTERM, SIG_DFL);
		kill(getpid(), SIGTERM);
		_exit(1);
	}
	/* Parent. */
	যদি (pid == -1)
		fatal_f("fork: %.100s", strerror(errno));

	যেতিয়ালৈ (waitpid(pid, &status, 0) == -1) {
		যদি (errno != EINTR && errno != EAGAIN)
			fatal_f("waitpid: %s", strerror(errno));
	}
	যদি (!WIFEXITED(status)) {
		error("command '%.100s' exited abnormally", cmd);
		ঘূৰাই -1;
	}
	debug3("command returned status %d", WEXITSTATUS(status));
	ঘূৰাই WEXITSTATUS(status);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
স্থির পূর্ণাঙ্ক
check_match_ifaddrs(ধ্রুৱ ৱর্ণ *addrlist)
{
#ifdef HAVE_IFADDRS_H
	সংরচনা ifaddrs *ifa, *ifaddrs = রিক্ত;
	পূর্ণাঙ্ক r, found = 0;
	ৱর্ণ addr[NI_MAXHOST];
	socklen_t salen;

	যদি (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    strerror(errno));
		ঘূৰাই 0;
	}
	বাবে (ifa = ifaddrs; ifa != রিক্ত; ifa = ifa->ifa_next) {
		যদি (ifa->ifa_addr == রিক্ত || ifa->ifa_name == রিক্ত ||
		    (ifa->ifa_flags & IFF_UP) == 0)
			অনুৱর্ত;
		ৱিকল্প (ifa->ifa_addr->sa_family) {
		পক্ষ AF_INET:
			salen = পরিমাণ(সংরচনা sockaddr_in);
			ভঙ্গ;
		পক্ষ AF_INET6:
			salen = পরিমাণ(সংরচনা sockaddr_in6);
			ভঙ্গ;
#ifdef AF_LINK
		পক্ষ AF_LINK:
			/* ignore */
			অনুৱর্ত;
#endif /* AF_LINK */
		স্ৱভাৱ:
			debug2_f("interface %s: unsupported address family %d",
			    ifa->ifa_name, ifa->ifa_addr->sa_family);
			অনুৱর্ত;
		}
		যদি ((r = getnameinfo(ifa->ifa_addr, salen, addr, পরিমাণ(addr),
		    রিক্ত, 0, NI_NUMERICHOST)) != 0) {
			debug2_f("interface %s getnameinfo failed: %s",
			    ifa->ifa_name, gai_strerror(r));
			অনুৱর্ত;
		}
		debug3_f("interface %s addr %s", ifa->ifa_name, addr);
		যদি (addr_match_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			found = 1;
			ভঙ্গ;
		}
	}
	freeifaddrs(ifaddrs);
	ঘূৰাই found;
#অন্যথা /* HAVE_IFADDRS_H */
	error("match localnetwork: not supported on this platform");
	ঘূৰাই 0;
#endif /* HAVE_IFADDRS_H */
}

/*
 * Expand a "match exec" command or an Include path, caller must free returned
 * value.
 */
স্থির ৱর্ণ *
expand_match_exec_or_include_path(ধ্রুৱ ৱর্ণ *path, Options *options,
    সংরচনা passwd *pw, ধ্রুৱ ৱর্ণ *host_arg, ধ্রুৱ ৱর্ণ *original_host,
    পূর্ণাঙ্ক final_pass, পূর্ণাঙ্ক is_include_path)
{
	ৱর্ণ thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	ৱর্ণ uidstr[32], *conn_hash_hex, *keyalias, *jmphost, *ruser;
	ৱর্ণ *host, *ret;
	পূর্ণাঙ্ক port;

	port = options->port <= 0 ? default_ssh_port() : options->port;
	ruser = options->user == রিক্ত ? pw->pw_name : options->user;
	যদি (final_pass) {
		host = xstrdup(options->hostname);
	} অন্যথা যদি (options->hostname != রিক্ত) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (ৱর্ণ *)রিক্ত);
	} অন্যথা {
		host = xstrdup(host_arg);
	}
	যদি (gethostname(thishost, পরিমাণ(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	jmphost = option_clear_or_none(options->jump_host) ?
	    "" : options->jump_host;
	strlcpy(shorthost, thishost, পরিমাণ(shorthost));
	shorthost[strcspn(thishost, ".")] = '\0';
	snprintf(portstr, পরিমাণ(portstr), "%d", port);
	snprintf(uidstr, পরিমাণ(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	conn_hash_hex = ssh_connection_hash(thishost, host,
	    portstr, ruser, jmphost);
	keyalias = options->host_চাবি_alias ?  options->host_চাবি_alias : host;

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
	    (ৱর্ণ *)রিক্ত);
	মুক্ত(host);
	মুক্ত(conn_hash_hex);
	ঘূৰাই ret;
}

/*
 * Parse and execute a Match directive.
 */
স্থির পূর্ণাঙ্ক
match_cfg_সাৰি(Options *options, ধ্রুৱ ৱর্ণ *full_সাৰি, পূর্ণাঙ্ক *acp, ৱর্ণ ***avp,
    সংরচনা passwd *pw, ধ্রুৱ ৱর্ণ *host_arg, ধ্রুৱ ৱর্ণ *original_host,
    ধ্রুৱ ৱর্ণ *remote_command, পূর্ণাঙ্ক final_pass, পূর্ণাঙ্ক *want_final_pass,
    ধ্রুৱ ৱর্ণ *filename, পূর্ণাঙ্ক linenum)
{
	ৱর্ণ *arg, *oattrib = রিক্ত, *attrib = রিক্ত, *cmd, *host, *criteria;
	ধ্রুৱ ৱর্ণ *ruser;
	পূর্ণাঙ্ক r, this_result, result = 1, attributes = 0, negate;

	/*
	 * Configuration is likely to be incomplete at this point so we
	 * must be prepared to use default values.
	 */
	ruser = options->user == রিক্ত ? pw->pw_name : options->user;
	যদি (final_pass) {
		host = xstrdup(options->hostname);
	} অন্যথা যদি (options->hostname != রিক্ত) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (ৱর্ণ *)রিক্ত);
	} অন্যথা {
		host = xstrdup(host_arg);
	}

	debug2("checking match for '%s' host %s originally %s",
	    full_সাৰি, host, original_host);
	যেতিয়ালৈ ((attrib = argv_next(acp, avp)) != রিক্ত) {
		/* Terminate on comment */
		যদি (*attrib == '#') {
			argv_consume(acp);
			ভঙ্গ;
		}
		attrib = oattrib = xstrdup(attrib);
		arg = criteria = রিক্ত;
		this_result = 1;
		যদি ((negate = (attrib[0] == '!')))
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		যদি (strcasecmp(attrib, "all") == 0) {
			যদি (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != রিক্ত &&
			    *arg != '\0' && *arg != '#')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				result = -1;
				গচ্ছ out;
			}
			যদি (arg != রিক্ত && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			যদি (result)
				result = negate ? 0 : 1;
			গচ্ছ out;
		}
		attributes++;
		/* criteria "final" and "canonical" have no argument */
		যদি (strcasecmp(attrib, "canonical") == 0 ||
		    strcasecmp(attrib, "final") == 0) {
			/*
			 * If the config requests "Match final" without
			 * negation then remember this so we can perform a
			 * second pass later.
			 */
			যদি (strcasecmp(attrib, "final") == 0 &&
			    want_final_pass != রিক্ত)
				*want_final_pass |= !negate;
			r = !!final_pass;  /* force bitmask member to boolean */
			যদি (r == (negate ? 1 : 0))
				this_result = result = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_result ? "" : "not ", oattrib);
			গচ্ছ next;
		}

		/* Keep this list in sync with below */
		যদি (strprefix(attrib, "host=", 1)  != রিক্ত ||
		    strprefix(attrib, "originalhost=", 1) != রিক্ত ||
		    strprefix(attrib, "user=", 1) != রিক্ত ||
		    strprefix(attrib, "localuser=", 1) != রিক্ত ||
		    strprefix(attrib, "localnetwork=", 1) != রিক্ত ||
		    strprefix(attrib, "version=", 1) != রিক্ত ||
		    strprefix(attrib, "tagged=", 1) != রিক্ত ||
		    strprefix(attrib, "command=", 1) != রিক্ত ||
		    strprefix(attrib, "exec=", 1) != রিক্ত) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} অন্যথা যদি ((arg = argv_next(acp, avp)) == রিক্ত) {
			error("%.200s line %d: missing argument for Match '%s'",
			    filename, linenum, oattrib);
			result = -1;
			গচ্ছ out;
		}

		/*
		 * All other criteria require an argument, though it may
		 * be the empty string for the "tagged" and "command"
		 * options.
		 */
		যদি (*arg == '\0' &&
		    strcasecmp(attrib, "tagged") != 0 &&
		    strcasecmp(attrib, "command") != 0)
			arg = রিক্ত;
		যদি (arg == রিক্ত || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			গচ্ছ out;
		}
		যদি (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = match_hostname(host, arg) == 1;
			যদি (r == (negate ? 1 : 0))
				this_result = result = 0;
		} অন্যথা যদি (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = match_hostname(original_host, arg) == 1;
			যদি (r == (negate ? 1 : 0))
				this_result = result = 0;
		} অন্যথা যদি (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = match_pattern_list(ruser, arg, 0) == 1;
			যদি (r == (negate ? 1 : 0))
				this_result = result = 0;
		} অন্যথা যদি (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = match_pattern_list(pw->pw_name, arg, 0) == 1;
			যদি (r == (negate ? 1 : 0))
				this_result = result = 0;
		} অন্যথা যদি (strcasecmp(attrib, "localnetwork") == 0) {
			যদি (addr_match_cidr_list(রিক্ত, arg) == -1) {
				/* Error already printed */
				result = -1;
				গচ্ছ out;
			}
			r = check_match_ifaddrs(arg) == 1;
			যদি (r == (negate ? 1 : 0))
				this_result = result = 0;
		} অন্যথা যদি (strcasecmp(attrib, "version") == 0) {
			criteria = xstrdup(SSH_RELEASE);
			r = match_pattern_list(SSH_RELEASE, arg, 0) == 1;
			যদি (r == (negate ? 1 : 0))
				this_result = result = 0;
		} অন্যথা যদি (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->tag == রিক্ত ? "" :
			    options->tag);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			যদি (r == (negate ? 1 : 0))
				this_result = result = 0;
		} অন্যথা যদি (strcasecmp(attrib, "command") == 0) {
			criteria = xstrdup(remote_command == রিক্ত ?
			    "" : remote_command);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			যদি (r == (negate ? 1 : 0))
				this_result = result = 0;
		} অন্যথা যদি (strcasecmp(attrib, "sessiontype") == 0) {
			যদি (options->session_type == SESSION_TYPE_SUBSYSTEM)
				criteria = xstrdup("subsystem");
			অন্যথা যদি (options->session_type == SESSION_TYPE_NONE)
				criteria = xstrdup("none");
			অন্যথা যদি (remote_command != রিক্ত &&
			    *remote_command != '\0')
				criteria = xstrdup("exec");
			অন্যথা
				criteria = xstrdup("shell");
			r = match_pattern_list(criteria, arg, 0) == 1;
			যদি (r == (negate ? 1 : 0))
				this_result = result = 0;
		} অন্যথা যদি (strcasecmp(attrib, "exec") == 0) {
			যদি ((cmd = expand_match_exec_or_include_path(arg,
			    options, pw, host_arg, original_host,
			    final_pass, 0)) == রিক্ত) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			যদি (result != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				মুক্ত(cmd);
				গচ্ছ next;
			}
			r = execute_in_shell(cmd);
			যদি (r == -1) {
				fatal("%.200s line %d: match exec "
				    "'%.100s' error", filename,
				    linenum, cmd);
			}
			criteria = xstrdup(cmd);
			মুক্ত(cmd);
			/* Force exit status to boolean */
			r = r == 0;
			যদি (r == (negate ? 1 : 0))
				this_result = result = 0;
		} অন্যথা {
			error("Unsupported Match attribute %s", attrib);
			result = -1;
			গচ্ছ out;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s' ",
		    filename, linenum, this_result ? "": "not ", oattrib,
		    criteria == রিক্ত ? "" : " \"",
		    criteria == রিক্ত ? "" : criteria,
		    criteria == রিক্ত ? "" : "\"");
 next:
		মুক্ত(criteria);
		মুক্ত(oattrib);
		oattrib = attrib = রিক্ত;
	}
	যদি (attributes == 0) {
		error("One or more attributes required for Match");
		result = -1;
		গচ্ছ out;
	}
 out:
	যদি (result != -1)
		debug2("match %sfound", result ? "" : "not ");
	মুক্ত(oattrib);
	মুক্ত(host);
	ঘূৰাই result;
}

/* Remove environment variable by pattern */
স্থির শূন্য
rm_env(Options *options, ধ্রুৱ ৱর্ণ *arg, ধ্রুৱ ৱর্ণ *filename, পূর্ণাঙ্ক linenum)
{
	u_int i, j, onum_send_env = options->অঙ্ক_send_env;

	/* Remove an environment variable */
	বাবে (i = 0; i < options->অঙ্ক_send_env; ) {
		যদি (!match_pattern(options->send_env[i], arg + 1)) {
			i++;
			অনুৱর্ত;
		}
		debug3("%s line %d: removing environment %s",
		    filename, linenum, options->send_env[i]);
		মুক্ত(options->send_env[i]);
		options->send_env[i] = রিক্ত;
		বাবে (j = i; j < options->অঙ্ক_send_env - 1; j++) {
			options->send_env[j] = options->send_env[j + 1];
			options->send_env[j + 1] = রিক্ত;
		}
		options->অঙ্ক_send_env--;
		/* NB. don't increment i */
	}
	যদি (onum_send_env != options->অঙ্ক_send_env) {
		options->send_env = xrecallocarray(options->send_env,
		    onum_send_env, options->অঙ্ক_send_env,
		    পরিমাণ(*options->send_env));
	}
}

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */
স্থির OpCodes
parse_token(ধ্রুৱ ৱর্ণ *cp, ধ্রুৱ ৱর্ণ *filename, পূর্ণাঙ্ক linenum,
    ধ্রুৱ ৱর্ণ *ignored_unknown)
{
	পূর্ণাঙ্ক i;

	বাবে (i = 0; keywords[i].name; i++)
		যদি (strcmp(cp, keywords[i].name) == 0)
			ঘূৰাই keywords[i].opcode;
	যদি (ignored_unknown != রিক্ত &&
	    match_pattern_list(cp, ignored_unknown, 1) == 1)
		ঘূৰাই oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	ঘূৰাই oBadOption;
}

স্থির শূন্য
free_canon_cnames(সংরচনা allowed_cname *cnames, u_int n)
{
	u_int i;

	যদি (cnames == রিক্ত || n == 0)
		ঘূৰাই;
	বাবে (i = 0; i < n; i++) {
		মুক্ত(cnames[i].source_list);
		মুক্ত(cnames[i].target_list);
	}
	মুক্ত(cnames);
}

/* Multistate option parsing */
সংরচনা multistate {
	ৱর্ণ *চাবি;
	পূর্ণাঙ্ক মান;
};
স্থির ধ্রুৱ সংরচনা multistate multistate_flag[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ রিক্ত, -1 }
};
স্থির ধ্রুৱ সংরচনা multistate multistate_yesnoask[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ রিক্ত, -1 }
};
স্থির ধ্রুৱ সংরচনা multistate multistate_strict_hostkey[] = {
	{ "true",			SSH_STRICT_HOSTKEY_YES },
	{ "false",			SSH_STRICT_HOSTKEY_OFF },
	{ "yes",			SSH_STRICT_HOSTKEY_YES },
	{ "no",				SSH_STRICT_HOSTKEY_OFF },
	{ "ask",			SSH_STRICT_HOSTKEY_ASK },
	{ "off",			SSH_STRICT_HOSTKEY_OFF },
	{ "accept-new",			SSH_STRICT_HOSTKEY_NEW },
	{ রিক্ত, -1 }
};
স্থির ধ্রুৱ সংরচনা multistate multistate_yesnoaskconfirm[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "confirm",			3 },
	{ রিক্ত, -1 }
};
স্থির ধ্রুৱ সংরচনা multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ রিক্ত, -1 }
};
স্থির ধ্রুৱ সংরচনা multistate multistate_controlmaster[] = {
	{ "true",			SSHCTL_MASTER_YES },
	{ "yes",			SSHCTL_MASTER_YES },
	{ "false",			SSHCTL_MASTER_NO },
	{ "no",				SSHCTL_MASTER_NO },
	{ "auto",			SSHCTL_MASTER_AUTO },
	{ "ask",			SSHCTL_MASTER_ASK },
	{ "autoask",			SSHCTL_MASTER_AUTO_ASK },
	{ রিক্ত, -1 }
};
স্থির ধ্রুৱ সংরচনা multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET },
	{ "point-to-point",		SSH_TUNMODE_POINTOPOINT },
	{ "true",			SSH_TUNMODE_DEFAULT },
	{ "yes",			SSH_TUNMODE_DEFAULT },
	{ "false",			SSH_TUNMODE_NO },
	{ "no",				SSH_TUNMODE_NO },
	{ রিক্ত, -1 }
};
স্থির ধ্রুৱ সংরচনা multistate multistate_requesttty[] = {
	{ "true",			REQUEST_TTY_YES },
	{ "yes",			REQUEST_TTY_YES },
	{ "false",			REQUEST_TTY_NO },
	{ "no",				REQUEST_TTY_NO },
	{ "force",			REQUEST_TTY_FORCE },
	{ "auto",			REQUEST_TTY_AUTO },
	{ রিক্ত, -1 }
};
স্থির ধ্রুৱ সংরচনা multistate multistate_sessiontype[] = {
	{ "none",			SESSION_TYPE_NONE },
	{ "subsystem",			SESSION_TYPE_SUBSYSTEM },
	{ "default",			SESSION_TYPE_DEFAULT },
	{ রিক্ত, -1 }
};
স্থির ধ্রুৱ সংরচনা multistate multistate_canonicalizehostname[] = {
	{ "true",			SSH_CANONICALISE_YES },
	{ "false",			SSH_CANONICALISE_NO },
	{ "yes",			SSH_CANONICALISE_YES },
	{ "no",				SSH_CANONICALISE_NO },
	{ "always",			SSH_CANONICALISE_ALWAYS },
	{ রিক্ত, -1 }
};
স্থির ধ্রুৱ সংরচনা multistate multistate_pubkey_auth[] = {
	{ "true",			SSH_PUBKEY_AUTH_ALL },
	{ "false",			SSH_PUBKEY_AUTH_NO },
	{ "yes",			SSH_PUBKEY_AUTH_ALL },
	{ "no",				SSH_PUBKEY_AUTH_NO },
	{ "unbound",			SSH_PUBKEY_AUTH_UNBOUND },
	{ "host-bound",			SSH_PUBKEY_AUTH_HBOUND },
	{ রিক্ত, -1 }
};
স্থির ধ্রুৱ সংরচনা multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ রিক্ত, -1 }
};
স্থির ধ্রুৱ সংরচনা multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ রিক্ত, -1 }
};
/* XXX this will need to be replaced with a bitmask if we add more flags */
স্থির ধ্রুৱ সংরচনা multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ রিক্ত, -1 }
};

স্থির পূর্ণাঙ্ক
parse_multistate_মান(ধ্রুৱ ৱর্ণ *arg, ধ্রুৱ ৱর্ণ *filename, পূর্ণাঙ্ক linenum,
    ধ্রুৱ সংরচনা multistate *multistate_ptr)
{
	পূর্ণাঙ্ক i;

	যদি (!arg || *arg == '\0') {
		error("%s line %d: missing argument.", filename, linenum);
		ঘূৰাই -1;
	}
	বাবে (i = 0; multistate_ptr[i].চাবি != রিক্ত; i++) {
		যদি (strcasecmp(arg, multistate_ptr[i].চাবি) == 0)
			ঘূৰাই multistate_ptr[i].মান;
	}
	ঘূৰাই -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
পূর্ণাঙ্ক
process_config_সাৰি(Options *options, সংরচনা passwd *pw, ধ্রুৱ ৱর্ণ *host,
    ধ্রুৱ ৱর্ণ *original_host, ধ্রুৱ ৱর্ণ *remote_command, ৱর্ণ *সাৰি,
    ধ্রুৱ ৱর্ণ *filename, পূর্ণাঙ্ক linenum, পূর্ণাঙ্ক *activep, পূর্ণাঙ্ক flags)
{
	ঘূৰাই process_config_সাৰি_depth(options, pw, host, original_host,
	    remote_command, সাৰি, filename, linenum, activep, flags, রিক্ত, 0);
}

#define WHITESPACE " \t\r\n"
স্থির পূর্ণাঙ্ক
process_config_সাৰি_depth(Options *options, সংরচনা passwd *pw, ধ্রুৱ ৱর্ণ *host,
    ধ্রুৱ ৱর্ণ *original_host, ধ্রুৱ ৱর্ণ *remote_command, ৱর্ণ *সাৰি,
    ধ্রুৱ ৱর্ণ *filename, পূর্ণাঙ্ক linenum, পূর্ণাঙ্ক *activep, পূর্ণাঙ্ক flags,
    পূর্ণাঙ্ক *want_final_pass, পূর্ণাঙ্ক depth)
{
	ৱর্ণ *str, **charptr, *endofnumber, *keyword, *arg, *arg2, *p;
	ৱর্ণ **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	পূর্ণাঙ্ক r, oactive, negated, opcode, *intptr, মান, value2, cmdline = 0;
	পূর্ণাঙ্ক remotefwd, dynamicfwd, ca_only = 0, found = 0;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	long long val64;
	size_t len;
	সংরচনা Forward fwd;
	ধ্রুৱ সংরচনা multistate *multistate_ptr;
	glob_t gl;
	ধ্রুৱ ৱর্ণ *errstr;
	ৱর্ণ **oav = রিক্ত, **av;
	পূর্ণাঙ্ক oac = 0, ac;
	পূর্ণাঙ্ক ret = -1;
	সংরচনা allowed_cname *cnames = রিক্ত;
	u_int ncnames = 0;
	ৱর্ণ **strs = রিক্ত; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	যদি (activep == রিক্ত) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	যদি ((len = strlen(সাৰি)) == 0)
		ঘূৰাই 0;
	বাবে (len--; len > 0; len--) {
		যদি (strchr(WHITESPACE "\f", সাৰি[len]) == রিক্ত)
			ভঙ্গ;
		সাৰি[len] = '\0';
	}

	str = সাৰি;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	যদি ((keyword = strdelim(&str)) == রিক্ত)
		ঘূৰাই 0;
	/* Ignore leading whitespace. */
	যদি (*keyword == '\0')
		keyword = strdelim(&str);
	যদি (keyword == রিক্ত || !*keyword || *keyword == '\n' || *keyword == '#')
		ঘূৰাই 0;
	/* Match lowercase keyword */
	lowercase(keyword);

	/* Prepare to parse remainder of line */
	যদি (str != রিক্ত)
		str += strspn(str, WHITESPACE);
	যদি (str == রিক্ত || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		ঘূৰাই -1;
	}
	opcode = parse_token(keyword, filename, linenum,
	    options->ignored_unknown);
	যদি (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		ঘূৰাই -1;
	}
	ac = oac;
	av = oav;

	ৱিকল্প (opcode) {
	পক্ষ oBadOption:
		/* don't panic, but count bad options */
		গচ্ছ out;
	পক্ষ oIgnore:
		argv_consume(&ac);
		ভঙ্গ;
	পক্ষ oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		ভঙ্গ;
	পক্ষ oConnectTimeout:
		intptr = &options->connection_timeout;
parse_time:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			গচ্ছ out;
		}
		যদি (strcmp(arg, "none") == 0)
			মান = -1;
		অন্যথা যদি ((মান = convtime(arg)) == -1) {
			error("%s line %d: invalid time value.",
			    filename, linenum);
			গচ্ছ out;
		}
		যদি (*activep && *intptr == -1)
			*intptr = মান;
		ভঙ্গ;

	পক্ষ oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%s line %d: missing argument.",
			    filename, linenum);
			গচ্ছ out;
		}

		মান = -1;
		multistate_ptr = multistate_flag;
		বাবে (i = 0; multistate_ptr[i].চাবি != রিক্ত; i++) {
			যদি (strcasecmp(arg, multistate_ptr[i].চাবি) == 0) {
				মান = multistate_ptr[i].মান;
				ভঙ্গ;
			}
		}
		যদি (মান != -1) {
			যদি (*activep && *intptr == -1)
				*intptr = মান;
			ভঙ্গ;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		যদি (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_path;
		গচ্ছ parse_agent_path;

	পক্ষ oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_next(&ac, &av);
		যদি ((মান = parse_multistate_মান(arg, filename, linenum,
		    multistate_ptr)) == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			গচ্ছ out;
		}
		যদি (*activep && *intptr == -1)
			*intptr = মান;
		ভঙ্গ;

	পক্ষ oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		গচ্ছ parse_flag;

	পক্ষ oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		গচ্ছ parse_time;

	পক্ষ oGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		গচ্ছ parse_flag;

	পক্ষ oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		গচ্ছ parse_flag;

	পক্ষ oPasswordAuthentication:
		intptr = &options->password_authentication;
		গচ্ছ parse_flag;

	পক্ষ oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		গচ্ছ parse_flag;

	পক্ষ oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		গচ্ছ parse_string;

	পক্ষ oPubkeyAuthentication:
		multistate_ptr = multistate_pubkey_auth;
		intptr = &options->pubkey_authentication;
		গচ্ছ parse_multistate;

	পক্ষ oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		গচ্ছ parse_flag;

	পক্ষ oGssAuthentication:
		intptr = &options->gss_authentication;
		গচ্ছ parse_flag;

	পক্ষ oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		গচ্ছ parse_flag;

	পক্ষ oBatchMode:
		intptr = &options->batch_mode;
		গচ্ছ parse_flag;

	পক্ষ oCheckHostIP:
		intptr = &options->check_host_ip;
		গচ্ছ parse_flag;

	পক্ষ o_Verify_Host_চাবি_DNS:
		intptr = &options->verify_host_চাবি_dns;
		multistate_ptr = multistate_yesnoask;
		গচ্ছ parse_multistate;

	পক্ষ o_Strict_Host_চাবি_Checking:
		intptr = &options->strict_host_চাবি_checking;
		multistate_ptr = multistate_strict_hostkey;
		গচ্ছ parse_multistate;

	পক্ষ oCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		গচ্ছ parse_multistate;

	পক্ষ oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		গচ্ছ parse_multistate;

	পক্ষ oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		গচ্ছ parse_flag;

	পক্ষ o_সংখ্যা_Of_Password_Prompts:
		intptr = &options->সংখ্যা_of_password_prompts;
		গচ্ছ parse_int;

	পক্ষ oRekeyLimit:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.", filename,
			    linenum);
			গচ্ছ out;
		}
		যদি (strcmp(arg, "default") == 0) {
			val64 = 0;
		} অন্যথা {
			যদি (scan_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, strerror(errno));
				গচ্ছ out;
			}
			যদি (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				গচ্ছ out;
			}
		}
		যদি (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		যদি (ac != 0) { /* optional rekey interval present */
			যদি (strcmp(av[0], "none") == 0) {
				(শূন্য)argv_next(&ac, &av);	/* discard */
				ভঙ্গ;
			}
			intptr = &options->rekey_interval;
			গচ্ছ parse_time;
		}
		ভঙ্গ;

	পক্ষ oIdentityFile:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			গচ্ছ out;
		}
		যদি (*activep) {
			intptr = &options->অঙ্ক_identity_files;
			যদি (*intptr >= SSH_MAX_IDENTITY_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_IDENTITY_FILES);
				গচ্ছ out;
			}
			add_identity_file(options, রিক্ত,
			    arg, flags & SSHCONF_USERCONF);
		}
		ভঙ্গ;

	পক্ষ oCertificateFile:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			গচ্ছ out;
		}
		যদি (*activep) {
			intptr = &options->অঙ্ক_certificate_files;
			যদি (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				গচ্ছ out;
			}
			add_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		ভঙ্গ;

	পক্ষ oXAuthLocation:
		charptr=&options->xauth_location;
		গচ্ছ parse_string;

	পক্ষ oUser:
		charptr = &options->user;
parse_string:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			গচ্ছ out;
		}
		যদি (*activep && *charptr == রিক্ত)
			*charptr = xstrdup(arg);
		ভঙ্গ;

	পক্ষ oGlobalKnownHostsFile:
		cpptr = (ৱর্ণ **)&options->system_hostfiles;
		uintptr = &options->অঙ্ক_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		i = 0;
		মান = *uintptr == 0; /* was array empty when we started? */
		যেতিয়ালৈ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			যদি (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				গচ্ছ out;
			}
			/* Allow "none" only in first position */
			যদি (strcasecmp(arg, "none") == 0) {
				যদি (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					গচ্ছ out;
				}
			}
			i++;
			যদি (*activep && মান) {
				যদি ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries.", filename, linenum,
					    keyword);
					গচ্ছ out;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		ভঙ্গ;

	পক্ষ oUserKnownHostsFile:
		cpptr = (ৱর্ণ **)&options->user_hostfiles;
		uintptr = &options->অঙ্ক_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		গচ্ছ parse_char_array;

	পক্ষ oHostname:
		charptr = &options->hostname;
		গচ্ছ parse_string;

	পক্ষ oTag:
		charptr = &options->tag;
		গচ্ছ parse_string;

	পক্ষ o_Host_চাবি_Alias:
		charptr = &options->host_চাবি_alias;
		গচ্ছ parse_string;

	পক্ষ oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		গচ্ছ parse_string;

	পক্ষ oBindAddress:
		charptr = &options->bind_address;
		গচ্ছ parse_string;

	পক্ষ oBindInterface:
		charptr = &options->bind_interface;
		গচ্ছ parse_string;

	পক্ষ oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		গচ্ছ parse_string;

	পক্ষ o_Security_চাবি_Provider:
		charptr = &options->sk_provider;
		গচ্ছ parse_string;

	পক্ষ oKnownHostsCommand:
		charptr = &options->known_hosts_command;
		গচ্ছ parse_command;

	পক্ষ oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		যদি (str == রিক্ত) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			গচ্ছ out;
		}
		len = strspn(str, WHITESPACE "=");
		যদি (*activep && *charptr == রিক্ত)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		ভঙ্গ;

	পক্ষ oProxyJump:
		যদি (str == রিক্ত) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			গচ্ছ out;
		}
		len = strspn(str, WHITESPACE "=");
		/* XXX use argv? */
		যদি (parse_jump(str + len, options, cmdline, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			গচ্ছ out;
		}
		argv_consume(&ac);
		ভঙ্গ;

	পক্ষ oPort:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			গচ্ছ out;
		}
		মান = a2port(arg);
		যদি (মান <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			গচ্ছ out;
		}
		যদি (*activep && options->port == -1)
			options->port = মান;
		ভঙ্গ;

	পক্ষ oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_next(&ac, &av);
		যদি ((errstr = atoi_err(arg, &মান)) != রিক্ত) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			গচ্ছ out;
		}
		যদি (*activep && *intptr == -1)
			*intptr = মান;
		ভঙ্গ;

	পক্ষ oCiphers:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			গচ্ছ out;
		}
		যদি (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			গচ্ছ out;
		}
		যদি (*activep && options->ciphers == রিক্ত)
			options->ciphers = xstrdup(arg);
		ভঙ্গ;

	পক্ষ oMacs:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			গচ্ছ out;
		}
		যদি (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			গচ্ছ out;
		}
		যদি (*activep && options->macs == রিক্ত)
			options->macs = xstrdup(arg);
		ভঙ্গ;

	পক্ষ oKexAlgorithms:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			গচ্ছ out;
		}
		যদি (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			গচ্ছ out;
		}
		যদি (*activep && options->kex_algorithms == রিক্ত)
			options->kex_algorithms = xstrdup(arg);
		ভঙ্গ;

	পক্ষ o_Host_চাবি_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			গচ্ছ out;
		}
		যদি (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			গচ্ছ out;
		}
		যদি (*activep && *charptr == রিক্ত)
			*charptr = xstrdup(arg);
		ভঙ্গ;

	পক্ষ oCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		গচ্ছ parse_pubkey_algos;

	পক্ষ oLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		মান = log_level_সংখ্যা(arg);
		যদি (মান == SYSLOG_LEVEL_NOT_SET) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			গচ্ছ out;
		}
		যদি (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_SET)
			*log_level_ptr = (LogLevel) মান;
		ভঙ্গ;

	পক্ষ oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		মান = log_facility_সংখ্যা(arg);
		যদি (মান == SYSLOG_FACILITY_NOT_SET) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			গচ্ছ out;
		}
		যদি (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) মান;
		ভঙ্গ;

	পক্ষ oLogVerbose:
		cppptr = &options->log_verbose;
		uintptr = &options->অঙ্ক_log_verbose;
		i = 0;
		যেতিয়ালৈ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			যদি (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				গচ্ছ out;
			}
			/* Allow "none" only in first position */
			যদি (strcasecmp(arg, "none") == 0) {
				যদি (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					গচ্ছ out;
				}
			}
			i++;
			যদি (*activep && *uintptr == 0) {
				*cppptr = xrecallocarray(*cppptr, *uintptr,
				    *uintptr + 1, পরিমাণ(**cppptr));
				(*cppptr)[(*uintptr)++] = xstrdup(arg);
			}
		}
		ভঙ্গ;

	পক্ষ oLocalForward:
	পক্ষ oRemoteForward:
	পক্ষ oDynamicForward:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			গচ্ছ out;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		যদি (!dynamicfwd) {
			arg2 = argv_next(&ac, &av);
			যদি (arg2 == রিক্ত || *arg2 == '\0') {
				যদি (remotefwd)
					dynamicfwd = 1;
				অন্যথা {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					গচ্ছ out;
				}
			} অন্যথা {
				/* construct a string for parse_forward */
				snprintf(fwdarg, পরিমাণ(fwdarg), "%s:%s", arg,
				    arg2);
			}
		}
		যদি (dynamicfwd)
			strlcpy(fwdarg, arg, পরিমাণ(fwdarg));

		যদি (parse_forward(&fwd, fwdarg, dynamicfwd, remotefwd) == 0) {
			error("%.200s line %d: Bad forwarding specification.",
			    filename, linenum);
			গচ্ছ out;
		}

		যদি (*activep) {
			যদি (remotefwd) {
				add_remote_forward(options, &fwd);
			} অন্যথা {
				add_local_forward(options, &fwd);
			}
		}
		ভঙ্গ;

	পক্ষ oPermitRemoteOpen:
		uintptr = &options->অঙ্ক_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		found = *uintptr == 0;
		যেতিয়ালৈ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			যদি (strcasecmp(arg, "none") == 0 ||
			    strcasecmp(arg, "any") == 0) {
				যদি (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					মুক্ত(arg2);
					গচ্ছ out;
				}
			} অন্যথা {
				p = hpdelim(&arg);
				যদি (p == রিক্ত) {
					fatal("%s line %d: missing host in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
				}
				p = cleanhostname(p);
				/*
				 * don't want to use permitopen_port to avoid
				 * dependency on channels.[ch] here.
				 */
				যদি (arg == রিক্ত || (strcmp(arg, "*") != 0 &&
				    a2port(arg) <= 0)) {
					fatal("%s line %d: bad port number "
					    "in %s", filename, linenum,
					    lookup_opcode_name(opcode));
				}
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg2);
			মুক্ত(arg2);
		}
		যদি (nstrs == 0)
			fatal("%s line %d: missing %s specification",
			    filename, linenum, lookup_opcode_name(opcode));
		যদি (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = রিক্ত; /* transferred */
			nstrs = 0;
		}
		ভঙ্গ;

	পক্ষ oClearAllForwardings:
		intptr = &options->clear_forwardings;
		গচ্ছ parse_flag;

	পক্ষ oHost:
		যদি (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			গচ্ছ out;
		}
		*activep = 0;
		arg2 = রিক্ত;
		যেতিয়ালৈ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			যদি (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				গচ্ছ out;
			}
			যদি ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				ভঙ্গ;
			}
			negated = *arg == '!';
			যদি (negated)
				arg++;
			যদি (match_pattern(host, arg)) {
				যদি (negated) {
					debug("%.200s line %d: Skipping Host "
					    "block because of negated match "
					    "for %.100s", filename, linenum,
					    arg);
					*activep = 0;
					argv_consume(&ac);
					ভঙ্গ;
				}
				যদি (!*activep)
					arg2 = arg; /* logged below */
				*activep = 1;
			}
		}
		যদি (*activep)
			debug("%.200s line %d: Applying options for %.100s",
			    filename, linenum, arg2);
		ভঙ্গ;

	পক্ষ oMatch:
		যদি (cmdline) {
			error("Match directive not supported as a command-line "
			    "option");
			গচ্ছ out;
		}
		মান = match_cfg_সাৰি(options, str, &ac, &av, pw, host,
		    original_host, remote_command, flags & SSHCONF_FINAL,
		    want_final_pass, filename, linenum);
		যদি (মান < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			গচ্ছ out;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : মান;
		ভঙ্গ;

	পক্ষ oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			গচ্ছ out;
		}
		যদি (strcmp(arg, "none") == 0)
			মান = SSH_ESCAPECHAR_NONE;
		অন্যথা যদি (arg[1] == '\0')
			মান = (u_char) arg[0];
		অন্যথা যদি (arg[0] == '^' && arg[2] == 0 &&
		    (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			মান = (u_char) arg[1] & 31;
		অন্যথা {
			error("%.200s line %d: Bad escape character.",
			    filename, linenum);
			গচ্ছ out;
		}
		যদি (*activep && *intptr == -1)
			*intptr = মান;
		ভঙ্গ;

	পক্ষ oAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
		গচ্ছ parse_multistate;

	পক্ষ oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		গচ্ছ parse_flag;

	পক্ষ oIdentitiesOnly:
		intptr = &options->identities_only;
		গচ্ছ parse_flag;

	পক্ষ oServerAliveInterval:
		intptr = &options->server_alive_interval;
		গচ্ছ parse_time;

	পক্ষ o_Server_Alive_গুনতি_Max:
		intptr = &options->server_alive_গুনতি_max;
		গচ্ছ parse_int;

	পক্ষ oSendEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		যেতিয়ালৈ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			যদি (*arg == '\0' || strchr(arg, '=') != রিক্ত) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				গচ্ছ out;
			}
			found = 1;
			যদি (!*activep)
				অনুৱর্ত;
			যদি (*arg == '-') {
				/* Removing an env var */
				rm_env(options, arg, filename, linenum);
				অনুৱর্ত;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->অঙ্ক_send_env, arg);
		}
		যদি (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		ভঙ্গ;

	পক্ষ oSetEnv:
		found = options->অঙ্ক_setenv == 0;
		যেতিয়ালৈ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			যদি (strchr(arg, '=') == রিক্ত) {
				error("%s line %d: Invalid SetEnv.",
				    filename, linenum);
				গচ্ছ out;
			}
			যদি (lookup_setenv_in_list(arg, strs, nstrs) != রিক্ত) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				অনুৱর্ত;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg);
		}
		যদি (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		যদি (found && *activep) {
			options->setenv = strs;
			options->অঙ্ক_setenv = nstrs;
			strs = রিক্ত; /* transferred */
			nstrs = 0;
		}
		ভঙ্গ;

	পক্ষ oControlPath:
		charptr = &options->control_path;
		গচ্ছ parse_string;

	পক্ষ oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		গচ্ছ parse_multistate;

	পক্ষ oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing ControlPersist"
			    " argument.", filename, linenum);
			গচ্ছ out;
		}
		মান = 0;
		value2 = 0;	/* timeout */
		যদি (strcmp(arg, "no") == 0 || strcmp(arg, "false") == 0)
			মান = 0;
		অন্যথা যদি (strcmp(arg, "yes") == 0 || strcmp(arg, "true") == 0)
			মান = 1;
		অন্যথা যদি ((value2 = convtime(arg)) >= 0)
			মান = 1;
		অন্যথা {
			error("%.200s line %d: Bad ControlPersist argument.",
			    filename, linenum);
			গচ্ছ out;
		}
		যদি (*activep && *intptr == -1) {
			*intptr = মান;
			options->control_persist_timeout = value2;
		}
		ভঙ্গ;

	পক্ষ oHashKnownHosts:
		intptr = &options->hash_known_hosts;
		গচ্ছ parse_flag;

	পক্ষ oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		গচ্ছ parse_multistate;

	পক্ষ oTunnelDevice:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			গচ্ছ out;
		}
		মান = a2tun(arg, &value2);
		যদি (মান == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			গচ্ছ out;
		}
		যদি (*activep && options->tun_local == -1) {
			options->tun_local = মান;
			options->tun_remote = value2;
		}
		ভঙ্গ;

	পক্ষ oLocalCommand:
		charptr = &options->local_command;
		গচ্ছ parse_command;

	পক্ষ oPermitLocalCommand:
		intptr = &options->permit_local_command;
		গচ্ছ parse_flag;

	পক্ষ oRemoteCommand:
		charptr = &options->remote_command;
		গচ্ছ parse_command;

	পক্ষ o_Visual_Host_চাবি:
		intptr = &options->visual_host_চাবি;
		গচ্ছ parse_flag;

	পক্ষ oInclude:
		যদি (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			গচ্ছ out;
		}
		মান = 0;
		যেতিয়ালৈ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			যদি (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				গচ্ছ out;
			}
			/* Expand %tokens and environment variables */
			যদি ((p = expand_match_exec_or_include_path(arg,
			    options, pw, host, original_host,
			    flags & SSHCONF_FINAL, 1)) == রিক্ত) {
				error("%.200s line %d: Unable to expand user "
				    "config file '%.100s'",
				    filename, linenum, arg);
				অনুৱর্ত;
			}
			/*
			 * Ensure all paths are anchored. User configuration
			 * files may begin with '~/' but system configurations
			 * must not. If the path is relative, then treat it
			 * as living in ~/.ssh for user configurations or
			 * /etc/ssh for system ones.
			 */
			যদি (*p == '~' && (flags & SSHCONF_USERCONF) == 0) {
				error("%.200s line %d: bad include path %s.",
				    filename, linenum, p);
				গচ্ছ out;
			}
			যদি (!path_absolute(p) && *p != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" _PATH_SSH_USER_DIR : SSHDIR, p);
			} অন্যথা {
				arg2 = xstrdup(p);
			}
			মুক্ত(p);
			memset(&gl, 0, পরিমাণ(gl));
			r = glob(arg2, GLOB_TILDE, রিক্ত, &gl);
			যদি (r == GLOB_NOMATCH) {
				debug("%.200s line %d: include %s matched no "
				    "files",filename, linenum, arg2);
				মুক্ত(arg2);
				অনুৱর্ত;
			} অন্যথা যদি (r != 0) {
				error("%.200s line %d: glob failed for %s.",
				    filename, linenum, arg2);
				গচ্ছ out;
			}
			মুক্ত(arg2);
			oactive = *activep;
			বাবে (i = 0; i < gl.gl_pathc; i++) {
				debug3("%.200s line %d: Including file %s "
				    "depth %d%s", filename, linenum,
				    gl.gl_pathv[i], depth,
				    oactive ? "" : " (parse only)");
				r = read_config_file_depth(gl.gl_pathv[i],
				    pw, host, original_host, remote_command,
				    options, flags | SSHCONF_CHECKPERM |
				    (oactive ? 0 : SSHCONF_NEVERMATCH),
				    activep, want_final_pass, depth + 1);
				যদি (r != 1 && errno != ENOENT) {
					error("%.200s line %d: Can't open user "
					    "config file %.100s: %.100s",
					    filename, linenum, gl.gl_pathv[i],
					    strerror(errno));
					globfree(&gl);
					গচ্ছ out;
				}
				/*
				 * don't let Match in includes clobber the
				 * containing file's Match state.
				 */
				*activep = oactive;
				যদি (r != 1)
					মান = -1;
			}
			globfree(&gl);
		}
		যদি (মান != 0)
			ret = মান;
		ভঙ্গ;

	পক্ষ oIPQoS:
		arg = argv_next(&ac, &av);
		যদি ((মান = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			গচ্ছ out;
		}
		যদি (মান == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			মান = INT_MAX;
		}
		arg = argv_next(&ac, &av);
		যদি (arg == রিক্ত)
			value2 = মান;
		অন্যথা যদি ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			গচ্ছ out;
		}
		যদি (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		যদি (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = মান;
			options->ip_qos_bulk = value2;
		}
		ভঙ্গ;

	পক্ষ oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		গচ্ছ parse_multistate;

	পক্ষ oSessionType:
		intptr = &options->session_type;
		multistate_ptr = multistate_sessiontype;
		গচ্ছ parse_multistate;

	পক্ষ oStdinNull:
		intptr = &options->stdin_null;
		গচ্ছ parse_flag;

	পক্ষ oForkAfterAuthentication:
		intptr = &options->fork_after_authentication;
		গচ্ছ parse_flag;

	পক্ষ oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		গচ্ছ parse_string;

	পক্ষ oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		গচ্ছ parse_flag;

	পক্ষ oCanonicalDomains:
		found = options->অঙ্ক_canonical_domains == 0;
		যেতিয়ালৈ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			/* Allow "none" only in first position */
			যদি (strcasecmp(arg, "none") == 0) {
				যদি (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					গচ্ছ out;
				}
			}
			যদি (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				গচ্ছ out;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		যদি (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		যদি (found && *activep) {
			options->canonical_domains = strs;
			options->অঙ্ক_canonical_domains = nstrs;
			strs = রিক্ত; /* transferred */
			nstrs = 0;
		}
		ভঙ্গ;

	পক্ষ oCanonicalizePermittedCNAMEs:
		found = options->অঙ্ক_permitted_cnames == 0;
		যেতিয়ালৈ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			যদি (strcasecmp(arg, "none") == 0) {
				যদি (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					গচ্ছ out;
				}
				arg2 = "";
			} অন্যথা যদি (strcmp(arg, "*") == 0) {
				arg2 = arg;
			} অন্যথা {
				lowercase(arg);
				যদি ((arg2 = strchr(arg, ':')) == রিক্ত ||
				    arg2[1] == '\0') {
					error("%s line %d: "
					    "Invalid permitted CNAME \"%s\"",
					    filename, linenum, arg);
					গচ্ছ out;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    পরিমাণ(*cnames));
			cnames[ncnames].source_list = xstrdup(arg);
			cnames[ncnames].target_list = xstrdup(arg2);
			ncnames++;
		}
		যদি (ncnames == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		যদি (found && *activep) {
			options->permitted_cnames = cnames;
			options->অঙ্ক_permitted_cnames = ncnames;
			cnames = রিক্ত; /* transferred */
			ncnames = 0;
		}
		/* un-transferred cnames is cleaned up before exit */
		ভঙ্গ;

	পক্ষ oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		গচ্ছ parse_multistate;

	পক্ষ oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		গচ্ছ parse_int;

	পক্ষ oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		গচ্ছ parse_flag;

	পক্ষ oStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			গচ্ছ out;
		}
		/* Parse mode in octal format */
		মান = strtol(arg, &endofnumber, 8);
		যদি (arg == endofnumber || মান < 0 || মান > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			গচ্ছ out;
		}
		যদি (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)মান;
		ভঙ্গ;

	পক্ষ oStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		গচ্ছ parse_flag;

	পক্ষ o_Revoked_Host_চাবিগুলি:
		uintptr = &options->অঙ্ক_revoked_host_চাবিগুলি;
		cppptr = &options->revoked_host_চাবিগুলি;
		found = *uintptr == 0;
		যেতিয়ালৈ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			যদি (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				গচ্ছ out;
			}
			/* Allow "none" only in first position */
			যদি (strcasecmp(arg, "none") == 0) {
				যদি (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					গচ্ছ out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		যদি (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		যদি (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = রিক্ত; /* transferred */
			nstrs = 0;
		}
		ভঙ্গ;

	পক্ষ oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			গচ্ছ out;
		}
		যদি ((মান = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			গচ্ছ out;
		}
		যদি (*activep && *intptr == -1)
			*intptr = মান;
		ভঙ্গ;

	পক্ষ oUpdateHostkeys:
		intptr = &options->update_hostkeys;
		multistate_ptr = multistate_yesnoask;
		গচ্ছ parse_multistate;

	পক্ষ oHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
		গচ্ছ parse_pubkey_algos;

	পক্ষ oPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		গচ্ছ parse_pubkey_algos;

	পক্ষ o_Add_চাবিগুলি_To_Agent:
		arg = argv_next(&ac, &av);
		arg2 = argv_next(&ac, &av);
		মান = parse_multistate_মান(arg, filename, linenum,
		    multistate_yesnoaskconfirm);
		value2 = 0; /* unlimited lifespan by default */
		যদি (মান == 3 && arg2 != রিক্ত) {
			/* allow "AddKeysToAgent confirm 5m" */
			যদি ((value2 = convtime(arg2)) == -1) {
				error("%s line %d: invalid time value.",
				    filename, linenum);
				গচ্ছ out;
			}
		} অন্যথা যদি (মান == -1 && arg2 == রিক্ত) {
			যদি ((value2 = convtime(arg)) == -1) {
				error("%s line %d: unsupported option",
				    filename, linenum);
				গচ্ছ out;
			}
			মান = 1; /* yes */
		} অন্যথা যদি (মান == -1 || arg2 != রিক্ত) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			গচ্ছ out;
		}
		যদি (*activep && options->add_চাবিগুলি_to_agent == -1) {
			options->add_চাবিগুলি_to_agent = মান;
			options->add_চাবিগুলি_to_agent_lifespan = value2;
		}
		ভঙ্গ;

	পক্ষ oIdentityAgent:
		charptr = &options->identity_agent;
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			গচ্ছ out;
		}
  parse_agent_path:
		/* Extra validation if the string represents an env var. */
		যদি ((arg2 = dollar_expand(&r, arg)) == রিক্ত || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			গচ্ছ out;
		}
		মুক্ত(arg2);
		/* check for legacy environment format */
		যদি (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			গচ্ছ out;
		}
		যদি (*activep && *charptr == রিক্ত)
			*charptr = xstrdup(arg);
		ভঙ্গ;

	পক্ষ oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		গচ্ছ parse_flag;

	পক্ষ oRequiredRSASize:
		intptr = &options->required_rsa_size;
		গচ্ছ parse_int;

	পক্ষ oWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		গচ্ছ parse_multistate;

	পক্ষ oObscureKeystrokeTiming:
		মান = -1;
		যেতিয়ালৈ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			যদি (মান != -1) {
				error("%s line %d: invalid arguments",
				    filename, linenum);
				গচ্ছ out;
			}
			যদি (strcmp(arg, "yes") == 0 ||
			    strcmp(arg, "true") == 0)
				মান = SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
			অন্যথা যদি (strcmp(arg, "no") == 0 ||
			    strcmp(arg, "false") == 0)
				মান = 0;
			অন্যথা যদি (strncmp(arg, "interval:", 9) == 0) {
				যদি ((errstr = atoi_err(arg + 9,
				    &মান)) != রিক্ত) {
					error("%s line %d: integer value %s.",
					    filename, linenum, errstr);
					গচ্ছ out;
				}
				যদি (মান <= 0 || মান > 1000) {
					error("%s line %d: value out of range.",
					    filename, linenum);
					গচ্ছ out;
				}
			} অন্যথা {
				error("%s line %d: unsupported argument \"%s\"",
				    filename, linenum, arg);
				গচ্ছ out;
			}
		}
		যদি (মান == -1) {
			error("%s line %d: missing argument",
			    filename, linenum);
			গচ্ছ out;
		}
		intptr = &options->obscure_keystroke_timing_interval;
		যদি (*activep && *intptr == -1)
			*intptr = মান;
		ভঙ্গ;

	পক্ষ oChannelTimeout:
		found = options->অঙ্ক_channel_timeouts == 0;
		যেতিয়ালৈ ((arg = argv_next(&ac, &av)) != রিক্ত) {
			/* Allow "none" only in first position */
			যদি (strcasecmp(arg, "none") == 0) {
				যদি (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					গচ্ছ out;
				}
			} অন্যথা যদি (parse_pattern_interval(arg,
			    রিক্ত, রিক্ত) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		যদি (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		যদি (found && *activep) {
			options->channel_timeouts = strs;
			options->অঙ্ক_channel_timeouts = nstrs;
			strs = রিক্ত; /* transferred */
			nstrs = 0;
		}
		ভঙ্গ;

	পক্ষ oVersionAddendum:
		যদি (str == রিক্ত || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		যদি (strchr(str + len, '\r') != রিক্ত) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		যদি ((arg = strchr(সাৰি, '#')) != রিক্ত) {
			*arg = '\0';
			rtrim(সাৰি);
		}
		যদি (*activep && options->version_addendum == রিক্ত) {
			যদি (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			অন্যথা
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		ভঙ্গ;

	পক্ষ oRefuseConnection:
		arg = argv_next(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			গচ্ছ out;
		}
		যদি (*activep) {
			fatal("%.200s line %d: RefuseConnection: %s",
			    filename, linenum, arg);
		}
		ভঙ্গ;

	পক্ষ oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		ভঙ্গ;

	পক্ষ oUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		ভঙ্গ;

	স্ৱভাৱ:
		error("%s line %d: Unimplemented opcode %d",
		    filename, linenum, opcode);
		গচ্ছ out;
	}

	/* Check that there is no garbage at end of line. */
	যদি (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		গচ্ছ out;
	}

	/* success */
	ret = 0;
 out:
	free_canon_cnames(cnames, ncnames);
	opt_array_free2(strs, রিক্ত, nstrs);
	argv_free(oav, oac);
	ঘূৰাই ret;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */
পূর্ণাঙ্ক
read_config_file(ধ্রুৱ ৱর্ণ *filename, সংরচনা passwd *pw, ধ্রুৱ ৱর্ণ *host,
    ধ্রুৱ ৱর্ণ *original_host, ধ্রুৱ ৱর্ণ *remote_command, Options *options, পূর্ণাঙ্ক flags,
    পূর্ণাঙ্ক *want_final_pass)
{
	পূর্ণাঙ্ক active = 1;

	ঘূৰাই read_config_file_depth(filename, pw, host, original_host,
	    remote_command, options, flags, &active, want_final_pass, 0);
}

#define READCONF_MAX_DEPTH	16
স্থির পূর্ণাঙ্ক
read_config_file_depth(ধ্রুৱ ৱর্ণ *filename, সংরচনা passwd *pw,
    ধ্রুৱ ৱর্ণ *host, ধ্রুৱ ৱর্ণ *original_host, ধ্রুৱ ৱর্ণ *remote_command,
    Options *options, পূর্ণাঙ্ক flags, পূর্ণাঙ্ক *activep, পূর্ণাঙ্ক *want_final_pass, পূর্ণাঙ্ক depth)
{
	FILE *f;
	ৱর্ণ *সাৰি = রিক্ত;
	size_t linesize = 0;
	পূর্ণাঙ্ক linenum;
	পূর্ণাঙ্ক bad_options = 0;

	যদি (depth < 0 || depth > READCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	যদি ((f = fopen(filename, "r")) == রিক্ত)
		ঘূৰাই 0;

	যদি (flags & SSHCONF_CHECKPERM) {
		সংরচনা stat sb;

		যদি (fstat(fileno(f), &sb) == -1)
			fatal("fstat %s: %s", filename, strerror(errno));
		যদি (((sb.st_uid != 0 && sb.st_uid != getuid()) ||
		    (sb.st_mode & 022) != 0))
			fatal("Bad owner or permissions on %s", filename);
	}

	debug("Reading configuration data %.200s", filename);

	/*
	 * Mark that we are now processing the options.  This flag is turned
	 * on/off by Host specifications.
	 */
	linenum = 0;
	যেতিয়ালৈ (getline(&সাৰি, &linesize, f) != -1) {
		/* Update line number counter. */
		linenum++;
		/*
		 * Trim out comments and strip whitespace.
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages.
		 */
		যদি (process_config_সাৰি_depth(options, pw, host, original_host,
		    remote_command, সাৰি, filename, linenum, activep, flags,
		    want_final_pass, depth) != 0)
			bad_options++;
	}
	মুক্ত(সাৰি);
	fclose(f);
	যদি (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
	ঘূৰাই 1;
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
পূর্ণাঙ্ক
option_clear_or_none(ধ্রুৱ ৱর্ণ *o)
{
	ঘূৰাই o == রিক্ত || strcasecmp(o, "none") == 0;
}

/*
 * Returns 1 if CanonicalizePermittedCNAMEs have been specified, 0 otherwise.
 * Allowed to be called on non-final configuration.
 */
পূর্ণাঙ্ক
config_has_permitted_cnames(Options *options)
{
	যদি (options->অঙ্ক_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].source_list, "none") == 0 &&
	    strcmp(options->permitted_cnames[0].target_list, "") == 0)
		ঘূৰাই 0;
	ঘূৰাই options->অঙ্ক_permitted_cnames > 0;
}

/*
 * Initializes options to special values that indicate that they have not yet
 * been set.  Read_config_file will only set options with this value. Options
 * are processed in the following order: command line, user config file,
 * system config file.  Last, fill_default_options is called.
 */

শূন্য
initialize_options(Options * options)
{
	memset(options, 'X', পরিমাণ(*options));
	options->host_arg = রিক্ত;
	options->forward_agent = -1;
	options->forward_agent_sock_path = রিক্ত;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = রিক্ত;
	options->stdio_forward_port = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = রিক্ত;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_mask = (mode_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = রিক্ত;
	options->hostbased_authentication = -1;
	options->batch_mode = -1;
	options->check_host_ip = -1;
	options->strict_host_চাবি_checking = -1;
	options->compression = -1;
	options->tcp_keep_alive = -1;
	options->port = -1;
	options->address_family = -1;
	options->connection_attempts = -1;
	options->connection_timeout = -1;
	options->সংখ্যা_of_password_prompts = -1;
	options->ciphers = রিক্ত;
	options->macs = রিক্ত;
	options->kex_algorithms = রিক্ত;
	options->hostkeyalgorithms = রিক্ত;
	options->ca_sign_algorithms = রিক্ত;
	options->অঙ্ক_identity_files = 0;
	memset(options->identity_চাবিগুলি, 0, পরিমাণ(options->identity_চাবিগুলি));
	options->অঙ্ক_certificate_files = 0;
	memset(options->certificates, 0, পরিমাণ(options->certificates));
	options->hostname = রিক্ত;
	options->host_চাবি_alias = রিক্ত;
	options->proxy_command = রিক্ত;
	options->jump_user = রিক্ত;
	options->jump_host = রিক্ত;
	options->jump_port = -1;
	options->jump_extra = রিক্ত;
	options->user = রিক্ত;
	options->escape_char = -1;
	options->অঙ্ক_system_hostfiles = 0;
	options->অঙ্ক_user_hostfiles = 0;
	options->local_forwards = রিক্ত;
	options->অঙ্ক_local_forwards = 0;
	options->remote_forwards = রিক্ত;
	options->অঙ্ক_remote_forwards = 0;
	options->permitted_remote_opens = রিক্ত;
	options->অঙ্ক_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
	options->log_level = SYSLOG_LEVEL_NOT_SET;
	options->অঙ্ক_log_verbose = 0;
	options->log_verbose = রিক্ত;
	options->preferred_authentications = রিক্ত;
	options->bind_address = রিক্ত;
	options->bind_interface = রিক্ত;
	options->pkcs11_provider = রিক্ত;
	options->sk_provider = রিক্ত;
	options->enable_ssh_keysign = -1;
	options->no_host_authentication_for_localhost = -1;
	options->identities_only = -1;
	options->rekey_limit = -1;
	options->rekey_interval = -1;
	options->verify_host_চাবি_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_গুনতি_max = -1;
	options->send_env = রিক্ত;
	options->অঙ্ক_send_env = 0;
	options->setenv = রিক্ত;
	options->অঙ্ক_setenv = 0;
	options->control_path = রিক্ত;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_known_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = রিক্ত;
	options->permit_local_command = -1;
	options->remote_command = রিক্ত;
	options->add_চাবিগুলি_to_agent = -1;
	options->add_চাবিগুলি_to_agent_lifespan = -1;
	options->identity_agent = রিক্ত;
	options->visual_host_চাবি = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = রিক্ত;
	options->অঙ্ক_canonical_domains = 0;
	options->অঙ্ক_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_চাবিগুলি = রিক্ত;
	options->অঙ্ক_revoked_host_চাবিগুলি = 0;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->hostbased_accepted_algos = রিক্ত;
	options->pubkey_accepted_algos = রিক্ত;
	options->known_hosts_command = রিক্ত;
	options->required_rsa_size = -1;
	options->warn_weak_crypto = -1;
	options->enable_escape_commandline = -1;
	options->obscure_keystroke_timing_interval = -1;
	options->tag = রিক্ত;
	options->channel_timeouts = রিক্ত;
	options->অঙ্ক_channel_timeouts = 0;
	options->version_addendum = রিক্ত;
}

/*
 * A petite version of fill_default_options() that just fills the options
 * needed for hostname canonicalization to proceed.
 */
শূন্য
fill_default_options_for_canonicalization(Options *options)
{
	যদি (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	যদি (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	যদি (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
}

/*
 * Called after processing other sources of option data, this fills those
 * options for which no value has been specified with their default values.
 */
পূর্ণাঙ্ক
fill_default_options(Options * options)
{
	ৱর্ণ *all_cipher, *all_mac, *all_kex, *all_চাবি, *all_sig;
	ৱর্ণ *def_cipher, *def_mac, *def_kex, *def_চাবি, *def_sig;
	পূর্ণাঙ্ক ret = -1, r;

	যদি (options->forward_agent == -1)
		options->forward_agent = 0;
	যদি (options->forward_x11 == -1)
		options->forward_x11 = 0;
	যদি (options->forward_x11_trusted == -1)
		options->forward_x11_trusted = 0;
	যদি (options->forward_x11_timeout == -1)
		options->forward_x11_timeout = 1200;
	/*
	 * stdio forwarding (-W) changes the default for these but we defer
	 * setting the values so they can be overridden.
	 */
	যদি (options->exit_on_forward_failure == -1)
		options->exit_on_forward_failure =
		    options->stdio_forward_host != রিক্ত ? 1 : 0;
	যদি (options->clear_forwardings == -1)
		options->clear_forwardings =
		    options->stdio_forward_host != রিক্ত ? 1 : 0;
	যদি (options->clear_forwardings == 1)
		clear_forwardings(options);

	যদি (options->xauth_location == রিক্ত)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	যদি (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	যদি (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	যদি (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	যদি (options->pubkey_authentication == -1)
		options->pubkey_authentication = SSH_PUBKEY_AUTH_ALL;
	যদি (options->gss_authentication == -1)
		options->gss_authentication = 0;
	যদি (options->gss_deleg_creds == -1)
		options->gss_deleg_creds = 0;
	যদি (options->password_authentication == -1)
		options->password_authentication = 1;
	যদি (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	যদি (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	যদি (options->batch_mode == -1)
		options->batch_mode = 0;
	যদি (options->check_host_ip == -1)
		options->check_host_ip = 0;
	যদি (options->strict_host_চাবি_checking == -1)
		options->strict_host_চাবি_checking = SSH_STRICT_HOSTKEY_ASK;
	যদি (options->compression == -1)
		options->compression = 0;
	যদি (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = SSH_KEEPALIVES_TRANSPORT;
	যদি (options->port == -1)
		options->port = 0;	/* Filled in ssh_connect. */
	যদি (options->address_family == -1)
		options->address_family = AF_UNSPEC;
	যদি (options->connection_attempts == -1)
		options->connection_attempts = 1;
	যদি (options->সংখ্যা_of_password_prompts == -1)
		options->সংখ্যা_of_password_prompts = 3;
	/* options->hostkeyalgorithms, default set in myproposals.h */
	যদি (options->add_চাবিগুলি_to_agent == -1) {
		options->add_চাবিগুলি_to_agent = 0;
		options->add_চাবিগুলি_to_agent_lifespan = 0;
	}
	যদি (options->অঙ্ক_identity_files == 0) {
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
	যদি (options->escape_char == -1)
		options->escape_char = '~';
	যদি (options->অঙ্ক_system_hostfiles == 0) {
		options->system_hostfiles[options->অঙ্ক_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->অঙ্ক_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE2);
	}
	যদি (options->update_hostkeys == -1) {
		যদি (options->verify_host_চাবি_dns <= 0 &&
		    (options->অঙ্ক_user_hostfiles == 0 ||
		    (options->অঙ্ক_user_hostfiles == 1 && strcmp(options->
		    user_hostfiles[0], _PATH_SSH_USER_HOSTFILE) == 0)))
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_YES;
		অন্যথা
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_NO;
	}
	যদি (options->অঙ্ক_user_hostfiles == 0) {
		options->user_hostfiles[options->অঙ্ক_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->অঙ্ক_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE2);
	}
	যদি (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	যদি (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_USER;
	যদি (options->no_host_authentication_for_localhost == -1)
		options->no_host_authentication_for_localhost = 0;
	যদি (options->identities_only == -1)
		options->identities_only = 0;
	যদি (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	যদি (options->rekey_limit == -1)
		options->rekey_limit = 0;
	যদি (options->rekey_interval == -1)
		options->rekey_interval = 0;
	যদি (options->verify_host_চাবি_dns == -1)
		options->verify_host_চাবি_dns = 0;
	যদি (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	যদি (options->server_alive_গুনতি_max == -1)
		options->server_alive_গুনতি_max = 3;
	যদি (options->control_master == -1)
		options->control_master = 0;
	যদি (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	যদি (options->hash_known_hosts == -1)
		options->hash_known_hosts = 0;
	যদি (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	যদি (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	যদি (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	যদি (options->permit_local_command == -1)
		options->permit_local_command = 0;
	যদি (options->visual_host_চাবি == -1)
		options->visual_host_চাবি = 0;
	যদি (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	যদি (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	যদি (options->request_tty == -1)
		options->request_tty = REQUEST_TTY_AUTO;
	যদি (options->session_type == -1)
		options->session_type = SESSION_TYPE_DEFAULT;
	যদি (options->stdin_null == -1)
		options->stdin_null = 0;
	যদি (options->fork_after_authentication == -1)
		options->fork_after_authentication = 0;
	যদি (options->proxy_use_fdpass == -1)
		options->proxy_use_fdpass = 0;
	যদি (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	যদি (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	যদি (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
	যদি (options->fingerprint_hash == -1)
		options->fingerprint_hash = SSH_FP_HASH_DEFAULT;
#ifdef ENABLE_SK_INTERNAL
	যদি (options->sk_provider == রিক্ত)
		options->sk_provider = xstrdup("internal");
#অন্যথা
	যদি (options->sk_provider == রিক্ত)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
#endif
	যদি (options->required_rsa_size == -1)
		options->required_rsa_size = SSH_RSA_MINIMUM_MODULUS_SIZE;
	যদি (options->warn_weak_crypto == -1)
		options->warn_weak_crypto = 1;
	যদি (options->enable_escape_commandline == -1)
		options->enable_escape_commandline = 0;
	যদি (options->obscure_keystroke_timing_interval == -1) {
		options->obscure_keystroke_timing_interval =
		    SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
	}

	/* Expand KEX name lists */
	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_চাবি = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_CLIENT_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_CLIENT_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_CLIENT_KEX, all_kex);
	def_চাবি = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_চাবি);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	কৰা { \
		যদি ((r = kex_assemble_names(&options->what, \
		    defaults, all)) != 0) { \
			error_fr(r, "%s", #what); \
			গচ্ছ fail; \
		} \
	} যেতিয়ালৈ (0)
	options->kex_algorithms_set = options->kex_algorithms != রিক্ত;
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostbased_accepted_algos, def_চাবি, all_চাবি);
	ASSEMBLE(pubkey_accepted_algos, def_চাবি, all_চাবি);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE

#define CLEAR_ON_NONE(v) \
	কৰা { \
		যদি (option_clear_or_none(v)) { \
			মুক্ত(v); \
			v = রিক্ত; \
		} \
	} যেতিয়ালৈ(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	কৰা { \
		যদি (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			মুক্ত(options->v[0]); \
			মুক্ত(options->v); \
			options->v = রিক্ত; \
			options->nv = 0; \
		} \
	} যেতিয়ালৈ (0)
	CLEAR_ON_NONE(options->local_command);
	CLEAR_ON_NONE(options->remote_command);
	CLEAR_ON_NONE(options->proxy_command);
	CLEAR_ON_NONE(options->control_path);
	CLEAR_ON_NONE(options->pkcs11_provider);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->known_hosts_command);
	CLEAR_ON_NONE_ARRAY(channel_timeouts, অঙ্ক_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(revoked_host_চাবিগুলি, অঙ্ক_revoked_host_চাবিগুলি, "none");
#undef CLEAR_ON_NONE
#undef CLEAR_ON_NONE_ARRAY
	যদি (options->jump_host != রিক্ত &&
	    strcmp(options->jump_host, "none") == 0 &&
	    options->jump_port == 0 && options->jump_user == রিক্ত) {
		মুক্ত(options->jump_host);
		options->jump_host = রিক্ত;
	}
	যদি (options->অঙ্ক_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		মুক্ত(options->permitted_cnames[0].source_list);
		মুক্ত(options->permitted_cnames[0].target_list);
		memset(options->permitted_cnames, '\0',
		    পরিমাণ(*options->permitted_cnames));
		options->অঙ্ক_permitted_cnames = 0;
	}
	/* options->identity_agent distinguishes NULL from 'none' */
	/* options->user will be set in the main program if appropriate */
	/* options->hostname will be set in the main program if appropriate */
	/* options->host_key_alias should not be set by default */
	/* options->preferred_authentications will be set in ssh */

	/* success */
	ret = 0;
 fail:
	মুক্ত(all_cipher);
	মুক্ত(all_mac);
	মুক্ত(all_kex);
	মুক্ত(all_চাবি);
	মুক্ত(all_sig);
	মুক্ত(def_cipher);
	মুক্ত(def_mac);
	মুক্ত(def_kex);
	মুক্ত(def_চাবি);
	মুক্ত(def_sig);
	ঘূৰাই ret;
}

শূন্য
free_options(Options *o)
{
	পূর্ণাঙ্ক i;

	যদি (o == রিক্ত)
		ঘূৰাই;

#define FREE_ARRAY(type, n, a) \
	কৰা { \
		type _i; \
		বাবে (_i = 0; _i < (n); _i++) \
			মুক্ত((a)[_i]); \
	} যেতিয়ালৈ (0)

	মুক্ত(o->forward_agent_sock_path);
	মুক্ত(o->xauth_location);
	FREE_ARRAY(u_int, o->অঙ্ক_log_verbose, o->log_verbose);
	মুক্ত(o->log_verbose);
	মুক্ত(o->ciphers);
	মুক্ত(o->macs);
	মুক্ত(o->hostkeyalgorithms);
	মুক্ত(o->kex_algorithms);
	মুক্ত(o->ca_sign_algorithms);
	মুক্ত(o->hostname);
	মুক্ত(o->host_চাবি_alias);
	মুক্ত(o->proxy_command);
	মুক্ত(o->user);
	FREE_ARRAY(u_int, o->অঙ্ক_system_hostfiles, o->system_hostfiles);
	FREE_ARRAY(u_int, o->অঙ্ক_user_hostfiles, o->user_hostfiles);
	মুক্ত(o->preferred_authentications);
	মুক্ত(o->bind_address);
	মুক্ত(o->bind_interface);
	মুক্ত(o->pkcs11_provider);
	মুক্ত(o->sk_provider);
	বাবে (i = 0; i < o->অঙ্ক_identity_files; i++) {
		মুক্ত(o->identity_files[i]);
		sshkey_free(o->identity_চাবিগুলি[i]);
	}
	বাবে (i = 0; i < o->অঙ্ক_certificate_files; i++) {
		মুক্ত(o->certificate_files[i]);
		sshkey_free(o->certificates[i]);
	}
	মুক্ত(o->identity_agent);
	বাবে (i = 0; i < o->অঙ্ক_local_forwards; i++) {
		মুক্ত(o->local_forwards[i].listen_host);
		মুক্ত(o->local_forwards[i].listen_path);
		মুক্ত(o->local_forwards[i].connect_host);
		মুক্ত(o->local_forwards[i].connect_path);
	}
	মুক্ত(o->local_forwards);
	বাবে (i = 0; i < o->অঙ্ক_remote_forwards; i++) {
		মুক্ত(o->remote_forwards[i].listen_host);
		মুক্ত(o->remote_forwards[i].listen_path);
		মুক্ত(o->remote_forwards[i].connect_host);
		মুক্ত(o->remote_forwards[i].connect_path);
	}
	মুক্ত(o->remote_forwards);
	মুক্ত(o->stdio_forward_host);
	FREE_ARRAY(u_int, o->অঙ্ক_send_env, o->send_env);
	মুক্ত(o->send_env);
	FREE_ARRAY(u_int, o->অঙ্ক_setenv, o->setenv);
	মুক্ত(o->setenv);
	মুক্ত(o->control_path);
	মুক্ত(o->local_command);
	মুক্ত(o->remote_command);
	FREE_ARRAY(পূর্ণাঙ্ক, o->অঙ্ক_canonical_domains, o->canonical_domains);
	বাবে (i = 0; i < o->অঙ্ক_permitted_cnames; i++) {
		মুক্ত(o->permitted_cnames[i].source_list);
		মুক্ত(o->permitted_cnames[i].target_list);
	}
	FREE_ARRAY(u_int, o->অঙ্ক_revoked_host_চাবিগুলি, o->revoked_host_চাবিগুলি);
	মুক্ত(o->revoked_host_চাবিগুলি);
	মুক্ত(o->hostbased_accepted_algos);
	মুক্ত(o->pubkey_accepted_algos);
	মুক্ত(o->jump_user);
	মুক্ত(o->jump_host);
	মুক্ত(o->jump_extra);
	মুক্ত(o->ignored_unknown);
	explicit_bzero(o, পরিমাণ(*o));
#undef FREE_ARRAY
}

সংরচনা fwdarg {
	ৱর্ণ *arg;
	পূর্ণাঙ্ক ispath;
};

/*
 * parse_fwd_field
 * parses the next field in a port forwarding specification.
 * sets fwd to the parsed field and advances p past the colon
 * or sets it to NULL at end of string.
 * returns 0 on success, else non-zero.
 */
স্থির পূর্ণাঙ্ক
parse_fwd_field(ৱর্ণ **p, সংরচনা fwdarg *fwd)
{
	ৱর্ণ *ep, *cp = *p;
	পূর্ণাঙ্ক ispath = 0;

	যদি (*cp == '\0') {
		*p = রিক্ত;
		ঘূৰাই -1;	/* end of string */
	}

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	যদি (*cp == '[') {
		/* find matching ']' */
		বাবে (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++) {
			যদি (*ep == '/')
				ispath = 1;
		}
		/* no matching ']' or not at end of field. */
		যদি (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			ঘূৰাই -1;
		/* NUL terminate the field and advance p past the colon */
		*ep++ = '\0';
		যদি (*ep != '\0')
			*ep++ = '\0';
		fwd->arg = cp + 1;
		fwd->ispath = ispath;
		*p = ep;
		ঘূৰাই 0;
	}

	বাবে (cp = *p; *cp != '\0'; cp++) {
		ৱিকল্প (*cp) {
		পক্ষ '\\':
			memmove(cp, cp + 1, strlen(cp + 1) + 1);
			যদি (*cp == '\0')
				ঘূৰাই -1;
			ভঙ্গ;
		পক্ষ '/':
			ispath = 1;
			ভঙ্গ;
		পক্ষ ':':
			*cp++ = '\0';
			গচ্ছ done;
		}
	}
done:
	fwd->arg = *p;
	fwd->ispath = ispath;
	*p = cp;
	ঘূৰাই 0;
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
পূর্ণাঙ্ক
parse_forward(সংরচনা Forward *fwd, ধ্রুৱ ৱর্ণ *fwdspec, পূর্ণাঙ্ক dynamicfwd, পূর্ণাঙ্ক remotefwd)
{
	সংরচনা fwdarg fwdargs[4];
	ৱর্ণ *p, *cp;
	পূর্ণাঙ্ক i, err;

	memset(fwd, 0, পরিমাণ(*fwd));
	memset(fwdargs, 0, পরিমাণ(fwdargs));

	/*
	 * We expand environment variables before checking if we think they're
	 * paths so that if ${VAR} expands to a fully qualified path it is
	 * treated as a path.
	 */
	cp = p = dollar_expand(&err, fwdspec);
	যদি (p == রিক্ত || err)
		ঘূৰাই 0;

	/* skip leading spaces */
	যেতিয়ালৈ (isspace((u_char)*cp))
		cp++;

	বাবে (i = 0; i < 4; ++i) {
		যদি (parse_fwd_field(&cp, &fwdargs[i]) != 0)
			ভঙ্গ;
	}

	/* Check for trailing garbage */
	যদি (cp != রিক্ত && *cp != '\0') {
		i = 0;	/* failure */
	}

	ৱিকল্প (i) {
	পক্ষ 1:
		যদি (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
		} অন্যথা {
			fwd->listen_host = রিক্ত;
			fwd->listen_port = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		ভঙ্গ;

	পক্ষ 2:
		যদি (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} অন্যথা যদি (fwdargs[1].ispath) {
			fwd->listen_host = রিক্ত;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} অন্যথা {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		ভঙ্গ;

	পক্ষ 3:
		যদি (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		} অন্যথা যদি (fwdargs[2].ispath) {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_path = xstrdup(fwdargs[2].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} অন্যথা {
			fwd->listen_host = রিক্ত;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		}
		ভঙ্গ;

	পক্ষ 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_port = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_port = a2port(fwdargs[3].arg);
		ভঙ্গ;
	স্ৱভাৱ:
		i = 0; /* failure */
	}

	মুক্ত(p);

	যদি (dynamicfwd) {
		যদি (!(i == 1 || i == 2))
			গচ্ছ fail_free;
	} অন্যথা {
		যদি (!(i == 3 || i == 4)) {
			যদি (fwd->connect_path == রিক্ত &&
			    fwd->listen_path == রিক্ত)
				গচ্ছ fail_free;
		}
		যদি (fwd->connect_port <= 0 && fwd->connect_path == রিক্ত)
			গচ্ছ fail_free;
	}

	যদি ((fwd->listen_port < 0 && fwd->listen_path == রিক্ত) ||
	    (!remotefwd && fwd->listen_port == 0))
		গচ্ছ fail_free;
	যদি (fwd->connect_host != রিক্ত &&
	    strlen(fwd->connect_host) >= NI_MAXHOST)
		গচ্ছ fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	যদি (fwd->connect_path != রিক্ত &&
	    strlen(fwd->connect_path) >= PATH_MAX_SUN)
		গচ্ছ fail_free;
	যদি (fwd->listen_host != রিক্ত &&
	    strlen(fwd->listen_host) >= NI_MAXHOST)
		গচ্ছ fail_free;
	যদি (fwd->listen_path != রিক্ত &&
	    strlen(fwd->listen_path) >= PATH_MAX_SUN)
		গচ্ছ fail_free;

	ঘূৰাই (i);

 fail_free:
	মুক্ত(fwd->connect_host);
	fwd->connect_host = রিক্ত;
	মুক্ত(fwd->connect_path);
	fwd->connect_path = রিক্ত;
	মুক্ত(fwd->listen_host);
	fwd->listen_host = রিক্ত;
	মুক্ত(fwd->listen_path);
	fwd->listen_path = রিক্ত;
	ঘূৰাই (0);
}

পূর্ণাঙ্ক
ssh_valid_hostname(ধ্রুৱ ৱর্ণ *s)
{
	size_t i;

	যদি (*s == '-')
		ঘূৰাই 0;
	বাবে (i = 0; s[i] != 0; i++) {
		যদি (strchr("'`\"$\\;&<>|(){},", s[i]) != রিক্ত ||
		    isspace((u_char)s[i]) || iscntrl((u_char)s[i]))
			ঘূৰাই 0;
	}
	ঘূৰাই 1;
}

পূর্ণাঙ্ক
ssh_valid_ruser(ধ্রুৱ ৱর্ণ *s)
{
	size_t i;

	যদি (*s == '-')
		ঘূৰাই 0;
	বাবে (i = 0; s[i] != 0; i++) {
		যদি (iscntrl((u_char)s[i]))
			ঘূৰাই 0;
		যদি (strchr("'`\";&<>|(){}$\\", s[i]) != রিক্ত)
			ঘূৰাই 0;
		/* Disallow '-' after whitespace */
		যদি (isspace((u_char)s[i]) && s[i + 1] == '-')
			ঘূৰাই 0;
	}
	ঘূৰাই 1;
}

পূর্ণাঙ্ক
parse_jump(ধ্রুৱ ৱর্ণ *s, Options *o, পূর্ণাঙ্ক strict, পূর্ণাঙ্ক active)
{
	ৱর্ণ *orig = রিক্ত, *sdup = রিক্ত, *cp;
	ৱর্ণ *tmp_user = রিক্ত, *tmp_host = রিক্ত, *host = রিক্ত, *user = রিক্ত;
	পূর্ণাঙ্ক r, ret = -1, tmp_port = -1, port = -1, first = 1;

	যদি (strcasecmp(s, "none") == 0) {
		যদি (active && o->jump_host == রিক্ত) {
			o->jump_host = xstrdup("none");
			o->jump_port = 0;
		}
		ঘূৰাই 0;
	}

	orig = xstrdup(s);
	যদি ((cp = strchr(orig, '#')) != রিক্ত)
		*cp = '\0';
	rtrim(orig);

	active &= o->proxy_command == রিক্ত && o->jump_host == রিক্ত;
	sdup = xstrdup(orig);
	কৰা {
		/* Work backwards through string */
		যদি ((cp = strrchr(sdup, ',')) == রিক্ত)
			cp = sdup; /* last */
		অন্যথা
			*cp++ = '\0';

		r = parse_ssh_uri(cp, &tmp_user, &tmp_host, &tmp_port);
		যদি (r == -1 || (r == 1 && parse_user_host_port(cp,
		    &tmp_user, &tmp_host, &tmp_port) != 0))
			গচ্ছ out; /* error already logged */
		যদি (strict) {
			যদি (!ssh_valid_hostname(tmp_host)) {
				error_f("invalid hostname \"%s\"", tmp_host);
				গচ্ছ out;
			}
			যদি (tmp_user != রিক্ত && !ssh_valid_ruser(tmp_user)) {
				error_f("invalid username \"%s\"", tmp_user);
				গচ্ছ out;
			}
		}
		যদি (first) {
			user = tmp_user;
			host = tmp_host;
			port = tmp_port;
			tmp_user = tmp_host = রিক্ত; /* transferred */
		}
		first = 0; /* only check syntax for subsequent hosts */
		মুক্ত(tmp_user);
		মুক্ত(tmp_host);
		tmp_user = tmp_host = রিক্ত;
		tmp_port = -1;
	} যেতিয়ালৈ (cp != sdup);

	/* success */
	যদি (active) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_port = port;
		o->proxy_command = xstrdup("none");
		user = host = রিক্ত; /* transferred */
		যদি (orig != রিক্ত && (cp = strrchr(orig, ',')) != রিক্ত) {
			o->jump_extra = xstrdup(orig);
			o->jump_extra[cp - orig] = '\0';
		}
	}
	ret = 0;
 out:
	মুক্ত(orig);
	মুক্ত(sdup);
	মুক্ত(tmp_user);
	মুক্ত(tmp_host);
	মুক্ত(user);
	মুক্ত(host);
	ঘূৰাই ret;
}

পূর্ণাঙ্ক
parse_ssh_uri(ধ্রুৱ ৱর্ণ *uri, ৱর্ণ **userp, ৱর্ণ **hostp, পূর্ণাঙ্ক *portp)
{
	ৱর্ণ *user = রিক্ত, *host = রিক্ত, *path = রিক্ত;
	পূর্ণাঙ্ক r, port;

	r = parse_uri("ssh", uri, &user, &host, &port, &path);
	যদি (r == 0 && path != রিক্ত)
		r = -1;		/* path not allowed */
	যদি (r == 0) {
		যদি (userp != রিক্ত) {
			*userp = user;
			user = রিক্ত;
		}
		যদি (hostp != রিক্ত) {
			*hostp = host;
			host = রিক্ত;
		}
		যদি (portp != রিক্ত)
			*portp = port;
	}
	মুক্ত(user);
	মুক্ত(host);
	মুক্ত(path);
	ঘূৰাই r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
স্থির ধ্রুৱ ৱর্ণ *
fmt_multistate_int(পূর্ণাঙ্ক val, ধ্রুৱ সংরচনা multistate *m)
{
	u_int i;

	বাবে (i = 0; m[i].চাবি != রিক্ত; i++) {
		যদি (m[i].মান == val)
			ঘূৰাই m[i].চাবি;
	}
	ঘূৰাই "UNKNOWN";
}

স্থির ধ্রুৱ ৱর্ণ *
fmt_intarg(OpCodes code, পূর্ণাঙ্ক val)
{
	যদি (val == -1)
		ঘূৰাই "unset";
	ৱিকল্প (code) {
	পক্ষ oAddressFamily:
		ঘূৰাই fmt_multistate_int(val, multistate_addressfamily);
	পক্ষ oCompression:
		ঘূৰাই fmt_multistate_int(val, multistate_compression);
	পক্ষ o_Verify_Host_চাবি_DNS:
	পক্ষ oUpdateHostkeys:
		ঘূৰাই fmt_multistate_int(val, multistate_yesnoask);
	পক্ষ o_Strict_Host_চাবি_Checking:
		ঘূৰাই fmt_multistate_int(val, multistate_strict_hostkey);
	পক্ষ oControlMaster:
		ঘূৰাই fmt_multistate_int(val, multistate_controlmaster);
	পক্ষ oTunnel:
		ঘূৰাই fmt_multistate_int(val, multistate_tunnel);
	পক্ষ oRequestTTY:
		ঘূৰাই fmt_multistate_int(val, multistate_requesttty);
	পক্ষ oSessionType:
		ঘূৰাই fmt_multistate_int(val, multistate_sessiontype);
	পক্ষ oCanonicalizeHostname:
		ঘূৰাই fmt_multistate_int(val, multistate_canonicalizehostname);
	পক্ষ o_Add_চাবিগুলি_To_Agent:
		ঘূৰাই fmt_multistate_int(val, multistate_yesnoaskconfirm);
	পক্ষ oPubkeyAuthentication:
		ঘূৰাই fmt_multistate_int(val, multistate_pubkey_auth);
	পক্ষ oTCPKeepAlive:
		ঘূৰাই fmt_multistate_int(val, multistate_keepalives);
	পক্ষ oFingerprintHash:
		ঘূৰাই ssh_digest_alg_name(val);
	স্ৱভাৱ:
		ৱিকল্প (val) {
		পক্ষ 0:
			ঘূৰাই "no";
		পক্ষ 1:
			ঘূৰাই "yes";
		স্ৱভাৱ:
			ঘূৰাই "UNKNOWN";
		}
	}
}

স্থির ধ্রুৱ ৱর্ণ *
lookup_opcode_name(OpCodes code)
{
	u_int i;

	বাবে (i = 0; keywords[i].name != রিক্ত; i++)
		যদি (keywords[i].opcode == code)
			ঘূৰাই(keywords[i].name);
	ঘূৰাই "UNKNOWN";
}

স্থির শূন্য
dump_cfg_int(OpCodes code, পূর্ণাঙ্ক val)
{
	যদি (code == oObscureKeystrokeTiming) {
		যদি (val == 0) {
			printf("%s no\n", lookup_opcode_name(code));
			ঘূৰাই;
		} অন্যথা যদি (val == SSH_KEYSTROKE_DEFAULT_INTERVAL_MS) {
			printf("%s yes\n", lookup_opcode_name(code));
			ঘূৰাই;
		}
		/* FALLTHROUGH */
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

স্থির শূন্য
dump_cfg_fmtint(OpCodes code, পূর্ণাঙ্ক val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

স্থির শূন্য
dump_cfg_string(OpCodes code, ধ্রুৱ ৱর্ণ *val)
{
	যদি (val == রিক্ত)
		ঘূৰাই;
	printf("%s %s\n", lookup_opcode_name(code), val);
}

স্থির শূন্য
dump_cfg_strarray(OpCodes code, u_int গুনতি, ৱর্ণ **vals)
{
	u_int i;

	বাবে (i = 0; i < গুনতি; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

স্থির শূন্য
dump_cfg_strarray_oneline(OpCodes code, u_int গুনতি, ৱর্ণ **vals)
{
	u_int i;

	printf("%s", lookup_opcode_name(code));
	যদি (গুনতি == 0)
		printf(" none");
	বাবে (i = 0; i < গুনতি; i++)
		printf(" %s",  vals[i]);
	printf("\n");
}

স্থির শূন্য
dump_cfg_forwards(OpCodes code, u_int গুনতি, ধ্রুৱ সংরচনা Forward *fwds)
{
	ধ্রুৱ সংরচনা Forward *fwd;
	u_int i;

	/* oDynamicForward */
	বাবে (i = 0; i < গুনতি; i++) {
		fwd = &fwds[i];
		যদি (code == oDynamicForward && fwd->connect_host != রিক্ত &&
		    strcmp(fwd->connect_host, "socks") != 0)
			অনুৱর্ত;
		যদি (code == oLocalForward && fwd->connect_host != রিক্ত &&
		    strcmp(fwd->connect_host, "socks") == 0)
			অনুৱর্ত;
		printf("%s", lookup_opcode_name(code));
		যদি (fwd->listen_port == PORT_STREAMLOCAL)
			printf(" %s", fwd->listen_path);
		অন্যথা যদি (fwd->listen_host == রিক্ত)
			printf(" %d", fwd->listen_port);
		অন্যথা {
			printf(" [%s]:%d",
			    fwd->listen_host, fwd->listen_port);
		}
		যদি (code != oDynamicForward) {
			যদি (fwd->connect_port == PORT_STREAMLOCAL)
				printf(" %s", fwd->connect_path);
			অন্যথা যদি (fwd->connect_host == রিক্ত)
				printf(" %d", fwd->connect_port);
			অন্যথা {
				printf(" [%s]:%d",
				    fwd->connect_host, fwd->connect_port);
			}
		}
		printf("\n");
	}
}

শূন্য
dump_client_config(Options *o, ধ্রুৱ ৱর্ণ *host)
{
	পূর্ণাঙ্ক i, r;
	ৱর্ণ buf[8], *all_চাবি;

	/*
	 * Expand HostKeyAlgorithms name lists. This isn't handled in
	 * fill_default_options() like the other algorithm lists because
	 * the host key algorithms are by default dynamically chosen based
	 * on the host's keys found in known_hosts.
	 */
	all_চাবি = sshkey_alg_list(0, 0, 1, ',');
	যদি ((r = kex_assemble_names(&o->hostkeyalgorithms, kex_default_pk_alg(),
	    all_চাবি)) != 0)
		fatal_fr(r, "expand HostKeyAlgorithms");
	মুক্ত(all_চাবি);

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
	dump_cfg_fmtint(o_Strict_Host_চাবি_Checking, o->strict_host_চাবি_checking);
	dump_cfg_fmtint(oTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(oTunnel, o->tun_open);
	dump_cfg_fmtint(o_Verify_Host_চাবি_DNS, o->verify_host_চাবি_dns);
	dump_cfg_fmtint(o_Visual_Host_চাবি, o->visual_host_চাবি);
	dump_cfg_fmtint(oUpdateHostkeys, o->update_hostkeys);
	dump_cfg_fmtint(oEnableEscapeCommandline, o->enable_escape_commandline);
	dump_cfg_fmtint(oWarnWeakCrypto, o->warn_weak_crypto);

	/* Integer options */
	dump_cfg_int(oCanonicalizeMaxDots, o->canonicalize_max_dots);
	dump_cfg_int(oConnectionAttempts, o->connection_attempts);
	dump_cfg_int(oForwardX11Timeout, o->forward_x11_timeout);
	dump_cfg_int(o_সংখ্যা_Of_Password_Prompts, o->সংখ্যা_of_password_prompts);
	dump_cfg_int(o_Server_Alive_গুনতি_Max, o->server_alive_গুনতি_max);
	dump_cfg_int(oServerAliveInterval, o->server_alive_interval);
	dump_cfg_int(oRequiredRSASize, o->required_rsa_size);
	dump_cfg_int(oObscureKeystrokeTiming,
	    o->obscure_keystroke_timing_interval);

	/* String options */
	dump_cfg_string(oBindAddress, o->bind_address);
	dump_cfg_string(oBindInterface, o->bind_interface);
	dump_cfg_string(oCiphers, o->ciphers);
	dump_cfg_string(oControlPath, o->control_path);
	dump_cfg_string(o_Host_চাবি_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(o_Host_চাবি_Alias, o->host_চাবি_alias);
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
	dump_cfg_string(o_Security_চাবি_Provider, o->sk_provider);
	dump_cfg_string(oPreferredAuthentications, o->preferred_authentications);
	dump_cfg_string(oPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
	dump_cfg_string(oXAuthLocation, o->xauth_location);
	dump_cfg_string(oKnownHostsCommand, o->known_hosts_command);
	dump_cfg_string(oTag, o->tag);
	dump_cfg_string(oVersionAddendum, o->version_addendum);

	/* Forwards */
	dump_cfg_forwards(oDynamicForward, o->অঙ্ক_local_forwards, o->local_forwards);
	dump_cfg_forwards(oLocalForward, o->অঙ্ক_local_forwards, o->local_forwards);
	dump_cfg_forwards(oRemoteForward, o->অঙ্ক_remote_forwards, o->remote_forwards);

	/* String array options */
	dump_cfg_strarray(oIdentityFile, o->অঙ্ক_identity_files, o->identity_files);
	dump_cfg_strarray_oneline(oCanonicalDomains, o->অঙ্ক_canonical_domains, o->canonical_domains);
	dump_cfg_strarray(oCertificateFile, o->অঙ্ক_certificate_files, o->certificate_files);
	dump_cfg_strarray_oneline(oGlobalKnownHostsFile, o->অঙ্ক_system_hostfiles, o->system_hostfiles);
	dump_cfg_strarray_oneline(oUserKnownHostsFile, o->অঙ্ক_user_hostfiles, o->user_hostfiles);
	dump_cfg_strarray_oneline(o_Revoked_Host_চাবিগুলি, o->অঙ্ক_revoked_host_চাবিগুলি, o->revoked_host_চাবিগুলি);
	dump_cfg_strarray(oSendEnv, o->অঙ্ক_send_env, o->send_env);
	dump_cfg_strarray(oSetEnv, o->অঙ্ক_setenv, o->setenv);
	dump_cfg_strarray_oneline(oLogVerbose,
	    o->অঙ্ক_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(oChannelTimeout,
	    o->অঙ্ক_channel_timeouts, o->channel_timeouts);

	/* Special cases */

	/* PermitRemoteOpen */
	যদি (o->অঙ্ক_permitted_remote_opens == 0)
		printf("%s any\n", lookup_opcode_name(oPermitRemoteOpen));
	অন্যথা
		dump_cfg_strarray_oneline(oPermitRemoteOpen,
		    o->অঙ্ক_permitted_remote_opens, o->permitted_remote_opens);

	/* AddKeysToAgent */
	যদি (o->add_চাবিগুলি_to_agent_lifespan <= 0)
		dump_cfg_fmtint(o_Add_চাবিগুলি_To_Agent, o->add_চাবিগুলি_to_agent);
	অন্যথা {
		printf("addkeystoagent%s %d\n",
		    o->add_চাবিগুলি_to_agent == 3 ? " confirm" : "",
		    o->add_চাবিগুলি_to_agent_lifespan);
	}

	/* oForwardAgent */
	যদি (o->forward_agent_sock_path == রিক্ত)
		dump_cfg_fmtint(oForwardAgent, o->forward_agent);
	অন্যথা
		dump_cfg_string(oForwardAgent, o->forward_agent_sock_path);

	/* oConnectTimeout */
	যদি (o->connection_timeout == -1)
		printf("connecttimeout none\n");
	অন্যথা
		dump_cfg_int(oConnectTimeout, o->connection_timeout);

	/* oTunnelDevice */
	printf("tunneldevice");
	যদি (o->tun_local == SSH_TUNID_ANY)
		printf(" any");
	অন্যথা
		printf(" %d", o->tun_local);
	যদি (o->tun_remote == SSH_TUNID_ANY)
		printf(":any");
	অন্যথা
		printf(":%d", o->tun_remote);
	printf("\n");

	/* oCanonicalizePermittedCNAMEs */
	printf("canonicalizepermittedcnames");
	যদি (o->অঙ্ক_permitted_cnames == 0)
		printf(" none");
	বাবে (i = 0; i < o->অঙ্ক_permitted_cnames; i++) {
		printf(" %s:%s", o->permitted_cnames[i].source_list,
		    o->permitted_cnames[i].target_list);
	}
	printf("\n");

	/* oControlPersist */
	যদি (o->control_persist == 0 || o->control_persist_timeout == 0)
		dump_cfg_fmtint(oControlPersist, o->control_persist);
	অন্যথা
		dump_cfg_int(oControlPersist, o->control_persist_timeout);

	/* oEscapeChar */
	যদি (o->escape_char == SSH_ESCAPECHAR_NONE)
		printf("escapechar none\n");
	অন্যথা {
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
	যদি (o->jump_host == রিক্ত)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	অন্যথা {
		/* Check for numeric addresses */
		i = strchr(o->jump_host, ':') != রিক্ত ||
		    strspn(o->jump_host, "1234567890.") == strlen(o->jump_host);
		snprintf(buf, পরিমাণ(buf), "%d", o->jump_port);
		printf("proxyjump %s%s%s%s%s%s%s%s%s\n",
		    /* optional additional jump spec */
		    o->jump_extra == রিক্ত ? "" : o->jump_extra,
		    o->jump_extra == রিক্ত ? "" : ",",
		    /* optional user */
		    o->jump_user == রিক্ত ? "" : o->jump_user,
		    o->jump_user == রিক্ত ? "" : "@",
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
