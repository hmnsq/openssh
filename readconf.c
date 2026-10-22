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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/stat.h>
#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/wait.h>
#অন্তর্ভাব <sys/un.h>

#অন্তর্ভাব <net/if.h>
#অন্তর্ভাব <netinet/in.h>
#অন্তর্ভাব <netinet/ip.h>
#অন্তর্ভাব <arpa/inet.h>

#অন্তর্ভাব <ctype.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <glob.h>
#অন্তর্ভাব <ifaddrs.h>
#অন্তর্ভাব <limits.h>
#অন্তর্ভাব <netdb.h>
#অন্তর্ভাব <paths.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <util.h>
#যদি defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "cipher.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "readconf.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "kex.h"
#অন্তর্ভাব "mac.h"
#অন্তর্ভাব "myproposal.h"
#অন্তর্ভাব "digest.h"
#অন্তর্ভাব "version.h"

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

স্থির পূর্ণসংখ্যা read_config_file_depth(ধ্রুবক অক্ষর *filename, কাঠামো passwd *pw,
    ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *original_host, ধ্রুবক অক্ষর *remote_command,
    Options *options, পূর্ণসংখ্যা flags, পূর্ণসংখ্যা *activep, পূর্ণসংখ্যা *want_final_pass, পূর্ণসংখ্যা depth);
স্থির পূর্ণসংখ্যা process_config_সারি_depth(Options *options, কাঠামো passwd *pw,
    ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *original_host, ধ্রুবক অক্ষর *remote_command,
    অক্ষর *সারি, ধ্রুবক অক্ষর *filename, পূর্ণসংখ্যা linenum, পূর্ণসংখ্যা *activep, পূর্ণসংখ্যা flags,
    পূর্ণসংখ্যা *want_final_pass, পূর্ণসংখ্যা depth);

/* Keyword tokens. */

প্রকারলেখ গণনা {
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

স্থির কাঠামো {
	ধ্রুবক অক্ষর *name;
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

	{ ফাঁকা, oBadOption }
};

স্থির ধ্রুবক অক্ষর *lookup_opcode_name(OpCodes code);

ধ্রুবক অক্ষর *
kex_default_pk_alg(শূন্য)
{
	স্থির অক্ষর *pkalgs;

	যদি (pkalgs == ফাঁকা) {
		অক্ষর *all_চাবি;

		all_চাবি = sshkey_alg_list(0, 0, 1, ',');
		pkalgs = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_চাবি);
		মুক্ত(all_চাবি);
	}
	ফেরত pkalgs;
}

অক্ষর *
ssh_connection_hash(ধ্রুবক অক্ষর *thishost, ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *portstr,
    ধ্রুবক অক্ষর *user, ধ্রুবক অক্ষর *jumphost)
{
	কাঠামো ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_দৈর্ঘ্য];

	যদি ((md = ssh_digest_start(SSH_DIGEST_SHA1)) == ফাঁকা ||
	    ssh_digest_update(md, thishost, strlen(thishost)) < 0 ||
	    ssh_digest_update(md, host, strlen(host)) < 0 ||
	    ssh_digest_update(md, portstr, strlen(portstr)) < 0 ||
	    ssh_digest_update(md, user, strlen(user)) < 0 ||
	    ssh_digest_update(md, jumphost, strlen(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, আকার(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	ফেরত tohex(conn_hash, ssh_digest_bytes(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

শূন্য
add_local_forward(Options *options, ধ্রুবক কাঠামো Forward *newfwd)
{
	কাঠামো Forward *fwd;
	পূর্ণসংখ্যা i;

	/* Don't add duplicates */
	জন্য (i = 0; i < options->অঙ্ক_local_forwards; i++) {
		যদি (forward_equals(newfwd, options->local_forwards + i))
			ফেরত;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->অঙ্ক_local_forwards + 1,
	    আকার(*options->local_forwards));
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
add_remote_forward(Options *options, ধ্রুবক কাঠামো Forward *newfwd)
{
	কাঠামো Forward *fwd;
	পূর্ণসংখ্যা i;

	/* Don't add duplicates */
	জন্য (i = 0; i < options->অঙ্ক_remote_forwards; i++) {
		যদি (forward_equals(newfwd, options->remote_forwards + i))
			ফেরত;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->অঙ্ক_remote_forwards + 1,
	    আকার(*options->remote_forwards));
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
	পূর্ণসংখ্যা i;

	জন্য (i = 0; i < options->অঙ্ক_local_forwards; i++) {
		মুক্ত(options->local_forwards[i].listen_host);
		মুক্ত(options->local_forwards[i].listen_path);
		মুক্ত(options->local_forwards[i].connect_host);
		মুক্ত(options->local_forwards[i].connect_path);
	}
	যদি (options->অঙ্ক_local_forwards > 0) {
		মুক্ত(options->local_forwards);
		options->local_forwards = ফাঁকা;
	}
	options->অঙ্ক_local_forwards = 0;
	জন্য (i = 0; i < options->অঙ্ক_remote_forwards; i++) {
		মুক্ত(options->remote_forwards[i].listen_host);
		মুক্ত(options->remote_forwards[i].listen_path);
		মুক্ত(options->remote_forwards[i].connect_host);
		মুক্ত(options->remote_forwards[i].connect_path);
	}
	যদি (options->অঙ্ক_remote_forwards > 0) {
		মুক্ত(options->remote_forwards);
		options->remote_forwards = ফাঁকা;
	}
	options->অঙ্ক_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

শূন্য
add_certificate_file(Options *options, ধ্রুবক অক্ষর *path, পূর্ণসংখ্যা userprovided)
{
	পূর্ণসংখ্যা i;

	যদি (options->অঙ্ক_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	জন্য (i = 0; i < options->অঙ্ক_certificate_files; i++) {
		যদি (options->certificate_file_userprovided[i] == userprovided &&
		    strcmp(options->certificate_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			ফেরত;
		}
	}

	options->certificate_file_userprovided[options->অঙ্ক_certificate_files] =
	    userprovided;
	options->certificate_files[options->অঙ্ক_certificate_files++] =
	    xstrdup(path);
}

শূন্য
add_identity_file(Options *options, ধ্রুবক অক্ষর *dir, ধ্রুবক অক্ষর *filename,
    পূর্ণসংখ্যা userprovided)
{
	অক্ষর *path;
	পূর্ণসংখ্যা i;

	যদি (options->অঙ্ক_identity_files >= SSH_MAX_IDENTITY_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_IDENTITY_FILES);

	যদি (dir == ফাঁকা) /* no dir, filename is absolute */
		path = xstrdup(filename);
	অন্যথা যদি (xasprintf(&path, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", path);

	/* Avoid registering duplicates */
	জন্য (i = 0; i < options->অঙ্ক_identity_files; i++) {
		যদি (options->identity_file_userprovided[i] == userprovided &&
		    strcmp(options->identity_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			মুক্ত(path);
			ফেরত;
		}
	}

	options->identity_file_userprovided[options->অঙ্ক_identity_files] =
	    userprovided;
	options->identity_files[options->অঙ্ক_identity_files++] = path;
}

পূর্ণসংখ্যা
default_ssh_port(শূন্য)
{
	স্থির পূর্ণসংখ্যা port;
	কাঠামো servent *sp;

	যদি (port == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		port = sp ? ntohs(sp->s_port) : SSH_DEFAULT_PORT;
	}
	ফেরত port;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
স্থির পূর্ণসংখ্যা
execute_in_shell(ধ্রুবক অক্ষর *cmd)
{
	অক্ষর *shell;
	pid_t pid;
	পূর্ণসংখ্যা status;

	যদি ((shell = getenv("SHELL")) == ফাঁকা)
		shell = _PATH_BSHELL;

	যদি (access(shell, X_OK) == -1) {
		fatal("Shell \"%s\" is not executable: %s",
		    shell, strerror(errno));
	}

	debug("Executing command: '%.500s'", cmd);

	/* Fork and execute the command. */
	যদি ((pid = fork()) == 0) {
		অক্ষর *argv[4];

		যদি (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = xstrdup(cmd);
		argv[3] = ফাঁকা;

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

	যখন (waitpid(pid, &status, 0) == -1) {
		যদি (errno != EINTR && errno != EAGAIN)
			fatal_f("waitpid: %s", strerror(errno));
	}
	যদি (!WIFEXITED(status)) {
		error("command '%.100s' exited abnormally", cmd);
		ফেরত -1;
	}
	debug3("command returned status %d", WEXITSTATUS(status));
	ফেরত WEXITSTATUS(status);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
স্থির পূর্ণসংখ্যা
check_match_ifaddrs(ধ্রুবক অক্ষর *addrlist)
{
#ifdef HAVE_IFADDRS_H
	কাঠামো ifaddrs *ifa, *ifaddrs = ফাঁকা;
	পূর্ণসংখ্যা r, found = 0;
	অক্ষর addr[NI_MAXHOST];
	socklen_t salen;

	যদি (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    strerror(errno));
		ফেরত 0;
	}
	জন্য (ifa = ifaddrs; ifa != ফাঁকা; ifa = ifa->ifa_পরবর্তী) {
		যদি (ifa->ifa_addr == ফাঁকা || ifa->ifa_name == ফাঁকা ||
		    (ifa->ifa_flags & IFF_UP) == 0)
			চালু;
		নির্বাচন (ifa->ifa_addr->sa_family) {
		ক্ষেত্র AF_INET:
			salen = আকার(কাঠামো sockaddr_in);
			বিরতি;
		ক্ষেত্র AF_INET6:
			salen = আকার(কাঠামো sockaddr_in6);
			বিরতি;
#ifdef AF_LINK
		ক্ষেত্র AF_LINK:
			/* ignore */
			চালু;
#endif /* AF_LINK */
		পূর্বনির্ধারিত:
			debug2_f("interface %s: unsupported address family %d",
			    ifa->ifa_name, ifa->ifa_addr->sa_family);
			চালু;
		}
		যদি ((r = getnameinfo(ifa->ifa_addr, salen, addr, আকার(addr),
		    ফাঁকা, 0, NI_NUMERICHOST)) != 0) {
			debug2_f("interface %s getnameinfo failed: %s",
			    ifa->ifa_name, gai_strerror(r));
			চালু;
		}
		debug3_f("interface %s addr %s", ifa->ifa_name, addr);
		যদি (addr_match_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			found = 1;
			বিরতি;
		}
	}
	freeifaddrs(ifaddrs);
	ফেরত found;
#অন্যথা /* HAVE_IFADDRS_H */
	error("match localnetwork: not supported on this platform");
	ফেরত 0;
#endif /* HAVE_IFADDRS_H */
}

/*
 * Expand a "match exec" command or an Include path, caller must free returned
 * value.
 */
স্থির অক্ষর *
expand_match_exec_or_include_path(ধ্রুবক অক্ষর *path, Options *options,
    কাঠামো passwd *pw, ধ্রুবক অক্ষর *host_arg, ধ্রুবক অক্ষর *original_host,
    পূর্ণসংখ্যা final_pass, পূর্ণসংখ্যা is_include_path)
{
	অক্ষর thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	অক্ষর uidstr[32], *conn_hash_hex, *keyalias, *jmphost, *ruser;
	অক্ষর *host, *ret;
	পূর্ণসংখ্যা port;

	port = options->port <= 0 ? default_ssh_port() : options->port;
	ruser = options->user == ফাঁকা ? pw->pw_name : options->user;
	যদি (final_pass) {
		host = xstrdup(options->hostname);
	} অন্যথা যদি (options->hostname != ফাঁকা) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (অক্ষর *)ফাঁকা);
	} অন্যথা {
		host = xstrdup(host_arg);
	}
	যদি (gethostname(thishost, আকার(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	jmphost = option_clear_or_none(options->jump_host) ?
	    "" : options->jump_host;
	strlcpy(shorthost, thishost, আকার(shorthost));
	shorthost[strcspn(thishost, ".")] = '\0';
	snprintf(portstr, আকার(portstr), "%d", port);
	snprintf(uidstr, আকার(uidstr), "%llu",
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
	    (অক্ষর *)ফাঁকা);
	মুক্ত(host);
	মুক্ত(conn_hash_hex);
	ফেরত ret;
}

/*
 * Parse and execute a Match directive.
 */
স্থির পূর্ণসংখ্যা
match_cfg_সারি(Options *options, ধ্রুবক অক্ষর *full_সারি, পূর্ণসংখ্যা *acp, অক্ষর ***avp,
    কাঠামো passwd *pw, ধ্রুবক অক্ষর *host_arg, ধ্রুবক অক্ষর *original_host,
    ধ্রুবক অক্ষর *remote_command, পূর্ণসংখ্যা final_pass, পূর্ণসংখ্যা *want_final_pass,
    ধ্রুবক অক্ষর *filename, পূর্ণসংখ্যা linenum)
{
	অক্ষর *arg, *oattrib = ফাঁকা, *attrib = ফাঁকা, *cmd, *host, *criteria;
	ধ্রুবক অক্ষর *ruser;
	পূর্ণসংখ্যা r, this_ফলাফল, ফলাফল = 1, attributes = 0, negate;

	/*
	 * Configuration is likely to be incomplete at this point so we
	 * must be prepared to use default values.
	 */
	ruser = options->user == ফাঁকা ? pw->pw_name : options->user;
	যদি (final_pass) {
		host = xstrdup(options->hostname);
	} অন্যথা যদি (options->hostname != ফাঁকা) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (অক্ষর *)ফাঁকা);
	} অন্যথা {
		host = xstrdup(host_arg);
	}

	debug2("checking match for '%s' host %s originally %s",
	    full_সারি, host, original_host);
	যখন ((attrib = argv_পরবর্তী(acp, avp)) != ফাঁকা) {
		/* Terminate on comment */
		যদি (*attrib == '#') {
			argv_consume(acp);
			বিরতি;
		}
		attrib = oattrib = xstrdup(attrib);
		arg = criteria = ফাঁকা;
		this_ফলাফল = 1;
		যদি ((negate = (attrib[0] == '!')))
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		যদি (strcasecmp(attrib, "all") == 0) {
			যদি (attributes > 1 ||
			    ((arg = argv_পরবর্তী(acp, avp)) != ফাঁকা &&
			    *arg != '\0' && *arg != '#')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				ফলাফল = -1;
				যাও out;
			}
			যদি (arg != ফাঁকা && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			যদি (ফলাফল)
				ফলাফল = negate ? 0 : 1;
			যাও out;
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
			    want_final_pass != ফাঁকা)
				*want_final_pass |= !negate;
			r = !!final_pass;  /* force bitmask member to boolean */
			যদি (r == (negate ? 1 : 0))
				this_ফলাফল = ফলাফল = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_ফলাফল ? "" : "not ", oattrib);
			যাও পরবর্তী;
		}

		/* Keep this list in sync with below */
		যদি (strprefix(attrib, "host=", 1)  != ফাঁকা ||
		    strprefix(attrib, "originalhost=", 1) != ফাঁকা ||
		    strprefix(attrib, "user=", 1) != ফাঁকা ||
		    strprefix(attrib, "localuser=", 1) != ফাঁকা ||
		    strprefix(attrib, "localnetwork=", 1) != ফাঁকা ||
		    strprefix(attrib, "version=", 1) != ফাঁকা ||
		    strprefix(attrib, "tagged=", 1) != ফাঁকা ||
		    strprefix(attrib, "command=", 1) != ফাঁকা ||
		    strprefix(attrib, "exec=", 1) != ফাঁকা) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} অন্যথা যদি ((arg = argv_পরবর্তী(acp, avp)) == ফাঁকা) {
			error("%.200s line %d: missing argument for Match '%s'",
			    filename, linenum, oattrib);
			ফলাফল = -1;
			যাও out;
		}

		/*
		 * All other criteria require an argument, though it may
		 * be the empty string for the "tagged" and "command"
		 * options.
		 */
		যদি (*arg == '\0' &&
		    strcasecmp(attrib, "tagged") != 0 &&
		    strcasecmp(attrib, "command") != 0)
			arg = ফাঁকা;
		যদি (arg == ফাঁকা || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			ফলাফল = -1;
			যাও out;
		}
		যদি (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = match_hostname(host, arg) == 1;
			যদি (r == (negate ? 1 : 0))
				this_ফলাফল = ফলাফল = 0;
		} অন্যথা যদি (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = match_hostname(original_host, arg) == 1;
			যদি (r == (negate ? 1 : 0))
				this_ফলাফল = ফলাফল = 0;
		} অন্যথা যদি (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = match_pattern_list(ruser, arg, 0) == 1;
			যদি (r == (negate ? 1 : 0))
				this_ফলাফল = ফলাফল = 0;
		} অন্যথা যদি (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = match_pattern_list(pw->pw_name, arg, 0) == 1;
			যদি (r == (negate ? 1 : 0))
				this_ফলাফল = ফলাফল = 0;
		} অন্যথা যদি (strcasecmp(attrib, "localnetwork") == 0) {
			যদি (addr_match_cidr_list(ফাঁকা, arg) == -1) {
				/* Error already printed */
				ফলাফল = -1;
				যাও out;
			}
			r = check_match_ifaddrs(arg) == 1;
			যদি (r == (negate ? 1 : 0))
				this_ফলাফল = ফলাফল = 0;
		} অন্যথা যদি (strcasecmp(attrib, "version") == 0) {
			criteria = xstrdup(SSH_RELEASE);
			r = match_pattern_list(SSH_RELEASE, arg, 0) == 1;
			যদি (r == (negate ? 1 : 0))
				this_ফলাফল = ফলাফল = 0;
		} অন্যথা যদি (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->tag == ফাঁকা ? "" :
			    options->tag);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			যদি (r == (negate ? 1 : 0))
				this_ফলাফল = ফলাফল = 0;
		} অন্যথা যদি (strcasecmp(attrib, "command") == 0) {
			criteria = xstrdup(remote_command == ফাঁকা ?
			    "" : remote_command);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			যদি (r == (negate ? 1 : 0))
				this_ফলাফল = ফলাফল = 0;
		} অন্যথা যদি (strcasecmp(attrib, "sessiontype") == 0) {
			যদি (options->session_type == SESSION_TYPE_SUBSYSTEM)
				criteria = xstrdup("subsystem");
			অন্যথা যদি (options->session_type == SESSION_TYPE_NONE)
				criteria = xstrdup("none");
			অন্যথা যদি (remote_command != ফাঁকা &&
			    *remote_command != '\0')
				criteria = xstrdup("exec");
			অন্যথা
				criteria = xstrdup("shell");
			r = match_pattern_list(criteria, arg, 0) == 1;
			যদি (r == (negate ? 1 : 0))
				this_ফলাফল = ফলাফল = 0;
		} অন্যথা যদি (strcasecmp(attrib, "exec") == 0) {
			যদি ((cmd = expand_match_exec_or_include_path(arg,
			    options, pw, host_arg, original_host,
			    final_pass, 0)) == ফাঁকা) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			যদি (ফলাফল != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				মুক্ত(cmd);
				যাও পরবর্তী;
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
				this_ফলাফল = ফলাফল = 0;
		} অন্যথা {
			error("Unsupported Match attribute %s", attrib);
			ফলাফল = -1;
			যাও out;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s' ",
		    filename, linenum, this_ফলাফল ? "": "not ", oattrib,
		    criteria == ফাঁকা ? "" : " \"",
		    criteria == ফাঁকা ? "" : criteria,
		    criteria == ফাঁকা ? "" : "\"");
 পরবর্তী:
		মুক্ত(criteria);
		মুক্ত(oattrib);
		oattrib = attrib = ফাঁকা;
	}
	যদি (attributes == 0) {
		error("One or more attributes required for Match");
		ফলাফল = -1;
		যাও out;
	}
 out:
	যদি (ফলাফল != -1)
		debug2("match %sfound", ফলাফল ? "" : "not ");
	মুক্ত(oattrib);
	মুক্ত(host);
	ফেরত ফলাফল;
}

/* Remove environment variable by pattern */
স্থির শূন্য
rm_env(Options *options, ধ্রুবক অক্ষর *arg, ধ্রুবক অক্ষর *filename, পূর্ণসংখ্যা linenum)
{
	u_int i, j, onum_send_env = options->অঙ্ক_send_env;

	/* Remove an environment variable */
	জন্য (i = 0; i < options->অঙ্ক_send_env; ) {
		যদি (!match_pattern(options->send_env[i], arg + 1)) {
			i++;
			চালু;
		}
		debug3("%s line %d: removing environment %s",
		    filename, linenum, options->send_env[i]);
		মুক্ত(options->send_env[i]);
		options->send_env[i] = ফাঁকা;
		জন্য (j = i; j < options->অঙ্ক_send_env - 1; j++) {
			options->send_env[j] = options->send_env[j + 1];
			options->send_env[j + 1] = ফাঁকা;
		}
		options->অঙ্ক_send_env--;
		/* NB. don't increment i */
	}
	যদি (onum_send_env != options->অঙ্ক_send_env) {
		options->send_env = xrecallocarray(options->send_env,
		    onum_send_env, options->অঙ্ক_send_env,
		    আকার(*options->send_env));
	}
}

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */
স্থির OpCodes
parse_token(ধ্রুবক অক্ষর *cp, ধ্রুবক অক্ষর *filename, পূর্ণসংখ্যা linenum,
    ধ্রুবক অক্ষর *ignored_unknown)
{
	পূর্ণসংখ্যা i;

	জন্য (i = 0; keywords[i].name; i++)
		যদি (strcmp(cp, keywords[i].name) == 0)
			ফেরত keywords[i].opcode;
	যদি (ignored_unknown != ফাঁকা &&
	    match_pattern_list(cp, ignored_unknown, 1) == 1)
		ফেরত oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	ফেরত oBadOption;
}

স্থির শূন্য
free_canon_cnames(কাঠামো allowed_cname *cnames, u_int n)
{
	u_int i;

	যদি (cnames == ফাঁকা || n == 0)
		ফেরত;
	জন্য (i = 0; i < n; i++) {
		মুক্ত(cnames[i].source_list);
		মুক্ত(cnames[i].target_list);
	}
	মুক্ত(cnames);
}

/* Multistate option parsing */
কাঠামো multistate {
	অক্ষর *চাবি;
	পূর্ণসংখ্যা মান;
};
স্থির ধ্রুবক কাঠামো multistate multistate_flag[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ ফাঁকা, -1 }
};
স্থির ধ্রুবক কাঠামো multistate multistate_yesnoask[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ ফাঁকা, -1 }
};
স্থির ধ্রুবক কাঠামো multistate multistate_strict_hostkey[] = {
	{ "true",			SSH_STRICT_HOSTKEY_YES },
	{ "false",			SSH_STRICT_HOSTKEY_OFF },
	{ "yes",			SSH_STRICT_HOSTKEY_YES },
	{ "no",				SSH_STRICT_HOSTKEY_OFF },
	{ "ask",			SSH_STRICT_HOSTKEY_ASK },
	{ "off",			SSH_STRICT_HOSTKEY_OFF },
	{ "accept-new",			SSH_STRICT_HOSTKEY_NEW },
	{ ফাঁকা, -1 }
};
স্থির ধ্রুবক কাঠামো multistate multistate_yesnoaskconfirm[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "confirm",			3 },
	{ ফাঁকা, -1 }
};
স্থির ধ্রুবক কাঠামো multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ ফাঁকা, -1 }
};
স্থির ধ্রুবক কাঠামো multistate multistate_controlmaster[] = {
	{ "true",			SSHCTL_MASTER_YES },
	{ "yes",			SSHCTL_MASTER_YES },
	{ "false",			SSHCTL_MASTER_NO },
	{ "no",				SSHCTL_MASTER_NO },
	{ "auto",			SSHCTL_MASTER_AUTO },
	{ "ask",			SSHCTL_MASTER_ASK },
	{ "autoask",			SSHCTL_MASTER_AUTO_ASK },
	{ ফাঁকা, -1 }
};
স্থির ধ্রুবক কাঠামো multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET },
	{ "point-to-point",		SSH_TUNMODE_POINTOPOINT },
	{ "true",			SSH_TUNMODE_DEFAULT },
	{ "yes",			SSH_TUNMODE_DEFAULT },
	{ "false",			SSH_TUNMODE_NO },
	{ "no",				SSH_TUNMODE_NO },
	{ ফাঁকা, -1 }
};
স্থির ধ্রুবক কাঠামো multistate multistate_requesttty[] = {
	{ "true",			REQUEST_TTY_YES },
	{ "yes",			REQUEST_TTY_YES },
	{ "false",			REQUEST_TTY_NO },
	{ "no",				REQUEST_TTY_NO },
	{ "force",			REQUEST_TTY_FORCE },
	{ "auto",			REQUEST_TTY_AUTO },
	{ ফাঁকা, -1 }
};
স্থির ধ্রুবক কাঠামো multistate multistate_sessiontype[] = {
	{ "none",			SESSION_TYPE_NONE },
	{ "subsystem",			SESSION_TYPE_SUBSYSTEM },
	{ "default",			SESSION_TYPE_DEFAULT },
	{ ফাঁকা, -1 }
};
স্থির ধ্রুবক কাঠামো multistate multistate_canonicalizehostname[] = {
	{ "true",			SSH_CANONICALISE_YES },
	{ "false",			SSH_CANONICALISE_NO },
	{ "yes",			SSH_CANONICALISE_YES },
	{ "no",				SSH_CANONICALISE_NO },
	{ "always",			SSH_CANONICALISE_ALWAYS },
	{ ফাঁকা, -1 }
};
স্থির ধ্রুবক কাঠামো multistate multistate_pubkey_auth[] = {
	{ "true",			SSH_PUBKEY_AUTH_ALL },
	{ "false",			SSH_PUBKEY_AUTH_NO },
	{ "yes",			SSH_PUBKEY_AUTH_ALL },
	{ "no",				SSH_PUBKEY_AUTH_NO },
	{ "unbound",			SSH_PUBKEY_AUTH_UNBOUND },
	{ "host-bound",			SSH_PUBKEY_AUTH_HBOUND },
	{ ফাঁকা, -1 }
};
স্থির ধ্রুবক কাঠামো multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ ফাঁকা, -1 }
};
স্থির ধ্রুবক কাঠামো multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ ফাঁকা, -1 }
};
/* XXX this will need to be replaced with a bitmask if we add more flags */
স্থির ধ্রুবক কাঠামো multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ ফাঁকা, -1 }
};

স্থির পূর্ণসংখ্যা
parse_multistate_মান(ধ্রুবক অক্ষর *arg, ধ্রুবক অক্ষর *filename, পূর্ণসংখ্যা linenum,
    ধ্রুবক কাঠামো multistate *multistate_ptr)
{
	পূর্ণসংখ্যা i;

	যদি (!arg || *arg == '\0') {
		error("%s line %d: missing argument.", filename, linenum);
		ফেরত -1;
	}
	জন্য (i = 0; multistate_ptr[i].চাবি != ফাঁকা; i++) {
		যদি (strcasecmp(arg, multistate_ptr[i].চাবি) == 0)
			ফেরত multistate_ptr[i].মান;
	}
	ফেরত -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
পূর্ণসংখ্যা
process_config_সারি(Options *options, কাঠামো passwd *pw, ধ্রুবক অক্ষর *host,
    ধ্রুবক অক্ষর *original_host, ধ্রুবক অক্ষর *remote_command, অক্ষর *সারি,
    ধ্রুবক অক্ষর *filename, পূর্ণসংখ্যা linenum, পূর্ণসংখ্যা *activep, পূর্ণসংখ্যা flags)
{
	ফেরত process_config_সারি_depth(options, pw, host, original_host,
	    remote_command, সারি, filename, linenum, activep, flags, ফাঁকা, 0);
}

#define WHITESPACE " \t\r\n"
স্থির পূর্ণসংখ্যা
process_config_সারি_depth(Options *options, কাঠামো passwd *pw, ধ্রুবক অক্ষর *host,
    ধ্রুবক অক্ষর *original_host, ধ্রুবক অক্ষর *remote_command, অক্ষর *সারি,
    ধ্রুবক অক্ষর *filename, পূর্ণসংখ্যা linenum, পূর্ণসংখ্যা *activep, পূর্ণসংখ্যা flags,
    পূর্ণসংখ্যা *want_final_pass, পূর্ণসংখ্যা depth)
{
	অক্ষর *str, **charptr, *endofnumber, *keyword, *arg, *arg2, *p;
	অক্ষর **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	পূর্ণসংখ্যা r, oactive, negated, opcode, *intptr, মান, value2, cmdline = 0;
	পূর্ণসংখ্যা remotefwd, dynamicfwd, ca_only = 0, found = 0;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	long long val64;
	আকার_t len;
	কাঠামো Forward fwd;
	ধ্রুবক কাঠামো multistate *multistate_ptr;
	glob_t gl;
	ধ্রুবক অক্ষর *errstr;
	অক্ষর **oav = ফাঁকা, **av;
	পূর্ণসংখ্যা oac = 0, ac;
	পূর্ণসংখ্যা ret = -1;
	কাঠামো allowed_cname *cnames = ফাঁকা;
	u_int ncnames = 0;
	অক্ষর **strs = ফাঁকা; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	যদি (activep == ফাঁকা) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	যদি ((len = strlen(সারি)) == 0)
		ফেরত 0;
	জন্য (len--; len > 0; len--) {
		যদি (strchr(WHITESPACE "\f", সারি[len]) == ফাঁকা)
			বিরতি;
		সারি[len] = '\0';
	}

	str = সারি;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	যদি ((keyword = strdelim(&str)) == ফাঁকা)
		ফেরত 0;
	/* Ignore leading whitespace. */
	যদি (*keyword == '\0')
		keyword = strdelim(&str);
	যদি (keyword == ফাঁকা || !*keyword || *keyword == '\n' || *keyword == '#')
		ফেরত 0;
	/* Match lowercase keyword */
	lowercase(keyword);

	/* Prepare to parse remainder of line */
	যদি (str != ফাঁকা)
		str += strspn(str, WHITESPACE);
	যদি (str == ফাঁকা || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		ফেরত -1;
	}
	opcode = parse_token(keyword, filename, linenum,
	    options->ignored_unknown);
	যদি (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		ফেরত -1;
	}
	ac = oac;
	av = oav;

	নির্বাচন (opcode) {
	ক্ষেত্র oBadOption:
		/* don't panic, but count bad options */
		যাও out;
	ক্ষেত্র oIgnore:
		argv_consume(&ac);
		বিরতি;
	ক্ষেত্র oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		বিরতি;
	ক্ষেত্র oConnectTimeout:
		intptr = &options->connection_timeout;
parse_time:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			যাও out;
		}
		যদি (strcmp(arg, "none") == 0)
			মান = -1;
		অন্যথা যদি ((মান = convtime(arg)) == -1) {
			error("%s line %d: invalid time value.",
			    filename, linenum);
			যাও out;
		}
		যদি (*activep && *intptr == -1)
			*intptr = মান;
		বিরতি;

	ক্ষেত্র oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%s line %d: missing argument.",
			    filename, linenum);
			যাও out;
		}

		মান = -1;
		multistate_ptr = multistate_flag;
		জন্য (i = 0; multistate_ptr[i].চাবি != ফাঁকা; i++) {
			যদি (strcasecmp(arg, multistate_ptr[i].চাবি) == 0) {
				মান = multistate_ptr[i].মান;
				বিরতি;
			}
		}
		যদি (মান != -1) {
			যদি (*activep && *intptr == -1)
				*intptr = মান;
			বিরতি;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		যদি (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_path;
		যাও parse_agent_path;

	ক্ষেত্র oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_পরবর্তী(&ac, &av);
		যদি ((মান = parse_multistate_মান(arg, filename, linenum,
		    multistate_ptr)) == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			যাও out;
		}
		যদি (*activep && *intptr == -1)
			*intptr = মান;
		বিরতি;

	ক্ষেত্র oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		যাও parse_flag;

	ক্ষেত্র oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		যাও parse_time;

	ক্ষেত্র oGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		যাও parse_flag;

	ক্ষেত্র oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		যাও parse_flag;

	ক্ষেত্র oPasswordAuthentication:
		intptr = &options->password_authentication;
		যাও parse_flag;

	ক্ষেত্র oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		যাও parse_flag;

	ক্ষেত্র oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		যাও parse_string;

	ক্ষেত্র oPubkeyAuthentication:
		multistate_ptr = multistate_pubkey_auth;
		intptr = &options->pubkey_authentication;
		যাও parse_multistate;

	ক্ষেত্র oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		যাও parse_flag;

	ক্ষেত্র oGssAuthentication:
		intptr = &options->gss_authentication;
		যাও parse_flag;

	ক্ষেত্র oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		যাও parse_flag;

	ক্ষেত্র oBatchMode:
		intptr = &options->batch_mode;
		যাও parse_flag;

	ক্ষেত্র oCheckHostIP:
		intptr = &options->check_host_ip;
		যাও parse_flag;

	ক্ষেত্র o_Verify_Host_চাবি_DNS:
		intptr = &options->verify_host_চাবি_dns;
		multistate_ptr = multistate_yesnoask;
		যাও parse_multistate;

	ক্ষেত্র o_Strict_Host_চাবি_Checking:
		intptr = &options->strict_host_চাবি_checking;
		multistate_ptr = multistate_strict_hostkey;
		যাও parse_multistate;

	ক্ষেত্র oCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		যাও parse_multistate;

	ক্ষেত্র oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		যাও parse_multistate;

	ক্ষেত্র oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		যাও parse_flag;

	ক্ষেত্র o_সংখ্যা_Of_Password_Prompts:
		intptr = &options->সংখ্যা_of_password_prompts;
		যাও parse_int;

	ক্ষেত্র oRekeyLimit:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.", filename,
			    linenum);
			যাও out;
		}
		যদি (strcmp(arg, "default") == 0) {
			val64 = 0;
		} অন্যথা {
			যদি (scan_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, strerror(errno));
				যাও out;
			}
			যদি (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				যাও out;
			}
		}
		যদি (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		যদি (ac != 0) { /* optional rekey interval present */
			যদি (strcmp(av[0], "none") == 0) {
				(শূন্য)argv_পরবর্তী(&ac, &av);	/* discard */
				বিরতি;
			}
			intptr = &options->rekey_interval;
			যাও parse_time;
		}
		বিরতি;

	ক্ষেত্র oIdentityFile:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			যাও out;
		}
		যদি (*activep) {
			intptr = &options->অঙ্ক_identity_files;
			যদি (*intptr >= SSH_MAX_IDENTITY_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_IDENTITY_FILES);
				যাও out;
			}
			add_identity_file(options, ফাঁকা,
			    arg, flags & SSHCONF_USERCONF);
		}
		বিরতি;

	ক্ষেত্র oCertificateFile:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			যাও out;
		}
		যদি (*activep) {
			intptr = &options->অঙ্ক_certificate_files;
			যদি (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				যাও out;
			}
			add_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		বিরতি;

	ক্ষেত্র oXAuthLocation:
		charptr=&options->xauth_location;
		যাও parse_string;

	ক্ষেত্র oUser:
		charptr = &options->user;
parse_string:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			যাও out;
		}
		যদি (*activep && *charptr == ফাঁকা)
			*charptr = xstrdup(arg);
		বিরতি;

	ক্ষেত্র oGlobalKnownHostsFile:
		cpptr = (অক্ষর **)&options->system_hostfiles;
		uintptr = &options->অঙ্ক_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		i = 0;
		মান = *uintptr == 0; /* was array empty when we started? */
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			যদি (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				যাও out;
			}
			/* Allow "none" only in first position */
			যদি (strcasecmp(arg, "none") == 0) {
				যদি (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					যাও out;
				}
			}
			i++;
			যদি (*activep && মান) {
				যদি ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries.", filename, linenum,
					    keyword);
					যাও out;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		বিরতি;

	ক্ষেত্র oUserKnownHostsFile:
		cpptr = (অক্ষর **)&options->user_hostfiles;
		uintptr = &options->অঙ্ক_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		যাও parse_char_array;

	ক্ষেত্র oHostname:
		charptr = &options->hostname;
		যাও parse_string;

	ক্ষেত্র oTag:
		charptr = &options->tag;
		যাও parse_string;

	ক্ষেত্র o_Host_চাবি_Alias:
		charptr = &options->host_চাবি_alias;
		যাও parse_string;

	ক্ষেত্র oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		যাও parse_string;

	ক্ষেত্র oBindAddress:
		charptr = &options->bind_address;
		যাও parse_string;

	ক্ষেত্র oBindInterface:
		charptr = &options->bind_interface;
		যাও parse_string;

	ক্ষেত্র oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		যাও parse_string;

	ক্ষেত্র o_Security_চাবি_Provider:
		charptr = &options->sk_provider;
		যাও parse_string;

	ক্ষেত্র oKnownHostsCommand:
		charptr = &options->known_hosts_command;
		যাও parse_command;

	ক্ষেত্র oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		যদি (str == ফাঁকা) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			যাও out;
		}
		len = strspn(str, WHITESPACE "=");
		যদি (*activep && *charptr == ফাঁকা)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		বিরতি;

	ক্ষেত্র oProxyJump:
		যদি (str == ফাঁকা) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			যাও out;
		}
		len = strspn(str, WHITESPACE "=");
		/* XXX use argv? */
		যদি (parse_jump(str + len, options, cmdline, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			যাও out;
		}
		argv_consume(&ac);
		বিরতি;

	ক্ষেত্র oPort:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			যাও out;
		}
		মান = a2port(arg);
		যদি (মান <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			যাও out;
		}
		যদি (*activep && options->port == -1)
			options->port = মান;
		বিরতি;

	ক্ষেত্র oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_পরবর্তী(&ac, &av);
		যদি ((errstr = atoi_err(arg, &মান)) != ফাঁকা) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			যাও out;
		}
		যদি (*activep && *intptr == -1)
			*intptr = মান;
		বিরতি;

	ক্ষেত্র oCiphers:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			যাও out;
		}
		যদি (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			যাও out;
		}
		যদি (*activep && options->ciphers == ফাঁকা)
			options->ciphers = xstrdup(arg);
		বিরতি;

	ক্ষেত্র oMacs:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			যাও out;
		}
		যদি (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			যাও out;
		}
		যদি (*activep && options->macs == ফাঁকা)
			options->macs = xstrdup(arg);
		বিরতি;

	ক্ষেত্র oKexAlgorithms:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			যাও out;
		}
		যদি (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			যাও out;
		}
		যদি (*activep && options->kex_algorithms == ফাঁকা)
			options->kex_algorithms = xstrdup(arg);
		বিরতি;

	ক্ষেত্র o_Host_চাবি_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
parse_pubkey_algos:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			যাও out;
		}
		যদি (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			যাও out;
		}
		যদি (*activep && *charptr == ফাঁকা)
			*charptr = xstrdup(arg);
		বিরতি;

	ক্ষেত্র oCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		যাও parse_pubkey_algos;

	ক্ষেত্র oLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_পরবর্তী(&ac, &av);
		মান = log_level_সংখ্যা(arg);
		যদি (মান == SYSLOG_LEVEL_NOT_SET) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			যাও out;
		}
		যদি (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_SET)
			*log_level_ptr = (LogLevel) মান;
		বিরতি;

	ক্ষেত্র oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_পরবর্তী(&ac, &av);
		মান = log_facility_সংখ্যা(arg);
		যদি (মান == SYSLOG_FACILITY_NOT_SET) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			যাও out;
		}
		যদি (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) মান;
		বিরতি;

	ক্ষেত্র oLogVerbose:
		cppptr = &options->log_verbose;
		uintptr = &options->অঙ্ক_log_verbose;
		i = 0;
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			যদি (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				যাও out;
			}
			/* Allow "none" only in first position */
			যদি (strcasecmp(arg, "none") == 0) {
				যদি (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					যাও out;
				}
			}
			i++;
			যদি (*activep && *uintptr == 0) {
				*cppptr = xrecallocarray(*cppptr, *uintptr,
				    *uintptr + 1, আকার(**cppptr));
				(*cppptr)[(*uintptr)++] = xstrdup(arg);
			}
		}
		বিরতি;

	ক্ষেত্র oLocalForward:
	ক্ষেত্র oRemoteForward:
	ক্ষেত্র oDynamicForward:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			যাও out;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		যদি (!dynamicfwd) {
			arg2 = argv_পরবর্তী(&ac, &av);
			যদি (arg2 == ফাঁকা || *arg2 == '\0') {
				যদি (remotefwd)
					dynamicfwd = 1;
				অন্যথা {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					যাও out;
				}
			} অন্যথা {
				/* construct a string for parse_forward */
				snprintf(fwdarg, আকার(fwdarg), "%s:%s", arg,
				    arg2);
			}
		}
		যদি (dynamicfwd)
			strlcpy(fwdarg, arg, আকার(fwdarg));

		যদি (parse_forward(&fwd, fwdarg, dynamicfwd, remotefwd) == 0) {
			error("%.200s line %d: Bad forwarding specification.",
			    filename, linenum);
			যাও out;
		}

		যদি (*activep) {
			যদি (remotefwd) {
				add_remote_forward(options, &fwd);
			} অন্যথা {
				add_local_forward(options, &fwd);
			}
		}
		বিরতি;

	ক্ষেত্র oPermitRemoteOpen:
		uintptr = &options->অঙ্ক_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		found = *uintptr == 0;
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			যদি (strcasecmp(arg, "none") == 0 ||
			    strcasecmp(arg, "any") == 0) {
				যদি (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					মুক্ত(arg2);
					যাও out;
				}
			} অন্যথা {
				p = hpdelim(&arg);
				যদি (p == ফাঁকা) {
					fatal("%s line %d: missing host in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
				}
				p = cleanhostname(p);
				/*
				 * don't want to use permitopen_port to avoid
				 * dependency on channels.[ch] here.
				 */
				যদি (arg == ফাঁকা || (strcmp(arg, "*") != 0 &&
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
			strs = ফাঁকা; /* transferred */
			nstrs = 0;
		}
		বিরতি;

	ক্ষেত্র oClearAllForwardings:
		intptr = &options->clear_forwardings;
		যাও parse_flag;

	ক্ষেত্র oHost:
		যদি (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			যাও out;
		}
		*activep = 0;
		arg2 = ফাঁকা;
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			যদি (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				যাও out;
			}
			যদি ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				বিরতি;
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
					বিরতি;
				}
				যদি (!*activep)
					arg2 = arg; /* logged below */
				*activep = 1;
			}
		}
		যদি (*activep)
			debug("%.200s line %d: Applying options for %.100s",
			    filename, linenum, arg2);
		বিরতি;

	ক্ষেত্র oMatch:
		যদি (cmdline) {
			error("Match directive not supported as a command-line "
			    "option");
			যাও out;
		}
		মান = match_cfg_সারি(options, str, &ac, &av, pw, host,
		    original_host, remote_command, flags & SSHCONF_FINAL,
		    want_final_pass, filename, linenum);
		যদি (মান < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			যাও out;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : মান;
		বিরতি;

	ক্ষেত্র oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			যাও out;
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
			যাও out;
		}
		যদি (*activep && *intptr == -1)
			*intptr = মান;
		বিরতি;

	ক্ষেত্র oAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
		যাও parse_multistate;

	ক্ষেত্র oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		যাও parse_flag;

	ক্ষেত্র oIdentitiesOnly:
		intptr = &options->identities_only;
		যাও parse_flag;

	ক্ষেত্র oServerAliveInterval:
		intptr = &options->server_alive_interval;
		যাও parse_time;

	ক্ষেত্র o_Server_Alive_গুনতি_Max:
		intptr = &options->server_alive_গুনতি_max;
		যাও parse_int;

	ক্ষেত্র oSendEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			যদি (*arg == '\0' || strchr(arg, '=') != ফাঁকা) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				যাও out;
			}
			found = 1;
			যদি (!*activep)
				চালু;
			যদি (*arg == '-') {
				/* Removing an env var */
				rm_env(options, arg, filename, linenum);
				চালু;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->অঙ্ক_send_env, arg);
		}
		যদি (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		বিরতি;

	ক্ষেত্র oSetEnv:
		found = options->অঙ্ক_setenv == 0;
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			যদি (strchr(arg, '=') == ফাঁকা) {
				error("%s line %d: Invalid SetEnv.",
				    filename, linenum);
				যাও out;
			}
			যদি (lookup_setenv_in_list(arg, strs, nstrs) != ফাঁকা) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				চালু;
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
			strs = ফাঁকা; /* transferred */
			nstrs = 0;
		}
		বিরতি;

	ক্ষেত্র oControlPath:
		charptr = &options->control_path;
		যাও parse_string;

	ক্ষেত্র oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		যাও parse_multistate;

	ক্ষেত্র oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing ControlPersist"
			    " argument.", filename, linenum);
			যাও out;
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
			যাও out;
		}
		যদি (*activep && *intptr == -1) {
			*intptr = মান;
			options->control_persist_timeout = value2;
		}
		বিরতি;

	ক্ষেত্র oHashKnownHosts:
		intptr = &options->hash_known_hosts;
		যাও parse_flag;

	ক্ষেত্র oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		যাও parse_multistate;

	ক্ষেত্র oTunnelDevice:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			যাও out;
		}
		মান = a2tun(arg, &value2);
		যদি (মান == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			যাও out;
		}
		যদি (*activep && options->tun_local == -1) {
			options->tun_local = মান;
			options->tun_remote = value2;
		}
		বিরতি;

	ক্ষেত্র oLocalCommand:
		charptr = &options->local_command;
		যাও parse_command;

	ক্ষেত্র oPermitLocalCommand:
		intptr = &options->permit_local_command;
		যাও parse_flag;

	ক্ষেত্র oRemoteCommand:
		charptr = &options->remote_command;
		যাও parse_command;

	ক্ষেত্র o_Visual_Host_চাবি:
		intptr = &options->visual_host_চাবি;
		যাও parse_flag;

	ক্ষেত্র oInclude:
		যদি (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			যাও out;
		}
		মান = 0;
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			যদি (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				যাও out;
			}
			/* Expand %tokens and environment variables */
			যদি ((p = expand_match_exec_or_include_path(arg,
			    options, pw, host, original_host,
			    flags & SSHCONF_FINAL, 1)) == ফাঁকা) {
				error("%.200s line %d: Unable to expand user "
				    "config file '%.100s'",
				    filename, linenum, arg);
				চালু;
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
				যাও out;
			}
			যদি (!path_absolute(p) && *p != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" _PATH_SSH_USER_DIR : SSHDIR, p);
			} অন্যথা {
				arg2 = xstrdup(p);
			}
			মুক্ত(p);
			memset(&gl, 0, আকার(gl));
			r = glob(arg2, GLOB_TILDE, ফাঁকা, &gl);
			যদি (r == GLOB_NOMATCH) {
				debug("%.200s line %d: include %s matched no "
				    "files",filename, linenum, arg2);
				মুক্ত(arg2);
				চালু;
			} অন্যথা যদি (r != 0) {
				error("%.200s line %d: glob failed for %s.",
				    filename, linenum, arg2);
				যাও out;
			}
			মুক্ত(arg2);
			oactive = *activep;
			জন্য (i = 0; i < gl.gl_pathc; i++) {
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
					যাও out;
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
		বিরতি;

	ক্ষেত্র oIPQoS:
		arg = argv_পরবর্তী(&ac, &av);
		যদি ((মান = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			যাও out;
		}
		যদি (মান == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			মান = INT_MAX;
		}
		arg = argv_পরবর্তী(&ac, &av);
		যদি (arg == ফাঁকা)
			value2 = মান;
		অন্যথা যদি ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			যাও out;
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
		বিরতি;

	ক্ষেত্র oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		যাও parse_multistate;

	ক্ষেত্র oSessionType:
		intptr = &options->session_type;
		multistate_ptr = multistate_sessiontype;
		যাও parse_multistate;

	ক্ষেত্র oStdinNull:
		intptr = &options->stdin_null;
		যাও parse_flag;

	ক্ষেত্র oForkAfterAuthentication:
		intptr = &options->fork_after_authentication;
		যাও parse_flag;

	ক্ষেত্র oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		যাও parse_string;

	ক্ষেত্র oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		যাও parse_flag;

	ক্ষেত্র oCanonicalDomains:
		found = options->অঙ্ক_canonical_domains == 0;
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			/* Allow "none" only in first position */
			যদি (strcasecmp(arg, "none") == 0) {
				যদি (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					যাও out;
				}
			}
			যদি (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				যাও out;
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
			strs = ফাঁকা; /* transferred */
			nstrs = 0;
		}
		বিরতি;

	ক্ষেত্র oCanonicalizePermittedCNAMEs:
		found = options->অঙ্ক_permitted_cnames == 0;
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			যদি (strcasecmp(arg, "none") == 0) {
				যদি (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					যাও out;
				}
				arg2 = "";
			} অন্যথা যদি (strcmp(arg, "*") == 0) {
				arg2 = arg;
			} অন্যথা {
				lowercase(arg);
				যদি ((arg2 = strchr(arg, ':')) == ফাঁকা ||
				    arg2[1] == '\0') {
					error("%s line %d: "
					    "Invalid permitted CNAME \"%s\"",
					    filename, linenum, arg);
					যাও out;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    আকার(*cnames));
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
			cnames = ফাঁকা; /* transferred */
			ncnames = 0;
		}
		/* un-transferred cnames is cleaned up before exit */
		বিরতি;

	ক্ষেত্র oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		যাও parse_multistate;

	ক্ষেত্র oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		যাও parse_int;

	ক্ষেত্র oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		যাও parse_flag;

	ক্ষেত্র oStreamLocalBindMask:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			যাও out;
		}
		/* Parse mode in octal format */
		মান = strtol(arg, &endofnumber, 8);
		যদি (arg == endofnumber || মান < 0 || মান > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			যাও out;
		}
		যদি (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)মান;
		বিরতি;

	ক্ষেত্র oStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		যাও parse_flag;

	ক্ষেত্র o_Revoked_Host_চাবিগুলি:
		uintptr = &options->অঙ্ক_revoked_host_চাবিগুলি;
		cppptr = &options->revoked_host_চাবিগুলি;
		found = *uintptr == 0;
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			যদি (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				যাও out;
			}
			/* Allow "none" only in first position */
			যদি (strcasecmp(arg, "none") == 0) {
				যদি (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					যাও out;
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
			strs = ফাঁকা; /* transferred */
			nstrs = 0;
		}
		বিরতি;

	ক্ষেত্র oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			যাও out;
		}
		যদি ((মান = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			যাও out;
		}
		যদি (*activep && *intptr == -1)
			*intptr = মান;
		বিরতি;

	ক্ষেত্র oUpdateHostkeys:
		intptr = &options->update_hostkeys;
		multistate_ptr = multistate_yesnoask;
		যাও parse_multistate;

	ক্ষেত্র oHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
		যাও parse_pubkey_algos;

	ক্ষেত্র oPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		যাও parse_pubkey_algos;

	ক্ষেত্র o_Add_চাবিগুলি_To_Agent:
		arg = argv_পরবর্তী(&ac, &av);
		arg2 = argv_পরবর্তী(&ac, &av);
		মান = parse_multistate_মান(arg, filename, linenum,
		    multistate_yesnoaskconfirm);
		value2 = 0; /* unlimited lifespan by default */
		যদি (মান == 3 && arg2 != ফাঁকা) {
			/* allow "AddKeysToAgent confirm 5m" */
			যদি ((value2 = convtime(arg2)) == -1) {
				error("%s line %d: invalid time value.",
				    filename, linenum);
				যাও out;
			}
		} অন্যথা যদি (মান == -1 && arg2 == ফাঁকা) {
			যদি ((value2 = convtime(arg)) == -1) {
				error("%s line %d: unsupported option",
				    filename, linenum);
				যাও out;
			}
			মান = 1; /* yes */
		} অন্যথা যদি (মান == -1 || arg2 != ফাঁকা) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			যাও out;
		}
		যদি (*activep && options->add_চাবিগুলি_to_agent == -1) {
			options->add_চাবিগুলি_to_agent = মান;
			options->add_চাবিগুলি_to_agent_lifespan = value2;
		}
		বিরতি;

	ক্ষেত্র oIdentityAgent:
		charptr = &options->identity_agent;
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			যাও out;
		}
  parse_agent_path:
		/* Extra validation if the string represents an env var. */
		যদি ((arg2 = dollar_expand(&r, arg)) == ফাঁকা || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			যাও out;
		}
		মুক্ত(arg2);
		/* check for legacy environment format */
		যদি (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			যাও out;
		}
		যদি (*activep && *charptr == ফাঁকা)
			*charptr = xstrdup(arg);
		বিরতি;

	ক্ষেত্র oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		যাও parse_flag;

	ক্ষেত্র oRequiredRSASize:
		intptr = &options->required_rsa_আকার;
		যাও parse_int;

	ক্ষেত্র oWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		যাও parse_multistate;

	ক্ষেত্র oObscureKeystrokeTiming:
		মান = -1;
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			যদি (মান != -1) {
				error("%s line %d: invalid arguments",
				    filename, linenum);
				যাও out;
			}
			যদি (strcmp(arg, "yes") == 0 ||
			    strcmp(arg, "true") == 0)
				মান = SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
			অন্যথা যদি (strcmp(arg, "no") == 0 ||
			    strcmp(arg, "false") == 0)
				মান = 0;
			অন্যথা যদি (strncmp(arg, "interval:", 9) == 0) {
				যদি ((errstr = atoi_err(arg + 9,
				    &মান)) != ফাঁকা) {
					error("%s line %d: integer value %s.",
					    filename, linenum, errstr);
					যাও out;
				}
				যদি (মান <= 0 || মান > 1000) {
					error("%s line %d: value out of range.",
					    filename, linenum);
					যাও out;
				}
			} অন্যথা {
				error("%s line %d: unsupported argument \"%s\"",
				    filename, linenum, arg);
				যাও out;
			}
		}
		যদি (মান == -1) {
			error("%s line %d: missing argument",
			    filename, linenum);
			যাও out;
		}
		intptr = &options->obscure_keystroke_timing_interval;
		যদি (*activep && *intptr == -1)
			*intptr = মান;
		বিরতি;

	ক্ষেত্র oChannelTimeout:
		found = options->অঙ্ক_channel_timeouts == 0;
		যখন ((arg = argv_পরবর্তী(&ac, &av)) != ফাঁকা) {
			/* Allow "none" only in first position */
			যদি (strcasecmp(arg, "none") == 0) {
				যদি (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					যাও out;
				}
			} অন্যথা যদি (parse_pattern_interval(arg,
			    ফাঁকা, ফাঁকা) != 0) {
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
			strs = ফাঁকা; /* transferred */
			nstrs = 0;
		}
		বিরতি;

	ক্ষেত্র oVersionAddendum:
		যদি (str == ফাঁকা || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		যদি (strchr(str + len, '\r') != ফাঁকা) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		যদি ((arg = strchr(সারি, '#')) != ফাঁকা) {
			*arg = '\0';
			rtrim(সারি);
		}
		যদি (*activep && options->version_addendum == ফাঁকা) {
			যদি (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			অন্যথা
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		বিরতি;

	ক্ষেত্র oRefuseConnection:
		arg = argv_পরবর্তী(&ac, &av);
		যদি (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			যাও out;
		}
		যদি (*activep) {
			fatal("%.200s line %d: RefuseConnection: %s",
			    filename, linenum, arg);
		}
		বিরতি;

	ক্ষেত্র oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		বিরতি;

	ক্ষেত্র oUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		বিরতি;

	পূর্বনির্ধারিত:
		error("%s line %d: Unimplemented opcode %d",
		    filename, linenum, opcode);
		যাও out;
	}

	/* Check that there is no garbage at end of line. */
	যদি (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		যাও out;
	}

	/* success */
	ret = 0;
 out:
	free_canon_cnames(cnames, ncnames);
	opt_array_free2(strs, ফাঁকা, nstrs);
	argv_free(oav, oac);
	ফেরত ret;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */
পূর্ণসংখ্যা
read_config_file(ধ্রুবক অক্ষর *filename, কাঠামো passwd *pw, ধ্রুবক অক্ষর *host,
    ধ্রুবক অক্ষর *original_host, ধ্রুবক অক্ষর *remote_command, Options *options, পূর্ণসংখ্যা flags,
    পূর্ণসংখ্যা *want_final_pass)
{
	পূর্ণসংখ্যা active = 1;

	ফেরত read_config_file_depth(filename, pw, host, original_host,
	    remote_command, options, flags, &active, want_final_pass, 0);
}

#define READCONF_MAX_DEPTH	16
স্থির পূর্ণসংখ্যা
read_config_file_depth(ধ্রুবক অক্ষর *filename, কাঠামো passwd *pw,
    ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *original_host, ধ্রুবক অক্ষর *remote_command,
    Options *options, পূর্ণসংখ্যা flags, পূর্ণসংখ্যা *activep, পূর্ণসংখ্যা *want_final_pass, পূর্ণসংখ্যা depth)
{
	FILE *f;
	অক্ষর *সারি = ফাঁকা;
	আকার_t linesize = 0;
	পূর্ণসংখ্যা linenum;
	পূর্ণসংখ্যা bad_options = 0;

	যদি (depth < 0 || depth > READCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	যদি ((f = fopen(filename, "r")) == ফাঁকা)
		ফেরত 0;

	যদি (flags & SSHCONF_CHECKPERM) {
		কাঠামো stat sb;

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
	যখন (getline(&সারি, &linesize, f) != -1) {
		/* Update line number counter. */
		linenum++;
		/*
		 * Trim out comments and strip whitespace.
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages.
		 */
		যদি (process_config_সারি_depth(options, pw, host, original_host,
		    remote_command, সারি, filename, linenum, activep, flags,
		    want_final_pass, depth) != 0)
			bad_options++;
	}
	মুক্ত(সারি);
	fclose(f);
	যদি (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
	ফেরত 1;
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
পূর্ণসংখ্যা
option_clear_or_none(ধ্রুবক অক্ষর *o)
{
	ফেরত o == ফাঁকা || strcasecmp(o, "none") == 0;
}

/*
 * Returns 1 if CanonicalizePermittedCNAMEs have been specified, 0 otherwise.
 * Allowed to be called on non-final configuration.
 */
পূর্ণসংখ্যা
config_has_permitted_cnames(Options *options)
{
	যদি (options->অঙ্ক_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].source_list, "none") == 0 &&
	    strcmp(options->permitted_cnames[0].target_list, "") == 0)
		ফেরত 0;
	ফেরত options->অঙ্ক_permitted_cnames > 0;
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
	memset(options, 'X', আকার(*options));
	options->host_arg = ফাঁকা;
	options->forward_agent = -1;
	options->forward_agent_sock_path = ফাঁকা;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = ফাঁকা;
	options->stdio_forward_port = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = ফাঁকা;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_mask = (mode_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = ফাঁকা;
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
	options->ciphers = ফাঁকা;
	options->macs = ফাঁকা;
	options->kex_algorithms = ফাঁকা;
	options->hostkeyalgorithms = ফাঁকা;
	options->ca_sign_algorithms = ফাঁকা;
	options->অঙ্ক_identity_files = 0;
	memset(options->identity_চাবিগুলি, 0, আকার(options->identity_চাবিগুলি));
	options->অঙ্ক_certificate_files = 0;
	memset(options->certificates, 0, আকার(options->certificates));
	options->hostname = ফাঁকা;
	options->host_চাবি_alias = ফাঁকা;
	options->proxy_command = ফাঁকা;
	options->jump_user = ফাঁকা;
	options->jump_host = ফাঁকা;
	options->jump_port = -1;
	options->jump_extra = ফাঁকা;
	options->user = ফাঁকা;
	options->escape_char = -1;
	options->অঙ্ক_system_hostfiles = 0;
	options->অঙ্ক_user_hostfiles = 0;
	options->local_forwards = ফাঁকা;
	options->অঙ্ক_local_forwards = 0;
	options->remote_forwards = ফাঁকা;
	options->অঙ্ক_remote_forwards = 0;
	options->permitted_remote_opens = ফাঁকা;
	options->অঙ্ক_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
	options->log_level = SYSLOG_LEVEL_NOT_SET;
	options->অঙ্ক_log_verbose = 0;
	options->log_verbose = ফাঁকা;
	options->preferred_authentications = ফাঁকা;
	options->bind_address = ফাঁকা;
	options->bind_interface = ফাঁকা;
	options->pkcs11_provider = ফাঁকা;
	options->sk_provider = ফাঁকা;
	options->enable_ssh_keysign = -1;
	options->no_host_authentication_for_localhost = -1;
	options->identities_only = -1;
	options->rekey_limit = -1;
	options->rekey_interval = -1;
	options->verify_host_চাবি_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_গুনতি_max = -1;
	options->send_env = ফাঁকা;
	options->অঙ্ক_send_env = 0;
	options->setenv = ফাঁকা;
	options->অঙ্ক_setenv = 0;
	options->control_path = ফাঁকা;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_known_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = ফাঁকা;
	options->permit_local_command = -1;
	options->remote_command = ফাঁকা;
	options->add_চাবিগুলি_to_agent = -1;
	options->add_চাবিগুলি_to_agent_lifespan = -1;
	options->identity_agent = ফাঁকা;
	options->visual_host_চাবি = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = ফাঁকা;
	options->অঙ্ক_canonical_domains = 0;
	options->অঙ্ক_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_চাবিগুলি = ফাঁকা;
	options->অঙ্ক_revoked_host_চাবিগুলি = 0;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->hostbased_accepted_algos = ফাঁকা;
	options->pubkey_accepted_algos = ফাঁকা;
	options->known_hosts_command = ফাঁকা;
	options->required_rsa_আকার = -1;
	options->warn_weak_crypto = -1;
	options->enable_escape_commandline = -1;
	options->obscure_keystroke_timing_interval = -1;
	options->tag = ফাঁকা;
	options->channel_timeouts = ফাঁকা;
	options->অঙ্ক_channel_timeouts = 0;
	options->version_addendum = ফাঁকা;
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
পূর্ণসংখ্যা
fill_default_options(Options * options)
{
	অক্ষর *all_cipher, *all_mac, *all_kex, *all_চাবি, *all_sig;
	অক্ষর *def_cipher, *def_mac, *def_kex, *def_চাবি, *def_sig;
	পূর্ণসংখ্যা ret = -1, r;

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
		    options->stdio_forward_host != ফাঁকা ? 1 : 0;
	যদি (options->clear_forwardings == -1)
		options->clear_forwardings =
		    options->stdio_forward_host != ফাঁকা ? 1 : 0;
	যদি (options->clear_forwardings == 1)
		clear_forwardings(options);

	যদি (options->xauth_location == ফাঁকা)
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
	যদি (options->sk_provider == ফাঁকা)
		options->sk_provider = xstrdup("internal");
#অন্যথা
	যদি (options->sk_provider == ফাঁকা)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
#endif
	যদি (options->required_rsa_আকার == -1)
		options->required_rsa_আকার = SSH_RSA_MINIMUM_MODULUS_আকার;
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
	করো { \
		যদি ((r = kex_assemble_names(&options->what, \
		    defaults, all)) != 0) { \
			error_fr(r, "%s", #what); \
			যাও fail; \
		} \
	} যখন (0)
	options->kex_algorithms_set = options->kex_algorithms != ফাঁকা;
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostbased_accepted_algos, def_চাবি, all_চাবি);
	ASSEMBLE(pubkey_accepted_algos, def_চাবি, all_চাবি);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE

#define CLEAR_ON_NONE(v) \
	করো { \
		যদি (option_clear_or_none(v)) { \
			মুক্ত(v); \
			v = ফাঁকা; \
		} \
	} যখন(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	করো { \
		যদি (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			মুক্ত(options->v[0]); \
			মুক্ত(options->v); \
			options->v = ফাঁকা; \
			options->nv = 0; \
		} \
	} যখন (0)
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
	যদি (options->jump_host != ফাঁকা &&
	    strcmp(options->jump_host, "none") == 0 &&
	    options->jump_port == 0 && options->jump_user == ফাঁকা) {
		মুক্ত(options->jump_host);
		options->jump_host = ফাঁকা;
	}
	যদি (options->অঙ্ক_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		মুক্ত(options->permitted_cnames[0].source_list);
		মুক্ত(options->permitted_cnames[0].target_list);
		memset(options->permitted_cnames, '\0',
		    আকার(*options->permitted_cnames));
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
	ফেরত ret;
}

শূন্য
free_options(Options *o)
{
	পূর্ণসংখ্যা i;

	যদি (o == ফাঁকা)
		ফেরত;

#define FREE_ARRAY(type, n, a) \
	করো { \
		type _i; \
		জন্য (_i = 0; _i < (n); _i++) \
			মুক্ত((a)[_i]); \
	} যখন (0)

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
	জন্য (i = 0; i < o->অঙ্ক_identity_files; i++) {
		মুক্ত(o->identity_files[i]);
		sshkey_free(o->identity_চাবিগুলি[i]);
	}
	জন্য (i = 0; i < o->অঙ্ক_certificate_files; i++) {
		মুক্ত(o->certificate_files[i]);
		sshkey_free(o->certificates[i]);
	}
	মুক্ত(o->identity_agent);
	জন্য (i = 0; i < o->অঙ্ক_local_forwards; i++) {
		মুক্ত(o->local_forwards[i].listen_host);
		মুক্ত(o->local_forwards[i].listen_path);
		মুক্ত(o->local_forwards[i].connect_host);
		মুক্ত(o->local_forwards[i].connect_path);
	}
	মুক্ত(o->local_forwards);
	জন্য (i = 0; i < o->অঙ্ক_remote_forwards; i++) {
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
	FREE_ARRAY(পূর্ণসংখ্যা, o->অঙ্ক_canonical_domains, o->canonical_domains);
	জন্য (i = 0; i < o->অঙ্ক_permitted_cnames; i++) {
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
	explicit_bzero(o, আকার(*o));
#undef FREE_ARRAY
}

কাঠামো fwdarg {
	অক্ষর *arg;
	পূর্ণসংখ্যা ispath;
};

/*
 * parse_fwd_field
 * parses the next field in a port forwarding specification.
 * sets fwd to the parsed field and advances p past the colon
 * or sets it to NULL at end of string.
 * returns 0 on success, else non-zero.
 */
স্থির পূর্ণসংখ্যা
parse_fwd_field(অক্ষর **p, কাঠামো fwdarg *fwd)
{
	অক্ষর *ep, *cp = *p;
	পূর্ণসংখ্যা ispath = 0;

	যদি (*cp == '\0') {
		*p = ফাঁকা;
		ফেরত -1;	/* end of string */
	}

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	যদি (*cp == '[') {
		/* find matching ']' */
		জন্য (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++) {
			যদি (*ep == '/')
				ispath = 1;
		}
		/* no matching ']' or not at end of field. */
		যদি (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			ফেরত -1;
		/* NUL terminate the field and advance p past the colon */
		*ep++ = '\0';
		যদি (*ep != '\0')
			*ep++ = '\0';
		fwd->arg = cp + 1;
		fwd->ispath = ispath;
		*p = ep;
		ফেরত 0;
	}

	জন্য (cp = *p; *cp != '\0'; cp++) {
		নির্বাচন (*cp) {
		ক্ষেত্র '\\':
			memmove(cp, cp + 1, strlen(cp + 1) + 1);
			যদি (*cp == '\0')
				ফেরত -1;
			বিরতি;
		ক্ষেত্র '/':
			ispath = 1;
			বিরতি;
		ক্ষেত্র ':':
			*cp++ = '\0';
			যাও done;
		}
	}
done:
	fwd->arg = *p;
	fwd->ispath = ispath;
	*p = cp;
	ফেরত 0;
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
পূর্ণসংখ্যা
parse_forward(কাঠামো Forward *fwd, ধ্রুবক অক্ষর *fwdspec, পূর্ণসংখ্যা dynamicfwd, পূর্ণসংখ্যা remotefwd)
{
	কাঠামো fwdarg fwdargs[4];
	অক্ষর *p, *cp;
	পূর্ণসংখ্যা i, err;

	memset(fwd, 0, আকার(*fwd));
	memset(fwdargs, 0, আকার(fwdargs));

	/*
	 * We expand environment variables before checking if we think they're
	 * paths so that if ${VAR} expands to a fully qualified path it is
	 * treated as a path.
	 */
	cp = p = dollar_expand(&err, fwdspec);
	যদি (p == ফাঁকা || err)
		ফেরত 0;

	/* skip leading spaces */
	যখন (isspace((u_char)*cp))
		cp++;

	জন্য (i = 0; i < 4; ++i) {
		যদি (parse_fwd_field(&cp, &fwdargs[i]) != 0)
			বিরতি;
	}

	/* Check for trailing garbage */
	যদি (cp != ফাঁকা && *cp != '\0') {
		i = 0;	/* failure */
	}

	নির্বাচন (i) {
	ক্ষেত্র 1:
		যদি (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
		} অন্যথা {
			fwd->listen_host = ফাঁকা;
			fwd->listen_port = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		বিরতি;

	ক্ষেত্র 2:
		যদি (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} অন্যথা যদি (fwdargs[1].ispath) {
			fwd->listen_host = ফাঁকা;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} অন্যথা {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		বিরতি;

	ক্ষেত্র 3:
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
			fwd->listen_host = ফাঁকা;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		}
		বিরতি;

	ক্ষেত্র 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_port = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_port = a2port(fwdargs[3].arg);
		বিরতি;
	পূর্বনির্ধারিত:
		i = 0; /* failure */
	}

	মুক্ত(p);

	যদি (dynamicfwd) {
		যদি (!(i == 1 || i == 2))
			যাও fail_free;
	} অন্যথা {
		যদি (!(i == 3 || i == 4)) {
			যদি (fwd->connect_path == ফাঁকা &&
			    fwd->listen_path == ফাঁকা)
				যাও fail_free;
		}
		যদি (fwd->connect_port <= 0 && fwd->connect_path == ফাঁকা)
			যাও fail_free;
	}

	যদি ((fwd->listen_port < 0 && fwd->listen_path == ফাঁকা) ||
	    (!remotefwd && fwd->listen_port == 0))
		যাও fail_free;
	যদি (fwd->connect_host != ফাঁকা &&
	    strlen(fwd->connect_host) >= NI_MAXHOST)
		যাও fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	যদি (fwd->connect_path != ফাঁকা &&
	    strlen(fwd->connect_path) >= PATH_MAX_SUN)
		যাও fail_free;
	যদি (fwd->listen_host != ফাঁকা &&
	    strlen(fwd->listen_host) >= NI_MAXHOST)
		যাও fail_free;
	যদি (fwd->listen_path != ফাঁকা &&
	    strlen(fwd->listen_path) >= PATH_MAX_SUN)
		যাও fail_free;

	ফেরত (i);

 fail_free:
	মুক্ত(fwd->connect_host);
	fwd->connect_host = ফাঁকা;
	মুক্ত(fwd->connect_path);
	fwd->connect_path = ফাঁকা;
	মুক্ত(fwd->listen_host);
	fwd->listen_host = ফাঁকা;
	মুক্ত(fwd->listen_path);
	fwd->listen_path = ফাঁকা;
	ফেরত (0);
}

পূর্ণসংখ্যা
ssh_valid_hostname(ধ্রুবক অক্ষর *s)
{
	আকার_t i;

	যদি (*s == '-')
		ফেরত 0;
	জন্য (i = 0; s[i] != 0; i++) {
		যদি (strchr("'`\"$\\;&<>|(){},", s[i]) != ফাঁকা ||
		    isspace((u_char)s[i]) || iscntrl((u_char)s[i]))
			ফেরত 0;
	}
	ফেরত 1;
}

পূর্ণসংখ্যা
ssh_valid_ruser(ধ্রুবক অক্ষর *s)
{
	আকার_t i;

	যদি (*s == '-')
		ফেরত 0;
	জন্য (i = 0; s[i] != 0; i++) {
		যদি (iscntrl((u_char)s[i]))
			ফেরত 0;
		যদি (strchr("'`\";&<>|(){}$\\", s[i]) != ফাঁকা)
			ফেরত 0;
		/* Disallow '-' after whitespace */
		যদি (isspace((u_char)s[i]) && s[i + 1] == '-')
			ফেরত 0;
	}
	ফেরত 1;
}

পূর্ণসংখ্যা
parse_jump(ধ্রুবক অক্ষর *s, Options *o, পূর্ণসংখ্যা strict, পূর্ণসংখ্যা active)
{
	অক্ষর *orig = ফাঁকা, *sdup = ফাঁকা, *cp;
	অক্ষর *tmp_user = ফাঁকা, *tmp_host = ফাঁকা, *host = ফাঁকা, *user = ফাঁকা;
	পূর্ণসংখ্যা r, ret = -1, tmp_port = -1, port = -1, first = 1;

	যদি (strcasecmp(s, "none") == 0) {
		যদি (active && o->jump_host == ফাঁকা) {
			o->jump_host = xstrdup("none");
			o->jump_port = 0;
		}
		ফেরত 0;
	}

	orig = xstrdup(s);
	যদি ((cp = strchr(orig, '#')) != ফাঁকা)
		*cp = '\0';
	rtrim(orig);

	active &= o->proxy_command == ফাঁকা && o->jump_host == ফাঁকা;
	sdup = xstrdup(orig);
	করো {
		/* Work backwards through string */
		যদি ((cp = strrchr(sdup, ',')) == ফাঁকা)
			cp = sdup; /* last */
		অন্যথা
			*cp++ = '\0';

		r = parse_ssh_uri(cp, &tmp_user, &tmp_host, &tmp_port);
		যদি (r == -1 || (r == 1 && parse_user_host_port(cp,
		    &tmp_user, &tmp_host, &tmp_port) != 0))
			যাও out; /* error already logged */
		যদি (strict) {
			যদি (!ssh_valid_hostname(tmp_host)) {
				error_f("invalid hostname \"%s\"", tmp_host);
				যাও out;
			}
			যদি (tmp_user != ফাঁকা && !ssh_valid_ruser(tmp_user)) {
				error_f("invalid username \"%s\"", tmp_user);
				যাও out;
			}
		}
		যদি (first) {
			user = tmp_user;
			host = tmp_host;
			port = tmp_port;
			tmp_user = tmp_host = ফাঁকা; /* transferred */
		}
		first = 0; /* only check syntax for subsequent hosts */
		মুক্ত(tmp_user);
		মুক্ত(tmp_host);
		tmp_user = tmp_host = ফাঁকা;
		tmp_port = -1;
	} যখন (cp != sdup);

	/* success */
	যদি (active) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_port = port;
		o->proxy_command = xstrdup("none");
		user = host = ফাঁকা; /* transferred */
		যদি (orig != ফাঁকা && (cp = strrchr(orig, ',')) != ফাঁকা) {
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
	ফেরত ret;
}

পূর্ণসংখ্যা
parse_ssh_uri(ধ্রুবক অক্ষর *uri, অক্ষর **userp, অক্ষর **hostp, পূর্ণসংখ্যা *portp)
{
	অক্ষর *user = ফাঁকা, *host = ফাঁকা, *path = ফাঁকা;
	পূর্ণসংখ্যা r, port;

	r = parse_uri("ssh", uri, &user, &host, &port, &path);
	যদি (r == 0 && path != ফাঁকা)
		r = -1;		/* path not allowed */
	যদি (r == 0) {
		যদি (userp != ফাঁকা) {
			*userp = user;
			user = ফাঁকা;
		}
		যদি (hostp != ফাঁকা) {
			*hostp = host;
			host = ফাঁকা;
		}
		যদি (portp != ফাঁকা)
			*portp = port;
	}
	মুক্ত(user);
	মুক্ত(host);
	মুক্ত(path);
	ফেরত r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
স্থির ধ্রুবক অক্ষর *
fmt_multistate_int(পূর্ণসংখ্যা val, ধ্রুবক কাঠামো multistate *m)
{
	u_int i;

	জন্য (i = 0; m[i].চাবি != ফাঁকা; i++) {
		যদি (m[i].মান == val)
			ফেরত m[i].চাবি;
	}
	ফেরত "UNKNOWN";
}

স্থির ধ্রুবক অক্ষর *
fmt_intarg(OpCodes code, পূর্ণসংখ্যা val)
{
	যদি (val == -1)
		ফেরত "unset";
	নির্বাচন (code) {
	ক্ষেত্র oAddressFamily:
		ফেরত fmt_multistate_int(val, multistate_addressfamily);
	ক্ষেত্র oCompression:
		ফেরত fmt_multistate_int(val, multistate_compression);
	ক্ষেত্র o_Verify_Host_চাবি_DNS:
	ক্ষেত্র oUpdateHostkeys:
		ফেরত fmt_multistate_int(val, multistate_yesnoask);
	ক্ষেত্র o_Strict_Host_চাবি_Checking:
		ফেরত fmt_multistate_int(val, multistate_strict_hostkey);
	ক্ষেত্র oControlMaster:
		ফেরত fmt_multistate_int(val, multistate_controlmaster);
	ক্ষেত্র oTunnel:
		ফেরত fmt_multistate_int(val, multistate_tunnel);
	ক্ষেত্র oRequestTTY:
		ফেরত fmt_multistate_int(val, multistate_requesttty);
	ক্ষেত্র oSessionType:
		ফেরত fmt_multistate_int(val, multistate_sessiontype);
	ক্ষেত্র oCanonicalizeHostname:
		ফেরত fmt_multistate_int(val, multistate_canonicalizehostname);
	ক্ষেত্র o_Add_চাবিগুলি_To_Agent:
		ফেরত fmt_multistate_int(val, multistate_yesnoaskconfirm);
	ক্ষেত্র oPubkeyAuthentication:
		ফেরত fmt_multistate_int(val, multistate_pubkey_auth);
	ক্ষেত্র oTCPKeepAlive:
		ফেরত fmt_multistate_int(val, multistate_keepalives);
	ক্ষেত্র oFingerprintHash:
		ফেরত ssh_digest_alg_name(val);
	পূর্বনির্ধারিত:
		নির্বাচন (val) {
		ক্ষেত্র 0:
			ফেরত "no";
		ক্ষেত্র 1:
			ফেরত "yes";
		পূর্বনির্ধারিত:
			ফেরত "UNKNOWN";
		}
	}
}

স্থির ধ্রুবক অক্ষর *
lookup_opcode_name(OpCodes code)
{
	u_int i;

	জন্য (i = 0; keywords[i].name != ফাঁকা; i++)
		যদি (keywords[i].opcode == code)
			ফেরত(keywords[i].name);
	ফেরত "UNKNOWN";
}

স্থির শূন্য
dump_cfg_int(OpCodes code, পূর্ণসংখ্যা val)
{
	যদি (code == oObscureKeystrokeTiming) {
		যদি (val == 0) {
			printf("%s no\n", lookup_opcode_name(code));
			ফেরত;
		} অন্যথা যদি (val == SSH_KEYSTROKE_DEFAULT_INTERVAL_MS) {
			printf("%s yes\n", lookup_opcode_name(code));
			ফেরত;
		}
		/* FALLTHROUGH */
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

স্থির শূন্য
dump_cfg_fmtint(OpCodes code, পূর্ণসংখ্যা val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

স্থির শূন্য
dump_cfg_string(OpCodes code, ধ্রুবক অক্ষর *val)
{
	যদি (val == ফাঁকা)
		ফেরত;
	printf("%s %s\n", lookup_opcode_name(code), val);
}

স্থির শূন্য
dump_cfg_strarray(OpCodes code, u_int গুনতি, অক্ষর **vals)
{
	u_int i;

	জন্য (i = 0; i < গুনতি; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

স্থির শূন্য
dump_cfg_strarray_oneline(OpCodes code, u_int গুনতি, অক্ষর **vals)
{
	u_int i;

	printf("%s", lookup_opcode_name(code));
	যদি (গুনতি == 0)
		printf(" none");
	জন্য (i = 0; i < গুনতি; i++)
		printf(" %s",  vals[i]);
	printf("\n");
}

স্থির শূন্য
dump_cfg_forwards(OpCodes code, u_int গুনতি, ধ্রুবক কাঠামো Forward *fwds)
{
	ধ্রুবক কাঠামো Forward *fwd;
	u_int i;

	/* oDynamicForward */
	জন্য (i = 0; i < গুনতি; i++) {
		fwd = &fwds[i];
		যদি (code == oDynamicForward && fwd->connect_host != ফাঁকা &&
		    strcmp(fwd->connect_host, "socks") != 0)
			চালু;
		যদি (code == oLocalForward && fwd->connect_host != ফাঁকা &&
		    strcmp(fwd->connect_host, "socks") == 0)
			চালু;
		printf("%s", lookup_opcode_name(code));
		যদি (fwd->listen_port == PORT_STREAMLOCAL)
			printf(" %s", fwd->listen_path);
		অন্যথা যদি (fwd->listen_host == ফাঁকা)
			printf(" %d", fwd->listen_port);
		অন্যথা {
			printf(" [%s]:%d",
			    fwd->listen_host, fwd->listen_port);
		}
		যদি (code != oDynamicForward) {
			যদি (fwd->connect_port == PORT_STREAMLOCAL)
				printf(" %s", fwd->connect_path);
			অন্যথা যদি (fwd->connect_host == ফাঁকা)
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
dump_client_config(Options *o, ধ্রুবক অক্ষর *host)
{
	পূর্ণসংখ্যা i, r;
	অক্ষর buf[8], *all_চাবি;

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
	dump_cfg_int(oRequiredRSASize, o->required_rsa_আকার);
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
	যদি (o->forward_agent_sock_path == ফাঁকা)
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
	জন্য (i = 0; i < o->অঙ্ক_permitted_cnames; i++) {
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
	যদি (o->jump_host == ফাঁকা)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	অন্যথা {
		/* Check for numeric addresses */
		i = strchr(o->jump_host, ':') != ফাঁকা ||
		    strspn(o->jump_host, "1234567890.") == strlen(o->jump_host);
		snprintf(buf, আকার(buf), "%d", o->jump_port);
		printf("proxyjump %s%s%s%s%s%s%s%s%s\n",
		    /* optional additional jump spec */
		    o->jump_extra == ফাঁকা ? "" : o->jump_extra,
		    o->jump_extra == ফাঁকা ? "" : ",",
		    /* optional user */
		    o->jump_user == ফাঁকা ? "" : o->jump_user,
		    o->jump_user == ফাঁকা ? "" : "@",
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
