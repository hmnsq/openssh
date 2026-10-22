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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/stat.h>
#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/wait.h>
#அந்தர்பாவ <sys/un.h>

#அந்தர்பாவ <net/if.h>
#அந்தர்பாவ <netinet/in.h>
#அந்தர்பாவ <netinet/ip.h>
#அந்தர்பாவ <arpa/inet.h>

#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <glob.h>
#அந்தர்பாவ <ifaddrs.h>
#அந்தர்பாவ <limits.h>
#அந்தர்பாவ <netdb.h>
#அந்தர்பாவ <paths.h>
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <util.h>
#எனில் defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "cipher.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "readconf.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "kex.h"
#அந்தர்பாவ "mac.h"
#அந்தர்பாவ "myproposal.h"
#அந்தர்பாவ "digest.h"
#அந்தர்பாவ "version.h"

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

நிலையான முழு read_config_file_depth(மாறிலி எழுத்து *filename, கட்டமைப்பு passwd *pw,
    மாறிலி எழுத்து *host, மாறிலி எழுத்து *original_host, மாறிலி எழுத்து *remote_command,
    Options *options, முழு flags, முழு *activep, முழு *want_final_pass, முழு depth);
நிலையான முழு process_config_வரி_depth(Options *options, கட்டமைப்பு passwd *pw,
    மாறிலி எழுத்து *host, மாறிலி எழுத்து *original_host, மாறிலி எழுத்து *remote_command,
    எழுத்து *வரி, மாறிலி எழுத்து *filename, முழு linenum, முழு *activep, முழு flags,
    முழு *want_final_pass, முழு depth);

/* Keyword tokens. */

வகைவரை எண்ணிக்கை {
	oBadOption,
	oHost, oMatch, oInclude, oTag,
	oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout,
	oGatewayPorts, oExitOnForwardFailure,
	oPasswordAuthentication,
	oXAuthLocation,
	oIdentityFile, oHostname, oPort, oRemoteForward, oLocalForward,
	oPermitRemoteOpen,
	oCertificateFile, o_Add_சாவிகள்_To_Agent, oIdentityAgent,
	oUser, oEscapeChar, oProxyCommand,
	oGlobalKnownHostsFile, oUserKnownHostsFile, oConnectionAttempts,
	oBatchMode, oCheckHostIP, o_Strict_Host_சாவி_Checking, oCompression,
	oTCPKeepAlive, o_எண்_Of_Password_Prompts,
	oLogFacility, oLogLevel, oLogVerbose, oCiphers, oMacs,
	oPubkeyAuthentication,
	oKbdInteractiveAuthentication, oKbdInteractiveDevices, o_Host_சாவி_Alias,
	oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication,
	o_Host_சாவி_Algorithms, oBindAddress, oBindInterface, oPKCS11Provider,
	oClearAllForwardings, oNoHostAuthenticationForLocalhost,
	oEnableSSHKeysign, oRekeyLimit, o_Verify_Host_சாவி_DNS, oConnectTimeout,
	oAddressFamily, oGssAuthentication, oGssDelegateCreds,
	oServerAliveInterval, o_Server_Alive_மொத்தம்_Max, oIdentitiesOnly,
	oSendEnv, oSetEnv, oControlPath, oControlMaster, oControlPersist,
	oHashKnownHosts,
	oTunnel, oTunnelDevice,
	oLocalCommand, oPermitLocalCommand, oRemoteCommand,
	o_Visual_Host_சாவி,
	oKexAlgorithms, oIPQoS, oRequestTTY, oSessionType, oStdinNull,
	oForkAfterAuthentication, oIgnoreUnknown, oProxyUseFdpass,
	oCanonicalDomains, oCanonicalizeHostname, oCanonicalizeMaxDots,
	oCanonicalizeFallbackLocal, oCanonicalizePermittedCNAMEs,
	oStreamLocalBindMask, oStreamLocalBindUnlink, o_Revoked_Host_சாவிகள்,
	oFingerprintHash, oUpdateHostkeys, oHostbasedAcceptedAlgorithms,
	oPubkeyAcceptedAlgorithms, oCASignatureAlgorithms, oProxyJump,
	o_Security_சாவி_Provider, oKnownHostsCommand, oRequiredRSASize,
	oEnableEscapeCommandline, oObscureKeystrokeTiming, oChannelTimeout,
	oVersionAddendum, oRefuseConnection, oWarnWeakCrypto,
	oIgnore, oIgnoredUnknownOption, oDeprecated, oUnsupported
} OpCodes;

/* Textual representations of the tokens. */

நிலையான கட்டமைப்பு {
	மாறிலி எழுத்து *name;
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
#எனில் defined(GSSAPI)
	{ "gssapiauthentication", oGssAuthentication },
	{ "gssapidelegatecredentials", oGssDelegateCreds },
# இல்லையெனில்
	{ "gssapiauthentication", oUnsupported },
	{ "gssapidelegatecredentials", oUnsupported },
#endif
#ifdef ENABLE_PKCS11
	{ "pkcs11provider", oPKCS11Provider },
	{ "smartcarddevice", oPKCS11Provider },
# இல்லையெனில்
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
	{ "addkeystoagent", o_Add_சாவிகள்_To_Agent },
	{ "identityagent", oIdentityAgent },
	{ "hostname", oHostname },
	{ "hostkeyalias", o_Host_சாவி_Alias },
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
	{ "stricthostkeychecking", o_Strict_Host_சாவி_Checking },
	{ "compression", oCompression },
	{ "tcpkeepalive", oTCPKeepAlive },
	{ "keepalive", oTCPKeepAlive },				/* obsolete */
	{ "numberofpasswordprompts", o_எண்_Of_Password_Prompts },
	{ "syslogfacility", oLogFacility },
	{ "loglevel", oLogLevel },
	{ "logverbose", oLogVerbose },
	{ "dynamicforward", oDynamicForward },
	{ "preferredauthentications", oPreferredAuthentications },
	{ "hostkeyalgorithms", o_Host_சாவி_Algorithms },
	{ "casignaturealgorithms", oCASignatureAlgorithms },
	{ "bindaddress", oBindAddress },
	{ "bindinterface", oBindInterface },
	{ "clearallforwardings", oClearAllForwardings },
	{ "enablesshkeysign", oEnableSSHKeysign },
	{ "verifyhostkeydns", o_Verify_Host_சாவி_DNS },
	{ "nohostauthenticationforlocalhost", oNoHostAuthenticationForLocalhost },
	{ "rekeylimit", oRekeyLimit },
	{ "connecttimeout", oConnectTimeout },
	{ "addressfamily", oAddressFamily },
	{ "serveraliveinterval", oServerAliveInterval },
	{ "serveralivecountmax", o_Server_Alive_மொத்தம்_Max },
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
	{ "visualhostkey", o_Visual_Host_சாவி },
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
	{ "revokedhostkeys", o_Revoked_Host_சாவிகள் },
	{ "fingerprinthash", oFingerprintHash },
	{ "updatehostkeys", oUpdateHostkeys },
	{ "hostbasedacceptedalgorithms", oHostbasedAcceptedAlgorithms },
	{ "hostbasedkeytypes", oHostbasedAcceptedAlgorithms }, /* obsolete */
	{ "pubkeyacceptedalgorithms", oPubkeyAcceptedAlgorithms },
	{ "pubkeyacceptedkeytypes", oPubkeyAcceptedAlgorithms }, /* obsolete */
	{ "ignoreunknown", oIgnoreUnknown },
	{ "proxyjump", oProxyJump },
	{ "securitykeyprovider", o_Security_சாவி_Provider },
	{ "knownhostscommand", oKnownHostsCommand },
	{ "requiredrsasize", oRequiredRSASize },
	{ "enableescapecommandline", oEnableEscapeCommandline },
	{ "obscurekeystroketiming", oObscureKeystrokeTiming },
	{ "channeltimeout", oChannelTimeout },
	{ "versionaddendum", oVersionAddendum },
	{ "refuseconnection", oRefuseConnection },
	{ "warnweakcrypto", oWarnWeakCrypto },

	{ வெற்று, oBadOption }
};

நிலையான மாறிலி எழுத்து *lookup_opcode_name(OpCodes code);

மாறிலி எழுத்து *
kex_default_pk_alg(வெறுமை)
{
	நிலையான எழுத்து *pkalgs;

	எனில் (pkalgs == வெற்று) {
		எழுத்து *all_சாவி;

		all_சாவி = sshkey_alg_list(0, 0, 1, ',');
		pkalgs = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_சாவி);
		விடுவி(all_சாவி);
	}
	திரும்பு pkalgs;
}

எழுத்து *
ssh_connection_hash(மாறிலி எழுத்து *thishost, மாறிலி எழுத்து *host, மாறிலி எழுத்து *portstr,
    மாறிலி எழுத்து *user, மாறிலி எழுத்து *jumphost)
{
	கட்டமைப்பு ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_LENGTH];

	எனில் ((md = ssh_digest_start(SSH_DIGEST_SHA1)) == வெற்று ||
	    ssh_digest_update(md, thishost, strlen(thishost)) < 0 ||
	    ssh_digest_update(md, host, strlen(host)) < 0 ||
	    ssh_digest_update(md, portstr, strlen(portstr)) < 0 ||
	    ssh_digest_update(md, user, strlen(user)) < 0 ||
	    ssh_digest_update(md, jumphost, strlen(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, அளவு(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	திரும்பு tohex(conn_hash, ssh_digest_bytes(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

வெறுமை
add_local_forward(Options *options, மாறிலி கட்டமைப்பு Forward *newfwd)
{
	கட்டமைப்பு Forward *fwd;
	முழு i;

	/* Don't add duplicates */
	க்கு (i = 0; i < options->இலக்கம்_local_forwards; i++) {
		எனில் (forward_equals(newfwd, options->local_forwards + i))
			திரும்பு;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->இலக்கம்_local_forwards + 1,
	    அளவு(*options->local_forwards));
	fwd = &options->local_forwards[options->இலக்கம்_local_forwards++];

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

வெறுமை
add_remote_forward(Options *options, மாறிலி கட்டமைப்பு Forward *newfwd)
{
	கட்டமைப்பு Forward *fwd;
	முழு i;

	/* Don't add duplicates */
	க்கு (i = 0; i < options->இலக்கம்_remote_forwards; i++) {
		எனில் (forward_equals(newfwd, options->remote_forwards + i))
			திரும்பு;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->இலக்கம்_remote_forwards + 1,
	    அளவு(*options->remote_forwards));
	fwd = &options->remote_forwards[options->இலக்கம்_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_port = newfwd->listen_port;
	fwd->listen_path = newfwd->listen_path;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_port = newfwd->connect_port;
	fwd->connect_path = newfwd->connect_path;
	fwd->handle = newfwd->handle;
	fwd->allocated_port = 0;
}

நிலையான வெறுமை
clear_forwardings(Options *options)
{
	முழு i;

	க்கு (i = 0; i < options->இலக்கம்_local_forwards; i++) {
		விடுவி(options->local_forwards[i].listen_host);
		விடுவி(options->local_forwards[i].listen_path);
		விடுவி(options->local_forwards[i].connect_host);
		விடுவி(options->local_forwards[i].connect_path);
	}
	எனில் (options->இலக்கம்_local_forwards > 0) {
		விடுவி(options->local_forwards);
		options->local_forwards = வெற்று;
	}
	options->இலக்கம்_local_forwards = 0;
	க்கு (i = 0; i < options->இலக்கம்_remote_forwards; i++) {
		விடுவி(options->remote_forwards[i].listen_host);
		விடுவி(options->remote_forwards[i].listen_path);
		விடுவி(options->remote_forwards[i].connect_host);
		விடுவி(options->remote_forwards[i].connect_path);
	}
	எனில் (options->இலக்கம்_remote_forwards > 0) {
		விடுவி(options->remote_forwards);
		options->remote_forwards = வெற்று;
	}
	options->இலக்கம்_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

வெறுமை
add_certificate_file(Options *options, மாறிலி எழுத்து *path, முழு userprovided)
{
	முழு i;

	எனில் (options->இலக்கம்_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	க்கு (i = 0; i < options->இலக்கம்_certificate_files; i++) {
		எனில் (options->certificate_file_userprovided[i] == userprovided &&
		    strcmp(options->certificate_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			திரும்பு;
		}
	}

	options->certificate_file_userprovided[options->இலக்கம்_certificate_files] =
	    userprovided;
	options->certificate_files[options->இலக்கம்_certificate_files++] =
	    xstrdup(path);
}

வெறுமை
add_identity_file(Options *options, மாறிலி எழுத்து *dir, மாறிலி எழுத்து *filename,
    முழு userprovided)
{
	எழுத்து *path;
	முழு i;

	எனில் (options->இலக்கம்_identity_files >= SSH_MAX_IDENTITY_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_IDENTITY_FILES);

	எனில் (dir == வெற்று) /* no dir, filename is absolute */
		path = xstrdup(filename);
	இல்லையெனில் எனில் (xasprintf(&path, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", path);

	/* Avoid registering duplicates */
	க்கு (i = 0; i < options->இலக்கம்_identity_files; i++) {
		எனில் (options->identity_file_userprovided[i] == userprovided &&
		    strcmp(options->identity_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			விடுவி(path);
			திரும்பு;
		}
	}

	options->identity_file_userprovided[options->இலக்கம்_identity_files] =
	    userprovided;
	options->identity_files[options->இலக்கம்_identity_files++] = path;
}

முழு
default_ssh_port(வெறுமை)
{
	நிலையான முழு port;
	கட்டமைப்பு servent *sp;

	எனில் (port == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		port = sp ? ntohs(sp->s_port) : SSH_DEFAULT_PORT;
	}
	திரும்பு port;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
நிலையான முழு
execute_in_shell(மாறிலி எழுத்து *cmd)
{
	எழுத்து *shell;
	pid_t pid;
	முழு status;

	எனில் ((shell = getenv("SHELL")) == வெற்று)
		shell = _PATH_BSHELL;

	எனில் (access(shell, X_OK) == -1) {
		fatal("Shell \"%s\" is not executable: %s",
		    shell, strerror(errno));
	}

	debug("Executing command: '%.500s'", cmd);

	/* Fork and execute the command. */
	எனில் ((pid = fork()) == 0) {
		எழுத்து *argv[4];

		எனில் (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = xstrdup(cmd);
		argv[3] = வெற்று;

		execv(argv[0], argv);
		error("Unable to execute '%.100s': %s", cmd, strerror(errno));
		/* Die with signal to make this error apparent to parent. */
		ssh_signal(SIGTERM, SIG_DFL);
		kill(getpid(), SIGTERM);
		_exit(1);
	}
	/* Parent. */
	எனில் (pid == -1)
		fatal_f("fork: %.100s", strerror(errno));

	போது (waitpid(pid, &status, 0) == -1) {
		எனில் (errno != EINTR && errno != EAGAIN)
			fatal_f("waitpid: %s", strerror(errno));
	}
	எனில் (!WIFEXITED(status)) {
		error("command '%.100s' exited abnormally", cmd);
		திரும்பு -1;
	}
	debug3("command returned status %d", WEXITSTATUS(status));
	திரும்பு WEXITSTATUS(status);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
நிலையான முழு
check_match_ifaddrs(மாறிலி எழுத்து *addrlist)
{
#ifdef HAVE_IFADDRS_H
	கட்டமைப்பு ifaddrs *ifa, *ifaddrs = வெற்று;
	முழு r, found = 0;
	எழுத்து addr[NI_MAXHOST];
	socklen_t salen;

	எனில் (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    strerror(errno));
		திரும்பு 0;
	}
	க்கு (ifa = ifaddrs; ifa != வெற்று; ifa = ifa->ifa_next) {
		எனில் (ifa->ifa_addr == வெற்று || ifa->ifa_name == வெற்று ||
		    (ifa->ifa_flags & IFF_UP) == 0)
			தொடர்;
		தேர்வு (ifa->ifa_addr->sa_family) {
		நிலை AF_INET:
			salen = அளவு(கட்டமைப்பு sockaddr_in);
			நிறுத்து;
		நிலை AF_INET6:
			salen = அளவு(கட்டமைப்பு sockaddr_in6);
			நிறுத்து;
#ifdef AF_LINK
		நிலை AF_LINK:
			/* ignore */
			தொடர்;
#endif /* AF_LINK */
		இயல்பு:
			debug2_f("interface %s: unsupported address family %d",
			    ifa->ifa_name, ifa->ifa_addr->sa_family);
			தொடர்;
		}
		எனில் ((r = getnameinfo(ifa->ifa_addr, salen, addr, அளவு(addr),
		    வெற்று, 0, NI_NUMERICHOST)) != 0) {
			debug2_f("interface %s getnameinfo failed: %s",
			    ifa->ifa_name, gai_strerror(r));
			தொடர்;
		}
		debug3_f("interface %s addr %s", ifa->ifa_name, addr);
		எனில் (addr_match_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			found = 1;
			நிறுத்து;
		}
	}
	freeifaddrs(ifaddrs);
	திரும்பு found;
#இல்லையெனில் /* HAVE_IFADDRS_H */
	error("match localnetwork: not supported on this platform");
	திரும்பு 0;
#endif /* HAVE_IFADDRS_H */
}

/*
 * Expand a "match exec" command or an Include path, caller must free returned
 * value.
 */
நிலையான எழுத்து *
expand_match_exec_or_include_path(மாறிலி எழுத்து *path, Options *options,
    கட்டமைப்பு passwd *pw, மாறிலி எழுத்து *host_arg, மாறிலி எழுத்து *original_host,
    முழு final_pass, முழு is_include_path)
{
	எழுத்து thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	எழுத்து uidstr[32], *conn_hash_hex, *keyalias, *jmphost, *ruser;
	எழுத்து *host, *ret;
	முழு port;

	port = options->port <= 0 ? default_ssh_port() : options->port;
	ruser = options->user == வெற்று ? pw->pw_name : options->user;
	எனில் (final_pass) {
		host = xstrdup(options->hostname);
	} இல்லையெனில் எனில் (options->hostname != வெற்று) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (எழுத்து *)வெற்று);
	} இல்லையெனில் {
		host = xstrdup(host_arg);
	}
	எனில் (gethostname(thishost, அளவு(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	jmphost = option_clear_or_none(options->jump_host) ?
	    "" : options->jump_host;
	strlcpy(shorthost, thishost, அளவு(shorthost));
	shorthost[strcspn(thishost, ".")] = '\0';
	snprintf(portstr, அளவு(portstr), "%d", port);
	snprintf(uidstr, அளவு(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	conn_hash_hex = ssh_connection_hash(thishost, host,
	    portstr, ruser, jmphost);
	keyalias = options->host_சாவி_alias ?  options->host_சாவி_alias : host;

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
	    (எழுத்து *)வெற்று);
	விடுவி(host);
	விடுவி(conn_hash_hex);
	திரும்பு ret;
}

/*
 * Parse and execute a Match directive.
 */
நிலையான முழு
match_cfg_வரி(Options *options, மாறிலி எழுத்து *full_வரி, முழு *acp, எழுத்து ***avp,
    கட்டமைப்பு passwd *pw, மாறிலி எழுத்து *host_arg, மாறிலி எழுத்து *original_host,
    மாறிலி எழுத்து *remote_command, முழு final_pass, முழு *want_final_pass,
    மாறிலி எழுத்து *filename, முழு linenum)
{
	எழுத்து *arg, *oattrib = வெற்று, *attrib = வெற்று, *cmd, *host, *criteria;
	மாறிலி எழுத்து *ruser;
	முழு r, this_result, result = 1, attributes = 0, negate;

	/*
	 * Configuration is likely to be incomplete at this point so we
	 * must be prepared to use default values.
	 */
	ruser = options->user == வெற்று ? pw->pw_name : options->user;
	எனில் (final_pass) {
		host = xstrdup(options->hostname);
	} இல்லையெனில் எனில் (options->hostname != வெற்று) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (எழுத்து *)வெற்று);
	} இல்லையெனில் {
		host = xstrdup(host_arg);
	}

	debug2("checking match for '%s' host %s originally %s",
	    full_வரி, host, original_host);
	போது ((attrib = argv_next(acp, avp)) != வெற்று) {
		/* Terminate on comment */
		எனில் (*attrib == '#') {
			argv_consume(acp);
			நிறுத்து;
		}
		attrib = oattrib = xstrdup(attrib);
		arg = criteria = வெற்று;
		this_result = 1;
		எனில் ((negate = (attrib[0] == '!')))
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		எனில் (strcasecmp(attrib, "all") == 0) {
			எனில் (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != வெற்று &&
			    *arg != '\0' && *arg != '#')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				result = -1;
				செல் out;
			}
			எனில் (arg != வெற்று && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			எனில் (result)
				result = negate ? 0 : 1;
			செல் out;
		}
		attributes++;
		/* criteria "final" and "canonical" have no argument */
		எனில் (strcasecmp(attrib, "canonical") == 0 ||
		    strcasecmp(attrib, "final") == 0) {
			/*
			 * If the config requests "Match final" without
			 * negation then remember this so we can perform a
			 * second pass later.
			 */
			எனில் (strcasecmp(attrib, "final") == 0 &&
			    want_final_pass != வெற்று)
				*want_final_pass |= !negate;
			r = !!final_pass;  /* force bitmask member to boolean */
			எனில் (r == (negate ? 1 : 0))
				this_result = result = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_result ? "" : "not ", oattrib);
			செல் next;
		}

		/* Keep this list in sync with below */
		எனில் (strprefix(attrib, "host=", 1)  != வெற்று ||
		    strprefix(attrib, "originalhost=", 1) != வெற்று ||
		    strprefix(attrib, "user=", 1) != வெற்று ||
		    strprefix(attrib, "localuser=", 1) != வெற்று ||
		    strprefix(attrib, "localnetwork=", 1) != வெற்று ||
		    strprefix(attrib, "version=", 1) != வெற்று ||
		    strprefix(attrib, "tagged=", 1) != வெற்று ||
		    strprefix(attrib, "command=", 1) != வெற்று ||
		    strprefix(attrib, "exec=", 1) != வெற்று) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} இல்லையெனில் எனில் ((arg = argv_next(acp, avp)) == வெற்று) {
			error("%.200s line %d: missing argument for Match '%s'",
			    filename, linenum, oattrib);
			result = -1;
			செல் out;
		}

		/*
		 * All other criteria require an argument, though it may
		 * be the empty string for the "tagged" and "command"
		 * options.
		 */
		எனில் (*arg == '\0' &&
		    strcasecmp(attrib, "tagged") != 0 &&
		    strcasecmp(attrib, "command") != 0)
			arg = வெற்று;
		எனில் (arg == வெற்று || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			செல் out;
		}
		எனில் (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = match_hostname(host, arg) == 1;
			எனில் (r == (negate ? 1 : 0))
				this_result = result = 0;
		} இல்லையெனில் எனில் (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = match_hostname(original_host, arg) == 1;
			எனில் (r == (negate ? 1 : 0))
				this_result = result = 0;
		} இல்லையெனில் எனில் (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = match_pattern_list(ruser, arg, 0) == 1;
			எனில் (r == (negate ? 1 : 0))
				this_result = result = 0;
		} இல்லையெனில் எனில் (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = match_pattern_list(pw->pw_name, arg, 0) == 1;
			எனில் (r == (negate ? 1 : 0))
				this_result = result = 0;
		} இல்லையெனில் எனில் (strcasecmp(attrib, "localnetwork") == 0) {
			எனில் (addr_match_cidr_list(வெற்று, arg) == -1) {
				/* Error already printed */
				result = -1;
				செல் out;
			}
			r = check_match_ifaddrs(arg) == 1;
			எனில் (r == (negate ? 1 : 0))
				this_result = result = 0;
		} இல்லையெனில் எனில் (strcasecmp(attrib, "version") == 0) {
			criteria = xstrdup(SSH_RELEASE);
			r = match_pattern_list(SSH_RELEASE, arg, 0) == 1;
			எனில் (r == (negate ? 1 : 0))
				this_result = result = 0;
		} இல்லையெனில் எனில் (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->tag == வெற்று ? "" :
			    options->tag);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			எனில் (r == (negate ? 1 : 0))
				this_result = result = 0;
		} இல்லையெனில் எனில் (strcasecmp(attrib, "command") == 0) {
			criteria = xstrdup(remote_command == வெற்று ?
			    "" : remote_command);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			எனில் (r == (negate ? 1 : 0))
				this_result = result = 0;
		} இல்லையெனில் எனில் (strcasecmp(attrib, "sessiontype") == 0) {
			எனில் (options->session_type == SESSION_TYPE_SUBSYSTEM)
				criteria = xstrdup("subsystem");
			இல்லையெனில் எனில் (options->session_type == SESSION_TYPE_NONE)
				criteria = xstrdup("none");
			இல்லையெனில் எனில் (remote_command != வெற்று &&
			    *remote_command != '\0')
				criteria = xstrdup("exec");
			இல்லையெனில்
				criteria = xstrdup("shell");
			r = match_pattern_list(criteria, arg, 0) == 1;
			எனில் (r == (negate ? 1 : 0))
				this_result = result = 0;
		} இல்லையெனில் எனில் (strcasecmp(attrib, "exec") == 0) {
			எனில் ((cmd = expand_match_exec_or_include_path(arg,
			    options, pw, host_arg, original_host,
			    final_pass, 0)) == வெற்று) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			எனில் (result != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				விடுவி(cmd);
				செல் next;
			}
			r = execute_in_shell(cmd);
			எனில் (r == -1) {
				fatal("%.200s line %d: match exec "
				    "'%.100s' error", filename,
				    linenum, cmd);
			}
			criteria = xstrdup(cmd);
			விடுவி(cmd);
			/* Force exit status to boolean */
			r = r == 0;
			எனில் (r == (negate ? 1 : 0))
				this_result = result = 0;
		} இல்லையெனில் {
			error("Unsupported Match attribute %s", attrib);
			result = -1;
			செல் out;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s' ",
		    filename, linenum, this_result ? "": "not ", oattrib,
		    criteria == வெற்று ? "" : " \"",
		    criteria == வெற்று ? "" : criteria,
		    criteria == வெற்று ? "" : "\"");
 next:
		விடுவி(criteria);
		விடுவி(oattrib);
		oattrib = attrib = வெற்று;
	}
	எனில் (attributes == 0) {
		error("One or more attributes required for Match");
		result = -1;
		செல் out;
	}
 out:
	எனில் (result != -1)
		debug2("match %sfound", result ? "" : "not ");
	விடுவி(oattrib);
	விடுவி(host);
	திரும்பு result;
}

/* Remove environment variable by pattern */
நிலையான வெறுமை
rm_env(Options *options, மாறிலி எழுத்து *arg, மாறிலி எழுத்து *filename, முழு linenum)
{
	u_int i, j, onum_send_env = options->இலக்கம்_send_env;

	/* Remove an environment variable */
	க்கு (i = 0; i < options->இலக்கம்_send_env; ) {
		எனில் (!match_pattern(options->send_env[i], arg + 1)) {
			i++;
			தொடர்;
		}
		debug3("%s line %d: removing environment %s",
		    filename, linenum, options->send_env[i]);
		விடுவி(options->send_env[i]);
		options->send_env[i] = வெற்று;
		க்கு (j = i; j < options->இலக்கம்_send_env - 1; j++) {
			options->send_env[j] = options->send_env[j + 1];
			options->send_env[j + 1] = வெற்று;
		}
		options->இலக்கம்_send_env--;
		/* NB. don't increment i */
	}
	எனில் (onum_send_env != options->இலக்கம்_send_env) {
		options->send_env = xrecallocarray(options->send_env,
		    onum_send_env, options->இலக்கம்_send_env,
		    அளவு(*options->send_env));
	}
}

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */
நிலையான OpCodes
parse_token(மாறிலி எழுத்து *cp, மாறிலி எழுத்து *filename, முழு linenum,
    மாறிலி எழுத்து *ignored_unknown)
{
	முழு i;

	க்கு (i = 0; keywords[i].name; i++)
		எனில் (strcmp(cp, keywords[i].name) == 0)
			திரும்பு keywords[i].opcode;
	எனில் (ignored_unknown != வெற்று &&
	    match_pattern_list(cp, ignored_unknown, 1) == 1)
		திரும்பு oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	திரும்பு oBadOption;
}

நிலையான வெறுமை
free_canon_cnames(கட்டமைப்பு allowed_cname *cnames, u_int n)
{
	u_int i;

	எனில் (cnames == வெற்று || n == 0)
		திரும்பு;
	க்கு (i = 0; i < n; i++) {
		விடுவி(cnames[i].source_list);
		விடுவி(cnames[i].target_list);
	}
	விடுவி(cnames);
}

/* Multistate option parsing */
கட்டமைப்பு multistate {
	எழுத்து *சாவி;
	முழு மதிப்பு;
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_flag[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ வெற்று, -1 }
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_yesnoask[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ வெற்று, -1 }
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_strict_hostkey[] = {
	{ "true",			SSH_STRICT_HOSTKEY_YES },
	{ "false",			SSH_STRICT_HOSTKEY_OFF },
	{ "yes",			SSH_STRICT_HOSTKEY_YES },
	{ "no",				SSH_STRICT_HOSTKEY_OFF },
	{ "ask",			SSH_STRICT_HOSTKEY_ASK },
	{ "off",			SSH_STRICT_HOSTKEY_OFF },
	{ "accept-new",			SSH_STRICT_HOSTKEY_NEW },
	{ வெற்று, -1 }
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_yesnoaskconfirm[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "confirm",			3 },
	{ வெற்று, -1 }
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ வெற்று, -1 }
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_controlmaster[] = {
	{ "true",			SSHCTL_MASTER_YES },
	{ "yes",			SSHCTL_MASTER_YES },
	{ "false",			SSHCTL_MASTER_NO },
	{ "no",				SSHCTL_MASTER_NO },
	{ "auto",			SSHCTL_MASTER_AUTO },
	{ "ask",			SSHCTL_MASTER_ASK },
	{ "autoask",			SSHCTL_MASTER_AUTO_ASK },
	{ வெற்று, -1 }
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET },
	{ "point-to-point",		SSH_TUNMODE_POINTOPOINT },
	{ "true",			SSH_TUNMODE_DEFAULT },
	{ "yes",			SSH_TUNMODE_DEFAULT },
	{ "false",			SSH_TUNMODE_NO },
	{ "no",				SSH_TUNMODE_NO },
	{ வெற்று, -1 }
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_requesttty[] = {
	{ "true",			REQUEST_TTY_YES },
	{ "yes",			REQUEST_TTY_YES },
	{ "false",			REQUEST_TTY_NO },
	{ "no",				REQUEST_TTY_NO },
	{ "force",			REQUEST_TTY_FORCE },
	{ "auto",			REQUEST_TTY_AUTO },
	{ வெற்று, -1 }
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_sessiontype[] = {
	{ "none",			SESSION_TYPE_NONE },
	{ "subsystem",			SESSION_TYPE_SUBSYSTEM },
	{ "default",			SESSION_TYPE_DEFAULT },
	{ வெற்று, -1 }
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_canonicalizehostname[] = {
	{ "true",			SSH_CANONICALISE_YES },
	{ "false",			SSH_CANONICALISE_NO },
	{ "yes",			SSH_CANONICALISE_YES },
	{ "no",				SSH_CANONICALISE_NO },
	{ "always",			SSH_CANONICALISE_ALWAYS },
	{ வெற்று, -1 }
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_pubkey_auth[] = {
	{ "true",			SSH_PUBKEY_AUTH_ALL },
	{ "false",			SSH_PUBKEY_AUTH_NO },
	{ "yes",			SSH_PUBKEY_AUTH_ALL },
	{ "no",				SSH_PUBKEY_AUTH_NO },
	{ "unbound",			SSH_PUBKEY_AUTH_UNBOUND },
	{ "host-bound",			SSH_PUBKEY_AUTH_HBOUND },
	{ வெற்று, -1 }
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ வெற்று, -1 }
};
நிலையான மாறிலி கட்டமைப்பு multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ வெற்று, -1 }
};
/* XXX this will need to be replaced with a bitmask if we add more flags */
நிலையான மாறிலி கட்டமைப்பு multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ வெற்று, -1 }
};

நிலையான முழு
parse_multistate_மதிப்பு(மாறிலி எழுத்து *arg, மாறிலி எழுத்து *filename, முழு linenum,
    மாறிலி கட்டமைப்பு multistate *multistate_ptr)
{
	முழு i;

	எனில் (!arg || *arg == '\0') {
		error("%s line %d: missing argument.", filename, linenum);
		திரும்பு -1;
	}
	க்கு (i = 0; multistate_ptr[i].சாவி != வெற்று; i++) {
		எனில் (strcasecmp(arg, multistate_ptr[i].சாவி) == 0)
			திரும்பு multistate_ptr[i].மதிப்பு;
	}
	திரும்பு -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
முழு
process_config_வரி(Options *options, கட்டமைப்பு passwd *pw, மாறிலி எழுத்து *host,
    மாறிலி எழுத்து *original_host, மாறிலி எழுத்து *remote_command, எழுத்து *வரி,
    மாறிலி எழுத்து *filename, முழு linenum, முழு *activep, முழு flags)
{
	திரும்பு process_config_வரி_depth(options, pw, host, original_host,
	    remote_command, வரி, filename, linenum, activep, flags, வெற்று, 0);
}

#define WHITESPACE " \t\r\n"
நிலையான முழு
process_config_வரி_depth(Options *options, கட்டமைப்பு passwd *pw, மாறிலி எழுத்து *host,
    மாறிலி எழுத்து *original_host, மாறிலி எழுத்து *remote_command, எழுத்து *வரி,
    மாறிலி எழுத்து *filename, முழு linenum, முழு *activep, முழு flags,
    முழு *want_final_pass, முழு depth)
{
	எழுத்து *str, **charptr, *endofnumber, *keyword, *arg, *arg2, *p;
	எழுத்து **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	முழு r, oactive, negated, opcode, *intptr, மதிப்பு, value2, cmdline = 0;
	முழு remotefwd, dynamicfwd, ca_only = 0, found = 0;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	long long val64;
	size_t len;
	கட்டமைப்பு Forward fwd;
	மாறிலி கட்டமைப்பு multistate *multistate_ptr;
	glob_t gl;
	மாறிலி எழுத்து *errstr;
	எழுத்து **oav = வெற்று, **av;
	முழு oac = 0, ac;
	முழு ret = -1;
	கட்டமைப்பு allowed_cname *cnames = வெற்று;
	u_int ncnames = 0;
	எழுத்து **strs = வெற்று; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	எனில் (activep == வெற்று) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	எனில் ((len = strlen(வரி)) == 0)
		திரும்பு 0;
	க்கு (len--; len > 0; len--) {
		எனில் (strchr(WHITESPACE "\f", வரி[len]) == வெற்று)
			நிறுத்து;
		வரி[len] = '\0';
	}

	str = வரி;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	எனில் ((keyword = strdelim(&str)) == வெற்று)
		திரும்பு 0;
	/* Ignore leading whitespace. */
	எனில் (*keyword == '\0')
		keyword = strdelim(&str);
	எனில் (keyword == வெற்று || !*keyword || *keyword == '\n' || *keyword == '#')
		திரும்பு 0;
	/* Match lowercase keyword */
	lowercase(keyword);

	/* Prepare to parse remainder of line */
	எனில் (str != வெற்று)
		str += strspn(str, WHITESPACE);
	எனில் (str == வெற்று || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		திரும்பு -1;
	}
	opcode = parse_token(keyword, filename, linenum,
	    options->ignored_unknown);
	எனில் (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		திரும்பு -1;
	}
	ac = oac;
	av = oav;

	தேர்வு (opcode) {
	நிலை oBadOption:
		/* don't panic, but count bad options */
		செல் out;
	நிலை oIgnore:
		argv_consume(&ac);
		நிறுத்து;
	நிலை oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		நிறுத்து;
	நிலை oConnectTimeout:
		intptr = &options->connection_timeout;
parse_time:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			செல் out;
		}
		எனில் (strcmp(arg, "none") == 0)
			மதிப்பு = -1;
		இல்லையெனில் எனில் ((மதிப்பு = convtime(arg)) == -1) {
			error("%s line %d: invalid time value.",
			    filename, linenum);
			செல் out;
		}
		எனில் (*activep && *intptr == -1)
			*intptr = மதிப்பு;
		நிறுத்து;

	நிலை oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			error("%s line %d: missing argument.",
			    filename, linenum);
			செல் out;
		}

		மதிப்பு = -1;
		multistate_ptr = multistate_flag;
		க்கு (i = 0; multistate_ptr[i].சாவி != வெற்று; i++) {
			எனில் (strcasecmp(arg, multistate_ptr[i].சாவி) == 0) {
				மதிப்பு = multistate_ptr[i].மதிப்பு;
				நிறுத்து;
			}
		}
		எனில் (மதிப்பு != -1) {
			எனில் (*activep && *intptr == -1)
				*intptr = மதிப்பு;
			நிறுத்து;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		எனில் (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_path;
		செல் parse_agent_path;

	நிலை oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_next(&ac, &av);
		எனில் ((மதிப்பு = parse_multistate_மதிப்பு(arg, filename, linenum,
		    multistate_ptr)) == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			செல் out;
		}
		எனில் (*activep && *intptr == -1)
			*intptr = மதிப்பு;
		நிறுத்து;

	நிலை oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		செல் parse_flag;

	நிலை oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		செல் parse_time;

	நிலை oGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		செல் parse_flag;

	நிலை oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		செல் parse_flag;

	நிலை oPasswordAuthentication:
		intptr = &options->password_authentication;
		செல் parse_flag;

	நிலை oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		செல் parse_flag;

	நிலை oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		செல் parse_string;

	நிலை oPubkeyAuthentication:
		multistate_ptr = multistate_pubkey_auth;
		intptr = &options->pubkey_authentication;
		செல் parse_multistate;

	நிலை oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		செல் parse_flag;

	நிலை oGssAuthentication:
		intptr = &options->gss_authentication;
		செல் parse_flag;

	நிலை oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		செல் parse_flag;

	நிலை oBatchMode:
		intptr = &options->batch_mode;
		செல் parse_flag;

	நிலை oCheckHostIP:
		intptr = &options->check_host_ip;
		செல் parse_flag;

	நிலை o_Verify_Host_சாவி_DNS:
		intptr = &options->verify_host_சாவி_dns;
		multistate_ptr = multistate_yesnoask;
		செல் parse_multistate;

	நிலை o_Strict_Host_சாவி_Checking:
		intptr = &options->strict_host_சாவி_checking;
		multistate_ptr = multistate_strict_hostkey;
		செல் parse_multistate;

	நிலை oCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		செல் parse_multistate;

	நிலை oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		செல் parse_multistate;

	நிலை oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		செல் parse_flag;

	நிலை o_எண்_Of_Password_Prompts:
		intptr = &options->எண்_of_password_prompts;
		செல் parse_int;

	நிலை oRekeyLimit:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.", filename,
			    linenum);
			செல் out;
		}
		எனில் (strcmp(arg, "default") == 0) {
			val64 = 0;
		} இல்லையெனில் {
			எனில் (scan_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, strerror(errno));
				செல் out;
			}
			எனில் (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				செல் out;
			}
		}
		எனில் (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		எனில் (ac != 0) { /* optional rekey interval present */
			எனில் (strcmp(av[0], "none") == 0) {
				(வெறுமை)argv_next(&ac, &av);	/* discard */
				நிறுத்து;
			}
			intptr = &options->rekey_interval;
			செல் parse_time;
		}
		நிறுத்து;

	நிலை oIdentityFile:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			செல் out;
		}
		எனில் (*activep) {
			intptr = &options->இலக்கம்_identity_files;
			எனில் (*intptr >= SSH_MAX_IDENTITY_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_IDENTITY_FILES);
				செல் out;
			}
			add_identity_file(options, வெற்று,
			    arg, flags & SSHCONF_USERCONF);
		}
		நிறுத்து;

	நிலை oCertificateFile:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			செல் out;
		}
		எனில் (*activep) {
			intptr = &options->இலக்கம்_certificate_files;
			எனில் (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				செல் out;
			}
			add_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		நிறுத்து;

	நிலை oXAuthLocation:
		charptr=&options->xauth_location;
		செல் parse_string;

	நிலை oUser:
		charptr = &options->user;
parse_string:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			செல் out;
		}
		எனில் (*activep && *charptr == வெற்று)
			*charptr = xstrdup(arg);
		நிறுத்து;

	நிலை oGlobalKnownHostsFile:
		cpptr = (எழுத்து **)&options->system_hostfiles;
		uintptr = &options->இலக்கம்_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		i = 0;
		மதிப்பு = *uintptr == 0; /* was array empty when we started? */
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			எனில் (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				செல் out;
			}
			/* Allow "none" only in first position */
			எனில் (strcasecmp(arg, "none") == 0) {
				எனில் (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					செல் out;
				}
			}
			i++;
			எனில் (*activep && மதிப்பு) {
				எனில் ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries.", filename, linenum,
					    keyword);
					செல் out;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		நிறுத்து;

	நிலை oUserKnownHostsFile:
		cpptr = (எழுத்து **)&options->user_hostfiles;
		uintptr = &options->இலக்கம்_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		செல் parse_char_array;

	நிலை oHostname:
		charptr = &options->hostname;
		செல் parse_string;

	நிலை oTag:
		charptr = &options->tag;
		செல் parse_string;

	நிலை o_Host_சாவி_Alias:
		charptr = &options->host_சாவி_alias;
		செல் parse_string;

	நிலை oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		செல் parse_string;

	நிலை oBindAddress:
		charptr = &options->bind_address;
		செல் parse_string;

	நிலை oBindInterface:
		charptr = &options->bind_interface;
		செல் parse_string;

	நிலை oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		செல் parse_string;

	நிலை o_Security_சாவி_Provider:
		charptr = &options->sk_provider;
		செல் parse_string;

	நிலை oKnownHostsCommand:
		charptr = &options->known_hosts_command;
		செல் parse_command;

	நிலை oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		எனில் (str == வெற்று) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			செல் out;
		}
		len = strspn(str, WHITESPACE "=");
		எனில் (*activep && *charptr == வெற்று)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		நிறுத்து;

	நிலை oProxyJump:
		எனில் (str == வெற்று) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			செல் out;
		}
		len = strspn(str, WHITESPACE "=");
		/* XXX use argv? */
		எனில் (parse_jump(str + len, options, cmdline, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			செல் out;
		}
		argv_consume(&ac);
		நிறுத்து;

	நிலை oPort:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			செல் out;
		}
		மதிப்பு = a2port(arg);
		எனில் (மதிப்பு <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			செல் out;
		}
		எனில் (*activep && options->port == -1)
			options->port = மதிப்பு;
		நிறுத்து;

	நிலை oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_next(&ac, &av);
		எனில் ((errstr = atoi_err(arg, &மதிப்பு)) != வெற்று) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			செல் out;
		}
		எனில் (*activep && *intptr == -1)
			*intptr = மதிப்பு;
		நிறுத்து;

	நிலை oCiphers:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			செல் out;
		}
		எனில் (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			செல் out;
		}
		எனில் (*activep && options->ciphers == வெற்று)
			options->ciphers = xstrdup(arg);
		நிறுத்து;

	நிலை oMacs:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			செல் out;
		}
		எனில் (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			செல் out;
		}
		எனில் (*activep && options->macs == வெற்று)
			options->macs = xstrdup(arg);
		நிறுத்து;

	நிலை oKexAlgorithms:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			செல் out;
		}
		எனில் (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			செல் out;
		}
		எனில் (*activep && options->kex_algorithms == வெற்று)
			options->kex_algorithms = xstrdup(arg);
		நிறுத்து;

	நிலை o_Host_சாவி_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			செல் out;
		}
		எனில் (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			செல் out;
		}
		எனில் (*activep && *charptr == வெற்று)
			*charptr = xstrdup(arg);
		நிறுத்து;

	நிலை oCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		செல் parse_pubkey_algos;

	நிலை oLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		மதிப்பு = log_level_எண்(arg);
		எனில் (மதிப்பு == SYSLOG_LEVEL_NOT_SET) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			செல் out;
		}
		எனில் (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_SET)
			*log_level_ptr = (LogLevel) மதிப்பு;
		நிறுத்து;

	நிலை oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		மதிப்பு = log_facility_எண்(arg);
		எனில் (மதிப்பு == SYSLOG_FACILITY_NOT_SET) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			செல் out;
		}
		எனில் (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) மதிப்பு;
		நிறுத்து;

	நிலை oLogVerbose:
		cppptr = &options->log_verbose;
		uintptr = &options->இலக்கம்_log_verbose;
		i = 0;
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			எனில் (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				செல் out;
			}
			/* Allow "none" only in first position */
			எனில் (strcasecmp(arg, "none") == 0) {
				எனில் (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					செல் out;
				}
			}
			i++;
			எனில் (*activep && *uintptr == 0) {
				*cppptr = xrecallocarray(*cppptr, *uintptr,
				    *uintptr + 1, அளவு(**cppptr));
				(*cppptr)[(*uintptr)++] = xstrdup(arg);
			}
		}
		நிறுத்து;

	நிலை oLocalForward:
	நிலை oRemoteForward:
	நிலை oDynamicForward:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			செல் out;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		எனில் (!dynamicfwd) {
			arg2 = argv_next(&ac, &av);
			எனில் (arg2 == வெற்று || *arg2 == '\0') {
				எனில் (remotefwd)
					dynamicfwd = 1;
				இல்லையெனில் {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					செல் out;
				}
			} இல்லையெனில் {
				/* construct a string for parse_forward */
				snprintf(fwdarg, அளவு(fwdarg), "%s:%s", arg,
				    arg2);
			}
		}
		எனில் (dynamicfwd)
			strlcpy(fwdarg, arg, அளவு(fwdarg));

		எனில் (parse_forward(&fwd, fwdarg, dynamicfwd, remotefwd) == 0) {
			error("%.200s line %d: Bad forwarding specification.",
			    filename, linenum);
			செல் out;
		}

		எனில் (*activep) {
			எனில் (remotefwd) {
				add_remote_forward(options, &fwd);
			} இல்லையெனில் {
				add_local_forward(options, &fwd);
			}
		}
		நிறுத்து;

	நிலை oPermitRemoteOpen:
		uintptr = &options->இலக்கம்_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		found = *uintptr == 0;
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			எனில் (strcasecmp(arg, "none") == 0 ||
			    strcasecmp(arg, "any") == 0) {
				எனில் (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					விடுவி(arg2);
					செல் out;
				}
			} இல்லையெனில் {
				p = hpdelim(&arg);
				எனில் (p == வெற்று) {
					fatal("%s line %d: missing host in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
				}
				p = cleanhostname(p);
				/*
				 * don't want to use permitopen_port to avoid
				 * dependency on channels.[ch] here.
				 */
				எனில் (arg == வெற்று || (strcmp(arg, "*") != 0 &&
				    a2port(arg) <= 0)) {
					fatal("%s line %d: bad port number "
					    "in %s", filename, linenum,
					    lookup_opcode_name(opcode));
				}
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg2);
			விடுவி(arg2);
		}
		எனில் (nstrs == 0)
			fatal("%s line %d: missing %s specification",
			    filename, linenum, lookup_opcode_name(opcode));
		எனில் (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = வெற்று; /* transferred */
			nstrs = 0;
		}
		நிறுத்து;

	நிலை oClearAllForwardings:
		intptr = &options->clear_forwardings;
		செல் parse_flag;

	நிலை oHost:
		எனில் (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			செல் out;
		}
		*activep = 0;
		arg2 = வெற்று;
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			எனில் (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				செல் out;
			}
			எனில் ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				நிறுத்து;
			}
			negated = *arg == '!';
			எனில் (negated)
				arg++;
			எனில் (match_pattern(host, arg)) {
				எனில் (negated) {
					debug("%.200s line %d: Skipping Host "
					    "block because of negated match "
					    "for %.100s", filename, linenum,
					    arg);
					*activep = 0;
					argv_consume(&ac);
					நிறுத்து;
				}
				எனில் (!*activep)
					arg2 = arg; /* logged below */
				*activep = 1;
			}
		}
		எனில் (*activep)
			debug("%.200s line %d: Applying options for %.100s",
			    filename, linenum, arg2);
		நிறுத்து;

	நிலை oMatch:
		எனில் (cmdline) {
			error("Match directive not supported as a command-line "
			    "option");
			செல் out;
		}
		மதிப்பு = match_cfg_வரி(options, str, &ac, &av, pw, host,
		    original_host, remote_command, flags & SSHCONF_FINAL,
		    want_final_pass, filename, linenum);
		எனில் (மதிப்பு < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			செல் out;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : மதிப்பு;
		நிறுத்து;

	நிலை oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			செல் out;
		}
		எனில் (strcmp(arg, "none") == 0)
			மதிப்பு = SSH_ESCAPECHAR_NONE;
		இல்லையெனில் எனில் (arg[1] == '\0')
			மதிப்பு = (u_char) arg[0];
		இல்லையெனில் எனில் (arg[0] == '^' && arg[2] == 0 &&
		    (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			மதிப்பு = (u_char) arg[1] & 31;
		இல்லையெனில் {
			error("%.200s line %d: Bad escape character.",
			    filename, linenum);
			செல் out;
		}
		எனில் (*activep && *intptr == -1)
			*intptr = மதிப்பு;
		நிறுத்து;

	நிலை oAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
		செல் parse_multistate;

	நிலை oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		செல் parse_flag;

	நிலை oIdentitiesOnly:
		intptr = &options->identities_only;
		செல் parse_flag;

	நிலை oServerAliveInterval:
		intptr = &options->server_alive_interval;
		செல் parse_time;

	நிலை o_Server_Alive_மொத்தம்_Max:
		intptr = &options->server_alive_மொத்தம்_max;
		செல் parse_int;

	நிலை oSendEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			எனில் (*arg == '\0' || strchr(arg, '=') != வெற்று) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				செல் out;
			}
			found = 1;
			எனில் (!*activep)
				தொடர்;
			எனில் (*arg == '-') {
				/* Removing an env var */
				rm_env(options, arg, filename, linenum);
				தொடர்;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->இலக்கம்_send_env, arg);
		}
		எனில் (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		நிறுத்து;

	நிலை oSetEnv:
		found = options->இலக்கம்_setenv == 0;
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			எனில் (strchr(arg, '=') == வெற்று) {
				error("%s line %d: Invalid SetEnv.",
				    filename, linenum);
				செல் out;
			}
			எனில் (lookup_setenv_in_list(arg, strs, nstrs) != வெற்று) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				தொடர்;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg);
		}
		எனில் (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		எனில் (found && *activep) {
			options->setenv = strs;
			options->இலக்கம்_setenv = nstrs;
			strs = வெற்று; /* transferred */
			nstrs = 0;
		}
		நிறுத்து;

	நிலை oControlPath:
		charptr = &options->control_path;
		செல் parse_string;

	நிலை oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		செல் parse_multistate;

	நிலை oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			error("%.200s line %d: Missing ControlPersist"
			    " argument.", filename, linenum);
			செல் out;
		}
		மதிப்பு = 0;
		value2 = 0;	/* timeout */
		எனில் (strcmp(arg, "no") == 0 || strcmp(arg, "false") == 0)
			மதிப்பு = 0;
		இல்லையெனில் எனில் (strcmp(arg, "yes") == 0 || strcmp(arg, "true") == 0)
			மதிப்பு = 1;
		இல்லையெனில் எனில் ((value2 = convtime(arg)) >= 0)
			மதிப்பு = 1;
		இல்லையெனில் {
			error("%.200s line %d: Bad ControlPersist argument.",
			    filename, linenum);
			செல் out;
		}
		எனில் (*activep && *intptr == -1) {
			*intptr = மதிப்பு;
			options->control_persist_timeout = value2;
		}
		நிறுத்து;

	நிலை oHashKnownHosts:
		intptr = &options->hash_known_hosts;
		செல் parse_flag;

	நிலை oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		செல் parse_multistate;

	நிலை oTunnelDevice:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			செல் out;
		}
		மதிப்பு = a2tun(arg, &value2);
		எனில் (மதிப்பு == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			செல் out;
		}
		எனில் (*activep && options->tun_local == -1) {
			options->tun_local = மதிப்பு;
			options->tun_remote = value2;
		}
		நிறுத்து;

	நிலை oLocalCommand:
		charptr = &options->local_command;
		செல் parse_command;

	நிலை oPermitLocalCommand:
		intptr = &options->permit_local_command;
		செல் parse_flag;

	நிலை oRemoteCommand:
		charptr = &options->remote_command;
		செல் parse_command;

	நிலை o_Visual_Host_சாவி:
		intptr = &options->visual_host_சாவி;
		செல் parse_flag;

	நிலை oInclude:
		எனில் (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			செல் out;
		}
		மதிப்பு = 0;
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			எனில் (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				செல் out;
			}
			/* Expand %tokens and environment variables */
			எனில் ((p = expand_match_exec_or_include_path(arg,
			    options, pw, host, original_host,
			    flags & SSHCONF_FINAL, 1)) == வெற்று) {
				error("%.200s line %d: Unable to expand user "
				    "config file '%.100s'",
				    filename, linenum, arg);
				தொடர்;
			}
			/*
			 * Ensure all paths are anchored. User configuration
			 * files may begin with '~/' but system configurations
			 * must not. If the path is relative, then treat it
			 * as living in ~/.ssh for user configurations or
			 * /etc/ssh for system ones.
			 */
			எனில் (*p == '~' && (flags & SSHCONF_USERCONF) == 0) {
				error("%.200s line %d: bad include path %s.",
				    filename, linenum, p);
				செல் out;
			}
			எனில் (!path_absolute(p) && *p != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" _PATH_SSH_USER_DIR : SSHDIR, p);
			} இல்லையெனில் {
				arg2 = xstrdup(p);
			}
			விடுவி(p);
			memset(&gl, 0, அளவு(gl));
			r = glob(arg2, GLOB_TILDE, வெற்று, &gl);
			எனில் (r == GLOB_NOMATCH) {
				debug("%.200s line %d: include %s matched no "
				    "files",filename, linenum, arg2);
				விடுவி(arg2);
				தொடர்;
			} இல்லையெனில் எனில் (r != 0) {
				error("%.200s line %d: glob failed for %s.",
				    filename, linenum, arg2);
				செல் out;
			}
			விடுவி(arg2);
			oactive = *activep;
			க்கு (i = 0; i < gl.gl_pathc; i++) {
				debug3("%.200s line %d: Including file %s "
				    "depth %d%s", filename, linenum,
				    gl.gl_pathv[i], depth,
				    oactive ? "" : " (parse only)");
				r = read_config_file_depth(gl.gl_pathv[i],
				    pw, host, original_host, remote_command,
				    options, flags | SSHCONF_CHECKPERM |
				    (oactive ? 0 : SSHCONF_NEVERMATCH),
				    activep, want_final_pass, depth + 1);
				எனில் (r != 1 && errno != ENOENT) {
					error("%.200s line %d: Can't open user "
					    "config file %.100s: %.100s",
					    filename, linenum, gl.gl_pathv[i],
					    strerror(errno));
					globfree(&gl);
					செல் out;
				}
				/*
				 * don't let Match in includes clobber the
				 * containing file's Match state.
				 */
				*activep = oactive;
				எனில் (r != 1)
					மதிப்பு = -1;
			}
			globfree(&gl);
		}
		எனில் (மதிப்பு != 0)
			ret = மதிப்பு;
		நிறுத்து;

	நிலை oIPQoS:
		arg = argv_next(&ac, &av);
		எனில் ((மதிப்பு = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			செல் out;
		}
		எனில் (மதிப்பு == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			மதிப்பு = INT_MAX;
		}
		arg = argv_next(&ac, &av);
		எனில் (arg == வெற்று)
			value2 = மதிப்பு;
		இல்லையெனில் எனில் ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			செல் out;
		}
		எனில் (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		எனில் (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = மதிப்பு;
			options->ip_qos_bulk = value2;
		}
		நிறுத்து;

	நிலை oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		செல் parse_multistate;

	நிலை oSessionType:
		intptr = &options->session_type;
		multistate_ptr = multistate_sessiontype;
		செல் parse_multistate;

	நிலை oStdinNull:
		intptr = &options->stdin_null;
		செல் parse_flag;

	நிலை oForkAfterAuthentication:
		intptr = &options->fork_after_authentication;
		செல் parse_flag;

	நிலை oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		செல் parse_string;

	நிலை oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		செல் parse_flag;

	நிலை oCanonicalDomains:
		found = options->இலக்கம்_canonical_domains == 0;
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			/* Allow "none" only in first position */
			எனில் (strcasecmp(arg, "none") == 0) {
				எனில் (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					செல் out;
				}
			}
			எனில் (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				செல் out;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		எனில் (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		எனில் (found && *activep) {
			options->canonical_domains = strs;
			options->இலக்கம்_canonical_domains = nstrs;
			strs = வெற்று; /* transferred */
			nstrs = 0;
		}
		நிறுத்து;

	நிலை oCanonicalizePermittedCNAMEs:
		found = options->இலக்கம்_permitted_cnames == 0;
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			எனில் (strcasecmp(arg, "none") == 0) {
				எனில் (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					செல் out;
				}
				arg2 = "";
			} இல்லையெனில் எனில் (strcmp(arg, "*") == 0) {
				arg2 = arg;
			} இல்லையெனில் {
				lowercase(arg);
				எனில் ((arg2 = strchr(arg, ':')) == வெற்று ||
				    arg2[1] == '\0') {
					error("%s line %d: "
					    "Invalid permitted CNAME \"%s\"",
					    filename, linenum, arg);
					செல் out;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    அளவு(*cnames));
			cnames[ncnames].source_list = xstrdup(arg);
			cnames[ncnames].target_list = xstrdup(arg2);
			ncnames++;
		}
		எனில் (ncnames == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		எனில் (found && *activep) {
			options->permitted_cnames = cnames;
			options->இலக்கம்_permitted_cnames = ncnames;
			cnames = வெற்று; /* transferred */
			ncnames = 0;
		}
		/* un-transferred cnames is cleaned up before exit */
		நிறுத்து;

	நிலை oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		செல் parse_multistate;

	நிலை oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		செல் parse_int;

	நிலை oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		செல் parse_flag;

	நிலை oStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			செல் out;
		}
		/* Parse mode in octal format */
		மதிப்பு = strtol(arg, &endofnumber, 8);
		எனில் (arg == endofnumber || மதிப்பு < 0 || மதிப்பு > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			செல் out;
		}
		எனில் (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)மதிப்பு;
		நிறுத்து;

	நிலை oStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		செல் parse_flag;

	நிலை o_Revoked_Host_சாவிகள்:
		uintptr = &options->இலக்கம்_revoked_host_சாவிகள்;
		cppptr = &options->revoked_host_சாவிகள்;
		found = *uintptr == 0;
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			எனில் (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				செல் out;
			}
			/* Allow "none" only in first position */
			எனில் (strcasecmp(arg, "none") == 0) {
				எனில் (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					செல் out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		எனில் (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		எனில் (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = வெற்று; /* transferred */
			nstrs = 0;
		}
		நிறுத்து;

	நிலை oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			செல் out;
		}
		எனில் ((மதிப்பு = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			செல் out;
		}
		எனில் (*activep && *intptr == -1)
			*intptr = மதிப்பு;
		நிறுத்து;

	நிலை oUpdateHostkeys:
		intptr = &options->update_hostkeys;
		multistate_ptr = multistate_yesnoask;
		செல் parse_multistate;

	நிலை oHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
		செல் parse_pubkey_algos;

	நிலை oPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		செல் parse_pubkey_algos;

	நிலை o_Add_சாவிகள்_To_Agent:
		arg = argv_next(&ac, &av);
		arg2 = argv_next(&ac, &av);
		மதிப்பு = parse_multistate_மதிப்பு(arg, filename, linenum,
		    multistate_yesnoaskconfirm);
		value2 = 0; /* unlimited lifespan by default */
		எனில் (மதிப்பு == 3 && arg2 != வெற்று) {
			/* allow "AddKeysToAgent confirm 5m" */
			எனில் ((value2 = convtime(arg2)) == -1) {
				error("%s line %d: invalid time value.",
				    filename, linenum);
				செல் out;
			}
		} இல்லையெனில் எனில் (மதிப்பு == -1 && arg2 == வெற்று) {
			எனில் ((value2 = convtime(arg)) == -1) {
				error("%s line %d: unsupported option",
				    filename, linenum);
				செல் out;
			}
			மதிப்பு = 1; /* yes */
		} இல்லையெனில் எனில் (மதிப்பு == -1 || arg2 != வெற்று) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			செல் out;
		}
		எனில் (*activep && options->add_சாவிகள்_to_agent == -1) {
			options->add_சாவிகள்_to_agent = மதிப்பு;
			options->add_சாவிகள்_to_agent_lifespan = value2;
		}
		நிறுத்து;

	நிலை oIdentityAgent:
		charptr = &options->identity_agent;
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			செல் out;
		}
  parse_agent_path:
		/* Extra validation if the string represents an env var. */
		எனில் ((arg2 = dollar_expand(&r, arg)) == வெற்று || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			செல் out;
		}
		விடுவி(arg2);
		/* check for legacy environment format */
		எனில் (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			செல் out;
		}
		எனில் (*activep && *charptr == வெற்று)
			*charptr = xstrdup(arg);
		நிறுத்து;

	நிலை oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		செல் parse_flag;

	நிலை oRequiredRSASize:
		intptr = &options->required_rsa_size;
		செல் parse_int;

	நிலை oWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		செல் parse_multistate;

	நிலை oObscureKeystrokeTiming:
		மதிப்பு = -1;
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			எனில் (மதிப்பு != -1) {
				error("%s line %d: invalid arguments",
				    filename, linenum);
				செல் out;
			}
			எனில் (strcmp(arg, "yes") == 0 ||
			    strcmp(arg, "true") == 0)
				மதிப்பு = SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
			இல்லையெனில் எனில் (strcmp(arg, "no") == 0 ||
			    strcmp(arg, "false") == 0)
				மதிப்பு = 0;
			இல்லையெனில் எனில் (strncmp(arg, "interval:", 9) == 0) {
				எனில் ((errstr = atoi_err(arg + 9,
				    &மதிப்பு)) != வெற்று) {
					error("%s line %d: integer value %s.",
					    filename, linenum, errstr);
					செல் out;
				}
				எனில் (மதிப்பு <= 0 || மதிப்பு > 1000) {
					error("%s line %d: value out of range.",
					    filename, linenum);
					செல் out;
				}
			} இல்லையெனில் {
				error("%s line %d: unsupported argument \"%s\"",
				    filename, linenum, arg);
				செல் out;
			}
		}
		எனில் (மதிப்பு == -1) {
			error("%s line %d: missing argument",
			    filename, linenum);
			செல் out;
		}
		intptr = &options->obscure_keystroke_timing_interval;
		எனில் (*activep && *intptr == -1)
			*intptr = மதிப்பு;
		நிறுத்து;

	நிலை oChannelTimeout:
		found = options->இலக்கம்_channel_timeouts == 0;
		போது ((arg = argv_next(&ac, &av)) != வெற்று) {
			/* Allow "none" only in first position */
			எனில் (strcasecmp(arg, "none") == 0) {
				எனில் (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					செல் out;
				}
			} இல்லையெனில் எனில் (parse_pattern_interval(arg,
			    வெற்று, வெற்று) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		எனில் (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		எனில் (found && *activep) {
			options->channel_timeouts = strs;
			options->இலக்கம்_channel_timeouts = nstrs;
			strs = வெற்று; /* transferred */
			nstrs = 0;
		}
		நிறுத்து;

	நிலை oVersionAddendum:
		எனில் (str == வெற்று || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		எனில் (strchr(str + len, '\r') != வெற்று) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		எனில் ((arg = strchr(வரி, '#')) != வெற்று) {
			*arg = '\0';
			rtrim(வரி);
		}
		எனில் (*activep && options->version_addendum == வெற்று) {
			எனில் (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			இல்லையெனில்
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		நிறுத்து;

	நிலை oRefuseConnection:
		arg = argv_next(&ac, &av);
		எனில் (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			செல் out;
		}
		எனில் (*activep) {
			fatal("%.200s line %d: RefuseConnection: %s",
			    filename, linenum, arg);
		}
		நிறுத்து;

	நிலை oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		நிறுத்து;

	நிலை oUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		நிறுத்து;

	இயல்பு:
		error("%s line %d: Unimplemented opcode %d",
		    filename, linenum, opcode);
		செல் out;
	}

	/* Check that there is no garbage at end of line. */
	எனில் (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		செல் out;
	}

	/* success */
	ret = 0;
 out:
	free_canon_cnames(cnames, ncnames);
	opt_array_free2(strs, வெற்று, nstrs);
	argv_free(oav, oac);
	திரும்பு ret;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */
முழு
read_config_file(மாறிலி எழுத்து *filename, கட்டமைப்பு passwd *pw, மாறிலி எழுத்து *host,
    மாறிலி எழுத்து *original_host, மாறிலி எழுத்து *remote_command, Options *options, முழு flags,
    முழு *want_final_pass)
{
	முழு active = 1;

	திரும்பு read_config_file_depth(filename, pw, host, original_host,
	    remote_command, options, flags, &active, want_final_pass, 0);
}

#define READCONF_MAX_DEPTH	16
நிலையான முழு
read_config_file_depth(மாறிலி எழுத்து *filename, கட்டமைப்பு passwd *pw,
    மாறிலி எழுத்து *host, மாறிலி எழுத்து *original_host, மாறிலி எழுத்து *remote_command,
    Options *options, முழு flags, முழு *activep, முழு *want_final_pass, முழு depth)
{
	FILE *f;
	எழுத்து *வரி = வெற்று;
	size_t linesize = 0;
	முழு linenum;
	முழு bad_options = 0;

	எனில் (depth < 0 || depth > READCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	எனில் ((f = fopen(filename, "r")) == வெற்று)
		திரும்பு 0;

	எனில் (flags & SSHCONF_CHECKPERM) {
		கட்டமைப்பு stat sb;

		எனில் (fstat(fileno(f), &sb) == -1)
			fatal("fstat %s: %s", filename, strerror(errno));
		எனில் (((sb.st_uid != 0 && sb.st_uid != getuid()) ||
		    (sb.st_mode & 022) != 0))
			fatal("Bad owner or permissions on %s", filename);
	}

	debug("Reading configuration data %.200s", filename);

	/*
	 * Mark that we are now processing the options.  This flag is turned
	 * on/off by Host specifications.
	 */
	linenum = 0;
	போது (getline(&வரி, &linesize, f) != -1) {
		/* Update line number counter. */
		linenum++;
		/*
		 * Trim out comments and strip whitespace.
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages.
		 */
		எனில் (process_config_வரி_depth(options, pw, host, original_host,
		    remote_command, வரி, filename, linenum, activep, flags,
		    want_final_pass, depth) != 0)
			bad_options++;
	}
	விடுவி(வரி);
	fclose(f);
	எனில் (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
	திரும்பு 1;
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
முழு
option_clear_or_none(மாறிலி எழுத்து *o)
{
	திரும்பு o == வெற்று || strcasecmp(o, "none") == 0;
}

/*
 * Returns 1 if CanonicalizePermittedCNAMEs have been specified, 0 otherwise.
 * Allowed to be called on non-final configuration.
 */
முழு
config_has_permitted_cnames(Options *options)
{
	எனில் (options->இலக்கம்_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].source_list, "none") == 0 &&
	    strcmp(options->permitted_cnames[0].target_list, "") == 0)
		திரும்பு 0;
	திரும்பு options->இலக்கம்_permitted_cnames > 0;
}

/*
 * Initializes options to special values that indicate that they have not yet
 * been set.  Read_config_file will only set options with this value. Options
 * are processed in the following order: command line, user config file,
 * system config file.  Last, fill_default_options is called.
 */

வெறுமை
initialize_options(Options * options)
{
	memset(options, 'X', அளவு(*options));
	options->host_arg = வெற்று;
	options->forward_agent = -1;
	options->forward_agent_sock_path = வெற்று;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = வெற்று;
	options->stdio_forward_port = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = வெற்று;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_mask = (mode_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = வெற்று;
	options->hostbased_authentication = -1;
	options->batch_mode = -1;
	options->check_host_ip = -1;
	options->strict_host_சாவி_checking = -1;
	options->compression = -1;
	options->tcp_keep_alive = -1;
	options->port = -1;
	options->address_family = -1;
	options->connection_attempts = -1;
	options->connection_timeout = -1;
	options->எண்_of_password_prompts = -1;
	options->ciphers = வெற்று;
	options->macs = வெற்று;
	options->kex_algorithms = வெற்று;
	options->hostkeyalgorithms = வெற்று;
	options->ca_sign_algorithms = வெற்று;
	options->இலக்கம்_identity_files = 0;
	memset(options->identity_சாவிகள், 0, அளவு(options->identity_சாவிகள்));
	options->இலக்கம்_certificate_files = 0;
	memset(options->certificates, 0, அளவு(options->certificates));
	options->hostname = வெற்று;
	options->host_சாவி_alias = வெற்று;
	options->proxy_command = வெற்று;
	options->jump_user = வெற்று;
	options->jump_host = வெற்று;
	options->jump_port = -1;
	options->jump_extra = வெற்று;
	options->user = வெற்று;
	options->escape_char = -1;
	options->இலக்கம்_system_hostfiles = 0;
	options->இலக்கம்_user_hostfiles = 0;
	options->local_forwards = வெற்று;
	options->இலக்கம்_local_forwards = 0;
	options->remote_forwards = வெற்று;
	options->இலக்கம்_remote_forwards = 0;
	options->permitted_remote_opens = வெற்று;
	options->இலக்கம்_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
	options->log_level = SYSLOG_LEVEL_NOT_SET;
	options->இலக்கம்_log_verbose = 0;
	options->log_verbose = வெற்று;
	options->preferred_authentications = வெற்று;
	options->bind_address = வெற்று;
	options->bind_interface = வெற்று;
	options->pkcs11_provider = வெற்று;
	options->sk_provider = வெற்று;
	options->enable_ssh_keysign = -1;
	options->no_host_authentication_for_localhost = -1;
	options->identities_only = -1;
	options->rekey_limit = -1;
	options->rekey_interval = -1;
	options->verify_host_சாவி_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_மொத்தம்_max = -1;
	options->send_env = வெற்று;
	options->இலக்கம்_send_env = 0;
	options->setenv = வெற்று;
	options->இலக்கம்_setenv = 0;
	options->control_path = வெற்று;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_known_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = வெற்று;
	options->permit_local_command = -1;
	options->remote_command = வெற்று;
	options->add_சாவிகள்_to_agent = -1;
	options->add_சாவிகள்_to_agent_lifespan = -1;
	options->identity_agent = வெற்று;
	options->visual_host_சாவி = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = வெற்று;
	options->இலக்கம்_canonical_domains = 0;
	options->இலக்கம்_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_சாவிகள் = வெற்று;
	options->இலக்கம்_revoked_host_சாவிகள் = 0;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->hostbased_accepted_algos = வெற்று;
	options->pubkey_accepted_algos = வெற்று;
	options->known_hosts_command = வெற்று;
	options->required_rsa_size = -1;
	options->warn_weak_crypto = -1;
	options->enable_escape_commandline = -1;
	options->obscure_keystroke_timing_interval = -1;
	options->tag = வெற்று;
	options->channel_timeouts = வெற்று;
	options->இலக்கம்_channel_timeouts = 0;
	options->version_addendum = வெற்று;
}

/*
 * A petite version of fill_default_options() that just fills the options
 * needed for hostname canonicalization to proceed.
 */
வெறுமை
fill_default_options_for_canonicalization(Options *options)
{
	எனில் (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	எனில் (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	எனில் (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
}

/*
 * Called after processing other sources of option data, this fills those
 * options for which no value has been specified with their default values.
 */
முழு
fill_default_options(Options * options)
{
	எழுத்து *all_cipher, *all_mac, *all_kex, *all_சாவி, *all_sig;
	எழுத்து *def_cipher, *def_mac, *def_kex, *def_சாவி, *def_sig;
	முழு ret = -1, r;

	எனில் (options->forward_agent == -1)
		options->forward_agent = 0;
	எனில் (options->forward_x11 == -1)
		options->forward_x11 = 0;
	எனில் (options->forward_x11_trusted == -1)
		options->forward_x11_trusted = 0;
	எனில் (options->forward_x11_timeout == -1)
		options->forward_x11_timeout = 1200;
	/*
	 * stdio forwarding (-W) changes the default for these but we defer
	 * setting the values so they can be overridden.
	 */
	எனில் (options->exit_on_forward_failure == -1)
		options->exit_on_forward_failure =
		    options->stdio_forward_host != வெற்று ? 1 : 0;
	எனில் (options->clear_forwardings == -1)
		options->clear_forwardings =
		    options->stdio_forward_host != வெற்று ? 1 : 0;
	எனில் (options->clear_forwardings == 1)
		clear_forwardings(options);

	எனில் (options->xauth_location == வெற்று)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	எனில் (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	எனில் (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	எனில் (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	எனில் (options->pubkey_authentication == -1)
		options->pubkey_authentication = SSH_PUBKEY_AUTH_ALL;
	எனில் (options->gss_authentication == -1)
		options->gss_authentication = 0;
	எனில் (options->gss_deleg_creds == -1)
		options->gss_deleg_creds = 0;
	எனில் (options->password_authentication == -1)
		options->password_authentication = 1;
	எனில் (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	எனில் (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	எனில் (options->batch_mode == -1)
		options->batch_mode = 0;
	எனில் (options->check_host_ip == -1)
		options->check_host_ip = 0;
	எனில் (options->strict_host_சாவி_checking == -1)
		options->strict_host_சாவி_checking = SSH_STRICT_HOSTKEY_ASK;
	எனில் (options->compression == -1)
		options->compression = 0;
	எனில் (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = SSH_KEEPALIVES_TRANSPORT;
	எனில் (options->port == -1)
		options->port = 0;	/* Filled in ssh_connect. */
	எனில் (options->address_family == -1)
		options->address_family = AF_UNSPEC;
	எனில் (options->connection_attempts == -1)
		options->connection_attempts = 1;
	எனில் (options->எண்_of_password_prompts == -1)
		options->எண்_of_password_prompts = 3;
	/* options->hostkeyalgorithms, default set in myproposals.h */
	எனில் (options->add_சாவிகள்_to_agent == -1) {
		options->add_சாவிகள்_to_agent = 0;
		options->add_சாவிகள்_to_agent_lifespan = 0;
	}
	எனில் (options->இலக்கம்_identity_files == 0) {
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
	எனில் (options->escape_char == -1)
		options->escape_char = '~';
	எனில் (options->இலக்கம்_system_hostfiles == 0) {
		options->system_hostfiles[options->இலக்கம்_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->இலக்கம்_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE2);
	}
	எனில் (options->update_hostkeys == -1) {
		எனில் (options->verify_host_சாவி_dns <= 0 &&
		    (options->இலக்கம்_user_hostfiles == 0 ||
		    (options->இலக்கம்_user_hostfiles == 1 && strcmp(options->
		    user_hostfiles[0], _PATH_SSH_USER_HOSTFILE) == 0)))
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_YES;
		இல்லையெனில்
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_NO;
	}
	எனில் (options->இலக்கம்_user_hostfiles == 0) {
		options->user_hostfiles[options->இலக்கம்_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->இலக்கம்_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE2);
	}
	எனில் (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	எனில் (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_USER;
	எனில் (options->no_host_authentication_for_localhost == -1)
		options->no_host_authentication_for_localhost = 0;
	எனில் (options->identities_only == -1)
		options->identities_only = 0;
	எனில் (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	எனில் (options->rekey_limit == -1)
		options->rekey_limit = 0;
	எனில் (options->rekey_interval == -1)
		options->rekey_interval = 0;
	எனில் (options->verify_host_சாவி_dns == -1)
		options->verify_host_சாவி_dns = 0;
	எனில் (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	எனில் (options->server_alive_மொத்தம்_max == -1)
		options->server_alive_மொத்தம்_max = 3;
	எனில் (options->control_master == -1)
		options->control_master = 0;
	எனில் (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	எனில் (options->hash_known_hosts == -1)
		options->hash_known_hosts = 0;
	எனில் (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	எனில் (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	எனில் (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	எனில் (options->permit_local_command == -1)
		options->permit_local_command = 0;
	எனில் (options->visual_host_சாவி == -1)
		options->visual_host_சாவி = 0;
	எனில் (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	எனில் (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	எனில் (options->request_tty == -1)
		options->request_tty = REQUEST_TTY_AUTO;
	எனில் (options->session_type == -1)
		options->session_type = SESSION_TYPE_DEFAULT;
	எனில் (options->stdin_null == -1)
		options->stdin_null = 0;
	எனில் (options->fork_after_authentication == -1)
		options->fork_after_authentication = 0;
	எனில் (options->proxy_use_fdpass == -1)
		options->proxy_use_fdpass = 0;
	எனில் (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	எனில் (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	எனில் (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
	எனில் (options->fingerprint_hash == -1)
		options->fingerprint_hash = SSH_FP_HASH_DEFAULT;
#ifdef ENABLE_SK_INTERNAL
	எனில் (options->sk_provider == வெற்று)
		options->sk_provider = xstrdup("internal");
#இல்லையெனில்
	எனில் (options->sk_provider == வெற்று)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
#endif
	எனில் (options->required_rsa_size == -1)
		options->required_rsa_size = SSH_RSA_MINIMUM_MODULUS_SIZE;
	எனில் (options->warn_weak_crypto == -1)
		options->warn_weak_crypto = 1;
	எனில் (options->enable_escape_commandline == -1)
		options->enable_escape_commandline = 0;
	எனில் (options->obscure_keystroke_timing_interval == -1) {
		options->obscure_keystroke_timing_interval =
		    SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
	}

	/* Expand KEX name lists */
	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_சாவி = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_CLIENT_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_CLIENT_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_CLIENT_KEX, all_kex);
	def_சாவி = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_சாவி);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	செய் { \
		எனில் ((r = kex_assemble_names(&options->what, \
		    defaults, all)) != 0) { \
			error_fr(r, "%s", #what); \
			செல் fail; \
		} \
	} போது (0)
	options->kex_algorithms_set = options->kex_algorithms != வெற்று;
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostbased_accepted_algos, def_சாவி, all_சாவி);
	ASSEMBLE(pubkey_accepted_algos, def_சாவி, all_சாவி);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE

#define CLEAR_ON_NONE(v) \
	செய் { \
		எனில் (option_clear_or_none(v)) { \
			விடுவி(v); \
			v = வெற்று; \
		} \
	} போது(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	செய் { \
		எனில் (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			விடுவி(options->v[0]); \
			விடுவி(options->v); \
			options->v = வெற்று; \
			options->nv = 0; \
		} \
	} போது (0)
	CLEAR_ON_NONE(options->local_command);
	CLEAR_ON_NONE(options->remote_command);
	CLEAR_ON_NONE(options->proxy_command);
	CLEAR_ON_NONE(options->control_path);
	CLEAR_ON_NONE(options->pkcs11_provider);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->known_hosts_command);
	CLEAR_ON_NONE_ARRAY(channel_timeouts, இலக்கம்_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(revoked_host_சாவிகள், இலக்கம்_revoked_host_சாவிகள், "none");
#undef CLEAR_ON_NONE
#undef CLEAR_ON_NONE_ARRAY
	எனில் (options->jump_host != வெற்று &&
	    strcmp(options->jump_host, "none") == 0 &&
	    options->jump_port == 0 && options->jump_user == வெற்று) {
		விடுவி(options->jump_host);
		options->jump_host = வெற்று;
	}
	எனில் (options->இலக்கம்_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		விடுவி(options->permitted_cnames[0].source_list);
		விடுவி(options->permitted_cnames[0].target_list);
		memset(options->permitted_cnames, '\0',
		    அளவு(*options->permitted_cnames));
		options->இலக்கம்_permitted_cnames = 0;
	}
	/* options->identity_agent distinguishes NULL from 'none' */
	/* options->user will be set in the main program if appropriate */
	/* options->hostname will be set in the main program if appropriate */
	/* options->host_key_alias should not be set by default */
	/* options->preferred_authentications will be set in ssh */

	/* success */
	ret = 0;
 fail:
	விடுவி(all_cipher);
	விடுவி(all_mac);
	விடுவி(all_kex);
	விடுவி(all_சாவி);
	விடுவி(all_sig);
	விடுவி(def_cipher);
	விடுவி(def_mac);
	விடுவி(def_kex);
	விடுவி(def_சாவி);
	விடுவி(def_sig);
	திரும்பு ret;
}

வெறுமை
free_options(Options *o)
{
	முழு i;

	எனில் (o == வெற்று)
		திரும்பு;

#define FREE_ARRAY(type, n, a) \
	செய் { \
		type _i; \
		க்கு (_i = 0; _i < (n); _i++) \
			விடுவி((a)[_i]); \
	} போது (0)

	விடுவி(o->forward_agent_sock_path);
	விடுவி(o->xauth_location);
	FREE_ARRAY(u_int, o->இலக்கம்_log_verbose, o->log_verbose);
	விடுவி(o->log_verbose);
	விடுவி(o->ciphers);
	விடுவி(o->macs);
	விடுவி(o->hostkeyalgorithms);
	விடுவி(o->kex_algorithms);
	விடுவி(o->ca_sign_algorithms);
	விடுவி(o->hostname);
	விடுவி(o->host_சாவி_alias);
	விடுவி(o->proxy_command);
	விடுவி(o->user);
	FREE_ARRAY(u_int, o->இலக்கம்_system_hostfiles, o->system_hostfiles);
	FREE_ARRAY(u_int, o->இலக்கம்_user_hostfiles, o->user_hostfiles);
	விடுவி(o->preferred_authentications);
	விடுவி(o->bind_address);
	விடுவி(o->bind_interface);
	விடுவி(o->pkcs11_provider);
	விடுவி(o->sk_provider);
	க்கு (i = 0; i < o->இலக்கம்_identity_files; i++) {
		விடுவி(o->identity_files[i]);
		sshkey_free(o->identity_சாவிகள்[i]);
	}
	க்கு (i = 0; i < o->இலக்கம்_certificate_files; i++) {
		விடுவி(o->certificate_files[i]);
		sshkey_free(o->certificates[i]);
	}
	விடுவி(o->identity_agent);
	க்கு (i = 0; i < o->இலக்கம்_local_forwards; i++) {
		விடுவி(o->local_forwards[i].listen_host);
		விடுவி(o->local_forwards[i].listen_path);
		விடுவி(o->local_forwards[i].connect_host);
		விடுவி(o->local_forwards[i].connect_path);
	}
	விடுவி(o->local_forwards);
	க்கு (i = 0; i < o->இலக்கம்_remote_forwards; i++) {
		விடுவி(o->remote_forwards[i].listen_host);
		விடுவி(o->remote_forwards[i].listen_path);
		விடுவி(o->remote_forwards[i].connect_host);
		விடுவி(o->remote_forwards[i].connect_path);
	}
	விடுவி(o->remote_forwards);
	விடுவி(o->stdio_forward_host);
	FREE_ARRAY(u_int, o->இலக்கம்_send_env, o->send_env);
	விடுவி(o->send_env);
	FREE_ARRAY(u_int, o->இலக்கம்_setenv, o->setenv);
	விடுவி(o->setenv);
	விடுவி(o->control_path);
	விடுவி(o->local_command);
	விடுவி(o->remote_command);
	FREE_ARRAY(முழு, o->இலக்கம்_canonical_domains, o->canonical_domains);
	க்கு (i = 0; i < o->இலக்கம்_permitted_cnames; i++) {
		விடுவி(o->permitted_cnames[i].source_list);
		விடுவி(o->permitted_cnames[i].target_list);
	}
	FREE_ARRAY(u_int, o->இலக்கம்_revoked_host_சாவிகள், o->revoked_host_சாவிகள்);
	விடுவி(o->revoked_host_சாவிகள்);
	விடுவி(o->hostbased_accepted_algos);
	விடுவி(o->pubkey_accepted_algos);
	விடுவி(o->jump_user);
	விடுவி(o->jump_host);
	விடுவி(o->jump_extra);
	விடுவி(o->ignored_unknown);
	explicit_bzero(o, அளவு(*o));
#undef FREE_ARRAY
}

கட்டமைப்பு fwdarg {
	எழுத்து *arg;
	முழு ispath;
};

/*
 * parse_fwd_field
 * parses the next field in a port forwarding specification.
 * sets fwd to the parsed field and advances p past the colon
 * or sets it to NULL at end of string.
 * returns 0 on success, else non-zero.
 */
நிலையான முழு
parse_fwd_field(எழுத்து **p, கட்டமைப்பு fwdarg *fwd)
{
	எழுத்து *ep, *cp = *p;
	முழு ispath = 0;

	எனில் (*cp == '\0') {
		*p = வெற்று;
		திரும்பு -1;	/* end of string */
	}

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	எனில் (*cp == '[') {
		/* find matching ']' */
		க்கு (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++) {
			எனில் (*ep == '/')
				ispath = 1;
		}
		/* no matching ']' or not at end of field. */
		எனில் (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			திரும்பு -1;
		/* NUL terminate the field and advance p past the colon */
		*ep++ = '\0';
		எனில் (*ep != '\0')
			*ep++ = '\0';
		fwd->arg = cp + 1;
		fwd->ispath = ispath;
		*p = ep;
		திரும்பு 0;
	}

	க்கு (cp = *p; *cp != '\0'; cp++) {
		தேர்வு (*cp) {
		நிலை '\\':
			memmove(cp, cp + 1, strlen(cp + 1) + 1);
			எனில் (*cp == '\0')
				திரும்பு -1;
			நிறுத்து;
		நிலை '/':
			ispath = 1;
			நிறுத்து;
		நிலை ':':
			*cp++ = '\0';
			செல் done;
		}
	}
done:
	fwd->arg = *p;
	fwd->ispath = ispath;
	*p = cp;
	திரும்பு 0;
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
முழு
parse_forward(கட்டமைப்பு Forward *fwd, மாறிலி எழுத்து *fwdspec, முழு dynamicfwd, முழு remotefwd)
{
	கட்டமைப்பு fwdarg fwdargs[4];
	எழுத்து *p, *cp;
	முழு i, err;

	memset(fwd, 0, அளவு(*fwd));
	memset(fwdargs, 0, அளவு(fwdargs));

	/*
	 * We expand environment variables before checking if we think they're
	 * paths so that if ${VAR} expands to a fully qualified path it is
	 * treated as a path.
	 */
	cp = p = dollar_expand(&err, fwdspec);
	எனில் (p == வெற்று || err)
		திரும்பு 0;

	/* skip leading spaces */
	போது (isspace((u_char)*cp))
		cp++;

	க்கு (i = 0; i < 4; ++i) {
		எனில் (parse_fwd_field(&cp, &fwdargs[i]) != 0)
			நிறுத்து;
	}

	/* Check for trailing garbage */
	எனில் (cp != வெற்று && *cp != '\0') {
		i = 0;	/* failure */
	}

	தேர்வு (i) {
	நிலை 1:
		எனில் (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
		} இல்லையெனில் {
			fwd->listen_host = வெற்று;
			fwd->listen_port = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		நிறுத்து;

	நிலை 2:
		எனில் (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} இல்லையெனில் எனில் (fwdargs[1].ispath) {
			fwd->listen_host = வெற்று;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} இல்லையெனில் {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		நிறுத்து;

	நிலை 3:
		எனில் (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		} இல்லையெனில் எனில் (fwdargs[2].ispath) {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_path = xstrdup(fwdargs[2].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} இல்லையெனில் {
			fwd->listen_host = வெற்று;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		}
		நிறுத்து;

	நிலை 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_port = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_port = a2port(fwdargs[3].arg);
		நிறுத்து;
	இயல்பு:
		i = 0; /* failure */
	}

	விடுவி(p);

	எனில் (dynamicfwd) {
		எனில் (!(i == 1 || i == 2))
			செல் fail_free;
	} இல்லையெனில் {
		எனில் (!(i == 3 || i == 4)) {
			எனில் (fwd->connect_path == வெற்று &&
			    fwd->listen_path == வெற்று)
				செல் fail_free;
		}
		எனில் (fwd->connect_port <= 0 && fwd->connect_path == வெற்று)
			செல் fail_free;
	}

	எனில் ((fwd->listen_port < 0 && fwd->listen_path == வெற்று) ||
	    (!remotefwd && fwd->listen_port == 0))
		செல் fail_free;
	எனில் (fwd->connect_host != வெற்று &&
	    strlen(fwd->connect_host) >= NI_MAXHOST)
		செல் fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	எனில் (fwd->connect_path != வெற்று &&
	    strlen(fwd->connect_path) >= PATH_MAX_SUN)
		செல் fail_free;
	எனில் (fwd->listen_host != வெற்று &&
	    strlen(fwd->listen_host) >= NI_MAXHOST)
		செல் fail_free;
	எனில் (fwd->listen_path != வெற்று &&
	    strlen(fwd->listen_path) >= PATH_MAX_SUN)
		செல் fail_free;

	திரும்பு (i);

 fail_free:
	விடுவி(fwd->connect_host);
	fwd->connect_host = வெற்று;
	விடுவி(fwd->connect_path);
	fwd->connect_path = வெற்று;
	விடுவி(fwd->listen_host);
	fwd->listen_host = வெற்று;
	விடுவி(fwd->listen_path);
	fwd->listen_path = வெற்று;
	திரும்பு (0);
}

முழு
ssh_valid_hostname(மாறிலி எழுத்து *s)
{
	size_t i;

	எனில் (*s == '-')
		திரும்பு 0;
	க்கு (i = 0; s[i] != 0; i++) {
		எனில் (strchr("'`\"$\\;&<>|(){},", s[i]) != வெற்று ||
		    isspace((u_char)s[i]) || iscntrl((u_char)s[i]))
			திரும்பு 0;
	}
	திரும்பு 1;
}

முழு
ssh_valid_ruser(மாறிலி எழுத்து *s)
{
	size_t i;

	எனில் (*s == '-')
		திரும்பு 0;
	க்கு (i = 0; s[i] != 0; i++) {
		எனில் (iscntrl((u_char)s[i]))
			திரும்பு 0;
		எனில் (strchr("'`\";&<>|(){}$\\", s[i]) != வெற்று)
			திரும்பு 0;
		/* Disallow '-' after whitespace */
		எனில் (isspace((u_char)s[i]) && s[i + 1] == '-')
			திரும்பு 0;
	}
	திரும்பு 1;
}

முழு
parse_jump(மாறிலி எழுத்து *s, Options *o, முழு strict, முழு active)
{
	எழுத்து *orig = வெற்று, *sdup = வெற்று, *cp;
	எழுத்து *tmp_user = வெற்று, *tmp_host = வெற்று, *host = வெற்று, *user = வெற்று;
	முழு r, ret = -1, tmp_port = -1, port = -1, first = 1;

	எனில் (strcasecmp(s, "none") == 0) {
		எனில் (active && o->jump_host == வெற்று) {
			o->jump_host = xstrdup("none");
			o->jump_port = 0;
		}
		திரும்பு 0;
	}

	orig = xstrdup(s);
	எனில் ((cp = strchr(orig, '#')) != வெற்று)
		*cp = '\0';
	rtrim(orig);

	active &= o->proxy_command == வெற்று && o->jump_host == வெற்று;
	sdup = xstrdup(orig);
	செய் {
		/* Work backwards through string */
		எனில் ((cp = strrchr(sdup, ',')) == வெற்று)
			cp = sdup; /* last */
		இல்லையெனில்
			*cp++ = '\0';

		r = parse_ssh_uri(cp, &tmp_user, &tmp_host, &tmp_port);
		எனில் (r == -1 || (r == 1 && parse_user_host_port(cp,
		    &tmp_user, &tmp_host, &tmp_port) != 0))
			செல் out; /* error already logged */
		எனில் (strict) {
			எனில் (!ssh_valid_hostname(tmp_host)) {
				error_f("invalid hostname \"%s\"", tmp_host);
				செல் out;
			}
			எனில் (tmp_user != வெற்று && !ssh_valid_ruser(tmp_user)) {
				error_f("invalid username \"%s\"", tmp_user);
				செல் out;
			}
		}
		எனில் (first) {
			user = tmp_user;
			host = tmp_host;
			port = tmp_port;
			tmp_user = tmp_host = வெற்று; /* transferred */
		}
		first = 0; /* only check syntax for subsequent hosts */
		விடுவி(tmp_user);
		விடுவி(tmp_host);
		tmp_user = tmp_host = வெற்று;
		tmp_port = -1;
	} போது (cp != sdup);

	/* success */
	எனில் (active) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_port = port;
		o->proxy_command = xstrdup("none");
		user = host = வெற்று; /* transferred */
		எனில் (orig != வெற்று && (cp = strrchr(orig, ',')) != வெற்று) {
			o->jump_extra = xstrdup(orig);
			o->jump_extra[cp - orig] = '\0';
		}
	}
	ret = 0;
 out:
	விடுவி(orig);
	விடுவி(sdup);
	விடுவி(tmp_user);
	விடுவி(tmp_host);
	விடுவி(user);
	விடுவி(host);
	திரும்பு ret;
}

முழு
parse_ssh_uri(மாறிலி எழுத்து *uri, எழுத்து **userp, எழுத்து **hostp, முழு *portp)
{
	எழுத்து *user = வெற்று, *host = வெற்று, *path = வெற்று;
	முழு r, port;

	r = parse_uri("ssh", uri, &user, &host, &port, &path);
	எனில் (r == 0 && path != வெற்று)
		r = -1;		/* path not allowed */
	எனில் (r == 0) {
		எனில் (userp != வெற்று) {
			*userp = user;
			user = வெற்று;
		}
		எனில் (hostp != வெற்று) {
			*hostp = host;
			host = வெற்று;
		}
		எனில் (portp != வெற்று)
			*portp = port;
	}
	விடுவி(user);
	விடுவி(host);
	விடுவி(path);
	திரும்பு r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
நிலையான மாறிலி எழுத்து *
fmt_multistate_int(முழு val, மாறிலி கட்டமைப்பு multistate *m)
{
	u_int i;

	க்கு (i = 0; m[i].சாவி != வெற்று; i++) {
		எனில் (m[i].மதிப்பு == val)
			திரும்பு m[i].சாவி;
	}
	திரும்பு "UNKNOWN";
}

நிலையான மாறிலி எழுத்து *
fmt_intarg(OpCodes code, முழு val)
{
	எனில் (val == -1)
		திரும்பு "unset";
	தேர்வு (code) {
	நிலை oAddressFamily:
		திரும்பு fmt_multistate_int(val, multistate_addressfamily);
	நிலை oCompression:
		திரும்பு fmt_multistate_int(val, multistate_compression);
	நிலை o_Verify_Host_சாவி_DNS:
	நிலை oUpdateHostkeys:
		திரும்பு fmt_multistate_int(val, multistate_yesnoask);
	நிலை o_Strict_Host_சாவி_Checking:
		திரும்பு fmt_multistate_int(val, multistate_strict_hostkey);
	நிலை oControlMaster:
		திரும்பு fmt_multistate_int(val, multistate_controlmaster);
	நிலை oTunnel:
		திரும்பு fmt_multistate_int(val, multistate_tunnel);
	நிலை oRequestTTY:
		திரும்பு fmt_multistate_int(val, multistate_requesttty);
	நிலை oSessionType:
		திரும்பு fmt_multistate_int(val, multistate_sessiontype);
	நிலை oCanonicalizeHostname:
		திரும்பு fmt_multistate_int(val, multistate_canonicalizehostname);
	நிலை o_Add_சாவிகள்_To_Agent:
		திரும்பு fmt_multistate_int(val, multistate_yesnoaskconfirm);
	நிலை oPubkeyAuthentication:
		திரும்பு fmt_multistate_int(val, multistate_pubkey_auth);
	நிலை oTCPKeepAlive:
		திரும்பு fmt_multistate_int(val, multistate_keepalives);
	நிலை oFingerprintHash:
		திரும்பு ssh_digest_alg_name(val);
	இயல்பு:
		தேர்வு (val) {
		நிலை 0:
			திரும்பு "no";
		நிலை 1:
			திரும்பு "yes";
		இயல்பு:
			திரும்பு "UNKNOWN";
		}
	}
}

நிலையான மாறிலி எழுத்து *
lookup_opcode_name(OpCodes code)
{
	u_int i;

	க்கு (i = 0; keywords[i].name != வெற்று; i++)
		எனில் (keywords[i].opcode == code)
			திரும்பு(keywords[i].name);
	திரும்பு "UNKNOWN";
}

நிலையான வெறுமை
dump_cfg_int(OpCodes code, முழு val)
{
	எனில் (code == oObscureKeystrokeTiming) {
		எனில் (val == 0) {
			printf("%s no\n", lookup_opcode_name(code));
			திரும்பு;
		} இல்லையெனில் எனில் (val == SSH_KEYSTROKE_DEFAULT_INTERVAL_MS) {
			printf("%s yes\n", lookup_opcode_name(code));
			திரும்பு;
		}
		/* FALLTHROUGH */
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

நிலையான வெறுமை
dump_cfg_fmtint(OpCodes code, முழு val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

நிலையான வெறுமை
dump_cfg_string(OpCodes code, மாறிலி எழுத்து *val)
{
	எனில் (val == வெற்று)
		திரும்பு;
	printf("%s %s\n", lookup_opcode_name(code), val);
}

நிலையான வெறுமை
dump_cfg_strarray(OpCodes code, u_int மொத்தம், எழுத்து **vals)
{
	u_int i;

	க்கு (i = 0; i < மொத்தம்; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

நிலையான வெறுமை
dump_cfg_strarray_oneline(OpCodes code, u_int மொத்தம், எழுத்து **vals)
{
	u_int i;

	printf("%s", lookup_opcode_name(code));
	எனில் (மொத்தம் == 0)
		printf(" none");
	க்கு (i = 0; i < மொத்தம்; i++)
		printf(" %s",  vals[i]);
	printf("\n");
}

நிலையான வெறுமை
dump_cfg_forwards(OpCodes code, u_int மொத்தம், மாறிலி கட்டமைப்பு Forward *fwds)
{
	மாறிலி கட்டமைப்பு Forward *fwd;
	u_int i;

	/* oDynamicForward */
	க்கு (i = 0; i < மொத்தம்; i++) {
		fwd = &fwds[i];
		எனில் (code == oDynamicForward && fwd->connect_host != வெற்று &&
		    strcmp(fwd->connect_host, "socks") != 0)
			தொடர்;
		எனில் (code == oLocalForward && fwd->connect_host != வெற்று &&
		    strcmp(fwd->connect_host, "socks") == 0)
			தொடர்;
		printf("%s", lookup_opcode_name(code));
		எனில் (fwd->listen_port == PORT_STREAMLOCAL)
			printf(" %s", fwd->listen_path);
		இல்லையெனில் எனில் (fwd->listen_host == வெற்று)
			printf(" %d", fwd->listen_port);
		இல்லையெனில் {
			printf(" [%s]:%d",
			    fwd->listen_host, fwd->listen_port);
		}
		எனில் (code != oDynamicForward) {
			எனில் (fwd->connect_port == PORT_STREAMLOCAL)
				printf(" %s", fwd->connect_path);
			இல்லையெனில் எனில் (fwd->connect_host == வெற்று)
				printf(" %d", fwd->connect_port);
			இல்லையெனில் {
				printf(" [%s]:%d",
				    fwd->connect_host, fwd->connect_port);
			}
		}
		printf("\n");
	}
}

வெறுமை
dump_client_config(Options *o, மாறிலி எழுத்து *host)
{
	முழு i, r;
	எழுத்து buf[8], *all_சாவி;

	/*
	 * Expand HostKeyAlgorithms name lists. This isn't handled in
	 * fill_default_options() like the other algorithm lists because
	 * the host key algorithms are by default dynamically chosen based
	 * on the host's keys found in known_hosts.
	 */
	all_சாவி = sshkey_alg_list(0, 0, 1, ',');
	எனில் ((r = kex_assemble_names(&o->hostkeyalgorithms, kex_default_pk_alg(),
	    all_சாவி)) != 0)
		fatal_fr(r, "expand HostKeyAlgorithms");
	விடுவி(all_சாவி);

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
	dump_cfg_fmtint(o_Strict_Host_சாவி_Checking, o->strict_host_சாவி_checking);
	dump_cfg_fmtint(oTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(oTunnel, o->tun_open);
	dump_cfg_fmtint(o_Verify_Host_சாவி_DNS, o->verify_host_சாவி_dns);
	dump_cfg_fmtint(o_Visual_Host_சாவி, o->visual_host_சாவி);
	dump_cfg_fmtint(oUpdateHostkeys, o->update_hostkeys);
	dump_cfg_fmtint(oEnableEscapeCommandline, o->enable_escape_commandline);
	dump_cfg_fmtint(oWarnWeakCrypto, o->warn_weak_crypto);

	/* Integer options */
	dump_cfg_int(oCanonicalizeMaxDots, o->canonicalize_max_dots);
	dump_cfg_int(oConnectionAttempts, o->connection_attempts);
	dump_cfg_int(oForwardX11Timeout, o->forward_x11_timeout);
	dump_cfg_int(o_எண்_Of_Password_Prompts, o->எண்_of_password_prompts);
	dump_cfg_int(o_Server_Alive_மொத்தம்_Max, o->server_alive_மொத்தம்_max);
	dump_cfg_int(oServerAliveInterval, o->server_alive_interval);
	dump_cfg_int(oRequiredRSASize, o->required_rsa_size);
	dump_cfg_int(oObscureKeystrokeTiming,
	    o->obscure_keystroke_timing_interval);

	/* String options */
	dump_cfg_string(oBindAddress, o->bind_address);
	dump_cfg_string(oBindInterface, o->bind_interface);
	dump_cfg_string(oCiphers, o->ciphers);
	dump_cfg_string(oControlPath, o->control_path);
	dump_cfg_string(o_Host_சாவி_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(o_Host_சாவி_Alias, o->host_சாவி_alias);
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
	dump_cfg_string(o_Security_சாவி_Provider, o->sk_provider);
	dump_cfg_string(oPreferredAuthentications, o->preferred_authentications);
	dump_cfg_string(oPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
	dump_cfg_string(oXAuthLocation, o->xauth_location);
	dump_cfg_string(oKnownHostsCommand, o->known_hosts_command);
	dump_cfg_string(oTag, o->tag);
	dump_cfg_string(oVersionAddendum, o->version_addendum);

	/* Forwards */
	dump_cfg_forwards(oDynamicForward, o->இலக்கம்_local_forwards, o->local_forwards);
	dump_cfg_forwards(oLocalForward, o->இலக்கம்_local_forwards, o->local_forwards);
	dump_cfg_forwards(oRemoteForward, o->இலக்கம்_remote_forwards, o->remote_forwards);

	/* String array options */
	dump_cfg_strarray(oIdentityFile, o->இலக்கம்_identity_files, o->identity_files);
	dump_cfg_strarray_oneline(oCanonicalDomains, o->இலக்கம்_canonical_domains, o->canonical_domains);
	dump_cfg_strarray(oCertificateFile, o->இலக்கம்_certificate_files, o->certificate_files);
	dump_cfg_strarray_oneline(oGlobalKnownHostsFile, o->இலக்கம்_system_hostfiles, o->system_hostfiles);
	dump_cfg_strarray_oneline(oUserKnownHostsFile, o->இலக்கம்_user_hostfiles, o->user_hostfiles);
	dump_cfg_strarray_oneline(o_Revoked_Host_சாவிகள், o->இலக்கம்_revoked_host_சாவிகள், o->revoked_host_சாவிகள்);
	dump_cfg_strarray(oSendEnv, o->இலக்கம்_send_env, o->send_env);
	dump_cfg_strarray(oSetEnv, o->இலக்கம்_setenv, o->setenv);
	dump_cfg_strarray_oneline(oLogVerbose,
	    o->இலக்கம்_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(oChannelTimeout,
	    o->இலக்கம்_channel_timeouts, o->channel_timeouts);

	/* Special cases */

	/* PermitRemoteOpen */
	எனில் (o->இலக்கம்_permitted_remote_opens == 0)
		printf("%s any\n", lookup_opcode_name(oPermitRemoteOpen));
	இல்லையெனில்
		dump_cfg_strarray_oneline(oPermitRemoteOpen,
		    o->இலக்கம்_permitted_remote_opens, o->permitted_remote_opens);

	/* AddKeysToAgent */
	எனில் (o->add_சாவிகள்_to_agent_lifespan <= 0)
		dump_cfg_fmtint(o_Add_சாவிகள்_To_Agent, o->add_சாவிகள்_to_agent);
	இல்லையெனில் {
		printf("addkeystoagent%s %d\n",
		    o->add_சாவிகள்_to_agent == 3 ? " confirm" : "",
		    o->add_சாவிகள்_to_agent_lifespan);
	}

	/* oForwardAgent */
	எனில் (o->forward_agent_sock_path == வெற்று)
		dump_cfg_fmtint(oForwardAgent, o->forward_agent);
	இல்லையெனில்
		dump_cfg_string(oForwardAgent, o->forward_agent_sock_path);

	/* oConnectTimeout */
	எனில் (o->connection_timeout == -1)
		printf("connecttimeout none\n");
	இல்லையெனில்
		dump_cfg_int(oConnectTimeout, o->connection_timeout);

	/* oTunnelDevice */
	printf("tunneldevice");
	எனில் (o->tun_local == SSH_TUNID_ANY)
		printf(" any");
	இல்லையெனில்
		printf(" %d", o->tun_local);
	எனில் (o->tun_remote == SSH_TUNID_ANY)
		printf(":any");
	இல்லையெனில்
		printf(":%d", o->tun_remote);
	printf("\n");

	/* oCanonicalizePermittedCNAMEs */
	printf("canonicalizepermittedcnames");
	எனில் (o->இலக்கம்_permitted_cnames == 0)
		printf(" none");
	க்கு (i = 0; i < o->இலக்கம்_permitted_cnames; i++) {
		printf(" %s:%s", o->permitted_cnames[i].source_list,
		    o->permitted_cnames[i].target_list);
	}
	printf("\n");

	/* oControlPersist */
	எனில் (o->control_persist == 0 || o->control_persist_timeout == 0)
		dump_cfg_fmtint(oControlPersist, o->control_persist);
	இல்லையெனில்
		dump_cfg_int(oControlPersist, o->control_persist_timeout);

	/* oEscapeChar */
	எனில் (o->escape_char == SSH_ESCAPECHAR_NONE)
		printf("escapechar none\n");
	இல்லையெனில் {
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
	எனில் (o->jump_host == வெற்று)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	இல்லையெனில் {
		/* Check for numeric addresses */
		i = strchr(o->jump_host, ':') != வெற்று ||
		    strspn(o->jump_host, "1234567890.") == strlen(o->jump_host);
		snprintf(buf, அளவு(buf), "%d", o->jump_port);
		printf("proxyjump %s%s%s%s%s%s%s%s%s\n",
		    /* optional additional jump spec */
		    o->jump_extra == வெற்று ? "" : o->jump_extra,
		    o->jump_extra == வெற்று ? "" : ",",
		    /* optional user */
		    o->jump_user == வெற்று ? "" : o->jump_user,
		    o->jump_user == வெற்று ? "" : "@",
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
