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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/stat.h>
#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/wait.h>
#अन्तर्भाव <sys/un.h>

#अन्तर्भाव <net/if.h>
#अन्तर्भाव <netinet/in.h>
#अन्तर्भाव <netinet/ip.h>
#अन्तर्भाव <arpa/inet.h>

#अन्तर्भाव <ctype.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <glob.h>
#अन्तर्भाव <ifaddrs.h>
#अन्तर्भाव <limits.h>
#अन्तर्भाव <netdb.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <util.h>
#जइ defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#endif

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "cipher.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "readconf.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "kex.h"
#अन्तर्भाव "mac.h"
#अन्तर्भाव "myproposal.h"
#अन्तर्भाव "digest.h"
#अन्तर्भाव "version.h"

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

स्थिर पूर्णाङ्क read_config_file_depth(ध्रुव वर्ण *filename, संरचना passwd *pw,
    ध्रुव वर्ण *host, ध्रुव वर्ण *original_host, ध्रुव वर्ण *remote_command,
    Options *options, पूर्णाङ्क flags, पूर्णाङ्क *activep, पूर्णाङ्क *want_final_pass, पूर्णाङ्क depth);
स्थिर पूर्णाङ्क process_config_पङ्क्तिः_depth(Options *options, संरचना passwd *pw,
    ध्रुव वर्ण *host, ध्रुव वर्ण *original_host, ध्रुव वर्ण *remote_command,
    वर्ण *पङ्क्तिः, ध्रुव वर्ण *filename, पूर्णाङ्क linenum, पूर्णाङ्क *activep, पूर्णाङ्क flags,
    पूर्णाङ्क *want_final_pass, पूर्णाङ्क depth);

/* Keyword tokens. */

प्रकारनिर्देश गणना {
	oBadOption,
	oHost, oMatch, oInclude, oTag,
	oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout,
	oGatewayPorts, oExitOnForwardFailure,
	oPasswordAuthentication,
	oXAuthLocation,
	oIdentityFile, oHostname, oPort, oRemoteForward, oLocalForward,
	oPermitRemoteOpen,
	oCertificateFile, o_Add_कुञ्चिकाः_To_Agent, oIdentityAgent,
	oUser, oEscapeChar, oProxyCommand,
	oGlobalKnownHostsFile, oUserKnownHostsFile, oConnectionAttempts,
	oBatchMode, oCheckHostIP, o_Strict_Host_कुञ्चिका_Checking, oCompression,
	oTCPKeepAlive, o_सङ्ख्या_Of_Password_Prompts,
	oLogFacility, oLogLevel, oLogVerbose, oCiphers, oMacs,
	oPubkeyAuthentication,
	oKbdInteractiveAuthentication, oKbdInteractiveDevices, o_Host_कुञ्चिका_Alias,
	oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication,
	o_Host_कुञ्चिका_Algorithms, oBindAddress, oBindInterface, oPKCS11Provider,
	oClearAllForwardings, oNoHostAuthenticationForLocalhost,
	oEnableSSHKeysign, oRekeyLimit, o_Verify_Host_कुञ्चिका_DNS, oConnectTimeout,
	oAddressFamily, oGssAuthentication, oGssDelegateCreds,
	oServerAliveInterval, o_Server_Alive_गणनम्_Max, oIdentitiesOnly,
	oSendEnv, oSetEnv, oControlPath, oControlMaster, oControlPersist,
	oHashKnownHosts,
	oTunnel, oTunnelDevice,
	oLocalCommand, oPermitLocalCommand, oRemoteCommand,
	o_Visual_Host_कुञ्चिका,
	oKexAlgorithms, oIPQoS, oRequestTTY, oSessionType, oStdinNull,
	oForkAfterAuthentication, oIgnoreUnknown, oProxyUseFdpass,
	oCanonicalDomains, oCanonicalizeHostname, oCanonicalizeMaxDots,
	oCanonicalizeFallbackLocal, oCanonicalizePermittedCNAMEs,
	oStreamLocalBindMask, oStreamLocalBindUnlink, o_Revoked_Host_कुञ्चिकाः,
	oFingerprintHash, oUpdateHostkeys, oHostbasedAcceptedAlgorithms,
	oPubkeyAcceptedAlgorithms, oCASignatureAlgorithms, oProxyJump,
	o_Security_कुञ्चिका_Provider, oKnownHostsCommand, oRequiredRSASize,
	oEnableEscapeCommandline, oObscureKeystrokeTiming, oChannelTimeout,
	oVersionAddendum, oRefuseConnection, oWarnWeakCrypto,
	oIgnore, oIgnoredUnknownOption, oDeprecated, oUnsupported
} OpCodes;

/* Textual representations of the tokens. */

स्थिर संरचना {
	ध्रुव वर्ण *name;
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
#जइ defined(GSSAPI)
	{ "gssapiauthentication", oGssAuthentication },
	{ "gssapidelegatecredentials", oGssDelegateCreds },
# अण्णहा
	{ "gssapiauthentication", oUnsupported },
	{ "gssapidelegatecredentials", oUnsupported },
#endif
#ifdef ENABLE_PKCS11
	{ "pkcs11provider", oPKCS11Provider },
	{ "smartcarddevice", oPKCS11Provider },
# अण्णहा
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
	{ "addkeystoagent", o_Add_कुञ्चिकाः_To_Agent },
	{ "identityagent", oIdentityAgent },
	{ "hostname", oHostname },
	{ "hostkeyalias", o_Host_कुञ्चिका_Alias },
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
	{ "stricthostkeychecking", o_Strict_Host_कुञ्चिका_Checking },
	{ "compression", oCompression },
	{ "tcpkeepalive", oTCPKeepAlive },
	{ "keepalive", oTCPKeepAlive },				/* obsolete */
	{ "numberofpasswordprompts", o_सङ्ख्या_Of_Password_Prompts },
	{ "syslogfacility", oLogFacility },
	{ "loglevel", oLogLevel },
	{ "logverbose", oLogVerbose },
	{ "dynamicforward", oDynamicForward },
	{ "preferredauthentications", oPreferredAuthentications },
	{ "hostkeyalgorithms", o_Host_कुञ्चिका_Algorithms },
	{ "casignaturealgorithms", oCASignatureAlgorithms },
	{ "bindaddress", oBindAddress },
	{ "bindinterface", oBindInterface },
	{ "clearallforwardings", oClearAllForwardings },
	{ "enablesshkeysign", oEnableSSHKeysign },
	{ "verifyhostkeydns", o_Verify_Host_कुञ्चिका_DNS },
	{ "nohostauthenticationforlocalhost", oNoHostAuthenticationForLocalhost },
	{ "rekeylimit", oRekeyLimit },
	{ "connecttimeout", oConnectTimeout },
	{ "addressfamily", oAddressFamily },
	{ "serveraliveinterval", oServerAliveInterval },
	{ "serveralivecountmax", o_Server_Alive_गणनम्_Max },
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
	{ "visualhostkey", o_Visual_Host_कुञ्चिका },
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
	{ "revokedhostkeys", o_Revoked_Host_कुञ्चिकाः },
	{ "fingerprinthash", oFingerprintHash },
	{ "updatehostkeys", oUpdateHostkeys },
	{ "hostbasedacceptedalgorithms", oHostbasedAcceptedAlgorithms },
	{ "hostbasedkeytypes", oHostbasedAcceptedAlgorithms }, /* obsolete */
	{ "pubkeyacceptedalgorithms", oPubkeyAcceptedAlgorithms },
	{ "pubkeyacceptedkeytypes", oPubkeyAcceptedAlgorithms }, /* obsolete */
	{ "ignoreunknown", oIgnoreUnknown },
	{ "proxyjump", oProxyJump },
	{ "securitykeyprovider", o_Security_कुञ्चिका_Provider },
	{ "knownhostscommand", oKnownHostsCommand },
	{ "requiredrsasize", oRequiredRSASize },
	{ "enableescapecommandline", oEnableEscapeCommandline },
	{ "obscurekeystroketiming", oObscureKeystrokeTiming },
	{ "channeltimeout", oChannelTimeout },
	{ "versionaddendum", oVersionAddendum },
	{ "refuseconnection", oRefuseConnection },
	{ "warnweakcrypto", oWarnWeakCrypto },

	{ रिक्त, oBadOption }
};

स्थिर ध्रुव वर्ण *lookup_opcode_name(OpCodes code);

ध्रुव वर्ण *
kex_default_pk_alg(शून्य)
{
	स्थिर वर्ण *pkalgs;

	जइ (pkalgs == रिक्त) {
		वर्ण *all_कुञ्चिका;

		all_कुञ्चिका = sshkey_alg_list(0, 0, 1, ',');
		pkalgs = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_कुञ्चिका);
		मुक्त(all_कुञ्चिका);
	}
	प्रत्यागम pkalgs;
}

वर्ण *
ssh_connection_hash(ध्रुव वर्ण *thishost, ध्रुव वर्ण *host, ध्रुव वर्ण *portstr,
    ध्रुव वर्ण *user, ध्रुव वर्ण *jumphost)
{
	संरचना ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_LENGTH];

	जइ ((md = ssh_digest_start(SSH_DIGEST_SHA1)) == रिक्त ||
	    ssh_digest_update(md, thishost, strlen(thishost)) < 0 ||
	    ssh_digest_update(md, host, strlen(host)) < 0 ||
	    ssh_digest_update(md, portstr, strlen(portstr)) < 0 ||
	    ssh_digest_update(md, user, strlen(user)) < 0 ||
	    ssh_digest_update(md, jumphost, strlen(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, परिमाण(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	प्रत्यागम tohex(conn_hash, ssh_digest_bytes(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

शून्य
add_local_forward(Options *options, ध्रुव संरचना Forward *newfwd)
{
	संरचना Forward *fwd;
	पूर्णाङ्क i;

	/* Don't add duplicates */
	प्रति (i = 0; i < options->अङ्कः_local_forwards; i++) {
		जइ (forward_equals(newfwd, options->local_forwards + i))
			प्रत्यागम;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->अङ्कः_local_forwards + 1,
	    परिमाण(*options->local_forwards));
	fwd = &options->local_forwards[options->अङ्कः_local_forwards++];

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

शून्य
add_remote_forward(Options *options, ध्रुव संरचना Forward *newfwd)
{
	संरचना Forward *fwd;
	पूर्णाङ्क i;

	/* Don't add duplicates */
	प्रति (i = 0; i < options->अङ्कः_remote_forwards; i++) {
		जइ (forward_equals(newfwd, options->remote_forwards + i))
			प्रत्यागम;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->अङ्कः_remote_forwards + 1,
	    परिमाण(*options->remote_forwards));
	fwd = &options->remote_forwards[options->अङ्कः_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_port = newfwd->listen_port;
	fwd->listen_path = newfwd->listen_path;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_port = newfwd->connect_port;
	fwd->connect_path = newfwd->connect_path;
	fwd->handle = newfwd->handle;
	fwd->allocated_port = 0;
}

स्थिर शून्य
clear_forwardings(Options *options)
{
	पूर्णाङ्क i;

	प्रति (i = 0; i < options->अङ्कः_local_forwards; i++) {
		मुक्त(options->local_forwards[i].listen_host);
		मुक्त(options->local_forwards[i].listen_path);
		मुक्त(options->local_forwards[i].connect_host);
		मुक्त(options->local_forwards[i].connect_path);
	}
	जइ (options->अङ्कः_local_forwards > 0) {
		मुक्त(options->local_forwards);
		options->local_forwards = रिक्त;
	}
	options->अङ्कः_local_forwards = 0;
	प्रति (i = 0; i < options->अङ्कः_remote_forwards; i++) {
		मुक्त(options->remote_forwards[i].listen_host);
		मुक्त(options->remote_forwards[i].listen_path);
		मुक्त(options->remote_forwards[i].connect_host);
		मुक्त(options->remote_forwards[i].connect_path);
	}
	जइ (options->अङ्कः_remote_forwards > 0) {
		मुक्त(options->remote_forwards);
		options->remote_forwards = रिक्त;
	}
	options->अङ्कः_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

शून्य
add_certificate_file(Options *options, ध्रुव वर्ण *path, पूर्णाङ्क userprovided)
{
	पूर्णाङ्क i;

	जइ (options->अङ्कः_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	प्रति (i = 0; i < options->अङ्कः_certificate_files; i++) {
		जइ (options->certificate_file_userprovided[i] == userprovided &&
		    strcmp(options->certificate_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			प्रत्यागम;
		}
	}

	options->certificate_file_userprovided[options->अङ्कः_certificate_files] =
	    userprovided;
	options->certificate_files[options->अङ्कः_certificate_files++] =
	    xstrdup(path);
}

शून्य
add_identity_file(Options *options, ध्रुव वर्ण *dir, ध्रुव वर्ण *filename,
    पूर्णाङ्क userprovided)
{
	वर्ण *path;
	पूर्णाङ्क i;

	जइ (options->अङ्कः_identity_files >= SSH_MAX_IDENTITY_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_IDENTITY_FILES);

	जइ (dir == रिक्त) /* no dir, filename is absolute */
		path = xstrdup(filename);
	अण्णहा जइ (xasprintf(&path, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", path);

	/* Avoid registering duplicates */
	प्रति (i = 0; i < options->अङ्कः_identity_files; i++) {
		जइ (options->identity_file_userprovided[i] == userprovided &&
		    strcmp(options->identity_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			मुक्त(path);
			प्रत्यागम;
		}
	}

	options->identity_file_userprovided[options->अङ्कः_identity_files] =
	    userprovided;
	options->identity_files[options->अङ्कः_identity_files++] = path;
}

पूर्णाङ्क
default_ssh_port(शून्य)
{
	स्थिर पूर्णाङ्क port;
	संरचना servent *sp;

	जइ (port == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		port = sp ? ntohs(sp->s_port) : SSH_DEFAULT_PORT;
	}
	प्रत्यागम port;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
स्थिर पूर्णाङ्क
execute_in_shell(ध्रुव वर्ण *cmd)
{
	वर्ण *shell;
	pid_t pid;
	पूर्णाङ्क status;

	जइ ((shell = getenv("SHELL")) == रिक्त)
		shell = _PATH_BSHELL;

	जइ (access(shell, X_OK) == -1) {
		fatal("Shell \"%s\" is not executable: %s",
		    shell, strerror(errno));
	}

	debug("Executing command: '%.500s'", cmd);

	/* Fork and execute the command. */
	जइ ((pid = fork()) == 0) {
		वर्ण *argv[4];

		जइ (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = xstrdup(cmd);
		argv[3] = रिक्त;

		execv(argv[0], argv);
		error("Unable to execute '%.100s': %s", cmd, strerror(errno));
		/* Die with signal to make this error apparent to parent. */
		ssh_signal(SIGTERM, SIG_DFL);
		kill(getpid(), SIGTERM);
		_exit(1);
	}
	/* Parent. */
	जइ (pid == -1)
		fatal_f("fork: %.100s", strerror(errno));

	जाव (waitpid(pid, &status, 0) == -1) {
		जइ (errno != EINTR && errno != EAGAIN)
			fatal_f("waitpid: %s", strerror(errno));
	}
	जइ (!WIFEXITED(status)) {
		error("command '%.100s' exited abnormally", cmd);
		प्रत्यागम -1;
	}
	debug3("command returned status %d", WEXITSTATUS(status));
	प्रत्यागम WEXITSTATUS(status);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
स्थिर पूर्णाङ्क
check_match_ifaddrs(ध्रुव वर्ण *addrlist)
{
#ifdef HAVE_IFADDRS_H
	संरचना ifaddrs *ifa, *ifaddrs = रिक्त;
	पूर्णाङ्क r, found = 0;
	वर्ण addr[NI_MAXHOST];
	socklen_t salen;

	जइ (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    strerror(errno));
		प्रत्यागम 0;
	}
	प्रति (ifa = ifaddrs; ifa != रिक्त; ifa = ifa->ifa_next) {
		जइ (ifa->ifa_addr == रिक्त || ifa->ifa_name == रिक्त ||
		    (ifa->ifa_flags & IFF_UP) == 0)
			अनुवर्त;
		विकल्प (ifa->ifa_addr->sa_family) {
		पक्ष AF_INET:
			salen = परिमाण(संरचना sockaddr_in);
			भङ्ग;
		पक्ष AF_INET6:
			salen = परिमाण(संरचना sockaddr_in6);
			भङ्ग;
#ifdef AF_LINK
		पक्ष AF_LINK:
			/* ignore */
			अनुवर्त;
#endif /* AF_LINK */
		स्वभाव:
			debug2_f("interface %s: unsupported address family %d",
			    ifa->ifa_name, ifa->ifa_addr->sa_family);
			अनुवर्त;
		}
		जइ ((r = getnameinfo(ifa->ifa_addr, salen, addr, परिमाण(addr),
		    रिक्त, 0, NI_NUMERICHOST)) != 0) {
			debug2_f("interface %s getnameinfo failed: %s",
			    ifa->ifa_name, gai_strerror(r));
			अनुवर्त;
		}
		debug3_f("interface %s addr %s", ifa->ifa_name, addr);
		जइ (addr_match_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			found = 1;
			भङ्ग;
		}
	}
	freeifaddrs(ifaddrs);
	प्रत्यागम found;
#अण्णहा /* HAVE_IFADDRS_H */
	error("match localnetwork: not supported on this platform");
	प्रत्यागम 0;
#endif /* HAVE_IFADDRS_H */
}

/*
 * Expand a "match exec" command or an Include path, caller must free returned
 * value.
 */
स्थिर वर्ण *
expand_match_exec_or_include_path(ध्रुव वर्ण *path, Options *options,
    संरचना passwd *pw, ध्रुव वर्ण *host_arg, ध्रुव वर्ण *original_host,
    पूर्णाङ्क final_pass, पूर्णाङ्क is_include_path)
{
	वर्ण thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	वर्ण uidstr[32], *conn_hash_hex, *keyalias, *jmphost, *ruser;
	वर्ण *host, *ret;
	पूर्णाङ्क port;

	port = options->port <= 0 ? default_ssh_port() : options->port;
	ruser = options->user == रिक्त ? pw->pw_name : options->user;
	जइ (final_pass) {
		host = xstrdup(options->hostname);
	} अण्णहा जइ (options->hostname != रिक्त) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (वर्ण *)रिक्त);
	} अण्णहा {
		host = xstrdup(host_arg);
	}
	जइ (gethostname(thishost, परिमाण(thishost)) == -1)
		fatal("gethostname: %s", strerror(errno));
	jmphost = option_clear_or_none(options->jump_host) ?
	    "" : options->jump_host;
	strlcpy(shorthost, thishost, परिमाण(shorthost));
	shorthost[strcspn(thishost, ".")] = '\0';
	snprintf(portstr, परिमाण(portstr), "%d", port);
	snprintf(uidstr, परिमाण(uidstr), "%llu",
	    (unsigned long long)pw->pw_uid);
	conn_hash_hex = ssh_connection_hash(thishost, host,
	    portstr, ruser, jmphost);
	keyalias = options->host_कुञ्चिका_alias ?  options->host_कुञ्चिका_alias : host;

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
	    (वर्ण *)रिक्त);
	मुक्त(host);
	मुक्त(conn_hash_hex);
	प्रत्यागम ret;
}

/*
 * Parse and execute a Match directive.
 */
स्थिर पूर्णाङ्क
match_cfg_पङ्क्तिः(Options *options, ध्रुव वर्ण *full_पङ्क्तिः, पूर्णाङ्क *acp, वर्ण ***avp,
    संरचना passwd *pw, ध्रुव वर्ण *host_arg, ध्रुव वर्ण *original_host,
    ध्रुव वर्ण *remote_command, पूर्णाङ्क final_pass, पूर्णाङ्क *want_final_pass,
    ध्रुव वर्ण *filename, पूर्णाङ्क linenum)
{
	वर्ण *arg, *oattrib = रिक्त, *attrib = रिक्त, *cmd, *host, *criteria;
	ध्रुव वर्ण *ruser;
	पूर्णाङ्क r, this_result, result = 1, attributes = 0, negate;

	/*
	 * Configuration is likely to be incomplete at this point so we
	 * must be prepared to use default values.
	 */
	ruser = options->user == रिक्त ? pw->pw_name : options->user;
	जइ (final_pass) {
		host = xstrdup(options->hostname);
	} अण्णहा जइ (options->hostname != रिक्त) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (वर्ण *)रिक्त);
	} अण्णहा {
		host = xstrdup(host_arg);
	}

	debug2("checking match for '%s' host %s originally %s",
	    full_पङ्क्तिः, host, original_host);
	जाव ((attrib = argv_next(acp, avp)) != रिक्त) {
		/* Terminate on comment */
		जइ (*attrib == '#') {
			argv_consume(acp);
			भङ्ग;
		}
		attrib = oattrib = xstrdup(attrib);
		arg = criteria = रिक्त;
		this_result = 1;
		जइ ((negate = (attrib[0] == '!')))
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		जइ (strcasecmp(attrib, "all") == 0) {
			जइ (attributes > 1 ||
			    ((arg = argv_next(acp, avp)) != रिक्त &&
			    *arg != '\0' && *arg != '#')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				result = -1;
				गच्छ out;
			}
			जइ (arg != रिक्त && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			जइ (result)
				result = negate ? 0 : 1;
			गच्छ out;
		}
		attributes++;
		/* criteria "final" and "canonical" have no argument */
		जइ (strcasecmp(attrib, "canonical") == 0 ||
		    strcasecmp(attrib, "final") == 0) {
			/*
			 * If the config requests "Match final" without
			 * negation then remember this so we can perform a
			 * second pass later.
			 */
			जइ (strcasecmp(attrib, "final") == 0 &&
			    want_final_pass != रिक्त)
				*want_final_pass |= !negate;
			r = !!final_pass;  /* force bitmask member to boolean */
			जइ (r == (negate ? 1 : 0))
				this_result = result = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_result ? "" : "not ", oattrib);
			गच्छ next;
		}

		/* Keep this list in sync with below */
		जइ (strprefix(attrib, "host=", 1)  != रिक्त ||
		    strprefix(attrib, "originalhost=", 1) != रिक्त ||
		    strprefix(attrib, "user=", 1) != रिक्त ||
		    strprefix(attrib, "localuser=", 1) != रिक्त ||
		    strprefix(attrib, "localnetwork=", 1) != रिक्त ||
		    strprefix(attrib, "version=", 1) != रिक्त ||
		    strprefix(attrib, "tagged=", 1) != रिक्त ||
		    strprefix(attrib, "command=", 1) != रिक्त ||
		    strprefix(attrib, "exec=", 1) != रिक्त) {
			arg = strchr(attrib, '=');
			*(arg++) = '\0';
		} अण्णहा जइ ((arg = argv_next(acp, avp)) == रिक्त) {
			error("%.200s line %d: missing argument for Match '%s'",
			    filename, linenum, oattrib);
			result = -1;
			गच्छ out;
		}

		/*
		 * All other criteria require an argument, though it may
		 * be the empty string for the "tagged" and "command"
		 * options.
		 */
		जइ (*arg == '\0' &&
		    strcasecmp(attrib, "tagged") != 0 &&
		    strcasecmp(attrib, "command") != 0)
			arg = रिक्त;
		जइ (arg == रिक्त || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			result = -1;
			गच्छ out;
		}
		जइ (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = match_hostname(host, arg) == 1;
			जइ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} अण्णहा जइ (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = match_hostname(original_host, arg) == 1;
			जइ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} अण्णहा जइ (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = match_pattern_list(ruser, arg, 0) == 1;
			जइ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} अण्णहा जइ (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = match_pattern_list(pw->pw_name, arg, 0) == 1;
			जइ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} अण्णहा जइ (strcasecmp(attrib, "localnetwork") == 0) {
			जइ (addr_match_cidr_list(रिक्त, arg) == -1) {
				/* Error already printed */
				result = -1;
				गच्छ out;
			}
			r = check_match_ifaddrs(arg) == 1;
			जइ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} अण्णहा जइ (strcasecmp(attrib, "version") == 0) {
			criteria = xstrdup(SSH_RELEASE);
			r = match_pattern_list(SSH_RELEASE, arg, 0) == 1;
			जइ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} अण्णहा जइ (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->tag == रिक्त ? "" :
			    options->tag);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			जइ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} अण्णहा जइ (strcasecmp(attrib, "command") == 0) {
			criteria = xstrdup(remote_command == रिक्त ?
			    "" : remote_command);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			जइ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} अण्णहा जइ (strcasecmp(attrib, "sessiontype") == 0) {
			जइ (options->session_type == SESSION_TYPE_SUBSYSTEM)
				criteria = xstrdup("subsystem");
			अण्णहा जइ (options->session_type == SESSION_TYPE_NONE)
				criteria = xstrdup("none");
			अण्णहा जइ (remote_command != रिक्त &&
			    *remote_command != '\0')
				criteria = xstrdup("exec");
			अण्णहा
				criteria = xstrdup("shell");
			r = match_pattern_list(criteria, arg, 0) == 1;
			जइ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} अण्णहा जइ (strcasecmp(attrib, "exec") == 0) {
			जइ ((cmd = expand_match_exec_or_include_path(arg,
			    options, pw, host_arg, original_host,
			    final_pass, 0)) == रिक्त) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			जइ (result != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				मुक्त(cmd);
				गच्छ next;
			}
			r = execute_in_shell(cmd);
			जइ (r == -1) {
				fatal("%.200s line %d: match exec "
				    "'%.100s' error", filename,
				    linenum, cmd);
			}
			criteria = xstrdup(cmd);
			मुक्त(cmd);
			/* Force exit status to boolean */
			r = r == 0;
			जइ (r == (negate ? 1 : 0))
				this_result = result = 0;
		} अण्णहा {
			error("Unsupported Match attribute %s", attrib);
			result = -1;
			गच्छ out;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s' ",
		    filename, linenum, this_result ? "": "not ", oattrib,
		    criteria == रिक्त ? "" : " \"",
		    criteria == रिक्त ? "" : criteria,
		    criteria == रिक्त ? "" : "\"");
 next:
		मुक्त(criteria);
		मुक्त(oattrib);
		oattrib = attrib = रिक्त;
	}
	जइ (attributes == 0) {
		error("One or more attributes required for Match");
		result = -1;
		गच्छ out;
	}
 out:
	जइ (result != -1)
		debug2("match %sfound", result ? "" : "not ");
	मुक्त(oattrib);
	मुक्त(host);
	प्रत्यागम result;
}

/* Remove environment variable by pattern */
स्थिर शून्य
rm_env(Options *options, ध्रुव वर्ण *arg, ध्रुव वर्ण *filename, पूर्णाङ्क linenum)
{
	u_int i, j, onum_send_env = options->अङ्कः_send_env;

	/* Remove an environment variable */
	प्रति (i = 0; i < options->अङ्कः_send_env; ) {
		जइ (!match_pattern(options->send_env[i], arg + 1)) {
			i++;
			अनुवर्त;
		}
		debug3("%s line %d: removing environment %s",
		    filename, linenum, options->send_env[i]);
		मुक्त(options->send_env[i]);
		options->send_env[i] = रिक्त;
		प्रति (j = i; j < options->अङ्कः_send_env - 1; j++) {
			options->send_env[j] = options->send_env[j + 1];
			options->send_env[j + 1] = रिक्त;
		}
		options->अङ्कः_send_env--;
		/* NB. don't increment i */
	}
	जइ (onum_send_env != options->अङ्कः_send_env) {
		options->send_env = xrecallocarray(options->send_env,
		    onum_send_env, options->अङ्कः_send_env,
		    परिमाण(*options->send_env));
	}
}

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */
स्थिर OpCodes
parse_token(ध्रुव वर्ण *cp, ध्रुव वर्ण *filename, पूर्णाङ्क linenum,
    ध्रुव वर्ण *ignored_unknown)
{
	पूर्णाङ्क i;

	प्रति (i = 0; keywords[i].name; i++)
		जइ (strcmp(cp, keywords[i].name) == 0)
			प्रत्यागम keywords[i].opcode;
	जइ (ignored_unknown != रिक्त &&
	    match_pattern_list(cp, ignored_unknown, 1) == 1)
		प्रत्यागम oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	प्रत्यागम oBadOption;
}

स्थिर शून्य
free_canon_cnames(संरचना allowed_cname *cnames, u_int n)
{
	u_int i;

	जइ (cnames == रिक्त || n == 0)
		प्रत्यागम;
	प्रति (i = 0; i < n; i++) {
		मुक्त(cnames[i].source_list);
		मुक्त(cnames[i].target_list);
	}
	मुक्त(cnames);
}

/* Multistate option parsing */
संरचना multistate {
	वर्ण *कुञ्चिका;
	पूर्णाङ्क मानम्;
};
स्थिर ध्रुव संरचना multistate multistate_flag[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_yesnoask[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_strict_hostkey[] = {
	{ "true",			SSH_STRICT_HOSTKEY_YES },
	{ "false",			SSH_STRICT_HOSTKEY_OFF },
	{ "yes",			SSH_STRICT_HOSTKEY_YES },
	{ "no",				SSH_STRICT_HOSTKEY_OFF },
	{ "ask",			SSH_STRICT_HOSTKEY_ASK },
	{ "off",			SSH_STRICT_HOSTKEY_OFF },
	{ "accept-new",			SSH_STRICT_HOSTKEY_NEW },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_yesnoaskconfirm[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "confirm",			3 },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_controlmaster[] = {
	{ "true",			SSHCTL_MASTER_YES },
	{ "yes",			SSHCTL_MASTER_YES },
	{ "false",			SSHCTL_MASTER_NO },
	{ "no",				SSHCTL_MASTER_NO },
	{ "auto",			SSHCTL_MASTER_AUTO },
	{ "ask",			SSHCTL_MASTER_ASK },
	{ "autoask",			SSHCTL_MASTER_AUTO_ASK },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET },
	{ "point-to-point",		SSH_TUNMODE_POINTOPOINT },
	{ "true",			SSH_TUNMODE_DEFAULT },
	{ "yes",			SSH_TUNMODE_DEFAULT },
	{ "false",			SSH_TUNMODE_NO },
	{ "no",				SSH_TUNMODE_NO },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_requesttty[] = {
	{ "true",			REQUEST_TTY_YES },
	{ "yes",			REQUEST_TTY_YES },
	{ "false",			REQUEST_TTY_NO },
	{ "no",				REQUEST_TTY_NO },
	{ "force",			REQUEST_TTY_FORCE },
	{ "auto",			REQUEST_TTY_AUTO },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_sessiontype[] = {
	{ "none",			SESSION_TYPE_NONE },
	{ "subsystem",			SESSION_TYPE_SUBSYSTEM },
	{ "default",			SESSION_TYPE_DEFAULT },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_canonicalizehostname[] = {
	{ "true",			SSH_CANONICALISE_YES },
	{ "false",			SSH_CANONICALISE_NO },
	{ "yes",			SSH_CANONICALISE_YES },
	{ "no",				SSH_CANONICALISE_NO },
	{ "always",			SSH_CANONICALISE_ALWAYS },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_pubkey_auth[] = {
	{ "true",			SSH_PUBKEY_AUTH_ALL },
	{ "false",			SSH_PUBKEY_AUTH_NO },
	{ "yes",			SSH_PUBKEY_AUTH_ALL },
	{ "no",				SSH_PUBKEY_AUTH_NO },
	{ "unbound",			SSH_PUBKEY_AUTH_UNBOUND },
	{ "host-bound",			SSH_PUBKEY_AUTH_HBOUND },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_compression[] = {
#ifdef WITH_ZLIB
	{ "yes",			COMP_DELAYED },
#endif
	{ "no",				COMP_NONE },
	{ रिक्त, -1 }
};
स्थिर ध्रुव संरचना multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ रिक्त, -1 }
};
/* XXX this will need to be replaced with a bitmask if we add more flags */
स्थिर ध्रुव संरचना multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ रिक्त, -1 }
};

स्थिर पूर्णाङ्क
parse_multistate_मानम्(ध्रुव वर्ण *arg, ध्रुव वर्ण *filename, पूर्णाङ्क linenum,
    ध्रुव संरचना multistate *multistate_ptr)
{
	पूर्णाङ्क i;

	जइ (!arg || *arg == '\0') {
		error("%s line %d: missing argument.", filename, linenum);
		प्रत्यागम -1;
	}
	प्रति (i = 0; multistate_ptr[i].कुञ्चिका != रिक्त; i++) {
		जइ (strcasecmp(arg, multistate_ptr[i].कुञ्चिका) == 0)
			प्रत्यागम multistate_ptr[i].मानम्;
	}
	प्रत्यागम -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
पूर्णाङ्क
process_config_पङ्क्तिः(Options *options, संरचना passwd *pw, ध्रुव वर्ण *host,
    ध्रुव वर्ण *original_host, ध्रुव वर्ण *remote_command, वर्ण *पङ्क्तिः,
    ध्रुव वर्ण *filename, पूर्णाङ्क linenum, पूर्णाङ्क *activep, पूर्णाङ्क flags)
{
	प्रत्यागम process_config_पङ्क्तिः_depth(options, pw, host, original_host,
	    remote_command, पङ्क्तिः, filename, linenum, activep, flags, रिक्त, 0);
}

#define WHITESPACE " \t\r\n"
स्थिर पूर्णाङ्क
process_config_पङ्क्तिः_depth(Options *options, संरचना passwd *pw, ध्रुव वर्ण *host,
    ध्रुव वर्ण *original_host, ध्रुव वर्ण *remote_command, वर्ण *पङ्क्तिः,
    ध्रुव वर्ण *filename, पूर्णाङ्क linenum, पूर्णाङ्क *activep, पूर्णाङ्क flags,
    पूर्णाङ्क *want_final_pass, पूर्णाङ्क depth)
{
	वर्ण *str, **charptr, *endofnumber, *keyword, *arg, *arg2, *p;
	वर्ण **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	पूर्णाङ्क r, oactive, negated, opcode, *intptr, मानम्, value2, cmdline = 0;
	पूर्णाङ्क remotefwd, dynamicfwd, ca_only = 0, found = 0;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	long long val64;
	size_t len;
	संरचना Forward fwd;
	ध्रुव संरचना multistate *multistate_ptr;
	glob_t gl;
	ध्रुव वर्ण *errstr;
	वर्ण **oav = रिक्त, **av;
	पूर्णाङ्क oac = 0, ac;
	पूर्णाङ्क ret = -1;
	संरचना allowed_cname *cnames = रिक्त;
	u_int ncnames = 0;
	वर्ण **strs = रिक्त; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	जइ (activep == रिक्त) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	जइ ((len = strlen(पङ्क्तिः)) == 0)
		प्रत्यागम 0;
	प्रति (len--; len > 0; len--) {
		जइ (strchr(WHITESPACE "\f", पङ्क्तिः[len]) == रिक्त)
			भङ्ग;
		पङ्क्तिः[len] = '\0';
	}

	str = पङ्क्तिः;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	जइ ((keyword = strdelim(&str)) == रिक्त)
		प्रत्यागम 0;
	/* Ignore leading whitespace. */
	जइ (*keyword == '\0')
		keyword = strdelim(&str);
	जइ (keyword == रिक्त || !*keyword || *keyword == '\n' || *keyword == '#')
		प्रत्यागम 0;
	/* Match lowercase keyword */
	lowercase(keyword);

	/* Prepare to parse remainder of line */
	जइ (str != रिक्त)
		str += strspn(str, WHITESPACE);
	जइ (str == रिक्त || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		प्रत्यागम -1;
	}
	opcode = parse_token(keyword, filename, linenum,
	    options->ignored_unknown);
	जइ (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		प्रत्यागम -1;
	}
	ac = oac;
	av = oav;

	विकल्प (opcode) {
	पक्ष oBadOption:
		/* don't panic, but count bad options */
		गच्छ out;
	पक्ष oIgnore:
		argv_consume(&ac);
		भङ्ग;
	पक्ष oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		भङ्ग;
	पक्ष oConnectTimeout:
		intptr = &options->connection_timeout;
parse_time:
		arg = argv_next(&ac, &av);
		जइ (!arg || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			गच्छ out;
		}
		जइ (strcmp(arg, "none") == 0)
			मानम् = -1;
		अण्णहा जइ ((मानम् = convtime(arg)) == -1) {
			error("%s line %d: invalid time value.",
			    filename, linenum);
			गच्छ out;
		}
		जइ (*activep && *intptr == -1)
			*intptr = मानम्;
		भङ्ग;

	पक्ष oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_next(&ac, &av);
		जइ (!arg || *arg == '\0') {
			error("%s line %d: missing argument.",
			    filename, linenum);
			गच्छ out;
		}

		मानम् = -1;
		multistate_ptr = multistate_flag;
		प्रति (i = 0; multistate_ptr[i].कुञ्चिका != रिक्त; i++) {
			जइ (strcasecmp(arg, multistate_ptr[i].कुञ्चिका) == 0) {
				मानम् = multistate_ptr[i].मानम्;
				भङ्ग;
			}
		}
		जइ (मानम् != -1) {
			जइ (*activep && *intptr == -1)
				*intptr = मानम्;
			भङ्ग;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		जइ (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_path;
		गच्छ parse_agent_path;

	पक्ष oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_next(&ac, &av);
		जइ ((मानम् = parse_multistate_मानम्(arg, filename, linenum,
		    multistate_ptr)) == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			गच्छ out;
		}
		जइ (*activep && *intptr == -1)
			*intptr = मानम्;
		भङ्ग;

	पक्ष oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		गच्छ parse_flag;

	पक्ष oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		गच्छ parse_time;

	पक्ष oGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		गच्छ parse_flag;

	पक्ष oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		गच्छ parse_flag;

	पक्ष oPasswordAuthentication:
		intptr = &options->password_authentication;
		गच्छ parse_flag;

	पक्ष oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		गच्छ parse_flag;

	पक्ष oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		गच्छ parse_string;

	पक्ष oPubkeyAuthentication:
		multistate_ptr = multistate_pubkey_auth;
		intptr = &options->pubkey_authentication;
		गच्छ parse_multistate;

	पक्ष oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		गच्छ parse_flag;

	पक्ष oGssAuthentication:
		intptr = &options->gss_authentication;
		गच्छ parse_flag;

	पक्ष oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		गच्छ parse_flag;

	पक्ष oBatchMode:
		intptr = &options->batch_mode;
		गच्छ parse_flag;

	पक्ष oCheckHostIP:
		intptr = &options->check_host_ip;
		गच्छ parse_flag;

	पक्ष o_Verify_Host_कुञ्चिका_DNS:
		intptr = &options->verify_host_कुञ्चिका_dns;
		multistate_ptr = multistate_yesnoask;
		गच्छ parse_multistate;

	पक्ष o_Strict_Host_कुञ्चिका_Checking:
		intptr = &options->strict_host_कुञ्चिका_checking;
		multistate_ptr = multistate_strict_hostkey;
		गच्छ parse_multistate;

	पक्ष oCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		गच्छ parse_multistate;

	पक्ष oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		गच्छ parse_multistate;

	पक्ष oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		गच्छ parse_flag;

	पक्ष o_सङ्ख्या_Of_Password_Prompts:
		intptr = &options->सङ्ख्या_of_password_prompts;
		गच्छ parse_int;

	पक्ष oRekeyLimit:
		arg = argv_next(&ac, &av);
		जइ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.", filename,
			    linenum);
			गच्छ out;
		}
		जइ (strcmp(arg, "default") == 0) {
			val64 = 0;
		} अण्णहा {
			जइ (scan_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, strerror(errno));
				गच्छ out;
			}
			जइ (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				गच्छ out;
			}
		}
		जइ (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		जइ (ac != 0) { /* optional rekey interval present */
			जइ (strcmp(av[0], "none") == 0) {
				(शून्य)argv_next(&ac, &av);	/* discard */
				भङ्ग;
			}
			intptr = &options->rekey_interval;
			गच्छ parse_time;
		}
		भङ्ग;

	पक्ष oIdentityFile:
		arg = argv_next(&ac, &av);
		जइ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ out;
		}
		जइ (*activep) {
			intptr = &options->अङ्कः_identity_files;
			जइ (*intptr >= SSH_MAX_IDENTITY_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_IDENTITY_FILES);
				गच्छ out;
			}
			add_identity_file(options, रिक्त,
			    arg, flags & SSHCONF_USERCONF);
		}
		भङ्ग;

	पक्ष oCertificateFile:
		arg = argv_next(&ac, &av);
		जइ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ out;
		}
		जइ (*activep) {
			intptr = &options->अङ्कः_certificate_files;
			जइ (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				गच्छ out;
			}
			add_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		भङ्ग;

	पक्ष oXAuthLocation:
		charptr=&options->xauth_location;
		गच्छ parse_string;

	पक्ष oUser:
		charptr = &options->user;
parse_string:
		arg = argv_next(&ac, &av);
		जइ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ out;
		}
		जइ (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		भङ्ग;

	पक्ष oGlobalKnownHostsFile:
		cpptr = (वर्ण **)&options->system_hostfiles;
		uintptr = &options->अङ्कः_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		i = 0;
		मानम् = *uintptr == 0; /* was array empty when we started? */
		जाव ((arg = argv_next(&ac, &av)) != रिक्त) {
			जइ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				गच्छ out;
			}
			/* Allow "none" only in first position */
			जइ (strcasecmp(arg, "none") == 0) {
				जइ (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ out;
				}
			}
			i++;
			जइ (*activep && मानम्) {
				जइ ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries.", filename, linenum,
					    keyword);
					गच्छ out;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		भङ्ग;

	पक्ष oUserKnownHostsFile:
		cpptr = (वर्ण **)&options->user_hostfiles;
		uintptr = &options->अङ्कः_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		गच्छ parse_char_array;

	पक्ष oHostname:
		charptr = &options->hostname;
		गच्छ parse_string;

	पक्ष oTag:
		charptr = &options->tag;
		गच्छ parse_string;

	पक्ष o_Host_कुञ्चिका_Alias:
		charptr = &options->host_कुञ्चिका_alias;
		गच्छ parse_string;

	पक्ष oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		गच्छ parse_string;

	पक्ष oBindAddress:
		charptr = &options->bind_address;
		गच्छ parse_string;

	पक्ष oBindInterface:
		charptr = &options->bind_interface;
		गच्छ parse_string;

	पक्ष oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		गच्छ parse_string;

	पक्ष o_Security_कुञ्चिका_Provider:
		charptr = &options->sk_provider;
		गच्छ parse_string;

	पक्ष oKnownHostsCommand:
		charptr = &options->known_hosts_command;
		गच्छ parse_command;

	पक्ष oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		जइ (str == रिक्त) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ out;
		}
		len = strspn(str, WHITESPACE "=");
		जइ (*activep && *charptr == रिक्त)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		भङ्ग;

	पक्ष oProxyJump:
		जइ (str == रिक्त) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ out;
		}
		len = strspn(str, WHITESPACE "=");
		/* XXX use argv? */
		जइ (parse_jump(str + len, options, cmdline, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			गच्छ out;
		}
		argv_consume(&ac);
		भङ्ग;

	पक्ष oPort:
		arg = argv_next(&ac, &av);
		जइ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ out;
		}
		मानम् = a2port(arg);
		जइ (मानम् <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			गच्छ out;
		}
		जइ (*activep && options->port == -1)
			options->port = मानम्;
		भङ्ग;

	पक्ष oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_next(&ac, &av);
		जइ ((errstr = atoi_err(arg, &मानम्)) != रिक्त) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			गच्छ out;
		}
		जइ (*activep && *intptr == -1)
			*intptr = मानम्;
		भङ्ग;

	पक्ष oCiphers:
		arg = argv_next(&ac, &av);
		जइ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ out;
		}
		जइ (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			गच्छ out;
		}
		जइ (*activep && options->ciphers == रिक्त)
			options->ciphers = xstrdup(arg);
		भङ्ग;

	पक्ष oMacs:
		arg = argv_next(&ac, &av);
		जइ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ out;
		}
		जइ (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			गच्छ out;
		}
		जइ (*activep && options->macs == रिक्त)
			options->macs = xstrdup(arg);
		भङ्ग;

	पक्ष oKexAlgorithms:
		arg = argv_next(&ac, &av);
		जइ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ out;
		}
		जइ (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			गच्छ out;
		}
		जइ (*activep && options->kex_algorithms == रिक्त)
			options->kex_algorithms = xstrdup(arg);
		भङ्ग;

	पक्ष o_Host_कुञ्चिका_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
parse_pubkey_algos:
		arg = argv_next(&ac, &av);
		जइ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ out;
		}
		जइ (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			गच्छ out;
		}
		जइ (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		भङ्ग;

	पक्ष oCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		गच्छ parse_pubkey_algos;

	पक्ष oLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_next(&ac, &av);
		मानम् = log_level_सङ्ख्या(arg);
		जइ (मानम् == SYSLOG_LEVEL_NOT_SET) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			गच्छ out;
		}
		जइ (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_SET)
			*log_level_ptr = (LogLevel) मानम्;
		भङ्ग;

	पक्ष oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_next(&ac, &av);
		मानम् = log_facility_सङ्ख्या(arg);
		जइ (मानम् == SYSLOG_FACILITY_NOT_SET) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			गच्छ out;
		}
		जइ (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) मानम्;
		भङ्ग;

	पक्ष oLogVerbose:
		cppptr = &options->log_verbose;
		uintptr = &options->अङ्कः_log_verbose;
		i = 0;
		जाव ((arg = argv_next(&ac, &av)) != रिक्त) {
			जइ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				गच्छ out;
			}
			/* Allow "none" only in first position */
			जइ (strcasecmp(arg, "none") == 0) {
				जइ (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ out;
				}
			}
			i++;
			जइ (*activep && *uintptr == 0) {
				*cppptr = xrecallocarray(*cppptr, *uintptr,
				    *uintptr + 1, परिमाण(**cppptr));
				(*cppptr)[(*uintptr)++] = xstrdup(arg);
			}
		}
		भङ्ग;

	पक्ष oLocalForward:
	पक्ष oRemoteForward:
	पक्ष oDynamicForward:
		arg = argv_next(&ac, &av);
		जइ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ out;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		जइ (!dynamicfwd) {
			arg2 = argv_next(&ac, &av);
			जइ (arg2 == रिक्त || *arg2 == '\0') {
				जइ (remotefwd)
					dynamicfwd = 1;
				अण्णहा {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					गच्छ out;
				}
			} अण्णहा {
				/* construct a string for parse_forward */
				snprintf(fwdarg, परिमाण(fwdarg), "%s:%s", arg,
				    arg2);
			}
		}
		जइ (dynamicfwd)
			strlcpy(fwdarg, arg, परिमाण(fwdarg));

		जइ (parse_forward(&fwd, fwdarg, dynamicfwd, remotefwd) == 0) {
			error("%.200s line %d: Bad forwarding specification.",
			    filename, linenum);
			गच्छ out;
		}

		जइ (*activep) {
			जइ (remotefwd) {
				add_remote_forward(options, &fwd);
			} अण्णहा {
				add_local_forward(options, &fwd);
			}
		}
		भङ्ग;

	पक्ष oPermitRemoteOpen:
		uintptr = &options->अङ्कः_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		found = *uintptr == 0;
		जाव ((arg = argv_next(&ac, &av)) != रिक्त) {
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			जइ (strcasecmp(arg, "none") == 0 ||
			    strcasecmp(arg, "any") == 0) {
				जइ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					मुक्त(arg2);
					गच्छ out;
				}
			} अण्णहा {
				p = hpdelim(&arg);
				जइ (p == रिक्त) {
					fatal("%s line %d: missing host in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
				}
				p = cleanhostname(p);
				/*
				 * don't want to use permitopen_port to avoid
				 * dependency on channels.[ch] here.
				 */
				जइ (arg == रिक्त || (strcmp(arg, "*") != 0 &&
				    a2port(arg) <= 0)) {
					fatal("%s line %d: bad port number "
					    "in %s", filename, linenum,
					    lookup_opcode_name(opcode));
				}
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg2);
			मुक्त(arg2);
		}
		जइ (nstrs == 0)
			fatal("%s line %d: missing %s specification",
			    filename, linenum, lookup_opcode_name(opcode));
		जइ (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष oClearAllForwardings:
		intptr = &options->clear_forwardings;
		गच्छ parse_flag;

	पक्ष oHost:
		जइ (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			गच्छ out;
		}
		*activep = 0;
		arg2 = रिक्त;
		जाव ((arg = argv_next(&ac, &av)) != रिक्त) {
			जइ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				गच्छ out;
			}
			जइ ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				भङ्ग;
			}
			negated = *arg == '!';
			जइ (negated)
				arg++;
			जइ (match_pattern(host, arg)) {
				जइ (negated) {
					debug("%.200s line %d: Skipping Host "
					    "block because of negated match "
					    "for %.100s", filename, linenum,
					    arg);
					*activep = 0;
					argv_consume(&ac);
					भङ्ग;
				}
				जइ (!*activep)
					arg2 = arg; /* logged below */
				*activep = 1;
			}
		}
		जइ (*activep)
			debug("%.200s line %d: Applying options for %.100s",
			    filename, linenum, arg2);
		भङ्ग;

	पक्ष oMatch:
		जइ (cmdline) {
			error("Match directive not supported as a command-line "
			    "option");
			गच्छ out;
		}
		मानम् = match_cfg_पङ्क्तिः(options, str, &ac, &av, pw, host,
		    original_host, remote_command, flags & SSHCONF_FINAL,
		    want_final_pass, filename, linenum);
		जइ (मानम् < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			गच्छ out;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : मानम्;
		भङ्ग;

	पक्ष oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_next(&ac, &av);
		जइ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ out;
		}
		जइ (strcmp(arg, "none") == 0)
			मानम् = SSH_ESCAPECHAR_NONE;
		अण्णहा जइ (arg[1] == '\0')
			मानम् = (u_char) arg[0];
		अण्णहा जइ (arg[0] == '^' && arg[2] == 0 &&
		    (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			मानम् = (u_char) arg[1] & 31;
		अण्णहा {
			error("%.200s line %d: Bad escape character.",
			    filename, linenum);
			गच्छ out;
		}
		जइ (*activep && *intptr == -1)
			*intptr = मानम्;
		भङ्ग;

	पक्ष oAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
		गच्छ parse_multistate;

	पक्ष oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		गच्छ parse_flag;

	पक्ष oIdentitiesOnly:
		intptr = &options->identities_only;
		गच्छ parse_flag;

	पक्ष oServerAliveInterval:
		intptr = &options->server_alive_interval;
		गच्छ parse_time;

	पक्ष o_Server_Alive_गणनम्_Max:
		intptr = &options->server_alive_गणनम्_max;
		गच्छ parse_int;

	पक्ष oSendEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		जाव ((arg = argv_next(&ac, &av)) != रिक्त) {
			जइ (*arg == '\0' || strchr(arg, '=') != रिक्त) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				गच्छ out;
			}
			found = 1;
			जइ (!*activep)
				अनुवर्त;
			जइ (*arg == '-') {
				/* Removing an env var */
				rm_env(options, arg, filename, linenum);
				अनुवर्त;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->अङ्कः_send_env, arg);
		}
		जइ (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		भङ्ग;

	पक्ष oSetEnv:
		found = options->अङ्कः_setenv == 0;
		जाव ((arg = argv_next(&ac, &av)) != रिक्त) {
			जइ (strchr(arg, '=') == रिक्त) {
				error("%s line %d: Invalid SetEnv.",
				    filename, linenum);
				गच्छ out;
			}
			जइ (lookup_setenv_in_list(arg, strs, nstrs) != रिक्त) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				अनुवर्त;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg);
		}
		जइ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		जइ (found && *activep) {
			options->setenv = strs;
			options->अङ्कः_setenv = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष oControlPath:
		charptr = &options->control_path;
		गच्छ parse_string;

	पक्ष oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		गच्छ parse_multistate;

	पक्ष oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_next(&ac, &av);
		जइ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing ControlPersist"
			    " argument.", filename, linenum);
			गच्छ out;
		}
		मानम् = 0;
		value2 = 0;	/* timeout */
		जइ (strcmp(arg, "no") == 0 || strcmp(arg, "false") == 0)
			मानम् = 0;
		अण्णहा जइ (strcmp(arg, "yes") == 0 || strcmp(arg, "true") == 0)
			मानम् = 1;
		अण्णहा जइ ((value2 = convtime(arg)) >= 0)
			मानम् = 1;
		अण्णहा {
			error("%.200s line %d: Bad ControlPersist argument.",
			    filename, linenum);
			गच्छ out;
		}
		जइ (*activep && *intptr == -1) {
			*intptr = मानम्;
			options->control_persist_timeout = value2;
		}
		भङ्ग;

	पक्ष oHashKnownHosts:
		intptr = &options->hash_known_hosts;
		गच्छ parse_flag;

	पक्ष oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		गच्छ parse_multistate;

	पक्ष oTunnelDevice:
		arg = argv_next(&ac, &av);
		जइ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ out;
		}
		मानम् = a2tun(arg, &value2);
		जइ (मानम् == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			गच्छ out;
		}
		जइ (*activep && options->tun_local == -1) {
			options->tun_local = मानम्;
			options->tun_remote = value2;
		}
		भङ्ग;

	पक्ष oLocalCommand:
		charptr = &options->local_command;
		गच्छ parse_command;

	पक्ष oPermitLocalCommand:
		intptr = &options->permit_local_command;
		गच्छ parse_flag;

	पक्ष oRemoteCommand:
		charptr = &options->remote_command;
		गच्छ parse_command;

	पक्ष o_Visual_Host_कुञ्चिका:
		intptr = &options->visual_host_कुञ्चिका;
		गच्छ parse_flag;

	पक्ष oInclude:
		जइ (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			गच्छ out;
		}
		मानम् = 0;
		जाव ((arg = argv_next(&ac, &av)) != रिक्त) {
			जइ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				गच्छ out;
			}
			/* Expand %tokens and environment variables */
			जइ ((p = expand_match_exec_or_include_path(arg,
			    options, pw, host, original_host,
			    flags & SSHCONF_FINAL, 1)) == रिक्त) {
				error("%.200s line %d: Unable to expand user "
				    "config file '%.100s'",
				    filename, linenum, arg);
				अनुवर्त;
			}
			/*
			 * Ensure all paths are anchored. User configuration
			 * files may begin with '~/' but system configurations
			 * must not. If the path is relative, then treat it
			 * as living in ~/.ssh for user configurations or
			 * /etc/ssh for system ones.
			 */
			जइ (*p == '~' && (flags & SSHCONF_USERCONF) == 0) {
				error("%.200s line %d: bad include path %s.",
				    filename, linenum, p);
				गच्छ out;
			}
			जइ (!path_absolute(p) && *p != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" _PATH_SSH_USER_DIR : SSHDIR, p);
			} अण्णहा {
				arg2 = xstrdup(p);
			}
			मुक्त(p);
			memset(&gl, 0, परिमाण(gl));
			r = glob(arg2, GLOB_TILDE, रिक्त, &gl);
			जइ (r == GLOB_NOMATCH) {
				debug("%.200s line %d: include %s matched no "
				    "files",filename, linenum, arg2);
				मुक्त(arg2);
				अनुवर्त;
			} अण्णहा जइ (r != 0) {
				error("%.200s line %d: glob failed for %s.",
				    filename, linenum, arg2);
				गच्छ out;
			}
			मुक्त(arg2);
			oactive = *activep;
			प्रति (i = 0; i < gl.gl_pathc; i++) {
				debug3("%.200s line %d: Including file %s "
				    "depth %d%s", filename, linenum,
				    gl.gl_pathv[i], depth,
				    oactive ? "" : " (parse only)");
				r = read_config_file_depth(gl.gl_pathv[i],
				    pw, host, original_host, remote_command,
				    options, flags | SSHCONF_CHECKPERM |
				    (oactive ? 0 : SSHCONF_NEVERMATCH),
				    activep, want_final_pass, depth + 1);
				जइ (r != 1 && errno != ENOENT) {
					error("%.200s line %d: Can't open user "
					    "config file %.100s: %.100s",
					    filename, linenum, gl.gl_pathv[i],
					    strerror(errno));
					globfree(&gl);
					गच्छ out;
				}
				/*
				 * don't let Match in includes clobber the
				 * containing file's Match state.
				 */
				*activep = oactive;
				जइ (r != 1)
					मानम् = -1;
			}
			globfree(&gl);
		}
		जइ (मानम् != 0)
			ret = मानम्;
		भङ्ग;

	पक्ष oIPQoS:
		arg = argv_next(&ac, &av);
		जइ ((मानम् = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			गच्छ out;
		}
		जइ (मानम् == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			मानम् = INT_MAX;
		}
		arg = argv_next(&ac, &av);
		जइ (arg == रिक्त)
			value2 = मानम्;
		अण्णहा जइ ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			गच्छ out;
		}
		जइ (value2 == INT_MIN) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = INT_MAX;
		}
		जइ (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = मानम्;
			options->ip_qos_bulk = value2;
		}
		भङ्ग;

	पक्ष oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		गच्छ parse_multistate;

	पक्ष oSessionType:
		intptr = &options->session_type;
		multistate_ptr = multistate_sessiontype;
		गच्छ parse_multistate;

	पक्ष oStdinNull:
		intptr = &options->stdin_null;
		गच्छ parse_flag;

	पक्ष oForkAfterAuthentication:
		intptr = &options->fork_after_authentication;
		गच्छ parse_flag;

	पक्ष oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		गच्छ parse_string;

	पक्ष oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		गच्छ parse_flag;

	पक्ष oCanonicalDomains:
		found = options->अङ्कः_canonical_domains == 0;
		जाव ((arg = argv_next(&ac, &av)) != रिक्त) {
			/* Allow "none" only in first position */
			जइ (strcasecmp(arg, "none") == 0) {
				जइ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ out;
				}
			}
			जइ (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				गच्छ out;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		जइ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		जइ (found && *activep) {
			options->canonical_domains = strs;
			options->अङ्कः_canonical_domains = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष oCanonicalizePermittedCNAMEs:
		found = options->अङ्कः_permitted_cnames == 0;
		जाव ((arg = argv_next(&ac, &av)) != रिक्त) {
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			जइ (strcasecmp(arg, "none") == 0) {
				जइ (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ out;
				}
				arg2 = "";
			} अण्णहा जइ (strcmp(arg, "*") == 0) {
				arg2 = arg;
			} अण्णहा {
				lowercase(arg);
				जइ ((arg2 = strchr(arg, ':')) == रिक्त ||
				    arg2[1] == '\0') {
					error("%s line %d: "
					    "Invalid permitted CNAME \"%s\"",
					    filename, linenum, arg);
					गच्छ out;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    परिमाण(*cnames));
			cnames[ncnames].source_list = xstrdup(arg);
			cnames[ncnames].target_list = xstrdup(arg2);
			ncnames++;
		}
		जइ (ncnames == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		जइ (found && *activep) {
			options->permitted_cnames = cnames;
			options->अङ्कः_permitted_cnames = ncnames;
			cnames = रिक्त; /* transferred */
			ncnames = 0;
		}
		/* un-transferred cnames is cleaned up before exit */
		भङ्ग;

	पक्ष oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		गच्छ parse_multistate;

	पक्ष oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		गच्छ parse_int;

	पक्ष oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		गच्छ parse_flag;

	पक्ष oStreamLocalBindMask:
		arg = argv_next(&ac, &av);
		जइ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			गच्छ out;
		}
		/* Parse mode in octal format */
		मानम् = strtol(arg, &endofnumber, 8);
		जइ (arg == endofnumber || मानम् < 0 || मानम् > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			गच्छ out;
		}
		जइ (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)मानम्;
		भङ्ग;

	पक्ष oStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		गच्छ parse_flag;

	पक्ष o_Revoked_Host_कुञ्चिकाः:
		uintptr = &options->अङ्कः_revoked_host_कुञ्चिकाः;
		cppptr = &options->revoked_host_कुञ्चिकाः;
		found = *uintptr == 0;
		जाव ((arg = argv_next(&ac, &av)) != रिक्त) {
			जइ (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				गच्छ out;
			}
			/* Allow "none" only in first position */
			जइ (strcasecmp(arg, "none") == 0) {
				जइ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		जइ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		जइ (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_next(&ac, &av);
		जइ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ out;
		}
		जइ ((मानम् = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			गच्छ out;
		}
		जइ (*activep && *intptr == -1)
			*intptr = मानम्;
		भङ्ग;

	पक्ष oUpdateHostkeys:
		intptr = &options->update_hostkeys;
		multistate_ptr = multistate_yesnoask;
		गच्छ parse_multistate;

	पक्ष oHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
		गच्छ parse_pubkey_algos;

	पक्ष oPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		गच्छ parse_pubkey_algos;

	पक्ष o_Add_कुञ्चिकाः_To_Agent:
		arg = argv_next(&ac, &av);
		arg2 = argv_next(&ac, &av);
		मानम् = parse_multistate_मानम्(arg, filename, linenum,
		    multistate_yesnoaskconfirm);
		value2 = 0; /* unlimited lifespan by default */
		जइ (मानम् == 3 && arg2 != रिक्त) {
			/* allow "AddKeysToAgent confirm 5m" */
			जइ ((value2 = convtime(arg2)) == -1) {
				error("%s line %d: invalid time value.",
				    filename, linenum);
				गच्छ out;
			}
		} अण्णहा जइ (मानम् == -1 && arg2 == रिक्त) {
			जइ ((value2 = convtime(arg)) == -1) {
				error("%s line %d: unsupported option",
				    filename, linenum);
				गच्छ out;
			}
			मानम् = 1; /* yes */
		} अण्णहा जइ (मानम् == -1 || arg2 != रिक्त) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			गच्छ out;
		}
		जइ (*activep && options->add_कुञ्चिकाः_to_agent == -1) {
			options->add_कुञ्चिकाः_to_agent = मानम्;
			options->add_कुञ्चिकाः_to_agent_lifespan = value2;
		}
		भङ्ग;

	पक्ष oIdentityAgent:
		charptr = &options->identity_agent;
		arg = argv_next(&ac, &av);
		जइ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ out;
		}
  parse_agent_path:
		/* Extra validation if the string represents an env var. */
		जइ ((arg2 = dollar_expand(&r, arg)) == रिक्त || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			गच्छ out;
		}
		मुक्त(arg2);
		/* check for legacy environment format */
		जइ (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			गच्छ out;
		}
		जइ (*activep && *charptr == रिक्त)
			*charptr = xstrdup(arg);
		भङ्ग;

	पक्ष oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		गच्छ parse_flag;

	पक्ष oRequiredRSASize:
		intptr = &options->required_rsa_size;
		गच्छ parse_int;

	पक्ष oWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		गच्छ parse_multistate;

	पक्ष oObscureKeystrokeTiming:
		मानम् = -1;
		जाव ((arg = argv_next(&ac, &av)) != रिक्त) {
			जइ (मानम् != -1) {
				error("%s line %d: invalid arguments",
				    filename, linenum);
				गच्छ out;
			}
			जइ (strcmp(arg, "yes") == 0 ||
			    strcmp(arg, "true") == 0)
				मानम् = SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
			अण्णहा जइ (strcmp(arg, "no") == 0 ||
			    strcmp(arg, "false") == 0)
				मानम् = 0;
			अण्णहा जइ (strncmp(arg, "interval:", 9) == 0) {
				जइ ((errstr = atoi_err(arg + 9,
				    &मानम्)) != रिक्त) {
					error("%s line %d: integer value %s.",
					    filename, linenum, errstr);
					गच्छ out;
				}
				जइ (मानम् <= 0 || मानम् > 1000) {
					error("%s line %d: value out of range.",
					    filename, linenum);
					गच्छ out;
				}
			} अण्णहा {
				error("%s line %d: unsupported argument \"%s\"",
				    filename, linenum, arg);
				गच्छ out;
			}
		}
		जइ (मानम् == -1) {
			error("%s line %d: missing argument",
			    filename, linenum);
			गच्छ out;
		}
		intptr = &options->obscure_keystroke_timing_interval;
		जइ (*activep && *intptr == -1)
			*intptr = मानम्;
		भङ्ग;

	पक्ष oChannelTimeout:
		found = options->अङ्कः_channel_timeouts == 0;
		जाव ((arg = argv_next(&ac, &av)) != रिक्त) {
			/* Allow "none" only in first position */
			जइ (strcasecmp(arg, "none") == 0) {
				जइ (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					गच्छ out;
				}
			} अण्णहा जइ (parse_pattern_interval(arg,
			    रिक्त, रिक्त) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		जइ (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		जइ (found && *activep) {
			options->channel_timeouts = strs;
			options->अङ्कः_channel_timeouts = nstrs;
			strs = रिक्त; /* transferred */
			nstrs = 0;
		}
		भङ्ग;

	पक्ष oVersionAddendum:
		जइ (str == रिक्त || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = strspn(str, WHITESPACE);
		जइ (strchr(str + len, '\r') != रिक्त) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		जइ ((arg = strchr(पङ्क्तिः, '#')) != रिक्त) {
			*arg = '\0';
			rtrim(पङ्क्तिः);
		}
		जइ (*activep && options->version_addendum == रिक्त) {
			जइ (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			अण्णहा
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		भङ्ग;

	पक्ष oRefuseConnection:
		arg = argv_next(&ac, &av);
		जइ (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			गच्छ out;
		}
		जइ (*activep) {
			fatal("%.200s line %d: RefuseConnection: %s",
			    filename, linenum, arg);
		}
		भङ्ग;

	पक्ष oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		भङ्ग;

	पक्ष oUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		भङ्ग;

	स्वभाव:
		error("%s line %d: Unimplemented opcode %d",
		    filename, linenum, opcode);
		गच्छ out;
	}

	/* Check that there is no garbage at end of line. */
	जइ (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		गच्छ out;
	}

	/* success */
	ret = 0;
 out:
	free_canon_cnames(cnames, ncnames);
	opt_array_free2(strs, रिक्त, nstrs);
	argv_free(oav, oac);
	प्रत्यागम ret;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */
पूर्णाङ्क
read_config_file(ध्रुव वर्ण *filename, संरचना passwd *pw, ध्रुव वर्ण *host,
    ध्रुव वर्ण *original_host, ध्रुव वर्ण *remote_command, Options *options, पूर्णाङ्क flags,
    पूर्णाङ्क *want_final_pass)
{
	पूर्णाङ्क active = 1;

	प्रत्यागम read_config_file_depth(filename, pw, host, original_host,
	    remote_command, options, flags, &active, want_final_pass, 0);
}

#define READCONF_MAX_DEPTH	16
स्थिर पूर्णाङ्क
read_config_file_depth(ध्रुव वर्ण *filename, संरचना passwd *pw,
    ध्रुव वर्ण *host, ध्रुव वर्ण *original_host, ध्रुव वर्ण *remote_command,
    Options *options, पूर्णाङ्क flags, पूर्णाङ्क *activep, पूर्णाङ्क *want_final_pass, पूर्णाङ्क depth)
{
	FILE *f;
	वर्ण *पङ्क्तिः = रिक्त;
	size_t linesize = 0;
	पूर्णाङ्क linenum;
	पूर्णाङ्क bad_options = 0;

	जइ (depth < 0 || depth > READCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	जइ ((f = fopen(filename, "r")) == रिक्त)
		प्रत्यागम 0;

	जइ (flags & SSHCONF_CHECKPERM) {
		संरचना stat sb;

		जइ (fstat(fileno(f), &sb) == -1)
			fatal("fstat %s: %s", filename, strerror(errno));
		जइ (((sb.st_uid != 0 && sb.st_uid != getuid()) ||
		    (sb.st_mode & 022) != 0))
			fatal("Bad owner or permissions on %s", filename);
	}

	debug("Reading configuration data %.200s", filename);

	/*
	 * Mark that we are now processing the options.  This flag is turned
	 * on/off by Host specifications.
	 */
	linenum = 0;
	जाव (getline(&पङ्क्तिः, &linesize, f) != -1) {
		/* Update line number counter. */
		linenum++;
		/*
		 * Trim out comments and strip whitespace.
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages.
		 */
		जइ (process_config_पङ्क्तिः_depth(options, pw, host, original_host,
		    remote_command, पङ्क्तिः, filename, linenum, activep, flags,
		    want_final_pass, depth) != 0)
			bad_options++;
	}
	मुक्त(पङ्क्तिः);
	fclose(f);
	जइ (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
	प्रत्यागम 1;
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
पूर्णाङ्क
option_clear_or_none(ध्रुव वर्ण *o)
{
	प्रत्यागम o == रिक्त || strcasecmp(o, "none") == 0;
}

/*
 * Returns 1 if CanonicalizePermittedCNAMEs have been specified, 0 otherwise.
 * Allowed to be called on non-final configuration.
 */
पूर्णाङ्क
config_has_permitted_cnames(Options *options)
{
	जइ (options->अङ्कः_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].source_list, "none") == 0 &&
	    strcmp(options->permitted_cnames[0].target_list, "") == 0)
		प्रत्यागम 0;
	प्रत्यागम options->अङ्कः_permitted_cnames > 0;
}

/*
 * Initializes options to special values that indicate that they have not yet
 * been set.  Read_config_file will only set options with this value. Options
 * are processed in the following order: command line, user config file,
 * system config file.  Last, fill_default_options is called.
 */

शून्य
initialize_options(Options * options)
{
	memset(options, 'X', परिमाण(*options));
	options->host_arg = रिक्त;
	options->forward_agent = -1;
	options->forward_agent_sock_path = रिक्त;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = रिक्त;
	options->stdio_forward_port = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = रिक्त;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_mask = (mode_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = रिक्त;
	options->hostbased_authentication = -1;
	options->batch_mode = -1;
	options->check_host_ip = -1;
	options->strict_host_कुञ्चिका_checking = -1;
	options->compression = -1;
	options->tcp_keep_alive = -1;
	options->port = -1;
	options->address_family = -1;
	options->connection_attempts = -1;
	options->connection_timeout = -1;
	options->सङ्ख्या_of_password_prompts = -1;
	options->ciphers = रिक्त;
	options->macs = रिक्त;
	options->kex_algorithms = रिक्त;
	options->hostkeyalgorithms = रिक्त;
	options->ca_sign_algorithms = रिक्त;
	options->अङ्कः_identity_files = 0;
	memset(options->identity_कुञ्चिकाः, 0, परिमाण(options->identity_कुञ्चिकाः));
	options->अङ्कः_certificate_files = 0;
	memset(options->certificates, 0, परिमाण(options->certificates));
	options->hostname = रिक्त;
	options->host_कुञ्चिका_alias = रिक्त;
	options->proxy_command = रिक्त;
	options->jump_user = रिक्त;
	options->jump_host = रिक्त;
	options->jump_port = -1;
	options->jump_extra = रिक्त;
	options->user = रिक्त;
	options->escape_char = -1;
	options->अङ्कः_system_hostfiles = 0;
	options->अङ्कः_user_hostfiles = 0;
	options->local_forwards = रिक्त;
	options->अङ्कः_local_forwards = 0;
	options->remote_forwards = रिक्त;
	options->अङ्कः_remote_forwards = 0;
	options->permitted_remote_opens = रिक्त;
	options->अङ्कः_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
	options->log_level = SYSLOG_LEVEL_NOT_SET;
	options->अङ्कः_log_verbose = 0;
	options->log_verbose = रिक्त;
	options->preferred_authentications = रिक्त;
	options->bind_address = रिक्त;
	options->bind_interface = रिक्त;
	options->pkcs11_provider = रिक्त;
	options->sk_provider = रिक्त;
	options->enable_ssh_keysign = -1;
	options->no_host_authentication_for_localhost = -1;
	options->identities_only = -1;
	options->rekey_limit = -1;
	options->rekey_interval = -1;
	options->verify_host_कुञ्चिका_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_गणनम्_max = -1;
	options->send_env = रिक्त;
	options->अङ्कः_send_env = 0;
	options->setenv = रिक्त;
	options->अङ्कः_setenv = 0;
	options->control_path = रिक्त;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_known_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = रिक्त;
	options->permit_local_command = -1;
	options->remote_command = रिक्त;
	options->add_कुञ्चिकाः_to_agent = -1;
	options->add_कुञ्चिकाः_to_agent_lifespan = -1;
	options->identity_agent = रिक्त;
	options->visual_host_कुञ्चिका = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = रिक्त;
	options->अङ्कः_canonical_domains = 0;
	options->अङ्कः_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_कुञ्चिकाः = रिक्त;
	options->अङ्कः_revoked_host_कुञ्चिकाः = 0;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->hostbased_accepted_algos = रिक्त;
	options->pubkey_accepted_algos = रिक्त;
	options->known_hosts_command = रिक्त;
	options->required_rsa_size = -1;
	options->warn_weak_crypto = -1;
	options->enable_escape_commandline = -1;
	options->obscure_keystroke_timing_interval = -1;
	options->tag = रिक्त;
	options->channel_timeouts = रिक्त;
	options->अङ्कः_channel_timeouts = 0;
	options->version_addendum = रिक्त;
}

/*
 * A petite version of fill_default_options() that just fills the options
 * needed for hostname canonicalization to proceed.
 */
शून्य
fill_default_options_for_canonicalization(Options *options)
{
	जइ (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	जइ (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	जइ (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
}

/*
 * Called after processing other sources of option data, this fills those
 * options for which no value has been specified with their default values.
 */
पूर्णाङ्क
fill_default_options(Options * options)
{
	वर्ण *all_cipher, *all_mac, *all_kex, *all_कुञ्चिका, *all_sig;
	वर्ण *def_cipher, *def_mac, *def_kex, *def_कुञ्चिका, *def_sig;
	पूर्णाङ्क ret = -1, r;

	जइ (options->forward_agent == -1)
		options->forward_agent = 0;
	जइ (options->forward_x11 == -1)
		options->forward_x11 = 0;
	जइ (options->forward_x11_trusted == -1)
		options->forward_x11_trusted = 0;
	जइ (options->forward_x11_timeout == -1)
		options->forward_x11_timeout = 1200;
	/*
	 * stdio forwarding (-W) changes the default for these but we defer
	 * setting the values so they can be overridden.
	 */
	जइ (options->exit_on_forward_failure == -1)
		options->exit_on_forward_failure =
		    options->stdio_forward_host != रिक्त ? 1 : 0;
	जइ (options->clear_forwardings == -1)
		options->clear_forwardings =
		    options->stdio_forward_host != रिक्त ? 1 : 0;
	जइ (options->clear_forwardings == 1)
		clear_forwardings(options);

	जइ (options->xauth_location == रिक्त)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	जइ (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	जइ (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	जइ (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	जइ (options->pubkey_authentication == -1)
		options->pubkey_authentication = SSH_PUBKEY_AUTH_ALL;
	जइ (options->gss_authentication == -1)
		options->gss_authentication = 0;
	जइ (options->gss_deleg_creds == -1)
		options->gss_deleg_creds = 0;
	जइ (options->password_authentication == -1)
		options->password_authentication = 1;
	जइ (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	जइ (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	जइ (options->batch_mode == -1)
		options->batch_mode = 0;
	जइ (options->check_host_ip == -1)
		options->check_host_ip = 0;
	जइ (options->strict_host_कुञ्चिका_checking == -1)
		options->strict_host_कुञ्चिका_checking = SSH_STRICT_HOSTKEY_ASK;
	जइ (options->compression == -1)
		options->compression = 0;
	जइ (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = SSH_KEEPALIVES_TRANSPORT;
	जइ (options->port == -1)
		options->port = 0;	/* Filled in ssh_connect. */
	जइ (options->address_family == -1)
		options->address_family = AF_UNSPEC;
	जइ (options->connection_attempts == -1)
		options->connection_attempts = 1;
	जइ (options->सङ्ख्या_of_password_prompts == -1)
		options->सङ्ख्या_of_password_prompts = 3;
	/* options->hostkeyalgorithms, default set in myproposals.h */
	जइ (options->add_कुञ्चिकाः_to_agent == -1) {
		options->add_कुञ्चिकाः_to_agent = 0;
		options->add_कुञ्चिकाः_to_agent_lifespan = 0;
	}
	जइ (options->अङ्कः_identity_files == 0) {
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
	जइ (options->escape_char == -1)
		options->escape_char = '~';
	जइ (options->अङ्कः_system_hostfiles == 0) {
		options->system_hostfiles[options->अङ्कः_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->अङ्कः_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE2);
	}
	जइ (options->update_hostkeys == -1) {
		जइ (options->verify_host_कुञ्चिका_dns <= 0 &&
		    (options->अङ्कः_user_hostfiles == 0 ||
		    (options->अङ्कः_user_hostfiles == 1 && strcmp(options->
		    user_hostfiles[0], _PATH_SSH_USER_HOSTFILE) == 0)))
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_YES;
		अण्णहा
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_NO;
	}
	जइ (options->अङ्कः_user_hostfiles == 0) {
		options->user_hostfiles[options->अङ्कः_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->अङ्कः_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE2);
	}
	जइ (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	जइ (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_USER;
	जइ (options->no_host_authentication_for_localhost == -1)
		options->no_host_authentication_for_localhost = 0;
	जइ (options->identities_only == -1)
		options->identities_only = 0;
	जइ (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	जइ (options->rekey_limit == -1)
		options->rekey_limit = 0;
	जइ (options->rekey_interval == -1)
		options->rekey_interval = 0;
	जइ (options->verify_host_कुञ्चिका_dns == -1)
		options->verify_host_कुञ्चिका_dns = 0;
	जइ (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	जइ (options->server_alive_गणनम्_max == -1)
		options->server_alive_गणनम्_max = 3;
	जइ (options->control_master == -1)
		options->control_master = 0;
	जइ (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	जइ (options->hash_known_hosts == -1)
		options->hash_known_hosts = 0;
	जइ (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	जइ (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	जइ (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	जइ (options->permit_local_command == -1)
		options->permit_local_command = 0;
	जइ (options->visual_host_कुञ्चिका == -1)
		options->visual_host_कुञ्चिका = 0;
	जइ (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	जइ (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	जइ (options->request_tty == -1)
		options->request_tty = REQUEST_TTY_AUTO;
	जइ (options->session_type == -1)
		options->session_type = SESSION_TYPE_DEFAULT;
	जइ (options->stdin_null == -1)
		options->stdin_null = 0;
	जइ (options->fork_after_authentication == -1)
		options->fork_after_authentication = 0;
	जइ (options->proxy_use_fdpass == -1)
		options->proxy_use_fdpass = 0;
	जइ (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	जइ (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	जइ (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
	जइ (options->fingerprint_hash == -1)
		options->fingerprint_hash = SSH_FP_HASH_DEFAULT;
#ifdef ENABLE_SK_INTERNAL
	जइ (options->sk_provider == रिक्त)
		options->sk_provider = xstrdup("internal");
#अण्णहा
	जइ (options->sk_provider == रिक्त)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
#endif
	जइ (options->required_rsa_size == -1)
		options->required_rsa_size = SSH_RSA_MINIMUM_MODULUS_SIZE;
	जइ (options->warn_weak_crypto == -1)
		options->warn_weak_crypto = 1;
	जइ (options->enable_escape_commandline == -1)
		options->enable_escape_commandline = 0;
	जइ (options->obscure_keystroke_timing_interval == -1) {
		options->obscure_keystroke_timing_interval =
		    SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
	}

	/* Expand KEX name lists */
	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_कुञ्चिका = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_CLIENT_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_CLIENT_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_CLIENT_KEX, all_kex);
	def_कुञ्चिका = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_कुञ्चिका);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#define ASSEMBLE(what, defaults, all) \
	करेहि { \
		जइ ((r = kex_assemble_names(&options->what, \
		    defaults, all)) != 0) { \
			error_fr(r, "%s", #what); \
			गच्छ fail; \
		} \
	} जाव (0)
	options->kex_algorithms_set = options->kex_algorithms != रिक्त;
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostbased_accepted_algos, def_कुञ्चिका, all_कुञ्चिका);
	ASSEMBLE(pubkey_accepted_algos, def_कुञ्चिका, all_कुञ्चिका);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#undef ASSEMBLE

#define CLEAR_ON_NONE(v) \
	करेहि { \
		जइ (option_clear_or_none(v)) { \
			मुक्त(v); \
			v = रिक्त; \
		} \
	} जाव(0)
#define CLEAR_ON_NONE_ARRAY(v, nv, none) \
	करेहि { \
		जइ (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			मुक्त(options->v[0]); \
			मुक्त(options->v); \
			options->v = रिक्त; \
			options->nv = 0; \
		} \
	} जाव (0)
	CLEAR_ON_NONE(options->local_command);
	CLEAR_ON_NONE(options->remote_command);
	CLEAR_ON_NONE(options->proxy_command);
	CLEAR_ON_NONE(options->control_path);
	CLEAR_ON_NONE(options->pkcs11_provider);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->known_hosts_command);
	CLEAR_ON_NONE_ARRAY(channel_timeouts, अङ्कः_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(revoked_host_कुञ्चिकाः, अङ्कः_revoked_host_कुञ्चिकाः, "none");
#undef CLEAR_ON_NONE
#undef CLEAR_ON_NONE_ARRAY
	जइ (options->jump_host != रिक्त &&
	    strcmp(options->jump_host, "none") == 0 &&
	    options->jump_port == 0 && options->jump_user == रिक्त) {
		मुक्त(options->jump_host);
		options->jump_host = रिक्त;
	}
	जइ (options->अङ्कः_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		मुक्त(options->permitted_cnames[0].source_list);
		मुक्त(options->permitted_cnames[0].target_list);
		memset(options->permitted_cnames, '\0',
		    परिमाण(*options->permitted_cnames));
		options->अङ्कः_permitted_cnames = 0;
	}
	/* options->identity_agent distinguishes NULL from 'none' */
	/* options->user will be set in the main program if appropriate */
	/* options->hostname will be set in the main program if appropriate */
	/* options->host_key_alias should not be set by default */
	/* options->preferred_authentications will be set in ssh */

	/* success */
	ret = 0;
 fail:
	मुक्त(all_cipher);
	मुक्त(all_mac);
	मुक्त(all_kex);
	मुक्त(all_कुञ्चिका);
	मुक्त(all_sig);
	मुक्त(def_cipher);
	मुक्त(def_mac);
	मुक्त(def_kex);
	मुक्त(def_कुञ्चिका);
	मुक्त(def_sig);
	प्रत्यागम ret;
}

शून्य
free_options(Options *o)
{
	पूर्णाङ्क i;

	जइ (o == रिक्त)
		प्रत्यागम;

#define FREE_ARRAY(type, n, a) \
	करेहि { \
		type _i; \
		प्रति (_i = 0; _i < (n); _i++) \
			मुक्त((a)[_i]); \
	} जाव (0)

	मुक्त(o->forward_agent_sock_path);
	मुक्त(o->xauth_location);
	FREE_ARRAY(u_int, o->अङ्कः_log_verbose, o->log_verbose);
	मुक्त(o->log_verbose);
	मुक्त(o->ciphers);
	मुक्त(o->macs);
	मुक्त(o->hostkeyalgorithms);
	मुक्त(o->kex_algorithms);
	मुक्त(o->ca_sign_algorithms);
	मुक्त(o->hostname);
	मुक्त(o->host_कुञ्चिका_alias);
	मुक्त(o->proxy_command);
	मुक्त(o->user);
	FREE_ARRAY(u_int, o->अङ्कः_system_hostfiles, o->system_hostfiles);
	FREE_ARRAY(u_int, o->अङ्कः_user_hostfiles, o->user_hostfiles);
	मुक्त(o->preferred_authentications);
	मुक्त(o->bind_address);
	मुक्त(o->bind_interface);
	मुक्त(o->pkcs11_provider);
	मुक्त(o->sk_provider);
	प्रति (i = 0; i < o->अङ्कः_identity_files; i++) {
		मुक्त(o->identity_files[i]);
		sshkey_free(o->identity_कुञ्चिकाः[i]);
	}
	प्रति (i = 0; i < o->अङ्कः_certificate_files; i++) {
		मुक्त(o->certificate_files[i]);
		sshkey_free(o->certificates[i]);
	}
	मुक्त(o->identity_agent);
	प्रति (i = 0; i < o->अङ्कः_local_forwards; i++) {
		मुक्त(o->local_forwards[i].listen_host);
		मुक्त(o->local_forwards[i].listen_path);
		मुक्त(o->local_forwards[i].connect_host);
		मुक्त(o->local_forwards[i].connect_path);
	}
	मुक्त(o->local_forwards);
	प्रति (i = 0; i < o->अङ्कः_remote_forwards; i++) {
		मुक्त(o->remote_forwards[i].listen_host);
		मुक्त(o->remote_forwards[i].listen_path);
		मुक्त(o->remote_forwards[i].connect_host);
		मुक्त(o->remote_forwards[i].connect_path);
	}
	मुक्त(o->remote_forwards);
	मुक्त(o->stdio_forward_host);
	FREE_ARRAY(u_int, o->अङ्कः_send_env, o->send_env);
	मुक्त(o->send_env);
	FREE_ARRAY(u_int, o->अङ्कः_setenv, o->setenv);
	मुक्त(o->setenv);
	मुक्त(o->control_path);
	मुक्त(o->local_command);
	मुक्त(o->remote_command);
	FREE_ARRAY(पूर्णाङ्क, o->अङ्कः_canonical_domains, o->canonical_domains);
	प्रति (i = 0; i < o->अङ्कः_permitted_cnames; i++) {
		मुक्त(o->permitted_cnames[i].source_list);
		मुक्त(o->permitted_cnames[i].target_list);
	}
	FREE_ARRAY(u_int, o->अङ्कः_revoked_host_कुञ्चिकाः, o->revoked_host_कुञ्चिकाः);
	मुक्त(o->revoked_host_कुञ्चिकाः);
	मुक्त(o->hostbased_accepted_algos);
	मुक्त(o->pubkey_accepted_algos);
	मुक्त(o->jump_user);
	मुक्त(o->jump_host);
	मुक्त(o->jump_extra);
	मुक्त(o->ignored_unknown);
	explicit_bzero(o, परिमाण(*o));
#undef FREE_ARRAY
}

संरचना fwdarg {
	वर्ण *arg;
	पूर्णाङ्क ispath;
};

/*
 * parse_fwd_field
 * parses the next field in a port forwarding specification.
 * sets fwd to the parsed field and advances p past the colon
 * or sets it to NULL at end of string.
 * returns 0 on success, else non-zero.
 */
स्थिर पूर्णाङ्क
parse_fwd_field(वर्ण **p, संरचना fwdarg *fwd)
{
	वर्ण *ep, *cp = *p;
	पूर्णाङ्क ispath = 0;

	जइ (*cp == '\0') {
		*p = रिक्त;
		प्रत्यागम -1;	/* end of string */
	}

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	जइ (*cp == '[') {
		/* find matching ']' */
		प्रति (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++) {
			जइ (*ep == '/')
				ispath = 1;
		}
		/* no matching ']' or not at end of field. */
		जइ (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			प्रत्यागम -1;
		/* NUL terminate the field and advance p past the colon */
		*ep++ = '\0';
		जइ (*ep != '\0')
			*ep++ = '\0';
		fwd->arg = cp + 1;
		fwd->ispath = ispath;
		*p = ep;
		प्रत्यागम 0;
	}

	प्रति (cp = *p; *cp != '\0'; cp++) {
		विकल्प (*cp) {
		पक्ष '\\':
			memmove(cp, cp + 1, strlen(cp + 1) + 1);
			जइ (*cp == '\0')
				प्रत्यागम -1;
			भङ्ग;
		पक्ष '/':
			ispath = 1;
			भङ्ग;
		पक्ष ':':
			*cp++ = '\0';
			गच्छ done;
		}
	}
done:
	fwd->arg = *p;
	fwd->ispath = ispath;
	*p = cp;
	प्रत्यागम 0;
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
पूर्णाङ्क
parse_forward(संरचना Forward *fwd, ध्रुव वर्ण *fwdspec, पूर्णाङ्क dynamicfwd, पूर्णाङ्क remotefwd)
{
	संरचना fwdarg fwdargs[4];
	वर्ण *p, *cp;
	पूर्णाङ्क i, err;

	memset(fwd, 0, परिमाण(*fwd));
	memset(fwdargs, 0, परिमाण(fwdargs));

	/*
	 * We expand environment variables before checking if we think they're
	 * paths so that if ${VAR} expands to a fully qualified path it is
	 * treated as a path.
	 */
	cp = p = dollar_expand(&err, fwdspec);
	जइ (p == रिक्त || err)
		प्रत्यागम 0;

	/* skip leading spaces */
	जाव (isspace((u_char)*cp))
		cp++;

	प्रति (i = 0; i < 4; ++i) {
		जइ (parse_fwd_field(&cp, &fwdargs[i]) != 0)
			भङ्ग;
	}

	/* Check for trailing garbage */
	जइ (cp != रिक्त && *cp != '\0') {
		i = 0;	/* failure */
	}

	विकल्प (i) {
	पक्ष 1:
		जइ (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
		} अण्णहा {
			fwd->listen_host = रिक्त;
			fwd->listen_port = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		भङ्ग;

	पक्ष 2:
		जइ (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} अण्णहा जइ (fwdargs[1].ispath) {
			fwd->listen_host = रिक्त;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} अण्णहा {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		भङ्ग;

	पक्ष 3:
		जइ (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		} अण्णहा जइ (fwdargs[2].ispath) {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_path = xstrdup(fwdargs[2].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} अण्णहा {
			fwd->listen_host = रिक्त;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		}
		भङ्ग;

	पक्ष 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_port = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_port = a2port(fwdargs[3].arg);
		भङ्ग;
	स्वभाव:
		i = 0; /* failure */
	}

	मुक्त(p);

	जइ (dynamicfwd) {
		जइ (!(i == 1 || i == 2))
			गच्छ fail_free;
	} अण्णहा {
		जइ (!(i == 3 || i == 4)) {
			जइ (fwd->connect_path == रिक्त &&
			    fwd->listen_path == रिक्त)
				गच्छ fail_free;
		}
		जइ (fwd->connect_port <= 0 && fwd->connect_path == रिक्त)
			गच्छ fail_free;
	}

	जइ ((fwd->listen_port < 0 && fwd->listen_path == रिक्त) ||
	    (!remotefwd && fwd->listen_port == 0))
		गच्छ fail_free;
	जइ (fwd->connect_host != रिक्त &&
	    strlen(fwd->connect_host) >= NI_MAXHOST)
		गच्छ fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	जइ (fwd->connect_path != रिक्त &&
	    strlen(fwd->connect_path) >= PATH_MAX_SUN)
		गच्छ fail_free;
	जइ (fwd->listen_host != रिक्त &&
	    strlen(fwd->listen_host) >= NI_MAXHOST)
		गच्छ fail_free;
	जइ (fwd->listen_path != रिक्त &&
	    strlen(fwd->listen_path) >= PATH_MAX_SUN)
		गच्छ fail_free;

	प्रत्यागम (i);

 fail_free:
	मुक्त(fwd->connect_host);
	fwd->connect_host = रिक्त;
	मुक्त(fwd->connect_path);
	fwd->connect_path = रिक्त;
	मुक्त(fwd->listen_host);
	fwd->listen_host = रिक्त;
	मुक्त(fwd->listen_path);
	fwd->listen_path = रिक्त;
	प्रत्यागम (0);
}

पूर्णाङ्क
ssh_valid_hostname(ध्रुव वर्ण *s)
{
	size_t i;

	जइ (*s == '-')
		प्रत्यागम 0;
	प्रति (i = 0; s[i] != 0; i++) {
		जइ (strchr("'`\"$\\;&<>|(){},", s[i]) != रिक्त ||
		    isspace((u_char)s[i]) || iscntrl((u_char)s[i]))
			प्रत्यागम 0;
	}
	प्रत्यागम 1;
}

पूर्णाङ्क
ssh_valid_ruser(ध्रुव वर्ण *s)
{
	size_t i;

	जइ (*s == '-')
		प्रत्यागम 0;
	प्रति (i = 0; s[i] != 0; i++) {
		जइ (iscntrl((u_char)s[i]))
			प्रत्यागम 0;
		जइ (strchr("'`\";&<>|(){}$\\", s[i]) != रिक्त)
			प्रत्यागम 0;
		/* Disallow '-' after whitespace */
		जइ (isspace((u_char)s[i]) && s[i + 1] == '-')
			प्रत्यागम 0;
	}
	प्रत्यागम 1;
}

पूर्णाङ्क
parse_jump(ध्रुव वर्ण *s, Options *o, पूर्णाङ्क strict, पूर्णाङ्क active)
{
	वर्ण *orig = रिक्त, *sdup = रिक्त, *cp;
	वर्ण *tmp_user = रिक्त, *tmp_host = रिक्त, *host = रिक्त, *user = रिक्त;
	पूर्णाङ्क r, ret = -1, tmp_port = -1, port = -1, first = 1;

	जइ (strcasecmp(s, "none") == 0) {
		जइ (active && o->jump_host == रिक्त) {
			o->jump_host = xstrdup("none");
			o->jump_port = 0;
		}
		प्रत्यागम 0;
	}

	orig = xstrdup(s);
	जइ ((cp = strchr(orig, '#')) != रिक्त)
		*cp = '\0';
	rtrim(orig);

	active &= o->proxy_command == रिक्त && o->jump_host == रिक्त;
	sdup = xstrdup(orig);
	करेहि {
		/* Work backwards through string */
		जइ ((cp = strrchr(sdup, ',')) == रिक्त)
			cp = sdup; /* last */
		अण्णहा
			*cp++ = '\0';

		r = parse_ssh_uri(cp, &tmp_user, &tmp_host, &tmp_port);
		जइ (r == -1 || (r == 1 && parse_user_host_port(cp,
		    &tmp_user, &tmp_host, &tmp_port) != 0))
			गच्छ out; /* error already logged */
		जइ (strict) {
			जइ (!ssh_valid_hostname(tmp_host)) {
				error_f("invalid hostname \"%s\"", tmp_host);
				गच्छ out;
			}
			जइ (tmp_user != रिक्त && !ssh_valid_ruser(tmp_user)) {
				error_f("invalid username \"%s\"", tmp_user);
				गच्छ out;
			}
		}
		जइ (first) {
			user = tmp_user;
			host = tmp_host;
			port = tmp_port;
			tmp_user = tmp_host = रिक्त; /* transferred */
		}
		first = 0; /* only check syntax for subsequent hosts */
		मुक्त(tmp_user);
		मुक्त(tmp_host);
		tmp_user = tmp_host = रिक्त;
		tmp_port = -1;
	} जाव (cp != sdup);

	/* success */
	जइ (active) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_port = port;
		o->proxy_command = xstrdup("none");
		user = host = रिक्त; /* transferred */
		जइ (orig != रिक्त && (cp = strrchr(orig, ',')) != रिक्त) {
			o->jump_extra = xstrdup(orig);
			o->jump_extra[cp - orig] = '\0';
		}
	}
	ret = 0;
 out:
	मुक्त(orig);
	मुक्त(sdup);
	मुक्त(tmp_user);
	मुक्त(tmp_host);
	मुक्त(user);
	मुक्त(host);
	प्रत्यागम ret;
}

पूर्णाङ्क
parse_ssh_uri(ध्रुव वर्ण *uri, वर्ण **userp, वर्ण **hostp, पूर्णाङ्क *portp)
{
	वर्ण *user = रिक्त, *host = रिक्त, *path = रिक्त;
	पूर्णाङ्क r, port;

	r = parse_uri("ssh", uri, &user, &host, &port, &path);
	जइ (r == 0 && path != रिक्त)
		r = -1;		/* path not allowed */
	जइ (r == 0) {
		जइ (userp != रिक्त) {
			*userp = user;
			user = रिक्त;
		}
		जइ (hostp != रिक्त) {
			*hostp = host;
			host = रिक्त;
		}
		जइ (portp != रिक्त)
			*portp = port;
	}
	मुक्त(user);
	मुक्त(host);
	मुक्त(path);
	प्रत्यागम r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
स्थिर ध्रुव वर्ण *
fmt_multistate_int(पूर्णाङ्क val, ध्रुव संरचना multistate *m)
{
	u_int i;

	प्रति (i = 0; m[i].कुञ्चिका != रिक्त; i++) {
		जइ (m[i].मानम् == val)
			प्रत्यागम m[i].कुञ्चिका;
	}
	प्रत्यागम "UNKNOWN";
}

स्थिर ध्रुव वर्ण *
fmt_intarg(OpCodes code, पूर्णाङ्क val)
{
	जइ (val == -1)
		प्रत्यागम "unset";
	विकल्प (code) {
	पक्ष oAddressFamily:
		प्रत्यागम fmt_multistate_int(val, multistate_addressfamily);
	पक्ष oCompression:
		प्रत्यागम fmt_multistate_int(val, multistate_compression);
	पक्ष o_Verify_Host_कुञ्चिका_DNS:
	पक्ष oUpdateHostkeys:
		प्रत्यागम fmt_multistate_int(val, multistate_yesnoask);
	पक्ष o_Strict_Host_कुञ्चिका_Checking:
		प्रत्यागम fmt_multistate_int(val, multistate_strict_hostkey);
	पक्ष oControlMaster:
		प्रत्यागम fmt_multistate_int(val, multistate_controlmaster);
	पक्ष oTunnel:
		प्रत्यागम fmt_multistate_int(val, multistate_tunnel);
	पक्ष oRequestTTY:
		प्रत्यागम fmt_multistate_int(val, multistate_requesttty);
	पक्ष oSessionType:
		प्रत्यागम fmt_multistate_int(val, multistate_sessiontype);
	पक्ष oCanonicalizeHostname:
		प्रत्यागम fmt_multistate_int(val, multistate_canonicalizehostname);
	पक्ष o_Add_कुञ्चिकाः_To_Agent:
		प्रत्यागम fmt_multistate_int(val, multistate_yesnoaskconfirm);
	पक्ष oPubkeyAuthentication:
		प्रत्यागम fmt_multistate_int(val, multistate_pubkey_auth);
	पक्ष oTCPKeepAlive:
		प्रत्यागम fmt_multistate_int(val, multistate_keepalives);
	पक्ष oFingerprintHash:
		प्रत्यागम ssh_digest_alg_name(val);
	स्वभाव:
		विकल्प (val) {
		पक्ष 0:
			प्रत्यागम "no";
		पक्ष 1:
			प्रत्यागम "yes";
		स्वभाव:
			प्रत्यागम "UNKNOWN";
		}
	}
}

स्थिर ध्रुव वर्ण *
lookup_opcode_name(OpCodes code)
{
	u_int i;

	प्रति (i = 0; keywords[i].name != रिक्त; i++)
		जइ (keywords[i].opcode == code)
			प्रत्यागम(keywords[i].name);
	प्रत्यागम "UNKNOWN";
}

स्थिर शून्य
dump_cfg_int(OpCodes code, पूर्णाङ्क val)
{
	जइ (code == oObscureKeystrokeTiming) {
		जइ (val == 0) {
			printf("%s no\n", lookup_opcode_name(code));
			प्रत्यागम;
		} अण्णहा जइ (val == SSH_KEYSTROKE_DEFAULT_INTERVAL_MS) {
			printf("%s yes\n", lookup_opcode_name(code));
			प्रत्यागम;
		}
		/* FALLTHROUGH */
	}
	printf("%s %d\n", lookup_opcode_name(code), val);
}

स्थिर शून्य
dump_cfg_fmtint(OpCodes code, पूर्णाङ्क val)
{
	printf("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

स्थिर शून्य
dump_cfg_string(OpCodes code, ध्रुव वर्ण *val)
{
	जइ (val == रिक्त)
		प्रत्यागम;
	printf("%s %s\n", lookup_opcode_name(code), val);
}

स्थिर शून्य
dump_cfg_strarray(OpCodes code, u_int गणनम्, वर्ण **vals)
{
	u_int i;

	प्रति (i = 0; i < गणनम्; i++)
		printf("%s %s\n", lookup_opcode_name(code), vals[i]);
}

स्थिर शून्य
dump_cfg_strarray_oneline(OpCodes code, u_int गणनम्, वर्ण **vals)
{
	u_int i;

	printf("%s", lookup_opcode_name(code));
	जइ (गणनम् == 0)
		printf(" none");
	प्रति (i = 0; i < गणनम्; i++)
		printf(" %s",  vals[i]);
	printf("\n");
}

स्थिर शून्य
dump_cfg_forwards(OpCodes code, u_int गणनम्, ध्रुव संरचना Forward *fwds)
{
	ध्रुव संरचना Forward *fwd;
	u_int i;

	/* oDynamicForward */
	प्रति (i = 0; i < गणनम्; i++) {
		fwd = &fwds[i];
		जइ (code == oDynamicForward && fwd->connect_host != रिक्त &&
		    strcmp(fwd->connect_host, "socks") != 0)
			अनुवर्त;
		जइ (code == oLocalForward && fwd->connect_host != रिक्त &&
		    strcmp(fwd->connect_host, "socks") == 0)
			अनुवर्त;
		printf("%s", lookup_opcode_name(code));
		जइ (fwd->listen_port == PORT_STREAMLOCAL)
			printf(" %s", fwd->listen_path);
		अण्णहा जइ (fwd->listen_host == रिक्त)
			printf(" %d", fwd->listen_port);
		अण्णहा {
			printf(" [%s]:%d",
			    fwd->listen_host, fwd->listen_port);
		}
		जइ (code != oDynamicForward) {
			जइ (fwd->connect_port == PORT_STREAMLOCAL)
				printf(" %s", fwd->connect_path);
			अण्णहा जइ (fwd->connect_host == रिक्त)
				printf(" %d", fwd->connect_port);
			अण्णहा {
				printf(" [%s]:%d",
				    fwd->connect_host, fwd->connect_port);
			}
		}
		printf("\n");
	}
}

शून्य
dump_client_config(Options *o, ध्रुव वर्ण *host)
{
	पूर्णाङ्क i, r;
	वर्ण buf[8], *all_कुञ्चिका;

	/*
	 * Expand HostKeyAlgorithms name lists. This isn't handled in
	 * fill_default_options() like the other algorithm lists because
	 * the host key algorithms are by default dynamically chosen based
	 * on the host's keys found in known_hosts.
	 */
	all_कुञ्चिका = sshkey_alg_list(0, 0, 1, ',');
	जइ ((r = kex_assemble_names(&o->hostkeyalgorithms, kex_default_pk_alg(),
	    all_कुञ्चिका)) != 0)
		fatal_fr(r, "expand HostKeyAlgorithms");
	मुक्त(all_कुञ्चिका);

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
	dump_cfg_fmtint(o_Strict_Host_कुञ्चिका_Checking, o->strict_host_कुञ्चिका_checking);
	dump_cfg_fmtint(oTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(oTunnel, o->tun_open);
	dump_cfg_fmtint(o_Verify_Host_कुञ्चिका_DNS, o->verify_host_कुञ्चिका_dns);
	dump_cfg_fmtint(o_Visual_Host_कुञ्चिका, o->visual_host_कुञ्चिका);
	dump_cfg_fmtint(oUpdateHostkeys, o->update_hostkeys);
	dump_cfg_fmtint(oEnableEscapeCommandline, o->enable_escape_commandline);
	dump_cfg_fmtint(oWarnWeakCrypto, o->warn_weak_crypto);

	/* Integer options */
	dump_cfg_int(oCanonicalizeMaxDots, o->canonicalize_max_dots);
	dump_cfg_int(oConnectionAttempts, o->connection_attempts);
	dump_cfg_int(oForwardX11Timeout, o->forward_x11_timeout);
	dump_cfg_int(o_सङ्ख्या_Of_Password_Prompts, o->सङ्ख्या_of_password_prompts);
	dump_cfg_int(o_Server_Alive_गणनम्_Max, o->server_alive_गणनम्_max);
	dump_cfg_int(oServerAliveInterval, o->server_alive_interval);
	dump_cfg_int(oRequiredRSASize, o->required_rsa_size);
	dump_cfg_int(oObscureKeystrokeTiming,
	    o->obscure_keystroke_timing_interval);

	/* String options */
	dump_cfg_string(oBindAddress, o->bind_address);
	dump_cfg_string(oBindInterface, o->bind_interface);
	dump_cfg_string(oCiphers, o->ciphers);
	dump_cfg_string(oControlPath, o->control_path);
	dump_cfg_string(o_Host_कुञ्चिका_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(o_Host_कुञ्चिका_Alias, o->host_कुञ्चिका_alias);
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
	dump_cfg_string(o_Security_कुञ्चिका_Provider, o->sk_provider);
	dump_cfg_string(oPreferredAuthentications, o->preferred_authentications);
	dump_cfg_string(oPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
	dump_cfg_string(oXAuthLocation, o->xauth_location);
	dump_cfg_string(oKnownHostsCommand, o->known_hosts_command);
	dump_cfg_string(oTag, o->tag);
	dump_cfg_string(oVersionAddendum, o->version_addendum);

	/* Forwards */
	dump_cfg_forwards(oDynamicForward, o->अङ्कः_local_forwards, o->local_forwards);
	dump_cfg_forwards(oLocalForward, o->अङ्कः_local_forwards, o->local_forwards);
	dump_cfg_forwards(oRemoteForward, o->अङ्कः_remote_forwards, o->remote_forwards);

	/* String array options */
	dump_cfg_strarray(oIdentityFile, o->अङ्कः_identity_files, o->identity_files);
	dump_cfg_strarray_oneline(oCanonicalDomains, o->अङ्कः_canonical_domains, o->canonical_domains);
	dump_cfg_strarray(oCertificateFile, o->अङ्कः_certificate_files, o->certificate_files);
	dump_cfg_strarray_oneline(oGlobalKnownHostsFile, o->अङ्कः_system_hostfiles, o->system_hostfiles);
	dump_cfg_strarray_oneline(oUserKnownHostsFile, o->अङ्कः_user_hostfiles, o->user_hostfiles);
	dump_cfg_strarray_oneline(o_Revoked_Host_कुञ्चिकाः, o->अङ्कः_revoked_host_कुञ्चिकाः, o->revoked_host_कुञ्चिकाः);
	dump_cfg_strarray(oSendEnv, o->अङ्कः_send_env, o->send_env);
	dump_cfg_strarray(oSetEnv, o->अङ्कः_setenv, o->setenv);
	dump_cfg_strarray_oneline(oLogVerbose,
	    o->अङ्कः_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(oChannelTimeout,
	    o->अङ्कः_channel_timeouts, o->channel_timeouts);

	/* Special cases */

	/* PermitRemoteOpen */
	जइ (o->अङ्कः_permitted_remote_opens == 0)
		printf("%s any\n", lookup_opcode_name(oPermitRemoteOpen));
	अण्णहा
		dump_cfg_strarray_oneline(oPermitRemoteOpen,
		    o->अङ्कः_permitted_remote_opens, o->permitted_remote_opens);

	/* AddKeysToAgent */
	जइ (o->add_कुञ्चिकाः_to_agent_lifespan <= 0)
		dump_cfg_fmtint(o_Add_कुञ्चिकाः_To_Agent, o->add_कुञ्चिकाः_to_agent);
	अण्णहा {
		printf("addkeystoagent%s %d\n",
		    o->add_कुञ्चिकाः_to_agent == 3 ? " confirm" : "",
		    o->add_कुञ्चिकाः_to_agent_lifespan);
	}

	/* oForwardAgent */
	जइ (o->forward_agent_sock_path == रिक्त)
		dump_cfg_fmtint(oForwardAgent, o->forward_agent);
	अण्णहा
		dump_cfg_string(oForwardAgent, o->forward_agent_sock_path);

	/* oConnectTimeout */
	जइ (o->connection_timeout == -1)
		printf("connecttimeout none\n");
	अण्णहा
		dump_cfg_int(oConnectTimeout, o->connection_timeout);

	/* oTunnelDevice */
	printf("tunneldevice");
	जइ (o->tun_local == SSH_TUNID_ANY)
		printf(" any");
	अण्णहा
		printf(" %d", o->tun_local);
	जइ (o->tun_remote == SSH_TUNID_ANY)
		printf(":any");
	अण्णहा
		printf(":%d", o->tun_remote);
	printf("\n");

	/* oCanonicalizePermittedCNAMEs */
	printf("canonicalizepermittedcnames");
	जइ (o->अङ्कः_permitted_cnames == 0)
		printf(" none");
	प्रति (i = 0; i < o->अङ्कः_permitted_cnames; i++) {
		printf(" %s:%s", o->permitted_cnames[i].source_list,
		    o->permitted_cnames[i].target_list);
	}
	printf("\n");

	/* oControlPersist */
	जइ (o->control_persist == 0 || o->control_persist_timeout == 0)
		dump_cfg_fmtint(oControlPersist, o->control_persist);
	अण्णहा
		dump_cfg_int(oControlPersist, o->control_persist_timeout);

	/* oEscapeChar */
	जइ (o->escape_char == SSH_ESCAPECHAR_NONE)
		printf("escapechar none\n");
	अण्णहा {
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
	जइ (o->jump_host == रिक्त)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	अण्णहा {
		/* Check for numeric addresses */
		i = strchr(o->jump_host, ':') != रिक्त ||
		    strspn(o->jump_host, "1234567890.") == strlen(o->jump_host);
		snprintf(buf, परिमाण(buf), "%d", o->jump_port);
		printf("proxyjump %s%s%s%s%s%s%s%s%s\n",
		    /* optional additional jump spec */
		    o->jump_extra == रिक्त ? "" : o->jump_extra,
		    o->jump_extra == रिक्त ? "" : ",",
		    /* optional user */
		    o->jump_user == रिक्त ? "" : o->jump_user,
		    o->jump_user == रिक्त ? "" : "@",
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
