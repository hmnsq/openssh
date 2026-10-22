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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/stat.h>
#समावेश <sys/socket.h>
#समावेश <sys/wait.h>
#समावेश <sys/un.h>

#समावेश <net/if.h>
#समावेश <netinet/in.h>
#समावेश <netinet/ip.h>
#समावेश <arpa/inet.h>

#समावेश <ctype.h>
#समावेश <errno.h>
#समावेश <glob.h>
#समावेश <ifaddrs.h>
#समावेश <limits.h>
#समावेश <netdb.h>
#समावेश <paths.h>
#समावेश <pwd.h>
#समावेश <signal.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <stdarg.h>
#समावेश <unistd.h>
#समावेश <util.h>
#अगर defined(HAVE_STRNVIS) && defined(HAVE_VIS_H) && !defined(BROKEN_STRNVIS)
# include <vis.h>
#पूर्ण_अगर

#समावेश "xmalloc.h"
#समावेश "ssh.h"
#समावेश "cipher.h"
#समावेश "pathnames.h"
#समावेश "log.h"
#समावेश "sshkey.h"
#समावेश "misc.h"
#समावेश "readconf.h"
#समावेश "match.h"
#समावेश "kex.h"
#समावेश "mac.h"
#समावेश "myproposal.h"
#समावेश "digest.h"
#समावेश "version.h"

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

अटल पूर्णांक read_config_file_depth(स्थिर अक्षर *filename, काष्ठा passwd *pw,
    स्थिर अक्षर *host, स्थिर अक्षर *original_host, स्थिर अक्षर *remote_command,
    Options *options, पूर्णांक flags, पूर्णांक *activep, पूर्णांक *want_final_pass, पूर्णांक depth);
अटल पूर्णांक process_config_पंक्ति_depth(Options *options, काष्ठा passwd *pw,
    स्थिर अक्षर *host, स्थिर अक्षर *original_host, स्थिर अक्षर *remote_command,
    अक्षर *पंक्ति, स्थिर अक्षर *filename, पूर्णांक linenum, पूर्णांक *activep, पूर्णांक flags,
    पूर्णांक *want_final_pass, पूर्णांक depth);

/* Keyword tokens. */

प्रकार क्रमागत {
	oBadOption,
	oHost, oMatch, oInclude, oTag,
	oForwardAgent, oForwardX11, oForwardX11Trusted, oForwardX11Timeout,
	oGatewayPorts, oExitOnForwardFailure,
	oPasswordAuthentication,
	oXAuthLocation,
	oIdentityFile, oHostname, oPort, oRemoteForward, oLocalForward,
	oPermitRemoteOpen,
	oCertificateFile, o_Add_कुंजियाँ_To_Agent, oIdentityAgent,
	oUser, oEscapeChar, oProxyCommand,
	oGlobalKnownHostsFile, oUserKnownHostsFile, oConnectionAttempts,
	oBatchMode, oCheckHostIP, o_Strict_Host_कुंजी_Checking, oCompression,
	oTCPKeepAlive, o_संख्या_Of_Password_Prompts,
	oLogFacility, oLogLevel, oLogVerbose, oCiphers, oMacs,
	oPubkeyAuthentication,
	oKbdInteractiveAuthentication, oKbdInteractiveDevices, o_Host_कुंजी_Alias,
	oDynamicForward, oPreferredAuthentications, oHostbasedAuthentication,
	o_Host_कुंजी_Algorithms, oBindAddress, oBindInterface, oPKCS11Provider,
	oClearAllForwardings, oNoHostAuthenticationForLocalhost,
	oEnableSSHKeysign, oRekeyLimit, o_Verify_Host_कुंजी_DNS, oConnectTimeout,
	oAddressFamily, oGssAuthentication, oGssDelegateCreds,
	oServerAliveInterval, o_Server_Alive_गिनती_Max, oIdentitiesOnly,
	oSendEnv, oSetEnv, oControlPath, oControlMaster, oControlPersist,
	oHashKnownHosts,
	oTunnel, oTunnelDevice,
	oLocalCommand, oPermitLocalCommand, oRemoteCommand,
	o_Visual_Host_कुंजी,
	oKexAlgorithms, oIPQoS, oRequestTTY, oSessionType, oStdinNull,
	oForkAfterAuthentication, oIgnoreUnknown, oProxyUseFdpass,
	oCanonicalDomains, oCanonicalizeHostname, oCanonicalizeMaxDots,
	oCanonicalizeFallbackLocal, oCanonicalizePermittedCNAMEs,
	oStreamLocalBindMask, oStreamLocalBindUnlink, o_Revoked_Host_कुंजियाँ,
	oFingerprintHash, oUpdateHostkeys, oHostbasedAcceptedAlgorithms,
	oPubkeyAcceptedAlgorithms, oCASignatureAlgorithms, oProxyJump,
	o_Security_कुंजी_Provider, oKnownHostsCommand, oRequiredRSASize,
	oEnableEscapeCommandline, oObscureKeystrokeTiming, oChannelTimeout,
	oVersionAddendum, oRefuseConnection, oWarnWeakCrypto,
	oIgnore, oIgnoredUnknownOption, oDeprecated, oUnsupported
} OpCodes;

/* Textual representations of the tokens. */

अटल काष्ठा {
	स्थिर अक्षर *name;
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
#अगर defined(GSSAPI)
	{ "gssapiauthentication", oGssAuthentication },
	{ "gssapidelegatecredentials", oGssDelegateCreds },
# अन्यथा
	{ "gssapiauthentication", oUnsupported },
	{ "gssapidelegatecredentials", oUnsupported },
#पूर्ण_अगर
#अगर_घोषित ENABLE_PKCS11
	{ "pkcs11provider", oPKCS11Provider },
	{ "smartcarddevice", oPKCS11Provider },
# अन्यथा
	{ "smartcarddevice", oUnsupported },
	{ "pkcs11provider", oUnsupported },
#पूर्ण_अगर

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
	{ "addkeystoagent", o_Add_कुंजियाँ_To_Agent },
	{ "identityagent", oIdentityAgent },
	{ "hostname", oHostname },
	{ "hostkeyalias", o_Host_कुंजी_Alias },
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
	{ "stricthostkeychecking", o_Strict_Host_कुंजी_Checking },
	{ "compression", oCompression },
	{ "tcpkeepalive", oTCPKeepAlive },
	{ "keepalive", oTCPKeepAlive },				/* obsolete */
	{ "numberofpasswordprompts", o_संख्या_Of_Password_Prompts },
	{ "syslogfacility", oLogFacility },
	{ "loglevel", oLogLevel },
	{ "logverbose", oLogVerbose },
	{ "dynamicforward", oDynamicForward },
	{ "preferredauthentications", oPreferredAuthentications },
	{ "hostkeyalgorithms", o_Host_कुंजी_Algorithms },
	{ "casignaturealgorithms", oCASignatureAlgorithms },
	{ "bindaddress", oBindAddress },
	{ "bindinterface", oBindInterface },
	{ "clearallforwardings", oClearAllForwardings },
	{ "enablesshkeysign", oEnableSSHKeysign },
	{ "verifyhostkeydns", o_Verify_Host_कुंजी_DNS },
	{ "nohostauthenticationforlocalhost", oNoHostAuthenticationForLocalhost },
	{ "rekeylimit", oRekeyLimit },
	{ "connecttimeout", oConnectTimeout },
	{ "addressfamily", oAddressFamily },
	{ "serveraliveinterval", oServerAliveInterval },
	{ "serveralivecountmax", o_Server_Alive_गिनती_Max },
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
	{ "visualhostkey", o_Visual_Host_कुंजी },
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
	{ "revokedhostkeys", o_Revoked_Host_कुंजियाँ },
	{ "fingerprinthash", oFingerprintHash },
	{ "updatehostkeys", oUpdateHostkeys },
	{ "hostbasedacceptedalgorithms", oHostbasedAcceptedAlgorithms },
	{ "hostbasedkeytypes", oHostbasedAcceptedAlgorithms }, /* obsolete */
	{ "pubkeyacceptedalgorithms", oPubkeyAcceptedAlgorithms },
	{ "pubkeyacceptedkeytypes", oPubkeyAcceptedAlgorithms }, /* obsolete */
	{ "ignoreunknown", oIgnoreUnknown },
	{ "proxyjump", oProxyJump },
	{ "securitykeyprovider", o_Security_कुंजी_Provider },
	{ "knownhostscommand", oKnownHostsCommand },
	{ "requiredrsasize", oRequiredRSASize },
	{ "enableescapecommandline", oEnableEscapeCommandline },
	{ "obscurekeystroketiming", oObscureKeystrokeTiming },
	{ "channeltimeout", oChannelTimeout },
	{ "versionaddendum", oVersionAddendum },
	{ "refuseconnection", oRefuseConnection },
	{ "warnweakcrypto", oWarnWeakCrypto },

	{ शून्य, oBadOption }
};

अटल स्थिर अक्षर *lookup_opcode_name(OpCodes code);

स्थिर अक्षर *
kex_default_pk_alg(व्योम)
{
	अटल अक्षर *pkalgs;

	अगर (pkalgs == शून्य) {
		अक्षर *all_कुंजी;

		all_कुंजी = sshkey_alg_list(0, 0, 1, ',');
		pkalgs = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_कुंजी);
		मुक्त(all_कुंजी);
	}
	वापस pkalgs;
}

अक्षर *
ssh_connection_hash(स्थिर अक्षर *thishost, स्थिर अक्षर *host, स्थिर अक्षर *portstr,
    स्थिर अक्षर *user, स्थिर अक्षर *jumphost)
{
	काष्ठा ssh_digest_ctx *md;
	u_char conn_hash[SSH_DIGEST_MAX_लंबाई];

	अगर ((md = ssh_digest_start(SSH_DIGEST_SHA1)) == शून्य ||
	    ssh_digest_update(md, thishost, म_माप(thishost)) < 0 ||
	    ssh_digest_update(md, host, म_माप(host)) < 0 ||
	    ssh_digest_update(md, portstr, म_माप(portstr)) < 0 ||
	    ssh_digest_update(md, user, म_माप(user)) < 0 ||
	    ssh_digest_update(md, jumphost, म_माप(jumphost)) < 0 ||
	    ssh_digest_final(md, conn_hash, माप(conn_hash)) < 0)
		fatal_f("mux digest failed");
	ssh_digest_free(md);
	वापस tohex(conn_hash, ssh_digest_bytes(SSH_DIGEST_SHA1));
}

/*
 * Adds a local TCP/IP port forward to options.  Never returns if there is an
 * error.
 */

व्योम
add_local_forward(Options *options, स्थिर काष्ठा Forward *newfwd)
{
	काष्ठा Forward *fwd;
	पूर्णांक i;

	/* Don't add duplicates */
	क्रम (i = 0; i < options->अंक_local_forwards; i++) {
		अगर (forward_equals(newfwd, options->local_forwards + i))
			वापस;
	}
	options->local_forwards = xreallocarray(options->local_forwards,
	    options->अंक_local_forwards + 1,
	    माप(*options->local_forwards));
	fwd = &options->local_forwards[options->अंक_local_forwards++];

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

व्योम
add_remote_forward(Options *options, स्थिर काष्ठा Forward *newfwd)
{
	काष्ठा Forward *fwd;
	पूर्णांक i;

	/* Don't add duplicates */
	क्रम (i = 0; i < options->अंक_remote_forwards; i++) {
		अगर (forward_equals(newfwd, options->remote_forwards + i))
			वापस;
	}
	options->remote_forwards = xreallocarray(options->remote_forwards,
	    options->अंक_remote_forwards + 1,
	    माप(*options->remote_forwards));
	fwd = &options->remote_forwards[options->अंक_remote_forwards++];

	fwd->listen_host = newfwd->listen_host;
	fwd->listen_port = newfwd->listen_port;
	fwd->listen_path = newfwd->listen_path;
	fwd->connect_host = newfwd->connect_host;
	fwd->connect_port = newfwd->connect_port;
	fwd->connect_path = newfwd->connect_path;
	fwd->handle = newfwd->handle;
	fwd->allocated_port = 0;
}

अटल व्योम
clear_forwardings(Options *options)
{
	पूर्णांक i;

	क्रम (i = 0; i < options->अंक_local_forwards; i++) {
		मुक्त(options->local_forwards[i].listen_host);
		मुक्त(options->local_forwards[i].listen_path);
		मुक्त(options->local_forwards[i].connect_host);
		मुक्त(options->local_forwards[i].connect_path);
	}
	अगर (options->अंक_local_forwards > 0) {
		मुक्त(options->local_forwards);
		options->local_forwards = शून्य;
	}
	options->अंक_local_forwards = 0;
	क्रम (i = 0; i < options->अंक_remote_forwards; i++) {
		मुक्त(options->remote_forwards[i].listen_host);
		मुक्त(options->remote_forwards[i].listen_path);
		मुक्त(options->remote_forwards[i].connect_host);
		मुक्त(options->remote_forwards[i].connect_path);
	}
	अगर (options->अंक_remote_forwards > 0) {
		मुक्त(options->remote_forwards);
		options->remote_forwards = शून्य;
	}
	options->अंक_remote_forwards = 0;
	options->tun_open = SSH_TUNMODE_NO;
}

व्योम
add_certificate_file(Options *options, स्थिर अक्षर *path, पूर्णांक userprovided)
{
	पूर्णांक i;

	अगर (options->अंक_certificate_files >= SSH_MAX_CERTIFICATE_FILES)
		fatal("Too many certificate files specified (max %d)",
		    SSH_MAX_CERTIFICATE_FILES);

	/* Avoid registering duplicates */
	क्रम (i = 0; i < options->अंक_certificate_files; i++) {
		अगर (options->certificate_file_userprovided[i] == userprovided &&
		    म_भेद(options->certificate_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			वापस;
		}
	}

	options->certificate_file_userprovided[options->अंक_certificate_files] =
	    userprovided;
	options->certificate_files[options->अंक_certificate_files++] =
	    xstrdup(path);
}

व्योम
add_identity_file(Options *options, स्थिर अक्षर *dir, स्थिर अक्षर *filename,
    पूर्णांक userprovided)
{
	अक्षर *path;
	पूर्णांक i;

	अगर (options->अंक_identity_files >= SSH_MAX_IDENTITY_FILES)
		fatal("Too many identity files specified (max %d)",
		    SSH_MAX_IDENTITY_FILES);

	अगर (dir == शून्य) /* no dir, filename is absolute */
		path = xstrdup(filename);
	अन्यथा अगर (xasprintf(&path, "%s%s", dir, filename) >= PATH_MAX)
		fatal("Identity file path %s too long", path);

	/* Avoid registering duplicates */
	क्रम (i = 0; i < options->अंक_identity_files; i++) {
		अगर (options->identity_file_userprovided[i] == userprovided &&
		    म_भेद(options->identity_files[i], path) == 0) {
			debug2_f("ignoring duplicate key %s", path);
			मुक्त(path);
			वापस;
		}
	}

	options->identity_file_userprovided[options->अंक_identity_files] =
	    userprovided;
	options->identity_files[options->अंक_identity_files++] = path;
}

पूर्णांक
default_ssh_port(व्योम)
{
	अटल पूर्णांक port;
	काष्ठा servent *sp;

	अगर (port == 0) {
		sp = getservbyname(SSH_SERVICE_NAME, "tcp");
		port = sp ? ntohs(sp->s_port) : SSH_DEFAULT_PORT;
	}
	वापस port;
}

/*
 * Execute a command in a shell.
 * Return its exit status or -1 on abnormal exit.
 */
अटल पूर्णांक
execute_in_shell(स्थिर अक्षर *cmd)
{
	अक्षर *shell;
	pid_t pid;
	पूर्णांक status;

	अगर ((shell = दो_पर्या("SHELL")) == शून्य)
		shell = _PATH_BSHELL;

	अगर (access(shell, X_OK) == -1) {
		fatal("Shell \"%s\" is not executable: %s",
		    shell, म_त्रुटि(त्रुटि_सं));
	}

	debug("Executing command: '%.500s'", cmd);

	/* Fork and execute the command. */
	अगर ((pid = विभाजन()) == 0) {
		अक्षर *argv[4];

		अगर (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);

		argv[0] = shell;
		argv[1] = "-c";
		argv[2] = xstrdup(cmd);
		argv[3] = शून्य;

		execv(argv[0], argv);
		error("Unable to execute '%.100s': %s", cmd, म_त्रुटि(त्रुटि_सं));
		/* Die with signal to make this error apparent to parent. */
		ssh_signal(संक_इति, संक_पूर्व);
		समाप्त(getpid(), संक_इति);
		_निकास(1);
	}
	/* Parent. */
	अगर (pid == -1)
		fatal_f("fork: %.100s", म_त्रुटि(त्रुटि_सं));

	जबतक (waitpid(pid, &status, 0) == -1) {
		अगर (त्रुटि_सं != EINTR && त्रुटि_सं != EAGAIN)
			fatal_f("waitpid: %s", म_त्रुटि(त्रुटि_सं));
	}
	अगर (!WIFEXITED(status)) {
		error("command '%.100s' exited abnormally", cmd);
		वापस -1;
	}
	debug3("command returned status %d", WEXITSTATUS(status));
	वापस WEXITSTATUS(status);
}

/*
 * Check whether a local network interface address appears in CIDR pattern-
 * list 'addrlist'. Returns 1 if matched or 0 otherwise.
 */
अटल पूर्णांक
check_match_ifaddrs(स्थिर अक्षर *addrlist)
{
#अगर_घोषित HAVE_IFADDRS_H
	काष्ठा ifaddrs *ifa, *ifaddrs = शून्य;
	पूर्णांक r, found = 0;
	अक्षर addr[NI_MAXHOST];
	socklen_t salen;

	अगर (getifaddrs(&ifaddrs) != 0) {
		error("match localnetwork: getifaddrs failed: %s",
		    म_त्रुटि(त्रुटि_सं));
		वापस 0;
	}
	क्रम (ifa = ifaddrs; ifa != शून्य; ifa = ifa->ifa_अग्र) {
		अगर (ifa->ifa_addr == शून्य || ifa->ifa_name == शून्य ||
		    (ifa->ifa_flags & IFF_UP) == 0)
			जारी;
		चयन (ifa->ifa_addr->sa_family) {
		हाल AF_INET:
			salen = माप(काष्ठा sockaddr_in);
			अवरोध;
		हाल AF_INET6:
			salen = माप(काष्ठा sockaddr_in6);
			अवरोध;
#अगर_घोषित AF_LINK
		हाल AF_LINK:
			/* ignore */
			जारी;
#पूर्ण_अगर /* AF_LINK */
		शेष:
			debug2_f("interface %s: unsupported address family %d",
			    ifa->ifa_name, ifa->ifa_addr->sa_family);
			जारी;
		}
		अगर ((r = getnameinfo(ifa->ifa_addr, salen, addr, माप(addr),
		    शून्य, 0, NI_NUMERICHOST)) != 0) {
			debug2_f("interface %s getnameinfo failed: %s",
			    ifa->ifa_name, gai_strerror(r));
			जारी;
		}
		debug3_f("interface %s addr %s", ifa->ifa_name, addr);
		अगर (addr_match_cidr_list(addr, addrlist) == 1) {
			debug3_f("matched interface %s: address %s in %s",
			    ifa->ifa_name, addr, addrlist);
			found = 1;
			अवरोध;
		}
	}
	freeifaddrs(ifaddrs);
	वापस found;
#अन्यथा /* HAVE_IFADDRS_H */
	error("match localnetwork: not supported on this platform");
	वापस 0;
#पूर्ण_अगर /* HAVE_IFADDRS_H */
}

/*
 * Expand a "match exec" command or an Include path, caller must free returned
 * value.
 */
अटल अक्षर *
expand_match_exec_or_include_path(स्थिर अक्षर *path, Options *options,
    काष्ठा passwd *pw, स्थिर अक्षर *host_arg, स्थिर अक्षर *original_host,
    पूर्णांक final_pass, पूर्णांक is_include_path)
{
	अक्षर thishost[NI_MAXHOST], shorthost[NI_MAXHOST], portstr[NI_MAXSERV];
	अक्षर uidstr[32], *conn_hash_hex, *keyalias, *jmphost, *ruser;
	अक्षर *host, *ret;
	पूर्णांक port;

	port = options->port <= 0 ? default_ssh_port() : options->port;
	ruser = options->user == शून्य ? pw->pw_name : options->user;
	अगर (final_pass) {
		host = xstrdup(options->hostname);
	} अन्यथा अगर (options->hostname != शून्य) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (अक्षर *)शून्य);
	} अन्यथा {
		host = xstrdup(host_arg);
	}
	अगर (gethostname(thishost, माप(thishost)) == -1)
		fatal("gethostname: %s", म_त्रुटि(त्रुटि_सं));
	jmphost = option_clear_or_none(options->jump_host) ?
	    "" : options->jump_host;
	strlcpy(shorthost, thishost, माप(shorthost));
	shorthost[म_खोज(thishost, ".")] = '\0';
	snprintf(portstr, माप(portstr), "%d", port);
	snprintf(uidstr, माप(uidstr), "%llu",
	    (अचिन्हित दीर्घ दीर्घ)pw->pw_uid);
	conn_hash_hex = ssh_connection_hash(thishost, host,
	    portstr, ruser, jmphost);
	keyalias = options->host_कुंजी_alias ?  options->host_कुंजी_alias : host;

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
	    (अक्षर *)शून्य);
	मुक्त(host);
	मुक्त(conn_hash_hex);
	वापस ret;
}

/*
 * Parse and execute a Match directive.
 */
अटल पूर्णांक
match_cfg_पंक्ति(Options *options, स्थिर अक्षर *full_पंक्ति, पूर्णांक *acp, अक्षर ***avp,
    काष्ठा passwd *pw, स्थिर अक्षर *host_arg, स्थिर अक्षर *original_host,
    स्थिर अक्षर *remote_command, पूर्णांक final_pass, पूर्णांक *want_final_pass,
    स्थिर अक्षर *filename, पूर्णांक linenum)
{
	अक्षर *arg, *oattrib = शून्य, *attrib = शून्य, *cmd, *host, *criteria;
	स्थिर अक्षर *ruser;
	पूर्णांक r, this_परिणाम, परिणाम = 1, attributes = 0, negate;

	/*
	 * Configuration is likely to be incomplete at this point so we
	 * must be prepared to use default values.
	 */
	ruser = options->user == शून्य ? pw->pw_name : options->user;
	अगर (final_pass) {
		host = xstrdup(options->hostname);
	} अन्यथा अगर (options->hostname != शून्य) {
		/* NB. Please keep in sync with ssh.c:main() */
		host = percent_expand(options->hostname,
		    "h", host_arg, (अक्षर *)शून्य);
	} अन्यथा {
		host = xstrdup(host_arg);
	}

	debug2("checking match for '%s' host %s originally %s",
	    full_पंक्ति, host, original_host);
	जबतक ((attrib = argv_अग्र(acp, avp)) != शून्य) {
		/* Terminate on comment */
		अगर (*attrib == '#') {
			argv_consume(acp);
			अवरोध;
		}
		attrib = oattrib = xstrdup(attrib);
		arg = criteria = शून्य;
		this_परिणाम = 1;
		अगर ((negate = (attrib[0] == '!')))
			attrib++;
		/* Criterion "all" has no argument and must appear alone */
		अगर (strcasecmp(attrib, "all") == 0) {
			अगर (attributes > 1 ||
			    ((arg = argv_अग्र(acp, avp)) != शून्य &&
			    *arg != '\0' && *arg != '#')) {
				error("%.200s line %d: '%s' cannot be combined "
				    "with other Match attributes",
				    filename, linenum, oattrib);
				परिणाम = -1;
				जाओ out;
			}
			अगर (arg != शून्य && *arg == '#')
				argv_consume(acp); /* consume remaining args */
			अगर (परिणाम)
				परिणाम = negate ? 0 : 1;
			जाओ out;
		}
		attributes++;
		/* criteria "final" and "canonical" have no argument */
		अगर (strcasecmp(attrib, "canonical") == 0 ||
		    strcasecmp(attrib, "final") == 0) {
			/*
			 * If the config requests "Match final" without
			 * negation then remember this so we can perform a
			 * second pass later.
			 */
			अगर (strcasecmp(attrib, "final") == 0 &&
			    want_final_pass != शून्य)
				*want_final_pass |= !negate;
			r = !!final_pass;  /* force bitmask member to boolean */
			अगर (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
			debug3("%.200s line %d: %smatched '%s'",
			    filename, linenum,
			    this_परिणाम ? "" : "not ", oattrib);
			जाओ अग्र;
		}

		/* Keep this list in sync with below */
		अगर (strprefix(attrib, "host=", 1)  != शून्य ||
		    strprefix(attrib, "originalhost=", 1) != शून्य ||
		    strprefix(attrib, "user=", 1) != शून्य ||
		    strprefix(attrib, "localuser=", 1) != शून्य ||
		    strprefix(attrib, "localnetwork=", 1) != शून्य ||
		    strprefix(attrib, "version=", 1) != शून्य ||
		    strprefix(attrib, "tagged=", 1) != शून्य ||
		    strprefix(attrib, "command=", 1) != शून्य ||
		    strprefix(attrib, "exec=", 1) != शून्य) {
			arg = म_अक्षर(attrib, '=');
			*(arg++) = '\0';
		} अन्यथा अगर ((arg = argv_अग्र(acp, avp)) == शून्य) {
			error("%.200s line %d: missing argument for Match '%s'",
			    filename, linenum, oattrib);
			परिणाम = -1;
			जाओ out;
		}

		/*
		 * All other criteria require an argument, though it may
		 * be the empty string for the "tagged" and "command"
		 * options.
		 */
		अगर (*arg == '\0' &&
		    strcasecmp(attrib, "tagged") != 0 &&
		    strcasecmp(attrib, "command") != 0)
			arg = शून्य;
		अगर (arg == शून्य || *arg == '#') {
			error("Missing Match criteria for %s", attrib);
			परिणाम = -1;
			जाओ out;
		}
		अगर (strcasecmp(attrib, "host") == 0) {
			criteria = xstrdup(host);
			r = match_hostname(host, arg) == 1;
			अगर (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
		} अन्यथा अगर (strcasecmp(attrib, "originalhost") == 0) {
			criteria = xstrdup(original_host);
			r = match_hostname(original_host, arg) == 1;
			अगर (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
		} अन्यथा अगर (strcasecmp(attrib, "user") == 0) {
			criteria = xstrdup(ruser);
			r = match_pattern_list(ruser, arg, 0) == 1;
			अगर (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
		} अन्यथा अगर (strcasecmp(attrib, "localuser") == 0) {
			criteria = xstrdup(pw->pw_name);
			r = match_pattern_list(pw->pw_name, arg, 0) == 1;
			अगर (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
		} अन्यथा अगर (strcasecmp(attrib, "localnetwork") == 0) {
			अगर (addr_match_cidr_list(शून्य, arg) == -1) {
				/* Error already printed */
				परिणाम = -1;
				जाओ out;
			}
			r = check_match_ifaddrs(arg) == 1;
			अगर (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
		} अन्यथा अगर (strcasecmp(attrib, "version") == 0) {
			criteria = xstrdup(SSH_RELEASE);
			r = match_pattern_list(SSH_RELEASE, arg, 0) == 1;
			अगर (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
		} अन्यथा अगर (strcasecmp(attrib, "tagged") == 0) {
			criteria = xstrdup(options->tag == शून्य ? "" :
			    options->tag);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			अगर (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
		} अन्यथा अगर (strcasecmp(attrib, "command") == 0) {
			criteria = xstrdup(remote_command == शून्य ?
			    "" : remote_command);
			/* Special case: empty criteria matches empty arg */
			r = (*criteria == '\0') ? *arg == '\0' :
			    match_pattern_list(criteria, arg, 0) == 1;
			अगर (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
		} अन्यथा अगर (strcasecmp(attrib, "sessiontype") == 0) {
			अगर (options->session_type == SESSION_TYPE_SUBSYSTEM)
				criteria = xstrdup("subsystem");
			अन्यथा अगर (options->session_type == SESSION_TYPE_NONE)
				criteria = xstrdup("none");
			अन्यथा अगर (remote_command != शून्य &&
			    *remote_command != '\0')
				criteria = xstrdup("exec");
			अन्यथा
				criteria = xstrdup("shell");
			r = match_pattern_list(criteria, arg, 0) == 1;
			अगर (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
		} अन्यथा अगर (strcasecmp(attrib, "exec") == 0) {
			अगर ((cmd = expand_match_exec_or_include_path(arg,
			    options, pw, host_arg, original_host,
			    final_pass, 0)) == शून्य) {
				fatal("%.200s line %d: failed to expand match "
				    "exec '%.100s'", filename, linenum, arg);
			}
			अगर (परिणाम != 1) {
				/* skip execution if prior predicate failed */
				debug3("%.200s line %d: skipped exec "
				    "\"%.100s\"", filename, linenum, cmd);
				मुक्त(cmd);
				जाओ अग्र;
			}
			r = execute_in_shell(cmd);
			अगर (r == -1) {
				fatal("%.200s line %d: match exec "
				    "'%.100s' error", filename,
				    linenum, cmd);
			}
			criteria = xstrdup(cmd);
			मुक्त(cmd);
			/* Force exit status to boolean */
			r = r == 0;
			अगर (r == (negate ? 1 : 0))
				this_परिणाम = परिणाम = 0;
		} अन्यथा {
			error("Unsupported Match attribute %s", attrib);
			परिणाम = -1;
			जाओ out;
		}
		debug3("%.200s line %d: %smatched '%s%s%.100s%s' ",
		    filename, linenum, this_परिणाम ? "": "not ", oattrib,
		    criteria == शून्य ? "" : " \"",
		    criteria == शून्य ? "" : criteria,
		    criteria == शून्य ? "" : "\"");
 अग्र:
		मुक्त(criteria);
		मुक्त(oattrib);
		oattrib = attrib = शून्य;
	}
	अगर (attributes == 0) {
		error("One or more attributes required for Match");
		परिणाम = -1;
		जाओ out;
	}
 out:
	अगर (परिणाम != -1)
		debug2("match %sfound", परिणाम ? "" : "not ");
	मुक्त(oattrib);
	मुक्त(host);
	वापस परिणाम;
}

/* Remove environment variable by pattern */
अटल व्योम
rm_env(Options *options, स्थिर अक्षर *arg, स्थिर अक्षर *filename, पूर्णांक linenum)
{
	u_int i, j, onum_send_env = options->अंक_send_env;

	/* Remove an environment variable */
	क्रम (i = 0; i < options->अंक_send_env; ) {
		अगर (!match_pattern(options->send_env[i], arg + 1)) {
			i++;
			जारी;
		}
		debug3("%s line %d: removing environment %s",
		    filename, linenum, options->send_env[i]);
		मुक्त(options->send_env[i]);
		options->send_env[i] = शून्य;
		क्रम (j = i; j < options->अंक_send_env - 1; j++) {
			options->send_env[j] = options->send_env[j + 1];
			options->send_env[j + 1] = शून्य;
		}
		options->अंक_send_env--;
		/* NB. don't increment i */
	}
	अगर (onum_send_env != options->अंक_send_env) {
		options->send_env = xrecallocarray(options->send_env,
		    onum_send_env, options->अंक_send_env,
		    माप(*options->send_env));
	}
}

/*
 * Returns the number of the token pointed to by cp or oBadOption.
 */
अटल OpCodes
parse_token(स्थिर अक्षर *cp, स्थिर अक्षर *filename, पूर्णांक linenum,
    स्थिर अक्षर *ignored_unknown)
{
	पूर्णांक i;

	क्रम (i = 0; keywords[i].name; i++)
		अगर (म_भेद(cp, keywords[i].name) == 0)
			वापस keywords[i].opcode;
	अगर (ignored_unknown != शून्य &&
	    match_pattern_list(cp, ignored_unknown, 1) == 1)
		वापस oIgnoredUnknownOption;
	error("%s: line %d: Bad configuration option: %s",
	    filename, linenum, cp);
	वापस oBadOption;
}

अटल व्योम
free_canon_cnames(काष्ठा allowed_cname *cnames, u_int n)
{
	u_int i;

	अगर (cnames == शून्य || n == 0)
		वापस;
	क्रम (i = 0; i < n; i++) {
		मुक्त(cnames[i].source_list);
		मुक्त(cnames[i].target_list);
	}
	मुक्त(cnames);
}

/* Multistate option parsing */
काष्ठा multistate {
	अक्षर *कुंजी;
	पूर्णांक मूल्य;
};
अटल स्थिर काष्ठा multistate multistate_flag[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ शून्य, -1 }
};
अटल स्थिर काष्ठा multistate multistate_yesnoask[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ शून्य, -1 }
};
अटल स्थिर काष्ठा multistate multistate_strict_hostkey[] = {
	{ "true",			SSH_STRICT_HOSTKEY_YES },
	{ "false",			SSH_STRICT_HOSTKEY_OFF },
	{ "yes",			SSH_STRICT_HOSTKEY_YES },
	{ "no",				SSH_STRICT_HOSTKEY_OFF },
	{ "ask",			SSH_STRICT_HOSTKEY_ASK },
	{ "off",			SSH_STRICT_HOSTKEY_OFF },
	{ "accept-new",			SSH_STRICT_HOSTKEY_NEW },
	{ शून्य, -1 }
};
अटल स्थिर काष्ठा multistate multistate_yesnoaskconfirm[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "ask",			2 },
	{ "confirm",			3 },
	{ शून्य, -1 }
};
अटल स्थिर काष्ठा multistate multistate_addressfamily[] = {
	{ "inet",			AF_INET },
	{ "inet6",			AF_INET6 },
	{ "any",			AF_UNSPEC },
	{ शून्य, -1 }
};
अटल स्थिर काष्ठा multistate multistate_controlmaster[] = {
	{ "true",			SSHCTL_MASTER_YES },
	{ "yes",			SSHCTL_MASTER_YES },
	{ "false",			SSHCTL_MASTER_NO },
	{ "no",				SSHCTL_MASTER_NO },
	{ "auto",			SSHCTL_MASTER_AUTO },
	{ "ask",			SSHCTL_MASTER_ASK },
	{ "autoask",			SSHCTL_MASTER_AUTO_ASK },
	{ शून्य, -1 }
};
अटल स्थिर काष्ठा multistate multistate_tunnel[] = {
	{ "ethernet",			SSH_TUNMODE_ETHERNET },
	{ "point-to-point",		SSH_TUNMODE_POINTOPOINT },
	{ "true",			SSH_TUNMODE_DEFAULT },
	{ "yes",			SSH_TUNMODE_DEFAULT },
	{ "false",			SSH_TUNMODE_NO },
	{ "no",				SSH_TUNMODE_NO },
	{ शून्य, -1 }
};
अटल स्थिर काष्ठा multistate multistate_requesttty[] = {
	{ "true",			REQUEST_TTY_YES },
	{ "yes",			REQUEST_TTY_YES },
	{ "false",			REQUEST_TTY_NO },
	{ "no",				REQUEST_TTY_NO },
	{ "force",			REQUEST_TTY_FORCE },
	{ "auto",			REQUEST_TTY_AUTO },
	{ शून्य, -1 }
};
अटल स्थिर काष्ठा multistate multistate_sessiontype[] = {
	{ "none",			SESSION_TYPE_NONE },
	{ "subsystem",			SESSION_TYPE_SUBSYSTEM },
	{ "default",			SESSION_TYPE_DEFAULT },
	{ शून्य, -1 }
};
अटल स्थिर काष्ठा multistate multistate_canonicalizehostname[] = {
	{ "true",			SSH_CANONICALISE_YES },
	{ "false",			SSH_CANONICALISE_NO },
	{ "yes",			SSH_CANONICALISE_YES },
	{ "no",				SSH_CANONICALISE_NO },
	{ "always",			SSH_CANONICALISE_ALWAYS },
	{ शून्य, -1 }
};
अटल स्थिर काष्ठा multistate multistate_pubkey_auth[] = {
	{ "true",			SSH_PUBKEY_AUTH_ALL },
	{ "false",			SSH_PUBKEY_AUTH_NO },
	{ "yes",			SSH_PUBKEY_AUTH_ALL },
	{ "no",				SSH_PUBKEY_AUTH_NO },
	{ "unbound",			SSH_PUBKEY_AUTH_UNBOUND },
	{ "host-bound",			SSH_PUBKEY_AUTH_HBOUND },
	{ शून्य, -1 }
};
अटल स्थिर काष्ठा multistate multistate_compression[] = {
#अगर_घोषित WITH_ZLIB
	{ "yes",			COMP_DELAYED },
#पूर्ण_अगर
	{ "no",				COMP_NONE },
	{ शून्य, -1 }
};
अटल स्थिर काष्ठा multistate multistate_keepalives[] = {
	{ "true",			SSH_KEEPALIVES_TRANSPORT },
	{ "false",			SSH_KEEPALIVES_OFF },
	{ "yes",			SSH_KEEPALIVES_TRANSPORT },
	{ "no",				SSH_KEEPALIVES_OFF },
	{ "transport",			SSH_KEEPALIVES_TRANSPORT },
	{ "all",			SSH_KEEPALIVES_ALL },
	{ शून्य, -1 }
};
/* XXX this will need to be replaced with a bitmask if we add more flags */
अटल स्थिर काष्ठा multistate multistate_warnweakcrypto[] = {
	{ "true",			1 },
	{ "false",			0 },
	{ "yes",			1 },
	{ "no",				0 },
	{ "no-pq-kex",			0 },
	{ शून्य, -1 }
};

अटल पूर्णांक
parse_multistate_मूल्य(स्थिर अक्षर *arg, स्थिर अक्षर *filename, पूर्णांक linenum,
    स्थिर काष्ठा multistate *multistate_ptr)
{
	पूर्णांक i;

	अगर (!arg || *arg == '\0') {
		error("%s line %d: missing argument.", filename, linenum);
		वापस -1;
	}
	क्रम (i = 0; multistate_ptr[i].कुंजी != शून्य; i++) {
		अगर (strcasecmp(arg, multistate_ptr[i].कुंजी) == 0)
			वापस multistate_ptr[i].मूल्य;
	}
	वापस -1;
}

/*
 * Processes a single option line as used in the configuration files. This
 * only sets those values that have not already been set.
 */
पूर्णांक
process_config_पंक्ति(Options *options, काष्ठा passwd *pw, स्थिर अक्षर *host,
    स्थिर अक्षर *original_host, स्थिर अक्षर *remote_command, अक्षर *पंक्ति,
    स्थिर अक्षर *filename, पूर्णांक linenum, पूर्णांक *activep, पूर्णांक flags)
{
	वापस process_config_पंक्ति_depth(options, pw, host, original_host,
	    remote_command, पंक्ति, filename, linenum, activep, flags, शून्य, 0);
}

#घोषणा WHITESPACE " \t\r\n"
अटल पूर्णांक
process_config_पंक्ति_depth(Options *options, काष्ठा passwd *pw, स्थिर अक्षर *host,
    स्थिर अक्षर *original_host, स्थिर अक्षर *remote_command, अक्षर *पंक्ति,
    स्थिर अक्षर *filename, पूर्णांक linenum, पूर्णांक *activep, पूर्णांक flags,
    पूर्णांक *want_final_pass, पूर्णांक depth)
{
	अक्षर *str, **charptr, *endofnumber, *keyword, *arg, *arg2, *p;
	अक्षर **cpptr, ***cppptr, fwdarg[256];
	u_int i, *uintptr, max_entries = 0;
	पूर्णांक r, oactive, negated, opcode, *intptr, मूल्य, value2, cmdline = 0;
	पूर्णांक remotefwd, dynamicfwd, ca_only = 0, found = 0;
	LogLevel *log_level_ptr;
	SyslogFacility *log_facility_ptr;
	दीर्घ दीर्घ val64;
	माप_प्रकार len;
	काष्ठा Forward fwd;
	स्थिर काष्ठा multistate *multistate_ptr;
	glob_t gl;
	स्थिर अक्षर *errstr;
	अक्षर **oav = शून्य, **av;
	पूर्णांक oac = 0, ac;
	पूर्णांक ret = -1;
	काष्ठा allowed_cname *cnames = शून्य;
	u_int ncnames = 0;
	अक्षर **strs = शून्य; /* string array arguments; freed implicitly */
	u_int nstrs = 0;

	अगर (activep == शून्य) { /* We are processing a command line directive */
		cmdline = 1;
		activep = &cmdline;
	}

	/* Strip trailing whitespace. Allow \f (form feed) at EOL only */
	अगर ((len = म_माप(पंक्ति)) == 0)
		वापस 0;
	क्रम (len--; len > 0; len--) {
		अगर (म_अक्षर(WHITESPACE "\f", पंक्ति[len]) == शून्य)
			अवरोध;
		पंक्ति[len] = '\0';
	}

	str = पंक्ति;
	/* Get the keyword. (Each line is supposed to begin with a keyword). */
	अगर ((keyword = strdelim(&str)) == शून्य)
		वापस 0;
	/* Ignore leading whitespace. */
	अगर (*keyword == '\0')
		keyword = strdelim(&str);
	अगर (keyword == शून्य || !*keyword || *keyword == '\n' || *keyword == '#')
		वापस 0;
	/* Match lowercase keyword */
	lowercase(keyword);

	/* Prepare to parse remainder of line */
	अगर (str != शून्य)
		str += म_अखोज(str, WHITESPACE);
	अगर (str == शून्य || *str == '\0') {
		error("%s line %d: no argument after keyword \"%s\"",
		    filename, linenum, keyword);
		वापस -1;
	}
	opcode = parse_token(keyword, filename, linenum,
	    options->ignored_unknown);
	अगर (argv_split(str, &oac, &oav, 1) != 0) {
		error("%s line %d: invalid quotes", filename, linenum);
		वापस -1;
	}
	ac = oac;
	av = oav;

	चयन (opcode) {
	हाल oBadOption:
		/* don't panic, but count bad options */
		जाओ out;
	हाल oIgnore:
		argv_consume(&ac);
		अवरोध;
	हाल oIgnoredUnknownOption:
		debug("%s line %d: Ignored unknown option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		अवरोध;
	हाल oConnectTimeout:
		intptr = &options->connection_timeout;
parse_time:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			error("%s line %d: missing time value.",
			    filename, linenum);
			जाओ out;
		}
		अगर (म_भेद(arg, "none") == 0)
			मूल्य = -1;
		अन्यथा अगर ((मूल्य = convtime(arg)) == -1) {
			error("%s line %d: invalid time value.",
			    filename, linenum);
			जाओ out;
		}
		अगर (*activep && *intptr == -1)
			*intptr = मूल्य;
		अवरोध;

	हाल oForwardAgent:
		intptr = &options->forward_agent;

		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			error("%s line %d: missing argument.",
			    filename, linenum);
			जाओ out;
		}

		मूल्य = -1;
		multistate_ptr = multistate_flag;
		क्रम (i = 0; multistate_ptr[i].कुंजी != शून्य; i++) {
			अगर (strcasecmp(arg, multistate_ptr[i].कुंजी) == 0) {
				मूल्य = multistate_ptr[i].मूल्य;
				अवरोध;
			}
		}
		अगर (मूल्य != -1) {
			अगर (*activep && *intptr == -1)
				*intptr = मूल्य;
			अवरोध;
		}
		/* ForwardAgent wasn't 'yes' or 'no', assume a path */
		अगर (*activep && *intptr == -1)
			*intptr = 1;

		charptr = &options->forward_agent_sock_path;
		जाओ parse_agent_path;

	हाल oForwardX11:
		intptr = &options->forward_x11;
 parse_flag:
		multistate_ptr = multistate_flag;
 parse_multistate:
		arg = argv_अग्र(&ac, &av);
		अगर ((मूल्य = parse_multistate_मूल्य(arg, filename, linenum,
		    multistate_ptr)) == -1) {
			error("%s line %d: unsupported option \"%s\".",
			    filename, linenum, arg);
			जाओ out;
		}
		अगर (*activep && *intptr == -1)
			*intptr = मूल्य;
		अवरोध;

	हाल oForwardX11Trusted:
		intptr = &options->forward_x11_trusted;
		जाओ parse_flag;

	हाल oForwardX11Timeout:
		intptr = &options->forward_x11_timeout;
		जाओ parse_time;

	हाल oGatewayPorts:
		intptr = &options->fwd_opts.gateway_ports;
		जाओ parse_flag;

	हाल oExitOnForwardFailure:
		intptr = &options->exit_on_forward_failure;
		जाओ parse_flag;

	हाल oPasswordAuthentication:
		intptr = &options->password_authentication;
		जाओ parse_flag;

	हाल oKbdInteractiveAuthentication:
		intptr = &options->kbd_interactive_authentication;
		जाओ parse_flag;

	हाल oKbdInteractiveDevices:
		charptr = &options->kbd_interactive_devices;
		जाओ parse_string;

	हाल oPubkeyAuthentication:
		multistate_ptr = multistate_pubkey_auth;
		intptr = &options->pubkey_authentication;
		जाओ parse_multistate;

	हाल oHostbasedAuthentication:
		intptr = &options->hostbased_authentication;
		जाओ parse_flag;

	हाल oGssAuthentication:
		intptr = &options->gss_authentication;
		जाओ parse_flag;

	हाल oGssDelegateCreds:
		intptr = &options->gss_deleg_creds;
		जाओ parse_flag;

	हाल oBatchMode:
		intptr = &options->batch_mode;
		जाओ parse_flag;

	हाल oCheckHostIP:
		intptr = &options->check_host_ip;
		जाओ parse_flag;

	हाल o_Verify_Host_कुंजी_DNS:
		intptr = &options->verify_host_कुंजी_dns;
		multistate_ptr = multistate_yesnoask;
		जाओ parse_multistate;

	हाल o_Strict_Host_कुंजी_Checking:
		intptr = &options->strict_host_कुंजी_checking;
		multistate_ptr = multistate_strict_hostkey;
		जाओ parse_multistate;

	हाल oCompression:
		intptr = &options->compression;
		multistate_ptr = multistate_compression;
		जाओ parse_multistate;

	हाल oTCPKeepAlive:
		intptr = &options->tcp_keep_alive;
		multistate_ptr = multistate_keepalives;
		जाओ parse_multistate;

	हाल oNoHostAuthenticationForLocalhost:
		intptr = &options->no_host_authentication_for_localhost;
		जाओ parse_flag;

	हाल o_संख्या_Of_Password_Prompts:
		intptr = &options->संख्या_of_password_prompts;
		जाओ parse_int;

	हाल oRekeyLimit:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.", filename,
			    linenum);
			जाओ out;
		}
		अगर (म_भेद(arg, "default") == 0) {
			val64 = 0;
		} अन्यथा {
			अगर (scan_scaled(arg, &val64) == -1) {
				error("%.200s line %d: Bad number '%s': %s",
				    filename, linenum, arg, म_त्रुटि(त्रुटि_सं));
				जाओ out;
			}
			अगर (val64 != 0 && val64 < 16) {
				error("%.200s line %d: RekeyLimit too small",
				    filename, linenum);
				जाओ out;
			}
		}
		अगर (*activep && options->rekey_limit == -1)
			options->rekey_limit = val64;
		अगर (ac != 0) { /* optional rekey interval present */
			अगर (म_भेद(av[0], "none") == 0) {
				(व्योम)argv_अग्र(&ac, &av);	/* discard */
				अवरोध;
			}
			intptr = &options->rekey_interval;
			जाओ parse_time;
		}
		अवरोध;

	हाल oIdentityFile:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जाओ out;
		}
		अगर (*activep) {
			intptr = &options->अंक_identity_files;
			अगर (*intptr >= SSH_MAX_IDENTITY_FILES) {
				error("%.200s line %d: Too many identity files "
				    "specified (max %d).", filename, linenum,
				    SSH_MAX_IDENTITY_FILES);
				जाओ out;
			}
			add_identity_file(options, शून्य,
			    arg, flags & SSHCONF_USERCONF);
		}
		अवरोध;

	हाल oCertificateFile:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जाओ out;
		}
		अगर (*activep) {
			intptr = &options->अंक_certificate_files;
			अगर (*intptr >= SSH_MAX_CERTIFICATE_FILES) {
				error("%.200s line %d: Too many certificate "
				    "files specified (max %d).",
				    filename, linenum,
				    SSH_MAX_CERTIFICATE_FILES);
				जाओ out;
			}
			add_certificate_file(options, arg,
			    flags & SSHCONF_USERCONF);
		}
		अवरोध;

	हाल oXAuthLocation:
		charptr=&options->xauth_location;
		जाओ parse_string;

	हाल oUser:
		charptr = &options->user;
parse_string:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जाओ out;
		}
		अगर (*activep && *charptr == शून्य)
			*charptr = xstrdup(arg);
		अवरोध;

	हाल oGlobalKnownHostsFile:
		cpptr = (अक्षर **)&options->system_hostfiles;
		uintptr = &options->अंक_system_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
parse_char_array:
		i = 0;
		मूल्य = *uintptr == 0; /* was array empty when we started? */
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			अगर (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				जाओ out;
			}
			/* Allow "none" only in first position */
			अगर (strcasecmp(arg, "none") == 0) {
				अगर (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					जाओ out;
				}
			}
			i++;
			अगर (*activep && मूल्य) {
				अगर ((*uintptr) >= max_entries) {
					error("%s line %d: too many %s "
					    "entries.", filename, linenum,
					    keyword);
					जाओ out;
				}
				cpptr[(*uintptr)++] = xstrdup(arg);
			}
		}
		अवरोध;

	हाल oUserKnownHostsFile:
		cpptr = (अक्षर **)&options->user_hostfiles;
		uintptr = &options->अंक_user_hostfiles;
		max_entries = SSH_MAX_HOSTS_FILES;
		जाओ parse_char_array;

	हाल oHostname:
		charptr = &options->hostname;
		जाओ parse_string;

	हाल oTag:
		charptr = &options->tag;
		जाओ parse_string;

	हाल o_Host_कुंजी_Alias:
		charptr = &options->host_कुंजी_alias;
		जाओ parse_string;

	हाल oPreferredAuthentications:
		charptr = &options->preferred_authentications;
		जाओ parse_string;

	हाल oBindAddress:
		charptr = &options->bind_address;
		जाओ parse_string;

	हाल oBindInterface:
		charptr = &options->bind_interface;
		जाओ parse_string;

	हाल oPKCS11Provider:
		charptr = &options->pkcs11_provider;
		जाओ parse_string;

	हाल o_Security_कुंजी_Provider:
		charptr = &options->sk_provider;
		जाओ parse_string;

	हाल oKnownHostsCommand:
		charptr = &options->known_hosts_command;
		जाओ parse_command;

	हाल oProxyCommand:
		charptr = &options->proxy_command;
parse_command:
		अगर (str == शून्य) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जाओ out;
		}
		len = म_अखोज(str, WHITESPACE "=");
		अगर (*activep && *charptr == शून्य)
			*charptr = xstrdup(str + len);
		argv_consume(&ac);
		अवरोध;

	हाल oProxyJump:
		अगर (str == शून्य) {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जाओ out;
		}
		len = म_अखोज(str, WHITESPACE "=");
		/* XXX use argv? */
		अगर (parse_jump(str + len, options, cmdline, *activep) == -1) {
			error("%.200s line %d: Invalid ProxyJump \"%s\"",
			    filename, linenum, str + len);
			जाओ out;
		}
		argv_consume(&ac);
		अवरोध;

	हाल oPort:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जाओ out;
		}
		मूल्य = a2port(arg);
		अगर (मूल्य <= 0) {
			error("%.200s line %d: Bad port '%s'.",
			    filename, linenum, arg);
			जाओ out;
		}
		अगर (*activep && options->port == -1)
			options->port = मूल्य;
		अवरोध;

	हाल oConnectionAttempts:
		intptr = &options->connection_attempts;
parse_int:
		arg = argv_अग्र(&ac, &av);
		अगर ((errstr = atoi_err(arg, &मूल्य)) != शून्य) {
			error("%s line %d: integer value %s.",
			    filename, linenum, errstr);
			जाओ out;
		}
		अगर (*activep && *intptr == -1)
			*intptr = मूल्य;
		अवरोध;

	हाल oCiphers:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जाओ out;
		}
		अगर (*arg != '-' &&
		    !ciphers_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)){
			error("%.200s line %d: Bad SSH2 cipher spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			जाओ out;
		}
		अगर (*activep && options->ciphers == शून्य)
			options->ciphers = xstrdup(arg);
		अवरोध;

	हाल oMacs:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जाओ out;
		}
		अगर (*arg != '-' &&
		    !mac_valid(*arg == '+' || *arg == '^' ? arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 MAC spec '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			जाओ out;
		}
		अगर (*activep && options->macs == शून्य)
			options->macs = xstrdup(arg);
		अवरोध;

	हाल oKexAlgorithms:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जाओ out;
		}
		अगर (*arg != '-' &&
		    !kex_names_valid(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg)) {
			error("%.200s line %d: Bad SSH2 KexAlgorithms '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			जाओ out;
		}
		अगर (*activep && options->kex_algorithms == शून्य)
			options->kex_algorithms = xstrdup(arg);
		अवरोध;

	हाल o_Host_कुंजी_Algorithms:
		charptr = &options->hostkeyalgorithms;
		ca_only = 0;
parse_pubkey_algos:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जाओ out;
		}
		अगर (*arg != '-' &&
		    !sshkey_names_valid2(*arg == '+' || *arg == '^' ?
		    arg + 1 : arg, 1, ca_only)) {
			error("%s line %d: Bad key types '%s'.",
			    filename, linenum, arg ? arg : "<NONE>");
			जाओ out;
		}
		अगर (*activep && *charptr == शून्य)
			*charptr = xstrdup(arg);
		अवरोध;

	हाल oCASignatureAlgorithms:
		charptr = &options->ca_sign_algorithms;
		ca_only = 1;
		जाओ parse_pubkey_algos;

	हाल oLogLevel:
		log_level_ptr = &options->log_level;
		arg = argv_अग्र(&ac, &av);
		मूल्य = log_level_संख्या(arg);
		अगर (मूल्य == SYSLOG_LEVEL_NOT_SET) {
			error("%.200s line %d: unsupported log level '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			जाओ out;
		}
		अगर (*activep && *log_level_ptr == SYSLOG_LEVEL_NOT_SET)
			*log_level_ptr = (LogLevel) मूल्य;
		अवरोध;

	हाल oLogFacility:
		log_facility_ptr = &options->log_facility;
		arg = argv_अग्र(&ac, &av);
		मूल्य = log_facility_संख्या(arg);
		अगर (मूल्य == SYSLOG_FACILITY_NOT_SET) {
			error("%.200s line %d: unsupported log facility '%s'",
			    filename, linenum, arg ? arg : "<NONE>");
			जाओ out;
		}
		अगर (*log_facility_ptr == -1)
			*log_facility_ptr = (SyslogFacility) मूल्य;
		अवरोध;

	हाल oLogVerbose:
		cppptr = &options->log_verbose;
		uintptr = &options->अंक_log_verbose;
		i = 0;
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			अगर (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				जाओ out;
			}
			/* Allow "none" only in first position */
			अगर (strcasecmp(arg, "none") == 0) {
				अगर (i > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					जाओ out;
				}
			}
			i++;
			अगर (*activep && *uintptr == 0) {
				*cppptr = xrecallocarray(*cppptr, *uintptr,
				    *uintptr + 1, माप(**cppptr));
				(*cppptr)[(*uintptr)++] = xstrdup(arg);
			}
		}
		अवरोध;

	हाल oLocalForward:
	हाल oRemoteForward:
	हाल oDynamicForward:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जाओ out;
		}

		remotefwd = (opcode == oRemoteForward);
		dynamicfwd = (opcode == oDynamicForward);

		अगर (!dynamicfwd) {
			arg2 = argv_अग्र(&ac, &av);
			अगर (arg2 == शून्य || *arg2 == '\0') {
				अगर (remotefwd)
					dynamicfwd = 1;
				अन्यथा {
					error("%.200s line %d: Missing target "
					    "argument.", filename, linenum);
					जाओ out;
				}
			} अन्यथा {
				/* construct a string for parse_forward */
				snprintf(fwdarg, माप(fwdarg), "%s:%s", arg,
				    arg2);
			}
		}
		अगर (dynamicfwd)
			strlcpy(fwdarg, arg, माप(fwdarg));

		अगर (parse_forward(&fwd, fwdarg, dynamicfwd, remotefwd) == 0) {
			error("%.200s line %d: Bad forwarding specification.",
			    filename, linenum);
			जाओ out;
		}

		अगर (*activep) {
			अगर (remotefwd) {
				add_remote_forward(options, &fwd);
			} अन्यथा {
				add_local_forward(options, &fwd);
			}
		}
		अवरोध;

	हाल oPermitRemoteOpen:
		uintptr = &options->अंक_permitted_remote_opens;
		cppptr = &options->permitted_remote_opens;
		found = *uintptr == 0;
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			arg2 = xstrdup(arg);
			/* Allow any/none only in first position */
			अगर (strcasecmp(arg, "none") == 0 ||
			    strcasecmp(arg, "any") == 0) {
				अगर (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"%s\" "
					    "argument must appear alone.",
					    filename, linenum, keyword, arg);
					मुक्त(arg2);
					जाओ out;
				}
			} अन्यथा {
				p = hpdelim(&arg);
				अगर (p == शून्य) {
					fatal("%s line %d: missing host in %s",
					    filename, linenum,
					    lookup_opcode_name(opcode));
				}
				p = cleanhostname(p);
				/*
				 * don't want to use permitopen_port to avoid
				 * dependency on channels.[ch] here.
				 */
				अगर (arg == शून्य || (म_भेद(arg, "*") != 0 &&
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
		अगर (nstrs == 0)
			fatal("%s line %d: missing %s specification",
			    filename, linenum, lookup_opcode_name(opcode));
		अगर (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = शून्य; /* transferred */
			nstrs = 0;
		}
		अवरोध;

	हाल oClearAllForwardings:
		intptr = &options->clear_forwardings;
		जाओ parse_flag;

	हाल oHost:
		अगर (cmdline) {
			error("Host directive not supported as a command-line "
			    "option");
			जाओ out;
		}
		*activep = 0;
		arg2 = शून्य;
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			अगर (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				जाओ out;
			}
			अगर ((flags & SSHCONF_NEVERMATCH) != 0) {
				argv_consume(&ac);
				अवरोध;
			}
			negated = *arg == '!';
			अगर (negated)
				arg++;
			अगर (match_pattern(host, arg)) {
				अगर (negated) {
					debug("%.200s line %d: Skipping Host "
					    "block because of negated match "
					    "for %.100s", filename, linenum,
					    arg);
					*activep = 0;
					argv_consume(&ac);
					अवरोध;
				}
				अगर (!*activep)
					arg2 = arg; /* logged below */
				*activep = 1;
			}
		}
		अगर (*activep)
			debug("%.200s line %d: Applying options for %.100s",
			    filename, linenum, arg2);
		अवरोध;

	हाल oMatch:
		अगर (cmdline) {
			error("Match directive not supported as a command-line "
			    "option");
			जाओ out;
		}
		मूल्य = match_cfg_पंक्ति(options, str, &ac, &av, pw, host,
		    original_host, remote_command, flags & SSHCONF_FINAL,
		    want_final_pass, filename, linenum);
		अगर (मूल्य < 0) {
			error("%.200s line %d: Bad Match condition", filename,
			    linenum);
			जाओ out;
		}
		*activep = (flags & SSHCONF_NEVERMATCH) ? 0 : मूल्य;
		अवरोध;

	हाल oEscapeChar:
		intptr = &options->escape_char;
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जाओ out;
		}
		अगर (म_भेद(arg, "none") == 0)
			मूल्य = SSH_ESCAPECHAR_NONE;
		अन्यथा अगर (arg[1] == '\0')
			मूल्य = (u_char) arg[0];
		अन्यथा अगर (arg[0] == '^' && arg[2] == 0 &&
		    (u_char) arg[1] >= 64 && (u_char) arg[1] < 128)
			मूल्य = (u_char) arg[1] & 31;
		अन्यथा {
			error("%.200s line %d: Bad escape character.",
			    filename, linenum);
			जाओ out;
		}
		अगर (*activep && *intptr == -1)
			*intptr = मूल्य;
		अवरोध;

	हाल oAddressFamily:
		intptr = &options->address_family;
		multistate_ptr = multistate_addressfamily;
		जाओ parse_multistate;

	हाल oEnableSSHKeysign:
		intptr = &options->enable_ssh_keysign;
		जाओ parse_flag;

	हाल oIdentitiesOnly:
		intptr = &options->identities_only;
		जाओ parse_flag;

	हाल oServerAliveInterval:
		intptr = &options->server_alive_interval;
		जाओ parse_time;

	हाल o_Server_Alive_गिनती_Max:
		intptr = &options->server_alive_गिनती_max;
		जाओ parse_int;

	हाल oSendEnv:
		/* XXX appends to list; doesn't respect first-match-wins */
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			अगर (*arg == '\0' || म_अक्षर(arg, '=') != शून्य) {
				error("%s line %d: Invalid environment name.",
				    filename, linenum);
				जाओ out;
			}
			found = 1;
			अगर (!*activep)
				जारी;
			अगर (*arg == '-') {
				/* Removing an env var */
				rm_env(options, arg, filename, linenum);
				जारी;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &options->send_env, &options->अंक_send_env, arg);
		}
		अगर (!found) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		अवरोध;

	हाल oSetEnv:
		found = options->अंक_setenv == 0;
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			अगर (म_अक्षर(arg, '=') == शून्य) {
				error("%s line %d: Invalid SetEnv.",
				    filename, linenum);
				जाओ out;
			}
			अगर (lookup_setenv_in_list(arg, strs, nstrs) != शून्य) {
				debug2("%s line %d: ignoring duplicate env "
				    "name \"%.64s\"", filename, linenum, arg);
				जारी;
			}
			opt_array_append(filename, linenum,
			    lookup_opcode_name(opcode),
			    &strs, &nstrs, arg);
		}
		अगर (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		अगर (found && *activep) {
			options->setenv = strs;
			options->अंक_setenv = nstrs;
			strs = शून्य; /* transferred */
			nstrs = 0;
		}
		अवरोध;

	हाल oControlPath:
		charptr = &options->control_path;
		जाओ parse_string;

	हाल oControlMaster:
		intptr = &options->control_master;
		multistate_ptr = multistate_controlmaster;
		जाओ parse_multistate;

	हाल oControlPersist:
		/* no/false/yes/true, or a time spec */
		intptr = &options->control_persist;
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing ControlPersist"
			    " argument.", filename, linenum);
			जाओ out;
		}
		मूल्य = 0;
		value2 = 0;	/* timeout */
		अगर (म_भेद(arg, "no") == 0 || म_भेद(arg, "false") == 0)
			मूल्य = 0;
		अन्यथा अगर (म_भेद(arg, "yes") == 0 || म_भेद(arg, "true") == 0)
			मूल्य = 1;
		अन्यथा अगर ((value2 = convtime(arg)) >= 0)
			मूल्य = 1;
		अन्यथा {
			error("%.200s line %d: Bad ControlPersist argument.",
			    filename, linenum);
			जाओ out;
		}
		अगर (*activep && *intptr == -1) {
			*intptr = मूल्य;
			options->control_persist_timeout = value2;
		}
		अवरोध;

	हाल oHashKnownHosts:
		intptr = &options->hash_known_hosts;
		जाओ parse_flag;

	हाल oTunnel:
		intptr = &options->tun_open;
		multistate_ptr = multistate_tunnel;
		जाओ parse_multistate;

	हाल oTunnelDevice:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जाओ out;
		}
		मूल्य = a2tun(arg, &value2);
		अगर (मूल्य == SSH_TUNID_ERR) {
			error("%.200s line %d: Bad tun device.",
			    filename, linenum);
			जाओ out;
		}
		अगर (*activep && options->tun_local == -1) {
			options->tun_local = मूल्य;
			options->tun_remote = value2;
		}
		अवरोध;

	हाल oLocalCommand:
		charptr = &options->local_command;
		जाओ parse_command;

	हाल oPermitLocalCommand:
		intptr = &options->permit_local_command;
		जाओ parse_flag;

	हाल oRemoteCommand:
		charptr = &options->remote_command;
		जाओ parse_command;

	हाल o_Visual_Host_कुंजी:
		intptr = &options->visual_host_कुंजी;
		जाओ parse_flag;

	हाल oInclude:
		अगर (cmdline) {
			error("Include directive not supported as a "
			    "command-line option");
			जाओ out;
		}
		मूल्य = 0;
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			अगर (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				जाओ out;
			}
			/* Expand %tokens and environment variables */
			अगर ((p = expand_match_exec_or_include_path(arg,
			    options, pw, host, original_host,
			    flags & SSHCONF_FINAL, 1)) == शून्य) {
				error("%.200s line %d: Unable to expand user "
				    "config file '%.100s'",
				    filename, linenum, arg);
				जारी;
			}
			/*
			 * Ensure all paths are anchored. User configuration
			 * files may begin with '~/' but system configurations
			 * must not. If the path is relative, then treat it
			 * as living in ~/.ssh for user configurations or
			 * /etc/ssh for system ones.
			 */
			अगर (*p == '~' && (flags & SSHCONF_USERCONF) == 0) {
				error("%.200s line %d: bad include path %s.",
				    filename, linenum, p);
				जाओ out;
			}
			अगर (!path_absolute(p) && *p != '~') {
				xasprintf(&arg2, "%s/%s",
				    (flags & SSHCONF_USERCONF) ?
				    "~/" _PATH_SSH_USER_DIR : SSHDIR, p);
			} अन्यथा {
				arg2 = xstrdup(p);
			}
			मुक्त(p);
			स_रखो(&gl, 0, माप(gl));
			r = glob(arg2, GLOB_TILDE, शून्य, &gl);
			अगर (r == GLOB_NOMATCH) {
				debug("%.200s line %d: include %s matched no "
				    "files",filename, linenum, arg2);
				मुक्त(arg2);
				जारी;
			} अन्यथा अगर (r != 0) {
				error("%.200s line %d: glob failed for %s.",
				    filename, linenum, arg2);
				जाओ out;
			}
			मुक्त(arg2);
			oactive = *activep;
			क्रम (i = 0; i < gl.gl_pathc; i++) {
				debug3("%.200s line %d: Including file %s "
				    "depth %d%s", filename, linenum,
				    gl.gl_pathv[i], depth,
				    oactive ? "" : " (parse only)");
				r = read_config_file_depth(gl.gl_pathv[i],
				    pw, host, original_host, remote_command,
				    options, flags | SSHCONF_CHECKPERM |
				    (oactive ? 0 : SSHCONF_NEVERMATCH),
				    activep, want_final_pass, depth + 1);
				अगर (r != 1 && त्रुटि_सं != ENOENT) {
					error("%.200s line %d: Can't open user "
					    "config file %.100s: %.100s",
					    filename, linenum, gl.gl_pathv[i],
					    म_त्रुटि(त्रुटि_सं));
					globfree(&gl);
					जाओ out;
				}
				/*
				 * don't let Match in includes clobber the
				 * containing file's Match state.
				 */
				*activep = oactive;
				अगर (r != 1)
					मूल्य = -1;
			}
			globfree(&gl);
		}
		अगर (मूल्य != 0)
			ret = मूल्य;
		अवरोध;

	हाल oIPQoS:
		arg = argv_अग्र(&ac, &av);
		अगर ((मूल्य = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			जाओ out;
		}
		अगर (मूल्य == पूर्णांक_न्यून) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			मूल्य = पूर्णांक_उच्च;
		}
		arg = argv_अग्र(&ac, &av);
		अगर (arg == शून्य)
			value2 = मूल्य;
		अन्यथा अगर ((value2 = parse_ipqos(arg)) == -1) {
			error("%s line %d: Bad IPQoS value: %s",
			    filename, linenum, arg);
			जाओ out;
		}
		अगर (value2 == पूर्णांक_न्यून) {
			debug("%s line %d: Deprecated IPQoS value \"%s\" "
			    "ignored - using system default instead. Consider"
			    " using DSCP values.", filename, linenum, arg);
			value2 = पूर्णांक_उच्च;
		}
		अगर (*activep && options->ip_qos_interactive == -1) {
			options->ip_qos_interactive = मूल्य;
			options->ip_qos_bulk = value2;
		}
		अवरोध;

	हाल oRequestTTY:
		intptr = &options->request_tty;
		multistate_ptr = multistate_requesttty;
		जाओ parse_multistate;

	हाल oSessionType:
		intptr = &options->session_type;
		multistate_ptr = multistate_sessiontype;
		जाओ parse_multistate;

	हाल oStdinNull:
		intptr = &options->stdin_null;
		जाओ parse_flag;

	हाल oForkAfterAuthentication:
		intptr = &options->fork_after_authentication;
		जाओ parse_flag;

	हाल oIgnoreUnknown:
		charptr = &options->ignored_unknown;
		जाओ parse_string;

	हाल oProxyUseFdpass:
		intptr = &options->proxy_use_fdpass;
		जाओ parse_flag;

	हाल oCanonicalDomains:
		found = options->अंक_canonical_domains == 0;
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			/* Allow "none" only in first position */
			अगर (strcasecmp(arg, "none") == 0) {
				अगर (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					जाओ out;
				}
			}
			अगर (!valid_domain(arg, 1, &errstr)) {
				error("%s line %d: %s", filename, linenum,
				    errstr);
				जाओ out;
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		अगर (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		अगर (found && *activep) {
			options->canonical_domains = strs;
			options->अंक_canonical_domains = nstrs;
			strs = शून्य; /* transferred */
			nstrs = 0;
		}
		अवरोध;

	हाल oCanonicalizePermittedCNAMEs:
		found = options->अंक_permitted_cnames == 0;
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			/*
			 * Either 'none' (only in first position), '*' for
			 * everything or 'list:list'
			 */
			अगर (strcasecmp(arg, "none") == 0) {
				अगर (ncnames > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					जाओ out;
				}
				arg2 = "";
			} अन्यथा अगर (म_भेद(arg, "*") == 0) {
				arg2 = arg;
			} अन्यथा {
				lowercase(arg);
				अगर ((arg2 = म_अक्षर(arg, ':')) == शून्य ||
				    arg2[1] == '\0') {
					error("%s line %d: "
					    "Invalid permitted CNAME \"%s\"",
					    filename, linenum, arg);
					जाओ out;
				}
				*arg2 = '\0';
				arg2++;
			}
			cnames = xrecallocarray(cnames, ncnames, ncnames + 1,
			    माप(*cnames));
			cnames[ncnames].source_list = xstrdup(arg);
			cnames[ncnames].target_list = xstrdup(arg2);
			ncnames++;
		}
		अगर (ncnames == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		अगर (found && *activep) {
			options->permitted_cnames = cnames;
			options->अंक_permitted_cnames = ncnames;
			cnames = शून्य; /* transferred */
			ncnames = 0;
		}
		/* un-transferred cnames is cleaned up before exit */
		अवरोध;

	हाल oCanonicalizeHostname:
		intptr = &options->canonicalize_hostname;
		multistate_ptr = multistate_canonicalizehostname;
		जाओ parse_multistate;

	हाल oCanonicalizeMaxDots:
		intptr = &options->canonicalize_max_dots;
		जाओ parse_int;

	हाल oCanonicalizeFallbackLocal:
		intptr = &options->canonicalize_fallback_local;
		जाओ parse_flag;

	हाल oStreamLocalBindMask:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing StreamLocalBindMask "
			    "argument.", filename, linenum);
			जाओ out;
		}
		/* Parse mode in octal format */
		मूल्य = म_से_दीर्घ(arg, &endofnumber, 8);
		अगर (arg == endofnumber || मूल्य < 0 || मूल्य > 0777) {
			error("%.200s line %d: Bad mask.", filename, linenum);
			जाओ out;
		}
		अगर (*activep &&
		    options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
			options->fwd_opts.streamlocal_bind_mask = (mode_t)मूल्य;
		अवरोध;

	हाल oStreamLocalBindUnlink:
		intptr = &options->fwd_opts.streamlocal_bind_unlink;
		जाओ parse_flag;

	हाल o_Revoked_Host_कुंजियाँ:
		uintptr = &options->अंक_revoked_host_कुंजियाँ;
		cppptr = &options->revoked_host_कुंजियाँ;
		found = *uintptr == 0;
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			अगर (*arg == '\0') {
				error("%s line %d: keyword %s empty argument",
				    filename, linenum, keyword);
				जाओ out;
			}
			/* Allow "none" only in first position */
			अगर (strcasecmp(arg, "none") == 0) {
				अगर (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					जाओ out;
				}
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		अगर (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		अगर (found && *activep) {
			*cppptr = strs;
			*uintptr = nstrs;
			strs = शून्य; /* transferred */
			nstrs = 0;
		}
		अवरोध;

	हाल oFingerprintHash:
		intptr = &options->fingerprint_hash;
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जाओ out;
		}
		अगर ((मूल्य = ssh_digest_alg_by_name(arg)) == -1) {
			error("%.200s line %d: Invalid hash algorithm \"%s\".",
			    filename, linenum, arg);
			जाओ out;
		}
		अगर (*activep && *intptr == -1)
			*intptr = मूल्य;
		अवरोध;

	हाल oUpdateHostkeys:
		intptr = &options->update_hostkeys;
		multistate_ptr = multistate_yesnoask;
		जाओ parse_multistate;

	हाल oHostbasedAcceptedAlgorithms:
		charptr = &options->hostbased_accepted_algos;
		ca_only = 0;
		जाओ parse_pubkey_algos;

	हाल oPubkeyAcceptedAlgorithms:
		charptr = &options->pubkey_accepted_algos;
		ca_only = 0;
		जाओ parse_pubkey_algos;

	हाल o_Add_कुंजियाँ_To_Agent:
		arg = argv_अग्र(&ac, &av);
		arg2 = argv_अग्र(&ac, &av);
		मूल्य = parse_multistate_मूल्य(arg, filename, linenum,
		    multistate_yesnoaskconfirm);
		value2 = 0; /* unlimited lifespan by default */
		अगर (मूल्य == 3 && arg2 != शून्य) {
			/* allow "AddKeysToAgent confirm 5m" */
			अगर ((value2 = convtime(arg2)) == -1) {
				error("%s line %d: invalid time value.",
				    filename, linenum);
				जाओ out;
			}
		} अन्यथा अगर (मूल्य == -1 && arg2 == शून्य) {
			अगर ((value2 = convtime(arg)) == -1) {
				error("%s line %d: unsupported option",
				    filename, linenum);
				जाओ out;
			}
			मूल्य = 1; /* yes */
		} अन्यथा अगर (मूल्य == -1 || arg2 != शून्य) {
			error("%s line %d: unsupported option",
			    filename, linenum);
			जाओ out;
		}
		अगर (*activep && options->add_कुंजियाँ_to_agent == -1) {
			options->add_कुंजियाँ_to_agent = मूल्य;
			options->add_कुंजियाँ_to_agent_lifespan = value2;
		}
		अवरोध;

	हाल oIdentityAgent:
		charptr = &options->identity_agent;
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जाओ out;
		}
  parse_agent_path:
		/* Extra validation if the string represents an env var. */
		अगर ((arg2 = dollar_expand(&r, arg)) == शून्य || r) {
			error("%.200s line %d: Invalid environment expansion "
			    "%s.", filename, linenum, arg);
			जाओ out;
		}
		मुक्त(arg2);
		/* check for legacy environment format */
		अगर (arg[0] == '$' && arg[1] != '{' &&
		    !valid_env_name(arg + 1)) {
			error("%.200s line %d: Invalid environment name %s.",
			    filename, linenum, arg);
			जाओ out;
		}
		अगर (*activep && *charptr == शून्य)
			*charptr = xstrdup(arg);
		अवरोध;

	हाल oEnableEscapeCommandline:
		intptr = &options->enable_escape_commandline;
		जाओ parse_flag;

	हाल oRequiredRSASize:
		intptr = &options->required_rsa_आकार;
		जाओ parse_int;

	हाल oWarnWeakCrypto:
		intptr = &options->warn_weak_crypto;
		multistate_ptr = multistate_warnweakcrypto;
		जाओ parse_multistate;

	हाल oObscureKeystrokeTiming:
		मूल्य = -1;
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			अगर (मूल्य != -1) {
				error("%s line %d: invalid arguments",
				    filename, linenum);
				जाओ out;
			}
			अगर (म_भेद(arg, "yes") == 0 ||
			    म_भेद(arg, "true") == 0)
				मूल्य = SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
			अन्यथा अगर (म_भेद(arg, "no") == 0 ||
			    म_भेद(arg, "false") == 0)
				मूल्य = 0;
			अन्यथा अगर (म_भेदन(arg, "interval:", 9) == 0) {
				अगर ((errstr = atoi_err(arg + 9,
				    &मूल्य)) != शून्य) {
					error("%s line %d: integer value %s.",
					    filename, linenum, errstr);
					जाओ out;
				}
				अगर (मूल्य <= 0 || मूल्य > 1000) {
					error("%s line %d: value out of range.",
					    filename, linenum);
					जाओ out;
				}
			} अन्यथा {
				error("%s line %d: unsupported argument \"%s\"",
				    filename, linenum, arg);
				जाओ out;
			}
		}
		अगर (मूल्य == -1) {
			error("%s line %d: missing argument",
			    filename, linenum);
			जाओ out;
		}
		intptr = &options->obscure_keystroke_timing_interval;
		अगर (*activep && *intptr == -1)
			*intptr = मूल्य;
		अवरोध;

	हाल oChannelTimeout:
		found = options->अंक_channel_timeouts == 0;
		जबतक ((arg = argv_अग्र(&ac, &av)) != शून्य) {
			/* Allow "none" only in first position */
			अगर (strcasecmp(arg, "none") == 0) {
				अगर (nstrs > 0 || ac > 0) {
					error("%s line %d: keyword %s \"none\" "
					    "argument must appear alone.",
					    filename, linenum, keyword);
					जाओ out;
				}
			} अन्यथा अगर (parse_pattern_interval(arg,
			    शून्य, शून्य) != 0) {
				fatal("%s line %d: invalid channel timeout %s",
				    filename, linenum, arg);
			}
			opt_array_append(filename, linenum, keyword,
			    &strs, &nstrs, arg);
		}
		अगर (nstrs == 0) {
			fatal("%s line %d: no %s specified",
			    filename, linenum, keyword);
		}
		अगर (found && *activep) {
			options->channel_timeouts = strs;
			options->अंक_channel_timeouts = nstrs;
			strs = शून्य; /* transferred */
			nstrs = 0;
		}
		अवरोध;

	हाल oVersionAddendum:
		अगर (str == शून्य || *str == '\0')
			fatal("%s line %d: %s missing argument.",
			    filename, linenum, keyword);
		len = म_अखोज(str, WHITESPACE);
		अगर (म_अक्षर(str + len, '\r') != शून्य) {
			fatal("%.200s line %d: Invalid %s argument",
			    filename, linenum, keyword);
		}
		अगर ((arg = म_अक्षर(पंक्ति, '#')) != शून्य) {
			*arg = '\0';
			rtrim(पंक्ति);
		}
		अगर (*activep && options->version_addendum == शून्य) {
			अगर (strcasecmp(str + len, "none") == 0)
				options->version_addendum = xstrdup("");
			अन्यथा
				options->version_addendum = xstrdup(str + len);
		}
		argv_consume(&ac);
		अवरोध;

	हाल oRefuseConnection:
		arg = argv_अग्र(&ac, &av);
		अगर (!arg || *arg == '\0') {
			error("%.200s line %d: Missing argument.",
			    filename, linenum);
			जाओ out;
		}
		अगर (*activep) {
			fatal("%.200s line %d: RefuseConnection: %s",
			    filename, linenum, arg);
		}
		अवरोध;

	हाल oDeprecated:
		debug("%s line %d: Deprecated option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		अवरोध;

	हाल oUnsupported:
		error("%s line %d: Unsupported option \"%s\"",
		    filename, linenum, keyword);
		argv_consume(&ac);
		अवरोध;

	शेष:
		error("%s line %d: Unimplemented opcode %d",
		    filename, linenum, opcode);
		जाओ out;
	}

	/* Check that there is no garbage at end of line. */
	अगर (ac > 0) {
		error("%.200s line %d: keyword %s extra arguments "
		    "at end of line", filename, linenum, keyword);
		जाओ out;
	}

	/* success */
	ret = 0;
 out:
	free_canon_cnames(cnames, ncnames);
	opt_array_free2(strs, शून्य, nstrs);
	argv_free(oav, oac);
	वापस ret;
}

/*
 * Reads the config file and modifies the options accordingly.  Options
 * should already be initialized before this call.  This never returns if
 * there is an error.  If the file does not exist, this returns 0.
 */
पूर्णांक
read_config_file(स्थिर अक्षर *filename, काष्ठा passwd *pw, स्थिर अक्षर *host,
    स्थिर अक्षर *original_host, स्थिर अक्षर *remote_command, Options *options, पूर्णांक flags,
    पूर्णांक *want_final_pass)
{
	पूर्णांक active = 1;

	वापस read_config_file_depth(filename, pw, host, original_host,
	    remote_command, options, flags, &active, want_final_pass, 0);
}

#घोषणा READCONF_MAX_DEPTH	16
अटल पूर्णांक
read_config_file_depth(स्थिर अक्षर *filename, काष्ठा passwd *pw,
    स्थिर अक्षर *host, स्थिर अक्षर *original_host, स्थिर अक्षर *remote_command,
    Options *options, पूर्णांक flags, पूर्णांक *activep, पूर्णांक *want_final_pass, पूर्णांक depth)
{
	खाता *f;
	अक्षर *पंक्ति = शून्य;
	माप_प्रकार linesize = 0;
	पूर्णांक linenum;
	पूर्णांक bad_options = 0;

	अगर (depth < 0 || depth > READCONF_MAX_DEPTH)
		fatal("Too many recursive configuration includes");

	अगर ((f = ख_खोलो(filename, "r")) == शून्य)
		वापस 0;

	अगर (flags & SSHCONF_CHECKPERM) {
		काष्ठा stat sb;

		अगर (ख_स्थिति(fileno(f), &sb) == -1)
			fatal("fstat %s: %s", filename, म_त्रुटि(त्रुटि_सं));
		अगर (((sb.st_uid != 0 && sb.st_uid != getuid()) ||
		    (sb.st_mode & 022) != 0))
			fatal("Bad owner or permissions on %s", filename);
	}

	debug("Reading configuration data %.200s", filename);

	/*
	 * Mark that we are now processing the options.  This flag is turned
	 * on/off by Host specifications.
	 */
	linenum = 0;
	जबतक (getline(&पंक्ति, &linesize, f) != -1) {
		/* Update line number counter. */
		linenum++;
		/*
		 * Trim out comments and strip whitespace.
		 * NB - preserve newlines, they are needed to reproduce
		 * line numbers later for error messages.
		 */
		अगर (process_config_पंक्ति_depth(options, pw, host, original_host,
		    remote_command, पंक्ति, filename, linenum, activep, flags,
		    want_final_pass, depth) != 0)
			bad_options++;
	}
	मुक्त(पंक्ति);
	ख_बंद(f);
	अगर (bad_options > 0)
		fatal("%s: terminating, %d bad configuration options",
		    filename, bad_options);
	वापस 1;
}

/* Returns 1 if a string option is unset or set to "none" or 0 otherwise. */
पूर्णांक
option_clear_or_none(स्थिर अक्षर *o)
{
	वापस o == शून्य || strcasecmp(o, "none") == 0;
}

/*
 * Returns 1 if CanonicalizePermittedCNAMEs have been specified, 0 otherwise.
 * Allowed to be called on non-final configuration.
 */
पूर्णांक
config_has_permitted_cnames(Options *options)
{
	अगर (options->अंक_permitted_cnames == 1 &&
	    strcasecmp(options->permitted_cnames[0].source_list, "none") == 0 &&
	    म_भेद(options->permitted_cnames[0].target_list, "") == 0)
		वापस 0;
	वापस options->अंक_permitted_cnames > 0;
}

/*
 * Initializes options to special values that indicate that they have not yet
 * been set.  Read_config_file will only set options with this value. Options
 * are processed in the following order: command line, user config file,
 * system config file.  Last, fill_default_options is called.
 */

व्योम
initialize_options(Options * options)
{
	स_रखो(options, 'X', माप(*options));
	options->host_arg = शून्य;
	options->forward_agent = -1;
	options->forward_agent_sock_path = शून्य;
	options->forward_x11 = -1;
	options->forward_x11_trusted = -1;
	options->forward_x11_timeout = -1;
	options->stdio_forward_host = शून्य;
	options->stdio_forward_port = 0;
	options->clear_forwardings = -1;
	options->exit_on_forward_failure = -1;
	options->xauth_location = शून्य;
	options->fwd_opts.gateway_ports = -1;
	options->fwd_opts.streamlocal_bind_mask = (mode_t)-1;
	options->fwd_opts.streamlocal_bind_unlink = -1;
	options->pubkey_authentication = -1;
	options->gss_authentication = -1;
	options->gss_deleg_creds = -1;
	options->password_authentication = -1;
	options->kbd_interactive_authentication = -1;
	options->kbd_interactive_devices = शून्य;
	options->hostbased_authentication = -1;
	options->batch_mode = -1;
	options->check_host_ip = -1;
	options->strict_host_कुंजी_checking = -1;
	options->compression = -1;
	options->tcp_keep_alive = -1;
	options->port = -1;
	options->address_family = -1;
	options->connection_attempts = -1;
	options->connection_timeout = -1;
	options->संख्या_of_password_prompts = -1;
	options->ciphers = शून्य;
	options->macs = शून्य;
	options->kex_algorithms = शून्य;
	options->hostkeyalgorithms = शून्य;
	options->ca_sign_algorithms = शून्य;
	options->अंक_identity_files = 0;
	स_रखो(options->identity_कुंजियाँ, 0, माप(options->identity_कुंजियाँ));
	options->अंक_certificate_files = 0;
	स_रखो(options->certificates, 0, माप(options->certificates));
	options->hostname = शून्य;
	options->host_कुंजी_alias = शून्य;
	options->proxy_command = शून्य;
	options->jump_user = शून्य;
	options->jump_host = शून्य;
	options->jump_port = -1;
	options->jump_extra = शून्य;
	options->user = शून्य;
	options->escape_char = -1;
	options->अंक_system_hostfiles = 0;
	options->अंक_user_hostfiles = 0;
	options->local_forwards = शून्य;
	options->अंक_local_forwards = 0;
	options->remote_forwards = शून्य;
	options->अंक_remote_forwards = 0;
	options->permitted_remote_opens = शून्य;
	options->अंक_permitted_remote_opens = 0;
	options->log_facility = SYSLOG_FACILITY_NOT_SET;
	options->log_level = SYSLOG_LEVEL_NOT_SET;
	options->अंक_log_verbose = 0;
	options->log_verbose = शून्य;
	options->preferred_authentications = शून्य;
	options->bind_address = शून्य;
	options->bind_interface = शून्य;
	options->pkcs11_provider = शून्य;
	options->sk_provider = शून्य;
	options->enable_ssh_keysign = -1;
	options->no_host_authentication_for_localhost = -1;
	options->identities_only = -1;
	options->rekey_limit = -1;
	options->rekey_interval = -1;
	options->verify_host_कुंजी_dns = -1;
	options->server_alive_interval = -1;
	options->server_alive_गिनती_max = -1;
	options->send_env = शून्य;
	options->अंक_send_env = 0;
	options->setenv = शून्य;
	options->अंक_setenv = 0;
	options->control_path = शून्य;
	options->control_master = -1;
	options->control_persist = -1;
	options->control_persist_timeout = 0;
	options->hash_known_hosts = -1;
	options->tun_open = -1;
	options->tun_local = -1;
	options->tun_remote = -1;
	options->local_command = शून्य;
	options->permit_local_command = -1;
	options->remote_command = शून्य;
	options->add_कुंजियाँ_to_agent = -1;
	options->add_कुंजियाँ_to_agent_lifespan = -1;
	options->identity_agent = शून्य;
	options->visual_host_कुंजी = -1;
	options->ip_qos_interactive = -1;
	options->ip_qos_bulk = -1;
	options->request_tty = -1;
	options->session_type = -1;
	options->stdin_null = -1;
	options->fork_after_authentication = -1;
	options->proxy_use_fdpass = -1;
	options->ignored_unknown = शून्य;
	options->अंक_canonical_domains = 0;
	options->अंक_permitted_cnames = 0;
	options->canonicalize_max_dots = -1;
	options->canonicalize_fallback_local = -1;
	options->canonicalize_hostname = -1;
	options->revoked_host_कुंजियाँ = शून्य;
	options->अंक_revoked_host_कुंजियाँ = 0;
	options->fingerprint_hash = -1;
	options->update_hostkeys = -1;
	options->hostbased_accepted_algos = शून्य;
	options->pubkey_accepted_algos = शून्य;
	options->known_hosts_command = शून्य;
	options->required_rsa_आकार = -1;
	options->warn_weak_crypto = -1;
	options->enable_escape_commandline = -1;
	options->obscure_keystroke_timing_interval = -1;
	options->tag = शून्य;
	options->channel_timeouts = शून्य;
	options->अंक_channel_timeouts = 0;
	options->version_addendum = शून्य;
}

/*
 * A petite version of fill_default_options() that just fills the options
 * needed for hostname canonicalization to proceed.
 */
व्योम
fill_default_options_for_canonicalization(Options *options)
{
	अगर (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	अगर (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	अगर (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
}

/*
 * Called after processing other sources of option data, this fills those
 * options for which no value has been specified with their default values.
 */
पूर्णांक
fill_default_options(Options * options)
{
	अक्षर *all_cipher, *all_mac, *all_kex, *all_कुंजी, *all_sig;
	अक्षर *def_cipher, *def_mac, *def_kex, *def_कुंजी, *def_sig;
	पूर्णांक ret = -1, r;

	अगर (options->forward_agent == -1)
		options->forward_agent = 0;
	अगर (options->forward_x11 == -1)
		options->forward_x11 = 0;
	अगर (options->forward_x11_trusted == -1)
		options->forward_x11_trusted = 0;
	अगर (options->forward_x11_timeout == -1)
		options->forward_x11_timeout = 1200;
	/*
	 * stdio forwarding (-W) changes the default for these but we defer
	 * setting the values so they can be overridden.
	 */
	अगर (options->exit_on_forward_failure == -1)
		options->exit_on_forward_failure =
		    options->stdio_forward_host != शून्य ? 1 : 0;
	अगर (options->clear_forwardings == -1)
		options->clear_forwardings =
		    options->stdio_forward_host != शून्य ? 1 : 0;
	अगर (options->clear_forwardings == 1)
		clear_forwardings(options);

	अगर (options->xauth_location == शून्य)
		options->xauth_location = xstrdup(_PATH_XAUTH);
	अगर (options->fwd_opts.gateway_ports == -1)
		options->fwd_opts.gateway_ports = 0;
	अगर (options->fwd_opts.streamlocal_bind_mask == (mode_t)-1)
		options->fwd_opts.streamlocal_bind_mask = 0177;
	अगर (options->fwd_opts.streamlocal_bind_unlink == -1)
		options->fwd_opts.streamlocal_bind_unlink = 0;
	अगर (options->pubkey_authentication == -1)
		options->pubkey_authentication = SSH_PUBKEY_AUTH_ALL;
	अगर (options->gss_authentication == -1)
		options->gss_authentication = 0;
	अगर (options->gss_deleg_creds == -1)
		options->gss_deleg_creds = 0;
	अगर (options->password_authentication == -1)
		options->password_authentication = 1;
	अगर (options->kbd_interactive_authentication == -1)
		options->kbd_interactive_authentication = 1;
	अगर (options->hostbased_authentication == -1)
		options->hostbased_authentication = 0;
	अगर (options->batch_mode == -1)
		options->batch_mode = 0;
	अगर (options->check_host_ip == -1)
		options->check_host_ip = 0;
	अगर (options->strict_host_कुंजी_checking == -1)
		options->strict_host_कुंजी_checking = SSH_STRICT_HOSTKEY_ASK;
	अगर (options->compression == -1)
		options->compression = 0;
	अगर (options->tcp_keep_alive == -1)
		options->tcp_keep_alive = SSH_KEEPALIVES_TRANSPORT;
	अगर (options->port == -1)
		options->port = 0;	/* Filled in ssh_connect. */
	अगर (options->address_family == -1)
		options->address_family = AF_UNSPEC;
	अगर (options->connection_attempts == -1)
		options->connection_attempts = 1;
	अगर (options->संख्या_of_password_prompts == -1)
		options->संख्या_of_password_prompts = 3;
	/* options->hostkeyalgorithms, default set in myproposals.h */
	अगर (options->add_कुंजियाँ_to_agent == -1) {
		options->add_कुंजियाँ_to_agent = 0;
		options->add_कुंजियाँ_to_agent_lifespan = 0;
	}
	अगर (options->अंक_identity_files == 0) {
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
	अगर (options->escape_char == -1)
		options->escape_char = '~';
	अगर (options->अंक_system_hostfiles == 0) {
		options->system_hostfiles[options->अंक_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE);
		options->system_hostfiles[options->अंक_system_hostfiles++] =
		    xstrdup(_PATH_SSH_SYSTEM_HOSTFILE2);
	}
	अगर (options->update_hostkeys == -1) {
		अगर (options->verify_host_कुंजी_dns <= 0 &&
		    (options->अंक_user_hostfiles == 0 ||
		    (options->अंक_user_hostfiles == 1 && म_भेद(options->
		    user_hostfiles[0], _PATH_SSH_USER_HOSTFILE) == 0)))
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_YES;
		अन्यथा
			options->update_hostkeys = SSH_UPDATE_HOSTKEYS_NO;
	}
	अगर (options->अंक_user_hostfiles == 0) {
		options->user_hostfiles[options->अंक_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE);
		options->user_hostfiles[options->अंक_user_hostfiles++] =
		    xstrdup(_PATH_SSH_USER_HOSTFILE2);
	}
	अगर (options->log_level == SYSLOG_LEVEL_NOT_SET)
		options->log_level = SYSLOG_LEVEL_INFO;
	अगर (options->log_facility == SYSLOG_FACILITY_NOT_SET)
		options->log_facility = SYSLOG_FACILITY_USER;
	अगर (options->no_host_authentication_for_localhost == -1)
		options->no_host_authentication_for_localhost = 0;
	अगर (options->identities_only == -1)
		options->identities_only = 0;
	अगर (options->enable_ssh_keysign == -1)
		options->enable_ssh_keysign = 0;
	अगर (options->rekey_limit == -1)
		options->rekey_limit = 0;
	अगर (options->rekey_interval == -1)
		options->rekey_interval = 0;
	अगर (options->verify_host_कुंजी_dns == -1)
		options->verify_host_कुंजी_dns = 0;
	अगर (options->server_alive_interval == -1)
		options->server_alive_interval = 0;
	अगर (options->server_alive_गिनती_max == -1)
		options->server_alive_गिनती_max = 3;
	अगर (options->control_master == -1)
		options->control_master = 0;
	अगर (options->control_persist == -1) {
		options->control_persist = 0;
		options->control_persist_timeout = 0;
	}
	अगर (options->hash_known_hosts == -1)
		options->hash_known_hosts = 0;
	अगर (options->tun_open == -1)
		options->tun_open = SSH_TUNMODE_NO;
	अगर (options->tun_local == -1)
		options->tun_local = SSH_TUNID_ANY;
	अगर (options->tun_remote == -1)
		options->tun_remote = SSH_TUNID_ANY;
	अगर (options->permit_local_command == -1)
		options->permit_local_command = 0;
	अगर (options->visual_host_कुंजी == -1)
		options->visual_host_कुंजी = 0;
	अगर (options->ip_qos_interactive == -1)
		options->ip_qos_interactive = IPTOS_DSCP_EF;
	अगर (options->ip_qos_bulk == -1)
		options->ip_qos_bulk = IPTOS_DSCP_CS0;
	अगर (options->request_tty == -1)
		options->request_tty = REQUEST_TTY_AUTO;
	अगर (options->session_type == -1)
		options->session_type = SESSION_TYPE_DEFAULT;
	अगर (options->stdin_null == -1)
		options->stdin_null = 0;
	अगर (options->fork_after_authentication == -1)
		options->fork_after_authentication = 0;
	अगर (options->proxy_use_fdpass == -1)
		options->proxy_use_fdpass = 0;
	अगर (options->canonicalize_max_dots == -1)
		options->canonicalize_max_dots = 1;
	अगर (options->canonicalize_fallback_local == -1)
		options->canonicalize_fallback_local = 1;
	अगर (options->canonicalize_hostname == -1)
		options->canonicalize_hostname = SSH_CANONICALISE_NO;
	अगर (options->fingerprint_hash == -1)
		options->fingerprint_hash = SSH_FP_HASH_DEFAULT;
#अगर_घोषित ENABLE_SK_INTERNAL
	अगर (options->sk_provider == शून्य)
		options->sk_provider = xstrdup("internal");
#अन्यथा
	अगर (options->sk_provider == शून्य)
		options->sk_provider = xstrdup("$SSH_SK_PROVIDER");
#पूर्ण_अगर
	अगर (options->required_rsa_आकार == -1)
		options->required_rsa_आकार = SSH_RSA_MINIMUM_MODULUS_आकार;
	अगर (options->warn_weak_crypto == -1)
		options->warn_weak_crypto = 1;
	अगर (options->enable_escape_commandline == -1)
		options->enable_escape_commandline = 0;
	अगर (options->obscure_keystroke_timing_interval == -1) {
		options->obscure_keystroke_timing_interval =
		    SSH_KEYSTROKE_DEFAULT_INTERVAL_MS;
	}

	/* Expand KEX name lists */
	all_cipher = cipher_alg_list(',', 0);
	all_mac = mac_alg_list(',');
	all_kex = kex_alg_list(',');
	all_कुंजी = sshkey_alg_list(0, 0, 1, ',');
	all_sig = sshkey_alg_list(0, 1, 1, ',');
	/* remove unsupported algos from default lists */
	def_cipher = match_filter_allowlist(KEX_CLIENT_ENCRYPT, all_cipher);
	def_mac = match_filter_allowlist(KEX_CLIENT_MAC, all_mac);
	def_kex = match_filter_allowlist(KEX_CLIENT_KEX, all_kex);
	def_कुंजी = match_filter_allowlist(KEX_DEFAULT_PK_ALG, all_कुंजी);
	def_sig = match_filter_allowlist(SSH_ALLOWED_CA_SIGALGS, all_sig);
#घोषणा ASSEMBLE(what, defaults, all) \
	करो { \
		अगर ((r = kex_assemble_names(&options->what, \
		    defaults, all)) != 0) { \
			error_fr(r, "%s", #what); \
			जाओ fail; \
		} \
	} जबतक (0)
	options->kex_algorithms_set = options->kex_algorithms != शून्य;
	ASSEMBLE(ciphers, def_cipher, all_cipher);
	ASSEMBLE(macs, def_mac, all_mac);
	ASSEMBLE(kex_algorithms, def_kex, all_kex);
	ASSEMBLE(hostbased_accepted_algos, def_कुंजी, all_कुंजी);
	ASSEMBLE(pubkey_accepted_algos, def_कुंजी, all_कुंजी);
	ASSEMBLE(ca_sign_algorithms, def_sig, all_sig);
#अघोषित ASSEMBLE

#घोषणा CLEAR_ON_NONE(v) \
	करो { \
		अगर (option_clear_or_none(v)) { \
			मुक्त(v); \
			v = शून्य; \
		} \
	} जबतक(0)
#घोषणा CLEAR_ON_NONE_ARRAY(v, nv, none) \
	करो { \
		अगर (options->nv == 1 && \
		    strcasecmp(options->v[0], none) == 0) { \
			मुक्त(options->v[0]); \
			मुक्त(options->v); \
			options->v = शून्य; \
			options->nv = 0; \
		} \
	} जबतक (0)
	CLEAR_ON_NONE(options->local_command);
	CLEAR_ON_NONE(options->remote_command);
	CLEAR_ON_NONE(options->proxy_command);
	CLEAR_ON_NONE(options->control_path);
	CLEAR_ON_NONE(options->pkcs11_provider);
	CLEAR_ON_NONE(options->sk_provider);
	CLEAR_ON_NONE(options->known_hosts_command);
	CLEAR_ON_NONE_ARRAY(channel_timeouts, अंक_channel_timeouts, "none");
	CLEAR_ON_NONE_ARRAY(revoked_host_कुंजियाँ, अंक_revoked_host_कुंजियाँ, "none");
#अघोषित CLEAR_ON_NONE
#अघोषित CLEAR_ON_NONE_ARRAY
	अगर (options->jump_host != शून्य &&
	    म_भेद(options->jump_host, "none") == 0 &&
	    options->jump_port == 0 && options->jump_user == शून्य) {
		मुक्त(options->jump_host);
		options->jump_host = शून्य;
	}
	अगर (options->अंक_permitted_cnames == 1 &&
	    !config_has_permitted_cnames(options)) {
		/* clean up CanonicalizePermittedCNAMEs=none */
		मुक्त(options->permitted_cnames[0].source_list);
		मुक्त(options->permitted_cnames[0].target_list);
		स_रखो(options->permitted_cnames, '\0',
		    माप(*options->permitted_cnames));
		options->अंक_permitted_cnames = 0;
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
	मुक्त(all_कुंजी);
	मुक्त(all_sig);
	मुक्त(def_cipher);
	मुक्त(def_mac);
	मुक्त(def_kex);
	मुक्त(def_कुंजी);
	मुक्त(def_sig);
	वापस ret;
}

व्योम
free_options(Options *o)
{
	पूर्णांक i;

	अगर (o == शून्य)
		वापस;

#घोषणा FREE_ARRAY(type, n, a) \
	करो { \
		type _i; \
		क्रम (_i = 0; _i < (n); _i++) \
			मुक्त((a)[_i]); \
	} जबतक (0)

	मुक्त(o->forward_agent_sock_path);
	मुक्त(o->xauth_location);
	FREE_ARRAY(u_int, o->अंक_log_verbose, o->log_verbose);
	मुक्त(o->log_verbose);
	मुक्त(o->ciphers);
	मुक्त(o->macs);
	मुक्त(o->hostkeyalgorithms);
	मुक्त(o->kex_algorithms);
	मुक्त(o->ca_sign_algorithms);
	मुक्त(o->hostname);
	मुक्त(o->host_कुंजी_alias);
	मुक्त(o->proxy_command);
	मुक्त(o->user);
	FREE_ARRAY(u_int, o->अंक_system_hostfiles, o->system_hostfiles);
	FREE_ARRAY(u_int, o->अंक_user_hostfiles, o->user_hostfiles);
	मुक्त(o->preferred_authentications);
	मुक्त(o->bind_address);
	मुक्त(o->bind_interface);
	मुक्त(o->pkcs11_provider);
	मुक्त(o->sk_provider);
	क्रम (i = 0; i < o->अंक_identity_files; i++) {
		मुक्त(o->identity_files[i]);
		sshkey_free(o->identity_कुंजियाँ[i]);
	}
	क्रम (i = 0; i < o->अंक_certificate_files; i++) {
		मुक्त(o->certificate_files[i]);
		sshkey_free(o->certificates[i]);
	}
	मुक्त(o->identity_agent);
	क्रम (i = 0; i < o->अंक_local_forwards; i++) {
		मुक्त(o->local_forwards[i].listen_host);
		मुक्त(o->local_forwards[i].listen_path);
		मुक्त(o->local_forwards[i].connect_host);
		मुक्त(o->local_forwards[i].connect_path);
	}
	मुक्त(o->local_forwards);
	क्रम (i = 0; i < o->अंक_remote_forwards; i++) {
		मुक्त(o->remote_forwards[i].listen_host);
		मुक्त(o->remote_forwards[i].listen_path);
		मुक्त(o->remote_forwards[i].connect_host);
		मुक्त(o->remote_forwards[i].connect_path);
	}
	मुक्त(o->remote_forwards);
	मुक्त(o->stdio_forward_host);
	FREE_ARRAY(u_int, o->अंक_send_env, o->send_env);
	मुक्त(o->send_env);
	FREE_ARRAY(u_int, o->अंक_setenv, o->setenv);
	मुक्त(o->setenv);
	मुक्त(o->control_path);
	मुक्त(o->local_command);
	मुक्त(o->remote_command);
	FREE_ARRAY(पूर्णांक, o->अंक_canonical_domains, o->canonical_domains);
	क्रम (i = 0; i < o->अंक_permitted_cnames; i++) {
		मुक्त(o->permitted_cnames[i].source_list);
		मुक्त(o->permitted_cnames[i].target_list);
	}
	FREE_ARRAY(u_int, o->अंक_revoked_host_कुंजियाँ, o->revoked_host_कुंजियाँ);
	मुक्त(o->revoked_host_कुंजियाँ);
	मुक्त(o->hostbased_accepted_algos);
	मुक्त(o->pubkey_accepted_algos);
	मुक्त(o->jump_user);
	मुक्त(o->jump_host);
	मुक्त(o->jump_extra);
	मुक्त(o->ignored_unknown);
	explicit_bzero(o, माप(*o));
#अघोषित FREE_ARRAY
}

काष्ठा fwdarg {
	अक्षर *arg;
	पूर्णांक ispath;
};

/*
 * parse_fwd_field
 * parses the next field in a port forwarding specification.
 * sets fwd to the parsed field and advances p past the colon
 * or sets it to NULL at end of string.
 * returns 0 on success, else non-zero.
 */
अटल पूर्णांक
parse_fwd_field(अक्षर **p, काष्ठा fwdarg *fwd)
{
	अक्षर *ep, *cp = *p;
	पूर्णांक ispath = 0;

	अगर (*cp == '\0') {
		*p = शून्य;
		वापस -1;	/* end of string */
	}

	/*
	 * A field escaped with square brackets is used literally.
	 * XXX - allow ']' to be escaped via backslash?
	 */
	अगर (*cp == '[') {
		/* find matching ']' */
		क्रम (ep = cp + 1; *ep != ']' && *ep != '\0'; ep++) {
			अगर (*ep == '/')
				ispath = 1;
		}
		/* no matching ']' or not at end of field. */
		अगर (ep[0] != ']' || (ep[1] != ':' && ep[1] != '\0'))
			वापस -1;
		/* NUL terminate the field and advance p past the colon */
		*ep++ = '\0';
		अगर (*ep != '\0')
			*ep++ = '\0';
		fwd->arg = cp + 1;
		fwd->ispath = ispath;
		*p = ep;
		वापस 0;
	}

	क्रम (cp = *p; *cp != '\0'; cp++) {
		चयन (*cp) {
		हाल '\\':
			स_हटाओ(cp, cp + 1, म_माप(cp + 1) + 1);
			अगर (*cp == '\0')
				वापस -1;
			अवरोध;
		हाल '/':
			ispath = 1;
			अवरोध;
		हाल ':':
			*cp++ = '\0';
			जाओ done;
		}
	}
done:
	fwd->arg = *p;
	fwd->ispath = ispath;
	*p = cp;
	वापस 0;
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
पूर्णांक
parse_forward(काष्ठा Forward *fwd, स्थिर अक्षर *fwdspec, पूर्णांक dynamicfwd, पूर्णांक remotefwd)
{
	काष्ठा fwdarg fwdargs[4];
	अक्षर *p, *cp;
	पूर्णांक i, err;

	स_रखो(fwd, 0, माप(*fwd));
	स_रखो(fwdargs, 0, माप(fwdargs));

	/*
	 * We expand environment variables before checking if we think they're
	 * paths so that if ${VAR} expands to a fully qualified path it is
	 * treated as a path.
	 */
	cp = p = dollar_expand(&err, fwdspec);
	अगर (p == शून्य || err)
		वापस 0;

	/* skip leading spaces */
	जबतक (है_खाली((u_char)*cp))
		cp++;

	क्रम (i = 0; i < 4; ++i) {
		अगर (parse_fwd_field(&cp, &fwdargs[i]) != 0)
			अवरोध;
	}

	/* Check for trailing garbage */
	अगर (cp != शून्य && *cp != '\0') {
		i = 0;	/* failure */
	}

	चयन (i) {
	हाल 1:
		अगर (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
		} अन्यथा {
			fwd->listen_host = शून्य;
			fwd->listen_port = a2port(fwdargs[0].arg);
		}
		fwd->connect_host = xstrdup("socks");
		अवरोध;

	हाल 2:
		अगर (fwdargs[0].ispath && fwdargs[1].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} अन्यथा अगर (fwdargs[1].ispath) {
			fwd->listen_host = शून्य;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_path = xstrdup(fwdargs[1].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} अन्यथा {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_host = xstrdup("socks");
		}
		अवरोध;

	हाल 3:
		अगर (fwdargs[0].ispath) {
			fwd->listen_path = xstrdup(fwdargs[0].arg);
			fwd->listen_port = PORT_STREAMLOCAL;
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		} अन्यथा अगर (fwdargs[2].ispath) {
			fwd->listen_host = xstrdup(fwdargs[0].arg);
			fwd->listen_port = a2port(fwdargs[1].arg);
			fwd->connect_path = xstrdup(fwdargs[2].arg);
			fwd->connect_port = PORT_STREAMLOCAL;
		} अन्यथा {
			fwd->listen_host = शून्य;
			fwd->listen_port = a2port(fwdargs[0].arg);
			fwd->connect_host = xstrdup(fwdargs[1].arg);
			fwd->connect_port = a2port(fwdargs[2].arg);
		}
		अवरोध;

	हाल 4:
		fwd->listen_host = xstrdup(fwdargs[0].arg);
		fwd->listen_port = a2port(fwdargs[1].arg);
		fwd->connect_host = xstrdup(fwdargs[2].arg);
		fwd->connect_port = a2port(fwdargs[3].arg);
		अवरोध;
	शेष:
		i = 0; /* failure */
	}

	मुक्त(p);

	अगर (dynamicfwd) {
		अगर (!(i == 1 || i == 2))
			जाओ fail_free;
	} अन्यथा {
		अगर (!(i == 3 || i == 4)) {
			अगर (fwd->connect_path == शून्य &&
			    fwd->listen_path == शून्य)
				जाओ fail_free;
		}
		अगर (fwd->connect_port <= 0 && fwd->connect_path == शून्य)
			जाओ fail_free;
	}

	अगर ((fwd->listen_port < 0 && fwd->listen_path == शून्य) ||
	    (!remotefwd && fwd->listen_port == 0))
		जाओ fail_free;
	अगर (fwd->connect_host != शून्य &&
	    म_माप(fwd->connect_host) >= NI_MAXHOST)
		जाओ fail_free;
	/*
	 * XXX - if connecting to a remote socket, max sun len may not
	 * match this host
	 */
	अगर (fwd->connect_path != शून्य &&
	    म_माप(fwd->connect_path) >= PATH_MAX_SUN)
		जाओ fail_free;
	अगर (fwd->listen_host != शून्य &&
	    म_माप(fwd->listen_host) >= NI_MAXHOST)
		जाओ fail_free;
	अगर (fwd->listen_path != शून्य &&
	    म_माप(fwd->listen_path) >= PATH_MAX_SUN)
		जाओ fail_free;

	वापस (i);

 fail_free:
	मुक्त(fwd->connect_host);
	fwd->connect_host = शून्य;
	मुक्त(fwd->connect_path);
	fwd->connect_path = शून्य;
	मुक्त(fwd->listen_host);
	fwd->listen_host = शून्य;
	मुक्त(fwd->listen_path);
	fwd->listen_path = शून्य;
	वापस (0);
}

पूर्णांक
ssh_valid_hostname(स्थिर अक्षर *s)
{
	माप_प्रकार i;

	अगर (*s == '-')
		वापस 0;
	क्रम (i = 0; s[i] != 0; i++) {
		अगर (म_अक्षर("'`\"$\\;&<>|(){},", s[i]) != शून्य ||
		    है_खाली((u_char)s[i]) || है_नियंत्रण((u_char)s[i]))
			वापस 0;
	}
	वापस 1;
}

पूर्णांक
ssh_valid_ruser(स्थिर अक्षर *s)
{
	माप_प्रकार i;

	अगर (*s == '-')
		वापस 0;
	क्रम (i = 0; s[i] != 0; i++) {
		अगर (है_नियंत्रण((u_char)s[i]))
			वापस 0;
		अगर (म_अक्षर("'`\";&<>|(){}$\\", s[i]) != शून्य)
			वापस 0;
		/* Disallow '-' after whitespace */
		अगर (है_खाली((u_char)s[i]) && s[i + 1] == '-')
			वापस 0;
	}
	वापस 1;
}

पूर्णांक
parse_jump(स्थिर अक्षर *s, Options *o, पूर्णांक strict, पूर्णांक active)
{
	अक्षर *orig = शून्य, *sdup = शून्य, *cp;
	अक्षर *tmp_user = शून्य, *tmp_host = शून्य, *host = शून्य, *user = शून्य;
	पूर्णांक r, ret = -1, tmp_port = -1, port = -1, first = 1;

	अगर (strcasecmp(s, "none") == 0) {
		अगर (active && o->jump_host == शून्य) {
			o->jump_host = xstrdup("none");
			o->jump_port = 0;
		}
		वापस 0;
	}

	orig = xstrdup(s);
	अगर ((cp = म_अक्षर(orig, '#')) != शून्य)
		*cp = '\0';
	rtrim(orig);

	active &= o->proxy_command == शून्य && o->jump_host == शून्य;
	sdup = xstrdup(orig);
	करो {
		/* Work backwards through string */
		अगर ((cp = म_खोजप(sdup, ',')) == शून्य)
			cp = sdup; /* last */
		अन्यथा
			*cp++ = '\0';

		r = parse_ssh_uri(cp, &tmp_user, &tmp_host, &tmp_port);
		अगर (r == -1 || (r == 1 && parse_user_host_port(cp,
		    &tmp_user, &tmp_host, &tmp_port) != 0))
			जाओ out; /* error already logged */
		अगर (strict) {
			अगर (!ssh_valid_hostname(tmp_host)) {
				error_f("invalid hostname \"%s\"", tmp_host);
				जाओ out;
			}
			अगर (tmp_user != शून्य && !ssh_valid_ruser(tmp_user)) {
				error_f("invalid username \"%s\"", tmp_user);
				जाओ out;
			}
		}
		अगर (first) {
			user = tmp_user;
			host = tmp_host;
			port = tmp_port;
			tmp_user = tmp_host = शून्य; /* transferred */
		}
		first = 0; /* only check syntax for subsequent hosts */
		मुक्त(tmp_user);
		मुक्त(tmp_host);
		tmp_user = tmp_host = शून्य;
		tmp_port = -1;
	} जबतक (cp != sdup);

	/* success */
	अगर (active) {
		o->jump_user = user;
		o->jump_host = host;
		o->jump_port = port;
		o->proxy_command = xstrdup("none");
		user = host = शून्य; /* transferred */
		अगर (orig != शून्य && (cp = म_खोजप(orig, ',')) != शून्य) {
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
	वापस ret;
}

पूर्णांक
parse_ssh_uri(स्थिर अक्षर *uri, अक्षर **userp, अक्षर **hostp, पूर्णांक *portp)
{
	अक्षर *user = शून्य, *host = शून्य, *path = शून्य;
	पूर्णांक r, port;

	r = parse_uri("ssh", uri, &user, &host, &port, &path);
	अगर (r == 0 && path != शून्य)
		r = -1;		/* path not allowed */
	अगर (r == 0) {
		अगर (userp != शून्य) {
			*userp = user;
			user = शून्य;
		}
		अगर (hostp != शून्य) {
			*hostp = host;
			host = शून्य;
		}
		अगर (portp != शून्य)
			*portp = port;
	}
	मुक्त(user);
	मुक्त(host);
	मुक्त(path);
	वापस r;
}

/* XXX the following is a near-verbatim copy from servconf.c; refactor */
अटल स्थिर अक्षर *
fmt_multistate_int(पूर्णांक val, स्थिर काष्ठा multistate *m)
{
	u_int i;

	क्रम (i = 0; m[i].कुंजी != शून्य; i++) {
		अगर (m[i].मूल्य == val)
			वापस m[i].कुंजी;
	}
	वापस "UNKNOWN";
}

अटल स्थिर अक्षर *
fmt_intarg(OpCodes code, पूर्णांक val)
{
	अगर (val == -1)
		वापस "unset";
	चयन (code) {
	हाल oAddressFamily:
		वापस fmt_multistate_int(val, multistate_addressfamily);
	हाल oCompression:
		वापस fmt_multistate_int(val, multistate_compression);
	हाल o_Verify_Host_कुंजी_DNS:
	हाल oUpdateHostkeys:
		वापस fmt_multistate_int(val, multistate_yesnoask);
	हाल o_Strict_Host_कुंजी_Checking:
		वापस fmt_multistate_int(val, multistate_strict_hostkey);
	हाल oControlMaster:
		वापस fmt_multistate_int(val, multistate_controlmaster);
	हाल oTunnel:
		वापस fmt_multistate_int(val, multistate_tunnel);
	हाल oRequestTTY:
		वापस fmt_multistate_int(val, multistate_requesttty);
	हाल oSessionType:
		वापस fmt_multistate_int(val, multistate_sessiontype);
	हाल oCanonicalizeHostname:
		वापस fmt_multistate_int(val, multistate_canonicalizehostname);
	हाल o_Add_कुंजियाँ_To_Agent:
		वापस fmt_multistate_int(val, multistate_yesnoaskconfirm);
	हाल oPubkeyAuthentication:
		वापस fmt_multistate_int(val, multistate_pubkey_auth);
	हाल oTCPKeepAlive:
		वापस fmt_multistate_int(val, multistate_keepalives);
	हाल oFingerprintHash:
		वापस ssh_digest_alg_name(val);
	शेष:
		चयन (val) {
		हाल 0:
			वापस "no";
		हाल 1:
			वापस "yes";
		शेष:
			वापस "UNKNOWN";
		}
	}
}

अटल स्थिर अक्षर *
lookup_opcode_name(OpCodes code)
{
	u_int i;

	क्रम (i = 0; keywords[i].name != शून्य; i++)
		अगर (keywords[i].opcode == code)
			वापस(keywords[i].name);
	वापस "UNKNOWN";
}

अटल व्योम
dump_cfg_int(OpCodes code, पूर्णांक val)
{
	अगर (code == oObscureKeystrokeTiming) {
		अगर (val == 0) {
			म_लिखो("%s no\n", lookup_opcode_name(code));
			वापस;
		} अन्यथा अगर (val == SSH_KEYSTROKE_DEFAULT_INTERVAL_MS) {
			म_लिखो("%s yes\n", lookup_opcode_name(code));
			वापस;
		}
		/* FALLTHROUGH */
	}
	म_लिखो("%s %d\n", lookup_opcode_name(code), val);
}

अटल व्योम
dump_cfg_fmtint(OpCodes code, पूर्णांक val)
{
	म_लिखो("%s %s\n", lookup_opcode_name(code), fmt_intarg(code, val));
}

अटल व्योम
dump_cfg_string(OpCodes code, स्थिर अक्षर *val)
{
	अगर (val == शून्य)
		वापस;
	म_लिखो("%s %s\n", lookup_opcode_name(code), val);
}

अटल व्योम
dump_cfg_strarray(OpCodes code, u_int गिनती, अक्षर **vals)
{
	u_int i;

	क्रम (i = 0; i < गिनती; i++)
		म_लिखो("%s %s\n", lookup_opcode_name(code), vals[i]);
}

अटल व्योम
dump_cfg_strarray_oneline(OpCodes code, u_int गिनती, अक्षर **vals)
{
	u_int i;

	म_लिखो("%s", lookup_opcode_name(code));
	अगर (गिनती == 0)
		म_लिखो(" none");
	क्रम (i = 0; i < गिनती; i++)
		म_लिखो(" %s",  vals[i]);
	म_लिखो("\n");
}

अटल व्योम
dump_cfg_forwards(OpCodes code, u_int गिनती, स्थिर काष्ठा Forward *fwds)
{
	स्थिर काष्ठा Forward *fwd;
	u_int i;

	/* oDynamicForward */
	क्रम (i = 0; i < गिनती; i++) {
		fwd = &fwds[i];
		अगर (code == oDynamicForward && fwd->connect_host != शून्य &&
		    म_भेद(fwd->connect_host, "socks") != 0)
			जारी;
		अगर (code == oLocalForward && fwd->connect_host != शून्य &&
		    म_भेद(fwd->connect_host, "socks") == 0)
			जारी;
		म_लिखो("%s", lookup_opcode_name(code));
		अगर (fwd->listen_port == PORT_STREAMLOCAL)
			म_लिखो(" %s", fwd->listen_path);
		अन्यथा अगर (fwd->listen_host == शून्य)
			म_लिखो(" %d", fwd->listen_port);
		अन्यथा {
			म_लिखो(" [%s]:%d",
			    fwd->listen_host, fwd->listen_port);
		}
		अगर (code != oDynamicForward) {
			अगर (fwd->connect_port == PORT_STREAMLOCAL)
				म_लिखो(" %s", fwd->connect_path);
			अन्यथा अगर (fwd->connect_host == शून्य)
				म_लिखो(" %d", fwd->connect_port);
			अन्यथा {
				म_लिखो(" [%s]:%d",
				    fwd->connect_host, fwd->connect_port);
			}
		}
		म_लिखो("\n");
	}
}

व्योम
dump_client_config(Options *o, स्थिर अक्षर *host)
{
	पूर्णांक i, r;
	अक्षर buf[8], *all_कुंजी;

	/*
	 * Expand HostKeyAlgorithms name lists. This isn't handled in
	 * fill_default_options() like the other algorithm lists because
	 * the host key algorithms are by default dynamically chosen based
	 * on the host's keys found in known_hosts.
	 */
	all_कुंजी = sshkey_alg_list(0, 0, 1, ',');
	अगर ((r = kex_assemble_names(&o->hostkeyalgorithms, kex_default_pk_alg(),
	    all_कुंजी)) != 0)
		fatal_fr(r, "expand HostKeyAlgorithms");
	मुक्त(all_कुंजी);

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
#अगर_घोषित GSSAPI
	dump_cfg_fmtint(oGssAuthentication, o->gss_authentication);
	dump_cfg_fmtint(oGssDelegateCreds, o->gss_deleg_creds);
#पूर्ण_अगर /* GSSAPI */
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
	dump_cfg_fmtint(o_Strict_Host_कुंजी_Checking, o->strict_host_कुंजी_checking);
	dump_cfg_fmtint(oTCPKeepAlive, o->tcp_keep_alive);
	dump_cfg_fmtint(oTunnel, o->tun_open);
	dump_cfg_fmtint(o_Verify_Host_कुंजी_DNS, o->verify_host_कुंजी_dns);
	dump_cfg_fmtint(o_Visual_Host_कुंजी, o->visual_host_कुंजी);
	dump_cfg_fmtint(oUpdateHostkeys, o->update_hostkeys);
	dump_cfg_fmtint(oEnableEscapeCommandline, o->enable_escape_commandline);
	dump_cfg_fmtint(oWarnWeakCrypto, o->warn_weak_crypto);

	/* Integer options */
	dump_cfg_int(oCanonicalizeMaxDots, o->canonicalize_max_dots);
	dump_cfg_int(oConnectionAttempts, o->connection_attempts);
	dump_cfg_int(oForwardX11Timeout, o->forward_x11_timeout);
	dump_cfg_int(o_संख्या_Of_Password_Prompts, o->संख्या_of_password_prompts);
	dump_cfg_int(o_Server_Alive_गिनती_Max, o->server_alive_गिनती_max);
	dump_cfg_int(oServerAliveInterval, o->server_alive_interval);
	dump_cfg_int(oRequiredRSASize, o->required_rsa_आकार);
	dump_cfg_int(oObscureKeystrokeTiming,
	    o->obscure_keystroke_timing_interval);

	/* String options */
	dump_cfg_string(oBindAddress, o->bind_address);
	dump_cfg_string(oBindInterface, o->bind_interface);
	dump_cfg_string(oCiphers, o->ciphers);
	dump_cfg_string(oControlPath, o->control_path);
	dump_cfg_string(o_Host_कुंजी_Algorithms, o->hostkeyalgorithms);
	dump_cfg_string(o_Host_कुंजी_Alias, o->host_कुंजी_alias);
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
#अगर_घोषित ENABLE_PKCS11
	dump_cfg_string(oPKCS11Provider, o->pkcs11_provider);
#पूर्ण_अगर
	dump_cfg_string(o_Security_कुंजी_Provider, o->sk_provider);
	dump_cfg_string(oPreferredAuthentications, o->preferred_authentications);
	dump_cfg_string(oPubkeyAcceptedAlgorithms, o->pubkey_accepted_algos);
	dump_cfg_string(oXAuthLocation, o->xauth_location);
	dump_cfg_string(oKnownHostsCommand, o->known_hosts_command);
	dump_cfg_string(oTag, o->tag);
	dump_cfg_string(oVersionAddendum, o->version_addendum);

	/* Forwards */
	dump_cfg_forwards(oDynamicForward, o->अंक_local_forwards, o->local_forwards);
	dump_cfg_forwards(oLocalForward, o->अंक_local_forwards, o->local_forwards);
	dump_cfg_forwards(oRemoteForward, o->अंक_remote_forwards, o->remote_forwards);

	/* String array options */
	dump_cfg_strarray(oIdentityFile, o->अंक_identity_files, o->identity_files);
	dump_cfg_strarray_oneline(oCanonicalDomains, o->अंक_canonical_domains, o->canonical_domains);
	dump_cfg_strarray(oCertificateFile, o->अंक_certificate_files, o->certificate_files);
	dump_cfg_strarray_oneline(oGlobalKnownHostsFile, o->अंक_system_hostfiles, o->system_hostfiles);
	dump_cfg_strarray_oneline(oUserKnownHostsFile, o->अंक_user_hostfiles, o->user_hostfiles);
	dump_cfg_strarray_oneline(o_Revoked_Host_कुंजियाँ, o->अंक_revoked_host_कुंजियाँ, o->revoked_host_कुंजियाँ);
	dump_cfg_strarray(oSendEnv, o->अंक_send_env, o->send_env);
	dump_cfg_strarray(oSetEnv, o->अंक_setenv, o->setenv);
	dump_cfg_strarray_oneline(oLogVerbose,
	    o->अंक_log_verbose, o->log_verbose);
	dump_cfg_strarray_oneline(oChannelTimeout,
	    o->अंक_channel_timeouts, o->channel_timeouts);

	/* Special cases */

	/* PermitRemoteOpen */
	अगर (o->अंक_permitted_remote_opens == 0)
		म_लिखो("%s any\n", lookup_opcode_name(oPermitRemoteOpen));
	अन्यथा
		dump_cfg_strarray_oneline(oPermitRemoteOpen,
		    o->अंक_permitted_remote_opens, o->permitted_remote_opens);

	/* AddKeysToAgent */
	अगर (o->add_कुंजियाँ_to_agent_lifespan <= 0)
		dump_cfg_fmtint(o_Add_कुंजियाँ_To_Agent, o->add_कुंजियाँ_to_agent);
	अन्यथा {
		म_लिखो("addkeystoagent%s %d\n",
		    o->add_कुंजियाँ_to_agent == 3 ? " confirm" : "",
		    o->add_कुंजियाँ_to_agent_lifespan);
	}

	/* oForwardAgent */
	अगर (o->forward_agent_sock_path == शून्य)
		dump_cfg_fmtint(oForwardAgent, o->forward_agent);
	अन्यथा
		dump_cfg_string(oForwardAgent, o->forward_agent_sock_path);

	/* oConnectTimeout */
	अगर (o->connection_timeout == -1)
		म_लिखो("connecttimeout none\n");
	अन्यथा
		dump_cfg_int(oConnectTimeout, o->connection_timeout);

	/* oTunnelDevice */
	म_लिखो("tunneldevice");
	अगर (o->tun_local == SSH_TUNID_ANY)
		म_लिखो(" any");
	अन्यथा
		म_लिखो(" %d", o->tun_local);
	अगर (o->tun_remote == SSH_TUNID_ANY)
		म_लिखो(":any");
	अन्यथा
		म_लिखो(":%d", o->tun_remote);
	म_लिखो("\n");

	/* oCanonicalizePermittedCNAMEs */
	म_लिखो("canonicalizepermittedcnames");
	अगर (o->अंक_permitted_cnames == 0)
		म_लिखो(" none");
	क्रम (i = 0; i < o->अंक_permitted_cnames; i++) {
		म_लिखो(" %s:%s", o->permitted_cnames[i].source_list,
		    o->permitted_cnames[i].target_list);
	}
	म_लिखो("\n");

	/* oControlPersist */
	अगर (o->control_persist == 0 || o->control_persist_timeout == 0)
		dump_cfg_fmtint(oControlPersist, o->control_persist);
	अन्यथा
		dump_cfg_int(oControlPersist, o->control_persist_timeout);

	/* oEscapeChar */
	अगर (o->escape_char == SSH_ESCAPECHAR_NONE)
		म_लिखो("escapechar none\n");
	अन्यथा {
		vis(buf, o->escape_char, VIS_WHITE, 0);
		म_लिखो("escapechar %s\n", buf);
	}

	/* oIPQoS */
	म_लिखो("ipqos %s ", iptos2str(o->ip_qos_interactive));
	म_लिखो("%s\n", iptos2str(o->ip_qos_bulk));

	/* oRekeyLimit */
	म_लिखो("rekeylimit %llu %d\n",
	    (अचिन्हित दीर्घ दीर्घ)o->rekey_limit, o->rekey_interval);

	/* oStreamLocalBindMask */
	म_लिखो("streamlocalbindmask 0%o\n",
	    o->fwd_opts.streamlocal_bind_mask);

	/* oLogFacility */
	म_लिखो("syslogfacility %s\n", log_facility_name(o->log_facility));

	/* oProxyCommand / oProxyJump */
	अगर (o->jump_host == शून्य)
		dump_cfg_string(oProxyCommand, o->proxy_command);
	अन्यथा {
		/* Check for numeric addresses */
		i = म_अक्षर(o->jump_host, ':') != शून्य ||
		    म_अखोज(o->jump_host, "1234567890.") == म_माप(o->jump_host);
		snprintf(buf, माप(buf), "%d", o->jump_port);
		म_लिखो("proxyjump %s%s%s%s%s%s%s%s%s\n",
		    /* optional additional jump spec */
		    o->jump_extra == शून्य ? "" : o->jump_extra,
		    o->jump_extra == शून्य ? "" : ",",
		    /* optional user */
		    o->jump_user == शून्य ? "" : o->jump_user,
		    o->jump_user == शून्य ? "" : "@",
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
