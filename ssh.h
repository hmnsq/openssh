/* $OpenBSD: ssh.h,v 1.91 2024/09/25 23:01:39 jsg Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

/* Default port number. */
#تعریف_کن SSH_DEFAULT_پورت	22

/*
 * Maximum number of certificate files that can be specified
 * in configuration files or on the command line.
 */
#تعریف_کن SSH_MAX_CERTIFICATE_FILES	100

/*
 * Maximum number of RSA authentication identity files that can be specified
 * in configuration files or on the command line.
 */
#تعریف_کن SSH_MAX_عنصر_خنثی_FILES		100

/*
 * Major protocol version.  Different version indicates major incompatibility
 * that prevents communication.
 *
 * Minor protocol version.  Different version indicates minor incompatibility
 * that does not prevent interoperation.
 *
 * We support only SSH2
 */
#تعریف_کن PROTOCOL_MAJOR_2	2
#تعریف_کن PROTOCOL_MINOR_2	0

/*
 * Name for the service.  The port named by this service overrides the
 * default port if present.
 */
#تعریف_کن SSH_SERVICE_NAME	"ssh"

/*
 * Name of the environment variable containing the process ID of the
 * authentication agent.
 */
#تعریف_کن SSH_AGENTPID_ENV_NAME	"SSH_AGENT_PID"

/*
 * Name of the environment variable containing the pathname of the
 * authentication socket.
 */
#تعریف_کن SSH_AUTHSOCKET_ENV_NAME "SSH_AUTH_SOCK"

/*
 * Environment variable for overwriting the default location of askpass
 */
#تعریف_کن SSH_ASKPASS_ENV		"SSH_ASKPASS"

/*
 * Environment variable to control whether or not askpass is used.
 */
#تعریف_کن SSH_ASKPASS_REQUIRE_ENV		"SSH_ASKPASS_REQUIRE"

/*
 * Length of the session key in bytes.  (Specified as 256 bits in the
 * protocol.)
 */
#تعریف_کن SSH_SESSION_کلید_درازی		32

/* Used to identify ``EscapeChar none'' */
#تعریف_کن SSH_ESCAPECHAR_NONE		-2

/*
 * unprivileged user when UsePrivilegeSeparation=yes;
 * sshd will change its privileges to this user and its
 * primary group.
 */
#اگر_تعریف_نشده SSH_PRIVSEP_USER
#تعریف_کن SSH_PRIVSEP_USER		"sshd"
#پایان_اگر

/* Listen backlog for sshd, ssh-agent and forwarding sockets */
#تعریف_کن SSH_LISTEN_BACKLOG		128

/* Limits for banner exchange */
#تعریف_کن SSH_MAX_BANNER_LEN		8192
#تعریف_کن SSH_MAX_PRE_BANNER_سطرها	1024
