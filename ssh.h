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
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_DEFAULT_ಪೋರ್ಟ್	22

/*
 * Maximum number of certificate files that can be specified
 * in configuration files or on the command line.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_MAX_CERTIFICATE_FILES	100

/*
 * Maximum number of RSA authentication identity files that can be specified
 * in configuration files or on the command line.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_MAX_ತಟಸ್ಥ_FILES		100

/*
 * Major protocol version.  Different version indicates major incompatibility
 * that prevents communication.
 *
 * Minor protocol version.  Different version indicates minor incompatibility
 * that does not prevent interoperation.
 *
 * We support only SSH2
 */
#ವ್ಯಾಖ್ಯಾನಿಸು PROTOCOL_MAJOR_2	2
#ವ್ಯಾಖ್ಯಾನಿಸು PROTOCOL_MINOR_2	0

/*
 * Name for the service.  The port named by this service overrides the
 * default port if present.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SERVICE_NAME	"ssh"

/*
 * Name of the environment variable containing the process ID of the
 * authentication agent.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AGENTPID_ENV_NAME	"SSH_AGENT_PID"

/*
 * Name of the environment variable containing the pathname of the
 * authentication socket.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_AUTHSOCKET_ENV_NAME "SSH_AUTH_SOCK"

/*
 * Environment variable for overwriting the default location of askpass
 */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ASKPASS_ENV		"SSH_ASKPASS"

/*
 * Environment variable to control whether or not askpass is used.
 */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ASKPASS_REQUIRE_ENV		"SSH_ASKPASS_REQUIRE"

/*
 * Length of the session key in bytes.  (Specified as 256 bits in the
 * protocol.)
 */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SESSION_ಕೀಲಿ_ಉದ್ದಳತೆ		32

/* Used to identify ``EscapeChar none'' */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ESCAPECHAR_NONE		-2

/*
 * unprivileged user when UsePrivilegeSeparation=yes;
 * sshd will change its privileges to this user and its
 * primary group.
 */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SSH_PRIVSEP_USER
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_PRIVSEP_USER		"sshd"
#ಆದರೆ_ಅಂತ್ಯ

/* Listen backlog for sshd, ssh-agent and forwarding sockets */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_LISTEN_BACKLOG		128

/* Limits for banner exchange */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_MAX_BANNER_LEN		8192
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_MAX_PRE_BANNER_ಸಾಲುಗಳು	1024
