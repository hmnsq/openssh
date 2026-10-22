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
#నిర్వచించు SSH_DEFAULT_పోర్టు	22

/*
 * Maximum number of certificate files that can be specified
 * in configuration files or on the command line.
 */
#నిర్వచించు SSH_MAX_CERTIFICATE_FILES	100

/*
 * Maximum number of RSA authentication identity files that can be specified
 * in configuration files or on the command line.
 */
#నిర్వచించు SSH_MAX_తటస్థం_FILES		100

/*
 * Major protocol version.  Different version indicates major incompatibility
 * that prevents communication.
 *
 * Minor protocol version.  Different version indicates minor incompatibility
 * that does not prevent interoperation.
 *
 * We support only SSH2
 */
#నిర్వచించు PROTOCOL_MAJOR_2	2
#నిర్వచించు PROTOCOL_MINOR_2	0

/*
 * Name for the service.  The port named by this service overrides the
 * default port if present.
 */
#నిర్వచించు SSH_SERVICE_NAME	"ssh"

/*
 * Name of the environment variable containing the process ID of the
 * authentication agent.
 */
#నిర్వచించు SSH_AGENTPID_ENV_NAME	"SSH_AGENT_PID"

/*
 * Name of the environment variable containing the pathname of the
 * authentication socket.
 */
#నిర్వచించు SSH_AUTHSOCKET_ENV_NAME "SSH_AUTH_SOCK"

/*
 * Environment variable for overwriting the default location of askpass
 */
#నిర్వచించు SSH_ASKPASS_ENV		"SSH_ASKPASS"

/*
 * Environment variable to control whether or not askpass is used.
 */
#నిర్వచించు SSH_ASKPASS_REQUIRE_ENV		"SSH_ASKPASS_REQUIRE"

/*
 * Length of the session key in bytes.  (Specified as 256 bits in the
 * protocol.)
 */
#నిర్వచించు SSH_SESSION_కీలకం_నిడివి		32

/* Used to identify ``EscapeChar none'' */
#నిర్వచించు SSH_ESCAPECHAR_NONE		-2

/*
 * unprivileged user when UsePrivilegeSeparation=yes;
 * sshd will change its privileges to this user and its
 * primary group.
 */
#నిర్వచితం_కాకపోతే SSH_PRIVSEP_USER
#నిర్వచించు SSH_PRIVSEP_USER		"sshd"
#అయితే_ముగింపు

/* Listen backlog for sshd, ssh-agent and forwarding sockets */
#నిర్వచించు SSH_LISTEN_BACKLOG		128

/* Limits for banner exchange */
#నిర్వచించు SSH_MAX_BANNER_LEN		8192
#నిర్వచించు SSH_MAX_PRE_BANNER_పంక్తులు	1024
