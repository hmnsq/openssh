/* $OpenBSD: ssh2.h,v 1.22 2023/10/10 03:57:45 djm Exp $ */

/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * RFC4251:
 *
 *   Transport layer protocol:
 *
 *     1-19     Transport layer generic (e.g. disconnect, ignore, debug,
 *              etc)
 *     20-29    Algorithm negotiation
 *     30-49    Key exchange method specific (numbers can be reused for
 *              different authentication methods)
 *
 *   User authentication protocol:
 *
 *     50-59    User authentication generic
 *     60-79    User authentication method specific (numbers can be reused
 *              for different authentication methods)
 *
 *   Connection protocol:
 *
 *     80-89    Connection protocol generic
 *     90-127   Channel related messages
 *
 *   Reserved for client protocols:
 *
 *     128-191  Reserved
 *
 *   Local extensions:
 *
 *     192-255  Local extensions
 *     248-255  Local extensions (OpenSSH will never use numbers in this range)
 */

/* special marker for no message */

#ವ್ಯಾಖ್ಯಾನಿಸು SSH_ಸಂದೇಶ_NONE					0

/* ranges */

#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_TRANSPORT_MIN				1
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_TRANSPORT_MAX				49
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_USERAUTH_MIN				50
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_USERAUTH_MAX				79
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_USERAUTH_ಪ್ರತಿ_ವಿಧಾನ_MIN		60
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_USERAUTH_ಪ್ರತಿ_ವಿಧಾನ_MAX		SSH2_ಸಂದೇಶ_USERAUTH_MAX
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_CONNECTION_MIN				80
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_CONNECTION_MAX				127
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_RESERVED_MIN				128
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_RESERVED_MAX				191
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_LOCAL_MIN				192
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_LOCAL_MAX				255
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_MIN					1
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_MAX					255

/* transport layer: generic */

#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_DISCONNECT				1
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_IGNORE					2
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_UNIMPLEMENTED				3
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_DEBUG					4
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_SERVICE_REQUEST			5
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_SERVICE_ACCEPT				6
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_EXT_INFO				7
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_NEWCOMPRESS				8

/* transport layer: alg negotiation */

#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_KEXINIT				20
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_NEWKEYS				21

/* transport layer: kex specific messages, can be reused */

#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_KEXDH_INIT				30
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_KEXDH_ಉತ್ತರ				31

/* dh-group-exchange */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_KEX_DH_GEX_REQUEST_OLD			30
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_KEX_DH_GEX_ಗುಂಪು			31
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_KEX_DH_GEX_INIT			32
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_KEX_DH_GEX_ಉತ್ತರ			33
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_KEX_DH_GEX_REQUEST			34

/* ecdh */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_KEX_ECDH_INIT				30
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_KEX_ECDH_ಉತ್ತರ				31

/* transport layer: OpenSSH extensions */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_PING					192
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_PONG					193

/* user authentication: generic */

#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_USERAUTH_REQUEST			50
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_USERAUTH_FAILURE			51
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_USERAUTH_SUCCESS			52
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_USERAUTH_BANNER			53

/* user authentication: method specific, can be reused */

#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_USERAUTH_PK_OK				60
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_USERAUTH_PASSWD_CHANGEREQ		60
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_USERAUTH_INFO_REQUEST			60
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_USERAUTH_INFO_RESPONSE			61

/* connection protocol: generic */

#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_GLOBAL_REQUEST				80
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_REQUEST_SUCCESS			81
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_REQUEST_FAILURE			82

/* channel related messages */

#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_CHANNEL_OPEN				90
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_CHANNEL_OPEN_CONFIRMATION		91
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_CHANNEL_OPEN_FAILURE			92
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_CHANNEL_ಕಿಟಕಿ_ADJUST			93
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_CHANNEL_ದತ್ತಾಂಶ				94
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_CHANNEL_EXTENDED_ದತ್ತಾಂಶ			95
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_CHANNEL_EOF				96
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_CHANNEL_CLOSE				97
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_CHANNEL_REQUEST			98
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_CHANNEL_SUCCESS			99
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_ಸಂದೇಶ_CHANNEL_FAILURE			100

/* disconnect reason code */

#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_DISCONNECT_HOST_NOT_ALLOWED_ಗಮ್ಯ_CONNECT	1
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_DISCONNECT_PROTOCOL_ERROR			2
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_DISCONNECT_ಕೀಲಿ_EXCHANGE_FAILED		3
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED	4
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_DISCONNECT_RESERVED			4
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_DISCONNECT_MAC_ERROR			5
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_DISCONNECT_COMPRESSION_ERROR		6
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_DISCONNECT_SERVICE_NOT_ಲಭ್ಯ		7
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_DISCONNECT_PROTOCOL_ಆವೃತ್ತಿ_NOT_SUPPORTED	8
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_DISCONNECT_HOST_ಕೀಲಿ_NOT_VERIFIABLE		9
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_DISCONNECT_CONNECTION_ಕಳೆದುಹೋದ			10
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_DISCONNECT_BY_APPLICATION			11
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_DISCONNECT_TOO_MANY_CONNECTIONS		12
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER		13
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_DISCONNECT_NO_ಇನ್ನಷ್ಟು_AUTH_METHODS_ಲಭ್ಯ	14
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_DISCONNECT_ILLEGAL_USER_NAME		15

/* misc */

#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED		1
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_OPEN_CONNECT_FAILED			2
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_OPEN_UNKNOWN_CHANNEL_TYPE			3
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_OPEN_RESOURCE_SHORTAGE			4

#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_EXTENDED_ದತ್ತಾಂಶ_STDERR			1

/* Certificate types for OpenSSH certificate keys extension */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_CERT_TYPE_USER				1
#ವ್ಯಾಖ್ಯಾನಿಸು SSH2_CERT_TYPE_HOST				2
