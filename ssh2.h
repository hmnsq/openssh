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

#घोषणा SSH_संदेश_NONE					0

/* ranges */

#घोषणा SSH2_संदेश_TRANSPORT_MIN				1
#घोषणा SSH2_संदेश_TRANSPORT_MAX				49
#घोषणा SSH2_संदेश_USERAUTH_MIN				50
#घोषणा SSH2_संदेश_USERAUTH_MAX				79
#घोषणा SSH2_संदेश_USERAUTH_PER_METHOD_MIN		60
#घोषणा SSH2_संदेश_USERAUTH_PER_METHOD_MAX		SSH2_संदेश_USERAUTH_MAX
#घोषणा SSH2_संदेश_CONNECTION_MIN				80
#घोषणा SSH2_संदेश_CONNECTION_MAX				127
#घोषणा SSH2_संदेश_RESERVED_MIN				128
#घोषणा SSH2_संदेश_RESERVED_MAX				191
#घोषणा SSH2_संदेश_LOCAL_MIN				192
#घोषणा SSH2_संदेश_LOCAL_MAX				255
#घोषणा SSH2_संदेश_MIN					1
#घोषणा SSH2_संदेश_MAX					255

/* transport layer: generic */

#घोषणा SSH2_संदेश_DISCONNECT				1
#घोषणा SSH2_संदेश_IGNORE					2
#घोषणा SSH2_संदेश_UNIMPLEMENTED				3
#घोषणा SSH2_संदेश_DEBUG					4
#घोषणा SSH2_संदेश_SERVICE_REQUEST			5
#घोषणा SSH2_संदेश_SERVICE_ACCEPT				6
#घोषणा SSH2_संदेश_EXT_INFO				7
#घोषणा SSH2_संदेश_NEWCOMPRESS				8

/* transport layer: alg negotiation */

#घोषणा SSH2_संदेश_KEXINIT				20
#घोषणा SSH2_संदेश_NEWKEYS				21

/* transport layer: kex specific messages, can be reused */

#घोषणा SSH2_संदेश_KEXDH_INIT				30
#घोषणा SSH2_संदेश_KEXDH_REPLY				31

/* dh-group-exchange */
#घोषणा SSH2_संदेश_KEX_DH_GEX_REQUEST_OLD			30
#घोषणा SSH2_संदेश_KEX_DH_GEX_GROUP			31
#घोषणा SSH2_संदेश_KEX_DH_GEX_INIT			32
#घोषणा SSH2_संदेश_KEX_DH_GEX_REPLY			33
#घोषणा SSH2_संदेश_KEX_DH_GEX_REQUEST			34

/* ecdh */
#घोषणा SSH2_संदेश_KEX_ECDH_INIT				30
#घोषणा SSH2_संदेश_KEX_ECDH_REPLY				31

/* transport layer: OpenSSH extensions */
#घोषणा SSH2_संदेश_PING					192
#घोषणा SSH2_संदेश_PONG					193

/* user authentication: generic */

#घोषणा SSH2_संदेश_USERAUTH_REQUEST			50
#घोषणा SSH2_संदेश_USERAUTH_FAILURE			51
#घोषणा SSH2_संदेश_USERAUTH_SUCCESS			52
#घोषणा SSH2_संदेश_USERAUTH_BANNER			53

/* user authentication: method specific, can be reused */

#घोषणा SSH2_संदेश_USERAUTH_PK_OK				60
#घोषणा SSH2_संदेश_USERAUTH_PASSWD_CHANGEREQ		60
#घोषणा SSH2_संदेश_USERAUTH_INFO_REQUEST			60
#घोषणा SSH2_संदेश_USERAUTH_INFO_RESPONSE			61

/* connection protocol: generic */

#घोषणा SSH2_संदेश_GLOBAL_REQUEST				80
#घोषणा SSH2_संदेश_REQUEST_SUCCESS			81
#घोषणा SSH2_संदेश_REQUEST_FAILURE			82

/* channel related messages */

#घोषणा SSH2_संदेश_CHANNEL_OPEN				90
#घोषणा SSH2_संदेश_CHANNEL_OPEN_CONFIRMATION		91
#घोषणा SSH2_संदेश_CHANNEL_OPEN_FAILURE			92
#घोषणा SSH2_संदेश_CHANNEL_WINDOW_ADJUST			93
#घोषणा SSH2_संदेश_CHANNEL_तथ्य				94
#घोषणा SSH2_संदेश_CHANNEL_EXTENDED_तथ्य			95
#घोषणा SSH2_संदेश_CHANNEL_EOF				96
#घोषणा SSH2_संदेश_CHANNEL_CLOSE				97
#घोषणा SSH2_संदेश_CHANNEL_REQUEST			98
#घोषणा SSH2_संदेश_CHANNEL_SUCCESS			99
#घोषणा SSH2_संदेश_CHANNEL_FAILURE			100

/* disconnect reason code */

#घोषणा SSH2_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT	1
#घोषणा SSH2_DISCONNECT_PROTOCOL_ERROR			2
#घोषणा SSH2_DISCONNECT_कुंजी_EXCHANGE_FAILED		3
#घोषणा SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED	4
#घोषणा SSH2_DISCONNECT_RESERVED			4
#घोषणा SSH2_DISCONNECT_MAC_ERROR			5
#घोषणा SSH2_DISCONNECT_COMPRESSION_ERROR		6
#घोषणा SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE		7
#घोषणा SSH2_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED	8
#घोषणा SSH2_DISCONNECT_HOST_कुंजी_NOT_VERIFIABLE		9
#घोषणा SSH2_DISCONNECT_CONNECTION_LOST			10
#घोषणा SSH2_DISCONNECT_BY_APPLICATION			11
#घोषणा SSH2_DISCONNECT_TOO_MANY_CONNECTIONS		12
#घोषणा SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER		13
#घोषणा SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE	14
#घोषणा SSH2_DISCONNECT_ILLEGAL_USER_NAME		15

/* misc */

#घोषणा SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED		1
#घोषणा SSH2_OPEN_CONNECT_FAILED			2
#घोषणा SSH2_OPEN_UNKNOWN_CHANNEL_TYPE			3
#घोषणा SSH2_OPEN_RESOURCE_SHORTAGE			4

#घोषणा SSH2_EXTENDED_तथ्य_STDERR			1

/* Certificate types for OpenSSH certificate keys extension */
#घोषणा SSH2_CERT_TYPE_USER				1
#घोषणा SSH2_CERT_TYPE_HOST				2
