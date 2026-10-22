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

#وصف_ڪريو SSH_نياپو_NONE					0

/* ranges */

#وصف_ڪريو SSH2_نياپو_TRANSPORT_MIN				1
#وصف_ڪريو SSH2_نياپو_TRANSPORT_MAX				49
#وصف_ڪريو SSH2_نياپو_USERAUTH_MIN				50
#وصف_ڪريو SSH2_نياپو_USERAUTH_MAX				79
#وصف_ڪريو SSH2_نياپو_USERAUTH_في_طريقو_MIN		60
#وصف_ڪريو SSH2_نياپو_USERAUTH_في_طريقو_MAX		SSH2_نياپو_USERAUTH_MAX
#وصف_ڪريو SSH2_نياپو_CONNECTION_MIN				80
#وصف_ڪريو SSH2_نياپو_CONNECTION_MAX				127
#وصف_ڪريو SSH2_نياپو_RESERVED_MIN				128
#وصف_ڪريو SSH2_نياپو_RESERVED_MAX				191
#وصف_ڪريو SSH2_نياپو_LOCAL_MIN				192
#وصف_ڪريو SSH2_نياپو_LOCAL_MAX				255
#وصف_ڪريو SSH2_نياپو_MIN					1
#وصف_ڪريو SSH2_نياپو_MAX					255

/* transport layer: generic */

#وصف_ڪريو SSH2_نياپو_DISCONNECT				1
#وصف_ڪريو SSH2_نياپو_IGNORE					2
#وصف_ڪريو SSH2_نياپو_UNIMPLEMENTED				3
#وصف_ڪريو SSH2_نياپو_DEBUG					4
#وصف_ڪريو SSH2_نياپو_SERVICE_REQUEST			5
#وصف_ڪريو SSH2_نياپو_SERVICE_ACCEPT				6
#وصف_ڪريو SSH2_نياپو_EXT_INFO				7
#وصف_ڪريو SSH2_نياپو_NEWCOMPRESS				8

/* transport layer: alg negotiation */

#وصف_ڪريو SSH2_نياپو_KEXINIT				20
#وصف_ڪريو SSH2_نياپو_NEWKEYS				21

/* transport layer: kex specific messages, can be reused */

#وصف_ڪريو SSH2_نياپو_KEXDH_INIT				30
#وصف_ڪريو SSH2_نياپو_KEXDH_جواب				31

/* dh-group-exchange */
#وصف_ڪريو SSH2_نياپو_KEX_DH_GEX_REQUEST_OLD			30
#وصف_ڪريو SSH2_نياپو_KEX_DH_GEX_گروهه			31
#وصف_ڪريو SSH2_نياپو_KEX_DH_GEX_INIT			32
#وصف_ڪريو SSH2_نياپو_KEX_DH_GEX_جواب			33
#وصف_ڪريو SSH2_نياپو_KEX_DH_GEX_REQUEST			34

/* ecdh */
#وصف_ڪريو SSH2_نياپو_KEX_ECDH_INIT				30
#وصف_ڪريو SSH2_نياپو_KEX_ECDH_جواب				31

/* transport layer: OpenSSH extensions */
#وصف_ڪريو SSH2_نياپو_PING					192
#وصف_ڪريو SSH2_نياپو_PONG					193

/* user authentication: generic */

#وصف_ڪريو SSH2_نياپو_USERAUTH_REQUEST			50
#وصف_ڪريو SSH2_نياپو_USERAUTH_FAILURE			51
#وصف_ڪريو SSH2_نياپو_USERAUTH_SUCCESS			52
#وصف_ڪريو SSH2_نياپو_USERAUTH_BANNER			53

/* user authentication: method specific, can be reused */

#وصف_ڪريو SSH2_نياپو_USERAUTH_PK_OK				60
#وصف_ڪريو SSH2_نياپو_USERAUTH_PASSWD_CHANGEREQ		60
#وصف_ڪريو SSH2_نياپو_USERAUTH_INFO_REQUEST			60
#وصف_ڪريو SSH2_نياپو_USERAUTH_INFO_RESPONSE			61

/* connection protocol: generic */

#وصف_ڪريو SSH2_نياپو_GLOBAL_REQUEST				80
#وصف_ڪريو SSH2_نياپو_REQUEST_SUCCESS			81
#وصف_ڪريو SSH2_نياپو_REQUEST_FAILURE			82

/* channel related messages */

#وصف_ڪريو SSH2_نياپو_CHANNEL_OPEN				90
#وصف_ڪريو SSH2_نياپو_CHANNEL_OPEN_CONFIRMATION		91
#وصف_ڪريو SSH2_نياپو_CHANNEL_OPEN_FAILURE			92
#وصف_ڪريو SSH2_نياپو_CHANNEL_دري_ADJUST			93
#وصف_ڪريو SSH2_نياپو_CHANNEL_معلومات				94
#وصف_ڪريو SSH2_نياپو_CHANNEL_EXTENDED_معلومات			95
#وصف_ڪريو SSH2_نياپو_CHANNEL_EOF				96
#وصف_ڪريو SSH2_نياپو_CHANNEL_CLOSE				97
#وصف_ڪريو SSH2_نياپو_CHANNEL_REQUEST			98
#وصف_ڪريو SSH2_نياپو_CHANNEL_SUCCESS			99
#وصف_ڪريو SSH2_نياپو_CHANNEL_FAILURE			100

/* disconnect reason code */

#وصف_ڪريو SSH2_DISCONNECT_HOST_NOT_ALLOWED_منزل_CONNECT	1
#وصف_ڪريو SSH2_DISCONNECT_PROTOCOL_ERROR			2
#وصف_ڪريو SSH2_DISCONNECT_ڪنجي_EXCHANGE_FAILED		3
#وصف_ڪريو SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED	4
#وصف_ڪريو SSH2_DISCONNECT_RESERVED			4
#وصف_ڪريو SSH2_DISCONNECT_MAC_ERROR			5
#وصف_ڪريو SSH2_DISCONNECT_COMPRESSION_ERROR		6
#وصف_ڪريو SSH2_DISCONNECT_SERVICE_NOT_موجود		7
#وصف_ڪريو SSH2_DISCONNECT_PROTOCOL_نسخو_NOT_SUPPORTED	8
#وصف_ڪريو SSH2_DISCONNECT_HOST_ڪنجي_NOT_VERIFIABLE		9
#وصف_ڪريو SSH2_DISCONNECT_CONNECTION_گم			10
#وصف_ڪريو SSH2_DISCONNECT_BY_APPLICATION			11
#وصف_ڪريو SSH2_DISCONNECT_TOO_MANY_CONNECTIONS		12
#وصف_ڪريو SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER		13
#وصف_ڪريو SSH2_DISCONNECT_NO_وڌيڪ_AUTH_METHODS_موجود	14
#وصف_ڪريو SSH2_DISCONNECT_ILLEGAL_USER_NAME		15

/* misc */

#وصف_ڪريو SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED		1
#وصف_ڪريو SSH2_OPEN_CONNECT_FAILED			2
#وصف_ڪريو SSH2_OPEN_UNKNOWN_CHANNEL_TYPE			3
#وصف_ڪريو SSH2_OPEN_RESOURCE_SHORTAGE			4

#وصف_ڪريو SSH2_EXTENDED_معلومات_STDERR			1

/* Certificate types for OpenSSH certificate keys extension */
#وصف_ڪريو SSH2_CERT_TYPE_USER				1
#وصف_ڪريو SSH2_CERT_TYPE_HOST				2
