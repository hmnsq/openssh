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

#تعریف_کرو SSH_پیغام_NONE					0

/* ranges */

#تعریف_کرو SSH2_پیغام_TRANSPORT_MIN				1
#تعریف_کرو SSH2_پیغام_TRANSPORT_MAX				49
#تعریف_کرو SSH2_پیغام_USERAUTH_MIN				50
#تعریف_کرو SSH2_پیغام_USERAUTH_MAX				79
#تعریف_کرو SSH2_پیغام_USERAUTH_فی_طریقہ_MIN		60
#تعریف_کرو SSH2_پیغام_USERAUTH_فی_طریقہ_MAX		SSH2_پیغام_USERAUTH_MAX
#تعریف_کرو SSH2_پیغام_CONNECTION_MIN				80
#تعریف_کرو SSH2_پیغام_CONNECTION_MAX				127
#تعریف_کرو SSH2_پیغام_RESERVED_MIN				128
#تعریف_کرو SSH2_پیغام_RESERVED_MAX				191
#تعریف_کرو SSH2_پیغام_LOCAL_MIN				192
#تعریف_کرو SSH2_پیغام_LOCAL_MAX				255
#تعریف_کرو SSH2_پیغام_MIN					1
#تعریف_کرو SSH2_پیغام_MAX					255

/* transport layer: generic */

#تعریف_کرو SSH2_پیغام_DISCONNECT				1
#تعریف_کرو SSH2_پیغام_IGNORE					2
#تعریف_کرو SSH2_پیغام_UNIMPLEMENTED				3
#تعریف_کرو SSH2_پیغام_DEBUG					4
#تعریف_کرو SSH2_پیغام_SERVICE_REQUEST			5
#تعریف_کرو SSH2_پیغام_SERVICE_ACCEPT				6
#تعریف_کرو SSH2_پیغام_EXT_INFO				7
#تعریف_کرو SSH2_پیغام_NEWCOMPRESS				8

/* transport layer: alg negotiation */

#تعریف_کرو SSH2_پیغام_KEXINIT				20
#تعریف_کرو SSH2_پیغام_NEWKEYS				21

/* transport layer: kex specific messages, can be reused */

#تعریف_کرو SSH2_پیغام_KEXDH_INIT				30
#تعریف_کرو SSH2_پیغام_KEXDH_جواب				31

/* dh-group-exchange */
#تعریف_کرو SSH2_پیغام_KEX_DH_GEX_REQUEST_OLD			30
#تعریف_کرو SSH2_پیغام_KEX_DH_GEX_گروہ			31
#تعریف_کرو SSH2_پیغام_KEX_DH_GEX_INIT			32
#تعریف_کرو SSH2_پیغام_KEX_DH_GEX_جواب			33
#تعریف_کرو SSH2_پیغام_KEX_DH_GEX_REQUEST			34

/* ecdh */
#تعریف_کرو SSH2_پیغام_KEX_ECDH_INIT				30
#تعریف_کرو SSH2_پیغام_KEX_ECDH_جواب				31

/* transport layer: OpenSSH extensions */
#تعریف_کرو SSH2_پیغام_PING					192
#تعریف_کرو SSH2_پیغام_PONG					193

/* user authentication: generic */

#تعریف_کرو SSH2_پیغام_USERAUTH_REQUEST			50
#تعریف_کرو SSH2_پیغام_USERAUTH_FAILURE			51
#تعریف_کرو SSH2_پیغام_USERAUTH_SUCCESS			52
#تعریف_کرو SSH2_پیغام_USERAUTH_BANNER			53

/* user authentication: method specific, can be reused */

#تعریف_کرو SSH2_پیغام_USERAUTH_PK_OK				60
#تعریف_کرو SSH2_پیغام_USERAUTH_PASSWD_CHANGEREQ		60
#تعریف_کرو SSH2_پیغام_USERAUTH_INFO_REQUEST			60
#تعریف_کرو SSH2_پیغام_USERAUTH_INFO_RESPONSE			61

/* connection protocol: generic */

#تعریف_کرو SSH2_پیغام_GLOBAL_REQUEST				80
#تعریف_کرو SSH2_پیغام_REQUEST_SUCCESS			81
#تعریف_کرو SSH2_پیغام_REQUEST_FAILURE			82

/* channel related messages */

#تعریف_کرو SSH2_پیغام_CHANNEL_OPEN				90
#تعریف_کرو SSH2_پیغام_CHANNEL_OPEN_CONFIRMATION		91
#تعریف_کرو SSH2_پیغام_CHANNEL_OPEN_FAILURE			92
#تعریف_کرو SSH2_پیغام_CHANNEL_کھڑکی_ADJUST			93
#تعریف_کرو SSH2_پیغام_CHANNEL_انکڑے				94
#تعریف_کرو SSH2_پیغام_CHANNEL_EXTENDED_انکڑے			95
#تعریف_کرو SSH2_پیغام_CHANNEL_EOF				96
#تعریف_کرو SSH2_پیغام_CHANNEL_CLOSE				97
#تعریف_کرو SSH2_پیغام_CHANNEL_REQUEST			98
#تعریف_کرو SSH2_پیغام_CHANNEL_SUCCESS			99
#تعریف_کرو SSH2_پیغام_CHANNEL_FAILURE			100

/* disconnect reason code */

#تعریف_کرو SSH2_DISCONNECT_HOST_NOT_ALLOWED_منزل_CONNECT	1
#تعریف_کرو SSH2_DISCONNECT_PROTOCOL_ERROR			2
#تعریف_کرو SSH2_DISCONNECT_کلید_EXCHANGE_FAILED		3
#تعریف_کرو SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED	4
#تعریف_کرو SSH2_DISCONNECT_RESERVED			4
#تعریف_کرو SSH2_DISCONNECT_MAC_ERROR			5
#تعریف_کرو SSH2_DISCONNECT_COMPRESSION_ERROR		6
#تعریف_کرو SSH2_DISCONNECT_SERVICE_NOT_دستیاب		7
#تعریف_کرو SSH2_DISCONNECT_PROTOCOL_نسخہ_NOT_SUPPORTED	8
#تعریف_کرو SSH2_DISCONNECT_HOST_کلید_NOT_VERIFIABLE		9
#تعریف_کرو SSH2_DISCONNECT_CONNECTION_گواچا			10
#تعریف_کرو SSH2_DISCONNECT_BY_APPLICATION			11
#تعریف_کرو SSH2_DISCONNECT_TOO_MANY_CONNECTIONS		12
#تعریف_کرو SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER		13
#تعریف_کرو SSH2_DISCONNECT_NO_ہور_AUTH_METHODS_دستیاب	14
#تعریف_کرو SSH2_DISCONNECT_ILLEGAL_USER_NAME		15

/* misc */

#تعریف_کرو SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED		1
#تعریف_کرو SSH2_OPEN_CONNECT_FAILED			2
#تعریف_کرو SSH2_OPEN_UNKNOWN_CHANNEL_TYPE			3
#تعریف_کرو SSH2_OPEN_RESOURCE_SHORTAGE			4

#تعریف_کرو SSH2_EXTENDED_انکڑے_STDERR			1

/* Certificate types for OpenSSH certificate keys extension */
#تعریف_کرو SSH2_CERT_TYPE_USER				1
#تعریف_کرو SSH2_CERT_TYPE_HOST				2
