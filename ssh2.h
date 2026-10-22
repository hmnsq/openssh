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

#परिभाषय SSH_सन्देशः_NONE					0

/* ranges */

#परिभाषय SSH2_सन्देशः_TRANSPORT_MIN				1
#परिभाषय SSH2_सन्देशः_TRANSPORT_MAX				49
#परिभाषय SSH2_सन्देशः_USERAUTH_MIN				50
#परिभाषय SSH2_सन्देशः_USERAUTH_MAX				79
#परिभाषय SSH2_सन्देशः_USERAUTH_प्रत्येकम्_विधानम्_MIN		60
#परिभाषय SSH2_सन्देशः_USERAUTH_प्रत्येकम्_विधानम्_MAX		SSH2_सन्देशः_USERAUTH_MAX
#परिभाषय SSH2_सन्देशः_CONNECTION_MIN				80
#परिभाषय SSH2_सन्देशः_CONNECTION_MAX				127
#परिभाषय SSH2_सन्देशः_RESERVED_MIN				128
#परिभाषय SSH2_सन्देशः_RESERVED_MAX				191
#परिभाषय SSH2_सन्देशः_LOCAL_MIN				192
#परिभाषय SSH2_सन्देशः_LOCAL_MAX				255
#परिभाषय SSH2_सन्देशः_MIN					1
#परिभाषय SSH2_सन्देशः_MAX					255

/* transport layer: generic */

#परिभाषय SSH2_सन्देशः_DISCONNECT				1
#परिभाषय SSH2_सन्देशः_IGNORE					2
#परिभाषय SSH2_सन्देशः_UNIMPLEMENTED				3
#परिभाषय SSH2_सन्देशः_DEBUG					4
#परिभाषय SSH2_सन्देशः_SERVICE_REQUEST			5
#परिभाषय SSH2_सन्देशः_SERVICE_ACCEPT				6
#परिभाषय SSH2_सन्देशः_EXT_INFO				7
#परिभाषय SSH2_सन्देशः_NEWCOMPRESS				8

/* transport layer: alg negotiation */

#परिभाषय SSH2_सन्देशः_KEXINIT				20
#परिभाषय SSH2_सन्देशः_NEWKEYS				21

/* transport layer: kex specific messages, can be reused */

#परिभाषय SSH2_सन्देशः_KEXDH_INIT				30
#परिभाषय SSH2_सन्देशः_KEXDH_प्रत्युत्तरम्				31

/* dh-group-exchange */
#परिभाषय SSH2_सन्देशः_KEX_DH_GEX_REQUEST_OLD			30
#परिभाषय SSH2_सन्देशः_KEX_DH_GEX_गणः			31
#परिभाषय SSH2_सन्देशः_KEX_DH_GEX_INIT			32
#परिभाषय SSH2_सन्देशः_KEX_DH_GEX_प्रत्युत्तरम्			33
#परिभाषय SSH2_सन्देशः_KEX_DH_GEX_REQUEST			34

/* ecdh */
#परिभाषय SSH2_सन्देशः_KEX_ECDH_INIT				30
#परिभाषय SSH2_सन्देशः_KEX_ECDH_प्रत्युत्तरम्				31

/* transport layer: OpenSSH extensions */
#परिभाषय SSH2_सन्देशः_PING					192
#परिभाषय SSH2_सन्देशः_PONG					193

/* user authentication: generic */

#परिभाषय SSH2_सन्देशः_USERAUTH_REQUEST			50
#परिभाषय SSH2_सन्देशः_USERAUTH_FAILURE			51
#परिभाषय SSH2_सन्देशः_USERAUTH_SUCCESS			52
#परिभाषय SSH2_सन्देशः_USERAUTH_BANNER			53

/* user authentication: method specific, can be reused */

#परिभाषय SSH2_सन्देशः_USERAUTH_PK_OK				60
#परिभाषय SSH2_सन्देशः_USERAUTH_PASSWD_CHANGEREQ		60
#परिभाषय SSH2_सन्देशः_USERAUTH_INFO_REQUEST			60
#परिभाषय SSH2_सन्देशः_USERAUTH_INFO_RESPONSE			61

/* connection protocol: generic */

#परिभाषय SSH2_सन्देशः_GLOBAL_REQUEST				80
#परिभाषय SSH2_सन्देशः_REQUEST_SUCCESS			81
#परिभाषय SSH2_सन्देशः_REQUEST_FAILURE			82

/* channel related messages */

#परिभाषय SSH2_सन्देशः_CHANNEL_OPEN				90
#परिभाषय SSH2_सन्देशः_CHANNEL_OPEN_CONFIRMATION		91
#परिभाषय SSH2_सन्देशः_CHANNEL_OPEN_FAILURE			92
#परिभाषय SSH2_सन्देशः_CHANNEL_गवाक्षः_ADJUST			93
#परिभाषय SSH2_सन्देशः_CHANNEL_दत्त				94
#परिभाषय SSH2_सन्देशः_CHANNEL_EXTENDED_दत्त			95
#परिभाषय SSH2_सन्देशः_CHANNEL_EOF				96
#परिभाषय SSH2_सन्देशः_CHANNEL_CLOSE				97
#परिभाषय SSH2_सन्देशः_CHANNEL_REQUEST			98
#परिभाषय SSH2_सन्देशः_CHANNEL_SUCCESS			99
#परिभाषय SSH2_सन्देशः_CHANNEL_FAILURE			100

/* disconnect reason code */

#परिभाषय SSH2_DISCONNECT_HOST_NOT_ALLOWED_गन्तव्यम्_CONNECT	1
#परिभाषय SSH2_DISCONNECT_PROTOCOL_ERROR			2
#परिभाषय SSH2_DISCONNECT_कुञ्चिका_EXCHANGE_FAILED		3
#परिभाषय SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED	4
#परिभाषय SSH2_DISCONNECT_RESERVED			4
#परिभाषय SSH2_DISCONNECT_MAC_ERROR			5
#परिभाषय SSH2_DISCONNECT_COMPRESSION_ERROR		6
#परिभाषय SSH2_DISCONNECT_SERVICE_NOT_उपलब्धम्		7
#परिभाषय SSH2_DISCONNECT_PROTOCOL_संस्करणम्_NOT_SUPPORTED	8
#परिभाषय SSH2_DISCONNECT_HOST_कुञ्चिका_NOT_VERIFIABLE		9
#परिभाषय SSH2_DISCONNECT_CONNECTION_नष्टम्			10
#परिभाषय SSH2_DISCONNECT_BY_APPLICATION			11
#परिभाषय SSH2_DISCONNECT_TOO_MANY_CONNECTIONS		12
#परिभाषय SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER		13
#परिभाषय SSH2_DISCONNECT_NO_अधिकम्_AUTH_METHODS_उपलब्धम्	14
#परिभाषय SSH2_DISCONNECT_ILLEGAL_USER_NAME		15

/* misc */

#परिभाषय SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED		1
#परिभाषय SSH2_OPEN_CONNECT_FAILED			2
#परिभाषय SSH2_OPEN_UNKNOWN_CHANNEL_TYPE			3
#परिभाषय SSH2_OPEN_RESOURCE_SHORTAGE			4

#परिभाषय SSH2_EXTENDED_दत्त_STDERR			1

/* Certificate types for OpenSSH certificate keys extension */
#परिभाषय SSH2_CERT_TYPE_USER				1
#परिभाषय SSH2_CERT_TYPE_HOST				2
