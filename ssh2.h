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

#నిర్వచించు SSH_సందేశం_NONE					0

/* ranges */

#నిర్వచించు SSH2_సందేశం_TRANSPORT_MIN				1
#నిర్వచించు SSH2_సందేశం_TRANSPORT_MAX				49
#నిర్వచించు SSH2_సందేశం_USERAUTH_MIN				50
#నిర్వచించు SSH2_సందేశం_USERAUTH_MAX				79
#నిర్వచించు SSH2_సందేశం_USERAUTH_చొప్పున_పద్ధతి_MIN		60
#నిర్వచించు SSH2_సందేశం_USERAUTH_చొప్పున_పద్ధతి_MAX		SSH2_సందేశం_USERAUTH_MAX
#నిర్వచించు SSH2_సందేశం_CONNECTION_MIN				80
#నిర్వచించు SSH2_సందేశం_CONNECTION_MAX				127
#నిర్వచించు SSH2_సందేశం_RESERVED_MIN				128
#నిర్వచించు SSH2_సందేశం_RESERVED_MAX				191
#నిర్వచించు SSH2_సందేశం_LOCAL_MIN				192
#నిర్వచించు SSH2_సందేశం_LOCAL_MAX				255
#నిర్వచించు SSH2_సందేశం_MIN					1
#నిర్వచించు SSH2_సందేశం_MAX					255

/* transport layer: generic */

#నిర్వచించు SSH2_సందేశం_DISCONNECT				1
#నిర్వచించు SSH2_సందేశం_IGNORE					2
#నిర్వచించు SSH2_సందేశం_UNIMPLEMENTED				3
#నిర్వచించు SSH2_సందేశం_DEBUG					4
#నిర్వచించు SSH2_సందేశం_SERVICE_REQUEST			5
#నిర్వచించు SSH2_సందేశం_SERVICE_ACCEPT				6
#నిర్వచించు SSH2_సందేశం_EXT_INFO				7
#నిర్వచించు SSH2_సందేశం_NEWCOMPRESS				8

/* transport layer: alg negotiation */

#నిర్వచించు SSH2_సందేశం_KEXINIT				20
#నిర్వచించు SSH2_సందేశం_NEWKEYS				21

/* transport layer: kex specific messages, can be reused */

#నిర్వచించు SSH2_సందేశం_KEXDH_INIT				30
#నిర్వచించు SSH2_సందేశం_KEXDH_జవాబు				31

/* dh-group-exchange */
#నిర్వచించు SSH2_సందేశం_KEX_DH_GEX_REQUEST_OLD			30
#నిర్వచించు SSH2_సందేశం_KEX_DH_GEX_సమూహం			31
#నిర్వచించు SSH2_సందేశం_KEX_DH_GEX_INIT			32
#నిర్వచించు SSH2_సందేశం_KEX_DH_GEX_జవాబు			33
#నిర్వచించు SSH2_సందేశం_KEX_DH_GEX_REQUEST			34

/* ecdh */
#నిర్వచించు SSH2_సందేశం_KEX_ECDH_INIT				30
#నిర్వచించు SSH2_సందేశం_KEX_ECDH_జవాబు				31

/* transport layer: OpenSSH extensions */
#నిర్వచించు SSH2_సందేశం_PING					192
#నిర్వచించు SSH2_సందేశం_PONG					193

/* user authentication: generic */

#నిర్వచించు SSH2_సందేశం_USERAUTH_REQUEST			50
#నిర్వచించు SSH2_సందేశం_USERAUTH_FAILURE			51
#నిర్వచించు SSH2_సందేశం_USERAUTH_SUCCESS			52
#నిర్వచించు SSH2_సందేశం_USERAUTH_BANNER			53

/* user authentication: method specific, can be reused */

#నిర్వచించు SSH2_సందేశం_USERAUTH_PK_OK				60
#నిర్వచించు SSH2_సందేశం_USERAUTH_PASSWD_CHANGEREQ		60
#నిర్వచించు SSH2_సందేశం_USERAUTH_INFO_REQUEST			60
#నిర్వచించు SSH2_సందేశం_USERAUTH_INFO_RESPONSE			61

/* connection protocol: generic */

#నిర్వచించు SSH2_సందేశం_GLOBAL_REQUEST				80
#నిర్వచించు SSH2_సందేశం_REQUEST_SUCCESS			81
#నిర్వచించు SSH2_సందేశం_REQUEST_FAILURE			82

/* channel related messages */

#నిర్వచించు SSH2_సందేశం_CHANNEL_OPEN				90
#నిర్వచించు SSH2_సందేశం_CHANNEL_OPEN_CONFIRMATION		91
#నిర్వచించు SSH2_సందేశం_CHANNEL_OPEN_FAILURE			92
#నిర్వచించు SSH2_సందేశం_CHANNEL_కిటికీ_ADJUST			93
#నిర్వచించు SSH2_సందేశం_CHANNEL_దత్తాంశం				94
#నిర్వచించు SSH2_సందేశం_CHANNEL_EXTENDED_దత్తాంశం			95
#నిర్వచించు SSH2_సందేశం_CHANNEL_EOF				96
#నిర్వచించు SSH2_సందేశం_CHANNEL_CLOSE				97
#నిర్వచించు SSH2_సందేశం_CHANNEL_REQUEST			98
#నిర్వచించు SSH2_సందేశం_CHANNEL_SUCCESS			99
#నిర్వచించు SSH2_సందేశం_CHANNEL_FAILURE			100

/* disconnect reason code */

#నిర్వచించు SSH2_DISCONNECT_HOST_NOT_ALLOWED_గమ్యం_CONNECT	1
#నిర్వచించు SSH2_DISCONNECT_PROTOCOL_ERROR			2
#నిర్వచించు SSH2_DISCONNECT_కీలకం_EXCHANGE_FAILED		3
#నిర్వచించు SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED	4
#నిర్వచించు SSH2_DISCONNECT_RESERVED			4
#నిర్వచించు SSH2_DISCONNECT_MAC_ERROR			5
#నిర్వచించు SSH2_DISCONNECT_COMPRESSION_ERROR		6
#నిర్వచించు SSH2_DISCONNECT_SERVICE_NOT_అందుబాటు		7
#నిర్వచించు SSH2_DISCONNECT_PROTOCOL_సంస్కరణ_NOT_SUPPORTED	8
#నిర్వచించు SSH2_DISCONNECT_HOST_కీలకం_NOT_VERIFIABLE		9
#నిర్వచించు SSH2_DISCONNECT_CONNECTION_కోల్పోయిన			10
#నిర్వచించు SSH2_DISCONNECT_BY_APPLICATION			11
#నిర్వచించు SSH2_DISCONNECT_TOO_MANY_CONNECTIONS		12
#నిర్వచించు SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER		13
#నిర్వచించు SSH2_DISCONNECT_NO_మరిన్ని_AUTH_METHODS_అందుబాటు	14
#నిర్వచించు SSH2_DISCONNECT_ILLEGAL_USER_NAME		15

/* misc */

#నిర్వచించు SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED		1
#నిర్వచించు SSH2_OPEN_CONNECT_FAILED			2
#నిర్వచించు SSH2_OPEN_UNKNOWN_CHANNEL_TYPE			3
#నిర్వచించు SSH2_OPEN_RESOURCE_SHORTAGE			4

#నిర్వచించు SSH2_EXTENDED_దత్తాంశం_STDERR			1

/* Certificate types for OpenSSH certificate keys extension */
#నిర్వచించు SSH2_CERT_TYPE_USER				1
#నిర్వచించు SSH2_CERT_TYPE_HOST				2
