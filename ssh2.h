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

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_ਸੁਨੇਹਾ_NONE					0

/* ranges */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_TRANSPORT_MIN				1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_TRANSPORT_MAX				49
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_USERAUTH_MIN				50
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_USERAUTH_MAX				79
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_USERAUTH_ਪ੍ਰਤੀ_ਵਿਧੀ_MIN		60
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_USERAUTH_ਪ੍ਰਤੀ_ਵਿਧੀ_MAX		SSH2_ਸੁਨੇਹਾ_USERAUTH_MAX
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_CONNECTION_MIN				80
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_CONNECTION_MAX				127
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_RESERVED_MIN				128
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_RESERVED_MAX				191
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_LOCAL_MIN				192
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_LOCAL_MAX				255
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_MIN					1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_MAX					255

/* transport layer: generic */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_DISCONNECT				1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_IGNORE					2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_UNIMPLEMENTED				3
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_DEBUG					4
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_SERVICE_REQUEST			5
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_SERVICE_ACCEPT				6
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_EXT_INFO				7
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_NEWCOMPRESS				8

/* transport layer: alg negotiation */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_KEXINIT				20
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_NEWKEYS				21

/* transport layer: kex specific messages, can be reused */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_KEXDH_INIT				30
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_KEXDH_ਜਵਾਬ				31

/* dh-group-exchange */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_KEX_DH_GEX_REQUEST_OLD			30
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_KEX_DH_GEX_ਸਮੂਹ			31
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_KEX_DH_GEX_INIT			32
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_KEX_DH_GEX_ਜਵਾਬ			33
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_KEX_DH_GEX_REQUEST			34

/* ecdh */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_KEX_ECDH_INIT				30
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_KEX_ECDH_ਜਵਾਬ				31

/* transport layer: OpenSSH extensions */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_PING					192
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_PONG					193

/* user authentication: generic */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_USERAUTH_REQUEST			50
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_USERAUTH_FAILURE			51
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_USERAUTH_SUCCESS			52
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_USERAUTH_BANNER			53

/* user authentication: method specific, can be reused */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_USERAUTH_PK_OK				60
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_USERAUTH_PASSWD_CHANGEREQ		60
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_USERAUTH_INFO_REQUEST			60
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_USERAUTH_INFO_RESPONSE			61

/* connection protocol: generic */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_GLOBAL_REQUEST				80
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_REQUEST_SUCCESS			81
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_REQUEST_FAILURE			82

/* channel related messages */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN				90
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_CONFIRMATION		91
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_CHANNEL_OPEN_FAILURE			92
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_CHANNEL_ਖਿੜਕੀ_ADJUST			93
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_CHANNEL_ਅੰਕੜੇ				94
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_CHANNEL_EXTENDED_ਅੰਕੜੇ			95
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_CHANNEL_EOF				96
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_CHANNEL_CLOSE				97
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_CHANNEL_REQUEST			98
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_CHANNEL_SUCCESS			99
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_ਸੁਨੇਹਾ_CHANNEL_FAILURE			100

/* disconnect reason code */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_DISCONNECT_HOST_NOT_ALLOWED_ਮੰਜ਼ਿਲ_CONNECT	1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_DISCONNECT_PROTOCOL_ERROR			2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_DISCONNECT_ਕੁੰਜੀ_EXCHANGE_FAILED		3
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_DISCONNECT_HOST_AUTHENTICATION_FAILED	4
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_DISCONNECT_RESERVED			4
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_DISCONNECT_MAC_ERROR			5
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_DISCONNECT_COMPRESSION_ERROR		6
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_DISCONNECT_SERVICE_NOT_ਉਪਲਬਧ		7
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_DISCONNECT_PROTOCOL_ਸੰਸਕਰਣ_NOT_SUPPORTED	8
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_DISCONNECT_HOST_ਕੁੰਜੀ_NOT_VERIFIABLE		9
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_DISCONNECT_CONNECTION_ਗੁਆਚਾ			10
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_DISCONNECT_BY_APPLICATION			11
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_DISCONNECT_TOO_MANY_CONNECTIONS		12
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_DISCONNECT_AUTH_CANCELLED_BY_USER		13
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_DISCONNECT_NO_ਹੋਰ_AUTH_METHODS_ਉਪਲਬਧ	14
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_DISCONNECT_ILLEGAL_USER_NAME		15

/* misc */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED		1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_OPEN_CONNECT_FAILED			2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_OPEN_UNKNOWN_CHANNEL_TYPE			3
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_OPEN_RESOURCE_SHORTAGE			4

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_EXTENDED_ਅੰਕੜੇ_STDERR			1

/* Certificate types for OpenSSH certificate keys extension */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_CERT_TYPE_USER				1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH2_CERT_TYPE_HOST				2
