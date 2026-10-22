/* $OpenBSD: packet.h,v 1.108 2026/09/22 00:24:47 dtucker Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Interface for the packet protocol functions.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ifndef PACKET_H
#define PACKET_H

#অন্তর্ভাৱ <sys/queue.h>

#অন্তর্ভাৱ <stdint.h>
#অন্তর্ভাৱ <signal.h>
#অন্তর্ভাৱ <termios.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাৱ <openssl/bn.h>
#অন্তর্ভাৱ <openssl/ec.h>
#অন্তর্ভাৱ <openssl/ecdsa.h>
#অন্তর্ভাৱ <openssl/evp.h>
#অন্যথা /* OPENSSL */
#define BIGNUM		শূন্য
#define EC_GROUP	শূন্য
#define EC_POINT	শূন্য
#define EVP_PKEY	শূন্য
#endif /* WITH_OPENSSL */

সংরচনা kex;
সংরচনা sshkey;
সংরচনা sshbuf;
সংরচনা session_state;	/* private session data */

#অন্তর্ভাৱ "dispatch.h"	/* typedef, DISPATCH_MAX */

সংরচনা চাবি_entry {
	TAILQ_ENTRY(চাবি_entry) next;
	সংরচনা sshkey *চাবি;
};

সংরচনা ssh {
	/* Session state */
	সংরচনা session_state *state;

	/* Key exchange */
	সংরচনা kex *kex;

	/* cached local and remote ip addresses and ports */
	ৱর্ণ *remote_ipaddr;
	পূর্ণাঙ্ক remote_port;
	ৱর্ণ *local_ipaddr;
	পূর্ণাঙ্ক local_port;
	ৱর্ণ *rdomain_in;

	/* Optional preamble for log messages (e.g. username) */
	ৱর্ণ *log_preamble;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	পূর্ণাঙ্ক dispatch_skip_packets;

	/* datafellows */
	uint32_t compat;
	ৱর্ণ *remote_version;

	/* Lists for private and public keys */
	TAILQ_HEAD(, চাবি_entry) private_চাবিগুলি;
	TAILQ_HEAD(, চাবি_entry) public_চাবিগুলি;

	/* Client/Server authentication context */
	শূন্য *authctxt;

	/* Channels context */
	সংরচনা ssh_channels *chanctxt;

	/* APP data */
	শূন্য *app_data;
};

প্রকারনির্দেশ পূর্ণাঙ্ক (ssh_packet_hook_fn)(সংরচনা ssh *, সংরচনা sshbuf *,
    u_char *, শূন্য *);

সংরচনা ssh *ssh_alloc_session_state(শূন্য);
সংরচনা ssh *ssh_packet_set_connection(সংরচনা ssh *, পূর্ণাঙ্ক, পূর্ণাঙ্ক);
শূন্য     ssh_packet_set_timeout(সংরচনা ssh *, পূর্ণাঙ্ক, পূর্ণাঙ্ক);
পূর্ণাঙ্ক	 ssh_packet_stop_discard(সংরচনা ssh *);
পূর্ণাঙ্ক	 ssh_packet_connection_af(সংরচনা ssh *);
শূন্য     ssh_packet_set_nonblocking(সংরচনা ssh *);
পূর্ণাঙ্ক      ssh_packet_get_connection_in(সংরচনা ssh *);
পূর্ণাঙ্ক      ssh_packet_get_connection_out(সংরচনা ssh *);
শূন্য	 ssh_packet_free(সংরচনা ssh *);
শূন্য     ssh_packet_close(সংরচনা ssh *);
শূন্য	 ssh_packet_set_প্ৰবেশ_hook(সংরচনা ssh *, ssh_packet_hook_fn *, শূন্য *);
শূন্য	 ssh_packet_clear_চাবিগুলি(সংরচনা ssh *);
শূন্য	 ssh_clear_newkeys(সংরচনা ssh *, পূর্ণাঙ্ক);

পূর্ণাঙ্ক	 ssh_packet_is_rekeying(সংরচনা ssh *);
পূর্ণাঙ্ক	 ssh_packet_check_rekey(সংরচনা ssh *);
শূন্য     ssh_packet_set_protocol_flags(সংরচনা ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(সংরচনা ssh *);
শূন্য	 ssh_packet_set_interactive(সংরচনা ssh *, পূর্ণাঙ্ক);
শূন্য	 ssh_packet_set_qos(সংরচনা ssh *, পূর্ণাঙ্ক, পূর্ণাঙ্ক);
শূন্য     ssh_packet_set_server(সংরচনা ssh *);
শূন্য     ssh_packet_set_authenticated(সংরচনা ssh *);
শূন্য     ssh_packet_set_mux(সংরচনা ssh *);
পূর্ণাঙ্ক	 ssh_packet_get_mux(সংরচনা ssh *);
পূর্ণাঙ্ক	 ssh_packet_set_log_preamble(সংরচনা ssh *, ধ্রুৱ ৱর্ণ *, ...)
    __attribute__((format(printf, 2, 3)));

পূর্ণাঙ্ক	 ssh_packet_log_type(u_char);

পূর্ণাঙ্ক	 ssh_packet_send2_wrapped(সংরচনা ssh *);
পূর্ণাঙ্ক	 ssh_packet_send2(সংরচনা ssh *);

পূর্ণাঙ্ক      ssh_packet_read(সংরচনা ssh *);
পূর্ণাঙ্ক ssh_packet_read_poll2(সংরচনা ssh *, u_char *, uint32_t *seqnr_p);
পূর্ণাঙ্ক	 ssh_packet_process_incoming(সংরচনা ssh *, ধ্রুৱ ৱর্ণ *buf, u_int len);
পূর্ণাঙ্ক	 ssh_packet_process_read(সংরচনা ssh *, পূর্ণাঙ্ক);
পূর্ণাঙ্ক      ssh_packet_read_seqnr(সংরচনা ssh *, u_char *, uint32_t *seqnr_p);
পূর্ণাঙ্ক      ssh_packet_read_poll_seqnr(সংরচনা ssh *, u_char *, uint32_t *seqnr_p);

শূন্য     ssh_packet_disconnect(সংরচনা ssh *, ধ্রুৱ ৱর্ণ *fmt, ...)
	__attribute__((format(printf, 2, 3)))
	__attribute__((noreturn));
শূন্য     ssh_packet_send_debug(সংরচনা ssh *, ধ্রুৱ ৱর্ণ *fmt, ...) __attribute__((format(printf, 2, 3)));

পূর্ণাঙ্ক	 ssh_set_newkeys(সংরচনা ssh *, পূর্ণাঙ্ক mode);
শূন্য	 ssh_packet_get_bytes(সংরচনা ssh *, uint64_t *, uint64_t *);

পূর্ণাঙ্ক	 ssh_packet_write_poll(সংরচনা ssh *);
পূর্ণাঙ্ক	 ssh_packet_write_wait(সংরচনা ssh *);
পূর্ণাঙ্ক      ssh_packet_have_data_to_write(সংরচনা ssh *);
পূর্ণাঙ্ক      ssh_packet_not_very_much_data_to_write(সংরচনা ssh *);
পূর্ণাঙ্ক	 ssh_packet_interactive_data_to_write(সংরচনা ssh *);

পূর্ণাঙ্ক	 ssh_packet_connection_is_on_socket(সংরচনা ssh *);
পূর্ণাঙ্ক	 ssh_packet_remaining(সংরচনা ssh *);

শূন্য	 ssh_tty_make_modes(সংরচনা ssh *, পূর্ণাঙ্ক, সংরচনা termios *);
শূন্য	 ssh_tty_parse_modes(সংরচনা ssh *, পূর্ণাঙ্ক);

শূন্য	 ssh_packet_set_alive_timeouts(সংরচনা ssh *, পূর্ণাঙ্ক);
পূর্ণাঙ্ক	 ssh_packet_inc_alive_timeouts(সংরচনা ssh *);
পূর্ণাঙ্ক	 ssh_packet_set_maxsize(সংরচনা ssh *, u_int);
u_int	 ssh_packet_get_maxsize(সংরচনা ssh *);

পূর্ণাঙ্ক	 ssh_packet_get_state(সংরচনা ssh *, সংরচনা sshbuf *);
পূর্ণাঙ্ক	 ssh_packet_set_state(সংরচনা ssh *, সংরচনা sshbuf *);

ধ্রুৱ ৱর্ণ *ssh_remote_ipaddr(সংরচনা ssh *);
পূর্ণাঙ্ক	 ssh_remote_port(সংরচনা ssh *);
ধ্রুৱ ৱর্ণ *ssh_local_ipaddr(সংরচনা ssh *);
পূর্ণাঙ্ক	 ssh_local_port(সংরচনা ssh *);
ধ্রুৱ ৱর্ণ *ssh_packet_rdomain_in(সংরচনা ssh *);
ৱর্ণ	*ssh_remote_hostname(সংরচনা ssh *);

শূন্য	 ssh_packet_set_rekey_limits(সংরচনা ssh *, uint64_t, uint32_t);
time_t	 ssh_packet_get_rekey_timeout(সংরচনা ssh *);

শূন্য	*ssh_packet_get_প্ৰবেশ(সংরচনা ssh *);
শূন্য	*ssh_packet_get_output(সংরচনা ssh *);

/* new API */
পূর্ণাঙ্ক	sshpkt_start(সংরচনা ssh *ssh, u_char type);
পূর্ণাঙ্ক	sshpkt_send(সংরচনা ssh *ssh);
পূর্ণাঙ্ক     sshpkt_disconnect(সংরচনা ssh *, ধ্রুৱ ৱর্ণ *fmt, ...)
	    __attribute__((format(printf, 2, 3)));
পূর্ণাঙ্ক	sshpkt_add_padding(সংরচনা ssh *, u_char);
শূন্য	sshpkt_fatal(সংরচনা ssh *ssh, পূর্ণাঙ্ক r, ধ্রুৱ ৱর্ণ *fmt, ...)
	    __attribute__((format(printf, 3, 4)))
	    __attribute__((noreturn));
পূর্ণাঙ্ক	sshpkt_বাৰ্তা_ignore(সংরচনা ssh *, u_int);

পূর্ণাঙ্ক	sshpkt_put(সংরচনা ssh *ssh, ধ্রুৱ শূন্য *v, size_t len);
পূর্ণাঙ্ক	sshpkt_putb(সংরচনা ssh *ssh, ধ্রুৱ সংরচনা sshbuf *b);
পূর্ণাঙ্ক	sshpkt_put_u8(সংরচনা ssh *ssh, u_char val);
পূর্ণাঙ্ক	sshpkt_put_u32(সংরচনা ssh *ssh, uint32_t val);
পূর্ণাঙ্ক	sshpkt_put_u64(সংরচনা ssh *ssh, uint64_t val);
পূর্ণাঙ্ক	sshpkt_put_string(সংরচনা ssh *ssh, ধ্রুৱ শূন্য *v, size_t len);
পূর্ণাঙ্ক	sshpkt_put_cstring(সংরচনা ssh *ssh, ধ্রুৱ শূন্য *v);
পূর্ণাঙ্ক	sshpkt_put_stringb(সংরচনা ssh *ssh, ধ্রুৱ সংরচনা sshbuf *v);
পূর্ণাঙ্ক	sshpkt_put_ec(সংরচনা ssh *ssh, ধ্রুৱ EC_POINT *v, ধ্রুৱ EC_GROUP *g);
পূর্ণাঙ্ক	sshpkt_put_ec_pkey(সংরচনা ssh *ssh, EVP_PKEY *pkey);
পূর্ণাঙ্ক	sshpkt_put_bignum2(সংরচনা ssh *ssh, ধ্রুৱ BIGNUM *v);

পূর্ণাঙ্ক	sshpkt_get(সংরচনা ssh *ssh, শূন্য *valp, size_t len);
পূর্ণাঙ্ক	sshpkt_get_u8(সংরচনা ssh *ssh, u_char *valp);
পূর্ণাঙ্ক	sshpkt_get_u32(সংরচনা ssh *ssh, uint32_t *valp);
পূর্ণাঙ্ক	sshpkt_get_u64(সংরচনা ssh *ssh, uint64_t *valp);
পূর্ণাঙ্ক	sshpkt_get_string(সংরচনা ssh *ssh, u_char **valp, size_t *lenp);
পূর্ণাঙ্ক	sshpkt_get_string_direct(সংরচনা ssh *ssh, ধ্রুৱ u_char **valp, size_t *lenp);
পূর্ণাঙ্ক	sshpkt_peek_string_direct(সংরচনা ssh *ssh, ধ্রুৱ u_char **valp, size_t *lenp);
পূর্ণাঙ্ক	sshpkt_get_cstring(সংরচনা ssh *ssh, ৱর্ণ **valp, size_t *lenp);
পূর্ণাঙ্ক	sshpkt_getb_froms(সংরচনা ssh *ssh, সংরচনা sshbuf **valp);
পূর্ণাঙ্ক	sshpkt_get_ec(সংরচনা ssh *ssh, EC_POINT *v, ধ্রুৱ EC_GROUP *g);
পূর্ণাঙ্ক	sshpkt_get_bignum2(সংরচনা ssh *ssh, BIGNUM **valp);
পূর্ণাঙ্ক	sshpkt_get_end(সংরচনা ssh *ssh);
শূন্য	sshpkt_fmt_connection_id(সংরচনা ssh *ssh, ৱর্ণ *s, size_t l);
ধ্রুৱ u_char	*sshpkt_ptr(সংরচনা ssh *, size_t *lenp);
ৱর্ণ	*connection_info_message(সংরচনা ssh *ssh);

#endif				/* PACKET_H */
