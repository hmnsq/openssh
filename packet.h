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

#ಅನ್ತರ್ಭಾವ <sys/queue.h>

#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <termios.h>

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/ecdsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಅನ್ಯಥಾ /* OPENSSL */
#define BIGNUM		ಶೂನ್ಯ
#define EC_GROUP	ಶೂನ್ಯ
#define EC_POINT	ಶೂನ್ಯ
#define EVP_PKEY	ಶೂನ್ಯ
#endif /* WITH_OPENSSL */

ಸಂರಚನಾ kex;
ಸಂರಚನಾ sshkey;
ಸಂರಚನಾ sshbuf;
ಸಂರಚನಾ session_state;	/* private session data */

#ಅನ್ತರ್ಭಾವ "dispatch.h"	/* typedef, DISPATCH_MAX */

ಸಂರಚನಾ ಕೀಲಿ_entry {
	TAILQ_ENTRY(ಕೀಲಿ_entry) next;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ;
};

ಸಂರಚನಾ ssh {
	/* Session state */
	ಸಂರಚನಾ session_state *state;

	/* Key exchange */
	ಸಂರಚನಾ kex *kex;

	/* cached local and remote ip addresses and ports */
	ವರ್ಣ *remote_ipaddr;
	ಪೂರ್ಣಾಙ್ಕ remote_port;
	ವರ್ಣ *local_ipaddr;
	ಪೂರ್ಣಾಙ್ಕ local_port;
	ವರ್ಣ *rdomain_in;

	/* Optional preamble for log messages (e.g. username) */
	ವರ್ಣ *log_preamble;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	ಪೂರ್ಣಾಙ್ಕ dispatch_skip_packets;

	/* datafellows */
	uint32_t compat;
	ವರ್ಣ *remote_version;

	/* Lists for private and public keys */
	TAILQ_HEAD(, ಕೀಲಿ_entry) private_ಕೀಲಿಗಳು;
	TAILQ_HEAD(, ಕೀಲಿ_entry) public_ಕೀಲಿಗಳು;

	/* Client/Server authentication context */
	ಶೂನ್ಯ *authctxt;

	/* Channels context */
	ಸಂರಚನಾ ssh_channels *chanctxt;

	/* APP data */
	ಶೂನ್ಯ *app_data;
};

ಪ್ರಕಾರನಿರ್ದೇಶ ಪೂರ್ಣಾಙ್ಕ (ssh_packet_hook_fn)(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ sshbuf *,
    u_char *, ಶೂನ್ಯ *);

ಸಂರಚನಾ ssh *ssh_alloc_session_state(ಶೂನ್ಯ);
ಸಂರಚನಾ ssh *ssh_packet_set_connection(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ     ssh_packet_set_timeout(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 ssh_packet_stop_discard(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 ssh_packet_connection_af(ಸಂರಚನಾ ssh *);
ಶೂನ್ಯ     ssh_packet_set_nonblocking(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ      ssh_packet_get_connection_in(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ      ssh_packet_get_connection_out(ಸಂರಚನಾ ssh *);
ಶೂನ್ಯ	 ssh_packet_free(ಸಂರಚನಾ ssh *);
ಶೂನ್ಯ     ssh_packet_close(ಸಂರಚನಾ ssh *);
ಶೂನ್ಯ	 ssh_packet_set_ಒಳಹರಿವು_hook(ಸಂರಚನಾ ssh *, ssh_packet_hook_fn *, ಶೂನ್ಯ *);
ಶೂನ್ಯ	 ssh_packet_clear_ಕೀಲಿಗಳು(ಸಂರಚನಾ ssh *);
ಶೂನ್ಯ	 ssh_clear_newkeys(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ);

ಪೂರ್ಣಾಙ್ಕ	 ssh_packet_is_rekeying(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 ssh_packet_check_rekey(ಸಂರಚನಾ ssh *);
ಶೂನ್ಯ     ssh_packet_set_protocol_flags(ಸಂರಚನಾ ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(ಸಂರಚನಾ ssh *);
ಶೂನ್ಯ	 ssh_packet_set_interactive(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ	 ssh_packet_set_qos(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಪೂರ್ಣಾಙ್ಕ);
ಶೂನ್ಯ     ssh_packet_set_server(ಸಂರಚನಾ ssh *);
ಶೂನ್ಯ     ssh_packet_set_authenticated(ಸಂರಚನಾ ssh *);
ಶೂನ್ಯ     ssh_packet_set_mux(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 ssh_packet_get_mux(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 ssh_packet_set_log_preamble(ಸಂರಚನಾ ssh *, ಧ್ರುವ ವರ್ಣ *, ...)
    __attribute__((format(printf, 2, 3)));

ಪೂರ್ಣಾಙ್ಕ	 ssh_packet_log_type(u_char);

ಪೂರ್ಣಾಙ್ಕ	 ssh_packet_send2_wrapped(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 ssh_packet_send2(ಸಂರಚನಾ ssh *);

ಪೂರ್ಣಾಙ್ಕ      ssh_packet_read(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ ssh_packet_read_poll2(ಸಂರಚನಾ ssh *, u_char *, uint32_t *seqnr_p);
ಪೂರ್ಣಾಙ್ಕ	 ssh_packet_process_incoming(ಸಂರಚನಾ ssh *, ಧ್ರುವ ವರ್ಣ *buf, u_int len);
ಪೂರ್ಣಾಙ್ಕ	 ssh_packet_process_read(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ      ssh_packet_read_seqnr(ಸಂರಚನಾ ssh *, u_char *, uint32_t *seqnr_p);
ಪೂರ್ಣಾಙ್ಕ      ssh_packet_read_poll_seqnr(ಸಂರಚನಾ ssh *, u_char *, uint32_t *seqnr_p);

ಶೂನ್ಯ     ssh_packet_disconnect(ಸಂರಚನಾ ssh *, ಧ್ರುವ ವರ್ಣ *fmt, ...)
	__attribute__((format(printf, 2, 3)))
	__attribute__((noreturn));
ಶೂನ್ಯ     ssh_packet_send_debug(ಸಂರಚನಾ ssh *, ಧ್ರುವ ವರ್ಣ *fmt, ...) __attribute__((format(printf, 2, 3)));

ಪೂರ್ಣಾಙ್ಕ	 ssh_set_newkeys(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ mode);
ಶೂನ್ಯ	 ssh_packet_get_bytes(ಸಂರಚನಾ ssh *, uint64_t *, uint64_t *);

ಪೂರ್ಣಾಙ್ಕ	 ssh_packet_write_poll(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 ssh_packet_write_wait(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ      ssh_packet_have_data_to_write(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ      ssh_packet_not_very_much_data_to_write(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 ssh_packet_interactive_data_to_write(ಸಂರಚನಾ ssh *);

ಪೂರ್ಣಾಙ್ಕ	 ssh_packet_connection_is_on_socket(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 ssh_packet_remaining(ಸಂರಚನಾ ssh *);

ಶೂನ್ಯ	 ssh_tty_make_modes(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ, ಸಂರಚನಾ termios *);
ಶೂನ್ಯ	 ssh_tty_parse_modes(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ);

ಶೂನ್ಯ	 ssh_packet_set_alive_timeouts(ಸಂರಚನಾ ssh *, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 ssh_packet_inc_alive_timeouts(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 ssh_packet_set_maxsize(ಸಂರಚನಾ ssh *, u_int);
u_int	 ssh_packet_get_maxsize(ಸಂರಚನಾ ssh *);

ಪೂರ್ಣಾಙ್ಕ	 ssh_packet_get_state(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ sshbuf *);
ಪೂರ್ಣಾಙ್ಕ	 ssh_packet_set_state(ಸಂರಚನಾ ssh *, ಸಂರಚನಾ sshbuf *);

ಧ್ರುವ ವರ್ಣ *ssh_remote_ipaddr(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 ssh_remote_port(ಸಂರಚನಾ ssh *);
ಧ್ರುವ ವರ್ಣ *ssh_local_ipaddr(ಸಂರಚನಾ ssh *);
ಪೂರ್ಣಾಙ್ಕ	 ssh_local_port(ಸಂರಚನಾ ssh *);
ಧ್ರುವ ವರ್ಣ *ssh_packet_rdomain_in(ಸಂರಚನಾ ssh *);
ವರ್ಣ	*ssh_remote_hostname(ಸಂರಚನಾ ssh *);

ಶೂನ್ಯ	 ssh_packet_set_rekey_limits(ಸಂರಚನಾ ssh *, uint64_t, uint32_t);
time_t	 ssh_packet_get_rekey_timeout(ಸಂರಚನಾ ssh *);

ಶೂನ್ಯ	*ssh_packet_get_ಒಳಹರಿವು(ಸಂರಚನಾ ssh *);
ಶೂನ್ಯ	*ssh_packet_get_output(ಸಂರಚನಾ ssh *);

/* new API */
ಪೂರ್ಣಾಙ್ಕ	sshpkt_start(ಸಂರಚನಾ ssh *ssh, u_char type);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_send(ಸಂರಚನಾ ssh *ssh);
ಪೂರ್ಣಾಙ್ಕ     sshpkt_disconnect(ಸಂರಚನಾ ssh *, ಧ್ರುವ ವರ್ಣ *fmt, ...)
	    __attribute__((format(printf, 2, 3)));
ಪೂರ್ಣಾಙ್ಕ	sshpkt_add_padding(ಸಂರಚನಾ ssh *, u_char);
ಶೂನ್ಯ	sshpkt_fatal(ಸಂರಚನಾ ssh *ssh, ಪೂರ್ಣಾಙ್ಕ r, ಧ್ರುವ ವರ್ಣ *fmt, ...)
	    __attribute__((format(printf, 3, 4)))
	    __attribute__((noreturn));
ಪೂರ್ಣಾಙ್ಕ	sshpkt_ಸಂದೇಶ_ignore(ಸಂರಚನಾ ssh *, u_int);

ಪೂರ್ಣಾಙ್ಕ	sshpkt_put(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ಶೂನ್ಯ *v, size_t len);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_putb(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ಸಂರಚನಾ sshbuf *b);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_put_u8(ಸಂರಚನಾ ssh *ssh, u_char val);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_put_u32(ಸಂರಚನಾ ssh *ssh, uint32_t val);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_put_u64(ಸಂರಚನಾ ssh *ssh, uint64_t val);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_put_string(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ಶೂನ್ಯ *v, size_t len);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_put_cstring(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ಶೂನ್ಯ *v);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_put_stringb(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ಸಂರಚನಾ sshbuf *v);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_put_ec(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ EC_POINT *v, ಧ್ರುವ EC_GROUP *g);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_put_ec_pkey(ಸಂರಚನಾ ssh *ssh, EVP_PKEY *pkey);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_put_bignum2(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ BIGNUM *v);

ಪೂರ್ಣಾಙ್ಕ	sshpkt_get(ಸಂರಚನಾ ssh *ssh, ಶೂನ್ಯ *valp, size_t len);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_get_u8(ಸಂರಚನಾ ssh *ssh, u_char *valp);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_get_u32(ಸಂರಚನಾ ssh *ssh, uint32_t *valp);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_get_u64(ಸಂರಚನಾ ssh *ssh, uint64_t *valp);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_get_string(ಸಂರಚನಾ ssh *ssh, u_char **valp, size_t *lenp);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_get_string_direct(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ u_char **valp, size_t *lenp);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_peek_string_direct(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ u_char **valp, size_t *lenp);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_get_cstring(ಸಂರಚನಾ ssh *ssh, ವರ್ಣ **valp, size_t *lenp);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_getb_froms(ಸಂರಚನಾ ssh *ssh, ಸಂರಚನಾ sshbuf **valp);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_get_ec(ಸಂರಚನಾ ssh *ssh, EC_POINT *v, ಧ್ರುವ EC_GROUP *g);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_get_bignum2(ಸಂರಚನಾ ssh *ssh, BIGNUM **valp);
ಪೂರ್ಣಾಙ್ಕ	sshpkt_get_end(ಸಂರಚನಾ ssh *ssh);
ಶೂನ್ಯ	sshpkt_fmt_connection_id(ಸಂರಚನಾ ssh *ssh, ವರ್ಣ *s, size_t l);
ಧ್ರುವ u_char	*sshpkt_ptr(ಸಂರಚನಾ ssh *, size_t *lenp);
ವರ್ಣ	*connection_info_message(ಸಂರಚನಾ ssh *ssh);

#endif				/* PACKET_H */
