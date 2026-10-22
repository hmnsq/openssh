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

#ଅନ୍ତର୍ଭାଵ <sys/queue.h>

#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <termios.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ec.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ecdsa.h>
#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>
#ଅନ୍ୟଥା /* OPENSSL */
#define BIGNUM		ଶୂନ୍ୟ
#define EC_GROUP	ଶୂନ୍ୟ
#define EC_POINT	ଶୂନ୍ୟ
#define EVP_PKEY	ଶୂନ୍ୟ
#endif /* WITH_OPENSSL */

ସଂରଚନା kex;
ସଂରଚନା sshkey;
ସଂରଚନା sshbuf;
ସଂରଚନା session_state;	/* private session data */

#ଅନ୍ତର୍ଭାଵ "dispatch.h"	/* typedef, DISPATCH_MAX */

ସଂରଚନା ଚାବି_entry {
	TAILQ_ENTRY(ଚାବି_entry) next;
	ସଂରଚନା sshkey *ଚାବି;
};

ସଂରଚନା ssh {
	/* Session state */
	ସଂରଚନା session_state *state;

	/* Key exchange */
	ସଂରଚନା kex *kex;

	/* cached local and remote ip addresses and ports */
	ଅକ୍ଷର *remote_ipaddr;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା remote_port;
	ଅକ୍ଷର *local_ipaddr;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା local_port;
	ଅକ୍ଷର *rdomain_in;

	/* Optional preamble for log messages (e.g. username) */
	ଅକ୍ଷର *log_preamble;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା dispatch_skip_packets;

	/* datafellows */
	uint32_t compat;
	ଅକ୍ଷର *remote_version;

	/* Lists for private and public keys */
	TAILQ_HEAD(, ଚାବି_entry) private_ଚାବିଗୁଡ଼ିକ;
	TAILQ_HEAD(, ଚାବି_entry) public_ଚାବିଗୁଡ଼ିକ;

	/* Client/Server authentication context */
	ଶୂନ୍ୟ *authctxt;

	/* Channels context */
	ସଂରଚନା ssh_channels *chanctxt;

	/* APP data */
	ଶୂନ୍ୟ *app_data;
};

ପ୍ରକାରବ୍ୟାଖ୍ୟା ପୂର୍ଣ୍ଣସଂଖ୍ୟା (ssh_packet_hook_fn)(ସଂରଚନା ssh *, ସଂରଚନା sshbuf *,
    u_char *, ଶୂନ୍ୟ *);

ସଂରଚନା ssh *ssh_alloc_session_state(ଶୂନ୍ୟ);
ସଂରଚନା ssh *ssh_packet_set_connection(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ     ssh_packet_set_timeout(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_packet_stop_discard(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_packet_connection_af(ସଂରଚନା ssh *);
ଶୂନ୍ୟ     ssh_packet_set_nonblocking(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା      ssh_packet_get_connection_in(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା      ssh_packet_get_connection_out(ସଂରଚନା ssh *);
ଶୂନ୍ୟ	 ssh_packet_free(ସଂରଚନା ssh *);
ଶୂନ୍ୟ     ssh_packet_close(ସଂରଚନା ssh *);
ଶୂନ୍ୟ	 ssh_packet_set_ନିବେଶ_hook(ସଂରଚନା ssh *, ssh_packet_hook_fn *, ଶୂନ୍ୟ *);
ଶୂନ୍ୟ	 ssh_packet_clear_ଚାବିଗୁଡ଼ିକ(ସଂରଚନା ssh *);
ଶୂନ୍ୟ	 ssh_clear_newkeys(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_packet_is_rekeying(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_packet_check_rekey(ସଂରଚନା ssh *);
ଶୂନ୍ୟ     ssh_packet_set_protocol_flags(ସଂରଚନା ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(ସଂରଚନା ssh *);
ଶୂନ୍ୟ	 ssh_packet_set_interactive(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ	 ssh_packet_set_qos(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ଶୂନ୍ୟ     ssh_packet_set_server(ସଂରଚନା ssh *);
ଶୂନ୍ୟ     ssh_packet_set_authenticated(ସଂରଚନା ssh *);
ଶୂନ୍ୟ     ssh_packet_set_mux(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_packet_get_mux(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_packet_set_log_preamble(ସଂରଚନା ssh *, ଅଚଳ ଅକ୍ଷର *, ...)
    __attribute__((format(printf, 2, 3)));

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_packet_log_type(u_char);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_packet_send2_wrapped(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_packet_send2(ସଂରଚନା ssh *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା      ssh_packet_read(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_packet_read_poll2(ସଂରଚନା ssh *, u_char *, uint32_t *seqnr_p);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_packet_process_incoming(ସଂରଚନା ssh *, ଅଚଳ ଅକ୍ଷର *buf, u_int len);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_packet_process_read(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା      ssh_packet_read_seqnr(ସଂରଚନା ssh *, u_char *, uint32_t *seqnr_p);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା      ssh_packet_read_poll_seqnr(ସଂରଚନା ssh *, u_char *, uint32_t *seqnr_p);

ଶୂନ୍ୟ     ssh_packet_disconnect(ସଂରଚନା ssh *, ଅଚଳ ଅକ୍ଷର *fmt, ...)
	__attribute__((format(printf, 2, 3)))
	__attribute__((noreturn));
ଶୂନ୍ୟ     ssh_packet_send_debug(ସଂରଚନା ssh *, ଅଚଳ ଅକ୍ଷର *fmt, ...) __attribute__((format(printf, 2, 3)));

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_set_newkeys(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା mode);
ଶୂନ୍ୟ	 ssh_packet_get_bytes(ସଂରଚନା ssh *, uint64_t *, uint64_t *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_packet_write_poll(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_packet_write_wait(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା      ssh_packet_have_data_to_write(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା      ssh_packet_not_very_much_data_to_write(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_packet_interactive_data_to_write(ସଂରଚନା ssh *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_packet_connection_is_on_socket(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_packet_remaining(ସଂରଚନା ssh *);

ଶୂନ୍ୟ	 ssh_tty_make_modes(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା, ସଂରଚନା termios *);
ଶୂନ୍ୟ	 ssh_tty_parse_modes(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

ଶୂନ୍ୟ	 ssh_packet_set_alive_timeouts(ସଂରଚନା ssh *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_packet_inc_alive_timeouts(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_packet_set_maxsize(ସଂରଚନା ssh *, u_int);
u_int	 ssh_packet_get_maxsize(ସଂରଚନା ssh *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_packet_get_state(ସଂରଚନା ssh *, ସଂରଚନା sshbuf *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_packet_set_state(ସଂରଚନା ssh *, ସଂରଚନା sshbuf *);

ଅଚଳ ଅକ୍ଷର *ssh_remote_ipaddr(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_remote_port(ସଂରଚନା ssh *);
ଅଚଳ ଅକ୍ଷର *ssh_local_ipaddr(ସଂରଚନା ssh *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 ssh_local_port(ସଂରଚନା ssh *);
ଅଚଳ ଅକ୍ଷର *ssh_packet_rdomain_in(ସଂରଚନା ssh *);
ଅକ୍ଷର	*ssh_remote_hostname(ସଂରଚନା ssh *);

ଶୂନ୍ୟ	 ssh_packet_set_rekey_limits(ସଂରଚନା ssh *, uint64_t, uint32_t);
time_t	 ssh_packet_get_rekey_timeout(ସଂରଚନା ssh *);

ଶୂନ୍ୟ	*ssh_packet_get_ନିବେଶ(ସଂରଚନା ssh *);
ଶୂନ୍ୟ	*ssh_packet_get_output(ସଂରଚନା ssh *);

/* new API */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_start(ସଂରଚନା ssh *ssh, u_char type);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_send(ସଂରଚନା ssh *ssh);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା     sshpkt_disconnect(ସଂରଚନା ssh *, ଅଚଳ ଅକ୍ଷର *fmt, ...)
	    __attribute__((format(printf, 2, 3)));
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_add_padding(ସଂରଚନା ssh *, u_char);
ଶୂନ୍ୟ	sshpkt_fatal(ସଂରଚନା ssh *ssh, ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ଅଚଳ ଅକ୍ଷର *fmt, ...)
	    __attribute__((format(printf, 3, 4)))
	    __attribute__((noreturn));
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_ସନ୍ଦେଶ_ignore(ସଂରଚନା ssh *, u_int);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_put(ସଂରଚନା ssh *ssh, ଅଚଳ ଶୂନ୍ୟ *v, size_t len);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_putb(ସଂରଚନା ssh *ssh, ଅଚଳ ସଂରଚନା sshbuf *b);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_put_u8(ସଂରଚନା ssh *ssh, u_char val);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_put_u32(ସଂରଚନା ssh *ssh, uint32_t val);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_put_u64(ସଂରଚନା ssh *ssh, uint64_t val);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_put_string(ସଂରଚନା ssh *ssh, ଅଚଳ ଶୂନ୍ୟ *v, size_t len);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_put_cstring(ସଂରଚନା ssh *ssh, ଅଚଳ ଶୂନ୍ୟ *v);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_put_stringb(ସଂରଚନା ssh *ssh, ଅଚଳ ସଂରଚନା sshbuf *v);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_put_ec(ସଂରଚନା ssh *ssh, ଅଚଳ EC_POINT *v, ଅଚଳ EC_GROUP *g);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_put_ec_pkey(ସଂରଚନା ssh *ssh, EVP_PKEY *pkey);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_put_bignum2(ସଂରଚନା ssh *ssh, ଅଚଳ BIGNUM *v);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_get(ସଂରଚନା ssh *ssh, ଶୂନ୍ୟ *valp, size_t len);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_get_u8(ସଂରଚନା ssh *ssh, u_char *valp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_get_u32(ସଂରଚନା ssh *ssh, uint32_t *valp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_get_u64(ସଂରଚନା ssh *ssh, uint64_t *valp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_get_string(ସଂରଚନା ssh *ssh, u_char **valp, size_t *lenp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_get_string_direct(ସଂରଚନା ssh *ssh, ଅଚଳ u_char **valp, size_t *lenp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_peek_string_direct(ସଂରଚନା ssh *ssh, ଅଚଳ u_char **valp, size_t *lenp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_get_cstring(ସଂରଚନା ssh *ssh, ଅକ୍ଷର **valp, size_t *lenp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_getb_froms(ସଂରଚନା ssh *ssh, ସଂରଚନା sshbuf **valp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_get_ec(ସଂରଚନା ssh *ssh, EC_POINT *v, ଅଚଳ EC_GROUP *g);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_get_bignum2(ସଂରଚନା ssh *ssh, BIGNUM **valp);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	sshpkt_get_end(ସଂରଚନା ssh *ssh);
ଶୂନ୍ୟ	sshpkt_fmt_connection_id(ସଂରଚନା ssh *ssh, ଅକ୍ଷର *s, size_t l);
ଅଚଳ u_char	*sshpkt_ptr(ସଂରଚନା ssh *, size_t *lenp);
ଅକ୍ଷର	*connection_info_message(ସଂରଚନା ssh *ssh);

#endif				/* PACKET_H */
