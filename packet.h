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

#অন্তর্ভাব <sys/queue.h>

#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <termios.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/bn.h>
#অন্তর্ভাব <openssl/ec.h>
#অন্তর্ভাব <openssl/ecdsa.h>
#অন্তর্ভাব <openssl/evp.h>
#অন্যথা /* OPENSSL */
#define BIGNUM		শূন্য
#define EC_GROUP	শূন্য
#define EC_POINT	শূন্য
#define EVP_PKEY	শূন্য
#endif /* WITH_OPENSSL */

কাঠামো kex;
কাঠামো sshkey;
কাঠামো sshbuf;
কাঠামো session_state;	/* private session data */

#অন্তর্ভাব "dispatch.h"	/* typedef, DISPATCH_MAX */

কাঠামো চাবি_entry {
	TAILQ_ENTRY(চাবি_entry) পরবর্তী;
	কাঠামো sshkey *চাবি;
};

কাঠামো ssh {
	/* Session state */
	কাঠামো session_state *state;

	/* Key exchange */
	কাঠামো kex *kex;

	/* cached local and remote ip addresses and ports */
	অক্ষর *remote_ipaddr;
	পূর্ণসংখ্যা remote_port;
	অক্ষর *local_ipaddr;
	পূর্ণসংখ্যা local_port;
	অক্ষর *rdomain_in;

	/* Optional preamble for log messages (e.g. username) */
	অক্ষর *log_preamble;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	পূর্ণসংখ্যা dispatch_skip_packets;

	/* datafellows */
	uint32_t compat;
	অক্ষর *remote_version;

	/* Lists for private and public keys */
	TAILQ_HEAD(, চাবি_entry) private_চাবিগুলি;
	TAILQ_HEAD(, চাবি_entry) public_চাবিগুলি;

	/* Client/Server authentication context */
	শূন্য *authctxt;

	/* Channels context */
	কাঠামো ssh_channels *chanctxt;

	/* APP data */
	শূন্য *app_তথ্য;
};

প্রকারলেখ পূর্ণসংখ্যা (ssh_packet_hook_fn)(কাঠামো ssh *, কাঠামো sshbuf *,
    u_char *, শূন্য *);

কাঠামো ssh *ssh_alloc_session_state(শূন্য);
কাঠামো ssh *ssh_packet_set_connection(কাঠামো ssh *, পূর্ণসংখ্যা, পূর্ণসংখ্যা);
শূন্য     ssh_packet_set_timeout(কাঠামো ssh *, পূর্ণসংখ্যা, পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 ssh_packet_stop_discard(কাঠামো ssh *);
পূর্ণসংখ্যা	 ssh_packet_connection_af(কাঠামো ssh *);
শূন্য     ssh_packet_set_nonblocking(কাঠামো ssh *);
পূর্ণসংখ্যা      ssh_packet_get_connection_in(কাঠামো ssh *);
পূর্ণসংখ্যা      ssh_packet_get_connection_out(কাঠামো ssh *);
শূন্য	 ssh_packet_free(কাঠামো ssh *);
শূন্য     ssh_packet_close(কাঠামো ssh *);
শূন্য	 ssh_packet_set_প্রবেশ_hook(কাঠামো ssh *, ssh_packet_hook_fn *, শূন্য *);
শূন্য	 ssh_packet_clear_চাবিগুলি(কাঠামো ssh *);
শূন্য	 ssh_clear_newkeys(কাঠামো ssh *, পূর্ণসংখ্যা);

পূর্ণসংখ্যা	 ssh_packet_is_rekeying(কাঠামো ssh *);
পূর্ণসংখ্যা	 ssh_packet_check_rekey(কাঠামো ssh *);
শূন্য     ssh_packet_set_protocol_flags(কাঠামো ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(কাঠামো ssh *);
শূন্য	 ssh_packet_set_interactive(কাঠামো ssh *, পূর্ণসংখ্যা);
শূন্য	 ssh_packet_set_qos(কাঠামো ssh *, পূর্ণসংখ্যা, পূর্ণসংখ্যা);
শূন্য     ssh_packet_set_server(কাঠামো ssh *);
শূন্য     ssh_packet_set_authenticated(কাঠামো ssh *);
শূন্য     ssh_packet_set_mux(কাঠামো ssh *);
পূর্ণসংখ্যা	 ssh_packet_get_mux(কাঠামো ssh *);
পূর্ণসংখ্যা	 ssh_packet_set_log_preamble(কাঠামো ssh *, ধ্রুবক অক্ষর *, ...)
    __attribute__((format(printf, 2, 3)));

পূর্ণসংখ্যা	 ssh_packet_log_type(u_char);

পূর্ণসংখ্যা	 ssh_packet_send2_wrapped(কাঠামো ssh *);
পূর্ণসংখ্যা	 ssh_packet_send2(কাঠামো ssh *);

পূর্ণসংখ্যা      ssh_packet_read(কাঠামো ssh *);
পূর্ণসংখ্যা ssh_packet_read_poll2(কাঠামো ssh *, u_char *, uint32_t *seqnr_p);
পূর্ণসংখ্যা	 ssh_packet_process_incoming(কাঠামো ssh *, ধ্রুবক অক্ষর *buf, u_int len);
পূর্ণসংখ্যা	 ssh_packet_process_read(কাঠামো ssh *, পূর্ণসংখ্যা);
পূর্ণসংখ্যা      ssh_packet_read_seqnr(কাঠামো ssh *, u_char *, uint32_t *seqnr_p);
পূর্ণসংখ্যা      ssh_packet_read_poll_seqnr(কাঠামো ssh *, u_char *, uint32_t *seqnr_p);

শূন্য     ssh_packet_disconnect(কাঠামো ssh *, ধ্রুবক অক্ষর *fmt, ...)
	__attribute__((format(printf, 2, 3)))
	__attribute__((noreturn));
শূন্য     ssh_packet_send_debug(কাঠামো ssh *, ধ্রুবক অক্ষর *fmt, ...) __attribute__((format(printf, 2, 3)));

পূর্ণসংখ্যা	 ssh_set_newkeys(কাঠামো ssh *, পূর্ণসংখ্যা mode);
শূন্য	 ssh_packet_get_bytes(কাঠামো ssh *, uint64_t *, uint64_t *);

পূর্ণসংখ্যা	 ssh_packet_write_poll(কাঠামো ssh *);
পূর্ণসংখ্যা	 ssh_packet_write_wait(কাঠামো ssh *);
পূর্ণসংখ্যা      ssh_packet_have_তথ্য_to_write(কাঠামো ssh *);
পূর্ণসংখ্যা      ssh_packet_not_very_much_তথ্য_to_write(কাঠামো ssh *);
পূর্ণসংখ্যা	 ssh_packet_interactive_তথ্য_to_write(কাঠামো ssh *);

পূর্ণসংখ্যা	 ssh_packet_connection_is_on_socket(কাঠামো ssh *);
পূর্ণসংখ্যা	 ssh_packet_remaining(কাঠামো ssh *);

শূন্য	 ssh_tty_make_modes(কাঠামো ssh *, পূর্ণসংখ্যা, কাঠামো termios *);
শূন্য	 ssh_tty_parse_modes(কাঠামো ssh *, পূর্ণসংখ্যা);

শূন্য	 ssh_packet_set_alive_timeouts(কাঠামো ssh *, পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 ssh_packet_inc_alive_timeouts(কাঠামো ssh *);
পূর্ণসংখ্যা	 ssh_packet_set_maxsize(কাঠামো ssh *, u_int);
u_int	 ssh_packet_get_maxsize(কাঠামো ssh *);

পূর্ণসংখ্যা	 ssh_packet_get_state(কাঠামো ssh *, কাঠামো sshbuf *);
পূর্ণসংখ্যা	 ssh_packet_set_state(কাঠামো ssh *, কাঠামো sshbuf *);

ধ্রুবক অক্ষর *ssh_remote_ipaddr(কাঠামো ssh *);
পূর্ণসংখ্যা	 ssh_remote_port(কাঠামো ssh *);
ধ্রুবক অক্ষর *ssh_local_ipaddr(কাঠামো ssh *);
পূর্ণসংখ্যা	 ssh_local_port(কাঠামো ssh *);
ধ্রুবক অক্ষর *ssh_packet_rdomain_in(কাঠামো ssh *);
অক্ষর	*ssh_remote_hostname(কাঠামো ssh *);

শূন্য	 ssh_packet_set_rekey_limits(কাঠামো ssh *, uint64_t, uint32_t);
time_t	 ssh_packet_get_rekey_timeout(কাঠামো ssh *);

শূন্য	*ssh_packet_get_প্রবেশ(কাঠামো ssh *);
শূন্য	*ssh_packet_get_output(কাঠামো ssh *);

/* new API */
পূর্ণসংখ্যা	sshpkt_start(কাঠামো ssh *ssh, u_char type);
পূর্ণসংখ্যা	sshpkt_send(কাঠামো ssh *ssh);
পূর্ণসংখ্যা     sshpkt_disconnect(কাঠামো ssh *, ধ্রুবক অক্ষর *fmt, ...)
	    __attribute__((format(printf, 2, 3)));
পূর্ণসংখ্যা	sshpkt_add_padding(কাঠামো ssh *, u_char);
শূন্য	sshpkt_fatal(কাঠামো ssh *ssh, পূর্ণসংখ্যা r, ধ্রুবক অক্ষর *fmt, ...)
	    __attribute__((format(printf, 3, 4)))
	    __attribute__((noreturn));
পূর্ণসংখ্যা	sshpkt_বার্তা_ignore(কাঠামো ssh *, u_int);

পূর্ণসংখ্যা	sshpkt_put(কাঠামো ssh *ssh, ধ্রুবক শূন্য *v, আকার_t len);
পূর্ণসংখ্যা	sshpkt_putb(কাঠামো ssh *ssh, ধ্রুবক কাঠামো sshbuf *b);
পূর্ণসংখ্যা	sshpkt_put_u8(কাঠামো ssh *ssh, u_char val);
পূর্ণসংখ্যা	sshpkt_put_u32(কাঠামো ssh *ssh, uint32_t val);
পূর্ণসংখ্যা	sshpkt_put_u64(কাঠামো ssh *ssh, uint64_t val);
পূর্ণসংখ্যা	sshpkt_put_string(কাঠামো ssh *ssh, ধ্রুবক শূন্য *v, আকার_t len);
পূর্ণসংখ্যা	sshpkt_put_cstring(কাঠামো ssh *ssh, ধ্রুবক শূন্য *v);
পূর্ণসংখ্যা	sshpkt_put_stringb(কাঠামো ssh *ssh, ধ্রুবক কাঠামো sshbuf *v);
পূর্ণসংখ্যা	sshpkt_put_ec(কাঠামো ssh *ssh, ধ্রুবক EC_POINT *v, ধ্রুবক EC_GROUP *g);
পূর্ণসংখ্যা	sshpkt_put_ec_pkey(কাঠামো ssh *ssh, EVP_PKEY *pkey);
পূর্ণসংখ্যা	sshpkt_put_bignum2(কাঠামো ssh *ssh, ধ্রুবক BIGNUM *v);

পূর্ণসংখ্যা	sshpkt_get(কাঠামো ssh *ssh, শূন্য *valp, আকার_t len);
পূর্ণসংখ্যা	sshpkt_get_u8(কাঠামো ssh *ssh, u_char *valp);
পূর্ণসংখ্যা	sshpkt_get_u32(কাঠামো ssh *ssh, uint32_t *valp);
পূর্ণসংখ্যা	sshpkt_get_u64(কাঠামো ssh *ssh, uint64_t *valp);
পূর্ণসংখ্যা	sshpkt_get_string(কাঠামো ssh *ssh, u_char **valp, আকার_t *lenp);
পূর্ণসংখ্যা	sshpkt_get_string_direct(কাঠামো ssh *ssh, ধ্রুবক u_char **valp, আকার_t *lenp);
পূর্ণসংখ্যা	sshpkt_peek_string_direct(কাঠামো ssh *ssh, ধ্রুবক u_char **valp, আকার_t *lenp);
পূর্ণসংখ্যা	sshpkt_get_cstring(কাঠামো ssh *ssh, অক্ষর **valp, আকার_t *lenp);
পূর্ণসংখ্যা	sshpkt_getb_froms(কাঠামো ssh *ssh, কাঠামো sshbuf **valp);
পূর্ণসংখ্যা	sshpkt_get_ec(কাঠামো ssh *ssh, EC_POINT *v, ধ্রুবক EC_GROUP *g);
পূর্ণসংখ্যা	sshpkt_get_bignum2(কাঠামো ssh *ssh, BIGNUM **valp);
পূর্ণসংখ্যা	sshpkt_get_end(কাঠামো ssh *ssh);
শূন্য	sshpkt_fmt_connection_id(কাঠামো ssh *ssh, অক্ষর *s, আকার_t l);
ধ্রুবক u_char	*sshpkt_ptr(কাঠামো ssh *, আকার_t *lenp);
অক্ষর	*connection_info_message(কাঠামো ssh *ssh);

#endif				/* PACKET_H */
