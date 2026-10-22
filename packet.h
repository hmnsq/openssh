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

#अन्तर्भाव <sys/queue.h>

#अन्तर्भाव <stdint.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <termios.h>

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/ec.h>
#अन्तर्भाव <openssl/ecdsa.h>
#अन्तर्भाव <openssl/evp.h>
#अन्यथा /* OPENSSL */
#define BIGNUM		शून्य
#define EC_GROUP	शून्य
#define EC_POINT	शून्य
#define EVP_PKEY	शून्य
#endif /* WITH_OPENSSL */

संरचना kex;
संरचना sshkey;
संरचना sshbuf;
संरचना session_state;	/* private session data */

#अन्तर्भाव "dispatch.h"	/* typedef, DISPATCH_MAX */

संरचना कुंजी_entry {
	TAILQ_ENTRY(कुंजी_entry) next;
	संरचना sshkey *कुंजी;
};

संरचना ssh {
	/* Session state */
	संरचना session_state *state;

	/* Key exchange */
	संरचना kex *kex;

	/* cached local and remote ip addresses and ports */
	वर्ण *remote_ipaddr;
	पूर्णाङ्क remote_port;
	वर्ण *local_ipaddr;
	पूर्णाङ्क local_port;
	वर्ण *rdomain_in;

	/* Optional preamble for log messages (e.g. username) */
	वर्ण *log_preamble;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	पूर्णाङ्क dispatch_skip_packets;

	/* datafellows */
	uint32_t compat;
	वर्ण *remote_version;

	/* Lists for private and public keys */
	TAILQ_HEAD(, कुंजी_entry) private_कुंजियाँ;
	TAILQ_HEAD(, कुंजी_entry) public_कुंजियाँ;

	/* Client/Server authentication context */
	शून्य *authctxt;

	/* Channels context */
	संरचना ssh_channels *chanctxt;

	/* APP data */
	शून्य *app_data;
};

प्रकारनिर्देश पूर्णाङ्क (ssh_packet_hook_fn)(संरचना ssh *, संरचना sshbuf *,
    u_char *, शून्य *);

संरचना ssh *ssh_alloc_session_state(शून्य);
संरचना ssh *ssh_packet_set_connection(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क);
शून्य     ssh_packet_set_timeout(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क);
पूर्णाङ्क	 ssh_packet_stop_discard(संरचना ssh *);
पूर्णाङ्क	 ssh_packet_connection_af(संरचना ssh *);
शून्य     ssh_packet_set_nonblocking(संरचना ssh *);
पूर्णाङ्क      ssh_packet_get_connection_in(संरचना ssh *);
पूर्णाङ्क      ssh_packet_get_connection_out(संरचना ssh *);
शून्य	 ssh_packet_free(संरचना ssh *);
शून्य     ssh_packet_close(संरचना ssh *);
शून्य	 ssh_packet_set_निवेश_hook(संरचना ssh *, ssh_packet_hook_fn *, शून्य *);
शून्य	 ssh_packet_clear_कुंजियाँ(संरचना ssh *);
शून्य	 ssh_clear_newkeys(संरचना ssh *, पूर्णाङ्क);

पूर्णाङ्क	 ssh_packet_is_rekeying(संरचना ssh *);
पूर्णाङ्क	 ssh_packet_check_rekey(संरचना ssh *);
शून्य     ssh_packet_set_protocol_flags(संरचना ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(संरचना ssh *);
शून्य	 ssh_packet_set_interactive(संरचना ssh *, पूर्णाङ्क);
शून्य	 ssh_packet_set_qos(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क);
शून्य     ssh_packet_set_server(संरचना ssh *);
शून्य     ssh_packet_set_authenticated(संरचना ssh *);
शून्य     ssh_packet_set_mux(संरचना ssh *);
पूर्णाङ्क	 ssh_packet_get_mux(संरचना ssh *);
पूर्णाङ्क	 ssh_packet_set_log_preamble(संरचना ssh *, ध्रुव वर्ण *, ...)
    __attribute__((format(म_लिखो, 2, 3)));

पूर्णाङ्क	 ssh_packet_log_type(u_char);

पूर्णाङ्क	 ssh_packet_send2_wrapped(संरचना ssh *);
पूर्णाङ्क	 ssh_packet_send2(संरचना ssh *);

पूर्णाङ्क      ssh_packet_read(संरचना ssh *);
पूर्णाङ्क ssh_packet_read_poll2(संरचना ssh *, u_char *, uint32_t *seqnr_p);
पूर्णाङ्क	 ssh_packet_process_incoming(संरचना ssh *, ध्रुव वर्ण *buf, u_int len);
पूर्णाङ्क	 ssh_packet_process_read(संरचना ssh *, पूर्णाङ्क);
पूर्णाङ्क      ssh_packet_read_seqnr(संरचना ssh *, u_char *, uint32_t *seqnr_p);
पूर्णाङ्क      ssh_packet_read_poll_seqnr(संरचना ssh *, u_char *, uint32_t *seqnr_p);

शून्य     ssh_packet_disconnect(संरचना ssh *, ध्रुव वर्ण *fmt, ...)
	__attribute__((format(म_लिखो, 2, 3)))
	__attribute__((noreturn));
शून्य     ssh_packet_send_debug(संरचना ssh *, ध्रुव वर्ण *fmt, ...) __attribute__((format(म_लिखो, 2, 3)));

पूर्णाङ्क	 ssh_set_newkeys(संरचना ssh *, पूर्णाङ्क mode);
शून्य	 ssh_packet_get_bytes(संरचना ssh *, uint64_t *, uint64_t *);

पूर्णाङ्क	 ssh_packet_write_poll(संरचना ssh *);
पूर्णाङ्क	 ssh_packet_write_wait(संरचना ssh *);
पूर्णाङ्क      ssh_packet_have_data_to_write(संरचना ssh *);
पूर्णाङ्क      ssh_packet_not_very_much_data_to_write(संरचना ssh *);
पूर्णाङ्क	 ssh_packet_interactive_data_to_write(संरचना ssh *);

पूर्णाङ्क	 ssh_packet_connection_is_on_socket(संरचना ssh *);
पूर्णाङ्क	 ssh_packet_remaining(संरचना ssh *);

शून्य	 ssh_tty_make_modes(संरचना ssh *, पूर्णाङ्क, संरचना termios *);
शून्य	 ssh_tty_parse_modes(संरचना ssh *, पूर्णाङ्क);

शून्य	 ssh_packet_set_alive_timeouts(संरचना ssh *, पूर्णाङ्क);
पूर्णाङ्क	 ssh_packet_inc_alive_timeouts(संरचना ssh *);
पूर्णाङ्क	 ssh_packet_set_maxsize(संरचना ssh *, u_int);
u_int	 ssh_packet_get_maxsize(संरचना ssh *);

पूर्णाङ्क	 ssh_packet_get_state(संरचना ssh *, संरचना sshbuf *);
पूर्णाङ्क	 ssh_packet_set_state(संरचना ssh *, संरचना sshbuf *);

ध्रुव वर्ण *ssh_remote_ipaddr(संरचना ssh *);
पूर्णाङ्क	 ssh_remote_port(संरचना ssh *);
ध्रुव वर्ण *ssh_local_ipaddr(संरचना ssh *);
पूर्णाङ्क	 ssh_local_port(संरचना ssh *);
ध्रुव वर्ण *ssh_packet_rdomain_in(संरचना ssh *);
वर्ण	*ssh_remote_hostname(संरचना ssh *);

शून्य	 ssh_packet_set_rekey_limits(संरचना ssh *, uint64_t, uint32_t);
समय_प्रकार	 ssh_packet_get_rekey_timeout(संरचना ssh *);

शून्य	*ssh_packet_get_निवेश(संरचना ssh *);
शून्य	*ssh_packet_get_output(संरचना ssh *);

/* new API */
पूर्णाङ्क	sshpkt_start(संरचना ssh *ssh, u_char type);
पूर्णाङ्क	sshpkt_send(संरचना ssh *ssh);
पूर्णाङ्क     sshpkt_disconnect(संरचना ssh *, ध्रुव वर्ण *fmt, ...)
	    __attribute__((format(म_लिखो, 2, 3)));
पूर्णाङ्क	sshpkt_add_padding(संरचना ssh *, u_char);
शून्य	sshpkt_fatal(संरचना ssh *ssh, पूर्णाङ्क r, ध्रुव वर्ण *fmt, ...)
	    __attribute__((format(म_लिखो, 3, 4)))
	    __attribute__((noreturn));
पूर्णाङ्क	sshpkt_संदेश_ignore(संरचना ssh *, u_int);

पूर्णाङ्क	sshpkt_put(संरचना ssh *ssh, ध्रुव शून्य *v, माप_प्रकार len);
पूर्णाङ्क	sshpkt_putb(संरचना ssh *ssh, ध्रुव संरचना sshbuf *b);
पूर्णाङ्क	sshpkt_put_u8(संरचना ssh *ssh, u_char val);
पूर्णाङ्क	sshpkt_put_u32(संरचना ssh *ssh, uint32_t val);
पूर्णाङ्क	sshpkt_put_u64(संरचना ssh *ssh, uint64_t val);
पूर्णाङ्क	sshpkt_put_string(संरचना ssh *ssh, ध्रुव शून्य *v, माप_प्रकार len);
पूर्णाङ्क	sshpkt_put_cstring(संरचना ssh *ssh, ध्रुव शून्य *v);
पूर्णाङ्क	sshpkt_put_stringb(संरचना ssh *ssh, ध्रुव संरचना sshbuf *v);
पूर्णाङ्क	sshpkt_put_ec(संरचना ssh *ssh, ध्रुव EC_POINT *v, ध्रुव EC_GROUP *g);
पूर्णाङ्क	sshpkt_put_ec_pkey(संरचना ssh *ssh, EVP_PKEY *pkey);
पूर्णाङ्क	sshpkt_put_bignum2(संरचना ssh *ssh, ध्रुव BIGNUM *v);

पूर्णाङ्क	sshpkt_get(संरचना ssh *ssh, शून्य *valp, माप_प्रकार len);
पूर्णाङ्क	sshpkt_get_u8(संरचना ssh *ssh, u_char *valp);
पूर्णाङ्क	sshpkt_get_u32(संरचना ssh *ssh, uint32_t *valp);
पूर्णाङ्क	sshpkt_get_u64(संरचना ssh *ssh, uint64_t *valp);
पूर्णाङ्क	sshpkt_get_string(संरचना ssh *ssh, u_char **valp, माप_प्रकार *lenp);
पूर्णाङ्क	sshpkt_get_string_direct(संरचना ssh *ssh, ध्रुव u_char **valp, माप_प्रकार *lenp);
पूर्णाङ्क	sshpkt_peek_string_direct(संरचना ssh *ssh, ध्रुव u_char **valp, माप_प्रकार *lenp);
पूर्णाङ्क	sshpkt_get_cstring(संरचना ssh *ssh, वर्ण **valp, माप_प्रकार *lenp);
पूर्णाङ्क	sshpkt_getb_froms(संरचना ssh *ssh, संरचना sshbuf **valp);
पूर्णाङ्क	sshpkt_get_ec(संरचना ssh *ssh, EC_POINT *v, ध्रुव EC_GROUP *g);
पूर्णाङ्क	sshpkt_get_bignum2(संरचना ssh *ssh, BIGNUM **valp);
पूर्णाङ्क	sshpkt_get_end(संरचना ssh *ssh);
शून्य	sshpkt_fmt_connection_id(संरचना ssh *ssh, वर्ण *s, माप_प्रकार l);
ध्रुव u_char	*sshpkt_ptr(संरचना ssh *, माप_प्रकार *lenp);
वर्ण	*connection_info_message(संरचना ssh *ssh);

#endif				/* PACKET_H */
