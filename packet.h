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

#यदि_अपरिभाषितम् PACKET_H
#परिभाषय PACKET_H

#अन्तर्भाव <sys/queue.h>

#अन्तर्भाव <stdint.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <termios.h>

#यदि_परिभाषितम् WITH_OPENSSL
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/ec.h>
#अन्तर्भाव <openssl/ecdsa.h>
#अन्तर्भाव <openssl/evp.h>
#अन्यथा /* OPENSSL */
#परिभाषय BIGNUM		शून्य
#परिभाषय EC_गणः	शून्य
#परिभाषय EC_POINT	शून्य
#परिभाषय EVP_PKEY	शून्य
#यदि_अन्तः /* WITH_OPENSSL */

संरचना kex;
संरचना sshkey;
संरचना sshbuf;
संरचना session_state;	/* private session data */

#अन्तर्भाव "dispatch.h"	/* typedef, DISPATCH_MAX */

संरचना कुञ्चिका_प्रविष्टिः {
	TAILQ_ENTRY(कुञ्चिका_प्रविष्टिः) अग्र;
	संरचना sshkey *कुञ्चिका;
};

संरचना ssh {
	/* Session state */
	संरचना session_state *state;

	/* Key exchange */
	संरचना kex *kex;

	/* cached local and remote ip addresses and ports */
	वर्ण *remote_ipaddr;
	पूर्णाङ्क remote_पत्तनम्;
	वर्ण *local_ipaddr;
	पूर्णाङ्क local_पत्तनम्;
	वर्ण *rdomain_अन्तर्;

	/* Optional preamble for log messages (e.g. username) */
	वर्ण *log_preamble;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	पूर्णाङ्क dispatch_skip_packets;

	/* datafellows */
	uint32_t compat;
	वर्ण *remote_संस्करणम्;

	/* Lists for private and public keys */
	TAILQ_HEAD(, कुञ्चिका_प्रविष्टिः) वैयक्तिकम्_कुञ्चिकाः;
	TAILQ_HEAD(, कुञ्चिका_प्रविष्टिः) लौकिकम्_कुञ्चिकाः;

	/* Client/Server authentication context */
	शून्य *authctxt;

	/* Channels context */
	संरचना ssh_channels *chanctxt;

	/* APP data */
	शून्य *app_दत्त;
};

प्रकारनिर्देश पूर्णाङ्क (ssh_packet_hook_fn)(संरचना ssh *, संरचना sshbuf *,
    u_char *, शून्य *);

संरचना ssh *ssh_alloc_session_state(शून्य);
संरचना ssh *ssh_packet_समुच्चयः_connection(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क);
शून्य     ssh_packet_समुच्चयः_timeout(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क);
पूर्णाङ्क	 ssh_packet_stop_discard(संरचना ssh *);
पूर्णाङ्क	 ssh_packet_connection_af(संरचना ssh *);
शून्य     ssh_packet_समुच्चयः_nonblocking(संरचना ssh *);
पूर्णाङ्क      ssh_packet_get_connection_अन्तर्(संरचना ssh *);
पूर्णाङ्क      ssh_packet_get_connection_बहिर्गमनम्(संरचना ssh *);
शून्य	 ssh_packet_free(संरचना ssh *);
शून्य     ssh_packet_close(संरचना ssh *);
शून्य	 ssh_packet_समुच्चयः_निवेशः_hook(संरचना ssh *, ssh_packet_hook_fn *, शून्य *);
शून्य	 ssh_packet_clear_कुञ्चिकाः(संरचना ssh *);
शून्य	 ssh_clear_newkeys(संरचना ssh *, पूर्णाङ्क);

पूर्णाङ्क	 ssh_packet_is_rekeying(संरचना ssh *);
पूर्णाङ्क	 ssh_packet_check_rekey(संरचना ssh *);
शून्य     ssh_packet_समुच्चयः_protocol_flags(संरचना ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(संरचना ssh *);
शून्य	 ssh_packet_समुच्चयः_interactive(संरचना ssh *, पूर्णाङ्क);
शून्य	 ssh_packet_समुच्चयः_qos(संरचना ssh *, पूर्णाङ्क, पूर्णाङ्क);
शून्य     ssh_packet_समुच्चयः_server(संरचना ssh *);
शून्य     ssh_packet_समुच्चयः_authenticated(संरचना ssh *);
शून्य     ssh_packet_समुच्चयः_mux(संरचना ssh *);
पूर्णाङ्क	 ssh_packet_get_mux(संरचना ssh *);
पूर्णाङ्क	 ssh_packet_समुच्चयः_log_preamble(संरचना ssh *, ध्रुव वर्ण *, ...)
    __attribute__((format(प्रारूप_लिख, 2, 3)));

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
	__attribute__((format(प्रारूप_लिख, 2, 3)))
	__attribute__((noreturn));
शून्य     ssh_packet_send_debug(संरचना ssh *, ध्रुव वर्ण *fmt, ...) __attribute__((format(प्रारूप_लिख, 2, 3)));

पूर्णाङ्क	 ssh_समुच्चयः_newkeys(संरचना ssh *, पूर्णाङ्क बहुलकम्);
शून्य	 ssh_packet_get_अष्टकानि(संरचना ssh *, uint64_t *, uint64_t *);

पूर्णाङ्क	 ssh_packet_write_poll(संरचना ssh *);
पूर्णाङ्क	 ssh_packet_write_wait(संरचना ssh *);
पूर्णाङ्क      ssh_packet_have_दत्त_गन्तव्यम्_write(संरचना ssh *);
पूर्णाङ्क      ssh_packet_not_very_much_दत्त_गन्तव्यम्_write(संरचना ssh *);
पूर्णाङ्क	 ssh_packet_interactive_दत्त_गन्तव्यम्_write(संरचना ssh *);

पूर्णाङ्क	 ssh_packet_connection_is_on_socket(संरचना ssh *);
पूर्णाङ्क	 ssh_packet_remaining(संरचना ssh *);

शून्य	 ssh_tty_make_modes(संरचना ssh *, पूर्णाङ्क, संरचना termios *);
शून्य	 ssh_tty_parse_modes(संरचना ssh *, पूर्णाङ्क);

शून्य	 ssh_packet_समुच्चयः_alive_timeouts(संरचना ssh *, पूर्णाङ्क);
पूर्णाङ्क	 ssh_packet_inc_alive_timeouts(संरचना ssh *);
पूर्णाङ्क	 ssh_packet_समुच्चयः_maxsize(संरचना ssh *, u_int);
u_int	 ssh_packet_get_maxsize(संरचना ssh *);

पूर्णाङ्क	 ssh_packet_get_state(संरचना ssh *, संरचना sshbuf *);
पूर्णाङ्क	 ssh_packet_समुच्चयः_state(संरचना ssh *, संरचना sshbuf *);

ध्रुव वर्ण *ssh_remote_ipaddr(संरचना ssh *);
पूर्णाङ्क	 ssh_remote_पत्तनम्(संरचना ssh *);
ध्रुव वर्ण *ssh_local_ipaddr(संरचना ssh *);
पूर्णाङ्क	 ssh_local_पत्तनम्(संरचना ssh *);
ध्रुव वर्ण *ssh_packet_rdomain_अन्तर्(संरचना ssh *);
वर्ण	*ssh_remote_hostname(संरचना ssh *);

शून्य	 ssh_packet_समुच्चयः_rekey_limits(संरचना ssh *, uint64_t, uint32_t);
time_t	 ssh_packet_get_rekey_timeout(संरचना ssh *);

शून्य	*ssh_packet_get_निवेशः(संरचना ssh *);
शून्य	*ssh_packet_get_output(संरचना ssh *);

/* new API */
पूर्णाङ्क	sshpkt_start(संरचना ssh *ssh, u_char type);
पूर्णाङ्क	sshpkt_send(संरचना ssh *ssh);
पूर्णाङ्क     sshpkt_disconnect(संरचना ssh *, ध्रुव वर्ण *fmt, ...)
	    __attribute__((format(प्रारूप_लिख, 2, 3)));
पूर्णाङ्क	sshpkt_सङ्कलय_padding(संरचना ssh *, u_char);
शून्य	sshpkt_fatal(संरचना ssh *ssh, पूर्णाङ्क r, ध्रुव वर्ण *fmt, ...)
	    __attribute__((format(प्रारूप_लिख, 3, 4)))
	    __attribute__((noreturn));
पूर्णाङ्क	sshpkt_सन्देशः_ignore(संरचना ssh *, u_int);

पूर्णाङ्क	sshpkt_put(संरचना ssh *ssh, ध्रुव शून्य *v, आकार_t len);
पूर्णाङ्क	sshpkt_putb(संरचना ssh *ssh, ध्रुव संरचना sshbuf *b);
पूर्णाङ्क	sshpkt_put_u8(संरचना ssh *ssh, u_char val);
पूर्णाङ्क	sshpkt_put_u32(संरचना ssh *ssh, uint32_t val);
पूर्णाङ्क	sshpkt_put_u64(संरचना ssh *ssh, uint64_t val);
पूर्णाङ्क	sshpkt_put_string(संरचना ssh *ssh, ध्रुव शून्य *v, आकार_t len);
पूर्णाङ्क	sshpkt_put_cstring(संरचना ssh *ssh, ध्रुव शून्य *v);
पूर्णाङ्क	sshpkt_put_stringb(संरचना ssh *ssh, ध्रुव संरचना sshbuf *v);
पूर्णाङ्क	sshpkt_put_ec(संरचना ssh *ssh, ध्रुव EC_POINT *v, ध्रुव EC_गणः *g);
पूर्णाङ्क	sshpkt_put_ec_pkey(संरचना ssh *ssh, EVP_PKEY *pkey);
पूर्णाङ्क	sshpkt_put_bignum2(संरचना ssh *ssh, ध्रुव BIGNUM *v);

पूर्णाङ्क	sshpkt_get(संरचना ssh *ssh, शून्य *valp, आकार_t len);
पूर्णाङ्क	sshpkt_get_u8(संरचना ssh *ssh, u_char *valp);
पूर्णाङ्क	sshpkt_get_u32(संरचना ssh *ssh, uint32_t *valp);
पूर्णाङ्क	sshpkt_get_u64(संरचना ssh *ssh, uint64_t *valp);
पूर्णाङ्क	sshpkt_get_string(संरचना ssh *ssh, u_char **valp, आकार_t *lenp);
पूर्णाङ्क	sshpkt_get_string_प्रत्यक्षम्(संरचना ssh *ssh, ध्रुव u_char **valp, आकार_t *lenp);
पूर्णाङ्क	sshpkt_peek_string_प्रत्यक्षम्(संरचना ssh *ssh, ध्रुव u_char **valp, आकार_t *lenp);
पूर्णाङ्क	sshpkt_get_cstring(संरचना ssh *ssh, वर्ण **valp, आकार_t *lenp);
पूर्णाङ्क	sshpkt_getb_froms(संरचना ssh *ssh, संरचना sshbuf **valp);
पूर्णाङ्क	sshpkt_get_ec(संरचना ssh *ssh, EC_POINT *v, ध्रुव EC_गणः *g);
पूर्णाङ्क	sshpkt_get_bignum2(संरचना ssh *ssh, BIGNUM **valp);
पूर्णाङ्क	sshpkt_get_अन्तः(संरचना ssh *ssh);
शून्य	sshpkt_fmt_connection_id(संरचना ssh *ssh, वर्ण *s, आकार_t l);
ध्रुव u_char	*sshpkt_ptr(संरचना ssh *, आकार_t *lenp);
वर्ण	*connection_info_सन्देशः(संरचना ssh *ssh);

#यदि_अन्तः				/* PACKET_H */
