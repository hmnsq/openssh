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

#अगर_अघोषित PACKET_H
#घोषणा PACKET_H

#समावेश <sys/queue.h>

#समावेश <stdint.h>
#समावेश <signal.h>
#समावेश <termios.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/bn.h>
#समावेश <openssl/ec.h>
#समावेश <openssl/ecdsa.h>
#समावेश <openssl/evp.h>
#अन्यथा /* OPENSSL */
#घोषणा BIGNUM		व्योम
#घोषणा EC_GROUP	व्योम
#घोषणा EC_POINT	व्योम
#घोषणा EVP_PKEY	व्योम
#पूर्ण_अगर /* WITH_OPENSSL */

काष्ठा kex;
काष्ठा sshkey;
काष्ठा sshbuf;
काष्ठा session_state;	/* private session data */

#समावेश "dispatch.h"	/* typedef, DISPATCH_MAX */

काष्ठा कुंजी_entry {
	TAILQ_ENTRY(कुंजी_entry) अग्र;
	काष्ठा sshkey *कुंजी;
};

काष्ठा ssh {
	/* Session state */
	काष्ठा session_state *state;

	/* Key exchange */
	काष्ठा kex *kex;

	/* cached local and remote ip addresses and ports */
	अक्षर *remote_ipaddr;
	पूर्णांक remote_port;
	अक्षर *local_ipaddr;
	पूर्णांक local_port;
	अक्षर *rdomain_in;

	/* Optional preamble for log messages (e.g. username) */
	अक्षर *log_preamble;

	/* Dispatcher table */
	dispatch_fn *dispatch[DISPATCH_MAX];
	/* number of packets to ignore in the dispatcher */
	पूर्णांक dispatch_skip_packets;

	/* datafellows */
	uint32_t compat;
	अक्षर *remote_version;

	/* Lists for private and public keys */
	TAILQ_HEAD(, कुंजी_entry) private_कुंजियाँ;
	TAILQ_HEAD(, कुंजी_entry) public_कुंजियाँ;

	/* Client/Server authentication context */
	व्योम *authctxt;

	/* Channels context */
	काष्ठा ssh_channels *chanctxt;

	/* APP data */
	व्योम *app_तथ्य;
};

प्रकार पूर्णांक (ssh_packet_hook_fn)(काष्ठा ssh *, काष्ठा sshbuf *,
    u_char *, व्योम *);

काष्ठा ssh *ssh_alloc_session_state(व्योम);
काष्ठा ssh *ssh_packet_set_connection(काष्ठा ssh *, पूर्णांक, पूर्णांक);
व्योम     ssh_packet_set_timeout(काष्ठा ssh *, पूर्णांक, पूर्णांक);
पूर्णांक	 ssh_packet_stop_discard(काष्ठा ssh *);
पूर्णांक	 ssh_packet_connection_af(काष्ठा ssh *);
व्योम     ssh_packet_set_nonblocking(काष्ठा ssh *);
पूर्णांक      ssh_packet_get_connection_in(काष्ठा ssh *);
पूर्णांक      ssh_packet_get_connection_out(काष्ठा ssh *);
व्योम	 ssh_packet_free(काष्ठा ssh *);
व्योम     ssh_packet_close(काष्ठा ssh *);
व्योम	 ssh_packet_set_निवेश_hook(काष्ठा ssh *, ssh_packet_hook_fn *, व्योम *);
व्योम	 ssh_packet_clear_कुंजियाँ(काष्ठा ssh *);
व्योम	 ssh_clear_newkeys(काष्ठा ssh *, पूर्णांक);

पूर्णांक	 ssh_packet_is_rekeying(काष्ठा ssh *);
पूर्णांक	 ssh_packet_check_rekey(काष्ठा ssh *);
व्योम     ssh_packet_set_protocol_flags(काष्ठा ssh *, u_int);
u_int	 ssh_packet_get_protocol_flags(काष्ठा ssh *);
व्योम	 ssh_packet_set_interactive(काष्ठा ssh *, पूर्णांक);
व्योम	 ssh_packet_set_qos(काष्ठा ssh *, पूर्णांक, पूर्णांक);
व्योम     ssh_packet_set_server(काष्ठा ssh *);
व्योम     ssh_packet_set_authenticated(काष्ठा ssh *);
व्योम     ssh_packet_set_mux(काष्ठा ssh *);
पूर्णांक	 ssh_packet_get_mux(काष्ठा ssh *);
पूर्णांक	 ssh_packet_set_log_preamble(काष्ठा ssh *, स्थिर अक्षर *, ...)
    __attribute__((format(म_लिखो, 2, 3)));

पूर्णांक	 ssh_packet_log_type(u_char);

पूर्णांक	 ssh_packet_send2_wrapped(काष्ठा ssh *);
पूर्णांक	 ssh_packet_send2(काष्ठा ssh *);

पूर्णांक      ssh_packet_read(काष्ठा ssh *);
पूर्णांक ssh_packet_read_poll2(काष्ठा ssh *, u_char *, uint32_t *seqnr_p);
पूर्णांक	 ssh_packet_process_incoming(काष्ठा ssh *, स्थिर अक्षर *buf, u_int len);
पूर्णांक	 ssh_packet_process_read(काष्ठा ssh *, पूर्णांक);
पूर्णांक      ssh_packet_read_seqnr(काष्ठा ssh *, u_char *, uint32_t *seqnr_p);
पूर्णांक      ssh_packet_read_poll_seqnr(काष्ठा ssh *, u_char *, uint32_t *seqnr_p);

व्योम     ssh_packet_disconnect(काष्ठा ssh *, स्थिर अक्षर *fmt, ...)
	__attribute__((format(म_लिखो, 2, 3)))
	__attribute__((noreturn));
व्योम     ssh_packet_send_debug(काष्ठा ssh *, स्थिर अक्षर *fmt, ...) __attribute__((format(म_लिखो, 2, 3)));

पूर्णांक	 ssh_set_newkeys(काष्ठा ssh *, पूर्णांक mode);
व्योम	 ssh_packet_get_bytes(काष्ठा ssh *, uint64_t *, uint64_t *);

पूर्णांक	 ssh_packet_write_poll(काष्ठा ssh *);
पूर्णांक	 ssh_packet_write_wait(काष्ठा ssh *);
पूर्णांक      ssh_packet_have_तथ्य_to_write(काष्ठा ssh *);
पूर्णांक      ssh_packet_not_very_much_तथ्य_to_write(काष्ठा ssh *);
पूर्णांक	 ssh_packet_interactive_तथ्य_to_write(काष्ठा ssh *);

पूर्णांक	 ssh_packet_connection_is_on_socket(काष्ठा ssh *);
पूर्णांक	 ssh_packet_remaining(काष्ठा ssh *);

व्योम	 ssh_tty_make_modes(काष्ठा ssh *, पूर्णांक, काष्ठा termios *);
व्योम	 ssh_tty_parse_modes(काष्ठा ssh *, पूर्णांक);

व्योम	 ssh_packet_set_alive_timeouts(काष्ठा ssh *, पूर्णांक);
पूर्णांक	 ssh_packet_inc_alive_timeouts(काष्ठा ssh *);
पूर्णांक	 ssh_packet_set_maxsize(काष्ठा ssh *, u_int);
u_int	 ssh_packet_get_maxsize(काष्ठा ssh *);

पूर्णांक	 ssh_packet_get_state(काष्ठा ssh *, काष्ठा sshbuf *);
पूर्णांक	 ssh_packet_set_state(काष्ठा ssh *, काष्ठा sshbuf *);

स्थिर अक्षर *ssh_remote_ipaddr(काष्ठा ssh *);
पूर्णांक	 ssh_remote_port(काष्ठा ssh *);
स्थिर अक्षर *ssh_local_ipaddr(काष्ठा ssh *);
पूर्णांक	 ssh_local_port(काष्ठा ssh *);
स्थिर अक्षर *ssh_packet_rdomain_in(काष्ठा ssh *);
अक्षर	*ssh_remote_hostname(काष्ठा ssh *);

व्योम	 ssh_packet_set_rekey_limits(काष्ठा ssh *, uint64_t, uint32_t);
समय_प्रकार	 ssh_packet_get_rekey_timeout(काष्ठा ssh *);

व्योम	*ssh_packet_get_निवेश(काष्ठा ssh *);
व्योम	*ssh_packet_get_output(काष्ठा ssh *);

/* new API */
पूर्णांक	sshpkt_start(काष्ठा ssh *ssh, u_char type);
पूर्णांक	sshpkt_send(काष्ठा ssh *ssh);
पूर्णांक     sshpkt_disconnect(काष्ठा ssh *, स्थिर अक्षर *fmt, ...)
	    __attribute__((format(म_लिखो, 2, 3)));
पूर्णांक	sshpkt_add_padding(काष्ठा ssh *, u_char);
व्योम	sshpkt_fatal(काष्ठा ssh *ssh, पूर्णांक r, स्थिर अक्षर *fmt, ...)
	    __attribute__((format(म_लिखो, 3, 4)))
	    __attribute__((noreturn));
पूर्णांक	sshpkt_संदेश_ignore(काष्ठा ssh *, u_int);

पूर्णांक	sshpkt_put(काष्ठा ssh *ssh, स्थिर व्योम *v, माप_प्रकार len);
पूर्णांक	sshpkt_putb(काष्ठा ssh *ssh, स्थिर काष्ठा sshbuf *b);
पूर्णांक	sshpkt_put_u8(काष्ठा ssh *ssh, u_char val);
पूर्णांक	sshpkt_put_u32(काष्ठा ssh *ssh, uint32_t val);
पूर्णांक	sshpkt_put_u64(काष्ठा ssh *ssh, uint64_t val);
पूर्णांक	sshpkt_put_string(काष्ठा ssh *ssh, स्थिर व्योम *v, माप_प्रकार len);
पूर्णांक	sshpkt_put_cstring(काष्ठा ssh *ssh, स्थिर व्योम *v);
पूर्णांक	sshpkt_put_stringb(काष्ठा ssh *ssh, स्थिर काष्ठा sshbuf *v);
पूर्णांक	sshpkt_put_ec(काष्ठा ssh *ssh, स्थिर EC_POINT *v, स्थिर EC_GROUP *g);
पूर्णांक	sshpkt_put_ec_pkey(काष्ठा ssh *ssh, EVP_PKEY *pkey);
पूर्णांक	sshpkt_put_bignum2(काष्ठा ssh *ssh, स्थिर BIGNUM *v);

पूर्णांक	sshpkt_get(काष्ठा ssh *ssh, व्योम *valp, माप_प्रकार len);
पूर्णांक	sshpkt_get_u8(काष्ठा ssh *ssh, u_char *valp);
पूर्णांक	sshpkt_get_u32(काष्ठा ssh *ssh, uint32_t *valp);
पूर्णांक	sshpkt_get_u64(काष्ठा ssh *ssh, uint64_t *valp);
पूर्णांक	sshpkt_get_string(काष्ठा ssh *ssh, u_char **valp, माप_प्रकार *lenp);
पूर्णांक	sshpkt_get_string_direct(काष्ठा ssh *ssh, स्थिर u_char **valp, माप_प्रकार *lenp);
पूर्णांक	sshpkt_peek_string_direct(काष्ठा ssh *ssh, स्थिर u_char **valp, माप_प्रकार *lenp);
पूर्णांक	sshpkt_get_cstring(काष्ठा ssh *ssh, अक्षर **valp, माप_प्रकार *lenp);
पूर्णांक	sshpkt_getb_froms(काष्ठा ssh *ssh, काष्ठा sshbuf **valp);
पूर्णांक	sshpkt_get_ec(काष्ठा ssh *ssh, EC_POINT *v, स्थिर EC_GROUP *g);
पूर्णांक	sshpkt_get_bignum2(काष्ठा ssh *ssh, BIGNUM **valp);
पूर्णांक	sshpkt_get_end(काष्ठा ssh *ssh);
व्योम	sshpkt_fmt_connection_id(काष्ठा ssh *ssh, अक्षर *s, माप_प्रकार l);
स्थिर u_char	*sshpkt_ptr(काष्ठा ssh *, माप_प्रकार *lenp);
अक्षर	*connection_info_message(काष्ठा ssh *ssh);

#पूर्ण_अगर				/* PACKET_H */
