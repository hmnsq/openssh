/* $OpenBSD: ssh_api.h,v 1.2 2018/04/10 00:10:49 djm Exp $ */
/*
 * Copyright (c) 2012 Markus Friedl.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#నిర్వచితం_కాకపోతే API_H
#నిర్వచించు API_H

#అన్తర్భావ <sys/queue.h>
#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <signal.h>

#అన్తర్భావ "cipher.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "packet.h"

నిర్మాణం kex_params {
	అక్షరం *proposal[PROPOSAL_MAX];
};

/* public SSH API functions */

/*
 * ssh_init() create a ssh connection object with given (optional)
 * key exchange parameters.
 */
పూర్ణాంకం	ssh_init(నిర్మాణం ssh **, పూర్ణాంకం is_server, నిర్మాణం kex_params *kex_params);

/*
 * release ssh connection state.
 */
శూన్య	ssh_free(నిర్మాణం ssh *);

/*
 * attach application specific data to the connection state
 */
శూన్య	ssh_సమితి_app_దత్తాంశం(నిర్మాణం ssh *, శూన్య *);
శూన్య	*ssh_get_app_దత్తాంశం(నిర్మాణం ssh *);

/*
 * ssh_add_hostkey() registers a private/public hostkey for an ssh
 * connection.
 * ssh_add_hostkey() needs to be called before a key exchange is
 * initiated with ssh_packet_next().
 * private hostkeys are required if we need to act as a server.
 * public hostkeys are used to verify the servers hostkey.
 */
పూర్ణాంకం	ssh_కూడు_hostkey(నిర్మాణం ssh *ssh, నిర్మాణం sshkey *కీలకం);

/*
 * ssh_set_verify_host_key_callback() registers a callback function
 * which should be called instead of the default verification. The
 * function given must return 0 if the hostkey is ok, -1 if the
 * verification has failed.
 */
పూర్ణాంకం	ssh_సమితి_verify_host_కీలకం_callback(నిర్మాణం ssh *ssh,
    పూర్ణాంకం (*cb)(నిర్మాణం sshkey *, నిర్మాణం ssh *));

/*
 * ssh_packet_next() advances to the next input packet and returns
 * the packet type in typep.
 * ssh_packet_next() works by processing an input byte-stream,
 * decrypting the received data and hiding the key-exchange from
 * the caller.
 * ssh_packet_next() sets typep if there is no new packet available.
 * in this case the caller must fill the input byte-stream by passing
 * the data received over network to ssh_input_append().
 * additionally, the caller needs to send the resulting output
 * byte-stream back over the network. otherwise the key exchange
 * would not proceed. the output byte-stream is accessed through
 * ssh_output_ptr().
 */
పూర్ణాంకం	ssh_packet_తదుపరి(నిర్మాణం ssh *ssh, u_char *typep);

/*
 * ssh_packet_payload() returns a pointer to the raw payload data of
 * the current input packet and the length of this payload.
 * the payload is accessible until ssh_packet_next() is called again.
 */
స్థిరరాశి u_char	*ssh_packet_payload(నిర్మాణం ssh *ssh, కొలత_t *lenp);

/*
 * ssh_packet_put() creates an encrypted packet with the given type
 * and payload.
 * the encrypted packet is appended to the output byte-stream.
 */
పూర్ణాంకం	ssh_packet_put(నిర్మాణం ssh *ssh, పూర్ణాంకం type, స్థిరరాశి u_char *దత్తాంశం,
    కొలత_t len);

/*
 * ssh_input_space() checks if 'len' bytes can be appended to the
 * input byte-stream.
 */
పూర్ణాంకం	ssh_ఆదానం_space(నిర్మాణం ssh *ssh, కొలత_t len);

/*
 * ssh_input_append() appends data to the input byte-stream.
 */
పూర్ణాంకం	ssh_ఆదానం_append(నిర్మాణం ssh *ssh, స్థిరరాశి u_char *దత్తాంశం, కొలత_t len);

/*
 * ssh_output_space() checks if 'len' bytes can be appended to the
 * output byte-stream. XXX
 */
పూర్ణాంకం	ssh_output_space(నిర్మాణం ssh *ssh, కొలత_t len);

/*
 * ssh_output_ptr() retrieves both a pointer and the length of the
 * current output byte-stream. the bytes need to be sent over the
 * network. the number of bytes that have been successfully sent can
 * be removed from the output byte-stream with ssh_output_consume().
 */
స్థిరరాశి u_char	*ssh_output_ptr(నిర్మాణం ssh *ssh, కొలత_t *len);

/*
 * ssh_output_consume() removes the given number of bytes from
 * the output byte-stream.
 */
పూర్ణాంకం	ssh_output_consume(నిర్మాణం ssh *ssh, కొలత_t len);

#అయితే_ముగింపు
