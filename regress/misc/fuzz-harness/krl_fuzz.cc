// libfuzzer driver for krl parse fuzzing.

#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdio.h>

બાહ્ય "C" {
#અન્તર્ભાવ "includes.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "krl.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "authfile.h"
}

સ્થિર પૂર્ણાંક initialised = 0;
સ્થિર FILE *null_file;
સ્થિર સંરચના sshkey *ચાવી = ખાલી;

બાહ્ય "C" પૂર્ણાંક LLVMFuzzer_Test_One_આગત(અચલ uint8_t *data, size_t size) {
    // single initialisation
    જો (!initialised) {
        log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

        જો ((null_file = fopen("/dev/null", "w")) == ખાલી) પાછા 0;

        જો (sshkey_generate(ચાવી_ED25519, 0, &ચાવી) != 0) પાછા 0;

        initialised = 1;
    }

    // Reject empty corpus
    જો (size < 4) પાછા 0;

    // Convert fuzzer data to ssh buffer
    સંરચના sshbuf *buf = sshbuf_from(data, size);
    જો (!buf) પાછા 0;

    // Parse the ssh buffer as krl, early exit if failed
    સંરચના ssh_krl *krl = ખાલી;
    પૂર્ણાંક ret = ssh_krl_from_blob(buf, &krl);
    sshbuf_free(buf);
    જો (ret != 0) પાછા 0;

    // Fuzz serailisation roundtrip
    સંરચના sshbuf *output = sshbuf_new();
    સંરચના ssh_krl *krl2 = ખાલી;
    ssh_krl_to_blob(krl, output);
    ssh_krl_from_blob(output, &krl2);
    ssh_krl_free(krl2);
    sshbuf_free(output);

    // Fuzz krl_dump
    krl_dump(krl, null_file);

    // Fuzz ssh_krl_check_key
    ssh_krl_check_ચાવી(krl, ચાવી);

    ssh_krl_free(krl);
    પાછા 0;
}
