// libfuzzer driver for krl parse fuzzing.

#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>

ବାହ୍ୟ "C" {
#ଅନ୍ତର୍ଭାଵ "includes.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "krl.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା initialised = 0;
ସ୍ଥିର FILE *null_file;
ସ୍ଥିର ସଂରଚନା sshkey *ଚାବି = ଖାଲି;

ବାହ୍ୟ "C" ପୂର୍ଣ୍ଣସଂଖ୍ୟା LLVMFuzzer_Test_One_ନିବେଶ(ଅଚଳ uint8_t *data, size_t size) {
    // single initialisation
    ଯଦି (!initialised) {
        log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

        ଯଦି ((null_file = fopen("/dev/null", "w")) == ଖାଲି) ଫେରନ୍ତୁ 0;

        ଯଦି (sshkey_generate(ଚାବି_ED25519, 0, &ଚାବି) != 0) ଫେରନ୍ତୁ 0;

        initialised = 1;
    }

    // Reject empty corpus
    ଯଦି (size < 4) ଫେରନ୍ତୁ 0;

    // Convert fuzzer data to ssh buffer
    ସଂରଚନା sshbuf *buf = sshbuf_from(data, size);
    ଯଦି (!buf) ଫେରନ୍ତୁ 0;

    // Parse the ssh buffer as krl, early exit if failed
    ସଂରଚନା ssh_krl *krl = ଖାଲି;
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = ssh_krl_from_blob(buf, &krl);
    sshbuf_free(buf);
    ଯଦି (ret != 0) ଫେରନ୍ତୁ 0;

    // Fuzz serailisation roundtrip
    ସଂରଚନା sshbuf *output = sshbuf_new();
    ସଂରଚନା ssh_krl *krl2 = ଖାଲି;
    ssh_krl_to_blob(krl, output);
    ssh_krl_from_blob(output, &krl2);
    ssh_krl_free(krl2);
    sshbuf_free(output);

    // Fuzz krl_dump
    krl_dump(krl, null_file);

    // Fuzz ssh_krl_check_key
    ssh_krl_check_ଚାବି(krl, ଚାବି);

    ssh_krl_free(krl);
    ଫେରନ୍ତୁ 0;
}
