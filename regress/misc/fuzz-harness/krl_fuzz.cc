// libfuzzer driver for krl parse fuzzing.

#شامل <stddef.h>
#شامل <stdint.h>
#شامل <string.h>
#شامل <stdlib.h>
#شامل <stdio.h>

بیرونی "C" {
#شامل "includes.h"
#شامل "sshkey.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "krl.h"
#شامل "log.h"
#شامل "authfile.h"
}

ایستا صحیح initialised = 0;
ایستا FILE *null_file;
ایستا ساختار sshkey *کلید = پوچ;

بیرونی "C" صحیح LLVMFuzzer_Test_One_درون_داد(ثابت uint8_t *data, size_t size) {
    // single initialisation
    اگر (!initialised) {
        log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

        اگر ((null_file = fopen("/dev/null", "w")) == پوچ) بازگشت 0;

        اگر (sshkey_generate(کلید_ED25519, 0, &کلید) != 0) بازگشت 0;

        initialised = 1;
    }

    // Reject empty corpus
    اگر (size < 4) بازگشت 0;

    // Convert fuzzer data to ssh buffer
    ساختار sshbuf *buf = sshbuf_from(data, size);
    اگر (!buf) بازگشت 0;

    // Parse the ssh buffer as krl, early exit if failed
    ساختار ssh_krl *krl = پوچ;
    صحیح ret = ssh_krl_from_blob(buf, &krl);
    sshbuf_free(buf);
    اگر (ret != 0) بازگشت 0;

    // Fuzz serailisation roundtrip
    ساختار sshbuf *output = sshbuf_new();
    ساختار ssh_krl *krl2 = پوچ;
    ssh_krl_to_blob(krl, output);
    ssh_krl_from_blob(output, &krl2);
    ssh_krl_free(krl2);
    sshbuf_free(output);

    // Fuzz krl_dump
    krl_dump(krl, null_file);

    // Fuzz ssh_krl_check_key
    ssh_krl_check_کلید(krl, کلید);

    ssh_krl_free(krl);
    بازگشت 0;
}
