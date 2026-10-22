// libfuzzer driver for krl parse fuzzing.

#شامل <stddef.h>
#شامل <stdint.h>
#شامل <string.h>
#شامل <stdlib.h>
#شامل <stdio.h>

خارجی "C" {
#شامل "includes.h"
#شامل "sshkey.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "krl.h"
#شامل "log.h"
#شامل "authfile.h"
}

ساکن صحیح initialised = 0;
ساکن FILE *null_file;
ساکن ساخت sshkey *کلید = تہی;

خارجی "C" صحیح LLVMFuzzer_Test_One_داخلہ(ثابت uint8_t *ڈیٹا, سائز_t سائز) {
    // single initialisation
    اگر (!initialised) {
        log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

        اگر ((null_file = fopen("/dev/null", "w")) == تہی) واپس 0;

        اگر (sshkey_generate(کلید_ED25519, 0, &کلید) != 0) واپس 0;

        initialised = 1;
    }

    // Reject empty corpus
    اگر (سائز < 4) واپس 0;

    // Convert fuzzer data to ssh buffer
    ساخت sshbuf *buf = sshbuf_from(ڈیٹا, سائز);
    اگر (!buf) واپس 0;

    // Parse the ssh buffer as krl, early exit if failed
    ساخت ssh_krl *krl = تہی;
    صحیح ret = ssh_krl_from_blob(buf, &krl);
    sshbuf_free(buf);
    اگر (ret != 0) واپس 0;

    // Fuzz serailisation roundtrip
    ساخت sshbuf *output = sshbuf_new();
    ساخت ssh_krl *krl2 = تہی;
    ssh_krl_مقصد_blob(krl, output);
    ssh_krl_from_blob(output, &krl2);
    ssh_krl_free(krl2);
    sshbuf_free(output);

    // Fuzz krl_dump
    krl_dump(krl, null_file);

    // Fuzz ssh_krl_check_key
    ssh_krl_check_کلید(krl, کلید);

    ssh_krl_free(krl);
    واپس 0;
}
