// libfuzzer driver for krl parse fuzzing.

#ضمن <stddef.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <stdlib.h>
#ضمن <stdio.h>

خارجي "C" {
#ضمن "includes.h"
#ضمن "sshkey.h"
#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "krl.h"
#ضمن "log.h"
#ضمن "authfile.h"
}

ساكن صحيح initialised = 0;
ساكن FILE *null_file;
ساكن بنية sshkey *key = عدم;

خارجي "C" صحيح LLVMFuzzerTestOneInput(ثابت uint8_t *data, size_t size) {
    // single initialisation
    𐤀𐤌 (!initialised) {
        log_init("krl_fuzz", SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTH, 0);

        𐤀𐤌 ((null_file = fopen("/dev/null", "w")) == عدم) أرجع 0;

        𐤀𐤌 (sshkey_generate(KEY_ED25519, 0, &key) != 0) أرجع 0;

        initialised = 1;
    }

    // Reject empty corpus
    𐤀𐤌 (size < 4) أرجع 0;

    // Convert fuzzer data to ssh buffer
    بنية sshbuf *buf = sshbuf_from(data, size);
    𐤀𐤌 (!buf) أرجع 0;

    // Parse the ssh buffer as krl, early exit if failed
    بنية ssh_krl *krl = عدم;
    صحيح ret = ssh_krl_from_blob(buf, &krl);
    sshbuf_free(buf);
    𐤀𐤌 (ret != 0) أرجع 0;

    // Fuzz serailisation roundtrip
    بنية sshbuf *output = sshbuf_new();
    بنية ssh_krl *krl2 = عدم;
    ssh_krl_to_blob(krl, output);
    ssh_krl_from_blob(output, &krl2);
    ssh_krl_free(krl2);
    sshbuf_free(output);

    // Fuzz krl_dump
    krl_dump(krl, null_file);

    // Fuzz ssh_krl_check_key
    ssh_krl_check_key(krl, key);

    ssh_krl_free(krl);
    أرجع 0;
}
