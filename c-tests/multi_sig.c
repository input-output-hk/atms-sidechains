#include <gtest/gtest.h>
extern "C" {
#include "../target/include/atms.h"
}

TEST(multisig, produceAndVerifyMultiSignature) {
    const char *msg = "some message";

    // Test with 5 parties and threshold 4.
    SigningKeyPtr sk;
    PublicKeyPoPPtr key_pop;
    PublicKeyPtr key;
    int err;

    err = atms_generate_keypair(&sk, &key_pop);
    ASSERT_EQ(err, 0);

    err = atms_pkpop_to_pk(key_pop, &key);
    ASSERT_EQ(err, 0);

    SignaturePtr sig;
    err = atms_sign(msg, sk, &sig);
    ASSERT_EQ(err, 0);

    err = atms_verify(msg, key, sig);
    ASSERT_EQ(err, 0);
}