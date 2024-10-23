#ifndef MYLIB
#define MYLIB

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <string>

enum Algorithms {
  RSA,
  ECDSA_BP256R1,
  ECDSA_SECP256R1,
  ECDSA_CURVE25519,
  EDDSA_25519,
  EDDSA_448
};

class MyLib {
  public:
    MyLib();
    void mbedtls_init(Algorithms a);
    void mbedtls_close();
    void mbedtls_gen_keys();
    void mbedtls_gen_keys(unsigned int rsa_key_size, int rsa_exponent);
    void mbedtls_get_pub_key(char * buffer, const int buffer_length);
    void mbedtls_sign(const char * message, unsigned char * signature_buffer, size_t * signature_length);
    void mbedtls_verify(const char * message, unsigned char * signature_buffer, size_t signature_length);
    void save_pub_key(const char * pubkey_filename, char * public_key_pem, const int buffer_length);
    std::string load_pub_key(const char * pubkey_filename);
    int mbedtls_get_signature_size();
    Algorithms get_chosen_algorithm();
  
  private:
    mbedtls_pk_context pk_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    static const char* pers;
    static const int mbedtls_ecdsa_sig_max_len = MBEDTLS_ECDSA_MAX_LEN;
    Algorithms chosen_algorithm;
    unsigned int mbedtls_rsa_key_size;
};

#endif