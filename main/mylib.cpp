#include "mylib.h"
#include <mbedtls/platform.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/error.h>
#include <string.h>
#include "esp_spiffs.h"
#include "esp_log.h"

#define ED25519_KEY_SIZE 32
#define ED25519_SIG_SIZE 64
#define RSA_KEY_SIZE 2048
#define RSA_EXPONENT 65537

static const char *TAG = "MyLib";

const char* MyLib::pers = "personalized_data";

MyLib::MyLib() {}

void MyLib::mbedtls_init(Algorithms a) {
    ESP_LOGI(TAG, "Initializing mbedtls...");

    // Inicializar SPIFFS usando a API do ESP-IDF
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = NULL,
        .max_files = 5,
        .format_if_mount_failed = true
    };

    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            ESP_LOGE(TAG, "Failed to mount or format SPIFFS");
        } else if (ret == ESP_ERR_NOT_FOUND) {
            ESP_LOGE(TAG, "SPIFFS partition not found");
        } else {
            ESP_LOGE(TAG, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
        }
        return;
    }

    chosen_algorithm = a;

    mbedtls_pk_type_t pk_type = MBEDTLS_PK_NONE;
    if (chosen_algorithm == Algorithms::RSA) {
        pk_type = MBEDTLS_PK_RSA;
    } else if (chosen_algorithm == Algorithms::ECDSA_BP256R1 || chosen_algorithm == Algorithms::ECDSA_SECP256R1) {
        pk_type = MBEDTLS_PK_ECKEY;
    }

    if (pk_type == MBEDTLS_PK_NONE) {
        ESP_LOGE(TAG, "Invalid algorithm type");
        return;
    }

    ESP_LOGI(TAG, "Seeding the RNG...");

    mbedtls_pk_init(&pk_ctx);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed seeding the RNG");
        return;
    }

    ESP_LOGI(TAG, "Setting up pk context with chosen type...");

    ret = mbedtls_pk_setup(&pk_ctx, mbedtls_pk_info_from_type(pk_type));
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed setting up pk context");
        return;
    }

    ESP_LOGI(TAG, "Initialization complete");
}

void MyLib::mbedtls_gen_keys() {
    int ret;

    switch (chosen_algorithm) {
        case ECDSA_BP256R1:
            ESP_LOGI(TAG, "Generating the key pair with curve BP256R1...");

            ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_BP256R1, mbedtls_pk_ec(pk_ctx), mbedtls_ctr_drbg_random, &ctr_drbg);
            if (ret != 0) {
                ESP_LOGE(TAG, "Failed generating the key pair");
            }
            break;
        case ECDSA_SECP256R1:
            ESP_LOGI(TAG, "Generating the key pair with curve SECP256R1...");

            ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk_ctx), mbedtls_ctr_drbg_random, &ctr_drbg);
            if (ret != 0) {
                ESP_LOGE(TAG, "Failed generating the key pair");
            }
            break;
        case ECDSA_CURVE25519:
            ESP_LOGI(TAG, "Generating the key pair with curve 25519...");

            ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_CURVE25519, mbedtls_pk_ec(pk_ctx), mbedtls_ctr_drbg_random, &ctr_drbg);
            if (ret != 0) {
                ESP_LOGE(TAG, "Failed generating the key pair");
            }
            break;
        case EDDSA_25519:
            ESP_LOGI(TAG, "Generating the key pair with EDDSA curve 25519...");

            // Adicione aqui o código para gerar a chave EDDSA 25519, se aplicável
            ESP_LOGE(TAG, "EDDSA 25519 key generation not implemented");
            break;
        case EDDSA_448:
            ESP_LOGI(TAG, "Generating the key pair with EDDSA curve 448...");

            // Adicione aqui o código para gerar a chave EDDSA 448, se aplicável
            ESP_LOGE(TAG, "EDDSA 448 key generation not implemented");
            break;
        case RSA:
            ESP_LOGI(TAG, "Generating the RSA key pair...");
            mbedtls_gen_keys(RSA_KEY_SIZE, RSA_EXPONENT);
            break;
    }
}

void MyLib::mbedtls_gen_keys(unsigned int rsa_key_size, int rsa_exponent) {
    ESP_LOGI(TAG, "Generating the RSA key pair...");
    mbedtls_rsa_key_size = rsa_key_size;

    int ret;
    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk_ctx), mbedtls_ctr_drbg_random, &ctr_drbg, mbedtls_rsa_key_size, rsa_exponent);
    if (ret != 0) {
        ESP_LOGE(TAG, "Error when trying to generate RSA key pair");
    }
}

void MyLib::mbedtls_get_pub_key(char *buffer, const int buffer_length) {
    ESP_LOGI(TAG, "Writing public key PEM...");

    int ret;
    ret = mbedtls_pk_write_pubkey_pem(&pk_ctx, (unsigned char *)buffer, buffer_length);
    if (ret != 0) {
        mbedtls_strerror(ret, buffer, buffer_length);
        ESP_LOGE(TAG, "%s", buffer);
    }
}

void MyLib::mbedtls_sign(const char *message, unsigned char *signature_buffer, size_t *signature_length) {
    ESP_LOGI(TAG, "Hashing the message...");

    const size_t hash_len = 32;
    unsigned char hash[hash_len];
    mbedtls_sha256((const unsigned char *)message, strlen(message), hash, 0);

    ESP_LOGI(TAG, "Signing the message hash...");

    int ret;
    ret = mbedtls_pk_sign(&pk_ctx, MBEDTLS_MD_SHA256, hash, hash_len, signature_buffer, mbedtls_get_signature_size(), signature_length, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed signing the message hash");
    }
}

void MyLib::mbedtls_verify(const char *message, unsigned char *signature_buffer, size_t signature_length) {
    ESP_LOGI(TAG, "Hashing message to be verified...");

    const size_t hash_len = 32;
    unsigned char hash_to_verify[hash_len];
    mbedtls_sha256((const unsigned char *)message, strlen(message), hash_to_verify, 0);

    ESP_LOGI(TAG, "Verifying the signature...");

    int ret;
    ret = mbedtls_pk_verify(&pk_ctx, MBEDTLS_MD_SHA256, hash_to_verify, hash_len, signature_buffer, signature_length);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed verifying the signature");
    } else {
        ESP_LOGI(TAG, "Signature verified successfully");
    }
}

void MyLib::save_pub_key(const char *pubkey_filename, char *public_key_pem, const int buffer_length) {
    ESP_LOGI(TAG, "Saving public key PEM...");

    // Construir o caminho completo
    char filepath[128];
    snprintf(filepath, sizeof(filepath), "/spiffs/%s", pubkey_filename);

    FILE *file = fopen(filepath, "w");
    if (!file) {
        ESP_LOGE(TAG, "Failed to open the public key file for writing");
        return;
    }

    size_t bytes_written = fwrite(public_key_pem, 1, buffer_length, file);
    if (bytes_written != buffer_length) {
        ESP_LOGE(TAG, "Error writing to the public key file");
    }

    fclose(file);
}

std::string MyLib::load_pub_key(const char *pubkey_filename) {
    ESP_LOGI(TAG, "Loading public key PEM...");

    // Construir o caminho completo
    char filepath[128];
    snprintf(filepath, sizeof(filepath), "/spiffs/%s", pubkey_filename);

    FILE *file = fopen(filepath, "r");
    if (!file) {
        ESP_LOGE(TAG, "Failed to open the public key file");
        return "error";
    }

    std::string public_key_pem;
    char buffer[64];
    while (fgets(buffer, sizeof(buffer), file)) {
        public_key_pem += buffer;
    }
    fclose(file);

    return public_key_pem;
}

int MyLib::mbedtls_get_signature_size() {
    return chosen_algorithm == Algorithms::RSA ? mbedtls_rsa_key_size : mbedtls_ecdsa_sig_max_len;
}

Algorithms MyLib::get_chosen_algorithm() {
    return chosen_algorithm;
}

void MyLib::mbedtls_close() {
    ESP_LOGI(TAG, "Cleaning up mbedtls resources...");
    mbedtls_pk_free(&pk_ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}
