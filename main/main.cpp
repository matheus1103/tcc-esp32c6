// main.cpp
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "mylib.h"

// Define uma tag para log
static const char *TAG = "MainApp";

// Defina a função principal do ESP-IDF
extern "C" void app_main() {
    const unsigned int RSA_KEY_SIZE = 4096;
    const int RSA_EXPONENT = 65537;

    ESP_LOGI(TAG, "Iniciando o projeto com MyLib...");

    MyLib myLib;
    myLib.mbedtls_init(Algorithms::RSA);

    myLib.mbedtls_gen_keys(RSA_KEY_SIZE, RSA_EXPONENT);

    // Alocando dinamicamente a chave pública
    char *pub_key_buffer = (char *)malloc(4096);
    if (pub_key_buffer == nullptr) {
        ESP_LOGE(TAG, "Falha ao alocar memória para a chave pública");
        return;
    }

    myLib.mbedtls_get_pub_key(pub_key_buffer, 4096);
    ESP_LOGI(TAG, "Chave pública:\n%s", pub_key_buffer);
    free(pub_key_buffer);

    // Assinatura e verificação
    const char *message = "Mensagem de exemplo para assinatura";
    unsigned char signature_buffer[512];
    size_t signature_length;
    myLib.mbedtls_sign(message, signature_buffer, &signature_length);
    ESP_LOGI(TAG, "Assinatura gerada com sucesso!");

    myLib.mbedtls_verify(message, signature_buffer, signature_length);
    ESP_LOGI(TAG, "Verificação de assinatura concluída.");

    myLib.mbedtls_close();
    ESP_LOGI(TAG, "Recursos mbedtls liberados.");

    while (true) {
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}
