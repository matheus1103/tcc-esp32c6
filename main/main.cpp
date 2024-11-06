#include "mylib.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

static const char *TAG = "Main";

void generate_100_keys(MyLib &mylib) {
    for (int i = 0; i < 100; ++i) {
        mylib.mbedtls_gen_keys();
    }
}

extern "C" void app_main() {
    MyLib mylib;
    mylib.mbedtls_init(Algorithms::RSA);
    generate_100_keys(mylib);
    mylib.mbedtls_close();
}
