#include <iostream>
#include <psa/crypto.h>

int main() {
    std::cout << "Testing PSA crypto initialization..." << std::endl;
    
    psa_status_t status = psa_crypto_init();
    std::cout << "PSA crypto init returned: " << status << " (0x" << std::hex << status << std::dec << ")" << std::endl;
    
    if (status == PSA_SUCCESS) {
        std::cout << "PSA crypto initialized successfully!" << std::endl;
        return 0;
    } else {
        std::cout << "PSA crypto initialization failed!" << std::endl;
        return 1;
    }
}