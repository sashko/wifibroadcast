//
// Created by consti10 on 20.04.22.
//

#include "HelperSources/Helper.hpp"

#include "WBReceiver.h"
#include "Encryption.hpp"

int main(int argc, char *const *argv) {

    WBReceiver wbReceiver(ROptions{}, nullptr);
    Encryptor encryptor{std::nullopt};
    return 0;
}