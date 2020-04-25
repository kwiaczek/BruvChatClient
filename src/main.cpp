#include "chatwindow.h"
#include <QApplication>
#include <sodium.h>
#include <iostream>
#include "user.h"
#include "utils.h"
#include "crypto.h"
#include "message.h"
int main(int argc, char *argv[])
{

    //initalize sodium
    if(sodium_init() < 0)
    {
        std::cerr << "Could not initalize sodium!" << std::endl;
        return -1;
    }

    if(crypto_aead_aes256gcm_is_available() == 0)
    {
        std::cerr << "AES GCM NOT SUPPORTED!" << std::endl;
        return -1;
    }

    User * alice = new User();
    alice->userid = 1;
    alice->init_new_device();
    User * bob = new User();
    bob->userid = 2;
    bob->init_new_device();

    alice->devices[alice->current_device_id]->correspondents[bob->userid] = bob;
    bob->devices[bob->current_device_id]->correspondents[alice->userid] = alice;

    QJsonObject alice_msg_1 = alice->encrypt_message(bob->userid, "Hello this is alice, and this is my first message!")[0].toObject();
    QJsonObject alice_msg_2 = alice->encrypt_message(bob->userid, "second message")[0].toObject();
    std::cout << bob->decrypt_message(QJsonDocument(alice_msg_2)) << std::endl;
    std::cout << bob->decrypt_message(QJsonDocument(alice_msg_1)) << std::endl;
    QJsonObject bob_msg_1 = bob->encrypt_message(alice->userid, "Hello this is bob and this is my first message!")[0].toObject();
    QJsonObject bob_msg_2 = bob->encrypt_message(alice->userid, "bob second message")[0].toObject();
    std::cout << alice->decrypt_message(QJsonDocument(bob_msg_2)) << std::endl;
    std::cout << alice->decrypt_message(QJsonDocument(bob_msg_1)) << std::endl;

    return 0;
}
