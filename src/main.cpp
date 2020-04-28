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

    alice->current_device->correspondents[bob->userid] = bob;
    bob->current_device->correspondents[alice->userid] = alice;

    QJsonArray msg = alice->encrypt_message(bob->userid, "Gothenburg, Sweden");

    for(int i =0 ;i < msg.size(); i++)
    {
        std::cout << bob->decrypt_message(QJsonDocument(msg[i].toObject())) << std::endl;
    }


    return 0;
}
