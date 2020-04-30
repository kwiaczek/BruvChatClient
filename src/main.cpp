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
    alice->current_device = new Device();
    alice->current_device->deviceid = 1;
    User * bob = new User();
    bob->userid = 2;
    bob->devices[1] = new Device();
    bob->devices[1]->deviceid = 1;
    alice->current_device->correspondents[bob->userid] = bob;

    alice->encrypt_message(bob->userid, "text");

    QJsonDocument doc =  QJsonDocument(alice->toJson(USER_PRIVATE));

    std::cout << doc.toJson().toStdString() << std::endl;

    User new_user;
    new_user.parseJson(doc);
    doc = QJsonDocument(new_user.toJson(USER_PRIVATE));
    std::cout << doc.toJson().toStdString() << std::endl;




    return 0;
}
