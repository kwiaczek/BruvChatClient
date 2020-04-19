#include "chatwindow.h"
#include <QApplication>
#include <sodium.h>
#include <iostream>
#include "user.h"
#include "utils.h"
#include "crypto.h"

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
    User * bob = new User();

    alice->devices[0]->correspondents[0] = bob;
    bob->devices[0]->correspondents[0] = alice;


    X25519 ephemeral;
    ephemeral.generate();

    X3DH  alice_x3dh;
    X3DH  bob_x3dh;

    alice_x3dh.initiate(alice->devices[0], alice->devices[0]->correspondents[0]->devices[0], ephemeral);
    bob_x3dh.sync(bob->devices[0]->correspondents[0]->devices[0], bob->devices[0], ephemeral);

    DoubleRatchet * alice_ratchet = new DoubleRatchet();
    DoubleRatchet * bob_ratchet = new DoubleRatchet();
    bob_ratchet->initalize(bob_x3dh);

    QJsonObject msg_bob = bob_ratchet->encrypt("hello there, my guy!");
    QJsonObject msg_bob2 = bob_ratchet->encrypt("hello there, my guy!");
    std::cout << QJsonDocument(msg_bob).toJson().toStdString() << std::endl;
    std::cout << QJsonDocument(msg_bob2).toJson().toStdString() << std::endl;

    alice_ratchet->sync(alice_x3dh, bob_ratchet->self);
    auto decrypted = alice_ratchet->decrypt(QJsonDocument(msg_bob));
    auto decrypted2 = alice_ratchet->decrypt(QJsonDocument(msg_bob2));
    std::cout << std::string(decrypted.begin(), decrypted.end()) << std::endl;
    std::cout << std::string(decrypted2.begin(), decrypted2.end()) << std::endl;

    QJsonObject msg_alice = alice_ratchet->encrypt("hello there, my guy!");
    QJsonObject msg_alice2 = alice_ratchet->encrypt("hello there, my guy!");

    auto decrypted3 = bob_ratchet->decrypt(QJsonDocument(msg_alice));
    auto decrypted4 = bob_ratchet->decrypt(QJsonDocument(msg_alice2));
    std::cout << std::string(decrypted3.begin(), decrypted3.end()) << std::endl;
    std::cout << std::string(decrypted4.begin(), decrypted4.end()) << std::endl;

    return 0;
}
