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
    alice_ratchet->sync(alice_x3dh, bob_ratchet->self);

    return 0;
}
