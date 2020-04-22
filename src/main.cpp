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
    User * bob = new User();

    alice->devices[0]->correspondents[0] = bob;
    alice->devices[0]->correspondents[0]->devices[0] = bob->devices[0];
    alice->devices[0]->correspondents[0]->devices[0]->sessions[0] = new Session();
    alice->devices[0]->correspondents[0]->devices[0]->sessions[0]->double_ratchet = new DoubleRatchet(alice->devices[0], bob->devices[0]);

    bob->devices[0]->correspondents[0] = alice;
    bob->devices[0]->correspondents[0]->devices[0] = alice->devices[0];
    bob->devices[0]->correspondents[0]->devices[0]->sessions[0] = new Session();
    bob->devices[0]->correspondents[0]->devices[0]->sessions[0]->double_ratchet = new DoubleRatchet(bob->devices[0], alice->devices[0]);

    EncryptedMessage x = alice->devices[0]->correspondents[0]->devices[0]->sessions[0]->double_ratchet->encrypt("plaintext");
    EncryptedMessage y = alice->devices[0]->correspondents[0]->devices[0]->sessions[0]->double_ratchet->encrypt("plaintext");
    EncryptedMessage z = alice->devices[0]->correspondents[0]->devices[0]->sessions[0]->double_ratchet->encrypt("plaintext");
    DecryptedMessage w = bob->devices[0]->correspondents[0]->devices[0]->sessions[0]->double_ratchet->decrypt(x);
    DecryptedMessage s = bob->devices[0]->correspondents[0]->devices[0]->sessions[0]->double_ratchet->decrypt(y);
    DecryptedMessage v = bob->devices[0]->correspondents[0]->devices[0]->sessions[0]->double_ratchet->decrypt(z);
    std::cout << w.getString() << std::endl;
    std::cout << s.getString() << std::endl;
    std::cout << v.getString() << std::endl;

    return 0;
}
