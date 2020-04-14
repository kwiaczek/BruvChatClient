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

    User * alice = new User();
    User * bob = new User();

    alice->devices[0]->correspondents[0] = bob;
    bob->devices[0]->correspondents[0] = alice;


    X25519 ephemeral;
    ephemeral.generate();

    X3DH * alice_x3dh = new X3DH();
    X3DH * bob_x3dh = new X3DH();

    alice_x3dh->initiate(alice->devices[0], alice->devices[0]->correspondents[0]->devices[0], ephemeral);
    bob_x3dh->recreate(bob->devices[0]->correspondents[0]->devices[0], bob->devices[0], ephemeral);

    printVecBase64(alice_x3dh->rx);
    printVecBase64(bob_x3dh->tx);


    return 0;
}
