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

    X3DH  alice_x3dh;
    X3DH  bob_x3dh;

    alice_x3dh.initiate(alice->devices[0], alice->devices[0]->correspondents[0]->devices[0], ephemeral);
    bob_x3dh.recreate(bob->devices[0]->correspondents[0]->devices[0], bob->devices[0], ephemeral);

    DoubleRatchet * double_ratchet_alice = new DoubleRatchet();
    double_ratchet_alice->initalize(alice_x3dh);


    DoubleRatchet * double_ratchet_bob = new DoubleRatchet();
    double_ratchet_bob->initalize(bob_x3dh);

    std::cout << "ALICE PERFORM" << std::endl;
    double_ratchet_alice->initalizeRatchetStep();
    std::cout << "Alice's keys" << std::endl;
    printVecBase64(double_ratchet_alice->rx);
    printVecBase64(double_ratchet_alice->tx);
    std::cout << "BOB's keys" << std::endl;
    printVecBase64(double_ratchet_bob->rx);
    printVecBase64(double_ratchet_bob->tx);
    std::cout << "#######################" << std::endl;

    std::cout << "BOB UPDATE" << std::endl;
    double_ratchet_bob->updateRatchetStep(double_ratchet_alice->ratchet_keypair);

    std::cout << "Alice's keys" << std::endl;
    printVecBase64(double_ratchet_alice->rx);
    printVecBase64(double_ratchet_alice->tx);
    std::cout << "BOB's keys" << std::endl;
    printVecBase64(double_ratchet_bob->rx);
    printVecBase64(double_ratchet_bob->tx);

    std::cout << "#######################" << std::endl;
    std::cout << "ALICE FINALIZE" << std::endl;
    double_ratchet_alice->finalizeRatchetStep(double_ratchet_bob->ratchet_keypair);


    std::cout << "Alice's keys" << std::endl;
    printVecBase64(double_ratchet_alice->rx);
    printVecBase64(double_ratchet_alice->tx);
    std::cout << "BOB's keys" << std::endl;
    printVecBase64(double_ratchet_bob->rx);
    printVecBase64(double_ratchet_bob->tx);

    return 0;
}
