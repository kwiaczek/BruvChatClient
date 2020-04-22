#include "session.h"
#include "utils.h"
#include <iostream>
#include <QByteArray>

Session::Session()
{
}

void Session::createSession(Device *sender, Device *receiver)
{
    double_ratchet = new DoubleRatchet();

    double_ratchet->init_device = sender;
    double_ratchet->sync_device = receiver;
}


