#ifndef SESSION_H
#define SESSION_H
#include <vector>
#include <sodium.h>
#include "device.h"
#include "crypto.h"


class Session
{
public:
    //There is some SessionID which uniquely identifies each session
    long long int sessionid;
    DoubleRatchet * double_ratchet;

    Session();
};

#endif
