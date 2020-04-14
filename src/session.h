#ifndef SESSION_H
#define SESSION_H
#include <vector>
#include <sodium.h>
#include "device.h"


class Session
{
public:
    //There is some SessionID which uniquely identifies each session
    long long int sessionid;

    Session();
};

#endif
