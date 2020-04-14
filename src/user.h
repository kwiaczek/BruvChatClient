#ifndef USER_H
#define USER_H

#include "device.h"
#include <map>

class Device;
class User
{
public:
    //Each user has a UserID (e.g. a username or phone number).
    long long int userid;
    //Each UserRecord contains a set of DeviceRecords, indexed by DeviceID.
    //Index 0 is used for current device
    std::map<long long int, Device*> devices;
    User();
};

#endif
