#ifndef DEVICE_H
#define DEVICE_H
#include "session.h"
#include "crypto.h"
#include <map>

class User;
class Session;
class Device
{
public:
    //Each device has a DeviceID which is unique for the UserID.
    long long int deviceid;
    //Each device stores a set of UserRecords for its correspondents, indexed by UserID.
    std::map<long long int, User*> correspondents;
    //There is some SessionID which uniquely identifies each session
    std::map<long long int, Session*> sessions;

    IdentityKey identity_key;
    SignedPreKey signed_prekey;

    Device();
};

#endif
