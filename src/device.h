#ifndef DEVICE_H
#define DEVICE_H
#include "session.h"
#include "crypto.h"
#include <map>


enum {
    DEVICE_PUBLIC,
    DEVICE_PRIVATE,
    DEVICE_PRIVATE_REMOTE
};

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
    Session * current_session;

    IdentityKey identity_key;
    SignedPreKey signed_prekey;


    QJsonObject encryptMessage(Device * receiver, const std::string & plaintext);

    std::string decryptMessage(Device * sender, const QJsonDocument & encrypted_message);

    Device();

    QJsonObject toJson(int serialization_type);
    void parseJson(const QJsonDocument & serialized_data);
private:
    long long get_new_session_id();

    bool check_if_got_session_id(long long id);
};

#endif
