#ifndef USER_H
#define USER_H

#include "device.h"
#include <map>
#include <QJsonArray>

class Device;
class User
{
public:
    //Each user has a UserID (e.g. a username or phone number).
    long long int userid;
    //Each UserRecord contains a set of DeviceRecords, indexed by DeviceID.
    std::map<long long int, Device*> devices;
    long long current_device_id;

    User();

    QJsonArray encrypt_message(long long receiver_userid, const std::string & plaintext);
    std::string decrypt_message(const QJsonDocument & encrypted_message);

    void init_new_device();
private:
    long long get_new_device_id();
};

#endif
