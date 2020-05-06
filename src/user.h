#ifndef USER_H
#define USER_H

#include "device.h"
#include "MessageUI.h"
#include <map>
#include <QJsonArray>

enum{
    USER_PUBLIC,
    USER_PRIVATE,
    USER_PRIVATE_REMOTE
};

class Device;
class User
{
public:
    //Each user has a UserID (e.g. a username or phone number).
    long long int userid;
    //Each UserRecord contains a set of DeviceRecords, indexed by DeviceID.
    std::map<long long int, Device*> devices;
    Device * current_device;
    std::string username;
    std::string password;

    std::vector<MessageUI> messages_ui;

    User();

    QJsonObject encrypt_message(long long receiver_userid, const std::string & plaintext);
    MessageUI decrypt_message(const QJsonDocument & encrypted_message);

    QJsonObject toJson(int serialization_type);
    void parseJson(const QJsonDocument & serialized_data);
};

#endif
