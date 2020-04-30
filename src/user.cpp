#include "user.h"
#include <iostream>
User::User()
{
    userid = 0;
    current_device = nullptr;
}

//given a userid, function will encrypt copy for every devices of the user, as well copy for every device for the remote user
QJsonArray User::encrypt_message(long long receiver_userid, const std::string &plaintext)
{
    QJsonArray messages;

    QJsonObject encrypted_message_json;
    encrypted_message_json.insert("sender_userid", userid);
    encrypted_message_json.insert("receiver_userid", receiver_userid);

    //internal messages
    for(auto it = devices.begin(); it != devices.end(); it++)
    {
        QJsonObject tmp = encrypted_message_json;
        tmp.insert("type", "interal");

        if(it->second != current_device)
        {
            tmp.insert( "device", it->second->encryptMessage(it->second, plaintext));
            messages.append(tmp);
        }
    }

    //external messages
    for(auto it = current_device->correspondents[receiver_userid]->devices.begin(); it != current_device->correspondents[receiver_userid]->devices.end(); it++)
    {
        QJsonObject tmp = encrypted_message_json;
        tmp.insert("type", "external");
        tmp.insert( "device", current_device->encryptMessage(it->second, plaintext));
        messages.append(tmp);
    }
    return messages;
}

std::string User::decrypt_message(const QJsonDocument &encrypted_message)
{
    QString type = encrypted_message["type"].toString();
    long long sender_deviceid = QJsonDocument(encrypted_message["device"].toObject())["sender_deviceid"].toInt();
    long long sender_userid  = encrypted_message["sender_userid"].toInt();

    std::string plaintext = "";
    if(type == "external")
    {
        Device * sender = current_device->correspondents[sender_userid]->devices[sender_deviceid];
        plaintext = current_device->decryptMessage(sender, QJsonDocument(encrypted_message["device"].toObject()));
    }
    else if(type == "internal")
    {
        Device * sender = current_device->correspondents[userid]->devices[sender_deviceid];
        plaintext = current_device->decryptMessage(sender, QJsonDocument(encrypted_message["device"].toObject()));

    }
    return plaintext;
}

void User::init_new_device()
{
    long long new_device_id = get_new_device_id();
    devices[new_device_id] = new Device();
    devices[new_device_id]->deviceid = new_device_id;
    current_device =  devices[new_device_id];
}

long long User::get_new_device_id()
{
    long long max_device_id = 0;
    for(auto it = devices.begin(); it != devices.end(); it++)
    {
        max_device_id = std::max(max_device_id, it->first);
    }
    max_device_id++;
    return  max_device_id;
}
