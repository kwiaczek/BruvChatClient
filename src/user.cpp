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


QJsonObject User::toJson(int serialization_type)
{
    QJsonObject obj;
    obj.insert("serialization_type", serialization_type);
    obj.insert("userid", userid);
    if(current_device != nullptr)
    {
        obj.insert("current_device", current_device->toJson(serialization_type));
    }
    if(serialization_type != USER_PUBLIC)
    {
        QJsonArray devices_json;
        for(auto it = devices.begin(); it != devices.end(); it++)
        {
            QJsonObject device_obj_json;
            device_obj_json.insert("index", it->first);
            device_obj_json.insert("device", it->second->toJson(serialization_type));
            devices_json.append(device_obj_json);
        }
        obj.insert("devices", devices_json);
    }
    return obj;
}

void User::parseJson(const QJsonDocument & serialized_data)
{
    int serialization_type = serialized_data["serialization_type"].toInt();
    userid = serialized_data["userid"].toInt();
    if(serialized_data["current_device"] != QJsonValue::Undefined)
    {
        current_device = new Device();
        current_device->parseJson(QJsonDocument(serialized_data["current_device"].toObject()));
    }
    QJsonArray devices_array_json = serialized_data["devices"].toArray();
    for(int i =0; i <devices_array_json.size(); i++)
    {
        QJsonObject devices_json_obj = devices_array_json[i].toObject();
        devices[devices_json_obj["index"].toInt()] = new Device();
        devices[devices_json_obj["index"].toInt()]->parseJson(QJsonDocument(devices_json_obj["device"].toObject()));
    }
}

