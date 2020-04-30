#include <iostream>
#include "user.h"
#include "device.h"

QJsonObject Device::encryptMessage(Device *receiver, const std::string &plaintext)
{
    if(current_session == nullptr)
    {
        //create new session
        long long new_current_session_id = receiver->get_new_session_id();
        receiver->current_session = new Session();
        receiver->current_session->sessionid = new_current_session_id;
        receiver->sessions[new_current_session_id] = receiver->current_session;
    }
    QJsonObject device_json;
    device_json.insert("sender_deviceid", deviceid);
    device_json.insert("receiver_deviceid", receiver->deviceid);
    device_json.insert("session", receiver->current_session->encryptMessage(this, receiver, plaintext));

    return device_json;
}

std::string Device::decryptMessage(Device *sender, const QJsonDocument &encrypted_message)
{
    long long session_id = encrypted_message["session"].toObject()["sessionid"].toInt();
    //if nullptr there was not such session, we shall create one!
    if(sender->check_if_got_session_id(session_id))
    {
        sender->current_session = sender->sessions[session_id];
    }
    else if(sender->current_session == nullptr)
    {
        //create new session
        sender->current_session = new Session();
        sender->current_session->sessionid = session_id;
        sender->sessions[session_id] = sender->current_session;
    }


    return sender->current_session->decryptMessage(sender,this, QJsonDocument(encrypted_message["session"].toObject()));
}

Device::Device()
{
    deviceid = 0;
    current_session = nullptr;

    //generate identity key
    identity_key.ed25519_keypair.generate();
    identity_key.x25519_keypair.derive_from_ed25519(identity_key.ed25519_keypair);

    //generate signed pre key
    signed_prekey.ed25519_keypair.generate();
    signed_prekey.x25519_keypair.derive_from_ed25519(signed_prekey.ed25519_keypair);
    signed_prekey.signature = create_signature(identity_key.ed25519_keypair, signed_prekey.x25519_keypair.public_key);
}

QJsonObject Device::toJson(int serialization_type)
{
    QJsonObject obj;
    obj.insert("serialization_type", serialization_type);
    obj.insert("deviceid", deviceid);
    obj.insert("identity_key", identity_key.toJson(serialization_type));
    obj.insert("signed_prekey", signed_prekey.toJson(serialization_type));

    if(serialization_type == DEVICE_PRIVATE_REMOTE)
    {
        QJsonArray sessions_arrays_json;
        for(auto it = sessions.begin(); it != sessions.end(); it++)
        {
            QJsonObject session_json;
            session_json.insert("index", it->first);
            session_json.insert("session", it->second->toJson());
            sessions_arrays_json.append(session_json);
        }
        obj.insert("sessions", sessions_arrays_json);
    }


    if(serialization_type == DEVICE_PRIVATE)
    {
        QJsonArray correspondes_array_json;
        for(auto it = correspondents.begin(); it != correspondents.end(); it++)
        {
            QJsonObject correspondents_json;
            correspondents_json.insert("index", it->first);
            correspondents_json.insert("user", it->second->toJson(USER_PRIVATE_REMOTE));
            correspondes_array_json.append(correspondents_json);
        }
        obj.insert("correspondents", correspondes_array_json);
    }

    return  obj;
}

void Device::parseJson(const QJsonDocument &serialized_data)
{
    int serialization_type = serialized_data["serialization_type"].toInt();


    identity_key.parseJson(QJsonDocument(serialized_data["identity_key"].toObject()));
    signed_prekey.parseJson(QJsonDocument(serialized_data["signed_prekey"].toObject()));
    deviceid = serialized_data["deviceid"].toInt();

    if(serialization_type == DEVICE_PRIVATE_REMOTE)
    {
        QJsonArray sessions_array_json = serialized_data["sessions"].toArray();
        for(int i = 0; i < sessions_array_json.size(); i++)
        {
            QJsonObject session_json = sessions_array_json[i].toObject();
            sessions[session_json["index"].toInt()] = new Session();
            sessions[session_json["index"].toInt()]->parseJson(QJsonDocument(session_json["session"].toObject()));
        }
    }

    if(serialization_type == DEVICE_PRIVATE)
    {
        QJsonArray correspondes_array_json = serialized_data["correspondents"].toArray();
        for(int i = 0; i < correspondes_array_json.size(); i++)
        {
            QJsonObject correspondent_json =  correspondes_array_json[i].toObject();
            correspondents[correspondent_json["index"].toInt()] = new User();
            correspondents[correspondent_json["index"].toInt()]->parseJson(QJsonDocument(correspondent_json["user"].toObject()));
        }
    }

}

long long Device::get_new_session_id()
{
    // for now find highest sessionid and increment it
    long long max_session_id = 0;
    for(auto it = sessions.begin(); it != sessions.end(); it++)
    {
        max_session_id = std::max(max_session_id, it->first);
    }
    max_session_id++;
    return  max_session_id;
}

bool Device::check_if_got_session_id(long long id)
{
    for(auto it = sessions.begin(); it != sessions.end(); it++)
    {
        if(it->first == id)
        {
            return  true;
        }
    }
    return false;
}
