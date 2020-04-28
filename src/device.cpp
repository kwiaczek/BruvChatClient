#include <iostream>
#include "user.h"
#include "device.h"

QJsonObject Device::encryptMessage(Device *receiver, const std::string &plaintext)
{
    if(current_session == nullptr)
    {
        //create new session
        long long new_current_session_id = get_new_session_id();
        current_session = new Session();
        current_session->sessionid = new_current_session_id;
        sessions[new_current_session_id] = current_session;
    }
    QJsonObject device_json;
    device_json.insert("sender_deviceid", deviceid);
    device_json.insert("receiver_deviceid", receiver->deviceid);
    device_json.insert("session", current_session->encryptMessage(this, receiver, plaintext));

    return device_json;
}

std::string Device::decryptMessage(Device *sender, const QJsonDocument &encrypted_message)
{
    long long session_id = encrypted_message["session"].toObject()["sessionid"].toInt();
    //if nullptr there was not such session, we shall create one!
    if(check_if_got_session_id(session_id))
    {
        current_session = sessions[session_id];
    }
    else if(current_session == nullptr)
    {
        //create new session
        current_session = new Session();
        current_session->sessionid = session_id;
        sessions[session_id] = current_session;
    }

    return current_session->decryptMessage(sender, this, QJsonDocument(encrypted_message["session"].toObject()));
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
