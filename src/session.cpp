#include "session.h"
#include "utils.h"
#include <iostream>
#include <QByteArray>

Session::Session()
{
    double_ratchet = nullptr;
}

void Session::createSession(Device *sender, Device *receiver)
{
    double_ratchet = new DoubleRatchet();

    double_ratchet->init_device = sender;
    double_ratchet->sync_device = receiver;
}

QJsonObject Session::encryptMessage(Device *sender, Device *receiver, const std::string &plaintext)
{
    QJsonObject encrypted_message;
    //if double ratchet is not define that means that it's inital message
    if(double_ratchet == nullptr)
    {
        createSession(sender, receiver);
    }
    encrypted_message.insert("encrypted_message", double_ratchet->encrypt(plaintext).toJson());

    return  encrypted_message;
}

std::string Session::decryptMessage(Device *sender, Device *receiver, const QJsonDocument &encrypted)
{
    //if double ratchet is not define that means that it's inital message
    if(double_ratchet == nullptr)
    {
        createSession(sender, receiver);
    }


    EncryptedMessage encrypted_message;
    encrypted_message.parseJson(QJsonDocument(encrypted["encrypted_message"].toObject()));


    return double_ratchet->decrypt(encrypted_message).getString();
}
