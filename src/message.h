#ifndef MESSAGE_H
#define MESSAGE_H
#include <QJsonDocument>
#include "x25519.h"

class MessageHeader{
public:
    //double ratchet
    X25519 self;
    long long tx_counter;
    long long tx_previous;
    std::vector<unsigned char> nonce;
    //X3DH
    X25519 ephemeral;

    void parseJson(const QJsonDocument & header_json);
    QJsonObject toJson();
    std::vector<unsigned char> toJsonBytes();
};

class Message{
public:
    virtual void parseJson(const QJsonDocument &) = 0;
    virtual QJsonObject toJson() = 0;
};

class EncryptedMessage : public Message{
public:
    MessageHeader header;
    std::vector<unsigned char> ciphertext;

    void parseJson(const QJsonDocument &) override;
    QJsonObject toJson() override;
};

class DecryptedMessage: public Message
{
public:
    std::vector<unsigned char> plaintext;

    std::string getString();
    void parseJson(const QJsonDocument &) override;
    QJsonObject toJson() override;
};

#endif // MESSAGE_H
