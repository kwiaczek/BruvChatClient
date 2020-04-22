#include "message.h"
#include "utils.h"

void MessageHeader::parseJson(const QJsonDocument &header_json)
{
    self.parseJson(QJsonDocument(header_json["self"].toObject()));
    ephemeral.parseJson(QJsonDocument(header_json["ephemeral"].toObject()));
    tx_counter = header_json["tx_counter"].toInt();
    tx_previous = header_json["tx_previous"].toInt();
    nonce = base64QStringToBytes(header_json["nonce"].toString());
}

QJsonObject MessageHeader::toJson()
{
    QJsonObject h;
    h.insert("tx_counter", tx_counter);
    h.insert("tx_previous", tx_previous);
    h.insert("nonce", bytesToBase64qstring(nonce));
    h.insert("self", self.toJson(X25519_PUBLIC));
    h.insert("ephemeral", ephemeral.toJson(X25519_PUBLIC));
    return h;
}

std::vector<unsigned char> MessageHeader::toJsonBytes()
{
    std::string json_string = QJsonDocument(toJson()).toJson().toStdString();
    std::vector<unsigned char> json_bytes(json_string.begin(), json_string.end());
    return  json_bytes;
}

std::string DecryptedMessage::getString()
{
    std::string plaintext_string(plaintext.begin(), plaintext.end());
    return  plaintext_string;
}

void DecryptedMessage::parseJson(const QJsonDocument & decrypted_message)
{
    plaintext = base64QStringToBytes(decrypted_message["plaintext"].toString());
}

QJsonObject DecryptedMessage::toJson()
{
    QJsonObject decrypted_message_json;
    decrypted_message_json.insert("message_type", "decrypted");
    decrypted_message_json.insert("plaintext", bytesToBase64qstring(plaintext));
    return decrypted_message_json;
}

void EncryptedMessage::parseJson(const QJsonDocument & encrypted_message)
{
    header.parseJson(QJsonDocument(encrypted_message["header"].toObject()));
    ciphertext = base64QStringToBytes(encrypted_message["ciphertext"].toString());
}

QJsonObject EncryptedMessage::toJson()
{
    QJsonObject encrypted_message_json;
    encrypted_message_json.insert("message_type", "encrypted");
    encrypted_message_json.insert("header", header.toJson());
    encrypted_message_json.insert("ciphertext", bytesToBase64qstring(ciphertext));
    return encrypted_message_json;
}
