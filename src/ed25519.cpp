#include "ed25519.h"
#include "utils.h"
Ed25519::Ed25519()
{
    public_key.reserve(crypto_sign_PUBLICKEYBYTES);
    public_key.resize(crypto_sign_PUBLICKEYBYTES);
    secret_key.reserve(crypto_sign_SECRETKEYBYTES);
    secret_key.resize(crypto_sign_SECRETKEYBYTES);
}

void Ed25519::generate()
{
    crypto_sign_keypair(public_key.data(), secret_key.data());
}

QJsonObject Ed25519::toJson(int serialization_type)
{
    QJsonObject tmp;
    tmp.insert("serialization_type", serialization_type);
    tmp.insert("public", bytesToBase64qstring(public_key));

    if(serialization_type == ED25519_PRIVATE)
    {
        tmp.insert("private", bytesToBase64qstring(secret_key));
    }
    return tmp;
}

void Ed25519::parseJson(const QJsonDocument &obj)
{
    int serialization_type = obj["serialization_type"].toInt();

    std::vector<unsigned char> json_pub = base64QStringToBytes(obj["public"].toString());
    std::copy(json_pub.begin(), json_pub.end(), public_key.begin());

    if(serialization_type == ED25519_PRIVATE)
    {
        std::vector<unsigned char> json_prv = base64QStringToBytes(obj["private"].toString());
        std::copy(json_prv.begin(), json_prv.end(), secret_key.begin());
    }
}
