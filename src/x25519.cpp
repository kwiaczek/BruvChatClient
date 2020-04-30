#include "utils.h"
#include "x25519.h"

X25519::X25519()
{
    public_key.reserve(crypto_box_PUBLICKEYBYTES);
    public_key.resize(crypto_box_PUBLICKEYBYTES);
    secret_key.reserve(crypto_box_SECRETKEYBYTES);
    secret_key.resize(crypto_box_SECRETKEYBYTES);
}

void X25519::generate()
{
    crypto_box_keypair(public_key.data(), secret_key.data());
}

void X25519::derive_from_ed25519(Ed25519 &key)
{
    crypto_sign_ed25519_pk_to_curve25519(public_key.data(), key.public_key.data());
    crypto_sign_ed25519_sk_to_curve25519(secret_key.data(), key.secret_key.data());
}

QJsonObject X25519::toJson(int serialization_type)
{
    QJsonObject tmp;
    tmp.insert("serialization_type", serialization_type);
    tmp.insert("public", bytesToBase64qstring(public_key));

    if(serialization_type == X25519_PRIVATE)
    {
        tmp.insert("private", bytesToBase64qstring(secret_key));
    }
    return tmp;
}

void X25519::parseJson(const QJsonDocument &obj)
{
    int serialization_type = obj["serialization_type"].toInt();

    std::vector<unsigned char> json_pub = base64QStringToBytes(obj["public"].toString());
    std::copy(json_pub.begin(), json_pub.end(), public_key.begin());

    if(serialization_type == X25519_PRIVATE)
    {
        std::vector<unsigned char> json_prv = base64QStringToBytes(obj["private"].toString());
        std::copy(json_prv.begin(), json_prv.end(), secret_key.begin());
    }
}


