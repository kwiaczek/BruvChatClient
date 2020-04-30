#ifndef X25519_H
#define X25519_H
#include <vector>
#include <iostream>
#include <sodium.h>
#include <QJsonObject>
#include <QJsonDocument>
#include "ed25519.h"

enum{
    X25519_PUBLIC,
    X25519_PRIVATE,
    X25519_PRIVATE_REMOTE
};
struct X25519
{
    //used for AEAD
    std::vector<unsigned char> public_key;
    std::vector<unsigned char> secret_key;

    X25519();

    void generate();

    //ed25519 -> curve25519
    void derive_from_ed25519(Ed25519 & key);

    QJsonObject toJson(int serialization_type);
    void parseJson(const QJsonDocument & obj);
};

#endif // X25519_H
