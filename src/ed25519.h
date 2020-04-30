#ifndef ED25519_H
#define ED25519_H
#include <vector>
#include <sodium.h>
#include <QJsonObject>
#include <QJsonDocument>


enum{
    ED25519_PUBLIC,
    ED25519_PRIVATE,
    ED25519_PRIVATE_REMOTE
};

struct Ed25519
{
//used for signatures
    std::vector<unsigned char> public_key;
    std::vector<unsigned char> secret_key;

    Ed25519();

    void generate();

    QJsonObject toJson(int serialization_type);
    void parseJson(const QJsonDocument & obj);
};
#endif // ED25519_H
