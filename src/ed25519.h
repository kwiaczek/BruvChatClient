#ifndef ED25519_H
#define ED25519_H
#include <vector>
#include <sodium.h>
#include <QJsonObject>
#include <QJsonDocument>

#define ED25519_PUBLIC true
#define ED25519_PRIVATE false

struct Ed25519
{
//used for signatures
    std::vector<unsigned char> public_key;
    std::vector<unsigned char> secret_key;

    Ed25519();

    void generate();

    QJsonObject toJson(bool is_public);
    void parseJson(const QJsonDocument & obj);
};
#endif // ED25519_H
