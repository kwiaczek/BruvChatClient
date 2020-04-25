#ifndef SESSION_H
#define SESSION_H
#include <vector>
#include <sodium.h>
#include "device.h"
#include "crypto.h"


class Session
{
public:
    //There is some SessionID which uniquely identifies each session
    long long int sessionid;
    DoubleRatchet * double_ratchet;

    Session();

    void createSession(Device * sender, Device * receiver);
    void recreateSession(Device * sender, Device * receiver);

    QJsonObject encryptMessage(Device * sender, Device * receiver, const std::string & plaintext);

    std::string decryptMessage(Device * sender, Device * receiver, const QJsonDocument & encrypted);
};

#endif
