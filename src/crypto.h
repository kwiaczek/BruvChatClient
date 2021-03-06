#ifndef CRYPTO_H
#define CRYPTO_H
#include <vector>
#include <sodium.h>
#include <string>
#include <iostream>
#include <map>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include "x25519.h"
#include "ed25519.h"
#include "message.h"
#include "utils.h"


enum{
    IDENTITY_KEY_PUBLIC,
    IDENTITY_KEY_PRIVATE,
    IDENTITY_KEY_PRIVATE_REMOTE
};


struct IdentityKey
{
    Ed25519 ed25519_keypair;
    X25519 x25519_keypair;

    QJsonObject toJson(int serializaion_type);
    void parseJson(const QJsonDocument & serialized_data);
};

enum{
    SIGNED_PREKEY_PUBLIC,
    SIGNED_PREKEY_PRIVATE,
    SIGNED_PREKEY_PRIVATE_REMOTE
};

struct SignedPreKey
{
    Ed25519 ed25519_keypair;
    X25519 x25519_keypair;
    std::vector<unsigned char> signature;
    QJsonObject toJson(int serializaion_type);
    void parseJson(const QJsonDocument & serialized_data);
};

struct DH{
    std::vector<unsigned char> rx;
    std::vector<unsigned char> tx;

    void initalize(const X25519 & sender, const X25519 & receiver);
    void sync(const X25519 & sender, const X25519 & receiver);

    DH();
};

class Device;

struct X3DH
{
    std::vector<unsigned char> rx;
    std::vector<unsigned char> tx;
    X25519  ephemeral;

    void initiate(Device * sender, Device * receiver);
    void sync(Device * sender, Device * receiver);

    QJsonObject toJson();
    void parseJson(const QJsonDocument & serialzed_data);

    X3DH();
};

class DoubleRatchet
{
public:
    X25519 self; //  DH Ratchet key pair (the "sending" or "self" ratchet key)
    X25519 remote; //  DH Ratchet public key (the "received" or "remote" key)
    //32-byte Chain Keys for sending and receiving
    std::vector<unsigned char> rx_chainkey;
    std::vector<unsigned char> tx_chainkey;
    //Ns, Nr: Message numbers for sending and receiving
    long long rx_counter;
    long long tx_counter;
    //PN: Number of messages in previous sending chain
    long long tx_previous;
    //MKSKIPPED: Dictionary of skipped-over message keys, indexed by ratchet public key and message number. Raises an exception if too many elements are stored.
    std::map<std::pair<std::vector<unsigned char>, long long>, std::vector<unsigned char>> skipped_messages_keys;
    X3DH * x3dh;

    Device * init_device;
    Device * sync_device;
public:
    //init functions
    DoubleRatchet();
    void initalize();
    void sync(MessageHeader header);
public:
    EncryptedMessage encrypt(const std::string & plaintext);
    DecryptedMessage decrypt(EncryptedMessage  encrypted);
public:
    QJsonObject toJson();
    void parseJson(const QJsonDocument & serialized_data);
private:
    MessageHeader header(const std::vector<unsigned char> & nonce);
private:
    std::vector<unsigned char> get_message_key(MessageHeader  ad);
    void skip_message(long long until);
    void dhratchet(const X25519 & new_remote);
};

//deatached mode
static std::vector<unsigned char> create_signature(Ed25519 & key, std::vector<unsigned char> & data)
{
    std::vector<unsigned char> sig;
    sig.reserve(crypto_sign_BYTES);
    sig.resize(crypto_sign_BYTES);
    crypto_sign_detached(sig.data(), NULL, data.data(), data.size(), key.secret_key.data());
    return sig;
}

static bool verify_signature(Ed25519 & key, std::vector<unsigned char> & sig, std::vector<unsigned char> & message)
{
    if(crypto_sign_verify_detached(sig.data(), message.data(), message.size(), key.public_key.data()) != 0)
    {
        return false;
    }
    return true;
}


#endif
