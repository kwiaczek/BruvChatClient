#ifndef CRYPTO_H
#define CRYPTO_H
#include <vector>
#include <sodium.h>
#include <string>
#include <iostream>

struct Ed25519
{
//used for signatures
    std::vector<unsigned char> public_key;
    std::vector<unsigned char> secret_key;

    Ed25519();

    void generate();
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
};

struct IdentityKey
{
   Ed25519 ed25519_keypair;
    X25519 x25519_keypair;
};

struct SignedPreKey
{
    Ed25519 ed25519_keypair;
    X25519 x25519_keypair;
    std::vector<unsigned char> signature;
};

struct DH{
    std::vector<unsigned char> rx;
    std::vector<unsigned char> tx;

    void initalize(const X25519 & sender, const X25519 & receiver);
    void recreate(const X25519 & sender, const X25519 & receiver);

    DH();
};

class Device;
struct X3DH
{
    std::vector<unsigned char> rx;
    std::vector<unsigned char> tx;


    void initiate(Device * sender, Device * receiver, X25519 & ephemeral);
    void recreate(Device * sender, Device * receiver, X25519 & ephemeral);

    X3DH();
};

struct DoubleRatchet
{
    std::vector<unsigned char> rx;
    std::vector<unsigned char> tx;

    X25519 ratchet_keypair;

    DoubleRatchet();

    void initalize(const X3DH & x3dh);

    //for receiver
    void updateRatchetStep(const X25519 & keys);

    //for sender
    void initalizeRatchetStep();
    void finalizeRatchetStep(const X25519 & key);
};

//(detached mode)
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
