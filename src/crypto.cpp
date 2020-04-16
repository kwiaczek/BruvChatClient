#include "crypto.h"
#include "device.h"
#include <memory>
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

void X3DH::initiate(Device *sender, Device *receiver, X25519 &ephemeral)
{
    std::vector<std::unique_ptr<DH>> dhs;

    for(int i =0; i < 3; i++)
    {
        dhs.push_back(std::make_unique<DH>());
    }

    //DH1 = DH(IKA, SPKB)
    dhs[0]->initalize(sender->identity_key.x25519_keypair, receiver->signed_prekey.x25519_keypair);
    //DH2 = DH(EKA, IKB)
    dhs[1]->initalize(ephemeral, receiver->identity_key.x25519_keypair);
    //DH3 = DH(EKA, SPKB)
    dhs[2]->initalize(ephemeral, receiver->signed_prekey.x25519_keypair);

    //SK = KDF(DH1 || DH2 || DH3

    //derive rx
    crypto_generichash_state state;
    crypto_generichash_init(&state, dhs[0]->rx.data(), dhs[0]->rx.size(), rx.size());
    crypto_generichash_init(&state, dhs[1]->rx.data(), dhs[1]->rx.size(), rx.size());
    crypto_generichash_init(&state, dhs[2]->rx.data(), dhs[2]->rx.size(), rx.size());
    crypto_generichash_final(&state, rx.data(), rx.size());

    //derive tx
    crypto_generichash_init(&state, dhs[0]->tx.data(), dhs[0]->tx.size(), tx.size());
    crypto_generichash_init(&state, dhs[1]->tx.data(), dhs[1]->tx.size(), tx.size());
    crypto_generichash_init(&state, dhs[2]->tx.data(), dhs[2]->tx.size(), tx.size());
    crypto_generichash_final(&state, tx.data(), tx.size());
}

void X3DH::recreate(Device *sender, Device *receiver, X25519 &ephemeral)
{
    std::vector<std::unique_ptr<DH>> dhs;

    for(int i =0; i < 3; i++)
    {
        dhs.push_back(std::make_unique<DH>());
    }

    //DH1 = DH(IKA, SPKB)
    dhs[0]->recreate(sender->identity_key.x25519_keypair, receiver->signed_prekey.x25519_keypair);
    //DH2 = DH(EKA, IKB)
    dhs[1]->recreate(ephemeral, receiver->identity_key.x25519_keypair);
    //DH3 = DH(EKA, SPKB)
    dhs[2]->recreate(ephemeral, receiver->signed_prekey.x25519_keypair);

    //SK = KDF(DH1 || DH2 || DH3

    //derive rx
    crypto_generichash_state state;
    crypto_generichash_init(&state, dhs[0]->rx.data(), dhs[0]->rx.size(), rx.size());
    crypto_generichash_init(&state, dhs[1]->rx.data(), dhs[1]->rx.size(), rx.size());
    crypto_generichash_init(&state, dhs[2]->rx.data(), dhs[2]->rx.size(), rx.size());
    crypto_generichash_final(&state, rx.data(), rx.size());

    //derive tx
    crypto_generichash_init(&state, dhs[0]->tx.data(), dhs[0]->tx.size(), tx.size());
    crypto_generichash_init(&state, dhs[1]->tx.data(), dhs[1]->tx.size(), tx.size());
    crypto_generichash_init(&state, dhs[2]->tx.data(), dhs[2]->tx.size(), tx.size());
    crypto_generichash_final(&state, tx.data(), tx.size());
}

X3DH::X3DH(){
    rx.reserve(crypto_kx_SESSIONKEYBYTES);
    rx.resize(crypto_kx_SESSIONKEYBYTES);
    tx.reserve(crypto_kx_SESSIONKEYBYTES);
    tx.resize(crypto_kx_SESSIONKEYBYTES);
}

DoubleRatchet::DoubleRatchet()
{
    rx.reserve(crypto_kx_SESSIONKEYBYTES);
    rx.resize(crypto_kx_SESSIONKEYBYTES);
    tx.reserve(crypto_kx_SESSIONKEYBYTES);
    tx.resize(crypto_kx_SESSIONKEYBYTES);

    ratchet_keypair.generate();
}

void DoubleRatchet::initalize(const X3DH &x3dh)
{
    //initalize chains with shared secret established via X3DH
    std::copy(x3dh.rx.begin(), x3dh.rx.end(), rx.begin());
    std::copy(x3dh.tx.begin(), x3dh.tx.end(), tx.begin());
}

void DoubleRatchet::updateRatchetStep(const X25519 &key)
{
    //derive new shared secret
    std::unique_ptr<DH> dh = std::make_unique<DH>();
    dh->initalize(ratchet_keypair, key);
    //update tx chains
    crypto_generichash_state state;
    crypto_generichash_init(&state, tx.data(), tx.size(), tx.size());
    crypto_generichash_update(&state, dh->tx.data(), dh->tx.size());
    crypto_generichash_final(&state, tx.data(), tx.size());
}

void DoubleRatchet::initalizeRatchetStep()
{
    //generate ratchet keys
    ratchet_keypair.generate();
}

void DoubleRatchet::finalizeRatchetStep(const X25519 &key)
{
    //derive new shared secret
    std::unique_ptr<DH> dh = std::make_unique<DH>();
    dh->recreate(key, ratchet_keypair);
    //update rx chains
    crypto_generichash_state state;
    crypto_generichash_init(&state, rx.data(), rx.size(), rx.size());
    crypto_generichash_update(&state, dh->rx.data(), dh->rx.size());
    crypto_generichash_final(&state, rx.data(), rx.size());
}

void DH::initalize(const X25519 &sender, const X25519 &receiver)
{
    crypto_kx_client_session_keys(rx.data(), tx.data(), sender.public_key.data(), sender.secret_key.data(), receiver.public_key.data());
}

void DH::recreate(const X25519 &sender, const X25519 & receiver)
{
    crypto_kx_server_session_keys(rx.data(), tx.data(), receiver.public_key.data(), receiver.secret_key.data(),  sender.public_key.data());
}

DH::DH()
{
    rx.reserve(crypto_kx_SESSIONKEYBYTES);
    rx.resize(crypto_kx_SESSIONKEYBYTES);
    tx.reserve(crypto_kx_SESSIONKEYBYTES);
    tx.resize(crypto_kx_SESSIONKEYBYTES);
}
