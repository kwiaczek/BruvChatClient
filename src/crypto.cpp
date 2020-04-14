#include "crypto.h"
#include "device.h"

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
    //X3DH
    std::vector<unsigned char> tmp_rx[3];
    std::vector<unsigned char> tmp_tx[3];

    for(int i =0; i<3;i++)
    {
        tmp_rx[i].reserve(crypto_kx_SESSIONKEYBYTES);
        tmp_rx[i].resize(crypto_kx_SESSIONKEYBYTES);
        tmp_tx[i].reserve(crypto_kx_SESSIONKEYBYTES);
        tmp_tx[i].resize(crypto_kx_SESSIONKEYBYTES);
    }

    //DH1 = DH(IKA, SPKB)
    crypto_kx_client_session_keys(tmp_rx[0].data(), tmp_tx[0].data(), sender->identity_key.x25519_keypair.public_key.data(), sender->identity_key.x25519_keypair.secret_key.data(), receiver->signed_prekey.x25519_keypair.public_key.data());
    //DH2 = DH(EKA, IKB)
    crypto_kx_client_session_keys(tmp_rx[1].data(), tmp_tx[1].data(), ephemeral.public_key.data(), ephemeral.secret_key.data(), receiver->identity_key.x25519_keypair.public_key.data());
    //DH3 = DH(EKA, SPKB)
    crypto_kx_client_session_keys(tmp_rx[2].data(), tmp_tx[2].data(), ephemeral.public_key.data(), ephemeral.secret_key.data(), receiver->signed_prekey.x25519_keypair.public_key.data());
    //SK = KDF(DH1 || DH2 || DH3
    //instead i will hash all those rx together and tx togheter to derive one rx and tx
    //for rx
    crypto_generichash_state state;
    crypto_generichash_init(&state, tmp_rx[0].data(), tmp_rx[0].size(), rx.size());
    crypto_generichash_update(&state, tmp_rx[1].data(), tmp_rx[1].size());
    crypto_generichash_update(&state, tmp_rx[2].data(), tmp_rx[2].size());
    crypto_generichash_final(&state, rx.data(), rx.size());
    //for tx
    crypto_generichash_init(&state, tmp_tx[0].data(), tmp_tx[0].size(), tx.size());
    crypto_generichash_update(&state, tmp_tx[1].data(), tmp_tx[1].size());
    crypto_generichash_update(&state, tmp_tx[2].data(), tmp_tx[2].size());
    crypto_generichash_final(&state, tx.data(), tx.size());
}

void X3DH::recreate(Device *sender, Device *receiver, X25519 &ephemeral)
{
    std::vector<unsigned char> tmp_rx[3];
    std::vector<unsigned char> tmp_tx[3];

    for(int i =0; i<3;i++)
    {
        tmp_rx[i].reserve(crypto_kx_SESSIONKEYBYTES);
        tmp_rx[i].resize(crypto_kx_SESSIONKEYBYTES);
        tmp_tx[i].reserve(crypto_kx_SESSIONKEYBYTES);
        tmp_tx[i].resize(crypto_kx_SESSIONKEYBYTES);
    }
    //DH1 = DH(IKA, SPKB)
    crypto_kx_server_session_keys(tmp_rx[0].data(), tmp_tx[0].data(), receiver->signed_prekey.x25519_keypair.public_key.data(), receiver->signed_prekey.x25519_keypair.secret_key.data(), sender->identity_key.x25519_keypair.public_key.data());
    //DH2 = DH(EKA, IKB)
    crypto_kx_server_session_keys(tmp_rx[1].data(), tmp_tx[1].data(), receiver->identity_key.x25519_keypair.public_key.data(), receiver->identity_key.x25519_keypair.secret_key.data(), ephemeral.public_key.data());
    //DH3 = DH(EKA, SPKB)
    crypto_kx_server_session_keys(tmp_rx[2].data(), tmp_tx[2].data(), receiver->signed_prekey.x25519_keypair.public_key.data(), receiver->signed_prekey.x25519_keypair.secret_key.data(), ephemeral.public_key.data());
    //SK = KDF(DH1 || DH2 || DH3
    //instead i will hash all those rx together and tx togheter to derive one rx and tx
    //for rx
    crypto_generichash_state state;
    crypto_generichash_init(&state, tmp_rx[0].data(), tmp_rx[0].size(), rx.size());
    crypto_generichash_update(&state, tmp_rx[1].data(), tmp_rx[1].size());
    crypto_generichash_update(&state, tmp_rx[2].data(), tmp_rx[2].size());
    crypto_generichash_final(&state, rx.data(), rx.size());
    //for tx
    crypto_generichash_init(&state, tmp_tx[0].data(), tmp_tx[0].size(), tx.size());
    crypto_generichash_update(&state, tmp_tx[1].data(), tmp_tx[1].size());
    crypto_generichash_update(&state, tmp_tx[2].data(), tmp_tx[2].size());
    crypto_generichash_final(&state, tx.data(), tx.size());
}

X3DH::X3DH(){
    rx.reserve(crypto_kx_SESSIONKEYBYTES);
    rx.resize(crypto_kx_SESSIONKEYBYTES);
    tx.reserve(crypto_kx_SESSIONKEYBYTES);
    tx.resize(crypto_kx_SESSIONKEYBYTES);
}
