#include "crypto.h"
#include "device.h"
#include <memory>
#include "utils.h"

// todo: choose correct value
#define MAX_SKIP 9999999

void X3DH::initiate(Device *sender, Device *receiver)
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

void X3DH::sync(Device *sender, Device *receiver)
{
    std::vector<std::unique_ptr<DH>> dhs;

    for(int i =0; i < 3; i++)
    {
        dhs.push_back(std::make_unique<DH>());
    }

    //DH1 = DH(IKA, SPKB)
    dhs[0]->sync(sender->identity_key.x25519_keypair, receiver->signed_prekey.x25519_keypair);
    //DH2 = DH(EKA, IKB)
    dhs[1]->sync(ephemeral, receiver->identity_key.x25519_keypair);
    //DH3 = DH(EKA, SPKB)
    dhs[2]->sync(ephemeral, receiver->signed_prekey.x25519_keypair);

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
void DH::initalize(const X25519 &sender, const X25519 &receiver)
{
    crypto_kx_client_session_keys(rx.data(), tx.data(), sender.public_key.data(), sender.secret_key.data(), receiver.public_key.data());
}

void DH::sync(const X25519 &sender, const X25519 & receiver)
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

DoubleRatchet::DoubleRatchet(Device * self_, Device * remote_)
{
    self_device = self_;
    remote_device = remote_;

    rx_chainkey.reserve(crypto_kx_SESSIONKEYBYTES);
    rx_chainkey.resize(crypto_kx_SESSIONKEYBYTES);
    tx_chainkey.reserve(crypto_kx_SESSIONKEYBYTES);
    tx_chainkey.resize(crypto_kx_SESSIONKEYBYTES);
    /*
    state.Ns = 0
    state.Nr = 0
    state.PN = 0
    */
    tx_counter = 0;
    tx_previous = 0;
    rx_counter = 0;
}

void DoubleRatchet::initalize()
{
    x3dh = new X3DH();
    x3dh->ephemeral.generate();
    x3dh->initiate(self_device, remote_device);

    //initalize with x3dh
    std::copy(x3dh->rx.begin(), x3dh->rx.end(), rx_chainkey.begin());
    std::copy(x3dh->tx.begin(), x3dh->tx.end(), tx_chainkey.begin());
    //state.DHs = bob_dh_key_pair
    self.generate();
}

void DoubleRatchet::sync(MessageHeader header)
{
    x3dh = new X3DH();
    x3dh->ephemeral = header.ephemeral;
    x3dh->sync( remote_device, self_device);

    //initalize with x3dh
    std::copy(x3dh->rx.begin(), x3dh->rx.end(), rx_chainkey.begin());
    std::copy(x3dh->tx.begin(), x3dh->tx.end(), tx_chainkey.begin());

    //state.DHs = GENERATE_DH()
    self.generate();
    //state.DHr = bob_dh_public_key
    remote = header.self;
    //state.RK, state.CKs = KDF_RK(SK, DH(state.DHs, state.DHr))
    std::unique_ptr<DH> dh = std::make_unique<DH>();
    dh->initalize(self, remote);
    crypto_generichash_state state;
    crypto_generichash_init(&state, tx_chainkey.data(), tx_chainkey.size(), tx_chainkey.size());
    crypto_generichash_update(&state, dh->tx.data(), dh->tx.size());
    crypto_generichash_final(&state, tx_chainkey.data(), tx_chainkey.size());
}

EncryptedMessage DoubleRatchet::encrypt(const std::string &plaintext)
{
    if(x3dh == nullptr)
    {
        initalize();
    }

    EncryptedMessage encrypted_message;

   //message key
   std::vector<unsigned char> mk;
   mk.reserve(crypto_aead_aes256gcm_KEYBYTES);
   mk.resize(crypto_aead_aes256gcm_KEYBYTES);
   crypto_kdf_derive_from_key(mk.data(), mk.size(), tx_counter, "RATCHET", tx_chainkey.data());
   //nonce
   std::vector<unsigned char> nonce;
   nonce.reserve(crypto_aead_aes256gcm_NPUBBYTES);
   nonce.resize(crypto_aead_aes256gcm_NPUBBYTES);
   randombytes_buf(nonce.data(), nonce.size());
   //create header
   encrypted_message.header = header(nonce);
   encrypted_message.ciphertext.reserve(plaintext.size() + crypto_aead_aes256gcm_ABYTES);
   encrypted_message.ciphertext.resize(plaintext.size() + crypto_aead_aes256gcm_ABYTES);

   crypto_aead_aes256gcm_encrypt(encrypted_message.ciphertext.data(), nullptr, (unsigned char *) plaintext.c_str(), plaintext.size(), encrypted_message.header.toJsonBytes().data(), encrypted_message.header.toJsonBytes().size(), NULL, nonce.data(), mk.data());

   tx_counter++;

   return encrypted_message;
}

DecryptedMessage DoubleRatchet::decrypt(EncryptedMessage encrypted)
{
    if(x3dh == nullptr)
    {
        sync(encrypted.header);
    }

    std::vector<unsigned char> mk = get_message_key(encrypted.header);
    std::vector<unsigned char> nonce = encrypted.header.nonce;
    std::vector<unsigned char> ciphertext =encrypted.ciphertext;

    DecryptedMessage decrypted_message;
    decrypted_message.plaintext.reserve(ciphertext.size() - crypto_aead_aes256gcm_ABYTES);
    decrypted_message.plaintext.resize(ciphertext.size() - crypto_aead_aes256gcm_ABYTES);

    if(ciphertext.size() < crypto_aead_aes256gcm_ABYTES || (crypto_aead_aes256gcm_decrypt(decrypted_message.plaintext.data(), nullptr, NULL, ciphertext.data(), ciphertext.size(), encrypted.header.toJsonBytes().data(), encrypted.header.toJsonBytes().size(), nonce.data(), mk.data()) != 0))
    {
        std::cerr << "error!!" << std::endl;
    }

    return decrypted_message;
}


MessageHeader DoubleRatchet::header(const std::vector<unsigned char> &nonce)
{
    MessageHeader h;
    h.nonce = nonce;
    h.self = self;
    h.tx_counter = tx_counter;
    h.tx_previous = tx_previous;
    h.ephemeral = x3dh->ephemeral;
    return h;
}

std::vector<unsigned char> DoubleRatchet::get_message_key(MessageHeader h)
{
    X25519 send_remote_key = h.self;
    long long n = h.tx_counter;
    long long pn = h.tx_previous;

    auto index = skipped_messages_keys.find(std::make_pair(send_remote_key.public_key, n));
    if(index != skipped_messages_keys.end())
    {
        auto mk = index->second;
        skipped_messages_keys.erase(index);
        return  mk;
    }

    if(send_remote_key.public_key != remote.public_key)
    {
        skip_message(pn);
        dhratchet(send_remote_key);
    }
    skip_message(n);

    std::vector<unsigned char> mk;
    mk.reserve(crypto_aead_aes256gcm_KEYBYTES);
    mk.resize(crypto_aead_aes256gcm_KEYBYTES);
    crypto_kdf_derive_from_key(mk.data(), mk.size(), rx_counter, "RATCHET", rx_chainkey.data());

    rx_counter++;

    return mk;
}

void DoubleRatchet::skip_message(long long until)
{
    if(rx_counter + MAX_SKIP < until)
    {
        std::cerr << "TO MANY MESSAGES SKIPPED!" << std::endl;
    }

    for(rx_counter; rx_counter<until;rx_counter+=1)
    {
        std::vector<unsigned char> mk;
        mk.reserve(crypto_aead_aes256gcm_KEYBYTES);
        mk.resize(crypto_aead_aes256gcm_KEYBYTES);
        crypto_kdf_derive_from_key(mk.data(), mk.size(), rx_counter, "RATCHET", rx_chainkey.data());

        auto index = std::make_pair(remote.public_key, rx_counter);

        skipped_messages_keys[index] = mk;
    }
}

void DoubleRatchet::dhratchet(const X25519 &new_remote)
{
    //state.PN = state.Ns
    //state.Ns = 0
    //state.Nr = 0
    tx_previous = tx_counter;
    tx_counter = 0;
    rx_counter = 0;
    //    state.DHr = header.dh
    remote = new_remote;
    //    state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs, state.DHr))
    std::unique_ptr<DH> dh = std::make_unique<DH>();
    dh->sync(remote, self);
    crypto_generichash_state state;
    crypto_generichash_init(&state, rx_chainkey.data(), rx_chainkey.size(), rx_chainkey.size());
    crypto_generichash_update(&state, dh->rx.data(), dh->rx.size());
    crypto_generichash_final(&state, rx_chainkey.data(), rx_chainkey.size());
    //    state.DHs = GENERATE_DH()
    self.generate();
    dh = std::make_unique<DH>();
    dh->initalize(self, remote);
    crypto_generichash_init(&state, tx_chainkey.data(), tx_chainkey.size(), tx_chainkey.size());
    crypto_generichash_update(&state, dh->tx.data(), dh->tx.size());
    crypto_generichash_final(&state, tx_chainkey.data(), tx_chainkey.size());
}
