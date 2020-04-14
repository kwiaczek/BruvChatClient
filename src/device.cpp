#include <iostream>
#include "user.h"
#include "device.h"

Device::Device()
{
    deviceid = 0;

    //generate identity key
    identity_key.ed25519_keypair.generate();
    identity_key.x25519_keypair.derive_from_ed25519(identity_key.ed25519_keypair);

    //generate signed pre key
    signed_prekey.ed25519_keypair.generate();
    signed_prekey.x25519_keypair.derive_from_ed25519(signed_prekey.ed25519_keypair);
    signed_prekey.signature = create_signature(identity_key.ed25519_keypair, signed_prekey.x25519_keypair.public_key);
}
