#
#  GoogleFindMyTools - A set of tools to interact with the Google Find My API
#  Copyright © 2024 Leon Böttger. All rights reserved.
#

import secrets
import struct
import time
from pathlib import Path
from math import ceil

from FMDNCrypto.key_derivation import FMDNOwnerOperations
from FMDNCrypto.eid_generator import ROTATION_PERIOD, generate_eid
from KeyBackup.cloud_key_decryptor import encrypt_aes_gcm
from ProtoDecoders.DeviceUpdate_pb2 import DeviceComponentInformation, SpotDeviceType, RegisterBleDeviceRequest, PublicKeyIdList
from SpotApi.CreateBleDevice.config import mcu_fast_pair_model_id, max_truncated_eid_seconds_server
from SpotApi.CreateBleDevice.util import flip_bits
from SpotApi.GetEidInfoForE2eeDevices.get_owner_key import get_owner_key
from SpotApi.spot_request import spot_request


DEFAULT_TRACKER_NAME = "GoogleFindMyTools µC"
DEFAULT_TRACKER_IMAGE_URL = "https://docs.espressif.com/projects/esp-idf/en/v4.3/esp32/_images/esp32-DevKitM-1-isometric.png"


def _ask_registration_metadata() -> tuple[str, str]:
    print("\nConfigure tracker metadata (press Enter to keep defaults):")

    entered_name = input(f"- Tracker name [{DEFAULT_TRACKER_NAME}]: ").strip()
    entered_image_url = input(f"- Image URL [{DEFAULT_TRACKER_IMAGE_URL}]: ").strip()

    tracker_name = entered_name if entered_name else DEFAULT_TRACKER_NAME
    image_url = entered_image_url if entered_image_url else DEFAULT_TRACKER_IMAGE_URL

    return tracker_name, image_url


def register_esp32():

    owner_key = get_owner_key()

    eik = secrets.token_bytes(32)
    pair_date = int(time.time())
    key_count = ceil(max_truncated_eid_seconds_server / ROTATION_PERIOD)
    eids = [
        generate_eid(eik, pair_date + i * ROTATION_PERIOD)
        for i in range(key_count)
    ]

    tracker_name, image_url = _ask_registration_metadata()

    register_request = RegisterBleDeviceRequest()
    register_request.fastPairModelId = mcu_fast_pair_model_id

    # Description
    register_request.description.userDefinedName = tracker_name
    register_request.description.deviceType = SpotDeviceType.DEVICE_TYPE_BEACON

    # Device Components Information
    component_information = DeviceComponentInformation()
    component_information.imageUrl = image_url
    register_request.description.deviceComponentsInformation.append(component_information)

    # Capabilities
    register_request.capabilities.isAdvertising = True
    register_request.capabilities.trackableComponents = 1
    register_request.capabilities.capableComponents = 1

    # E2EE Registration
    register_request.e2eePublicKeyRegistration.rotationExponent = 10
    register_request.e2eePublicKeyRegistration.pairingDate = pair_date

    # Encrypted User Secrets
    # Flip bits so Android devices cannot decrypt the key
    register_request.e2eePublicKeyRegistration.encryptedUserSecrets.encryptedIdentityKey = flip_bits(encrypt_aes_gcm(owner_key, eik), True)

    # Random keys, not used for ESP
    register_request.e2eePublicKeyRegistration.encryptedUserSecrets.encryptedAccountKey = secrets.token_bytes(44)
    register_request.e2eePublicKeyRegistration.encryptedUserSecrets.encryptedSha256AccountKeyPublicAddress = secrets.token_bytes(60)

    register_request.e2eePublicKeyRegistration.encryptedUserSecrets.ownerKeyVersion = 1
    register_request.e2eePublicKeyRegistration.encryptedUserSecrets.creationDate.seconds = pair_date

    time_counter = pair_date

    # announce advertisements
    for eid in eids:
        pub_key_id = PublicKeyIdList.PublicKeyIdInfo()
        pub_key_id.publicKeyId.truncatedEid = eid[:10]
        pub_key_id.timestamp.seconds = time_counter
        register_request.e2eePublicKeyRegistration.publicKeyIdList.publicKeyIdInfo.append(pub_key_id)

        time_counter += ROTATION_PERIOD

    # General
    register_request.manufacturerName = "GoogleFindMyTools"
    register_request.modelName = "µC"

    ownerKeys = FMDNOwnerOperations()
    ownerKeys.generate_keys(identity_key=eik)

    if ownerKeys.ringing_key is None or ownerKeys.recovery_key is None or ownerKeys.tracking_key is None:
        raise RuntimeError("Failed to derive owner operation keys from identity key.")

    register_request.ringKey = ownerKeys.ringing_key
    register_request.recoveryKey = ownerKeys.recovery_key
    register_request.unwantedTrackingKey = ownerKeys.tracking_key

    bytes_data = register_request.SerializeToString()
    spot_request("CreateBleDevice", bytes_data)

    print(f"Registered device successfully. Generated {key_count} rotating advertisement keys.")
    print("Afterward, go to the folder 'PIO_ESP32Firmware' and follow the instructions in the README.md file.")

    print("\nFirst rotating key (for reference):")
    print("+" + "-" * 78 + "+")
    print("|" + " " * 19 + eids[0].hex() + " " * 19 + "|")
    print("|" + " " * 26 + "Advertisement Key [index 0]" + " " * 26 + "|")
    print("+" + "-" * 78 + "+")

    concatenated_keys_hex = "".join(eid.hex() for eid in eids)

    print("\nC string for PIO_ESP32Firmware/src/secret.h:")
    print(f"const unsigned short eid_key_count = {key_count};")
    print(f"const char *eid_keys_hex = \"{concatenated_keys_hex}\";")

    # Write binary key file: 16-bit little-endian key count followed by 20-byte keys.
    bin_path = Path(f"eid_{pair_date}.bin").resolve()
    with open(bin_path, "wb") as keyfile:
        keyfile.write(struct.pack("<H", key_count))
        for eid in eids:
            keyfile.write(eid)

    print(f"\nWrote binary key file: {bin_path}")
