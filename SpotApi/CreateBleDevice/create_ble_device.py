#
#  GoogleFindMyTools - A set of tools to interact with the Google Find My API
#  Copyright © 2024 Leon Böttger. All rights reserved.
#

import secrets
import struct
import time
from pathlib import Path

from Auth.token_cache import get_cached_json_value, set_cached_json_value
from FMDNCrypto.key_derivation import FMDNOwnerOperations
from FMDNCrypto.eid_generator import ROTATION_PERIOD, generate_eid
from KeyBackup.cloud_key_decryptor import encrypt_aes_gcm
from ProtoDecoders.DeviceUpdate_pb2 import DeviceComponentInformation, SpotDeviceType, RegisterBleDeviceRequest, PublicKeyIdList
from SpotApi.CreateBleDevice.config import (
    mcu_fast_pair_model_id,
    COMPOUND_TRACKER_PREFIX,
    COMPOUND_TRACKERS_CACHE_KEY,
    TRACKER_SLOT_WINDOW_SIZE,
    TRACKER_WINDOW_SIZES_CACHE_KEY,
)
from SpotApi.CreateBleDevice.util import flip_bits
from SpotApi.GetEidInfoForE2eeDevices.get_owner_key import get_owner_key
from SpotApi.spot_request import spot_request


DEFAULT_TRACKER_NAME = "GoogleFindMyTools µC"
DEFAULT_TRACKER_IMAGE_URL = "https://docs.espressif.com/projects/esp-idf/en/v4.3/esp32/_images/esp32-DevKitM-1-isometric.png"


def _ask_registration_metadata() -> tuple[str, str, int]:
    print("\nConfigure tracker metadata (press Enter to keep defaults):")

    entered_name = input(f"- Tracker name [{DEFAULT_TRACKER_NAME}]: ").strip()
    entered_image_url = input(f"- Image URL [{DEFAULT_TRACKER_IMAGE_URL}]: ").strip()
    default_key_count = TRACKER_SLOT_WINDOW_SIZE

    while True:
        entered_key_count = input(f"- Number of rotating keys to generate [{default_key_count}]: ").strip()
        candidate_value = entered_key_count if entered_key_count else str(default_key_count)

        try:
            key_count = int(candidate_value)
            if key_count <= 0:
                print("Please enter a positive integer.")
                continue
            break
        except ValueError:
            print("Please enter a valid integer value.")

    tracker_name = entered_name if entered_name else DEFAULT_TRACKER_NAME
    image_url = entered_image_url if entered_image_url else DEFAULT_TRACKER_IMAGE_URL

    return tracker_name, image_url, key_count


def _chunk_sizes(total_key_count: int, window_size: int) -> list[int]:
    sizes = []
    remaining = total_key_count
    while remaining > 0:
        size = min(window_size, remaining)
        sizes.append(size)
        remaining -= size
    return sizes


def _format_virtual_tracker_name(base_tracker_name: str, tracker_index: int) -> str:
    return f"{COMPOUND_TRACKER_PREFIX}{base_tracker_name}_{tracker_index}"


def _build_register_request(
    owner_key: bytes,
    eik: bytes,
    pair_date: int,
    tracker_name: str,
    image_url: str,
    eids: list[bytes],
) -> RegisterBleDeviceRequest:
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

    # Announce advertisements
    for eid in eids:
        pub_key_id = PublicKeyIdList.PublicKeyIdInfo()
        pub_key_id.publicKeyId.truncatedEid = eid[:10]
        pub_key_id.timestamp.seconds = time_counter
        register_request.e2eePublicKeyRegistration.publicKeyIdList.publicKeyIdInfo.append(pub_key_id)
        time_counter += ROTATION_PERIOD

    # General
    register_request.manufacturerName = "GoogleFindMyTools"
    register_request.modelName = "µC"

    owner_keys = FMDNOwnerOperations()
    owner_keys.generate_keys(identity_key=eik)

    if owner_keys.ringing_key is None or owner_keys.recovery_key is None or owner_keys.tracking_key is None:
        raise RuntimeError("Failed to derive owner operation keys from identity key.")

    register_request.ringKey = owner_keys.ringing_key
    register_request.recoveryKey = owner_keys.recovery_key
    register_request.unwantedTrackingKey = owner_keys.tracking_key

    return register_request


def _persist_tracker_window_sizes(subtag_chunks: list[tuple[str, int]]) -> None:
    existing_sizes = get_cached_json_value(TRACKER_WINDOW_SIZES_CACHE_KEY, default={})
    if not isinstance(existing_sizes, dict):
        existing_sizes = {}

    for subtag_name, key_count in subtag_chunks:
        existing_sizes[subtag_name] = int(key_count)

    set_cached_json_value(TRACKER_WINDOW_SIZES_CACHE_KEY, existing_sizes)


def _persist_compound_tracker_metadata(base_tracker_name: str, requested_key_count: int, subtag_chunks: list[tuple[str, int]]) -> None:
    existing_metadata = get_cached_json_value(COMPOUND_TRACKERS_CACHE_KEY, default={})
    if not isinstance(existing_metadata, dict):
        existing_metadata = {}

    compounds = existing_metadata.get("compounds")
    if not isinstance(compounds, dict):
        compounds = {}

    compound_id = f"{int(time.time())}_{base_tracker_name}"
    compounds[compound_id] = {
        "base_name": base_tracker_name,
        "requested_key_count": int(requested_key_count),
        "window_size": TRACKER_SLOT_WINDOW_SIZE,
        "subtags": [
            {
                "name": subtag_name,
                "key_count": int(key_count),
            }
            for subtag_name, key_count in subtag_chunks
        ],
        "created_at": int(time.time()),
    }

    existing_metadata["compounds"] = compounds
    set_cached_json_value(COMPOUND_TRACKERS_CACHE_KEY, existing_metadata)


def _print_esp32_snippet(key_count: int, eids: list[bytes]) -> None:
    concatenated_keys_hex = "".join(eid.hex() for eid in eids)

    print("\nFirst rotating key (for reference):")
    print("+" + "-" * 78 + "+")
    print("|" + " " * 19 + eids[0].hex() + " " * 19 + "|")
    print("|" + " " * 26 + "Advertisement Key [index 0]" + " " * 26 + "|")
    print("+" + "-" * 78 + "+")

    print("\nC string for PIO_ESP32Firmware/src/secret.h:")
    print(f"const unsigned short eid_key_count = {key_count};")
    print(f"const char *eid_keys_hex = \"{concatenated_keys_hex}\";")


def _write_combined_keyfile(total_key_count: int, all_eids: list[bytes], file_timestamp: int) -> Path:
    # Write binary key file: 16-bit little-endian key count followed by 20-byte keys.
    bin_path = Path(f"eid_{file_timestamp}.bin").resolve()
    with open(bin_path, "wb") as keyfile:
        keyfile.write(struct.pack("<H", total_key_count))
        for eid in all_eids:
            keyfile.write(eid)
    return bin_path


def register_esp32():

    owner_key = get_owner_key()
    tracker_name, image_url, requested_key_count = _ask_registration_metadata()

    chunk_sizes = _chunk_sizes(requested_key_count, TRACKER_SLOT_WINDOW_SIZE)
    is_compound_tracker = len(chunk_sizes) > 1

    all_eids: list[bytes] = []
    created_virtual_tracker_chunks: list[tuple[str, int]] = []
    file_timestamp = int(time.time())

    for tracker_index, chunk_size in enumerate(chunk_sizes):
        eik = secrets.token_bytes(32)
        pair_date = int(time.time())
        eids = [
            generate_eid(eik, pair_date + i * ROTATION_PERIOD)
            for i in range(chunk_size)
        ]
        all_eids.extend(eids)

        if is_compound_tracker:
            virtual_tracker_name = _format_virtual_tracker_name(tracker_name, tracker_index)
        else:
            virtual_tracker_name = tracker_name
        created_virtual_tracker_chunks.append((virtual_tracker_name, chunk_size))

        register_request = _build_register_request(
            owner_key=owner_key,
            eik=eik,
            pair_date=pair_date,
            tracker_name=virtual_tracker_name,
            image_url=image_url,
            eids=eids,
        )

        bytes_data = register_request.SerializeToString()
        spot_request("CreateBleDevice", bytes_data)

        print(
            f"Registered virtual tracker {tracker_index + 1}/{len(chunk_sizes)}: "
            f"{virtual_tracker_name} with {chunk_size} rotating keys."
        )

    if is_compound_tracker:
        _persist_compound_tracker_metadata(
            base_tracker_name=tracker_name,
            requested_key_count=requested_key_count,
            subtag_chunks=created_virtual_tracker_chunks,
        )

    _persist_tracker_window_sizes(created_virtual_tracker_chunks)

    print(f"Registered device successfully. Generated {requested_key_count} rotating advertisement keys.")
    print("Afterward, go to the folder 'PIO_ESP32Firmware' and follow the instructions in the README.md file.")

    _print_esp32_snippet(requested_key_count, all_eids)

    bin_path = _write_combined_keyfile(requested_key_count, all_eids, file_timestamp)
    print(f"\nWrote binary key file: {bin_path}")

