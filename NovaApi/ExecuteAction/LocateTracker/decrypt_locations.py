#
#  GoogleFindMyTools - A set of tools to interact with the Google Find My API
#  Copyright © 2024 Leon Böttger. All rights reserved.
#

import datetime
import hashlib
from binascii import unhexlify
from math import ceil

from Auth.token_cache import get_cached_value, get_cached_value_or_set
from FMDNCrypto.foreign_tracker_cryptor import decrypt
from KeyBackup.cloud_key_decryptor import decrypt_eik, decrypt_aes_gcm
from NovaApi.ExecuteAction.LocateTracker.decrypted_location import WrappedLocation
from ProtoDecoders import DeviceUpdate_pb2
from ProtoDecoders import Common_pb2
from ProtoDecoders.DeviceUpdate_pb2 import DeviceRegistration
from ProtoDecoders.decoder import parse_device_update_protobuf
from SpotApi.CreateBleDevice.config import mcu_fast_pair_model_id, max_truncated_eid_seconds_server
from SpotApi.CreateBleDevice.util import flip_bits
from SpotApi.GetEidInfoForE2eeDevices.get_eid_info_request import get_eid_info
from SpotApi.GetEidInfoForE2eeDevices.get_owner_key import get_owner_key


def create_google_maps_link(latitude, longitude):
    try:  
        latitude = float(latitude)
        longitude = float(longitude)
        if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
            raise ValueError("Invalid latitude or longitude values.")
    except ValueError as e:
        return f"Error: {e}" #more descriptive error message for the user
    base_url = "https://www.google.com/maps/search/?api=1"
    query_params = f"query={latitude},{longitude}"  

    return f"{base_url}&{query_params}"

# Indicates if the device is a custom microcontroller
def is_mcu_tracker(device_registration: DeviceRegistration) -> bool:
    return device_registration.fastPairModelId == mcu_fast_pair_model_id


def _get_identity_key_cache_name(device_registration: DeviceRegistration, is_mcu: bool) -> str:
    encrypted_user_secrets = device_registration.encryptedUserSecrets
    cache_source = flip_bits(encrypted_user_secrets.encryptedIdentityKey, is_mcu)
    cache_hash = hashlib.sha256(cache_source).hexdigest()
    return f"identity_key_{encrypted_user_secrets.ownerKeyVersion}_{cache_hash}"


def _retrieve_identity_key(device_registration: DeviceRegistration, is_mcu: bool) -> str:
    encrypted_user_secrets = device_registration.encryptedUserSecrets
    encrypted_identity_key = flip_bits(encrypted_user_secrets.encryptedIdentityKey, is_mcu)
    owner_key = get_owner_key()

    try:
        identity_key = decrypt_eik(owner_key, encrypted_identity_key)
        return identity_key.hex()
    except Exception as e:

        e2eeData = get_eid_info()
        current_owner_key_version = e2eeData.encryptedOwnerKeyAndMetadata.ownerKeyVersion

        print("")
        print("-" * 40)
        print("Attention:")
        print("-" * 40)

        if encrypted_user_secrets.ownerKeyVersion < current_owner_key_version:
            print(f"Failed to decrypt E2EE data. This tracker was encrypted with owner key version {encrypted_user_secrets.ownerKeyVersion}, but the current owner key version is {current_owner_key_version}.\nThis happens if you reset your end-to-end-encrypted data in the past.\nThe tracker cannot be decrypted anymore, and it is recommended to remove it in the Find My Device app.")
            exit(1)
        else:
            print(f"Failed to decrypt identity key encrypted with owner key version {encrypted_user_secrets.ownerKeyVersion}, current owner key version is {current_owner_key_version}.\nThis may happen if you reset your end-to-end-encrypted data. To resolve this issue, open the folder 'Auth' and delete the file 'secrets.json'.")
            exit(1)


def retrieve_identity_key(device_registration: DeviceRegistration) -> bytes:
    is_mcu = is_mcu_tracker(device_registration)
    cache_name = _get_identity_key_cache_name(device_registration, is_mcu)

    cached_identity_key_hex = get_cached_value(cache_name)
    if cached_identity_key_hex is not None:
        print(f"[IdentityKeyCache] HIT: {cache_name}")
        return unhexlify(cached_identity_key_hex)

    print(f"[IdentityKeyCache] MISS: {cache_name}")
    identity_key_hex = get_cached_value_or_set(
        cache_name,
        lambda: _retrieve_identity_key(device_registration, is_mcu)
    )
    return unhexlify(identity_key_hex)


def _decrypt_mcu_with_slot_fallback(identity_key: bytes, encrypted_location: bytes, public_key_random: bytes, reported_time_offset: int, pair_date: int) -> tuple[bytes, int, int | None]:
    # First try the reported counter directly.
    counters_to_try = [int(reported_time_offset)]

    slot_count = ceil(max_truncated_eid_seconds_server / 1024)
    for i in range(slot_count):
        counter_from_pair_date = pair_date + i * 1024
        counter_offset_only = i * 1024
        counters_to_try.append(counter_from_pair_date)
        counters_to_try.append(counter_offset_only)

    seen = set()
    unique_counters = []
    for counter in counters_to_try:
        if counter not in seen:
            seen.add(counter)
            unique_counters.append(counter)

    for counter in unique_counters:
        try:
            decrypted = decrypt(identity_key, encrypted_location, public_key_random, counter)
            decoded_slot = None
            if counter >= pair_date:
                delta = counter - pair_date
                if delta % 1024 == 0 and delta >= 0:
                    decoded_slot = delta // 1024

            return decrypted, counter, decoded_slot
        except ValueError as e:
            if str(e) != "MAC check failed":
                raise

    raise ValueError("MAC check failed")


def decrypt_location_response_locations(device_update_protobuf):

    device_registration = device_update_protobuf.deviceMetadata.information.deviceRegistration

    identity_key = retrieve_identity_key(device_registration)
    locations_proto = device_update_protobuf.deviceMetadata.information.locationInformation.reports.recentLocationAndNetworkLocations
    is_mcu = is_mcu_tracker(device_registration)

    # At All Areas Reports or Own Reports
    recent_location = locations_proto.recentLocation
    recent_location_time = locations_proto.recentLocationTimestamp

    # High Traffic Reports
    network_locations = list(locations_proto.networkLocations)
    network_locations_time = list(locations_proto.networkLocationTimestamps)

    if locations_proto.HasField("recentLocation"):
        network_locations.append(recent_location)
        network_locations_time.append(recent_location_time)

    location_time_array = []
    for loc, time in zip(network_locations, network_locations_time):

        if loc.status == Common_pb2.Status.SEMANTIC:
            print("Semantic Location Report")

            wrapped_location = WrappedLocation(
                decrypted_location=b'',
                time=int(time.seconds),
                accuracy=0,
                status=loc.status,
                is_own_report=True,
                name=loc.semanticLocation.locationName
            )
            location_time_array.append(wrapped_location)
        else:

            encrypted_location = loc.geoLocation.encryptedReport.encryptedLocation
            public_key_random = loc.geoLocation.encryptedReport.publicKeyRandom

            if public_key_random == b"":  # Own Report
                identity_key_hash = hashlib.sha256(identity_key).digest()
                decrypted_location = decrypt_aes_gcm(identity_key_hash, encrypted_location)
                decoded_counter = None
                decoded_slot = None
            else:
                time_offset = loc.geoLocation.deviceTimeOffset
                if is_mcu:
                    decrypted_location, decoded_counter, decoded_slot = _decrypt_mcu_with_slot_fallback(
                        identity_key,
                        encrypted_location,
                        public_key_random,
                        time_offset,
                        device_registration.pairDate,
                    )
                else:
                    decrypted_location = decrypt(identity_key, encrypted_location, public_key_random, time_offset)
                    decoded_counter = time_offset
                    decoded_slot = None

            wrapped_location = WrappedLocation(
                decrypted_location=decrypted_location,
                time=int(time.seconds),
                accuracy=loc.geoLocation.accuracy,
                status=loc.status,
                is_own_report=loc.geoLocation.encryptedReport.isOwnReport,
                name="",
                decoded_counter=decoded_counter,
                decoded_slot=decoded_slot,
            )
            location_time_array.append(wrapped_location)

    print("-" * 40)
    print("[DecryptLocations] Decrypted Locations:")

    if not location_time_array:
        print("No locations found.")
        return

    for loc in location_time_array:

        if loc.status == Common_pb2.Status.SEMANTIC:
            print(f"Semantic Location: {loc.name}")

        else:
            proto_loc = DeviceUpdate_pb2.Location()
            proto_loc.ParseFromString(loc.decrypted_location)

            latitude = proto_loc.latitude / 1e7
            longitude = proto_loc.longitude / 1e7
            altitude = proto_loc.altitude

            print(f"Latitude: {latitude}")
            print(f"Longitude: {longitude}")
            print(f"Altitude: {altitude}")
            print(f"Google Maps Link: {create_google_maps_link(latitude, longitude)}")
            
        print(f"Time: {datetime.datetime.fromtimestamp(loc.time).strftime('%Y-%m-%d %H:%M:%S')}")
        if loc.decoded_counter is not None:
            print(f"Decoded Counter: {loc.decoded_counter}")
        if loc.decoded_slot is not None:
            print(f"Decoded Timeslot: {loc.decoded_slot}")
        try:
            status_name = Common_pb2.Status.Name(loc.status)
        except ValueError:
            status_name = "UNKNOWN"
        print(f"Status: {loc.status} ({status_name})")
        print(f"Is Own Report: {loc.is_own_report}")
        print("-" * 40)

    pass


if __name__ == '__main__':
    res = parse_device_update_protobuf("")
    decrypt_location_response_locations(res)