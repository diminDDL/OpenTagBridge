#
#  GoogleFindMyTools - A set of tools to interact with the Google Find My API
#  Copyright © 2024 Leon Böttger. All rights reserved.
#

import asyncio
import time

from Auth.fcm_receiver import FcmReceiver
from NovaApi.ExecuteAction.LocateTracker.decrypt_locations import decrypt_location_response_locations, decrypt_location_response_locations_to_entries
from NovaApi.ExecuteAction.nbe_execute_action import create_action_request, serialize_action_request
from NovaApi.nova_request import nova_request
from NovaApi.scopes import NOVA_ACTION_API_SCOPE
from NovaApi.util import generate_random_uuid
from ProtoDecoders import DeviceUpdate_pb2
from ProtoDecoders.decoder import parse_device_update_protobuf
from example_data_provider import get_example_data

def create_location_request(canonic_device_id, fcm_registration_id, request_uuid):

    action_request = create_action_request(canonic_device_id, fcm_registration_id, request_uuid=request_uuid)

    # Random values, can be arbitrary
    action_request.action.locateTracker.lastHighTrafficEnablingTime.seconds = 1732120060
    action_request.action.locateTracker.contributorType = DeviceUpdate_pb2.SpotContributorType.FMDN_ALL_LOCATIONS

    # Convert to hex string
    hex_payload = serialize_action_request(action_request)

    return hex_payload


def get_location_data_for_device(canonic_device_id, name):

    print(f"[LocationRequest] Requesting location data for {name}...")

    result = None
    request_uuid = generate_random_uuid()

    def handle_location_response(response):
        nonlocal result
        device_update = parse_device_update_protobuf(response)

        if device_update.fcmMetadata.requestUuid == request_uuid:
            print("[LocationRequest] Location request successful. Decrypting locations...")
            result = parse_device_update_protobuf(response)
            #print_device_update_protobuf(response)

    fcm_token = FcmReceiver().register_for_location_updates(handle_location_response)

    hex_payload = create_location_request(canonic_device_id, fcm_token, request_uuid)
    nova_request(NOVA_ACTION_API_SCOPE, hex_payload)

    while result is None:
        time.sleep(0.1)

    decrypt_location_response_locations(result)


def _print_merged_summary(compound_name: str, merged_entries: list[dict]) -> None:
    print("=" * 40)
    print(f"[LocationRequest] Combined summary for {compound_name}")
    print("=" * 40)

    if not merged_entries:
        print("No locations found across subtags.")
        return

    dedup = {}
    for entry in merged_entries:
        if entry.get("kind") == "semantic":
            key = (entry.get("source_subtag"), entry.get("time"), entry.get("status"), entry.get("name"))
        else:
            lat = entry.get("latitude")
            lon = entry.get("longitude")
            key = (entry.get("time"), lat, lon, entry.get("status"))
        dedup[key] = entry

    sorted_entries = sorted(dedup.values(), key=lambda item: item.get("time", 0), reverse=True)
    for entry in sorted_entries:
        subtag = entry.get("source_subtag", "unknown")
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(entry.get("time", 0)))
        status_name = entry.get("status_name", "UNKNOWN")

        if entry.get("kind") == "semantic":
            print(f"[{subtag}] Semantic: {entry.get('name')} | Time: {timestamp} | Status: {status_name}")
        else:
            print(
                f"[{subtag}] Lat: {entry.get('latitude')} Lon: {entry.get('longitude')} "
                f"Time: {timestamp} Status: {status_name}"
            )


def get_location_data_for_compound(compound_name: str, subtags: list[dict]):
    merged_entries = []

    print(f"[LocationRequest] Requesting location data for compound tag {compound_name} ({len(subtags)} subtags)...")

    for subtag in subtags:
        subtag_name = subtag["name"]
        canonic_id = subtag["canonic_id"]

        print("-" * 40)
        print(f"[LocationRequest] Subtag: {subtag_name}")

        result = None
        request_uuid = generate_random_uuid()

        def handle_location_response(response):
            nonlocal result
            device_update = parse_device_update_protobuf(response)

            if device_update.fcmMetadata.requestUuid == request_uuid:
                print("[LocationRequest] Location request successful. Decrypting locations...")
                result = parse_device_update_protobuf(response)

        fcm_token = FcmReceiver().register_for_location_updates(handle_location_response)
        hex_payload = create_location_request(canonic_id, fcm_token, request_uuid)
        nova_request(NOVA_ACTION_API_SCOPE, hex_payload)

        while result is None:
            time.sleep(0.1)

        decrypt_location_response_locations(result)
        entries = decrypt_location_response_locations_to_entries(result)
        for entry in entries:
            entry["source_subtag"] = subtag_name
            merged_entries.append(entry)

    _print_merged_summary(compound_name, merged_entries)

if __name__ == '__main__':
    get_location_data_for_device(get_example_data("sample_canonic_device_id"), "Test")