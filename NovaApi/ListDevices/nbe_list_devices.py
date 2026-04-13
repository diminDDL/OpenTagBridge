#
#  GoogleFindMyTools - A set of tools to interact with the Google Find My API
#  Copyright © 2024 Leon Böttger. All rights reserved.
#

import binascii
from NovaApi.ExecuteAction.LocateTracker.location_request import get_location_data_for_device, get_location_data_for_compound
from NovaApi.nova_request import nova_request
from NovaApi.scopes import NOVA_LIST_DEVICS_API_SCOPE
from NovaApi.util import generate_random_uuid
from Auth.token_cache import get_cached_json_value, set_cached_json_value
from ProtoDecoders import DeviceUpdate_pb2
from ProtoDecoders.decoder import parse_device_list_protobuf, get_canonic_ids, get_grouped_menu_entries
from SpotApi.CreateBleDevice.create_ble_device import register_esp32
from SpotApi.UploadPrecomputedPublicKeyIds.upload_precomputed_public_key_ids import refresh_custom_trackers


CANONIC_IDS_CACHE_KEY = "canonic_ids_v1"


def request_device_list():

    hex_payload = create_device_list_request()
    result = nova_request(NOVA_LIST_DEVICS_API_SCOPE, hex_payload)

    return result


def create_device_list_request():
    wrapper = DeviceUpdate_pb2.DevicesListRequest()

    # Query for Spot devices
    wrapper.deviceListRequestPayload.type = DeviceUpdate_pb2.DeviceType.SPOT_DEVICE

    # Set a random UUID as the request ID
    wrapper.deviceListRequestPayload.id = generate_random_uuid()

    # Serialize to binary string
    binary_payload = wrapper.SerializeToString()

    # Convert to hex string
    hex_payload = binascii.hexlify(binary_payload).decode('utf-8')

    return hex_payload


def _extract_device_canonic_ids(device):
    if device.identifierInformation.type == DeviceUpdate_pb2.IDENTIFIER_ANDROID:
        canonic_ids = device.identifierInformation.phoneInformation.canonicIds.canonicId
    else:
        canonic_ids = device.identifierInformation.canonicIds.canonicId
    return [canonic_id.id for canonic_id in canonic_ids if canonic_id.id]


def _cache_canonic_ids_from_device_list(device_list) -> None:
    existing_cache = get_cached_json_value(CANONIC_IDS_CACHE_KEY, default={})
    if not isinstance(existing_cache, dict):
        existing_cache = {}

    existing_entries = existing_cache.get("entries", [])
    if not isinstance(existing_entries, list):
        existing_entries = []

    by_id = {
        entry.get("canonic_id"): entry
        for entry in existing_entries
        if isinstance(entry, dict) and isinstance(entry.get("canonic_id"), str)
    }

    for device in device_list.deviceMetadata:
        device_name = device.userDefinedDeviceName or "Unknown"
        for canonic_id in _extract_device_canonic_ids(device):
            current = by_id.get(canonic_id, {})
            current["canonic_id"] = canonic_id
            current["name"] = device_name
            by_id[canonic_id] = current

    merged_entries = sorted(by_id.values(), key=lambda item: item.get("name", ""))
    set_cached_json_value(CANONIC_IDS_CACHE_KEY, {"entries": merged_entries})


def list_devices(
    target_canonic_id=None,
    force_upload_keys: bool = False,
    allow_device_registration: bool = False,
):
    print("Loading...")
    result_hex = request_device_list()

    device_list = parse_device_list_protobuf(result_hex)
    _cache_canonic_ids_from_device_list(device_list)

    refresh_custom_trackers(device_list, force_upload=force_upload_keys)
    canonic_ids = get_canonic_ids(device_list)
    grouped_entries = get_grouped_menu_entries(device_list)

    print("")
    print("-" * 50)
    print("Welcome to GoogleFindMyTools!")
    print("-" * 50)
    print("")
    print("The following trackers are available:")

    for idx, entry in enumerate(grouped_entries, start=1):
        if entry["type"] == "compound":
            print(f"{idx}. {entry['display_name']} [compound: {len(entry['subtags'])} subtags]")
        else:
            print(f"{idx}. {entry['display_name']}: {entry['canonic_id']}")

    if target_canonic_id:
        selected_canonic_id = target_canonic_id
        selected_device_name = "Unknown"
        for device_name, current_canonic_id in canonic_ids:
            if current_canonic_id == selected_canonic_id:
                selected_device_name = device_name
                break

        get_location_data_for_device(selected_canonic_id, selected_device_name)
        return

    if allow_device_registration:
        print("\n" + "!" * 70)
        print("WARNING: STALKING / TRACKING PEOPLE WITHOUT CONSENT IS HARMFUL")
        print("!" * 70)
        print(
            "This tool can register new trackers. Using trackers to follow or harass someone\n"
            "without their clear, informed consent is unethical and may be illegal.\n\n"
            "The developers of this tool do not condone stalking. Only use this for legitimate,\n"
            "research and educational purposes."
        )
        print("!" * 70)

    prompt_lines = [
        "\nIf you want to see locations of a tracker, type the number of the tracker and press 'Enter'."
    ]
    if allow_device_registration:
        prompt_lines.append(
            "If you want to register a new MCU-based tracker, type 'r' and press 'Enter'."
        )
    prompt = "\n".join(prompt_lines) + ": "

    while True:
        selected_value = input(prompt).strip()

        if allow_device_registration and selected_value.lower() == 'r':
            print("Loading...")
            register_esp32()
            return

        try:
            selected_idx = int(selected_value) - 1
        except ValueError:
            print("Invalid input. Please enter a tracker number" + (" or 'r'." if allow_device_registration else "."))
            continue

        if not (0 <= selected_idx < len(grouped_entries)):
            print(f"Invalid tracker number. Please enter a number between 1 and {len(grouped_entries)}.")
            continue

        selected_entry = grouped_entries[selected_idx]
        if selected_entry["type"] == "compound":
            get_location_data_for_compound(selected_entry["display_name"], selected_entry["subtags"])
        else:
            get_location_data_for_device(selected_entry["canonic_id"], selected_entry["display_name"])
        return


if __name__ == '__main__':
    list_devices()
