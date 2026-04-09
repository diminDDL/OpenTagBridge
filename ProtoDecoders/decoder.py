#
#  GoogleFindMyTools - A set of tools to interact with the Google Find My API
#  Copyright © 2024 Leon Böttger. All rights reserved.
#

import binascii
import subprocess
import re

from google.protobuf import text_format
import datetime
import pytz

from Auth.token_cache import get_cached_json_value
from ProtoDecoders import DeviceUpdate_pb2, LocationReportsUpload_pb2
from example_data_provider import get_example_data
from SpotApi.CreateBleDevice.config import COMPOUND_TRACKER_PREFIX, COMPOUND_TRACKERS_CACHE_KEY


# Custom message formatter to print the Protobuf byte fields as hex strings
def custom_message_formatter(message, indent, as_one_line):
    lines = []
    indent = f"{indent}"
    indent = indent.removeprefix("0")

    for field, value in message.ListFields():
        if field.type == field.TYPE_BYTES:
            hex_value = binascii.hexlify(value).decode('utf-8')
            lines.append(f"{indent}{field.name}: \"{hex_value}\"")
        elif field.type == field.TYPE_MESSAGE:
            if field.label == field.LABEL_REPEATED:
                for sub_message in value:
                    if field.message_type.name == "Time":
                        # Convert Unix time to human-readable format
                        unix_time = sub_message.seconds
                        local_time = datetime.datetime.fromtimestamp(unix_time, pytz.timezone('Europe/Berlin'))
                        lines.append(f"{indent}{field.name} {{\n{indent}  {local_time}\n{indent}}}")
                    else:
                        nested_message = custom_message_formatter(sub_message, f"{indent}  ", as_one_line)
                        lines.append(f"{indent}{field.name} {{\n{nested_message}\n{indent}}}")
            else:
                if field.message_type.name == "Time":
                    # Convert Unix time to human-readable format
                    unix_time = value.seconds
                    local_time = datetime.datetime.fromtimestamp(unix_time, pytz.timezone('Europe/Berlin'))
                    lines.append(f"{indent}{field.name} {{\n{indent}  {local_time}\n{indent}}}")
                else:
                    nested_message = custom_message_formatter(value, f"{indent}  ", as_one_line)
                    lines.append(f"{indent}{field.name} {{\n{nested_message}\n{indent}}}")
        else:
            lines.append(f"{indent}{field.name}: {value}")
    return "\n".join(lines)


def parse_location_report_upload_protobuf(hex_string):
    location_reports = LocationReportsUpload_pb2.LocationReportsUpload()
    location_reports.ParseFromString(bytes.fromhex(hex_string))
    return location_reports


def parse_device_update_protobuf(hex_string):
    device_update = DeviceUpdate_pb2.DeviceUpdate()
    device_update.ParseFromString(bytes.fromhex(hex_string))
    return device_update


def parse_device_list_protobuf(hex_string):
    device_list = DeviceUpdate_pb2.DevicesList()
    device_list.ParseFromString(bytes.fromhex(hex_string))
    return device_list


def get_canonic_ids(device_list):
    result = []
    for device in device_list.deviceMetadata:
        if device.identifierInformation.type == DeviceUpdate_pb2.IDENTIFIER_ANDROID: 
            canonic_ids = device.identifierInformation.phoneInformation.canonicIds.canonicId
        else:
            canonic_ids = device.identifierInformation.canonicIds.canonicId
        device_name = device.userDefinedDeviceName
        for canonic_id in canonic_ids:
            result.append((device_name, canonic_id.id))
    return result


def _extract_device_canonic_ids(device):
    if device.identifierInformation.type == DeviceUpdate_pb2.IDENTIFIER_ANDROID:
        canonic_ids = device.identifierInformation.phoneInformation.canonicIds.canonicId
    else:
        canonic_ids = device.identifierInformation.canonicIds.canonicId
    return [canonic_id.id for canonic_id in canonic_ids]


def _parse_compound_subtag_name(device_name: str):
    if not device_name.startswith(COMPOUND_TRACKER_PREFIX):
        return None

    raw_name = device_name[len(COMPOUND_TRACKER_PREFIX):]
    match = re.match(r"^(.*)_([0-9]+)$", raw_name)
    if not match:
        return None

    base_name = match.group(1)
    index = int(match.group(2))
    return base_name, index


def get_grouped_menu_entries(device_list):
    rows = []
    for device in device_list.deviceMetadata:
        ids = _extract_device_canonic_ids(device)
        for canonic_id in ids:
            rows.append({
                "device_name": device.userDefinedDeviceName,
                "canonic_id": canonic_id,
            })

    if not rows:
        return []

    name_to_indices = {}
    for index, row in enumerate(rows):
        name_to_indices.setdefault(row["device_name"], []).append(index)

    consumed_indices = set()
    entries = []

    metadata = get_cached_json_value(COMPOUND_TRACKERS_CACHE_KEY, default={})
    compounds = metadata.get("compounds", {}) if isinstance(metadata, dict) else {}

    if isinstance(compounds, dict):
        for compound_data in compounds.values():
            if not isinstance(compound_data, dict):
                continue

            base_name = compound_data.get("base_name")
            subtags_data = compound_data.get("subtags")

            if isinstance(subtags_data, list):
                subtag_names = [
                    item.get("name")
                    for item in subtags_data
                    if isinstance(item, dict) and isinstance(item.get("name"), str)
                ]
            else:
                subtag_names = compound_data.get("subtag_names", [])

            if not isinstance(base_name, str) or not isinstance(subtag_names, list) or not subtag_names:
                continue

            compound_subtags = []
            compound_indices = []

            for subtag_name in subtag_names:
                parsed_name = _parse_compound_subtag_name(subtag_name)
                if parsed_name is None:
                    compound_subtags = []
                    compound_indices = []
                    break

                matching_indices = [idx for idx in name_to_indices.get(subtag_name, []) if idx not in consumed_indices]
                if not matching_indices:
                    compound_subtags = []
                    compound_indices = []
                    break

                for idx in matching_indices:
                    compound_subtags.append({
                        "name": rows[idx]["device_name"],
                        "canonic_id": rows[idx]["canonic_id"],
                    })
                    compound_indices.append(idx)

            if compound_subtags:
                for idx in compound_indices:
                    consumed_indices.add(idx)
                entries.append({
                    "type": "compound",
                    "display_name": base_name,
                    "subtags": compound_subtags,
                    "_order": min(compound_indices),
                })

    inferred_groups = {}
    for index, row in enumerate(rows):
        if index in consumed_indices:
            continue
        parsed_name = _parse_compound_subtag_name(row["device_name"])
        if parsed_name is None:
            continue
        base_name, subtag_index = parsed_name
        inferred_groups.setdefault(base_name, []).append((subtag_index, index))

    for base_name, indexed_rows in inferred_groups.items():
        indexed_rows.sort(key=lambda item: item[0])
        subtags = []
        for _, row_index in indexed_rows:
            consumed_indices.add(row_index)
            subtags.append({
                "name": rows[row_index]["device_name"],
                "canonic_id": rows[row_index]["canonic_id"],
            })

        entries.append({
            "type": "compound",
            "display_name": base_name,
            "subtags": subtags,
            "_order": min(row_index for _, row_index in indexed_rows),
        })

    for index, row in enumerate(rows):
        if index in consumed_indices:
            continue
        entries.append({
            "type": "single",
            "display_name": row["device_name"],
            "canonic_id": row["canonic_id"],
            "_order": index,
        })

    entries.sort(key=lambda item: item.get("_order", 0))
    for entry in entries:
        entry.pop("_order", None)

    return entries


def print_location_report_upload_protobuf(hex_string):
    print(text_format.MessageToString(parse_location_report_upload_protobuf(hex_string), message_formatter=custom_message_formatter))


def print_device_update_protobuf(hex_string):
    print(text_format.MessageToString(parse_device_update_protobuf(hex_string), message_formatter=custom_message_formatter))


def print_device_list_protobuf(hex_string):
    print(text_format.MessageToString(parse_device_list_protobuf(hex_string), message_formatter=custom_message_formatter))


if __name__ == '__main__':
    # Recompile
    subprocess.run(["protoc", "--python_out=.", "ProtoDecoders/Common.proto"], cwd="../")
    subprocess.run(["protoc", "--python_out=.", "ProtoDecoders/DeviceUpdate.proto"], cwd="../")
    subprocess.run(["protoc", "--python_out=.", "ProtoDecoders/LocationReportsUpload.proto"], cwd="../")

    subprocess.run(["protoc", "--pyi_out=.", "ProtoDecoders/Common.proto"], cwd="../")
    subprocess.run(["protoc", "--pyi_out=.", "ProtoDecoders/DeviceUpdate.proto"], cwd="../")
    subprocess.run(["protoc", "--pyi_out=.", "ProtoDecoders/LocationReportsUpload.proto"], cwd="../")

    print("\n ------------------- \n")

    print("Device List: ")
    print_device_list_protobuf(get_example_data("sample_nbe_list_devices_response"))

    print("Own Report: ")
    print_location_report_upload_protobuf(get_example_data("sample_own_report"))

    print("\n ------------------- \n")

    print("Not Own Report: ")
    print_location_report_upload_protobuf(get_example_data("sample_foreign_report"))

    print("\n ------------------- \n")

    print("Device Update: ")
    print_device_update_protobuf(get_example_data("sample_device_update"))
