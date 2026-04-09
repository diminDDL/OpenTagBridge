#
#  GoogleFindMyTools - A set of tools to interact with the Google Find My API
#  Copyright © 2024 Leon Böttger. All rights reserved.
#
import time
import re
from math import ceil

from FMDNCrypto.eid_generator import ROTATION_PERIOD, generate_eid
from NovaApi.ExecuteAction.LocateTracker.decrypt_locations import retrieve_identity_key, is_mcu_tracker
from ProtoDecoders import DeviceUpdate_pb2
from ProtoDecoders.DeviceUpdate_pb2 import DevicesList, UploadPrecomputedPublicKeyIdsRequest, PublicKeyIdList
from SpotApi.CreateBleDevice.config import max_truncated_eid_seconds_server, TRACKER_SLOT_WINDOW_SIZE
from SpotApi.CreateBleDevice.util import hours_to_seconds
from SpotApi.spot_request import spot_request
from Auth.token_cache import get_cached_value, set_cached_value, get_cached_json_value
from SpotApi.CreateBleDevice.config import TRACKER_WINDOW_SIZES_CACHE_KEY


LAST_UPLOAD_TIMESTAMP_KEY = "upload_precomputed_public_key_ids_last_updated"
UPLOAD_TTL_SECONDS = 24 * 60 * 60
LEGACY_TRACKER_SLOT_COUNT = ceil(max_truncated_eid_seconds_server / ROTATION_PERIOD)


def _resolve_tracker_window_size(device_name: str) -> int:
    tracker_window_sizes = get_cached_json_value(TRACKER_WINDOW_SIZES_CACHE_KEY, default={})
    if isinstance(tracker_window_sizes, dict):
        value = tracker_window_sizes.get(device_name)
        try:
            if value is not None:
                parsed = int(value)
                if parsed > 0:
                    return parsed
        except (TypeError, ValueError):
            pass

    # If cache was lost but the tracker follows compound naming, keep wrapped behavior.
    if re.match(r"^\[OTB-C\] .+_[0-9]+$", device_name):
        return TRACKER_SLOT_WINDOW_SIZE

    # Legacy trackers should keep legacy horizon sizing.
    return LEGACY_TRACKER_SLOT_COUNT


def refresh_custom_trackers(device_list: DevicesList, force_upload: bool = False):

    if not force_upload and _is_recent_upload():
        print(
            "[UploadPrecomputedPublicKeyIds] Skipping refresh; last update was less "
            "than 24 hours ago. Use --force-upload-keys to override."
        )
        return

    request = UploadPrecomputedPublicKeyIdsRequest()
    needs_upload = False

    for device in device_list.deviceMetadata:

        # This is a microcontroller
        if is_mcu_tracker(device.information.deviceRegistration):

            needs_upload = True
            identity_key = retrieve_identity_key(device.information.deviceRegistration)

            if device.identifierInformation.type == DeviceUpdate_pb2.IDENTIFIER_ANDROID:
                canonic_ids = device.identifierInformation.phoneInformation.canonicIds.canonicId
            else:
                canonic_ids = device.identifierInformation.canonicIds.canonicId

            for canonic_id in canonic_ids:
                new_truncated_ids = UploadPrecomputedPublicKeyIdsRequest.DevicePublicKeyIds()
                new_truncated_ids.pairDate = device.information.deviceRegistration.pairDate
                new_truncated_ids.canonicId.id = canonic_id.id

                next_eids = get_next_eids(
                    identity_key,
                    new_truncated_ids.pairDate,
                    int(time.time() - hours_to_seconds(3)),
                    duration_seconds=max_truncated_eid_seconds_server,
                    window_size=_resolve_tracker_window_size(device.userDefinedDeviceName),
                )

                for next_eid in next_eids:
                    new_truncated_ids.clientList.publicKeyIdInfo.append(next_eid)

                request.deviceEids.append(new_truncated_ids)

    if needs_upload:
        print("[UploadPrecomputedPublicKeyIds] Updating your registered µC devices...")
        try:
            bytes_data = request.SerializeToString()
            spot_request("UploadPrecomputedPublicKeyIds", bytes_data)
            _set_last_upload_timestamp()
        except Exception as e:
            print(f"[UploadPrecomputedPublicKeyIds] Failed to refresh custom trackers. Please file a bug report. Continuing... {str(e)}")


def get_next_eids(
    eik: bytes,
    pair_date: int,
    start_date: int,
    duration_seconds: int,
    window_size: int = TRACKER_SLOT_WINDOW_SIZE,
) -> list[PublicKeyIdList.PublicKeyIdInfo]:
    duration_seconds = int(duration_seconds)
    window_size = max(1, int(window_size))
    public_key_id_list = []

    wrapped_eids = [
        generate_eid(eik, pair_date + i * ROTATION_PERIOD)
        for i in range(window_size)
    ]

    start_offset = start_date - pair_date
    current_time_offset = start_offset - (start_offset % ROTATION_PERIOD)

    while current_time_offset <= start_offset + duration_seconds:
        slot = (current_time_offset // ROTATION_PERIOD) % window_size
        timestamp = pair_date + current_time_offset
        evolved_eid = wrapped_eids[slot]

        info = PublicKeyIdList.PublicKeyIdInfo()
        info.timestamp.seconds = timestamp
        info.publicKeyId.truncatedEid = evolved_eid[:10]

        public_key_id_list.append(info)

        current_time_offset += ROTATION_PERIOD

    return public_key_id_list


def _is_recent_upload() -> bool:
    last_upload = get_cached_value(LAST_UPLOAD_TIMESTAMP_KEY)
    if last_upload is None:
        return False
    try:
        last_upload = int(last_upload)
    except (TypeError, ValueError):
        return False
    return (int(time.time()) - last_upload) < UPLOAD_TTL_SECONDS


def _set_last_upload_timestamp() -> None:
    set_cached_value(LAST_UPLOAD_TIMESTAMP_KEY, int(time.time()))