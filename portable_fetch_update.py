#!/usr/bin/env python3
"""Portable location fetch and update script.

This script is self-contained and does not import project modules.

Required pip packages:
- requests
- beautifulsoup4
- gpsoauth
- protobuf
- grpcio-tools
- firebase-messaging
- pycryptodomex
- cryptography
- ecdsa

Example:
# fetch locations for a specific canonic ID (tracker):
python fetch_location_minimal.py --canonic-id <CANONIC_ID> --auth-file ./secrets.json
# list cached canonic IDs and compounds:
python fetch_location_minimal.py --auth-file ./secrets.json
# fetch locations for a compound tracker:
python fetch_location_minimal.py --compound "Compound Name" --auth-file ./secrets.json
# refresh announcements
python fetch_location_minimal.py --refresh-announcements --auth-file ./secrets.json
"""

import argparse
import asyncio
import base64
import datetime
import hashlib
import importlib
import inspect
import json
import os
import re
import sys
import tempfile
import threading
import time
import uuid
from math import ceil
from pathlib import Path

gpsoauth = None
requests = None
BeautifulSoup = None
httpx = None
AES = None
hashes = None
AESGCM = None
HKDF = None
SECP160r1 = None
Point = None
FcmPushClient = None
FcmRegisterConfig = None
protoc = None


def _load_runtime_dependencies(*, need_protoc: bool = False, need_fcm: bool = False) -> None:
    global FcmPushClient, FcmRegisterConfig, protoc

    if need_fcm and (FcmPushClient is None or FcmRegisterConfig is None):
        import_errors = []
        for module_name in ("firebase_messaging", "Auth.firebase_messaging"):
            try:
                firebase_messaging = importlib.import_module(module_name)
                FcmPushClient = firebase_messaging.FcmPushClient
                FcmRegisterConfig = firebase_messaging.FcmRegisterConfig
                break
            except Exception as exc:
                import_errors.append((module_name, exc))

        if FcmPushClient is None or FcmRegisterConfig is None:
            tried = ", ".join(name for name, _ in import_errors)
            raise RuntimeError(
                "Missing dependency: firebase-messaging. "
                f"Interpreter: {sys.executable}. Tried imports: {tried}"
            ) from import_errors[-1][1]

    if need_protoc and protoc is None:
        try:
            grpc_tools = importlib.import_module("grpc_tools.protoc")
            protoc = grpc_tools
        except Exception as exc:
            raise RuntimeError("Missing dependency: grpcio-tools") from exc


def _load_fetch_dependencies() -> None:
    global gpsoauth, requests, BeautifulSoup, httpx, AES, hashes, AESGCM, HKDF, SECP160r1, Point

    if gpsoauth is None:
        try:
            gpsoauth = importlib.import_module("gpsoauth")
        except Exception as exc:
            raise RuntimeError("Missing dependency: gpsoauth") from exc

    if requests is None:
        try:
            requests = importlib.import_module("requests")
        except Exception as exc:
            raise RuntimeError("Missing dependency: requests") from exc

    if BeautifulSoup is None:
        try:
            bs4_module = importlib.import_module("bs4")
            BeautifulSoup = bs4_module.BeautifulSoup
        except Exception as exc:
            raise RuntimeError("Missing dependency: beautifulsoup4") from exc

    if httpx is None:
        try:
            httpx = importlib.import_module("httpx")
        except Exception as exc:
            raise RuntimeError("Missing dependency: httpx") from exc

    if AES is None:
        import_errors = []
        for module_name in ("Cryptodome.Cipher.AES", "Crypto.Cipher.AES"):
            try:
                aes_module = importlib.import_module(module_name)
                AES = aes_module
                break
            except Exception as exc:
                import_errors.append((module_name, exc))

        if AES is None:
            tried = ", ".join(name for name, _ in import_errors)
            raise RuntimeError(
                "Missing AES dependency. Install pycryptodomex or pycryptodome. "
                f"Interpreter: {sys.executable}. Tried imports: {tried}"
            ) from import_errors[-1][1]

    if hashes is None:
        try:
            hashes = importlib.import_module("cryptography.hazmat.primitives.hashes")
        except Exception as exc:
            raise RuntimeError("Missing dependency: cryptography") from exc

    if AESGCM is None:
        try:
            aead_module = importlib.import_module("cryptography.hazmat.primitives.ciphers.aead")
            AESGCM = aead_module.AESGCM
        except Exception as exc:
            raise RuntimeError("Missing dependency: cryptography") from exc

    if HKDF is None:
        try:
            hkdf_module = importlib.import_module("cryptography.hazmat.primitives.kdf.hkdf")
            HKDF = hkdf_module.HKDF
        except Exception as exc:
            raise RuntimeError("Missing dependency: cryptography") from exc

    if SECP160r1 is None or Point is None:
        try:
            ecdsa_module = importlib.import_module("ecdsa")
            curve_module = importlib.import_module("ecdsa.ellipticcurve")
            SECP160r1 = ecdsa_module.SECP160r1
            Point = curve_module.Point
        except Exception as exc:
            raise RuntimeError("Missing dependency: ecdsa") from exc


COMMON_PROTO = r'''syntax = "proto3";

message Time {
    uint32 seconds = 1;
    uint32 nanos = 2;
}

message LocationReport {
  SemanticLocation semanticLocation = 5;
  GeoLocation geoLocation = 10;
  Status status = 11;
}

message SemanticLocation {
  string locationName = 1;
}

enum Status {
  SEMANTIC = 0;
  LAST_KNOWN = 1;
  CROWDSOURCED = 2;
  AGGREGATED = 3;
}

message GeoLocation {
  EncryptedReport encryptedReport = 1;
  uint32 deviceTimeOffset = 2;
  float accuracy = 3;
}

message EncryptedReport {
    bytes publicKeyRandom = 1;
    bytes encryptedLocation = 2;
    bool isOwnReport = 3;
}
'''


DEVICE_UPDATE_PROTO = r'''syntax = "proto3";
import "ProtoDecoders/Common.proto";

message DeviceTypeInformation {
  SpotDeviceType deviceType = 2;
}

enum DeviceType {
    UNKNOWN_DEVICE_TYPE = 0;
    ANDROID_DEVICE = 1;
    SPOT_DEVICE = 2;
}

message ExecuteActionRequest {
    ExecuteActionScope scope = 1;
    ExecuteActionType action = 2;
    ExecuteActionRequestMetadata requestMetadata = 3;
}

message ExecuteActionRequestMetadata {
  DeviceType type = 1;
  string requestUuid = 2;
  string fmdClientUuid = 3;
  GcmCloudMessagingIdProtobuf gcmRegistrationId = 4;
  bool unknown = 6;
}

message GcmCloudMessagingIdProtobuf {
  string id = 1;
}

message ExecuteActionType {
  ExecuteActionLocateTrackerType locateTracker = 30;
}

message ExecuteActionLocateTrackerType {
  Time lastHighTrafficEnablingTime = 2;
  SpotContributorType contributorType = 3;
}

enum SpotContributorType {
    FMDN_DISABLED_DEFAULT = 0;
    FMDN_ALL_LOCATIONS = 2;
}

message ExecuteActionScope {
    DeviceType type = 2;
    ExecuteActionDeviceIdentifier device = 3;
}

message ExecuteActionDeviceIdentifier {
  CanonicId canonicId = 1;
}

message DevicesList {
    repeated DeviceMetadata deviceMetadata = 2;
}

message DevicesListRequest {
    DevicesListRequestPayload deviceListRequestPayload = 1;
}

message DevicesListRequestPayload {
    DeviceType type = 1;
    string id = 3;
}

message DeviceUpdate {
    ExecuteActionRequestMetadata fcmMetadata = 1;
    DeviceMetadata deviceMetadata = 3;
}

message DeviceMetadata {
    IdentitfierInformation identifierInformation = 1;
  DeviceInformation information = 4;
  string userDefinedDeviceName = 5;
}

message IdentitfierInformation {
    PhoneInformation phoneInformation = 1;
    IdentifierInformationType type = 2;
    CanonicIds canonicIds = 3;
}

enum IdentifierInformationType {
    IDENTIFIER_UNKNOWN = 0;
    IDENTIFIER_ANDROID = 1;
    IDENTIFIER_SPOT = 2;
}

message PhoneInformation {
    CanonicIds canonicIds = 2;
}

message CanonicIds {
    repeated CanonicId canonicId = 1;
}

message DeviceInformation {
  DeviceRegistration deviceRegistration = 1;
  LocationInformation locationInformation = 2;
}

message DeviceRegistration {
  EncryptedUserSecrets encryptedUserSecrets = 19;
  string fastPairModelId = 21;
  int32 pairDate = 23;
}

message EncryptedUserSecrets {
  bytes encryptedIdentityKey = 1;
  int32 ownerKeyVersion = 3;
}

message LocationInformation {
  LocationsAndTimestampsWrapper reports = 3;
}

message LocationsAndTimestampsWrapper {
  RecentLocationAndNetworkLocations recentLocationAndNetworkLocations = 4;
}

message RecentLocationAndNetworkLocations {
  LocationReport recentLocation = 1;
  Time recentLocationTimestamp = 2;
  repeated LocationReport networkLocations = 5;
  repeated Time networkLocationTimestamps = 6;
}

enum SpotDeviceType {
    DEVICE_TYPE_UNKNOWN = 0;
}

message CanonicId {
  string id = 1;
}

message PublicKeyIdList {
    repeated PublicKeyIdInfo publicKeyIdInfo = 1;

    message PublicKeyIdInfo {
        Time timestamp = 1;
        TruncatedEID publicKeyId = 2;
        int32 trackableComponent = 3;
    }
}

message TruncatedEID {
    bytes truncatedEid = 1;
}

message UploadPrecomputedPublicKeyIdsRequest {
    repeated DevicePublicKeyIds deviceEids = 1;

    message DevicePublicKeyIds {
        CanonicId canonicId = 1;
        PublicKeyIdList clientList = 2;
        int32 pairDate = 3;
    }
}

message Location {
    sfixed32 latitude = 1;
    sfixed32 longitude = 2;
    int32 altitude = 3;
}
'''


CANONIC_IDS_CACHE_KEY = "canonic_ids_v1"
COMPOUND_TRACKERS_CACHE_KEY = "compound_trackers_v1"
TRACKER_WINDOW_SIZES_CACHE_KEY = "tracker_window_sizes_v1"
MCU_FAST_PAIR_MODEL_ID = "003200"
ROTATION_PERIOD = 1024
MAX_TRUNCATED_EID_SECONDS_SERVER = 4 * 24 * 3600
TRACKER_SLOT_WINDOW_SIZE = 32
LAST_UPLOAD_TIMESTAMP_KEY = "upload_precomputed_public_key_ids_last_updated"
UPLOAD_TTL_SECONDS = 24 * 60 * 60


def _load_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_json(path: Path, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


def _get_cached_json(auth_data: dict, key: str, default):
    value = auth_data.get(key)
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return default


def _extract_response_canonic_ids(DeviceUpdate_pb2, device_update) -> list[str]:
    identifier = device_update.deviceMetadata.identifierInformation
    if identifier.type == DeviceUpdate_pb2.IDENTIFIER_ANDROID:
        canonic_ids = identifier.phoneInformation.canonicIds.canonicId
    else:
        canonic_ids = identifier.canonicIds.canonicId
    return [item.id for item in canonic_ids if item.id]


def _update_canonic_ids_cache(auth_data: dict, auth_path: Path, discovered_rows: list[dict]) -> None:
    current_cache = _get_cached_json(auth_data, CANONIC_IDS_CACHE_KEY, default={})
    if not isinstance(current_cache, dict):
        current_cache = {}

    entries = current_cache.get("entries", [])
    if not isinstance(entries, list):
        entries = []

    by_id = {
        entry.get("canonic_id"): entry
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("canonic_id"), str)
    }

    now_ts = int(time.time())
    for row in discovered_rows:
        canonic_id = row.get("canonic_id")
        if not canonic_id:
            continue

        existing = by_id.get(canonic_id, {})
        existing["canonic_id"] = canonic_id
        existing["name"] = row.get("name") or existing.get("name") or "Unknown"
        existing["last_seen"] = now_ts
        by_id[canonic_id] = existing

    merged_entries = sorted(by_id.values(), key=lambda item: item.get("name", ""))
    auth_data[CANONIC_IDS_CACHE_KEY] = json.dumps({"entries": merged_entries})
    _save_json(auth_path, auth_data)


def _is_recent_upload(auth_data: dict) -> bool:
    last_upload = auth_data.get(LAST_UPLOAD_TIMESTAMP_KEY)
    if last_upload is None:
        return False
    try:
        last_upload = int(last_upload)
    except (TypeError, ValueError):
        return False
    return (int(time.time()) - last_upload) < UPLOAD_TTL_SECONDS


def _set_last_upload_timestamp(auth_data: dict, auth_path: Path) -> None:
    auth_data[LAST_UPLOAD_TIMESTAMP_KEY] = int(time.time())
    _save_json(auth_path, auth_data)


def _list_cached_canonic_ids(auth_data: dict) -> bool:
    compound_payload = _get_cached_json(auth_data, COMPOUND_TRACKERS_CACHE_KEY, default={})
    compounds = compound_payload.get("compounds", {}) if isinstance(compound_payload, dict) else {}
    if not isinstance(compounds, dict):
        compounds = {}

    cache_payload = _get_cached_json(auth_data, CANONIC_IDS_CACHE_KEY, default={})
    if not isinstance(cache_payload, dict):
        cache_payload = {}

    entries = cache_payload.get("entries", [])
    if not isinstance(entries, list):
        entries = []

    normalized_entries = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        canonic_id = entry.get("canonic_id")
        name = entry.get("name", "Unknown")
        if isinstance(canonic_id, str) and canonic_id:
            normalized_entries.append({"canonic_id": canonic_id, "name": str(name)})

    if not normalized_entries:
        print("No cached canonic IDs found in auth file.")
        if compounds:
            print("")
            print("Compound trackers found in auth metadata:")
            for _, compound in sorted(compounds.items(), key=lambda item: item[0]):
                if not isinstance(compound, dict):
                    continue
                base_name = compound.get("base_name", "Unknown")
                print(f"[Compound] {base_name}")
                subtags = compound.get("subtags", [])
                if isinstance(subtags, list):
                    for subtag in subtags:
                        if isinstance(subtag, dict):
                            subtag_name = subtag.get("name", "Unknown")
                            print(f"  {subtag_name}: <canonic-id-not-cached>")
            print("")
        print("Run once with --canonic-id to cache tracker names/IDs for future startup listing.")
        return False

    by_name = {}
    for row in normalized_entries:
        by_name.setdefault(row["name"], []).append(row)

    used_ids = set()
    printed_any = False

    for _, compound in sorted(compounds.items(), key=lambda item: item[0]):
        if not isinstance(compound, dict):
            continue

        base_name = compound.get("base_name")
        subtags = compound.get("subtags", [])
        if not isinstance(base_name, str) or not isinstance(subtags, list):
            continue

        matched = []
        for subtag in subtags:
            if not isinstance(subtag, dict):
                continue
            subtag_name = subtag.get("name")
            if not isinstance(subtag_name, str):
                continue
            for row in by_name.get(subtag_name, []):
                if row["canonic_id"] not in used_ids:
                    matched.append(row)

        if matched:
            printed_any = True
            print(f"[Compound] {base_name}")
            for row in matched:
                used_ids.add(row["canonic_id"])
                print(f"  {row['name']}: {row['canonic_id']}")

    singles = [row for row in normalized_entries if row["canonic_id"] not in used_ids]
    if singles:
        printed_any = True
        if used_ids:
            print("")
        print("[Single trackers]")
        for row in sorted(singles, key=lambda item: item["name"]):
            print(f"{row['name']}: {row['canonic_id']}")

    if printed_any:
        print("")
        print("Raw canonic IDs:")
        for row in sorted(normalized_entries, key=lambda item: item["canonic_id"]):
            print(row["canonic_id"])

    return printed_any


def _build_cached_listing_payload(auth_data: dict) -> dict:
    compound_payload = _get_cached_json(auth_data, COMPOUND_TRACKERS_CACHE_KEY, default={})
    compounds = compound_payload.get("compounds", {}) if isinstance(compound_payload, dict) else {}
    if not isinstance(compounds, dict):
        compounds = {}

    cache_payload = _get_cached_json(auth_data, CANONIC_IDS_CACHE_KEY, default={})
    entries = cache_payload.get("entries", []) if isinstance(cache_payload, dict) else []
    if not isinstance(entries, list):
        entries = []

    normalized_entries = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        canonic_id = entry.get("canonic_id")
        name = entry.get("name", "Unknown")
        if isinstance(canonic_id, str) and canonic_id:
            normalized_entries.append({"canonic_id": canonic_id, "name": str(name)})

    by_name = {}
    for row in normalized_entries:
        by_name.setdefault(row["name"], []).append(row["canonic_id"])

    compound_results = []
    used_ids = set()

    for _, compound in sorted(compounds.items(), key=lambda item: item[0]):
        if not isinstance(compound, dict):
            continue
        base_name = compound.get("base_name")
        subtags = compound.get("subtags", [])
        if not isinstance(base_name, str) or not isinstance(subtags, list):
            continue

        subtag_results = []
        for subtag in subtags:
            if not isinstance(subtag, dict):
                continue
            subtag_name = subtag.get("name")
            if not isinstance(subtag_name, str):
                continue
            ids = by_name.get(subtag_name, [])
            for canonic_id in ids:
                used_ids.add(canonic_id)
            subtag_results.append({
                "name": subtag_name,
                "canonic_ids": ids,
            })

        compound_results.append(
            {
                "base_name": base_name,
                "subtags": subtag_results,
            }
        )

    single_results = [
        row for row in sorted(normalized_entries, key=lambda item: item["name"])
        if row["canonic_id"] not in used_ids
    ]

    return {
        "mode": "list",
        "timestamp_unix": int(time.time()),
        "compounds": compound_results,
        "singles": single_results,
        "raw_canonic_ids": sorted(row["canonic_id"] for row in normalized_entries),
    }


def _resolve_compound_targets(auth_data: dict, compound_name: str) -> list[dict]:
    compound_payload = _get_cached_json(auth_data, COMPOUND_TRACKERS_CACHE_KEY, default={})
    compounds = compound_payload.get("compounds", {}) if isinstance(compound_payload, dict) else {}
    if not isinstance(compounds, dict):
        compounds = {}

    cache_payload = _get_cached_json(auth_data, CANONIC_IDS_CACHE_KEY, default={})
    entries = cache_payload.get("entries", []) if isinstance(cache_payload, dict) else []
    if not isinstance(entries, list):
        entries = []

    by_name = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        canonic_id = entry.get("canonic_id")
        name = entry.get("name")
        if isinstance(canonic_id, str) and canonic_id and isinstance(name, str):
            by_name.setdefault(name, []).append(canonic_id)

    matching_compounds = []
    for _, compound in sorted(compounds.items(), key=lambda item: item[0]):
        if not isinstance(compound, dict):
            continue
        if compound.get("base_name") == compound_name:
            matching_compounds.append(compound)

    if not matching_compounds:
        raise RuntimeError(
            f"Compound '{compound_name}' not found in auth metadata. Run without arguments to list available compounds."
        )

    targets = []
    missing_subtags = []

    for compound in matching_compounds:
        subtags = compound.get("subtags", [])
        if not isinstance(subtags, list):
            continue
        for subtag in subtags:
            if not isinstance(subtag, dict):
                continue
            subtag_name = subtag.get("name")
            if not isinstance(subtag_name, str):
                continue

            ids = by_name.get(subtag_name, [])
            if not ids:
                missing_subtags.append(subtag_name)
                continue

            for canonic_id in ids:
                targets.append({
                    "display_name": subtag_name,
                    "canonic_id": canonic_id,
                })

    if missing_subtags:
        missing_joined = ", ".join(sorted(set(missing_subtags)))
        raise RuntimeError(
            "Missing cached canonic IDs for subtags: "
            f"{missing_joined}. Run main.py once to refresh canonic_ids_v1 cache."
        )

    if not targets:
        raise RuntimeError(
            f"No canonic IDs resolved for compound '{compound_name}'."
        )

    return targets


def _compile_and_import_protos(cache_root: Path):
    # Prefer local generated protobuf modules when available (repo mode).
    try:
        Common_pb2 = importlib.import_module("ProtoDecoders.Common_pb2")
        DeviceUpdate_pb2 = importlib.import_module("ProtoDecoders.DeviceUpdate_pb2")
        return Common_pb2, DeviceUpdate_pb2
    except Exception:
        pass

    _load_runtime_dependencies(need_protoc=True)
    if protoc is None:
        raise RuntimeError(
            "Missing dependency: grpcio-tools (required only outside repository mode)."
        )

    proto_root = cache_root / "otb_portable_protos"
    out_root = proto_root / "generated"
    source_root = proto_root / "src"
    proto_decoders = source_root / "ProtoDecoders"

    proto_decoders.mkdir(parents=True, exist_ok=True)
    out_root.mkdir(parents=True, exist_ok=True)

    common_proto_path = proto_decoders / "Common.proto"
    device_proto_path = proto_decoders / "DeviceUpdate.proto"
    common_proto_path.write_text(COMMON_PROTO, encoding="utf-8")
    device_proto_path.write_text(DEVICE_UPDATE_PROTO, encoding="utf-8")

    rc = protoc.main([
        "grpc_tools.protoc",
        f"-I{source_root}",
        f"--python_out={out_root}",
        str(common_proto_path),
        str(device_proto_path),
    ])
    if rc != 0:
        raise RuntimeError("Failed to compile protobuf schemas with grpcio-tools.")

    sys.path.insert(0, str(out_root))
    Common_pb2 = importlib.import_module("ProtoDecoders.Common_pb2")
    DeviceUpdate_pb2 = importlib.import_module("ProtoDecoders.DeviceUpdate_pb2")
    return Common_pb2, DeviceUpdate_pb2


def _calculate_r(identity_key: bytes, timestamp: int, k: int = 10) -> int:
    _load_fetch_dependencies()
    if AES is None or SECP160r1 is None:
        raise RuntimeError("Missing crypto dependencies")

    aes_cls = AES
    curve = SECP160r1

    timestamp_masked = timestamp & ~((1 << k) - 1)
    ts_bytes = timestamp_masked.to_bytes(4, byteorder="big")

    data = bytearray(32)
    data[0:11] = b"\xFF" * 11
    data[11] = k
    data[12:16] = ts_bytes
    data[16:27] = b"\x00" * 11
    data[27] = k
    data[28:32] = ts_bytes

    cipher = aes_cls.new(identity_key, aes_cls.MODE_ECB)
    r_dash = cipher.encrypt(bytes(data))
    r_dash_int = int.from_bytes(r_dash, byteorder="big", signed=False)

    return r_dash_int % curve.order


def _generate_eid(identity_key: bytes, timestamp: int) -> bytes:
    _load_fetch_dependencies()
    if SECP160r1 is None:
        raise RuntimeError("Missing ECDSA dependency")

    curve = SECP160r1
    r = _calculate_r(identity_key, timestamp)
    r_point = r * curve.generator
    return r_point.x().to_bytes(20, "big")


def _get_next_eids(
    DeviceUpdate_pb2,
    identity_key: bytes,
    pair_date: int,
    start_date: int,
    duration_seconds: int,
    window_size: int,
):
    duration_seconds = int(duration_seconds)
    window_size = max(1, int(window_size))
    public_key_id_list = []

    wrapped_eids = [
        _generate_eid(identity_key, pair_date + i * ROTATION_PERIOD)
        for i in range(window_size)
    ]

    start_offset = start_date - pair_date
    current_time_offset = start_offset - (start_offset % ROTATION_PERIOD)

    while current_time_offset <= start_offset + duration_seconds:
        slot = (current_time_offset // ROTATION_PERIOD) % window_size
        timestamp = pair_date + current_time_offset
        evolved_eid = wrapped_eids[slot]

        info = DeviceUpdate_pb2.PublicKeyIdList.PublicKeyIdInfo()
        info.timestamp.seconds = int(timestamp)
        info.publicKeyId.truncatedEid = evolved_eid[:10]
        public_key_id_list.append(info)

        current_time_offset += ROTATION_PERIOD

    return public_key_id_list


def _rx_to_ry(rx: int, curve) -> int:
    ryy = (rx ** 3 + curve.a() * rx + curve.b()) % curve.p()
    ry = pow(ryy, (curve.p() + 1) // 4, curve.p())
    if (ry * ry) % curve.p() != ryy:
        raise ValueError("Invalid curve point from EID/public key")
    if ry % 2 != 0:
        ry = curve.p() - ry
    return ry


def _decrypt_foreign_location(identity_key: bytes, encrypted_and_tag: bytes, sx_bytes: bytes, beacon_counter: int) -> bytes:
    _load_fetch_dependencies()
    if AES is None or HKDF is None or hashes is None or SECP160r1 is None or Point is None:
        raise RuntimeError("Missing crypto dependencies")

    aes_cls = AES
    hkdf_cls = HKDF
    hashes_mod = hashes
    curve = SECP160r1
    point_cls = Point

    m_dash = encrypted_and_tag[:-16]
    tag = encrypted_and_tag[-16:]

    r = _calculate_r(identity_key, beacon_counter)
    r_point = r * curve.generator

    sx = int.from_bytes(sx_bytes, byteorder="big")
    sy = _rx_to_ry(sx, curve.curve)
    s_point = point_cls(curve.curve, sx, sy)

    hkdf = hkdf_cls(algorithm=hashes_mod.SHA256(), length=32, salt=None, info=b"")
    k = hkdf.derive((r * s_point).x().to_bytes(20, "big"))

    lrx = r_point.x().to_bytes(20, "big")[12:]
    lsx = s_point.x().to_bytes(20, "big")[12:]
    nonce = lrx + lsx

    cipher = aes_cls.new(k, aes_cls.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(m_dash, tag)


def _is_mcu_tracker(device_registration) -> bool:
    return device_registration.fastPairModelId == MCU_FAST_PAIR_MODEL_ID


def _resolve_tracker_window_size(auth_data: dict, device_name: str) -> int:
    tracker_window_sizes = _get_cached_json(auth_data, TRACKER_WINDOW_SIZES_CACHE_KEY, default={})
    if isinstance(tracker_window_sizes, dict):
        value = tracker_window_sizes.get(device_name)
        try:
            if value is not None:
                parsed = int(value)
                if parsed > 0:
                    return parsed
        except (TypeError, ValueError):
            pass

    if re.match(r"^\[OTB-C\] .+_[0-9]+$", device_name):
        return TRACKER_SLOT_WINDOW_SIZE

    return ceil(MAX_TRUNCATED_EID_SECONDS_SERVER / ROTATION_PERIOD)


def _decrypt_mcu_with_slot_fallback(
    identity_key: bytes,
    encrypted_location: bytes,
    public_key_random: bytes,
    reported_time_offset: int,
    pair_date: int,
    window_size: int,
) -> tuple[bytes, int, int | None]:
    # First try reported counter, then fallback counters compatible with wrapped MCU slots.
    counters_to_try = [int(reported_time_offset)]

    slot_count = ceil(MAX_TRUNCATED_EID_SECONDS_SERVER / ROTATION_PERIOD)
    for i in range(slot_count):
        counters_to_try.append(pair_date + i * ROTATION_PERIOD)
        counters_to_try.append(i * ROTATION_PERIOD)

    unique_counters = []
    seen = set()
    for counter in counters_to_try:
        if counter not in seen:
            seen.add(counter)
            unique_counters.append(counter)

    for counter in unique_counters:
        try:
            decrypted = _decrypt_foreign_location(identity_key, encrypted_location, public_key_random, counter)
            decoded_slot = None
            if counter >= pair_date:
                delta = counter - pair_date
                if delta % ROTATION_PERIOD == 0 and delta >= 0:
                    decoded_slot = (delta // ROTATION_PERIOD) % max(1, int(window_size))
            return decrypted, counter, decoded_slot
        except ValueError as exc:
            if str(exc) != "MAC check failed":
                raise

    raise ValueError("MAC check failed")


def _decrypt_own_location(identity_key: bytes, encrypted_data_with_iv: bytes) -> bytes:
    _load_fetch_dependencies()
    if AESGCM is None:
        raise RuntimeError("Missing crypto dependencies")

    aesgcm_cls = AESGCM

    key = hashlib.sha256(identity_key).digest()
    iv = encrypted_data_with_iv[:12]
    ciphertext = encrypted_data_with_iv[12:]
    return aesgcm_cls(key).decrypt(iv, ciphertext, None)


def _cached_identity_key(auth_data: dict, device_registration) -> bytes:
    encrypted_identity_key = device_registration.encryptedUserSecrets.encryptedIdentityKey
    owner_key_version = device_registration.encryptedUserSecrets.ownerKeyVersion

    # Custom MCU trackers invert bits before decryption/cache derivation.
    if device_registration.fastPairModelId == "003200":
        encrypted_identity_key = bytes(b ^ 0xFF for b in encrypted_identity_key)

    cache_hash = hashlib.sha256(encrypted_identity_key).hexdigest()
    cache_name = f"identity_key_{owner_key_version}_{cache_hash}"
    cached_hex = auth_data.get(cache_name)
    if not cached_hex:
        raise RuntimeError(
            "Identity key is not present in auth file cache. "
            "Run the full OpenTagBridge flow once to populate identity_key_* entries."
        )
    return bytes.fromhex(cached_hex)


class PortableFcmReceiver:
    def __init__(self, auth_data: dict, auth_file: Path) -> None:
        _load_runtime_dependencies(need_fcm=True)
        if FcmPushClient is None or FcmRegisterConfig is None:
            raise RuntimeError("Missing dependency: firebase-messaging")

        fcm_register_config_cls = FcmRegisterConfig
        fcm_push_client_cls = FcmPushClient

        self.auth_data = auth_data
        self.auth_file = auth_file
        self.credentials = auth_data.get("fcm_credentials")
        self.location_callbacks = []
        self._listening = False
        self._loop = None
        self._loop_thread = None

        base_config_kwargs = {
            "project_id": "google.com:api-project-289722593072",
            "app_id": "1:289722593072:android:3cfcf5bc359f0308",
            "api_key": "AIzaSyD_gko3P392v6how2H7UpdeXQ0v2HLettc",
            "messaging_sender_id": "289722593072",
            "bundle_id": "com.google.android.apps.adm",
            "android_package": "com.google.android.apps.adm",
            "android_cert_sha1": "38918a453d07199354f8b19af05ec6562ced5788",
        }

        # Some firebase_messaging builds expose different constructor signatures.
        cfg_sig = inspect.signature(fcm_register_config_cls)
        cfg_kwargs = {
            key: value
            for key, value in base_config_kwargs.items()
            if key in cfg_sig.parameters
        }
        fcm_config = fcm_register_config_cls(**cfg_kwargs)

        push_sig = inspect.signature(fcm_push_client_cls)
        if "credentials_updated_callback" in push_sig.parameters:
            self.pc = fcm_push_client_cls(
                self._on_notification,
                fcm_config,
                self.credentials,
                credentials_updated_callback=self._on_credentials_updated,
            )
        else:
            self.pc = fcm_push_client_cls(
                self._on_notification,
                fcm_config,
                self.credentials,
                self._on_credentials_updated,
            )

    def _on_credentials_updated(self, creds: dict) -> None:
        self.credentials = creds
        self.auth_data["fcm_credentials"] = creds
        _save_json(self.auth_file, self.auth_data)

    def _on_notification(self, obj: dict, notification, data_message) -> None:
        data = obj.get("data", {})
        payload_b64 = data.get("com.google.android.apps.adm.FCM_PAYLOAD")
        if not payload_b64:
            return

        payload_hex = base64.b64decode(payload_b64).hex()
        for callback in self.location_callbacks:
            callback(payload_hex)

    async def _register_for_fcm(self) -> None:
        while True:
            try:
                await self.pc.checkin_or_register()
                return
            except Exception:
                await self.pc.stop()
                await asyncio.sleep(3)

    def _run_event_loop(self) -> None:
        if self._loop is None:
            return
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _start_listener_in_background(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(target=self._run_event_loop, daemon=True)
        self._loop_thread.start()

        temp_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(temp_loop)
        temp_loop.run_until_complete(self._register_for_fcm())
        temp_loop.close()

        asyncio.run_coroutine_threadsafe(self.pc.start(), self._loop)
        self._listening = True

    def get_android_id(self) -> str:
        if self.credentials is None:
            self._start_listener_in_background()
        if self.credentials is None:
            raise RuntimeError("Unable to initialize FCM credentials")
        return self.credentials["gcm"]["android_id"]

    def register_for_location_updates(self, callback) -> str:
        if not self._listening:
            self._start_listener_in_background()
        self.location_callbacks.append(callback)
        if self.credentials is None:
            raise RuntimeError("Unable to initialize FCM credentials")
        return self.credentials["fcm"]["registration"]["token"]

    def stop_listening(self) -> None:
        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self.pc.stop(), self._loop)


def _get_adm_token(auth_data: dict, receiver: PortableFcmReceiver) -> str:
    _load_fetch_dependencies()
    if gpsoauth is None:
        raise RuntimeError("Missing dependency: gpsoauth")

    gpsoauth_mod = gpsoauth

    username = auth_data.get("username", "")
    aas_token = auth_data.get("aas_token")
    if not username or not aas_token:
        raise RuntimeError("Auth file must contain 'username' and 'aas_token'.")

    android_id = receiver.get_android_id()
    auth_response = gpsoauth_mod.perform_oauth(
        username,
        aas_token,
        android_id,
        service="oauth2:https://www.googleapis.com/auth/android_device_manager",
        app="com.google.android.apps.adm",
        client_sig="38918a453d07199354f8b19af05ec6562ced5788",
    )
    token = auth_response.get("Auth")
    if not token:
        raise RuntimeError(f"Failed to get ADM token: {auth_response}")
    return token


def _get_spot_token(auth_data: dict, receiver: PortableFcmReceiver) -> str:
    _load_fetch_dependencies()
    if gpsoauth is None:
        raise RuntimeError("Missing dependency: gpsoauth")

    gpsoauth_mod = gpsoauth

    username = auth_data.get("username", "")
    aas_token = auth_data.get("aas_token")
    if not username or not aas_token:
        raise RuntimeError("Auth file must contain 'username' and 'aas_token'.")

    android_id = receiver.get_android_id()
    auth_response = gpsoauth_mod.perform_oauth(
        username,
        aas_token,
        android_id,
        service="oauth2:https://www.googleapis.com/auth/spot",
        app="com.google.android.gms",
        client_sig="38918a453d07199354f8b19af05ec6562ced5788",
    )
    token = auth_response.get("Auth")
    if not token:
        raise RuntimeError(f"Failed to get Spot token: {auth_response}")
    return token


def _construct_grpc(payload: bytes) -> bytes:
    length = len(payload).to_bytes(4, byteorder="big", signed=False)
    return b"\x00" + length + payload


def _extract_grpc_payload(grpc_payload: bytes) -> bytes:
    if len(grpc_payload) < 5:
        raise ValueError("Invalid gRPC payload")
    length = int.from_bytes(grpc_payload[1:5], byteorder="big", signed=False)
    if len(grpc_payload) < 5 + length:
        raise ValueError("Invalid gRPC payload length")
    return grpc_payload[5:5 + length]


def _spot_request(api_scope: str, payload: bytes, spot_token: str) -> bytes:
    _load_fetch_dependencies()
    if httpx is None or BeautifulSoup is None:
        raise RuntimeError("Missing network dependencies")

    httpx_mod = httpx
    bs4_cls = BeautifulSoup

    url = f"https://spot-pa.googleapis.com/google.internal.spot.v1.SpotService/{api_scope}"
    headers = {
        "User-Agent": "com.google.android.gms/244433022 grpc-java-cronet/1.69.0-SNAPSHOT",
        "Content-Type": "application/grpc",
        "Te": "trailers",
        "Authorization": f"Bearer {spot_token}",
        "Grpc-Accept-Encoding": "gzip",
    }

    grpc_payload = _construct_grpc(payload)
    with httpx_mod.Client(http2=True, timeout=30.0) as client:
        response = client.post(url, headers=headers, content=grpc_payload)

    if response.status_code != 200:
        soup = bs4_cls(response.text, "html.parser")
        raise RuntimeError(f"Spot request failed ({response.status_code}): {soup.get_text()}")

    return _extract_grpc_payload(response.content)


def _extract_device_canonic_ids(DeviceUpdate_pb2, device) -> list[str]:
    if device.identifierInformation.type == DeviceUpdate_pb2.IDENTIFIER_ANDROID:
        canonic_ids = device.identifierInformation.phoneInformation.canonicIds.canonicId
    else:
        canonic_ids = device.identifierInformation.canonicIds.canonicId
    return [canonic_id.id for canonic_id in canonic_ids if canonic_id.id]


def _create_device_list_request(DeviceUpdate_pb2) -> bytes:
    wrapper = DeviceUpdate_pb2.DevicesListRequest()
    wrapper.deviceListRequestPayload.type = DeviceUpdate_pb2.SPOT_DEVICE
    wrapper.deviceListRequestPayload.id = str(uuid.uuid4())
    return wrapper.SerializeToString()


def _cache_canonic_ids_from_device_list(auth_data: dict, auth_path: Path, DeviceUpdate_pb2, device_list) -> None:
    discovered_rows = []
    for device in device_list.deviceMetadata:
        device_name = device.userDefinedDeviceName or "Unknown"
        for canonic_id in _extract_device_canonic_ids(DeviceUpdate_pb2, device):
            discovered_rows.append({"name": device_name, "canonic_id": canonic_id})

    if discovered_rows:
        _update_canonic_ids_cache(auth_data, auth_path, discovered_rows)


def _refresh_precomputed_key_announcements(
    auth_data: dict,
    auth_path: Path,
    DeviceUpdate_pb2,
    timeout_seconds: int,
    force_upload: bool,
) -> dict:
    if not force_upload and _is_recent_upload(auth_data):
        return {
            "refreshed": False,
            "skipped": True,
            "reason": "last_upload_less_than_24h",
            "devices_considered": 0,
            "devices_uploaded": 0,
        }

    receiver = PortableFcmReceiver(auth_data, auth_path)
    adm_token = _get_adm_token(auth_data, receiver)
    spot_token = _get_spot_token(auth_data, receiver)

    list_payload = _create_device_list_request(DeviceUpdate_pb2)
    device_list_hex = _nova_request("nbe_list_devices", list_payload, adm_token)
    device_list = DeviceUpdate_pb2.DevicesList()
    device_list.ParseFromString(bytes.fromhex(device_list_hex))

    _cache_canonic_ids_from_device_list(auth_data, auth_path, DeviceUpdate_pb2, device_list)

    upload_request = DeviceUpdate_pb2.UploadPrecomputedPublicKeyIdsRequest()
    devices_considered = 0
    devices_uploaded = 0

    for device in device_list.deviceMetadata:
        if not _is_mcu_tracker(device.information.deviceRegistration):
            continue

        devices_considered += 1
        identity_key = _cached_identity_key(auth_data, device.information.deviceRegistration)
        pair_date = int(device.information.deviceRegistration.pairDate)
        window_size = _resolve_tracker_window_size(auth_data, device.userDefinedDeviceName)

        for canonic_id in _extract_device_canonic_ids(DeviceUpdate_pb2, device):
            device_entry = DeviceUpdate_pb2.UploadPrecomputedPublicKeyIdsRequest.DevicePublicKeyIds()
            device_entry.pairDate = pair_date
            device_entry.canonicId.id = canonic_id

            next_eids = _get_next_eids(
                DeviceUpdate_pb2,
                identity_key,
                pair_date,
                int(time.time() - 3 * 3600),
                MAX_TRUNCATED_EID_SECONDS_SERVER,
                window_size,
            )

            for next_eid in next_eids:
                device_entry.clientList.publicKeyIdInfo.append(next_eid)

            upload_request.deviceEids.append(device_entry)
            devices_uploaded += 1

    if devices_uploaded == 0:
        receiver.stop_listening()
        return {
            "refreshed": False,
            "skipped": True,
            "reason": "no_mcu_trackers_or_ids",
            "devices_considered": devices_considered,
            "devices_uploaded": 0,
        }

    _spot_request("UploadPrecomputedPublicKeyIds", upload_request.SerializeToString(), spot_token)
    _set_last_upload_timestamp(auth_data, auth_path)
    receiver.stop_listening()

    return {
        "refreshed": True,
        "skipped": False,
        "devices_considered": devices_considered,
        "devices_uploaded": devices_uploaded,
    }


def _nova_request(api_scope: str, payload: bytes, adm_token: str) -> str:
    _load_fetch_dependencies()
    if requests is None or BeautifulSoup is None:
        raise RuntimeError("Missing network dependencies")

    requests_mod = requests
    bs4_cls = BeautifulSoup

    response = requests_mod.post(
        f"https://android.googleapis.com/nova/{api_scope}",
        headers={
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Authorization": f"Bearer {adm_token}",
            "Accept-Language": "en-US",
            "User-Agent": "fmd/20006320; gzip",
        },
        data=payload,
        timeout=30,
    )
    if response.status_code != 200:
        soup = bs4_cls(response.text, "html.parser")
        raise RuntimeError(f"Nova request failed ({response.status_code}): {soup.get_text()}")
    return response.content.hex()


def _create_location_request(DeviceUpdate_pb2, canonic_id: str, fcm_registration_id: str, request_uuid: str, client_uuid: str) -> bytes:
    action_request = DeviceUpdate_pb2.ExecuteActionRequest()
    action_request.scope.type = DeviceUpdate_pb2.SPOT_DEVICE
    action_request.scope.device.canonicId.id = canonic_id

    action_request.requestMetadata.type = DeviceUpdate_pb2.SPOT_DEVICE
    action_request.requestMetadata.requestUuid = request_uuid
    action_request.requestMetadata.fmdClientUuid = client_uuid
    action_request.requestMetadata.gcmRegistrationId.id = fcm_registration_id
    action_request.requestMetadata.unknown = True

    action_request.action.locateTracker.lastHighTrafficEnablingTime.seconds = 1732120060
    action_request.action.locateTracker.contributorType = DeviceUpdate_pb2.FMDN_ALL_LOCATIONS

    return action_request.SerializeToString()


def _collect_locations(Common_pb2, DeviceUpdate_pb2, device_update, auth_data: dict) -> dict:
    locations_proto = device_update.deviceMetadata.information.locationInformation.reports.recentLocationAndNetworkLocations
    network_locations = list(locations_proto.networkLocations)
    network_times = list(locations_proto.networkLocationTimestamps)

    if locations_proto.HasField("recentLocation"):
        network_locations.append(locations_proto.recentLocation)
        network_times.append(locations_proto.recentLocationTimestamp)

    device_registration = device_update.deviceMetadata.information.deviceRegistration
    device_name = device_update.deviceMetadata.userDefinedDeviceName or "Unknown"
    is_mcu = _is_mcu_tracker(device_registration)
    window_size = _resolve_tracker_window_size(auth_data, device_name)
    result = {
        "device_name": device_name,
        "is_mcu": is_mcu,
        "window_size": window_size,
        "locations": [],
        "decrypt_failures": [],
    }

    if not network_locations:
        return result

    identity_key = _cached_identity_key(auth_data, device_registration)

    for loc, ts in zip(network_locations, network_times):
        status_name = Common_pb2.Status.Name(loc.status) if loc.status in Common_pb2.Status.values() else "UNKNOWN"
        report_time_unix = int(ts.seconds)
        report_time = datetime.datetime.fromtimestamp(report_time_unix).strftime("%Y-%m-%d %H:%M:%S")

        if loc.status == Common_pb2.SEMANTIC:
            result["locations"].append(
                {
                    "type": "semantic",
                    "name": loc.semanticLocation.locationName,
                    "time_unix": report_time_unix,
                    "time_local": report_time,
                    "status": status_name,
                }
            )
            continue

        encrypted_report = loc.geoLocation.encryptedReport
        encrypted_location = encrypted_report.encryptedLocation
        public_key_random = encrypted_report.publicKeyRandom

        try:
            if public_key_random:
                if is_mcu:
                    decrypted, decoded_counter, decoded_slot = _decrypt_mcu_with_slot_fallback(
                        identity_key,
                        encrypted_location,
                        public_key_random,
                        int(loc.geoLocation.deviceTimeOffset),
                        int(device_registration.pairDate),
                        window_size,
                    )
                else:
                    decrypted = _decrypt_foreign_location(
                        identity_key,
                        encrypted_location,
                        public_key_random,
                        int(loc.geoLocation.deviceTimeOffset),
                    )
                    decoded_counter = int(loc.geoLocation.deviceTimeOffset)
                    decoded_slot = None
            else:
                decrypted = _decrypt_own_location(identity_key, encrypted_location)
                decoded_counter = None
                decoded_slot = None
        except Exception as exc:
            result["decrypt_failures"].append(
                {
                    "time_unix": report_time_unix,
                    "time_local": report_time,
                    "error": str(exc),
                    "status": status_name,
                }
            )
            continue

        parsed = DeviceUpdate_pb2.Location()
        parsed.ParseFromString(decrypted)

        latitude = parsed.latitude / 1e7
        longitude = parsed.longitude / 1e7
        result["locations"].append(
            {
                "type": "geo",
                "latitude": latitude,
                "longitude": longitude,
                "altitude": parsed.altitude,
                "time_unix": report_time_unix,
                "time_local": report_time,
                "status": status_name,
                "decoded_counter": decoded_counter,
                "decoded_slot": decoded_slot,
                "google_maps": f"https://www.google.com/maps/search/?api=1&query={latitude},{longitude}",
            }
        )

    return result


def _print_locations_summary(collected: dict) -> None:
    if not collected["locations"] and not collected["decrypt_failures"]:
        print("No locations found.")
        return

    if collected.get("is_mcu"):
        print(f"[MCU fallback] Enabled for {collected.get('device_name', 'Unknown')} (window={collected.get('window_size')})")

    print("-" * 40)
    print("Decrypted Locations")
    print("-" * 40)

    for entry in collected["locations"]:
        if entry["type"] == "semantic":
            print(f"Semantic: {entry['name']}")
            print(f"Time: {entry['time_local']}")
            print(f"Status: {entry['status']}")
            print("-" * 40)
            continue

        print(f"Latitude: {entry['latitude']}")
        print(f"Longitude: {entry['longitude']}")
        print(f"Altitude: {entry['altitude']}")
        print(f"Time: {entry['time_local']}")
        print(f"Status: {entry['status']}")
        if entry.get("decoded_counter") is not None:
            print(f"Decoded Counter: {entry['decoded_counter']}")
        if entry.get("decoded_slot") is not None:
            print(f"Decoded Slot: {entry['decoded_slot']}")
        print(f"Google Maps: {entry['google_maps']}")
        print("-" * 40)

    for failure in collected["decrypt_failures"]:
        print(f"Failed to decrypt report at {failure['time_local']}: {failure['error']}")
        print("-" * 40)


def _fetch_for_canonic_id(
    auth_data: dict,
    auth_path: Path,
    Common_pb2,
    DeviceUpdate_pb2,
    canonic_id: str,
    timeout_seconds: int,
    label: str | None = None,
    human_output: bool = True,
) -> dict:
    receiver = PortableFcmReceiver(auth_data, auth_path)
    request_uuid = str(uuid.uuid4())
    client_uuid = str(uuid.uuid4())
    result_holder = {"result": None}

    def handle_location_response(response_hex: str) -> None:
        device_update = DeviceUpdate_pb2.DeviceUpdate()
        device_update.ParseFromString(bytes.fromhex(response_hex))
        if device_update.fcmMetadata.requestUuid == request_uuid:
            result_holder["result"] = device_update

    fcm_token = receiver.register_for_location_updates(handle_location_response)
    adm_token = _get_adm_token(auth_data, receiver)
    payload = _create_location_request(DeviceUpdate_pb2, canonic_id, fcm_token, request_uuid, client_uuid)

    _nova_request("nbe_execute_action", payload, adm_token)

    start = time.time()
    while result_holder["result"] is None and (time.time() - start) < timeout_seconds:
        time.sleep(0.1)

    receiver.stop_listening()

    if result_holder["result"] is None:
        raise TimeoutError(f"Timed out waiting for matching FCM location response for {canonic_id}.")

    discovered_name = result_holder["result"].deviceMetadata.userDefinedDeviceName or "Unknown"
    discovered_ids = _extract_response_canonic_ids(DeviceUpdate_pb2, result_holder["result"])
    if canonic_id not in discovered_ids:
        discovered_ids.append(canonic_id)

    _update_canonic_ids_cache(
        auth_data,
        auth_path,
        [{"name": discovered_name, "canonic_id": discovered_id} for discovered_id in discovered_ids],
    )

    if label and human_output:
        print("")
        print("=" * 60)
        print(f"Tracker: {label} | Canonic ID: {canonic_id}")
        print("=" * 60)

    collected = _collect_locations(Common_pb2, DeviceUpdate_pb2, result_holder["result"], auth_data)
    if human_output:
        _print_locations_summary(collected)

    return {
        "requested_canonic_id": canonic_id,
        "label": label,
        "resolved_device_name": discovered_name,
        "resolved_canonic_ids": discovered_ids,
        "result": collected,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Portable OpenTagBridge location fetcher.")
    parser.add_argument("--canonic-id", help="Tracker canonic ID.")
    parser.add_argument("--compound-name", help="Fetch all subtags for a compound tracker base name.")
    parser.add_argument("--auth-file", default="./secrets.json", help="Path to auth/secrets JSON.")
    parser.add_argument("--timeout", type=int, default=45, help="Seconds to wait for location response.")
    parser.add_argument("--json", dest="json_output", action="store_true", help="Output machine-readable JSON payload.")
    parser.add_argument("--refresh-announcements", action="store_true", help="Upload precomputed key announcements (24h TTL by default).")
    parser.add_argument("--force-upload", action="store_true", help="Force announcement upload even if last upload was under 24h ago.")
    args = parser.parse_args()

    auth_path = Path(args.auth_file)
    if not auth_path.exists():
        raise FileNotFoundError(f"Auth file not found: {auth_path}")

    auth_data = _load_json(auth_path)

    if args.canonic_id and args.compound_name:
        raise RuntimeError("Use either --canonic-id or --compound-name, not both.")

    if args.refresh_announcements and (args.canonic_id or args.compound_name):
        raise RuntimeError("--refresh-announcements cannot be combined with --canonic-id or --compound-name.")

    if args.force_upload and not args.refresh_announcements:
        raise RuntimeError("--force-upload is only valid with --refresh-announcements.")

    if not args.canonic_id and not args.compound_name:
        if args.refresh_announcements:
            _load_fetch_dependencies()
            cache_root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
            _, DeviceUpdate_pb2 = _compile_and_import_protos(cache_root)
            refresh_result = _refresh_precomputed_key_announcements(
                auth_data,
                auth_path,
                DeviceUpdate_pb2,
                args.timeout,
                args.force_upload,
            )
            if args.json_output:
                print(json.dumps({
                    "mode": "refresh_announcements",
                    "timestamp_unix": int(time.time()),
                    **refresh_result,
                }))
            else:
                if refresh_result.get("skipped"):
                    print(f"Announcement refresh skipped: {refresh_result.get('reason')}")
                else:
                    print(
                        "Announcement refresh complete. "
                        f"devices_considered={refresh_result.get('devices_considered')} "
                        f"devices_uploaded={refresh_result.get('devices_uploaded')}"
                    )
            return

        if args.json_output:
            print(json.dumps(_build_cached_listing_payload(auth_data)))
            return

        _list_cached_canonic_ids(auth_data)
        return

    _load_fetch_dependencies()

    cache_root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    Common_pb2, DeviceUpdate_pb2 = _compile_and_import_protos(cache_root)
    fetch_payload = {
        "mode": "compound" if args.compound_name else "single",
        "timestamp_unix": int(time.time()),
        "targets": [],
    }

    if args.compound_name:
        targets = _resolve_compound_targets(auth_data, args.compound_name)
        fetch_payload["compound_name"] = args.compound_name
        if not args.json_output:
            print(f"Fetching {len(targets)} subtags for compound: {args.compound_name}")
        for target in targets:
            item = _fetch_for_canonic_id(
                auth_data,
                auth_path,
                Common_pb2,
                DeviceUpdate_pb2,
                target["canonic_id"],
                args.timeout,
                label=target["display_name"],
                human_output=not args.json_output,
            )
            fetch_payload["targets"].append(item)

        if args.json_output:
            print(json.dumps(fetch_payload))
        return

    item = _fetch_for_canonic_id(
        auth_data,
        auth_path,
        Common_pb2,
        DeviceUpdate_pb2,
        args.canonic_id,
        args.timeout,
        human_output=not args.json_output,
    )
    fetch_payload["targets"].append(item)
    if args.json_output:
        print(json.dumps(fetch_payload))


if __name__ == "__main__":
    main()
