#
#  GoogleFindMyTools - A set of tools to interact with the Google Find My API
#  Copyright © 2024 Leon Böttger. All rights reserved.
#

import argparse

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="GoogleFindMyTools entrypoint.")
    parser.add_argument(
        "--canonic-id",
        dest="canonic_id",
        help="Query a specific tracker by canonic ID and skip the interactive prompt.",
    )
    parser.add_argument(
        "--force-upload-keys",
        dest="force_upload_keys",
        action="store_true",
        help="Force UploadPrecomputedPublicKeyIds even if a recent upload was recorded.",
    )

    # Intentionally hidden: used to gate tag creation behind someone reading the code.
    parser.add_argument(
        "--iwillnotstalk",
        "-iwns",
        dest="iwillnotstalk",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()

    from NovaApi.ListDevices.nbe_list_devices import list_devices

    list_devices(
        target_canonic_id=args.canonic_id,
        force_upload_keys=args.force_upload_keys,
        allow_device_registration=args.iwillnotstalk,
    )
