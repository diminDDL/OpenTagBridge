#
#  GoogleFindMyTools - A set of tools to interact with the Google Find My API
#  Copyright © 2024 Leon Böttger. All rights reserved.
#

from SpotApi.CreateBleDevice.util import hours_to_seconds

mcu_fast_pair_model_id = "003200"
max_truncated_eid_seconds_server = hours_to_seconds(4*24)

# Google currently accepts reports in a bounded window around expected time slots.
# Keep virtual tracker slot windows small and fixed.
TRACKER_SLOT_WINDOW_SIZE = 32
COMPOUND_TRACKER_PREFIX = "[OTB-C] "  # Open Tag Bridge Compound (arbitrary prefix to identify compound trackers)
COMPOUND_TRACKERS_CACHE_KEY = "compound_trackers_v1"
TRACKER_WINDOW_SIZES_CACHE_KEY = "tracker_window_sizes_v1"