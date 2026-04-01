#
#  GoogleFindMyTools - A set of tools to interact with the Google Find My API
#  Copyright © 2024 Leon Böttger. All rights reserved.
#

class WrappedLocation:
    def __init__(self, decrypted_location, time, accuracy, status, is_own_report, name, decoded_counter=None, decoded_slot=None):
        self.time = time
        self.status = status
        self.decrypted_location = decrypted_location
        self.is_own_report = is_own_report
        self.accuracy = accuracy
        self.name = name
        self.decoded_counter = decoded_counter
        self.decoded_slot = decoded_slot