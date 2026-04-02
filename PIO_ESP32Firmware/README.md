# Find My Device ESP32 Firmware

This code enables you to use an ESP32-device as a custom Google Find My Device tracker. Note that the firmware is very minimal and serves as a proof of concept to test the system end to end. For a more practical tag hardware and firmware package check out [OpenTag](https://github.com/Cuprum77/OpenTag).

The ESP32 firmware works differently to regular Find My Device trackers. It is made to be as simple as possible. It has no Fast Pair support and only rotates a set number of pre-defined keys instead of using a dynamic key rotation mechanism based on the current time (since that would require a synchronized clock).

## How to use

- Run the Python Script [`main.py`](../main.py) in the parent folder. Follow the instructions of the [README of the parent folder](../README.md).
- When the device list is displayed, press 'r' to register a new ESP32/MCU device in your account, enter the name and an image url if you wish.
- Wait for the key to generate, then create a new file called `secret.h` under the src folder of this firmware folder and insert the code from the `secret-example.h` file, replacing the values with the ones retrieved from the Python Script. The file should look like this:
```c
#pragma once

// 16-bit count of rotating advertisement keys.
const unsigned short eid_key_count = 338;

// Concatenated hex string for all 20-byte EIDs (40 hex chars per key).
// Example for one key:
// "00112233445566778899aabbccddeeff00112233"
const char *eid_keys_hex = "001122..."
```

- Install Visual Studio Code [here](https://code.visualstudio.com/download)
- Install the [PlatformIO extension](https://platformio.org/install/ide?install=vscode)
- Open the folder containing this README file in Visual Studio Code, PlatformIO should automatically detect the project and install the necessary dependencies (this may take a few minutes). If it doesn't detect the project, you can click on the PlatformIO icon on the left sidebar and click "Open Project" to select the folder. 
- Connect your ESP32 to your system with USB.
- On the bottom left of Visual Studio Code, click the 'right arrow' icon and it should compile and flash the firmware to your ESP32. (On linux you might need to install udev rules as described [here](https://docs.platformio.org/en/stable/core/installation/udev-rules.html))
- After flashing, the ESP32 will restart and start advertising as the Find My Device tracker previously registered and rotate the keys and MAC every 1024 seconds by default.
- You can use the [STBLEToolbox](https://www.st.com/en/embedded-software/stbletoolbox.html) to verify that advertising is working and inspect the advertised data.

## Known Issues

- You need to run [`main.py`](../main.py) every 4 days to keep receiving location reports from the server. This is because the advertisements have to be "announced" to Google. 
- Might not work with 'fresh' Google accounts: "Your encryption data is locked on your device" is shown if you have never paired a Find My Device tracker with an Android device. Solution: See [README of the parent folder](../README.md).
- You cannot view locations for the ESP32 in the Google Find My Device app. You will need to use the Python script to do so.
- The firmware was built to receive as many network reports as possible. Therefore, it might consume more power than necessary. To fix this you'd need to implement a more complex sleeping mechanism and wake the ESP32 up to broadcast periodically. See [OpenTag](https://github.com/Cuprum77/OpenTag) for proper tag hardware and firmware implementations compatible with this project.

