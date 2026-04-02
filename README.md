# OpenTagBridge

This is a fork of "[GoogleFindMyTools](https://github.com/leonboe1/GoogleFindMyTools)" by [Leon Böttger  (leonboe1)](https://github.com/leonboe1).

Below are the changes compared to the original repository:
- Fixed Google Chrome Login procedure
- Added ESP32 Firmware that uses PlatformIO
- Added a cache for tag keys to make location fetching faster
- Added a basic key rotation implementation

--- 

This repository includes some useful tools that reimplement parts of Google's Find My Device Network (now called Find Hub Network). Note that the code of this repo is still **still** very experimental.

### What's possible?
Currently, it is possible to query Find My Device / Find Hub trackers and Android devices, read out their E2EE keys, and decrypt encrypted locations sent from the Find My Device / Find Hub network. You can also send register your own ESP32- trackers, as described below.

### How to use

> [!CAUTION]
> Before starting, ensure you have Chrome and Python updated.
> 
> ~~**If Chrome is not up to date, the script will NOT work, guaranteed!** [1]~~ 

[1] **Should work fine with any semi modern Chrome version now.**

- Clone this repository: `git clone` or download the ZIP file
- Change into the directory: `cd OpenTagBridge`
- Optional: Create venv: `python -m venv venv`
- Optional: Activate venv: `venv\Scripts\activate` (Windows) or `source venv/bin/activate` (Linux & macOS)
- Install all required packages: `pip install -r requirements.txt`
- Install the latest version of Google Chrome: https://www.google.com/chrome/
- Start the program by running [main.py](main.py): `python main.py` or `python3 main.py`

### Authentication

On the first run, an authentication sequence is executed, which requires a computer with access to Google Chrome.

The authentication results are stored in `Auth/secrets.json`. If you intend to run this tool on a headless machine (server implementation WIP), you can just copy this file to avoid having to use Chrome.

### Known Issues
- "Your encryption data is locked on your device" is shown if you have never set up Find My Device on an Android device. Solution: Login with your Google Account on an Android device, go to Settings > Google > All Services > Find My Device > Find your offline devices > enable "With network in all areas" or "With network in high-traffic areas only". If "Find your offline devices" is not shown in Settings, you will need to download the Find My Device app from Google's Play Store, and pair a real Find My Device tracker with your device to force-enable the Find My Device network. And/or logging into a different Android phone and setting up Find Hub there again (with the "Find your offline devices" settings enabled) with the account you wish to use set as the primary one also worked sometimes during testing.
- No support for trackers using the P-256 curve and 32-Byte advertisements. Regular trackers don't seem to use this curve at all - it is only confirmed that it is used with Sony's WH1000XM5 headphones.
- No support for the authentication process on ARM Linux
- If you receive "ssl.SSLCertVerificationError" when running the script, try to follow [this answer](https://stackoverflow.com/a/53310545).
- Please also consider the issues listed in the [README in the ESP32Firmware folder](PIO_ESP32Firmware/README.md) if you want to register custom trackers.

### Firmware for custom ESP32-based trackers
For more information, check the [README in the PIO_ESP32Firmware folder](PIO_ESP32Firmware/README.md).


### iOS App
~~You can also use this [iOS App](https://testflight.apple.com/join/rGqa2mTe) to access your Find My Device trackers on the go.~~

Doesn't work with the key rotation implemented here.
