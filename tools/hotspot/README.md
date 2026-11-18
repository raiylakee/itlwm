# Hotspot control for AirportItlwm

A userspace app that talks directly to a user client exposed by the
AirportItlwm kext, bypassing airportd's HostAP policy gate. This is the
"expose something out of the driver and communicate through userspace" path.

## Why this exists

Apple's `apple80211` control path is closed to ordinary processes on modern
macOS: the BSD socket ioctl returns `ENOTSUP`, and the real channel
(`IO80211APIUserClient`) is entitlement-gated to airportd. So a plain app
cannot ask the driver to start an AP through Apple's API.

The driver already has a complete exclusive-AP implementation. This change
publishes it through an `IOUserClient` owned by *our* kext, which any local
process can open with `IOServiceOpen()` — no entitlement, no airportd, no
Internet Sharing.

## What changed in the kext

- `AirportItlwm/ItlHotspotUserClient.{hpp,cpp}` — `IOUserClient` with three
  external methods: start AP, stop AP, status. It forwards to the driver's
  own `setSSID` / `setCHANNEL` / `setAP_MODE`, in that order (`setAP_MODE`
  last, since it is the request that actually starts the AP).
- `include/ItlHotspotShared.h` — the userspace/kext wire protocol, shared by
  both sides.
- `AirportItlwm/*Info.plist` and `AirportItlwm/WCL/*Info.plist` — register
  `IOUserClientClass = ItlHotspotUserClient` on the `AirportItlwm`
  personality, so `IOServiceOpen()` creates the client.
- `itlwm.xcodeproj/project.pbxproj` — add the two new files to the build.

## Build and install

Build the kext (full Xcode required) using the target for your macOS version,
for example on Sequoia:

```sh
xcodebuild -project itlwm.xcodeproj -scheme AirportItlwm-Sequoia \
  -configuration Release ARCHS=x86_64 CODE_SIGNING_ALLOWED=NO build
```

Install the rebuilt kext the same way you installed AirportItlwm originally
(OpenCore / kextutil), reboot, and confirm the user client is published:

```sh
ioreg -r -c AirportItlwm | grep IOUserClientClass
# should print: "IOUserClientClass" = "ItlHotspotUserClient"
```

Build the userspace tool:

```sh
cd tools/hotspot
clang -Wall -Wextra -framework Foundation -framework IOKit \
  -I../../include -o hotspot hotspot.m
```

## Usage

```sh
./hotspot probe              # driver opmode / state / SSID / channel
./hotspot start MyHotspot 6  # start the AP on channel 6
./hotspot stop               # stop the AP, return to station mode
```

`probe` is read-only. It is the first thing to run after rebooting into the
rebuilt kext: if `IOServiceOpen` succeeds, the control channel works.

## Important limitations

- **Open network only.** The kext's AP path does not set a passphrase, and the
  WPA2 4-way authenticator is not wired up in this driver. The password you
  supplied earlier cannot be used by this AP. WPA2 would need the
  authenticator handshake implemented in the kext.
- **Exclusive AP.** Starting the AP tears down any station association. The
  shared upstream connection must come from a different interface (Ethernet
  or USB tether) with NAT configured. This cannot repeat Wi-Fi to Wi-Fi on
  the single radio.
- **Local build required.** The kext must be rebuilt from this tree and
  loaded; the currently loaded kext does not contain the user client. This
  environment has only Command Line Tools, so the kext build has to happen
  on the Mac with full Xcode.
