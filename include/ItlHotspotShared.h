/*
 * ItlHotspotShared.h - userspace <-> ItlHotspotUserClient wire protocol.
 *
 * Included by both the kext (AirportItlwmSkywalkInterface.cpp) and the
 * userspace tool (tools/hotspot/hotspot.m).  Keep the structs in sync.
 *
 * The user client is an IOUserClient published by the AirportItlwm kext via
 * the IOUserClientClass property.  Userspace opens it with IOServiceOpen()
 * and calls these selectors with IOConnectCallStructMethod().  This bypasses
 * airportd entirely: we call the driver's own setSSID/setCHANNEL/setAP_MODE
 * methods, which are the same ones airportd reaches through IO80211Family.
 */
#ifndef ITL_HOTSPOT_SHARED_H
#define ITL_HOTSPOT_SHARED_H

#include <stdint.h>

#define ITL_HOTSPOT_VERSION 1

/* externalMethod selectors (IOConnectCallStructMethod selector) */
enum {
    kItlHotspotStartAP = 0,
    kItlHotspotStopAP  = 1,
    kItlHotspotStatus  = 2,
    kItlHotspotNumMethods
};

/* kItlHotspotStartAP input */
struct itl_hotspot_start {
    uint32_t version;
    uint32_t ssid_len;      /* 1..32 */
    uint8_t  ssid[32];
    uint32_t channel;       /* wifi channel number; 0 => default 6 */
    uint32_t password_len;  /* 0 = open AP, else 8..63 (WPA2 passphrase) */
    uint8_t  password[64];  /* ASCII passphrase; NUL terminator not required */
    uint32_t reserved[4];
};

/* kItlHotspotStatus output */
struct itl_hotspot_status {
    uint32_t version;
    uint32_t opmode;        /* ieee80211_opmode: 1=STA, 6=HOSTAP */
    uint32_t state;         /* ieee80211_state: 0=INIT .. 4=RUN */
    uint32_t ssid_len;
    uint8_t  ssid[32];
    uint32_t channel;
    uint32_t reserved[4];
};

#endif /* ITL_HOTSPOT_SHARED_H */
