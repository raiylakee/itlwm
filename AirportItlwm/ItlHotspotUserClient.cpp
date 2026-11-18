/*
 * ItlHotspotUserClient.cpp - expose the driver's software-AP controls to a
 * userspace process, bypassing airportd's HostAP policy gate.
 *
 * The driver already contains a complete exclusive-AP implementation
 * (setSSID / setCHANNEL / setAP_MODE -> startAPMode -> ic_ap_start_pending).
 * The only reason a userspace app could not reach it is that Apple's
 * apple80211 ioctl path is closed to ordinary processes on modern macOS
 * (ENOTSUP on the BSD socket, and IO80211APIUserClient is entitlement-gated
 * to airportd).  An IOUserClient published by *our* kext has neither problem.
 *
 * This client simply forwards to the same public methods airportd would
 * call, in the same order: SSID, channel, then AP mode last (setAP_MODE is
 * the gate that flips apModeRequested and starts the AP).
 */
#include "ItlHotspotUserClient.hpp"

#include <IOKit/IOLib.h>
#include <net80211/ieee80211_var.h>

#define super IOUserClient
OSDefineMetaClassAndStructors(ItlHotspotUserClient, IOUserClient)

bool
ItlHotspotUserClient::start(IOService *provider)
{
    if (!super::start(provider))
        return false;

    fController = OSDynamicCast(AirportItlwm, provider);
    if (!fController) {
        IOLog("ItlHotspotUserClient: provider is not AirportItlwm\n");
        super::stop(provider);
        return false;
    }

    /* fNetIf is created in AirportItlwm::start(), which has already run by
     * the time IOServiceOpen can reach us. */
    fSkywalk = static_cast<AirportItlwmSkywalkInterface *>(fController->fNetIf);
    if (!fSkywalk) {
        IOLog("ItlHotspotUserClient: no Skywalk interface on provider\n");
        super::stop(provider);
        return false;
    }
    /* startAPMode/stopAPMode dereference the HAL controller.  Fail closed
     * rather than panic if the driver is not fully brought up. */
    if (!fController->fHalService ||
        !fController->fHalService->get80211Controller()) {
        IOLog("ItlHotspotUserClient: no HAL controller on provider\n");
        super::stop(provider);
        return false;
    }

    IOLog("ItlHotspotUserClient: connected\n");
    return true;
}

void
ItlHotspotUserClient::stop(IOService *provider)
{
    fSkywalk = nullptr;
    fController = nullptr;
    super::stop(provider);
}

IOReturn
ItlHotspotUserClient::startAP(const itl_hotspot_start *in)
{
    if (!in || !fSkywalk)
        return kIOReturnBadArgument;
    if (in->version != ITL_HOTSPOT_VERSION)
        return kIOReturnBadArgument;
    if (in->ssid_len == 0 || in->ssid_len > 32)
        return kIOReturnBadArgument;

    /* Validate the channel here because the driver's setCHANNEL() silently
     * accepts an unusable channel and returns success.  Channel numbers are
     * 1..IEEE80211_CHAN_MAX (255); 0 means "use the default". */
    uint32_t channel = in->channel ? in->channel : 6;
    if (channel > IEEE80211_CHAN_MAX)
        return kIOReturnBadArgument;

    apple80211_ssid_data sd;
    memset(&sd, 0, sizeof(sd));
    sd.version = APPLE80211_VERSION;
    sd.ssid_len = in->ssid_len;
    memcpy(sd.ssid_bytes, in->ssid, in->ssid_len);
    IOReturn r = fSkywalk->setSSID(&sd);
    if (r != kIOReturnSuccess)
        return r;

    apple80211_channel_data cd;
    memset(&cd, 0, sizeof(cd));
    cd.version = APPLE80211_VERSION;
    cd.channel.version = APPLE80211_VERSION;
    cd.channel.channel = channel;
    /* 2.4 GHz channels are 1..14; 5 GHz channels start at 36. */
    cd.channel.flags = APPLE80211_C_FLAG_ACTIVE |
        (channel >= 36 ? APPLE80211_C_FLAG_5GHZ : APPLE80211_C_FLAG_2GHZ);
    r = fSkywalk->setCHANNEL(&cd);
    if (r != kIOReturnSuccess)
        return r;

    /* AP_MODE last: this is the request that actually starts the AP. */
    apple80211_apmode_data ad;
    memset(&ad, 0, sizeof(ad));
    ad.version = APPLE80211_VERSION;
    ad.apmode = APPLE80211_AP_MODE_INFRA;
    r = fSkywalk->setAP_MODE(&ad);
    if (r != kIOReturnSuccess)
        return r;

    IOLog("ItlHotspotUserClient: AP start requested (ssid_len=%u ch=%u)\n",
          in->ssid_len, channel);
    return kIOReturnSuccess;
}

IOReturn
ItlHotspotUserClient::stopAP()
{
    if (!fSkywalk || !fController->fHalService)
        return kIOReturnNotReady;

    apple80211_apmode_data ad;
    memset(&ad, 0, sizeof(ad));
    ad.version = APPLE80211_VERSION;
    ad.apmode = APPLE80211_AP_MODE_UNKNOWN;
    fSkywalk->setAP_MODE(&ad);

    IOLog("ItlHotspotUserClient: AP stop requested\n");
    return kIOReturnSuccess;
}

IOReturn
ItlHotspotUserClient::status(itl_hotspot_status *out)
{
    if (!out || !fController || !fController->fHalService)
        return kIOReturnNotReady;

    struct ieee80211com *ic = fController->fHalService->get80211Controller();
    if (!ic)
        return kIOReturnNotReady;

    memset(out, 0, sizeof(*out));
    out->version = ITL_HOTSPOT_VERSION;
    out->opmode = (uint32_t)ic->ic_opmode;
    out->state = (uint32_t)ic->ic_state;

    uint32_t n = ic->ic_des_esslen;
    if (n > 32) n = 32;
    out->ssid_len = n;
    if (n) memcpy(out->ssid, ic->ic_des_essid, n);

    /* ieee80211_channel has no number field; report the frequency in MHz.
     * 2.4 GHz channel n is 2412 + 5*(n-1); the tool converts back. */
    if (ic->ic_des_chan && ic->ic_des_chan != IEEE80211_CHAN_ANYC)
        out->channel = ic->ic_des_chan->ic_freq;

    return kIOReturnSuccess;
}

IOReturn
ItlHotspotUserClient::externalMethod(uint32_t selector,
                                     IOExternalMethodArguments *arguments,
                                     IOExternalMethodDispatch *dispatch,
                                     OSObject *target, void *reference)
{
    (void)dispatch;
    (void)target;
    (void)reference;

    if (!arguments)
        return kIOReturnBadArgument;

    switch (selector) {
        case kItlHotspotStartAP: {
            if (!arguments->structureInput ||
                arguments->structureInputSize < sizeof(itl_hotspot_start))
                return kIOReturnBadArgument;
            return startAP(
                reinterpret_cast<const itl_hotspot_start *>(arguments->structureInput));
        }
        case kItlHotspotStopAP:
            return stopAP();
        case kItlHotspotStatus: {
            if (!arguments->structureOutput ||
                arguments->structureOutputSize < sizeof(itl_hotspot_status))
                return kIOReturnBadArgument;
            return status(
                reinterpret_cast<itl_hotspot_status *>(arguments->structureOutput));
        }
        default:
            return super::externalMethod(selector, arguments, nullptr, this, nullptr);
    }
}
