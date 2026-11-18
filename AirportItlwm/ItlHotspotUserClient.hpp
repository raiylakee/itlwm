/*
 * ItlHotspotUserClient.hpp - IOUserClient that exposes the driver's
 * software-AP controls to a userspace process without airportd.
 *
 * Copyright (C) 2026. GPL v2, same as the rest of AirportItlwm.
 */
#ifndef ITL_HOTSPOT_USER_CLIENT_HPP
#define ITL_HOTSPOT_USER_CLIENT_HPP

#include <IOKit/IOUserClient.h>
#include "AirportItlwmV2.hpp"
#include "AirportItlwmSkywalkInterface.hpp"
#include "ItlHotspotShared.h"

class ItlHotspotUserClient : public IOUserClient {
    OSDeclareDefaultStructors(ItlHotspotUserClient)

public:
    virtual bool start(IOService *provider) override;
    virtual void stop(IOService *provider) override;
    virtual IOReturn externalMethod(uint32_t selector,
                                    IOExternalMethodArguments *arguments,
                                    IOExternalMethodDispatch *dispatch = nullptr,
                                    OSObject *target = nullptr,
                                    void *reference = nullptr) override;

private:
    AirportItlwm                   *fController;
    AirportItlwmSkywalkInterface   *fSkywalk;

    IOReturn startAP(const itl_hotspot_start *in);
    IOReturn stopAP();
    IOReturn status(itl_hotspot_status *out);
};

#endif /* ITL_HOTSPOT_USER_CLIENT_HPP */
