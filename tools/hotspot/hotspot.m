/*
 * hotspot.m - talk to ItlHotspotUserClient in the loaded AirportItlwm kext.
 *
 * This bypasses airportd entirely.  We open the IOUserClient that our kext
 * publishes (IOUserClientClass = ItlHotspotUserClient) and call its external
 * methods.  The kext forwards to the driver's own setSSID/setCHANNEL/
 * setAP_MODE, which start the exclusive software AP.
 *
 * Build: clang -framework Foundation -framework IOKit -o hotspot hotspot.m
 *
 * Usage:
 *   hotspot probe                     read-only: show driver state
 *   hotspot start <ssid> [ch] [pass]   start AP; pass enables WPA2-PSK
 *   hotspot stop                      stop the AP, return to STA
 *
 * NOTE: WPA2-PSK is handled entirely in-driver.  The passphrase is derived to
 * a PMK with PBKDF2 in the kext, and net80211's built-in 4-way authenticator
 * runs the handshake with each station.  No passphrase crosses into airportd.
 * NOTE: AP mode is EXCLUSIVE - it tears down any STA link.  Upstream internet
 * must come from a different interface (Ethernet / USB tether) + NAT.
 */

#import <Foundation/Foundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOCFPlugIn.h>
#include <mach/mach_error.h>
#include "ItlHotspotShared.h"

static io_connect_t gConn = IO_OBJECT_NULL;

static BOOL
openClient(void)
{
    /* Match on IOClass, not the IORegistry entry name.  IOServiceNameMatching
     * matches the name and can miss the controller; IOServiceMatching matches
     * the IOClass property set by the kext's IOKit personality. */
    io_service_t svc = IOServiceGetMatchingService(
        kIOMainPortDefault,
        IOServiceMatching("AirportItlwm"));
    if (!svc) {
        fprintf(stderr, "AirportItlwm service not found in IORegistry\n");
        return NO;
    }
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &gConn);
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "IOServiceOpen failed: 0x%x (%s)\n", kr, mach_error_string(kr));
        fprintf(stderr, "The loaded kext must be rebuilt with ItlHotspotUserClient "
                        "(IOUserClientClass in Info.plist).\n");
        return NO;
    }
    return YES;
}

static const char *
opmode_name(uint32_t m)
{
    switch (m) {
        case 1: return "STA";
        case 2: return "HOSTAP (AP)";
        case 3: return "IBSS";
        case 4: return "MONITOR";
        case 6: return "HOSTAP (AP)";
        default: return "?";
    }
}
static const char *
state_name(uint32_t s)
{
    static const char *n[] = {"INIT","SCAN","AUTH","ASSOC","RUN","IE","SLEEP"};
    return s < sizeof(n)/sizeof(n[0]) ? n[s] : "?";
}

static int
do_probe(void)
{
    struct itl_hotspot_status st;
    memset(&st, 0, sizeof(st));
    size_t outSize = sizeof(st);
    kern_return_t kr = IOConnectCallStructMethod(gConn, kItlHotspotStatus,
                                                 NULL, 0, &st, &outSize);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "status call failed: 0x%x (%s)\n", kr, mach_error_string(kr));
        return 1;
    }
    char ssid[33] = {0};
    uint32_t n = st.ssid_len < 32 ? st.ssid_len : 32;
    memcpy(ssid, st.ssid, n);
    printf("driver status:\n");
    printf("  opmode  : %u (%s)\n", st.opmode, opmode_name(st.opmode));
    printf("  state   : %u (%s)\n", st.state, state_name(st.state));
    printf("  SSID    : \"%s\"\n", ssid);
    printf("  channel : %u MHz\n", st.channel);
    return 0;
}

static int
do_start(const char *ssid, int channel, const char *password)
{
    if (!ssid || strlen(ssid) == 0 || strlen(ssid) > 32) {
        fprintf(stderr, "SSID must be 1-32 bytes\n");
        return 2;
    }
    if (channel == 0) channel = 6;

    size_t passlen = password ? strlen(password) : 0;
    if (passlen != 0 && (passlen < 8 || passlen > 63)) {
        fprintf(stderr, "WPA2 passphrase must be 8-63 characters\n");
        return 2;
    }

    struct itl_hotspot_start in;
    memset(&in, 0, sizeof(in));
    in.version = ITL_HOTSPOT_VERSION;
    in.ssid_len = (uint32_t)strlen(ssid);
    memcpy(in.ssid, ssid, in.ssid_len);
    in.channel = (uint32_t)channel;
    in.password_len = (uint32_t)passlen;
    if (passlen) memcpy(in.password, password, passlen);

    kern_return_t kr = IOConnectCallStructMethod(gConn, kItlHotspotStartAP,
                                                 &in, sizeof(in), NULL, NULL);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "start call failed: 0x%x (%s)\n", kr, mach_error_string(kr));
        return 1;
    }
    printf("AP start requested: ssid=\"%s\" channel=%d security=%s\n",
           ssid, channel, passlen ? "WPA2-PSK" : "open");
    printf("Verify with: hotspot probe\n");
    printf("Check driver log: log show --last 2m --predicate 'eventMessage CONTAINS[c] \"itlwm: AP\"'\n");
    return 0;
}

static int
do_stop(void)
{
    kern_return_t kr = IOConnectCallStructMethod(gConn, kItlHotspotStopAP,
                                                 NULL, 0, NULL, NULL);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "stop call failed: 0x%x (%s)\n", kr, mach_error_string(kr));
        return 1;
    }
    printf("AP stop requested.\n");
    return 0;
}

static void
usage(void)
{
    fprintf(stderr,
        "usage:\n"
        "  hotspot probe                       show driver opmode/state/SSID/channel\n"
        "  hotspot start <ssid> [ch] [pass]    start AP (ch default 6; pass = WPA2-PSK)\n"
        "  hotspot stop                        stop AP, return to STA\n"
        "\n"
        "Examples:\n"
        "  hotspot probe\n"
        "  hotspot start MyHotspot 6 mypassword   (WPA2-PSK)\n"
        "  hotspot start OpenNet 6                (open AP)\n"
        "  hotspot stop\n");
}

int
main(int argc, char **argv)
{
    @autoreleasepool {
        if (argc < 2) { usage(); return 2; }
        if (!openClient()) return 1;

        int rc;
        if (!strcmp(argv[1], "probe")) {
            rc = do_probe();
        } else if (!strcmp(argv[1], "start")) {
            if (argc < 3) { usage(); rc = 2; }
            else {
                int ch = argc >= 4 ? atoi(argv[3]) : 6;
                const char *pass = argc >= 5 ? argv[4] : NULL;
                rc = do_start(argv[2], ch, pass);
            }
        } else if (!strcmp(argv[1], "stop")) {
            rc = do_stop();
        } else {
            usage(); rc = 2;
        }

        IOServiceClose(gConn);
        return rc;
    }
}
