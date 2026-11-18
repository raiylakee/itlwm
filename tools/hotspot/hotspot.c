/*
 * hotspot.c - drive AirportItlwm's software-AP mode directly over the
 * apple80211 ioctl interface, bypassing airportd / Internet Sharing.
 *
 * This talks to the SAME kernel entry point airportd uses: a raw socket
 * ioctl (SIOCSA80211) on the Wi-Fi interface.  IO80211Family dispatches
 * req_type through gSetHandlerTable[] into the driver's setSSID /
 * setCHANNEL / setAP_MODE vtable methods.  No private framework, no
 * entitlement, no Internet Sharing required.
 *
 * Build:  clang -O2 -Wall -o hotspot hotspot.c
 *
 * Usage:
 *   hotspot probe [ifname]            read-only: show current SSID/opmode/state
 *   hotspot start <ssid> [channel]    bring up the AP (open network)
 *   hotspot stop  [ifname]            tear the AP down, return to STA
 *
 * NOTE ON SECURITY: this activates an OPEN AP.  The driver's AP path does
 * not consume a passphrase (setAP_MODE/startAPMode never set ic_psk), and
 * the WPA2 4-way handshake in Apple's stack lives in airportd's userspace
 * RSNA, which we are deliberately bypassing.  WPA2 would require porting
 * that handshake here.  Open AP is what the kext supports on its own.
 *
 * NOTE ON UPSTREAM: the driver's AP mode is EXCLUSIVE - startAPMode()
 * disassociates any STA link.  The shared internet therefore has to come
 * from a different interface (e.g. Ethernet / USB tether), set up with
 * nat.sh.  This tool does not and cannot make Wi-Fi->Wi-Fi repeaters.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

/* ---- ioctl ABI (from include/Airport/apple80211_ioctl.h) ---- */
#define SIOCSA80211 2150656456u   /* __IO80211_TARGET >= 10.15 */
#define SIOCGA80211 3224398281u

struct apple80211req {
    char     req_if_name[IFNAMSIZ];
    int      req_type;    /* request number */
    int      req_val;     /* sub-value */
    uint32_t req_len;
    void    *req_data;
};

enum {
    IOC_SSID          = 1,
    IOC_AUTH_TYPE     = 2,
    IOC_CIPHER_KEY    = 3,
    IOC_CHANNEL       = 4,
    IOC_OP_MODE       = 15,
    IOC_IBSS_MODE     = 24,
    IOC_HOST_AP_MODE  = 25,
    IOC_AP_MODE       = 26,
};

#define APPLE80211_VERSION        1
#define APPLE80211_MAX_SSID_LEN   32

/* apple80211_apmode */
enum {
    AP_MODE_UNKNOWN = 0,
    AP_MODE_IBSS    = 1,
    AP_MODE_INFRA   = 2,   /* Access Point */
    AP_MODE_ANY     = 3,
};

/* apple80211_channel_flag bits */
#define C_FLAG_2GHZ   0x8
#define C_FLAG_5GHZ   0x10
#define C_FLAG_ACTIVE 0x80

struct a80211_channel {
    uint32_t version;
    uint32_t channel;
    uint32_t flags;
};
struct apple80211_ssid_data {
    uint32_t version;
    uint32_t ssid_len;
    uint8_t  ssid_bytes[APPLE80211_MAX_SSID_LEN];
};
struct apple80211_channel_data {
    uint32_t version;
    struct a80211_channel channel;
};
struct apple80211_apmode_data {
    uint32_t version;
    uint32_t apmode;
};
struct apple80211_opmode_data {
    uint32_t version;
    uint32_t op_mode;
};
struct apple80211_state_data {
    uint32_t version;
    uint32_t state;
};

static int g_sock = -1;

static int
a80211_ioctl(unsigned long cmd, const char *ifname, int req_type, int req_val,
             void *data, uint32_t len)
{
    struct apple80211req req;
    memset(&req, 0, sizeof(req));
    strlcpy(req.req_if_name, ifname, sizeof(req.req_if_name));
    req.req_type = req_type;
    req.req_val  = req_val;
    req.req_len  = len;
    req.req_data = data;
    return ioctl(g_sock, cmd, &req);
}

static const char *
state_name(uint32_t s)
{
    static const char *names[] = {
        "INIT", "SCAN", "AUTH", "ASSOC", "RUN", "IE", "SLEEP", "LISTEN",
        "WAIT", "ROAM"
    };
    return s < sizeof(names)/sizeof(names[0]) ? names[s] : "?";
}
static const char *
opmode_name(uint32_t m)
{
    static const char *names[] = {
        "AUTO", "STA", "HOSTAP", "IBSS", "MONITOR", "WDS"
    };
    return m < sizeof(names)/sizeof(names[0]) ? names[m] : "?";
}
static const char *
apmode_name(uint32_t m)
{
    switch (m) {
        case AP_MODE_UNKNOWN: return "UNKNOWN (STA)";
        case AP_MODE_IBSS:    return "IBSS";
        case AP_MODE_INFRA:   return "INFRA (AP)";
        case AP_MODE_ANY:     return "ANY";
        default:              return "?";
    }
}

static int
do_probe(const char *ifname)
{
    struct apple80211_ssid_data ssid;
    struct apple80211_apmode_data apm;
    struct apple80211_opmode_data opm;
    struct apple80211_state_data st;
    int rc, any = 0;

    printf("probe %s:\n", ifname);

    memset(&ssid, 0, sizeof(ssid));
    rc = a80211_ioctl(SIOCGA80211, ifname, IOC_SSID, 0, &ssid, sizeof(ssid));
    if (rc == 0) {
        char buf[APPLE80211_MAX_SSID_LEN + 1] = {0};
        uint32_t n = ssid.ssid_len < APPLE80211_MAX_SSID_LEN ?
                     ssid.ssid_len : APPLE80211_MAX_SSID_LEN;
        memcpy(buf, ssid.ssid_bytes, n);
        printf("  SSID    : \"%s\"\n", buf);
        any = 1;
    } else printf("  SSID    : <error %d: %s>\n", errno, strerror(errno));

    memset(&opm, 0, sizeof(opm));
    rc = a80211_ioctl(SIOCGA80211, ifname, IOC_OP_MODE, 0, &opm, sizeof(opm));
    if (rc == 0) {
        printf("  opmode  : %u (%s)\n", opm.op_mode, opmode_name(opm.op_mode));
        any = 1;
    } else printf("  opmode  : <error %d: %s>\n", errno, strerror(errno));

    memset(&st, 0, sizeof(st));
    rc = a80211_ioctl(SIOCGA80211, ifname, 13, 0, &st, sizeof(st)); /* STATE */
    if (rc == 0) {
        printf("  state   : %u (%s)\n", st.state, state_name(st.state));
        any = 1;
    } else printf("  state   : <error %d: %s>\n", errno, strerror(errno));

    memset(&apm, 0, sizeof(apm));
    rc = a80211_ioctl(SIOCGA80211, ifname, IOC_AP_MODE, 0, &apm, sizeof(apm));
    if (rc == 0) {
        printf("  apmode  : %u (%s)\n", apm.apmode, apmode_name(apm.apmode));
        any = 1;
    } else printf("  apmode  : <error %d: %s (req 26 may be set-only)>\n",
                  errno, strerror(errno));

    if (!any) {
        fprintf(stderr, "\nNo ioctl answered.  The interface/kext is not "
                        "reachable via apple80211 (wrong ifname, or the "
                        "loaded kext is not AirportItlwm).\n");
        return 1;
    }
    printf("\nioctl path is live - the driver is answering apple80211 requests.\n");
    return 0;
}

static int
do_start(const char *ifname, const char *ssid, int channel)
{
    struct apple80211_ssid_data sd;
    struct apple80211_channel_data cd;
    struct apple80211_apmode_data ad;
    int rc;

    if (strlen(ssid) == 0 || strlen(ssid) > APPLE80211_MAX_SSID_LEN) {
        fprintf(stderr, "SSID must be 1-32 bytes\n");
        return 2;
    }
    if (channel == 0) channel = 6;   /* sane 2.4 GHz default */

    memset(&sd, 0, sizeof(sd));
    sd.version = APPLE80211_VERSION;
    sd.ssid_len = (uint32_t)strlen(ssid);
    memcpy(sd.ssid_bytes, ssid, sd.ssid_len);
    rc = a80211_ioctl(SIOCSA80211, ifname, IOC_SSID, 0, &sd, sizeof(sd));
    printf("set SSID \"%s\"      : %s\n", ssid, rc == 0 ? "ok" : strerror(errno));

    memset(&cd, 0, sizeof(cd));
    cd.version = APPLE80211_VERSION;
    cd.channel.version = APPLE80211_VERSION;
    cd.channel.channel = (uint32_t)channel;
    cd.channel.flags = C_FLAG_2GHZ | C_FLAG_ACTIVE;
    rc = a80211_ioctl(SIOCSA80211, ifname, IOC_CHANNEL, 0, &cd, sizeof(cd));
    printf("set channel %d       : %s\n", channel, rc == 0 ? "ok" : strerror(errno));

    memset(&ad, 0, sizeof(ad));
    ad.version = APPLE80211_VERSION;
    ad.apmode = AP_MODE_INFRA;
    rc = a80211_ioctl(SIOCSA80211, ifname, IOC_AP_MODE, 0, &ad, sizeof(ad));
    printf("set AP_MODE=INFRA    : %s\n", rc == 0 ? "ok" : strerror(errno));

    if (rc != 0) {
        fprintf(stderr, "\nAP_MODE ioctl failed.  The loaded kext may not "
                        "contain the AP code from commit 9625545, or req 26 "
                        "is not dispatched on this macOS build.  Check the "
                        "driver log: log show --predicate 'eventMessage "
                        "CONTAINS[c] \"itlwm: AP\"'\n");
        return 1;
    }
    printf("\nAP start requested.  Verify with: hotspot probe %s\n", ifname);
    printf("Then check for the network with: /System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport scan\n");
    return 0;
}

static int
do_stop(const char *ifname)
{
    struct apple80211_apmode_data ad;
    int rc;

    memset(&ad, 0, sizeof(ad));
    ad.version = APPLE80211_VERSION;
    ad.apmode = AP_MODE_UNKNOWN;   /* driver maps UNKNOWN -> stopAPMode() */
    rc = a80211_ioctl(SIOCSA80211, ifname, IOC_AP_MODE, 0, &ad, sizeof(ad));
    printf("set AP_MODE=UNKNOWN  : %s\n", rc == 0 ? "ok" : strerror(errno));

    if (rc != 0) {
        /* Fall back to HOST_AP_MODE_STOP */
        ad.apmode = 2; /* req_val STOP on HOST_AP_MODE, see below */
        rc = a80211_ioctl(SIOCSA80211, ifname, IOC_HOST_AP_MODE, 2, &ad, sizeof(ad));
        printf("HOST_AP_MODE STOP    : %s\n", rc == 0 ? "ok" : strerror(errno));
    }
    return rc == 0 ? 0 : 1;
}

static void
usage(void)
{
    fprintf(stderr,
        "usage:\n"
        "  hotspot probe [ifname]             read-only state check (default en1)\n"
        "  hotspot start <ssid> [channel]     start open AP (default ch 6)\n"
        "  hotspot stop  [ifname]             stop AP, return to STA\n"
        "\n"
        "Examples:\n"
        "  hotspot probe en1\n"
        "  hotspot start MyHotspot 6\n"
        "  hotspot stop en1\n");
}

int
main(int argc, char **argv)
{
    const char *ifname = "en1";
    int rc;

    if (argc < 2) { usage(); return 2; }

    g_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_sock < 0) { perror("socket"); return 1; }

    if (!strcmp(argv[1], "probe")) {
        if (argc >= 3) ifname = argv[2];
        rc = do_probe(ifname);
    } else if (!strcmp(argv[1], "start")) {
        if (argc < 3) { usage(); rc = 2; goto out; }
        if (argc >= 5) ifname = argv[4];
        rc = do_start(ifname, argv[2], argc >= 4 ? atoi(argv[3]) : 6);
    } else if (!strcmp(argv[1], "stop")) {
        if (argc >= 3) ifname = argv[2];
        rc = do_stop(ifname);
    } else {
        usage(); rc = 2;
    }

out:
    close(g_sock);
    return rc;
}
