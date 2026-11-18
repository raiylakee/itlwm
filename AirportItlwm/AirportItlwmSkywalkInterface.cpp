//
//  AirportItlwmSkywalkInterface.cpp
//  AirportItlwm-Sonoma
//
//  Created by qcwap on 2023/6/27.
//  Copyright © 2023 钟先耀. All rights reserved.
//
#include "AirportItlwmV2.hpp"
#include "AirportItlwmSkywalkInterface.hpp"
#include <sys/CTimeout.hpp>
#include <libkern/c++/OSMetaClass.h>
#include <crypto/sha1.h>
#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_node.h>
#include <net80211/ieee80211_ioctl.h>
#include <net80211/ieee80211_priv.h>
#include <pexpert/pexpert.h>

#ifdef AIRPORT_WCL
extern IOCommandGate *_fCommandGate;
#endif

/*
 * Map an ISO 3166 country code onto Apple's regulatory locale. The driver
 * used to hardcode FCC; that is correct for the US but wrong for ID/JP/KR
 * and the ETSI countries, and airportd uses this value to decide which
 * channels/powers are legal.
 */
static u_int32_t
appleLocaleForCountryCode(const char *in)
{
    static const char *const etsi[] = {
        "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
        "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
        "NO", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "CH", "GB",
        "IS", "LI", "TR", "UA", nullptr
    };
    static const char *const apac[] = {
        "AU", "NZ", "SG", "HK", "IN", "MY", "TH", "PH", "VN", "TW",
        "CN", "MO", "PK", "BD", "LK", nullptr
    };
    static const char *const fcc[] = {
        "US", "CA", "MX", "BR", "AR", "CL", "CO", "PE", "CR", "PA",
        "DO", "GT", "UY", "PY", "BO", "EC", "VE", "PR", nullptr
    };
    char cc[3] = { 0, 0, 0 };
    unsigned i;

    if (!in || !in[0] || !in[1])
        return APPLE80211_LOCALE_FCC;

    cc[0] = (in[0] >= 'a' && in[0] <= 'z') ? in[0] - 0x20 : in[0];
    cc[1] = (in[1] >= 'a' && in[1] <= 'z') ? in[1] - 0x20 : in[1];

    if (strcmp(cc, "ID") == 0)
        return APPLE80211_LOCALE_INDONESIA;
    if (strcmp(cc, "JP") == 0)
        return APPLE80211_LOCALE_JAPAN;
    if (strcmp(cc, "KR") == 0)
        return APPLE80211_LOCALE_KOREA;
    for (i = 0; etsi[i] != nullptr; i++)
        if (strcmp(cc, etsi[i]) == 0)
            return APPLE80211_LOCALE_ETSI;
    for (i = 0; apac[i] != nullptr; i++)
        if (strcmp(cc, apac[i]) == 0)
            return APPLE80211_LOCALE_APAC;
    for (i = 0; fcc[i] != nullptr; i++)
        if (strcmp(cc, fcc[i]) == 0)
            return APPLE80211_LOCALE_FCC;

    /* Unknown/unspecified ("ZZ") keeps the previous FCC default. */
    return APPLE80211_LOCALE_FCC;
}

#define super IO80211InfraProtocol
OSDefineMetaClassAndStructors(AirportItlwmSkywalkInterface, IO80211InfraProtocol);

const char* hexdump(uint8_t *buf, size_t len) {
    ssize_t str_len = len * 3 + 1;
    char *str = (char*)IOMalloc(str_len);
    if (!str)
        return nullptr;
    for (size_t i = 0; i < len; i++)
    snprintf(str + 3 * i, (len - i) * 3, "%02x ", buf[i]);
    str[MAX(str_len - 2, 0)] = 0;
    return str;
}

static int ieeeChanFlag2appleScanFlagVentura(int flags)
{
    int ret = 0;
    if (flags & IEEE80211_CHAN_2GHZ)
        ret |= APPLE80211_C_FLAG_2GHZ;
    if (flags & IEEE80211_CHAN_5GHZ)
        ret |= APPLE80211_C_FLAG_5GHZ;
    ret |= (APPLE80211_C_FLAG_ACTIVE | APPLE80211_C_FLAG_20MHZ);
    return ret;
}

static int ieeeChanFlag2apple(int flags, int bw)
{
    int ret = 0;
    if (flags & IEEE80211_CHAN_2GHZ)
        ret |= APPLE80211_C_FLAG_2GHZ;
    if (flags & IEEE80211_CHAN_5GHZ)
        ret |= APPLE80211_C_FLAG_5GHZ;
    if (!(flags & IEEE80211_CHAN_PASSIVE))
        ret |= APPLE80211_C_FLAG_ACTIVE;
    if (flags & IEEE80211_CHAN_DFS)
        ret |= APPLE80211_C_FLAG_DFS;
    if (bw == -1) {
        if (flags & IEEE80211_CHAN_VHT) {
            if ((flags & IEEE80211_CHAN_VHT160) || (flags & IEEE80211_CHAN_VHT80_80))
                ret |= APPLE80211_C_FLAG_160MHZ;
            if (flags & IEEE80211_CHAN_VHT80)
                ret |= APPLE80211_C_FLAG_80MHZ;
        } else if ((flags & IEEE80211_CHAN_HT40) && (flags & IEEE80211_CHAN_HT)) {
            ret |= APPLE80211_C_FLAG_40MHZ;
            if (flags & IEEE80211_CHAN_HT40U)
                ret |= APPLE80211_C_FLAG_EXT_ABV;
        } else if (flags & IEEE80211_CHAN_HT20)
            ret |= APPLE80211_C_FLAG_20MHZ;
        else if ((flags & IEEE80211_CHAN_CCK) || (flags & IEEE80211_CHAN_OFDM))
            ret |= APPLE80211_C_FLAG_10MHZ;
    } else {
        switch (bw) {
            case IEEE80211_CHAN_WIDTH_80P80:
            case IEEE80211_CHAN_WIDTH_160:
                ret |= APPLE80211_C_FLAG_160MHZ;
                break;
            case IEEE80211_CHAN_WIDTH_80:
                ret |= APPLE80211_C_FLAG_80MHZ;
                break;
            case IEEE80211_CHAN_WIDTH_40:
                ret |= APPLE80211_C_FLAG_40MHZ;
                if (flags & IEEE80211_CHAN_HT40U)
                    ret |= APPLE80211_C_FLAG_EXT_ABV;
                break;
            case IEEE80211_CHAN_WIDTH_20:
                ret |= APPLE80211_C_FLAG_20MHZ;
                break;
            default:
                if (flags & IEEE80211_CHAN_HT20)
                    ret |= APPLE80211_C_FLAG_20MHZ;
                else if ((flags & IEEE80211_CHAN_CCK) || (flags & IEEE80211_CHAN_OFDM))
                    ret |= APPLE80211_C_FLAG_10MHZ;
                break;
        }
    }
    return ret;
}

void AirportItlwmSkywalkInterface::associateSSID(uint8_t *ssid, uint32_t ssid_len, const struct ether_addr &bssid, uint32_t authtype_lower, uint32_t authtype_upper, uint8_t *key, uint32_t key_len, int key_index)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    
    ieee80211_disable_rsn(ic);
    ieee80211_disable_wep(ic);
    
    struct ieee80211_wpaparams     wpa;
    struct ieee80211_nwkey         nwkey;
    bzero(&wpa, sizeof(wpa));
    bzero(&nwkey, sizeof(nwkey));
    
    memset(ic->ic_des_essid, 0, IEEE80211_NWID_LEN);
    memcpy(ic->ic_des_essid, ssid, ssid_len);
    ic->ic_des_esslen = ssid_len;
    
    bool is_zero = true;
    for (int i = 0; i < IEEE80211_ADDR_LEN; i++)
    is_zero &= bssid.octet[i] == 0;
    
    if (!is_zero) {
        IEEE80211_ADDR_COPY(ic->ic_des_bssid, bssid.octet);
        ic->ic_flags |= IEEE80211_F_DESBSSID;
    }
    else {
        memset(ic->ic_des_bssid, 0, IEEE80211_ADDR_LEN);
        ic->ic_flags &= ~IEEE80211_F_DESBSSID;
    }

#ifndef AIRPORT_WCL
    // AUTHTYPE_WPA3_SAE AUTHTYPE_WPA3_FT_SAE
    // we don't really support WPA3, but we have announced we support WPA3 in card capability function. so we fake it as WPA2 to support some WPA2/WPA3 mix wifi connection.
    if (authtype_upper == APPLE80211_AUTHTYPE_WPA3_SAE || authtype_upper == APPLE80211_AUTHTYPE_WPA3_FT_SAE) {
        wpa.i_protos |= IEEE80211_WPA_PROTO_WPA2;
        authtype_upper |= APPLE80211_AUTHTYPE_WPA2_PSK;// hack
    }
    // AUTHTYPE_WPA3_ENTERPRISE AUTHTYPE_WPA3_FT_ENTERPRISE
    if (authtype_upper == APPLE80211_AUTHTYPE_WPA3_ENTERPRISE || authtype_upper == APPLE80211_AUTHTYPE_WPA3_FT_ENTERPRISE) {
        wpa.i_protos |= IEEE80211_WPA_PROTO_WPA2;
        authtype_upper |= APPLE80211_AUTHTYPE_WPA2;// hack
    }
    
#endif
    if (authtype_upper & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA_PSK | APPLE80211_AUTHTYPE_WPA2 | APPLE80211_AUTHTYPE_WPA2_PSK | APPLE80211_AUTHTYPE_SHA256_PSK | APPLE80211_AUTHTYPE_SHA256_8021X)) {
        XYLog("%s %d\n", __FUNCTION__, __LINE__);
        wpa.i_protos = IEEE80211_WPA_PROTO_WPA1 | IEEE80211_WPA_PROTO_WPA2;
    }
    
    if (authtype_upper & (APPLE80211_AUTHTYPE_WPA_PSK | APPLE80211_AUTHTYPE_WPA2_PSK | APPLE80211_AUTHTYPE_SHA256_PSK)) {
        XYLog("%s %d\n", __FUNCTION__, __LINE__);
        wpa.i_akms |= IEEE80211_WPA_AKM_PSK | IEEE80211_WPA_AKM_SHA256_PSK;
        wpa.i_enabled = 1;
        memcpy(ic->ic_psk, key, sizeof(ic->ic_psk));
        ic->ic_flags |= IEEE80211_F_PSK;
        ieee80211_ioctl_setwpaparms(ic, &wpa);
    }
    if (authtype_upper & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA2 | APPLE80211_AUTHTYPE_SHA256_8021X)) {
        XYLog("%s %d\n", __FUNCTION__, __LINE__);
        wpa.i_akms |= IEEE80211_WPA_AKM_8021X | IEEE80211_WPA_AKM_SHA256_8021X;
        wpa.i_enabled = 1;
        ieee80211_ioctl_setwpaparms(ic, &wpa);
    }
    
    if (authtype_lower == APPLE80211_AUTHTYPE_SHARED) {
        XYLog("shared key authentication is not supported!\n");
        return;
    }
    
    if (authtype_upper == APPLE80211_AUTHTYPE_NONE && authtype_lower == APPLE80211_AUTHTYPE_OPEN) { // Open or WEP Open System
        if (key_len > 0) {
            XYLog("%s %d\n", __FUNCTION__, __LINE__);
            nwkey.i_wepon = IEEE80211_NWKEY_WEP;
            nwkey.i_defkid = key_index + 1;
            nwkey.i_key[key_index].i_keylen = (int)key_len;
            nwkey.i_key[key_index].i_keydat = key;
            ieee80211_ioctl_setnwkeys(ic, &nwkey);
        }
    }
}

void AirportItlwmSkywalkInterface::setPTK(const u_int8_t *key, size_t key_len) {
    struct ieee80211com *ic = fHalService->get80211Controller();
    struct ieee80211_node    * ni = ic->ic_bss;
    struct ieee80211_key *k;
    int keylen;
    
    ni->ni_rsn_supp_state = RNSA_SUPP_PTKDONE;
    
    if (ni->ni_rsncipher != IEEE80211_CIPHER_USEGROUP) {
        u_int64_t prsc;
        
        /* check that key length matches that of pairwise cipher */
        keylen = ieee80211_cipher_keylen(ni->ni_rsncipher);
        if (key_len != keylen) {
            XYLog("PTK length mismatch. expected %d, got %zu\n", keylen, key_len);
            return;
        }
        prsc = /*(gtk == NULL) ? LE_READ_6(key->rsc) :*/ 0;
        
        /* map PTK to 802.11 key */
        k = &ni->ni_pairwise_key;
        memset(k, 0, sizeof(*k));
        k->k_cipher = ni->ni_rsncipher;
        k->k_rsc[0] = prsc;
        k->k_len = keylen;
        memcpy(k->k_key, key, k->k_len);
        /* install the PTK */
        if ((*ic->ic_set_key)(ic, ni, k) != 0) {
            XYLog("setting PTK failed\n");
            return;
        }
        else
            XYLog("setting PTK successfully\n");
        ni->ni_flags &= ~IEEE80211_NODE_RSN_NEW_PTK;
        ni->ni_flags &= ~IEEE80211_NODE_TXRXPROT;
        ni->ni_flags |= IEEE80211_NODE_RXPROT;
    } else if (ni->ni_rsncipher != IEEE80211_CIPHER_USEGROUP)
        XYLog("%s: unexpected pairwise key update received from %s\n",
              ic->ic_if.if_xname, ether_sprintf(ni->ni_macaddr));
}

void AirportItlwmSkywalkInterface::setGTK(const u_int8_t *gtk, size_t key_len, u_int8_t kid, u_int8_t *rsc) {
    struct ieee80211com *ic = fHalService->get80211Controller();
    struct ieee80211_node    * ni = ic->ic_bss;
    struct ieee80211_key *k;
    int keylen;
    
    if (gtk != NULL) {
        /* check that key length matches that of group cipher */
        keylen = ieee80211_cipher_keylen(ni->ni_rsngroupcipher);
        if (key_len != keylen) {
            XYLog("GTK length mismatch. expected %d, got %zu\n", keylen, key_len);
            return;
        }
        /* map GTK to 802.11 key */
        k = &ic->ic_nw_keys[kid];
        if (k->k_cipher == IEEE80211_CIPHER_NONE || k->k_len != keylen || memcmp(k->k_key, gtk, keylen) != 0) {
            memset(k, 0, sizeof(*k));
            k->k_id = kid;    /* 0-3 */
            k->k_cipher = ni->ni_rsngroupcipher;
            k->k_flags = IEEE80211_KEY_GROUP;
            //if (gtk[6] & (1 << 2))
            //  k->k_flags |= IEEE80211_KEY_TX;
            k->k_rsc[0] = LE_READ_6(rsc);
            k->k_len = keylen;
            memcpy(k->k_key, gtk, k->k_len);
            /* install the GTK */
            if ((*ic->ic_set_key)(ic, ni, k) != 0) {
                XYLog("setting GTK failed\n");
                return;
            }
            else
                XYLog("setting GTK successfully\n");
        }
    }
    
    if (true) {
        ni->ni_flags |= IEEE80211_NODE_TXRXPROT;
#ifndef IEEE80211_STA_ONLY
        if (ic->ic_opmode != IEEE80211_M_IBSS ||
            ++ni->ni_key_count == 2)
#endif
        {
            XYLog("marking port %s valid\n",
                  ether_sprintf(ni->ni_macaddr));
            ni->ni_port_valid = 1;
            ieee80211_set_link_state(ic, LINK_STATE_UP);
            ni->ni_assoc_fail = 0;
            if (ic->ic_opmode == IEEE80211_M_STA)
                ic->ic_rsngroupcipher = ni->ni_rsngroupcipher;
        }
    }
}

bool AirportItlwmSkywalkInterface::
init(IOService *provider)
{
    bool ret = IO80211InfraInterface::init();
    if (!ret) {
        XYLog("%s IO80211InfraInterface init failed\n", __PRETTY_FUNCTION__);
        return false;
    }
    instance = OSDynamicCast(AirportItlwm, provider);
    if (!instance)
        return false;
    this->fHalService = instance->fHalService;
    this->scanSource = instance->scanSource;
#ifdef AIRPORT_WCL
    IOEthernetAddress address;
    if (instance->getHardwareAddress(&address) != kIOReturnSuccess)
        return false;
    memcpy(wclPermanentMAC, &address, sizeof(wclPermanentMAC));
    if (!IO80211SkywalkInterface::init(provider, reinterpret_cast<ether_addr *>(&address)))
        return false;
    if (!initWCL())
        return false;
#endif
    return ret;
}

//ifnet_t AirportItlwmSkywalkInterface::
//getBSDInterface()
//{
//    if (instance->bsdInterface)
//        return instance->bsdInterface->getIfnet();
//    return NULL;
//}

IOReturn AirportItlwmSkywalkInterface::
getSSID(struct apple80211_ssid_data *sd)
{
    struct ieee80211com * ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(sd, 0, sizeof(*sd));
        sd->version = APPLE80211_VERSION;
#ifdef AIRPORT_WCL
        sd->ssid_len = MIN(ic->ic_bss->ni_esslen, sizeof(sd->ssid_bytes));
        memcpy(sd->ssid_bytes, ic->ic_bss->ni_essid, sd->ssid_len);
#else
        memcpy(sd->ssid_bytes, ic->ic_des_essid, strlen((const char*)ic->ic_des_essid));
        sd->ssid_len = (uint32_t)strlen((const char*)ic->ic_des_essid);
#endif
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getAUTH_TYPE(struct apple80211_authtype_data *ad)
{
    ad->version = APPLE80211_VERSION;
    ad->authtype_lower = current_authtype_lower;
    ad->authtype_upper = current_authtype_upper;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setAUTH_TYPE(struct apple80211_authtype_data *ad)
{
    current_authtype_lower = ad->authtype_lower;
    current_authtype_upper = ad->authtype_upper;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setCIPHER_KEY(struct apple80211_key *key)
{
#ifdef AIRPORT_WCL
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(8), key);
#else

    XYLog("%s\n", __FUNCTION__);
    const char* keydump = hexdump(key->key, key->key_len);
    const char* rscdump = hexdump(key->key_rsc, key->key_rsc_len);
    const char* eadump = hexdump(key->key_ea.octet, APPLE80211_ADDR_LEN);
    static_assert(__offsetof(struct apple80211_key, key_ea) == 92, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, key_rsc_len) == 80, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, wowl_kck_len) == 100, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, wowl_kek_len) == 120, "struct corrupted");
    static_assert(__offsetof(struct apple80211_key, wowl_kck_key) == 104, "struct corrupted");
    if (keydump && rscdump && eadump)
        XYLog("Set key request: len=%d cipher_type=%d flags=%d index=%d key=%s rsc_len=%d rsc=%s ea=%s\n",
              key->key_len, key->key_cipher_type, key->key_flags, key->key_index, keydump, key->key_rsc_len, rscdump, eadump);
    else
        XYLog("Set key request, but failed to allocate memory for hexdump\n");
    
    if (keydump)
        IOFree((void*)keydump, 3 * key->key_len + 1);
    if (rscdump)
        IOFree((void*)rscdump, 3 * key->key_rsc_len + 1);
    if (eadump)
        IOFree((void*)eadump, 3 * APPLE80211_ADDR_LEN + 1);
    
    switch (key->key_cipher_type) {
        case APPLE80211_CIPHER_NONE:
            // clear existing key
//            XYLog("Setting NONE key is not supported\n");
            break;
        case APPLE80211_CIPHER_WEP_40:
        case APPLE80211_CIPHER_WEP_104:
            XYLog("Setting WEP key %d is not supported\n", key->key_index);
            break;
        case APPLE80211_CIPHER_TKIP:
        case APPLE80211_CIPHER_AES_OCB:
        case APPLE80211_CIPHER_AES_CCM:
            switch (key->key_flags) {
                case 4: // PTK
                    setPTK(key->key, key->key_len);
                    break;
                case 0: // GTK
                    setGTK(key->key, key->key_len, key->key_index, key->key_rsc);
                    break;
            }
            break;
        case APPLE80211_CIPHER_PMK:
            XYLog("Setting WPA PMK is not supported\n");
            break;
        case APPLE80211_CIPHER_MSK:
            XYLog("Setting MSK\n");
            ieee80211_pmksa_add(fHalService->get80211Controller(), IEEE80211_AKM_8021X,
                                fHalService->get80211Controller()->ic_bss->ni_macaddr, key->key, 0);
            break;
        case APPLE80211_CIPHER_PMKSA:
            XYLog("Setting WPA PMKSA\n");
            ieee80211_pmksa_add(fHalService->get80211Controller(), IEEE80211_AKM_8021X,
                                fHalService->get80211Controller()->ic_bss->ni_macaddr, key->key, 0);
            break;
    }
    //fInterface->postMessage(APPLE80211_M_CIPHER_KEY_CHANGED);
    return kIOReturnSuccess;
#endif
}

IOReturn AirportItlwmSkywalkInterface::
getPHY_MODE(struct apple80211_phymode_data *pd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    
    pd->version = APPLE80211_VERSION;
    pd->phy_mode = APPLE80211_MODE_11A
    | APPLE80211_MODE_11B
    | APPLE80211_MODE_11G
    | APPLE80211_MODE_11N;
    
    if (ic->ic_flags & IEEE80211_F_VHTON)
        pd->phy_mode |= APPLE80211_MODE_11AC;
    
    if (ic->ic_flags & IEEE80211_F_HEON)
        pd->phy_mode |= APPLE80211_MODE_11AX;
    
    switch (fHalService->get80211Controller()->ic_curmode) {
        case IEEE80211_MODE_AUTO:
            pd->active_phy_mode = APPLE80211_MODE_AUTO;
            break;
        case IEEE80211_MODE_11A:
            pd->active_phy_mode = APPLE80211_MODE_11A;
            break;
        case IEEE80211_MODE_11B:
            pd->active_phy_mode = APPLE80211_MODE_11B;
            break;
        case IEEE80211_MODE_11G:
            pd->active_phy_mode = APPLE80211_MODE_11G;
            break;
        case IEEE80211_MODE_11N:
            pd->active_phy_mode = APPLE80211_MODE_11N;
            break;
        case IEEE80211_MODE_11AC:
            pd->active_phy_mode = APPLE80211_MODE_11AC;
            break;
        case IEEE80211_MODE_11AX:
            pd->active_phy_mode = ic->ic_state == IEEE80211_S_RUN && ic->ic_bss &&
                (ic->ic_bss->ni_flags & IEEE80211_NODE_HE) ? APPLE80211_MODE_11AX : APPLE80211_MODE_AUTO;
            break;
            
        default:
            pd->active_phy_mode = APPLE80211_MODE_AUTO;
            break;
    }
    
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getCHANNEL(struct apple80211_channel_data *cd)
{
    struct ieee80211com * ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(cd, 0, sizeof(apple80211_channel_data));
        cd->version = APPLE80211_VERSION;
        cd->channel.version = APPLE80211_VERSION;
        cd->channel.channel = ieee80211_chan2ieee(ic, ic->ic_bss->ni_chan);
        cd->channel.flags = ieeeChanFlag2apple(ic->ic_bss->ni_chan->ic_flags, ic->ic_bss->ni_chw);
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getSTATE(struct apple80211_state_data *sd)
{
    memset(sd, 0, sizeof(*sd));
    sd->version = APPLE80211_VERSION;
    sd->state = fHalService->get80211Controller()->ic_state;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getMCS_INDEX_SET(struct apple80211_mcs_index_set_data *ad)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(ad, 0, sizeof(*ad));
        ad->version = APPLE80211_VERSION;
        size_t size = min(ARRAY_SIZE(ic->ic_bss->ni_rxmcs), ARRAY_SIZE(ad->mcs_set_map));
        for (int i = 0; i < size; i++)
            ad->mcs_set_map[i] = ic->ic_bss->ni_rxmcs[i];
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getVHT_MCS_INDEX_SET(struct apple80211_vht_mcs_index_set_data *data)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL || ic->ic_curmode != IEEE80211_MODE_11AC) {
        return kIOReturnError;
    }
    memset(data, 0, sizeof(struct apple80211_vht_mcs_index_set_data));
    data->version = APPLE80211_VERSION;
    data->mcs_map = ic->ic_bss->ni_vht_mcsinfo.tx_mcs_map;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getMCS_VHT(struct apple80211_mcs_vht_data *data)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL || ic->ic_curmode != IEEE80211_MODE_11AC) {
        return kIOReturnError;
    }
    memset(data, 0, sizeof(struct apple80211_mcs_vht_data));
    data->version = APPLE80211_VERSION;
    data->guard_interval = (ieee80211_node_supports_vht_sgi80(ic->ic_bss) || ieee80211_node_supports_vht_sgi160(ic->ic_bss)) ? APPLE80211_GI_SHORT : APPLE80211_GI_LONG;
    data->index = ic->ic_bss->ni_txmcs;
    data->nss = fHalService->getDriverInfo()->getTxNSS();
    switch (ic->ic_bss->ni_chw) {
        case IEEE80211_CHAN_WIDTH_40:
            data->bw = 40;
            break;
        case IEEE80211_CHAN_WIDTH_80:
            data->bw = 80;
            break;
        case IEEE80211_CHAN_WIDTH_80P80:
        case IEEE80211_CHAN_WIDTH_160:
            data->bw = 160;
            break;
            
        default:
            data->bw = 20;
            break;
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getRATE_SET(struct apple80211_rate_set_data *ad)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(ad, 0, sizeof(*ad));
        ad->version = APPLE80211_VERSION;
        ad->num_rates = ic->ic_bss->ni_rates.rs_nrates;
        size_t size = min(ic->ic_bss->ni_rates.rs_nrates, ARRAY_SIZE(ad->rates));
        for (int i=0; i < size; i++) {
#ifdef AIRPORT_WCL
            struct apple80211_rate &apple_rate = ad->rates[i];
#else
            struct apple80211_rate apple_rate = ad->rates[i];
#endif
            apple_rate.version = APPLE80211_VERSION;
            apple_rate.rate = ic->ic_bss->ni_rates.rs_rates[i];
            apple_rate.flags = 0;
        }
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getOP_MODE(struct apple80211_opmode_data *od)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    od->version = APPLE80211_VERSION;
    switch (ic->ic_opmode) {
        case IEEE80211_M_HOSTAP:
            od->op_mode = APPLE80211_M_HOSTAP;
            break;
        case IEEE80211_M_IBSS:
        case IEEE80211_M_AHDEMO:
            od->op_mode = APPLE80211_M_IBSS;
            break;
        case IEEE80211_M_MONITOR:
            od->op_mode = APPLE80211_M_MONITOR;
            break;
        default:
            od->op_mode = APPLE80211_M_STA;
            break;
    }
    return kIOReturnSuccess;
}

/* ---------------------------------------------------------------------- *
 *  Software AP (Internet Sharing / hotspot)
 *
 *  airportd never tells the driver "be an AP" in one shot: it drips the
 *  ssid, the channel, the key and finally the mode over several ioctls, in
 *  an order we do not control.  Everything below therefore only *records*
 *  what was asked for and, once we have at least an ssid and a channel,
 *  latches an AP start into ic_ap_start_pending and lets the driver's
 *  state machine do the actual bring-up (INIT -> SCAN -> create_ibss ->
 *  RUN -> iwm_run()).  Returning an error from any of these is not an
 *  option: WCL treats it as a fatal configuration failure and tears the
 *  whole link down.
 * ---------------------------------------------------------------------- */

void AirportItlwmSkywalkInterface::
noteAPConfig(const char *what)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    XYLog("itlwm: AP %s: opmode=%d state=%d pending=%d chan=%d essid_len=%u\n",
          what, ic->ic_opmode, ic->ic_state, ic->ic_ap_start_pending,
          ic->ic_des_chan == IEEE80211_CHAN_ANYC ?
              0 : ieee80211_chan2ieee(ic, ic->ic_des_chan),
          (unsigned)ic->ic_des_esslen);
}

struct ieee80211_channel *AirportItlwmSkywalkInterface::
lookupChannel(uint32_t channel)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (channel == 0 || channel == IEEE80211_CHAN_ANY ||
        channel > IEEE80211_CHAN_MAX)
        return IEEE80211_CHAN_ANYC;
    if (ic->ic_channels[channel].ic_freq == 0)
        return IEEE80211_CHAN_ANYC;
    if (isclr(ic->ic_chan_active, channel))
        return IEEE80211_CHAN_ANYC;
    return &ic->ic_channels[channel];
}

/*
 * Derive the AP's PMK from a WPA2 passphrase and turn on RSN/PSK.  The
 * in-driver 4-way authenticator (ieee80211_pae_input.c) picks up ic_psk on
 * association and sends msg1; the beacon advertises the RSN IE built from
 * these parameters.  passwordLen == 0 restores an open AP.
 */
void AirportItlwmSkywalkInterface::
configureAPSecurity(const uint8_t *ssid, uint32_t ssidLen,
                    const uint8_t *password, uint32_t passwordLen)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (!ic)
        return;

    /* Always start from a clean RSN state so a previous start's PSK does
     * not leak into an open AP (and vice versa). */
    ieee80211_disable_rsn(ic);

    if (passwordLen == 0 || !password)
        return; /* open AP */

    /* PBKDF2 uses strlen() on the passphrase, so it must be NUL-terminated.
     * WPA2 passphrases are 8..63 printable ASCII characters. */
    if (passwordLen < 8 || passwordLen > 63)
        return;
    char passphrase[64];
    memcpy(passphrase, password, passwordLen);
    passphrase[passwordLen] = '\0';

    uint8_t pmk[IEEE80211_PMK_LEN];
    if (pbkdf2_sha1(passphrase, ssid, ssidLen, 4096, pmk, sizeof(pmk)) != 0) {
        XYLog("itlwm: AP PBKDF2 failed; leaving AP open\n");
        return;
    }

    memcpy(ic->ic_psk, pmk, sizeof(ic->ic_psk));
    explicit_bzero(pmk, sizeof(pmk));
    ic->ic_flags |= IEEE80211_F_PSK;

    struct ieee80211_wpaparams wpa;
    bzero(&wpa, sizeof(wpa));
    wpa.i_enabled = 1;
    wpa.i_protos = IEEE80211_WPA_PROTO_WPA2;
    wpa.i_akms = IEEE80211_WPA_AKM_PSK;
    wpa.i_ciphers = IEEE80211_WPA_CIPHER_CCMP;
    wpa.i_groupcipher = IEEE80211_WPA_CIPHER_CCMP;
    ieee80211_ioctl_setwpaparms(ic, &wpa);   /* sets IEEE80211_F_RSNON */

    XYLog("itlwm: AP WPA2-PSK configured (ssid_len=%u passphrase_len=%u)\n",
          ssidLen, passwordLen);
}

/*
 * Everything needed for an AP start is in place: switch the opmode and
 * hand the request to the state machine.  ieee80211_new_state(INIT) is a
 * no-op for net80211 when we are already in INIT, which is exactly why
 * iwm_newstate() honours ic_ap_start_pending instead of returning early.
 */
IOReturn AirportItlwmSkywalkInterface::
startAPMode(const uint8_t *ssid, uint32_t ssidLen, struct ieee80211_channel *chan)
{
    struct ieee80211com *ic = fHalService->get80211Controller();

    if (ssid == NULL || ssidLen == 0 || ssidLen > IEEE80211_NWID_LEN) {
        XYLog("itlwm: AP start rejected, no ssid (len=%u)\n", ssidLen);
        noteAPConfig("start-no-ssid");
        return kIOReturnSuccess;
    }
    if (chan == NULL) {
        XYLog("itlwm: AP start rejected, no channel\n");
        noteAPConfig("start-no-chan");
        return kIOReturnSuccess;
    }

    /*
     * Drop a station association first.  The AP needs the radio to itself
     * and net80211's INIT transition only sends disassoc frames when it
     * still thinks we are a station.
     */
    if (ic->ic_opmode == IEEE80211_M_STA &&
        (ic->ic_state == IEEE80211_S_RUN || ic->ic_state == IEEE80211_S_ASSOC)) {
        ieee80211_del_ess(ic, NULL, 0, 1);
        ieee80211_deselect_ess(ic);
    }

    ic->ic_opmode = IEEE80211_M_HOSTAP;
    ic->ic_flags &= ~IEEE80211_F_IBSSON;
    ieee80211_reset_erp(ic);

    memset(ic->ic_des_essid, 0, IEEE80211_NWID_LEN);
    memcpy(ic->ic_des_essid, ssid, ssidLen);
    ic->ic_des_esslen = ssidLen;
    ic->ic_des_chan = chan;
    ic->ic_ibss_chan = chan;

    /* Derive and install the WPA2 PMK before the state machine brings the
     * BSS up, so the beacon advertises RSN and association starts the 4-way
     * handshake with a PSK already in place. */
    configureAPSecurity(ic->ic_des_essid, ic->ic_des_esslen,
                        apPassword, apPasswordLen);
    ic->ic_flags &= ~IEEE80211_F_DESBSSID;
    IEEE80211_ADDR_COPY(ic->ic_des_bssid, etheranyaddr);

    apConfigured = true;
    noteAPConfig("start");

    ic->ic_ap_start_pending = 1;
    ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
stopAPMode()
{
    struct ieee80211com *ic = fHalService->get80211Controller();

    if (ic->ic_opmode != IEEE80211_M_HOSTAP && !apConfigured) {
        noteAPConfig("stop-noop");
        apModeRequested = false;
        return kIOReturnSuccess;
    }
    apConfigured = false;
    apModeRequested = false;
    noteAPConfig("stop");

    if (ic->ic_state == IEEE80211_S_INIT) {
        /* Nothing is running: fall back immediately, no trip through the
         * state machine required. */
        ic->ic_opmode = IEEE80211_M_STA;
        ic->ic_flags &= ~IEEE80211_F_IBSSON;
        ieee80211_reset_erp(ic);
        ic->ic_des_chan = IEEE80211_CHAN_ANYC;
        return kIOReturnSuccess;
    }

    ic->ic_ap_start_pending = 2;
    ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
    return kIOReturnSuccess;
}

/*
 * Called once the recorded ssid and channel are both present *and* an AP
 * mode has actually been requested.  A missing half is not an error:
 * airportd is free to send them in either order, and setSSID/setCHANNEL on
 * their own belong to an ordinary station join.
 */
void AirportItlwmSkywalkInterface::
maybeStartAP(const char *why)
{
    if (!apModeRequested)
        return;
    if (apSsidLen == 0 || apChan == NULL) {
        noteAPConfig(why);
        return;
    }
    startAPMode(apSsid, apSsidLen, apChan);
}

IOReturn AirportItlwmSkywalkInterface::
setAP_MODE(struct apple80211_apmode_data *d)
{
    if (!d)
        return kIOReturnSuccess;
    XYLog("%s apmode=%u\n", __FUNCTION__, d->apmode);

    switch (d->apmode) {
        case APPLE80211_AP_MODE_INFRA:
        case APPLE80211_AP_MODE_ANY:
            apModeRequested = true;
            maybeStartAP("setAP_MODE");
            break;
        case APPLE80211_AP_MODE_IBSS:
            /*
             * Ad-hoc is requested; net80211's bring-up path is shared with
             * hostap (ieee80211_create_ibss) but our HAL only implements
             * the AP role, so honour it as an AP and say so.
             */
            XYLog("itlwm: IBSS requested, using AP mode\n");
            apModeRequested = true;
            maybeStartAP("setAP_MODE-ibss");
            break;
        case APPLE80211_AP_MODE_UNKNOWN:
        default:
            stopAPMode();
            break;
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setIBSS_MODE(struct apple80211_network_data *nd)
{
    if (!nd)
        return kIOReturnSuccess;
    XYLog("%s nd_mode=%u ssid_len=%u chan=%u key_len=%u\n", __FUNCTION__,
          nd->nd_mode, nd->nd_ssid_len, nd->nd_channel.channel,
          nd->nd_key.key_len);

    if (nd->nd_ssid_len > 0 && nd->nd_ssid_len <= IEEE80211_NWID_LEN) {
        memset(apSsid, 0, sizeof(apSsid));
        memcpy(apSsid, nd->nd_ssid, nd->nd_ssid_len);
        apSsidLen = nd->nd_ssid_len;
    }
    if (nd->nd_channel.channel != 0)
        apChan = lookupChannel(nd->nd_channel.channel);

    if (nd->nd_ssid_len == 0 && nd->nd_channel.channel == 0) {
        /* Empty request: tear any AP down. */
        stopAPMode();
        return kIOReturnSuccess;
    }

    if (nd->nd_mode == APPLE80211_AP_MODE_IBSS)
        XYLog("itlwm: IBSS requested, using AP mode\n");

    apModeRequested = true;
    maybeStartAP("setIBSS_MODE");
    return kIOReturnSuccess;
}

/*
 * Legacy spelling of the same request; the macOS15 protocol does not even
 * declare it, but the older IO80211InfraProtocol does, so keep it working
 * for the non-WCL targets.
 */
IOReturn AirportItlwmSkywalkInterface::
setHOST_AP_MODE(struct apple80211_network_data *nd)
{
    XYLog("%s\n", __FUNCTION__);
    return setIBSS_MODE(nd);
}

IOReturn AirportItlwmSkywalkInterface::
setCHANNEL(struct apple80211_channel_data *cd)
{
    if (!cd)
        return kIOReturnSuccess;
    apChan = lookupChannel(cd->channel.channel);
    XYLog("%s channel=%u -> %s\n", __FUNCTION__, cd->channel.channel,
          apChan == IEEE80211_CHAN_ANYC ? "unusable" : "ok");
    if (apChan == IEEE80211_CHAN_ANYC) {
        /* An unusable channel must not be kept around: it would make every
         * later AP start fail with "no channel". */
        apChan = NULL;
        return kIOReturnSuccess;
    }
    if (apSsidLen > 0)
        maybeStartAP("setCHANNEL");
    return kIOReturnSuccess;
}

void AirportItlwmSkywalkInterface::
setAPPassword(const uint8_t *password, uint32_t passwordLen)
{
    memset(apPassword, 0, sizeof(apPassword));
    apPasswordLen = 0;
    if (!password || passwordLen == 0)
        return; /* open AP */
    if (passwordLen > sizeof(apPassword))
        passwordLen = sizeof(apPassword);
    memcpy(apPassword, password, passwordLen);
    apPasswordLen = passwordLen;
}

IOReturn AirportItlwmSkywalkInterface::
setSSID(struct apple80211_ssid_data *sd)
{
    if (!sd)
        return kIOReturnSuccess;
    XYLog("%s len=%u\n", __FUNCTION__, sd->ssid_len);

    if (sd->ssid_len == 0 || sd->ssid_len > IEEE80211_NWID_LEN)
        return kIOReturnSuccess;
    memset(apSsid, 0, sizeof(apSsid));
    memcpy(apSsid, sd->ssid_bytes, sd->ssid_len);
    apSsidLen = sd->ssid_len;
    if (apChan != NULL)
        maybeStartAP("setSSID");
    return kIOReturnSuccess;
}

/*
 * Extra beacon/probe-response IEs.  net80211 builds its own beacon from
 * the node state, so there is nothing sensible to store yet -- but log it
 * so the sequence airportd actually uses is visible in the log.
 */
IOReturn AirportItlwmSkywalkInterface::
setIE(struct apple80211_ie_data *ie)
{
    if (!ie)
        return kIOReturnSuccess;
    XYLog("%s frame_type=%u add=%u ie_len=%u\n", __FUNCTION__,
          ie->frame_type_flags, ie->add, ie->ie_len);
    return kIOReturnSuccess;
}

/*
 * Internet Sharing asks for a virtual interface before configuring the AP.
 * We only ever expose one interface, so acknowledge the request rather than
 * fail it -- a failure here aborts the whole sharing setup.
 */
IOReturn AirportItlwmSkywalkInterface::
setVIRTUAL_IF_CREATE(struct apple80211_virt_if_create_data *vif)
{
    if (!vif)
        return kIOReturnSuccess;
    XYLog("%s role=%u bsd_name=%.16s\n", __FUNCTION__, vif->role,
          (const char *)vif->bsd_name);
    noteAPConfig("virt-if-create");
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getTXPOWER(struct apple80211_txpower_data *txd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(txd, 0, sizeof(*txd));
        txd->version = APPLE80211_VERSION;
        txd->txpower = ic->ic_txpower;
        txd->txpower_unit = APPLE80211_UNIT_PERCENT;
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getRATE(struct apple80211_rate_data *rd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL)
        return 6;
    int nss;
    int sgi;
    int index = 0;
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(rd, 0, sizeof(*rd));
        rd->version = APPLE80211_VERSION;
        rd->num_radios = 1;
        sgi = ieee80211_node_supports_sgi(ic->ic_bss);
        if (ic->ic_bss->ni_flags & IEEE80211_NODE_HE) {
            rd->rate[0] = ic->ic_bss->ni_he_txrate_kbps / 1000;
        } else if (ic->ic_curmode == IEEE80211_MODE_11AC) {
            if (sgi)
                index += 1;
            nss = fHalService->getDriverInfo()->getTxNSS();
            switch (ic->ic_bss->ni_chw) {
                case IEEE80211_CHAN_WIDTH_40:
                    index += 4;
                    break;
                case IEEE80211_CHAN_WIDTH_80:
                    index += 8;
                    break;
                case IEEE80211_CHAN_WIDTH_80P80:
                case IEEE80211_CHAN_WIDTH_160:
                    index += 12;
                    break;

                default:
                    break;
            }
            index += 2 * (nss - 1);
            const struct ieee80211_vht_rateset *rs = &ieee80211_std_ratesets_11ac[index];
            rd->rate[0] = rs->rates[ic->ic_bss->ni_txmcs % rs->nrates] / 2;
        } else if (ic->ic_curmode == IEEE80211_MODE_11N) {
            int is_40mhz = ic->ic_bss->ni_chw == IEEE80211_CHAN_WIDTH_40;
            if (sgi)
                index += 1;
            if (is_40mhz)
                index += (IEEE80211_HT_RATESET_MIMO4_SGI + 1);
            index += (ic->ic_bss->ni_txmcs / 16);
            nss = ic->ic_bss->ni_txmcs / 8 + 1;
            index += 2 * (nss - 1);
            rd->rate[0] = ieee80211_std_ratesets_11n[index].rates[ic->ic_bss->ni_txmcs % 8] / 2;
        } else
            rd->rate[0] = ic->ic_bss->ni_rates.rs_rates[ic->ic_bss->ni_txrate];
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getBSSID(struct apple80211_bssid_data *bd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(bd, 0, sizeof(*bd));
        bd->version = APPLE80211_VERSION;
        memcpy(bd->bssid.octet, ic->ic_bss->ni_bssid, APPLE80211_ADDR_LEN);
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getRSSI(struct apple80211_rssi_data *rd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(rd, 0, sizeof(*rd));
        rd->num_radios = 1;
        rd->rssi_unit = APPLE80211_UNIT_DBM;
        rd->rssi[0] = rd->aggregate_rssi
        = rd->rssi_ext[0]
        = rd->aggregate_rssi_ext
        = -(0 - IWM_MIN_DBM - ic->ic_bss->ni_rssi);
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getRSN_IE(struct apple80211_rsn_ie_data *data)
{
#ifdef AIRPORT_WCL
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(10), data);
#elif defined(USE_APPLE_SUPPLICANT)
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_bss == NULL || ic->ic_bss->ni_rsnie == NULL) {
        return kIOReturnError;
    }
    data->version = APPLE80211_VERSION;
    if (ic->ic_rsn_ie_override[1] > 0) {
        data->len = 2 + ic->ic_rsn_ie_override[1];
        memcpy(data->ie, ic->ic_rsn_ie_override, data->len);
    }
    else {
        data->len = 2 + ic->ic_bss->ni_rsnie[1];
        memcpy(data->ie, ic->ic_bss->ni_rsnie, data->len);
    }
    return kIOReturnSuccess;
#else
    return kIOReturnUnsupported;
#endif
}

IOReturn AirportItlwmSkywalkInterface::
setRSN_IE(struct apple80211_rsn_ie_data *data)
{
#ifdef AIRPORT_WCL
    return _fCommandGate->runAction(wclCommand, this, reinterpret_cast<void *>(9), data);
#elif defined(USE_APPLE_SUPPLICANT)
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (!data)
        return kIOReturnError;
    static_assert(sizeof(ic->ic_rsn_ie_override) == APPLE80211_MAX_RSN_IE_LEN, "Max RSN IE length mismatch");
    memcpy(ic->ic_rsn_ie_override, data->ie, APPLE80211_MAX_RSN_IE_LEN);
    if (ic->ic_state == IEEE80211_S_RUN && ic->ic_bss != nullptr)
        ieee80211_save_ie(data->ie, &ic->ic_bss->ni_rsnie);
    return kIOReturnSuccess;
#else
    return kIOReturnUnsupported;
#endif
}

IOReturn AirportItlwmSkywalkInterface::
getAP_IE_LIST(struct apple80211_ap_ie_data *data)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (!data)
        return kIOReturnError;
    if (ic->ic_bss == NULL || ic->ic_bss->ni_rsnie_tlv == NULL || ic->ic_bss->ni_rsnie_tlv_len == 0 || ic->ic_bss->ni_rsnie_tlv_len > data->len || ic->ic_bss->ni_rsnie_tlv_len > 1024)
        return kIOReturnError;
    data->version = APPLE80211_VERSION;
    data->len = ic->ic_bss->ni_rsnie_tlv_len;
    memcpy(data->ie_data, ic->ic_bss->ni_rsnie_tlv, data->len);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getDTIM_INT(struct apple80211_dtim_int_data *dd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (!dd)
        return kIOReturnError;
    dd->version = APPLE80211_VERSION;
    /*
     * The associated node carries the DTIM period advertised by the AP;
     * ic_dtim_period is the value net80211 last programmed while running.
     */
    if (ic->ic_state == IEEE80211_S_RUN && ic->ic_bss != NULL)
        dd->interval = ic->ic_bss->ni_dtimperiod;
    else
        dd->interval = ic->ic_dtim_period;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getSTATS(struct apple80211_stats_data *sd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (!sd)
        return kIOReturnError;

    memset(sd, 0, sizeof(*sd));
    sd->version = APPLE80211_VERSION;

#ifdef AIRPORT_WCL
    /* Per-AC software counters maintained by the TX/RX fast paths. */
    for (unsigned i = 0; i < 4; i++) {
        sd->tx_frame_count += (u_int32_t)ic->ic_wcl_tx_packets[i];
        sd->rx_frame_count += (u_int32_t)ic->ic_wcl_rx_packets[i];
    }
#endif

    /* Drop counters from net80211; cheap and truthful diagnostics. */
    sd->tx_errors = ic->ic_stats.is_tx_nombuf + ic->ic_stats.is_tx_nonode +
                    ic->ic_stats.is_tx_unknownmgt + ic->ic_stats.is_tx_noauth;
    sd->rx_errors = ic->ic_stats.is_rx_badversion +
                    ic->ic_stats.is_rx_tooshort +
                    ic->ic_stats.is_rx_wrongbss +
                    ic->ic_stats.is_rx_dup +
                    ic->ic_stats.is_rx_notassoc +
                    ic->ic_stats.is_rx_decryptcrc +
                    ic->ic_stats.is_rx_eapol_badmic +
                    ic->ic_stats.is_ccmp_dec_errs;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getRX_RATE(struct apple80211_rate_data *rd)
{
    /*
     * The HAL does not track a per-packet RX rate; the firmware reports the
     * negotiated set only. Return the same current-rate view as getRATE so
     * networkQuality and wdutil have a consistent value instead of an error.
     */
    return getRATE(rd);
}

IOReturn AirportItlwmSkywalkInterface::
getNOISE(struct apple80211_noise_data *nd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state == IEEE80211_S_RUN) {
        memset(nd, 0, sizeof(*nd));
        nd->version = APPLE80211_VERSION;
        nd->num_radios = 1;
        nd->noise[0]
        = nd->aggregate_noise = -fHalService->getDriverInfo()->getBSSNoise();
        nd->noise_unit = APPLE80211_UNIT_DBM;
        return kIOReturnSuccess;
    }
    return 6;
}

IOReturn AirportItlwmSkywalkInterface::
getPOWERSAVE(struct apple80211_powersave_data *pd)
{
    if (!pd)
        return kIOReturnError;
    pd->version = APPLE80211_VERSION;
    pd->powersave_level = fHalService->getPowerSaveMode() ?
        APPLE80211_POWERSAVE_MODE_80211 :
        APPLE80211_POWERSAVE_MODE_DISABLED;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setPOWERSAVE(struct apple80211_powersave_data *pd)
{
    if (!pd)
        return kIOReturnBadArgument;
    /*
     * Unknown levels (WOW, vendor MIMO) are accepted without changing the
     * hardware: failing a power-save request is treated as a config error by
     * WCL and can take the link down with it.
     */
    if (pd->powersave_level > APPLE80211_POWERSAVE_MODE_MAX_POWERSAVE)
        return kIOReturnSuccess;
#ifdef AIRPORT_WCL
    if (!_fCommandGate)
        return kIOReturnNotReady;
    return _fCommandGate->runAction(wclCommand, this,
                                    reinterpret_cast<void *>(16), pd);
#else
    /* Any non-zero Apple level means "let the hardware doze". */
    return fHalService->setPowerSaveMode(
        pd->powersave_level != APPLE80211_POWERSAVE_MODE_DISABLED ? 1 : 0);
#endif
}

IOReturn AirportItlwmSkywalkInterface::
setPM_MODE(apple80211_pm_mode *pm)
{
    if (!pm)
        return kIOReturnBadArgument;
    /*
     * apple80211_pm_mode is opaque in the public IO80211 headers. Like every
     * Apple 80211 request it begins with a 32-bit version, and the mode
     * follows it. Read the field defensively: an unexpected layout yields a
     * value outside the powersave range and is accepted without touching the
     * hardware, so a wrong guess can never disable a working link.
     */
    u_int32_t mode = 0;
    memcpy(&mode, reinterpret_cast<const u_int8_t *>(pm) + sizeof(u_int32_t),
           sizeof(mode));
    if (mode > APPLE80211_POWERSAVE_MODE_MAX_POWERSAVE)
        return kIOReturnSuccess;
#ifdef AIRPORT_WCL
    if (!_fCommandGate)
        return kIOReturnNotReady;
    return _fCommandGate->runAction(
        wclCommand, this,
        reinterpret_cast<void *>(17),
        reinterpret_cast<void *>(static_cast<uintptr_t>(
            mode != APPLE80211_POWERSAVE_MODE_DISABLED)));
#else
    return fHalService->setPowerSaveMode(
        mode != APPLE80211_POWERSAVE_MODE_DISABLED ? 1 : 0);
#endif
}

IOReturn AirportItlwmSkywalkInterface::
getNSS(struct apple80211_nss_data *data)
{
    memset(data, 0, sizeof(*data));
    data->version = APPLE80211_VERSION;
    data->nss = fHalService->getDriverInfo()->getTxNSS();
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setASSOCIATE(struct apple80211_assoc_data *ad)
{
    XYLog("%s [%s] mode=%d ad_auth_lower=%d ad_auth_upper=%d rsn_ie_len=%d%s%s%s%s%s%s%s\n", __FUNCTION__, ad->ad_ssid, ad->ad_mode, ad->ad_auth_lower, ad->ad_auth_upper, ad->ad_rsn_ie_len,
          (ad->ad_flags & 2) ? ", Instant Hotspot" : "",
          (ad->ad_flags & 4) ? ", Auto Instant Hotspot" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 1) ? ", don't disassociate" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 2) ? ", don't blacklist" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 4) ? ", closed Network" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 8) ? ", 802.1X" : "",
          (ad->ad_rsn_ie[APPLE80211_MAX_RSN_IE_LEN] & 0x20) ? ", force BSSID" : "");
    
    struct apple80211_rsn_ie_data rsn_ie_data;
    struct apple80211_authtype_data auth_type_data;
    struct ieee80211com *ic = fHalService->get80211Controller();

    if (!ad)
        return kIOReturnError;
    
    if (ic->ic_state < IEEE80211_S_SCAN)
        return kIOReturnSuccess;
    
    if (ic->ic_state == IEEE80211_S_ASSOC || ic->ic_state == IEEE80211_S_AUTH)
        return kIOReturnSuccess;

    if (ad->ad_mode != APPLE80211_AP_MODE_IBSS) {
        disassocIsVoluntary = false;
        auth_type_data.version = APPLE80211_VERSION;
        auth_type_data.authtype_upper = ad->ad_auth_upper;
        auth_type_data.authtype_lower = ad->ad_auth_lower;
        setAUTH_TYPE(&auth_type_data);
        rsn_ie_data.version = APPLE80211_VERSION;
        rsn_ie_data.len = ad->ad_rsn_ie[1] + 2;
        memcpy(rsn_ie_data.ie, ad->ad_rsn_ie, rsn_ie_data.len);
        setRSN_IE(&rsn_ie_data);

        associateSSID(ad->ad_ssid, ad->ad_ssid_len, ad->ad_bssid, ad->ad_auth_lower, ad->ad_auth_upper, ad->ad_key.key, ad->ad_key.key_len, ad->ad_key.key_index);
        /*
         * net80211 joins at the end of the scan in progress, up to a full
         * scan (3-4 s) later, which can exceed the system's ~4 s association
         * timeout. Ask the driver to end the scan now and choose the BSS
         * from the node table filled by the scan that preceded this request.
         */
        if (ic->ic_state == IEEE80211_S_SCAN && ic->ic_scan_restart_supported) {
            ic->ic_join_now = true;
            ic->ic_newstate(ic, IEEE80211_S_SCAN, -1);
        }
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setDISASSOCIATE(struct apple80211_disassoc_data *ad)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = fHalService->get80211Controller();

    if (ic->ic_state < IEEE80211_S_SCAN)
        return kIOReturnSuccess;
    
    if (ic->ic_state > IEEE80211_S_AUTH && ic->ic_bss != NULL)
        IEEE80211_SEND_MGMT(ic, ic->ic_bss, IEEE80211_FC0_SUBTYPE_DEAUTH, IEEE80211_REASON_AUTH_LEAVE);
    
    if (ic->ic_state == IEEE80211_S_ASSOC || ic->ic_state == IEEE80211_S_AUTH)
        return kIOReturnSuccess;
    
    disassocIsVoluntary = true;

    ieee80211_del_ess(ic, nullptr, 0, 1);
    ieee80211_deselect_ess(ic);
#ifdef USE_APPLE_SUPPLICANT
    ic->ic_rsn_ie_override[1] = 0;
#endif
    ic->ic_assoc_status = APPLE80211_STATUS_UNAVAILABLE;
    ic->ic_deauth_reason = APPLE80211_REASON_ASSOC_LEAVING;
    ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getSUPPORTED_CHANNELS(struct apple80211_sup_channel_data *ad)
{
    if (!ad)
        return kIOReturnError;
    ad->version = APPLE80211_VERSION;
    ad->num_channels = 0;
    struct ieee80211com *ic = fHalService->get80211Controller();
    for (int i = 0; i < IEEE80211_CHAN_MAX; i++) {
        if (ic->ic_channels[i].ic_freq != 0) {
            ad->supported_channels[ad->num_channels].channel = ieee80211_chan2ieee(ic, &ic->ic_channels[i]);
            ad->supported_channels[ad->num_channels].flags = ieeeChanFlag2appleScanFlagVentura(ic->ic_channels[i].ic_flags);
            ad->num_channels++;
        }
    }
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getLOCALE(struct apple80211_locale_data *ld)
{
    char cc[3] = { 0, 0, 0 };
    const char *fw_cc;

    if (!ld)
        return kIOReturnError;

    /* Same precedence as getCOUNTRY_CODE: boot override, then firmware. */
    PE_parse_boot_argn("itlwm_cc", cc, sizeof(cc));
    if (!cc[0]) {
        fw_cc = fHalService->getDriverInfo()->getFirmwareCountryCode();
        if (fw_cc) {
            cc[0] = fw_cc[0];
            cc[1] = fw_cc[1];
        }
    }

    ld->version = APPLE80211_VERSION;
    ld->locale  = appleLocaleForCountryCode(cc);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getDEAUTH(struct apple80211_deauth_data *da)
{
    if (!da)
        return kIOReturnError;
    da->version = APPLE80211_VERSION;
    struct ieee80211com *ic = fHalService->get80211Controller();
    da->deauth_reason = ic->ic_deauth_reason;
//    XYLog("%s, %d\n", __FUNCTION__, da->deauth_reason);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getASSOCIATION_STATUS(struct apple80211_assoc_status_data *hv)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    
    if (!hv)
        return kIOReturnError;
    memset(hv, 0, sizeof(*hv));
    hv->version = APPLE80211_VERSION;
    if (ic->ic_state == IEEE80211_S_RUN)
        hv->status = APPLE80211_STATUS_SUCCESS;
    else
        hv->status = APPLE80211_STATUS_UNAVAILABLE;
//    XYLog("%s, %d\n", __FUNCTION__, hv->status);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setSCANCACHE_CLEAR(void *req)
{
    XYLog("%s\n", __FUNCTION__);
    struct ieee80211com *ic = fHalService->get80211Controller();
    //if doing background or active scan, don't free nodes.
    if ((ic->ic_flags & IEEE80211_F_BGSCAN) || (ic->ic_flags & IEEE80211_F_ASCAN))
        return kIOReturnSuccess;
    ieee80211_free_allnodes(ic, 0);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setDEAUTH(struct apple80211_deauth_data *da)
{
    XYLog("%s\n", __FUNCTION__);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getMCS(struct apple80211_mcs_data* md)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
    if (ic->ic_state != IEEE80211_S_RUN ||  ic->ic_bss == NULL || !md)
        return 6;
    md->version = APPLE80211_VERSION;
    md->index = ic->ic_bss->ni_txmcs;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getLINK_CHANGED_EVENT_DATA(struct apple80211_link_changed_event_data *ed)
{
    if (ed == nullptr)
        return 16;
    
    struct ieee80211com *ic = fHalService->get80211Controller();
    
    bzero(ed, sizeof(apple80211_link_changed_event_data));
    ed->isLinkDown = !(instance->currentStatus & kIONetworkLinkActive);
    if (ed->isLinkDown) {
        ed->voluntary = disassocIsVoluntary;
        ed->reason = APPLE80211_LINK_DOWN_REASON_DEAUTH;
    } else
        ed->rssi = -(0 - IWM_MIN_DBM - ic->ic_bss->ni_rssi);
    XYLog("Link %s, reason: %d, voluntary: %d\n", ed->isLinkDown ? "down" : "up", ed->reason, ed->voluntary);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
setSCAN_REQ(struct apple80211_scan_data *sd)
{
    struct ieee80211com *ic = fHalService->get80211Controller();
#if 0
    XYLog("%s Type: %u BSS Type: %u PHY Mode: %u Dwell time: %u Rest time: %u Num channels: %u SSID: %s BSSID: %s\n",
          __FUNCTION__,
          sd->scan_type,
          sd->bss_type,
          sd->phy_mode,
          sd->dwell_time,
          sd->rest_time,
          sd->num_channels,
          sd->ssid,
          ether_sprintf(sd->bssid.octet));
#endif
    if (fScanResultWrapping)
        return 22;
    if (ic->ic_state <= IEEE80211_S_INIT)
        return 22;
    if (sd->scan_type == APPLE80211_SCAN_TYPE_FAST || sd->scan_type == APPLE80211_SCAN_TYPE_PASSIVE) {
        if (scanSource) {
            scanSource->setTimeoutMS(100);
            scanSource->enable();
        }
        return kIOReturnSuccess;
    }
    ieee80211_begin_cache_bgscan(&ic->ic_ac.ac_if);
    if (scanSource) {
        scanSource->setTimeoutMS(100);
        scanSource->enable();
    }
    return kIOReturnSuccess;
}

extern OSDictionary *convertScanToDictionary(apple80211_scan_result *a1);

static int convertNodeToScanResult(ItlHalService *fHalService, struct ieee80211_node *fNextNodeToSend, apple80211_scan_result *result)
{
    bzero(result, sizeof(*result));
    result->version = APPLE80211_VERSION;
    if (fNextNodeToSend->ni_rsnie_tlv && fNextNodeToSend->ni_rsnie_tlv_len > 0) {
        result->asr_ie_len = fNextNodeToSend->ni_rsnie_tlv_len;
        memcpy(result->asr_ie_data, fNextNodeToSend->ni_rsnie_tlv, MIN(result->asr_ie_len, sizeof(result->asr_ie_data)));
    } else {
        result->asr_ie_len = 0;
    }
    result->asr_beacon_int = fNextNodeToSend->ni_intval;
    for (int i = 0; i < result->asr_nrates; i++ )
        result->asr_rates[i] = fNextNodeToSend->ni_rates.rs_rates[i];
    result->asr_nrates = fNextNodeToSend->ni_rates.rs_nrates;
    result->asr_age = (uint32_t)(airport_up_time() - fNextNodeToSend->ni_age_ts);
    result->asr_cap = fNextNodeToSend->ni_capinfo;
    result->asr_channel.version = APPLE80211_VERSION;
    result->asr_channel.channel = ieee80211_chan2ieee(fHalService->get80211Controller(), fNextNodeToSend->ni_chan);
    result->asr_channel.flags = ieeeChanFlag2appleScanFlagVentura(fNextNodeToSend->ni_chan->ic_flags);
    result->asr_noise = -fHalService->getDriverInfo()->getBSSNoise();
    result->asr_rssi = -(0 - IWM_MIN_DBM - fNextNodeToSend->ni_rssi);
    memcpy(result->asr_bssid, fNextNodeToSend->ni_bssid, IEEE80211_ADDR_LEN);
    result->asr_ssid_len = fNextNodeToSend->ni_esslen;
    if (result->asr_ssid_len != 0)
        memcpy(&result->asr_ssid, fNextNodeToSend->ni_essid, result->asr_ssid_len);
    return 0;
}

IOReturn AirportItlwmSkywalkInterface::
getCURRENT_NETWORK(apple80211_scan_result *sr)
{
    if (fHalService->get80211Controller()->ic_state != IEEE80211_S_RUN || fHalService->get80211Controller()->ic_bss == NULL)
        return kIOReturnError;
    convertNodeToScanResult(fHalService, fHalService->get80211Controller()->ic_bss, sr);
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getCOLOCATED_NETWORK_SCOPE_ID(apple80211_colocated_network_scope_id *as)
{
    if (!as)
        return kIOReturnBadArgument;
    as->version = APPLE80211_VERSION;
    return kIOReturnSuccess;
}

IOReturn AirportItlwmSkywalkInterface::
getSCAN_RESULT(struct apple80211_scan_result *sr)
{
    if (fNextNodeToSend == NULL) {
        if (fScanResultWrapping) {
            fScanResultWrapping = false;
            return 5;
        } else {
            fNextNodeToSend = RB_MIN(ieee80211_tree, &fHalService->get80211Controller()->ic_tree);
            if (fNextNodeToSend == NULL) {
                return 5;
            }
        }
    }
//    XYLog("%s ni_bssid=%s ni_essid=%s channel=%d flags=%d asr_cap=%d asr_nrates=%d asr_ssid_len=%d asr_ie_len=%d asr_rssi=%d\n", __FUNCTION__, ether_sprintf(fNextNodeToSend->ni_bssid), fNextNodeToSend->ni_essid, ieee80211_chan2ieee(ic, fNextNodeToSend->ni_chan), ieeeChanFlag2apple(fNextNodeToSend->ni_chan->ic_flags, -1), fNextNodeToSend->ni_capinfo, fNextNodeToSend->ni_rates.rs_nrates, fNextNodeToSend->ni_esslen, fNextNodeToSend->ni_rsnie_tlv == NULL ? 0 : fNextNodeToSend->ni_rsnie_tlv_len, fNextNodeToSend->ni_rssi);
    convertNodeToScanResult(fHalService, fNextNodeToSend, sr);
    
    fNextNodeToSend = RB_NEXT(ieee80211_tree, &HalService->get80211Controller()->ic_tree, fNextNodeToSend);
    if (fNextNodeToSend == NULL)
        fScanResultWrapping = true;

    return kIOReturnSuccess;
}

#ifdef AIRPORT_WCL
IOReturn AirportItlwmSkywalkInterface::getHW_ADDR(apple80211_hw_mac_address *data)
{
    if (!data) return kIOReturnBadArgument;
    AirportWCL::HardwareAddress value;
    if (!AirportWCL::copyHardwareAddress(wclPermanentMAC, value)) return kIOReturnNotReady;
    memcpy(data, &value, sizeof(value));
    return kIOReturnSuccess;
}

#if __IO80211_TARGET == __MAC_15_2
IOReturn AirportItlwmSkywalkInterface::setMacAddress(ether_addr &address)
{
    return instance->setHardwareAddress(&address, IEEE80211_ADDR_LEN);
}
#else
IOReturn AirportItlwmSkywalkInterface::setMacAddress(mloAddrArray &addresses)
{
    return instance->setHardwareAddress(&addresses, IEEE80211_ADDR_LEN);
}
#endif

#endif

#ifndef AIRPORT_WCL
IOReturn AirportItlwmSkywalkInterface::getHW_ADDR(apple80211_hw_mac_address *)
{
    return kIOReturnUnsupported;
}
#endif
