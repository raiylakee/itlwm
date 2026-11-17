/*
 * Copyright (C) 2020  钟先耀
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
/*    $OpenBSD: if_iwm.c,v 1.316 2020/12/07 20:09:24 tobhe Exp $    */

/*
 * Copyright (c) 2014, 2016 genua gmbh <info@genua.de>
 *   Author: Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2014 Fixup Software Ltd.
 * Copyright (c) 2017 Stefan Sperling <stsp@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*-
 * Based on BSD-licensed source modules in the Linux iwlwifi driver,
 * which were used as the reference documentation for this implementation.
 *
 ***********************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2007 - 2013 Intel Corporation. All rights reserved.
 * Copyright(c) 2013 - 2015 Intel Mobile Communications GmbH
 * Copyright(c) 2016 Intel Deutschland GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110,
 * USA
 *
 * The full GNU General Public License is included in this distribution
 * in the file called COPYING.
 *
 * Contact Information:
 *  Intel Linux Wireless <ilw@linux.intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 *
 * BSD LICENSE
 *
 * Copyright(c) 2005 - 2013 Intel Corporation. All rights reserved.
 * Copyright(c) 2013 - 2015 Intel Mobile Communications GmbH
 * Copyright(c) 2016 Intel Deutschland GmbH
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*-
 * Copyright (c) 2007-2010 Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "ItlIwm.hpp"

#define IWM_POWER_KEEP_ALIVE_PERIOD_SEC    25

int ItlIwm::
iwm_beacon_filter_send_cmd(struct iwm_softc *sc,
                           struct iwm_beacon_filter_cmd *cmd)
{
    return iwm_send_cmd_pdu(sc, IWM_REPLY_BEACON_FILTERING_CMD,
                            0, sizeof(struct iwm_beacon_filter_cmd), cmd);
}

void ItlIwm::
iwm_beacon_filter_set_cqm_params(struct iwm_softc *sc, struct iwm_node *in,
                                 struct iwm_beacon_filter_cmd *cmd)
{
    cmd->ba_enable_beacon_abort = htole32(sc->sc_bf.ba_enabled);
}

int ItlIwm::
iwm_update_beacon_abort(struct iwm_softc *sc, struct iwm_node *in, int enable)
{
    struct iwm_beacon_filter_cmd cmd = {
        IWM_BF_CMD_CONFIG_DEFAULTS,
        .bf_enable_beacon_filter = htole32(1),
        .ba_enable_beacon_abort = htole32(enable),
    };
    
    if (!sc->sc_bf.bf_enabled)
        return 0;
    
    sc->sc_bf.ba_enabled = enable;
    iwm_beacon_filter_set_cqm_params(sc, in, &cmd);
    return iwm_beacon_filter_send_cmd(sc, &cmd);
}

void ItlIwm::
iwm_power_build_cmd(struct iwm_softc *sc, struct iwm_node *in,
                    struct iwm_mac_power_cmd *cmd)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni = &in->in_ni;
    int dtim_period, dtim_msec, keep_alive;
    
    cmd->id_and_color = htole32(IWM_FW_CMD_ID_AND_COLOR(in->in_id,
                                                        in->in_color));
    if (ni->ni_dtimperiod)
        dtim_period = ni->ni_dtimperiod;
    else
        dtim_period = 1;
    
    /*
     * Regardless of power management state the driver must set
     * keep alive period. FW will use it for sending keep alive NDPs
     * immediately after association. Check that keep alive period
     * is at least 3 * DTIM.
     */
    dtim_msec = dtim_period * ni->ni_intval;
    keep_alive = MAX(3 * dtim_msec, 1000 * IWM_POWER_KEEP_ALIVE_PERIOD_SEC);
    keep_alive = roundup(keep_alive, 1000) / 1000;
    cmd->keep_alive_seconds = htole16(keep_alive);
    
    if (ic->ic_opmode != IEEE80211_M_MONITOR) {
        cmd->flags = htole16(IWM_POWER_FLAGS_POWER_SAVE_ENA_MSK);
        /*
         * POWER_SAVE_ENA alone does not let the firmware doze: without
         * POWER_MANAGEMENT_ENA the MAC stays awake between DTIMs. This is
         * the bit iwlwifi sets for IWL_POWER_ENABLED, and the reason
         * beacon abort was always disabled here (it was derived from this
         * same flags field below).
         */
        if (sc->sc_pwrsave_mode) {
            cmd->flags |= htole16(IWM_POWER_FLAGS_POWER_MANAGEMENT_ENA_MSK);
            /*
             * Linux's default PS timeouts: stay awake for 100 ms after the
             * last Rx/Tx before letting the firmware doze. Zero would also
             * work but makes the MAC enter PS after every single frame,
             * which costs latency for no measurable gain.
             */
            cmd->rx_data_timeout = htole32(100 * 1000);
            cmd->tx_data_timeout = htole32(100 * 1000);
        }
    }
}

int ItlIwm::
iwm_power_set_mode(struct iwm_softc *sc, int enable)
{
    struct ieee80211com *ic = &sc->sc_ic;

    if (sc->sc_pwrsave_disabled)
        enable = 0;
    if (sc->sc_pwrsave_mode == enable)
        return 0;
    sc->sc_pwrsave_mode = enable;

    /*
     * Only a running association has a MAC context and DTIM period to
     * program. Elsewhere the next iwm_power_mac_update_mode() at
     * association (mac80211.cpp) picks the new state up.
     */
    if (ic->ic_state != IEEE80211_S_RUN || ic->ic_bss == NULL ||
        (sc->sc_flags & IWM_FLAG_SCANNING))
        return 0;

    return iwm_power_mac_update_mode(sc, (struct iwm_node *)ic->ic_bss);
}

int ItlIwm::
iwm_power_mac_update_mode(struct iwm_softc *sc, struct iwm_node *in)
{
    int err;
    int ba_enable;
    struct iwm_mac_power_cmd cmd;
    
    memset(&cmd, 0, sizeof(cmd));
    
    iwm_power_build_cmd(sc, in, &cmd);
    
    err = iwm_send_cmd_pdu(sc, IWM_MAC_PM_POWER_TABLE, 0,
                           sizeof(cmd), &cmd);
    if (err != 0)
        return err;
    
    ba_enable = !!(cmd.flags &
                   htole16(IWM_POWER_FLAGS_POWER_MANAGEMENT_ENA_MSK));
    return iwm_update_beacon_abort(sc, in, ba_enable);
}

int ItlIwm::
iwm_power_update_device(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_device_power_cmd cmd = { };
    struct ieee80211com *ic = &sc->sc_ic;
    
    if (ic->ic_opmode != IEEE80211_M_MONITOR)
        cmd.flags = htole16(IWM_DEVICE_POWER_FLAGS_POWER_SAVE_ENA_MSK);
    
    return iwm_send_cmd_pdu(sc,
                            IWM_POWER_TABLE_CMD, 0, sizeof(cmd), &cmd);
}

IOReturn ItlIwm::
setPowerSaveMode(uint32_t mode)
{
    XYLog("%s mode=%u\n", __FUNCTION__, mode);
    return iwm_power_set_mode(&com, mode ? 1 : 0) == 0 ?
           kIOReturnSuccess : kIOReturnError;
}

uint32_t ItlIwm::
getPowerSaveMode()
{
    return com.sc_pwrsave_mode ? 1 : 0;
}

int ItlIwm::
iwm_enable_beacon_filter(struct iwm_softc *sc, struct iwm_node *in)
{
    struct iwm_beacon_filter_cmd cmd = {
        IWM_BF_CMD_CONFIG_DEFAULTS,
        .bf_enable_beacon_filter = htole32(1),
    };
    int err;
    
    iwm_beacon_filter_set_cqm_params(sc, in, &cmd);
    err = iwm_beacon_filter_send_cmd(sc, &cmd);
    
    if (err == 0)
        sc->sc_bf.bf_enabled = 1;
    
    return err;
}

int ItlIwm::
iwm_disable_beacon_filter(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_beacon_filter_cmd cmd;
    int err;
    
    memset(&cmd, 0, sizeof(cmd));
    
    err = iwm_beacon_filter_send_cmd(sc, &cmd);
    if (err == 0)
        sc->sc_bf.bf_enabled = 0;
    
    return err;
}

int ItlIwm::
iwm_add_sta_cmd(struct iwm_softc *sc, struct iwm_node *in, int update, unsigned int flags)
{
    struct iwm_add_sta_cmd add_sta_cmd;
    int err;
    uint32_t status;
    size_t cmdsize;
    uint32_t aggsize = 0;
    uint32_t max_aggsize = (IWM_STA_FLG_MAX_AGG_SIZE_4M >> IWM_STA_FLG_MAX_AGG_SIZE_SHIFT);
    struct ieee80211com *ic = &sc->sc_ic;
    
    /*
     * IWM_FLAG_STA_ACTIVE tracks the BSS entry (index 0) only; associated
     * clients carry their own index and their own in_sta_added bit, so adding
     * or removing one must not disturb the bookkeeping for the other.
     */
    if (!update && in->in_sta_added) {
        XYLog("sta %d already added\n", in->in_sta_id);
        return 0;
    }
    if (!update && in->in_sta_id == IWM_STATION_ID &&
        (sc->sc_flags & IWM_FLAG_STA_ACTIVE)) {
        XYLog("STA already added\n");
        return 0;
    }
    
    memset(&add_sta_cmd, 0, sizeof(add_sta_cmd));
    
    if (ic->ic_opmode == IEEE80211_M_MONITOR)
        add_sta_cmd.sta_id = IWM_MONITOR_STA_ID;
    else
        add_sta_cmd.sta_id = in->in_sta_id;
    if (isset(sc->sc_ucode_api, IWM_UCODE_TLV_API_STA_TYPE)) {
        if (ic->ic_opmode == IEEE80211_M_MONITOR)
            add_sta_cmd.station_type = IWM_STA_GENERAL_PURPOSE;
        else if (ic->ic_opmode == IEEE80211_M_HOSTAP &&
                 in->in_sta_id == IWM_STATION_ID)
            /*
             * Our own entry while operating as an AP.  REPLY_ADD_STA
             * documents IWM_STA_GENERAL_PURPOSE as "in AP mode used for
             * beacons and probe responses", which is exactly the role this
             * node plays: firmware schedules the beacon template against it
             * and it is the destination node for group-addressed traffic.
             */
            add_sta_cmd.station_type = IWM_STA_GENERAL_PURPOSE;
        else
            add_sta_cmd.station_type = IWM_STA_LINK;
    }
    add_sta_cmd.mac_id_n_color
    = htole32(IWM_FW_CMD_ID_AND_COLOR(in->in_id, in->in_color));
    if (ic->ic_opmode == IEEE80211_M_MONITOR) {
        int qid;
        IEEE80211_ADDR_COPY(&add_sta_cmd.addr, etheranyaddr);
        if (isset(sc->sc_enabled_capa, IWM_UCODE_TLV_CAPA_DQA_SUPPORT))
            qid = IWM_DQA_INJECT_MONITOR_QUEUE;
        else
            qid = IWM_AUX_QUEUE;
        add_sta_cmd.tfd_queue_msk |= htole32(1 << qid);
    } else if (!update || (flags & IWM_STA_MODIFY_QUEUES)) {
        if (!update) {
            int ac;
            sc->agg_queue_mask = 0;
            sc->agg_tid_disable = 0xffff;
            for (ac = 0; ac < EDCA_NUM_AC; ac++) {
                int qid = ac;
                if (isset(sc->sc_enabled_capa,
                          IWM_UCODE_TLV_CAPA_DQA_SUPPORT))
                    qid += IWM_DQA_MIN_MGMT_QUEUE;
                sc->agg_queue_mask |= htole32(1 << qid);
            }
        }
        add_sta_cmd.tfd_queue_msk = sc->agg_queue_mask;
        IEEE80211_ADDR_COPY(&add_sta_cmd.addr, in->in_macaddr);
    }
    add_sta_cmd.add_modify = update ? 1 : 0;
    add_sta_cmd.station_flags_msk
    |= htole32(IWM_STA_FLG_FAT_EN_MSK | IWM_STA_FLG_MIMO_EN_MSK);
    add_sta_cmd.tid_disable_tx = htole16(sc->agg_tid_disable);
    if (update)
        add_sta_cmd.modify_mask |= (IWM_STA_MODIFY_TID_DISABLE_TX);
    
    if ((in->in_ni.ni_flags & IEEE80211_NODE_HT) ||
        (in->in_ni.ni_flags & IEEE80211_NODE_VHT)) {
        add_sta_cmd.station_flags_msk
        |= htole32(IWM_STA_FLG_MAX_AGG_SIZE_MSK |
                   IWM_STA_FLG_AGG_MPDU_DENS_MSK);
        
        if (ic->ic_state >= IEEE80211_S_ASSOC) {
            switch (in->in_ni.ni_chw) {
                case IEEE80211_CHAN_WIDTH_80P80:
                case IEEE80211_CHAN_WIDTH_160:
                    add_sta_cmd.station_flags |= htole32(IWM_STA_FLG_FAT_EN_160MHZ);
                case IEEE80211_CHAN_WIDTH_80:
                    add_sta_cmd.station_flags |= htole32(IWM_STA_FLG_FAT_EN_80MHZ);
                case IEEE80211_CHAN_WIDTH_40:
                    add_sta_cmd.station_flags |= htole32(IWM_STA_FLG_FAT_EN_40MHZ);
                case IEEE80211_CHAN_WIDTH_20:
                default:
                    add_sta_cmd.station_flags |= htole32(IWM_STA_FLG_FAT_EN_20MHZ);
                    break;
            }
        }
        
        if (iwm_mimo_enabled(sc) && ic->ic_bss->ni_rx_nss > 1)
            add_sta_cmd.station_flags |= htole32(IWM_STA_FLG_MIMO_EN_MIMO2);
        else
            add_sta_cmd.station_flags |= htole32(IWM_STA_FLG_MIMO_EN_SISO);
        
        if (in->in_ni.ni_flags & IEEE80211_NODE_VHT) {
            aggsize = in->in_ni.ni_vhtcaps &
            IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK;
            aggsize >>=
            IEEE80211_VHTCAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT;
            add_sta_cmd.station_flags |=
            htole32(min(max_aggsize, aggsize) << IWM_STA_FLG_MAX_AGG_SIZE_SHIFT);
        }
        else if (in->in_ni.ni_flags & IEEE80211_NODE_HT)
            add_sta_cmd.station_flags |= htole32(IWM_STA_FLG_MAX_AGG_SIZE_64K);
        
        switch (ic->ic_ampdu_params & IEEE80211_AMPDU_PARAM_SS) {
            case IEEE80211_AMPDU_PARAM_SS_2:
                add_sta_cmd.station_flags
                |= htole32(IWM_STA_FLG_AGG_MPDU_DENS_2US);
                break;
            case IEEE80211_AMPDU_PARAM_SS_4:
                add_sta_cmd.station_flags
                |= htole32(IWM_STA_FLG_AGG_MPDU_DENS_4US);
                break;
            case IEEE80211_AMPDU_PARAM_SS_8:
                add_sta_cmd.station_flags
                |= htole32(IWM_STA_FLG_AGG_MPDU_DENS_8US);
                break;
            case IEEE80211_AMPDU_PARAM_SS_16:
                add_sta_cmd.station_flags
                |= htole32(IWM_STA_FLG_AGG_MPDU_DENS_16US);
                break;
            default:
                break;
        }
    }
    
    status = IWM_ADD_STA_SUCCESS;
    if (isset(sc->sc_ucode_api, IWM_UCODE_TLV_API_STA_TYPE))
        cmdsize = sizeof(add_sta_cmd);
    else
        cmdsize = sizeof(struct iwm_add_sta_cmd_v7);
    err = iwm_send_cmd_pdu_status(sc, IWM_ADD_STA, cmdsize,
                                  &add_sta_cmd, &status);
    if (!err && (status & IWM_ADD_STA_STATUS_MASK) != IWM_ADD_STA_SUCCESS) {
        err = EIO;
        XYLog("%s failed sta_id=%d status=0x%x\n", __FUNCTION__,
              add_sta_cmd.sta_id, status);
    } else {
        in->in_sta_added = 1;
        if (in->in_sta_id == IWM_STATION_ID)
            sc->sc_flags |= IWM_FLAG_STA_ACTIVE;
    }

    return err;
}

int ItlIwm::
iwm_add_aux_sta(struct iwm_softc *sc)
{
    XYLog("%s\n", __FUNCTION__);
    struct iwm_add_sta_cmd cmd;
    int err, qid;
    uint32_t status;
    size_t cmdsize;
    
    if (isset(sc->sc_enabled_capa, IWM_UCODE_TLV_CAPA_DQA_SUPPORT)) {
        qid = IWM_DQA_AUX_QUEUE;
        err = iwm_enable_txq(sc, IWM_AUX_STA_ID, qid,
                             IWM_TX_FIFO_MCAST, 0, IWM_MAX_TID_COUNT, 0);
    } else {
        qid = IWM_AUX_QUEUE;
        err = iwm_enable_ac_txq(sc, qid, IWM_TX_FIFO_MCAST);
    }
    if (err)
        return err;
    
    memset(&cmd, 0, sizeof(cmd));
    cmd.sta_id = IWM_AUX_STA_ID;
    if (isset(sc->sc_ucode_api, IWM_UCODE_TLV_API_STA_TYPE))
        cmd.station_type = IWM_STA_AUX_ACTIVITY;
    cmd.mac_id_n_color =
    htole32(IWM_FW_CMD_ID_AND_COLOR(IWM_MAC_INDEX_AUX, 0));
    cmd.tfd_queue_msk = htole32(1 << qid);
    cmd.tid_disable_tx = htole16(0xffff);
    
    status = IWM_ADD_STA_SUCCESS;
    if (isset(sc->sc_ucode_api, IWM_UCODE_TLV_API_STA_TYPE))
        cmdsize = sizeof(cmd);
    else
        cmdsize = sizeof(struct iwm_add_sta_cmd_v7);
    err = iwm_send_cmd_pdu_status(sc, IWM_ADD_STA, cmdsize, &cmd,
                                  &status);
    if (!err && (status & IWM_ADD_STA_STATUS_MASK) != IWM_ADD_STA_SUCCESS)
        err = EIO;
    
    return err;
}

/*
 * Station-id bookkeeping for AP mode.
 *
 * 0 is the BSS station, 1 is AUX and 2 is MONITOR, so every AP station --
 * the two internal ones plus one per associated client -- is handed out of
 * the 3..15 range tracked by sc_sta_id_mask.  Bit N of the mask means
 * station id N is taken.
 */
int ItlIwm::
iwm_alloc_ap_sta_id(struct iwm_softc *sc)
{
    int i;

    for (i = IWM_AP_STA_ID_MIN; i <= IWM_AP_STA_ID_MAX; i++) {
        if ((sc->sc_sta_id_mask & (1 << i)) == 0) {
            sc->sc_sta_id_mask |= (1 << i);
            return i;
        }
    }
    return -1;
}

void ItlIwm::
iwm_free_ap_sta_id(struct iwm_softc *sc, int sta_id)
{
    if (sta_id >= IWM_AP_STA_ID_MIN && sta_id <= IWM_AP_STA_ID_MAX)
        sc->sc_sta_id_mask &= ~(1 << sta_id);
}

/*
 * Add a station-table entry that is not backed by an ieee80211_node: the
 * internal broadcast/multicast stations of an AP.  Mirrors Linux's
 * iwl_mvm_add_int_sta_common().
 *
 * tfd_queue_msk is the set of Tx queues the scheduler should associate with
 * the station; it is only meaningful on the old (SCD) Tx API, which is what
 * the 8000C family uses.
 */
int ItlIwm::
iwm_add_int_sta(struct iwm_softc *sc, uint8_t sta_id, const uint8_t *addr,
                uint8_t type, uint32_t tfd_queue_msk)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_node *bin = (struct iwm_node *)ic->ic_bss;
    struct iwm_add_sta_cmd cmd;
    uint32_t status;
    size_t cmdsize;
    int err;

    XYLog("%s: sta_id=%d type=%d msk=0x%x\n", DEVNAME(sc), sta_id, type,
          tfd_queue_msk);

    memset(&cmd, 0, sizeof(cmd));
    cmd.sta_id = sta_id;
    cmd.add_modify = 0;            /* 0 = add a new station */
    cmd.mac_id_n_color =
        htole32(IWM_FW_CMD_ID_AND_COLOR(bin->in_id, bin->in_color));
    if (isset(sc->sc_ucode_api, IWM_UCODE_TLV_API_STA_TYPE))
        cmd.station_type = type;
    cmd.tfd_queue_msk = htole32(tfd_queue_msk);
    cmd.tid_disable_tx = htole16(0xffff);
    memcpy(cmd.addr, addr, ETHER_ADDR_LEN);

    status = IWM_ADD_STA_SUCCESS;
    if (isset(sc->sc_ucode_api, IWM_UCODE_TLV_API_STA_TYPE))
        cmdsize = sizeof(cmd);
    else
        cmdsize = sizeof(struct iwm_add_sta_cmd_v7);
    err = iwm_send_cmd_pdu_status(sc, IWM_ADD_STA, cmdsize, &cmd, &status);
    if (err) {
        XYLog("%s: could not add internal station %d (error %d)\n",
              DEVNAME(sc), sta_id, err);
        return err;
    }
    if ((status & IWM_ADD_STA_STATUS_MASK) != IWM_ADD_STA_SUCCESS) {
        XYLog("%s: add internal station %d failed, status=0x%x\n",
              DEVNAME(sc), sta_id, status);
        return EIO;
    }
    return 0;
}

/*
 * Bring up the two internal stations an AP needs.
 *
 * Linux adds the multicast station first and the broadcast one second
 * (iwl_mvm_start_ap_ibss_common()), and -- because this is the old Tx API --
 * enables each station's Tx queue *before* the ADD_STA that claims it.
 *
 * The four management queues (5..8) are bound to station 0 by iwm_init_hw(),
 * but station 0 never exists in AP mode, so they are handed to the broadcast
 * station here; unicast client traffic still carries the client's own id in
 * every Tx command and byte-count entry.
 */
int ItlIwm::
iwm_add_ap_stas(struct iwm_softc *sc, struct iwm_node *in)
{
    static const uint8_t mcast_addr[ETHER_ADDR_LEN] =
        { 0x03, 0x00, 0x00, 0x00, 0x00, 0x00 };
    static const uint8_t bcast_addr[ETHER_ADDR_LEN] =
        { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    int mcast_id, bcast_id, err, qid, ac;

    if (!isset(sc->sc_enabled_capa, IWM_UCODE_TLV_CAPA_DQA_SUPPORT)) {
        XYLog("%s: AP requires DQA firmware\n", DEVNAME(sc));
        return ENOTSUP;
    }
    if (sc->sc_mcast_sta_id != 0 || sc->sc_bcast_sta_id != 0) {
        XYLog("%s: AP stations already added\n", DEVNAME(sc));
        return 0;
    }

    mcast_id = iwm_alloc_ap_sta_id(sc);
    bcast_id = iwm_alloc_ap_sta_id(sc);
    if (mcast_id < 0 || bcast_id < 0) {
        if (mcast_id >= 0)
            iwm_free_ap_sta_id(sc, mcast_id);
        if (bcast_id >= 0)
            iwm_free_ap_sta_id(sc, bcast_id);
        XYLog("%s: no free station id for AP\n", DEVNAME(sc));
        return ENOSPC;
    }

    /*
     * iwm_enable_txq() pokes PRPH registers and the SCD and asserts that
     * the NIC lock is held.  The counter is re-entrant, so holding it
     * across the ADD_STA commands below is fine -- iwm_init_hw() does the
     * same around iwm_add_aux_sta().
     */
    if (!iwm_nic_lock(sc)) {
        iwm_free_ap_sta_id(sc, mcast_id);
        iwm_free_ap_sta_id(sc, bcast_id);
        return EBUSY;
    }

    /* Multicast station: group-addressed data, cab queue. */
    err = iwm_enable_txq(sc, mcast_id, IWM_DQA_GCAST_QUEUE,
                         IWM_TX_FIFO_MCAST, 0, IWM_TID_NON_QOS, 0);
    if (err == 0)
        err = iwm_add_int_sta(sc, (uint8_t)mcast_id, mcast_addr,
                              IWM_STA_MULTICAST, 1 << IWM_DQA_GCAST_QUEUE);
    if (err != 0)
        goto fail;

    /* Broadcast station: beacons, probe responses, deauth/disassoc. */
    err = iwm_enable_txq(sc, bcast_id, IWM_DQA_AP_PROBE_RESP_QUEUE,
                         IWM_TX_FIFO_VO, 0, IWM_MAX_TID_COUNT, 0);
    if (err == 0)
        err = iwm_add_int_sta(sc, (uint8_t)bcast_id, bcast_addr,
                              IWM_STA_GENERAL_PURPOSE,
                              1 << IWM_DQA_AP_PROBE_RESP_QUEUE);
    if (err != 0)
        goto fail;

    /* Rebind the management queues iwm_init_hw() gave to station 0. */
    for (ac = 0; ac < EDCA_NUM_AC; ac++) {
        qid = IWM_DQA_MIN_MGMT_QUEUE + ac;
        err = iwm_enable_txq(sc, bcast_id, qid, iwm_ac_to_tx_fifo[ac],
                             0, IWM_TID_NON_QOS, 0);
        if (err != 0)
            goto fail;
    }

    iwm_nic_unlock(sc);

    sc->sc_mcast_sta_id = (uint8_t)mcast_id;
    sc->sc_bcast_sta_id = (uint8_t)bcast_id;
    XYLog("%s: AP internal stations added (mcast=%d bcast=%d)\n",
          DEVNAME(sc), mcast_id, bcast_id);
    return 0;

fail:
    iwm_nic_unlock(sc);
    XYLog("%s: could not add AP stations (error %d)\n", DEVNAME(sc), err);
    iwm_rm_ap_stas(sc);
    return err;
}

/*
 * Tear the internal AP stations down.  Also sweeps the node tree for client
 * stations that were never handed back through ic_node_leave(), because
 * iwm_deauth() runs before net80211 drops the nodes.
 */
int ItlIwm::
iwm_rm_ap_stas(struct iwm_softc *sc)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct ieee80211_node *ni;
    struct iwm_node *in;
    struct iwm_rm_sta_cmd rm;
    int err = 0, e;

    RB_FOREACH(ni, ieee80211_tree, &ic->ic_tree) {
        in = (struct iwm_node *)ni;
        if (ni == ic->ic_bss || !in->in_sta_added ||
            in->in_sta_id < IWM_AP_STA_ID_MIN)
            continue;
        memset(&rm, 0, sizeof(rm));
        rm.sta_id = in->in_sta_id;
        e = iwm_send_cmd_pdu(sc, IWM_REMOVE_STA, 0, sizeof(rm), &rm);
        if (e != 0)
            err = e;
        in->in_sta_added = 0;
        iwm_free_ap_sta_id(sc, in->in_sta_id);
        in->in_sta_id = IWM_STATION_ID;
        XYLog("%s: removed AP client station for %s\n", DEVNAME(sc),
              ether_sprintf(ni->ni_macaddr));
    }

    if (sc->sc_bcast_sta_id != 0) {
        memset(&rm, 0, sizeof(rm));
        rm.sta_id = sc->sc_bcast_sta_id;
        e = iwm_send_cmd_pdu(sc, IWM_REMOVE_STA, 0, sizeof(rm), &rm);
        if (e != 0)
            err = e;
        iwm_free_ap_sta_id(sc, sc->sc_bcast_sta_id);
        sc->sc_bcast_sta_id = 0;
    }
    if (sc->sc_mcast_sta_id != 0) {
        memset(&rm, 0, sizeof(rm));
        rm.sta_id = sc->sc_mcast_sta_id;
        e = iwm_send_cmd_pdu(sc, IWM_REMOVE_STA, 0, sizeof(rm), &rm);
        if (e != 0)
            err = e;
        iwm_free_ap_sta_id(sc, sc->sc_mcast_sta_id);
        sc->sc_mcast_sta_id = 0;
    }

    return err;
}

int ItlIwm::
iwm_drain_sta(struct iwm_softc *sc, struct iwm_node *in, bool drain)
{
    struct iwm_add_sta_cmd cmd = {};
    int err;
    uint32_t status;
    size_t cmdsize;
    
    cmd.mac_id_n_color = cpu_to_le32(IWM_FW_CMD_ID_AND_COLOR(in->in_id, in->in_color));
    cmd.sta_id = IWM_STATION_ID;
    cmd.add_modify = IWM_STA_MODE_MODIFY;
    cmd.station_flags = drain ? cpu_to_le32(IWM_STA_FLG_DRAIN_FLOW) : 0;
    cmd.station_flags_msk = cpu_to_le32(IWM_STA_FLG_DRAIN_FLOW);
    status = IWM_ADD_STA_SUCCESS;
    if (isset(sc->sc_ucode_api, IWM_UCODE_TLV_API_STA_TYPE))
        cmdsize = sizeof(cmd);
    else
        cmdsize = sizeof(struct iwm_add_sta_cmd_v7);
    err = iwm_send_cmd_pdu_status(sc, IWM_ADD_STA,
                      cmdsize,
                      &cmd, &status);
    return err;
}

int ItlIwm::
iwm_rm_sta_cmd(struct iwm_softc *sc, struct iwm_node *in)
{
    struct ieee80211com *ic = &sc->sc_ic;
    struct iwm_rm_sta_cmd rm_sta_cmd;
    int err;
    uint8_t qid;
    
    if (!in->in_sta_added &&
        (sc->sc_flags & IWM_FLAG_STA_ACTIVE) == 0) {
        XYLog("sta already removed\n");
        return 0;
    }
    
    if (ic->ic_opmode == IEEE80211_M_STA) {
        err = iwm_drain_sta(sc, in, true);
        if (err) {
            XYLog("%s can not drain sta(TRUE)\n", __FUNCTION__);
            goto done;
        }
        err = iwm_flush_tx_path(sc, sc->agg_queue_mask);
        if (err) {
            XYLog("%s can not flush sta tx path\n", __FUNCTION__);
            goto done;
        }
        err = iwm_drain_sta(sc, in, false);
        if (err) {
            XYLog("%s can not drain sta(FALSE)\n", __FUNCTION__);
            goto done;
        }
        for (qid = IWM_FIRST_AGG_TX_QUEUE; qid <= IWM_LAST_AGG_TX_QUEUE; qid++) {
            if (sc->agg_queue_mask & (1 << qid)) {
                iwm_disable_txq(sc, qid, 0, 0);
            }
        }
    }
    memset(&rm_sta_cmd, 0, sizeof(rm_sta_cmd));
    if (ic->ic_opmode == IEEE80211_M_MONITOR)
        rm_sta_cmd.sta_id = IWM_MONITOR_STA_ID;
    else
        rm_sta_cmd.sta_id = in->in_sta_id;
    
    err = iwm_send_cmd_pdu(sc, IWM_REMOVE_STA, 0, sizeof(rm_sta_cmd),
                           &rm_sta_cmd);
done:
    sc->agg_queue_mask = 0;
    sc->agg_tid_disable = 0xffff;
    
    in->in_sta_added = 0;
    if (in->in_sta_id == IWM_STATION_ID)
        sc->sc_flags &= ~IWM_FLAG_STA_ACTIVE;

    return err;
}
