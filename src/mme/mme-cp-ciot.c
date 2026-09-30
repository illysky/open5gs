/*
 * Control Plane CIoT EPS optimisation: user data over NAS.
 * See mme-cp-ciot.h.
 */

#include "mme-timer.h"
#include "mme-cp-ciot.h"
#include "nas-security.h"
#include "nas-path.h"
#include "mme-path.h"
#include "mme-gtp-path.h"
#include "s1ap-path.h"

/* As in nas-security.c */
#define NAS_SECURITY_BEARER 0
#define NAS_SECURITY_MAC_SIZE 4

#define EMM_SERVICE_ACCEPT 79

/* TS 24.301 9.9.4.25: Release assistance indication, downlink data expected */
#define RAI_IEI 0xF0
#define RAI_DDX_NONE 1          /* no further uplink or downlink data */
#define RAI_DDX_SINGLE_DL 2     /* only a single downlink transmission */

/* CONTROL PLANE SERVICE REQUEST optional IEs (TS 24.301 8.2.33) */
#define CPSR_IEI_ESM_MESSAGE_CONTAINER 0x78
#define CPSR_IEI_NAS_MESSAGE_CONTAINER 0x67
#define CPSR_IEI_EPS_BEARER_CONTEXT_STATUS 0x57

/* Control plane service type (TS 24.301 9.9.3.47) */
#define CP_SERVICE_TYPE_MO 0
#define CP_SERVICE_TYPE_MT 1

#define GTPU_PORT 2152
#define GTPU_HEADER_LEN 8
#define GTPU_MSG_ECHO_REQUEST 1
#define GTPU_MSG_ECHO_RESPONSE 2
#define GTPU_MSG_GPDU 255

/* EPS bearer identity + PD, PTI, message type, user data container length */
#define ESM_DATA_TRANSPORT_HEADER_LEN 5

static ogs_sock_t *gtpu_sock;
static ogs_poll_t *gtpu_poll;
static ogs_ip_t gtpu_ip;

bool mme_cp_ciot_ue(const mme_ue_t *mme_ue)
{
    const ogs_nas_ue_network_capability_t *cap;

    ogs_assert(mme_ue);
    cap = &mme_ue->ue_network_capability;
    return cap->control_plane_ciot_eps_optimization &&
        !cap->s1_u_data_transfer;
}

void mme_cp_ciot_set_downlink_path(mme_bearer_t *bearer)
{
    ogs_assert(bearer);
    bearer->enb_s1u_teid = (uint32_t)bearer->id;
    memcpy(&bearer->enb_s1u_ip, &gtpu_ip, sizeof(gtpu_ip));
}

static ogs_pkbuf_t *security_encode(mme_ue_t *mme_ue, ogs_pkbuf_t *pkbuf)
{
    ogs_nas_eps_security_header_t h;

    memset(&h, 0, sizeof(h));
    h.security_header_type =
        OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED;
    h.protocol_discriminator = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    h.sequence_number = (mme_ue->dl_count & 0xff);

    if (mme_ue->selected_enc_algorithm)
        ogs_nas_encrypt(mme_ue->selected_enc_algorithm,
            mme_ue->knas_enc, mme_ue->dl_count, NAS_SECURITY_BEARER,
            OGS_NAS_SECURITY_DOWNLINK_DIRECTION, pkbuf);

    ogs_assert(ogs_pkbuf_push(pkbuf, 1));
    *(uint8_t *)(pkbuf->data) = h.sequence_number;

    if (mme_ue->selected_int_algorithm) {
        uint8_t mac[NAS_SECURITY_MAC_SIZE];

        ogs_nas_mac_calculate(mme_ue->selected_int_algorithm,
            mme_ue->knas_int, mme_ue->dl_count, NAS_SECURITY_BEARER,
            OGS_NAS_SECURITY_DOWNLINK_DIRECTION, pkbuf, mac);
        memcpy(&h.message_authentication_code, mac, sizeof(mac));
    }

    mme_ue->dl_count = (mme_ue->dl_count + 1) & 0xffffff;

    ogs_assert(ogs_pkbuf_push(pkbuf, 5));
    memcpy(pkbuf->data, &h, sizeof(ogs_nas_eps_security_header_t));

    return pkbuf;
}

/* TS 24.301 6.6.4.2 / 23.401 5.3.4B.2: the UE said it expects nothing more */
static void release_nas_connection(enb_ue_t *enb_ue, mme_ue_t *mme_ue)
{
    ogs_info("[%s] CP-CIoT: release assistance, releasing the "
            "NAS signalling connection", mme_ue->imsi_bcd);
    enb_ue->relcause.group = S1AP_Cause_PR_nas;
    enb_ue->relcause.cause = S1AP_CauseNas_normal_release;
    mme_send_release_access_bearer_or_ue_context_release(enb_ue);
}

static uint32_t gprs_timer_sec(uint8_t octet, bool timer3)
{
    /* TS 24.008 10.5.7.4 (GPRS timer 2) and 10.5.7.4a (GPRS timer 3) */
    static const uint32_t unit2[8] = { 2, 60, 360, 60, 60, 60, 60, 0 };
    static const uint32_t unit3[8] = { 600, 3600, 36000, 2, 30, 60, 1152000, 0 };
    uint8_t unit = octet >> 5;
    uint8_t value = octet & 0x1f;

    return (timer3 ? unit3[unit] : unit2[unit]) * value;
}

void mme_psm_store_request(mme_ue_t *mme_ue,
        const ogs_nas_gprs_timer_2_t *t3324,
        const ogs_nas_gprs_timer_3_t *t3412_extended,
        const ogs_nas_extended_drx_parameters_t *edrx)
{
    ogs_assert(mme_ue);

    mme_ue->psm.t3324_present = t3324 != NULL;
    if (t3324)
        mme_ue->psm.t3324 = *t3324;
    mme_ue->psm.t3412_extended_present = t3412_extended != NULL;
    if (t3412_extended)
        mme_ue->psm.t3412_extended = *t3412_extended;
    mme_ue->psm.edrx_present = edrx != NULL;
    if (edrx)
        mme_ue->psm.edrx = *edrx;

    if (t3324 || t3412_extended || edrx)
        ogs_info("[%s] PSM/eDRX requested: T3324 %s%u s, T3412ext %s%u s, "
                "eDRX %s0x%x PTW 0x%x", mme_ue->imsi_bcd,
                t3324 ? "" : "(none) ",
                t3324 ? gprs_timer_sec(*(const uint8_t *)&t3324->t, false) : 0,
                t3412_extended ? "" : "(none) ",
                t3412_extended ? gprs_timer_sec(
                    *(const uint8_t *)&t3412_extended->t, true) : 0,
                edrx ? "" : "(none) ",
                edrx ? edrx->e_drx_value : 0,
                edrx ? edrx->paging_time_window : 0);
}

bool mme_psm_active_timer_running(const mme_ue_t *mme_ue)
{
    uint32_t t3324;

    ogs_assert(mme_ue);
    if (!mme_ue->psm.t3324_present || !mme_ue->psm.idle_since)
        return true;
    if ((*(const uint8_t *)&mme_ue->psm.t3324.t >> 5) == 7)
        return true; /* deactivated: no PSM */
    t3324 = gprs_timer_sec(*(const uint8_t *)&mme_ue->psm.t3324.t, false);
    return ogs_time_now() < mme_ue->psm.idle_since + ogs_time_from_sec(t3324);
}

uint32_t mme_psm_periodic_tau_sec(const mme_ue_t *mme_ue)
{
    ogs_assert(mme_ue);
    if (mme_ue->psm.t3412_extended_present &&
            (*(const uint8_t *)&mme_ue->psm.t3412_extended.t >> 5) != 7)
        return gprs_timer_sec(
                *(const uint8_t *)&mme_ue->psm.t3412_extended.t, true);
    return (uint32_t)mme_self()->time.t3412.value;
}

uint32_t mme_edrx_cycle_ms(const mme_ue_t *mme_ue)
{
    /* TS 24.008 10.5.5.32, NB-S1 mode: 2..1024 hyperframes of 10.24 s */
    static const uint16_t hf[16] = {
        0, 0, 2, 4, 6, 8, 10, 12, 14, 16, 32, 64, 128, 256, 512, 1024 };
    /* WB-S1 mode: 5.12 s .. 2621.44 s in units of 5.12 s; 14 and 15 have
     * no Paging-eDRX-Cycle (TS 36.413 9.2.1.116), so no eDRX paging */
    static const uint16_t wb[16] = {
        1, 2, 4, 8, 12, 16, 20, 24, 28, 32, 64, 128, 256, 512, 0, 0 };

    ogs_assert(mme_ue);
    if (!mme_ue->psm.edrx_present)
        return 0;
    if (!mme_cp_ciot_ue(mme_ue))
        return (uint32_t)wb[mme_ue->psm.edrx.e_drx_value & 0xf] * 5120;
    return (uint32_t)hf[mme_ue->psm.edrx.e_drx_value & 0xf] * 10240;
}

ogs_time_t mme_paging_interval(const mme_ue_t *mme_ue)
{
    uint32_t cycle = mme_edrx_cycle_ms(mme_ue);
    if (cycle)
        return ogs_time_from_msec(cycle);
    return mme_timer_cfg(MME_TIMER_T3413)->duration;
}

int mme_paging_max_count(const mme_ue_t *mme_ue)
{
    if (mme_edrx_cycle_ms(mme_ue))
        return MME_CP_CIOT_EDRX_PAGING_CYCLES - 1;
    return mme_timer_cfg(MME_TIMER_T3413)->max_count;
}

static void hold_downlink(mme_ue_t *mme_ue, mme_bearer_t *bearer,
        const uint8_t *data, size_t len)
{
    ogs_pkbuf_t *pkbuf = NULL;
    int r;

    if (mme_ue->cp_ciot_dl_count == MME_CP_CIOT_MAX_DL_QUEUE) {
        ogs_warn("[%s] CP-CIoT: downlink queue full, oldest packet dropped",
                mme_ue->imsi_bcd);
        ogs_pkbuf_free(mme_ue->cp_ciot_dl[0].pkbuf);
        memmove(&mme_ue->cp_ciot_dl[0], &mme_ue->cp_ciot_dl[1],
                sizeof(mme_ue->cp_ciot_dl[0]) *
                    (MME_CP_CIOT_MAX_DL_QUEUE - 1));
        mme_ue->cp_ciot_dl_count--;
    }
    pkbuf = ogs_pkbuf_alloc(NULL, len);
    ogs_assert(pkbuf);
    ogs_pkbuf_put_data(pkbuf, data, len);
    mme_ue->cp_ciot_dl[mme_ue->cp_ciot_dl_count].pkbuf = pkbuf;
    mme_ue->cp_ciot_dl[mme_ue->cp_ciot_dl_count].bearer_id = bearer->id;
    mme_ue->cp_ciot_dl_count++;

    if (!mme_psm_active_timer_running(mme_ue)) {
        ogs_info("[%s] CP-CIoT: %d bytes held, UE in power saving mode "
                "(%d queued)", mme_ue->imsi_bcd, (int)len,
                mme_ue->cp_ciot_dl_count);
        return;
    }
    if (mme_ue->t3413.timer->running) {
        ogs_debug("[%s] CP-CIoT: %d bytes held, paging in progress",
                mme_ue->imsi_bcd, (int)len);
        return;
    }
    ogs_info("[%s] CP-CIoT: %d bytes held, paging the UE",
            mme_ue->imsi_bcd, (int)len);
    mme_ue->t3413.retry_count = 0;
    r = s1ap_send_paging(mme_ue, S1AP_CNDomain_ps);
    ogs_expect(r == OGS_OK);
}

static void send_downlink(mme_bearer_t *bearer, const uint8_t *data, size_t len);

bool mme_cp_ciot_has_queue(const mme_ue_t *mme_ue)
{
    return mme_ue && mme_ue->cp_ciot_dl_count > 0;
}

void mme_cp_ciot_flush_queue(mme_ue_t *mme_ue)
{
    int i, n;

    ogs_assert(mme_ue);
    n = mme_ue->cp_ciot_dl_count;
    if (n)
        ogs_info("[%s] CP-CIoT: delivering %d held packet(s)",
                mme_ue->imsi_bcd, n);
    mme_ue->cp_ciot_dl_count = 0;
    for (i = 0; i < n; i++) {
        ogs_pkbuf_t *pkbuf = mme_ue->cp_ciot_dl[i].pkbuf;
        mme_bearer_t *bearer =
            mme_bearer_find_by_id(mme_ue->cp_ciot_dl[i].bearer_id);

        if (bearer)
            send_downlink(bearer, pkbuf->data, pkbuf->len);
        ogs_pkbuf_free(pkbuf);
    }
}

void mme_cp_ciot_drop_queue(mme_ue_t *mme_ue)
{
    int i;

    ogs_assert(mme_ue);
    for (i = 0; i < mme_ue->cp_ciot_dl_count; i++)
        ogs_pkbuf_free(mme_ue->cp_ciot_dl[i].pkbuf);
    mme_ue->cp_ciot_dl_count = 0;
}

static void send_downlink(mme_bearer_t *bearer, const uint8_t *data, size_t len)
{
    mme_ue_t *mme_ue = NULL;
    enb_ue_t *enb_ue = NULL;
    ogs_pkbuf_t *pkbuf = NULL;
    uint8_t *p = NULL;
    int r;

    mme_ue = mme_ue_find_by_id(bearer->mme_ue_id);
    if (!mme_ue) {
        ogs_error("[CP-CIoT] No UE for bearer %d", bearer->id);
        return;
    }
    enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
    if (!enb_ue) {
        hold_downlink(mme_ue, bearer, data, len);
        return;
    }

    pkbuf = ogs_pkbuf_alloc(NULL,
            OGS_NAS_HEADROOM + ESM_DATA_TRANSPORT_HEADER_LEN + len);
    ogs_assert(pkbuf);
    ogs_pkbuf_reserve(pkbuf, OGS_NAS_HEADROOM);
    p = ogs_pkbuf_put(pkbuf, ESM_DATA_TRANSPORT_HEADER_LEN + len);
    p[0] = (uint8_t)((bearer->ebi << 4) | OGS_NAS_PROTOCOL_DISCRIMINATOR_ESM);
    p[1] = 0;
    p[2] = MME_CP_CIOT_ESM_DATA_TRANSPORT;
    p[3] = (uint8_t)(len >> 8);
    p[4] = (uint8_t)len;
    memcpy(p + ESM_DATA_TRANSPORT_HEADER_LEN, data, len);

    ogs_debug("[%s] CP-CIoT downlink %d bytes on EBI %d",
            mme_ue->imsi_bcd, (int)len, bearer->ebi);

    r = nas_eps_send_to_downlink_nas_transport(
            enb_ue, security_encode(mme_ue, pkbuf));
    ogs_expect(r == OGS_OK);

    if (mme_ue->cp_ciot_release_after_dl) {
        mme_ue->cp_ciot_release_after_dl = false;
        release_nas_connection(enb_ue, mme_ue);
    }
}

static void gtpu_recv_cb(short when, ogs_socket_t fd, void *data)
{
    uint8_t buf[OGS_MAX_SDU_LEN];
    ogs_sockaddr_t from;
    socklen_t fromlen = sizeof(from.sa);
    ssize_t n;
    size_t hlen = GTPU_HEADER_LEN;
    uint16_t len;
    uint32_t teid;
    mme_bearer_t *bearer = NULL;

    n = recvfrom(fd, buf, sizeof(buf), 0, &from.sa, &fromlen);
    if (n < GTPU_HEADER_LEN)
        return;

    len = (uint16_t)((buf[2] << 8) | buf[3]);
    if ((size_t)n < GTPU_HEADER_LEN + (size_t)len)
        return;

    if (buf[1] == GTPU_MSG_ECHO_REQUEST) {
        buf[1] = GTPU_MSG_ECHO_RESPONSE;
        ogs_sendto(fd, buf, (size_t)n, 0, &from);
        return;
    }
    if (buf[1] != GTPU_MSG_GPDU)
        return;

    /* Optional sequence number, N-PDU number and extension headers */
    if (buf[0] & 0x07) {
        uint8_t next;

        hlen += 4;
        if ((size_t)n < hlen)
            return;
        next = (buf[0] & 0x04) ? buf[hlen - 1] : 0;
        while (next) {
            size_t ext;

            if ((size_t)n < hlen + 1)
                return;
            ext = (size_t)buf[hlen] * 4;
            if (ext == 0 || (size_t)n < hlen + ext)
                return;
            next = buf[hlen + ext - 1];
            hlen += ext;
        }
    }

    teid = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
        ((uint32_t)buf[6] << 8) | buf[7];
    bearer = mme_bearer_find_by_id((ogs_pool_id_t)teid);
    if (!bearer) {
        ogs_warn("[CP-CIoT] Downlink for unknown TEID 0x%x", teid);
        return;
    }
    if (GTPU_HEADER_LEN + (size_t)len < hlen)
        return;

    send_downlink(bearer, buf + hlen, GTPU_HEADER_LEN + len - hlen);
}

int mme_cp_ciot_handle_uplink(mme_ue_t *mme_ue, ogs_pkbuf_t *esmbuf)
{
    uint8_t *p = NULL;
    uint8_t ebi;
    uint16_t len;
    mme_bearer_t *bearer = NULL;
    enb_ue_t *enb_ue = NULL;
    ogs_sockaddr_t *to = NULL;
    ssize_t sent;
    uint8_t ddx;
    size_t i;

    ogs_assert(mme_ue);
    ogs_assert(esmbuf);

    if (mme_ue->mac_failed) {
        ogs_error("[%s] CP-CIoT uplink failed the NAS MAC check",
                mme_ue->imsi_bcd);
        goto drop;
    }
    if (esmbuf->len < ESM_DATA_TRANSPORT_HEADER_LEN)
        goto drop;

    p = esmbuf->data;
    ebi = p[0] >> 4;
    len = (uint16_t)((p[3] << 8) | p[4]);
    if (len > esmbuf->len - ESM_DATA_TRANSPORT_HEADER_LEN) {
        ogs_error("[%s] CP-CIoT user data container too long (%d > %d)",
                mme_ue->imsi_bcd, len,
                esmbuf->len - ESM_DATA_TRANSPORT_HEADER_LEN);
        goto drop;
    }

    ddx = 0;
    for (i = ESM_DATA_TRANSPORT_HEADER_LEN + len; i < esmbuf->len; i++) {
        if ((p[i] & 0xF0) == RAI_IEI) {
            ddx = p[i] & 0x03;
            break;
        }
    }

    bearer = mme_bearer_find_by_ue_ebi(mme_ue, ebi);
    if (!bearer || !bearer->sgw_s1u_teid) {
        ogs_error("[%s] CP-CIoT uplink on EBI %d without an S1-U path",
                mme_ue->imsi_bcd, ebi);
        goto drop;
    }

    ogs_assert(ogs_pkbuf_pull(esmbuf, ESM_DATA_TRANSPORT_HEADER_LEN));
    ogs_pkbuf_trim(esmbuf, len);
    ogs_assert(ogs_pkbuf_push(esmbuf, GTPU_HEADER_LEN));
    p = esmbuf->data;
    p[0] = 0x30;
    p[1] = GTPU_MSG_GPDU;
    p[2] = (uint8_t)(len >> 8);
    p[3] = (uint8_t)len;
    p[4] = (uint8_t)(bearer->sgw_s1u_teid >> 24);
    p[5] = (uint8_t)(bearer->sgw_s1u_teid >> 16);
    p[6] = (uint8_t)(bearer->sgw_s1u_teid >> 8);
    p[7] = (uint8_t)bearer->sgw_s1u_teid;

    if (ogs_ip_to_sockaddr(&bearer->sgw_s1u_ip, GTPU_PORT, &to) != OGS_OK ||
            !to) {
        ogs_error("[%s] CP-CIoT: bad SGW S1-U address", mme_ue->imsi_bcd);
        goto drop;
    }
    sent = ogs_sendto(gtpu_sock->fd, esmbuf->data, esmbuf->len, 0, to);
    ogs_freeaddrinfo(to);
    if (sent < 0)
        ogs_error("[%s] CP-CIoT: GTP-U send failed", mme_ue->imsi_bcd);
    else
        ogs_debug("[%s] CP-CIoT uplink %d bytes on EBI %d%s",
                mme_ue->imsi_bcd, len, ebi,
                ddx == RAI_DDX_NONE ? ", no more data expected" :
                ddx == RAI_DDX_SINGLE_DL ? ", one downlink expected" : "");

    ogs_pkbuf_free(esmbuf);

    enb_ue = enb_ue_find_by_id(mme_ue->enb_ue_id);
    if (enb_ue && ddx == RAI_DDX_NONE) {
        mme_ue->cp_ciot_release_after_dl = false;
        release_nas_connection(enb_ue, mme_ue);
    } else if (ddx == RAI_DDX_SINGLE_DL) {
        mme_ue->cp_ciot_release_after_dl = true;
    }
    return OGS_OK;

drop:
    ogs_pkbuf_free(esmbuf);
    return OGS_ERROR;
}

static void bearer_status(mme_ue_t *mme_ue, uint8_t status[2])
{
    mme_sess_t *sess = NULL;
    mme_bearer_t *bearer = NULL;

    status[0] = status[1] = 0;
    ogs_list_for_each(&mme_ue->sess_list, sess) {
        ogs_list_for_each(&sess->bearer_list, bearer) {
            if (bearer->ebi < 8)
                status[0] |= (uint8_t)(1 << bearer->ebi);
            else if (bearer->ebi < 16)
                status[1] |= (uint8_t)(1 << (bearer->ebi - 8));
        }
    }
}

static int send_service_accept(
        enb_ue_t *enb_ue, mme_ue_t *mme_ue, bool with_status)
{
    ogs_pkbuf_t *pkbuf = NULL;
    uint8_t *p = NULL;
    uint8_t status[2];

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_NAS_HEADROOM + 6);
    ogs_assert(pkbuf);
    ogs_pkbuf_reserve(pkbuf, OGS_NAS_HEADROOM);
    p = ogs_pkbuf_put(pkbuf, 2);
    p[0] = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
    p[1] = EMM_SERVICE_ACCEPT;
    bearer_status(mme_ue, status);
    if (with_status && (status[0] || status[1])) {
        p = ogs_pkbuf_put(pkbuf, 4);
        p[0] = CPSR_IEI_EPS_BEARER_CONTEXT_STATUS;
        p[1] = 2;
        p[2] = status[0];
        p[3] = status[1];
    }
    ogs_info("[%s] CP-CIoT: Service accept", mme_ue->imsi_bcd);
    return nas_eps_send_to_downlink_nas_transport(
            enb_ue, security_encode(mme_ue, pkbuf));
}

int mme_cp_ciot_handle_service_request(
        enb_ue_t *enb_ue, mme_ue_t *mme_ue, ogs_pkbuf_t *nasbuf)
{
    uint8_t *p = NULL;
    size_t n, i;
    uint8_t type, ksi;
    const uint8_t *esm = NULL;
    size_t esm_len = 0;
    bool with_status = false;
    mme_sess_t *sess = NULL;
    mme_bearer_t *bearer = NULL;
    int r;

    ogs_assert(enb_ue);
    ogs_assert(nasbuf);

    if (!mme_ue) {
        /* Plain SERVICE REJECT #9: the UE attaches again */
        ogs_pkbuf_t *rej = ogs_pkbuf_alloc(NULL, OGS_NAS_HEADROOM + 3);

        ogs_warn("CP-CIoT: Control plane service request from an "
                "unknown UE");
        ogs_assert(rej);
        ogs_pkbuf_reserve(rej, OGS_NAS_HEADROOM);
        p = ogs_pkbuf_put(rej, 3);
        p[0] = OGS_NAS_PROTOCOL_DISCRIMINATOR_EMM;
        p[1] = OGS_NAS_EPS_SERVICE_REJECT;
        p[2] = OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK;
        r = nas_eps_send_to_downlink_nas_transport(enb_ue, rej);
        ogs_expect(r == OGS_OK);
        goto out;
    }
    if (mme_ue->mac_failed || !SECURITY_CONTEXT_IS_VALID(mme_ue) ||
            !SESSION_CONTEXT_IS_AVAILABLE(mme_ue)) {
        ogs_warn("[%s] CP-CIoT: Control plane service request rejected "
                "(%s)", mme_ue->imsi_bcd,
                mme_ue->mac_failed ? "NAS MAC check failed" :
                !SECURITY_CONTEXT_IS_VALID(mme_ue) ?
                    "no security context" : "no session");
        r = nas_eps_send_service_reject(enb_ue, mme_ue,
                OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK);
        ogs_expect(r == OGS_OK);
        goto out;
    }

    p = nasbuf->data;
    n = nasbuf->len;
    if (n < 3) {
        ogs_error("[%s] CP-CIoT: Control plane service request too short",
                mme_ue->imsi_bcd);
        goto out;
    }
    type = p[2] & 0x07;
    ksi = (p[2] >> 4) & 0x07;
    for (i = 3; i < n;) {
        uint8_t iei = p[i];
        size_t len;

        if (iei & 0x80) {
            i++;
            continue;
        }
        if (iei == CPSR_IEI_ESM_MESSAGE_CONTAINER) {
            if (i + 3 > n)
                break;
            len = ((size_t)p[i + 1] << 8) | p[i + 2];
            if (i + 3 + len > n)
                break;
            esm = p + i + 3;
            esm_len = len;
            i += 3 + len;
            continue;
        }
        if (i + 2 > n)
            break;
        len = p[i + 1];
        if (iei == CPSR_IEI_EPS_BEARER_CONTEXT_STATUS)
            with_status = true;
        else if (iei == CPSR_IEI_NAS_MESSAGE_CONTAINER)
            ogs_warn("[%s] CP-CIoT: NAS message container (SMS) ignored",
                    mme_ue->imsi_bcd);
        i += 2 + len;
    }

    ogs_info("[%s] CP-CIoT: Control plane service request (%s%s%s)",
            mme_ue->imsi_bcd,
            type == CP_SERVICE_TYPE_MO ? "mobile originating" :
            type == CP_SERVICE_TYPE_MT ? "mobile terminating" : "other",
            esm ? ", with data" : "",
            with_status ? ", bearer status" : "");

    mme_ue->nas_eps.type = MME_EPS_TYPE_SERVICE_REQUEST;
    mme_ue->nas_eps.ue.ksi = ksi;
    if (mme_ue->nas_eps.ue.ksi < OGS_NAS_KSI_NO_KEY_IS_AVAILABLE) {
        mme_ue->nas_eps.mme.tsc = mme_ue->nas_eps.ue.tsc;
        mme_ue->nas_eps.mme.ksi = mme_ue->nas_eps.ue.ksi;
    }
    CLEAR_MME_UE_ALL_TIMERS(mme_ue);
    mme_ue->cp_ciot_release_after_dl = false;
    mme_ue->psm.idle_since = 0;

    /* The SGW dropped our downlink F-TEID in Release Access Bearers */
    ogs_list_init(&mme_ue->bearer_to_modify_list);
    ogs_list_for_each(&mme_ue->sess_list, sess) {
        ogs_list_for_each(&sess->bearer_list, bearer) {
            if (!bearer->sgw_s1u_teid || bearer->enb_s1u_teid)
                continue;
            mme_cp_ciot_set_downlink_path(bearer);
            ogs_list_add(&mme_ue->bearer_to_modify_list,
                    &bearer->to_modify_node);
        }
    }
    if (ogs_list_count(&mme_ue->bearer_to_modify_list)) {
        r = mme_gtp_send_modify_bearer_request(enb_ue, mme_ue, 1, 0);
        ogs_expect(r == OGS_OK);
    }

    r = send_service_accept(enb_ue, mme_ue, with_status);
    ogs_expect(r == OGS_OK);

    if (MME_PAGING_ONGOING(mme_ue))
        mme_send_after_paging(mme_ue, false);

    mme_cp_ciot_flush_queue(mme_ue);

    if (esm && esm_len) {
        ogs_pkbuf_t *esmbuf = ogs_pkbuf_alloc(NULL, OGS_NAS_HEADROOM + esm_len);

        ogs_assert(esmbuf);
        ogs_pkbuf_reserve(esmbuf, OGS_NAS_HEADROOM);
        ogs_pkbuf_put_data(esmbuf, esm, esm_len);
        /* Partially ciphered: the container value, with this message's COUNT
         * (TS 24.301 4.4.5) */
        if (mme_ue->selected_enc_algorithm)
            ogs_nas_encrypt(mme_ue->selected_enc_algorithm,
                mme_ue->knas_enc, mme_ue->ul_count.i32, NAS_SECURITY_BEARER,
                OGS_NAS_SECURITY_UPLINK_DIRECTION, esmbuf);
        if (esmbuf->len >= 3 &&
                esmbuf->data[2] == MME_CP_CIOT_ESM_DATA_TRANSPORT) {
            r = mme_cp_ciot_handle_uplink(mme_ue, esmbuf);
            ogs_expect(r == OGS_OK);
        } else {
            ogs_warn("[%s] CP-CIoT: ESM message 0x%02x in a control plane "
                    "service request ignored", mme_ue->imsi_bcd,
                    esmbuf->len >= 3 ? esmbuf->data[2] : 0);
            ogs_pkbuf_free(esmbuf);
        }
    }

out:
    ogs_pkbuf_free(nasbuf);
    return OGS_OK;
}

int mme_cp_ciot_open(void)
{
    ogs_sockaddr_t *addr = NULL;
    char buf[OGS_ADDRSTRLEN];

    if (!ogs_gtp_self()->gtpc_addr) {
        ogs_warn("[CP-CIoT] No IPv4 GTP-C address: CP-CIoT data disabled");
        return OGS_OK;
    }

    ogs_assert(OGS_OK == ogs_copyaddrinfo(&addr, ogs_gtp_self()->gtpc_addr));
    addr->ogs_sin_port = htobe16(GTPU_PORT);
    addr->next = NULL;

    gtpu_sock = ogs_udp_server(addr, NULL);
    if (!gtpu_sock) {
        ogs_freeaddrinfo(addr);
        return OGS_ERROR;
    }
    ogs_assert(OGS_OK == ogs_sockaddr_to_ip(addr, NULL, &gtpu_ip));
    gtpu_poll = ogs_pollset_add(ogs_app()->pollset,
            OGS_POLLIN, gtpu_sock->fd, gtpu_recv_cb, NULL);
    ogs_assert(gtpu_poll);

    ogs_info("[CP-CIoT] GTP-U for user data over NAS on %s:%d",
            OGS_ADDR(addr, buf), GTPU_PORT);
    ogs_freeaddrinfo(addr);
    return OGS_OK;
}

void mme_cp_ciot_close(void)
{
    if (gtpu_poll)
        ogs_pollset_remove(gtpu_poll);
    gtpu_poll = NULL;
    if (gtpu_sock)
        ogs_sock_destroy(gtpu_sock);
    gtpu_sock = NULL;
}
