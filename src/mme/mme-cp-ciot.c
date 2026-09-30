/*
 * Control Plane CIoT EPS optimisation: user data over NAS.
 * See mme-cp-ciot.h.
 */

#include "mme-cp-ciot.h"
#include "nas-security.h"
#include "nas-path.h"

/* As in nas-security.c */
#define NAS_SECURITY_BEARER 0
#define NAS_SECURITY_MAC_SIZE 4

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
        ogs_warn("[%s] CP-CIoT downlink of %d bytes dropped: UE is idle",
                mme_ue->imsi_bcd, (int)len);
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
    ogs_sockaddr_t *to = NULL;
    ssize_t sent;

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
        ogs_debug("[%s] CP-CIoT uplink %d bytes on EBI %d",
                mme_ue->imsi_bcd, len, ebi);

    ogs_pkbuf_free(esmbuf);
    return OGS_OK;

drop:
    ogs_pkbuf_free(esmbuf);
    return OGS_ERROR;
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
