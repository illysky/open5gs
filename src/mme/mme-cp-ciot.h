/*
 * Control Plane CIoT EPS optimisation (TS 23.401 5.3.4B) for UEs that
 * support neither S1-U data transfer nor the User Plane optimisation, such
 * as an NB-IoT-only modem.
 *
 * User data travels in ESM DATA TRANSPORT messages (TS 24.301 8.3.25). The
 * MME terminates the SGW's S1-U tunnel itself: the bearer's "eNB" F-TEID
 * given to the SGW in Modify Bearer Request is a GTP-U socket in the MME,
 * so SGW-C and SGW-U need no S11-U support.
 */

#ifndef MME_CP_CIOT_H
#define MME_CP_CIOT_H

#include "mme-context.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MME_CP_CIOT_ESM_DATA_TRANSPORT 235
#define MME_CP_CIOT_CONTROL_PLANE_SERVICE_REQUEST 77

int mme_cp_ciot_open(void);
void mme_cp_ciot_close(void);

bool mme_cp_ciot_ue(const mme_ue_t *mme_ue);
void mme_cp_ciot_set_downlink_path(mme_bearer_t *bearer);

/* Takes ownership of esmbuf, a plain ESM DATA TRANSPORT message */
int mme_cp_ciot_handle_uplink(mme_ue_t *mme_ue, ogs_pkbuf_t *esmbuf);

/*
 * CONTROL PLANE SERVICE REQUEST (TS 24.301 5.6.1.2.2, 8.2.33) of a UE in
 * EMM-IDLE, integrity checked: nasbuf starts at the plain EMM header.
 * Takes ownership of nasbuf.
 */
int mme_cp_ciot_handle_service_request(
        enb_ue_t *enb_ue, mme_ue_t *mme_ue, ogs_pkbuf_t *nasbuf);

/*
 * Downlink user data that arrives while the UE is in ECM-IDLE is held in the
 * MME (the SGW keeps sending to the MME's GTP-U socket, see
 * mme_send_release_access_bearer_or_ue_context_release) and the UE is paged,
 * unless it is in power saving mode, in which case the data waits for the UE's
 * next contact.
 */
bool mme_cp_ciot_has_queue(const mme_ue_t *mme_ue);
void mme_cp_ciot_flush_queue(mme_ue_t *mme_ue);
void mme_cp_ciot_drop_queue(mme_ue_t *mme_ue);

/*
 * What the UE asked for in ATTACH / TRACKING AREA UPDATE REQUEST (NULL: not
 * included, i.e. not requested); the accept grants exactly that.
 */
void mme_psm_store_request(mme_ue_t *mme_ue,
        const ogs_nas_gprs_timer_2_t *t3324,
        const ogs_nas_gprs_timer_3_t *t3412_extended,
        const ogs_nas_extended_drx_parameters_t *edrx);

/* PSM (TS 24.301 5.3.11): T3324 still running since the UE went idle */
bool mme_psm_active_timer_running(const mme_ue_t *mme_ue);
/* T3412 extended if negotiated, otherwise T3412 */
uint32_t mme_psm_periodic_tau_sec(const mme_ue_t *mme_ue);

/* Paging a UE in eDRX: one page per eDRX cycle (each reaches one paging time
 * window), MME_CP_CIOT_EDRX_PAGING_CYCLES in all; other UEs keep T3413 */
#define MME_CP_CIOT_EDRX_PAGING_CYCLES 4
uint32_t mme_edrx_cycle_ms(const mme_ue_t *mme_ue);
ogs_time_t mme_paging_interval(const mme_ue_t *mme_ue);
int mme_paging_max_count(const mme_ue_t *mme_ue);

#ifdef __cplusplus
}
#endif

#endif /* MME_CP_CIOT_H */
