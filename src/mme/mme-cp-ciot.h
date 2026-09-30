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

int mme_cp_ciot_open(void);
void mme_cp_ciot_close(void);

bool mme_cp_ciot_ue(const mme_ue_t *mme_ue);
void mme_cp_ciot_set_downlink_path(mme_bearer_t *bearer);

/* Takes ownership of esmbuf, a plain ESM DATA TRANSPORT message */
int mme_cp_ciot_handle_uplink(mme_ue_t *mme_ue, ogs_pkbuf_t *esmbuf);

#ifdef __cplusplus
}
#endif

#endif /* MME_CP_CIOT_H */
