/******************************************************************************
 *
 *  Copyright (C) 1998-2012 Broadcom Corporation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#include <string.h>

#include "bt_target.h"
#if defined(HL_INCLUDED) && (HL_INCLUDED == TRUE)

#include "sdp_api.h"
#include "bta_hl_int.h"
#include "utl.h"

/*******************************************************************************
**
** Function         bta_hl_fill_sup_feature_list
**
** Description      Fill the supported features from teh SDP record
**
** Returns          TRUE if found, FALSE if not
**                  If found, the passed protocol list element is filled in.
**
*******************************************************************************/
BOOLEAN bta_hl_fill_sup_feature_list( const tSDP_DISC_ATTR  *p_attr,
                                      tBTA_HL_SUP_FEATURE_LIST_ELEM *p_list)
{
    tSDP_DISC_ATTR  *p_sattr;
    UINT8           item_cnt;
    UINT8           list_cnt=0;
    BOOLEAN         status=TRUE;

    for (p_attr = p_attr->attr_value.v.p_sub_attr; p_attr; p_attr = p_attr->p_next_attr)
    {
        /* mdep sequence */
        if (SDP_DISC_ATTR_TYPE(p_attr->attr_len_type) != DATA_ELE_SEQ_DESC_TYPE)
        {
            return(FALSE);
        }

        item_cnt=0;

        for (p_sattr = p_attr->attr_value.v.p_sub_attr; p_sattr && (item_cnt < 4) ; p_sattr = p_sattr->p_next_attr)
        {
            /* for each mdep list */

            p_list->list_elem[list_cnt].p_mdep_desp = NULL;
            switch (item_cnt)
            {
                case 0:
                    p_list->list_elem[list_cnt].mdep_id = p_sattr->attr_value.v.u8;
                    break;
                case 1:
                    p_list->list_elem[list_cnt].data_type = p_sattr->attr_value.v.u16;
                    break;
                case 2:
                    p_list->list_elem[list_cnt].mdep_role = (tBTA_HL_MDEP_ROLE) p_sattr->attr_value.v.u8;
                    break;
                case 3:
                    p_list->list_elem[list_cnt].p_mdep_desp    = (char *) p_sattr->attr_value.v.array;
                    break;
            }

            item_cnt++;
        }
        list_cnt++;
    }
    p_list->num_elems = list_cnt;
    return(status);
}

/*******************************************************************************
**
** Function         bta_hl_compose_supported_feature_list
**
** Description      This function is called to compose a data sequence from
**                  the supported  feature element list struct pointer
**
** Returns          the length of the data sequence
**
*******************************************************************************/
int bta_hl_compose_supported_feature_list( UINT8 *p, UINT16 num_elem,
                                           const tBTA_HL_SUP_FEATURE_ELEM *p_elem_list)
{
    UINT16          xx, str_len, seq_len;
    UINT8           *p_head = p;

    for (xx = 0; xx < num_elem; xx++, p_elem_list++)
    {
        UINT8_TO_BE_STREAM  (p, (DATA_ELE_SEQ_DESC_TYPE << 3) | SIZE_IN_NEXT_BYTE);
        seq_len=7;
        str_len=0;
        if (p_elem_list->p_mdep_desp)
        {
            str_len = strlen(p_elem_list->p_mdep_desp)+1;
            seq_len += str_len+2; /* todo add a # symbol for 2 */
        }

        *p++ = (UINT8) seq_len;

        UINT8_TO_BE_STREAM  (p, (UINT_DESC_TYPE << 3) | SIZE_ONE_BYTE);
        UINT8_TO_BE_STREAM  (p, p_elem_list->mdep_id);
        UINT8_TO_BE_STREAM  (p, (UINT_DESC_TYPE << 3) | SIZE_TWO_BYTES);
        UINT16_TO_BE_STREAM (p, p_elem_list->data_type);
        UINT8_TO_BE_STREAM  (p, (UINT_DESC_TYPE << 3) | SIZE_ONE_BYTE);
        UINT8_TO_BE_STREAM  (p, p_elem_list->mdep_role);

        if (str_len)
        {
            UINT8_TO_BE_STREAM  (p, (TEXT_STR_DESC_TYPE << 3) | SIZE_IN_NEXT_BYTE);
            UINT8_TO_BE_STREAM  (p, str_len);
            ARRAY_TO_BE_STREAM(p, p_elem_list->p_mdep_desp, str_len);
        }
    }

    return(p - p_head);
}

/*******************************************************************************
**
** Function         bta_hl_add_sup_feature_list
**
** Description      This function is called to add a protocol descriptor list to
**                  a record. This would be through the SDP database maintenance API.
**                  If the protocol list already exists in the record, it is replaced
**                  with the new list.
**
** Returns          TRUE if added OK, else FALSE
**
*******************************************************************************/
BOOLEAN bta_hl_add_sup_feature_list (UINT32 handle, UINT16 num_elem,
                                     const tBTA_HL_SUP_FEATURE_ELEM *p_elem_list)
{
    int offset;
    BOOLEAN result;
    UINT8 *p_buf = (UINT8 *)osi_malloc(BTA_HL_SUP_FEATURE_SDP_BUF_SIZE);

    offset = bta_hl_compose_supported_feature_list(p_buf, num_elem,
                                                   p_elem_list);
    result = SDP_AddAttribute(handle, ATTR_ID_HDP_SUP_FEAT_LIST,
                              DATA_ELE_SEQ_DESC_TYPE, (UINT32) offset, p_buf);
    osi_free(p_buf);

    return result;
}

/*****************************************************************************
**
**  Function:    bta_hl_sdp_update
**
**  Purpose:     Register an HDP application with SDP
**
**  Parameters:
**
**  Returns:     void
**
*****************************************************************************/
tBTA_HL_STATUS bta_hl_sdp_update (UINT8 app_id)
{
    UINT16                          svc_class_id_list[BTA_HL_NUM_SVC_ELEMS];
    tSDP_PROTOCOL_ELEM              proto_elem_list[BTA_HL_NUM_PROTO_ELEMS];
    tSDP_PROTO_LIST_ELEM            add_proto_list;
    tBTA_HL_SUP_FEATURE_LIST_ELEM   sup_feature_list;
    UINT16                          browse_list[] = {UUID_SERVCLASS_PUBLIC_BROWSE_GROUP};
    UINT8                           i,j, cnt,mdep_id, mdep_role;
    UINT8                           data_exchange_spec = BTA_HL_SDP_IEEE_11073_20601;
    UINT8                           mcap_sup_proc = BTA_HL_MCAP_SUP_PROC_MASK;
    UINT16                          profile_uuid = UUID_SERVCLASS_HDP_PROFILE;
#if (MTK_COMMON == TRUE)
    UINT16                          version = BTA_HL_VERSION_01_01;
#else
    UINT16                          version = BTA_HL_VERSION_01_00;
#endif
    UINT8                           num_services=1;
    tBTA_HL_APP_CB                  *p_cb = BTA_HL_GET_APP_CB_PTR(0);
    BOOLEAN                         result = TRUE;
    tBTA_HL_STATUS                  status = BTA_HL_STATUS_OK;
    UNUSED(app_id);

    if ((p_cb->sup_feature.app_role_mask == BTA_HL_MDEP_ROLE_MASK_SOURCE) &&
        (!p_cb->sup_feature.advertize_source_sdp))
    {
        return BTA_HL_STATUS_OK;
    }

    num_services=1;
    svc_class_id_list[0]= UUID_SERVCLASS_HDP_SOURCE;
    if (p_cb->sup_feature.app_role_mask == BTA_HL_MDEP_ROLE_MASK_SINK)
    {
        svc_class_id_list[0]= UUID_SERVCLASS_HDP_SINK;
    }
    else
    {
        if (p_cb->sup_feature.app_role_mask != BTA_HL_MDEP_ROLE_MASK_SOURCE)
        {
            /* dual role */
            num_services=2;
            svc_class_id_list[1]= UUID_SERVCLASS_HDP_SINK;
        }
    }
    result &= SDP_AddServiceClassIdList(p_cb->sdp_handle, num_services, svc_class_id_list);

    if (result)
    {
        /* add the protocol element sequence */
        proto_elem_list[0].protocol_uuid = UUID_PROTOCOL_L2CAP;
        proto_elem_list[0].num_params = 1;
        proto_elem_list[0].params[0] = p_cb->ctrl_psm;
        proto_elem_list[1].protocol_uuid = UUID_PROTOCOL_MCAP_CTRL;
        proto_elem_list[1].num_params = 1;
        proto_elem_list[1].params[0] = version;
        result &= SDP_AddProtocolList(p_cb->sdp_handle, BTA_HL_NUM_PROTO_ELEMS, proto_elem_list);

        result &= SDP_AddProfileDescriptorList(p_cb->sdp_handle, profile_uuid, version);
    }

    if (result)
    {
        add_proto_list.num_elems = BTA_HL_NUM_ADD_PROTO_ELEMS;
        add_proto_list.list_elem[0].protocol_uuid = UUID_PROTOCOL_L2CAP;
        add_proto_list.list_elem[0].num_params = 1;
        add_proto_list.list_elem[0].params[0] = p_cb->data_psm;
        add_proto_list.list_elem[1].protocol_uuid = UUID_PROTOCOL_MCAP_DATA;
        add_proto_list.list_elem[1].num_params = 0;
        result &= SDP_AddAdditionProtoLists(p_cb->sdp_handle, BTA_HL_NUM_ADD_PROTO_LISTS,
                                            (tSDP_PROTO_LIST_ELEM *)&add_proto_list);
    }

    if (result)
    {
        if (p_cb->srv_name[0] )
        {
            result &= SDP_AddAttribute(p_cb->sdp_handle,
                                       (UINT16)ATTR_ID_SERVICE_NAME,
                                       (UINT8)TEXT_STR_DESC_TYPE,
                                       (UINT32)(strlen(p_cb->srv_name) + 1),
                                       (UINT8 *)p_cb->srv_name);
        } /* end of setting optional service name */
    }

    if (result)
    {
        if (p_cb->srv_desp[0] )
        {
            result &= SDP_AddAttribute(p_cb->sdp_handle,
                                       (UINT16)ATTR_ID_SERVICE_DESCRIPTION,
                                       (UINT8)TEXT_STR_DESC_TYPE,
                                       (UINT32)(strlen(p_cb->srv_desp) + 1),
                                       (UINT8 *)p_cb->srv_desp);

        } /* end of setting optional service description */

    }

    if (result)
    {
        if (p_cb->provider_name[0] )
        {
            result &= SDP_AddAttribute(p_cb->sdp_handle,
                                       (UINT16)ATTR_ID_PROVIDER_NAME,
                                       (UINT8)TEXT_STR_DESC_TYPE,
                                       (UINT32)(strlen(p_cb->provider_name) + 1),
                                       (UINT8 *)p_cb->provider_name);
        } /* end of setting optional provider name */
    }

    /* add supported feture list */

    if (result)
    {
        cnt=0;
        for (i=1; i< BTA_HL_NUM_MDEPS; i++)
        {
            if (p_cb->sup_feature.mdep[i].mdep_id)
            {
                mdep_id = (UINT8)p_cb->sup_feature.mdep[i].mdep_id;
                mdep_role = (UINT8)p_cb->sup_feature.mdep[i].mdep_cfg.mdep_role;

                APPL_TRACE_DEBUG("num_of_mdep_data_types %d ", p_cb->sup_feature.mdep[i].mdep_cfg.num_of_mdep_data_types);
                for (j=0; j<p_cb->sup_feature.mdep[i].mdep_cfg.num_of_mdep_data_types; j++)
                {
                    sup_feature_list.list_elem[cnt].mdep_id = mdep_id;
                    sup_feature_list.list_elem[cnt].mdep_role = mdep_role;
                    sup_feature_list.list_elem[cnt].data_type = p_cb->sup_feature.mdep[i].mdep_cfg.data_cfg[j].data_type;
                    if (p_cb->sup_feature.mdep[i].mdep_cfg.data_cfg[j].desp[0] != '\0')
                    {
                        sup_feature_list.list_elem[cnt].p_mdep_desp = p_cb->sup_feature.mdep[i].mdep_cfg.data_cfg[j].desp;
                    }
                    else
                    {
                        sup_feature_list.list_elem[cnt].p_mdep_desp = NULL;
                    }

                    cnt++;
                    if (cnt==BTA_HL_NUM_SUP_FEATURE_ELEMS)
                    {
                        result = FALSE;
                        break;
                    }
                }
            }
        }
        sup_feature_list.num_elems = cnt;
        result &=   bta_hl_add_sup_feature_list (p_cb->sdp_handle,
                                                 sup_feature_list.num_elems,
                                                 sup_feature_list.list_elem);
    }
    if (result)
    {
        result &= SDP_AddAttribute(p_cb->sdp_handle, ATTR_ID_HDP_DATA_EXCH_SPEC, UINT_DESC_TYPE,
                                   (UINT32)1, (UINT8*)&data_exchange_spec);
    }

    if (result)
    {

        result &= SDP_AddAttribute(p_cb->sdp_handle, ATTR_ID_HDP_MCAP_SUP_PROC, UINT_DESC_TYPE,
                                   (UINT32)1, (UINT8*)&mcap_sup_proc);
    }

    if (result)
    {
        result &= SDP_AddUuidSequence(p_cb->sdp_handle, ATTR_ID_BROWSE_GROUP_LIST, 1, browse_list);
    }

    if (result)
    {
        for(i=0; i < num_services; i++)
        {
            bta_sys_add_uuid(svc_class_id_list[i]);
            APPL_TRACE_DEBUG("dbg bta_sys_add_uuid i=%d uuid=0x%x", i, svc_class_id_list[i]); //todo
        }
    }
    else
    {
        if (p_cb->sdp_handle)
        {
            SDP_DeleteRecord(p_cb->sdp_handle);
            p_cb->sdp_handle = 0;
        }
        status = BTA_HL_STATUS_SDP_FAIL;
    }
#if BTA_HL_DEBUG == TRUE
    APPL_TRACE_DEBUG("bta_hl_sdp_update status=%s", bta_hl_status_code(status));
#endif
    return status;
}


/*****************************************************************************
**
**  Function:    bta_hl_sdp_register
**
**  Purpose:     Register an HDP application with SDP
**
**  Parameters:  p_cb           - Pointer to MA instance control block
**               p_service_name - MA server name
**               inst_id        - MAS instance ID
**               msg_type       - Supported message type(s)
**
**
**  Returns:     void
**
*****************************************************************************/
tBTA_HL_STATUS bta_hl_sdp_register (UINT8 app_idx)
{
    UINT16                          svc_class_id_list[BTA_HL_NUM_SVC_ELEMS];
    tSDP_PROTOCOL_ELEM              proto_elem_list[BTA_HL_NUM_PROTO_ELEMS];
    tSDP_PROTO_LIST_ELEM            add_proto_list;
    tBTA_HL_SUP_FEATURE_LIST_ELEM   sup_feature_list;
    UINT16                          browse_list[] = {UUID_SERVCLASS_PUBLIC_BROWSE_GROUP};
    UINT8                           i,j, cnt,mdep_id, mdep_role;
    UINT8                           data_exchange_spec = BTA_HL_SDP_IEEE_11073_20601;
    UINT8                           mcap_sup_proc = BTA_HL_MCAP_SUP_PROC_MASK;
    UINT16                          profile_uuid = UUID_SERVCLASS_HDP_PROFILE;
#if (MTK_COMMON == TRUE)
    UINT16                          version = BTA_HL_VERSION_01_01;
#else
    UINT16                          version = BTA_HL_VERSION_01_00;
#endif
    UINT8                           num_services=1;
    tBTA_HL_APP_CB                  *p_cb = BTA_HL_GET_APP_CB_PTR(app_idx);
    BOOLEAN                         result = TRUE;
    tBTA_HL_STATUS                  status = BTA_HL_STATUS_OK;

#if BTA_HL_DEBUG == TRUE
    APPL_TRACE_DEBUG("bta_hl_sdp_register app_idx=%d",app_idx);
#endif

    if ((p_cb->sup_feature.app_role_mask == BTA_HL_MDEP_ROLE_MASK_SOURCE) &&
        (!p_cb->sup_feature.advertize_source_sdp))
    {
        return BTA_HL_STATUS_OK;
    }

    if ((p_cb->sdp_handle  = SDP_CreateRecord()) == 0)
    {
        return BTA_HL_STATUS_SDP_NO_RESOURCE;
    }

    num_services=1;
    svc_class_id_list[0]= UUID_SERVCLASS_HDP_SOURCE;
    if (p_cb->sup_feature.app_role_mask == BTA_HL_MDEP_ROLE_MASK_SINK)
    {
        svc_class_id_list[0]= UUID_SERVCLASS_HDP_SINK;
    }
    else
    {
        if (p_cb->sup_feature.app_role_mask != BTA_HL_MDEP_ROLE_MASK_SOURCE)
        {
            /* dual role */
            num_services=2;
            svc_class_id_list[1]= UUID_SERVCLASS_HDP_SINK;
        }
    }
    result &= SDP_AddServiceClassIdList(p_cb->sdp_handle, num_services, svc_class_id_list);

    if (result)
    {
        /* add the protocol element sequence */
        proto_elem_list[0].protocol_uuid = UUID_PROTOCOL_L2CAP;
        proto_elem_list[0].num_params = 1;
        proto_elem_list[0].params[0] = p_cb->ctrl_psm;
        proto_elem_list[1].protocol_uuid = UUID_PROTOCOL_MCAP_CTRL;
        proto_elem_list[1].num_params = 1;
        proto_elem_list[1].params[0] = version;
        result &= SDP_AddProtocolList(p_cb->sdp_handle, BTA_HL_NUM_PROTO_ELEMS, proto_elem_list);

        result &= SDP_AddProfileDescriptorList(p_cb->sdp_handle, profile_uuid, version);
    }

    if (result)
    {
        add_proto_list.num_elems = BTA_HL_NUM_ADD_PROTO_ELEMS;
        add_proto_list.list_elem[0].protocol_uuid = UUID_PROTOCOL_L2CAP;
        add_proto_list.list_elem[0].num_params = 1;
        add_proto_list.list_elem[0].params[0] = p_cb->data_psm;
        add_proto_list.list_elem[1].protocol_uuid = UUID_PROTOCOL_MCAP_DATA;
        add_proto_list.list_elem[1].num_params = 0;
        result &= SDP_AddAdditionProtoLists(p_cb->sdp_handle, BTA_HL_NUM_ADD_PROTO_LISTS,
                                            (tSDP_PROTO_LIST_ELEM *)&add_proto_list);
    }

    if (result)
    {
        if (p_cb->srv_name[0] )
        {
            result &= SDP_AddAttribute(p_cb->sdp_handle,
                                       (UINT16)ATTR_ID_SERVICE_NAME,
                                       (UINT8)TEXT_STR_DESC_TYPE,
                                       (UINT32)(strlen(p_cb->srv_name) + 1),
                                       (UINT8 *)p_cb->srv_name);
        } /* end of setting optional service name */
    }

    if (result)
    {
        if (p_cb->srv_desp[0] )
        {
            result &= SDP_AddAttribute(p_cb->sdp_handle,
                                       (UINT16)ATTR_ID_SERVICE_DESCRIPTION,
                                       (UINT8)TEXT_STR_DESC_TYPE,
                                       (UINT32)(strlen(p_cb->srv_desp) + 1),
                                       (UINT8 *)p_cb->srv_desp);

        } /* end of setting optional service description */

    }

    if (result)
    {
        if (p_cb->provider_name[0] )
        {
            result &= SDP_AddAttribute(p_cb->sdp_handle,
                                       (UINT16)ATTR_ID_PROVIDER_NAME,
                                       (UINT8)TEXT_STR_DESC_TYPE,
                                       (UINT32)(strlen(p_cb->provider_name) + 1),
                                       (UINT8 *)p_cb->provider_name);
        } /* end of setting optional provider name */
    }

    /* add supported feture list */

    if (result)
    {
        cnt=0;
        for (i=1; i<= p_cb->sup_feature.num_of_mdeps; i++)
        {
            mdep_id = (UINT8)p_cb->sup_feature.mdep[i].mdep_id;
            mdep_role = (UINT8)p_cb->sup_feature.mdep[i].mdep_cfg.mdep_role;

            for (j=0; j<p_cb->sup_feature.mdep[i].mdep_cfg.num_of_mdep_data_types; j++)
            {
                sup_feature_list.list_elem[cnt].mdep_id = mdep_id;
                sup_feature_list.list_elem[cnt].mdep_role = mdep_role;
                sup_feature_list.list_elem[cnt].data_type = p_cb->sup_feature.mdep[i].mdep_cfg.data_cfg[j].data_type;
                if (p_cb->sup_feature.mdep[i].mdep_cfg.data_cfg[j].desp[0] != '\0')
                {
                    sup_feature_list.list_elem[cnt].p_mdep_desp = p_cb->sup_feature.mdep[i].mdep_cfg.data_cfg[j].desp;
                }
                else
                {
                    sup_feature_list.list_elem[cnt].p_mdep_desp = NULL;
                }

                cnt++;
                if (cnt==BTA_HL_NUM_SUP_FEATURE_ELEMS)
                {
                    result = FALSE;
                    break;
                }
            }
        }
        sup_feature_list.num_elems = cnt;
        result &=   bta_hl_add_sup_feature_list (p_cb->sdp_handle,
                                                 sup_feature_list.num_elems,
                                                 sup_feature_list.list_elem);
    }
    if (result)
    {
        result &= SDP_AddAttribute(p_cb->sdp_handle, ATTR_ID_HDP_DATA_EXCH_SPEC, UINT_DESC_TYPE,
                                   (UINT32)1, (UINT8*)&data_exchange_spec);
    }

    if (result)
    {

        result &= SDP_AddAttribute(p_cb->sdp_handle, ATTR_ID_HDP_MCAP_SUP_PROC, UINT_DESC_TYPE,
                                   (UINT32)1, (UINT8*)&mcap_sup_proc);
    }

    if (result)
    {
        result &= SDP_AddUuidSequence(p_cb->sdp_handle, ATTR_ID_BROWSE_GROUP_LIST, 1, browse_list);
    }

    if (result)
    {
        for(i=0; i < num_services; i++)
        {
            bta_sys_add_uuid(svc_class_id_list[i]);
            APPL_TRACE_DEBUG("dbg bta_sys_add_uuid i=%d uuid=0x%x", i, svc_class_id_list[i]); //todo
        }
    }
    else
    {
        if (p_cb->sdp_handle)
        {
            SDP_DeleteRecord(p_cb->sdp_handle);
            p_cb->sdp_handle = 0;
        }
        status = BTA_HL_STATUS_SDP_FAIL;
    }
#if BTA_HL_DEBUG == TRUE
    APPL_TRACE_DEBUG("bta_hl_sdp_register status=%s", bta_hl_status_code(status));
#endif
    return status;
}

/*******************************************************************************
**
** Function         bta_hl_find_sink_or_src_srv_class_in_db
**
** Description      This function queries an SDP database for either a HDP Sink or
**                  Source service class ID.
**                  If the p_start_rec pointer is NULL, it looks from the beginning
**                  of the database, else it continues from the next record after
**                  p_start_rec.
**
** Returns          Pointer to record containing service class, or NULL
**
*******************************************************************************/
tSDP_DISC_REC *bta_hl_find_sink_or_src_srv_class_in_db (const tSDP_DISCOVERY_DB *p_db,
                                                        const tSDP_DISC_REC *p_start_rec)
{
#if SDP_CLIENT_ENABLED == TRUE
    tSDP_DISC_REC   *p_rec;
    tSDP_DISC_ATTR  *p_attr, *p_sattr;

    /* Must have a valid database */
    if (p_db == NULL)
        return(NULL);


    if (!p_start_rec)
    {

        p_rec = p_db->p_first_rec;
    }
    else
    {
        p_rec = p_start_rec->p_next_rec;
    }

    while (p_rec)
    {
        p_attr = p_rec->p_first_attr;
        while (p_attr)
        {
            if ((p_attr->attr_id == ATTR_ID_SERVICE_CLASS_ID_LIST)
                && (SDP_DISC_ATTR_TYPE(p_attr->attr_len_type) == DATA_ELE_SEQ_DESC_TYPE))
            {
                for (p_sattr = p_attr->attr_value.v.p_sub_attr; p_sattr; p_sattr = p_sattr->p_next_attr)
                {
                    if ((SDP_DISC_ATTR_TYPE(p_sattr->attr_len_type) == UUID_DESC_TYPE)
                        && (SDP_DISC_ATTR_LEN(p_sattr->attr_len_type) == 2)
                        && ( (p_sattr->attr_value.v.u16 == UUID_SERVCLASS_HDP_SINK) ||
                             (p_sattr->attr_value.v.u16 == UUID_SERVCLASS_HDP_SOURCE)) )
                    {
                        return(p_rec);
                    }
                }
                break;
            }

            p_attr = p_attr->p_next_attr;
        }

        p_rec = p_rec->p_next_rec;
    }
#endif
    /* If here, no matching UUID found */

#if BTA_HL_DEBUG == TRUE
    APPL_TRACE_DEBUG("bta_hl_find_sink_or_src_srv_class_in_db failed");
#endif

    return(NULL);
}
#endif /* HL_INCLUDED */
