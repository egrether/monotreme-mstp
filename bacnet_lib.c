// bacnet_lib.c: Functions cadged from _lib.* and lib.* in broadway/mpx/lib/bacnet.

#include "super_hdr.h"
#include "bacnet_lib.h"

static int sizeof_apci(const struct UNKNOWN_PDU *unknown,
                       const struct BACNET_NPCI *npci)
{
    switch (unknown->pdu_type) {
    case CONFIRMED_REQUEST_TYPE:
        if (unknown->segmented_message) {
            return sizeof(struct SEGMENTED_CONFIRMED_REQUEST_PDU);
        }
        return sizeof(struct CONFIRMED_REQUEST_PDU);
    case UNCONFIRMED_REQUEST_TYPE:
        return sizeof(struct UNCONFIRMED_REQUEST_PDU);
    case SIMPLE_ACK_TYPE:
        return sizeof(struct SIMPLE_ACK_PDU);
    case COMPLEX_ACK_TYPE:
        if (unknown->segmented_message || npci->data_expecting_reply) {
            // @fixme According to ASHRAE 135-1995, the test should only be
            //        for source->segmented_message.  But the Trane BCU specifies
            //        sequence-number and proposed-window-size even though
            //        segmented-message == 0.
            return sizeof(struct SEGMENTED_COMPLEX_ACK_PDU);
        }
        return sizeof(struct COMPLEX_ACK_PDU);
    case SEGMENT_ACK_TYPE:
        return sizeof(struct SEGMENT_ACK_PDU);
    case ERROR_TYPE:
        return sizeof(struct ERROR_PDU);
    case REJECT_TYPE:
        return sizeof(struct REJECT_PDU);
    case ABORT_TYPE:
        return sizeof(struct ABORT_PDU);
    }
    return 0;
}

////
// Decodes a BACNET_BUFFER, setting up all the offsets used to find
// the NPCI data and the APCI.
// @note bnb->p_npci must point to the beginning of the NPCI data,
//       bnb->p_data should point to bnb->p_npci and bnb->s_data
//       MUST be set to the length of the message FROM BNB->P_NPCI.

void bacnet_decode_npci_data(struct BACNET_BUFFER *bnb)
{
    int offset;
    unsigned char dlen;
    struct BACNET_NPCI scratch_npci;
    struct BACNET_NPCI_OFFSET *o = &bnb->npci_offset;
    memset(o, (unsigned char) -1, sizeof(*o));
    offset = 0;
    if (bnb->p_npci->dspec) {
        o->dnet = 0;
        offset += 2;
        o->dlen = offset;
        offset += 1;
        dlen = *(bnb->p_npci->data + o->dlen);
        if (dlen) {
            o->dadr = offset;
            offset += dlen;
        }
    }
    if (bnb->p_npci->sspec) {
        o->snet = offset;
        offset += 2;
        o->slen = offset;
        offset += 1;
        o->sadr = offset;
        offset += *(bnb->p_npci->data + o->slen);
    }
    if (bnb->p_npci->dspec) {
        o->hop_count = offset;
        offset += 1;
    }
    if (bnb->p_npci->network_msg) {
        o->msg_type = offset;
        offset += 1;
    }
    if (bnb->p_npci->network_msg
        && (bnb->p_npci->data[o->msg_type] >= 0x80)) {
        o->vendor_id = offset;
        offset += 2;
    }
    if (!bnb->p_npci->network_msg) {
        o->apci = offset;
        bnb->apci.unknown =
            (struct UNKNOWN_PDU *) (bnb->p_npci->data + offset);
        // @note Create a fake struct BACNET_NPCI for use by sizeof_apci.  This is
        //       required because it appears the decoding of a BACnet-Complex-ACK-PDU
        //       is based on the NPCI's data_expecting_reply bit, not on the the
        //       APDU's segmented-message bit as per ASHREA 135-1995 20.1.5.4-5.
        memset(&scratch_npci, 0, sizeof scratch_npci);
        scratch_npci.data_expecting_reply =
            bnb->p_npci->data_expecting_reply;
        offset += sizeof_apci(bnb->apci.unknown, &scratch_npci);
    } else {
        bnb->apci.unknown = NULL;
    }
    o->data = offset;
    o->valid = 1;
    // Adjust p_data and s_data accordingly.
    bnb->p_data = (bnb->p_npci->data + o->data);
    bnb->s_data = bnb->s_data - (bnb->p_data - (void *) bnb->p_npci);
    return;
}
