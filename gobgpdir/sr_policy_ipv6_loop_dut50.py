#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import print_function

import grpc
from google.protobuf.any_pb2 import Any

import gobgp_pb2
import gobgp_pb2_grpc
import attribute_pb2

_TIMEOUT_SECONDS = 1000

#added by kun: ipv6 address pre-processing to fit in the script
def ipv6_to_intlist(ipv6):
    groups = ipv6.split(":")
    result = []
    for group in groups:
        group = int(group, 16)
        result.append(group)
    return result


#added by kun: label processing to carry ttl and s_flag information
def label_offset12(label):
    loop = 1
    while loop <= 12:
        label = label*2
        loop +=1
    return label

def label_update(labels):
    result = []
    label_num = len(labels)
    s_flag = 0
    loop = 0 # list index starts from 0
    while loop < label_num:
        label = labels[loop]

        if loop == (label_num-1):
            s_flag = 1

        label = label_offset12(label)+256*s_flag+255
        result.append(label)
        loop +=1
    return result



#original main funtion
def go_bgp_subnet(color, endpoint_device, target_device, sid_list, bsid_value, nh):
    """
    inject or delete an route with <ACME>-CIDR and <ACME>-SCRUBBING community
    NLRI
    ORIGIN
    AS_PATH
    LP
    EXTENDED COMMUNITIES
     RT
    TUNNEL ENCAP
     TLVs
      SR Policy
       SUB-TLVs
        Preference
        Binding-SID
        SEG-LIST
         WEIGHT
         SEGMENT(1..n)
    """
    channel = grpc.insecure_channel("localhost:50051")
    stub = gobgp_pb2_grpc.GobgpApiStub(channel)
    attributes = []
    segments = []
    # bgp-sr-te safi
    family = gobgp_pb2.Family(
        afi=gobgp_pb2.Family.AFI_IP6, safi=gobgp_pb2.Family.SAFI_SR_POLICY
    )

    # sr-te policy nlri
    nlri = Any()
    nlri.Pack(
        attribute_pb2.SRPolicyNLRI(
            color=color,
            distinguisher=666,
            endpoint=bytes(ipv6_to_intlist(endpoint_device)),
            length=192,
        )
    )

    # next-hop
    next_hop = Any()
    next_hop.Pack(
        attribute_pb2.NextHopAttribute(
            next_hop=nh,
        )
    )
    attributes.append(next_hop)

    # Origin
    origin = Any()
    origin.Pack(attribute_pb2.OriginAttribute(origin=0))
    attributes.append(origin)
    # Ext RT Communities
    rt = Any()
    rt.Pack(
        attribute_pb2.IPv4AddressSpecificExtended(
            address=target_device, local_admin=1, sub_type=0x02, is_transitive=False
        )
    )
    communities = Any()
    communities.Pack(
        attribute_pb2.ExtendedCommunitiesAttribute(
            communities=[rt],
        )
    )
    attributes.append(communities)
    # generic sid used for bsid
    sid = Any()
    sid.Pack(
        attribute_pb2.SRBindingSID(
            s_flag=False, i_flag=False, sid=(bsid_value).to_bytes(4, byteorder="big")
        )
    )
    # bsid
    bsid = Any()
    bsid.Pack(attribute_pb2.TunnelEncapSubTLVSRBindingSID(bsid=sid))

    # generic segment lbl
    sid_list = label_update(sid_list)

    for n in sid_list:
        segment = Any()
        segment.Pack(
            attribute_pb2.SegmentTypeA(
                flags=attribute_pb2.SegmentFlags(v_flag=False, a_flag=False, s_flag=False, b_flag=False), label=n
            )
        )
        segments.append(segment)
    # segment list
    seglist = Any()
    seglist.Pack(
        attribute_pb2.TunnelEncapSubTLVSRSegmentList(
            weight=attribute_pb2.SRWeight(flags=0, weight=12),
            segments=segments,
        )
    )

    # pref
    pref = Any()
    pref.Pack(attribute_pb2.TunnelEncapSubTLVSRPreference(flags=0, preference=11))

    # path name not used for now
    cpn = Any()
    cpn.Pack(
        attribute_pb2.TunnelEncapSubTLVSRCandidatePathName(
            candidate_path_name="test-path"
        )
    )
    # priority not used for now
    pri = Any()
    pri.Pack(attribute_pb2.TunnelEncapSubTLVSRPriority(priority=10))


    tun = Any()
    # generate tunnel
    tun.Pack(
        attribute_pb2.TunnelEncapAttribute(
            tlvs=[
                attribute_pb2.TunnelEncapTLV(
                    type=15,
                    tlvs=[
                        pref,
                        # bsid,
                        seglist,
                        # cpn,
                        # pri,
                    ],
                )
            ]
        )
    )

    attributes.append(tun)

    stub.AddPath(
        gobgp_pb2.AddPathRequest(
            table_type=gobgp_pb2.GLOBAL,
            path=gobgp_pb2.Path(
                nlri=nlri,
                pattrs=attributes,
                family=family,
                best=True,
            ),
        ),
        _TIMEOUT_SECONDS,
    )


if __name__ == "__main__":
    #read ipv6 endpoint addresses
    f = open("v6_ep.txt", "r")
    v6_eps = f.read()
    v6_ep_list = v6_eps.split(",\n")
    del(v6_ep_list[-1])
    print(v6_ep_list)

    LSP_NUM = len(v6_ep_list) #total lsp number
    print(LSP_NUM)

    
    #Send 4* different lsp with 4* different (colors, [starting labels]) for 1* endpoint
    for current_color in [100,200,300,400]:

        #initiate
        current_lsp = 0 # current lsp no. start from the first one
    
        #static value
        nh = "2001:1::5"
        target_device = "1.1.1.1"
        bsid_value = 10000 #it could be any value, not used actually
        x = 116001
        current_labels = [x, 136001]


        #loop
        while current_lsp < LSP_NUM:
            #fetch current lsp endpoint
            v6_ep = v6_ep_list[current_lsp]


            #do check - print current lsp no.
            print("current_lsp is", current_lsp)
            print("current color is", current_color)
            print("current label is", current_labels)
            print("current ep is", v6_ep, type(v6_ep))
        
            
            #do work - call function go_bgp_subnet
            go_bgp_subnet(
                color=current_color,
                endpoint_device=v6_ep,
                target_device=target_device,
                bsid_value=bsid_value,
                sid_list=current_labels,
                nh=nh,
            )
            

            #goto next loop
            current_lsp +=1
            x +=1
            current_labels = [x, 136001]

