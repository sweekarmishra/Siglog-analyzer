"""Expected NAS message sequences (3GPP TS 24.501 for 5GS, TS 24.301 for EPS).

Each step is (name, message_type_code, required). Message type codes are the
hex values Wireshark shows in nas-5gs.mm.message_type / nas_eps.nas_msg_emm_type.
"""

CAUSES_5GMM = {3: "Illegal UE", 5: "PEI not accepted", 6: "Illegal ME",
               7: "5GS services not allowed", 9: "UE identity cannot be derived by the network",
               10: "Implicitly de-registered", 11: "PLMN not allowed", 12: "Tracking area not allowed",
               13: "Roaming not allowed in this tracking area", 15: "No suitable cells in tracking area",
               20: "MAC failure", 21: "Synch failure", 22: "Congestion",
               23: "UE security capabilities mismatch", 24: "Security mode rejected, unspecified",
               27: "N1 mode not allowed", 28: "Restricted service area",
               62: "No network slices available"}
CAUSES_EMM = {3: "Illegal UE", 6: "Illegal ME", 7: "EPS services not allowed",
              8: "EPS and non-EPS services not allowed", 9: "UE identity cannot be derived by the network",
              10: "Implicitly detached", 11: "PLMN not allowed", 12: "Tracking area not allowed",
              13: "Roaming not allowed in this tracking area", 14: "EPS services not allowed in this PLMN",
              15: "No suitable cells in tracking area", 17: "Network failure", 22: "Congestion"}

FLOWS = {
    "5g-registration": {
        "layer": "nas-5gs",
        "causes": CAUSES_5GMM,
        "security_step": 0x5D,
        "field": "nas-5gs.mm.message_type",
        "cause_field": "nas-5gs.mm.5gmm_cause",
        "reject_code": 0x44,
        "names": {0x41: "Registration Request", 0x42: "Registration Accept",
                  0x43: "Registration Complete", 0x44: "Registration Reject",
                  0x56: "Authentication Request", 0x57: "Authentication Response",
                  0x5D: "Security Mode Command", 0x5E: "Security Mode Complete"},
        "steps": [(0x41, True), (0x56, True), (0x57, True), (0x5D, True),
                  (0x5E, True), (0x42, True), (0x43, True)],
    },
    "lte-attach": {
        "layer": "nas-eps",
        "causes": CAUSES_EMM,
        "security_step": 0x5D,
        "field": "nas_eps.nas_msg_emm_type",
        "cause_field": "nas_eps.emm.cause",
        "reject_code": 0x44,
        "names": {0x41: "Attach Request", 0x42: "Attach Accept",
                  0x43: "Attach Complete", 0x44: "Attach Reject",
                  0x52: "Authentication Request", 0x53: "Authentication Response",
                  0x5D: "Security Mode Command", 0x5E: "Security Mode Complete"},
        "steps": [(0x41, True), (0x52, True), (0x53, True), (0x5D, True),
                  (0x5E, True), (0x42, True), (0x43, True)],
    },
}
