Known Bugs (On 0.2 branch)
--------------------------

  * All Map-Request type packet variations only have a single ITR-RLOC
  * When RLOC probing, the probe bit is set for all RLOCs, not just the one probed
  * When an SMR is done due to an ifdown, no Map-Register is sent
  * Sometime a Map-Register is sent on SMRs (not due ifdown) but afterwards. Should be sent before
  * Once an SMR is sent, Wireshark detects Map-Register and Map-Reply packets as "malformed"
  * LSBs are harcoded to 1
  * XEN kernel not supported
