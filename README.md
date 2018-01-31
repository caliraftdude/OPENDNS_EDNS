CustomerID to EDSN0 iRule

v0.5.2
2017.08.25 

Background:
The Network Device Registration API provides a way for networking hardware vendors to integrate their 
network devices with the OpenDNS Umbrella Dashboard. After properly implementing this Registration API 
into a device, vendors can provide their end customers with the ability to have traffic passing through 
this device appear in the customers specific dashboard, and allow the customer to apply policies to 
this traffic.

Purpose:
This iRule looks at the VIP that the DNS request is made on.  Each customer has its own VIP, so it then
looks up the deviceIDs that apply to the VIP names in a data group.  Next it determines if there are 
Additional RR in the packet to decide how to write the EDNS0 extension onto the packet.  Most of the
extension is static content with the DeviceID being dependent on the VIP the traffic was received on.

Functionally this iRule works well - however, there are some superfluous items lines that could before
deleted and cleaned up (75-94).  Logging is multi-level to help with debugging.

Dependencies:
LTM licensing
datagroup VIP_TO_DEVICEID populated as documented in RULE_INIT event
vips that match datagroup VIP_TO_DEVICEID

Changes:
v0.5.1 - Initialize packet and buffer variables, un-set packet, buffer, and before when finished.
v0.5.2 - Changed method of separating virtual name from partition for DeviceID lookup. 
       - Moved DeviceID lookup to CLIENT_ACCEPTED
