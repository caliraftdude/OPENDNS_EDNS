# CustomerID to EDSN0 iRule
#
# v0.5.2
# 2017.08.25 
# 
# Background:
# The Network Device Registration API provides a way for networking hardware vendors to integrate their 
# network devices with the OpenDNS Umbrella Dashboard. After properly implementing this Registration API 
# into a device, vendors can provide their end customers with the ability to have traffic passing through 
# this device appear in the customers specific dashboard, and allow the customer to apply policies to 
# this traffic.
#
# Purpose:
# This iRule looks at the VIP that the DNS request is made on.  Each customer has its own VIP, so it then
# looks up the deviceIDs that apply to the VIP names in a data group.  Next it determines if there are 
# Additional RR in the packet to decide how to write the EDNS0 extension onto the packet.  Most of the
# extension is static content with the DeviceID being dependent on the VIP the traffic was received on.
#
# Functionally this iRule works well - however, there are some superfluous items lines that could before
# deleted and cleaned up (75-94).  Logging is multi-level to help with debugging.
#
# Dependencies:
#	LTM licensing
#	datagroup VIP_TO_DEVICEID populated as documented in RULE_INIT event
#	vips that match datagroup VIP_TO_DEVICEID
#
# Changes:
# v0.5.1 - Initialize packet and buffer variables, un-set packet, buffer, and before when finished.
# v0.5.2 - Changed method of separating virtual name from partition for DeviceID lookup. 
#        - Moved DeviceID lookup to CLIENT_ACCEPTED


when RULE_INIT {
	# 1, 2, 4, or 8 or any sum of these for different log levels
	set static::debug 0

	# Additional Record (11):
	#	Name 					(00)
	#	Type 			OPT-41	(00 29)
	#	Payload Size 	1280	(05 00)
	#	Ext R-Code		00		(00)
	#	EDNS0 Version			(00)
	#	Options					(00 00)
	#	Data Length		19		(00 13)
	set static::optrr "0000290500000000000013"

	# rdata(11)
	#	OPTION-CODE 	uint16 4		(69 42) 
	#	OPTION-LENGTH	uint16 15		(00 0F)
	#	OPTION-DATA		var "OpenDNS"	(4F 70 65 6E44 4E 53)
	#	+ 8 octets for DeviceID			(Concated after lookup)
	set static::rdata "6942000F4F70656E444E53"

	set static::AR "00002905000000000000136942000F4F70656E444E53"
	# Required datagroup VIP_TO_DEVICEID which must have a vip name to a device id.  Example:
	#	name				value
	# vip_customer_a		01 23 45 67 89 ab cd ef
	# vip_customer_b		9876543210abcdef

}
when CLIENT_ACCEPTED {
	# Use the client IP:Port as a prefix to make it easier to follow the flows
	set log_prefix "[virtual name]:[IP::client_addr]\t"
	if {$static::debug & 1} { log local0. "$log_prefix Connection Accepted." }

	set deviceID [class match -value [lrange [split [virtual name] / ] end end] equals VIP_TO_DEVICEID]
}

when CLIENT_DATA {
    # Initialize
    set buffer ""
    set packet ""

	# Check for device ID first - if that fails, dump immediately
	if { $deviceID equals "" } {
		if {$static::debug & 2} { log local0. "$log_prefix No deviceID mapping found for VIP [virtual name]" }
		return
	} 

	if {$static::debug & 1} { log local0. "$log_prefix translated [virtual name] to $deviceID" }

	# collect the UDP packet into a buffer to manipulate
	binary scan [UDP::payload] @0H* before

	# Break down the packet
	# XXX all if this isn't necessary - 
	set Header [string range $before 0 23]
	set index [ expr [string first 00 $before 24] + 2]
	set query [string range $before 24 [expr {$index-1}] ]
	set type [string range $before $index [expr {$index+3}] ]
	set class [string range $before [expr {$index+4}] [expr {$index+7}]]

	set addRR [string range $Header 20 23]

	if {$static::debug & 4} { 
		log local0. "===============================PACKET========================="
		log local0. "Header = $Header"
		log local0. "query = $query"
		log local0. "type = $type"
		log local0. "class = $class"
		log local0. "Additional RR = $addRR"
		log local0. "size = [expr {$index+7}]"
		log local0. "===========================END=PACKET========================="
	}

	if {$static::debug & 2} { 
		log local0. "$log_prefix before (size=[UDP::payload length]): $before"
	}

	# Build the packet
	if {$addRR == 0001} {
		# if there is an existing RR then we need to overwrite
		if {$static::debug & 2} { log local0. "found additional RR record, overwriting" }
		append packet [string range $before 0 [expr {$index+7}]] $static::AR $deviceID
	}
	else
	{
		# if we do not find an existing RR then we can append and modify the RR count
		if {$static::debug & 2} { log local0. "No additional RR record found, appending" }
		append buffer $before $static::AR $deviceID
		set packet [string replace $buffer 23 23 "1"]
	}


	if {$static::debug & 4} { log local0. "packet: $packet" }

	# Wipe the payload and write our buffer out
	UDP::payload replace 0 [UDP::payload length] " "
	UDP::payload replace 0 0 [ binary format @0H* $packet ]

	if {$static::debug & 2} {
		binary scan [UDP::payload] @0H* after
		log local0. "$log_prefix after (size=[UDP::payload length]): $after"
	}
    # Free up memory now that we have created our payload
    unset before
    unset buffer
    unset packet
}
