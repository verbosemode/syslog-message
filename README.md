# Syslog Message

This is a parser for [RFC 3164](https://tools.ietf.org/html/rfc3164) Syslog messages.

[![docs](https://img.shields.io/badge/doc-online-blue.svg)](http://verbosemo.de/syslog-message/)

	match Ptime.of_date_time ((1970, 1, 1), ((0, 0, 0), 0)) with
	| Some ts -> Syslog_message.parse ~ctx:{timestamp=ts; hostname="-"; set_hostname=false} "<133>Oct  3 15:51:21 server001: foobar"
	| None -> failwith "Failed to parse Syslog message";;
	- : Syslog_message.t option =
	Some {Syslog_message.facility = Syslog_message.Local0; severity = Syslog_message.Notice; timestamp = <abstr>;
	  hostname = "server001"; message = "foobar"}
