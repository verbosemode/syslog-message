# Syslog Message

This is a parser for [RFC 3164](https://tools.ietf.org/html/rfc3164) Syslog messages.

    # Syslog_message.parse "<133>Oct  3 15:51:21 server001: foobar";;
    - : Syslog_message.message option =
          Some {Syslog_message.facility = Syslog_message.Local0;
	          severity = Syslog_message.Notice; timestamp = {Syslog_message.month = 10;
		  day = 3; hour = 15; minute = 51; second = 21}; hostname = "server001";
		  message = "foobar"}
