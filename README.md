# Syslog Message

This is a parser for [RFC 3164](https://tools.ietf.org/html/rfc3164) Syslog messages.


    # let ctx = {Syslog_Message.hostname=srcip; timestamp="Jan  1 00:00:00"; set_hostname=false};;
    # Syslog_message.parse ~ctx "<133>Oct  3 15:51:21 server001: foobar"
    - : Syslog_message.message option =
	  Some
	    {Syslog_message.facility = Syslog_message.Local0; severity = Syslog_message.Notice;
	     timestamp = {Syslog_message.month = 10; day = 13; hour = 15; minute = 51; second = 21};
	     hostname = "server001"; message = "foobar"}
