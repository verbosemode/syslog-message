val int_of_day_string : string -> int option
val int_of_month_name : string -> int option
val month_name_of_int : int -> string option
type facility =
    Kernel_Message
  | User_Level_Messages
  | Mail_System
  | System_Daemons
  | Security_Authorization_Messages
  | Messages_Generated_Internally_By_Syslogd
  | Line_Printer_Subsystem
  | Network_News_Subsystem
  | UUCP_subsystem
  | Clock_Daemon
  | Security_Authorization_Messages_10
  | Ftp_Daemon
  | Ntp_Subsystem
  | Log_Audit
  | Log_Alert
  | Clock_Daemon_15
  | Local0
  | Local1
  | Local2
  | Local3
  | Local4
  | Local5
  | Local6
  | Local7
  | Invalid_Facility
val int_of_facility : facility -> int
val facility_of_int : int -> facility
val string_of_facility : facility -> string
type severity =
    Emergency
  | Alert
  | Critical
  | Error
  | Warning
  | Notice
  | Informational
  | Debug
  | Invalid_Severity
val int_of_severity : severity -> int
val severity_of_int : int -> severity
val string_of_severity : severity -> string
type timestamp = {
  month : int;
  day : int;
  hour : int;
  minute : int;
  second : int;
}
val string_of_timestamp : timestamp -> string
type message = {
  facility : facility;
  severity : severity;
  timestamp : timestamp;
  hostname : string;
  message : string;
}
val pp_string : message -> string
val pp : message -> unit
type ctx = { timestamp : timestamp; hostname : string; set_hostname : bool; }
val ctx_hostname : ctx -> string -> ctx
val ctx_set_hostname : ctx -> ctx
val parse : ?ctx:ctx -> string -> message option
