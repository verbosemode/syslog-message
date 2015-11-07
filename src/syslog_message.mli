(** Module for parsing RFC 3164 Syslog messages *)

(** The type for Facilities *)
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

(** Convert a {!type:facility} into an integer *)
val int_of_facility : facility -> int

(** Converts an integer into a {!type:facility} *)
val facility_of_int : int -> facility

(** Converts a {!type:facility} into a string *)
val string_of_facility : facility -> string

(** The type for Severity levels *)
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

(** Converts a {!type:severity} into an integer *)
val int_of_severity : severity -> int

(** Converts an integer into a {!type:severity} *)
val severity_of_int : int -> severity

(** Converts a {!type:severity} into a string *)
val string_of_severity : severity -> string

(** The type for RFC 3164 compatible timestamps *)
type timestamp = {
  month : int;
  day : int;
  hour : int;
  minute : int;
  second : int;
}

(** [string_of_timestamp] Converts a {!type:timestamp} into a string *)
val string_of_timestamp : timestamp -> string

(** [ctx] provides additional information to the {!val:parse} function in case one of the
sub-parsers fails.
- [timestamp]: A {!type:timestamp}
- [hostname]: Hostname, IPv4 or IPv6 address of the sender. "{i -}" if unknown.
- [set_hostname]: If true, the {!val:parse} function will skip its hostname
sub-parser and use the hostname from {!type:ctx} instead.

[set_hostname] is automatically set by the timestamp sub-parser when it fails, because at this
point it is no longer possible to determine the hostname from the input string. *)
type ctx = { timestamp : timestamp; hostname : string; set_hostname : bool; }

(** [ctx_hostname] sets a new hostname in {!type:ctx} *)
val ctx_hostname : ctx -> string -> ctx

(** [ctx_set_hostname] *)
val ctx_set_hostname : ctx -> ctx

(** The type for Syslog messages *)
type t = {
  facility : facility;
  severity : severity;
  timestamp : timestamp;
  hostname : string;
  message : string;
}

(** [pp_string] returns a pretty-printed string of {!type:t} *)
val pp_string : t -> string

(** [pp] pretty-prints a {!type:t} using print_string *)
val pp : t -> unit

(** [parse]s a string containing a Syslog message and returns an option {!type:t} *)
val parse : ?ctx:ctx -> string -> t option

(** [to_string] returns a Syslog message of type {!type:t} as string.
The output string is truncated to 1024 bytes, which is the default of [len].
Setting [len] to 0, leaves the output string unmodified. *)
val to_string : ?len:int -> t -> string
