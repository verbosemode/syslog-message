(** Syslog message parser and unparser

    [Syslog-message] is a module for handling syslog messages, as defined in
    {{:https://tools.ietf.org/html/rfc3164}RFC 3164}.

    The {!parse} function transforms a string to a syslog message {!t}, using a
    {{!ctx}context} of default parameters.  Such a message can be transformed
    into a string {!to_string} or pretty printed {!pp_string}, {!pp}.

    {e %%VERSION%% - {{:%%PKG_HOMEPAGE%% }homepage}} *)

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

(** [string_of_facility f] is [data], the string representation of [f]. *)
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

(** [string_of_severity s] is [data], the string representation of [s]. *)
val string_of_severity : severity -> string

(** [ctx] provides additional information to the {!val:parse} function in case one of the
sub-parsers fails.
- [timestamp]: A {!type:timestamp}
- [hostname]: Hostname, IPv4 or IPv6 address of the sender. "{i -}" if unknown.
- [set_hostname]: If true, the {!val:parse} function will skip its hostname
sub-parser and use the hostname from {!type:ctx} instead.

[set_hostname] is automatically set by the timestamp sub-parser when it fails, because at this
point it is no longer possible to determine the hostname from the input string. *)
type ctx = {
  timestamp : Ptime.t;
  hostname : string;
  set_hostname : bool;
}

(** The type for Syslog messages *)
type t = {
  facility : facility;
  severity : severity;
  timestamp : Ptime.t;
  hostname : string;
  tag : string;
  content : string;
}

(** [pp ppf t] prints the syslog message [t] on [ppf]. *)
val pp : Format.formatter -> t -> unit

(** [to_string t] is [str], a pretty printed string of syslog message [t]. *)
val to_string : t -> string

(** [decode ~ctx data] is [t], either [Ok t], a successfully decoded
    syslog message, or [Error e]. *)
val decode : ctx:ctx -> string -> (t, [> Rresult.R.msg ]) result

(** [encode ~len t] is [data], the encoded syslog message [t], truncated to
    [len] bytes. If [len] is 0 the output is not truncated.

    {e Warning:} Since version 0.0.3, messages are no longer truncated to 1024
    bytes by default. *)
val encode : ?len:int -> t -> string

(** [encode_local ~len t] behaves as {!encode} except that the message is
    formatted for sending to the local syslog daemon (e.g. on [/dev/log]). *)
val encode_local : ?len:int -> t -> string

(** RFC 3164 Timestamps *)
module Rfc3164_Timestamp : sig

  (** [encode t] is [data], a timestamp in the presentation of RFC 3164.  *)
  val encode : Ptime.t -> string

  (** [decode data year] is [Ok (timestamp, leftover)], the decoded RFC 3164
      timestamp and superfluous bytes, or [Error e] on parse failure.  *)
  val decode : string -> int -> (Ptime.t * string, [> Rresult.R.msg ]) result
end
