open Astring

type facility =
  | Kernel_Message
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

let int_of_facility = function
  | Kernel_Message -> 0
  | User_Level_Messages -> 1
  | Mail_System -> 2
  | System_Daemons -> 3
  | Security_Authorization_Messages -> 4
  | Messages_Generated_Internally_By_Syslogd -> 5
  | Line_Printer_Subsystem -> 6
  | Network_News_Subsystem -> 7
  | UUCP_subsystem -> 8
  | Clock_Daemon -> 9
  | Security_Authorization_Messages_10 -> 10
  | Ftp_Daemon -> 11
  | Ntp_Subsystem -> 12
  | Log_Audit -> 13
  | Log_Alert -> 14
  | Clock_Daemon_15 -> 15
  | Local0 -> 16
  | Local1 -> 17
  | Local2 -> 18
  | Local3 -> 19
  | Local4 -> 20
  | Local5 -> 21
  | Local6 -> 22
  | Local7 -> 23
  | Invalid_Facility -> failwith "Invalid_Facility"

let facility_of_int = function
  | 0  -> Kernel_Message
  | 1  -> User_Level_Messages
  | 2  -> Mail_System
  | 3  -> System_Daemons
  | 4  -> Security_Authorization_Messages
  | 5  -> Messages_Generated_Internally_By_Syslogd
  | 6  -> Line_Printer_Subsystem
  | 7  -> Network_News_Subsystem
  | 8  -> UUCP_subsystem
  | 9  -> Clock_Daemon
  | 10 -> Security_Authorization_Messages_10
  | 11 -> Ftp_Daemon
  | 12 -> Ntp_Subsystem
  | 13 -> Log_Audit
  | 14 -> Log_Alert
  | 15 -> Clock_Daemon_15
  | 16 -> Local0
  | 17 -> Local1
  | 18 -> Local2
  | 19 -> Local3
  | 20 -> Local4
  | 21 -> Local5
  | 22 -> Local6
  | 23 -> Local7
  | _  -> Invalid_Facility

let string_of_facility = function
  | Kernel_Message -> "kern"
  | User_Level_Messages -> "user"
  | Mail_System -> "mail"
  | System_Daemons -> "daemon"
  | Security_Authorization_Messages -> "security/auth"
  | Messages_Generated_Internally_By_Syslogd -> "syslog"
  | Line_Printer_Subsystem -> "lpr"
  | Network_News_Subsystem -> "news"
  | UUCP_subsystem -> "uucp"
  | Clock_Daemon -> "clock"
  | Security_Authorization_Messages_10 -> "security/auth-10"
  | Ftp_Daemon -> "ftp"
  | Ntp_Subsystem -> "ntp"
  | Log_Audit -> "log-audit"
  | Log_Alert -> "log-alert"
  | Clock_Daemon_15 -> "clock-15"
  | Local0 -> "local0"
  | Local1 -> "local1"
  | Local2 -> "local2"
  | Local3 -> "local3"
  | Local4 -> "local4"
  | Local5 -> "local5"
  | Local6 -> "local6"
  | Local7 -> "local7"
  | Invalid_Facility -> "invalid"

type severity =
  | Emergency
  | Alert
  | Critical
  | Error
  | Warning
  | Notice
  | Informational
  | Debug
  | Invalid_Severity

let int_of_severity = function
  | Emergency -> 0
  | Alert -> 1
  | Critical -> 2
  | Error -> 3
  | Warning -> 4
  | Notice -> 5
  | Informational -> 6
  | Debug -> 7
  | Invalid_Severity -> failwith "Invalid_Severity"

let severity_of_int = function
  | 0 -> Emergency
  | 1 -> Alert
  | 2 -> Critical
  | 3 -> Error
  | 4 -> Warning
  | 5 -> Notice
  | 6 -> Informational
  | 7 -> Debug
  | _ -> Invalid_Severity

let string_of_severity = function
  | Emergency -> "emerg"
  | Alert -> "alert"
  | Critical -> "crit"
  | Error -> "err"
  | Warning -> "warning"
  | Notice -> "notice"
  | Informational -> "info"
  | Debug -> "debug"
  | Invalid_Severity -> "invalid"

type ctx = {
  timestamp    : Ptime.t;
  hostname     : string;
  set_hostname : bool
}

type t = {
  facility  : facility;
  severity  : severity;
  timestamp : Ptime.t;
  hostname  : string;
  message   : string
}

module Rfc3164_Timestamp = struct
  let int_of_month_name = function
    | "Jan" -> Some 1
    | "Feb" -> Some 2
    | "Mar" -> Some 3
    | "Apr" -> Some 4
    | "May" -> Some 5
    | "Jun" -> Some 6
    | "Jul" -> Some 7
    | "Aug" -> Some 8
    | "Sep" -> Some 9
    | "Oct" -> Some 10
    | "Nov" -> Some 11
    | "Dec" -> Some 12
    | _ -> None

  let month_name_of_int = function
    | 1  -> "Jan"
    | 2  -> "Feb"
    | 3  -> "Mar"
    | 4  -> "Apr"
    | 5  -> "May"
    | 6  -> "Jun"
    | 7  -> "Jul"
    | 8  -> "Aug"
    | 9  -> "Sep"
    | 10 -> "Oct"
    | 11 -> "Nov"
    | 12 -> "Dec"
    | _ -> failwith "Invalid month integer"

  let encode ts =
    let ((_, month, day), ((h, m, s), _)) = Ptime.to_date_time ts in
    Printf.sprintf "%s %.2i %.2i:%.2i:%.2i" (month_name_of_int month) day h m s
end

let to_string msg =
  let facility = string_of_facility msg.facility
  and severity = string_of_severity msg.severity
  and timestamp = Rfc3164_Timestamp.encode msg.timestamp
  in
  Printf.sprintf
    "Facility: %s Severity: %s Timestamp: %s Hostname: %s Message: %s\n%!"
    facility severity timestamp msg.hostname msg.message

let pp ppf msg = Format.pp_print_string ppf (to_string msg)

let encode ?(len=1024) msg =
  let facse = int_of_facility msg.facility * 8 + int_of_severity msg.severity
  and ts = Rfc3164_Timestamp.encode msg.timestamp
  in
  let msgstr = Printf.sprintf "<%d>%s %s %s" facse ts msg.hostname msg.message
  in
  if len > 0 && String.length msgstr > len then
    String.with_range ~first:0 ~len:len msgstr
  else
    msgstr

let priority_value_of_int pri =
    let facility = facility_of_int @@ pri / 8
    and severity = severity_of_int @@ pri mod 8
    in
    match facility, severity with
    | Invalid_Facility, _ -> None
    | _, Invalid_Severity -> None
    | facility, severity ->
      Some (facility, severity)

let build_timestamp ~(ctx : ctx) (mon, day, (h, m, s)) =
  let ((year, _, _), _) = Ptime.to_date_time ctx.timestamp in             
  match Rfc3164_Timestamp.int_of_month_name mon with
  | None -> None                          
  | Some mon ->                                        
    Ptime.of_date_time ((year, mon, day), ((h, m, s), 0))

module Syslog_parser = struct
  open Angstrom

  module P = struct
    let is_digit = function '0' .. '9' -> true | _ -> false

    let is_space = function ' ' -> true | _ -> false

    let is_hostname_token = function
      | 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' -> true
      | _ -> false
  end

  let digits = take_while1 P.is_digit

  let pri =
    string "<" *> lift
    (fun i -> int_of_string i |> priority_value_of_int)
    (take_while1 P.is_digit) <* string ">"
    <?> "priority"

  let month =
    string "Jan" <|>
    string "Feb" <|>
    string "Mar" <|>
    string "Apr" <|>
    string "May" <|>
    string "Jun" <|>
    string "Jul" <|>
    string "Aug" <|>
    string "Sep" <|>
    string "Oct" <|>
    string "Nov" <|>
    string "Dec" <* char ' ' <?> "month"

  let day =
    (skip_while P.is_space) *> lift int_of_string (take_while1 P.is_digit)
    <* char ' '
    <?> "day"

  let time =
    lift3 (fun hour min sec ->
      (int_of_string hour, int_of_string min, int_of_string sec))
      (digits <* char ':')
      (digits <* char ':')
      (digits <* char ' ')
      <?> "time"

  let timestamp =
    lift3 (fun month day time ->
      (month, day, time))
      month day time

  let hostname =
      (take_while1 P.is_hostname_token <* (char ' ' <|> (char ':' <* char ' ')))
      <?> "hostname"

  let create_timestamp_hostname_parser ctx =
    fun () ->
    lift4 (fun month day time hostname ->
      (build_timestamp ~ctx (month, day, time)), hostname)
      month day time hostname

  let message =
    take_while (fun _ -> true)

  let p_full (ctx : ctx) =
    fun () ->
    lift4 (fun pri timestamp hostname message ->
      (pri, (build_timestamp ~ctx timestamp), hostname, message))
      pri
      timestamp
      hostname
      message

  let p_failed_timestamp (ctx : ctx) =
    fun () ->
    lift2
      (fun pri message -> (pri, Some ctx.timestamp, ctx.hostname, message))
      pri
      message

  let p_failed_pri (ctx : ctx) =
    fun () ->
    lift
      (fun message -> (priority_value_of_int 13, Some ctx.timestamp, ctx.hostname, message))
      message

  let p (ctx : ctx) =
    p_full ctx () <|> p_failed_timestamp ctx ()
    (* Fix tests before enabling the p_faild_pri parser *)
    (* p_full ctx () <|> p_failed_timestamp ctx () <|> p_failed_pri ctx () *)
end

let decode ~ctx data =
  match String.length data with
  | l when l > 0 && l < 1025 ->
    (match Angstrom.parse_only (Syslog_parser.p ctx) (`String data) with
    | Result.Ok (pri, timestamp, hostname, message) ->
        (match pri, timestamp with
        | None, _ -> None
        | _, None -> None
        | Some (facility, severity), Some timestamp ->
          Some {facility; severity; timestamp; hostname; message})
    | Result.Error _ -> None)
  | _ -> None
