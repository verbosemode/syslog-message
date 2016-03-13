module String = Astring.String

let bind o f =
  match o with
  | None -> None
  | Some x -> f x

let (>>=) o f = bind o f

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

let string_of_timestamp ts =
  match Ptime.to_date_time ts with
  | ((_, month, day), ((hour, min, sec), _)) ->
      Printf.sprintf "%s %.2i %.2i:%.2i:%.2i" (month_name_of_int month) day hour min sec

type ctx =
  {timestamp    : Ptime.t;
   hostname     : string;
   set_hostname : bool}

let ctx_hostname ctx hostname = {ctx with hostname}

let ctx_set_hostname ctx = {ctx with set_hostname=true}

type t =
  {facility  : facility;
   severity  : severity;
   timestamp : Ptime.t;
   hostname  : string;
   message   : string}

let pp_string msg =
  let facility = string_of_facility msg.facility in
  let severity = string_of_severity msg.severity in
    Printf.sprintf "Facility: %s Severity: %s Timestamp: %s Hostname: %s Message: %s\n%!"
      facility severity (string_of_timestamp msg.timestamp) msg.hostname msg.message

let pp msg =
  print_string (pp_string msg)

let to_string ?(len=1024) msg =
  let msgstr = "<" ^ string_of_int ((int_of_facility msg.facility) * 8 +
    (int_of_severity msg.severity)) ^ ">" ^
    string_of_timestamp msg.timestamp ^ " " ^
    msg.hostname ^ " " ^
    msg.message
  in
    if len > 0
    then
      match String.length msgstr with
      | l when l > len -> String.with_range ~first:0 ~len:len msgstr
      | _ -> msgstr
    else
      msgstr

let parse_priority_value s =
  let l = String.length s in
  if String.get s 0 = '<' then
    match String.find (fun x -> x = '>') s with
    | None -> None
    | Some pri_endmarker when pri_endmarker > 4 || l <= pri_endmarker + 1 ->
      None
    | Some pri_endmarker ->
      match String.with_range ~first:1 ~len:(pri_endmarker - 1) s |> String.to_int with
      | Some priority_value ->
          let facility = facility_of_int (priority_value / 8) in
          let severity = severity_of_int (priority_value mod 8) in
          begin match facility, severity with
          | Invalid_Facility, _ -> None
          | _, Invalid_Severity -> None
          | facility, severity ->
              let data = String.with_range ~first:(pri_endmarker + 1) ~len:(l - pri_endmarker -1) s in
                Some (facility, severity, data)
          end
      | None -> None
  else
    None

let parse_timestamp_rfc3164 s year =
  let tslen = 16 in
  match String.length s with
  | l when l < tslen -> None
  | l ->
    let month = int_of_month_name (String.with_range ~first:0 ~len:3 s) in
    let day = String.with_range ~first:4 ~len:2 s |> String.trim |> String.to_int in
    let hour = String.with_range ~first:7 ~len:2 s |> String.to_int in
    let minute = String.with_range ~first:10 ~len:2 s |> String.to_int in
    let second = String.with_range ~first:13 ~len:2 s |> String.to_int in
    match month, day, hour, minute, second with
    | None, _, _, _, _ -> None
    | _, None, _, _, _ -> None
    | _, _, None, _, _ -> None
    | _, _, _, None, _ -> None
    | _, _, _, _, None -> None
    | Some month, Some day, Some hour, Some min, Some sec ->
      match Ptime.of_date_time ((year, month, day), ((hour, min, sec), 0)) with
      | Some ts ->
          let data = String.with_range ~first:tslen ~len:(l - tslen) s in
            Some (ts, data)
      | None -> None

let parse_timestamp s (ctx : ctx) =
  let year =
    match Ptime.to_date_time ctx.timestamp with
    | ((y, _, _), _) -> y
  in
  match parse_timestamp_rfc3164 s year with
  | Some (timestamp, data) -> Some (timestamp, data, ctx)
  | None ->
      let ctx = ctx_set_hostname ctx in
        Some (ctx.timestamp, s, ctx)

let parse_hostname s ctx =
  if ctx.set_hostname
  then
    Some (ctx.hostname, s)
  else
    match String.length s with
    | l when l > 1 ->
        (match String.find (fun x -> x = ' ') s with
        | Some i when i > 0 ->
              let hostname = String.with_range ~first:0 ~len:i s in
              let hostnamelen = String.length hostname in
              let data = String.with_range ~first:(i + 1) ~len:(l - i - 1) s in
                if (String.get hostname (hostnamelen - 1)) = ':'
                then
                  Some (String.with_range ~first:0 ~len:(hostnamelen - 1) hostname, data)
                else
                  Some (hostname, data)
        | _ -> None)
   | _ -> None

(* FIXME Provide default Ptime.t? Version bellow doesn't work. Option type
let parse ?(ctx={timestamp=(Ptime.of_date_time ((1970, 1, 1), ((0, 0,0), 0))); hostname="-"; set_hostname=false}) data =
*)
let parse ~ctx data =
  match String.length data with
  | l when l > 0 && l < 1025 ->
      parse_priority_value data >>= fun (facility, severity, data) ->
      parse_timestamp data ctx >>= fun (timestamp, data, ctx) ->
      parse_hostname data ctx >>= fun (hostname, data) ->
        Some {facility; severity; timestamp; hostname; message=data}
  | _ -> None
