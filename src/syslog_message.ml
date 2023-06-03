let ( let* ) = Result.bind

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

let facility_of_int = function
  | 0  -> Some Kernel_Message
  | 1  -> Some User_Level_Messages
  | 2  -> Some Mail_System
  | 3  -> Some System_Daemons
  | 4  -> Some Security_Authorization_Messages
  | 5  -> Some Messages_Generated_Internally_By_Syslogd
  | 6  -> Some Line_Printer_Subsystem
  | 7  -> Some Network_News_Subsystem
  | 8  -> Some UUCP_subsystem
  | 9  -> Some Clock_Daemon
  | 10 -> Some Security_Authorization_Messages_10
  | 11 -> Some Ftp_Daemon
  | 12 -> Some Ntp_Subsystem
  | 13 -> Some Log_Audit
  | 14 -> Some Log_Alert
  | 15 -> Some Clock_Daemon_15
  | 16 -> Some Local0
  | 17 -> Some Local1
  | 18 -> Some Local2
  | 19 -> Some Local3
  | 20 -> Some Local4
  | 21 -> Some Local5
  | 22 -> Some Local6
  | 23 -> Some Local7
  | _  -> None

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

let pp_print_facility ppf f =
  Format.fprintf ppf "%s" (string_of_facility f)

type severity =
  | Emergency
  | Alert
  | Critical
  | Error
  | Warning
  | Notice
  | Informational
  | Debug

let int_of_severity = function
  | Emergency -> 0
  | Alert -> 1
  | Critical -> 2
  | Error -> 3
  | Warning -> 4
  | Notice -> 5
  | Informational -> 6
  | Debug -> 7

let severity_of_int = function
  | 0 -> Some Emergency
  | 1 -> Some Alert
  | 2 -> Some Critical
  | 3 -> Some Error
  | 4 -> Some Warning
  | 5 -> Some Notice
  | 6 -> Some Informational
  | 7 -> Some Debug
  | _ -> None

let string_of_severity = function
  | Emergency -> "emerg"
  | Alert -> "alert"
  | Critical -> "crit"
  | Error -> "err"
  | Warning -> "warning"
  | Notice -> "notice"
  | Informational -> "info"
  | Debug -> "debug"

let pp_print_severity ppf s =
  Format.fprintf ppf "%s" (string_of_severity s)

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
  tag       : string;
  content   : string
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

  let decode s year : (Ptime.t * string, [> `Msg of string ]) result =
    let tslen = 16 in
    match String.length s with
    | l when l < tslen ->
      Error (`Msg "timestamp too short, must be at least 16 bytes")
    | l ->
      let month = int_of_month_name @@ String.sub s 0 3 in
      let day = String.sub s 4 2 |> String.trim |> int_of_string_opt in
      let hour = String.sub s 7 2 |> int_of_string_opt in
      let minute = String.sub s 10 2 |> int_of_string_opt in
      let second = String.sub s 13 2 |> int_of_string_opt in
      match month, day, hour, minute, second with
      | None, _, _, _, _ -> Error (`Msg "couldn't decode month in timestamp")
      | _, None, _, _, _ -> Error (`Msg "couldn't decode day in timestamp")
      | _, _, None, _, _ -> Error (`Msg "couldn't decode hours in timestamp")
      | _, _, _, None, _ -> Error (`Msg "couldn't decode minutes in timestamp")
      | _, _, _, _, None -> Error (`Msg "couldn't decode seconds in timestamp")
      | Some month, Some day, Some hour, Some min, Some sec ->
        match Ptime.of_date_time ((year, month, day), ((hour, min, sec), 0)) with
        | None -> Error (`Msg "couldn't transform timestamp to ptime.t")
        | Some ts -> Ok (ts, String.sub s tslen (l - tslen))
end

let to_string msg =
  let facility = string_of_facility msg.facility
  and severity = string_of_severity msg.severity
  and timestamp = Rfc3164_Timestamp.encode msg.timestamp
  in
  Printf.sprintf
    "Facility: %s Severity: %s Timestamp: %s Hostname: %s Tag: %s Content: %s\n%!"
    facility severity timestamp msg.hostname msg.tag msg.content

let pp ppf msg = Format.pp_print_string ppf (to_string msg)

let encode_gen encode ?len msg =
  let facse = int_of_facility msg.facility * 8 + int_of_severity msg.severity
  and ts = Rfc3164_Timestamp.encode msg.timestamp
  in
  let msgstr = encode facse ts msg.hostname msg.tag msg.content
  in
  match len with
  | None -> msgstr
  | Some max_len ->
    if String.length msgstr > max_len then
      String.sub msgstr 0 max_len
    else
      msgstr

let is_alphanum = function
  | '0' .. '9' | 'A' .. 'Z' | 'a' .. 'z' -> true
  | _ -> false

let separator s =
  match String.get s 0 with
  | exception Invalid_argument _ -> " "
  | c when not (is_alphanum c) -> ""
  | _ -> " "

let encode ?len msg =
  let encode facse ts hostname tag content =
    Printf.sprintf "<%d>%s %s %s%s%s" facse ts hostname tag
      (separator content) content
  in
  encode_gen encode ?len msg

let encode_local ?len msg =
  let encode facse ts _ tag content =
    Printf.sprintf "<%d>%s %s%s%s" facse ts tag (separator content) content
  in
  encode_gen encode ?len msg

let parse_priority_value s :
  (facility * severity * string, [> `Msg of string ]) result =
  match String.split_on_char '<' s with
  | "" :: datas ->
    begin
      let data = String.concat "<" datas in
      match String.split_on_char '>' data with
      | pri :: datas ->
        begin
          let data = String.concat ">" datas in
          if String.length pri > 3 then
            Error (`Msg "couldn't parse priority: expected '>' earlier")
          else
            (* TODO RFC 3164 4.1.1 requires decimal, String.to_int accepts "0x1" *)
            match int_of_string_opt pri with
            | None -> Error (`Msg "couldn't parse priority: not an integer")
            | Some priority_value ->
              let facility = facility_of_int @@ priority_value / 8
              and severity = severity_of_int @@ priority_value mod 8
              in
              match facility, severity with
              | None, _ -> Error (`Msg "invalid facility")
              | _, None -> Error (`Msg "invalid severity")
              | Some facility, Some severity -> Ok (facility, severity, data)
        end
      | _ -> Error (`Msg "couldn't parse priority: no '>' found")
    end
  | _ -> Error (`Msg "couldn't parse priority: expected '<'")

let parse_hostname s (ctx : ctx) : (string * string, [> `Msg of string ]) result =
  if ctx.set_hostname then
    Ok (ctx.hostname, s)
  else
    match String.split_on_char ' ' s with
    | host :: datas ->
      let data = String.concat " " datas in
      let* hostname =
        match String.split_on_char ':' host with
        | [ "" ] -> Error (`Msg "invalid or empty hostname")
        | [ host ]
        | [ host ; "" ] -> Ok host
        | _ -> Error (`Msg "invalid empty hostname")
      in
      Ok (hostname, data)
    | _ -> Error (`Msg "invalid or empty hostname")

let parse_timestamp s (ctx : ctx) =
  let ((year, _, _), _) = Ptime.to_date_time ctx.timestamp in
  match Rfc3164_Timestamp.decode s year with
  | Ok (timestamp, data) -> Ok (timestamp, data, ctx)
  | Error _ ->
    let ctx = { ctx with set_hostname = true } in
    Ok (ctx.timestamp, s, ctx)

let parse_tag s : (string * string, [> `Msg of string ]) result =
  let rec collect s len idx =
    if idx > 32 then
      Result.Error (`Msg "tag exceeds 32 characters")
    else if idx >= len then
      Ok (s, "")
    else if is_alphanum (String.get s idx) then
      collect s len (idx + 1)
    else
      Ok (String.sub s 0 idx, String.sub s idx (len - idx))
  in
  collect s (String.length s) 0

(* FIXME Provide default Ptime.t? Version bellow doesn't work. Option type
let parse ?(ctx={timestamp=(Ptime.of_date_time ((1970, 1, 1), ((0, 0,0), 0))); hostname="-"; set_hostname=false}) data =
*)
let decode ~ctx data : (t, [> `Msg of string ]) result =
  let* facility, severity, data = parse_priority_value data in
  let* timestamp, data, ctx = parse_timestamp data ctx in
  let* hostname, data = parse_hostname data ctx in
  let* tag, content = parse_tag data in
  Ok { facility; severity; timestamp; hostname; tag; content }
