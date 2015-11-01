let bind o f =
  match o with
  | None -> None
  | Some x -> f x

let (>>=) o f = bind o f

let is_intchar = function
  | '0' .. '9' -> true
  | _ -> false

(* Verify if all chars are valid integers *)
let all_intchars b =
  Astring.String.fold_left
    (fun a c -> if (is_intchar c) && a = true then true else false)
    true b

let int_of_day_bytes b =
  let chars = Astring.String.trim ~drop:(fun c -> c = ' ' || false) b in
    if all_intchars chars
    then
      let i = int_of_string chars in
        if i > 0 && i < 32
        then Some i
        else None
    else None

(* Apply validation function prior to converting a string into an int *)
let valid_int_of_bytes b f =
  if all_intchars b
  then
    let i = int_of_string b in
      if (f i)
      then Some i
      else None
  else
    None

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
  | 1  -> Some "Jan"
  | 2  -> Some "Feb"
  | 3  -> Some "Mar"
  | 4  -> Some "Apr"
  | 5  -> Some "May"
  | 6  -> Some "Jun"
  | 7  -> Some "Jul"
  | 8  -> Some "Aug"
  | 9  -> Some "Sep"
  | 10 -> Some "Oct"
  | 11 -> Some "Nov"
  | 12 -> Some "Dec"
  | _ -> None

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

let bytes_of_facility = function
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

let bytes_of_severity = function
  | Emergency -> "emerg"
  | Alert -> "alert"
  | Critical -> "crit"
  | Error -> "err"
  | Warning -> "warning"
  | Notice -> "notice"
  | Informational -> "info"
  | Debug -> "debug"
  | Invalid_Severity -> "invalid"

type timestamp =
  {month  : int;
   day    : int;
   hour   : int;
   minute : int;
   second : int}

let bytes_of_timestamp ts =
  Printf.sprintf "%.2i %.2i %.2i:%.2i:%.2i" ts.month ts.day ts.hour ts.minute
    ts.second

type message =
  {facility  : facility;
   severity  : severity;
   timestamp : timestamp;
   hostname  : bytes;
   message   : bytes}

let pp_bytes msg =
  let facility = bytes_of_facility msg.facility in
  let severity = bytes_of_severity msg.severity in
    Printf.sprintf "Facility: %s Severity: %s Timestamp: %s Hostname: %s Message: %s\n%!"
      facility severity (bytes_of_timestamp msg.timestamp) msg.hostname msg.message

let pp msg =
  print_string (pp_bytes msg)

type ctx =
  {timestamp    : timestamp;
   hostname     : bytes;
   set_hostname : bool}

let ctx_hostname ctx hostname = {ctx with hostname}
let ctx_set_hostname ctx = {ctx with set_hostname=true}

let parse_priority_value b =
  let l = Bytes.length b in
    if l > 0 && l < 1025 && (Bytes.get b 0) = '<' then
      match Astring.String.find (fun x -> x = '>') b with
        Some pri_endmarker ->
          if pri_endmarker > 4 || l <= pri_endmarker + 1
          then None
          else
            let priority_value_bytes = Bytes.sub b 1 (pri_endmarker - 1) in
              if all_intchars priority_value_bytes
              then
                let priority_value = int_of_string priority_value_bytes in
                let facility = facility_of_int (priority_value / 8) in
                let severity = severity_of_int (priority_value mod 8) in 
                  begin match facility, severity with
                  | Invalid_Facility, _ -> None
                  | _, Invalid_Severity -> None
                  | facility, severity ->
                      let data = Bytes.sub b (pri_endmarker + 1) (l - pri_endmarker -1) in
                        Some (facility, severity, data)
                  end
              else None
      | None -> None
    else
      None

let parse_timestamp_rfc3164 b =
  let tslen = 16 in
  let l = Bytes.length b in
    if l < tslen
    then None
    else 
      let month = int_of_month_name (Bytes.sub b 0 3) in
      let day = valid_int_of_bytes
        (Astring.String.trim ~drop:(fun c -> c = ' ' || false) (Bytes.sub b 4 2))
        (fun i -> if (i > 0 && i < 32) then true else false) in
      let hour = valid_int_of_bytes (Bytes.sub b 7 2)
        (fun i -> if (i > 0 && i < 24) then true else false) in
      let minute = valid_int_of_bytes (Bytes.sub b 10 2)
        (fun i -> if (i > 0 && i < 59) then true else false) in
      let second = valid_int_of_bytes (Bytes.sub b 13 2)
        (fun i -> if (i > 0 && i < 59) then true else false) in
      match month, day, hour, minute, second with
        None, _, _, _, _
      | _, None, _, _, _ -> None
      | _, _, None, _, _ -> None
      | _, _, _, None, _ -> None
      | _, _, _, _, None -> None
      | Some month, Some day, Some hour, Some minute, Some second ->
        let ts =  {month; day; hour; minute; second} in
        let data = Bytes.sub b tslen (l - tslen) in
          Some (ts, data)

let parse_timestamp b ctx =
  match (parse_timestamp_rfc3164 b) with
    Some (timestamp, data) -> Some (timestamp, data, ctx)
  | None ->
      let ctx = ctx_set_hostname ctx in
        Some (ctx.timestamp, b, ctx)

let parse_hostname b ctx =
  if ctx.set_hostname
  then
    Some (ctx.hostname, b)
  else
    let l = Bytes.length b in
      if l > 3 then
        match Astring.String.find (fun x -> x = ' ') b with
          None -> None
        | Some i ->
            if i > 0
            then
              let hostname = Bytes.sub b 0 i in
              let hostnamelen = Bytes.length hostname in
              let data = Bytes.sub b (i + 1) (l - i - 1) in
                if (Bytes.get hostname (hostnamelen - 1)) = ':'
                then
                  Some (Bytes.sub hostname 0 (hostnamelen - 1), data)
                else
                  Some (hostname, data)

            else None
      else
        None

let parse ?(ctx={timestamp={month=1; day=1; hour=0; minute=0; second=0}; hostname="-"; set_hostname=false}) data =
  parse_priority_value data >>= fun (facility, severity, data) ->
  parse_timestamp data ctx >>= fun (timestamp, data, ctx) ->
  parse_hostname data ctx >>= fun (hostname, data) ->
    Some {facility; severity; timestamp; hostname; message=data}
