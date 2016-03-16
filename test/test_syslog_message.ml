module Smsg = Syslog_message

(* 8 severities * 23 facilities *)
let priority = QCheck.Arbitrary.int 184

let ptime =
  let open QCheck.Arbitrary in
  int (int_of_float @@ 2. ** 29.)
  >|= fun n ->
    n
    |> Ptime.Span.of_int_s
    |> Ptime.of_span

let hostname = QCheck.Arbitrary.string

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

let string_of_ptime pt =
  let ((_, m, d), ((hh, mm, ss), _)) = Ptime.to_date_time pt in
  Printf.sprintf "%s %2d %02d:%02d:%02d"
    (month_name_of_int m) d hh mm ss

let pp_ptime = function
  | None -> "<None>"
  | Some pt -> string_of_ptime pt

let valid_data_succeeds = QCheck.mk_test ~n:100
  ~name:"generating valid data gets a reasonable result"
  ~pp:QCheck.PP.(triple int pp_ptime string)
  QCheck.Arbitrary.(triple priority ptime hostname)
  @@ fun (pri, pt, host) ->
    QCheck.Prop.assume (pt <> None);
    let ctx = Smsg.{timestamp=Ptime.epoch;
                    hostname="";
                    set_hostname=false} in
    match pt with
    | None -> false
    | Some pt ->
      let msg = Printf.sprintf "<%d>%s %s: Whatever"
        pri (string_of_ptime pt) host in
      match Smsg.parse ctx msg with
      | None -> false
      | Some parsed ->
        let ((_, m, d), ((hh, mm, ss), _)) =
          Ptime.to_date_time parsed.Smsg.timestamp in
        let ((_, m', d'), ((hh', mm', ss'), _)) =
          Ptime.to_date_time pt in
        m = m' && d = d' && hh = hh' && mm = mm' && ss = ss' &&
        parsed.Smsg.hostname = host

let invalid_timestamp = QCheck.mk_test ~n:100
  ~name:"parser substitutes the timestamp when it can't be parsed"
  ~pp:QCheck.PP.(quad int pp_ptime string string)
  QCheck.Arbitrary.(quad priority ptime string hostname)
  @@ fun (pri, valid, invalid, host) ->
    QCheck.Prop.assume (valid <> None);
    match valid with
    | None -> false
    | Some valid ->
      let msg = Printf.sprintf "<%d>%s %s: Whatever"
        pri invalid host in
      let ctx = Smsg.{timestamp=valid;
                      hostname="";
                      set_hostname=false} in
      match Smsg.parse ctx msg with
      | None -> false
      | Some parsed ->
        Smsg.(parsed.timestamp = valid)

let invalid_data_fails = QCheck.mk_test ~n:100
  ~name:"putting in invalid data always fails"
  QCheck.Arbitrary.string
  @@ fun msg ->
    let ctx = Smsg.{timestamp=Ptime.epoch;
                    hostname="";
                    set_hostname=false} in
    Smsg.parse ctx msg = None

let () =
  let suite = [invalid_data_fails; valid_data_succeeds;
               invalid_timestamp] in
  if not (QCheck.run_tests suite) then exit 1 else ()
