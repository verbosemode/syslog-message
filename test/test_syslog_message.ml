module Smsg = Syslog_message

let priority = QCheck.Arbitrary.int 256

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
  ~name:"Check that generating valid data gets a reasonable result"
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
      let msg = Printf.sprintf "<%d> %s %s: Whatever"
        pri (string_of_ptime pt) host in
      match Smsg.parse ctx msg with
      | None -> false
      | Some parsed ->
        parsed.Smsg.hostname = host

let invalid_data_fails = QCheck.mk_test ~n:100
  ~name:"Check that putting in invalid data always fails"
  QCheck.Arbitrary.(string)
  @@ fun msg ->
    let ctx = Smsg.{timestamp=Ptime.epoch;
                    hostname="";
                    set_hostname=false} in
    Smsg.parse ctx msg = None

let () =
  let suite = [invalid_data_fails; valid_data_succeeds] in
  if not (QCheck.run_tests suite) then exit 1 else ()
