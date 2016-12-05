open Syslog_message

module QCheck_legacy = struct
(* I've copied this code over from QCheck 0.4 to preserve the way, strings are
 * generated.
 *
 * Copyright (c) 2013, Simon Cruanes
 * All rights reserved.
 *
 * License (BSD): https://github.com/c-cube/qcheck/blob/6e002d5b3afbb32e364b5fa4b7e3f6e32b8d0dde/LICENSE
 * Source: https://github.com/c-cube/qcheck/blob/6e002d5b3afbb32e364b5fa4b7e3f6e32b8d0dde/qCheck.ml *)
  let alpha st =
    Char.chr (Char.code 'a' + Random.State.int st (Char.code 'z' - Char.code 'a'))

  let string_len len st =
    let n = len st in
    assert (n>=0);
    let b = Buffer.create n in
    for _i = 0 to n-1 do
      Buffer.add_char b (alpha st)
    done;
    Buffer.contents b

  let string_g =
    QCheck.Gen.string_size ~gen:alpha (QCheck.Gen.int_range 0 10)

  let string =
    QCheck.(string_gen_of_size (QCheck.Gen.int_range 0 10) alpha)
end

(* 8 severities * 23 facilities *)
let priority = QCheck.int_bound 184
let priority_g = QCheck.Gen.int_bound 184

let ptime_g =
  let open QCheck.Gen in
  int_bound (int_of_float @@ 2. ** 29.)
  >|= fun n ->
    n
    |> Ptime.Span.of_int_s
    |> Ptime.of_span

let pp_ptime = function
  | None -> "<None>"
  | Some pt -> Rfc3164_Timestamp.encode pt

let ptime = QCheck.make ~print:pp_ptime ptime_g

let valid_data_succeeds =
  let open QCheck in
  Test.make ~count:100
  ~name:"generating valid data gets a reasonable result"
  (triple priority ptime QCheck_legacy.string)
  @@ fun (pri, pt, host) ->
    (pt <> None) ==>
    let ctx = { timestamp = Ptime.epoch; hostname = ""; set_hostname = false } in
    match pt with
    | None -> false
    | Some pt ->
      let msg =
        Printf.sprintf "<%d>%s %s: Whatever" pri (Rfc3164_Timestamp.encode pt) host
      in
      match decode ctx msg with
      | None -> false
      | Some parsed ->
        let ((_, m, d), ((hh, mm, ss), _)) = Ptime.to_date_time parsed.timestamp in
        let ((_, m', d'), ((hh', mm', ss'), _)) = Ptime.to_date_time pt in
        m = m' && d = d' && hh = hh' && mm = mm' && ss = ss' &&
        parsed.hostname = host

let invalid_timestamp =
  let open QCheck in
  let pp = Print.(quad int pp_ptime string string) in
  Test.make ~count:100
  ~name:"parser substitutes the timestamp when it can't be parsed"
  (make ~print:pp Gen.(quad priority_g ptime_g QCheck_legacy.string_g
    QCheck_legacy.string_g))
  @@ fun (pri, valid, invalid, host) ->
    (valid <> None) ==>
    match valid with
    | None -> false
    | Some valid ->
      let msg =
        Printf.sprintf "<%d>%s %s: Whatever" pri invalid host
      in
      let ctx = { timestamp = valid; hostname = ""; set_hostname = false } in
      match decode ctx msg with
      | None -> false
      | Some parsed -> parsed.timestamp = valid

let invalid_data_fails =
  QCheck.Test.make ~count:100
  ~name:"putting in invalid data always fails"
  QCheck.string
  @@ fun msg ->
    let ctx = { timestamp = Ptime.epoch; hostname = ""; set_hostname = false } in
    decode ctx msg = None

let () =
  let suite = [invalid_data_fails; valid_data_succeeds; invalid_timestamp] in
  QCheck_runner.run_tests_main suite
