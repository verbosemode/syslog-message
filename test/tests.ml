open Syslog_message.Rfc_5424

(* [mirageOsPowerSupply@49836 status="ok" name="Camelus Dromedarius"] *)
let test1 () =
  let sd_id1 = Sd_id.create "mirageOsPowerSupply" "49836" in
  let sd_elt1 = Sd_element.create sd_id1 in

  let sd_param = Sd_param.create "name" (`Utf8 "Camelus Dromedarius") in
  let sd_elt1 = Sd_element.add sd_param sd_elt1 in
  let sd_param = Sd_param.create "status" (`Utf8 "ok") in
  let sd_elt1 = Sd_element.add sd_param sd_elt1 in

  let sd = Structured_data.add sd_elt1 (Structured_data.empty) in

  (* let syslogmsg = { *)
  (*   facility=Syslog_message.Local0; *)
  (*   severity=Syslog_message.Notice; *)
  (*   version=1; *)
  (*   timestamp= *)
  (*     (match Ptime.of_date_time ((2017, 1, 1), ((1, 1, 1), 0)) with *)
  (*     | None -> assert false *)
  (*     | Some t -> Some t *)
  (*     ); *)
  (*   hostname=Some "alepale"; *)
  (*   app_name=None; *)
  (*   procid=Some "42"; *)
  (*   msgid=None; *)
  (*   structured_data=Some sd; *)
  (*   msg=`Ascii "test message"; *)
  (* } *)
  (* in *)
  (* encode syslogmsg *)

  let timestamp = Ptime.of_date_time ((2017, 1, 1), ((1, 1, 1), 0)) in
  let open Syslog_message in
    create ~facility:Local0 ~severity:Notice
      ~timestamp ~hostname:(Some "alepale") ~procid:(Some "42")
      ~structured_data:(Some sd) (`Ascii "test message")

let test1_result =
  "<133>1 2017-01-01T01:01:01Z alepale - 42 - [mirageOsPowerSupply@49836 \
  status=\"ok\" name=\"Camelus Dromedarius\"] test message"

let test_message () =
  Alcotest.(check string) "Message encoding" test1_result (test1 ())

let test_set = [
  "Example message", `Quick, test_message;
]

let () =
  Alcotest.run "Running even more tests" [
    "test_set", test_set;
  ]
