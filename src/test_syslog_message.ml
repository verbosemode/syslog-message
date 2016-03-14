module Smsg = Syslog_message

let invalid_data_fails = QCheck.mk_test ~n:100
  ~name:"Check that putting in invalid data always fails"
  QCheck.Arbitrary.(string)
  @@ fun msg ->
    let ctx = {Smsg.timestamp=Ptime.epoch;
               Smsg.hostname="";
               Smsg.set_hostname=false} in
    Smsg.parse ctx msg = None

let () =
  let suite = [invalid_data_fails] in
  ignore @@ QCheck.run_tests suite
