#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  Pkg.describe "syslog-message" @@ fun _ ->
  Ok [
    Pkg.mllib "src/syslog-message.mllib";
    Pkg.test "test/test_syslog_message"
  ]
