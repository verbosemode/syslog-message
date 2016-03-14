let () =
  let suite = [] in
  ignore @@ QCheck.run_tests suite
