open Ledgerwallet

let main () =
  let h = Hidapi.hid_open ~vendor_id:0x2581 ~product_id:0x3B7C in
  Ledgerwallet.ping h ;
  begin match verify_pin h "0000" with
  | `Ok -> Printf.printf "Pin OK\n"
  | `Need_power_cycle -> Printf.printf "Pin need power cycle\n"
  end ;
  Printf.printf "%d pin attemps possible\n" (get_remaining_pin_attempts h) ;
  let firmware_version = get_firmware_version h in
  Printf.printf "Firmware: %s\n"
    (Sexplib.Sexp.to_string_hum (Firmware_version.sexp_of_t firmware_version)) ;
  let op_mode = get_operation_mode h in
  Printf.printf "Operation mode: %s\n"
    (Sexplib.Sexp.to_string_hum (Operation_mode.sexp_of_t op_mode)) ;
  let second_factor = get_second_factor h in
  Printf.printf "Second factor: %s\n"
    (Sexplib.Sexp.to_string_hum (Second_factor.sexp_of_t second_factor)) ;
  let random_str = Ledgerwallet.get_random h 200 in
  Printf.printf "%d %S\n" (String.length random_str) random_str ;
  let pk =  get_wallet_pubkeys h Bitcoin.Util.KeyPath.[H 44l; H 1l; H 0l; N 0l; N 0l] in
  let `Hex uncomp = Hex.of_string pk.uncompressed in
  Printf.printf "Uncompressed public key %s\n" uncomp ;
  Printf.printf "Adderss %s\n" pk.b58addr ;
  let `Hex chaincode = Hex.of_string pk.bip32_chaincode in
  Printf.printf "Chaincode %s\n" chaincode

let () = main ()
