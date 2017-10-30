open Ledgerwallet

let rawTx = `Hex "0100000002ba0eb35fa910ccd759ff46b5233663e96017e8dfaedd315407dc5be45d8c260f000000001976a9146ce472b3cfced15a7d50b6b0cd75a3b042554e8e88acfdffffff69c84956a9cc0ec5986091e1ab229e1a7ea6f4813beb367c01c8ccc708e160cc000000001976a9146ce472b3cfced15a7d50b6b0cd75a3b042554e8e88acfdffffff01a17c0100000000001976a914efd0919fc05311850a8382b9c7e80abcd347343288ac00000000"

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
  Printf.printf "Address %s\n" pk.b58addr ;
  let `Hex chaincode = Hex.of_string pk.bip32_chaincode in
  Printf.printf "Chaincode %s\n" chaincode ;
  let rawTx = Cstruct.of_string (Hex.to_string rawTx) in
  let tx, _ = Bitcoin__Protocol.Transaction.of_cstruct rawTx in
  let `Hex ti = Hex.of_cstruct (get_trusted_input h tx 0) in
  Printf.printf "Trusted input %s\n" ti

let () = main ()
