open Ledgerwallet_ssh_agent

let test_open_close () =
  let h = Hidapi.open_id_exn ~vendor_id:0x2C97 ~product_id:0x0001 in
  Hidapi.close h

let test_ping () =
  let h = Hidapi.open_id_exn ~vendor_id:0x2C97 ~product_id:0x0001 in
  Ledgerwallet.Transport.ping h ;
  Hidapi.close h

let hard x =
  Int32.logor x 0x8000_0000l

let path = [
  hard 44l ; hard 535348l
]

let test_get_public_key () =
  let h = Hidapi.open_id_exn ~vendor_id:0x2C97 ~product_id:0x0001 in
  let pk_prime = get_public_key h ~curve:Prime256v1 ~path in
  let pk_curve = get_public_key h ~curve:Curve25519 ~path in
  Format.printf "Uncompressed prime256v1 public key %a@." Hex.pp (Hex.of_cstruct pk_prime) ;
  Format.printf "Uncompressed curve25519 public key %a@." Hex.pp (Hex.of_cstruct pk_curve) ;
  Hidapi.close h

let basic = [
  "open_close", `Quick, test_open_close ;
  "ping", `Quick, test_ping ;
  "get_public_key", `Quick, test_get_public_key ;
]

let () =
  Alcotest.run "ledgerwallet.ssh-agent" [
    "basic", basic ;
  ]
