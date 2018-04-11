open Tezos

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

let test_sign () =
  let open Tweetnacl in
  let h = Hidapi.open_id_exn ~vendor_id:0x2C97 ~product_id:0x0001 in
  let pk = get_public_key h path in
  let msg = Cstruct.of_string "Voulez-vous coucher avec moi, ce soir ?" in
  let pk = Sign.(pk_of_cstruct_exn (Cstruct.sub pk 1 pkbytes)) in
  let signature = sign h path msg in
  assert (Sign.verify_detached ~key:pk ~signature msg) ;
  Hidapi.close h

let basic = [
  "open_close", `Quick, test_open_close ;
  "ping", `Quick, test_ping ;
  "sign", `Quick, test_sign ;
]

let () =
  Alcotest.run "ledgerwallet.tezos" [
    "basic", basic ;
  ]
