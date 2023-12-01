open Ledgerwallet_tezos
open Lwt_result.Infix

let return_unit = Lwt.return_ok ()

let vendor_id = 0x2C97

let product_id = 0x0001

let fail_on_error x =
  Lwt.bind x (function
      | None -> Alcotest.fail "Found no ledger."
      | Some (Ok ()) -> Lwt.return_unit
      | Some (Error e) ->
          Alcotest.fail
            (Format.asprintf
               "Ledger error: %a"
               Ledgerwallet.Transport.pp_error
               e))

let with_connection f =
  fail_on_error
    (Ledgerwallet.Transport.with_connection_id ~vendor_id ~product_id f)

let test_open_close () = with_connection (fun _ -> return_unit)

let test_ping () = with_connection Ledgerwallet.Transport.ping

let test_git_commit () = with_connection (fun h -> get_git_commit h >|= ignore)

let hard x = Int32.logor x 0x8000_0000l

let path = [hard 44l; hard 1729l]

let curves = [Ed25519; Secp256k1; Secp256r1]

let msg = Cstruct.of_string "Voulez-vous coucher avec moi, ce soir ?"

let msg_ba = Cstruct.to_bigarray msg

let test_getpk h curve =
  get_public_key h curve path >|= fun pk ->
  Alcotest.(
    check int "pklen" (if curve = Ed25519 then 33 else 65) (Cstruct.length pk))

let test_getpk () =
  Lwt_list.iter_s (fun x -> with_connection (fun h -> test_getpk h x)) curves

let secp256k1_ctx =
  Secp256k1.Context.create [Secp256k1.Context.Verify; Secp256k1.Context.Sign]

let test_sign h curve =
  let open Alcotest in
  (* Add the watermark Generic_operation to the message *)
  let msg = Cstruct.concat [Cstruct.of_string "\x03"; msg] in
  get_public_key ~pp:Format.err_formatter h curve path >>= fun pk ->
  sign ~pp:Format.err_formatter h curve path msg >|= fun signature ->
  match curve with
  | Bip32_ed25519 -> ()
  | Ed25519 ->
      ()
      (*let pk = Tweetnacl.Sign.(pk pk) in
        check bool "sign Ed25519" true
          (Tweetnacl.Sign.verify_detached ~key:pk ~signature msg)*)
  | Secp256k1 -> (
      let open Rresult in
      let out =
        Secp256k1.Key.read_pk secp256k1_ctx (Cstruct.to_bigarray pk)
        >>= fun pk ->
        (* Remove parity info *)
        Cstruct.(set_uint8 signature 0 (get_uint8 signature 0 land 0xfe)) ;
        Secp256k1.Sign.read_der secp256k1_ctx (Cstruct.to_bigarray signature)
        >>= fun signature ->
        let msg = Secp256k1.Sign.msg_of_bytes_exn msg_ba in
        Secp256k1.Sign.verify secp256k1_ctx ~pk ~msg ~signature
      in
      match out with
      | Ok b -> check bool "sign Secp256k1" true b
      | Error e -> Alcotest.fail e)
  | Secp256r1 -> (
      let pk = Cstruct.to_bytes pk in
      let signature = Cstruct.to_bytes signature in
      let msg = Cstruct.to_bytes msg in
      (*(* Remove parity info *)
        Cstruct.(set_uint8 signature 0 (get_uint8 signature 0 land 0xfe)) ;
        let signature =
          Secp256k1.Sign.read_der_exn
            secp256k1_ctx (Cstruct.to_bigarray signature) in
        let signature =
          Secp256k1.Sign.to_bytes
            secp256k1_ctx signature in*)
      match Uecc.(pk_of_bytes pk) with
      | None -> assert false
      | Some pk ->
          check bool "sign Secp256r1" true (Uecc.verify pk ~msg ~signature))

let test_sign () =
  with_connection (fun h ->
      test_sign h Secp256r1 >>= fun () -> test_sign h Secp256r1)

let basic =
  [
    ("open_close", `Quick, test_open_close);
    ("ping", `Quick, test_ping);
    ("git_commit", `Quick, test_git_commit);
    ("get_public_key", `Quick, test_getpk);
    ("sign", `Quick, test_sign);
  ]

let () = Lwt_main.run (Alcotest_lwt.run "ledgerwallet.tezos" [("basic", basic)])
