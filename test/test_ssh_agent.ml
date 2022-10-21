open Rresult
open Ledgerwallet_ssh_agent

let fail_on_error = function
  | None -> Alcotest.fail "Found no ledger."
  | Some (Result.Ok ()) -> ()
  | Some (Result.Error e) ->
      Alcotest.fail
        (Format.asprintf "Ledger error: %a" Ledgerwallet.Transport.pp_error e)

let with_connection f =
  fail_on_error
    (Ledgerwallet.Transport.with_connection_id
       ~vendor_id:0x2C97
       ~product_id:0x1005
       f)

let test_open_close () = with_connection (fun _ -> R.ok ())

let test_ping () = with_connection Ledgerwallet.Transport.ping

let hard x = Int32.logor x 0x8000_0000l

let path = [hard 44l; hard 535348l]

let test_get_public_key () =
  with_connection (fun h ->
      get_public_key h ~curve:Prime256v1 ~path >>= fun pk_prime ->
      get_public_key h ~curve:Curve25519 ~path >>| fun pk_curve ->
      Format.printf
        "Uncompressed prime256v1 public key %a@."
        Hex.pp
        (Hex.of_cstruct pk_prime) ;
      Format.printf
        "Uncompressed curve25519 public key %a@."
        Hex.pp
        (Hex.of_cstruct pk_curve))

let basic =
  [
    ("open_close", `Quick, test_open_close);
    ("ping", `Quick, test_ping);
    ("get_public_key", `Quick, test_get_public_key);
  ]

let () = Alcotest.run "ledgerwallet.ssh-agent" [("basic", basic)]
