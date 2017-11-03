open Ledgerwallet

let ctx = Secp256k1.Context.create []
let prevTx = `Hex "0100000001c3798bf6520ac4e95e24c587b6ee25a1c492f33ddd35615f90f38d89e8e2b47c010000006b483045022100dc48cef9d3e1eb71e84bcf51ceaf7f938328573e482bf8af951e9b53e87a74c802206280177d6ac07455d9984a8dd62f8d9f87c91884820c9fa587c8ada46750a44d4121032af552f85308e3c68c9751c415a5efe01fc165a955e48835a84894ab9986b149ffffffff02005ed0b2000000001976a914c78d002920f40f471846083f4283eae42246035988acb0cecff5150000001976a9147e854f6a0d4b20f61ba91ab0aa8e1f6f428e628e88ac00000000"
let prevTx = fst (Bitcoin.Protocol.Transaction.of_cstruct (Hex.to_cstruct prevTx))

let nextTx =
  let open Bitcoin in
  let open Bitcoin.Util in
  let open Bitcoin.Protocol in
  (* Format.printf "%a@." Transaction.pp prevTx ; *)
  let prev_out_hash = Transaction.hash256 prevTx in
  let my_out = List.hd prevTx.outputs in
  let input =
    TxIn.create' ~prev_out_hash ~prev_out_i:0 ~script:my_out.script () in
  let value = Int64.sub my_out.value 100000L in
  (* Printf.printf "%Ld %Ld\n%!" my_out.value value ; *)
  let output =
    TxOut.create ~value ~script:my_out.script in
  Transaction.create ~inputs:[input] ~outputs:[output] ()

let main () =
  let h = Hidapi.hid_open ~vendor_id:0x2C97 ~product_id:0x0001 in
  let path = Bitcoin.Util.KeyPath.[H 44l; H 1l; H 0l; N 0l; N 0l] in
  Ledgerwallet.ping h ;
  (* begin match verify_pin h "0000" with
   * | `Ok -> Printf.printf "Pin OK\n"
   * | `Need_power_cycle -> Printf.printf "Pin need power cycle\n"
   * end ;
   * Printf.printf "%d pin attemps possible\n" (get_remaining_pin_attempts h) ; *)
  let firmware_version = get_firmware_version h in
  Printf.printf "Firmware: %s\n"
    (Sexplib.Sexp.to_string_hum (Firmware_version.sexp_of_t firmware_version)) ;
  let op_mode = get_operation_mode h in
  Printf.printf "Operation mode: %s\n"
    (Sexplib.Sexp.to_string_hum (Operation_mode.sexp_of_t op_mode)) ;
  (* let second_factor = get_second_factor h in *)
  (* Printf.printf "Second factor: %s\n"
   *   (Sexplib.Sexp.to_string_hum (Second_factor.sexp_of_t second_factor)) ; *)
  let random_str = Ledgerwallet.get_random h 200 in
  Printf.printf "%d %S\n" (String.length random_str) random_str ;
  let pk = get_wallet_pubkeys h path in
  let pk_computed =
    Secp256k1.Public.of_bytes_exn ctx pk.uncompressed.buffer in
  let pk_compressed = Secp256k1.Public.to_bytes ctx pk_computed |> Cstruct.of_bigarray in
  let addr_computed = Bitcoin.Wallet.Address.of_pubkey ctx pk_computed in
  let `Hex uncomp = Hex.of_cstruct pk.uncompressed in
  Printf.printf "Uncompressed public key %s\n%!" uncomp ;
  Printf.printf "Address %s\n%!" pk.b58addr ;
  Format.printf "Address computed %a\n%!" Base58.Bitcoin.pp addr_computed ;
  let addr_computed_testnet =
    Base58.Bitcoin.create ~version:Testnet_P2PKH ~payload:addr_computed.payload in
  Format.printf "Address computed %a\n%!" Base58.Bitcoin.pp addr_computed_testnet ;
  let `Hex chaincode = Hex.of_cstruct pk.bip32_chaincode in
  Printf.printf "Chaincode %s\n%!" chaincode ;
  let `Hex ti = Hex.of_cstruct (get_trusted_input h prevTx 0) in
  Printf.printf "Trusted input %s\n%!" ti ;
  Format.printf "%a@." Bitcoin.Protocol.Transaction.pp nextTx ;
  let bch_signatures = sign_segwit ~bch:true ~path ~prev_amounts:[3000000000L] h nextTx in
  Printf.printf "Got %d BCH signatures.\n%!" (List.length bch_signatures) ;
  (* let signatures = sign ~path ~prev_outputs:[prevTx, 0] h nextTx in
   * Printf.printf "Got %d signatures.\n%!" (List.length signatures) ; *)
  let bchSig = List.hd bch_signatures in
  let scriptSig =
    Bitcoin.Script.[Element.O (Op_pushdata (Cstruct.len bchSig));
                    D bchSig ;
                    O (Op_pushdata (Cstruct.len pk_compressed)) ;
                    D pk_compressed ;
                   ] in
  let nextTx_input = List.hd nextTx.inputs in
  let nextTx_input = { nextTx_input with script = scriptSig @ nextTx_input.script } in
  let txFinal = { nextTx with inputs = [nextTx_input] } in
  let cs = Cstruct.create 1024 in
  let cs' = Bitcoin.Protocol.Transaction.to_cstruct cs txFinal in
  let txSerialized = Cstruct.sub cs 0 cs'.off in
  let `Hex txS_hex = Hex.of_cstruct txSerialized in
  Printf.printf "Tx = %s" txS_hex

let () = main ()
