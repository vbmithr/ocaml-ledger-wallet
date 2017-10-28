let main () =
  let h = Hidapi.hid_open ~vendor_id:0x2581 ~product_id:0x3B7C in
  Ledgerwallet.ping h ;
  ()
  (* let random_str = Ledgerwallet.get_random h 10 in
   * Printf.printf "%S\n" random_str *)

let () = main ()
