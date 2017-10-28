open Ledgerwallet

let main () =
  let h = Hidapi.hid_open ~vendor_id:0x2581 ~product_id:0x3B7C in
  Ledgerwallet.ping h ;
  let op_mode = get_operation_mode h in
  Printf.printf "%s\n"
    (Sexplib.Sexp.to_string_hum (Operation_mode.sexp_of_t op_mode)) ;
  let random_str = Ledgerwallet.get_random h 200 in
  Printf.printf "%d %S\n" (String.length random_str) random_str

let () = main ()
