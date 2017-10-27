open Lwt.Infix

let main () =
  let h = Usb.open_device_with ~vendor_id:0x2581 ~product_id:0x3B7C in
  let dev = Usb.get_device h in
  let device_descr = Usb.get_device_descriptor dev in
  let cfg_descr = Usb.get_config_descriptor dev 0 in
  Usb.get_configuration h >>= fun cfg_id ->
  Printf.printf "%d\n%!" cfg_id ;
  Printf.printf "%s\n%!"
    (Sexplib.Sexp.to_string_hum (Usb.sexp_of_device_descriptor device_descr)) ;
  Printf.printf "%s\n%!"
    (Sexplib.Sexp.to_string_hum (Usb.sexp_of_config_descriptor cfg_descr)) ;
  Ledgerwallet.ping h

let () =
  Lwt_main.run (main ())
