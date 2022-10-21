open Rresult

type error = Exception of exn

let pp_error fmt = function
  | Exception (Unix.Unix_error (err, x, y)) ->
      Format.fprintf fmt "Unix error: %s %s %s" x (Unix.error_message err) y
  | Exception End_of_file ->
      Format.pp_print_string
        fmt
        "Transport level error: Cannot read enough bytes"
  | Exception e -> Format.pp_print_string fmt (Printexc.to_string e)

type t = {input : in_channel; output : out_channel}

let create ?(name = "127.0.0.1") ?(port = 9999) () =
  let info = Unix.getaddrinfo name (string_of_int port) [] in
  let sockaddr =
    match info with
    | [] -> failwith (Format.sprintf "Unknown host %s" name)
    | {ai_addr; _} :: _ -> ai_addr
  in
  let input, output = Unix.open_connection sockaddr in
  {input; output}

let close {output; _} = close_out output

let send t buf =
  try
    let s = Cstruct.to_string buf in
    output_binary_int t.output (String.length s) ;
    output_string t.output s ;
    flush t.output ;
    R.ok ()
  with e -> R.error (Exception e)

let get inc =
  try
    let size = input_binary_int inc in
    let v = really_input_string inc size in
    let code = really_input_string inc 2 in
    R.ok (Bytes.get_uint16_be (Bytes.of_string code) 0, v)
  with e -> R.error (Exception e)

let write_apdu ?pp t p =
  let apdu_len = Apdu.length p in
  let apdu_buf = Cstruct.create apdu_len in
  let _nb_written = Apdu.write apdu_buf p in
  (match pp with
  | None -> ()
  | Some pp ->
      Format.fprintf pp "-> REQ %a@." Cstruct.hexdump_pp apdu_buf ;
      Format.pp_print_flush pp ()) ;
  send t apdu_buf

let read t =
  R.map
    (fun (code, data) -> (Status.of_int code, Cstruct.of_string data))
    (get t.input)
