(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

open Rresult

type t = Hidapi of Hidapi.t | Proxy of Transport_proxy.t

type transport_error =
  | HidapiError of Transport_hidapi.error
  | ProxyError of Transport_proxy.error

type error =
  | AppError of {status : Status.t; msg : string}
  | TransportError of transport_error

let app_error ~msg r = R.reword_error (fun status -> AppError {status; msg}) r

let pp_error ppf = function
  | AppError {status; msg} ->
      Format.fprintf ppf "Application level error (%s): %a" msg Status.pp status
  | TransportError (HidapiError e) -> Transport_hidapi.pp_error ppf e
  | TransportError (ProxyError e) -> Transport_proxy.pp_error ppf e

let create open_ =
  let name = Sys.getenv_opt "LEDGER_PROXY_ADDRESS" in
  let port =
    Option.bind (Sys.getenv_opt "LEDGER_PROXY_PORT") (fun s ->
        try Some (int_of_string s) with _ -> None)
  in
  match (name, port) with
  | None, None -> Option.map (fun x -> Hidapi x) (open_ ())
  | _, _ -> Some (Proxy (Transport_proxy.create ?name ?port ()))

let open_id ~vendor_id ~product_id =
  create (fun () -> Hidapi.open_id ~vendor_id ~product_id)

let open_path path = create (fun () -> Hidapi.open_path path)

let close = function
  | Hidapi h -> Hidapi.close h
  | Proxy p -> Transport_proxy.close p

let with_connection f = function
  | Some h -> (
      try
        let out = f h in
        close h ;
        Some out
      with exn ->
        close h ;
        raise exn)
  | None -> None

let with_connection_id ~vendor_id ~product_id f =
  with_connection f (open_id ~vendor_id ~product_id)

let with_connection_path path f = with_connection f (open_path path)

let write_apdu ?pp ?buf h apdu =
  match h with
  | Hidapi h ->
      R.reword_error
        (fun e -> TransportError (HidapiError e))
        (Transport_hidapi.write_apdu ?pp ?buf h apdu)
  | Proxy p ->
      R.reword_error
        (fun e -> TransportError (ProxyError e))
        (Transport_proxy.write_apdu ?pp p apdu)

let read ?pp ?buf h =
  match h with
  | Hidapi h ->
      R.reword_error
        (fun e -> TransportError (HidapiError e))
        (Transport_hidapi.read ?pp ?buf h)
  | Proxy p ->
      R.reword_error
        (fun e -> TransportError (ProxyError e))
        (Transport_proxy.read p)

let ping ?pp ?buf h =
  match h with
  | Hidapi h ->
      R.reword_error
        (fun e -> TransportError (HidapiError e))
        (Transport_hidapi.ping ?pp ?buf h)
  | Proxy _ -> Ok ()

let apdu ?pp ?(msg = "") ?buf h apdu =
  write_apdu ?pp ?buf h apdu >>= fun () ->
  read ?pp ?buf h >>= fun (status, payload) ->
  (match pp with
  | None -> ()
  | Some pp ->
      Format.fprintf
        pp
        "<- RESP [%a] %a@."
        Status.pp
        status
        Cstruct.hexdump_pp
        payload ;
      Format.pp_print_flush pp ()) ;
  match status with
  | Status.Ok -> R.ok payload
  | status -> app_error ~msg (R.error status)

let write_payload ?pp ?(msg = "write_payload") ?buf ?(mark_last = false) ~cmd
    ?p1 ?p2 h cs =
  let rec inner cs =
    let cs_len = Cstruct.length cs in
    let lc = min Apdu.max_data_length cs_len in
    let last = lc = cs_len in
    let p1 =
      match (last, mark_last, p1) with
      | true, true, None -> Some 0x80
      | true, true, Some p1 -> Some (0x80 lor p1)
      | _ -> p1
    in
    apdu
      ?pp
      ~msg
      ?buf
      h
      Apdu.(create ?p1 ?p2 ~lc ~data:(Cstruct.sub cs 0 lc) cmd)
    >>= fun response ->
    if last then R.ok response else inner (Cstruct.shift cs lc)
  in
  if Cstruct.length cs = 0 then R.ok cs else inner cs

(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff

   Permission to use, copy, modify, and/or distribute this software for any
   purpose with or without fee is hereby granted, provided that the above
   copyright notice and this permission notice appear in all copies.

   THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
   WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
   ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
   WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
   ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
   OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
  ---------------------------------------------------------------------------*)
