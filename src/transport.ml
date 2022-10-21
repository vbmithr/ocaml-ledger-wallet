(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

open Rresult

type t = Hidapi of Hidapi.t

type transport_error = HidapiError of Transport_hidapi.error

type error =
  | AppError of {status : Status.t; msg : string}
  | TransportError of transport_error

let app_error ~msg r = R.reword_error (fun status -> AppError {status; msg}) r

let pp_error ppf = function
  | AppError {status; msg} ->
      Format.fprintf ppf "Application level error (%s): %a" msg Status.pp status
  | TransportError (HidapiError e) -> Transport_hidapi.pp_error ppf e

let with_connection ~vendor_id ~product_id f =
  let h = Hidapi.open_id_exn ~vendor_id ~product_id in
  try let out = f (Hidapi h) in
    Hidapi.close h ;
    out
  with exn ->
    Hidapi.close h ;
    raise exn

let write_apdu ?pp ?buf h apdu =
  match h with
  | Hidapi h ->
      R.reword_error
        (fun e -> TransportError (HidapiError e))
        (Transport_hidapi.write_apdu ?pp ?buf h apdu)

let read ?pp ?buf h =
  match h with
  | Hidapi h ->
      R.reword_error
        (fun e -> TransportError (HidapiError e))
        (Transport_hidapi.read ?pp ?buf h)

let ping ?pp ?buf h =
  match h with
  | Hidapi h ->
      R.reword_error
        (fun e -> TransportError (HidapiError e))
        (Transport_hidapi.ping ?pp ?buf h)

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
