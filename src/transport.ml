(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

open Rresult

let packet_length = 64

let channel = 0x0101

let apdu = 0x05

let ping = 0x02

let check_buflen cs =
  let cslen = Cstruct.length cs in
  if cslen < packet_length then
    invalid_arg ("HID packets must be 64 bytes long, got " ^ string_of_int cslen)

type t = Hidapi of Hidapi.t

module Header = struct
  type t = {cmd : cmd; seq : int}

  and cmd = Ping | Apdu

  let cmd_of_int = function 0x05 -> Some Apdu | 0x02 -> Some Ping | _ -> None

  module Error = struct
    type t =
      | Header_too_short of int
      | Invalid_channel of int
      | Invalid_command_tag of int
      | Unexpected_sequence_number of {expected : int; actual : int}

    let pp ppf = function
      | Header_too_short i ->
          Format.fprintf ppf "Header too short (got %d bytes)" i
      | Invalid_channel i -> Format.fprintf ppf "Invalid channel (%d)" i
      | Invalid_command_tag i -> Format.fprintf ppf "Invalid command tag (%d)" i
      | Unexpected_sequence_number {expected; actual} ->
          Format.fprintf
            ppf
            "Unexpected sequence number (expected %d, got %d)"
            expected
            actual
  end

  let fail_header_too_short i = R.error (Error.Header_too_short i)

  let fail_invalid_chan i = R.error (Error.Invalid_channel i)

  let fail_invalid_cmd i = R.error (Error.Invalid_command_tag i)

  let fail_unexpected_seqnum ~expected ~actual =
    R.error (Error.Unexpected_sequence_number {expected; actual})

  let read cs =
    let cslen = Cstruct.length cs in
    (if cslen < 5 then fail_header_too_short cslen else R.ok ()) >>= fun () ->
    let channel_id = Cstruct.BE.get_uint16 cs 0 in
    let cmd = Cstruct.get_uint8 cs 2 in
    let seq = Cstruct.BE.get_uint16 cs 3 in
    (if channel_id <> channel then fail_invalid_chan channel_id else R.ok ())
    >>= fun () ->
    (match cmd_of_int cmd with
    | Some cmd -> R.ok cmd
    | None -> fail_invalid_cmd cmd)
    >>= fun cmd -> R.ok ({cmd; seq}, Cstruct.shift cs 5)

  let check_seqnum t expected_seq =
    if expected_seq <> t.seq then
      fail_unexpected_seqnum ~actual:t.seq ~expected:expected_seq
    else R.ok ()
end

type transport_error =
  | Hidapi_error of string
  | Incomplete_write of int
  | Incomplete_read of int

let pp_transport_error ppf = function
  | Hidapi_error s -> Format.pp_print_string ppf s
  | Incomplete_write i ->
      Format.fprintf ppf "wrote %d bytes, expected to write 64 bytes" i
  | Incomplete_read i ->
      Format.fprintf ppf "read %d bytes, expected to read 64 bytes" i

type error =
  | AppError of {status : Status.t; msg : string}
  | ApduError of Header.Error.t
  | TransportError of transport_error

let app_error ~msg r = R.reword_error (fun status -> AppError {status; msg}) r

let apdu_error r = R.reword_error (fun e -> ApduError e) r

let pp_error ppf = function
  | AppError {status; msg} ->
      Format.fprintf ppf "Application level error (%s): %a" msg Status.pp status
  | ApduError e -> Format.fprintf ppf "APDU level error: %a" Header.Error.pp e
  | TransportError e ->
      Format.fprintf ppf "Transport level error: %a" pp_transport_error e

let check_nbwritten = function
  | n when n = packet_length -> R.ok ()
  | n -> R.error (TransportError (Incomplete_write n))

let check_nbread = function
  | n when n = packet_length -> R.ok ()
  | n -> R.error (TransportError (Incomplete_read n))

let with_connection ~vendor_id ~product_id f =
  let h = Hidapi.open_id_exn ~vendor_id ~product_id in
  try let out = f (Hidapi h) in
    Hidapi.close h ;
    out
  with exn ->
    Hidapi.close h ;
    raise exn

let write_hidapi h ?len buf =
  R.reword_error
    (fun s -> TransportError (Hidapi_error s))
    (Hidapi.write h ?len Cstruct.(to_bigarray (sub buf 0 packet_length)))
  >>= check_nbwritten

let read_hidapi ?timeout h buf =
  R.reword_error
    (fun s -> TransportError (Hidapi_error s))
    (Hidapi.read ?timeout h buf packet_length)
  >>= check_nbread

let write_ping ?(buf = Cstruct.create packet_length) (Hidapi h) =
  check_buflen buf ;
  let open Cstruct in
  BE.set_uint16 buf 0 channel ;
  set_uint8 buf 2 ping ;
  BE.set_uint16 buf 3 0 ;
  memset (sub buf 5 59) 0 ;
  write_hidapi h buf

let write_apdu ?pp ?(buf = Cstruct.create packet_length) (Hidapi h) p =
  check_buflen buf ;
  let apdu_len = Apdu.length p in
  let apdu_buf = Cstruct.create apdu_len in
  let _nb_written = Apdu.write apdu_buf p in
  (match pp with
  | None -> ()
  | Some pp ->
      Format.fprintf pp "-> REQ %a@." Cstruct.hexdump_pp apdu_buf ;
      Format.pp_print_flush pp ()) ;
  let apdu_p = ref 0 in
  (* pos in the apdu buf *)
  let i = ref 0 in
  (* packet id *)
  let open Cstruct in
  (* write first packet *)
  BE.set_uint16 buf 0 channel ;
  set_uint8 buf 2 apdu ;
  BE.set_uint16 buf 3 !i ;
  BE.set_uint16 buf 5 apdu_len ;
  let nb_to_write = min apdu_len (packet_length - 7) in
  blit apdu_buf 0 buf 7 nb_to_write ;
  write_hidapi h buf >>= fun () ->
  apdu_p := !apdu_p + nb_to_write ;
  incr i ;

  (* write following packets *)
  let rec inner apdu_p =
    if apdu_p >= apdu_len then R.ok ()
    else (
      memset buf 0 ;
      BE.set_uint16 buf 0 channel ;
      set_uint8 buf 2 apdu ;
      BE.set_uint16 buf 3 !i ;
      let nb_to_write = min (apdu_len - apdu_p) (packet_length - 5) in
      blit apdu_buf apdu_p buf 5 nb_to_write ;
      write_hidapi h buf >>= fun () ->
      incr i ;
      inner (apdu_p + nb_to_write))
  in
  inner !apdu_p

let read ?pp ?(buf = Cstruct.create packet_length) (Hidapi h) =
  check_buflen buf ;
  let expected_seq = ref 0 in
  let full_payload = ref (Cstruct.create 0) in
  let payload = ref (Cstruct.create 0) in
  (* let pos = ref 0 in *)
  let rec inner () =
    read_hidapi ~timeout:600_000 h (Cstruct.to_bigarray buf) >>= fun () ->
    (match pp with
    | None -> ()
    | Some pp ->
        Format.fprintf
          pp
          "<- RAW PKT %a@."
          Cstruct.hexdump_pp
          (Cstruct.sub buf 0 packet_length) ;
        Format.pp_print_flush pp ()) ;
    apdu_error (Header.read buf) >>= fun (hdr, buf) ->
    apdu_error (Header.check_seqnum hdr !expected_seq) >>= fun () ->
    (if hdr.seq = 0 then (
     (* first frame *)
     let len = Cstruct.BE.get_uint16 buf 0 in
     let cs = Cstruct.shift buf 2 in
     payload := Cstruct.create len ;
     full_payload := !payload ;
     let nb_to_read = min len (packet_length - 7) in
     Cstruct.blit cs 0 !payload 0 nb_to_read ;
     payload := Cstruct.shift !payload nb_to_read ;
     (* pos := !pos + nb_to_read ; *)
     expected_seq := !expected_seq + 1)
    else
      (* next frames *)
      (* let rem = Bytes.length !payload - !pos in *)
      let nb_to_read = min (Cstruct.length !payload) (packet_length - 5) in
      Cstruct.blit buf 0 !payload 0 nb_to_read ;
      payload := Cstruct.shift !payload nb_to_read ;
      (* pos := !pos + nb_to_read ; *)
      expected_seq := !expected_seq + 1) ;
    match (Cstruct.length !payload, hdr.cmd) with
    | 0, Ping -> R.ok (Status.Ok, Cstruct.create 0)
    | 0, Apdu ->
        (* let sw_pos = Bytes.length !payload - 2 in *)
        let payload_len = Cstruct.length !full_payload in
        let sw = Cstruct.BE.get_uint16 !full_payload (payload_len - 2) in
        R.ok (Status.of_int sw, Cstruct.sub !full_payload 0 (payload_len - 2))
    | _ -> inner ()
  in
  inner ()

let ping ?pp ?buf h = write_ping ?buf h >>= fun () -> read ?pp ?buf h >>| ignore

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
