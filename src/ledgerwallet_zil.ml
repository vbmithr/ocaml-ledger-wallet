(*---------------------------------------------------------------------------
   Copyright (c) 2019 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

open Ledgerwallet

type ins =
  | Get_version
  | Get_public_key
  (* | Sign_hash
   * | Sign_txn *)

let int_of_ins = function
  | Get_version -> 0x01
  | Get_public_key -> 0x02
  (* | Sign_hash -> 0x04
   * | Sign_txn -> 0x08 *)

let wrap_ins cmd =
  Apdu.create_cmd ~cmd ~cla_of_cmd:(fun _ -> 0xe0) ~ins_of_cmd:int_of_ins

(* let write_path cs path =
 *   ListLabels.fold_left path ~init:cs ~f:begin fun cs i ->
 *     Cstruct.BE.set_uint32 cs 0 i ;
 *     Cstruct.shift cs 4
 *   end *)

let get_version ?pp ?buf h =
  let msg = "Zil.get_version" in
  let apdu = Apdu.create (wrap_ins Get_version) in
  let ver = Transport.apdu ~msg ?pp ?buf h apdu in
  Cstruct.(get_uint8 ver 0, get_uint8 ver 1, get_uint8 ver 2)

let get_pk ?(display_addr=false) ?pp ?buf h i =
  let msg = "Zil.get_pk" in
  let data = Cstruct.create 4 in
  Cstruct.LE.set_uint32 data 0 i ;
  let p2 = if display_addr then 1 else 0 in
  let apdu = Apdu.create ~p2 ~data (wrap_ins Get_public_key) in
  let buf = Transport.apdu ~msg ?pp ?buf h apdu in
  let pk = Cstruct.sub buf 0 33 in
  let buf = Cstruct.shift buf 33 in
  pk, Bech32.Segwit.(decode ~version:false (module Zil) (Cstruct.to_string buf))

(* let get_public_key ?pp ?buf h curve path =
 *   let nb_derivations = List.length path in
 *   if nb_derivations > 10 then invalid_arg "get_public_key: max 10 derivations" ;
 *   let lc = 1 + 4 * nb_derivations in
 *   let data_init = Cstruct.create lc in
 *   Cstruct.set_uint8 data_init 0 nb_derivations ;
 *   let data = Cstruct.shift data_init 1 in
 *   let _data = write_path data path in
 *   let msg = "Tezos.get_public_key" in
 *   let apdu =  Apdu.create ~p2:(int_of_curve curve)
 *       ~lc ~data:data_init (wrap_ins Get_public_key) in
 *   let addr = Transport.apdu ~msg ?pp ?buf h apdu in
 *   let keylen = Cstruct.get_uint8 addr 0 in
 *   Cstruct.sub addr 1 keylen *)

(* let sign ?pp ?buf h curve path payload =
 *   let nb_derivations = List.length path in
 *   if nb_derivations > 10 then invalid_arg "get_public_key: max 10 derivations" ;
 *   let lc = 1 + 4 * nb_derivations in
 *   let data_init = Cstruct.create lc in
 *   Cstruct.set_uint8 data_init 0 nb_derivations ;
 *   let data = Cstruct.shift data_init 1 in
 *   let _data = write_path data path in
 *   let cmd = wrap_ins Sign in
 *   let msg = "Tezos.sign" in
 *   let apdu = Apdu.create ~p2:(int_of_curve curve) ~lc ~data:data_init cmd in
 *   let _addr = Transport.apdu ~msg ?pp ?buf h apdu in
 *   Transport.write_payload ~mark_last:true ?pp ?buf ~msg ~cmd h ~p1:0x01 payload *)

(*---------------------------------------------------------------------------
   Copyright (c) 2019 Vincent Bernardoff

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
