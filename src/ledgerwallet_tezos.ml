(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

open Rresult
open Ledgerwallet

module Version = struct
  type app_class = Tezos | TezBake

  let pp_app_class ppf = function
    | Tezos -> Format.pp_print_string ppf "Tezos Wallet"
    | TezBake -> Format.pp_print_string ppf "Tezos Baking"

  let class_of_int = function
    | 0 -> Tezos
    | 1 -> TezBake
    | _ -> invalid_arg "class_of_int"

  type t = {app_class : app_class; major : int; minor : int; patch : int}

  let pp ppf {app_class; major; minor; patch} =
    Format.fprintf ppf "%a %d.%d.%d" pp_app_class app_class major minor patch

  let create ~app_class ~major ~minor ~patch = {app_class; major; minor; patch}

  type Status.t += Tezos_impossible_to_read_version

  let () =
    Status.register_string_f (function
        | Tezos_impossible_to_read_version -> Some "Impossible to read version"
        | _ -> None)

  let read cs =
    try
      let app_class = class_of_int (Cstruct.get_uint8 cs 0) in
      let major = Cstruct.get_uint8 cs 1 in
      let minor = Cstruct.get_uint8 cs 2 in
      let patch = Cstruct.get_uint8 cs 3 in
      R.ok (create ~app_class ~major ~minor ~patch)
    with _ ->
      Transport.app_error
        ~msg:"Version.read"
        (R.error Tezos_impossible_to_read_version)
end

type ins =
  | Version
  | Git_commit
  | Authorize_baking
  | Get_public_key
  | Prompt_public_key
  | Sign
  | Sign_unsafe
  | Reset_high_watermark
  | Query_high_watermark
  | Get_authorized_key
  | Setup
  | Query_all_high_watermarks
  | Deauthorize_baking
  | Get_authorized_path_and_curve
  | Make_deterministic_nonce
  | Sign_with_hash

let int_of_ins = function
  | Version -> 0x00
  | Authorize_baking -> 0x01
  | Get_public_key -> 0x02
  | Prompt_public_key -> 0x03
  | Sign -> 0x04
  | Sign_unsafe -> 0x05
  | Reset_high_watermark -> 0x06
  | Query_high_watermark -> 0x08
  | Git_commit -> 0x09
  | Get_authorized_key -> 0x07
  | Setup -> 0x0A
  | Query_all_high_watermarks -> 0x0B
  | Deauthorize_baking -> 0x0C
  | Get_authorized_path_and_curve -> 0x0D
  | Make_deterministic_nonce -> 0x0E
  | Sign_with_hash -> 0x0F

type curve = Ed25519 | Secp256k1 | Secp256r1 | Bip32_ed25519

let pp_curve ppf = function
  | Ed25519 -> Format.pp_print_string ppf "ed25519"
  | Secp256k1 -> Format.pp_print_string ppf "secp256k1"
  | Secp256r1 -> Format.pp_print_string ppf "P-256"
  | Bip32_ed25519 -> Format.pp_print_string ppf "bip25519"

let pp_curve_short ppf = function
  | Ed25519 -> Format.pp_print_string ppf "ed"
  | Secp256k1 -> Format.pp_print_string ppf "secp"
  | Secp256r1 -> Format.pp_print_string ppf "p2"
  | Bip32_ed25519 -> Format.pp_print_string ppf "bip25519"

let curve_of_string str =
  match String.lowercase_ascii str with
  | "ed" | "ed25519" -> Some Ed25519
  | "bip25519" | "bip32-ed25519" -> Some Bip32_ed25519
  | "secp256k1" -> Some Secp256k1
  | "p256" | "p-256" | "secp256r1" -> Some Secp256r1
  | _ -> None

let int_of_curve = function
  | Ed25519 -> 0x00
  | Secp256k1 -> 0x01
  | Secp256r1 -> 0x02
  | Bip32_ed25519 -> 0x03

let curve_of_int = function
  | 0x00 -> Some Ed25519
  | 0x01 -> Some Secp256k1
  | 0x02 -> Some Secp256r1
  | 0x03 -> Some Bip32_ed25519
  | _ -> None

type Status.t += Tezos_invalid_curve_code of int | Payload_too_big of int

let () =
  Status.register_string_f (function
      | Tezos_invalid_curve_code curve_code ->
          Some ("Unrecognized curve code: " ^ string_of_int curve_code)
      | Payload_too_big size ->
          Some (Printf.sprintf "Payload too big: %d bytes" size)
      | _ -> None)

let () =
  Status.register_help_suggestor_f (function
      | Status.Conditions_of_use_not_satisfied ->
          Some
            "Either you rejected the operation or you waited long enough to \
             respond that the device rejected it for you."
      | Status.Incorrect_class ->
          Some
            "A Tezos application wasn't found on the device. Is the Tezos \
             Wallet or Tezos Baking application open on the device? Is the \
             device busy talking to another process?"
      | Status.Security_status_unsatisfied ->
          Some
            "The operation was automatically rejected for security reasons. If \
             baking, you may need to setup the device or reset the high-water \
             mark."
      | _ -> None)

let wrap_ins cmd =
  Apdu.create_cmd ~cmd ~cla_of_cmd:(fun _ -> 0x80) ~ins_of_cmd:int_of_ins

let get_version ?pp ?buf h =
  let apdu = Apdu.create (wrap_ins Version) in
  Transport.apdu ~msg:"get_version" ?pp ?buf h apdu >>= Version.read

let get_git_commit ?pp ?buf h =
  let apdu = Apdu.create (wrap_ins Git_commit) in
  Transport.apdu ~msg:"get_git_commit" ?pp ?buf h apdu >>| Cstruct.to_string

let read_path_with_length buf =
  let length = Cstruct.get_uint8 buf 0 in
  let rec go acc path =
    if Cstruct.length path = 0 || List.length acc = length then List.rev acc
    else go (Cstruct.BE.get_uint32 path 0 :: acc) (Cstruct.shift path 4)
  in
  go [] (Cstruct.shift buf 1)

let get_authorized_key ?pp ?buf h =
  let apdu = Apdu.create (wrap_ins Get_authorized_key) in
  Transport.apdu ~msg:"get_authorized_key" ?pp ?buf h apdu >>| fun path ->
  read_path_with_length path

let get_authorized_path_and_curve ?pp ?buf h =
  let apdu = Apdu.create (wrap_ins Get_authorized_path_and_curve) in
  Transport.apdu ~msg:"get_authorized_path_and_curve" ?pp ?buf h apdu
  >>= fun payload ->
  let curve_code = Cstruct.get_uint8 payload 0 in
  match curve_of_int curve_code with
  | None ->
      Transport.app_error
        ~msg:"get_authorized_path_and_curve"
        (R.error (Tezos_invalid_curve_code curve_code))
  | Some curve ->
      let path_components = read_path_with_length (Cstruct.shift payload 1) in
      R.ok (path_components, curve)

let write_path cs path =
  ListLabels.fold_left path ~init:cs ~f:(fun cs i ->
      Cstruct.BE.set_uint32 cs 0 i ;
      Cstruct.shift cs 4)

let get_public_key_like cmd ?pp ?buf h curve path =
  let nb_derivations = List.length path in
  if nb_derivations > 10 then invalid_arg "get_public_key: max 10 derivations" ;
  let lc = 1 + (4 * nb_derivations) in
  let data_init = Cstruct.create lc in
  Cstruct.set_uint8 data_init 0 nb_derivations ;
  let data = Cstruct.shift data_init 1 in
  let _data = write_path data path in
  let msg = "get_public_key" in
  let apdu =
    Apdu.create ~p2:(int_of_curve curve) ~lc ~data:data_init (wrap_ins cmd)
  in
  Transport.apdu ~msg ?pp ?buf h apdu >>| fun addr ->
  let keylen = Cstruct.get_uint8 addr 0 in
  Cstruct.sub addr 1 keylen

let get_public_key ?(prompt = true) =
  let cmd = if prompt then Prompt_public_key else Get_public_key in
  get_public_key_like cmd

let authorize_baking = get_public_key_like Authorize_baking

let setup_baking ?pp ?buf h ~main_chain_id ~main_hwm ~test_hwm curve path =
  let nb_derivations = List.length path in
  if nb_derivations > 10 then
    invalid_arg "Ledgerwallet_tezos.setup: max 10 derivations" ;
  let lc =
    (* [ chain-id | main-hwm | test-hwm | derivations-path ] *)
    (* derivations-path = [ length | paths ] *)
    (3 * 4) + 1 + (4 * nb_derivations)
  in
  let data_init = Cstruct.create lc in
  (* If the size of chain-ids changes, then all assumptions of this
     binary format are broken (the ledger expects a uint32). *)
  assert (String.length main_chain_id = 4) ;
  for ith = 0 to 3 do
    Cstruct.set_uint8 data_init ith (int_of_char main_chain_id.[ith])
  done ;
  Cstruct.BE.set_uint32 data_init 4 main_hwm ;
  Cstruct.BE.set_uint32 data_init 8 test_hwm ;
  Cstruct.set_uint8 data_init 12 nb_derivations ;
  let (_ : Cstruct.t) =
    let data = Cstruct.shift data_init (12 + 1) in
    write_path data path
  in
  let msg = "setup" in
  let apdu =
    Apdu.create ~p2:(int_of_curve curve) ~lc ~data:data_init (wrap_ins Setup)
  in
  Transport.apdu ~msg ?pp ?buf h apdu >>| fun addr ->
  let keylen = Cstruct.get_uint8 addr 0 in
  Cstruct.sub addr 1 keylen

let deauthorize_baking ?pp ?buf h =
  let apdu = Apdu.create (wrap_ins Deauthorize_baking) in
  Transport.apdu ~msg:"deauthorize_baking" ?pp ?buf h apdu >>| fun _ -> ()

let get_high_watermark ?pp ?buf h =
  let apdu = Apdu.create (wrap_ins Query_high_watermark) in
  Transport.apdu ~msg:"get_high_watermark" ?pp ?buf h apdu >>| fun data ->
  let has_migrated_to_tenderbake = Cstruct.length data >= 8 in
  if has_migrated_to_tenderbake then
    (Cstruct.BE.get_uint32 data 0, Some (Cstruct.BE.get_uint32 data 4))
  else (Cstruct.BE.get_uint32 data 0, None)

let get_all_high_watermarks ?pp ?buf h =
  let apdu = Apdu.create (wrap_ins Query_all_high_watermarks) in
  Transport.apdu ~msg:"get_high_watermark" ?pp ?buf h apdu >>| fun data ->
  let has_migrated_to_tenderbake = Cstruct.length data >= 20 in
  if has_migrated_to_tenderbake then
    let main_hwm = Cstruct.BE.get_uint32 data 0 in
    let main_hwm_round = Cstruct.BE.get_uint32 data 4 in
    let test_hwm = Cstruct.BE.get_uint32 data 8 in
    let test_hwm_round = Cstruct.BE.get_uint32 data 12 in
    let chain_id = Cstruct.copy data 16 4 in
    ( `Main_hwm (main_hwm, Some main_hwm_round),
      `Test_hwm (test_hwm, Some test_hwm_round),
      `Chain_id chain_id )
  else
    let main_hwm = Cstruct.BE.get_uint32 data 0 in
    let test_hwm = Cstruct.BE.get_uint32 data 4 in
    let chain_id = Cstruct.copy data 8 4 in
    (`Main_hwm (main_hwm, None), `Test_hwm (test_hwm, None), `Chain_id chain_id)

let set_high_watermark ?pp ?buf h hwm =
  let data = Cstruct.create 4 in
  Cstruct.BE.set_uint32 data 0 hwm ;
  let apdu = Apdu.create ~lc:4 ~data (wrap_ins Reset_high_watermark) in
  Transport.apdu ~msg:"set_high_watermark" ?pp ?buf h apdu >>| ignore

let sign ?pp ?buf ?(hash_on_ledger = true) h curve path payload =
  let nb_derivations = List.length path in
  if nb_derivations > 10 then invalid_arg "get_public_key: max 10 derivations" ;
  let lc = 1 + (4 * nb_derivations) in
  let data_init = Cstruct.create lc in
  Cstruct.set_uint8 data_init 0 nb_derivations ;
  let data = Cstruct.shift data_init 1 in
  let _data = write_path data path in
  let cmd = wrap_ins (if hash_on_ledger then Sign else Sign_unsafe) in
  let msg = "sign" in
  let apdu = Apdu.create ~p2:(int_of_curve curve) ~lc ~data:data_init cmd in
  let _addr = Transport.apdu ~msg ?pp ?buf h apdu in
  Transport.write_payload ~mark_last:true ?pp ?buf ~msg ~cmd h ~p1:0x01 payload

let get_deterministic_nonce ?pp ?buf h curve path payload =
  let nb_derivations = List.length path in
  if nb_derivations > 10 then
    invalid_arg "get_deterministic_nonce: max 10 derivations" ;
  let path_data =
    let lc = 1 + (4 * nb_derivations) in
    let data = Cstruct.create lc in
    Cstruct.set_uint8 data 0 nb_derivations ;
    let _ = write_path (Cstruct.shift data 1) path in
    data
  in
  let data = Cstruct.append path_data payload in
  let cmd = wrap_ins Make_deterministic_nonce in
  let lc = Cstruct.length data in
  if lc >= Apdu.max_data_length then
    Transport.app_error ~msg:"get_deterministic_nonce"
    @@ R.error (Payload_too_big (Cstruct.length payload))
  else
    let apdu = Apdu.create ~p2:(int_of_curve curve) ~lc ~data cmd in
    let msg = "make-deterministic-nonce" in
    Transport.apdu ~msg ?pp ?buf h apdu

let sign_and_hash ?pp ?buf h curve path payload =
  let nb_derivations = List.length path in
  if nb_derivations > 10 then invalid_arg "get_public_key: max 10 derivations" ;
  let lc = 1 + (4 * nb_derivations) in
  let data_init = Cstruct.create lc in
  Cstruct.set_uint8 data_init 0 nb_derivations ;
  let data = Cstruct.shift data_init 1 in
  let _data = write_path data path in
  let cmd = wrap_ins Sign_with_hash in
  let msg = "sign-with-hash" in
  let apdu = Apdu.create ~p2:(int_of_curve curve) ~lc ~data:data_init cmd in
  let _addr = Transport.apdu ~msg ?pp ?buf h apdu in
  Transport.write_payload ~mark_last:true ?pp ?buf ~msg ~cmd h ~p1:0x01 payload
  >>= fun bytes ->
  let hash, signature = Cstruct.split bytes 32 in
  R.return (hash, signature)

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
