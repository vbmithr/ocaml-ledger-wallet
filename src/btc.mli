(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

module Operation_mode : sig
  type mode =
    | Standard
    | Relaxed
    | Server
    | Developer [@@deriving sexp]

  type t = {
    mode : mode ;
    seed_not_redeemed : bool ;
  } [@@deriving sexp]
end

module Second_factor : sig
  type t =
    | Keyboard
    | Card
    | Card_screen [@@deriving sexp]
end

module Firmware_version : sig
  type flag =
    | Public_key_compressed
    | Internal_screen_buttons
    | External_screen_buttons
    | Nfc
    | Ble
    | Tee
  [@@deriving sexp]

  type t = {
    flags : flag list ;
    arch : int ;
    major : int ;
    minor : int ;
    patch : int ;
    loader_major : int ;
    loader_minor : int ;
    loader_patch : int ;
  } [@@deriving sexp]
end

module Public_key : sig
  type t = {
    uncompressed : Cstruct.t ;
    b58addr : string ;
    bip32_chaincode : Cstruct.t ;
  } [@@deriving sexp]
end

val ping : ?buf:Cstruct.t -> Hidapi.t -> unit
val get_random : ?buf:Cstruct.t -> Hidapi.t -> int -> string
val get_operation_mode : ?buf:Cstruct.t -> Hidapi.t -> Operation_mode.t
val get_second_factor : ?buf:Cstruct.t -> Hidapi.t -> Second_factor.t
val get_firmware_version : ?buf:Cstruct.t -> Hidapi.t -> Firmware_version.t
val verify_pin : ?buf:Cstruct.t -> Hidapi.t -> string -> [`Ok | `Need_power_cycle]
val get_remaining_pin_attempts : ?buf:Cstruct.t -> Hidapi.t -> int
val get_wallet_public_key :
  ?pp:Format.formatter ->
  ?buf:Cstruct.t -> Hidapi.t -> Bitcoin.Wallet.KeyPath.t -> Public_key.t
val get_trusted_input :
  ?pp:Format.formatter ->
  ?buf:Cstruct.t -> Hidapi.t -> Bitcoin.Protocol.Transaction.t -> int -> Cstruct.t

type input_type =
  | Untrusted
  | Trusted of Cstruct.t list
  | Segwit of Int64.t list

val hash_tx_input_start :
  ?pp:Format.formatter ->
  ?buf:Cstruct.t -> new_transaction:bool -> input_type:input_type -> Hidapi.t ->
  Bitcoin.Protocol.Transaction.t -> int -> unit

val hash_tx_finalize_full :
  ?pp:Format.formatter ->
  ?buf:Cstruct.t -> Hidapi.t -> Bitcoin.Protocol.Transaction.t -> Cstruct.t

module HashType : sig
  type typ =
    | All
    | None
    | Single

  type flag =
    | ForkId
    | AnyoneCanPay

  type t = {
    typ: typ ;
    flags: flag list ;
  }
end

val hash_sign :
  ?pp:Format.formatter ->
  ?buf:Cstruct.t -> path:Bitcoin.Wallet.KeyPath.t ->
  hash_type:HashType.typ -> hash_flags:HashType.flag list ->
  Hidapi.t -> Bitcoin.Protocol.Transaction.t -> Cstruct.t

val sign :
  ?pp:Format.formatter ->
  ?buf:Cstruct.t ->
  path:Bitcoin.Wallet.KeyPath.t ->
  prev_outputs:(Bitcoin.Protocol.Transaction.t * int) list ->
  Hidapi.t -> Bitcoin.Protocol.Transaction.t -> Cstruct.t list

val sign_segwit :
  ?pp:Format.formatter ->
  ?bch:bool ->
  ?buf:Cstruct.t ->
  path:Bitcoin.Wallet.KeyPath.t ->
  prev_amounts:Int64.t list ->
  Hidapi.t -> Bitcoin.Protocol.Transaction.t -> Cstruct.t list

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
