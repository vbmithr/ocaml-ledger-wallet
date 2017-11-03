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

val ping : ?buf:Cstruct.t -> Hidapi.hid_device -> unit
val get_random : ?buf:Cstruct.t -> Hidapi.hid_device -> int -> string
val get_operation_mode : ?buf:Cstruct.t -> Hidapi.hid_device -> Operation_mode.t
val get_second_factor : ?buf:Cstruct.t -> Hidapi.hid_device -> Second_factor.t
val get_firmware_version : ?buf:Cstruct.t -> Hidapi.hid_device -> Firmware_version.t
val verify_pin : ?buf:Cstruct.t -> Hidapi.hid_device -> string -> [`Ok | `Need_power_cycle]
val get_remaining_pin_attempts : ?buf:Cstruct.t -> Hidapi.hid_device -> int
val get_wallet_pubkeys :
  ?buf:Cstruct.t -> Hidapi.hid_device -> Bitcoin.Wallet.KeyPath.t -> Public_key.t
val get_trusted_input :
  ?buf:Cstruct.t -> Hidapi.hid_device -> Bitcoin.Protocol.Transaction.t -> int -> Cstruct.t

type input_type =
  | Untrusted
  | Trusted of Cstruct.t list
  | Segwit of Int64.t list

val hash_tx_input_start :
  ?buf:Cstruct.t -> new_transaction:bool -> input_type:input_type -> Hidapi.hid_device ->
  Bitcoin.Protocol.Transaction.t -> int -> unit

val hash_tx_finalize_full :
  ?buf:Cstruct.t -> Hidapi.hid_device -> Bitcoin.Protocol.Transaction.t -> Cstruct.t

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
  ?buf:Cstruct.t -> path:Bitcoin.Wallet.KeyPath.t ->
  hash_type:HashType.typ -> hash_flags:HashType.flag list ->
  Hidapi.hid_device -> Bitcoin.Protocol.Transaction.t -> Cstruct.t * HashType.t

val sign :
  ?buf:Cstruct.t ->
  path:Bitcoin.Wallet.KeyPath.t ->
  prev_outputs:(Bitcoin.Protocol.Transaction.t * int) list ->
  Hidapi.hid_device -> Bitcoin.Protocol.Transaction.t -> Cstruct.t list

val sign_segwit :
  ?bch:bool ->
  ?buf:Cstruct.t ->
  path:Bitcoin.Wallet.KeyPath.t ->
  prev_amounts:Int64.t list ->
  Hidapi.hid_device -> Bitcoin.Protocol.Transaction.t -> Cstruct.t list

