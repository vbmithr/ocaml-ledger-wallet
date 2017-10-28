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

val ping : ?buf:Bigstring.t -> Hidapi.hid_device -> unit
val get_random : ?buf:Bigstring.t -> Hidapi.hid_device -> int -> string
val get_operation_mode : ?buf:Bigstring.t -> Hidapi.hid_device -> Operation_mode.t
