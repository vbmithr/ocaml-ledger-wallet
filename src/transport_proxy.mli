type t

type error

val pp_error : Format.formatter -> error -> unit

val create : ?name:string -> ?port:int -> unit -> t

val close : t -> unit

(** [write_apdu ?pp ledger apdu] writes [apdu] to [ledger]. *)
val write_apdu : ?pp:Format.formatter -> t -> Apdu.t -> (unit, error) result

(** [read ledger] reads from [ledger] a status response and a
    payload. *)
val read : t -> (Status.t * Cstruct.t, error) result
