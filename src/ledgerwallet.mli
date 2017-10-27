module Status : sig
  type t =
    | Incorrect_length
    | Security_status_unsatisfied
    | Invalid_data
    | File_not_found
    | Incorrect_params
    | Technical_problem of int
    | Ok
end

val ping : Usb.handle -> unit Lwt.t
