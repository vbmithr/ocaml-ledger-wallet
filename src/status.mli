(*---------------------------------------------------------------------------
   Copyright (c) 2017 Vincent Bernardoff. All rights reserved.
   Distributed under the ISC license, see terms at the end of the file.
  ---------------------------------------------------------------------------*)

type t = ..

type t +=
  | Invalid_pin of int
  | Incorrect_length
  | Incorrect_length_for_ins
  | Incompatible_file_structure
  | Security_status_unsatisfied
  | Hid_required
  | Conditions_of_use_not_satisfied
  | Incorrect_data
  | File_not_found
  | Parse_error
  | Incorrect_params
  | Incorrect_class
  | Ins_not_supported
  | Memory_error
  | Referenced_data_not_found
  | Technical_problem of int
  | Ok
  | Unknown of int

val of_int : int -> t

val register_string_f : (t -> string option) -> unit

val to_string : t -> string

val register_help_suggestor_f : (t -> string option) -> unit

val to_help_suggestion : t -> string option

val show : t -> string

val pp : Format.formatter -> t -> unit

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
