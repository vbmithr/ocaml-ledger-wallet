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

let of_int = function
  | 0x6700 -> Incorrect_length
  | 0x6981 -> Incompatible_file_structure
  | 0x6982 -> Security_status_unsatisfied
  | 0x6983 -> Hid_required
  | 0x6985 -> Conditions_of_use_not_satisfied
  | 0x6a80 -> Incorrect_data
  | 0x9404 -> File_not_found
  | 0x9405 -> Parse_error
  | 0x6b00 -> Incorrect_params
  | 0x6c00 -> Incorrect_length
  | 0x6d00 -> Ins_not_supported
  | 0x6e00 -> Incorrect_class
  | 0x9000 -> Ok
  | 0x917e -> Incorrect_length_for_ins
  | 0x9200 -> Memory_error
  | 0x6a88 -> Referenced_data_not_found
  | v when v >= 0x63c0 && v <= 0x63cf -> Invalid_pin (v land 0x0f)
  | v when v >= 0x6f00 && v <= 0x6fff -> Technical_problem (v land 0xff)
  | v -> Unknown v

let string_fs = ref []

let register_string_f f = string_fs := f :: !string_fs

let to_string = function
  | Conditions_of_use_not_satisfied -> "Conditions of use not satisfied"
  | File_not_found -> "File not found"
  | Hid_required -> "HID required"
  | Incompatible_file_structure -> "Incompatible file structure"
  | Incorrect_class -> "Incorrect class"
  | Incorrect_data -> "Incorrect data"
  | Incorrect_length -> "Incorrect length"
  | Incorrect_length_for_ins -> "Incorrect length for instruction"
  | Incorrect_params -> "Incorrect parameters"
  | Ins_not_supported -> "Instruction not supported"
  | Invalid_pin i -> "Invalid pin " ^ string_of_int i
  | Memory_error -> "Memory error"
  | Ok -> "Ok"
  | Parse_error -> "Parse error"
  | Referenced_data_not_found -> "Referenced data not found"
  | Security_status_unsatisfied -> "Security status unsatisfied"
  | Technical_problem i -> "Technical problem " ^ string_of_int i
  | Unknown i -> Printf.sprintf "Unknown status code 0x%x" i
  | t -> (
      try
        List.fold_left
          (fun a f -> match f t with Some s -> failwith s | None -> a)
          "Unregistered status message"
          !string_fs
      with Failure s -> s)

let help_suggestor_f = ref (fun _ -> None)

let register_help_suggestor_f (f : t -> string option) = help_suggestor_f := f

let to_help_suggestion t = !help_suggestor_f t

let show t = to_string t

let pp ppf t =
  Format.fprintf ppf "%s%t" (to_string t) (fun ppf ->
      match to_help_suggestion t with
      | None -> ()
      | Some s -> Format.fprintf ppf " - %a" Format.pp_print_text s)

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
