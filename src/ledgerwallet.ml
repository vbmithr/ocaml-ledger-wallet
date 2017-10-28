module Status = struct
  type t =
    | Incorrect_length
    | Security_status_unsatisfied
    | Invalid_data
    | File_not_found
    | Incorrect_params
    | Technical_problem of int
    | Ok

  let of_int = function
    | 0x6700 -> Incorrect_length
    | 0x6982 -> Security_status_unsatisfied
    | 0x6a80 -> Invalid_data
    | 0x6a82 -> File_not_found
    | 0x6b00 -> Incorrect_params
    | 0x9000 -> Ok
    | v when v >= 0x6f00 && v <= 0x6fff -> Technical_problem v
    | _ -> invalid_arg "Status.of_int"
end

module Apdu = struct
  type ins =
    | Setup
    | Verify_pin
    | Set_operation_mode
    | Get_operation_mode
    | Set_keymap
    | Set_comm_protocol
    | Get_wallet_public_key
    | Get_trusted_input
    | Hash_input_start
    | Hash_input_finalize
    | Hash_sign
    | Hash_input_finalize_full
    | Get_internal_chain_index
    | Sign_message
    | Get_transaction_limit
    | Set_transaction_limit
    | Import_private_key
    | Get_public_key
    | Derive_bip32_key
    | Signverify_immediate
    | Get_random
    | Get_attestation
    | Get_firmware_version
    | Compose_mofn_address
    | Dongle_authenticate
    | Get_pos_seed

  let int_of_ins = function
    | Setup -> 0x20
    | Verify_pin -> 0x22
    | Set_operation_mode -> 0x24
    | Get_operation_mode -> 0x26
    | Set_keymap -> 0x28
    | Set_comm_protocol -> 0x2a
    | Get_wallet_public_key -> 0x40
    | Get_trusted_input -> 0x42
    | Hash_input_start -> 0x44
    | Hash_input_finalize -> 0x46
    | Hash_sign -> 0x48
    | Hash_input_finalize_full -> 0x4a
    | Get_internal_chain_index -> 0x4c
    | Sign_message -> 0x4e
    | Get_transaction_limit -> 0xa0
    | Set_transaction_limit -> 0xa2
    | Import_private_key -> 0xb0
    | Get_public_key -> 0xb2
    | Derive_bip32_key -> 0xb4
    | Signverify_immediate -> 0xb6
    | Get_random -> 0xc0
    | Get_attestation -> 0xc2
    | Get_firmware_version -> 0xc4
    | Compose_mofn_address -> 0xc6
    | Dongle_authenticate -> 0xc8
    | Get_pos_seed -> 0xca

  let ins_of_int = function
    | 0x20 -> Setup
    | 0x22 -> Verify_pin
    | 0x24 -> Set_operation_mode
    | 0x26 -> Get_operation_mode
    | 0x28 -> Set_keymap
    | 0x2a -> Set_comm_protocol
    | 0x40 -> Get_wallet_public_key
    | 0x42 -> Get_trusted_input
    | 0x44 -> Hash_input_start
    | 0x46 -> Hash_input_finalize
    | 0x48 -> Hash_sign
    | 0x4a -> Hash_input_finalize_full
    | 0x4c -> Get_internal_chain_index
    | 0x4e -> Sign_message
    | 0xa0 -> Get_transaction_limit
    | 0xa2 -> Set_transaction_limit
    | 0xb0 -> Import_private_key
    | 0xb2 -> Get_public_key
    | 0xb4 -> Derive_bip32_key
    | 0xb6 -> Signverify_immediate
    | 0xc0 -> Get_random
    | 0xc2 -> Get_attestation
    | 0xc4 -> Get_firmware_version
    | 0xc6 -> Compose_mofn_address
    | 0xc8 -> Dongle_authenticate
    | 0xca -> Get_pos_seed
    | _ -> invalid_arg "Adpu.ins_of_int"

  type adm_ins =
    | Init_keys
    | Init_attestation
    | Get_update_id
    | Firmware_update

  let int_of_adm_ins = function
    | Init_keys -> 0x20
    | Init_attestation -> 0x22
    | Get_update_id -> 0x24
    | Firmware_update -> 0x42

  let adm_ins_of_int = function
    | 0x20 -> Init_keys
    | 0x22 -> Init_attestation
    | 0x24 -> Get_update_id
    | 0x42 -> Firmware_update
    | _ -> invalid_arg "Adpu.adm_ins_of_int"

  let adm_cla = 0xd0
  let cla = 0xe0

  type cmd =
    | Adm_cla of adm_ins
    | Cla of ins

  type t = {
    cmd : cmd ;
    p1 : int ;
    p2 : int ;
    lc : int ;
    le : int ;
    data : string ;
  }

  let create ?(p1=0) ?(p2=0) ?(lc=0) ?(le=0) ?(data="") cmd =
    { cmd ; p1 ; p2 ; lc ; le ; data }

  let length { data } = 5 + String.length data

  let write buf pos { cmd ; p1 ; p2 ; lc ; le ; data } =
    let open EndianBigstring in
    let len = match lc, le with | 0, _ -> le | _ -> lc in
    let datalen = String.length data in
    begin match cmd with
    | Adm_cla i ->
      BigEndian.set_int8 buf pos adm_cla ;
      BigEndian.set_int8 buf (pos+1) (int_of_adm_ins i)
    | Cla i ->
      BigEndian.set_int8 buf pos cla ;
      BigEndian.set_int8 buf (pos+1) (int_of_ins i)
    end ;
    BigEndian.set_int8 buf (pos+2) p1 ;
    BigEndian.set_int8 buf (pos+3) p2 ;
    BigEndian.set_int8 buf (pos+4) len ;
    Bigstring.blit_of_string data 0 buf (pos+5) datalen ;
    pos + 5 + datalen
end

module Transport : sig
  type t =
    | Ping
    | Apdu of Apdu.t

  val packet_length : int
  val length : t -> int
  val write : EndianBigstring.bigstring -> int -> t -> int
  val read : EndianBigstring.bigstring -> int -> string
end = struct
  let packet_length = 64
  let channel = 0x0101
  let apdu = 0x05
  let ping = 0x02

  module Header = struct
    type t = {
      cmd : [`Ping | `Apdu] ;
      seq : int ;
    }

    let read buf pos =
      let open EndianBigstring in
      if BigEndian.get_int16 buf pos <> channel then
        invalid_arg "Transport.read_header: invalid channel id" ;
      let cmd = match BigEndian.get_int8 buf (pos+2) with
        | 0x05 -> `Apdu
        | 0x02 -> `Ping
        | _ -> invalid_arg "Transport.read_header: invalid command tag"
      in
      let seq = BigEndian.get_int16 buf (pos+3) in
      { cmd ; seq }, pos + 5

    let check_exn ?cmd ?seq t =
      begin match cmd with
      | None -> ()
      | Some expected ->
        if expected <> t.cmd then failwith "Header.check: unexpected command"
      end ;
      begin match seq with
        | None -> ()
        | Some expected ->
          if expected <> t.seq then failwith "Header.check: unexpected seq num"
      end

    let check ?cmd ?seq t =
      try Result.Ok (check_exn ?cmd ?seq t)
      with Failure msg -> Result.Error msg

    let length = 5
  end

  type t =
    | Ping
    | Apdu of Apdu.t

  let length = function
    | Ping -> 5
    | Apdu apdu ->
      let apdu_len = Apdu.length apdu in
      if apdu_len < packet_length - 7 then packet_length else
      let rec inner acc rest =
        if rest < packet_length - 5 then acc + packet_length
        else inner (acc + packet_length) (rest - (packet_length - 5))
      in
      inner packet_length (apdu_len - (packet_length - 7))

  let write (buf : EndianBigstring.bigstring) pos = function
    | Ping ->
      let open EndianBigstring in
      BigEndian.set_int16 buf pos channel ;
      BigEndian.set_int8 buf (pos+2) ping ;
      BigEndian.set_int16 buf (pos+3) 0 ;
      Bigstring.fill_slice buf '\x00' 5 59 ;
      pos + packet_length

    | Apdu ({ cmd ; p1 ; p2 ; lc ; le ; data } as p) ->
      let apdu_len = Apdu.length p in
      let apdu_buf = Bigstring.create apdu_len in
      let _nb_written = Apdu.write apdu_buf 0 p in
      let apdu_p = ref 0 in (* pos in the apdu buf *)
      let i = ref 0 in (* packet id *)
      let p = ref pos in (* pos in the result buf *)
      let open EndianBigstring in

      (* write first packet *)
      BigEndian.set_int16 buf !p channel ;
      BigEndian.set_int8 buf (!p+2) apdu ;
      BigEndian.set_int16 buf (!p+3) !i ;
      BigEndian.set_int16 buf (!p+5) apdu_len ;
      let nb_to_write = (min apdu_len (packet_length - 7)) in
      Bigstring.blit apdu_buf 0 buf (!p+7) nb_to_write ;
      p := !p + 7 + nb_to_write ;
      apdu_p := !apdu_p + nb_to_write ;
      incr i ;

      (* write following packets *)
      while !apdu_p < apdu_len do
        BigEndian.set_int16 buf !p channel ;
        BigEndian.set_int8 buf (!p+2) apdu ;
        BigEndian.set_int16 buf (!p+3) !i ;
        let nb_to_write = (min (apdu_len - !apdu_p) (packet_length - 5)) in
        Bigstring.blit apdu_buf !apdu_p buf (!p+5) nb_to_write ;
        p := !p + 5 + nb_to_write ;
        apdu_p := !apdu_p + nb_to_write ;
        incr i
      done ;

      (* write trailing zeros if needed *)
      let total_written = !p - pos in
      match total_written mod packet_length with
      | 0 -> pos + total_written
      | rem ->
        Bigstring.fill_slice buf '\x00' !p (packet_length - rem) ;
        pos + total_written + (packet_length - rem)

  let read buf pos =
    let hdr, pos = Header.read buf pos in
    let cmd = hdr.cmd in
    Header.check_exn ~seq:0 hdr ;
    let len = EndianBigstring.BigEndian.get_int16 buf pos in
    let i = ref 0 in
    let p = ref (pos + 2) in
    let out = Bytes.create len in
    let nb_to_read = min len (packet_length - 7) in

    let out_p = ref 0 in
    Bigstring.blit_to_bytes buf !p out !out_p nb_to_read ;
    out_p := !out_p + nb_to_read ;
    p := !p + nb_to_read ;
    incr i ;
    while len - !out_p > 0 do
      let hdr, pos = Header.read buf !p in
      Header.check_exn ~cmd ~seq:!i hdr ;
      let nb_to_read = min (len - !out_p) (packet_length - Header.length) in
      Bigstring.blit_to_bytes buf pos out !out_p nb_to_read ;
      p := pos + nb_to_read ;
      out_p := !out_p + nb_to_read
    done ;
    out
end

let ping h =
  let buf = Bigstring.create Transport.packet_length in
  let nb_written = Transport.write buf 0 Ping in
  let nb_written' = Hidapi.hid_write h buf nb_written in
  assert (nb_written = nb_written' && nb_written = Transport.packet_length) ;
  let nb_read = Hidapi.hid_read_timeout ~timeout:1000 h buf Transport.packet_length in
  assert (nb_read = Transport.packet_length) ;
  let payload = Transport.read buf 0 in
  assert (payload = "")

let get_random h len =
  let random_string = Bigstring.create len in
  let apdu = Apdu.(create ~le:len (Cla Get_random)) in
  let len = Transport.length (Apdu apdu) in
  let buf = Bigstring.create len in
  let _nb_written = Transport.write buf 0 (Apdu apdu) in
  let _nb_written' = Hidapi.hid_write h buf len in
  let nb_read = Hidapi.hid_read_timeout ~timeout:1000 h random_string 0 in
  Bigstring.sub_string buf 0 nb_read

let get_public_key indices =
  let nb_indices = List.length indices in
  if nb_indices > 10 then
    invalid_arg "Wallet.get_pubkeys: indices > 10" ;
  let lc = 1 + 4 * nb_indices in
  Apdu.(create ~lc (Cla Get_public_key))

