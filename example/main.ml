module Hyper_acme_client = Letsencrypt.Client.Make (struct
  type ctx = unit

  module Headers = struct
    type t = (string * string) list

    let add hs h v = (String.lowercase_ascii h, v) :: hs
    let get hs h = List.assoc_opt (String.lowercase_ascii h) hs
    let get_location hs = Option.map Uri.of_string (get hs "location")
    let init_with h v = [(String.lowercase_ascii h, v)]

    let to_string hs =
      hs
      |> List.map (fun (h, v) -> Printf.sprintf "%s: %s" h v)
      |> String.concat "\n"
  end

  module Body = struct
    type t = string

    let of_string v = v
    let to_string v = Lwt.return v
  end

  module Response = struct
    type t = Hyper.response

    let status resp = Hyper.status_to_int (Hyper.status resp)
    let headers resp = Hyper.all_headers resp
  end

  let head ?ctx:_ ?headers uri =
    Hyper.run @@ Hyper.request ~method_:`HEAD ?headers (Uri.to_string uri)

  let run_and_read_body req =
    let open Lwt.Infix in
    Hyper.run req >>= fun resp ->
    Hyper.body resp >|= fun body -> (resp, body)

  let get ?ctx:_ ?headers uri =
    run_and_read_body
    @@ Hyper.request ~method_:`GET ?headers (Uri.to_string uri)

  let post ?ctx:_ ?body ?chunked:_ ?headers uri =
    run_and_read_body
    @@ Hyper.request ~method_:`POST ?headers ?body (Uri.to_string uri)
end)

let read_file filename =
  let ic = open_in filename in
  let buf = Buffer.create 2028 in
  let rec aux () =
    match input_line ic with
    | line ->
      Buffer.add_string buf line;
      Buffer.add_char buf '\n';
      aux ()
    | exception End_of_file -> Buffer.contents buf
  in
  try
    let data = aux () in
    close_in ic;
    data
  with e ->
    close_in_noerr ic;
    raise e

let write_file filename data =
  let oc = open_out filename in
  try
    output_string oc data;
    close_out oc
  with e ->
    close_out_noerr oc;
    raise e

let or_fail ~ctx = function
  | Ok v -> v
  | Error (`Msg msg) -> failwith @@ Printf.sprintf "%s: %s" ctx msg

let main _req = Dream.respond "OK"

let () =
  let () = Dream.initialize_log ~level:`Debug () in
  let () = Logs.set_level ~all:true (Some Info) in
  let account =
    or_fail ~ctx:"reading account.pem"
    @@ X509.Private_key.decode_pem (Cstruct.of_string (read_file "account.pem"))
  in
  let csr =
    or_fail ~ctx:"reading csr.pem"
    @@ X509.Signing_request.decode_pem (Cstruct.of_string (read_file "csr.pem"))
  in
  let acme =
    or_fail ~ctx:"initializing ACME client"
    @@ Lwt_main.run
    @@ Hyper_acme_client.initialise
         ~endpoint:Letsencrypt.letsencrypt_staging_url account
  in
  let solver, shutdown =
    let stop : unit Lwt_mvar.t = Lwt_mvar.create_empty () in
    let solver =
      Letsencrypt.Client.alpn_solver (fun _domain ~alpn key cert ->
          let open Lwt.Infix in
          let certificate_file = "order_cert.pem" in
          let key_file = "order_key.pem" in
          write_file certificate_file
            (Cstruct.to_string (X509.Certificate.encode_pem cert));
          write_file key_file
            (Cstruct.to_string (X509.Private_key.encode_pem key));
          print_endline alpn;
          let _server =
            Dream.serve ~tls:true ~interface:"10.0.1.20" ~port:4443 ~key_file
              ~certificate_file ~stop:(Lwt_mvar.take stop)
            @@ Dream.logger
            @@ Dream.router [Dream.get "/" main]
          in
          Lwt_unix.sleep 1.0 >>= fun _ -> Lwt.return_ok ())
    in
    let shutdown () = Lwt_mvar.put stop () in
    (solver, shutdown)
  in
  let () =
    Lwt_main.run
      (let open Lwt.Infix in
      Hyper_acme_client.sign_certificate solver acme
        (fun s -> Lwt_unix.sleep (Float.of_int s))
        csr
      >>= fun res ->
      let certs = or_fail ~ctx:"signing CSR" res in
      List.iteri
        (fun idx cert ->
          let filename = Printf.sprintf "cert%d.pem" idx in
          let data = Cstruct.to_string (X509.Certificate.encode_pem cert) in
          write_file filename data)
        certs;
      print_endline "OK!";
      shutdown ())
  in
  let interface =
    Option.value (Sys.getenv_opt "INTERFACE") ~default:"127.0.0.1"
  in
  Dream.run ~tls:true ~adjust_terminal:false ~interface ~port:4443
    ~certificate_file:"cert0.pem" ~key_file:"privkey.pem"
  @@ Dream.logger
  @@ Dream.router [Dream.get "/" main]
