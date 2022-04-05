let or_fail ~ctx = function
  | Ok v -> v
  | Error (`Msg msg) -> failwith @@ Printf.sprintf "%s: %s" ctx msg

(** File operations. *)
module File = struct
  let read filename =
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

  let read_and_decode f filename =
    or_fail ~ctx:(Printf.sprintf "reading %s" filename)
    @@ f (Cstruct.of_string (read filename))

  let with_oc ~f filename =
    let oc = open_out filename in
    try
      f oc;
      close_out oc
    with e ->
      close_out_noerr oc;
      raise e

  let write filename data =
    with_oc filename ~f:(fun oc -> output_string oc data)
end

let acquire_certificate ~interface ~port ~account ~csr ~certificate () =
  let open Lwt.Infix in
  let sleep s = Lwt_unix.sleep (Float.of_int s) in
  let acme =
    or_fail ~ctx:"initializing ACME client"
    @@ Lwt_main.run
    @@ Acme_client.initialise ~endpoint:Letsencrypt.letsencrypt_staging_url
         account
  in
  let solver, shutdown_solver =
    let stop : unit Lwt_mvar.t = Lwt_mvar.create_empty () in
    let temp_files = ref [] in
    let temp_file prefix suffix data =
      let filename, _ = Filename.open_temp_file prefix suffix in
      temp_files := filename :: !temp_files;
      File.write filename data;
      filename
    in
    let solver =
      Letsencrypt.Client.alpn_solver (fun _domain ~alpn:_ key cert ->
          let certificate_file =
            temp_file "order_cert" ".pem"
              (Cstruct.to_string (X509.Certificate.encode_pem cert))
          in
          let key_file =
            temp_file "order_key" ".pem"
              (Cstruct.to_string (X509.Private_key.encode_pem key))
          in
          ignore
            (Dream.serve ~tls:true ~interface ~port ~key_file ~certificate_file
               ~stop:(Lwt_mvar.take stop) (fun _req ->
                 failwith "acme-tls/1 server does not support this")
              : unit Lwt.t);
          sleep 1 >>= fun () -> Lwt.return_ok ())
    in
    let shutdown () =
      Lwt_mvar.put stop () >>= fun () ->
      List.iter Sys.remove !temp_files;
      Lwt.return ()
    in
    (solver, shutdown)
  in
  Lwt_main.run
    ( Acme_client.sign_certificate solver acme sleep csr >>= fun res ->
      let certs = or_fail ~ctx:"signing" res in
      File.with_oc certificate ~f:(fun oc ->
          List.iter
            (fun cert ->
              let data = Cstruct.to_string (X509.Certificate.encode_pem cert) in
              output_string oc data)
            certs);
      Dream.info (fun log -> log "OK!");
      shutdown_solver () )

let () =
  let () = Dream.initialize_log ~level:`Debug () in
  let () = Logs.set_level ~all:true (Some Info) in

  let open Cmdliner in
  let account =
    Term.(
      const @@ File.read_and_decode X509.Private_key.decode_pem
      $ Arg.(
          required
          & opt (some file) None
          & info ["account"] ~doc:"CA account private key (in PEM format)"))
  in

  let csr =
    Term.(
      const @@ File.read_and_decode X509.Signing_request.decode_pem
      $ Arg.(
          required
          & opt (some file) None
          & info ["csr"] ~doc:"Certificate Signing Request (in PEM format)"))
  in

  let certificate =
    Arg.(
      value
      & opt string "certificate.pem"
      & info ["certificate"]
          ~doc:
            "Certificate to use (in PEM format), if not exists one will be \
             issue by CA")
  in

  let key =
    Arg.(
      required & opt (some file) None & info ["key"] ~doc:"Private key to use")
  in

  let interface =
    Arg.(
      value
      & opt string "0.0.0.0"
      & info ["interface"] ~env:(Cmd.Env.info "INTERFACE")
          ~doc:"Interface to listen on")
  in

  let port =
    Arg.(
      value
      & opt int 443
      & info ["port"] ~env:(Cmd.Env.info "PORT") ~doc:"Port to listen on")
  in

  let main account csr key certificate interface port =
    if not (Sys.file_exists certificate) then
      acquire_certificate ~interface ~port ~account ~csr ~certificate ();
    assert (Sys.file_exists certificate);
    Dream.run ~tls:true ~adjust_terminal:false ~interface ~port
      ~certificate_file:certificate ~key_file:key
    @@ Dream.logger
    @@ Dream.router [Dream.get "/" (fun _req -> Dream.respond "OK")]
  in

  let cmd =
    Cmd.(
      v
        (info "dream-letsencrypt" ~version:"%%VERSION%%")
        Term.(const main $ account $ csr $ key $ certificate $ interface $ port))
  in

  exit (Cmd.eval cmd)
