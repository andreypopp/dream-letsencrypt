(** ACME client which uses Hyper as HTTP client. *)

include Letsencrypt.Client.Make (struct
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
