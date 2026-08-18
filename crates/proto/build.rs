fn main() {
    if std::env::var_os("CARGO_FEATURE_GRPC").is_none() {
        return;
    }

    let protoc = protoc_bin_vendored::protoc_bin_path().expect("finding vendored protoc");
    std::env::set_var("PROTOC", protoc);
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/proxy.proto"], &["proto"])
        .expect("compiling proxy gRPC protocol");
    println!("cargo:rerun-if-changed=proto/proxy.proto");
}
