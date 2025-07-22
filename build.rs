fn main() {
    prost_build::Config::new()
        .out_dir("src/proto")
        .compile_protos(&["proto/block.proto", "proto/transaction.proto", "proto/finality.proto"], &["proto"])
        .unwrap();
} 