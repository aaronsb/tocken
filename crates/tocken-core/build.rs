fn main() {
    // Compile proto/migration.proto → OUT_DIR/_.rs which
    // src/enroll/migration.rs include!()s. We have no `package` in
    // the .proto so prost emits a single underscored module name.
    println!("cargo:rerun-if-changed=proto/migration.proto");
    prost_build::compile_protos(&["proto/migration.proto"], &["proto/"])
        .expect("prost compile migration.proto");
}
