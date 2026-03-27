fn main() {
    cc::Build::new()
        .file("csrc/test.c")
        .compile("test");

    let project_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-search=native={}/go", project_dir);

    println!("cargo:rustc-link-lib=static=gofuncs");
}
