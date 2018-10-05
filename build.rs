extern crate gcc;

fn main() {
    // Compile the external code
    let mut conf = gcc::Build::new();

    if cfg!(debug_assertions) {
        conf.define("DEBUG", None);
    }

    conf.cpp(true)
        .include("/usr/local/include/flint")
        .file("src/solver/solver_flint/solver_flint.cpp")
        .compile("libsolver_flint.a");

    // Tell rustc to link against flint and gmp
    println!("cargo:rustc-link-lib=flint");
    println!("cargo:rustc-link-lib=gmp");
}
