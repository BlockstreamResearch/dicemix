mod solver_flint;

// "bindgen --whitelist-function solve --output solver_flint.rs solver_flint.h"
// was used to generate the bindings.
use self::solver_flint::solve as solve_flint;

pub fn solve() {
}
