mod solver_flint;

use ::field::Fp;

use self::solver_flint::Solver;

trait Solve {
    fn solve(power_sums: &Vec<Fp>, my_message: &Fp) -> Option<Vec<Fp>>;
}

pub fn solve(power_sums: Vec<Fp>) {
}
