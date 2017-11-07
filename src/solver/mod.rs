mod solver_flint;

use ::dc::fp::Fp;

use self::solver_flint::Solver;

trait Solve {
    fn solve(power_sums: &Vec<Fp>) -> Option<Vec<Fp>>;
}
