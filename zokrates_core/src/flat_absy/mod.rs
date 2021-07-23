//! Module containing structs and enums to represent a program.
//!
//! @file absy.rs
//! @author Dennis Kuhnert <dennis.kuhnert@campus.tu-berlin.de>
//! @author Jacob Eberhardt <jacob.eberhardt@tu-berlin.de>
//! @date 2017

pub mod flat_parameter;
pub mod flat_variable;

pub use self::flat_parameter::FlatParameter;
pub use self::flat_variable::FlatVariable;

use serde::{Deserialize, Serialize};

use crate::solvers::Solver;
use std::collections::HashMap;
use std::fmt;
use zokrates_field::Field;

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub enum RuntimeError {
    BellmanConstraint,
    BellmanOneBinding,
    BellmanInputBinding,
    ArkConstraint,
    ArkOneBinding,
    ArkInputBinding,
    Bitness,
    Sum,
    Equal,
    Le,
    BranchIsolation,
    ConstantLtBitness,
    ConstantLtSum,
    LtBitness,
    LtSum,
    LtFinalBitness,
    LtFinalSum,
    Or,
    Xor,
    Inverse,
    Euclidean,
    ShaXor,
    Division,
    Source,
    ArgumentBitness,
    SelectRangeCheck,
}

impl RuntimeError {
    fn is_malicious(&self) -> bool {
        use RuntimeError::*;

        !matches!(
            self,
            Source | Inverse | LtSum | SelectRangeCheck | ArgumentBitness
        )
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use RuntimeError::*;

        let msg = match self {
            BellmanConstraint => "Bellman constraint is unsatisfied",
            BellmanOneBinding => "Bellman ~one binding is unsatisfied",
            BellmanInputBinding => "Bellman input binding is unsatisfied",
            ArkConstraint => "Ark constraint is unsatisfied",
            ArkOneBinding => "Ark ~one binding is unsatisfied",
            ArkInputBinding => "Ark input binding is unsatisfied",
            Bitness => "Bitness check failed",
            Sum => "Sum check failed",
            Equal => "Equal check failed",
            Le => "Constant Le check failed",
            BranchIsolation => "Branch isolation failed",
            ConstantLtBitness => "Bitness check failed in constant Lt check",
            ConstantLtSum => "Sum check failed in constant Lt check",
            LtBitness => "Bitness check failed in Lt check",
            LtSum => "Sum check failed in Lt check",
            LtFinalBitness => "Bitness check failed in final Lt check",
            LtFinalSum => "Sum check failed in final Lt check",
            Or => "Or check failed",
            Xor => "Xor check failed",
            Inverse => "Division by zero",
            Euclidean => "Euclidean check failed",
            ShaXor => "Internal Sha check failed",
            Division => "Division check failed",
            Source => "User assertion failed",
            ArgumentBitness => "Argument bitness check failed",
            SelectRangeCheck => "Out of bounds array access",
        };

        write!(f, "{}", msg)?;

        if self.is_malicious() {
            writeln!(f)?;
            write!(f, "The default ZoKrates interpreter should not yield this error. Please open an issue")?;
        }

        write!(f, "")
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct FlatProg<T> {
    /// FlatFunctions of the program
    pub main: FlatFunction<T>,
}

impl<T: Field> fmt::Display for FlatProg<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.main)
    }
}

impl<T: Field> fmt::Debug for FlatProg<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "flat_program(main: {}\t)", self.main)
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct FlatFunction<T> {
    /// Arguments of the function
    pub arguments: Vec<FlatParameter>,
    /// Vector of statements that are executed when running the function
    pub statements: Vec<FlatStatement<T>>,
}

impl<T: Field> fmt::Display for FlatFunction<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "def main({}):\n{}",
            self.arguments
                .iter()
                .map(|x| format!("{}", x))
                .collect::<Vec<_>>()
                .join(","),
            self.statements
                .iter()
                .map(|x| format!("\t{}", x))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }
}

impl<T: Field> fmt::Debug for FlatFunction<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "FlatFunction(arguments: {:?}):\n{}",
            self.arguments,
            self.statements
                .iter()
                .map(|x| format!("\t{:?}", x))
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }
}

/// Calculates a flattened function based on a R1CS (A, B, C) and returns that flattened function:
/// * The Rank 1 Constraint System (R1CS) is defined as:
/// * `<A,x>*<B,x> = <C,x>` for a witness `x`
/// * Since the matrices in R1CS are usually sparse, the following encoding is used:
/// * For each constraint (i.e., row in the R1CS), only non-zero values are supplied and encoded as a tuple (index, value).
///
/// # Arguments
///
/// * r1cs - R1CS in standard JSON data format

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum FlatStatement<T> {
    Return(FlatExpressionList<T>),
    Condition(FlatExpression<T>, FlatExpression<T>, RuntimeError),
    Definition(FlatVariable, FlatExpression<T>),
    Directive(FlatDirective<T>),
}

impl<T: Field> fmt::Display for FlatStatement<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            FlatStatement::Definition(ref lhs, ref rhs) => write!(f, "{} = {}", lhs, rhs),
            FlatStatement::Return(ref expr) => write!(f, "return {}", expr),
            FlatStatement::Condition(ref lhs, ref rhs, ref message) => {
                write!(f, "{} == {} // {}", lhs, rhs, message)
            }
            FlatStatement::Directive(ref d) => write!(f, "{}", d),
        }
    }
}

impl<T: Field> fmt::Debug for FlatStatement<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            FlatStatement::Definition(ref lhs, ref rhs) => write!(f, "{} = {}", lhs, rhs),
            FlatStatement::Return(ref expr) => write!(f, "FlatReturn({:?})", expr),
            FlatStatement::Condition(ref lhs, ref rhs, ref error) => {
                write!(f, "FlatCondition({:?}, {:?}, {:?})", lhs, rhs, error)
            }
            FlatStatement::Directive(ref d) => write!(f, "{:?}", d),
        }
    }
}

impl<T: Field> FlatStatement<T> {
    pub fn apply_substitution(
        self,
        substitution: &HashMap<FlatVariable, FlatVariable>,
    ) -> FlatStatement<T> {
        match self {
            FlatStatement::Definition(id, x) => FlatStatement::Definition(
                *id.apply_substitution(substitution),
                x.apply_substitution(substitution),
            ),
            FlatStatement::Return(x) => FlatStatement::Return(x.apply_substitution(substitution)),
            FlatStatement::Condition(x, y, message) => FlatStatement::Condition(
                x.apply_substitution(substitution),
                y.apply_substitution(substitution),
                message,
            ),
            FlatStatement::Directive(d) => {
                let outputs = d
                    .outputs
                    .into_iter()
                    .map(|o| *o.apply_substitution(substitution))
                    .collect();
                let inputs = d
                    .inputs
                    .into_iter()
                    .map(|i| i.apply_substitution(substitution))
                    .collect();

                FlatStatement::Directive(FlatDirective {
                    inputs,
                    outputs,
                    ..d
                })
            }
        }
    }
}

#[derive(Clone, Hash, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatDirective<T> {
    pub inputs: Vec<FlatExpression<T>>,
    pub outputs: Vec<FlatVariable>,
    pub solver: Solver,
}

impl<T: Field> FlatDirective<T> {
    pub fn new<E: Into<FlatExpression<T>>>(
        outputs: Vec<FlatVariable>,
        solver: Solver,
        inputs: Vec<E>,
    ) -> Self {
        let (in_len, out_len) = solver.get_signature();
        assert_eq!(in_len, inputs.len());
        assert_eq!(out_len, outputs.len());
        FlatDirective {
            solver,
            inputs: inputs.into_iter().map(|i| i.into()).collect(),
            outputs,
        }
    }
}

impl<T: Field> fmt::Display for FlatDirective<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "# {} = {}({})",
            self.outputs
                .iter()
                .map(|o| o.to_string())
                .collect::<Vec<String>>()
                .join(", "),
            self.solver,
            self.inputs
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<String>>()
                .join(", ")
        )
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlatExpression<T> {
    Number(T),
    Identifier(FlatVariable),
    Add(Box<FlatExpression<T>>, Box<FlatExpression<T>>),
    Sub(Box<FlatExpression<T>>, Box<FlatExpression<T>>),
    Mult(Box<FlatExpression<T>>, Box<FlatExpression<T>>),
}

impl<T: Field> From<T> for FlatExpression<T> {
    fn from(other: T) -> Self {
        Self::Number(other)
    }
}

impl<T: Field> FlatExpression<T> {
    pub fn apply_substitution(
        self,
        substitution: &HashMap<FlatVariable, FlatVariable>,
    ) -> FlatExpression<T> {
        match self {
            e @ FlatExpression::Number(_) => e,
            FlatExpression::Identifier(id) => {
                FlatExpression::Identifier(*id.apply_substitution(substitution))
            }
            FlatExpression::Add(e1, e2) => FlatExpression::Add(
                box e1.apply_substitution(substitution),
                box e2.apply_substitution(substitution),
            ),
            FlatExpression::Sub(e1, e2) => FlatExpression::Sub(
                box e1.apply_substitution(substitution),
                box e2.apply_substitution(substitution),
            ),
            FlatExpression::Mult(e1, e2) => FlatExpression::Mult(
                box e1.apply_substitution(substitution),
                box e2.apply_substitution(substitution),
            ),
        }
    }

    pub fn is_linear(&self) -> bool {
        match *self {
            FlatExpression::Number(_) | FlatExpression::Identifier(_) => true,
            FlatExpression::Add(ref x, ref y) | FlatExpression::Sub(ref x, ref y) => {
                x.is_linear() && y.is_linear()
            }
            FlatExpression::Mult(ref x, ref y) => matches!(
                (x.clone(), y.clone()),
                (box FlatExpression::Number(_), box FlatExpression::Number(_))
                    | (
                        box FlatExpression::Number(_),
                        box FlatExpression::Identifier(_)
                    )
                    | (
                        box FlatExpression::Identifier(_),
                        box FlatExpression::Number(_)
                    )
            ),
        }
    }
}

impl<T: Field> fmt::Display for FlatExpression<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            FlatExpression::Number(ref i) => write!(f, "{}", i),
            FlatExpression::Identifier(ref var) => write!(f, "{}", var),
            FlatExpression::Add(ref lhs, ref rhs) => write!(f, "({} + {})", lhs, rhs),
            FlatExpression::Sub(ref lhs, ref rhs) => write!(f, "({} - {})", lhs, rhs),
            FlatExpression::Mult(ref lhs, ref rhs) => write!(f, "({} * {})", lhs, rhs),
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for FlatExpression<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            FlatExpression::Number(ref i) => write!(f, "Num({:?})", i),
            FlatExpression::Identifier(ref var) => write!(f, "Ide({})", var),
            FlatExpression::Add(ref lhs, ref rhs) => write!(f, "Add({:?}, {:?})", lhs, rhs),
            FlatExpression::Sub(ref lhs, ref rhs) => write!(f, "Sub({:?}, {:?})", lhs, rhs),
            FlatExpression::Mult(ref lhs, ref rhs) => write!(f, "Mult({:?}, {:?})", lhs, rhs),
        }
    }
}

impl<T: Field> From<FlatVariable> for FlatExpression<T> {
    fn from(v: FlatVariable) -> FlatExpression<T> {
        FlatExpression::Identifier(v)
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct FlatExpressionList<T> {
    pub expressions: Vec<FlatExpression<T>>,
}

impl<T: Field> fmt::Display for FlatExpressionList<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, param) in self.expressions.iter().enumerate() {
            write!(f, "{}", param)?;
            if i < self.expressions.len() - 1 {
                write!(f, ", ")?;
            }
        }
        write!(f, "")
    }
}

impl<T: Field> FlatExpressionList<T> {
    pub fn apply_substitution(
        self,
        substitution: &HashMap<FlatVariable, FlatVariable>,
    ) -> FlatExpressionList<T> {
        FlatExpressionList {
            expressions: self
                .expressions
                .into_iter()
                .map(|e| e.apply_substitution(substitution))
                .collect(),
        }
    }
}

impl<T: Field> fmt::Debug for FlatExpressionList<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ExpressionList({:?})", self.expressions)
    }
}

#[derive(PartialEq, Debug)]
pub struct Error {
    message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
