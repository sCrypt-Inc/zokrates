; Auto generated by ZoKrates
; Number of circuit variables: 3
; Number of equalities: 1
(declare-const |~prime| Int)
(declare-const |~one| Int)
(declare-const |_0| Int)
(declare-const |_1| Int)
(assert (and
(= |~prime| 21888242871839275222246405745257275088548364400416034343698204186575808495617)
(= |~one| 1)
(= (mod (* (* |~one| 1) (* |_0| 1)) |~prime|) (mod (* |_1| 1) |~prime|))
))