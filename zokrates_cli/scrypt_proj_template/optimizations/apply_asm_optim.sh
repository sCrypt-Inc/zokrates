#!/bin/sh


apply() {
    scryptSrc=$1
    dirOptim=$2

    for fAsm in $(find $dirOptim -type f -name '*.asm'); do
        funcName=$(basename $fAsm .asm)
        node optimizations/replaceFuncBodyAsm.js $scryptSrc $funcName $fAsm > $scryptSrc.tmp
        mv $scryptSrc.tmp $scryptSrc
    done

}

# BN256
apply artifacts/src/contracts/snark.scrypt optimizations/ec/bn256
