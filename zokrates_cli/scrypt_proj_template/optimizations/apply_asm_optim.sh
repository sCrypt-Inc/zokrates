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
apply scrypts/src/contracts/verifier.scrypt optimizations/ec/bn256
