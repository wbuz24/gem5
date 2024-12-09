#!/bin/bash

# Sensitivity analysis script for pmp tables

# Remove the pmpEntries variable so for loop will recognize
d=0    
origtxt="pmpTable.resize($d);"
sed -i "/pmpTable.resize(pmpEntries);/c $origtxt" src/arch/riscv/pmp.cc
for i in $( seq 0 4 32)
  do
    # edit line
    echo "\n\nInput size: $i\n\n"
    txt="    pmpTable.resize($i);"
    sed -i "/pmpTable.resize($d);/c $txt" src/arch/riscv/pmp.cc

    # recomple gem5
    scons build/RISCV/gem5.opt -j 20

    # run config/secureTEEs/simple_board.py
    ./build/RISCV/gem5.opt configs/secureTEEs/simple_board.py \

    # move m5out/stats.txt ../graduate-repo/pmp/pmp_stats_$i.txt
    mv m5out/stats.txt ../grad-research/pmp/pmp_stats_$i.txt
    echo "Moved stats to ../grad-research/pmp/pmp_stats_$i.txt"

    # In the future, extract info and append to existing stats file

    d=$i

  done

# put the pmpEntries variable back for the next iteration
sed -i "/pmpTable.resize($i);/c\    pmpTable.resize(pmpEntries);" src/arch/riscv/pmp.cc
