#!/bin/bash

# Sensitivity analysis script for pmp tables

# Remove the pmpEntries variable so for loop will recognize
d=0    
origtxt="pmpTable.resize($d);"
ofile="../grad-research/pmp/pmp_stats.txt"
file="m5out/stats.txt"
sed -i "/pmpTable.resize(pmpEntries);/c $origtxt" src/arch/riscv/pmp.cc
for i in $( seq 0 4 32)
  do
    # edit line
    echo ""
    txt="    pmpTable.resize($i);"
    sed -i "/pmpTable.resize($d);/c $txt" src/arch/riscv/pmp.cc

    # recomple gem5
    scons build/RISCV/gem5.opt -j 20

    # run config/secureTEEs/simple_board.py
    ./build/RISCV/gem5.opt configs/secureTEEs/riscvTEE.py \

    # Extract useful info and append to existing stats file
      # interested in:
      #  - sim time
      #  - host memory
      #  - # of instructions
    read -p $file
    while read f1 f2 f3
      do
      if [ "$f1" = "simSeconds" ]; then
        echo "PMP Size: $i" >> $ofile
        echo "$f1: $f2" >> $ofile 
      fi  
      if [ "$f1" = "hostMemory" ]; then
        echo "$f1: $f2" >> $ofile
      fi
      if [ "$f1" = "simInsts" ]; then
        echo "$f1: $f2" >> $ofile
      fi
      #echo $line
    done < $file

    # move m5out/stats.txt ../graduate-repo/pmp/pmp_stats_$i.txt
    mv $file ../grad-research/pmp/pmp_stats_$i.txt
    echo "Moved stats to ../grad-research/pmp/pmp_stats_$i.txt"

    d=$i

  done

# put the pmpEntries variable back for the next iteration
sed -i "/pmpTable.resize($i);/c\    pmpTable.resize(pmpEntries);" src/arch/riscv/pmp.cc
