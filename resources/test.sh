file="m5out/stats.txt"
read -p $file
ofile="test.txt"
while read f1 f2 f3
  do
    if [ "$f1" = "simSeconds" ]; then
      echo "PMP Size: " >> $ofile
      echo "$f1: $f2" >> $ofile 
    fi
    #echo $line
  done < $file
