#! /bin/sh
#
# etos.sh
# Copyright (C) 2020 vyouzhi <vyouzhi@localhost.localdomain>
#
# Distributed under terms of the MIT license.
#


sed -i 's/simba/etomc2/g' *.c
sed -i 's/SIMBA/ETOMC2/g' *.c
sed -i 's/Simba/Etomc2/g' *.c

sed -i 's/simba/etomc2/g' *.h
sed -i 's/SIMBA/ETOMC2/g' *.h
sed -i 's/Simba/Etomc2/g' *.h

sed -i 's/simba/etomc2/g' config
sed -i 's/SIMBA/ETOMC2/g' config


for n in `ls simba*`;do
    N=`echo $n | sed 's/simba/etomc2/'`;
    mv $n $N;
done
