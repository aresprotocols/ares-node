
echo -n "Input SECRET"
read SECRET
echo -n "Input key: $SECRET"

for i in 1 2 3 4; do for j in stash controller; do subkey inspect "$SECRET//$i//$j"; done; done
for i in 1 2 3 4; do for j in babe; do subkey inspect "$SECRET//$i//$j" --scheme Sr25519; done; done
for i in 1 2 3 4; do for j in grandpa; do subkey inspect "$SECRET//$i//$j" --scheme Ed25519; done; done
for i in 1 2 3 4; do for j in im_online; do subkey inspect "$SECRET//$i//$j" --scheme Sr25519; done; done