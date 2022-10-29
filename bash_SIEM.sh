#!/bin/bash
path="./honeypot.txt"
file=$(cat $path)

bi="Top_IpAddress"
bu="Top_UserNames"
bp="Top_Passwords"
bz="Top__Commands"
ba="Top_Successfully_Hacked_Account"
bc="Count"
bx="Percentage"

i_cont=$(echo "$file" | grep -o "\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}" | grep -v "10\(\.[0-9]\{1,3\}\)\{3\}\|192\.168\(\.[0-9]\{1,3\}\)\|172\.\(1[6-9]\|2[0-9]\|3[01]\)\.[0-9]\{1,3\}\.[0-9]\{1,3\}\|127.0.0.1" | sort -d | uniq -c | sort -rn | awk '{print $1}' | head -n 10)
i_name=$(echo "$file" | grep -o "\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}" | grep -v "10\(\.[0-9]\{1,3\}\)\{3\}\|192\.168\(\.[0-9]\{1,3\}\)\|172\.\(1[6-9]\|2[0-9]\|3[01]\)\.[0-9]\{1,3\}\.[0-9]\{1,3\}\|127.0.0.1" | sort -d | uniq -c | sort -rn | awk '{print $2}' | head -n 10)
u_cont=$(echo "$file" | grep -w "login attempt" | sed -n -e 's/^.*attempt //p' | cut -d "'" -f 2 | sort -d | uniq -c | sort -rn | awk '{print $1}' | head -n 10)
u_name=$(echo "$file" | grep -w "login attempt" | sed -n -e 's/^.*attempt //p' | cut -d "'" -f 2 | sort -d | uniq -c | sort -rn | awk '{print $2}' | head -n 10)
p_cont=$(echo "$file" | grep -w "login attempt" | sed -n -e 's/^.*attempt //p' | cut -d "'" -f 4 | sort -d | uniq -c | sort -rn | awk '{print $1}' | head -n 10)
p_name=$(echo "$file" | grep -w "login attempt" | sed -n -e 's/^.*attempt //p' | cut -d "'" -f 4 | sort -d | uniq -c | sort -rn | awk '{print $2}' | head -n 10)
c_name=$(echo "$file" | grep -w "CMD" | sed -n -e 's/^.*CMD: //p' | sort -d | uniq -c | sort -rn | awk '{print $2" "$3" "$4}' | head -n 10)
c_cont=$(echo "$file" | grep -w "CMD" | sed -n -e 's/^.*CMD: //p' | sort -d | uniq -c | sort -rn | awk -F' '  '{print $1}' | head -n 10)
a_cont=$(echo "$file" | grep -w "login attempt" | sed -n -e 's/^.*attempt //p'| grep -w "succeeded" | cut -d "'" -f 2 | sort -d | uniq -c | sort -rn | awk '{print $1}' | head -n 10)
a_name=$(echo "$file" | grep -w "login attempt" | sed -n -e 's/^.*attempt //p'| grep -w "succeeded" | cut -d "'" -f 2 | sort -d | uniq -c | sort -rn | awk '{print $2}' | head -n 10)

for i in $i_cont; do ((i_tot+=$i)); done
for i in $u_cont; do ((u_tot+=$i)); done
for i in $p_cont; do ((p_tot+=$i)); done
for i in $c_cont; do ((c_tot+=$i)); done
for i in $a_cont; do ((a_tot+=$i)); done


ip_p=$(for no in $i_cont; do echo "scale=2; $no*100/$i_tot" | bc 2> /dev/null; done)
user_p=$(for no in $u_cont; do echo "scale=2; $no*100/$u_tot" | bc 2> /dev/null; done)
pass_p=$(for no in $p_cont; do echo "scale=2; $no*100/$p_tot" | bc 2> /dev/null; done)
cmd_p=$(for no in $c_cont; do echo "scale=2; $no*100/$c_tot" | bc 2> /dev/null; done)
acc_p=$(for no in $a_cont; do echo "scale=2; $no*100/$a_tot" | bc 2> /dev/null; done)

echo ""
sgformat="%-40s %-40s %-12s\n"
sgheader="\033[4m\033[1m%-40s %-40s %-12s\033[0m\033[0m\n"
sgheadr="\033[4m\033[1m%-35s %-40s %-17s\033[0m\033[0m\n"
printf "${sgheadr}" "" "BASH SIEM SUMMARY" ""

col1=$(echo -e "${i_name}")
col2=$(echo -e "${i_cont}")
col3=$(echo -e "${ip_p}")

printf "${sgheader}" "${bi}"  "${bc}"  "${bx}"
paste <(printf '%s\n' "$col1") \
      <(printf '%s\n' "$col2") \
      <(printf '%s\n' "$col3") | expand -t42
echo -e "\n\n"

col1=$(echo -e "${u_name}")
col2=$(echo -e "${u_cont}")
col3=$(echo -e "${user_p}")

printf "${sgheader}"
printf "${sgheader}" "${bu}"  "${bc}"  "${bx}"
paste <(printf '%s\n' "$col1") \
      <(printf '%s\n' "$col2") \
      <(printf '%s\n' "$col3") | expand -t42
echo -e "\n\n"

col1=$(echo -e "${p_name}")
col2=$(echo -e "${p_cont}")
col3=$(echo -e "${pass_p}")

printf "${sgheader}"
printf "${sgheader}" "${bp}"  "${bc}"  "${bx}"
paste <(printf '%s\n' "$col1") \
      <(printf '%s\n' "$col2") \
      <(printf '%s\n' "$col3") | expand -t42
echo -e "\n\n"

col1=$(echo -e "${c_name}")
col2=$(echo -e "${c_cont}")
col3=$(echo -e "${cmd_p}")

printf "${sgheader}"
printf "${sgheader}" "${bz}"  "${bc}"  "${bx}"
paste <(printf '%s\n' "$col1") \
      <(printf '%s\n' "$col2") \
      <(printf '%s\n' "$col3") | expand -t42
echo -e "\n\n"

col1=$(echo -e "${a_name}")
col2=$(echo -e "${a_cont}")
col3=$(echo -e "${acc_p}")

printf "${sgheader}"
printf "${sgheader}" "${ba}"  "${bc}"  "${bx}"
paste <(printf '%s\n' "$col1") \
      <(printf '%s\n' "$col2") \
      <(printf '%s\n' "$col3") | expand -t42
echo -e "\n\n"