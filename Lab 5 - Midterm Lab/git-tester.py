import os

#Git push
output = os.system("cd /home/kiran/sdn-midterm/")
print(output)
output  = os.system("git pull")
print(output)
output = os.system("cp -r /home/kiran/SDNcodes/* /home/kiran/sdn-midterm/.")
output = os.system("git status")
print(output)
os.system("git add .")
os.system("git commit -m 'Pushed via code'")
output = os.system("git push origin master")
print(output)

