#!/usr/bin/python3

from bs4 import BeautifulSoup
import os
import sys
from tqdm import tqdm

OFFICIAL_IMAGE_PATH="/home/ubuntu/official_reports"
fwi=open("official_individual_image_stats.txt","w")
fwc=open("official_output_cve_list.txt","w")
fws=open("official_stats.txt","w")
sys.stdout=fwi
print("--------CLASSIFYING VULNERABILITIES IN OFFICIAL IMAGES-------------")
directory = os.fsencode(OFFICIAL_IMAGE_PATH)
os.chdir(OFFICIAL_IMAGE_PATH)
total_low=total_medium=total_high=total_neg=0
file_counter=0
total_list_cve=[]

# The below four dictionaries will store imagename and their correspoding
# number of low, medium, high and total vulnerabilities
image_low={}
image_medium={}
image_high={}
image_neg={}
image_tot={}
for file in tqdm(os.listdir(directory)):
     file_counter+=1
     low=medium=high=neg=0
     filename = os.fsdecode(file)
     if filename.endswith(".html"):
         filename=str(filename).strip()
         with open(filename, "r") as f:
             contents = f.read()

             soup = BeautifulSoup(contents, 'lxml')
             data = soup.find("div", {"class": "graph"})
             data = list(data)
             new_list_data = list(filter(None, data))
             for element in new_list_data:
                 if element == '' or element == "\n":
                     new_list_data.remove(element)


             #cve is a dictionary with key as CVE ID and value as vulnerability severity i.e.
             # low, medium, high, negligible
             cve = {}
             for i in range(1, len(new_list_data)):
                 data_value = (new_list_data[i])
                 if (data_value is not None or data_value != "" or data_value != '\n'):
                     str_data = str(data_value).split('"')

                     # cve[vulnearability_id] = severity
                     cve[str_data[3]] = str_data[1]

             low = medium = neg = high = 0
             for key in cve:
                 total_list_cve.append(key.replace("#",''))
                 if (cve[key] == 'node Low'):
                     low += 1
                     total_low+=1
                 if (cve[key] == 'node Medium'):
                     medium += 1
                     total_medium+=1
                 if (cve[key] == 'node Negligible'):
                     neg += 1
                     total_neg+=1
                 if (cve[key] == 'node High'):
                     high += 1
                     total_high+=1

             print("-------------------------------------------------------------")
             print("File Image: ", filename)
             print("LOW: ", low)
             print("MEDIUM: ", medium)
             print("HIGH: ", high)
             print("NEGLIGIBLE: ", neg)
             print("-------------------------------------------------------------")

             image_low[filename]=low
             image_medium[filename] = medium
             image_high[filename] = high
             image_neg[filename] = neg
             image_tot[filename]=low+medium+high+neg

unique_list_cve=set(total_list_cve)
for item in unique_list_cve:
    fwc.write('\n'+item)

image_tot=dict(sorted(image_tot.items(),key=lambda kv:kv[1],reverse=True))


print("TOTAL HTML FILES ANALYZED: ",file_counter,file=fws)
print("TOTAL UNIQUE CVE: ",len(unique_list_cve),file=fws)
print("AVERAGE VULNERABILITIES(CVES) IN IMAGE: ",int((total_low+total_medium+total_high+total_neg)/file_counter),file=fws)
print("TOTAL LOW VULNERABILITIES: ", total_low,file=fws)
print("TOTAL MEDIUM VULNERABILITIES: ", total_medium,file=fws)
print("TOTAL HIGH VULNERABILITIES: ", total_high,file=fws)
print("TOTAL NEGLIGIBLE VULNERABILITIES: ", total_neg,file=fws)
print("AVERAGE NUMBER OF LOW VULNERABILITIES: ", int(total_low/file_counter),file=fws)
print("AVERAGE NUMBER OF MEDIUM VULNERABILITIES: ", int(total_medium/file_counter),file=fws)
print("AVERAGE NUMBER OF HIGH VULNERABILITIES: ", int(total_high/file_counter),file=fws)
print("AVERAGE NUMBER OF NEGLIGIBLE VULNERABILITIES: ", int(total_neg/file_counter),file=fws)
print("\n")
print("TOP 11 OFFICIAL IMAGES WITH MOST VULNERABILITIES: ",file=fws)
t=1
for item in image_tot:
    if t > 11:
        break
    print(t,". "+item+": ",image_tot[item], file=fws)
    t+=1
print("--------------------------------------------------------------------------")







