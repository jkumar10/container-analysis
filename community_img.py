#!/usr/bin/env python3
import simplejson as json
from urllib.request import urlopen
#from urllib2 import urlopen
import subprocess
import os

ignore_list=['clefos','elasticsearch','radle','kibana','logstash','notary','opensuse','ross','silverpeas','httpd','postgres']

def pullimage(imagename):
    try:
        cmd = "sudo docker pull"
        print("\n----------Analysis started--------------")
        if(imagename not in ignore_list):
            newcmd=cmd+" "+imagename
            output = subprocess.check_output(['bash', '-c', newcmd])
            print("Pulled image:",imagename)
    except Exception as e:
        pass

def analyse(imagename):
    try:
        print("Running clairctl analyze")
        if subprocess.check_call("sudo docker images | grep"+" "+imagename,shell=True)==0:
            wd = os.getcwd()
            scan_cmd = "sudo docker-compose exec clairctl clairctl analyze -l"+" "+imagename
            os.chdir("/home/ubuntu/Docker-security-example/clair/")
            try:
                subprocess.check_call(scan_cmd,shell=True)
            except Exception as e:
                print(e)
            os.chdir(wd)
        else:
            print("Image not found")
            return
    except Exception as e:
        pass


def report(imagename):
    try:
        print("Generating clairctl report for: ",imagename)
        wd = os.getcwd()
        report_cmd="sudo docker-compose exec clairctl clairctl report -l"+" "+imagename
        os.chdir("/home/ubuntu/Docker-security-example/clair/")
        try:
            subprocess.check_call(report_cmd,shell=True)
        except Exception as e:
            print(e)
        os.chdir(wd)
        print("Report generated for: ",imagename)
    except Exception as e:
        pass

def servereport(imagename,officialimagename):
    try:
        newimagename=imagename.replace('/','-')
        print(newimagename)
        os.chdir("/home/ubuntu/Docker-security-example/clair/docker-compose-data/clairctl-reports/html/")
        serve_cmd="sudo cp analysis-"+newimagename+"-latest.html /home/ubuntu/community_reports/"+officialimagename+"/"
        try:
            process=subprocess.Popen(serve_cmd.split(),stdout=subprocess.PIPE)
        except Exception as e:
            #output,error=process.communicate()
            pass
        print("Report served for: ",imagename)
    except Exception as e:
        pass


def imagedelete(imagename):
    try:
        print("Deletion started:",imagename)
        sub_cmd="sudo docker images | grep"+" "+imagename+" | awk '{print $3}'"
        image_id=subprocess.check_output(sub_cmd, shell=True)
        image_id=image_id.decode("utf-8")
        del_cmd="sudo docker rmi"+" "+image_id
        subprocess.check_call(del_cmd,shell=True)
        print("Image removed:",imagename)
    except Exception as e:
        pass


with open('officialimagelist.txt') as f:
    content = f.readlines()
content = [x.strip() for x in content]
for oname in range(40,45):
    officialimagename=content[oname]
    os.chdir("/home/ubuntu/community_reports/")
    create_folder="mkdir"+" "+officialimagename
    subprocess.check_call(create_folder,shell=True)
    wd=os.getcwd()
    os.chdir(wd)
    url = urlopen('https://hub.docker.com/v2/search/repositories/?query='+officialimagename+'&page_size=20').read()
    url = json.loads(url)

    url_dict=dict(url)
    repo_names=[]

    k=0
    for i in url_dict['results']:
        if k>0:
            repo_names.append(i.get('repo_name'))
        k+=1
    
    for j in range(len(repo_names)):
        imagename=repo_names[j]
        pullimage(imagename)
        analyse(imagename)
        report(imagename)
        servereport(imagename,officialimagename)
        imagedelete(imagename)
    
