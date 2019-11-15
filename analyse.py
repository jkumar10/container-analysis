import sys
import os
import subprocess
from tqdm import tqdm

with open('officialimagelist.txt') as f:
    content = f.readlines()
content = [x.strip() for x in content]
#print len(content)
cmd="sudo docker pull"
def pullimage():
    try:
        print "\n----------Analysis started--------------"
        for i in tqdm(range(69,80)):
            imagename=content[i]
            if imagename is not "httpd" and imagename is not "postgres":
                newcmd=cmd+" "+imagename
                output = subprocess.check_output(['bash', '-c', newcmd])
                print "Pulled image:",imagename
                analyse(imagename)
    except Exception as e:
        print(e)

def analyse(imagename):
    try:
        print "Running clairctl analyze"
        if subprocess.check_call("sudo docker images | grep"+" "+imagename,shell=True)==0:
            wd = os.getcwd()
            scan_cmd = "sudo docker-compose exec clairctl clairctl analyze -l"+" "+imagename
            os.chdir("/home/ubuntu/Docker-security-example/clair/")
            try:
                subprocess.check_call(scan_cmd,shell=True)
            except Exception as e:
                print(e)
            os.chdir(wd)
            report(imagename) 
        else:
            print "Image not found"
            return
    except Exception as e:
        print(e)

def report(imagename):
    try:
        print "Generating clairctl report for: ",imagename
        wd = os.getcwd()
        report_cmd="sudo docker-compose exec clairctl clairctl report -l"+" "+imagename
        os.chdir("/home/ubuntu/Docker-security-example/clair/")
        try:
            subprocess.check_call(report_cmd,shell=True)
        except Exception as e:
            print(e)
        os.chdir(wd)
        print "Report generated for: ",imagename
        servereport(imagename)
    except Exception as e:
        print(e)

def servereport(imagename):
    try:
        os.chdir("/home/ubuntu/Docker-security-example/clair/docker-compose-data/clairctl-reports/html/")
        serve_cmd="sudo cp analysis-"+imagename+"-latest.html /home/ubuntu/reports/"
        try:
            process=subprocess.Popen(serve_cmd.split(),stdout=subprocess.PIPE)
        except Exception as e:
            output,error=process.communicate()
        print "Report served for: ",imagename
        imagedelete(imagename)
    except Exception as e:
        print(e)


def imagedelete(imagename):
    try:
        sub_cmd="sudo docker images | grep"+" "+imagename+" | awk '{print $3}'"
        id=subprocess.check_output(sub_cmd, shell=True)
        del_cmd="sudo docker rmi"+" "+id
        subprocess.check_call(del_cmd,shell=True)
        print "Image removed:",imagename
    except Exception as e:
        print(e)


pullimage()



