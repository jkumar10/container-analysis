# container-analysis
Identifying container vulnerabilities in official and non official docker images from docker hub.
https://nullsweep.com/docker-static-analysis-with-clair/

Clair is a vulnerability scanner for Docker containers and images.

# Setup
git clone git@github.com:Charlie-belmer/Docker-security-example.git   
cd Docker-security-example/clair/   
docker-compose up

# Download a vulnerable container

docker pull imiell/bad-dockerfile
docker-compose exec clairctl clairctl analyze -l imiell/bad-dockerfile
docker-compose exec clairctl clairctl report -l imiell/bad-dockerfile

HTML report at /reports/html/analysis-imiell-bad-dockerfile-latest.html


