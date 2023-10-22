set -e

docker pull bloaryth/enclyzer:latest
docker pull bloaryth/aesmd:latest

docker volume create --driver local --opt type=tmpfs --opt device=tmpfs --opt o=rw aesmd-socket
docker-compose --verbose up