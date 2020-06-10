# CandiCrash Python Backend

to the docker container use:
  - docker build -t myimage ./
  - docker run -p 80:80 -e MODULE_NAME="candycrash" -e WORKERS_PER_CORE="1" myimage