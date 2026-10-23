# The machine the game runs on during a Linux test: a plain desktop-like system with a virtual screen
# and software OpenGL. Java comes from the host, mounted read-only.
FROM ubuntu:24.04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      xvfb x11-xserver-utils xkb-data x11-xkb-utils libgl1 libgl1-mesa-dri libglx-mesa0 libegl1 \
      libx11-6 libxext6 libxrender1 libxtst6 libxi6 libxrandr2 libxcursor1 libxxf86vm1 libxinerama1 \
      libasound2t64 libpulse0 libfreetype6 fontconfig fonts-dejavu-core ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -u 10001 -m -d /home/player -s /bin/bash player

USER 10001
WORKDIR /home/player
