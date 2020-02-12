FROM node:13-buster
RUN apt-get update && apt-get install -y \
    auto-multiple-choice \
    graphicsmagick \
    && rm -rf /var/lib/apt/lists/*
RUN git config --global user.email "root@amcui.ig.he-arc.ch"
RUN git config --global user.name "GradeManager (AMCUI)"
RUN mkdir -p /amc
COPY . /amc/
WORKDIR /amc
RUN npm install

VOLUME ["/amc/projects"]

# Define default command.
CMD ["supervisor", "--watch", "/amc/dist", "dist/server.js"]
