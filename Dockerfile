FROM node:16-bullseye
LABEL org.opencontainers.image.source=https://github.com/bfritscher/amcui-server
RUN apt-get update && apt-get install -y \
    auto-multiple-choice \
    graphicsmagick \
    && rm -rf /var/lib/apt/lists/*
RUN sed -i '/disable ghostscript format types/,+6d' /etc/ImageMagick-6/policy.xml
RUN git config --global user.email "root@amcui.ig.he-arc.ch"
RUN git config --global user.name "GradeManager (AMCUI)"
RUN mkdir -p /amc
WORKDIR /amc
COPY package.json /amc/package.json
RUN npm install
ARG COMMIT_SHA=""
ENV COMMIT_SHA=${COMMIT_SHA}
COPY . /amc/
RUN npm run build

VOLUME ["/amc/projects"]
VOLUME ["/amc/templates"]

# Define default command.
CMD ["node", "dist/server.js"]
