FROM node:20

RUN apt-get update \
    && apt-get install -y wget gnupg \
    && wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list' \
    && apt-get update \
    && apt-get install -y google-chrome-stable fonts-noto-color-emoji fonts-ipafont-gothic fonts-wqy-zenhei fonts-thai-tlwg fonts-kacst fonts-freefont-ttf libxss1 \
      --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/google-chrome

COPY ./fonts /usr/share/fonts/
RUN fc-cache -fv

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install && groupadd -r pptruser && useradd -r -g pptruser -G audio,video pptruser \
&& chown -R pptruser:pptruser . 

USER pptruser

COPY . .

EXPOSE 3000

CMD [ "node", "server.js" ]
