FROM bfritscher/amc-server
RUN mkdir -p /amc
COPY package.json /amc/package.json
WORKDIR /amc
RUN npm install
CMD ["bash"]