FROM bfritscher/amcui-server-base
RUN mkdir -p /amc
COPY . /amc/
WORKDIR /amc
#RUN npm install
RUN grunt

VOLUME ["/amc/projects"]

# Define default command.
CMD ["supervisor", "--watch", "/amc/dist", "dist/server.js"]
