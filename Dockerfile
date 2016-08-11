FROM bfritscher/amcui-server-base
RUN mkdir -p /amc
COPY . /amc/
WORKDIR /amc
#RUN npm install
RUN grunt
RUN git config --global user.email "root@amcui.ig.he-arc.ch"
RUN git config --global user.name "GradeManager (AMCUI)"

VOLUME ["/amc/projects"]

# Define default command.
CMD ["supervisor", "--watch", "/amc/dist", "dist/server.js"]
