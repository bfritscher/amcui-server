FROM bfritscher/amc-server
RUN mkdir -p /amc
COPY . /amc/
WORKDIR /amc
RUN npm install
#COPY bower.json .bowerrc* /app/
#RUN bower install --allow-root
#ONBUILD COPY . /usr/src/app/
#ONBUILD RUN [[ -f "Gruntfile.js" ]] && grunt build || /bin/true
#ONBUILD ENV NODE_ENV production

VOLUME ["/amc/app/projects"]

# Define default command.
CMD ["grunt ", "serve"]
