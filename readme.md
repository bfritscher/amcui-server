
## deployment

### frontend
```
git clone https://github.com/bfritscher/grademanager frontend
docker-compose build
docker-compose up
```
This will create the frontend/dist/spa folder

### backend
create and configure .env file
```
NODE_ENV=development|production
SERVER_PORT=9001
JWT_SECRET=
SENTRY_DSN=
ADMIN_USER= # default user which will be admin (more user can be added via the admin project)
FRONTEND_DOMAIN=
```

```
touch traefik/acme.json
chmod 600 traefik/acme.json
docker-compose -f docker-compose.production.yml pull
docker-compose -f docker-compose.production.yml build
docker-compose -f docker-compose.production.yml up -d
```


### dependencies

acl2 <4 needs rewrite into promise callback support removed
redis <4 api changed...

