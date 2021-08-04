import * as request from 'supertest';
import 'jest-extended';

const ENDPONIT_API_URL = 'http://localhost:9001';
const api = request(ENDPONIT_API_URL);
let token: string;

describe('API Home', () => {
  it('should respond', async () => {
    await api
      .get('/')
      .set('Accept', 'text/html')
      .expect('Content-Type', /text\/html/)
      .expect(200)
      .expect('AMCUI API SERVER');
  });

  it('should require authorization', async () => {
    await api.get('/project/list').expect(401);
  });

  it('should login/create user', async () => {
    const res = await api
      .post('/login')
      .send({username: 'admin', password: 'admin'})
      .expect(200);
    token = res.body.token;
  });
});

describe('API', () => {
  it('should respond', async () => {
    await api
      .get('/project/list')
      .set('Accept', 'application/json')
      .set('Authorization', `Bearer ${token}`)
      .expect('Content-Type', /application\/json/)
      .expect(200)
      .expect(res => {
        expect(res.body).toBeArray();
      });
  });
});

/*
can login on websocket
websocket events


/login
u2f
/changePassword
/project/list
/project/recent

createProject
commitGit

/project/create
/project/:project/options

/project/:project/copy/template
/project/:project/copy/project
/project/:project/copy/graphics
/project/:project/copy/codes

[ACL]
/project/:project/add
/project/:project/remove
/project/:project/rename
/project/:project/delete

[GIT]
/project/:project/gitlogs
/project/:project/revert

/project/:project/zip
/project/:project/static/:file*

makeThumb

[UPLOAD]
/project/:project/upload/graphics
/project/:project/graphics/sync ??
/project/:project/graphics/delete

saveSourceFilesSync

/project/:project/preview
/project/:project/reset/lock
/project/:project/print
/project/:project/zip/pdf

/project/:project/upload
/project/:project/missing

/project/:project/capture

/project/:project/capture/:student/:page::copy
/project/:project/capture/setauto
/project/:project/capture/setmanual

/project/:project/capture/delete

/project/:project/zones/:student/:page::copy
/project/:project/scoring
/project/:project/csv
/project/:project/gradefiles
/project/:project/association/manual
/project/:project/names

calculateMarks
/project/:project/mark
/project/:project/scores

/project/:project/ods
/project/:project/annotate
/project/:project/zip/annotate

/project/:project/stats

*/
