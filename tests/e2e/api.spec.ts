import * as request from 'supertest';
import 'jest-extended';

process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';

//const ENDPONIT_API_URL = 'https://amcui.ig.he-arc.ch';
const ENDPONIT_API_URL = 'http://localhost:9001';
const api = request(ENDPONIT_API_URL);
let token: string;

describe('API Login', () => {
  it('should respond', async () => {
    await api
      .get('/')
      .set('Accept', 'text/html')
      .expect('Content-Type', /text\/html/)
      .expect(200);
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

  it('should not change password if password wrong', async () => {
    await api
      .post('/changePassword') // TODO fix url
      .send({username: 'admin', password: 'password', newPassword: 'admin2'})
      .expect(404);
  });

  it('should change password for a user if password known', async () => {
    await api
      .post('/changePassword') // TODO fix url
      .send({username: 'admin', password: 'admin', newPassword: 'admin2'})
      .expect(200);
    await api
      .post('/changePassword') // TODO fix url
      .send({username: 'admin', password: 'admin2', newPassword: 'admin'})
      .expect(200);
    // client has to ask for a new token via login
  });
});

const PROJECT_NAME = 'ci-api-test';
describe('API Project', () => {
  it('can create project', async () => {
    await api
      .post('/project/create')
      .send({project: PROJECT_NAME})
      .set('Authorization', `Bearer ${token}`)
      //TODO FIX .expect('Content-Type', /application\/json/)
      .expect(200)
      .expect((res) => {
        expect(res.text).toMatch(PROJECT_NAME);
      });
  });

  it('fails to create existing project', async () => {
    await api
      .post('/project/create')
      .send({project: PROJECT_NAME})
      .set('Authorization', `Bearer ${token}`)
      .expect(403);
  });

  it('should list project', async () => {
    await api
      .get('/project/list')
      .set('Accept', 'application/json')
      .set('Authorization', `Bearer ${token}`)
      .expect('Content-Type', /application\/json/)
      .expect(200)
      .expect((res) => {
        expect(res.body).toEqual(
          expect.arrayContaining([
            expect.objectContaining({project: PROJECT_NAME, users: ['admin']}),
          ])
        );
      });
  });

  it('should get students.csv', async () => {
    await api
      .get(`/project/${PROJECT_NAME}/csv`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200)
      .expect((res) => {
        expect(res.text).toMatch('id,name');
      });
  });

  // must visit csv first or ws connection to register a visit
  it('should list recent project', async () => {
    await api
      .get('/project/recent')
      .set('Accept', 'application/json')
      .set('Authorization', `Bearer ${token}`)
      .expect('Content-Type', /application\/json/)
      .expect(200)
      .expect((res) => {
        expect(res.body).toMatchObject([PROJECT_NAME]);
      });
  });

  // /project/:project/options

  /*
   [ACL]
   /project/:project/add
   /project/:project/remove
   /project/:project/rename
*/

  it('delete existing project', async () => {
    await api
      .post(`/project/${PROJECT_NAME}/delete`)
      .set('Accept', 'application/json')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
  });

  it('cannot delete missing project', async () => {
    await api
      .post(`/project/${PROJECT_NAME}/delete`)
      .set('Accept', 'application/json')
      .set('Authorization', `Bearer ${token}`)
      .expect(500); // currently 500 TODO FIX
  });
});

/*
can login on websocket
websocket events

[ Unit tests ]
createProject
commitGit
makeThumb
saveSourceFilesSync
u2f
calculateMarks

/project/:project/copy/template
/project/:project/copy/project
/project/:project/copy/graphics
/project/:project/copy/codes


[GIT]
/project/:project/gitlogs
/project/:project/revert

/project/:project/zip
/project/:project/static/:file*


[UPLOAD]
/project/:project/upload/graphics
/project/:project/graphics/sync ??
/project/:project/graphics/delete

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

/project/:project/mark
/project/:project/scores

/project/:project/ods
/project/:project/annotate
/project/:project/zip/annotate


TODO setup admin permissions
/project/:project/stats

*/
