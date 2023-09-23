// index.js
const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('db.json'); // Assuming your data is in db.json
const middlewares = jsonServer.defaults();

server.use(middlewares);
server.use(router);

const port = process.env.PORT || 9000;

server.listen(port, () => {
  console.log(`JSON Server is running on port ${port}`);
});