import { createServer } from 'http';
import app from './server.js';

const server = createServer(app);
server.listen(process.env.PORT ?? 4000, () => {
  console.log('Server started on port 4000');
});
