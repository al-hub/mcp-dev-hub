import {openDb} from './worker.mjs';
import {createReadOnlyDashboard} from '../src/dashboard/read-only-server.mjs';
import {createGithubStatusReader} from '../src/dashboard/github-status.mjs';

const token=process.env.MCP_DEV_HUB_DASHBOARD_TOKEN;
const project=process.env.MCP_DEV_HUB_DASHBOARD_PROJECT;
const repository=process.env.MCP_DEV_HUB_DASHBOARD_REPOSITORY;
const port=Number(process.env.MCP_DEV_HUB_DASHBOARD_PORT || 8765);
if (!Number.isInteger(port) || port<1 || port>65535)throw Error('invalid dashboard port');
const db=openDb();
const dashboard=createReadOnlyDashboard({
 token,project,repository,port,host:'localhost',db,
 readGithub:createGithubStatusReader({token:process.env.MCP_DEV_HUB_GITHUB_TOKEN})
});
try{
 await dashboard.listen();
 console.error('private read-only dashboard listening on localhost');
}catch(e){db.close();throw e;}
const shutdown=()=>dashboard.server.close(()=>{db.close();process.exit(0);});
process.on('SIGTERM',shutdown);
process.on('SIGINT',shutdown);
