// #35: exactly two fixed, root-owned runtime entrypoints; no wildcards.
// Render only; NO sudo privileges or files are created by this module.
// OS root activation must validate resulting text with /usr/sbin/visudo.
const PATH='/usr/local/lib/mcp-dev-hub/protected-updater/code/scripts/';
const NODE='/usr/bin/node';
const SUFFIXES=Object.freeze([
  'protected-update-root-apply.mjs',
  'protected-update-root-reconcile.mjs'
]);
const deny=()=>{throw Error('protected_sudo_policy_denied');};
const NAME=/^[a-z_][a-z0-9_-]{0,30}$/;
export function renderFixedProtectedSudoPolicy({workerAccount}={}){
  if(typeof workerAccount!=='string'||!NAME.test(workerAccount)||
     workerAccount==='root'||workerAccount==='sudo'||
     workerAccount.startsWith('issuer-'))deny();
  const cmd=SUFFIXES.map(path=>NODE+' '+PATH+path);
  return Object.freeze({
    file:'/etc/sudoers.d/mcp-dev-hub-protected-update',
    mode:0o440,
    rootOwned:true,
    allowedCommands:Object.freeze(cmd),
    text:'Defaults:'+workerAccount+
      ' env_reset, !setenv, secure_path="/usr/sbin:/usr/bin:/sbin:/bin"\n'+
      'Defaults:'+workerAccount+
      ' env_delete += "NODE_OPTIONS NODE_PATH NODE_EXTRA_CA_CERTS NODE_TLS_REJECT_UNAUTHORIZED"\n'+
      workerAccount+' ALL=(root) NOPASSWD: '+cmd.join(', ')+
      '\n',
    unrestrictedSudo:false,
    installAuthorized:false
  });
}
export const PROTECTED_SUDO_FIXED_COMMANDS=SUFFIXES;
