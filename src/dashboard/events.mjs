export const STATES = new Set(['queued','running','succeeded','failed','blocked']);
export function sanitize(value) {
  return String(value).replace(/(Bearer\s+)[^\s]+/gi,'$1[REDACTED]').replace(/((?:token|password|secret|api[_-]?key)\s*[=:]\s*)[^\s&]+/gi,'$1[REDACTED]');
}
export class EventStore {
  constructor(limit=200){this.limit=limit;this.events=[];this.nextId=1;this.listeners=new Set();}
  append({project,cli,state,message='',source='observed'}){
    if(!/^[a-z0-9][a-z0-9_-]{0,63}$/i.test(project)||!['codex','gemini','antigravity','opencode'].includes(cli)||!STATES.has(state)||!['observed','synthetic'].includes(source))throw Error('invalid event');
    const event={id:this.nextId++,project,cli,state,message:sanitize(message).slice(0,2000),source,at:new Date().toISOString()};
    this.events.push(event);if(this.events.length>this.limit)this.events.shift();
    for(const fn of this.listeners)fn(event);return event;
  }
  list(project,since=0){return this.events.filter(e=>e.project===project&&e.id>since);}
  subscribe(fn){this.listeners.add(fn);return()=>this.listeners.delete(fn);}
}
