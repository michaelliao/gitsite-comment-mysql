import Koa from 'koa';
import Router from '@koa/router';
import { bodyParser } from '@koa/bodyparser';

const app = new Koa();

// log and benchmark:
app.use(async (ctx, next) => {
    console.log(`Process ${ctx.request.method} ${ctx.request.url}...`);
    const start = Date.now();
    await next();
    const execTime = Date.now() - start;
    ctx.set('X-Response-Time', `${execTime}ms`);
});

// parse request.body:
app.use(bodyParser({
    parsedMethods: ['POST', 'PUT', 'DELETE']
}));

// set cors:
app.use(async (ctx, next) => {
    ctx.set('Access-Control-Allow-Origin', process.env.PAGE_ORIGIN);
    ctx.set('Access-Control-Allow-Headers', '*');
    ctx.set("Vary", "Origin");
    if (ctx.method === 'OPTIONS') {
        ctx.set('Access-Control-Allow-Methods', 'GET, POST, DELETE, HEAD, OPTIONS');
        ctx.set('Access-Control-Max-Age', '2592000');
        ctx.status = 200;
    } else {
        await next();
    }
});

// init router:
const router = new Router();

// add router from api:
let { default: mapping } = await import(`./api.mjs`);
for (let url in mapping) {
    if (url.startsWith('GET ')) {
        let p = url.substring(4);
        router.get(p, mapping[url]);
        console.log(`mapping: GET ${p}`);
    } else if (url.startsWith('POST ')) {
        let p = url.substring(5);
        router.post(p, mapping[url]);
        console.log(`mapping: POST ${p}`);
    } else if (url.startsWith('DELETE ')) {
        let p = url.substring(7);
        router.del(p, mapping[url]);
        console.log(`mapping: DELETE ${p}`);
    } else {
        console.warn(`invalid mapping: ${url}`);
    }
}

app.use(router.routes());

app.listen(5000);
console.log('app started at port 5000...');
