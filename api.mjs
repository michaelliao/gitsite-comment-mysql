import { randomUUID, randomBytes, randomInt, createHmac, createHash } from 'node:crypto';
import { dbQueryAll, dbQueryFirst, dbExecute, dbInsert, dbUpdate } from './db.mjs';
import { cacheGet, cachePut, cacheDelete } from './cache.mjs';

const ROLE_USER = 0;
const ROLE_ADMIN = 1000;

const DEFAULT_POST_INTERVAL = '60000';

// to_pathname('https://example.com/app/path/TO/', '/app') => '/path/to/index.html', lowercase, ends with /index.html
function url_to_pathname(fullUrl, pathPrefix) {
    let url = new URL(fullUrl);
    let path = url.pathname.toLowerCase();
    if (!path.startsWith(pathPrefix.toLowerCase())) {
        throw { error: 'INVALID_PATH', message: 'bad path prefix.' };
    }
    let pathname = path.substring(pathPrefix.length);
    if (pathname.endsWith('/')) {
        pathname = pathname + 'index.html';
    }
    return pathname;
}

// hash('any string') => 32-bytes hex string (can be used as uuid)
function hash(str) {
    const sha1 = createHash('sha1');
    sha1.update(str);
    return sha1.digest('hex').substring(0, 32);
}

// 16-bytes random string:
function randomStr() {
    return randomUUID().substring(19).replace(/-/g, '');
}

const TS_OFFSET = new Date('2000-01-01T00:00:00Z').getTime();

/**
 * nextId(millis) => 53-bit int (can be used as increment int)
 * 
 * 53 bits unique id:
 *
 * |--------|--------|--------|--------|--------|--------|--------|--------|
 * |00000000|00011111|11111111|11111111|11111111|11111111|11111111|11111111|
 * |--------|---xxxxx|xxxxxxxx|xxxxxxxx|xxxxxxxx|xxxxxxxx|xxxxx---|--------|
 * |--------|--------|--------|--------|--------|--------|-----xxx|xxxxxxxx|
 *
 * Maximum ID = 11111_11111111_11111111_11111111_11111111_11111111_11111111
 *
 * Maximum TS = 11111_11111111_11111111_11111111_11111111_11111
 *
 * Maximum RN = ----- -------- -------- -------- -------- -----111_11111111 = 2047
 */
function nextId(ts) {
    return ((ts - TS_OFFSET) * 2048) + randomInt(2048);
}

async function load_comments(pageId, limit = 20) {
    let comments;
    if (pageId) {
        comments = await dbQueryAll`SELECT * FROM comments WHERE page_id = ${pageId} ORDER BY updated_at DESC LIMIT ${limit}`;
        for (let comment of comments) {
            if (comment.replies_count === 0) {
                comment.replies = [];
            } else {
                comment.replies = await dbQueryAll`SELECT * FROM replies WHERE comment_id = ${comment.id} ORDER BY id LIMIT ${limit}`;
            }
        }
    } else {
        comments = await dbQueryAll`SELECT * FROM comments ORDER BY updated_at DESC LIMIT ${limit}`;
        for (let comment of comments) {
            comment.page = await dbQueryFirst`SELECT * FROM pages WHERE id = ${comment.page_id}`;
        }
    }
    return comments;
}

// validate page and return page object:
async function validate_page(pageId, pageUrl, pathname, now) {
    let page = await dbQueryFirst`SELECT * FROM pages WHERE id=${pageId}`;
    if (page === null || (now - page.updated_at) > 604800_000) {
        // check page url:
        console.log(`check if page url accessible: ${pageUrl}`);
        let resp = await fetch(pageUrl);
        if (resp.status !== 200) {
            throw { error: 'INVALID_URL', message: 'Cannot access page.' };
        }
        // page url ok:
        if (page === null) {
            page = {
                id: pageId,
                pathname: pathname,
                updated_at: now
            }
            await dbInsert('pages', page);
        } else {
            page.updated_at = now;
            await dbUpdate('pages', page, 'updated_at');
        }
        return page;
    }
    // page exist and checked recently:
    return page;
}

// insert comment and return:
async function insert_comment(user, pageId, content, now) {
    let commentId = nextId(now);
    let comment = {
        id: commentId,
        page_id: pageId,
        user_id: user.id,
        user_name: user.name,
        user_image: user.image,
        content: content,
        replies_count: 0,
        created_at: now,
        updated_at: now
    };
    user.updated_at = now;
    await dbUpdate('users', user, 'updated_at');
    await dbInsert('comments', comment);
    return comment;
}

// insert reply and return:
async function insert_reply(user, commentId, content, now) {
    let replyId = nextId(now);
    let reply = {
        id: replyId,
        comment_id: commentId,
        user_id: user.id,
        user_name: user.name,
        user_image: user.image,
        content: content,
        created_at: now
    };
    user.updated_at = now;
    await dbUpdate('users', user, 'updated_at');
    await dbInsert('replies', reply);
    await update_comment_replies(commentId, now, 1);
    return reply;
}

async function update_comment_replies(commentId, now, add) {
    if (add > 0) {
        await dbExecute`UPDATE comments SET replies_count = replies_count + ${add}, updated_at = ${now} WHERE id = ${commentId}`;
    } else {
        await dbExecute`UPDATE comments SET replies_count = replies_count + ${add} WHERE id = ${commentId}`;
    }
}

function create_state(salt) {
    const exp = (Date.now() + 600_000).toString(16);
    const rnd = randomBytes(5).toString('hex');
    const payload = `${exp}_${rnd}`;
    const hmac = createHmac('sha1', salt);
    hmac.update(payload);
    const hash = hmac.digest('hex').substring(0, 10);
    return `${payload}_${hash}`;
}

function is_valid_state(state, salt) {
    const [exp, rnd, hash] = state.split('_');
    if (parseInt(exp, 16) < Date.now()) {
        return false;
    }
    const payload = `${exp}_${rnd}`;
    const hmac = createHmac('sha1', salt);
    hmac.update(payload);
    return hash === hmac.digest('hex').substring(0, 10);
}

function create_user_token(user, expires, salt) {
    // id, role, name, image, expires, hash:
    const payload = user.id + '\n' + user.role + '\n' + user.name + '\n' + user.image + '\n' + expires;
    const hmac = createHmac('sha1', salt);
    hmac.update(payload);
    const hash = hmac.digest('hex').substring(0, 10);
    return encodeURIComponent(payload + '\n' + hash)
}

async function parse_user_from_token(str) {
    const [id, role, name, image, expires, hash] = decodeURIComponent(str).split('\n');
    if (parseInt(expires) < Date.now()) {
        return null;
    }
    // fetch user salt:
    const db_user = await dbQueryFirst`SELECT * FROM users WHERE id = ${id}`;
    if (db_user === null) {
        return null;
    }
    const payload = id + '\n' + role + '\n' + name + '\n' + image + '\n' + expires;
    const hmac = createHmac('sha1', db_user.salt);
    hmac.update(payload);
    if (hash !== hmac.digest('hex').substring(0, 10)) {
        return null;
    }
    return db_user;
}

function get_oauth_redirect(provider, state, clientId, redirectUri) {
    switch (provider) {
        case 'github':
            return `https://github.com/login/oauth/authorize?response_type=code&client_id=${clientId}&state=${state}&redirect_uri=${encodeURIComponent(redirectUri)}`;
        case 'qq':
            return `https://graph.qq.com/oauth2.0/authorize?response_type=code&client_id=${clientId}&state=${state}&redirect_uri=${encodeURIComponent(redirectUri)}`;
        case 'weibo':
            return `https://api.weibo.com/oauth2/authorize?response_type=code&client_id=${clientId}&state=${state}&redirect_uri=${encodeURIComponent(redirectUri)}`;
        default:
            throw { error: 'INVALID_OAUTH_PROVIDER', data: provider, message: `unsupported oauth provider.` };
    }
}

function oauth_request(ctx) {
    const salt = process.env.SALT;
    const provider = process.env.OAUTH_PROVIDER;
    const clientId = process.env.OAUTH_CLIENT_ID;
    const redirectUri = process.env.OAUTH_REDIRECT_URI;
    const state = create_state(salt);
    // 302 redirect:
    ctx.redirect(get_oauth_redirect(provider, state, clientId, redirectUri));
}

async function oauth_response(ctx) {
    const now = Date.now();
    const salt = process.env.SALT;
    const provider = process.env.OAUTH_PROVIDER;
    const clientId = process.env.OAUTH_CLIENT_ID;
    const clientSecret = process.env.OAUTH_CLIENT_SECRET;
    const redirectUri = process.env.OAUTH_REDIRECT_URI;

    const state = ctx.request.query.state;
    const code = ctx.request.query.code;
    if (!state) {
        return oauth_response_failed(ctx, 'OAuth login failed: missing state.');
    }
    if (!code) {
        return oauth_response_failed(ctx, 'OAuth login failed: missing code.');
    }
    if (!is_valid_state(state, salt)) {
        return oauth_response_failed(ctx, 'OAuth login failed: invalid state.');
    }
    let user = {};
    switch (provider) {
        case 'qq':
            const qqUrl1 = `https://graph.qq.com/oauth2.0/token?fmt=json&grant_type=authorization_code&code=${code}&client_id=${clientId}&client_secret=${clientSecret}&redirect_uri=${encodeURIComponent(redirectUri)}`;
            const qqResp1 = await fetch(qqUrl1);
            const qqJson1 = await qqResp1.json();
            const qqAccessToken = qqJson1.access_token || '';
            if (!qqAccessToken) {
                return oauth_response_failed(ctx, 'OAuth login failed: no access token.');
            }
            const qqUrl2 = `https://graph.qq.com/oauth2.0/me?fmt=json&access_token=${qqAccessToken}`;
            const qqResp2 = await fetch(qqUrl2);
            const qqJson2 = await qqResp2.json();
            const qqOpenId = qqJson2.openid || '';
            if (!qqOpenId) {
                return oauth_response_failed(ctx, 'OAuth login failed: no open id.');
            }
            const qqUrl3 = `https://graph.qq.com/user/get_user_info?oauth_comsumer_key=${clientId}&appid=${clientId}&access_token=${qqAccessToken}&openid=${qqOpenId}`;
            const qqResp3 = await fetch(qqUrl3);
            const qqJson3 = await qqResp3.json();
            // set user profile:
            user.id = qqOpenId;
            user.name = qqJson3.nickname;
            user.image = qqJson3.figureurl_qq_2 || qqJson3.figureurl_qq_1 || qqJson3.figureurl_1 || qqJson3.figureurl;
            break;
        default:
            return oauth_response_failed(ctx, 'OAuth login failed: unsupported oauth provider.');
    }
    // check user:
    if (!user.id) {
        return oauth_response_failed(ctx, 'OAuth login failed: missing user id.');
    }
    if (!user.name) {
        return oauth_response_failed(ctx, 'OAuth login failed: missing user name.');
    }
    if (!user.image) {
        return oauth_response_failed(ctx, 'OAuth login failed: missing user image.');
    }
    // create or update db user:
    let db_user = await dbQueryFirst`SELECT * FROM users WHERE id = ${user.id}`;
    if (db_user === null) {
        // insert:
        db_user = {
            id: user.id,
            role: ROLE_USER,
            name: user.name,
            image: user.image,
            salt: randomStr(),
            locked_at: 0,
            updated_at: 0
        };
        await dbInsert('users', db_user);
    } else {
        if (db_user.locked_at > now) {
            return oauth_response_failed(ctx, 'User is locked.');
        }
        // update:
        db_user.name = user.name;
        db_user.image = user.image;
        db_user.salt = randomStr();
        await dbUpdate('users', db_user, 'name', 'image', 'salt');
    }
    user.role = db_user.role;
    const expires = now + 31536000_000;
    const token = create_user_token(user, expires, db_user.salt);
    const html = `<!DOCTYPE html>
<html>
<head>
<script>
setTimeout(() => {
	console.log('post message to opener...');
	window.opener.postMessage({
		type: 'oauth',
		success: true,
		token: '${token}',
		user: ${JSON.stringify(user)},
		expires: ${expires}
	}, '*');
}, 1000);
</script>
</head>
<body>
	<p>${user.name} signed successfully.</p>
</body>
</html>
`;
    create_html_response(ctx, html);
}

function oauth_response_failed(ctx, error) {
    create_html_response(ctx, `<!DOCTYPE html>
<html>
<head>
</head>
<body>
	<h1>Login failed</h1>
	<p>${error}</p>
</body>
</html>
`);
}

function create_html_response(ctx, html) {
    ctx.type = 'text/html;charset=utf-8';
    ctx.body = html;
}

// user from auth header, or null if parse failed:
async function get_user_from_auth_header(ctx) {
    const auth = ctx.get('authorization');
    if (auth && auth.startsWith('Bearer: ')) {
        const token = auth.substring(8).trim();
        return await parse_user_from_token(token);
    }
    return null;
}

async function get_comments(ctx) {
    const pageUrl = ctx.query.url || '';
    console.log(pageUrl);
    let result;
    if (!pageUrl) {
        // no page url, return recent comments:
        const size = parseInt(ctx.query.size || 20);
        const comments = await load_comments('', size);
        result = {
            comments: comments
        };
    } else {
        // by page url:
        const pathname = url_to_pathname(pageUrl, process.env.PAGE_PATH_PREFIX || '');
        const pageId = hash(pathname);
        result = await cacheGet(pageId);
        if (!result) {
            const comments = await load_comments(pageId);
            result = {
                comments: comments
            };
            if (comments.length > 0) {
                await cachePut(pageId, result);
            }
        }
    }
    ctx.type = 'application/json';
    ctx.body = result;
}

async function check_user(ctx, now, checkRateLimit = true) {
    const db_user = await get_user_from_auth_header(ctx);
    if (db_user === null) {
        throw { error: 'SIGNIN_REQUIRED', message: 'Please signin first.' };
    }
    if (db_user.locked_at > now) {
        throw { error: 'USER_LOCKED', message: 'User is locked.' };
    }
    if (checkRateLimit && db_user.role === ROLE_USER && ((now - db_user.updated_at) < (parseInt(process.env.POST_INTERVAL || DEFAULT_POST_INTERVAL)))) {
        throw { error: 'RATE_LIMIT', message: 'Please wait a little while.' };
    }
    return db_user;
}

async function post_reply(ctx) {
    const now = Date.now();
    const user = await check_user(ctx, now);
    // make a reply:
    const body = ctx.request.body;
    // check commentId:
    const commentId = parseInt(body.commentId || '0');
    if (!commentId) {
        throw { error: 'INVALID_PARAMETER', data: 'commentId', message: 'Missing commentId.' };
    }
    const content = (body.content || '').trim();
    if (!content) {
        throw { error: 'INVALID_PARAMETER', date: 'content', message: 'Missing content.' };
    }
    // reply:
    const comment = await dbQueryFirst`SELECT id, page_id, replies_count FROM comments WHERE id = ${commentId}`;
    if (!comment) {
        throw { error: 'INVALID_PARAMETER', data: 'commentId', message: 'Invalid commentId.' };
    }
    const reply = await insert_reply(user, commentId, content, now);
    if (comment.replies_count <= 20) {
        // clear cache:
        await cacheDelete(comment.page_id);
    }
    ctx.type = 'application/json';
    ctx.body = reply;
}

async function delete_reply(ctx) {
    const now = Date.now();
    const user = await check_user(ctx, now, false);
    const body = ctx.request.body;
    const replyId = parseInt(body.replyId || '0');
    if (!replyId) {
        throw { error: 'INVALID_PARAMETER', data: 'replyId', message: 'Missing replyId.' };
    }
    const reply = await dbQueryFirst`SELECT * FROM replies WHERE id = ${replyId}`;
    if (reply === null) {
        throw { error: 'INVALID_PARAMETER', data: 'replyId', message: 'Reply not exist.' };
    }
    if (user.role !== ROLE_ADMIN && user.id !== reply.user_id) {
        throw { error: 'PERMISSION_DENIED', message: 'Cannot delete reply.' };
    }
    const comment = await dbQueryFirst`SELECT page_id FROM comments WHERE id = ${reply.comment_id}`;
    // delete reply:
    await dbExecute`DELETE FROM replies WHERE id = ${reply.id}`;
    await update_comment_replies(reply.comment_id, now, -1);

    // remove cache:
    await cacheDelete(comment.page_id);

    ctx.type = 'application/json';
    ctx.body = {
        id: reply.id
    };
}

async function post_comment(ctx) {
    const now = Date.now();
    const user = await check_user(ctx, now);
    const body = ctx.request.body;
    // check pageUrl or commentId:
    const pageUrl = body.pageUrl || '';
    if (!pageUrl) {
        throw { error: 'INVALID_PARAMETER', data: 'pageUrl', message: 'Missing pageUrl.' };
    }
    const content = (body.content || '').trim();
    if (!content) {
        throw { error: 'INVALID_PARAMETER', data: 'content', message: 'Missing content.' };
    }
    if (content.length > 20000) {
        throw { error: 'INVALID_PARAMETER', data: 'content', message: 'Content too long.' };
    }
    // normalize page url:
    const pathname = url_to_pathname(pageUrl, process.env.PAGE_PATH_PREFIX || '');
    const pageId = hash(pathname);
    await validate_page(pageId, pageUrl, pathname, now);
    const comment = await insert_comment(user, pageId, content, now);
    // clear cache:
    await cacheDelete(pageId);

    ctx.type = 'application/json';
    ctx.body = comment;
}

async function delete_comment(ctx) {
    const now = Date.now();
    const user = await check_user(ctx, now, false);
    const body = ctx.request.body;
    const commentId = parseInt(body.commentId || '0');
    if (!commentId) {
        throw { error: 'INVALID_PARAMETER', data: 'commentId', message: 'Missing commentId.' };
    }
    const comment = await dbQueryFirst`SELECT * FROM comments WHERE id = ${commentId}`;
    if (comment === null) {
        throw { error: 'INVALID_PARAMETER', data: 'commentId', message: 'Comment not exist.' };
    }
    if (user.role !== ROLE_ADMIN && user.id !== comment.user_id) {
        throw { error: 'PERMISSION_DENIED', message: 'Cannot delete comment.' };
    }
    // delete comment / replies:
    await dbExecute`DELETE FROM comments WHERE id = ${comment.id}`;
    await dbExecute`DELETE FROM replies WHERE comment_id = ${comment.id}`;
    // remove cache:
    await cacheDelete(comment.page_id);

    ctx.type = 'application/json';
    ctx.body = {
        id: comment.id
    };
}

function translate_error(err) {
    if (err.error) {
        err.message = process.env['I18N_' + err.error] || err.message;
    }
    return err;
}

function async_wrapper(asyncFn) {
    return async (ctx) => {
        try {
            await asyncFn(ctx);
        } catch (err) {
            console.error(err);
            ctx.status = 400;
            ctx.type = 'application/json';
            ctx.body = translate_error(err);
        }
    }
}

export default {
    'GET /api/comments': async_wrapper(get_comments),
    'POST /api/comments': async_wrapper(post_comment),
    'DELETE /api/comments': async_wrapper(delete_comment),
    'POST /api/replies': async_wrapper(post_reply),
    'DELETE /api/replies': async_wrapper(delete_reply),
    'GET /oauth_request': async_wrapper(oauth_request),
    'GET /oauth_response': async_wrapper(oauth_response),
    'GET /': async (ctx) => {
        ctx.type = 'text/html';
        ctx.body = '<h1>It works!</h1>';
    }
}
