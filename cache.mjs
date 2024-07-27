import { createClient } from 'redis';

const REDIS_HOST = process.env.REDIS_HOST || '127.0.0.1';
const REDIS_PORT = process.env.REDIS_PORT || '6379';

const client = await createClient({
    url: `redis://${REDIS_HOST}:${REDIS_PORT}`
})
    .on('error', err => console.log('Redis Client Error', err))
    .connect();

export async function cacheGet(key) {
    let value = await client.get(key);
    if (value) {
        return JSON.parse(value);
    }
    return null;
}

export async function cachePut(key, value) {
    await client.set(key, JSON.stringify(value));
}

export async function cacheDelete(key) {
    await client.del(key);
}
