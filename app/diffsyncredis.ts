///<reference path="../typings/tsd.d.ts" />
import redis = require('redis');

class RedisDataAdapter {
    client: redis.RedisClient;
    namespace: string;
    debug: boolean;

    constructor(client: redis.RedisClient, namespace: string, debug?: boolean) {
        if (!client){ throw new Error('Need to specify a redis client'); }
        this.client = client;
        this.namespace = namespace;
        this.debug = debug;
    }

    getData(id, callback): void {
        this.client.get(this.namespace + ':' + id, (err, data) => {
            if (this.debug) {
                console.log('getData', id, err, data);
            }
            if ( callback ) {
                if (err) {
                    callback(err, null);
                } else {
                    var obj;
                    try{
                        obj = JSON.parse(data);
                    } catch (e){
                        obj = {};
                    }
                    callback(err, obj || {});
                }
            }
        });
    }

    storeData(id, data, callback): void {
        if (!data) {
            data = {};
        }
        data = JSON.stringify(data);
        this.client.set(this.namespace + ':' + id, data, (err, msg) => {
            if (this.debug){
                console.log('setData', id, err, data, msg);
            }
            if (callback) {
                callback(err, msg);
            }
        });
    }
}
export = RedisDataAdapter;
