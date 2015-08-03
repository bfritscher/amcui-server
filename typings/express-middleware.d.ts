/// <reference path="express/express.d.ts" />

declare module "method-override" {
    import express = require("express");
    function methodOverride(): express.RequestHandler;
    export = methodOverride;
}

declare module "cors" {
    import express = require("express");
    function cors(args?:any): express.RequestHandler;
    export = cors;
}

declare module "raven" {
    var middleware;
    var Client:Client;
    interface Client {
        new (dsn:String, options?:any);
        captureMessage(message:String, options?:any, callback?:Function);
        captureError(error:Error, options?:any, callback?:Function);
        captureQuery(query:String, type?:String, callback?:Function);
    }
}

declare module "is-online" {
    function isOnline(callback:(err:Error, isOnline:boolean)=>void):void;
    export = isOnline;
}

declare module "connect-redis" {
    function RedisStore(session:any):any;
    export = RedisStore;
}

declare module "connect-multiparty" {
    import express = require("express");
    module multiparty {
        interface Request extends express.Request {
            files:any;
        }
    }
    function multiparty(): express.RequestHandler;
    export = multiparty;
}

declare module "passport.socketio" {
    export function authorize(options:any):any;
}

declare module "socketio-jwt" {
    function authorize(options:any):any;
}

declare module "archiver" {
    function archiver(format:string):any;
    export = archiver;
}

declare module "diffsync" {
    export var InMemoryDataAdapter:{
        new():any;
    };
    export var Server:{
        new(dataAdapter:any, io:any):any;
    };
}

declare module "stream-splitter" {
    function StreamSplitter(splitter:string):any;
    export = StreamSplitter;
}