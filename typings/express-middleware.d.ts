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

declare module "raven"{
    var middleware;
    var Client:Client;
    interface Client{
        new (dsn:String, options?:any);
        captureMessage(message:String, options?:any, callback?:Function);
        captureError(error:Error, options?:any, callback?:Function);
        captureQuery(query:String, type?:String, callback?:Function);
    }
}

declare module "is-online"{
    function isOnline(callback:(err:Error, isOnline:boolean)=>void):void;
    export = isOnline;
}