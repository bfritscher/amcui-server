declare module "is-online" {
    function isOnline(callback:(err:Error, isOnline:boolean)=>void):void;
    export = isOnline;
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

declare module "image-size" {
    function sizeOf(uri:string, callback:(err:Error|null, dimensions:any) => void):any;
    export = sizeOf;
}

declare module "simple-git" {
    function SimpleGit(workingDirPath?:string):any;
    export = SimpleGit;
}

declare module "u2f" {
    interface Request {
        version:string,
        appId:string,
        challenge:string,
        keyHandle?:string
    }

    interface RegistrationResult {
        successful: boolean;
        publicKey: string;
        keyHandle: string;
        certificate: string;
    }

    interface SignatureResult {
        successful: boolean;
        userPresent: number;
        counter: number
    }

    export function request(appId:string, keyHandle?:string):Request;
    export function checkRegistration(request:Request, registerData:Object):RegistrationResult;
    export function checkSignature(request:Request, signResult:Object, publicKey:string):SignatureResult;
}