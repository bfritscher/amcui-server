declare module 'stream-splitter' {
  function StreamSplitter(splitter: string): any;
  export = StreamSplitter;
}

declare module 'pdf-page-counter' {
  interface pdfData {
    numpages: number;
    numrender: number;
    info: any;
    metadata: any;
    version: string;
    text: string;
  }
  function pdf(dataBuffer: Buffer): pdfData;
  export = pdf;
}

declare module 'u2f' {
  interface Request {
    version: string;
    appId: string;
    challenge: string;
    keyHandle?: string;
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
    counter: number;
  }

  export function request(appId: string, keyHandle?: string): Request;
  export function checkRegistration(
    request: Request,
    registerData: any
  ): RegistrationResult;
  export function checkSignature(
    request: Request,
    signResult: any,
    publicKey: string
  ): SignatureResult;
}


declare module "y-websocket/bin/utils" {
  import { LeveldbPersistence } from 'y-leveldb'
  export function setPersistence(
    persistence_: {
      bindState: (arg0: string, arg1: WSSharedDoc) => void;
      writeState: (arg0: string, arg1: WSSharedDoc) => Promise<any>;
      provider: any;
    } | null
  ): void;
  export function getPersistence(): null | {
    provider: LeveldbPersistence;
    bindState: (arg0: string, arg1: WSSharedDoc) => void;
    writeState: (arg0: string, arg1: WSSharedDoc) => Promise<any>;
  } | null;
  export function setContentInitializor(
    f: (ydoc: Y.Doc) => Promise<void>
  ): void;
  export function setupWSConnection(
    conn: import("ws").WebSocket,
    req: import("http").IncomingMessage,
    { docName, gc }?: any
  ): void;
  export class WSSharedDoc extends Y.Doc {
    /**
     * @param {string} name
     */
    constructor(name: string);
    name: string;
    /**
     * Maps from conn to set of controlled user ids. Delete all user ids from awareness when this conn is closed
     * @type {Map<Object, Set<number>>}
     */
    conns: Map<any, Set<number>>;
    /**
     * @type {awarenessProtocol.Awareness}
     */
    awareness: awarenessProtocol.Awareness;
    whenInitialized: Promise<void>;
  }
  /**
   * @type {Map<string,WSSharedDoc>}
   */
  export const docs: Map<string, WSSharedDoc>;
  import Y = require("yjs");
  /**
   * Gets a Y.Doc by name, whether in memory or on disk
   *
   * @param {string} docname - the name of the Y.Doc to find or create
   * @param {boolean} gc - whether to allow gc on the doc (applies only when created)
   * @return {WSSharedDoc}
   */
  export function getYDoc(docname: string, gc?: boolean): WSSharedDoc;
  import awarenessProtocol = require("y-protocols/awareness");
}
