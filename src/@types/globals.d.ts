declare module 'diffsync' {
  export let InMemoryDataAdapter: {
    new (): any;
  };
  export let Server: {
    new (dataAdapter: any, io: any): any;
  };
}

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
    registerData: Object
  ): RegistrationResult;
  export function checkSignature(
    request: Request,
    signResult: Object,
    publicKey: string
  ): SignatureResult;
}
