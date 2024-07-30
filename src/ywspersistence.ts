import {RedisClientType, commandOptions } from 'redis';
import * as Y from "yjs";
import ywsUtils from 'y-websocket/bin/utils';

function stripPrefix(prefix: string, key: string) {
  return key.startsWith(prefix) ? key.slice(prefix.length) : key;
}

export function ywsRedisPersistence(redisClient: RedisClientType, namespace: string, prefix?: string) {
  const provider = {
    async retrieveDoc(docName: string) {
      try {
        docName = prefix ? stripPrefix(prefix, docName) : docName;
        return await redisClient.GET(commandOptions({ returnBuffers: true }), `${namespace}:${docName}`);
      } catch (error) {
        return null;
      }
    },
    async persistDoc(docName: string, ydoc: Y.Doc) {
      const state = Y.encodeStateAsUpdateV2(ydoc);
      try {
        docName = prefix ? stripPrefix(prefix, docName) : docName;
        await redisClient.SET(`${namespace}:${docName}`, Buffer.from(state));
      } catch (error) {
        console.error(`Error saving document ${docName}:`, error);
      }
    },
  };

  ywsUtils.setPersistence({
    provider,
    bindState: async (docName, ydoc) => {
      const persistedYdoc = await provider.retrieveDoc(docName);
      if (persistedYdoc) {
        Y.applyUpdateV2(ydoc, persistedYdoc);
      }
      ydoc.on('update', (_update, _origin, doc) => {
        provider.persistDoc(docName, doc);
      });
    },
    writeState: async (_docName, _ydoc) => {},
  });
}

/* check initial doc here or in persistence or on client?
  ywsUtils.setContentInitializor(async (ydoc: Y.Doc) => {
    // ydoc as WSSharedDoc
    console.log("Initializing content", ydoc);
  });
  */
