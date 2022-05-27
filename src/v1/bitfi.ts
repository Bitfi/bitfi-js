import WebSocket from 'isomorphic-ws'
import CryptoJS from 'crypto'
import { Buffer } from 'buffer'
import fetch from 'node-fetch'
import ecdsa from 'secp256k1'
import { BitfiConfig, Callback, EnvoyMessage, SignedMessageResponse } from './types'
import bs58 from '../utils/bs58'
import hex from '../utils/hex'

export function calculateCode(randomSigningData: string, privKey: string, deviceId: string) {
  const pubKey = Buffer.from(ecdsa.publicKeyCreate(Buffer.from(privKey, 'hex'), true))
  const ripemd160 = CryptoJS.createHash('ripemd160')
  const sha256 = CryptoJS.createHash('sha256')
  const md5 = CryptoJS.createHash('md5')

  const key160 = ripemd160.update(sha256.update(pubKey).digest()).digest()

  const data = Buffer.concat([
    key160,
    Buffer.from(deviceId, 'hex'),
    Buffer.from(randomSigningData, 'hex')
  ])
  
  const md5hash = md5.update(data).digest().toString('hex')

  const tmp = md5hash.slice(-12)
  const first = bs58.encode(hex.toBytes(tmp.slice(0, 4)))
  const second = tmp.slice(4, 10)
  
  return `${first}-${second}`.toUpperCase()
}

export class Bitfi {
  private readonly _config: BitfiConfig
  private readonly _authToken: string
  private readonly _publicKey: string
  private readonly _address: string
  private readonly _sessionSecret: string

  constructor(
    authToken: string, 
    publicKey: string, 
    sessionSecret: string, 
    address: string, 
    config: BitfiConfig
  ) {
    this._config = config
    this._authToken = authToken
    this._publicKey = publicKey
    this._address = address,
    this._sessionSecret = sessionSecret
  }

  public getPublicKey() {
    return this._publicKey
  }

  public getAddress() {
    return this._address
  }

  public getAuthToken() {
    return this._authToken
  }

  public getConfig() {
    return this._config
  }

  public getSessionSecret() {
    return this._sessionSecret
  }

  private _receiveEnvoy<T extends any>(envoyToken: string, onMessage?: Callback<EnvoyMessage>): Promise<T> {
    return new Promise((res, rej) => {
      var websocket = new WebSocket(this._config.envoyUrl);
      
      websocket.on("open", function (event: any) {
        websocket.send(JSON.stringify({ ClientToken: envoyToken }));
      });
  
      websocket.on("message", function (event: string) {
        var obj = JSON.parse(event);

        const envoyMes: EnvoyMessage = {
          completed: obj.Completed,
          error_message: obj.Error,
          user_message: obj.Message,
          ticks: obj.Ticks
        } 

        if (envoyMes.error_message) {
          //websocket.close()
          rej(envoyMes.error_message)
        }

        if (!envoyMes.completed) {
          onMessage && onMessage(envoyMes)
        }
        
        if (envoyMes.user_message && envoyMes.completed) {
          websocket.close()
          res(JSON.parse(Buffer.from(envoyMes.user_message, 'base64').toString('utf-8')))
        }
      })
    })
  }

  public async signMessageBlind(message: string, onMessage?: Callback<EnvoyMessage>): Promise<SignedMessageResponse> {
    let envoyToken = ''
    
    const sessionSecret = Buffer.from(this._sessionSecret, 'hex')
    const sha256 = CryptoJS.createHash('sha256')
    const hash = sha256.update(message, 'utf8').digest()    
    const pubKey = ecdsa.publicKeyCreate(sessionSecret)
    const res = ecdsa.ecdsaSign(hash, sessionSecret)


    //verify signature
    const verified = ecdsa.ecdsaVerify(res.signature, hash, pubKey)

    if (!verified) {
      throw new Error("Signature is not valid")
    }

    const signatureDer = ecdsa.signatureExport(res.signature)

    try {

      const request = {
        authToken: this._authToken,
        method: 'BlindMessage',
        messageModel: {
          BlindRequest: {
            PublicKey: Buffer.from(pubKey).toString('hex'),
            RequestMessage: message,
            Signature: Buffer.from(signatureDer).toString('hex')
          },
          MessageRequest: {
            Address: this._address,
            Symbol: 'dag',
          }
        }
      }

      const response = await fetch(this._config.apiUrl, {
        method: 'POST',
        body: JSON.stringify(request)
      })
      
      const data = await response.json()
  
      if (data && data.error) {
        throw new Error(data.error && data.error.message)
      }
  
      if (!data && typeof data !== 'string') {
        throw new Error("Not valid envoy token")
      }
  
      envoyToken = data
    }
    catch (exc: any) {
      throw new Error(`Unable to fetch envoy token: ${JSON.stringify(exc && exc.message)}`)
    }
  
    const raw = await this._receiveEnvoy<any>(envoyToken, onMessage)

    return {
      success: raw.Success,
      signatureResponse: raw.SignatureResponse,
      nodeResponse: raw.NodeResponse
    }
  }
  

  public async signMessagePrefixed(message: string, onMessage?: Callback<EnvoyMessage>): Promise<SignedMessageResponse> {
    let envoyToken = ''
  
    try {
      const res = await fetch(this._config.apiUrl, {
        method: 'POST',
        body: JSON.stringify({
          authToken: this._authToken,
          method: 'SignMessage',
          messageModel: {
            MessageRequest: {
              Message: message,
              Address: this._address,
              Symbol: 'dag',
            }
          }
        })
      })

      const data = await res.json()
  
      if (data && data.error) {
        throw new Error(data.error && data.error.message)
      }
  
      if (!data && typeof data !== 'string') {
        throw new Error("Not valid envoy token")
      }
  
      envoyToken = data
    }
    catch (exc: any) {
      throw new Error(`Unable to fetch envoy token: ${JSON.stringify(exc && exc.message)}`)
    }
  
    const raw = await this._receiveEnvoy<any>(envoyToken, onMessage)

    return {
      success: raw.Success,
      signatureResponse: raw.SignatureResponse,
      nodeResponse: raw.NodeResponse
    }
  }
}

module.exports = {
  Bitfi,
  calculateCode
}