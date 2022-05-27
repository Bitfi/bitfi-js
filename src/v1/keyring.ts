import { Transaction } from 'ethereumjs-tx'
import { BitfiConfig, SignInParams, BitfiKeyringSerialized } from './types'
import { IBitfiKeyring } from '../types'
import { Buffer } from 'buffer'
import { Bitfi, calculateCode } from './bitfi'
import WebSocket from 'isomorphic-ws'
import axios from 'axios'
import { ec } from "elliptic";
const curve = new ec('secp256k1')

function signin(params: SignInParams): Promise<IBitfiKeyring<BitfiKeyringSerialized>>{
  const privKey = Buffer.from(params.appSecret, 'hex')
  const randomSigningData = Buffer.from(params.signData, 'hex')
  const deviceId = Buffer.from(params.deviceId, 'hex')
  
  /*
  if (!ecdsa.privateKeyVerify(privKey)) {
    throw new Error("Invalid ecdsa key, please, provide another one")
  }
  */

  if (deviceId.length !== 3) {
    throw new Error('Invalid device ID')
  }

  if (randomSigningData.length !== 16) {
    throw new Error("Invalid randomsigning data")
  }

  if (privKey.length !== 32) {
    throw Error("Inavlid private key")
  }

  const eckey = curve.keyFromPrivate(privKey)
  const pubKey = Buffer.from(eckey.getPublic().encodeCompressed('hex'), 'hex')  

  //const pubKey = Buffer.from(ecdsa.publicKeyCreate(privKey, true))
  const code = calculateCode(params.signData, params.appSecret, params.deviceId)

  let notified = false

  return new Promise((res, rej) => {
    
    let websocket = new WebSocket(params.url);
    
    const request = {
      data_for_signing: randomSigningData.toString('hex'),
      device_id: params.deviceId,
      match_profile: true,
      request_method: "register",
      public_key: `${pubKey.toString('hex')}`, //04 means uncompressed public key
      request_id: "",
      derivation_index: "22" //dag
    }

    websocket.on('open', function (event: any) {
      websocket.send(JSON.stringify(request));
    });
    

    websocket.on('message', async function (e: any) {
      const response = JSON.parse(e)

      if (response.display_code && response.display_code !== code) {
        rej('Codes are not equal, please, contact support')
      }

      if (response.error_message) {
        //websocket.close()
        rej(response.error_message)
      }

      if (response.notified && !notified) {
        params.onNotified && params.onNotified()
        notified = true
      }

      if (response.completed === false) {
        params.onMessage && params.onMessage(response)
      } else {
        const token = response.request_id 

        try {
          const keyring = new BitfiKeyring()
          await keyring.deserialize({
            authToken: token,
            publicKey: response.public_key,
            appSecret: params.appSecret,
            config: params.config
          })
          res(keyring)
        }
        catch (exc) {
          rej(exc)
        }
        finally {
          websocket.close()
        }
      }
    });
  })
};

async function request(token: string, method: 'GetAddresses' | 'IsTokenValid', url: string, params = undefined) {
  const response = await axios(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
      // 'Content-Type': 'application/x-www-form-urlencoded',
    },
    data: JSON.stringify({
      authToken: token,
      method,
      transferModel: params
    })
  })
  const json = await response.data

  if (json.error)
    throw new Error(json.Content.error)

  return json
}

async function init(token: string, public_key: string, secret: string, config: BitfiConfig) {
  
  const { Content : addresses } = await request(token, 'GetAddresses', config.apiUrl)

  if (!addresses || !addresses[0])
    throw new Error('No address')
  
  const valid = await request(token, 'IsTokenValid', config.apiUrl)

  if (!valid)
    throw new Error('Invalid token, sign in again')
  
  const address = addresses[0]
  const bitfi = new Bitfi(token, public_key, secret, address, config)
  
  return bitfi
  
}

class BitfiKeyring implements IBitfiKeyring<BitfiKeyringSerialized> {
  private _bitfi: Bitfi | null
  public type: string = "Bitfi"

  constructor() {
    this._bitfi = null
  }

  public async signPersonalMessage(address: string, data: string) {
    this._checkAddress(address)

    const res = await this._bitfi.signMessagePrefixed(data)
    return res.signatureResponse
  }

  public async serialize() {
    const authToken = this._bitfi.getAuthToken()
    const appSecret = this._bitfi.getSessionSecret()
    const publicKey = this._bitfi.getPublicKey()
    const config = this._bitfi.getConfig()

    const serialized = {
      authToken,
      appSecret,
      publicKey,
      config
    }

    return serialized
  }

  public async deserialize(obj: {
    authToken: string,
    publicKey: string,
    appSecret: string,
    config: BitfiConfig
  }) {
    this._bitfi = await init(
      obj.authToken, 
      obj.publicKey, 
      obj.appSecret,
      obj.config
    )
  }

  public async addAccounts(n: number) {
    throw new Error("Is not supported on this device");
  }

  private _checkInitialized() {
    if (!this._bitfi)
      throw new Error('Not initialized')
  }

  public async getAccounts() {
    const address = this._bitfi.getAddress()
    return [address]
  }

  public async signTransaction(address: string, transaction: Transaction) {
    this._checkAddress(address)

    //if (transaction.data) {
    const serialized = transaction.serialize().toString('hex')
    const res = await this._bitfi.signMessageBlind(serialized)

    //const { v, r, s } = derh2obj(res.signatureResponse)
    //transaction.v = v
    //transaction.r = r
    //transaction.s = s
    return transaction
    //}
  }

  private _checkAddress(address: string) {
    if (address.toLowerCase() !== this._bitfi.getAddress().toLowerCase()) {
      throw new Error(`This address is not present in bitfi wallet: ${address}`)
    }
  }

  public async signMessage(address: string, data: string) {
    this._checkAddress(address)

    const signature = await this._bitfi.signMessageBlind(data)
    return signature.signatureResponse
  }

  public async getEncryptionPublicKey(address: string) {
    this._checkAddress(address)

    return this._bitfi.getPublicKey()
  }

  public async decryptMessage(address: string, data: string): Promise<string> {
    throw new Error("Method not implemented.");
  }

  public async exportAccount(address: string) {
    throw new Error("Not supported on this device");
  }

  public async removeAccount(address: string) {
    this._bitfi = null
  }
  
}

export {
  BitfiKeyring,
  signin, 
  calculateCode
}
