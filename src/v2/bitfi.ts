
import axios from 'axios'
import { ec } from "elliptic";
import { Buffer } from 'buffer'
import CryptoJS from 'crypto-js';
import Crypto from 'crypto'
import { 
  Addresses, DeviceInfo, PublicKeys, 
  Result, Signature, Symbol, 
  SignedTransaction, Session, TransferType, 
  Methods, OPCODES, TransferParams, DeviceErrorResponse 
} from './types';
import { DeviceError, TimeoutError } from './errors';
import { buffer2wa, wa2buffer } from '../../src/utils/buffer';
const curve = new ec('secp256k1')

export default class Bitfi { 
  private readonly _url: string
  private readonly _timeoutSec: number
  private _session: Session
  private readonly _channelPublicKey: Buffer
  private readonly _deviceID: string

  constructor(url: string, deviceId: string, channelPublicKey: Buffer | string, timeoutSec: number = 5) {
    const buffer: Buffer = typeof channelPublicKey === 'string'? Buffer.from(channelPublicKey, 'hex') : channelPublicKey

    if (buffer.length !== 33)
      throw new Error("Invalid compressed public key, it should 33 bytes")

    if (Buffer.from(deviceId, 'hex').length !== 3) {
      throw new Error(`Invalid device id ${deviceId}`)
    }
    this._timeoutSec = timeoutSec
    this._channelPublicKey = buffer
    this._url = url
    this._deviceID = deviceId
  }

  private async _request(content: Buffer, timeoutSec?: number): Promise<string> {
    const wrapped = content.toString('base64')

    const { data } = await axios(`${this._url}/?nonce=${this._deviceID}&timeout=${timeoutSec || this._timeoutSec}&channel=${this._channelPublicKey.toString('hex')}`, {
      method: 'POST',
      headers: {'Content-Type': 'application/text'},
      data: wrapped
    })

    if (data.indexOf("timeout") !== -1) {
      throw new TimeoutError()
    }

    return this._decode(data)
  }

  
  private _decode(raw: string): string {
    const buffer = Buffer.from(raw, 'base64')
    const opcode = buffer.slice(0, 4)
    const data = buffer.slice(4)

    switch (opcode.toString('hex')) {
      case OPCODES.CHALLEGE:
      case OPCODES.AUTH:
        return data.toString('hex')

      case OPCODES.PONG:
        return opcode.toString('utf-8')
        
      case OPCODES.ENCRYPTED:
        return this._decrypt(buffer, this._session).toString('utf-8')
      
      default: {
        const deviceError = JSON.parse(buffer.toString('utf-8')) as DeviceErrorResponse
        throw new DeviceError(deviceError.message, deviceError.code)
      }
    }
  }
  

  public async ping(): Promise<boolean> {
    try {
      const parsed = await this._request(Buffer.from("PING", 'ascii'))
      
      if (parsed !== "PONG") {
        throw new Error("Invalid response")
      }

      return true
    }
    catch (exc) {
      console.log(exc)
      return false
    }
  }

  private _deserializeSessionDhKeyHash(session: Session) {
    const { sharedSecretHash } = session
    const iv = sharedSecretHash.slice(0, 16)
    const encKey = sharedSecretHash.slice(16, 32)
    const hashingKey = sharedSecretHash.slice(32)

    return {
      iv,
      encKey,
      hashingKey
    }
  }

  private _decrypt(encrypted: Buffer, session: Session): Buffer {
    const opcode = encrypted.slice(0, 4)
    const devicePublicKey = encrypted.slice(4, 37)
    const cipherText = encrypted.slice(37, encrypted.length - 32)
    const mac = encrypted.slice(encrypted.length - 32)
    const { iv, encKey, hashingKey } = this._deserializeSessionDhKeyHash(session)

    const hmac = wa2buffer(CryptoJS.HmacSHA256(buffer2wa(
      Buffer.concat([
        opcode,
        devicePublicKey,
        cipherText
      ])
    ), buffer2wa(hashingKey)))
    
    if (!hmac.equals(mac)) {
      throw new Error(`hmac's are not equal`)
    }

    const decipher = CryptoJS.algo.AES.createDecryptor(
      buffer2wa(encKey), 
      {
        mode: CryptoJS.mode.CBC, 
        padding: CryptoJS.pad.Pkcs7,
        iv: buffer2wa(iv)
      }
    )

    let decryptedText: Buffer = wa2buffer(decipher.process(buffer2wa(cipherText)))
    
    decryptedText = Buffer.concat([
      decryptedText,
      wa2buffer(decipher.finalize())
    ])

    return decryptedText
  }

  private _encrypt(message: Buffer, session: Session): Buffer {
    const { code, eckey } = session
    const { iv, encKey, hashingKey } = this._deserializeSessionDhKeyHash(session)

    const cipher = CryptoJS.algo.AES.createEncryptor(
      buffer2wa(encKey), 
      {
        mode: CryptoJS.mode.CBC, 
        padding: CryptoJS.pad.Pkcs7,
        iv: buffer2wa(iv)
      }
    )

    let cipherText = wa2buffer(cipher.process(buffer2wa(message)))
    
    cipherText = Buffer.concat([
      cipherText,
      wa2buffer(cipher.finalize())
    ])
    
    const publiKey = Buffer.from(eckey.getPublic().encodeCompressed('hex'), 'hex')

    const data = Buffer.concat([
      code,
      publiKey,
      cipherText
    ])

    const hmac = wa2buffer(CryptoJS.HmacSHA256(buffer2wa(data), buffer2wa(hashingKey)))
    const res = Buffer.concat([
      data,
      hmac
    ])

    return res
  }
  
  private _calculateSessionCode(pubKey: Buffer, message: Buffer): Buffer {
    const key160 = wa2buffer(CryptoJS.RIPEMD160(
      CryptoJS.SHA256(buffer2wa(pubKey))
    ))

    const data = Buffer.concat([
      key160,
      message,
    ])

    const code = wa2buffer(CryptoJS.MD5(buffer2wa(data))).slice(0, 4)
    return code
  }

  public async authorize() {
    const eckey = curve.genKeyPair()

    const publicKeyCompressed = eckey.getPublic().encodeCompressed('hex')

    const message = await this._request(Buffer.from(`${OPCODES.CHALLEGE}${publicKeyCompressed}`, 'hex'))
    const bytes = Buffer.from(message, 'hex')
      
    if (bytes.length !== 16) {
      throw new Error("Invalid message to sign")
    }

    const code = this._calculateSessionCode(Buffer.from(publicKeyCompressed, 'hex'), bytes)
    const hash = wa2buffer(CryptoJS.SHA256(buffer2wa(bytes)))

    const derSignature = eckey.sign(hash, { canonical: true }).toDER()
    const derSignatureHex = Buffer.from(derSignature).toString('hex');

    const verified = eckey.verify(hash, derSignature)
    
    if (!verified) {
      throw new Error("Invalid signature")
    }

    const keyHex = await this._request(Buffer.from(`${OPCODES.AUTH}${message}${derSignatureHex}`, 'hex'), 60 << 1)
    const key = curve.keyFromPublic(keyHex, 'hex').getPublic()

    const sharedHex = key.mul(eckey.getPrivate()).encodeCompressed('hex') //03 means compressed
    const sharedSecretHash = wa2buffer(CryptoJS.SHA512(buffer2wa(Buffer.from(sharedHex, 'hex'))))
  
    const session: Session = {
      code,
      eckey,
      sharedSecretHash
    }
    
    this._session = session
  }

  private async _requestEncrypted<T>(object: any): Promise<T> {
    const serialized = Buffer.from(JSON.stringify(object), 'utf-8')
    const ecnrypted = this._encrypt(serialized, this._session)
    const jsonraw = await this._request(ecnrypted, 120)
    const res = JSON.parse(jsonraw) as Result<T>
    return res.result
  }

  public async getDeviceInfo(): Promise<DeviceInfo> {
    const object = {
      method: Methods.get_device_info.toString(),
    }

    return this._requestEncrypted<DeviceInfo>(object)
  }

  public async transfer<T extends TransferType>(params: TransferParams[T]): Promise<SignedTransaction> {
    const object = {
      method: Methods.transfer.toString(),
      params: {
        ...params,
        amount: params.amount.toString(),
        feeValue: (params.gasPrice * params.gasLimit).toString(),
        gasUsed: params.gasLimit.toString(),
      }
    }

    delete object.params.gasPrice
    delete object.params.gasLimit

    return this._requestEncrypted<SignedTransaction>(object)
  }

  public async getAddresses(symbol: Symbol = 'eth'): Promise<string[]> {
    const object = {
      method: Methods.get_addresses,
      params: {
        symbol
      }
    }

    return (await this._requestEncrypted<Addresses>(object)).addresses
  }

  public async getDeviceEnvoy(): Promise<string> {
    const object = {
      method: Methods.get_device_envoy,
    }

    return await this._requestEncrypted<string>(object)
  }

  public async getPublicKeys(symbol: Symbol = 'eth'): Promise<string[]> {
    const object = {
      method: Methods.get_pub_keys,
      params: {
        symbol
      }
    }

    return (await this._requestEncrypted<PublicKeys>(object)).publicKeys
  }

  public async signMessage(address: string, message: Buffer | string, symbol: Symbol = 'eth'): Promise<Signature> {
    const buffer: Buffer = typeof message === 'string'? Buffer.from(message, 'utf-8') : message

    const object = {
      method: Methods.sign_message.toString(),
      params: {
        address,
        message: buffer.toString('base64'),
        symbol
      }
    }

    return this._requestEncrypted<Signature>(object)
  }
}