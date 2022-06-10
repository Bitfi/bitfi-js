
import axios from 'axios'
import { ec } from "elliptic";
import { Buffer } from 'buffer'
import CryptoJS from 'crypto-js';
import { 
  Addresses, DeviceInfo, PublicKeys, 
  Result, Signature, Symbol, 
  SignedTransaction, Session, TransferType, 
  Methods, OPCODES, TransferParams, DeviceErrorResponse, 
  EthLikeSymbol, TransferResponse, BitfiDump 
} from './types';
import { DeviceError, DeviceNotSupported, TimeoutError } from './errors';
import { buffer2wa, wa2buffer } from '../../src/utils/buffer';
import { IBitfiKeyring, IDeviceListener } from '../types';
import { Transaction } from 'ethereumjs-tx';
import { WebSocket } from 'ws';
import { Listener } from './listener';
const curve = new ec('secp256k1')

const DEFAULT_NEED_APPROVE_MSEC = 60 * 1000
const DEFAULT_NO_APPROVE_MSEC = 3 * 1000
const DEFAULT_AUTHORIZE_TIMEOUT_MSEC  = 120 * 1000

export default class Bitfi implements IBitfiKeyring<BitfiDump> { 
  public type: string = "Bitfi"
  private _url: string
  private _session: Session
  private _channelPublicKey: Buffer
  private _deviceID: string

  constructor(url: string, channelPublicKey: Buffer | string, deviceId?: string) {
    const buffer: Buffer = typeof channelPublicKey === 'string'? Buffer.from(channelPublicKey, 'hex') : channelPublicKey

    if (buffer.length !== 33)
      throw new Error("Invalid compressed public key, it should 33 bytes")

    this._channelPublicKey = buffer
    this._url = url
    
    if (deviceId) {
      if (Buffer.from(deviceId, 'hex').length !== 3) {
        throw new Error(`Invalid device id ${deviceId}`)
      }

      this._deviceID = deviceId
    }
  }
  
  public async createListener(url: string, wsProvider: WebSocket): Promise<IDeviceListener> {
    //@ts-ignore
    return new Listener(this, url, wsProvider)
  }

  public async getAccounts(symbol: Symbol, timeoutMsec: number = DEFAULT_NO_APPROVE_MSEC): Promise<string[]> {
    const object = {
      method: Methods.get_addresses,
      params: {
        symbol
      }
    }

    return (await this._requestEncrypted<Addresses>(object, timeoutMsec)).addresses
  }

  public async removeAccount(address: string): Promise<void> {
    this._session = null
    this._channelPublicKey = null
    this._deviceID = null
  }

  public async serialize(): Promise<BitfiDump> {
    return {
      deviceId: this._deviceID,
      sharedSecretHash: this._session.sharedSecretHash.toString('hex'),
      eckey: this._session.eckey.getPrivate().toString('hex'),
      code: this._session.code.toString('hex')
    }
  }

  public async deserialize(obj: BitfiDump): Promise<void> {
    this._session = {
      eckey: curve.keyFromPrivate(obj.eckey, 'hex'),
      sharedSecretHash: Buffer.from(obj.sharedSecretHash, 'hex'),
      code: Buffer.from(obj.code, 'hex')
    }
    this._deviceID = obj.deviceId
  }

  public async enable(timeoutMsec: number = 30000, pingFrequencyMsec: number = 5000): Promise<void> {
    const deadline = Date.now() + timeoutMsec
    return new Promise((res, rej) => {
      const ping = async () => {
        if (Date.now() > deadline) 
          rej(new TimeoutError())

        try {
          const state = await this.ping(pingFrequencyMsec)
          if (state) {
            clearInterval(id)
            res()
          }
        }
        catch (exc) {}
      }

      ping()
      let id = setInterval(ping, pingFrequencyMsec)
    })
  }

  public async ping(timeoutMsec: number = 3000): Promise<boolean> {
    try {
      console.log('Ping...')
      const parsed = await this._request(Buffer.from("PING", 'ascii'), timeoutMsec)
      
      if (parsed !== "PONG") {
        throw new Error("Invalid response")
      }

      return true
    }
    catch (exc) {
      return false
    }
  }

  public async authorize(
    onSessionCodeReceived: (code: string) => void, 
    timeoutMsec: number = DEFAULT_AUTHORIZE_TIMEOUT_MSEC 
  ): Promise<boolean> {
    const eckey = curve.genKeyPair()

    const publicKeyCompressed = eckey.getPublic().encodeCompressed('hex')

    const message = await this._request(Buffer.from(`${OPCODES.CHALLEGE}${publicKeyCompressed}`, 'hex'), DEFAULT_NO_APPROVE_MSEC)
    const bytes = Buffer.from(message, 'hex')
      
    if (bytes.length !== 16) {
      throw new Error("Invalid message to sign")
    }

    const code = this._calculateSessionCode(Buffer.from(publicKeyCompressed, 'hex'), bytes)
    onSessionCodeReceived(code.toString('hex'))
    
    const hash = wa2buffer(CryptoJS.SHA256(buffer2wa(bytes)))

    const derSignature = eckey.sign(hash, { canonical: true }).toDER()
    const derSignatureHex = Buffer.from(derSignature).toString('hex');

    const verified = eckey.verify(hash, derSignature)
    
    if (!verified) {
      throw new Error("Invalid signature")
    }

    const keyHex = await this._request(Buffer.from(`${OPCODES.AUTH}${message}${derSignatureHex}`, 'hex'), timeoutMsec)
    const key = curve.keyFromPublic(keyHex, 'hex').getPublic()

    const sharedHex = key.mul(eckey.getPrivate()).encodeCompressed('hex') //03 means compressed
    const sharedSecretHash = wa2buffer(CryptoJS.SHA512(buffer2wa(Buffer.from(sharedHex, 'hex'))))
  
    const session: Session = {
      code,
      eckey,
      sharedSecretHash
    }
    
    this._session = session
    return true
  }

  public async getDeviceInfo(timeoutMsec: number = DEFAULT_NO_APPROVE_MSEC): Promise<DeviceInfo> {
    const object = {
      method: Methods.get_device_info.toString(),
    }

    return this._requestEncrypted<DeviceInfo>(object, timeoutMsec)
  }

  public async transfer<T extends TransferType, C extends Symbol>(
    params: TransferParams[T][C], timeoutMsec: number = DEFAULT_NEED_APPROVE_MSEC
  ): Promise<TransferResponse[C]> {
    //@ts-ignore
    const isEthLike = params.gasPrice && params.gasLimit
    const isDag = params.symbol === 'dag'
    const isBlindExecution = params.transferType === TransferType.BLIND_EXECUTION

    const object = {
      method: Methods.transfer.toString(),
      params: {
        ...params,
        ...isEthLike? {
          ...isBlindExecution? { tokenAddress: params.to }: {},
          //@ts-ignore
          feeValue: (BigInt(params.gasPrice) * BigInt(params.gasLimit)).toString(),
          //@ts-ignore
          gasUsed: params.gasLimit.toString(),
        } : {
          //@ts-ignore
          feeValue: params.fee
        },
        ...isDag? { lastTxRef: JSON.stringify(params.lastTxRef)} : {}
      }
    }

    //@ts-ignore
    delete object.params.gasPrice
    //@ts-ignore
    delete object.params.gasLimit

    let response = (await this._requestEncrypted<SignedTransaction>(object, timeoutMsec)).transaction

    if (isDag) {
      response = JSON.parse(Buffer.from(response, 'base64').toString('utf-8'))
    }

    return response as TransferResponse[C]
  }

  public async getDeviceEnvoy(timeoutMsec: number = DEFAULT_NO_APPROVE_MSEC): Promise<string> {
    const object = {
      method: Methods.get_device_envoy,
    }

    return await this._requestEncrypted<string>(object, timeoutMsec)
  }

  public async getPublicKeys(symbol: Symbol, timeoutMsec: number = DEFAULT_NO_APPROVE_MSEC): Promise<string[]> {
    const object = {
      method: Methods.get_pub_keys,
      params: {
        symbol
      }
    }

    return (await this._requestEncrypted<PublicKeys>(object, timeoutMsec)).publicKeys
  }

  public async signMessage(
    address: string, message: Buffer | string, 
    symbol: Symbol, timeoutMsec: number = DEFAULT_NEED_APPROVE_MSEC
  ): Promise<string> {
    const buffer: Buffer = typeof message === 'string'? Buffer.from(message, 'utf-8') : message

    const object = {
      method: Methods.sign_message.toString(),
      params: {
        address,
        message: buffer.toString('base64'),
        symbol
      }
    }

    return (await this._requestEncrypted<Signature>(object, timeoutMsec)).signature
  }

  public addAccounts(n: number): Promise<void> {
    throw new DeviceNotSupported()
  }
  
  
  public async signTransaction(address: string, transaction: Transaction, symbol: EthLikeSymbol): Promise<Transaction> {
    throw new DeviceNotSupported()
    /*
    const hexDer = await this.transfer<TransferType.BLIND_EXECUTION>({
      from: address,
      amount: BigInt(transaction.value.toString('hex')),
      nonce: parseInt(transaction.nonce.toString('hex'), 16),
      gasPrice: BigInt(transaction.gasPrice.toString('hex')),
      gasLimit: BigInt(transaction.gasLimit.toString('hex')),
      symbol,
      transferType: TransferType.BLIND_EXECUTION,
      contractData: transaction.data.toString('hex'),
      tokenAddr: transaction.to.toString('hex')
    })

    const der = DER.from(Buffer.from(hexDer, 'hex'))

    transaction.r = der.r
    transaction.s = der.s
    transaction.v = der.v
    */
  }
  
  
  public getEncryptionPublicKey(address: string): Promise<string> {
    throw new DeviceNotSupported()
  }

  public async decryptMessage(address: string, data: string): Promise<string> {
    throw new DeviceNotSupported()
  }

  public async exportAccount(address: string): Promise<void> {
    throw new DeviceNotSupported()
  }

  /** PRIVATE */
  private async _request(content: Buffer, timeoutMsec: number): Promise<string> {
    const wrapped = content.toString('base64')
    const timeoutSec = Math.round(timeoutMsec / 1000)
    
    const { data } = await axios(`${this._url}/?nonce=${this._deviceID}&timeout=${timeoutSec}&channel=${this._channelPublicKey.toString('hex')}`, {
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
        const deviceError = JSON.parse(buffer.toString('utf-8')).error as DeviceErrorResponse
        throw new DeviceError(deviceError.message, deviceError.code)
      }
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

  private async _requestEncrypted<T>(object: any, timeoutMsec: number): Promise<T> {
    const serialized = Buffer.from(JSON.stringify(object), 'utf-8')
    const ecnrypted = this._encrypt(serialized, this._session)
    const jsonraw = await this._request(ecnrypted, timeoutMsec)
    const res = JSON.parse(jsonraw) as Result<T>
    return res.result
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
}