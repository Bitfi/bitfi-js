const WebSocket = require('isomorphic-ws')
const base64 = require('base64-js')
const CryptoJS = require('crypto')
const fetch = require('node-fetch')
const ecdsa = require('secp256k1')
const bs58 = require('./bs58')

function hexToBytes(hex) {
  for (var bytes = [], c = 0; c < hex.length; c += 2)
      bytes.push(parseInt(hex.substr(c, 2), 16));
  return bytes;
}

function calculateCode(randomSigningData, privKey, deviceId) {
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
  const first = bs58.encode(hexToBytes(tmp.slice(0, 4)))
  const second = tmp.slice(4, 10)
  
  return `${first}-${second}`.toUpperCase()
}

class Bitfi {
  constructor(
    authToken, 
    publicKey, 
    sessionSecret, 
    address, 
    config
  ) {
    this._config = config
    this._authToken = authToken
    this._publicKey = publicKey
    this._address = address,
    this._sessionSecret = sessionSecret
  }

  getPublicKey() {
    return this._publicKey
  }

  getAddress() {
    return this._address
  }

  getAuthToken() {
    return this._authToken
  }

  getConfig() {
    return this._config
  }

  getSessionSecret() {
    return this._sessionSecret
  }

  receiveEnvoy(envoyToken, onMessage) {
    return new Promise((res, rej) => {
      var websocket = new WebSocket(this._config.envoyUrl);
      
      websocket.on("open", function (event) {
        websocket.send(JSON.stringify({ ClientToken: envoyToken }));
      });
  
      websocket.on("message", function (e) {
        var obj = JSON.parse(e);

        const envoyMes = {
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
          res(JSON.parse(Buffer.from(base64.toByteArray(envoyMes.user_message), 'hex')))
        }
      })
    })
  }

  async signMessageBlind(message, onMessage) {
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

      const { data } = await fetch.post(this._config.apiUrl, request)
  
      if (data && data.error) {
        throw new Error(data.error && data.error.message)
      }
  
      if (!data && typeof data !== 'string') {
        throw new Error("Not valid envoy token")
      }
  
      envoyToken = data
    }
    catch (exc) {
      throw new Error(`Unable to fetch envoy token: ${JSON.stringify(exc && exc.message)}`)
    }
  
    const raw = await this.receiveEnvoy<any>(envoyToken, onMessage)

    return {
      success: raw.Success,
      signatureResponse: raw.SignatureResponse,
      nodeResponse: raw.NodeResponse
    }
  }
  

  async signMessagePrefixed(message, onMessage) {
    let envoyToken = ''
  
    try {
      const { data } = await fetch.post(this._config.apiUrl, {
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
  
      if (data && data.error) {
        throw new Error(data.error && data.error.message)
      }
  
      if (!data && typeof data !== 'string') {
        throw new Error("Not valid envoy token")
      }
  
      envoyToken = data
    }
    catch (exc) {
      throw new Error(`Unable to fetch envoy token: ${JSON.stringify(exc && exc.message)}`)
    }
  
    const raw = await this.receiveEnvoy<any>(envoyToken, onMessage)

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