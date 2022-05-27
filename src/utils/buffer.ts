import { Buffer } from 'buffer'
import CryptoJS from 'crypto-js'

export function buffer2wa(v: Buffer): CryptoJS.lib.WordArray {
  return CryptoJS.enc.Hex.parse(v.toString('hex'))
}

export function wa2buffer(wa: CryptoJS.lib.WordArray) {
  return Buffer.from(wa.toString(CryptoJS.enc.Hex), 'hex')
}