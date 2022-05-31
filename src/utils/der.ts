import prefix from './prefix'
import { DER } from './types'

function from(buffer: Buffer | string): DER {
  const derhex = buffer instanceof Buffer? 
    prefix.remove(buffer.toString('hex')) :
    buffer

  const format = derhex.slice(0, 2)
  if (format !== '30') {
    throw new Error("Not a der signature")
  }

  //const length = parseInt(derhex.slice(2, 4), 16)
  
  if (derhex.slice(4, 6) !== '02') {
    throw new Error("Not a der signature")
  }

  const lengthR = parseInt(derhex.slice(6, 8), 16) << 1
  const r = derhex.slice(8, 8 + lengthR)

  if (derhex.slice(8 + lengthR, 8 + lengthR + 2) !== '02') {
    throw new Error("Not a der signature")
  }

  const lengthS = parseInt(derhex.slice(8 + lengthR + 2, 10 + lengthR + 2), 16) << 1
  const s = derhex.slice(12 + lengthR, 12 + lengthR + lengthS)
  //'304502200b69ac595722a1547a6765e652c617e0d1e887e81e752b9252dbcaf5089589640221009b232abb2c90fbb01e980a62af37d85189643a796bed19e863ef09e38de4c05a'
  //'        0b69ac595722a1547a6765e652c617e0d1e887e81e752b9252dbcaf508958964    009b232abb2c90fbb01e980a62af37d85189643a796bed19e863ef09e38de4c05a
  return {
    v: Buffer.from('0', 'hex'),
    r: Buffer.from(r, 'hex'),
    s: Buffer.from(s, 'hex')
  }
}

export default {
  from
}