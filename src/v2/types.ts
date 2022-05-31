export type DeviceInfo = {
  devicePubKey: string,
  signerPubKey: string,
  runningVersion: string,
  availableMem: string,
  deviceTime: string,
  uptimeElapsed: string,
  uptimeAwake: string,
  isRestartPending: boolean,
  isVibeEnabled: boolean,
  isAutoUpdate: boolean,
  processList: string[]
}

export type EthLikeSymbol = 'eth' | 'dag'
export type Symbol = 'btc' | EthLikeSymbol

export type SignedTransaction = {
  transaction: string
}

export type Addresses = {
  addresses: string[]
}

export type PublicKeys = {
  publicKeys: string[]
}

export type Result<T> = {
  result: T
}

export type Signature = {
  signature: string
}

export type Session = {
  code: Buffer,
  sharedSecretHash: Buffer,
  eckey: any
}

export enum Methods {
  transfer = 1, 
  sign_message, 
  get_addresses,
  get_pub_keys, 
  get_bat_stats, 
  get_device_info, 
  get_device_envoy
}

//BAD!
export enum TransferType {
  OUT_SELF = 0,
  BLIND_EXECUTION,
  TOKENTRANSFER,
}

type GeneralParams = {
  from: string,
  gasPrice: bigint,
  gasLimit: bigint,
  amount: bigint,
  nonce: number,
  symbol: Symbol,
  transferType: TransferType,
}

export type TransferParams = {
  [TransferType.OUT_SELF]: GeneralParams & {
    to: string,
  },
  [TransferType.BLIND_EXECUTION]: GeneralParams & {
    tokenAddr: string,
    contractData: string
  },
  [TransferType.TOKENTRANSFER]: GeneralParams & {
    to: string,
    tokenAddr: string,
    decimals: number,
    tokenName: string
  }
}

export type DeviceErrorResponse = {
  message: string,
  code: number
}

export enum OPCODES {
  CHALLEGE = "90c55055",
  AUTH = "e9d92935",
  PONG = "504f4e47", //ascii for PONG
  ENCRYPTED = "41494531" // ascii for AIE1
}