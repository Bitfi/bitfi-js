import { DeviceError } from "./errors"

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


export type EthLikeSymbol = 'eth'
export type Symbol = ('dag' | 'btc') | EthLikeSymbol

type GeneralParamsDescriptor = {
  from: string,
  to: string,
  amount: string
}

type EthLikeSpecificParams = {
  gasPrice: string,
  gasLimit: string,
  nonce: number
}

type BtcLikeSpecificParams = {
  fee: string
}

export type DagLastTxRef = {
  prevHash: string,
  ordinal: number
}

export type DagSignedTransaction = {
  edge: {
    parents: any[], 
    data: any
  },
  data: {
    amount: string,
    lastTxRef: DagLastTxRef,
    salt: number,
    fee: string
  },
  isDummy: boolean,
  isTest: boolean,
  lastTxRef: DagLastTxRef
}

export enum DeviceEventType {
  Battery = 1,
  Availability,
  Session,
  Error = 999
}

type DeviceEventPayloadMap = {
  [DeviceEventType.Battery]: {
    isCharging: boolean
    level: number 
  },
  [DeviceEventType.Availability]: {
    isUserBusy: boolean,
    isUserBlocking: boolean
  },
  [DeviceEventType.Session]: {
    isDisposed: boolean
  },
  [DeviceEventType.Error]: DeviceError,
}

export type TransferResponse = {
  [key in Exclude<Symbol, 'dag'>]: string
} & {
  [key in 'dag']: DagSignedTransaction
}

export type DeviceEvent = {
  [key in DeviceEventType]: DeviceEventPayloadMap[key]
}

export type BitfiDump = {
  code: string,
  sharedSecretHash: string,
  eckey: any,
  deviceId: string
}

export type DeviceMessageRaw = {
  error: string,
  ticks: string,
  message: string,
  completed: boolean
}

export type DeviceMessage<T extends DeviceEventType> = {
  event_type: T,
  event_info: DeviceEvent[T]
}

export type DeviceEventCallback<T extends DeviceEventType> = (event: DeviceEvent[T]) => void

type SpecificParamsDescriptor = {
  [TransferType.OUT_SELF]: {
    'eth': EthLikeSpecificParams
    'dag': BtcLikeSpecificParams & {
      lastTxRef: DagLastTxRef
    },
    'btc': BtcLikeSpecificParams
  },

  [TransferType.BLIND_EXECUTION]: {
    [key in Exclude<Symbol, EthLikeSymbol>]: never 
  } & {
    [key in EthLikeSymbol]: EthLikeSpecificParams & {
      data: string
    }
  },

  [TransferType.TOKENTRANSFER]: {
    [key in Exclude<Symbol, EthLikeSymbol>]: never 
  } & {
    [key in EthLikeSymbol]: EthLikeSpecificParams & {
      tokenAddr: string,
      decimals: number,
      tokenName: string,
      transferType: TransferType.TOKENTRANSFER
    }
  }
}

export type TransferParams = {
  [type in TransferType]: {
    [key in Symbol]: GeneralParamsDescriptor & SpecificParamsDescriptor[type][key] & {
      symbol: key,
      transferType: type
    }
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