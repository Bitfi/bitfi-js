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
  addresses: WalletAddress[]
}

export type LegacyProfile = {
  symbol: Symbol,
  index: number,
  doSegwit: boolean,
  address: string
}

export type PublicKeys = {
  publicKeys: string[]
}

export type Utxo = {
  address: string,
  amount: string,
  txnHash: string,
  number: number
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
  get_device_info, 
  get_device_envoy,
  get_legacy_profile
}

export type RequestObject = {
  method: Methods
  params?: any
}

//BAD!
export enum TransferType {
  OUT_SELF = 0,
  BLIND_EXECUTION,
  TOKENTRANSFER,
}


export type WalletAddress = {
  address: string,
  index: string
}

export type SegwitParam = {
  [key in SegwitSupportedSymbol]: true | false
} & {
  [key in Exclude<Symbol, SegwitSupportedSymbol>]: false
}

export type EthLikeSymbol = 'eth'
export type SegwitSupportedSymbol = 'btc'
export type Symbol = ('dag' | 'btc') | EthLikeSymbol

type GeneralParamsDescriptor = {
  from: string,
  to: string,
  amount: string,
  index: number
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
    data: {
      amount: string,
      lastTxRef: DagLastTxRef,
      salt: number,
      fee: string
    },
  },
  isDummy: boolean,
  isTest: boolean,
  lastTxRef: DagLastTxRef
}

export enum EventType {
  Battery = 1,
  Availability,
  Session,
  Closed = 998,
  Error = 999
}

type DeviceEventPayloadMap = {
  [EventType.Battery]: {
    isCharging: boolean
    level: number 
  },
  [EventType.Availability]: {
    isUserBusy: boolean,
    isUserBlocking: boolean
  },
  [EventType.Session]: {
    isDisposed: boolean
  },
  [EventType.Error]: DeviceError,
  [EventType.Closed]: void
}

export type TransferResponse = {
  [key in Exclude<Symbol, 'dag'>]: string
} & {
  [key in 'dag']: DagSignedTransaction
}

export type DeviceEvent = {
  [key in EventType]: DeviceEventPayloadMap[key]
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

export type DeviceMessage<T extends EventType> = {
  event_type: T,
  event_info: DeviceEvent[T]
}

export type DeviceEventCallback<T extends EventType> = (event: DeviceEvent[T]) => void

type SpecificParamsDescriptor = {
  [TransferType.OUT_SELF]: {
    'eth': EthLikeSpecificParams
    'dag': BtcLikeSpecificParams & {
      lastTxRef: DagLastTxRef
    },
    'btc': BtcLikeSpecificParams & {
      outs: Utxo[]
    }
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