import { 
  DeviceEventCallback, EventType, 
  DeviceInfo, EthLikeSymbol, Symbol, 
  TransferParams, TransferResponse, TransferType, WalletAddress, LegacyProfile, SegwitParam 
} from "../v2/types"
import { Transaction } from "ethereumjs-tx"
import { WebSocket } from "ws"



export interface IEthKeyring<T> {
  type: string,
  serialize(): Promise<T>
  deserialize(obj: T): Promise<void>
  addAccounts(n: number): Promise<void>
  getAccounts<T extends Symbol>(symbol: T, indexes: number[], doSegwit?: SegwitParam[T], timeoutMsec?: number): Promise<WalletAddress[]>
  signMessage<T extends Symbol>(
    address: string, data: Buffer | string, 
    symbol: T, index: number, doSegwit?: SegwitParam[T], timeoutMsec?: number
  ): Promise<string>
  getEncryptionPublicKey(address: string): Promise<string>
  decryptMessage(address: string, data: string): Promise<string>
  exportAccount(address: string): Promise<void>
  removeAccount(address: string): Promise<void>
  signTransaction(address: string, transaction: Transaction, indexes: number[], symbol: EthLikeSymbol, timeoutMsec?: number): Promise<Transaction>
}



export interface IBitfiKeyring<T> extends IEthKeyring<T> {
  enable(timeoutMsec?: number, pingFrequencyMsec?: number): Promise<void>
  authorize(onSessionCodeReceived: (code: string) => void, timeoutMsec?: number): Promise<boolean>
  getDeviceInfo(timeoutMsec?: number): Promise<DeviceInfo>
  transfer<T extends TransferType, C extends Symbol>(params: TransferParams[T][C], timeoutMsec?: number): Promise<TransferResponse[C]>
  getPublicKeys(symbol: Symbol, indexes: number[], timeoutMsec?: number): Promise<string[]>
  getDeviceEnvoy(timeoutMsec?: number): Promise<string>
  createListener(url: string, wsProvider: WebSocket): Promise<IDeviceListener>
  ping(timeoutMsec?: number): Promise<boolean>
  getLegacyProfile(symbol: Symbol, timeoutMsec?: number): Promise<LegacyProfile[]>
}

export interface IDeviceListener {
  subscribe<T extends Exclude<EventType, EventType.Session>>(
    eventType: T, callback: DeviceEventCallback<T>
  ): () => void;
  start(envoyToken?: string): Promise<void>
  stop: () => void
}