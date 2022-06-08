import { 
  DeviceEventCallback, DeviceEventType, 
  DeviceInfo, EthLikeSymbol, Symbol, 
  TransferParams, TransferResponse, TransferType 
} from "../v2/types"
import { Transaction } from "ethereumjs-tx"
import { WebSocket } from "ws"

export interface IEthKeyring<T> {
  type: string,
  serialize(): Promise<T>
  deserialize(obj: T): Promise<void>
  addAccounts(n: number): Promise<void>
  getAccounts(symbol: Symbol): Promise<string[]>
  signMessage(address: string, data: Buffer | string, symbol: Symbol): Promise<string>
  getEncryptionPublicKey(address: string): Promise<string>
  decryptMessage(address: string, data: string): Promise<string>
  exportAccount(address: string): Promise<void>
  removeAccount(address: string): Promise<void>
  signTransaction(address: string, transaction: Transaction, symbol: EthLikeSymbol): Promise<Transaction>
}

export interface IBitfiKeyring<T> extends IEthKeyring<T> {
  enable(pingFrequencySec: number): Promise<void>
  authorize(onSessionCodeReceived: (code: string) => void): Promise<boolean>
  getDeviceInfo(): Promise<DeviceInfo>
  transfer<T extends TransferType, C extends Symbol>(params: TransferParams[T][C]): Promise<TransferResponse[C]>
  getPublicKeys(symbol: Symbol): Promise<string[]>
  getDeviceEnvoy(): Promise<string>
  createListener(url: string, wsProvider: WebSocket): Promise<IDeviceListener>
}

export interface IDeviceListener {
  subscribe<T extends DeviceEventType>(eventType: T, callback: DeviceEventCallback<T>): () => void;
  close: () => void
}